//! クラッシュで残った pull のリース・ステージングの回収 GC（OCI-7・TASK-183.11.2・MS-4・#852）。
//!
//! pull は `<root>/staging/<pull-id>/` に新規 blob を書き（`pull` モジュール）、その間 `@pull.lock`
//! （[`PULL_LOCK_FILE_NAME`]）の OS 排他ロックを保持する。pull プロセスがクラッシュ・drop すると OS が
//! ロックを解放するため、本ファイルの [`ImageStore::recover_stale_pulls`] はロックを取れた pull ID を
//! 「pull プロセスの不在を確認できた」ものとして、ステージングの削除と同一プロセス内に残ったリースの解放を行う。
//!
//! # 判定の規則（誤る方向は「余分に残す」側だけ。OCI-7）
//!
//! - ロックを取れた: 不在を確認できた。回収する。
//! - ロックが取れない（`WouldBlock`）: pull は生きている。残す。
//! - ロックファイルが無い・通常ファイルでない（symlink を含む）・開けない・差し替えを検出・ロック API の
//!   失敗: 確認できない。残す。
//!
//! PID の生存確認は使わない。PID の再利用や PID namespace 越し（別 namespace の pull が `/proc` に見えない）で
//! 「不在」と誤判定しうるためで、誤る方向が OCI-7 に反する。
//!
//! # 排他の規律
//!
//! `begin_pull` はストアの排他区間（[`ImageStore::lock`]）の内側でロックファイルの作成とロックまでを済ませる。
//! 本 GC も判定（ロックの試行）とリースの解放を同じ排他区間で行うため、「作成途中でまだロックされていない」
//! ロックファイルを見て誤って回収することはない。回収の削除も排他区間を保持したまま行う。手放すと別の GC が
//! 同じ残骸を回収対象に確定し、先行の削除後に `begin_pull` が同 ID で作った新しいステージングを遅れて消すため。
//! `abort` / `publish` も自分のステージングの削除が終わるまで排他を保持する。
//!
//! # 呼び出し文脈と前提
//!
//! 想定の呼び出しは再起動時（OCI-7）だが、ロックで生存を判定するため、いつ呼んでも生きている pull を壊さない。
//! ロックはローカルファイルシステムの OS ロック前提で、NFS 等での意味は保証しない。root は所有者専用の
//! ディレクトリである前提で、ロックファイルは symlink を辿らず、unix では開いた後に dev / inode を照合して
//! 差し替えを検出する（`store` の `@lock` と同じ）。
//!
//! staging の走査・判定・削除は、`ImageStore::open` が検査した root を保持する `RootHandle` の fd 起点で行う
//! （`root_handle::StagingDir` / `PullDir`。Linux の x86_64 / aarch64。それ以外はパス起点）。入口の再検査の
//! 後に root が別のディレクトリへ差し替えられても、削除は検査済みの実体にだけ届き、おとりの同名の残骸には
//! 触れない（OCI-7・SEC-1・#2694）。
//!
//! `abort` は排他を取れなければステージングを消さずエラーを返す（残骸は本 GC が回収し、メモリに残ったリースも
//! 解放する）。
//!
//! # 回収の順序（部分削除・クラッシュ後の再試行）
//!
//! 生存判定の証跡である `@pull.lock` は最後に消す。他の子エントリを先に消し、1 つでも失敗したら `@pull.lock` を
//! 残して失敗として返す（次回も同じ判定で再試行できる）。`@pull.lock` を消した後にクラッシュ・`rmdir` 失敗が
//! あっても、空のディレクトリは `begin_pull` の排他区間の外では「作成途中」にならない（作成はストア排他の内側）ため、
//! 排他下で見た空ディレクトリは不在として回収する。
//!
//! リースは `@image-inventory.json` に永続化され（#2380）、排他取得のたびに読み直されるため、別プロセスの
//! pull が残したリースも不在の確認後に解放して保存する。解放の保存に失敗したら、その pull のステージングは
//! 消さずに `failed` へ積む（保存の順序の不変条件: 永続化済みのリースがあれば `staging/<id>` がある）。
//!
//! 既知の残り（「余分に残す」側）: `staging/<id>` が無いのに永続化されたリース（上の順序を守る限り通常は
//! 生じない）は、ステージングを手がかりにする本 GC では解放されない。`@pull.lock` を持たない（#852 より前に作られた）空でないステージングは
//! 回収されない。
//!
//! 未実装（REPAIR-3）: 起動時の呼び出しの配線と結果のログ出力は、cri・core と oci の両方に依存するアダプタの
//! 担当（#2315）。ここでは新しい操作種別を増やさず、結果を構造化された戻り値で返す。

use std::ffi::OsStr;
use std::fs::{File, TryLockError};

use super::pull::PULL_LOCK_FILE_NAME;
use super::root_handle::{PullDir, StagingDir};
use super::{ImageStore, MAX_CACHE_SCAN_ENTRIES, PullId};
use crate::error::{OciError, OciErrorCode};
use crate::instrument::{OciOpKind, record_oci_op};

/// [`ImageStore::recover_stale_pulls`] の結果。各一覧は pull ID の昇順で決定的（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StalePullRecovery {
    reclaimed: Vec<PullId>,
    released_leases: Vec<(PullId, usize)>,
    kept_live: Vec<PullId>,
    kept_undetermined: Vec<PullId>,
    failed: Vec<(PullId, OciErrorCode)>,
    foreign_entries: usize,
}

impl StalePullRecovery {
    /// ステージングを消した pull ID。
    pub fn reclaimed(&self) -> &[PullId] {
        &self.reclaimed
    }

    /// 解放したリースの件数（0 件は含まない）。
    pub fn released_leases(&self) -> &[(PullId, usize)] {
        &self.released_leases
    }

    /// ロックが保持されている（pull が生きている）ため残した pull ID。
    pub fn kept_live(&self) -> &[PullId] {
        &self.kept_live
    }

    /// 不在を確認できなかったため残した pull ID。
    pub fn kept_undetermined(&self) -> &[PullId] {
        &self.kept_undetermined
    }

    /// 不在を確認できたがステージングの削除に失敗した pull ID と失敗の code（残置は余分に残す側）。
    pub fn failed(&self) -> &[(PullId, OciErrorCode)] {
        &self.failed
    }

    /// 触らなかったエントリ数（不正な名前・通常ディレクトリ以外）。
    pub fn foreign_entries(&self) -> usize {
        self.foreign_entries
    }
}

/// pull 1 件の判定。`Absent` だけがロックを持ったまま回収へ進む。
enum PullLiveness {
    Live,
    Absent(Option<File>),
    Undetermined,
}

/// `<pull dir>/@pull.lock` のロックを試して pull の生存を判定する。確認できなければ `Undetermined`。
fn probe_pull(dir: &PullDir) -> PullLiveness {
    let pre = match dir.stat_name(PULL_LOCK_FILE_NAME) {
        Ok(Some(m)) if m.is_file() => m,
        // 回収の途中で `@pull.lock` を消した後に落ちた残骸。排他下の空ディレクトリは不在とみなす。
        Ok(None) => {
            return match dir.list_names(1) {
                Ok(names) if names.is_empty() => PullLiveness::Absent(None),
                _ => PullLiveness::Undetermined,
            };
        }
        _ => return PullLiveness::Undetermined,
    };
    // 作成はしない（無ければ確認できない扱い）。symlink は辿らない。
    let file = match dir.open_lock_for_probe(PULL_LOCK_FILE_NAME) {
        Ok(f) => f,
        Err(_) => return PullLiveness::Undetermined,
    };
    let post = match file.metadata() {
        Ok(m) if m.is_file() => m,
        _ => return PullLiveness::Undetermined,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if pre.dev() != post.dev() || pre.ino() != post.ino() {
            return PullLiveness::Undetermined;
        }
    }
    #[cfg(not(unix))]
    let _ = (&pre, &post);
    match file.try_lock() {
        Ok(()) => PullLiveness::Absent(Some(file)),
        Err(TryLockError::WouldBlock) => PullLiveness::Live,
        Err(TryLockError::Error(_)) => PullLiveness::Undetermined,
    }
}

/// 回収対象と確定したステージングを消す。`@pull.lock` は最後に消し、それ以前に失敗したら残して返す
/// （部分削除の後も次回の判定・再試行ができるように。モジュール doc「回収の順序」）。
///
/// pull 自身の abort / publish 後の後始末（`pull` モジュールの `remove_staging`）も同じ関数を使い、
/// 通常の後始末の中断でも証跡を失わず本 GC が回収できるようにする（OCI-7・#852）。`staging` は検査済み root の
/// fd 起点で開いたもの（#2694）。ディレクトリが無ければ成功、symlink・非ディレクトリなら `FailedPrecondition`。
pub(super) fn reclaim_dir(staging: &StagingDir, id: &PullId) -> Result<(), OciErrorCode> {
    reclaim_dir_with(staging, id, &remove_entry)
}

/// 子エントリ 1 件の削除（ディレクトリは再帰）。
fn remove_entry(dir: &PullDir, name: &OsStr) -> std::io::Result<()> {
    dir.remove_child_tree(name)
}

/// [`reclaim_dir`] の本体。子エントリの削除手段を差し替えられる（削除失敗の注入試験用）。
fn reclaim_dir_with(
    staging: &StagingDir,
    id: &PullId,
    remove: &dyn Fn(&PullDir, &OsStr) -> std::io::Result<()>,
) -> Result<(), OciErrorCode> {
    let dir = match staging.open_pull_dir(id) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            return Err(OciErrorCode::FailedPrecondition);
        }
        Err(_) => return Err(OciErrorCode::Internal),
    };
    // 子の列挙は上限を 1 件超えて読み、超過を検出したら何も消さず `@pull.lock` ごと残す（確認できなければ
    // 残す。未列挙の子が残ったままロックだけ消すと次回の probe_pull が Undetermined になり再回収できない。OCI-7）。
    let names = dir
        .list_names(MAX_CACHE_SCAN_ENTRIES + 1)
        .map_err(|_| OciErrorCode::Internal)?;
    if names.len() > MAX_CACHE_SCAN_ENTRIES {
        return Err(OciErrorCode::ResourceExhausted);
    }
    let mut failed = false;
    for name in names {
        if name == PULL_LOCK_FILE_NAME {
            continue;
        }
        match remove(&dir, &name) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => failed = true,
        }
    }
    if failed {
        return Err(OciErrorCode::Internal);
    }
    match dir.unlink(PULL_LOCK_FILE_NAME) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(OciErrorCode::Internal),
    }
    match staging.remove_pull_dir(id) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(OciErrorCode::Internal),
    }
}

fn scan_err(msg: &str) -> OciError {
    OciError::new(OciErrorCode::Internal, msg)
}

impl ImageStore {
    /// クラッシュで残った pull のリースとステージングを、pull プロセスの不在を確認できたものに限って回収する
    /// （OCI-7・TASK-183.11.2・#852）。
    ///
    /// 排他の取得が失敗したら何も触らずエラーを返す。`staging` が symlink・非ディレクトリなら
    /// `FailedPrecondition`、エントリ数が `MAX_CACHE_SCAN_ENTRIES` を超えたら（何も消す前に）`ResourceExhausted`。
    /// 判定の規則と排他の規律はモジュール doc を参照。
    ///
    /// 操作全体の成否と所要時間を記録する（REPAIR-4）。一部のステージング削除が失敗した場合（`failed()` が
    /// 空でない）は、結果を `Ok` で返しつつ記録上は最初の失敗の code で失敗として数える。
    pub fn recover_stale_pulls(&self) -> Result<StalePullRecovery, OciError> {
        let mut out: Option<StalePullRecovery> = None;
        let r = record_oci_op(self.recorder(), OciOpKind::RecoverStalePulls, || {
            let res = self.recover_stale_pulls_inner()?;
            let partial = res.failed.first().map(|(_, c)| *c);
            out = Some(res);
            match partial {
                Some(code) => Err(OciError::new(code, "failed to remove some stale staging")),
                None => Ok(()),
            }
        });
        match (out, r) {
            (Some(res), _) => Ok(res),
            (None, Err(e)) => Err(e),
            (None, Ok(())) => Err(scan_err("recovery result missing")),
        }
    }

    fn recover_stale_pulls_inner(&self) -> Result<StalePullRecovery, OciError> {
        let mut result = StalePullRecovery::default();

        let mut guard = self.lock()?;
        // 検査済み root の fd 起点で `staging` を開く（symlink・非ディレクトリは辿らず拒否。#2694）。
        let staging = match self
            .handle()
            .open_staging_dir("staging is not a plain directory")?
        {
            Some(s) => s,
            None => return Ok(result),
        };
        // 上限を 1 件超えて読み、超過を検出したら何も消す前に拒否する。
        let names = staging
            .list_names(MAX_CACHE_SCAN_ENTRIES + 1)
            .map_err(|_| scan_err("failed to read staging directory"))?;
        if names.len() > MAX_CACHE_SCAN_ENTRIES {
            return Err(OciError::new(
                OciErrorCode::ResourceExhausted,
                "too many entries in staging directory",
            ));
        }
        let mut ids: Vec<PullId> = Vec::new();
        for name in names {
            let id = name.to_str().and_then(|n| PullId::new(n).ok());
            let is_dir = staging
                .stat_name(&name)
                .ok()
                .flatten()
                .is_some_and(|m| m.is_dir());
            match id {
                Some(id) if is_dir => ids.push(id),
                _ => result.foreign_entries += 1,
            }
        }
        ids.sort();

        // 1 件ずつ「判定 → リース解放 → ハンドル解放 → 削除」を行い、開いた `@pull.lock` の同時保持数を
        // 1 に抑える（残骸が多くても fd 上限に達しない）。ストア排他は削除が終わるまで保持する。
        // 手放すと別の GC が同じ残骸を確定し、この削除の後に `begin_pull` が同 ID で作った新しい
        // ステージングを遅れて消しうる（OCI-7）。
        for id in ids {
            let liveness = match staging.open_pull_dir(&id) {
                Ok(dir) => probe_pull(&dir),
                // 開けない（消えた・差し替えられた）ものは確認できない扱いで残す。
                Err(_) => PullLiveness::Undetermined,
            };
            match liveness {
                PullLiveness::Live => result.kept_live.push(id),
                PullLiveness::Undetermined => result.kept_undetermined.push(id),
                PullLiveness::Absent(file) => {
                    // 不在を確認できた pull のリース（排他取得時に永続化から読み直したもの。別プロセスの
                    // リースを含む。#2380）。解放を保存してからステージングを消す（保存の順序の不変条件）。
                    let before = guard.inventory_portion();
                    let n = guard.release_all_leases(&id).len();
                    if let Err(e) = guard.persist_inventory(before) {
                        // 保存できなければリースは残り（戻される）、ステージングも消さない（余分に残す側）。
                        drop(file);
                        result.failed.push((id, e.code()));
                        continue;
                    }
                    if n > 0 {
                        result.released_leases.push((id.clone(), n));
                    }
                    // Windows は開いたハンドルがディレクトリ削除を妨げるため、先に閉じる。
                    drop(file);
                    match reclaim_dir(&staging, &id) {
                        Ok(()) => result.reclaimed.push(id),
                        Err(code) => result.failed.push((id, code)),
                    }
                }
            }
        }
        drop(guard);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::root_handle::RootHandle;
    use super::*;
    use crate::reference::Digest;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    fn pid(s: &str) -> PullId {
        PullId::new(s).unwrap()
    }

    struct Root(PathBuf);
    impl Root {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fc-oci-recov-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(p.join("blobs").join("sha256")).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
            }
            Root(p)
        }
        fn staging(&self) -> PathBuf {
            self.0.join("staging")
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sha_hex(b: u8) -> String {
        format!("{b:02x}").repeat(32)
    }

    fn cached_blob(root: &Root, b: u8) -> Digest {
        let hex = sha_hex(b);
        let d = Digest::parse(&format!("sha256:{hex}")).unwrap();
        fs::write(root.0.join("blobs").join("sha256").join(&hex), b"x").unwrap();
        d
    }

    fn leases(store: &ImageStore, dg: &Digest) -> Vec<PullId> {
        store.lock().unwrap().blob_references(dg).leases
    }

    fn mk_stale(root: &Root, id: &str, with_lock: bool) -> PathBuf {
        let dir = root.staging().join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("aa"), b"data").unwrap();
        if with_lock {
            fs::write(dir.join(PULL_LOCK_FILE_NAME), b"").unwrap();
        }
        dir
    }

    fn hold_lock(dir: &Path) -> File {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join(PULL_LOCK_FILE_NAME))
            .unwrap();
        f.try_lock().unwrap();
        f
    }

    /// OCI-7: ロックファイルの無いステージングは不在を確認できないので残す。
    #[test]
    fn oci7_recover_keeps_staging_without_lock_file() {
        let root = Root::new("nolock");
        let dir = mk_stale(&root, "p1", false);
        let store = ImageStore::open(&root.0).unwrap();
        let r = store.recover_stale_pulls().unwrap();
        assert_eq!(r.kept_undetermined(), &[pid("p1")]);
        assert!(r.reclaimed().is_empty());
        assert!(dir.join("aa").exists());
    }

    /// OCI-7: ロックが保持されている（pull が生きている）ステージングは残す。
    #[test]
    fn oci7_recover_keeps_staging_when_lock_is_held() {
        let root = Root::new("held");
        let dir = mk_stale(&root, "p1", true);
        let _held = hold_lock(&dir);
        let store = ImageStore::open(&root.0).unwrap();
        let r = store.recover_stale_pulls().unwrap();
        assert_eq!(r.kept_live(), &[pid("p1")]);
        assert!(r.reclaimed().is_empty());
        assert!(dir.join("aa").exists());
    }

    /// OCI-7: 生きているセッションのリースとステージングは回収されず、その後の abort も成功する。
    #[test]
    fn oci7_recover_keeps_live_session() {
        let root = Root::new("live");
        let dg = cached_blob(&root, 1);
        let store = ImageStore::open(&root.0).unwrap();
        let mut s = store.begin_pull(pid("p1")).unwrap();
        let _t = s.lease_existing_blob(&dg).unwrap();
        let r = store.recover_stale_pulls().unwrap();
        assert_eq!(r.kept_live(), &[pid("p1")]);
        assert_eq!(leases(&store, &dg), vec![pid("p1")]);
        assert!(s.staging_dir().exists());
        let out = s.abort().unwrap();
        assert_eq!(out.released_leases, 1);
        assert!(leases(&store, &dg).is_empty());
    }

    /// OCI-7: ロックファイルが symlink・ディレクトリなら確認できないので残し、先には触れない。
    #[test]
    fn oci7_recover_keeps_when_lock_file_is_dir() {
        let root = Root::new("lockdir");
        let dir = mk_stale(&root, "p1", false);
        fs::create_dir(dir.join(PULL_LOCK_FILE_NAME)).unwrap();
        let store = ImageStore::open(&root.0).unwrap();
        let r = store.recover_stale_pulls().unwrap();
        assert_eq!(r.kept_undetermined(), &[pid("p1")]);
        assert!(dir.join("aa").exists());
    }

    #[cfg(unix)]
    #[test]
    fn oci7_recover_keeps_when_lock_file_is_symlink() {
        let root = Root::new("locklink");
        let dir = mk_stale(&root, "p1", false);
        let target = root.0.join("target");
        fs::write(&target, b"t").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(PULL_LOCK_FILE_NAME)).unwrap();
        let store = ImageStore::open(&root.0).unwrap();
        let r = store.recover_stale_pulls().unwrap();
        assert_eq!(r.kept_undetermined(), &[pid("p1")]);
        assert!(dir.join("aa").exists());
        assert_eq!(fs::read(&target).unwrap(), b"t");
    }

    /// OCI-7: drop されたセッションは回収し、同一プロセスに残ったリースも解放する。
    #[test]
    fn oci7_recover_reclaims_dropped_session_and_releases_its_leases() {
        let root = Root::new("dropped");
        let dg = cached_blob(&root, 2);
        let store = ImageStore::open(&root.0).unwrap();
        let dir = {
            let mut s = store.begin_pull(pid("p1")).unwrap();
            let _t = s.lease_existing_blob(&dg).unwrap();
            let staged =
                s.staged_blob_path(&Digest::parse(&format!("sha256:{}", sha_hex(3))).unwrap());
            fs::write(staged.unwrap(), b"partial").unwrap();
            s.staging_dir().to_path_buf()
        };
        assert!(dir.exists());
        let r = store.recover_stale_pulls().unwrap();
        assert_eq!(r.reclaimed(), &[pid("p1")]);
        assert_eq!(r.released_leases(), &[(pid("p1"), 1)]);
        assert!(r.kept_live().is_empty() && r.kept_undetermined().is_empty());
        assert!(r.failed().is_empty());
        assert!(!dir.exists());
        assert!(leases(&store, &dg).is_empty());
    }

    /// OCI-7: 未ロックのロックファイル（保持者の不在を確認できた）は回収する。
    #[test]
    fn oci7_recover_reclaims_unlocked_lock_file() {
        let root = Root::new("unlocked");
        let dir = mk_stale(&root, "p1", true);
        let store = ImageStore::open(&root.0).unwrap();
        let r = store.recover_stale_pulls().unwrap();
        assert_eq!(r.reclaimed(), &[pid("p1")]);
        assert!(!dir.exists());
    }

    /// OCI-7: 不在を確認できた ID だけを触り、生きている・確認できない ID とそのリースには触れない。
    #[test]
    fn oci7_recover_only_touches_absent_ids() {
        let root = Root::new("mixed");
        let dg = cached_blob(&root, 4);
        let store = ImageStore::open(&root.0).unwrap();
        let mut live = store.begin_pull(pid("live")).unwrap();
        let _t = live.lease_existing_blob(&dg).unwrap();
        let absent = mk_stale(&root, "absent", true);
        let undet = mk_stale(&root, "undet", false);
        let r = store.recover_stale_pulls().unwrap();
        assert_eq!(r.reclaimed(), &[pid("absent")]);
        assert_eq!(r.kept_live(), &[pid("live")]);
        assert_eq!(r.kept_undetermined(), &[pid("undet")]);
        assert!(!absent.exists());
        assert!(undet.join("aa").exists());
        assert!(live.staging_dir().exists());
        assert_eq!(leases(&store, &dg), vec![pid("live")]);
        live.abort().unwrap();
    }

    /// OCI-7: 不正な名前・通常ファイル・symlink のエントリは触らず foreign として数える。
    #[test]
    fn oci7_recover_skips_foreign_entries() {
        let root = Root::new("foreign");
        fs::create_dir_all(root.staging().join("bad name")).unwrap();
        fs::write(root.staging().join("stray"), b"s").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.staging(), root.staging().join("lnk")).unwrap();
        let store = ImageStore::open(&root.0).unwrap();
        let r = store.recover_stale_pulls().unwrap();
        let expected = if cfg!(unix) { 3 } else { 2 };
        assert_eq!(r.foreign_entries(), expected);
        assert!(r.reclaimed().is_empty());
        assert!(root.staging().join("bad name").exists());
        assert!(root.staging().join("stray").exists());
    }

    /// OCI-7: staging が無ければ空の結果。
    #[test]
    fn oci7_recover_without_staging_is_empty() {
        let root = Root::new("nostaging");
        let store = ImageStore::open(&root.0).unwrap();
        assert_eq!(
            store.recover_stale_pulls().unwrap(),
            StalePullRecovery::default()
        );
    }

    /// OCI-7: symlink の staging は辿らず拒否する。
    #[cfg(unix)]
    #[test]
    fn oci7_recover_rejects_symlinked_staging() {
        let root = Root::new("stagelink");
        let other = root.0.join("other");
        fs::create_dir_all(other.join("p1")).unwrap();
        std::os::unix::fs::symlink(&other, root.staging()).unwrap();
        let store = ImageStore::open(&root.0).unwrap();
        let e = store.recover_stale_pulls().unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert!(other.join("p1").exists());
    }

    /// OCI-7: 排他を取れなければ何も消さずに Timeout を返す。
    #[test]
    fn oci7_recover_lock_timeout_touches_nothing() {
        let root = Root::new("timeout");
        let dir = mk_stale(&root, "p1", true);
        let store = ImageStore::open(&root.0)
            .unwrap()
            .with_timeout(Duration::from_millis(50));
        let held = store.lock().unwrap();
        let e = store.recover_stale_pulls().unwrap_err();
        drop(held);
        assert_eq!(e.code(), OciErrorCode::Timeout);
        assert!(dir.join("aa").exists());
    }

    /// OCI-7: begin_pull は 0600 の `@pull.lock` を作ってロックを保持し、abort で全部消える。
    #[test]
    fn oci7_begin_pull_creates_locked_lock_file() {
        let root = Root::new("beginlock");
        let store = ImageStore::open(&root.0).unwrap();
        let s = store.begin_pull(pid("p1")).unwrap();
        let lock = s.staging_dir().join(PULL_LOCK_FILE_NAME);
        let m = fs::symlink_metadata(&lock).unwrap();
        assert!(m.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
        let other = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock)
            .unwrap();
        assert!(matches!(other.try_lock(), Err(TryLockError::WouldBlock)));
        drop(other);
        let dir = s.staging_dir().to_path_buf();
        s.abort().unwrap();
        assert!(!dir.exists());
    }

    fn recorded_store(
        root: &Root,
    ) -> (
        ImageStore,
        std::sync::Arc<crate::instrument::testing::Collect>,
    ) {
        let rec = std::sync::Arc::new(crate::instrument::testing::Collect::default());
        let store = ImageStore::open(&root.0)
            .unwrap()
            .with_recorder(rec.clone());
        (store, rec)
    }

    fn gc_samples(
        rec: &crate::instrument::testing::Collect,
    ) -> Vec<crate::instrument::OciOpSample> {
        rec.items()
            .into_iter()
            .filter(|s| s.kind() == OciOpKind::RecoverStalePulls)
            .collect()
    }

    /// REPAIR-4・OCI-7: 回収全体の成功が 1 件記録される。
    #[test]
    fn oci7_recover_records_success() {
        let root = Root::new("recsucc");
        mk_stale(&root, "p1", true);
        let (store, rec) = recorded_store(&root);
        let r = store.recover_stale_pulls().unwrap();
        assert_eq!(r.reclaimed(), &[pid("p1")]);
        let s = gc_samples(&rec);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].outcome(), crate::instrument::OciOpOutcome::Success);
    }

    /// REPAIR-4・OCI-7: 非ディレクトリの staging は失敗として code つきで 1 件記録される。
    #[test]
    fn oci7_recover_records_failure_for_non_directory_staging() {
        let root = Root::new("recfail");
        fs::write(root.staging(), b"x").unwrap();
        let (store, rec) = recorded_store(&root);
        let e = store.recover_stale_pulls().unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        let s = gc_samples(&rec);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].outcome(), crate::instrument::OciOpOutcome::Failure);
        assert_eq!(s[0].error_code(), Some(OciErrorCode::FailedPrecondition));
    }

    /// REPAIR-4・OCI-7: 一部の削除失敗は結果を返しつつ失敗として記録される。
    /// 失敗は `reclaim_dir_with` の注入で確実に起こす（root でも成立）ため、アサーションは常に実行される。
    #[test]
    fn oci7_reclaim_keeps_lock_on_injected_failure_and_retry_succeeds() {
        let root = Root::new("recpartial");
        let dir = mk_stale(&root, "p1", true);
        fs::write(dir.join("keep"), b"x").unwrap();
        let fail = std::cell::Cell::new(true);
        let inject = |d: &PullDir, n: &OsStr| -> std::io::Result<()> {
            if fail.get() && n == "keep" {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            }
            remove_entry(d, n)
        };
        let handle = RootHandle::open_unchecked(&root.0).unwrap();
        let staging = handle.open_staging_dir("not a dir").unwrap().unwrap();
        let id = pid("p1");
        assert_eq!(
            reclaim_dir_with(&staging, &id, &inject),
            Err(OciErrorCode::Internal)
        );
        // 証跡の `@pull.lock` と失敗した子は残る。
        assert!(dir.join(PULL_LOCK_FILE_NAME).exists());
        assert!(dir.join("keep").exists());
        // 注入を止めた再試行で回収できる。
        fail.set(false);
        assert_eq!(reclaim_dir_with(&staging, &id, &inject), Ok(()));
        assert!(!dir.exists());
    }

    /// REPAIR-4・OCI-7: `recover_stale_pulls` が削除失敗を `failed()` と失敗記録に反映する
    /// （unix の非 root では実際の権限エラーで確認。root では上の注入試験が契約を担保する）。
    /// fd 起点の再帰削除（Linux の x86_64 / aarch64）は所有者の rwx を戻してから消すため、権限だけでは
    /// 失敗を作れず、その環境では回収成功の分岐になる。失敗経路の契約は注入試験が担保する（#2694）。
    #[cfg(unix)]
    #[test]
    fn oci7_recover_records_partial_removal_failure() {
        use std::os::unix::fs::PermissionsExt;
        let root = Root::new("recpartial2");
        let dir = mk_stale(&root, "p1", true);
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("f"), b"x").unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).unwrap();
        let (store, rec) = recorded_store(&root);
        let r = store.recover_stale_pulls().unwrap();
        if r.failed().is_empty() {
            // root では権限で拒否されない。後始末のみ行い、契約は注入試験が担保する。
            assert_eq!(r.reclaimed(), &[pid("p1")]);
            return;
        }
        assert_eq!(r.failed(), &[(pid("p1"), OciErrorCode::Internal)]);
        let s = gc_samples(&rec);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].outcome(), crate::instrument::OciOpOutcome::Failure);
        assert_eq!(s[0].error_code(), Some(OciErrorCode::Internal));
        assert!(dir.join(PULL_LOCK_FILE_NAME).exists());
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
        let r2 = store.recover_stale_pulls().unwrap();
        assert_eq!(r2.reclaimed(), &[pid("p1")]);
        assert!(!dir.exists());
    }

    /// OCI-7: `@pull.lock` を消した後に落ちた空のステージングも回収される。
    #[test]
    fn oci7_recover_reclaims_empty_staging_dir() {
        let root = Root::new("emptydir");
        let dir = root.staging().join("p1");
        fs::create_dir_all(&dir).unwrap();
        let store = ImageStore::open(&root.0).unwrap();
        let r = store.recover_stale_pulls().unwrap();
        assert_eq!(r.reclaimed(), &[pid("p1")]);
        assert!(!dir.exists());
    }
}
