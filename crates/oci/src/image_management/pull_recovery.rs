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
//! ロックファイルを見て誤って回収することはない。`remove_dir_all` も排他区間を保持したまま行う。手放すと別の GC が
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
//! 既知の残り（いずれも「余分に残す」側）: `abort` が排他の取得に失敗するとリースはメモリに残るがステージングは
//! 消えるため、本 GC はその pull ID を見つけられない（プロセス終了で消える）。`@pull.lock` を持たない
//! （#852 より前に作られた）ステージングは回収されない。
//!
//! 未実装（REPAIR-3）: 起動時の呼び出しの配線と結果のログ出力は、cri・core と oci の両方に依存するアダプタの
//! 担当（#2315）。ここでは新しい操作種別を増やさず、結果を構造化された戻り値で返す。

use std::fs::{self, File, TryLockError};

use super::pull::{PULL_LOCK_FILE_NAME, STAGING_DIR_NAME};
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
    Absent(File),
    Undetermined,
}

/// `<dir>/@pull.lock` のロックを試して pull の生存を判定する。確認できなければ `Undetermined`。
fn probe_pull(dir: &std::path::Path) -> PullLiveness {
    let lock_path = dir.join(PULL_LOCK_FILE_NAME);
    let pre = match fs::symlink_metadata(&lock_path) {
        Ok(m) if m.is_file() => m,
        _ => return PullLiveness::Undetermined,
    };
    // Windows の LockFileEx は読み書き権限が要る。作成はしない（無ければ確認できない扱い）。
    let file = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open(&lock_path)
    {
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
        Ok(()) => PullLiveness::Absent(file),
        Err(TryLockError::WouldBlock) => PullLiveness::Live,
        Err(TryLockError::Error(_)) => PullLiveness::Undetermined,
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
        let staging = self.root().join(STAGING_DIR_NAME);
        let mut absent: Vec<(PullId, File)> = Vec::new();

        let mut guard = self.lock()?;
        match fs::symlink_metadata(&staging) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(OciError::new(
                    OciErrorCode::FailedPrecondition,
                    "staging is not a plain directory",
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(result),
            Err(_) => return Err(scan_err("failed to stat staging")),
        }
        let rd =
            fs::read_dir(&staging).map_err(|_| scan_err("failed to read staging directory"))?;
        let mut ids: Vec<PullId> = Vec::new();
        let mut seen = 0usize;
        for ent in rd {
            let ent = ent.map_err(|_| scan_err("failed to read staging entry"))?;
            seen += 1;
            if seen > MAX_CACHE_SCAN_ENTRIES {
                return Err(OciError::new(
                    OciErrorCode::ResourceExhausted,
                    "too many entries in staging directory",
                ));
            }
            let id = ent.file_name().to_str().and_then(|n| PullId::new(n).ok());
            let is_dir = fs::symlink_metadata(ent.path()).is_ok_and(|m| m.is_dir());
            match id {
                Some(id) if is_dir => ids.push(id),
                _ => result.foreign_entries += 1,
            }
        }
        ids.sort();

        for id in ids {
            match probe_pull(&staging.join(id.as_str())) {
                PullLiveness::Live => result.kept_live.push(id),
                PullLiveness::Undetermined => result.kept_undetermined.push(id),
                PullLiveness::Absent(file) => {
                    // 同一プロセスで drop されたセッションのリース。別プロセスのリースはこのテーブルに無い。
                    let n = guard.release_all_leases(&id).len();
                    if n > 0 {
                        result.released_leases.push((id.clone(), n));
                    }
                    absent.push((id, file));
                }
            }
        }
        // 削除が終わるまでストア排他を保持する。手放すと別の GC が同じ残骸を確定し、この削除の後に
        // `begin_pull` が同 ID で作った新しいステージングを遅れて消しうる（OCI-7）。
        for (id, file) in absent {
            // Windows は開いたハンドルがディレクトリ削除を妨げるため、先に閉じる。
            drop(file);
            let dir = staging.join(id.as_str());
            match fs::remove_dir_all(&dir) {
                Ok(()) => result.reclaimed.push(id),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => result.reclaimed.push(id),
                Err(_) => result.failed.push((id, OciErrorCode::Internal)),
            }
        }
        drop(guard);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::Digest;
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

    /// REPAIR-4・OCI-7: 一部の削除失敗は結果を返しつつ失敗として記録される（root では削除できるため skip）。
    #[cfg(unix)]
    #[test]
    fn oci7_recover_records_partial_removal_failure() {
        use std::os::unix::fs::PermissionsExt;
        let root = Root::new("recpartial");
        let dir = mk_stale(&root, "p1", true);
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("f"), b"x").unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o500)).unwrap();
        let (store, rec) = recorded_store(&root);
        let r = store.recover_stale_pulls().unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
        if r.failed().is_empty() {
            return;
        }
        assert_eq!(r.failed(), &[(pid("p1"), OciErrorCode::Internal)]);
        let s = gc_samples(&rec);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].outcome(), crate::instrument::OciOpOutcome::Failure);
        assert_eq!(s[0].error_code(), Some(OciErrorCode::Internal));
    }
}
