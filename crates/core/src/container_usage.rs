//! コンテナの使用容量（bundle と rootfs）の読み取り専用計測（OCI-7・TASK-183・#2222）。
//!
//! `system df` の「コンテナ」行のために、`StateStore` に記録された全コンテナの bundle と、
//! その `config.json` の `root.path` が指す rootfs の通常ファイルの見かけのサイズを集計する。
//! rootfs・bundle は core が管理する領域のため計測口をここに置く。oci は core に依存しない
//! （依存方向を変えない）ので、結果は呼び出し側（cri・将来の CLI アダプタ。#2221）が
//! oci の `ContainersUsage` へ写して `DiskUsage::with_containers` で合成する。
//!
//! # サイズの定義（暫定。OCI-7 は Should・検討中）
//!
//! 通常ファイルの `len`（見かけのサイズ）の合計。symlink は辿らず自身のサイズも足さない。ハードリンクは
//! `(dev, ino)` で 1 回だけ数える。起点と `st_dev` が違うディレクトリ（マウント点）には降りない。
//! Docker の writable layer の差分容量とは定義が異なる。
//!
//! # 呼び出し文脈と排他
//!
//! 読み取り専用。取るロックは `StateStore::list` の内部のものだけで、走査はロックの外で行う
//! スナップショットである（走査中の create / delete とは整合しない。消えたエントリは飛ばす）。
//! oci の `ImageStoreGuard` を保持したまま呼ばない（重い走査で他の操作が Timeout する。REPAIR-5）。
//!
//! # 権限不足の扱い
//!
//! rootless では rootfs に subuid 所有の 0700 ディレクトリがあり得るため、読めなかった
//! ディレクトリは全体を失敗させず `inaccessible_entries` に数える（過少計上は件数で示す）。
//! 所有者専用の blob キャッシュを「過少計上せず失敗」とする oci 側とは前提が異なる。

use std::collections::BTreeSet;
use std::fs::{self, Metadata};
use std::io::ErrorKind;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use crate::oci_runtime::load_config;
use crate::traits::{ErrorCode, ListStateRequest, MAX_PAGE_SIZE, StateStore, TraitError};

/// 走査するエントリ数の上限（無制限の走査と集合の膨張を避ける。超えたら失敗）。
pub const MAX_CONTAINER_SCAN_ENTRIES: usize = 16_777_216;

/// 一覧のページ送りの上限回数（`StateStore` の応答が終わらない場合の保護。REPAIR-5）。
const MAX_LIST_PAGES: usize = 100_000;

/// コンテナ領域の使用容量。件数は「数えられなかった・降りなかった」ものを示し、黙った過少計上を防ぐ。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ContainerDiskUsage {
    /// 一覧にあったコンテナ数（同じ bundle を指す複数のコンテナも 1 件ずつ数える）。
    pub count: usize,
    /// bundle と rootfs の通常ファイルの見かけのサイズの合計（ハードリンクは 1 回）。
    pub bytes: u64,
    /// bundle が存在しない・ディレクトリでない・symlink の件数。
    pub missing_bundles: usize,
    /// `config.json` を読めず rootfs を特定できなかった件数（bundle は計測する）。
    pub unreadable_configs: usize,
    /// 権限不足などで読めなかったディレクトリ・エントリの件数。
    pub inaccessible_entries: usize,
    /// `st_dev` が変わるため降りなかったディレクトリの件数。
    pub mount_points_skipped: usize,
    /// 走査したエントリの総数。
    pub entries_scanned: usize,
}

fn terr(code: ErrorCode, msg: &'static str) -> TraitError {
    TraitError::new(code, msg)
}

/// `store` の全コンテナの bundle・rootfs の使用容量を計測する（読み取り専用）。
///
/// `list` の失敗（破損レコードの fail-closed を含む）はそのまま返す。走査が
/// [`MAX_CONTAINER_SCAN_ENTRIES`] を超えたら `FailedPrecondition`。
pub fn measure_container_usage(store: &dyn StateStore) -> Result<ContainerDiskUsage, TraitError> {
    // Linux の走査は固定 fd を `/proc/self/fd/N` で読む。procfs が無ければ黙って過少計上せず失敗させる。
    #[cfg(target_os = "linux")]
    if !Path::new("/proc/self/fd").is_dir() {
        return Err(terr(
            ErrorCode::FailedPrecondition,
            "procfs is required to measure container usage",
        ));
    }
    let page = NonZeroU32::new(MAX_PAGE_SIZE)
        .ok_or_else(|| terr(ErrorCode::Internal, "invalid page size"))?;
    let mut req = ListStateRequest::new(page)?;
    let mut bundles: Vec<PathBuf> = Vec::new();
    let mut count = 0usize;
    for _ in 0..MAX_LIST_PAGES {
        let list = store.list(&req)?;
        count = count.saturating_add(list.records().len());
        bundles.extend(list.records().iter().map(|r| r.bundle().to_path_buf()));
        match list.next_cursor() {
            Some(c) => req = ListStateRequest::new(page)?.with_cursor(c.clone()),
            None => return measure_bundles(count, bundles),
        }
    }
    Err(terr(ErrorCode::FailedPrecondition, "too many list pages"))
}

fn measure_bundles(count: usize, bundles: Vec<PathBuf>) -> Result<ContainerDiskUsage, TraitError> {
    let mut w = Walker::default();
    w.usage.count = count;
    // 同じ bundle を共有するコンテナは 1 回だけ走査する。
    let unique: BTreeSet<PathBuf> = bundles.into_iter().collect();
    for bundle in &unique {
        match fs::symlink_metadata(bundle) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                w.usage.missing_bundles += 1;
                continue;
            }
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                w.usage.inaccessible_entries += 1;
                continue;
            }
            Err(_) => {
                w.usage.missing_bundles += 1;
                continue;
            }
        }
        let rootfs = match load_config(&bundle.join("config.json")) {
            Ok(cfg) => match rootfs_within_bundle(bundle, cfg.root().path()) {
                Some(p) => Some(p),
                None => {
                    // bundle 外を指す root.path は走査しない（SEC-1。create 側と整合）。
                    w.usage.unreadable_configs += 1;
                    None
                }
            },
            Err(_) => {
                w.usage.unreadable_configs += 1;
                None
            }
        };
        w.walk_root(bundle)?;
        // rootfs は bundle 配下に限るため bundle の走査で数え済み。個別に歩くのは、bundle 側が
        // マウント点として降りなかった rootfs を拾う Unix だけ（`(dev, ino)` で二重計上を防げる）。
        // 非 Unix は識別子が無く重複を判定できないため、二度目の走査をしない（二重計上の防止）。
        #[cfg(unix)]
        if let Some(rootfs) = rootfs {
            w.walk_root(&rootfs)?;
        }
        #[cfg(not(unix))]
        let _ = rootfs;
    }
    Ok(w.usage)
}

/// `root.path` を bundle に結合し、bundle 配下に収まる場合だけ返す（SEC-1・OCI-7）。
/// `..` 成分、および symlink 解決後に bundle の外へ出る経路は `None`（改ざん config.json による
/// 任意ディレクトリの走査を防ぐ）。rootfs が未作成で解決できない場合は字句上のパスを返す。
fn rootfs_within_bundle(bundle: &Path, root_path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    if root_path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return None;
    }
    let joined = bundle.join(root_path);
    let canon_bundle = fs::canonicalize(bundle).ok()?;
    match fs::canonicalize(&joined) {
        Ok(c) if c.starts_with(&canon_bundle) => Some(joined),
        Ok(_) => None,
        Err(_) => joined.starts_with(bundle).then_some(joined),
    }
}

#[cfg(unix)]
fn identity(m: &Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((m.dev(), m.ino()))
}
#[cfg(not(unix))]
fn identity(_: &Metadata) -> Option<(u64, u64)> {
    None
}

#[cfg(unix)]
fn nlink(m: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    m.nlink()
}
#[cfg(not(unix))]
fn nlink(_: &Metadata) -> u64 {
    1
}

/// 全コンテナで共有する走査状態（訪問済みディレクトリとハードリンクの集合を跨いで持つ）。
#[derive(Default)]
struct Walker {
    usage: ContainerDiskUsage,
    visited_dirs: BTreeSet<(u64, u64)>,
    seen_links: BTreeSet<(u64, u64)>,
}

impl Walker {
    fn tick(&mut self) -> Result<(), TraitError> {
        self.usage.entries_scanned += 1;
        if self.usage.entries_scanned > MAX_CONTAINER_SCAN_ENTRIES {
            return Err(terr(
                ErrorCode::FailedPrecondition,
                "too many entries to scan",
            ));
        }
        Ok(())
    }

    fn add_bytes(&mut self, n: u64) -> Result<(), TraitError> {
        self.usage.bytes = self
            .usage
            .bytes
            .checked_add(n)
            .ok_or_else(|| terr(ErrorCode::Internal, "size overflow"))?;
        Ok(())
    }

    /// 通常ファイル 1 件の加算（ハードリンクは `(dev, ino)` で 1 回だけ）。
    fn account_file(&mut self, m: &Metadata) -> Result<(), TraitError> {
        if nlink(m) > 1
            && let Some(id) = identity(m)
            && !self.seen_links.insert(id)
        {
            return Ok(());
        }
        self.add_bytes(m.len())
    }

    /// ディレクトリ `m` に降りてよいか（マウント点・訪問済みは降りない）。
    fn should_descend(&mut self, m: &Metadata, root_id: Option<(u64, u64)>) -> bool {
        let id = identity(m);
        if let (Some((dev, _)), Some((rdev, _))) = (id, root_id)
            && dev != rdev
        {
            self.usage.mount_points_skipped += 1;
            return false;
        }
        match id {
            Some(id) => self.visited_dirs.insert(id),
            None => true,
        }
    }

    /// 起点ディレクトリから深さ優先で歩く（再帰なし・symlink は辿らない）。
    ///
    /// Linux では各ディレクトリを `O_PATH|O_DIRECTORY|O_NOFOLLOW` の fd で固定し、子は親 fd 起点で
    /// 開く。走査中にコンテナ側がディレクトリを symlink へ差し替えても、固定済みの実体だけを読む
    /// （TOCTOU 対策。SEC-1・OCI-7）。起点が存在しない・ディレクトリでない・訪問済みなら何もしない。
    /// procfs（`/proc/self/fd`）が無い環境では呼び出し側（[`measure_container_usage`]）が事前に失敗させる。
    #[cfg(target_os = "linux")]
    fn walk_root(&mut self, root: &Path) -> Result<(), TraitError> {
        use std::ffi::CString;
        use std::os::fd::{AsFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        use std::rc::Rc;

        use crate::sys::{self, SysError};

        let Ok(croot) = CString::new(root.as_os_str().as_bytes()) else {
            return Ok(());
        };
        let root_fd = match sys::open_dir_path_nofollow(None, &croot) {
            Ok(fd) => fd,
            Err(SysError::Os(e)) if e == sys::EACCES => {
                self.usage.inaccessible_entries += 1;
                return Ok(());
            }
            // 不在・symlink・非ディレクトリ（ENOENT・ENOTDIR 等）は何もしない。
            Err(_) => return Ok(()),
        };
        let Ok(root_meta) = fs::metadata(fd_path(&root_fd)) else {
            return Ok(());
        };
        let root_id = identity(&root_meta);
        if let Some(id) = root_id
            && !self.visited_dirs.insert(id)
        {
            return Ok(());
        }
        // 未処理の子ディレクトリ。親 fd を共有して保持し、子は取り出す時に開く（開いたままの fd 数は深さに比例）。
        let mut pending: Vec<(Rc<OwnedFd>, CString)> = Vec::new();
        self.scan_dir(&Rc::new(root_fd), &mut pending)?;
        while let Some((parent, name)) = pending.pop() {
            let fd = match sys::open_dir_path_nofollow(Some(parent.as_fd()), &name) {
                Ok(fd) => fd,
                Err(SysError::Os(e)) if e == sys::EACCES => {
                    self.usage.inaccessible_entries += 1;
                    continue;
                }
                // 差し替えられた（symlink・非ディレクトリ）・消えた子は辿らない。
                Err(_) => continue,
            };
            // 固定した fd 自身の実体で dev / ino を判定する（パスを引き直さない）。
            let Ok(m) = fs::metadata(fd_path(&fd)) else {
                continue;
            };
            if !self.should_descend(&m, root_id) {
                continue;
            }
            self.scan_dir(&Rc::new(fd), &mut pending)?;
        }
        Ok(())
    }

    /// 固定済みのディレクトリ fd 1 つの直下を読み、通常ファイルを加算し、子ディレクトリを `pending` へ積む。
    #[cfg(target_os = "linux")]
    fn scan_dir(
        &mut self,
        dfd: &std::rc::Rc<std::os::fd::OwnedFd>,
        pending: &mut Vec<(std::rc::Rc<std::os::fd::OwnedFd>, std::ffi::CString)>,
    ) -> Result<(), TraitError> {
        use std::os::unix::ffi::OsStrExt;

        let dpath = fd_path(dfd);
        let rd = match fs::read_dir(&dpath) {
            Ok(rd) => rd,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                self.usage.inaccessible_entries += 1;
                return Ok(());
            }
            Err(_) => return Err(terr(ErrorCode::Internal, "failed to read directory")),
        };
        for ent in rd {
            let ent = match ent {
                Ok(e) => e,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    self.usage.inaccessible_entries += 1;
                    continue;
                }
                Err(_) => return Err(terr(ErrorCode::Internal, "failed to read entry")),
            };
            self.tick()?;
            let name = ent.file_name();
            // 親は固定済み fd（magic link）で解決され、最終要素だけを lstat する。
            let m = match fs::symlink_metadata(dpath.join(&name)) {
                Ok(m) => m,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    self.usage.inaccessible_entries += 1;
                    continue;
                }
                Err(_) => return Err(terr(ErrorCode::Internal, "failed to stat entry")),
            };
            if m.is_dir() {
                if let Ok(c) = std::ffi::CString::new(name.as_bytes()) {
                    pending.push((std::rc::Rc::clone(dfd), c));
                }
            } else if m.is_file() {
                self.account_file(&m)?;
            }
        }
        Ok(())
    }

    /// 起点ディレクトリから深さ優先で歩く（再帰なし・symlink は辿らない）。Linux 以外の fd 起点 API を
    /// 使わない経路で、検査後にパスを解決し直す（Linux では固定 fd で行うため差し替え競合を避けている。
    /// 非 Linux は暫定。OCI-7）。起点が存在しない・ディレクトリでない・訪問済みなら何もしない。
    #[cfg(not(target_os = "linux"))]
    fn walk_root(&mut self, root: &Path) -> Result<(), TraitError> {
        let Ok(meta) = fs::symlink_metadata(root) else {
            return Ok(());
        };
        if !meta.is_dir() {
            return Ok(());
        }
        let root_id = identity(&meta);
        if let Some(id) = root_id
            && !self.visited_dirs.insert(id)
        {
            return Ok(());
        }
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let rd = match fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    self.usage.inaccessible_entries += 1;
                    continue;
                }
                Err(_) => return Err(terr(ErrorCode::Internal, "failed to read directory")),
            };
            for ent in rd {
                let ent = match ent {
                    Ok(e) => e,
                    Err(e) if e.kind() == ErrorKind::NotFound => continue,
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                        self.usage.inaccessible_entries += 1;
                        continue;
                    }
                    Err(_) => return Err(terr(ErrorCode::Internal, "failed to read entry")),
                };
                self.tick()?;
                let path = ent.path();
                let m = match fs::symlink_metadata(&path) {
                    Ok(m) => m,
                    Err(e) if e.kind() == ErrorKind::NotFound => continue,
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                        self.usage.inaccessible_entries += 1;
                        continue;
                    }
                    Err(_) => return Err(terr(ErrorCode::Internal, "failed to stat entry")),
                };
                if m.is_dir() {
                    if self.should_descend(&m, root_id) {
                        stack.push(path);
                    }
                } else if m.is_file() {
                    self.account_file(&m)?;
                }
            }
        }
        Ok(())
    }
}

/// fd が指す実体を `/proc/self/fd/N` 経由で引くパス（パス文字列は再解決されない）。
#[cfg(target_os = "linux")]
fn fd_path(fd: &std::os::fd::OwnedFd) -> PathBuf {
    use std::os::fd::AsRawFd;
    PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
        GetStateRequest, StateList, StateRecord, StateRevision, UpdateStateRequest,
    };

    /// `list` だけ実データを返す最小の偽ストア（他の操作は使わない）。
    struct FakeStore(Vec<StateRecord>);
    impl StateStore for FakeStore {
        fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(terr(ErrorCode::Unimplemented, "unused"))
        }
        fn update(&self, _: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            Err(terr(ErrorCode::Unimplemented, "unused"))
        }
        fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
            Err(terr(ErrorCode::Unimplemented, "unused"))
        }
        fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
            Ok(StateList::new(self.0.clone(), None))
        }
        fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(terr(ErrorCode::Unimplemented, "unused"))
        }
    }

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fc-cusage-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn rec(bundle: &Path, n: usize) -> StateRecord {
        StateRecord::new(
            ContainerStatus::created(ContainerId::new(format!("c{n}")).unwrap(), None),
            bundle.to_path_buf(),
            StateRevision::INITIAL,
        )
        .unwrap()
    }

    fn config(root_path: &str) -> String {
        format!(r#"{{"ociVersion":"1.2.0","root":{{"path":"{root_path}"}}}}"#)
    }

    /// bundle を作り、`config.json` の長さを返す。
    fn make_bundle(base: &Path, name: &str, root_path: &str) -> (PathBuf, u64) {
        let b = base.join(name);
        fs::create_dir_all(b.join("rootfs")).unwrap();
        let cfg = config(root_path);
        fs::write(b.join("config.json"), &cfg).unwrap();
        (b, cfg.len() as u64)
    }

    /// OCI-7・TASK-183: bundle 内 rootfs・ハードリンク・symlink を具体値で照合する。
    #[test]
    fn oci7_container_usage_counts_files_hardlink_once_and_skips_symlink() {
        let t = Tmp::new("basic");
        let (b, cfg_len) = make_bundle(&t.0, "b1", "rootfs");
        fs::write(b.join("rootfs/a"), vec![0u8; 100]).unwrap();
        fs::create_dir(b.join("rootfs/sub")).unwrap();
        fs::write(b.join("rootfs/sub/b"), vec![0u8; 1000]).unwrap();
        fs::write(b.join("rootfs/sub/c"), vec![0u8; 10000]).unwrap();
        fs::hard_link(b.join("rootfs/a"), b.join("rootfs/a2")).unwrap();
        std::os::unix::fs::symlink(b.join("rootfs/sub/c"), b.join("rootfs/link")).unwrap();
        let u = measure_container_usage(&FakeStore(vec![rec(&b, 1)])).unwrap();
        assert_eq!(u.count, 1);
        assert_eq!(u.bytes, 11100 + cfg_len);
        assert_eq!(u.missing_bundles, 0);
        assert_eq!(u.unreadable_configs, 0);
        assert_eq!(u.mount_points_skipped, 0);
    }

    /// OCI-7・SEC-1: 同じ bundle を共有する 2 コンテナは 1 回だけ数える。
    #[test]
    fn oci7_container_usage_shared_bundle_counted_once() {
        let t = Tmp::new("shared");
        let (b, cfg_len) = make_bundle(&t.0, "b1", "rootfs");
        fs::write(b.join("rootfs/f"), vec![0u8; 2000]).unwrap();
        let u = measure_container_usage(&FakeStore(vec![rec(&b, 1), rec(&b, 2)])).unwrap();
        assert_eq!(u.count, 2);
        assert_eq!(u.bytes, 2000 + cfg_len);
        assert_eq!(u.unreadable_configs, 0);
    }

    /// OCI-7・SEC-1: `..` と bundle 外の絶対パスの root.path は走査せず unreadable_configs に数える。
    #[test]
    fn oci7_container_usage_rejects_escaping_root_path() {
        let t = Tmp::new("escape");
        let ext = t.0.join("ext-rootfs");
        fs::create_dir_all(&ext).unwrap();
        fs::write(ext.join("f"), vec![0u8; 2000]).unwrap();
        let (b1, len1) = make_bundle(&t.0, "b1", ext.to_str().unwrap());
        let (b2, len2) = make_bundle(&t.0, "b2", "../ext-rootfs");
        let u = measure_container_usage(&FakeStore(vec![rec(&b1, 1), rec(&b2, 2)])).unwrap();
        assert_eq!(u.unreadable_configs, 2);
        assert_eq!(u.bytes, len1 + len2);
    }

    /// OCI-7・SEC-1: bundle 内の symlink 経由で外へ出る root.path も走査しない。
    #[test]
    fn oci7_container_usage_rejects_symlink_escape() {
        let t = Tmp::new("symesc");
        let ext = t.0.join("ext-rootfs");
        fs::create_dir_all(&ext).unwrap();
        fs::write(ext.join("f"), vec![0u8; 2000]).unwrap();
        let (b, len) = make_bundle(&t.0, "b1", "link/sub");
        fs::create_dir_all(ext.join("sub")).unwrap();
        std::os::unix::fs::symlink(&ext, b.join("link")).unwrap();
        let u = measure_container_usage(&FakeStore(vec![rec(&b, 1)])).unwrap();
        assert_eq!(u.unreadable_configs, 1);
        assert_eq!(u.bytes, len);
    }

    /// OCI-7: bundle が無ければ missing_bundles、config.json が不正なら unreadable_configs。
    #[test]
    fn oci7_container_usage_reports_missing_bundle_and_unreadable_config() {
        let t = Tmp::new("missing");
        let gone = t.0.join("gone");
        let bad = t.0.join("bad");
        fs::create_dir_all(bad.join("rootfs")).unwrap();
        fs::write(bad.join("config.json"), b"{not json").unwrap();
        fs::write(bad.join("rootfs/x"), vec![0u8; 50]).unwrap();
        let u = measure_container_usage(&FakeStore(vec![rec(&gone, 1), rec(&bad, 2)])).unwrap();
        assert_eq!(u.count, 2);
        assert_eq!(u.missing_bundles, 1);
        assert_eq!(u.unreadable_configs, 1);
        // rootfs は特定できないが bundle 配下は数える（config.json 9 + rootfs/x 50）。
        assert_eq!(u.bytes, 59);
    }

    /// OCI-7: 読めないディレクトリは全体を失敗させず inaccessible に数える。
    #[test]
    fn oci7_container_usage_counts_inaccessible_directory() {
        use std::os::unix::fs::PermissionsExt;
        let t = Tmp::new("perm");
        let (b, cfg_len) = make_bundle(&t.0, "b1", "rootfs");
        fs::write(b.join("rootfs/a"), vec![0u8; 100]).unwrap();
        fs::create_dir(b.join("rootfs/locked")).unwrap();
        fs::write(b.join("rootfs/locked/x"), vec![0u8; 7]).unwrap();
        fs::set_permissions(b.join("rootfs/locked"), fs::Permissions::from_mode(0o000)).unwrap();
        let u = measure_container_usage(&FakeStore(vec![rec(&b, 1)])).unwrap();
        fs::set_permissions(b.join("rootfs/locked"), fs::Permissions::from_mode(0o755)).unwrap();
        // root 実行など権限が効かない環境では中身まで数えた値になる。
        if u.inaccessible_entries == 1 {
            assert_eq!(u.bytes, 100 + cfg_len);
        } else {
            assert_eq!(u.inaccessible_entries, 0);
            assert_eq!(u.bytes, 107 + cfg_len);
        }
    }

    /// OCI-7・SEC-1: ディレクトリへの symlink（祖先を指すループを含む）は辿らず、外の実体を数えない。
    #[test]
    fn oci7_container_usage_does_not_follow_directory_symlinks() {
        let t = Tmp::new("dirlink");
        let ext = t.0.join("ext");
        fs::create_dir_all(&ext).unwrap();
        fs::write(ext.join("big"), vec![0u8; 5000]).unwrap();
        let (b, cfg_len) = make_bundle(&t.0, "b1", "rootfs");
        fs::write(b.join("rootfs/a"), vec![0u8; 10]).unwrap();
        std::os::unix::fs::symlink(&ext, b.join("rootfs/outside")).unwrap();
        std::os::unix::fs::symlink(&b, b.join("rootfs/loop")).unwrap();
        let u = measure_container_usage(&FakeStore(vec![rec(&b, 1)])).unwrap();
        assert_eq!(u.bytes, 10 + cfg_len);
    }

    /// OCI-7: 空の一覧は全 0。
    #[test]
    fn oci7_container_usage_empty_store_is_zero() {
        let u = measure_container_usage(&FakeStore(vec![])).unwrap();
        assert_eq!(u, ContainerDiskUsage::default());
    }

    /// OCI-7: 走査上限は `tick` で `FailedPrecondition`。
    #[test]
    fn oci7_container_usage_scan_limit_is_error() {
        let mut w = Walker::default();
        w.usage.entries_scanned = MAX_CONTAINER_SCAN_ENTRIES;
        assert_eq!(w.tick().unwrap_err().code(), ErrorCode::FailedPrecondition);
    }
}
