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
            Ok(cfg) => Some(bundle.join(cfg.root().path())),
            Err(_) => {
                w.usage.unreadable_configs += 1;
                None
            }
        };
        w.walk_root(bundle)?;
        if let Some(rootfs) = rootfs {
            w.walk_root(&rootfs)?;
        }
    }
    Ok(w.usage)
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

    /// 起点ディレクトリから深さ優先で歩く（再帰なし・symlink は辿らない）。
    /// 起点が存在しない・ディレクトリでない・訪問済みなら何もしない。
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
                    let id = identity(&m);
                    if let (Some((dev, _)), Some((rdev, _))) = (id, root_id)
                        && dev != rdev
                    {
                        self.usage.mount_points_skipped += 1;
                        continue;
                    }
                    if let Some(id) = id
                        && !self.visited_dirs.insert(id)
                    {
                        continue;
                    }
                    stack.push(path);
                } else if m.is_file() {
                    if nlink(&m) > 1
                        && let Some(id) = identity(&m)
                        && !self.seen_links.insert(id)
                    {
                        continue;
                    }
                    self.add_bytes(m.len())?;
                }
            }
        }
        Ok(())
    }
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

    /// OCI-7: bundle 外の絶対パスの rootfs と、同じ bundle を共有する 2 コンテナ。
    #[test]
    fn oci7_container_usage_external_rootfs_and_shared_bundle_counted_once() {
        let t = Tmp::new("ext");
        let ext = t.0.join("ext-rootfs");
        fs::create_dir_all(&ext).unwrap();
        fs::write(ext.join("f"), vec![0u8; 2000]).unwrap();
        let (b, cfg_len) = make_bundle(&t.0, "b1", ext.to_str().unwrap());
        let u = measure_container_usage(&FakeStore(vec![rec(&b, 1), rec(&b, 2)])).unwrap();
        assert_eq!(u.count, 2);
        assert_eq!(u.bytes, 2000 + cfg_len);
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
