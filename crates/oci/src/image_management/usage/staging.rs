//! pull 中のステージング領域 `<root>/staging/<pull-id>/<hex>` の使用容量（OCI-7・TASK-183・#2222）。
//!
//! 配置は `pull` モジュール（#474）で確定済み。`ReferenceTable::disk_usage` が 1 階層だけ走査して
//! `DiskUsage::staging` に載せる（メタデータだけの走査なのでガードの内側でも軽い）。
//!
//! サイズの定義は blob キャッシュと同じ見かけのサイズ。書き込み途中の一時名も実使用量として含める
//! （名前では絞らない）。キャッシュ側の `bytes` / `images.bytes` には混ぜない。
//! 検査済み root の fd 起点で読む（#2695）。パス起点の実装（macOS・Windows 等）は従来どおり。
//! 所有者専用の領域なので、`stat` の失敗は `NotFound`（pull の完了と競合）以外は過少計上せず
//! `Internal` で失敗させる（`scan_cache` と同じ方針）。

use super::{MAX_CACHE_SCAN_ENTRIES, add, err};
use crate::error::{OciError, OciErrorCode};
use crate::image_management::PullId;
use crate::image_management::pull::STAGING_DIR_NAME;
use crate::image_management::root_handle::{RootHandle, SubDirError};

/// ステージング領域の使用容量。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct StagingUsage {
    /// `<pull-id>` ディレクトリの数。
    pub pulls: usize,
    /// `<pull-id>` 直下の通常ファイルの数。
    pub file_count: usize,
    /// 上記の見かけのサイズの合計。
    pub bytes: u64,
    /// 数えなかったエントリ数（`staging` 直下の通常ディレクトリ以外・不正な名前、`<pull-id>` 内の
    /// サブディレクトリ・symlink 等）。中へは降りない。
    pub foreign_entries: usize,
}

/// `<root>/staging` を走査する。無ければ全 0、symlink・非ディレクトリは `FailedPrecondition`、
/// エントリ数が `MAX_CACHE_SCAN_ENTRIES` を超えたら `ResourceExhausted`。
///
/// 検査済み root の fd 起点で読む（#2695）。`staging` と各 `<pull-id>` は開いたディレクトリの fd から
/// 辿り、stat と open の間に差し替えられた `<pull-id>`（symlink 等）は中へ降りず foreign に数える。
pub(super) fn scan_staging(root: &RootHandle) -> Result<StagingUsage, OciError> {
    let dir = match root.open_subdir(STAGING_DIR_NAME) {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(StagingUsage::default()),
        Err(SubDirError::NotPlain) => {
            return Err(err(
                OciErrorCode::FailedPrecondition,
                "staging is not a plain directory",
            ));
        }
        Err(SubDirError::Io) => return Err(err(OciErrorCode::Internal, "failed to stat staging")),
    };
    let mut usage = StagingUsage::default();
    let mut seen = 0usize;
    let rd = dir
        .entries()
        .map_err(|_| err(OciErrorCode::Internal, "failed to read staging directory"))?;
    for ent in rd {
        let name = ent.map_err(|_| err(OciErrorCode::Internal, "failed to read staging entry"))?;
        bump(&mut seen)?;
        let valid_name = name.to_str().is_some_and(|n| PullId::new(n).is_ok());
        let meta = match dir.stat(&name) {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(_) => return Err(err(OciErrorCode::Internal, "failed to stat staging entry")),
        };
        if !valid_name || !meta.is_dir() {
            usage.foreign_entries += 1;
            continue;
        }
        let pull = match dir.open_subdir(&name) {
            Ok(Some(d)) => d,
            // pull の完了（公開・ロールバック）と競合して消えた。
            Ok(None) => continue,
            // stat の後に通常ディレクトリでないものへ差し替えられた。降りずに foreign とする。
            Err(SubDirError::NotPlain) => {
                usage.foreign_entries += 1;
                continue;
            }
            Err(SubDirError::Io) => {
                return Err(err(
                    OciErrorCode::Internal,
                    "failed to read pull staging directory",
                ));
            }
        };
        let inner = pull.entries().map_err(|_| {
            err(
                OciErrorCode::Internal,
                "failed to read pull staging directory",
            )
        })?;
        usage.pulls += 1;
        for f in inner {
            let fname =
                f.map_err(|_| err(OciErrorCode::Internal, "failed to read pull staging entry"))?;
            bump(&mut seen)?;
            let m = match pull.stat(&fname) {
                Ok(Some(m)) => m,
                Ok(None) => continue,
                Err(_) => {
                    return Err(err(
                        OciErrorCode::Internal,
                        "failed to stat pull staging entry",
                    ));
                }
            };
            // 生存確認用のロックファイル（#852）は blob ではないので数えない。
            if fname == super::super::pull::PULL_LOCK_FILE_NAME && m.is_file() {
                continue;
            }
            if m.is_file() {
                usage.file_count += 1;
                usage.bytes = add(usage.bytes, m.len())?;
            } else {
                usage.foreign_entries += 1;
            }
        }
    }
    Ok(usage)
}

fn bump(seen: &mut usize) -> Result<(), OciError> {
    *seen += 1;
    if *seen > MAX_CACHE_SCAN_ENTRIES {
        return Err(err(
            OciErrorCode::ResourceExhausted,
            "too many entries in staging directory",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image_management::root_handle::rh;
    use std::fs;

    struct Root(std::path::PathBuf);
    impl Root {
        fn new(tag: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("fc-oci-staging-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Root(p)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// OCI-7: pull 2 件（300 + 40 と 5 バイト）の件数とバイト数を具体値で照合する。
    #[test]
    fn oci7_staging_counts_pulls_files_and_bytes() {
        let r = Root::new("basic");
        let s = r.0.join("staging");
        fs::create_dir_all(s.join("p1")).unwrap();
        fs::create_dir_all(s.join("p2")).unwrap();
        fs::write(s.join("p1").join("aa"), vec![0u8; 300]).unwrap();
        fs::write(s.join("p1").join("bb.tmp"), vec![0u8; 40]).unwrap();
        fs::write(s.join("p2").join("cc"), vec![0u8; 5]).unwrap();
        let u = scan_staging(&rh(&r.0)).unwrap();
        assert_eq!(
            u,
            StagingUsage {
                pulls: 2,
                file_count: 3,
                bytes: 345,
                foreign_entries: 0
            }
        );
    }

    /// OCI-7: `@pull.lock`（#852）は file_count・bytes・foreign_entries のいずれにも入らない。
    #[test]
    fn oci7_staging_ignores_pull_lock_file() {
        let r = Root::new("lockfile");
        let s = r.0.join("staging");
        fs::create_dir_all(s.join("p1")).unwrap();
        fs::write(s.join("p1").join("@pull.lock"), vec![0u8; 9]).unwrap();
        fs::write(s.join("p1").join("aa"), vec![0u8; 10]).unwrap();
        let u = scan_staging(&rh(&r.0)).unwrap();
        assert_eq!(
            u,
            StagingUsage {
                pulls: 1,
                file_count: 1,
                bytes: 10,
                foreign_entries: 0
            }
        );
    }

    /// OCI-7: staging が無ければ全 0。
    #[test]
    fn oci7_staging_missing_is_zero() {
        let r = Root::new("none");
        assert_eq!(scan_staging(&rh(&r.0)).unwrap(), StagingUsage::default());
    }

    /// OCI-7: staging が非ディレクトリなら FailedPrecondition。
    #[test]
    fn oci7_staging_rejects_non_directory() {
        let r = Root::new("file");
        fs::write(r.0.join("staging"), b"x").unwrap();
        let e = scan_staging(&rh(&r.0)).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    }

    /// OCI-7: symlink の staging は辿らず拒否する。
    #[cfg(unix)]
    #[test]
    fn oci7_staging_rejects_symlink() {
        let r = Root::new("symlink");
        let other = r.0.join("other");
        fs::create_dir_all(&other).unwrap();
        std::os::unix::fs::symlink(&other, r.0.join("staging")).unwrap();
        let e = scan_staging(&rh(&r.0)).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    }

    /// OCI-7: 直下の通常ファイル・pull 内のサブディレクトリ・symlink は foreign で、バイトに入れない。
    #[cfg(unix)]
    #[test]
    fn oci7_staging_counts_foreign_entries_without_descending() {
        let r = Root::new("foreign");
        let s = r.0.join("staging");
        fs::create_dir_all(s.join("p1").join("subdir")).unwrap();
        fs::write(s.join("p1").join("subdir").join("big"), vec![0u8; 999]).unwrap();
        fs::write(s.join("p1").join("aa"), vec![0u8; 10]).unwrap();
        std::os::unix::fs::symlink(s.join("p1").join("aa"), s.join("p1").join("lnk")).unwrap();
        fs::write(s.join("stray"), vec![0u8; 77]).unwrap();
        std::os::unix::fs::symlink(&s, s.join("p-link")).unwrap();
        let u = scan_staging(&rh(&r.0)).unwrap();
        assert_eq!(u.pulls, 1);
        assert_eq!(u.file_count, 1);
        assert_eq!(u.bytes, 10);
        // subdir・lnk（pull 内）と stray・p-link（直下）。
        assert_eq!(u.foreign_entries, 4);
    }
}
