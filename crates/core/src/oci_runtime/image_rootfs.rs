//! イメージつき create でレイヤーを rootfs へ展開するための依存注入口と、展開先の作成・後始末
//! （#2342・OCI-7・TASK-183.8 追補・TASK-29）。
//!
//! # 役割と呼び出し元
//!
//! `create::create_with_image` が「参照登録 → config 検証 → 展開先の作成 → 展開 → bundle 検証 → 状態作成」の
//! 順で呼ぶ。展開の実体（`fandhe-container-oci` の `layer::extract`）は oci にあり、core は oci に
//! 依存しない（`docs/architecture.md`）ため、`ContainerImageRefs` と同様に
//! トレイト [`ImageRootfsUnpacker`] を上位 crate が `ImageStore` で満たす。展開先のパスの決定・作成・
//! 失敗時の後始末は core の責務で、本ファイルの `prepare_rootfs_target` と `CreatedRootfs::remove` が担う。
//!
//! 本番の展開器（manifest からレイヤーの blob・mediaType・diff_id を引いて oci へ渡すアダプタ）と
//! CLI / plugin の配線は未実装である（REPAIR-3。#2315 の配線で扱う）。

use std::path::{Component, Path, PathBuf};

use super::image_refs::ImageManifestDigest;
use crate::traits::{ErrorCode, TraitError};

/// 後始末で権限を補正しながら辿る項目数の上限（無制限の走査を避ける。展開側の既定上限と同程度）。
#[cfg(unix)]
const CLEANUP_MAX_ENTRIES: usize = 1_000_000;
/// 後始末で辿るディレクトリの深さの上限。
#[cfg(unix)]
const CLEANUP_MAX_DEPTH: usize = 256;

/// [`ImageRootfsUnpacker::unpack`] の結果（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ImageRootfsUnpacked {
    /// 展開したレイヤーの数。
    pub layers: usize,
}

/// イメージのレイヤーを rootfs へ展開する（OCI-7・#2342）。
///
/// 契約:
///
/// - `rootfs` は core が作った、存在する空のディレクトリ（Unix は実行ユーザー所有の 0700）。oci の
///   `extract_*` の「root は呼び出し側が排他的に所有する既存の空ディレクトリ」と一致する
/// - 展開器は `rootfs` 自体を作り直したり別の場所へ移したりしない
/// - 失敗時に部分的な展開物を残してよい。後始末は core が行う
/// - イメージストアの排他は blob パスの解決に必要な間だけ取り、展開の全体にわたっては保持しない
///   （呼び出し元が参照を登録済みで、GC から blob は守られる。REPAIR-5）
/// - 展開量・件数の上限を必ず課す（無制限の展開をしない）
/// - digest・diff_id の検証、mediaType の選択、所有者の写像、特殊ビットの扱いは実装側の責務
/// - エラーメッセージにパス・OS のエラー文字列を含めない
pub trait ImageRootfsUnpacker {
    /// `manifest` のレイヤーを下位から順に `rootfs` へ展開する。
    fn unpack(
        &self,
        manifest: &ImageManifestDigest,
        rootfs: &Path,
    ) -> Result<ImageRootfsUnpacked, TraitError>;
}

/// core が排他的に作った rootfs ディレクトリ（展開途中の後始末の対象）。
///
/// Linux では作成時に検証した親ディレクトリの fd を保持し、作成と後始末を `mkdirat` / `unlinkat` 等の
/// fd 相対・リンク非追従の操作だけで行う（作成後に親を symlink へ差し替えられても bundle 外に作用しない）。
/// Linux 以外の Unix は経路の lstat と dev・ino の照合による best effort、Windows は同一性を保証できない
/// ため後始末を拒否する（fail-closed。ハンドルのファイル ID 照合は未実装。REPAIR-3）。
#[derive(Debug)]
pub(super) struct CreatedRootfs {
    path: PathBuf,
    backing: imp::Backing,
}

fn invalid(message: &str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, message)
}

fn refuse() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "rootfs was replaced; refusing to remove",
    )
}

#[cfg(unix)]
fn remove_failed() -> TraitError {
    TraitError::new(ErrorCode::Internal, "failed to remove rootfs")
}

/// `root.path` の経路を検査し、末尾の要素を空のディレクトリとして排他的に作る。
///
/// `check_rootfs` と同じ規則（`..`・ファイルシステムのルート・bundle 外の絶対指定・中間要素の
/// symlink / junction を拒否）に加え、末尾が既に存在すれば `AlreadyExists` で拒否して利用者の既存データへ
/// 展開しない。相対部分が空（rootfs が bundle そのもの）は拒否する。
pub(super) fn prepare_rootfs_target(
    bundle: &Path,
    root_path: &Path,
) -> Result<CreatedRootfs, TraitError> {
    if root_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(invalid("root.path must not contain '..'"));
    }
    let rootfs = bundle.join(root_path);
    if !rootfs
        .components()
        .any(|c| matches!(c, Component::Normal(_)))
    {
        return Err(invalid("rootfs must not be the filesystem root"));
    }
    let rel = rootfs
        .strip_prefix(bundle)
        .map_err(|_| invalid("rootfs must be inside the bundle"))?;
    let parts: Vec<_> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(p) => Some(p),
            _ => None,
        })
        .collect();
    let Some((last, parents)) = parts.split_last() else {
        return Err(invalid("rootfs must be a directory below the bundle"));
    };
    let backing = imp::create_dir(bundle, parents, last)?;
    // 正規化した（Normal 要素だけの）経路。
    let path = parts.iter().fold(bundle.to_path_buf(), |mut p, part| {
        p.push(part);
        p
    });
    Ok(CreatedRootfs { path, backing })
}

impl CreatedRootfs {
    /// 作った rootfs のパス（bundle 配下。Normal 要素だけの正規化済みの経路）。
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// 展開途中の rootfs を消す。
    ///
    /// 作成時に固定した親（Linux は fd）の下で、末尾が作ったときと同じディレクトリ（dev・ino）で
    /// なければ削除しない（`FailedPrecondition`。差し替えられた先 = bundle 外の実体を消さない fail-closed）。
    pub(super) fn remove(self) -> Result<(), TraitError> {
        imp::remove(&self.path, self.backing)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    //! Linux: 親ディレクトリの fd を保持して fd 相対・リンク非追従で作成・後始末する。

    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;

    use super::{CLEANUP_MAX_DEPTH, CLEANUP_MAX_ENTRIES, invalid, refuse, remove_failed};
    use crate::sys::{self, SysError};
    use crate::traits::{ErrorCode, TraitError};

    /// 検証済みの親ディレクトリの fd と、その下の rootfs の名前・同一性。
    #[derive(Debug)]
    pub(super) struct Backing {
        parent: OwnedFd,
        name: CString,
        identity: (u64, u64),
    }

    fn cstr(s: &OsStr) -> Result<CString, TraitError> {
        CString::new(s.as_bytes()).map_err(|_| invalid("rootfs path contains a NUL byte"))
    }

    /// `parent` 配下の `name` をリンク非追従のディレクトリとして開く。
    fn open_dir(parent: BorrowedFd<'_>, name: &CString) -> Result<OwnedFd, TraitError> {
        sys::open_dir_path_nofollow(Some(parent), name).map_err(|e| match e {
            SysError::Os(n) if n == sys::ENOTDIR || n == sys::ELOOP => {
                invalid("rootfs must not contain a symlink or a non-directory")
            }
            SysError::Os(n) if n == sys::ENOENT => {
                TraitError::new(ErrorCode::NotFound, "rootfs parent directory not found")
            }
            SysError::Os(n) if n == sys::EACCES || n == sys::EPERM => {
                TraitError::new(ErrorCode::PermissionDenied, "cannot access rootfs")
            }
            _ => TraitError::new(ErrorCode::Internal, "failed to open rootfs directory"),
        })
    }

    /// fd の指す実体の (dev, ino, ディレクトリか, mode)。fd は複製して `File` として fstat する。
    fn fstat(fd: BorrowedFd<'_>) -> Result<(u64, u64, bool, u32), std::io::Error> {
        let file = File::from(fd.try_clone_to_owned()?);
        let m = file.metadata()?;
        Ok((m.dev(), m.ino(), m.is_dir(), m.mode()))
    }

    pub(super) fn create_dir(
        bundle: &Path,
        parents: &[&OsStr],
        last: &OsStr,
    ) -> Result<Backing, TraitError> {
        // bundle そのものは呼び出し側が渡した経路（上位が symlink でもよい）。追従して開き、以降は fd で固定する。
        let file = File::open(bundle).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                TraitError::new(ErrorCode::NotFound, "bundle directory not found")
            }
            std::io::ErrorKind::PermissionDenied => {
                TraitError::new(ErrorCode::PermissionDenied, "cannot access bundle")
            }
            _ => TraitError::new(ErrorCode::Internal, "failed to open bundle"),
        })?;
        if !file.metadata().map(|m| m.is_dir()).unwrap_or(false) {
            return Err(invalid("bundle is not a directory"));
        }
        let mut cur = OwnedFd::from(file);
        for part in parents {
            cur = open_dir(cur.as_fd(), &cstr(part)?)?;
        }
        let name = cstr(last)?;
        sys::mkdir_at(cur.as_fd(), &name, 0o700).map_err(|e| match e {
            SysError::Os(n) if n == sys::EEXIST => {
                TraitError::new(ErrorCode::AlreadyExists, "rootfs already exists")
            }
            SysError::Os(n) if n == sys::ENOENT || n == sys::ENOTDIR => {
                TraitError::new(ErrorCode::NotFound, "rootfs parent directory not found")
            }
            SysError::Os(n) if n == sys::EACCES || n == sys::EPERM => {
                TraitError::new(ErrorCode::PermissionDenied, "cannot create rootfs")
            }
            _ => TraitError::new(ErrorCode::Internal, "failed to create rootfs"),
        })?;
        let identity = match open_dir(cur.as_fd(), &name)
            .ok()
            .and_then(|fd| fstat(fd.as_fd()).ok())
        {
            Some((dev, ino, true, _)) => (dev, ino),
            _ => {
                // 作った直後に差し替えられた。固定済みの親の下の空ディレクトリだけを best effort で戻す。
                let _ = sys::remove_dir_at(cur.as_fd(), &name);
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    "created rootfs is not a directory",
                ));
            }
        };
        Ok(Backing {
            parent: cur,
            name,
            identity,
        })
    }

    pub(super) fn remove(_path: &Path, b: Backing) -> Result<(), TraitError> {
        let root = match sys::open_dir_path_nofollow(Some(b.parent.as_fd()), &b.name) {
            Ok(fd) => fd,
            // 既に無ければ消す物が無い。
            Err(SysError::Os(n)) if n == sys::ENOENT => return Ok(()),
            Err(_) => return Err(refuse()),
        };
        match fstat(root.as_fd()) {
            Ok((dev, ino, true, _)) if (dev, ino) == b.identity => {}
            _ => return Err(refuse()),
        }
        let mut seen = 0usize;
        remove_children(root.as_fd(), 0, &mut seen)?;
        match sys::remove_dir_at(b.parent.as_fd(), &b.name) {
            Ok(()) => Ok(()),
            Err(SysError::Os(n)) if n == sys::ENOENT => Ok(()),
            Err(_) => Err(remove_failed()),
        }
    }

    /// `dir`（固定済みの fd）の中身を、fd 相対・リンク非追従で再帰的に消す（件数・深さの上限つき）。
    ///
    /// 展開が適用した読み取り専用の mode は、ディレクトリごとに所有者の rwx を足して戻す。
    /// 列挙と chmod は `/proc/self/fd/N` 経由（magic link は fd の実体へ解決され、経路は再解決されない）。
    fn remove_children(
        dir: BorrowedFd<'_>,
        depth: usize,
        seen: &mut usize,
    ) -> Result<(), TraitError> {
        if depth > CLEANUP_MAX_DEPTH {
            return Err(remove_failed());
        }
        let proc_path = format!("/proc/self/fd/{}", dir.as_raw_fd());
        let (_, _, is_dir, mode) = fstat(dir).map_err(|_| remove_failed())?;
        if !is_dir {
            return Err(remove_failed());
        }
        if mode & 0o700 != 0o700 {
            std::fs::set_permissions(&proc_path, std::fs::Permissions::from_mode(mode | 0o700))
                .map_err(|_| remove_failed())?;
        }
        for entry in std::fs::read_dir(&proc_path).map_err(|_| remove_failed())? {
            let entry = entry.map_err(|_| remove_failed())?;
            *seen += 1;
            if *seen > CLEANUP_MAX_ENTRIES {
                return Err(remove_failed());
            }
            let name = cstr(&entry.file_name())?;
            let child = match sys::open_path_nofollow_at(dir, &name) {
                Ok(fd) => fd,
                Err(SysError::Os(n)) if n == sys::ENOENT => continue,
                Err(_) => return Err(remove_failed()),
            };
            let is_child_dir = fstat(child.as_fd())
                .map(|(_, _, d, _)| d)
                .map_err(|_| remove_failed())?;
            if is_child_dir {
                remove_children(child.as_fd(), depth + 1, seen)?;
                sys::remove_dir_at(dir, &name).map_err(|_| remove_failed())?;
            } else {
                sys::remove_file_at(dir, &name).map_err(|_| remove_failed())?;
            }
        }
        Ok(())
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod imp {
    //! Linux 以外の Unix: 経路の lstat と dev・ino の照合による best effort（fd 相対の操作は未実装）。

    use std::ffi::OsStr;
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    use super::{CLEANUP_MAX_DEPTH, CLEANUP_MAX_ENTRIES, invalid, refuse, remove_failed};
    use crate::oci_runtime::create::{inspect, is_link_like};
    use crate::traits::{ErrorCode, TraitError};

    #[derive(Debug)]
    pub(super) struct Backing {
        bundle: PathBuf,
        identity: (u64, u64),
    }

    pub(super) fn create_dir(
        bundle: &Path,
        parents: &[&OsStr],
        last: &OsStr,
    ) -> Result<Backing, TraitError> {
        let mut current = bundle.to_path_buf();
        for part in parents {
            current.push(part);
            let meta = inspect(&current)?;
            if is_link_like(&meta) {
                return Err(invalid("rootfs must not contain a symlink"));
            }
            if !meta.is_dir() {
                return Err(invalid("rootfs parent is not a directory"));
            }
        }
        current.push(last);
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&current).map_err(|e| match e.kind() {
            io::ErrorKind::AlreadyExists => {
                TraitError::new(ErrorCode::AlreadyExists, "rootfs already exists")
            }
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => {
                TraitError::new(ErrorCode::NotFound, "rootfs parent directory not found")
            }
            io::ErrorKind::PermissionDenied => {
                TraitError::new(ErrorCode::PermissionDenied, "cannot create rootfs")
            }
            _ => TraitError::new(ErrorCode::Internal, "failed to create rootfs"),
        })?;
        let meta = inspect(&current)?;
        if is_link_like(&meta) || !meta.is_dir() {
            return Err(TraitError::new(
                ErrorCode::Internal,
                "created rootfs is not a directory",
            ));
        }
        Ok(Backing {
            bundle: bundle.to_path_buf(),
            identity: (meta.dev(), meta.ino()),
        })
    }

    pub(super) fn remove(path: &Path, b: Backing) -> Result<(), TraitError> {
        let rel = path.strip_prefix(&b.bundle).map_err(|_| refuse())?;
        let parts: Vec<_> = rel.components().collect();
        let mut current = b.bundle.clone();
        for (i, c) in parts.iter().enumerate() {
            let std::path::Component::Normal(part) = c else {
                return Err(refuse());
            };
            current.push(part);
            let meta = match std::fs::symlink_metadata(&current) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(_) => return Err(remove_failed()),
            };
            if is_link_like(&meta) || !meta.is_dir() {
                return Err(refuse());
            }
            if i + 1 == parts.len() && (meta.dev(), meta.ino()) != b.identity {
                return Err(refuse());
            }
        }
        match std::fs::remove_dir_all(&current) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                restore_owner_access(&current)?;
                std::fs::remove_dir_all(&current).map_err(|_| remove_failed())
            }
            Err(_) => Err(remove_failed()),
        }
    }

    fn restore_owner_access(root: &Path) -> Result<(), TraitError> {
        let mut stack = vec![(root.to_path_buf(), 0usize)];
        let mut seen = 0usize;
        while let Some((dir, depth)) = stack.pop() {
            if depth > CLEANUP_MAX_DEPTH {
                return Err(remove_failed());
            }
            let meta = std::fs::symlink_metadata(&dir).map_err(|_| remove_failed())?;
            if !meta.file_type().is_dir() {
                continue;
            }
            let mut perms = meta.permissions();
            perms.set_mode(perms.mode() | 0o700);
            std::fs::set_permissions(&dir, perms).map_err(|_| remove_failed())?;
            for entry in std::fs::read_dir(&dir).map_err(|_| remove_failed())? {
                let entry = entry.map_err(|_| remove_failed())?;
                seen += 1;
                if seen > CLEANUP_MAX_ENTRIES {
                    return Err(remove_failed());
                }
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    stack.push((entry.path(), depth + 1));
                }
            }
        }
        Ok(())
    }
}

#[cfg(not(unix))]
mod imp {
    //! Windows 等: ファイル ID とボリューム識別子をハンドルから照合する実装が無いため、後始末は拒否する
    //! （fail-closed。REPAIR-3: 実装済みを装わない）。

    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};

    use super::{invalid, refuse};
    use crate::oci_runtime::create::{inspect, is_link_like};
    use crate::traits::{ErrorCode, TraitError};

    #[derive(Debug)]
    pub(super) struct Backing;

    pub(super) fn create_dir(
        bundle: &Path,
        parents: &[&OsStr],
        last: &OsStr,
    ) -> Result<Backing, TraitError> {
        let mut current: PathBuf = bundle.to_path_buf();
        for part in parents {
            current.push(part);
            let meta = inspect(&current)?;
            if is_link_like(&meta) {
                return Err(invalid("rootfs must not contain a symlink"));
            }
            if !meta.is_dir() {
                return Err(invalid("rootfs parent is not a directory"));
            }
        }
        current.push(last);
        std::fs::DirBuilder::new()
            .create(&current)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    TraitError::new(ErrorCode::AlreadyExists, "rootfs already exists")
                }
                std::io::ErrorKind::NotFound => {
                    TraitError::new(ErrorCode::NotFound, "rootfs parent directory not found")
                }
                std::io::ErrorKind::PermissionDenied => {
                    TraitError::new(ErrorCode::PermissionDenied, "cannot create rootfs")
                }
                _ => TraitError::new(ErrorCode::Internal, "failed to create rootfs"),
            })?;
        Ok(Backing)
    }

    pub(super) fn remove(_path: &Path, _b: Backing) -> Result<(), TraitError> {
        Err(refuse())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fandhe-image-rootfs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    /// OCI-7: 空の rootfs を作り、remove で消せる。
    #[cfg(unix)]
    #[test]
    fn oci7_prepare_creates_empty_dir_and_remove_deletes_it() {
        let b = tmp("basic");
        let c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        assert_eq!(c.path(), b.join("rootfs"));
        assert_eq!(std::fs::read_dir(c.path()).expect("read").count(), 0);
        std::fs::write(c.path().join("f"), b"x").expect("write");
        c.remove().expect("remove");
        assert!(!b.join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 既存の rootfs・bundle 自身・`..` は拒否し、既存の中身に触れない。
    #[test]
    fn oci7_prepare_rejects_existing_bundle_itself_and_parent_dir() {
        let b = tmp("reject");
        std::fs::create_dir(b.join("rootfs")).expect("mk");
        std::fs::write(b.join("rootfs").join("keep"), b"x").expect("w");
        let e = prepare_rootfs_target(&b, Path::new("rootfs")).expect_err("exists");
        assert_eq!(e.code(), ErrorCode::AlreadyExists);
        assert!(b.join("rootfs").join("keep").exists());
        let e = prepare_rootfs_target(&b, Path::new(".")).expect_err("bundle itself");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        let e = prepare_rootfs_target(&b, Path::new("../x")).expect_err("parent");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 読み取り専用 mode の木も権限を補正して消せる。
    #[cfg(unix)]
    #[test]
    fn oci7_remove_restores_permissions_for_read_only_tree() {
        use std::os::unix::fs::PermissionsExt;
        let b = tmp("ro");
        let c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        let sub = c.path().join("sub");
        std::fs::create_dir(&sub).expect("sub");
        std::fs::write(sub.join("f"), b"x").expect("f");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o555)).expect("ro");
        c.remove().expect("remove");
        assert!(!b.join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 中間要素が symlink なら拒否し、bundle 外に何も作らない。
    #[cfg(unix)]
    #[test]
    fn oci7_prepare_rejects_symlink_parent() {
        let b = tmp("symparent");
        let outside = tmp("symparent-out");
        std::os::unix::fs::symlink(&outside, b.join("link")).expect("symlink");
        let e = prepare_rootfs_target(&b, Path::new("link/rootfs")).expect_err("symlink");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert_eq!(std::fs::read_dir(&outside).expect("read").count(), 0);
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// OCI-7: 差し替えられた rootfs（symlink）は消さない。
    #[cfg(unix)]
    #[test]
    fn oci7_remove_refuses_replaced_rootfs() {
        let b = tmp("replaced");
        let outside = tmp("replaced-out");
        std::fs::write(outside.join("marker"), b"x").expect("marker");
        let c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        std::fs::remove_dir(c.path()).expect("rm");
        std::os::unix::fs::symlink(&outside, c.path()).expect("symlink");
        let e = c.remove().expect_err("refuse");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(outside.join("marker").exists());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// SEC-1: 作成後に親ディレクトリが symlink へ差し替えられても、後始末は固定済みの親の下だけを消し、
    /// 差し替え先（bundle 外）には触れない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_ignores_parent_swapped_for_symlink() {
        let b = tmp("parentswap");
        let outside = tmp("parentswap-out");
        std::fs::create_dir(b.join("p")).expect("p");
        let c = prepare_rootfs_target(&b, Path::new("p/rootfs")).expect("prepare");
        std::fs::write(c.path().join("mine"), b"x").expect("mine");
        std::fs::create_dir(outside.join("rootfs")).expect("o rootfs");
        std::fs::write(outside.join("rootfs").join("marker"), b"x").expect("marker");
        std::fs::rename(b.join("p"), b.join("p_moved")).expect("move");
        std::os::unix::fs::symlink(&outside, b.join("p")).expect("symlink");
        c.remove().expect("remove");
        assert!(outside.join("rootfs").join("marker").exists());
        assert!(!b.join("p_moved").join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// SEC-1: 後始末は木の内側の symlink を辿らず、リンク自体だけを消す。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_does_not_follow_symlinks_inside_tree() {
        let b = tmp("innerlink");
        let outside = tmp("innerlink-out");
        std::fs::write(outside.join("marker"), b"x").expect("marker");
        let c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        std::os::unix::fs::symlink(&outside, c.path().join("dirlink")).expect("symlink");
        c.remove().expect("remove");
        assert!(outside.join("marker").exists());
        assert!(!b.join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// OCI-7: 返す経路は正規化済みで、等価な書き方の `root.path` でも同じ場所に作る。
    #[test]
    fn oci7_prepare_normalizes_path() {
        let b = tmp("normalize");
        let c = prepare_rootfs_target(&b, Path::new("./rootfs/")).expect("prepare");
        assert_eq!(c.path(), b.join("rootfs"));
        assert!(b.join("rootfs").is_dir());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: Windows は同一性を保証できないため後始末を拒否し、展開物を残す。
    #[cfg(not(unix))]
    #[test]
    fn oci7_remove_refuses_without_identity_check() {
        let b = tmp("winrefuse");
        let c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        let e = c.remove().expect_err("refuse");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(b.join("rootfs").is_dir());
        let _ = std::fs::remove_dir_all(&b);
    }
}
