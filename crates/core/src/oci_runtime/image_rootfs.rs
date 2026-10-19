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
#[cfg(target_os = "linux")]
const CLEANUP_MAX_ENTRIES: usize = 1_000_000;
/// 後始末で辿るディレクトリの深さの上限。
#[cfg(target_os = "linux")]
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
/// - `rootfs` は core が作った、存在する空のディレクトリ（Unix は実行ユーザー所有の 0700）を指す経路。oci の
///   `extract_*` の「root は呼び出し側が排他的に所有する既存の空ディレクトリ」と一致する
/// - Linux では、`rootfs` は core が保持するディレクトリ fd を指す `/proc/self/fd/N`（bundle 配下の経路ではない）で、
///   最終要素が symlink（magic link）である。作成後に bundle 内の中間ディレクトリを symlink へ差し替えられても、
///   展開先は固定したディレクトリのままで bundle 外へ書かない（SEC-1）。展開器は `rootfs` を開くとき
///   最終要素の symlink を辿ること（`O_NOFOLLOW` を付けて開かない）。以降の要素は `rootfs` 配下を fd 相対・
///   リンク非追従で扱うこと。この経路は展開の呼び出しの間だけ有効で、保持・保存してはならない
///   （Linux 以外は bundle 配下の経路そのもの。後始末は拒否されるため展開物が残りうる）
/// - 展開中の rootfs は、Linux では最終の `root.path` とは別の非公開の名前にあり、展開の成功後に core が
///   最終の名前へ公開する（展開中に別の create が rootfs を使用中と見なして成功する競合を防ぐ。OCI-7）
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
/// Linux では作成時に検証した親ディレクトリの fd を保持し、作成・展開先の指定・公開・後始末を `mkdirat` /
/// `renameat2` / `unlinkat` 等の fd 相対・リンク非追従の操作だけで行う（作成後に親を symlink へ差し替えられても
/// bundle 外に作用しない）。展開は非公開の名前で行い、成功後に [`CreatedRootfs::publish`] で最終の名前へ
/// 改名する。Linux 以外（macOS 等の Unix・Windows）は fd 相対の操作が未実装で、経路を再解決する
/// 後始末は差し替えで bundle 外を消しうるため、後始末を拒否する（fail-closed。展開物が残る。REPAIR-3）。
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

#[cfg(target_os = "linux")]
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

    /// 展開器へ渡す経路（[`ImageRootfsUnpacker::unpack`] の契約）。Linux は保持した fd を指す
    /// `/proc/self/fd/N`、それ以外は [`Self::path`] と同じ。
    pub(super) fn unpack_path(&self) -> PathBuf {
        imp::unpack_path(&self.path, &self.backing)
    }

    /// 展開済みの rootfs を最終の名前（`root.path`）へ公開する。公開後は他の create が rootfs として見る。
    ///
    /// Linux は固定した親の下で `renameat2(RENAME_NOREPLACE)` により改名し、最終の名前が既にあれば
    /// `AlreadyExists`（置き換えない）。Linux 以外は作成時から最終の名前にあるため何もしない。
    pub(super) fn publish(&mut self) -> Result<(), TraitError> {
        imp::publish(&mut self.backing)
    }

    /// rootfs を消す。
    ///
    /// 作成時に固定した親（Linux は fd）の下で、末尾が作ったときと同じディレクトリ（dev・ino）で
    /// なければ削除しない（`FailedPrecondition`。差し替えられた先 = bundle 外の実体を消さない fail-closed）。
    /// Linux 以外は同一性を保証できないため常に `FailedPrecondition` で拒否する。
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
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{CLEANUP_MAX_DEPTH, CLEANUP_MAX_ENTRIES, invalid, refuse, remove_failed};
    use crate::sys::{self, SysError};
    use crate::traits::{ErrorCode, TraitError};

    /// 非公開の展開先の名前の連番（同一プロセス内の衝突を避ける。別プロセスとは pid で分ける）。
    static STAGING_SEQ: AtomicU64 = AtomicU64::new(0);

    /// 検証済みの親ディレクトリの fd と、その下の rootfs の名前・同一性。
    ///
    /// 作成直後は `current` が非公開の展開先の名前で、`publish` 後に最終の名前 `final_name` になる。
    #[derive(Debug)]
    pub(super) struct Backing {
        parent: OwnedFd,
        final_name: CString,
        current: CString,
        /// 作った rootfs ディレクトリそのものの fd（展開器へ `/proc/self/fd/N` で渡す）。
        dir: OwnedFd,
        identity: (u64, u64),
    }

    pub(super) fn unpack_path(_path: &Path, b: &Backing) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", b.dir.as_raw_fd()))
    }

    pub(super) fn publish(b: &mut Backing) -> Result<(), TraitError> {
        if b.current == b.final_name {
            return Ok(());
        }
        sys::rename_noreplace_at(
            b.parent.as_fd(),
            &b.current,
            b.parent.as_fd(),
            &b.final_name,
        )
        .map_err(|e| match e {
            SysError::Os(n) if n == sys::EEXIST || n == sys::ENOTEMPTY => {
                TraitError::new(ErrorCode::AlreadyExists, "rootfs already exists")
            }
            _ => TraitError::new(ErrorCode::Internal, "failed to publish rootfs"),
        })?;
        b.current = b.final_name.clone();
        Ok(())
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
        let final_name = cstr(last)?;
        // 最終の名前が既にあれば展開せずに拒否する（利用者の既存データへ展開しない。公開時の
        // `RENAME_NOREPLACE` が最終的な排他）。
        match sys::open_path_nofollow_at(cur.as_fd(), &final_name) {
            Ok(_) => {
                return Err(TraitError::new(
                    ErrorCode::AlreadyExists,
                    "rootfs already exists",
                ));
            }
            Err(SysError::Os(n)) if n == sys::ENOENT => {}
            Err(_) => {
                return Err(TraitError::new(
                    ErrorCode::Internal,
                    "failed to create rootfs",
                ));
            }
        }
        let staging = format!(
            ".fandhe-unpack-{}-{}",
            std::process::id(),
            STAGING_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let name = cstr(OsStr::new(&staging))?;
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
        let opened = open_dir(cur.as_fd(), &name).ok().and_then(|fd| {
            fstat(fd.as_fd())
                .ok()
                .map(|(dev, ino, is_dir, _)| (fd, dev, ino, is_dir))
        });
        let (dir, identity) = match opened {
            Some((fd, dev, ino, true)) => (fd, (dev, ino)),
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
            final_name,
            current: name,
            dir,
            identity,
        })
    }

    pub(super) fn remove(_path: &Path, b: Backing) -> Result<(), TraitError> {
        let root = match sys::open_dir_path_nofollow(Some(b.parent.as_fd()), &b.current) {
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
        match sys::remove_dir_at(b.parent.as_fd(), &b.current) {
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

#[cfg(not(target_os = "linux"))]
mod imp {
    //! Linux 以外（macOS 等の Unix・Windows）: fd 相対の作成・削除が未実装のため、経路を再解決して
    //! 削除すると中間要素の差し替えで bundle 外を消しうる。後始末は拒否する（fail-closed。展開物が残る。
    //! REPAIR-3: 実装済みを装わない）。展開先は最終の名前に直接作る（非公開の名前での展開・公開は Linux のみ）。

    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};

    use super::{invalid, refuse};
    use crate::oci_runtime::create::{inspect, is_link_like};
    use crate::traits::{ErrorCode, TraitError};

    #[derive(Debug)]
    pub(super) struct Backing;

    pub(super) fn unpack_path(path: &Path, _b: &Backing) -> PathBuf {
        path.to_path_buf()
    }

    pub(super) fn publish(_b: &mut Backing) -> Result<(), TraitError> {
        Ok(())
    }

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
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt;
            let mut b = std::fs::DirBuilder::new();
            b.mode(0o700);
            b
        };
        #[cfg(not(unix))]
        let builder = std::fs::DirBuilder::new();
        builder.create(&current).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => {
                TraitError::new(ErrorCode::AlreadyExists, "rootfs already exists")
            }
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => {
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

    /// OCI-7: 空の rootfs を作り、展開先の経路へ書いて公開し、remove で消せる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_prepare_creates_empty_dir_publishes_and_remove_deletes_it() {
        let b = tmp("basic");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        assert_eq!(c.path(), b.join("rootfs"));
        // 公開前は最終の名前に存在しない（他の create から rootfs として見えない）。
        assert!(!b.join("rootfs").exists());
        let up = c.unpack_path();
        assert_eq!(std::fs::read_dir(&up).expect("read").count(), 0);
        std::fs::write(up.join("f"), b"x").expect("write");
        c.publish().expect("publish");
        assert!(b.join("rootfs").join("f").exists());
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
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_restores_permissions_for_read_only_tree() {
        use std::os::unix::fs::PermissionsExt;
        let b = tmp("ro");
        let c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        let sub = c.unpack_path().join("sub");
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
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_refuses_replaced_rootfs() {
        let b = tmp("replaced");
        let outside = tmp("replaced-out");
        std::fs::write(outside.join("marker"), b"x").expect("marker");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        c.publish().expect("publish");
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
        let mut c = prepare_rootfs_target(&b, Path::new("p/rootfs")).expect("prepare");
        std::fs::write(c.unpack_path().join("mine"), b"x").expect("mine");
        c.publish().expect("publish");
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
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        std::os::unix::fs::symlink(&outside, c.unpack_path().join("dirlink")).expect("symlink");
        c.publish().expect("publish");
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
        let mut c = prepare_rootfs_target(&b, Path::new("./rootfs/")).expect("prepare");
        assert_eq!(c.path(), b.join("rootfs"));
        c.publish().expect("publish");
        assert!(b.join("rootfs").is_dir());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// SEC-1: 展開先は固定した rootfs の fd を指し、作成後に親を symlink へ差し替えても bundle 外へ書かない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_unpack_path_survives_parent_swap() {
        let b = tmp("unpackswap");
        let outside = tmp("unpackswap-out");
        std::fs::create_dir(b.join("p")).expect("p");
        let c = prepare_rootfs_target(&b, Path::new("p/rootfs")).expect("prepare");
        std::fs::rename(b.join("p"), b.join("p_moved")).expect("move");
        std::os::unix::fs::symlink(&outside, b.join("p")).expect("symlink");
        std::fs::write(c.unpack_path().join("payload"), b"x").expect("write");
        assert_eq!(std::fs::read_dir(&outside).expect("read").count(), 0);
        assert_eq!(
            std::fs::read_dir(b.join("p_moved")).expect("read").count(),
            1
        );
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// OCI-7: 最終の名前が公開前に作られていたら、公開は置き換えずに拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_publish_refuses_when_final_name_appeared() {
        let b = tmp("pubrace");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        std::fs::create_dir(b.join("rootfs")).expect("mk");
        std::fs::write(b.join("rootfs").join("keep"), b"x").expect("w");
        let e = c.publish().expect_err("exists");
        assert_eq!(e.code(), ErrorCode::AlreadyExists);
        assert!(b.join("rootfs").join("keep").exists());
        c.remove().expect("remove staging");
        assert!(b.join("rootfs").join("keep").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・SEC-1: Linux 以外は同一性を保証できないため後始末を拒否し、展開物を残す。
    #[cfg(not(target_os = "linux"))]
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
