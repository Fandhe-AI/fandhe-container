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

use std::io;
use std::path::{Component, Path, PathBuf};

use super::create::{inspect, is_link_like};
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
#[derive(Debug)]
pub(super) struct CreatedRootfs {
    bundle: PathBuf,
    path: PathBuf,
    #[cfg(unix)]
    identity: (u64, u64),
}

fn invalid(message: &str) -> TraitError {
    TraitError::new(ErrorCode::InvalidArgument, message)
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
    create_private_dir(&current)?;
    let meta = inspect(&current)?;
    if is_link_like(&meta) || !meta.is_dir() {
        return Err(TraitError::new(
            ErrorCode::Internal,
            "created rootfs is not a directory",
        ));
    }
    Ok(CreatedRootfs {
        bundle: bundle.to_path_buf(),
        #[cfg(unix)]
        identity: identity_of(&meta),
        path: current,
    })
}

#[cfg(unix)]
fn identity_of(meta: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

/// 非再帰・排他的にディレクトリを作る（Unix は 0700）。既存なら `AlreadyExists`。
fn create_private_dir(path: &Path) -> Result<(), TraitError> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|e| match e.kind() {
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
    })
}

impl CreatedRootfs {
    /// 作った rootfs のパス（bundle 配下）。
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// 展開途中の rootfs を消す。
    ///
    /// 経路を bundle から lstat で辿り直し、末尾が作ったときと同じディレクトリ（Unix は dev・ino）で
    /// なければ削除しない（`FailedPrecondition`。差し替えられた先 = bundle 外の実体を消さない fail-closed）。
    pub(super) fn remove(self) -> Result<(), TraitError> {
        let refuse = || {
            TraitError::new(
                ErrorCode::FailedPrecondition,
                "rootfs was replaced; refusing to remove",
            )
        };
        let rel = self
            .path
            .strip_prefix(&self.bundle)
            .map_err(|_| refuse())?
            .to_path_buf();
        let mut current = self.bundle.clone();
        let parts: Vec<_> = rel.components().collect();
        for (i, c) in parts.iter().enumerate() {
            let Component::Normal(part) = c else {
                return Err(refuse());
            };
            current.push(part);
            let meta = match std::fs::symlink_metadata(&current) {
                Ok(m) => m,
                // 既に無ければ消す物が無い。
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(_) => {
                    return Err(TraitError::new(
                        ErrorCode::Internal,
                        "failed to inspect rootfs for removal",
                    ));
                }
            };
            if is_link_like(&meta) || !meta.is_dir() {
                return Err(refuse());
            }
            #[cfg(unix)]
            if i + 1 == parts.len() && identity_of(&meta) != self.identity {
                return Err(refuse());
            }
            #[cfg(not(unix))]
            let _ = i;
        }
        remove_tree(&current)
    }
}

fn remove_failed() -> TraitError {
    TraitError::new(ErrorCode::Internal, "failed to remove rootfs")
}

/// `remove_dir_all`（木の内側の symlink を辿らない）で消す。Unix で権限不足なら所有者の rwx を足して 1 回だけやり直す。
fn remove_tree(path: &Path) -> Result<(), TraitError> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        #[cfg(unix)]
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            restore_owner_access(path)?;
            std::fs::remove_dir_all(path).map_err(|_| remove_failed())
        }
        Err(_) => Err(remove_failed()),
    }
}

/// 展開が適用した読み取り専用の mode を、木のディレクトリごとに戻す（明示スタック・件数と深さの上限つき）。
#[cfg(unix)]
fn restore_owner_access(root: &Path) -> Result<(), TraitError> {
    use std::os::unix::fs::PermissionsExt;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut seen = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        if depth > CLEANUP_MAX_DEPTH {
            return Err(remove_failed());
        }
        // lstat でディレクトリと確かめたものだけを触る（symlink の先は辿らない）。
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
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                stack.push((entry.path(), depth + 1));
            }
        }
    }
    Ok(())
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
}
