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
use crate::traits::{ErrorCode, ImageRootfsRecord, TraitError};

/// 非公開の展開先の名前の接頭辞。`root.path` の要素としてこの接頭辞を持つ名前は、展開中の非公開の木を
/// 通常の create が rootfs として採用することを防ぐため、`prepare_rootfs_target` と `check_rootfs` が拒否する
/// （OCI-7: 使用中 rootfs の保持。展開中の木は名前を列挙でき、別 ID の create が指せてしまう）。
/// 記録（`ImageRootfsRecord`）の経路検証と同じ定数を使い、単一の真実源にする（#2378）。
pub(super) const STAGING_PREFIX: &str = crate::traits::state_store::IMAGE_ROOTFS_STAGING_PREFIX;

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
///   （Linux 以外は作成の前に `Unimplemented` で拒否されるため、この経路は渡されない）
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
/// 後始末は差し替えで bundle 外を消しうるため、作成の前に `Unimplemented` で拒否する（fail-closed。何も作らないので展開物は残らない。REPAIR-3）。
#[derive(Debug)]
pub(super) struct CreatedRootfs {
    path: PathBuf,
    /// bundle 相対の正規化済みの経路（Normal 要素だけ。[`CreatedRootfs::record`] が状態へ記録する）。
    relative: PathBuf,
    backing: imp::Backing,
}

/// [`remove_recorded_rootfs`] の結果（将来の拡張に備え非網羅）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum RecordedRootfsRemoval {
    /// 記録の実体を消した。
    Removed,
    /// 既に無かった（どの段でも `ENOENT`）。冪等な再実行として成功扱いにする。
    NotPresent,
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
    if has_staging_component(root_path) {
        return Err(invalid("root.path must not use a reserved staging name"));
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
    let relative = parts.iter().collect::<PathBuf>();
    Ok(CreatedRootfs {
        path,
        relative,
        backing,
    })
}

/// 経路のいずれかの要素が非公開の展開先の予約名（[`STAGING_PREFIX`] 始まり）か。
pub(super) fn has_staging_component(path: &Path) -> bool {
    path.components().any(|c| match c {
        Component::Normal(p) => p.to_string_lossy().starts_with(STAGING_PREFIX),
        _ => false,
    })
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
    /// `AlreadyExists`（置き換えない）。Linux 以外は作成自体が拒否されるため到達しない。
    pub(super) fn publish(&mut self) -> Result<(), TraitError> {
        imp::publish(&mut self.backing)
    }

    /// 最終の名前への改名が済んでいるか。`publish` が Err でも true なら公開済みで、他の create が
    /// 使いうるため後始末で消してはならない（OCI-7）。
    pub(super) fn is_published(&self) -> bool {
        imp::is_published(&self.backing)
    }

    /// `path`（bundle の検証で得た最終の rootfs の経路）を今解決した実体が、展開した実体か（dev・ino）。
    ///
    /// 展開中に bundle の途中の要素が別名へ移され、同じ文字列の別ディレクトリに差し替わっていないかの確認。
    pub(super) fn is_unpacked_at(&self, path: &Path) -> bool {
        imp::path_is_unpacked(path, &self.backing)
    }

    /// 公開済みの rootfs を、状態レコードへ残す記録にする（契約 13。OCI-7・#2378）。
    ///
    /// 経路は bundle 相対の正規化済みのもの、同一性は作成時に固定した実体の (dev, ino)。delete が
    /// [`remove_recorded_rootfs`] で「作ったときと同じ実体」だけを消すための印になる。Linux 以外は作成自体が
    /// 拒否されるため到達しない（`Unimplemented`）。
    pub(super) fn record(&self) -> Result<ImageRootfsRecord, TraitError> {
        let (dev, ino) = imp::identity(&self.backing)?;
        ImageRootfsRecord::new(self.relative.clone(), dev, ino)
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

/// 状態レコードに記録された rootfs を消す（delete が状態削除の成功後に呼ぶ。OCI-7・OCI-5・#2378）。
///
/// 呼び出し元は `oci_runtime::delete`。`bundle` はレコードの bundle、`rec` は create が記録した経路と実体の
/// 同一性。bundle は作成時と同じく追従して開き、記録の経路は中間要素をリンク非追従の fd 相対で辿る。
/// 末尾が記録の (dev, ino) と一致するディレクトリのときだけ中身ごと消す。symlink・ディレクトリでないもの・
/// 同一性の不一致は `FailedPrecondition` で拒否し何も消さない（fail-closed）。どの段でも `ENOENT` なら
/// [`RecordedRootfsRemoval::NotPresent`]。Linux 以外は同一性を保証できないため `Unimplemented`。
pub(super) fn remove_recorded_rootfs(
    bundle: &Path,
    rec: &ImageRootfsRecord,
) -> Result<RecordedRootfsRemoval, TraitError> {
    imp::remove_recorded(bundle, rec)
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

    use super::{
        CLEANUP_MAX_DEPTH, CLEANUP_MAX_ENTRIES, ImageRootfsRecord, RecordedRootfsRemoval, invalid,
        refuse, remove_failed,
    };
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
        // 改名した先を固定済みの親から開き直し、展開した実体（保持中の fd の dev・ino）と一致することを確認する。
        // 一致しなければ公開した名前は別の実体を指しており、成功を装わず拒否する。
        let same = open_dir(b.parent.as_fd(), &b.final_name)
            .ok()
            .and_then(|fd| fstat(fd.as_fd()).ok())
            .is_some_and(|(dev, ino, is_dir, _)| is_dir && (dev, ino) == b.identity);
        if same { Ok(()) } else { Err(refuse()) }
    }

    /// 経路を今ここで解決した実体が、展開した実体（保持中の fd の dev・ino）か。
    pub(super) fn is_published(b: &Backing) -> bool {
        b.current == b.final_name
    }

    pub(super) fn path_is_unpacked(path: &Path, b: &Backing) -> bool {
        std::fs::metadata(path).is_ok_and(|m| m.is_dir() && (m.dev(), m.ino()) == b.identity)
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

    /// fd の指す実体の所有者 uid。
    fn fd_owner(fd: BorrowedFd<'_>) -> Option<u32> {
        let file = File::from(fd.try_clone_to_owned().ok()?);
        file.metadata().ok().map(|m| m.uid())
    }

    /// fd の指すディレクトリが空か（`/proc/self/fd/N` 経由で列挙。読めなければ空と見なさない）。
    fn dir_is_empty(fd: BorrowedFd<'_>) -> bool {
        std::fs::read_dir(format!("/proc/self/fd/{}", fd.as_raw_fd()))
            .is_ok_and(|mut it| it.next().is_none())
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
            "{}{}-{}",
            super::STAGING_PREFIX,
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
        // mkdirat と open の間に、親へ書ける別プロセスが別の実体へ差し替えうる。採用する実体は、自分（実効 uid）
        // 所有・権限 0700・空のディレクトリに限る（既存データへ展開せず、失敗時の再帰削除が他人のデータに
        // 及ばない）。0700（setgid 親の下の 02700 も許容）で自分の所有なら、検証後に他者は中身を足せない（root を除く）。
        let owned_empty = opened.as_ref().is_some_and(|(fd, _, _, _)| {
            fstat(fd.as_fd()).is_ok_and(|(_, _, is_dir, mode)| is_dir && mode & 0o777 == 0o700)
                && fd_owner(fd.as_fd()) == Some(sys::effective_uid())
                && dir_is_empty(fd.as_fd())
        });
        let (dir, identity) = match opened {
            Some((fd, dev, ino, true)) if owned_empty => (fd, (dev, ino)),
            _ => {
                // 作った直後に差し替えられた。差し替えられた実体は自分のものと確認できないため消さない
                // （空ディレクトリでなければ `remove_dir_at` は失敗する。best effort で戻すのは空の場合だけ）。
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

    pub(super) fn identity(b: &Backing) -> Result<(u64, u64), TraitError> {
        Ok(b.identity)
    }

    pub(super) fn remove(_path: &Path, b: Backing) -> Result<(), TraitError> {
        // 既に無ければ消す物が無い（`NotPresent` も成功）。
        remove_tree_at(b.parent.as_fd(), &b.current, b.identity).map(|_| ())
    }

    /// 固定済みの `parent` の下の `name` を、(dev, ino) が `identity` と一致するときだけ中身ごと消す。
    /// 末尾はリンク非追従で開く。`ENOENT` は `NotPresent`、それ以外の開く失敗・種類や同一性の不一致は拒否する。
    fn remove_tree_at(
        parent: BorrowedFd<'_>,
        name: &CString,
        identity: (u64, u64),
    ) -> Result<RecordedRootfsRemoval, TraitError> {
        let root = match sys::open_dir_path_nofollow(Some(parent), name) {
            Ok(fd) => fd,
            Err(SysError::Os(n)) if n == sys::ENOENT => {
                return Ok(RecordedRootfsRemoval::NotPresent);
            }
            Err(_) => return Err(refuse()),
        };
        match fstat(root.as_fd()) {
            Ok((dev, ino, true, _)) if (dev, ino) == identity => {}
            _ => return Err(refuse()),
        }
        let mut seen = 0usize;
        remove_children(root.as_fd(), 0, &mut seen)?;
        match sys::remove_dir_at(parent, name) {
            Ok(()) => Ok(RecordedRootfsRemoval::Removed),
            Err(SysError::Os(n)) if n == sys::ENOENT => Ok(RecordedRootfsRemoval::Removed),
            Err(_) => Err(remove_failed()),
        }
    }

    pub(super) fn remove_recorded(
        bundle: &Path,
        rec: &ImageRootfsRecord,
    ) -> Result<RecordedRootfsRemoval, TraitError> {
        let file = match File::open(bundle) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RecordedRootfsRemoval::NotPresent);
            }
            Err(_) => return Err(remove_failed()),
        };
        if !file.metadata().map(|m| m.is_dir()).unwrap_or(false) {
            return Err(refuse());
        }
        let mut cur = OwnedFd::from(file);
        let mut parts = rec.relative_path().iter().peekable();
        while let Some(part) = parts.next() {
            let name = cstr(part)?;
            if parts.peek().is_none() {
                return remove_tree_at(cur.as_fd(), &name, rec.identity());
            }
            cur = match open_dir(cur.as_fd(), &name) {
                Ok(fd) => fd,
                // 中間の要素が無ければ rootfs も無い。
                Err(e) if e.code() == ErrorCode::NotFound => {
                    return Ok(RecordedRootfsRemoval::NotPresent);
                }
                // symlink・ディレクトリでないものへの差し替え（リンクは辿らない）。
                Err(e) if e.code() == ErrorCode::InvalidArgument => return Err(refuse()),
                Err(e) => return Err(e),
            };
        }
        // 空の経路は `ImageRootfsRecord::new` が拒否済みで到達しない。
        Err(refuse())
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
    //! Linux 以外（macOS 等の Unix・Windows）: 展開先を fd／ハンドルで固定する実装が無い。経路を再解決して
    //! 作成・展開・削除すると、検査後や作成後に親が symlink／junction へ差し替えられて bundle 外へ
    //! 作成・書き込み・削除しうる（SEC-1）。そのため作成の前に Unimplemented を返して展開を拒否する
    //! （fail-closed。REPAIR-3: 実装済みを装わない。固定の実装は 3 OS 対応の課題として追跡する）。

    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};

    use super::{ImageRootfsRecord, RecordedRootfsRemoval, refuse};
    use crate::traits::{ErrorCode, TraitError};

    #[derive(Debug)]
    pub(super) struct Backing;

    pub(super) fn unpack_path(path: &Path, _b: &Backing) -> PathBuf {
        path.to_path_buf()
    }

    pub(super) fn publish(_b: &mut Backing) -> Result<(), TraitError> {
        Ok(())
    }

    /// 作成自体が拒否される（`create_dir` は Unimplemented）ため到達しない。
    pub(super) fn is_published(_b: &Backing) -> bool {
        true
    }

    pub(super) fn path_is_unpacked(_path: &Path, _b: &Backing) -> bool {
        false
    }

    pub(super) fn create_dir(
        _bundle: &Path,
        _parents: &[&OsStr],
        _last: &OsStr,
    ) -> Result<Backing, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "image rootfs unpacking is not supported on this OS yet",
        ))
    }

    pub(super) fn remove(_path: &Path, _b: Backing) -> Result<(), TraitError> {
        Err(refuse())
    }

    /// 作成自体が拒否される（`create_dir` は Unimplemented）ため到達しない。
    pub(super) fn identity(_b: &Backing) -> Result<(u64, u64), TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "image rootfs unpacking is not supported on this OS yet",
        ))
    }

    /// 同一性を fd で固定できないため、経路を再解決して消さない（SEC-1。記録は失敗として残す）。
    pub(super) fn remove_recorded(
        _bundle: &Path,
        _rec: &ImageRootfsRecord,
    ) -> Result<RecordedRootfsRemoval, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "image rootfs removal is not supported on this OS yet",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        // 呼び出しごとに固有（並行する試験が同じ名前を使っても相手のディレクトリを消さない。REPAIR-12）。
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fandhe-image-rootfs-{name}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    /// OCI-7・SEC-1: 公開後の最終の経路が別の実体（同名の差し替え）なら展開した実体と見なさない。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_is_unpacked_at_rejects_replaced_directory() {
        let b = tmp("replaced");
        std::fs::create_dir(b.join("p")).expect("parent");
        let mut c = prepare_rootfs_target(&b, Path::new("p/rootfs")).expect("prepare");
        c.publish().expect("publish");
        assert!(c.is_unpacked_at(&b.join("p/rootfs")));
        std::fs::rename(b.join("p"), b.join("moved")).expect("rename");
        std::fs::create_dir_all(b.join("p/rootfs")).expect("new");
        assert!(!c.is_unpacked_at(&b.join("p/rootfs")));
        let _ = std::fs::remove_dir_all(&b);
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
    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
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

    /// OCI-7: 展開中の非公開の名前（予約名）は root.path として拒否する。
    #[test]
    fn oci7_prepare_rejects_reserved_staging_name() {
        let b = tmp("reserved");
        let e = prepare_rootfs_target(&b, Path::new(".fandhe-unpack-1-0")).expect_err("reserved");
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        assert!(has_staging_component(Path::new("a/.fandhe-unpack-x/b")));
        assert!(!has_staging_component(Path::new("a/rootfs")));
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: setgid の親の下で 02700 になる展開先も採用できる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_prepare_accepts_setgid_parent() {
        use std::os::unix::fs::PermissionsExt;
        let b = tmp("setgid");
        std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o2755)).expect("setgid");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        c.publish().expect("publish");
        assert!(c.is_published());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 返す経路は正規化済みで、等価な書き方の `root.path` でも同じ場所に作る。
    #[cfg(target_os = "linux")]
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

    /// 公開済みの rootfs を作り、記録を返す（`<b>/<rel>` に `f` を置く）。
    #[cfg(target_os = "linux")]
    fn published_record(b: &Path, rel: &str) -> ImageRootfsRecord {
        let mut c = prepare_rootfs_target(b, Path::new(rel)).expect("prepare");
        std::fs::write(c.unpack_path().join("f"), b"x").expect("write");
        c.publish().expect("publish");
        c.record().expect("record")
    }

    /// OCI-7: 記録から公開済みの rootfs を消せる。bundle と他のファイルは残る。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_recorded_rootfs_deletes_tree() {
        let b = tmp("rec-del");
        std::fs::write(b.join("config.json"), b"{}").expect("config");
        let rec = published_record(&b, "rootfs");
        assert_eq!(rec.relative_path(), Path::new("rootfs"));
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("remove"),
            RecordedRootfsRemoval::Removed
        );
        assert!(!b.join("rootfs").exists());
        assert!(b.join("config.json").is_file());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 入れ子の `root.path` でも記録の経路で消せる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_recorded_rootfs_nested_path() {
        let b = tmp("rec-nested");
        std::fs::create_dir(b.join("p")).expect("parent");
        let rec = published_record(&b, "p/rootfs");
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("remove"),
            RecordedRootfsRemoval::Removed
        );
        assert!(b.join("p").is_dir());
        assert!(!b.join("p/rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7: 既に無ければ `NotPresent`（冪等な再実行）。bundle・中間要素が無い場合も同じ。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_recorded_rootfs_absent_is_not_present() {
        let b = tmp("rec-absent");
        std::fs::create_dir(b.join("p")).expect("parent");
        let rec = published_record(&b, "p/rootfs");
        std::fs::remove_dir_all(b.join("p/rootfs")).expect("gone");
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("absent"),
            RecordedRootfsRemoval::NotPresent
        );
        std::fs::remove_dir_all(b.join("p")).expect("parent gone");
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("no parent"),
            RecordedRootfsRemoval::NotPresent
        );
        let _ = std::fs::remove_dir_all(&b);
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("no bundle"),
            RecordedRootfsRemoval::NotPresent
        );
    }

    /// SEC-1: 同名の別ディレクトリ・symlink に差し替えられていたら `FailedPrecondition` で何も消さない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_recorded_rootfs_refuses_replaced_dir() {
        let b = tmp("rec-replaced");
        let rec = published_record(&b, "rootfs");
        std::fs::rename(b.join("rootfs"), b.join("moved")).expect("move");
        std::fs::create_dir(b.join("rootfs")).expect("replacement");
        std::fs::write(b.join("rootfs/marker"), b"o").expect("marker");
        let e = remove_recorded_rootfs(&b, &rec).expect_err("replaced");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(b.join("rootfs/marker").is_file());

        std::fs::remove_dir_all(b.join("rootfs")).expect("rm replacement");
        let outside = tmp("rec-replaced-out");
        std::fs::write(outside.join("marker"), b"o").expect("marker");
        std::os::unix::fs::symlink(&outside, b.join("rootfs")).expect("symlink");
        let e = remove_recorded_rootfs(&b, &rec).expect_err("symlink");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(outside.join("marker").is_file());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// SEC-1: 中間要素が bundle 外への symlink に差し替えられても、外側は消さない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec1_remove_recorded_rootfs_parent_symlink_untouched() {
        let b = tmp("rec-parent");
        std::fs::create_dir(b.join("p")).expect("parent");
        let rec = published_record(&b, "p/rootfs");
        let outside = tmp("rec-parent-out");
        std::fs::create_dir(outside.join("rootfs")).expect("outside rootfs");
        std::fs::write(outside.join("rootfs/marker"), b"o").expect("marker");
        std::fs::rename(b.join("p"), b.join("p-moved")).expect("move");
        std::os::unix::fs::symlink(&outside, b.join("p")).expect("symlink");
        let e = remove_recorded_rootfs(&b, &rec).expect_err("symlinked parent");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert!(outside.join("rootfs/marker").is_file());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// OCI-7: 展開時に読み取り専用にされたディレクトリを含む木も消せる。
    #[cfg(target_os = "linux")]
    #[test]
    fn oci7_remove_recorded_rootfs_handles_read_only_dirs() {
        use std::os::unix::fs::PermissionsExt as _;
        let b = tmp("rec-ro");
        let mut c = prepare_rootfs_target(&b, Path::new("rootfs")).expect("prepare");
        let up = c.unpack_path();
        std::fs::create_dir(up.join("ro")).expect("ro");
        std::fs::write(up.join("ro/f"), b"x").expect("f");
        std::fs::set_permissions(up.join("ro"), std::fs::Permissions::from_mode(0o500))
            .expect("chmod");
        c.publish().expect("publish");
        let rec = c.record().expect("record");
        assert_eq!(
            remove_recorded_rootfs(&b, &rec).expect("remove"),
            RecordedRootfsRemoval::Removed
        );
        assert!(!b.join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
    }

    /// OCI-7・SEC-1: Linux 以外は展開先を固定できないため、作成の前に Unimplemented で拒否する。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn sec1_prepare_refuses_without_fd_pinning() {
        let b = tmp("winrefuse");
        let e = prepare_rootfs_target(&b, Path::new("rootfs")).expect_err("refuse");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert!(!b.join("rootfs").exists());
        let _ = std::fs::remove_dir_all(&b);
    }
}
