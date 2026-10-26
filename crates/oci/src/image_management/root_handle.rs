//! 検査済みのイメージストア root を指すハンドル（OCI-7・SEC-1・REPAIR-3・#2638）。
//!
//! # 役割と呼び出し元
//!
//! `ImageStore::lock` / create ゲートの入口は `reverify_root` で root の差し替えを検出して拒否する（#2547）。
//! ただし検査から使用までの間に root が別のディレクトリへ差し替えられると、`self.root` からパスを組み
//! 直す操作は差し替え後のディレクトリへ届く（TOCTOU）。本モジュールは、`ImageStore::open` が検査した
//! root を開いたまま持ち、排他区間の中の永続化操作（`@lock`・`@container-refs.json`・
//! `@image-inventory.json`・`@gc-pending.json` とその一時ファイル・`blobs/sha256/<hex>` の削除）を
//! その fd 起点の `openat2` / `*at` に閉じ込める。差し替えが起きても書き込み・削除は検査済みの実体にだけ
//! 届き、差し替え後のディレクトリには何も書かず何も消さない（入口の検出と区間内の閉じ込めの 2 層）。
//! 読み取り専用の集計（`usage*`。件数・サイズ・staging・展開後サイズ）も同じ fd 起点の `open_blob_dir` /
//! `open_subdir` / `stat` / `entries` / `open_file` で行い、検査済みの実体にだけ届く（#2695）。
//! 呼び出し元は `store`（open・lock・create ゲート）・`container_ref_persist`・`inventory_persist`・
//! `gc_journal`・`remove`・`prune`・`usage`。名前は定数か検証済みの hex の 1 コンポーネントに限る
//! （外部入力からパスを組まない。`sys::at::component_cstring` が入口で再検証する）。
//!
//! # 方式と `cfg` の局所化
//!
//! `cfg` は本モジュールの中だけに置き、永続化モジュールには `cfg(target_os)` / `cfg(target_arch)` を書かない。
//!
//! - Linux の x86_64 / aarch64: root の fd を `OwnedFd` で持つ。名前の解決は
//!   `RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` 付きの `openat2` で行い、
//!   最後の要素も `O_NOFOLLOW` で辿らない。`openat2`（Linux 5.6 以降）が使えない環境（`ENOSYS`・seccomp による
//!   `EPERM`）では `ImageStore::open` が `Unimplemented` で拒否し、パス起点へは縮退しない（fail-closed）。
//!   root 配下の別マウントは `RESOLVE_NO_XDEV` の `EXDEV` で拒否し、`FailedPrecondition` と固定メッセージ
//!   （[`MOUNT_CROSSING_MESSAGE`]）に写す（対応外。#2701・`docs/design/image-store-root-trust.md` 3-d）。
//! - macOS と Windows: 正規パスを持つ従来のパス起点の実装で、差し替えは入口の再検査だけで検出する。
//!   macOS は本番経路が `ImageStore::open` に届かず（cli の `non_linux_failure`）、`openat` 系の定数・FFI・
//!   libc 照合を足す根拠が無い。Windows の ACL は #2428 の方式判断待ち。
//! - Linux の他アーキテクチャ: `sys::at` の定数・番号を確かめていないため、パス起点へ縮退せず
//!   `Unimplemented` で拒否する（`layer::anchored` と同じ fail-closed。#2701）。
//!
//! # 移していない操作（実装済みを装わない。REPAIR-3）
//!
//! `pull` / `pull_recovery` の staging・公開（#2694）はパス起点のままである。根拠と追跡 issue は `docs/design/image-store-root-trust.md` の論点 3 を参照。

use std::path::{Path, PathBuf};

use crate::error::{OciError, OciErrorCode};

fn root_inaccessible() -> OciError {
    OciError::new(OciErrorCode::Internal, "image store root is not accessible")
}

/// root 配下の別マウント（`RESOLVE_NO_XDEV` の `EXDEV`）を示す固定メッセージ（OCI-7・SEC-1・ERR-1・#2701）。
pub(crate) const MOUNT_CROSSING_MESSAGE: &str =
    "image store path crosses a mount point; unsupported (RESOLVE_NO_XDEV)";

/// root 配下の別マウントで拒否したことを表す `FailedPrecondition`。
///
/// 永続化モジュールは errno を書かず、`map_root_io` 経由で本関数へ届く。対応外の構成であり、
/// 再試行しても直らない（呼び出し側は再試行回数を消費しない）。
pub(crate) fn mount_crossing() -> OciError {
    OciError::new(OciErrorCode::FailedPrecondition, MOUNT_CROSSING_MESSAGE)
}

/// fd 起点の I/O の失敗を OCI のエラーへ写す。`EXDEV`（`CrossesDevices`）は `mount_crossing()`、
/// それ以外は `fallback()`（各呼び出し元の従来の code・文言）。
///
/// `EXDEV` は fd 起点の `openat2`（`RESOLVE_NO_XDEV`）以外では通常 `rename` の別デバイスでも起きるが、
/// 本ストアの rename は同一ディレクトリ内に限るため、どちらでも「root 配下の別マウント」を意味する。
pub(crate) fn map_root_io(e: &std::io::Error, fallback: impl FnOnce() -> OciError) -> OciError {
    if e.kind() == std::io::ErrorKind::CrossesDevices {
        mount_crossing()
    } else {
        fallback()
    }
}

/// `e` が `mount_crossing()` か（復旧が再試行回数を消費せずに止まる判定に使う）。
pub(crate) fn is_mount_crossing(e: &OciError) -> bool {
    e.code() == OciErrorCode::FailedPrecondition && e.message() == MOUNT_CROSSING_MESSAGE
}

/// `openat2` が root を開けなかった理由を、利用者が原因を切り分けられる固定メッセージにする。
///
/// code はどちらも `Unimplemented`（呼び出し側の分類を変えない）。`EPERM` は古い Docker の既定 seccomp
/// プロファイルなど、外側のコンテナランタイムによる拒否を示す（#2701）。
#[cfg_attr(
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )),
    allow(dead_code)
)]
pub(crate) fn openat2_unavailable(is_enosys: bool) -> OciError {
    let msg = if is_enosys {
        "openat2 is not available (ENOSYS): the image store requires Linux 5.6 or later, or a seccomp profile that allows openat2"
    } else {
        "openat2 was denied (EPERM), likely by a seccomp profile of the enclosing container runtime; the image store requires openat2"
    };
    OciError::new(OciErrorCode::Unimplemented, msg)
}

/// `open_subdir` の失敗。呼び出し側（usage）が既存の code・文言へ写す（文言はここに固定しない）。
#[derive(Debug)]
pub(crate) enum SubDirError {
    /// symlink・非ディレクトリ（辿らない）。
    NotPlain,
    /// その他の I/O の失敗。
    Io,
}

/// 検査済み root へのハンドル。`ImageStore` が `Arc` で保持し、`ReferenceTable` の排他区間にも渡す。
#[derive(Debug)]
pub(crate) struct RootHandle {
    path: PathBuf,
    /// 開いた時点の root の (dev, ino)。入口の再検査が差し替えの検出に使う。
    #[cfg(unix)]
    id: (u64, u64),
    /// fd 起点の実装だけが持つ root の fd。パス起点の実装は `path` から都度組み立てる。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    inner: imp::Inner,
}

impl RootHandle {
    /// 開いた root の正規パス（表示・照合用。操作の起点には使わない）。
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// 開いた時点の root の (dev, ino)。
    #[cfg(unix)]
    pub(crate) fn id(&self) -> (u64, u64) {
        self.id
    }

    /// root がストアのパスから切り離されて（unlink 済みで）いないことを fd の fstat で確かめる。
    ///
    /// 開いた fd は unlink 後も inode を指し続けるため、確定（rename・成功の返却）の直前に呼び、
    /// 到達できないディレクトリへの永続化を成功と報告しない（OCI-7・SEC-1・#2696）。Linux の
    /// ディレクトリは rmdir で `st_nlink` が 0 になる。移動（rename）では 0 にならず、fd 起点の実装は
    /// 設計どおり移動後も検査済みの実体に書く。unix 以外はパス起点で、消えていれば操作自体が失敗するため
    /// 何も検査しない（Windows は同等の確認を持たない）。
    pub(crate) fn ensure_linked(&self) -> Result<(), OciError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m = self.root_meta().map_err(|_| root_inaccessible())?;
            if m.nlink() == 0 {
                return Err(OciError::new(
                    OciErrorCode::Internal,
                    "image store root was removed",
                ));
            }
        }
        Ok(())
    }

    /// `p` が本ハンドルの root と同じディレクトリか（unix は dev / ino、他はパス比較）。
    pub(crate) fn matches(&self, p: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(p).is_ok_and(|m| (m.dev(), m.ino()) == self.id)
        }
        #[cfg(not(unix))]
        {
            let norm: PathBuf = p.components().collect();
            norm == self.path
        }
    }

    /// 信頼検査をしない単体テーブル用に、パスから開く（検査は `ImageStore::open` の担当）。
    ///
    /// 試験と、ガードの外の単体テーブルの読み取り専用 API で使う（削除系の `gc_journal::root_handle_for` は
    /// 本番ビルドでこの経路を拒否する。#2701）。末尾が symlink・非ディレクトリなら拒否する。
    pub(super) fn open_unchecked(path: &Path) -> Result<Self, OciError> {
        let path: PathBuf = path.components().collect();
        let meta = std::fs::symlink_metadata(&path).map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                OciErrorCode::NotFound
            } else {
                OciErrorCode::Internal
            };
            OciError::new(code, "image store root is not accessible")
        })?;
        if !meta.is_dir() {
            return Err(OciError::new(
                OciErrorCode::FailedPrecondition,
                "image store root is not a directory",
            ));
        }
        Self::open_dir(path, None)
    }
}

// ---------------------------------------------------------------------------
// Linux の x86_64 / aarch64: root の fd 起点
// ---------------------------------------------------------------------------
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod imp {
    use std::ffi::{CString, OsStr, OsString};
    use std::fs::{File, Metadata};
    use std::io;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::MetadataExt as _;
    use std::path::PathBuf;

    use super::{OciError, OciErrorCode, RootHandle, SubDirError, root_inaccessible};
    use crate::sys::at::{
        self, ELOOP, ENOSYS, ENOTDIR, EPERM, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW,
        O_NONBLOCK, O_PATH, O_RDONLY, O_WRONLY, RESOLVE_IN_ROOT, RESOLVE_NO_MAGICLINKS,
        RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV,
    };

    /// root の fd。
    pub(super) type Inner = OwnedFd;

    /// 名前解決で常に付ける制約。root の外・symlink・マウント越えへ出ない。
    const RESOLVE: u64 =
        RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;

    /// blob 置き場の相対パス。
    const BLOB_DIR: [&str; 2] = ["blobs", "sha256"];

    /// blob 置き場の検査で使う文言（`usage::checked_dir` と同じ code・文言を保つ）。
    fn blob_dir_not_plain() -> OciError {
        OciError::new(
            OciErrorCode::FailedPrecondition,
            "blob directory is not a plain directory",
        )
    }

    fn blob_dir_stat_failed() -> OciError {
        OciError::new(OciErrorCode::Internal, "failed to stat blob directory")
    }

    fn errno(e: &io::Error) -> Option<i32> {
        e.raw_os_error()
    }

    impl RootHandle {
        /// `path`（正規パス）を開く。`expected` があれば開いた実体の (dev, ino) と一致することを確かめる。
        pub(super) fn open_dir(
            path: PathBuf,
            expected: Option<(u64, u64)>,
        ) -> Result<Self, OciError> {
            let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| root_inaccessible())?;
            let fd = at::openat2(
                None,
                &c,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
                0,
                0,
            )
            .map_err(|e| match errno(&e) {
                Some(ENOSYS) => super::openat2_unavailable(true),
                Some(EPERM) => super::openat2_unavailable(false),
                _ => root_inaccessible(),
            })?;
            let meta = File::from(fd.try_clone().map_err(|_| root_inaccessible())?)
                .metadata()
                .map_err(|_| root_inaccessible())?;
            let id = (meta.dev(), meta.ino());
            if expected.is_some_and(|x| x != id) {
                return Err(OciError::new(
                    OciErrorCode::Internal,
                    "image store root changed while opening",
                ));
            }
            Ok(Self {
                path,
                id,
                inner: fd,
            })
        }

        fn open_at(&self, rel: &std::ffi::CStr, flags: u64, mode: u64) -> io::Result<OwnedFd> {
            #[cfg(test)]
            if test_hook::is_xdev(rel) {
                return Err(io::Error::from_raw_os_error(at::EXDEV));
            }
            at::openat2(
                Some(self.inner.as_fd()),
                rel,
                flags | O_CLOEXEC,
                mode,
                RESOLVE,
            )
        }

        fn name_cstr(name: &OsStr) -> io::Result<CString> {
            at::component_cstring(name)
        }

        /// root 自身のメタデータ（開いた fd の fstat。パスの差し替えに影響されない）。
        #[cfg(unix)]
        pub(crate) fn root_meta(&self) -> io::Result<Metadata> {
            File::from(self.inner.try_clone()?).metadata()
        }

        /// 直下の名前のメタデータ。symlink は辿らず symlink 自身のものを返す。無ければ `None`。
        pub(crate) fn stat_name(&self, name: impl AsRef<OsStr>) -> io::Result<Option<Metadata>> {
            let n = Self::name_cstr(name.as_ref())?;
            match self.open_at(&n, O_PATH | O_NOFOLLOW, 0) {
                Ok(fd) => File::from(fd).metadata().map(Some),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// ロックファイルを開く（無ければ 0600 で作る）。symlink は `ELOOP`、ディレクトリは `EISDIR`。
        pub(crate) fn open_lock(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
            let n = Self::name_cstr(name.as_ref())?;
            self.open_at(&n, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0o600)
                .map(File::from)
        }

        /// 読み取りで開く。無ければ `None`。symlink は `ELOOP`。FIFO で止まらないよう `O_NONBLOCK`。
        pub(crate) fn open_read(&self, name: impl AsRef<OsStr>) -> io::Result<Option<File>> {
            let n = Self::name_cstr(name.as_ref())?;
            match self.open_at(&n, O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0) {
                Ok(fd) => Ok(Some(File::from(fd))),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// 新規ファイルを 0600 で排他作成する（既存なら `AlreadyExists`）。
        pub(crate) fn create_new(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
            let n = Self::name_cstr(name.as_ref())?;
            self.open_at(&n, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
                .map(File::from)
        }

        /// 直下の名前を付け替える（`to` があれば原子的に置き換える）。
        pub(crate) fn rename(
            &self,
            from: impl AsRef<OsStr>,
            to: impl AsRef<OsStr>,
        ) -> io::Result<()> {
            at::renameat_names(
                self.inner.as_fd(),
                from.as_ref(),
                self.inner.as_fd(),
                to.as_ref(),
            )
        }

        /// 直下の名前を unlink する（ディレクトリは消さない）。
        pub(crate) fn unlink(&self, name: impl AsRef<OsStr>) -> io::Result<()> {
            at::unlinkat_name(self.inner.as_fd(), name.as_ref(), false)
        }

        /// root ディレクトリを fsync する。
        pub(crate) fn sync(&self) -> io::Result<()> {
            File::from(self.inner.try_clone()?).sync_all()
        }

        /// 直下の名前の一覧（最大 `limit` 件。`.` と `..` は除く）。
        ///
        /// dup ではなく新しい open file description を開いて走査する（dup はファイル位置を共有し、
        /// 2 回目以降の走査が空になる）。
        pub(crate) fn list_names(&self, limit: usize) -> io::Result<Vec<OsString>> {
            let dot = at::relative_cstring::<&str>(&[])?;
            let dir = self.open_at(&dot, O_RDONLY | O_DIRECTORY, 0)?;
            let mut out = Vec::new();
            let mut buf = vec![0u8; 8192];
            while out.len() < limit {
                let n = at::getdents64(dir.as_fd(), &mut buf)?;
                if n == 0 {
                    break;
                }
                let chunk = buf.get(..n).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "malformed directory entry")
                })?;
                at::for_each_dirent(chunk, |name| {
                    if out.len() < limit {
                        out.push(OsString::from_vec(name.to_vec()));
                    }
                })?;
            }
            Ok(out)
        }

        /// `blobs/sha256` を開く。両方が通常ディレクトリなら `Some`、どちらかが無ければ `None`、
        /// symlink・非ディレクトリは `FailedPrecondition`（`usage::check_blob_dirs` と同じ判定）。
        pub(crate) fn open_blob_dir(&self) -> Result<Option<BlobDir>, OciError> {
            let rel = at::relative_cstring(&BLOB_DIR).map_err(|_| blob_dir_stat_failed())?;
            match self.open_at(&rel, O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0) {
                Ok(fd) => Ok(Some(SubDir(fd))),
                Err(e) => match errno(&e) {
                    Some(ELOOP | ENOTDIR) => Err(blob_dir_not_plain()),
                    _ if e.kind() == io::ErrorKind::CrossesDevices => Err(super::mount_crossing()),
                    _ if e.kind() == io::ErrorKind::NotFound => Ok(None),
                    _ => Err(blob_dir_stat_failed()),
                },
            }
        }

        /// 直下のサブディレクトリを開く（#2695）。無ければ `None`、symlink・非ディレクトリは `NotPlain`。
        pub(crate) fn open_subdir(
            &self,
            name: impl AsRef<OsStr>,
        ) -> Result<Option<SubDir>, SubDirError> {
            let n = Self::name_cstr(name.as_ref()).map_err(|_| SubDirError::Io)?;
            open_dir_at(self.inner.as_fd(), &n)
        }
    }

    /// 試験用: 指定した相対名（`@lock`・`blobs/sha256` 等）の `openat2` を `EXDEV` で失敗させる。
    ///
    /// root 配下の別マウント（bind mount・別ボリューム）が `RESOLVE_NO_XDEV` で拒否される状況を、
    /// 実マウントなしで決定的に再現する（実マウントでの確認は `tests/image_store_xdev.rs`。#2701）。
    #[cfg(test)]
    pub(crate) mod test_hook {
        use std::cell::RefCell;
        use std::ffi::CStr;

        thread_local! {
            static XDEV: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
        }

        /// 解除用ガード（drop で全解除）。
        pub(crate) struct XdevGuard;

        impl Drop for XdevGuard {
            fn drop(&mut self) {
                XDEV.with(|x| x.borrow_mut().clear());
            }
        }

        /// 以降このスレッドで、`names` の相対名の解決を `EXDEV` にする。
        pub(crate) fn fail_xdev(names: &[&str]) -> XdevGuard {
            XDEV.with(|x| *x.borrow_mut() = names.iter().map(|n| (*n).to_owned()).collect());
            XdevGuard
        }

        pub(super) fn is_xdev(rel: &CStr) -> bool {
            XDEV.with(|x| x.borrow().iter().any(|n| n.as_bytes() == rel.to_bytes()))
        }
    }

    /// `dirfd` 起点で `rel` のディレクトリを開く（末尾の symlink は辿らない）。
    fn open_dir_at(
        dirfd: std::os::fd::BorrowedFd<'_>,
        rel: &std::ffi::CStr,
    ) -> Result<Option<SubDir>, SubDirError> {
        match at::openat2(
            Some(dirfd),
            rel,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC,
            0,
            RESOLVE,
        ) {
            Ok(fd) => Ok(Some(SubDir(fd))),
            Err(e) => match errno(&e) {
                Some(ELOOP | ENOTDIR) => Err(SubDirError::NotPlain),
                _ if e.kind() == io::ErrorKind::NotFound => Ok(None),
                _ => Err(SubDirError::Io),
            },
        }
    }

    /// 開いたディレクトリ（`blobs/sha256`・`staging`・`staging/<pull-id>`）。fd 起点で、読み取りの名前解決は
    /// 常にこの fd の下に閉じる。
    #[derive(Debug)]
    pub(crate) struct SubDir(OwnedFd);

    /// `blobs/sha256`（`SubDir` と同じ型）。
    pub(crate) type BlobDir = SubDir;

    impl SubDir {
        /// 直下のメタデータ（symlink は辿らない）。無ければ `None`。
        pub(crate) fn stat(&self, name: impl AsRef<OsStr>) -> io::Result<Option<Metadata>> {
            let n = at::component_cstring(name.as_ref())?;
            match at::openat2(
                Some(self.0.as_fd()),
                &n,
                O_PATH | O_NOFOLLOW | O_CLOEXEC,
                0,
                RESOLVE,
            ) {
                Ok(fd) => File::from(fd).metadata().map(Some),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// 直下のサブディレクトリを開く。無ければ `None`、symlink・非ディレクトリは `NotPlain`。
        pub(crate) fn open_subdir(
            &self,
            name: impl AsRef<OsStr>,
        ) -> Result<Option<SubDir>, SubDirError> {
            let n = at::component_cstring(name.as_ref()).map_err(|_| SubDirError::Io)?;
            open_dir_at(self.0.as_fd(), &n)
        }

        /// 直下の名前を 1 件ずつ返す（`.` と `..` は除く）。呼ぶたびに新しい open file description を開く
        /// （dup はファイル位置を共有し、2 回目以降の走査が空になる）。件数の上限判定は呼び出し側が行う。
        pub(crate) fn entries(&self) -> io::Result<Entries> {
            let dot = at::relative_cstring::<&str>(&[])?;
            let dir = at::openat2(
                Some(self.0.as_fd()),
                &dot,
                O_RDONLY | O_DIRECTORY | O_CLOEXEC,
                0,
                RESOLVE,
            )?;
            Ok(Entries {
                dir,
                buf: vec![0u8; 8192],
                queue: std::collections::VecDeque::new(),
                done: false,
            })
        }

        /// 直下の通常ファイルを読み取りで開く。無い・symlink・通常ファイルでないものは `None`（欠損扱い）。
        /// FIFO で止まらないよう `O_NONBLOCK`。その他の I/O の失敗は `Err`（過少計上しない）。
        pub(crate) fn open_file(&self, name: &str) -> Result<Option<File>, OciError> {
            let n = at::component_cstring(OsStr::new(name)).map_err(crate::layer::map_io_error)?;
            // 開く前に O_PATH の fstat で種類を確かめる。socket・デバイスを読み取りで開くと ENXIO 等で
            // 失敗し集計全体が落ちる（従来の lstat 先行と同じく、通常ファイル以外は開かず欠損扱い）。
            match self.stat(name) {
                Ok(Some(m)) if m.is_file() => {}
                Ok(_) => return Ok(None),
                Err(e) => return Err(crate::layer::map_io_error(e)),
            }
            match at::openat2(
                Some(self.0.as_fd()),
                &n,
                O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                0,
                RESOLVE,
            ) {
                Ok(fd) => {
                    let f = File::from(fd);
                    let m = f.metadata().map_err(crate::layer::map_io_error)?;
                    Ok(m.is_file().then_some(f))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) if errno(&e) == Some(ELOOP) => Ok(None),
                Err(e) => Err(crate::layer::map_io_error(e)),
            }
        }

        /// blob を unlink する。
        pub(crate) fn unlink(&self, hex: &str) -> io::Result<()> {
            at::unlinkat_name(self.0.as_fd(), OsStr::new(hex), false)
        }

        /// ディレクトリを fsync する。
        pub(crate) fn sync(&self) -> io::Result<()> {
            File::from(self.0.try_clone()?).sync_all()
        }
    }

    /// `SubDir::entries` の逐次イテレータ。`getdents64` を 8192 バイトずつ読み、溜めた名前を 1 件ずつ返す。
    #[derive(Debug)]
    pub(crate) struct Entries {
        dir: OwnedFd,
        buf: Vec<u8>,
        queue: std::collections::VecDeque<OsString>,
        done: bool,
    }

    impl Iterator for Entries {
        type Item = io::Result<OsString>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if let Some(n) = self.queue.pop_front() {
                    return Some(Ok(n));
                }
                if self.done {
                    return None;
                }
                let n = match at::getdents64(self.dir.as_fd(), &mut self.buf) {
                    Ok(n) => n,
                    Err(e) => {
                        self.done = true;
                        return Some(Err(e));
                    }
                };
                if n == 0 {
                    self.done = true;
                    return None;
                }
                let Some(chunk) = self.buf.get(..n) else {
                    self.done = true;
                    return Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "malformed directory entry",
                    )));
                };
                let queue = &mut self.queue;
                if let Err(e) = at::for_each_dirent(chunk, |name| {
                    queue.push_back(OsString::from_vec(name.to_vec()));
                }) {
                    self.done = true;
                    return Some(Err(e));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// その他の unix と Windows: パス起点（従来の実装）
// ---------------------------------------------------------------------------
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod imp {
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, File, Metadata, OpenOptions};
    use std::io;
    use std::path::PathBuf;

    use super::{OciError, OciErrorCode, RootHandle, SubDirError, root_inaccessible};
    use crate::image_management::usage::{blob_dir, check_blob_dirs};

    fn opts_mode(opts: &mut OpenOptions) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = opts;
    }

    impl RootHandle {
        /// `path`（正規パス）を記録する。`expected` があれば現在の (dev, ino) と一致することを確かめる。
        pub(super) fn open_dir(
            path: PathBuf,
            expected: Option<(u64, u64)>,
        ) -> Result<Self, OciError> {
            // Linux の他アーキテクチャは fd 起点の定数・番号を確かめていないため、パス起点へ縮退せず拒否する
            // （`layer::anchored` と同じ fail-closed。OCI-7・SEC-1・#2701）。
            if cfg!(target_os = "linux") {
                return Err(OciError::new(
                    OciErrorCode::Unimplemented,
                    "image store requires directory-fd based access, which is not supported on this architecture",
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let m = fs::symlink_metadata(&path).map_err(|_| root_inaccessible())?;
                let id = (m.dev(), m.ino());
                if expected.is_some_and(|x| x != id) {
                    return Err(OciError::new(
                        OciErrorCode::Internal,
                        "image store root changed while opening",
                    ));
                }
                Ok(Self { path, id })
            }
            #[cfg(not(unix))]
            {
                let _ = (expected, root_inaccessible as fn() -> OciError);
                Ok(Self { path })
            }
        }

        /// root 自身のメタデータ（パスの lstat）。
        #[cfg(unix)]
        pub(crate) fn root_meta(&self) -> io::Result<Metadata> {
            fs::symlink_metadata(&self.path)
        }

        /// 直下の名前のメタデータ（symlink は辿らない）。無ければ `None`。
        pub(crate) fn stat_name(&self, name: impl AsRef<OsStr>) -> io::Result<Option<Metadata>> {
            match fs::symlink_metadata(self.path.join(name.as_ref())) {
                Ok(m) => Ok(Some(m)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// ロックファイルを開く（無ければ 0600 で作る）。
        pub(crate) fn open_lock(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
            let mut opts = OpenOptions::new();
            opts.create(true).truncate(false).write(true);
            opts_mode(&mut opts);
            opts.open(self.path.join(name.as_ref()))
        }

        /// 読み取りで開く。無ければ `None`。
        pub(crate) fn open_read(&self, name: impl AsRef<OsStr>) -> io::Result<Option<File>> {
            match File::open(self.path.join(name.as_ref())) {
                Ok(f) => Ok(Some(f)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// 新規ファイルを排他作成する。
        pub(crate) fn create_new(&self, name: impl AsRef<OsStr>) -> io::Result<File> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            opts_mode(&mut opts);
            opts.open(self.path.join(name.as_ref()))
        }

        /// 直下の名前を付け替える。
        pub(crate) fn rename(
            &self,
            from: impl AsRef<OsStr>,
            to: impl AsRef<OsStr>,
        ) -> io::Result<()> {
            fs::rename(self.path.join(from.as_ref()), self.path.join(to.as_ref()))
        }

        /// 直下の名前を unlink する。
        pub(crate) fn unlink(&self, name: impl AsRef<OsStr>) -> io::Result<()> {
            fs::remove_file(self.path.join(name.as_ref()))
        }

        /// root ディレクトリを fsync する（Windows は std で開けないため何もしない）。
        pub(crate) fn sync(&self) -> io::Result<()> {
            #[cfg(unix)]
            {
                File::open(&self.path)?.sync_all()
            }
            #[cfg(not(unix))]
            {
                Ok(())
            }
        }

        /// 直下の名前の一覧（最大 `limit` 件）。
        pub(crate) fn list_names(&self, limit: usize) -> io::Result<Vec<OsString>> {
            Ok(fs::read_dir(&self.path)?
                .flatten()
                .take(limit)
                .map(|e| e.file_name())
                .collect())
        }

        /// `blobs/sha256` を検査して開く（無ければ `None`）。
        pub(crate) fn open_blob_dir(&self) -> Result<Option<BlobDir>, OciError> {
            Ok(check_blob_dirs(&self.path)?.then(|| SubDir(blob_dir(&self.path))))
        }

        /// 直下のサブディレクトリを開く（#2695）。無ければ `None`、symlink・非ディレクトリは `NotPlain`。
        pub(crate) fn open_subdir(
            &self,
            name: impl AsRef<OsStr>,
        ) -> Result<Option<SubDir>, SubDirError> {
            open_dir_path(self.path.join(name.as_ref()))
        }
    }

    fn open_dir_path(p: PathBuf) -> Result<Option<SubDir>, SubDirError> {
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => Ok(Some(SubDir(p))),
            Ok(_) => Err(SubDirError::NotPlain),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(SubDirError::Io),
        }
    }

    /// 開いたディレクトリ（パス起点）。
    #[derive(Debug)]
    pub(crate) struct SubDir(PathBuf);

    /// `blobs/sha256`（`SubDir` と同じ型）。
    pub(crate) type BlobDir = SubDir;

    impl SubDir {
        /// 直下のメタデータ（symlink は辿らない）。無ければ `None`。
        pub(crate) fn stat(&self, name: impl AsRef<OsStr>) -> io::Result<Option<Metadata>> {
            match fs::symlink_metadata(self.0.join(name.as_ref())) {
                Ok(m) => Ok(Some(m)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        /// 直下のサブディレクトリを開く。
        pub(crate) fn open_subdir(
            &self,
            name: impl AsRef<OsStr>,
        ) -> Result<Option<SubDir>, SubDirError> {
            open_dir_path(self.0.join(name.as_ref()))
        }

        /// 直下の名前を 1 件ずつ返す（`.` と `..` は除く）。
        pub(crate) fn entries(&self) -> io::Result<Entries> {
            Ok(Entries(fs::read_dir(&self.0)?))
        }

        /// 直下の通常ファイルを読み取りで開く。無い・通常ファイルでない（symlink 等）・開く間に差し替えられた
        /// ものは `None`（欠損扱い）。非 Unix は `open_blob_nofollow` と同じく `Unimplemented`。
        pub(crate) fn open_file(&self, name: &str) -> Result<Option<File>, OciError> {
            match crate::layer::open_blob_nofollow(&self.0.join(name)) {
                Ok(f) => Ok(Some(f)),
                Err(e)
                    if matches!(
                        e.code(),
                        OciErrorCode::NotFound
                            | OciErrorCode::InvalidArgument
                            | OciErrorCode::FailedPrecondition
                    ) =>
                {
                    Ok(None)
                }
                Err(e) => Err(e),
            }
        }

        /// blob を unlink する。
        pub(crate) fn unlink(&self, hex: &str) -> io::Result<()> {
            fs::remove_file(self.0.join(hex))
        }

        /// ディレクトリを fsync する（Windows は何もしない）。
        pub(crate) fn sync(&self) -> io::Result<()> {
            #[cfg(unix)]
            {
                File::open(&self.0)?.sync_all()
            }
            #[cfg(not(unix))]
            {
                Ok(())
            }
        }
    }

    /// `SubDir::entries` のイテレータ（`read_dir` の包み）。
    #[derive(Debug)]
    pub(crate) struct Entries(fs::ReadDir);

    impl Iterator for Entries {
        type Item = io::Result<OsString>;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next().map(|r| r.map(|e| e.file_name()))
        }
    }
}

pub(crate) use imp::BlobDir;
#[cfg(all(test, unix))]
pub(crate) use imp::SubDir;
#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use imp::test_hook;

impl RootHandle {
    /// 正規化済みのパスと検査時の (dev, ino) から開く（`ImageStore::open` が信頼検査の後に呼ぶ）。
    #[cfg(unix)]
    pub(crate) fn open_checked(path: PathBuf, id: (u64, u64)) -> Result<Self, OciError> {
        Self::open_dir(path, Some(id))
    }

    /// 正規化済みのパスから開く（非 unix は dev / ino を持たない）。
    #[cfg(not(unix))]
    pub(crate) fn open_checked(path: PathBuf) -> Result<Self, OciError> {
        Self::open_dir(path, None)
    }

    /// `blobs/sha256` の検査（`usage::check_blob_dirs` と同じ判定。root の fd 起点）。
    pub(crate) fn check_blob_dirs(&self) -> Result<bool, OciError> {
        Ok(self.open_blob_dir()?.is_some())
    }
}

/// 試験用: パスから検査なしでハンドルを開く（永続化層の関数へ渡す）。
#[cfg(test)]
pub(super) fn rh(p: &Path) -> RootHandle {
    RootHandle::open_unchecked(p).expect("open root handle")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_root(label: &str) -> PathBuf {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fc-oci-roothandle-{}-{}-{label}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    fn sorted(h: &RootHandle) -> Vec<String> {
        let mut v: Vec<String> = h
            .list_names(100)
            .expect("list")
            .into_iter()
            .map(|n| n.to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// OCI-7・SEC-1・#2638: 名前の一覧は何度呼んでも同じ結果（位置を共有しない）。
    #[test]
    fn oci7_list_names_is_repeatable() {
        let r = temp_root("list");
        std::fs::write(r.join("a"), b"1").expect("a");
        std::fs::write(r.join("b"), b"2").expect("b");
        let h = RootHandle::open_unchecked(&r).expect("open");
        assert_eq!(sorted(&h), vec!["a", "b"]);
        assert_eq!(sorted(&h), vec!["a", "b"]);
        assert_eq!(h.list_names(1).expect("limited").len(), 1);
        let _ = std::fs::remove_dir_all(&r);
    }

    /// OCI-7・SEC-1・#2638: `stat_name` は symlink を辿らず、symlink 自身を返す。
    #[cfg(unix)]
    #[test]
    fn oci7_stat_name_does_not_follow_symlink() {
        let r = temp_root("stat");
        std::fs::write(r.join("target"), b"x").expect("target");
        std::os::unix::fs::symlink(r.join("target"), r.join("lnk")).expect("link");
        let h = RootHandle::open_unchecked(&r).expect("open");
        let m = h.stat_name("lnk").expect("stat").expect("some");
        assert!(m.file_type().is_symlink());
        assert!(
            h.stat_name("target")
                .expect("stat")
                .expect("some")
                .is_file()
        );
        assert!(h.stat_name("missing").expect("stat").is_none());
        let _ = std::fs::remove_dir_all(&r);
    }

    /// OCI-7・SEC-1・#2638: `blobs/sha256` が symlink なら `FailedPrecondition`、無ければ `None`。
    #[cfg(unix)]
    #[test]
    fn oci7_open_blob_dir_rejects_symlink() {
        let r = temp_root("blobdir");
        let h = RootHandle::open_unchecked(&r).expect("open");
        assert!(h.open_blob_dir().expect("absent").is_none());
        let other = temp_root("blobdir-other");
        std::fs::create_dir_all(r.join("blobs")).expect("blobs");
        std::os::unix::fs::symlink(&other, r.join("blobs").join("sha256")).expect("link");
        let e = h.open_blob_dir().expect_err("symlinked");
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "blob directory is not a plain directory");
        let _ = std::fs::remove_dir_all(&r);
        let _ = std::fs::remove_dir_all(&other);
    }

    /// OCI-7・SEC-1・#2638: root を別名へ移して空のディレクトリを置いても、ハンドルは元の実体を指す。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn oci7_handle_follows_moved_root() {
        let r = temp_root("moved");
        let h = RootHandle::open_unchecked(&r).expect("open");
        let moved = r.with_file_name(format!(
            "{}-moved",
            r.file_name().expect("name").to_string_lossy()
        ));
        std::fs::rename(&r, &moved).expect("rename");
        std::fs::create_dir(&r).expect("decoy");
        h.create_new("f").expect("create").sync_all().expect("sync");
        assert_eq!(std::fs::read_dir(&r).expect("decoy dir").count(), 0);
        assert!(moved.join("f").is_file());
        assert!(!h.matches(&r));
        let _ = std::fs::remove_dir_all(&r);
        let _ = std::fs::remove_dir_all(&moved);
    }

    /// OCI-7・SEC-1・#2696: root を rmdir した後は `ensure_linked` が `Internal` で拒否する（移動では拒否しない）。
    #[cfg(all(
        unix,
        any(
            not(target_os = "linux"),
            target_arch = "x86_64",
            target_arch = "aarch64"
        )
    ))]
    #[test]
    fn oci7_ensure_linked_rejects_removed_root() {
        let r = temp_root("unlinked");
        let h = RootHandle::open_unchecked(&r).expect("open");
        h.ensure_linked().expect("linked");
        std::fs::remove_dir_all(&r).expect("remove");
        let e = h.ensure_linked().expect_err("removed");
        assert_eq!(e.code(), OciErrorCode::Internal);
        // fd 起点は `st_nlink == 0` を検出する。パス起点の unix（macOS）は
        // root_meta が lstat のため、削除後は到達不能として扱われる。
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        assert_eq!(e.message(), "image store root was removed");
        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        assert_eq!(e.message(), "image store root is not accessible");
    }

    /// OCI-7・SEC-1・#2701: Linux の他アーキテクチャはパス起点へ縮退せず、open の時点で `Unimplemented`
    /// （`layer::anchored` と同じ fail-closed）。CI に該当アーキテクチャの実行環境は無く、型検査のみ。
    #[cfg(all(
        target_os = "linux",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    #[test]
    fn oci7_other_linux_arch_is_rejected() {
        let r = temp_root("other-arch");
        let e = RootHandle::open_unchecked(&r).expect_err("unsupported arch");
        assert_eq!(e.code(), OciErrorCode::Unimplemented);
        assert_eq!(
            e.message(),
            "image store requires directory-fd based access, which is not supported on this architecture"
        );
        let _ = std::fs::remove_dir_all(&r);
    }

    /// OCI-7・SEC-1・ERR-1・#2701: `is_mount_crossing` は固定メッセージの `FailedPrecondition` だけを真にする。
    #[test]
    fn oci7_is_mount_crossing_matches_only_the_fixed_error() {
        assert!(is_mount_crossing(&mount_crossing()));
        assert!(!is_mount_crossing(&OciError::new(
            OciErrorCode::FailedPrecondition,
            "blob directory is not a plain directory"
        )));
        assert!(!is_mount_crossing(&OciError::new(
            OciErrorCode::Internal,
            MOUNT_CROSSING_MESSAGE
        )));
    }

    /// OCI-7・SEC-1・#2695: `entries` は何度呼んでも同じ名前の集合を返し、`open_subdir` は symlink・通常ファイルを
    /// `NotPlain`、不在を `None` にする。`stat` は symlink を辿らない。
    #[cfg(unix)]
    #[test]
    fn oci7_subdir_entries_open_and_stat() {
        let r = temp_root("subdir");
        std::fs::create_dir_all(r.join("d")).expect("d");
        std::fs::write(r.join("d").join("a"), b"1").expect("a");
        std::fs::write(r.join("d").join("b"), b"22").expect("b");
        std::os::unix::fs::symlink(r.join("d").join("a"), r.join("d").join("lnk")).expect("lnk");
        std::fs::write(r.join("file"), b"x").expect("file");
        std::os::unix::fs::symlink(r.join("d"), r.join("dlink")).expect("dlink");
        let h = RootHandle::open_unchecked(&r).expect("open");
        let d = h.open_subdir("d").expect("open d").expect("some");
        let names = |d: &SubDir| {
            let mut v: Vec<String> = d
                .entries()
                .expect("entries")
                .map(|n| n.expect("entry").to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        };
        assert_eq!(names(&d), vec!["a", "b", "lnk"]);
        assert_eq!(names(&d), vec!["a", "b", "lnk"]);
        assert!(d.stat("lnk").expect("stat").expect("some").is_symlink());
        assert_eq!(d.stat("b").expect("stat").expect("some").len(), 2);
        assert!(d.stat("none").expect("stat").is_none());
        assert!(matches!(h.open_subdir("file"), Err(SubDirError::NotPlain)));
        assert!(matches!(h.open_subdir("dlink"), Err(SubDirError::NotPlain)));
        assert!(h.open_subdir("none").expect("absent").is_none());
        // 通常ファイルは読めて、symlink・ディレクトリは欠損（None）。
        assert!(d.open_file("a").expect("open a").is_some());
        assert!(d.open_file("lnk").expect("open lnk").is_none());
        assert!(d.open_file("none").expect("open none").is_none());
        // socket・FIFO は開く前の種類確認で欠損扱い（ENXIO で集計全体が落ちない。OCI-7・SEC-1）。
        let _sock = std::os::unix::net::UnixListener::bind(r.join("d").join("sock")).expect("sock");
        assert!(d.open_file("sock").expect("open sock").is_none());
        let _ = std::fs::remove_dir_all(&r);
    }

    /// OCI-7・SEC-1・#2695: 開いたサブディレクトリは、root を移しておとりを置いた後も元の実体を列挙する。
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn oci7_open_subdir_follows_moved_root() {
        let r = temp_root("subdir-moved");
        std::fs::create_dir_all(r.join("d")).expect("d");
        std::fs::write(r.join("d").join("real"), b"1").expect("real");
        let h = RootHandle::open_unchecked(&r).expect("open");
        let moved = r.with_file_name(format!(
            "{}-moved",
            r.file_name().expect("name").to_string_lossy()
        ));
        std::fs::rename(&r, &moved).expect("rename");
        std::fs::create_dir_all(r.join("d")).expect("decoy d");
        std::fs::write(r.join("d").join("decoy"), b"1").expect("decoy");
        let d = h.open_subdir("d").expect("open").expect("some");
        let v: Vec<String> = d
            .entries()
            .expect("entries")
            .map(|n| n.expect("entry").to_string_lossy().into_owned())
            .collect();
        assert_eq!(v, vec!["real"]);
        let _ = std::fs::remove_dir_all(&r);
        let _ = std::fs::remove_dir_all(&moved);
    }
}
