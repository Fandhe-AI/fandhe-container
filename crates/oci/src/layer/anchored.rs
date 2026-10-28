//! 展開先 `root` のディレクトリ fd 起点の操作（レイヤー展開の変更操作の閉じ込め。OCI-1・OCI-2・SEC-5・#2437）。
//!
//! # 役割
//! `layer::extract` の `Extractor` は、各コンポーネントを `lstat` で確かめながら `root` 内の物理位置（symlink を
//! 含まないコンポーネント列）を解決する。ただし確認から使用までの間に祖先が symlink へ差し替えられると、
//! 文字列パスに対する変更操作は `root` の外へ出うる（TOCTOU）。本モジュールは変更操作（作成・削除・symlink・
//! hardlink・`chown`・mode 変更）を、`root` を開いた fd を起点に行う口に束ねる。
//!
//! # 方式（Linux の x86_64 / aarch64）
//! - `root` は展開の開始時に 1 回だけ `openat2` で開き（`O_NOFOLLOW`）、以後パスで開き直さない。
//! - 親ディレクトリは、解決済みのコンポーネント列を `root` の fd からの相対パスとして
//!   `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)` で開き直す。
//!   コンポーネント列には symlink も `..` も含まれないはずなので、`RESOLVE_NO_SYMLINKS` は差し替えの検出器に
//!   なる。確認の後に祖先が symlink へ差し替えられていれば `ELOOP`、マウントをまたげば `EXDEV`、非ディレクトリへ
//!   差し替えられていれば `ENOTDIR` で失敗し、`FailedPrecondition`（`path_changed`）で fail-closed にする。
//!   `RESOLVE_IN_ROOT` は二重の保険（仮に `..` や絶対パスが混じっても `root` の外へ出ない）である。
//! - 最終コンポーネントへの操作は親 fd に対する `*at(2)` で、追従しない形（`O_EXCL`・`O_NOFOLLOW`・
//!   `AT_SYMLINK_NOFOLLOW`・`linkat` の flags 0）で行う。
//! - 古いカーネル（`openat2` は Linux 5.6 以降）や seccomp で `openat2` が使えない場合は、パス起点へ縮退せず
//!   `Unimplemented` で展開の開始前に拒否する（fail-closed）。`Strip` ポリシーでも同じ。
//!
//! - 木ごとの削除は子を 1 コンポーネントずつ `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` で
//!   開いて下降する。所有者に `r` が無い（0000 等）ディレクトリは `O_PATH` の fd と `/proc/self/fd` 経由で権限を
//!   戻して開き直す（`/proc` が必要。#2598）。公開の `remove_extracted_tree` も `remove_path_tree` でこの経路を使う
//!   （`path` の親だけは信頼済みの接頭辞としてパスで開く）。マウントをまたぐ木は `FailedPrecondition` で拒否する
//!   （非特権では作れないため試験で確かめていない）。
//!
//! # 他の OS・アーキテクチャ
//! macOS・Windows・Linux の他アーキテクチャは従来どおりパス起点の `std::fs` で動く（特殊ビットの保持は
//! Linux 限定で `UnsupportedHost` に落ちるため、SEC-5 の TOCTOU は Linux 固有）。Linux の x86_64 / aarch64 以外は
//! 定数と syscall 番号を確かめていないため、`open` が `Unimplemented` で拒否する。
//!
//! 展開と `remove_extracted_tree` を fd 起点にしない理由（#2598）: macOS・Windows の本番経路は cli の
//! `non_linux_failure` が先に fail-closed にし、ホストでの展開に届かない（実行はゲストの Linux 側）。macOS の
//! `openat` 系・Windows のハンドル起点操作には新しい FFI 宣言と libc 照合・オーナー判断が要る。Linux の他
//! アーキテクチャでは展開が `Unimplemented` のため展開物が存在せず、`remove_extracted_tree` は空の木を消すだけ
//! なのでパス起点のままにする。残余はパス起点の TOCTOU（確認から使用までの間の祖先の差し替え）と、木の中に
//! 残ったマウントの中身まで消しうること（REPAIR-3。`docs/design/oci-layer-special-bits.md` の「未実装」）。
//!
//! # 呼び出し文脈
//! `extract_stack` / `extract_zero_layers` が `AnchoredRoot::open` で作り、`Extractor` が保持する。syscall は
//! `crate::sys::at`（`unsafe` の事前承認の範囲）にだけあり、本モジュールは安全な API だけを使う。

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use crate::error::{OciError, OciErrorCode};

use super::extract::{err, map_fs_err};

/// 確認の後に展開経路が差し替えられた（または差し替えが疑われる）ときのエラー（パスは載せない）。
pub(super) fn path_changed() -> OciError {
    err(
        OciErrorCode::FailedPrecondition,
        "an extraction path changed during extraction",
    )
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod imp {
    use std::io::Seek as _;
    use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
    use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::unix::fs::PermissionsExt as _;

    use super::{
        File, OciError, OciErrorCode, OsStr, OsString, Path, PathBuf, err, fs, io, map_fs_err,
        path_changed,
    };
    use crate::sys::at;
    use crate::whiteout::MAX_REMOVE_DEPTH;

    /// `openat2` の差し替え口（試験だけが差し替える。既定は `crate::sys::at::openat2`）。
    pub(in crate::layer) type Openat2Fn =
        fn(Option<BorrowedFd<'_>>, &std::ffi::CStr, u64, u64, u64) -> io::Result<OwnedFd>;

    /// 展開で差し替える部品（試験だけが差し替える）。
    #[derive(Clone, Copy)]
    pub(in crate::layer) struct AnchorHooks {
        pub(in crate::layer) openat2: Openat2Fn,
    }

    impl AnchorHooks {
        pub(in crate::layer) fn host() -> Self {
            Self {
                openat2: at::openat2,
            }
        }
    }

    /// 親ディレクトリを開くときの `openat2` の解決フラグ（モジュール冒頭「方式」）。
    const RESOLVE: u64 = at::RESOLVE_IN_ROOT
        | at::RESOLVE_NO_SYMLINKS
        | at::RESOLVE_NO_MAGICLINKS
        | at::RESOLVE_NO_XDEV;
    /// `RESOLVE_IN_ROOT` / `RESOLVE_BENEATH` が競合を検出したときの `EAGAIN` の再試行の上限。
    const MAX_EAGAIN_RETRIES: u32 = 8;
    /// ディレクトリを空にする走査の最大パス数（削除中の列挙の取りこぼしを拾い直す。無限ループにしない）。
    const MAX_DRAIN_PASSES: u32 = 64;
    /// `getdents64` のバッファ長。
    const DIRENT_BUF_LEN: usize = 16 * 1024;
    /// `readlinkat` のバッファ長（`MAX_PATH_BYTES` より 1 大きくして切り詰めを検出する）。
    const LINK_BUF_LEN: usize = 4097;

    const DIR_FLAGS: u64 = at::O_PATH | at::O_DIRECTORY | at::O_NOFOLLOW | at::O_CLOEXEC;
    const DIR_FLAGS_RW: u64 = at::O_RDONLY | at::O_DIRECTORY | at::O_NOFOLLOW | at::O_CLOEXEC;
    const ENOENT: i32 = 2;

    /// `openat2` 等の errno を構造化エラーにする。差し替えの疑い（`ELOOP`・`EXDEV`・`ENOTDIR`・`EAGAIN` の
    /// 再試行超過）は `path_changed`、それ以外は `map_fs_err`。
    pub(in crate::layer) fn map_at_err(e: &io::Error) -> OciError {
        match e.raw_os_error() {
            Some(at::ELOOP | at::EXDEV | at::ENOTDIR | at::EAGAIN) => path_changed(),
            _ => map_fs_err(e),
        }
    }

    /// `root` を開いたディレクトリ fd と、そこを起点にした変更操作（モジュール冒頭を参照）。
    pub(in crate::layer) struct AnchoredRoot {
        root: File,
        /// 試験と診断だけが使うパス（`debug_path`）。変更操作には使わない。
        #[cfg(test)]
        path: PathBuf,
        hooks: AnchorHooks,
    }

    impl AnchoredRoot {
        /// `root` を `O_NOFOLLOW | O_DIRECTORY` で 1 回だけ開く。`openat2` が使えなければ `Unimplemented`。
        pub(in crate::layer) fn open(root: &Path, hooks: AnchorHooks) -> Result<Self, OciError> {
            let c = std::ffi::CString::new(root.as_os_str().as_bytes()).map_err(|_| {
                err(
                    OciErrorCode::InvalidArgument,
                    "extraction root path is invalid",
                )
            })?;
            let fd = (hooks.openat2)(None, &c, DIR_FLAGS_RW, 0, 0).map_err(|e| {
                match e.raw_os_error() {
                    Some(at::ENOSYS | at::E2BIG | at::EINVAL) => err(
                        OciErrorCode::Unimplemented,
                        "openat2 is not available on this kernel",
                    ),
                    Some(at::ELOOP | at::ENOTDIR) => err(
                        OciErrorCode::InvalidArgument,
                        "extraction root is not a directory",
                    ),
                    _ => map_fs_err(&e),
                }
            })?;
            Ok(Self {
                root: File::from(fd),
                #[cfg(test)]
                path: root.to_path_buf(),
                hooks,
            })
        }

        /// `root` 自身のメタデータ（fd の `fstat`。パスを開き直さない）。
        pub(in crate::layer) fn root_meta(&self) -> io::Result<fs::Metadata> {
            self.root.metadata()
        }

        /// `root` が空か（fd 経由で列挙する）。
        pub(in crate::layer) fn root_is_empty(&self) -> io::Result<bool> {
            let mut buf = vec![0u8; DIRENT_BUF_LEN];
            (&self.root).rewind()?;
            loop {
                let n = at::getdents64(self.root.as_fd(), &mut buf)?;
                if n == 0 {
                    return Ok(true);
                }
                let mut any = false;
                at::for_each_dirent(buf.get(..n).unwrap_or(&[]), |_| any = true)?;
                if any {
                    return Ok(false);
                }
            }
        }

        /// 試験だけが使うパス（変更操作には使わない）。
        #[cfg(test)]
        pub(in crate::layer) fn debug_path(&self, comps: &[OsString]) -> PathBuf {
            let mut p = self.path.clone();
            p.extend(comps);
            p
        }

        fn open_rel(&self, comps: &[OsString], flags: u64) -> io::Result<OwnedFd> {
            let rel = at::relative_cstring(comps)?;
            let mut tries = 0;
            loop {
                match (self.hooks.openat2)(Some(self.root.as_fd()), &rel, flags, 0, RESOLVE) {
                    Err(e)
                        if e.raw_os_error() == Some(at::EAGAIN) && tries < MAX_EAGAIN_RETRIES =>
                    {
                        tries += 1;
                    }
                    r => return r,
                }
            }
        }

        fn parent(&self, comps: &[OsString]) -> io::Result<OwnedFd> {
            self.open_rel(comps, DIR_FLAGS)
        }

        pub(in crate::layer) fn mkdir(&self, parent: &[OsString], name: &OsStr) -> io::Result<()> {
            at::mkdirat_name(self.parent(parent)?.as_fd(), name, 0o777)
        }

        pub(in crate::layer) fn create_file(
            &self,
            parent: &[OsString],
            name: &OsStr,
        ) -> io::Result<File> {
            let dir = self.parent(parent)?;
            let n = at::component_cstring(name)?;
            let fd = (self.hooks.openat2)(
                Some(dir.as_fd()),
                &n,
                at::O_WRONLY | at::O_CREAT | at::O_EXCL | at::O_NOFOLLOW | at::O_CLOEXEC,
                0o666,
                at::RESOLVE_NO_SYMLINKS | at::RESOLVE_NO_MAGICLINKS | at::RESOLVE_NO_XDEV,
            )?;
            Ok(File::from(fd))
        }

        pub(in crate::layer) fn symlink(
            &self,
            parent: &[OsString],
            name: &OsStr,
            target: &OsStr,
        ) -> io::Result<()> {
            at::symlinkat_name(target, self.parent(parent)?.as_fd(), name)
        }

        pub(in crate::layer) fn read_link(
            &self,
            parent: &[OsString],
            name: &OsStr,
        ) -> io::Result<PathBuf> {
            let dir = self.parent(parent)?;
            let mut buf = vec![0u8; LINK_BUF_LEN];
            let n = at::readlinkat_name(dir.as_fd(), name, &mut buf)?;
            buf.truncate(n);
            Ok(PathBuf::from(OsString::from_vec(buf)))
        }

        pub(in crate::layer) fn unlink(&self, parent: &[OsString], name: &OsStr) -> io::Result<()> {
            at::unlinkat_name(self.parent(parent)?.as_fd(), name, false)
        }

        pub(in crate::layer) fn hardlink(
            &self,
            target_parent: &[OsString],
            target_name: &OsStr,
            parent: &[OsString],
            name: &OsStr,
        ) -> io::Result<()> {
            let t = self.parent(target_parent)?;
            let d = self.parent(parent)?;
            at::linkat_names(t.as_fd(), target_name, d.as_fd(), name)
        }

        /// `parent/name` が通常ファイルか（追従しない）。作った hardlink の事後確認に使う。
        pub(in crate::layer) fn is_regular_file(
            &self,
            parent: &[OsString],
            name: &OsStr,
        ) -> io::Result<bool> {
            let dir = self.parent(parent)?;
            let n = at::component_cstring(name)?;
            let fd = (self.hooks.openat2)(
                Some(dir.as_fd()),
                &n,
                at::O_PATH | at::O_NOFOLLOW | at::O_CLOEXEC,
                0,
                at::RESOLVE_NO_SYMLINKS | at::RESOLVE_NO_MAGICLINKS | at::RESOLVE_NO_XDEV,
            )?;
            Ok(File::from(fd).metadata()?.is_file())
        }

        /// `comps`（`root` からの物理コンポーネント列。空なら `root` 自身）の所有者を、追従せずに変える。
        pub(in crate::layer) fn lchown(
            &self,
            comps: &[OsString],
            uid: u32,
            gid: u32,
        ) -> io::Result<()> {
            let Some((name, parent)) = comps.split_last() else {
                return std::os::unix::fs::fchown(&self.root, Some(uid), Some(gid));
            };
            at::lchown_name(self.parent(parent)?.as_fd(), name, uid, gid)
        }

        /// `comps` がディレクトリであることを確かめる（追従しない）。
        pub(in crate::layer) fn check_dir(&self, comps: &[OsString]) -> io::Result<()> {
            self.open_rel(comps, DIR_FLAGS_RW).map(drop)
        }

        /// `comps` のディレクトリの mode を fd 経由で適用する（`fchmod`）。
        pub(in crate::layer) fn set_dir_mode(
            &self,
            comps: &[OsString],
            mode: u32,
        ) -> io::Result<()> {
            let perms = fs::Permissions::from_mode(mode & 0o7777);
            match self.open_rel(comps, DIR_FLAGS_RW) {
                Ok(fd) => File::from(fd).set_permissions(perms),
                // umask で所有者の読み取り権限が落ちた新規ディレクトリ（0400・0777 等）は読み取りで開けない。
                // 読み取り権限を要らない `O_PATH` の fd を握り、`/proc/self/fd/<n>` 経由で mode を適用する
                // （fd 起点のまま。パスの再解決をしない。#2565 P1）。
                Err(e) if e.raw_os_error() == Some(at::EACCES) => {
                    let fd = self.open_rel(comps, DIR_FLAGS)?;
                    let p = format!("/proc/self/fd/{}", fd.as_raw_fd());
                    fs::set_permissions(p, perms)
                }
                Err(e) => Err(e),
            }
        }

        /// `parent/name` を symlink を追従せず木ごと消す。存在しなければ成功（冪等）。
        ///
        /// 所有者に `r` がないディレクトリ（0000 等）は、`O_PATH` の fd と `/proc/self/fd` 経由で権限を戻して
        /// 開き直してから消す（`open_dir_for_removal`。パスを解決し直さない。#2598）。公開の
        /// `remove_extracted_tree` も同じ部品（`remove_path_tree`）を使う。
        pub(in crate::layer) fn remove_tree(
            &self,
            parent: &[OsString],
            name: &OsStr,
        ) -> Result<(), OciError> {
            let dir = match self.parent(parent) {
                Ok(d) => d,
                Err(e) if e.raw_os_error() == Some(ENOENT) => return Ok(()),
                Err(e) => return Err(map_at_err(&e)),
            };
            let mut buf = vec![0u8; DIRENT_BUF_LEN];
            remove_at(self.hooks.openat2, dir.as_fd(), name, 0, &mut buf, &|| {
                Ok(())
            })
        }

        /// `comps` のディレクトリ自体は残し、直下を symlink を追従せず木ごと消す（不透明ディレクトリ）。
        pub(in crate::layer) fn remove_contents(&self, comps: &[OsString]) -> Result<(), OciError> {
            let opened = match self.open_rel(comps, DIR_FLAGS_RW) {
                // 0000 の不透明ディレクトリ: `O_PATH` で握って権限を戻し、同じ inode を開き直す（#2598）。
                Err(e) if e.raw_os_error() == Some(at::EACCES) => {
                    self.open_rel(comps, DIR_FLAGS).and_then(reopen_readable)
                }
                r => r.map(File::from),
            };
            let dir = match opened {
                Ok(d) => d,
                Err(e) if e.raw_os_error() == Some(ENOENT) => return Ok(()),
                Err(e) if matches!(e.raw_os_error(), Some(at::ELOOP | at::ENOTDIR)) => {
                    return Err(err(
                        OciErrorCode::FailedPrecondition,
                        "opaque directory is not a directory",
                    ));
                }
                Err(e) => return Err(map_at_err(&e)),
            };
            make_removable(&dir)?;
            let mut buf = vec![0u8; DIRENT_BUF_LEN];
            remove_contents_of(self.hooks.openat2, &dir, 1, &mut buf, &|| Ok(()))
        }
    }

    /// 削除のために下降する子の `openat2` 解決フラグ（symlink・マジックリンク・マウント越えを拒否する）。
    const RESOLVE_DESCEND: u64 =
        at::RESOLVE_NO_SYMLINKS | at::RESOLVE_NO_MAGICLINKS | at::RESOLVE_NO_XDEV;

    /// `O_PATH` の fd が指すディレクトリの所有者権限を戻し、同じ inode を読み取りで開き直す（#2598）。
    ///
    /// 所有者に `r` が無い（0000 等）ディレクトリは `O_RDONLY` で開けない。`set_dir_mode` と同じく
    /// `/proc/self/fd/<n>` 経由で mode を適用し（fd 起点のまま。`fchmodat` は最終コンポーネントの symlink を
    /// 追従するため使わない）、その fd を起点に `.` を開き直す（名前の再解決は起きない）。`/proc` が無い環境では
    /// 失敗する。`ENOENT` を `NotFound` として「既に無い」と取り違えて黙って残さないよう `ENOSYS` に写す。
    fn reopen_readable(opath: OwnedFd) -> io::Result<File> {
        let meta = File::from(opath.try_clone()?).metadata()?;
        let mode = meta.permissions().mode();
        if mode & 0o700 != 0o700 {
            let p = format!("/proc/self/fd/{}", opath.as_raw_fd());
            fs::set_permissions(p, fs::Permissions::from_mode((mode | 0o700) & 0o7777)).map_err(
                |e| {
                    if e.raw_os_error() == Some(ENOENT) {
                        io::Error::from_raw_os_error(at::ENOSYS)
                    } else {
                        e
                    }
                },
            )?;
        }
        let dot = at::relative_cstring::<&str>(&[])?;
        at::openat2(Some(opath.as_fd()), &dot, DIR_FLAGS_RW, 0, RESOLVE_DESCEND).map(File::from)
    }

    /// `dirfd` 直下のディレクトリ `name` を削除のために開く。所有者に `r` が無ければ権限を戻して開き直す。
    fn open_dir_for_removal(
        openat2: Openat2Fn,
        dirfd: BorrowedFd<'_>,
        name: &std::ffi::CStr,
    ) -> io::Result<File> {
        match openat2(Some(dirfd), name, DIR_FLAGS_RW, 0, RESOLVE_DESCEND) {
            Ok(fd) => Ok(File::from(fd)),
            Err(e) if e.raw_os_error() == Some(at::EACCES) => {
                openat2(Some(dirfd), name, DIR_FLAGS, 0, RESOLVE_DESCEND).and_then(reopen_readable)
            }
            Err(e) => Err(e),
        }
    }

    /// 公開の `remove_extracted_tree` の本体。`path` の最終コンポーネントを、親ディレクトリ fd 起点で木ごと消す。
    ///
    /// 親は信頼済みの接頭辞（呼び出し側が所有するステージング等）としてパスで 1 回だけ開き、`path` から下は
    /// 1 コンポーネントずつ `RESOLVE_DESCEND` で開く。差し替え（symlink・マウント越え）は `FailedPrecondition`
    /// で拒否し `path` の外を消さない（OCI-1・SEC-5・#2598）。`file_name` を持たない `path`（`/`・`..` 終わり）は
    /// `InvalidArgument`。親が無ければ成功（冪等）。
    pub(in crate::layer) fn remove_path_tree(path: &Path) -> Result<(), OciError> {
        remove_path_tree_checked(path, &|| Ok(()))
    }

    /// `remove_path_tree` に確認点 `check` を足した版（期限・取り消し。#3142・CRI-2・REPAIR-5）。
    ///
    /// `check` はエントリ 1 件を消す前と、空の走査になるまでの各パスの前に呼ぶ。`Err` ならそこで止まり、消した分は
    /// 残る（再実行は冪等で続きから進む）。検査（`RESOLVE_DESCEND`・深さ・走査回数）の順序は変えない。
    pub(in crate::layer) fn remove_path_tree_checked(
        path: &Path,
        check: &dyn Fn() -> Result<(), OciError>,
    ) -> Result<(), OciError> {
        let bad = || err(OciErrorCode::InvalidArgument, "path to remove is invalid");
        let name = path.file_name().ok_or_else(bad)?;
        at::component_cstring(name).map_err(|_| bad())?;
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let parent_c = if parent.as_os_str().is_empty() {
            std::ffi::CString::new(".")
        } else {
            std::ffi::CString::new(parent.as_os_str().as_bytes())
        }
        .map_err(|_| bad())?;
        let dir = match at::openat2(
            None,
            &parent_c,
            at::O_PATH | at::O_DIRECTORY | at::O_CLOEXEC,
            0,
            0,
        ) {
            Ok(d) => d,
            Err(e) if e.raw_os_error() == Some(ENOENT) => return Ok(()),
            Err(e) if e.raw_os_error() == Some(at::ENOTDIR) => return Err(bad()),
            Err(e) => return Err(map_fs_err(&e)),
        };
        let mut buf = vec![0u8; DIRENT_BUF_LEN];
        remove_at(at::openat2, dir.as_fd(), name, 0, &mut buf, check)
    }

    /// `dirfd` 直下の `name`（1 コンポーネント）を symlink を追従せず木ごと消す（存在しなければ成功）。
    ///
    /// イメージストアの staging（`image_management` の pull 回収・中止）が、root の fd 起点で開いた
    /// pull ディレクトリの子を消すために使う（OCI-7・SEC-1・#2694）。下降は 1 コンポーネントずつ
    /// `RESOLVE_NO_SYMLINKS` で開き、深さと走査回数に上限がある（`remove_at` を参照）。
    pub(crate) fn remove_name_tree(dirfd: BorrowedFd<'_>, name: &OsStr) -> Result<(), OciError> {
        let mut buf = vec![0u8; DIRENT_BUF_LEN];
        remove_at(at::openat2, dirfd, name, 0, &mut buf, &|| Ok(()))
    }

    /// 所有者の rwx が欠けるディレクトリは権限を戻す（中身を消せるように）。
    fn make_removable(dir: &File) -> Result<(), OciError> {
        let mode = dir
            .metadata()
            .map_err(|e| map_fs_err(&e))?
            .permissions()
            .mode();
        if mode & 0o700 != 0o700 {
            dir.set_permissions(fs::Permissions::from_mode(mode | 0o700))
                .map_err(|e| map_fs_err(&e))?;
        }
        Ok(())
    }

    /// `dirfd` 直下の `name` を symlink を追従せず木ごと消す（存在しなければ成功）。
    fn remove_at(
        openat2: Openat2Fn,
        dirfd: BorrowedFd<'_>,
        name: &OsStr,
        depth: usize,
        buf: &mut [u8],
        check: &dyn Fn() -> Result<(), OciError>,
    ) -> Result<(), OciError> {
        check()?;
        let first = match at::unlinkat_name(dirfd, name, false) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        match first.raw_os_error() {
            Some(ENOENT) => return Ok(()),
            // Linux はディレクトリへの `unlink` に `EISDIR`（POSIX 上は `EPERM`）を返す。
            Some(at::EISDIR | at::EPERM) => {}
            _ => return Err(map_at_err(&first)),
        }
        if depth >= MAX_REMOVE_DEPTH {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "directory tree to remove is too deep",
            ));
        }
        let n = at::component_cstring(name).map_err(|e| map_fs_err(&e))?;
        let child = match open_dir_for_removal(openat2, dirfd, &n) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(ENOENT) => return Ok(()),
            Err(e) if matches!(e.raw_os_error(), Some(at::ELOOP | at::ENOTDIR)) => {
                // 本物のディレクトリではない: 元の `EPERM` は権限の失敗、それ以外は差し替え。
                return Err(if first.raw_os_error() == Some(at::EPERM) {
                    map_fs_err(&first)
                } else {
                    path_changed()
                });
            }
            Err(e) => return Err(map_at_err(&e)),
        };
        make_removable(&child)?;
        remove_contents_of(openat2, &child, depth + 1, buf, check)?;
        match at::unlinkat_name(dirfd, name, true) {
            Ok(()) => Ok(()),
            Err(e) if e.raw_os_error() == Some(ENOENT) => Ok(()),
            Err(e) => Err(map_at_err(&e)),
        }
    }

    /// `dir` 直下の全エントリを木ごと消す。列挙中の削除で取りこぼしがないよう、空の走査になるまで繰り返す。
    fn remove_contents_of(
        openat2: Openat2Fn,
        dir: &File,
        depth: usize,
        buf: &mut [u8],
        check: &dyn Fn() -> Result<(), OciError>,
    ) -> Result<(), OciError> {
        for _ in 0..MAX_DRAIN_PASSES {
            check()?;
            (&*dir).rewind().map_err(|e| map_fs_err(&e))?;
            let mut any = false;
            loop {
                let n = at::getdents64(dir.as_fd(), buf).map_err(|e| map_fs_err(&e))?;
                if n == 0 {
                    break;
                }
                let mut names: Vec<OsString> = Vec::new();
                at::for_each_dirent(buf.get(..n).unwrap_or(&[]), |nm| {
                    names.push(OsStr::from_bytes(nm).to_os_string());
                })
                .map_err(|_| err(OciErrorCode::Internal, "failed to list a directory"))?;
                for nm in names {
                    any = true;
                    remove_at(openat2, dir.as_fd(), &nm, depth, buf, check)?;
                }
            }
            if !any {
                return Ok(());
            }
        }
        Err(err(
            OciErrorCode::ResourceExhausted,
            "directory tree to remove keeps changing",
        ))
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod imp {
    use super::{
        File, OciError, OciErrorCode, OsStr, OsString, Path, PathBuf, err, fs, io, map_fs_err,
    };
    use crate::whiteout;

    /// 差し替える部品は無い（パス起点の実装）。
    #[derive(Clone, Copy)]
    pub(in crate::layer) struct AnchorHooks;

    impl AnchorHooks {
        pub(in crate::layer) fn host() -> Self {
            Self
        }
    }

    /// 構造化エラーへの写像（差し替え検出は fd 起点の実装だけが行う）。
    pub(in crate::layer) fn map_at_err(e: &io::Error) -> OciError {
        map_fs_err(e)
    }

    /// パス起点の実装（macOS・Windows・Linux の他アーキテクチャ。モジュール冒頭「他の OS・アーキテクチャ」）。
    pub(in crate::layer) struct AnchoredRoot {
        root: PathBuf,
    }

    impl AnchoredRoot {
        /// Linux の対応外アーキテクチャは、定数を確かめていないため `Unimplemented` で拒否する（fail-closed）。
        pub(in crate::layer) fn open(root: &Path, _hooks: AnchorHooks) -> Result<Self, OciError> {
            if cfg!(target_os = "linux") {
                return Err(err(
                    OciErrorCode::Unimplemented,
                    "directory-fd based extraction is not supported on this architecture",
                ));
            }
            match fs::symlink_metadata(root) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => {
                    return Err(err(
                        OciErrorCode::InvalidArgument,
                        "extraction root is not a directory",
                    ));
                }
                Err(e) => return Err(map_fs_err(&e)),
            }
            Ok(Self {
                root: root.to_path_buf(),
            })
        }

        // 特殊ビットの保持（`root` の再確認）は Linux 限定のため、他の OS では呼ばれない。
        #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
        pub(in crate::layer) fn root_meta(&self) -> io::Result<fs::Metadata> {
            fs::symlink_metadata(&self.root)
        }

        pub(in crate::layer) fn root_is_empty(&self) -> io::Result<bool> {
            match fs::read_dir(&self.root)?.next() {
                None => Ok(true),
                Some(Ok(_)) => Ok(false),
                Some(Err(e)) => Err(e),
            }
        }

        pub(in crate::layer) fn debug_path(&self, comps: &[OsString]) -> PathBuf {
            let mut p = self.root.clone();
            p.extend(comps);
            p
        }

        fn at(&self, parent: &[OsString], name: &OsStr) -> PathBuf {
            let mut p = self.debug_path(parent);
            p.push(name);
            p
        }

        pub(in crate::layer) fn mkdir(&self, parent: &[OsString], name: &OsStr) -> io::Result<()> {
            fs::create_dir(self.at(parent, name))
        }

        pub(in crate::layer) fn create_file(
            &self,
            parent: &[OsString],
            name: &OsStr,
        ) -> io::Result<File> {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.at(parent, name))
        }

        #[cfg(unix)]
        pub(in crate::layer) fn symlink(
            &self,
            parent: &[OsString],
            name: &OsStr,
            target: &OsStr,
        ) -> io::Result<()> {
            std::os::unix::fs::symlink(target, self.at(parent, name))
        }

        #[cfg(not(unix))]
        pub(in crate::layer) fn symlink(
            &self,
            _parent: &[OsString],
            _name: &OsStr,
            _target: &OsStr,
        ) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        pub(in crate::layer) fn read_link(
            &self,
            parent: &[OsString],
            name: &OsStr,
        ) -> io::Result<PathBuf> {
            fs::read_link(self.at(parent, name))
        }

        pub(in crate::layer) fn unlink(&self, parent: &[OsString], name: &OsStr) -> io::Result<()> {
            fs::remove_file(self.at(parent, name))
        }

        pub(in crate::layer) fn hardlink(
            &self,
            target_parent: &[OsString],
            target_name: &OsStr,
            parent: &[OsString],
            name: &OsStr,
        ) -> io::Result<()> {
            fs::hard_link(self.at(target_parent, target_name), self.at(parent, name))
        }

        pub(in crate::layer) fn is_regular_file(
            &self,
            parent: &[OsString],
            name: &OsStr,
        ) -> io::Result<bool> {
            Ok(fs::symlink_metadata(self.at(parent, name))?.is_file())
        }

        #[cfg(unix)]
        pub(in crate::layer) fn lchown(
            &self,
            comps: &[OsString],
            uid: u32,
            gid: u32,
        ) -> io::Result<()> {
            std::os::unix::fs::lchown(self.debug_path(comps), Some(uid), Some(gid))
        }

        // 非 unix の `ChownFns::host` は `unsupported` を返すだけで、この関数は呼ばれない。
        #[cfg(not(unix))]
        #[allow(dead_code)]
        pub(in crate::layer) fn lchown(
            &self,
            _comps: &[OsString],
            _uid: u32,
            _gid: u32,
        ) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        pub(in crate::layer) fn check_dir(&self, comps: &[OsString]) -> io::Result<()> {
            if fs::symlink_metadata(self.debug_path(comps))?.is_dir() {
                Ok(())
            } else {
                Err(io::Error::from(io::ErrorKind::InvalidInput))
            }
        }

        #[cfg(unix)]
        pub(in crate::layer) fn set_dir_mode(
            &self,
            comps: &[OsString],
            mode: u32,
        ) -> io::Result<()> {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                self.debug_path(comps),
                fs::Permissions::from_mode(mode & 0o7777),
            )
        }

        #[cfg(not(unix))]
        pub(in crate::layer) fn set_dir_mode(
            &self,
            _comps: &[OsString],
            _mode: u32,
        ) -> io::Result<()> {
            Ok(())
        }

        pub(in crate::layer) fn remove_tree(
            &self,
            parent: &[OsString],
            name: &OsStr,
        ) -> Result<(), OciError> {
            whiteout::remove_tree_nofollow(&self.at(parent, name))
        }

        pub(in crate::layer) fn remove_contents(&self, comps: &[OsString]) -> Result<(), OciError> {
            whiteout::remove_dir_contents_nofollow(&self.debug_path(comps))
        }
    }

    /// 公開の `remove_extracted_tree` の本体（パス起点。fd 起点は Linux の x86_64 / aarch64 のみ。#2598）。
    pub(in crate::layer) fn remove_path_tree(path: &Path) -> Result<(), OciError> {
        whiteout::remove_tree_nofollow(path)
    }

    /// 確認点つきの版（パス起点。エントリごとに `check` を呼ぶ。#3142）。
    pub(in crate::layer) fn remove_path_tree_checked(
        path: &Path,
        check: &dyn Fn() -> Result<(), OciError>,
    ) -> Result<(), OciError> {
        whiteout::remove_tree_nofollow_checked(path, check)
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use imp::remove_name_tree;
pub(super) use imp::{
    AnchorHooks, AnchoredRoot, map_at_err, remove_path_tree, remove_path_tree_checked,
};
#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use std::os::fd::{BorrowedFd, OwnedFd};
    use std::os::unix::fs::PermissionsExt as _;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("fc-oci-anchored-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    /// OCI-2・SEC-5・#2437: fd 起点の木ごとの削除は、0555 / 0500 のディレクトリの権限を戻して消し、
    /// symlink は追従せずリンクだけを消す。`root` の外のファイルは残る。
    #[test]
    fn oci2_remove_tree_modes_and_symlinks_are_confined() {
        let base = tmp("rm");
        let root = base.join("root");
        let outside = base.join("outside");
        fs::create_dir_all(root.join("t/ro/deep")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("keep"), b"k").unwrap();
        fs::write(root.join("t/ro/deep/f"), b"f").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("t/link")).unwrap();
        fs::set_permissions(root.join("t/ro/deep"), fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(root.join("t/ro"), fs::Permissions::from_mode(0o555)).unwrap();
        let a = AnchoredRoot::open(&root, AnchorHooks::host()).unwrap();
        a.remove_tree(&[], OsStr::new("t")).unwrap();
        assert!(fs::symlink_metadata(root.join("t")).is_err());
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"k");
        // 冪等: 無ければ成功。
        a.remove_tree(&[], OsStr::new("t")).unwrap();
        a.remove_tree(&os(&["none"]), OsStr::new("x")).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    /// OCI-2・#2437: 不透明ディレクトリは自身を残して中身だけを消し、非ディレクトリ・symlink は拒否する。
    #[test]
    fn oci2_remove_contents_keeps_dir_and_rejects_non_dirs() {
        let base = tmp("opq");
        let root = base.join("root");
        fs::create_dir_all(root.join("d/sub")).unwrap();
        fs::write(root.join("d/a"), b"a").unwrap();
        fs::write(root.join("d/sub/b"), b"b").unwrap();
        fs::write(root.join("file"), b"f").unwrap();
        std::os::unix::fs::symlink(&base, root.join("lnk")).unwrap();
        let a = AnchoredRoot::open(&root, AnchorHooks::host()).unwrap();
        a.remove_contents(&os(&["d"])).unwrap();
        assert!(root.join("d").is_dir());
        assert_eq!(fs::read_dir(root.join("d")).unwrap().count(), 0);
        a.remove_contents(&os(&["none"])).unwrap();
        for bad in ["file", "lnk"] {
            let e = a.remove_contents(&os(&[bad])).unwrap_err();
            assert_eq!(e.code(), OciErrorCode::FailedPrecondition, "{bad}");
        }
        assert!(base.is_dir());
        fs::remove_dir_all(&base).unwrap();
    }

    /// OCI-2・SEC-5・#2598: 所有者に `r` が無い（0000）ディレクトリと 0555 の下の 0000 も、fd 起点の削除
    /// （`remove_tree` と `remove_path_tree`）が権限を戻して消す。`root` の外は残る。
    #[test]
    fn oci2_remove_tree_removes_unreadable_0000_dirs() {
        for via_path in [false, true] {
            let base = tmp(if via_path { "z0path" } else { "z0root" });
            let root = base.join("root");
            let outside = base.join("outside");
            fs::create_dir_all(root.join("t/a")).unwrap();
            fs::create_dir_all(root.join("t/ro/z")).unwrap();
            fs::create_dir_all(&outside).unwrap();
            fs::write(outside.join("keep"), b"k").unwrap();
            fs::write(root.join("t/ro/z/f"), b"f").unwrap();
            for (p, m) in [("t/ro/z", 0o000), ("t/ro", 0o555), ("t/a", 0o000)] {
                fs::set_permissions(root.join(p), fs::Permissions::from_mode(m)).unwrap();
            }
            if via_path {
                remove_path_tree(&root.join("t")).unwrap();
            } else {
                let a = AnchoredRoot::open(&root, AnchorHooks::host()).unwrap();
                a.remove_tree(&[], OsStr::new("t")).unwrap();
            }
            assert!(fs::symlink_metadata(root.join("t")).is_err());
            assert_eq!(fs::read(outside.join("keep")).unwrap(), b"k");
            fs::remove_dir_all(&base).unwrap();
        }
    }

    /// OCI-2・#2598: 0000 の不透明ディレクトリの中身を消せ、自身は残って空になる。
    #[test]
    fn oci2_remove_contents_handles_0000_opaque_dir() {
        let base = tmp("opq0");
        let root = base.join("root");
        fs::create_dir_all(root.join("d/sub")).unwrap();
        fs::write(root.join("d/a"), b"a").unwrap();
        fs::set_permissions(root.join("d"), fs::Permissions::from_mode(0o000)).unwrap();
        let a = AnchoredRoot::open(&root, AnchorHooks::host()).unwrap();
        a.remove_contents(&os(&["d"])).unwrap();
        fs::set_permissions(root.join("d"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::read_dir(root.join("d")).unwrap().count(), 0);
        fs::remove_dir_all(&base).unwrap();
    }

    /// OCI-1・#2598: `file_name` を持たない `path` は `InvalidArgument`、親が無ければ冪等に成功する。
    #[test]
    fn oci1_remove_path_tree_rejects_nameless_paths_and_is_idempotent() {
        for bad in ["/", "..", "a/..", "."] {
            let e = remove_path_tree(Path::new(bad)).unwrap_err();
            assert_eq!(e.code(), OciErrorCode::InvalidArgument, "{bad}");
        }
        let base = tmp("rpt");
        remove_path_tree(&base.join("no/such/x")).unwrap();
        remove_path_tree(&base.join("none")).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    /// OCI-1・SEC-5・#2598: `path` 自身が symlink ならリンクだけを消し、先は残る。
    #[test]
    fn sec5_remove_path_tree_unlinks_symlink_only() {
        let base = tmp("rptl");
        fs::create_dir_all(base.join("outside")).unwrap();
        fs::write(base.join("outside/keep"), b"k").unwrap();
        std::os::unix::fs::symlink(base.join("outside"), base.join("lnk")).unwrap();
        remove_path_tree(&base.join("lnk")).unwrap();
        assert!(fs::symlink_metadata(base.join("lnk")).is_err());
        assert_eq!(fs::read(base.join("outside/keep")).unwrap(), b"k");
        fs::remove_dir_all(&base).unwrap();
    }

    /// SEC-5・#2598: 下降の直前に子ディレクトリが `root` の外を指す symlink へ差し替えられたら
    /// `FailedPrecondition` で拒否し、外のファイルを消さない。
    #[test]
    fn sec5_remove_tree_rejects_swap_to_symlink_before_descend() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static SWAPPED: AtomicBool = AtomicBool::new(false);
        static BASE: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
        fn swapping(
            dir: Option<BorrowedFd<'_>>,
            path: &std::ffi::CStr,
            flags: u64,
            mode: u64,
            resolve: u64,
        ) -> io::Result<OwnedFd> {
            // 子 `d` を開く最初の呼び出しの直前に、`d` を外への symlink へ差し替える。
            if path.to_bytes() == b"d" && !SWAPPED.swap(true, Ordering::SeqCst) {
                let base = BASE.lock().unwrap().clone().unwrap();
                fs::remove_dir_all(base.join("root/t/d")).unwrap();
                std::os::unix::fs::symlink(base.join("outside"), base.join("root/t/d")).unwrap();
            }
            crate::sys::at::openat2(dir, path, flags, mode, resolve)
        }
        let base = tmp("swap");
        fs::create_dir_all(base.join("root/t/d")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        fs::write(base.join("outside/keep"), b"k").unwrap();
        *BASE.lock().unwrap() = Some(base.clone());
        let a = AnchoredRoot::open(&base.join("root"), AnchorHooks { openat2: swapping }).unwrap();
        let e = a.remove_tree(&[], OsStr::new("t")).unwrap_err();
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(fs::read(base.join("outside/keep")).unwrap(), b"k");
        fs::remove_dir_all(&base).unwrap();
    }

    /// OCI-1・#2437: `root` が symlink・非ディレクトリなら `InvalidArgument`、無ければ `NotFound`。
    #[test]
    fn oci1_open_rejects_symlink_and_non_directory_roots() {
        let base = tmp("open");
        fs::create_dir_all(base.join("real")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("lnk")).unwrap();
        fs::write(base.join("file"), b"f").unwrap();
        for bad in ["lnk", "file"] {
            let e = AnchoredRoot::open(&base.join(bad), AnchorHooks::host())
                .err()
                .unwrap();
            assert_eq!(e.code(), OciErrorCode::InvalidArgument, "{bad}");
        }
        let e = AnchoredRoot::open(&base.join("none"), AnchorHooks::host())
            .err()
            .unwrap();
        assert_eq!(e.code(), OciErrorCode::NotFound);
        fs::remove_dir_all(&base).unwrap();
    }

    /// OCI-1・#2565 P1: umask（0400・0777）で所有者の読み取り権限が落ちた新規ディレクトリ（mkdirat の結果は
    /// `0777 & !umask` で、0377 と 0000 になる）でも、fd 起点のまま mode を復元できる。
    #[test]
    fn oci1_set_dir_mode_restores_dirs_made_unreadable_by_umask() {
        use std::os::fd::AsFd as _;
        let base = tmp("umask");
        let root = base.join("root");
        fs::create_dir_all(&root).unwrap();
        let a = AnchoredRoot::open(&root, AnchorHooks::host()).unwrap();
        let rf = File::open(&root).unwrap();
        for (name, made) in [("u0400", 0o377), ("u0777", 0o000)] {
            crate::sys::at::mkdirat_name(rf.as_fd(), OsStr::new(name), made).unwrap();
            let comps = os(&[name]);
            a.set_dir_mode(&comps, 0o700).unwrap();
            assert_eq!(
                fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o7777,
                0o700,
                "{name}"
            );
        }
        fs::remove_dir_all(&base).unwrap();
    }
}
