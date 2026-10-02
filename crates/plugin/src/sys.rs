//! syscall・FFI の薄いラッパー（`crates/plugin` の `sys` モジュール。`unsafe` 事前承認の範囲。
//! coding-rust.md「unsafe・FFI・syscall」節・オーナー決定 2026-09-27
//! 〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::transport` の UDS listener が、bind 時に自プロセスの実効 uid を取得して配置ディレクトリ
//! 所有者と照合し、accept ごとに接続元の接続時点の実効 uid を取得して照合する（PLUG-12・
//! security.md「別 UID からの接続は peer credential 検証で切断する」）。`libc` / `nix` は依存追加が
//! 禁止（dependency-policy）で `UnixStream::peer_cred` は unstable のため、`crates/io/src/sys.rs` と
//! 同じ流儀で必要最小限の `extern "C"` 宣言を自前で持つ。
//!
//! - Linux（x86_64 / aarch64）: `getsockopt(SOL_SOCKET, SO_PEERCRED)` の `struct ucred`
//! - macOS: `getpeereid(2)`
//! - いずれの unix: `fchmodat(2)`（`AT_SYMLINK_NOFOLLOW`。Linux の `fchmodat2` 非対応環境は `O_PATH` fd 経由へ縮退）・`unlinkat(2)` を検証済みディレクトリ fd
//!   基準で呼ぶ（パス再解決による TOCTOU を避ける。PLUG-12）
//! - いずれの unix（対応 OS・アーキテクチャ）: `openat(O_NOFOLLOW | O_DIRECTORY)` で配置ディレクトリを
//!   ルートから 1 要素ずつ辿る（祖先要素の symlink を拒否。PLUG-12）
//! - それ以外の OS・アーキテクチャ: peer credential を取得できないため `Unimplemented`（fail-closed）
//!
//! # 契約
//! - `unsafe fn` は公開しない。公開するのは安全な [`peer_uid`]・[`effective_uid`]・[`fchmodat_nofollow`]・
//!   [`unlinkat`]・[`lstat_at`]・[`open_dir_nofollow`]（いずれも `pub(crate)`）のみ
//! - fd は `&UnixStream` の借用中のみ渡す（呼び出し中にクローズされない）
//! - SOL_SOCKET / SO_PEERCRED の定数は `cfg(target_arch)` ごとに個別定義し、流用しない

#![cfg(unix)]

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;

use crate::error::{PluginError, PluginErrorCode};

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `uid_t geteuid(void)` と同じ戻り値の型・幅
    // （`uid_t` は `u32`）。引数を取らず、エラー条件を持たない。
    fn geteuid() -> u32;
}

/// 自プロセスの実効 uid を返す（`geteuid(2)`。エラーを返さない）。
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: 引数を取らず、POSIX の規定上エラー条件を持たない。
    unsafe { geteuid() }
}

#[cfg(target_os = "linux")]
type ModeT = u32;
#[cfg(target_os = "macos")]
type ModeT = u16;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
type ModeT = u32;

#[cfg(target_os = "linux")]
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
#[cfg(target_os = "macos")]
const AT_SYMLINK_NOFOLLOW: i32 = 0x20;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int fchmodat(int, const char *, mode_t, int)` と
    // 同じ型・幅（`mode_t` は Linux で `u32`、macOS で `u16`。上の `ModeT`）。
    #[link_name = "fchmodat"]
    fn c_fchmodat(dirfd: i32, path: *const core::ffi::c_char, mode: ModeT, flags: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: POSIX の `int unlinkat(int, const char *, int)` と同じ型・幅。
    #[link_name = "unlinkat"]
    fn c_unlinkat(dirfd: i32, path: *const core::ffi::c_char, flags: i32) -> i32;
}

/// `dir`（開いたディレクトリ fd）基準で `name` の mode を設定する。最終要素が symlink なら
/// 辿らない（PLUG-12）。
///
/// まず `fchmodat(AT_SYMLINK_NOFOLLOW)` を試す。この flags は Linux 6.6 の `fchmodat2` に依存し、
/// 古いカーネル・libc（musl 等）では `ENOSYS` / `EOPNOTSUPP` / `EINVAL` で失敗するため、Linux では
/// その場合に限り [`fchmodat_via_opath`] へ縮退する（symlink 防御は保ったまま古い環境でも bind 可能にする）。
/// 縮退できない環境・OS はそのままエラー（fail-closed）。
pub(crate) fn fchmodat_nofollow(dir: &File, name: &CStr, mode: u32) -> io::Result<()> {
    let mode = ModeT::try_from(mode).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: fd は `&File` の借用中のため有効。`name` は NUL 終端の有効な C 文字列。
    let rc = unsafe { c_fchmodat(dir.as_raw_fd(), name.as_ptr(), mode, AT_SYMLINK_NOFOLLOW) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        // ENOSYS=38・EINVAL=22・EOPNOTSUPP=95（Linux の errno は x86_64 / aarch64 で共通）。
        if matches!(err.raw_os_error(), Some(38 | 22 | 95)) {
            return fchmodat_via_opath(dir, name, mode);
        }
    }
    Err(err)
}

/// `fchmodat2` 非対応環境向けの縮退実装（Linux のみ）。`name` を `O_PATH | O_NOFOLLOW` で開き、
/// fd 自体が socket であること（symlink・通常ファイルでない）を `statx(AT_EMPTY_PATH)` で確認してから、
/// `/proc/self/fd/<fd>` 経由で chmod する（fd が指す inode に対して作用し、パスは再解決しない）。
/// `/proc` が使えない場合は失敗する（fail-closed）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn fchmodat_via_opath(dir: &File, name: &CStr, mode: ModeT) -> io::Result<()> {
    // O_PATH は x86_64 / aarch64 とも 0o10000000。
    const O_PATH: i32 = 0o10000000;
    const AT_EMPTY_PATH: i32 = 0x1000;
    // SAFETY: `name` は NUL 終端の有効な C 文字列。`dir` は `&File` の借用中のため有効。
    let fd = unsafe {
        c_openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            O_PATH | O_NOFOLLOW | O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` は直前の openat が返した、他に所有者のいない有効な fd（非負を確認済み）。
    let opened = unsafe { File::from_raw_fd(fd) };
    let ident = statx_ident(opened.as_raw_fd(), c"", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW)?;
    if !ident.is_socket {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let proc_path = std::ffi::CString::new(format!("/proc/self/fd/{}", opened.as_raw_fd()))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `proc_path` は NUL 終端の有効な C 文字列。AT_FDCWD + 絶対パスで、flags=0 は
    // /proc の magic link を辿って検証済み socket inode に作用する（`opened` が生存中は有効）。
    let rc = unsafe { c_fchmodat(AT_FDCWD, proc_path.as_ptr(), mode, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `lstat` 相当の識別情報（同一性照合・所有者・種別の確認用。PLUG-12）。
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct FileIdent {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub is_socket: bool,
}

#[cfg(target_os = "linux")]
mod statx_abi {
    /// `struct statx` と同じレイアウト（アーキテクチャ非依存の安定 ABI。256 バイト）。
    #[repr(C)]
    pub(super) struct Statx {
        pub mask: u32,
        pub blksize: u32,
        pub attributes: u64,
        pub nlink: u32,
        pub uid: u32,
        pub gid: u32,
        pub mode: u16,
        pub pad0: u16,
        pub ino: u64,
        pub size: u64,
        pub blocks: u64,
        pub attributes_mask: u64,
        pub timestamps: [u64; 8],
        pub rdev_major: u32,
        pub rdev_minor: u32,
        pub dev_major: u32,
        pub dev_minor: u32,
        pub tail: [u64; 14],
    }
    const _: () = assert!(core::mem::size_of::<Statx>() == 256);

    /// `STATX_TYPE | STATX_MODE | STATX_UID | STATX_INO`。
    pub(super) const REQUIRED_MASK: u32 = 0x1 | 0x2 | 0x8 | 0x100;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: glibc（2.28 以降）/ musl の
        // `int statx(int, const char *, int, unsigned int, struct statx *)` と同じ型・幅。
        pub(super) fn statx(
            dirfd: i32,
            path: *const core::ffi::c_char,
            flags: i32,
            mask: u32,
            buf: *mut Statx,
        ) -> i32;
    }
}

/// `statx(dirfd, name, flags)` を呼び、識別情報へ変換する（Linux のみ。symlink を辿るか否かは
/// `flags` で決まる）。`lstat_at` と、O_PATH fd の同一性確認（`AT_EMPTY_PATH`）から使う。
#[cfg(target_os = "linux")]
fn statx_ident(dirfd: i32, name: &CStr, flags: i32) -> io::Result<FileIdent> {
    let mut st = statx_abi::Statx {
        mask: 0,
        blksize: 0,
        attributes: 0,
        nlink: 0,
        uid: 0,
        gid: 0,
        mode: 0,
        pad0: 0,
        ino: 0,
        size: 0,
        blocks: 0,
        attributes_mask: 0,
        timestamps: [0; 8],
        rdev_major: 0,
        rdev_minor: 0,
        dev_major: 0,
        dev_minor: 0,
        tail: [0; 14],
    };
    // SAFETY: `dirfd` は呼び出し側が保持する開いた fd。`name` は NUL 終端の有効な C 文字列。
    // `st` はスタック上の 256 バイトの `#[repr(C)]` 領域で、カーネルが書き込む最大サイズと一致。
    let rc = unsafe {
        statx_abi::statx(
            dirfd,
            name.as_ptr(),
            flags,
            statx_abi::REQUIRED_MASK,
            &raw mut st,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if st.mask & statx_abi::REQUIRED_MASK != statx_abi::REQUIRED_MASK {
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }
    Ok(FileIdent {
        dev: (u64::from(st.dev_major) << 32) | u64::from(st.dev_minor),
        ino: st.ino,
        uid: st.uid,
        is_socket: u32::from(st.mode) & 0o170000 == 0o140000,
    })
}

/// `dir` 基準で `name`（symlink を辿らない）の識別情報を返す。
///
/// Linux は `statx(dirfd, name, AT_SYMLINK_NOFOLLOW)` でパスを再解決しない。Linux 以外の unix は
/// アーキテクチャ別の `struct stat` を自前で持たないため `fallback_path` の `symlink_metadata` に
/// 縮退する（残余: macOS ではパス再解決の競合窓が残る。ディレクトリ自体は 0700 の自 UID 所有で
/// 同一 UID のみが差し替えられる。TASK-123・TASK-124 で fstatat 化を検討）。
pub(crate) fn lstat_at(
    dir: &File,
    name: &CStr,
    fallback_path: &std::path::Path,
) -> io::Result<FileIdent> {
    #[cfg(target_os = "linux")]
    {
        let _ = fallback_path;
        statx_ident(dir.as_raw_fd(), name, AT_SYMLINK_NOFOLLOW)
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let _ = (dir, name);
        let m = std::fs::symlink_metadata(fallback_path)?;
        Ok(FileIdent {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            is_socket: m.file_type().is_socket(),
        })
    }
}

// openat 用の open(2) フラグ・AT_FDCWD。値は OS・アーキテクチャごとに異なるため個別定義し流用しない。
//
// Linux の `O_DIRECTORY` / `O_NOFOLLOW` は x86_64 が asm-generic の既定値（0o200000 / 0o400000）、
// aarch64 は `arch/arm64/include/uapi/asm/fcntl.h` が既定値を上書きした 0o40000 / 0o100000 を使う
// （aarch64 では 0o200000 は `O_DIRECT`、0o400000 は `O_LARGEFILE`。x86_64 の値を aarch64 へ
// 流用すると symlink を辿るうえに `O_DIRECT` 付きで開いてしまうため、揃えてはならない）。
// `O_CLOEXEC`・`O_PATH`・`AT_FDCWD` は両アーキテクチャで共通。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_DIRECTORY: i32 = 0o200000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_DIRECTORY: i32 = 0o40000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_NOFOLLOW: i32 = 0o100000;
#[cfg(target_os = "linux")]
const O_CLOEXEC: i32 = 0o2000000;
#[cfg(target_os = "linux")]
const AT_FDCWD: i32 = -100;
#[cfg(target_os = "macos")]
const O_DIRECTORY: i32 = 0x0010_0000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;
#[cfg(target_os = "macos")]
const O_CLOEXEC: i32 = 0x0100_0000;
#[cfg(target_os = "macos")]
const AT_FDCWD: i32 = -2;

#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: POSIX の `int openat(int, const char *, int, ...)` と同じ型・幅。
    // O_CREAT を使わないため可変長引数（mode）は渡さない。
    #[link_name = "openat"]
    fn c_openat(dirfd: i32, path: *const core::ffi::c_char, flags: i32, ...) -> i32;
}

/// `dirfd` 基準で `name` を `O_DIRECTORY | O_NOFOLLOW` で開く（1 要素）。
#[cfg(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn openat_dir_nofollow(dirfd: i32, name: &CStr) -> io::Result<File> {
    // SAFETY: `name` は NUL 終端の有効な C 文字列。`dirfd` は呼び出し側が保持する開いた fd
    // （または AT_FDCWD + 絶対パス）。
    let fd = unsafe { c_openat(dirfd, name.as_ptr(), O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` は直前の openat が返した、他に所有者のいない有効な fd（非負を確認済み）。
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// 絶対パス `abs`（`canonicalize` 済み）をルートから 1 要素ずつ `openat(O_NOFOLLOW | O_DIRECTORY)`
/// で辿り、ディレクトリ fd を返す（PLUG-12）。いずれかの要素が symlink（検証後の差し替えを含む）なら
/// `ELOOP` 等で失敗する（fail-closed）。以降はこの fd を基準に bind・chmod・unlink を行い、
/// パスを再解決しない。未対応の OS・アーキテクチャは `Unsupported`（fail-closed）。
pub(crate) fn open_dir_nofollow(abs: &std::path::Path) -> io::Result<File> {
    #[cfg(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::path::Component;
        let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
        let mut comps = abs.components();
        if comps.next() != Some(Component::RootDir) {
            return Err(invalid());
        }
        let mut cur = openat_dir_nofollow(AT_FDCWD, c"/")?;
        for c in comps {
            let Component::Normal(n) = c else {
                return Err(invalid());
            };
            let name = CString::new(n.as_bytes()).map_err(|_| invalid())?;
            cur = openat_dir_nofollow(cur.as_raw_fd(), &name)?;
        }
        Ok(cur)
    }
    #[cfg(not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )))]
    {
        let _ = abs;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// `dir`（開いたディレクトリ fd）基準で `name` を unlink する（ディレクトリは対象外: flags=0）。
pub(crate) fn unlinkat(dir: &File, name: &CStr) -> io::Result<()> {
    // SAFETY: fd は `&File` の借用中のため有効。`name` は NUL 終端の有効な C 文字列。
    let rc = unsafe { c_unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    /// `struct ucred` と同じレイアウト。
    #[repr(C)]
    pub(super) struct Ucred {
        pub pid: i32,
        pub uid: u32,
        pub gid: u32,
    }

    pub(super) const UCRED_SIZE: usize = core::mem::size_of::<Ucred>();
    const _: () = assert!(UCRED_SIZE <= u32::MAX as usize);
    pub(super) const UCRED_LEN: u32 = UCRED_SIZE as u32;

    #[cfg(target_arch = "x86_64")]
    pub(super) const SOL_SOCKET: i32 = 1;
    #[cfg(target_arch = "x86_64")]
    pub(super) const SO_PEERCRED: i32 = 17;

    #[cfg(target_arch = "aarch64")]
    pub(super) const SOL_SOCKET: i32 = 1;
    #[cfg(target_arch = "aarch64")]
    pub(super) const SO_PEERCRED: i32 = 17;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: glibc / musl の
        // `int getsockopt(int, int, int, void *, socklen_t *)` と同じ型・幅（`socklen_t` は `u32`）。
        pub(super) fn getsockopt(
            sockfd: i32,
            level: i32,
            optname: i32,
            optval: *mut core::ffi::c_void,
            optlen: *mut u32,
        ) -> i32;
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: libSystem の `int getpeereid(int, uid_t *, gid_t *)` と同じ型・幅。
    fn getpeereid(socket: i32, euid: *mut u32, egid: *mut u32) -> i32;
}

/// 接続元の接続時点の実効 uid を返す（Linux）。取得できなければ fail-closed でエラー。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, PluginError> {
    use std::os::unix::io::AsRawFd;
    let mut ucred = linux::Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = linux::UCRED_LEN;
    // SAFETY: fd は `&UnixStream` の借用中のため有効。`optval` はスタック上の `#[repr(C)]` な
    // `ucred` を指し、`optlen` はそのサイズを指す有効なポインタ。
    let rc = unsafe {
        linux::getsockopt(
            stream.as_raw_fd(),
            linux::SOL_SOCKET,
            linux::SO_PEERCRED,
            (&raw mut ucred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 || len as usize != linux::UCRED_SIZE {
        return Err(PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        ));
    }
    Ok(ucred.uid)
}

/// 接続元の接続時点の実効 uid を返す（macOS）。
#[cfg(target_os = "macos")]
pub(crate) fn peer_uid(stream: &UnixStream) -> Result<u32, PluginError> {
    use std::os::unix::io::AsRawFd;
    let mut euid: u32 = 0;
    let mut egid: u32 = 0;
    // SAFETY: fd は `&UnixStream` の借用中のため有効。2 つのポインタはスタック上の有効な変数を指す。
    let rc = unsafe { getpeereid(stream.as_raw_fd(), &raw mut euid, &raw mut egid) };
    if rc != 0 {
        return Err(PluginError::new(
            PluginErrorCode::Internal,
            "failed to obtain peer credential",
        ));
    }
    Ok(euid)
}

/// 未対応の OS・アーキテクチャでは peer を検証できないため常に拒否する（fail-closed）。
#[cfg(not(any(
    target_os = "macos",
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
pub(crate) fn peer_uid(_stream: &UnixStream) -> Result<u32, PluginError> {
    Err(PluginError::new(
        PluginErrorCode::Unimplemented,
        "peer credential verification is not implemented for this platform",
    ))
}
#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::os::unix::net::UnixListener;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fc-sys-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// PLUG-12: `fchmodat2` 非対応環境向けの縮退経路が socket の mode を設定できる。
    #[test]
    fn opath_fallback_sets_socket_mode_0600() {
        let d = tmpdir("sock");
        let _l = UnixListener::bind(d.join("s.sock")).unwrap();
        let dir = File::open(&d).unwrap();
        fchmodat_via_opath(&dir, c"s.sock", 0o600).unwrap();
        let mode = std::fs::symlink_metadata(d.join("s.sock")).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PLUG-12: 縮退経路でも最終要素が symlink なら辿らず拒否し、リンク先の mode は変えない。
    #[test]
    fn opath_fallback_rejects_symlink_and_leaves_target() {
        let d = tmpdir("link");
        std::fs::write(d.join("target"), b"x").unwrap();
        std::fs::set_permissions(
            d.join("target"),
            std::os::unix::fs::PermissionsExt::from_mode(0o644),
        )
        .unwrap();
        symlink(d.join("target"), d.join("lnk")).unwrap();
        let dir = File::open(&d).unwrap();
        assert!(fchmodat_via_opath(&dir, c"lnk", 0o600).is_err());
        let mode = std::fs::metadata(d.join("target")).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o644);
        let _ = std::fs::remove_dir_all(&d);
    }
}
