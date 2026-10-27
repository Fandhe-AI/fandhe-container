//! CDI `deviceNodes` の作成（`crate::cdi_apply`。TASK-127.1・GPU-2）に使う syscall の薄いラッパー
//! （`crates/gpu` の `sys` モジュール。`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::cdi_apply` の `create_device_nodes` が、コンテナの `/dev` のルート fd を起点に 1 要素ずつ
//! `openat(2)`（`O_NOFOLLOW`）で辿り、`mkdirat(2)` / `mknodat(2)` / `unlinkat(2)` で作成・後始末する。
//! 属性の読み取り（`fstat` 相当）と chmod / chown は std（`File::metadata`・`/proc/self/fd/<n>` 経由）で
//! 行うため、`struct stat` の FFI は持たない。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない。公開するのは安全な関数のみ
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と維持すべき不変条件を明記する
//! - 定数は `cfg(target_arch = ...)` ごとに個別に定義し、値が同じでも流用しない。対応外では各ラッパーが
//!   [`SysError::Unsupported`] を返す（fail-closed）。対応 arch は LP64 の x86_64・aarch64 だけ
//! - 戻り値が `-1` のときは直後に `std::io::Error::last_os_error()` で errno を確保する
//! - 名前は 1 要素（`/` を含まない・空 / `.` / `..` でない）だけを受け、途中要素の symlink を辿らせない
//!
//! # `libc` との機械照合について
//! 本 crate は #1837 系列に入っておらず、`libc` 照合は未導入（dev-dependency の追加は承認制のため
//! 本変更では足さない。追跡は後続）。

#![cfg(target_os = "linux")]

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

/// syscall 失敗の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysError {
    /// 対応外のアーキテクチャ（定数が未定義）。
    Unsupported,
    /// カーネルが返した errno。
    Os(i32),
}

/// 定数（x86_64）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) mod consts {
    pub const SUPPORTED: bool = true;
    pub const O_DIRECTORY: i32 = 0o200_000;
    pub const O_NOFOLLOW: i32 = 0o400_000;
    pub const O_CLOEXEC: i32 = 0o2_000_000;
    pub const O_PATH: i32 = 0o10_000_000;
    pub const AT_REMOVEDIR: i32 = 0x200;
    pub const S_IFCHR: u32 = 0o020_000;
    pub const S_IFBLK: u32 = 0o060_000;
    pub const S_IFIFO: u32 = 0o010_000;
    pub const F_GETFL: i32 = 3;
    pub const F_SETFL: i32 = 4;
    pub const O_NONBLOCK: i32 = 0o4_000;
    pub const O_NOCTTY: i32 = 0o400;
}

/// 定数（aarch64。`O_DIRECTORY` / `O_NOFOLLOW` が x86_64 と異なる）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) mod consts {
    pub const SUPPORTED: bool = true;
    pub const O_DIRECTORY: i32 = 0o40_000;
    pub const O_NOFOLLOW: i32 = 0o100_000;
    pub const O_CLOEXEC: i32 = 0o2_000_000;
    pub const O_PATH: i32 = 0o10_000_000;
    pub const AT_REMOVEDIR: i32 = 0x200;
    pub const S_IFCHR: u32 = 0o020_000;
    pub const S_IFBLK: u32 = 0o060_000;
    pub const S_IFIFO: u32 = 0o010_000;
    pub const F_GETFL: i32 = 3;
    pub const F_SETFL: i32 = 4;
    pub const O_NONBLOCK: i32 = 0o4_000;
    pub const O_NOCTTY: i32 = 0o400;
}

/// 対応外アーキテクチャ。値は使われない（各ラッパーが `Unsupported` を返す）。
#[cfg(not(any(
    all(target_arch = "x86_64", target_pointer_width = "64"),
    all(target_arch = "aarch64", target_pointer_width = "64")
)))]
pub(crate) mod consts {
    pub const SUPPORTED: bool = false;
    pub const O_DIRECTORY: i32 = 0;
    pub const O_NOFOLLOW: i32 = 0;
    pub const O_CLOEXEC: i32 = 0;
    pub const O_PATH: i32 = 0;
    pub const AT_REMOVEDIR: i32 = 0;
    pub const S_IFCHR: u32 = 0;
    pub const S_IFBLK: u32 = 0;
    pub const S_IFIFO: u32 = 0;
    pub const F_GETFL: i32 = 0;
    pub const F_SETFL: i32 = 0;
    pub const O_NONBLOCK: i32 = 0;
    pub const O_NOCTTY: i32 = 0;
}

// SAFETY: 以下は libc（glibc / musl）が提供する POSIX 関数の宣言で、LP64 の x86_64 / aarch64 では
// `mode_t` = u32・`dev_t` = u64・`int` = i32。各呼び出しは下のラッパーだけが行い、ポインタ引数は
// 呼び出しの間有効な NUL 終端の `CStr` を指す。
unsafe extern "C" {
    // 原型: `int openat(int dirfd, const char *pathname, int flags, ...)`。mode は `O_CREAT` のときだけ
    // 読まれ、本モジュールは渡さない。
    fn openat(dirfd: i32, path: *const core::ffi::c_char, flags: i32, ...) -> i32;
    // 原型: `int mkdirat(int dirfd, const char *pathname, mode_t mode)`。
    fn mkdirat(dirfd: i32, path: *const core::ffi::c_char, mode: u32) -> i32;
    // 原型: `int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev)`。
    fn mknodat(dirfd: i32, path: *const core::ffi::c_char, mode: u32, dev: u64) -> i32;
    // 原型: `int unlinkat(int dirfd, const char *pathname, int flags)`。
    fn unlinkat(dirfd: i32, path: *const core::ffi::c_char, flags: i32) -> i32;
    // 原型: `int fcntl(int fd, int cmd, ...)`。本モジュールは `F_GETFL`（引数なし）と `F_SETFL`（int 1 個）だけ使う。
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

fn last_error() -> SysError {
    SysError::Os(io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// 名前が 1 要素であることを確認する（複数要素は途中の symlink を辿るため入口で拒否）。
fn check_single_component(name: &CStr) -> Result<(), SysError> {
    let b = name.to_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(SysError::Os(22)); // EINVAL
    }
    Ok(())
}

fn check_supported() -> Result<(), SysError> {
    if consts::SUPPORTED {
        Ok(())
    } else {
        Err(SysError::Unsupported)
    }
}

fn open_at_raw(dir: BorrowedFd<'_>, name: &CStr, flags: i32) -> Result<OwnedFd, SysError> {
    check_supported()?;
    check_single_component(name)?;
    // SAFETY: `name` は NUL 終端済みの `CStr` で呼び出しの間有効。`dir` は借用中の生存 fd。`flags` に
    // `O_CREAT` を含まないため可変長引数 mode は読まれない。
    let fd = unsafe { openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` は直前の openat が返した非負の新規 fd で、他に所有者がおらず `OwnedFd` が唯一の所有者になる。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `dir` 直下の 1 要素のディレクトリを `O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` で開く。
pub(crate) fn open_dir_nofollow_at(dir: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd, SysError> {
    open_at_raw(
        dir,
        name,
        consts::O_PATH | consts::O_DIRECTORY | consts::O_NOFOLLOW | consts::O_CLOEXEC,
    )
}

/// `dir` 直下の 1 要素を `O_PATH | O_NOFOLLOW | O_CLOEXEC` で開く（中身は開かない。デバイスの `open()` を呼ばない）。
pub(crate) fn open_path_nofollow_at(dir: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd, SysError> {
    open_at_raw(
        dir,
        name,
        consts::O_PATH | consts::O_NOFOLLOW | consts::O_CLOEXEC,
    )
}

/// `dir` 直下にディレクトリを作る。
pub(crate) fn mkdir_at(dir: BorrowedFd<'_>, name: &CStr, mode: u32) -> Result<(), SysError> {
    check_supported()?;
    check_single_component(name)?;
    // SAFETY: `name` は NUL 終端済みで呼び出しの間有効、`dir` は借用中の生存 fd。カーネルはパスを読むだけ。
    let r = unsafe { mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `dir` 直下にデバイスノード / FIFO を作る。`mode` は種別ビット（`S_IF*`）と権限の OR、`dev` は `makedev` 済み。
pub(crate) fn mknod_at(
    dir: BorrowedFd<'_>,
    name: &CStr,
    mode: u32,
    dev: u64,
) -> Result<(), SysError> {
    check_supported()?;
    check_single_component(name)?;
    // SAFETY: `name` は NUL 終端済みで呼び出しの間有効、`dir` は借用中の生存 fd。mode・dev は値渡しで
    // ポインタを含まない。
    let r = unsafe { mknodat(dir.as_raw_fd(), name.as_ptr(), mode, dev) };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `dir` 直下の 1 要素を消す。`remove_dir` が真なら空ディレクトリを `rmdir` 相当で消す。
pub(crate) fn unlink_at(
    dir: BorrowedFd<'_>,
    name: &CStr,
    remove_dir: bool,
) -> Result<(), SysError> {
    check_supported()?;
    check_single_component(name)?;
    let flags = if remove_dir { consts::AT_REMOVEDIR } else { 0 };
    // SAFETY: `name` は NUL 終端済みで呼び出しの間有効、`dir` は借用中の生存 fd。
    let r = unsafe { unlinkat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `fd` を `O_NONBLOCK` にする（既存のステータスフラグは保つ）。createContainer フックの stdin / stderr の pipe を
/// スレッド無しで有界に回すために使う（TASK-127.3・GPU-2・REPAIR-5）。フラグは open file description に付くため、
/// 子が持つ反対側の端には影響しない。
pub(crate) fn set_nonblocking(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    check_supported()?;
    // SAFETY: `fd` は借用中の生存 fd。`F_GETFL` は第 3 引数を読まず、ポインタも渡さない。
    let flags = unsafe { fcntl(fd.as_raw_fd(), consts::F_GETFL) };
    if flags < 0 {
        return Err(last_error());
    }
    // SAFETY: 同上。`F_SETFL` の第 3 引数は int 値渡しで、直前に得たフラグに `O_NONBLOCK` を足しただけ。
    let r = unsafe { fcntl(fd.as_raw_fd(), consts::F_SETFL, flags | consts::O_NONBLOCK) };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::fd::AsFd as _;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fc-gpu-sys-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// GPU-2: 定数の具体値（arch 別）。
    #[test]
    fn constants_have_expected_values() {
        assert_eq!(consts::O_PATH, 0o10_000_000);
        assert_eq!(consts::O_CLOEXEC, 0o2_000_000);
        assert_eq!(consts::S_IFCHR, 0o020_000);
        assert_eq!(consts::S_IFBLK, 0o060_000);
        assert_eq!(consts::S_IFIFO, 0o010_000);
        assert_eq!(consts::O_NOCTTY, 0o400);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            (consts::O_DIRECTORY, consts::O_NOFOLLOW),
            (0o200_000, 0o400_000)
        );
        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            (consts::O_DIRECTORY, consts::O_NOFOLLOW),
            (0o40_000, 0o100_000)
        );
    }

    /// GPU-2・REPAIR-5: `set_nonblocking` 後の空 pipe の read は WouldBlock、端を閉じると EOF になる。
    #[test]
    fn nonblocking_pipe_read() {
        use std::io::Read as _;
        use std::process::{Command, Stdio};
        let mut c = Command::new("sleep")
            .arg("1")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = c.stdout.take().unwrap();
        set_nonblocking(out.as_fd()).unwrap();
        let mut b = [0u8; 8];
        assert_eq!(
            out.read(&mut b).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        c.kill().unwrap();
        c.wait().unwrap();
        assert_eq!(out.read(&mut b).unwrap(), 0);
    }

    /// GPU-2: mkdirat / openat が動き、symlink は O_NOFOLLOW で拒否される。
    #[test]
    fn mkdir_open_and_nofollow() {
        let d = tmp("mk");
        let root = std::fs::File::open(&d).unwrap();
        let a = CString::new("a").unwrap();
        mkdir_at(root.as_fd(), &a, 0o755).unwrap();
        assert!(open_dir_nofollow_at(root.as_fd(), &a).is_ok());
        assert_eq!(
            mkdir_at(root.as_fd(), &a, 0o755).unwrap_err(),
            SysError::Os(17)
        );
        std::os::unix::fs::symlink("/tmp", d.join("l")).unwrap();
        let l = CString::new("l").unwrap();
        let e = open_dir_nofollow_at(root.as_fd(), &l).unwrap_err();
        assert!(matches!(e, SysError::Os(40) | SysError::Os(20)), "{e:?}");
        assert_eq!(
            open_path_nofollow_at(root.as_fd(), &CString::new("a/b").unwrap()).unwrap_err(),
            SysError::Os(22)
        );
        unlink_at(root.as_fd(), &a, true).unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }
}
