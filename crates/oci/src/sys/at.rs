//! ディレクトリ fd 起点の操作（`openat2(2)`・`*at(2)`・`getdents64(2)`）の薄いラッパー。Linux の x86_64 / aarch64 限定。
//!
//! # 呼び出し文脈
//! `layer::anchored` の `AnchoredRoot` と `image_management::root_handle` が使う。前者はレイヤー展開
//! （OCI-1・OCI-2）の変更操作を `root` の fd 起点に閉じ込め、確認（`lstat`）から使用までの間に祖先が
//! symlink へ差し替えられても `root` の外へ書き込めないようにする（SEC-5・#2437）。後者はイメージストア root
//! 直下の永続化操作を検査済み root の fd 起点に閉じ込める（OCI-7・SEC-1・#2638）。製品の依存に `libc` は入れない（dependency-policy・#1318。`libc` は dev-dependencies で照合にだけ使う）ため `extern "C"` 宣言を自前で持つ。`libc` との機械照合は
//! 子 `libc_abi` で行う（#2590。`docs/design/ffi-libc-check.md`）。定数と構造体は次の一次情報で確認した値である:
//! `include/uapi/linux/openat2.h`（`struct open_how` は `flags` / `mode` / `resolve` の `u64` 3 つで 24 バイト。
//! Linux 5.6 で追加）、`include/uapi/asm-generic/unistd.h`（`__NR_openat2` = 437 は全アーキテクチャ共通。
//! aarch64 の `getdents64` = 61）、`arch/x86/include/uapi/asm/unistd_64.h`（`getdents64` = 217）、
//! `include/uapi/linux/dirent.h`（`struct linux_dirent64`）、`arch/arm64/include/uapi/asm/fcntl.h`
//! （`O_DIRECTORY` / `O_NOFOLLOW` が x86_64 と異なる）。同じ値を `libc` 0.2.189 のソース
//! （`SYS_openat2`・`SYS_getdents64`・`O_PATH`）とも突き合わせた。
//!
//! # 契約
//! - 名前は 1 コンポーネント（空・`/`・NUL を含まず、`.` / `..` でもない）に限り、この入口で検証する
//! - 公開するのは安全な関数だけ。fd の所有権は `OwnedFd` で受け渡し、`unsafe fn` は外へ出さない

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::raw::{c_char, c_int, c_long, c_uint};
use std::os::unix::ffi::OsStrExt as _;

/// `AT_FDCWD`（`include/uapi/linux/fcntl.h`）。
const AT_FDCWD: c_int = -100;
/// `AT_SYMLINK_NOFOLLOW`（`include/uapi/linux/fcntl.h`）。
const AT_SYMLINK_NOFOLLOW: c_int = 0x100;
/// `AT_REMOVEDIR`（`include/uapi/linux/fcntl.h`）。
const AT_REMOVEDIR: c_int = 0x200;

pub(crate) const O_RDONLY: u64 = 0;
pub(crate) const O_WRONLY: u64 = 1;
pub(crate) const O_CREAT: u64 = 0o100;
pub(crate) const O_EXCL: u64 = 0o200;
/// `O_CLOEXEC` と `O_PATH` は asm-generic の値で、arm64 も上書きしない。
pub(crate) const O_CLOEXEC: u64 = 0o2_000_000;
pub(crate) const O_PATH: u64 = 0o10_000_000;
/// `O_NONBLOCK` も asm-generic の値（FIFO の読み取り open をブロックさせない。#2606）。
pub(crate) const O_NONBLOCK: u64 = 0o4000;
/// `O_DIRECTORY` / `O_NOFOLLOW` は x86_64 と arm64 で値が違う（`arch/arm64/include/uapi/asm/fcntl.h`）。
#[cfg(target_arch = "x86_64")]
pub(crate) const O_DIRECTORY: u64 = 0o200_000;
#[cfg(target_arch = "x86_64")]
pub(crate) const O_NOFOLLOW: u64 = 0o400_000;
#[cfg(target_arch = "aarch64")]
pub(crate) const O_DIRECTORY: u64 = 0o40_000;
#[cfg(target_arch = "aarch64")]
pub(crate) const O_NOFOLLOW: u64 = 0o100_000;

/// `include/uapi/linux/openat2.h` の `RESOLVE_*`。
pub(crate) const RESOLVE_NO_XDEV: u64 = 0x01;
pub(crate) const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub(crate) const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub(crate) const RESOLVE_IN_ROOT: u64 = 0x10;

/// errno（`include/uapi/asm-generic/errno-base.h` と `errno.h`。x86_64 / aarch64 で共通）。
pub(crate) const EPERM: i32 = 1;
pub(crate) const EACCES: i32 = 13;
pub(crate) const E2BIG: i32 = 7;
pub(crate) const EAGAIN: i32 = 11;
pub(crate) const EXDEV: i32 = 18;
pub(crate) const ENOTDIR: i32 = 20;
pub(crate) const EISDIR: i32 = 21;
pub(crate) const EINVAL: i32 = 22;
pub(crate) const ENOSYS: i32 = 38;
pub(crate) const ELOOP: i32 = 40;
const EINTR: i32 = 4;

/// `__NR_openat2`（全アーキテクチャ共通。Linux 5.6 以降）。
const SYS_OPENAT2: c_long = 437;
/// `__NR_getdents64`。x86_64 は 217、aarch64 は 61。
#[cfg(target_arch = "x86_64")]
const SYS_GETDENTS64: c_long = 217;
#[cfg(target_arch = "aarch64")]
const SYS_GETDENTS64: c_long = 61;

/// `struct open_how`（`include/uapi/linux/openat2.h`）。
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: glibc / musl の `long syscall(long number, ...)`。LP64（x86_64・aarch64）で
    // `c_long` は 64 ビット。呼び出し側は引数をすべて 64 ビット幅（ポインタを含む）で渡す。
    fn syscall(number: c_long, ...) -> c_long;
    // SAFETY（宣言そのものの妥当性）: POSIX の `int mkdirat(int, const char *, mode_t)`（`mode_t` は `u32`）。
    fn mkdirat(dirfd: c_int, path: *const c_char, mode: c_uint) -> c_int;
    // SAFETY（宣言そのものの妥当性）: POSIX の `int unlinkat(int, const char *, int)`。
    fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int;
    // SAFETY（宣言そのものの妥当性）: POSIX の `int renameat(int, const char *, int, const char *)`。
    fn renameat(
        olddirfd: c_int,
        oldpath: *const c_char,
        newdirfd: c_int,
        newpath: *const c_char,
    ) -> c_int;
    // SAFETY（宣言そのものの妥当性）: POSIX の `int symlinkat(const char *, int, const char *)`。
    fn symlinkat(target: *const c_char, newdirfd: c_int, linkpath: *const c_char) -> c_int;
    // SAFETY（宣言そのものの妥当性）: POSIX の `int linkat(int, const char *, int, const char *, int)`。
    fn linkat(
        olddirfd: c_int,
        oldpath: *const c_char,
        newdirfd: c_int,
        newpath: *const c_char,
        flags: c_int,
    ) -> c_int;
    // SAFETY（宣言そのものの妥当性）: POSIX の `ssize_t readlinkat(int, const char *, char *, size_t)`。
    fn readlinkat(dirfd: c_int, path: *const c_char, buf: *mut c_char, bufsiz: usize) -> isize;
    // SAFETY（宣言そのものの妥当性）: POSIX の `int fchownat(int, const char *, uid_t, gid_t, int)`。
    fn fchownat(
        dirfd: c_int,
        path: *const c_char,
        owner: c_uint,
        group: c_uint,
        flags: c_int,
    ) -> c_int;
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// 1 コンポーネントの名前を NUL 終端に変換する（空・`/`・NUL・`.`・`..` は拒否。多重防御）。
pub(crate) fn component_cstring(name: &OsStr) -> io::Result<CString> {
    let b = name.as_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(invalid("invalid path component"));
    }
    CString::new(b).map_err(|_| invalid("invalid path component"))
}

/// コンポーネント列を `/` で連結した相対パスにする（空列は `.`）。各要素は 1 コンポーネントの検証を通す。
pub(crate) fn relative_cstring<S: AsRef<OsStr>>(comps: &[S]) -> io::Result<CString> {
    if comps.is_empty() {
        return CString::new(".").map_err(|_| invalid("invalid path"));
    }
    let mut v: Vec<u8> = Vec::new();
    for (i, c) in comps.iter().enumerate() {
        let c = component_cstring(c.as_ref())?;
        if i > 0 {
            v.push(b'/');
        }
        v.extend_from_slice(c.as_bytes());
    }
    CString::new(v).map_err(|_| invalid("invalid path"))
}

fn raw(fd: BorrowedFd<'_>) -> c_int {
    fd.as_raw_fd()
}

fn check(r: c_int) -> io::Result<()> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `openat2(2)`。`dir` が `None` なら `AT_FDCWD`。`EINTR` は再試行する。
pub(crate) fn openat2(
    dir: Option<BorrowedFd<'_>>,
    path: &CStr,
    flags: u64,
    mode: u64,
    resolve: u64,
) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags,
        mode,
        resolve,
    };
    let dirfd = dir.map_or(AT_FDCWD, raw);
    loop {
        // SAFETY: `path` は NUL 終端で呼び出しの間生きる。`how` は `struct open_how` と同じ `#[repr(C)]` で、
        // 渡す大きさ（24 バイト）と一致する。引数はすべて 64 ビット幅で渡す。戻り値が負でなければ新しく開いた
        // fd で、他に所有者がないため下で `OwnedFd` に所有権を渡す。
        let r = unsafe {
            syscall(
                SYS_OPENAT2,
                c_long::from(dirfd),
                path.as_ptr(),
                std::ptr::from_ref(&how),
                std::mem::size_of::<OpenHow>(),
            )
        };
        if r >= 0 {
            let Ok(fd) = RawFd::try_from(r) else {
                return Err(io::Error::from_raw_os_error(EINVAL));
            };
            // SAFETY: 上記のとおり、カーネルが今返した所有者のいない fd。
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(EINTR) {
            return Err(e);
        }
    }
}

/// `mkdirat(2)`。
pub(crate) fn mkdirat_name(dir: BorrowedFd<'_>, name: &OsStr, mode: u32) -> io::Result<()> {
    let n = component_cstring(name)?;
    // SAFETY: `n` は NUL 終端で呼び出しの間生きる。`dir` は借用の間有効。
    check(unsafe { mkdirat(raw(dir), n.as_ptr(), mode) })
}

/// `unlinkat(2)`。`remove_dir` が真なら `AT_REMOVEDIR`。
pub(crate) fn unlinkat_name(dir: BorrowedFd<'_>, name: &OsStr, remove_dir: bool) -> io::Result<()> {
    let n = component_cstring(name)?;
    let flags = if remove_dir { AT_REMOVEDIR } else { 0 };
    // SAFETY: `n` は NUL 終端で呼び出しの間生きる。`dir` は借用の間有効。
    check(unsafe { unlinkat(raw(dir), n.as_ptr(), flags) })
}

/// `renameat(2)`。両方の名前は 1 コンポーネントで、`new_name` が既にあれば原子的に置き換わる
/// （`image_management::root_handle` が一時ファイルを固定名へ公開するために使う。#2638）。
pub(crate) fn renameat_names(
    old_dir: BorrowedFd<'_>,
    old_name: &OsStr,
    new_dir: BorrowedFd<'_>,
    new_name: &OsStr,
) -> io::Result<()> {
    let o = component_cstring(old_name)?;
    let n = component_cstring(new_name)?;
    // SAFETY: `o` と `n` は `component_cstring` で「空・`.`・`..`・`/`・NUL を含まない 1 コンポーネント」と検証済みで、
    // 名前解決が dirfd の外へ出ない。どちらも NUL 終端で呼び出しの間生きる。2 つの fd は借用の間有効。
    check(unsafe { renameat(raw(old_dir), o.as_ptr(), raw(new_dir), n.as_ptr()) })
}

/// `symlinkat(2)`。`target` は NUL を含まない任意のバイト列（リンク先は解釈されない）。
pub(crate) fn symlinkat_name(target: &OsStr, dir: BorrowedFd<'_>, name: &OsStr) -> io::Result<()> {
    let n = component_cstring(name)?;
    let t = CString::new(target.as_bytes()).map_err(|_| invalid("invalid symlink target"))?;
    // SAFETY: `t` と `n` は NUL 終端で呼び出しの間生きる。`dir` は借用の間有効。
    check(unsafe { symlinkat(t.as_ptr(), raw(dir), n.as_ptr()) })
}

/// `linkat(2)`（`flags` は 0。参照元が symlink でも追従しない。`AT_EMPTY_PATH` は非特権で使えないため使わない）。
pub(crate) fn linkat_names(
    old_dir: BorrowedFd<'_>,
    old_name: &OsStr,
    new_dir: BorrowedFd<'_>,
    new_name: &OsStr,
) -> io::Result<()> {
    let o = component_cstring(old_name)?;
    let n = component_cstring(new_name)?;
    // SAFETY: `o` と `n` は `component_cstring` で「空・`.`・`..`・`/`・NUL を含まない 1 コンポーネント」と検証済みで、
    // 名前解決が dirfd の外へ出ない。どちらも NUL 終端で呼び出しの間生きる。2 つの fd は借用の間有効。
    check(unsafe { linkat(raw(old_dir), o.as_ptr(), raw(new_dir), n.as_ptr(), 0) })
}

/// `readlinkat(2)`。`buf` に収まらない（切り詰められた可能性がある）リンクは `InvalidData` で拒否する。
pub(crate) fn readlinkat_name(
    dir: BorrowedFd<'_>,
    name: &OsStr,
    buf: &mut [u8],
) -> io::Result<usize> {
    let n = component_cstring(name)?;
    // SAFETY: `n` は NUL 終端。`buf` は書き込み可能な `buf.len()` バイトの領域で、カーネルはその範囲を超えて書かない。
    let r = unsafe {
        readlinkat(
            raw(dir),
            n.as_ptr(),
            buf.as_mut_ptr().cast::<c_char>(),
            buf.len(),
        )
    };
    let len = usize::try_from(r).map_err(|_| io::Error::last_os_error())?;
    if len >= buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "symlink target is too long",
        ));
    }
    Ok(len)
}

/// `fchownat(2)` に `AT_SYMLINK_NOFOLLOW` を付けて所有者を変える（`lchown` 相当）。
pub(crate) fn lchown_name(dir: BorrowedFd<'_>, name: &OsStr, uid: u32, gid: u32) -> io::Result<()> {
    let n = component_cstring(name)?;
    // SAFETY: `n` は NUL 終端で呼び出しの間生きる。`dir` は借用の間有効。
    check(unsafe { fchownat(raw(dir), n.as_ptr(), uid, gid, AT_SYMLINK_NOFOLLOW) })
}

/// `getdents64(2)` で `buf` にディレクトリエントリを読み、読んだバイト数を返す（0 は終端）。
pub(crate) fn getdents64(dir: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `buf` は書き込み可能な `buf.len()` バイトの領域で、カーネルはその範囲を超えて書かない。
        // 引数はすべて 64 ビット幅（ポインタを含む）で渡す。
        let r = unsafe {
            syscall(
                SYS_GETDENTS64,
                c_long::from(raw(dir)),
                buf.as_mut_ptr(),
                buf.len(),
            )
        };
        if let Ok(n) = usize::try_from(r) {
            return Ok(n);
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(EINTR) {
            return Err(e);
        }
    }
}

/// `getdents64` が返したバッファを解析し、`.` と `..` を除いた各名前を `f` へ渡す。
///
/// `struct linux_dirent64` は `d_ino`(u64) `d_off`(i64) `d_reclen`(u16, offset 16) `d_type`(u8) `d_name`(offset 19、
/// NUL 終端) の順。レコード長と NUL 終端はバッファの範囲内であることを確かめ、壊れていれば `InvalidData`。
pub(crate) fn for_each_dirent(buf: &[u8], mut f: impl FnMut(&[u8])) -> io::Result<()> {
    const NAME_OFFSET: usize = 19;
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed directory entry");
    let mut pos = 0usize;
    while pos < buf.len() {
        let rest = buf.get(pos..).ok_or_else(bad)?;
        let len_bytes: [u8; 2] = rest
            .get(16..18)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(bad)?;
        let reclen = usize::from(u16::from_ne_bytes(len_bytes));
        if reclen <= NAME_OFFSET {
            return Err(bad());
        }
        let rec = rest.get(..reclen).ok_or_else(bad)?;
        let name_area = rec.get(NAME_OFFSET..).ok_or_else(bad)?;
        let nul = name_area.iter().position(|b| *b == 0).ok_or_else(bad)?;
        let name = name_area.get(..nul).ok_or_else(bad)?;
        if name != b"." && name != b".." {
            f(name);
        }
        pos = pos.checked_add(reclen).ok_or_else(bad)?;
    }
    Ok(())
}

#[cfg(test)]
mod libc_abi {
    //! 自前の宣言を `libc` 0.2.189 と `const` 評価で照合する（#2590・OCI-1・SEC-5・REPAIR-12）。関数は呼ばない。
    //! 親モジュールと同じ cfg（Linux の x86_64 / aarch64）の下にあり、ターゲットごとの `libc` の値と比べる。
    //!
    //! 対象外（理由つき）:
    //! - `component_cstring`・`relative_cstring`・`raw`・`check`・`invalid` と安全なラッパー群: FFI ではない
    //! - `openat2` に渡す大きさ: `size_of::<OpenHow>()` の照合（24 バイト）に含まれる
    //! - `struct linux_dirent64`: カーネルの構造体で `libc` に無い。ヘッダ部のオフセットが一致する
    //!   `libc::dirent64`（glibc の構造体）で `for_each_dirent` の `NAME_OFFSET`・`16..18` を代わりに照合する
    //!   （試験 `oci1_dirent_parser_concrete_values` が具体値を見る）
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    /// `libc` の `c_int` の `O_*` を `u64` へ広げる。負値は拒否する（切り詰めを隠さない）。
    const fn widen(v: libc::c_int) -> u64 {
        assert!(v >= 0);
        v as u64
    }

    const _: () = {
        assert!(AT_FDCWD == libc::AT_FDCWD);
        assert!(AT_SYMLINK_NOFOLLOW == libc::AT_SYMLINK_NOFOLLOW);
        assert!(AT_REMOVEDIR == libc::AT_REMOVEDIR);

        // 自前の `O_*` は `open_how.flags`（`u64`）に入れるため `u64`。`O_DIRECTORY` / `O_NOFOLLOW` は
        // アーキテクチャで値が違い、`libc` 側もターゲットの値になる。
        assert!(O_RDONLY == widen(libc::O_RDONLY));
        assert!(O_WRONLY == widen(libc::O_WRONLY));
        assert!(O_CREAT == widen(libc::O_CREAT));
        assert!(O_EXCL == widen(libc::O_EXCL));
        assert!(O_CLOEXEC == widen(libc::O_CLOEXEC));
        assert!(O_PATH == widen(libc::O_PATH));
        assert!(O_NONBLOCK == widen(libc::O_NONBLOCK));
        assert!(O_DIRECTORY == widen(libc::O_DIRECTORY));
        assert!(O_NOFOLLOW == widen(libc::O_NOFOLLOW));

        assert!(RESOLVE_NO_XDEV == libc::RESOLVE_NO_XDEV);
        assert!(RESOLVE_NO_MAGICLINKS == libc::RESOLVE_NO_MAGICLINKS);
        assert!(RESOLVE_NO_SYMLINKS == libc::RESOLVE_NO_SYMLINKS);
        assert!(RESOLVE_IN_ROOT == libc::RESOLVE_IN_ROOT);

        assert!(EPERM == libc::EPERM);
        assert!(EACCES == libc::EACCES);
        assert!(E2BIG == libc::E2BIG);
        assert!(EAGAIN == libc::EAGAIN);
        assert!(EXDEV == libc::EXDEV);
        assert!(ENOTDIR == libc::ENOTDIR);
        assert!(EISDIR == libc::EISDIR);
        assert!(EINVAL == libc::EINVAL);
        assert!(ENOSYS == libc::ENOSYS);
        assert!(ELOOP == libc::ELOOP);
        assert!(EINTR == libc::EINTR);

        assert!(SYS_OPENAT2 == libc::SYS_openat2);
        assert!(SYS_GETDENTS64 == libc::SYS_getdents64);

        // `struct open_how`: サイズ・アラインメント・各フィールドのオフセット。
        assert!(size_of::<u64>() == size_of::<libc::__u64>());
        assert!(size_of::<OpenHow>() == size_of::<libc::open_how>());
        assert!(align_of::<OpenHow>() == align_of::<libc::open_how>());
        assert!(offset_of!(OpenHow, flags) == offset_of!(libc::open_how, flags));
        assert!(offset_of!(OpenHow, mode) == offset_of!(libc::open_how, mode));
        assert!(offset_of!(OpenHow, resolve) == offset_of!(libc::open_how, resolve));

        // `linux_dirent64` のヘッダ部（`for_each_dirent` の 16..18 と NAME_OFFSET = 19）。
        assert!(offset_of!(libc::dirent64, d_reclen) == 16);
        assert!(offset_of!(libc::dirent64, d_name) == 19);
        assert!(size_of::<libc::c_ushort>() == 2);
    };

    // `syscall` は自前も `libc` も可変長。
    const _: unsafe extern "C" fn(libc::c_long, ...) -> libc::c_long = syscall;
    const _: unsafe extern "C" fn(libc::c_long, ...) -> libc::c_long = libc::syscall;

    const _: unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::mode_t) -> libc::c_int =
        mkdirat;
    const _: unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::mode_t) -> libc::c_int =
        libc::mkdirat;

    const _: unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::c_int) -> libc::c_int =
        unlinkat;
    const _: unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::c_int) -> libc::c_int =
        libc::unlinkat;

    const _: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        *const libc::c_char,
    ) -> libc::c_int = renameat;
    const _: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        *const libc::c_char,
    ) -> libc::c_int = libc::renameat;

    const _: unsafe extern "C" fn(
        *const libc::c_char,
        libc::c_int,
        *const libc::c_char,
    ) -> libc::c_int = symlinkat;
    const _: unsafe extern "C" fn(
        *const libc::c_char,
        libc::c_int,
        *const libc::c_char,
    ) -> libc::c_int = libc::symlinkat;

    const _: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
    ) -> libc::c_int = linkat;
    const _: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
    ) -> libc::c_int = libc::linkat;

    const _: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        *mut libc::c_char,
        libc::size_t,
    ) -> libc::ssize_t = readlinkat;
    const _: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        *mut libc::c_char,
        libc::size_t,
    ) -> libc::ssize_t = libc::readlinkat;

    const _: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::uid_t,
        libc::gid_t,
        libc::c_int,
    ) -> libc::c_int = fchownat;
    const _: unsafe extern "C" fn(
        libc::c_int,
        *const libc::c_char,
        libc::uid_t,
        libc::gid_t,
        libc::c_int,
    ) -> libc::c_int = libc::fchownat;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;
    use std::os::unix::ffi::OsStringExt as _;

    fn dirent(name: &[u8], reclen: u16) -> Vec<u8> {
        let mut v = vec![0u8; usize::from(reclen)];
        v[16..18].copy_from_slice(&reclen.to_ne_bytes());
        v[19..19 + name.len()].copy_from_slice(name);
        v
    }

    fn names(buf: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for_each_dirent(buf, |n| out.push(n.to_vec()))?;
        Ok(out)
    }

    /// OCI-1・#2437: dirent の解析は `.` / `..` を除き、壊れたレコードを `InvalidData` で拒否する。
    #[test]
    fn oci1_dirent_parser_concrete_values() {
        let mut buf = dirent(b".", 24);
        buf.extend(dirent(b"..", 24));
        buf.extend(dirent(b"alpha", 32));
        buf.extend(dirent(b"b", 24));
        assert_eq!(names(&buf).unwrap(), vec![b"alpha".to_vec(), b"b".to_vec()]);
        // reclen 0 は無限ループにならず拒否する。
        assert!(names(&[0u8; 24]).is_err());
        // reclen がバッファを超える。
        let mut over = dirent(b"x", 24);
        over[16..18].copy_from_slice(&64u16.to_ne_bytes());
        assert!(names(&over).is_err());
        // NUL 終端が無い。
        let mut nonul = dirent(b"", 24);
        for b in &mut nonul[19..] {
            *b = b'a';
        }
        assert!(names(&nonul).is_err());
        // ヘッダに満たない端数。
        assert!(names(&[0u8; 10]).is_err());
    }

    /// OCI-1・#2437: 名前は 1 コンポーネントに限る。
    #[test]
    fn oci1_component_validation() {
        for bad in ["", ".", "..", "a/b", "/"] {
            assert!(component_cstring(OsStr::new(bad)).is_err(), "{bad:?}");
        }
        assert!(component_cstring(&std::ffi::OsString::from_vec(b"a\0b".to_vec())).is_err());
        assert_eq!(
            relative_cstring::<&str>(&[]).unwrap().as_bytes(),
            b".".as_slice()
        );
        assert_eq!(
            relative_cstring(&["a", "b"]).unwrap().as_bytes(),
            b"a/b".as_slice()
        );
        assert!(relative_cstring(&["a", ".."]).is_err());
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("fc-oci-sys-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn open_dir(p: &std::path::Path) -> OwnedFd {
        let c = CString::new(p.as_os_str().as_bytes()).unwrap();
        openat2(None, &c, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0, 0).unwrap()
    }

    /// OCI-1・SEC-5・#2437: `RESOLVE_NO_SYMLINKS` は途中の symlink（差し替え）を `ELOOP` で拒否し、
    /// 通常の階層は開ける。
    #[test]
    fn sec5_openat2_no_symlinks_rejects_swapped_component() {
        let base = tmp("swap");
        std::fs::create_dir_all(base.join("root/a/b")).unwrap();
        std::fs::create_dir_all(base.join("outside")).unwrap();
        let root = open_dir(&base.join("root"));
        let resolve =
            RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
        let flags = O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
        let ab = CString::new("a/b").unwrap();
        assert!(openat2(Some(root.as_fd()), &ab, flags, 0, resolve).is_ok());
        std::fs::remove_dir_all(base.join("root/a")).unwrap();
        std::os::unix::fs::symlink(base.join("outside"), base.join("root/a")).unwrap();
        let e = openat2(Some(root.as_fd()), &ab, flags, 0, resolve).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(ELOOP));
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// OCI-7・SEC-1・#2638: `renameat_names` は fd 起点で名前を付け替え、既存の名前を置き換える。
    /// 1 コンポーネントでない名前は `InvalidInput`、存在しない元は `NotFound`。
    #[test]
    fn oci7_renameat_names_concrete_values() {
        let base = tmp("renameat");
        let d = open_dir(&base);
        std::fs::write(base.join("a"), b"new").unwrap();
        std::fs::write(base.join("b"), b"old").unwrap();
        renameat_names(d.as_fd(), OsStr::new("a"), d.as_fd(), OsStr::new("b")).unwrap();
        assert_eq!(std::fs::read(base.join("b")).unwrap(), b"new");
        assert_eq!(
            std::fs::symlink_metadata(base.join("a"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        for bad in ["x/y", "..", ""] {
            let e =
                renameat_names(d.as_fd(), OsStr::new(bad), d.as_fd(), OsStr::new("c")).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{bad}");
        }
        let e =
            renameat_names(d.as_fd(), OsStr::new("nope"), d.as_fd(), OsStr::new("c")).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// OCI-1・#2437: `*at` は fd 起点で動き、`linkat` は参照元の symlink を追従しない。
    #[test]
    fn oci1_at_operations_roundtrip() {
        let base = tmp("ops");
        let d = open_dir(&base);
        mkdirat_name(d.as_fd(), OsStr::new("sub"), 0o777).unwrap();
        symlinkat_name(OsStr::new("sub"), d.as_fd(), OsStr::new("lnk")).unwrap();
        let mut buf = [0u8; 64];
        let n = readlinkat_name(d.as_fd(), OsStr::new("lnk"), &mut buf).unwrap();
        assert_eq!(&buf[..n], b"sub");
        // symlink への hardlink は symlink 自身へのリンクになる（追従しない）。
        linkat_names(d.as_fd(), OsStr::new("lnk"), d.as_fd(), OsStr::new("lnk2")).unwrap();
        assert!(
            std::fs::symlink_metadata(base.join("lnk2"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let mut small = [0u8; 3];
        assert!(readlinkat_name(d.as_fd(), OsStr::new("lnk"), &mut small).is_err());
        let mut all = Vec::new();
        let mut b = vec![0u8; 4096];
        loop {
            let n = getdents64(d.as_fd(), &mut b).unwrap();
            if n == 0 {
                break;
            }
            for_each_dirent(&b[..n], |x| all.push(x.to_vec())).unwrap();
        }
        all.sort();
        assert_eq!(
            all,
            vec![b"lnk".to_vec(), b"lnk2".to_vec(), b"sub".to_vec()]
        );
        unlinkat_name(d.as_fd(), OsStr::new("lnk"), false).unwrap();
        unlinkat_name(d.as_fd(), OsStr::new("lnk2"), false).unwrap();
        unlinkat_name(d.as_fd(), OsStr::new("sub"), true).unwrap();
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
