//! namespace 分離に使う syscall・FFI の薄いラッパー（`crates/core` の `sys` モジュール。
//! `unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・オーナー決定
//! 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::exec::isolate`・`crate::exec::MountIsolation::establish`・`crate::exec::mount_proc`
//! （CORE-1・TASK-27.2・#134）と、`crate::exec::prepare_rootfs`・`crate::exec::pivot_root`
//! （CORE-1・TASK-27.3・#135）と、`crate::exec::create_default_devices`（CORE-1・TASK-27.6・#834）が、
//! `mkdirat(2)`・`unlinkat(2)`・`fstatfs(2)` と `O_NOFOLLOW` 付きの `openat(2)` を呼ぶほか、
//! `unshare(2)`・`sethostname(2)`・`mount(2)`・`openat(2)`・`geteuid(2)`・`getegid(2)` に加え、
//! `pivot_root(2)`（glibc がラッパーを持たないため `syscall(2)` 経由）・`umount2(2)`・`fchdir(2)`
//! を呼ぶために使う。さらに fork / exec 段（CORE-1・TASK-27.4.1・#831）の `crate::exec::spawn_container`・
//! `crate::exec::exec_entrypoint`・`crate::exec::ContainerChild` が、`fork(2)`・`_exit(2)`・`execveat(2)`・
//! `waitpid(2)`・`kill(2)`・`signal(2)` と `close_range(2)`（`syscall(2)` 経由）を呼ぶために使う。
//! さらに固定ステージ `crate::exec::no_new_privs`（CORE-1・TASK-27.4.3・#833）が `prctl(2)` を呼ぶ。
//! 基本デバイスノード作成は、`mknodat(2)`・`O_PATH` での `openat(2)` を呼ぶために使う。std だけでは提供されない
//! syscall のみを持ち、`crate::cgroups`（CORE-3・TASK-32.1・#158。委譲 cgroup の検出と子 cgroup 作成）も
//! `fstatfs(2)` による cgroup2 判定などに使う。検証（hostname の文字種・パス形式等）は呼び出し側の型
//! （`Hostname` 等）が済ませた値だけを受け取る。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない。公開するのは安全な関数のみ
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と
//!   維持すべき不変条件を明記する
//! - syscall の定数は `cfg(target_arch = ...)` ごとに個別に定義し、値が同じでも
//!   他アーキテクチャの定義を流用しない。対応外アーキテクチャでは各ラッパーが
//!   [`SysError::Unsupported`] を返す（fail-closed。`ErrorCode::Unimplemented` に写す）
//! - `extern "C"` の型幅は glibc / musl の宣言に合わせる（`c_int` = `i32`・
//!   `c_ulong` = `u64`・`uid_t`/`gid_t` = `u32`）。戻り値が `-1` のときは直後に
//!   `std::io::Error::last_os_error()` で errno を確保する
//!
//! # `libc` / `nix` について
//! `libc` は #86 で採用承認済みだが、自動運転下では「追加時点で新しい版があれば PR で
//! 確認する」運用条件を満たせないため、`crates/io/src/sys.rs` と同じ流儀で `Cargo.toml`
//! を変更せず必要最小限の `extern "C"` 宣言を自前で持つ（dependency-policy）。

#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, IntoRawFd as _, OwnedFd};

/// syscall 失敗の分類。`crate::exec` が `ErrorCode` へ写す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysError {
    /// 対応外のアーキテクチャ（定数が未定義）。
    Unsupported,
    /// カーネルが返した errno。
    Os(i32),
    /// シングルスレッドであることを確認できなかったため fork を拒否した（`Threads:` が 1 でない、
    /// または `/proc/self/status` を読めない・解釈できない。fail-closed）。
    MultiThreaded,
}

/// errno の値（アーキテクチャごとに `consts` で個別定義。alpha / mips / sparc 等は値が違う）。
pub(crate) use consts::{
    E2BIG, EACCES, EBADF, EBUSY, EEXIST, EINTR, EINVAL, ELOOP, ENOENT, ENOEXEC, ENOSYS, ENOTDIR,
    ENOTEMPTY, EPERM, ESRCH,
};

// # `open(2)` フラグのアーキテクチャ差（Codex P0 指摘〔aarch64 の値が誤り〕への確認記録）
//
// `O_DIRECTORY`・`O_NOFOLLOW` は Linux でもアーキテクチャごとに値が違う。x86_64 は
// `arch/x86/include/uapi/asm/` に `fcntl.h` を持たず（`include/uapi/asm-generic/Kbuild` の
// `mandatory-y += fcntl.h` で生成される汎用版）、`include/uapi/asm-generic/fcntl.h` の
// `O_DIRECTORY = 0o200000`・`O_NOFOLLOW = 0o400000` を使う。一方 arm64 は AArch32 互換
// のため `arch/arm64/include/uapi/asm/fcntl.h` で `O_DIRECTORY = 0o40000`・
// `O_NOFOLLOW = 0o100000`・`O_DIRECT = 0o200000`・`O_LARGEFILE = 0o400000` を定義し直して
// いる（Rust `libc` 0.2.189 の `src/unix/linux_like/linux/gnu/b64/aarch64/mod.rs` の
// `O_DIRECTORY = 0x4000`・`O_NOFOLLOW = 0x8000` も同値）。asm-generic の値を arm64 へ流用すると、`O_DIRECTORY` のつもりで `O_DIRECT`、
// `O_NOFOLLOW` のつもりで `O_LARGEFILE` を渡すことになり、ディレクトリ限定と symlink
// 非追従の保証が黙って失われる。そのため下の `consts` はアーキテクチャごとに個別定義し、
// 値は固定値テストで照合する（`crates/io/src/sys.rs` の `beneath_consts` と同じ判断）。
// `O_CLOEXEC`（`0o2000000`）は arm64 も上書きしない asm-generic の値。

/// アーキテクチャごとの clone / mount / open 定数。値が同一でも arch ごとに個別定義する。
#[cfg(target_arch = "x86_64")]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const CLONE_NEWNS: i32 = 0x0002_0000;
    pub const CLONE_NEWUTS: i32 = 0x0400_0000;
    pub const CLONE_NEWIPC: i32 = 0x0800_0000;
    pub const CLONE_NEWUSER: i32 = 0x1000_0000;
    pub const CLONE_NEWPID: i32 = 0x2000_0000;
    pub const MS_NOSUID: u64 = 2;
    pub const MS_NODEV: u64 = 4;
    pub const MS_NOEXEC: u64 = 8;
    pub const MS_BIND: u64 = 0x1000;
    pub const MS_REC: u64 = 0x4000;
    pub const MS_PRIVATE: u64 = 0x4_0000;
    // include/uapi/linux/mount.h の `MNT_DETACH`（umount2 のフラグ。全アーキテクチャ共通）。
    pub const MNT_DETACH: i32 = 2;
    // arch/x86/entry/syscalls/syscall_64.tbl の `pivot_root`。
    pub const SYS_PIVOT_ROOT: i64 = 155;
    // arch/x86/entry/syscalls/syscall_64.tbl の `close_range`（436）。
    pub const SYS_CLOSE_RANGE: i64 = 436;
    // include/uapi/linux/close_range.h の `CLOSE_RANGE_CLOEXEC`（`1U << 2`）。
    pub const CLOSE_RANGE_CLOEXEC: i64 = 4;
    // include/uapi/linux/wait.h の `WNOHANG`。
    pub const WNOHANG: i32 = 1;
    // include/uapi/asm-generic/signal.h の `SIGKILL`・`SIGPIPE`（x86_64 は上書きしない）。
    pub const SIGKILL: i32 = 9;
    pub const SIGPIPE: i32 = 13;
    // include/uapi/asm-generic/fcntl.h（x86_64 は上書きしない）。
    pub const O_DIRECTORY: i32 = 0o200_000;
    pub const O_NOFOLLOW: i32 = 0o400_000;
    pub const O_CLOEXEC: i32 = 0o2_000_000;
    pub const O_PATH: i32 = 0o10_000_000;
    // include/uapi/asm-generic/fcntl.h の `O_NONBLOCK`（x86_64 は上書きしない）。
    pub const O_NONBLOCK: i32 = 0o4_000;
    pub const O_RDWR: i32 = 2;
    // include/uapi/asm-generic/fcntl.h の `O_RDONLY`・`O_WRONLY`（全アーキテクチャ共通）。
    pub const O_RDONLY: i32 = 0;
    pub const O_WRONLY: i32 = 1;
    // include/uapi/linux/fcntl.h の `AT_REMOVEDIR`（全アーキテクチャ共通）。
    pub const AT_REMOVEDIR: i32 = 0x200;
    // include/uapi/asm-generic/errno-base.h・errno.h の EBUSY・ENOTEMPTY（cgroup 操作の分類用）。
    pub const EBUSY: i32 = 16;
    pub const ENOTEMPTY: i32 = 39;
    // include/uapi/linux/magic.h の `CGROUP2_SUPER_MAGIC`（"cgrp"）。
    pub const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
    // arch/x86/entry/syscalls/syscall_64.tbl の `execveat`。
    pub const SYS_EXECVEAT: i64 = 322;
    // include/uapi/linux/fcntl.h の `AT_EMPTY_PATH`（全アーキテクチャ共通）。
    pub const AT_EMPTY_PATH: i64 = 0x1000;
    // include/uapi/asm-generic/fcntl.h の `F_SETFD` と `FD_CLOEXEC`。
    pub const F_SETFD: i32 = 2;
    pub const FD_CLOEXEC: i32 = 1;
    // include/uapi/linux/fcntl.h の `F_DUPFD_CLOEXEC`（`F_LINUX_SPECIFIC_BASE` 1024 + 6）。
    pub const F_DUPFD_CLOEXEC: i32 = 1030;
    // include/uapi/asm-generic/errno-base.h・errno.h（x86_64 は上書きしない）。
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EACCES: i32 = 13;
    pub const EEXIST: i32 = 17;
    pub const ENOTDIR: i32 = 20;
    pub const EINVAL: i32 = 22;
    pub const ELOOP: i32 = 40;
    // errno-base.h / errno.h の ESRCH・EINTR・E2BIG・ENOEXEC・EBADF・ENOSYS。
    pub const ESRCH: i32 = 3;
    pub const EINTR: i32 = 4;
    pub const E2BIG: i32 = 7;
    pub const ENOEXEC: i32 = 8;
    pub const EBADF: i32 = 9;
    pub const ENOSYS: i32 = 38;
    // include/uapi/linux/stat.h の `S_IFCHR`（文字デバイス。全アーキテクチャ共通）。
    pub const S_IFCHR: u32 = 0o020_000;

    // include/uapi/linux/prctl.h の `PR_SET_NO_NEW_PRIVS`（38）・`PR_GET_NO_NEW_PRIVS`（39）。
    // 全アーキテクチャ共通の定義だが、他アーキテクチャの定義を流用しないため個別に持つ。
    pub const PR_SET_NO_NEW_PRIVS: i32 = 38;
    pub const PR_GET_NO_NEW_PRIVS: i32 = 39;
}

#[cfg(target_arch = "aarch64")]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const CLONE_NEWNS: i32 = 0x0002_0000;
    pub const CLONE_NEWUTS: i32 = 0x0400_0000;
    pub const CLONE_NEWIPC: i32 = 0x0800_0000;
    pub const CLONE_NEWUSER: i32 = 0x1000_0000;
    pub const CLONE_NEWPID: i32 = 0x2000_0000;
    pub const MS_NOSUID: u64 = 2;
    pub const MS_NODEV: u64 = 4;
    pub const MS_NOEXEC: u64 = 8;
    pub const MS_BIND: u64 = 0x1000;
    pub const MS_REC: u64 = 0x4000;
    pub const MS_PRIVATE: u64 = 0x4_0000;
    // include/uapi/linux/mount.h の `MNT_DETACH`（umount2 のフラグ。全アーキテクチャ共通）。
    pub const MNT_DETACH: i32 = 2;
    // include/uapi/asm-generic/unistd.h の `__NR_pivot_root`（arm64 は asm-generic の表を使う。
    // x86_64 の 155 を流用しない）。
    pub const SYS_PIVOT_ROOT: i64 = 41;
    // include/uapi/asm-generic/unistd.h の `__NR_close_range`（arm64 は asm-generic の表。
    // x86_64 と値が同じでも流用せず個別に定義する）。
    pub const SYS_CLOSE_RANGE: i64 = 436;
    // include/uapi/linux/close_range.h の `CLOSE_RANGE_CLOEXEC`（`1U << 2`）。
    pub const CLOSE_RANGE_CLOEXEC: i64 = 4;
    // include/uapi/linux/wait.h の `WNOHANG`。
    pub const WNOHANG: i32 = 1;
    // include/uapi/asm-generic/signal.h の `SIGKILL`・`SIGPIPE`（arm64 は上書きしない）。
    pub const SIGKILL: i32 = 9;
    pub const SIGPIPE: i32 = 13;
    // arch/arm64/include/uapi/asm/fcntl.h（asm-generic と異なる。x86_64 の値を流用しない。
    // 流用すると O_DIRECT / O_LARGEFILE に化ける）。
    pub const O_DIRECTORY: i32 = 0o40_000;
    pub const O_NOFOLLOW: i32 = 0o100_000;
    // include/uapi/asm-generic/fcntl.h（arm64 も上書きしない）。
    pub const O_CLOEXEC: i32 = 0o2_000_000;
    pub const O_PATH: i32 = 0o10_000_000;
    // include/uapi/asm-generic/fcntl.h の `O_NONBLOCK`（arm64 も上書きしない）。
    pub const O_NONBLOCK: i32 = 0o4_000;
    pub const O_RDWR: i32 = 2;
    // include/uapi/asm-generic/fcntl.h の `O_RDONLY`・`O_WRONLY`（全アーキテクチャ共通）。
    pub const O_RDONLY: i32 = 0;
    pub const O_WRONLY: i32 = 1;
    // include/uapi/linux/fcntl.h の `AT_REMOVEDIR`（全アーキテクチャ共通）。
    pub const AT_REMOVEDIR: i32 = 0x200;
    // include/uapi/asm-generic/errno-base.h・errno.h の EBUSY・ENOTEMPTY（cgroup 操作の分類用）。
    pub const EBUSY: i32 = 16;
    pub const ENOTEMPTY: i32 = 39;
    // include/uapi/linux/magic.h の `CGROUP2_SUPER_MAGIC`（"cgrp"）。
    pub const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
    // include/uapi/asm-generic/unistd.h の `__NR_execveat`（arm64 は asm-generic の表。
    // x86_64 の 322 を流用しない）。
    pub const SYS_EXECVEAT: i64 = 281;
    // include/uapi/linux/fcntl.h の `AT_EMPTY_PATH`（全アーキテクチャ共通）。
    pub const AT_EMPTY_PATH: i64 = 0x1000;
    // include/uapi/asm-generic/fcntl.h の `F_SETFD` と `FD_CLOEXEC`。
    pub const F_SETFD: i32 = 2;
    pub const FD_CLOEXEC: i32 = 1;
    // include/uapi/linux/fcntl.h の `F_DUPFD_CLOEXEC`（`F_LINUX_SPECIFIC_BASE` 1024 + 6）。
    pub const F_DUPFD_CLOEXEC: i32 = 1030;
    // include/uapi/asm-generic/errno-base.h・errno.h（arm64 は上書きしない）。
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EACCES: i32 = 13;
    pub const EEXIST: i32 = 17;
    pub const ENOTDIR: i32 = 20;
    pub const EINVAL: i32 = 22;
    pub const ELOOP: i32 = 40;
    // errno-base.h / errno.h の ESRCH・EINTR・E2BIG・ENOEXEC・EBADF・ENOSYS。
    pub const ESRCH: i32 = 3;
    pub const EINTR: i32 = 4;
    pub const E2BIG: i32 = 7;
    pub const ENOEXEC: i32 = 8;
    pub const EBADF: i32 = 9;
    pub const ENOSYS: i32 = 38;
    // include/uapi/linux/stat.h の `S_IFCHR`（文字デバイス。全アーキテクチャ共通）。
    pub const S_IFCHR: u32 = 0o020_000;

    // include/uapi/linux/prctl.h の `PR_SET_NO_NEW_PRIVS`（38）・`PR_GET_NO_NEW_PRIVS`（39）。
    // 全アーキテクチャ共通の定義だが、他アーキテクチャの定義を流用しないため個別に持つ。
    pub const PR_SET_NO_NEW_PRIVS: i32 = 38;
    pub const PR_GET_NO_NEW_PRIVS: i32 = 39;
}

/// 対応外アーキテクチャ: 定数は 0 で、ラッパーは `Unsupported` を返す。errno は実在しない
/// 負の値にして、`std::io::Error` 由来の実 errno と誤って一致させない（分類は `Internal`）。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod consts {
    pub const SUPPORTED: bool = false;
    pub const CLONE_NEWNS: i32 = 0;
    pub const CLONE_NEWUTS: i32 = 0;
    pub const CLONE_NEWIPC: i32 = 0;
    pub const CLONE_NEWUSER: i32 = 0;
    pub const CLONE_NEWPID: i32 = 0;
    pub const MS_NOSUID: u64 = 0;
    pub const MS_NODEV: u64 = 0;
    pub const MS_NOEXEC: u64 = 0;
    pub const MS_BIND: u64 = 0;
    pub const MS_REC: u64 = 0;
    pub const MS_PRIVATE: u64 = 0;
    pub const MNT_DETACH: i32 = 0;
    pub const SYS_PIVOT_ROOT: i64 = 0;
    pub const SYS_CLOSE_RANGE: i64 = 0;
    pub const CLOSE_RANGE_CLOEXEC: i64 = 0;
    pub const WNOHANG: i32 = 0;
    pub const SIGKILL: i32 = 0;
    pub const SIGPIPE: i32 = 0;
    pub const O_DIRECTORY: i32 = 0;
    pub const O_NOFOLLOW: i32 = 0;
    pub const O_CLOEXEC: i32 = 0;
    pub const O_PATH: i32 = 0;
    pub const O_NONBLOCK: i32 = 0;
    pub const O_RDWR: i32 = 0;
    pub const O_RDONLY: i32 = 0;
    pub const O_WRONLY: i32 = 0;
    pub const AT_REMOVEDIR: i32 = 0;
    pub const EBUSY: i32 = -14;
    pub const ENOTEMPTY: i32 = -15;
    pub const CGROUP2_SUPER_MAGIC: i64 = 0;
    pub const SYS_EXECVEAT: i64 = 0;
    pub const AT_EMPTY_PATH: i64 = 0;
    pub const F_SETFD: i32 = 0;
    pub const FD_CLOEXEC: i32 = 0;
    pub const F_DUPFD_CLOEXEC: i32 = 0;
    pub const EPERM: i32 = -1;
    pub const ENOENT: i32 = -2;
    pub const EACCES: i32 = -3;
    pub const EEXIST: i32 = -7;
    pub const ENOTDIR: i32 = -4;
    pub const EINVAL: i32 = -5;
    pub const ELOOP: i32 = -6;
    pub const ESRCH: i32 = -8;
    pub const EINTR: i32 = -9;
    pub const E2BIG: i32 = -10;
    pub const ENOEXEC: i32 = -11;
    pub const ENOSYS: i32 = -12;
    pub const EBADF: i32 = -13;
    pub const S_IFCHR: u32 = 0;

    pub const PR_SET_NO_NEW_PRIVS: i32 = 0;
    pub const PR_GET_NO_NEW_PRIVS: i32 = 0;
}

/// `openat(2)` の `AT_FDCWD`（絶対パス指定時は dirfd が無視される）。値は
/// `include/uapi/linux/fcntl.h` の全アーキテクチャ共通定義（arch 別の上書きなし）。
const AT_FDCWD: i32 = -100;

/// `unshare(2)` に渡す namespace フラグ 1 種（生のビット値を crate 外へ出さない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NsFlag {
    Mount,
    Uts,
    Ipc,
    User,
    Pid,
}

impl NsFlag {
    /// 対応する `CLONE_NEW*` のビット値。
    pub(crate) fn bits(self) -> i32 {
        match self {
            Self::Mount => consts::CLONE_NEWNS,
            Self::Uts => consts::CLONE_NEWUTS,
            Self::Ipc => consts::CLONE_NEWIPC,
            Self::User => consts::CLONE_NEWUSER,
            Self::Pid => consts::CLONE_NEWPID,
        }
    }
}

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: glibc / musl の `int unshare(int flags)` と同じ型幅。
    fn unshare(flags: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int sethostname(const char *name, size_t len)`。
    fn sethostname(name: *const core::ffi::c_char, len: usize) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int mount(const char *source, const char *target,
    // const char *fstype, unsigned long flags, const void *data)`（`c_ulong` は LP64 で u64）。
    fn mount(
        source: *const core::ffi::c_char,
        target: *const core::ffi::c_char,
        fstype: *const core::ffi::c_char,
        flags: u64,
        data: *const core::ffi::c_void,
    ) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int openat(int dirfd, const char *path, int flags, ...)`
    // と同じく可変長引数として宣言する（非可変長で宣言して呼ぶと、可変長引数の渡し方が
    // 異なる ABI で未定義動作になる）。可変長部は mode で、O_CREAT / O_TMPFILE 不使用の
    // ため渡さない（カーネル・libc は読まない）。
    fn openat(dirfd: i32, path: *const core::ffi::c_char, flags: i32, ...) -> i32;
    // SAFETY（宣言そのものの妥当性）: `long syscall(long number, ...)`（glibc / musl。LP64 で
    // `long` は i64）。`pivot_root(2)` は glibc にラッパーが無いため使う。可変長引数として宣言する
    // （非可変長で宣言して呼ぶと、可変長引数の渡し方が異なる ABI で未定義動作になる）。
    fn syscall(number: i64, ...) -> i64;
    // SAFETY（宣言そのものの妥当性）: `int umount2(const char *target, int flags)`。
    fn umount2(target: *const core::ffi::c_char, flags: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int fchdir(int fd)`。
    fn fchdir(fd: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int mknodat(int dirfd, const char *pathname, mode_t mode,
    // dev_t dev)`（glibc / musl の LP64 で `mode_t` は u32・`dev_t` は u64）。
    fn mknodat(dirfd: i32, path: *const core::ffi::c_char, mode: u32, dev: u64) -> i32;
    // SAFETY（宣言そのものの妥当性）: `uid_t geteuid(void)`（Linux の `uid_t` は u32）。
    fn geteuid() -> u32;
    // SAFETY（宣言そのものの妥当性）: `gid_t getegid(void)`（Linux の `gid_t` は u32）。
    fn getegid() -> u32;
    // SAFETY（宣言そのものの妥当性）: `pid_t fork(void)`（Linux の `pid_t` は i32）。
    fn fork() -> i32;
    // SAFETY（宣言そのものの妥当性）: `void _exit(int status)`（noreturn。atexit・デストラクタを
    // 実行しない）。
    fn _exit(status: i32) -> !;
    // SAFETY（宣言そのものの妥当性）: `pid_t waitpid(pid_t pid, int *wstatus, int options)`。
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int kill(pid_t pid, int sig)`。
    fn kill(pid: i32, sig: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `sighandler_t signal(int signum, sighandler_t handler)`。
    // `sighandler_t`（関数ポインタ）はポインタ幅の整数として扱う（`SIG_DFL` = 0、
    // `SIG_ERR` = `usize::MAX`）。
    fn signal(sig: i32, handler: usize) -> usize;
    // SAFETY（宣言そのものの妥当性）: `int fcntl(int fd, int cmd, ...)`。可変長引数として宣言する
    // （非可変長で宣言して呼ぶと、可変長引数の渡し方が異なる ABI で未定義動作になる）。
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int dup2(int oldfd, int newfd)`。
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int prctl(int option, ...)`（glibc / musl）。可変長引数として
    // 宣言する（非可変長で宣言して呼ぶと、可変長引数の渡し方が異なる ABI で未定義動作になる）。
    // 可変長部は `unsigned long`（LP64 で u64）なので呼び出し側は u64 で渡す。
    fn prctl(option: i32, ...) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int mkdirat(int dirfd, const char *path, mode_t mode)`
    // （LP64 で `mode_t` は u32）。
    fn mkdirat(dirfd: i32, path: *const core::ffi::c_char, mode: u32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int unlinkat(int dirfd, const char *path, int flags)`。
    fn unlinkat(dirfd: i32, path: *const core::ffi::c_char, flags: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int fstatfs(int fd, struct statfs *buf)`。構造体は下の
    // [`StatFs`]（arch 別に個別定義）で、カーネルが書く 120 バイトを確保する。
    fn fstatfs(fd: i32, buf: *mut StatFs) -> i32;
}

/// `fstatfs(2)` の出力バッファ（x86_64）。`struct statfs` は先頭が `f_type`（`long`）、全体 120 バイト
/// （arch/x86/include/uapi/asm/statfs.h → asm-generic/statfs.h の 64 ビット版）。先頭以外は使わない。
#[cfg(target_arch = "x86_64")]
#[repr(C)]
struct StatFs {
    f_type: i64,
    _rest: [i64; 14],
}

/// `fstatfs(2)` の出力バッファ（aarch64）。レイアウトは asm-generic/statfs.h の 64 ビット版で、
/// x86_64 と同値だが他 arch の定義を流用せず個別に持つ（先頭 `f_type`、全体 120 バイト）。
#[cfg(target_arch = "aarch64")]
#[repr(C)]
struct StatFs {
    f_type: i64,
    _rest: [i64; 14],
}

/// 対応外アーキテクチャ: レイアウト未確認のためラッパーは `Unsupported` を返し、カーネルには渡さない。
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[repr(C)]
struct StatFs {
    f_type: i64,
}

/// 直前の失敗した syscall の errno を `SysError` にする（失敗直後に呼ぶこと）。
fn last_error() -> SysError {
    SysError::Os(io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// 指定 namespace 群を 1 回の `unshare(2)` で分離する。
///
/// `CLONE_NEWUSER` を同時指定すると他 namespace が新 user namespace の所有になり、
/// 非特権でも作成できる。空のフラグは呼び出し側で拒否済みの前提。
pub(crate) fn unshare_namespaces(flags: &[NsFlag]) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let bits = flags.iter().fold(0i32, |acc, f| acc | f.bits());
    // SAFETY: 引数は値渡しの整数のみでポインタを取らない。呼び出し元プロセスの
    // namespace を変更する副作用は `crate::exec::isolate` の契約として文書化済み。
    let rc = unsafe { unshare(bits) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// UTS namespace 内の hostname を設定する。`name` は `Hostname` newtype で検証済みの値。
pub(crate) fn set_hostname(name: &[u8]) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `name.as_ptr()` は `name.len()` バイト有効な借用スライスで、呼び出しの間
    // 生存する。sethostname は NUL 終端を要求せず、長さぶんだけを読む。
    let rc = unsafe { sethostname(name.as_ptr().cast(), name.len()) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `/` を再帰的に private へ変更し、以後のマウントをホストへ伝播させない。
pub(crate) fn mount_root_private_recursive() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `c"/"` は NUL 終端の静的文字列。source / fstype / data は NULL で、
    // MS_REC|MS_PRIVATE の propagation 変更ではカーネルが参照しない。
    let rc = unsafe {
        mount(
            core::ptr::null(),
            c"/".as_ptr(),
            core::ptr::null(),
            consts::MS_REC | consts::MS_PRIVATE,
            core::ptr::null(),
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// [`open_dir_path_nofollow`] が渡す `openat(2)` のフラグ。
///
/// - `O_PATH`: 読み取り権限を要求せず、経路上の search（実行）権限だけで辿れる fd を得る。
///   `CLONE_NEWUSER` 後はホスト所有で実行権限のみ（読み取り不可）の祖先ディレクトリが
///   あり得るため、読み取り可能な fd を要求すると正当なパスでも失敗する（Cursor Bugbot 指摘）。
///   O_PATH fd は `openat` の dirfd と `/proc/thread-self/fd/N` の magic link（`mount(2)` の
///   マウント先）に使え、本モジュールの用途はこの 2 つに限る
/// - `O_DIRECTORY`: **symlink 拒否の要**。`O_PATH|O_NOFOLLOW` だけでは最終要素の symlink
///   そのものを指す fd が返る（`open(2)` の O_PATH 節）。`O_DIRECTORY` を併用することで
///   symlink・非ディレクトリはいずれも `ENOTDIR` で拒否される（実測でも symlink は `ELOOP`
///   ではなく `ENOTDIR`）。このフラグを外すと symlink を固定してしまうため外さない
/// - `O_NOFOLLOW`・`O_CLOEXEC`: 最終要素の symlink を辿らない・exec で fd を漏らさない
fn open_dir_path_flags() -> i32 {
    consts::O_PATH | consts::O_DIRECTORY | consts::O_NOFOLLOW | consts::O_CLOEXEC
}

/// `parent` 配下（`None` なら絶対パス `name` を CWD 非依存で）の `name` を
/// [`open_dir_path_flags`]（`O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`）で開き、fd を返す。
/// 最終要素が symlink・非ディレクトリなら `ENOTDIR`、不在なら `ENOENT`、search 権限が
/// 無ければ `EACCES`。
///
/// 呼び出し側が 1 要素ずつ辿ることで、検証した実体を fd で固定できる（TOCTOU 対策）。
/// 返る fd は O_PATH のため読み書きには使えない（dirfd・`/proc/thread-self/fd/N`・fdinfo 専用）。
pub(crate) fn open_dir_path_nofollow(
    parent: Option<BorrowedFd<'_>>,
    name: &CStr,
) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let dirfd = parent.map_or(AT_FDCWD, |p| p.as_raw_fd());
    let flags = open_dir_path_flags();
    // SAFETY: `name` は借用した NUL 終端文字列で呼び出しの間生存する。`dirfd` は
    // 生存中の `BorrowedFd`（O_PATH fd も dirfd として有効）か `AT_FDCWD`。flags に
    // O_CREAT / O_TMPFILE を含まないため可変長引数（mode）は渡さず、カーネルも読まない。
    // 成功時の戻り値は新規 fd で、直後に `OwnedFd` が唯一の所有者となる（二重 close なし）。
    let fd = unsafe { openat(dirfd, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` は上で成功した openat が返した、他に所有者のいない有効な fd。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `target` に procfs を `nosuid,nodev,noexec` でマウントする。
///
/// `crate::exec::mount_proc` は検証済みの O_PATH fd を指す `/proc/thread-self/fd/N` を渡す
/// （magic link は fd の実体へ解決されるため、パス文字列を再解決しない）。
// テストビルドでは `crate::exec` の dry-run 差し込み点（`mount_proc_syscall`）が本関数を
// 呼ばないため、dead_code を許可する（本番ビルドでは使われる）。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn mount_proc_at(target: &CStr) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `target` は `&CStr` の借用で NUL 終端かつ呼び出しの間生存する。
    // source / fstype は静的な NUL 終端文字列、data は NULL。
    let rc = unsafe {
        mount(
            c"proc".as_ptr(),
            target.as_ptr(),
            c"proc".as_ptr(),
            consts::MS_NOSUID | consts::MS_NODEV | consts::MS_NOEXEC,
            core::ptr::null(),
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `target` を自分自身へ再帰 bind mount し（`MS_BIND|MS_REC`）、`target` をマウントポイントにする。
///
/// `pivot_root(2)` の new_root は「マウントポイントであること」が要件で、rootfs が単なる
/// ディレクトリでも `crate::exec::prepare_rootfs` がこれで満たす。`target` は検証済みの O_PATH fd を
/// 指す `/proc/thread-self/fd/N`（magic link は fd の実体へ解決される）。
// テストビルドでは `crate::exec` の dry-run 差し込み点が本関数を呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn bind_mount_recursive(target: &CStr) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `target` は `&CStr` の借用で NUL 終端かつ呼び出しの間生存する（source と target
    // に同じポインタを渡す）。fstype / data は NULL（MS_BIND ではカーネルが参照しない）。
    let rc = unsafe {
        mount(
            target.as_ptr(),
            target.as_ptr(),
            core::ptr::null(),
            consts::MS_BIND | consts::MS_REC,
            core::ptr::null(),
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `pivot_root(".", ".")`。new_root と put_old を同じ cwd にすることで put_old 用ディレクトリを
/// 作らずに済む（固定名 `.old_root` による共有 rootfs での ENOENT 競合を避ける。TASK-27.3）。
/// 呼び出し前に cwd を new_root（マウントポイント）の fd へ `fchdir` しておくこと。
// テストビルドでは dry-run 差し込み点が本関数を呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn pivot_root_dot() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 第 2・3 引数は静的な NUL 終端文字列 `c"."` へのポインタ（`*const c_char`。可変長
    // 引数として register 幅で渡され、カーネルは 2 引数だけ読む）。番号は arch ごとの定数。
    // 戻り値 -1 のとき直後に errno を確保する。
    let rc = unsafe { syscall(consts::SYS_PIVOT_ROOT, c".".as_ptr(), c".".as_ptr()) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// cwd のマウントを `MNT_DETACH` で切り離す（`umount2(".", MNT_DETACH)`）。`pivot_root(".", ".")` 後に
/// cwd を旧 root の fd へ戻してから呼び、旧 root を mount namespace から外す。
// テストビルドでは dry-run 差し込み点が本関数を呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn umount_cwd_detach() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `c"."` は静的な NUL 終端文字列。flags は定数で、ポインタ以外の副作用は
    // 呼び出しスレッドの mount namespace の変更（`crate::exec::pivot_root` の契約として文書化済み）。
    let rc = unsafe { umount2(c".".as_ptr(), consts::MNT_DETACH) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// cwd を `fd`（ディレクトリを指す fd。O_PATH でも可）へ変更する。
// テストビルドでは dry-run 差し込み点が本関数を呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn change_dir_fd(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `fd` は生存中の `BorrowedFd`。fchdir は fd を読み取るだけで所有権を取らない。
    let rc = unsafe { fchdir(fd.as_raw_fd()) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `/proc/self/status` の内容から `Threads:` が 1（シングルスレッド）かを判定する純関数。
/// 行が無い・数値でない場合は `false`（fail-closed）。`crate::exec` の `status_threads` は
/// 上位モジュールのため呼ばず（依存方向を保つ）、ここに最小の解析を持つ。
fn threads_is_one(status: &str) -> bool {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse::<u64>().ok())
        == Some(1)
}

/// `child` をシングルスレッドの呼び出し元から `fork(2)` した子で実行し、親には子の PID を返す。
///
/// `crate::exec::spawn_container`（CORE-1・TASK-27.4.1）が使う。fork の健全性条件を呼び出し側の
/// 検査に依存させないため、**この関数の内側で強制する**:
///
/// - fork 直前に `/proc/self/status` の `Threads:` が 1 であることを確認する。満たさない・読めない
///   ときは fork せず [`SysError::MultiThreaded`] を返す（`Threads: 1` の間、確認から fork までに
///   新しいスレッドを作れる主体は自身以外に存在しない）
/// - fork 前に stdout / stderr のバッファを flush する（子が親のバッファを二重出力しない）
/// - 子は `child` を `catch_unwind` で実行し、その結果（panic なら `panic_exit`）で必ず
///   `_exit(2)` する。呼び出し元のスタックフレームへ戻らず、`std::process::exit`（atexit・
///   デストラクタ）も使わない
pub(crate) fn fork_single_threaded<F: FnOnce() -> i32>(
    child: F,
    panic_exit: i32,
) -> Result<u32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let status =
        std::fs::read_to_string("/proc/self/status").map_err(|_| SysError::MultiThreaded)?;
    if !threads_is_one(&status) {
        return Err(SysError::MultiThreaded);
    }
    {
        use std::io::Write as _;
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
    }
    // SAFETY: 直前に `Threads: 1` を確認済みで、fork した子には呼び出しスレッドだけが複製される
    // ため、他スレッドが保持していたロック・ヒープの不整合を子が引き継がない。子は下の分岐で
    // `child` を実行して `_exit` し、呼び出し元のフレームへ戻らない。親は戻り値の pid だけを使う。
    let pid = unsafe { fork() };
    if pid < 0 {
        return Err(last_error());
    }
    if pid == 0 {
        let code =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(child)).unwrap_or(panic_exit);
        // SAFETY: 引数は値渡しの整数のみ。noreturn で、子プロセスをここで終了させる
        // （atexit・デストラクタを実行せず、親と共有している状態を触らない）。
        unsafe { _exit(code) }
    }
    u32::try_from(pid).map_err(|_| SysError::Os(EINVAL))
}

/// NULL 終端のポインタ配列を作る（`execve(2)` の `argv` / `envp` 用）。各ポインタは `items` の
/// 要素を指すため、戻り値は `items` より長く生存させない。
fn null_terminated_ptrs(items: &[CString]) -> Vec<*const core::ffi::c_char> {
    items
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(core::ptr::null()))
        .collect()
}

/// 絶対パス `path` を読み取り専用で開く（`O_RDONLY|O_CLOEXEC|O_NONBLOCK`。最終要素の symlink は辿る）。
///
/// エントリポイントの検査と実行を同じ実体に固定するための fd を得る（[`exec_fd`] と組で使う）。
/// `O_NONBLOCK` は FIFO 等の open が相手待ちでハングするのを避けるため（REPAIR-5）。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn open_file_read(path: &CStr) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let flags = consts::O_CLOEXEC | consts::O_NONBLOCK;
    // SAFETY: `path` は借用した NUL 終端文字列で呼び出しの間生存する。flags に O_CREAT / O_TMPFILE を
    // 含まないため可変長引数（mode）は渡さず、カーネルも読まない。成功時の戻り値は新規 fd で、
    // 直後に `OwnedFd` が唯一の所有者となる（二重 close なし）。
    let fd = unsafe { openat(AT_FDCWD, path.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` は上で成功した openat が返した、他に所有者のいない有効な fd。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `fd` の close-on-exec を `on` に設定する（`fcntl(F_SETFD)`）。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn set_cloexec(fd: BorrowedFd<'_>, on: bool) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let arg = if on { consts::FD_CLOEXEC } else { 0 };
    // SAFETY: `fd` は生存中の `BorrowedFd`。F_SETFD は整数引数のみを取りポインタを渡さない。
    let rc = unsafe { fcntl(fd.as_raw_fd(), consts::F_SETFD, arg) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `fd` を `min` 以上の最小の空き番号へ複製する（`fcntl(F_DUPFD_CLOEXEC, min)`。複製は close-on-exec）。
///
/// エントリポイントの fd を標準入出力の番号（0〜2）の外へ置くために使う（`crate::exec` の
/// `keep_above_stdio`）。std の `try_clone` の下限は文書化された保証ではないため、下限を明示して呼ぶ。
/// `min` が負なら `EINVAL`。
pub(crate) fn dup_fd_at_least(fd: BorrowedFd<'_>, min: i32) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    if min < 0 {
        return Err(SysError::Os(EINVAL));
    }
    // SAFETY: `fd` は生存中の `BorrowedFd`。F_DUPFD_CLOEXEC は整数引数（下限）のみを取りポインタを
    // 渡さない。成功時の戻り値は新規 fd で、直後に `OwnedFd` が唯一の所有者となる（二重 close なし）。
    let new = unsafe { fcntl(fd.as_raw_fd(), consts::F_DUPFD_CLOEXEC, min) };
    if new < 0 {
        return Err(last_error());
    }
    // SAFETY: `new` は上で成功した fcntl が返した、他に所有者のいない有効な fd。
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

/// 絶対パス `path` を読み書きで開く（`O_RDWR|O_CLOEXEC|O_NONBLOCK`。最終要素の symlink は辿る）。
/// 呼び出し側が開いた実体の種別を検証する前提（[`redirect_stdio_to`] と組で使う）。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn open_file_rdwr(path: &CStr) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let flags = consts::O_RDWR | consts::O_CLOEXEC | consts::O_NONBLOCK;
    // SAFETY: `path` は借用した NUL 終端文字列で呼び出しの間生存する。flags に O_CREAT / O_TMPFILE を
    // 含まないため可変長引数（mode）は渡さない。成功時の戻り値は新規 fd で、直後に `OwnedFd` が
    // 唯一の所有者となる（二重 close なし）。
    let fd = unsafe { openat(AT_FDCWD, path.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` は上で成功した openat が返した、他に所有者のいない有効な fd。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// fd 0・1・2 を `fd` の実体で置き換える（`dup2`。置換先は close-on-exec が外れる）。呼び出し元が
/// 引き継いだ標準入出力の実体（ホストのファイル・ソケット）をコンテナへ渡さないために使う。
/// `fd` 自体が 0〜2 のいずれかのときは、その番号は置換せず close-on-exec を外して保持する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn redirect_stdio_to(fd: OwnedFd) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let raw = fd.as_raw_fd();
    for target in 0..=2 {
        if target == raw {
            continue;
        }
        // SAFETY: `raw` は `fd` が所有する生存中の fd。`target` は 0〜2 の整数で、引数はいずれも
        // 整数のみ（ポインタなし）。既存の標準 fd は暗黙に close され置換される（意図した動作）。
        if unsafe { dup2(raw, target) } == -1 {
            return Err(last_error());
        }
    }
    if raw <= 2 {
        // 0〜2 のいずれかとして確保された fd は閉じずに保持する（標準 fd の役目を兼ねる）。
        let kept = fd.into_raw_fd();
        // SAFETY: `kept` は今 `OwnedFd` から取り出した有効な fd で、ここで所有権を手放すため
        // 借用の間に close されない。
        let borrowed = unsafe { BorrowedFd::borrow_raw(kept) };
        return set_cloexec(borrowed, false);
    }
    Ok(())
}

/// 開いた fd の実体を `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` で実行する。パスを再解決しない
/// ため、検査した fd とは別のファイルが実行されることはない（TOCTOU 対策）。成功すると戻らず、
/// 戻ったら常に失敗でその errno を返す。`fd` が close-on-exec のままだとシェバン付きスクリプトは
/// `ENOENT` になる（カーネルが `/dev/fd/N` を開けないため）。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn exec_fd(fd: BorrowedFd<'_>, argv: &[CString], envp: &[CString]) -> SysError {
    if !consts::SUPPORTED {
        return SysError::Unsupported;
    }
    let argv_ptrs = null_terminated_ptrs(argv);
    let envp_ptrs = null_terminated_ptrs(envp);
    // SAFETY: `fd` は生存中の `BorrowedFd`。パス引数は静的な空文字列（NUL 終端）で AT_EMPTY_PATH と
    // 組で使う。`argv_ptrs` / `envp_ptrs` は末尾が NULL のポインタ配列で、各要素は呼び出しの間生存する
    // `argv` / `envp`（NUL 終端の `CString`）を指す。成功時は戻らず、失敗時は配列を読み取っただけ。
    unsafe {
        syscall(
            consts::SYS_EXECVEAT,
            i64::from(fd.as_raw_fd()),
            c"".as_ptr(),
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
            consts::AT_EMPTY_PATH,
        )
    };
    last_error()
}

/// fd `first` 以上のすべてを close-on-exec にする（`close_range(first, ~0, CLOSE_RANGE_CLOEXEC)`。
/// Linux 5.11 以降）。exec 後のコンテナへホスト側の fd を漏らさない（CVE-2024-21626 型）。
/// 未対応カーネルは `ENOSYS`/`EINVAL` を返す（呼び出し側が fail-closed にする）。
// テストビルドでは dry-run 差し込み点が本関数を呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn mark_fds_cloexec_from(first: u32) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみでポインタを取らない（`close_range` は glibc 2.34 未満に無いため
    // `syscall(2)` 経由。unsigned int 引数は register 幅に拡張して渡され、カーネルは下位 32 bit を
    // 読む）。CLOEXEC 指定のため fd は閉じず、exec までの間は引き続き使える。
    let rc = unsafe {
        syscall(
            consts::SYS_CLOSE_RANGE,
            i64::from(first),
            i64::from(u32::MAX),
            consts::CLOSE_RANGE_CLOEXEC,
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// fd `first` 以上のすべてを閉じる（`close_range(first, ~0, 0)`。Linux 5.11 以降）。
/// 呼び出し元から継承したホスト側の fd を、エントリポイントを開く前に断つ。コンテナの rootfs 内の
/// `/proc/self/fd/N` 経由で継承 fd の実体を開かれる経路を塞ぐ（CVE-2024-21626 型）。
/// 未対応カーネルは `ENOSYS`/`EINVAL` を返す（呼び出し側が fail-closed にする）。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn close_fds_from(first: u32) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみでポインタを取らない（`syscall(2)` 経由。unsigned int 引数は register
    // 幅に拡張して渡され、カーネルは下位 32 bit を読む）。閉じる対象は `first` 以上の fd だけで、
    // 呼び出し側（exec 直前の子）はそれらの fd をこの後使わない前提。
    let rc = unsafe {
        syscall(
            consts::SYS_CLOSE_RANGE,
            i64::from(first),
            i64::from(u32::MAX),
            0i64,
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// [`open_path_nofollow`] が渡す `openat(2)` のフラグ（`O_PATH|O_NOFOLLOW|O_CLOEXEC`）。
/// `O_DIRECTORY` を付けないため、最終要素が symlink でもそれ自体を指す fd が得られる
/// （辿らない）。返る fd は fstat と `/proc/thread-self/fd/N` の magic link 専用。
fn open_path_flags() -> i32 {
    consts::O_PATH | consts::O_NOFOLLOW | consts::O_CLOEXEC
}

/// `parent` 配下の `name` を [`open_path_flags`] で開く（種別は問わない・最終要素の symlink は辿らない）。
/// `crate::exec::create_default_devices` が、作成直後のデバイスノードを固定して種別と
/// `rdev` を検証するために使う（検証した実体だけを chmod する TOCTOU 対策。CORE-1）。
pub(crate) fn open_path_nofollow(parent: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let flags = open_path_flags();
    // SAFETY: `name` は借用した NUL 終端文字列で呼び出しの間生存する。`parent` は生存中の
    // `BorrowedFd`。flags に O_CREAT / O_TMPFILE を含まないため可変長引数（mode）は渡さない。
    // 成功時の戻り値は新規 fd で、直後に `OwnedFd` が唯一の所有者となる（二重 close なし）。
    let fd = unsafe { openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` は上で成功した openat が返した、他に所有者のいない有効な fd。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `parent` 配下に 1 要素のディレクトリ `name` を `mkdirat(2)` で作る（cgroup v2 ではこれが子 cgroup
/// の作成になる。`crate::cgroups`・CORE-3・TASK-32.1）。既存なら `EEXIST`、権限不足は `EACCES`/`EPERM`。
/// `name` は呼び出し側が 1 要素（`/` を含まない）に検証済みの前提。
pub(crate) fn mkdir_at(parent: BorrowedFd<'_>, name: &CStr, mode: u32) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `name` は `&CStr` の借用で NUL 終端かつ呼び出しの間生存する。`parent` は生存中の
    // `BorrowedFd`。副作用は `parent` 配下へのディレクトリ作成のみで、ポインタは保持されない。
    let rc = unsafe { mkdirat(parent.as_raw_fd(), name.as_ptr(), mode & 0o7777) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `parent` 配下の `name` を `unlinkat(2)` の `AT_REMOVEDIR` で削除する（空の cgroup のみ消せる。
/// 子・プロセスが残っていれば `EBUSY`）。最終要素の symlink は辿らない（`AT_REMOVEDIR` は
/// ディレクトリ以外を `ENOTDIR` で拒否する）。
pub(crate) fn remove_dir_at(parent: BorrowedFd<'_>, name: &CStr) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `name` は NUL 終端の借用で呼び出しの間生存する。`parent` は生存中の `BorrowedFd`。
    // 副作用は `parent` 配下の空ディレクトリ 1 件の削除のみ。
    let rc = unsafe { unlinkat(parent.as_raw_fd(), name.as_ptr(), consts::AT_REMOVEDIR) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// [`open_read_at`] / [`open_write_at`] 共通の `openat(2)` 呼び出し。`O_NOFOLLOW|O_CLOEXEC` を常に付け、
/// `O_CREAT` を含まない（既存ファイルだけを開く。cgroup のインターフェースファイルは作らせない）。
fn open_file_at(parent: BorrowedFd<'_>, name: &CStr, access: i32) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let flags = access | consts::O_NOFOLLOW | consts::O_CLOEXEC;
    // SAFETY: `name` は借用した NUL 終端文字列で呼び出しの間生存する。`parent` は生存中の
    // `BorrowedFd`。flags に O_CREAT / O_TMPFILE を含まないため可変長引数（mode）は渡さない。
    // 成功時の戻り値は新規 fd で、直後に `OwnedFd` が唯一の所有者となる（二重 close なし）。
    let fd = unsafe { openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` は上で成功した openat が返した、他に所有者のいない有効な fd。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `parent` 配下の既存ファイル `name` を読み取り専用（`O_NOFOLLOW`）で開く。
pub(crate) fn open_read_at(parent: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd, SysError> {
    open_file_at(parent, name, consts::O_RDONLY)
}

/// `parent` 配下の既存ファイル `name` を書き込み専用（`O_NOFOLLOW`）で開く。
/// `cgroup.procs`・`cgroup.subtree_control` への書き込みに使う（CORE-3）。
pub(crate) fn open_write_at(parent: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd, SysError> {
    open_file_at(parent, name, consts::O_WRONLY)
}

/// `fd` が属するファイルシステムの種別（`statfs.f_type`）を `fstatfs(2)` で返す。cgroup2 の
/// 検証（`consts::CGROUP2_SUPER_MAGIC` との比較）に使う。O_PATH fd でも使える。
pub(crate) fn fs_type(fd: BorrowedFd<'_>) -> Result<i64, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut buf = StatFs {
        f_type: 0,
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        _rest: [0; 14],
    };
    // SAFETY: `buf` は `struct statfs`（120 バイト）と同じレイアウトの書き込み可能な領域で、
    // 呼び出しの間生存する（対応 arch のみ。対応外は上で `Unsupported`）。`fd` は生存中の
    // `BorrowedFd`。カーネルは `buf` の範囲内にのみ書く。
    let rc = unsafe { fstatfs(fd.as_raw_fd(), &raw mut buf) };
    if rc == -1 {
        return Err(last_error());
    }
    Ok(buf.f_type)
}

/// CORE-3: cgroup2 の `statfs.f_type` 定数（`CGROUP2_SUPER_MAGIC`）。
pub(crate) const CGROUP2_MAGIC: i64 = consts::CGROUP2_SUPER_MAGIC;

/// glibc の `gnu_dev_makedev` と同じビット配置で `dev_t` を作る純関数（`unsafe` なし）。
pub(crate) const fn makedev(major: u32, minor: u32) -> u64 {
    let (major, minor) = (major as u64, minor as u64);
    ((major & 0xfff) << 8) | (minor & 0xff) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32)
}

/// `dir` 配下に文字デバイスノード `name`（1 要素の名前）を `mknodat(2)` で作る。モードは
/// `S_IFCHR | mode` だが umask で削られ得るため、呼び出し側が作成後に補正する。既存のエントリが
/// あれば `EEXIST`（上書きしない。最終要素の symlink も辿らない）。非特権 user namespace では
/// `EPERM`（`CAP_MKNOD` が init user namespace でしか効かないため）。
// テストビルドでは `crate::exec` の dry-run 差し込み点が本関数を呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn make_char_device(
    dir: BorrowedFd<'_>,
    name: &CStr,
    mode: u32,
    major: u32,
    minor: u32,
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `name` は `&CStr` の借用で NUL 終端かつ呼び出しの間生存する。`dir` は生存中の
    // `BorrowedFd`（O_PATH fd も dirfd として有効）。ポインタ以外の副作用は `dir` 配下の
    // ノード作成だけで、`name` は呼び出し側が 1 要素の静的名を渡す契約（`/` を含まない）。
    let rc = unsafe {
        mknodat(
            dir.as_raw_fd(),
            name.as_ptr(),
            consts::S_IFCHR | (mode & 0o7777),
            makedev(major, minor),
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `SIGPIPE` の disposition を `SIG_DFL` に戻す。Rust ランタイムは起動時に `SIGPIPE` を無視へ
/// するが、無視の disposition は `execve` を越えて継承されるため、コンテナ内プロセスへ持ち込まない。
// テストビルドでは dry-run 差し込み点が本関数を呼ばない（libtest のプロセスの disposition を
// 変えないため）ので、dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn reset_sigpipe_default() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数（`SIG_DFL` = 0）のみでポインタを取らない。ハンドラ関数を登録しない
    // ため、シグナルハンドラの再入・非同期安全性の問題は生じない。
    let prev = unsafe { signal(consts::SIGPIPE, SIG_DFL) };
    if prev == SIG_ERR {
        Err(last_error())
    } else {
        Ok(())
    }
}

/// `signal(2)` の `SIG_DFL`（既定動作）と `SIG_ERR`（失敗）。`sighandler_t` はポインタ幅。
const SIG_DFL: usize = 0;
const SIG_ERR: usize = usize::MAX;

/// [`kill_pid`] が送るシグナル（生の番号を crate 外へ出さない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Signal {
    /// `SIGKILL`。
    Kill,
}

/// `pid` を `waitpid` / `kill` に渡せる正の `i32` に変換する。0（自プロセスグループ）と
/// `i32` を超える値（負の pid になり、プロセスグループ・全プロセス宛てを意味し得る）は
/// `EINVAL` で拒否する（`kill(-1, SIGKILL)` の事故防止）。
fn positive_pid(pid: u32) -> Result<i32, SysError> {
    match i32::try_from(pid) {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(SysError::Os(EINVAL)),
    }
}

/// 子 `pid` を `waitpid(WNOHANG)` で回収する。まだ生きていれば `Ok(None)`、回収できれば wait
/// status（`decode_wait_status` 用の生の値）を返す。`EINTR` は呼び出し側が再試行する。
pub(crate) fn wait_pid_nohang(pid: u32) -> Result<Option<i32>, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let raw = positive_pid(pid)?;
    let mut status: i32 = 0;
    // SAFETY: `status` は呼び出しの間生存するスタック上の i32 への有効な書き込み先。`raw` は
    // 正であることを確認済みで、特定の子 1 つだけが対象になる（-1 や 0 を渡さない）。
    let rc = unsafe { waitpid(raw, &mut status, consts::WNOHANG) };
    match rc {
        -1 => Err(last_error()),
        0 => Ok(None),
        r if r == raw => Ok(Some(status)),
        _ => Err(SysError::Os(EINVAL)),
    }
}

/// 子 `pid` へシグナルを送る。`pid` は正であることを確認してから渡す。
///
/// 回収済みの pid は別プロセスへ再利用され得るため、呼び出し側は `pid` が未回収の自分の子で
/// あることを保証する（`crate::exec::ContainerChild` が回収状態のロック下でのみ呼ぶ。CORE-1）。
pub(crate) fn kill_pid(pid: u32, sig: Signal) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let raw = positive_pid(pid)?;
    let number = match sig {
        Signal::Kill => consts::SIGKILL,
    };
    // SAFETY: 引数は整数のみでポインタを取らない。`raw` は正であることを確認済みで、
    // プロセスグループ・全プロセス宛て（0・負値）にならない。
    let rc = unsafe { kill(raw, number) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// 呼び出したスレッドに `PR_SET_NO_NEW_PRIVS` を立てる（CORE-1・TASK-27.4.3・#833）。
///
/// `crate::exec` の固定ステージ `no_new_privs` だけが呼ぶ。フラグはスレッド単位で、fork・clone・
/// execve を越えて継承され、解除できない。arg3〜5 が 0 でないとカーネルは `EINVAL` を返す。
pub(crate) fn set_no_new_privs() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみでポインタを渡さない。可変長部は `unsigned long` に合わせて u64 の 0 を
    // 4 つ渡す（arg2 = 1 で有効化）。呼び出したスレッドのフラグを立てるだけでメモリには触れない。
    let rc = unsafe { prctl(consts::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// 呼び出したスレッドの `NO_NEW_PRIVS` が立っているかを返す（`PR_GET_NO_NEW_PRIVS`）。
pub(crate) fn no_new_privs_enabled() -> Result<bool, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみでポインタを渡さない。arg2〜5 はすべて 0 でなければカーネルが `EINVAL`
    // を返す。読み取りだけで状態を変えない。
    let rc = unsafe { prctl(consts::PR_GET_NO_NEW_PRIVS, 0u64, 0u64, 0u64, 0u64) };
    match rc {
        -1 => Err(last_error()),
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SysError::Os(EINVAL)),
    }
}

/// 自プロセスの実効 uid。
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: 引数なし・常に成功する副作用のない syscall。
    unsafe { geteuid() }
}

/// 自プロセスの実効 gid。
pub(crate) fn effective_gid() -> u32 {
    // SAFETY: 引数なし・常に成功する副作用のない syscall。
    unsafe { getegid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd as _;

    /// CORE-3・TASK-32.1: cgroup 操作用の定数・`statfs` バッファの具体値。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core3_task32_1_cgroup_consts_are_exact() {
        assert_eq!((consts::O_RDONLY, consts::O_WRONLY), (0, 1));
        assert_eq!(consts::AT_REMOVEDIR, 0x200);
        assert_eq!((EBUSY, ENOTEMPTY), (16, 39));
        assert_eq!(consts::CGROUP2_SUPER_MAGIC, 0x6367_7270);
        assert_eq!(std::mem::size_of::<StatFs>(), 120);
    }

    /// CORE-3・TASK-32.1: `/proc` が procfs と判定され、cgroup2 とは区別されること。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core3_task32_1_fs_type_identifies_procfs_not_cgroup2() {
        let proc_dir = std::fs::File::open("/proc").unwrap();
        // procfs の PROC_SUPER_MAGIC（include/uapi/linux/magic.h）。
        assert_eq!(fs_type(proc_dir.as_fd()), Ok(0x9fa0));
        assert_ne!(fs_type(proc_dir.as_fd()), Ok(CGROUP2_MAGIC));
    }

    /// CORE-3・TASK-32.1: `mkdir_at` / `remove_dir_at` / `open_*_at` の往復（一時ディレクトリ）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core3_task32_1_mkdir_open_remove_roundtrip() {
        use std::io::Write as _;
        let base = std::env::temp_dir().join(format!("fc-sys-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let dir = std::fs::File::open(&base).unwrap();
        let name = CString::new("child").unwrap();
        assert_eq!(mkdir_at(dir.as_fd(), &name, 0o755), Ok(()));
        assert_eq!(
            mkdir_at(dir.as_fd(), &name, 0o755),
            Err(SysError::Os(EEXIST))
        );
        std::fs::write(base.join("f"), b"x").unwrap();
        let f = CString::new("f").unwrap();
        let mut w = std::fs::File::from(open_write_at(dir.as_fd(), &f).unwrap());
        w.write_all(b"y").unwrap();
        let missing = CString::new("nope").unwrap();
        assert_eq!(
            open_read_at(dir.as_fd(), &missing).err(),
            Some(SysError::Os(ENOENT))
        );
        assert_eq!(remove_dir_at(dir.as_fd(), &name), Ok(()));
        assert_eq!(remove_dir_at(dir.as_fd(), &name), Err(SysError::Os(ENOENT)));
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// CORE-1・TASK-27.4.3: `prctl` オプションの具体値（include/uapi/linux/prctl.h）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core1_prctl_no_new_privs_consts_are_exact() {
        assert_eq!(consts::PR_SET_NO_NEW_PRIVS, 38);
        assert_eq!(consts::PR_GET_NO_NEW_PRIVS, 39);
    }

    /// CORE-1・TASK-27.4.3: 専用スレッドで set し、GET と /proc の値で確認する（冪等）。
    /// フラグはスレッド単位なので、libtest の他スレッドに影響を残さないよう使い捨てスレッドで行う。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core1_set_no_new_privs_sets_calling_thread_flag() {
        std::thread::spawn(|| {
            // 親から継承している場合があるため、設定前の値は assert しない。
            let _before = no_new_privs_enabled();
            assert_eq!(set_no_new_privs(), Ok(()));
            assert_eq!(no_new_privs_enabled(), Ok(true));
            let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
            assert!(status.lines().any(|l| l == "NoNewPrivs:\t1"), "{status}");
            assert_eq!(set_no_new_privs(), Ok(()));
        })
        .join()
        .unwrap();
    }

    /// CORE-1: フラグの具体値（Linux の CLONE_NEW* 定義）。
    #[test]
    fn core1_ns_flag_bits_are_exact() {
        assert_eq!(NsFlag::Mount.bits(), 0x0002_0000);
        assert_eq!(NsFlag::Uts.bits(), 0x0400_0000);
        assert_eq!(NsFlag::Ipc.bits(), 0x0800_0000);
        assert_eq!(NsFlag::User.bits(), 0x1000_0000);
        assert_eq!(NsFlag::Pid.bits(), 0x2000_0000);
    }

    /// x86_64: open フラグ・errno は asm-generic の値（include/uapi/asm-generic/fcntl.h・
    /// errno-base.h・errno.h）。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn core1_open_flags_and_errno_are_exact_x86_64() {
        assert_eq!(consts::O_DIRECTORY, 0o200_000);
        assert_eq!(consts::O_NOFOLLOW, 0o400_000);
        assert_eq!(consts::O_CLOEXEC, 0o2_000_000);
        assert_eq!(consts::O_PATH, 0o10_000_000);
        assert_eq!(open_dir_path_flags(), 0o12_600_000);
        assert_eq!(
            (EPERM, ENOENT, EACCES, ENOTDIR, EINVAL, ELOOP),
            (1, 2, 13, 20, 22, 40)
        );
    }

    /// CORE-1（TASK-27.3）: mount 系フラグ・pivot_root の syscall 番号の具体値。番号は arch ごとに
    /// 違う（x86_64 = 155、aarch64 = 41）。
    #[test]
    fn core1_pivot_consts_are_exact() {
        assert_eq!(consts::MS_BIND, 0x1000);
        assert_eq!(consts::MS_REC, 0x4000);
        assert_eq!(consts::MNT_DETACH, 2);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(consts::SYS_PIVOT_ROOT, 155);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(consts::SYS_PIVOT_ROOT, 41);
    }

    /// aarch64: O_DIRECTORY / O_NOFOLLOW は arch/arm64/include/uapi/asm/fcntl.h の上書き値
    /// （asm-generic の 0o200000 / 0o400000 は arm64 では O_DIRECT / O_LARGEFILE）。
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn core1_open_flags_and_errno_are_exact_aarch64() {
        assert_eq!(consts::O_DIRECTORY, 0o40_000);
        assert_eq!(consts::O_NOFOLLOW, 0o100_000);
        assert_eq!(consts::O_CLOEXEC, 0o2_000_000);
        assert_eq!(consts::O_PATH, 0o10_000_000);
        assert_eq!(open_dir_path_flags(), 0o12_140_000);
        assert_eq!(
            (EPERM, ENOENT, EACCES, ENOTDIR, EINVAL, ELOOP),
            (1, 2, 13, 20, 22, 40)
        );
    }

    /// CORE-1（TASK-27.4.1）: fork / exec / wait 系の定数の具体値。syscall 番号・フラグ・シグナル番号は
    /// arch ごとに個別定義する（x86_64 = syscall_64.tbl、aarch64 = asm-generic/unistd.h）。
    #[test]
    fn core1_fork_exec_consts_are_exact() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(consts::SYS_EXECVEAT, 322);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(consts::SYS_EXECVEAT, 281);
        assert_eq!(consts::AT_EMPTY_PATH, 0x1000);
        assert_eq!(consts::O_NONBLOCK, 0o4_000);
        assert_eq!(consts::O_RDWR, 2);
        assert_eq!((consts::F_SETFD, consts::FD_CLOEXEC), (2, 1));
        assert_eq!(consts::F_DUPFD_CLOEXEC, 1030);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(consts::SYS_CLOSE_RANGE, 436);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(consts::SYS_CLOSE_RANGE, 436);
        assert_eq!(consts::CLOSE_RANGE_CLOEXEC, 4);
        assert_eq!(consts::WNOHANG, 1);
        assert_eq!((consts::SIGKILL, consts::SIGPIPE), (9, 13));
        assert_eq!(
            (ESRCH, EINTR, E2BIG, ENOEXEC, EBADF, ENOSYS),
            (3, 4, 7, 8, 9, 38)
        );
    }

    /// CORE-1（TASK-27.4.1）: `Threads:` が 1 のときだけ fork を許す（それ以外・解釈不能は拒否）。
    #[test]
    fn core1_threads_is_one_is_fail_closed() {
        assert!(threads_is_one("Name:\tx\nThreads:\t1\nVmRSS:\t1 kB\n"));
        assert!(!threads_is_one("Name:\tx\nThreads:\t2\n"));
        assert!(!threads_is_one("Name:\tx\n"));
        assert!(!threads_is_one("Threads:\tmany\n"));
        assert!(!threads_is_one(""));
    }

    /// CORE-1（TASK-27.4.1）: libtest はマルチスレッドなので、fork は子を作らず `MultiThreaded` で拒否する。
    #[test]
    fn core1_fork_is_refused_when_multithreaded() {
        // 別スレッドを 1 つ生かした状態で試す（libtest 本体のスレッドも存在する）。
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        let err = fork_single_threaded(|| 0, 125).unwrap_err();
        assert_eq!(err, SysError::MultiThreaded);
        tx.send(()).unwrap();
        helper.join().unwrap();
    }

    /// CORE-1（TASK-27.4.1）: `execve` の引数配列は要素数 + 1 の NULL 終端。
    #[test]
    fn core1_null_terminated_ptrs_ends_with_null() {
        let items = [CString::new("a").unwrap(), CString::new("bc").unwrap()];
        let ptrs = null_terminated_ptrs(&items);
        assert_eq!(ptrs.len(), 3);
        assert_eq!(ptrs[0], items[0].as_ptr());
        assert_eq!(ptrs[1], items[1].as_ptr());
        assert!(ptrs[2].is_null());
        let empty = null_terminated_ptrs(&[]);
        assert_eq!(empty.len(), 1);
        assert!(empty[0].is_null());
    }

    /// CORE-1（TASK-27.4.1）: `dup_fd_at_least` は下限以上の番号へ close-on-exec で複製し、負の下限は
    /// `EINVAL` で拒否する。
    #[test]
    fn core1_dup_fd_at_least_respects_minimum() {
        let file = std::fs::File::open("/proc/self/status").unwrap();
        for min in [3, 64] {
            let dup = dup_fd_at_least(file.as_fd(), min).unwrap();
            assert!(dup.as_raw_fd() >= min, "min {min}: got {}", dup.as_raw_fd());
            // close-on-exec は fdinfo の flags（8 進）の O_CLOEXEC ビットで確かめる。
            let info =
                std::fs::read_to_string(format!("/proc/self/fdinfo/{}", dup.as_raw_fd())).unwrap();
            let flags = info
                .lines()
                .find_map(|l| l.strip_prefix("flags:"))
                .map(|v| i32::from_str_radix(v.trim(), 8).unwrap())
                .unwrap();
            assert_eq!(flags & consts::O_CLOEXEC, consts::O_CLOEXEC, "min {min}");
        }
        assert_eq!(
            dup_fd_at_least(file.as_fd(), -1).unwrap_err(),
            SysError::Os(EINVAL)
        );
    }

    /// CORE-1（TASK-27.4.1）: 0 とプロセスグループ・全プロセス宛てになり得る値の pid は拒否する。
    #[test]
    fn core1_positive_pid_rejects_zero_and_overflow() {
        assert_eq!(positive_pid(1), Ok(1));
        assert_eq!(positive_pid(i32::MAX as u32), Ok(i32::MAX));
        assert_eq!(positive_pid(0), Err(SysError::Os(EINVAL)));
        assert_eq!(positive_pid(i32::MAX as u32 + 1), Err(SysError::Os(EINVAL)));
        assert_eq!(positive_pid(u32::MAX), Err(SysError::Os(EINVAL)));
        assert_eq!(wait_pid_nohang(0), Err(SysError::Os(EINVAL)));
        assert_eq!(kill_pid(u32::MAX, Signal::Kill), Err(SysError::Os(EINVAL)));
    }

    /// テスト用の一時ディレクトリ（`chmod` で絞ったディレクトリを戻してから削除する）。
    struct TempTree {
        base: std::path::PathBuf,
        restore: Vec<std::path::PathBuf>,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let base = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("fandhe-sys-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(&base).unwrap();
            Self {
                base,
                restore: Vec::new(),
            }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            for p in &self.restore {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
            }
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn c(path: &std::path::Path) -> std::ffi::CString {
        use std::os::unix::ffi::OsStrExt as _;
        std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    /// fdinfo の `flags:`（八進）。
    fn fd_flags(fd: &OwnedFd) -> i32 {
        let info =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
        let v = info.lines().find_map(|l| l.strip_prefix("flags:")).unwrap();
        i32::from_str_radix(v.trim(), 8).unwrap()
    }

    /// CORE-1: symlink（ディレクトリを指すもの・宙吊りのもの）と非ディレクトリは `ENOTDIR`、
    /// 不在は `ENOENT` で拒否し、ディレクトリは O_PATH fd として開く。
    #[test]
    fn core1_open_dir_path_nofollow_rejects_symlink_and_non_dir() {
        let t = TempTree::new("nofollow");
        std::fs::create_dir(t.base.join("dir")).unwrap();
        std::fs::write(t.base.join("file"), b"").unwrap();
        std::os::unix::fs::symlink(t.base.join("dir"), t.base.join("link")).unwrap();
        std::os::unix::fs::symlink("/nonexistent", t.base.join("dangling")).unwrap();
        let parent = open_dir_path_nofollow(None, &c(&t.base)).unwrap();
        for (name, want) in [
            (c"link", ENOTDIR),
            (c"dangling", ENOTDIR),
            (c"file", ENOTDIR),
            (c"missing", ENOENT),
        ] {
            let err = open_dir_path_nofollow(Some(parent.as_fd()), name).unwrap_err();
            assert_eq!(err, SysError::Os(want), "{name:?}");
        }
        let dir = open_dir_path_nofollow(Some(parent.as_fd()), c"dir").unwrap();
        assert_eq!(
            std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd())).unwrap(),
            t.base.join("dir")
        );
        assert_eq!(fd_flags(&dir) & consts::O_PATH, consts::O_PATH);
    }

    /// CORE-1（Cursor Bugbot 指摘の回帰）: 実行権限のみ（読み取り不可）のディレクトリを
    /// 起点・経由として辿れる。root では DAC を迂回するため判別力はないが失敗もしない。
    #[test]
    fn core1_open_dir_path_nofollow_traverses_execute_only_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        let mut t = TempTree::new("xonly");
        let xonly = t.base.join("xonly");
        std::fs::create_dir_all(xonly.join("inner")).unwrap();
        std::fs::set_permissions(&xonly, std::fs::Permissions::from_mode(0o100)).unwrap();
        t.restore.push(xonly.clone());
        if effective_uid() != 0 {
            // 前提の確認: 読み取りで開く従来の方式ではこのディレクトリを開けない。
            let err = std::fs::read_dir(&xonly).unwrap_err();
            assert_eq!(err.raw_os_error(), Some(EACCES));
        }
        let fd = open_dir_path_nofollow(None, &c(&xonly)).unwrap();
        let inner = open_dir_path_nofollow(Some(fd.as_fd()), c"inner").unwrap();
        assert_eq!(
            std::fs::read_link(format!("/proc/self/fd/{}", inner.as_raw_fd())).unwrap(),
            xonly.join("inner")
        );
    }

    /// CORE-1（TASK-27.6）: 文字デバイス種別・EEXIST の具体値と `makedev` のビット配置
    /// （glibc の `gnu_dev_makedev`）。
    #[test]
    fn core1_device_consts_and_makedev_are_exact() {
        assert_eq!(consts::S_IFCHR, 0o020_000);
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert_eq!(EEXIST, 17);
        assert_eq!(makedev(1, 3), 0x103);
        assert_eq!(makedev(1, 5), 0x105);
        assert_eq!(makedev(1, 7), 0x107);
        assert_eq!(makedev(1, 8), 0x108);
        assert_eq!(makedev(1, 9), 0x109);
        assert_eq!(makedev(5, 0), 0x500);
        assert_eq!(makedev(0x1000, 0x100), 0x1000_0000_0000 | 0x10_0000);
    }

    /// CORE-1（TASK-27.6）: `open_path_nofollow` は symlink を辿らずそれ自体を開き、通常ファイルも
    /// 開ける。不在は ENOENT。
    #[test]
    fn core1_open_path_nofollow_does_not_follow_symlink() {
        use std::os::unix::fs::MetadataExt as _;
        let t = TempTree::new("pathnf");
        std::fs::write(t.base.join("file"), b"x").unwrap();
        std::os::unix::fs::symlink("/nonexistent", t.base.join("link")).unwrap();
        let parent = open_dir_path_nofollow(None, &c(&t.base)).unwrap();
        let link = open_path_nofollow(parent.as_fd(), c"link").unwrap();
        let meta = std::fs::File::from(link).metadata().unwrap();
        assert!(meta.file_type().is_symlink());
        let file = open_path_nofollow(parent.as_fd(), c"file").unwrap();
        assert_eq!(std::fs::File::from(file).metadata().unwrap().size(), 1);
        assert_eq!(
            open_path_nofollow(parent.as_fd(), c"missing").unwrap_err(),
            SysError::Os(ENOENT)
        );
    }

    /// geteuid は `/proc/self/status` の実効 uid と一致する。
    #[test]
    fn effective_uid_matches_proc_status() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = status.lines().find(|l| l.starts_with("Uid:")).unwrap();
        let euid: u32 = line.split_whitespace().nth(2).unwrap().parse().unwrap();
        assert_eq!(effective_uid(), euid);
    }
}
