//! namespace 分離に使う syscall・FFI の薄いラッパー（`crates/core` の `sys` モジュール。
//! `unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・オーナー決定
//! 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::exec::isolate`・`crate::exec::MountIsolation::establish`・`crate::exec::mount_proc`
//! （CORE-1・TASK-27.2・#134）と、`crate::exec::prepare_rootfs`・`crate::exec::pivot_root`
//! （CORE-1・TASK-27.3・#135）と、`crate::exec::create_default_devices`（CORE-1・TASK-27.6・#834）が、
//! `unshare(2)`・`sethostname(2)`・`mount(2)`・`openat(2)`・`geteuid(2)`・`getegid(2)` に加え、
//! `pivot_root(2)`（glibc がラッパーを持たないため `syscall(2)` 経由）・`umount2(2)`・`fchdir(2)`
//! を呼ぶために使う。さらに fork / exec 段（CORE-1・TASK-27.4.1・#831）の `crate::exec::spawn_container`・
//! `crate::exec::exec_entrypoint`・`crate::exec::ContainerChild` が、`fork(2)`・`_exit(2)`・`execveat(2)`・
//! `waitpid(2)`・`kill(2)`・`pidfd_open(2)` / `pidfd_send_signal(2)`（回収後の pid 再利用対策）・`signal(2)` と `close_range(2)`（`syscall(2)` 経由）を呼ぶために使う。
//! `kill(2)` は `crate::oci_runtime::kill`（CORE-2・OCI-6・TASK-30.1）が `ContainerChild::send_signal`
//! 経由で任意番号（1..=64 検証済み）を送る経路でも使う。
//! さらに固定ステージ `crate::exec::no_new_privs`（CORE-1・TASK-27.4.3・#833）が `prctl(2)` を呼ぶ。
//! さらに `exec/capabilities.rs` の `apply_default_capabilities`（SEC-1・TASK-37.1・#172）が `capget(2)`・`capset(2)`
//! （`syscall(2)` 経由）と `prctl(2)` の capability 系オプションを呼ぶ（スレッド単位の操作で、
//! `fork_single_threaded` による単一スレッドの子で呼ぶ前提）。
//! さらに `crate::exec::seccomp` の `apply_seccomp_filter`（CORE-5・TASK-38.2・#177）が
//! `prctl(PR_SET_SECCOMP)` / `prctl(PR_GET_SECCOMP)` を呼ぶ（呼び出したスレッドへのフィルタ追加。不可逆）。
//! さらに `crate::landlock::detect_landlock_abi`（CORE-5・TASK-39.1・#181）が `landlock_create_ruleset(2)`
//! （`syscall(2)` 経由。ABI バージョン問い合わせのみ）を呼ぶ。
//! さらに `crate::landlock::apply_landlock_ruleset`（CORE-5・TASK-39.3・#183）が `landlock_create_ruleset(2)`・
//! `landlock_add_rule(2)`・`landlock_restrict_self(2)`（いずれも `syscall(2)` 経由）を呼ぶ
//! （restrict は呼び出したスレッドへの不可逆な適用）。
//! さらに `crate::exec` の結合試験用プローブ（CORE-5・TASK-38.4・#179）が、副作用の無い引数に固定した
//! `ptrace(2)`・`kexec_load(2)`（`syscall(2)` 経由）を呼ぶ。
//! 基本デバイスノード作成は、`mknodat(2)`・`O_PATH` での `openat(2)` を呼ぶために使う。
//! 委譲 cgroup の検出と子 cgroup 作成（`crate::cgroups`。CORE-3・TASK-32.1・#158）は、
//! `mkdirat(2)`・`unlinkat(2)`・`fstatfs(2)`（cgroup2 判定）と `O_NOFOLLOW` 付きの `openat(2)` を呼ぶために使う。
//! rlimit の適用（`exec/rlimits.rs` の `apply_rlimits`。SUP-12・TASK-169.1・#526）は、fork 後の子で `prlimit(2)` を呼ぶために使う。
//! さらに `crate::audit_log` のカーネル監査フォールバック（SEC-4・TASK-41.5.2・#840）が、
//! `socket(2)`（NETLINK_AUDIT）・`sendto(2)`・`recvfrom(2)`・`poll(2)` を呼ぶ。
//! std だけでは提供されない syscall のみを持ち、検証（hostname の文字種・パス形式等）は呼び出し側の型
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

use crate::seccomp::{BpfInstruction, SeccompProgram};
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
    E2BIG, EACCES, EAFNOSUPPORT, EBADF, EBUSY, ECHILD, ECONNREFUSED, EEXIST, EINTR, EINVAL, ELOOP,
    ENOENT, ENOEXEC, ENOSYS, ENOTDIR, ENOTEMPTY, EOPNOTSUPP, EPERM, EPROTONOSUPPORT, ESRCH,
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
    pub const CLONE_NEWNET: i32 = 0x4000_0000;
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
    // arch/x86/entry/syscalls/syscall_64.tbl の `pidfd_send_signal`（424）・`pidfd_open`（434）。
    pub const SYS_PIDFD_SEND_SIGNAL: i64 = 424;
    pub const SYS_PIDFD_OPEN: i64 = 434;
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
    // arch/x86/entry/syscalls/syscall_64.tbl の `landlock_create_ruleset`（444）。
    pub const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
    // include/uapi/linux/landlock.h の `LANDLOCK_CREATE_RULESET_VERSION`（`1U << 0`）。
    pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    // arch/x86/entry/syscalls/syscall_64.tbl の `landlock_add_rule`（445）・`landlock_restrict_self`（446）。
    pub const SYS_LANDLOCK_ADD_RULE: i64 = 445;
    pub const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;
    // include/uapi/linux/landlock.h の `enum landlock_rule_type` の `LANDLOCK_RULE_PATH_BENEATH`。
    pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
    // include/uapi/asm-generic/errno.h の `EOPNOTSUPP`（x86_64 は上書きしない）。
    pub const EOPNOTSUPP: i32 = 95;
    pub const ELOOP: i32 = 40;
    // errno-base.h / errno.h の ESRCH・EINTR・E2BIG・ENOEXEC・EBADF・ENOSYS。
    pub const ESRCH: i32 = 3;
    // errno-base.h の ECHILD（回収対象の子が無い。既に回収済み）。
    pub const ECHILD: i32 = 10;
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

    // include/uapi/asm-generic/resource.h の `RLIMIT_*`（0〜15。SUP-12・TASK-169.1）。
    // 全アーキテクチャ共通の定義だが、他アーキテクチャの定義を流用しないため個別に持つ。
    pub const RLIMIT_CPU: i32 = 0;
    pub const RLIMIT_FSIZE: i32 = 1;
    pub const RLIMIT_DATA: i32 = 2;
    pub const RLIMIT_STACK: i32 = 3;
    pub const RLIMIT_CORE: i32 = 4;
    pub const RLIMIT_RSS: i32 = 5;
    pub const RLIMIT_NPROC: i32 = 6;
    pub const RLIMIT_NOFILE: i32 = 7;
    pub const RLIMIT_MEMLOCK: i32 = 8;
    pub const RLIMIT_AS: i32 = 9;
    pub const RLIMIT_LOCKS: i32 = 10;
    pub const RLIMIT_SIGPENDING: i32 = 11;
    pub const RLIMIT_MSGQUEUE: i32 = 12;
    pub const RLIMIT_NICE: i32 = 13;
    pub const RLIMIT_RTPRIO: i32 = 14;
    pub const RLIMIT_RTTIME: i32 = 15;

    // include/uapi/linux/prctl.h の `PR_GET_SECCOMP`（21）・`PR_SET_SECCOMP`（22）と
    // include/uapi/linux/seccomp.h の `SECCOMP_MODE_FILTER`（2。可変長引数で渡すため u64）。
    pub const PR_GET_SECCOMP: i32 = 21;
    pub const PR_SET_SECCOMP: i32 = 22;
    pub const SECCOMP_MODE_FILTER: u64 = 2;

    // capability 操作（TASK-37.1・#172）。`SYS_CAPGET` / `SYS_CAPSET` は glibc がラッパーを
    // 公開しないため `syscall(2)` 経由で呼ぶ。出典: x86_64 は arch/x86/entry/syscalls/syscall_64.tbl、
    // aarch64 は include/uapi/asm-generic/unistd.h。
    pub const SYS_CAPGET: i64 = 125;
    pub const SYS_CAPSET: i64 = 126;
    // 禁止 syscall 遮断の結合試験用プローブ（CORE-5・TASK-38.4・#179）。番号は `crate::seccomp` の
    // テーブルとは独立に、x86_64 は syscall_64.tbl、aarch64 は asm-generic/unistd.h から取る。
    // `PTRACE_CONT`（include/uapi/linux/ptrace.h）は attach を伴わない要求で、`KEXEC_SEGMENT_MAX`
    // （include/linux/kexec.h）は kexec_load の segment 数の上限。
    pub const SYS_PTRACE: i64 = 101;
    pub const SYS_KEXEC_LOAD: i64 = 246;
    pub const PTRACE_CONT: i64 = 7;
    pub const KEXEC_SEGMENT_MAX: i64 = 16;
    // include/uapi/linux/capability.h の `_LINUX_CAPABILITY_VERSION_3`（2 語・64 bit 形式）。
    pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    // include/uapi/linux/prctl.h の `PR_CAPBSET_READ`（23）・`PR_CAPBSET_DROP`（24）・
    // `PR_CAP_AMBIENT`（47）・`PR_CAP_AMBIENT_CLEAR_ALL`（4）。
    pub const PR_CAPBSET_READ: i32 = 23;
    pub const PR_CAPBSET_DROP: i32 = 24;
    pub const PR_CAP_AMBIENT: i32 = 47;
    pub const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;
    // include/linux/socket.h・uapi/linux/netlink.h・uapi/asm-generic/socket.h・poll.h・errno.h の値
    // （カーネル監査への NETLINK_AUDIT 送信用。TASK-41.5.2・#840。`SOCK_CLOEXEC` は `O_CLOEXEC` と同値）。
    pub const AF_NETLINK: u16 = 16;
    pub const SOCK_RAW: i32 = 3;
    pub const SOCK_CLOEXEC: i32 = 0o2_000_000;
    pub const NETLINK_AUDIT: i32 = 9;
    pub const POLLIN: i16 = 1;
    /// `MSG_DONTWAIT`（送信側を非ブロッキングにする。x86_64・aarch64 とも 0x40）。
    pub const MSG_DONTWAIT: i32 = 0x40;
    pub const EPROTONOSUPPORT: i32 = 93;
    pub const EAFNOSUPPORT: i32 = 97;
    pub const ECONNREFUSED: i32 = 111;
}

#[cfg(target_arch = "aarch64")]
mod consts {
    pub const SUPPORTED: bool = true;
    pub const CLONE_NEWNS: i32 = 0x0002_0000;
    pub const CLONE_NEWUTS: i32 = 0x0400_0000;
    pub const CLONE_NEWIPC: i32 = 0x0800_0000;
    pub const CLONE_NEWUSER: i32 = 0x1000_0000;
    pub const CLONE_NEWPID: i32 = 0x2000_0000;
    pub const CLONE_NEWNET: i32 = 0x4000_0000;
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
    // include/uapi/asm-generic/unistd.h の `__NR_pidfd_send_signal`・`__NR_pidfd_open`（arm64 は
    // asm-generic の表。x86_64 と値が同じでも流用せず個別に定義する）。
    pub const SYS_PIDFD_SEND_SIGNAL: i64 = 424;
    pub const SYS_PIDFD_OPEN: i64 = 434;
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
    // include/uapi/asm-generic/unistd.h の `__NR_landlock_create_ruleset`（444。arm64 は汎用表）。
    pub const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
    // include/uapi/linux/landlock.h の `LANDLOCK_CREATE_RULESET_VERSION`（`1U << 0`）。
    pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    // include/uapi/asm-generic/unistd.h の `landlock_add_rule`（445）・`landlock_restrict_self`（446）。
    pub const SYS_LANDLOCK_ADD_RULE: i64 = 445;
    pub const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;
    // include/uapi/linux/landlock.h の `enum landlock_rule_type` の `LANDLOCK_RULE_PATH_BENEATH`。
    pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
    // include/uapi/asm-generic/errno.h の `EOPNOTSUPP`（arm64 は上書きしない）。
    pub const EOPNOTSUPP: i32 = 95;
    pub const ELOOP: i32 = 40;
    // errno-base.h / errno.h の ESRCH・EINTR・E2BIG・ENOEXEC・EBADF・ENOSYS。
    pub const ESRCH: i32 = 3;
    // errno-base.h の ECHILD（回収対象の子が無い。既に回収済み）。
    pub const ECHILD: i32 = 10;
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

    // include/uapi/asm-generic/resource.h の `RLIMIT_*`（0〜15。SUP-12・TASK-169.1）。
    // 全アーキテクチャ共通の定義だが、他アーキテクチャの定義を流用しないため個別に持つ。
    pub const RLIMIT_CPU: i32 = 0;
    pub const RLIMIT_FSIZE: i32 = 1;
    pub const RLIMIT_DATA: i32 = 2;
    pub const RLIMIT_STACK: i32 = 3;
    pub const RLIMIT_CORE: i32 = 4;
    pub const RLIMIT_RSS: i32 = 5;
    pub const RLIMIT_NPROC: i32 = 6;
    pub const RLIMIT_NOFILE: i32 = 7;
    pub const RLIMIT_MEMLOCK: i32 = 8;
    pub const RLIMIT_AS: i32 = 9;
    pub const RLIMIT_LOCKS: i32 = 10;
    pub const RLIMIT_SIGPENDING: i32 = 11;
    pub const RLIMIT_MSGQUEUE: i32 = 12;
    pub const RLIMIT_NICE: i32 = 13;
    pub const RLIMIT_RTPRIO: i32 = 14;
    pub const RLIMIT_RTTIME: i32 = 15;

    // include/uapi/linux/prctl.h の `PR_GET_SECCOMP`（21）・`PR_SET_SECCOMP`（22）と
    // include/uapi/linux/seccomp.h の `SECCOMP_MODE_FILTER`（2。可変長引数で渡すため u64）。
    pub const PR_GET_SECCOMP: i32 = 21;
    pub const PR_SET_SECCOMP: i32 = 22;
    pub const SECCOMP_MODE_FILTER: u64 = 2;

    // capability 操作（TASK-37.1・#172）。`SYS_CAPGET` / `SYS_CAPSET` は glibc がラッパーを
    // 公開しないため `syscall(2)` 経由で呼ぶ。出典: x86_64 は arch/x86/entry/syscalls/syscall_64.tbl、
    // aarch64 は include/uapi/asm-generic/unistd.h。
    pub const SYS_CAPGET: i64 = 90;
    pub const SYS_CAPSET: i64 = 91;
    // 禁止 syscall 遮断の結合試験用プローブ（CORE-5・TASK-38.4・#179）。番号は `crate::seccomp` の
    // テーブルとは独立に、x86_64 は syscall_64.tbl、aarch64 は asm-generic/unistd.h から取る。
    // `PTRACE_CONT`（include/uapi/linux/ptrace.h）は attach を伴わない要求で、`KEXEC_SEGMENT_MAX`
    // （include/linux/kexec.h）は kexec_load の segment 数の上限。
    pub const SYS_PTRACE: i64 = 117;
    pub const SYS_KEXEC_LOAD: i64 = 104;
    pub const PTRACE_CONT: i64 = 7;
    pub const KEXEC_SEGMENT_MAX: i64 = 16;
    // include/uapi/linux/capability.h の `_LINUX_CAPABILITY_VERSION_3`（2 語・64 bit 形式）。
    pub const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    // include/uapi/linux/prctl.h の `PR_CAPBSET_READ`（23）・`PR_CAPBSET_DROP`（24）・
    // `PR_CAP_AMBIENT`（47）・`PR_CAP_AMBIENT_CLEAR_ALL`（4）。
    pub const PR_CAPBSET_READ: i32 = 23;
    pub const PR_CAPBSET_DROP: i32 = 24;
    pub const PR_CAP_AMBIENT: i32 = 47;
    pub const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;
    // include/linux/socket.h・uapi/linux/netlink.h・uapi/asm-generic/socket.h・poll.h・errno.h の値
    // （カーネル監査への NETLINK_AUDIT 送信用。TASK-41.5.2・#840。`SOCK_CLOEXEC` は `O_CLOEXEC` と同値）。
    pub const AF_NETLINK: u16 = 16;
    pub const SOCK_RAW: i32 = 3;
    pub const SOCK_CLOEXEC: i32 = 0o2_000_000;
    pub const NETLINK_AUDIT: i32 = 9;
    pub const POLLIN: i16 = 1;
    /// `MSG_DONTWAIT`（送信側を非ブロッキングにする。x86_64・aarch64 とも 0x40）。
    pub const MSG_DONTWAIT: i32 = 0x40;
    pub const EPROTONOSUPPORT: i32 = 93;
    pub const EAFNOSUPPORT: i32 = 97;
    pub const ECONNREFUSED: i32 = 111;
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
    pub const CLONE_NEWNET: i32 = 0;
    pub const MS_NOSUID: u64 = 0;
    pub const MS_NODEV: u64 = 0;
    pub const MS_NOEXEC: u64 = 0;
    pub const MS_BIND: u64 = 0;
    pub const MS_REC: u64 = 0;
    pub const MS_PRIVATE: u64 = 0;
    pub const MNT_DETACH: i32 = 0;
    pub const SYS_PIVOT_ROOT: i64 = 0;
    pub const SYS_CLOSE_RANGE: i64 = 0;
    pub const SYS_PIDFD_SEND_SIGNAL: i64 = 0;
    pub const SYS_PIDFD_OPEN: i64 = 0;
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
    pub const EBUSY: i32 = -16;
    pub const ENOTEMPTY: i32 = -17;
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
    pub const SYS_LANDLOCK_CREATE_RULESET: i64 = 0;
    pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 0;
    pub const SYS_LANDLOCK_ADD_RULE: i64 = 0;
    pub const SYS_LANDLOCK_RESTRICT_SELF: i64 = 0;
    pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 0;
    pub const EOPNOTSUPP: i32 = -15;
    pub const ELOOP: i32 = -6;
    pub const ESRCH: i32 = -8;
    pub const ECHILD: i32 = -14;
    pub const EINTR: i32 = -9;
    pub const E2BIG: i32 = -10;
    pub const ENOEXEC: i32 = -11;
    pub const ENOSYS: i32 = -12;
    pub const EBADF: i32 = -13;
    pub const S_IFCHR: u32 = 0;

    pub const PR_SET_NO_NEW_PRIVS: i32 = 0;
    pub const PR_GET_NO_NEW_PRIVS: i32 = 0;

    // rlimit の定数（対応外アーキテクチャでは各ラッパーが SUPPORTED で弾くため未使用）。
    pub const RLIMIT_CPU: i32 = 0;
    pub const RLIMIT_FSIZE: i32 = 0;
    pub const RLIMIT_DATA: i32 = 0;
    pub const RLIMIT_STACK: i32 = 0;
    pub const RLIMIT_CORE: i32 = 0;
    pub const RLIMIT_RSS: i32 = 0;
    pub const RLIMIT_NPROC: i32 = 0;
    pub const RLIMIT_NOFILE: i32 = 0;
    pub const RLIMIT_MEMLOCK: i32 = 0;
    pub const RLIMIT_AS: i32 = 0;
    pub const RLIMIT_LOCKS: i32 = 0;
    pub const RLIMIT_SIGPENDING: i32 = 0;
    pub const RLIMIT_MSGQUEUE: i32 = 0;
    pub const RLIMIT_NICE: i32 = 0;
    pub const RLIMIT_RTPRIO: i32 = 0;
    pub const RLIMIT_RTTIME: i32 = 0;

    // seccomp 適用の定数（対応外アーキテクチャでは各ラッパーが SUPPORTED で弾くため未使用）。
    pub const PR_GET_SECCOMP: i32 = 0;
    pub const PR_SET_SECCOMP: i32 = 0;
    pub const SECCOMP_MODE_FILTER: u64 = 0;

    // capability 操作（TASK-37.1・#172）。`SYS_CAPGET` / `SYS_CAPSET` は glibc がラッパーを
    // 公開しないため `syscall(2)` 経由で呼ぶ。出典: x86_64 は arch/x86/entry/syscalls/syscall_64.tbl、
    // aarch64 は include/uapi/asm-generic/unistd.h。
    pub const SYS_CAPGET: i64 = 0;
    pub const SYS_CAPSET: i64 = 0;
    // 禁止 syscall 遮断の結合試験用プローブ（CORE-5・TASK-38.4・#179）。番号は `crate::seccomp` の
    // テーブルとは独立に、x86_64 は syscall_64.tbl、aarch64 は asm-generic/unistd.h から取る。
    // `PTRACE_CONT`（include/uapi/linux/ptrace.h）は attach を伴わない要求で、`KEXEC_SEGMENT_MAX`
    // （include/linux/kexec.h）は kexec_load の segment 数の上限。
    pub const SYS_PTRACE: i64 = 0;
    pub const SYS_KEXEC_LOAD: i64 = 0;
    pub const PTRACE_CONT: i64 = 0;
    pub const KEXEC_SEGMENT_MAX: i64 = 0;
    // include/uapi/linux/capability.h の `_LINUX_CAPABILITY_VERSION_3`（2 語・64 bit 形式）。
    pub const LINUX_CAPABILITY_VERSION_3: u32 = 0;
    // include/uapi/linux/prctl.h の `PR_CAPBSET_READ`（23）・`PR_CAPBSET_DROP`（24）・
    // `PR_CAP_AMBIENT`（47）・`PR_CAP_AMBIENT_CLEAR_ALL`（4）。
    pub const PR_CAPBSET_READ: i32 = 0;
    pub const PR_CAPBSET_DROP: i32 = 0;
    pub const PR_CAP_AMBIENT: i32 = 0;
    pub const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 0;
    pub const AF_NETLINK: u16 = 0;
    pub const SOCK_RAW: i32 = 0;
    pub const SOCK_CLOEXEC: i32 = 0;
    pub const NETLINK_AUDIT: i32 = 0;
    pub const POLLIN: i16 = 0;
    pub const MSG_DONTWAIT: i32 = 0;
    pub const EPROTONOSUPPORT: i32 = -22;
    pub const EAFNOSUPPORT: i32 = -23;
    pub const ECONNREFUSED: i32 = -24;
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
    /// network namespace。`setns(2)` による参加（SUP-6・TASK-163.1）専用で、`unshare` 経路は使わない。
    Net,
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
            Self::Net => consts::CLONE_NEWNET,
        }
    }
}

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: glibc 2.14+ / musl の `int setns(int fd, int nstype)` と同じ型幅
    // （SUP-6・TASK-163.1）。`syscall(2)` 経由にせず arch 別の syscall 番号を増やさない。
    fn setns(fd: i32, nstype: i32) -> i32;
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
    // SAFETY（宣言そのものの妥当性）: `int socket(int domain, int type, int protocol)`。
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `ssize_t sendto(int fd, const void *buf, size_t len, int flags,
    // const struct sockaddr *addr, socklen_t addrlen)`（LP64 で `ssize_t` は i64・`socklen_t` は u32）。
    fn sendto(
        fd: i32,
        buf: *const core::ffi::c_void,
        len: usize,
        flags: i32,
        addr: *const SockaddrNl,
        addrlen: u32,
    ) -> isize;
    // SAFETY（宣言そのものの妥当性）: `ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
    // struct sockaddr *addr, socklen_t *addrlen)`。
    fn recvfrom(
        fd: i32,
        buf: *mut core::ffi::c_void,
        len: usize,
        flags: i32,
        addr: *mut SockaddrNl,
        addrlen: *mut u32,
    ) -> isize;
    // SAFETY（宣言そのものの妥当性）: `int poll(struct pollfd *fds, nfds_t nfds, int timeout)`
    // （`nfds_t` は `unsigned long`＝LP64 で u64）。
    fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int prlimit(pid_t pid, int resource, const struct rlimit64 *new_limit,
    // struct rlimit64 *old_limit)`（glibc 2.13 以降・musl。LP64 の `pid_t` は i32、`resource` は
    // `enum __rlimit_resource` 相当で `int` 幅）。構造体は下の [`RLimit64`]（`rlim64_t` = u64 × 2）。
    fn prlimit(
        pid: i32,
        resource: i32,
        new_limit: *const RLimit64,
        old_limit: *mut RLimit64,
    ) -> i32;
}

/// `struct rlimit64`（`rlim_cur` / `rlim_max` ともに 64 ビット。全アーキテクチャ共通の 16 バイト）。
#[repr(C)]
#[derive(Clone, Copy)]
struct RLimit64 {
    cur: u64,
    max: u64,
}

/// `struct sockaddr_nl`（include/uapi/linux/netlink.h。全アーキテクチャ共通の 12 バイト）。
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

/// `struct pollfd`（include/uapi/asm-generic/poll.h。全アーキテクチャ共通の 8 バイト）。
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
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

/// カーネル監査（NETLINK_AUDIT）用のソケットを開く（`SOCK_RAW|SOCK_CLOEXEC`。TASK-41.5.2・#840）。
///
/// `crate::audit_log` のカーネル監査フォールバックが呼び出しごとに開閉する。socket 作成自体は
/// 非特権でも通る（権限検査は送信先のカーネルが `audit_netlink_ok` で行う）。
pub(crate) fn netlink_audit_socket() -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数はすべて値渡しの整数でポインタを取らない。成功時の戻り値は新規 fd で、直後に
    // `OwnedFd` が唯一の所有者となる（二重 close なし）。
    let fd = unsafe {
        socket(
            i32::from(consts::AF_NETLINK),
            consts::SOCK_RAW | consts::SOCK_CLOEXEC,
            consts::NETLINK_AUDIT,
        )
    };
    if fd < 0 {
        return Err(last_error());
    }
    // SAFETY: `fd` は上で成功した socket が返した、他に所有者のいない有効な fd。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `buf` 全体を 1 データグラムとしてカーネル（`nl_pid = 0`）へ送る。送れたバイト数を返す。
///
/// 送信は `MSG_DONTWAIT` で行い、送信キューが詰まっていても待たずに `EAGAIN` で失敗する
/// （監査ファイル失敗時の呼び出し元を無期限にブロックさせない。SEC-4・TASK-41.5.2）。
pub(crate) fn netlink_send_to_kernel(fd: BorrowedFd<'_>, buf: &[u8]) -> Result<usize, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let addr = SockaddrNl {
        nl_family: consts::AF_NETLINK,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    // SAFETY: `buf` は借用したスライスで、`buf.len()` バイトが呼び出しの間読み出し可能。`addr` は
    // スタック上の初期化済み `SockaddrNl` で、`addrlen` はその `size_of`（12）と一致する。`fd` は生存中の
    // `BorrowedFd`。カーネルは両バッファを呼び出しの間だけ読む。
    let n = unsafe {
        sendto(
            fd.as_raw_fd(),
            buf.as_ptr().cast(),
            buf.len(),
            consts::MSG_DONTWAIT,
            &raw const addr,
            core::mem::size_of::<SockaddrNl>() as u32,
        )
    };
    usize::try_from(n).map_err(|_| last_error())
}

/// 1 データグラムを受信し、`(受信バイト数, 送信元の nl_pid)` を返す（呼び出し前に `poll_readable` で
/// 読み取り可能を確認する。確認なしだとブロックしうる）。送信元が netlink アドレスでなければ `EINVAL`。
pub(crate) fn netlink_recv(fd: BorrowedFd<'_>, buf: &mut [u8]) -> Result<(usize, u32), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut addr = SockaddrNl {
        nl_family: 0,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };
    let mut addrlen = core::mem::size_of::<SockaddrNl>() as u32;
    // SAFETY: `buf` は排他借用したスライスで `buf.len()` バイトが書き込み可能。`addr`・`addrlen` は
    // スタック上の初期化済みローカルで、`addrlen` は `addr` の確保サイズ（12）を入力として渡す。
    // カーネルは書き込んだ長さを `addrlen` へ返し、確保サイズを超えて書かない。
    let n = unsafe {
        recvfrom(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            &raw mut addr,
            &raw mut addrlen,
        )
    };
    let n = usize::try_from(n).map_err(|_| last_error())?;
    if addrlen < core::mem::size_of::<SockaddrNl>() as u32 || addr.nl_family != consts::AF_NETLINK {
        return Err(SysError::Os(EINVAL));
    }
    Ok((n, addr.nl_pid))
}

/// `fd` が読み取り可能になるまで最大 `timeout_ms` ミリ秒待つ。可能なら `true`、時間切れなら `false`。
/// シグナルによる中断は `Os(EINTR)` で返す（呼び出し側が残り時間で再試行する）。
pub(crate) fn poll_readable(fd: BorrowedFd<'_>, timeout_ms: i32) -> Result<bool, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut pfd = PollFd {
        fd: fd.as_raw_fd(),
        events: consts::POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` はスタック上の初期化済み 1 要素で、`nfds` = 1 と一致する。カーネルは呼び出しの間だけ
    // `revents` を書く。
    let r = unsafe { poll(&raw mut pfd, 1, timeout_ms) };
    if r < 0 {
        return Err(last_error());
    }
    Ok(r > 0)
}

/// 稼働中プロセスの pidfd 経由で、指定 namespace 群へ 1 回の `setns(2)` で参加する（Linux 5.8 以降。
/// SUP-6・TASK-163.1）。
///
/// 呼び出し元は `crate::exec::join_namespaces` のみで、単一スレッドであることを確認済みの前提で呼ぶ。
/// 1 回の syscall なので全 namespace が all-or-nothing で切り替わり、途中まで参加した状態を作らない。
/// 空の集合と `NsFlag::User`（user namespace 参加は未対応。fail-closed）は `EINVAL` で拒否する。
pub(crate) fn setns_pidfd(pidfd: BorrowedFd<'_>, flags: &[NsFlag]) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    if flags.is_empty() || flags.contains(&NsFlag::User) {
        return Err(SysError::Os(EINVAL));
    }
    let bits = flags.iter().fold(0i32, |acc, f| acc | f.bits());
    // SAFETY: 引数は整数のみでポインタを取らない。`pidfd` は呼び出しの間有効な `BorrowedFd`。
    // 副作用は呼び出しスレッドの namespace 所属の変更で、呼び出し側が単一スレッドであることを
    // 確認済み。失敗時（-1）はカーネルが namespace を変更しない。
    let rc = unsafe { setns(pidfd.as_raw_fd(), bits) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
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

/// `parent` 配下の既存ファイル `name` を `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` で開く。
/// FIFO 等へ差し替えられても `openat(2)` が相手待ちで止まらない（REPAIR-5）。種別は呼び出し側が
/// 開いた fd への `fstat` で確かめる（PLUG-11・TASK-122.1）。通常ファイルの読み取りには影響しない。
pub(crate) fn open_read_nonblock_at(
    parent: BorrowedFd<'_>,
    name: &CStr,
) -> Result<OwnedFd, SysError> {
    open_file_at(parent, name, consts::O_RDONLY | consts::O_NONBLOCK)
}

/// [`open_path_follow_at`] / [`reopen_pinned_read_nonblock`] 共通の `openat(2)` 呼び出し。
/// `O_NOFOLLOW` を付けず最終要素の symlink チェーンをカーネルに辿らせる（ホップ上限を超えると
/// `ELOOP`）。`O_CREAT` を含まない。辿った先の実体は呼び出し側が fstat と祖先検証で確かめる前提
/// （PLUG-11・TASK-122.2）。
fn open_follow_at(parent: BorrowedFd<'_>, name: &CStr, flags: i32) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let flags = flags | consts::O_CLOEXEC;
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

/// `parent` 配下の `name` を `O_PATH|O_CLOEXEC` で開く（最終要素の symlink を辿る）。
/// 辿った先の種別を、ブロックや副作用なしに fstat で確かめるためのプローブ（REPAIR-5）。
/// 返る fd は fstat 専用。symlink ループは `ELOOP`（PLUG-11・TASK-122.2）。
pub(crate) fn open_path_follow_at(
    parent: BorrowedFd<'_>,
    name: &CStr,
) -> Result<OwnedFd, SysError> {
    open_follow_at(parent, name, consts::O_PATH)
}

/// 保持中の `O_PATH` fd `pinned` が指す inode を `/proc/thread-self/fd/N` 経由で
/// `O_RDONLY|O_NONBLOCK|O_CLOEXEC` に開き直す。パスの再解決（symlink チェーンの再走査）を
/// 行わず、`pinned` が固定した inode そのものを開く（magic link はリンク先を再 walk しない）。
/// 呼び出し側は `pinned` への fstat で通常ファイルと確認済みであること（デバイス・FIFO 等への
/// open の副作用を避ける。REPAIR-5・PLUG-11・TASK-122.2）。
pub(crate) fn reopen_pinned_read_nonblock(pinned: BorrowedFd<'_>) -> Result<OwnedFd, SysError> {
    let path = std::ffi::CString::new(format!("/proc/thread-self/fd/{}", pinned.as_raw_fd()))
        .map_err(|_| SysError::Unsupported)?;
    // 絶対パスのため dirfd は無視される（`pinned` を渡しても解決に影響しない）。
    open_follow_at(pinned, &path, consts::O_RDONLY | consts::O_NONBLOCK)
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
    /// 呼び出し側が 1..=64 で検証済みの任意のシグナル番号（`oci_runtime::kill`。TASK-30.1）。
    ///
    /// 番号体系は x86_64 / aarch64 共通の asm-generic（`traits::Signal` と同じ）を前提とする。
    /// `kill_pid` でも範囲を再検査する（二重の防御）。
    Number(std::num::NonZeroU8),
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
        // 1..=64 以外（0 は存在確認、65 以上は未定義）は送らずに拒否する。
        Signal::Number(n) if (1..=64).contains(&n.get()) => i32::from(n.get()),
        Signal::Number(_) => return Err(SysError::Os(EINVAL)),
    };
    // SAFETY: 引数は整数のみでポインタを取らない。`raw` は正であることを確認済みで、
    // プロセスグループ・全プロセス宛て（0・負値）にならない。`number` は `SIGKILL` 定数か、
    // 1..=64 を検証済みの番号だけである。
    let rc = unsafe { kill(raw, number) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// 子 `pid` のプロセス同一性を保持する pidfd を開く（`pidfd_open(pid, 0)`。Linux 5.3 以降）。
///
/// fork 直後（回収前）に呼ぶと、以後 `pid` が回収・再利用されても fd は元のプロセスを指し続ける。
/// [`pidfd_send_signal`] で送れば、契約外の回収者による回収後の pid 再利用でも無関係なプロセスへ
/// シグナルが届かない（CORE-1・CORE-2・TASK-30.1）。未対応カーネル・seccomp 等で開けない場合は
/// `ENOSYS` / `EPERM` 等を返す（呼び出し側が `kill(2)` へ退避する）。fd は close-on-exec で返る。
pub(crate) fn pidfd_open(pid: u32) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let raw = positive_pid(pid)?;
    // SAFETY: 引数は整数のみでポインタを取らない（glibc 2.36 未満に無いため `syscall(2)` 経由）。
    // `raw` は正であることを確認済み。flags は 0 で、成功時は新規 fd を返す。
    let fd = unsafe { syscall(consts::SYS_PIDFD_OPEN, i64::from(raw), 0_i64) };
    if fd == -1 {
        return Err(last_error());
    }
    let fd = i32::try_from(fd).map_err(|_| SysError::Os(EINVAL))?;
    // SAFETY: `fd` は今 `pidfd_open` が返した新規の有効な fd で、他に所有者がいない。直後に
    // `OwnedFd` が唯一の所有者となる（二重 close なし）。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// [`pidfd_open`] で得た pidfd の指すプロセスへシグナルを送る（`pidfd_send_signal(fd, sig, NULL, 0)`）。
///
/// 指すプロセスが既に回収済み（終了して消えた）なら `ESRCH` を返し、再利用された別プロセスには
/// 届かない。番号は [`kill_pid`] と同じく 1..=64 だけを受ける。
pub(crate) fn pidfd_send_signal(pidfd: BorrowedFd<'_>, sig: Signal) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let number = match sig {
        Signal::Kill => consts::SIGKILL,
        Signal::Number(n) if (1..=64).contains(&n.get()) => i32::from(n.get()),
        Signal::Number(_) => return Err(SysError::Os(EINVAL)),
    };
    // SAFETY: `pidfd` は呼び出しの間有効な fd（`BorrowedFd`）。`info` は NULL（カーネルが siginfo を
    // 既定値で作る）で、ポインタ引数は書き込み・読み出しされない。`number` は検証済みの値、flags は 0。
    let rc = unsafe {
        syscall(
            consts::SYS_PIDFD_SEND_SIGNAL,
            i64::from(pidfd.as_raw_fd()),
            i64::from(number),
            0_i64,
            0_i64,
        )
    };
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

/// `RlimitKind` を `RLIMIT_*` の番号へ写す（網羅 match。アーキテクチャ別の値は `consts`）。
fn rlimit_resource(kind: crate::rlimits::RlimitKind) -> i32 {
    use crate::rlimits::RlimitKind as K;
    match kind {
        K::Cpu => consts::RLIMIT_CPU,
        K::Fsize => consts::RLIMIT_FSIZE,
        K::Data => consts::RLIMIT_DATA,
        K::Stack => consts::RLIMIT_STACK,
        K::Core => consts::RLIMIT_CORE,
        K::Rss => consts::RLIMIT_RSS,
        K::Nproc => consts::RLIMIT_NPROC,
        K::Nofile => consts::RLIMIT_NOFILE,
        K::Memlock => consts::RLIMIT_MEMLOCK,
        K::As => consts::RLIMIT_AS,
        K::Locks => consts::RLIMIT_LOCKS,
        K::Sigpending => consts::RLIMIT_SIGPENDING,
        K::Msgqueue => consts::RLIMIT_MSGQUEUE,
        K::Nice => consts::RLIMIT_NICE,
        K::Rtprio => consts::RLIMIT_RTPRIO,
        K::Rttime => consts::RLIMIT_RTTIME,
    }
}

/// `prlimit(2)` の薄い共通実装。`new` が `Some` なら設定、`None` なら読み取りだけ。旧値を返す。
///
/// `pid` は 0 で呼び出しプロセス自身。他プロセスを対象にする経路は `cfg(test)` の関数だけが使う。
fn prlimit_raw(
    pid: i32,
    kind: crate::rlimits::RlimitKind,
    new: Option<(u64, u64)>,
) -> Result<(u64, u64), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let new_limit = new.map(|(cur, max)| RLimit64 { cur, max });
    let mut old = RLimit64 { cur: 0, max: 0 };
    let new_ptr = new_limit
        .as_ref()
        .map_or(core::ptr::null(), |r| r as *const RLimit64);
    // SAFETY: `new_ptr` は NULL か、このスタックフレームの有効な `RLimit64`（呼び出しの間生存）を指し、
    // カーネルは 16 バイトを読むだけ。`old` は書き込み可能な有効な `RLimit64` で、カーネルは 16 バイトだけ
    // 書く。`resource` は網羅 match 由来の定数、`pid` は 0（自身）か呼び出し側が検査済みの値。
    let rc = unsafe { prlimit(pid, rlimit_resource(kind), new_ptr, &mut old) };
    if rc == -1 {
        Err(last_error())
    } else {
        Ok((old.cur, old.max))
    }
}

/// 呼び出しプロセス自身の rlimit を設定する（SUP-12・TASK-169.1・#526）。
///
/// `crate::exec` の `rlimits` ステージだけが fork 後の子から呼ぶ。`soft <= hard` は
/// `crate::rlimits::Rlimit` が検証済み。hard の引き上げは `CAP_SYS_RESOURCE` が無いと `EPERM`。
// `cfg(test)` では `exec/rlimits.rs` が偽物へ差し替えるため、テストビルドでは未使用になる。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn set_rlimit_self(
    kind: crate::rlimits::RlimitKind,
    soft: u64,
    hard: u64,
) -> Result<(), SysError> {
    prlimit_raw(0, kind, Some((soft, hard))).map(|_old| ())
}

/// 呼び出しプロセス自身の rlimit `(soft, hard)` を読む。
pub(crate) fn get_rlimit_self(kind: crate::rlimits::RlimitKind) -> Result<(u64, u64), SysError> {
    prlimit_raw(0, kind, None)
}

/// 他プロセスの rlimit を読む（テスト専用。本番コードへ他プロセス操作の経路を増やさない）。
#[cfg(test)]
pub(crate) fn get_rlimit_of(
    pid: u32,
    kind: crate::rlimits::RlimitKind,
) -> Result<(u64, u64), SysError> {
    let pid = i32::try_from(pid).map_err(|_| SysError::Os(EINVAL))?;
    prlimit_raw(pid, kind, None)
}

/// 他プロセスの rlimit を設定する（テスト専用）。
#[cfg(test)]
pub(crate) fn set_rlimit_of(
    pid: u32,
    kind: crate::rlimits::RlimitKind,
    soft: u64,
    hard: u64,
) -> Result<(), SysError> {
    let pid = i32::try_from(pid).map_err(|_| SysError::Os(EINVAL))?;
    prlimit_raw(pid, kind, Some((soft, hard))).map(|_old| ())
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

/// `struct sock_fprog`（include/uapi/linux/filter.h）。LP64 では `len` の後に 6 バイトの
/// パディングが入り、`filter` はオフセット 8、全体 16 バイト。
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const BpfInstruction,
}

/// 呼び出したスレッドへ seccomp フィルタを追加する（`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`。
/// CORE-5・TASK-38.2・#177）。
///
/// `crate::exec::seccomp` の `apply_seccomp_filter` だけが呼ぶ。適用は不可逆で呼び出しスレッドにのみ
/// 効く。`NO_NEW_PRIVS` の事前確認は呼び出し側の契約（本関数は検証しない）。命令列は型
/// （[`SeccompProgram`]）により 1 以上 4096 以下が保証される。
pub(crate) fn seccomp_set_filter(program: &SeccompProgram) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let insns = program.instructions();
    let Ok(len) = u16::try_from(insns.len()) else {
        return Err(SysError::Os(EINVAL));
    };
    let fprog = SockFprog {
        len,
        filter: insns.as_ptr(),
    };
    // SAFETY: `fprog` と `insns`（`program` が所有）は呼び出し中生存する。カーネルは
    // `seccomp_prepare_filter` で命令列をコピーし、呼び出し後にポインタを保持しない。`len` は実際の
    // 命令数と一致し非ゼロ・4096 以下（`SeccompProgram` の型保証）。`BpfInstruction` は `repr(C)` で
    // `struct sock_filter` と同一レイアウト（テストでサイズを照合）。ポインタはレジスタ幅の値として
    // 可変長引数に渡す。副作用は呼び出しスレッドへのフィルタ追加のみ。
    let rc = unsafe {
        prctl(
            consts::PR_SET_SECCOMP,
            consts::SECCOMP_MODE_FILTER,
            &fprog as *const SockFprog as usize as u64,
            0u64,
            0u64,
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// 呼び出したスレッドの seccomp モード（`PR_GET_SECCOMP`。0 = 無効・1 = strict・2 = filter）を返す。
pub(crate) fn seccomp_mode() -> Result<u32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみでポインタを渡さない。読み取りだけで状態を変えない。
    let rc = unsafe { prctl(consts::PR_GET_SECCOMP, 0u64, 0u64, 0u64, 0u64) };
    if rc == -1 {
        return Err(last_error());
    }
    u32::try_from(rc).map_err(|_| SysError::Os(EINVAL))
}

/// `capget(2)` / `capset(2)` のヘッダ（`struct __user_cap_header_struct`）。
#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

/// `capget(2)` / `capset(2)` のデータ 1 語分（`struct __user_cap_data_struct`）。v3 は 2 要素の配列。
#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// 呼び出したスレッドの capability（v3 の 2 語 = 64 bit ずつ。ビット位置は capability 番号）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreadCaps {
    pub(crate) effective: [u32; 2],
    pub(crate) permitted: [u32; 2],
    pub(crate) inheritable: [u32; 2],
}

/// 呼び出したスレッドの effective / permitted / inheritable を読む（pid 0 の `capget(2)`）。
///
/// `exec/capabilities.rs` の `apply_default_capabilities`（TASK-37.1・#172）が適用前の値の取得と適用後の
/// 読み戻し検証に使う。カーネルが v3 以外のバージョンを返したら `EINVAL` として fail-closed にする。
pub(crate) fn cap_get_thread() -> Result<ThreadCaps, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut header = CapUserHeader {
        version: consts::LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: `header` と `data`（v3 が要求する 2 要素）はこの関数のスタック上の `#[repr(C)]` 値で、
    // 呼び出しの間有効かつ排他的に借用されている。可変長部のポインタはカーネルが
    // `CapUserHeader` と `[CapUserData; 2]` の大きさだけ読み書きする。影響は呼び出したスレッドの
    // 読み取りのみ。
    let rc = unsafe { syscall(consts::SYS_CAPGET, &raw mut header, data.as_mut_ptr()) };
    if rc == -1 {
        return Err(last_error());
    }
    if header.version != consts::LINUX_CAPABILITY_VERSION_3 {
        return Err(SysError::Os(EINVAL));
    }
    Ok(ThreadCaps {
        effective: [data[0].effective, data[1].effective],
        permitted: [data[0].permitted, data[1].permitted],
        inheritable: [data[0].inheritable, data[1].inheritable],
    })
}

/// 呼び出したスレッドの effective / permitted / inheritable を設定する（pid 0 の `capset(2)`）。
///
/// スレッド単位の操作。`fork_single_threaded` による単一スレッドの子で呼ぶ前提
/// （`exec/capabilities.rs` の `apply_default_capabilities` が使う。TASK-37.1・#172）。
pub(crate) fn cap_set_thread(caps: ThreadCaps) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let header = CapUserHeader {
        version: consts::LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [0usize, 1].map(|i| CapUserData {
        effective: caps.effective[i],
        permitted: caps.permitted[i],
        inheritable: caps.inheritable[i],
    });
    // SAFETY: `header` と `data`（v3 が要求する 2 要素）はスタック上の `#[repr(C)]` 値で、呼び出しの
    // 間有効。カーネルは読み取りのみ行う（const ポインタ）。資格情報の変更は呼び出したスレッドに
    // 限られ、メモリ安全性には影響しない。
    let rc = unsafe { syscall(consts::SYS_CAPSET, &raw const header, data.as_ptr()) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `cap`（capability 番号）が呼び出したスレッドの bounding set に残っているかを返す
/// （`PR_CAPBSET_READ`）。カーネルの最後の capability を超える番号は `EINVAL`。
pub(crate) fn cap_bounding_contains(cap: u8) -> Result<bool, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみでポインタを渡さない。可変長部は `unsigned long`（LP64 で u64）に
    // 合わせる。読み取りだけで状態を変えない。
    let rc = unsafe { prctl(consts::PR_CAPBSET_READ, u64::from(cap), 0u64, 0u64, 0u64) };
    match rc {
        -1 => Err(last_error()),
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SysError::Os(EINVAL)),
    }
}

/// `cap` を呼び出したスレッドの bounding set から外す（`PR_CAPBSET_DROP`。不可逆。
/// `CAP_SETPCAP` が effective に必要）。
pub(crate) fn cap_bounding_drop(cap: u8) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみでポインタを渡さない。可変長部は `unsigned long` に合わせて u64 で渡す。
    // 影響は呼び出したスレッドの bounding set の縮小のみ（権限を減らす方向にしか働かない）。
    let rc = unsafe { prctl(consts::PR_CAPBSET_DROP, u64::from(cap), 0u64, 0u64, 0u64) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// ambient capability をすべて消す（`PR_CAP_AMBIENT_CLEAR_ALL`）。
pub(crate) fn cap_ambient_clear_all() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみでポインタを渡さない。可変長部は `unsigned long` に合わせて u64 で渡す。
    // 影響は呼び出したスレッドの ambient 集合の縮小のみ。
    let rc = unsafe {
        prctl(
            consts::PR_CAP_AMBIENT,
            consts::PR_CAP_AMBIENT_CLEAR_ALL,
            0u64,
            0u64,
            0u64,
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// 実行中カーネルの Landlock ABI バージョンを返す（`landlock_create_ruleset(NULL, 0, VERSION)`。
/// CORE-5・TASK-39.1）。`0` の妥当性判定は呼び出し側（`crate::landlock`）が行う。
/// Landlock 非対応は `ENOSYS`、起動時に無効化されていれば `EOPNOTSUPP`。
pub(crate) fn landlock_abi_version() -> Result<u32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: attr は NULL・size は 0 で、VERSION フラグの問い合わせではカーネルはメモリを読まない
    // （それ以外の組み合わせは EINVAL）。fd を作らずプロセス状態も変えない読み取り専用の問い合わせ。
    // `landlock_create_ruleset` は glibc に無いため可変長の `syscall(2)` 経由で呼び、引数は
    // ポインタ・`usize`・`u64` とレジスタ幅で渡す（32 bit 値を可変長で渡すと上位ビットが未規定に
    // なり得るため、flags は `prctl` と同様に `u64` へ拡幅する。カーネルは `__u32` へ切り詰める）。
    let rc = unsafe {
        syscall(
            consts::SYS_LANDLOCK_CREATE_RULESET,
            core::ptr::null::<core::ffi::c_void>(),
            0usize,
            u64::from(consts::LANDLOCK_CREATE_RULESET_VERSION),
        )
    };
    if rc == -1 {
        return Err(last_error());
    }
    u32::try_from(rc).map_err(|_| SysError::Os(EINVAL))
}

/// `struct landlock_ruleset_attr`（include/uapi/linux/landlock.h。ABI 6 時点の 24 バイト版）。
/// `handled_access_net`・`scoped` は本実装では使わず 0（`MIN_LANDLOCK_ABI` = 6 によりカーネルは
/// 常にこのサイズを理解する）。
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// `struct landlock_path_beneath_attr`（include/uapi/linux/landlock.h。`__attribute__((packed))`
/// のため 12 バイトで、`parent_fd` はオフセット 8）。
#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// fs アクセス権 `handled_fs` を扱う ruleset を作り、その fd を返す（`landlock_create_ruleset(2)`。
/// CORE-5・TASK-39.3・#183）。fd はカーネルが `O_CLOEXEC` 付きで返す。この時点ではプロセスを制限しない。
pub(crate) fn landlock_create_ruleset_fs(handled_fs: u64) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_fs,
        handled_access_net: 0,
        scoped: 0,
    };
    // SAFETY: `attr` はスタック上の `#[repr(C)]` 値（24 バイト）で呼び出しの間有効。カーネルは
    // `size` バイトを読んでコピーするだけでポインタを保持しない。`size` は実際の構造体サイズと一致する。
    // flags は 0。可変長 `syscall(2)` へはポインタ・`usize`・`u64` とレジスタ幅で渡す。
    let rc = unsafe {
        syscall(
            consts::SYS_LANDLOCK_CREATE_RULESET,
            &raw const attr,
            core::mem::size_of::<LandlockRulesetAttr>(),
            0u64,
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    let fd = i32::try_from(rc).map_err(|_| SysError::Os(EINVAL))?;
    // SAFETY: `fd` は上で成功した syscall が返した、他に所有者のいない有効な fd（二重 close なし）。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// ruleset に「`parent`（O_PATH 可）配下に `allowed` を許可する」ルールを追加する
/// （`landlock_add_rule(2)` の `LANDLOCK_RULE_PATH_BENEATH`。CORE-5・TASK-39.3・#183）。
/// `allowed` が空なら `ENOMSG`、handled に含まれない権利を含むと `EINVAL`。
pub(crate) fn landlock_add_path_beneath(
    ruleset: BorrowedFd<'_>,
    allowed: u64,
    parent: BorrowedFd<'_>,
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let attr = LandlockPathBeneathAttr {
        allowed_access: allowed,
        parent_fd: parent.as_raw_fd(),
    };
    // SAFETY: `attr` はスタック上の packed `#[repr(C)]` 値（12 バイト）で呼び出しの間有効。
    // カーネルは読み取りのみでポインタを保持しない。`ruleset`・`parent` は生存中の `BorrowedFd`。
    // flags は 0。可変長引数はレジスタ幅（`i32` は `i64` へ拡幅して符号を保つ）で渡す。
    let rc = unsafe {
        syscall(
            consts::SYS_LANDLOCK_ADD_RULE,
            i64::from(ruleset.as_raw_fd()),
            u64::from(consts::LANDLOCK_RULE_PATH_BENEATH),
            &raw const attr,
            0u64,
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// ruleset を呼び出したスレッドへ適用する（`landlock_restrict_self(2)`。CORE-5・TASK-39.3・#183）。
///
/// 適用は不可逆で、呼び出したスレッド（と以後 fork・clone する子）にのみ効く。`NO_NEW_PRIVS` と
/// 単一スレッドの事前確認は呼び出し側（`crate::landlock`）の契約で、本関数は検証しない。
/// flags は 0（ABI 7 のログ系フラグは使わない）。
pub(crate) fn landlock_restrict_self(ruleset: BorrowedFd<'_>) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は生存中の `BorrowedFd` の fd 番号と flags 0 の整数のみでポインタを渡さない。
    // メモリには触れず、影響は呼び出したスレッドの Landlock ドメインの追加（権限を減らす方向）のみ。
    let rc = unsafe {
        syscall(
            consts::SYS_LANDLOCK_RESTRICT_SELF,
            i64::from(ruleset.as_raw_fd()),
            0u64,
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `ptrace(PTRACE_CONT, pid, 0, 0)` を発行して errno を返す結合試験用プローブ（CORE-5・TASK-38.4・#179）。
///
/// `PTRACE_CONT` は attach 済みのトレーシー専用の要求で、フィルタが無ければ自プロセスのような
/// 「自分がトレースしていない」対象に対し `ESRCH` で失敗し副作用が無い。seccomp の遮断が効いていれば
/// `EPERM` になり、capability 不足との区別に使える。呼び出しは結合試験用の観測経路だけ。
// 結合試験専用。テストビルドの単体テストは呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn ptrace_cont_probe(pid: u32) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数はすべて整数（request・pid・addr=0・data=0）でポインタを渡さず、PTRACE_CONT では
    // カーネルは data をシグナル番号としてしか読まない（メモリは読まない）。attach を伴わないため、
    // フィルタが欠けていても対象プロセスへの副作用は無い（`ESRCH`）。
    let rc = unsafe {
        syscall(
            consts::SYS_PTRACE,
            consts::PTRACE_CONT,
            i64::from(pid),
            0_i64,
            0_i64,
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `kexec_load(0, KEXEC_SEGMENT_MAX + 1, NULL, 0xffff_ffff)` を発行して errno を返す結合試験用プローブ
/// （CORE-5・TASK-38.4・#179）。
///
/// segment 数が上限超過のため、フィルタが無くても権限検査（非 root は `EPERM`）または引数検査
/// （root は `EINVAL`）で失敗し、ロード済みカーネルの入れ替え・破棄は起きない。識別的な根拠には
/// 使わない（capability 不足でも `EPERM` になり得る）。
// 結合試験専用。テストビルドの単体テストは呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn kexec_load_invalid_probe() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: segments は NULL（整数 0 として渡す）。nr_segments が上限を超えるためカーネルは
    // segments を読む前に拒否する。flags は無効値で、どの経路でもロード・アンロードに至らない。
    let rc = unsafe {
        syscall(
            consts::SYS_KEXEC_LOAD,
            0_i64,
            consts::KEXEC_SEGMENT_MAX + 1,
            0_i64,
            0xffff_ffff_i64,
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `std::fs::OpenOptions` の `custom_flags` へ渡す `O_NOFOLLOW | O_NONBLOCK`（アーキテクチャ別の値）。
///
/// 状態ストア（`state_store`。OCI-5・REPAIR-5）が、最終要素の symlink を辿らず、FIFO 等でも
/// `open(2)` 自体が相手を待って止まらないように開くために使う。`O_NONBLOCK` は通常ファイルの
/// 読み書き・`flock` には影響しない。対応外アーキテクチャでは値を持たないため `None`（呼び出し側で
/// fail-closed にする）。syscall を呼ばない定数の組み立てのみで、`unsafe` を含まない。
pub(crate) fn nofollow_nonblock_open_flags() -> Option<i32> {
    consts::SUPPORTED.then_some(consts::O_NOFOLLOW | consts::O_NONBLOCK)
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

    /// CORE-5・TASK-38.4: プローブ用定数の固定値照合（x86_64。arch ごとの個別定義の誤り検出）。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn core5_probe_consts_are_exact_x86_64() {
        assert_eq!(consts::SYS_PTRACE, 101);
        assert_eq!(consts::SYS_KEXEC_LOAD, 246);
        assert_eq!(consts::PTRACE_CONT, 7);
        assert_eq!(consts::KEXEC_SEGMENT_MAX, 16);
    }

    /// CORE-5・TASK-38.4: プローブ用定数の固定値照合（aarch64）。
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn core5_probe_consts_are_exact_aarch64() {
        assert_eq!(consts::SYS_PTRACE, 117);
        assert_eq!(consts::SYS_KEXEC_LOAD, 104);
        assert_eq!(consts::PTRACE_CONT, 7);
        assert_eq!(consts::KEXEC_SEGMENT_MAX, 16);
    }

    /// CORE-5・TASK-39.1: Landlock 関連定数の固定値照合（arch ごとに個別定義した値の誤り検出）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core5_landlock_consts_are_exact() {
        assert_eq!(consts::SYS_LANDLOCK_CREATE_RULESET, 444);
        assert_eq!(consts::LANDLOCK_CREATE_RULESET_VERSION, 1);
        assert_eq!(consts::EOPNOTSUPP, 95);
    }

    /// CORE-5・TASK-39.3: Landlock 適用系の定数・構造体レイアウトの固定値照合。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core5_landlock_apply_consts_and_layout_are_exact() {
        assert_eq!(consts::SYS_LANDLOCK_ADD_RULE, 445);
        assert_eq!(consts::SYS_LANDLOCK_RESTRICT_SELF, 446);
        assert_eq!(consts::LANDLOCK_RULE_PATH_BENEATH, 1);
        assert_eq!(core::mem::size_of::<LandlockRulesetAttr>(), 24);
        assert_eq!(core::mem::size_of::<LandlockPathBeneathAttr>(), 12);
        assert_eq!(core::mem::offset_of!(LandlockPathBeneathAttr, parent_fd), 8);
    }

    /// CORE-5・TASK-39.3: ruleset 作成とルール追加は fd に触れるだけでプロセスを制限しないため
    /// libtest 内で実 syscall を呼べる（`landlock_restrict_self` は不可逆のため呼ばない）。
    #[test]
    fn core5_landlock_create_and_add_rule_real_syscall() {
        use std::os::fd::AsFd as _;
        const READ_DIR: u64 = 1 << 3;
        match landlock_create_ruleset_fs(READ_DIR) {
            Ok(rs) => {
                let root = open_dir_path_nofollow(None, c"/").expect("open /");
                assert_eq!(
                    landlock_add_path_beneath(rs.as_fd(), READ_DIR, root.as_fd()),
                    Ok(())
                );
                // 空の allowed はカーネルが拒否する（ENOMSG = 42）。
                assert_eq!(
                    landlock_add_path_beneath(rs.as_fd(), 0, root.as_fd()),
                    Err(SysError::Os(42))
                );
            }
            Err(SysError::Os(e)) => assert!(e > 0, "errno must be positive, got {e}"),
            Err(SysError::Unsupported) => {}
            Err(other) => panic!("unexpected result: {other:?}"),
        }
    }

    /// CORE-5・TASK-39.1: 実 syscall の結果が想定どおりの集合に収まる（カーネル版数に依存しない）。
    #[test]
    fn core5_landlock_abi_version_real_syscall() {
        match landlock_abi_version() {
            Ok(n) => assert!(n >= 1, "abi must be >= 1, got {n}"),
            // ENOSYS / EOPNOTSUPP のほか、seccomp 等で syscall が制限された環境の EPERM なども
            // 実装が ProbeFailed として拒否する正当な応答。errno は正の値であることだけ確かめる。
            Err(SysError::Os(e)) => assert!(e > 0, "errno must be positive, got {e}"),
            // 対応外アーキテクチャは明示的な Unsupported を返す。
            Err(SysError::Unsupported) => {}
            Err(other) => panic!("unexpected result: {other:?}"),
        }
    }
    use std::os::fd::AsFd as _;

    /// SEC-4・TASK-41.5.2: netlink 監査用の定数・構造体レイアウトの具体値（kernel の uapi と照合）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sec4_task41_5_2_netlink_consts_and_layout_are_exact() {
        assert_eq!((consts::AF_NETLINK, consts::SOCK_RAW), (16, 3));
        assert_eq!(consts::SOCK_CLOEXEC, 0o2_000_000);
        assert_eq!((consts::NETLINK_AUDIT, consts::POLLIN), (9, 1));
        assert_eq!(consts::MSG_DONTWAIT, 0x40);
        assert_eq!((EAFNOSUPPORT, EPROTONOSUPPORT, ECONNREFUSED), (97, 93, 111));
        assert_eq!(std::mem::size_of::<SockaddrNl>(), 12);
        assert_eq!(std::mem::size_of::<PollFd>(), 8);
    }

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

    /// SEC-1・TASK-37.1: capability 関連の定数の具体値。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn sec1_capability_consts_are_exact_x86_64() {
        assert_eq!(consts::SYS_CAPGET, 125);
        assert_eq!(consts::SYS_CAPSET, 126);
        assert_eq!(consts::LINUX_CAPABILITY_VERSION_3, 0x2008_0522);
        assert_eq!(consts::PR_CAPBSET_READ, 23);
        assert_eq!(consts::PR_CAPBSET_DROP, 24);
        assert_eq!(consts::PR_CAP_AMBIENT, 47);
        assert_eq!(consts::PR_CAP_AMBIENT_CLEAR_ALL, 4);
    }

    /// SEC-1・TASK-37.1: capability 関連の定数の具体値（aarch64）。
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn sec1_capability_consts_are_exact_aarch64() {
        assert_eq!(consts::SYS_CAPGET, 90);
        assert_eq!(consts::SYS_CAPSET, 91);
        assert_eq!(consts::LINUX_CAPABILITY_VERSION_3, 0x2008_0522);
        assert_eq!(consts::PR_CAPBSET_READ, 23);
        assert_eq!(consts::PR_CAPBSET_DROP, 24);
        assert_eq!(consts::PR_CAP_AMBIENT, 47);
        assert_eq!(consts::PR_CAP_AMBIENT_CLEAR_ALL, 4);
    }

    /// `/proc/thread-self/status` の `field:` 行（16 進 64 bit）を 2 語にする。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn status_caps(field: &str) -> [u32; 2] {
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        let line = status
            .lines()
            .find_map(|l| l.strip_prefix(field))
            .unwrap_or_else(|| panic!("{field} missing in {status}"));
        let v = u64::from_str_radix(line.trim(), 16).unwrap();
        [v as u32, (v >> 32) as u32]
    }

    /// SEC-1・TASK-37.1: `capget` の結果が `/proc/thread-self/status` と一致する。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sec1_cap_get_thread_reads_v3() {
        std::thread::spawn(|| {
            let caps = cap_get_thread().unwrap();
            assert_eq!(caps.effective, status_caps("CapEff:"));
            assert_eq!(caps.permitted, status_caps("CapPrm:"));
            assert_eq!(caps.inheritable, status_caps("CapInh:"));
        })
        .join()
        .unwrap();
    }

    /// SEC-1・TASK-37.1: カーネルの最後の capability 以降の番号は `EINVAL`。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sec1_cap_bounding_read_beyond_last_cap_is_einval() {
        assert_eq!(cap_bounding_contains(63), Err(SysError::Os(EINVAL)));
        assert_eq!(cap_bounding_contains(0).map(|_| ()), Ok(()));
    }

    /// CORE-5・TASK-38.2: seccomp 適用の定数とレイアウトの具体値。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn core5_seccomp_prctl_consts_and_layout_are_exact() {
        assert_eq!(consts::PR_GET_SECCOMP, 21);
        assert_eq!(consts::PR_SET_SECCOMP, 22);
        assert_eq!(consts::SECCOMP_MODE_FILTER, 2);
        assert_eq!(std::mem::size_of::<BpfInstruction>(), 8);
        assert_eq!(std::mem::size_of::<SockFprog>(), 16);
        assert_eq!(std::mem::offset_of!(SockFprog, filter), 8);
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

    /// SUP-6・TASK-163.1: network namespace のビット値。
    #[test]
    fn sup6_ns_flag_net_bits_are_exact() {
        assert_eq!(NsFlag::Net.bits(), 0x4000_0000);
    }

    /// SUP-6・TASK-163.1: 空集合・user namespace は拒否し、namespace でない fd は EINVAL（副作用なし）。
    #[test]
    fn sup6_setns_pidfd_rejects_invalid_input() {
        let null = std::fs::File::open("/dev/null").unwrap();
        let fd = std::os::fd::AsFd::as_fd(&null);
        assert_eq!(setns_pidfd(fd, &[]), Err(SysError::Os(EINVAL)));
        assert_eq!(setns_pidfd(fd, &[NsFlag::User]), Err(SysError::Os(EINVAL)));
        assert_eq!(
            setns_pidfd(fd, &[NsFlag::Mount, NsFlag::Net]),
            Err(SysError::Os(EINVAL))
        );
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
        // OCI-5・REPAIR-5: 状態ストアの非ブロッキング・symlink 非追従 open（0o400000 | 0o4000）。
        assert_eq!(nofollow_nonblock_open_flags(), Some(0o404_000));
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
        // OCI-5・REPAIR-5: 状態ストアの非ブロッキング・symlink 非追従 open（0o100000 | 0o4000）。
        assert_eq!(nofollow_nonblock_open_flags(), Some(0o104_000));
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

    /// CORE-2（TASK-30.1）: 範囲外のシグナル番号は `kill` を呼ばずに `EINVAL` で拒否する。
    #[test]
    fn core2_kill_pid_rejects_out_of_range_signal() {
        let pid = std::process::id();
        let n65 = Signal::Number(std::num::NonZeroU8::new(65).unwrap());
        assert_eq!(kill_pid(pid, n65), Err(SysError::Os(EINVAL)));
        let n255 = Signal::Number(std::num::NonZeroU8::MAX);
        assert_eq!(kill_pid(pid, n255), Err(SysError::Os(EINVAL)));
    }

    /// CORE-2（TASK-30.1）: 任意番号（SIGTERM=15）を子へ送ると、子が `Signaled(15)` で終了する。
    #[cfg(target_os = "linux")]
    #[test]
    fn core2_kill_pid_sends_sigterm_to_child() {
        // 子は下で `wait_pid_nohang` が回収する（`Child` の wait は使わない）。
        #[allow(clippy::zombie_processes)]
        let pid = std::process::Command::new("sleep")
            .arg("30")
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap()
            .id();
        kill_pid(pid, Signal::Number(std::num::NonZeroU8::new(15).unwrap())).unwrap();
        let status = loop {
            match wait_pid_nohang(pid).unwrap() {
                Some(s) => break s,
                None => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        };
        // 終了ステータスの下位 7 ビットが終了シグナル。
        assert_eq!(status & 0x7f, 15);
    }

    /// SUP-12・TASK-169.1: RLIMIT_* の番号を固定値で照合する（asm-generic/resource.h）。
    #[test]
    fn sup12_rlimit_constants_are_fixed() {
        use crate::rlimits::RlimitKind;
        let got: Vec<i32> = RlimitKind::ALL
            .iter()
            .map(|k| rlimit_resource(*k))
            .collect();
        assert_eq!(got, (0..16).collect::<Vec<i32>>());
        assert_eq!(consts::RLIMIT_NOFILE, 7);
        assert_eq!(consts::RLIMIT_CORE, 4);
    }

    /// SUP-12・TASK-169.1: 自プロセスの rlimit が soft <= hard で読める（変更はしない）。
    #[test]
    fn sup12_get_rlimit_self_is_consistent() {
        let (soft, hard) = get_rlimit_self(crate::rlimits::RlimitKind::Nofile).unwrap();
        assert!(soft <= hard, "soft={soft} hard={hard}");
    }

    /// SUP-12・TASK-169.1: 別プロセス（sleep の子）へ設定した値が読み戻しと `/proc/<pid>/limits` の
    /// 両方で具体値として一致する（テストプロセス自身の制限は変えない）。
    #[test]
    fn sup12_set_rlimit_of_child_is_reflected() {
        use crate::rlimits::RlimitKind;
        /// テストが失敗しても子を残さない。
        struct KillOnDrop(std::process::Child);
        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = KillOnDrop(
            std::process::Command::new("sleep")
                .arg("30")
                .stdin(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id();
        let (_, hard) = get_rlimit_of(pid, RlimitKind::Nofile).unwrap();
        let soft = 64u64;
        let hard = hard.min(4096).max(soft);
        set_rlimit_of(pid, RlimitKind::Nofile, soft, hard).unwrap();
        assert_eq!(
            get_rlimit_of(pid, RlimitKind::Nofile).unwrap(),
            (soft, hard)
        );
        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
        let line = limits
            .lines()
            .find(|l| l.starts_with("Max open files"))
            .unwrap()
            .to_owned();
        let cols: Vec<&str> = line.split_whitespace().collect();
        // "Max open files <soft> <hard> files"
        assert_eq!(cols.get(3).copied(), Some("64"), "{line}");
        assert_eq!(
            cols.get(4).copied(),
            Some(hard.to_string().as_str()),
            "{line}"
        );
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

    /// PLUG-11・REPAIR-5（TASK-122.1）: `open_read_nonblock_at` は書き手のいない FIFO でも
    /// 待たずに返り、開いた fd は FIFO として判別できる。
    #[test]
    fn plug11_open_read_nonblock_at_does_not_block_on_fifo() {
        use std::os::unix::fs::FileTypeExt as _;
        let t = TempTree::new("rdnb");
        let status = std::process::Command::new("mkfifo")
            .arg(t.base.join("pipe"))
            .status()
            .expect("run mkfifo");
        assert!(status.success());
        let parent = open_dir_path_nofollow(None, &c(&t.base)).unwrap();
        let fd = open_read_nonblock_at(parent.as_fd(), c"pipe").unwrap();
        assert!(
            std::fs::File::from(fd)
                .metadata()
                .unwrap()
                .file_type()
                .is_fifo()
        );
    }

    /// PLUG-11・TASK-122.2: 追従 open は symlink チェーンの実体を開き、ループは `ELOOP`、
    /// FIFO への symlink でもブロックしない。
    #[test]
    fn plug11_follow_open_resolves_chain_and_detects_loop() {
        use std::os::unix::fs::{FileTypeExt as _, symlink};
        let t = TempTree::new("follow");
        std::fs::write(t.base.join("real"), b"x").unwrap();
        symlink("real", t.base.join("l1")).unwrap();
        symlink("l1", t.base.join("l2")).unwrap();
        symlink("loop", t.base.join("loop")).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(t.base.join("pipe"))
            .status()
            .expect("run mkfifo");
        assert!(status.success());
        symlink("pipe", t.base.join("lp")).unwrap();
        let parent = open_dir_path_nofollow(None, &c(&t.base)).unwrap();

        let probe = open_path_follow_at(parent.as_fd(), c"l2").unwrap();
        assert!(std::fs::File::from(probe).metadata().unwrap().is_file());
        let pinned = open_path_follow_at(parent.as_fd(), c"l2").unwrap();
        let fd = reopen_pinned_read_nonblock(pinned.as_fd()).unwrap();
        assert_eq!(std::fs::File::from(fd).metadata().unwrap().len(), 1);

        assert!(matches!(
            open_path_follow_at(parent.as_fd(), c"loop"),
            Err(SysError::Os(n)) if n == ELOOP
        ));
        let pinned = open_path_follow_at(parent.as_fd(), c"lp").unwrap();
        let fd = reopen_pinned_read_nonblock(pinned.as_fd()).unwrap();
        assert!(
            std::fs::File::from(fd)
                .metadata()
                .unwrap()
                .file_type()
                .is_fifo()
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
