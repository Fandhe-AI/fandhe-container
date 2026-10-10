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
//! さらに封印した複製からの実行（TASK-163 追補・#1530・#1531）が、`memfd_create(2)`（`syscall(2)` 経由）と
//! `fcntl(2)` の `F_ADD_SEALS` / `F_GET_SEALS`、複製の前に元のファイルを実行してよいかをカーネルに判定させる
//! `execveat(2)` の `AT_EXECVE_CHECK`（`syscall(2)` 経由。Linux 6.14 以降）と、元のファイルのマウントの `noexec` を
//! 見る `fstatfs(2)` を呼ぶ。実行そのものは既存の `execveat(2)`（`exec_fd`）を使う。
//! 基本デバイスノード作成は、`mknodat(2)`・`O_PATH` での `openat(2)` を呼ぶために使う。
//! 委譲 cgroup の検出と子 cgroup 作成（`crate::cgroups`。CORE-3・TASK-32.1・#158）は、
//! `mkdirat(2)`・`unlinkat(2)`・`fstatfs(2)`（cgroup2 判定）と `O_NOFOLLOW` 付きの `openat(2)` を呼ぶために使う。
//! rlimit の適用（`exec/rlimits.rs` の `apply_rlimits`。SUP-12・TASK-169.1・#526）は、fork 後の子で `prlimit(2)` を呼ぶために使う。
//! 稼働中コンテナへの exec（`exec/exec_command.rs`。SUP-6・TASK-163.4・#503）は、exec 専用 worker を
//! non-dumpable にし、子を親の生存に結び付けるために `prctl(2)`（`PR_SET_DUMPABLE` / `PR_GET_DUMPABLE` /
//! `PR_SET_PDEATHSIG`）を呼ぶ。
//! tmpfs のマウント（`crate::exec::mount_tmpfs`。SUP-12・TASK-169 追補・#1472）は、新マウント API（`fsopen(2)`・`fsconfig(2)`・
//! `fsmount(2)`・`move_mount(2)`。Linux 5.2 以降）で検証済みの O_PATH fd の上へ直接載せる。未対応カーネルは拒否する（縮退しない）。
//! 同じ経路で rootfs の `/dev` 用の nodev なし tmpfs も載せる入口（`mount_dev_tmpfs_on`。TASK-29 追補・#1652）を持つ。
//! 呼び出しの配線は #1653 で行う。rootless の基本デバイスは `open_tree(2)` + `move_mount(2)` でホストのノードを fd 起点で bind する（CORE-6・SEC-5・#1659・#1660）。
//! exec 入口の前提（TASK-163 追補・#1456〜#1460）は、exec 直前の子でセッションを切り離す `setsid(2)`、補助グループを
//! 空にする `getgroups(2)` / `setgroups(2)`、`/dev/null` とインタープリタを検証済みの `O_PATH` fd から開き直す
//! `openat(2)`（`O_NOCTTY`）、状態を返す pipe だけを残して fd を閉じる `close_range(2)` を呼ぶ。
//! さらに `crate::audit_log` のカーネル監査フォールバック（SEC-4・TASK-41.5.2・#840）が、
//! `socket(2)`（NETLINK_AUDIT）・`sendto(2)`・`recvfrom(2)`・`poll(2)` を呼ぶ。
//! std だけでは提供されない syscall のみを持ち、検証（hostname の文字種・パス形式等）は呼び出し側の型
//! （`Hostname` 等）が済ませた値だけを受け取る。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない。公開するのは安全な関数のみ
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と
//!   維持すべき不変条件を明記する
//! - syscall(2) の番号は `ArchSysNo::get` を通した `SyscallNumber` でしか `syscall` に渡せない
//!   （型で強制。対応外アーキテクチャ〔x32・aarch64 ILP32 を含む〕では `get` が常に
//!   `Unsupported` を返し、仮置きの番号 0 を発行しない。対応 arch の番号の値は固定値テストで
//!   照合する。#1619）。フラグ定数（`MS_*` 等）は対応外 arch で 0 のままで、libc 経由ラッパーの
//!   `SUPPORTED` 検査は引き続き慣習で保つ（型では強制しない）
//! - syscall の定数は `cfg(target_arch = ...)` ごとに個別に定義し、値が同じでも
//!   他アーキテクチャの定義を流用しない。対応 arch は LP64 の x86_64・aarch64 に限り
//!   （`target_pointer_width = "64"` を条件に含める）、x32 などの 32 bit ABI は対応外とする。
//!   対応外アーキテクチャでは各ラッパーが [`SysError::Unsupported`] を返す
//!   （fail-closed。`ErrorCode::Unimplemented` に写す。新マウント API の `ENOSYS`〔古いカーネル〕も
//!   同じ値に写す。経路の一覧は [`SysError::Unsupported`] の doc）
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
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, IntoRawFd as _, OwnedFd, RawFd};

/// syscall 失敗の分類。`crate::exec` が `ErrorCode` へ写す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysError {
    /// 対応外として拒否した操作（縮退せず fail-closed）。`crate::exec` が `ErrorCode::Unimplemented` に写し、
    /// 表示文言は "not supported by the kernel or the target architecture"（#1690）。次の経路で返る:
    /// - 対応外アーキテクチャ: `consts::SUPPORTED` が偽、または `ArchSysNo::get` が番号を持たない（#1619）
    /// - 古いカーネル: 新マウント API（`fsopen`・`fsconfig`・`fsmount`・`move_mount`・`open_tree` は
    ///   Linux 5.2 未満、`mount_setattr` は 5.12 未満）が返した `ENOSYS` を `new_mount_api_error` が写す。
    ///   それ以外の syscall の `ENOSYS` は写さず [`SysError::Os`] のまま返す
    /// - `reopen_pinned_read_nonblock` のパス組み立て（`CString::new`）の失敗。整数の書式化のため NUL を
    ///   含まず、実際には起こらない
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
    EMFILE, ENFILE, ENOENT, ENOEXEC, ENOMEM, ENOSYS, ENOTDIR, ENOTEMPTY, EOPNOTSUPP, EPERM,
    EPROTONOSUPPORT, ESRCH,
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

/// syscall(2) の番号を型で守る小さなサブモジュール（#1619・SUP-12・SEC-1・CORE-5・REPAIR-3）。
///
/// 対応 arch は LP64 の x86_64・aarch64 だけ（`cfg(all(target_pointer_width = "64", any(target_arch =
/// "x86_64", target_arch = "aarch64")))`）。x32 ABI（`x86_64-unknown-linux-gnux32`）と aarch64 の ILP32
/// （`aarch64-unknown-linux-gnu_ilp32`）は `target_arch` が同じでも `long` が 32 bit で、x32 の番号には
/// `__X32_SYSCALL_BIT` が付く（arm64 の ILP32 はカーネル本体に無い）ため、64 bit の表をそのまま使えず対応外に含める。
/// 対応外アーキテクチャでは `consts` の番号が実在せず、素の整数 0 を `syscall` に渡すと別の
/// syscall（x86_64 以外では 0 番が何に当たるかは arch 依存）を発行し得る。各ラッパー冒頭の
/// `SUPPORTED` 検査が慣習で止めていたのを、`extern` の `syscall` が [`SyscallNumber`] しか
/// 受けず、その唯一の入手経路が [`ArchSysNo::get`]（対応外 arch では常に `Unsupported`）に
/// なる形で型に強制する。構築子は本モジュールの外へ出さない（フィールドは非公開）。
/// 各ラッパーは `unsafe` ブロックの前で `let nr = consts::SYS_*.get()?;`（複数の syscall を呼ぶ関数では
/// `nr_fsopen` 等）として番号を取り出し、失敗時は FFI 呼び出しの前に戻る（ブロック内の `syscall` には
/// 取り出し済みの番号だけを渡す）。
/// 対応 arch の番号の値そのもの（表との一致）は型では守らず、`consts` の固定値テストで照合する。
mod sysno {
    use super::SysError;

    /// カーネルへ渡せる syscall 番号。`extern` の `syscall` の第 1 引数はこの型だけを受ける。
    /// `repr(transparent)` により ABI は C の `long`（対応 arch は LP64 のみのため i64）と同一。
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    #[cfg_attr(
        not(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )),
        allow(dead_code, reason = "対応外 arch では構築されない（常に Unsupported）")
    )]
    pub(super) struct SyscallNumber(i64);

    impl SyscallNumber {
        /// 固定値テスト専用の生の番号（対応 arch のみ）。`consts` の固定値テストが `ArchSysNo::get` を
        /// 通した値（`get().map(SyscallNumber::raw)`）を照合するために使い、本体のコードからは使わない。
        #[cfg(all(
            test,
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        pub(super) const fn raw(self) -> i64 {
            self.0
        }
    }

    /// `consts` に置く、この arch での syscall 番号の定義。取り出し口は [`ArchSysNo::get`] のみ。
    #[derive(Clone, Copy)]
    pub(super) struct ArchSysNo(
        #[cfg(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        i64,
        #[cfg(not(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        (),
    );

    impl ArchSysNo {
        /// 対応 arch の番号定義。対応外 arch には存在しない（対応外 arch での直書きはコンパイルエラー）。
        ///
        /// 対応 arch では任意の正の番号を書ける（値の正しさは固定値テストで照合する）。0 以下は
        /// `const` の初期化式で評価される `assert!` によりコンパイルエラーになる（`SYS_*` はすべて
        /// `const` 項目のため、実行時に到達しない）。
        #[cfg(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        pub(super) const fn new(nr: i64) -> Self {
            assert!(nr > 0, "syscall number must be positive");
            Self(nr)
        }

        /// 対応外 arch の番号定義。`get` は常に `Unsupported` を返し、番号は発行されない。
        #[cfg(not(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        pub(super) const UNSUPPORTED: Self = Self(());

        /// 発行可能な番号を返す。対応外 arch では `Err(Unsupported)`（fail-closed）。
        #[cfg(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        #[expect(
            clippy::unnecessary_wraps,
            reason = "対応外 arch と同じシグネチャにして呼び出し側の `?` を強制するため"
        )]
        pub(super) const fn get(self) -> Result<SyscallNumber, SysError> {
            Ok(SyscallNumber(self.0))
        }

        /// 対応外 arch では番号を持たないため常に `Unsupported`。
        #[cfg(not(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        pub(super) const fn get(self) -> Result<SyscallNumber, SysError> {
            let () = self.0;
            Err(SysError::Unsupported)
        }
    }
}
use sysno::{ArchSysNo, SyscallNumber};

/// アーキテクチャごとの clone / mount / open 定数。値が同一でも arch ごとに個別定義する。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
mod consts {
    use super::ArchSysNo;
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
    pub const SYS_PIVOT_ROOT: ArchSysNo = ArchSysNo::new(155);
    // arch/x86/entry/syscalls/syscall_64.tbl の `close_range`（436）。
    pub const SYS_CLOSE_RANGE: ArchSysNo = ArchSysNo::new(436);
    // arch/x86/entry/syscalls/syscall_64.tbl の `move_mount`・`fsopen`・`fsconfig`・`fsmount`（新マウント API。Linux 5.2 以降。SUP-12・TASK-169 追補・#1472）。
    pub const SYS_MOVE_MOUNT: ArchSysNo = ArchSysNo::new(429);
    pub const SYS_FSOPEN: ArchSysNo = ArchSysNo::new(430);
    pub const SYS_FSCONFIG: ArchSysNo = ArchSysNo::new(431);
    pub const SYS_FSMOUNT: ArchSysNo = ArchSysNo::new(432);
    // arch/x86/entry/syscalls/syscall_64.tbl の `open_tree`（428。#1659）。
    pub const SYS_OPEN_TREE: ArchSysNo = ArchSysNo::new(428);
    // include/uapi/linux/mount.h の `FSOPEN_CLOEXEC`・`FSMOUNT_CLOEXEC`・`fsconfig_command`・`MOUNT_ATTR_*`（`MOUNT_ATTR_STRICTATIME` を含む）・`MOVE_MOUNT_*`（全アーキテクチャ共通）。
    pub const FSOPEN_CLOEXEC: u32 = 1;
    pub const FSMOUNT_CLOEXEC: u32 = 1;
    pub const FSCONFIG_SET_FLAG: u32 = 0;
    pub const FSCONFIG_SET_STRING: u32 = 1;
    pub const FSCONFIG_CMD_CREATE: u32 = 6;
    pub const MOUNT_ATTR_RDONLY: u32 = 1;
    pub const MOUNT_ATTR_NOSUID: u32 = 2;
    pub const MOUNT_ATTR_NODEV: u32 = 4;
    pub const MOUNT_ATTR_NOEXEC: u32 = 8;
    pub const MOUNT_ATTR_STRICTATIME: u32 = 0x20;
    pub const MOVE_MOUNT_F_EMPTY_PATH: u32 = 4;
    pub const MOVE_MOUNT_T_EMPTY_PATH: u32 = 64;
    // include/uapi/linux/mount.h の `OPEN_TREE_CLONE`（1 << 0）・`OPEN_TREE_CLOEXEC`（`O_CLOEXEC` と同値で、`FSOPEN_CLOEXEC` の 1 とは別）と、
    // include/uapi/linux/fcntl.h の `AT_EMPTY_PATH`（`open_tree` 用に u32 で持つ）。rootless のデバイスノード bind 用（#1659・CORE-6・SEC-5）。
    pub const OPEN_TREE_CLONE: u32 = 1;
    pub const OPEN_TREE_CLOEXEC: u32 = 0o2_000_000;
    pub const OPEN_TREE_AT_EMPTY_PATH: u32 = 0x1000;
    // mount_setattr(2)（#1676・rootfs の nodev。CORE-1・SEC-1）。arch/x86/entry/syscalls/syscall_64.tbl の 442。
    // `AT_EMPTY_PATH` は `mount_setattr` 用に u32 で持つ。
    pub const SYS_MOUNT_SETATTR: ArchSysNo = ArchSysNo::new(442);
    pub const MOUNT_SETATTR_AT_EMPTY_PATH: u32 = 0x1000;
    // arch/x86/entry/syscalls/syscall_64.tbl の `pidfd_send_signal`（424）・`pidfd_open`（434）。
    pub const SYS_PIDFD_SEND_SIGNAL: ArchSysNo = ArchSysNo::new(424);
    pub const SYS_PIDFD_OPEN: ArchSysNo = ArchSysNo::new(434);
    // include/uapi/linux/close_range.h の `CLOSE_RANGE_CLOEXEC`（`1U << 2`）。
    pub const CLOSE_RANGE_CLOEXEC: i64 = 4;
    // include/uapi/linux/wait.h の `WNOHANG`。
    pub const WNOHANG: i32 = 1;
    // include/uapi/asm-generic/signal.h の `SIGKILL`・`SIGPIPE`（x86_64 は上書きしない）。
    pub const SIGKILL: i32 = 9;
    pub const SIGPIPE: i32 = 13;
    // arch/x86/include/uapi/asm/signal.h の `SIGCHLD`（結合試験の `set_child_signal_ignored_for_test` だけが使う）。
    #[cfg_attr(not(feature = "exec-test-support"), allow(dead_code))]
    pub const SIGCHLD: i32 = 17;
    // include/uapi/asm-generic/fcntl.h（x86_64 は上書きしない）。
    pub const O_DIRECTORY: i32 = 0o200_000;
    pub const O_NOFOLLOW: i32 = 0o400_000;
    pub const O_CLOEXEC: i32 = 0o2_000_000;
    pub const O_PATH: i32 = 0o10_000_000;
    // include/uapi/asm-generic/fcntl.h の `O_NONBLOCK`（x86_64 は上書きしない）。
    pub const O_NONBLOCK: i32 = 0o4_000;
    pub const O_RDWR: i32 = 2;
    // include/uapi/asm-generic/fcntl.h の `O_NOCTTY`（x86_64 は上書きしない。TASK-163 追補・#1459）。
    pub const O_NOCTTY: i32 = 0o400;
    // include/uapi/asm-generic/fcntl.h の `O_RDONLY`・`O_WRONLY`（全アーキテクチャ共通）。
    pub const O_RDONLY: i32 = 0;
    pub const O_WRONLY: i32 = 1;
    // include/uapi/asm-generic/fcntl.h の `O_CREAT`・`O_EXCL`（x86_64・arm64 とも上書きしない）。
    pub const O_CREAT: i32 = 0o100;
    pub const O_EXCL: i32 = 0o200;
    // include/uapi/linux/fcntl.h の `AT_REMOVEDIR`（全アーキテクチャ共通）。
    pub const AT_REMOVEDIR: i32 = 0x200;
    // include/uapi/asm-generic/errno-base.h・errno.h の EBUSY・ENOTEMPTY（cgroup 操作の分類用）。
    pub const EBUSY: i32 = 16;
    pub const ENOTEMPTY: i32 = 39;
    // include/uapi/linux/magic.h の `CGROUP2_SUPER_MAGIC`（"cgrp"）。
    pub const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
    // include/linux/statfs.h の `ST_NOEXEC`・`ST_VALID`（`statfs.f_flags`。全アーキテクチャ共通）。
    pub const ST_NOEXEC: i64 = 0x0008;
    // include/linux/statfs.h の `ST_NODEV`（#1676・rootfs の nodev の事後検証）。
    pub const ST_NODEV: i64 = 0x0004;
    pub const ST_VALID: i64 = 0x0020;
    // arch/x86/entry/syscalls/syscall_64.tbl の `execveat`。
    pub const SYS_EXECVEAT: ArchSysNo = ArchSysNo::new(322);
    // include/uapi/linux/fcntl.h の `AT_EMPTY_PATH`（全アーキテクチャ共通）。
    pub const AT_EMPTY_PATH: i64 = 0x1000;
    // include/uapi/linux/fcntl.h の `AT_EXECVE_CHECK`（Linux 6.14+。全アーキテクチャ共通）。
    pub const AT_EXECVE_CHECK: i64 = 0x10000;
    // arch/x86/entry/syscalls/syscall_64.tbl の `memfd_create`。
    pub const SYS_MEMFD_CREATE: ArchSysNo = ArchSysNo::new(319);
    // include/uapi/linux/memfd.h の `MFD_CLOEXEC`・`MFD_ALLOW_SEALING`・`MFD_EXEC`（6.3+。全アーキテクチャ共通）。
    pub const MFD_CLOEXEC: u32 = 0x1;
    pub const MFD_ALLOW_SEALING: u32 = 0x2;
    pub const MFD_EXEC: u32 = 0x10;
    // include/uapi/linux/fcntl.h の `F_ADD_SEALS`・`F_GET_SEALS`（`F_LINUX_SPECIFIC_BASE` 1024 + 9・+ 10）。
    pub const F_ADD_SEALS: i32 = 1033;
    pub const F_GET_SEALS: i32 = 1034;
    // include/uapi/linux/fcntl.h の `F_SEAL_SEAL`・`F_SEAL_SHRINK`・`F_SEAL_GROW`・`F_SEAL_WRITE`・`F_SEAL_EXEC`（6.3+）。
    pub const F_SEAL_SEAL: u32 = 0x1;
    pub const F_SEAL_SHRINK: u32 = 0x2;
    pub const F_SEAL_GROW: u32 = 0x4;
    pub const F_SEAL_WRITE: u32 = 0x8;
    #[cfg_attr(not(test), allow(dead_code))]
    pub const F_SEAL_EXEC: u32 = 0x20;
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
    pub const SYS_LANDLOCK_CREATE_RULESET: ArchSysNo = ArchSysNo::new(444);
    // include/uapi/linux/landlock.h の `LANDLOCK_CREATE_RULESET_VERSION`（`1U << 0`）。
    pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    // arch/x86/entry/syscalls/syscall_64.tbl の `landlock_add_rule`（445）・`landlock_restrict_self`（446）。
    pub const SYS_LANDLOCK_ADD_RULE: ArchSysNo = ArchSysNo::new(445);
    pub const SYS_LANDLOCK_RESTRICT_SELF: ArchSysNo = ArchSysNo::new(446);
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
    // errno-base.h の ENOMEM（12）・ENFILE（23）・EMFILE（24）（`pidfd_open` の失敗理由の分類。#1617）。
    pub const ENOMEM: i32 = 12;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    // include/uapi/linux/stat.h の `S_IFCHR`（文字デバイス。全アーキテクチャ共通）。
    pub const S_IFCHR: u32 = 0o020_000;

    // include/uapi/linux/prctl.h の `PR_SET_NO_NEW_PRIVS`（38）・`PR_GET_NO_NEW_PRIVS`（39）。
    // 全アーキテクチャ共通の定義だが、他アーキテクチャの定義を流用しないため個別に持つ。
    pub const PR_SET_NO_NEW_PRIVS: i32 = 38;
    pub const PR_GET_NO_NEW_PRIVS: i32 = 39;

    // include/uapi/linux/prctl.h の `PR_GET_DUMPABLE`（3）・`PR_SET_DUMPABLE`（4）。SUP-6・TASK-163.4。
    // 全アーキテクチャ共通の定義だが、他アーキテクチャの定義を流用しないため個別に持つ。
    pub const PR_GET_DUMPABLE: i32 = 3;
    pub const PR_SET_DUMPABLE: i32 = 4;

    // include/uapi/linux/prctl.h の `PR_SET_PDEATHSIG`（1）。SUP-6・REPAIR-5・TASK-163.4。
    // 全アーキテクチャ共通の定義だが、他アーキテクチャの定義を流用しないため個別に持つ。
    pub const PR_SET_PDEATHSIG: i32 = 1;

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
    pub const SYS_CAPGET: ArchSysNo = ArchSysNo::new(125);
    pub const SYS_CAPSET: ArchSysNo = ArchSysNo::new(126);
    // arch/x86/entry/syscalls/syscall_64.tbl の `getgroups`（115）・`setgroups`（116）。補助グループの
    // 消去（SUP-6・SEC-1・SEC-5・TASK-163 追補・#1457）。glibc の `setgroups` は全スレッドへ反映する仕組み
    // （setxid のシグナル配送）を持つため、capability と同じく呼び出しスレッドだけに効く生の syscall を使う。
    pub const SYS_GETGROUPS: ArchSysNo = ArchSysNo::new(115);
    pub const SYS_SETGROUPS: ArchSysNo = ArchSysNo::new(116);
    // 禁止 syscall 遮断の結合試験用プローブ（CORE-5・TASK-38.4・#179）。番号は `crate::seccomp` の
    // テーブルとは独立に、x86_64 は syscall_64.tbl、aarch64 は asm-generic/unistd.h から取る。
    // `PTRACE_CONT`（include/uapi/linux/ptrace.h）は attach を伴わない要求で、`KEXEC_SEGMENT_MAX`
    // （include/linux/kexec.h）は kexec_load の segment 数の上限。
    pub const SYS_PTRACE: ArchSysNo = ArchSysNo::new(101);
    pub const SYS_KEXEC_LOAD: ArchSysNo = ArchSysNo::new(246);
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

#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
mod consts {
    use super::ArchSysNo;
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
    pub const SYS_PIVOT_ROOT: ArchSysNo = ArchSysNo::new(41);
    // include/uapi/asm-generic/unistd.h の `__NR_close_range`（arm64 は asm-generic の表。
    // x86_64 と値が同じでも流用せず個別に定義する）。
    pub const SYS_CLOSE_RANGE: ArchSysNo = ArchSysNo::new(436);
    // include/uapi/asm-generic/unistd.h（aarch64） の `move_mount`・`fsopen`・`fsconfig`・`fsmount`（新マウント API。Linux 5.2 以降。SUP-12・TASK-169 追補・#1472）。
    pub const SYS_MOVE_MOUNT: ArchSysNo = ArchSysNo::new(429);
    pub const SYS_FSOPEN: ArchSysNo = ArchSysNo::new(430);
    pub const SYS_FSCONFIG: ArchSysNo = ArchSysNo::new(431);
    pub const SYS_FSMOUNT: ArchSysNo = ArchSysNo::new(432);
    // include/uapi/asm-generic/unistd.h の `__NR_open_tree`（428。arm64 は asm-generic の表。
    // x86_64 と値が同じでも流用せず個別に定義する。#1659）。
    pub const SYS_OPEN_TREE: ArchSysNo = ArchSysNo::new(428);
    // include/uapi/linux/mount.h の `FSOPEN_CLOEXEC`・`FSMOUNT_CLOEXEC`・`fsconfig_command`・`MOUNT_ATTR_*`（`MOUNT_ATTR_STRICTATIME` を含む）・`MOVE_MOUNT_*`（全アーキテクチャ共通）。
    pub const FSOPEN_CLOEXEC: u32 = 1;
    pub const FSMOUNT_CLOEXEC: u32 = 1;
    pub const FSCONFIG_SET_FLAG: u32 = 0;
    pub const FSCONFIG_SET_STRING: u32 = 1;
    pub const FSCONFIG_CMD_CREATE: u32 = 6;
    pub const MOUNT_ATTR_RDONLY: u32 = 1;
    pub const MOUNT_ATTR_NOSUID: u32 = 2;
    pub const MOUNT_ATTR_NODEV: u32 = 4;
    pub const MOUNT_ATTR_NOEXEC: u32 = 8;
    pub const MOUNT_ATTR_STRICTATIME: u32 = 0x20;
    pub const MOVE_MOUNT_F_EMPTY_PATH: u32 = 4;
    pub const MOVE_MOUNT_T_EMPTY_PATH: u32 = 64;
    // include/uapi/linux/mount.h の `OPEN_TREE_CLONE`（1 << 0）・`OPEN_TREE_CLOEXEC`（`O_CLOEXEC` と同値で、`FSOPEN_CLOEXEC` の 1 とは別）と、
    // include/uapi/linux/fcntl.h の `AT_EMPTY_PATH`（`open_tree` 用に u32 で持つ）。rootless のデバイスノード bind 用（#1659・CORE-6・SEC-5）。
    pub const OPEN_TREE_CLONE: u32 = 1;
    pub const OPEN_TREE_CLOEXEC: u32 = 0o2_000_000;
    pub const OPEN_TREE_AT_EMPTY_PATH: u32 = 0x1000;
    // mount_setattr(2)（#1676・rootfs の nodev。CORE-1・SEC-1）。include/uapi/asm-generic/unistd.h の
    // `__NR_mount_setattr`（442）。`AT_EMPTY_PATH` は `mount_setattr` 用に u32 で持つ。
    pub const SYS_MOUNT_SETATTR: ArchSysNo = ArchSysNo::new(442);
    pub const MOUNT_SETATTR_AT_EMPTY_PATH: u32 = 0x1000;
    // include/uapi/asm-generic/unistd.h の `__NR_pidfd_send_signal`・`__NR_pidfd_open`（arm64 は
    // asm-generic の表。x86_64 と値が同じでも流用せず個別に定義する）。
    pub const SYS_PIDFD_SEND_SIGNAL: ArchSysNo = ArchSysNo::new(424);
    pub const SYS_PIDFD_OPEN: ArchSysNo = ArchSysNo::new(434);
    // include/uapi/linux/close_range.h の `CLOSE_RANGE_CLOEXEC`（`1U << 2`）。
    pub const CLOSE_RANGE_CLOEXEC: i64 = 4;
    // include/uapi/linux/wait.h の `WNOHANG`。
    pub const WNOHANG: i32 = 1;
    // include/uapi/asm-generic/signal.h の `SIGKILL`・`SIGPIPE`（arm64 は上書きしない）。
    pub const SIGKILL: i32 = 9;
    pub const SIGPIPE: i32 = 13;
    // include/uapi/asm-generic/signal.h の `SIGCHLD`（結合試験の `set_child_signal_ignored_for_test` だけが使う）。
    #[cfg_attr(not(feature = "exec-test-support"), allow(dead_code))]
    pub const SIGCHLD: i32 = 17;
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
    // include/uapi/asm-generic/fcntl.h の `O_NOCTTY`（arm64 の arch/arm64/include/uapi/asm/fcntl.h は
    // `O_DIRECTORY`・`O_NOFOLLOW`・`O_DIRECT`・`O_LARGEFILE` だけを上書きし、`O_NOCTTY` は上書きしない）。
    pub const O_NOCTTY: i32 = 0o400;
    // include/uapi/asm-generic/fcntl.h の `O_RDONLY`・`O_WRONLY`（全アーキテクチャ共通）。
    pub const O_RDONLY: i32 = 0;
    pub const O_WRONLY: i32 = 1;
    // include/uapi/asm-generic/fcntl.h の `O_CREAT`・`O_EXCL`（x86_64・arm64 とも上書きしない）。
    pub const O_CREAT: i32 = 0o100;
    pub const O_EXCL: i32 = 0o200;
    // include/uapi/linux/fcntl.h の `AT_REMOVEDIR`（全アーキテクチャ共通）。
    pub const AT_REMOVEDIR: i32 = 0x200;
    // include/uapi/asm-generic/errno-base.h・errno.h の EBUSY・ENOTEMPTY（cgroup 操作の分類用）。
    pub const EBUSY: i32 = 16;
    pub const ENOTEMPTY: i32 = 39;
    // include/uapi/linux/magic.h の `CGROUP2_SUPER_MAGIC`（"cgrp"）。
    pub const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
    // include/linux/statfs.h の `ST_NOEXEC`・`ST_VALID`（`statfs.f_flags`。全アーキテクチャ共通）。
    pub const ST_NOEXEC: i64 = 0x0008;
    // include/linux/statfs.h の `ST_NODEV`（#1676・rootfs の nodev の事後検証）。
    pub const ST_NODEV: i64 = 0x0004;
    pub const ST_VALID: i64 = 0x0020;
    // include/uapi/asm-generic/unistd.h の `__NR_execveat`（arm64 は asm-generic の表。
    // x86_64 の 322 を流用しない）。
    pub const SYS_EXECVEAT: ArchSysNo = ArchSysNo::new(281);
    // include/uapi/linux/fcntl.h の `AT_EMPTY_PATH`（全アーキテクチャ共通）。
    pub const AT_EMPTY_PATH: i64 = 0x1000;
    // include/uapi/linux/fcntl.h の `AT_EXECVE_CHECK`（Linux 6.14+。全アーキテクチャ共通）。
    pub const AT_EXECVE_CHECK: i64 = 0x10000;
    // include/uapi/asm-generic/unistd.h の `__NR_memfd_create`（aarch64 は asm-generic 表を使う）。
    pub const SYS_MEMFD_CREATE: ArchSysNo = ArchSysNo::new(279);
    // include/uapi/linux/memfd.h の `MFD_CLOEXEC`・`MFD_ALLOW_SEALING`・`MFD_EXEC`（6.3+。全アーキテクチャ共通）。
    pub const MFD_CLOEXEC: u32 = 0x1;
    pub const MFD_ALLOW_SEALING: u32 = 0x2;
    pub const MFD_EXEC: u32 = 0x10;
    // include/uapi/linux/fcntl.h の `F_ADD_SEALS`・`F_GET_SEALS`（`F_LINUX_SPECIFIC_BASE` 1024 + 9・+ 10）。
    pub const F_ADD_SEALS: i32 = 1033;
    pub const F_GET_SEALS: i32 = 1034;
    // include/uapi/linux/fcntl.h の `F_SEAL_SEAL`・`F_SEAL_SHRINK`・`F_SEAL_GROW`・`F_SEAL_WRITE`・`F_SEAL_EXEC`（6.3+）。
    pub const F_SEAL_SEAL: u32 = 0x1;
    pub const F_SEAL_SHRINK: u32 = 0x2;
    pub const F_SEAL_GROW: u32 = 0x4;
    pub const F_SEAL_WRITE: u32 = 0x8;
    #[cfg_attr(not(test), allow(dead_code))]
    pub const F_SEAL_EXEC: u32 = 0x20;
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
    pub const SYS_LANDLOCK_CREATE_RULESET: ArchSysNo = ArchSysNo::new(444);
    // include/uapi/linux/landlock.h の `LANDLOCK_CREATE_RULESET_VERSION`（`1U << 0`）。
    pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    // include/uapi/asm-generic/unistd.h の `landlock_add_rule`（445）・`landlock_restrict_self`（446）。
    pub const SYS_LANDLOCK_ADD_RULE: ArchSysNo = ArchSysNo::new(445);
    pub const SYS_LANDLOCK_RESTRICT_SELF: ArchSysNo = ArchSysNo::new(446);
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
    // errno-base.h の ENOMEM（12）・ENFILE（23）・EMFILE（24）（`pidfd_open` の失敗理由の分類。#1617）。
    pub const ENOMEM: i32 = 12;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    // include/uapi/linux/stat.h の `S_IFCHR`（文字デバイス。全アーキテクチャ共通）。
    pub const S_IFCHR: u32 = 0o020_000;

    // include/uapi/linux/prctl.h の `PR_SET_NO_NEW_PRIVS`（38）・`PR_GET_NO_NEW_PRIVS`（39）。
    // 全アーキテクチャ共通の定義だが、他アーキテクチャの定義を流用しないため個別に持つ。
    pub const PR_SET_NO_NEW_PRIVS: i32 = 38;
    pub const PR_GET_NO_NEW_PRIVS: i32 = 39;

    // include/uapi/linux/prctl.h の `PR_GET_DUMPABLE`（3）・`PR_SET_DUMPABLE`（4）。SUP-6・TASK-163.4。
    // 全アーキテクチャ共通の定義だが、他アーキテクチャの定義を流用しないため個別に持つ。
    pub const PR_GET_DUMPABLE: i32 = 3;
    pub const PR_SET_DUMPABLE: i32 = 4;

    // include/uapi/linux/prctl.h の `PR_SET_PDEATHSIG`（1）。SUP-6・REPAIR-5・TASK-163.4。
    // 全アーキテクチャ共通の定義だが、他アーキテクチャの定義を流用しないため個別に持つ。
    pub const PR_SET_PDEATHSIG: i32 = 1;

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
    pub const SYS_CAPGET: ArchSysNo = ArchSysNo::new(90);
    pub const SYS_CAPSET: ArchSysNo = ArchSysNo::new(91);
    // include/uapi/asm-generic/unistd.h の `getgroups`（158）・`setgroups`（159）。TASK-163 追補・#1457。
    pub const SYS_GETGROUPS: ArchSysNo = ArchSysNo::new(158);
    pub const SYS_SETGROUPS: ArchSysNo = ArchSysNo::new(159);
    // 禁止 syscall 遮断の結合試験用プローブ（CORE-5・TASK-38.4・#179）。番号は `crate::seccomp` の
    // テーブルとは独立に、x86_64 は syscall_64.tbl、aarch64 は asm-generic/unistd.h から取る。
    // `PTRACE_CONT`（include/uapi/linux/ptrace.h）は attach を伴わない要求で、`KEXEC_SEGMENT_MAX`
    // （include/linux/kexec.h）は kexec_load の segment 数の上限。
    pub const SYS_PTRACE: ArchSysNo = ArchSysNo::new(117);
    pub const SYS_KEXEC_LOAD: ArchSysNo = ArchSysNo::new(104);
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
#[cfg(not(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod consts {
    use super::ArchSysNo;
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
    pub const SYS_PIVOT_ROOT: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const SYS_CLOSE_RANGE: ArchSysNo = ArchSysNo::UNSUPPORTED;
    // 対応外アーキテクチャ（各ラッパーが SUPPORTED で弾く） の `move_mount`・`fsopen`・`fsconfig`・`fsmount`（新マウント API。Linux 5.2 以降。SUP-12・TASK-169 追補・#1472）。
    pub const SYS_MOVE_MOUNT: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const SYS_FSOPEN: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const SYS_FSCONFIG: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const SYS_FSMOUNT: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const SYS_OPEN_TREE: ArchSysNo = ArchSysNo::UNSUPPORTED;
    // include/uapi/linux/mount.h の `FSOPEN_CLOEXEC`・`FSMOUNT_CLOEXEC`・`fsconfig_command`・`MOUNT_ATTR_*`（`MOUNT_ATTR_STRICTATIME` を含む）・`MOVE_MOUNT_*`（全アーキテクチャ共通）。
    pub const FSOPEN_CLOEXEC: u32 = 0;
    pub const FSMOUNT_CLOEXEC: u32 = 0;
    pub const FSCONFIG_SET_FLAG: u32 = 0;
    pub const FSCONFIG_SET_STRING: u32 = 0;
    pub const FSCONFIG_CMD_CREATE: u32 = 0;
    pub const MOUNT_ATTR_RDONLY: u32 = 0;
    pub const MOUNT_ATTR_NOSUID: u32 = 0;
    pub const MOUNT_ATTR_NODEV: u32 = 0;
    pub const MOUNT_ATTR_NOEXEC: u32 = 0;
    pub const MOUNT_ATTR_STRICTATIME: u32 = 0;
    pub const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0;
    pub const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0;
    // 対応外アーキテクチャ（各ラッパーが SUPPORTED で弾く）の `open_tree` 用定数。
    pub const OPEN_TREE_CLONE: u32 = 0;
    pub const OPEN_TREE_CLOEXEC: u32 = 0;
    pub const OPEN_TREE_AT_EMPTY_PATH: u32 = 0;
    pub const SYS_MOUNT_SETATTR: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const MOUNT_SETATTR_AT_EMPTY_PATH: u32 = 0;
    pub const SYS_PIDFD_SEND_SIGNAL: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const SYS_PIDFD_OPEN: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const CLOSE_RANGE_CLOEXEC: i64 = 0;
    pub const WNOHANG: i32 = 0;
    pub const SIGKILL: i32 = 0;
    pub const SIGPIPE: i32 = 0;
    #[cfg_attr(not(feature = "exec-test-support"), allow(dead_code))]
    pub const SIGCHLD: i32 = 0;
    pub const O_DIRECTORY: i32 = 0;
    pub const O_NOFOLLOW: i32 = 0;
    pub const O_CLOEXEC: i32 = 0;
    pub const O_PATH: i32 = 0;
    pub const O_NONBLOCK: i32 = 0;
    pub const O_RDWR: i32 = 0;
    pub const O_NOCTTY: i32 = 0;
    pub const O_RDONLY: i32 = 0;
    pub const O_WRONLY: i32 = 0;
    pub const O_CREAT: i32 = 0;
    pub const O_EXCL: i32 = 0;
    pub const AT_REMOVEDIR: i32 = 0;
    pub const EBUSY: i32 = -16;
    pub const ENOTEMPTY: i32 = -17;
    pub const CGROUP2_SUPER_MAGIC: i64 = 0;
    pub const ST_NOEXEC: i64 = 0;
    pub const ST_NODEV: i64 = 0;
    pub const ST_VALID: i64 = 0;
    pub const SYS_EXECVEAT: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const AT_EMPTY_PATH: i64 = 0;
    pub const AT_EXECVE_CHECK: i64 = 0;
    pub const SYS_MEMFD_CREATE: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const MFD_CLOEXEC: u32 = 0;
    pub const MFD_ALLOW_SEALING: u32 = 0;
    pub const MFD_EXEC: u32 = 0;
    pub const F_ADD_SEALS: i32 = 0;
    pub const F_GET_SEALS: i32 = 0;
    pub const F_SEAL_SEAL: u32 = 0;
    pub const F_SEAL_SHRINK: u32 = 0;
    pub const F_SEAL_GROW: u32 = 0;
    pub const F_SEAL_WRITE: u32 = 0;
    #[cfg_attr(not(test), allow(dead_code))]
    pub const F_SEAL_EXEC: u32 = 0;
    pub const F_SETFD: i32 = 0;
    pub const FD_CLOEXEC: i32 = 0;
    pub const F_DUPFD_CLOEXEC: i32 = 0;
    pub const EPERM: i32 = -1;
    pub const ENOENT: i32 = -2;
    pub const EACCES: i32 = -3;
    pub const EEXIST: i32 = -7;
    pub const ENOTDIR: i32 = -4;
    pub const EINVAL: i32 = -5;
    pub const SYS_LANDLOCK_CREATE_RULESET: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 0;
    pub const SYS_LANDLOCK_ADD_RULE: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const SYS_LANDLOCK_RESTRICT_SELF: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 0;
    pub const EOPNOTSUPP: i32 = -15;
    pub const ELOOP: i32 = -6;
    pub const ESRCH: i32 = -8;
    pub const ECHILD: i32 = -14;
    pub const EINTR: i32 = -9;
    pub const E2BIG: i32 = -10;
    pub const ENOEXEC: i32 = -11;
    pub const ENOSYS: i32 = -12;
    pub const ENOMEM: i32 = -18;
    pub const ENFILE: i32 = -19;
    pub const EMFILE: i32 = -20;
    pub const EBADF: i32 = -13;
    pub const S_IFCHR: u32 = 0;

    pub const PR_SET_NO_NEW_PRIVS: i32 = 0;
    pub const PR_GET_NO_NEW_PRIVS: i32 = 0;
    pub const PR_GET_DUMPABLE: i32 = 0;
    pub const PR_SET_DUMPABLE: i32 = 0;
    pub const PR_SET_PDEATHSIG: i32 = 0;

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
    pub const SYS_CAPGET: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const SYS_CAPSET: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const SYS_GETGROUPS: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const SYS_SETGROUPS: ArchSysNo = ArchSysNo::UNSUPPORTED;
    // 禁止 syscall 遮断の結合試験用プローブ（CORE-5・TASK-38.4・#179）。番号は `crate::seccomp` の
    // テーブルとは独立に、x86_64 は syscall_64.tbl、aarch64 は asm-generic/unistd.h から取る。
    // `PTRACE_CONT`（include/uapi/linux/ptrace.h）は attach を伴わない要求で、`KEXEC_SEGMENT_MAX`
    // （include/linux/kexec.h）は kexec_load の segment 数の上限。
    pub const SYS_PTRACE: ArchSysNo = ArchSysNo::UNSUPPORTED;
    pub const SYS_KEXEC_LOAD: ArchSysNo = ArchSysNo::UNSUPPORTED;
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
    // 第 1 引数は `repr(transparent)` の `SyscallNumber`（中身 i64）で `long` と ABI が同一。
    // 番号は `ArchSysNo::get` からしか得られない（#1619。対応外 arch では常に `Unsupported`）。
    fn syscall(number: SyscallNumber, ...) -> i64;
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
    // SAFETY（宣言そのものの妥当性）: `pid_t setsid(void)`（Linux の `pid_t` は i32。失敗は `(pid_t)-1`）。
    // libc のラッパーを使い、arch 別の syscall 番号を増やさない（SUP-6・TASK-163 追補・#1456）。
    fn setsid() -> i32;
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

/// `fstatfs(2)` の出力バッファ（x86_64）。`struct statfs` は `f_type`・`f_bsize`・`f_blocks`・`f_bfree`・
/// `f_bavail`・`f_files`・`f_ffree`・`f_fsid`（`int` × 2）・`f_namelen`・`f_frsize`・`f_flags`・`f_spare[4]` の順で
/// 全体 120 バイト（arch/x86/include/uapi/asm/statfs.h → asm-generic/statfs.h の 64 ビット版。各語は `long`）。
/// 使うのは `f_type` と `f_flags`（`f_flags` は先頭から 11 語目 = オフセット 80）だけで、間は名前を付けずに確保する。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
struct StatFs {
    f_type: i64,
    _before_flags: [i64; 9],
    f_flags: i64,
    _spare: [i64; 4],
}

/// `fstatfs(2)` の出力バッファ（aarch64）。レイアウトは asm-generic/statfs.h の 64 ビット版で、
/// x86_64 と同値だが他 arch の定義を流用せず個別に持つ（`f_type` が先頭・`f_flags` がオフセット 80、全体 120 バイト）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
#[repr(C)]
struct StatFs {
    f_type: i64,
    _before_flags: [i64; 9],
    f_flags: i64,
    _spare: [i64; 4],
}

/// 対応外アーキテクチャ: レイアウト未確認のためラッパーは `Unsupported` を返し、カーネルには渡さない。
#[cfg(not(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[repr(C)]
struct StatFs {
    f_type: i64,
    f_flags: i64,
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

/// tmpfs の `statfs.f_type`（include/uapi/linux/magic.h の `TMPFS_MAGIC`。アーキテクチャ非依存）。
pub(crate) const TMPFS_MAGIC: i64 = 0x0102_1994;

/// procfs の `statfs.f_type`（include/uapi/linux/magic.h の `PROC_SUPER_MAGIC`。アーキテクチャ非依存）。
/// `crate::exec` の exec 再適用が、スレッド数の取得元が本物の procfs であることを確かめるのに使う（SUP-6）。
pub(crate) const PROC_MAGIC: i64 = 0x9fa0;

/// [`mount_tmpfs_on`] に渡せるフラグ。可変なのは読み取り専用と実行許可の 2 値だけで、
/// `nosuid`・`nodev` は常に付与する（任意のビットを渡せない型にして SEC-1 の fail-closed を保つ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TmpfsMountFlags {
    pub(crate) read_only: bool,
    pub(crate) exec: bool,
}

impl TmpfsMountFlags {
    /// `fsmount(2)` の `attr_flags` 値（`MOUNT_ATTR_NOSUID|MOUNT_ATTR_NODEV` は固定）。
    /// `MS_*` と数値が同じでも別の名前つき定数から組む（流用しない）。
    pub(crate) fn attr_bits(self) -> u32 {
        let mut f = consts::MOUNT_ATTR_NOSUID | consts::MOUNT_ATTR_NODEV;
        if self.read_only {
            f |= consts::MOUNT_ATTR_RDONLY;
        }
        if !self.exec {
            f |= consts::MOUNT_ATTR_NOEXEC;
        }
        f
    }
}

/// [`mount_tmpfs_on`] の作成パラメータ。値はすべて整数・真偽値で、カーネルへ渡す文字列は
/// 本モジュール内で整数から生成する（利用者文字列・カンマ区切りの data を渡す経路を持たない。SEC-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TmpfsCreate {
    /// ルートディレクトリのモード（8 進で `mode=` に渡す）。
    pub(crate) mode: u32,
    /// サイズ（バイト）。`None` はカーネル既定。
    pub(crate) size: Option<u64>,
    pub(crate) flags: TmpfsMountFlags,
}

/// 新マウント API 失敗時の errno。`ENOSYS`（Linux 5.2 未満）は縮退せず [`SysError::Unsupported`] に写す。
// テストビルドでは `crate::exec` の dry-run 差し込み点が呼ぶ側を差し替えるため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
fn new_mount_api_error() -> SysError {
    match last_error() {
        SysError::Os(e) if e == ENOSYS => SysError::Unsupported,
        other => other,
    }
}

/// `fsconfig(2)` の戻り値を `Result` にする。
#[cfg_attr(test, allow(dead_code))]
fn fsconfig_result(rc: i64) -> Result<(), SysError> {
    if rc == -1 {
        Err(new_mount_api_error())
    } else {
        Ok(())
    }
}

/// fd を返す新マウント API の戻り値（`fsopen` / `fsmount` / `open_tree`）を検証して `OwnedFd` にする。
#[cfg_attr(test, allow(dead_code))]
fn new_mount_api_fd(rc: i64) -> Result<OwnedFd, SysError> {
    if rc == -1 {
        return Err(new_mount_api_error());
    }
    let fd = i32::try_from(rc).map_err(|_| SysError::Os(EINVAL))?;
    if fd < 0 {
        return Err(SysError::Os(EINVAL));
    }
    // SAFETY: `fd` は直前に成功した新マウント API の syscall が返した、他に所有者のいない有効な fd
    // （`fsopen` / `fsmount` / `open_tree` の戻り値）。`OwnedFd` が唯一の所有者になる（二重 close なし）。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `fsconfig(2)` へ渡す 1 件のパラメータ。key は静的文字列、value は整数から生成した数字のみ
/// （NUL・カンマを含み得ない。SEC-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum FsconfigParam {
    /// `FSCONFIG_SET_STRING`（キーと文字列値）。
    String(&'static CStr, CString),
    /// `FSCONFIG_SET_FLAG`（値なしのフラグ）。
    Flag(&'static CStr),
}

/// tmpfs 作成の内部パラメータ。`mount_tmpfs_impl` の唯一の入力で、本モジュールの外へ公開しない。
///
/// 生成は [`TmpfsCreate`]（`TmpfsMountFlags::attr_bits` 由来で nodev 固定）と [`DevTmpfsCreate`]
/// （`/dev` 専用の固定値）からの変換だけに限り、呼び出し側が任意の `attr` ビットを渡す経路を作らない
/// （SEC-1・CORE-1・REPAIR-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct TmpfsParams {
    mode: u32,
    size: Option<u64>,
    read_only: bool,
    /// `fsmount(2)` の `attr_flags`。名前つき定数の和のみ。
    attr: u32,
}

impl From<TmpfsCreate> for TmpfsParams {
    fn from(create: TmpfsCreate) -> Self {
        Self {
            mode: create.mode,
            size: create.size,
            read_only: create.flags.read_only,
            attr: create.flags.attr_bits(),
        }
    }
}

impl From<DevTmpfsCreate> for TmpfsParams {
    fn from(_: DevTmpfsCreate) -> Self {
        Self {
            mode: DevTmpfsCreate::MODE,
            size: Some(DevTmpfsCreate::SIZE_BYTES),
            read_only: false,
            attr: DevTmpfsCreate::ATTR_BITS,
        }
    }
}

impl TmpfsParams {
    /// `fsconfig` へ流すパラメータ列（`source` → `mode` → `size`（`Some` のみ）→ `ro`（読み取り専用のみ））。
    /// 実マウントなしでキーと値を単体テストで照合するため純関数にしてある。
    #[cfg_attr(test, allow(dead_code))]
    fn fsconfig_params(&self) -> Result<Vec<FsconfigParam>, SysError> {
        let mut params = vec![FsconfigParam::String(
            c"source",
            CString::new("tmpfs").map_err(|_| SysError::Os(EINVAL))?,
        )];
        // 値は整数から生成した数字のみで、NUL・カンマを含み得ない。
        let mode = CString::new(format!("{:o}", self.mode)).map_err(|_| SysError::Os(EINVAL))?;
        params.push(FsconfigParam::String(c"mode", mode));
        if let Some(size) = self.size {
            let size = CString::new(size.to_string()).map_err(|_| SysError::Os(EINVAL))?;
            params.push(FsconfigParam::String(c"size", size));
        }
        if self.read_only {
            params.push(FsconfigParam::Flag(c"ro"));
        }
        Ok(params)
    }
}

/// rootfs の `/dev` に載せる tmpfs の固定作成パラメータ（TASK-29 追補・#1652。設計ドラフト
/// `docs/design/dev-default-mounts.md` 3.1・オーナー判断 2026-10-10）。
///
/// 値は固定で、利用者から受け取る経路を持たない。`nodev` を外せるのは本型だけで、[`TmpfsMountFlags`]
/// （`nodev` 固定）は変更しない（SEC-1）。出典は runc v1.5.2 `libcontainer/specconv/example.go` の
/// `nosuid,strictatime,mode=755,size=65536k`。
///
/// - `nodev` を付けない: tmpfs の上に作る文字デバイスを開けるようにするため。
/// - `noexec` を付けない: runc に合わせる。`noexec` のマウント上のデバイスノードは `mmap(PROT_EXEC)` が
///   `EPERM` になり `/dev/zero` の実行可能マップが壊れるおそれがあり、付ける根拠となるビヘイビアも無い。
/// - `strictatime` を付ける: runc と同じ。既定の relatime に任せず明示する。
///
/// その結果、コンテナの `/dev` は書き込み可能かつ実行可能な領域になり、読み取り専用でない rootfs と同じ扱いに
/// なる（`root.readonly=true` でも `/dev` は書き込める。Landlock も `/dev` に `WRITE` を許す。#1664・#1672 の
/// 事後監査）。新たなデバイスノードの作成は Landlock の `MAKE_CHAR`・`MAKE_BLOCK` 不許可が止める（SEC-1）。
///
/// `crate::exec::create_default_devices` が呼ぶ（#1653）。付け替え先は `exec::devices` の検証済みの型からしか
/// 渡さない（#1664 の事後監査 P2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DevTmpfsCreate {
    _private: (),
}

impl DevTmpfsCreate {
    const MODE: u32 = 0o755;
    const SIZE_BYTES: u64 = 64 * 1024 * 1024;
    const ATTR_BITS: u32 = consts::MOUNT_ATTR_NOSUID | consts::MOUNT_ATTR_STRICTATIME;

    /// 固定値の作成パラメータを返す。
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// ルートディレクトリのモード（0o755）。dry-run の記録（`cfg(test)`）だけが読む。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn mode(&self) -> u32 {
        Self::MODE
    }

    /// サイズ（バイト。64 MiB）。dry-run の記録（`cfg(test)`）だけが読む。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn size_bytes(&self) -> u64 {
        Self::SIZE_BYTES
    }

    /// `fsmount(2)` の `attr_flags`（`MOUNT_ATTR_NOSUID|MOUNT_ATTR_STRICTATIME`。nodev・noexec・rdonly なし）。
    /// dry-run の記録（`cfg(test)`）だけが読む。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn attr_bits(&self) -> u32 {
        Self::ATTR_BITS
    }
}

/// `target_dir`（検証済みのマウント先ディレクトリの O_PATH fd）の上へ、新マウント API で tmpfs を載せ、
/// 載せたマウントのルートを指す fd（close-on-exec）を返す。
///
/// `fsopen("tmpfs")` → `fsconfig`（`source`・`mode`・`size`・`ro` をキー単位で指定）→ `fsconfig(CMD_CREATE)`
/// → `fsmount` → `move_mount(.., target_dir, "", T_EMPTY_PATH)`。マウント先は fd のまま `move_mount` へ渡すため、
/// パス文字列の再解決・symlink 追従が起きず、`mount(2)` の `data` 文字列も使わない。返す fd は自分のマウントを
/// 一意に指し、`crate::exec::mount_tmpfs` が事後検証と失敗時の後始末（解除対象の特定）に使う
/// （SUP-12・TASK-169 追補・#1472）。
///
/// 必要なカーネルは Linux 5.2 以降。未対応（`ENOSYS`）は [`SysError::Unsupported`] で返し、`mount(2)` へは
/// 縮退しない（fail-closed）。途中で失敗した場合、未接続の中間 fd は drop で閉じ、マウントは破棄される。
// テストビルドでは `crate::exec` の dry-run 差し込み点が本関数を呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn mount_tmpfs_on(
    target_dir: BorrowedFd<'_>,
    create: TmpfsCreate,
) -> Result<OwnedFd, SysError> {
    mount_tmpfs_impl(target_dir, &TmpfsParams::from(create))
}

/// `/dev` 用の nodev なし tmpfs を [`mount_tmpfs_on`] と同じ契約で載せる（TASK-29 追補・#1652）。
///
/// マウント先は検証済みの `O_PATH` fd で受け取り、パス文字列の再解決も `data` 文字列も使わない。返す fd は
/// 載せたマウントのルートを指す close-on-exec の fd。`ENOSYS` は [`SysError::Unsupported`] で返し縮退しない。
/// 途中失敗は drop で破棄される。Linux 5.2 以降。`crate::exec::create_default_devices` が呼ぶ（#1653）。
// テストビルドでは `crate::exec` の dry-run 差し込み点が本関数を呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn mount_dev_tmpfs_on(
    target_dir: BorrowedFd<'_>,
    create: DevTmpfsCreate,
) -> Result<OwnedFd, SysError> {
    mount_tmpfs_impl(target_dir, &TmpfsParams::from(create))
}

/// [`mount_tmpfs_on`] と [`mount_dev_tmpfs_on`] の共通手順。`params` は型付きの入口からしか作られない。
#[cfg_attr(test, allow(dead_code))]
fn mount_tmpfs_impl(target_dir: BorrowedFd<'_>, params: &TmpfsParams) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let fsconfig_params = params.fsconfig_params()?;
    // syscall 番号は fd を作る前にまとめて取り出す（`ArchSysNo::get` 経由。#1619）。
    let nr_fsopen = consts::SYS_FSOPEN.get()?;
    let nr_fsconfig = consts::SYS_FSCONFIG.get()?;
    let nr_fsmount = consts::SYS_FSMOUNT.get()?;
    // SAFETY: 静的な NUL 終端文字列のポインタと定数フラグのみ。カーネルは呼び出し中に文字列を複写するだけで
    // ポインタを保持しない。可変長引数は register 幅（`i64` / ポインタ）で渡す。成功時の戻り値は新規 fd で、
    // 直後に `new_mount_api_fd` が唯一の所有者にする。
    let fs_fd = new_mount_api_fd(unsafe {
        syscall(
            nr_fsopen,
            c"tmpfs".as_ptr(),
            i64::from(consts::FSOPEN_CLOEXEC),
        )
    })?;
    for param in &fsconfig_params {
        // SAFETY: `fs_fd` は生存中の fsopen の fd。key は静的な NUL 終端文字列、value は `fsconfig_params` が
        // 保持する NUL 終端文字列（文字列形式）または NULL（フラグ形式）で、ループの間生存しカーネルは保持しない。
        // aux は 0。副作用はこの fs コンテキストへのパラメータ設定に限る。
        let rc = unsafe {
            match param {
                FsconfigParam::String(key, value) => syscall(
                    nr_fsconfig,
                    i64::from(fs_fd.as_raw_fd()),
                    i64::from(consts::FSCONFIG_SET_STRING),
                    key.as_ptr(),
                    value.as_ptr(),
                    0i64,
                ),
                FsconfigParam::Flag(key) => syscall(
                    nr_fsconfig,
                    i64::from(fs_fd.as_raw_fd()),
                    i64::from(consts::FSCONFIG_SET_FLAG),
                    key.as_ptr(),
                    core::ptr::null::<core::ffi::c_char>(),
                    0i64,
                ),
            }
        };
        fsconfig_result(rc)?;
    }
    // SAFETY: `fs_fd` は生存中の fsopen の fd。key・value は NULL、aux は 0（`FSCONFIG_CMD_CREATE` の仕様）。
    // 副作用は superblock の作成（まだどこにも接続されない）に限る。
    fsconfig_result(unsafe {
        syscall(
            nr_fsconfig,
            i64::from(fs_fd.as_raw_fd()),
            i64::from(consts::FSCONFIG_CMD_CREATE),
            core::ptr::null::<core::ffi::c_char>(),
            core::ptr::null::<core::ffi::c_char>(),
            0i64,
        )
    })?;
    // SAFETY: `fs_fd` は生存中の fd。flags は定数、attr は `TmpfsParams::attr`（`TmpfsMountFlags::attr_bits` か `DevTmpfsCreate::attr_bits` だけから作られる名前つき定数の和）のみ。
    // 成功時の戻り値は新規 fd で、直後に `new_mount_api_fd` が唯一の所有者にする。副作用は未接続の
    // マウントの作成に限る（fd を閉じればカーネルが破棄する）。
    let mnt_fd = new_mount_api_fd(unsafe {
        syscall(
            nr_fsmount,
            i64::from(fs_fd.as_raw_fd()),
            i64::from(consts::FSMOUNT_CLOEXEC),
            i64::from(params.attr),
        )
    })?;
    move_mount_empty_path(std::os::fd::AsFd::as_fd(&mnt_fd), target_dir)?;
    Ok(mnt_fd)
}

/// `move_mount(2)` に渡すフラグ（`MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH`）。
///
/// `mount_tmpfs_on` とデバイスノード bind が同じフラグを使うことを、単体テストで具体値（0x44）として
/// 固定するために `unsafe` から切り出している。
#[cfg_attr(test, allow(dead_code))]
fn move_mount_empty_path_flags() -> u32 {
    consts::MOVE_MOUNT_F_EMPTY_PATH | consts::MOVE_MOUNT_T_EMPTY_PATH
}

/// 切り離したマウント `from` を、`to`（検証済みの O_PATH fd）の上へ `move_mount(2)` で載せる。
///
/// 両端とも fd を指し、パス文字列は渡さない（`*_EMPTY_PATH`）ため、パスの再解決・symlink 追従が起きない。
/// `mount_tmpfs_on`（tmpfs の載せ替え）と、rootless のデバイスノード bind（`crate::exec::devices` が呼ぶ。CORE-6・SEC-5・#1660）が
/// 共有する。`ENOSYS`（Linux 5.2 未満）は [`SysError::Unsupported`] で返し、`mount(2)` へは縮退しない。
/// ファイルの bind では `to` もファイルである必要がある（ディレクトリ同士かファイル同士のみ成功する）。
///
/// 前提: `to` が属するマウントは shared でない（`crate::exec::MountIsolation::establish` が `/` を
/// `MS_REC|MS_PRIVATE` にした mount namespace の中で呼ぶ）。shared のままでは接続が peer へ伝播し、
/// ホスト側にもマウントが現れる。seccomp フィルタ（`DeniedSyscall::MoveMount`）の適用前に呼ぶ。
// テストビルドでは `crate::exec` の dry-run 差し込み点が呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn move_mount_empty_path(
    from: BorrowedFd<'_>,
    to: BorrowedFd<'_>,
) -> Result<(), SysError> {
    move_mount_empty_path_raw(from.as_raw_fd(), to.as_raw_fd())
}

/// [`move_mount_empty_path`] の本体。fd 番号（`RawFd`）を受ける非公開部分で、無効 fd の拒否（`EBADF`）を
/// `BorrowedFd` の契約に反せず単体テストで確かめるために切り出している。呼び出し側は生存中の fd を渡す。
#[cfg_attr(test, allow(dead_code))]
fn move_mount_empty_path_raw(from: RawFd, to: RawFd) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let nr = consts::SYS_MOVE_MOUNT.get()?;
    // SAFETY: `from`・`to` は fd 番号の整数で、カーネルが検証する（無効なら `EBADF`）。パスは静的な空文字列で、`*_EMPTY_PATH` により fd 自身が
    // 対象になる（パス解決なし）。副作用は呼び出しスレッドの mount namespace へのマウント 1 件の追加に限る
    // （接続先は private であること〔`MountIsolation::establish` の `MS_REC|MS_PRIVATE` 済み〕が前提。shared なら peer へ伝播する）。
    let rc = unsafe {
        syscall(
            nr,
            i64::from(from),
            c"".as_ptr(),
            i64::from(to),
            c"".as_ptr(),
            i64::from(move_mount_empty_path_flags()),
        )
    };
    if rc == -1 {
        return Err(new_mount_api_error());
    }
    Ok(())
}

/// [`open_tree_clone`] へ渡せる、文字デバイスと確かめたホストのデバイスノードの fd（CORE-6・SEC-5・SEC-1・#1659）。
///
/// [`verify_device_node_fd`] だけが作る（フィールドは `sys` の外から触れない）。保持するのは検証に使った fd
/// そのもので、検証後にパスを開き直さないため、検証と複製の対象は同じ inode になる（TOCTOU なし）。
#[derive(Debug)]
pub(crate) struct VerifiedDeviceNodeFd(OwnedFd);

impl std::os::fd::AsFd for VerifiedDeviceNodeFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.0)
    }
}

/// [`verify_device_node_fd`] の拒否理由。照合した実値を持ち、呼び出し側（`crate::exec::devices`。#1660）が
/// 構造化エラーへ写す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeviceNodeError {
    /// 文字デバイスではない（ディレクトリ・通常ファイル・`O_NOFOLLOW` で開いた symlink 等）。`mode` は `st_mode` の実値。
    NotCharDevice { mode: u32 },
    /// 文字デバイスだが `rdev` が期待値と違う。
    UnexpectedRdev { actual: u64, expected: u64 },
    /// `fstat`（fd の複製を含む）の失敗、または対応外アーキテクチャ（[`SysError::Unsupported`]）。
    Sys(SysError),
}

/// [`verify_device_node_fd`] が受け付けるホストのデバイスノード（OCI default devices の 6 種。CORE-6・SEC-1・#1659）。
///
/// 許可する `(major, minor)` の集合を型で閉じる固定表。列挙子以外の値（例: `/dev/mem` = 1:1）は表現できないため、
/// 呼び出し側が誤っても任意の文字デバイスを [`open_tree_clone`] へ渡す経路はできない（fail-closed）。
/// `sys` は上位層（`crate::exec::devices`）に依存しないため表を自前で持ち、`DEFAULT_DEVICES` との一致は
/// `exec::devices` 側の単体テストが順序込みで照合する（どちらかだけを変えるとテストが落ちる）。
/// CDI の deviceNodes は別責務（TASK-127）で、ここへ列挙子を足して受け付けない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostDeviceNode {
    /// `/dev/null`（1:3）。
    Null,
    /// `/dev/zero`（1:5）。
    Zero,
    /// `/dev/full`（1:7）。
    Full,
    /// `/dev/random`（1:8）。
    Random,
    /// `/dev/urandom`（1:9）。
    Urandom,
    /// `/dev/tty`（5:0）。
    Tty,
}

impl HostDeviceNode {
    /// 全列挙子（`DEFAULT_DEVICES` と同じ順）。`exec::devices` の照合テストが使う。
    #[cfg(test)]
    pub(crate) const ALL: [Self; 6] = [
        Self::Null,
        Self::Zero,
        Self::Full,
        Self::Random,
        Self::Urandom,
        Self::Tty,
    ];

    /// `(major, minor)`。
    pub(crate) const fn major_minor(self) -> (u32, u32) {
        match self {
            Self::Null => (1, 3),
            Self::Zero => (1, 5),
            Self::Full => (1, 7),
            Self::Random => (1, 8),
            Self::Urandom => (1, 9),
            Self::Tty => (5, 0),
        }
    }
}

/// `fd`（呼び出し側が `O_PATH|O_NOFOLLOW` で開いたホストのデバイスノード）を、同じ fd の `fstat` で照合する。
///
/// 文字デバイス（`S_IFCHR`）かつ `rdev == makedev(node.major_minor())` のときだけ [`VerifiedDeviceNodeFd`] を返す。
/// 期待値は [`HostDeviceNode`] の固定表に限り、任意の major/minor は受け付けない（SEC-1。呼び出し側〔#1660〕は
/// `DEFAULT_DEVICES` の要素に対応する列挙子を渡す）。パスの `stat` ではなく fd の `fstat`（std の
/// `File::metadata`。fd は複製して見るだけで、元の fd をそのまま保持する）で見るため、検証後の差し替えは効かない。
/// 照合は `crate::exec::devices` の既存ノードの検証と同じ形（種別と `rdev` の完全一致）。
pub(crate) fn verify_device_node_fd(
    fd: OwnedFd,
    node: HostDeviceNode,
) -> Result<VerifiedDeviceNodeFd, DeviceNodeError> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    if !consts::SUPPORTED {
        return Err(DeviceNodeError::Sys(SysError::Unsupported));
    }
    let os = |e: io::Error| DeviceNodeError::Sys(SysError::Os(e.raw_os_error().unwrap_or(EINVAL)));
    let dup = std::os::fd::AsFd::as_fd(&fd)
        .try_clone_to_owned()
        .map_err(os)?;
    let meta = std::fs::File::from(dup).metadata().map_err(os)?;
    if !meta.file_type().is_char_device() {
        return Err(DeviceNodeError::NotCharDevice { mode: meta.mode() });
    }
    let (major, minor) = node.major_minor();
    let expected = makedev(major, minor);
    if meta.rdev() != expected {
        return Err(DeviceNodeError::UnexpectedRdev {
            actual: meta.rdev(),
            expected,
        });
    }
    Ok(VerifiedDeviceNodeFd(fd))
}

/// `open_tree(2)` に渡すフラグ（`OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH`）。
///
/// `AT_RECURSIVE` は付けない（複製をノード 1 個に限り、ホスト側の子マウントを持ち込まない）。
#[cfg_attr(test, allow(dead_code))]
fn open_tree_clone_flags() -> u32 {
    consts::OPEN_TREE_CLONE | consts::OPEN_TREE_CLOEXEC | consts::OPEN_TREE_AT_EMPTY_PATH
}

/// `node`（呼び出し側が検証したホストのデバイスノードの O_PATH fd）を、切り離したマウントとして複製する。
///
/// rootless（user namespace）では `mknod` できないため、ホストのノードを fd 起点で `open_tree` +
/// `move_mount_empty_path` により bind する（方式 (a)。`docs/design/dev-default-mounts.md` §3.6・
/// 判断 4。CORE-6・SEC-5・#1659。呼び出し元は `crate::exec::devices` の rootless 経路。#1660）。戻り値は未接続のマウントを指す close-on-exec の fd で、
/// 途中で失敗して drop すればカーネルが破棄する。
///
/// 引数は [`verify_device_node_fd`] だけが作れる [`VerifiedDeviceNodeFd`] に限る。文字デバイス（`S_IFCHR`）で
/// `rdev` が [`HostDeviceNode`] の固定表の値と一致することを同じ fd の `fstat` で確かめた fd しか渡せないため、
/// ディレクトリ・通常ファイル・表にない文字デバイス（`/dev/mem` 等）を複製して nosuid・noexec なしでコンテナへ
/// 渡す経路は型で塞がれる（SEC-1）。symlink を辿らないこと
/// （`O_PATH|O_NOFOLLOW` で開くこと）は fd を開く呼び出し側の責務で、辿らずに開いた symlink 自体は
/// `S_IFCHR` でないため検証で拒否される。
///
/// マウントフラグは緩めも追加もしない。複製はホスト側マウントのフラグ（locked flag 含む）を継承する。
/// `nosuid`・`noexec` を付与しない理由は、マウントのルートが文字デバイス 1 個（上の型で強制）で他のファイルへ届かず、exec と
/// setuid が通常ファイルにしか効かないため守る対象が無いこと（runc の `bindMountDeviceNode` も `MS_BIND` のみ）。
/// `nodev` はノードが使えなくなるため付けてはならない。よってデバイスノードの bind には `mount_setattr` を掛けない
/// （[`set_mount_nodev`] は rootfs 専用で nodev 固定。#1676）。
///
/// 必要なカーネルは Linux 5.2 以降。`ENOSYS` は [`SysError::Unsupported`] で返し、`mount(2)` へは縮退しない。
/// user namespace では自分の mount namespace を所有する userns の `CAP_SYS_ADMIN` が要る。
///
/// 呼び出し順の前提（`crate::exec::devices` が固定し結合試験 `default_devices` で照合する。#1660）:
/// - ホストのノードは `unshare(CLONE_NEWNS)` の後・`pivot_root` の前に、呼び出しと同じ mount namespace の中で
///   開き、同じ namespace の中で本関数を呼ぶ。fs/namespace.c の `__do_loopback`（v5.2・v6.12 で確認）は
///   `check_mnt(old)`（fd のマウントの `mnt_ns` が呼び出しスレッドの mount namespace と一致）を満たさないと
///   `EINVAL` を返す。unshare 前に開いた fd のマウントは元の namespace に属し、`pivot_root` 後に旧ルートを
///   `umount2(MNT_DETACH)` で切り離すと `umount_tree` が `mnt_ns` を NULL にするため、どちらも複製できない。
/// - seccomp フィルタの適用前に呼ぶ。`crate::seccomp` の既定の拒否集合は `open_tree`（`DeniedSyscall::OpenTree`）と
///   `move_mount`（`DeniedSyscall::MoveMount`）を含み、適用後は失敗する。
// テストビルドでは `crate::exec::devices` の dry-run 差し込み点が呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn open_tree_clone(node: &VerifiedDeviceNodeFd) -> Result<OwnedFd, SysError> {
    open_tree_clone_raw(node.0.as_raw_fd())
}

/// [`open_tree_clone`] の本体。fd 番号（`RawFd`）を受ける非公開部分で、無効 fd の拒否（`EBADF`）を
/// `BorrowedFd` の契約に反せず単体テストで確かめるために切り出している。
#[cfg_attr(test, allow(dead_code))]
fn open_tree_clone_raw(node: RawFd) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let nr = consts::SYS_OPEN_TREE.get()?;
    // SAFETY: `node` は fd 番号の整数で、カーネルが検証する（無効なら `EBADF`）。パスは静的な空文字列（NUL 終端）で、`AT_EMPTY_PATH` により fd 自身が
    // 対象になる（パス解決なし）。`AT_RECURSIVE` は付けない。成功時の戻り値は新規 fd で、直後に
    // `new_mount_api_fd` が唯一の所有者にする。副作用は未接続の複製マウントの作成に限る（fd を閉じれば破棄される）。
    new_mount_api_fd(unsafe {
        syscall(
            nr,
            i64::from(node),
            c"".as_ptr(),
            i64::from(open_tree_clone_flags()),
        )
    })
}

/// `mount_setattr(2)` の `struct mount_attr`（include/uapi/linux/mount.h。`MOUNT_ATTR_SIZE_VER0` = 32 バイト）。
/// 値は [`rootfs_nodev_mount_attr`]・[`read_only_mount_attr`] だけが作る（任意のビットを渡す経路を持たない。REPAIR-2・SEC-1）。
///
/// 構築子はどれも private な固定の `const fn` で、`attr_clr`・`propagation`・`userns_fd` は 0（属性を足すだけ）。
/// 構築子を足す・変えるときは、[`mount_setattr_empty_path_raw`] の `// SAFETY:` と、構築子の一覧と値を具体値で
/// 照合する単体テスト `sec1_sup12_mount_attr_constructors_are_exhaustive` を合わせて更新すること（#1693 の事後監査 P3）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// rootfs の自己 bind に足す属性。`nodev` を足すだけで、既存の属性は外さない（`attr_clr` = 0）。
#[cfg_attr(test, allow(dead_code))]
const fn rootfs_nodev_mount_attr() -> MountAttr {
    MountAttr {
        attr_set: consts::MOUNT_ATTR_NODEV as u64,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    }
}

/// inject の tmpfs に足す属性。`rdonly` を足すだけで、ロック済みの `nosuid`・`nodev`・`noexec` を含め既存の属性は
/// 外さない（`attr_clr` = 0）。`MS_REMOUNT` と違い superblock ではなくマウント単位の ro になる（SUP-12・SEC-1・#1620）。
#[cfg_attr(test, allow(dead_code))]
const fn read_only_mount_attr() -> MountAttr {
    MountAttr {
        attr_set: consts::MOUNT_ATTR_RDONLY as u64,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    }
}

/// `mount_setattr(2)` の `flags`。`AT_EMPTY_PATH` のみで、`AT_RECURSIVE` は付けない（mount top 1 枚だけに掛ける）。
#[cfg_attr(test, allow(dead_code))]
const fn mount_setattr_flags() -> u32 {
    consts::MOUNT_SETATTR_AT_EMPTY_PATH
}

/// 単体テストの dry-run が記録する、本番ラッパーと同じ値の組
/// `(attr_set, attr_clr, propagation, userns_fd, flags, size)`。
#[cfg(test)]
pub(crate) fn rootfs_nodev_call_params() -> (u64, u64, u64, u64, u32, usize) {
    let a = rootfs_nodev_mount_attr();
    (
        a.attr_set,
        a.attr_clr,
        a.propagation,
        a.userns_fd,
        mount_setattr_flags(),
        std::mem::size_of::<MountAttr>(),
    )
}

/// 単体テストの dry-run が記録する、[`set_mount_read_only`] と同じ値の組（[`rootfs_nodev_call_params`] と同形）。
#[cfg(test)]
pub(crate) fn read_only_call_params() -> (u64, u64, u64, u64, u32, usize) {
    let a = read_only_mount_attr();
    (
        a.attr_set,
        a.attr_clr,
        a.propagation,
        a.userns_fd,
        mount_setattr_flags(),
        std::mem::size_of::<MountAttr>(),
    )
}

/// `mount_top`（マウントのルートを指す fd）のマウントに `nodev` を足す（`mount_setattr(2)`。再帰なし）。
///
/// rootfs の自己 bind は初回の `MS_BIND` がフラグを無視するため `nodev` が付かない。イメージが
/// `/dev` 以外へ同梱したデバイスノードを開けないよう、`crate::exec::prepare_rootfs` が検証済みの mount top の
/// fd に対して `/dev` の tmpfs を載せる前に、rootful・rootless を問わず常に呼ぶ（#1676・SEC-1・CORE-1・TASK-27.3。
/// オーナー判断 2026-10-10）。rootless では mount namespace を所有する user namespace の `CAP_SYS_ADMIN` で通る。値は nodev 固定で、
/// 既存の属性は変えない。パスは渡さず `AT_EMPTY_PATH` で fd 自身を対象にする。
///
/// fd がマウントのルートでない、または呼び出し側の mount namespace の外にあると `EINVAL`。必要なカーネルは
/// Linux 5.12 以降で、`ENOSYS` は [`SysError::Unsupported`] で返し `mount(2)` へは縮退しない。seccomp の既定の
/// 拒否集合は `mount_setattr`（`DeniedSyscall::MountSetattr`）を含むため、フィルタの適用前に呼ぶ。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn set_mount_nodev(mount_top: BorrowedFd<'_>) -> Result<(), SysError> {
    set_mount_nodev_raw(mount_top.as_raw_fd())
}

/// [`set_mount_nodev`] の本体。無効 fd の拒否（`EBADF`）を単体テストで確かめるために `RawFd` を受ける。
#[cfg_attr(test, allow(dead_code))]
fn set_mount_nodev_raw(fd: RawFd) -> Result<(), SysError> {
    mount_setattr_empty_path_raw(fd, rootfs_nodev_mount_attr())
}

/// `mount_root`（マウントのルートを指す fd）のマウントを読み取り専用にする（`mount_setattr(2)` +
/// `MOUNT_ATTR_RDONLY`。再帰なし）。
///
/// `crate::exec::inject_files` が、secrets / configs を書き終えた tmpfs を read-only にするために呼ぶ
/// （SUP-12・TASK-169.4.2・SEC-1・#1620）。`/proc/thread-self/fd/N` のパス文字列を経由せず、`AT_EMPTY_PATH` で
/// fd 自身を対象にするため、パスの再解決の余地がない。属性は足すだけ（`attr_clr` = 0）で、user namespace 内で
/// ロックされた `nosuid`・`nodev`・`noexec` を落とさない。
///
/// 意味論: `MS_REMOUNT` が superblock ごと ro にするのに対し、本関数はこのマウントの `MNT_READONLY` だけを立てる。
/// 呼び出し側は同じ superblock の別マウントを作らないため、コンテナから見た保証（`EROFS`）は変わらない。
/// 書き込み中の fd が残っていると `EBUSY` になるので、呼び出し前にすべて閉じておくこと。
/// fd がマウントのルートでないと `EINVAL`。必要なカーネルは Linux 5.12 以降で、`ENOSYS` は
/// [`SysError::Unsupported`] で返し `mount(2)` へは縮退しない。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn set_mount_read_only(mount_root: BorrowedFd<'_>) -> Result<(), SysError> {
    set_mount_read_only_raw(mount_root.as_raw_fd())
}

/// [`set_mount_read_only`] の本体。無効 fd の拒否を単体テストで確かめるために `RawFd` を受ける。
#[cfg_attr(test, allow(dead_code))]
fn set_mount_read_only_raw(fd: RawFd) -> Result<(), SysError> {
    mount_setattr_empty_path_raw(fd, read_only_mount_attr())
}

/// `mount_setattr(fd, "", AT_EMPTY_PATH, attr, 32)` の共通本体。`attr` は `attr_clr` = 0 の private な固定 const
/// 構築子（[`rootfs_nodev_mount_attr`]・[`read_only_mount_attr`]）の値だけが渡る（本関数は private）。
///
/// 構築子を足すときは、下の `// SAFETY:` と構築子一覧の単体テスト `sec1_sup12_mount_attr_constructors_are_exhaustive`
/// を合わせて更新する（[`MountAttr`] の doc を参照）。
#[cfg_attr(test, allow(dead_code))]
fn mount_setattr_empty_path_raw(fd: RawFd, attr: MountAttr) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let nr = consts::SYS_MOUNT_SETATTR.get()?;
    // SAFETY: `fd` は fd 番号の整数で、カーネルが検証する（無効なら `EBADF`）。パスは静的な空文字列（NUL 終端）で、
    // `AT_EMPTY_PATH` により fd 自身が対象になる。`attr` は呼び出しの間生存する 32 バイトの `repr(C)` で、
    // カーネルは読むだけ（`size` は構造体の大きさ）。`attr` は `attr_clr` = 0 の private な固定 const 構築子
    // （`rootfs_nodev_mount_attr`・`read_only_mount_attr`）の値だけが渡り、副作用は fd が指す 1 マウントへの
    // 属性の追加に限る（既存の属性は外さない）。構築子を足すときは本コメントと構築子一覧の試験を更新する。
    let rc = unsafe {
        syscall(
            nr,
            i64::from(fd),
            c"".as_ptr(),
            i64::from(mount_setattr_flags()),
            &raw const attr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if rc == -1 {
        return Err(new_mount_api_error());
    }
    Ok(())
}

/// devpts の `statfs.f_type`（include/uapi/linux/magic.h の `DEVPTS_SUPER_MAGIC`。アーキテクチャ非依存）。
/// [`mount_devpts_on`] が返す fd の事後検証で使う（`crate::exec::create_default_devices` が呼ぶ。CORE-1・SEC-1・#1656）。
pub(crate) const DEVPTS_MAGIC: i64 = 0x1cd1;

/// [`mount_devpts_on`] の作成パラメータ。`/dev/pts` の devpts は OCI runtime-spec の Default Filesystems で
/// SHOULD とされ、常に載せる暗黙の固定集合である（TASK-29 追補・CORE-1・SEC-1）。
///
/// 可変なのは `gid` だけで、`mode`（0o620）・`ptmxmode`（0o666）・マウント属性（nosuid・noexec）は型の外から
/// 変えられない。カーネルへ渡す文字列は本モジュール内で整数から生成し、利用者文字列や `mount(2)` の data を
/// 渡す経路を持たない。呼び出し元（`crate::exec::create_default_devices`。#1656）が rootless で gid 5 が写像されていないときに
/// `gid` を `None` にする（判定はここでは行わない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DevptsCreate {
    /// pty スレーブの所有グループ（tty グループの 5 か、`gid` のキー自体を渡さないかの 2 通り）。
    pub(crate) gid: DevptsGid,
}

/// devpts の `gid=` の指定（#1663 事後監査 P3。SEC-1・SEC-5）。
///
/// runc と同じ tty グループ（5）を渡すか、`gid` のキー自体を渡さない（カーネル既定。rootless で gid 5 が
/// 写像されていないとき）かの 2 通りに型で限り、crate 内からも任意の gid を渡せないようにする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DevptsGid {
    /// `gid=5`（tty グループ）。
    Tty,
    /// `gid` のキーを渡さない。
    Omitted,
}

impl DevptsGid {
    /// tty グループの gid（runc の既定と同じ。設計ドラフト `dev-default-mounts.md` 3.3）。
    pub(crate) const TTY_GID: u32 = 5;

    /// `gid=` に渡す値（`Omitted` は `None`）。
    pub(crate) const fn value(self) -> Option<u32> {
        match self {
            Self::Tty => Some(Self::TTY_GID),
            Self::Omitted => None,
        }
    }
}

impl DevptsCreate {
    /// pty スレーブのモード（`mode=`）。
    pub(crate) const MODE: u32 = 0o620;
    /// `/dev/pts/ptmx` のモード（`ptmxmode=`）。0o666 でないと非特権プロセスが pty を確保できない。
    pub(crate) const PTMXMODE: u32 = 0o666;

    /// `fsmount(2)` の `attr_flags`。`nosuid`・`noexec` を固定で付ける。pty は文字デバイスなので
    /// `nodev` は付けない（付けるとスレーブを open できなくなる）。
    pub(crate) fn attr_bits(self) -> u32 {
        consts::MOUNT_ATTR_NOSUID | consts::MOUNT_ATTR_NOEXEC
    }

    /// `fsconfig(SET_STRING)` へ渡すキーと値の列（順序固定）。`gid` は [`DevptsGid`] で 5 か省略に限られる
    /// ため、無効な gid（`(gid_t)-1` 等）を表せない。安全なコードだけの純粋関数で、マウント権限なしに
    /// 具体値で照合できる。
    fn fsconfig_params(self) -> Result<Vec<FsconfigParam>, SysError> {
        let make = |key: &'static CStr, value: String| -> Result<FsconfigParam, SysError> {
            // 値は整数から生成した数字（または静的な識別子）のみで、NUL・カンマを含み得ない。
            let value = CString::new(value).map_err(|_| SysError::Os(EINVAL))?;
            Ok(FsconfigParam::String(key, value))
        };
        let mut params = vec![
            make(c"source", "devpts".to_owned())?,
            make(c"mode", format!("{:04o}", Self::MODE))?,
            make(c"ptmxmode", format!("{:04o}", Self::PTMXMODE))?,
        ];
        if let Some(gid) = self.gid.value() {
            params.push(make(c"gid", gid.to_string())?);
        }
        Ok(params)
    }
}

/// `target_dir`（検証済みのマウント先ディレクトリの O_PATH fd）の上へ、新マウント API で devpts を載せ、
/// 載せたマウントのルートを指す fd（close-on-exec）を返す。
///
/// `fsopen("devpts")` → `fsconfig`（[`DevptsCreate`] のキーを 1 つずつ SET_STRING）→ `fsconfig(CMD_CREATE)`
/// → `fsmount`（nosuid・noexec）→ `move_mount(.., target_dir, "", *_EMPTY_PATH)`。syscall 境界ではキー単位で
/// 渡し、利用者の文字列や `mount(2)` の data は渡さない。返す fd は自分のマウントを一意に指し、呼び出し元
/// （`crate::exec::create_default_devices`。#1656）が `DEVPTS_MAGIC` による事後検証と失敗時の後始末に使う。
///
/// `nodev` は付けない（pty は文字デバイスのため）。`newinstance` は渡さない（Linux 4.7 以降は devpts の
/// mount がすべて独立 instance で、本 API の前提は 5.2 以降）。instance ごとの `max=` も付けない
/// （全体上限は `kernel.pty.max` が担う）。未対応（`ENOSYS`）は [`SysError::Unsupported`] で返し、
/// `mount(2)` へは縮退しない（fail-closed）。実マウントは `sys::tests::core1_sec1_task29_devpts_real_mount`（実機前提・`--ignored`）が
/// user + mount namespace 内で確認し、`crate::exec` からの呼び出しは `tests/default_devices.rs` が確認する（#1656）。
/// ビヘイビア: CORE-1・SEC-1・REPAIR-2（TASK-29 追補・#1655）。
pub(crate) fn mount_devpts_on(
    target_dir: BorrowedFd<'_>,
    create: DevptsCreate,
) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // 検証エラーは fd を作る前に返す。
    let params = create.fsconfig_params()?;
    // syscall 番号は fd を作る前にまとめて取り出す（`ArchSysNo::get` 経由。#1619）。
    let nr_fsopen = consts::SYS_FSOPEN.get()?;
    let nr_fsconfig = consts::SYS_FSCONFIG.get()?;
    let nr_fsmount = consts::SYS_FSMOUNT.get()?;
    let nr_move_mount = consts::SYS_MOVE_MOUNT.get()?;
    // SAFETY: 静的な NUL 終端文字列のポインタと定数フラグのみ。カーネルは呼び出し中に文字列を複写するだけで
    // ポインタを保持しない。可変長引数は register 幅（`i64` / ポインタ）で渡す。成功時の戻り値は新規 fd で、
    // 直後に `new_mount_api_fd` が唯一の所有者にする。
    let fs_fd = new_mount_api_fd(unsafe {
        syscall(
            nr_fsopen,
            c"devpts".as_ptr(),
            i64::from(consts::FSOPEN_CLOEXEC),
        )
    })?;
    for param in &params {
        // devpts のパラメータは文字列形式のみ（`fsconfig_params` が `String` しか作らない）。
        let FsconfigParam::String(key, value) = param else {
            return Err(SysError::Os(EINVAL));
        };
        // SAFETY: `fs_fd` は生存中の fsopen の fd。`key`・`value` は借用した NUL 終端文字列で
        // 呼び出しの間生存し、カーネルは保持しない。aux は 0。副作用はこの fs コンテキストへのパラメータ設定に限る。
        fsconfig_result(unsafe {
            syscall(
                nr_fsconfig,
                i64::from(fs_fd.as_raw_fd()),
                i64::from(consts::FSCONFIG_SET_STRING),
                key.as_ptr(),
                value.as_ptr(),
                0i64,
            )
        })?;
    }
    // SAFETY: `fs_fd` は生存中の fsopen の fd。key・value は NULL、aux は 0（`FSCONFIG_CMD_CREATE` の仕様）。
    // 副作用は superblock の作成（まだどこにも接続されない）に限る。
    fsconfig_result(unsafe {
        syscall(
            nr_fsconfig,
            i64::from(fs_fd.as_raw_fd()),
            i64::from(consts::FSCONFIG_CMD_CREATE),
            core::ptr::null::<core::ffi::c_char>(),
            core::ptr::null::<core::ffi::c_char>(),
            0i64,
        )
    })?;
    // SAFETY: `fs_fd` は生存中の fd。flags・attr は定数と `attr_bits`（nosuid・noexec 固定、nodev なし）のみ。
    // 成功時の戻り値は新規 fd で、直後に `new_mount_api_fd` が唯一の所有者にする。副作用は未接続の
    // マウントの作成に限る（fd を閉じればカーネルが破棄する）。
    let mnt_fd = new_mount_api_fd(unsafe {
        syscall(
            nr_fsmount,
            i64::from(fs_fd.as_raw_fd()),
            i64::from(consts::FSMOUNT_CLOEXEC),
            i64::from(create.attr_bits()),
        )
    })?;
    // SAFETY: `mnt_fd`・`target_dir` は生存中の fd（`OwnedFd` と `BorrowedFd`）。パスは静的な空文字列で、
    // `*_EMPTY_PATH` により fd 自身が対象になる（パス解決なし）。副作用は呼び出しスレッドの mount namespace への
    // マウント 1 件の追加に限る。
    let rc = unsafe {
        syscall(
            nr_move_mount,
            i64::from(mnt_fd.as_raw_fd()),
            c"".as_ptr(),
            i64::from(target_dir.as_raw_fd()),
            c"".as_ptr(),
            i64::from(consts::MOVE_MOUNT_F_EMPTY_PATH | consts::MOVE_MOUNT_T_EMPTY_PATH),
        )
    };
    if rc == -1 {
        return Err(new_mount_api_error());
    }
    Ok(mnt_fd)
}

/// `target` のマウントを `MNT_DETACH` で切り離す（`umount2(target, MNT_DETACH)`）。
///
/// `crate::exec::mount_tmpfs`・`inject_files` の失敗時の後始末が、自分でマウントした tmpfs のルートを指す
/// fd の `/proc/thread-self/fd/N` を渡す（fd を直接指定して外す syscall が無いためパス経由になり、`/proc` が
/// 見えないと失敗する。呼び出し元は失敗を元のエラーに併記する。#1620）（magic link を fd の実体へ解決させるため
/// `UMOUNT_NOFOLLOW` は付けない）。`target` がマウントのルートでなければカーネルが `EINVAL` で拒否する。
// テストビルドでは `crate::exec` の dry-run 差し込み点が本関数を呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn umount_detach_at(target: &CStr) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `target` は `&CStr` の借用で NUL 終端かつ呼び出しの間生存し、カーネルはポインタを
    // 保持しない。flags は定数。副作用は呼び出しスレッドの mount namespace からのマウント 1 件の切り離しのみ。
    let rc = unsafe { umount2(target.as_ptr(), consts::MNT_DETACH) };
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
    let nr = consts::SYS_PIVOT_ROOT.get()?;
    // SAFETY: 第 2・3 引数は静的な NUL 終端文字列 `c"."` へのポインタ（`*const c_char`。可変長
    // 引数として register 幅で渡され、カーネルは 2 引数だけ読む）。番号 `nr` は `ArchSysNo::get` を
    // 通した arch ごとの定数（#1619）。
    // 戻り値 -1 のとき直後に errno を確保する。
    let rc = unsafe { syscall(nr, c".".as_ptr(), c".".as_ptr()) };
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
    status_thread_count(status) == Some(1)
}

/// `/proc/self/status` の内容から `Threads:` の値を読む純関数。行が無い・数値でない場合は `None`。
fn status_thread_count(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// 呼び出しプロセスの現在のスレッド数（`/proc/self/status` の `Threads:`）。読めない・解釈できなければ `None`。
///
/// `crate::audit_log` の `FileAuditSink` が、通知の出し直しスレッドを join した後にスレッド数が元へ戻るのを
/// 上限付きで待つために使う（join の完了からスレッドの解放までの短い間は増えたまま読めるため。REPAIR-5・SUP-6）。
pub(crate) fn current_thread_count() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| status_thread_count(&status))
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
    fork_single_threaded_with(
        || std::fs::read_to_string("/proc/self/status").is_ok_and(|status| threads_is_one(&status)),
        child,
        panic_exit,
    )
}

/// [`fork_single_threaded`] の本体。`is_single_threaded` が「呼び出しプロセスのスレッド数が 1 である」ことを
/// 返したときだけ fork する（SUP-6・TASK-163.4・#503）。
///
/// exec 専用プロセスは `setns(CLONE_NEWNS)` の後に `/proc` がコンテナ側の procfs になり、自プロセスを
/// `/proc/self` で解決できない。そのため `setns` の前に開いた自プロセスの status fd からスレッド数を読む
/// 判定（`ThreadCountSource::PreOpened`）を呼び出し側が渡す。判定の出所が変わるだけで「fork の直前に
/// `Threads: 1` を確認する」という強制は同じ関数の内側に残る。判定が偽（読めない場合を含む）なら fork せず
/// [`SysError::MultiThreaded`]（fail-closed）。
pub(crate) fn fork_single_threaded_with<F: FnOnce() -> i32>(
    is_single_threaded: impl FnOnce() -> bool,
    child: F,
    panic_exit: i32,
) -> Result<u32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    fork_checked(is_single_threaded, child, panic_exit, true)
}

/// [`fork_single_threaded`] と同じ強制（`Threads: 1` の確認・子は `_exit`）だが、**fork 前に親で
/// stdout / stderr を flush しない**（REPAIR-5・SEC-4・TASK-163 追補・#1594）。
///
/// 親の flush は出力先（パイプ満杯など）で無期限に止まり得て、呼び出し側の期限（監査の
/// `PRIMARY_WRITE_TIMEOUT` 等）は fork の後に始まるため効かない。子は `child` の後に `_exit` するだけで
/// 親の stdio バッファを flush しない（`exit` / atexit を通らない）ので、flush を省いても二重出力は起きない。
/// ただし子の `child` が親から継承した stdout のバッファを書き出す処理を呼んではならない。
pub(crate) fn fork_single_threaded_no_flush<F: FnOnce() -> i32>(
    child: F,
    panic_exit: i32,
) -> Result<u32, SysError> {
    fork_checked(
        || std::fs::read_to_string("/proc/self/status").is_ok_and(|status| threads_is_one(&status)),
        child,
        panic_exit,
        false,
    )
}

/// fork の共通本体。`flush_stdio` が真のときだけ fork 前に stdout / stderr を flush する。
fn fork_checked<F: FnOnce() -> i32>(
    is_single_threaded: impl FnOnce() -> bool,
    child: F,
    panic_exit: i32,
    flush_stdio: bool,
) -> Result<u32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    if !is_single_threaded() {
        return Err(SysError::MultiThreaded);
    }
    if flush_stdio {
        use std::io::Write as _;
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
    }
    // SAFETY: 直前に呼び出し側の判定で `Threads: 1` を確認済みで、fork した子には呼び出しスレッドだけが複製される
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
    let nr = match consts::SYS_EXECVEAT.get() {
        Ok(nr) => nr,
        Err(e) => return e,
    };
    let argv_ptrs = null_terminated_ptrs(argv);
    let envp_ptrs = null_terminated_ptrs(envp);
    // SAFETY: 番号は `ArchSysNo::get` を通した arch 別の定数（#1619）。`fd` は生存中の `BorrowedFd`。パス引数は静的な空文字列（NUL 終端）で AT_EMPTY_PATH と
    // 組で使う。`argv_ptrs` / `envp_ptrs` は末尾が NULL のポインタ配列で、各要素は呼び出しの間生存する
    // `argv` / `envp`（NUL 終端の `CString`）を指す。成功時は戻らず、失敗時は配列を読み取っただけ。
    unsafe {
        syscall(
            nr,
            i64::from(fd.as_raw_fd()),
            c"".as_ptr(),
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
            consts::AT_EMPTY_PATH,
        )
    };
    last_error()
}
/// memfd に付ける seal の集合（`F_SEAL_*` のビット和）。生の整数を `sys` の外へ出さないための newtype
/// （REPAIR-2）。封印した複製からの実行（TASK-163 追補・#1530・#1531・SUP-6・SEC-1）で使う。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SealSet(u32);

impl SealSet {
    /// 封印した複製に付ける seal の完全集合（`SEAL | SHRINK | GROW | WRITE` = 0x0F）。
    /// 書き込み・伸長・縮小を拒否し、以後 seal の追加・変更もできなくする。
    pub(crate) const EXEC_COPY: SealSet = SealSet(
        consts::F_SEAL_SEAL | consts::F_SEAL_SHRINK | consts::F_SEAL_GROW | consts::F_SEAL_WRITE,
    );

    /// seal のビット値（診断・テスト用）。
    pub(crate) fn bits(self) -> u32 {
        self.0
    }

    /// `other` の seal がすべて含まれるか。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn contains(self, other: SealSet) -> bool {
        self.0 & other.0 == other.0
    }
}

/// 実行用 memfd を作る（`memfd_create(2)`。`MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC`）。
///
/// 封印した複製からの実行（#1530・#1531）の入口。`MFD_EXEC` を知らないカーネル（6.3 未満）は `EINVAL`
/// を返すため、そのときだけ `MFD_EXEC` を外して 1 回再試行する（6.3 未満の memfd は実行できる）。
/// `EACCES`（`vm.memfd_noexec=2`）・`EPERM`（seccomp）・`ENOSYS` などはそのまま返し、拒否（fail-closed）
/// は呼び出し側が行う。`name` は固定値を渡す前提で、外部入力を混ぜない（`/` を含めない・249 バイト以下）。
/// glibc 2.27・musl 1.1.20 の版前提を増やさないよう、`execveat`・`close_range` と同じく `syscall(2)` 経由で呼ぶ。
pub(crate) fn memfd_create_for_exec_copy(name: &'static CStr) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let base = consts::MFD_CLOEXEC | consts::MFD_ALLOW_SEALING;
    match memfd_create_raw(name, base | consts::MFD_EXEC) {
        Err(SysError::Os(e)) if e == EINVAL => memfd_create_raw(name, base),
        other => other,
    }
}

fn memfd_create_raw(name: &CStr, flags: u32) -> Result<OwnedFd, SysError> {
    let nr = consts::SYS_MEMFD_CREATE.get()?;
    // SAFETY: `name` は呼び出しの間生存する NUL 終端の借用で、カーネルは読み取るだけ。`flags` は整数
    // （unsigned int 引数は register 幅に拡張して渡され、カーネルは下位 32 bit を読む）。
    let rc = unsafe { syscall(nr, name.as_ptr(), i64::from(flags)) };
    if rc < 0 {
        return Err(last_error());
    }
    let Ok(fd) = i32::try_from(rc) else {
        return Err(SysError::Os(EINVAL));
    };
    // SAFETY: `fd` は直前に成功した memfd_create が返した、他に所有者のいない有効な fd。ここで 1 回だけ
    // 所有権を `OwnedFd` へ移す（二重 close なし）。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `fd` に seal を追加する（`fcntl(F_ADD_SEALS)`）。`MFD_ALLOW_SEALING` なしの memfd・memfd でない fd は
/// `EPERM` / `EINVAL`、`F_SEAL_SEAL` 済みなら `EPERM`。
pub(crate) fn add_seals(fd: BorrowedFd<'_>, seals: SealSet) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `fd` は生存中の `BorrowedFd`。F_ADD_SEALS は unsigned int の整数引数のみを取りポインタを渡さない。
    let rc = unsafe { fcntl(fd.as_raw_fd(), consts::F_ADD_SEALS, seals.bits()) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `fd` に付いている seal を返す（`fcntl(F_GET_SEALS)`）。memfd でない fd は `EINVAL`。
pub(crate) fn get_seals(fd: BorrowedFd<'_>) -> Result<SealSet, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `fd` は生存中の `BorrowedFd`。F_GET_SEALS は追加引数を取らない。戻り値は seal のビット和か -1。
    let rc = unsafe { fcntl(fd.as_raw_fd(), consts::F_GET_SEALS) };
    if rc < 0 {
        return Err(last_error());
    }
    // rc は非負の int なので u32 へ損失なく変換できる（できなければ黙って 0 にせず失敗にする）。
    u32::try_from(rc)
        .map(SealSet)
        .map_err(|_| SysError::Os(EINVAL))
}

/// 封印の検証に失敗した理由（[`seal_for_exec`]）。`SysError` を拡張せず別の列挙にして、既存の
/// `ExecError::from_sys` の分類へ波及させない。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SealError {
    /// seal の追加・取得の syscall が失敗した。
    Sys(SysError),
    /// 追加後の `F_GET_SEALS` が期待（`SealSet::EXEC_COPY` ちょうど）と一致しない。`F_SEAL_EXEC` など
    /// 余分な seal が付いていた場合も含む。
    Unexpected { actual: u32 },
    /// 読み取り専用で開き直した fd が、封印した memfd と同じ実体（`(st_dev, st_ino)`）を指さない。
    IdentityMismatch,
}

/// 封印を検証済みの memfd。作れるのは [`seal_for_exec`] だけで、「封印を確認していない fd を実行する」
/// 状態を型の上で表せなくする（REPAIR-2）。exec の子（`crate::exec::sealed_copy`）が `as_fd()` を読み取り専用で開き直して実行する。
#[derive(Debug)]
pub(crate) struct SealedMemfd(OwnedFd);

impl SealedMemfd {
    /// 封印済み fd を貸す（単体テストが封印の性質を直接確かめる用。本番は [`SealedMemfd::reopen_read_only`] だけを使う）。
    #[cfg(test)]
    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.0)
    }

    /// 所有権を取り出す（単体テストが封印の性質を直接確かめる用）。
    #[cfg(test)]
    pub(crate) fn into_owned_fd(self) -> OwnedFd {
        self.0
    }

    /// 読み取り専用で開き直し（`proc_dir` 配下の `thread-self/fd/N` 経由。[`reopen_pinned_read`]）、開き直した fd の
    /// `F_GET_SEALS` が 0x0F ちょうどで `(st_dev, st_ino)` が封印した memfd と一致することを確かめて
    /// [`SealedReadOnlyCopy`] にする（TASK-163 追補・#1531・SEC-1。開き直した fd は 3 以上に置く）。書き込み用の fd（`self`）はここで閉じる
    /// （`ETXTBSY` と、書き込み可能な fd が exec 先へ残ることを避ける）。開き直しの syscall の失敗は
    /// `SealError::Sys`、seal の不一致は `Unexpected`、実体の不一致は `IdentityMismatch`。
    pub(crate) fn reopen_read_only(
        self,
        proc_dir: BorrowedFd<'_>,
    ) -> Result<SealedReadOnlyCopy, SealError> {
        let writer = std::fs::File::from(self.0);
        let expected = writer
            .metadata()
            .map_err(|e| SealError::Sys(SysError::Os(e.raw_os_error().unwrap_or(EINVAL))))?;
        let reopened = reopen_pinned_read(proc_dir, std::os::fd::AsFd::as_fd(&writer))
            .and_then(above_stdio)
            .map(std::fs::File::from)
            .map_err(SealError::Sys)?;
        let actual = get_seals(std::os::fd::AsFd::as_fd(&reopened)).map_err(SealError::Sys)?;
        if actual != SealSet::EXEC_COPY {
            return Err(SealError::Unexpected {
                actual: actual.bits(),
            });
        }
        let meta = reopened
            .metadata()
            .map_err(|e| SealError::Sys(SysError::Os(e.raw_os_error().unwrap_or(EINVAL))))?;
        if !same_inode(&meta, &expected) {
            return Err(SealError::IdentityMismatch);
        }
        drop(writer);
        Ok(SealedReadOnlyCopy {
            file: reopened,
            meta,
        })
    }
}

/// `fd` が 0〜2 なら 3 以上へ複製して元を閉じる（標準 fd が閉じた呼び出し側で、後段の標準入出力の置換に
/// 潰されないようにする。照合はこの後の fd に対して行う）。
fn above_stdio(fd: OwnedFd) -> Result<OwnedFd, SysError> {
    if fd.as_raw_fd() > 2 {
        return Ok(fd);
    }
    dup_fd_at_least(std::os::fd::AsFd::as_fd(&fd), 3)
}

/// `(st_dev, st_ino)` が一致するか。
fn same_inode(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    (a.dev(), a.ino()) == (b.dev(), b.ino())
}

/// 封印した memfd を読み取り専用で開き直し、seal（0x0F ちょうど）と実体（`(st_dev, st_ino)`）を再照合した fd
/// （TASK-163 追補・#1531・SEC-1）。作れるのは [`SealedMemfd::reopen_read_only`] だけで、「封印を確かめていない
/// fd を複製として実行する」状態を型の上で表せなくする（REPAIR-2）。exec の子が解析（読み取りの借用）と
/// `execveat`（`as_fd`）に使い、所有権は外へ出さない。
#[derive(Debug)]
pub(crate) struct SealedReadOnlyCopy {
    file: std::fs::File,
    meta: std::fs::Metadata,
}

impl SealedReadOnlyCopy {
    /// 読み取り用の借用（シェバン・`PT_INTERP` の解析と `pread`）。読み取り専用で開いており、seal 0x0F の下で
    /// 内容は変えられない。
    pub(crate) fn file(&self) -> &std::fs::File {
        &self.file
    }

    /// 開き直した fd の `fstat`（再照合に使った値）。
    pub(crate) fn metadata(&self) -> &std::fs::Metadata {
        &self.meta
    }
}

/// `fd` に `SealSet::EXEC_COPY` を付け、`F_GET_SEALS` がちょうど 0x0F であることを確かめて
/// [`SealedMemfd`] にする。書き込みを終えた後に呼ぶ（以後の書き込み・伸長・縮小は `EPERM`）。
pub(crate) fn seal_for_exec(fd: OwnedFd) -> Result<SealedMemfd, SealError> {
    let borrowed = std::os::fd::AsFd::as_fd(&fd);
    add_seals(borrowed, SealSet::EXEC_COPY).map_err(SealError::Sys)?;
    let actual = get_seals(borrowed).map_err(SealError::Sys)?;
    if actual != SealSet::EXEC_COPY {
        return Err(SealError::Unexpected {
            actual: actual.bits(),
        });
    }
    Ok(SealedMemfd(fd))
}

/// `fd` の実体を実行してよいかを、実行せずにカーネルへ判定させる（`execveat(fd, "", argv, envp,
/// AT_EMPTY_PATH | AT_EXECVE_CHECK)`。Linux 6.14 以降。封印した複製からの実行〔TASK-163 追補・#1531・SEC-1〕の前提）。
///
/// カーネルは `execveat` と同じ経路で `fd` を実行用に開き直し（マウントの `noexec`・`MAY_EXEC`・Landlock の
/// `EXECUTE`〔継承した domain を含む全層〕）、`security_bprm_creds_for_exec` まで評価したところで戻る（プロセスは
/// 置き換わらない）。呼び出しスレッドに載った最終的な Landlock・seccomp・LSM の下で呼ぶこと（判定はその時点の
/// domain で行われる）。許されなければ `EACCES` 等、`AT_EXECVE_CHECK` を知らないカーネル（6.14 未満）は
/// `EINVAL`（呼び出し側が fail-closed にする）。`argv` は固定の 1 要素（`argc` 0 の警告を避ける）・`envp` は空で、
/// 判定に外部入力を渡さない。ファイルの形式（ELF・シェバン）と、その先のインタープリタは判定しない。
pub(crate) fn exec_check_fd(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let argv: [*const core::ffi::c_char; 2] = [c"exec-check".as_ptr(), std::ptr::null()];
    let envp: [*const core::ffi::c_char; 1] = [std::ptr::null()];
    let nr = consts::SYS_EXECVEAT.get()?;
    // SAFETY: `fd` は生存中の `BorrowedFd`。パス引数は静的な空文字列（NUL 終端）で `AT_EMPTY_PATH` と組で使う。
    // `argv` / `envp` は末尾が NULL のポインタ配列で、要素は静的な NUL 終端文字列を指し、呼び出しの間生存する。
    // `AT_EXECVE_CHECK` によりカーネルは判定だけを行って戻り、呼び出しプロセスを置き換えない（未対応カーネルは
    // フラグを `EINVAL` で拒否し、何も実行しない）。
    let rc = unsafe {
        syscall(
            nr,
            i64::from(fd.as_raw_fd()),
            c"".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            consts::AT_EMPTY_PATH | consts::AT_EXECVE_CHECK,
        )
    };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `close_range(first, last, flags)` を呼ぶ（Linux 5.11 以降。glibc 2.34 未満にラッパーが無いため `syscall(2)` 経由）。
/// 未対応カーネルは `ENOSYS`/`EINVAL` を返す（呼び出し側が fail-closed にする）。
fn close_range_raw(first: u32, last: u32, flags: i64) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let nr = consts::SYS_CLOSE_RANGE.get()?;
    // SAFETY: 引数は整数のみでポインタを取らない（unsigned int 引数は register 幅に拡張して渡され、カーネルは
    // 下位 32 bit を読む）。`flags` は 0（閉じる）か `CLOSE_RANGE_CLOEXEC`（閉じずに close-on-exec を立てる）で、
    // 対象は `first`〜`last` の fd だけ。閉じる場合、呼び出し側（exec 直前の子）はそれらの fd をこの後使わない前提。
    let rc = unsafe { syscall(nr, i64::from(first), i64::from(last), flags) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// fd `first` 以上のすべてを close-on-exec にする（`close_range(first, ~0, CLOSE_RANGE_CLOEXEC)`。
/// Linux 5.11 以降）。exec 後のコンテナへホスト側の fd を漏らさない（CVE-2024-21626 型）。
/// 未対応カーネルは `ENOSYS`/`EINVAL` を返す（呼び出し側が fail-closed にする）。
// テストビルドでは dry-run 差し込み点が本関数を呼ばないため dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn mark_fds_cloexec_from(first: u32) -> Result<(), SysError> {
    close_range_raw(first, u32::MAX, consts::CLOSE_RANGE_CLOEXEC)
}

/// fd `first` 以上のすべてを閉じる（`close_range(first, ~0, 0)`。Linux 5.11 以降）。
/// 呼び出し元から継承したホスト側の fd を、エントリポイントを開く前に断つ。コンテナの rootfs 内の
/// `/proc/self/fd/N` 経由で継承 fd の実体を開かれる経路を塞ぐ（CVE-2024-21626 型）。
/// 未対応カーネルは `ENOSYS`/`EINVAL` を返す（呼び出し側が fail-closed にする）。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn close_fds_from(first: u32) -> Result<(), SysError> {
    close_range_raw(first, u32::MAX, 0)
}

/// fd 1 本（`fd`）だけを閉じる（`close_range(fd, fd, 0)`。結合試験専用。#1299・SEC-1・CORE-1）。
///
/// `exec::close_standard_fds_for_test` が、標準 fd（0〜2）を閉じた呼び出し側を作るために使う。既に閉じている
/// 番号は `EBADF` ではなく成功になる（`close_range` の仕様）ため、閉じる前後の状態は呼び出し側が照合する。
/// 呼び出し側は閉じた番号をこの後使わないこと。未対応カーネルは `ENOSYS`/`EINVAL`（呼び出し側が失敗にする）。
#[cfg(all(feature = "exec-test-support", not(test)))]
pub(crate) fn close_fd_number(fd: u32) -> Result<(), SysError> {
    close_range_raw(fd, fd, 0)
}

/// fd `first` 以上のうち、`keep` の 1 本だけを残してすべて閉じる（TASK-163 追補・#1460）。
///
/// 稼働中コンテナへの exec の子が、`execve` 前の失敗を親へ知らせる pipe の書き込み側（close-on-exec）だけを
/// 残すために使う。`keep` の番号を動かさず、その前後の範囲を 2 回の `close_range` で閉じる（`dup2` で番号を
/// 付け替えると、同じ番号を指す別の所有者と衝突し得るため）。`keep` が `first` 未満なら [`close_fds_from`] と同じ。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn close_fds_from_except(first: u32, keep: BorrowedFd<'_>) -> Result<(), SysError> {
    let Ok(keep) = u32::try_from(keep.as_raw_fd()) else {
        return Err(SysError::Os(EBADF));
    };
    if keep < first {
        return close_range_raw(first, u32::MAX, 0);
    }
    if keep > first {
        close_range_raw(first, keep - 1, 0)?;
    }
    match keep.checked_add(1) {
        Some(next) => close_range_raw(next, u32::MAX, 0),
        None => Ok(()),
    }
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

/// `parent` 配下に新規ファイル `name` を `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` で作って開く。
///
/// `crate::exec::inject_files` が、検証済みの tmpfs ルート fd の直下へ secrets / configs を作るために
/// 使う（SUP-12・TASK-169.4.2）。`O_EXCL` により既存名（既存 symlink を含む。`O_EXCL` の `O_CREAT` は
/// symlink を辿らず `EEXIST`）を拒否する。`mode` は `0o777` 以下に切り詰め、umask の影響を受けるため
/// 呼び出し側が作成後に `fchmod` 相当で最終モードへ設定する。`name` は 1 要素に検証済みの前提。
pub(crate) fn create_file_excl_at(
    parent: BorrowedFd<'_>,
    name: &CStr,
    mode: u32,
) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let flags = consts::O_WRONLY
        | consts::O_CREAT
        | consts::O_EXCL
        | consts::O_NOFOLLOW
        | consts::O_CLOEXEC;
    // SAFETY: `name` は借用した NUL 終端文字列で呼び出しの間生存する。`parent` は生存中の
    // `BorrowedFd`。flags に O_CREAT を含むため、可変長引数として mode を `c_uint` で渡す（`openat` の
    // 宣言は可変長で、整数昇格後の `unsigned int` を読むのが C ABI）。成功時の戻り値は新規 fd で、
    // 直後に `OwnedFd` が唯一の所有者となる（二重 close なし）。
    let fd = unsafe {
        openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags,
            (mode & 0o777) as core::ffi::c_uint,
        )
    };
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

/// procfs の fd エントリ名 `thread-self/fd/<fd>` を、NUL 終端つきで `buf` に組み立てる（アロケーションなし）。
///
/// fork 後・`execve` 前の子（`crate::exec` の `/dev/null` の開き直し。TASK-163 追補・#1459）から呼ぶため、
/// `format!` を使わずスタック上のバッファへ書く。`fd` が負なら `None`。
fn proc_fd_entry(fd: i32, buf: &mut [u8; 32]) -> Option<&CStr> {
    const PREFIX: &[u8] = b"thread-self/fd/";
    let mut value = u32::try_from(fd).ok()?;
    // 10 進の桁を下位から取り出す（u32 は最大 10 桁）。
    let mut digits = [0u8; 10];
    let mut count = 0usize;
    loop {
        *digits.get_mut(count)? = b'0'.checked_add(u8::try_from(value % 10).ok()?)?;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let mut len = 0usize;
    for byte in PREFIX
        .iter()
        .chain(digits.get(..count)?.iter().rev())
        .chain(std::iter::once(&0u8))
    {
        *buf.get_mut(len)? = *byte;
        len += 1;
    }
    CStr::from_bytes_with_nul(buf.get(..len)?).ok()
}

/// 保持中の `O_PATH` fd `pinned` が指す inode を、procfs のディレクトリ fd `proc_dir` 配下の
/// `thread-self/fd/N`（magic link）経由で `O_RDWR|O_NOCTTY|O_CLOEXEC` に開き直す（TASK-163 追補・#1459）。
///
/// パスを再解決せず `pinned` が固定した inode そのものを開くため、呼び出し側が `pinned` への `fstat` で
/// 確かめた種別・デバイス番号と、開く実体が食い違わない（検査の後に名前を差し替えられても影響しない）。
/// `O_NOCTTY` は、開いた端末を呼び出しプロセスの制御端末にしないため（検証済みの実体が端末でなくても常に付ける）。
/// 呼び出し側の前提: `proc_dir` が本物の procfs であること（[`fs_type`] で [`PROC_MAGIC`] と照合済み）と、
/// `pinned` の種別を確認済みであること。アロケーションを伴わない（fork 後の子から呼べる）。
pub(crate) fn reopen_pinned_rdwr_noctty(
    proc_dir: BorrowedFd<'_>,
    pinned: BorrowedFd<'_>,
) -> Result<OwnedFd, SysError> {
    let mut buf = [0u8; 32];
    let name = proc_fd_entry(pinned.as_raw_fd(), &mut buf).ok_or(SysError::Os(EBADF))?;
    open_follow_at(proc_dir, name, consts::O_RDWR | consts::O_NOCTTY)
}

/// 保持中の `O_PATH` fd `pinned` が指す inode を、procfs のディレクトリ fd `proc_dir` 配下の
/// `thread-self/fd/N`（magic link）経由で `O_RDONLY|O_NONBLOCK|O_NOCTTY|O_CLOEXEC` に開き直す
/// （TASK-163 追補・#1458）。
///
/// `crate::exec` のインタープリタ検査が、ランタイムのバイナリでないことを `O_PATH` の fd で確かめた通常ファイルの
/// 先頭を読むために使う。[`reopen_pinned_read_nonblock`] と違い `format!` を使わず（fork 後の子から呼ぶ）、
/// 起点の procfs を呼び出し側が検証して渡す。前提は [`reopen_pinned_rdwr_noctty`] と同じ。
pub(crate) fn reopen_pinned_read(
    proc_dir: BorrowedFd<'_>,
    pinned: BorrowedFd<'_>,
) -> Result<OwnedFd, SysError> {
    let mut buf = [0u8; 32];
    let name = proc_fd_entry(pinned.as_raw_fd(), &mut buf).ok_or(SysError::Os(EBADF))?;
    open_follow_at(
        proc_dir,
        name,
        consts::O_RDONLY | consts::O_NONBLOCK | consts::O_NOCTTY,
    )
}

/// `parent` 配下の既存ファイル `name` を書き込み専用（`O_NOFOLLOW`）で開く。
/// `cgroup.procs`・`cgroup.subtree_control` への書き込みに使う（CORE-3）。
pub(crate) fn open_write_at(parent: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd, SysError> {
    open_file_at(parent, name, consts::O_WRONLY)
}

/// `fd` が属するファイルシステムの種別（`statfs.f_type`）を `fstatfs(2)` で返す。cgroup2 の
/// 検証（`consts::CGROUP2_SUPER_MAGIC` との比較）に使う。O_PATH fd でも使える。
pub(crate) fn fs_type(fd: BorrowedFd<'_>) -> Result<i64, SysError> {
    statfs_of(fd).map(|buf| buf.f_type)
}

/// `fd` が開かれているマウントのフラグ（`statfs.f_flags`。`ST_*`）。生の整数を `sys` の外へ出さない newtype
/// （REPAIR-2）。封印した複製からの実行（TASK-163 追補・#1531・SEC-1）が、元のファイルのマウントの `noexec` を
/// 複製の前に確かめるのに使う。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MountFlags(i64);

impl MountFlags {
    /// 生の `f_flags` から作る（単体テストが境界値を組み立てる用）。
    #[cfg(test)]
    pub(crate) const fn from_bits(bits: i64) -> Self {
        Self(bits)
    }

    /// カーネルが `f_flags` を埋めたか（`ST_VALID`。Linux 2.6.36 以降は常に立つ）。立っていない値は
    /// マウントフラグとして信用できない（呼び出し側は判定不能として拒否に倒す）。
    pub(crate) fn is_valid(self) -> bool {
        self.0 & consts::ST_VALID != 0
    }

    /// マウントが `nodev`（`ST_NODEV`。`MNT_NODEV` 由来）か。rootfs の nodev 付与の事後検証に使う
    /// （`crate::exec::prepare_rootfs`。#1676・SEC-1）。
    pub(crate) fn is_nodev(self) -> bool {
        self.0 & consts::ST_NODEV != 0
    }

    /// マウントが `noexec`（`ST_NOEXEC`。`MNT_NOEXEC` 由来）か。
    pub(crate) fn is_noexec(self) -> bool {
        self.0 & consts::ST_NOEXEC != 0
    }
}

/// `fd` が開かれているマウント（`fd` の `f_path.mnt`）のフラグを `fstatfs(2)` で返す（パスを再解決しない）。
///
/// `f_flags` はカーネルが `fd` の vfsmount のフラグ（`MNT_NOEXEC` → `ST_NOEXEC` 等）と superblock のフラグから
/// 作る値で、`execveat(fd, "", AT_EMPTY_PATH)` が `path_noexec` で見るマウントと同じものを指す。superblock 単位の
/// `SB_I_NOEXEC`（procfs 等）は含まない（呼び出し側は `exec_check_fd` と併用する）。O_PATH fd でも使える。
pub(crate) fn mount_flags(fd: BorrowedFd<'_>) -> Result<MountFlags, SysError> {
    statfs_of(fd).map(|buf| MountFlags(buf.f_flags))
}

/// `fstatfs(2)` の本体（[`fs_type`]・[`mount_flags`] が共有する）。
fn statfs_of(fd: BorrowedFd<'_>) -> Result<StatFs, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut buf = StatFs {
        f_type: 0,
        #[cfg(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        _before_flags: [0; 9],
        f_flags: 0,
        #[cfg(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        _spare: [0; 4],
    };
    // SAFETY: `buf` は `struct statfs`（120 バイト）と同じレイアウトの書き込み可能な領域で、
    // 呼び出しの間生存する（対応 arch のみ。対応外は上で `Unsupported`）。`fd` は生存中の
    // `BorrowedFd`。カーネルは `buf` の範囲内にのみ書く。
    let rc = unsafe { fstatfs(fd.as_raw_fd(), &raw mut buf) };
    if rc == -1 {
        return Err(last_error());
    }
    Ok(buf)
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

/// 呼び出しプロセスを新しいセッションのリーダーにし、制御端末から切り離す（`setsid(2)`。
/// SUP-6・SEC-1・TASK-163 追補・#1456）。戻り値は新しいセッション ID（= 呼び出しプロセスの pid）。
///
/// `crate::exec` の exec 直前の子（launch の PID 1・稼働中コンテナへの exec の子）が、呼び出し側の
/// セッションと制御端末をコンテナ内のコマンドへ引き継がせないために呼ぶ。新しいセッションは制御端末を
/// 持たないため、以後 `/dev/tty` は `ENXIO` になる（端末を `O_NOCTTY` なしで開けば取得し得るため、
/// 呼び出し側は以後の open に `O_NOCTTY` を付ける）。呼び出しプロセスがプロセスグループのリーダーだと
/// `EPERM`（fork 直後の子はリーダーでないため成立しない。失敗時は呼び出し側が fail-closed にする）。
/// 引数・ポインタを取らず、アロケーション・ロックを伴わない（fork 後の子から呼べる）。
// テストビルドでは dry-run 差し込み点が本関数を呼ばない（libtest のプロセスのセッションを変えないため）。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn new_session() -> Result<u32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数を取らずポインタも渡さない。効果は呼び出しプロセスのセッション・プロセスグループの
    // 付け替えのみで、メモリには触れない。戻り値が -1 のときは直後に errno を確保する。
    let sid = unsafe { setsid() };
    if sid < 0 {
        return Err(last_error());
    }
    u32::try_from(sid).map_err(|_| SysError::Os(EINVAL))
}

/// 呼び出しスレッドの補助グループの件数を返す（`getgroups(0, NULL)`。SUP-6・SEC-1・TASK-163 追補・#1457）。
///
/// `crate::exec` の capability 削減段が、補助グループを消去する前後に件数を確かめるために使う。サイズ 0 の
/// 呼び出しはリストを書き込まず件数だけを返すため、バッファを渡さない。
pub(crate) fn supplementary_group_count() -> Result<usize, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let nr = consts::SYS_GETGROUPS.get()?;
    // SAFETY: `getgroups(int size, gid_t *list)` に size = 0 と NULL を渡す。size が 0 のときカーネルは `list` を
    // 参照せず件数だけを返す（getgroups(2)）ため、ポインタは読み書きされない。引数は register 幅の整数として渡す。
    let count = unsafe { syscall(nr, 0i64, core::ptr::null_mut::<u32>()) };
    if count < 0 {
        return Err(last_error());
    }
    usize::try_from(count).map_err(|_| SysError::Os(EINVAL))
}

/// 呼び出しスレッドの補助グループをすべて消去する（`setgroups(0, NULL)`。SUP-6・SEC-1・SEC-5・TASK-163 追補・
/// #1457）。
///
/// 自分の user namespace の `CAP_SETGID` を要し、user namespace が `setgroups` を `deny` にしている場合
/// （非特権で作った user namespace。`/proc/<pid>/setgroups`）は権限があっても `EPERM` になる。生の syscall のため
/// 効果は呼び出しスレッドだけに及ぶ（呼び出し側が単一スレッドであることを確かめる）。
// テストビルドでは capability 削減段が偽のカーネルを使い、本関数を呼ばない（libtest のプロセスの資格情報を
// 変えないため）。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn clear_supplementary_groups() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let nr = consts::SYS_SETGROUPS.get()?;
    // SAFETY: `setgroups(size_t size, const gid_t *list)` に size = 0 と NULL を渡す。size が 0 のときカーネルは
    // `list` を読まない（空のグループ集合を設定する）ため、ポインタは参照されない。効果は呼び出しスレッドの
    // 資格情報（補助グループ）の変更のみで、メモリには触れない。
    let rc = unsafe { syscall(nr, 0i64, core::ptr::null::<u32>()) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// `signal(2)` の `SIG_DFL`（既定動作）と `SIG_ERR`（失敗）。`sighandler_t` はポインタ幅。
const SIG_DFL: usize = 0;
const SIG_ERR: usize = usize::MAX;
/// `signal(2)` の `SIG_IGN`（無視。include/uapi/asm-generic/signal-defs.h の `((__sighandler_t)1)`）。
#[cfg(feature = "exec-test-support")]
const SIG_IGN: usize = 1;

/// 結合試験専用: 自プロセスの `SIGCHLD` を `ignored` なら `SIG_IGN`、そうでなければ `SIG_DFL` にする
/// （`FileAuditSink` の子プロセス隔離が、`SIGCHLD` を無視するプロセス〔子が自動回収され `waitpid` が
/// `ECHILD` を返す〕でも主経路の結果を取り違えないことの照合用。REPAIR-5・SEC-4・TASK-163 追補・#1594）。
///
/// `tests/audit_sink_isolation.rs` の単一スレッドの `main` からだけ呼ぶ。プロセス全体の disposition を
/// 変えるため、他の試験と同じプロセスで並行に使わない。
#[cfg(feature = "exec-test-support")]
pub(crate) fn set_child_signal_ignored_for_test(ignored: bool) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let handler = if ignored { SIG_IGN } else { SIG_DFL };
    // SAFETY: 引数は整数（`SIG_IGN` = 1 / `SIG_DFL` = 0）のみでポインタを取らない。ハンドラ関数を
    // 登録しないため、シグナルハンドラの再入・非同期安全性の問題は生じない。対象は `SIGCHLD` の定数だけ。
    let prev = unsafe { signal(consts::SIGCHLD, handler) };
    if prev == SIG_ERR {
        Err(last_error())
    } else {
        Ok(())
    }
}

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
/// `ENOSYS` / `EPERM` 等を返す（呼び出し側が `kill(2)` へ退避する）。失敗理由の分類（未対応・拒否・資源枯渇）と
/// 観測は呼び出し側（`exec::ContainerChild`。#1617）が行い、ここでは errno をそのまま返す。fd は close-on-exec で返る。
pub(crate) fn pidfd_open(pid: u32) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let raw = positive_pid(pid)?;
    let nr = consts::SYS_PIDFD_OPEN.get()?;
    // SAFETY: 引数は整数のみでポインタを取らない（glibc 2.36 未満に無いため `syscall(2)` 経由）。
    // `raw` は正であることを確認済み。flags は 0 で、成功時は新規 fd を返す。
    let fd = unsafe { syscall(nr, i64::from(raw), 0_i64) };
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
    let nr = consts::SYS_PIDFD_SEND_SIGNAL.get()?;
    // SAFETY: `pidfd` は呼び出しの間有効な fd（`BorrowedFd`）。`info` は NULL（カーネルが siginfo を
    // 既定値で作る）で、ポインタ引数は書き込み・読み出しされない。`number` は検証済みの値、flags は 0。
    let rc = unsafe {
        syscall(
            nr,
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

/// 呼び出したプロセスを non-dumpable にする（`PR_SET_DUMPABLE` = 0。SUP-6・SEC-1・TASK-163.4・#503）。
///
/// `crate::exec` の exec 専用 worker（`spawn_exec_worker` の子）が、稼働中コンテナの namespace へ参加する前に
/// 呼ぶ。exec の子は fork した時点でコンテナの PID namespace に入り、`close_range` と `execve` までの間
/// コンテナ側の procfs から見える。dumpable のままだと、同じ uid のコンテナ内プロセスが `/proc/<pid>/fd` 等
/// （`PTRACE_MODE_READ_FSCREDS`）や `ptrace` の attach を通じて、ホスト側の fd・メモリへ届く
/// （CVE-2016-9962 型）。non-dumpable にすると、これらは対象の user namespace の `CAP_SYS_PTRACE` を持たない
/// プロセスから拒否される。
///
/// フラグはプロセス（`mm`）単位で全スレッドに効き、fork で子へ継承される。`execve` は資格情報が変わらない
/// 限り dumpable を 1 へ戻すため、コンテナ内で実行されるコマンド自身は launch 経路のプロセスと同じ扱いに
/// なる。capability の削減（`capset`・bounding set の drop）は dumpable を変えない（カーネルが dumpable を
/// 落とすのは uid / gid の変化か capability の増加のときだけ）。
pub(crate) fn set_non_dumpable() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみでポインタを渡さない。可変長部は `unsigned long` に合わせて u64 で渡す
    // （arg2 = 0 が `SUID_DUMP_DISABLE`。arg3〜5 はカーネルが参照しないが 0 に揃える）。呼び出した
    // プロセスの `mm` のフラグを下げるだけで、メモリの内容・fd には触れない。
    let rc = unsafe { prctl(consts::PR_SET_DUMPABLE, 0u64, 0u64, 0u64, 0u64) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// 親が終了したら呼び出しプロセスへ `SIGKILL` が届くようにする（`PR_SET_PDEATHSIG`。SUP-6・REPAIR-5・
/// TASK-163.4・#503）。
///
/// `crate::exec` の exec 経路（`exec/exec_command.rs`）で、fork した子（worker・コマンド）が最初に呼ぶ。
/// worker が全体の期限で強制終了されたとき、worker が待っていたコマンドを孤児として残さないために使う。
///
/// - 対象は「このプロセスを作ったスレッド」の終了。設定より前に親が終了していた場合はシグナルが届かない
///   ため、呼び出し側は設定の **後** に親の生存を別の手段（親の pidfd）で確かめること
/// - 設定はプロセス（スレッド）単位で、fork した子へは継承されない。資格情報が変わらない `execve` では
///   保持される（set-uid / capability 付きの実行ファイルではカーネルが解除するが、`NO_NEW_PRIVS` の下では
///   資格情報が変わらない）。実行されたプログラム自身は `prctl` で解除できる
/// - 親が別の PID namespace にいてもカーネルは届ける（`forget_original_parent` が子の `pdeath_signal` を送る）
pub(crate) fn set_parent_death_sigkill() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let Ok(signal) = u64::try_from(consts::SIGKILL) else {
        return Err(SysError::Os(EINVAL));
    };
    // SAFETY: 引数は整数のみでポインタを渡さない。可変長部は `unsigned long` に合わせて u64 で渡す
    // （arg2 がシグナル番号。`SIGKILL` の定数だけを渡す。arg3〜5 はカーネルが参照しないが 0 に揃える）。
    // 呼び出したスレッドの `pdeath_signal` を設定するだけで、メモリ・fd には触れない。
    let rc = unsafe { prctl(consts::PR_SET_PDEATHSIG, signal, 0u64, 0u64, 0u64) };
    if rc == -1 { Err(last_error()) } else { Ok(()) }
}

/// 呼び出したプロセスが dumpable か（`PR_GET_DUMPABLE`。SUP-6・SEC-1・TASK-163.4・#503）。
///
/// `0`（`SUID_DUMP_DISABLE`）だけを non-dumpable として `Ok(false)` を返す。`1`（`SUID_DUMP_USER`）と
/// `2`（`SUID_DUMP_ROOT`。`fs.suid_dumpable=2` のホストで資格情報が変わったプロセス）は、コンテナ側から
/// procfs 経由で読める・core が書かれる状態を含むため `Ok(true)`。想定外の値は `EINVAL`（fail-closed）。
pub(crate) fn is_dumpable() -> Result<bool, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数は整数のみでポインタを渡さない。可変長部は u64 の 0 を 4 つ渡す（カーネルは参照しない）。
    // 読み取りだけで状態を変えない。
    let rc = unsafe { prctl(consts::PR_GET_DUMPABLE, 0u64, 0u64, 0u64, 0u64) };
    match rc {
        -1 => Err(last_error()),
        0 => Ok(false),
        1 | 2 => Ok(true),
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
    let nr = consts::SYS_CAPGET.get()?;
    // SAFETY: `header` と `data`（v3 が要求する 2 要素）はこの関数のスタック上の `#[repr(C)]` 値で、
    // 呼び出しの間有効かつ排他的に借用されている。可変長部のポインタはカーネルが
    // `CapUserHeader` と `[CapUserData; 2]` の大きさだけ読み書きする。影響は呼び出したスレッドの
    // 読み取りのみ。
    let rc = unsafe { syscall(nr, &raw mut header, data.as_mut_ptr()) };
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
    let nr = consts::SYS_CAPSET.get()?;
    // SAFETY: `header` と `data`（v3 が要求する 2 要素）はスタック上の `#[repr(C)]` 値で、呼び出しの
    // 間有効。カーネルは読み取りのみ行う（const ポインタ）。資格情報の変更は呼び出したスレッドに
    // 限られ、メモリ安全性には影響しない。
    let rc = unsafe { syscall(nr, &raw const header, data.as_ptr()) };
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
    let nr = consts::SYS_LANDLOCK_CREATE_RULESET.get()?;
    // SAFETY: attr は NULL・size は 0 で、VERSION フラグの問い合わせではカーネルはメモリを読まない
    // （それ以外の組み合わせは EINVAL）。fd を作らずプロセス状態も変えない読み取り専用の問い合わせ。
    // `landlock_create_ruleset` は glibc に無いため可変長の `syscall(2)` 経由で呼び、引数は
    // ポインタ・`usize`・`u64` とレジスタ幅で渡す（32 bit 値を可変長で渡すと上位ビットが未規定に
    // なり得るため、flags は `prctl` と同様に `u64` へ拡幅する。カーネルは `__u32` へ切り詰める）。
    let rc = unsafe {
        syscall(
            nr,
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
    let nr = consts::SYS_LANDLOCK_CREATE_RULESET.get()?;
    // SAFETY: `attr` はスタック上の `#[repr(C)]` 値（24 バイト）で呼び出しの間有効。カーネルは
    // `size` バイトを読んでコピーするだけでポインタを保持しない。`size` は実際の構造体サイズと一致する。
    // flags は 0。可変長 `syscall(2)` へはポインタ・`usize`・`u64` とレジスタ幅で渡す。
    let rc = unsafe {
        syscall(
            nr,
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
    let nr = consts::SYS_LANDLOCK_ADD_RULE.get()?;
    // SAFETY: `attr` はスタック上の packed `#[repr(C)]` 値（12 バイト）で呼び出しの間有効。
    // カーネルは読み取りのみでポインタを保持しない。`ruleset`・`parent` は生存中の `BorrowedFd`。
    // flags は 0。可変長引数はレジスタ幅（`i32` は `i64` へ拡幅して符号を保つ）で渡す。
    let rc = unsafe {
        syscall(
            nr,
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
    let nr = consts::SYS_LANDLOCK_RESTRICT_SELF.get()?;
    // SAFETY: 引数は生存中の `BorrowedFd` の fd 番号と flags 0 の整数のみでポインタを渡さない。
    // メモリには触れず、影響は呼び出したスレッドの Landlock ドメインの追加（権限を減らす方向）のみ。
    let rc = unsafe { syscall(nr, i64::from(ruleset.as_raw_fd()), 0u64) };
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
    let nr = consts::SYS_PTRACE.get()?;
    // SAFETY: 引数はすべて整数（request・pid・addr=0・data=0）でポインタを渡さず、PTRACE_CONT では
    // カーネルは data をシグナル番号としてしか読まない（メモリは読まない）。attach を伴わないため、
    // フィルタが欠けていても対象プロセスへの副作用は無い（`ESRCH`）。
    let rc = unsafe { syscall(nr, consts::PTRACE_CONT, i64::from(pid), 0_i64, 0_i64) };
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
    let nr = consts::SYS_KEXEC_LOAD.get()?;
    // SAFETY: segments は NULL（整数 0 として渡す）。nr_segments が上限を超えるためカーネルは
    // segments を読む前に拒否する。flags は無効値で、どの経路でもロード・アンロードに至らない。
    let rc = unsafe {
        syscall(
            nr,
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

/// `O_NONBLOCK` 単体（アーキテクチャ別の値）。`/proc/self/fd` 経由の開き直しで FIFO 等に止まらないために使う。
///
/// `crate::open_flags` が呼ぶ。対応外アーキテクチャでは `None`（fail-closed）。`unsafe` を含まない。
pub(crate) fn nonblock_open_flag() -> Option<i32> {
    consts::SUPPORTED.then_some(consts::O_NONBLOCK)
}

/// `O_NOCTTY` 単体（アーキテクチャ別の値）。結合試験用の観測（`crate::exec` の `LandlockAccessKind::OpenNoCtty`）が、
/// `/dev/ptmx` を制御端末にせずに開くために使う（#1672 事後監査 P2）。対応外アーキテクチャでは `None`（fail-closed）。
/// 定数を返すだけで syscall を呼ばない。
pub(crate) fn noctty_open_flag() -> Option<i32> {
    consts::SUPPORTED.then_some(consts::O_NOCTTY)
}

/// `O_NONBLOCK | O_NOFOLLOW | O_DIRECTORY`。親ディレクトリを 1 要素ずつ symlink 非追従で開くための値。
///
/// `crate::open_flags` が呼ぶ。対応外アーキテクチャでは `None`（fail-closed）。`unsafe` を含まない。
pub(crate) fn directory_nofollow_nonblock_open_flags() -> Option<i32> {
    consts::SUPPORTED.then_some(consts::O_NONBLOCK | consts::O_NOFOLLOW | consts::O_DIRECTORY)
}

/// `O_PATH | O_NOFOLLOW`。最終要素を副作用なく固定するための値。
///
/// `crate::open_flags` が呼ぶ。対応外アーキテクチャでは `None`（fail-closed）。`unsafe` を含まない。
pub(crate) fn path_nofollow_open_flags() -> Option<i32> {
    consts::SUPPORTED.then_some(consts::O_PATH | consts::O_NOFOLLOW)
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
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn core5_probe_consts_are_exact_x86_64() {
        assert_eq!(consts::SYS_PTRACE.get().map(SyscallNumber::raw), Ok(101));
        assert_eq!(
            consts::SYS_KEXEC_LOAD.get().map(SyscallNumber::raw),
            Ok(246)
        );
        assert_eq!(consts::PTRACE_CONT, 7);
        assert_eq!(consts::KEXEC_SEGMENT_MAX, 16);
    }

    /// CORE-5・TASK-38.4: プローブ用定数の固定値照合（aarch64）。
    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    #[test]
    fn core5_probe_consts_are_exact_aarch64() {
        assert_eq!(consts::SYS_PTRACE.get().map(SyscallNumber::raw), Ok(117));
        assert_eq!(
            consts::SYS_KEXEC_LOAD.get().map(SyscallNumber::raw),
            Ok(104)
        );
        assert_eq!(consts::PTRACE_CONT, 7);
        assert_eq!(consts::KEXEC_SEGMENT_MAX, 16);
    }

    /// CORE-1・CORE-2・TASK-30.1（#1619）: pidfd 系の syscall 番号を `ArchSysNo::get` 経由で照合する。
    /// 424・434 は全アーキテクチャ共通の番号帯（x86_64 は syscall_64.tbl、aarch64 は asm-generic/unistd.h）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core1_task30_pidfd_syscall_numbers_are_exact() {
        assert_eq!(
            (
                consts::SYS_PIDFD_SEND_SIGNAL.get().map(SyscallNumber::raw),
                consts::SYS_PIDFD_OPEN.get().map(SyscallNumber::raw)
            ),
            (Ok(424), Ok(434))
        );
    }

    /// SEC-1・CORE-5（#1619）: 対応 arch の `ArchSysNo::new` は 0 以下を拒否する。`SYS_*` の `const` では
    /// コンパイルエラーになり、`const` 文脈の外で呼んだ場合も番号を作らずに panic する。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    #[should_panic(expected = "syscall number must be positive")]
    fn sec1_issue1619_arch_sysno_new_rejects_zero() {
        let zero = std::hint::black_box(0_i64);
        let _ = ArchSysNo::new(zero);
    }

    /// SEC-1・CORE-5（#1619）: 対応外 arch（x32・aarch64 ILP32・riscv64 等）では、どの番号も `get` が
    /// `Unsupported` を返し発行されない。CI の 3 OS では対象外で、対応外 target の型検査でだけ確かめる。
    #[cfg(not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    #[test]
    fn sec1_issue1619_unsupported_arch_get_is_unsupported() {
        let numbers = [
            consts::SYS_PIVOT_ROOT,
            consts::SYS_CLOSE_RANGE,
            consts::SYS_MOVE_MOUNT,
            consts::SYS_FSOPEN,
            consts::SYS_FSCONFIG,
            consts::SYS_FSMOUNT,
            consts::SYS_OPEN_TREE,
            consts::SYS_MOUNT_SETATTR,
            consts::SYS_PIDFD_SEND_SIGNAL,
            consts::SYS_PIDFD_OPEN,
            consts::SYS_EXECVEAT,
            consts::SYS_MEMFD_CREATE,
            consts::SYS_LANDLOCK_CREATE_RULESET,
            consts::SYS_LANDLOCK_ADD_RULE,
            consts::SYS_LANDLOCK_RESTRICT_SELF,
            consts::SYS_CAPGET,
            consts::SYS_CAPSET,
            consts::SYS_GETGROUPS,
            consts::SYS_SETGROUPS,
            consts::SYS_PTRACE,
            consts::SYS_KEXEC_LOAD,
        ];
        let errors: Vec<_> = numbers.iter().map(|n| n.get().err()).collect();
        assert_eq!(errors, vec![Some(SysError::Unsupported); 21]);
    }

    /// CORE-5・TASK-39.1: Landlock 関連定数の固定値照合（arch ごとに個別定義した値の誤り検出）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core5_landlock_consts_are_exact() {
        assert_eq!(
            consts::SYS_LANDLOCK_CREATE_RULESET
                .get()
                .map(SyscallNumber::raw),
            Ok(444)
        );
        assert_eq!(consts::LANDLOCK_CREATE_RULESET_VERSION, 1);
        assert_eq!(consts::EOPNOTSUPP, 95);
    }

    /// CORE-5・TASK-39.3: Landlock 適用系の定数・構造体レイアウトの固定値照合。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core5_landlock_apply_consts_and_layout_are_exact() {
        assert_eq!(
            consts::SYS_LANDLOCK_ADD_RULE.get().map(SyscallNumber::raw),
            Ok(445)
        );
        assert_eq!(
            consts::SYS_LANDLOCK_RESTRICT_SELF
                .get()
                .map(SyscallNumber::raw),
            Ok(446)
        );
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
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
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
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core3_task32_1_cgroup_consts_are_exact() {
        assert_eq!((consts::O_RDONLY, consts::O_WRONLY), (0, 1));
        assert_eq!(consts::AT_REMOVEDIR, 0x200);
        assert_eq!((EBUSY, ENOTEMPTY), (16, 39));
        assert_eq!(consts::CGROUP2_SUPER_MAGIC, 0x6367_7270);
        assert_eq!(std::mem::size_of::<StatFs>(), 120);
    }

    /// SEC-1（TASK-163 追補・#1531）: `statfs.f_flags` の位置と `ST_*` の具体値（include/linux/statfs.h）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sec1_task163_statfs_flags_layout_and_consts_are_exact() {
        assert_eq!(std::mem::offset_of!(StatFs, f_flags), 80);
        assert_eq!(std::mem::size_of::<StatFs>(), 120);
        assert_eq!((consts::ST_NOEXEC, consts::ST_VALID), (0x8, 0x20));
        let flags = MountFlags::from_bits(0x20 | 0x8);
        assert!(flags.is_valid() && flags.is_noexec());
        assert!(!MountFlags::from_bits(0x20).is_noexec());
        assert!(!MountFlags::from_bits(0x8).is_valid());
    }

    /// `/proc/self/mountinfo` から、マウントポイント `mount_point` のマウントごとのオプション（6 列目）を返す。
    fn mount_options_of(mount_point: &str) -> Option<String> {
        let text = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        text.lines().rev().find_map(|line| {
            let mut cols = line.split(' ');
            let point = cols.nth(4)?;
            let options = cols.next()?;
            (point == mount_point).then(|| options.to_owned())
        })
    }

    /// SEC-1（TASK-163 追補・#1531）: `mount_flags` が fd のマウントの `noexec` を返す。`/proc`（mountinfo で
    /// `noexec` と確かめたうえで）は `ST_NOEXEC` 付き、`noexec` でない `/` は付かない。どちらも `ST_VALID` が立つ。
    /// mountinfo の値と照合するため、前提（`/proc` が `noexec`・`/` が `noexec` でない）が崩れた環境では失敗する
    /// （skip しない。systemd・コンテナ実行環境の既定はどちらもこの前提を満たす）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sec1_task163_mount_flags_report_noexec_of_the_fd_mount() {
        let has_noexec = |opts: &str| opts.split(',').any(|o| o == "noexec");
        let proc_opts = mount_options_of("/proc").expect("/proc is mounted");
        assert!(has_noexec(&proc_opts), "/proc must be noexec: {proc_opts}");
        let root_opts = mount_options_of("/").expect("/ is mounted");
        assert!(!has_noexec(&root_opts), "/ must not be noexec: {root_opts}");
        let proc_file = std::fs::File::open("/proc/self/status").expect("open status");
        let proc_flags = mount_flags(proc_file.as_fd()).expect("fstatfs /proc");
        assert_eq!(
            (proc_flags.is_valid(), proc_flags.is_noexec()),
            (true, true)
        );
        let root = std::fs::File::open("/").expect("open /");
        let root_flags = mount_flags(root.as_fd()).expect("fstatfs /");
        assert_eq!(
            (root_flags.is_valid(), root_flags.is_noexec()),
            (true, false)
        );
    }

    /// CORE-3・TASK-32.1: `/proc` が procfs と判定され、cgroup2 とは区別されること。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core3_task32_1_fs_type_identifies_procfs_not_cgroup2() {
        let proc_dir = std::fs::File::open("/proc").unwrap();
        // procfs の PROC_SUPER_MAGIC（include/uapi/linux/magic.h）。
        assert_eq!(PROC_MAGIC, 0x9fa0);
        assert_eq!(fs_type(proc_dir.as_fd()), Ok(PROC_MAGIC));
        assert_ne!(fs_type(proc_dir.as_fd()), Ok(CGROUP2_MAGIC));
    }

    /// CORE-3・TASK-32.1: `mkdir_at` / `remove_dir_at` / `open_*_at` の往復（一時ディレクトリ）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core3_task32_1_mkdir_open_remove_roundtrip() {
        use std::io::Write as _;
        let guard = crate::test_support::TestTempDir::new("sys-roundtrip").unwrap();
        let base = guard.path().to_path_buf();
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
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1457）: `getgroups` / `setgroups` の syscall 番号（x86_64 は
    /// syscall_64.tbl、aarch64 は asm-generic/unistd.h）と、件数の取得が実プロセスの `Groups:` と一致すること。
    #[test]
    fn sup6_task163_group_syscall_numbers_and_count_are_exact() {
        #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
        assert_eq!(
            (
                consts::SYS_GETGROUPS.get().map(SyscallNumber::raw),
                consts::SYS_SETGROUPS.get().map(SyscallNumber::raw)
            ),
            (Ok(115), Ok(116))
        );
        #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
        assert_eq!(
            (
                consts::SYS_GETGROUPS.get().map(SyscallNumber::raw),
                consts::SYS_SETGROUPS.get().map(SyscallNumber::raw)
            ),
            (Ok(158), Ok(159))
        );
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        let groups = status
            .lines()
            .find_map(|l| l.strip_prefix("Groups:"))
            .unwrap()
            .split_whitespace()
            .count();
        assert_eq!(supplementary_group_count(), Ok(groups));
    }

    /// SEC-1・TASK-37.1: capability 関連の定数の具体値。
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn sec1_capability_consts_are_exact_x86_64() {
        assert_eq!(consts::SYS_CAPGET.get().map(SyscallNumber::raw), Ok(125));
        assert_eq!(consts::SYS_CAPSET.get().map(SyscallNumber::raw), Ok(126));
        assert_eq!(consts::LINUX_CAPABILITY_VERSION_3, 0x2008_0522);
        assert_eq!(consts::PR_CAPBSET_READ, 23);
        assert_eq!(consts::PR_CAPBSET_DROP, 24);
        assert_eq!(consts::PR_CAP_AMBIENT, 47);
        assert_eq!(consts::PR_CAP_AMBIENT_CLEAR_ALL, 4);
    }

    /// SEC-1・TASK-37.1: capability 関連の定数の具体値（aarch64）。
    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    #[test]
    fn sec1_capability_consts_are_exact_aarch64() {
        assert_eq!(consts::SYS_CAPGET.get().map(SyscallNumber::raw), Ok(90));
        assert_eq!(consts::SYS_CAPSET.get().map(SyscallNumber::raw), Ok(91));
        assert_eq!(consts::LINUX_CAPABILITY_VERSION_3, 0x2008_0522);
        assert_eq!(consts::PR_CAPBSET_READ, 23);
        assert_eq!(consts::PR_CAPBSET_DROP, 24);
        assert_eq!(consts::PR_CAP_AMBIENT, 47);
        assert_eq!(consts::PR_CAP_AMBIENT_CLEAR_ALL, 4);
    }

    /// `/proc/thread-self/status` の `field:` 行（16 進 64 bit）を 2 語にする。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
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
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
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
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sec1_cap_bounding_read_beyond_last_cap_is_einval() {
        assert_eq!(cap_bounding_contains(63), Err(SysError::Os(EINVAL)));
        assert_eq!(cap_bounding_contains(0).map(|_| ()), Ok(()));
    }

    /// CORE-5・TASK-38.2: seccomp 適用の定数とレイアウトの具体値。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
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
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core1_prctl_no_new_privs_consts_are_exact() {
        assert_eq!(consts::PR_SET_NO_NEW_PRIVS, 38);
        assert_eq!(consts::PR_GET_NO_NEW_PRIVS, 39);
    }

    /// SUP-6・TASK-163.4: `prctl` の dumpable・親死亡シグナルのオプションの具体値（include/uapi/linux/prctl.h）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sup6_task163_4_prctl_dumpable_consts_are_exact() {
        assert_eq!(consts::PR_GET_DUMPABLE, 3);
        assert_eq!(consts::PR_SET_DUMPABLE, 4);
        assert_eq!(consts::PR_SET_PDEATHSIG, 1);
        // 親死亡シグナルの実 syscall は単体テストでは呼ばない（設定はスレッド単位で、テストプロセスを起動した
        // スレッドが先に終わるとテストプロセス全体へ SIGKILL が届く）。実プロセスでの照合は supervisor の
        // 結合試験 `exec_timeout` が行う。
    }

    /// SUP-6・SEC-1・TASK-163.4: テストプロセス自身は dumpable（`PR_GET_DUMPABLE` が 1）で、`/proc/self` 配下の
    /// 所有者は自分の euid。dumpable はプロセス単位で元へ戻すと他のテストと競合するため、ここでは読み取り
    /// だけを確かめる。`set_non_dumpable` の実 syscall と読み戻しは、単一スレッドの使い捨て worker で行う
    /// supervisor の結合試験 `exec_timeout`（既定のテスト集合）が照合する。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn sup6_task163_4_test_process_is_dumpable() {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(is_dumpable(), Ok(true));
        let owner = std::fs::metadata("/proc/self/fd").unwrap().uid();
        assert_eq!(owner, effective_uid());
    }

    /// CORE-1・TASK-27.4.3: 専用スレッドで set し、GET と /proc の値で確認する（冪等）。
    /// フラグはスレッド単位なので、libtest の他スレッドに影響を残さないよう使い捨てスレッドで行う。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
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
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn core1_open_flags_and_errno_are_exact_x86_64() {
        assert_eq!(consts::O_DIRECTORY, 0o200_000);
        assert_eq!(consts::O_NOFOLLOW, 0o400_000);
        assert_eq!(consts::O_CLOEXEC, 0o2_000_000);
        assert_eq!(consts::O_PATH, 0o10_000_000);
        assert_eq!(open_dir_path_flags(), 0o12_600_000);
        // OCI-5・REPAIR-5: 状態ストアの非ブロッキング・symlink 非追従 open（0o400000 | 0o4000）。
        assert_eq!(nofollow_nonblock_open_flags(), Some(0o404_000));
        assert_eq!(nonblock_open_flag(), Some(0o4_000));
        assert_eq!(directory_nofollow_nonblock_open_flags(), Some(0o604_000));
        assert_eq!(path_nofollow_open_flags(), Some(0o10_400_000));
        assert_eq!(
            (EPERM, ENOENT, EACCES, ENOTDIR, EINVAL, ELOOP),
            (1, 2, 13, 20, 22, 40)
        );
    }

    /// SUP-12（TASK-169.2）: tmpfs の `statfs.f_type`（`TMPFS_MAGIC`）の具体値。tmpfs の `fsmount` の attr フラグ
    /// （nosuid・nodev 固定、ro / exec の 4 通り）は `sup12_task169_tmpfs_attr_bits_are_exact` が照合する
    /// （`MS_*` 側の `TmpfsMountFlags::bits` は #1693 で削除。#1693 の事後監査 P3・REPAIR-12）。
    #[test]
    fn sup12_task169_2_tmpfs_magic_is_exact() {
        assert_eq!(TMPFS_MAGIC, 0x0102_1994);
    }

    /// CORE-1・SEC-1（TASK-29 追補・#1655）: devpts の fsconfig 列は具体値で固定され、`DevptsGid::Omitted` では
    /// `gid` のキーを渡さない。`mode`・`ptmxmode` は 4 桁 8 進表記（runc と同じ）。
    #[test]
    fn core1_sec1_task29_devpts_fsconfig_params_are_exact() {
        let to_strs = |c: DevptsCreate| -> Vec<(String, String)> {
            c.fsconfig_params()
                .unwrap()
                .iter()
                .map(|p| match p {
                    FsconfigParam::String(k, v) => (
                        k.to_str().unwrap().to_owned(),
                        v.to_str().unwrap().to_owned(),
                    ),
                    FsconfigParam::Flag(k) => panic!("unexpected flag param: {k:?}"),
                })
                .collect()
        };
        let pair = |k: &str, v: &str| (k.to_owned(), v.to_owned());
        assert_eq!(DevptsCreate::MODE, 0o620);
        assert_eq!(DevptsCreate::PTMXMODE, 0o666);
        assert_eq!(DevptsGid::TTY_GID, 5);
        assert_eq!(DevptsGid::Tty.value(), Some(5));
        assert_eq!(DevptsGid::Omitted.value(), None);
        assert_eq!(
            to_strs(DevptsCreate {
                gid: DevptsGid::Tty
            }),
            vec![
                pair("source", "devpts"),
                pair("mode", "0620"),
                pair("ptmxmode", "0666"),
                pair("gid", "5"),
            ]
        );
        assert_eq!(
            to_strs(DevptsCreate {
                gid: DevptsGid::Omitted
            }),
            vec![
                pair("source", "devpts"),
                pair("mode", "0620"),
                pair("ptmxmode", "0666"),
            ]
        );
    }

    /// CORE-1・SEC-1（TASK-29 追補・#1655）: devpts の fsmount attr は nosuid|noexec（0xA）で nodev を含まない。
    /// syscall 番号は `sup12_task169_new_mount_api_consts_are_exact` が x86_64・aarch64 で照合する。
    #[test]
    fn core1_sec1_task29_devpts_attr_bits_are_exact() {
        let bits = DevptsCreate {
            gid: DevptsGid::Omitted,
        }
        .attr_bits();
        assert_eq!(bits, 0xA);
        assert_eq!(bits & consts::MOUNT_ATTR_NODEV, 0);
        assert_eq!(bits & 0x4, 0);
    }

    /// CORE-1（TASK-29 追補・#1655）: devpts の `statfs.f_type`（`DEVPTS_SUPER_MAGIC`）。
    #[test]
    fn core1_task29_devpts_magic_is_exact() {
        assert_eq!(DEVPTS_MAGIC, 0x1cd1);
    }

    /// CORE-1・SEC-1・REPAIR-2（TASK-29 追補・#1655）: [`mount_devpts_on`] の実マウント経路の結合試験。
    ///
    /// 実機前提のため `#[ignore]` で既定のテスト集合から分離する（実行は
    /// `cargo test -p fandhe-container-core --lib -- --ignored core1_sec1_task29_devpts_real_mount`）。
    /// 必要環境は Linux 5.2 以降（新マウント API）・util-linux の `unshare`・非特権 user namespace を許可する
    /// ホスト（または root）。libtest はテストをスレッドで動かし `CLONE_NEWUSER` が `EINVAL` になるため、
    /// 外側のテストが `unshare --user --map-root-user --mount` で自身を再実行し、内側（環境変数で判別）が
    /// その namespace 内でマウントする。ホストのマウントは変えない。内側は (1) カーネルがパラメータを受理して
    /// 成功する、(2) 返された fd が devpts（magic 0x1cd1）を指す、(3) 指定先へ接続され mountinfo に
    /// `nosuid,noexec` の devpts として現れる、(4) `ptmx` が 0666 の独立 instance で pty を確保できる、
    /// ことを具体値で照合する。
    #[cfg(all(
        target_os = "linux",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    #[ignore = "real-machine test: needs Linux 5.2+, util-linux unshare and unprivileged user namespaces (or root). CORE-1/SEC-1"]
    fn core1_sec1_task29_devpts_real_mount() {
        const INNER_ENV: &str = "FANDHE_DEVPTS_MOUNT_INNER";
        if std::env::var_os(INNER_ENV).is_some() {
            devpts_real_mount_inner();
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let mut child = std::process::Command::new("unshare")
            .args([
                "--user",
                "--map-root-user",
                "--mount",
                "--propagation",
                "private",
            ])
            .arg(exe)
            .args([
                "--exact",
                "sys::tests::core1_sec1_task29_devpts_real_mount",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(INNER_ENV, "1")
            .spawn()
            .expect("spawn unshare (util-linux required)");
        // 相手の終了待ちには必ず期限を設ける（REPAIR-5）。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            if std::time::Instant::now() >= deadline {
                // kill の失敗・回収猶予の超過も無期限に待たず、明示的に失敗させる（REPAIR-5）。
                child.kill().expect("kill timed-out inner devpts test");
                reap_bounded(&mut child, std::time::Duration::from_secs(5))
                    .expect("reap timed-out inner devpts test within the grace period");
                panic!("inner devpts mount test timed out after 60s");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        // 内側が作った空のマウント先（子の pid 名）を後始末する。マウントは namespace と共に消えている。
        let _ =
            std::fs::remove_dir(std::env::temp_dir().join(format!("fandhe-devpts-{}", child.id())));
        assert!(
            status.success(),
            "inner devpts mount test failed: {status:?}"
        );
    }

    /// [`core1_sec1_task29_devpts_real_mount`] の内側（新しい user + mount namespace の中）。
    #[cfg(all(
        target_os = "linux",
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn devpts_real_mount_inner() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = std::env::temp_dir().join(format!("fandhe-devpts-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let cdir = CString::new(dir.to_str().unwrap()).unwrap();
        let target = open_dir_path_nofollow(None, &cdir).unwrap();
        // マウント前は devpts ではない。
        assert_ne!(fs_type(target.as_fd()).unwrap(), DEVPTS_MAGIC);

        // DevptsGid::Omitted: user namespace 内で gid 5 が写像されているとは限らない。
        let mnt = mount_devpts_on(
            target.as_fd(),
            DevptsCreate {
                gid: DevptsGid::Omitted,
            },
        )
        .unwrap();
        // 返された fd が devpts のマウントを指す。
        assert_eq!(fs_type(mnt.as_fd()).unwrap(), 0x1cd1);
        // 指定先へ接続された（パスを開き直しても devpts）。
        let reopened = open_dir_path_nofollow(None, &cdir).unwrap();
        assert_eq!(fs_type(reopened.as_fd()).unwrap(), 0x1cd1);

        // mountinfo: 指定先に fstype devpts・nosuid・noexec で現れ、nodev は付かない。5 列目は 8 進エスケープを
        // 戻してから比べる（`TMPDIR` が空白等を含んでも見落とさない。`is_mount_point` と同じ扱い）。
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let dir_bytes = {
            use std::os::unix::ffi::OsStrExt as _;
            dir.as_os_str().as_bytes().to_vec()
        };
        let line = mountinfo
            .lines()
            .find(|l| {
                l.split(' ')
                    .nth(4)
                    .is_some_and(|f| unescape_mountinfo_field(f.as_bytes()) == dir_bytes)
            })
            .expect("mountinfo entry for the target");
        let (pre, post) = line.split_once(" - ").unwrap();
        let opts: Vec<&str> = pre.split(' ').nth(5).unwrap().split(',').collect();
        assert!(
            opts.contains(&"nosuid") && opts.contains(&"noexec"),
            "{line}"
        );
        assert!(!opts.contains(&"nodev"), "{line}");
        assert_eq!(post.split(' ').next(), Some("devpts"), "{line}");

        // ptmx は ptmxmode=0666。開くと独立 instance 側にスレーブ（数字名）が現れ、モードは 0620。
        let ptmx = dir.join("ptmx");
        assert_eq!(std::fs::metadata(&ptmx).unwrap().mode() & 0o7777, 0o666);
        let master = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&ptmx)
            .unwrap();
        let slaves: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.chars().all(|c| c.is_ascii_digit()))
            .collect();
        assert_eq!(slaves.len(), 1, "slaves: {slaves:?}");
        assert_eq!(
            std::fs::metadata(dir.join(&slaves[0])).unwrap().mode() & 0o7777,
            0o620
        );
        drop(master);
        drop(mnt);
    }
    /// SUP-12（TASK-169 追補・#1472）: `fsmount` の attr フラグは nosuid・nodev を常に含み、可変なのは
    /// ro / exec だけ（`MOUNT_ATTR_*` は `MS_*` と別の名前つき定数から組む）。
    #[test]
    fn sup12_task169_tmpfs_attr_bits_are_exact() {
        let f = |read_only, exec| TmpfsMountFlags { read_only, exec }.attr_bits();
        assert_eq!(f(false, false), 2 | 4 | 8);
        assert_eq!(f(true, false), 1 | 2 | 4 | 8);
        assert_eq!(f(false, true), 2 | 4);
        assert_eq!(f(true, true), 1 | 2 | 4);
    }

    /// CORE-6・SEC-5（TASK-29 追補・#1659）: `open_tree` の syscall 番号（x86_64・aarch64 とも 428）と
    /// フラグの具体値。`AT_RECURSIVE` は付けず、`move_mount` の空パス指定は 0x44。
    #[test]
    fn core6_sec5_open_tree_consts_and_flags_are_exact() {
        #[cfg(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            assert_eq!(consts::SYS_OPEN_TREE.get().map(SyscallNumber::raw), Ok(428));
            assert_eq!(
                (
                    consts::OPEN_TREE_CLONE,
                    consts::OPEN_TREE_CLOEXEC,
                    consts::OPEN_TREE_AT_EMPTY_PATH
                ),
                (1, 0o2_000_000, 0x1000)
            );
            assert_eq!(consts::OPEN_TREE_CLOEXEC, 0x8_0000);
            assert_eq!(open_tree_clone_flags(), 0x8_1001);
            // AT_RECURSIVE（0x8000）と OPEN_TREE_NAMESPACE（2）は付けない。
            assert_eq!(open_tree_clone_flags() & 0x8000, 0);
            assert_eq!(open_tree_clone_flags() & 0x2, 0);
            assert_eq!(move_mount_empty_path_flags(), 0x44);
        }
    }

    /// CORE-1・SEC-1（TASK-27.3 追補・#1676）: `mount_setattr` の syscall 番号（x86_64・aarch64 とも 442）、
    /// `struct mount_attr` の大きさ（32 バイト）、渡す値（nodev を足すだけ・`AT_RECURSIVE` なし）の具体値。
    #[test]
    fn core1_sec1_mount_setattr_consts_and_attr_are_exact() {
        #[cfg(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            assert_eq!(
                consts::SYS_MOUNT_SETATTR.get().map(SyscallNumber::raw),
                Ok(442)
            );
            assert_eq!(consts::MOUNT_SETATTR_AT_EMPTY_PATH, 0x1000);
            assert_eq!(consts::ST_NODEV, 4);
            assert_eq!(
                rootfs_nodev_call_params(),
                (0x4, 0, 0, 0, 0x1000, 32),
                "attr_set, attr_clr, propagation, userns_fd, flags, size"
            );
            assert_eq!(
                read_only_call_params(),
                (0x1, 0, 0, 0, 0x1000, 32),
                "SUP-12 #1620: rdonly だけを足す"
            );
            // AT_RECURSIVE（0x8000）は付けない。
            assert_eq!(mount_setattr_flags() & 0x8000, 0);
        }
        assert_eq!(std::mem::size_of::<MountAttr>(), 32);
    }

    /// SEC-1・SUP-12（#1676・#1620・#1693 の事後監査 P3）: `MountAttr` の構築子は `rootfs_nodev_mount_attr`・
    /// `read_only_mount_attr` の 2 つだけで、どちらも `attr_clr`・`propagation`・`userns_fd` が 0（属性を足すだけ）。
    /// `mount_setattr_empty_path_raw` の `// SAFETY:` はこの一覧を前提にするため、構築子を足すと本テストが落ちる
    /// （ソースを走査して `-> MountAttr` を返す `const fn` と `MountAttr {` の構築式を数える）。
    #[test]
    fn sec1_sup12_mount_attr_constructors_are_exhaustive() {
        let fields = |a: MountAttr| (a.attr_set, a.attr_clr, a.propagation, a.userns_fd);
        let listed = [
            ("rootfs_nodev_mount_attr", fields(rootfs_nodev_mount_attr())),
            ("read_only_mount_attr", fields(read_only_mount_attr())),
        ];
        assert_eq!(
            listed,
            [
                ("rootfs_nodev_mount_attr", (0x4, 0, 0, 0)),
                ("read_only_mount_attr", (0x1, 0, 0, 0)),
            ],
            "attr_set, attr_clr, propagation, userns_fd"
        );
        // テスト以外のソース（`mod tests` より前）を走査する。本テスト自身の行は対象外になる。
        let src = include_str!("sys.rs");
        let body = src.split("\nmod tests {").next().unwrap_or(src);
        let constructors: Vec<&str> = body
            .lines()
            .filter(|l| l.trim_end().ends_with("-> MountAttr {"))
            .filter_map(|l| l.trim_start().strip_prefix("const fn "))
            .filter_map(|l| l.split('(').next())
            .collect();
        assert_eq!(
            constructors,
            vec!["rootfs_nodev_mount_attr", "read_only_mount_attr"]
        );
        let functions_returning_attr = body.lines().filter(|l| l.contains("-> MountAttr")).count();
        assert_eq!(
            functions_returning_attr, 2,
            "no other MountAttr constructor"
        );
        let literals = body.lines().filter(|l| l.trim() == "MountAttr {").count();
        assert_eq!(
            literals, 2,
            "MountAttr is built only in the listed constructors"
        );
    }

    /// SEC-1（#1676）: `is_nodev` は `ST_NODEV`（0x4）だけを見る。
    #[test]
    fn sec1_mount_flags_is_nodev_boundaries() {
        #[cfg(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            assert!(MountFlags::from_bits(0x4).is_nodev());
            assert!(!MountFlags::from_bits(0x20).is_nodev());
            assert!(MountFlags::from_bits(0x20 | 0x4).is_nodev());
            assert!(!MountFlags::from_bits(0).is_nodev());
        }
    }

    /// SEC-1（#1676）: 無効 fd は失敗する。特権の有無でカーネルの検査順が変わるため、非特権では `may_mount` の
    /// `EPERM` が `EBADF` より先に返り得る。`ENOSYS` の旧カーネルでは `Unsupported` が先に返るため受け入れる。
    #[test]
    fn sec1_set_mount_nodev_rejects_invalid_fd() {
        match set_mount_nodev_raw(-1) {
            Err(SysError::Os(e)) => assert!(e == EBADF || e == EPERM, "errno {e}"),
            Err(SysError::Unsupported) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// SUP-12（#1620）: 無効 fd は失敗する（検査順の事情は `sec1_set_mount_nodev_rejects_invalid_fd` と同じ）。
    #[test]
    fn sup12_set_mount_read_only_rejects_invalid_fd() {
        match set_mount_read_only_raw(-1) {
            Err(SysError::Os(e)) => assert!(e == EBADF || e == EPERM, "errno {e}"),
            Err(SysError::Unsupported) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// CORE-5（TASK-29 追補・#1657）: `/dev`・`/dev/pts` の fsmount 属性ビットが、Landlock 側と共有する
    /// 暗黙の固定集合の定義（`dev_mounts`）と一致する。片方だけが変わったらここで検出する。
    #[test]
    fn core5_implicit_dev_mount_attrs_match_fsmount_bits() {
        use crate::dev_mounts::ImplicitDevMount;
        let bits = |m: ImplicitDevMount| {
            let a = m.attrs();
            let mut b = 0;
            if a.read_only {
                b |= consts::MOUNT_ATTR_RDONLY;
            }
            if a.nosuid {
                b |= consts::MOUNT_ATTR_NOSUID;
            }
            if a.nodev {
                b |= consts::MOUNT_ATTR_NODEV;
            }
            if a.noexec {
                b |= consts::MOUNT_ATTR_NOEXEC;
            }
            b
        };
        // `/dev` は strictatime が加わる（定義側に atime の属性は無い）。
        assert_eq!(
            DevTmpfsCreate::new().attr_bits() & !consts::MOUNT_ATTR_STRICTATIME,
            bits(ImplicitDevMount::Dev)
        );
        assert_eq!(
            DevptsCreate {
                gid: DevptsGid::Omitted,
            }
            .attr_bits(),
            bits(ImplicitDevMount::DevPts)
        );
    }

    /// CORE-1・SEC-1（TASK-29 追補・#1652）: `/dev` 用 tmpfs の attr は nosuid|strictatime のみ。
    #[test]
    fn core1_sec1_dev_tmpfs_attr_bits_are_exact() {
        let c = DevTmpfsCreate::new();
        assert_eq!(c.attr_bits(), 0x22);
        assert_eq!(c.attr_bits() & consts::MOUNT_ATTR_NODEV, 0);
        assert_eq!(c.attr_bits() & consts::MOUNT_ATTR_NOEXEC, 0);
        assert_eq!(c.attr_bits() & consts::MOUNT_ATTR_RDONLY, 0);
        assert_eq!(c.attr_bits() & consts::MOUNT_ATTR_NOSUID, 0x2);
        assert_eq!(c.attr_bits() & 0x70, 0x20);
    }

    /// CORE-1・SEC-1（TASK-29 追補・#1652）: `/dev` 用 tmpfs の固定値と fsconfig へ渡すキー・値。
    #[test]
    fn core1_sec1_dev_tmpfs_fsconfig_params_are_exact() {
        let c = DevTmpfsCreate::new();
        assert_eq!(c.mode(), 0o755);
        assert_eq!(c.size_bytes(), 67_108_864);
        let params = TmpfsParams::from(c).fsconfig_params().expect("params");
        assert_eq!(
            params,
            vec![
                FsconfigParam::String(c"source", CString::new("tmpfs").unwrap()),
                FsconfigParam::String(c"mode", CString::new("755").unwrap()),
                FsconfigParam::String(c"size", CString::new("67108864").unwrap()),
            ]
        );
    }

    /// SEC-1（回帰）: 既存の `TmpfsMountFlags::attr_bits` は 4 通りすべてで nodev を含む。
    #[test]
    fn sup12_task169_tmpfs_attr_bits_always_include_nodev() {
        for (read_only, exec, want) in [
            (false, false, 0xE),
            (false, true, 0x6),
            (true, false, 0xF),
            (true, true, 0x7),
        ] {
            let bits = TmpfsMountFlags { read_only, exec }.attr_bits();
            assert_eq!(bits, want);
            assert_eq!(bits & consts::MOUNT_ATTR_NODEV, 0x4);
        }
    }

    /// SUP-12・SEC-1: 既存の呼び出し（`exec/tmpfs.rs`・`inject.rs` の形）が渡す attr と文字列は変わらない。
    #[test]
    fn sup12_task169_tmpfs_params_unchanged_for_existing_callers() {
        for (read_only, exec, want) in [
            (false, false, 0xE),
            (false, true, 0x6),
            (true, false, 0xF),
            (true, true, 0x7),
        ] {
            let p = TmpfsParams::from(TmpfsCreate {
                mode: 0o1777,
                size: Some(67_108_864),
                flags: TmpfsMountFlags { read_only, exec },
            });
            assert_eq!(p.attr, want);
            let params = p.fsconfig_params().expect("params");
            assert_eq!(
                params.get(1),
                Some(&FsconfigParam::String(
                    c"mode",
                    CString::new("1777").unwrap()
                ))
            );
            assert_eq!(
                params.last() == Some(&FsconfigParam::Flag(c"ro")),
                read_only
            );
        }
        let inject = TmpfsParams::from(TmpfsCreate {
            mode: 0o755,
            size: Some(4096),
            flags: TmpfsMountFlags {
                read_only: false,
                exec: false,
            },
        });
        assert_eq!(inject.attr, 0xE);
        assert_eq!(
            inject.fsconfig_params().expect("params"),
            vec![
                FsconfigParam::String(c"source", CString::new("tmpfs").unwrap()),
                FsconfigParam::String(c"mode", CString::new("755").unwrap()),
                FsconfigParam::String(c"size", CString::new("4096").unwrap()),
            ]
        );
        let no_size = TmpfsParams::from(TmpfsCreate {
            mode: 0o755,
            size: None,
            flags: TmpfsMountFlags {
                read_only: true,
                exec: false,
            },
        });
        assert_eq!(
            no_size.fsconfig_params().expect("params"),
            vec![
                FsconfigParam::String(c"source", CString::new("tmpfs").unwrap()),
                FsconfigParam::String(c"mode", CString::new("755").unwrap()),
                FsconfigParam::Flag(c"ro"),
            ]
        );
    }

    /// SUP-12（TASK-169 追補・#1472）: 新マウント API の syscall 番号・フラグの具体値。番号は x86_64 と
    /// aarch64（asm-generic）で個別に定義し、どちらも 429〜432。
    #[test]
    fn sup12_task169_new_mount_api_consts_are_exact() {
        #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
        assert_eq!(
            (
                consts::SYS_MOVE_MOUNT.get().map(SyscallNumber::raw),
                consts::SYS_FSOPEN.get().map(SyscallNumber::raw),
                consts::SYS_FSCONFIG.get().map(SyscallNumber::raw),
                consts::SYS_FSMOUNT.get().map(SyscallNumber::raw)
            ),
            (Ok(429), Ok(430), Ok(431), Ok(432))
        );
        #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
        assert_eq!(
            (
                consts::SYS_MOVE_MOUNT.get().map(SyscallNumber::raw),
                consts::SYS_FSOPEN.get().map(SyscallNumber::raw),
                consts::SYS_FSCONFIG.get().map(SyscallNumber::raw),
                consts::SYS_FSMOUNT.get().map(SyscallNumber::raw)
            ),
            (Ok(429), Ok(430), Ok(431), Ok(432))
        );
        assert_eq!(
            (
                consts::FSOPEN_CLOEXEC,
                consts::FSMOUNT_CLOEXEC,
                consts::FSCONFIG_SET_FLAG,
                consts::FSCONFIG_SET_STRING,
                consts::FSCONFIG_CMD_CREATE
            ),
            (1, 1, 0, 1, 6)
        );
        assert_eq!(
            (
                consts::MOUNT_ATTR_RDONLY,
                consts::MOUNT_ATTR_NOSUID,
                consts::MOUNT_ATTR_NODEV,
                consts::MOUNT_ATTR_NOEXEC
            ),
            (1, 2, 4, 8)
        );
        // include/uapi/linux/mount.h の `MOUNT_ATTR_STRICTATIME`（x86_64・aarch64 共通）。
        assert_eq!(consts::MOUNT_ATTR_STRICTATIME, 0x20);
        assert_eq!(
            (
                consts::MOVE_MOUNT_F_EMPTY_PATH,
                consts::MOVE_MOUNT_T_EMPTY_PATH
            ),
            (0x4, 0x40)
        );
    }

    /// SUP-12（TASK-169.4.2）: 作成系フラグの定数値（x86_64・aarch64 共通）。
    #[test]
    fn sup12_task169_4_2_inject_consts_are_exact() {
        assert_eq!(
            (consts::O_CREAT, consts::O_EXCL, consts::O_WRONLY),
            (0o100, 0o200, 1)
        );
    }

    /// SUP-12（TASK-169.4.2）: `create_file_excl_at` は新規作成でき、既存名・既存 symlink 名は
    /// `EEXIST`（辿らない）。
    #[test]
    fn sup12_task169_4_2_create_file_excl_at_refuses_existing_names() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let dir = std::env::temp_dir().join(format!("fandhe-sys-excl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let parent =
            open_dir_path_nofollow(None, &CString::new(dir.to_str().expect("utf8")).expect("c"))
                .expect("open dir");
        let name = CString::new("new").expect("c");
        let fd = create_file_excl_at(parent.as_fd(), &name, 0o600).expect("create");
        drop(fd);
        let mode = std::fs::metadata(dir.join("new"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777 & !0o077, 0o600 & !0o077);
        assert_eq!(
            create_file_excl_at(parent.as_fd(), &name, 0o600).expect_err("exists"),
            SysError::Os(EEXIST)
        );
        symlink(dir.join("target-not-created"), dir.join("link")).expect("symlink");
        let link = CString::new("link").expect("c");
        assert_eq!(
            create_file_excl_at(parent.as_fd(), &link, 0o600).expect_err("symlink"),
            SysError::Os(EEXIST)
        );
        assert!(!dir.join("target-not-created").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CORE-1（TASK-27.3）: mount 系フラグ・pivot_root の syscall 番号の具体値。番号は arch ごとに
    /// 違う（x86_64 = 155、aarch64 = 41）。
    #[test]
    fn core1_pivot_consts_are_exact() {
        assert_eq!(consts::MS_BIND, 0x1000);
        assert_eq!(consts::MS_REC, 0x4000);
        assert_eq!(consts::MNT_DETACH, 2);
        #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
        assert_eq!(
            consts::SYS_PIVOT_ROOT.get().map(SyscallNumber::raw),
            Ok(155)
        );
        #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
        assert_eq!(consts::SYS_PIVOT_ROOT.get().map(SyscallNumber::raw), Ok(41));
    }

    /// aarch64: O_DIRECTORY / O_NOFOLLOW は arch/arm64/include/uapi/asm/fcntl.h の上書き値
    /// （asm-generic の 0o200000 / 0o400000 は arm64 では O_DIRECT / O_LARGEFILE）。
    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    #[test]
    fn core1_open_flags_and_errno_are_exact_aarch64() {
        assert_eq!(consts::O_DIRECTORY, 0o40_000);
        assert_eq!(consts::O_NOFOLLOW, 0o100_000);
        assert_eq!(consts::O_CLOEXEC, 0o2_000_000);
        assert_eq!(consts::O_PATH, 0o10_000_000);
        assert_eq!(open_dir_path_flags(), 0o12_140_000);
        // OCI-5・REPAIR-5: 状態ストアの非ブロッキング・symlink 非追従 open（0o100000 | 0o4000）。
        assert_eq!(nofollow_nonblock_open_flags(), Some(0o104_000));
        assert_eq!(nonblock_open_flag(), Some(0o4_000));
        assert_eq!(directory_nofollow_nonblock_open_flags(), Some(0o144_000));
        assert_eq!(path_nofollow_open_flags(), Some(0o10_100_000));
        assert_eq!(
            (EPERM, ENOENT, EACCES, ENOTDIR, EINVAL, ELOOP),
            (1, 2, 13, 20, 22, 40)
        );
    }

    /// SUP-6・TASK-163 追補（#1459）: `O_NOCTTY` の値（x86_64・aarch64 とも asm-generic の 0o400）と、
    /// procfs の fd エントリ名の組み立て（アロケーションなし）の具体値。
    #[test]
    fn sup6_task163_noctty_const_and_proc_fd_entry_are_exact() {
        #[cfg(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        assert_eq!(consts::O_NOCTTY, 0o400);
        let mut buf = [0u8; 32];
        assert_eq!(proc_fd_entry(0, &mut buf), Some(c"thread-self/fd/0"));
        assert_eq!(proc_fd_entry(7, &mut buf), Some(c"thread-self/fd/7"));
        assert_eq!(proc_fd_entry(1048, &mut buf), Some(c"thread-self/fd/1048"));
        assert_eq!(
            proc_fd_entry(i32::MAX, &mut buf),
            Some(c"thread-self/fd/2147483647")
        );
        assert_eq!(proc_fd_entry(-1, &mut buf), None);
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1459）: 固定した `O_PATH` fd を procfs の magic link 経由で読み書きに
    /// 開き直すと、パスを再解決せず同じ inode（`/dev/null` = 文字デバイス 1:3）が開く。
    #[test]
    fn sup6_task163_reopen_pinned_rdwr_opens_the_pinned_inode() {
        use std::io::Write as _;
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
        let proc_dir = open_dir_path_nofollow(None, c"/proc").unwrap();
        let dev = open_dir_path_nofollow(None, c"/dev").unwrap();
        let pinned = open_path_nofollow(dev.as_fd(), c"null").unwrap();
        let reopened = reopen_pinned_rdwr_noctty(proc_dir.as_fd(), pinned.as_fd()).unwrap();
        let mut file = std::fs::File::from(reopened);
        let meta = file.metadata().unwrap();
        assert!(meta.file_type().is_char_device());
        assert_eq!(meta.rdev(), makedev(1, 3));
        assert_eq!(file.write(b"x").unwrap(), 1);
        // procfs でないディレクトリを起点にすると、エントリが無く開けない（ENOENT）。
        assert_eq!(
            reopen_pinned_rdwr_noctty(dev.as_fd(), pinned.as_fd()).unwrap_err(),
            SysError::Os(ENOENT)
        );
    }

    /// SUP-6・SEC-1（TASK-163 追補・#1530）: 封印した複製の定数の具体値。memfd_create の syscall 番号は
    /// arch ごとに個別定義する（x86_64 = syscall_64.tbl の 319、aarch64 = asm-generic/unistd.h の 279）。
    #[test]
    fn sup6_task163_sealed_copy_consts_are_exact() {
        #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
        assert_eq!(
            consts::SYS_MEMFD_CREATE.get().map(SyscallNumber::raw),
            Ok(319)
        );
        #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
        assert_eq!(
            consts::SYS_MEMFD_CREATE.get().map(SyscallNumber::raw),
            Ok(279)
        );
        assert_eq!(consts::MFD_CLOEXEC, 0x1);
        assert_eq!(consts::MFD_ALLOW_SEALING, 0x2);
        assert_eq!(consts::MFD_EXEC, 0x10);
        assert_eq!(consts::F_ADD_SEALS, 1033);
        assert_eq!(consts::F_GET_SEALS, 1034);
        assert_eq!(consts::F_SEAL_SEAL, 0x1);
        assert_eq!(consts::F_SEAL_SHRINK, 0x2);
        assert_eq!(consts::F_SEAL_GROW, 0x4);
        assert_eq!(consts::F_SEAL_WRITE, 0x8);
        assert_eq!(consts::F_SEAL_EXEC, 0x20);
    }

    /// SEC-1（TASK-163 追補・#1531）: `AT_EXECVE_CHECK` の具体値（include/uapi/linux/fcntl.h。全アーキテクチャ共通）。
    #[test]
    fn sec1_task163_at_execve_check_const_is_exact() {
        assert_eq!(consts::AT_EXECVE_CHECK, 0x10000);
        assert_eq!(consts::AT_EMPTY_PATH, 0x1000);
    }

    /// SEC-1（TASK-163 追補・#1531）: `exec_check_fd` は実行せずにカーネルの判定だけを返す。Linux 6.14 以降
    /// （`/proc/sys/kernel/osrelease` で判定）では 0755 のスクリプト・`/bin/true` が成功、0644 のファイル・`noexec` の
    /// `/proc` 上のファイル・ディレクトリが `EACCES`。6.14 未満ではフラグを知らないため、いずれも `EINVAL`
    /// （呼び出し側が fail-closed にする）。どちらの場合も呼び出しプロセスは置き換わらない（この試験が続行する）。
    #[test]
    fn sec1_task163_exec_check_fd_reports_the_kernel_verdict_without_executing() {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = crate::test_support::TestTempDir::new("exec-check").expect("temp dir");
        let dir = tmp.path().to_path_buf();
        let file_with_mode = |mode: u32| {
            let path = dir.join(format!("f{mode:o}"));
            std::fs::write(&path, b"#!/bin/sh\nexit 0\n").expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            std::fs::File::open(&path).expect("open")
        };
        let x755 = file_with_mode(0o755);
        let x644 = file_with_mode(0o644);
        let true_bin = std::fs::File::open("/bin/true").expect("open /bin/true");
        let proc_file = std::fs::File::open("/proc/self/status").expect("open status");
        let directory = std::fs::File::open(&dir).expect("open dir");
        let got = [
            exec_check_fd(x755.as_fd()),
            exec_check_fd(true_bin.as_fd()),
            exec_check_fd(x644.as_fd()),
            exec_check_fd(proc_file.as_fd()),
            exec_check_fd(directory.as_fd()),
        ];
        let expected = if crate::test_support::kernel_at_least(6, 14) {
            [
                Ok(()),
                Ok(()),
                Err(SysError::Os(EACCES)),
                Err(SysError::Os(EACCES)),
                Err(SysError::Os(EACCES)),
            ]
        } else {
            [Err(SysError::Os(EINVAL)); 5]
        };
        assert_eq!(got, expected);
    }

    /// SEC-1（TASK-163 追補・#1531）: 封印した memfd を読み取り専用で開き直すと、seal 0x0F と実体が再照合された
    /// fd になる（書き込みは拒否され、`(st_dev, st_ino)` は封印した memfd と同じ）。
    #[test]
    fn sec1_task163_reopen_read_only_verifies_seals_and_identity() {
        use std::io::Write as _;
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::{FileExt as _, MetadataExt as _};
        let mut writer =
            std::fs::File::from(memfd_create_for_exec_copy(c"fandhe-reopen-test").expect("memfd"));
        writer.write_all(b"#!/bin/sh\n").expect("write");
        let sealed = seal_for_exec(writer.into()).expect("seal");
        let ino = std::fs::File::from(dup_fd_at_least(sealed.as_fd(), 3).expect("dup"))
            .metadata()
            .expect("stat")
            .ino();
        let procfs = std::fs::File::open("/proc").expect("open /proc");
        let copy = sealed.reopen_read_only(procfs.as_fd()).expect("reopen");
        assert_eq!(get_seals(copy.file().as_fd()).expect("seals").bits(), 0x0F);
        assert_eq!(copy.metadata().ino(), ino);
        assert_eq!(copy.metadata().len(), 10);
        assert!(copy.file().write_at(b"x", 0).is_err());
        let mut head = [0u8; 2];
        assert_eq!(copy.file().read_at(&mut head, 0).expect("read"), 2);
        assert_eq!(&head, b"#!");
    }

    /// SUP-6: 封印に使う seal の完全集合は SEAL | SHRINK | GROW | WRITE の 0x0F（`F_SEAL_EXEC` を含まない）。
    #[test]
    fn sup6_task163_seal_set_exec_copy_is_0x0f() {
        assert_eq!(SealSet::EXEC_COPY.bits(), 0x0F);
        assert!(SealSet::EXEC_COPY.contains(SealSet(consts::F_SEAL_WRITE)));
        assert!(!SealSet::EXEC_COPY.contains(SealSet(consts::F_SEAL_EXEC)));
    }

    /// SUP-6・SEC-1: 封印した memfd は書き込み・伸長・縮小・seal の追加がいずれも `EPERM` で拒否され、
    /// `F_GET_SEALS` はちょうど 0x0F を返し、内容は封印前のまま変わらない。
    #[test]
    fn sup6_task163_memfd_seals_reject_write_grow_shrink() {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::FileExt as _;
        let fd = memfd_create_for_exec_copy(c"fandhe-exec-test").expect("memfd_create");
        // MFD_ALLOW_SEALING 付きで作った直後は seal が 1 つも付いていない。
        assert_eq!(get_seals(fd.as_fd()).expect("get_seals").bits(), 0);
        let mut content = b"#!/bin/sh\n".to_vec();
        content.resize(4096, b'x');
        let file = std::fs::File::from(fd);
        file.write_all_at(&content, 0).expect("write before seal");
        let sealed = seal_for_exec(file.into()).expect("seal_for_exec");
        assert_eq!(get_seals(sealed.as_fd()).expect("get_seals").bits(), 0x0F);
        let file = std::fs::File::from(sealed.into_owned_fd());
        let eperm = Some(EPERM);
        assert_eq!(file.write_at(b"y", 0).unwrap_err().raw_os_error(), eperm);
        assert_eq!(file.write_at(b"y", 4096).unwrap_err().raw_os_error(), eperm);
        assert_eq!(file.set_len(4097).unwrap_err().raw_os_error(), eperm);
        assert_eq!(file.set_len(4095).unwrap_err().raw_os_error(), eperm);
        assert_eq!(
            add_seals(file.as_fd(), SealSet(consts::F_SEAL_WRITE)),
            Err(SysError::Os(EPERM))
        );
        let mut after = vec![0u8; 4096];
        file.read_exact_at(&mut after, 0).expect("read back");
        assert_eq!(after, content);
        assert_eq!(file.metadata().expect("metadata").len(), 4096);
    }

    /// SUP-6: memfd でない fd への `F_GET_SEALS` / `F_ADD_SEALS` は `EINVAL`（seal の概念が無い fd を
    /// 「封印済み」と誤認しない）。
    #[test]
    fn sup6_task163_seals_on_regular_file_are_einval() {
        use std::os::fd::AsFd as _;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/null")
            .expect("open /dev/null");
        assert_eq!(get_seals(file.as_fd()), Err(SysError::Os(EINVAL)));
        assert_eq!(
            add_seals(file.as_fd(), SealSet::EXEC_COPY),
            Err(SysError::Os(EINVAL))
        );
        let owned: OwnedFd = file.into();
        assert_eq!(
            seal_for_exec(owned).unwrap_err(),
            SealError::Sys(SysError::Os(EINVAL))
        );
    }

    /// SUP-6: 封印した複製を読み取り専用で開き直し、書き込み用 fd を閉じれば実行できる（`MFD_EXEC` と
    /// `ETXTBSY` 回避の早期確認）。`vm.memfd_noexec=2` の環境では `memfd_create` が `EACCES` になり失敗する
    /// （skip しない。fail-closed の設計どおり）。
    #[test]
    fn sup6_task163_sealed_memfd_is_executable_after_readonly_reopen() {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        use std::os::unix::fs::FileExt as _;
        let src = std::fs::read("/bin/true").expect("read /bin/true");
        let fd = memfd_create_for_exec_copy(c"fandhe-exec-test").expect("memfd_create");
        let file = std::fs::File::from(fd);
        file.write_all_at(&src, 0).expect("copy");
        let sealed = seal_for_exec(file.into()).expect("seal_for_exec");
        let n = sealed.as_fd().as_raw_fd();
        let ro = std::fs::File::open(format!("/proc/self/fd/{n}")).expect("reopen read-only");
        drop(sealed); // 書き込み用に開いた fd を閉じる。
        set_cloexec(ro.as_fd(), false).expect("clear cloexec");
        let path = format!("/proc/self/fd/{}", ro.as_raw_fd());
        // 並列テストの fork が閉じる前の書き込み用 fd を一瞬保持すると ETXTBSY になり得るため、数回再試行する。
        let mut status = None;
        for _ in 0..20 {
            match run_with_deadline(
                std::process::Command::new(&path),
                std::time::Duration::from_secs(30),
            ) {
                Ok(s) => {
                    status = Some(s);
                    break;
                }
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => panic!("spawn failed: {e}"),
            }
        }
        assert_eq!(status.expect("spawned").code(), Some(0));
    }

    /// 子プロセスを起動し、期限付きの `try_wait` で終了を待つ（REPAIR-5）。期限超過時は kill し、
    /// 有限の猶予内で回収して `ErrorKind::TimedOut` を返す。kill の失敗・回収猶予の超過は
    /// 期限なしで待たず、明示的なエラーとして返す。起動失敗（`ETXTBSY` 等）はそのまま返す。
    fn run_with_deadline(
        mut cmd: std::process::Command,
        deadline: std::time::Duration,
    ) -> io::Result<std::process::ExitStatus> {
        let mut child = cmd.spawn()?;
        let start = std::time::Instant::now();
        loop {
            if let Some(s) = child.try_wait()? {
                return Ok(s);
            }
            if start.elapsed() >= deadline {
                if let Err(e) = child.kill() {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("failed to kill child after the deadline: {e}"),
                    ));
                }
                reap_bounded(&mut child, std::time::Duration::from_secs(5))?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child did not exit before the deadline",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// kill 後の子を `try_wait` のループで回収する。`grace` 内に回収できなければ無期限に待たず
    /// `ErrorKind::TimedOut` を返す（REPAIR-5）。
    fn reap_bounded(child: &mut std::process::Child, grace: std::time::Duration) -> io::Result<()> {
        let start = std::time::Instant::now();
        loop {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            if start.elapsed() >= grace {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child was not reaped within the grace period",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// REPAIR-5: 回収猶予内に終了しない子（kill していないため生存）は無期限に待たず `TimedOut` を返す。
    #[test]
    fn repair5_reap_bounded_returns_timed_out_when_child_stays_alive() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let started = std::time::Instant::now();
        let err = reap_bounded(&mut child, std::time::Duration::from_millis(100))
            .expect_err("must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            err.to_string(),
            "child was not reaped within the grace period"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        child.kill().expect("kill");
        reap_bounded(&mut child, std::time::Duration::from_secs(5)).expect("reap after kill");
    }

    /// REPAIR-5: 期限内に終了しない子は kill・回収され `TimedOut` の失敗が返る。
    #[test]
    fn repair5_run_with_deadline_times_out_and_reaps_child() {
        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("30");
        let started = std::time::Instant::now();
        let err = run_with_deadline(cmd, std::time::Duration::from_millis(200))
            .expect_err("must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(err.to_string(), "child did not exit before the deadline");
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    /// CORE-1（TASK-27.4.1）: fork / exec / wait 系の定数の具体値。syscall 番号・フラグ・シグナル番号は
    /// arch ごとに個別定義する（x86_64 = syscall_64.tbl、aarch64 = asm-generic/unistd.h）。
    #[test]
    fn core1_fork_exec_consts_are_exact() {
        #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
        assert_eq!(consts::SYS_EXECVEAT.get().map(SyscallNumber::raw), Ok(322));
        #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
        assert_eq!(consts::SYS_EXECVEAT.get().map(SyscallNumber::raw), Ok(281));
        assert_eq!(consts::AT_EMPTY_PATH, 0x1000);
        assert_eq!(consts::O_NONBLOCK, 0o4_000);
        assert_eq!(consts::O_RDWR, 2);
        assert_eq!((consts::F_SETFD, consts::FD_CLOEXEC), (2, 1));
        assert_eq!(consts::F_DUPFD_CLOEXEC, 1030);
        #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
        assert_eq!(
            consts::SYS_CLOSE_RANGE.get().map(SyscallNumber::raw),
            Ok(436)
        );
        #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
        assert_eq!(
            consts::SYS_CLOSE_RANGE.get().map(SyscallNumber::raw),
            Ok(436)
        );
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

    /// REPAIR-5・SUP-6・#1616: `Threads:` の値を数で読み、行が無い・数値でなければ `None`。
    #[test]
    fn repair5_status_thread_count_reads_the_number() {
        assert_eq!(status_thread_count("Name:\tx\nThreads:\t3\n"), Some(3));
        assert_eq!(status_thread_count("Threads:\tmany\n"), None);
        assert_eq!(status_thread_count("Name:\tx\n"), None);
        // libtest のプロセスは複数スレッドで、少なくとも 1。
        assert!(current_thread_count().is_some_and(|n| n >= 1));
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

    /// SUP-6（TASK-163.4）: 呼び出し側が渡す判定が偽なら、スレッド数によらず fork せず `MultiThreaded` で拒否する
    /// （子のクロージャは実行されない）。判定の出所が変わっても「確認が偽なら fork しない」強制は同じ。
    #[test]
    fn sup6_task163_4_fork_with_refuses_when_predicate_is_false() {
        let ran = std::cell::Cell::new(false);
        let err = fork_single_threaded_with(
            || false,
            || {
                ran.set(true);
                0
            },
            125,
        )
        .unwrap_err();
        assert_eq!(err, SysError::MultiThreaded);
        assert!(!ran.get());
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
        /// 排他作成した本体（#1298）。`Drop::drop`（chmod 復元）の後にフィールドとして drop され削除する。
        _guard: crate::test_support::TestTempDir,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let guard = crate::test_support::TestTempDir::new(&format!("sys-{label}")).unwrap();
            Self {
                base: guard.path().to_path_buf(),
                restore: Vec::new(),
                _guard: guard,
            }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            for p in &self.restore {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
            }
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
        #[cfg(all(
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
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

    /// 存在しない fd 番号（`RLIMIT_NOFILE` を超える値）。`BorrowedFd` は作らず `RawFd` のまま非公開部分へ渡す。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    const BOGUS_FD: RawFd = 1_000_000;

    /// CORE-6・SEC-5（TASK-29 追補・#1659）: 失敗経路。無効な fd は `Os(EBADF)`（非特権では先に
    /// 特権検査で `Os(EPERM)`）で返り、パニックも縮退（`mount(2)` への切り替え）もしない。`move_mount_empty_path` も同様。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core6_sec5_open_tree_and_move_mount_fail_with_ebadf_on_invalid_fd() {
        // 特権チェックが fd 検証より先に走るため、非特権では EPERM になる（どちらも拒否で、成功しない）。
        let accepted = [SysError::Os(EBADF), SysError::Os(EPERM)];
        let err = open_tree_clone_raw(BOGUS_FD).unwrap_err();
        assert!(accepted.contains(&err), "unexpected error: {err:?}");
        let null = std::fs::File::open("/dev/null").expect("open /dev/null");
        let err = move_mount_empty_path_raw(BOGUS_FD, null.as_raw_fd()).unwrap_err();
        assert!(accepted.contains(&err), "unexpected error: {err:?}");
    }

    /// CORE-6・SEC-5（TASK-29 追補・#1659）: `open_tree` の複製は呼び出しスレッドの実効 `CAP_SYS_ADMIN`
    /// （`capget` で読む。bit 21）で結果が決まる。持たなければ `Os(EPERM)` で拒否され、持てば（root で走らせた
    /// 場合）未接続の複製が close-on-exec の fd で返る（接続しないため drop でカーネルが破棄し、ホストへの副作用は
    /// 無い）。どちらの分岐も具体値を照合する（euid だけで判定しない。root でも `CAP_SYS_ADMIN` を落とした
    /// コンテナ内では EPERM 側になる）。Linux 5.2 未満は両分岐とも `Unsupported`。前提: テストプロセスの
    /// user namespace が自分の mount namespace を所有する（`unshare --user` だけで走らせた場合は対象外）。
    /// user namespace 内での接続まで含む成功経路は下の実機前提テストが検証する。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core6_sec5_open_tree_clone_result_follows_cap_sys_admin() {
        const CAP_SYS_ADMIN_BIT: u32 = 1 << 21;
        let caps = cap_get_thread().expect("capget");
        let privileged = caps.effective[0] & CAP_SYS_ADMIN_BIT != 0;
        let node = verify_device_node_fd(open_o_path("/dev/null"), HostDeviceNode::Null)
            .expect("verify /dev/null");
        match (privileged, open_tree_clone(&node)) {
            (_, Err(SysError::Unsupported)) => {}
            (false, Err(err)) => assert_eq!(err, SysError::Os(EPERM)),
            (true, Ok(clone)) => assert_eq!(fd_flags(&clone) & 0o2_000_000, 0o2_000_000),
            (privileged, other) => panic!("privileged={privileged}: unexpected result: {other:?}"),
        }
    }

    /// `path` が呼び出しスレッドの mount namespace でマウントポイントか（`/proc/self/mountinfo` の 5 列目を
    /// [`unescape_mountinfo_field`] で戻した値と、正規化したパスのバイト列が完全一致）。`TMPDIR` が空白・タブ・
    /// 改行・`\` を含んでも誤判定しない（カーネルはこれらを 8 進エスケープして出力する）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn is_mount_point(path: &std::path::Path) -> bool {
        use std::os::unix::ffi::OsStrExt as _;
        let real = std::fs::canonicalize(path).expect("canonicalize");
        let real = real.as_os_str().as_bytes();
        // バイト列のまま読む（他のマウントポイントが UTF-8 でなくても panic しない）。
        std::fs::read("/proc/self/mountinfo")
            .expect("read mountinfo")
            .split(|&c| c == b'\n')
            .filter_map(|l| l.split(|&c| c == b' ').nth(4))
            .any(|field| unescape_mountinfo_field(field) == real)
    }

    /// mountinfo の 1 列を戻す。カーネル（fs/proc_namespace.c の `show_mountinfo` → `seq_path_root` の
    /// `" \t\n\\"`）は空白・タブ・改行・`\` を `\` + 8 進 3 桁（`\040`・`\011`・`\012`・`\134`）で出力する。
    /// 1 回の走査で戻し、戻した結果は再走査しない（`\134040` は `\040` の 4 バイトになる）。`\` の後が 8 進
    /// 3 桁でなければそのまま残す（カーネルはそうした列を出さない）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn unescape_mountinfo_field(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while let Some(&b) = bytes.get(i) {
            let octal = bytes
                .get(i + 1..i + 4)
                .filter(|d| b == b'\\' && d.iter().all(|c| (b'0'..=b'7').contains(c)))
                .map(|d| d.iter().fold(0u32, |acc, c| acc * 8 + u32::from(c - b'0')))
                .and_then(|v| u8::try_from(v).ok());
            match octal {
                Some(v) => {
                    out.push(v);
                    i += 4;
                }
                None => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        out
    }

    /// CORE-6・REPAIR-12（TASK-29 追補・#1659）: mountinfo の 8 進エスケープ（空白 `\040`・タブ `\011`・
    /// 改行 `\012`・`\` の `\134`）を具体値で戻す。1 回だけ戻し（`\134040` → `\040`）、8 進 3 桁でない
    /// `\` の並びと 255 を超える値（`\777`）はそのまま残す。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core6_unescape_mountinfo_field_decodes_octal_escapes_once() {
        assert_eq!(
            unescape_mountinfo_field(b"/tmp/plain"),
            b"/tmp/plain".to_vec()
        );
        assert_eq!(
            unescape_mountinfo_field(b"/tmp/a\\040b"),
            b"/tmp/a b".to_vec()
        );
        assert_eq!(
            unescape_mountinfo_field(b"/t\\011m\\012p"),
            b"/t\tm\np".to_vec()
        );
        assert_eq!(unescape_mountinfo_field(b"/x\\134y"), b"/x\\y".to_vec());
        assert_eq!(unescape_mountinfo_field(b"/\\134040"), b"/\\040".to_vec());
        assert_eq!(unescape_mountinfo_field(b"/a\\04"), b"/a\\04".to_vec());
        assert_eq!(unescape_mountinfo_field(b"/a\\089"), b"/a\\089".to_vec());
        assert_eq!(unescape_mountinfo_field(b"/a\\777"), b"/a\\777".to_vec());
        assert_eq!(unescape_mountinfo_field(b"\\"), b"\\".to_vec());
    }

    /// CORE-6・REPAIR-12（TASK-29 追補・#1659）: 実機前提テストが使う `is_mount_point` を、特権なしで実際の
    /// `/proc/self/mountinfo` に当てる。`/proc`（procfs のマウントポイント）は真、作ったばかりの一時ディレクトリ
    /// （空白を含む名前の子を含む）は偽になる。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core6_is_mount_point_reads_real_mountinfo() {
        assert!(
            is_mount_point(std::path::Path::new("/proc")),
            "/proc must be a mount point"
        );
        let guard = crate::test_support::TestTempDir::new("sys-mountinfo").expect("temp dir");
        let spaced = guard.path().join("with space");
        std::fs::create_dir(&spaced).expect("create dir");
        assert!(
            !is_mount_point(&spaced),
            "fresh dir must not be a mount point"
        );
        assert!(
            !is_mount_point(guard.path()),
            "fresh dir must not be a mount point"
        );
    }

    /// CORE-6・SEC-5・SEC-1（TASK-29 追補・#1659）: `/dev/null`（文字デバイス 1:3）は期待値 (1, 3) で検証を通り、
    /// 検証に使った fd そのもの（開き直さない）を保持する。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core6_sec5_verify_device_node_fd_accepts_dev_null_and_keeps_the_fd() {
        let fd = open_o_path("/dev/null");
        let raw = fd.as_raw_fd();
        let node = verify_device_node_fd(fd, HostDeviceNode::Null).expect("verify /dev/null");
        assert_eq!(node.as_fd().as_raw_fd(), raw);
    }

    /// CORE-6・SEC-5・SEC-1（TASK-29 追補・#1659）: 文字デバイスでも `rdev` が期待値と違えば、実値と期待値を
    /// 持つ `UnexpectedRdev` で拒否する（`/dev/null` = 0x103 を `Zero`〔1:5〕= 0x105 として検証）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core6_sec5_verify_device_node_fd_rejects_unexpected_rdev() {
        let err =
            verify_device_node_fd(open_o_path("/dev/null"), HostDeviceNode::Zero).unwrap_err();
        assert_eq!(
            err,
            DeviceNodeError::UnexpectedRdev {
                actual: 0x103,
                expected: 0x105
            }
        );
    }

    /// CORE-6・SEC-5・SEC-1（TASK-29 追補・#1659）: ディレクトリ（`/`）と通常ファイル（テストバイナリ自身）は
    /// 文字デバイスでないため `NotCharDevice` で拒否する。`mode` は `st_mode` の実値で、種別ビット
    /// （`S_IFMT` = 0o170000）がディレクトリ 0o040000・通常ファイル 0o100000 になる。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core6_sec5_verify_device_node_fd_rejects_directory_and_regular_file() {
        let kind = |path: &str| match verify_device_node_fd(open_o_path(path), HostDeviceNode::Null)
        {
            Err(DeviceNodeError::NotCharDevice { mode }) => mode & 0o170_000,
            other => panic!("{path}: unexpected result: {other:?}"),
        };
        assert_eq!(kind("/"), 0o040_000);
        let exe = std::env::current_exe().expect("current_exe");
        assert_eq!(kind(exe.to_str().expect("utf8 path")), 0o100_000);
    }

    /// CORE-6・SEC-1・REPAIR-12（TASK-29 追補・#1659）: `/dev/null` を指す symlink を `O_PATH|O_NOFOLLOW` で
    /// 開いた fd は symlink 自体を指し、`NotCharDevice` で拒否される。`mode` の種別ビット（`S_IFMT`）は
    /// symlink の 0o120000。リンク先が実在する文字デバイスであること（辿れば検証を通る値であること）も先に
    /// 確かめ、拒否の理由が `O_NOFOLLOW` で辿らなかったことにあると示す（ぶら下がりリンクでの偶然の一致を除く）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn core6_sec1_verify_device_node_fd_rejects_symlink_opened_with_nofollow() {
        use std::os::unix::fs::{FileTypeExt as _, symlink};
        let guard = crate::test_support::TestTempDir::new("sys-devnode-symlink").expect("temp dir");
        let link = guard.path().join("null-link");
        symlink("/dev/null", &link).expect("symlink");
        let followed = std::fs::metadata(&link).expect("stat through link");
        assert!(
            followed.file_type().is_char_device(),
            "link target must be a char device"
        );
        match verify_device_node_fd(
            open_o_path(link.to_str().expect("utf8 path")),
            HostDeviceNode::Null,
        ) {
            Err(DeviceNodeError::NotCharDevice { mode }) => assert_eq!(mode & 0o170_000, 0o120_000),
            other => panic!("unexpected result: {other:?}"),
        }
    }

    /// `path` を `O_PATH | O_NOFOLLOW` で開く（実機前提テストと特権なしテストの共通部品）。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn open_o_path(path: &str) -> OwnedFd {
        use std::os::unix::fs::OpenOptionsExt as _;
        let flags = path_nofollow_open_flags().expect("supported arch");
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
            .expect("open O_PATH")
            .into()
    }

    /// 実機前提テストの子側であることを示す環境変数。
    const OPEN_TREE_CHILD_ENV: &str = "FANDHE_OPEN_TREE_CHILD";

    /// CORE-6・SEC-5（TASK-29 追補・#1659）: 実機前提（非特権 user namespace を許可するホスト。util-linux の
    /// `unshare`）。`unshare --user --map-root-user --mount` で隔離した子として自身（`--ignored`）を再実行し、
    /// 子の中で `open_tree_clone` → `move_mount_empty_path` の成功経路を照合する。実行:
    /// `cargo test -p fandhe-container-core --lib core6_sec5_open_tree_binds -- --ignored`
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    #[ignore = "requires unprivileged user+mount namespaces and util-linux unshare (CORE-6, SEC-5)"]
    fn core6_sec5_open_tree_binds_host_device_node_in_userns() {
        if std::env::var_os(OPEN_TREE_CHILD_ENV).is_some() {
            open_tree_bind_checks();
            return;
        }
        let exe = std::env::current_exe().expect("current_exe");
        let mut cmd = std::process::Command::new("unshare");
        cmd.args(["--user", "--map-root-user", "--mount", "--"])
            .arg(exe)
            .args([
                "--exact",
                "sys::tests::core6_sec5_open_tree_binds_host_device_node_in_userns",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(OPEN_TREE_CHILD_ENV, "1");
        // 子の終了待ちには期限を設け、期限超過時の kill の失敗・回収猶予（5 秒）の超過も無期限に待たず
        // 明示的に失敗させる（REPAIR-5）。同モジュールの `run_with_deadline`・`reap_bounded` を再利用する。
        let status = run_with_deadline(cmd, std::time::Duration::from_secs(60))
            .expect("spawn unshare and reap the inner open_tree test within the 60s deadline");
        assert!(status.success(), "child failed: {status:?}");
    }

    /// 子側の照合。fd 起点の複製・close-on-exec・ファイルへの接続・失敗時の未接続を具体値で確かめる。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn open_tree_bind_checks() {
        use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

        // 共有の一時領域で予測可能な名前・既存ディレクトリの受け入れ・symlink 追従を避ける: 0700 で排他的に
        // `create_dir` し（既存は拒否して名前を変えて再試行）、対象ファイルは `create_new`（O_EXCL。
        // symlink は追従せず既存なら失敗）で作る。
        let (dir, target_file) = {
            use std::os::unix::fs::DirBuilderExt as _;
            let mut attempt = 0u32;
            let dir = loop {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos())
                    .unwrap_or(0);
                let candidate = std::env::temp_dir().join(format!(
                    "fandhe-open-tree-{}-{nanos}-{attempt}",
                    std::process::id()
                ));
                match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
                    Ok(()) => break candidate,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < 16 => {
                        attempt += 1;
                    }
                    Err(e) => panic!("create dir: {e}"),
                }
            };
            let target_file = dir.join("null");
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target_file)
                .expect("create target file exclusively");
            (dir, target_file)
        };

        // fd 起点で /dev/null を複製できる。fd は close-on-exec（fdinfo の flags が O_CLOEXEC = 02000000）。
        let node = verify_device_node_fd(open_o_path("/dev/null"), HostDeviceNode::Null)
            .expect("verify /dev/null");
        let clone = open_tree_clone(&node).expect("open_tree_clone");
        assert_eq!(fd_flags(&clone) & 0o2_000_000, 0o2_000_000);

        // 失敗時: ディレクトリ（ファイルの複製の接続先として不正）へ接続すると `EINVAL` で拒否される
        // （fs/namespace.c の `do_move_mount` は `err = -EINVAL` のまま `d_is_dir(new) != d_is_dir(old)` で抜ける。
        // v5.2・v6.12 で確認。`ENOTDIR` は `mount(2)` 側の `graft_tree` の値）。接続を試みたディレクトリにも、
        // まだ接続していないファイルにも何も載っていない。
        let dir_fd = open_o_path(dir.to_str().expect("utf8 path"));
        let err = move_mount_empty_path(clone.as_fd(), dir_fd.as_fd()).unwrap_err();
        assert_eq!(err, SysError::Os(EINVAL));
        assert!(!is_mount_point(&dir), "dir must stay unattached");
        assert!(!is_mount_point(&target_file), "file must stay unattached");
        let before = std::fs::metadata(&target_file).expect("stat");
        assert!(
            before.file_type().is_file(),
            "target must stay a regular file"
        );

        // 成功: 通常ファイルへ接続すると、そのパスが /dev/null（文字デバイス 1:3）として見える。
        let to = open_o_path(target_file.to_str().expect("utf8 path"));
        move_mount_empty_path(clone.as_fd(), to.as_fd()).expect("move_mount_empty_path");
        assert!(
            is_mount_point(&target_file),
            "file must be a mount point after attach"
        );
        assert!(!is_mount_point(&dir), "dir must stay unattached");
        let meta = std::fs::metadata(&target_file).expect("stat after attach");
        assert!(meta.file_type().is_char_device());
        let rdev = meta.rdev();
        // major = 1, minor = 3（Linux の dev_t エンコード: major は bit 8..19、minor は下位 8bit）。
        assert_eq!(((rdev >> 8) & 0xfff, rdev & 0xff), (1, 3));
        // 読み書きが通る（/dev/null として機能している）。
        std::fs::write(&target_file, b"x").expect("write to attached /dev/null");

        // 後始末: clone の fd を閉じても接続済みのマウントは解除されない。マウントポイントのまま
        // `remove_dir_all` すると EBUSY で一時領域（ホスト側の dir と空ファイル）が残るため、先に
        // 切り離してから削除し、どちらの失敗も検出する。
        drop(clone);
        let target_c = std::ffi::CString::new(target_file.to_str().expect("utf8 path"))
            .expect("no interior NUL");
        umount_detach_at(&target_c).expect("detach attached mount");
        std::fs::remove_dir_all(&dir).expect("remove temp dir after detach");
        assert!(!dir.exists(), "temp dir must be removed");
    }
}
