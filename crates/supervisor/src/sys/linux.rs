//! Linux 向け capability / credential syscall の薄いラッパー（`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・
//! syscall」節・オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 役割と呼び出し文脈
//! `privilege::elevate`（SUP-14・SEC-1・TASK-171.1.3・#1475・MS-9）が縮退計画（`ReductionPlan::steps`）を適用する際に
//! 呼ぶ。方式（特権ランチャー + ambient〔file capability〕／setuid root）は #1454 のオーナー判断（2026-10-10）で承認済み。
//! `crates/core/src/sys.rs` の同等関数は `pub(crate)` で crate をまたげないため、supervisor 側に同等のものを持つ
//! （重複は #1454 で許容済み。依存は増やさない）。
//!
//! `privilege::detach_session`（SUP-14 の要素 (B)。TASK-171.2・#537）向けに、新しいセッションを作る `setsid(2)` も持つ。
//!
//! # 不変条件
//! - `unsafe` は本モジュール内に閉じ、公開するのは安全な関数のみ（`unsafe fn` を外へ出さない）。
//! - capability / keepcaps の操作は呼び出したスレッドだけに効く。`setresuid` 等は glibc / musl のラッパーが全スレッドへ
//!   配る。呼び出し元（`privilege::elevate`）が単一スレッドであることを確認してから使う。
//! - 対応 arch は LP64 の x86_64・aarch64 のみ。その他では `capget` / `capset` の syscall 番号を持たず、
//!   仮の番号を発行せず `Unsupported` を返す（fail-closed）。他 arch の番号を流用しない。
//! - `syscall(2)` の宣言と、それを使う `capget` / `capset` / `execveat` / `close_range` は LP64 の x86_64・aarch64 に限る。
//!   それ以外では宣言を持たず、capability / execveat は `Unsupported`、`close_fds_from` は `/proc/self/fd` の走査だけ
//!   で閉じる（`compile_error!` にしない理由: 他の fail-closed と形を揃え、非 LP64 でも crate をビルドできる
//!   ため。#3100・SUP-6・MVM-4）。
//! - `prctl(2)` の宣言と、それを使う `cap_bounding_drop` / `cap_ambient_raise` / `cap_ambient_clear_all` / `set_keep_caps` /
//!   `get_keep_caps` / `set_dumpable` も同じ LP64 の x86_64・aarch64 に限る（可変長部を `u64` = `unsigned long` で渡すため、
//!   ILP32 では引数の並びがずれる）。それ以外では FFI を呼ばず `Unsupported` を返す。`clear_ambient_caps_on_exec` は
//!   `pre_exec` の失敗で `spawn` が `Err` になり、ambient を持ったまま exec しない（#3202・SUP-6・MVM-4）。
//! - 制御チャネル用の FFI（`socket` / `connect` / `clock_gettime`・`Timespec`・`SockaddrUn`）は LP64 の x86_64・aarch64 でのみ
//!   コンパイルし、それ以外は `Unsupported`（#2140）。
//! - 引数はすべて整数または呼び出しの間有効なスタック上の `#[repr(C)]` 値で、`-1` 戻り時は直後に
//!   `io::Error::last_os_error()` を取る。

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;

/// `capget(2)` / `capset(2)` の syscall 番号（`syscall(2)` 経由。glibc にラッパーが無い）。
/// 出典: x86_64 は arch/x86/entry/syscalls/syscall_64.tbl、aarch64 は include/uapi/asm-generic/unistd.h。
/// 値が同じでも arch ごとに別定義にし、他 arch の定義を流用しない。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
mod arch {
    #[cfg(test)]
    pub(super) const SYS_CAPGET: Option<i64> = Some(125);
    pub(super) const SYS_CAPSET: Option<i64> = Some(126);
    pub(super) const SYS_EXECVEAT: Option<i64> = Some(322);
    // 制御チャネル（#2058）。open(2) の O_DIRECTORY / O_NOFOLLOW は arch ごとに値が違う
    // （arch/x86/include/uapi/asm/fcntl.h は asm-generic の既定値のまま: 0o200000 / 0o400000）。
    pub(super) const O_DIRECTORY: Option<i32> = Some(0o200000);
    pub(super) const O_NOFOLLOW: Option<i32> = Some(0o400000);
    // asm-generic/socket.h の値（x86_64・aarch64 で共通）。
    pub(super) const SOL_SOCKET: Option<i32> = Some(1);
    pub(super) const SO_PEERCRED: Option<i32> = Some(17);
}
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
mod arch {
    #[cfg(test)]
    pub(super) const SYS_CAPGET: Option<i64> = Some(90);
    pub(super) const SYS_CAPSET: Option<i64> = Some(91);
    pub(super) const SYS_EXECVEAT: Option<i64> = Some(281);
    // 制御チャネル（#2058）。aarch64 の O_DIRECTORY / O_NOFOLLOW は
    // arch/arm64/include/uapi/asm/fcntl.h の値（0o40000 / 0o100000）。
    pub(super) const O_DIRECTORY: Option<i32> = Some(0o40000);
    pub(super) const O_NOFOLLOW: Option<i32> = Some(0o100000);
    // asm-generic/socket.h の値（x86_64・aarch64 で共通）。
    pub(super) const SOL_SOCKET: Option<i32> = Some(1);
    pub(super) const SO_PEERCRED: Option<i32> = Some(17);
}
#[cfg(not(any(
    all(target_arch = "x86_64", target_pointer_width = "64"),
    all(target_arch = "aarch64", target_pointer_width = "64")
)))]
mod arch {
    pub(super) const O_DIRECTORY: Option<i32> = None;
    pub(super) const O_NOFOLLOW: Option<i32> = None;
    pub(super) const SOL_SOCKET: Option<i32> = None;
    pub(super) const SO_PEERCRED: Option<i32> = None;
}

/// `EPERM`（include/uapi/asm-generic/errno-base.h の 1。x86_64・aarch64 で共通）。`privilege` が `setsid(2)` の
/// 「プロセスグループのリーダー」と capability 系 syscall の権限不足を見分けるのに使う（SUP-14・#2426）。
/// 値は `libc_abi`（#1840）が `libc` と照合し、下の単体テストが具体値も照合する。
pub(crate) const EPERM: i32 = 1;

/// `fcntl(2)` の `F_GETFD`（fd が開いているかの確認に使う）。
const F_GETFD: i32 = 1;
/// capability 番号の上限（排他）。カーネルの `CAP_LAST_CAP` は 63 以下で、64 以上は ambient / bounding に渡さない。
const CAP_NUMBER_LIMIT: u8 = 64;

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: `int setgroups(size_t size, const gid_t *list)`（Linux の `gid_t` は u32）。
    fn setgroups(size: usize, list: *const u32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int setresgid(gid_t rgid, gid_t egid, gid_t sgid)`。
    fn setresgid(rgid: u32, egid: u32, sgid: u32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int setresuid(uid_t ruid, uid_t euid, uid_t suid)`。
    fn setresuid(ruid: u32, euid: u32, suid: u32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int fcntl(int fd, int cmd, ...)`。可変長部は使わない。
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int close(int fd)`。
    fn close(fd: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `pid_t setsid(void)`（`pid_t` は Linux で i32）。引数なし・ポインタなし。
    // `libc` との照合は `libc_abi`（#1840）。#537 で追加。
    fn setsid() -> i32;
    // SAFETY（宣言そのものの妥当性）: `int kill(pid_t pid, int sig)`（`pid_t` は Linux で i32）。整数引数のみ。
    // `libc` との照合は `libc_abi`（#1840）。
    fn kill(pid: i32, sig: i32) -> i32;
    // SAFETY（宣言そのものの妥当性）: `int getsockopt(int sockfd, int level, int optname, void *optval,
    // socklen_t *optlen)`（`socklen_t` は Linux で u32）。制御チャネルの `SO_PEERCRED` 取得だけに使う（#2058）。
    fn getsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *mut std::ffi::c_void,
        optlen: *mut u32,
    ) -> i32;
    // SAFETY（宣言そのものの妥当性）: `ssize_t lgetxattr(const char *path, const char *name, void *value,
    // size_t size)`（glibc / musl。LP64 で `ssize_t` は isize、`size_t` は usize）。symlink を辿らない。
    // doctor の特権ランチャー診断（#2599）の `security.capability` 読み取りだけに使う。`libc` との照合は
    // `libc_abi`（#1840）。
    fn lgetxattr(
        path: *const std::ffi::c_char,
        name: *const std::ffi::c_char,
        value: *mut std::ffi::c_void,
        size: usize,
    ) -> isize;
}

/// `struct ucred`（`SO_PEERCRED` の結果。include/uapi/asm-generic/socket.h・`<sys/socket.h>`）。
/// `libc::ucred` との照合は `libc_abi`（#1840）。レイアウトは pid_t(i32)・uid_t(u32)・gid_t(u32) の 12 バイトで、
/// 単体テストが大きさも固定する。
#[repr(C)]
struct Ucred {
    pid: i32,
    uid: u32,
    gid: u32,
}

/// 接続相手の資格情報（`SO_PEERCRED`。接続時点の相手プロセスの値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerCredentials {
    pub(crate) pid: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

/// 呼び出したスレッドの capability（ビット位置は capability 番号。v3 の 2 語を 64 bit に束ねた値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreadCaps {
    pub(crate) effective: u64,
    pub(crate) permitted: u64,
    pub(crate) inheritable: u64,
}

/// 対応外アーキテクチャ向けの失敗。非 LP64 では `pre_exec`（fork 後・exec 前）の `cap_ambient_clear_all` から
/// 呼ばれるため、ヒープを確保しない `ErrorKind` だけの error にする（async-signal-safe を保つ。#3313・SUP-6）。
///
/// メッセージ文字列は持たない。std は `pre_exec` の失敗を親へ EINVAL として返すので、親の `spawn` は `Err`
/// になる（fail-closed）。数値 errno（ENOSYS 等）は arch ごとに値が異なりうるため推測して使わない。
fn unsupported() -> io::Error {
    io::Error::from(io::ErrorKind::Unsupported)
}

/// `-1` なら直後の errno を `io::Error` にする（`-1` の直後に呼ぶこと）。
fn check(rc: i64) -> io::Result<i64> {
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

fn check_cap_number(cap: u8) -> io::Result<()> {
    if cap >= CAP_NUMBER_LIMIT {
        return Err(io::Error::from_raw_os_error(22)); // EINVAL
    }
    Ok(())
}

/// `pgid` のプロセスグループ全体へ SIGKILL を送る（`kill(-pgid, SIGKILL)`。#2390・REPAIR-5）。
///
/// 呼び出し元は `process_group(0)` で起動した子の pid（= pgid）だけを渡す。`pgid` が 2 未満・`i32` 範囲外なら
/// `EINVAL` を返し、全プロセス（-1）や自グループ・init への送信を作らない。
pub(crate) fn kill_process_group(pgid: u32) -> io::Result<()> {
    const SIGKILL: i32 = 9;
    let pgid = i32::try_from(pgid)
        .ok()
        .filter(|p| *p >= 2)
        .ok_or_else(|| io::Error::from_raw_os_error(22))?;
    // SAFETY: 引数は整数のみでポインタを渡さない。負の pid はプロセスグループ宛てで、pgid >= 2 を検証済みのため
    // 全プロセス（-1）や自プロセスへ送らない。影響は対象グループの終了のみ（メモリ安全性に影響しない）。
    let rc = unsafe { kill(-pgid, SIGKILL) };
    check(i64::from(rc)).map(|_| ())
}

/// 子プロセスの exec 直前に ambient capability をすべて消すよう `cmd` へ登録する（#2390・SEC-5・SUP-14）。
///
/// supervisor は特権ランチャー経由で ambient capability を持つことがあり、setuid でない外部コマンド
/// （NSS 参照の `getent`）はそのまま exec すると ambient を引き継ぐ。`id_model` が `getent` を起動する前に
/// 呼ぶ。消去に失敗したら子は exec せず `spawn` が `Err` を返す（fail-closed）。
pub(crate) fn clear_ambient_caps_on_exec(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: クロージャは fork 後・exec 前の子で実行される。呼ぶのは整数引数のみの `prctl` 1 回で、
    // 確保・ロック・親との共有状態の操作をしない（async-signal-safe。非 LP64 のスタブも確保しない `unsupported()` を返す）。影響は子の ambient 集合の縮小のみ。
    unsafe {
        cmd.pre_exec(cap_ambient_clear_all);
    }
}

/// 補助グループを全消去する（`setgroups(0, NULL)`。`CAP_SETGID` が effective に必要）。
pub(crate) fn clear_supplementary_groups() -> io::Result<()> {
    // SAFETY: サイズ 0 のため `list` は読まれず、NULL を渡してよい。影響はプロセスの補助グループの消去のみ。
    let rc = unsafe { setgroups(0, std::ptr::null()) };
    check(i64::from(rc)).map(|_| ())
}

/// `setresgid(r, e, s)`。fs gid は effective に追従する。呼び出し元は単一スレッドに限る。
pub(crate) fn set_resgid(real: u32, effective: u32, saved: u32) -> io::Result<()> {
    // SAFETY: 引数は整数のみでポインタを渡さない。影響はプロセスの gid の変更のみ（メモリ安全性に影響しない）。
    let rc = unsafe { setresgid(real, effective, saved) };
    check(i64::from(rc)).map(|_| ())
}

/// `setresuid(r, e, s)`。fs uid は effective に追従する。呼び出し元は単一スレッドに限る。
pub(crate) fn set_resuid(real: u32, effective: u32, saved: u32) -> io::Result<()> {
    // SAFETY: 引数は整数のみでポインタを渡さない。影響はプロセスの uid の変更のみ（メモリ安全性に影響しない）。
    let rc = unsafe { setresuid(real, effective, saved) };
    check(i64::from(rc)).map(|_| ())
}

/// `syscall(2)` を使う経路（capget / capset / execveat / close_range）。`syscall` の宣言が LP64（`long` が 64 bit）
/// 前提のため、LP64 の x86_64・aarch64 でのみ宣言ごとコンパイルする。cfg は `libc_abi` の照合と同一にし、
/// 宣言があるのに照合されないターゲットを作らない（#3100・SUP-6・MVM-4・REPAIR-12）。他ターゲットは下の
/// スタブが `Unsupported` を返し、`close_fds_from` は `/proc/self/fd` の走査だけで閉じる。
#[cfg(any(
    all(target_arch = "x86_64", target_pointer_width = "64"),
    all(target_arch = "aarch64", target_pointer_width = "64")
))]
mod syscall_ffi {
    use super::*;

    /// include/uapi/linux/capability.h の `_LINUX_CAPABILITY_VERSION_3`（2 語・64 bit 形式）。
    pub(super) const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    /// `execveat(2)` の `AT_EMPTY_PATH`（include/uapi/linux/fcntl.h）。pathname が空のとき dirfd 自体を実行対象にする。
    pub(super) const AT_EMPTY_PATH: i64 = 0x1000;
    /// `close_range(2)` の syscall 番号（全 arch 共通の統一番号表の値。Linux 5.9 以降）。
    pub(super) const SYS_CLOSE_RANGE: i64 = 436;
    /// execveat に渡す argv / envp の要素数の上限（無制限確保の防止）。
    pub(super) const MAX_EXEC_VECTOR: usize = 4096;
    /// include/uapi/linux/prctl.h の値。prctl は可変長部を `unsigned long` で渡すため LP64 限定（#3202）。
    pub(super) const PR_SET_DUMPABLE: i32 = 4;
    pub(super) const PR_GET_KEEPCAPS: i32 = 7;
    pub(super) const PR_SET_KEEPCAPS: i32 = 8;
    pub(super) const PR_CAPBSET_DROP: i32 = 24;
    pub(super) const PR_CAP_AMBIENT: i32 = 47;
    pub(super) const PR_CAP_AMBIENT_RAISE: u64 = 2;
    pub(super) const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;
    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: `long syscall(long number, ...)`（glibc / musl。LP64 で `long` は i64）。この宣言は LP64 の x86_64・aarch64 でのみ
        // コンパイルし、cfg は `libc_abi` と同一（#3100）。
        pub(super) fn syscall(number: i64, ...) -> i64;
        // SAFETY（宣言そのものの妥当性）: `int prctl(int option, ...)`（glibc / musl）。可変長引数として宣言する
        // （非可変長で宣言して呼ぶと、可変長引数の渡し方が異なる ABI で未定義動作になる）。可変長部は
        // `unsigned long`（LP64 で u64）に合わせて渡す。この宣言は LP64 の x86_64・aarch64 でのみコンパイルする（#3202）。
        pub(super) fn prctl(option: i32, ...) -> i32;
    }

    /// `cap` を呼び出したスレッドの bounding set から外す（`PR_CAPBSET_DROP`。不可逆。`CAP_SETPCAP` が effective に必要）。
    pub(crate) fn cap_bounding_drop(cap: u8) -> io::Result<()> {
        check_cap_number(cap)?;
        // SAFETY: 引数は整数のみでポインタを渡さない。可変長部は `unsigned long` に合わせて u64 で渡す。
        // 影響は呼び出したスレッドの bounding set の縮小のみ（権限を減らす方向にしか働かない）。
        let rc = unsafe { prctl(PR_CAPBSET_DROP, u64::from(cap), 0u64, 0u64, 0u64) };
        check(i64::from(rc)).map(|_| ())
    }

    /// `cap` を ambient 集合へ載せる（`PR_CAP_AMBIENT_RAISE`。permitted かつ inheritable に含まれる必要がある）。
    pub(crate) fn cap_ambient_raise(cap: u8) -> io::Result<()> {
        check_cap_number(cap)?;
        // SAFETY: 引数は整数のみでポインタを渡さない。可変長部は `unsigned long` に合わせて u64 で渡す。
        // 影響は呼び出したスレッドの ambient 集合の拡大のみで、permitted ∩ inheritable を超えてはカーネルが拒否する。
        let rc = unsafe {
            prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_RAISE,
                u64::from(cap),
                0u64,
                0u64,
            )
        };
        check(i64::from(rc)).map(|_| ())
    }

    /// ambient capability をすべて消す（`PR_CAP_AMBIENT_CLEAR_ALL`）。
    pub(crate) fn cap_ambient_clear_all() -> io::Result<()> {
        // SAFETY: 引数は整数のみでポインタを渡さない。可変長部は `unsigned long` に合わせて u64 で渡す。
        // 影響は呼び出したスレッドの ambient 集合の縮小のみ。
        let rc = unsafe { prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0u64, 0u64, 0u64) };
        check(i64::from(rc)).map(|_| ())
    }

    /// `PR_SET_KEEPCAPS` を設定 / 解除する（`setresuid` をまたいで permitted を保持するための一時設定。
    /// 呼び出したスレッドのみ）。
    pub(crate) fn set_keep_caps(on: bool) -> io::Result<()> {
        // SAFETY: 引数は整数のみでポインタを渡さない。可変長部は `unsigned long` に合わせて u64 で渡す。
        // 影響は呼び出したスレッドの securebits の `SECBIT_KEEP_CAPS` のみ。
        let rc = unsafe { prctl(PR_SET_KEEPCAPS, u64::from(on), 0u64, 0u64, 0u64) };
        check(i64::from(rc)).map(|_| ())
    }

    /// `PR_GET_KEEPCAPS` を読む。戻り値が 0 / 1 以外なら `EINVAL` として扱う。
    pub(crate) fn get_keep_caps() -> io::Result<bool> {
        // SAFETY: 引数は整数のみでポインタを渡さない。読み取りだけで状態を変えない。
        let rc = unsafe { prctl(PR_GET_KEEPCAPS, 0u64, 0u64, 0u64, 0u64) };
        match check(i64::from(rc))? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(io::Error::from_raw_os_error(22)), // EINVAL
        }
    }

    /// `PR_SET_DUMPABLE` を設定する。0 にすると ptrace attach・core dump・`/proc/<pid>/mem` 等の読み取りを
    /// 同一 uid の別プロセスから受けない（昇格中の窓の防御）。
    pub(crate) fn set_dumpable(on: bool) -> io::Result<()> {
        // SAFETY: 引数は整数のみでポインタを渡さない。影響は呼び出しプロセスの dumpable 属性のみ。
        let rc = unsafe { prctl(PR_SET_DUMPABLE, u64::from(on), 0u64, 0u64, 0u64) };
        check(i64::from(rc)).map(|_| ())
    }

    /// `capget(2)` / `capset(2)` のヘッダ（`struct __user_cap_header_struct`）。
    #[repr(C)]
    pub(super) struct CapUserHeader {
        version: u32,
        pid: i32,
    }

    /// `capget(2)` / `capset(2)` のデータ 1 語分（`struct __user_cap_data_struct`）。v3 は 2 要素の配列。
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    pub(super) fn split(v: u64) -> [u32; 2] {
        // 下位 32 bit と上位 32 bit への分割（意図的な切り詰め）。
        [(v & 0xffff_ffff) as u32, (v >> 32) as u32]
    }

    #[cfg(test)]
    pub(super) fn join(lo: u32, hi: u32) -> u64 {
        u64::from(lo) | (u64::from(hi) << 32)
    }

    /// 呼び出したスレッドの effective / permitted / inheritable を読む（pid 0 の `capget(2)`）。
    ///
    /// 単体テストで `capset` のレイアウトと `/proc/self/status` の整合を照合するために使う。カーネルが v3 以外を
    /// 返したら `EINVAL` として fail-closed にする。
    #[cfg(test)]
    pub(super) fn cap_get_thread() -> io::Result<ThreadCaps> {
        let nr = arch::SYS_CAPGET.ok_or_else(unsupported)?;
        let mut header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        // SAFETY: `header` と `data`（v3 が要求する 2 要素）はこの関数のスタック上の `#[repr(C)]` 値で、呼び出しの
        // 間有効かつ排他的に借用されている。カーネルは `CapUserHeader` と `[CapUserData; 2]` の大きさだけ書く。
        // 影響は呼び出したスレッドの読み取りのみ。
        let rc = unsafe { syscall(nr, &raw mut header, data.as_mut_ptr()) };
        check(rc)?;
        if header.version != LINUX_CAPABILITY_VERSION_3 {
            return Err(io::Error::from_raw_os_error(22)); // EINVAL
        }
        Ok(ThreadCaps {
            effective: join(data[0].effective, data[1].effective),
            permitted: join(data[0].permitted, data[1].permitted),
            inheritable: join(data[0].inheritable, data[1].inheritable),
        })
    }

    /// 呼び出したスレッドの effective / permitted / inheritable を設定する（pid 0 の `capset(2)`）。
    pub(crate) fn cap_set_thread(caps: ThreadCaps) -> io::Result<()> {
        let nr = arch::SYS_CAPSET.ok_or_else(unsupported)?;
        let header = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let (e, p, i) = (
            split(caps.effective),
            split(caps.permitted),
            split(caps.inheritable),
        );
        let data = [0usize, 1].map(|n| CapUserData {
            effective: e.get(n).copied().unwrap_or(0),
            permitted: p.get(n).copied().unwrap_or(0),
            inheritable: i.get(n).copied().unwrap_or(0),
        });
        // SAFETY: `header` と `data`（v3 が要求する 2 要素）はスタック上の `#[repr(C)]` 値で、呼び出しの間有効。
        // カーネルは読み取りのみ行う。資格情報の変更は呼び出したスレッドに限られ、メモリ安全性には影響しない。
        let rc = unsafe { syscall(nr, &raw const header, data.as_ptr()) };
        check(rc).map(|_| ())
    }

    /// 検証済みの実行ファイルの fd を `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` で実行する（SUP-14・TASK-171 追補・#1719）。
    ///
    /// パス文字列で検証して別途パスで exec する方式の TOCTOU を避けるため、呼び出し元が `fstat` で検証した fd をそのまま
    /// 渡す。成功時は戻らない。戻るのは失敗（`io::Error`）のときだけで、`Unsupported`（対応外 arch）・`EINVAL`
    /// （要素数の上限超過）を含む。`argv` / `envp` は NUL 終端済みの `CString` で受け、ポインタ配列は本関数内で組む。
    pub(crate) fn execveat_fd(fd: i32, argv: &[CString], envp: &[CString]) -> io::Result<()> {
        let nr = arch::SYS_EXECVEAT.ok_or_else(unsupported)?;
        if argv.len() > MAX_EXEC_VECTOR || envp.len() > MAX_EXEC_VECTOR {
            return Err(io::Error::from_raw_os_error(22)); // EINVAL
        }
        let mut argv_ptrs: Vec<*const std::ffi::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        let mut envp_ptrs: Vec<*const std::ffi::c_char> = envp.iter().map(|s| s.as_ptr()).collect();
        envp_ptrs.push(std::ptr::null());
        let empty = c"";
        // SAFETY: `empty`・`argv_ptrs`・`envp_ptrs` と各 `CString` は呼び出しの間有効で、ポインタ配列は NULL 終端、
        // 各要素は NUL 終端の C 文字列を指す。カーネルは読み取りのみ行う。成功時はプロセス像が置き換わって戻らず、
        // 失敗時は何も変えずに -1 を返す（直後に errno を取る）。
        let rc = unsafe {
            syscall(
                nr,
                i64::from(fd),
                empty.as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptrs.as_ptr(),
                AT_EMPTY_PATH,
            )
        };
        check(rc).map(|_| ())
    }

    /// `first` 以降の fd をすべて閉じる（`close_range(first, !0, 0)`。Linux 5.9 以降）。`ENOSYS` のときは
    /// `/proc/self/fd` を列挙して閉じる。継承 fd を supervisor へ渡さないために exec の前に呼ぶ。
    pub(crate) fn close_fds_from(first: u32) -> io::Result<()> {
        // SAFETY: 引数は整数のみでポインタを渡さない。影響は呼び出しプロセスの fd 表の縮小のみ。
        let rc = unsafe { syscall(SYS_CLOSE_RANGE, i64::from(first), i64::from(u32::MAX), 0i64) };
        match check(rc) {
            Ok(_) => Ok(()),
            Err(e) if e.raw_os_error() == Some(38) => close_fds_from_proc(first), // ENOSYS
            Err(e) => Err(e),
        }
    }
}

/// 非 LP64 向けのスタブ。仮の番号や食い違う ABI で `syscall(2)` を発行しない（fail-closed）。`close_fds_from` は
/// `close(int)` だけを使う `/proc/self/fd` 経路で、ILP32 でも ABI が正しく、継承 fd を渡さない目的を満たす。
#[cfg(not(any(
    all(target_arch = "x86_64", target_pointer_width = "64"),
    all(target_arch = "aarch64", target_pointer_width = "64")
)))]
mod syscall_ffi {
    use super::*;

    pub(crate) fn cap_set_thread(_caps: ThreadCaps) -> io::Result<()> {
        Err(unsupported())
    }

    pub(crate) fn cap_bounding_drop(cap: u8) -> io::Result<()> {
        check_cap_number(cap)?;
        Err(unsupported())
    }

    pub(crate) fn cap_ambient_raise(cap: u8) -> io::Result<()> {
        check_cap_number(cap)?;
        Err(unsupported())
    }

    /// 非 LP64 では `Err` を返す。`clear_ambient_caps_on_exec` が登録する `pre_exec` も失敗し、`spawn` が
    /// `Err` になる（ambient を持ったまま子を exec しない。fail-closed）。
    pub(crate) fn cap_ambient_clear_all() -> io::Result<()> {
        Err(unsupported())
    }

    pub(crate) fn set_keep_caps(_on: bool) -> io::Result<()> {
        Err(unsupported())
    }

    pub(crate) fn get_keep_caps() -> io::Result<bool> {
        Err(unsupported())
    }

    pub(crate) fn set_dumpable(_on: bool) -> io::Result<()> {
        Err(unsupported())
    }

    pub(crate) fn execveat_fd(_fd: i32, _argv: &[CString], _envp: &[CString]) -> io::Result<()> {
        Err(unsupported())
    }

    pub(crate) fn close_fds_from(first: u32) -> io::Result<()> {
        close_fds_from_proc(first)
    }
}

#[cfg(any(
    all(target_arch = "x86_64", target_pointer_width = "64"),
    all(target_arch = "aarch64", target_pointer_width = "64")
))]
// 抑止理由: libc との照合試験（FFI 宣言の機械照合。MVM-4）が `super::*` 経由で syscall_ffi の
// 定数・構造体・関数を参照する。通常ビルドでは再 export 済みの 3 関数以外は未使用になるため、
// glob import の `unused_imports` だけを許す（LP64 以外では syscall_ffi ごと cfg で除外される）。
#[allow(unused_imports)]
use syscall_ffi::*;
pub(crate) use syscall_ffi::{
    cap_ambient_clear_all, cap_ambient_raise, cap_bounding_drop, cap_set_thread, close_fds_from,
    execveat_fd, get_keep_caps, set_dumpable, set_keep_caps,
};

/// `close_range` が無いカーネル向けの代替。`/proc/self/fd` の列挙を先に集めてから閉じる（列挙中の fd を閉じない）。
fn close_fds_from_proc(first: u32) -> io::Result<()> {
    let mut fds: Vec<i32> = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd")? {
        let name = entry?.file_name();
        if let Some(fd) = name.to_str().and_then(|s| s.parse::<i32>().ok())
            && u32::try_from(fd).is_ok_and(|v| v >= first)
        {
            fds.push(fd);
        }
    }
    for fd in fds {
        // 列挙に使った fd は閉じた時点で EBADF になり得る。それは無視する。
        // SAFETY: `close(2)` の引数は整数のみ。影響は呼び出しプロセスの fd 表の縮小のみ。
        let _ = unsafe { close(fd) };
    }
    Ok(())
}

/// `fd` が開いているか（`fcntl(F_GETFD)`）。
pub(crate) fn fd_is_open(fd: i32) -> bool {
    // SAFETY: 引数は整数のみでポインタを渡さない。読み取りだけで状態を変えない。
    unsafe { fcntl(fd, F_GETFD) != -1 }
}

/// ディレクトリを symlink を辿らずに開くための `open(2)` フラグ（`O_DIRECTORY | O_NOFOLLOW`）。
/// 対応外の arch では `Unsupported`（別 arch の値を流用しない。fail-closed）。
pub(crate) fn open_dir_nofollow_flags() -> io::Result<i32> {
    match (arch::O_DIRECTORY, arch::O_NOFOLLOW) {
        (Some(d), Some(n)) => Ok(d | n),
        _ => Err(unsupported()),
    }
}

/// `ENODATA`（include/uapi/asm-generic/errno.h の 61。x86_64・aarch64 で共通）。xattr が付いていない。
pub(crate) const ENODATA: i32 = 61;
/// `EOPNOTSUPP`（同 95。Linux の `ENOTSUP` と同値）。ファイルシステムが xattr に非対応。
pub(crate) const EOPNOTSUPP: i32 = 95;
/// `ERANGE`（include/uapi/asm-generic/errno-base.h の 34）。値が渡したバッファより大きい。
pub(crate) const ERANGE: i32 = 34;

/// `security.capability`（file capability。カーネルの `XATTR_NAME_CAPS`）の名前。NUL 終端。
const XATTR_NAME_CAPS: &[u8] = b"security.capability\0";
/// `security.capability` を読むバッファの大きさ（`VFS_CAP_REVISION_3` の 24 バイトちょうど。これを超える値は `ERANGE`）。
pub(crate) const FILE_CAPS_BUF_LEN: usize = 24;

/// `path` の `security.capability` を symlink を辿らず読む（`lgetxattr(2)`。読み取り専用）。
///
/// 値が無ければ `ENODATA`、非対応のファイルシステムなら `EOPNOTSUPP`、24 バイトを超えれば `ERANGE` を `io::Error`
/// の errno で返す。`security.*` はファイルの読み取り権限を要さない。`path` に NUL を含むと `InvalidInput`。
pub(crate) fn read_security_capability(path: &Path) -> io::Result<Vec<u8>> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut buf = [0u8; FILE_CAPS_BUF_LEN];
    // SAFETY: `c_path`・`XATTR_NAME_CAPS` は NUL 終端でこの呼び出しの間有効。`buf` はこの関数のスタック上の
    // 24 バイトで、`size` に同じ長さを渡すためカーネルは最大 24 バイトしか書かない。影響は読み取りのみ。
    let rc = unsafe {
        lgetxattr(
            c_path.as_ptr(),
            XATTR_NAME_CAPS.as_ptr().cast(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    let len = usize::try_from(rc).map_err(|_| io::Error::last_os_error())?;
    // 戻り値が渡した大きさを超えることはないが、外部（カーネル）応答として検証する。
    buf.get(..len)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| io::Error::from_raw_os_error(ERANGE))
}

/// 接続済みの UNIX ドメインソケットの相手の資格情報を取る（`getsockopt(SOL_SOCKET, SO_PEERCRED)`）。
///
/// 制御チャネルの accept 直後（サーバ）と connect 直後（クライアント）に、相手の uid を照合するために呼ぶ
/// （SEC-1・PLUG-12 と同じ考え方）。結果の大きさが `struct ucred` と一致しなければ `EINVAL`。
pub(crate) fn peer_credentials(fd: BorrowedFd<'_>) -> io::Result<PeerCredentials> {
    let (Some(level), Some(optname)) = (arch::SOL_SOCKET, arch::SO_PEERCRED) else {
        return Err(unsupported());
    };
    let mut cred = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let expected = u32::try_from(std::mem::size_of::<Ucred>())
        .map_err(|_| io::Error::from_raw_os_error(22))?;
    let mut len = expected;
    // SAFETY: `fd` は借用で呼び出しの間開いている。`cred` は `#[repr(C)]` の 12 バイトで `optval` に渡すポインタは
    // その先頭を指し、`len` は書き込み可能な大きさ（12）を表す `optlen`。カーネルは最大 `len` バイトを `cred` に書き、
    // `len` を実際の大きさへ更新する。いずれもこの関数のスタック上の値で呼び出しの間有効かつ排他的。
    let rc = unsafe {
        getsockopt(
            fd.as_raw_fd(),
            level,
            optname,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    check(i64::from(rc))?;
    if len != expected {
        return Err(io::Error::from_raw_os_error(22)); // EINVAL
    }
    Ok(PeerCredentials {
        pid: u32::try_from(cred.pid).unwrap_or(0),
        uid: cred.uid,
        gid: cred.gid,
    })
}

/// 制御チャネル用 FFI の LP64 限定モジュール（x86_64・aarch64 の 64 ビットのみ。#2140・SUP-1・REPAIR-5）。
///
/// `Timespec` は `time_t`・`long` が 8 バイトの LP64 を、`SOCK_NONBLOCK` / `SOCK_CLOEXEC` は asm-generic の値を
/// 前提とする（`SockaddrUn` 自体は LP64 非依存だが、制御チャネル全体が同じ対象に閉じるためここへ置く）。
/// 対象外のターゲットでは構造体も extern も持たず、後続の `cfg(not(...))` 側が `Unsupported` を返す。
#[cfg(any(
    all(target_arch = "x86_64", target_pointer_width = "64"),
    all(target_arch = "aarch64", target_pointer_width = "64")
))]
mod control_ffi {
    use super::check;
    use std::io;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::net::UnixStream;

    unsafe extern "C" {
        // SAFETY（宣言そのものの妥当性）: `int socket(int domain, int type, int protocol)`。制御チャネルの
        // non-blocking connect だけに使う（#2058・REPAIR-5）。
        fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
        // SAFETY（宣言そのものの妥当性）: `int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`
        // （`socklen_t` は Linux で u32）。
        fn connect(fd: i32, addr: *const std::ffi::c_void, addrlen: u32) -> i32;
        // SAFETY（宣言そのものの妥当性）: `int clock_gettime(clockid_t clk_id, struct timespec *tp)`
        // （`clockid_t` は i32）。LP64 の `struct timespec` は `time_t`・`long` がともに 8 バイト。
        fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32;
    }

    /// `struct timespec`（LP64 の Linux。`time_t` と `long` はともに i64）。本モジュールは LP64 でのみ
    /// コンパイルされ、大きさはコンパイル時と単体テストが固定する。
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }

    /// `struct sockaddr_un`（`sa_family_t` は u16、`sun_path` は 108 バイト。大きさ 110）。
    #[repr(C)]
    struct SockaddrUn {
        sun_family: u16,
        sun_path: [u8; 108],
    }

    // レイアウトのずれはコンパイル時に検出する（推測したレイアウトで syscall しない）。
    const _: () = assert!(std::mem::size_of::<Timespec>() == 16);
    const _: () = assert!(std::mem::size_of::<SockaddrUn>() == 110);

    const AF_UNIX: i32 = 1;
    const SOCK_STREAM: i32 = 1;
    /// asm-generic の値（x86_64・aarch64 で共通）: `O_NONBLOCK`（0o4000）と `O_CLOEXEC`（0o2000000）。
    const SOCK_NONBLOCK: i32 = 0o4000;
    const SOCK_CLOEXEC: i32 = 0o2_000_000;
    /// `CLOCK_MONOTONIC`（include/uapi/linux/time.h）。`std::time::Instant` と同じ時計で、同一ホストの
    /// プロセス間で比較できる。
    const CLOCK_MONOTONIC: i32 = 1;

    /// 検証済み（非空・NUL なし・108 バイト未満）のパスバイト列へ non-blocking で 1 回接続する。
    pub(super) fn connect_bytes(bytes: &[u8]) -> io::Result<UnixStream> {
        let mut addr = SockaddrUn {
            sun_family: 0,
            sun_path: [0u8; 108],
        };
        addr.sun_family = u16::try_from(AF_UNIX).map_err(|_| io::Error::from_raw_os_error(22))?;
        for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
            *dst = *src;
        }
        // SAFETY: 引数は整数のみ。成功時の戻り値は新規に作られた所有権のある fd。本モジュールは LP64 の
        // x86_64 / aarch64 でのみコンパイルされる。
        let fd = unsafe { socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0) };
        check(i64::from(fd))?;
        // SAFETY: `fd` は直前の `socket(2)` が返した有効な fd で、他に所有者がいない。`OwnedFd` が drop で閉じる。
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let len = u32::try_from(std::mem::size_of::<SockaddrUn>())
            .map_err(|_| io::Error::from_raw_os_error(22))?;
        loop {
            // SAFETY: `owned` は開いている fd。`addr` は `#[repr(C)]` の `sockaddr_un`（コンパイル時に 110 バイトを
            // 固定）で、`len` はその大きさ。いずれもこの関数のスタック上の値で呼び出しの間有効。カーネルは読むだけ。
            let rc = unsafe { connect(owned.as_raw_fd(), (&raw const addr).cast(), len) };
            match check(i64::from(rc)) {
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        let stream = UnixStream::from(owned);
        stream.set_nonblocking(false)?;
        Ok(stream)
    }

    pub(super) fn monotonic_now_ns() -> io::Result<u64> {
        let mut ts = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` は `#[repr(C)]` の 16 バイト（コンパイル時に固定）で、呼び出しの間有効かつ排他的。
        // カーネルは `ts` に書くだけ。本モジュールは LP64 の x86_64 / aarch64 でのみコンパイルされる。
        let rc = unsafe { clock_gettime(CLOCK_MONOTONIC, &raw mut ts) };
        check(i64::from(rc))?;
        let secs = u64::try_from(ts.tv_sec).map_err(|_| io::Error::from_raw_os_error(22))?;
        let nanos = u64::try_from(ts.tv_nsec).map_err(|_| io::Error::from_raw_os_error(22))?;
        secs.checked_mul(1_000_000_000)
            .and_then(|v| v.checked_add(nanos))
            .ok_or_else(|| io::Error::from_raw_os_error(22))
    }

    #[cfg(test)]
    pub(super) fn layout_sizes() -> (usize, usize) {
        (
            std::mem::size_of::<Timespec>(),
            std::mem::size_of::<SockaddrUn>(),
        )
    }

    /// 制御チャネル用 FFI と `libc` の機械照合（親の `libc_abi` と同じ方針。#1840。コンパイル時評価のみ）。
    #[cfg(test)]
    mod libc_abi {
        use super::*;
        use std::mem::{align_of, offset_of, size_of};

        const _: () = {
            assert!(AF_UNIX == libc::AF_UNIX);
            assert!(SOCK_STREAM == libc::SOCK_STREAM);
            assert!(SOCK_NONBLOCK == libc::SOCK_NONBLOCK);
            assert!(SOCK_CLOEXEC == libc::SOCK_CLOEXEC);
            assert!(CLOCK_MONOTONIC == libc::CLOCK_MONOTONIC);
            // Timespec（LP64 の struct timespec）。
            assert!(size_of::<Timespec>() == size_of::<libc::timespec>());
            assert!(align_of::<Timespec>() == align_of::<libc::timespec>());
            assert!(offset_of!(Timespec, tv_sec) == offset_of!(libc::timespec, tv_sec));
            assert!(offset_of!(Timespec, tv_nsec) == offset_of!(libc::timespec, tv_nsec));
            assert!(size_of::<i64>() == size_of::<libc::time_t>());
            assert!(size_of::<i64>() == size_of::<libc::c_long>());
            // SockaddrUn。自前の sun_path は u8 で、x86_64 の c_char（i8）と符号が違う。バイト列としてしか使わないため
            // 大きさとオフセットで照合する。
            assert!(size_of::<SockaddrUn>() == size_of::<libc::sockaddr_un>());
            assert!(align_of::<SockaddrUn>() == align_of::<libc::sockaddr_un>());
            assert!(
                offset_of!(SockaddrUn, sun_family) == offset_of!(libc::sockaddr_un, sun_family)
            );
            assert!(offset_of!(SockaddrUn, sun_path) == offset_of!(libc::sockaddr_un, sun_path));
            assert!(size_of::<u16>() == size_of::<libc::sa_family_t>());
            assert!(size_of::<[u8; 108]>() == size_of::<[libc::c_char; 108]>());
        };

        const _: unsafe extern "C" fn(libc::c_int, libc::c_int, libc::c_int) -> libc::c_int =
            socket;
        const _: unsafe extern "C" fn(libc::c_int, libc::c_int, libc::c_int) -> libc::c_int =
            libc::socket;
        // connect の第 2 引数は自前が不透明ポインタ（c_void）、libc は sockaddr を指すポインタ。どちらも同じ幅の
        // データポインタで ABI は同じ。渡す SockaddrUn のレイアウトは上で照合している。
        const _: unsafe extern "C" fn(
            libc::c_int,
            *const libc::c_void,
            libc::socklen_t,
        ) -> libc::c_int = connect;
        const _: unsafe extern "C" fn(
            libc::c_int,
            *const libc::sockaddr,
            libc::socklen_t,
        ) -> libc::c_int = libc::connect;
        const _: unsafe extern "C" fn(libc::clockid_t, *mut Timespec) -> libc::c_int =
            clock_gettime;
        const _: unsafe extern "C" fn(libc::clockid_t, *mut libc::timespec) -> libc::c_int =
            libc::clock_gettime;
    }
}

/// LP64 でない（または x86_64 / aarch64 でない）ターゲットのフォールバック。構造体レイアウトを推測せず
/// `Unsupported` を返す（fail-closed。#2140・REPAIR-5）。
#[cfg(not(any(
    all(target_arch = "x86_64", target_pointer_width = "64"),
    all(target_arch = "aarch64", target_pointer_width = "64")
)))]
mod control_ffi {
    use std::io;
    use std::os::unix::net::UnixStream;

    /// `pre_exec` からは呼ばれない（fork 後の経路ではない）ため、メッセージ付きでヒープを確保してよい（#3313）。
    fn unsupported_control() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "control channel syscalls are not supported on this architecture",
        )
    }

    pub(super) fn connect_bytes(_bytes: &[u8]) -> io::Result<UnixStream> {
        Err(unsupported_control())
    }

    pub(super) fn monotonic_now_ns() -> io::Result<u64> {
        Err(unsupported_control())
    }
}

/// UNIX ドメインソケットへ non-blocking で 1 回だけ接続を試みる（制御チャネルのクライアント。#2058・REPAIR-5）。
///
/// `UnixStream::connect` は相手の listen backlog が満杯だと無期限にブロックし、期限で打ち切れない。ここでは
/// `SOCK_NONBLOCK` のソケットで `connect(2)` を 1 回呼び、backlog 満杯は `WouldBlock`（`EAGAIN`）で即座に返す。
/// 呼び出し元が絶対期限まで間隔を置いて再試行し、期限で自分の fd を閉じる（作業スレッドも fd も残らない）。
/// 成功時は blocking に戻した `UnixStream` を返す。`NotFound`（`ENOENT`）・`ConnectionRefused` はそのまま返す。
/// パスが空（全 0 の `sun_path` は abstract namespace の名前と解釈されうる）・`sun_path`（108 バイト、終端 NUL を
/// 含む）に収まらない・NUL を含む場合は、syscall より前に `InvalidInput`。LP64 の x86_64 / aarch64 以外は
/// `Unsupported`（#2140）。
pub(crate) fn connect_unix_nonblocking(path: &Path) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    // 終端 NUL のために 1 バイト残す。
    if bytes.is_empty() || bytes.len() >= 108 || bytes.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    control_ffi::connect_bytes(bytes)
}

/// `CLOCK_MONOTONIC` の現在値（ナノ秒）。制御チャネルの絶対期限の基準（同一ホストの別プロセスと比較できる。
/// #2058・REPAIR-5）。負の値・桁あふれは `EINVAL`。LP64 の x86_64 / aarch64 以外は `Unsupported`（#2140）。
pub(crate) fn monotonic_now_ns() -> io::Result<u64> {
    control_ffi::monotonic_now_ns()
}

/// 新しいセッションを作り、呼び出しプロセスをそのリーダー兼新しいプロセスグループのリーダーにする（`setsid(2)`）。
/// 制御端末は外れる。SUP-14 の要素 (B)（pty 非経由の起動。TASK-171.2・#537）で、`privilege::detach_session` が
/// ランチャーの入口で呼ぶ。既にプロセスグループのリーダーなら `EPERM`（呼び出し元が扱う）。
pub(crate) fn new_session() -> io::Result<()> {
    // SAFETY: 引数もポインタも無い。影響は呼び出しプロセスのセッション・プロセスグループ・制御端末の関係だけで、
    // メモリ安全性に影響しない。単一スレッドである必要は無い。
    let rc = unsafe { setsid() };
    check(i64::from(rc)).map(|_| ())
}

/// 自前の FFI 宣言と `libc` の機械照合（コンパイル時の `const` 評価のみ。関数は呼ばず `unsafe` を足さない。
/// #1840・#1837・#1318・MVM-4・REPAIR-7・REPAIR-12。方式は docs/design/ffi-libc-check.md）。
///
/// `libc` は dev-dependencies だけ（`libc` =0.2.189）で、製品コードの依存グラフは変わらない。
/// 対象は本モジュールが対応する LP64 の x86_64・aarch64 に限る（`syscall(i64, ...)` が LP64 前提のため、宣言自体も同じ cfg に限った。#3100）。
/// 他の構成は `arch` が `None` を返す `Unsupported` の fail-closed で、照合する値が無い。
/// `arch` の値と `libc` の値はどちらもターゲットの cfg で決まるため、同じ cfg の下で比べる（他ターゲットの値は流用しない）。
///
/// 対象外（`libc` 0.2.189 に対応物が無い）:
/// - `LINUX_CAPABILITY_VERSION_3`・`CapUserHeader`・`CapUserData`: カーネルの include/uapi/linux/capability.h の
///   `_LINUX_CAPABILITY_VERSION_3`・`struct __user_cap_header_struct`・`__user_cap_data_struct`。実行時には
///   `/proc/thread-self/status` との一致を見る単体テストが `capget` の結果を照合する。
/// - `XATTR_NAME_CAPS`: include/uapi/linux/xattr.h の `XATTR_NAME_CAPS`。
/// - `FILE_CAPS_BUF_LEN`: include/uapi/linux/capability.h の `XATTR_CAPS_SZ_3`（24）に対応する。
/// - `MAX_EXEC_VECTOR`・`CAP_NUMBER_LIMIT`: FFI ではなく自前の上限。
/// - `arch` の非 LP64 系統: 値が `None` で照合する値が無い。
///
/// 関数内のローカル定数やリテラルで書いた errno 等は項目として参照できないため、`libc` の値をリテラルと比べる。
#[cfg(all(
    test,
    any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    )
))]
mod libc_abi {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    const fn opt_i64_eq(o: Option<i64>, v: i64) -> bool {
        match o {
            Some(x) => x == v,
            None => false,
        }
    }
    const fn opt_i32_eq(o: Option<i32>, v: libc::c_int) -> bool {
        match o {
            Some(x) => x == v,
            None => false,
        }
    }
    /// `c_int` を負でないことを確かめて `u64` へ広げる（符号の食い違いを見逃さない）。
    const fn widen_u64(v: libc::c_int) -> u64 {
        assert!(v >= 0);
        v as u64
    }
    /// `c_int` を `i64` へ広げる（拡幅で切り詰めは起きない）。
    const fn widen_i64(v: libc::c_int) -> i64 {
        v as i64
    }

    const _: () = {
        // arch（syscall 番号・open フラグ・ソケット定数）。
        assert!(opt_i64_eq(arch::SYS_CAPGET, libc::SYS_capget));
        assert!(opt_i64_eq(arch::SYS_CAPSET, libc::SYS_capset));
        assert!(opt_i64_eq(arch::SYS_EXECVEAT, libc::SYS_execveat));
        assert!(opt_i32_eq(arch::O_DIRECTORY, libc::O_DIRECTORY));
        assert!(opt_i32_eq(arch::O_NOFOLLOW, libc::O_NOFOLLOW));
        assert!(opt_i32_eq(arch::SOL_SOCKET, libc::SOL_SOCKET));
        assert!(opt_i32_eq(arch::SO_PEERCRED, libc::SO_PEERCRED));
        // errno。
        assert!(EPERM == libc::EPERM);
        assert!(ENODATA == libc::ENODATA);
        assert!(EOPNOTSUPP == libc::EOPNOTSUPP);
        assert!(ERANGE == libc::ERANGE);
        // prctl。
        assert!(PR_SET_DUMPABLE == libc::PR_SET_DUMPABLE);
        assert!(PR_GET_KEEPCAPS == libc::PR_GET_KEEPCAPS);
        assert!(PR_SET_KEEPCAPS == libc::PR_SET_KEEPCAPS);
        assert!(PR_CAPBSET_DROP == libc::PR_CAPBSET_DROP);
        assert!(PR_CAP_AMBIENT == libc::PR_CAP_AMBIENT);
        assert!(PR_CAP_AMBIENT_RAISE == widen_u64(libc::PR_CAP_AMBIENT_RAISE));
        assert!(PR_CAP_AMBIENT_CLEAR_ALL == widen_u64(libc::PR_CAP_AMBIENT_CLEAR_ALL));
        // そのほか。
        assert!(AT_EMPTY_PATH == widen_i64(libc::AT_EMPTY_PATH));
        assert!(SYS_CLOSE_RANGE == libc::SYS_close_range);
        assert!(F_GETFD == libc::F_GETFD);
        // 関数内のローカル定数・リテラルの errno / シグナル（項目として参照できないため libc の値を固定する）。
        assert!(libc::SIGKILL == 9); // kill_process_group
        assert!(libc::EINVAL == 22); // check_cap_number ほか
        assert!(libc::ENOSYS == 38); // close_fds_from の縮退の判定
        assert!(libc::EBADF == 9); // 試験 sup14_task1719_execveat_bad_fd_returns_ebadf
    };

    // Ucred（struct ucred）。
    const _: () = {
        assert!(size_of::<Ucred>() == size_of::<libc::ucred>());
        assert!(align_of::<Ucred>() == align_of::<libc::ucred>());
        assert!(offset_of!(Ucred, pid) == offset_of!(libc::ucred, pid));
        assert!(offset_of!(Ucred, uid) == offset_of!(libc::ucred, uid));
        assert!(offset_of!(Ucred, gid) == offset_of!(libc::ucred, gid));
        assert!(size_of::<i32>() == size_of::<libc::pid_t>());
        assert!(size_of::<u32>() == size_of::<libc::uid_t>());
        assert!(size_of::<u32>() == size_of::<libc::gid_t>());
    };

    // 関数の型（自前と libc を同じ型の const に代入する。食い違えば型エラー）。
    const _: unsafe extern "C" fn(libc::c_int, ...) -> libc::c_int = prctl;
    const _: unsafe extern "C" fn(libc::c_int, ...) -> libc::c_int = libc::prctl;
    const _: unsafe extern "C" fn(libc::c_long, ...) -> libc::c_long = syscall;
    const _: unsafe extern "C" fn(libc::c_long, ...) -> libc::c_long = libc::syscall;
    const _: unsafe extern "C" fn(libc::c_int, libc::c_int, ...) -> libc::c_int = fcntl;
    const _: unsafe extern "C" fn(libc::c_int, libc::c_int, ...) -> libc::c_int = libc::fcntl;
    const _: unsafe extern "C" fn(libc::size_t, *const libc::gid_t) -> libc::c_int = setgroups;
    const _: unsafe extern "C" fn(libc::size_t, *const libc::gid_t) -> libc::c_int =
        libc::setgroups;
    const _: unsafe extern "C" fn(libc::gid_t, libc::gid_t, libc::gid_t) -> libc::c_int = setresgid;
    const _: unsafe extern "C" fn(libc::gid_t, libc::gid_t, libc::gid_t) -> libc::c_int =
        libc::setresgid;
    const _: unsafe extern "C" fn(libc::uid_t, libc::uid_t, libc::uid_t) -> libc::c_int = setresuid;
    const _: unsafe extern "C" fn(libc::uid_t, libc::uid_t, libc::uid_t) -> libc::c_int =
        libc::setresuid;
    const _: unsafe extern "C" fn(libc::c_int) -> libc::c_int = close;
    const _: unsafe extern "C" fn(libc::c_int) -> libc::c_int = libc::close;
    const _: unsafe extern "C" fn() -> libc::pid_t = setsid;
    const _: unsafe extern "C" fn() -> libc::pid_t = libc::setsid;
    const _: unsafe extern "C" fn(libc::pid_t, libc::c_int) -> libc::c_int = kill;
    const _: unsafe extern "C" fn(libc::pid_t, libc::c_int) -> libc::c_int = libc::kill;
    const _: unsafe extern "C" fn(
        libc::c_int,
        libc::c_int,
        libc::c_int,
        *mut libc::c_void,
        *mut libc::socklen_t,
    ) -> libc::c_int = getsockopt;
    const _: unsafe extern "C" fn(
        libc::c_int,
        libc::c_int,
        libc::c_int,
        *mut libc::c_void,
        *mut libc::socklen_t,
    ) -> libc::c_int = libc::getsockopt;
    const _: unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        *mut libc::c_void,
        libc::size_t,
    ) -> libc::ssize_t = lgetxattr;
    const _: unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        *mut libc::c_void,
        libc::size_t,
    ) -> libc::ssize_t = libc::lgetxattr;
    // 試験 repair5_connect_unix_nonblocking_returns_wouldblock_when_backlog_is_full の関数内宣言 `listen` は
    // 項目として参照できないため、試験に書いた型 `unsafe extern "C" fn(i32, i32) -> i32` へ libc を代入して照合する。
    const _: unsafe extern "C" fn(i32, i32) -> i32 = libc::listen;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SUP-14・#2599: errno の値（x86_64・aarch64 共通）と、実ファイルの `security.capability` 読み取り。
    #[test]
    fn sup14_xattr_errno_constants_and_read() {
        assert_eq!((ENODATA, EOPNOTSUPP, ERANGE), (61, 95, 34));
        assert_eq!(FILE_CAPS_BUF_LEN, 24);
        let dir = std::env::temp_dir().join(format!("fc-xattr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let f = dir.join("plain");
        std::fs::write(&f, b"x").expect("write");
        let err = read_security_capability(&f).expect_err("no file capability");
        assert!(
            matches!(err.raw_os_error(), Some(ENODATA | EOPNOTSUPP)),
            "{err:?}"
        );
        let bad = read_security_capability(Path::new("/nonexistent/fc-xattr")).expect_err("absent");
        assert_eq!(bad.kind(), io::ErrorKind::NotFound);
        let nul = read_security_capability(Path::new("a\0b")).expect_err("nul");
        assert_eq!(nul.kind(), io::ErrorKind::InvalidInput);
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    /// SUP-14・#2426: `EPERM` の値と、`io::Error` 上で `PermissionDenied` になることを固定する。
    #[test]
    fn sup14_eperm_constant_is_one_and_permission_denied() {
        assert_eq!(EPERM, 1);
        assert_eq!(
            io::Error::from_raw_os_error(EPERM).kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    /// SUP-14・TASK-171.1.3: prctl の番号と capability ABI の値を固定する（include/uapi の値との照合）。
    /// 定数は LP64 の x86_64・aarch64 に限って宣言するため、試験も同じ対象に閉じる（#3202）。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn sup14_task171_1_3_constants_are_fixed() {
        assert_eq!(PR_GET_KEEPCAPS, 7);
        assert_eq!(PR_SET_KEEPCAPS, 8);
        assert_eq!(PR_CAPBSET_DROP, 24);
        assert_eq!(PR_CAP_AMBIENT, 47);
        assert_eq!(PR_CAP_AMBIENT_RAISE, 2);
        assert_eq!(PR_CAP_AMBIENT_CLEAR_ALL, 4);
    }

    /// SUP-6・MVM-4・#3100: capability ABI のバージョン値（`syscall` 経路は LP64 限定）。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn sup14_task171_1_3_capability_version_is_fixed() {
        assert_eq!(LINUX_CAPABILITY_VERSION_3, 0x2008_0522);
    }

    /// REPAIR-5・SUP-1: 制御チャネル用 FFI 構造体の大きさと時計の単調性を固定する。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn repair5_sup1_control_ffi_layout_and_clock() {
        assert_eq!(control_ffi::layout_sizes(), (16, 110));
        let a = monotonic_now_ns().unwrap();
        let b = monotonic_now_ns().unwrap();
        assert!(b >= a && a > 0);
    }

    /// REPAIR-5: 長すぎる・NUL を含むパスは接続を試みず `InvalidInput`、存在しないパスは `NotFound`。
    #[test]
    fn repair5_connect_unix_nonblocking_rejects_bad_paths() {
        let long = std::path::PathBuf::from("/".repeat(120));
        assert_eq!(
            connect_unix_nonblocking(&long).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        let nul = std::path::PathBuf::from("/tmp/a\0b");
        assert_eq!(
            connect_unix_nonblocking(&nul).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        // #2140: 空パスは abstract namespace と解釈されうるため syscall 前に拒否する。
        assert_eq!(
            connect_unix_nonblocking(Path::new("")).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    /// REPAIR-5: 存在しないパスは `NotFound`（実際に connect する LP64 のみ）。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn repair5_connect_unix_nonblocking_missing_path_is_not_found() {
        let missing = std::path::PathBuf::from("/nonexistent-fandhe-dir/sock");
        assert_eq!(
            connect_unix_nonblocking(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    /// #2140・REPAIR-5: LP64 でないターゲットでは制御チャネルの syscall を発行せず `Unsupported`。
    #[cfg(not(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    )))]
    #[test]
    fn repair5_control_ffi_is_unsupported_off_lp64() {
        assert_eq!(
            monotonic_now_ns().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            connect_unix_nonblocking(Path::new("/tmp/x"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }

    /// 試験用の一時ディレクトリ（0700 の排他作成・drop で削除。#2140）。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    struct TempDir(std::path::PathBuf);

    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    impl TempDir {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt as _;
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            for attempt in 0..16u32 {
                let path = std::env::temp_dir()
                    .join(format!("fc-bl-{}-{nanos}-{attempt}", std::process::id()));
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => panic!("create temp dir: {e}"),
                }
            }
            panic!("could not create a unique temp dir");
        }
    }

    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// REPAIR-5: listen backlog が満杯の相手へは、ブロックせず `WouldBlock` で即座に戻る。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn repair5_connect_unix_nonblocking_returns_wouldblock_when_backlog_is_full() {
        let dir = TempDir::new();
        let path = dir.0.join("s");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        // 既に listen 中のソケットへ `listen(2)` を再度呼ぶと backlog だけが更新される。0 にして早く満杯にする。
        unsafe extern "C" {
            // SAFETY（宣言そのものの妥当性）: `int listen(int sockfd, int backlog)`。
            fn listen(fd: i32, backlog: i32) -> i32;
        }
        // SAFETY: `_listener` は開いている listen 中のソケットの fd。整数引数のみ。
        let rc = unsafe { listen(std::os::fd::AsRawFd::as_raw_fd(&_listener), 0) };
        assert_eq!(rc, 0);
        let mut held = Vec::new();
        let started = std::time::Instant::now();
        let mut saw = None;
        for _ in 0..600 {
            match connect_unix_nonblocking(&path) {
                Ok(s) => held.push(s),
                Err(e) => {
                    saw = Some(e.kind());
                    break;
                }
            }
        }
        drop(held);
        assert_eq!(saw, Some(io::ErrorKind::WouldBlock));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn sup14_task171_1_3_syscall_numbers_x86_64() {
        assert_eq!(arch::SYS_CAPGET, Some(125));
        assert_eq!(arch::SYS_CAPSET, Some(126));
    }

    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    #[test]
    fn sup14_task171_1_3_syscall_numbers_aarch64() {
        assert_eq!(arch::SYS_CAPGET, Some(90));
        assert_eq!(arch::SYS_CAPSET, Some(91));
    }

    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn sup14_task171_1_3_split_join_roundtrip() {
        assert_eq!(split(0x0000_0000_2820_1122), [0x2820_1122, 0]);
        assert_eq!(split(0x0000_0001_0000_0002), [2, 1]);
        assert_eq!(join(0x2820_1122, 1), 0x0000_0001_2820_1122);
    }

    #[test]
    fn sup14_task171_1_3_out_of_range_capability_is_einval() {
        let e = cap_bounding_drop(64).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(22));
        let e = cap_ambient_raise(255).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(22));
    }

    /// 状態を変えない読み取りだけを実際に呼ぶ。keepcaps は既定で 0、capget は `/proc/self/status` と一致する。
    #[test]
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    fn sup14_task171_1_3_reads_match_proc_status() {
        assert!(!get_keep_caps().unwrap());
        // libtest はテストごとにスレッドを作るため、`/proc/thread-self/status` が呼び出しスレッドの値になる。
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        let field = |name: &str| -> u64 {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
                .unwrap()
        };
        let caps = cap_get_thread().unwrap();
        assert_eq!(caps.permitted, field("CapPrm:"));
        assert_eq!(caps.effective, field("CapEff:"));
        assert_eq!(caps.inheritable, field("CapInh:"));
    }

    /// SUP-14・TASK-171 追補(#1719): execveat / close_range / dumpable の番号と値を固定する。
    #[test]
    fn sup14_task1719_launcher_constants_are_fixed() {
        assert_eq!(PR_SET_DUMPABLE, 4);
        assert_eq!(F_GETFD, 1);
    }

    /// SUP-6・MVM-4・#3100: `syscall` 経由の定数は LP64 の x86_64・aarch64 だけで存在する。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn sup14_task1719_syscall_constants_are_fixed() {
        assert_eq!(AT_EMPTY_PATH, 0x1000);
        assert_eq!(SYS_CLOSE_RANGE, 436);
    }

    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn sup14_task1719_execveat_number_x86_64() {
        assert_eq!(arch::SYS_EXECVEAT, Some(322));
    }

    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    #[test]
    fn sup14_task1719_execveat_number_aarch64() {
        assert_eq!(arch::SYS_EXECVEAT, Some(281));
    }

    /// SEC-1・SUP-1・#2058: `struct ucred` の大きさと制御チャネル用の ABI 定数を固定する。
    #[test]
    fn sup1_sec1_task2058_ucred_layout_and_constants() {
        assert_eq!(std::mem::size_of::<Ucred>(), 12);
        assert_eq!(std::mem::align_of::<Ucred>(), 4);
        assert_eq!(arch::SOL_SOCKET, Some(1));
        assert_eq!(arch::SO_PEERCRED, Some(17));
    }

    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn sup1_sec1_task2058_open_flags_x86_64() {
        assert_eq!(open_dir_nofollow_flags().unwrap(), 0o200000 | 0o400000);
    }

    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    #[test]
    fn sup1_sec1_task2058_open_flags_aarch64() {
        assert_eq!(open_dir_nofollow_flags().unwrap(), 0o40000 | 0o100000);
    }

    /// socketpair 相手（自プロセス）の pid・uid が `/proc/self/status` と一致する。
    #[test]
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    fn sup1_sec1_task2058_peer_credentials_match_self() {
        use std::os::fd::AsFd as _;
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let cred = peer_credentials(a.as_fd()).unwrap();
        assert_eq!(cred.pid, std::process::id());
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let uid_line = status.lines().find(|l| l.starts_with("Uid:")).unwrap();
        let euid: u32 = uid_line.split_whitespace().nth(2).unwrap().parse().unwrap();
        assert_eq!(cred.uid, euid);
    }

    /// 存在しない fd への execveat は exec せず EBADF で戻る。
    #[test]
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    fn sup14_task1719_execveat_bad_fd_returns_ebadf() {
        let argv = [CString::new("x").unwrap()];
        let e = execveat_fd(i32::MAX, &argv, &[]).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(9));
    }

    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn sup14_task1719_execveat_rejects_oversized_vectors() {
        let argv = vec![CString::new("x").unwrap(); MAX_EXEC_VECTOR + 1];
        let e = execveat_fd(i32::MAX, &argv, &[]).unwrap_err();
        // LP64 の対応 arch 限定の試験。EINVAL で戻り、exec しない。
        assert_eq!(e.raw_os_error(), Some(22));
    }

    #[test]
    fn sup14_task1719_fd_is_open_and_close_range() {
        use std::os::fd::AsRawFd;
        let f = std::fs::File::open("/proc/self/status").unwrap();
        let fd = f.as_raw_fd();
        assert!(fd_is_open(fd));
        assert!(!fd_is_open(i32::MAX));
        // 閉じる範囲に fd を含めない（他テストの fd を壊さないよう、自分の fd より大きい未使用範囲を指定する）。
        close_fds_from(u32::try_from(fd).unwrap() + 10_000).unwrap();
        assert!(fd_is_open(fd));
        // /proc フォールバックも、範囲外なら何も閉じない。
        close_fds_from_proc(u32::try_from(fd).unwrap() + 10_000).unwrap();
        assert!(fd_is_open(fd));
    }
}
