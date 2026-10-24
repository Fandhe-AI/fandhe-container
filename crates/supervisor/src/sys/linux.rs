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
    #[cfg(test)]
    pub(super) const SYS_CAPGET: Option<i64> = None;
    pub(super) const SYS_CAPSET: Option<i64> = None;
    pub(super) const SYS_EXECVEAT: Option<i64> = None;
    pub(super) const O_DIRECTORY: Option<i32> = None;
    pub(super) const O_NOFOLLOW: Option<i32> = None;
    pub(super) const SOL_SOCKET: Option<i32> = None;
    pub(super) const SO_PEERCRED: Option<i32> = None;
}

/// `EPERM`（include/uapi/asm-generic/errno-base.h の 1。x86_64・aarch64 で共通）。`privilege` が `setsid(2)` の
/// 「プロセスグループのリーダー」と capability 系 syscall の権限不足を見分けるのに使う（SUP-14・#2426）。
/// この crate は `libc` との機械照合が未導入のため、値は下の単体テストで具体値を照合する。
pub(crate) const EPERM: i32 = 1;

/// include/uapi/linux/prctl.h の値。
const PR_SET_DUMPABLE: i32 = 4;
const PR_GET_KEEPCAPS: i32 = 7;
const PR_SET_KEEPCAPS: i32 = 8;
const PR_CAPBSET_DROP: i32 = 24;
const PR_CAP_AMBIENT: i32 = 47;
const PR_CAP_AMBIENT_RAISE: u64 = 2;
const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;
/// include/uapi/linux/capability.h の `_LINUX_CAPABILITY_VERSION_3`（2 語・64 bit 形式）。
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
/// `execveat(2)` の `AT_EMPTY_PATH`（include/uapi/linux/fcntl.h）。pathname が空のとき dirfd 自体を実行対象にする。
const AT_EMPTY_PATH: i64 = 0x1000;
/// `close_range(2)` の syscall 番号（全 arch 共通の統一番号表の値。Linux 5.9 以降）。
const SYS_CLOSE_RANGE: i64 = 436;
/// `fcntl(2)` の `F_GETFD`（fd が開いているかの確認に使う）。
const F_GETFD: i32 = 1;
/// execveat に渡す argv / envp の要素数の上限（無制限確保の防止）。
const MAX_EXEC_VECTOR: usize = 4096;
/// capability 番号の上限（排他）。カーネルの `CAP_LAST_CAP` は 63 以下で、64 以上は ambient / bounding に渡さない。
const CAP_NUMBER_LIMIT: u8 = 64;

unsafe extern "C" {
    // SAFETY（宣言そのものの妥当性）: `int prctl(int option, ...)`（glibc / musl）。可変長引数として宣言する
    // （非可変長で宣言して呼ぶと、可変長引数の渡し方が異なる ABI で未定義動作になる）。可変長部は
    // `unsigned long`（LP64 で u64）に合わせて渡す。
    fn prctl(option: i32, ...) -> i32;
    // SAFETY（宣言そのものの妥当性）: `long syscall(long number, ...)`（glibc / musl。LP64 で `long` は i64）。
    fn syscall(number: i64, ...) -> i64;
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
    // `libc` との機械照合はこの crate では未導入（dev-dependencies に `libc` が無い。coding-rust.md「照合が未導入の
    // crate には、その crate の実装 issue が済んでから効く」）。#537 で追加。
    fn setsid() -> i32;
    // SAFETY（宣言そのものの妥当性）: `int kill(pid_t pid, int sig)`（`pid_t` は Linux で i32）。整数引数のみ。
    // `libc` との機械照合はこの crate では未導入（上の `setsid` と同じ理由）。
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
    // doctor の特権ランチャー診断（#2599）の `security.capability` 読み取りだけに使う。`libc` との機械照合は
    // この crate では未導入（上の `setsid` と同じ理由）。
    fn lgetxattr(
        path: *const std::ffi::c_char,
        name: *const std::ffi::c_char,
        value: *mut std::ffi::c_void,
        size: usize,
    ) -> isize;
}

/// `struct ucred`（`SO_PEERCRED` の結果。include/uapi/asm-generic/socket.h・`<sys/socket.h>`）。
/// `libc` との機械照合はこの crate では未導入（dev-dependencies に `libc` が無い。coding-rust.md「照合が未導入の
/// crate」）。レイアウトは pid_t(i32)・uid_t(u32)・gid_t(u32) の 12 バイトで、単体テストが大きさを固定する。
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

/// 呼び出したスレッドの capability（ビット位置は capability 番号。v3 の 2 語を 64 bit に束ねた値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ThreadCaps {
    pub(crate) effective: u64,
    pub(crate) permitted: u64,
    pub(crate) inheritable: u64,
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "capability syscalls are not supported on this architecture",
    )
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

fn split(v: u64) -> [u32; 2] {
    // 下位 32 bit と上位 32 bit への分割（意図的な切り詰め）。
    [(v & 0xffff_ffff) as u32, (v >> 32) as u32]
}

#[cfg(test)]
fn join(lo: u32, hi: u32) -> u64 {
    u64::from(lo) | (u64::from(hi) << 32)
}

/// 呼び出したスレッドの effective / permitted / inheritable を読む（pid 0 の `capget(2)`）。
///
/// 単体テストで `capset` のレイアウトと `/proc/self/status` の整合を照合するために使う。カーネルが v3 以外を
/// 返したら `EINVAL` として fail-closed にする。
#[cfg(test)]
pub(crate) fn cap_get_thread() -> io::Result<ThreadCaps> {
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
    // 確保・ロック・親との共有状態の操作をしない（async-signal-safe）。影響は子の ambient 集合の縮小のみ。
    unsafe {
        cmd.pre_exec(cap_ambient_clear_all);
    }
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
        // SAFETY（宣言そのものの妥当性）: `ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)`
        // （`ssize_t` は LP64 で isize）。制御チャネルの exec 用 pidfd の受け渡し（`SCM_RIGHTS`。#2626）だけに使う。
        fn sendmsg(fd: i32, msg: *const Msghdr, flags: i32) -> isize;
        // SAFETY（宣言そのものの妥当性）: `ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)`。同上。
        fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;
    }

    /// `struct iovec`（LP64 で 16 バイト）。
    // フィールドはカーネルがポインタ越しに読み書きするもので、Rust からは読まない（dead_code の誤検出を避ける）。
    #[repr(C)]
    #[allow(dead_code)]
    struct Iovec {
        iov_base: *mut std::ffi::c_void,
        iov_len: usize,
    }

    /// `struct msghdr`（glibc / musl の LP64 で 56 バイト。カーネルの `struct user_msghdr` と同じ配置）。
    #[repr(C)]
    #[allow(dead_code)]
    struct Msghdr {
        msg_name: *mut std::ffi::c_void,
        msg_namelen: u32,
        msg_iov: *mut Iovec,
        msg_iovlen: usize,
        msg_control: *mut std::ffi::c_void,
        msg_controllen: usize,
        msg_flags: i32,
    }

    /// `struct cmsghdr`（LP64 で 16 バイト。データは 8 バイト境界から始まる）。
    #[repr(C)]
    #[allow(dead_code)]
    struct Cmsghdr {
        cmsg_len: usize,
        cmsg_level: i32,
        cmsg_type: i32,
    }

    /// 送信用の制御メッセージ（`SCM_RIGHTS` で fd 1 本。`CMSG_SPACE(4)` = 24 バイト、8 バイト整列）。
    #[repr(C)]
    #[allow(dead_code)]
    struct ControlOne {
        hdr: Cmsghdr,
        fd: i32,
        pad: i32,
    }

    /// 受信用の制御バッファ（`CMSG_SPACE(4 * 4)` = 32 バイト = fd 4 本分。8 バイト整列）。溢れた fd は
    /// カーネルが `MSG_CTRUNC` を立てて閉じる。
    #[repr(C, align(8))]
    struct ControlBuf([u8; RECV_CONTROL_LEN]);

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
    const _: () = assert!(std::mem::size_of::<Iovec>() == 16);
    const _: () = assert!(std::mem::size_of::<Msghdr>() == 56);
    const _: () = assert!(std::mem::size_of::<Cmsghdr>() == 16);
    const _: () = assert!(std::mem::size_of::<ControlOne>() == 24);
    const _: () = assert!(std::mem::align_of::<ControlOne>() == 8);

    /// `SOL_SOCKET`（asm-generic/socket.h。x86_64・aarch64 で共通）。
    const SOL_SOCKET: i32 = 1;
    /// `SCM_RIGHTS`（include/linux/socket.h）。
    const SCM_RIGHTS: i32 = 1;
    /// `MSG_NOSIGNAL`（0x4000。x86_64・aarch64 で共通）。
    const MSG_NOSIGNAL: i32 = 0x4000;
    /// `MSG_CMSG_CLOEXEC`（0x40000000。受け取った fd に close-on-exec を付ける）。
    const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;
    /// `MSG_CTRUNC`（制御データが切り詰められた）。
    const MSG_CTRUNC: i32 = 0x8;
    /// 受信する制御バッファの長さ。
    const RECV_CONTROL_LEN: usize = 32;
    /// cmsg のデータ部の先頭オフセット（`CMSG_LEN(0)` = ヘッダの 16 バイト）。
    const CMSG_HDR_LEN: usize = 16;

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

    /// `sock` へ `data` を送り、`fd` を `SCM_RIGHTS` で 1 本添える。送れたバイト数を返す
    /// （ストリームなので短い書き込みはあり得る。fd は最初に送れたバイトに付く。呼び出し側が残りを書く）。
    pub(super) fn send_with_fd(
        sock: std::os::fd::BorrowedFd<'_>,
        data: &[u8],
        fd: std::os::fd::BorrowedFd<'_>,
    ) -> io::Result<usize> {
        let mut control = ControlOne {
            hdr: Cmsghdr {
                // CMSG_LEN(4) = ヘッダ 16 + データ 4。
                cmsg_len: CMSG_HDR_LEN + 4,
                cmsg_level: SOL_SOCKET,
                cmsg_type: SCM_RIGHTS,
            },
            fd: fd.as_raw_fd(),
            pad: 0,
        };
        let mut iov = Iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
        let msg = Msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &raw mut iov,
            msg_iovlen: 1,
            msg_control: (&raw mut control).cast(),
            msg_controllen: std::mem::size_of::<ControlOne>(),
            msg_flags: 0,
        };
        loop {
            // SAFETY: `sock`・`fd` は借用で呼び出しの間開いている。`msg` は `#[repr(C)]` の 56 バイト（コンパイル時に固定）で、
            // `msg_iov` は 1 要素の `iov`（`data` の先頭と長さ。カーネルは読むだけ）、`msg_control` は 24 バイトの
            // `ControlOne`（8 バイト整列。`msg_controllen` はその大きさ）を指す。いずれもこの関数のスタック上の値か
            // 呼び出し元の借用で、呼び出しの間有効。`msg_name` は null・長さ 0。カーネルは `fd` の複製を受け手に作るだけで、
            // 呼び出し側の fd の所有権は動かない。本モジュールは LP64 の x86_64 / aarch64 でのみコンパイルされる。
            let rc = unsafe { sendmsg(sock.as_raw_fd(), &raw const msg, MSG_NOSIGNAL) };
            match check(rc as i64) {
                Ok(n) => return usize::try_from(n).map_err(|_| io::Error::from_raw_os_error(22)),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// `sock` から最大 `buf.len()` バイトと、添えられた `SCM_RIGHTS` の fd（最大 4 本）を 1 回の `recvmsg` で受ける。
    /// 受け取った fd は close-on-exec で、`OwnedFd` として返す（呼び出し側が不要なら drop で閉じる）。
    pub(super) fn recv_with_fds(
        sock: std::os::fd::BorrowedFd<'_>,
        buf: &mut [u8],
    ) -> io::Result<super::Received> {
        let mut control = ControlBuf([0u8; RECV_CONTROL_LEN]);
        let mut iov = Iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut msg = Msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &raw mut iov,
            msg_iovlen: 1,
            msg_control: (&raw mut control).cast(),
            msg_controllen: RECV_CONTROL_LEN,
            msg_flags: 0,
        };
        let n = loop {
            // SAFETY: `sock` は借用で呼び出しの間開いている。`msg` は `#[repr(C)]` の 56 バイトで、`msg_iov` は 1 要素の
            // `iov`（`buf` の先頭と長さ。カーネルは `buf` に最大その長さを書く）、`msg_control` は 32 バイトの
            // `ControlBuf`（8 バイト整列。`msg_controllen` はその大きさ）を指す。いずれも呼び出しの間有効かつ排他的。
            // カーネルは `msg_controllen`・`msg_flags` を更新する。本モジュールは LP64 の x86_64 / aarch64 でのみ
            // コンパイルされる。
            let rc = unsafe { recvmsg(sock.as_raw_fd(), &raw mut msg, MSG_CMSG_CLOEXEC) };
            match check(rc as i64) {
                Ok(n) => break usize::try_from(n).map_err(|_| io::Error::from_raw_os_error(22))?,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        };
        let used = msg.msg_controllen.min(RECV_CONTROL_LEN);
        let raw = control.0.get(..used).unwrap_or(&[]);
        let fds = parse_rights(raw)?
            .into_iter()
            // SAFETY: `recvmsg(2)` が呼び出しプロセスの fd 表へ新規に作った fd で、他に所有者がいない。`OwnedFd` が
            // drop で閉じる。値は `parse_rights` がカーネルの返した `SCM_RIGHTS` から読んだもの。
            .map(|raw_fd| unsafe { OwnedFd::from_raw_fd(raw_fd) })
            .collect();
        Ok(super::Received {
            len: n,
            fds,
            truncated: msg.msg_flags & MSG_CTRUNC != 0,
        })
    }

    /// 制御データのバイト列から `SCM_RIGHTS` の fd 番号を取り出す（純関数。添字アクセスをしない）。
    /// 長さの足りないヘッダ・範囲外の `cmsg_len`・4 の倍数でないデータは `InvalidData`。他の種別の cmsg は読み飛ばす。
    pub(super) fn parse_rights(control: &[u8]) -> io::Result<Vec<i32>> {
        let bad = || io::Error::from(io::ErrorKind::InvalidData);
        let mut fds = Vec::new();
        let mut pos = 0usize;
        while pos < control.len() {
            let head_end = pos.checked_add(CMSG_HDR_LEN).ok_or_else(bad)?;
            let head = control.get(pos..head_end).ok_or_else(bad)?;
            let (len_bytes, rest) = head.split_first_chunk::<8>().ok_or_else(bad)?;
            let (level_bytes, rest) = rest.split_first_chunk::<4>().ok_or_else(bad)?;
            let (type_bytes, _) = rest.split_first_chunk::<4>().ok_or_else(bad)?;
            let cmsg_len = usize::from_ne_bytes(*len_bytes);
            let level = i32::from_ne_bytes(*level_bytes);
            let kind = i32::from_ne_bytes(*type_bytes);
            let end = pos.checked_add(cmsg_len).ok_or_else(bad)?;
            if cmsg_len < CMSG_HDR_LEN || end > control.len() {
                return Err(bad());
            }
            if level == SOL_SOCKET && kind == SCM_RIGHTS {
                let data = control.get(head_end..end).ok_or_else(bad)?;
                if data.len() % 4 != 0 {
                    return Err(bad());
                }
                let (words, _) = data.as_chunks::<4>();
                for word in words {
                    fds.push(i32::from_ne_bytes(*word));
                }
            }
            // 次の cmsg は 8 バイト境界から始まる。
            pos = end.checked_add(7).ok_or_else(bad)? & !7;
        }
        Ok(fds)
    }

    #[cfg(test)]
    pub(super) fn control_constants() -> (i32, i32, i32, i32, i32) {
        (
            SOL_SOCKET,
            SCM_RIGHTS,
            MSG_NOSIGNAL,
            MSG_CMSG_CLOEXEC,
            MSG_CTRUNC,
        )
    }

    #[cfg(test)]
    pub(super) fn layout_sizes() -> (usize, usize) {
        (
            std::mem::size_of::<Timespec>(),
            std::mem::size_of::<SockaddrUn>(),
        )
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

    pub(super) fn send_with_fd(
        _sock: std::os::fd::BorrowedFd<'_>,
        _data: &[u8],
        _fd: std::os::fd::BorrowedFd<'_>,
    ) -> io::Result<usize> {
        Err(unsupported_control())
    }

    pub(super) fn recv_with_fds(
        _sock: std::os::fd::BorrowedFd<'_>,
        _buf: &mut [u8],
    ) -> io::Result<super::Received> {
        Err(unsupported_control())
    }
}

/// [`recv_with_fds`] の結果。
#[derive(Debug)]
pub(crate) struct Received {
    /// 受け取ったバイト数。
    pub(crate) len: usize,
    /// 添えられていた fd（close-on-exec。最大 4 本。drop で閉じる）。
    pub(crate) fds: Vec<std::os::fd::OwnedFd>,
    /// 制御データが切り詰められた（受け切れなかった fd はカーネルが閉じている）。
    pub(crate) truncated: bool,
}

/// `data` を送り、`fd` を `SCM_RIGHTS` で 1 本添える（`sendmsg(2)`）。制御チャネルの exec 用 pidfd の受け渡し
/// （サーバ側。#2626・SUP-6・SEC-1）。送れたバイト数を返す（短い書き込みは呼び出し側が残りを書く）。
/// LP64 の x86_64 / aarch64 以外は `Unsupported`（#2140）。
pub(crate) fn send_with_fd(
    sock: BorrowedFd<'_>,
    data: &[u8],
    fd: BorrowedFd<'_>,
) -> io::Result<usize> {
    control_ffi::send_with_fd(sock, data, fd)
}

/// 最大 `buf.len()` バイトと添えられた fd（最大 4 本）を 1 回で受ける（`recvmsg(2)`。close-on-exec）。
/// 制御チャネルの exec 用 pidfd の受け取り（クライアント側。#2626）。呼び出し側は fd の本数と `truncated` を
/// 検証し、想定外なら `fds` を drop して閉じる。LP64 の x86_64 / aarch64 以外は `Unsupported`。
pub(crate) fn recv_with_fds(sock: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Received> {
    control_ffi::recv_with_fds(sock, buf)
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

/// `PR_SET_DUMPABLE` を設定する。0 にすると ptrace attach・core dump・`/proc/<pid>/mem` 等の読み取りを
/// 同一 uid の別プロセスから受けない（昇格中の窓の防御）。
pub(crate) fn set_dumpable(on: bool) -> io::Result<()> {
    // SAFETY: 引数は整数のみでポインタを渡さない。影響は呼び出しプロセスの dumpable 属性のみ。
    let rc = unsafe { prctl(PR_SET_DUMPABLE, u64::from(on), 0u64, 0u64, 0u64) };
    check(i64::from(rc)).map(|_| ())
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
    #[test]
    fn sup14_task171_1_3_constants_are_fixed() {
        assert_eq!(PR_GET_KEEPCAPS, 7);
        assert_eq!(PR_SET_KEEPCAPS, 8);
        assert_eq!(PR_CAPBSET_DROP, 24);
        assert_eq!(PR_CAP_AMBIENT, 47);
        assert_eq!(PR_CAP_AMBIENT_RAISE, 2);
        assert_eq!(PR_CAP_AMBIENT_CLEAR_ALL, 4);
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

    /// SUP-6・SEC-1・#2626: `SCM_RIGHTS` 関連の定数は具体値で固定する（x86_64・aarch64 で共通の値。
    /// この crate は libc との機械照合が未導入のため、値は include/uapi の出典と本試験で照合する）。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn sup6_exec_handover_scm_constants() {
        assert_eq!(
            control_ffi::control_constants(),
            (1, 1, 0x4000, 0x4000_0000, 8)
        );
    }

    /// 試験用: `SCM_RIGHTS` の cmsg 1 件（ヘッダ 16 バイト + データ。8 バイトへ詰める）を組み立てる。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    fn cmsg(level: i32, kind: i32, fds: &[i32]) -> Vec<u8> {
        let len = 16 + fds.len() * 4;
        let mut v = Vec::new();
        v.extend_from_slice(&len.to_ne_bytes());
        v.extend_from_slice(&level.to_ne_bytes());
        v.extend_from_slice(&kind.to_ne_bytes());
        for fd in fds {
            v.extend_from_slice(&fd.to_ne_bytes());
        }
        while v.len() % 8 != 0 {
            v.push(0);
        }
        v
    }

    /// SUP-6・#2626: cmsg の解析は fd 番号を具体値で取り出し、壊れた入力を `InvalidData` で拒否する。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn sup6_exec_handover_parse_rights() {
        // 空・fd 1 本・fd 2 本・他種別（読み飛ばし）・種別違いの後ろの fd。
        assert_eq!(control_ffi::parse_rights(&[]).unwrap(), Vec::<i32>::new());
        assert_eq!(
            control_ffi::parse_rights(&cmsg(1, 1, &[7])).unwrap(),
            vec![7]
        );
        assert_eq!(
            control_ffi::parse_rights(&cmsg(1, 1, &[7, 9])).unwrap(),
            vec![7, 9]
        );
        let mut mixed = cmsg(1, 2, &[5]);
        mixed.extend(cmsg(1, 1, &[11]));
        assert_eq!(control_ffi::parse_rights(&mixed).unwrap(), vec![11]);
        // 短いヘッダ・cmsg_len がヘッダ未満・範囲外・データが 4 の倍数でない。
        for bad in [
            vec![0u8; 8],
            {
                let mut v = cmsg(1, 1, &[7]);
                v[..8].copy_from_slice(&8usize.to_ne_bytes());
                v
            },
            {
                let mut v = cmsg(1, 1, &[7]);
                v[..8].copy_from_slice(&1000usize.to_ne_bytes());
                v
            },
            {
                let mut v = cmsg(1, 1, &[7]);
                v[..8].copy_from_slice(&18usize.to_ne_bytes());
                v
            },
        ] {
            assert_eq!(
                control_ffi::parse_rights(&bad).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    /// SUP-6・SEC-1・#2626: fd が実際に `SCM_RIGHTS` で届く（ソケット対の上で、パイプの書き端を渡し、
    /// 受け手がそれへ書いて元のパイプの読み端で読める）。受け取った fd は close-on-exec。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn sup6_exec_handover_send_recv_roundtrip() {
        use std::io::{Read as _, Write as _};
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let (a, b) = UnixStream::pair().unwrap();
        let (mut read_end, write_end) = std::io::pipe().unwrap();
        let sent = send_with_fd(a.as_fd(), b"hello", write_end.as_fd()).unwrap();
        assert_eq!(sent, 5);
        let mut buf = [0u8; 16];
        let got = recv_with_fds(b.as_fd(), &mut buf).unwrap();
        assert_eq!(got.len, 5);
        assert_eq!(buf.get(..5), Some(&b"hello"[..]));
        assert!(!got.truncated);
        assert_eq!(got.fds.len(), 1);
        let received = got.fds.into_iter().next().unwrap();
        assert_ne!(received.as_raw_fd(), write_end.as_raw_fd());
        // FD_CLOEXEC（F_GETFD = 1, FD_CLOEXEC = 1）。
        // SAFETY: テスト用。開いている fd に対する `fcntl(F_GETFD)` は整数のみを返す。
        let flags = unsafe { fcntl(received.as_raw_fd(), F_GETFD) };
        assert_eq!(flags & 1, 1);
        let mut w = std::fs::File::from(received);
        w.write_all(b"x").unwrap();
        drop(w);
        drop(write_end);
        let mut out = String::new();
        read_end.read_to_string(&mut out).unwrap();
        assert_eq!(out, "x");
    }

    /// SUP-6・#2626: fd が添えられていない通常の送信では `fds` は空で `truncated` は偽。
    #[cfg(any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        all(target_arch = "aarch64", target_pointer_width = "64")
    ))]
    #[test]
    fn sup6_exec_handover_recv_without_fd() {
        use std::io::Write as _;
        use std::os::fd::AsFd as _;
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"abc").unwrap();
        let mut buf = [0u8; 8];
        let got = recv_with_fds(b.as_fd(), &mut buf).unwrap();
        assert_eq!((got.len, got.fds.len(), got.truncated), (3, 0, false));
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
        assert_eq!(AT_EMPTY_PATH, 0x1000);
        assert_eq!(SYS_CLOSE_RANGE, 436);
        assert_eq!(F_GETFD, 1);
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

    #[test]
    fn sup14_task1719_execveat_rejects_oversized_vectors() {
        let argv = vec![CString::new("x").unwrap(); MAX_EXEC_VECTOR + 1];
        let e = execveat_fd(i32::MAX, &argv, &[]).unwrap_err();
        // 対応 arch では EINVAL、対応外 arch では Unsupported。いずれも exec しない。
        assert!(e.raw_os_error() == Some(22) || e.kind() == io::ErrorKind::Unsupported);
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
