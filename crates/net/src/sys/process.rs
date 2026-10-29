//! DNS ヘルパーの切り離し起動と pidfd 経由の停止（`crate::dns_helper::detach`。NET-5・NET-7・REPAIR-5・#3070）が
//! 使う syscall・FFI の薄いラッパー（`crates/net` の `sys` モジュールの子。`unsafe` 事前承認の範囲。
//! coding-rust.md「unsafe・FFI・syscall」節）。
//!
//! # 呼び出し文脈
//! - 停止側（CLI・supervisor・plugin の任意のプロセス）が、記録の pid から [`pidfd_open`] で pidfd を先に取り、
//!   開始時刻の照合の後で期限つきの待機（`sys::wait_readable`）と [`pidfd_send_sigkill`] を行う。pid 番号へは
//!   シグナルを送らない（pid の再利用で別プロセスを撃たないため。D11）
//! - 切り離し起動の段 1（`run_dns_helper_main` の `--dns-helper-detach`）が [`setsid`] を呼ぶ
//! - 呼び出し元が child subreaper のとき、切り離した孫は自分の子になりゾンビが残るため、停止後に
//!   [`reap_pidfd_nohang`] で回収する
//!
//! # 契約
//! 親 `sys` と同じ（`unsafe fn` を公開しない・`SAFETY:` の明記・arch ごとの定数・戻り値 -1 は直後に errno を確保）。
//! 対応外アーキテクチャでは各ラッパーが [`SysError::Unsupported`] を返す。`pidfd_open` が使えないカーネル
//! （Linux 5.3 未満）は `ENOSYS` を返し、呼び出し側が `Unimplemented` にする。
//!
//! # `libc` 照合
//! 定数と関数型は `libc_abi`（本ファイル末尾）で `libc` と `const` 評価で照合する。`waitid(2)` の `siginfo_t` は
//! 渡さない（NULL）ため構造体は宣言しない。

use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

use super::{SysError, last_error};

pub(crate) use consts::{ENOSYS, ESRCH};

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
mod consts {
    pub const SUPPORTED: bool = true;
    /// `pidfd_open(2)` のシステムコール番号（arch/x86/entry/syscalls/syscall_64.tbl。Linux 5.3 以上）。
    pub const SYS_PIDFD_OPEN: core::ffi::c_long = 434;
    /// `pidfd_send_signal(2)` のシステムコール番号（syscall_64.tbl。Linux 5.1 以上）。
    pub const SYS_PIDFD_SEND_SIGNAL: core::ffi::c_long = 424;
    pub const P_PIDFD: u32 = 3;
    pub const WNOHANG: i32 = 1;
    pub const WEXITED: i32 = 4;
    pub const SIGKILL: i32 = 9;
    pub const ESRCH: i32 = 3;
    pub const ECHILD: i32 = 10;
    pub const ENOSYS: i32 = 38;
}

#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
mod consts {
    pub const SUPPORTED: bool = true;
    /// `pidfd_open(2)` のシステムコール番号（include/uapi/asm-generic/unistd.h）。
    pub const SYS_PIDFD_OPEN: core::ffi::c_long = 434;
    /// `pidfd_send_signal(2)` のシステムコール番号（include/uapi/asm-generic/unistd.h）。
    pub const SYS_PIDFD_SEND_SIGNAL: core::ffi::c_long = 424;
    pub const P_PIDFD: u32 = 3;
    pub const WNOHANG: i32 = 1;
    pub const WEXITED: i32 = 4;
    pub const SIGKILL: i32 = 9;
    pub const ESRCH: i32 = 3;
    pub const ECHILD: i32 = 10;
    pub const ENOSYS: i32 = 38;
}

#[cfg(not(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_pointer_width = "64"
)))]
mod consts {
    pub const SUPPORTED: bool = false;
    pub const SYS_PIDFD_OPEN: core::ffi::c_long = 0;
    pub const SYS_PIDFD_SEND_SIGNAL: core::ffi::c_long = 0;
    pub const P_PIDFD: u32 = 0;
    pub const WNOHANG: i32 = 0;
    pub const WEXITED: i32 = 0;
    pub const SIGKILL: i32 = 0;
    pub const ESRCH: i32 = -1;
    pub const ECHILD: i32 = -2;
    pub const ENOSYS: i32 = -3;
}

// SAFETY: C の原型と一致させた宣言。`syscall` は可変長、`waitid` の `idtype_t` は enum（u32）、`id_t` は u32、
// `infop` は常に NULL を渡す（`siginfo_t` を読まないため `*mut c_void` で宣言する）。`setsid` は引数なし。
unsafe extern "C" {
    // 原型: `long syscall(long number, ...)`。`pidfd_open` / `pidfd_send_signal` は glibc の版によって
    // 関数が無いため経由する。
    fn syscall(number: core::ffi::c_long, ...) -> core::ffi::c_long;
    // 原型: `int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)`。
    fn waitid(idtype: u32, id: u32, infop: *mut core::ffi::c_void, options: i32) -> i32;
    // 原型: `pid_t setsid(void)`。Rust 側で安全な `setsid` を公開するため別名で宣言する。
    #[link_name = "setsid"]
    fn setsid_raw() -> i32;
}

/// pid から pidfd を取る（`pidfd_open(pid, 0)`）。存在しなければ `Os(ESRCH)`、未対応のカーネルは `Os(ENOSYS)`。
///
/// 返る fd は `O_CLOEXEC` つきで、プロセスの終了で可読になる（`sys::wait_readable` で期限つきに待てる）。
pub(crate) fn pidfd_open(pid: u32) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 整数引数のみでポインタを取らない。`pid` は値渡し、flags は 0。成功時の戻り値は新しい fd で、
    // 直後に `OwnedFd` が所有する（二重 close を起こさない）。
    let rc = unsafe {
        syscall(
            consts::SYS_PIDFD_OPEN,
            pid as core::ffi::c_ulong,
            0 as core::ffi::c_ulong,
        )
    };
    if rc < 0 {
        return Err(last_error());
    }
    let Ok(fd) = i32::try_from(rc) else {
        return Err(SysError::Os(consts::ENOSYS));
    };
    // SAFETY: `rc` はカーネルが今返した新規の fd で、他の所有者はいない。
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// pidfd が指すプロセスへ SIGKILL を送る（`pidfd_send_signal(fd, SIGKILL, NULL, 0)`）。
/// 既に終了していれば `Os(ESRCH)`。`siginfo_t` は渡さない（NULL なら `kill(2)` と同じ扱いと権限検査になる）。
pub(crate) fn pidfd_send_sigkill(pidfd: BorrowedFd<'_>) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `pidfd` は生存中の `BorrowedFd`。`info` は NULL、flags は 0、シグナル番号は定義済みの SIGKILL。
    // ポインタ引数は NULL のみでメモリに触れない。
    let rc = unsafe {
        syscall(
            consts::SYS_PIDFD_SEND_SIGNAL,
            pidfd.as_raw_fd() as core::ffi::c_ulong,
            consts::SIGKILL as core::ffi::c_ulong,
            0 as core::ffi::c_ulong,
            0 as core::ffi::c_ulong,
        )
    };
    if rc < 0 { Err(last_error()) } else { Ok(()) }
}

/// pidfd が指す子プロセスを待たずに回収する（`waitid(P_PIDFD, fd, NULL, WEXITED | WNOHANG)`）。
/// 自分の子でない（`ECHILD`）場合は `Ok(false)`（回収は親の仕事）。`waitid` が成功したら `Ok(true)`
/// （NULL の `infop` では「回収した」と「まだ終了していない」を区別できないため、終了の確認は pidfd の可読性で行う）。
/// 呼び出し元が child subreaper のときの孫のゾンビを残さないために使う。
pub(crate) fn reap_pidfd_nohang(pidfd: BorrowedFd<'_>) -> Result<bool, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `pidfd` は生存中の `BorrowedFd` で、`id` には fd 番号を非負の u32 として渡す（P_PIDFD の規約）。
    // `infop` は NULL（Linux は NULL を許す）。options は定義済み定数の組み合わせ。
    let rc = unsafe {
        waitid(
            consts::P_PIDFD,
            pidfd.as_raw_fd() as u32,
            core::ptr::null_mut(),
            consts::WEXITED | consts::WNOHANG,
        )
    };
    if rc < 0 {
        let e = last_error();
        return if e == SysError::Os(consts::ECHILD) {
            Ok(false)
        } else {
            Err(e)
        };
    }
    Ok(true)
}

/// 呼び出しプロセスを新しいセッションのリーダーにする（`setsid(2)`）。
/// 既にプロセスグループのリーダーなら `Os(EPERM)`。切り離し起動の段 1 だけが呼ぶ。
pub(crate) fn setsid() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 引数なしで、メモリを参照しない。副作用は呼び出しプロセスのセッション・制御端末の切り離しのみ。
    let rc = unsafe { setsid_raw() };
    if rc < 0 { Err(last_error()) } else { Ok(()) }
}

/// 自前の宣言・定数の `libc` との機械照合（#1841・#1837・REPAIR-12。方式は `docs/design/ffi-libc-check.md`）。
///
/// `waitid` の `infop` は自前が `*mut c_void`、`libc` が `*mut siginfo_t` で型が違うため、他の引数・戻り値を
/// 揃えた関数型で照合する（NULL しか渡さない）。
#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod libc_abi {
    use super::{consts, setsid_raw, syscall, waitid};

    const _: () = {
        assert!(consts::SYS_PIDFD_OPEN == libc::SYS_pidfd_open);
        assert!(consts::SYS_PIDFD_SEND_SIGNAL == libc::SYS_pidfd_send_signal);
        assert!(consts::P_PIDFD == libc::P_PIDFD);
        assert!(consts::WNOHANG == libc::WNOHANG);
        assert!(consts::WEXITED == libc::WEXITED);
        assert!(consts::SIGKILL == libc::SIGKILL);
        assert!(consts::ESRCH == libc::ESRCH);
        assert!(consts::ECHILD == libc::ECHILD);
        assert!(consts::ENOSYS == libc::ENOSYS);
        assert!(core::mem::size_of::<u32>() == core::mem::size_of::<libc::id_t>());
        assert!(core::mem::size_of::<u32>() == core::mem::size_of::<libc::idtype_t>());
    };

    const _: unsafe extern "C" fn(libc::c_long, ...) -> libc::c_long = syscall;
    const _: unsafe extern "C" fn(libc::c_long, ...) -> libc::c_long = libc::syscall;
    const _: unsafe extern "C" fn(u32, u32, *mut libc::c_void, libc::c_int) -> libc::c_int = waitid;
    const _: unsafe extern "C" fn(
        libc::idtype_t,
        libc::id_t,
        *mut libc::siginfo_t,
        libc::c_int,
    ) -> libc::c_int = libc::waitid;
    const _: unsafe extern "C" fn() -> libc::pid_t = setsid_raw;
    const _: unsafe extern "C" fn() -> libc::pid_t = libc::setsid;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::{Deadline, Readiness, wait_readable};
    use std::os::fd::AsFd as _;
    use std::process::Command;
    use std::time::Duration;

    /// NET-7・#3070: 自プロセスの pidfd は取れ、存在しない pid は ESRCH になる。
    #[test]
    fn net7_3070_pidfd_open_self_and_missing() {
        match pidfd_open(std::process::id()) {
            Ok(fd) => assert!(fd.as_raw_fd() >= 0),
            // pidfd 非対応のカーネルでは ENOSYS（呼び出し側が Unimplemented にする）。
            Err(SysError::Os(e)) => assert_eq!(e, ENOSYS),
            Err(e) => panic!("unexpected {e:?}"),
        }
        // pid_max（最大 4194304）を超える値は存在しない（範囲外は ESRCH か EINVAL）。
        match pidfd_open(0x7fff_fff0) {
            Err(SysError::Os(e)) => assert!(e == ESRCH || e == ENOSYS || e == 22, "errno {e}"),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// NET-7・REPAIR-5・#3070: 子へ pidfd 経由で SIGKILL を送ると pidfd が可読になり、waitid で回収できる。
    #[test]
    fn net7_3070_sigkill_via_pidfd_then_reap() {
        let mut child = Command::new("sleep").arg("30").spawn().expect("sleep");
        let pidfd = match pidfd_open(child.id()) {
            Ok(fd) => fd,
            // 検証を省いてよいのは「非対応」と確定したときだけ。EPERM・EMFILE 等は失敗として扱う。
            Err(SysError::Os(e)) if e == ENOSYS => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
            Err(SysError::Unsupported) => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("pidfd_open failed: {e:?}");
            }
        };
        assert_eq!(
            wait_readable(pidfd.as_fd(), &Deadline::after(Duration::ZERO)).expect("poll"),
            Readiness::TimedOut
        );
        pidfd_send_sigkill(pidfd.as_fd()).expect("kill");
        assert_eq!(
            wait_readable(pidfd.as_fd(), &Deadline::after(Duration::from_secs(5))).expect("poll"),
            Readiness::Readable
        );
        assert!(reap_pidfd_nohang(pidfd.as_fd()).expect("reap"));
        // waitid で回収済みなので std 側は ECHILD になりうる（結果は問わない）。
        let _ = child.try_wait();
    }
}
