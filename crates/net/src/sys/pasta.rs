//! pasta の起動・停止（`crate::pasta::process`。NET-9・REPAIR-5・#1938）が使う syscall・FFI の薄いラッパー
//! （`crates/net` の `sys` モジュールの子。`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節）。
//!
//! # 呼び出し文脈
//! - `spawn_pasta`: spawn 前に [`set_pdeathsig_on_spawn`] で `pre_exec` を登録する（12.10 の (1)）
//! - `PastaProcess::stop*`: SIGTERM を [`send_sigterm_unreaped`] で送る（SIGKILL は std の `Child::kill`）
//!
//! # 契約
//! - 親 `sys` と同じ（`unsafe fn` を公開しない・`SAFETY:` の明記・arch ごとの定数・戻り値 -1 は直後に errno を確保）
//! - [`send_sigterm_unreaped`] は未回収の子にだけ送る。回収済みの pid は再利用されうるため、先に `try_wait` で
//!   回収済みかを確かめ、回収済みなら送らない。未回収の子は zombie でも pid が固定される。前提として、
//!   プロセスは `SIGCHLD` を `SIG_IGN` にしない（無視すると子が自動回収され、この不変条件が崩れる）
//! - `pre_exec` の closure は async-signal-safe な呼び出し（`prctl`・`getppid`）だけで、メモリ確保をしない
//!
//! # `libc` 照合について
//! 定数と `kill` の関数型を `libc_abi`（本ファイル末尾）で `libc` と `const` 評価で照合する。

use std::io;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command};

use super::holder::set_pdeathsig_sigkill;
use super::{SysError, last_error};

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
mod consts {
    pub const SIGTERM: i32 = 15;
    pub const ESRCH: i32 = 3;
    pub const EINVAL: i32 = 22;
}

#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
mod consts {
    pub const SIGTERM: i32 = 15;
    pub const ESRCH: i32 = 3;
    pub const EINVAL: i32 = 22;
}

#[cfg(not(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod consts {
    pub const SIGTERM: i32 = 0;
    pub const ESRCH: i32 = -1;
    pub const EINVAL: i32 = -2;
}

// SAFETY: Linux の libc（glibc / musl 共通）の C 関数の宣言で、型は原型 `int kill(pid_t pid, int sig)`
// （`pid_t` は i32）と一致させている。呼び出し側の不変条件は `unsafe` ブロックの SAFETY に記す。
unsafe extern "C" {
    // 原型: `int kill(pid_t pid, int sig)`。
    fn kill(pid: i32, sig: i32) -> i32;
}

/// 未回収の子へ `SIGTERM` を送る。送ったら `Ok(true)`、既に終了していた（回収は呼び出し側）なら `Ok(false)`。
///
/// 先に `try_wait` を呼ぶ。`try_wait` が回収した場合は std が子の状態を保持するため、呼び出し側が
/// 再度 `try_wait` / `wait` で同じ終了状態を得られる。
pub(crate) fn send_sigterm_unreaped(child: &mut Child) -> Result<bool, SysError> {
    if !super::consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    match child.try_wait() {
        Ok(Some(_)) => return Ok(false),
        Ok(None) => {}
        Err(e) => return Err(SysError::Os(e.raw_os_error().unwrap_or(consts::EINVAL))),
    }
    let pid = i32::try_from(child.id()).map_err(|_| SysError::Os(consts::EINVAL))?;
    // SAFETY: `kill(2)` は整数 2 つだけを取りメモリに触れない。`pid` は直前の `try_wait` が `None`
    // （未回収）を返した子の pid で、未回収の子は zombie でも pid が再利用されないため、別プロセスへ
    // 送らない（回収するのはこの `Child` だけ。モジュール doc の SIGCHLD の前提）。`SIGTERM` は正の定数。
    let rc = unsafe { kill(pid, consts::SIGTERM) };
    if rc < 0 {
        let e = last_error();
        if e == SysError::Os(consts::ESRCH) {
            return Ok(false);
        }
        return Err(e);
    }
    Ok(true)
}

/// spawn する子に、親の死亡で `SIGKILL` を受ける設定（`PR_SET_PDEATHSIG`）と、親が `expected_parent`
/// のままであることの確認（`getppid`）を `pre_exec` として登録する（12.10 の (1)）。
///
/// 親がこの設定の前に死ぬと `getppid` は別の値になり、spawn は `ESRCH` で失敗する。注意: 「親」は fork を呼んだ
/// **スレッド**で、そのスレッドの終了でも届く。呼び出し側（supervisor。#1940）は入口の main スレッドから
/// spawn すること。
pub(crate) fn set_pdeathsig_on_spawn(cmd: &mut Command, expected_parent: u32) {
    // SAFETY: closure は fork 後・exec 前の子で実行される。呼ぶのは `prctl(PR_SET_PDEATHSIG)` と `getppid(2)`
    // だけで、どちらも async-signal-safe。メモリ確保・ロック・panic をしない（エラーは `from_raw_os_error` の
    // 値型で返す）。捕捉するのは `u32` のコピーだけ。
    unsafe {
        cmd.pre_exec(move || {
            set_pdeathsig_sigkill().map_err(|e| match e {
                SysError::Os(n) => io::Error::from_raw_os_error(n),
                _ => io::Error::from_raw_os_error(consts::EINVAL),
            })?;
            if std::os::unix::process::parent_id() != expected_parent {
                return Err(io::Error::from_raw_os_error(consts::ESRCH));
            }
            Ok(())
        });
    }
}

/// `pre_exec` の ppid 不一致（`ESRCH`）かを判定する（spawn の失敗の分類用）。
pub(crate) fn is_parent_gone(e: &io::Error) -> bool {
    e.raw_os_error() == Some(consts::ESRCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn sleeper() -> Child {
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sleep")
    }

    #[test]
    fn sigterm_reaches_live_child() {
        let mut c = sleeper();
        assert_eq!(send_sigterm_unreaped(&mut c), Ok(true));
        let started = Instant::now();
        let st = loop {
            if let Some(st) = c.try_wait().expect("try_wait") {
                break st;
            }
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(st.signal(), Some(15));
    }

    #[test]
    fn sigterm_not_sent_to_reaped_child() {
        let mut c = Command::new("true").spawn().expect("spawn true");
        let _ = c.wait();
        assert_eq!(send_sigterm_unreaped(&mut c), Ok(false));
    }

    #[test]
    fn parent_gone_mapping() {
        assert!(is_parent_gone(&io::Error::from_raw_os_error(consts::ESRCH)));
        assert!(!is_parent_gone(&io::Error::from_raw_os_error(
            consts::EINVAL
        )));
    }
}

#[cfg(all(
    test,
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod libc_abi {
    use super::{consts, kill};

    const _: () = {
        assert!(consts::SIGTERM == libc::SIGTERM);
        assert!(consts::ESRCH == libc::ESRCH);
        assert!(consts::EINVAL == libc::EINVAL);
    };

    const _: unsafe extern "C" fn(libc::pid_t, libc::c_int) -> libc::c_int = kill;
    const _: unsafe extern "C" fn(libc::pid_t, libc::c_int) -> libc::c_int = libc::kill;
}
