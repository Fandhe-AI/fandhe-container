//! 中断シグナル（SIGINT・SIGTERM・SIGHUP）を「ブロックして保留を確かめる」ための薄い FFI ラッパー
//! （TASK-190・REPAIR-5。`startup_latency` の計測ループが後始末の経路へ進むために使う）。
//!
//! 本 crate で `unsafe` を置く唯一のモジュール（各 crate の `sys` モジュールに限る事前承認の範囲。
//! `.claude/rules/coding-rust.md`）。`unsafe` は外へ公開せず、安全な関数だけを公開する。
//! シグナルハンドラは登録しない（ブロックして `sigpending` で見るだけ）。
//!
//! # エラーの返し方（REPAIR-4）
//! 関数ごとに失敗の伝わり方が違う。`pthread_sigmask` は errno を設定せず、エラー番号を戻り値で返す（POSIX.1-2008 の規定）ため
//! `io::Error::last_os_error()` を使わず戻り値から作る（`sigmask_result`）。`sigpending`・`raise` は失敗時に
//! 非 0（-1）を返し errno を設定する型で、本モジュールは errno を読まず成否だけを扱う。
//!
//! # 呼び出しの契約
//! - ブロックは呼び出したスレッドだけに効く（以後にそのスレッドが作るスレッドへは継承される）。他のスレッドを作る前に
//!   `block_termination_signals` を呼ぶこと。先に作られたスレッドはブロックしておらず、シグナルをそのスレッドが受けて
//!   既定動作（プロセス終了）になり得る。
//! - `std::process::Command` は子へ親のシグナルマスクを継承する（fork+exec・`posix_spawn` のどちらも戻さない）。
//!   ブロックしたまま子（`systemd-run`・supervisor・コンテナ init）を起こすと、子で SIGTERM 等がブロックされ、
//!   graceful stop が効かない。子を起こす `Command` には必ず `unblock_termination_signals_in_child` を適用すること。
//!   `pre_exec` を使うため、その `Command` は `posix_spawn` の経路を外れ、fork+exec で起動される。
//!
//! 対象は Linux の 64 ビット（x86_64 / aarch64）。この 2 つは `SIG_BLOCK`・シグナル番号・`sigset_t`
//! （1024 ビット = `u64` 16 個。第 n 番のシグナルは語 `(n-1)/64` のビット `(n-1)%64`）が同じ。
//! `libc` は本 crate の依存に無い（依存の追加は承認制）ため宣言は自前で行い、`libc` との機械照合は置けない。
//! 代わりに値を固定値で照合する（下のテスト。Linux ABI 由来の定数で、x86_64 / aarch64 とも同じ）。

use std::ffi::c_int;

const SIG_BLOCK: c_int = 0;
const SIG_UNBLOCK: c_int = 1;
const SIGHUP: c_int = 1;
const SIGINT: c_int = 2;
const SIGTERM: c_int = 15;
const TERMINATION: [c_int; 3] = [SIGHUP, SIGINT, SIGTERM];

/// glibc・musl の `sigset_t`（1024 ビット）。
#[repr(C)]
#[derive(Clone, Copy)]
struct SigSet([u64; 16]);

impl SigSet {
    const fn empty() -> Self {
        Self([0; 16])
    }

    /// シグナル番号 `sig`（1 以上 1024 以下）のビットを立てる。範囲外は何もしない。
    fn add(&mut self, sig: c_int) {
        if let Some(n) = usize::try_from(sig).ok().and_then(|s| s.checked_sub(1))
            && let Some(word) = self.0.get_mut(n / 64)
        {
            *word |= 1u64 << (n % 64);
        }
    }

    fn contains(&self, sig: c_int) -> bool {
        usize::try_from(sig)
            .ok()
            .and_then(|s| s.checked_sub(1))
            .and_then(|n| self.0.get(n / 64).map(|w| w & (1u64 << (n % 64)) != 0))
            .unwrap_or(false)
    }
}

unsafe extern "C" {
    /// 成功で 0、失敗でエラー番号（正の値）を戻り値で返す。errno は設定しない（POSIX）。
    fn pthread_sigmask(how: c_int, set: *const SigSet, old: *mut SigSet) -> c_int;
    /// 成功で 0、失敗で -1 を返し errno を設定する。
    fn sigpending(set: *mut SigSet) -> c_int;
    /// 成功で 0、失敗で非 0 を返す（試験専用）。
    #[cfg(test)]
    fn raise(sig: c_int) -> c_int;
}

/// `pthread_sigmask` の戻り値を `io::Result` にする（REPAIR-4）。
/// `pthread_sigmask` は errno を設定せず、成功で 0、失敗でエラー番号を戻り値で返す（POSIX）ため、
/// `io::Error::last_os_error()` ではなく戻り値から作る。`from_raw_os_error` はアロケーション・ロックを伴わず、
/// `pre_exec`（fork 後・exec 前）のクロージャからも呼べる。
fn sigmask_result(rc: c_int) -> std::io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(rc))
    }
}

/// 呼び出しスレッド（と以後に作るスレッド）で SIGINT・SIGTERM・SIGHUP をブロックする。
/// 計測の開始前（スレッドを作る前）に 1 回呼ぶ。
///
/// エラー（REPAIR-4）: `pthread_sigmask` は errno を設定せず戻り値でエラー番号を返すため、そのエラー番号を保持する
/// `io::Error` を返す（`sigmask_result`）。呼び出し側は番号（数値）だけをメッセージに載せて `unsupported-environment` にする。
pub fn block_termination_signals() -> std::io::Result<()> {
    let mut set = SigSet::empty();
    for s in TERMINATION {
        set.add(s);
    }
    // SAFETY: `set` は有効な `sigset_t` 相当（1024 ビット）の領域を指す読み取り専用の引数で、`old` は
    // 使わないため null を渡す（pthread_sigmask は null を許す）。呼び出し中、`set` は生存し続ける。
    let rc = unsafe { pthread_sigmask(SIG_BLOCK, &raw const set, std::ptr::null_mut()) };
    sigmask_result(rc)
}

/// ブロック中の中断シグナルが保留されているか。確認できない場合は `true`（fail-closed。後始末へ進める）。
///
/// エラー: `sigpending` は失敗時に -1 を返し errno を設定する（POSIX）。本関数は errno を読まず、失敗を `true` にする。
pub fn termination_pending() -> bool {
    let mut set = SigSet::empty();
    // SAFETY: `set` は書き込み可能な 1024 ビットの領域で、`sigpending` はそこへ保留集合を書くだけ。
    // 呼び出し中は生存し、他から参照されない。
    let rc = unsafe { sigpending(&raw mut set) };
    rc != 0 || TERMINATION.iter().any(|s| set.contains(*s))
}

/// 子の起動前（`pre_exec`）に、中断シグナルのブロックを解除する（親のマスクの継承を打ち消す）。
/// `cmd` で起こす子は、親が `block_termination_signals` 済みでも SIGINT・SIGTERM・SIGHUP を通常どおり受ける。
/// `pre_exec` を使うため `posix_spawn` の経路は使われず、fork+exec になる。
///
/// エラー: `pthread_sigmask` は errno を設定せず戻り値でエラー番号を返すため、そのエラー番号から `io::Error` を作って
/// 返す（`sigmask_result`）。`spawn` が `Err` になり子は exec しない。
pub fn unblock_termination_signals_in_child(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt as _;
    let mut set = SigSet::empty();
    for s in TERMINATION {
        set.add(s);
    }
    // SAFETY: `pre_exec` のクロージャは fork 後・exec 前の子で、非同期シグナル安全な呼び出しだけを行う必要がある。
    // `pthread_sigmask` は POSIX.1-2008 TC1 で async-signal-safe 関数の一覧に加わった（signal-safety(7)）。glibc・musl では
    // `rt_sigprocmask` の薄いラッパーで、ロックもアロケーションも伴わない。
    // ここでは `pthread_sigmask` を、あらかじめスタック上に作った `set`（クロージャへ
    // Copy で移動済み）に対して呼ぶだけで、アロケーション・ロック・panic を伴う処理をしない。失敗時は戻り値の
    // エラー番号（`pthread_sigmask` は errno を設定しない）を `from_raw_os_error` で `io::Error` にして返す
    // （同関数もアロケーション・ロックを伴わない）。`spawn` が `Err` になり子は exec しない。
    unsafe {
        cmd.pre_exec(move || {
            sigmask_result(pthread_sigmask(
                SIG_UNBLOCK,
                &raw const set,
                std::ptr::null_mut(),
            ))
        });
    }
}

/// 試験用: 呼び出しスレッドへ SIGTERM を送る（`raise` はスレッド宛て。ブロック済みなら保留になる）。
#[cfg(test)]
pub fn raise_sigterm() -> bool {
    // SAFETY: 引数なしで数値のシグナル番号だけを渡す。呼び出しスレッドでブロック済みの前提（呼び出し側の試験が保証）で、
    // 未ブロックだとプロセスが終了するため試験は先に `block_termination_signals` を呼ぶ。
    unsafe { raise(SIGTERM) == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 宣言した定数・レイアウトの固定値照合（Linux の x86_64 / aarch64 共通の ABI。`libc` は未依存のため）。
    #[test]
    fn declarations_have_the_linux_abi_values() {
        assert_eq!((SIG_BLOCK, SIGHUP, SIGINT, SIGTERM), (0, 1, 2, 15));
        assert_eq!(size_of::<SigSet>(), 128);
        assert_eq!(align_of::<SigSet>(), 8);
    }

    /// 子の `SigBlk`（`/proc/<pid>/status`）を読む。
    fn child_sigblk(cmd: &mut std::process::Command) -> u64 {
        let mut child = cmd
            .arg("30")
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let status = std::fs::read_to_string(format!("/proc/{}/status", child.id()));
        let _ = child.kill();
        let _ = child.wait();
        let status = status.expect("read status");
        let hex = status
            .lines()
            .find_map(|l| l.strip_prefix("SigBlk:"))
            .expect("SigBlk line")
            .trim();
        u64::from_str_radix(hex, 16).expect("hex")
    }

    /// 親がブロック済みでも、適用した子の SigBlk は 0（対照: 適用しない子は継承して非 0）。
    #[test]
    fn child_does_not_inherit_the_blocked_termination_signals() {
        std::thread::spawn(|| {
            block_termination_signals().expect("block");
            let inherited = child_sigblk(&mut std::process::Command::new("sleep"));
            // SIGHUP(1)・SIGINT(2)・SIGTERM(15) のビット。
            assert_eq!(inherited & 0x4003, 0x4003);
            let mut cmd = std::process::Command::new("sleep");
            unblock_termination_signals_in_child(&mut cmd);
            assert_eq!(child_sigblk(&mut cmd), 0);
        })
        .join()
        .expect("thread");
    }

    /// REPAIR-4: 戻り値 0 は `Ok`、非 0 はそのエラー番号を保持する `io::Error`（22 = EINVAL は x86_64 / aarch64 共通）。
    #[test]
    fn sigmask_result_maps_return_code_to_io_error_repair_4() {
        assert!(sigmask_result(0).is_ok());
        let einval = sigmask_result(22).expect_err("EINVAL");
        assert_eq!(einval.raw_os_error(), Some(22));
        assert_eq!(einval.kind(), std::io::ErrorKind::InvalidInput);
        let eperm = sigmask_result(1).expect_err("EPERM");
        assert_eq!(eperm.raw_os_error(), Some(1));
    }

    #[test]
    fn sigset_bits_follow_the_kernel_layout() {
        let mut s = SigSet::empty();
        s.add(SIGTERM);
        assert_eq!(s.0[0], 1u64 << 14);
        assert!(s.contains(SIGTERM) && !s.contains(SIGINT));
        s.add(0);
        s.add(1025);
        assert_eq!(s.0.iter().filter(|w| **w != 0).count(), 1);
    }

    /// ブロックした SIGTERM は保留になり、プロセスを終了させない。別スレッドへ影響しない。
    #[test]
    fn blocked_sigterm_becomes_pending_without_killing_the_process() {
        std::thread::spawn(|| {
            block_termination_signals().expect("block");
            assert!(!termination_pending());
            assert!(raise_sigterm());
            assert!(termination_pending());
        })
        .join()
        .expect("thread");
    }
}
