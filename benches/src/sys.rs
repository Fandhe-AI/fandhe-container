//! 中断シグナル（SIGINT・SIGTERM・SIGHUP）を「ブロックして保留を確かめる」ための薄い FFI ラッパー
//! （TASK-190・REPAIR-5。`startup_latency` の計測ループが後始末の経路へ進むために使う）。
//!
//! 本 crate で `unsafe` を置く唯一のモジュール（各 crate の `sys` モジュールに限る事前承認の範囲。
//! `.claude/rules/coding-rust.md`）。`unsafe` は外へ公開せず、安全な関数だけを公開する。
//! シグナルハンドラは登録しない（ブロックして `sigpending` で見るだけ）。ブロックはスレッド単位で、
//! 以後に作るスレッドへ継承される。`std::process::Command` は子の起動時にマスクを空へ戻すため、
//! 子（`systemd-run` と supervisor）へはブロックが継承されない。
//!
//! 対象は Linux の 64 ビット（x86_64 / aarch64）。この 2 つは `SIG_BLOCK`・シグナル番号・`sigset_t`
//! （1024 ビット = `u64` 16 個。第 n 番のシグナルは語 `(n-1)/64` のビット `(n-1)%64`）が同じ。
//! `libc` は本 crate の依存に無い（依存の追加は承認制）ため宣言は自前で行い、`libc` との機械照合は置けない。
//! 代わりに値を固定値で照合する（下のテスト。Linux ABI 由来の定数で、x86_64 / aarch64 とも同じ）。

use std::ffi::c_int;

const SIG_BLOCK: c_int = 0;
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
    fn pthread_sigmask(how: c_int, set: *const SigSet, old: *mut SigSet) -> c_int;
    fn sigpending(set: *mut SigSet) -> c_int;
    #[cfg(test)]
    fn raise(sig: c_int) -> c_int;
}

/// 呼び出しスレッド（と以後に作るスレッド）で SIGINT・SIGTERM・SIGHUP をブロックする。成功なら `true`。
/// 計測の開始前（スレッドを作る前）に 1 回呼ぶ。
pub fn block_termination_signals() -> bool {
    let mut set = SigSet::empty();
    for s in TERMINATION {
        set.add(s);
    }
    // SAFETY: `set` は有効な `sigset_t` 相当（1024 ビット）の領域を指す読み取り専用の引数で、`old` は
    // 使わないため null を渡す（pthread_sigmask は null を許す）。呼び出し中、`set` は生存し続ける。
    unsafe { pthread_sigmask(SIG_BLOCK, &raw const set, std::ptr::null_mut()) == 0 }
}

/// ブロック中の中断シグナルが保留されているか。確認できない場合は `true`（fail-closed。後始末へ進める）。
pub fn termination_pending() -> bool {
    let mut set = SigSet::empty();
    // SAFETY: `set` は書き込み可能な 1024 ビットの領域で、`sigpending` はそこへ保留集合を書くだけ。
    // 呼び出し中は生存し、他から参照されない。
    let rc = unsafe { sigpending(&raw mut set) };
    rc != 0 || TERMINATION.iter().any(|s| set.contains(*s))
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
            assert!(block_termination_signals());
            assert!(!termination_pending());
            assert!(raise_sigterm());
            assert!(termination_pending());
        })
        .join()
        .expect("thread");
    }
}
