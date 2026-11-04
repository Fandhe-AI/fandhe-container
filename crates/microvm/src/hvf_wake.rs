//! WFI の待ちを SPI の注入と停止要求で起こす仕組み（#3887・MVM-5・MVM-1・REPAIR-5）。OS 非依存・`unsafe` なし。
//!
//! 役割: macOS の `hvf::timer::handle_wfx` は WFI でホスト側に待つ。その待ちを `std::thread::sleep` ではなく
//! [`WfiWaker::wait`] にし、(a) `hv_gic_set_spi` の assert 成功後（`hvf::gic` の SPI sink。virtio の完了通知・シリアル入力）と
//! (b) 停止要求の kick（[`WakingKick`]。`LoopHandle::stop` / drop が `hv_vcpus_exit` の代わりに呼ぶ）から [`WfiWaker::notify`] で
//! 即座に起こす。`hv_*` を呼ばないので Linux の CI で単体試験できる。
//!
//! # 契約
//! - 通知は自動リセットのフラグ 1 個。待つ前に届いた通知は残り、次の [`WfiWaker::wait`] を 1 回だけ即時に戻す
//!   （取りこぼし防止）。ゲストの走行中に届いた通知も残るため、次の WFI が 1 回だけ早期に再開する。ゲストは `wfi` を
//!   再実行して正しく待つので、WFI の早期再開（spurious wakeup）はアーキテクチャ上許される範囲に収まる。
//! - 待ちは常に期限つき（呼び出し側が `WFI_WAIT_MAX` を渡す。REPAIR-5）。通知されない起床要因（framework 側で pending に
//!   なる PPI 等）の安全網は、この期限である。
//! - 内部の lock が poison されても回復する（bool の状態は常に有効）。panic しない。
//!
//! # 範囲外（REPAIR-3）
//! フラグ 1 個を 1 つの待ち手が消費する設計で、vCPU 1 台を前提にする。SMP（複数 vCPU が待つ）では vCPU ごとの waker
//! か世代カウンタが要る（#3864 の後続）。

use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::error::MicrovmError;
use crate::hvf_loop::VcpuKick;

/// [`WfiWaker::wait`] の戻り。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeOutcome {
    /// 通知で戻った（待つ前の通知を含む）。
    Notified,
    /// 通知が無く、期限で戻った。
    TimedOut,
}

/// WFI の待ちを起こす通知口。clone は同じフラグを共有する（VM・SPI の sink・vCPU スレッドで共有する）。
#[derive(Clone, Default)]
pub struct WfiWaker {
    inner: Arc<(Mutex<bool>, Condvar)>,
}

impl fmt::Debug for WfiWaker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WfiWaker").finish_non_exhaustive()
    }
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WfiWaker>();
};

impl WfiWaker {
    /// 通知を立てて、待っているスレッドを起こす。アロケーションも待ちも持たない。
    pub fn notify(&self) {
        let (lock, cv) = &*self.inner;
        let mut g = lock.lock().unwrap_or_else(|e| e.into_inner());
        *g = true;
        cv.notify_all();
    }

    /// 通知か `limit` の期限まで待つ。通知を消費して戻る。`limit` が 0 なら待たずにフラグだけ見る。
    pub fn wait(&self, limit: Duration) -> WakeOutcome {
        let (lock, cv) = &*self.inner;
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let (mut guard, _) = cv
            .wait_timeout_while(guard, limit, |notified| !*notified)
            .unwrap_or_else(|e| e.into_inner());
        if *guard {
            *guard = false;
            WakeOutcome::Notified
        } else {
            WakeOutcome::TimedOut
        }
    }
}

/// `inner.kick()` の後に [`WfiWaker::notify`] する [`VcpuKick`]。停止要求で WFI の待ちも起こす。
///
/// `hvf::vcpu` が `VcpuCanceller` を包んで `spawn_loop` へ渡す。`inner` の成否によらず通知し、`inner` の結果を返す
/// （vCPU 破棄後の kick が失敗しても、待っているスレッドは起こす）。
#[derive(Debug)]
pub struct WakingKick<K> {
    inner: K,
    waker: WfiWaker,
}

impl<K: VcpuKick> WakingKick<K> {
    /// `inner` と `waker` を束ねる。
    pub fn new(inner: K, waker: WfiWaker) -> Self {
        Self { inner, waker }
    }
}

impl<K: VcpuKick> VcpuKick for WakingKick<K> {
    fn kick(&self) -> Result<(), MicrovmError> {
        let r = self.inner.kick();
        self.waker.notify();
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::MicrovmErrorCode;
    use crate::hvf_abi::HvRunStats;
    use crate::hvf_loop::spawn_loop;
    use crate::stop::StopReason;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    #[derive(Debug)]
    struct FakeKick(Result<(), MicrovmErrorCode>);

    impl VcpuKick for FakeKick {
        fn kick(&self) -> Result<(), MicrovmError> {
            self.0
                .map_err(|c| MicrovmError::new(c, "fake kick failure"))
        }
    }

    #[test]
    fn repair5_mvm5_3887_notify_from_thread_wakes_within_100ms() {
        let w = WfiWaker::default();
        let w2 = w.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1));
            w2.notify();
        });
        let start = Instant::now();
        assert_eq!(w.wait(Duration::from_secs(1)), WakeOutcome::Notified);
        assert!(start.elapsed() < Duration::from_millis(100));
        t.join().unwrap();
    }

    #[test]
    fn repair5_mvm5_3887_pending_notify_returns_without_waiting() {
        let w = WfiWaker::default();
        w.notify();
        let start = Instant::now();
        assert_eq!(w.wait(Duration::from_secs(1)), WakeOutcome::Notified);
        assert!(start.elapsed() < Duration::from_millis(50));
        // 通知は消費されている。
        assert_eq!(w.wait(Duration::from_millis(20)), WakeOutcome::TimedOut);
    }

    #[test]
    fn repair5_mvm5_3887_no_notify_times_out_at_limit() {
        let w = WfiWaker::default();
        let start = Instant::now();
        assert_eq!(w.wait(Duration::from_millis(50)), WakeOutcome::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn repair5_mvm5_3887_zero_limit_does_not_block() {
        let w = WfiWaker::default();
        assert_eq!(w.wait(Duration::ZERO), WakeOutcome::TimedOut);
        w.notify();
        assert_eq!(w.wait(Duration::ZERO), WakeOutcome::Notified);
    }

    #[test]
    fn repair5_mvm5_3887_waking_kick_notifies_even_if_inner_fails() {
        let w = WfiWaker::default();
        let k = WakingKick::new(
            FakeKick(Err(MicrovmErrorCode::FailedPrecondition)),
            w.clone(),
        );
        let e = k.kick().unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        let start = Instant::now();
        assert_eq!(w.wait(Duration::from_secs(1)), WakeOutcome::Notified);
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    /// 停止要求の kick が、WFI の待ちを模した長い `wait` を起こして `Requested` で止まる（結線の照合）。
    #[test]
    fn repair5_mvm5_3887_stop_wakes_blocked_wfi_wait() {
        let waker = WfiWaker::default();
        let body_waker = waker.clone();
        let h = spawn_loop("hvf-wake-test", Duration::from_secs(5), move |start| {
            let kick = WakingKick::new(FakeKick(Ok(())), body_waker.clone());
            let stop = start.ready(kick);
            while !stop.load(Ordering::Acquire) {
                // 通知が無ければ 1 秒待つ（WFI の待ちの模擬）。
                let _ = body_waker.wait(Duration::from_secs(1));
            }
            (StopReason::Requested, HvRunStats::default())
        })
        .unwrap();
        // 本体が待ちに入る時間を与える。
        std::thread::sleep(Duration::from_millis(20));
        let start = Instant::now();
        let report = h.stop(Duration::from_secs(2)).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert!(start.elapsed() < Duration::from_millis(100));
    }
}
