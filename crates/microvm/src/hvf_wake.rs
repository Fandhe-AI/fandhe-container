//! WFI の待ちを SPI の注入と停止要求で起こす仕組み（#3887・#3933・MVM-5・MVM-1・REPAIR-5）。OS 非依存・`unsafe` なし。
//!
//! 役割: macOS の `hvf::timer::handle_wfx` は WFI でホスト側に待つ。その待ちを `std::thread::sleep` ではなく
//! [`WfiWaker::wait`] にし、(a) SPI の注入後（#4041 で外した。下記）と
//! (b) 停止要求の kick（[`WakingKick`]。#4040 から製品の停止経路では使わない・削除は #4042。`LoopHandle::stop` / drop が `hv_vcpus_exit` の代わりに呼ぶ）から [`WfiWaker::notify`] で
//! 即座に起こす。`hv_*` を呼ばないので Linux の CI で単体試験できる。
//!
//! GIC つきの構成では WFI は exit せず `hv_vcpu_run` の中で待つため、この待ちは macOS 27.2・Apple M4 Max では通らない
//! （#3803・#3994）。別の版・チップで exit した場合のために残す（要否の判断は #3995）。
//!
//! # 契約
//! - 通知は VM 全体で共有する世代番号の加算で、待ち手（[`WfiWaker`] の clone 1 個 = vCPU 1 台）は clone ごとに既読位置を持つ。
//!   1 回の [`WfiWaker::notify`] は、待っている全待ち手を起こす（SMP で最初に起きた 1 台が通知を消費して残りが
//!   `WFI_WAIT_MAX` まで寝る取り合いをなくす。#3933）。各 vCPU は自分専用の clone を持つこと。
//! - 待つ前に届いた通知は各待ち手に 1 回ずつ残り、次の [`WfiWaker::wait`] を 1 回だけ即時に戻す（取りこぼし防止）。
//!   複数回の通知は 1 回の早期再開に畳まれる（セマフォではない）。ゲストの走行中に届いた通知も残るため、次の WFI が
//!   1 回だけ早期に再開する。ゲストは `wfi` を再実行して正しく待つので、WFI の早期再開（spurious wakeup）は
//!   アーキテクチャ上許される範囲に収まる。clone は元の既読位置を写すので、clone 前の通知でも 1 回の早期再開が起こりうる。
//! - 待ちは常に期限つき（呼び出し側が `WFI_WAIT_MAX` を渡す。REPAIR-5）。通知されない起床要因（framework 側で pending に
//!   なる PPI 等）の安全網は、この期限である。世代番号は `wrapping_add` で、ちょうど 2^64 回の通知で 1 回取りこぼしても期限で有界。
//! - 内部の lock が poison されても回復する（世代番号の状態は常に有効）。panic しない。
//!
//! # SPI の注入からの起床は外した（#3995・#4041・MVM-5・REPAIR-3）
//! (a) の `hv_gic_set_spi` の assert 後の起床と、宛先の決定（`GICD_IROUTER<n>` の読み出し・`InterruptACK` からの学習・縮退の計数とログ）は
//! #4041 で消した。GIC つきの構成では WFI が exit しないため待つ相手が無く、非 vCPU スレッドからの `set_spi` は通知なしで届く（#3803）。
//! スロットの束（[`WfiWakeSet`]）・[`WfiWaker`]・[`WakingKick`] は製品の呼び出し元が無いまま残っており、#4042 で消す。
//! - スロットの mutex は 1 個ずつ取り入れ子にしない。
//! - 通知されない起床要因（PPI 等）は従来どおり `WFI_WAIT_MAX` の期限が安全網である。

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::error::MicrovmError;
use crate::error::MicrovmErrorCode;
use crate::hvf_abi::HVF_MAX_VCPUS;
use crate::hvf_loop::VcpuKick;

/// [`WfiWaker::wait`] の戻り。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeOutcome {
    /// 通知で戻った（待つ前の通知を含む）。
    Notified,
    /// 通知が無く、期限で戻った。
    TimedOut,
}

/// WFI の待ちを起こす通知口。clone は同じ世代番号（通知）を共有するが、既読位置は clone ごとに持つ
/// （VM・SPI の sink で共有し、vCPU スレッドごとに 1 個の clone を割り当てる。#3933）。
#[derive(Default)]
pub struct WfiWaker {
    inner: Arc<(Mutex<u64>, Condvar)>,
    /// この clone が観測済みの世代。`inner` の mutex を持つ間だけ読み書きする。
    seen: AtomicU64,
}

impl Clone for WfiWaker {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            seen: AtomicU64::new(self.seen.load(Ordering::Relaxed)),
        }
    }
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
    /// 世代を進めて、待っている全スレッドを起こす。アロケーションも待ちも持たない。
    pub fn notify(&self) {
        let (lock, cv) = &*self.inner;
        let mut g = lock.lock().unwrap_or_else(|e| e.into_inner());
        *g = g.wrapping_add(1);
        cv.notify_all();
    }

    /// 通知か `limit` の期限まで待つ。この clone の既読位置まで進めて戻る。`limit` が 0 なら待たずに世代だけ見る。
    pub fn wait(&self, limit: Duration) -> WakeOutcome {
        let (lock, cv) = &*self.inner;
        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        let seen = self.seen.load(Ordering::Relaxed);
        let (guard, _) = cv
            .wait_timeout_while(guard, limit, |g| *g == seen)
            .unwrap_or_else(|e| e.into_inner());
        if *guard != seen {
            self.seen.store(*guard, Ordering::Relaxed);
            WakeOutcome::Notified
        } else {
            WakeOutcome::TimedOut
        }
    }
}

/// 待っている全 vCPU を起こす口。停止要求の kick（[`WakingKick`]）が使う（#3948）。
pub trait WakeAll: Send + Sync + 'static {
    /// 待っている全スレッドを起こす。
    fn wake_all(&self);
}

impl WakeAll for WfiWaker {
    fn wake_all(&self) {
        self.notify();
    }
}

/// vCPU ごとに独立した [`WfiWaker`] の束（#3948・MVM-5・REPAIR-5）。
///
/// `hvf::gic::VmWithGic` が VM につき 1 個持ち、vCPU スレッドは [`Self::handle`] で自分のスロットの clone を受け取って待つ。
/// 停止要求・VM の終了は [`Self::notify_all`] で起こす。スロットごとに mutex と condvar が
/// 別なので、宛先以外のスレッドは OS のレベルでも起きない。
#[derive(Clone)]
pub struct WfiWakeSet {
    slots: Arc<[WfiWaker]>,
}

impl fmt::Debug for WfiWakeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WfiWakeSet")
            .field("vcpus", &self.slots.len())
            .finish()
    }
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WfiWakeSet>();
};

impl WfiWakeSet {
    /// `vcpus` 台分のスロットを作る。0 と [`HVF_MAX_VCPUS`] 超は `InvalidArgument`（台数は host の構成値で、確保はここで 1 回だけ）。
    pub fn new(vcpus: u32) -> Result<Self, MicrovmError> {
        if vcpus == 0 || vcpus > HVF_MAX_VCPUS {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "wake set vcpu count out of range",
            ));
        }
        let slots: Vec<WfiWaker> = (0..vcpus).map(|_| WfiWaker::default()).collect();
        Ok(Self {
            slots: slots.into(),
        })
    }

    /// vCPU `index` 専用の待ち手（スロットの clone）。範囲外は `InvalidArgument`。各 vCPU は自分のスロットだけで待つこと。
    pub fn handle(&self, index: u32) -> Result<WfiWaker, MicrovmError> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.slots.get(i))
            .cloned()
            .ok_or_else(|| {
                MicrovmError::new(
                    MicrovmErrorCode::InvalidArgument,
                    "wake set vcpu index out of range",
                )
            })
    }

    /// 全スロットを起こす（停止要求・VM の終了・宛先不明）。スロットの mutex は 1 個ずつ取る。
    pub fn notify_all(&self) {
        for w in self.slots.iter() {
            w.notify();
        }
    }

    /// vCPU `index` のスロットだけを起こす。範囲外なら取りこぼさないよう全台を起こす。
    pub fn notify_vcpu(&self, index: u32) {
        match usize::try_from(index).ok().and_then(|i| self.slots.get(i)) {
            Some(w) => w.notify(),
            None => self.notify_all(),
        }
    }

    /// スロットの数（vCPU 数）。
    pub fn vcpus(&self) -> u32 {
        u32::try_from(self.slots.len()).unwrap_or(0)
    }
}

impl WakeAll for WfiWakeSet {
    fn wake_all(&self) {
        self.notify_all();
    }
}

/// `inner.kick()` の後に全 vCPU の待ちを起こす [`VcpuKick`]。停止要求で WFI の待ちも起こす。
///
/// 製品の呼び出し元は無い（#4040 で `hvf::vcpu` は `HvfKick` を直接渡すようにした。削除は #4042）。`inner` の成否によらず起こし、`inner` の結果を返す
/// （vCPU 破棄後の kick が失敗しても、待っているスレッドは起こす）。`W` は [`WfiWaker`]（単一）か [`WfiWakeSet`]（全台。#3948）。
#[derive(Debug)]
pub struct WakingKick<K, W = WfiWaker> {
    inner: K,
    waker: W,
}

impl<K: VcpuKick, W: WakeAll> WakingKick<K, W> {
    /// `inner` と `waker` を束ねる。
    pub fn new(inner: K, waker: W) -> Self {
        Self { inner, waker }
    }
}

impl<K: VcpuKick, W: WakeAll> VcpuKick for WakingKick<K, W> {
    fn kick(&self) -> Result<(), MicrovmError> {
        let r = self.inner.kick();
        self.waker.wake_all();
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

    /// N 台が同時に待つとき、1 回の通知で全台が上限を待たず `Notified` で戻る（#3933・MVM-5・REPAIR-5）。
    #[test]
    fn repair5_mvm5_3933_one_notify_wakes_all_concurrent_waiters() {
        const N: usize = 4;
        let w = WfiWaker::default();
        let barrier = Arc::new(std::sync::Barrier::new(N + 1));
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let wc = w.clone();
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    let r = wc.wait(Duration::from_secs(1));
                    (r, Instant::now(), wc)
                })
            })
            .collect();
        barrier.wait();
        std::thread::sleep(Duration::from_millis(20));
        let notified_at = Instant::now();
        w.notify();
        let mut notified = 0;
        for h in handles {
            let (r, at, wc) = h.join().unwrap();
            if r == WakeOutcome::Notified {
                notified += 1;
            }
            assert!(at.duration_since(notified_at) < Duration::from_millis(100));
            // 通知は各待ち手で 1 回ずつ消費されている。
            assert_eq!(wc.wait(Duration::from_millis(20)), WakeOutcome::TimedOut);
        }
        assert_eq!(notified, N);
    }

    /// 待つ前の複数回の通知は、各待ち手に 1 回の早期再開として残る（#3933）。
    #[test]
    fn repair5_mvm5_3933_pending_notifies_collapse_per_waiter() {
        let w = WfiWaker::default();
        let (a, b) = (w.clone(), w.clone());
        w.notify();
        w.notify();
        for x in [&a, &b] {
            assert_eq!(x.wait(Duration::ZERO), WakeOutcome::Notified);
            assert_eq!(x.wait(Duration::ZERO), WakeOutcome::TimedOut);
        }
    }

    /// 停止要求の kick 1 回が、待っている 2 台とも起こす（#3933）。
    #[test]
    fn repair5_mvm5_3933_waking_kick_wakes_all_waiters() {
        let w = WfiWaker::default();
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let wc = w.clone();
                std::thread::spawn(move || {
                    let s = Instant::now();
                    (wc.wait(Duration::from_secs(1)), s.elapsed())
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(20));
        WakingKick::new(FakeKick(Ok(())), w.clone()).kick().unwrap();
        for h in handles {
            let (r, e) = h.join().unwrap();
            assert_eq!(r, WakeOutcome::Notified);
            assert!(e < Duration::from_millis(200));
        }
    }

    const SLOTS: usize = 4;

    fn set4() -> WfiWakeSet {
        WfiWakeSet::new(4).unwrap()
    }

    /// 各スロットを別スレッドで `limit` まで待たせ、全員が待ちに入った後 20 ms で `fire` を呼び、(結果, 経過) を返す。
    fn run_waiters(
        set: &WfiWakeSet,
        limit: Duration,
        fire: impl FnOnce(&WfiWakeSet),
    ) -> Vec<(WakeOutcome, Duration)> {
        let barrier = Arc::new(std::sync::Barrier::new(SLOTS + 1));
        let handles: Vec<_> = (0..SLOTS as u32)
            .map(|i| {
                let w = set.handle(i).unwrap();
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    let s = Instant::now();
                    (w.wait(limit), s.elapsed())
                })
            })
            .collect();
        barrier.wait();
        std::thread::sleep(Duration::from_millis(20));
        fire(set);
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    }

    /// 宛先の 1 台だけが上限を待たず戻り、他の 3 台は起きずに期限まで待つ（#3948）。
    #[test]
    fn repair5_mvm5_3948_targeted_notify_wakes_only_target() {
        let set = set4();
        let r = run_waiters(&set, Duration::from_millis(300), |s| s.notify_vcpu(2));
        for (i, (out, el)) in r.iter().enumerate() {
            if i == 2 {
                assert_eq!(*out, WakeOutcome::Notified);
                assert!(*el < Duration::from_millis(250), "target waited {el:?}");
            } else {
                assert_eq!(*out, WakeOutcome::TimedOut, "slot {i}");
                assert!(*el >= Duration::from_millis(300), "slot {i} woke at {el:?}");
            }
        }
    }

    /// 決定的な版: 通知の後に各スロットの既読を即時に見る（#3948）。
    #[test]
    fn repair5_mvm5_3948_targeted_notify_leaves_others_pending_free() {
        let set = set4();
        set.notify_vcpu(1);
        for i in 0..SLOTS as u32 {
            let want = if i == 1 {
                WakeOutcome::Notified
            } else {
                WakeOutcome::TimedOut
            };
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                want,
                "slot {i}"
            );
        }
    }

    #[test]
    fn repair5_mvm5_3948_notify_all_wakes_every_slot() {
        let set = set4();
        let r = run_waiters(&set, Duration::from_secs(1), |s| s.notify_all());
        assert_eq!(r.len(), SLOTS);
        for (out, el) in r {
            assert_eq!(out, WakeOutcome::Notified);
            assert!(el < Duration::from_millis(500));
        }
    }

    #[test]
    fn repair5_mvm5_3948_out_of_range_target_falls_back_to_all() {
        let set = set4();
        set.notify_vcpu(4);
        for i in 0..SLOTS as u32 {
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                WakeOutcome::Notified
            );
        }
    }

    /// 停止の kick は全スロットを起こし、inner の失敗も透過する（#3948）。
    #[test]
    fn repair5_mvm5_3948_waking_kick_with_set_wakes_all() {
        let set = set4();
        let k = WakingKick::new(
            FakeKick(Err(MicrovmErrorCode::FailedPrecondition)),
            set.clone(),
        );
        let e = k.kick().unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        for i in 0..SLOTS as u32 {
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                WakeOutcome::Notified
            );
        }
        WakingKick::new(FakeKick(Ok(())), set.clone())
            .kick()
            .unwrap();
        for i in 0..SLOTS as u32 {
            assert_eq!(
                set.handle(i).unwrap().wait(Duration::ZERO),
                WakeOutcome::Notified
            );
        }
    }

    /// vCPU 1 台なら、どの経路の通知も従来の単一 waker と同じ（1 回だけ起こす）（#3948）。
    #[test]
    fn repair5_mvm5_3948_single_vcpu_unchanged() {
        let set = WfiWakeSet::new(1).unwrap();
        let w = set.handle(0).unwrap();
        let paths: [&dyn Fn(); 2] = [&|| set.notify_vcpu(0), &|| set.notify_all()];
        for fire in paths {
            fire();
            assert_eq!(w.wait(Duration::ZERO), WakeOutcome::Notified);
            assert_eq!(w.wait(Duration::ZERO), WakeOutcome::TimedOut);
        }
    }

    #[test]
    fn mvm5_3948_wake_set_rejects_invalid_vcpu_count() {
        assert_eq!(
            WfiWakeSet::new(0).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            WfiWakeSet::new(HVF_MAX_VCPUS + 1).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        let set = WfiWakeSet::new(HVF_MAX_VCPUS).unwrap();
        assert!(set.handle(HVF_MAX_VCPUS - 1).is_ok());
        assert_eq!(
            set.handle(HVF_MAX_VCPUS).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        let two = WfiWakeSet::new(2).unwrap();
        assert_eq!(
            two.handle(2).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
    }
}
