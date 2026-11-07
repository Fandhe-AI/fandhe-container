//! virtio-net の受信ポーラーの OS 非依存部分（#4030・MVM-5・MVM-1・REPAIR-5）。`unsafe` なし・全 OS でビルドする。
//!
//! 役割: ゲストの kick なしに、ホスト側 backend のフレームを受信キューへ配送して割り込みを上げる周期処理の共通部品を置く。
//! `NetBackend::recv` は待たない API で到着通知を持たないため、周期で取り出す（Linux の `microvm-net-rx`・#3742 と同じ判断）。
//!
//! 呼び出し元と使い分け:
//! - macOS（`hvf::microvm`）: [`spawn_net_rx_poller`] で専用スレッド `hvf-net-rx` を起動し、`HvfMicroVm::start` がゲートを開く前に
//!   結ぶ。停止は `hvf_lifecycle::StopWithAux` 経由で vCPU の停止を確かめた後に行い、RAM の解放はその後になる。
//! - Linux（`microvm::NetRxPoller`）: 周期の検査（[`check_net_rx_poll_interval`]）・集計（`NetRxPollReport`）・失敗の判定
//!   （`poll_failure`）だけを共有する。スレッド機構（`StopAggregate` と `VcpuLoopBody`）は Linux 専用の土台に乗っており、
//!   macOS の `hvf_loop::spawn_loop` / `LoopHandle` / `VmShutdown` と統合しない（両者は同じ契約を別の機構で満たす。REPAIR-3）。
//!
//! 契約:
//! - 待ちはすべて期限つき。周期は `[NET_RX_POLL_INTERVAL_MIN, NET_RX_POLL_INTERVAL_MAX]` に制限し、停止・VM の終了の要求で即座に起きる。
//! - 1 回の処理量は「net デバイス数 x キュー長」で頭打ち。リング破損・lock の poison・割り込み線の失敗は fail-closed で
//!   `Failed(code)` にし、`VmShutdown` で VM 全体を止める。ログは固定語彙のコードだけで、ゲスト由来の文字列は載せない（ERR-1）。
//! - スレッドは終了の直前に routes（transport、ゲスト RAM のスロット、線の保持）を落としてから報告を送る。つまり停止の報告を
//!   受けた時点で、このスレッドが持つ RAM への参照は無い。
//!
//! 将来仕様（REPAIR-3）: backend の到着通知（TAP の fd の poll 等）への置き換えは TASK-75・TASK-117。アイドル時の起床は
//! 毎秒 100 回（Linux と同値）で、CORE-7 の実測で問題になったら見直す。

use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_abi::HvRunStats;
use crate::hvf_lifecycle::AuxStopper;
use crate::hvf_loop::{
    LoopHandle, LoopStart, VCPU_CREATE_DEADLINE_DEFAULT, VcpuKick, log_line, spawn_loop,
};
use crate::hvf_smp::VmShutdown;
use crate::interrupt::{NetQueueStats, NetRxPollOutcome, NetRxPollRoute};
use crate::stop::StopReason;

/// 受信ポーラーが backend のフレームを確かめる周期（#3742・MVM-1・REPAIR-5）。値は暫定。
///
/// 受信遅延の上限になる。busy loop にしないため下限は 1ms（[`NET_RX_POLL_INTERVAL_MIN`]）。待ちは停止要求で即座に起きる。
pub const NET_RX_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// 受信ポーラーの周期の下限（0 による busy loop を防ぐ）。
pub const NET_RX_POLL_INTERVAL_MIN: Duration = Duration::from_millis(1);
/// 受信ポーラーの周期の上限（無期限に近い周期で受信が止まるのを防ぐ）。
pub const NET_RX_POLL_INTERVAL_MAX: Duration = Duration::from_secs(1);

/// 周期を `[NET_RX_POLL_INTERVAL_MIN, NET_RX_POLL_INTERVAL_MAX]` に検証する（範囲外は `InvalidArgument`）。
pub fn check_net_rx_poll_interval(interval: Duration) -> Result<(), MicrovmError> {
    if !(NET_RX_POLL_INTERVAL_MIN..=NET_RX_POLL_INTERVAL_MAX).contains(&interval) {
        return Err(MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "net rx poll interval out of range",
        ));
    }
    Ok(())
}

/// 1 周期ぶん（全 net デバイスを 1 回ずつ処理した）の集計（crate 内。REPAIR-4）。
#[derive(Debug, Default)]
pub(crate) struct NetRxPollReport {
    /// `process_rx` を呼んだデバイス数。
    pub(crate) polled: u32,
    /// 状態（未 activate・FAILED・キュー停止）で飛ばしたデバイス数。
    pub(crate) skipped: u32,
    /// used へ返した数の合計。
    pub(crate) completed: u32,
    /// ゲストのバッファへ配送したフレーム数の合計。
    pub(crate) delivered: u32,
    /// 注入した割り込みの回数。
    pub(crate) interrupts: u32,
    /// 最初に見つかったリング破損など（ゲスト起因）。
    pub(crate) queue_error: Option<MicrovmError>,
}

impl NetRxPollReport {
    /// 1 台分の結果を足す。`queue_error` が出たら `Break`（呼び出し元はそこで巡回を打ち切る。fail-closed）。
    pub(crate) fn record(&mut self, outcome: NetRxPollOutcome) -> ControlFlow<()> {
        match outcome {
            NetRxPollOutcome::Skipped(_) => self.skipped += 1,
            NetRxPollOutcome::Polled(r) => {
                self.polled += 1;
                if let NetQueueStats::Rx(s) = r.stats {
                    self.delivered = self.delivered.saturating_add(s.delivered);
                }
                self.completed = self.completed.saturating_add(r.stats.completed());
                if r.delivery == crate::interrupt::InterruptDelivery::Triggered {
                    self.interrupts += 1;
                }
                if let Some(e) = r.queue_error {
                    self.queue_error = Some(e);
                    return ControlFlow::Break(());
                }
            }
        }
        ControlFlow::Continue(())
    }
}

/// 1 周期の結果から、ポーラーが止まるべき失敗を取り出す。外側の `Err`（lock の poison・割り込み線の失敗）と、
/// `Ok` の中の `queue_error`（リング破損）のどちらも失敗で、どちらも無ければ `None`（続ける）。ログは呼び出し側が出す。
pub(crate) fn poll_failure(result: Result<NetRxPollReport, MicrovmError>) -> Option<MicrovmError> {
    match result {
        Ok(report) => report.queue_error,
        Err(e) => Some(e),
    }
}

/// 全 net デバイスを 1 回ずつ処理する（1 回の処理量は台数 x キュー長で頭打ち）。最初の `queue_error` で打ち切る。
pub(crate) fn poll_routes(
    routes: &[Arc<dyn NetRxPollRoute>],
) -> Result<NetRxPollReport, MicrovmError> {
    let mut report = NetRxPollReport::default();
    for route in routes {
        if report.record(route.poll_rx()?).is_break() {
            break;
        }
    }
    Ok(report)
}

/// 周期の待ちと即時の起床（世代番号つき。起床を取りこぼさない）。
struct NetRxWake {
    generation: Mutex<u64>,
    cv: Condvar,
}

impl NetRxWake {
    fn new() -> Self {
        Self {
            generation: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    /// 現在の世代。停止フラグを見る前に取り、[`Self::wait_after`] へ渡す（間の起床を取りこぼさない）。
    fn generation(&self) -> u64 {
        *self.generation.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 世代を進めて待ち手を起こす。
    fn notify(&self) {
        let mut g = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        *g = g.wrapping_add(1);
        self.cv.notify_all();
    }

    /// 世代が `seen` から進むか `interval` が過ぎるまで待つ。
    fn wait_after(&self, seen: u64, interval: Duration) {
        let g = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        drop(
            self.cv
                .wait_timeout_while(g, interval, |cur| *cur == seen)
                .unwrap_or_else(|e| e.into_inner()),
        );
    }
}

/// `LoopHandle` の kick（ポーラーを即座に起こす）。
struct NetRxKick(Arc<NetRxWake>);

impl VcpuKick for NetRxKick {
    fn kick(&self) -> Result<(), MicrovmError> {
        self.0.notify();
        Ok(())
    }
}

/// 起動済みの受信ポーラー（スレッド `hvf-net-rx`）の操作口。
pub struct NetRxPollerHandle {
    inner: LoopHandle<NetRxKick>,
}

impl std::fmt::Debug for NetRxPollerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetRxPollerHandle")
            .field("finished", &self.is_finished())
            .finish_non_exhaustive()
    }
}

impl NetRxPollerHandle {
    /// スレッドが既に終わったか（失敗による終了を含む）。
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    /// 停止を要求し、`deadline`（0 超 60 秒以下）まで終了報告を待つ。`Ok` で戻った時点で routes は解放済み。
    pub fn stop(self, deadline: Duration) -> Result<StopReason, MicrovmError> {
        self.inner.stop(deadline).map(|r| r.reason)
    }
}

impl AuxStopper for NetRxPollerHandle {
    fn stop(self, deadline: Duration) -> Result<StopReason, MicrovmError> {
        NetRxPollerHandle::stop(self, deadline)
    }
}

/// 受信ポーラーのスレッドを起動する（macOS の `HvfMicroVm::start` が呼ぶ）。
///
/// 周期を検証し、routes が空なら `InvalidArgument`。スレッドは `shutdown` の参加者になり、VM の終了で止まる。ポーラー自身が
/// 失敗したら `shutdown.on_vcpu_end` で全 vCPU を止める（fail-closed）。
pub fn spawn_net_rx_poller(
    routes: Vec<Arc<dyn NetRxPollRoute>>,
    interval: Duration,
    shutdown: Arc<VmShutdown>,
) -> Result<NetRxPollerHandle, MicrovmError> {
    check_net_rx_poll_interval(interval)?;
    if routes.is_empty() {
        return Err(MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "net rx poller needs at least one device",
        ));
    }
    let inner = spawn_loop::<NetRxKick, _>(
        "hvf-net-rx",
        VCPU_CREATE_DEADLINE_DEFAULT,
        move |start: LoopStart<NetRxKick>| {
            let wake = Arc::new(NetRxWake::new());
            let stop = start.ready(NetRxKick(Arc::clone(&wake)));
            let peer_wake = Arc::clone(&wake);
            shutdown.register(Arc::clone(&stop), Box::new(move || peer_wake.notify()));
            let reason = poll_loop(&routes, interval, &stop, &wake);
            shutdown.on_vcpu_end(reason);
            // 報告より前に routes（transport、RAM のスロット、線）を落とす。
            drop(routes);
            (reason, HvRunStats::default())
        },
    )?;
    Ok(NetRxPollerHandle { inner })
}

/// 停止フラグが立つか失敗するまで、周期ごとに全デバイスを処理する。
fn poll_loop(
    routes: &[Arc<dyn NetRxPollRoute>],
    interval: Duration,
    stop: &AtomicBool,
    wake: &NetRxWake,
) -> StopReason {
    loop {
        let seen = wake.generation();
        if stop.load(Ordering::Acquire) {
            return StopReason::Requested;
        }
        wake.wait_after(seen, interval);
        if stop.load(Ordering::Acquire) {
            return StopReason::Requested;
        }
        if let Some(e) = poll_failure(poll_routes(routes)) {
            log_line(format_args!(
                "level=error op=hvf.net_rx_poll outcome=error code={}",
                e.code().as_str()
            ));
            return StopReason::Failed(e.code());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU32;
    use std::time::Instant;

    use super::*;
    use crate::interrupt::{InterruptDelivery, NetNotifyReport, NetRxPollSkip};
    use crate::virtio_net::NetRxStats;

    fn polled(
        rx: NetRxStats,
        delivery: InterruptDelivery,
        queue_error: Option<MicrovmError>,
    ) -> NetRxPollOutcome {
        NetRxPollOutcome::Polled(NetNotifyReport {
            stats: NetQueueStats::Rx(rx),
            delivery,
            queue_error,
        })
    }

    #[test]
    fn mvm5_4030_interval_range_is_checked() {
        for bad in [
            Duration::ZERO,
            NET_RX_POLL_INTERVAL_MIN - Duration::from_nanos(1),
            NET_RX_POLL_INTERVAL_MAX + Duration::from_nanos(1),
        ] {
            let e = check_net_rx_poll_interval(bad).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        }
        assert!(check_net_rx_poll_interval(NET_RX_POLL_INTERVAL).is_ok());
        assert!(check_net_rx_poll_interval(NET_RX_POLL_INTERVAL_MIN).is_ok());
        assert!(check_net_rx_poll_interval(NET_RX_POLL_INTERVAL_MAX).is_ok());
    }

    #[test]
    fn mvm5_4030_report_counts_skip_and_delivery() {
        let mut r = NetRxPollReport::default();
        assert!(
            r.record(NetRxPollOutcome::Skipped(NetRxPollSkip::NotActive))
                .is_continue()
        );
        assert_eq!((r.skipped, r.polled), (1, 0));
        let rx = NetRxStats {
            completed: 1,
            delivered: 1,
            ..NetRxStats::default()
        };
        assert!(
            r.record(polled(rx, InterruptDelivery::Triggered, None))
                .is_continue()
        );
        assert_eq!(
            (r.polled, r.completed, r.delivered, r.interrupts),
            (1, 1, 1, 1)
        );
        assert!(r.queue_error.is_none());
    }

    #[test]
    fn mvm5_4030_report_breaks_on_queue_error() {
        let mut r = NetRxPollReport::default();
        let err = MicrovmError::new(MicrovmErrorCode::InvalidArgument, "corrupt");
        let flow = r.record(polled(
            NetRxStats::default(),
            InterruptDelivery::NotNeeded,
            Some(err),
        ));
        assert!(flow.is_break());
        assert_eq!(
            r.queue_error.as_ref().map(MicrovmError::code),
            Some(MicrovmErrorCode::InvalidArgument)
        );
    }

    #[test]
    fn mvm5_4030_poll_failure_covers_err_and_queue_error() {
        assert!(poll_failure(Ok(NetRxPollReport::default())).is_none());
        let outer = MicrovmError::new(MicrovmErrorCode::Internal, "lock");
        assert_eq!(
            poll_failure(Err(outer)).map(|e| e.code()),
            Some(MicrovmErrorCode::Internal)
        );
        let inner = NetRxPollReport {
            queue_error: Some(MicrovmError::new(MicrovmErrorCode::InvalidArgument, "x")),
            ..NetRxPollReport::default()
        };
        assert_eq!(
            poll_failure(Ok(inner)).map(|e| e.code()),
            Some(MicrovmErrorCode::InvalidArgument)
        );
    }

    /// 呼ばれた回数を数え、指定の結果を返す偽の route。
    #[derive(Debug)]
    struct FakeRoute {
        calls: Arc<AtomicU32>,
        fail: bool,
    }

    impl NetRxPollRoute for FakeRoute {
        fn poll_rx(&self) -> Result<NetRxPollOutcome, MicrovmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Ok(polled(
                    NetRxStats::default(),
                    InterruptDelivery::NotNeeded,
                    Some(MicrovmError::new(MicrovmErrorCode::InvalidArgument, "bad")),
                ));
            }
            Ok(NetRxPollOutcome::Skipped(NetRxPollSkip::NotActive))
        }
    }

    fn fake(fail: bool) -> (Arc<AtomicU32>, Arc<dyn NetRxPollRoute>) {
        let calls = Arc::new(AtomicU32::new(0));
        let route: Arc<dyn NetRxPollRoute> = Arc::new(FakeRoute {
            calls: Arc::clone(&calls),
            fail,
        });
        (calls, route)
    }

    #[test]
    fn mvm5_4030_poll_routes_stops_after_first_queue_error() {
        let (c1, r1) = fake(true);
        let (c2, r2) = fake(false);
        let report = poll_routes(&[r1, r2]).unwrap();
        assert!(report.queue_error.is_some());
        assert_eq!(
            (c1.load(Ordering::SeqCst), c2.load(Ordering::SeqCst)),
            (1, 0)
        );
    }

    #[test]
    fn mvm5_4030_empty_routes_and_bad_interval_are_rejected() {
        let sd = Arc::new(VmShutdown::new());
        let e = spawn_net_rx_poller(Vec::new(), NET_RX_POLL_INTERVAL, Arc::clone(&sd)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        let (_, r) = fake(false);
        let e = spawn_net_rx_poller(vec![r], Duration::ZERO, sd).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    }

    /// REPAIR-5: 周期が上限（1s）でも、stop は kick で即座に起こして期限内に戻る。
    #[test]
    fn repair5_4030_stop_returns_within_deadline_with_long_interval() {
        let (_, r) = fake(false);
        let h = spawn_net_rx_poller(
            vec![r],
            NET_RX_POLL_INTERVAL_MAX,
            Arc::new(VmShutdown::new()),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let t = Instant::now();
        let reason = h.stop(Duration::from_millis(500)).unwrap();
        assert_eq!(reason, StopReason::Requested);
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "{:?}",
            t.elapsed()
        );
    }

    /// 失敗は VM 全体の終了として登録済みの peer を止め、stop の報告は `Failed(InvalidArgument)`。
    #[test]
    fn mvm5_4030_failure_triggers_vm_shutdown() {
        let sd = Arc::new(VmShutdown::new());
        let peer_stop = Arc::new(AtomicBool::new(false));
        sd.register(Arc::clone(&peer_stop), Box::new(|| {}));
        let (_, r) = fake(true);
        let h = spawn_net_rx_poller(vec![r], Duration::from_millis(2), Arc::clone(&sd)).unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        while !h.is_finished() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(peer_stop.load(Ordering::SeqCst));
        assert!(sd.is_triggered());
        assert_eq!(
            h.stop(Duration::from_secs(2)).unwrap(),
            StopReason::Failed(MicrovmErrorCode::InvalidArgument)
        );
    }

    /// VM の終了通知（外からの trigger）でポーラーが期限内に止まり、報告は `Requested`。
    #[test]
    fn mvm5_4030_vm_shutdown_stops_poller() {
        let sd = Arc::new(VmShutdown::new());
        let (_, r) = fake(false);
        let h = spawn_net_rx_poller(vec![r], NET_RX_POLL_INTERVAL_MAX, Arc::clone(&sd)).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        sd.trigger();
        let end = Instant::now() + Duration::from_secs(2);
        while !h.is_finished() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(h.is_finished());
        assert_eq!(
            h.stop(Duration::from_secs(2)).unwrap(),
            StopReason::Requested
        );
    }
}
