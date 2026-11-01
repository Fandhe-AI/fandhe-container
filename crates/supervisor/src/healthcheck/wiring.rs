//! healthcheck の周期実行を監視ループへ配線する部品（TASK-161・#2953・SUP-4。関連: SUP-1・SUP-3・SUP-6・REPAIR-3・REPAIR-4・REPAIR-5・SEC-1）。
//!
//! 役割: [`super::run_periodic`] を「monitor の 1 回の呼び出し」の間だけ専用スレッドで回し、戻る前に期限つきで止めて回収する。
//! 呼び出し元は `crate::run::monitor_with_health`（監視権の取得の後に [`HealthWorker`] を起動し、終了検知・stop・wait の失敗の
//! 全経路で [`HealthWorker::stop_and_join`] を呼ぶ）と、その外側の `crate::restart::supervise_with_restart_health`
//! （世代ごとに monitor を呼ぶので、周期実行は再 launch のたびに新しいプロセスへ付け替わる）。supervisor の入口
//! （`crate::start_entry`）は、起動オプション文書の healthcheck 定義から [`HealthWiring`] を組んで渡す。
//! 呼び出し先は `run_periodic`（判定・集約・`health` の記録）と、[`HealthProbeFactory`] が作る [`crate::health::HealthProbe`]
//! （Linux の本番は [`ExecHealthProbeFactory`] が作る `ExecHealthProbe`）。
//!
//! # 設計判断（spec の確定値ではなく本実装の判断）
//! - 寿命は monitor の 1 回の呼び出しに結びつける。`LauncherRelauncher` の単一スレッド要求（SUP-3・CORE-1）は
//!   「monitor が戻った時点で healthcheck のスレッドが居ない」ことで満たす。join が期限（[`HEALTH_STOP_LIMIT`]）内に終わらず
//!   スレッドが残った場合は、既存の `thread_settle` が再 launch を `RelaunchFailed` で止める（fail-closed）。
//! - probe は 1 起動世代につき 1 つ作る（[`HealthProbeFactory::probe_for`]）。pidfd の複製は monitor のスレッド上で
//!   起動ハンドルから取り、記録された pid を宛先に使わない（SEC-1）。
//! - 作れないとき（pidfd が無い・非 Linux）は [`FailingProbe`] で周期実行を回す。start_period と retries の後に
//!   `Unhealthy` になり、`Healthy` にならない（fail-closed）。スレッドを作れないときは `Unhealthy` を 1 回記録する。
//! - 周期実行のスレッドは `LaunchedProcess` を持てない（`Send` だが `wait` を呼ぶ権利を渡さない）ため、pid だけを持つ
//!   [`PidView`] を渡す（`run_periodic` と `health` が使うのは `pid()` だけ）。
//! - 観測イベントはスレッドから有界のチャネルで monitor のスレッドへ運び、`MonitorObserver`（`Sync` でない）へ転送する。
//!
//! 未実装（REPAIR-3）: CLI の `create` が healthcheck 定義を文書へ書く処理（書き手が無い間は本番の経路は動かない）、
//! `monitor_with_capture` への組み込み（本番は `supervise_with_restart` の経路を使う）、
//! `ExecHealthProbe::last_report` の inspect への表示。

use std::num::NonZeroU32;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{ErrorCode, HealthStatus, TraitError};

use super::periodic::{HealthcheckClock, HealthcheckLoopOutcome, HealthcheckSchedule};
use super::{HealthcheckDefinition, run_periodic};
use crate::health::{HealthProbe, ProbeRunner};
use crate::run::{MonitorEvent, MonitorObserver, StopToken};
use crate::state::SupervisedState;

/// 周期実行の停止から回収までの待ちの上限。`ExecHealthProbe` の cgroup.kill（1 秒）と回収（1 秒）に余裕を足した
/// 本実装の判断（REPAIR-5）。超過したらスレッドを切り離して先へ進む。
pub const HEALTH_STOP_LIMIT: Duration = Duration::from_secs(3);

/// 停止待ちの間に実行中の試行へ cancel を再送する刻み（試行の開始と停止要求が競合しても取りこぼさない）。
const STOP_POLL: Duration = Duration::from_millis(25);

/// 時計の待ちの最大刻み（起床の合図の取りこぼしを許さない保険）。
const CLOCK_SLICE: Duration = Duration::from_millis(200);

/// 観測イベントのチャネルの容量（満杯なら捨てる。REPAIR-5）。
const EVENT_QUEUE: usize = 256;

/// 1 起動世代ぶんの [`HealthProbe`] を作る口（試験で偽物に替える）。
///
/// 呼び出しは monitor のスレッド上で、起動ハンドルが生きている間に行う（pidfd の複製を取るため）。
pub trait HealthProbeFactory: Send + Sync {
    /// `process` に対応する probe を作る。失敗したら周期実行は [`FailingProbe`] で回る（`Healthy` にならない）。
    fn probe_for(&self, process: &dyn LaunchedProcess) -> Result<Arc<dyn HealthProbe>, TraitError>;
}

/// 検証済みの周期実行スケジュールと probe の工場（`monitor_with_health` へ渡す配線）。
#[derive(Clone)]
pub struct HealthWiring {
    schedule: HealthcheckSchedule,
    factory: Arc<dyn HealthProbeFactory>,
}

impl std::fmt::Debug for HealthWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HealthWiring")
            .field("schedule", &self.schedule)
            .finish_non_exhaustive()
    }
}

impl HealthWiring {
    /// 定義を検証して作る（timeout が周期実行の上限を超えるなら `InvalidArgument`）。
    pub fn new(
        definition: &HealthcheckDefinition,
        factory: Arc<dyn HealthProbeFactory>,
    ) -> Result<Self, TraitError> {
        Ok(Self {
            schedule: HealthcheckSchedule::from_definition(definition)?,
            factory,
        })
    }

    /// 検証済みのスケジュール。
    pub fn schedule(&self) -> &HealthcheckSchedule {
        &self.schedule
    }

    /// 周期実行を起動する。`state` は monitor の保持するハンドルで、別の attach を作ってスレッドへ渡す。
    ///
    /// probe を作れないときは [`FailingProbe`] で回す（構造化ログ `healthcheck_probe_unavailable`）。
    /// attach・スレッド作成の失敗は `Err`（呼び出し側は `Unhealthy` を記録して監視を続ける）。
    pub(crate) fn start_worker(
        &self,
        state: &SupervisedState,
        process: &dyn LaunchedProcess,
    ) -> Result<HealthWorker, TraitError> {
        let probe: Arc<dyn HealthProbe> = match self.factory.probe_for(process) {
            Ok(p) => p,
            Err(e) => {
                let line = format!(
                    "{{\"component\":\"supervisor.healthcheck\",\"event\":\"healthcheck_probe_unavailable\",\"code\":\"{}\"}}\n",
                    e.code().as_str()
                );
                // 満杯・書き込み失敗でも周期実行は止めない（ログの欠落は許す。REPAIR-5）。
                let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
                Arc::new(FailingProbe)
            }
        };
        let sibling = state.attach_sibling()?;
        HealthWorker::spawn(self.schedule, sibling, process.pid(), probe)
    }
}

/// 作れなかった probe の代わりに、常に失敗を返す probe（`Healthy` を装わない。SUP-4 の fail-closed）。
///
/// `FailedPrecondition` は周期実行の停止条件と区別がつかなくなるため使わない。
#[derive(Debug, Clone, Copy, Default)]
pub struct FailingProbe;

impl HealthProbe for FailingProbe {
    fn probe(&self, _timeout: Duration) -> Result<HealthStatus, TraitError> {
        Err(TraitError::new(
            ErrorCode::Internal,
            "healthcheck probe is unavailable",
        ))
    }
}

/// 停止要求で即座に起こせる時計（周期実行の停止が interval の刻みの分だけ遅れないようにする）。
#[derive(Debug, Default)]
pub struct WakeableClock {
    woken: Mutex<bool>,
    cv: Condvar,
}

impl WakeableClock {
    /// 待っているスレッドを起こす（以降の `sleep_until` はすぐ `false` で戻る）。
    pub fn wake(&self) {
        *self.woken.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.cv.notify_all();
    }
}

impl HealthcheckClock for WakeableClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, deadline: Instant, stop: &StopToken) -> bool {
        let mut guard = self.woken.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if stop.is_stop_requested() || *guard {
                return false;
            }
            let now = Instant::now();
            if now >= deadline {
                return true;
            }
            let slice = (deadline - now).min(CLOCK_SLICE);
            guard = self
                .cv
                .wait_timeout(guard, slice)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// 周期実行のスレッドへ渡す、pid だけを持つ起動ハンドルの代役。
///
/// `run_periodic` と `crate::health` が使うのは [`LaunchedProcess::pid`] だけ（記録との照合用）。`wait` は呼ばれない
/// 前提で `Ok(None)`、`terminate` は `FailedPrecondition` を返し、本物の回収の権利は monitor のスレッドだけが持つ。
#[derive(Debug, Clone, Copy)]
pub(crate) struct PidView(pub(crate) NonZeroU32);

impl LaunchedProcess for PidView {
    fn pid(&self) -> NonZeroU32 {
        self.0
    }

    fn wait(&self, _timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        Ok(None)
    }

    fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
        Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "the healthcheck worker cannot terminate the container",
        ))
    }
}

/// スレッド側の観測器: イベントを有界のチャネルへ送る（満杯なら捨てる。スレッドを塞がない）。
struct ChannelObserver(SyncSender<MonitorEvent>);

impl MonitorObserver for ChannelObserver {
    fn observe(&self, event: &MonitorEvent) {
        let _ = self.0.try_send(event.clone());
    }
}

/// 周期実行の停止と回収（`HealthWorker::stop_and_join`）の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HealthStopReport {
    /// 期限内に終わり、join した。
    Joined,
    /// 期限内に終わらず、スレッドを切り離した（`unfinished` は戻っていない probe / cancel の数）。
    TimedOut {
        /// 戻っていない probe / cancel スレッドの数。
        unfinished: usize,
    },
}

/// 周期実行の専用スレッド 1 本（起動・停止・回収）。`Drop` は停止を要求するだけで join しない。
pub(crate) struct HealthWorker {
    stop: StopToken,
    clock: Arc<WakeableClock>,
    runner: ProbeRunner,
    done: Receiver<HealthcheckLoopOutcome>,
    events: Receiver<MonitorEvent>,
    handle: Option<JoinHandle<()>>,
}

impl HealthWorker {
    fn spawn(
        schedule: HealthcheckSchedule,
        mut state: SupervisedState,
        pid: NonZeroU32,
        probe: Arc<dyn HealthProbe>,
    ) -> Result<Self, TraitError> {
        let stop = StopToken::new();
        let clock = Arc::new(WakeableClock::default());
        let runner = ProbeRunner::new(probe);
        let (done_tx, done) = mpsc::channel();
        let (event_tx, events) = mpsc::sync_channel(EVENT_QUEUE);
        let (t_stop, t_clock, t_runner) = (stop.clone(), Arc::clone(&clock), runner.clone());
        let handle = std::thread::Builder::new()
            .name("healthcheck-periodic".to_owned())
            .spawn(move || {
                let obs = ChannelObserver(event_tx);
                let process = PidView(pid);
                let outcome = run_periodic(
                    &schedule,
                    &mut state,
                    &process,
                    &t_runner,
                    t_clock.as_ref(),
                    &t_stop,
                    &obs,
                    &mut |_| {},
                );
                let _ = done_tx.send(outcome);
            })
            .map_err(|_| {
                TraitError::new(
                    ErrorCode::Internal,
                    "failed to spawn the healthcheck periodic thread",
                )
            })?;
        Ok(Self {
            stop,
            clock,
            runner,
            done,
            events,
            handle: Some(handle),
        })
    }

    /// スレッドが溜めた観測イベントを `obs` へ転送する（monitor のスレッドから呼ぶ）。
    pub(crate) fn drain_events(&self, obs: &dyn MonitorObserver) {
        while let Ok(event) = self.events.try_recv() {
            obs.observe(&event);
        }
    }

    /// 停止を要求し、実行中の試行を cancel し、`limit` まで終了を待って join する（REPAIR-5）。
    ///
    /// 待ちの間は cancel を再送する。`HealthProbe::cancel` は呼ばない（実装によってはブロックし得るため）。
    /// 期限を過ぎたらスレッドを切り離す（書き込みは revision と「Running かつ起動 pid」の検査で止まる）。
    pub(crate) fn stop_and_join(&mut self, limit: Duration) -> HealthStopReport {
        self.stop.request_stop();
        self.clock.wake();
        let deadline = Instant::now() + limit;
        let finished = loop {
            self.runner.cancel_in_flight();
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.done.recv_timeout(remaining.min(STOP_POLL)) {
                // 送信側が落ちた（スレッドが panic 等で終わった）場合も終了とみなす。
                Ok(_) | Err(RecvTimeoutError::Disconnected) => break true,
                Err(RecvTimeoutError::Timeout) if Instant::now() >= deadline => break false,
                Err(RecvTimeoutError::Timeout) => {}
            }
        };
        match (finished, self.handle.take()) {
            (true, Some(handle)) => {
                let _ = handle.join();
                HealthStopReport::Joined
            }
            (true, None) => HealthStopReport::Joined,
            (false, _) => HealthStopReport::TimedOut {
                unfinished: self.runner.unfinished(),
            },
        }
    }
}

impl Drop for HealthWorker {
    fn drop(&mut self) {
        // join はしない（呼び出し側の `stop_and_join` が期限つきで行う）。取りこぼしても周期実行は止まる。
        self.stop.request_stop();
        self.clock.wake();
    }
}

/// Linux の本番: exec 専用 helper で healthcheck コマンドを実行する probe の工場（SUP-4・SUP-6・#2441）。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct ExecHealthProbeFactory {
    definition: HealthcheckDefinition,
    state_root: std::path::PathBuf,
    id: fandhe_container_core::traits::ContainerId,
}

#[cfg(target_os = "linux")]
impl ExecHealthProbeFactory {
    /// 定義・状態ルート・コンテナ ID から作る（`state_root` は helper が状態を開く場所）。
    pub fn new(
        definition: HealthcheckDefinition,
        state_root: std::path::PathBuf,
        id: fandhe_container_core::traits::ContainerId,
    ) -> Self {
        Self {
            definition,
            state_root,
            id,
        }
    }
}

#[cfg(target_os = "linux")]
impl HealthProbeFactory for ExecHealthProbeFactory {
    fn probe_for(&self, process: &dyn LaunchedProcess) -> Result<Arc<dyn HealthProbe>, TraitError> {
        let target = super::HealthExecTarget::from_launched(
            self.state_root.clone(),
            self.id.clone(),
            process,
        )?;
        Ok(Arc::new(super::ExecHealthProbe::new(
            &self.definition,
            target,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SUP-4・REPAIR-5（#2953）: 起床の合図で `sleep_until` が interval の刻みを待たずに `false` で戻り、
    /// 期限が先に来れば `true` で戻る。
    #[test]
    fn sup4_2953_wakeable_clock_wakes_immediately() {
        let clock = Arc::new(WakeableClock::default());
        let stop = StopToken::new();
        let waker = Arc::clone(&clock);
        let started = Instant::now();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            waker.wake();
        });
        let slept = clock.sleep_until(Instant::now() + Duration::from_secs(30), &stop);
        t.join().unwrap();
        assert!(!slept);
        assert!(started.elapsed() < Duration::from_secs(5));
        let clock = WakeableClock::default();
        assert!(clock.sleep_until(Instant::now() + Duration::from_millis(5), &stop));
    }

    /// SUP-4（#2953）: probe を作れなかったときの代役は常に失敗し、`Healthy` を返さない（`FailedPrecondition` も使わない）。
    #[test]
    fn sup4_2953_failing_probe_never_healthy() {
        let e = FailingProbe.probe(Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(e.message(), "healthcheck probe is unavailable");
    }

    /// `PidView` は pid だけを返し、回収の権利（wait の結果・terminate）を持たない。
    #[test]
    fn sup4_2953_pid_view_exposes_only_the_pid() {
        let v = PidView(NonZeroU32::new(7).unwrap());
        assert_eq!(v.pid().get(), 7);
        assert_eq!(v.wait(Duration::ZERO).unwrap(), None);
        assert_eq!(
            v.terminate(Duration::ZERO).unwrap_err().code(),
            ErrorCode::FailedPrecondition
        );
    }
}
