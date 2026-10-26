//! healthcheck の周期実行エンジン（TASK-161.2・#495・SUP-4・MS-9。関連: SUP-1・SUP-6・REPAIR-3・REPAIR-4・REPAIR-5）。
//!
//! 役割: [`super::HealthcheckDefinition`] の interval ごとに、1 回分の判定と記録 [`crate::health::probe_and_record`]
//! を繰り返し呼ぶ。呼び出し元は専用スレッドで [`run_periodic`] を回す supervisor の入口（監視ループ
//! `crate::run::monitor` の手順 3 への組み込みは未実装）。呼び出し先は `health` モジュール（判定・記録・降格）。
//!
//! # 実装範囲の線引き（REPAIR-3）
//! - 提供するもの: スケジュールの検証 [`HealthcheckSchedule`]、時計の注入口 [`HealthcheckClock`]、
//!   ループ [`run_periodic`]、Linux 限定の exec 終了状態の写像 `health_from_exec_exit`。
//! - **未実装**: exec（`exec::run_command_with_pidfd`、SUP-6）を呼ぶ [`crate::health::HealthProbe`] の実装。
//!   理由は、(1) exec は fork 直前に単一スレッドを要求し、スレッドを持つ supervisor 本体からは必ず拒否される、
//!   (2) argv[0] の絶対パス要求と PATH 解決の方針が未決、(3) 監査の記録先の配線が別 issue、(4) 出力の受け渡しが未実装。
//!   実行基盤が未結線の間は [`crate::health::UnimplementedHealthProbe`] が `Unimplemented` を返し `Healthy` を装わない。
//! - 提供するもの（TASK-161.3・#496）: retries 回連続失敗での unhealthy 遷移・start_period・開始時の `Starting` を、
//!   [`super::HealthAggregator`] と `crate::health::probe_aggregate_and_record` で `state.json` の `health` へ反映する。
//!   集約は probe の結果と記録の間（`ProbeRunner` の排他区間の内側）で行い、1 回の失敗が `Unhealthy` として
//!   先に公開されない。遷移の規則は `aggregate` サブモジュールの doc（spec の確定値ではなく本実装の判断）。
//!
//! # ループの意味論（spec の確定値ではなく本実装の判断）
//! - 固定遅延: 初回はループ開始から interval 後、以降は前回の判定が戻った時刻から interval 後。
//!   前回と重ならないので `ProbeRunner` の「同時に走る判定は最大 1 本」と整合する。
//! - `FailedPrecondition`（Running でない・所有権を失った。SUP-1）が返り、かつ最新レコードでも前提が崩れていれば
//!   [`HealthcheckLoopOutcome::Halted`] で止める。前提が保たれている `FailedPrecondition`（書き込み競合の使い切り）は
//!   一時的な失敗として tick の結果に載せ、次の tick へ継続する。
//!   `Unavailable`（前回の判定が未終了）は次の tick へ進む。その他の失敗は tick の結果に載せて継続する。
//!   このため [`crate::health::HealthProbe`] の実装は、コマンドの失敗に `FailedPrecondition` を使ってはならない。
//! - 待ちはすべて有限（期限つき `sleep_until`・`probe_and_record` の timeout）で、[`StopToken`] で止められる。
//! - 同じコンテナの `health` を書く経路は 1 つの [`ProbeRunner`] に揃える（clone は排他を共有する）。
//!   command の中身はエラー・ログへ出さない。

use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::LaunchedProcess;
use fandhe_container_core::traits::{ErrorCode, StateRecord, TraitError};

use super::HealthAggregator;
use super::HealthcheckDefinition;
use crate::health::{ProbeFailure, ProbeRunner, probe_aggregate_and_record, record_starting};
use crate::run::{
    MAX_POLL_INTERVAL, MonitorObserver, StopToken, ensure_owner, is_running_with_pid,
};
use crate::state::SupervisedState;

/// 停止要求を確かめる待ちの刻み（`restart` のバックオフ待ちと同じ方式）。
const SLEEP_SLICE: Duration = Duration::from_millis(50);

/// 開始時の `Starting` 記録を試みる最大回数（REPAIR-5。使い切ったら `Halted` で返す）。
const START_ATTEMPTS: u32 = 3;

/// 周期実行の時刻源と、停止要求で打ち切れる待ち（テストで偽の時計に差し替える）。
pub trait HealthcheckClock: Send + Sync {
    /// 現在時刻。
    fn now(&self) -> Instant;
    /// `deadline` まで待つ。`stop` が要求されたら早めに戻り `false`、期限に達したら `true`。
    fn sleep_until(&self, deadline: Instant, stop: &StopToken) -> bool;
}

/// 本番用の時計。`stop` を `SLEEP_SLICE` ごとに確かめながら眠る。
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl HealthcheckClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, deadline: Instant, stop: &StopToken) -> bool {
        loop {
            if stop.is_stop_requested() {
                return false;
            }
            let now = Instant::now();
            if now >= deadline {
                return true;
            }
            std::thread::sleep(SLEEP_SLICE.min(deadline - now));
        }
    }
}

/// 検証済みの周期実行スケジュール（interval・1 回の timeout・start_period・retries）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthcheckSchedule {
    interval: Duration,
    timeout: Duration,
    start_period: Duration,
    retries: NonZeroU32,
}

impl HealthcheckSchedule {
    /// 定義から作る。timeout が `probe_and_record` の上限（[`MAX_POLL_INTERVAL`]）を超えるなら、
    /// tick ごとに失敗し続けないよう構築時に `InvalidArgument` で拒否する（fail-closed）。
    pub fn from_definition(def: &HealthcheckDefinition) -> Result<Self, TraitError> {
        if def.timeout() > MAX_POLL_INTERVAL {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "healthcheck timeout exceeds the probe limit",
            ));
        }
        Ok(Self {
            interval: def.interval(),
            timeout: def.timeout(),
            start_period: def.start_period(),
            retries: def.retries(),
        })
    }

    /// 実行間隔。
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// 1 回の判定の timeout。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 失敗を数え始めるまでの猶予。
    pub fn start_period(&self) -> Duration {
        self.start_period
    }

    /// unhealthy と判定する連続失敗回数。
    pub fn retries(&self) -> NonZeroU32 {
        self.retries
    }
}

/// 1 回の tick（判定と記録の 1 回分）の報告。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HealthcheckTick {
    /// 1 始まりの tick 番号。
    pub index: u64,
    /// ループ開始からの経過（判定が戻った時点）。
    pub elapsed: Duration,
    /// この tick 後の連続失敗数（集約器の内部の数。公開状態との同期の照合用。TASK-161.3）。
    pub consecutive_failures: u32,
    /// 記録に成功したレコード、または失敗（降格の結果つき）。
    pub result: Result<StateRecord, ProbeFailure>,
}

/// [`run_periodic`] の終了理由。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HealthcheckLoopOutcome {
    /// 停止要求で止まった。
    Stopped {
        /// 実行した tick 数。
        ticks: u64,
    },
    /// 前提が崩れて止まった（`FailedPrecondition`。Running でない・所有権を失った。SUP-1）。
    Halted {
        /// 止めたエラー。
        error: TraitError,
        /// 実行した tick 数（止めた判定を含む）。
        ticks: u64,
    },
}

fn overflow(ticks: u64) -> HealthcheckLoopOutcome {
    HealthcheckLoopOutcome::Halted {
        error: TraitError::new(ErrorCode::InvalidArgument, "healthcheck interval overflows"),
        ticks,
    }
}

/// interval ごとに `probe_aggregate_and_record` を呼ぶ（意味論はモジュール doc）。
///
/// 専用スレッドで回すこと。`state` は監視ループとは別に `SupervisedState::attach` で得る。
/// 各 tick の結果は `on_tick` へ渡す。
// 抑止理由: 引数 8 個は、状態・起動済みプロセス・probe 実行器・時計・停止トークン・観測器・tick 通知と、
// それぞれ別の差し替え点（試験で偽物に替える）を表す。構造体にまとめると差し替え点が隠れて
// 呼び出し側の見通しが悪くなるため、公開 API は 8 引数のまま維持する。
#[allow(clippy::too_many_arguments)]
pub fn run_periodic(
    schedule: &HealthcheckSchedule,
    state: &mut SupervisedState,
    process: &dyn LaunchedProcess,
    runner: &ProbeRunner,
    clock: &dyn HealthcheckClock,
    stop: &StopToken,
    obs: &dyn MonitorObserver,
    on_tick: &mut dyn FnMut(&HealthcheckTick),
) -> HealthcheckLoopOutcome {
    let start = clock.now();
    let mut agg = HealthAggregator::from_schedule(schedule);
    // 開始時に `Starting` へ戻す。成功するまで集約へ進まない（失敗を無視すると前の process の `Healthy` が
    // 残り、depends_on の healthy 条件を誤って満たす。SUP-4 の fail-closed）。有界に再試行し、使い切ったら
    // 止めて失敗を返す。
    let mut starting_err = None;
    for _ in 0..START_ATTEMPTS {
        if stop.is_stop_requested() {
            return HealthcheckLoopOutcome::Stopped { ticks: 0 };
        }
        match record_starting(state, process, runner, obs) {
            Ok(_) => {
                starting_err = None;
                break;
            }
            Err(e) => starting_err = Some(e),
        }
    }
    if let Some(error) = starting_err {
        return HealthcheckLoopOutcome::Halted { error, ticks: 0 };
    }
    let mut ticks: u64 = 0;
    let Some(mut next) = start.checked_add(schedule.interval) else {
        return overflow(ticks);
    };
    loop {
        if stop.is_stop_requested() || !clock.sleep_until(next, stop) || stop.is_stop_requested() {
            return HealthcheckLoopOutcome::Stopped { ticks };
        }
        let elapsed_at_probe = clock.now().saturating_duration_since(start);
        let result = probe_aggregate_and_record(
            state,
            process,
            runner,
            schedule.timeout,
            obs,
            &mut |r, cur| agg.observe(r, elapsed_at_probe, cur),
        );
        ticks = ticks.saturating_add(1);
        let finished = clock.now();
        // 書き込み競合の使い切りも `FailedPrecondition` で返るため、最新レコードで前提（Running・pid・所有）が
        // 実際に崩れているときだけ止める。保たれていれば一時的な競合として次の tick へ継続する（SUP-1・SUP-4）。
        if let Err(f) = &result
            && f.error().code() == ErrorCode::FailedPrecondition
            && !still_owned(state, process)
        {
            return HealthcheckLoopOutcome::Halted {
                error: f.error().clone(),
                ticks,
            };
        }
        on_tick(&HealthcheckTick {
            index: ticks,
            elapsed: finished.saturating_duration_since(start),
            consecutive_failures: agg.consecutive_failures(),
            result,
        });
        let Some(t) = finished.checked_add(schedule.interval) else {
            return overflow(ticks);
        };
        next = t;
    }
}

/// 最新レコードで Running・起動 pid 一致・自 supervisor 所有がまだ成り立つか。読み直せない場合は偽（安全側で止める）。
fn still_owned(state: &mut SupervisedState, process: &dyn LaunchedProcess) -> bool {
    let Some(self_pid) = std::num::NonZeroU32::new(std::process::id()) else {
        return false;
    };
    state.refresh().is_ok()
        && is_running_with_pid(state.record(), process.pid())
        && ensure_owner(state.record(), self_pid).is_ok()
}

/// exec の終了状態を health へ写す（SUP-4・SUP-6）。`FailedPrecondition` は返さない（ループの停止条件と区別するため）。
///
/// 終了コード 0 は `Healthy`、0 以外・シグナル終了は `Unhealthy`。コマンドが起動していない
/// （`SetupFailed`）場合と未知の variant は実行基盤側の失敗として `Internal`（fail-closed。`Healthy` にしない）。
#[cfg(target_os = "linux")]
pub fn health_from_exec_exit(
    exit: fandhe_container_core::exec::ExecExit,
) -> Result<fandhe_container_core::traits::HealthStatus, TraitError> {
    use fandhe_container_core::exec::{ChildExit, ExecExit};
    use fandhe_container_core::traits::HealthStatus;
    match exit {
        ExecExit::Command(ChildExit::Exited(0)) => Ok(HealthStatus::Healthy),
        ExecExit::Command(ChildExit::Exited(_)) | ExecExit::Command(ChildExit::Signaled(_)) => {
            Ok(HealthStatus::Unhealthy)
        }
        _ => Err(TraitError::new(
            ErrorCode::Internal,
            "healthcheck command did not start",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::HealthProbe;
    use crate::healthcheck::RawHealthcheck;
    use crate::run::MonitorEvent;
    use fandhe_container_core::oci_runtime::ProcessExit;
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
        GetStateRequest, HealthStatus, ListStateRequest, StateList, StateRevision, StateStore,
        SupervisionState, UpdateStateRequest,
    };
    use std::num::NonZeroU32;
    use std::sync::{Arc, Mutex};

    struct MemStore(Mutex<StateRecord>, std::sync::atomic::AtomicBool);

    impl StateStore for MemStore {
        fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "mem"))
        }
        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            let mut g = self.0.lock().unwrap();
            if self.1.load(std::sync::atomic::Ordering::SeqCst)
                || g.revision() != req.expected_revision()
            {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            let sup = req.supervision().unwrap_or_else(|| g.supervision());
            let next = StateRecord::new(
                req.status().clone(),
                g.bundle().to_path_buf(),
                StateRevision::from_raw(g.revision().value() + 1),
            )
            .unwrap()
            .with_supervision(sup);
            *g = next.clone();
            Ok(next)
        }
        fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "mem"))
        }
        fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "mem"))
        }
    }

    struct Proc;
    impl LaunchedProcess for Proc {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(42).unwrap()
        }
        fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(None)
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            Ok(())
        }
    }

    struct NoObs;
    impl MonitorObserver for NoObs {
        fn observe(&self, _: &MonitorEvent) {}
    }

    /// `sleep_until` でだけ進む偽の時計。`stop_on_sleep` 回目の待ちで停止を要求して `false` を返す。
    struct FakeClock {
        now: Mutex<Instant>,
        sleeps: Mutex<u32>,
        stop_on_sleep: Option<u32>,
    }

    impl FakeClock {
        fn new(stop_on_sleep: Option<u32>) -> Arc<Self> {
            Arc::new(Self {
                now: Mutex::new(Instant::now()),
                sleeps: Mutex::new(0),
                stop_on_sleep,
            })
        }
        fn advance(&self, d: Duration) {
            *self.now.lock().unwrap() += d;
        }
    }

    impl HealthcheckClock for FakeClock {
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
        fn sleep_until(&self, deadline: Instant, stop: &StopToken) -> bool {
            let mut n = self.sleeps.lock().unwrap();
            *n += 1;
            if self.stop_on_sleep == Some(*n) {
                stop.request_stop();
                return false;
            }
            let mut now = self.now.lock().unwrap();
            if deadline > *now {
                *now = deadline;
            }
            true
        }
    }

    /// 呼ばれた時刻を記録し、`cost` だけ偽の時計を進めて `result` を返す probe。
    struct TimedProbe {
        clock: Arc<FakeClock>,
        starts: Mutex<Vec<Instant>>,
        cost: Duration,
        result: fn() -> Result<HealthStatus, TraitError>,
    }

    impl HealthProbe for TimedProbe {
        fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
            self.starts.lock().unwrap().push(self.clock.now());
            self.clock.advance(self.cost);
            (self.result)()
        }
    }

    fn me() -> NonZeroU32 {
        NonZeroU32::new(std::process::id()).unwrap()
    }

    fn state(owner: Option<NonZeroU32>, running: bool) -> SupervisedState {
        state_with(owner, running, false)
    }

    /// `always_stale` なら update が常に revision 競合（`FailedPrecondition`）を返す。
    fn state_with(owner: Option<NonZeroU32>, running: bool, always_stale: bool) -> SupervisedState {
        let id = ContainerId::new("c1").unwrap();
        let status = if running {
            ContainerStatus::running(id.clone(), NonZeroU32::new(42))
        } else {
            ContainerStatus::running(id.clone(), NonZeroU32::new(7))
        };
        // 常に競合するストアでは Starting を書けないため、Starting を初期値にして開始時の記録を不要にする。
        let init_health = always_stale.then_some(HealthStatus::Starting);
        let rec = StateRecord::new(
            status,
            std::env::temp_dir().join("healthcheck-periodic-ut"),
            StateRevision::from_raw(1),
        )
        .unwrap()
        .with_supervision(SupervisionState::new(owner, init_health, 0));
        let store: Arc<dyn StateStore> = Arc::new(MemStore(
            Mutex::new(rec),
            std::sync::atomic::AtomicBool::new(always_stale),
        ));
        SupervisedState::attach(store, id).unwrap()
    }

    fn schedule(interval: &str, timeout: &str) -> HealthcheckSchedule {
        let def = HealthcheckDefinition::parse(&RawHealthcheck {
            command: vec!["true".into()],
            interval: Some(interval.into()),
            timeout: Some(timeout.into()),
            ..Default::default()
        })
        .unwrap();
        HealthcheckSchedule::from_definition(&def).unwrap()
    }

    fn ok_healthy() -> Result<HealthStatus, TraitError> {
        Ok(HealthStatus::Healthy)
    }

    fn run(
        sched: &HealthcheckSchedule,
        st: &mut SupervisedState,
        clock: &Arc<FakeClock>,
        probe: Arc<TimedProbe>,
        max_ticks: u64,
    ) -> (HealthcheckLoopOutcome, Vec<HealthcheckTick>) {
        let runner = ProbeRunner::new(probe);
        let stop = StopToken::new();
        let mut seen = Vec::new();
        let outcome = run_periodic(
            sched,
            st,
            &Proc,
            &runner,
            clock.as_ref(),
            &stop,
            &NoObs,
            &mut |t| {
                seen.push(t.clone());
                if t.index >= max_ticks {
                    stop.request_stop();
                }
            },
        );
        (outcome, seen)
    }

    fn offsets(starts: &[Instant], t0: Instant) -> Vec<Duration> {
        starts.iter().map(|s| *s - t0).collect()
    }

    /// SUP-4・TASK-161.2: interval = 10s で 3 tick、開始時刻が 10s・20s・30s に一致する。
    #[test]
    fn sup4_periodic_runs_at_interval() {
        let clock = FakeClock::new(None);
        let t0 = clock.now();
        let probe = Arc::new(TimedProbe {
            clock: clock.clone(),
            starts: Mutex::new(Vec::new()),
            cost: Duration::ZERO,
            result: ok_healthy,
        });
        let mut st = state(Some(me()), true);
        let (out, seen) = run(&schedule("10s", "5s"), &mut st, &clock, probe.clone(), 3);
        assert_eq!(out, HealthcheckLoopOutcome::Stopped { ticks: 3 });
        assert_eq!(
            offsets(&probe.starts.lock().unwrap(), t0),
            vec![
                Duration::from_secs(10),
                Duration::from_secs(20),
                Duration::from_secs(30)
            ]
        );
        assert_eq!(seen.len(), 3);
        assert_eq!(
            seen[2].result.as_ref().unwrap().health(),
            Some(HealthStatus::Healthy)
        );
    }

    /// SUP-4・REPAIR-5: 固定遅延。判定が 3s かかると次は戻りから 10s 後（10s・23s・36s）。
    #[test]
    fn sup4_periodic_fixed_delay() {
        let clock = FakeClock::new(None);
        let t0 = clock.now();
        let probe = Arc::new(TimedProbe {
            clock: clock.clone(),
            starts: Mutex::new(Vec::new()),
            cost: Duration::from_secs(3),
            result: ok_healthy,
        });
        let mut st = state(Some(me()), true);
        run(&schedule("10s", "5s"), &mut st, &clock, probe.clone(), 3);
        assert_eq!(
            offsets(&probe.starts.lock().unwrap(), t0),
            vec![
                Duration::from_secs(10),
                Duration::from_secs(23),
                Duration::from_secs(36)
            ]
        );
    }

    /// SUP-4: 待ちの途中で停止要求が立つと次の判定を呼ばず Stopped で戻る。
    #[test]
    fn sup4_periodic_stop_during_sleep() {
        let clock = FakeClock::new(Some(3));
        let probe = Arc::new(TimedProbe {
            clock: clock.clone(),
            starts: Mutex::new(Vec::new()),
            cost: Duration::ZERO,
            result: ok_healthy,
        });
        let mut st = state(Some(me()), true);
        let (out, _) = run(&schedule("10s", "5s"), &mut st, &clock, probe.clone(), 100);
        assert_eq!(out, HealthcheckLoopOutcome::Stopped { ticks: 2 });
        assert_eq!(probe.starts.lock().unwrap().len(), 2);
    }

    /// SUP-1: 所有権が無い（前提が崩れた）と probe せず Halted(FailedPrecondition)。
    #[test]
    fn sup1_periodic_halts_without_ownership() {
        let clock = FakeClock::new(None);
        let probe = Arc::new(TimedProbe {
            clock: clock.clone(),
            starts: Mutex::new(Vec::new()),
            cost: Duration::ZERO,
            result: ok_healthy,
        });
        let mut st = state(None, true);
        let (out, seen) = run(&schedule("10s", "5s"), &mut st, &clock, probe.clone(), 5);
        match out {
            HealthcheckLoopOutcome::Halted { error, ticks } => {
                assert_eq!(error.code(), ErrorCode::FailedPrecondition);
                // 所有していないため開始時の Starting 記録で止まる（tick 0）。
                assert_eq!(ticks, 0);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert!(probe.starts.lock().unwrap().is_empty());
        assert!(seen.is_empty());
    }

    /// SUP-1・SUP-4: 書き込み競合の使い切り（FailedPrecondition）でも、所有・Running が保たれていれば Halted にせず継続する。
    #[test]
    fn sup4_periodic_continues_on_stale_write_conflict() {
        let clock = FakeClock::new(None);
        let probe = Arc::new(TimedProbe {
            clock: clock.clone(),
            starts: Mutex::new(Vec::new()),
            cost: Duration::ZERO,
            result: ok_healthy,
        });
        let mut st = state_with(Some(me()), true, true);
        let (out, seen) = run(&schedule("10s", "5s"), &mut st, &clock, probe.clone(), 3);
        assert_eq!(out, HealthcheckLoopOutcome::Stopped { ticks: 3 });
        assert_eq!(probe.starts.lock().unwrap().len(), 3);
        for t in &seen {
            assert_eq!(
                t.result.as_ref().unwrap_err().error().code(),
                ErrorCode::FailedPrecondition
            );
        }
    }

    /// SUP-4: probe の失敗は止まらず継続し、tick の結果へ失敗が載る。
    #[test]
    fn sup4_periodic_continues_on_probe_failure() {
        fn boom() -> Result<HealthStatus, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "boom"))
        }
        let clock = FakeClock::new(None);
        let probe = Arc::new(TimedProbe {
            clock: clock.clone(),
            starts: Mutex::new(Vec::new()),
            cost: Duration::ZERO,
            result: boom,
        });
        let mut st = state(Some(me()), true);
        let (out, seen) = run(&schedule("10s", "5s"), &mut st, &clock, probe, 2);
        assert_eq!(out, HealthcheckLoopOutcome::Stopped { ticks: 2 });
        for t in &seen {
            assert_eq!(
                t.result.as_ref().unwrap_err().error().code(),
                ErrorCode::Internal
            );
        }
    }

    /// SUP-4・TASK-161.3: ループ開始時（最初の判定の前）に health が Starting になる。
    #[test]
    fn sup4_periodic_records_starting_at_start() {
        let clock = FakeClock::new(Some(1));
        let probe = Arc::new(TimedProbe {
            clock: clock.clone(),
            starts: Mutex::new(Vec::new()),
            cost: Duration::ZERO,
            result: ok_healthy,
        });
        let mut st = state(Some(me()), true);
        let (out, _) = run(&schedule("10s", "5s"), &mut st, &clock, probe.clone(), 5);
        assert_eq!(out, HealthcheckLoopOutcome::Stopped { ticks: 0 });
        assert!(probe.starts.lock().unwrap().is_empty());
        assert_eq!(st.refresh().unwrap().health(), Some(HealthStatus::Starting));
    }

    /// SUP-4・TASK-161.3: Starting を書けない（常に競合）と、古い Healthy を残したまま集約へ進まず Halted(tick 0)。
    #[test]
    fn sup4_periodic_halts_when_starting_cannot_be_recorded() {
        let clock = FakeClock::new(None);
        let probe = Arc::new(TimedProbe {
            clock: clock.clone(),
            starts: Mutex::new(Vec::new()),
            cost: Duration::ZERO,
            result: ok_healthy,
        });
        // 初期値を Healthy に差し替えた（再起動前の値が残った）状態を作る。
        let id = ContainerId::new("c1").unwrap();
        let rec = StateRecord::new(
            ContainerStatus::running(id.clone(), NonZeroU32::new(42)),
            std::env::temp_dir().join("healthcheck-periodic-ut"),
            StateRevision::from_raw(1),
        )
        .unwrap()
        .with_supervision(SupervisionState::new(
            Some(me()),
            Some(HealthStatus::Healthy),
            0,
        ));
        let store: Arc<dyn StateStore> = Arc::new(MemStore(
            Mutex::new(rec),
            std::sync::atomic::AtomicBool::new(true),
        ));
        let mut st = SupervisedState::attach(store, id).unwrap();
        let (out, seen) = run(&schedule("10s", "5s"), &mut st, &clock, probe.clone(), 3);
        match out {
            HealthcheckLoopOutcome::Halted { error, ticks } => {
                assert_eq!(error.code(), ErrorCode::FailedPrecondition);
                assert_eq!(ticks, 0);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert!(probe.starts.lock().unwrap().is_empty());
        assert!(seen.is_empty());
    }

    /// SUP-4: timeout は 60s まで受理し、61s は構築時に InvalidArgument。
    #[test]
    fn sup4_periodic_timeout_limit() {
        let mk = |t: &str| {
            HealthcheckDefinition::parse(&RawHealthcheck {
                command: vec!["true".into()],
                timeout: Some(t.into()),
                ..Default::default()
            })
            .unwrap()
        };
        assert_eq!(
            HealthcheckSchedule::from_definition(&mk("60s"))
                .unwrap()
                .timeout(),
            Duration::from_secs(60)
        );
        let e = HealthcheckSchedule::from_definition(&mk("61s")).unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
    }

    /// SUP-4・SUP-6: exec 終了状態の写像（Linux のみ）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup4_health_from_exec_exit_mapping() {
        use fandhe_container_core::exec::{ChildExit, ExecExit};
        assert_eq!(
            health_from_exec_exit(ExecExit::Command(ChildExit::Exited(0))).unwrap(),
            HealthStatus::Healthy
        );
        assert_eq!(
            health_from_exec_exit(ExecExit::Command(ChildExit::Exited(1))).unwrap(),
            HealthStatus::Unhealthy
        );
        assert_eq!(
            health_from_exec_exit(ExecExit::Command(ChildExit::Signaled(9))).unwrap(),
            HealthStatus::Unhealthy
        );
        let e = health_from_exec_exit(ExecExit::SetupFailed {
            exit: ChildExit::Exited(127),
            violation: None,
            code: ErrorCode::NotFound,
        })
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
    }
}
