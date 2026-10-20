//! healthcheck 周期実行エンジンの受け入れ照合（TASK-161.2・#495・SUP-4・SUP-1・REPAIR-12）。
//!
//! 公開 API だけで駆動する。偽の時計とメモリ上の `StateStore` を使うため実時間の待ちは無く、
//! 3 OS・root 不要で既定のテスト集合で動く。

use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
    ErrorCode, GetStateRequest, HealthStatus, ListStateRequest, StateList, StateRecord,
    StateRevision, StateStore, SupervisionState, TraitError, UpdateStateRequest,
};
use fandhe_container_supervisor::health::{HealthProbe, ProbeRunner};
use fandhe_container_supervisor::healthcheck::{
    HealthcheckClock, HealthcheckDefinition, HealthcheckLoopOutcome, HealthcheckSchedule,
    RawHealthcheck, run_periodic,
};
use fandhe_container_supervisor::run::{MonitorEvent, MonitorObserver, StopToken};
use fandhe_container_supervisor::state::SupervisedState;

struct MemStore(Mutex<StateRecord>);

impl StateStore for MemStore {
    fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "mem"))
    }
    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        let mut g = self.0.lock().unwrap();
        if g.revision() != req.expected_revision() {
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

/// `sleep_until` でだけ進む偽の時計。
struct FakeClock(Mutex<Instant>);

impl HealthcheckClock for FakeClock {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
    fn sleep_until(&self, deadline: Instant, stop: &StopToken) -> bool {
        if stop.is_stop_requested() {
            return false;
        }
        let mut now = self.0.lock().unwrap();
        if deadline > *now {
            *now = deadline;
        }
        true
    }
}

struct Recorder {
    clock: Arc<FakeClock>,
    starts: Mutex<Vec<Instant>>,
}

impl HealthProbe for Recorder {
    fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
        self.starts.lock().unwrap().push(self.clock.now());
        Ok(HealthStatus::Healthy)
    }
}

fn state(owner: Option<NonZeroU32>) -> SupervisedState {
    let id = ContainerId::new("c1").unwrap();
    let rec = StateRecord::new(
        ContainerStatus::running(id.clone(), NonZeroU32::new(42)),
        std::env::temp_dir().join("healthcheck-periodic-it"),
        StateRevision::from_raw(1),
    )
    .unwrap()
    .with_supervision(SupervisionState::new(owner, None, 0));
    let store: Arc<dyn StateStore> = Arc::new(MemStore(Mutex::new(rec)));
    SupervisedState::attach(store, id).unwrap()
}

fn schedule(interval: &str, timeout: &str) -> Result<HealthcheckSchedule, TraitError> {
    let def = HealthcheckDefinition::parse(&RawHealthcheck {
        command: vec!["pg_isready".into()],
        interval: Some(interval.into()),
        timeout: Some(timeout.into()),
        ..Default::default()
    })?;
    HealthcheckSchedule::from_definition(&def)
}

/// SUP-4: interval = 5s で 4 回、開始時刻が 5s・10s・15s・20s に一致し、最後の記録が Healthy。
#[test]
fn sup4_task161_2_it_runs_at_interval() {
    let t0 = Instant::now();
    let clock = Arc::new(FakeClock(Mutex::new(t0)));
    let probe = Arc::new(Recorder {
        clock: clock.clone(),
        starts: Mutex::new(Vec::new()),
    });
    let runner = ProbeRunner::new(probe.clone());
    let stop = StopToken::new();
    let mut st = state(Some(NonZeroU32::new(std::process::id()).unwrap()));
    let mut last = None;
    let out = run_periodic(
        &schedule("5s", "2s").unwrap(),
        &mut st,
        &Proc,
        &runner,
        clock.as_ref(),
        &stop,
        &NoObs,
        &mut |t| {
            last = t.result.as_ref().ok().and_then(|r| r.health());
            if t.index == 4 {
                stop.request_stop();
            }
        },
    );
    assert_eq!(out, HealthcheckLoopOutcome::Stopped { ticks: 4 });
    let offsets: Vec<Duration> = probe
        .starts
        .lock()
        .unwrap()
        .iter()
        .map(|s| *s - t0)
        .collect();
    assert_eq!(offsets, [5, 10, 15, 20].map(Duration::from_secs).to_vec());
    assert_eq!(last, Some(HealthStatus::Healthy));
    assert_eq!(st.record().health(), Some(HealthStatus::Healthy));
}

/// SUP-1: 所有者でない supervisor は書かず、Halted(FailedPrecondition) で止まる。
#[test]
fn sup1_task161_2_it_halts_when_not_owner() {
    let clock = Arc::new(FakeClock(Mutex::new(Instant::now())));
    let probe = Arc::new(Recorder {
        clock: clock.clone(),
        starts: Mutex::new(Vec::new()),
    });
    let runner = ProbeRunner::new(probe.clone());
    let stop = StopToken::new();
    let mut st = state(None);
    let out = run_periodic(
        &schedule("5s", "2s").unwrap(),
        &mut st,
        &Proc,
        &runner,
        clock.as_ref(),
        &stop,
        &NoObs,
        &mut |_| {},
    );
    match out {
        HealthcheckLoopOutcome::Halted { error, ticks } => {
            assert_eq!(error.code(), ErrorCode::FailedPrecondition);
            // 所有していないため開始時の Starting 記録（record_starting）で止まり、tick は進まない。
            assert_eq!(ticks, 0);
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert!(probe.starts.lock().unwrap().is_empty());
}

/// REPAIR-5: probe_and_record の上限（60s）を超える timeout は構築時に拒否される。
#[test]
fn sup4_task161_2_it_timeout_over_probe_limit_rejected() {
    assert!(schedule("5s", "60s").is_ok());
    assert_eq!(
        schedule("5s", "61s").unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

// ---- TASK-161.3・#496: health の集約と state.json への反映 ----

/// 用意した結果を順に返す probe（尽きたら `Healthy`）。
struct Script(Mutex<std::collections::VecDeque<Result<HealthStatus, TraitError>>>);

impl HealthProbe for Script {
    fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
        self.0
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Ok(HealthStatus::Healthy))
    }
}

fn unhealthy() -> Result<HealthStatus, TraitError> {
    Ok(HealthStatus::Unhealthy)
}

fn healthy() -> Result<HealthStatus, TraitError> {
    Ok(HealthStatus::Healthy)
}

fn schedule_full(interval: &str, start_period: &str, retries: i64) -> HealthcheckSchedule {
    let def = HealthcheckDefinition::parse(&RawHealthcheck {
        command: vec!["pg_isready".into()],
        interval: Some(interval.into()),
        timeout: Some("2s".into()),
        start_period: Some(start_period.into()),
        retries: Some(retries),
    })
    .unwrap();
    HealthcheckSchedule::from_definition(&def).unwrap()
}

/// 各 tick 後に別に持ったストアから読んだ (health, revision, tick の連続失敗数)。
type Seen = Vec<(Option<HealthStatus>, u64, u32)>;

fn drive(sched: &HealthcheckSchedule, script: Vec<Result<HealthStatus, TraitError>>) -> Seen {
    let id = ContainerId::new("c1").unwrap();
    let rec = StateRecord::new(
        ContainerStatus::running(id.clone(), NonZeroU32::new(42)),
        std::env::temp_dir().join("healthcheck-periodic-it"),
        StateRevision::from_raw(1),
    )
    .unwrap()
    .with_supervision(SupervisionState::new(
        Some(NonZeroU32::new(std::process::id()).unwrap()),
        None,
        0,
    ));
    let mem = Arc::new(MemStore(Mutex::new(rec)));
    let store: Arc<dyn StateStore> = mem.clone();
    let mut st = SupervisedState::attach(store, id).unwrap();
    let n = script.len() as u64;
    let clock = Arc::new(FakeClock(Mutex::new(Instant::now())));
    let runner = ProbeRunner::new(Arc::new(Script(Mutex::new(script.into()))));
    let stop = StopToken::new();
    let mut seen = Vec::new();
    run_periodic(
        sched,
        &mut st,
        &Proc,
        &runner,
        clock.as_ref(),
        &stop,
        &NoObs,
        &mut |t| {
            let g = mem.0.lock().unwrap();
            seen.push((g.health(), g.revision().value(), t.consecutive_failures));
            if t.index >= n {
                stop.request_stop();
            }
        },
    );
    seen
}

const ST: Option<HealthStatus> = Some(HealthStatus::Starting);
const HE: Option<HealthStatus> = Some(HealthStatus::Healthy);
const UN: Option<HealthStatus> = Some(HealthStatus::Unhealthy);

fn healths(v: &Seen) -> Vec<Option<HealthStatus>> {
    v.iter().map(|x| x.0).collect()
}

/// SUP-4・TASK-161.3: retries=3 で失敗が続くと、各 tick 後の state.json の health は Starting・Starting・Unhealthy。
#[test]
fn sup4_task161_3_it_unhealthy_after_retries() {
    let seen = drive(
        &schedule_full("5s", "0s", 3),
        vec![unhealthy(), unhealthy(), unhealthy()],
    );
    assert_eq!(healths(&seen), vec![ST, ST, UN]);
    let fails: Vec<u32> = seen.iter().map(|x| x.2).collect();
    assert_eq!(fails, vec![1, 2, 3]);
}

/// SUP-4・TASK-161.3: 成功 → 失敗 3 回で Healthy が retries まで保たれ、成功で戻る。
#[test]
fn sup4_task161_3_it_healthy_then_unhealthy() {
    let seen = drive(
        &schedule_full("5s", "0s", 3),
        vec![healthy(), unhealthy(), unhealthy(), unhealthy(), healthy()],
    );
    assert_eq!(healths(&seen), vec![HE, HE, HE, UN, HE]);
}

/// SUP-4・TASK-161.3: interval 5s・start_period 12s・retries 2 で、tick 1・2（5s・10s）は数えず、tick 3・4 で Unhealthy。
#[test]
fn sup4_task161_3_it_start_period() {
    let seen = drive(
        &schedule_full("5s", "12s", 2),
        vec![unhealthy(), unhealthy(), unhealthy(), unhealthy()],
    );
    assert_eq!(healths(&seen), vec![ST, ST, ST, UN]);
    let fails: Vec<u32> = seen.iter().map(|x| x.2).collect();
    assert_eq!(fails, vec![0, 0, 1, 2]);
}

/// SUP-4・TASK-161.3: Timeout も失敗に数え、retries 回で Starting から Unhealthy へ移る。
#[test]
fn sup4_task161_3_it_timeout_counts() {
    let t = || Err(TraitError::new(ErrorCode::Timeout, "t"));
    let seen = drive(&schedule_full("5s", "0s", 2), vec![t(), t()]);
    assert_eq!(healths(&seen), vec![ST, UN]);
}

/// SUP-4・TASK-161.3: 値が変わらない tick では revision が増えない。
#[test]
fn sup4_task161_3_it_no_redundant_write() {
    let seen = drive(
        &schedule_full("5s", "0s", 3),
        vec![healthy(), healthy(), healthy()],
    );
    let revs: Vec<u64> = seen.iter().map(|x| x.1).collect();
    // 初期 1 → Starting で 2 → Healthy で 3 → 以降は 3 のまま。
    assert_eq!(revs, vec![3, 3, 3]);
}
