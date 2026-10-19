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
            assert_eq!(ticks, 1);
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
