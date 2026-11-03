//! healthcheck の周期実行を監視ループ・restart・supervisor の入口へ配線した結果の受け入れ照合
//! （TASK-161・#2953・SUP-4・SUP-3・SUP-1・REPAIR-5・REPAIR-12）。
//!
//! 公開 API だけで駆動する。メモリ上の `StateStore`（revision の楽観的排他つき）と偽の起動ハンドル・偽の probe を使うため、
//! 3 OS・root 不要で既定のテスト集合で動く。待ちはすべて期限つきのポーリングで、期待値は具体値で照合する。
//! 検証範囲（REPAIR-3）: 本番の `ExecHealthProbe`（exec 専用 helper）は `healthcheck_exec_probe.rs` /
//! `healthcheck_exec_real.rs` が担い、ここでは配線（寿命・停止・付け替え・fail-closed）だけを見る。

use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit, StartTimeouts};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ContainerStatus, CreateStateRequest, DeleteStateRequest,
    DeleteStateResponse, ErrorCode, GetStateRequest, HealthStatus, ListStateRequest, StateList,
    StateRecord, StateRevision, StateStore, SupervisionState, TraitError, UpdateStateRequest,
};
use fandhe_container_supervisor::health::{HealthProbe, ProbeCancel};
use fandhe_container_supervisor::healthcheck::{
    HealthProbeFactory, HealthWiring, HealthcheckDefinition, RawHealthcheck,
};
use fandhe_container_supervisor::restart::{
    Relauncher, RestartConfig, RestartPolicy, SuperviseOutcome, supervise_with_restart_health,
};
use fandhe_container_supervisor::run::{
    MonitorConfig, MonitorEvent, MonitorObserver, MonitorOutcome, StopToken, monitor_with_health,
};
use fandhe_container_supervisor::start_entry::{Running, run_supervised_with_health};
use fandhe_container_supervisor::state::SupervisedState;

const DEADLINE: Duration = Duration::from_secs(10);

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

fn pid(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

fn store_with(health: Option<HealthStatus>, running_pid: u32) -> Arc<MemStore> {
    let id = ContainerId::new("c1").unwrap();
    let rec = StateRecord::new(
        ContainerStatus::running(id, Some(pid(running_pid))),
        std::env::temp_dir().join("healthcheck-monitor-wiring-it"),
        StateRevision::from_raw(1),
    )
    .unwrap()
    .with_supervision(SupervisionState::new(None, health, 0));
    Arc::new(MemStore(Mutex::new(rec)))
}

fn snapshot(store: &Arc<MemStore>) -> StateRecord {
    store.0.lock().unwrap().clone()
}

fn attach(store: &Arc<MemStore>) -> SupervisedState {
    let dyn_store: Arc<dyn StateStore> = store.clone();
    SupervisedState::attach(dyn_store, ContainerId::new("c1").unwrap()).unwrap()
}

/// `exit` が立つと終了コード 1 で終わる偽の起動ハンドル。
struct FakeProc {
    pid: u32,
    exit: Arc<AtomicBool>,
}

impl LaunchedProcess for FakeProc {
    fn pid(&self) -> NonZeroU32 {
        pid(self.pid)
    }
    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        std::thread::sleep(timeout.min(Duration::from_millis(5)));
        Ok(self
            .exit
            .load(Ordering::SeqCst)
            .then_some(ProcessExit::Exited(1)))
    }
    fn terminate(&self, _: Duration) -> Result<(), TraitError> {
        self.exit.store(true, Ordering::SeqCst);
        Ok(())
    }
}

struct NoObs;
impl MonitorObserver for NoObs {
    fn observe(&self, _: &MonitorEvent) {}
}

/// 台本どおりに結果を返し、尽きたら最後の値を繰り返す probe（呼び出し回数を数える）。
struct ScriptedProbe {
    script: Mutex<VecDeque<HealthStatus>>,
    last: Mutex<HealthStatus>,
    calls: AtomicU32,
}

impl ScriptedProbe {
    fn new(script: &[HealthStatus]) -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(script.iter().copied().collect()),
            last: Mutex::new(*script.last().unwrap()),
            calls: AtomicU32::new(0),
        })
    }
    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl HealthProbe for ScriptedProbe {
    fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let next = self.script.lock().unwrap().pop_front();
        let mut last = self.last.lock().unwrap();
        if let Some(v) = next {
            *last = v;
        }
        Ok(*last)
    }
}

/// 起動ハンドルの pid ごとに台本つきの probe を作る工場（作った probe と呼び出された pid を覚える）。
struct ScriptedFactory {
    script: Vec<HealthStatus>,
    fail: bool,
    made: Mutex<Vec<(u32, Arc<ScriptedProbe>)>>,
}

impl ScriptedFactory {
    fn new(script: &[HealthStatus]) -> Arc<Self> {
        Arc::new(Self {
            script: script.to_vec(),
            fail: false,
            made: Mutex::new(Vec::new()),
        })
    }
    fn failing() -> Arc<Self> {
        Arc::new(Self {
            script: vec![HealthStatus::Healthy],
            fail: true,
            made: Mutex::new(Vec::new()),
        })
    }
    fn pids(&self) -> Vec<u32> {
        self.made.lock().unwrap().iter().map(|(p, _)| *p).collect()
    }
    fn probe(&self, index: usize) -> Arc<ScriptedProbe> {
        Arc::clone(&self.made.lock().unwrap()[index].1)
    }
}

impl HealthProbeFactory for ScriptedFactory {
    fn probe_for(&self, process: &dyn LaunchedProcess) -> Result<Arc<dyn HealthProbe>, TraitError> {
        if self.fail {
            return Err(TraitError::new(ErrorCode::FailedPrecondition, "no pidfd"));
        }
        let probe = ScriptedProbe::new(&self.script);
        self.made
            .lock()
            .unwrap()
            .push((process.pid().get(), Arc::clone(&probe)));
        Ok(probe)
    }
}

fn wiring(factory: Arc<dyn HealthProbeFactory>, interval: &str) -> HealthWiring {
    wiring_with_timeout(factory, interval, "1s")
}

fn wiring_with_timeout(
    factory: Arc<dyn HealthProbeFactory>,
    interval: &str,
    timeout: &str,
) -> HealthWiring {
    let def = HealthcheckDefinition::parse(&RawHealthcheck {
        command: vec!["/bin/true".into()],
        interval: Some(interval.into()),
        timeout: Some(timeout.into()),
        retries: Some(2),
        ..Default::default()
    })
    .unwrap();
    HealthWiring::new(&def, factory).unwrap()
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + DEADLINE;
    while Instant::now() < end {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("timed out waiting for: {what}");
}

/// `health` の変化を重複なしで集める（ポーリング）。
fn collect_transitions(store: &Arc<MemStore>, until: HealthStatus, seen: &mut Vec<HealthStatus>) {
    wait_until("health transition", || {
        if let Some(h) = snapshot(store).health()
            && seen.last() != Some(&h)
        {
            seen.push(h);
        }
        seen.last() == Some(&until)
    });
}

fn config() -> MonitorConfig {
    MonitorConfig::new(Duration::from_millis(10)).unwrap()
}

/// SUP-4・TASK-161（#2953）: 定義がある monitor は `health` を `Starting` → `Healthy` → `Unhealthy` と遷移させる
/// （retries=2 の連続失敗で `Unhealthy`）。停止要求で監視権を戻し、周期実行のスレッドが残らない。
#[test]
fn sup4_2953_monitor_records_healthy_then_unhealthy() {
    let store = store_with(None, 42);
    let factory = ScriptedFactory::new(&[
        HealthStatus::Healthy,
        HealthStatus::Healthy,
        HealthStatus::Unhealthy,
    ]);
    let health = wiring(factory.clone(), "20ms");
    let stop = StopToken::new();
    let exit = Arc::new(AtomicBool::new(false));
    let handle = {
        let (store, stop, exit) = (store.clone(), stop.clone(), exit.clone());
        std::thread::spawn(move || {
            let mut state = attach(&store);
            let p = FakeProc { pid: 42, exit };
            monitor_with_health(&mut state, &p, &config(), &stop, &NoObs, &health)
        })
    };
    let mut seen = Vec::new();
    collect_transitions(&store, HealthStatus::Unhealthy, &mut seen);
    assert_eq!(seen.last(), Some(&HealthStatus::Unhealthy));
    assert!(seen.contains(&HealthStatus::Healthy), "{seen:?}");
    assert!(
        !seen.contains(&HealthStatus::Unhealthy) || seen.last() == Some(&HealthStatus::Unhealthy)
    );
    stop.request_stop();
    let out = handle.join().unwrap().unwrap();
    assert!(
        matches!(out, MonitorOutcome::StopRequested { .. }),
        "{out:?}"
    );
    let rec = snapshot(&store);
    assert_eq!(rec.supervision().supervisor_pid(), None);
    assert!(matches!(rec.status().state(), ContainerState::Running));
    // 停止後は周期実行が止まる。回数が増えず、工場の probe を握っているのはこのテストだけ(スレッドが解放した)。
    let probe = factory.probe(0);
    let calls = probe.calls();
    assert!(calls >= 3, "{calls}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(probe.calls(), calls);
    drop(factory);
    assert_eq!(Arc::strong_count(&probe), 1);
}

/// SUP-4・SUP-3（#2953）: 終了検知では周期実行を終了記録より前に止める。終了記録の後に `health` の書き込みが割り込まない。
#[test]
fn sup4_2953_exit_stops_before_record_exit() {
    let store = store_with(None, 42);
    let factory = ScriptedFactory::new(&[HealthStatus::Healthy]);
    let health = wiring(factory.clone(), "10ms");
    let exit = Arc::new(AtomicBool::new(false));
    let handle = {
        let (store, exit) = (store.clone(), exit.clone());
        std::thread::spawn(move || {
            let mut state = attach(&store);
            let p = FakeProc { pid: 42, exit };
            monitor_with_health(
                &mut state,
                &p,
                &config(),
                &StopToken::new(),
                &NoObs,
                &health,
            )
        })
    };
    wait_until("healthy", || {
        snapshot(&store).health() == Some(HealthStatus::Healthy)
    });
    exit.store(true, Ordering::SeqCst);
    let out = handle.join().unwrap().unwrap();
    let MonitorOutcome::Exited { record, .. } = out else {
        panic!("expected Exited, got {out:?}");
    };
    let revision = record.revision();
    let probe = factory.probe(0);
    let calls = probe.calls();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(snapshot(&store).revision(), revision);
    assert_eq!(probe.calls(), calls);
    assert!(matches!(
        snapshot(&store).status().state(),
        ContainerState::Stopped
    ));
}

/// SUP-4・SUP-3（#2953）: restart の再 launch で周期実行が新しいプロセスへ付け替わる。工場は pid 42・43 の順に 1 回ずつ呼ばれ、
/// 古い(42)の probe は 43 の最初の判定より後に呼ばれず、`RestartUnrecorded` にならない(20 回繰り返す)。
#[test]
fn sup3_sup4_2953_restart_reattaches_probe() {
    for round in 0..20 {
        let store = store_with(None, 42);
        let factory = ScriptedFactory::new(&[HealthStatus::Healthy]);
        let health = wiring(factory.clone(), "5ms");
        let stop = StopToken::new();
        let first_exit = Arc::new(AtomicBool::new(false));
        let second_exit = Arc::new(AtomicBool::new(false));

        struct Respawn(Arc<AtomicBool>);
        impl Relauncher for Respawn {
            fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
                Ok(Box::new(FakeProc {
                    pid: 43,
                    exit: Arc::clone(&self.0),
                }))
            }
        }
        let relauncher: Arc<dyn Relauncher> = Arc::new(Respawn(second_exit.clone()));
        let handle = {
            let (store, stop, first_exit) = (store.clone(), stop.clone(), first_exit.clone());
            std::thread::spawn(move || {
                let mut state = attach(&store);
                let process: Box<dyn LaunchedProcess> = Box::new(FakeProc {
                    pid: 42,
                    exit: first_exit,
                });
                let restart = RestartConfig::new(RestartPolicy::OnFailure {
                    max_retries: NonZeroU32::new(1),
                })
                .with_backoff(Duration::ZERO)
                .unwrap();
                supervise_with_restart_health(
                    &mut state,
                    process,
                    &relauncher,
                    &config(),
                    &restart,
                    &stop,
                    &NoObs,
                    Some(&health),
                )
            })
        };
        let old = {
            wait_until("first generation probe", || !factory.pids().is_empty());
            factory.probe(0)
        };
        wait_until("first generation healthy", || old.calls() >= 2);
        first_exit.store(true, Ordering::SeqCst);
        wait_until("second generation probe", || factory.pids().len() == 2);
        let new = factory.probe(1);
        wait_until("second generation ticks", || new.calls() >= 2);
        let old_calls = old.calls();
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            old.calls(),
            old_calls,
            "round {round}: old probe kept running"
        );
        stop.request_stop();
        let out = handle.join().unwrap().unwrap();
        let SuperviseOutcome::Stopped { restarts, .. } = out else {
            panic!("round {round}: expected Stopped, got {out:?}");
        };
        assert_eq!(restarts, 1, "round {round}");
        assert_eq!(factory.pids(), vec![42, 43], "round {round}");
        assert_eq!(snapshot(&store).restart_count(), 1);
    }
}

/// SUP-4（#2953）: probe を作れない(pidfd が無い等)ときは `Healthy` にならず、retries の後に `Unhealthy` になる(fail-closed)。
#[test]
fn sup4_2953_factory_failure_never_healthy() {
    let store = store_with(None, 42);
    let health = wiring(ScriptedFactory::failing(), "10ms");
    let stop = StopToken::new();
    let handle = {
        let (store, stop) = (store.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut state = attach(&store);
            let p = FakeProc {
                pid: 42,
                exit: Arc::new(AtomicBool::new(false)),
            };
            monitor_with_health(&mut state, &p, &config(), &stop, &NoObs, &health)
        })
    };
    let mut seen = Vec::new();
    collect_transitions(&store, HealthStatus::Unhealthy, &mut seen);
    assert!(!seen.contains(&HealthStatus::Healthy), "{seen:?}");
    stop.request_stop();
    handle.join().unwrap().unwrap();
}

/// SUP-4（#2953）: 前の世代の `Healthy` は、監視権の取得と同じ書き込みで `Starting` に戻る(probe が一度も走る前でも)。
#[test]
fn sup4_2953_claim_resets_stale_healthy() {
    let store = store_with(Some(HealthStatus::Healthy), 42);
    // interval 1h: 判定は走らない。
    let health = wiring(ScriptedFactory::new(&[HealthStatus::Healthy]), "1h");
    let stop = StopToken::new();
    let handle = {
        let (store, stop) = (store.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut state = attach(&store);
            let p = FakeProc {
                pid: 42,
                exit: Arc::new(AtomicBool::new(false)),
            };
            monitor_with_health(&mut state, &p, &config(), &stop, &NoObs, &health)
        })
    };
    wait_until("claim", || {
        snapshot(&store).supervision().supervisor_pid().is_some()
    });
    assert_eq!(snapshot(&store).health(), Some(HealthStatus::Starting));
    stop.request_stop();
    handle.join().unwrap().unwrap();
}

fn run_supervised_once(health: Option<HealthWiring>, store: &Arc<MemStore>) -> u8 {
    struct NeverRelaunch;
    impl Relauncher for NeverRelaunch {
        fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "not expected"))
        }
    }
    let exit = Arc::new(AtomicBool::new(false));
    let flip = Arc::clone(&exit);
    let timer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        flip.store(true, Ordering::SeqCst);
    });
    let running = Running {
        process: Box::new(FakeProc { pid: 42, exit }),
        relauncher: Arc::new(NeverRelaunch),
        instance: None,
        logs: None,
        seccomp: None,
    };
    let dyn_store: Arc<dyn StateStore> = store.clone();
    let code = run_supervised_with_health(
        dyn_store,
        ContainerId::new("c1").unwrap(),
        running,
        RestartPolicy::No,
        &StartTimeouts::default(),
        &StopToken::new(),
        health,
    );
    timer.join().unwrap();
    code
}

/// SUP-4（#2953）: supervisor の入口は、定義が無ければ工場を呼ばず `health` も書かない。定義があれば注入した工場の probe が回る。
#[test]
fn sup4_2953_entry_without_definition_starts_nothing() {
    let store = store_with(None, 42);
    let factory = ScriptedFactory::new(&[HealthStatus::Healthy]);
    let code = run_supervised_once(None, &store);
    assert_eq!(code, 0);
    assert!(factory.pids().is_empty());
    assert_eq!(snapshot(&store).health(), None);

    let store = store_with(None, 42);
    let factory = ScriptedFactory::new(&[HealthStatus::Healthy]);
    let code = run_supervised_once(Some(wiring(factory.clone(), "10ms")), &store);
    assert_eq!(code, 0);
    assert_eq!(factory.pids(), vec![42]);
    assert!(factory.probe(0).calls() >= 1);
    assert_eq!(snapshot(&store).health(), Some(HealthStatus::Healthy));
}

/// 実行中は旗が立つまで(または `release` が立つまで)戻らない probe。`honor_cancel` が偽なら cancel の旗を無視する。
struct BlockingProbe {
    started: AtomicBool,
    honor_cancel: bool,
    release: Arc<AtomicBool>,
}

impl HealthProbe for BlockingProbe {
    fn probe(&self, timeout: Duration) -> Result<HealthStatus, TraitError> {
        self.probe_cancellable(timeout, &ProbeCancel::new())
    }
    fn probe_cancellable(
        &self,
        timeout: Duration,
        cancel: &ProbeCancel,
    ) -> Result<HealthStatus, TraitError> {
        self.started.store(true, Ordering::SeqCst);
        let end = Instant::now() + timeout;
        while Instant::now() < end && !self.release.load(Ordering::SeqCst) {
            if self.honor_cancel && cancel.is_cancelled() {
                return Err(TraitError::new(ErrorCode::Internal, "cancelled"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(HealthStatus::Healthy)
    }
}

struct BlockingFactory(Arc<BlockingProbe>);

impl HealthProbeFactory for BlockingFactory {
    fn probe_for(&self, _: &dyn LaunchedProcess) -> Result<Arc<dyn HealthProbe>, TraitError> {
        Ok(self.0.clone())
    }
}

/// 実行中の判定を持つ monitor を停止し、戻るまでの時間を測る。`StopRequested` と監視権の解放も照合する。
fn stop_while_probing(honor_cancel: bool) -> (Duration, Arc<AtomicBool>, Arc<BlockingProbe>) {
    let store = store_with(None, 42);
    let release = Arc::new(AtomicBool::new(false));
    let probe = Arc::new(BlockingProbe {
        started: AtomicBool::new(false),
        honor_cancel,
        release: release.clone(),
    });
    // timeout 30s(上限 60s 以内)。cancel も timeout も待たずに止まることを見る。
    let health = wiring_with_timeout(Arc::new(BlockingFactory(probe.clone())), "5ms", "30s");
    let stop = StopToken::new();
    let handle = {
        let (store, stop) = (store.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut state = attach(&store);
            let p = FakeProc {
                pid: 42,
                exit: Arc::new(AtomicBool::new(false)),
            };
            monitor_with_health(&mut state, &p, &config(), &stop, &NoObs, &health)
        })
    };
    wait_until("probe started", || probe.started.load(Ordering::SeqCst));
    let started = Instant::now();
    stop.request_stop();
    let out = handle.join().unwrap().unwrap();
    let elapsed = started.elapsed();
    assert!(
        matches!(out, MonitorOutcome::StopRequested { .. }),
        "{out:?}"
    );
    assert_eq!(snapshot(&store).supervision().supervisor_pid(), None);
    (elapsed, release, probe)
}

/// SUP-4・REPAIR-5（#2953）: 停止要求は実行中の判定の cancel の旗を立てて止める。timeout(30 秒)も停止の上限(3 秒)も待たない。
#[test]
fn sup4_2953_stop_cancels_running_probe() {
    let (elapsed, release, probe) = stop_while_probing(true);
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    release.store(true, Ordering::SeqCst);
    drop(probe);
}

/// REPAIR-5（#2953）: cancel を無視する判定でも monitor は停止の上限(3 秒)を過ぎて戻る(スレッドは切り離す)。
#[test]
fn repair5_2953_stop_is_bounded_when_probe_ignores_cancel() {
    let (elapsed, release, _probe) = stop_while_probing(false);
    assert!(elapsed >= Duration::from_secs(2), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
    // 切り離したスレッドを解放する。
    release.store(true, Ordering::SeqCst);
}
