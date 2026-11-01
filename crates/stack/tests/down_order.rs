//! `down` の依存逆順停止の結合試験（STACK-8・TASK-155.3・#620・REPAIR-12）。
//!
//! 公開 API（`cli::down::down` と注入ポート）だけで、停止順が起動順の逆であること、
//! 計画失敗時に何も止めないこと、部分失敗でも残りを止めること、`up` 後に全サービスが
//! 停止状態になること（受け入れ条件）、秘密値の非露出を偽の世界で具体値照合する。
//! 実プロセスを起動しないため既定のテスト集合で走る。
//!
//! 範囲外: 本番の stopper、CLI 結線（#3639）、実プロセスでの停止順実測（STACK-10・TASK-188）。

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::{Duration, Instant};

use fandhe_container_stack::cli::{
    LaunchError, LaunchedService, ServiceLauncher, ServiceStopper, StopError, StopOutcome,
    UpPolicy, down, up,
};
use fandhe_container_stack::depends_on::wait::{
    DependencyObservation, DependencyObserver, ObserveError, WaitClock,
};
use fandhe_container_stack::depends_on::{
    HealthSource, HealthSourceError, ObservedHealth, PollClock, plan_startup,
};
use fandhe_container_stack::schema::{ComposeToml, Service};

const POC17: &str = include_str!("../testdata/depends_on_poc17.toml");
const CYCLE: &str = include_str!("../testdata/depends_on_cycle.toml");
const DIAMOND: &str = r#"
[project]
name = "diamond"

[services.base]
image = "example/base:1"

[services.left]
image = "example/left:1"
[services.left.depends_on]
base = "started"

[services.right]
image = "example/right:1"
[services.right.depends_on]
base = "started"

[services.top]
image = "example/top:1"
[services.top.depends_on]
left = "started"
right = "started"
"#;
const CHAIN: &str = r#"
[project]
name = "chain"

[services.c]
image = "example/c:1"
[services.c.depends_on]
b = "started"

[services.b]
image = "example/b:1"
[services.b.depends_on]
a = "started"

[services.a]
image = "example/a:1"
"#;
const INDEPENDENT: &str = r#"
[project]
name = "independent"

[services.zeta]
image = "example/zeta:1"

[services.alpha]
image = "example/alpha:1"

[services.mid]
image = "example/mid:1"
"#;
const SECRET: &str = r#"
[project]
name = "secret"

[services.a]
image = "example/a:1"
[services.a.env]
TOKEN = "DUMMY_SECRET_VALUE"

[services.b]
image = "example/b:1"
[services.b.env]
TOKEN = "DUMMY_SECRET_VALUE"
[services.b.depends_on]
a = "started"
"#;

fn services_of(src: &str) -> BTreeMap<String, Service> {
    let parsed: ComposeToml = toml::from_str(src).unwrap();
    parsed.services
}

fn startup_order(services: &BTreeMap<String, Service>) -> Vec<String> {
    plan_startup(services)
        .unwrap()
        .service_names()
        .map(str::to_owned)
        .collect()
}

/// 呼び出し順を記録する偽の stopper。
#[derive(Default)]
struct Recorder {
    calls: Vec<String>,
    fail_on: Option<&'static str>,
    already: Option<&'static str>,
}
impl ServiceStopper for Recorder {
    fn stop(&mut self, service: &str, _spec: &Service) -> Result<StopOutcome, StopError> {
        self.calls.push(service.to_string());
        if self.fail_on == Some(service) {
            return Err(StopError::new("TEST_STOP_FAILED", "injected"));
        }
        if self.already == Some(service) {
            return Ok(StopOutcome::AlreadyStopped);
        }
        Ok(StopOutcome::Stopped)
    }
}

/// STACK-8・TASK-155.3: 停止順は起動順（`plan_startup`）の逆と完全に一致する（受け入れ条件）。
#[test]
fn stack8_down_order_is_reverse_of_plan() {
    for src in [DIAMOND, CHAIN, INDEPENDENT, POC17] {
        let services = services_of(src);
        let mut expected = startup_order(&services);
        expected.reverse();
        let mut r = Recorder::default();
        let report = down(&services, &mut r).unwrap();
        assert_eq!(r.calls, expected);
        let reported: Vec<String> = report.service_names().map(str::to_owned).collect();
        assert_eq!(reported, expected);
    }
    let mut r = Recorder::default();
    down(&services_of(CHAIN), &mut r).unwrap();
    assert_eq!(r.calls, ["c", "b", "a"]);
}

/// STACK-8: 循環は何も止めずに失敗する（fail-closed。終了コード 2）。
#[test]
fn stack8_down_cycle_stops_nothing() {
    let mut r = Recorder::default();
    let f = down(&services_of(CYCLE), &mut r).unwrap_err();
    assert_eq!(f.code(), "DEPENDENCY_CYCLE");
    assert_eq!(f.exit_code().get(), 2);
    assert!(r.calls.is_empty());
    assert!(f.stopped().is_empty());
}

/// STACK-8: 1 件の停止失敗でも残りを停止し、失敗を集めて返す。
#[test]
fn stack8_down_continues_after_stop_failure() {
    let mut r = Recorder {
        fail_on: Some("b"),
        ..Recorder::default()
    };
    let f = down(&services_of(CHAIN), &mut r).unwrap_err();
    assert_eq!(r.calls, ["c", "b", "a"]);
    assert_eq!(f.errors().len(), 1);
    assert_eq!(f.code(), "SERVICE_STOP_FAILED");
    assert_eq!(f.exit_code().get(), 1);
    match &f.errors()[0] {
        fandhe_container_stack::cli::DownError::Stop { service, source } => {
            assert_eq!(service, "b");
            assert_eq!(source.code(), "TEST_STOP_FAILED");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    let stopped: Vec<&str> = f.stopped().iter().map(|s| s.service()).collect();
    assert_eq!(stopped, ["c", "a"]);
}

/// STACK-8: 既に停止済みは失敗ではなく、結果として報告される。
#[test]
fn stack8_down_already_stopped_is_success() {
    let mut r = Recorder {
        already: Some("b"),
        ..Recorder::default()
    };
    let report = down(&services_of(CHAIN), &mut r).unwrap();
    let outcomes: Vec<(&str, StopOutcome)> = report
        .steps()
        .iter()
        .map(|s| (s.service(), s.outcome()))
        .collect();
    assert_eq!(
        outcomes,
        [
            ("c", StopOutcome::Stopped),
            ("b", StopOutcome::AlreadyStopped),
            ("a", StopOutcome::Stopped),
        ]
    );
}

/// STACK-8・SEC-1: env の秘密値は失敗・報告の Display・Debug に現れない。
#[test]
fn stack8_down_does_not_leak_service_contents() {
    let services = services_of(SECRET);
    let mut r = Recorder {
        fail_on: Some("b"),
        ..Recorder::default()
    };
    let f = down(&services, &mut r).unwrap_err();
    assert_eq!(
        f.to_string(),
        "failed to stop a service: b (TEST_STOP_FAILED) (failed: 1, stopped: 1)"
    );
    for text in [format!("{f}"), format!("{f:?}")] {
        assert!(!text.contains("DUMMY_SECRET_VALUE"));
    }
    let ok = down(&services, &mut Recorder::default()).unwrap();
    assert!(!format!("{ok:?}").contains("DUMMY_SECRET_VALUE"));
}

/// STACK-8: サービスが無いプロジェクトは何もせず成功する。
#[test]
fn stack8_down_empty_project() {
    let mut r = Recorder::default();
    let report = down(&BTreeMap::new(), &mut r).unwrap();
    assert!(report.steps().is_empty());
    assert!(r.calls.is_empty());
}

/// 起動中集合を共有する launcher・stopper・観測の偽の世界。
#[derive(Clone, Default)]
struct World {
    running: Rc<RefCell<BTreeSet<String>>>,
    stops: Rc<RefCell<Vec<String>>>,
}
impl ServiceLauncher for World {
    fn launch(&mut self, service: &str, _spec: &Service) -> Result<LaunchedService, LaunchError> {
        self.running.borrow_mut().insert(service.to_string());
        Ok(LaunchedService::new(service, format!("id-{service}")))
    }
}
impl ServiceStopper for World {
    fn stop(&mut self, service: &str, _spec: &Service) -> Result<StopOutcome, StopError> {
        self.stops.borrow_mut().push(service.to_string());
        Ok(if self.running.borrow_mut().remove(service) {
            StopOutcome::Stopped
        } else {
            StopOutcome::AlreadyStopped
        })
    }
}
impl DependencyObserver for World {
    fn observe(&mut self, s: &str) -> Result<DependencyObservation, ObserveError> {
        Ok(if self.running.borrow().contains(s) {
            DependencyObservation::Running
        } else {
            DependencyObservation::Absent
        })
    }
}
impl HealthSource for World {
    fn observe(&mut self, s: &str) -> Result<Option<ObservedHealth>, HealthSourceError> {
        Ok(self
            .running
            .borrow()
            .contains(s)
            .then_some(ObservedHealth::Healthy))
    }
}

struct Clk {
    t: Rc<Cell<Duration>>,
    base: Instant,
}
impl PollClock for Clk {
    fn now(&self) -> Duration {
        self.t.get()
    }
    fn sleep(&mut self, d: Duration) {
        self.t.set(self.t.get() + d);
    }
}
impl WaitClock for Clk {
    fn now(&self) -> Instant {
        self.base + self.t.get()
    }
    fn sleep_until(&mut self, deadline: Instant) {
        let target = deadline.saturating_duration_since(self.base);
        self.t.set(self.t.get().max(target));
    }
}

/// STACK-8・TASK-155.3: `up` の後に `down` すると全サービスが停止状態になる（受け入れ条件）。
#[test]
fn stack8_down_all_services_stopped_after_up() {
    let services = services_of(POC17);
    let world = World::default();
    let mut clk = Clk {
        t: Rc::new(Cell::new(Duration::ZERO)),
        base: Instant::now(),
    };
    let up_report = up(
        &services,
        &mut world.clone(),
        &mut world.clone(),
        &mut world.clone(),
        &mut clk,
        &UpPolicy::default(),
    )
    .unwrap();
    let up_order: Vec<String> = up_report.service_names().map(str::to_owned).collect();
    assert_eq!(world.running.borrow().len(), services.len());

    let report = down(&services, &mut world.clone()).unwrap();
    assert!(world.running.borrow().is_empty());
    let mut expected = up_order;
    expected.reverse();
    let stopped: Vec<String> = report.service_names().map(str::to_owned).collect();
    assert_eq!(stopped, expected);
    assert_eq!(*world.stops.borrow(), expected);
    assert!(
        report
            .steps()
            .iter()
            .all(|s| s.outcome() == StopOutcome::Stopped)
    );
}
