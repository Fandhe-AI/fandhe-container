//! `up` のトポロジカル順起動の結合試験（STACK-8・STACK-2・TASK-155.1・#618・REPAIR-12）。
//!
//! 公開 API（`cli::up::up` と注入ポート）だけで、起動順が `plan_startup` の結果と一致すること
//! （受け入れ条件）、待ちの成立が依存元の起動より前であること、事前検査での起動ゼロ、
//! 途中失敗時の停止、秘密値の非露出を、偽の世界・仮想時計で具体値照合する。
//! 実プロセスを起動しないため既定のテスト集合で走り、実機前提テストへの分離は不要。
//!
//! 範囲外: 本番の launcher・観測アダプタ、CLI 結線（#3639）、実プロセスでの起動順実測（STACK-10・TASK-188）。

use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use fandhe_container_stack::cli::{
    LaunchError, LaunchedService, ServiceLauncher, UpError, UpPolicy, up,
};
use fandhe_container_stack::depends_on::wait::{
    DependencyObservation, DependencyObserver, ObserveError, WaitClock, WaitPolicy,
};
use fandhe_container_stack::depends_on::{
    HealthSource, HealthSourceError, HealthyWaitPolicy, ObservedHealth, PollClock, plan_startup,
};
use fandhe_container_stack::schema::{ComposeToml, DependsOnCondition, Service};

const POC17: &str = include_str!("../testdata/depends_on_poc17.toml");
const NEVER: &str = include_str!("../testdata/depends_on_poc17_neverhealthy.toml");
const CYCLE: &str = include_str!("../testdata/depends_on_cycle.toml");
const MIXED: &str = r#"
[project]
name = "mixed"

[services.db]
image = "example/db:1"

[services.cache]
image = "example/cache:1"

[services.app]
image = "example/app:1"

[services.app.depends_on]
db = "healthy"
cache = "started"
"#;
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
const COMPLETED_LATE: &str = r#"
[project]
name = "completed-late"

[services.a]
image = "example/a:1"

[services.b]
image = "example/b:1"
[services.b.depends_on]
a = "started"

[services.job]
image = "example/job:1"

[services.z]
image = "example/z:1"
[services.z.depends_on]
job = "completed"
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

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn services_of(src: &str) -> BTreeMap<String, Service> {
    let parsed: ComposeToml = toml::from_str(src).unwrap();
    parsed.services
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

/// launcher・observer・health source を兼ねる偽の世界。
struct World {
    t: Rc<Cell<Duration>>,
    healthy_after: BTreeMap<&'static str, Option<Duration>>,
    running_after: BTreeMap<&'static str, Duration>,
    fail_on: Option<&'static str>,
    started: BTreeMap<String, Duration>,
    launched_images: Vec<(String, String)>,
    events: Vec<(Duration, String)>,
    observe_calls: usize,
    health_calls: usize,
}
impl World {
    fn new() -> (Self, Clk) {
        let t = Rc::new(Cell::new(Duration::ZERO));
        let clk = Clk {
            t: t.clone(),
            base: Instant::now(),
        };
        (
            Self {
                t,
                // 既定では db は起動直後に healthy（個別の試験が上書きする）。
                healthy_after: BTreeMap::from([("db", Some(Duration::ZERO))]),
                running_after: BTreeMap::new(),
                fail_on: None,
                started: BTreeMap::new(),
                launched_images: vec![],
                events: vec![],
                observe_calls: 0,
                health_calls: 0,
            },
            clk,
        )
    }
    fn note(&mut self, e: String) {
        if !self.events.iter().any(|(_, x)| *x == e) {
            self.events.push((self.t.get(), e));
        }
    }
    fn pos(&self, e: &str) -> usize {
        self.events.iter().position(|(_, x)| x == e).unwrap()
    }
    fn at(&self, e: &str) -> Duration {
        self.events.iter().find(|(_, x)| x == e).unwrap().0
    }
    fn order(&self) -> Vec<String> {
        self.launched_images
            .iter()
            .map(|(n, _)| n.clone())
            .collect()
    }
}
impl ServiceLauncher for World {
    fn launch(&mut self, service: &str, spec: &Service) -> Result<LaunchedService, LaunchError> {
        if self.fail_on == Some(service) {
            return Err(LaunchError::new("TEST_LAUNCH", "test launch failure"));
        }
        self.started.insert(service.to_string(), self.t.get());
        self.launched_images
            .push((service.to_string(), spec.image.clone().unwrap_or_default()));
        self.note(format!("start:{service}"));
        Ok(LaunchedService::new(service, format!("id-{service}")))
    }
}
impl HealthSource for World {
    fn observe(&mut self, s: &str) -> Result<Option<ObservedHealth>, HealthSourceError> {
        self.health_calls += 1;
        let Some(st) = self.started.get(s).copied() else {
            return Ok(None);
        };
        let el = self.t.get() - st;
        Ok(match self.healthy_after.get(s).copied() {
            Some(Some(d)) if el >= d => {
                self.note(format!("healthy:{s}"));
                Some(ObservedHealth::Healthy)
            }
            Some(Some(_)) => Some(ObservedHealth::Starting),
            Some(None) => Some(ObservedHealth::Unhealthy),
            None => None,
        })
    }
}
impl DependencyObserver for World {
    fn observe(&mut self, s: &str) -> Result<DependencyObservation, ObserveError> {
        self.observe_calls += 1;
        let Some(st) = self.started.get(s).copied() else {
            return Ok(DependencyObservation::Absent);
        };
        let need = self.running_after.get(s).copied().unwrap_or(Duration::ZERO);
        if self.t.get() - st >= need {
            self.note(format!("running:{s}"));
            Ok(DependencyObservation::Running)
        } else {
            Ok(DependencyObservation::Created)
        }
    }
}

fn policy(timeout: Duration) -> UpPolicy {
    UpPolicy {
        started: WaitPolicy::new(ms(100), timeout).unwrap(),
        healthy: HealthyWaitPolicy::new(ms(100), timeout).unwrap(),
    }
}

fn run(
    services: &BTreeMap<String, Service>,
    w: &mut World,
    clk: &mut Clk,
    p: &UpPolicy,
) -> Result<fandhe_container_stack::cli::UpReport, fandhe_container_stack::cli::UpFailure> {
    // World は 3 つのポートを兼ねるため、同じ可変参照を複数渡せない。共有セル越しの薄い委譲を挟む。
    let cell = std::cell::RefCell::new(w);
    struct Shared<'a, 'b>(&'a std::cell::RefCell<&'b mut World>);
    impl ServiceLauncher for Shared<'_, '_> {
        fn launch(&mut self, s: &str, sp: &Service) -> Result<LaunchedService, LaunchError> {
            ServiceLauncher::launch(&mut **self.0.borrow_mut(), s, sp)
        }
    }
    impl DependencyObserver for Shared<'_, '_> {
        fn observe(&mut self, s: &str) -> Result<DependencyObservation, ObserveError> {
            DependencyObserver::observe(&mut **self.0.borrow_mut(), s)
        }
    }
    impl HealthSource for Shared<'_, '_> {
        fn observe(&mut self, s: &str) -> Result<Option<ObservedHealth>, HealthSourceError> {
            HealthSource::observe(&mut **self.0.borrow_mut(), s)
        }
    }
    up(
        services,
        &mut Shared(&cell),
        &mut Shared(&cell),
        &mut Shared(&cell),
        clk,
        p,
    )
}

fn expected_order(services: &BTreeMap<String, Service>) -> Vec<String> {
    plan_startup(services)
        .unwrap()
        .service_names()
        .map(str::to_owned)
        .collect()
}

/// STACK-8・TASK-155.1: 起動順は各形で `plan_startup` の結果と完全に一致する（受け入れ条件）。
#[test]
fn stack_8_launch_order_matches_plan_startup() {
    for src in [POC17, DIAMOND, CHAIN, INDEPENDENT, MIXED] {
        let services = services_of(src);
        let (mut w, mut clk) = World::new();
        let report = run(
            &services,
            &mut w,
            &mut clk,
            &policy(Duration::from_secs(10)),
        )
        .unwrap();
        assert_eq!(w.order(), expected_order(&services));
        let reported: Vec<String> = report.service_names().map(str::to_owned).collect();
        assert_eq!(reported, expected_order(&services));
    }
    let (mut w, mut clk) = World::new();
    run(
        &services_of(POC17),
        &mut w,
        &mut clk,
        &policy(Duration::from_secs(10)),
    )
    .unwrap();
    assert_eq!(w.order(), vec!["db", "app", "gateway"]);
    let (mut w, mut clk) = World::new();
    run(
        &services_of(CHAIN),
        &mut w,
        &mut clk,
        &policy(Duration::from_secs(10)),
    )
    .unwrap();
    assert_eq!(w.order(), vec!["a", "b", "c"]);
    let (mut w, mut clk) = World::new();
    run(
        &services_of(INDEPENDENT),
        &mut w,
        &mut clk,
        &policy(Duration::from_secs(10)),
    )
    .unwrap();
    assert_eq!(w.order(), vec!["alpha", "mid", "zeta"]);
}

/// STACK-8: launch に渡る Service は map の値（image で照合）。
#[test]
fn stack_8_launch_receives_matching_service_spec() {
    let services = services_of(POC17);
    let (mut w, mut clk) = World::new();
    run(
        &services,
        &mut w,
        &mut clk,
        &policy(Duration::from_secs(10)),
    )
    .unwrap();
    assert_eq!(
        w.launched_images,
        vec![
            ("db".to_string(), "example/db:1".to_string()),
            ("app".to_string(), "example/app:1".to_string()),
            ("gateway".to_string(), "example/gateway:1".to_string()),
        ]
    );
}

/// STACK-8・STACK-2: 依存先の待ちの成立が依存元の起動より前で、仮想時刻も具体値で一致する。
#[test]
fn stack_8_waits_are_satisfied_before_dependents_start() {
    let services = services_of(POC17);
    let (mut w, mut clk) = World::new();
    w.healthy_after.insert("db", Some(Duration::from_secs(5)));
    w.running_after.insert("app", ms(300));
    run(
        &services,
        &mut w,
        &mut clk,
        &policy(Duration::from_secs(10)),
    )
    .unwrap();
    assert!(w.pos("healthy:db") < w.pos("start:app"));
    assert!(w.pos("running:app") < w.pos("start:gateway"));
    assert_eq!(w.at("start:db"), Duration::ZERO);
    assert_eq!(w.at("start:app"), Duration::from_secs(5));
    assert_eq!(w.at("start:gateway"), ms(5300));
}

/// STACK-8: healthy と started が混在するステップが成功し、両方の待ちが報告に載る。
#[test]
fn stack_8_mixed_step_waits_for_both_conditions() {
    let services = services_of(MIXED);
    let (mut w, mut clk) = World::new();
    w.healthy_after.insert("db", Some(ms(200)));
    let report = run(
        &services,
        &mut w,
        &mut clk,
        &policy(Duration::from_secs(10)),
    )
    .unwrap();
    let app = report.steps().last().unwrap();
    assert_eq!(app.launched().service(), "app");
    assert_eq!(app.launched().container_id(), "id-app");
    assert_eq!(app.healthy_waits().len(), 1);
    assert_eq!(app.healthy_waits()[0].service(), "db");
    assert_eq!(app.started_waits().outcomes.len(), 1);
    assert_eq!(app.started_waits().outcomes[0].dependency, "cache");
    assert_eq!(
        app.started_waits().outcomes[0].condition,
        DependsOnCondition::Started
    );
    assert!(w.pos("healthy:db") < w.pos("start:app"));
    assert!(w.pos("running:cache") < w.pos("start:app"));
}

/// STACK-8: 循環は起動ゼロ・観測ゼロで終了コード 2。
#[test]
fn stack_8_cycle_launches_nothing() {
    let services = services_of(CYCLE);
    let (mut w, mut clk) = World::new();
    let f = run(
        &services,
        &mut w,
        &mut clk,
        &policy(Duration::from_secs(10)),
    )
    .unwrap_err();
    assert!(matches!(f.error(), UpError::Plan(_)));
    assert_eq!(f.error().code(), "DEPENDENCY_CYCLE");
    assert_eq!(f.error().exit_code().get(), 2);
    assert!(f.launched().is_empty());
    assert!(w.launched_images.is_empty());
    assert_eq!(w.observe_calls, 0);
    assert_eq!(w.health_calls, 0);
}

/// STACK-8: 後段にだけ completed があっても事前検査で起動ゼロ・終了コード 8。
#[test]
fn stack_8_completed_condition_stops_before_any_launch() {
    let services = services_of(COMPLETED_LATE);
    let (mut w, mut clk) = World::new();
    let f = run(
        &services,
        &mut w,
        &mut clk,
        &policy(Duration::from_secs(10)),
    )
    .unwrap_err();
    assert_eq!(f.error().code(), "DEPENDENCY_CONDITION_UNSUPPORTED");
    assert_eq!(f.error().exit_code().get(), 8);
    assert!(f.launched().is_empty());
    assert!(w.launched_images.is_empty());
    assert_eq!(w.observe_calls, 0);
}

/// STACK-8: 2 番目の launch が失敗したら 3 番目は呼ばれず、起動済みは 1 番目だけ。
#[test]
fn stack_8_launch_failure_stops_the_chain() {
    let services = services_of(CHAIN);
    let (mut w, mut clk) = World::new();
    w.fail_on = Some("b");
    let f = run(
        &services,
        &mut w,
        &mut clk,
        &policy(Duration::from_secs(10)),
    )
    .unwrap_err();
    assert_eq!(f.error().code(), "SERVICE_LAUNCH_FAILED");
    assert_eq!(f.error().exit_code().get(), 1);
    assert_eq!(f.launched(), ["a".to_string()]);
    assert_eq!(w.order(), vec!["a"]);
}

/// STACK-8・STACK-2: healthy が期限内に成立しなければ終了コード 7 で、依存元は起動しない。
#[test]
fn stack_8_healthy_timeout_blocks_dependent() {
    let services = services_of(NEVER);
    let (mut w, mut clk) = World::new();
    w.healthy_after.insert("neverdb", None);
    let f = run(&services, &mut w, &mut clk, &policy(Duration::from_secs(1))).unwrap_err();
    assert_eq!(f.error().code(), "DEPENDENCY_WAIT_TIMEOUT");
    assert_eq!(f.error().exit_code().get(), 7);
    assert_eq!(f.launched(), ["neverdb".to_string()]);
    assert_eq!(w.order(), vec!["neverdb"]);
}

/// STACK-8: 空の map は空の報告で、ポートは一切呼ばれない。
#[test]
fn stack_8_empty_services_is_noop() {
    let (mut w, mut clk) = World::new();
    let report = run(
        &BTreeMap::new(),
        &mut w,
        &mut clk,
        &policy(Duration::from_secs(1)),
    )
    .unwrap();
    assert!(report.steps().is_empty());
    assert!(w.launched_images.is_empty());
    assert_eq!(w.observe_calls, 0);
    assert_eq!(w.health_calls, 0);
}

/// STACK-8・SEC-1: env の秘密値は失敗の Display・Debug に現れない。
#[test]
fn stack_8_failure_does_not_expose_service_env() {
    let services = services_of(SECRET);
    let (mut w, mut clk) = World::new();
    w.fail_on = Some("b");
    let f = run(&services, &mut w, &mut clk, &policy(Duration::from_secs(1))).unwrap_err();
    assert_eq!(
        f.to_string(),
        "failed to launch a service: b (TEST_LAUNCH) (launched: 1)"
    );
    assert!(!format!("{f}").contains("DUMMY_SECRET_VALUE"));
    assert!(!format!("{f:?}").contains("DUMMY_SECRET_VALUE"));
}
