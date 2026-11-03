//! `depends_on` の PoC-17 相当の統合試験（STACK-2・TASK-150.5・#593・REPAIR-12）。
//!
//! 公開 API（`plan_startup`・`wait_for_step`・`require_healthy_dependencies`）だけで簡易 up ループを組み、
//! 循環検出、healthy→started の起動順、healthy 未達のタイムアウトを偽の観測・仮想時計で具体値照合する。
//!
//! 実プロセスを起動しないため既定のテスト集合（`cargo test -p fandhe-container-stack`・CI の rust-ci）で走り、
//! 実機前提テストへの分離は不要。
//!
//! 範囲外: 実プロセスでの起動順実測と本番の観測アダプタ・古い世代の state.json の無視（TASK-155）、
//! `completed` 条件の待機（未実装）。

use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use fandhe_container_stack::depends_on::wait::{
    DependencyObservation, DependencyObserver, DependencyWaitError, ObserveError, WaitClock,
    WaitPolicy, wait_for_step,
};
use fandhe_container_stack::depends_on::{
    DependsOnError, HealthSource, HealthSourceError, HealthyWaitPolicy, ObservedHealth, PollClock,
    StartupPlan, plan_startup, require_healthy_dependencies,
};
use fandhe_container_stack::schema::{ComposeToml, DependsOnCondition};

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

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn plan_of(src: &str) -> StartupPlan {
    let parsed: ComposeToml = toml::from_str(src).unwrap();
    plan_startup(&parsed.services).unwrap()
}

/// 両方の時計トレイトを実装する仮想時計（共有の仮想時刻を world と分けて持つ）。
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

/// 起動時刻からの経過で状態が進む偽の世界。
struct World {
    t: Rc<Cell<Duration>>,
    /// 起動から healthy になるまで。`None` は永遠に unhealthy。記載なしは health 無し。
    healthy_after: BTreeMap<&'static str, Option<Duration>>,
    /// 起動から Running になるまで（記載なしは 0）。
    running_after: BTreeMap<&'static str, Duration>,
    started: BTreeMap<String, Duration>,
    order: Vec<String>,
    events: Vec<(Duration, String)>,
    health_calls: Vec<String>,
    observe_calls: Vec<String>,
}
impl World {
    fn new(t: &Rc<Cell<Duration>>) -> Self {
        Self {
            t: t.clone(),
            healthy_after: BTreeMap::new(),
            running_after: BTreeMap::new(),
            started: BTreeMap::new(),
            order: vec![],
            events: vec![],
            health_calls: vec![],
            observe_calls: vec![],
        }
    }
    fn note(&mut self, e: String) {
        if !self.events.iter().any(|(_, x)| *x == e) {
            self.events.push((self.t.get(), e));
        }
    }
    fn start(&mut self, s: &str) {
        self.started.insert(s.to_string(), self.t.get());
        self.order.push(s.to_string());
        self.note(format!("start:{s}"));
    }
    fn at(&self, e: &str) -> Duration {
        self.events.iter().find(|(_, x)| x == e).unwrap().0
    }
    fn pos(&self, e: &str) -> usize {
        self.events.iter().position(|(_, x)| x == e).unwrap()
    }
}
impl HealthSource for World {
    fn observe(&mut self, s: &str) -> Result<Option<ObservedHealth>, HealthSourceError> {
        self.health_calls.push(s.to_string());
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
        self.observe_calls.push(s.to_string());
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

/// 簡易 up ループ。healthy のみのステップは healthy ゲート、それ以外（空・started のみ・混在・completed）は
/// `wait_for_step`（混在・completed はここで fail-closed）。Ok のときだけ起動する。
fn run_up(
    plan: &StartupPlan,
    world: &mut World,
    clk: &mut Clk,
    hp: &HealthyWaitPolicy,
    wp: &WaitPolicy,
) -> Result<(), DependencyWaitError> {
    for step in plan.steps() {
        let all_healthy = !step.waits().is_empty()
            && step
                .waits()
                .iter()
                .all(|w| w.condition() == DependsOnCondition::Healthy);
        if all_healthy {
            require_healthy_dependencies(step, world, clk, hp)?;
        } else {
            wait_for_step(step, world, clk, wp)?;
        }
        world.start(step.service());
    }
    Ok(())
}

fn setup() -> (Rc<Cell<Duration>>, World, Clk) {
    let t = Rc::new(Cell::new(Duration::ZERO));
    let w = World::new(&t);
    let c = Clk {
        t: t.clone(),
        base: Instant::now(),
    };
    (t, w, c)
}

fn policies(timeout: Duration) -> (HealthyWaitPolicy, WaitPolicy) {
    (
        HealthyWaitPolicy::new(ms(100), timeout).unwrap(),
        WaitPolicy::new(ms(100), timeout).unwrap(),
    )
}

/// STACK-2: 循環は計画の段階で拒否され、観測も起動も一切起きない（PoC-17 の循環依存）。
#[test]
fn stack_2_poc17_cycle_rejected_before_any_start() {
    let parsed: ComposeToml = toml::from_str(CYCLE).unwrap();
    let err = plan_startup(&parsed.services).unwrap_err();
    assert_eq!(err.code(), "DEPENDENCY_CYCLE");
    match err {
        DependsOnError::Cycle { path } => {
            assert_eq!(path, vec!["api", "db", "web", "api"]);
        }
        other => panic!("unexpected: {other:?}"),
    }
    // 計画が無いので起動ループに入れない。
    let (_t, world, _c) = setup();
    assert!(world.events.is_empty());
    assert!(world.observe_calls.is_empty() && world.health_calls.is_empty());
}

/// STACK-2: db(healthy 5s 後) → app(db を healthy) → gateway(app を started) の起動順と仮想時刻。
#[test]
fn stack_2_poc17_order_healthy_then_started() {
    let plan = plan_of(POC17);
    assert_eq!(
        plan.service_names().collect::<Vec<_>>(),
        vec!["db", "app", "gateway"]
    );
    let (_t, mut world, mut clk) = setup();
    world
        .healthy_after
        .insert("db", Some(Duration::from_secs(5)));
    world.running_after.insert("app", ms(300));
    let (hp, wp) = policies(Duration::from_secs(15));
    run_up(&plan, &mut world, &mut clk, &hp, &wp).unwrap();

    assert_eq!(world.order, vec!["db", "app", "gateway"]);
    assert_eq!(world.started["db"], Duration::ZERO);
    assert_eq!(world.started["app"], Duration::from_secs(5));
    assert_eq!(world.started["gateway"], ms(5300));
    assert_eq!(world.at("healthy:db"), Duration::from_secs(5));
    assert_eq!(world.at("running:app"), ms(5300));
    assert!(world.pos("healthy:db") < world.pos("start:app"));
    assert!(world.pos("running:app") < world.pos("start:gateway"));
    // 依存先ごとに必要な観測口だけを使う。
    assert!(world.health_calls.iter().all(|s| s == "db"));
    assert_eq!(world.health_calls.len(), 51);
    assert!(world.observe_calls.iter().all(|s| s == "app"));
    assert_eq!(world.observe_calls.len(), 4);
}

/// STACK-2: healthy にならない依存先は 2s で WaitTimeout(終了コード 7)、依存元は起動しない（PoC-17）。
#[test]
fn stack_2_poc17_never_healthy_times_out_without_starting_dependent() {
    let plan = plan_of(NEVER);
    let (t, mut world, mut clk) = setup();
    world.healthy_after.insert("neverdb", None);
    let (hp, wp) = policies(Duration::from_secs(2));
    let err = run_up(&plan, &mut world, &mut clk, &hp, &wp).unwrap_err();
    assert_eq!(
        err,
        DependencyWaitError::WaitTimeout {
            service: "neverapp".into(),
            dependency: "neverdb".into(),
            condition: DependsOnCondition::Healthy,
        }
    );
    assert_eq!(err.code(), "DEPENDENCY_WAIT_TIMEOUT");
    assert_eq!(err.exit_code().get(), 7);
    assert_eq!(world.order, vec!["neverdb"]);
    assert_eq!(t.get(), Duration::from_secs(2));
    assert_eq!(world.health_calls.len(), 20);
}

/// STACK-2: healthy と started が混在するステップは fail-closed（終了コード 8）。
/// 混在ステップの待機統合は TASK-155 の配線で、統合したら本試験を更新する（REPAIR-3）。
#[test]
fn stack_2_mixed_conditions_fail_closed_until_up_wiring() {
    let plan = plan_of(MIXED);
    let (_t, mut world, mut clk) = setup();
    world.healthy_after.insert("db", Some(Duration::ZERO));
    let (hp, wp) = policies(Duration::from_secs(1));
    let err = run_up(&plan, &mut world, &mut clk, &hp, &wp).unwrap_err();
    assert_eq!(err.code(), "DEPENDENCY_CONDITION_UNSUPPORTED");
    assert_eq!(err.exit_code().get(), 8);
    assert_eq!(world.order, vec!["cache", "db"]);
    assert!(world.health_calls.is_empty() && world.observe_calls.is_empty());
}
