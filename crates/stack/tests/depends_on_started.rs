//! `depends_on` の `started` 待機の結合試験（STACK-2・TASK-150.2・#590・REPAIR-12）。
//!
//! 偽の観測・時計の世界で簡易 up ループを回し、依存元の起動が依存先の Running 観測の後に来ることを照合する。

use std::collections::BTreeMap;
use std::time::Instant;

use fandhe_container_stack::depends_on::plan_startup;
use fandhe_container_stack::depends_on::wait::{
    DependencyObservation, DependencyObserver, ObserveError, WaitClock, WaitPolicy, wait_for_step,
};
use fandhe_container_stack::schema::ComposeToml;

const ACYCLIC: &str = include_str!("../testdata/depends_on_acyclic.toml");
const STARTED_ONLY: &str = r#"
[project]
name = "started-demo"

[services.web]
image = "x"
[services.web.depends_on]
api = "started"
worker = "started"

[services.api]
image = "x"
[services.api.depends_on]
migrate = "started"

[services.worker]
image = "x"
[services.worker.depends_on]
migrate = "started"

[services.migrate]
image = "x"
"#;

/// start 後 2 回の観測は Created、3 回目で Running になる偽の世界。
#[derive(Default)]
struct World {
    started: Vec<String>,
    seen: BTreeMap<String, u32>,
    events: Vec<String>,
}

impl DependencyObserver for World {
    fn observe(&mut self, service: &str) -> Result<DependencyObservation, ObserveError> {
        if !self.started.iter().any(|s| s == service) {
            return Ok(DependencyObservation::Absent);
        }
        let n = self.seen.entry(service.to_string()).or_insert(0);
        *n += 1;
        if *n >= 3 {
            self.events.push(format!("running:{service}"));
            Ok(DependencyObservation::Running)
        } else {
            Ok(DependencyObservation::Created)
        }
    }
}

struct Clock(Instant);

impl WaitClock for Clock {
    fn now(&self) -> Instant {
        self.0
    }
    fn sleep_until(&mut self, deadline: Instant) {
        self.0 = self.0.max(deadline);
    }
}

/// STACK-2: 依存元の start は、started 依存先の Running 観測より後に来る。
#[test]
fn stack_2_started_up_loop_starts_after_dependency_running() {
    let parsed: ComposeToml = toml::from_str(STARTED_ONLY).unwrap();
    let plan = plan_startup(&parsed.services).unwrap();
    let mut world = World::default();
    let mut clock = Clock(Instant::now());
    let policy = WaitPolicy::default();
    for step in plan.steps() {
        wait_for_step(step, &mut world, &mut clock, &policy).unwrap();
        world.events.push(format!("start:{}", step.service()));
        world.started.push(step.service().to_string());
    }
    assert_eq!(world.started, vec!["migrate", "api", "worker", "web"]);
    let pos = |e: &str| world.events.iter().position(|x| x == e).unwrap();
    assert!(pos("running:migrate") < pos("start:api"));
    assert!(pos("running:migrate") < pos("start:worker"));
    assert!(pos("running:api") < pos("start:web"));
    assert!(pos("running:worker") < pos("start:web"));
}

/// STACK-2: 未対応の条件（completed）は依存元を起動させない（#591 以降まで fail-closed）。
#[test]
fn stack_2_unsupported_condition_stops_up_loop_before_dependent_start() {
    let parsed: ComposeToml = toml::from_str(ACYCLIC).unwrap();
    let plan = plan_startup(&parsed.services).unwrap();
    let mut world = World::default();
    let mut clock = Clock(Instant::now());
    let policy = WaitPolicy::default();
    let mut err = None;
    for step in plan.steps() {
        match wait_for_step(step, &mut world, &mut clock, &policy) {
            Ok(_) => world.started.push(step.service().to_string()),
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    assert_eq!(world.started, vec!["migrate"]);
    assert_eq!(err.unwrap().code(), "DEPENDENCY_CONDITION_UNSUPPORTED");
}
