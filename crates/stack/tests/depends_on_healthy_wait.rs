//! `healthy` 待機ゲートの公開パス経由の結合試験（STACK-2・TASK-150.3・#591・REPAIR-12）。
//!
//! 合成フィクスチャ（web が worker を `healthy`、api を `started` で待つ）から `plan_startup` の
//! 計画を作り、偽の時計と台本の source でゲートを具体値で照合する。

use std::time::Duration;

use fandhe_container_stack::depends_on::{
    HealthSource, HealthSourceError, HealthyGate, HealthyWaitOutcome, HealthyWaitPolicy,
    ObservedHealth, PollClock, StartupStep, gate_healthy_dependencies, plan_startup,
};
use fandhe_container_stack::schema::ComposeToml;

const ACYCLIC: &str = include_str!("../testdata/depends_on_acyclic.toml");

struct FakeClock(Duration);
impl PollClock for FakeClock {
    fn now(&self) -> Duration {
        self.0
    }
    fn sleep(&mut self, d: Duration) {
        self.0 += d;
    }
}

/// 台本どおりに返し（尽きたら最後の値）、呼ばれた名前を記録する。
struct WorkerScript {
    values: Vec<ObservedHealth>,
    calls: Vec<String>,
}
impl HealthSource for WorkerScript {
    fn observe(&mut self, s: &str) -> Result<Option<ObservedHealth>, HealthSourceError> {
        self.calls.push(s.to_string());
        let i = self.calls.len() - 1;
        Ok(self.values.get(i).or(self.values.last()).copied())
    }
}

fn web_step() -> StartupStep {
    let parsed: ComposeToml = toml::from_str(ACYCLIC).unwrap();
    let plan = plan_startup(&parsed.services).unwrap();
    plan.steps().last().unwrap().clone()
}

fn policy() -> HealthyWaitPolicy {
    HealthyWaitPolicy::new(Duration::from_millis(100), Duration::from_secs(1)).unwrap()
}

/// STACK-2: worker が healthy になった時点で web の起動を許可し、started の api は観測しない。
#[test]
fn stack_2_healthy_observed_permits_start() {
    let mut src = WorkerScript {
        values: vec![ObservedHealth::Starting, ObservedHealth::Healthy],
        calls: vec![],
    };
    let mut clock = FakeClock(Duration::ZERO);
    let gate = gate_healthy_dependencies(&web_step(), &mut src, &mut clock, &policy()).unwrap();
    assert_eq!(
        gate,
        HealthyGate::Permitted {
            waited: vec![HealthyWaitOutcome::Healthy {
                service: "worker".into(),
                polls: 2,
                elapsed: Duration::from_millis(100)
            }]
        }
    );
    assert_eq!(src.calls, vec!["worker", "worker"]);
}

/// STACK-2: worker が unhealthy のままなら web は起動を許可されない。
#[test]
fn stack_2_unhealthy_blocks_start() {
    let mut src = WorkerScript {
        values: vec![ObservedHealth::Unhealthy],
        calls: vec![],
    };
    let mut clock = FakeClock(Duration::ZERO);
    let gate = gate_healthy_dependencies(&web_step(), &mut src, &mut clock, &policy()).unwrap();
    match gate {
        HealthyGate::Blocked(o) => {
            assert_eq!(o.service(), "worker");
            assert!(matches!(
                o,
                HealthyWaitOutcome::DeadlineReached {
                    last_observed: Some(ObservedHealth::Unhealthy),
                    ..
                }
            ));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

/// 観測のたびに時計を進める source（観測処理が長引いた場合の模擬）。
struct SlowHealthy<'a> {
    clock: &'a std::cell::Cell<Duration>,
    cost: Duration,
    calls: usize,
}
impl HealthSource for SlowHealthy<'_> {
    fn observe(&mut self, _s: &str) -> Result<Option<ObservedHealth>, HealthSourceError> {
        self.calls += 1;
        self.clock.set(self.clock.get() + self.cost);
        Ok(Some(ObservedHealth::Healthy))
    }
}
struct CellClock<'a>(&'a std::cell::Cell<Duration>, Duration);
impl PollClock for CellClock<'_> {
    fn now(&self) -> Duration {
        self.0.get()
    }
    fn sleep(&mut self, d: Duration) {
        // スケジューリング遅延で要求より長く眠る
        self.0.set(self.0.get() + d + self.1);
    }
}

/// STACK-2・REPAIR-5: 観測中に期限(1s)を超えて healthy を返しても許可しない。
#[test]
fn stack_2_healthy_observed_after_deadline_is_blocked() {
    let t = std::cell::Cell::new(Duration::ZERO);
    let mut src = SlowHealthy {
        clock: &t,
        cost: Duration::from_millis(1500),
        calls: 0,
    };
    let mut clock = CellClock(&t, Duration::ZERO);
    let gate = gate_healthy_dependencies(&web_step(), &mut src, &mut clock, &policy()).unwrap();
    assert_eq!(
        gate,
        HealthyGate::Blocked(HealthyWaitOutcome::DeadlineReached {
            service: "worker".into(),
            last_observed: Some(ObservedHealth::Healthy),
            polls: 1
        })
    );
    assert_eq!(src.calls, 1);
}

/// 1 回目は starting、2 回目以降は healthy を返す source。
struct Late(usize);
impl HealthSource for Late {
    fn observe(&mut self, _s: &str) -> Result<Option<ObservedHealth>, HealthSourceError> {
        self.0 += 1;
        Ok(Some(if self.0 == 1 {
            ObservedHealth::Starting
        } else {
            ObservedHealth::Healthy
        }))
    }
}

/// STACK-2・REPAIR-5: sleep が期限を超えた後は healthy を観測せず許可しない。
#[test]
fn stack_2_sleep_overshoot_blocks_without_further_observation() {
    let t = std::cell::Cell::new(Duration::ZERO);
    let mut src = Late(0);
    let mut clock = CellClock(&t, Duration::from_secs(5));
    let gate = gate_healthy_dependencies(&web_step(), &mut src, &mut clock, &policy()).unwrap();
    assert_eq!(
        gate,
        HealthyGate::Blocked(HealthyWaitOutcome::DeadlineReached {
            service: "worker".into(),
            last_observed: Some(ObservedHealth::Starting),
            polls: 1
        })
    );
    assert_eq!(src.0, 1);
}
