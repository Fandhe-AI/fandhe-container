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
