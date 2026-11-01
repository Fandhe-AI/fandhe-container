//! `depends_on` のトポロジカルソートと循環検出（STACK-2・TASK-150.1・#589）。
//!
//! サービス定義の map から起動順の計画（[`StartupPlan`]）を作る純関数だけを持つ。
//! 呼び出し元は `cli::up`（TASK-155.1・#618）で、profiles で絞った map（STACK-10・TASK-187）も渡せるよう
//! `ComposeToml` ではなく `BTreeMap<String, Service>` を受ける。循環と未定義の依存先は
//! 計画を返さずエラーにする（起動前に止める。fail-closed）。
//!
//! 本モジュールは各依存先の条件を [`DependencyWait`] として計画に残すだけで、待たない。
//! `started` の待機は `wait` サブモジュール（#590）、`healthy` のポーリング待機は
//! `healthy_wait`（#591）にあり、state.json の読み取りは `cli::up`（TASK-155）が `HealthSource` で注入する。
//! healthy 未達のタイムアウトは `require_healthy_dependencies`（#592）が `wait` の
//! `WaitTimeout`（非ゼロ終了コードつき）へ写す。
//! `wait_for_step` への healthy の統合は `cli::up` が条件ごとに絞って呼ぶ形で済み（#618）。
//! 未実装（実装済みを装わない。REPAIR-3）: `completed` の待機（`up` が起動前に未対応として止める）。
//!
//! 決定性: `BTreeMap` のキー順で DFS を始め、依存先もキー順にたどる。結果は「依存先が先、
//! 互いに独立なものは名前順の DFS 後行順」で、同じ入力なら常に同じ出力になる。
//! DFS は明示スタックの反復で、サービス数・依存の深さ（外部入力）で stack overflow しない
//! （O(V+E)）。入力サイズの上限検証は parse の入口が担う。エラーにはサービス名だけを入れ、
//! `Service`（`env` に資格情報を含みうる）の内容は出さない。

use std::collections::BTreeMap;
use std::collections::btree_map;
use std::fmt;

use crate::schema::{DependsOnCondition, Service};

pub mod wait;

mod healthy_wait;
pub use healthy_wait::{
    HealthSource, HealthSourceError, HealthyGate, HealthyWaitError, HealthyWaitOutcome,
    HealthyWaitPolicy, HealthyWaitPolicyError, MonotonicClock, ObservedHealth, PollClock,
    gate_healthy_dependencies, require_healthy_dependencies, wait_until_healthy,
};

/// 依存先ひとつ分の待ち条件（`DependsOnCondition` を依存先名と組にしたもの）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyWait {
    service: String,
    condition: DependsOnCondition,
}

impl DependencyWait {
    /// 待つ対象（依存先）のサービス名。
    pub fn service(&self) -> &str {
        &self.service
    }

    /// 依存先に対する待ち条件。
    pub fn condition(&self) -> DependsOnCondition {
        self.condition
    }
}

/// 起動順の 1 ステップ（サービス名と、起動前に満たすべき待ち条件）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupStep {
    service: String,
    waits: Vec<DependencyWait>,
}

impl StartupStep {
    /// 起動するサービス名。
    pub fn service(&self) -> &str {
        &self.service
    }

    /// 起動前の待ち条件（依存先名の昇順）。
    pub fn waits(&self) -> &[DependencyWait] {
        &self.waits
    }

    /// `condition` の待ちだけを残した複製（依存先名の昇順は保つ）。
    ///
    /// `up`（`cli::up`・TASK-155.1）が healthy と started の混在ステップを、条件ごとの待機関数へ
    /// 渡すために使う（`wait_for_step` は started 以外を未対応として拒否するため）。
    pub fn retain_condition(&self, condition: DependsOnCondition) -> StartupStep {
        StartupStep {
            service: self.service.clone(),
            waits: self
                .waits
                .iter()
                .filter(|w| w.condition == condition)
                .cloned()
                .collect(),
        }
    }
}

/// 起動順の計画（依存先が先）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupPlan {
    steps: Vec<StartupStep>,
}

impl StartupPlan {
    /// 起動順のステップ列。
    pub fn steps(&self) -> &[StartupStep] {
        &self.steps
    }

    /// 起動順のサービス名。
    pub fn service_names(&self) -> impl Iterator<Item = &str> {
        self.steps.iter().map(StartupStep::service)
    }
}

/// `depends_on` の計画作成エラー（STACK-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DependsOnError {
    /// 循環依存。`path` は閉路の順で、先頭と末尾が同名（例 `["a","b","a"]`。自己依存は `["a","a"]`）。
    Cycle { path: Vec<String> },
    /// 定義されていないサービスを `depends_on` が参照した。
    UnknownDependency { service: String, dependency: String },
}

impl DependsOnError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Cycle { .. } => "DEPENDENCY_CYCLE",
            Self::UnknownDependency { .. } => "UNKNOWN_DEPENDENCY",
        }
    }

    /// 固定の英語メッセージ（サービス名は含めない。名前は `Display` と各フィールドで得る）。
    pub fn message(&self) -> &'static str {
        match self {
            Self::Cycle { .. } => "depends_on contains a cycle",
            Self::UnknownDependency { .. } => "depends_on references an undefined service",
        }
    }
}

impl fmt::Display for DependsOnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cycle { path } => write!(f, "{}: {}", self.message(), path.join(" -> ")),
            Self::UnknownDependency {
                service,
                dependency,
            } => write!(f, "{}: {} -> {}", self.message(), service, dependency),
        }
    }
}

impl std::error::Error for DependsOnError {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    InProgress,
    Done,
}

/// DFS スタックの 1 要素（サービス名と、残りの依存先のイテレータ）。
struct Frame<'a> {
    name: &'a str,
    deps: btree_map::Keys<'a, String, DependsOnCondition>,
}

/// `depends_on` から起動順の計画を作る（STACK-2・TASK-150.1）。
///
/// 循環・未定義の依存先があれば計画を返さずエラーにする。
pub fn plan_startup(services: &BTreeMap<String, Service>) -> Result<StartupPlan, DependsOnError> {
    let mut states: BTreeMap<&str, State> = BTreeMap::new();
    let mut order: Vec<&str> = Vec::with_capacity(services.len());

    for (root, root_svc) in services {
        if states.contains_key(root.as_str()) {
            continue;
        }
        states.insert(root, State::InProgress);
        let mut stack = vec![Frame {
            name: root,
            deps: root_svc.depends_on.keys(),
        }];
        while let Some(top) = stack.last_mut() {
            let current = top.name;
            match top.deps.next() {
                Some(dep) => {
                    let Some(dep_svc) = services.get(dep) else {
                        return Err(DependsOnError::UnknownDependency {
                            service: current.to_owned(),
                            dependency: dep.clone(),
                        });
                    };
                    match states.get(dep.as_str()) {
                        Some(State::Done) => {}
                        Some(State::InProgress) => {
                            let start = stack.iter().position(|f| f.name == dep).unwrap_or(0);
                            let mut path: Vec<String> = stack
                                .iter()
                                .skip(start)
                                .map(|f| f.name.to_owned())
                                .collect();
                            path.push(dep.clone());
                            return Err(DependsOnError::Cycle { path });
                        }
                        None => {
                            states.insert(dep, State::InProgress);
                            stack.push(Frame {
                                name: dep,
                                deps: dep_svc.depends_on.keys(),
                            });
                        }
                    }
                }
                None => {
                    states.insert(current, State::Done);
                    order.push(current);
                    stack.pop();
                }
            }
        }
    }

    let steps = order
        .into_iter()
        .map(|name| StartupStep {
            service: name.to_owned(),
            waits: services
                .get(name)
                .map(|s| {
                    s.depends_on
                        .iter()
                        .map(|(dep, cond)| DependencyWait {
                            service: dep.clone(),
                            condition: *cond,
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect();
    Ok(StartupPlan { steps })
}

#[cfg(test)]
mod tests {
    use super::*;

    use DependsOnCondition::{Completed, Healthy, Started};

    fn svcs(spec: &[(&str, &[(&str, DependsOnCondition)])]) -> BTreeMap<String, Service> {
        spec.iter()
            .map(|(n, deps)| {
                let s = Service {
                    depends_on: deps.iter().map(|(d, c)| ((*d).to_owned(), *c)).collect(),
                    ..Service::default()
                };
                ((*n).to_owned(), s)
            })
            .collect()
    }

    fn names(plan: &StartupPlan) -> Vec<&str> {
        plan.service_names().collect()
    }

    /// STACK-8・TASK-155.1: retain_condition は指定条件だけを昇順のまま残す。
    #[test]
    fn stack_8_retain_condition_keeps_only_that_condition() {
        let m = svcs(&[
            ("a", &[]),
            ("b", &[]),
            ("c", &[]),
            ("app", &[("c", Started), ("a", Healthy), ("b", Started)]),
        ]);
        let plan = plan_startup(&m).unwrap();
        let step = plan.steps().last().unwrap();
        let started = step.retain_condition(Started);
        let deps: Vec<&str> = started.waits().iter().map(|w| w.service()).collect();
        assert_eq!(deps, vec!["b", "c"]);
        assert_eq!(started.service(), "app");
        let healthy = step.retain_condition(Healthy);
        assert_eq!(healthy.waits().len(), 1);
        assert!(step.retain_condition(Completed).waits().is_empty());
    }

    /// STACK-2・TASK-150.1: 空の map は空の計画。
    #[test]
    fn stack_2_empty_map_yields_empty_plan() {
        let plan = plan_startup(&BTreeMap::new()).unwrap();
        assert!(plan.steps().is_empty());
    }

    /// STACK-2・TASK-150.1: 依存なしの 1 サービス。
    #[test]
    fn stack_2_single_service_without_deps() {
        let plan = plan_startup(&svcs(&[("a", &[])])).unwrap();
        assert_eq!(names(&plan), vec!["a"]);
        assert!(plan.steps()[0].waits().is_empty());
    }

    /// STACK-2・TASK-150.1: 直線 c→b→a は依存先が先。
    #[test]
    fn stack_2_chain_orders_dependencies_first() {
        let plan = plan_startup(&svcs(&[
            ("c", &[("b", Started)]),
            ("b", &[("a", Started)]),
            ("a", &[]),
        ]))
        .unwrap();
        assert_eq!(names(&plan), vec!["a", "b", "c"]);
    }

    /// STACK-2・TASK-150.1: ダイヤモンド形。
    #[test]
    fn stack_2_diamond() {
        let plan = plan_startup(&svcs(&[
            ("d", &[("b", Started), ("c", Started)]),
            ("b", &[("a", Started)]),
            ("c", &[("a", Started)]),
            ("a", &[]),
        ]))
        .unwrap();
        assert_eq!(names(&plan), vec!["a", "b", "c", "d"]);
    }

    /// STACK-2・TASK-150.1: 独立したサービスは名前順（決定性）。
    #[test]
    fn stack_2_independent_services_sorted_by_name() {
        let plan = plan_startup(&svcs(&[("z", &[]), ("m", &[]), ("a", &[])])).unwrap();
        assert_eq!(names(&plan), vec!["a", "m", "z"]);
    }

    /// STACK-2・TASK-150.1: 自己依存は循環。
    #[test]
    fn stack_2_self_dependency_is_cycle() {
        let err = plan_startup(&svcs(&[("a", &[("a", Started)])])).unwrap_err();
        assert_eq!(
            err,
            DependsOnError::Cycle {
                path: vec!["a".into(), "a".into()]
            }
        );
    }

    /// STACK-2・TASK-150.1: 2 サービスの循環。
    #[test]
    fn stack_2_two_node_cycle() {
        let err =
            plan_startup(&svcs(&[("a", &[("b", Started)]), ("b", &[("a", Started)])])).unwrap_err();
        assert_eq!(
            err,
            DependsOnError::Cycle {
                path: vec!["a".into(), "b".into(), "a".into()]
            }
        );
    }

    /// STACK-2・TASK-150.1: 循環に入らない入口（w）を経由しても閉路だけを返す。
    #[test]
    fn stack_2_cycle_path_excludes_entry_prefix() {
        let err = plan_startup(&svcs(&[
            ("w", &[("x", Started)]),
            ("x", &[("y", Started)]),
            ("y", &[("z", Started)]),
            ("z", &[("x", Started)]),
            ("ok", &[]),
        ]))
        .unwrap_err();
        assert_eq!(
            err,
            DependsOnError::Cycle {
                path: vec!["x".into(), "y".into(), "z".into(), "x".into()]
            }
        );
        assert_eq!(err.code(), "DEPENDENCY_CYCLE");
    }

    /// STACK-2・TASK-150.1: 未定義の依存先。
    #[test]
    fn stack_2_unknown_dependency() {
        let err = plan_startup(&svcs(&[("a", &[("ghost", Started)])])).unwrap_err();
        assert_eq!(
            err,
            DependsOnError::UnknownDependency {
                service: "a".into(),
                dependency: "ghost".into()
            }
        );
        assert_eq!(err.code(), "UNKNOWN_DEPENDENCY");
    }

    /// STACK-2・TASK-150.1: 3 つの条件が waits にそのまま残る。
    #[test]
    fn stack_2_conditions_preserved_in_waits() {
        let plan = plan_startup(&svcs(&[
            (
                "app",
                &[("db", Healthy), ("init", Completed), ("log", Started)],
            ),
            ("db", &[]),
            ("init", &[]),
            ("log", &[]),
        ]))
        .unwrap();
        let app = plan.steps().last().unwrap();
        assert_eq!(app.service(), "app");
        let got: Vec<(&str, DependsOnCondition)> = app
            .waits()
            .iter()
            .map(|w| (w.service(), w.condition()))
            .collect();
        assert_eq!(
            got,
            vec![("db", Healthy), ("init", Completed), ("log", Started)]
        );
    }

    /// STACK-2・TASK-150.1: 長い直線鎖でも stack overflow しない（反復 DFS）。
    #[test]
    fn stack_2_long_chain_does_not_overflow() {
        const N: usize = 100_000;
        let mut m = BTreeMap::new();
        for i in 0..N {
            let mut s = Service::default();
            if i + 1 < N {
                s.depends_on
                    .insert(format!("s{:06}", i + 1), DependsOnCondition::Started);
            }
            m.insert(format!("s{i:06}"), s);
        }
        let plan = plan_startup(&m).unwrap();
        assert_eq!(plan.steps().len(), N);
        assert_eq!(plan.steps()[0].service(), "s099999");
        assert_eq!(plan.steps()[N - 1].service(), "s000000");
    }

    /// STACK-2・TASK-150.1: エラーの code / message / Display は英語でサービス名のみ。
    #[test]
    fn stack_2_error_text() {
        let c = DependsOnError::Cycle {
            path: vec!["a".into(), "b".into(), "a".into()],
        };
        assert_eq!(c.message(), "depends_on contains a cycle");
        assert_eq!(c.to_string(), "depends_on contains a cycle: a -> b -> a");
        let u = DependsOnError::UnknownDependency {
            service: "a".into(),
            dependency: "g".into(),
        };
        assert_eq!(u.message(), "depends_on references an undefined service");
        assert_eq!(
            u.to_string(),
            "depends_on references an undefined service: a -> g"
        );
    }
}
