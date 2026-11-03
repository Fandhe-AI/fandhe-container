//! `fandhe_container_stack::depends_on` の公開パス経由の結合試験（STACK-2・TASK-150.1・#589・REPAIR-12）。
//!
//! 合成フィクスチャ（TOML）を `toml` で読み、起動前の循環検出と起動順を具体値で照合する。

use fandhe_container_stack::depends_on::{DependsOnError, plan_startup};
use fandhe_container_stack::schema::{ComposeToml, DependsOnCondition};

const CYCLE: &str = include_str!("../testdata/depends_on_cycle.toml");
const ACYCLIC: &str = include_str!("../testdata/depends_on_acyclic.toml");

/// STACK-2: 循環を含む定義は起動前にエラーになる。
#[test]
fn stack_2_cycle_fixture_fails_before_start() {
    let parsed: ComposeToml = toml::from_str(CYCLE).unwrap();
    let err = plan_startup(&parsed.services).unwrap_err();
    assert_eq!(err.code(), "DEPENDENCY_CYCLE");
    assert_eq!(
        err,
        DependsOnError::Cycle {
            // 名前順の最初の入口 api から閉路を回る
            path: vec!["api".into(), "db".into(), "web".into(), "api".into()]
        }
    );
}

/// STACK-2: 循環なしの定義は依存先が先の順序と条件を保つ。
#[test]
fn stack_2_acyclic_fixture_orders_and_keeps_conditions() {
    let parsed: ComposeToml = toml::from_str(ACYCLIC).unwrap();
    let plan = plan_startup(&parsed.services).unwrap();
    assert_eq!(
        plan.service_names().collect::<Vec<_>>(),
        vec!["migrate", "api", "worker", "web"]
    );
    let web = plan.steps().last().unwrap();
    let waits: Vec<_> = web
        .waits()
        .iter()
        .map(|w| (w.service(), w.condition()))
        .collect();
    assert_eq!(
        waits,
        vec![
            ("api", DependsOnCondition::Started),
            ("worker", DependsOnCondition::Healthy)
        ]
    );
}
