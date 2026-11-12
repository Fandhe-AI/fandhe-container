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

/// STACK-2・ERR-1: 制御文字を含むサービス名の循環でも、公開 API の Display は固定文言で名前を漏らさず、
/// 元の名前は構造化フィールドにそのまま残る。
#[test]
fn stack_2_cycle_display_is_fixed_and_path_keeps_raw_names() {
    let toml_src = r#"
[services."a\u001b[31m"]
image = "example/a:1"
[services."a\u001b[31m".depends_on]
"b\n" = "started"

[services."b\n"]
image = "example/b:1"
[services."b\n".depends_on]
"a\u001b[31m" = "started"
"#;
    let parsed: ComposeToml = toml::from_str(toml_src).unwrap();
    let err = plan_startup(&parsed.services).unwrap_err();
    assert_eq!(err.code(), "DEPENDENCY_CYCLE");
    assert_eq!(err.to_string(), "depends_on contains a cycle");
    assert!(!err.to_string().contains('\u{1b}'));
    assert_eq!(
        err,
        DependsOnError::Cycle {
            path: vec!["a\u{1b}[31m".into(), "b\n".into(), "a\u{1b}[31m".into()]
        }
    );
}

/// STACK-2・ERR-1: 制御文字を含む未定義依存でも Display は固定文言で、名前はフィールドに残る。
#[test]
fn stack_2_unknown_dependency_display_is_fixed_and_fields_keep_raw_names() {
    let toml_src = r#"
[services."web\u001b[2J"]
image = "example/web:1"
[services."web\u001b[2J".depends_on]
"ghost\r\nX" = "started"
"#;
    let parsed: ComposeToml = toml::from_str(toml_src).unwrap();
    let err = plan_startup(&parsed.services).unwrap_err();
    assert_eq!(err.code(), "UNKNOWN_DEPENDENCY");
    assert_eq!(
        err.to_string(),
        "depends_on references an undefined service"
    );
    assert_eq!(
        err,
        DependsOnError::UnknownDependency {
            service: "web\u{1b}[2J".into(),
            dependency: "ghost\r\nX".into()
        }
    );
}
