//! `ps` のサービス状態一覧の結合試験（STACK-8・TASK-155.4・#621・REPAIR-12）。
//!
//! 公開 API（`cli::ps` と注入ポート）だけで、名前順の一覧・循環でも出ること・秘密値の非露出を
//! 具体値で照合する。実プロセスを起動しないため既定のテスト集合で走る。
//! 範囲外: 本番の状態読み取りアダプタと CLI 結線（#3639）。

use std::collections::HashMap;

use fandhe_container_stack::cli::{PsError, ServiceStatus, ServiceStatusSource, ps};
use fandhe_container_stack::depends_on::ObservedHealth;
use fandhe_container_stack::depends_on::wait::{DependencyObservation, ObserveError};
use fandhe_container_stack::schema::ComposeToml;

const POC17: &str = include_str!("../testdata/depends_on_poc17.toml");
const CYCLE: &str = include_str!("../testdata/depends_on_cycle.toml");

struct Fake(HashMap<String, Result<ServiceStatus, ObserveError>>);

impl ServiceStatusSource for Fake {
    fn status(&mut self, service: &str) -> Result<ServiceStatus, ObserveError> {
        self.0
            .get(service)
            .cloned()
            .unwrap_or_else(|| Ok(ServiceStatus::new(DependencyObservation::Absent, None)))
    }
}

fn parse(src: &str) -> ComposeToml {
    toml::from_str(src).unwrap()
}

#[test]
fn stack_8_ps_lists_poc17_services_in_name_order() {
    let c = parse(POC17);
    let mut f = Fake(HashMap::from([
        (
            "db".to_string(),
            Ok(ServiceStatus::new(
                DependencyObservation::Running,
                Some(ObservedHealth::Healthy),
            )),
        ),
        (
            "app".to_string(),
            Ok(ServiceStatus::new(
                DependencyObservation::Running,
                Some(ObservedHealth::Starting),
            )),
        ),
    ]));
    let r = ps(&c.services, &mut f).unwrap();
    assert_eq!(r.service_names(), ["app", "db", "gateway"]);
    assert_eq!(
        r.render_table(),
        "SERVICE  STATE    HEALTH\n\
         app      running  starting\n\
         db       running  healthy\n\
         gateway  absent   -\n"
    );
}

#[test]
fn stack_8_ps_lists_even_with_depends_on_cycle() {
    let c = parse(CYCLE);
    let mut f = Fake(HashMap::new());
    let r = ps(&c.services, &mut f).unwrap();
    let expected: Vec<&str> = c.services.keys().map(String::as_str).collect();
    assert!(!expected.is_empty());
    assert_eq!(r.service_names(), expected);
}

#[test]
fn stack_8_ps_does_not_expose_service_env() {
    let c = parse(
        r#"
[services.web]
image = "example/web:1"

[services.web.env]
TOKEN = "s3cr3t-dummy-value"
"#,
    );
    let mut f = Fake(HashMap::new());
    let r = ps(&c.services, &mut f).unwrap();
    assert!(!r.render_table().contains("s3cr3t-dummy-value"));
    assert!(!format!("{r:?}").contains("s3cr3t-dummy-value"));

    let mut bad = Fake(HashMap::from([(
        "web".to_string(),
        Err(ObserveError::new("STATE_READ_FAILED", "read failed")),
    )]));
    let e: PsError = ps(&c.services, &mut bad).unwrap_err();
    assert!(!e.to_string().contains("s3cr3t-dummy-value"));
    assert!(!format!("{e:?}").contains("s3cr3t-dummy-value"));
}
