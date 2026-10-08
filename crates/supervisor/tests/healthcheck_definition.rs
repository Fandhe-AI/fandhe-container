//! healthcheck 定義パースの受け入れ基準照合（TASK-161.1・#493・SUP-4・REPAIR-12）。
//! 公開 API のみを外部 crate 視点で使い、負の interval 等の拒否と正常系の具体値を確認する。

use std::time::Duration;

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_supervisor::healthcheck::{HealthcheckDefinition, RawHealthcheck};

fn base() -> RawHealthcheck {
    RawHealthcheck {
        command: vec!["pg_isready".to_string(), "-q".to_string()],
        ..Default::default()
    }
}

/// SUP-4: 負の interval は InvalidArgument で拒否される。
#[test]
fn sup4_negative_interval_is_rejected() {
    let raw = RawHealthcheck {
        interval: Some("-5s".to_string()),
        ..base()
    };
    let err = HealthcheckDefinition::parse(&raw).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(err.message().starts_with("interval:"), "{}", err.message());
}

/// SUP-4: 0 以下の retries と空 command も拒否される。
#[test]
fn sup4_invalid_retries_and_empty_command_are_rejected() {
    let raw = RawHealthcheck {
        retries: Some(0),
        ..base()
    };
    assert_eq!(
        HealthcheckDefinition::parse(&raw).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    let raw = RawHealthcheck::default();
    assert_eq!(
        HealthcheckDefinition::parse(&raw).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

/// SUP-4: 正常系で全 getter が具体値を返す。
#[test]
fn sup4_valid_definition_exposes_values() {
    let raw = RawHealthcheck {
        interval: Some("10s".to_string()),
        timeout: Some("500ms".to_string()),
        start_period: Some("1m".to_string()),
        retries: Some(5),
        ..base()
    };
    let d = HealthcheckDefinition::parse(&raw).unwrap();
    assert_eq!(d.command(), ["pg_isready".to_string(), "-q".to_string()]);
    assert_eq!(d.interval(), Duration::from_secs(10));
    assert_eq!(d.timeout(), Duration::from_millis(500));
    assert_eq!(d.start_period(), Duration::from_secs(60));
    assert_eq!(d.retries().get(), 5);
}
