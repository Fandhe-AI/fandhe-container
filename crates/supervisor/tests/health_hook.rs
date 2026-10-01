//! healthcheck フック土台の受け入れ照合テスト（TASK-157.6・#240・SUP-4・REPAIR-3・REPAIR-12）。
//!
//! 文字列照合であり構文解析ではない（tests/monitor_loop.rs と同じ手法）。

use std::time::Duration;

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_supervisor::health::{
    HealthProbe, UnimplementedHealthProbe, probe_and_record, record_health,
};

/// AC1: 公開 API が外部 crate から参照でき、スタブは Unimplemented を返す。
#[test]
fn sup4_task157_6_public_api_and_stub() {
    let _record = record_health;
    let _both = probe_and_record;
    let err = UnimplementedHealthProbe
        .probe(Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unimplemented);
}

/// AC2: 未実装範囲と将来仕様の対応 ID が doc に書かれている。
#[test]
fn sup4_task157_6_doc_states_unimplemented_scope() {
    const SRC: &str = include_str!("../src/health.rs");
    let body = SRC.split("#[cfg(test)]").next().unwrap_or(SRC);
    for needle in ["SUP-4", "SUP-6", "TASK-161", "未実装"] {
        assert!(body.contains(needle), "health.rs must mention {needle}");
    }
}

/// コマンド実行・グローバル状態・unsafe・記録 pid への直接操作を持たない。
#[test]
fn sup4_task157_6_health_rs_has_no_exec_or_global_state() {
    const SRC: &str = include_str!("../src/health.rs");
    let body = SRC.split("#[cfg(test)]").next().unwrap_or(SRC);
    let code: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        "\nstatic ",
        "\npub static ",
        "thread_local",
        "OnceLock",
        "LazyLock",
        "unsafe",
        "kill(",
        "waitpid",
        "/proc",
        "cfg(target_os",
        "Command",
    ] {
        assert!(
            !code.contains(banned),
            "health.rs must not contain {banned}"
        );
    }
}
