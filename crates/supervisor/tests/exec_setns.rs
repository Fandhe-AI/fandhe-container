//! exec（pid1 特定・setns）の受け入れ照合テスト（TASK-163.1・#500・SUP-6・REPAIR-3・REPAIR-12）。
//!
//! 文字列照合であり構文解析ではない（tests/health_hook.rs と同じ手法）。

#![cfg(target_os = "linux")]

use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, ErrorCode, StateRecord, StateRevision,
};

/// AC1: 失敗は panic ではなく `Result` の構造化エラーで返る（記録 pid が無い Running は拒否）。
#[test]
fn sup6_task163_1_failure_is_structured_result() {
    let status = ContainerStatus::running(ContainerId::new("c1").unwrap(), None);
    let rec = StateRecord::new(
        status,
        std::env::temp_dir().join("b"),
        StateRevision::from_raw(1),
    )
    .unwrap();
    let err = fandhe_container_supervisor::exec::identify_pid1(&rec).unwrap_err();
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);
}

/// AC2: 未実装範囲と対応 ID が doc に書かれている。
#[test]
fn sup6_task163_1_doc_states_unimplemented_scope() {
    const SRC: &str = include_str!("../src/exec.rs");
    let body = SRC.split("#[cfg(test)]").next().unwrap_or(SRC);
    for needle in ["SUP-6", "TASK-163", "未実装"] {
        assert!(body.contains(needle), "exec.rs must mention {needle}");
    }
}

/// supervisor 側に unsafe・OS 分岐・記録 pid への直接操作を持たない。
#[test]
fn sup6_task163_1_exec_rs_has_no_unsafe_or_raw_pid_ops() {
    const SRC: &str = include_str!("../src/exec.rs");
    let body = SRC.split("#[cfg(test)]").next().unwrap_or(SRC);
    let code: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in ["unsafe", "cfg(target_os", "kill(", "waitpid"] {
        assert!(!code.contains(banned), "exec.rs must not contain {banned}");
    }
}
