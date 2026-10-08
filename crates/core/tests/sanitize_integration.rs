//! 表示を乱す文字（Cc・Cf・Zl・Zp）のサニタイズの結合試験（SEC-4・ERR-2・TASK-96.1・REPAIR-12）。
//!
//! crate の外から、違反記録の対象パス（`exec::ViolationSubject`）とヘルパー stderr を載せる
//! `rootless` のエラーメッセージを具体値で照合する。root・実ヘルパーは不要で既定のテスト集合で動く
//! （`exec-test-support` は自己参照の dev-dependency で有効）。
//! 実際の拒否・実ヘルパー起動は特権を要するため、失敗時に通る生成関数だけを試験用入口から呼ぶ。

#![cfg(target_os = "linux")]

use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;

use fandhe_container_core::exec::{
    VIOLATION_SUBJECT_MAX_CHARS, ViolationReason, path_violation_error_for_test,
};
use fandhe_container_core::rootless::helper_failure_error_for_test;

/// SEC-4: 違反記録の対象は Cf（双方向制御・WORD JOINER）・Zl・Zp を `escape_default` 形式で保持する。
#[test]
fn sec4_violation_subject_escapes_cf_zl_zp() {
    let err = path_violation_error_for_test(
        ViolationReason::PathMissing,
        Path::new("/a\u{202E}b\u{2060}c\u{2028}d\u{2029}e\nf"),
    );
    let v = err.violation.as_ref().expect("violation record");
    let subject = v.subject.as_ref().expect("subject");
    assert_eq!(
        subject.as_str(),
        "/a\\u{202e}b\\u{2060}c\\u{2028}d\\u{2029}e\\nf"
    );
    assert!(!subject.is_truncated());
    assert_eq!(err.message, "mount target path must exist");
}

/// SEC-4: Cf のエスケープ列でも対象は上限（256 文字）を超えず、切り詰めを記録する。
#[test]
fn sec4_violation_subject_stays_bounded_with_cf_escapes() {
    let many = "\u{202E}".repeat(VIOLATION_SUBJECT_MAX_CHARS);
    let err = path_violation_error_for_test(ViolationReason::PathMissing, Path::new(&many));
    let subject = err
        .violation
        .as_ref()
        .and_then(|v| v.subject.as_ref())
        .expect("subject");
    assert_eq!(subject.as_str().chars().count(), 256);
    assert!(subject.is_truncated());
}

/// ERR-2: ヘルパー stderr の Cc・Cf・Zl・Zp はエラーメッセージから除去される。
#[test]
fn err2_helper_failure_message_drops_cf_zl_zp() {
    let status = std::process::ExitStatus::from_raw(1 << 8);
    let err = helper_failure_error_for_test(
        status,
        "a\u{202E}b\u{2060}c\u{2028}d\u{2029}e\x1b[31m\nz".as_bytes(),
    );
    assert_eq!(
        err.message,
        "id map helper failed (exit status: 1): abcde[31mz"
    );
}

/// ERR-2: ヘルパー stderr は 4096 バイトで頭打ちになり、不正バイトが U+FFFD へ膨らんでも超えない。
#[test]
fn err2_helper_failure_message_bounds_stderr() {
    let status = std::process::ExitStatus::from_raw(1 << 8);
    let prefix = "id map helper failed (exit status: 1): ";
    let ascii = vec![b'a'; 10_000];
    let err = helper_failure_error_for_test(status, &ascii);
    assert_eq!(err.message.len(), prefix.len() + 4096);
    let invalid = vec![0xFFu8; 10_000];
    let err = helper_failure_error_for_test(status, &invalid);
    assert_eq!(err.message.len(), prefix.len() + 4095);
}
