//! `TraitError` のメッセージ長上限の結合試験（ERR-2・REPAIR-4・REPAIR-12・TASK-96.1・MS-6）。
//!
//! 公開 API（`TraitError::new`・`message`・`message_truncated`・`TRAIT_ERROR_MESSAGE_MAX_BYTES`）だけを
//! crate の外から呼び、上限ちょうど・上限超過・UTF-8 境界・通知値を具体値で機械照合する。
//! plugin 応答由来の untrusted なメッセージが `TraitError` に入る経路の契約確認で、root・実プロセスは不要
//! （3 OS で動く）。確保量の上限は非公開フィールドのため `src/traits/types.rs` のユニットテストが担う。

use fandhe_container_core::traits::{ErrorCode, TRAIT_ERROR_MESSAGE_MAX_BYTES, TraitError};

/// ERR-2: 上限定数は 4096 バイト。
#[test]
fn err2_cap_constant_is_4096() {
    assert_eq!(TRAIT_ERROR_MESSAGE_MAX_BYTES, 4096);
}

/// ERR-2: 上限ちょうどは切り詰めず、通知値は false。
#[test]
fn err2_message_at_exact_cap_is_kept() {
    let err = TraitError::new(ErrorCode::Internal, "a".repeat(4096));
    assert_eq!(err.message().len(), 4096);
    assert!(!err.message_truncated());
    assert_eq!(err.code(), ErrorCode::Internal);
}

/// ERR-2: 1 バイト超過は 4096 バイトへ切り詰め、通知値は true。
#[test]
fn err2_message_over_cap_is_truncated_and_reported() {
    let err = TraitError::new(ErrorCode::Timeout, "a".repeat(4097));
    assert_eq!(err.message(), "a".repeat(4096));
    assert!(err.message_truncated());
    assert_eq!(err.to_string().len(), "TIMEOUT: ".len() + 4096);
}

/// ERR-2: マルチバイト文字の途中で切らず、文字境界まで戻す（3 バイト文字が 4095 バイト目から）。
#[test]
fn err2_truncation_respects_utf8_boundary() {
    let mut s = "a".repeat(4095);
    s.push('あ');
    let err = TraitError::new(ErrorCode::Internal, s);
    assert_eq!(err.message(), "a".repeat(4095));
    assert!(err.message_truncated());

    // 3 バイト文字が丁度 4096 バイトに収まる場合は保持される。
    let mut fits = "a".repeat(4093);
    fits.push('あ');
    let err = TraitError::new(ErrorCode::Internal, fits);
    assert_eq!(err.message().len(), 4096);
    assert!(!err.message_truncated());

    // 巨大な多バイト入力でも結果は有効な UTF-8 で 4095 バイト。
    let huge = TraitError::new(ErrorCode::Internal, "あ".repeat(100_000));
    assert_eq!(huge.message().len(), 4095);
    assert!(huge.message_truncated());
}

/// ERR-2: 短いメッセージは変更されず、通知値は false（容量が過大でも内容は不変）。
#[test]
fn err2_short_message_unchanged_even_with_large_capacity() {
    let mut s = String::with_capacity(1_000_000);
    s.push_str("short");
    let err = TraitError::new(ErrorCode::NotFound, s);
    assert_eq!(err.message(), "short");
    assert!(!err.message_truncated());
    assert_eq!(err.to_string(), "NOT_FOUND: short");
}
