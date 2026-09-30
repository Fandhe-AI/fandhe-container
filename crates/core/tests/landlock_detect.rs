//! Landlock ABI 検出の公開 API（`fandhe_container_core::landlock`）の結合試験
//! （CORE-5・TASK-39.1・#181。REPAIR-10・REPAIR-12 の機械照合）。
//!
//! 公開 API だけから、実行中カーネルの結果が「ABI 6 以上なら `Ok`、それ以外は理由付きの `Err`」の
//! いずれかに一貫して写ることを具体値で照合する。カーネル版数・seccomp 有無に依存しない。
//! ABI 6 以上を要求する実機前提の照合は `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。

#![cfg(target_os = "linux")]

use fandhe_container_core::landlock::{LandlockUnavailable, MIN_LANDLOCK_ABI, detect_landlock_abi};
use fandhe_container_core::traits::ErrorCode;

/// CORE-5: 要求する最小 ABI は 6。
#[test]
fn core5_min_abi_is_6() {
    assert_eq!(MIN_LANDLOCK_ABI, 6);
}

/// CORE-5: 検出結果は ABI 6 以上の `Ok`、または拒否理由・コード・機械可読な文字列が一致した `Err`。
#[test]
fn core5_detect_is_ok_or_structured_rejection() {
    match detect_landlock_abi() {
        Ok(s) => {
            assert!(s.abi.get() >= 6, "abi {} must be >= 6", s.abi.get());
            assert_eq!(s.required.get(), 6);
        }
        Err(e) => {
            // 拒否（fail-closed）の理由ごとにコードと理由コード文字列を具体値で照合する。
            let (code, reason_str) = match e.reason {
                LandlockUnavailable::KernelLacksLandlock => {
                    (ErrorCode::FailedPrecondition, "kernel_lacks_landlock")
                }
                LandlockUnavailable::DisabledAtBoot => {
                    (ErrorCode::FailedPrecondition, "landlock_disabled_at_boot")
                }
                LandlockUnavailable::AbiTooOld { detected, required } => {
                    assert!((1..6).contains(&detected), "detected {detected}");
                    assert_eq!(required, 6);
                    (ErrorCode::FailedPrecondition, "landlock_abi_too_old")
                }
                LandlockUnavailable::InvalidKernelResponse { raw } => {
                    assert_eq!(raw, 0);
                    (ErrorCode::Internal, "invalid_kernel_response")
                }
                LandlockUnavailable::UnsupportedArchitecture => {
                    (ErrorCode::Unimplemented, "unsupported_architecture")
                }
                LandlockUnavailable::ProbeFailed { errno } => {
                    assert!(errno >= 0, "errno {errno}");
                    (ErrorCode::Internal, "landlock_probe_failed")
                }
                // non_exhaustive: 将来の理由が増えても「拒否である」ことだけは保たれる。
                _ => (e.code, e.reason.as_str()),
            };
            assert_eq!(e.code, code);
            assert_eq!(e.reason.as_str(), reason_str);
            assert!(!e.message.is_empty());
            let text = e.to_string();
            assert!(text.starts_with(&format!("{}: ", code.as_str())), "{text}");
            assert!(text.ends_with(&format!("({reason_str})")), "{text}");
        }
    }
}

/// CORE-5: 2 回呼んでも同じ結果（読み取り専用の問い合わせで副作用が無い）。
#[test]
fn core5_detect_is_idempotent() {
    assert_eq!(detect_landlock_abi(), detect_landlock_abi());
}

/// CORE-5: 実機（Linux 6.12+・ABI 6+）では `Ok` になる。
#[test]
#[ignore = "requires Landlock ABI >= 6 (Linux 6.12+). CORE-5"]
fn core5_detect_succeeds_on_abi6_host() {
    let s = detect_landlock_abi().expect("Landlock ABI >= 6 required");
    assert!(s.abi.get() >= 6);
}
