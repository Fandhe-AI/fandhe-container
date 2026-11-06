//! `support/kvm_precondition.rs`（KVM 側の前提欠如と回帰の振り分けの正本）の単体試験。3 OS の既定集合で走る
//! （MVM-1・REPAIR-4・REPAIR-12・#3992）。
//!
//! 全エラーコードについて期待値を独立したリテラルの表で照合し、回帰側の行に
//! `PRECONDITION FAILED` が出ないこと（環境の問題に見せない）を機械照合する。

#[path = "support/kvm_precondition.rs"]
mod kvm_precondition;

use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
use kvm_precondition::{
    assemble_failure_line, is_assemble_environment_code, is_open_environment_code,
    open_failure_line,
};

/// (コード, open が環境か, assemble が環境か)。補助の判定とは独立に書く。
const EXPECTED: [(MicrovmErrorCode, bool, bool); 9] = [
    (MicrovmErrorCode::NotFound, true, false),
    (MicrovmErrorCode::PermissionDenied, true, true),
    (MicrovmErrorCode::FailedPrecondition, false, true),
    (MicrovmErrorCode::ResourceExhausted, false, false),
    (MicrovmErrorCode::Unimplemented, true, false),
    (MicrovmErrorCode::InvalidArgument, false, false),
    (MicrovmErrorCode::AlreadyExists, false, false),
    (MicrovmErrorCode::Internal, false, false),
    (MicrovmErrorCode::DeadlineExceeded, false, false),
];

#[test]
fn table_covers_every_error_code() {
    assert_eq!(MicrovmErrorCode::ALL.len(), 9);
    assert_eq!(EXPECTED.len(), MicrovmErrorCode::ALL.len());
    for code in MicrovmErrorCode::ALL {
        assert_eq!(
            EXPECTED.iter().filter(|(c, _, _)| *c == code).count(),
            1,
            "{code:?}"
        );
    }
}

#[test]
fn classification_matches_table_for_every_code() {
    for (code, open_env, assemble_env) in EXPECTED {
        assert_eq!(is_open_environment_code(code), open_env, "open {code:?}");
        assert_eq!(
            is_assemble_environment_code(code),
            assemble_env,
            "assemble {code:?}"
        );
    }
}

#[test]
fn regression_lines_never_say_precondition_failed() {
    for (code, open_env, assemble_env) in EXPECTED {
        let e = MicrovmError::new(code, "x");
        assert_eq!(
            open_failure_line("t", &e).contains("PRECONDITION FAILED"),
            open_env,
            "open {code:?}"
        );
        assert_eq!(
            assemble_failure_line("t", &e).contains("PRECONDITION FAILED"),
            assemble_env,
            "assemble {code:?}"
        );
    }
}

#[test]
fn open_lines_are_exact() {
    let nf = MicrovmError::new(MicrovmErrorCode::NotFound, "KVM device not found");
    assert_eq!(
        open_failure_line("kvm_device", &nf),
        "kvm_device: PRECONDITION FAILED (test environment, not a regression): NOT_FOUND: KVM device not found"
    );
    let ver = MicrovmError::new(
        MicrovmErrorCode::FailedPrecondition,
        "unsupported KVM API version 11 (expected 12)",
    );
    assert_eq!(
        open_failure_line("kvm_device", &ver),
        "kvm_device: open: FAILED_PRECONDITION: unsupported KVM API version 11 (expected 12)"
    );
    let internal = MicrovmError::new(
        MicrovmErrorCode::Internal,
        "failed to open KVM device (os error 6)",
    );
    assert_eq!(
        open_failure_line("microvm", &internal),
        "microvm: open: INTERNAL: failed to open KVM device (os error 6)"
    );
}

#[test]
fn assemble_lines_are_exact() {
    let gic = MicrovmError::new(
        MicrovmErrorCode::FailedPrecondition,
        "the host does not provide an in-kernel GICv3",
    );
    assert_eq!(
        assemble_failure_line("e2e", &gic),
        "e2e: PRECONDITION FAILED (test environment, not a regression): FAILED_PRECONDITION: the host does not provide an in-kernel GICv3"
    );
    let bad = MicrovmError::new(
        MicrovmErrorCode::InvalidArgument,
        "KVM rejected the vGIC address or state",
    );
    assert_eq!(
        assemble_failure_line("e2e", &bad),
        "e2e: assemble: INVALID_ARGUMENT: KVM rejected the vGIC address or state"
    );
}
