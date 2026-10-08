//! `CliError` の公開 API の結合試験（ERR-1・REPAIR-12。TASK-95.1・MS-6）。
//!
//! core のエラーからの変換・具体的な 1 行 JSON・終了コード対応を、crate 外部から公開 API だけで照合する。

use fandhe_container_cli::error::CliError;
use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError};
use fandhe_container_core::traits::{ErrorCode, TraitError};

#[test]
fn err1_from_trait_error_to_json_and_exit_code() {
    let e = CliError::from(TraitError::new(
        ErrorCode::NotFound,
        "container \"c1\" missing",
    ));
    assert_eq!(e.code(), ErrorCode::NotFound);
    assert_eq!(
        e.to_json_line(),
        "{\"code\":\"NOT_FOUND\",\"message\":\"container \\\"c1\\\" missing\"}\n"
    );
    assert_eq!(e.exit_code().get(), 3);
}

#[test]
fn err1_from_oci_runtime_error_drops_op() {
    let o = OciRuntimeError::new(LifecycleOp::Start, ErrorCode::Timeout, "slow");
    let e = CliError::from(&o);
    assert_eq!(
        e.to_json_line(),
        "{\"code\":\"TIMEOUT\",\"message\":\"slow\"}\n"
    );
    assert_eq!(e.exit_code().get(), 7);
}

#[test]
fn err1_exit_code_table() {
    let table = [
        (ErrorCode::InvalidArgument, 2),
        (ErrorCode::NotFound, 3),
        (ErrorCode::AlreadyExists, 4),
        (ErrorCode::FailedPrecondition, 5),
        (ErrorCode::PermissionDenied, 6),
        (ErrorCode::Timeout, 7),
        (ErrorCode::Unimplemented, 8),
        (ErrorCode::Unavailable, 9),
        (ErrorCode::Internal, 1),
    ];
    for (code, want) in table {
        assert_eq!(CliError::new(code, "x").exit_code().get(), want);
    }
}

#[test]
fn err1_write_stderr_emits_exact_line() {
    let e = CliError::new(ErrorCode::InvalidArgument, "bad\nvalue");
    let mut out: Vec<u8> = Vec::new();
    e.write_stderr(&mut out).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"bad value\"}\n"
    );
}
