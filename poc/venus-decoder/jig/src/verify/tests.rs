//! 検証入口の単体試験（GPU-6・REPAIR-2・REPAIR-12・#1885。3 OS・既定集合）。

use std::ffi::OsString;
use std::sync::mpsc;

use super::*;

fn args(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

#[test]
fn gpu6_repair2_1885_json_line_is_exact() {
    let ok = VerifyReport {
        result: "ok",
        records: Some(3),
        bytes: Some(80),
    };
    assert_eq!(
        ok.to_json_line(),
        "{\"result\":\"ok\",\"records\":3,\"bytes\":80}"
    );
    assert_eq!(ok.exit_code(), 0);
    let bad = VerifyReport::failure("venus_replay.io", None);
    assert_eq!(
        bad.to_json_line(),
        "{\"result\":\"venus_replay.io\",\"records\":null,\"bytes\":null}"
    );
    assert_eq!(bad.exit_code(), 1);
}

#[test]
fn gpu6_repair2_1885_parse_args_cases() {
    assert_eq!(parse_verify_args(&args(&["--socket", "/x"])), None);
    assert_eq!(parse_verify_args(&[]), None);
    let abs = if cfg!(windows) { "C:\\r.bin" } else { "/r.bin" };
    assert_eq!(
        parse_verify_args(&args(&["--verify-record", abs])),
        Some(Ok(PathBuf::from(abs)))
    );
    for bad in [
        args(&["--verify-record"]),
        args(&["--verify-record", abs, "--log", abs]),
        args(&["--verify-record", abs, "extra"]),
    ] {
        let e = parse_verify_args(&bad).expect("mode").expect_err("err");
        assert_eq!(e.code, "INVALID_ARGUMENT");
        assert_eq!(e.exit_code(), 2);
    }
    let e = parse_verify_args(&args(&["--verify-record", "rel/secret-path"]))
        .expect("mode")
        .expect_err("err");
    assert_eq!(e.code, "PATH_NOT_ABSOLUTE");
    assert!(!e.to_json_line().contains("secret-path"));
}

#[test]
fn gpu6_repair2_1885_timeout_is_reported() {
    let (tx, rx) = mpsc::channel::<()>();
    let r = verify_with(
        move || {
            let _ = rx.recv();
            Ok(Vec::new())
        },
        Duration::from_millis(50),
    );
    assert_eq!(
        r,
        VerifyReport {
            result: "venus_verify.timeout",
            records: None,
            bytes: None
        }
    );
    drop(tx);
}

#[test]
fn gpu6_repair2_1885_verify_bytes_failure_keeps_total_length() {
    let r = verify_bytes(&[0u8; 5]);
    assert_eq!(r.result, "venus_replay.truncated");
    assert_eq!(r.bytes, Some(5));
    assert_eq!(r.records, None);
}
