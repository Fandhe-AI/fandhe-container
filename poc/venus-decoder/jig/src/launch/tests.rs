//! 起動入口の拒否・期限のユニットテスト（GPU-6・REPAIR-5・TASK-172 F4・#1598）。
//!
//! bind 前の検証が `code` の具体値で拒否し、ソケットを作らず既存のものを消さないことを照合する。

use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::sync::atomic::{AtomicU32, Ordering};

use super::*;

/// `/tmp` 配下の一意な 0700 ディレクトリ（`sun_path` の上限に収めるため `temp_dir()` は使わない）。
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let p = PathBuf::from(format!(
        "/tmp/vjl-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    DirBuilder::new().mode(0o700).create(&p).expect("scratch");
    p
}

fn args(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

fn cfg(socket: &Path, log: &Path, extra: &[&str]) -> Result<Config, LaunchError> {
    let mut a = vec![
        "--socket".to_string(),
        socket.display().to_string(),
        "--log".to_string(),
        log.display().to_string(),
    ];
    a.extend(extra.iter().map(|s| s.to_string()));
    parse_args(&a.iter().map(OsString::from).collect::<Vec<_>>())
}

fn code_of(r: Result<SessionEnd, LaunchError>) -> &'static str {
    r.expect_err("must be rejected").code.as_str()
}

#[test]
fn gpu6_parse_args_rejects_bad_arguments_with_invalid_argument() {
    let cases: Vec<Vec<&str>> = vec![
        vec![],
        vec!["--socket", "/tmp/a.sock"],
        vec!["--bogus", "x", "--socket", "/tmp/a", "--log", "/tmp/b"],
        vec![
            "--socket", "/tmp/a", "--socket", "/tmp/c", "--log", "/tmp/b",
        ],
        vec!["--socket", "/tmp/a", "--log"],
        vec![
            "--socket",
            "/tmp/a",
            "--log",
            "/tmp/b",
            "--accept-timeout-ms",
            "0",
        ],
        vec![
            "--socket",
            "/tmp/a",
            "--log",
            "/tmp/b",
            "--idle-timeout-ms",
            "abc",
        ],
        vec![
            "--socket",
            "/tmp/a",
            "--log",
            "/tmp/b",
            "--accept-timeout-ms",
            "3600001",
        ],
        vec![
            "--socket",
            "/tmp/a",
            "--log",
            "/tmp/b",
            "--poll-slice-ms",
            "70000",
        ],
    ];
    for c in cases {
        let e = parse_args(&args(&c)).expect_err("must fail");
        assert_eq!(e.code.as_str(), "INVALID_ARGUMENT", "args: {c:?}");
        assert_eq!(e.exit_code(), 2);
    }
}

#[test]
fn gpu6_parse_args_accepts_defaults() {
    let c = parse_args(&args(&["--socket", "/tmp/a.sock", "--log", "/tmp/a.log"])).expect("ok");
    assert_eq!(c.socket, PathBuf::from("/tmp/a.sock"));
    assert_eq!(c.limits.message_timeout(), Duration::from_millis(5000));
    assert_eq!(c.limits.idle_timeout(), Duration::from_millis(60000));
    assert_eq!(c.accept_timeout, Duration::from_millis(60000));
}

#[test]
fn gpu6_relative_path_is_rejected() {
    let e = parse_args(&args(&["--socket", "a.sock", "--log", "/tmp/x.log"])).expect_err("reject");
    assert_eq!(e.code.as_str(), "PATH_NOT_ABSOLUTE");
    let e = parse_args(&args(&["--socket", "/tmp/a.sock", "--log", "x.log"])).expect_err("reject");
    assert_eq!(e.code.as_str(), "PATH_NOT_ABSOLUTE");
}

#[test]
fn gpu6_too_long_path_is_rejected() {
    let long = format!("/{}", "a".repeat(200));
    let e = parse_args(&args(&["--socket", &long, "--log", "/tmp/x.log"])).expect_err("reject");
    assert_eq!(e.code.as_str(), "PATH_TOO_LONG");
    // 107 バイトちょうどは通り、108 バイトは拒否する。
    let ok = format!("/{}", "a".repeat(106));
    assert_eq!(ok.len(), 107);
    assert!(parse_args(&args(&["--socket", &ok, "--log", "/tmp/x.log"])).is_ok());
    let over = format!("/{}", "a".repeat(107));
    let e = parse_args(&args(&["--socket", &over, "--log", "/tmp/x.log"])).expect_err("reject");
    assert_eq!(e.code.as_str(), "PATH_TOO_LONG");
}

#[test]
fn gpu6_dotdot_and_same_path_are_invalid() {
    for sock in ["/tmp/../tmp/a.sock", "/tmp/./a.sock", "/"] {
        let e = parse_args(&args(&["--socket", sock, "--log", "/tmp/x.log"])).expect_err("reject");
        assert_eq!(e.code.as_str(), "PATH_INVALID", "socket: {sock}");
    }
    let e = parse_args(&args(&["--socket", "/tmp/a", "--log", "/tmp/a"])).expect_err("reject");
    assert_eq!(e.code.as_str(), "PATH_INVALID");
}

#[test]
fn gpu6_world_writable_dir_is_rejected_without_bind() {
    let dir = scratch("ww");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
    let sock = dir.join("s.sock");
    let log = dir.join("j.log");
    let c = cfg(&sock, &log, &[]).unwrap();
    assert_eq!(code_of(run(&c)), "SOCKET_DIR_NOT_PRIVATE");
    assert!(fs::symlink_metadata(&sock).is_err(), "must not bind");
    assert!(fs::symlink_metadata(&log).is_err(), "must not create log");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn gpu6_symlinked_dir_is_rejected() {
    let real = scratch("real");
    let holder = scratch("hold");
    let link = holder.join("link");
    symlink(&real, &link).unwrap();
    let sock = link.join("s.sock");
    let log = holder.join("j.log");
    let c = cfg(&sock, &log, &[]).unwrap();
    assert_eq!(code_of(run(&c)), "SOCKET_DIR_SYMLINK");
    assert!(fs::symlink_metadata(real.join("s.sock")).is_err());
    fs::remove_dir_all(&real).unwrap();
    fs::remove_dir_all(&holder).unwrap();
}

#[test]
fn gpu6_non_directory_parent_is_rejected() {
    let dir = scratch("nd");
    let file = dir.join("f");
    fs::write(&file, b"x").unwrap();
    let c = cfg(&file.join("s.sock"), &dir.join("j.log"), &[]).unwrap();
    assert_eq!(code_of(run(&c)), "SOCKET_DIR_NOT_DIRECTORY");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn gpu6_existing_socket_path_is_rejected_and_kept() {
    let dir = scratch("ex");
    let sock = dir.join("s.sock");
    fs::write(&sock, b"precious").unwrap();
    let log = dir.join("j.log");
    let c = cfg(&sock, &log, &[]).unwrap();
    assert_eq!(code_of(run(&c)), "SOCKET_PATH_EXISTS");
    assert_eq!(fs::read(&sock).unwrap(), b"precious");
    assert!(fs::symlink_metadata(&log).is_err(), "must not create log");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn gpu6_existing_log_path_is_rejected_and_kept() {
    let dir = scratch("el");
    let log = dir.join("j.log");
    fs::write(&log, b"keep").unwrap();
    let sock = dir.join("s.sock");
    let c = cfg(&sock, &log, &[]).unwrap();
    let e = run(&c).expect_err("reject");
    assert_eq!(e.code.as_str(), "LOG_PATH_EXISTS");
    assert_eq!(e.exit_code(), 2);
    assert_eq!(fs::read(&log).unwrap(), b"keep");
    assert!(fs::symlink_metadata(&sock).is_err());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn gpu6_missing_socket_dir_is_created_with_0700() {
    let base = scratch("mk");
    let sub = base.join("sockdir");
    let c = cfg(
        &sub.join("s.sock"),
        &base.join("j.log"),
        &["--accept-timeout-ms", "50"],
    )
    .unwrap();
    assert_eq!(code_of(run(&c)), "ACCEPT_TIMEOUT");
    let mode = fs::metadata(&sub).unwrap().mode() & 0o7777;
    assert_eq!(mode, 0o700);
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn repair5_accept_timeout_cleans_up_socket_and_logs() {
    let dir = scratch("to");
    let sock = dir.join("s.sock");
    let log = dir.join("j.log");
    let c = cfg(&sock, &log, &["--accept-timeout-ms", "50"]).unwrap();
    let started = Instant::now();
    let e = run(&c).expect_err("timeout");
    assert_eq!(e.code.as_str(), "ACCEPT_TIMEOUT");
    assert_eq!(e.exit_code(), 1);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(fs::symlink_metadata(&sock).is_err(), "socket cleaned up");
    assert_eq!(
        fs::read_to_string(&log).unwrap(),
        "venus_jig event=launch_error code=ACCEPT_TIMEOUT\n"
    );
    assert_eq!(fs::metadata(&log).unwrap().mode() & 0o777, 0o600);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn gpu6_error_json_line_is_fixed_vocabulary() {
    let e = LaunchError {
        code: LaunchErrorCode::SessionFailed,
        cause: Some("IDLE_TIMEOUT"),
    };
    assert_eq!(
        e.to_json_line(),
        "{\"code\":\"SESSION_FAILED\",\"message\":\"vhost-user session ended with an error\",\"cause\":\"IDLE_TIMEOUT\"}"
    );
    assert_eq!(e.exit_code(), 1);
    let e = LaunchError::new(LaunchErrorCode::PathNotAbsolute);
    assert_eq!(
        e.to_json_line(),
        "{\"code\":\"PATH_NOT_ABSOLUTE\",\"message\":\"path must be absolute\"}"
    );
}
