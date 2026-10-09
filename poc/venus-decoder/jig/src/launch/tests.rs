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
    let logdir = scratch("wwlog");
    let sock = dir.join("s.sock");
    let log = logdir.join("j.log");
    let c = cfg(&sock, &log, &[]).unwrap();
    assert_eq!(code_of(run(&c)), "SOCKET_DIR_NOT_PRIVATE");
    assert!(fs::symlink_metadata(&sock).is_err(), "must not bind");
    assert!(fs::symlink_metadata(&log).is_err(), "must not create log");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(&dir).unwrap();
    fs::remove_dir_all(&logdir).unwrap();
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

#[test]
fn gpu6_writable_ancestor_is_rejected_without_bind() {
    // 祖先が他者書き込み可で sticky なし: 別 UID が子を rename で差し替えられる。
    let top = scratch("anc");
    let mid = top.join("mid");
    DirBuilder::new().mode(0o700).create(&mid).unwrap();
    let dir = mid.join("sock");
    DirBuilder::new().mode(0o700).create(&dir).unwrap();
    fs::set_permissions(&mid, fs::Permissions::from_mode(0o777)).unwrap();
    let c = cfg(&dir.join("s.sock"), &top.join("j.log"), &[]).unwrap();
    assert_eq!(code_of(run(&c)), "SOCKET_DIR_ANCESTOR_UNSAFE");
    assert!(fs::symlink_metadata(dir.join("s.sock")).is_err());
    assert!(fs::symlink_metadata(top.join("j.log")).is_err());
    fs::set_permissions(&mid, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(&top).unwrap();
}

#[test]
fn gpu6_symlinked_ancestor_is_rejected() {
    let real = scratch("areal");
    let holder = scratch("ahold");
    DirBuilder::new()
        .mode(0o700)
        .create(real.join("sock"))
        .unwrap();
    let link = holder.join("link");
    symlink(&real, &link).unwrap();
    let c = cfg(
        &link.join("sock").join("s.sock"),
        &holder.join("j.log"),
        &[],
    )
    .unwrap();
    assert_eq!(code_of(run(&c)), "SOCKET_DIR_ANCESTOR_UNSAFE");
    assert!(fs::symlink_metadata(real.join("sock").join("s.sock")).is_err());
    fs::remove_dir_all(&real).unwrap();
    fs::remove_dir_all(&holder).unwrap();
}

#[test]
fn repair5_run_revalidates_accept_timeout_without_side_effects() {
    let dir = scratch("at");
    let sock = dir.join("s.sock");
    let log = dir.join("j.log");
    let mut c = cfg(&sock, &log, &[]).unwrap();
    for t in [
        Duration::MAX,
        Duration::ZERO,
        MAX_ACCEPT_TIMEOUT + Duration::from_millis(1),
    ] {
        c.accept_timeout = t;
        assert_eq!(code_of(run(&c)), "INVALID_ARGUMENT");
    }
    assert!(fs::symlink_metadata(&log).is_err(), "must not create log");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn repair4_error_json_line_escapes_cause() {
    let e = LaunchError {
        code: LaunchErrorCode::SessionFailed,
        cause: Some("A\"B\\C\nD"),
    };
    assert!(
        e.to_json_line()
            .ends_with(",\"cause\":\"A\\\"B\\\\C\\u000aD\"}"),
        "{}",
        e.to_json_line()
    );
}

#[test]
fn gpu6_run_rejects_same_socket_and_log_paths_without_side_effects() {
    // PLUG-12 周辺: `Config` は公開フィールドなので `parse_args` を経ない同一パスも `run` が副作用の前に拒否する。
    let base = scratch("col");
    let p = base.join("sub").join("x");
    let mut c = cfg(&base.join("s.sock"), &base.join("j.log"), &[]).unwrap();
    c.socket = p.clone();
    c.log = p;
    assert_eq!(code_of(run(&c)), "PATH_INVALID");
    assert!(fs::symlink_metadata(base.join("sub")).is_err(), "no dir");
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn gpu6_unsafe_log_ancestor_is_rejected_without_creating_log() {
    let top = scratch("lanc");
    let mid = top.join("mid");
    DirBuilder::new().mode(0o700).create(&mid).unwrap();
    let logdir = mid.join("logs");
    DirBuilder::new().mode(0o700).create(&logdir).unwrap();
    fs::set_permissions(&mid, fs::Permissions::from_mode(0o777)).unwrap();
    let c = cfg(&top.join("s.sock"), &logdir.join("j.log"), &[]).unwrap();
    assert_eq!(code_of(run(&c)), "LOG_DIR_UNSAFE");
    assert!(fs::symlink_metadata(logdir.join("j.log")).is_err());
    assert!(fs::symlink_metadata(top.join("s.sock")).is_err());
    fs::set_permissions(&mid, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(&top).unwrap();
}

#[test]
fn gpu6_symlinked_log_ancestor_is_rejected() {
    let real = scratch("lreal");
    let holder = scratch("lhold");
    let link = holder.join("link");
    symlink(&real, &link).unwrap();
    let c = cfg(&holder.join("s.sock"), &link.join("j.log"), &[]).unwrap();
    assert_eq!(code_of(run(&c)), "LOG_DIR_UNSAFE");
    assert!(fs::symlink_metadata(real.join("j.log")).is_err());
    fs::remove_dir_all(&real).unwrap();
    fs::remove_dir_all(&holder).unwrap();
}

#[test]
fn gpu6_missing_socket_dir_parent_reports_create_failed_not_ancestor_unsafe() {
    // 親も無いとき: 祖先検査が NotFound を unsafe に写さず、作成失敗（終了コード 1）に到達する。
    let base = scratch("nopar");
    let c = cfg(
        &base.join("a").join("b").join("s.sock"),
        &base.join("j.log"),
        &[],
    )
    .unwrap();
    let e = run(&c).expect_err("must fail");
    assert_eq!(e.code.as_str(), "SOCKET_DIR_CREATE_FAILED");
    assert_eq!(e.exit_code(), 1);
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn gpu6_peer_uid_matches_effective_uid() {
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(sys::peer_uid(a.as_fd()).unwrap(), effective_uid().unwrap());
}

#[test]
fn gpu6_peer_with_other_uid_is_rejected_before_session() {
    // 実行ユーザーと別の UID を期待値として渡し、接続元不一致で PEER_REJECTED になりセッションに入らないことを照合する。
    let dir = scratch("peer");
    let sock = dir.join("s.sock");
    let log = dir.join("j.log");
    let c = cfg(&sock, &log, &["--accept-timeout-ms", "5000"]).unwrap();
    let uid = effective_uid().unwrap();
    let client_sock = sock.clone();
    let client = thread::spawn(move || {
        for _ in 0..500 {
            if let Ok(s) = std::os::unix::net::UnixStream::connect(&client_sock) {
                return Some(s);
            }
            thread::sleep(Duration::from_millis(10));
        }
        None
    });
    let file = open_log(&c.log).unwrap();
    let mut sink = LogSink::new(file);
    let r = serve(&c, uid.wrapping_add(1), &mut sink);
    assert_eq!(code_of(r), "PEER_REJECTED");
    let _ = client.join();
    fs::remove_dir_all(&dir).unwrap();
}
