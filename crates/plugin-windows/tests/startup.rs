//! 生成バイナリを実際に起動する結合試験（TASK-116.1・#392。受け入れ基準の機械照合。REPAIR-12）。
//!
//! 子プロセスは即終了するが、待機には期限を設け超過時は kill して失敗にする（REPAIR-5）。
//! 対応 ID: TASK-116・PLUG-1・PLUG-4・WIN-1・REPAIR-3。

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-windows");
const PLUGIN_SOCKET_ENV: &str = "FANDHE_CONTAINER_PLUGIN_SOCKET";
const DEADLINE: Duration = Duration::from_secs(30);

#[cfg(unix)]
const ABS: &str = "/tmp/fandhe-plugin-windows-test.sock";
#[cfg(not(unix))]
const ABS: &str = "C:\\fandhe-plugin-windows-test.sock";

/// 環境を空にして起動し、(終了コード, stderr) を返す。
fn run(args: &[&str], envs: &[(&str, &str)]) -> (i32, String) {
    let mut child = Command::new(BIN)
        .args(args)
        .env_clear()
        .envs(envs.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn plugin binary");
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if start.elapsed() > DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            panic!("plugin binary did not exit within deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut err = String::new();
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    (status.code().expect("exit code"), err)
}

#[test]
fn task116_1_arg_socket_starts_and_reports_unimplemented() {
    let (code, err) = run(&["--socket", ABS], &[]);
    assert_eq!(code, 1);
    assert!(err.contains("\"socket_source\":\"arg\""), "{err}");
    assert!(err.contains("\"code\":\"UNIMPLEMENTED\""), "{err}");
    assert!(!err.contains(ABS), "{err}");
}

#[test]
fn task116_1_env_socket() {
    let (code, err) = run(&[], &[(PLUGIN_SOCKET_ENV, ABS)]);
    assert_eq!(code, 1);
    assert!(err.contains("\"socket_source\":\"env\""), "{err}");
}

#[test]
fn task116_1_relative_path_rejected() {
    let (code, err) = run(&["--socket", "rel/a.sock"], &[]);
    assert_eq!(code, 2);
    assert!(err.contains("\"code\":\"INVALID_ARGUMENT\""), "{err}");
}

#[cfg(unix)]
#[test]
fn task116_1_default_path_uses_runtime_dir() {
    use std::os::unix::fs::DirBuilderExt;
    let base = std::env::temp_dir().join(format!("fc-pw-startup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&base)
        .expect("create base");
    let (code, err) = run(&[], &[("XDG_RUNTIME_DIR", base.to_str().expect("utf8"))]);
    let _ = std::fs::remove_dir_all(&base);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("\"socket_source\":\"default\""), "{err}");
}

#[cfg(not(unix))]
#[test]
fn task116_1_default_path_fails_closed_on_non_unix() {
    let (code, err) = run(&[], &[]);
    assert_eq!(code, 2);
    assert!(err.contains("\"code\":\"UNIMPLEMENTED\""), "{err}");
}
