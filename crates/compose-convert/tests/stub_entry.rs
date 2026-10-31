//! 実バイナリの stub 挙動の結合試験（STACK-3・REPAIR-3・REPAIR-12）。
//! 子プロセスの待ちには期限を付ける（REPAIR-5）。

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_compose_convert::{UNIMPLEMENTED_EXIT_CODE, UNIMPLEMENTED_JSON};

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-compose-convert");

fn run_with(args: &[&str]) -> (Option<i32>, String, String) {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("compose-convert did not exit within 30s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (mut out, mut err) = (String::new(), String::new());
    child
        .stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut out)
        .expect("read stdout");
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut err)
        .expect("read stderr");
    (status.code(), out, err)
}

#[test]
fn stub_returns_unimplemented_without_args() {
    let (code, out, err) = run_with(&[]);
    assert_eq!(code, Some(i32::from(UNIMPLEMENTED_EXIT_CODE)));
    assert_eq!(out, "");
    assert_eq!(err, format!("{UNIMPLEMENTED_JSON}\n"));
}

#[test]
fn stub_ignores_args_and_does_not_echo_them() {
    let (code, out, err) = run_with(&["--help", "secret-marker.yaml"]);
    assert_eq!(code, Some(8));
    assert_eq!(out, "");
    assert_eq!(err, format!("{UNIMPLEMENTED_JSON}\n"));
    assert!(!err.contains("secret-marker"));
}
