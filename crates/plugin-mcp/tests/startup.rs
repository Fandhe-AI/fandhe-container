//! バイナリ `fandhe-container-plugin-mcp` の起動の結合試験（MCP-1・PLUG-4・REPAIR-12・REPAIR-3）。
//!
//! 実バイナリを起動し、終了コード・stderr の 1 行 JSON・stdout が空であることを具体値で照合する。

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const UNIMPLEMENTED_JSON: &str =
    "{\"code\":\"UNIMPLEMENTED\",\"message\":\"mcp server is not implemented yet\"}\n";
const INVALID_ARGUMENT_JSON: &str =
    "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"unexpected argument\"}\n";

/// 子プロセスの終了を待つ上限（REPAIR-5）。
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);
/// kill 後の回収と出力収集を待つ上限（REPAIR-5）。
const REAP_TIMEOUT: Duration = Duration::from_secs(10);

fn spawn_reader<R: Read + Send + 'static>(mut pipe: R) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx
}

/// 実バイナリを環境変数なしで起動し、期限内に終了と出力収集を完了させる。
fn run(args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fandhe-container-plugin-mcp"));
    cmd.args(args).env_clear();
    // Windows ではプロセス起動に SystemRoot が要る。
    if let Some(root) = std::env::var_os("SystemRoot") {
        cmd.env("SystemRoot", root);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn fandhe-container-plugin-mcp");
    let out_rx = spawn_reader(child.stdout.take().expect("stdout is piped"));
    let err_rx = spawn_reader(child.stderr.take().expect("stderr is piped"));

    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("failed to poll child") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let reap_deadline = Instant::now() + REAP_TIMEOUT;
                while Instant::now() < reap_deadline {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                panic!("fandhe-container-plugin-mcp did not exit within {CHILD_TIMEOUT:?}");
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    let collect_deadline = Instant::now() + REAP_TIMEOUT;
    let remaining = || collect_deadline.saturating_duration_since(Instant::now());
    let stdout = out_rx
        .recv_timeout(remaining())
        .expect("stdout was not collected within the deadline");
    let stderr = err_rx
        .recv_timeout(remaining())
        .expect("stderr was not collected within the deadline");
    Output {
        status,
        stdout,
        stderr,
    }
}

/// MCP-1・REPAIR-3: 引数なしは未実装を示して終了コード 1。stdout は空。
#[test]
fn mcp1_no_args_reports_unimplemented() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&out.stderr), UNIMPLEMENTED_JSON);
    assert!(out.stdout.is_empty(), "stdout must be empty");
}

/// MCP-1・PLUG-4: 引数ありは終了コード 2。入力値は出力へ埋め込まれず、stdout は空。
#[test]
fn mcp1_any_argument_is_rejected_without_echo() {
    let out = run(&["--socket", "/tmp/x"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(stderr, INVALID_ARGUMENT_JSON);
    assert!(!stderr.contains("/tmp/x"));
    assert!(out.stdout.is_empty(), "stdout must be empty");
}
