//! バイナリ `fandhe-container-plugin-mcp` の起動の結合試験（MCP-1・PLUG-4・REPAIR-12・REPAIR-3）。
//!
//! 実バイナリを起動し、終了コード・stderr の 1 行 JSON・stdout が空であることを具体値で照合する。

use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fandhe-container-plugin-mcp"));
    cmd.args(args).env_clear();
    // Windows ではプロセス起動に SystemRoot が要る。
    if let Some(root) = std::env::var_os("SystemRoot") {
        cmd.env("SystemRoot", root);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn fandhe-container-plugin-mcp");
    // 書き込み用スレッドで stdin へ送って閉じる（パイプ満杯でのハングを避ける）。
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let input = stdin_bytes.to_vec();
    thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
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

/// MCP-1: stdin が空なら何も出さず終了コード 0。
#[test]
fn mcp1_empty_stdin_exits_zero() {
    let out = run(&[], b"");
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty(), "stdout must be empty");
    assert!(out.stderr.is_empty(), "stderr must be empty");
}

/// MCP-1・MCP-2: initialize → initialized 通知 → tools/list を stdio で処理し、応答は 2 行。
#[test]
fn mcp1_initialize_then_tools_list_over_stdio() {
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        "\n",
    );
    let out = run(&[], input.as_bytes());
    assert_eq!(out.status.code(), Some(0));
    // REPAIR-4: stderr には要求ごとの構造化ログ 1 行 JSON（3 要求分）だけが出る。
    let stderr = String::from_utf8(out.stderr).expect("stderr is UTF-8");
    let logs: Vec<serde_json::Value> = stderr
        .lines()
        .map(|l| serde_json::from_str(l).expect("log line is JSON"))
        .collect();
    let ops: Vec<&str> = logs.iter().filter_map(|l| l["op"].as_str()).collect();
    assert_eq!(ops, ["initialize", "notification", "tools/list"]);
    let results: Vec<&str> = logs.iter().filter_map(|l| l["result"].as_str()).collect();
    assert_eq!(results, ["ok", "no_reply", "ok"]);
    let text = String::from_utf8(out.stdout).expect("stdout is UTF-8");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "stdout: {text}");
    let init: serde_json::Value = serde_json::from_str(lines[0]).expect("line 1 is JSON");
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    let list: serde_json::Value = serde_json::from_str(lines[1]).expect("line 2 is JSON");
    assert_eq!(list["id"], 2);
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(names, ["list_containers", "start_container"]);
}

/// MCP-1・PLUG-4: 引数ありは終了コード 2。入力値は出力へ埋め込まれず、stdout は空。
#[test]
fn mcp1_any_argument_is_rejected_without_echo() {
    let out = run(&["--socket", "/tmp/x"], b"");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(stderr, INVALID_ARGUMENT_JSON);
    assert!(!stderr.contains("/tmp/x"));
    assert!(out.stdout.is_empty(), "stdout must be empty");
}
