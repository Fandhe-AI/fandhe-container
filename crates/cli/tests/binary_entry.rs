//! バイナリ `fandhe-container` の入口の結合試験（CLI-1・REPAIR-12。TASK-79.1・MS-6）。
//!
//! 実バイナリを起動し、終了コード・stderr の 1 行 JSON・stdout が空であることを具体値で照合する。

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const USAGE_JSON: &str = "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: fandhe-container <create|start|stop|delete|list|logs>\"}\n";
const UNIMPLEMENTED_JSON: &str =
    "{\"code\":\"UNIMPLEMENTED\",\"message\":\"command is not implemented yet\"}\n";

/// 子プロセスの終了を待つ上限（REPAIR-5）。超過時は kill して失敗させる。
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// kill 後の回収と、終了後の出力収集を待つ上限（REPAIR-5）。
const REAP_TIMEOUT: Duration = Duration::from_secs(10);

/// パイプを別スレッドで読み、結果をチャネルで返す（待つ側は `recv_timeout` で期限を設ける）。
fn spawn_reader<R: Read + Send + 'static>(mut pipe: R) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx
}

/// 実バイナリを起動し、有限期限内に終了と出力収集を完了させる（REPAIR-5）。
///
/// stdout / stderr は別スレッドで読み、パイプ詰まりによるデッドロックを避ける。
/// 回収・出力収集のいずれも期限付きで、期限超過時は読み取りを打ち切って panic で失敗させる
/// （stdout を継承した子孫が残って EOF が来ない場合も無期限に待たない）。
fn run(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fandhe-container"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn fandhe-container");
    let out_rx = spawn_reader(child.stdout.take().expect("stdout is piped"));
    let err_rx = spawn_reader(child.stderr.take().expect("stderr is piped"));

    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("failed to poll child") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                // kill 後の回収も期限付きでポーリングする。
                let reap_deadline = Instant::now() + REAP_TIMEOUT;
                while Instant::now() < reap_deadline {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                panic!("fandhe-container did not exit within {CHILD_TIMEOUT:?}");
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

fn assert_failure(out: &Output, code: i32, stderr: &str) {
    assert_eq!(out.status.code(), Some(code));
    assert_eq!(String::from_utf8_lossy(&out.stderr), stderr);
    assert!(out.stdout.is_empty(), "stdout must be empty");
}

/// CLI-1: 引数なしは使い方エラー（終了コード 2）。
#[test]
fn cli1_no_args_is_usage_error() {
    assert_failure(&run(&[]), 2, USAGE_JSON);
}

/// CLI-1: 未知コマンドは使い方エラー。引数値は出力へ埋め込まれない。
#[test]
fn cli1_unknown_command_is_usage_error() {
    for a in ["run", "Create", "", "--help", "a\"b\\c"] {
        assert_failure(&run(&[a]), 2, USAGE_JSON);
    }
}

/// CLI-1: 既知の各コマンドは未実装として終了コード 3。余分な引数があっても同じ。
#[test]
fn cli1_known_commands_are_unimplemented() {
    for c in ["create", "start", "stop", "delete", "list", "logs"] {
        assert_failure(&run(&[c]), 3, UNIMPLEMENTED_JSON);
        assert_failure(&run(&[c, "extra"]), 3, UNIMPLEMENTED_JSON);
    }
}
