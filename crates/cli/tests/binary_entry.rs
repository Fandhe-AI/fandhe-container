//! バイナリ `fandhe-container` の入口の結合試験（CLI-1・REPAIR-12。TASK-79.1）。
//!
//! 実バイナリを起動し、終了コード・stderr の 1 行 JSON・stdout が空であることを具体値で照合する。

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const USAGE_JSON: &str = "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"usage: fandhe-container <create|start|stop|delete|list|logs>\"}\n";
const UNIMPLEMENTED_JSON: &str =
    "{\"code\":\"UNIMPLEMENTED\",\"message\":\"command is not implemented yet\"}\n";

/// 子プロセスの終了を待つ上限（REPAIR-5）。超過時は kill して失敗させる。
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// 実バイナリを起動し、有限期限内に終了と出力収集を完了させる（REPAIR-5）。
///
/// stdout / stderr は別スレッドで読み、パイプ詰まりによるデッドロックを避ける。
/// 期限超過時は子を kill して回収し、panic で失敗させる。
fn run(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fandhe-container"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn fandhe-container");
    let mut out_pipe = child.stdout.take().expect("stdout is piped");
    let mut err_pipe = child.stderr.take().expect("stderr is piped");
    let out_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf);
        buf
    });
    let err_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("failed to poll child") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                // 子が kill されればパイプは閉じ、読み取りスレッドも終了する。
                let _ = out_reader.join();
                let _ = err_reader.join();
                panic!("fandhe-container did not exit within {CHILD_TIMEOUT:?}");
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    Output {
        status,
        stdout: out_reader.join().expect("stdout reader panicked"),
        stderr: err_reader.join().expect("stderr reader panicked"),
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
