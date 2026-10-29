//! 特権ランチャー bin（`fandhe-container-launcher`）の外形の結合試験（SUP-14・SEC-1・REPAIR-5・
//! TASK-171 追補・#1719・MS-9）。
//!
//! 実バイナリを CLI と同じ契約（argv・stdout の pipe の結果チャネル）で起動し、失敗の報告 1 行・stderr の構造化 JSON・
//! 終了コードを具体値で照合する。root 不要で既定のテスト集合で動く。file capability を付けた実機のシナリオ
//! （昇格後の `CapAmb` / `CapEff` の照合）は `tests/launcher_entry_real.rs` の `-- --ignored`（AGENTS.md）。
//! 子プロセスの待機には上限を設ける（REPAIR-5）。Linux 限定。

#![cfg(target_os = "linux")]

#[path = "../../core/tests/support/reap.rs"]
mod reap;

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::exit_code_for;
use fandhe_container_core::traits::ErrorCode;
use fandhe_container_supervisor::start_contract::StartReport;

const LAUNCHER: &str = env!("CARGO_BIN_EXE_fandhe-container-launcher");
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

struct Outcome {
    stdout: Vec<u8>,
    stderr: String,
    code: i32,
}

/// ランチャーを起動して完了を待つ。`CHILD_TIMEOUT` を超えたら強制終了して失敗にする。
fn run(args: &[&str], envs: &[(&str, &str)]) -> Outcome {
    run_with(args, envs, false)
}

/// `run` の本体。`new_process_group` が真なら子を新しいプロセスグループのリーダーとして起動する
/// （`setsid` が `EPERM` になる経路の再現用）。期限と子の回収は両経路で同じ。
fn run_with(args: &[&str], envs: &[(&str, &str)], new_process_group: bool) -> Outcome {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(LAUNCHER);
    if new_process_group {
        cmd.process_group(0);
    }
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = String::new();
        let _ = err.read_to_string(&mut b);
        b
    });
    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() >= deadline {
            crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
            panic!("launcher did not exit within {CHILD_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    Outcome {
        stdout: t_out.join().unwrap(),
        stderr: t_err.join().unwrap(),
        code: status.code().unwrap(),
    }
}

fn failed(o: &Outcome) -> (ErrorCode, String) {
    match StartReport::decode(&o.stdout).unwrap() {
        StartReport::Failed {
            code,
            exit_code,
            message,
        } => {
            assert_eq!(exit_code, exit_code_for(code));
            assert_eq!(i32::from(exit_code.get()), o.code);
            (code, message.as_str().to_owned())
        }
        other => panic!("unexpected report: {other:?}"),
    }
}

/// 引数が契約に合わなければ、昇格にも supervisor の exec にも進まず `INVALID_ARGUMENT` で止まる。
#[test]
fn sup14_task1719_invalid_arguments_stop_before_elevation() {
    let cases: [(&[&str], &str); 4] = [
        (&[], "the first argument must be \"start\""),
        (
            &["start", "--root", "relative", "c1"],
            "--root must be an absolute path",
        ),
        (&["start", "--bogus", "c1"], "unknown option"),
        (
            &["start", "--root", "/r"],
            "exactly one container id is required",
        ),
    ];
    for (args, message) in cases {
        let o = run(args, &[]);
        let (code, msg) = failed(&o);
        assert_eq!(code, ErrorCode::InvalidArgument, "{args:?}");
        assert_eq!(msg, message, "{args:?}");
        assert_eq!(o.code, 2, "{args:?}");
        assert!(
            o.stderr.contains(&format!(
                "\"code\":\"INVALID_ARGUMENT\",\"message\":\"{message}"
            )) || o.stderr.contains("\"code\":\"INVALID_ARGUMENT\""),
            "{}",
            o.stderr
        );
    }
}

/// プロセスグループのリーダーとして起動されると、ランチャーの `setsid` が `EPERM` になり、読み戻しでも
/// セッションのリーダーでないため、昇格にも exec にも進まず `FAILED_PRECONDITION` で止まる（SUP-14・TASK-171.2・#537）。
/// 報告は 1 行だけで、メッセージは `session detach failed:` で始まる。
#[test]
fn sup14_task171_2_process_group_leader_is_rejected() {
    let o = run_with(
        &["start", "--root", "/var/lib/fandhe-container", "c1"],
        &[],
        true,
    );
    let (code, msg) = failed(&o);
    assert_eq!(code, ErrorCode::FailedPrecondition, "{msg}");
    assert!(msg.starts_with("session detach failed: "), "{msg}");
    assert_eq!(o.stdout.iter().filter(|&&b| b == b'\n').count(), 1);
    assert_eq!(
        o.code,
        i32::from(exit_code_for(ErrorCode::FailedPrecondition).get())
    );
    assert!(
        o.stderr.contains("\"code\":\"FAILED_PRECONDITION\""),
        "{}",
        o.stderr
    );
}

/// 呼び出し元の環境に `LD_PRELOAD` があっても、検証に失敗する経路は fail-closed のままで、報告は 1 行だけ。
/// 通常の spawn（親と同じプロセスグループ・端末なしの標準入出力）で切り離しに成功し、信頼検証または昇格の段まで
/// 進むことの回帰ガードも兼ねる（#537）。
/// 開発環境のビルド出力は通常 root 所有・他者書き込み不可の経路にないため `PERMISSION_DENIED` で止まる。
/// root で実行した場合や経路が全て root 所有の場合は、検証を通って `elevate` が昇格手段が無いとして拒否する。
#[test]
fn sup14_task1719_untrusted_install_fails_closed_with_hostile_env() {
    let o = run(
        &["start", "--root", "/var/lib/fandhe-container", "c1"],
        &[("LD_PRELOAD", "/tmp/evil.so"), ("PATH", "/tmp/bin")],
    );
    let (code, msg) = failed(&o);
    assert_eq!(o.stdout.iter().filter(|&&b| b == b'\n').count(), 1);
    assert_eq!(
        o.code,
        i32::from(exit_code_for(ErrorCode::PermissionDenied).get())
    );
    assert_eq!(code, ErrorCode::PermissionDenied, "{msg}");
    let trust = msg.starts_with("directory ")
        && (msg.contains(" is owned by uid ") || msg.contains(" is writable by group or other"));
    let file = msg.contains(" is owned by uid ") || msg.contains(" is writable by group or other");
    let elevation = msg.starts_with("privilege elevation failed: ");
    assert!(trust || file || elevation, "unexpected message: {msg}");
    assert!(
        o.stderr.contains("\"code\":\"PERMISSION_DENIED\""),
        "{}",
        o.stderr
    );
}
