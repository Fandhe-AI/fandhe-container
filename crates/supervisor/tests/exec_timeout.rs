//! exec の全体上限時間（worker プロセス隔離）の結合試験（REPAIR-5・REPAIR-12・SUP-6・TASK-163.4・#503）。
//!
//! `run_command` は `setns`・cgroup join・制限の再適用などの割り込めない段を worker プロセスへ隔離し、親が
//! 全体の期限で待つ。ここでは各段が固まった状況を模した `work`（永久に眠る・panic する・エラーを返す）を
//! `run_in_worker_for_test` に渡し、期限内に構造化エラーが返ること・worker が回収されることを具体値で照合する。
//! root・実コンテナは不要で、既定のテスト集合で実行する。
//!
//! fork は呼び出しプロセスが単一スレッドであることを要求するため、libtest（マルチスレッド）ではなく
//! `harness = false` の単一スレッド `main` で動かす。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_timeout: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::time::{Duration, Instant};

    use fandhe_container_core::traits::{ErrorCode, TraitError};
    use fandhe_container_supervisor::exec::{ExecOutcome, run_in_worker_for_test};

    pub fn run() {
        hung_step_times_out_within_deadline();
        failing_step_error_is_returned_as_is();
        panicking_worker_is_reported_as_internal();
        println!("exec_timeout: all scenarios passed");
    }

    /// REPAIR-5・SUP-6: 準備・参加・再適用のどの段が固まっても、期限 + 猶予内に `Timeout` で返り、
    /// worker は `SIGKILL` で回収される（親は固まらない）。
    fn hung_step_times_out_within_deadline() {
        let start = Instant::now();
        let err = run_in_worker_for_test(
            Duration::from_millis(500),
            Duration::from_millis(500),
            || -> Result<ExecOutcome, TraitError> {
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            },
        )
        .unwrap_err();
        let elapsed = start.elapsed();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(err.message(), "exec timed out; the exec worker was killed");
        assert!(
            elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(5),
            "elapsed {elapsed:?}"
        );
    }

    /// worker が返したエラーは `code` / `message` のまま親へ届く（改行は空白へ置換される）。
    fn failing_step_error_is_returned_as_is() {
        let err = run_in_worker_for_test(
            Duration::from_secs(10),
            Duration::from_secs(10),
            || -> Result<ExecOutcome, TraitError> {
                Err(TraitError::new(
                    ErrorCode::PermissionDenied,
                    "exec stage SetNs: denied\nsecond line",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), "exec stage SetNs: denied second line");
    }

    /// worker が panic で終わったら、結果なしの異常終了として `Internal`（成功を装わない）。
    fn panicking_worker_is_reported_as_internal() {
        let err = run_in_worker_for_test(
            Duration::from_secs(10),
            Duration::from_secs(10),
            || -> Result<ExecOutcome, TraitError> { panic!("stub step panicked") },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert!(
            err.message()
                .starts_with("exec stage Spawn: the exec worker ended abnormally"),
            "{}",
            err.message()
        );
    }
}
