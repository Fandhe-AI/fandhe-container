//! exec の全体上限時間（worker プロセス隔離）の結合試験（REPAIR-5・REPAIR-12・SUP-6・TASK-163.4・#503）。
//!
//! `run_command` は `setns`・cgroup join・制限の再適用などの割り込めない段を worker プロセスへ隔離し、親が
//! 全体の期限で待つ。ここでは各段が固まった状況を模した `work`（永久に眠る・panic する・エラーを返す）を
//! `run_in_worker_for_test` に渡し、期限内に構造化エラーが返ること・worker が回収されることを具体値で照合する。
//! あわせて、worker が `work` を実行する前に non-dumpable になっていること（SEC-1。稼働中コンテナの PID
//! namespace に入る子を、コンテナ側から procfs 経由で読める状態で作らない。CVE-2016-9962 型の対策）を、
//! worker 自身の `/proc/self/fd` の所有者で照合する。root・実コンテナは不要で、既定のテスト集合で実行する。
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
        worker_is_non_dumpable_before_work_runs();
        hung_step_times_out_within_deadline();
        failing_step_error_is_returned_as_is();
        panicking_worker_is_reported_as_internal();
        println!("exec_timeout: all scenarios passed");
    }

    /// 自プロセスの実効 uid（`/proc/self/status` の `Uid:` の 2 列目）。
    fn effective_uid() -> u32 {
        std::fs::read_to_string("/proc/self/status")
            .expect("read own status")
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().nth(1)?.parse().ok())
            .expect("effective uid in own status")
    }

    /// 自プロセスの `/proc/self/fd` の所有者 uid。dumpable なプロセスでは自分の実効 uid、non-dumpable な
    /// プロセスではカーネルが root（自分の user namespace の uid 0）に付け替える（`task_dump_owner`）。
    fn proc_self_fd_owner() -> u32 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self/fd")
            .expect("stat own fd directory")
            .uid()
    }

    /// SUP-6・SEC-1・TASK-163.4（CVE-2016-9962 型の対策）: worker は `work` を実行する時点で non-dumpable。
    ///
    /// 対照として呼び出しプロセス（dumpable）の `/proc/self/fd` の所有者は自分の実効 uid で、worker の中では
    /// uid 0 になる。non-dumpable なプロセスの `/proc/<pid>/fd` 等は、対象の user namespace の
    /// `CAP_SYS_PTRACE` を持たないプロセス（コンテナ内の root を含む）から開けない。worker の起動は呼び出し
    /// プロセスの dumpable を変えない。root で実行した場合は対照と同じ値（0）になり区別できないが、照合する
    /// 値は同じ（非 root の CI で区別される）。
    fn worker_is_non_dumpable_before_work_runs() {
        let euid = effective_uid();
        assert_eq!(proc_self_fd_owner(), euid, "the caller must be dumpable");
        let err = run_in_worker_for_test(
            Duration::from_secs(10),
            Duration::from_secs(10),
            || -> Result<ExecOutcome, TraitError> {
                Err(TraitError::new(
                    ErrorCode::Unavailable,
                    format!("proc-self-fd-owner={}", proc_self_fd_owner()),
                ))
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert_eq!(err.message(), "proc-self-fd-owner=0");
        assert_eq!(proc_self_fd_owner(), euid, "the caller must stay dumpable");
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
