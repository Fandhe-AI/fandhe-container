//! exec の全体上限時間（worker プロセス隔離）の結合試験（REPAIR-5・REPAIR-12・SUP-6・TASK-163.4・#503）。
//!
//! 本番の入口 `run_command_with_pidfd`（と試験専用の `run_command`）は `setns`・cgroup join・制限の再適用などの割り込めない段を worker プロセスへ隔離し、親が
//! 全体の期限で待つ。ここでは各段が固まった状況を模した `work`（永久に眠る・panic する・エラーを返す）を
//! `run_in_worker_for_test` に渡し、期限内に構造化エラーが返ること・worker が回収されることを具体値で照合する。
//! あわせて、worker が `work` を実行する前に non-dumpable になっていること（SEC-1。稼働中コンテナの PID
//! namespace に入る子を、コンテナ側から procfs 経由で読める状態で作らない。CVE-2016-9962 型の対策）を、
//! worker 自身の `/proc/self/fd` の所有者で照合する。さらに、worker が期限超過で強制終了されたとき、worker が
//! 起動していた子（コマンド相当）も親の死亡シグナルで停止すること（REPAIR-5。孤児を残さない）を、入れ子の
//! worker で照合する。root・実コンテナは不要で、既定のテスト集合で実行する。
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
        killed_worker_takes_its_child_down();
        failing_step_error_is_returned_as_is();
        panicking_worker_is_reported_as_internal();
        child_cgroup_cleanup_runs_once_on_every_path();
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
            || Ok(()),
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
            || Ok(()),
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

    /// `/proc/<pid>/stat` の `(状態, 開始時刻)`。プロセスが無ければ `None`。開始時刻は pid の再利用と区別する
    /// ために使う（`comm` は括弧を含み得るため、最後の `)` より後ろを読む）。
    fn proc_state_and_start(pid: u32) -> Option<(String, String)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = stat.get(stat.rfind(')')? + 1..)?;
        let mut fields = rest.split_whitespace();
        let state = fields.next()?.to_owned();
        // 状態（3 番目）の後、開始時刻は 22 番目のフィールド。
        let start = fields.nth(18)?.to_owned();
        Some((state, start))
    }

    /// SUP-6・REPAIR-5・TASK-163.4: worker が期限超過で `SIGKILL` されると、worker が起動していた子も停止する。
    ///
    /// `run_command` では worker の子が稼働中コンテナ内のコマンドにあたる。ここでは worker（外側）の中で
    /// もう 1 段 worker（内側。コマンド相当）を起動し、内側が自分の pid と開始時刻を書いて眠り続ける状況を作る。
    /// 外側は内側の終了を待ち続けるため期限を過ぎ、呼び出しプロセスが外側を `SIGKILL` して `Timeout` を返す。
    /// 内側は親（外側）の死亡シグナルで終了していなければならない（孤児として動き続けない）。内側は失敗時に
    /// 残り続けないよう、自分でも 60 秒で終わる。
    fn killed_worker_takes_its_child_down() {
        let record = std::env::temp_dir().join(format!(
            "fandhe-exec-timeout-child-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        let record_tmp = record.with_extension("tmp");
        // 外側の期限は、内側が起動して記録を書き終えるのに十分な長さにする（負荷の高い CI でも揺れない値）。
        let err = run_in_worker_for_test(
            Duration::from_secs(3),
            Duration::from_millis(300),
            || Ok(()),
            || -> Result<ExecOutcome, TraitError> {
                run_in_worker_for_test(
                    Duration::from_secs(600),
                    Duration::from_secs(1),
                    || Ok(()),
                    || -> Result<ExecOutcome, TraitError> {
                        let pid = std::process::id();
                        let start = proc_state_and_start(pid).map_or_else(String::new, |s| s.1);
                        let _ = std::fs::write(&record_tmp, format!("{pid} {start}"));
                        let _ = std::fs::rename(&record_tmp, &record);
                        let deadline = Instant::now() + Duration::from_secs(60);
                        while Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(TraitError::new(ErrorCode::Internal, "inner child survived"))
                    },
                )
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(err.message(), "exec timed out; the exec worker was killed");
        let text = std::fs::read_to_string(&record).expect("the inner child must have started");
        let _ = std::fs::remove_file(&record);
        let (pid, start) = text.split_once(' ').expect("pid and start time");
        let pid: u32 = pid.parse().expect("inner child pid");
        assert!(!start.is_empty(), "inner child start time must be recorded");
        // 内側は、終了済み（エントリなし・ゾンビ）か、同じ pid が別プロセスに再利用されている（開始時刻が違う）
        // かのどちらかになる。親の死亡シグナルは非同期に届くため、短い期限つきで待つ。
        let gone = |pid: u32| match proc_state_and_start(pid) {
            None => true,
            Some((state, now)) => state == "Z" || state == "X" || now != start,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !gone(pid) {
            assert!(
                Instant::now() < deadline,
                "the worker's child (pid {pid}) is still running after the worker was killed"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// worker が返したエラーは `code` / `message` のまま親へ届く（改行は空白へ置換される）。
    fn failing_step_error_is_returned_as_is() {
        let err = run_in_worker_for_test(
            Duration::from_secs(10),
            Duration::from_secs(10),
            || Ok(()),
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
            || Ok(()),
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

    /// SUP-6・REPAIR-5・TASK-163 追補（#1466）: worker を fork した後は、期限切れ・エラー返却・異常終了（panic）の
    /// どの経路でも、呼び出し側の exec 用子 cgroup の後始末がちょうど 1 回実行される。後始末の失敗は元のエラーへ
    /// 併記される。
    fn child_cgroup_cleanup_runs_once_on_every_path() {
        let runs = std::cell::Cell::new(0u32);
        let count = || {
            runs.set(runs.get() + 1);
            Ok(())
        };
        let err = run_in_worker_for_test(
            Duration::from_millis(300),
            Duration::from_millis(300),
            count,
            || -> Result<ExecOutcome, TraitError> {
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(runs.get(), 1, "timeout path");

        let err = run_in_worker_for_test(
            Duration::from_secs(10),
            Duration::from_secs(10),
            || {
                runs.set(runs.get() + 1);
                Ok(())
            },
            || -> Result<ExecOutcome, TraitError> { panic!("stub step panicked") },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(runs.get(), 2, "abnormal worker exit path");

        let err = run_in_worker_for_test(
            Duration::from_secs(10),
            Duration::from_secs(10),
            || Err(TraitError::new(ErrorCode::Timeout, "still populated")),
            || -> Result<ExecOutcome, TraitError> {
                Err(TraitError::new(ErrorCode::PermissionDenied, "denied"))
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(
            err.message(),
            "denied; cleanup also failed: still populated"
        );
    }
}
