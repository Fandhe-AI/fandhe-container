//! exec の対象を、起動時から保持する pidfd で固定する経路の結合試験（SUP-6・SEC-1・CORE-1・TASK-163 追補・#1461）。
//!
//! 起動ハンドル（core の `ContainerChild`。fork 直後に pidfd を開いて保持する）の pidfd を、supervisor の
//! `identify_pid1_with_pidfd` / `run_command_with_pidfd` へ渡し、記録 pid との一致を同一性の根拠にすることを
//! 具体値で照合する。記録 pid が別の値なら違反 `exec_target_pidfd_mismatch` で拒否され、一致すれば次段
//! （入れ子の PID 1 の検査）へ進む（実コンテナではないため、そこで拒否されるのが期待値）。root・実コンテナは
//! 不要で、既定のテスト集合で実行する。実コンテナへの成功経路は実機前提の `tests/exec.rs` の範囲（#1453）。
//!
//! fork は呼び出しプロセスが単一スレッドであることを要求するため、libtest ではなく `harness = false` の
//! 単一スレッド `main` で動かす。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_launch_pidfd: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::num::NonZeroU32;
    use std::time::Duration;

    use fandhe_container_core::exec::{ContainerChild, spawn_exec_worker};
    use fandhe_container_core::traits::{
        CgroupPlacement, CgroupScope, ContainerId, ContainerStatus, ErrorCode, StateRecord,
        StateRevision,
    };
    use fandhe_container_supervisor::exec::{
        ExecRequest, identify_pid1_with_pidfd, run_command_with_pidfd,
    };

    pub fn run() {
        let child = spawn_exec_worker(|| {
            std::thread::sleep(Duration::from_secs(60));
            0
        })
        .expect("spawn the launch stand-in");
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scenarios(&child)));
        // 子は必ず kill・回収する（REPAIR-5）。
        let _ = child.kill_and_reap(Duration::from_secs(10));
        if let Err(p) = outcome {
            std::panic::resume_unwind(p);
        }
        println!("exec_launch_pidfd: all scenarios passed");
    }

    fn record(pid: u32, with_cgroup: bool) -> StateRecord {
        let id = ContainerId::new("c1").unwrap();
        let rec = StateRecord::new(
            ContainerStatus::running(id, NonZeroU32::new(pid)),
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .unwrap();
        if with_cgroup {
            rec.with_cgroup(CgroupPlacement::new(
                CgroupScope::new("/user.slice/x.scope").unwrap(),
                StateRevision::from_raw(7),
            ))
        } else {
            rec
        }
    }

    fn scenarios(child: &ContainerChild) {
        let pidfd = child
            .pidfd()
            .expect("pidfd は Linux 5.3 以降が前提（pidfd 非対応環境では失敗させる）");
        mismatched_record_pid_is_rejected(child, pidfd);
        matching_record_pid_reaches_nested_pid1_check(child, pidfd);
        run_command_with_inherited_pidfd(child, pidfd);
        missing_cgroup_placement_is_rejected(child, pidfd);
    }

    /// 記録 pid が pidfd の指すプロセスと違えば、`exec_target_pidfd_mismatch`（SUP-6）で拒否する。
    fn mismatched_record_pid_is_rejected(
        child: &ContainerChild,
        pidfd: std::os::fd::BorrowedFd<'_>,
    ) {
        let rec = record(child.pid() + 1, true);
        let err = identify_pid1_with_pidfd(&rec, pidfd).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "exec stage SetNs: the process held by the launch pidfd is not the recorded exec target \
             (violation: exec_target/exec_target_pidfd_mismatch, SUP-6)"
        );
    }

    /// 記録 pid が一致すれば pidfd の照合を通り、次段の入れ子の PID 1 の検査で拒否する（順序の証明）。
    fn matching_record_pid_reaches_nested_pid1_check(
        child: &ContainerChild,
        pidfd: std::os::fd::BorrowedFd<'_>,
    ) {
        let rec = record(child.pid(), true);
        let err = identify_pid1_with_pidfd(&rec, pidfd).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "exec stage SetNs: the exec target is not PID 1 of a directly nested PID namespace \
             (violation: exec_target/exec_target_not_nested_pid1, SUP-6)"
        );
    }

    /// worker が fork 継承した pidfd を使う通しの入口でも、同じ結果が構造化エラーのまま返る。
    fn run_command_with_inherited_pidfd(
        child: &ContainerChild,
        pidfd: std::os::fd::BorrowedFd<'_>,
    ) {
        let request = ExecRequest::new("/bin/true", ["true"]).unwrap();
        let rec = record(child.pid() + 1, true);
        let err =
            run_command_with_pidfd(&rec, pidfd, &request, Duration::from_secs(20)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert!(
            err.message()
                .contains("exec_target/exec_target_pidfd_mismatch, SUP-6"),
            "unexpected message: {}",
            err.message()
        );
        let rec = record(child.pid(), true);
        let err =
            run_command_with_pidfd(&rec, pidfd, &request, Duration::from_secs(20)).unwrap_err();
        assert!(
            err.message()
                .contains("exec_target/exec_target_not_nested_pid1, SUP-6"),
            "unexpected message: {}",
            err.message()
        );
    }

    /// cgroup 配置の記録がなければ、pidfd があっても拒否する（既存の入口と同じ）。
    fn missing_cgroup_placement_is_rejected(
        child: &ContainerChild,
        pidfd: std::os::fd::BorrowedFd<'_>,
    ) {
        let rec = record(child.pid(), false);
        let err = identify_pid1_with_pidfd(&rec, pidfd).unwrap_err();
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            err.message(),
            "container has no recorded cgroup placement; cannot verify pid1 identity"
        );
    }
}
