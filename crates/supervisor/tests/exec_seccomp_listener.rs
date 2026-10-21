//! exec の worker が seccomp の listener を親へ渡す経路の結合試験（SEC-4・SUP-6・#2385。`docs/design/audit-delivery.md`）。
//!
//! 本番の `run_command_with_pidfd` と同じ worker・受け渡し（`ListenerPolicy::Required`）を、試験専用の入口
//! `run_in_worker_with_listener_for_test` で任意の `work` から通す。worker の中では実カーネルで `NEW_LISTENER` 付きの
//! filter を載せ、listener を `SCM_RIGHTS` で親へ送り、親は検証して ACK を返す。親は worker の終了を待つ **前** に
//! 受信すること（相互待ちにならないこと）と、受け渡しの失敗（拒否・不着・期限切れ・ACK 無しの成功）が fail-closed に
//! なることを具体値で照合する。root・実コンテナは不要で、既定のテスト集合で実行する。
//!
//! 前提: 呼び出しプロセスの外側の filter が listener を既に持たないこと（持つ環境では `EBUSY` になる）。満たさない
//! 環境は skip せず失敗させる（`AGENTS.md`「実機前提でない試験」の注意）。
//!
//! fork は単一スレッドの呼び出し元を要求するため、libtest ではなく `harness = false` の単一スレッド `main` で動かす。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_seccomp_listener: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::cell::Cell;
    use std::time::{Duration, Instant};

    use fandhe_container_core::traits::{ErrorCode, TraitError};
    use fandhe_container_supervisor::exec::{
        ExecListenerHandover, apply_seccomp_listener_for_test, hand_over_non_listener_for_test,
        run_in_worker_with_listener_for_test,
    };

    pub fn run() {
        real_listener_is_handed_over_and_verified();
        non_listener_fd_is_rejected_and_worker_reaped();
        worker_failure_before_seccomp_is_returned_as_is();
        worker_success_without_handover_is_rejected();
        silent_worker_times_out_and_is_reaped();
        println!("exec_seccomp_listener: all scenarios passed");
    }

    /// 後始末（子 cgroup の削除に相当）の呼び出し回数を数える。
    fn counted(counter: &Cell<u32>) -> impl FnOnce() -> Result<(), TraitError> + '_ {
        move || {
            counter.set(counter.get() + 1);
            Ok(())
        }
    }

    /// worker が実 listener を作って渡すと、親は検証して ACK を返し、結果は `Verified`。
    fn real_listener_is_handed_over_and_verified() {
        let cleanups = Cell::new(0);
        let outcome = run_in_worker_with_listener_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            counted(&cleanups),
            apply_seccomp_listener_for_test,
        )
        .unwrap_or_else(|e| {
            panic!(
                "handover failed: {:?} {} (the caller's outer seccomp filter must not own a listener)",
                e.code(),
                e.message()
            )
        });
        assert_eq!(outcome.seccomp_listener, ExecListenerHandover::Verified);
        assert_eq!(cleanups.get(), 1);
    }

    /// listener ではない fd は親が拒否し（段 `Seccomp`）、worker は待たずに止められて回収され、後始末はちょうど 1 回。
    fn non_listener_fd_is_rejected_and_worker_reaped() {
        let cleanups = Cell::new(0);
        let started = Instant::now();
        let err = run_in_worker_with_listener_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            counted(&cleanups),
            |sender| match hand_over_non_listener_for_test(sender) {
                // 親が拒否して閉じると、worker の ACK 待ちは HUP で終わり `Err` になる（期待どおり）。
                Err(_) => Ok(()),
                Ok(()) => Err(TraitError::new(
                    ErrorCode::Internal,
                    "the parent acknowledged a non-listener fd",
                )),
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(
            err.message(),
            "exec stage Seccomp: the received fd is not a seccomp notification fd"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(cleanups.get(), 1);
    }

    /// worker が seccomp の前に失敗したときは、その `code` / `message` が listener 側の失敗に隠されずにそのまま届く。
    fn worker_failure_before_seccomp_is_returned_as_is() {
        let cleanups = Cell::new(0);
        let err = run_in_worker_with_listener_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            counted(&cleanups),
            |sender| {
                drop(sender);
                Err(TraitError::new(
                    ErrorCode::PermissionDenied,
                    "exec stage Validate: refused before seccomp",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PermissionDenied);
        assert_eq!(err.message(), "exec stage Validate: refused before seccomp");
        assert_eq!(cleanups.get(), 1);
    }

    /// worker が何も渡さずに成功を返しても、ACK 無しで進んだものとして `Internal`（fail-closed）で拒否される。
    fn worker_success_without_handover_is_rejected() {
        let cleanups = Cell::new(0);
        let err = run_in_worker_with_listener_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            counted(&cleanups),
            |sender| {
                drop(sender);
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(
            err.message(),
            "exec stage Seccomp: the exec worker finished without handing over the seccomp listener"
        );
        assert_eq!(cleanups.get(), 1);
    }

    /// 何も渡さず眠る worker は、期限で `Timeout` になり、待たずに止められて回収される。
    fn silent_worker_times_out_and_is_reaped() {
        let cleanups = Cell::new(0);
        let started = Instant::now();
        let err = run_in_worker_with_listener_for_test(
            Duration::from_secs(1),
            Duration::from_secs(1),
            counted(&cleanups),
            |sender| {
                let _keep = sender;
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "exec stage Seccomp: the seccomp listener was not delivered in time"
        );
        assert!(started.elapsed() < Duration::from_secs(8));
        assert_eq!(cleanups.get(), 1);
    }
}
