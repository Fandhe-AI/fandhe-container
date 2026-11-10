//! tty の exec で worker が割り当てた pty の master を、親が受けてフックへ渡す経路の結合試験
//! （SUP-6・SEC-1・REPAIR-5・CRI-6・#4416）。
//!
//! 本番の `run_command_with_pidfd_output_notify` と同じ worker・listener・pty の受け渡しと応答者を、試験専用の入口
//! `run_in_worker_with_pty_for_test` で任意の `work` から通す。親は応答者を回す刻みの中で master を **待たずに**
//! 受け取り（`ExecPtyReceiver::try_receive`）、検証してフックへ 1 回だけ渡す。次を具体値で照合する。
//! - 正しい master: フックがちょうど 1 回呼ばれ、受けた master の端末サイズが worker の送った値で、結果は成功
//! - 送らずに成功: `Internal`（master を受け取らずにコマンドが終わったことになる。フックは 0 回）
//! - master でない fd: 拒否され（フックは 0 回）、worker は回収される
//! - フックが `Err`: その分類で終わり、worker は期限内に回収される
//!
//! fork は単一スレッドの呼び出し元を要求するため、libtest ではなく `harness = false` の単一スレッド `main` で動かす。
//! root・実コンテナは不要で、既定のテスト集合で実行する。

#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn main() {
    println!("exec_pty_handover: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    linux::run();
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::cell::{Cell, RefCell};
    use std::os::fd::AsFd as _;
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{WindowSize, open_host_pty_for_test};
    use fandhe_container_core::traits::{ErrorCode, TraitError};
    use fandhe_container_supervisor::exec::{
        ExecPtyEvent, apply_seccomp_listener_for_test, open_socket_ids_for_test,
        run_in_worker_with_pty_for_test,
    };

    pub fn run() {
        correct_master_reaches_the_hook_once();
        success_without_a_master_is_rejected();
        non_master_fd_is_rejected();
        hook_error_ends_with_its_code_and_reaps_the_worker();
        println!("exec_pty_handover: all scenarios passed");
    }

    fn baseline_sockets() -> Vec<String> {
        open_socket_ids_for_test().expect("list the open sockets")
    }

    /// 正しい master: フックが 1 回、worker の送った 24x80 を読め、結果は成功。後始末はちょうど 1 回。
    fn correct_master_reaches_the_hook_once() {
        let calls = Cell::new(0u32);
        let seen = RefCell::new(None);
        let cleanups = Cell::new(0u32);
        let baseline = baseline_sockets();
        let failed = RefCell::new(Vec::new());
        let on_pty = |event: ExecPtyEvent<'_>| {
            match event {
                ExecPtyEvent::Master(master) => {
                    calls.set(calls.get() + 1);
                    *seen.borrow_mut() = Some(master.window_size().expect("window size"));
                }
                ExecPtyEvent::Failed(e) => failed.borrow_mut().push(e.code()),
                _ => panic!("unexpected pty event"),
            }
            Ok(())
        };
        let outcome = run_in_worker_with_pty_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            || {
                cleanups.set(cleanups.get() + 1);
                Ok(())
            },
            &on_pty,
            |listener, pty| {
                let (master, _slave) = open_host_pty_for_test(WindowSize::new(24, 80))
                    .map_err(|e| TraitError::new(e.code, "open pty failed"))?;
                pty.hand_over(master)
                    .map_err(|e| TraitError::new(e.code, "hand over failed"))?;
                apply_seccomp_listener_for_test(listener, &baseline)
            },
        )
        .unwrap_or_else(|e| panic!("handover failed: {:?} {}", e.code(), e.message()));
        assert_eq!(outcome.command_pid.map(|p| p.get()), Some(4321));
        assert_eq!(calls.get(), 1, "the hook runs exactly once");
        assert!(failed.borrow().is_empty(), "no failure event on success");
        assert_eq!(*seen.borrow(), Some(WindowSize::new(24, 80)));
        assert_eq!(cleanups.get(), 1);
        println!("exec_pty_handover: scenario=correct_master hook=1 size=24x80 ok");
    }

    /// 送らずに成功: `Internal`・フックは 0 回。
    fn success_without_a_master_is_rejected() {
        let calls = Cell::new(0u32);
        let baseline = baseline_sockets();
        let failed = RefCell::new(Vec::new());
        let on_pty = |event: ExecPtyEvent<'_>| {
            match event {
                ExecPtyEvent::Master(_) => calls.set(calls.get() + 1),
                ExecPtyEvent::Failed(e) => failed.borrow_mut().push(e.code()),
                _ => panic!("unexpected pty event"),
            }
            Ok(())
        };
        let err = run_in_worker_with_pty_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            || Ok(()),
            &on_pty,
            |listener, pty| {
                drop(pty);
                apply_seccomp_listener_for_test(listener, &baseline)
            },
        )
        .expect_err("a success without the master must be rejected");
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(
            err.message(),
            "exec stage Spawn: the exec worker finished without handing over the pty master"
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(*failed.borrow(), vec![ErrorCode::Internal]);
        println!("exec_pty_handover: scenario=no_master internal rejected, hook=0 ok");
    }

    /// master でない fd（`/dev/null`）: 拒否され、フックは 0 回。
    fn non_master_fd_is_rejected() {
        let baseline = baseline_sockets();
        let calls = Cell::new(0u32);
        let failed = RefCell::new(Vec::new());
        let on_pty = |event: ExecPtyEvent<'_>| {
            match event {
                ExecPtyEvent::Master(_) => calls.set(calls.get() + 1),
                ExecPtyEvent::Failed(e) => failed.borrow_mut().push(e.code()),
                _ => panic!("unexpected pty event"),
            }
            Ok(())
        };
        let started = Instant::now();
        let err = run_in_worker_with_pty_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            || Ok(()),
            &on_pty,
            |listener, pty| {
                let null = std::fs::File::open("/dev/null").expect("open /dev/null");
                pty.hand_over_non_pty_for_test(null.as_fd())
                    .map_err(|e| TraitError::new(e.code, "send failed"))?;
                // 本番の順（listener の受け渡しの後に pty）ではなく試験の都合で pty → listener の順にしている。
                apply_seccomp_listener_for_test(listener, &baseline)?;
                // 親が拒否して worker を止めるまで待つ（止められなければ期限で終わる）。
                std::thread::sleep(Duration::from_secs(30));
                Ok(())
            },
        )
        .expect_err("a non-master fd must be rejected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(calls.get(), 0);
        assert_eq!(*failed.borrow(), vec![ErrorCode::InvalidArgument]);
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the worker must be stopped by the rejection, not by the deadline"
        );
        println!(
            "exec_pty_handover: scenario=non_master rejected with INVALID_ARGUMENT, hook=0 ok"
        );
    }

    /// フックが `Unavailable` を返す: その分類で終わり、worker は期限より前に回収される。
    fn hook_error_ends_with_its_code_and_reaps_the_worker() {
        let baseline = baseline_sockets();
        let started = Instant::now();
        let failed = Cell::new(0u32);
        let on_pty = |event: ExecPtyEvent<'_>| {
            if matches!(event, ExecPtyEvent::Failed(_)) {
                failed.set(failed.get() + 1);
            }
            Err(TraitError::new(ErrorCode::Unavailable, "hook failed"))
        };
        let err = run_in_worker_with_pty_for_test(
            Duration::from_secs(20),
            Duration::from_secs(10),
            || Ok(()),
            &on_pty,
            |listener, pty| {
                let (master, _slave) = open_host_pty_for_test(WindowSize::new(24, 80))
                    .map_err(|e| TraitError::new(e.code, "open pty failed"))?;
                pty.hand_over(master)
                    .map_err(|e| TraitError::new(e.code, "hand over failed"))?;
                apply_seccomp_listener_for_test(listener, &baseline)?;
                std::thread::sleep(Duration::from_secs(30));
                Ok(())
            },
        )
        .expect_err("a failing hook must fail the exec");
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert!(
            err.message().starts_with("hook failed"),
            "{}",
            err.message()
        );
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the worker must be stopped by the hook failure, not by the deadline"
        );
        assert_eq!(
            failed.get(),
            0,
            "a hook error must not be reported back as a failure"
        );
        println!("exec_pty_handover: scenario=hook_error UNAVAILABLE reaped in time ok");
    }
}
