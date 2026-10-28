//! supervisor の bin の `netns-holder` 振り分けと、holder の起動の失敗・期限・回収の非特権結合試験
//! （NET-9・CORE-1・REPAIR-5・#3198。`docs/design/rootless-network.md` 12.2・12.9・12.10）。
//!
//! 自身の実行ファイルを holder として再実行する（`/proc/self/exe` が試験バイナリになるため、第 1 引数
//! `netns-holder` なら `run_netns_holder_main`）ので `harness = false`。root も user namespace も要らない
//! （自分自身の namespace を渡すと holder の `setns` が `EINVAL` になる前提の負の場面だけを使う）。
//! 参加の成功・fd・メモリ・supervisor の異常終了は `netns_holder_launch_userns`（`--ignored`）が担う。
//! 応答しない・READY の前に終わる holder は試験専用モード（`netns-holder-stall` / `netns-holder-exit`）で作る。
//! 待ちはすべて期限つき（REPAIR-5）。Linux のみ。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("netns_holder_launch: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os();
    let _exe = args.next();
    match args.next() {
        Some(a) if a == fandhe_container_net::netns_holder::NETNS_HOLDER_SUBCOMMAND => {
            fandhe_container_net::netns_holder::run_netns_holder_main(args)
        }
        Some(a) if a == "netns-holder-stall" => loop {
            // STOP も EOF も読まずに眠り続ける（SIGKILL でだけ終わる）。
            std::thread::sleep(std::time::Duration::from_secs(60));
        },
        Some(a) if a == "netns-holder-exit" => std::process::ExitCode::from(3),
        Some(a) if a == "netns-holder-exit-after-recv" => {
            // namespace メッセージ（stdin のソケット）を 1 回受けてから終わる。
            // 送信側の `send_namespaces` が EPIPE にならない順序を保証する（REPAIR-12）。
            use std::io::Read;
            let mut buf = [0u8; 4096];
            let _ = std::io::stdin().read(&mut buf);
            std::process::ExitCode::from(3)
        }
        _ => {
            linux::run();
            std::process::ExitCode::SUCCESS
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::os::fd::OwnedFd;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::traits::ErrorCode;
    use fandhe_container_net::netns_holder::{
        NetnsHolderFds, READY_TIMEOUT, REAP_TIMEOUT, STOP_GRACE,
    };
    use fandhe_container_supervisor::netns_holder::{
        StopPath, spawn_netns_holder, spawn_netns_holder_unready_for_test,
        spawn_netns_holder_with_args_for_test,
    };

    const OK_LINE: &str =
        "netns_holder_launch: dispatch, spawn failures, deadlines and reaping passed (NET-9)";

    fn own_fds() -> NetnsHolderFds {
        let open = |n: &str| OwnedFd::from(File::open(format!("/proc/self/ns/{n}")).expect(n));
        NetnsHolderFds::new(open("user"), open("net")).expect("distinct own namespaces")
    }

    /// 自プロセスの子の pid 一覧（`/proc/*/stat` の ppid。zombie も含む）。
    fn children_of_self() -> Vec<u32> {
        let me = std::process::id();
        let mut out = Vec::new();
        for e in std::fs::read_dir("/proc").expect("read /proc").flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            // "pid (comm) S ppid ..." — comm は括弧を含み得るため最後の ')' の後ろを読む。
            let ppid = stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_whitespace().nth(1))
                .and_then(|p| p.parse::<u32>().ok());
            if ppid == Some(me) {
                out.push(pid);
            }
        }
        out
    }

    fn assert_no_children(what: &str) {
        let kids = children_of_self();
        assert!(kids.is_empty(), "{what}: leftover children {kids:?}");
    }

    pub fn run() {
        bin_dispatch();
        production_spawn_failure_is_reaped();
        spawn_from_non_main_thread_is_refused();
        exhausted_deadline_does_not_spawn();
        stalled_holder_times_out_and_is_reaped();
        holder_exiting_before_ready_is_reported();
        stop_escalates_to_sigkill();
        println!("{OK_LINE}");
    }

    /// supervisor の bin が `netns-holder` を `run_main` より前に holder へ振り分ける（stdout に start の結果が出ない）。
    fn bin_dispatch() {
        let bin = env!("CARGO_BIN_EXE_fandhe-container-supervisor");
        let out = Command::new(bin)
            .arg("netns-holder")
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .expect("run supervisor bin");
        assert_eq!(
            out.status.code(),
            Some(1),
            "holder rejects a non-socket stdin"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            "error code=FAILED_PRECONDITION message=stdin is not a seqpacket socket\n"
        );
        assert!(
            out.stdout.is_empty(),
            "stdout must stay empty: {:?}",
            out.stdout
        );

        let out = Command::new(bin)
            .args(["netns-holder", "extra"])
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .expect("run supervisor bin with an extra argument");
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            "error code=INVALID_ARGUMENT message=unexpected argument (the argv is fixed)\n"
        );
        assert!(out.stdout.is_empty());
    }

    /// 本番の spawn: 自分の user namespace への `setns` は `EINVAL` で、holder が `FailedPrecondition` を返す。回収済みで残らない。
    fn production_spawn_failure_is_reaped() {
        let started = Instant::now();
        let e = spawn_netns_holder(own_fds(), Instant::now() + Duration::from_secs(10))
            .expect_err("joining the own user namespace must fail");
        assert_eq!(e.code(), ErrorCode::FailedPrecondition, "{e:?}");
        assert!(!e.unreaped);
        assert!(
            e.holder_stderr.contains("error code=FAILED_PRECONDITION"),
            "stderr material: {:?}",
            e.holder_stderr
        );
        assert!(
            started.elapsed() < READY_TIMEOUT,
            "took {:?}",
            started.elapsed()
        );
        assert_no_children("production spawn failure");
    }

    /// main スレッドでなければ拒否し、プロセスを起動しない。
    fn spawn_from_non_main_thread_is_refused() {
        let handle = std::thread::spawn(|| {
            spawn_netns_holder(own_fds(), Instant::now() + Duration::from_secs(10))
                .err()
                .map(|e| (e.code(), e.message().to_owned()))
        });
        let (code, message) = handle.join().expect("thread").expect("must be refused");
        assert_eq!(code, ErrorCode::FailedPrecondition);
        assert!(message.contains("main thread"), "{message}");
        assert_no_children("non-main thread");
    }

    /// 残りが 0 の期限は起動しない。
    fn exhausted_deadline_does_not_spawn() {
        let e = spawn_netns_holder(own_fds(), Instant::now()).expect_err("no time left");
        assert_eq!(e.code(), ErrorCode::Timeout);
        assert_no_children("exhausted deadline");
    }

    /// READY を返さない holder は `READY_TIMEOUT` で `Timeout` になり、kill されて回収される。
    fn stalled_holder_times_out_and_is_reaped() {
        let started = Instant::now();
        let e = spawn_netns_holder_with_args_for_test(
            own_fds(),
            Instant::now() + Duration::from_secs(30),
            &["netns-holder-stall"],
        )
        .expect_err("a silent holder must time out");
        let elapsed = started.elapsed();
        assert_eq!(e.code(), ErrorCode::Timeout, "{e:?}");
        assert!(!e.unreaped);
        assert!(
            elapsed >= READY_TIMEOUT - Duration::from_millis(100)
                && elapsed < READY_TIMEOUT + REAP_TIMEOUT + Duration::from_secs(2),
            "elapsed {elapsed:?}"
        );
        assert_no_children("stalled holder");

        // 全体の残りが READY_TIMEOUT より短ければ、その残りで待つ。
        let started = Instant::now();
        let e = spawn_netns_holder_with_args_for_test(
            own_fds(),
            Instant::now() + Duration::from_millis(300),
            &["netns-holder-stall"],
        )
        .expect_err("the remaining budget bounds the READY wait");
        assert_eq!(e.code(), ErrorCode::Timeout);
        assert!(started.elapsed() < READY_TIMEOUT, "{:?}", started.elapsed());
        assert_no_children("short budget");
    }

    /// READY の前に終わる holder は `FailedPrecondition`（EOF）で、回収される。
    fn holder_exiting_before_ready_is_reported() {
        let e = spawn_netns_holder_with_args_for_test(
            own_fds(),
            Instant::now() + Duration::from_secs(10),
            &["netns-holder-exit"],
        )
        .expect_err("holder exits before READY");
        // 受信しないまま閉じた端は、読み手に EOF（FailedPrecondition）か ECONNRESET（Internal）として見える。
        // どちらでも「READY を受けずに失敗し、holder は回収済み」であることを固定する。
        assert!(
            matches!(
                e.code(),
                ErrorCode::FailedPrecondition | ErrorCode::Internal
            ),
            "{e:?}"
        );
        assert!(!e.unreaped);
        assert_no_children("exit before READY");
    }

    /// STOP を無視する holder には `STOP_GRACE` の後に SIGKILL し、回収する（段階を上げる経路）。
    fn stop_escalates_to_sigkill() {
        let mut p = spawn_netns_holder_unready_for_test(
            own_fds(),
            Instant::now() + Duration::from_secs(10),
            &["netns-holder-stall"],
        )
        .expect("spawn a stalled holder without waiting for READY");
        assert!(p.pid() > 0);
        assert!(p.try_exit().expect("poll").is_none(), "holder is alive");
        let out = p.stop();
        assert_eq!(out.path, StopPath::Killed);
        assert!(out.unreaped.is_none());
        let exit = out.exit.expect("reaped");
        assert_eq!(exit.signal, Some(9), "{exit:?}");
        assert_eq!(exit.code, None);
        assert!(
            out.elapsed >= STOP_GRACE
                && out.elapsed < STOP_GRACE + REAP_TIMEOUT + Duration::from_secs(2),
            "elapsed {:?}",
            out.elapsed
        );
        assert_no_children("stop escalation");

        // Drop も回収する。
        let p = spawn_netns_holder_unready_for_test(
            own_fds(),
            Instant::now() + Duration::from_secs(10),
            &["netns-holder-stall"],
        )
        .expect("spawn");
        drop(p);
        assert_no_children("drop");

        // 終了を観測したら try_exit が回収して材料を返す。
        let mut p = spawn_netns_holder_unready_for_test(
            own_fds(),
            Instant::now() + Duration::from_secs(10),
            &["netns-holder-exit-after-recv"],
        )
        .expect("spawn");
        let deadline = Instant::now() + Duration::from_secs(10);
        let exit = loop {
            if let Some(x) = p.try_exit().expect("poll") {
                break x;
            }
            assert!(Instant::now() < deadline, "holder exit was not observed");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(exit.code, Some(3));
        assert_eq!(exit.signal, None);
        let out = p.stop();
        assert_eq!(out.path, StopPath::Stopped);
        assert!(out.exit.is_none(), "already reaped by try_exit");
        assert_no_children("try_exit");
    }
}
