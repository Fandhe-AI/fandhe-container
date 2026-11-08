//! 要求元（plugin-cri）の異常終了を stream-exec の helper が検知して exec のプロセスを回収し、早く終わることの結合試験
//! （SUP-6・SEC-1・REPAIR-5・#4166。方式は `docs/design/cri-streaming-server.md`「要求元の異常終了の検知」）。
//!
//! 本番と同じ worker・listener の受け渡し・応答者と serve ループを、試験専用の入口
//! `run_in_worker_with_listener_cancel_for_test` で通し、取り消し判定は本番と同じ
//! `stream_exec::channel::requester_gone`（fd 0 の channel への `poll(timeout = 0)`）を使う。偽の要求元は channel の
//! 相手の端だけを持つ別プロセス（`/bin/sleep`）で、SIGKILL する・自然に終わる（接続が閉じる）の 2 通りを試す。
//! 照合する値は (1) 消滅から終了まで 2 秒以内・`Unavailable` と固定メッセージ・後始末 1 回、(2) worker のプロセスが残らない
//! （`/proc/<pid>/stat` の不在・ゾンビ・開始時刻の不一致）、(3) 要求元が開いたままなら長い期限でも誤検知しない、
//! (4) 判定が常に偽なら従来の期限と猶予で `Timeout`（期限・猶予を弱めない）。
//!
//! 範囲: コンテナ内のコマンド単位の不在（cgroup.kill での回収）は実コンテナが要るため、実機前提の試験（#4167）が担う。
//! ここでは worker（コマンドの親）の回収までを具体値で照合する。root・実コンテナは不要で、既定のテスト集合で実行する。
//!
//! fork は単一スレッドの呼び出し元を要求するため、libtest ではなく `harness = false` の単一スレッド `main` で動かす。

#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn main() {
    println!("exec_requester_cancel: Linux only, not applicable on this OS");
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
    use std::io::{BufRead as _, Write as _};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::traits::{ErrorCode, TraitError};
    use fandhe_container_supervisor::exec::{
        ExecListenerHandover, apply_seccomp_listener_for_test, open_socket_ids_for_test,
        run_in_worker_with_listener_cancel_for_test,
    };
    use fandhe_container_supervisor::stream_exec::channel::requester_gone;

    use super::reap;

    pub fn run() {
        sigkill_of_the_requester_cancels_within_2s();
        closing_the_channel_cancels_within_2s();
        open_requester_is_not_mistaken_for_gone();
        never_gone_still_ends_at_the_deadline_with_timeout();
        println!("exec_requester_cancel: all scenarios passed");
    }

    /// 偽の要求元: channel の相手の端だけを stdin に持つ別プロセス。戻す `UnixStream` は helper 側の端。
    /// `Command` は spawn の後に drop し、相手の端を試験プロセス（と、後で fork する worker）に残さない
    /// （残ると要求元が死んでも `POLLHUP` が立たない）。
    fn spawn_requester(sleep_arg: &str) -> (UnixStream, Child) {
        let (helper_end, peer) = UnixStream::pair().expect("socketpair");
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg(sleep_arg)
            .stdin(Stdio::from(OwnedFd::from(peer)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = cmd.spawn().expect("spawn the fake requester");
        drop(cmd);
        (helper_end, child)
    }

    /// worker 自身の `(pid, 開始時刻)` を試験側へ書く（listener の受け渡しより前。取り消しが早くても必ず記録される）。
    fn announce(writer: &std::io::PipeWriter) {
        let pid = std::process::id();
        let start = proc_state_and_start(pid).map_or_else(String::new, |s| s.1);
        let mut w = writer;
        w.write_all(format!("{pid} {start}\n").as_bytes())
            .expect("announce the worker");
    }

    fn read_announce(reader: std::io::PipeReader) -> (u32, String) {
        let mut line = String::new();
        std::io::BufReader::new(reader)
            .read_line(&mut line)
            .expect("read the announce line");
        let (pid, start) = line.trim().split_once(' ').expect("pid and start time");
        assert!(!start.is_empty(), "the worker start time must be recorded");
        (pid.parse().expect("worker pid"), start.to_owned())
    }

    fn proc_state_and_start(pid: u32) -> Option<(String, String)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = stat.get(stat.rfind(')')? + 1..)?;
        let mut fields = rest.split_whitespace();
        let state = fields.next()?.to_owned();
        let start = fields.nth(18)?.to_owned();
        Some((state, start))
    }

    /// worker が終了済み（エントリなし・ゾンビ）か、同じ pid が別プロセスに再利用されている（開始時刻が違う）ことを、
    /// 短い期限つきで確かめる。
    fn assert_worker_gone(pid: u32, start: &str) {
        let gone = |pid: u32| match proc_state_and_start(pid) {
            None => true,
            Some((state, now)) => state == "Z" || state == "X" || now != start,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !gone(pid) {
            assert!(
                Instant::now() < deadline,
                "worker {pid} must not survive the cancel"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn counted(counter: &Cell<u32>) -> impl FnOnce() -> Result<(), TraitError> + '_ {
        move || {
            counter.set(counter.get() + 1);
            Ok(())
        }
    }

    /// 要求元を SIGKILL する。開始から 300 ms 後の最初の判定で kill して回収し、その時刻を記録する。以後は本番と同じ判定。
    fn sigkill_of_the_requester_cancels_within_2s() {
        let (helper_end, requester) = spawn_requester("60");
        let requester = RefCell::new(requester);
        let (announce_r, announce_w) = std::io::pipe().expect("pipe");
        // worker は書かれない pipe の blocking read で待つ（filter の下で nanosleep が拒否されても即戻りしない）。
        let (block_r, block_w) = std::io::pipe().expect("pipe");
        let cleanups = Cell::new(0);
        let baseline = open_socket_ids_for_test().expect("list the open sockets");
        let begin = Instant::now();
        let killed_at = Cell::new(None::<Instant>);
        let cancel = || {
            if killed_at.get().is_none() && begin.elapsed() >= Duration::from_millis(300) {
                reap::reap(&mut requester.borrow_mut(), reap::reap_within())
                    .expect("reap the fake requester");
                killed_at.set(Some(Instant::now()));
            }
            requester_gone(&helper_end)
        };
        let err = run_in_worker_with_listener_cancel_for_test(
            Duration::from_secs(60),
            Duration::from_secs(10),
            counted(&cleanups),
            &cancel,
            |sender| {
                announce(&announce_w);
                apply_seccomp_listener_for_test(sender, &baseline)?;
                block_forever(&block_r)
            },
        )
        .expect_err("a cancelled exec must fail");
        let ended = Instant::now();
        drop(block_w);
        drop(announce_w);
        let killed = killed_at
            .get()
            .expect("the requester must have been killed");
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert_eq!(
            err.message(),
            "exec cancelled: the requester went away; the exec worker was killed"
        );
        let latency = ended.duration_since(killed);
        assert!(
            latency < Duration::from_secs(2),
            "cancel must finish within 2s of the requester dying, took {latency:?}"
        );
        assert!(
            ended.duration_since(begin) < Duration::from_secs(20),
            "far below the 60s exec deadline"
        );
        assert_eq!(cleanups.get(), 1);
        let (pid, start) = read_announce(announce_r);
        assert_worker_gone(pid, &start);
    }

    /// 要求元が自然に終わる（channel の端が閉じる）。要求元は 0.3 秒で終わる。
    fn closing_the_channel_cancels_within_2s() {
        let (helper_end, mut requester) = spawn_requester("0.3");
        let (announce_r, announce_w) = std::io::pipe().expect("pipe");
        let (block_r, block_w) = std::io::pipe().expect("pipe");
        let cleanups = Cell::new(0);
        let baseline = open_socket_ids_for_test().expect("list the open sockets");
        let begin = Instant::now();
        let cancel = || requester_gone(&helper_end);
        let err = run_in_worker_with_listener_cancel_for_test(
            Duration::from_secs(60),
            Duration::from_secs(10),
            counted(&cleanups),
            &cancel,
            |sender| {
                announce(&announce_w);
                apply_seccomp_listener_for_test(sender, &baseline)?;
                block_forever(&block_r)
            },
        )
        .expect_err("a cancelled exec must fail");
        let elapsed = begin.elapsed();
        drop(block_w);
        drop(announce_w);
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert_eq!(
            err.message(),
            "exec cancelled: the requester went away; the exec worker was killed"
        );
        // 要求元の終了（約 0.3 秒）に 2 秒を足した範囲。60 秒の期限より十分短い。
        assert!(elapsed < Duration::from_millis(2_300), "took {elapsed:?}");
        assert_eq!(cleanups.get(), 1);
        let (pid, start) = read_announce(announce_r);
        assert_worker_gone(pid, &start);
        reap::reap_or_report(&mut requester, reap::reap_within());
    }

    /// 要求元が開いたまま待つ間（期限 60 秒）は止まらない（誤検知しない）。worker は、親が 1.5 秒後に書く 1 バイトを
    /// 受けて自分で終わる。結果は見本の成功（取り消しの `Err` ではない）で、経過は 1.5 秒以上。
    fn open_requester_is_not_mistaken_for_gone() {
        let (helper_end, mut requester) = spawn_requester("60");
        let (gate_r, gate_w) = std::io::pipe().expect("pipe");
        let cleanups = Cell::new(0);
        let baseline = open_socket_ids_for_test().expect("list the open sockets");
        let begin = Instant::now();
        let opened = Cell::new(false);
        let checks = Cell::new(0u32);
        let cancel = || {
            let gone = requester_gone(&helper_end);
            assert!(!gone, "an open requester must never be reported gone");
            checks.set(checks.get() + 1);
            if !opened.get() && begin.elapsed() >= Duration::from_millis(1_500) {
                opened.set(true);
                (&gate_w).write_all(b"x").expect("open the gate");
            }
            gone
        };
        let outcome = run_in_worker_with_listener_cancel_for_test(
            Duration::from_secs(60),
            Duration::from_secs(10),
            counted(&cleanups),
            &cancel,
            |sender| {
                apply_seccomp_listener_for_test(sender, &baseline)?;
                wait_for_byte(&gate_r)
            },
        )
        .expect("an open requester must not cancel the exec");
        let elapsed = begin.elapsed();
        assert_eq!(outcome.seccomp_listener, ExecListenerHandover::Verified);
        assert!(
            elapsed >= Duration::from_millis(1_500) && elapsed < Duration::from_secs(20),
            "took {elapsed:?}"
        );
        assert!(
            checks.get() >= 5,
            "the cancel hook must be polled while waiting"
        );
        assert_eq!(cleanups.get(), 1);
        reap::reap_or_report(&mut requester, reap::reap_within());
    }

    /// 判定が常に偽（検知できない）でも、従来の期限（1 秒）と猶予（1 秒）で `Timeout` になる（期限・猶予を弱めない）。
    fn never_gone_still_ends_at_the_deadline_with_timeout() {
        let (block_r, block_w) = std::io::pipe().expect("pipe");
        let cleanups = Cell::new(0);
        let baseline = open_socket_ids_for_test().expect("list the open sockets");
        let begin = Instant::now();
        let cancel = || false;
        let err = run_in_worker_with_listener_cancel_for_test(
            Duration::from_secs(1),
            Duration::from_secs(1),
            counted(&cleanups),
            &cancel,
            |sender| {
                apply_seccomp_listener_for_test(sender, &baseline)?;
                block_forever(&block_r)
            },
        )
        .expect_err("the deadline must still end the exec");
        let elapsed = begin.elapsed();
        drop(block_w);
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(err.message(), "exec timed out; the exec worker was killed");
        assert!(
            elapsed >= Duration::from_millis(1_800) && elapsed < Duration::from_secs(8),
            "took {elapsed:?}"
        );
        assert_eq!(cleanups.get(), 1);
    }

    /// 書かれない pipe を blocking read で待ち続ける（親が SIGKILL するまで戻らない）。
    fn block_forever(reader: &std::io::PipeReader) -> Result<(), TraitError> {
        wait_for_byte(reader)?;
        Err(TraitError::new(
            ErrorCode::Internal,
            "the worker was not stopped",
        ))
    }

    fn wait_for_byte(reader: &std::io::PipeReader) -> Result<(), TraitError> {
        use std::io::Read as _;
        let mut byte = [0u8; 1];
        let mut r = reader;
        match r.read(&mut byte) {
            Ok(1) => Ok(()),
            _ => Err(TraitError::new(ErrorCode::Internal, "the gate read failed")),
        }
    }
}
