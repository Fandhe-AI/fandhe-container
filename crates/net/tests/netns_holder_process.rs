//! netns holder の起動・フレーム検証・期限・孤児化の非特権結合試験（NET-9・CORE-6・SEC-5・REPAIR-2・REPAIR-5・#3197。Linux のみ）。
//!
//! 自身の実行ファイルを holder として再実行する（第 1 引数 `netns-holder` なら `run_netns_holder_main`）ため
//! `harness = false`。root も user namespace も要らない（負の場面は `setns` が失敗する前提の入力だけを使う）。
//! 参加の成功・capability の破棄・`/proc/<holder>/ns/*` の読み取りは非特権 user namespace を要するため
//! `netns_holder_userns`（`--ignored`）が担う。待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で
//! 期限を切る（REPAIR-5）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("netns_holder_process: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os();
    let _exe = args.next();
    match args.next() {
        Some(a) if a == fandhe_container_net::netns_holder::NETNS_HOLDER_SUBCOMMAND => {
            fandhe_container_net::netns_holder::run_netns_holder_main(args)
        }
        Some(a) if a == "--pdeath-mid" => linux::pdeath_mid(),
        _ => {
            linux::run();
            std::process::ExitCode::SUCCESS
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::io::Read as _;
    use std::os::fd::{AsFd as _, OwnedFd};
    use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::NetErrorCode;
    use fandhe_container_net::netns_holder::{
        HolderFrame, HolderMessage, NetnsHolderChannel, NsIdentity, READY_TIMEOUT, SentNamespaces,
    };

    const OK_LINE: &str =
        "netns_holder_process: frame validation, deadlines and orphan handling passed (NET-9)";

    fn limit() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn exe() -> std::path::PathBuf {
        std::env::current_exe().expect("current_exe")
    }

    /// holder を `netns-holder` の再入で起動する（`env_clear`・stdout は null・stderr は pipe。supervisor の契約どおり）。
    fn spawn_holder(stdin: Stdio, extra: &[&str]) -> Child {
        Command::new(exe())
            .arg("netns-holder")
            .args(extra)
            .env_clear()
            .stdin(stdin)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn holder")
    }

    /// 子の終了を期限つきで待ち、終了状態と stderr 全体を返す。
    fn finish(mut child: Child, within: Duration) -> (ExitStatus, String, Duration) {
        let mut stderr = child.stderr.take().expect("stderr piped");
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            let _ = tx.send(s);
        });
        let started = Instant::now();
        let status = loop {
            if let Some(st) = child.try_wait().expect("try_wait") {
                break st;
            }
            if started.elapsed() > within {
                let _ = child.kill();
                let _ = child.wait();
                panic!("holder did not exit within {within:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let elapsed = started.elapsed();
        let text = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        (status, text, elapsed)
    }

    fn stderr_line(code: &str, message: &str) -> String {
        format!("error code={code} message={message}\n")
    }

    fn any_sent() -> SentNamespaces {
        SentNamespaces::for_test(NsIdentity {
            dev: 0,
            net_ino: 0,
            user_ino: 0,
        })
    }

    /// 生のバイト列と fd を送り、holder が `code` の Error を返して非 0 終了し、stderr が固定の 1 行だけであることを照合する。
    fn expect_rejected(name: &str, bytes: &[u8], fds: &[&File], code: NetErrorCode, message: &str) {
        let (ch, child_end) = NetnsHolderChannel::pair().expect("pair");
        let child = spawn_holder(Stdio::from(child_end), &[]);
        let borrowed: Vec<_> = fds.iter().map(|f| f.as_fd()).collect();
        ch.send_raw_for_test(bytes, &borrowed).expect("send raw");
        let err = ch
            .wait_ready(&any_sent(), READY_TIMEOUT)
            .expect_err("holder must report an error");
        assert_eq!(err.code(), code, "{name}: error frame code");
        let (status, text, _) = finish(child, limit());
        assert_eq!(status.code(), Some(1), "{name}: exit code");
        assert_eq!(text, stderr_line(code.as_str(), message), "{name}: stderr");
    }

    fn open_ns(name: &str) -> File {
        File::open(format!("/proc/self/ns/{name}")).expect("open own ns")
    }

    pub fn run() {
        let namespaces = HolderFrame::encode(HolderMessage::Namespaces);
        let (user, net) = (open_ns("user"), open_ns("net"));
        let devnull = File::open("/dev/null").expect("/dev/null");
        let devzero = File::open("/dev/zero").expect("/dev/zero");

        // fd の本数（1 本・3 本）。制御バッファは 2 本ちょうどで、3 本目はカーネルが閉じて MSG_CTRUNC になる。
        expect_rejected(
            "one fd",
            namespaces.as_bytes(),
            &[&user],
            NetErrorCode::InvalidArgument,
            "exactly two namespace descriptors are required",
        );
        expect_rejected(
            "three fds",
            namespaces.as_bytes(),
            &[&user, &net, &devnull],
            NetErrorCode::InvalidArgument,
            "the supervisor message was truncated or carried extra descriptors",
        );
        // フレームの不正（magic・kind）。
        let mut bad_magic = *namespaces.as_bytes();
        bad_magic[0] = b'X';
        expect_rejected(
            "bad magic",
            &bad_magic,
            &[&user, &net],
            NetErrorCode::InvalidArgument,
            "the supervisor message is not a valid frame",
        );
        expect_rejected(
            "wrong kind",
            HolderFrame::encode(HolderMessage::Stop).as_bytes(),
            &[&user, &net],
            NetErrorCode::InvalidArgument,
            "the supervisor message has an unexpected kind",
        );
        // 同じ inode の fd 2 本・namespace でない fd（setns が EINVAL）・自分自身の user namespace・順の入れ替え。
        expect_rejected(
            "same file twice",
            namespaces.as_bytes(),
            &[&devnull, &devnull],
            NetErrorCode::FailedPrecondition,
            "the namespace descriptors are not distinct namespaces on one filesystem",
        );
        expect_rejected(
            "not namespaces",
            namespaces.as_bytes(),
            &[&devnull, &devzero],
            NetErrorCode::FailedPrecondition,
            "cannot join the user namespace",
        );
        expect_rejected(
            "own user namespace",
            namespaces.as_bytes(),
            &[&user, &net],
            NetErrorCode::FailedPrecondition,
            "cannot join the user namespace",
        );
        expect_rejected(
            "swapped order",
            namespaces.as_bytes(),
            &[&net, &user],
            NetErrorCode::FailedPrecondition,
            "cannot join the user namespace",
        );

        // supervisor 側: 範囲外の timeout・holder が READY の前に消えた場合・期限切れ。
        let (ch, child_end) = NetnsHolderChannel::pair().expect("pair");
        for bad in [Duration::ZERO, READY_TIMEOUT + Duration::from_millis(1)] {
            let e = ch.wait_ready(&any_sent(), bad).expect_err("range");
            assert_eq!(e.code(), NetErrorCode::InvalidArgument, "timeout {bad:?}");
        }
        let started = Instant::now();
        let e = ch
            .wait_ready(&any_sent(), Duration::from_millis(300))
            .expect_err("silent holder");
        assert_eq!(e.code(), NetErrorCode::Timeout);
        assert!(started.elapsed() >= Duration::from_millis(250));
        drop(child_end);
        let e = ch
            .wait_ready(&any_sent(), READY_TIMEOUT)
            .expect_err("eof before READY");
        assert_eq!(e.code(), NetErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "the holder exited before READY");

        // 何も送らない: holder は 2 秒の期限で Timeout を出して終了する（REPAIR-5）。
        let (ch, child_end) = NetnsHolderChannel::pair().expect("pair");
        let child = spawn_holder(Stdio::from(child_end), &[]);
        let (status, text, elapsed) = finish(child, limit());
        assert_eq!(status.code(), Some(1));
        assert_eq!(
            text,
            stderr_line("TIMEOUT", "timed out waiting for the supervisor")
        );
        assert!(
            elapsed >= Duration::from_millis(1500) && elapsed < Duration::from_secs(8),
            "holder deadline elapsed {elapsed:?}"
        );
        drop(ch);

        // 引数が空でない: 2 で終了。stdin がソケットでない: FailedPrecondition。
        let (ch, child_end) = NetnsHolderChannel::pair().expect("pair");
        let (status, text, _) = finish(spawn_holder(Stdio::from(child_end), &["--x"]), limit());
        assert_eq!(status.code(), Some(2));
        assert_eq!(
            text,
            stderr_line(
                "INVALID_ARGUMENT",
                "unexpected argument (the argv is fixed)"
            )
        );
        drop(ch);
        let (status, text, _) = finish(spawn_holder(Stdio::null(), &[]), limit());
        assert_eq!(status.code(), Some(1));
        assert_eq!(
            text,
            stderr_line("FAILED_PRECONDITION", "stdin is not a seqpacket socket")
        );

        inherited_fds_closed();
        pdeath();
        println!("{OK_LINE}");
    }

    /// 継承した fd（3 以上）は holder の起動直後に閉じられ、`/proc/<holder>/fd` には 0〜2 だけが残る
    /// （SEC-1・NET-9）。シェルが CLOEXEC なしの fd 3 を開いたまま holder を exec する。
    fn inherited_fds_closed() {
        let (ch, child_end) = NetnsHolderChannel::pair().expect("pair");
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("exec 3</dev/null 4</dev/null; echo ready >&2; exec \"$0\" netns-holder")
            .arg(exe())
            .env_clear()
            .stdin(Stdio::from(child_end))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sh");
        // fd 3・4 を開いた後に出る合図を待ってから観測する（開く前の 0〜2 だけの状態を誤って合格にしない）。
        let mut stderr = child.stderr.take().expect("stderr");
        let mut ready = [0u8; 6];
        stderr.read_exact(&mut ready).expect("ready marker");
        assert_eq!(&ready, b"ready\n");
        let dir = format!("/proc/{}/fd", child.id());
        let deadline = Instant::now() + limit();
        // exec 後の holder が fd を閉じ終えるまで観測を繰り返し、0〜2 だけになることを確かめる。
        let observed = loop {
            let mut names: Vec<String> = std::fs::read_dir(&dir)
                .map(|d| {
                    d.filter_map(|e| e.ok())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            names.sort();
            if names == ["0", "1", "2"] || Instant::now() >= deadline {
                break names;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let _ = child.kill();
        let _ = child.wait();
        drop(ch);
        assert_eq!(
            observed,
            ["0", "1", "2"],
            "holder kept inherited descriptors"
        );
    }

    /// 親（socketpair の作成者）が死んだら、端が別プロセスに残っていても holder は EOF を待たずに消える
    /// （PDEATHSIG または親の不一致の検出。REPAIR-5・SUP-5）。2 秒の fd 待ちの期限（Timeout の行）より前に消えること。
    fn pdeath() {
        let mut mid = Command::new(exe())
            .arg("--pdeath-mid")
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mid");
        let mut stderr = mid.stderr.take().expect("stderr");
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            let _ = tx.send(s);
        });
        let started = Instant::now();
        let text = rx
            .recv_timeout(Duration::from_millis(1500))
            .expect("holder must die before its own 2 s deadline");
        assert!(
            !text.contains("TIMEOUT"),
            "holder outlived its parent until its own deadline: {text:?}"
        );
        assert!(started.elapsed() < Duration::from_millis(1500));
        let _ = mid.wait();
    }

    /// `--pdeath-mid`: socketpair を作って holder を起動し、端を別プロセス（sleep）に持たせて即座に終了する。
    // 子を回収せずに終了して孤児にするのがこの再入の目的（親の死を作る）。
    #[allow(clippy::zombie_processes)]
    pub fn pdeath_mid() -> ExitCode {
        let (ch, child_end) = NetnsHolderChannel::pair().expect("pair");
        let _holder = Command::new(exe())
            .arg("netns-holder")
            .env_clear()
            .stdin(Stdio::from(child_end))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn holder");
        let keep: OwnedFd = ch.into_fd_for_test();
        let _keeper = Command::new("sleep")
            .arg("5")
            .stdin(Stdio::from(keep))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn keeper");
        ExitCode::SUCCESS
    }
}
