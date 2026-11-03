//! プロセスグループ宛ての SIGTERM の後も監査 helper が生き、ドレイン中の peer 認証の拒否が `@audit.log` に届くこと、
//! helper が本体の終了後に期限つきで終わること、登録したハンドラが exec した子へ継承されないことの結合試験
//! （SEC-4・PLUG-12・CRI-1・REPAIR-5・REPAIR-12・#3300）。
//!
//! 自分自身を再実行する 2 役の構成。親（試験のハーネス）は子を別のプロセスグループで起動し、子の helper が同じグループに
//! いることを確かめてから `kill -s TERM -- -<pgid>` でグループへ SIGTERM を送る（systemd の cgroup 全体宛てと同じく、
//! 本体と helper の両方に届く）。子は本番の `main.rs` と同じ組み立て（`audit_relay::open_audit_relay_in` → 停止シグナルの
//! 登録）を通し、**受信の後に** 拒否を発生させる（helper が先に死ぬ状況を決定的に再現する）。
//!
//! `ControlAuditRelay` の fork は単一スレッドの呼び出し元を要求するため `harness = false` の単一スレッド `main` で動かす。
//! 待ちはすべて期限つきで、前提が満たせないときは skip せず非ゼロで終わる。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("shutdown_audit_helper: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(target_os = "linux")]
mod linux {
    use std::future::poll_fn;
    use std::io::{BufRead as _, Read as _};
    use std::os::unix::fs::DirBuilderExt as _;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt as _;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditSink, RECORD_WAIT_LIMIT};
    use fandhe_container_plugin::UdsListener;
    use fandhe_container_plugin::grpc::UdsIncoming;
    use fandhe_container_plugin_cri::audit_relay::open_audit_relay_in;
    use fandhe_container_plugin_cri::shutdown::AUDIT_HELPER_LINGER_BOUND;
    use fandhe_container_plugin_cri::sys::{self, ShutdownSignal};
    use fandhe_container_plugin_cri::telemetry::{
        LineSink, PEER_AUDIT_QUEUE_CAPACITY, PeerAuditForwarder, SharedPeerAuthObserver,
    };
    use tonic::codegen::tokio_stream::Stream;

    const ROLE_ENV: &str = "FANDHE_CONTAINER_TEST_SHUTDOWN_ROLE";
    const ROOT_ENV: &str = "FANDHE_CONTAINER_TEST_SHUTDOWN_ROOT";
    /// ドレイン中に拒否させる接続の数。
    const REJECTED: usize = 3;
    /// 各待ちの基準の期限。
    const STEP_WAIT: Duration = Duration::from_secs(10);
    /// 子の終了を待つ上限（本体の停止の上限より十分長い）。
    const CHILD_EXIT_WAIT: Duration = Duration::from_secs(30);
    /// helper の終了を待つ上限に足す余裕。
    const LINGER_MARGIN: Duration = Duration::from_secs(2);
    /// `SigIgn` / `SigCgt` のマスク（シグナル番号 n はビット n-1）。
    const MASK_INT: u64 = 1 << (2 - 1);
    const MASK_TERM: u64 = 1 << (15 - 1);

    pub fn run() {
        match std::env::var(ROLE_ENV).as_deref() {
            Ok("child") => child(),
            _ => parent(),
        }
    }

    // ---- /proc の読み取り ----

    /// `/proc/<pid>/status` の `Sig*:` 行（16 進）。
    fn sig_mask(pid: u32, key: &str) -> Option<u64> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let line = text.lines().find(|l| l.starts_with(key))?;
        u64::from_str_radix(line.split_whitespace().nth(1)?, 16).ok()
    }

    /// `/proc/<pid>/stat` の `)` より後ろの欄（添字 0 が state = 第 3 欄）。
    fn stat_fields(pid: u32) -> Option<Vec<String>> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = text.get(text.rfind(')')? + 1..)?;
        Some(rest.split_whitespace().map(str::to_owned).collect())
    }

    /// プロセスが生きている（`/proc` があり、ゾンビでない）か。
    fn is_alive(pid: u32) -> bool {
        stat_fields(pid).is_some_and(|f| f.first().map(String::as_str) != Some("Z"))
    }

    fn deadline_loop(limit: Duration, what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + limit;
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            for attempt in 0..16u32 {
                let path = std::env::temp_dir()
                    .join(format!("fc-sah-{}-{nanos}-{attempt}", std::process::id()));
                match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self(path),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => panic!("create temp root: {e}"),
                }
            }
            panic!("could not create a unique temp root");
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // ---- 親の役 ----

    fn parent() {
        let root = TempRoot::new();
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .env(ROLE_ENV, "child")
            .env(ROOT_ENV, &root.0)
            // cargo・libtest を巻き込まないよう、別のプロセスグループにする。
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn child");
        let child_pid = child.id();
        let stdout = child.stdout.take().expect("child stdout");
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        let ready = rx
            .recv_timeout(STEP_WAIT)
            .expect("child did not report readiness in time");
        let helper_pid: u32 = ready
            .strip_prefix("ready helper_pid=")
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("unexpected ready line: {ready}"));

        let fields = stat_fields(helper_pid).expect("helper stat");
        // 第 5 欄 pgrp = 添字 2、第 22 欄 starttime = 添字 19。
        let helper_pgrp: u32 = fields
            .get(2)
            .and_then(|v| v.parse().ok())
            .expect("helper pgrp");
        let helper_start = fields.get(19).cloned().expect("helper starttime");
        assert_eq!(
            helper_pgrp, child_pid,
            "the helper must share the child's process group for the group signal to reach it"
        );

        // 期限なしの `status()` を避ける。スレッドを立てない `run_within` は単一スレッド前提を壊さない（#3409）。
        let mut kill = Command::new("kill");
        kill.args(["-s", "TERM", "--"]).arg(format!("-{child_pid}"));
        let status = crate::reap::run_within(&mut kill, crate::reap::reap_within())
            .unwrap_or_else(|e| panic!("group SIGTERM: {e}"));
        assert!(status.success(), "kill -s TERM to the group failed");

        let deadline = Instant::now() + CHILD_EXIT_WAIT;
        let exit = loop {
            if let Some(s) = child.try_wait().expect("try_wait") {
                break s;
            }
            if Instant::now() >= deadline {
                crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
                panic!("the child did not exit within {CHILD_EXIT_WAIT:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let exited_at = Instant::now();
        assert!(exit.success(), "child exit status: {exit:?}");
        // helper は子の stdout を継承しているため、helper が残る間は reader が EOF を受けない。join の前に
        // 本体の終了時点からの期限つきで helper の終了を確かめる（REPAIR-5。残存は join の無期限待ちにしない）。
        let bound = AUDIT_HELPER_LINGER_BOUND.max(RECORD_WAIT_LIMIT) + LINGER_MARGIN;
        deadline_loop(bound, "the audit helper to exit", || {
            match stat_fields(helper_pid) {
                None => true,
                Some(f) => {
                    f.first().map(String::as_str) == Some("Z")
                        || f.get(19).map(String::as_str) != Some(helper_start.as_str())
                }
            }
        });
        reader.join().expect("reader thread");
        let lines: Vec<String> = rx.try_iter().collect();
        let child_ok = format!(
            "shutdown_audit_helper child: {REJECTED} drain rejections queued after SIGTERM; helper alive until exit"
        );
        assert!(lines.contains(&child_ok), "child output: {lines:?}");

        // @audit.log にドレイン中の拒否がちょうど REJECTED 件ある。
        let log = std::fs::read_to_string(root.0.join("@audit.log")).expect("read @audit.log");
        let audit: Vec<&str> = log.lines().collect();
        assert_eq!(audit.len(), REJECTED, "audit lines: {audit:?}");
        let socket_json = format!("\"path\":\"{}\"", root.0.join("cri.sock").display());
        for line in &audit {
            assert!(line.contains("\"layer\":\"plugin_peer\""), "layer: {line}");
            assert!(
                line.contains("\"reason\":\"plugin_peer_uid_mismatch\""),
                "reason: {line}"
            );
            assert!(line.contains(&socket_json), "path: {line}");
            assert!(line.contains("\"container_id\":null"), "id: {line}");
            assert!(!line.contains("uid\":"), "no uid value: {line}");
        }

        println!(
            "shutdown_audit_helper: {REJECTED} drain rejections reached @audit.log after group SIGTERM; helper exited within bound ({} ms after the child)",
            exited_at.elapsed().as_millis()
        );
    }

    // ---- 子の役（本番 main.rs と同じ順序） ----

    /// 通知行の収集先。
    struct SharedBuf(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedBuf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn effective_uid() -> u32 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self")
            .expect("stat /proc/self")
            .uid()
    }

    fn child() {
        let root: PathBuf = std::env::var_os(ROOT_ENV).expect("root env").into();
        // 1. スレッドを作る前に relay を組む（本番の構築口）。
        let relay = open_audit_relay_in(Some(root.clone())).expect("open the audit relay");
        let helper_pid = relay.pid();
        // 2. 停止シグナルの登録。
        sys::install_shutdown_signals().expect("install shutdown signals");

        // 3. helper は停止シグナルを無視している。
        let ign = sig_mask(helper_pid, "SigIgn:").expect("helper SigIgn");
        assert_eq!(
            ign & (MASK_INT | MASK_TERM),
            MASK_INT | MASK_TERM,
            "helper SigIgn: {ign:#x}"
        );
        // 登録後に exec した子はハンドラを継承しない（捕捉は SIG_DFL に戻る）。
        let mut sleeper = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let sleeper_pid = sleeper.id();
        deadline_loop(STEP_WAIT, "sleep to exec", || {
            std::fs::read_to_string(format!("/proc/{sleeper_pid}/comm"))
                .is_ok_and(|c| c.trim() == "sleep")
        });
        let cgt = sig_mask(sleeper_pid, "SigCgt:").expect("sleep SigCgt");
        let sleeper_ign = sig_mask(sleeper_pid, "SigIgn:").expect("sleep SigIgn");
        crate::reap::reap(&mut sleeper, crate::reap::reap_within())
            .unwrap_or_else(|e| panic!("reap sleeper: {e}"));
        assert_eq!(
            cgt & (MASK_INT | MASK_TERM),
            0,
            "exec'd child SigCgt: {cgt:#x}"
        );
        assert_eq!(
            sleeper_ign & (MASK_INT | MASK_TERM),
            0,
            "exec'd child SigIgn: {sleeper_ign:#x}"
        );

        // 4. 受付側の部品（peer_auth_audit_delivery と同じ形）。
        let sink: Arc<dyn AuditSink> = relay;
        let socket = root.join("cri.sock");
        let listener = UdsListener::bind(&socket).expect("bind");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("runtime");
        let notices_out = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let notices = LineSink::spawn(Box::new(SharedBuf(Arc::clone(&notices_out))), 8);
        let forwarder = Arc::new(
            PeerAuditForwarder::spawn(sink, PEER_AUDIT_QUEUE_CAPACITY, notices.clone())
                .expect("forwarder thread"),
        );
        let (observer, _stderr_buf) = SharedPeerAuthObserver::new();
        let observer = observer.with_audit(Arc::clone(&forwarder));
        let euid = effective_uid();

        println!("ready helper_pid={helper_pid}");

        // 5. グループ宛ての SIGTERM を受けるまで待つ。
        deadline_loop(STEP_WAIT, "SIGTERM", || sys::received().is_some());
        assert_eq!(sys::received(), Some(ShutdownSignal::Term));
        // 受信の後も helper は生きている（修正前はここで死んでいる）。
        assert!(
            is_alive(helper_pid),
            "the audit helper died before the parent did"
        );

        // 6. 受信の後に拒否を起こす（ドレイン中の拒否の再現）。
        let clients: Vec<UnixStream> = rt.block_on(async {
            let mut incoming = UdsIncoming::with_expected_uid_for_test(
                listener,
                Box::new(observer),
                euid.wrapping_add(1),
            )
            .expect("incoming");
            let clients: Vec<UnixStream> = (0..REJECTED)
                .map(|_| UnixStream::connect(&socket).expect("connect"))
                .collect();
            let polled = tokio::time::timeout(
                Duration::from_secs(3),
                poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx)),
            )
            .await;
            assert!(polled.is_err(), "no connection may be accepted");
            clients
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        for mut client in clients {
            client.set_nonblocking(true).expect("nonblocking");
            let mut buf = [0u8; 16];
            let n = loop {
                match client.read(&mut buf) {
                    Ok(n) => break n,
                    Err(e) => match e.kind() {
                        std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe => break 0,
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {
                            assert!(
                                Instant::now() < deadline,
                                "no EOF from the rejecting server"
                            );
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        _ => panic!("unexpected read error: {e:?}"),
                    },
                }
            };
            assert_eq!(n, 0, "a rejected peer must not receive any byte");
        }
        forwarder.wait_idle(STEP_WAIT);
        assert_eq!(forwarder.dropped(), 0);
        notices.wait_idle(Duration::from_secs(2));
        assert!(
            notices_out
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "no audit notice expected"
        );
        assert!(
            is_alive(helper_pid),
            "the audit helper died during the drain"
        );
        println!(
            "shutdown_audit_helper child: {REJECTED} drain rejections queued after SIGTERM; helper alive until exit"
        );
        // relay を drop しない（drop は helper を SIGKILL するため）。本体の終了による EOF で helper が終わることを親が確かめる。
        std::process::exit(0);
    }
}
