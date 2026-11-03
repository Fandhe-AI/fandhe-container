//! plugin-cri の peer 認証の拒否が、実際の経路で監査の記録先 `<状態ルート>/@audit.log` へ届くことの結合試験
//! （SEC-4・PLUG-12・REPAIR-12・#2484）。
//!
//! 本番 `main.rs` の `serve` と同じ順序（スレッドを作る前に `ControlAuditRelay` を fork して記録先を確かめる →
//! listener を bind → ランタイム）で組み、accept → `SO_PEERCRED` → `SharedPeerAuthObserver` →
//! `PeerAuditForwarder` → relay の helper → `FileAuditSink` → ファイルの全経路を通して JSON Lines まで照合する。
//!
//! 期待 UID に自分の実効 UID と異なる値を渡し、自プロセスからの接続を別 UID 相当として拒否させる。接続元の資格情報は
//! カーネルの `SO_PEERCRED` の本物で、差し替えるのは期待値だけ（`UdsIncoming::with_expected_uid_for_test`。照合は省かない）。
//! 実機の別 UID の接続は `tests/integration.rs` の `#[ignore]` の試験（root）が担う。
//!
//! `ControlAuditRelay::spawn` は単一スレッドの呼び出し元を要求するため `harness = false` の単一スレッド `main` で動かす。
//! 待ちはすべて期限つき（REPAIR-5）。前提が満たせないときは skip せず非ゼロで終わる。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("peer_auth_audit_delivery: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::future::poll_fn;
    use std::io::Read as _;
    use std::os::unix::fs::DirBuilderExt as _;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{
        AuditSink, ControlAuditRelay, FileAuditSink, RECORD_WAIT_LIMIT,
    };
    use fandhe_container_plugin::UdsListener;
    use fandhe_container_plugin::grpc::UdsIncoming;
    use fandhe_container_plugin_cri::telemetry::{
        LineSink, PEER_AUDIT_QUEUE_CAPACITY, PeerAuditForwarder, SharedPeerAuthObserver,
    };
    use tonic::codegen::tokio_stream::Stream;

    /// 拒否させる接続の数。
    const REJECTED: usize = 3;
    /// 記録の到達を待つ余裕（relay の最悪待ちに足す）。
    const POLL_MARGIN: Duration = Duration::from_secs(5);

    /// 0700 の排他作成で作る一時ディレクトリ（drop で削除）。
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            for attempt in 0..16u32 {
                let path = std::env::temp_dir()
                    .join(format!("fc-pad-{}-{nanos}-{attempt}", std::process::id()));
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

    /// `@audit.log` を期限つきでポーリングし、`want` 行そろったら（または期限で）返す。
    fn wait_for_audit_lines(root: &std::path::Path, want: usize) -> Vec<String> {
        let log = root.join("@audit.log");
        let deadline = Instant::now() + RECORD_WAIT_LIMIT + POLL_MARGIN;
        loop {
            let lines: Vec<String> = std::fs::read_to_string(&log)
                .map(|t| t.lines().map(str::to_owned).collect())
                .unwrap_or_default();
            if lines.len() >= want || Instant::now() >= deadline {
                return lines;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// 実効 UID。`/proc/self` の所有者から取る（`sys` を持たない試験で unsafe を増やさない）。
    fn effective_uid() -> u32 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self")
            .expect("stat /proc/self")
            .uid()
    }

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

    pub fn run() {
        let root = TempRoot::new();
        // 本番 main.rs と同じ順序: スレッドを作る前に relay を fork し、記録先を確かめる。
        let relay = FileAuditSink::open_in_state_root(Some(root.0.clone()))
            .and_then(ControlAuditRelay::spawn)
            .and_then(|relay| relay.probe().map(|()| relay))
            .expect("spawn the audit relay while single-threaded");
        let sink: Arc<dyn AuditSink> = Arc::new(relay);

        let socket = root.0.join("cri.sock");
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
        let (observer, stderr_buf) = SharedPeerAuthObserver::new();
        let observer = observer.with_audit(Arc::clone(&forwarder));
        let euid = effective_uid();

        // 受付は rt の内側で作る（reactor へ登録するため）。接続は backlog に積まれるので、先に全部張る。
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
            // 正規の接続が無いので受付は Pending のまま残る。期限で打ち切り、その間に全拒否が処理される。
            let polled = tokio::time::timeout(
                Duration::from_secs(3),
                poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx)),
            )
            .await;
            assert!(polled.is_err(), "no connection may be accepted");
            clients
        });

        // 拒否された接続は 1 バイトも受け取らずに切断される。
        // set_read_timeout は使わない: macOS では相手が閉じた socket への setsockopt が EINVAL に
        // なるため（#2711。本試験は Linux 限定だが crates/plugin の試験と方式を揃える）。
        // setsockopt を伴わない set_nonblocking と、全 client 共有の期限つきループで待つ。
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
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
                                std::time::Instant::now() < deadline,
                                "no EOF from the rejecting server within the deadline"
                            );
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        _ => panic!("unexpected read error: {e:?}"),
                    },
                }
            };
            assert_eq!(n, 0, "a rejected peer must not receive any byte");
        }

        forwarder.wait_idle(Duration::from_secs(10));
        let lines = wait_for_audit_lines(&root.0, REJECTED);
        assert_eq!(lines.len(), REJECTED, "audit lines: {lines:?}");
        let socket_json = format!("\"path\":\"{}\"", socket.display());
        for line in &lines {
            assert!(line.contains("\"layer\":\"plugin_peer\""), "layer: {line}");
            assert!(
                line.contains("\"reason\":\"plugin_peer_uid_mismatch\""),
                "reason: {line}"
            );
            assert!(line.contains(&socket_json), "path: {line}");
            assert!(line.contains("\"container_id\":null"), "id: {line}");
            assert!(!line.contains("uid\":"), "no uid value: {line}");
        }
        assert_eq!(forwarder.dropped(), 0);

        // 既存の可観測性（stderr 向けの JSON Lines）にも同じ件数が積まれている。
        let stderr_lines = stderr_buf
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain_lines();
        assert_eq!(stderr_lines.len(), REJECTED, "{stderr_lines:?}");
        assert!(
            stderr_lines
                .iter()
                .all(|l| l.contains("\"event\":\"plugin_peer_auth\"")
                    && l.contains("\"reason\":\"peer_uid_mismatch\"")),
            "{stderr_lines:?}"
        );
        // 通知行（欠落・書き込み失敗）は出ていない。
        notices.wait_idle(Duration::from_secs(2));
        assert!(
            notices_out
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "no audit notice expected"
        );
        println!(
            "peer_auth_audit_delivery: {REJECTED} peer uid mismatch records reached @audit.log"
        );
    }
}
