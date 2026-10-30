//! UDS クライアント（[`fandhe_container_io::UdsClientConnection`]）の結合試験
//! （IO-1・PLUG-12・REPAIR-5・P1-3・#3165）。
//!
//! 実際の [`fandhe_container_io::UdsServer`] と UDS で接続し、期限つき connect・
//! 接続先 uid の照合・応答系フレームだけを受理する受信フィルタ・受信上限・
//! 期限切れ・分割（`SplitTransport`）を確かめる。別ユーザーの実サーバーへの接続拒否
//! （root が要る。F14）は実機前提・人間担当で、ここでは扱わない（uid 照合そのものは
//! `UdsServerPolicy::exact_uid` の不一致と、`src/uds_client.rs` の `UnixStream::pair()` の
//! 単体試験で CI でも確かめる）。

// 残骸・PID 再利用と衝突しない排他作成（REPAIR-12・#3435）。
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use fandhe_container_io::{
        AckReceipt, AppendFileSink, BatchConfig, Frame, FrameKind, FrameReceiver, FrameSender,
        InFlightLimit, IoErrorCode, IoTimeout, NoopSendObserver, NoopServerObserver,
        PipelineClient, ReceiveLimits, SinkOpenMode, SplitTransport, UdsClientConnection,
        UdsConnection, UdsServer, UdsServerPolicy, WritebackTimeouts, serve_connection,
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            Self(super::exclusive_dir::create("fcio-uc").expect("temp dir"))
        }
        fn socket_path(&self) -> PathBuf {
            self.0.join("s.sock")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn secs(n: u64) -> IoTimeout {
        IoTimeout::new(Duration::from_secs(n)).expect("valid timeout")
    }

    fn millis(n: u64) -> IoTimeout {
        IoTimeout::new(Duration::from_millis(n)).expect("valid timeout")
    }

    fn client(path: &std::path::Path) -> UdsClientConnection<NoopServerObserver> {
        UdsClientConnection::connect(
            path,
            secs(5),
            UdsServerPolicy::same_effective_uid(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("client must connect")
    }

    /// サーバー側で 1 接続を受け付け、`f` を実行して結果を返すスレッド。
    /// 結果はチャネルで受け、待ちには期限を付ける（REPAIR-5）。
    fn serve_once<T: Send + 'static>(
        dir: &TempDir,
        f: impl FnOnce(UdsConnection<NoopServerObserver>) -> T + Send + 'static,
    ) -> mpsc::Receiver<T> {
        let mut server = UdsServer::bind(
            &dir.socket_path(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let conn = server.accept(secs(10), NoopServerObserver).expect("accept");
            let _ = tx.send(f(conn));
            drop(server);
        });
        rx
    }

    fn finish<T>(rx: mpsc::Receiver<T>) -> T {
        rx.recv_timeout(Duration::from_secs(15))
            .expect("server thread must finish in time")
    }

    fn ack_frame(kind: FrameKind, id: u64) -> Frame {
        Frame::new(kind, id.to_le_bytes().to_vec()).expect("ack frame")
    }

    fn write_frame(id: u64, body: &[u8]) -> Frame {
        let mut payload = id.to_le_bytes().to_vec();
        payload.extend_from_slice(body);
        Frame::new(FrameKind::Write, payload).expect("write frame")
    }

    /// IO-1・#3165: UDS サーバーに接続し、Write を送って Ack を受け取れる。
    #[test]
    fn io1_uds_client_roundtrip_with_uds_server() {
        let dir = TempDir::new();
        let rx = serve_once(&dir, |mut conn| {
            let got = conn.recv_frame(secs(5)).expect("server recv");
            conn.send_frame(&ack_frame(FrameKind::Ack, 7), secs(5))
                .expect("server send");
            got.kind()
        });
        let mut c = client(&dir.socket_path());
        c.send_frame(&write_frame(7, b"hello"), secs(5))
            .expect("send");
        let ack = c.recv_frame(secs(5)).expect("recv ack");
        assert_eq!(ack.kind(), FrameKind::Ack);
        assert_eq!(finish(rx), FrameKind::Write);
    }

    /// IO-1・#3165: `PipelineClient` を UDS クライアントの上で動かし、`serve_connection` の
    /// 本番の write-back と Ack / FlushAck の往復ができる。
    #[test]
    fn io1_uds_client_drives_pipeline_client_with_serve_connection() {
        let dir = TempDir::new();
        let out_dir = dir.0.clone();
        let rx = serve_once(&dir, move |mut conn| {
            let mut sink =
                AppendFileSink::open_in(&out_dir, "out.bin", SinkOpenMode::CreateOrTruncate)
                    .expect("sink");
            let report = serve_connection(
                &mut conn,
                BatchConfig::default(),
                &mut sink,
                WritebackTimeouts {
                    recv: secs(5),
                    send: secs(5),
                },
            );
            report.stats.acks_sent
        });
        let c = client(&dir.socket_path());
        let mut pc =
            PipelineClient::new(c, InFlightLimit::new(8).expect("limit"), NoopSendObserver);
        pc.send(FrameKind::Write, b"abc", secs(5))
            .expect("send write");
        // write-back はバッチが満ちるか Flush が来るまで Ack を返さないため、先に Flush を送る。
        pc.flush(secs(5)).expect("flush");
        match pc.recv_ack(secs(5)).expect("ack") {
            AckReceipt::Write(_) => {}
            other => panic!("expected a write ack, got {other:?}"),
        }
        match pc.recv_ack(secs(5)).expect("flush ack") {
            AckReceipt::Flush(_) => {}
            other => panic!("expected a flush ack, got {other:?}"),
        }
        drop(pc);
        assert_eq!(finish(rx), 1);
    }

    /// 自プロセスの実効 uid（自分が作ったディレクトリの所有者から求める）。
    fn euid() -> u32 {
        let d = TempDir::new();
        std::fs::metadata(&d.0).expect("meta").uid()
    }

    /// PLUG-12・#3165: 期待 uid が違う policy では、接続前のパス検査（ソケットの所有者）で
    /// `InvalidArgument` になり、サーバーは接続を受けない。
    #[test]
    fn plug12_uds_client_rejects_policy_with_different_uid() {
        let dir = TempDir::new();
        let mut server = UdsServer::bind(
            &dir.socket_path(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind");
        let wrong = UdsServerPolicy::exact_uid(euid().wrapping_add(1)).expect("policy");
        let err = UdsClientConnection::connect(
            &dir.socket_path(),
            secs(5),
            wrong,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("uid mismatch must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        let accepted = server.accept(millis(300), NoopServerObserver);
        assert_eq!(
            accepted
                .expect_err("no connection reached the server")
                .code(),
            IoErrorCode::Timeout
        );
    }

    /// IO-1・#3165: サーバーが 11 B の Nack を送ると、クライアントはフレームとして受理する。
    #[test]
    fn io1_uds_client_accepts_nack_frame() {
        let dir = TempDir::new();
        let rx = serve_once(&dir, |mut conn| {
            let mut payload = 3u64.to_le_bytes().to_vec();
            payload.push(1);
            payload.extend_from_slice(&0u16.to_le_bytes());
            let nack = Frame::new(FrameKind::Nack, payload).expect("nack");
            conn.send_frame(&nack, secs(5)).expect("send nack");
            let _ = conn.recv_frame(millis(500));
        });
        let mut c = client(&dir.socket_path());
        let f = c.recv_frame(secs(5)).expect("nack accepted");
        assert_eq!(f.kind(), FrameKind::Nack);
        drop(c);
        finish(rx);
    }

    /// IO-1・P1-3・#3165: サーバーが要求系（Write）を送ると `InvalidArgument` で拒否し、
    /// 以後は `Unavailable`（poison）。
    #[test]
    fn io1_uds_client_rejects_request_frame_and_poisons() {
        let dir = TempDir::new();
        let rx = serve_once(&dir, |mut conn| {
            conn.send_frame(&write_frame(1, b"x"), secs(5))
                .expect("send");
            let _ = conn.recv_frame(millis(500));
        });
        let mut c = client(&dir.socket_path());
        let err = c.recv_frame(secs(5)).expect_err("request frame rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        let err = c.recv_frame(secs(1)).expect_err("poisoned");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
        drop(c);
        finish(rx);
    }

    /// IO-1・#3165: 申告長 9 B の Ack（本来は 8 B）を、本体を読む前に拒否する。
    #[test]
    fn io1_uds_client_rejects_oversized_ack_before_body_read() {
        let dir = TempDir::new();
        let rx = serve_once(&dir, |mut conn| {
            let frame = Frame::new(FrameKind::Ack, vec![0u8; 9]).expect("frame");
            conn.send_frame(&frame, secs(5)).expect("send");
            let _ = conn.recv_frame(millis(500));
        });
        let mut c = client(&dir.socket_path());
        let err = c.recv_frame(secs(5)).expect_err("oversized ack rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        drop(c);
        finish(rx);
    }

    /// REPAIR-5・#3165: サーバーが応答しないと `Timeout` で戻る。
    #[test]
    fn repair5_uds_client_recv_times_out_on_silent_server() {
        let dir = TempDir::new();
        let rx = serve_once(&dir, |mut conn| {
            let _ = conn.recv_frame(secs(3));
        });
        let mut c = client(&dir.socket_path());
        let started = Instant::now();
        let err = c.recv_frame(millis(200)).expect_err("timeout");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(started.elapsed() < Duration::from_secs(3));
        drop(c);
        finish(rx);
    }

    /// IO-1・#1118・#3165: `SplitTransport` で分けた送信側・受信側で送受信できる。
    #[test]
    fn io1_uds_client_split_halves_roundtrip() {
        let dir = TempDir::new();
        let rx = serve_once(&dir, |mut conn| {
            let _ = conn.recv_frame(secs(5)).expect("server recv");
            conn.send_frame(&ack_frame(FrameKind::Ack, 9), secs(5))
                .expect("server send");
        });
        let c = client(&dir.socket_path());
        let (mut tx, mut rx_half) = c.split().expect("split");
        tx.send_frame(&write_frame(9, b"z"), secs(5)).expect("send");
        let f = rx_half.recv_frame(secs(5)).expect("recv");
        assert_eq!(f.kind(), FrameKind::Ack);
        drop(tx);
        finish(rx);
    }

    /// IO-1・REPAIR-5・#3165: 存在しないソケットは `Unavailable`。
    #[test]
    fn io1_uds_client_missing_socket_is_unavailable() {
        let dir = TempDir::new();
        let err = UdsClientConnection::connect(
            &dir.socket_path(),
            secs(1),
            UdsServerPolicy::same_effective_uid(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("no server");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported {
    use std::time::Duration;

    use fandhe_container_io::{
        IoErrorCode, IoTimeout, NoopServerObserver, ReceiveLimits, UdsClientConnection,
        UdsServerPolicy,
    };

    /// REPAIR-3・#3165: UDS 非対応の OS では `connect` が `Unimplemented`。
    #[test]
    fn repair3_uds_client_is_unimplemented_on_unsupported_os() {
        let err = UdsClientConnection::connect(
            std::path::Path::new("C:\\none"),
            IoTimeout::new(Duration::from_secs(1)).expect("timeout"),
            UdsServerPolicy::same_effective_uid(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("unsupported");
        assert_eq!(err.code(), IoErrorCode::Unimplemented);
    }
}
