//! ファイル操作モード（`serve_file_connection`）の UDS 経由の結合試験
//! （IO-1・IO-5・F3・F6〜F10。#3163）。
//!
//! [`fandhe_container_io::UdsServer`] が accept した実際の UDS 接続の上で
//! `serve_file_connection` を動かし、std の `UnixStream`（client 役）が手で組んだ
//! `Create` / `WriteFile` / `Close` / `Flush` フレームの往復を確かめる。Linux / macOS 限定
//! （`tests/writeback.rs` と同じ扱い）。他 OS では 0 件になる。

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use fandhe_container_io::{
        BatchConfig, FileServeLimits, Frame, FrameHeader, FrameKind, GuestFileCreator, IoErrorCode,
        IoTimeout, MaxOpenFiles, NackCode, NackReason, NoopServerObserver, ReceiveLimits,
        UdsServer, UnflushedLimit, WritebackTimeouts, decode_ack, decode_nack,
        serve_file_connection, serve_file_connection_with_limit,
    };

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = super::exclusive_dir::create("fcio-fs")
                .expect("must be able to create a temp dir for the socket and share root");
            Self { path }
        }

        fn socket_path(&self) -> PathBuf {
            self.path.join("s.sock")
        }

        fn share_root(&self) -> PathBuf {
            self.path.join("share")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn test_timeout() -> IoTimeout {
        IoTimeout::new(Duration::from_secs(5)).expect("5s must be a valid IoTimeout")
    }

    fn timeouts() -> WritebackTimeouts {
        WritebackTimeouts {
            recv: test_timeout(),
            send: test_timeout(),
        }
    }

    fn send(stream: &mut UnixStream, kind: FrameKind, payload: Vec<u8>) {
        let frame = Frame::new(kind, payload).expect("frame must construct");
        stream
            .write_all(&frame.encode())
            .expect("client write must succeed");
    }

    fn send_create(stream: &mut UnixStream, id: u64, path: &str) {
        let mut payload = id.to_le_bytes().to_vec();
        payload.extend_from_slice(&u16::try_from(path.len()).expect("len").to_le_bytes());
        payload.extend_from_slice(path.as_bytes());
        send(stream, FrameKind::Create, payload);
    }

    fn send_write_file(stream: &mut UnixStream, id: u64, handle: u64, body: &[u8]) {
        let mut payload = id.to_le_bytes().to_vec();
        payload.extend_from_slice(&handle.to_le_bytes());
        payload.extend_from_slice(body);
        send(stream, FrameKind::WriteFile, payload);
    }

    fn send_close(stream: &mut UnixStream, id: u64, handle: u64) {
        let mut payload = id.to_le_bytes().to_vec();
        payload.extend_from_slice(&handle.to_le_bytes());
        send(stream, FrameKind::Close, payload);
    }

    fn send_flush(stream: &mut UnixStream, id: u64) {
        send(stream, FrameKind::Flush, id.to_le_bytes().to_vec());
    }

    /// 1 フレームを受信する。読み取りには期限（接続側の `set_read_timeout`）がある。
    fn try_recv_frame(stream: &mut UnixStream) -> Option<Frame> {
        let mut header = [0u8; fandhe_container_io::FRAME_HEADER_LEN];
        stream.read_exact(&mut header).ok()?;
        let parsed = FrameHeader::from_bytes(header).expect("response header must be valid");
        let mut body = vec![0u8; parsed.body_len()];
        stream.read_exact(&mut body).ok()?;
        Some(Frame::decode_body(parsed, &body).expect("response frame must decode"))
    }

    fn recv_frame(stream: &mut UnixStream) -> Frame {
        try_recv_frame(stream).expect("client must receive a response frame")
    }

    fn connect(path: &Path) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(5);
        let stream = loop {
            match UnixStream::connect(path) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(err) => panic!("client failed to connect: {err}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("must set a read timeout");
        stream
    }

    fn ack_id(frame: &Frame) -> u64 {
        let ack = decode_ack(frame).expect("frame must be a valid ack");
        assert_eq!(ack.kind(), FrameKind::Ack);
        ack.id().get()
    }

    /// `client` を別スレッドで動かし、サーバー側（`serve_file_connection`）の終了原因を返す。
    /// クライアント側の結果を先に join してからサーバーを join する（REPAIR-5: 待ちには期限がある）。
    fn run_session<R: Send + 'static>(
        dir: &TempDir,
        batch_size: usize,
        client: impl FnOnce(UnixStream) -> R + Send + 'static,
    ) -> (R, IoErrorCode) {
        let mut server = UdsServer::bind(
            &dir.socket_path(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");
        std::fs::create_dir(dir.share_root()).expect("share root");
        let creator = GuestFileCreator::new(dir.share_root()).expect("creator");

        let socket = dir.socket_path();
        let client_thread = std::thread::spawn(move || client(connect(&socket)));

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection within the timeout");
        let config = BatchConfig::new(batch_size).expect("batch size");
        let server_thread = std::thread::spawn(move || {
            serve_file_connection(&mut connection, config, &creator, timeouts())
        });

        let result = client_thread.join().expect("client thread must not panic");
        let report = server_thread.join().expect("server thread must not panic");
        (result, report.end.code())
    }

    /// IO-1・IO-5: 複数ファイルの作成・書き込み・Close の Ack が受信順に届き、中身が一致する。
    /// 大文字小文字の衝突は Nack（AlreadyExists / CaseCollision）で、接続は続く。
    #[test]
    fn io1_uds_file_mode_round_trip_with_nack() {
        let dir = TempDir::new();
        let (ids, end) = run_session(&dir, 6, |mut stream| {
            send_create(&mut stream, 1, "src/a.txt");
            send_create(&mut stream, 2, "SRC/A.TXT");
            send_write_file(&mut stream, 3, 1, b"alpha");
            send_write_file(&mut stream, 4, 1, b"-beta");
            send_write_file(&mut stream, 5, 2, b"lost");
            send_close(&mut stream, 6, 1);
            let mut ids = Vec::new();
            let mut nacks = Vec::new();
            for _ in 0..6 {
                let frame = recv_frame(&mut stream);
                match frame.kind() {
                    FrameKind::Ack => ids.push(ack_id(&frame)),
                    FrameKind::Nack => {
                        let n = decode_nack(&frame).expect("nack");
                        nacks.push((n.id().get(), n.code(), n.reason()));
                    }
                    other => panic!("unexpected response kind {other:?}"),
                }
            }
            (ids, nacks)
        });
        let (acks, nacks) = ids;
        assert_eq!(acks, vec![1, 3, 4, 6]);
        assert_eq!(
            nacks,
            vec![
                (2, NackCode::AlreadyExists, NackReason::CaseCollision),
                (5, NackCode::InvalidArgument, NackReason::UnknownHandle),
            ]
        );
        assert_eq!(
            std::fs::read(dir.share_root().join("src/a.txt")).expect("read"),
            b"alpha-beta"
        );
        // クライアントの切断で Unavailable（EOF）として終わる。
        assert_eq!(end, IoErrorCode::Unavailable);
    }

    /// IO-2・F9: Flush は滞留分の Ack の後に永続化し、FlushAck を返して接続を続ける。同じ接続で
    /// 次の Create と Flush も処理される。永続化に対応しない環境（5.8 未満の Linux 等）では
    /// FlushAck を偽装せず Unimplemented で終える。
    #[test]
    fn io2_uds_file_mode_flush_returns_flush_ack() {
        let supported = fandhe_container_io::persist_support().is_supported();
        let dir = TempDir::new();
        let (outcome, end) = run_session(&dir, 8, |mut stream| {
            send_create(&mut stream, 1, "f");
            send_write_file(&mut stream, 2, 1, b"data");
            send_flush(&mut stream, 3);
            let first = ack_id(&recv_frame(&mut stream));
            let second = ack_id(&recv_frame(&mut stream));
            let flush_ack = try_recv_frame(&mut stream).map(|f| {
                let ack = decode_ack(&f).expect("flush ack");
                (ack.kind(), ack.id().get())
            });
            if flush_ack.is_none() {
                return (first, second, None, None);
            }
            send_create(&mut stream, 4, "g");
            send_flush(&mut stream, 5);
            let third = ack_id(&recv_frame(&mut stream));
            let second_flush = try_recv_frame(&mut stream).map(|f| {
                let ack = decode_ack(&f).expect("flush ack");
                (ack.kind(), ack.id().get())
            });
            (first, second, flush_ack, Some((third, second_flush)))
        });
        if supported {
            assert_eq!(
                outcome,
                (
                    1,
                    2,
                    Some((FrameKind::FlushAck, 3)),
                    Some((4, Some((FrameKind::FlushAck, 5))))
                )
            );
            assert_eq!(end, IoErrorCode::Unavailable);
        } else {
            assert_eq!(outcome, (1, 2, None, None));
            assert_eq!(end, IoErrorCode::Unimplemented);
        }
        assert_eq!(
            std::fs::read(dir.share_root().join("f")).expect("read"),
            b"data"
        );
    }

    /// IO-10: 未フラッシュ滞留量の上限に達すると自動フラッシュ（FlushAck なし）して接続を続ける。
    #[test]
    fn io10_uds_file_mode_auto_flush_keeps_connection() {
        let supported = fandhe_container_io::persist_support().is_supported();
        let dir = TempDir::new();
        let mut server = UdsServer::bind(
            &dir.socket_path(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");
        std::fs::create_dir(dir.share_root()).expect("share root");
        let creator = GuestFileCreator::new(dir.share_root()).expect("creator");
        let socket = dir.socket_path();
        let client = std::thread::spawn(move || {
            let mut stream = connect(&socket);
            send_create(&mut stream, 1, "a");
            send_write_file(&mut stream, 2, 1, b"x");
            send_write_file(&mut stream, 3, 1, b"y");
            send_write_file(&mut stream, 4, 1, b"z");
            send_flush(&mut stream, 5);
            let mut kinds = Vec::new();
            for _ in 0..5 {
                match try_recv_frame(&mut stream) {
                    Some(frame) => kinds.push(frame.kind()),
                    None => break,
                }
            }
            kinds
        });
        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("accept");
        let limits = FileServeLimits::new(
            MaxOpenFiles::default(),
            UnflushedLimit::new(3, 1024).expect("limit"),
        );
        let server_thread = std::thread::spawn(move || {
            serve_file_connection_with_limit(
                &mut connection,
                BatchConfig::new(64).expect("batch size"),
                limits,
                &creator,
                timeouts(),
            )
        });
        let kinds = client.join().expect("client");
        let report = server_thread.join().expect("server");
        if supported {
            // 3 件目で自動フラッシュ（FlushAck なし）し、続く 4 件目と明示 Flush も処理される。
            let mut expected = vec![FrameKind::Ack; 4];
            expected.push(FrameKind::FlushAck);
            assert_eq!(kinds, expected);
            assert_eq!(report.stats.auto_flushes, 1);
            assert_eq!(report.stats.flush_acks_sent, 1);
            assert_eq!(report.end.code(), IoErrorCode::Unavailable);
        } else {
            assert_eq!(report.end.code(), IoErrorCode::Unimplemented);
        }
        // 未対応環境では 3 件目の自動フラッシュが Unimplemented で接続を終えるため、4 件目は
        // 実行されない。
        let expected_content: &[u8] = if supported { b"xyz" } else { b"xy" };
        assert_eq!(
            std::fs::read(dir.share_root().join("a")).expect("read"),
            expected_content
        );
    }

    /// F3: モードに合わない種別（v1 の Write）は接続全体の InvalidArgument で、応答は届かない。
    #[test]
    fn io1_uds_file_mode_rejects_v1_write() {
        let dir = TempDir::new();
        let (next, end) = run_session(&dir, 4, |mut stream| {
            let mut payload = 1u64.to_le_bytes().to_vec();
            payload.extend_from_slice(b"x");
            send(&mut stream, FrameKind::Write, payload);
            try_recv_frame(&mut stream).map(|f| f.kind())
        });
        assert_eq!(next, None);
        assert_eq!(end, IoErrorCode::InvalidArgument);
    }

    /// IO-5: 祖先をたどる `..` はパス構文違反の Nack で、共有ルートの外には何も作られない。
    #[test]
    fn io5_uds_file_mode_path_traversal_is_nacked() {
        let dir = TempDir::new();
        let (nack, _end) = run_session(&dir, 1, |mut stream| {
            send_create(&mut stream, 1, "../escape");
            let n = decode_nack(&recv_frame(&mut stream)).expect("nack");
            (n.id().get(), n.code(), n.reason())
        });
        assert_eq!(nack, (1, NackCode::InvalidArgument, NackReason::PathSyntax));
        assert!(!dir.path.join("escape").exists());
    }
}
