//! UDS サーバー側トランスポート（[`fandhe_container_io::server`]）の結合試験
//! （TASK-13.2.1・IO-1・REPAIR-5・REPAIR-6・P1-3・#820）。
//!
//! 公開 API と std の `UnixStream`（client 役。TASK-12.2 以降でクライアント側の
//! 具象実装ができるまでの代用）のみを使い、実際の UDS を通してフレームを
//! 送受信できることを確かめる（受け入れ条件 3）。

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::io::{Read, Write};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_io::{
        Frame, FrameKind, FrameReceiver, FrameSender, IoErrorCode, IoTimeout,
        JsonLinesServerObserver, MAX_CONTROL_PAYLOAD_LEN, NoopServerObserver, ReceiveLimits,
    };

    /// テストごとに固有かつ短いソケットディレクトリを作る（macOS の
    /// `/var/folders/...` が長く、sun_path の上限〔104 バイト〕に近づくため、
    /// ディレクトリ名・ソケット名の双方を短く保つ）。作成した一時ディレクトリは
    /// `Drop` で削除する（削除の失敗は無視する。テストの後片付けのため）。
    struct TempSocketDir {
        path: PathBuf,
    }

    impl TempSocketDir {
        fn new() -> Self {
            Self::with_mode(0o700)
        }

        /// `mode` で作成する。`DirBuilder::mode` は `mkdir(2)` 相当であり
        /// プロセスの umask でマスクされるため（実測: umask 022 環境では
        /// `mode(0o777)` で作っても実効モードが `0o755` になり、意図した
        /// world-writable な検証にならない）、作成直後に `set_permissions` で
        /// umask の影響を受けない実効モードを明示的に確定させる。
        fn with_mode(mode: u32) -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let dir = std::env::temp_dir().join(format!("fcio-{pid}-{n}"));
            std::fs::DirBuilder::new()
                .mode(mode)
                .create(&dir)
                .expect("must be able to create a temp dir for the socket");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))
                .expect("must be able to force the exact directory mode regardless of umask");
            Self { path: dir }
        }

        fn socket_path(&self) -> PathBuf {
            self.path.join("s.sock")
        }
    }

    impl Drop for TempSocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn test_timeout() -> IoTimeout {
        IoTimeout::new(Duration::from_secs(5)).expect("5s must be a valid IoTimeout")
    }

    /// IO-1: server が bind → accept、client が接続してフレームを 1 件送り、
    /// server がそれを受信できる。続けて server から client へ ACK フレームを
    /// 送り返し、client が受信できる（往復）。
    #[test]
    fn io1_uds_roundtrip_single_frame() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            // server の accept が listen 状態になるまでの短い待ち合わせ。
            // connect のリトライは「接続を試みるだけ」で、フレーム送受信自体の
            // タイムアウト検証には関わらない。
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match UnixStream::connect(&connect_path) {
                    Ok(s) => break s,
                    Err(_) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("client failed to connect: {e}"),
                }
            };

            let request = Frame::new(FrameKind::Write, vec![0xde, 0xad, 0xbe, 0xef])
                .expect("payload within MAX_PAYLOAD_LEN must construct a Frame");
            stream
                .write_all(&request.encode())
                .expect("client write must succeed");

            // ack フレームの受信（サイズは事前に分からないため、ヘッダ 10 バイト +
            // ペイロード + チェックサム 4 バイトを読み切る）。
            let mut header = [0u8; fandhe_container_io::FRAME_HEADER_LEN];
            stream
                .read_exact(&mut header)
                .expect("client must read the response header");
            let parsed_header = fandhe_container_io::FrameHeader::from_bytes(header)
                .expect("response header must be valid");
            let mut body = vec![0u8; parsed_header.body_len()];
            stream
                .read_exact(&mut body)
                .expect("client must read the response body");
            let ack = Frame::decode_body(parsed_header, &body).expect("response frame must decode");
            assert_eq!(ack.kind(), FrameKind::Ack);
            assert_eq!(ack.payload(), &[0x01]);
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection within the timeout");

        let received = connection
            .recv_frame(test_timeout())
            .expect("server must receive the client's frame");
        assert_eq!(received.kind(), FrameKind::Write);
        assert_eq!(received.payload(), &[0xde, 0xad, 0xbe, 0xef]);

        let ack = Frame::new(FrameKind::Ack, vec![0x01]).expect("ack frame must construct");
        connection
            .send_frame(&ack, test_timeout())
            .expect("server must be able to send the ack frame");

        client_thread.join().expect("client thread must not panic");
    }

    /// REPAIR-5: 誰も接続してこなければ `accept` は上限時間で `Timeout` を返し、
    /// 無期限に待ち続けない。
    #[test]
    fn io1_uds_accept_times_out_without_client() {
        let dir = TempSocketDir::new();
        let mut server = fandhe_container_io::UdsServer::bind(
            &dir.socket_path(),
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        let timeout = IoTimeout::new(Duration::from_millis(300)).expect("300ms must be valid");
        let started = Instant::now();
        let err = server
            .accept(timeout, NoopServerObserver)
            .expect_err("accept without any client must time out");
        let elapsed = started.elapsed();

        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(elapsed >= Duration::from_millis(300), "elapsed={elapsed:?}");
        assert!(elapsed <= Duration::from_secs(2), "elapsed={elapsed:?}");
    }

    /// REPAIR-5: 接続だけして何も送らない相手に対しては `recv_frame` が上限時間で
    /// `Timeout` を返す。
    ///
    /// #1130: client は固定 sleep ではなく、server の判定完了の合図
    /// （`release_tx`）まで接続を保持する（`repair5_uds_recv_times_out_on_trickling_peer`
    /// と同じ形。C2・#820）。
    #[test]
    fn repair5_uds_recv_times_out_on_silent_peer() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = UnixStream::connect(&connect_path).expect("client must connect");
            // 何も送らずに、server 側の判定完了の合図まで接続を保持する
            // （待ちは最大 10 秒。無期限にしない。REPAIR-5）。
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            drop(stream);
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection");

        let timeout = IoTimeout::new(Duration::from_millis(300)).expect("300ms must be valid");
        let started = Instant::now();
        let err = connection
            .recv_frame(timeout)
            .expect_err("recv from a silent peer must time out");
        let elapsed = started.elapsed();

        assert_eq!(
            err.code(),
            IoErrorCode::Timeout,
            "err={err:?} elapsed={elapsed:?}"
        );
        assert!(elapsed >= Duration::from_millis(300), "elapsed={elapsed:?}");
        assert!(elapsed <= Duration::from_secs(2), "elapsed={elapsed:?}");

        let _ = release_tx.send(());
        client_thread.join().expect("client thread must not panic");
    }

    /// REPAIR-5: 1 バイトずつ間隔を空けて送ってくる相手でも、フレーム全体の期限で
    /// `Timeout` になる（1 回の read ごとの期限ではないことの確認）。
    ///
    /// C2（#820 レビュー指摘）: client は「間隔を空けて送る」ループを終えた
    /// あと、`recv_timeout` で server 側の判定完了（`tx.send`）を待ってから
    /// 切断する。固定の sleep 時間で「server の期限より十分長く接続を保つ」
    /// ことを狙うのではなく、実際に server が期限切れの判定を終えるまで
    /// 同期することで、スケジューリングの遅れ（CI 環境の負荷等）で client が
    /// 先に切断し `Unavailable` になってしまうレースを構造的に無くす。
    #[test]
    fn repair5_uds_recv_times_out_on_trickling_peer() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&connect_path).expect("client must connect");
            let frame = Frame::new(FrameKind::Write, vec![1, 2, 3]).expect("frame must construct");
            let bytes = frame.encode();
            // ヘッダの途中までしか送らず、1 バイトずつ間隔を空けて送る。
            // server 側のフレーム全体の期限（500ms）を超えるまで送り続ける。
            for byte in bytes.iter().take(4) {
                let _ = stream.write_all(std::slice::from_ref(byte));
                std::thread::sleep(Duration::from_millis(200));
            }
            // server がタイムアウト判定・アサーションを終えるまで接続を保持する
            // （最大 10 秒。判定が来なければテスト側の `join` がハングせず
            // タイムアウト自体のバグとして顕在化するよう、待ちは無期限にしない）。
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            drop(stream);
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection");

        let timeout = IoTimeout::new(Duration::from_millis(500)).expect("500ms must be valid");
        let started = Instant::now();
        let err = connection
            .recv_frame(timeout)
            .expect_err("a trickling peer must not extend the per-frame deadline");
        let elapsed = started.elapsed();

        assert_eq!(err.code(), IoErrorCode::Timeout);
        // フレーム全体の期限（500ms）で打ち切られるはずで、1 バイトごとの
        // read 期限（500ms）× 送信回数ぶん待ち続けることはない。
        assert!(elapsed <= Duration::from_secs(2), "elapsed={elapsed:?}");

        let _ = release_tx.send(());
        let _ = client_thread.join();
    }

    /// IO-1: header_crc を 1 ビット反転させたヘッダを送ると `DataLoss` が返る。
    /// その後の呼び出しは P1-3 により `Unavailable` になる。
    #[test]
    fn io1_uds_recv_rejects_corrupted_header() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&connect_path).expect("client must connect");
            let frame = Frame::new(FrameKind::Write, vec![9, 9, 9]).expect("frame must construct");
            let mut bytes = frame.encode();
            // header_crc は末尾 4 バイトのうちの先頭バイト（オフセット 6）に
            // 位置する。1 ビット反転させてヘッダを壊す。
            if let Some(b) = bytes.get_mut(6) {
                *b ^= 0x01;
            }
            stream.write_all(&bytes).expect("client write must succeed");
            // server が poison するまで接続を保持する。
            std::thread::sleep(Duration::from_millis(200));
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection");

        let err = connection
            .recv_frame(test_timeout())
            .expect_err("a corrupted header must be rejected");
        assert_eq!(err.code(), IoErrorCode::DataLoss);

        let err = connection
            .recv_frame(test_timeout())
            .expect_err("a poisoned connection must not be reused for recv");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        let err = connection
            .send_frame(
                &Frame::new(FrameKind::Ack, vec![]).expect("ack frame must construct"),
                test_timeout(),
            )
            .expect_err("a poisoned connection must not be reused for send");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        let _ = client_thread.join();
    }

    /// IO-1: client がフレームを送る前に切断すると `recv_frame` は `Unavailable`
    /// を返す。
    #[test]
    fn io1_uds_recv_reports_unavailable_on_peer_close() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = UnixStream::connect(&connect_path).expect("client must connect");
            drop(stream);
        });
        client_thread.join().expect("client thread must not panic");

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the (already closed) client connection");

        let err = connection
            .recv_frame(test_timeout())
            .expect_err("recv on a peer-closed connection must report unavailable");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }

    /// IO-1・REPAIR-5・#820（PR #1113 の macOS CI 失敗の修正）: client が完全な
    /// フレームを 2 件送り切ってから close しても、server は受信バッファに残った
    /// 2 件とも受信でき、3 回目の `recv_frame` で `Unavailable` になる。
    ///
    /// macOS では相手の close 後に `set_read_timeout` が `EINVAL` を返すため、
    /// 以前の実装は最初の `recv_frame` で `Unavailable` を返し、相手が最後に
    /// 送ったフレームを失っていた（本テストはその回帰を捕まえる）。2 件にするのは、
    /// 1 件目の受信後に blocking へ戻したソケットで 2 件目の受信が再び受信バッファの
    /// 残りを読む経路を通すため。server が読む前に client が書き切って close
    /// できるよう、ペイロードは macOS の UDS の既定の送信バッファ（数 KiB）より
    /// 十分小さくする（大きいと client の write がブロックしたままになる）。
    #[test]
    fn io1_repair5_820_recv_reads_frames_sent_before_peer_close() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        let first_payload: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let second_payload = vec![0x5a; 37];
        let first =
            Frame::new(FrameKind::Write, first_payload.clone()).expect("write frame must build");
        let second =
            Frame::new(FrameKind::Flush, second_payload.clone()).expect("flush frame must build");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&connect_path).expect("client must connect");
            stream
                .write_all(&first.encode())
                .expect("client must send the first frame");
            stream
                .write_all(&second.encode())
                .expect("client must send the second frame");
            drop(stream);
        });
        // client が送り切って close してから server が受信を始める。
        client_thread.join().expect("client thread must not panic");

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the (already closed) client connection");

        let received = connection
            .recv_frame(test_timeout())
            .expect("a frame sent before the peer closed must still be received");
        assert_eq!(received.kind(), FrameKind::Write);
        assert_eq!(received.payload(), first_payload.as_slice());

        let received = connection
            .recv_frame(test_timeout())
            .expect("the last frame sent before the peer closed must still be received");
        assert_eq!(received.kind(), FrameKind::Flush);
        assert_eq!(received.payload(), second_payload.as_slice());

        let started = Instant::now();
        let err = connection
            .recv_frame(test_timeout())
            .expect_err("recv after the buffered frames are drained must report unavailable");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
        assert_eq!(
            err.message(),
            "peer closed the connection before sending a complete frame header"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "recv on a drained, peer-closed connection must not wait for the timeout: {:?}",
            started.elapsed()
        );
    }

    /// TASK-13.4・IO-1（#796・#820 レビュー指摘の 0b・0 コミット項目）: 制御
    /// フレーム（`Flush`）が `MAX_CONTROL_PAYLOAD_LEN` を超える長さを申告すると、
    /// `recv_frame` は本体を読む前に `ReceiveLimits::admit` により
    /// `ResourceExhausted` で拒否する。その後は P1-3 により `Unavailable` になる。
    #[test]
    fn io1_uds_recv_rejects_oversized_control_frame_before_body_read() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let oversized_len = MAX_CONTROL_PAYLOAD_LEN as usize + 1;
        let client_thread = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&connect_path).expect("client must connect");
            let frame = Frame::new(FrameKind::Flush, vec![0u8; oversized_len])
                .expect("payload within MAX_PAYLOAD_LEN must construct a Frame");
            // ヘッダだけ書き切れば admit の判定には十分（本体を待たずに拒否
            // されるはずのため、本体は送らずに接続を保持する）。
            let encoded = frame.encode();
            let header = encoded
                .get(..fandhe_container_io::FRAME_HEADER_LEN)
                .expect("encoded frame must contain a full header");
            stream
                .write_all(header)
                .expect("client header write must succeed");
            std::thread::sleep(Duration::from_millis(200));
            drop(stream);
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection");

        let err = connection
            .recv_frame(test_timeout())
            .expect_err("an oversized control frame must be rejected before the body is read");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert!(err.message().contains(&MAX_CONTROL_PAYLOAD_LEN.to_string()));

        let err = connection
            .recv_frame(test_timeout())
            .expect_err("a poisoned connection must not be reused for recv");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        let _ = client_thread.join();
    }

    /// F・#820（codex P1 指摘対応）: `UdsServer::bind` に構築時に渡した
    /// [`ReceiveLimits`] が、`ReceiveLimits::default()` ではなく実際に
    /// `recv_frame` の確保前検証へ反映される。既定値より小さい上限を設定した
    /// `Write` フレームは、本体バッファを確保する前に `ResourceExhausted` で
    /// 拒否される（既定の `MAX_PAYLOAD_LEN` に収まる長さでも、設定した小さい
    /// 上限では拒否されることを確認する）。
    #[test]
    fn f_820_uds_recv_honors_receive_limits_passed_to_bind() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let small_limits = ReceiveLimits::new(8, 8).expect("8 bytes must be a valid limit");
        let mut server =
            fandhe_container_io::UdsServer::bind(&socket_path, small_limits, NoopServerObserver)
                .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        // 既定の MAX_PAYLOAD_LEN には遠く及ばないが、上で設定した上限（8
        // バイト）は超える長さ。
        let oversized_len = 9usize;
        let client_thread = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&connect_path).expect("client must connect");
            let frame = Frame::new(FrameKind::Write, vec![0u8; oversized_len])
                .expect("payload within MAX_PAYLOAD_LEN must construct a Frame");
            // ヘッダだけ書き切れば admit の判定には十分（本体を待たずに拒否
            // されるはずのため、本体は送らずに接続を保持する）。
            let encoded = frame.encode();
            let header = encoded
                .get(..fandhe_container_io::FRAME_HEADER_LEN)
                .expect("encoded frame must contain a full header");
            stream
                .write_all(header)
                .expect("client header write must succeed");
            std::thread::sleep(Duration::from_millis(200));
            drop(stream);
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection");

        let err = connection.recv_frame(test_timeout()).expect_err(
            "a Write frame over the bind-time configured limit must be rejected before the \
             body is read",
        );
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
        assert!(err.message().contains('8'));

        let err = connection
            .recv_frame(test_timeout())
            .expect_err("a poisoned connection must not be reused for recv");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        let _ = client_thread.join();
    }

    /// IO-1・REPAIR-2（#820 レビュー指摘）: サーバー側はクライアントから
    /// `Ack` フレームを受け取ることを想定していない（サーバーが `Ack` を返す側）。
    /// `recv_frame` は本体を読む前に `InvalidArgument` で拒否し、その後は P1-3
    /// により `Unavailable` になる。
    #[test]
    fn io1_uds_recv_rejects_client_originated_ack_frame() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&connect_path).expect("client must connect");
            let frame = Frame::new(FrameKind::Ack, vec![0u8; 8]).expect("ack frame must construct");
            stream
                .write_all(&frame.encode())
                .expect("client write must succeed");
            std::thread::sleep(Duration::from_millis(200));
            drop(stream);
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection");

        let err = connection
            .recv_frame(test_timeout())
            .expect_err("a client-originated Ack frame must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let err = connection
            .recv_frame(test_timeout())
            .expect_err("a poisoned connection must not be reused for recv");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        let _ = client_thread.join();
    }

    /// IO-1・REPAIR-2（#820 レビュー指摘）: `FlushAck` も同様に
    /// サーバーが返す側の種別であり、クライアントから届くのはプロトコル違反
    /// として拒否する。
    #[test]
    fn io1_uds_recv_rejects_client_originated_flush_ack_frame() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&connect_path).expect("client must connect");
            let frame = Frame::new(FrameKind::FlushAck, vec![0u8; 8])
                .expect("flush ack frame must construct");
            stream
                .write_all(&frame.encode())
                .expect("client write must succeed");
            std::thread::sleep(Duration::from_millis(200));
            drop(stream);
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection");

        let err = connection
            .recv_frame(test_timeout())
            .expect_err("a client-originated FlushAck frame must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let err = connection
            .recv_frame(test_timeout())
            .expect_err("a poisoned connection must not be reused for recv");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        let _ = client_thread.join();
    }

    /// P1-3: エラーの後は send/recv どちらも `Unavailable` になり、socket に
    /// 追加のバイトが書き込まれない（client 側で追加データが届かないことを
    /// 短い read timeout で確かめる）。
    #[test]
    fn p1_3_uds_connection_unavailable_after_error() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        // #1130: client は server が recv の Timeout と poison 後の send 拒否を
        // 確認し終えるまで何も読まず接続を保持する。client の read timeout が
        // server の recv 期限より先に切れて接続が閉じ、server 側が Timeout でなく
        // Unavailable（EOF）になるレースを無くす。
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = UnixStream::connect(&connect_path).expect("client must connect");
            // 待ちは最大 10 秒。無期限にしない（REPAIR-5）。
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .expect("set_read_timeout must succeed");
            let mut buf = [0u8; 16];
            let mut client_stream = stream;
            // poison 後に server が何も書き込んでいないことを確認する。
            // 「タイムアウト（Err の WouldBlock/TimedOut）または EOF（Ok(0)）の
            // いずれか」だけを許し、それ以外（実データが届く Ok(n>0) や他の
            // エラー種別）は P1-3 契約違反として失敗させる（poison 後に
            // 誤ってバイトが書き込まれるケースを検出できるようにする）。
            match client_stream.read(&mut buf) {
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Ok(0) => {}
                other => {
                    panic!("server must not write any bytes after being poisoned, got {other:?}")
                }
            }
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection");

        let timeout = IoTimeout::new(Duration::from_millis(300)).expect("300ms must be valid");
        let err = connection
            .recv_frame(timeout)
            .expect_err("recv from a silent peer must time out and poison the connection");
        assert_eq!(err.code(), IoErrorCode::Timeout, "err={err:?}");

        let err = connection
            .send_frame(
                &Frame::new(FrameKind::Ack, vec![]).expect("ack frame must construct"),
                test_timeout(),
            )
            .expect_err("send after poisoning must be rejected without touching the socket");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        // server の判定が済んでから client に「バイトが届いていないこと」を確認させる。
        let _ = release_tx.send(());
        client_thread.join().expect("client thread must not panic");
    }

    /// security.md（UDS 観点）: 既存パスがあるとき `bind` は `InvalidArgument` を
    /// 返し、既存ファイルを消さない。
    #[test]
    fn io1_uds_bind_rejects_existing_path() {
        let dir = TempSocketDir::new();
        let path = dir.socket_path();
        std::fs::write(&path, b"not a socket").expect("must be able to create a placeholder file");

        let err = fandhe_container_io::UdsServer::bind(
            &path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("bind onto an existing path must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let contents = std::fs::read(&path).expect("the existing file must not be removed");
        assert_eq!(contents, b"not a socket");
    }

    /// security.md（UDS 観点）: 親ディレクトリが group / other 書き込み可能な場合は
    /// `bind` を `InvalidArgument` として拒否する（umask 022・002・000 いずれの
    /// 環境でも、`TempSocketDir::with_mode` が umask の影響を受けない実効モード
    /// `0o777` を保証するため再現する）。
    #[test]
    fn io1_uds_bind_rejects_world_writable_parent() {
        let dir = TempSocketDir::with_mode(0o777);
        let path = dir.socket_path();

        let err = fandhe_container_io::UdsServer::bind(
            &path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("bind under a world-writable parent must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        assert!(!path.exists(), "no socket file must be created");
    }

    /// security.md（UDS 観点。#820 レビュー指摘の回帰テスト）: 親ディレクトリが
    /// `0o755`（group / other は書き込めないが read / search は許す）でも、
    /// owner 以外への一切のアクセスを拒否する強化後の検証で `bind` を拒否する。
    /// 強化前（`mode & 0o022`）はこのケースを通してしまっていた。
    #[test]
    fn io1_uds_bind_rejects_parent_readable_by_others() {
        let dir = TempSocketDir::with_mode(0o755);
        let path = dir.socket_path();

        let err = fandhe_container_io::UdsServer::bind(
            &path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("bind under a 0o755 parent directory must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        assert!(!path.exists(), "no socket file must be created");
    }

    /// C1・security.md（UDS 観点。#820 レビュー指摘の回帰テスト）: 親ディレクトリ
    /// 自体が symlink の場合、`bind` は `InvalidArgument` として拒否し、symlink
    /// 先にソケットファイルを作らない（`imp::validate_parent_dir` の
    /// `is_symlink` 検査）。
    #[test]
    fn c1_uds_bind_rejects_symlinked_parent_directory() {
        let dir = TempSocketDir::new();
        let real_dir = dir.path.join("real");
        std::fs::create_dir(&real_dir).expect("must be able to create the real target dir");
        let link_dir = dir.path.join("link");
        std::os::unix::fs::symlink(&real_dir, &link_dir)
            .expect("must be able to create a symlinked parent directory");
        let path = link_dir.join("s.sock");

        let err = fandhe_container_io::UdsServer::bind(
            &path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("bind under a symlinked parent directory must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        assert!(
            !path.exists(),
            "no socket file must be created under the symlinked parent"
        );
        assert!(
            std::fs::symlink_metadata(&link_dir)
                .expect("the symlink itself must remain")
                .file_type()
                .is_symlink(),
            "the parent symlink must not be touched"
        );
    }

    /// C1・security.md（UDS 観点。#820 レビュー指摘の回帰テスト）: bind 先の
    /// パス自体が既存の symlink の場合も `bind` は `InvalidArgument` として
    /// 拒否し、その symlink を消さない（`imp::reject_existing_path` は
    /// `symlink_metadata` で symlink 自体を検出し、自動 unlink はしない）。
    #[test]
    fn c1_uds_bind_rejects_existing_symlink_path() {
        let dir = TempSocketDir::new();
        let target = dir.path.join("target-file");
        std::fs::write(&target, b"not a socket").expect("must be able to create the link target");
        let path = dir.socket_path();
        std::os::unix::fs::symlink(&target, &path)
            .expect("must be able to create a symlink at the socket path");

        let err = fandhe_container_io::UdsServer::bind(
            &path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect_err("bind onto an existing symlink must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        let meta =
            std::fs::symlink_metadata(&path).expect("the symlink at the socket path must remain");
        assert!(
            meta.file_type().is_symlink(),
            "the existing symlink must not be removed"
        );
    }

    /// security.md（UDS 観点）・PLUG-12・J2・#820（codex P0 指摘対応）: bind 後、
    /// 別 uid がソケットへ到達できない前提が親ディレクトリで担保されている
    /// （親ディレクトリは symlink でないディレクトリで、モードは bind 前と同じ
    /// `0700` のまま〔group / other のビットがない〕、所有者はソケットファイルの
    /// 所有者〔bind したプロセスの実効 uid〕と同じ）。`UdsServer` を drop すると
    /// ソケットファイルが削除される。
    ///
    /// ソケットファイル自体のモードは bind 時の umask に従い、`UdsServer` は
    /// 変更しない（bind 後にパスを再解決する chmod を廃止した。
    /// `UdsServer::bind` の「ソケットファイルのモード」節）ため、ここでは
    /// ソケットファイルのモードの値を検査しない（umask 000 では `0777` になる）。
    /// 旧テスト `io1_uds_socket_file_mode_and_cleanup` はソケットが `0600` で
    /// あることで「owner 以外が到達できない」ことを確かめていたが、その担保が
    /// 親ディレクトリへ移ったため、同じ目的を親ディレクトリの不変条件で確かめる。
    #[test]
    fn io1_plug12_uds_parent_dir_guards_socket_access_and_cleanup() {
        let dir = TempSocketDir::new();
        let path = dir.socket_path();
        let server = fandhe_container_io::UdsServer::bind(
            &path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a fresh path");
        assert_eq!(server.path(), path.as_path());

        let socket_meta =
            std::fs::symlink_metadata(&path).expect("socket file must exist after bind");
        assert!(socket_meta.file_type().is_socket());
        let parent_meta =
            std::fs::symlink_metadata(&dir.path).expect("parent directory must exist");
        assert!(!parent_meta.file_type().is_symlink());
        assert!(parent_meta.is_dir());
        assert_eq!(parent_meta.permissions().mode() & 0o777, 0o700);
        assert_eq!(parent_meta.permissions().mode() & 0o077, 0);
        assert_eq!(socket_meta.uid(), parent_meta.uid());

        drop(server);
        assert!(!path.exists(), "socket file must be removed after drop");
    }

    /// PLUG-12・J3・#820（codex P1 指摘対応）: bind 後に元のパスが unlink され、
    /// 別の listener が同じパスへ bind した場合、古い `UdsServer` の drop は
    /// 新しいソケットを削除しない（bind 直後に記録した `(dev, ino)`・所有者 uid と
    /// 一致しないため）。新しいソケットはパスに残り、接続できる。
    #[test]
    fn j3_plug12_uds_drop_keeps_socket_rebound_by_another_listener() {
        let dir = TempSocketDir::new();
        let path = dir.socket_path();
        let server = fandhe_container_io::UdsServer::bind(
            &path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a fresh path");
        let old_meta = std::fs::symlink_metadata(&path).expect("socket file must exist");

        std::fs::remove_file(&path).expect("must be able to unlink the bound socket");
        let new_listener =
            UnixListener::bind(&path).expect("another listener must be able to bind the path");
        let new_meta = std::fs::symlink_metadata(&path).expect("new socket file must exist");
        assert_ne!(
            (old_meta.dev(), old_meta.ino()),
            (new_meta.dev(), new_meta.ino()),
            "the filesystem reused the inode, so the two sockets cannot be told apart"
        );

        drop(server);

        let after = std::fs::symlink_metadata(&path)
            .expect("the new socket must not be removed by the old server's drop");
        assert!(after.file_type().is_socket());
        assert_eq!((after.dev(), after.ino()), (new_meta.dev(), new_meta.ino()));
        let _client =
            UnixStream::connect(&path).expect("the new listener must still accept connections");
        new_listener
            .accept()
            .expect("the new listener must receive the connection");
    }

    /// REPAIR-5（#820 レビュー指摘）: 書き込みがブロックし続ける相手に対しては
    /// `send_frame` がフレーム全体の期限で `Timeout` を返し（送信側の
    /// `write_all_until` のタイムアウト経路）、その後は P1-3 により
    /// `Unavailable` になる。
    ///
    /// #1130: client は固定 sleep ではなく、server の判定完了の合図
    /// （`release_tx`）まで接続を保持する。固定 sleep だと、遅い CI（macOS 等）で
    /// 16 MiB の準備が client の close に間に合わず、1 回目が `Timeout` でなく
    /// `Unavailable` になっていた（REPAIR-5・TASK-13.2.1）。
    #[test]
    fn repair5_uds_send_times_out_on_unresponsive_peer() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            NoopServerObserver,
        )
        .expect("bind must succeed on a private, empty path");

        // 重い準備（16 MiB のフレーム構築と CRC）は client 起動前に済ませる。
        let big_payload = vec![0x5au8; 16 * 1024 * 1024];
        let big_frame =
            Frame::new(FrameKind::Write, big_payload).expect("large frame must construct");

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = UnixStream::connect(&connect_path).expect("client must connect");
            // 接続を保持したまま何も読まない。カーネルの送信バッファ（既定は
            // 数百 KiB 程度）を溢れさせるには十分大きいペイロードが必要
            // （send_frame のテスト側で 16 MiB を送る）。server の判定完了の合図まで
            // 保持する（待ちは最大 10 秒。無期限にしない。REPAIR-5）。
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
            drop(stream);
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection");

        let timeout = IoTimeout::new(Duration::from_millis(300)).expect("300ms must be valid");
        let started = Instant::now();
        let err = connection
            .send_frame(&big_frame, timeout)
            .expect_err("send to an unresponsive peer must time out");
        let elapsed = started.elapsed();

        assert_eq!(
            err.code(),
            IoErrorCode::Timeout,
            "err={err:?} elapsed={elapsed:?}"
        );
        assert!(elapsed >= Duration::from_millis(300), "elapsed={elapsed:?}");
        assert!(elapsed <= Duration::from_secs(3), "elapsed={elapsed:?}");

        // poison 済みの接続は socket に触れずに拒否するため、client が閉じたか
        // どうかに依存しない。合図の前に確認する。
        let err = connection
            .send_frame(&big_frame, test_timeout())
            .expect_err("connection must be poisoned after a send timeout");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        let _ = release_tx.send(());
        let _ = client_thread.join();
    }

    /// A3（#820 レビュー指摘。REPAIR-4・REPAIR-5・IO-1・P1-3）: 公開 API
    /// （[`UdsServer`]・[`UdsConnection`]・[`JsonLinesServerObserver`]）だけを
    /// 使い、Accept 成功・Recv 成功・Recv 拒否（`Ack` 受信）・poison 後の拒否・
    /// Send 成功のそれぞれが `io_server` の JSON 行として観測フックへ届くことを
    /// 確認する。`UdsServer::bind`・`UdsServer::accept` へ渡す観測フックが
    /// I/O をせず、`drain_lines` を呼んだ呼び出し元が初めて中身を取り出せる
    /// ことの確認も兼ねる（[`crate::observe::ServerObserver`] のドキュメント
    /// 「`on_event` は I/O をしない」参照）。
    #[test]
    fn a3_uds_json_lines_server_observer_records_accept_recv_send_and_poison_events() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let mut server = fandhe_container_io::UdsServer::bind(
            &socket_path,
            ReceiveLimits::default(),
            JsonLinesServerObserver::new(),
        )
        .expect("bind must succeed on a private, empty path");

        // 1 本目の接続: Write を受信し（Recv 成功）、Ack を送り返す（Send 成功）。
        let connect_path = socket_path.clone();
        let ok_client = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&connect_path).expect("client must connect");
            let request = Frame::new(FrameKind::Write, vec![0x01]).expect("frame must construct");
            stream
                .write_all(&request.encode())
                .expect("client write must succeed");
            let mut header = [0u8; fandhe_container_io::FRAME_HEADER_LEN];
            stream
                .read_exact(&mut header)
                .expect("client must read the response header");
            let parsed_header = fandhe_container_io::FrameHeader::from_bytes(header)
                .expect("response header must be valid");
            let mut body = vec![0u8; parsed_header.body_len()];
            stream
                .read_exact(&mut body)
                .expect("client must read the response body");
        });

        let mut ok_connection = server
            .accept(test_timeout(), JsonLinesServerObserver::new())
            .expect("server must accept the first client connection");
        let received = ok_connection
            .recv_frame(test_timeout())
            .expect("server must receive the client's Write frame");
        assert_eq!(received.kind(), FrameKind::Write);
        let ack = Frame::new(FrameKind::Ack, vec![0x01]).expect("ack frame must construct");
        ok_connection
            .send_frame(&ack, test_timeout())
            .expect("server must be able to send the ack frame");
        ok_client.join().expect("client thread must not panic");

        let ok_lines = ok_connection.observer_mut().drain_lines();
        assert!(
            ok_lines
                .iter()
                .any(|line| line.contains("\"op\":\"recv\"") && line.contains("\"outcome\":\"ok\"")),
            "expected a successful recv event: {ok_lines:?}"
        );
        assert!(
            ok_lines
                .iter()
                .any(|line| line.contains("\"op\":\"send\"") && line.contains("\"outcome\":\"ok\"")),
            "expected a successful send event: {ok_lines:?}"
        );

        // 2 本目の接続: プロトコル違反（`Ack` を受信）で拒否させ、poison 後の
        // 拒否も観測させる。
        let connect_path = socket_path.clone();
        let poison_client = std::thread::spawn(move || {
            let mut stream = UnixStream::connect(&connect_path).expect("client must connect");
            let bad_frame =
                Frame::new(FrameKind::Ack, vec![0x00]).expect("ack frame must construct");
            stream
                .write_all(&bad_frame.encode())
                .expect("client write must succeed");
            std::thread::sleep(Duration::from_millis(200));
        });

        let mut poisoned_connection = server
            .accept(test_timeout(), JsonLinesServerObserver::new())
            .expect("server must accept the second client connection");
        let err = poisoned_connection
            .recv_frame(test_timeout())
            .expect_err("a client-originated Ack frame must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
        let err = poisoned_connection
            .recv_frame(test_timeout())
            .expect_err("a poisoned connection must not be reused for recv");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
        let _ = poison_client.join();

        let poisoned_lines = poisoned_connection.observer_mut().drain_lines();
        assert!(
            poisoned_lines.iter().any(|line| {
                line.contains("\"op\":\"recv\"")
                    && line.contains("\"kind\":\"ACK\"")
                    && line.contains("\"reason\":\"failure\"")
            }),
            "expected a rejected recv event carrying the offending kind: {poisoned_lines:?}"
        );
        assert!(
            poisoned_lines
                .iter()
                .any(|line| line.contains("\"reason\":\"rejected_poisoned\"")),
            "expected a rejected_poisoned event after the connection was poisoned: {poisoned_lines:?}"
        );

        // server 自体の観測フックには両方の accept 成功イベントが積まれている。
        let accept_lines = server.observer_mut().drain_lines();
        let accept_ok_count = accept_lines
            .iter()
            .filter(|line| {
                line.contains("\"op\":\"accept\"") && line.contains("\"outcome\":\"ok\"")
            })
            .count();
        assert_eq!(
            accept_ok_count, 2,
            "expected exactly two successful accept events: {accept_lines:?}"
        );
    }

    /// A1・REPAIR-4（#820 レビュー指摘）: `UdsServer::accept` のタイムアウトも
    /// `ServerOp::Accept`・`ServerOutcome::Failure` として観測フックへ通知される
    /// （成功だけでなく失敗も含め、全分岐で 1 回通知する契約の確認）。
    #[test]
    fn a1_uds_accept_timeout_is_observed_as_failure() {
        let dir = TempSocketDir::new();
        let mut server = fandhe_container_io::UdsServer::bind(
            &dir.socket_path(),
            ReceiveLimits::default(),
            JsonLinesServerObserver::new(),
        )
        .expect("bind must succeed on a private, empty path");

        let timeout = IoTimeout::new(Duration::from_millis(200)).expect("200ms must be valid");
        let err = server
            .accept(timeout, NoopServerObserver)
            .expect_err("accept without any client must time out");
        assert_eq!(err.code(), IoErrorCode::Timeout);

        let lines = server.observer_mut().drain_lines();
        assert_eq!(
            lines.len(),
            1,
            "expected exactly one accept event: {lines:?}"
        );
        let line = &lines[0];
        assert!(line.contains("\"op\":\"accept\""), "line={line}");
        assert!(line.contains("\"outcome\":\"error\""), "line={line}");
        assert!(line.contains("\"reason\":\"failure\""), "line={line}");
        assert!(line.contains("\"accept_aborted_retries\":0"), "line={line}");
    }

    /// 分割（split。#1118・IO-1・P1-3・REPAIR-5・TASK-13.4）の結合試験。
    mod split {
        use std::sync::mpsc;

        use fandhe_container_io::{FRAME_HEADER_LEN, SplitTransport, UdsConnection, UdsServer};

        use super::*;

        /// bind → client connect → accept までを済ませ、server 側の接続と client 側の
        /// stream を返す（listen 開始後の connect は accept 前でも成立する）。
        fn connected<O, C>(
            dir: &TempSocketDir,
            limits: ReceiveLimits,
            server_observer: O,
            conn_observer: C,
        ) -> (UdsServer<O>, UdsConnection<C>, UnixStream)
        where
            O: fandhe_container_io::ServerObserver,
            C: fandhe_container_io::ServerObserver,
        {
            let mut server = UdsServer::bind(&dir.socket_path(), limits, server_observer)
                .expect("bind must succeed on a private, empty path");
            let client = UnixStream::connect(dir.socket_path()).expect("client must connect");
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("client read timeout must be settable");
            let connection = server
                .accept(test_timeout(), conn_observer)
                .expect("server must accept the client connection");
            (server, connection, client)
        }

        fn read_frame(stream: &mut UnixStream) -> Frame {
            let mut header = [0u8; FRAME_HEADER_LEN];
            stream
                .read_exact(&mut header)
                .expect("client must read the frame header");
            let parsed = fandhe_container_io::FrameHeader::from_bytes(header)
                .expect("frame header must be valid");
            let mut body = vec![0u8; parsed.body_len()];
            stream
                .read_exact(&mut body)
                .expect("client must read the frame body");
            Frame::decode_body(parsed, &body).expect("frame must decode")
        }

        /// IO-1・#1118（受け入れ基準 1）: 分割後の送信側・受信側を別スレッドから並行に使い、
        /// 64 件の Write に対し送信順どおり 64 件の Ack を返せる。
        #[test]
        fn io1_1118_split_halves_pipeline_concurrently() {
            const N: u8 = 64;
            let dir = TempSocketDir::new();
            let (_server, connection, mut client) = connected(
                &dir,
                ReceiveLimits::default(),
                NoopServerObserver,
                NoopServerObserver,
            );
            let (mut send, mut recv) = connection.split().expect("split must succeed");

            let (tx, rx) = mpsc::channel::<u8>();
            let recv_thread = std::thread::spawn(move || {
                for _ in 0..N {
                    let frame = recv
                        .recv_frame(test_timeout())
                        .expect("recv half must receive a Write frame");
                    assert_eq!(frame.kind(), FrameKind::Write);
                    let id = *frame.payload().first().expect("payload must hold an id");
                    tx.send(id).expect("send thread must be alive");
                }
                recv
            });
            let send_thread = std::thread::spawn(move || {
                for _ in 0..N {
                    let id = rx.recv().expect("recv thread must forward ids");
                    let ack = Frame::new(FrameKind::Ack, vec![id]).expect("ack must construct");
                    send.send_frame(&ack, test_timeout())
                        .expect("send half must send the ack");
                }
                send
            });

            let mut writer = client.try_clone().expect("client stream must clone");
            let client_writer = std::thread::spawn(move || {
                for i in 0..N {
                    let frame = Frame::new(FrameKind::Write, vec![i]).expect("frame must build");
                    writer
                        .write_all(&frame.encode())
                        .expect("client write must succeed");
                }
            });
            for i in 0..N {
                let ack = read_frame(&mut client);
                assert_eq!(ack.kind(), FrameKind::Ack);
                assert_eq!(ack.payload(), &[i]);
            }
            client_writer.join().expect("client writer must not panic");
            let _recv = recv_thread.join().expect("recv thread must not panic");
            let _send = send_thread.join().expect("send thread must not panic");
        }

        /// P1-3・#1118（受け入れ基準 2）: 受信側がエラーになると、送信側は I/O なしで
        /// `Unavailable` になり、client は接続の shutdown（EOF）を観測する。
        #[test]
        fn p1_3_1118_recv_half_error_poisons_send_half() {
            let dir = TempSocketDir::new();
            let (_server, connection, mut client) = connected(
                &dir,
                ReceiveLimits::default(),
                NoopServerObserver,
                NoopServerObserver,
            );
            let (mut send, mut recv) = connection.split().expect("split must succeed");

            client
                .write_all(&[0xFFu8; FRAME_HEADER_LEN])
                .expect("client garbage write must succeed");
            let err = recv
                .recv_frame(test_timeout())
                .expect_err("a corrupted header must be rejected");
            assert_ne!(err.code(), IoErrorCode::Unavailable);

            let ack = Frame::new(FrameKind::Ack, vec![1]).expect("ack must construct");
            let err = send
                .send_frame(&ack, test_timeout())
                .expect_err("send half must be poisoned by the recv half error");
            assert_eq!(err.code(), IoErrorCode::Unavailable);
            let err = recv
                .recv_frame(test_timeout())
                .expect_err("recv half stays poisoned");
            assert_eq!(err.code(), IoErrorCode::Unavailable);

            let mut buf = [0u8; 1];
            let n = client
                .read(&mut buf)
                .expect("client must observe EOF, not a timeout");
            assert_eq!(n, 0);
        }

        /// P1-3・REPAIR-5・#1118（受け入れ基準 2）: 送信側のエラーは、ブロック中の
        /// 受信側を期限（5 秒）を待たず速やかに `Unavailable` で起こす。
        #[test]
        fn p1_3_1118_send_half_error_poisons_recv_half_and_wakes_it() {
            let dir = TempSocketDir::new();
            let (_server, connection, client) = connected(
                &dir,
                ReceiveLimits::default(),
                NoopServerObserver,
                NoopServerObserver,
            );
            let (mut send, mut recv) = connection.split().expect("split must succeed");

            let recv_thread = std::thread::spawn(move || {
                let result = recv.recv_frame(test_timeout());
                (recv, result, Instant::now())
            });
            std::thread::sleep(Duration::from_millis(200));

            // client は何も読まないため、送信バッファを溢れさせる大きさのフレームは
            // 期限で Timeout になる（EPIPE に依存せず Linux / macOS で同じ結果になる）。
            let big = Frame::new(FrameKind::Write, vec![0x5au8; 16 * 1024 * 1024])
                .expect("large frame must construct");
            let short = IoTimeout::new(Duration::from_millis(300)).expect("300ms must be valid");
            let err = send
                .send_frame(&big, short)
                .expect_err("send to a non-reading peer must time out");
            assert_eq!(err.code(), IoErrorCode::Timeout);
            let failed_at = Instant::now();

            let (mut recv, result, woke_at) = recv_thread.join().expect("recv must not panic");
            let err = result.expect_err("the blocked recv must be woken with an error");
            assert_eq!(err.code(), IoErrorCode::Unavailable);
            assert!(
                woke_at.saturating_duration_since(failed_at) < Duration::from_secs(2),
                "recv must wake promptly after the send half failed"
            );
            let err = recv
                .recv_frame(test_timeout())
                .expect_err("recv half stays poisoned");
            assert_eq!(err.code(), IoErrorCode::Unavailable);
            drop(client);
        }

        /// REPAIR-5・#1118: `with_observer` のクロージャが保持中でも、送信側の
        /// `send_frame` は観測ロックを待たず期限内に完了する。
        #[test]
        fn repair5_1118_send_half_does_not_block_on_held_observer() {
            let dir = TempSocketDir::new();
            let (_server, connection, mut client) = connected(
                &dir,
                ReceiveLimits::default(),
                NoopServerObserver,
                NoopServerObserver,
            );
            let (mut send, recv) = connection.split().expect("split must succeed");
            let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let holder = std::thread::spawn(move || {
                recv.with_observer(|_| {
                    held_tx.send(()).expect("held signal");
                    let _ = release_rx.recv_timeout(Duration::from_secs(10));
                });
                recv
            });
            held_rx.recv().expect("observer must be held");

            let ack = Frame::new(FrameKind::Ack, vec![7]).expect("ack must construct");
            let started = Instant::now();
            send.send_frame(&ack, test_timeout())
                .expect("send must succeed while the observer is held");
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "send must not wait for the observer lock"
            );
            release_tx.send(()).expect("release");
            let _recv = holder.join().expect("holder must not panic");
            let mut buf = [0u8; 1];
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            assert!(client.read(&mut buf).expect("client read") == 1);
        }

        /// REPAIR-4・#1118: `with_observer` のクロージャが保持中に送信側が I/O を終えても、
        /// そのイベントは欠落せず、保持側が解放した後にフックへ適用される。
        #[test]
        fn a3_1118_event_during_held_observer_is_not_lost() {
            let dir = TempSocketDir::new();
            let (_server, connection, mut client) = connected(
                &dir,
                ReceiveLimits::default(),
                NoopServerObserver,
                JsonLinesServerObserver::new(),
            );
            let (mut send, recv) = connection.split().expect("split must succeed");
            let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            let holder = std::thread::spawn(move || {
                recv.with_observer(|_| {
                    held_tx.send(()).expect("held signal");
                    let _ = release_rx.recv_timeout(Duration::from_secs(10));
                });
                recv
            });
            held_rx.recv().expect("observer must be held");

            let ack = Frame::new(FrameKind::Ack, vec![7]).expect("ack must construct");
            send.send_frame(&ack, test_timeout())
                .expect("send must succeed while the observer is held");
            release_tx.send(()).expect("release");
            let recv = holder.join().expect("holder must not panic");

            let lines = recv.with_observer(|o| o.drain_lines());
            assert_eq!(
                lines
                    .iter()
                    .filter(|l| l.contains("\"op\":\"send\"") && l.contains("\"outcome\":\"ok\""))
                    .count(),
                1,
                "the send event must be preserved exactly once: {lines:?}"
            );
            let mut buf = [0u8; 1];
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            assert!(client.read(&mut buf).expect("client read") == 1);
        }

        /// REPAIR-5・#1118（受け入れ基準 3）: 沈黙する相手に対し受信側は期限で `Timeout`、
        /// 以後は `Unavailable`。
        #[test]
        fn repair5_1118_recv_half_times_out_on_silent_peer() {
            let dir = TempSocketDir::new();
            let (_server, connection, _client) = connected(
                &dir,
                ReceiveLimits::default(),
                NoopServerObserver,
                NoopServerObserver,
            );
            let (_send, mut recv) = connection.split().expect("split must succeed");

            let timeout = IoTimeout::new(Duration::from_millis(300)).expect("300ms must be valid");
            let started = Instant::now();
            let err = recv
                .recv_frame(timeout)
                .expect_err("recv from a silent peer must time out");
            let elapsed = started.elapsed();
            assert_eq!(err.code(), IoErrorCode::Timeout);
            assert!(elapsed >= Duration::from_millis(300), "elapsed={elapsed:?}");
            assert!(elapsed <= Duration::from_secs(2), "elapsed={elapsed:?}");

            let err = recv
                .recv_frame(test_timeout())
                .expect_err("recv half must be poisoned after a timeout");
            assert_eq!(err.code(), IoErrorCode::Unavailable);
        }

        /// TASK-13.4・#1118（受け入れ基準 3）: 受信側は bind 時の `ReceiveLimits` を引き継ぎ、
        /// 上限超過を本体を読む前に拒否する。
        #[test]
        fn f_1118_recv_half_honors_receive_limits_passed_to_bind() {
            let dir = TempSocketDir::new();
            let small = ReceiveLimits::new(8, 8).expect("8 bytes must be a valid limit");
            let (_server, connection, mut client) =
                connected(&dir, small, NoopServerObserver, NoopServerObserver);
            let (_send, mut recv) = connection.split().expect("split must succeed");

            let frame = Frame::new(FrameKind::Write, vec![0u8; 9]).expect("frame must build");
            let encoded = frame.encode();
            let header = encoded
                .get(..FRAME_HEADER_LEN)
                .expect("encoded frame must contain a full header");
            client
                .write_all(header)
                .expect("client header write must succeed");

            let err = recv
                .recv_frame(test_timeout())
                .expect_err("a Write frame over the bind-time limit must be rejected");
            assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
            assert!(err.message().contains('8'));
            let err = recv
                .recv_frame(test_timeout())
                .expect_err("recv half must be poisoned");
            assert_eq!(err.code(), IoErrorCode::Unavailable);
        }

        /// IO-1・#1118: 送信側を drop すると書き込み側が half-close され client は EOF を
        /// 読むが、受信側はその後も client からのフレームを受信できる。
        #[test]
        fn io1_1118_send_half_drop_half_closes_write_side() {
            let dir = TempSocketDir::new();
            let (_server, connection, mut client) = connected(
                &dir,
                ReceiveLimits::default(),
                NoopServerObserver,
                NoopServerObserver,
            );
            let (send, mut recv) = connection.split().expect("split must succeed");
            drop(send);

            let mut buf = [0u8; 1];
            let n = client
                .read(&mut buf)
                .expect("client must observe EOF after the send half is dropped");
            assert_eq!(n, 0);

            let frame = Frame::new(FrameKind::Write, vec![7, 8]).expect("frame must build");
            client
                .write_all(&frame.encode())
                .expect("client write must still succeed");
            let received = recv
                .recv_frame(test_timeout())
                .expect("recv half must still receive after the send half is dropped");
            assert_eq!(received.kind(), FrameKind::Write);
            assert_eq!(received.payload(), &[7, 8]);
        }

        /// IO-1・REPAIR-5・#1118（O_NONBLOCK 共有の不変条件）: 相手が切断済みなら送信側は
        /// 期限（5 秒）を待たず速やかに `Unavailable` を返す。
        #[test]
        fn io1_1118_send_half_fails_fast_after_peer_close() {
            let dir = TempSocketDir::new();
            let (_server, connection, client) = connected(
                &dir,
                ReceiveLimits::default(),
                NoopServerObserver,
                NoopServerObserver,
            );
            let (mut send, _recv) = connection.split().expect("split must succeed");
            drop(client);

            let ack = Frame::new(FrameKind::Ack, vec![1]).expect("ack must construct");
            let started = Instant::now();
            let err = send
                .send_frame(&ack, test_timeout())
                .expect_err("send to a closed peer must fail");
            assert_eq!(err.code(), IoErrorCode::Unavailable);
            assert!(started.elapsed() < Duration::from_secs(2));
        }

        /// REPAIR-4・#1118: 両半分は 1 つの観測フックを共有し、Recv / Send の成功・失敗・
        /// poison 拒否がすべて同じフックに記録される。
        #[test]
        fn a3_1118_split_halves_share_observer() {
            let dir = TempSocketDir::new();
            let (_server, connection, mut client) = connected(
                &dir,
                ReceiveLimits::default(),
                NoopServerObserver,
                JsonLinesServerObserver::new(),
            );
            let (mut send, mut recv) = connection.split().expect("split must succeed");

            let request = Frame::new(FrameKind::Write, vec![1]).expect("frame must build");
            client
                .write_all(&request.encode())
                .expect("client write must succeed");
            recv.recv_frame(test_timeout())
                .expect("recv half must receive the Write frame");
            let ack = Frame::new(FrameKind::Ack, vec![1]).expect("ack must construct");
            send.send_frame(&ack, test_timeout())
                .expect("send half must send the ack");

            client
                .write_all(&[0xFFu8; FRAME_HEADER_LEN])
                .expect("client garbage write must succeed");
            recv.recv_frame(test_timeout())
                .expect_err("a corrupted header must be rejected");
            send.send_frame(&ack, test_timeout())
                .expect_err("send half must be poisoned");

            // どちらの半分から見ても同じフックである。
            let lines = send.with_observer(|o| o.drain_lines());
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains("\"op\":\"recv\"") && l.contains("\"outcome\":\"ok\"")),
                "expected a successful recv event: {lines:?}"
            );
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains("\"op\":\"send\"") && l.contains("\"outcome\":\"ok\"")),
                "expected a successful send event: {lines:?}"
            );
            assert!(
                lines.iter().any(|l| l.contains("\"reason\":\"failure\"")),
                "expected a failed recv event: {lines:?}"
            );
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains("\"reason\":\"rejected_poisoned\"")),
                "expected a rejected_poisoned send event: {lines:?}"
            );
            let rest = recv.with_observer(|o| o.drain_lines());
            assert!(
                rest.is_empty(),
                "the hook is shared, so it is drained: {rest:?}"
            );
        }

        /// P1-3・#1118: poison 済みの接続の `split` は `Unavailable`。
        #[test]
        fn p1_3_1118_split_rejects_poisoned_connection() {
            let dir = TempSocketDir::new();
            let (_server, mut connection, mut client) = connected(
                &dir,
                ReceiveLimits::default(),
                NoopServerObserver,
                NoopServerObserver,
            );
            client
                .write_all(&[0xFFu8; FRAME_HEADER_LEN])
                .expect("client garbage write must succeed");
            connection
                .recv_frame(test_timeout())
                .expect_err("a corrupted header must be rejected");
            let err = connection
                .split()
                .expect_err("a poisoned connection must not split");
            assert_eq!(err.code(), IoErrorCode::Unavailable);
        }
    }
}

/// TASK-13.2.1: UDS が使えない OS（Windows）での期待挙動。CI 通過のための
/// skip ではなく、非対応 OS でのスタブ挙動を具体値で検証するテスト
/// （ci.md「実機前提テスト」節の対象外。std が UDS を提供しない OS 一般の
/// 期待挙動を確かめるもの）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn io1_uds_bind_unimplemented_on_unsupported_platform() {
    use fandhe_container_io::{IoErrorCode, NoopServerObserver, ReceiveLimits};

    let dir = std::env::temp_dir().join("fcio-unsupported-platform-test");
    let err = fandhe_container_io::UdsServer::bind(
        &dir.join("s.sock"),
        ReceiveLimits::default(),
        NoopServerObserver,
    )
    .expect_err("unsupported platform must reject bind");
    assert_eq!(err.code(), IoErrorCode::Unimplemented);
}
