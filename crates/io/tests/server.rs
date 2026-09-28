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
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_io::{
        Frame, FrameKind, FrameReceiver, FrameSender, IoErrorCode, IoTimeout,
        MAX_CONTROL_PAYLOAD_LEN,
    };

    /// テストごとに固有かつ短いソケットディレクトリを作る（macOS の
    /// `/var/folders/...` が長く、sun_path の上限〔104 バイト〕に近づくため、
    /// ディレクトリ名・ソケット名の双方を短く保つ）。作成した一時ディレクトリは
    /// `Drop` で必ず削除する。
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
        let server = fandhe_container_io::UdsServer::bind(&socket_path)
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
            .accept(test_timeout())
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
        let server = fandhe_container_io::UdsServer::bind(&dir.socket_path())
            .expect("bind must succeed on a private, empty path");

        let timeout = IoTimeout::new(Duration::from_millis(300)).expect("300ms must be valid");
        let started = Instant::now();
        let err = server
            .accept(timeout)
            .expect_err("accept without any client must time out");
        let elapsed = started.elapsed();

        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(elapsed >= Duration::from_millis(300), "elapsed={elapsed:?}");
        assert!(elapsed <= Duration::from_secs(2), "elapsed={elapsed:?}");
    }

    /// REPAIR-5: 接続だけして何も送らない相手に対しては `recv_frame` が上限時間で
    /// `Timeout` を返す。
    #[test]
    fn repair5_uds_recv_times_out_on_silent_peer() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let server = fandhe_container_io::UdsServer::bind(&socket_path)
            .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = UnixStream::connect(&connect_path).expect("client must connect");
            // 何も送らずに、server 側の recv がタイムアウトするまで接続を保持する。
            std::thread::sleep(Duration::from_millis(600));
            drop(stream);
        });

        let mut connection = server
            .accept(test_timeout())
            .expect("server must accept the client connection");

        let timeout = IoTimeout::new(Duration::from_millis(300)).expect("300ms must be valid");
        let started = Instant::now();
        let err = connection
            .recv_frame(timeout)
            .expect_err("recv from a silent peer must time out");
        let elapsed = started.elapsed();

        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(elapsed >= Duration::from_millis(300), "elapsed={elapsed:?}");
        assert!(elapsed <= Duration::from_secs(2), "elapsed={elapsed:?}");

        client_thread.join().expect("client thread must not panic");
    }

    /// REPAIR-5: 1 バイトずつ間隔を空けて送ってくる相手でも、フレーム全体の期限で
    /// `Timeout` になる（1 回の read ごとの期限ではないことの確認）。
    #[test]
    fn repair5_uds_recv_times_out_on_trickling_peer() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let server = fandhe_container_io::UdsServer::bind(&socket_path)
            .expect("bind must succeed on a private, empty path");

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
            drop(stream);
        });

        let mut connection = server
            .accept(test_timeout())
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

        let _ = client_thread.join();
    }

    /// IO-1: header_crc を 1 ビット反転させたヘッダを送ると `DataLoss` が返る。
    /// その後の呼び出しは P1-3 により `Unavailable` になる。
    #[test]
    fn io1_uds_recv_rejects_corrupted_header() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let server = fandhe_container_io::UdsServer::bind(&socket_path)
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
            .accept(test_timeout())
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
        let server = fandhe_container_io::UdsServer::bind(&socket_path)
            .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = UnixStream::connect(&connect_path).expect("client must connect");
            drop(stream);
        });
        client_thread.join().expect("client thread must not panic");

        let mut connection = server
            .accept(test_timeout())
            .expect("server must accept the (already closed) client connection");

        let err = connection
            .recv_frame(test_timeout())
            .expect_err("recv on a peer-closed connection must report unavailable");
        assert_eq!(err.code(), IoErrorCode::Unavailable);
    }

    /// TASK-13.4・IO-1（#796・#820 レビュー指摘の 0b・0 コミット項目）: 制御
    /// フレーム（`Flush`）が `MAX_CONTROL_PAYLOAD_LEN` を超える長さを申告すると、
    /// `recv_frame` は本体を読む前に `ReceiveLimits::admit` により
    /// `ResourceExhausted` で拒否する。その後は P1-3 により `Unavailable` になる。
    #[test]
    fn io1_uds_recv_rejects_oversized_control_frame_before_body_read() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let server = fandhe_container_io::UdsServer::bind(&socket_path)
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
            .accept(test_timeout())
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

    /// IO-1・REPAIR-2（#820 レビュー指摘）: サーバー側はクライアントから
    /// `Ack` フレームを受け取ることを想定していない（サーバーが `Ack` を返す側）。
    /// `recv_frame` は本体を読む前に `InvalidArgument` で拒否し、その後は P1-3
    /// により `Unavailable` になる。
    #[test]
    fn io1_uds_recv_rejects_client_originated_ack_frame() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let server = fandhe_container_io::UdsServer::bind(&socket_path)
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
            .accept(test_timeout())
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
        let server = fandhe_container_io::UdsServer::bind(&socket_path)
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
            .accept(test_timeout())
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
        let server = fandhe_container_io::UdsServer::bind(&socket_path)
            .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = UnixStream::connect(&connect_path).expect("client must connect");
            // 何も送らないまま保持する（recv がタイムアウトで poison するのを待つ）。
            stream
                .set_read_timeout(Some(Duration::from_millis(700)))
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
            .accept(test_timeout())
            .expect("server must accept the client connection");

        let timeout = IoTimeout::new(Duration::from_millis(300)).expect("300ms must be valid");
        let err = connection
            .recv_frame(timeout)
            .expect_err("recv from a silent peer must time out and poison the connection");
        assert_eq!(err.code(), IoErrorCode::Timeout);

        let err = connection
            .send_frame(
                &Frame::new(FrameKind::Ack, vec![]).expect("ack frame must construct"),
                test_timeout(),
            )
            .expect_err("send after poisoning must be rejected without touching the socket");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        client_thread.join().expect("client thread must not panic");
    }

    /// security.md（UDS 観点）: 既存パスがあるとき `bind` は `InvalidArgument` を
    /// 返し、既存ファイルを消さない。
    #[test]
    fn io1_uds_bind_rejects_existing_path() {
        let dir = TempSocketDir::new();
        let path = dir.socket_path();
        std::fs::write(&path, b"not a socket").expect("must be able to create a placeholder file");

        let err = fandhe_container_io::UdsServer::bind(&path)
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

        let err = fandhe_container_io::UdsServer::bind(&path)
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

        let err = fandhe_container_io::UdsServer::bind(&path)
            .expect_err("bind under a 0o755 parent directory must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);

        assert!(!path.exists(), "no socket file must be created");
    }

    /// security.md（UDS 観点）: bind 後のソケットファイルは mode 0600 であり、
    /// `UdsServer` を drop するとソケットファイルが削除される。
    #[test]
    fn io1_uds_socket_file_mode_and_cleanup() {
        let dir = TempSocketDir::new();
        let path = dir.socket_path();
        let server =
            fandhe_container_io::UdsServer::bind(&path).expect("bind must succeed on a fresh path");
        assert_eq!(server.path(), path.as_path());

        let meta = std::fs::symlink_metadata(&path).expect("socket file must exist after bind");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        drop(server);
        assert!(!path.exists(), "socket file must be removed after drop");
    }

    /// REPAIR-5（#820 レビュー指摘）: 書き込みがブロックし続ける相手に対しては
    /// `send_frame` がフレーム全体の期限で `Timeout` を返し（送信側の
    /// `write_all_until` のタイムアウト経路）、その後は P1-3 により
    /// `Unavailable` になる。
    #[test]
    fn repair5_uds_send_times_out_on_unresponsive_peer() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let server = fandhe_container_io::UdsServer::bind(&socket_path)
            .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let stream = UnixStream::connect(&connect_path).expect("client must connect");
            // 接続を保持したまま何も読まない。カーネルの送信バッファ（既定は
            // 数百 KiB 程度）を溢れさせるには十分大きいペイロードが必要
            // （send_frame のテスト側で 16 MiB を送る）。
            std::thread::sleep(Duration::from_millis(900));
            drop(stream);
        });

        let mut connection = server
            .accept(test_timeout())
            .expect("server must accept the client connection");

        let big_payload = vec![0x5au8; 16 * 1024 * 1024];
        let big_frame =
            Frame::new(FrameKind::Write, big_payload).expect("large frame must construct");

        let timeout = IoTimeout::new(Duration::from_millis(300)).expect("300ms must be valid");
        let started = Instant::now();
        let err = connection
            .send_frame(&big_frame, timeout)
            .expect_err("send to an unresponsive peer must time out");
        let elapsed = started.elapsed();

        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(elapsed >= Duration::from_millis(300), "elapsed={elapsed:?}");
        assert!(elapsed <= Duration::from_secs(3), "elapsed={elapsed:?}");

        let err = connection
            .send_frame(&big_frame, test_timeout())
            .expect_err("connection must be poisoned after a send timeout");
        assert_eq!(err.code(), IoErrorCode::Unavailable);

        let _ = client_thread.join();
    }
}

/// TASK-13.2.1: UDS が使えない OS（Windows）での期待挙動。CI 通過のための
/// skip ではなく、非対応 OS でのスタブ挙動を具体値で検証するテスト
/// （ci.md「実機前提テスト」節の対象外。std が UDS を提供しない OS 一般の
/// 期待挙動を確かめるもの）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn io1_uds_bind_unimplemented_on_unsupported_platform() {
    use fandhe_container_io::IoErrorCode;

    let dir = std::env::temp_dir().join("fcio-unsupported-platform-test");
    let err = fandhe_container_io::UdsServer::bind(&dir.join("s.sock"))
        .expect_err("unsupported platform must reject bind");
    assert_eq!(err.code(), IoErrorCode::Unimplemented);
}
