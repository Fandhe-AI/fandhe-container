//! バッチ write-back（[`fandhe_container_io::writeback::serve_connection`]）の
//! UDS 経由の結合試験（TASK-13.2.2・IO-1・#822・受入基準 1）。
//!
//! [`fandhe_container_io::UdsServer`]（TASK-13.2.1・#820）が accept した実際の
//! UDS 接続の上で `serve_connection` を動かし、std の `UnixStream`（client 役）
//! から送った `Write` フレームが実際にディスクへ書き込まれ、到着順に ACK が
//! 返ることを確かめる。Linux / macOS 限定（`UdsServer` が UDS を実装する OS。
//! `tests/server.rs` と同じ扱い）。Windows では `UdsServer::bind` 自体が
//! `Unimplemented` を返すことを別テストで確認し、3 OS すべてでテストが空に
//! ならないようにする。

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::io::{Read, Write};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_io::{
        AppendFileSink, BatchConfig, Frame, FrameHeader, FrameKind, IoTimeout, NoopServerObserver,
        ReceiveLimits, UdsServer, WritebackTimeouts, serve_connection,
    };

    /// テストごとに固有かつ短いソケットディレクトリを作る（`tests/server.rs`
    /// の `TempSocketDir` と同じ理由・同じ実装）。
    struct TempSocketDir {
        path: PathBuf,
    }

    impl TempSocketDir {
        fn new() -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let dir = std::env::temp_dir().join(format!("fcio-wb-{pid}-{n}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .expect("must be able to create a temp dir for the socket");
            Self { path: dir }
        }

        fn socket_path(&self) -> PathBuf {
            self.path.join("s.sock")
        }

        fn output_path(&self) -> PathBuf {
            self.path.join("out.bin")
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

    fn writeback_timeouts() -> WritebackTimeouts {
        WritebackTimeouts {
            recv: test_timeout(),
            send: test_timeout(),
        }
    }

    /// client 役から `id`・`body` の Write フレームをワイヤーへ送る
    /// （`fandhe_container_io::payload::encode_request` と同じレイアウト
    /// `[request_id: u64 LE][body]` を手組みする。client 側の UDS `connect` 経由の
    /// 具象実装〔`PipelineClient` との本番結合〕はまだないため、テストでは
    /// std の `UnixStream` を代用する。`tests/server.rs` と同じ方針）。
    fn send_write(stream: &mut UnixStream, id: u64, body: &[u8]) {
        let mut payload = Vec::with_capacity(8 + body.len());
        payload.extend_from_slice(&id.to_le_bytes());
        payload.extend_from_slice(body);
        let frame = Frame::new(FrameKind::Write, payload).expect("write frame must construct");
        stream
            .write_all(&frame.encode())
            .expect("client write must succeed");
    }

    fn send_flush(stream: &mut UnixStream, id: u64) {
        let frame = Frame::new(FrameKind::Flush, id.to_le_bytes().to_vec())
            .expect("flush frame must construct");
        stream
            .write_all(&frame.encode())
            .expect("client flush write must succeed");
    }

    /// client 役でフレームを 1 件受信する（ヘッダ→ body の順に読み切る。
    /// `tests/server.rs` の client 受信ロジックと同じ）。
    fn recv_frame(stream: &mut UnixStream) -> Frame {
        let mut header = [0u8; fandhe_container_io::FRAME_HEADER_LEN];
        stream
            .read_exact(&mut header)
            .expect("client must read the response header");
        let parsed_header = FrameHeader::from_bytes(header).expect("response header must be valid");
        let mut body = vec![0u8; parsed_header.body_len()];
        stream
            .read_exact(&mut body)
            .expect("client must read the response body");
        Frame::decode_body(parsed_header, &body).expect("response frame must decode")
    }

    /// 受信したフレームが `Ack` であることを確認しつつ、その request id を
    /// 取り出す（`fandhe_container_io::decode_ack` は公開 API）。
    fn ack_id(frame: &Frame) -> u64 {
        let ack = fandhe_container_io::decode_ack(frame).expect("frame must be a valid ack");
        assert_eq!(ack.kind(), FrameKind::Ack);
        ack.id().get()
    }

    /// `path` へ接続し、読み取りタイムアウトを設定してから返す（REPAIR-5:
    /// サーバー側が期待した ACK を送り損ねた場合に `read_exact` が無期限に
    /// ブロックし、CI のジョブ全体タイムアウト〔30 分〕までテストが張り付く
    /// ことを防ぐ。client 役は `fandhe_container_io::transport::IoTimeout` を
    /// 使わない素朴な `std::net` 相当の代用実装のため、`set_read_timeout` で
    /// 同種の保護を掛ける）。
    fn connect(path: &std::path::Path) -> UnixStream {
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
            .expect("must be able to set a read timeout on the client stream");
        stream
    }

    /// IO-1 受入基準 1: 既定バッチサイズ（64 件）で 64 件送ると、ACK が
    /// 64 件・id が 0..64 の昇順・種別は `Ack` で届く。最初の ACK を受け取った
    /// 時点で、出力ファイル（別ハンドルで読む）にすでに 64 件ぶんの body が
    /// 挿入順に連結されている（ACK が「書き込み完了後」に届くことの直接確認。
    /// D2）。
    #[test]
    fn io1_uds_writeback_acks_after_batch_write_default_64() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let output_path = dir.output_path();

        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let output_path_for_client = output_path.clone();
        let client_thread = std::thread::spawn(move || {
            let mut stream = connect(&connect_path);
            for id in 0..64u64 {
                send_write(&mut stream, id, &id.to_le_bytes());
            }

            let mut acked_ids = Vec::with_capacity(64);
            let mut snapshot_after_first_ack: Option<Vec<u8>> = None;
            for _ in 0..64 {
                let frame = recv_frame(&mut stream);
                acked_ids.push(ack_id(&frame));
                if snapshot_after_first_ack.is_none() {
                    // D2 の直接確認: 最初の ACK を受け取った「その時点」で出力
                    // ファイル（別ハンドル）を読む。既定バッチサイズ（64）と
                    // 送信件数（64）が一致するため、この 1 バッチが書き込まれて
                    // から初めて ACK が送られ始める。すべて受信し終えてから読むと
                    // 「ACK 後に書かれた」偽陽性を検出できないため、ここで読む。
                    snapshot_after_first_ack =
                        Some(std::fs::read(&output_path_for_client).unwrap_or_default());
                }
            }
            (acked_ids, snapshot_after_first_ack.unwrap_or_default())
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection within the timeout");

        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&output_path)
            .expect("must open output file");
        let mut sink = AppendFileSink::new(file);

        // serve_connection はエラーで終わるまでブロックするため、別スレッドで
        // 動かし、64 件ぶんの ACK を読み終えたクライアントスレッドと合流する
        // （REPAIR-5: スレッドの join にも期限を設ける）。
        let server_thread = std::thread::spawn(move || {
            serve_connection(
                &mut connection,
                BatchConfig::default(),
                &mut sink,
                writeback_timeouts(),
            )
        });

        let (acked_ids, snapshot_after_first_ack) =
            client_thread.join().expect("client thread must not panic");
        assert_eq!(acked_ids, (0..64u64).collect::<Vec<_>>());

        // 最初の ACK を受け取った時点（クライアントスレッド内で読んだスナップ
        // ショット）で、出力ファイルはすでに 64 件ぶんの body を挿入順に連結
        // した内容になっている（D2: ACK は書き込み完了後に送られる）。
        let expected: Vec<u8> = (0..64u64).flat_map(|id| id.to_le_bytes()).collect();
        assert_eq!(snapshot_after_first_ack, expected);

        // 全 ACK 受信後の最終状態も同じ内容のまま（以後の書き込みは起きない）。
        let contents = std::fs::read(&output_path).expect("must read output file");
        assert_eq!(contents, expected);

        // クライアントが切断すると serve_connection は Unavailable で終わる。
        let report = server_thread.join().expect("server thread must not panic");
        assert_eq!(report.stats.acks_sent, 64);
        assert_eq!(report.stats.batches_written, 1);
        assert_eq!(report.stats.discarded_pending_frames, 0);
    }

    /// IO-1: `batch_size = 8` で 16 件送ると、ACK が 8 件ずつ 2 回届く。
    /// 1 回目の ACK 受信時点でファイルに 8 件ぶんの body があり、最終的に
    /// 16 件ぶんになる。
    #[test]
    fn io1_uds_writeback_configurable_batch_size_8() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let output_path = dir.output_path();

        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let output_path_for_client = output_path.clone();
        let client_thread = std::thread::spawn(move || {
            let mut stream = connect(&connect_path);
            // 1 回目のバッチ（8 件）だけを送り、8 件ぶんの ACK を読み切って
            // からスナップショットを取る。2 回目のバッチ（残り 8 件）はまだ
            // サーバーへ送っていないため、サーバー側がバッチ 1 の ACK 送出
            // 直後にバッチ 2 の書き込みへ進めるとしても受信すべきフレームが
            // 無く、スナップショット時点でバッチ 2 の書き込みが完了している
            // ことはあり得ない（テストレースの排除。#822 レビュー指摘）。
            for id in 0..8u64 {
                send_write(&mut stream, id, &id.to_le_bytes());
            }
            let mut acked_ids = Vec::with_capacity(16);
            for _ in 0..8 {
                let frame = recv_frame(&mut stream);
                acked_ids.push(ack_id(&frame));
            }
            // D2 の直接確認: 1 回目のバッチ（8 件）の最後の ACK を受け取った
            // 時点で、出力ファイルにはすでに 8 件ぶんの body しかない（2 回目
            // のバッチの書き込みはまだ起きていない）はず。
            let snapshot_after_8th_ack = std::fs::read(&output_path_for_client).unwrap_or_default();

            for id in 8..16u64 {
                send_write(&mut stream, id, &id.to_le_bytes());
            }
            for _ in 8..16 {
                let frame = recv_frame(&mut stream);
                acked_ids.push(ack_id(&frame));
            }
            (acked_ids, snapshot_after_8th_ack)
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection within the timeout");

        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&output_path)
            .expect("must open output file");
        let mut sink = AppendFileSink::new(file);

        let config = BatchConfig::new(8).expect("8 must be a valid batch size");
        let server_thread = std::thread::spawn(move || {
            serve_connection(&mut connection, config, &mut sink, writeback_timeouts())
        });

        let (acked_ids, snapshot_after_8th_ack) =
            client_thread.join().expect("client thread must not panic");
        assert_eq!(acked_ids, (0..16u64).collect::<Vec<_>>());

        let expected_after_first_batch: Vec<u8> =
            (0..8u64).flat_map(|id| id.to_le_bytes()).collect();
        assert_eq!(snapshot_after_8th_ack, expected_after_first_batch);

        let contents = std::fs::read(&output_path).expect("must read output file");
        let expected: Vec<u8> = (0..16u64).flat_map(|id| id.to_le_bytes()).collect();
        assert_eq!(contents, expected);

        let report = server_thread.join().expect("server thread must not panic");
        assert_eq!(report.stats.acks_sent, 16);
        assert_eq!(report.stats.batches_written, 2);
    }

    /// D4: Write 3 件 + Flush で、ACK 3 件の後に EOF が届く（FlushAck は
    /// 送られない）。
    #[test]
    fn io1_uds_writeback_flush_acks_pending_then_closes() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let output_path = dir.output_path();

        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let mut stream = connect(&connect_path);
            for id in 0..3u64 {
                send_write(&mut stream, id, &id.to_le_bytes());
            }
            send_flush(&mut stream, 3);

            let mut acked_ids = Vec::new();
            loop {
                let mut header = [0u8; fandhe_container_io::FRAME_HEADER_LEN];
                match stream.read_exact(&mut header) {
                    Ok(()) => {}
                    Err(_) => break, // EOF（サーバーが接続を閉じた）
                }
                let parsed_header =
                    FrameHeader::from_bytes(header).expect("response header must be valid");
                let mut body = vec![0u8; parsed_header.body_len()];
                stream
                    .read_exact(&mut body)
                    .expect("client must read the response body");
                let frame =
                    Frame::decode_body(parsed_header, &body).expect("response frame must decode");
                acked_ids.push(ack_id(&frame));
            }
            acked_ids
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection within the timeout");

        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&output_path)
            .expect("must open output file");
        let mut sink = AppendFileSink::new(file);

        let report = serve_connection(
            &mut connection,
            BatchConfig::default(),
            &mut sink,
            writeback_timeouts(),
        );
        assert_eq!(
            report.end.code(),
            fandhe_container_io::IoErrorCode::Unimplemented
        );
        assert_eq!(report.stats.acks_sent, 3);
        // serve_connection が接続を閉じる（drop する）のは呼び出し元がこの
        // 関数から抜けた後なので、ここで connection を明示的に落としてから
        // クライアントの EOF 検出を待つ。
        drop(connection);

        let acked_ids = client_thread.join().expect("client thread must not panic");
        assert_eq!(acked_ids, vec![0, 1, 2]);

        let contents = std::fs::read(&output_path).expect("must read output file");
        let expected: Vec<u8> = (0..3u64).flat_map(|id| id.to_le_bytes()).collect();
        assert_eq!(contents, expected);
    }

    /// D6・REPAIR-2: 4 バイト（request id すら入っていない）の Write を送ると、
    /// ACK は 1 件も届かず EOF になる。
    #[test]
    fn io1_uds_writeback_malformed_write_closes_without_ack() {
        let dir = TempSocketDir::new();
        let socket_path = dir.socket_path();
        let output_path = dir.output_path();

        let mut server =
            UdsServer::bind(&socket_path, ReceiveLimits::default(), NoopServerObserver)
                .expect("bind must succeed on a private, empty path");

        let connect_path = socket_path.clone();
        let client_thread = std::thread::spawn(move || {
            let mut stream = connect(&connect_path);
            let malformed =
                Frame::new(FrameKind::Write, vec![0u8; 4]).expect("short payload must construct");
            stream
                .write_all(&malformed.encode())
                .expect("client write must succeed");

            // サーバーは ACK を送らずに接続を閉じる。読み取りが即座に EOF /
            // エラーになることを確認する。
            let mut buf = [0u8; 1];
            stream.read(&mut buf).unwrap_or(0)
        });

        let mut connection = server
            .accept(test_timeout(), NoopServerObserver)
            .expect("server must accept the client connection within the timeout");

        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&output_path)
            .expect("must open output file");
        let mut sink = AppendFileSink::new(file);

        let report = serve_connection(
            &mut connection,
            BatchConfig::default(),
            &mut sink,
            writeback_timeouts(),
        );
        assert_eq!(report.stats.acks_sent, 0);
        assert_eq!(
            report.end.code(),
            fandhe_container_io::IoErrorCode::InvalidArgument
        );
        drop(connection);

        let read_bytes = client_thread.join().expect("client thread must not panic");
        assert_eq!(read_bytes, 0, "no ack bytes must be received");
    }
}

/// 非対応 OS（Windows）では `UdsServer::bind` が常に `Unimplemented` を返す
/// ことを確認する（`tests/server.rs` の同名テストと同じ方針。3 OS すべてで
/// テストを空にしないため）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn io1_uds_bind_is_unimplemented_on_unsupported_os() {
    use fandhe_container_io::{IoErrorCode, NoopServerObserver, ReceiveLimits, UdsServer};

    let path = std::env::temp_dir().join("fcio-wb-unsupported.sock");
    let err = UdsServer::bind(&path, ReceiveLimits::default(), NoopServerObserver)
        .expect_err("bind must be unimplemented on unsupported OS");
    assert_eq!(err.code(), IoErrorCode::Unimplemented);
}
