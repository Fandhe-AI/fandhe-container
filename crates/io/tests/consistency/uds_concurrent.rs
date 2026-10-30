//! 実ソケット（UDS）越しの並行 write の整合性ケース（TASK-14 追補・#1831・
//! IO-4・REPAIR-6）。
//!
//! [`super::concurrent_write`] はメモリ内トランスポート（[`super::harness::DuplexEnd`]）
//! だけで並行 write を検証している。本モジュールは同じ整合性の主張を、実際の
//! `WritebackSettings::bind` → `accept` → `BoundConnection::serve`（IO-1 の本番
//! 受付経路）で複数の UDS 接続を同時に流して確かめる。ソケットは `UdsServer::bind`
//! の検証（親ディレクトリ権限・既存パス・symlink）と peer credential 検証を
//! 通常どおり通し、生の `UnixListener` で迂回しない。
//!
//! # 範囲と制約
//! - 同じオフセットへの上書き競合は、現行ワイヤー形式（`fandhe_container_io::payload`）
//!   がパス・オフセットを持たず表現できないため対象外。ワイヤー形式の拡張
//!   （IO-1 の I/O 契約の変更）が前提となる。
//! - `UdsServer` は Linux / macOS 限定。Windows では
//!   `io4_uds_concurrent_bind_is_unimplemented_on_unsupported_os` が bind の未対応を
//!   明示する（黙って 0 件にしない）。
//! - 単一 sink モードの並行性を、client 役の std の `UnixStream` でフレームを手組みして確かめる
//!   （`tests/writeback.rs` と同じ方針）。本番クライアント経由のファイル操作は [`super::uds_file_ops`]。
//! - 待ち合わせは `Barrier`・期限つき join・ソケットの read/write timeout で行い、
//!   `sleep` による同期はしない（REPAIR-5）。

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    use fandhe_container_io::{
        BatchConfig, Frame, FrameHeader, FrameKind, InFlightLimit, IoErrorCode, NoopServerObserver,
        SendQueue, SinkOpenMode, WireRequestId, WritebackReport, WritebackSettings,
        WritebackTimeouts, encode_request,
    };

    use super::super::harness::{
        SharedSink, barrier_wait_within, body_for, decompose_records, join_within, open_sink,
        record_client, record_seq, timeout,
    };

    /// 各待ち合わせの期限（REPAIR-5）。
    fn deadline() -> Duration {
        Duration::from_secs(20)
    }

    fn io_timeouts() -> WritebackTimeouts {
        WritebackTimeouts {
            recv: timeout(),
            send: timeout(),
        }
    }

    /// 短いパスの 0700 ディレクトリ（macOS の `sun_path` 104 バイト上限対策。
    /// ソケットも出力ファイルもここに置き、`Drop` で削除する）。
    struct SocketDir {
        path: PathBuf,
    }

    impl SocketDir {
        fn new() -> Self {
            // 残骸・PID 再利用との衝突を避ける排他作成（REPAIR-12・#3435）。
            let path = crate::exclusive_dir::create("fcio-uds")
                .expect("must be able to create a temp dir for the socket");
            // umask の影響を除き、bind の親ディレクトリ権限検証を満たす。
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("must be able to set 0700 on the temp dir");
            Self { path }
        }

        fn socket_path(&self) -> PathBuf {
            self.path.join("s.sock")
        }

        fn out_path(&self, i: usize) -> PathBuf {
            self.path.join(format!("out-{i}.bin"))
        }
    }

    impl Drop for SocketDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// 接続して read/write timeout を付ける（bind 済みなので connect は即成功する）。
    fn connect(path: &std::path::Path) -> UnixStream {
        let stream = UnixStream::connect(path).expect("client must connect to the bound socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("must set read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("must set write timeout");
        stream
    }

    /// 共有の型付きエンコーダ（`encode_request`・`WireRequestId`。REPAIR-2）で Write フレームを
    /// 組み立てて送る。request id は `SendQueue` の採番（client ごとに 0 から連番）を使い、
    /// ACK 待ちを溜めないよう登録直後に外す。
    fn send_write(stream: &mut UnixStream, queue: &mut SendQueue, body: &[u8]) {
        let request = queue
            .register(FrameKind::Write)
            .expect("send queue must issue a request id");
        let id = request.id();
        queue
            .remove(id)
            .expect("issued request id must be removable");
        let frame = encode_request(FrameKind::Write, WireRequestId::from(id), body)
            .expect("write frame must construct");
        stream
            .write_all(&frame.encode())
            .expect("client write must succeed");
    }

    fn recv_ack_id(stream: &mut UnixStream) -> u64 {
        let mut header = [0u8; fandhe_container_io::FRAME_HEADER_LEN];
        stream
            .read_exact(&mut header)
            .expect("client must read the response header");
        let parsed = FrameHeader::from_bytes(header).expect("response header must be valid");
        let mut body = vec![0u8; parsed.body_len()];
        stream
            .read_exact(&mut body)
            .expect("client must read the response body");
        let frame = Frame::decode_body(parsed, &body).expect("response frame must decode");
        let ack = fandhe_container_io::decode_ack(&frame).expect("frame must be a valid ack");
        assert_eq!(ack.kind(), FrameKind::Ack);
        ack.id().get()
    }

    /// 1 シナリオの設定。
    struct Spec {
        clients: u16,
        frames: u32,
        body_len: usize,
        batch: usize,
        /// 全接続で 1 つの出力ファイルを共有するか。
        shared: bool,
        /// true: main が先に全 connect してから accept（accept 順 = client 番号）。
        /// false: 各 client スレッドが並行に connect する。
        preconnect: bool,
    }

    struct Outcome {
        /// accept 順の `serve` の結果。
        reports: Vec<WritebackReport>,
        /// 出力ファイルの内容（共有なら 1 件、別ファイルなら accept 順）。
        contents: Vec<Vec<u8>>,
    }

    /// 実ソケットで `spec` を走らせ、全 client が全 ACK を受け取るところまで確認する。
    fn run(spec: &Spec) -> Outcome {
        // 送信完了前に ACK を読まない client 役がデッドロックしないよう、
        // ソケットバッファに収まる規模に限る。
        let total_bytes = spec.frames as usize * (spec.body_len + 32);
        assert!(
            total_bytes <= 64 * 1024,
            "scenario must fit the socket buffer"
        );

        let dir = SocketDir::new();
        let socket_path = dir.socket_path();
        let settings =
            WritebackSettings::new(BatchConfig::new(spec.batch).expect("valid batch size"));
        let mut server = settings
            .bind(&socket_path, NoopServerObserver)
            .expect("bind must succeed on a private, empty path");

        let barrier = Arc::new(Barrier::new(spec.clients as usize + 1));
        let mut pre_streams: Vec<UnixStream> = Vec::new();
        if spec.preconnect {
            for _ in 0..spec.clients {
                pre_streams.push(connect(&socket_path));
            }
        }
        let mut pre_iter = pre_streams.into_iter();

        let mut client_handles = Vec::new();
        for i in 0..spec.clients {
            let pre = pre_iter.next();
            let barrier = Arc::clone(&barrier);
            let socket_path = socket_path.clone();
            let (frames, body_len) = (spec.frames, spec.body_len);
            client_handles.push(std::thread::spawn(move || {
                let mut stream = pre.unwrap_or_else(|| connect(&socket_path));
                barrier_wait_within(&barrier, deadline());
                let mut queue = SendQueue::new(
                    InFlightLimit::new(1).expect("in-flight limit of 1 must be valid"),
                );
                for seq in 0..frames {
                    send_write(&mut stream, &mut queue, &body_for(i, seq, body_len));
                }
                let acked: Vec<u64> = (0..frames).map(|_| recv_ack_id(&mut stream)).collect();
                // 全 ACK を受け取ってから切断する（discarded_pending_frames == 0）。
                drop(stream);
                acked
            }));
        }
        // 全 client が connect 済みで開始待ちになった後に accept する。
        barrier_wait_within(&barrier, deadline());

        let shared = if spec.shared {
            Some(SharedSink::new(
                open_sink(&dir.out_path(0), SinkOpenMode::CreateOrTruncate)
                    .expect("must create the shared output"),
            ))
        } else {
            None
        };

        let mut server_handles = Vec::new();
        for k in 0..spec.clients as usize {
            let mut connection = server
                .accept(timeout(), NoopServerObserver)
                .expect("server must accept the client connection within the timeout");
            match &shared {
                Some(sink) => {
                    let mut sink = sink.clone();
                    server_handles.push(std::thread::spawn(move || {
                        connection.serve(&mut sink, io_timeouts())
                    }));
                }
                None => {
                    let mut sink = open_sink(&dir.out_path(k), SinkOpenMode::CreateOrTruncate)
                        .expect("must create the output file");
                    server_handles.push(std::thread::spawn(move || {
                        connection.serve(&mut sink, io_timeouts())
                    }));
                }
            }
        }
        drop(shared);

        for handle in client_handles {
            let acked = join_within(handle, deadline());
            assert_eq!(acked, (0..u64::from(spec.frames)).collect::<Vec<_>>());
        }
        let reports: Vec<WritebackReport> = server_handles
            .into_iter()
            .map(|h| join_within(h, deadline()))
            .collect();
        for report in &reports {
            assert_eq!(report.stats.discarded_pending_frames, 0);
            assert_eq!(report.end.code(), IoErrorCode::Unavailable);
        }
        let files = if spec.shared {
            1
        } else {
            spec.clients as usize
        };
        let contents = (0..files)
            .map(|k| std::fs::read(dir.out_path(k)).expect("must read output file"))
            .collect();
        Outcome { reports, contents }
    }

    fn expected_for(client: u16, frames: u32, body_len: usize) -> Vec<u8> {
        (0..frames)
            .flat_map(|seq| body_for(client, seq, body_len))
            .collect()
    }

    fn assert_total_acks(outcome: &Outcome, spec: &Spec) {
        let acks: u64 = outcome.reports.iter().map(|r| r.stats.acks_sent).sum();
        assert_eq!(acks, u64::from(spec.clients) * u64::from(spec.frames));
    }

    /// 共有ファイルの検証: 総レコード数・クライアントごとの完全一致と seq 順、
    /// `check_batches` なら各バッチ（`batch` 件）が単一クライアントの連続 seq だけで
    /// 構成されること。
    fn assert_shared(contents: &[u8], spec: &Spec, check_batches: bool) {
        let records = decompose_records(contents);
        assert_eq!(records.len(), spec.clients as usize * spec.frames as usize);
        assert_eq!(contents.len(), records.iter().map(Vec::len).sum::<usize>());
        for client in 0..spec.clients {
            let actual: Vec<Vec<u8>> = records
                .iter()
                .filter(|r| record_client(r) == client)
                .cloned()
                .collect();
            let expected: Vec<Vec<u8>> = (0..spec.frames)
                .map(|seq| body_for(client, seq, spec.body_len))
                .collect();
            assert_eq!(
                actual, expected,
                "client {client} records must match exactly"
            );
        }
        if check_batches {
            for chunk in records.chunks(spec.batch) {
                assert_eq!(chunk.len(), spec.batch);
                let client = record_client(&chunk[0]);
                assert!(
                    chunk.iter().all(|r| record_client(r) == client),
                    "a batch must not interleave frames from different clients"
                );
                let first = record_seq(&chunk[0]);
                let seqs: Vec<u32> = chunk.iter().map(|r| record_seq(r)).collect();
                let want: Vec<u32> = (first..first + spec.batch as u32).collect();
                assert_eq!(seqs, want, "a batch must be one client's contiguous seqs");
            }
        }
    }

    /// U1: 2 クライアント × 64 件・既定バッチ 64・別ファイル。
    #[test]
    fn io4_uds_concurrent_two_clients_default_batch_exact_bytes() {
        let spec = Spec {
            clients: 2,
            frames: 64,
            body_len: 24,
            batch: 64,
            shared: false,
            preconnect: true,
        };
        let outcome = run(&spec);
        assert_total_acks(&outcome, &spec);
        for (i, report) in outcome.reports.iter().enumerate() {
            assert_eq!(report.stats.acks_sent, 64);
            assert_eq!(report.stats.batches_written, 1);
            assert_eq!(
                outcome.contents[i],
                expected_for(i as u16, 64, 24),
                "client {i} output must match exactly"
            );
        }
    }

    /// U2: 8 クライアント × 256 件・`batch_size = 16`・別ファイル。
    #[test]
    fn io4_uds_concurrent_eight_clients_many_batches_exact_bytes() {
        let spec = Spec {
            clients: 8,
            frames: 256,
            body_len: 16,
            batch: 16,
            shared: false,
            preconnect: true,
        };
        let outcome = run(&spec);
        assert_total_acks(&outcome, &spec);
        for (i, report) in outcome.reports.iter().enumerate() {
            assert_eq!(report.stats.batches_written, 16);
            assert_eq!(
                outcome.contents[i],
                expected_for(i as u16, 256, 16),
                "client {i} output must match exactly"
            );
        }
    }

    /// U3: 4 クライアント × 32 件・`batch_size = 8`・共有ファイル。バッチが交錯しない。
    #[test]
    fn io4_uds_concurrent_shared_file_batches_never_interleave() {
        let spec = Spec {
            clients: 4,
            frames: 32,
            body_len: 20,
            batch: 8,
            shared: true,
            preconnect: true,
        };
        let outcome = run(&spec);
        assert_total_acks(&outcome, &spec);
        let batches: u64 = outcome
            .reports
            .iter()
            .map(|r| r.stats.batches_written)
            .sum();
        assert_eq!(batches, 4 * (32 / 8));
        assert_shared(&outcome.contents[0], &spec, true);
    }

    /// U4: 8 クライアント × 64 件・`batch_size = 1`・共有ファイル。順序保存と総量。
    #[test]
    fn io4_uds_concurrent_shared_file_batch_size_one_preserves_per_client_order() {
        let spec = Spec {
            clients: 8,
            frames: 64,
            body_len: 18,
            batch: 1,
            shared: true,
            preconnect: true,
        };
        let outcome = run(&spec);
        assert_total_acks(&outcome, &spec);
        assert_eq!(outcome.contents[0].len(), 8 * 64 * 18);
        assert_shared(&outcome.contents[0], &spec, false);
    }

    /// U5: client が並行に connect し、accept 順に依存せず、先頭レコードの client
    /// フィールドで接続とファイルを対応づけて照合する。
    #[test]
    fn io4_uds_concurrent_parallel_connect_maps_by_record_client() {
        let spec = Spec {
            clients: 6,
            frames: 32,
            body_len: 24,
            batch: 8,
            shared: false,
            preconnect: false,
        };
        let outcome = run(&spec);
        assert_total_acks(&outcome, &spec);
        let mut seen = Vec::new();
        for content in &outcome.contents {
            let first = decompose_records(content)
                .first()
                .map(|r| record_client(r))
                .expect("every output must hold records");
            assert_eq!(*content, expected_for(first, 32, 24));
            seen.push(first);
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..6u16).collect::<Vec<_>>());
    }
}

/// Windows 等の UDS 非対応 OS では bind が `Unimplemented` を返すことを明示する
/// （本モジュールの試験が黙って 0 件にならないようにする）。
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn io4_uds_concurrent_bind_is_unimplemented_on_unsupported_os() {
    use fandhe_container_io::{BatchConfig, IoErrorCode, NoopServerObserver, WritebackSettings};

    let path = std::env::temp_dir().join("fcio-uds-unsupported.sock");
    let err = WritebackSettings::new(BatchConfig::default())
        .bind(&path, NoopServerObserver)
        .expect_err("bind must be unsupported on this OS");
    assert_eq!(err.code(), IoErrorCode::Unimplemented);
}
