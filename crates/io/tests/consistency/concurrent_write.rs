//! 並行 write の整合性ケース（TASK-14.1・IO-4・REPAIR-6・#80）。
//!
//! [`super::harness`] の [`harness::DuplexEnd`]（メモリ内の二方向トランスポート。
//! 3 OS で動く）で複数の接続を同時に張り、各接続を別スレッドの
//! [`fandhe_container_io::writeback::serve_connection`] が処理することで、
//! 「複数クライアントからの並行 write」（`tests/consistency.rs` モジュール doc
//! 参照）を検証する。全ケースで書き込み結果のバイト内容を [`harness::body_for`]
//! が生成する期待バイト列との完全一致で確認する（IO-4・REPAIR-6・#80 受入
//! 基準）。

use std::sync::{Arc, Barrier};
use std::time::Duration;

use fandhe_container_io::{
    AppendFileSink, BatchConfig, FrameKind, InFlightLimit, IoErrorCode, NoopSendObserver,
    PipelineClient, REQUEST_ID_WIRE_LEN, WritebackTimeouts,
};

use super::harness::{
    self, DuplexEnd, SharedSink, TempDir, barrier_wait_within, body_for, decompose_records,
    drain_acks, flush_acks_per_flush, flush_session_end_code, join_within, record_client,
    record_seq, recv_flush_ack_if_supported, send_all_writes, spawn_server, timeout,
};

/// `join_within` に渡す上限時間（各 `serve_connection`・クライアントスレッドの
/// 待ち合わせ。REPAIR-5）。個々の送受信は `harness::timeout()`（5 秒）で
/// 区切られるため、本ケースの規模（最大でも数百フレーム）であれば十分な余裕。
fn join_deadline() -> Duration {
    Duration::from_secs(20)
}

fn writeback_timeouts() -> WritebackTimeouts {
    WritebackTimeouts {
        recv: timeout(),
        send: timeout(),
    }
}

/// `path` に新規作成した出力ファイルから [`AppendFileSink`] を作る。
fn new_sink(path: &std::path::Path) -> AppendFileSink {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .expect("must be able to create the test output file");
    AppendFileSink::new_at(file, path).expect("seek to end must succeed on a freshly created file")
}

/// クライアント数分の [`DuplexEnd`] ペアを作り、`(client_ends, server_ends)`
/// を返す。
fn make_connections(n: usize) -> (Vec<DuplexEnd>, Vec<DuplexEnd>) {
    let mut clients = Vec::with_capacity(n);
    let mut servers = Vec::with_capacity(n);
    for _ in 0..n {
        let (client_end, server_end) = harness::duplex();
        clients.push(client_end);
        servers.push(server_end);
    }
    (clients, servers)
}

/// IO-4・REPAIR-6・TASK-14.1: 2 クライアント × 64 件（既定バッチサイズ）を
/// 別ファイルへ並行 write する。各ファイルがそのクライアントの 64 件を挿入順に
/// 連結したものと完全一致し、他クライアントのバイトが混ざらないことを確認する
/// （クロスクライアント破損の検出）。
#[test]
fn io4_concurrent_write_two_clients_default_batch_exact_bytes() {
    const CLIENTS: u16 = 2;
    const FRAMES: u32 = 64;
    const BODY_LEN: usize = 24;

    let dir = TempDir::new("two-clients-default");
    let (client_ends, server_ends) = make_connections(CLIENTS as usize);
    let barrier = Arc::new(Barrier::new(CLIENTS as usize + 1));

    let mut server_handles = Vec::new();
    let mut output_paths = Vec::new();
    for (i, server_end) in server_ends.into_iter().enumerate() {
        let path = dir.file_path(&format!("client-{i}.bin"));
        let sink = new_sink(&path);
        output_paths.push(path);
        server_handles.push(spawn_server(
            server_end,
            BatchConfig::default(),
            sink,
            writeback_timeouts(),
        ));
    }

    let mut client_handles = Vec::new();
    for (i, client_end) in client_ends.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        client_handles.push(std::thread::spawn(move || {
            let bodies: Vec<Vec<u8>> = (0..FRAMES)
                .map(|seq| body_for(i as u16, seq, BODY_LEN))
                .collect();
            let mut client = PipelineClient::new(
                client_end,
                InFlightLimit::new(FRAMES as usize + 1).expect("valid in-flight limit"),
                NoopSendObserver,
            );
            barrier_wait_within(&barrier, join_deadline());
            send_all_writes(&mut client, &bodies, timeout());
            drain_acks(&mut client, bodies.len(), timeout());
        }));
    }
    barrier_wait_within(&barrier, join_deadline());

    for handle in client_handles {
        join_within(handle, join_deadline());
    }

    for (i, handle) in server_handles.into_iter().enumerate() {
        let report = join_within(handle, join_deadline());
        assert_eq!(report.stats.acks_sent, u64::from(FRAMES));
        assert_eq!(report.stats.batches_written, 1);
        assert_eq!(report.stats.discarded_pending_frames, 0);
        assert_eq!(report.end.code(), IoErrorCode::Unavailable);

        let expected: Vec<u8> = (0..FRAMES)
            .flat_map(|seq| body_for(i as u16, seq, BODY_LEN))
            .collect();
        let actual = std::fs::read(&output_paths[i]).expect("must read output file");
        assert_eq!(actual, expected, "client {i} output must match exactly");
    }
}

/// IO-4・REPAIR-6・TASK-14.1: 8 クライアント × 256 件（`batch_size = 16`）を
/// 別ファイルへ並行 write する。多数のバッチ境界を跨いでも、各ファイルが
/// クライアント自身の 256 件と完全一致することを確認する。
#[test]
fn io4_concurrent_write_eight_clients_many_batches_exact_bytes() {
    const CLIENTS: u16 = 8;
    const FRAMES: u32 = 256;
    const BODY_LEN: usize = 16;
    let config = BatchConfig::new(16).expect("16 must be a valid batch size");

    let dir = TempDir::new("eight-clients-many-batches");
    let (client_ends, server_ends) = make_connections(CLIENTS as usize);
    let barrier = Arc::new(Barrier::new(CLIENTS as usize + 1));

    let mut server_handles = Vec::new();
    let mut output_paths = Vec::new();
    for (i, server_end) in server_ends.into_iter().enumerate() {
        let path = dir.file_path(&format!("client-{i}.bin"));
        let sink = new_sink(&path);
        output_paths.push(path);
        server_handles.push(spawn_server(server_end, config, sink, writeback_timeouts()));
    }

    let mut client_handles = Vec::new();
    for (i, client_end) in client_ends.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        client_handles.push(std::thread::spawn(move || {
            let bodies: Vec<Vec<u8>> = (0..FRAMES)
                .map(|seq| body_for(i as u16, seq, BODY_LEN))
                .collect();
            let mut client = PipelineClient::new(
                client_end,
                InFlightLimit::new(FRAMES as usize + 1).expect("valid in-flight limit"),
                NoopSendObserver,
            );
            barrier_wait_within(&barrier, join_deadline());
            send_all_writes(&mut client, &bodies, timeout());
            drain_acks(&mut client, bodies.len(), timeout());
        }));
    }
    barrier_wait_within(&barrier, join_deadline());

    for handle in client_handles {
        join_within(handle, join_deadline());
    }

    for (i, handle) in server_handles.into_iter().enumerate() {
        let report = join_within(handle, join_deadline());
        assert_eq!(report.stats.acks_sent, u64::from(FRAMES));
        assert_eq!(report.stats.batches_written, 16);
        assert_eq!(report.stats.discarded_pending_frames, 0);

        let expected: Vec<u8> = (0..FRAMES)
            .flat_map(|seq| body_for(i as u16, seq, BODY_LEN))
            .collect();
        let actual = std::fs::read(&output_paths[i]).expect("must read output file");
        assert_eq!(actual, expected, "client {i} output must match exactly");
    }
}

/// IO-4・REPAIR-6・TASK-14.1: 4 クライアント × 32 件（`batch_size = 8`）が
/// [`SharedSink`] 経由で 1 ファイルを共有する。バッチ単位で直列化されるため、
/// 各バッチ（8 件）はどのクライアントの連続した seq からのみ構成され、
/// クライアントごとに抜き出した部分列（[`decompose_records`] で分解）が
/// [`body_for`] の期待値と完全一致することを確認する（交錯によるレコード破損の
/// 検出）。
///
/// 検証対象は `serve_connection` がバッチ単位で発火させる書き込みの境界が
/// 複数接続の並行スケジューリング下でも保たれるかであり、`AppendFileSink`
/// 単体の並行安全性ではない（直列化は [`SharedSink`] の doc 参照。codex #1123
/// レビュー指摘への対応）。
#[test]
fn io4_concurrent_write_shared_file_batches_never_interleave() {
    const CLIENTS: u16 = 4;
    const FRAMES: u32 = 32;
    const BODY_LEN: usize = 20;
    let config = BatchConfig::new(8).expect("8 must be a valid batch size");

    let dir = TempDir::new("shared-file-no-interleave");
    let output_path = dir.file_path("shared.bin");
    let shared_sink = SharedSink::new(new_sink(&output_path));

    let (client_ends, server_ends) = make_connections(CLIENTS as usize);
    let barrier = Arc::new(Barrier::new(CLIENTS as usize + 1));

    let server_handles: Vec<_> = server_ends
        .into_iter()
        .map(|server_end| {
            spawn_server(
                server_end,
                config,
                shared_sink.clone(),
                writeback_timeouts(),
            )
        })
        .collect();
    drop(shared_sink);

    let mut client_handles = Vec::new();
    for (i, client_end) in client_ends.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        client_handles.push(std::thread::spawn(move || {
            let bodies: Vec<Vec<u8>> = (0..FRAMES)
                .map(|seq| body_for(i as u16, seq, BODY_LEN))
                .collect();
            let mut client = PipelineClient::new(
                client_end,
                InFlightLimit::new(FRAMES as usize + 1).expect("valid in-flight limit"),
                NoopSendObserver,
            );
            barrier_wait_within(&barrier, join_deadline());
            send_all_writes(&mut client, &bodies, timeout());
            drain_acks(&mut client, bodies.len(), timeout());
        }));
    }
    barrier_wait_within(&barrier, join_deadline());

    for handle in client_handles {
        join_within(handle, join_deadline());
    }

    let mut total_acks = 0u64;
    let mut total_batches = 0u64;
    for handle in server_handles {
        let report = join_within(handle, join_deadline());
        total_acks += report.stats.acks_sent;
        total_batches += report.stats.batches_written;
        assert_eq!(report.stats.discarded_pending_frames, 0);
    }
    assert_eq!(total_acks, u64::from(CLIENTS) * u64::from(FRAMES));
    assert_eq!(total_batches, u64::from(CLIENTS) * u64::from(FRAMES / 8));

    let contents = std::fs::read(&output_path).expect("must read shared output file");
    let records = decompose_records(&contents);
    assert_eq!(records.len(), (CLIENTS as usize) * (FRAMES as usize));

    for client in 0..CLIENTS {
        let per_client_seqs: Vec<u32> = records
            .iter()
            .filter(|record| record_client(record) == client)
            .map(|record| record_seq(record))
            .collect();
        assert_eq!(
            per_client_seqs,
            (0..FRAMES).collect::<Vec<_>>(),
            "client {client} must appear in seq order with no gaps or duplicates"
        );

        let expected: Vec<Vec<u8>> = (0..FRAMES)
            .map(|seq| body_for(client, seq, BODY_LEN))
            .collect();
        let actual: Vec<Vec<u8>> = records
            .iter()
            .filter(|record| record_client(record) == client)
            .cloned()
            .collect();
        assert_eq!(
            actual, expected,
            "client {client} records must match body_for exactly (byte-for-byte)"
        );
    }

    // 各バッチ（8 件）は単一クライアントの連続した seq からのみ構成される
    // （直列化により交錯しないこと。records は書き込み順のため 8 件ずつの
    // ブロックで検証する）。
    for chunk in records.chunks(8) {
        assert_eq!(
            chunk.len(),
            8,
            "records must be a multiple of the batch size"
        );
        let client = record_client(&chunk[0]);
        let seqs: Vec<u32> = chunk.iter().map(|record| record_seq(record)).collect();
        assert!(
            chunk.iter().all(|record| record_client(record) == client),
            "a single batch must not interleave frames from different clients"
        );
        let first_seq = seqs[0];
        assert_eq!(
            seqs,
            (first_seq..first_seq + 8).collect::<Vec<_>>(),
            "a single batch must contain a contiguous run of one client's seq numbers"
        );
    }
}

/// IO-4・REPAIR-6・TASK-14.1: 4 クライアント × 64 件・`batch_size = 1`（交錯が
/// 最大になる設定）が [`SharedSink`] を共有する。クライアントごとの部分列が
/// seq 昇順で完全一致し、レコード総数・全長が具体値と一致することを確認する。
///
/// `batch_size = 1` により `write_batch` 呼び出し（＝ [`SharedSink`] の
/// `Mutex` 獲得）の頻度が最大になり、複数接続からの獲得競合が最も起きやすい
/// 設定でも per-client の順序が壊れないことを確認する。ここでも検証対象は
/// `serve_connection` 側のスケジューリング・直列化の正しさであり、
/// `AppendFileSink` 単体の並行安全性ではない（[`SharedSink`] の doc 参照。
/// codex #1123 レビュー指摘への対応）。
#[test]
fn io4_concurrent_write_shared_file_batch_size_one_preserves_per_client_order() {
    const CLIENTS: u16 = 4;
    const FRAMES: u32 = 64;
    const BODY_LEN: usize = 16;
    let config = BatchConfig::new(1).expect("1 must be a valid batch size");

    let dir = TempDir::new("shared-file-batch-size-one");
    let output_path = dir.file_path("shared.bin");
    let shared_sink = SharedSink::new(new_sink(&output_path));

    let (client_ends, server_ends) = make_connections(CLIENTS as usize);
    let barrier = Arc::new(Barrier::new(CLIENTS as usize + 1));

    let server_handles: Vec<_> = server_ends
        .into_iter()
        .map(|server_end| {
            spawn_server(
                server_end,
                config,
                shared_sink.clone(),
                writeback_timeouts(),
            )
        })
        .collect();
    drop(shared_sink);

    let mut client_handles = Vec::new();
    for (i, client_end) in client_ends.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        client_handles.push(std::thread::spawn(move || {
            let bodies: Vec<Vec<u8>> = (0..FRAMES)
                .map(|seq| body_for(i as u16, seq, BODY_LEN))
                .collect();
            let mut client = PipelineClient::new(
                client_end,
                InFlightLimit::new(FRAMES as usize + 1).expect("valid in-flight limit"),
                NoopSendObserver,
            );
            barrier_wait_within(&barrier, join_deadline());
            send_all_writes(&mut client, &bodies, timeout());
            drain_acks(&mut client, bodies.len(), timeout());
        }));
    }
    barrier_wait_within(&barrier, join_deadline());

    for handle in client_handles {
        join_within(handle, join_deadline());
    }

    for handle in server_handles {
        let report = join_within(handle, join_deadline());
        assert_eq!(report.stats.acks_sent, u64::from(FRAMES));
        assert_eq!(report.stats.batches_written, u64::from(FRAMES));
    }

    let contents = std::fs::read(&output_path).expect("must read shared output file");
    let records = decompose_records(&contents);
    assert_eq!(records.len(), 256, "4 clients * 64 frames = 256 records");

    let expected_total_len: usize = records.iter().map(|record| record.len()).sum::<usize>();
    assert_eq!(contents.len(), expected_total_len);
    assert_eq!(contents.len(), 256 * BODY_LEN);

    for client in 0..CLIENTS {
        let actual: Vec<Vec<u8>> = records
            .iter()
            .filter(|record| record_client(record) == client)
            .cloned()
            .collect();
        let expected: Vec<Vec<u8>> = (0..FRAMES)
            .map(|seq| body_for(client, seq, BODY_LEN))
            .collect();
        assert_eq!(actual, expected, "client {client} must be in seq order");
    }
}

/// IO-4・REPAIR-6・TASK-14.1: 4 クライアントが、それぞれ異なる body 長
/// （ヘッダ最小付近・中間・大サイズ）を混在させて別ファイルへ書き込む。
/// `batch_size` を件数と一致させ 1 回で発火させたうえで、各ファイルが完全
/// 一致し `bytes_written` が Σ(len) の具体値と一致することを確認する。
#[test]
fn io4_concurrent_write_varied_body_sizes_exact_bytes() {
    const CLIENTS: u16 = 4;
    const BODY_LENS: [usize; 4] = [16, 255, 4096, 65536];
    let config = BatchConfig::new(BODY_LENS.len()).expect("valid batch size");
    let expected_bytes_written: u64 = BODY_LENS.iter().map(|&len| len as u64).sum();

    let dir = TempDir::new("varied-body-sizes");
    let (client_ends, server_ends) = make_connections(CLIENTS as usize);
    let barrier = Arc::new(Barrier::new(CLIENTS as usize + 1));

    let mut server_handles = Vec::new();
    let mut output_paths = Vec::new();
    for (i, server_end) in server_ends.into_iter().enumerate() {
        let path = dir.file_path(&format!("client-{i}.bin"));
        let sink = new_sink(&path);
        output_paths.push(path);
        server_handles.push(spawn_server(server_end, config, sink, writeback_timeouts()));
    }

    let mut client_handles = Vec::new();
    for (i, client_end) in client_ends.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        client_handles.push(std::thread::spawn(move || {
            let bodies: Vec<Vec<u8>> = BODY_LENS
                .iter()
                .enumerate()
                .map(|(seq, &len)| body_for(i as u16, seq as u32, len))
                .collect();
            let mut client = PipelineClient::new(
                client_end,
                InFlightLimit::new(BODY_LENS.len() + 1).expect("valid in-flight limit"),
                NoopSendObserver,
            );
            barrier_wait_within(&barrier, join_deadline());
            send_all_writes(&mut client, &bodies, timeout());
            drain_acks(&mut client, bodies.len(), timeout());
        }));
    }
    barrier_wait_within(&barrier, join_deadline());

    for handle in client_handles {
        join_within(handle, join_deadline());
    }

    for (i, handle) in server_handles.into_iter().enumerate() {
        let report = join_within(handle, join_deadline());
        assert_eq!(report.stats.acks_sent, BODY_LENS.len() as u64);
        assert_eq!(report.stats.batches_written, 1);
        assert_eq!(report.stats.bytes_written, expected_bytes_written);

        let expected: Vec<u8> = BODY_LENS
            .iter()
            .enumerate()
            .flat_map(|(seq, &len)| body_for(i as u16, seq as u32, len))
            .collect();
        let actual = std::fs::read(&output_paths[i]).expect("must read output file");
        assert_eq!(actual, expected, "client {i} output must match exactly");
    }
}

/// IO-4・REPAIR-6・TASK-14.1: 累積バイト数上限（[`BatchTrigger::BytesLimitReached`]
/// 相当。`crate::batch` のバイト数上限を参照）による発火を、明示的な `Flush`
/// と組み合わせて検証する。4 クライアントがそれぞれ body 長
/// [`harness::BODY_HEADER_LEN`]（[`body_for`] が要求する最小長）バイトの
/// フレームを 4 件送り、`max_bytes = 2 * (REQUEST_ID_WIRE_LEN + body 長)` に
/// 設定する。1・2 件目はちょうど上限に収まり滞留し、3 件目の push で 1・2
/// 件目が `BytesLimitReached` として発火、3・4 件目は明示的な `Flush` で
/// 確定する（`crate::batch` の
/// `batch_buffer_fires_on_bytes_limit_before_size_limit` と同じ発火規則）。
/// 各ファイルが完全一致し、`batches_written == 2` になることを確認する。
///
/// [`BatchTrigger::BytesLimitReached`]: fandhe_container_io::BatchTrigger::BytesLimitReached
#[test]
fn io4_concurrent_write_bytes_limit_trigger_exact_bytes() {
    const CLIENTS: u16 = 4;
    const FRAMES: u32 = 4;
    // body_for は最低でも BODY_HEADER_LEN バイトを要求するため、これより
    // 小さい body 長は使えない（BODY_LEN=4 で試すと body_for がスレッド内で
    // panic し、まだ barrier_wait_within に到達していない他クライアントの
    // 分が deadline（REPAIR-5）まで待たされた末に panic する — 修正前は
    // `barrier.wait()` が無期限で永久に揃わずテストがハングした回帰点なので
    // コメントに残す）。
    const BODY_LEN: usize = harness::BODY_HEADER_LEN;
    let frame_payload_len = REQUEST_ID_WIRE_LEN + BODY_LEN;
    let max_bytes = frame_payload_len * 2;
    // batch_size は十分大きく、バイト数上限だけが効くようにする。
    let config = BatchConfig::with_max_bytes(64, max_bytes).expect("valid config");

    let dir = TempDir::new("bytes-limit-trigger");
    let (client_ends, server_ends) = make_connections(CLIENTS as usize);
    let barrier = Arc::new(Barrier::new(CLIENTS as usize + 1));

    let mut server_handles = Vec::new();
    let mut output_paths = Vec::new();
    for (i, server_end) in server_ends.into_iter().enumerate() {
        let path = dir.file_path(&format!("client-{i}.bin"));
        let sink = new_sink(&path);
        output_paths.push(path);
        server_handles.push(spawn_server(server_end, config, sink, writeback_timeouts()));
    }

    let mut client_handles = Vec::new();
    for (i, client_end) in client_ends.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        client_handles.push(std::thread::spawn(move || {
            let bodies: Vec<Vec<u8>> = (0..FRAMES)
                .map(|seq| body_for(i as u16, seq, BODY_LEN))
                .collect();
            let mut client = PipelineClient::new(
                client_end,
                InFlightLimit::new(FRAMES as usize + 1).expect("valid in-flight limit"),
                NoopSendObserver,
            );
            barrier_wait_within(&barrier, join_deadline());
            send_all_writes(&mut client, &bodies, timeout());
            // 3・4 件目（末尾の滞留分）は、既存の滞留量上限だけでは発火
            // しないため、明示的な Flush で確定させる（D3。`writeback.rs`
            // モジュール doc「バッチが件数未達のまま残る場合の発火条件」）。
            client
                .send(FrameKind::Flush, &[], timeout())
                .expect("flush send must succeed");
            // Write フレームの分の ACK の後、persist 対応環境では FlushAck が
            // 届き、非対応環境（Linux 5.8 未満・非 Linux）では EOF になる
            // （IO-2・TASK-15.2.2。`persist_support` で分岐）。
            drain_acks(&mut client, bodies.len(), timeout());
            recv_flush_ack_if_supported(&mut client, timeout());
        }));
    }
    barrier_wait_within(&barrier, join_deadline());

    for handle in client_handles {
        join_within(handle, join_deadline());
    }

    for (i, handle) in server_handles.into_iter().enumerate() {
        let report = join_within(handle, join_deadline());
        assert_eq!(report.stats.acks_sent, u64::from(FRAMES));
        assert_eq!(report.stats.batches_written, 2);
        assert_eq!(report.stats.discarded_pending_frames, 0);
        assert_eq!(report.end.code(), flush_session_end_code());
        assert_eq!(report.stats.flush_acks_sent, flush_acks_per_flush());

        let expected: Vec<u8> = (0..FRAMES)
            .flat_map(|seq| body_for(i as u16, seq, BODY_LEN))
            .collect();
        let actual = std::fs::read(&output_paths[i]).expect("must read output file");
        assert_eq!(actual, expected, "client {i} output must match exactly");
    }
}

/// IO-4・REPAIR-6・TASK-14.1: 4 クライアントがそれぞれ `batch_size * 2 + 3`
/// 件を送った後に `Flush` を送る。端数 3 件を含む全件が書かれ、ACK も全件
/// 届く。Flush への FlushAck と終了コードは persist 対応環境で 1 件・
/// `Unavailable`、非対応環境で 0 件・`Unimplemented`（IO-2・TASK-15.2.2）で、
/// `discarded_pending_frames == 0`。各ファイルが完全一致することを確認する。
#[test]
fn io4_concurrent_write_partial_batch_flushed_by_flush_frame() {
    const CLIENTS: u16 = 4;
    const BATCH_SIZE: usize = 8;
    const FRAMES: u32 = (BATCH_SIZE as u32) * 2 + 3;
    const BODY_LEN: usize = 16;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("partial-batch-flushed");
    let (client_ends, server_ends) = make_connections(CLIENTS as usize);
    let barrier = Arc::new(Barrier::new(CLIENTS as usize + 1));

    let mut server_handles = Vec::new();
    let mut output_paths = Vec::new();
    for (i, server_end) in server_ends.into_iter().enumerate() {
        let path = dir.file_path(&format!("client-{i}.bin"));
        let sink = new_sink(&path);
        output_paths.push(path);
        server_handles.push(spawn_server(server_end, config, sink, writeback_timeouts()));
    }

    let mut client_handles = Vec::new();
    for (i, client_end) in client_ends.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        client_handles.push(std::thread::spawn(move || {
            let bodies: Vec<Vec<u8>> = (0..FRAMES)
                .map(|seq| body_for(i as u16, seq, BODY_LEN))
                .collect();
            let mut client = PipelineClient::new(
                client_end,
                InFlightLimit::new(FRAMES as usize + 1).expect("valid in-flight limit"),
                NoopSendObserver,
            );
            barrier_wait_within(&barrier, join_deadline());
            send_all_writes(&mut client, &bodies, timeout());
            client
                .send(FrameKind::Flush, &[], timeout())
                .expect("flush send must succeed");
            drain_acks(&mut client, bodies.len(), timeout());
            recv_flush_ack_if_supported(&mut client, timeout());
        }));
    }
    barrier_wait_within(&barrier, join_deadline());

    for handle in client_handles {
        join_within(handle, join_deadline());
    }

    for (i, handle) in server_handles.into_iter().enumerate() {
        let report = join_within(handle, join_deadline());
        assert_eq!(report.stats.acks_sent, u64::from(FRAMES));
        assert_eq!(report.stats.batches_written, 3);
        assert_eq!(report.stats.discarded_pending_frames, 0);
        assert_eq!(report.end.code(), flush_session_end_code());
        assert_eq!(report.stats.flush_acks_sent, flush_acks_per_flush());

        let expected: Vec<u8> = (0..FRAMES)
            .flat_map(|seq| body_for(i as u16, seq, BODY_LEN))
            .collect();
        let actual = std::fs::read(&output_paths[i]).expect("must read output file");
        assert_eq!(actual, expected, "client {i} output must match exactly");
    }
}

/// IO-4・REPAIR-6・TASK-14.1・D5: 4 クライアントのうち 1 台は
/// `batch_size + 5` 件を送って `Flush` せずに切断する（`DuplexEnd` を drop
/// するだけで、mpsc の送受信端が閉じ、サーバー側は次の受信で `Unavailable`
/// を観測する）。残る 3 台は通常どおり完了する。切断した接続のファイルは
/// ACK 済みの 1 バッチ分だけで完全一致し、端数 5 件は書かれない
/// （`discarded_pending_frames == 5`）。他の 3 ファイルも完全一致する
/// （1 クライアントの切断が他クライアントの書き込みを破損させないことの
/// 確認）。
#[test]
fn io4_concurrent_write_one_client_disconnect_does_not_corrupt_others() {
    const CLIENTS: u16 = 4;
    const DISCONNECTING_CLIENT: u16 = 2;
    const BATCH_SIZE: usize = 8;
    const NORMAL_FRAMES: u32 = (BATCH_SIZE as u32) * 2;
    const DISCONNECT_FRAMES: u32 = (BATCH_SIZE as u32) + 5;
    const BODY_LEN: usize = 16;
    let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");

    let dir = TempDir::new("one-disconnect");
    let (client_ends, server_ends) = make_connections(CLIENTS as usize);
    let barrier = Arc::new(Barrier::new(CLIENTS as usize + 1));

    let mut server_handles = Vec::new();
    let mut output_paths = Vec::new();
    for (i, server_end) in server_ends.into_iter().enumerate() {
        let path = dir.file_path(&format!("client-{i}.bin"));
        let sink = new_sink(&path);
        output_paths.push(path);
        server_handles.push(spawn_server(server_end, config, sink, writeback_timeouts()));
    }

    let mut client_handles = Vec::new();
    for (i, client_end) in client_ends.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        let client_id = i as u16;
        client_handles.push(std::thread::spawn(move || {
            if client_id == DISCONNECTING_CLIENT {
                let bodies: Vec<Vec<u8>> = (0..DISCONNECT_FRAMES)
                    .map(|seq| body_for(client_id, seq, BODY_LEN))
                    .collect();
                let mut client = PipelineClient::new(
                    client_end,
                    InFlightLimit::new(DISCONNECT_FRAMES as usize + 1)
                        .expect("valid in-flight limit"),
                    NoopSendObserver,
                );
                barrier_wait_within(&barrier, join_deadline());
                send_all_writes(&mut client, &bodies, timeout());
                // 最初の 1 バッチぶん（BATCH_SIZE 件）だけ ACK を受け取り、
                // 残りの端数（5 件）は未 ACK のまま Flush を送らずに切断する
                // （client の drop で DuplexEnd の送受信端が閉じる。D5）。
                drain_acks(&mut client, BATCH_SIZE, timeout());
                drop(client);
            } else {
                let bodies: Vec<Vec<u8>> = (0..NORMAL_FRAMES)
                    .map(|seq| body_for(client_id, seq, BODY_LEN))
                    .collect();
                let mut client = PipelineClient::new(
                    client_end,
                    InFlightLimit::new(NORMAL_FRAMES as usize + 1).expect("valid in-flight limit"),
                    NoopSendObserver,
                );
                barrier_wait_within(&barrier, join_deadline());
                send_all_writes(&mut client, &bodies, timeout());
                drain_acks(&mut client, bodies.len(), timeout());
            }
        }));
    }
    barrier_wait_within(&barrier, join_deadline());

    for handle in client_handles {
        join_within(handle, join_deadline());
    }

    for (i, handle) in server_handles.into_iter().enumerate() {
        let report = join_within(handle, join_deadline());
        let client_id = i as u16;
        if client_id == DISCONNECTING_CLIENT {
            assert_eq!(report.stats.acks_sent, BATCH_SIZE as u64);
            assert_eq!(report.stats.batches_written, 1);
            assert_eq!(report.stats.discarded_pending_frames, 5);
            assert_eq!(report.end.code(), IoErrorCode::Unavailable);

            let expected: Vec<u8> = (0..BATCH_SIZE as u32)
                .flat_map(|seq| body_for(client_id, seq, BODY_LEN))
                .collect();
            let actual = std::fs::read(&output_paths[i]).expect("must read output file");
            assert_eq!(
                actual, expected,
                "disconnecting client's file must contain exactly the acked batch"
            );
        } else {
            assert_eq!(report.stats.acks_sent, u64::from(NORMAL_FRAMES));
            assert_eq!(report.stats.batches_written, 2);
            assert_eq!(report.stats.discarded_pending_frames, 0);

            let expected: Vec<u8> = (0..NORMAL_FRAMES)
                .flat_map(|seq| body_for(client_id, seq, BODY_LEN))
                .collect();
            let actual = std::fs::read(&output_paths[i]).expect("must read output file");
            assert_eq!(
                actual, expected,
                "client {i}'s file must be unaffected by another client's disconnect"
            );
        }
    }
}
