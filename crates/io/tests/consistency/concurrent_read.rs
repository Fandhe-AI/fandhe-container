//! 書き込み・truncate と同時に読む読み手の整合性ケース（TASK-14 追補・#1828・
//! IO-4・REPAIR-6・REPAIR-5・REPAIR-12）。
//!
//! 既存スイートの読み手は書き込み停止後に新しいハンドルで読む（close-to-open。
//! [`super::graceful_shutdown::read_fresh`]）だけだった。本モジュールは、書き込みや
//! truncate が進行している間に別スレッドの読み手が「ファイルを新しく開いて
//! 全体を読む」ことを繰り返し、観測してよい内容の定義
//! （`tests/consistency.rs` モジュール doc「書き込み・truncate と同時に読む
//! 読み手の定義」(a)〜(e)）を機械照合する。永続化（IO-2）・クラッシュは対象外で、
//! `serve_connection`・`AppendFileSink`・`docs/api/io-barrier.md` の契約は変えない。
//!
//! # OS 差の前提（3 OS の一次資料に基づく保守的な定義）
//!
//! - 完了済みの書き込み（ACK 済み）は、その後に開いた読み手に見える。POSIX
//!   `write(2)` は戻った後の `read(2)` が書き込み結果を返すことを要求し
//!   （POSIX.1-2017 write・「Atomicity of file I/O」節）、Windows も
//!   `WriteFile` 完了後に開いた `ReadFile` は同じ内容を読む（キャッシュは
//!   ハンドル間で一貫。Microsoft Learn「WriteFile」「File Buffering」）。
//!   このため ACK 床（(b)）は 3 OS とも厳密に照合する。
//! - 書き込み進行中の領域（ACK 床より後ろ）は、Linux はページ単位で `i_size` を
//!   後から更新するため接頭辞しか見えないが、macOS の VFS/UBC と Windows の NTFS
//!   （EOF 拡張後の valid data length までの未書き込み領域はゼロとして読める）は
//!   一次資料で同等の保証を確認できていない。そこで当該領域は「期待値、または
//!   0x00」までを許容する（他接続の body・順序入れ替えは依然検出できる。強い主張は
//!   3 OS で確認できるまで置かない）。
//! - truncate は書き込み側の静止点（`drain_acks` 後）でのみ行い、`write_batch` の
//!   seek との競合（バッチ途中の外部 truncate）は踏まない（`writeback.rs`・
//!   `rename_truncate` の範囲）。

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use fandhe_container_io::{
    AppendFileSink, BatchConfig, InFlightLimit, NoopSendObserver, PipelineClient, SinkOpenMode,
    WritebackReport, WritebackTimeouts,
};

use super::harness::{
    self, AckProgress, BODY_HEADER_LEN, DuplexEnd, SharedSink, TempDir, barrier_wait_within,
    body_for, decompose_records, decompose_records_prefix, drain_acks, join_within, open_sink,
    record_client, record_seq, sample_snapshot, send_all_writes, spawn_server, timeout,
};

/// join・barrier・読み手ループの上限時間（REPAIR-5。他ケースと同じ 20 秒）。
fn join_deadline() -> Duration {
    Duration::from_secs(20)
}

fn writeback_timeouts() -> WritebackTimeouts {
    WritebackTimeouts {
        recv: timeout(),
        send: timeout(),
    }
}

fn create_sink(path: &Path) -> AppendFileSink {
    open_sink(path, SinkOpenMode::CreateOrTruncate)
        .expect("must be able to create the test output file")
}

/// `client` 固定の `body_for` を `seqs` の範囲で連結した期待バイト列。
fn records(client: u16, seqs: std::ops::Range<u32>, body_len: usize) -> Vec<u8> {
    seqs.flat_map(|seq| body_for(client, seq, body_len))
        .collect()
}

/// 関数の終了（panic を含む）で完了フラグを立てる。書き込み側が落ちても読み手が
/// 待ち続けないようにする（REPAIR-5）。
struct DoneOnDrop(Arc<AtomicBool>);

impl Drop for DoneOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// 位置 `i` の期待値との一致（`tolerant` のときは 0x00 も許す。(c)）。
fn first_mismatch(actual: &[u8], expected: &[u8], tolerant_from: usize) -> Option<usize> {
    actual.iter().enumerate().find_map(|(i, byte)| {
        let want = expected.get(i).copied();
        let ok = want == Some(*byte) || (i >= tolerant_from && *byte == 0);
        (!ok).then_some(i)
    })
}

/// (a)(b)(c): スナップショットが期待列 `expected` の接頭辞で、先頭 `acked_bytes`
/// は厳密一致、以降は期待値または 0x00 であることを確認する。
fn check_snapshot(snapshot: &[u8], expected: &[u8], acked_bytes: usize, who: &str, iter: u64) {
    assert!(
        snapshot.len() <= expected.len(),
        "{who} iter {iter}: snapshot ({} bytes) is longer than everything sent ({} bytes)",
        snapshot.len(),
        expected.len()
    );
    assert!(
        snapshot.len() >= acked_bytes,
        "{who} iter {iter}: snapshot ({} bytes) misses acked bytes ({acked_bytes})",
        snapshot.len()
    );
    if let Some(pos) = first_mismatch(snapshot, expected, acked_bytes) {
        panic!(
            "{who} iter {iter}: first mismatch at byte {pos} (snapshot len {}, acked floor \
             {acked_bytes}): got {:?}, want {:?}",
            snapshot.len(),
            snapshot.get(pos),
            expected.get(pos)
        );
    }
}

fn log_overlap(tag: &str, who: &str, iters: u64, lens: &BTreeSet<usize>) {
    eprintln!(
        "{tag} {who}: {iters} snapshots, {} distinct length(s), min {:?} max {:?}",
        lens.len(),
        lens.iter().next(),
        lens.iter().next_back()
    );
}

/// 単一接続で `records_total` 件を書き込む間、`readers` 本の読み手が反復して
/// 読む共通ケース本体。(a)(b)(c)(d) を照合する。
fn run_single_connection(
    tag: &str,
    readers: usize,
    batch_size: usize,
    window: usize,
    records_total: u32,
    body_len: usize,
) {
    assert_eq!(window % batch_size, 0, "window must be a batch multiple");
    let config = BatchConfig::new(batch_size).expect("valid batch size");
    let dir = TempDir::new(tag);
    let path = dir.file_path("out.bin");
    let expected = records(0, 0..records_total, body_len);

    let (client_end, server_end) = harness::duplex();
    let server = spawn_server(server_end, config, create_sink(&path), writeback_timeouts());
    let mut client = PipelineClient::new(
        client_end,
        InFlightLimit::new(window + 1).expect("valid in-flight limit"),
        NoopSendObserver,
    );

    let progress = AckProgress::new();
    let done = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(readers + 1));

    let writer = {
        let progress = progress.clone();
        let done = Arc::clone(&done);
        let barrier = Arc::clone(&barrier);
        let bodies: Vec<Vec<u8>> = (0..records_total)
            .map(|seq| body_for(0, seq, body_len))
            .collect();
        std::thread::spawn(move || {
            let _guard = DoneOnDrop(done);
            barrier_wait_within(&barrier, join_deadline());
            for chunk in bodies.chunks(window) {
                send_all_writes(&mut client, chunk, timeout());
                for _ in 0..chunk.len() {
                    client
                        .recv_ack(timeout())
                        .expect("recv_ack must succeed while writing");
                    progress.advance();
                }
            }
        })
    };

    let reader_handles: Vec<_> = (0..readers)
        .map(|r| {
            let progress = progress.clone();
            let done = Arc::clone(&done);
            let barrier = Arc::clone(&barrier);
            let expected = expected.clone();
            let path = path.clone();
            std::thread::spawn(move || {
                let who = format!("reader {r}");
                barrier_wait_within(&barrier, join_deadline());
                let start = Instant::now();
                let (mut iter, mut prev_len, mut prev_floor) = (0u64, 0usize, 0usize);
                let mut lens = BTreeSet::new();
                loop {
                    // 完了フラグ → ACK 件数 → 開く、の順（先に読んだ分だけが床になる）。
                    let finished = done.load(Ordering::Acquire);
                    let floor = progress.acked() as usize * body_len;
                    let snapshot = sample_snapshot(&path);
                    check_snapshot(&snapshot, &expected, floor, &who, iter);
                    // (d) 単調性（書き込みのみの局面）。
                    assert!(
                        snapshot.len() >= prev_len && floor >= prev_floor,
                        "{who} iter {iter}: length or acked floor went backwards \
                         ({prev_len} -> {}, {prev_floor} -> {floor})",
                        snapshot.len()
                    );
                    (prev_len, prev_floor) = (snapshot.len(), floor);
                    lens.insert(snapshot.len());
                    iter += 1;
                    if finished {
                        assert_eq!(snapshot, expected, "{who}: final snapshot must be complete");
                        break;
                    }
                    assert!(
                        start.elapsed() < join_deadline(),
                        "{who}: writer did not finish in time (REPAIR-5)"
                    );
                    std::thread::yield_now();
                }
                (iter, lens)
            })
        })
        .collect();

    join_within(writer, join_deadline());
    for (r, handle) in reader_handles.into_iter().enumerate() {
        let (iters, lens) = join_within(handle, join_deadline());
        log_overlap(tag, &format!("reader {r}"), iters, &lens);
    }
    let report = join_within(server, join_deadline());
    assert_eq!(report.stats.acks_sent, u64::from(records_total));
    assert_eq!(report.stats.discarded_pending_frames, 0);
    assert_eq!(std::fs::read(&path).expect("read output"), expected);
}

/// IO-4・REPAIR-6・#1828（定義 (a)(c)(d)）: 単一接続の書き込み中、読み手の
/// 全スナップショットが送信列の接頭辞（書きかけ末尾は許容）で、長さが
/// 減らないこと。
#[test]
fn io4_concurrent_read_single_connection_snapshots_are_record_prefixes() {
    run_single_connection("cr-single-prefix", 1, 4, 8, 512, 32);
}

/// IO-4・REPAIR-6・#1828（定義 (b)）: ACK 件数を先に読んでから開いた読み手に、
/// ACK 済みレコードが完全に見えること。バッチサイズ 1 で ACK を細かく進める。
#[test]
fn io4_concurrent_read_acked_records_visible_to_later_opened_reader() {
    run_single_connection("cr-acked-visible", 1, 1, 8, 512, 24);
}

/// IO-4・REPAIR-6・#1828（定義 (a)〜(d)）: 読み手 4 本が同時に反復しても、
/// 多重オープンの干渉なく全スナップショットが定義を満たすこと。
#[test]
fn io4_concurrent_read_multiple_readers_never_see_corrupt_prefix() {
    run_single_connection("cr-multi-readers", 4, 4, 8, 512, 32);
}

const SHARED_CLIENTS: u16 = 4;
const SHARED_FRAMES: u32 = 64;
const SHARED_BODY_LEN: usize = 20;

/// 共有ファイルのスナップショットを分解して照合する（定義 (a)(b)(c)）。
fn check_shared_snapshot(snapshot: &[u8], acked: &[u64], iter: u64) {
    let (recs, _tail) = decompose_records_prefix(snapshot);
    let mut next = vec![0u32; usize::from(SHARED_CLIENTS)];
    let last = recs.len().saturating_sub(1);
    for (idx, rec) in recs.iter().enumerate() {
        let client = record_client(rec);
        assert!(
            client < SHARED_CLIENTS,
            "iter {iter}: client {client} out of range"
        );
        let seq = record_seq(rec);
        let slot = next
            .get_mut(usize::from(client))
            .expect("client index checked above");
        assert_eq!(seq, *slot, "iter {iter}: client {client} seq out of order");
        *slot += 1;
        assert_eq!(rec.len(), SHARED_BODY_LEN, "iter {iter}: record length");
        let want = body_for(client, seq, SHARED_BODY_LEN);
        // 末尾の完全長レコードだけは書き込み進行中でゼロ相当を許す (c)。
        let tolerant_from = if idx == last {
            BODY_HEADER_LEN
        } else {
            want.len()
        };
        if let Some(pos) = first_mismatch(rec, &want, tolerant_from) {
            panic!("iter {iter}: client {client} seq {seq} differs at byte {pos}");
        }
    }
    for (client, (got, floor)) in next.iter().zip(acked).enumerate() {
        assert!(
            u64::from(*got) >= *floor,
            "iter {iter}: client {client} has {got} record(s) visible, but {floor} were acked"
        );
    }
}

/// IO-4・REPAIR-6・#1828（定義 (a)(b)(c)）: `SharedSink` を 4 接続が共有して
/// 書く間、読み手のスナップショットでレコードが交錯せず、接続内の順序が保たれ、
/// ACK 済みレコードがクライアントごとに見えること。
#[test]
fn io4_concurrent_read_shared_file_multi_connection_records_never_interleave() {
    let config = BatchConfig::new(4).expect("valid batch size");
    let dir = TempDir::new("cr-shared");
    let path = dir.file_path("shared.bin");
    let shared = SharedSink::new(create_sink(&path));

    let clients = usize::from(SHARED_CLIENTS);
    let progress: Vec<AckProgress> = (0..clients).map(|_| AckProgress::new()).collect();
    let done = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(clients + 1));

    let mut servers = Vec::new();
    let mut writers = Vec::new();
    for (i, progress) in progress.iter().enumerate() {
        let (client_end, server_end) = harness::duplex();
        servers.push(spawn_server(
            server_end,
            config,
            shared.clone(),
            writeback_timeouts(),
        ));
        let progress = progress.clone();
        let barrier = Arc::clone(&barrier);
        writers.push(std::thread::spawn(move || {
            let bodies: Vec<Vec<u8>> = (0..SHARED_FRAMES)
                .map(|seq| body_for(i as u16, seq, SHARED_BODY_LEN))
                .collect();
            let mut client = PipelineClient::new(
                client_end,
                InFlightLimit::new(SHARED_FRAMES as usize + 1).expect("valid in-flight limit"),
                NoopSendObserver,
            );
            barrier_wait_within(&barrier, join_deadline());
            for chunk in bodies.chunks(8) {
                send_all_writes(&mut client, chunk, timeout());
                for _ in 0..chunk.len() {
                    client.recv_ack(timeout()).expect("recv_ack must succeed");
                    progress.advance();
                }
            }
        }));
    }
    drop(shared);

    let reader = {
        let progress = progress.clone();
        let done = Arc::clone(&done);
        let barrier = Arc::clone(&barrier);
        let path = path.clone();
        std::thread::spawn(move || {
            barrier_wait_within(&barrier, join_deadline());
            let start = Instant::now();
            let (mut iter, mut lens) = (0u64, BTreeSet::new());
            loop {
                let finished = done.load(Ordering::Acquire);
                let acked: Vec<u64> = progress.iter().map(AckProgress::acked).collect();
                let snapshot = sample_snapshot(&path);
                check_shared_snapshot(&snapshot, &acked, iter);
                lens.insert(snapshot.len());
                iter += 1;
                if finished {
                    break;
                }
                assert!(
                    start.elapsed() < join_deadline(),
                    "writers did not finish in time"
                );
                std::thread::yield_now();
            }
            (iter, lens)
        })
    };

    for handle in writers {
        join_within(handle, join_deadline());
    }
    done.store(true, Ordering::Release);
    let (iters, lens) = join_within(reader, join_deadline());
    log_overlap("cr-shared", "reader", iters, &lens);
    for handle in servers {
        let report = join_within(handle, join_deadline());
        assert_eq!(report.stats.discarded_pending_frames, 0);
    }

    let contents = std::fs::read(&path).expect("read shared output");
    let recs = decompose_records(&contents);
    assert_eq!(recs.len(), clients * SHARED_FRAMES as usize);
    for client in 0..SHARED_CLIENTS {
        let seqs: Vec<u32> = recs
            .iter()
            .filter(|r| record_client(r) == client)
            .map(|r| record_seq(r))
            .collect();
        assert_eq!(
            seqs,
            (0..SHARED_FRAMES).collect::<Vec<_>>(),
            "client {client}"
        );
    }
}

/// truncate ケース用の最小ライブセッション（1 接続）。
struct Session {
    client: PipelineClient<DuplexEnd, NoopSendObserver>,
    server: std::thread::JoinHandle<WritebackReport>,
}

impl Session {
    fn start(path: &Path, batch_size: usize, in_flight: usize) -> Self {
        let (client_end, server_end) = harness::duplex();
        let config = BatchConfig::new(batch_size).expect("valid batch size");
        let server = spawn_server(server_end, config, create_sink(path), writeback_timeouts());
        let client = PipelineClient::new(
            client_end,
            InFlightLimit::new(in_flight).expect("valid in-flight limit"),
            NoopSendObserver,
        );
        Self { client, server }
    }

    /// 送信して全 ACK を受け取る（静止点）。
    fn write_and_ack(&mut self, bodies: &[Vec<u8>]) {
        send_all_writes(&mut self.client, bodies, timeout());
        drain_acks(&mut self.client, bodies.len(), timeout());
    }

    fn finish(self) -> WritebackReport {
        drop(self.client);
        join_within(self.server, join_deadline())
    }
}

fn truncate_to(path: &Path, len: u64) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("must open for truncate");
    file.set_len(len).expect("truncate must succeed");
}

/// 読み手が `min_iters` 回進むのを期限付きで待つ（スリープでなく yield。
/// truncate と読み手の確実な重なりを作る）。
fn wait_for_iters(iters: &AtomicU64, min_iters: u64) {
    let start = Instant::now();
    while iters.load(Ordering::Acquire) < min_iters {
        assert!(
            start.elapsed() < join_deadline(),
            "reader made no progress (REPAIR-5)"
        );
        std::thread::yield_now();
    }
}

/// truncate 中の読み手。各スナップショットは旧内容 `old` の接頭辞で（(e)。最終内容は
/// 旧内容の接頭辞か空）、読む前に観測した `stage` に応じた長さ上限
/// `stage_max_len[stage]` を満たす。`stage == final_stage` のスナップショットで終わる。
fn spawn_truncate_reader(
    path: std::path::PathBuf,
    old: Vec<u8>,
    stage: Arc<AtomicU8>,
    iters: Arc<AtomicU64>,
    barrier: Arc<Barrier>,
    stage_len_range: Vec<Option<(usize, usize)>>,
) -> std::thread::JoinHandle<BTreeSet<usize>> {
    std::thread::spawn(move || {
        barrier_wait_within(&barrier, join_deadline());
        let start = Instant::now();
        let mut lens = BTreeSet::new();
        loop {
            let seen = usize::from(stage.load(Ordering::Acquire));
            let snapshot = sample_snapshot(&path);
            assert!(
                snapshot.len() <= old.len(),
                "snapshot longer than the old content"
            );
            if let Some(pos) = first_mismatch(&snapshot, &old, usize::MAX) {
                panic!("stage {seen}: snapshot differs from old content at byte {pos}");
            }
            // 段階 `seen` の truncate 完了後に開いたスナップショットの長さ範囲
            // （次の段階の truncate が先に進んでいてもよいので上限・下限の幅で見る）。
            if let Some(Some((min, max))) = stage_len_range.get(seen) {
                assert!(
                    (*min..=*max).contains(&snapshot.len()),
                    "stage {seen}: length {} outside {min}..={max} after truncate",
                    snapshot.len()
                );
            }
            lens.insert(snapshot.len());
            iters.fetch_add(1, Ordering::Release);
            if seen + 1 == stage_len_range.len() {
                return lens;
            }
            assert!(
                start.elapsed() < join_deadline(),
                "truncate did not complete (REPAIR-5)"
            );
            std::thread::yield_now();
        }
    })
}

/// IO-4・REPAIR-6・#1828（定義 (e)）: 静止点で `set_len(0)` を行う間、読み手の
/// スナップショットは常に旧内容の接頭辞で、truncate 完了後に開けば空であること。
/// 続けて同じセッションで書いた分が新 EOF に穴なしで着地すること。
#[test]
fn io4_concurrent_read_truncate_to_zero_while_reading() {
    const BODY_LEN: usize = 16;
    const N: u32 = 64;
    const M: u32 = 64;
    let dir = TempDir::new("cr-trunc-zero");
    let path = dir.file_path("out.bin");

    let mut session = Session::start(&path, 4, N as usize + 1);
    let bodies_n: Vec<Vec<u8>> = (0..N).map(|s| body_for(0, s, BODY_LEN)).collect();
    session.write_and_ack(&bodies_n);
    let old = records(0, 0..N, BODY_LEN);

    let stage = Arc::new(AtomicU8::new(0));
    let iters = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(2));
    let reader = spawn_truncate_reader(
        path.clone(),
        old,
        Arc::clone(&stage),
        Arc::clone(&iters),
        Arc::clone(&barrier),
        vec![None, Some((0, 0))],
    );
    barrier_wait_within(&barrier, join_deadline());
    wait_for_iters(&iters, 20);
    truncate_to(&path, 0);
    stage.store(1, Ordering::Release);
    let lens = join_within(reader, join_deadline());
    log_overlap(
        "cr-trunc-zero",
        "reader",
        iters.load(Ordering::Acquire),
        &lens,
    );

    let bodies_m: Vec<Vec<u8>> = (0..M).map(|s| body_for(0, N + s, BODY_LEN)).collect();
    session.write_and_ack(&bodies_m);
    let report = session.finish();
    assert_eq!(report.stats.acks_sent, u64::from(N + M));
    assert_eq!(
        std::fs::read(&path).expect("read output"),
        records(0, N..N + M, BODY_LEN),
        "records written after truncate must land at the new EOF without a hole"
    );
}

/// IO-4・REPAIR-6・#1828（定義 (c)(e)）: レコード境界、続けてレコード途中への
/// 2 段階の truncate の間、読み手のスナップショットは常に旧内容の接頭辞で、
/// 各段階完了後は期待長（境界+端数、境界）になること。端数を残したままでは
/// 書かず、境界へ戻してから再開した書き込みが穴なしで着地すること。
#[test]
fn io4_concurrent_read_truncate_to_record_boundary_and_mid_record_while_reading() {
    const BODY_LEN: usize = 16;
    const N: u32 = 64;
    const K: u32 = 40;
    const M: u32 = 16;
    const FRAGMENT: usize = 7;
    let boundary = K as usize * BODY_LEN;
    let dir = TempDir::new("cr-trunc-mid");
    let path = dir.file_path("out.bin");

    let mut session = Session::start(&path, 4, N as usize + 1);
    let bodies_n: Vec<Vec<u8>> = (0..N).map(|s| body_for(0, s, BODY_LEN)).collect();
    session.write_and_ack(&bodies_n);
    let old = records(0, 0..N, BODY_LEN);

    let stage = Arc::new(AtomicU8::new(0));
    let iters = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(2));
    let reader = spawn_truncate_reader(
        path.clone(),
        old,
        Arc::clone(&stage),
        Arc::clone(&iters),
        Arc::clone(&barrier),
        vec![
            None,
            Some((boundary, boundary + FRAGMENT)),
            Some((boundary, boundary)),
        ],
    );
    barrier_wait_within(&barrier, join_deadline());
    wait_for_iters(&iters, 20);
    truncate_to(&path, (boundary + FRAGMENT) as u64);
    stage.store(1, Ordering::Release);
    wait_for_iters(&iters, iters.load(Ordering::Acquire) + 10);
    truncate_to(&path, boundary as u64);
    stage.store(2, Ordering::Release);
    let lens = join_within(reader, join_deadline());
    log_overlap(
        "cr-trunc-mid",
        "reader",
        iters.load(Ordering::Acquire),
        &lens,
    );

    let bodies_m: Vec<Vec<u8>> = (0..M).map(|s| body_for(0, K + s, BODY_LEN)).collect();
    session.write_and_ack(&bodies_m);
    session.finish();
    assert_eq!(
        std::fs::read(&path).expect("read output"),
        records(0, 0..K + M, BODY_LEN),
        "after restoring the record boundary, resumed writes must land without a hole"
    );
}

/// ヘルパー検証（#1828）: 正常な接頭辞は完全なレコードと書きかけ末尾に分かれる。
#[test]
fn io4_helper_decompose_records_prefix_splits_partial_tail() {
    let mut data = body_for(1, 0, 16);
    data.extend(body_for(2, 1, 16));
    data.extend(&body_for(3, 2, 16)[..5]);
    let (recs, tail) = decompose_records_prefix(&data);
    assert_eq!(recs, vec![body_for(1, 0, 16), body_for(2, 1, 16)]);
    assert_eq!(tail.len(), 5);

    let mut data = body_for(1, 0, 16);
    data.extend(&body_for(1, 1, 16)[..12]);
    let (recs, tail) = decompose_records_prefix(&data);
    assert_eq!((recs.len(), tail.len()), (1, 12));
}

/// ヘルパー検証（#1828）: 末尾の未書き込み（全ゼロ）領域は書きかけとして扱う。
#[test]
fn io4_helper_decompose_records_prefix_accepts_zero_filled_tail() {
    let mut data = body_for(0, 0, 16);
    data.extend([0u8; 40]);
    let (recs, tail) = decompose_records_prefix(&data);
    assert_eq!((recs.len(), tail.len()), (1, 40));
}

/// ヘルパー検証（#1828）: ゼロでない破損ヘッダ（len が短すぎる）は panic で検出する。
#[test]
#[should_panic(expected = "shorter than a record header")]
fn io4_helper_decompose_records_prefix_panics_on_corrupt_len() {
    let mut data = body_for(0, 0, 16);
    data[6..10].copy_from_slice(&3u32.to_le_bytes());
    let _ = decompose_records_prefix(&data);
}
