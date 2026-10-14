//! 実ファイルへの書き込み失敗で、失敗したバッチの部分レコードが ACK されない
//! ことの試験（TASK-14 追補・#1829・IO-4・REPAIR-6。関連 IO-1・REPAIR-12）。
//!
//! # 用語
//!
//! - 失敗バッチ: `BatchSink::write_batch` が `Err` を返したバッチ。`writeback.rs`
//!   の D6 により ACK を 1 件も返さない。
//! - ACK 済み: クライアントが `recv_ack` で受け取った送信順の先頭からの件数。
//! - 部分レコード: 失敗バッチの途中まで書かれた、ファイル末尾の不完全なレコード。
//!   D5・D6 は「ACK 前の書き込みは書かれたかどうか不定」とだけ約束する。
//!
//! # 失敗の注入方法
//!
//! 既存の試験は偽 sink（単体）と persist 失敗（結合）だけで、実ファイルを書く
//! `AppendFileSink` の write 失敗は未検証だった。本ファイルは次の 3 通りで補う。
//!
//! - 実エラー ENOSPC（Linux 限定）: `/dev/full` を書き込みモードで開いて渡し、
//!   本番の写像 `StorageFull` → `ResourceExhausted` を実 I/O エラーで通す。
//!   `cfg(target_os = "linux")` でコンパイル対象を分けており、skip ではない。
//! - 実エラー（3 OS）: 読み取り専用で開いたファイルを渡す。`AppendFileSink::new`
//!   の「書き込みモードで開く」前提をあえて破る注入で、その他のエラーが
//!   `Internal` に写ることを確認する。
//! - 部分書き込み: 試験側の `PartialWriteSink` が、完全なレコード数件と途中で
//!   切れたレコードを実ファイルへ追記してから `Err` を返す。
//!
//! `AppendFileSink` の書き込み先を総称にすれば短い書き込み（`write` が要求より
//! 少ないバイト数を返す）も注入できるが、公開型のシグネチャ変更になり、試験の
//! ためだけに本番の型を一般化する価値が低いため採らない。したがって短い書き込みを
//! `AppendFileSink` の内側で実際に発生させる経路は本ファイルの対象外である
//! （`PartialWriteSink` は結果として残るファイル状態を模す）。
//!
//! 待ちはすべて期限つき（`harness::join_within`・`harness::timeout`。REPAIR-5）で、
//! `sleep` は使わない。エラーメッセージにデータの中身・パスを含めないこと
//! （security.md）も W3・W4 で照合する。

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

#[cfg(target_os = "linux")]
use fandhe_container_io::AppendFileSink;
use fandhe_container_io::{
    Batch, BatchConfig, BatchSink, FrameKind, InFlightLimit, IoError, IoErrorCode,
    NoopSendObserver, PipelineClient, SinkOpenMode, SinkWriteReport, WritebackReport,
    WritebackTimeouts,
};

use super::harness::{
    self, DuplexEnd, TempDir, body_for, decompose_records, drain_acks, join_within, open_sink,
    send_all_writes, spawn_server, timeout,
};

const BODY_LEN: usize = 16;
const BATCH_SIZE: usize = 4;

/// join の上限（兄弟ファイルと同じ 20 秒。REPAIR-5）。
fn join_deadline() -> Duration {
    Duration::from_secs(20)
}

fn writeback_timeouts() -> WritebackTimeouts {
    WritebackTimeouts {
        recv: timeout(),
        send: timeout(),
    }
}

/// `client` 0 の `seqs` 範囲のレコードを連結した期待バイト列。
fn records(seqs: std::ops::Range<u32>) -> Vec<u8> {
    seqs.flat_map(|seq| body_for(0, seq, BODY_LEN)).collect()
}

fn bodies(seqs: std::ops::Range<u32>) -> Vec<Vec<u8>> {
    seqs.map(|seq| body_for(0, seq, BODY_LEN)).collect()
}

/// `data` を先頭から走査し、完全なレコードの件数と末尾の端数バイト数を返す
/// （panic しない。[`decompose_records`] は破損で panic するため、部分レコードの
/// 検出用に別に持つ）。
fn split_trailing_partial(data: &[u8]) -> (usize, usize) {
    let mut complete = 0usize;
    let mut rest = data;
    while rest.len() >= harness::BODY_HEADER_LEN {
        let Some(len_bytes) = rest.get(6..10).and_then(|b| <[u8; 4]>::try_from(b).ok()) else {
            break;
        };
        let len = u32::from_le_bytes(len_bytes) as usize;
        if len < harness::BODY_HEADER_LEN || rest.len() < len {
            break;
        }
        complete += 1;
        rest = rest.get(len..).unwrap_or(&[]);
    }
    (complete, rest.len())
}

/// 完全 2 レコード（seq 4・5）＋ seq 6 のヘッダ全体と body 3 バイトで切れた端数（13 バイト）。
fn partial_bytes() -> Vec<u8> {
    let mut partial = records(4..6);
    let torn = body_for(0, 6, BODY_LEN);
    partial.extend_from_slice(torn.get(..13).expect("torn prefix"));
    partial
}

/// `fail_on_call` 回目（1 始まり）の `write_batch` で、`partial` を実ファイルへ
/// 追記してから `Err` を返す sink。それ以外の呼び出しは実 `AppendFileSink` へ委譲する。
/// 単一スレッド・逐次の使用なら、`AppendFileSink` のバッチごとの末尾位置合わせにより
/// 別ハンドルの追記と交錯しない。
struct PartialWriteSink {
    inner: fandhe_container_io::AppendFileSink,
    tap: std::fs::File,
    fail_on_call: usize,
    calls: usize,
    partial: Vec<u8>,
}

impl PartialWriteSink {
    fn new(path: &Path, fail_on_call: usize, partial: Vec<u8>) -> Self {
        let inner = open_sink(path, SinkOpenMode::CreateOrTruncate).expect("create output file");
        let tap = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open append tap");
        Self {
            inner,
            tap,
            fail_on_call,
            calls: 0,
            partial,
        }
    }
}

impl BatchSink for PartialWriteSink {
    fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
        self.calls += 1;
        if self.calls == self.fail_on_call {
            self.tap
                .write_all(&self.partial)
                .expect("inject partial bytes");
            return Err(IoError::new(
                IoErrorCode::ResourceExhausted,
                "injected partial write",
            ));
        }
        self.inner.write_batch(batch)
    }

    fn persist(&mut self) -> Result<fandhe_container_io::SinkPersistReport, IoError> {
        self.inner.persist()
    }
}

/// クライアントと、`serve_connection` を動かすサーバースレッドの組。
struct Session {
    client: PipelineClient<DuplexEnd, NoopSendObserver>,
    server: std::thread::JoinHandle<WritebackReport>,
}

impl Session {
    fn start<W: BatchSink + Send + 'static>(sink: W, in_flight: usize) -> Self {
        let (client_end, server_end) = harness::duplex();
        let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");
        let server = spawn_server(server_end, config, sink, writeback_timeouts());
        let client = PipelineClient::new(
            client_end,
            InFlightLimit::new(in_flight).expect("valid in-flight limit"),
            NoopSendObserver,
        );
        Self { client, server }
    }

    fn send(&mut self, bodies: &[Vec<u8>]) {
        send_all_writes(&mut self.client, bodies, timeout());
    }

    /// 以降 ACK が 1 件も来ず、接続が閉じる（`Unavailable`）ことを確認する。
    fn expect_closed_without_ack(&mut self, context: &str) {
        let err = self.client.recv_ack(timeout()).expect_err(context);
        assert_eq!(err.code(), IoErrorCode::Unavailable, "{context}: {err}");
    }

    fn finish(self) -> WritebackReport {
        drop(self.client);
        join_within(self.server, join_deadline())
    }
}

/// W1: 第 2 バッチの途中で書き込みが失敗しても、そのバッチの ACK は 1 件も出ない。
///
/// IO-4・REPAIR-6・D6。ACK 済みの第 1 バッチ（seq 0..4）はファイル先頭に完全一致し、
/// 失敗バッチの書き残し（完全 2 件＋端数）は ACK されない。
#[test]
fn io4_write_failure_second_batch_partial_write_never_acked() {
    let dir = TempDir::new("write-failure-second-batch");
    let path = dir.file_path("data.bin");
    let partial = partial_bytes();
    let sink = PartialWriteSink::new(&path, 2, partial.clone());

    let mut session = Session::start(sink, 9);
    session.send(&bodies(0..8));
    drain_acks(&mut session.client, BATCH_SIZE, timeout());
    session.expect_closed_without_ack("no ack may arrive for the failed batch");
    let report = session.finish();

    assert_eq!(report.end.code(), IoErrorCode::ResourceExhausted);
    assert_eq!(report.stats.acks_sent, 4);
    assert_eq!(report.stats.batches_written, 1);
    assert_eq!(report.stats.bytes_written, (4 * BODY_LEN) as u64);
    assert_eq!(report.stats.discarded_pending_frames, 0);

    let data = std::fs::read(&path).expect("read output");
    let acked = records(0..4);
    assert_eq!(data.get(..acked.len()), Some(acked.as_slice()));
    let mut expected = acked;
    expected.extend_from_slice(&partial);
    assert_eq!(data, expected);
    // 末尾の部分レコードを検出できる（完全 6 件＋端数 13 バイト）。
    assert_eq!(split_trailing_partial(&data), (6, 13));
    // 破損の検出は panic で表れる（rename_truncate の T3 と同じ見方）。
    let result = std::panic::catch_unwind(|| decompose_records(&data));
    assert!(result.is_err(), "truncated tail must be detected");
}

/// W2: 失敗後に未 ACK の seq 4..8 を新セッションで再送すると、書き残しの後ろへ
/// 追記され重複しうる。
///
/// D6 の範囲内の現行挙動の記録であり、呼び出し側は ACK 済み境界へ切り詰める等で
/// 扱う前提（契約の変更ではない。IO-4・REPAIR-6）。
#[test]
fn io4_write_failure_resend_after_reconnect_duplicates_unacked_records() {
    let dir = TempDir::new("write-failure-resend");
    let path = dir.file_path("data.bin");
    let partial = partial_bytes();

    let mut session = Session::start(PartialWriteSink::new(&path, 2, partial.clone()), 9);
    session.send(&bodies(0..8));
    drain_acks(&mut session.client, BATCH_SIZE, timeout());
    let _ = session.finish();

    let sink = open_sink(&path, SinkOpenMode::Existing).expect("reopen");
    let mut session2 = Session::start(sink, 5);
    session2.send(&bodies(4..8));
    drain_acks(&mut session2.client, 4, timeout());
    let report = session2.finish();
    assert_eq!(report.stats.acks_sent, 4);

    let data = std::fs::read(&path).expect("read output");
    let mut expected = records(0..4);
    expected.extend_from_slice(&partial);
    expected.extend_from_slice(&records(4..8));
    assert_eq!(data, expected);
    // 書き残しの端数があるため、ファイル全体はレコード分解できない。
    assert!(std::panic::catch_unwind(|| decompose_records(&data)).is_err());
    // 書き残しの端数（13 バイト）が再送レコードの先頭 3 バイトを巻き込むため、
    // 端数以降は先頭から走査するとレコード境界がずれる。ACK 済み境界（4 件）と
    // 書き残しまでの範囲だけが、完全 6 件＋端数 13 バイトとして読める。
    let cut = records(0..4).len() + partial.len();
    assert_eq!(
        split_trailing_partial(data.get(..cut).expect("prefix")),
        (6, 13)
    );
}

/// W3: `/dev/full` への実書き込み失敗（ENOSPC）は `ResourceExhausted` になり ACK は 0 件。
///
/// IO-4・REPAIR-6。本番の写像 `StorageFull` → `ResourceExhausted` を実エラーで通す。
#[cfg(target_os = "linux")]
#[test]
fn io4_write_failure_dev_full_enospc_maps_to_resource_exhausted() {
    let file = OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let sink = AppendFileSink::new(file).expect("sink over /dev/full");

    let mut session = Session::start(sink, 5);
    session.send(&bodies(0..4));
    session.expect_closed_without_ack("no ack may arrive when the write fails with ENOSPC");
    let report = session.finish();

    assert_eq!(report.end.code(), IoErrorCode::ResourceExhausted);
    assert_eq!(
        report.end.message(),
        "sink write failed (StorageFull) while writing a batch of 4 frame(s)"
    );
    assert!(!report.end.message().contains("/dev/full"));
    assert_eq!(report.stats.acks_sent, 0);
    assert_eq!(report.stats.batches_written, 0);
}

/// W4: 読み取り専用ハンドルへの書き込み失敗は `Internal` になり、ACK は 0 件・
/// ファイルは不変。
///
/// IO-4・REPAIR-6。`AppendFileSink::new` の「書き込みモードで開く」前提をあえて
/// 破る注入。
#[test]
fn io4_write_failure_read_only_handle_maps_to_internal() {
    let dir = TempDir::new("write-failure-read-only");
    let path = dir.file_path("data.bin");
    let original = records(100..102);
    std::fs::write(&path, &original).expect("seed file");
    let file = std::fs::File::open(&path).expect("open read-only");
    let sink = fandhe_container_io::AppendFileSink::new(file).expect("sink over read-only handle");

    let mut session = Session::start(sink, 5);
    session.send(&bodies(0..4));
    session.expect_closed_without_ack("no ack may arrive when the write fails");
    let report = session.finish();

    assert_eq!(report.end.code(), IoErrorCode::Internal);
    let message = report.end.message().to_string();
    assert!(message.starts_with("sink write failed ("), "{message}");
    assert!(
        message.ends_with(") while writing a batch of 4 frame(s)"),
        "{message}"
    );
    let path_str = path.to_string_lossy().into_owned();
    assert!(!message.contains(&path_str), "{message}");
    assert_eq!(report.stats.acks_sent, 0);
    assert_eq!(std::fs::read(&path).expect("read"), original);
}

/// W5: Flush で取り出された端数バッチの書き込みが失敗すると、そのバッチの ACK も
/// FlushAck も出ず、persist も呼ばれない。
///
/// IO-4・REPAIR-6・D6（IO-2 の FlushAck は書き込み成功が前提）。
#[test]
fn io4_write_failure_on_flush_pending_batch_sends_no_ack_or_flush_ack() {
    let dir = TempDir::new("write-failure-on-flush");
    let path = dir.file_path("data.bin");
    let partial = records(4..5);
    let mut session = Session::start(PartialWriteSink::new(&path, 2, partial.clone()), 8);
    session.send(&bodies(0..6));
    session
        .client
        .send(FrameKind::Flush, &[], timeout())
        .expect("flush send");
    drain_acks(&mut session.client, BATCH_SIZE, timeout());
    session.expect_closed_without_ack("neither ack nor flush ack may follow the failed batch");
    let report = session.finish();

    assert_eq!(report.end.code(), IoErrorCode::ResourceExhausted);
    assert_eq!(report.stats.acks_sent, 4);
    assert_eq!(report.stats.flush_acks_sent, 0);
    assert_eq!(report.stats.persist_succeeded, 0);
    assert_eq!(report.stats.persist_failed, 0);
    assert_eq!(report.stats.discarded_pending_frames, 0);

    let data = std::fs::read(&path).expect("read output");
    let mut expected = records(0..4);
    expected.extend_from_slice(&partial);
    assert_eq!(data, expected);
}
