//! 静止点を作らずに、書き込みと rename・truncate を交錯させる整合性試験
//! （TASK-14 追補・#1830・IO-4・REPAIR-6。関連 REPAIR-5・REPAIR-12）。
//!
//! # 位置づけ
//!
//! 既存の [`rename_truncate`](super::rename_truncate) は操作を決定的な静止点
//! （`serve_connection` の join 後、または ACK を全件受けた直後）でしか行わない。
//! 本ファイルは ACK 受信前、つまり `write_batch` の前・サブバッチの間・後
//! （ACK の送出前）に外から rename・truncate を差し込む経路を検証する。
//!
//! # 差し込みの方法
//!
//! 1. 決定的な差し込み: 試験用 `InterposingSink`（`BatchSink` ラッパー）が、
//!    計画（位置 → 操作）に従ってパス経由で `rename` / `set_len` / 再作成を行う。
//!    - `Position::BeforeBatch`: n 番目の `write_batch` の先頭。
//!    - `Position::AfterFrame`: n 番目のバッチをフレームごとのサブバッチへ
//!      分けて書き、i 番目のフレームの後。
//!    - `Position::AfterBatch`: `write_batch` の完了後で ACK の送出前
//!      （既存の試験は ACK 受信後にしか操作しないので、これが新しい位置）。
//! 2. 同時実行の反復: `Barrier` で書き込みと rename を同時に解放する（rename のみ）。
//!
//! # 限界（本番コードを変えずに差し込める範囲）
//!
//! 内側の `AppendFileSink::write_batch` の中（フレーム間）へは差し込めない。
//! 「フレーム間」はサブバッチ分割による「サブバッチ間」であり、サブバッチごとに
//! `seek(End)` が走る。1 回の `write_batch` の最中の外部 truncate は
//! `AppendFileSink::new` の doc が対象外と明記しており、本ファイルは同時 truncate
//! の固定の期待値を置かない。
//!
//! # 成り立つ条件（期待値は `Vec<u8>` への追記・`set_len` 相当の単純な模型で作る）
//!
//! | 操作 | 最終内容 |
//! | ---- | -------- |
//! | rename（開いたまま移動） | 移動先に全レコードが完全一致・元パスは不在 |
//! | `set_len(0)` | 縮小後に書かれたレコードだけ（先頭から。穴なし） |
//! | `set_len(K レコード長)` | 先頭 K レコード + 縮小後のレコード |
//! | `set_len(現在長 + e)` | 縮小前の内容 + e バイトのゼロ + 縮小後のレコード |
//!
//! 追記モード・通常モードの両方で、位置 3 通りすべてで成り立つ。拡張後のゼロ埋めは
//! POSIX `ftruncate`・Windows `SetEndOfFile` で決定的（T6 と同じ前提）。置換 rename
//! （開いているファイルへの上書き）は Windows で失敗しうるため交錯させず、
//! `rename_truncate` の R3 に残す。
//!
//! 待ちはすべて期限つき（`harness::join_within`・`barrier_wait_within`・`timeout`。
//! REPAIR-5）で、`sleep` は使わない。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

use fandhe_container_io::{
    Batch, BatchBuffer, BatchConfig, BatchSink, InFlightLimit, IoError, IoErrorCode,
    NoopSendObserver, PipelineClient, PushOutcome, SinkOpenMode, SinkWriteReport, WritebackReport,
    WritebackTimeouts,
};

use super::harness::{
    self, DuplexEnd, TempDir, barrier_wait_within, body_for, drain_acks, join_within, open_sink,
    send_all_writes, spawn_server, timeout,
};

const BODY_LEN: usize = 16;
const BATCH_SIZE: usize = 4;
/// 送るレコード数（3 バッチ）。
const TOTAL: usize = 12;

fn join_deadline() -> Duration {
    Duration::from_secs(20)
}

fn records(seqs: std::ops::Range<usize>) -> Vec<u8> {
    seqs.flat_map(|seq| body_for(0, seq as u32, BODY_LEN))
        .collect()
}

fn bodies(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|s| body_for(0, s as u32, BODY_LEN))
        .collect()
}

/// 差し込みの位置。`batch` は 1 始まり、`frame` は 0 始まり。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Position {
    BeforeBatch(usize),
    AfterFrame { batch: usize, frame: usize },
    AfterBatch(usize),
}

/// 差し込む操作（パス経由。sink が持つハンドルとは別に開く）。
#[derive(Debug, Clone)]
enum FileOp {
    Rename { from: PathBuf, to: PathBuf },
    SetLen { path: PathBuf, len: u64 },
    Recreate { path: PathBuf, bytes: Vec<u8> },
}

impl FileOp {
    fn run(&self) -> std::io::Result<()> {
        match self {
            FileOp::Rename { from, to } => std::fs::rename(from, to),
            FileOp::SetLen { path, len } => std::fs::OpenOptions::new()
                .write(true)
                .open(path)?
                .set_len(*len),
            FileOp::Recreate { path, bytes } => std::fs::write(path, bytes),
        }
    }
}

type FailureLog = Arc<Mutex<Vec<String>>>;

/// 計画に従って `write_batch` の前後・サブバッチ間で操作を差し込む sink。
/// 操作の失敗は記録して `Err` を返し、試験の最後でログが空であることを照合する。
struct InterposingSink {
    inner: fandhe_container_io::AppendFileSink,
    plan: Vec<(Position, Option<FileOp>)>,
    calls: usize,
    failures: FailureLog,
}

impl InterposingSink {
    fn fire(&mut self, pos: Position) -> Result<(), IoError> {
        for (at, op) in &mut self.plan {
            if *at != pos {
                continue;
            }
            if let Some(op) = op.take()
                && let Err(err) = op.run()
            {
                self.failures
                    .lock()
                    .expect("failure log lock")
                    .push(format!("{pos:?}: {:?}", err.kind()));
                return Err(IoError::new(
                    IoErrorCode::Internal,
                    "interposed file operation failed",
                ));
            }
        }
        Ok(())
    }

    fn has_frame_plan(&self, batch: usize) -> bool {
        self.plan
            .iter()
            .any(|(p, _)| matches!(p, Position::AfterFrame { batch: b, .. } if *b == batch))
    }
}

/// 1 フレームだけのバッチを作る。
fn single_frame_batch(frame: &fandhe_container_io::Frame) -> Result<Batch, IoError> {
    let mut buf = BatchBuffer::new(BatchConfig::new(1)?);
    match buf.push(frame.clone())? {
        PushOutcome::Ready(batch) => Ok(batch),
        _ => Err(IoError::new(
            IoErrorCode::Internal,
            "unexpected push outcome",
        )),
    }
}

impl BatchSink for InterposingSink {
    fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
        self.calls += 1;
        let n = self.calls;
        self.fire(Position::BeforeBatch(n))?;
        let report = if self.has_frame_plan(n) {
            let (mut frames, mut bytes) = (0usize, 0u64);
            for (i, frame) in batch.frames().iter().enumerate() {
                let sub = single_frame_batch(frame)?;
                let r = self.inner.write_batch(&sub)?;
                frames += r.frames_written;
                bytes += r.bytes_written;
                self.fire(Position::AfterFrame { batch: n, frame: i })?;
            }
            SinkWriteReport::new(frames, bytes)
        } else {
            self.inner.write_batch(batch)?
        };
        self.fire(Position::AfterBatch(n))?;
        Ok(report)
    }

    fn persist(&mut self) -> Result<fandhe_container_io::SinkPersistReport, IoError> {
        self.inner.persist()
    }
}

#[derive(Debug, Clone, Copy)]
enum Mode {
    Normal,
    Append,
}

impl Mode {
    fn open_mode(self) -> SinkOpenMode {
        match self {
            Mode::Normal => SinkOpenMode::CreateOrTruncate,
            Mode::Append => SinkOpenMode::CreateOrAppend,
        }
    }
}

const MODES: [Mode; 2] = [Mode::Normal, Mode::Append];

/// 位置と、その時点でファイルに書かれているレコード数。
fn positions() -> [(Position, usize); 3] {
    [
        (Position::BeforeBatch(2), BATCH_SIZE),
        (Position::AfterFrame { batch: 2, frame: 1 }, BATCH_SIZE + 2),
        (Position::AfterBatch(2), 2 * BATCH_SIZE),
    ]
}

struct Session {
    client: PipelineClient<DuplexEnd, NoopSendObserver>,
    server: std::thread::JoinHandle<WritebackReport>,
}

impl Session {
    fn start<W: BatchSink + Send + 'static>(sink: W, in_flight: usize) -> Self {
        let (client_end, server_end) = harness::duplex();
        let config = BatchConfig::new(BATCH_SIZE).expect("valid batch size");
        let timeouts = WritebackTimeouts {
            recv: timeout(),
            send: timeout(),
        };
        let server = spawn_server(server_end, config, sink, timeouts);
        let client = PipelineClient::new(
            client_end,
            InFlightLimit::new(in_flight).expect("valid in-flight limit"),
            NoopSendObserver,
        );
        Self { client, server }
    }

    fn finish(self) -> WritebackReport {
        drop(self.client);
        join_within(self.server, join_deadline())
    }
}

/// 計画つきで `TOTAL` 件を送り、全 ACK を受けて終了する。失敗ログを返す。
fn run_interleaved(
    path: &Path,
    mode: Mode,
    plan: Vec<(Position, FileOp)>,
    label: &str,
) -> Vec<String> {
    let failures: FailureLog = Arc::default();
    let sink = InterposingSink {
        inner: open_sink(path, mode.open_mode()).expect("open sink"),
        plan: plan.into_iter().map(|(p, o)| (p, Some(o))).collect(),
        calls: 0,
        failures: Arc::clone(&failures),
    };
    let mut session = Session::start(sink, TOTAL + 1);
    send_all_writes(&mut session.client, &bodies(TOTAL), timeout());
    drain_acks(&mut session.client, TOTAL, timeout());
    let report = session.finish();
    assert_eq!(
        report.end.code(),
        IoErrorCode::Unavailable,
        "{label}: session end"
    );
    assert_eq!(report.stats.acks_sent, TOTAL as u64, "{label}: acks");
    assert_eq!(
        report.stats.batches_written,
        (TOTAL / BATCH_SIZE) as u64,
        "{label}: batches"
    );
    failures.lock().expect("failure log lock").clone()
}

fn assert_no_failures(log: &[String], label: &str) {
    assert!(log.is_empty(), "{label}: interposed ops failed: {log:?}");
}

/// I1: 書き込み中のファイルを rename しても、開いているハンドルへの書き込みが
/// 移動先へ続く（位置 3 通り × 2 モード）。IO-4・REPAIR-6。
#[test]
fn io4_interleave_rename_before_mid_after_batch_follows_handle() {
    for mode in MODES {
        for (pos, _) in positions() {
            let label = format!("{mode:?}/{pos:?}");
            let dir = TempDir::new("interleave-rename");
            let src = dir.file_path("a.bin");
            let dst = dir.file_path("b.bin");
            let plan = vec![(
                pos,
                FileOp::Rename {
                    from: src.clone(),
                    to: dst.clone(),
                },
            )];
            let log = run_interleaved(&src, mode, plan, &label);
            assert_no_failures(&log, &label);
            assert_eq!(
                std::fs::read(&dst).expect("read moved"),
                records(0..TOTAL),
                "{label}"
            );
            assert!(!src.exists(), "{label}: source path must be gone");
        }
    }
}

/// I2: a→b→c と連鎖 rename し、元の a を無関係な内容で作り直しても、後続の書き込みは
/// a へ混入せず最終の c へ続く。IO-4・REPAIR-6。
#[test]
fn io4_interleave_rename_chain_and_recreate_source_no_leak() {
    let unrelated = b"unrelated-content".to_vec();
    for mode in MODES {
        let label = format!("{mode:?}");
        let dir = TempDir::new("interleave-chain");
        let a = dir.file_path("a.bin");
        let b = dir.file_path("b.bin");
        let c = dir.file_path("c.bin");
        let plan = vec![
            (
                Position::BeforeBatch(2),
                FileOp::Rename {
                    from: a.clone(),
                    to: b.clone(),
                },
            ),
            (
                Position::AfterFrame { batch: 2, frame: 0 },
                FileOp::Recreate {
                    path: a.clone(),
                    bytes: unrelated.clone(),
                },
            ),
            (
                Position::AfterBatch(2),
                FileOp::Rename {
                    from: b.clone(),
                    to: c.clone(),
                },
            ),
        ];
        let log = run_interleaved(&a, mode, plan, &label);
        assert_no_failures(&log, &label);
        assert_eq!(
            std::fs::read(&c).expect("read c"),
            records(0..TOTAL),
            "{label}"
        );
        assert_eq!(std::fs::read(&a).expect("read a"), unrelated, "{label}");
        assert!(!b.exists(), "{label}: intermediate path must be gone");
    }
}

/// 縮小・拡張の種類。
#[derive(Debug, Clone, Copy)]
enum Trunc {
    Zero,
    ToRecords(usize),
    ExtendBy(usize),
}

/// 模型: `k_before` レコード書いた後に `trunc` を適用し、残りのレコードを追記する。
fn model_expected(k_before: usize, trunc: Trunc) -> Vec<u8> {
    let mut data = records(0..k_before);
    match trunc {
        Trunc::Zero => data.clear(),
        Trunc::ToRecords(k) => data.truncate(k * BODY_LEN),
        Trunc::ExtendBy(e) => data.resize(data.len() + e, 0),
    }
    data.extend(records(k_before..TOTAL));
    data
}

fn trunc_len(k_before: usize, trunc: Trunc) -> u64 {
    let len = match trunc {
        Trunc::Zero => 0,
        Trunc::ToRecords(k) => k * BODY_LEN,
        Trunc::ExtendBy(e) => k_before * BODY_LEN + e,
    };
    len as u64
}

fn truncate_matrix(tag: &str, trunc: Trunc) {
    for mode in MODES {
        for (pos, k_before) in positions() {
            let label = format!("{tag}/{mode:?}/{pos:?}");
            let dir = TempDir::new("interleave-truncate");
            let path = dir.file_path("data.bin");
            let plan = vec![(
                pos,
                FileOp::SetLen {
                    path: path.clone(),
                    len: trunc_len(k_before, trunc),
                },
            )];
            let log = run_interleaved(&path, mode, plan, &label);
            assert_no_failures(&log, &label);
            assert_eq!(
                std::fs::read(&path).expect("read output"),
                model_expected(k_before, trunc),
                "{label}"
            );
        }
    }
}

/// I3: `set_len(0)` の後は縮小後のレコードだけが先頭から残る（穴なし）。
#[test]
fn io4_interleave_truncate_to_zero_matrix() {
    truncate_matrix("zero", Trunc::Zero);
}

/// I4: レコード境界（2 レコード）への縮小の後は、先頭 2 レコード + 縮小後のレコード。
#[test]
fn io4_interleave_truncate_to_record_boundary_matrix() {
    truncate_matrix("boundary", Trunc::ToRecords(2));
}

/// I5: 拡張（5 バイト）の後は、縮小前の内容 + ゼロ 5 バイト + 縮小後のレコード。
#[test]
fn io4_interleave_truncate_extend_zero_fills_matrix() {
    truncate_matrix("extend", Trunc::ExtendBy(5));
}

/// I6: barrier で書き込みと rename を同時に解放しても、移動先に全バイトが入り元パスは
/// 残らない（100 反復 × 2 モード）。IO-4・REPAIR-6・REPAIR-5。
#[test]
fn io4_interleave_concurrent_rename_barrier_iterations() {
    const ITERATIONS: usize = 100;
    for mode in MODES {
        let dir = TempDir::new("interleave-concurrent");
        let mut mid_flight = 0usize;
        for i in 0..ITERATIONS {
            let label = format!("{mode:?}/iter {i}");
            let src = dir.file_path(&format!("iter-{i}.bin"));
            let dst = dir.file_path(&format!("iter-{i}.moved"));
            let sink = open_sink(&src, mode.open_mode()).expect("open sink");
            let mut session = Session::start(sink, TOTAL + 1);
            let barrier = Arc::new(Barrier::new(2));
            let renamer = {
                let barrier = Arc::clone(&barrier);
                let (src, dst) = (src.clone(), dst.clone());
                std::thread::spawn(move || {
                    barrier_wait_within(&barrier, join_deadline());
                    let before = std::fs::metadata(&src).map(|m| m.len()).unwrap_or(0);
                    std::fs::rename(&src, &dst).map(|()| before)
                })
            };
            barrier_wait_within(&barrier, join_deadline());
            send_all_writes(&mut session.client, &bodies(TOTAL), timeout());
            drain_acks(&mut session.client, TOTAL, timeout());
            let report = session.finish();
            let before = join_within(renamer, join_deadline()).expect("rename must succeed");
            assert_eq!(report.stats.acks_sent, TOTAL as u64, "{label}");
            if before > 0 && before < (TOTAL * BODY_LEN) as u64 {
                mid_flight += 1;
            }
            assert_eq!(
                std::fs::read(&dst).expect("read moved"),
                records(0..TOTAL),
                "{label}"
            );
            assert!(!src.exists(), "{label}: source path must be gone");
        }
        // 観測のみ（assert しない）。rename が書き込みの途中に着地した反復の数。
        eprintln!("{mode:?}: rename landed mid-write in {mid_flight}/{ITERATIONS} iterations");
    }
}
