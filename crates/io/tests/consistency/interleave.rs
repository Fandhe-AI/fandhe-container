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
//! 2. 同時実行の反復（I6）: sink が書き込みの途中で `mpsc` に信号を出し、rename
//!    スレッドが受けて残りの書き込みと並行に rename する（rename のみ。barrier で
//!    同時に解放するだけでは、通常モードで途中に着地した反復が 0/100 だった）。
//! 3. 1 回の `write_batch` の最中の truncate（I7）: `AppendFileSink` の試験用の継ぎ目
//!    `write_batch_with_frame_hook` で、実際の `write_batch` の k フレーム目を書いた直後に
//!    同じスレッドからパス経由の `set_len` を行う（スレッド・時間・スケジューラに依らない
//!    決定的な差し込み。REPAIR-12）。
//!
//! # 限界
//!
//! 1 回の `write_batch` の最中の外部 truncate は `AppendFileSink::new` の doc が
//! 「追随の対象外」とするが、I7 が上記の継ぎ目で固定の期待値を置く（truncate 時点で k
//! レコードが書かれ、m レコード長へ縮小した場合。縮小先がレコード境界のためレコードは
//! 分断されない）。
//!
//! - 通常モード: 先頭 m レコード + `[m, k)` のゼロ埋めの穴 + 元の位置の後続レコード。
//! - 追記モード: 先頭 m レコード + 後続レコード（穴なし）。
//!
//! 破損は「モデルに完全一致しない」（ずれ・重複・欠落・混入・断片）こと。縮小前の内容の
//! 消失と通常モードの穴は呼び出し側の truncate の帰結で、破損と判定しない。
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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_io::{
    Batch, BatchBuffer, BatchConfig, BatchSink, InFlightLimit, IoError, IoErrorCode,
    NoopSendObserver, PipelineClient, PushOutcome, SinkOpenMode, SinkWriteReport, WritebackReport,
    WritebackTimeouts,
};

use super::harness::{
    self, DuplexEnd, TempDir, body_for, drain_acks, join_within, open_sink, send_all_writes,
    spawn_server, timeout,
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

/// 書き込みの途中で信号を出す sink（I6 用）。n 番目のバッチをフレームごとのサブバッチへ
/// 分けて書き、`signal_after` 個目のフレームを書いた直後に「それまでに書いたバイト数」を
/// `tx` へ送り、受け手（rename スレッド）が操作を終えて `resume` へ通知するまで
/// 期限つきで待つ（進行制御のゲート。REPAIR-12）。これで受け手の操作は「残りのフレームを
/// 書く前」に必ず着地し、スケジューラに依らず書き込みの途中での交錯が成立する。
struct SignalingSink {
    inner: fandhe_container_io::AppendFileSink,
    tx: Option<std::sync::mpsc::Sender<u64>>,
    resume: std::sync::mpsc::Receiver<()>,
    signal_batch: usize,
    signal_after: usize,
    calls: usize,
    bytes: u64,
}

impl BatchSink for SignalingSink {
    fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
        self.calls += 1;
        let (mut frames, mut bytes) = (0usize, 0u64);
        for (i, frame) in batch.frames().iter().enumerate() {
            let sub = single_frame_batch(frame)?;
            let r = self.inner.write_batch(&sub)?;
            frames += r.frames_written;
            bytes += r.bytes_written;
            self.bytes += r.bytes_written;
            if self.calls == self.signal_batch
                && i + 1 == self.signal_after
                && let Some(tx) = self.tx.take()
            {
                // 受け手が先に終了していても書き込みは続ける（送信失敗は無視）。
                // 待ちは期限つき（REPAIR-5）。超過しても書き込みは続け、受け手側の assert が失敗を示す。
                if tx.send(self.bytes).is_ok() {
                    let _ = self.resume.recv_timeout(join_deadline());
                }
            }
        }
        Ok(SinkWriteReport::new(frames, bytes))
    }

    fn persist(&mut self) -> Result<fandhe_container_io::SinkPersistReport, IoError> {
        self.inner.persist()
    }
}

/// I6: 書き込みの途中（2 バッチ目の 2 フレーム目の直後。6 レコード書いた時点）で sink が
/// 信号を出して待ち、rename スレッドがそれを受けて rename し、終えたら sink が残りを書く
/// （100 反復 × 2 モード）。移動先に全バイトが入り元パスは残らない。
/// rename スレッドは rename 直前に元ファイルの実サイズを観測し、信号どおり 6 レコード
/// （全量未満）であること、つまり rename が実際に書き込みの途中に着地したことを
/// 全反復で assert する（信号値の再確認ではなく、rename 側の観測。REPAIR-12）。
/// IO-4・REPAIR-6・REPAIR-5。
#[test]
fn io4_interleave_concurrent_rename_signal_mid_write_iterations() {
    const ITERATIONS: usize = 100;
    for mode in MODES {
        let dir = TempDir::new("interleave-concurrent");
        for i in 0..ITERATIONS {
            let label = format!("{mode:?}/iter {i}");
            let src = dir.file_path(&format!("iter-{i}.bin"));
            let dst = dir.file_path(&format!("iter-{i}.moved"));
            let (tx, rx) = std::sync::mpsc::channel::<u64>();
            let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
            let sink = SignalingSink {
                inner: open_sink(&src, mode.open_mode()).expect("open sink"),
                tx: Some(tx),
                resume: resume_rx,
                signal_batch: 2,
                signal_after: 2,
                calls: 0,
                bytes: 0,
            };
            let mut session = Session::start(sink, TOTAL + 1);
            let renamer = {
                let (src, dst) = (src.clone(), dst.clone());
                std::thread::spawn(move || {
                    let written = rx
                        .recv_timeout(join_deadline())
                        .expect("sink must signal mid-write");
                    // sink は resume を受けるまで書かないので、実サイズは書き込み済み量に等しい。
                    let observed = std::fs::metadata(&src).map(|md| md.len());
                    let renamed = std::fs::rename(&src, &dst);
                    let _ = resume_tx.send(());
                    renamed.and(observed).map(|len| (written, len))
                })
            };
            send_all_writes(&mut session.client, &bodies(TOTAL), timeout());
            drain_acks(&mut session.client, TOTAL, timeout());
            let report = session.finish();
            let (written, observed) =
                join_within(renamer, join_deadline()).expect("rename must succeed");
            assert_eq!(report.stats.acks_sent, TOTAL as u64, "{label}");
            assert_eq!(
                written,
                ((BATCH_SIZE + 2) * BODY_LEN) as u64,
                "{label}: signal must fire mid-write"
            );
            assert_eq!(
                observed, written,
                "{label}: size seen by the renamer just before rename"
            );
            assert!(observed < (TOTAL * BODY_LEN) as u64, "{label}");
            assert_eq!(
                std::fs::read(&dst).expect("read moved"),
                records(0..TOTAL),
                "{label}"
            );
            assert!(!src.exists(), "{label}: source path must be gone");
        }
    }
}

/// I7 用: 1 バッチに入れるレコード数・レコード長（`MAX_BATCH_SIZE` 以下）。
const I7_TOTAL: usize = 512;
const I7_BODY_LEN: usize = 512;
/// truncate を差し込む書き込み済みレコード数 `k`。
const I7_TRIGGER: usize = 128;

fn i7_records(seqs: std::ops::Range<usize>) -> Vec<u8> {
    seqs.flat_map(|seq| body_for(0, seq as u32, I7_BODY_LEN))
        .collect()
}

/// I7 の期待モデル。truncate 時点で `k` レコード書かれており `m` レコード長へ縮小した場合。
/// 通常モードは `[m, k)` がゼロ埋めの穴（カーソルが古い EOF に残るため）、追記モードは穴なし。
fn i7_model(mode: Mode, m: usize, k: usize) -> Vec<u8> {
    let mut data = i7_records(0..m);
    if matches!(mode, Mode::Normal) {
        data.resize(k * I7_BODY_LEN, 0);
    }
    data.extend(i7_records(k..I7_TOTAL));
    data
}

/// 実際の `AppendFileSink::write_batch` のフレーム間（`k` フレーム書いた直後）で、
/// パス経由の `set_len` を同じスレッドで行う sink。スケジューラに依らず、truncate が
/// 1 回の `write_batch` の最中に必ず着地する（REPAIR-12）。失敗は記録して試験末尾で照合する。
struct TruncatingSink {
    inner: fandhe_container_io::AppendFileSink,
    path: PathBuf,
    trigger: usize,
    len: u64,
    failures: FailureLog,
}

impl BatchSink for TruncatingSink {
    fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
        let (path, trigger, len, failures) = (&self.path, self.trigger, self.len, &self.failures);
        self.inner
            .write_batch_with_frame_hook(batch, &mut |written| {
                if written == trigger {
                    let op = FileOp::SetLen {
                        path: path.clone(),
                        len,
                    };
                    if let Err(err) = op.run() {
                        failures
                            .lock()
                            .expect("lock")
                            .push(format!("set_len: {:?}", err.kind()));
                    }
                }
            })
    }

    fn persist(&mut self) -> Result<fandhe_container_io::SinkPersistReport, IoError> {
        self.inner.persist()
    }
}

/// 1 回の `write_batch` の最中（`I7_TRIGGER` レコード書いた直後）に truncate を行い、
/// 最終ファイルを返す。
fn i7_run_once(mode: Mode, m: usize, dir: &TempDir) -> (Vec<u8>, Vec<String>) {
    let path = dir.file_path("data.bin");
    let (client_end, server_end) = harness::duplex();
    let config = BatchConfig::new(I7_TOTAL).expect("valid batch size");
    let timeouts = WritebackTimeouts {
        recv: timeout(),
        send: timeout(),
    };
    let failures: FailureLog = Arc::default();
    let sink = TruncatingSink {
        inner: open_sink(&path, mode.open_mode()).expect("open sink"),
        path: path.clone(),
        trigger: I7_TRIGGER,
        len: (m * I7_BODY_LEN) as u64,
        failures: Arc::clone(&failures),
    };
    let server = spawn_server(server_end, config, sink, timeouts);
    let mut client = PipelineClient::new(
        client_end,
        InFlightLimit::new(I7_TOTAL + 1).expect("valid in-flight limit"),
        NoopSendObserver,
    );
    let bodies: Vec<Vec<u8>> = (0..I7_TOTAL)
        .map(|s| body_for(0, s as u32, I7_BODY_LEN))
        .collect();
    send_all_writes(&mut client, &bodies, timeout());
    drain_acks(&mut client, I7_TOTAL, timeout());
    drop(client);
    let report = join_within(server, join_deadline());
    assert_eq!(report.end.code(), IoErrorCode::Unavailable, "session end");
    assert_eq!(report.stats.acks_sent, I7_TOTAL as u64, "acks");
    assert_eq!(report.stats.batches_written, 1, "single batch");
    let log = failures.lock().expect("lock").clone();
    (std::fs::read(&path).expect("read output"), log)
}

fn i7_matrix(mode: Mode) {
    for m in [0usize, I7_TRIGGER / 2] {
        let dir = TempDir::new("interleave-write-batch-truncate");
        let (data, log) = i7_run_once(mode, m, &dir);
        assert_no_failures(&log, &format!("{mode:?}/m={m}"));
        // k は固定（I7_TRIGGER）。モデルとの完全一致で、ずれ・重複・欠落・混入・断片を検出する。
        assert!(
            data == i7_model(mode, m, I7_TRIGGER),
            "{mode:?}/m={m}: final file ({} bytes) differs from the model",
            data.len()
        );
    }
}

/// I7: 通常モードで 1 回の `write_batch` の最中に並行 truncate が入った場合の期待値。
/// `[m, k)` のゼロ埋めの穴（カーソルが古い EOF に残る。縮小後に書かれたレコードがある場合）以外は、先頭 m レコード・
/// 元の位置の後続レコードがそのまま残る。破損は「どの k のモデルにも一致しない」こと。
/// 縮小前の内容の消失と穴は呼び出し側の truncate の帰結で、破損と判定しない。
/// IO-4・REPAIR-6・REPAIR-5。
#[test]
fn io4_interleave_truncate_during_single_write_batch_normal_mode() {
    i7_matrix(Mode::Normal);
}

/// I7（追記モード）: `O_APPEND` は毎回 EOF へ書くため穴ができず、先頭 m レコードの後ろに
/// 縮小後のレコードが続く。IO-4・REPAIR-6・REPAIR-5。
#[test]
fn io4_interleave_truncate_during_single_write_batch_append_mode() {
    i7_matrix(Mode::Append);
}
