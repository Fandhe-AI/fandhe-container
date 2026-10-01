//! 監視対象プロセスの stdout / stderr を行単位で捕捉する土台（TASK-157.7・#241・SUP-1。関連: CORE-1・D-19・REPAIR-3・REPAIR-5）。
//!
//! [`crate::run::monitor_with_capture`] が、呼び出し側から注入された出力ストリーム（[`OutputStreams`]）を
//! ストリームごとのリーダースレッドで読み、LF 区切りの 1 行ずつを [`LogSink`] へ渡す。
//! 子の出力は非信頼データとして不透明なバイト列のまま扱い、解釈・パス / コマンドへの連結・
//! supervisor 自身のログやエラーメッセージへの混入をしない。
//!
//! # 契約
//! - 行は LF を除いたバイト列で渡す（UTF-8 を仮定しない。CR は除去しない）。EOF 時の LF なし末尾行も 1 行として渡す。
//! - 1 行は [`MAX_LINE_BYTES`] で切り捨てる（超過ぶんは捨て、[`StreamSummary::truncated_lines`] へ数える。無制限確保の防止）。
//! - [`LogSink::append`] が失敗しても読み取りは EOF まで続けて破棄する（読みを止めるとパイプが詰まり、
//!   コンテナ側の write がブロックするため）。最初のエラーコードだけを [`StreamSummary::error_code`] に残す。
//! - [`LogCapture::drain`] は期限付き（REPAIR-5）。期限切れ（孫プロセスがパイプを保持し続ける場合等）では
//!   リーダースレッドは切り離されたまま EOF まで走り続け、sink への追記も続く。
//! - ストリームの所有権は捕捉側へ移る。監視の引き継ぎ時に再注入はできない（引き継ぎは #239・TASK-164 で扱う）。
//! - OS 固有型（fd / HANDLE）は公開せず `Read` のみを受ける（CLI-1）。グローバル状態は持たない（CORE-1・D-19）。
//!
//! # 未実装（将来仕様。REPAIR-3）
//! 本モジュールは捕捉経路の土台だけで、次は未実装である。
//! - ファイルへの永続化、ローテーション（1MiB × 3 世代等）、ローテーション下で欠落・重複 0 行の保証: SUP-7・TASK-164。
//!   ログファイルの権限・配置・symlink 検証も TASK-164 で扱う。
//! - ローテーション失敗時のエラー形式: ERR-1（TASK-164）。
//! - `logs` コマンドからの読み出し経路: TASK-164 以降 / CLI 側。
//! - 実パイプの取得: core の本番 launcher が子の stdio をパイプへ接続して渡す経路は未提供
//!   （現状 core は子の標準入出力を null へ向けている）。そのため入力は注入式である。
//!
//! 既定の [`MemoryLogSink`] はメモリ保持のみ（上限付き）で、supervisor 終了時に失われる。

use std::collections::VecDeque;
use std::io::{ErrorKind, Read};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{ErrorCode, TraitError};

/// 1 行の上限バイト数（超過ぶんは切り捨てる）。
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// 1 回の読み取りに使う固定バッファのバイト数。
pub const READ_CHUNK_BYTES: usize = 8 * 1024;

/// [`MemoryLogSink`] の既定の保持上限（総バイト数）。
pub const DEFAULT_MEMORY_SINK_BYTES: usize = 1024 * 1024;

/// 出力の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamKind {
    /// 標準出力。
    Stdout,
    /// 標準エラー出力。
    Stderr,
}

impl StreamKind {
    /// ログ・スレッド名に使う安定名。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

/// 注入される出力ストリーム（実パイプは core が未提供のため呼び出し側が渡す）。
#[derive(Default)]
pub struct OutputStreams {
    stdout: Option<Box<dyn Read + Send>>,
    stderr: Option<Box<dyn Read + Send>>,
}

impl OutputStreams {
    /// stdout / stderr を渡す。
    pub fn new(stdout: Option<Box<dyn Read + Send>>, stderr: Option<Box<dyn Read + Send>>) -> Self {
        Self { stdout, stderr }
    }

    /// 捕捉対象のストリームを 1 つも持たないか。
    pub fn is_empty(&self) -> bool {
        self.stdout.is_none() && self.stderr.is_none()
    }

    /// どちらも捕捉しない。
    pub fn none() -> Self {
        Self::default()
    }
}

/// 捕捉した行の記録先。TASK-164（SUP-7）がファイル・ローテーション実装へ差し替える拡張点。
pub trait LogSink: Send + Sync {
    /// 1 行（LF 抜き・[`MAX_LINE_BYTES`] 以下）を追記する。失敗は構造化エラーで返す（panic しない）。
    fn append(&self, stream: StreamKind, line: &[u8]) -> Result<(), TraitError>;
}

/// [`MemoryLogSink`] が保持する 1 行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedLine {
    /// 出力の種別。
    pub stream: StreamKind,
    /// LF を除いた行のバイト列。
    pub bytes: Vec<u8>,
}

/// 1 行あたりの管理コスト（`CapturedLine`・`VecDeque` 要素の概算）。長さ 0 の行でも保持量へ計上し、
/// 空行の連続出力による無制限なメモリ増加を防ぐ（非信頼出力への上限。REPAIR-5 の資源上限方針）。
const LINE_OVERHEAD_BYTES: usize = 64;

fn line_cost(len: usize) -> usize {
    len.saturating_add(LINE_OVERHEAD_BYTES)
}

#[derive(Default)]
struct MemoryInner {
    lines: VecDeque<CapturedLine>,
    total_bytes: usize,
    dropped_lines: u64,
}

/// 上限付きメモリ保持のスタブ sink。永続化・ローテーションは行わずプロセス終了で失われる
/// （SUP-7・TASK-164 で置き換える。REPAIR-3）。上限超過時は古い行から捨て、件数を数える。
pub struct MemoryLogSink {
    capacity: usize,
    inner: Mutex<MemoryInner>,
}

impl MemoryLogSink {
    /// `capacity_bytes` が最大 1 行ぶん（[`MAX_LINE_BYTES`] + 行ごとの固定費）未満なら `InvalidArgument`（1 行が保持できなくなるため）。
    pub fn new(capacity_bytes: usize) -> Result<Self, TraitError> {
        if capacity_bytes < line_cost(MAX_LINE_BYTES) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "memory sink capacity is smaller than the maximum line size",
            ));
        }
        Ok(Self {
            capacity: capacity_bytes,
            inner: Mutex::new(MemoryInner::default()),
        })
    }

    /// 現在保持している行の複製（古い順）。
    pub fn snapshot(&self) -> Result<Vec<CapturedLine>, TraitError> {
        Ok(self.lock()?.lines.iter().cloned().collect())
    }

    /// 上限超過で捨てた行数。
    pub fn dropped_lines(&self) -> Result<u64, TraitError> {
        Ok(self.lock()?.dropped_lines)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemoryInner>, TraitError> {
        self.inner
            .lock()
            .map_err(|_| TraitError::new(ErrorCode::Internal, "memory log sink lock poisoned"))
    }
}

impl Default for MemoryLogSink {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_MEMORY_SINK_BYTES,
            inner: Mutex::new(MemoryInner::default()),
        }
    }
}

impl LogSink for MemoryLogSink {
    fn append(&self, stream: StreamKind, line: &[u8]) -> Result<(), TraitError> {
        // 直接呼び出しでも行サイズ上限を超えて確保しないよう、確保前に MAX_LINE_BYTES へ切り詰める。
        let line = line.get(..MAX_LINE_BYTES).unwrap_or(line);
        let mut g = self.lock()?;
        // 空行でも 1 行ごとに固定費（LINE_OVERHEAD_BYTES）を計上し、行数が無制限に増えないようにする。
        g.total_bytes = g.total_bytes.saturating_add(line_cost(line.len()));
        g.lines.push_back(CapturedLine {
            stream,
            bytes: line.to_vec(),
        });
        while g.total_bytes > self.capacity {
            let Some(old) = g.lines.pop_front() else {
                break;
            };
            g.total_bytes = g.total_bytes.saturating_sub(line_cost(old.bytes.len()));
            g.dropped_lines = g.dropped_lines.saturating_add(1);
        }
        Ok(())
    }
}

/// 1 ストリームの捕捉結果。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StreamSummary {
    lines: u64,
    bytes: u64,
    truncated_lines: u64,
    error_code: Option<ErrorCode>,
}

impl StreamSummary {
    /// 取り出した行数。
    pub fn lines(&self) -> u64 {
        self.lines
    }
    /// ストリームから読んだ総バイト数（LF を含み、切り捨て前）。
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    /// [`MAX_LINE_BYTES`] で切り捨てた行数。
    pub fn truncated_lines(&self) -> u64 {
        self.truncated_lines
    }
    /// 読み取りまたは sink 追記で最初に起きた失敗のコード。
    pub fn error_code(&self) -> Option<ErrorCode> {
        self.error_code
    }
}

/// 捕捉全体の結果（注入されなかったストリームは `None`）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CaptureSummary {
    stdout: Option<StreamSummary>,
    stderr: Option<StreamSummary>,
}

impl CaptureSummary {
    /// stdout の結果。
    pub fn stdout(&self) -> Option<&StreamSummary> {
        self.stdout.as_ref()
    }
    /// stderr の結果。
    pub fn stderr(&self) -> Option<&StreamSummary> {
        self.stderr.as_ref()
    }
}

/// 起動済みのリーダースレッド群への取っ手。
pub struct LogCapture {
    rx: mpsc::Receiver<(StreamKind, StreamSummary)>,
    expected: usize,
}

impl LogCapture {
    /// ストリームごとにリーダースレッドを起動する。
    ///
    /// 全スレッドの起動に成功してから一斉に読み取りを開始させる（起動ゲート）。途中のスレッド起動失敗は `Internal` で、
    /// 既に起動したスレッドはゲートの解放前に終了し、一行も読まず sink へも書かない（部分起動のまま走り続けない）。
    /// この失敗経路ではストリームは破棄される。破棄させたくない場合は [`LogCapture::start_from`] を使う。
    pub fn start(mut streams: OutputStreams, sink: Arc<dyn LogSink>) -> Result<Self, TraitError> {
        Self::start_from(&mut streams, sink)
    }

    /// [`LogCapture::start`] の可変参照版。スレッド起動に失敗した場合、ストリームは `streams` へ戻され
    /// 一行も読まれていないため、呼び出し側が捕捉を再試行できる（成功時は中身が取り出されて空になる）。
    /// [`crate::run::monitor_with_capture`] が開始失敗後の再試行を可能にするために使う。
    pub fn start_from(
        streams: &mut OutputStreams,
        sink: Arc<dyn LogSink>,
    ) -> Result<Self, TraitError> {
        type Slot = Arc<Mutex<Option<Box<dyn Read + Send>>>>;
        let (tx, rx) = mpsc::channel();
        let mut gates: Vec<mpsc::Sender<()>> = Vec::new();
        let mut slots: Vec<(StreamKind, Slot)> = Vec::new();
        for (kind, stream) in [
            (StreamKind::Stdout, streams.stdout.take()),
            (StreamKind::Stderr, streams.stderr.take()),
        ] {
            if let Some(stream) = stream {
                slots.push((kind, Arc::new(Mutex::new(Some(stream)))));
            }
        }
        let mut failed = false;
        for (kind, slot) in &slots {
            let kind = *kind;
            let slot = Arc::clone(slot);
            let tx = tx.clone();
            let sink = Arc::clone(&sink);
            let (gate_tx, gate_rx) = mpsc::channel::<()>();
            // 失敗時は gates が drop され、起動済みスレッドの recv が Err になって終了する（stream は slot に残る）。
            let spawned = std::thread::Builder::new()
                .name(format!("supervisor-log-{}", kind.as_str()))
                .spawn(move || {
                    // ゲートが解放されずに閉じた（部分起動の中止）なら、stream に触れず終わる。
                    if gate_rx.recv().is_err() {
                        return;
                    }
                    let stream = slot.lock().ok().and_then(|mut g| g.take());
                    let Some(stream) = stream else { return };
                    let summary = pump(stream, kind, sink.as_ref());
                    // 受信側が drain を諦めて破棄済みなら送信失敗は無視してよい。
                    let _ = tx.send((kind, summary));
                });
            if spawned.is_err() {
                failed = true;
                break;
            }
            gates.push(gate_tx);
        }
        if failed {
            drop(gates);
            for (kind, slot) in slots {
                let stream = slot.lock().ok().and_then(|mut g| g.take());
                match kind {
                    StreamKind::Stdout => streams.stdout = stream,
                    StreamKind::Stderr => streams.stderr = stream,
                }
            }
            return Err(TraitError::new(
                ErrorCode::Internal,
                "failed to spawn log reader thread",
            ));
        }
        let expected = gates.len();
        for gate in gates {
            // スレッドは gate_rx を保持して待機中のため送信は失敗しない。失敗しても当該スレッドが既に終了しているだけ。
            let _ = gate.send(());
        }
        Ok(Self { rx, expected })
    }

    /// 全ストリームが EOF になるまで `timeout` を上限に待つ。期限切れは `Timeout`
    /// （リーダースレッドは切り離されて走り続ける。module doc 参照）。
    pub fn drain(self, timeout: Duration) -> Result<CaptureSummary, TraitError> {
        // Duration::MAX 等で加算が溢れても panic しない（公開 API のため直接呼ばれうる）。
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "drain timeout is too large",
            ));
        };
        let mut out = CaptureSummary::default();
        for _ in 0..self.expected {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(remaining) {
                Ok((StreamKind::Stdout, s)) => out.stdout = Some(s),
                Ok((_, s)) => out.stderr = Some(s),
                Err(RecvTimeoutError::Timeout) => {
                    return Err(TraitError::new(
                        ErrorCode::Timeout,
                        "timed out waiting for log streams to reach EOF",
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(TraitError::new(
                        ErrorCode::Internal,
                        "log reader thread terminated unexpectedly",
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// 行バッファ（上限付き）と集計を持ち、読んだチャンクを行へ分割して sink へ渡す。
struct LineSplitter<'a> {
    kind: StreamKind,
    sink: &'a dyn LogSink,
    buf: Vec<u8>,
    cut: bool,
    summary: StreamSummary,
}

impl LineSplitter<'_> {
    fn feed(&mut self, chunk: &[u8]) {
        let mut segs = chunk.split(|b| *b == b'\n').peekable();
        while let Some(seg) = segs.next() {
            let room = MAX_LINE_BYTES.saturating_sub(self.buf.len());
            let take = room.min(seg.len());
            if let Some(head) = seg.get(..take) {
                self.buf.extend_from_slice(head);
            }
            if take < seg.len() {
                self.cut = true;
            }
            if segs.peek().is_some() {
                self.emit();
            }
        }
    }

    fn emit(&mut self) {
        if let Err(e) = self.sink.append(self.kind, &self.buf) {
            // 読み取りは続ける（パイプを詰まらせない）。最初のコードだけ残す。
            self.summary.error_code.get_or_insert(e.code());
        }
        self.summary.lines = self.summary.lines.saturating_add(1);
        if self.cut {
            self.summary.truncated_lines = self.summary.truncated_lines.saturating_add(1);
        }
        self.buf.clear();
        self.cut = false;
    }
}

/// 1 ストリームを EOF まで読み、行単位で sink へ渡す。
fn pump(mut stream: Box<dyn Read + Send>, kind: StreamKind, sink: &dyn LogSink) -> StreamSummary {
    let mut sp = LineSplitter {
        kind,
        sink,
        buf: Vec::new(),
        cut: false,
        summary: StreamSummary::default(),
    };
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                sp.summary.bytes = sp.summary.bytes.saturating_add(n as u64);
                if let Some(data) = chunk.get(..n) {
                    sp.feed(data);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                sp.summary.error_code.get_or_insert(ErrorCode::Internal);
                break;
            }
        }
    }
    if !sp.buf.is_empty() {
        sp.emit();
    }
    sp.summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn boxed(data: &[u8]) -> Option<Box<dyn Read + Send>> {
        Some(Box::new(Cursor::new(data.to_vec())))
    }

    fn run(
        stdout: Option<Box<dyn Read + Send>>,
        stderr: Option<Box<dyn Read + Send>>,
    ) -> (Arc<MemoryLogSink>, CaptureSummary) {
        let sink = Arc::new(MemoryLogSink::default());
        let cap = LogCapture::start(OutputStreams::new(stdout, stderr), sink.clone()).unwrap();
        let sum = cap.drain(Duration::from_secs(10)).unwrap();
        (sink, sum)
    }

    fn line(stream: StreamKind, s: &[u8]) -> CapturedLine {
        CapturedLine {
            stream,
            bytes: s.to_vec(),
        }
    }

    /// REPAIR-5・TASK-157.7: 溢れる timeout は panic せず InvalidArgument を返す。
    #[test]
    fn sup1_task157_7_drain_rejects_overflowing_timeout() {
        let cap = LogCapture::start(
            OutputStreams::new(None, None),
            Arc::new(MemoryLogSink::default()),
        )
        .unwrap();
        let err = cap.drain(Duration::MAX).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// TASK-157.7: 直接 append された巨大行も MAX_LINE_BYTES へ切り詰める。
    #[test]
    fn sup1_task157_7_memory_sink_truncates_oversized_direct_append() {
        let sink = MemoryLogSink::default();
        let big = vec![b'a'; MAX_LINE_BYTES + 100];
        sink.append(StreamKind::Stdout, &big).unwrap();
        assert_eq!(sink.snapshot().unwrap()[0].bytes.len(), MAX_LINE_BYTES);
    }

    /// SUP-1・TASK-157.7: stdout / stderr の両方を種別付きで捕捉する。
    #[test]
    fn sup1_task157_7_captures_stdout_and_stderr() {
        let (sink, sum) = run(boxed(b"out1\nout2\n"), boxed(b"err1\n"));
        let mut got = sink.snapshot().unwrap();
        got.sort_by_key(|l| l.stream.as_str());
        assert_eq!(
            got,
            vec![
                line(StreamKind::Stderr, b"err1"),
                line(StreamKind::Stdout, b"out1"),
                line(StreamKind::Stdout, b"out2"),
            ]
        );
        assert_eq!(sum.stdout().unwrap().lines(), 2);
        assert_eq!(sum.stdout().unwrap().bytes(), 10);
        assert_eq!(sum.stderr().unwrap().lines(), 1);
        assert_eq!(sum.stderr().unwrap().error_code(), None);
    }

    /// TASK-157.7: LF のない末尾行も 1 行として渡る。
    #[test]
    fn sup1_task157_7_partial_line_at_eof() {
        let (sink, _) = run(boxed(b"a\nb"), None);
        assert_eq!(
            sink.snapshot().unwrap(),
            vec![
                line(StreamKind::Stdout, b"a"),
                line(StreamKind::Stdout, b"b")
            ]
        );
    }

    /// TASK-157.7: CR は除去しない。
    #[test]
    fn sup1_task157_7_crlf_is_preserved() {
        let (sink, _) = run(boxed(b"x\r\n"), None);
        assert_eq!(
            sink.snapshot().unwrap(),
            vec![line(StreamKind::Stdout, b"x\r")]
        );
    }

    /// TASK-157.7: 非 UTF-8 バイトも不透明に保持する。
    #[test]
    fn sup1_task157_7_non_utf8_bytes_are_preserved() {
        let (sink, _) = run(None, boxed(&[0xff, 0xfe, b'\n']));
        assert_eq!(
            sink.snapshot().unwrap(),
            vec![line(StreamKind::Stderr, &[0xff, 0xfe])]
        );
    }

    /// TASK-157.7: 空行は空の行として渡る。
    #[test]
    fn sup1_task157_7_empty_lines_are_kept() {
        let (sink, sum) = run(boxed(b"\n\nz\n"), None);
        assert_eq!(sink.snapshot().unwrap().len(), 3);
        assert_eq!(sum.stdout().unwrap().lines(), 3);
    }

    /// TASK-157.7: 上限超過の行は切り捨てて件数を数える（チャンク境界をまたぐ長さ）。
    #[test]
    fn sup1_task157_7_oversized_line_is_truncated() {
        let mut data = vec![b'a'; MAX_LINE_BYTES + 20_000];
        data.push(b'\n');
        data.extend_from_slice(b"ok\n");
        let (sink, sum) = run(boxed(&data), None);
        let got = sink.snapshot().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].bytes.len(), MAX_LINE_BYTES);
        assert_eq!(got[1].bytes, b"ok".to_vec());
        assert_eq!(sum.stdout().unwrap().truncated_lines(), 1);
    }

    struct FailSink;
    impl LogSink for FailSink {
        fn append(&self, _: StreamKind, _: &[u8]) -> Result<(), TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "fake sink failure"))
        }
    }

    /// TASK-157.7: sink が失敗しても EOF まで読み切り、最初のエラーコードを返す。
    #[test]
    fn sup1_task157_7_sink_error_is_reported_and_reading_continues() {
        let cap = LogCapture::start(
            OutputStreams::new(boxed(b"a\nb\nc\n"), None),
            Arc::new(FailSink),
        )
        .unwrap();
        let sum = cap.drain(Duration::from_secs(10)).unwrap();
        let s = sum.stdout().unwrap();
        assert_eq!(s.error_code(), Some(ErrorCode::Internal));
        assert_eq!(s.bytes(), 6);
        assert_eq!(s.lines(), 3);
    }

    /// REPAIR-5・TASK-157.7: 閉じないストリームでは drain が Timeout になる。
    #[test]
    fn sup1_task157_7_drain_times_out_when_stream_stays_open() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        let sink = Arc::new(MemoryLogSink::default());
        let cap =
            LogCapture::start(OutputStreams::new(Some(Box::new(reader)), None), sink).unwrap();
        writer.write_all(b"hello\n").unwrap();
        let err = cap.drain(Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        drop(writer);
    }

    /// TASK-157.7: メモリ sink は上限で古い行から捨てる。
    #[test]
    fn sup1_task157_7_memory_sink_is_bounded() {
        let sink = MemoryLogSink::new(line_cost(MAX_LINE_BYTES)).unwrap();
        for _ in 0..3 {
            sink.append(StreamKind::Stdout, &[b'x'; 30_000]).unwrap();
        }
        assert_eq!(sink.snapshot().unwrap().len(), 2);
        assert_eq!(sink.dropped_lines().unwrap(), 1);
        assert_eq!(
            MemoryLogSink::new(line_cost(MAX_LINE_BYTES) - 1)
                .err()
                .map(|e| e.code()),
            Some(ErrorCode::InvalidArgument)
        );
    }

    /// TASK-157.7: 空行の連続でも保持行数が上限に収まる（容量 65600 バイト・1 行 64 バイト計上で 1025 行）。
    #[test]
    fn sup1_task157_7_memory_sink_bounds_empty_lines() {
        let sink = MemoryLogSink::new(line_cost(MAX_LINE_BYTES)).unwrap();
        for _ in 0..5000 {
            sink.append(StreamKind::Stdout, b"").unwrap();
        }
        assert_eq!(sink.snapshot().unwrap().len(), 1025);
        assert_eq!(sink.dropped_lines().unwrap(), 5000 - 1025);
    }

    /// TASK-157.7: ストリーム未注入なら空の結果。
    #[test]
    fn sup1_task157_7_no_streams_yields_empty_summary() {
        let (sink, sum) = run(None, None);
        assert_eq!(sum, CaptureSummary::default());
        assert!(sink.snapshot().unwrap().is_empty());
    }
}
