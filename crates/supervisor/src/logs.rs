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
//!   ブロック中の `Read` を外から中断する汎用手段がないため、リーダースレッドは切り離される。
//!   `drain` は `Err` を返す全経路（期限切れ・溢れる timeout・リーダーの異常終了）で、返る前に捕捉を取り消す。
//!   取消しは sink への追記と排他で、`drain` が `Err` を返した後は sink へ 1 行も追記されない。
//!   リーダーは現在の `read` が戻った時点でスレッドとストリームを解放して終了する。
//! - `read` が戻らない間に残るスレッド数は [`ReaderBudget`]（上限 [`MAX_LIVE_READERS`] 以下）で制限し、超える開始は
//!   `Unavailable` で拒否する（孫プロセスがパイプを保持する場合の無制限なスレッド・ストリーム蓄積の防止。REPAIR-5）。
//!   予算は省略できない: [`OutputStreams`] は [`ReaderBudget`] を渡さないと作れず、既定の予算を暗黙に作る経路は無い。
//!   呼び出し側（supervisor プロセス）は予算を 1 つだけ作り、再起動・再捕捉をまたいで同じものを渡す
//!   （捕捉ごとに作り直すと残存リーダーが数えられない）。
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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{ErrorCode, TraitError};

/// 1 行の上限バイト数（超過ぶんは切り捨てる）。
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// 1 回の読み取りに使う固定バッファのバイト数。
pub const READ_CHUNK_BYTES: usize = 8 * 1024;

/// 生存中のリーダースレッド数の上限の最大値（drain 期限切れ後に `read` でブロックし続けるスレッドの蓄積防止）。
/// [`ReaderBudget`] の上限はこの値を超えられない。
pub const MAX_LIVE_READERS: usize = 64;

/// 生存中のリーダースレッド数の予算（REPAIR-5）。
///
/// [`OutputStreams`] を作るのに必須で、同じ予算から作ったストリームは捕捉をまたいで同じカウンタを共有する
/// （複製も同じカウンタを指す）。drain の期限切れで残ったリーダーは、終了するまで枠を占有し続ける。
/// supervisor プロセスにつき 1 つだけ作り、監視対象の再起動・再捕捉のたびに同じものを渡すこと。
/// 捕捉ごとに作り直すと残存リーダーを数えられず、上限が効かない。
/// モジュール内にグローバル状態を持たないため（CORE-1・D-19）、所有は呼び出し側にある。
#[derive(Debug, Clone)]
pub struct ReaderBudget {
    live: Arc<AtomicUsize>,
    limit: usize,
}

impl ReaderBudget {
    /// 上限 `limit` 本の予算を作る。0 または [`MAX_LIVE_READERS`] 超なら `InvalidArgument`
    /// （上限の無い予算を作れないようにする）。
    pub fn new(limit: usize) -> Result<Self, TraitError> {
        if limit == 0 || limit > MAX_LIVE_READERS {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "live reader limit is out of range",
            ));
        }
        Ok(Self {
            live: Arc::new(AtomicUsize::new(0)),
            limit,
        })
    }

    /// 上限 [`MAX_LIVE_READERS`] 本の予算を作る。
    pub fn with_max_limit() -> Self {
        Self {
            live: Arc::new(AtomicUsize::new(0)),
            limit: MAX_LIVE_READERS,
        }
    }

    /// 上限（本数）。
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// 現在生存中のリーダー数。
    pub fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    /// `n` 本ぶんの枠を確保する。上限を超えるなら何も確保せず `None`。
    fn reserve(&self, n: usize) -> Option<Vec<ReaderSlot>> {
        let mut cur = self.live.load(Ordering::SeqCst);
        loop {
            let next = cur.checked_add(n).filter(|v| *v <= self.limit)?;
            match self
                .live
                .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
        Some((0..n).map(|_| ReaderSlot(Arc::clone(&self.live))).collect())
    }
}

/// リーダースレッド 1 本ぶんの枠。drop でカウンタを戻す。
struct ReaderSlot(Arc<AtomicUsize>);

impl Drop for ReaderSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

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
///
/// 生存リーダー数の予算（[`ReaderBudget`]）と必ず組で作る。予算なしで作る経路（`Default` 等）は意図的に提供しない
/// （既定の予算を暗黙に作ると、捕捉を繰り返すたびに上限が振り出しに戻るため。REPAIR-5）。
pub struct OutputStreams {
    stdout: Option<Box<dyn Read + Send>>,
    stderr: Option<Box<dyn Read + Send>>,
    budget: ReaderBudget,
}

impl OutputStreams {
    /// stdout / stderr を、生存リーダー数を数える `budget` と組にして渡す。
    /// `budget` は複製して保持する（カウンタは共有される）。
    pub fn new(
        budget: &ReaderBudget,
        stdout: Option<Box<dyn Read + Send>>,
        stderr: Option<Box<dyn Read + Send>>,
    ) -> Self {
        Self {
            stdout,
            stderr,
            budget: budget.clone(),
        }
    }

    /// 捕捉対象のストリームを 1 つも持たないか。
    pub fn is_empty(&self) -> bool {
        self.stdout.is_none() && self.stderr.is_none()
    }

    /// どちらも捕捉しない（リーダーを起動しないため枠は使わない）。
    pub fn none(budget: &ReaderBudget) -> Self {
        Self::new(budget, None, None)
    }
}

/// 捕捉した行の記録先。TASK-164（SUP-7）がファイル・ローテーション実装へ差し替える拡張点。
pub trait LogSink: Send + Sync {
    /// 1 行（LF 抜き・[`MAX_LINE_BYTES`] 以下）を追記する。失敗は構造化エラーで返す（panic しない）。
    ///
    /// 有限時間で戻ること。[`LogCapture::drain`] の取消しは実行中の `append` の完了を待つため
    /// （取消し後に追記が起きないことを保証するための排他）、戻らない `append` は `drain` を期限より長く止める。
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

/// 捕捉の取消し状態。リーダーは sink への追記のあいだ共有ロックを保持し、取消しは要求フラグを立ててから
/// 排他ロックを取る。これにより「取消しが返った後は追記が 1 件も起きない」ことを保証する
/// （確認と追記の間に取消しが返らない）。要求フラグを先に立てるので、取消しの要求後に新しい追記は始まらず、
/// 取消しが待つのは実行中の追記（ストリームあたり高々 1 件）だけである（ロックの公平性に依存しない）。
#[derive(Default)]
struct CancelGate {
    requested: AtomicBool,
    appending: RwLock<()>,
}

impl CancelGate {
    /// 取消し済みにする。実行中の追記があれば、その完了を待ってから返る。
    fn cancel(&self) {
        self.requested.store(true, Ordering::SeqCst);
        // 共有ロックを保持中（追記中）のリーダーが抜けるのを待つ。値は持たないので毒化は無視してよい。
        drop(
            self.appending
                .write()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// 取消しが要求済みか。
    fn is_cancelled(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    /// 取消し前なら `f` を実行して `Some`、取消し済みなら実行せず `None`。`f` の間は取消しを待たせる。
    fn run_unless_cancelled<T>(&self, f: impl FnOnce() -> T) -> Option<T> {
        let _appending = self
            .appending
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        // 共有ロックの保持中に確認する（未要求なら、cancel はこのロックの解放まで返れない）。
        if self.is_cancelled() {
            return None;
        }
        Some(f())
    }
}

/// 起動済みのリーダースレッド群への取っ手。
///
/// [`LogCapture::drain`] を呼ばずに破棄した場合、捕捉は取り消されない（リーダーは EOF まで sink へ追記を続ける。
/// [`crate::run::monitor_with_capture`] の停止要求時の契約）。捕捉を止めるには `drain` を呼ぶ。
pub struct LogCapture {
    rx: mpsc::Receiver<(StreamKind, StreamSummary)>,
    expected: usize,
    cancel: Arc<CancelGate>,
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
        Self::start_bounded(streams, sink)
    }

    /// 本体。`streams` が持つ [`ReaderBudget`] で生存リーダー数を制限する。
    fn start_bounded(
        streams: &mut OutputStreams,
        sink: Arc<dyn LogSink>,
    ) -> Result<Self, TraitError> {
        type Slot = Arc<Mutex<Option<Box<dyn Read + Send>>>>;
        // ストリームを取り出す前に枠を確保する。上限超過ならストリームは呼び出し側に残る。
        let wanted = usize::from(streams.stdout.is_some()) + usize::from(streams.stderr.is_some());
        let Some(mut reader_slots) = streams.budget.reserve(wanted) else {
            return Err(TraitError::new(
                ErrorCode::Unavailable,
                "too many log reader threads are still alive",
            ));
        };
        let cancel = Arc::new(CancelGate::default());
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
            let cancel = Arc::clone(&cancel);
            let reader_slot = reader_slots.pop();
            let (gate_tx, gate_rx) = mpsc::channel::<()>();
            // 失敗時は gates が drop され、起動済みスレッドの recv が Err になって終了する（stream は slot に残る）。
            let spawned = std::thread::Builder::new()
                .name(format!("supervisor-log-{}", kind.as_str()))
                .spawn(move || {
                    // スレッド終了時（正常・中止とも）に枠を返す。
                    let _reader_slot = reader_slot;
                    // ゲートが解放されずに閉じた（部分起動の中止）なら、stream に触れず終わる。
                    if gate_rx.recv().is_err() {
                        return;
                    }
                    let stream = slot.lock().ok().and_then(|mut g| g.take());
                    let Some(stream) = stream else { return };
                    let summary = pump(stream, kind, sink.as_ref(), &cancel);
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
        Ok(Self {
            rx,
            expected,
            cancel,
        })
    }

    /// 全ストリームが EOF になるまで `timeout` を上限に待つ。期限切れは `Timeout`、
    /// 期限を表現できない `timeout`（`Duration::MAX` 等）は `InvalidArgument`。
    ///
    /// `Err` を返す全経路で、返る前に捕捉を取り消す（`self` を消費するため、呼び出し側は後から止められない）。
    /// `Err` が返った後は sink へ 1 行も追記されず、リーダーは次に `read` が戻った時点で終了する（module doc 参照）。
    pub fn drain(self, timeout: Duration) -> Result<CaptureSummary, TraitError> {
        let result = self.wait_all(timeout);
        if result.is_err() {
            self.cancel.cancel();
        }
        result
    }

    /// [`LogCapture::drain`] の待機本体（取消しは呼び出し元が行う）。
    fn wait_all(&self, timeout: Duration) -> Result<CaptureSummary, TraitError> {
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
    cancel: &'a CancelGate,
    /// 取消しを検知した（以後は sink へ渡さない）。
    cancelled: bool,
    buf: Vec<u8>,
    cut: bool,
    summary: StreamSummary,
}

impl LineSplitter<'_> {
    fn feed(&mut self, chunk: &[u8]) {
        let mut segs = chunk.split(|b| *b == b'\n').peekable();
        while let Some(seg) = segs.next() {
            if self.cancelled {
                return;
            }
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
        // 取消しの確認と追記を排他にする（確認後・追記前に取消しが返ることを防ぐ）。
        let Some(appended) = self
            .cancel
            .run_unless_cancelled(|| self.sink.append(self.kind, &self.buf))
        else {
            self.cancelled = true;
            self.buf.clear();
            return;
        };
        if let Err(e) = appended {
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
fn pump(
    mut stream: Box<dyn Read + Send>,
    kind: StreamKind,
    sink: &dyn LogSink,
    cancel: &CancelGate,
) -> StreamSummary {
    let mut sp = LineSplitter {
        kind,
        sink,
        cancel,
        cancelled: false,
        buf: Vec::new(),
        cut: false,
        summary: StreamSummary::default(),
    };
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    loop {
        let r = stream.read(&mut chunk);
        // drain が取り消した後は、読めたデータも sink へ渡さず終了する（スレッド・ストリームの回収）。
        if sp.cancelled || cancel.is_cancelled() {
            return sp.summary;
        }
        match r {
            Ok(0) => break,
            Ok(n) => {
                sp.summary.bytes = sp.summary.bytes.saturating_add(n as u64);
                if let Some(data) = chunk.get(..n) {
                    sp.feed(data);
                }
                // 追記の直前に取消しを検知した場合は、次の read（ブロックし得る）へ進まず終了する。
                if sp.cancelled {
                    return sp.summary;
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                sp.summary.error_code.get_or_insert(ErrorCode::Internal);
                break;
            }
        }
    }
    if !sp.buf.is_empty() && !sp.cancelled {
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
        let budget = ReaderBudget::with_max_limit();
        let cap =
            LogCapture::start(OutputStreams::new(&budget, stdout, stderr), sink.clone()).unwrap();
        let sum = cap.drain(Duration::from_secs(10)).unwrap();
        // EOF まで読み切ったリーダーは枠を返す（送信後のスレッド終了を待つ）。
        assert_eq!(wait_live(&budget, 0), 0);
        (sink, sum)
    }

    /// `budget.live()` が `want` になるのを最大 10 秒待ち、最後に観測した値を返す。
    fn wait_live(budget: &ReaderBudget, want: usize) -> usize {
        let start = Instant::now();
        while budget.live() != want && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(5));
        }
        budget.live()
    }

    /// 開いたままのパイプを 1 本捕捉し、`drain` を期限切れ（50ms）にして残存リーダーを 1 本作る。
    /// 戻り値の writer を保持している間、リーダーは `read` でブロックし続ける。
    fn leave_stuck_reader(budget: &ReaderBudget, sink: Arc<MemoryLogSink>) -> std::io::PipeWriter {
        let (reader, writer) = std::io::pipe().unwrap();
        let cap = LogCapture::start(
            OutputStreams::new(budget, Some(Box::new(reader)), None),
            sink,
        )
        .unwrap();
        let err = cap.drain(Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        writer
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
            OutputStreams::none(&ReaderBudget::with_max_limit()),
            Arc::new(MemoryLogSink::default()),
        )
        .unwrap();
        let err = cap.drain(Duration::MAX).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "drain timeout is too large");
    }

    /// REPAIR-5・TASK-157.7: 溢れる timeout で返る前にも捕捉を取り消す。以後に届いた出力は sink へ追記されず、
    /// リーダーは終了して枠を返す。
    #[test]
    fn sup1_task157_7_drain_overflowing_timeout_cancels_capture() {
        let budget = ReaderBudget::new(1).unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let sink = Arc::new(MemoryLogSink::default());
        let cap = LogCapture::start(
            OutputStreams::new(&budget, Some(Box::new(reader)), None),
            sink.clone(),
        )
        .unwrap();
        assert_eq!(budget.live(), 1);
        let err = cap.drain(Duration::MAX).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        writer.write_all(b"late1\nlate2\n").unwrap();
        assert_eq!(wait_live(&budget, 0), 0);
        assert_eq!(sink.snapshot().unwrap(), Vec::<CapturedLine>::new());
        drop(writer);
    }

    /// REPAIR-5・TASK-157.7: 期限切れより前に届いた行は残り、期限切れ（Timeout）より後に届いた行は 1 行も追記されない。
    #[test]
    fn sup1_task157_7_no_append_after_drain_timeout() {
        let budget = ReaderBudget::new(1).unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let sink = Arc::new(MemoryLogSink::default());
        let cap = LogCapture::start(
            OutputStreams::new(&budget, Some(Box::new(reader)), None),
            sink.clone(),
        )
        .unwrap();
        writer.write_all(b"before\n").unwrap();
        let start = Instant::now();
        while sink.snapshot().unwrap().is_empty() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let err = cap.drain(Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "timed out waiting for log streams to reach EOF"
        );
        writer.write_all(b"after1\nafter2\n").unwrap();
        assert_eq!(wait_live(&budget, 0), 0);
        assert_eq!(
            sink.snapshot().unwrap(),
            vec![line(StreamKind::Stdout, b"before")]
        );
        drop(writer);
    }

    /// REPAIR-5・TASK-157.7: 取消しは実行中の追記の完了を待ち、取消しが返った後は追記が始まらない
    /// （確認と追記の間に取消しが割り込まない）。
    #[test]
    fn sup1_task157_7_cancel_gate_excludes_append() {
        let gate = CancelGate::default();
        assert_eq!(gate.run_unless_cancelled(|| 7), Some(7));
        assert!(!gate.is_cancelled());
        gate.cancel();
        assert!(gate.is_cancelled());
        assert_eq!(gate.run_unless_cancelled(|| 7), None);
    }

    /// 追記に 300ms かかる sink。追記に入ったことを `entered` で知らせ、完了した行だけを `done` に残す。
    struct SlowSink {
        entered: AtomicBool,
        done: Mutex<Vec<Vec<u8>>>,
    }
    impl LogSink for SlowSink {
        fn append(&self, _: StreamKind, line: &[u8]) -> Result<(), TraitError> {
            self.entered.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(300));
            self.done.lock().unwrap().push(line.to_vec());
            Ok(())
        }
    }

    /// REPAIR-5・TASK-157.7: 追記の実行中に drain が期限切れになった場合、drain は実行中の 1 行（"a"）の完了を待ってから
    /// 返り、同じチャンクで読めていた次の行（"b"）は追記されない。返った時点の内容は以後も変わらない。
    #[test]
    fn sup1_task157_7_drain_error_waits_for_in_flight_append_and_stops_the_rest() {
        let budget = ReaderBudget::new(1).unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let sink = Arc::new(SlowSink {
            entered: AtomicBool::new(false),
            done: Mutex::new(Vec::new()),
        });
        let cap = LogCapture::start(
            OutputStreams::new(&budget, Some(Box::new(reader)), None),
            sink.clone(),
        )
        .unwrap();
        writer.write_all(b"a\nb\n").unwrap();
        let start = Instant::now();
        while !sink.entered.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(1));
        }
        let err = cap.drain(Duration::from_millis(1)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(*sink.done.lock().unwrap(), vec![b"a".to_vec()]);
        // 同じチャンクの残りを処理せずに終了するため、パイプを閉じなくても枠が戻る。
        assert_eq!(wait_live(&budget, 0), 0);
        assert_eq!(*sink.done.lock().unwrap(), vec![b"a".to_vec()]);
        drop(writer);
    }

    /// REPAIR-5・TASK-157.7: 予算の上限は 1 以上 MAX_LIVE_READERS（64）以下に限る（上限なしの予算を作れない）。
    #[test]
    fn sup1_task157_7_reader_budget_limit_is_validated() {
        assert_eq!(MAX_LIVE_READERS, 64);
        for bad in [0, MAX_LIVE_READERS + 1, usize::MAX] {
            let err = ReaderBudget::new(bad).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert_eq!(err.message(), "live reader limit is out of range");
        }
        assert_eq!(ReaderBudget::new(1).unwrap().limit(), 1);
        assert_eq!(ReaderBudget::new(MAX_LIVE_READERS).unwrap().limit(), 64);
        assert_eq!(ReaderBudget::with_max_limit().limit(), 64);
        assert_eq!(ReaderBudget::with_max_limit().live(), 0);
    }

    /// REPAIR-5・TASK-157.7: drain の期限切れで残ったリーダーは、同じ予算から作った別の OutputStreams の開始でも数えられる。
    /// 上限 2・残存 2 本で 3 本目の開始は Unavailable（message 固定）で拒否され、ストリームは未読のまま残る。
    /// 残存リーダーが終了して枠が戻れば、同じストリームで開始できる。
    #[test]
    fn sup1_task157_7_stuck_readers_count_against_later_captures() {
        let budget = ReaderBudget::new(2).unwrap();
        let sink = Arc::new(MemoryLogSink::default());
        let w1 = leave_stuck_reader(&budget, sink.clone());
        let w2 = leave_stuck_reader(&budget, sink.clone());
        assert_eq!(budget.live(), 2);

        let mut streams = OutputStreams::new(&budget, boxed(b"x\n"), None);
        let err = LogCapture::start_from(&mut streams, sink.clone())
            .err()
            .unwrap();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert_eq!(err.message(), "too many log reader threads are still alive");
        assert!(!streams.is_empty());
        assert_eq!(budget.live(), 2);
        assert_eq!(sink.snapshot().unwrap(), Vec::<CapturedLine>::new());

        // 1 本ぶんの枠が戻れば開始でき、拒否されたストリームは 1 バイトも失われていない。
        drop(w1);
        assert_eq!(wait_live(&budget, 1), 1);
        let cap = LogCapture::start_from(&mut streams, sink.clone()).unwrap();
        let sum = cap.drain(Duration::from_secs(10)).unwrap();
        assert_eq!(sum.stdout().unwrap().lines(), 1);
        assert_eq!(sum.stdout().unwrap().bytes(), 2);
        assert_eq!(
            sink.snapshot().unwrap(),
            vec![line(StreamKind::Stdout, b"x")]
        );
        drop(w2);
        assert_eq!(wait_live(&budget, 0), 0);
    }

    /// REPAIR-5・TASK-157.7: 予算の複製は同じカウンタを共有し、別に作った予算は共有しない。
    #[test]
    fn sup1_task157_7_cloned_budget_shares_counter() {
        let budget = ReaderBudget::new(1).unwrap();
        let cloned = budget.clone();
        let sink = Arc::new(MemoryLogSink::default());
        let w = leave_stuck_reader(&budget, sink.clone());
        assert_eq!(cloned.live(), 1);
        let mut streams = OutputStreams::new(&cloned, boxed(b"x\n"), None);
        assert_eq!(
            LogCapture::start_from(&mut streams, sink)
                .err()
                .map(|e| e.code()),
            Some(ErrorCode::Unavailable)
        );
        drop(w);
        assert_eq!(wait_live(&budget, 0), 0);
        assert_eq!(cloned.live(), 0);
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
            OutputStreams::new(&ReaderBudget::with_max_limit(), boxed(b"a\nb\nc\n"), None),
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
        let cap = LogCapture::start(
            OutputStreams::new(
                &ReaderBudget::with_max_limit(),
                Some(Box::new(reader)),
                None,
            ),
            sink,
        )
        .unwrap();
        writer.write_all(b"hello\n").unwrap();
        let err = cap.drain(Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        drop(writer);
    }

    /// REPAIR-5・TASK-157.7: drain 期限切れ後、ブロック中の read が戻ればリーダーは sink へ書かず終了し枠を返す。
    #[test]
    fn sup1_task157_7_cancelled_reader_exits_without_appending() {
        let budget = ReaderBudget::new(4).unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let sink = Arc::new(MemoryLogSink::default());
        let mut streams = OutputStreams::new(&budget, Some(Box::new(reader)), None);
        let cap = LogCapture::start_from(&mut streams, sink.clone()).unwrap();
        assert_eq!(budget.live(), 1);
        let err = cap.drain(Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        writer.write_all(b"late\n").unwrap();
        assert_eq!(wait_live(&budget, 0), 0);
        assert!(sink.snapshot().unwrap().is_empty());
        drop(writer);
    }

    /// REPAIR-5・TASK-157.7: 生存リーダー数が上限なら開始を Unavailable で拒否し、ストリームは呼び出し側に残る。
    #[test]
    fn sup1_task157_7_start_rejects_beyond_live_reader_limit() {
        let sink = Arc::new(MemoryLogSink::default());
        let budget = ReaderBudget::new(1).unwrap();
        let mut streams = OutputStreams::new(&budget, boxed(b"a\n"), boxed(b"b\n"));
        let e = LogCapture::start_from(&mut streams, sink.clone())
            .err()
            .unwrap();
        assert_eq!(e.code(), ErrorCode::Unavailable);
        assert_eq!(e.message(), "too many log reader threads are still alive");
        assert!(!streams.is_empty());
        // 拒否は枠を 1 本も消費しない（部分確保しない）。
        assert_eq!(budget.live(), 0);
        streams.budget = ReaderBudget::new(2).unwrap();
        let cap = LogCapture::start_from(&mut streams, sink).unwrap();
        assert!(cap.drain(Duration::from_secs(10)).is_ok());
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
