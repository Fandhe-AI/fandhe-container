//! 監視対象プロセスの stdout / stderr を行単位で捕捉する土台（TASK-157.7・#241・SUP-1。関連: CORE-1・D-19・REPAIR-3・REPAIR-5）。
//!
//! [`crate::run::monitor_with_capture`] が、呼び出し側から注入された出力ストリーム（[`OutputStreams`]）を
//! ストリームごとのリーダースレッドで読み、LF 区切りの 1 行ずつを [`LogSink`] へ渡す。
//! 子の出力は非信頼データとして不透明なバイト列のまま扱い、解釈・パス / コマンドへの連結・
//! supervisor 自身のログやエラーメッセージへの混入をしない。
//!
//! # 契約
//! - 行は LF を除いたバイト列で渡す（UTF-8 を仮定しない。CR は除去しない）。EOF 時の LF なし末尾行も 1 行として渡す。
//!   読み取りがエラーで終わった場合、LF にも EOF にも達していない未完了の末尾は sink へ渡さず破棄する
//!   （途中で欠けた内容を正常な行として残さない）。破棄は [`StreamSummary::discarded_lines`] に数える。
//! - 行の内容は `read` の戻りサイズ・チャンク境界の位置に依らず同一（行の分断・結合・欠落なし）。
//!   行単位捕捉は TASK-164.1（#505・SUP-7）で境界跨ぎを機械照合済み。
//! - 1 行は [`MAX_LINE_BYTES`] で切り捨てる（超過ぶんは捨て、[`StreamSummary::truncated_lines`] へ数える。無制限確保の防止）。
//! - [`LogSink::append`] が失敗したら、そのストリームでは以後 sink を呼ばない（故障した sink へ出力行数ぶんの
//!   失敗処理を繰り返さない）。読み取りは EOF まで続けて破棄する（読みを止めるとパイプが詰まり、コンテナ側の write が
//!   ブロックするため）。失敗コードを [`StreamSummary::error_code`] に、sink へ届かなかった行数（失敗した行を含む）を
//!   [`StreamSummary::discarded_lines`] に残す。
//! - [`LogCapture::drain`] は期限付き（REPAIR-5）。期限切れ（孫プロセスがパイプを保持し続ける場合等）では
//!   ブロック中の `Read` を外から中断する汎用手段がないため、リーダースレッドは切り離される。
//!   `drain` は `Err` を返す全経路（期限切れ・溢れる timeout・リーダーの異常終了）で、返る前に捕捉を取り消す。
//!   取消しの要求後に新しい追記は始まらない。EOF は `timeout` いっぱいまで待ち、期限内に届いた EOF は成功として扱う。
//!   期限切れでは実行中の追記の完了を待たずに返る（`drain` は sink が止まっていても `timeout` 以内に返る）。
//!   したがって `drain` が `Err` を返した後に sink へ届き得るのは、返る時点で実行中だった追記
//!   （ストリームあたり高々 1 件）だけである。完了を待ってから止めたい場合は [`LogCapture::cancel`] を使う
//!   （[`CANCEL_SETTLE_TIMEOUT`] まで待つ）。
//!   リーダーは現在の `read` が戻った時点でスレッドとストリームを解放して終了する。
//! - `read` が戻らない間に残るスレッド数は [`ReaderBudget`]（上限 [`MAX_LIVE_READERS`] 以下）で制限し、超える開始は
//!   `Unavailable` で拒否する（孫プロセスがパイプを保持する場合の無制限なスレッド・ストリーム蓄積の防止。REPAIR-5）。
//!   予算は省略できない: [`OutputStreams`] は [`ReaderBudget`] を渡さないと作れず、既定の予算を暗黙に作る経路は無い。
//!   呼び出し側（supervisor プロセス）は予算を 1 つだけ作り、再起動・再捕捉をまたいで同じものを渡す
//!   （捕捉ごとに作り直すと残存リーダーが数えられない）。
//! - ストリームの所有権は捕捉側へ移る。監視の引き継ぎ時に再注入はできない（引き継ぎは #239・TASK-164 で扱う）。
//!   代わりに取っ手（[`LogCapture`]）が捕捉の継続を表す。[`crate::run::monitor_with_capture`] は終端待ちを
//!   しなかった全経路で取っ手を返すので、呼び出し側は [`LogCapture::cancel`] で止めるか、保持して後で
//!   [`LogCapture::drain`] する（取っ手を破棄すると止める手段が無くなる）。
//! - OS 固有型（fd / HANDLE）は公開せず `Read` のみを受ける（CLI-1）。グローバル状態は持たない（CORE-1・D-19）。
//!
//! # 実装済み（TASK-164.2・#506、TASK-164.3・#507）
//! ファイルへの永続化とローテーション（1MiB × 3 世代等。権限・symlink 検証・ERR-1 形式のエラー込み）は
//! [`rotating::RotatingFileSink`] が担う（SUP-7）。
//!
//! 書き込みバッファとフラッシュ制御（TASK-164.3）: [`LogSink::append`] の `Ok` は「sink が行を受理した」ことを表し、
//! ディスクへの到達は保証しない。リーダーは (a) read のたびに（次の read がブロックしても受理済みの行が滞留しない）
//! と (b) EOF・読み取りエラーでの終了前に [`LogSink::flush`] を呼ぶ（取消し後はリーダーからは呼ばない）。
//! 取消しでは [`LogCapture::cancel`] が実行中の追記の完了後に flush する。まとめ書きは sink 内のバッファが担う。
//! ローテーション境界でのバッファの書き切りと fsync は sink 側の責務
//! （[`rotating::RotatingFileSink`] のモジュール doc 参照）。flush が失敗すると、直前に受理済みの行が記録されて
//! いない可能性があり、その行は [`StreamSummary::lines`] に数えたままで [`StreamSummary::discarded_lines`] には
//! 計上されない（遡って数え直せないため。`error_code` が設定されることで失敗を知らせる）。
//!
//! # 未実装（将来仕様。REPAIR-3）
//! 本モジュールは捕捉経路とファイル sink までで、次は未実装である。
//! - flush ごとの fsync・同期ポリシーの設定化・タイマーによる定期 flush（read ごとの flush で代替している）: SUP-7。
//! - 100 万行規模でローテーション下の欠落 0・重複 0 行を機械照合する検証: SUP-7・TASK-164.4（#508）。
//! - `logs` コマンドからの読み出し経路: TASK-164 以降 / CLI 側。
//! - 実パイプの取得: core の本番 launcher が子の stdio をパイプへ接続して渡す経路は未提供
//!   （現状 core は子の標準入出力を null へ向けている）。そのため入力は注入式である。
//!
//! 既定の [`MemoryLogSink`] はメモリ保持のみ（上限付き）で、supervisor 終了時に失われる。永続化には [`rotating::RotatingFileSink`] を注入する。

pub mod rotating;

pub use rotating::{RotatingFileSink, RotationConfig};

use std::collections::VecDeque;
use std::io::{ErrorKind, Read};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
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

/// 期限を持たない取消し（[`LogCapture::cancel`]・不正な `timeout` での [`LogCapture::drain`]）が、
/// 実行中の sink 追記の完了を待つ猶予の上限。
///
/// 期限切れの [`LogCapture::drain`] はこの猶予を使わない（`timeout` を超えて待たないため、完了を待たずに返る）。
pub const CANCEL_SETTLE_TIMEOUT: Duration = Duration::from_millis(100);

/// [`MemoryLogSink`] の既定の保持上限（総バイト数）。
pub const DEFAULT_MEMORY_SINK_BYTES: usize = 1024 * 1024;

/// [`MemoryLogSink`] の保持上限に指定できる最大値（総バイト数）。非信頼な出力で supervisor のメモリを
/// 使い尽くせないよう、これを超える容量は拒否する（常駐メモリを抑える設計目標とも整合。CORE-8）。
pub const MAX_MEMORY_SINK_BYTES: usize = 64 * 1024 * 1024;

/// [`LogCapture::drain`] の `timeout` に指定できる最大値（REPAIR-5）。
pub const MAX_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

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

/// 捕捉した行の記録先の拡張点。ファイル・ローテーション実装は [`rotating::RotatingFileSink`]（SUP-7・TASK-164.2）。
pub trait LogSink: Send + Sync {
    /// 1 行（LF 抜き・[`MAX_LINE_BYTES`] 以下）を追記する。失敗は構造化エラーで返す（panic しない）。
    /// `Err` を返すと、そのストリームでは以後呼ばれない（残りの行は読み捨てられる）。
    ///
    /// 有限時間で戻ること。戻らない `append` はリーダースレッドとその枠（[`ReaderBudget`]）を占有し続け、
    /// パイプが詰まってコンテナ側の write を止める。[`LogCapture::drain`] は `append` の完了を期限を超えて待たない。
    fn append(&self, stream: StreamKind, line: &[u8]) -> Result<(), TraitError>;

    /// `append` が `Ok` を返した行を記録先へ書き出す（TASK-164.3・SUP-7）。既定は何もしない（バッファを持たない sink 用）。
    ///
    /// リーダーが read のたびと終了前に呼ぶ（[`LogCapture::cancel`] も取消し後に 1 回呼ぶ）。有限時間で戻ること。`Err` を返すと `append` と同様、
    /// そのストリームでは以後 sink を呼ばない。
    fn flush(&self) -> Result<(), TraitError> {
        Ok(())
    }
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
/// （永続化には [`rotating::RotatingFileSink`] を使う。SUP-7・TASK-164）。上限超過時は古い行から捨て、件数を数える。
pub struct MemoryLogSink {
    capacity: usize,
    inner: Mutex<MemoryInner>,
}

impl MemoryLogSink {
    /// `capacity_bytes` が最大 1 行ぶん（[`MAX_LINE_BYTES`] + 行ごとの固定費）未満なら `InvalidArgument`（1 行が保持できなくなるため）。
    /// [`MAX_MEMORY_SINK_BYTES`] 超も `InvalidArgument`（保持量に上限の無い sink を作れないようにする）。
    pub fn new(capacity_bytes: usize) -> Result<Self, TraitError> {
        if capacity_bytes < line_cost(MAX_LINE_BYTES) {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "memory sink capacity is smaller than the maximum line size",
            ));
        }
        if capacity_bytes > MAX_MEMORY_SINK_BYTES {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "memory sink capacity is larger than the maximum",
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
    discarded_lines: u64,
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
    /// sink へ届かなかった行数。sink の追記失敗によるもの（失敗した行と、以後に読み捨てた行）と、
    /// 読み取りエラーで未完了のまま破棄した末尾行を数える。[`Self::lines`] の内数。
    pub fn discarded_lines(&self) -> u64 {
        self.discarded_lines
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

#[derive(Default)]
struct GateState {
    /// 取消しが要求済みか（以後、新しい追記を始めない）。
    requested: bool,
    /// 実行中の追記の数（ストリームあたり高々 1）。
    in_flight: usize,
}

/// 捕捉の取消し状態。リーダーは追記の前後で実行中の件数を増減し、取消しは要求を立ててから
/// 実行中の追記が 0 件になるのを期限付きで待つ。
///
/// 保証: 取消しの要求後に新しい追記は始まらない（要求の確認と件数の加算を同じロック内で行う）。
/// 待機が期限内に終われば、返った後に sink へ届く追記は無い。期限切れなら実行中の追記
/// （ストリームあたり高々 1 件）だけが後から完了し得る。ロックは追記の間は保持しないため、
/// sink が止まっても取消しは期限で返る（REPAIR-5）。
#[derive(Default)]
struct CancelGate {
    state: Mutex<GateState>,
    idle: Condvar,
}

/// 実行中の追記 1 件ぶん。drop（追記が panic した場合を含む）で件数を戻し、待機中の取消しを起こす。
struct InFlight<'a>(&'a CancelGate);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let mut g = self.0.lock();
        g.in_flight = g.in_flight.saturating_sub(1);
        if g.in_flight == 0 {
            self.0.idle.notify_all();
        }
    }
}

impl CancelGate {
    /// 状態は整数と真偽値だけで、途中状態で壊れないため毒化は無視してよい。
    fn lock(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 取消しを要求し、実行中の追記が無くなるのを `until` まで待つ。
    /// 戻り値は、実行中の追記が無い状態で返ったか（`false` は期限切れで、実行中の追記が残っている）。
    fn cancel(&self, until: Instant) -> bool {
        let mut g = self.lock();
        g.requested = true;
        while g.in_flight > 0 {
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            g = self
                .idle
                .wait_timeout(g, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }

    /// 取消しが要求済みか。
    fn is_cancelled(&self) -> bool {
        self.lock().requested
    }

    /// 取消しの要求前なら `f` を実行して `Some`、要求済みなら実行せず `None`。
    /// `f` の間はロックを保持せず、実行中の件数として数える。
    fn run_unless_cancelled<T>(&self, f: impl FnOnce() -> T) -> Option<T> {
        let in_flight = {
            let mut g = self.lock();
            if g.requested {
                return None;
            }
            g.in_flight = g.in_flight.saturating_add(1);
            InFlight(self)
        };
        let out = f();
        drop(in_flight);
        Some(out)
    }
}

/// 起動済みのリーダースレッド群への取っ手。捕捉を止める・終端を待つ唯一の手段である。
///
/// [`LogCapture::drain`]・[`LogCapture::cancel`] を呼ばずに破棄した場合、捕捉は取り消されない（リーダーは EOF まで
/// sink へ追記を続け、以後は止める手段が無くなる）。そのため [`crate::run::monitor_with_capture`] は、
/// 終端待ちをしなかった全経路（停止要求・監視の失敗）で本取っ手を呼び出し側へ返す。
pub struct LogCapture {
    rx: mpsc::Receiver<(StreamKind, StreamSummary)>,
    expected: usize,
    cancel: Arc<CancelGate>,
    /// [`LogCapture::cancel`] が、取消し後に受理済みの行を書き出すために保持する（TASK-164.3・SUP-7）。
    sink: Arc<dyn LogSink>,
}

impl std::fmt::Debug for LogCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogCapture")
            .field("streams", &self.expected)
            .field("cancelled", &self.cancel.is_cancelled())
            .finish()
    }
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
            sink,
        })
    }

    /// 全ストリームが EOF になるまで `timeout` を上限に待つ。期限切れは `Timeout`、
    /// [`MAX_DRAIN_TIMEOUT`] を超える `timeout`（`Duration::MAX` 等）は `InvalidArgument`。
    ///
    /// `Err` を返す全経路で、返る前に捕捉を取り消す（`self` を消費するため、呼び出し側は後から止められない）。
    /// 取消しの要求後に新しい追記は始まらず、リーダーは次に `read` が戻った時点で終了する。
    ///
    /// EOF は `timeout` いっぱいまで待つ（期限内に届いた EOF は成功）。sink の追記が止まっていても `timeout` 以内に
    /// 返る（REPAIR-5）ため、期限切れでは実行中の追記の完了を待たない。その時点で実行中だった追記
    /// （ストリームあたり高々 1 件）だけは、`Err` が返った後に完了し得る（module doc 参照）。
    pub fn drain(self, timeout: Duration) -> Result<CaptureSummary, TraitError> {
        let started = Instant::now();
        // 公開 API のため直接呼ばれうる。上限超は拒否し、Duration::MAX 等で加算が溢れても panic しない。
        let deadline = if timeout > MAX_DRAIN_TIMEOUT {
            None
        } else {
            started.checked_add(timeout)
        };
        let Some(deadline) = deadline else {
            // 不正な timeout でも取り消してから返す。待つのは固定の猶予まで。
            let until = started
                .checked_add(CANCEL_SETTLE_TIMEOUT)
                .unwrap_or(started);
            self.cancel.cancel(until);
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "drain timeout is too large",
            ));
        };
        let result = self.wait_all(deadline);
        if result.is_err() {
            // 期限（deadline）を超えては待たない。期限切れの場合は取消しを要求するだけで返る。
            self.cancel.cancel(deadline);
        }
        result
    }

    /// EOF を待たずに捕捉を取り消す（プロセスが生存したまま監視をやめる場合等。REPAIR-5）。
    ///
    /// 取消しの要求後に新しい追記は始まらず、リーダーは次に `read` が戻った時点で終了する。実行中の追記の完了は
    /// [`CANCEL_SETTLE_TIMEOUT`] まで待つ。待ち切れなかった場合は `Timeout`（取消し自体は成立しており、
    /// 実行中だった追記〔ストリームあたり高々 1 件〕だけが後から完了し得る）。ストリームは取り戻せない。
    ///
    /// 契約（SUP-7）: 実行中の追記が終わった（`Ok` を返す）場合、返る前に [`LogSink::flush`] を呼び、受理済みの行を
    /// 書き出す（リーダーは取消し後に flush しないため、ここで行わないと sink 内バッファの行が見えないまま失われる）。
    /// この時点でリーダーによる sink 呼び出しは無いので競合しない。flush の失敗はその `Err` を返す。
    pub fn cancel(self) -> Result<(), TraitError> {
        let now = Instant::now();
        let until = now.checked_add(CANCEL_SETTLE_TIMEOUT).unwrap_or(now);
        if self.cancel.cancel(until) {
            self.sink.flush()
        } else {
            Err(TraitError::new(
                ErrorCode::Timeout,
                "timed out waiting for in-flight log append to finish",
            ))
        }
    }

    /// [`LogCapture::drain`] の EOF 待ち本体（取消しは呼び出し元が行う）。
    fn wait_all(&self, deadline: Instant) -> Result<CaptureSummary, TraitError> {
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
    /// sink の追記が失敗した（以後は sink を呼ばず、読み捨てる）。
    sink_failed: bool,
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

    /// 未完了の行バッファを sink へ渡さずに破棄する（読み取りエラー時）。行としては数え、届かなかった行数に計上する。
    fn discard_partial(&mut self) {
        if self.buf.is_empty() && !self.cut {
            return;
        }
        self.summary.lines = self.summary.lines.saturating_add(1);
        self.summary.discarded_lines = self.summary.discarded_lines.saturating_add(1);
        if self.cut {
            self.summary.truncated_lines = self.summary.truncated_lines.saturating_add(1);
        }
        self.buf.clear();
        self.cut = false;
    }

    /// sink のバッファを書き出す。取消し・失敗の扱いは [`Self::emit`] と同じ（取消し後・失敗後は呼ばない）。
    /// 失敗は `error_code` に載せる（受理済みの行は遡って数え直さない。モジュール doc 参照）。
    fn flush_sink(&mut self) {
        if self.cancelled || self.sink_failed {
            return;
        }
        match self.cancel.run_unless_cancelled(|| self.sink.flush()) {
            None => self.cancelled = true,
            Some(Err(e)) => {
                self.summary.error_code.get_or_insert(e.code());
                self.sink_failed = true;
            }
            Some(Ok(())) => {}
        }
    }

    fn emit(&mut self) {
        if self.sink_failed {
            // 故障した sink は再度呼ばない。行としては数え、届かなかった行数に計上する。
            self.summary.discarded_lines = self.summary.discarded_lines.saturating_add(1);
        } else {
            // 取消しの確認と「実行中」の計上を不可分にする（要求後に新しい追記を始めない）。
            let Some(appended) = self
                .cancel
                .run_unless_cancelled(|| self.sink.append(self.kind, &self.buf))
            else {
                self.cancelled = true;
                self.buf.clear();
                return;
            };
            if let Err(e) = appended {
                // 読み取りは続ける（パイプを詰まらせない）が、以後このストリームでは sink を呼ばない。
                self.summary.error_code.get_or_insert(e.code());
                self.summary.discarded_lines = self.summary.discarded_lines.saturating_add(1);
                self.sink_failed = true;
            }
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
        sink_failed: false,
        buf: Vec::new(),
        cut: false,
        summary: StreamSummary::default(),
    };
    let mut chunk = [0u8; READ_CHUNK_BYTES];
    loop {
        // 直前のチャンクの処理中に取り消された場合に、次の read（ブロックし得る）へ進まない。
        // sink の失敗後は追記時の確認を通らないため、ここで必ず確認する。
        if sp.cancelled || cancel.is_cancelled() {
            return sp.summary;
        }
        let r = stream.read(&mut chunk);
        // drain が取り消した後は、読めたデータも sink へ渡さず終了する（スレッド・ストリームの回収）。
        if cancel.is_cancelled() {
            return sp.summary;
        }
        match r {
            Ok(0) => break,
            Ok(n) => {
                sp.summary.bytes = sp.summary.bytes.saturating_add(n as u64);
                if let Some(data) = chunk.get(..n) {
                    sp.feed(data);
                }
                // 読むたびに書き出す。満杯の read の直後に書き手が止まっても、次の read（ブロックし得る）の前に
                // 受理済みの行が必ず書き出される（時間上限の無い滞留を作らない）。まとめ書きは sink 内のバッファが担う。
                sp.flush_sink();
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => {
                sp.summary.error_code.get_or_insert(ErrorCode::Internal);
                // LF にも EOF にも達していない末尾は、欠けた内容を正常な行として残さないよう破棄する。
                sp.discard_partial();
                break;
            }
        }
    }
    if !sp.buf.is_empty() && !sp.cancelled {
        sp.emit();
    }
    // EOF・読み取りエラーの単一出口。summary を返す（＝ drain 側が完了を観測する）前に書き出す。
    sp.flush_sink();
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
        // EOF は timeout（200ms）いっぱいまで待つ（手前で打ち切らない）。
        let drain_started = Instant::now();
        let err = cap.drain(Duration::from_millis(200)).unwrap_err();
        let waited = drain_started.elapsed();
        assert!(waited >= Duration::from_millis(200), "{waited:?}");
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

    /// REPAIR-5・TASK-157.7: 期限内に届いた EOF は成功として扱う（drain を始めてから 100ms 後に末尾行を書いて閉じても、
    /// 期限 10 秒の drain は集計〔2 行・10 バイト〕を返し、末尾行も sink に届く）。
    #[test]
    fn sup1_task157_7_drain_succeeds_when_eof_arrives_before_deadline() {
        let budget = ReaderBudget::new(1).unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let sink = Arc::new(MemoryLogSink::default());
        let cap = LogCapture::start(
            OutputStreams::new(&budget, Some(Box::new(reader)), None),
            sink.clone(),
        )
        .unwrap();
        writer.write_all(b"head\n").unwrap();
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            writer.write_all(b"tail\n").unwrap();
        });
        let sum = cap.drain(Duration::from_secs(10)).unwrap();
        closer.join().unwrap();
        assert_eq!(sum.stdout().unwrap().lines(), 2);
        assert_eq!(sum.stdout().unwrap().bytes(), 10);
        assert_eq!(
            sink.snapshot().unwrap(),
            vec![
                line(StreamKind::Stdout, b"head"),
                line(StreamKind::Stdout, b"tail")
            ]
        );
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    /// REPAIR-5・TASK-157.7: 取消しの要求後は追記を実行しない。
    #[test]
    fn sup1_task157_7_cancel_gate_rejects_append_after_cancel() {
        let gate = CancelGate::default();
        assert_eq!(gate.run_unless_cancelled(|| 7), Some(7));
        assert!(!gate.is_cancelled());
        assert!(gate.cancel(far()));
        assert!(gate.is_cancelled());
        assert_eq!(gate.run_unless_cancelled(|| 7), None);
    }

    /// REPAIR-5・TASK-157.7: 期限に余裕があれば、取消しは実行中の追記（200ms）の完了を待ってから true で返る。
    /// 返った時点で追記は完了済み（done = 1）で、以後の追記は実行されない。
    #[test]
    fn sup1_task157_7_cancel_gate_waits_for_in_flight_append() {
        let gate = Arc::new(CancelGate::default());
        let done = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let t = {
            let (gate, done) = (Arc::clone(&gate), Arc::clone(&done));
            std::thread::spawn(move || {
                gate.run_unless_cancelled(|| {
                    entered_tx.send(()).unwrap();
                    std::thread::sleep(Duration::from_millis(200));
                    done.fetch_add(1, Ordering::SeqCst);
                })
            })
        };
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(gate.cancel(far()));
        assert_eq!(done.load(Ordering::SeqCst), 1);
        assert_eq!(t.join().unwrap(), Some(()));
        assert_eq!(gate.run_unless_cancelled(|| 7), None);
    }

    /// REPAIR-5・TASK-157.7: 追記が止まっていても取消しは期限（50ms）で false を返し、無期限に待たない。
    /// 追記が panic しても実行中の件数は戻る（次の取消しは待たずに true）。
    #[test]
    fn sup1_task157_7_cancel_gate_does_not_wait_past_deadline() {
        let gate = Arc::new(CancelGate::default());
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let t = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                gate.run_unless_cancelled(|| {
                    entered_tx.send(()).unwrap();
                    let _ = release_rx.recv();
                    panic!("fake sink panic");
                })
            })
        };
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let start = Instant::now();
        assert!(!gate.cancel(Instant::now() + Duration::from_millis(50)));
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(50), "{waited:?}");
        assert!(waited < Duration::from_secs(5), "{waited:?}");
        assert_eq!(gate.run_unless_cancelled(|| 7), None);
        release_tx.send(()).unwrap();
        assert!(t.join().is_err());
        assert!(gate.cancel(far()));
    }

    /// REPAIR-5・TASK-157.7: cancel は EOF を待たずに捕捉を止める。以後に届いた行は追記されず、リーダーは終了して枠を返す。
    #[test]
    fn sup1_task157_7_cancel_stops_capture_without_eof() {
        let budget = ReaderBudget::new(1).unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let sink = Arc::new(MemoryLogSink::default());
        let cap = LogCapture::start(
            OutputStreams::new(&budget, Some(Box::new(reader)), None),
            sink.clone(),
        )
        .unwrap();
        assert_eq!(
            format!("{cap:?}"),
            "LogCapture { streams: 1, cancelled: false }"
        );
        assert_eq!(cap.cancel(), Ok(()));
        writer.write_all(b"late\n").unwrap();
        assert_eq!(wait_live(&budget, 0), 0);
        assert_eq!(sink.snapshot().unwrap(), Vec::<CapturedLine>::new());
        drop(writer);
    }

    /// 解放されるまで追記が戻らない sink。追記に入ったことを `entered` で知らせ、完了した行だけを `done` に残す。
    struct BlockingSink {
        entered: Mutex<mpsc::Sender<()>>,
        release: Mutex<mpsc::Receiver<()>>,
        done: Mutex<Vec<Vec<u8>>>,
        /// 解放後に失敗（`Unavailable`）を返すか。
        fail: bool,
    }
    impl LogSink for BlockingSink {
        fn append(&self, _: StreamKind, line: &[u8]) -> Result<(), TraitError> {
            let _ = self.entered.lock().unwrap().send(());
            let _ = self.release.lock().unwrap().recv();
            if self.fail {
                return Err(TraitError::new(ErrorCode::Unavailable, "fake sink failure"));
            }
            self.done.lock().unwrap().push(line.to_vec());
            Ok(())
        }
    }

    /// REPAIR-5・TASK-157.7: sink の失敗後（以後の行は追記時の取消し確認を通らない）でも、チャンクの処理中に
    /// 取り消されていれば次の read へ進まず終了する。パイプを開いたまま・追加の出力なしでも枠が 0 に戻る。
    #[test]
    fn sup1_task157_7_cancelled_reader_exits_after_sink_failure_without_another_read() {
        let budget = ReaderBudget::new(1).unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let sink = Arc::new(BlockingSink {
            entered: Mutex::new(entered_tx),
            release: Mutex::new(release_rx),
            done: Mutex::new(Vec::new()),
            fail: true,
        });
        let cap = LogCapture::start(
            OutputStreams::new(&budget, Some(Box::new(reader)), None),
            sink.clone(),
        )
        .unwrap();
        writer.write_all(b"a\nb\nc\n").unwrap();
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        // 1 行目の追記中に期限切れ → 取消し。その後 1 行目が失敗で戻り、残りは sink を呼ばずに読み捨てられる。
        let err = cap.drain(Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        release_tx.send(()).unwrap();
        assert_eq!(wait_live(&budget, 0), 0);
        assert_eq!(*sink.done.lock().unwrap(), Vec::<Vec<u8>>::new());
        drop(writer);
    }

    /// REPAIR-5・TASK-157.7: sink の追記が止まっていても drain は timeout（200ms）で Timeout を返す。
    /// 返った後に sink へ届くのは実行中だった 1 行（"a"）だけで、同じチャンクで読めていた次の行（"b"）は追記されない。
    #[test]
    fn sup1_task157_7_drain_times_out_even_if_sink_append_blocks() {
        let budget = ReaderBudget::new(1).unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let sink = Arc::new(BlockingSink {
            entered: Mutex::new(entered_tx),
            release: Mutex::new(release_rx),
            done: Mutex::new(Vec::new()),
            fail: false,
        });
        let cap = LogCapture::start(
            OutputStreams::new(&budget, Some(Box::new(reader)), None),
            sink.clone(),
        )
        .unwrap();
        writer.write_all(b"a\nb\n").unwrap();
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();

        let start = Instant::now();
        let err = cap.drain(Duration::from_millis(200)).unwrap_err();
        let waited = start.elapsed();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "timed out waiting for log streams to reach EOF"
        );
        assert!(waited >= Duration::from_millis(200), "{waited:?}");
        assert!(waited < Duration::from_secs(5), "{waited:?}");
        assert_eq!(*sink.done.lock().unwrap(), Vec::<Vec<u8>>::new());
        // 止まった追記はリーダーと枠を占有し続ける（上限で数えられる）。
        assert_eq!(budget.live(), 1);

        // 追記が再開しても、完了するのは実行中だった 1 行だけ。パイプを閉じなくてもリーダーは終了する。
        release_tx.send(()).unwrap();
        assert_eq!(wait_live(&budget, 0), 0);
        assert_eq!(*sink.done.lock().unwrap(), vec![b"a".to_vec()]);
        drop(writer);
    }

    /// REPAIR-5・TASK-157.7: sink の追記が止まっていると cancel は猶予（100ms）で Timeout を返す（無期限に待たない）。
    /// 取消し自体は成立しており、後から届くのは実行中だった 1 行（"a"）だけ。
    #[test]
    fn sup1_task157_7_cancel_reports_timeout_if_sink_append_blocks() {
        let budget = ReaderBudget::new(1).unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let sink = Arc::new(BlockingSink {
            entered: Mutex::new(entered_tx),
            release: Mutex::new(release_rx),
            done: Mutex::new(Vec::new()),
            fail: false,
        });
        let cap = LogCapture::start(
            OutputStreams::new(&budget, Some(Box::new(reader)), None),
            sink.clone(),
        )
        .unwrap();
        writer.write_all(b"a\nb\n").unwrap();
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let start = Instant::now();
        let err = cap.cancel().unwrap_err();
        let waited = start.elapsed();
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert_eq!(
            err.message(),
            "timed out waiting for in-flight log append to finish"
        );
        assert!(waited >= Duration::from_millis(100), "{waited:?}");
        assert!(waited < Duration::from_secs(5), "{waited:?}");
        release_tx.send(()).unwrap();
        assert_eq!(wait_live(&budget, 0), 0);
        assert_eq!(*sink.done.lock().unwrap(), vec![b"a".to_vec()]);
        drop(writer);
    }

    /// 追記に 20ms かかる sink。追記に入ったことを `entered` で知らせ、完了した行だけを `done` に残す。
    struct SlowSink {
        entered: Mutex<mpsc::Sender<()>>,
        done: Mutex<Vec<Vec<u8>>>,
    }
    impl LogSink for SlowSink {
        fn append(&self, _: StreamKind, line: &[u8]) -> Result<(), TraitError> {
            let _ = self.entered.lock().unwrap().send(());
            std::thread::sleep(Duration::from_millis(20));
            self.done.lock().unwrap().push(line.to_vec());
            Ok(())
        }
    }

    /// REPAIR-5・TASK-157.7: 溢れる timeout で取り消した時点で追記が実行中（20ms）なら、猶予（100ms）内の完了を待って
    /// から返る。返った時点で実行中だった 1 行（"a"）は完了済みで、次の行（"b"）は追記されず、以後も変わらない。
    #[test]
    fn sup1_task157_7_drain_error_waits_for_in_flight_append_and_stops_the_rest() {
        assert_eq!(CANCEL_SETTLE_TIMEOUT, Duration::from_millis(100));
        let budget = ReaderBudget::new(1).unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let sink = Arc::new(SlowSink {
            entered: Mutex::new(entered_tx),
            done: Mutex::new(Vec::new()),
        });
        let cap = LogCapture::start(
            OutputStreams::new(&budget, Some(Box::new(reader)), None),
            sink.clone(),
        )
        .unwrap();
        writer.write_all(b"a\nb\n").unwrap();
        entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let err = cap.drain(Duration::MAX).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
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

    /// `data` を返し切った後、EOF ではなく読み取りエラーを返すストリーム。
    struct FailingRead {
        data: Cursor<Vec<u8>>,
    }
    impl Read for FailingRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.data.read(buf)? {
                0 => Err(std::io::Error::other("fake read failure")),
                n => Ok(n),
            }
        }
    }

    /// TASK-157.7: 読み取りがエラーで終わった場合、未完了の末尾（"par"）は sink へ渡さず破棄する。
    /// 完了済みの 2 行だけが残り、集計は 3 行（うち届かなかった行 1）・10 バイト・Internal。
    #[test]
    fn sup1_task157_7_read_error_discards_incomplete_line() {
        let sink = Arc::new(MemoryLogSink::default());
        let stream = FailingRead {
            data: Cursor::new(b"ok1\nok2\npar".to_vec()),
        };
        let cap = LogCapture::start(
            OutputStreams::new(
                &ReaderBudget::with_max_limit(),
                Some(Box::new(stream)),
                None,
            ),
            sink.clone(),
        )
        .unwrap();
        let sum = cap.drain(Duration::from_secs(10)).unwrap();
        let s = sum.stdout().unwrap();
        assert_eq!(s.error_code(), Some(ErrorCode::Internal));
        assert_eq!(s.lines(), 3);
        assert_eq!(s.discarded_lines(), 1);
        assert_eq!(s.bytes(), 11);
        assert_eq!(
            sink.snapshot().unwrap(),
            vec![
                line(StreamKind::Stdout, b"ok1"),
                line(StreamKind::Stdout, b"ok2")
            ]
        );
    }

    /// TASK-157.7: 読み取りエラーの時点で未完了の末尾が無ければ、破棄する行は無い（2 行・届かなかった行 0）。
    #[test]
    fn sup1_task157_7_read_error_without_partial_line_discards_nothing() {
        let sink = Arc::new(MemoryLogSink::default());
        let stream = FailingRead {
            data: Cursor::new(b"ok1\nok2\n".to_vec()),
        };
        let cap = LogCapture::start(
            OutputStreams::new(
                &ReaderBudget::with_max_limit(),
                Some(Box::new(stream)),
                None,
            ),
            sink.clone(),
        )
        .unwrap();
        let sum = cap.drain(Duration::from_secs(10)).unwrap();
        let s = sum.stdout().unwrap();
        assert_eq!(s.error_code(), Some(ErrorCode::Internal));
        assert_eq!(s.lines(), 2);
        assert_eq!(s.discarded_lines(), 0);
        assert_eq!(sink.snapshot().unwrap().len(), 2);
    }

    /// 最初の `fail_after` 行までは成功し、以後は失敗する sink。呼ばれた回数を数える。
    struct FailAfterSink {
        fail_after: usize,
        calls: AtomicUsize,
    }
    impl LogSink for FailAfterSink {
        fn append(&self, _: StreamKind, _: &[u8]) -> Result<(), TraitError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) < self.fail_after {
                Ok(())
            } else {
                Err(TraitError::new(ErrorCode::Unavailable, "fake sink failure"))
            }
        }
    }

    /// TASK-157.7: sink の追記が失敗したら、そのストリームでは以後 sink を呼ばず、EOF まで読み捨てる。
    /// 5 行のうち 2 行目で失敗する場合、append は 2 回だけ呼ばれ、届かなかった行は 4 行（失敗した行を含む）。
    #[test]
    fn sup1_task157_7_sink_is_not_called_again_after_failure() {
        let sink = Arc::new(FailAfterSink {
            fail_after: 1,
            calls: AtomicUsize::new(0),
        });
        let cap = LogCapture::start(
            OutputStreams::new(
                &ReaderBudget::with_max_limit(),
                boxed(b"a\nb\nc\nd\ne"),
                None,
            ),
            sink.clone(),
        )
        .unwrap();
        let sum = cap.drain(Duration::from_secs(10)).unwrap();
        let s = sum.stdout().unwrap();
        assert_eq!(sink.calls.load(Ordering::SeqCst), 2);
        assert_eq!(s.error_code(), Some(ErrorCode::Unavailable));
        assert_eq!(s.lines(), 5);
        assert_eq!(s.discarded_lines(), 4);
        assert_eq!(s.bytes(), 9);
    }

    /// TASK-157.7: sink の失敗はストリームごとに扱う（stdout で失敗しても stderr の 2 行は届く）。
    #[test]
    fn sup1_task157_7_sink_failure_is_per_stream() {
        struct StdoutFails(MemoryLogSink);
        impl LogSink for StdoutFails {
            fn append(&self, stream: StreamKind, line: &[u8]) -> Result<(), TraitError> {
                if stream == StreamKind::Stdout {
                    return Err(TraitError::new(ErrorCode::Internal, "fake sink failure"));
                }
                self.0.append(stream, line)
            }
        }
        let sink = Arc::new(StdoutFails(MemoryLogSink::default()));
        let cap = LogCapture::start(
            OutputStreams::new(
                &ReaderBudget::with_max_limit(),
                boxed(b"o1\no2\n"),
                boxed(b"e1\ne2\n"),
            ),
            sink.clone(),
        )
        .unwrap();
        let sum = cap.drain(Duration::from_secs(10)).unwrap();
        assert_eq!(sum.stdout().unwrap().discarded_lines(), 2);
        assert_eq!(sum.stderr().unwrap().discarded_lines(), 0);
        assert_eq!(sum.stderr().unwrap().error_code(), None);
        assert_eq!(
            sink.0.snapshot().unwrap(),
            vec![
                line(StreamKind::Stderr, b"e1"),
                line(StreamKind::Stderr, b"e2")
            ]
        );
    }

    /// REPAIR-5・TASK-157.7: drain の timeout は MAX_DRAIN_TIMEOUT（60 秒）以下に限る。超過は待たずに
    /// InvalidArgument で返り、捕捉は取り消される（リーダーは終了して枠を返す）。
    #[test]
    fn sup1_task157_7_drain_rejects_timeout_above_max() {
        assert_eq!(MAX_DRAIN_TIMEOUT, Duration::from_secs(60));
        let budget = ReaderBudget::new(1).unwrap();
        let (reader, mut writer) = std::io::pipe().unwrap();
        let sink = Arc::new(MemoryLogSink::default());
        let cap = LogCapture::start(
            OutputStreams::new(&budget, Some(Box::new(reader)), None),
            sink.clone(),
        )
        .unwrap();
        let start = Instant::now();
        let err = cap
            .drain(MAX_DRAIN_TIMEOUT + Duration::from_nanos(1))
            .unwrap_err();
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        assert_eq!(err.message(), "drain timeout is too large");
        writer.write_all(b"late\n").unwrap();
        assert_eq!(wait_live(&budget, 0), 0);
        assert_eq!(sink.snapshot().unwrap(), Vec::<CapturedLine>::new());
        drop(writer);
    }

    /// TASK-157.7: メモリ sink の容量は MAX_MEMORY_SINK_BYTES（64MiB）以下に限る（境界は受理、超過は拒否）。
    #[test]
    fn sup1_task157_7_memory_sink_capacity_has_maximum() {
        assert_eq!(MAX_MEMORY_SINK_BYTES, 67_108_864);
        assert!(MemoryLogSink::new(MAX_MEMORY_SINK_BYTES).is_ok());
        for bad in [MAX_MEMORY_SINK_BYTES + 1, usize::MAX] {
            let err = MemoryLogSink::new(bad).err().unwrap();
            assert_eq!(err.code(), ErrorCode::InvalidArgument);
            assert_eq!(
                err.message(),
                "memory sink capacity is larger than the maximum"
            );
        }
        let err = MemoryLogSink::new(line_cost(MAX_LINE_BYTES) - 1)
            .err()
            .unwrap();
        assert_eq!(
            err.message(),
            "memory sink capacity is smaller than the maximum line size"
        );
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
        assert_eq!(s.discarded_lines(), 3);
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

    /// 1 回の `read` で最大 `step` バイトだけ返すリーダー。実パイプの短い read（バッファ境界を跨ぐ到着）を決定的に再現する
    /// （TASK-164.1・#505・SUP-7）。`LineSplitter` が read 戻りサイズに依存しないことの照合専用。
    struct StepRead {
        data: Cursor<Vec<u8>>,
        step: usize,
    }
    impl Read for StepRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.step);
            let head = buf.get_mut(..n).unwrap_or(&mut []);
            self.data.read(head)
        }
    }

    /// あらかじめ切ったチャンク列を 1 回の `read` につき 1 個ずつ返すリーダー（任意の境界位置を明示する用）。
    /// 各チャンクは `READ_CHUNK_BYTES` 以下であること。
    struct ChunkRead {
        chunks: VecDeque<Vec<u8>>,
    }
    impl Read for ChunkRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some(c) = self.chunks.pop_front() else {
                return Ok(0);
            };
            assert!(c.len() <= buf.len());
            let dst = buf.get_mut(..c.len()).unwrap_or(&mut []);
            dst.copy_from_slice(&c);
            Ok(c.len())
        }
    }

    fn chunked(chunks: &[&[u8]]) -> Option<Box<dyn Read + Send>> {
        Some(Box::new(ChunkRead {
            chunks: chunks.iter().map(|c| c.to_vec()).collect(),
        }))
    }

    fn stepped(data: &[u8], step: usize) -> Option<Box<dyn Read + Send>> {
        Some(Box::new(StepRead {
            data: Cursor::new(data.to_vec()),
            step,
        }))
    }

    fn out_lines(sink: &MemoryLogSink) -> Vec<Vec<u8>> {
        sink.snapshot()
            .unwrap()
            .into_iter()
            .map(|l| l.bytes)
            .collect()
    }

    /// TASK-164.1・SUP-7: チャンク境界が行内（単語途中）・LF 直前 / 直後・行をまたぐ位置にあっても行が壊れない。
    #[test]
    fn sup7_task164_1_chunk_boundaries_do_not_split_or_merge_lines() {
        type Case<'a> = (Vec<&'a [u8]>, Vec<&'a [u8]>);
        let cases: Vec<Case> = vec![
            (vec![b"hel", b"lo\nwor", b"ld\n"], vec![b"hello", b"world"]),
            (vec![b"abc\n", b"def\n"], vec![b"abc", b"def"]),
            (vec![b"abc", b"\ndef\n"], vec![b"abc", b"def"]),
            (vec![b"ab", b"c\nde", b"f"], vec![b"abc", b"def"]),
            (vec![b"a\n", b"\n", b"b\n"], vec![b"a", b"", b"b"]),
            (vec![b"x\r", b"\ny\n"], vec![b"x\r", b"y"]),
        ];
        for (chunks, want) in cases {
            let (sink, sum) = run(chunked(&chunks), None);
            let want: Vec<Vec<u8>> = want.iter().map(|w| w.to_vec()).collect();
            assert_eq!(out_lines(&sink), want, "chunks={chunks:?}");
            let s = sum.stdout().unwrap();
            assert_eq!(s.lines(), want.len() as u64);
            assert_eq!(s.truncated_lines(), 0);
            assert_eq!(s.discarded_lines(), 0);
            assert_eq!(s.error_code(), None);
        }
    }

    /// TASK-164.1・SUP-7: マルチバイト UTF-8・非 UTF-8 の途中で分断されてもバイト列は同一。
    #[test]
    fn sup7_task164_1_multibyte_and_invalid_utf8_split_is_byte_exact() {
        let (sink, _) = run(
            chunked(&[&[0xe3], &[0x81], &[0x82, b'\n', 0xff], &[0xfe, b'\n']]),
            None,
        );
        assert_eq!(
            out_lines(&sink),
            vec![vec![0xe3, 0x81, 0x82], vec![0xff, 0xfe]]
        );
    }

    /// TASK-164.1・SUP-7: read の戻りサイズ（1・2・3・7・READ_CHUNK_BYTES-1・READ_CHUNK_BYTES）に依らず、
    /// 一括入力と完全に同一の行列・集計になる。
    #[test]
    fn sup7_task164_1_result_is_independent_of_read_size() {
        let mut data: Vec<u8> = Vec::new();
        for i in 0..14u8 {
            match i % 4 {
                0 => data.extend_from_slice(format!("line-{i}\n").as_bytes()),
                1 => data.extend_from_slice(b"\n"),
                2 => data.extend_from_slice(format!("crlf-{i}\r\n").as_bytes()),
                _ => data.extend_from_slice(&[0xff, 0xfe, b'a' + i, b'\n']),
            }
        }
        data.extend_from_slice(b"tail-no-lf");
        let (base_sink, base) = run(boxed(&data), None);
        let want = out_lines(&base_sink);
        assert_eq!(want.len(), 15);
        assert_eq!(want.last().unwrap(), b"tail-no-lf");
        for step in [1, 2, 3, 7, READ_CHUNK_BYTES - 1, READ_CHUNK_BYTES] {
            let (sink, sum) = run(stepped(&data, step), None);
            assert_eq!(out_lines(&sink), want, "step={step}");
            assert_eq!(sum, base, "step={step}");
            let s = sum.stdout().unwrap();
            assert_eq!(s.lines(), 15);
            assert_eq!(s.truncated_lines(), 0);
            assert_eq!(s.discarded_lines(), 0);
            assert_eq!(s.error_code(), None);
        }
    }

    /// TASK-164.1・SUP-7: READ_CHUNK_BYTES（8KiB）境界を通常長の行が跨いでも内容・長さが一致する。
    #[test]
    fn sup7_task164_1_line_spanning_read_chunk_boundary_is_intact() {
        let mut data = vec![b'p'; READ_CHUNK_BYTES - 3];
        data.push(b'\n');
        data.extend_from_slice(b"0123456789\n");
        let (sink, sum) = run(boxed(&data), None);
        assert_eq!(
            out_lines(&sink),
            vec![vec![b'p'; READ_CHUNK_BYTES - 3], b"0123456789".to_vec()]
        );
        assert_eq!(sum.stdout().unwrap().truncated_lines(), 0);
    }

    /// TASK-164.1・SUP-7: 上限（MAX_LINE_BYTES）ちょうどの行は細切れでも切り捨てない。+1 は 1 件切り捨てて次行は無傷。
    #[test]
    fn sup7_task164_1_max_line_boundary_values() {
        let mut exact = vec![b'm'; MAX_LINE_BYTES];
        exact.extend_from_slice(b"\nnext\n");
        let (sink, sum) = run(stepped(&exact, 1000), None);
        assert_eq!(
            out_lines(&sink),
            vec![vec![b'm'; MAX_LINE_BYTES], b"next".to_vec()]
        );
        assert_eq!(sum.stdout().unwrap().truncated_lines(), 0);

        let mut over = vec![b'm'; MAX_LINE_BYTES + 1];
        over.extend_from_slice(b"\nnext\n");
        let (sink, sum) = run(stepped(&over, 1000), None);
        assert_eq!(
            out_lines(&sink),
            vec![vec![b'm'; MAX_LINE_BYTES], b"next".to_vec()]
        );
        assert_eq!(sum.stdout().unwrap().truncated_lines(), 1);
    }

    /// TASK-164.1・SUP-7: stdout と stderr を異なる分割幅で流しても、行バッファはストリーム別で混ざらない。
    #[test]
    fn sup7_task164_1_streams_do_not_mix_partial_lines() {
        let (sink, sum) = run(stepped(b"out-1\nout-2\n", 2), stepped(b"err-1\nerr-2\n", 5));
        let all = sink.snapshot().unwrap();
        let of = |k: StreamKind| -> Vec<Vec<u8>> {
            all.iter()
                .filter(|l| l.stream == k)
                .map(|l| l.bytes.clone())
                .collect()
        };
        assert_eq!(
            of(StreamKind::Stdout),
            vec![b"out-1".to_vec(), b"out-2".to_vec()]
        );
        assert_eq!(
            of(StreamKind::Stderr),
            vec![b"err-1".to_vec(), b"err-2".to_vec()]
        );
        assert_eq!(sum.stdout().unwrap().lines(), 2);
        assert_eq!(sum.stderr().unwrap().lines(), 2);
    }

    /// `append` / `flush` の呼び出し列を記録する sink（TASK-164.3・SUP-7）。`flush_err` が真なら flush が失敗する。
    #[derive(Default)]
    struct CallLog {
        calls: Mutex<Vec<String>>,
        flush_err: bool,
    }
    impl CallLog {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }
    impl LogSink for CallLog {
        fn append(&self, _stream: StreamKind, line: &[u8]) -> Result<(), TraitError> {
            let l = String::from_utf8_lossy(line).into_owned();
            self.calls.lock().unwrap().push(format!("append {l}"));
            Ok(())
        }
        fn flush(&self) -> Result<(), TraitError> {
            self.calls.lock().unwrap().push("flush".to_string());
            if self.flush_err {
                return Err(TraitError::new(ErrorCode::Internal, "flush failed"));
            }
            Ok(())
        }
    }

    fn pump_chunks(chunks: &[&[u8]], sink: &CallLog) -> StreamSummary {
        let gate = CancelGate::default();
        pump(chunked(chunks).unwrap(), StreamKind::Stdout, sink, &gate)
    }

    /// 短い read の後と EOF で flush される。
    #[test]
    fn sup7_task164_3_flush_after_short_read_and_at_eof() {
        let sink = CallLog::default();
        let sum = pump_chunks(&[b"a\nb\n", b"c\n"], &sink);
        assert_eq!(
            sink.calls(),
            [
                "append a", "append b", "flush", "append c", "flush", "flush"
            ]
        );
        assert_eq!(sum.lines(), 3);
        assert_eq!(sum.error_code(), None);
    }

    /// 満杯の read でも、次の read（ブロックし得る）の前に flush する。末尾の未完了行は EOF で渡し、その後に flush する。
    #[test]
    fn sup7_task164_3_full_reads_are_flushed_before_next_read() {
        let sink = CallLog::default();
        let mut c1 = vec![b'x'; READ_CHUNK_BYTES - 1];
        c1.push(b'\n');
        let c2 = vec![b'y'; READ_CHUNK_BYTES];
        let _ = pump_chunks(&[&c1, &c2], &sink);
        let expected = vec![
            format!("append {}", "x".repeat(READ_CHUNK_BYTES - 1)),
            "flush".to_string(),
            "flush".to_string(),
            format!("append {}", "y".repeat(READ_CHUNK_BYTES)),
            "flush".to_string(),
        ];
        assert_eq!(sink.calls(), expected);
    }

    /// 取消しは、受理済みの行を flush してから戻る（SUP-7）。リーダーは取消し後に flush しない。
    #[test]
    fn sup7_task164_3_cancel_flushes_accepted_lines() {
        let sink = Arc::new(CallLog::default());
        let (r, mut w) = std::io::pipe().unwrap();
        let budget = ReaderBudget::new(1).unwrap();
        let cap = LogCapture::start(
            OutputStreams::new(&budget, Some(Box::new(r)), None),
            sink.clone(),
        )
        .unwrap();
        w.write_all(b"a\n").unwrap();
        let t0 = Instant::now();
        while sink.calls().len() < 2 && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let before = sink.calls().len();
        assert_eq!(cap.cancel(), Ok(()));
        let calls = sink.calls();
        assert_eq!(calls.first().map(String::as_str), Some("append a"));
        assert_eq!(calls.len(), before + 1);
        assert_eq!(calls.last().map(String::as_str), Some("flush"));
        drop(w);
    }

    /// 取消し済みなら sink を一切呼ばない（flush も呼ばない）。
    #[test]
    fn sup7_task164_3_no_flush_after_cancel() {
        let sink = CallLog::default();
        let gate = CancelGate::default();
        assert!(gate.cancel(far()));
        let sum = pump(
            chunked(&[b"a\n"]).unwrap(),
            StreamKind::Stdout,
            &sink,
            &gate,
        );
        assert!(sink.calls().is_empty());
        assert_eq!(sum.lines(), 0);
    }

    /// flush の失敗は error_code に載り、以後 sink は呼ばれない。受け入れ済みの行は lines に残り discarded には載らない。
    #[test]
    fn sup7_task164_3_flush_error_is_reported_and_stops_sink_calls() {
        let sink = CallLog {
            flush_err: true,
            ..CallLog::default()
        };
        let sum = pump_chunks(&[b"a\n", b"b\n"], &sink);
        assert_eq!(sink.calls(), ["append a", "flush"]);
        assert_eq!(sum.error_code(), Some(ErrorCode::Internal));
        assert_eq!(sum.lines(), 2);
        assert_eq!(sum.discarded_lines(), 1);
    }
}
