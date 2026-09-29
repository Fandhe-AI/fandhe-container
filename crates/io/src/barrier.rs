//! FLUSH バリアの ACK 契約を、通常 ACK と型で分離する（IO-1・IO-2・TASK-15.1・
//! #85）。
//!
//! [`crate::client::PipelineClient::recv_ack`]（TASK-12.2・#74）は当初
//! `AckReceipt`（1 つの構造体に `ack_kind: FrameKind` フィールドを持たせ、
//! `ack_kind()` で判別する形）を返していたが、呼び出し元が `ack_kind()` の
//! 確認を怠ると、永続化を保証しない通常 ACK（[`FrameKind::Ack`]・IO-1）を
//! 永続化済み（[`FrameKind::FlushAck`]・IO-2）として扱えてしまい、データ損失
//! （ERR-3 `DATA_LOSS`）につながる余地があった（親 #84 の受入基準：同一型の
//! 判別フィールドで区別しない API にすること）。本モジュールはこれを
//! [`WriteAck`]・[`FlushAck`] という別々の型に分け、[`AckReceipt`] をその
//! 直和（`enum`）にすることで、呼び出し元が種別確認を忘れても取り違えを
//! コンパイル時に検出できるようにする。
//!
//! # 構築経路（偽造できないことの根拠）
//!
//! [`WriteAck`]・[`FlushAck`]・[`AckReceipt`] のフィールドはすべて非公開で、
//! 生成できるのは本 crate 内の `AckReceipt::from_matched`（`pub(crate)`）
//! だけである。これは [`crate::client::PipelineClient::recv_ack`] が、送信順・
//! 種別対応を検証済みの [`crate::client::InFlightRequest`] とワイヤーから
//! 復号した [`FrameKind`] からのみ呼び出す。相互変換（`WriteAck` ↔ `FlushAck`）
//! は一切実装しない。したがって crate 外のコードは実際に受信した ACK を
//! `recv_ack` に通す以外の方法で `FlushAck` を得られず、「バッファリング ACK を
//! 永続化済みとして偽装する」経路は型として存在しない。
//!
//! # サーバー側の永続化（TASK-15.2.2・#824）
//!
//! サーバー側の永続化実行体は本モジュールの `persist_file_system`
//! （`pub(crate)`）で、[`crate::writeback::AppendFileSink`] の
//! [`crate::writeback::BatchSink::persist`] から呼ばれる。
//! [`crate::writeback::serve_connection`] は `Flush` 受信時に persist の成功を
//! 確認してから [`FrameKind::FlushAck`] を送出する。Linux では
//! `crate::sys::syncfs`（`syncfs(2)`）を、中断できない syscall をタイムアウト
//! 付きの helper スレッドで待つ形で実行する（REPAIR-5）。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - 未フラッシュ滞留量のカウンタ [`UnflushedBacklog`] は実装済み（IO-10・TASK-16.1・#90）。
//!   上限との比較・到達時の自動フラッシュは未実装で TASK-16.2・#91 が担う。
//! - macOS / Windows の代替フラッシュ（TASK-15.3・#88）は sink が持つファイル自体
//!   （データ＋ファイルメタデータ）を明示的な syscall（macOS は `fcntl(F_FULLFSYNC)`、
//!   Windows は `FlushFileBuffers`）で永続化したうえで、sink が
//!   ファイルを開いた・作ったときのディレクトリハンドル
//!   （[`crate::writeback::AppendFileSink::open_in`]・[`crate::GuestFileCreator::create_file`]
//!   だけが設定する。任意のパスは受け付けない）も同期し、ファイルのディレクトリ
//!   エントリを永続化する（[`PersistSupport::SupportedFileSync`]）。親ディレクトリの
//!   ハンドルを持たない sink（[`crate::writeback::AppendFileSink::new`]）は
//!   エントリの永続化を保証できないため `Unimplemented` で拒否し FlushAck を返さない
//!   （fail-closed。IO-2・IO-3）。macOS は `F_FULLFSYNC` を使うため、それを
//!   拒否する FS（一部のネットワーク FS 等）では `fsync` へフォールバックせず
//!   失敗として FlushAck を返さない（fail-closed）。Linux・macOS・Windows 以外の OS は
//!   `Unimplemented` を返す。
//! - FLUSH による増幅（#824 の A4）への対策は 2 つ: [`crate::writeback::AppendFileSink`]
//!   は直近の成功以降に書き込みがなければ syncfs を再発行しない（書き込みを
//!   伴わない連続 FLUSH の合流）。また、プロセス全体で同時に実行中の syncfs の
//!   数を [`MaxConcurrentPersist`]（既定 2）までに抑え、超えた FLUSH は期限内で
//!   枠を待つ（接続を増やしても同時負荷は上限まで）。syncfs の回数そのものは
//!   減らさず（各 sink が自分の fd で発行する）、頻度（間隔）の制限も行わない。
//! - Linux 5.8 未満のカーネルは `syncfs(2)` が書き戻しエラーを報告しないため、
//!   [`persist_support`] が `/proc/sys/kernel/osrelease` で版数を確認し、5.8 未満・
//!   判定不能なら `Unimplemented` で拒否して FlushAck を返さない（fail-closed）。
//!   ディストロが修正を旧カーネルへバックポートしていても拒否する（安全側）。
//!   FlushAck が返る環境かは利用者・結合試験も [`persist_support`] で同じ基準で知る。
//! - 検証するのは順序と契約までで、電源断・SIGKILL への耐性は検証しない
//!   （TASK-18）。

use std::fs::File;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::client::{InFlightRequest, RequestId};
use crate::error::{IoError, IoErrorCode};
use crate::protocol::FrameKind;
use crate::transport::IoTimeout;

/// 通常 ACK（[`FrameKind::Ack`]）の受領記録（IO-1）。
///
/// 対応する書き込みが受信プロセスにバッファリングされたことのみを保証し、
/// **永続化は保証しない**。永続化完了の保証が必要な呼び出し元は
/// [`FlushAck`] を待つこと。プロセスクラッシュでは、この ACK 済みのデータも
/// 失われうる（IO-1・IO-2。契約は `docs/api/io-barrier.md`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteAck {
    request: InFlightRequest,
}

impl WriteAck {
    /// この ACK が対応付けた、送信済みだった元のリクエストを返す。
    pub fn request(&self) -> InFlightRequest {
        self.request
    }
}

/// FLUSH バリアに対する ACK（[`FrameKind::FlushAck`]）の受領記録（IO-2）。
///
/// このバリア以前に受理したすべての書き込みが永続化済みであることを保証する。
/// 「以前」は同一接続の受信順で `Flush` より前に受理した書き込みを指し、別接続・
/// 別ハンドル・別プロセスからの書き込みは対象外。実証済みなのは SIGKILL 耐性
/// までで、電源断・OS クラッシュへの耐性は未検証（IO-3）。詳細は
/// `docs/api/io-barrier.md`（TASK-17）を参照。
/// [`WriteAck`] とは異なる型であるため、呼び出し元が誤って通常 ACK を
/// 永続化済みとして扱うことはコンパイル時に防がれる（本モジュールの
/// `//!` ドキュメント「構築経路」参照）。
///
/// # 例（コンパイルできる: `FlushAck` を要求する箇所に `FlushAck` を渡せる）
///
/// ```
/// use fandhe_container_io::barrier::FlushAck;
///
/// fn require_durable(_: &FlushAck) {}
///
/// fn demo(ack: &FlushAck) {
///     require_durable(ack);
/// }
/// ```
///
/// # 例（コンパイルできない: `WriteAck` を `FlushAck` の代わりに渡せない）
///
/// ```compile_fail
/// use fandhe_container_io::barrier::{FlushAck, WriteAck};
///
/// fn require_durable(_: &FlushAck) {}
///
/// fn demo(ack: &WriteAck) {
///     require_durable(ack); // 型が合わずコンパイルエラーになる
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushAck {
    request: InFlightRequest,
}

impl FlushAck {
    /// この ACK が対応付けた、送信済みだった元の FLUSH リクエストを返す。
    pub fn request(&self) -> InFlightRequest {
        self.request
    }

    /// このリクエストに対応する [`FlushBarrier`] を返す。
    ///
    /// [`Self`] は `AckReceipt::from_matched` が種別 [`FrameKind::Flush`] の
    /// リクエストからのみ構築するため（本モジュールの `//!` ドキュメント参照）、
    /// ここでの変換は常に成功する。呼び出し元は
    /// [`crate::client::PipelineClient::flush`] が返した [`FlushBarrier`] との
    /// 対応を `ack.barrier() == barrier` で確認できる。
    pub fn barrier(&self) -> FlushBarrier {
        FlushBarrier(self.request)
    }
}

/// 種別が [`FrameKind::Flush`] であることが保証された、発行済みバリアの
/// ハンドル（IO-2・TASK-15.1・#85）。
///
/// [`crate::client::PipelineClient::flush`] が送信直後に返し、
/// [`FlushAck::barrier`] が受信した FLUSH ACK から返す。両者を
/// `PartialEq`（[`InFlightRequest`] の id・種別による比較）で突き合わせられる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlushBarrier(InFlightRequest);

impl FlushBarrier {
    /// このバリアの元になったリクエストを返す。
    pub fn request(&self) -> InFlightRequest {
        self.0
    }

    /// このバリアの識別子（[`RequestId`]）を返す。
    pub fn id(&self) -> RequestId {
        self.0.id()
    }
}

impl TryFrom<InFlightRequest> for FlushBarrier {
    type Error = IoError;

    /// `request` の種別が [`FrameKind::Flush`] でなければ
    /// [`IoErrorCode::InvalidArgument`] で拒否する。
    fn try_from(request: InFlightRequest) -> Result<Self, Self::Error> {
        if request.kind() == FrameKind::Flush {
            Ok(Self(request))
        } else {
            Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "FlushBarrier can only be built from a Flush-kind in-flight request",
            ))
        }
    }
}

/// [`crate::client::PipelineClient::recv_ack`] が返す、検証・対応付け済みの
/// ACK 受領記録（IO-1・IO-2・TASK-12.2・TASK-15.1・#74・#85）。
///
/// 通常 ACK（[`WriteAck`]）と FLUSH ACK（[`FlushAck`]）を同一型の判別
/// フィールドではなく別バリアントとして表現する（本モジュールの `//!`
/// ドキュメント参照）。`#[non_exhaustive]` により、将来 3 つ目の ACK 種別を
/// 追加してもこの enum を外部で網羅的に `match` しているコードを壊さない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AckReceipt {
    /// [`FrameKind::Ack`]（IO-1）。
    Write(WriteAck),
    /// [`FrameKind::FlushAck`]（IO-2）。
    Flush(FlushAck),
}

impl AckReceipt {
    /// 検証・対応付け済みの ACK 受領記録を、種別の組み合わせから構築する
    /// （`pub(crate)`。本モジュールの `//!` ドキュメント「構築経路」参照）。
    ///
    /// [`crate::client::PipelineClient::recv_ack`] だけが呼び出す想定で、
    /// `request` は送信順・`ack_kind` はペイロード検証済みのワイヤー値を渡す。
    /// `(Write, Ack)` → [`AckReceipt::Write`]、`(Flush, FlushAck)` →
    /// [`AckReceipt::Flush`] 以外の組み合わせは、呼び出し元がすでに
    /// `expected_ack_kind` で種別対応を検証しているため到達しないはずだが、
    /// `unwrap`・`expect` を使わず [`IoErrorCode::Internal`] を返して安全側
    /// （拒否）に倒す（coding-rust「ライブラリコードでは panic させない」）。
    pub(crate) fn from_matched(
        request: InFlightRequest,
        ack_kind: FrameKind,
    ) -> Result<Self, IoError> {
        match (request.kind(), ack_kind) {
            (FrameKind::Write, FrameKind::Ack) => Ok(AckReceipt::Write(WriteAck { request })),
            (FrameKind::Flush, FrameKind::FlushAck) => Ok(AckReceipt::Flush(FlushAck { request })),
            _ => Err(IoError::new(
                IoErrorCode::Internal,
                "in-flight request kind and ack frame kind do not correspond; this must not happen",
            )),
        }
    }

    /// この ACK が対応付けた、送信済みだった元のリクエストを返す
    /// （[`WriteAck::request`] / [`FlushAck::request`] の共通アクセサ。
    /// TASK-12.2 時点の `AckReceipt::request` との互換のため残す）。
    pub fn request(&self) -> InFlightRequest {
        match self {
            AckReceipt::Write(ack) => ack.request(),
            AckReceipt::Flush(ack) => ack.request(),
        }
    }
}

impl TryFrom<AckReceipt> for WriteAck {
    type Error = IoError;

    /// `receipt` が [`AckReceipt::Flush`] であれば
    /// [`IoErrorCode::InvalidArgument`] で拒否する。
    fn try_from(receipt: AckReceipt) -> Result<Self, Self::Error> {
        match receipt {
            AckReceipt::Write(ack) => Ok(ack),
            AckReceipt::Flush(_) => Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "AckReceipt is a Flush ack, not a Write ack",
            )),
        }
    }
}

impl TryFrom<AckReceipt> for FlushAck {
    type Error = IoError;

    /// `receipt` が [`AckReceipt::Write`] であれば
    /// [`IoErrorCode::InvalidArgument`] で拒否する。
    fn try_from(receipt: AckReceipt) -> Result<Self, Self::Error> {
        match receipt {
            AckReceipt::Flush(ack) => Ok(ack),
            AckReceipt::Write(_) => Err(IoError::new(
                IoErrorCode::InvalidArgument,
                "AckReceipt is a Write ack, not a Flush ack",
            )),
        }
    }
}

/// 永続化 helper スレッド（＝実行中の `syncfs`）の同時存在数の絶対上限
/// （プロセス全体）。
///
/// `syncfs(2)` は中断できないため、タイムアウトしたスレッドは detach して
/// 戻るまで残る。D state でハングし続ける場合にスレッドが際限なく増えない
/// ようにする DoS 対策（REPAIR-5・security.md「無制限リソース確保」）。
/// 設定できる同時実行数（[`MaxConcurrentPersist`]）はこの値以下に制限する
/// ため、helper スレッドの数がこの値を超えることはない。
pub(crate) const MAX_PERSIST_THREADS: usize = 64;

/// 同時に実行中の `syncfs` の数の上限（プロセス全体。IO-2・#824 の A4・
/// TASK-15.2.2）。
///
/// `syncfs(2)` はファイルシステム全体を同期するため、接続元が接続を増やして
/// 並行に FLUSH を送っても、同時に走る `syncfs` はこの上限までに留める。
/// 上限に達している FLUSH は、その FLUSH の期限（`AppendFileSink::with_flush_timeout`。
/// REPAIR-5）の範囲内で枠が空くのをブロッキングで待つ。
///
/// # 保証の範囲
/// - 抑えるのは同時実行数だけで、`syncfs` の回数は減らない（各 sink は自分の
///   fd で必ず `syncfs` を発行する。書き戻しエラー〔errseq〕は `struct file`
///   ごとに報告されるため、他の sink の結果を流用すると未報告のエラーを見逃す）
/// - 頻度（間隔）の制限は行わない
///
/// 値は 1 以上 [`MAX_PERSIST_THREADS`]（64）以下。0 は FLUSH が永久に進まない
/// ため、64 超は helper スレッドの絶対上限と矛盾するため拒否する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxConcurrentPersist(usize);

impl MaxConcurrentPersist {
    /// 既定値（2）。
    pub const DEFAULT: Self = Self(2);

    /// 上限値を検証して作る。0 または 64 超は [`IoErrorCode::InvalidArgument`]。
    pub fn new(limit: usize) -> Result<Self, IoError> {
        if (1..=MAX_PERSIST_THREADS).contains(&limit) {
            Ok(Self(limit))
        } else {
            Err(IoError::new(
                IoErrorCode::InvalidArgument,
                format!(
                    "max concurrent persist must be between 1 and {MAX_PERSIST_THREADS} (got {limit})"
                ),
            ))
        }
    }

    /// 上限値。
    pub fn get(self) -> usize {
        self.0
    }
}

impl Default for MaxConcurrentPersist {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// プロセス全体の `syncfs` 同時実行数の上限を変更する（既定は
/// [`MaxConcurrentPersist::DEFAULT`]）。
///
/// 実行中の `syncfs` には影響しない。上限を下げても既に走っているものは
/// 完了まで続き、新しい FLUSH は実行数が新しい上限を下回るまで待つ。上限を
/// 上げると待機中の FLUSH を起こす。
pub fn set_max_concurrent_persist(limit: MaxConcurrentPersist) {
    PERSIST_LIMITER.set_limit(limit);
}

/// 現在のプロセス全体の `syncfs` 同時実行数の上限。
pub fn max_concurrent_persist() -> MaxConcurrentPersist {
    PERSIST_LIMITER.limit()
}

/// 実行中の永続化 helper スレッド（`syncfs`）の数を数え、上限に達していれば
/// 期限まで枠が空くのを待つ計数セマフォ（`Mutex` + `Condvar`。ビジーウェイト
/// しない）。
///
/// 枠（[`PersistSlot`]）は helper スレッドが所有し、`work` が戻るまで保持する。
/// タイムアウトして detach された helper も、中断できない `syncfs` が実際に
/// 走り続けている間は枠を占有し続ける（ハングした `syncfs` の分だけ新しい
/// `syncfs` を起動しないため）。そのため同時実行数と helper スレッドの数は
/// 常に一致し、上限（≤ [`MAX_PERSIST_THREADS`]）を超えてスレッドを作らない。
/// 待機は呼び出し側のスレッドで行い、待機中は helper スレッドを作らない。
pub(crate) struct PersistLimiter {
    running: Mutex<usize>,
    released: Condvar,
    limit: AtomicUsize,
}

impl PersistLimiter {
    /// `limit` を上限とする limiter を作る（`static` 用。単体テストは 0 など
    /// 公開 API で拒否される値も直接与えられる）。
    pub(crate) const fn new(limit: usize) -> Self {
        Self {
            running: Mutex::new(0),
            released: Condvar::new(),
            limit: AtomicUsize::new(limit),
        }
    }

    fn lock(&self) -> MutexGuard<'_, usize> {
        // 保護対象は計数だけで、途中で panic しても不整合な中間状態を
        // 残さない（加減算のみ）ため、poison は無視して続行する。
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn effective_limit(&self) -> usize {
        self.limit.load(Ordering::Acquire).min(MAX_PERSIST_THREADS)
    }

    pub(crate) fn set_limit(&self, limit: MaxConcurrentPersist) {
        self.limit.store(limit.get(), Ordering::Release);
        // 計数のロックを取ってから起こし、待機側の判定と取りこぼしなく同期する。
        let _guard = self.lock();
        self.released.notify_all();
    }

    fn limit(&self) -> MaxConcurrentPersist {
        MaxConcurrentPersist(self.limit.load(Ordering::Acquire))
    }

    /// 現在実行中の数（テスト・観測用）。
    #[cfg(test)]
    pub(crate) fn running(&self) -> usize {
        *self.lock()
    }

    /// 枠を 1 つ確保する。上限に達していれば `deadline` まで待ち、期限を
    /// 過ぎたら [`IoErrorCode::Timeout`]（何も発行していない失敗）。
    ///
    /// コードを `ResourceExhausted` でなく `Timeout` にするのは、失敗の本質が
    /// 「その FLUSH の期限（REPAIR-5）が枠待ちの間に尽きた」ことで、syncfs が
    /// 期限内に終わらない場合と利用者から見て同じ扱い（再接続して再送）になる
    /// ため。また `Timeout` は spec の ERR-3 対応表の `DEADLINE_EXCEEDED` に
    /// 当たる定義済みのコードだが、`ResourceExhausted` は ERR-3 にまだない
    /// 拡張コードである（`crate::error::IoErrorCode` 参照）。
    ///
    /// 期限は空き枠の判定より先に確認する。枠待ちの間に期限が切れた直後に枠が
    /// 空いても、期限切れの FLUSH に枠を渡して `syncfs` を起動しない（REPAIR-5 の
    /// 期限内で枠待ちと実行を打ち切る。Codex #1142 指摘）。
    pub(crate) fn acquire(&'static self, deadline: Instant) -> Result<PersistSlot, IoError> {
        let mut running = self.lock();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(IoError::new(
                    IoErrorCode::Timeout,
                    "timed out waiting for a free syncfs slot (max concurrent persist reached)",
                ));
            }
            if *running < self.effective_limit() {
                *running = running.checked_add(1).ok_or_else(|| {
                    IoError::new(IoErrorCode::Internal, "persist slot counter overflow")
                })?;
                return Ok(PersistSlot { limiter: self });
            }
            running = self
                .released
                .wait_timeout(running, remaining)
                .map(|(guard, _)| guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner().0);
        }
    }
}

/// [`PersistLimiter`] の枠。Drop（helper スレッドで `work` が戻った直後。panic
/// による巻き戻しを含む）で解放し、待機中の FLUSH を起こす。
///
/// helper は `work` の結果を呼び出し側へ送る前に枠を解放する。そのため
/// [`run_with_deadline_tracked`] が `work` の結果（成功・エラー・panic による
/// 切断）を返した時点で、その枠は必ず解放済みである（IO-2・REPAIR-5）。
pub(crate) struct PersistSlot {
    limiter: &'static PersistLimiter,
}

impl Drop for PersistSlot {
    fn drop(&mut self) {
        let mut running = self.limiter.lock();
        *running = running.saturating_sub(1);
        drop(running);
        self.limiter.released.notify_all();
    }
}

static PERSIST_LIMITER: PersistLimiter = PersistLimiter::new(MaxConcurrentPersist::DEFAULT.0);

/// プロセス全体の limiter（`AppendFileSink` の既定。テストは別の limiter を注入する）。
pub(crate) fn default_persist_limiter() -> &'static PersistLimiter {
    &PERSIST_LIMITER
}

/// ブロッキングする `work` を helper スレッドで実行し、`timeout` まで待つ
/// （IO-2・REPAIR-5・TASK-15.2.2）。`work` は 1 回だけ実行し再試行しない。
///
/// タイムアウトした場合 helper スレッドは detach され、`work` が戻るまで
/// `limiter` の枠を占有する。
#[cfg(test)]
fn run_with_deadline<F>(
    limiter: &'static PersistLimiter,
    timeout: IoTimeout,
    work: F,
) -> Result<Duration, IoError>
where
    F: FnOnce() -> Result<(), IoError> + Send + 'static,
{
    let mut dispatched = false;
    run_with_deadline_tracked(limiter, timeout, work, &mut dispatched)
}

/// [`run_with_deadline`] の本体。`timeout` は枠待ちと `work` の実行を合わせた
/// 期限で、枠待ちで期限が尽きたら `work` を実行せず [`IoErrorCode::Timeout`]。
///
/// `work` を helper スレッドへ渡せた時点で `dispatched` を真にする（以後は
/// `work` が実行されうるため、呼び出し側は失敗を「syscall 発行済み」として
/// 扱う）。枠待ちの期限切れ・スレッド生成の失敗では偽のまま返る（何も発行して
/// いない一時的な失敗。Bugbot #1142 指摘）。
///
/// `work` の結果（成功・エラー・panic）を返すときは、その `work` が使った枠は
/// 解放済み（[`PersistSlot`] 参照）。タイムアウトで返るときは detach された
/// helper が `work` が戻るまで枠を保持し続ける。
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    allow(dead_code, reason = "対応 OS の永続化経路と単体テストのみが使う")
)]
fn run_with_deadline_tracked<F>(
    limiter: &'static PersistLimiter,
    timeout: IoTimeout,
    work: F,
    dispatched: &mut bool,
) -> Result<Duration, IoError>
where
    F: FnOnce() -> Result<(), IoError> + Send + 'static,
{
    let started = Instant::now();
    let deadline = started
        .checked_add(timeout.as_duration())
        .ok_or_else(|| IoError::new(IoErrorCode::Internal, "persist deadline overflow"))?;
    let slot = limiter.acquire(deadline)?;
    // 枠を得た時点で期限が尽きていたら、`work` を起動せず未発行で打ち切る
    // （期限切れの FLUSH のために syncfs を走らせない。REPAIR-5）。
    if deadline.saturating_duration_since(Instant::now()).is_zero() {
        drop(slot);
        return Err(IoError::new(
            IoErrorCode::Timeout,
            "persist deadline expired before syncfs could be issued",
        ));
    }
    let (tx, rx) = mpsc::sync_channel::<Result<(), IoError>>(1);
    std::thread::Builder::new()
        .name("fandhe-io-persist".to_owned())
        .stack_size(64 * 1024)
        .spawn(move || {
            // 枠は work が戻る（または panic で巻き戻る）まで保持し、結果を送る
            // 前に解放する。送信後に解放すると、結果を受け取った呼び出し側から
            // 枠がまだ占有中に見え、直後の FLUSH が不要に枠待ちする（計数の観測と
            // 結果の到着が前後する競合）。panic 時もブロック内の `_slot` が
            // クロージャに捕捉された `tx` より先に巻き戻しで破棄されるため、
            // 呼び出し側が切断（Disconnected）を観測した時点で枠は解放済み。
            let result = {
                let _slot = slot;
                work()
            };
            // 受信側がタイムアウトで離脱済みなら送信は失敗するが問題ない。
            let _ = tx.send(result);
        })
        .map_err(|_| {
            IoError::new(
                IoErrorCode::ResourceExhausted,
                "failed to spawn persist thread",
            )
        })?;
    *dispatched = true;
    let remaining = deadline.saturating_duration_since(Instant::now());
    match rx.recv_timeout(remaining) {
        Ok(Ok(())) => Ok(started.elapsed()),
        Ok(Err(err)) => Err(err),
        Err(RecvTimeoutError::Timeout) => Err(IoError::new(
            IoErrorCode::Timeout,
            "persist did not complete before the timeout",
        )),
        Err(RecvTimeoutError::Disconnected) => Err(IoError::new(
            IoErrorCode::Internal,
            "persist thread terminated unexpectedly",
        )),
    }
}

/// [`persist_file_system`] の失敗。`issued` は `syncfs` を発行した（または
/// helper スレッドが発行しうる）かを表す。偽なら errseq は消費されておらず、
/// 呼び出し側の sink は poison せず再試行できる（IO-2）。
#[derive(Debug)]
pub(crate) struct PersistFailure {
    pub(crate) error: IoError,
    pub(crate) issued: bool,
}

impl PersistFailure {
    /// syscall 発行前の失敗（カーネル版数拒否・fd 複製・枠確保・スレッド生成）。
    fn not_issued(error: IoError) -> Self {
        Self {
            error,
            issued: false,
        }
    }
}

/// 実行環境が FLUSH の永続化（FlushAck の返却）に対応しているかの判定結果
/// （IO-2・IO-3・TASK-15.2.2・#824）。
///
/// サーバー側の [`crate::writeback::AppendFileSink`] は [`persist_support`] が
/// [`PersistSupport::Supported`] 以外を返す環境では `persist` を
/// [`IoErrorCode::Unimplemented`] で拒否し、FlushAck を返さない（fail-closed）。
/// 利用者・結合試験はこの判定で「FlushAck が返る環境か」を production と同じ
/// 基準で知る（判定を 2 か所に持たないため）。非対応の理由を区別できるよう
/// 列挙型で返す（値を足せるよう `#[non_exhaustive]`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PersistSupport {
    /// Linux 5.8 以上。`syncfs(2)` が書き戻しエラーを報告するため、永続化の
    /// 成否を確認してから FlushAck を返せる。
    Supported,
    /// Linux 5.8 未満、またはカーネル版数を判定できない。`syncfs(2)` が書き戻し
    /// 失敗を隠して 0 を返しうるため拒否する（ディストロのバックポートも安全側で拒否）。
    KernelTooOld,
    /// Linux・macOS・Windows 以外の OS。代替フラッシュが未実装。
    UnsupportedOs,
    /// macOS / Windows（TASK-15.3・#88）。sink が持つファイルを明示的な syscall
    /// （macOS は `F_FULLFSYNC`、Windows は `FlushFileBuffers`）で永続化して
    /// から FlushAck を返す。
    ///
    /// 保証範囲は sink のファイル自体（データ＋ファイルメタデータ）と、sink が
    /// ファイルを開いた・作ったディレクトリのエントリ（新設した祖先を含む）。
    /// 親ディレクトリのハンドルを持たない sink は拒否する（新規作成ファイルの名前が
    /// 電源断で失われうるため）。`F_FULLFSYNC` 非対応の FS（一部のネットワーク FS 等）
    /// では `fsync` へフォールバックせず失敗し、FlushAck を返さない（`fsync` は
    /// ドライブのキャッシュを書き出さず IO-2 の保証を満たさないため）。
    SupportedFileSync,
}

impl PersistSupport {
    /// FlushAck を返せる（永続化に対応する）環境か。
    pub fn is_supported(self) -> bool {
        matches!(self, Self::Supported | Self::SupportedFileSync)
    }
}

/// 実行中の環境が FLUSH の永続化に対応しているかを返す（IO-2・TASK-15.2.2）。
///
/// Linux では `/proc/sys/kernel/osrelease` を読み、5.8 以上なら
/// [`PersistSupport::Supported`]、5.8 未満・読み取り失敗・解釈不能なら
/// [`PersistSupport::KernelTooOld`]（fail-closed）。結果はプロセス内で 1 回だけ
/// 判定してキャッシュする。macOS / Windows は [`PersistSupport::SupportedFileSync`]、
/// それ以外の OS は [`PersistSupport::UnsupportedOs`]。
pub fn persist_support() -> PersistSupport {
    #[cfg(target_os = "linux")]
    {
        use std::sync::OnceLock;
        static SUPPORT: OnceLock<PersistSupport> = OnceLock::new();
        *SUPPORT.get_or_init(|| {
            let supported = std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .map(|r| release_supports_syncfs_errors(&r))
                .unwrap_or(false);
            if supported {
                PersistSupport::Supported
            } else {
                PersistSupport::KernelTooOld
            }
        })
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        PersistSupport::SupportedFileSync
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        PersistSupport::UnsupportedOs
    }
}

/// `file` が属するファイルシステムを永続化し、所要時間を返す（IO-2・
/// TASK-15.2.2・#824）。
///
/// [`crate::writeback::AppendFileSink`] の `persist` から、実行環境の判定
/// （[`persist_support`]）を渡して呼ばれる。[`PersistSupport::Supported`]（Linux）なら
/// `file` を dup した fd に対し `crate::sys::syncfs` を helper スレッドで 1 回
/// だけ実行する。[`PersistSupport::SupportedFileSync`]（macOS / Windows）なら
/// dup したハンドルに `F_FULLFSYNC` / `FlushFileBuffers` を同じく helper スレッドで
/// 1 回だけ実行する。
/// 判定と実行 OS が食い違う値（Linux 上の `SupportedFileSync` 等）が注入された
/// 場合も syscall を発行せず拒否する。失敗しても再試行しない（errseq は 1 回しか報告しないため。
/// 呼び出し側の sink がポイズンする）。それ以外は syscall を発行せず
/// [`IoErrorCode::Unimplemented`]（`issued == false`。sink はポイズンしない）。
///
/// `syncfs` の同時実行数は `limiter`（既定はプロセス全体の
/// [`default_persist_limiter`]。上限は [`set_max_concurrent_persist`]）で抑え、
/// 上限に達していれば `timeout` の範囲内で枠を待つ。期限切れは
/// [`IoErrorCode::Timeout`]（`issued == false`）。枠を得ても `syncfs` は必ず
/// 呼び出し元の `file` の fd で発行し、他の sink の結果を流用しない（errseq は
/// `struct file` ごとに報告されるため）。
///
/// 判定・limiter を引数で受けるのは、5.8 以上のホストでも非対応経路（旧カーネル・
/// 非 Linux）や枠待ちの期限切れを単体テストで決定的に照合するため。
pub(crate) fn persist_file_system(
    support: PersistSupport,
    limiter: &'static PersistLimiter,
    file: &File,
    dirs: &[File],
    timeout: IoTimeout,
) -> Result<Duration, PersistFailure> {
    match support {
        PersistSupport::Supported => {
            #[cfg(target_os = "linux")]
            {
                // syncfs は FS 全体（ディレクトリエントリを含む）を同期するため
                // `dirs` は使わない。
                let _ = dirs;
                sync_file_system(limiter, file, timeout)
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(mismatched_support())
            }
        }
        PersistSupport::SupportedFileSync => {
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            {
                sync_file_system(limiter, file, dirs, timeout)
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            {
                Err(mismatched_support())
            }
        }
        PersistSupport::KernelTooOld => Err(PersistFailure::not_issued(IoError::new(
            IoErrorCode::Unimplemented,
            "kernel older than 5.8 (or unknown) cannot report syncfs write-back errors; refusing to send FlushAck",
        ))),
        PersistSupport::UnsupportedOs => Err(PersistFailure::not_issued(IoError::new(
            IoErrorCode::Unimplemented,
            "persist is not implemented on this OS",
        ))),
    }
}

/// 判定値が実行 OS と食い違う（他 OS 用の値が注入された）場合の拒否。syscall は
/// 発行しない（`issued == false`）。
fn mismatched_support() -> PersistFailure {
    PersistFailure::not_issued(IoError::new(
        IoErrorCode::Unimplemented,
        "persist support does not match this OS; refusing to send FlushAck",
    ))
}

/// Linux の永続化本体: dup した fd に `syncfs(2)` をタイムアウト付きで 1 回だけ
/// 発行する（REPAIR-5）。fd 複製の失敗は発行前（`issued == false`）。
#[cfg(target_os = "linux")]
fn sync_file_system(
    limiter: &'static PersistLimiter,
    file: &File,
    timeout: IoTimeout,
) -> Result<Duration, PersistFailure> {
    let dup = file.try_clone().map_err(|err| {
        PersistFailure::not_issued(IoError::new(
            IoErrorCode::Internal,
            format!("failed to duplicate fd for persist ({:?})", err.kind()),
        ))
    })?;
    let mut dispatched = false;
    run_with_deadline_tracked(
        limiter,
        timeout,
        move || crate::sys::syncfs(&dup),
        &mut dispatched,
    )
    .map_err(|error| PersistFailure {
        error,
        issued: dispatched,
    })
}

/// macOS / Windows の永続化本体（TASK-15.3・#88）: dup したハンドルに
/// [`sync_file`] を helper スレッドで 1 回だけ発行する（REPAIR-5）。limiter・
/// タイムアウト・発行後失敗の扱いは Linux 版と同一。発行後の失敗は sink が
/// ポイズンする（fsync 系の失敗後はページが clean 扱いになりうるため、再試行の
/// 成功は永続化を意味しない）。ハンドル複製の失敗は発行前（`issued == false`）。
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn sync_file_system(
    limiter: &'static PersistLimiter,
    file: &File,
    dirs: &[File],
    timeout: IoTimeout,
) -> Result<Duration, PersistFailure> {
    // 作成時に保持したハンドルを複製して同期する（パスを再解決しない）。
    let dirs = dirs
        .iter()
        .map(File::try_clone)
        .collect::<Result<Vec<File>, _>>()
        .map_err(|err| {
            PersistFailure::not_issued(IoError::new(
                IoErrorCode::Internal,
                format!("failed to duplicate directory handle ({:?})", err.kind()),
            ))
        })?;
    let dup = file.try_clone().map_err(|err| {
        PersistFailure::not_issued(IoError::new(
            IoErrorCode::Internal,
            format!("failed to duplicate handle for persist ({:?})", err.kind()),
        ))
    })?;
    let mut dispatched = false;
    run_with_deadline_tracked(
        limiter,
        timeout,
        move || {
            sync_file(&dup)?;
            // 新規作成ファイルのディレクトリエントリはファイル自体の sync では
            // 永続化されないため、呼び出し側が渡した親ディレクトリも同期する。
            // 1 つでも失敗すれば FlushAck を返さない（fail-closed）。
            dirs.iter().try_for_each(sync_dir)
        },
        &mut dispatched,
    )
    .map_err(|error| PersistFailure {
        error,
        issued: dispatched,
    })
}

/// ディレクトリのハンドルを同期し、そのエントリ（新規作成ファイルの名前等）を
/// 永続化する（TASK-15.3・#88。[`sync_handle`]）。Windows の `FlushFileBuffers` は
/// 書き込みアクセスが必要なため、sink へハンドルを渡す `AppendFileSink::open_in`・
/// `GuestFileCreator` は書き込み可能なハンドルで開く。エラーには `ErrorKind` のみを
/// 含め、パスは含めない。
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn sync_dir(handle: &File) -> Result<(), IoError> {
    sync_handle(handle).map_err(|err| {
        IoError::new(
            IoErrorCode::Internal,
            format!("directory sync failed ({:?})", err.kind()),
        )
    })
}

/// ファイルのデータとメタデータを永続化する（TASK-15.3・#88。[`sync_handle`]）。
/// エラーには `ErrorKind` のみを含め、パスや内容は含めない。
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn sync_file(file: &File) -> Result<(), IoError> {
    sync_handle(file).map_err(|err| {
        IoError::new(
            IoErrorCode::Internal,
            format!("file sync failed ({:?})", err.kind()),
        )
    })
}

/// OS ごとの永続化の syscall を明示的に発行する（std の `File::sync_all` の実装に
/// 依存しない。Codex #1146 P0）。macOS は `fcntl(F_FULLFSYNC)`（[`crate::sys::full_fsync`]。
/// 非対応の FS では `fsync` へフォールバックせず失敗する）、Windows は
/// `FlushFileBuffers`（`crate::sys_windows::flush_file_buffers`）。
#[cfg(target_os = "macos")]
fn sync_handle(handle: &File) -> std::io::Result<()> {
    crate::sys::full_fsync(handle)
}

#[cfg(target_os = "windows")]
fn sync_handle(handle: &File) -> std::io::Result<()> {
    crate::sys_windows::flush_file_buffers(handle)
}

/// `syncfs(2)` が書き戻し失敗を報告するカーネルの最小版数（major, minor）。
/// 5.8 未満は `EBADF` 以外を報告せず、失敗を隠したまま 0 を返しうる（IO-2・IO-3）。
#[cfg(any(target_os = "linux", test))]
const MIN_SYNCFS_ERROR_REPORTING: (u32, u32) = (5, 8);

/// カーネル release 文字列（例 `6.8.0-45-generic`）から `(major, minor)` を取り出す。
/// 解釈できなければ `None`（呼び出し側は fail-closed で拒否する）。
#[cfg(any(target_os = "linux", test))]
fn parse_kernel_release(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor_raw = parts.next()?;
    let digits: String = minor_raw.chars().take_while(char::is_ascii_digit).collect();
    let minor = digits.parse::<u32>().ok()?;
    Some((major, minor))
}

/// release 文字列が `syncfs` の書き戻しエラー報告に対応する版数か判定する。
#[cfg(any(target_os = "linux", test))]
fn release_supports_syncfs_errors(release: &str) -> bool {
    parse_kernel_release(release).is_some_and(|v| v >= MIN_SYNCFS_ERROR_REPORTING)
}

/// バッチ write-back 経路で「受理したが FLUSH バリアで永続化されていない」
/// 滞留量のカウンタ（IO-10・TASK-16.1・#90）。
///
/// [`crate::writeback::serve_connection`] が `Write` を 1 件受理するたびに加算し、
/// `Flush` の [`crate::writeback::BatchSink::persist`] が成功した時点で 0 に戻す。
/// バッチを書き込み通常 ACK（IO-1）を返した後も「未フラッシュ」に残る点が
/// [`crate::batch::BatchBuffer`] の滞留量（バッチ未形成分のみ。payload バイトで数える）と
/// 異なる。バイト数は body バイト（[`crate::writeback::WritebackStats::bytes_written`]
/// と同じ単位）。更新は crate 内専用で、crate 外は getter で読むだけとする
/// （値の偽装による上限判定のすり抜けを防ぐ）。
///
/// 未実装（REPAIR-3）: 上限との比較と到達時の自動フラッシュは TASK-16.2・#91 で
/// 実装予定（IO-10）。本型は計測のみを担う。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct UnflushedBacklog {
    frames: u64,
    bytes: u64,
}

impl UnflushedBacklog {
    /// 未フラッシュの `Write` 件数。
    pub fn frames(&self) -> u64 {
        self.frames
    }

    /// 未フラッシュの body 合計バイト数。
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// `Write` を 1 件受理した分を加算する（飽和加算。過小報告しない）。
    pub(crate) fn record_write(&mut self, body_len: usize) {
        self.frames = self.frames.saturating_add(1);
        let len = u64::try_from(body_len).unwrap_or(u64::MAX);
        self.bytes = self.bytes.saturating_add(len);
    }

    /// FLUSH バリア成功（永続化完了）で 0 に戻す。
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{InFlightLimit, SendQueue};

    fn ms(n: u64) -> IoTimeout {
        IoTimeout::new(Duration::from_millis(n)).expect("valid timeout")
    }

    /// IO-10・TASK-16.1: 初期値は 0 件・0 バイト。
    #[test]
    fn io10_unflushed_backlog_starts_empty() {
        let b = UnflushedBacklog::default();
        assert_eq!((b.frames(), b.bytes()), (0, 0));
    }

    /// IO-10・TASK-16.1: 書き込みごとに件数と body バイトが増える。
    #[test]
    fn io10_unflushed_backlog_counts_each_write() {
        let mut b = UnflushedBacklog::default();
        b.record_write(1);
        b.record_write(2);
        b.record_write(0);
        assert_eq!((b.frames(), b.bytes()), (3, 3));
    }

    /// IO-10・TASK-16.1: reset で 0 に戻り、以後また加算できる。
    #[test]
    fn io10_unflushed_backlog_reset_clears_counts() {
        let mut b = UnflushedBacklog::default();
        b.record_write(4);
        b.reset();
        assert_eq!((b.frames(), b.bytes()), (0, 0));
        b.record_write(5);
        assert_eq!((b.frames(), b.bytes()), (1, 5));
    }

    /// IO-10・TASK-16.1: 飽和し panic しない。
    #[test]
    fn io10_unflushed_backlog_saturates() {
        let mut b = UnflushedBacklog {
            frames: u64::MAX,
            bytes: u64::MAX - 1,
        };
        b.record_write(10);
        assert_eq!((b.frames(), b.bytes()), (u64::MAX, u64::MAX));
    }

    /// IO-2・TASK-15.2.2: 即座に成功する処理は `Ok` で経過時間が返る。
    #[test]
    fn io2_run_with_deadline_returns_ok_for_fast_work() {
        static L: PersistLimiter = PersistLimiter::new(4);
        assert!(run_with_deadline(&L, ms(2000), || Ok(())).is_ok());
    }

    /// REPAIR-5・TASK-15.2.2: タイムアウトより長い処理は `Timeout` になり、
    /// 待ちはタイムアウト程度で打ち切られる。
    #[test]
    fn repair5_run_with_deadline_times_out() {
        static L: PersistLimiter = PersistLimiter::new(4);
        let started = Instant::now();
        let err = run_with_deadline(&L, ms(50), || {
            std::thread::sleep(Duration::from_millis(600));
            Ok(())
        })
        .expect_err("must time out");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    /// REPAIR-5・IO-2（#824 A4）: 枠を占有中の FLUSH は期限まで待ち、期限を
    /// 過ぎたら `work` を実行せず `Timeout`（未発行）。タイムアウトして detach
    /// された helper は `work` が戻るまで枠を占有し続け、戻ったら解放する。
    #[test]
    fn repair5_persist_limiter_waits_then_times_out_without_running() {
        static L: PersistLimiter = PersistLimiter::new(1);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let err = run_with_deadline(&L, ms(30), move || {
            let _ = release_rx.recv();
            Ok(())
        })
        .expect_err("must time out while blocked");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        // タイムアウト後も helper は work 実行中のため枠を占有し続ける。
        assert_eq!(L.running(), 1);

        let ran = std::sync::Arc::new(AtomicUsize::new(0));
        let ran_in_work = std::sync::Arc::clone(&ran);
        let mut dispatched = false;
        let started = Instant::now();
        let busy = run_with_deadline_tracked(
            &L,
            ms(150),
            move || {
                ran_in_work.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            &mut dispatched,
        )
        .expect_err("limit reached until the deadline");
        assert_eq!(busy.code(), IoErrorCode::Timeout);
        assert!(busy.message().contains("syncfs slot"), "{}", busy.message());
        assert!(!dispatched);
        // 期限いっぱいまで待ってから諦める（即時拒否ではない）。
        assert!(started.elapsed() >= Duration::from_millis(140));
        assert_eq!(ran.load(Ordering::SeqCst), 0);

        release_tx.send(()).expect("helper still waiting");
        // helper が戻れば枠が解放され、次の FLUSH は待たずに成功する。
        run_with_deadline(&L, ms(2000), || Ok(())).expect("slot must be released");
        assert_eq!(L.running(), 0);
    }

    /// IO-2（#824 A4）: 枠が埋まっていても、期限内に空けば待っていた FLUSH は
    /// 成功する（Condvar による起床。ビジーウェイトしない）。
    #[test]
    fn io2_persist_limiter_waiter_succeeds_when_slot_frees_in_time() {
        static L: PersistLimiter = PersistLimiter::new(1);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (started_tx, started_rx) = mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            run_with_deadline(&L, ms(5000), move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                Ok(())
            })
        });
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("holder must start its work");
        assert_eq!(L.running(), 1);

        static RELEASED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            RELEASED.store(true, Ordering::SeqCst);
            release_tx.send(()).expect("holder still waiting");
        });
        // 待機側の work は、holder が枠を手放した後にしか実行されない。
        run_with_deadline(&L, ms(5000), || {
            assert!(
                RELEASED.load(Ordering::SeqCst),
                "waiter ran before the slot was freed"
            );
            Ok(())
        })
        .expect("waiter must get the freed slot");
        releaser.join().expect("releaser must not panic");
        holder
            .join()
            .expect("holder must not panic")
            .expect("holder work must succeed");
        assert_eq!(L.running(), 0);
    }

    /// IO-2（#824 A4）: 多数の FLUSH を並行に出しても、同時に実行される work は
    /// 上限（2）を超えない。全件が期限内に成功する。
    #[test]
    fn io2_persist_limiter_never_exceeds_limit() {
        static L: PersistLimiter = PersistLimiter::new(2);
        static CURRENT: AtomicUsize = AtomicUsize::new(0);
        static PEAK: AtomicUsize = AtomicUsize::new(0);
        let handles: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    run_with_deadline(&L, ms(10_000), || {
                        let now = CURRENT.fetch_add(1, Ordering::SeqCst) + 1;
                        PEAK.fetch_max(now, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(30));
                        CURRENT.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                })
            })
            .collect();
        for handle in handles {
            handle
                .join()
                .expect("worker must not panic")
                .expect("every flush must succeed within its deadline");
        }
        let peak = PEAK.load(Ordering::SeqCst);
        assert!(peak <= 2, "observed {peak} concurrent persists");
        assert!(peak >= 1);
        assert_eq!(L.running(), 0);
    }

    /// IO-2（#824 A4）: 上限を上げると、待機中の FLUSH が起こされて進む。
    #[test]
    fn io2_persist_limiter_raising_limit_wakes_waiter() {
        static L: PersistLimiter = PersistLimiter::new(1);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (started_tx, started_rx) = mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            run_with_deadline(&L, ms(5000), move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                Ok(())
            })
        });
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("holder must start its work");
        let raiser = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(50));
            L.set_limit(MaxConcurrentPersist::new(2).expect("valid limit"));
        });
        run_with_deadline(&L, ms(5000), || Ok(())).expect("raised limit must admit the waiter");
        raiser.join().expect("raiser must not panic");
        release_tx.send(()).expect("holder still waiting");
        holder
            .join()
            .expect("holder must not panic")
            .expect("holder work must succeed");
    }

    /// IO-2（#824 A4）: work が panic しても枠は巻き戻しで解放される。
    #[test]
    fn io2_persist_limiter_releases_slot_on_panic() {
        static L: PersistLimiter = PersistLimiter::new(1);
        let err = run_with_deadline(&L, ms(2000), || panic!("injected panic in persist work"))
            .expect_err("panicking work must fail");
        assert_eq!(err.code(), IoErrorCode::Internal);
        run_with_deadline(&L, ms(2000), || Ok(())).expect("slot must be released after panic");
        assert_eq!(L.running(), 0);
    }

    /// IO-2・REPAIR-5: `work` の結果（成功・エラー・panic）が返った時点で枠は
    /// 解放済み。helper が結果を送った後に枠を解放すると、負荷時に呼び出し側が
    /// 占有中の枠を観測する（main CI の `io2_persist_limiter_*` 断続失敗）。
    /// 競合の窓を踏みやすいよう各経路を繰り返し、毎回直後に計数を照合する。
    #[test]
    fn io2_persist_slot_released_before_result_is_returned() {
        static L: PersistLimiter = PersistLimiter::new(1);
        for round in 0..200 {
            run_with_deadline(&L, ms(2000), || Ok(())).expect("fast work must succeed");
            assert_eq!(L.running(), 0, "after Ok (round {round})");

            let err = run_with_deadline(&L, ms(2000), || {
                Err(IoError::new(IoErrorCode::Internal, "injected"))
            })
            .expect_err("error must propagate");
            assert_eq!(err.code(), IoErrorCode::Internal);
            assert_eq!(L.running(), 0, "after Err (round {round})");
        }
        for round in 0..20 {
            let err = run_with_deadline(&L, ms(2000), || panic!("injected panic in persist work"))
                .expect_err("panicking work must fail");
            assert_eq!(err.code(), IoErrorCode::Internal);
            assert_eq!(L.running(), 0, "after panic (round {round})");
        }
    }

    /// REPAIR-5（Codex #1142 指摘）: 期限を過ぎた後は、枠が空いていても枠を
    /// 渡さない（期限切れの FLUSH のために syncfs を起動しない）。
    #[test]
    fn repair5_persist_limiter_rejects_expired_deadline_even_with_free_slot() {
        static L: PersistLimiter = PersistLimiter::new(1);
        let expired = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        let err = L
            .acquire(expired)
            .err()
            .expect("an expired deadline must not get a slot");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert_eq!(L.running(), 0);
        // 期限内なら同じ空き枠を得られる。
        let slot = L
            .acquire(Instant::now() + Duration::from_secs(1))
            .expect("free slot within the deadline");
        assert_eq!(L.running(), 1);
        drop(slot);
        assert_eq!(L.running(), 0);
    }

    /// IO-2（#824 A4）: 上限値は 1 以上 64 以下だけを受け付け、既定値は 2。
    #[test]
    fn io2_max_concurrent_persist_validates_range() {
        for bad in [0usize, MAX_PERSIST_THREADS + 1, usize::MAX] {
            let err = MaxConcurrentPersist::new(bad).expect_err("out of range must be rejected");
            assert_eq!(err.code(), IoErrorCode::InvalidArgument, "{bad}");
        }
        assert_eq!(MaxConcurrentPersist::new(1).expect("1 is valid").get(), 1);
        assert_eq!(
            MaxConcurrentPersist::new(MAX_PERSIST_THREADS)
                .expect("64 is valid")
                .get(),
            64
        );
        assert_eq!(MaxConcurrentPersist::DEFAULT.get(), 2);
        assert_eq!(
            MaxConcurrentPersist::default(),
            MaxConcurrentPersist::DEFAULT
        );
        // プロセス全体の既定値（他のテストは変更しないため既定のまま）。
        set_max_concurrent_persist(MaxConcurrentPersist::DEFAULT);
        assert_eq!(max_concurrent_persist(), MaxConcurrentPersist::DEFAULT);
    }

    /// 内部で上限を 64 超に設定されても、helper スレッドの絶対上限を超えない。
    #[test]
    fn repair5_persist_limiter_clamps_to_thread_cap() {
        static L: PersistLimiter = PersistLimiter::new(usize::MAX);
        assert_eq!(L.effective_limit(), MAX_PERSIST_THREADS);
    }

    /// IO-2・TASK-15.2.2: 処理のエラーはそのまま伝播する。
    #[test]
    fn io2_run_with_deadline_propagates_error() {
        static L: PersistLimiter = PersistLimiter::new(4);
        let err = run_with_deadline(&L, ms(2000), || {
            Err(IoError::new(IoErrorCode::Internal, "injected"))
        })
        .expect_err("must propagate");
        assert_eq!(err.code(), IoErrorCode::Internal);
    }

    /// IO-2・IO-3: 5.8 未満・解釈不能な release は拒否し、5.8 以上は許可する。
    #[test]
    fn io2_kernel_release_gate_rejects_pre_5_8() {
        assert!(!release_supports_syncfs_errors("5.7.19"));
        assert!(!release_supports_syncfs_errors("4.18.0-553.el8.x86_64"));
        assert!(!release_supports_syncfs_errors(""));
        assert!(!release_supports_syncfs_errors("garbage"));
        assert!(release_supports_syncfs_errors("5.8.0"));
        assert!(release_supports_syncfs_errors("5.10.0-rc1\n"));
        assert!(release_supports_syncfs_errors("6.8.0-45-generic"));
        assert!(!release_supports_syncfs_errors("5.x"));
    }

    /// IO-2・TASK-15.2.2・TASK-15.3: 対応環境（Linux 5.8 以上・macOS・Windows）では
    /// 実ファイルへの persist が成功する。
    #[test]
    fn io2_persist_file_system_ok_when_supported() {
        let file = tempfile_in_target();
        // syncfs はファイルシステム全体を同期するため、並列テストや共有 runner の
        // 書き込み負荷で数秒かかりうる。許容上限（MAX_IO_TIMEOUT）まで待ち、
        // 失敗時は原因（Timeout / ResourceExhausted 等）を出力して診断可能にする。
        let support = persist_support();
        let result = persist_file_system(
            support,
            default_persist_limiter(),
            &file,
            &[],
            IoTimeout::new(crate::MAX_IO_TIMEOUT).expect("valid timeout"),
        );
        // 版数依存を避け、production と同じ判定（`persist_support`）に応じた期待値で
        // 照合する（5.8 未満は fail-closed の `Unimplemented`。非対応経路は
        // `io2_persist_file_system_rejects_unsupported_without_issuing` でも固定）。
        match support {
            PersistSupport::Supported => {
                assert!(result.is_ok(), "persist_file_system failed: {result:?}");
            }
            PersistSupport::SupportedFileSync => {
                assert!(result.is_ok(), "persist_file_system failed: {result:?}");
            }
            other => {
                assert!(
                    matches!(
                        other,
                        PersistSupport::KernelTooOld | PersistSupport::UnsupportedOs
                    ),
                    "{other:?}"
                );
                let failure = result.expect_err("pre-5.8 kernel must be rejected");
                assert_eq!(failure.error.code(), IoErrorCode::Unimplemented);
                assert!(!failure.issued);
            }
        }
    }

    /// IO-2・IO-3・TASK-15.3: `persist_support` は Linux では
    /// `/proc/sys/kernel/osrelease` の版数ゲートと一致し、macOS / Windows では
    /// `SupportedFileSync`、それ以外では `UnsupportedOs` を返す。
    #[test]
    fn io2_persist_support_matches_platform_gate() {
        let support = persist_support();
        #[cfg(target_os = "linux")]
        {
            let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
            let expected = if release_supports_syncfs_errors(&release) {
                PersistSupport::Supported
            } else {
                PersistSupport::KernelTooOld
            };
            assert_eq!(support, expected, "release = {release:?}");
        }
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        assert_eq!(support, PersistSupport::SupportedFileSync);
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        assert_eq!(support, PersistSupport::UnsupportedOs);
        assert_eq!(
            support.is_supported(),
            matches!(
                support,
                PersistSupport::Supported | PersistSupport::SupportedFileSync
            )
        );
    }

    /// IO-2・IO-3（Codex #1142 指摘）: 非対応の判定（旧カーネル・非 Linux）を
    /// 注入すると、実行ホストのカーネル版数に関係なく syscall を発行せず
    /// `Unimplemented`（`issued == false`）で拒否する。
    #[test]
    fn io2_persist_file_system_rejects_unsupported_without_issuing() {
        let path = std::env::temp_dir().join(format!(
            "fandhe-io-persist-unsupported-{}",
            std::process::id()
        ));
        let file = File::create(&path).expect("create temp file");
        let _ = std::fs::remove_file(&path);
        // 実行 OS と食い違う対応値（他 OS 用）も syscall を発行せず拒否する。
        #[cfg(target_os = "linux")]
        let mismatched = PersistSupport::SupportedFileSync;
        #[cfg(not(target_os = "linux"))]
        let mismatched = PersistSupport::Supported;
        for support in [
            PersistSupport::KernelTooOld,
            PersistSupport::UnsupportedOs,
            mismatched,
        ] {
            let failure =
                persist_file_system(support, default_persist_limiter(), &file, &[], ms(100))
                    .expect_err("must be rejected");
            assert_eq!(
                failure.error.code(),
                IoErrorCode::Unimplemented,
                "{support:?}"
            );
            assert!(!failure.issued, "{support:?}");
        }
    }

    fn tempfile_in_target() -> File {
        let path = std::env::temp_dir().join(format!(
            "fandhe-io-persist-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = File::create(&path).expect("create temp file");
        let _ = std::fs::remove_file(&path);
        file
    }

    /// IO-2（Bugbot #1142）: 枠が空かず期限を過ぎた失敗は「未発行」
    /// （dispatched = false）で、sink を poison させない。
    #[test]
    fn io2_run_with_deadline_not_dispatched_when_limit_reached() {
        static L: PersistLimiter = PersistLimiter::new(0);
        let mut dispatched = false;
        let err = run_with_deadline_tracked(&L, ms(50), || Ok(()), &mut dispatched)
            .expect_err("no slot available");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(!dispatched);
    }

    /// IO-2: タイムアウトは helper が syscall を発行しうるため dispatched = true。
    #[test]
    fn io2_run_with_deadline_dispatched_on_timeout() {
        static L: PersistLimiter = PersistLimiter::new(1);
        let mut dispatched = false;
        let err = run_with_deadline_tracked(
            &L,
            ms(30),
            || {
                std::thread::sleep(Duration::from_millis(300));
                Ok(())
            },
            &mut dispatched,
        )
        .expect_err("must time out");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert!(dispatched);
    }

    /// IO-2・TASK-15.3: Linux・macOS・Windows 以外では `Unimplemented`。
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    #[test]
    fn io2_persist_file_system_unimplemented_on_other_os() {
        let path = std::env::temp_dir().join(format!("fandhe-io-persist-{}", std::process::id()));
        let file = File::create(&path).expect("create temp file");
        let _ = std::fs::remove_file(&path);
        assert_eq!(persist_support(), PersistSupport::UnsupportedOs);
        let failure = persist_file_system(
            persist_support(),
            default_persist_limiter(),
            &file,
            &[],
            ms(100),
        )
        .expect_err("must be unimplemented");
        assert!(!failure.issued);
        assert_eq!(failure.error.code(), IoErrorCode::Unimplemented);
    }

    /// IO-2・TASK-15.3: Windows の `FlushFileBuffers` は書き込みアクセスが必須のため、
    /// 読み取り専用ハンドルへの persist は発行後の失敗（`issued == true`。sink は
    /// ポイズン対象）になり、成功を偽装しない（fail-closed）。
    #[cfg(target_os = "windows")]
    #[test]
    fn io2_persist_file_system_read_only_handle_fails_issued_on_windows() {
        let path =
            std::env::temp_dir().join(format!("fandhe-io-persist-ro-{}", std::process::id()));
        File::create(&path).expect("create temp file");
        let file = File::open(&path).expect("open read-only");
        let failure = persist_file_system(
            PersistSupport::SupportedFileSync,
            default_persist_limiter(),
            &file,
            &[],
            IoTimeout::new(crate::MAX_IO_TIMEOUT).expect("valid timeout"),
        )
        .expect_err("read-only handle must fail");
        assert!(failure.issued);
        assert_eq!(failure.error.code(), IoErrorCode::Internal);
        drop(file);
        let _ = std::fs::remove_file(&path);
    }

    /// テスト専用: 指定した種別の [`InFlightRequest`] を、公開 API
    /// （[`SendQueue::register`]）経由で作る。
    fn make_request(kind: FrameKind) -> InFlightRequest {
        let limit = InFlightLimit::new(1).expect("1 must be a valid limit");
        let mut queue = SendQueue::new(limit);
        queue.register(kind).expect("register must succeed")
    }

    /// IO-1・TASK-15.1: `(Write, Ack)` の組み合わせは `AckReceipt::Write` になる。
    #[test]
    fn io1_from_matched_write_ack_yields_write_variant() {
        let request = make_request(FrameKind::Write);
        let receipt =
            AckReceipt::from_matched(request, FrameKind::Ack).expect("must accept (Write, Ack)");
        match receipt {
            AckReceipt::Write(ack) => assert_eq!(ack.request().id().get(), request.id().get()),
            AckReceipt::Flush(_) => panic!("expected Write variant"),
        }
    }

    /// IO-2・TASK-15.1: `(Flush, FlushAck)` の組み合わせは `AckReceipt::Flush` になる。
    #[test]
    fn io2_from_matched_flush_ack_yields_flush_variant() {
        let request = make_request(FrameKind::Flush);
        let receipt = AckReceipt::from_matched(request, FrameKind::FlushAck)
            .expect("must accept (Flush, FlushAck)");
        match receipt {
            AckReceipt::Flush(ack) => assert_eq!(ack.request().id().get(), request.id().get()),
            AckReceipt::Write(_) => panic!("expected Flush variant"),
        }
    }

    /// IO-1・IO-2・TASK-15.1: 種別が対応しない組み合わせは `Internal` で拒否する。
    #[test]
    fn io2_from_matched_rejects_mismatched_kind_combinations() {
        let write_request = make_request(FrameKind::Write);
        let err = AckReceipt::from_matched(write_request, FrameKind::FlushAck)
            .expect_err("(Write, FlushAck) must be rejected");
        assert_eq!(err.code(), IoErrorCode::Internal);

        let flush_request = make_request(FrameKind::Flush);
        let err = AckReceipt::from_matched(flush_request, FrameKind::Ack)
            .expect_err("(Flush, Ack) must be rejected");
        assert_eq!(err.code(), IoErrorCode::Internal);
    }

    /// IO-2・TASK-15.1: `FlushBarrier::try_from` は `Flush` のみ受理し、
    /// `Write` は `InvalidArgument` で拒否する。
    #[test]
    fn io2_flush_barrier_try_from_accepts_flush_rejects_write() {
        let flush_request = make_request(FrameKind::Flush);
        let barrier =
            FlushBarrier::try_from(flush_request).expect("Flush request must be accepted");
        assert_eq!(barrier.id().get(), flush_request.id().get());

        let write_request = make_request(FrameKind::Write);
        let err =
            FlushBarrier::try_from(write_request).expect_err("Write request must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-2・TASK-15.1: `FlushAck::barrier()` の id は元の FLUSH リクエストと一致する。
    #[test]
    fn io2_flush_ack_barrier_id_matches_original_flush_request() {
        let request = make_request(FrameKind::Flush);
        let receipt = AckReceipt::from_matched(request, FrameKind::FlushAck)
            .expect("must accept (Flush, FlushAck)");
        let AckReceipt::Flush(flush_ack) = receipt else {
            panic!("expected Flush variant");
        };
        let barrier = flush_ack.barrier();
        assert_eq!(barrier.id().get(), request.id().get());
        assert_eq!(
            barrier,
            FlushBarrier::try_from(request).expect("Flush accepted")
        );
    }

    /// IO-1・TASK-15.1: `FlushAck::try_from(AckReceipt::Write(..))` は
    /// `InvalidArgument` で拒否する。
    #[test]
    fn io1_flush_ack_try_from_write_receipt_is_rejected() {
        let request = make_request(FrameKind::Write);
        let receipt =
            AckReceipt::from_matched(request, FrameKind::Ack).expect("must accept (Write, Ack)");
        let err = FlushAck::try_from(receipt).expect_err("Write receipt must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }

    /// IO-2・TASK-15.1: `WriteAck::try_from(AckReceipt::Flush(..))` は
    /// `InvalidArgument` で拒否する。
    #[test]
    fn io2_write_ack_try_from_flush_receipt_is_rejected() {
        let request = make_request(FrameKind::Flush);
        let receipt = AckReceipt::from_matched(request, FrameKind::FlushAck)
            .expect("must accept (Flush, FlushAck)");
        let err = WriteAck::try_from(receipt).expect_err("Flush receipt must be rejected");
        assert_eq!(err.code(), IoErrorCode::InvalidArgument);
    }
}
