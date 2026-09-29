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
//! - macOS / Windows には代替フラッシュがなく `Unimplemented` を返す
//!   （TASK-15.3・#88）。
//! - 同時並行する FLUSH の合流とレート制限はない。ただし [`crate::writeback::AppendFileSink`]
//!   は直近の成功以降に書き込みがなければ syncfs を再発行しない（書き込みを
//!   伴わない連続 FLUSH の増幅対策）。書き込みを挟む FLUSH のレート制限は後続課題。
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
use std::time::{Duration, Instant};

use crate::client::{InFlightRequest, RequestId};
use crate::error::{IoError, IoErrorCode};
use crate::protocol::FrameKind;
use crate::transport::IoTimeout;

/// 通常 ACK（[`FrameKind::Ack`]）の受領記録（IO-1）。
///
/// 対応する書き込みが受信プロセスにバッファリングされたことのみを保証し、
/// **永続化は保証しない**。永続化完了の保証が必要な呼び出し元は
/// [`FlushAck`] を待つこと。
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

/// 戻らない `syncfs` helper スレッドの同時存在数の上限（プロセス全体）。
///
/// `syncfs(2)` は中断できないため、タイムアウトしたスレッドは detach して
/// 戻るまで残る。D state でハングし続ける場合にスレッドが際限なく増えない
/// ようにする DoS 対策であり（REPAIR-5・security.md「無制限リソース確保」）、
/// 通常の同時実行を絞る値ではない。同時 Flush を出す結合試験・並列テスト
/// でも到達しない程度に大きく取る。
pub(crate) const MAX_PERSIST_THREADS: usize = 64;

/// 実行中の永続化 helper スレッド数を数え、上限を超える起動を拒否する。
pub(crate) struct PersistLimiter {
    running: AtomicUsize,
    max: usize,
}

impl PersistLimiter {
    pub(crate) const fn new(max: usize) -> Self {
        Self {
            running: AtomicUsize::new(0),
            max,
        }
    }

    /// 枠を 1 つ確保する。上限到達なら [`IoErrorCode::ResourceExhausted`]。
    fn acquire(&'static self) -> Result<PersistSlot, IoError> {
        self.running
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                if n < self.max { n.checked_add(1) } else { None }
            })
            .map(|_| PersistSlot { limiter: self })
            .map_err(|_| {
                IoError::new(
                    IoErrorCode::ResourceExhausted,
                    "too many persist operations are still running",
                )
            })
    }
}

/// [`PersistLimiter`] の枠。Drop（helper スレッド終了時）で解放する。
struct PersistSlot {
    limiter: &'static PersistLimiter,
}

impl Drop for PersistSlot {
    fn drop(&mut self) {
        self.limiter.running.fetch_sub(1, Ordering::AcqRel);
    }
}

static PERSIST_LIMITER: PersistLimiter = PersistLimiter::new(MAX_PERSIST_THREADS);

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

/// [`run_with_deadline`] の本体。`work` を helper スレッドへ渡せた時点で
/// `dispatched` を真にする（以後は `work` が実行されうるため、呼び出し側は
/// 失敗を「syscall 発行済み」として扱う）。枠の確保・スレッド生成の失敗では
/// 偽のまま返る（何も発行していない一時的な失敗。Bugbot #1142 指摘）。
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "Linux の syncfs 経路と単体テストのみが使う")
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
    let slot = limiter.acquire()?;
    let (tx, rx) = mpsc::sync_channel::<Result<(), IoError>>(1);
    let started = Instant::now();
    std::thread::Builder::new()
        .name("fandhe-io-persist".to_owned())
        .stack_size(64 * 1024)
        .spawn(move || {
            let _slot = slot;
            // 受信側がタイムアウトで離脱済みなら送信は失敗するが問題ない。
            let _ = tx.send(work());
        })
        .map_err(|_| {
            IoError::new(
                IoErrorCode::ResourceExhausted,
                "failed to spawn persist thread",
            )
        })?;
    *dispatched = true;
    match rx.recv_timeout(timeout.as_duration()) {
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
/// 列挙型で返す（将来の代替フラッシュ〔TASK-15.3・#88〕で値を足せるよう
/// `#[non_exhaustive]`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PersistSupport {
    /// Linux 5.8 以上。`syncfs(2)` が書き戻しエラーを報告するため、永続化の
    /// 成否を確認してから FlushAck を返せる。
    Supported,
    /// Linux 5.8 未満、またはカーネル版数を判定できない。`syncfs(2)` が書き戻し
    /// 失敗を隠して 0 を返しうるため拒否する（ディストロのバックポートも安全側で拒否）。
    KernelTooOld,
    /// Linux 以外の OS。代替フラッシュが未実装（TASK-15.3・#88）。
    UnsupportedOs,
}

impl PersistSupport {
    /// FlushAck を返せる（永続化に対応する）環境か。
    pub fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

/// 実行中の環境が FLUSH の永続化に対応しているかを返す（IO-2・TASK-15.2.2）。
///
/// Linux では `/proc/sys/kernel/osrelease` を読み、5.8 以上なら
/// [`PersistSupport::Supported`]、5.8 未満・読み取り失敗・解釈不能なら
/// [`PersistSupport::KernelTooOld`]（fail-closed）。結果はプロセス内で 1 回だけ
/// 判定してキャッシュする。Linux 以外は [`PersistSupport::UnsupportedOs`]。
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
    #[cfg(not(target_os = "linux"))]
    {
        PersistSupport::UnsupportedOs
    }
}

/// `file` が属するファイルシステムを永続化し、所要時間を返す（IO-2・
/// TASK-15.2.2・#824）。
///
/// [`crate::writeback::AppendFileSink`] の `persist` から、実行環境の判定
/// （[`persist_support`]）を渡して呼ばれる。[`PersistSupport::Supported`] なら
/// `file` を dup した fd に対し `crate::sys::syncfs` を helper スレッドで 1 回
/// だけ実行する。失敗しても再試行しない（errseq は 1 回しか報告しないため。
/// 呼び出し側の sink がポイズンする）。それ以外は syscall を発行せず
/// [`IoErrorCode::Unimplemented`]（`issued == false`。sink はポイズンしない）。
///
/// 判定を引数で受けるのは、5.8 以上のホストでも非対応経路（旧カーネル・非 Linux）
/// を単体テストで決定的に照合するため。
pub(crate) fn persist_file_system(
    support: PersistSupport,
    file: &File,
    timeout: IoTimeout,
) -> Result<Duration, PersistFailure> {
    match support {
        PersistSupport::Supported => sync_file_system(file, timeout),
        PersistSupport::KernelTooOld => Err(PersistFailure::not_issued(IoError::new(
            IoErrorCode::Unimplemented,
            "kernel older than 5.8 (or unknown) cannot report syncfs write-back errors; refusing to send FlushAck",
        ))),
        PersistSupport::UnsupportedOs => Err(PersistFailure::not_issued(IoError::new(
            IoErrorCode::Unimplemented,
            "persist is not implemented on this OS (TASK-15.3, #88)",
        ))),
    }
}

/// Linux の永続化本体: dup した fd に `syncfs(2)` をタイムアウト付きで 1 回だけ
/// 発行する（REPAIR-5）。fd 複製の失敗は発行前（`issued == false`）。
#[cfg(target_os = "linux")]
fn sync_file_system(file: &File, timeout: IoTimeout) -> Result<Duration, PersistFailure> {
    let dup = file.try_clone().map_err(|err| {
        PersistFailure::not_issued(IoError::new(
            IoErrorCode::Internal,
            format!("failed to duplicate fd for persist ({:?})", err.kind()),
        ))
    })?;
    let mut dispatched = false;
    run_with_deadline_tracked(
        &PERSIST_LIMITER,
        timeout,
        move || crate::sys::syncfs(&dup),
        &mut dispatched,
    )
    .map_err(|error| PersistFailure {
        error,
        issued: dispatched,
    })
}

/// 非 Linux 版: 代替フラッシュ未実装（TASK-15.3・#88）。[`persist_support`] が
/// [`PersistSupport::Supported`] を返さないため通常は到達しないが、判定を
/// 注入された場合も syscall を発行せず fail-closed で拒否する。
#[cfg(not(target_os = "linux"))]
fn sync_file_system(_file: &File, _timeout: IoTimeout) -> Result<Duration, PersistFailure> {
    let _ = &PERSIST_LIMITER;
    Err(PersistFailure::not_issued(IoError::new(
        IoErrorCode::Unimplemented,
        "persist is not implemented on this OS (TASK-15.3, #88)",
    )))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{InFlightLimit, SendQueue};

    fn ms(n: u64) -> IoTimeout {
        IoTimeout::new(Duration::from_millis(n)).expect("valid timeout")
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

    /// REPAIR-5・TASK-15.2.2: 枠を占有中は `ResourceExhausted`、解放後は `Ok`。
    #[test]
    fn repair5_run_with_deadline_rejects_when_limit_reached() {
        static L: PersistLimiter = PersistLimiter::new(1);
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let err = run_with_deadline(&L, ms(30), move || {
            let _ = release_rx.recv();
            Ok(())
        })
        .expect_err("must time out while blocked");
        assert_eq!(err.code(), IoErrorCode::Timeout);

        let busy = run_with_deadline(&L, ms(200), || Ok(())).expect_err("limit reached");
        assert_eq!(busy.code(), IoErrorCode::ResourceExhausted);

        release_tx.send(()).expect("helper still waiting");
        // helper が枠を返すまで短く待つ（最大 2 秒）。
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if run_with_deadline(&L, ms(500), || Ok(())).is_ok() {
                break;
            }
            assert!(Instant::now() < deadline, "slot was never released");
            std::thread::sleep(Duration::from_millis(10));
        }
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

    /// IO-2・TASK-15.2.2: Linux では実ファイルへの persist が成功する。
    #[cfg(target_os = "linux")]
    #[test]
    fn io2_persist_file_system_ok_on_linux() {
        let file = tempfile_in_target();
        // syncfs はファイルシステム全体を同期するため、並列テストや共有 runner の
        // 書き込み負荷で数秒かかりうる。許容上限（MAX_IO_TIMEOUT）まで待ち、
        // 失敗時は原因（Timeout / ResourceExhausted 等）を出力して診断可能にする。
        let support = persist_support();
        let result = persist_file_system(
            support,
            &file,
            IoTimeout::new(crate::MAX_IO_TIMEOUT).expect("valid timeout"),
        );
        // 版数依存を避け、production と同じ判定（`persist_support`）に応じた期待値で
        // 照合する（5.8 未満は fail-closed の `Unimplemented`。非対応経路は
        // `io2_persist_file_system_rejects_unsupported_without_issuing` でも固定）。
        match support {
            PersistSupport::Supported => {
                assert!(result.is_ok(), "persist_file_system failed: {result:?}");
            }
            other => {
                assert_eq!(other, PersistSupport::KernelTooOld);
                let failure = result.expect_err("pre-5.8 kernel must be rejected");
                assert_eq!(failure.error.code(), IoErrorCode::Unimplemented);
                assert!(!failure.issued);
            }
        }
    }

    /// IO-2・IO-3: `persist_support` は Linux では `/proc/sys/kernel/osrelease`
    /// の版数ゲートと一致し、非 Linux では `UnsupportedOs` を返す。
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
        #[cfg(not(target_os = "linux"))]
        assert_eq!(support, PersistSupport::UnsupportedOs);
        assert_eq!(support.is_supported(), support == PersistSupport::Supported);
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
        for support in [PersistSupport::KernelTooOld, PersistSupport::UnsupportedOs] {
            let failure =
                persist_file_system(support, &file, ms(100)).expect_err("must be rejected");
            assert_eq!(
                failure.error.code(),
                IoErrorCode::Unimplemented,
                "{support:?}"
            );
            assert!(!failure.issued, "{support:?}");
            assert!(!support.is_supported());
        }
    }

    #[cfg(target_os = "linux")]
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

    /// IO-2（Bugbot #1142）: 枠が埋まって helper を起動できない失敗は
    /// 「未発行」（dispatched = false）で、sink を poison させない。
    #[test]
    fn io2_run_with_deadline_not_dispatched_when_limit_reached() {
        static L: PersistLimiter = PersistLimiter::new(0);
        let mut dispatched = false;
        let err = run_with_deadline_tracked(&L, ms(50), || Ok(()), &mut dispatched)
            .expect_err("no slot available");
        assert_eq!(err.code(), IoErrorCode::ResourceExhausted);
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

    /// IO-2・TASK-15.3: 非 Linux では `Unimplemented`（#88 で代替を実装）。
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn io2_persist_file_system_unimplemented_off_linux() {
        let path = std::env::temp_dir().join(format!("fandhe-io-persist-{}", std::process::id()));
        let file = File::create(&path).expect("create temp file");
        let _ = std::fs::remove_file(&path);
        assert_eq!(persist_support(), PersistSupport::UnsupportedOs);
        let failure = persist_file_system(persist_support(), &file, ms(100))
            .expect_err("must be unimplemented");
        assert!(!failure.issued);
        let err = failure.error;
        assert_eq!(err.code(), IoErrorCode::Unimplemented);
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
