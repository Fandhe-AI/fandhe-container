//! virtiofs 共有向けの I/O 共有プロトコル（IO-1・IO-2）クライアント接続（MAC-1・TASK-65.2）。
//!
//! `fandhe_container_io::PipelineClient` を virtiofs 共有（[`VirtiofsShareSpec`]）の文脈で包み、
//! バッチ write-back（`Write` → `Ack`）と FLUSH バリア（`Flush` → `FlushAck`）を送受信する。
//! フレーム組み立て・チェックサム・request id 採番・送信順での ACK 照合は io crate の実装をそのまま使い、
//! 本モジュールは新しいワイヤー形式を作らない（REPAIR-2）。
//!
//! 呼び出し文脈: ゲスト側エージェント、または TASK-115 の `fandhe-container-plugin-macos` が具象トランスポート
//! （ゲストでは `fandhe_container_io::VsockConnection` 等）を渡して使う。サーバー側は io crate の
//! `writeback::serve_connection`（TASK-13）。
//!
//! # 契約
//!
//! - 通常 ACK は「サーバーがバッファへ受理した」ことだけを意味し、永続化は保証しない。永続化の保証は
//!   FLUSH ACK だけが持つ（IO-1・IO-2。`docs/api/io-barrier.md`）。
//! - すべての ACK 待ちにタイムアウトを渡す（REPAIR-5）。`write` の暗黙 flush と `flush` の ACK 受け取り
//!   （通常 ACK 分と最後の `FlushAck`）は区別せず `flush_ack` を使う（`ack` は予約値で現在は未使用）。
//! - エラー後の接続は再利用しない（poison。P1-3）。再接続は `reconnect` モジュールの
//!   `ReconnectingVirtiofsIoClient` が担う（TASK-65.5）。
//! - 共有が [`ShareAccess::ReadOnly`] の場合は構築を拒否する（fail-closed）。
//! - virtiofs タグはワイヤーへ載せない（`writeback.rs` の D1）。タグは識別・観測用に保持するだけで、
//!   載せるのは IO-1 契約の変更（`PROTOCOL_VERSION` の繰り上げを伴いうる）になるため行わない。
//!
//! # 運用ルール（D3）
//!
//! サーバーが ACK を返すのは batch_size 到達・バイト上限到達・`Flush` 受信・自動フラッシュのときだけ。
//! batch_size 未満の `Write` だけを送って ACK を待つとタイムアウトまで止まる。そのため
//! 本クライアントは in-flight 上限のうち 1 枠を `Flush` 用に予約し（上限は [`MIN_IN_FLIGHT_LIMIT`] 以上）、
//! `Write` が残り 1 枠に達すると通常 ACK を待たず暗黙の `Flush` で確定させるため、上限とサーバーの
//! batch_size の大小に関わらず ACK 待ちで止まらない。件数未達の残りは呼び出し側が `flush`
//! （[`VirtiofsIoClient::write_all_and_flush`]）で確定させること。
//!
//! # 未実装（REPAIR-3）
//!
//! クライアント側の UDS `connect`・macOS ホスト側の VZ vsock トランスポート（io は `Unimplemented`）・
//! ゲスト内 mount（TASK-65.3）・plugin-macos からの配線（TASK-115）は別タスクで、本モジュールは
//! 汎用トランスポートを受け取る契約に留める。

use std::fmt;
use std::time::{Duration, Instant};

use fandhe_container_io::{
    AckMetrics, AckReceipt, Frame, FrameKind, FrameReceiver, FrameSender, InFlightLimit, IoError,
    IoErrorCode, IoTimeout, PipelineClient, RequestId, SendMetrics, SendObserver,
};

use super::{ShareAccess, VirtiofsShareSpec, VirtiofsTag};

/// in-flight 上限の下限（`Flush` 用の予約 1 枠 + `Write` 1 枠）。
pub const MIN_IN_FLIGHT_LIMIT: usize = 2;
/// 既定の送信タイムアウト（秒。REPAIR-5）。
pub const DEFAULT_VIRTIOFS_IO_SEND_TIMEOUT_SECS: u64 = 5;
/// 既定の ACK 待ちタイムアウト（秒）。`fandhe_container_io::MAX_IO_TIMEOUT` に合わせる。
pub const DEFAULT_VIRTIOFS_IO_ACK_TIMEOUT_SECS: u64 = 10;
/// 既定の FLUSH ACK 待ちタイムアウト（秒）。`fandhe_container_io::MAX_IO_TIMEOUT` に合わせる。
pub const DEFAULT_VIRTIOFS_IO_FLUSH_ACK_TIMEOUT_SECS: u64 = 10;

/// 送信・ACK 待ち・FLUSH ACK 待ちのタイムアウト（REPAIR-5）。各値は `IoTimeout` で検証済み。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtiofsIoTimeouts {
    send: IoTimeout,
    ack: IoTimeout,
    flush_ack: IoTimeout,
}

impl VirtiofsIoTimeouts {
    /// 検証済みの各タイムアウトから組み立てる。
    pub fn new(send: IoTimeout, ack: IoTimeout, flush_ack: IoTimeout) -> Self {
        Self {
            send,
            ack,
            flush_ack,
        }
    }

    /// 既定値（send 5s / ack 10s / flush_ack 10s）。`IoTimeout` の検証が失敗した場合のみ `Err`。
    pub fn try_default() -> Result<Self, IoError> {
        Ok(Self {
            send: IoTimeout::new(Duration::from_secs(DEFAULT_VIRTIOFS_IO_SEND_TIMEOUT_SECS))?,
            ack: IoTimeout::new(Duration::from_secs(DEFAULT_VIRTIOFS_IO_ACK_TIMEOUT_SECS))?,
            flush_ack: IoTimeout::new(Duration::from_secs(
                DEFAULT_VIRTIOFS_IO_FLUSH_ACK_TIMEOUT_SECS,
            ))?,
        })
    }

    /// 1 フレームの送信に渡すタイムアウト。
    pub fn send(&self) -> IoTimeout {
        self.send
    }

    /// 予約値（現在 `write` の暗黙 flush も `flush_ack` を使うため、クライアント内では未使用）。
    pub fn ack(&self) -> IoTimeout {
        self.ack
    }

    /// `flush` の ACK 受け取り（通常 ACK 分と `FlushAck`）に渡すタイムアウト。
    pub fn flush_ack(&self) -> IoTimeout {
        self.flush_ack
    }
}

/// 失敗した操作の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtiofsIoOp {
    Write,
    Flush,
}

impl VirtiofsIoOp {
    fn as_str(self) -> &'static str {
        match self {
            VirtiofsIoOp::Write => "write",
            VirtiofsIoOp::Flush => "flush",
        }
    }
}

/// virtiofs I/O クライアントのエラー（ERR 系。message は英語で、body の内容を含めない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VirtiofsIoError {
    /// 読み取り専用の共有に write-back クライアントは作れない（fail-closed）。
    ReadOnlyShare { tag: VirtiofsTag },
    /// io crate のプロトコル層が返したエラー（タイムアウト・切断・検証失敗など）。
    Protocol { op: VirtiofsIoOp, source: IoError },
    /// 期待と異なる種別・対応の ACK を受け取った。
    UnexpectedAck { op: VirtiofsIoOp },
    /// in-flight 上限が `Flush` 用の予約枠を含めて足りない（[`MIN_IN_FLIGHT_LIMIT`] 未満）。
    InFlightLimitTooSmall { limit: usize },
    /// 接続断を検知した（TASK-65.5）。失敗した操作は再送されない。`unflushed_writes` は最後に成功した
    /// `flush` 以降に送った `Write` の件数で、永続化の有無が不明なため呼び出し元がコミット単位で再発行する。
    ConnectionLost {
        op: VirtiofsIoOp,
        unflushed_writes: u64,
        reconnected: bool,
        source: IoError,
    },
    /// 再接続を既定回数試みたがすべて失敗した（TASK-65.5）。`source` は最後の試行のエラー。
    /// `unflushed_writes` は切断時点で永続化が確認できていなかった `Write` の件数（初回接続の失敗では 0）。
    ReconnectFailed {
        attempts: u32,
        unflushed_writes: u64,
        source: IoError,
    },
    /// 再接続ポリシーの値が許容範囲外（TASK-65.5）。`field` は違反した項目名。
    InvalidReconnectPolicy { field: &'static str },
}

impl VirtiofsIoError {
    /// 機械可読なエラーコード（`virtiofs_io.*`）。
    pub fn code(&self) -> &'static str {
        match self {
            VirtiofsIoError::ReadOnlyShare { .. } => "virtiofs_io.read_only_share",
            VirtiofsIoError::UnexpectedAck { .. } => "virtiofs_io.unexpected_ack",
            VirtiofsIoError::InFlightLimitTooSmall { .. } => {
                "virtiofs_io.in_flight_limit_too_small"
            }
            VirtiofsIoError::ConnectionLost { .. } => "virtiofs_io.connection_lost",
            VirtiofsIoError::ReconnectFailed { .. } => "virtiofs_io.reconnect_failed",
            VirtiofsIoError::InvalidReconnectPolicy { .. } => {
                "virtiofs_io.invalid_reconnect_policy"
            }
            VirtiofsIoError::Protocol { source, .. } => match source.code() {
                IoErrorCode::InvalidArgument => "virtiofs_io.invalid_argument",
                IoErrorCode::Timeout => "virtiofs_io.timeout",
                IoErrorCode::Unavailable => "virtiofs_io.unavailable",
                IoErrorCode::Unimplemented => "virtiofs_io.unimplemented",
                IoErrorCode::Internal => "virtiofs_io.internal",
                IoErrorCode::DataLoss => "virtiofs_io.data_loss",
                IoErrorCode::ResourceExhausted => "virtiofs_io.resource_exhausted",
                IoErrorCode::AlreadyExists => "virtiofs_io.already_exists",
                _ => "virtiofs_io.error",
            },
        }
    }

    /// 人間可読なメッセージ（英語）。
    pub fn message(&self) -> String {
        match self {
            VirtiofsIoError::ReadOnlyShare { tag } => format!(
                "virtiofs share '{}' is read-only; a write-back client cannot be created",
                tag.as_str()
            ),
            VirtiofsIoError::Protocol { op, source } => {
                format!("virtiofs io {} failed: {}", op.as_str(), source)
            }
            VirtiofsIoError::InFlightLimitTooSmall { limit } => format!(
                "virtiofs io in-flight limit {limit} is too small; at least {MIN_IN_FLIGHT_LIMIT} is required \
                 (one slot is reserved for flush)"
            ),
            VirtiofsIoError::UnexpectedAck { op } => format!(
                "virtiofs io {} received an unexpected ack; the connection must be re-established",
                op.as_str()
            ),
            VirtiofsIoError::ConnectionLost {
                op,
                unflushed_writes,
                reconnected,
                ..
            } => format!(
                "virtiofs io {} failed because the connection was lost; reconnected={reconnected}, \
                 {unflushed_writes} unflushed write(s) must be re-issued",
                op.as_str()
            ),
            VirtiofsIoError::ReconnectFailed {
                attempts,
                unflushed_writes,
                source,
            } => {
                let base =
                    format!("virtiofs io reconnect failed after {attempts} attempt(s): {source}");
                if *unflushed_writes > 0 {
                    format!("{base}; {unflushed_writes} unflushed write(s) must be re-issued")
                } else {
                    base
                }
            }
            VirtiofsIoError::InvalidReconnectPolicy { field } => {
                format!("virtiofs io reconnect policy {field} is outside the allowed range")
            }
        }
    }
}

impl fmt::Display for VirtiofsIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for VirtiofsIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VirtiofsIoError::Protocol { source, .. }
            | VirtiofsIoError::ConnectionLost { source, .. }
            | VirtiofsIoError::ReconnectFailed { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// [`VirtiofsIoClient::write`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriteReport {
    /// この呼び出しで（枠を空けるために）受け取った通常 ACK の件数。
    pub acked_writes: u64,
    /// 送信した `Write` の request id。
    pub request: RequestId,
}

/// [`VirtiofsIoClient::flush`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlushReport {
    /// この呼び出しで受け取った通常 ACK の件数。
    pub acked_writes: u64,
    /// 永続化が確認されたバリアの request id（IO-2）。
    pub barrier: RequestId,
}

/// virtiofs 共有向け I/O 共有プロトコルのクライアント（MAC-1・TASK-65.2。契約はモジュール doc）。
pub struct VirtiofsIoClient<T, O>
where
    T: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>,
    O: SendObserver,
{
    tag: VirtiofsTag,
    client: PipelineClient<T, O>,
    timeouts: VirtiofsIoTimeouts,
    /// 状態が曖昧になったエラー（想定外 ACK・flush 途中の失敗）後に立てる。以後の呼び出しを拒否する。
    broken: bool,
    /// FLUSH ACK を確認できた回数（`confirmed_flushes` 参照）。
    confirmed_flushes: u64,
}

impl<T, O> VirtiofsIoClient<T, O>
where
    T: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>,
    O: SendObserver,
{
    /// 共有が `ReadOnly` なら [`VirtiofsIoError::ReadOnlyShare`] で拒否する（fail-closed）。
    pub fn new(
        share: &VirtiofsShareSpec,
        transport: T,
        limit: InFlightLimit,
        observer: O,
        timeouts: VirtiofsIoTimeouts,
    ) -> Result<Self, VirtiofsIoError> {
        if share.access != ShareAccess::ReadWrite {
            return Err(VirtiofsIoError::ReadOnlyShare {
                tag: share.tag.clone(),
            });
        }
        // Flush 用に 1 枠を予約するため、上限 1 では Write を 1 件も積めない。
        if limit.get() < MIN_IN_FLIGHT_LIMIT {
            return Err(VirtiofsIoError::InFlightLimitTooSmall { limit: limit.get() });
        }
        Ok(Self {
            tag: share.tag.clone(),
            client: PipelineClient::new(transport, limit, observer),
            timeouts,
            broken: false,
            confirmed_flushes: 0,
        })
    }

    /// 対象共有のタグ（識別・観測用。ワイヤーには載らない）。
    pub fn tag(&self) -> &VirtiofsTag {
        &self.tag
    }

    /// 設定されたタイムアウト。
    pub fn timeouts(&self) -> VirtiofsIoTimeouts {
        self.timeouts
    }

    /// FLUSH ACK を確認できた回数（暗黙 flush を含む。IO-2）。呼び出し前後の差で、その呼び出しの途中に
    /// 永続化が確定したか（`write` が暗黙 flush に成功した後で失敗した場合を含む）を判定するのに使う（TASK-65.5）。
    pub fn confirmed_flushes(&self) -> u64 {
        self.confirmed_flushes
    }

    /// 接続が再利用不可か（トランスポート失効または本クライアントが曖昧状態を検出済み）。
    pub fn is_poisoned(&self) -> bool {
        self.broken || self.client.is_poisoned()
    }

    /// 未 ACK の送信件数。
    pub fn in_flight(&self) -> usize {
        self.client.queue().len()
    }

    /// 送信メトリクス（REPAIR-4）。
    pub fn metrics(&self) -> &SendMetrics {
        self.client.metrics()
    }

    /// ACK 受信メトリクス（REPAIR-4）。
    pub fn ack_metrics(&self) -> &AckMetrics {
        self.client.ack_metrics()
    }

    fn protocol(op: VirtiofsIoOp, source: IoError) -> VirtiofsIoError {
        VirtiofsIoError::Protocol { op, source }
    }

    fn ensure_usable(&self, op: VirtiofsIoOp) -> Result<(), VirtiofsIoError> {
        if self.broken {
            return Err(Self::protocol(
                op,
                IoError::new(
                    IoErrorCode::Unavailable,
                    "virtiofs io client is poisoned; reconnect required",
                ),
            ));
        }
        Ok(())
    }

    /// `Write` を 1 件パイプライン送信する。
    ///
    /// キューの 1 枠は `Flush` 用に予約する。`Write` が残り 1 枠（上限 - 1 件）に達していたら、通常 ACK を
    /// 待たずに先に暗黙の `Flush` で滞留分を確定させる（サーバーは batch_size 未満の `Write` に `Flush` 受信まで
    /// ACK を返さないため、通常 ACK 待ちでは in-flight 上限 ≤ batch_size のときに止まる。D3）。
    pub fn write(&mut self, body: &[u8]) -> Result<WriteReport, VirtiofsIoError> {
        const OP: VirtiofsIoOp = VirtiofsIoOp::Write;
        self.ensure_usable(OP)?;
        let mut acked_writes = 0;
        if self.client.queue().len() >= self.write_capacity() {
            acked_writes = self.flush_inner()?.acked_writes;
        }
        let sent = self
            .client
            .send(FrameKind::Write, body, self.timeouts.send)
            .map_err(|e| Self::protocol(OP, e))?;
        Ok(WriteReport {
            acked_writes,
            request: sent.id(),
        })
    }

    /// `Write` が占有できる最大件数（上限 - `Flush` 用の予約 1 枠。構築時に上限 ≥ 2 を保証済み）。
    fn write_capacity(&self) -> usize {
        self.client.queue().limit().get().saturating_sub(1)
    }

    /// `Flush` を送り、それ以前の通常 ACK を順に受け取ってから同じ request id の `FlushAck` を待つ（IO-2）。
    pub fn flush(&mut self) -> Result<FlushReport, VirtiofsIoError> {
        self.ensure_usable(VirtiofsIoOp::Flush)?;
        self.flush_inner()
    }

    /// `flush` の本体。`Write` は予約枠を超えて積まれないため、`Flush` 送信用の枠は常に空いている。
    fn flush_inner(&mut self) -> Result<FlushReport, VirtiofsIoError> {
        const OP: VirtiofsIoOp = VirtiofsIoOp::Flush;
        let barrier = self
            .client
            .flush(self.timeouts.send)
            .map_err(|e| Self::protocol(OP, e))?;
        let mut acked_writes = 0;
        // 送信後は ACK の受け取りが途中で失敗すると状態が曖昧になるため、以後の再利用を拒否する。
        match self.drain_until(barrier.id(), &mut acked_writes) {
            Ok(()) => {
                self.confirmed_flushes = self.confirmed_flushes.saturating_add(1);
                Ok(FlushReport {
                    acked_writes,
                    barrier: barrier.id(),
                })
            }
            Err(e) => {
                self.broken = true;
                Err(e)
            }
        }
    }

    /// 送信時点の in-flight 件数を上限に（有限ループ）、`barrier` の `FlushAck` まで ACK を受け取る。
    ///
    /// `flush_ack` は 1 回の Flush 全体の期限として扱う。開始時に期限（deadline）を定め、各 `recv_ack` には
    /// 残り時間だけを渡す。ACK が期限直前に届くたびに待ち時間が再開すると、in-flight 上限件数ぶん
    /// 単一の `flush` が拘束され得るため（REPAIR-5）。期限超過は `IoErrorCode::Timeout` に揃える。
    fn drain_until(&mut self, barrier: RequestId, acked: &mut u64) -> Result<(), VirtiofsIoError> {
        const OP: VirtiofsIoOp = VirtiofsIoOp::Flush;
        let deadline = Instant::now().checked_add(self.timeouts.flush_ack.as_duration());
        let rounds = self.client.queue().len();
        for _ in 0..rounds {
            let remaining = Self::remaining_until(deadline)?;
            let receipt = self
                .client
                .recv_ack(remaining)
                .map_err(|e| Self::protocol(OP, e))?;
            match receipt {
                AckReceipt::Write(_) => {
                    *acked = acked
                        .checked_add(1)
                        .ok_or(VirtiofsIoError::UnexpectedAck { op: OP })?;
                }
                AckReceipt::Flush(ack) if ack.barrier().id() == barrier => return Ok(()),
                _ => return Err(VirtiofsIoError::UnexpectedAck { op: OP }),
            }
        }
        Err(VirtiofsIoError::UnexpectedAck { op: OP })
    }

    /// `deadline` までの残り時間を `IoTimeout` にする。残りが 0 以下（期限到達）なら `Timeout` を返す。
    ///
    /// `deadline` が `None`（加算オーバーフロー）の場合は fail-closed で即 `Timeout` とする。
    fn remaining_until(deadline: Option<Instant>) -> Result<IoTimeout, VirtiofsIoError> {
        const OP: VirtiofsIoOp = VirtiofsIoOp::Flush;
        let expired = || {
            Self::protocol(
                OP,
                IoError::new(IoErrorCode::Timeout, "flush deadline exceeded"),
            )
        };
        let deadline = deadline.ok_or_else(expired)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        // Duration::ZERO は IoTimeout として構築できない（期限到達と同義）。
        IoTimeout::new(remaining).map_err(|_| expired())
    }

    /// `bodies` を順に `write` し、最後に `flush` するコミット単位（D3 の滞留を必ず確定させる）。
    ///
    /// 戻り値の `acked_writes` は途中の枠空け分も含めた通常 ACK の総数。
    pub fn write_all_and_flush(
        &mut self,
        bodies: &[&[u8]],
    ) -> Result<FlushReport, VirtiofsIoError> {
        let mut acked: u64 = 0;
        for body in bodies {
            let report = self.write(body)?;
            acked = acked.saturating_add(report.acked_writes);
        }
        let mut report = self.flush()?;
        report.acked_writes = report.acked_writes.saturating_add(acked);
        Ok(report)
    }
}

#[cfg(test)]
#[path = "io_client_tests.rs"]
mod tests;
