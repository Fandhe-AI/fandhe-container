//! virtiofs I/O クライアントの切断時再接続（MAC-1・REPAIR-5・ERR-1・TASK-65.5）。
//!
//! [`VirtiofsIoClient`] はエラー後に poison され再利用できない（TASK-65.2 の契約）。本モジュールの
//! [`ReconnectingVirtiofsIoClient`] はその「再接続は呼び出し元の責務」を引き受け、接続断を検知したら
//! [`ReconnectPolicy`]（既定 3 回・500ms 間隔）に従って [`VirtiofsConnector`] で接続し直す。
//! 再接続にも失敗したら panic せず構造化エラー（[`VirtiofsIoError::ReconnectFailed`]。code は
//! `virtiofs_io.reconnect_failed`）で返す。
//!
//! 呼び出し文脈: ゲスト側エージェント、または TASK-115 の `fandhe-container-plugin-macos` が
//! 具象 connector を渡して使う。`PlatformError::VirtiofsIo` 経由で code / message が委譲される。
//!
//! # 契約
//!
//! - 失敗した操作も、最後の `FlushAck` 以降に送った未確定の `Write` も**自動では再送しない**。通常 ACK は
//!   永続化を保証せず（IO-2。`docs/api/io-barrier.md`）、サーバーは batch_size 到達時に自動フラッシュするため
//!   一部だけ永続化されている可能性がある。黙って再送すると重複書き込みや欠落を招く。
//!   再接続に成功しても失敗した操作は [`VirtiofsIoError::ConnectionLost`] で返し、`unflushed_writes` の
//!   件数とともに呼び出し元へコミット単位（[`ReconnectingVirtiofsIoClient::write_all_and_flush`]）の再発行を委ねる。
//! - 接続断以外のエラー（タイムアウト・DataLoss・想定外 ACK）は元のエラーをそのまま返す。client が poison
//!   されていれば次の呼び出しの冒頭で再接続する。その時点で未確定の `Write` が残っていれば、操作を実行せず
//!   `ConnectionLost`（再接続成功）または件数付き `ReconnectFailed` で明示し、呼び出し元の再発行を求める。
//! - 最悪の総待ち時間は `max_attempts × connect_timeout + (max_attempts − 1) × interval` で有界
//!   （既定 3×5s + 2×0.5s = 16s、上限値 10×10s + 9×10s = 190s。REPAIR-5）。無限リトライはしない。
//! - 再接続のたびに [`VirtiofsIoClient::new`] を通すため、ReadOnly 共有の拒否（fail-closed）は毎回再検証される。
//!
//! # 未実装（REPAIR-3）
//!
//! 具象 [`VirtiofsConnector`]（ゲストの vsock 接続・ホスト側 UDS / VZ vsock の connect）は別タスク
//! （TASK-115 ほか）。バックオフは固定間隔のみで、指数バックオフ・ジッターは将来拡張。

use std::time::Duration;

use fandhe_container_io::{
    Frame, FrameReceiver, FrameSender, InFlightLimit, IoError, IoErrorCode, IoTimeout, SendObserver,
};

use super::io_client::{
    FlushReport, MIN_IN_FLIGHT_LIMIT, VirtiofsIoClient, VirtiofsIoError, VirtiofsIoOp,
    VirtiofsIoTimeouts, WriteReport,
};
use super::{ShareAccess, VirtiofsShareSpec, VirtiofsTag};

/// 再接続の試行回数の既定値。
pub const DEFAULT_VIRTIOFS_RECONNECT_ATTEMPTS: u32 = 3;
/// 再接続の試行間隔の既定値（ミリ秒）。
pub const DEFAULT_VIRTIOFS_RECONNECT_INTERVAL_MILLIS: u64 = 500;
/// 1 回の接続試行に渡すタイムアウトの既定値（秒）。
pub const DEFAULT_VIRTIOFS_RECONNECT_CONNECT_TIMEOUT_SECS: u64 = 5;
/// 試行回数の上限（総待ち時間を有界にする。REPAIR-5）。
pub const MAX_RECONNECT_ATTEMPTS: u32 = 10;
/// 試行間隔の上限。
pub const MAX_RECONNECT_INTERVAL: Duration = Duration::from_secs(10);

/// 接続生成の境界。具象 connector は呼び出し元（ゲスト / plugin-macos）が実装する（REPAIR-3）。
pub trait VirtiofsConnector {
    /// 確立した接続の型。
    type Transport: FrameSender<Frame = Frame> + FrameReceiver<Frame = Frame>;

    /// 1 回の接続試行。`timeout` 以内に確立できなければ `IoErrorCode::Timeout` 等で返す（REPAIR-5）。
    fn connect(&mut self, timeout: IoTimeout) -> Result<Self::Transport, IoError>;
}

/// 再接続ポリシー。値は上限検証済みで、0 回・0 間隔や無制限リトライは表現できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectPolicy {
    max_attempts: u32,
    interval: Duration,
    connect_timeout: IoTimeout,
}

impl ReconnectPolicy {
    /// 範囲外の値を拒否して生成する（`1..=MAX_RECONNECT_ATTEMPTS` 回・`0 < interval <= MAX_RECONNECT_INTERVAL`）。
    pub fn try_new(
        max_attempts: u32,
        interval: Duration,
        connect_timeout: IoTimeout,
    ) -> Result<Self, VirtiofsIoError> {
        if max_attempts == 0 || max_attempts > MAX_RECONNECT_ATTEMPTS {
            return Err(VirtiofsIoError::InvalidReconnectPolicy {
                field: "max_attempts",
            });
        }
        if interval.is_zero() || interval > MAX_RECONNECT_INTERVAL {
            return Err(VirtiofsIoError::InvalidReconnectPolicy { field: "interval" });
        }
        Ok(Self {
            max_attempts,
            interval,
            connect_timeout,
        })
    }

    /// 既定値（3 回・500ms・接続タイムアウト 5s）。
    pub fn try_default() -> Result<Self, VirtiofsIoError> {
        let connect_timeout = IoTimeout::new(Duration::from_secs(
            DEFAULT_VIRTIOFS_RECONNECT_CONNECT_TIMEOUT_SECS,
        ))
        .map_err(|_| VirtiofsIoError::InvalidReconnectPolicy {
            field: "connect_timeout",
        })?;
        Self::try_new(
            DEFAULT_VIRTIOFS_RECONNECT_ATTEMPTS,
            Duration::from_millis(DEFAULT_VIRTIOFS_RECONNECT_INTERVAL_MILLIS),
            connect_timeout,
        )
    }

    /// 試行回数。
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// 試行間隔（固定）。
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// 1 回の接続試行に渡すタイムアウト。
    pub fn connect_timeout(&self) -> IoTimeout {
        self.connect_timeout
    }
}

/// 切断時に再接続する virtiofs I/O クライアント（MAC-1・TASK-65.5。契約はモジュール doc）。
pub struct ReconnectingVirtiofsIoClient<C, O>
where
    C: VirtiofsConnector,
    O: SendObserver + Clone,
{
    share: VirtiofsShareSpec,
    connector: C,
    limit: InFlightLimit,
    observer: O,
    timeouts: VirtiofsIoTimeouts,
    policy: ReconnectPolicy,
    client: Option<VirtiofsIoClient<C::Transport, O>>,
    unflushed_writes: u64,
    reconnects: u64,
    pause: Box<dyn FnMut(Duration)>,
}

impl<C, O> ReconnectingVirtiofsIoClient<C, O>
where
    C: VirtiofsConnector,
    O: SendObserver + Clone,
{
    /// ReadOnly 共有と `limit < MIN_IN_FLIGHT_LIMIT` を接続前に拒否し、ポリシーに従って初回接続する。
    pub fn connect(
        share: &VirtiofsShareSpec,
        connector: C,
        limit: InFlightLimit,
        observer: O,
        timeouts: VirtiofsIoTimeouts,
        policy: ReconnectPolicy,
    ) -> Result<Self, VirtiofsIoError> {
        Self::connect_with_pause(
            share,
            connector,
            limit,
            observer,
            timeouts,
            policy,
            Box::new(std::thread::sleep),
        )
    }

    /// 試行間の待機を差し替えて接続する（テスト用。実時間の sleep に依存させない）。
    pub(crate) fn connect_with_pause(
        share: &VirtiofsShareSpec,
        connector: C,
        limit: InFlightLimit,
        observer: O,
        timeouts: VirtiofsIoTimeouts,
        policy: ReconnectPolicy,
        pause: Box<dyn FnMut(Duration)>,
    ) -> Result<Self, VirtiofsIoError> {
        if share.access != ShareAccess::ReadWrite {
            return Err(VirtiofsIoError::ReadOnlyShare {
                tag: share.tag.clone(),
            });
        }
        if limit.get() < MIN_IN_FLIGHT_LIMIT {
            return Err(VirtiofsIoError::InFlightLimitTooSmall { limit: limit.get() });
        }
        let mut this = Self {
            share: share.clone(),
            connector,
            limit,
            observer,
            timeouts,
            policy,
            client: None,
            unflushed_writes: 0,
            reconnects: 0,
            pause,
        };
        this.establish()?;
        Ok(this)
    }

    /// 対象共有のタグ（識別・観測用）。
    pub fn tag(&self) -> &VirtiofsTag {
        &self.share.tag
    }

    /// 再接続に成功した回数（初回接続は含まない。REPAIR-4）。
    pub fn reconnects(&self) -> u64 {
        self.reconnects
    }

    /// 最後に FLUSH ACK を確認した `flush` 以降に送った `Write` の件数（永続化未確認の上限値。
    /// 通常 ACK では減らさない。IO-1・IO-2）。
    pub fn unflushed_writes(&self) -> u64 {
        self.unflushed_writes
    }

    /// 現在使える接続を保持しているか。
    pub fn is_connected(&self) -> bool {
        self.client.as_ref().is_some_and(|c| !c.is_poisoned())
    }

    /// ポリシーに従い接続を確立する。全試行が失敗したら [`VirtiofsIoError::ReconnectFailed`]。
    fn establish(&mut self) -> Result<(), VirtiofsIoError> {
        let mut last: Option<IoError> = None;
        for attempt in 1..=self.policy.max_attempts {
            match self.connector.connect(self.policy.connect_timeout) {
                Ok(transport) => {
                    let client = VirtiofsIoClient::new(
                        &self.share,
                        transport,
                        self.limit,
                        self.observer.clone(),
                        self.timeouts,
                    )?;
                    self.client = Some(client);
                    return Ok(());
                }
                Err(e) => last = Some(e),
            }
            if attempt < self.policy.max_attempts {
                (self.pause)(self.policy.interval);
            }
        }
        Err(VirtiofsIoError::ReconnectFailed {
            attempts: self.policy.max_attempts,
            unflushed_writes: 0,
            source: last.unwrap_or_else(|| {
                IoError::new(IoErrorCode::Internal, "no connect attempt was made")
            }),
        })
    }

    /// 再接続して `reconnects` を加算する。
    fn reconnect(&mut self) -> Result<(), VirtiofsIoError> {
        self.client = None;
        self.establish()?;
        self.reconnects = self.reconnects.saturating_add(1);
        Ok(())
    }

    /// 使える接続がなければ（未接続・poison）再接続する。`op` は次に実行しようとしている操作。
    ///
    /// 旧接続に未確定の `Write` が残っていた場合（タイムアウト等で poison された後）は、黙って捨てずに
    /// 再接続のうえ [`VirtiofsIoError::ConnectionLost`] で呼び出し元へ明示する。`op` は実行されない。
    fn ensure_connected(&mut self, op: VirtiofsIoOp) -> Result<(), VirtiofsIoError> {
        if self.is_connected() {
            return Ok(());
        }
        if self.unflushed_writes == 0 {
            return self.reconnect();
        }
        let source = IoError::new(
            IoErrorCode::Unavailable,
            "previous connection was poisoned by an earlier error",
        );
        Err(self.reconnect_reporting_unflushed(op, source))
    }

    /// 旧接続の未確定件数を持ち出して再接続する。成功なら `ConnectionLost`、全試行失敗なら件数付きの
    /// `ReconnectFailed` を返す（件数は返却値へ移し、状態は 0 に戻す。新接続に未確定分は存在しない）。
    fn reconnect_reporting_unflushed(
        &mut self,
        op: VirtiofsIoOp,
        source: IoError,
    ) -> VirtiofsIoError {
        let unflushed_writes = std::mem::take(&mut self.unflushed_writes);
        match self.reconnect() {
            Ok(()) => VirtiofsIoError::ConnectionLost {
                op,
                unflushed_writes,
                reconnected: true,
                source,
            },
            Err(VirtiofsIoError::ReconnectFailed {
                attempts, source, ..
            }) => VirtiofsIoError::ReconnectFailed {
                attempts,
                unflushed_writes,
                source,
            },
            Err(e) => {
                self.unflushed_writes = unflushed_writes;
                e
            }
        }
    }

    /// 失敗を分類する。接続断なら再接続したうえで [`VirtiofsIoError::ConnectionLost`] を返し、それ以外は素通しする。
    fn classify(&mut self, op: VirtiofsIoOp, err: VirtiofsIoError) -> VirtiofsIoError {
        let source = match &err {
            VirtiofsIoError::Protocol { source, .. }
                if source.code() == IoErrorCode::Unavailable =>
            {
                source.clone()
            }
            _ => return err,
        };
        self.reconnect_reporting_unflushed(op, source)
    }

    /// `Write` を 1 件送る。接続断は再接続のうえ `ConnectionLost` で返し、再送はしない。
    pub fn write(&mut self, body: &[u8]) -> Result<WriteReport, VirtiofsIoError> {
        self.ensure_connected(VirtiofsIoOp::Write)?;
        let result = match self.client.as_mut() {
            Some(c) => c.write(body),
            None => return Err(Self::not_connected(VirtiofsIoOp::Write)),
        };
        match result {
            Ok(report) => {
                // 通常 ACK は永続化を保証しない（IO-2）ため、暗黙 flush が走っても件数は減らさない。
                // 0 に戻すのは FLUSH ACK を確認できた `flush` 成功時のみ（件数は永続化未確認の上限値）。
                self.unflushed_writes = self.unflushed_writes.saturating_add(1);
                Ok(report)
            }
            Err(e) => Err(self.classify(VirtiofsIoOp::Write, e)),
        }
    }

    /// `Flush` を送り FLUSH ACK を待つ（IO-2）。成功すれば未確定件数は 0 に戻る。
    pub fn flush(&mut self) -> Result<FlushReport, VirtiofsIoError> {
        self.ensure_connected(VirtiofsIoOp::Flush)?;
        let result = match self.client.as_mut() {
            Some(c) => c.flush(),
            None => return Err(Self::not_connected(VirtiofsIoOp::Flush)),
        };
        match result {
            Ok(report) => {
                self.unflushed_writes = 0;
                Ok(report)
            }
            Err(e) => Err(self.classify(VirtiofsIoOp::Flush, e)),
        }
    }

    /// `bodies` を順に `write` し最後に `flush` するコミット単位。途中の切断は `ConnectionLost` で返す。
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

    /// `ensure_connected` 成功後は到達しない防御経路（panic させない）。
    fn not_connected(op: VirtiofsIoOp) -> VirtiofsIoError {
        VirtiofsIoError::Protocol {
            op,
            source: IoError::new(
                IoErrorCode::Unavailable,
                "virtiofs io client is not connected",
            ),
        }
    }
}

#[cfg(test)]
#[path = "reconnect_tests.rs"]
mod tests;
