//! plugin 境界の gRPC（tonic）面の共通基盤（PLUG-2・TASK-108.1・#453）。
//!
//! wire 互換性が必要な CRI 標準準拠面だけが gRPC を使う（PLUG-2）。本モジュールは、その gRPC サーバー起動と
//! クライアント接続に共通する処理（タイムアウト・メッセージ上限・同時実行上限・エラー変換）を提供する。
//! 呼び出し元は将来の `fandhe-container-plugin-cri`（サーバー側）と core 側 proxy（クライアント側。TASK-114）。
//!
//! 対応するビヘイビア・マイルストーンは PLUG-2・TASK-108.1・MS-3（plugin 境界機構）。
//!
//! 非既定 feature `grpc` の背後にあり、core が既定 feature で本 crate を引いても tokio / tonic は入らない
//! （PLUG-3・PLUG-4）。
//!
//! # 責務境界
//!
//! - トランスポート（UDS / TCP）の選択は呼び出し側に委ねる。本モジュールは TCP を待ち受ける公開 API を
//!   持たない（PLUG-12・既定で外部へ公開しない）。
//! - UDS 上の tonic 統合は `UdsIncoming`（サーバー側。`UdsListener` の配置検証・0600 化を再利用し、accept 直後・
//!   最初の read より前に peer UID を検証する）と `connect_uds_channel`（クライアント側。再接続のたびに
//!   server の peer UID を検証する）が担う（TASK-108.2・#454・PLUG-2・PLUG-12。いずれも unix のみ。WIN-1）。
//!   peer 認証の限界（fd の受け渡し・pid 再利用等）は `uds_security`・`sys` の「限界」節に従う。
//! - [`serve_router`]・[`connect_channel`] 自体は認証を持たない。gRPC の内容検証（リクエストの意味検証）は
//!   上位の責務で、入力は untrusted として扱う。
//!
//! # CRI proto の疎通
//!
//! 生成済み CRI サービス（`runtime.v1`）の UDS 経由 RPC 疎通は `tests/grpc_uds.rs` で試験する
//! （TASK-108.3・#455・CRI-3）。
//!
//! # 同時接続数の上限（PLUG-12）
//!
//! UDS サーバーの同時接続数は既定 [`GRPC_MAX_CONNECTIONS_DEFAULT`]（64）で、
//! [`GrpcServerConfig::with_max_connections`] で変更する。上限到達時の追加接続は拒否され
//! （累計は [`grpc_rejected_connections`] で観測する。ログ出力はしない）、既存接続が閉じると枠が戻る。
//! 接続あたりの並列・ストリーム数も [`GrpcServerConfig`] で制限される。
//!
//! # 期限（REPAIR-5）
//!
//! `Endpoint::timeout` / `Server::timeout` は応答ヘッダ到着までの期限で、応答本文・trailers の読み取りは
//! 保護しない。RPC 全体（ストリーミングの 1 メッセージの読み取り・trailers の取得を含む）は
//! [`call_with_deadline`] / [`read_stream_message`] で包み、期限切れは `Timeout` にする。
//!
//! # 観測性（REPAIR-4）
//!
//! [`serve_router`]・[`connect_channel`]・[`call_with_deadline`] は成功・失敗・期限切れの件数とレイテンシを
//! プロセス内の集計（[`grpc_stats`]）へ記録する。[`export_stats_json_lines`] が JSON Lines で書き出す。
//!
//! # エラー変換
//!
//! | 入力 | `PluginErrorCode` |
//! | ---- | ----------------- |
//! | 接続失敗・`Unavailable`・`Aborted`・`Cancelled` | `Unavailable` |
//! | `Cancelled` で message が `Timeout expired`（tonic の `Server::timeout` 超過の応答） | `Timeout` |
//! | 期限切れ・`DeadlineExceeded` | `Timeout` |
//! | `InvalidArgument`・`OutOfRange` | `InvalidArgument` |
//! | `NotFound` | `NotFound` |
//! | `AlreadyExists` | `AlreadyExists` |
//! | `PermissionDenied`・`Unauthenticated` | `PermissionDenied` |
//! | `FailedPrecondition` | `FailedPrecondition` |
//! | `Unimplemented` | `Unimplemented` |
//! | `ResourceExhausted` | `ResourceExhausted` |
//! | `DataLoss` | `DataLoss` |
//! | その他 | `Internal` |

use std::future::{Future, poll_fn};
use std::marker::PhantomData;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::path::{Path, PathBuf};

use tonic::codegen::tokio_stream::Stream;

use tonic::transport::server::Router;
use tonic::transport::{Channel, Endpoint, Server};

use crate::error::{PluginError, PluginErrorCode};

/// gRPC メッセージの送受信サイズ上限（4 MiB）。
///
/// 生成サービスの `max_decoding_message_size` / `max_encoding_message_size` へ渡す。
/// 無制限確保による DoS を防ぐ（OWASP A04）。
pub const GRPC_MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// リクエストタイムアウト・接続タイムアウト・shutdown 猶予の上限。REPAIR-5。
pub const GRPC_TIMEOUT_MAX: Duration = Duration::from_secs(600);

/// リクエストタイムアウトの既定値（AGENTS.md の推奨タイムアウト 5〜10 秒の上限に合わせる。REPAIR-5）。
pub const GRPC_REQUEST_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);

/// 接続タイムアウトの既定値。
pub const GRPC_CONNECT_TIMEOUT_DEFAULT: Duration = Duration::from_secs(5);

/// graceful shutdown 後にサーバーの終了を待つ猶予の既定値。
pub const GRPC_SHUTDOWN_GRACE_DEFAULT: Duration = Duration::from_secs(10);

/// 同時リクエスト数・同時ストリーム数の上限値。
pub const GRPC_CONCURRENCY_MAX: u32 = 65_536;

/// サーバー全体の同時接続数の既定値（小さい有限値。PLUG-12）。
pub const GRPC_MAX_CONNECTIONS_DEFAULT: u32 = 64;

/// HTTP/2 ヘッダリストサイズの上限値（バイト）。
pub const GRPC_HEADER_LIST_MAX_BYTES: u32 = 1024 * 1024;

fn invalid(msg: &str) -> PluginError {
    PluginError::new(PluginErrorCode::InvalidArgument, msg)
}

/// 期間が 0 でなく上限以内であることを検証する。
fn check_duration(d: Duration, what: &str) -> Result<Duration, PluginError> {
    if d.is_zero() {
        return Err(invalid(&format!("{what} must be greater than zero")));
    }
    if d > GRPC_TIMEOUT_MAX {
        return Err(invalid(&format!("{what} exceeds the maximum")));
    }
    Ok(d)
}

fn check_count(n: u32, max: u32, what: &str) -> Result<u32, PluginError> {
    if n == 0 {
        return Err(invalid(&format!("{what} must be greater than zero")));
    }
    if n > max {
        return Err(invalid(&format!("{what} exceeds the maximum")));
    }
    Ok(n)
}

/// gRPC サーバーの上限設定（REPAIR-2・REPAIR-5）。
///
/// 壊れた値（0・上限超過）は検証付きの `with_*` で拒否し、構築後は常に有効な状態を保つ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcServerConfig {
    request_timeout: Duration,
    concurrency_per_connection: u32,
    max_concurrent_streams: u32,
    keepalive_interval: Duration,
    keepalive_timeout: Duration,
    header_list_max_bytes: u32,
    shutdown_grace: Duration,
    max_connections: u32,
}

impl Default for GrpcServerConfig {
    fn default() -> Self {
        Self {
            request_timeout: GRPC_REQUEST_TIMEOUT_DEFAULT,
            concurrency_per_connection: 64,
            max_concurrent_streams: 64,
            keepalive_interval: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(10),
            header_list_max_bytes: 16 * 1024,
            shutdown_grace: GRPC_SHUTDOWN_GRACE_DEFAULT,
            max_connections: GRPC_MAX_CONNECTIONS_DEFAULT,
        }
    }
}

impl GrpcServerConfig {
    /// 既定値の設定を返す。
    pub fn new() -> Self {
        Self::default()
    }

    /// リクエスト 1 件のタイムアウト（0 と [`GRPC_TIMEOUT_MAX`] 超は `InvalidArgument`）。
    pub fn with_request_timeout(mut self, d: Duration) -> Result<Self, PluginError> {
        self.request_timeout = check_duration(d, "request timeout")?;
        Ok(self)
    }

    /// 接続あたりの同時リクエスト数（0 と [`GRPC_CONCURRENCY_MAX`] 超は `InvalidArgument`）。
    pub fn with_concurrency_per_connection(mut self, n: u32) -> Result<Self, PluginError> {
        self.concurrency_per_connection =
            check_count(n, GRPC_CONCURRENCY_MAX, "concurrency per connection")?;
        Ok(self)
    }

    /// HTTP/2 の同時ストリーム数（0 と [`GRPC_CONCURRENCY_MAX`] 超は `InvalidArgument`）。
    pub fn with_max_concurrent_streams(mut self, n: u32) -> Result<Self, PluginError> {
        self.max_concurrent_streams =
            check_count(n, GRPC_CONCURRENCY_MAX, "max concurrent streams")?;
        Ok(self)
    }

    /// HTTP/2 keepalive の間隔とタイムアウト（どちらも 0 と上限超過は `InvalidArgument`）。
    pub fn with_keepalive(
        mut self,
        interval: Duration,
        timeout: Duration,
    ) -> Result<Self, PluginError> {
        self.keepalive_interval = check_duration(interval, "keepalive interval")?;
        self.keepalive_timeout = check_duration(timeout, "keepalive timeout")?;
        Ok(self)
    }

    /// HTTP/2 ヘッダリストの最大バイト数（0 と [`GRPC_HEADER_LIST_MAX_BYTES`] 超は `InvalidArgument`）。
    pub fn with_header_list_max_bytes(mut self, n: u32) -> Result<Self, PluginError> {
        self.header_list_max_bytes =
            check_count(n, GRPC_HEADER_LIST_MAX_BYTES, "header list size")?;
        Ok(self)
    }

    /// shutdown 信号後にサーバーの終了を待つ猶予（0 と上限超過は `InvalidArgument`）。
    pub fn with_shutdown_grace(mut self, d: Duration) -> Result<Self, PluginError> {
        self.shutdown_grace = check_duration(d, "shutdown grace")?;
        Ok(self)
    }

    /// サーバー全体の同時接続数の上限（0 と [`GRPC_CONCURRENCY_MAX`] 超は `InvalidArgument`）。
    ///
    /// UID 認証を通った接続にも件数上限を掛け、同一 UID の非信頼 plugin による接続・タスク・fd の
    /// 枯渇を防ぐ（PLUG-12・OWASP A04）。上限到達後の接続は accept 直後に close して拒否する。
    pub fn with_max_connections(mut self, n: u32) -> Result<Self, PluginError> {
        self.max_connections = check_count(n, GRPC_CONCURRENCY_MAX, "max connections")?;
        Ok(self)
    }

    /// 同時接続数の上限を返す。
    pub fn max_connections(&self) -> u32 {
        self.max_connections
    }

    /// リクエストタイムアウトを返す。
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// shutdown 猶予を返す。
    pub fn shutdown_grace(&self) -> Duration {
        self.shutdown_grace
    }
}

/// gRPC クライアントの上限設定（REPAIR-2・REPAIR-5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcClientConfig {
    connect_timeout: Duration,
    request_timeout: Duration,
    keepalive_interval: Duration,
    keepalive_timeout: Duration,
}

impl Default for GrpcClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: GRPC_CONNECT_TIMEOUT_DEFAULT,
            request_timeout: GRPC_REQUEST_TIMEOUT_DEFAULT,
            keepalive_interval: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(10),
        }
    }
}

impl GrpcClientConfig {
    /// 既定値の設定を返す。
    pub fn new() -> Self {
        Self::default()
    }

    /// 接続タイムアウト（0 と [`GRPC_TIMEOUT_MAX`] 超は `InvalidArgument`）。
    pub fn with_connect_timeout(mut self, d: Duration) -> Result<Self, PluginError> {
        self.connect_timeout = check_duration(d, "connect timeout")?;
        Ok(self)
    }

    /// リクエスト 1 件のタイムアウト（0 と [`GRPC_TIMEOUT_MAX`] 超は `InvalidArgument`）。
    pub fn with_request_timeout(mut self, d: Duration) -> Result<Self, PluginError> {
        self.request_timeout = check_duration(d, "request timeout")?;
        Ok(self)
    }

    /// HTTP/2 keepalive の間隔とタイムアウト。
    pub fn with_keepalive(
        mut self,
        interval: Duration,
        timeout: Duration,
    ) -> Result<Self, PluginError> {
        self.keepalive_interval = check_duration(interval, "keepalive interval")?;
        self.keepalive_timeout = check_duration(timeout, "keepalive timeout")?;
        Ok(self)
    }

    /// 接続タイムアウトを返す。
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// リクエストタイムアウトを返す。[`call_with_deadline`] の期限に渡す。
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// 呼び出し側が組み立てた `Endpoint` に本設定を適用する。
    pub fn apply(&self, endpoint: Endpoint) -> Endpoint {
        endpoint
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .http2_keep_alive_interval(self.keepalive_interval)
            .keep_alive_timeout(self.keepalive_timeout)
            .tcp_nodelay(true)
    }
}

/// 設定を適用した tonic の `Server` ビルダーを返す。
///
/// 呼び出し側が `add_service` で `Router` を作り、[`serve_router`] で起動する。
pub fn server_builder(config: &GrpcServerConfig) -> Server {
    Server::builder()
        .timeout(config.request_timeout)
        .concurrency_limit_per_connection(config.concurrency_per_connection as usize)
        .max_concurrent_streams(config.max_concurrent_streams)
        .http2_keepalive_interval(Some(config.keepalive_interval))
        .http2_keepalive_timeout(Some(config.keepalive_timeout))
        .http2_max_header_list_size(config.header_list_max_bytes)
}

/// レイテンシ分布のバケット数。保持量は操作ごとに固定（無制限に増えない）。
pub const LATENCY_BUCKETS: usize = 24;

/// マイクロ秒のレイテンシをバケット番号へ写す。0 は 0、`[2^(i-1), 2^i)` は `i`、
/// `2^(LATENCY_BUCKETS-2)`（約 4.2 秒）以上は最終バケットに集める。
fn latency_bucket(us: u64) -> usize {
    let i = (u64::BITS - us.leading_zeros()) as usize;
    i.min(LATENCY_BUCKETS - 1)
}

/// 操作ごとの成功・失敗・期限切れ件数とレイテンシの集計（REPAIR-4）。ロックを持たない。
struct OpCounters {
    buckets: [AtomicU64; LATENCY_BUCKETS],
    success: AtomicU64,
    failure: AtomicU64,
    timeout: AtomicU64,
    total_us: AtomicU64,
    max_us: AtomicU64,
}

impl OpCounters {
    const fn new() -> Self {
        Self {
            buckets: [const { AtomicU64::new(0) }; LATENCY_BUCKETS],
            success: AtomicU64::new(0),
            failure: AtomicU64::new(0),
            timeout: AtomicU64::new(0),
            total_us: AtomicU64::new(0),
            max_us: AtomicU64::new(0),
        }
    }

    fn record(&self, elapsed: Duration, result: Result<(), PluginErrorCode>) {
        let us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        match result {
            Ok(()) => self.success.fetch_add(1, Ordering::Relaxed),
            Err(PluginErrorCode::Timeout) => self.timeout.fetch_add(1, Ordering::Relaxed),
            Err(_) => self.failure.fetch_add(1, Ordering::Relaxed),
        };
        self.total_us.fetch_add(us, Ordering::Relaxed);
        self.max_us.fetch_max(us, Ordering::Relaxed);
        if let Some(b) = self.buckets.get(latency_bucket(us)) {
            b.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn snapshot(&self, op: &'static str) -> GrpcOpStats {
        GrpcOpStats {
            op,
            success: self.success.load(Ordering::Relaxed),
            failure: self.failure.load(Ordering::Relaxed),
            timeout: self.timeout.load(Ordering::Relaxed),
            total_us: self.total_us.load(Ordering::Relaxed),
            max_us: self.max_us.load(Ordering::Relaxed),
            latency_buckets: std::array::from_fn(|i| {
                self.buckets.get(i).map_or(0, |b| b.load(Ordering::Relaxed))
            }),
        }
    }
}

static STATS_SERVE: OpCounters = OpCounters::new();
static STATS_CONNECT: OpCounters = OpCounters::new();
static STATS_CALL: OpCounters = OpCounters::new();
/// 接続上限（PLUG-12）で拒否した接続の累計（プロセス全体）。
static STATS_REJECTED: AtomicU64 = AtomicU64::new(0);

/// 接続上限超過で拒否した接続の累計件数を返す（観測用。出力を伴わず panic・ブロックしない。PLUG-12・REPAIR-4/5）。
pub fn grpc_rejected_connections() -> u64 {
    STATS_REJECTED.load(Ordering::Relaxed)
}

/// 1 操作（`serve`・`connect`・`call`）の集計スナップショット（REPAIR-4）。
///
/// `timeout` は期限切れ（`PluginErrorCode::Timeout`）、`failure` はそれ以外の失敗。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcOpStats {
    /// 操作名（`serve`・`connect`・`call`）。
    pub op: &'static str,
    /// 成功件数。
    pub success: u64,
    /// 期限切れ以外の失敗件数。
    pub failure: u64,
    /// 期限切れ件数。
    pub timeout: u64,
    /// 全サンプルのレイテンシ合計（マイクロ秒）。
    pub total_us: u64,
    /// 最大レイテンシ（マイクロ秒）。
    pub max_us: u64,
    /// レイテンシ分布（件数）。番号 0 は 0us、`i` は `[2^(i-1), 2^i)` us、最終番号は上限以上を含む。
    pub latency_buckets: [u64; LATENCY_BUCKETS],
}

/// 全操作の集計スナップショットを返す（順序は `serve`・`connect`・`call`）。
pub fn grpc_stats() -> Vec<GrpcOpStats> {
    vec![
        STATS_SERVE.snapshot("serve"),
        STATS_CONNECT.snapshot("connect"),
        STATS_CALL.snapshot("call"),
    ]
}

/// 集計を JSON Lines（1 操作 1 行・LF 終端）で書き出す。書き込み失敗は `Internal`。
pub fn export_stats_json_lines<W: std::io::Write>(w: &mut W) -> Result<(), PluginError> {
    for s in grpc_stats() {
        let buckets = s
            .latency_buckets
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        writeln!(
            w,
            "{{\"event\":\"grpc_op_stats\",\"op\":\"{}\",\"success\":{},\"failure\":{},\"timeout\":{},\"total_us\":{},\"max_us\":{},\"latency_buckets\":[{}]}}",
            s.op, s.success, s.failure, s.timeout, s.total_us, s.max_us, buckets
        )
        .map_err(|e| PluginError::new(PluginErrorCode::Internal, format!("stats write failed: {e}")))?;
    }
    Ok(())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // ロック内で panic しうる処理を置かないため、poison でも状態は整合している。
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// 読み書き 1 組分の waker 置き場。
#[derive(Default)]
struct WakeSlot {
    read: Mutex<Option<Waker>>,
    write: Mutex<Option<Waker>>,
}

/// shutdown 猶予超過時に tonic が起動した接続タスクの IO を打ち切る仕組み（REPAIR-5）。
///
/// tonic は接続ごとにタスクを `spawn` するため、serve future を drop しても接続は止まらない。
/// 受け付けた IO を [`KillableIo`] で包み、[`KillSwitch::kill`] 後の読み書きをエラーにして
/// 接続タスクを自然終了させる。`live` は存命の IO 数で、回収の確認に使う。
struct KillSwitch {
    killed: AtomicBool,
    live: AtomicUsize,
    slots: Mutex<Vec<Weak<WakeSlot>>>,
}

impl KillSwitch {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            killed: AtomicBool::new(false),
            live: AtomicUsize::new(0),
            slots: Mutex::new(Vec::new()),
        })
    }

    fn is_killed(&self) -> bool {
        self.killed.load(Ordering::SeqCst)
    }

    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    fn register(&self, slot: &Arc<WakeSlot>) {
        let mut slots = lock(&self.slots);
        slots.retain(|w| w.strong_count() > 0);
        slots.push(Arc::downgrade(slot));
    }

    /// 全 IO を打ち切り、待機中の poll を起こす。
    fn kill(&self) {
        self.killed.store(true, Ordering::SeqCst);
        let slots: Vec<Arc<WakeSlot>> =
            lock(&self.slots).iter().filter_map(Weak::upgrade).collect();
        for slot in slots {
            if let Some(w) = lock(&slot.read).take() {
                w.wake();
            }
            if let Some(w) = lock(&slot.write).take() {
                w.wake();
            }
        }
    }
}

/// future の破棄（timeout・select!・abort）でも接続を強制停止する RAII ガード（REPAIR-5）。
struct KillOnDrop(Arc<KillSwitch>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        self.0.kill();
    }
}

fn killed_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::BrokenPipe,
        "grpc connection closed by shutdown grace expiry",
    )
}

/// 打ち切り可能な IO。`Connected` は内側へ委譲するため peer 情報は変わらない。
struct KillableIo<IO> {
    inner: IO,
    switch: Arc<KillSwitch>,
    slot: Arc<WakeSlot>,
}

impl<IO> KillableIo<IO> {
    fn new(inner: IO, switch: Arc<KillSwitch>) -> Self {
        let slot = Arc::new(WakeSlot::default());
        switch.register(&slot);
        switch.live.fetch_add(1, Ordering::SeqCst);
        Self {
            inner,
            switch,
            slot,
        }
    }
}

impl<IO> Drop for KillableIo<IO> {
    fn drop(&mut self) {
        self.switch.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<IO: tonic::transport::server::Connected> tonic::transport::server::Connected
    for KillableIo<IO>
{
    type ConnectInfo = IO::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.inner.connect_info()
    }
}

impl<IO: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for KillableIo<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.switch.is_killed() {
            return Poll::Ready(Err(killed_error()));
        }
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if r.is_pending() {
            *lock(&self.slot.read) = Some(cx.waker().clone());
            if self.switch.is_killed() {
                return Poll::Ready(Err(killed_error()));
            }
        }
        r
    }
}

impl<IO: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for KillableIo<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.switch.is_killed() {
            return Poll::Ready(Err(killed_error()));
        }
        let r = Pin::new(&mut self.inner).poll_write(cx, buf);
        if r.is_pending() {
            *lock(&self.slot.write) = Some(cx.waker().clone());
            if self.switch.is_killed() {
                return Poll::Ready(Err(killed_error()));
            }
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.switch.is_killed() {
            return Poll::Ready(Err(killed_error()));
        }
        let r = Pin::new(&mut self.inner).poll_flush(cx);
        if r.is_pending() {
            *lock(&self.slot.write) = Some(cx.waker().clone());
            if self.switch.is_killed() {
                return Poll::Ready(Err(killed_error()));
            }
        }
        r
    }

    /// 強制停止後は内側の shutdown を待たず終了させる。内側が Pending のままでも
    /// `kill` の waker で起こして `Ready(Err)` を返す（REPAIR-5）。
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.switch.is_killed() {
            return Poll::Ready(Err(killed_error()));
        }
        let r = Pin::new(&mut self.inner).poll_shutdown(cx);
        if r.is_pending() {
            *lock(&self.slot.write) = Some(cx.waker().clone());
            if self.switch.is_killed() {
                return Poll::Ready(Err(killed_error()));
            }
        }
        r
    }
}

/// incoming の各 IO を [`KillableIo`] で包む。
struct KillableIncoming<I, IO, IE> {
    inner: Pin<Box<I>>,
    switch: Arc<KillSwitch>,
    /// 同時接続数の上限。存命の [`KillableIo`]（= `switch.live`）がこれに達したら新規接続を拒否する。
    max_connections: usize,
    /// 上限超過でこのストリームが拒否した累計件数。
    rejected: u64,
    _marker: PhantomData<fn() -> (IO, IE)>,
}

impl<I, IO, IE> Stream for KillableIncoming<I, IO, IE>
where
    I: Stream<Item = Result<IO, IE>>,
{
    type Item = Result<KillableIo<IO>, IE>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // 1 回の poll で連続拒否できる件数（REPAIR-5）。内側が Ready を返し続けても実行権を返し、
        // 接続の drop・shutdown・猶予期限のタスクが進めるようにする。
        let mut rejected_in_poll = 0usize;
        loop {
            let this = &mut *self;
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(io))) => {
                    // 件数は IO の生成（ここ）で加算し drop で減算するため、枠は接続の寿命と一致する。
                    if this.switch.live() >= this.max_connections {
                        // 即 close して拒否し、次の accept に進む（枠が空くのを待たない）。
                        drop(io);
                        this.rejected = this.rejected.saturating_add(1);
                        // 出力先（stderr 等）の失敗・ブロックが accept ループを止めないよう、
                        // 有界メモリのアトミック計数だけを更新する（panic・ブロックなし。REPAIR-5）。
                        STATS_REJECTED.fetch_add(1, Ordering::Relaxed);
                        rejected_in_poll += 1;
                        if rejected_in_poll >= MAX_REJECTS_PER_POLL {
                            // 自分を再スケジュールして Pending を返し、内側の協調動作に依存しない。
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        continue;
                    }
                    return Poll::Ready(Some(Ok(KillableIo::new(io, Arc::clone(&this.switch)))));
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// `KillableIncoming::poll_next` が 1 回の poll で連続して拒否する接続数の上限。
const MAX_REJECTS_PER_POLL: usize = 64;

/// 強制停止後に接続タスクの終了（IO の drop）を待つ上限。
const FORCE_RECLAIM_WAIT: Duration = Duration::from_secs(2);

/// `Router` を任意の incoming ストリームで起動し、`shutdown` の完了で graceful shutdown する。
///
/// shutdown 信号の後、`config` の shutdown 猶予内にサーバーが終わらなければ、受け付け済みの全接続を
/// 強制的に閉じ（tonic が起動した接続タスクの IO を打ち切る）、タスクの終了を `FORCE_RECLAIM_WAIT`
/// まで待って回収を確認したうえで `Timeout` を返す（接続が居座っても無期限に待たず、タスクも残さない。
/// REPAIR-5）。トランスポートの listener は呼び出し側が作る。結果は [`grpc_stats`] の `serve` に記録する。
pub async fn serve_router<I, IO, IE, F>(
    router: Router,
    incoming: I,
    shutdown: F,
    config: &GrpcServerConfig,
) -> Result<(), PluginError>
where
    I: Stream<Item = Result<IO, IE>>,
    IO: tokio::io::AsyncRead
        + tokio::io::AsyncWrite
        + tonic::transport::server::Connected
        + Unpin
        + Send
        + 'static,
    IE: Into<Box<dyn std::error::Error + Send + Sync>>,
    F: Future<Output = ()>,
{
    let started = Instant::now();
    let r = serve_router_inner(router, incoming, shutdown, config).await;
    STATS_SERVE.record(
        started.elapsed(),
        r.as_ref().map(|_| ()).map_err(|e| e.code()),
    );
    r
}

async fn serve_router_inner<I, IO, IE, F>(
    router: Router,
    incoming: I,
    shutdown: F,
    config: &GrpcServerConfig,
) -> Result<(), PluginError>
where
    I: Stream<Item = Result<IO, IE>>,
    IO: tokio::io::AsyncRead
        + tokio::io::AsyncWrite
        + tonic::transport::server::Connected
        + Unpin
        + Send
        + 'static,
    IE: Into<Box<dyn std::error::Error + Send + Sync>>,
    F: Future<Output = ()>,
{
    let switch = KillSwitch::new();
    let _kill_on_drop = KillOnDrop(Arc::clone(&switch));
    let wrapped = KillableIncoming {
        inner: Box::pin(incoming),
        switch: Arc::clone(&switch),
        max_connections: config.max_connections as usize,
        rejected: 0,
        _marker: PhantomData,
    };
    let fired = Arc::new(AtomicBool::new(false));
    let fired_in = Arc::clone(&fired);
    let serve = router.serve_with_incoming_shutdown(wrapped, async move {
        shutdown.await;
        fired_in.store(true, Ordering::SeqCst);
    });
    let mut serve = pin!(serve);
    let mut deadline: Option<Pin<Box<tokio::time::Sleep>>> = None;
    let grace = config.shutdown_grace;
    // 第 1 段: 猶予内の自然終了を待つ。`Some(結果)` なら終了、`None` なら猶予超過。
    let first = poll_fn(|cx| {
        if let Poll::Ready(r) = serve.as_mut().poll(cx) {
            return Poll::Ready(Some(r.map_err(|e| transport_error_to_plugin(&e))));
        }
        if fired.load(Ordering::SeqCst) {
            let sleep = deadline.get_or_insert_with(|| Box::pin(tokio::time::sleep(grace)));
            if sleep.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
        }
        Poll::Pending
    })
    .await;
    if let Some(r) = first {
        return r;
    }
    // 第 2 段: 接続を強制的に閉じ、serve と接続タスクの終了を上限付きで待つ。
    switch.kill();
    let mut reclaim = Box::pin(tokio::time::sleep(FORCE_RECLAIM_WAIT));
    let mut tick = Box::pin(tokio::time::sleep(Duration::from_millis(10)));
    let mut serve_done = false;
    poll_fn(|cx| {
        if !serve_done && serve.as_mut().poll(cx).is_ready() {
            serve_done = true;
        }
        if serve_done && switch.live() == 0 {
            return Poll::Ready(());
        }
        if reclaim.as_mut().poll(cx).is_ready() {
            return Poll::Ready(());
        }
        // live の減少は waker を持たないため、10ms 周期のタイマーで再 poll する（tokio の rt は使わない）。
        while tick.as_mut().poll(cx).is_ready() {
            tick.as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_millis(10));
            if serve_done && switch.live() == 0 {
                return Poll::Ready(());
            }
            if !serve_done && serve.as_mut().poll(cx).is_ready() {
                serve_done = true;
            }
        }
        Poll::Pending
    })
    .await;
    let reclaimed = serve_done && switch.live() == 0;
    Err(PluginError::new(
        PluginErrorCode::Timeout,
        format!(
            "grpc server did not shut down within the grace period; connections force-closed (reclaimed={reclaimed})"
        ),
    ))
}

/// 接続を確立する。`connect_timeout` で二重に保護し、期限切れは `Timeout`、接続失敗は `Unavailable`。
///
/// 結果は [`grpc_stats`] の `connect` に記録する。UDS 経由の接続は `connect_uds_channel`
/// （TASK-108.2・#454。PLUG-2・PLUG-12）を使う。
pub async fn connect_channel(
    endpoint: Endpoint,
    connect_timeout: Duration,
) -> Result<Channel, PluginError> {
    connect_recorded(connect_timeout, async {
        endpoint
            .connect()
            .await
            .map_err(|e| transport_error_to_plugin(&e))
    })
    .await
}

/// 接続 future を二重の期限で包み、結果を `connect` の集計へ記録する（`connect_channel` と
/// `connect_uds_channel` の共通部。REPAIR-4・REPAIR-5）。`fut` は期間の検証に通った場合のみ poll する。
async fn connect_recorded<F>(connect_timeout: Duration, fut: F) -> Result<Channel, PluginError>
where
    F: Future<Output = Result<Channel, PluginError>>,
{
    let started = Instant::now();
    let r = match check_duration(connect_timeout, "connect timeout") {
        Err(e) => Err(e),
        Ok(connect_timeout) => match tokio::time::timeout(connect_timeout, fut).await {
            Err(_) => Err(PluginError::new(
                PluginErrorCode::Timeout,
                "grpc connect timed out",
            )),
            Ok(r) => r,
        },
    };
    STATS_CONNECT.record(
        started.elapsed(),
        r.as_ref().map(|_| ()).map_err(|e| e.code()),
    );
    r
}

#[cfg(unix)]
mod uds {
    use super::*;

    // ---------------------------------------------------------------------------------------------
    // UDS 上の tonic 統合（TASK-108.2・#454・PLUG-2・PLUG-12）。unix のみ（WIN-1）。
    // ---------------------------------------------------------------------------------------------

    /// UDS の待ち受けを tonic の incoming ストリームにする（サーバー側。PLUG-2・PLUG-12）。
    ///
    /// 呼び出し元は `fandhe-container-plugin-cri` の `server`（#849）で、[`serve_router`] へ渡す。
    /// 配置検証（自 UID 所有・0700 相当・symlink 不可）・0600 化・stale 掃除・`sun_path` 長検査は
    /// `UdsListener::bind` が行い、本型は再実装しない。`UdsListener` を所有するため、drop で
    /// socket ファイルと bind ロックが後始末される。
    ///
    /// accept ごとに、tonic が最初の read をする前に peer UID を `uds_security::verify_peer` で検証する。
    /// 不一致・取得不能は切断し、監査イベントを `observer` へ 1 件通知して次の accept に進む（サーバーは
    /// 止まらない。UID 値は返却エラーにもログにも載せない）。`observer` は受付の中で同期に呼ばれるため
    /// ブロックしない実装であること（`PeerAuthObserver` の契約）。
    ///
    /// peer 拒否が続くと（別 UID の相手の接続・切断の連打）、連続 4 件目から 10ms 起点で倍々に待ち、
    /// 上限 500ms で頭打ちにする。peer 照合に合格した接続を受理したら解除する（PLUG-12・REPAIR-5）。
    /// 連続回数と待ちは監査イベントの `consecutive_rejections`・`backoff_ms` に載る（REPAIR-4）。
    ///
    /// accept の I/O エラー（fd 枯渇等）は `Err` として流し、tonic が記録して継続する。直後は 10ms の
    /// バックオフを挟み busy loop を避ける（REPAIR-5）。
    ///
    /// close-on-exec（PLUG-7・SEC-1・#3262）: 待ち受け fd は `UdsListener::bind`（spawn ゲートの中）で作った fd の
    /// `F_DUPFD_CLOEXEC` による複製で原子的。accept で得る接続は macOS では mio が `accept(2)` の後に
    /// `fcntl` で立てるため非原子でゲート外。同じプロセスに `spawn_gate::spawn` が無い間は実害がない
    /// （範囲と見直す条件は `spawn_gate` のモジュール doc を参照）。
    ///
    /// `new` は tokio ランタイムの内側で呼ぶこと（reactor へ登録するため）。
    pub struct UdsIncoming {
        /// 非同期 accept 用（`listener` の fd を dup したもの）。
        inner: tokio::net::UnixListener,
        /// socket ファイル・bind ロックの所有者（RAII）。
        listener: crate::UdsListener,
        expected_uid: u32,
        observer: Box<dyn crate::PeerAuthObserver>,
        backoff: Option<Pin<Box<tokio::time::Sleep>>>,
        /// peer 拒否の連続回数と待ち（PLUG-12・REPAIR-5）。
        peer_reject: PeerRejectBackoff,
    }

    /// accept エラー後のバックオフ。
    const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(10);
    /// 待たずに処理する連続 peer 拒否の件数（単発の拒否で正当な接続を遅らせない）。
    const PEER_REJECT_BACKOFF_FREE: u32 = 3;
    /// peer 拒否が `PEER_REJECT_BACKOFF_FREE` 件を超えた最初の待ち。
    const PEER_REJECT_BACKOFF_BASE: Duration = Duration::from_millis(10);
    /// peer 拒否のバックオフの上限。拒否の連打の最中に正当な同 UID の client が受ける追加遅延の
    /// 最悪値でもある（client の接続期限の既定より十分小さい）。
    const PEER_REJECT_BACKOFF_MAX: Duration = Duration::from_millis(500);

    /// peer 拒否の連続回数と待ちを決める状態機械（PLUG-12・REPAIR-5）。`UdsIncoming::poll_next` が使う。
    ///
    /// 別 UID の相手が接続と切断を繰り返しても受け付けが空回りしないよう、連続拒否が
    /// `PEER_REJECT_BACKOFF_FREE` 件を超えたら `BASE` 起点で倍々に待ち、`MAX` で頭打ちにする。
    /// 解除は「peer 照合に合格した接続の受理」だけで行う。待ち行列が空（`Pending`）になった時点では
    /// 解除しない。相手が間を空けて 1 接続ずつ繰り返すと毎回解除されて抑止が効かなくなるため。
    #[derive(Debug, Default)]
    pub(super) struct PeerRejectBackoff {
        streak: u32,
    }

    impl PeerRejectBackoff {
        /// 拒否を 1 件数え、(連続回数, この拒否の後の待ち) を返す。演算は飽和で panic しない。
        pub(super) fn on_rejection(&mut self) -> (u32, Duration) {
            self.streak = self.streak.saturating_add(1);
            let over = self.streak.saturating_sub(PEER_REJECT_BACKOFF_FREE);
            if over == 0 {
                return (self.streak, Duration::ZERO);
            }
            let factor = 1u32.checked_shl(over.saturating_sub(1)).unwrap_or(u32::MAX);
            let wait = PEER_REJECT_BACKOFF_BASE
                .checked_mul(factor)
                .map_or(PEER_REJECT_BACKOFF_MAX, |d| d.min(PEER_REJECT_BACKOFF_MAX));
            (self.streak, wait)
        }

        /// 合格した接続を受理したので連続回数を戻す。
        pub(super) fn on_accepted(&mut self) {
            self.streak = 0;
        }
    }

    impl UdsIncoming {
        /// bind 済みの `listener` を incoming にする。fd の dup・tokio 化に失敗したら `Internal`。
        pub fn new(
            listener: crate::UdsListener,
            observer: Box<dyn crate::PeerAuthObserver>,
        ) -> Result<Self, PluginError> {
            let expected_uid = listener.expected_uid();
            Self::with_expected_uid(listener, observer, expected_uid)
        }

        /// 期待 UID を指定して作る。公開経路は常に bind 時の実効 UID を渡す `new`。
        /// 検証を省く経路ではなく、テストで期待値だけをずらして拒否経路を再現するために分けている。
        pub(super) fn with_expected_uid(
            listener: crate::UdsListener,
            observer: Box<dyn crate::PeerAuthObserver>,
            expected_uid: u32,
        ) -> Result<Self, PluginError> {
            let internal = |msg: &'static str| PluginError::new(PluginErrorCode::Internal, msg);
            let std_listener = listener.try_clone_std_listener()?;
            std_listener
                .set_nonblocking(true)
                .map_err(|_| internal("failed to configure listener"))?;
            let inner = tokio::net::UnixListener::from_std(std_listener)
                .map_err(|_| internal("failed to register listener with the runtime"))?;
            Ok(Self {
                inner,
                listener,
                expected_uid,
                observer,
                backoff: None,
                peer_reject: PeerRejectBackoff::default(),
            })
        }

        /// crate 外の結合試験用: 期待 UID を指定して作る（#2484・PLUG-12）。
        ///
        /// 自プロセスからの接続を別 UID 相当として拒否させ、実際の `SO_PEERCRED` 照合と observer 通知の
        /// 全経路を通すための口。`with_expected_uid` に委ねるだけで、照合を省く経路ではない。
        /// feature `test-support`（既定で無効。本番の依存では有効にしない）の下にだけ存在する。
        #[cfg(feature = "test-support")]
        #[doc(hidden)]
        pub fn with_expected_uid_for_test(
            listener: crate::UdsListener,
            observer: Box<dyn crate::PeerAuthObserver>,
            expected_uid: u32,
        ) -> Result<Self, PluginError> {
            Self::with_expected_uid(listener, observer, expected_uid)
        }

        /// 試験用: 期待 UID を差し替える（`with_expected_uid` と同じ趣旨で、照合を省く経路ではない）。
        #[cfg(test)]
        pub(super) fn set_expected_uid_for_test(&mut self, uid: u32) {
            self.expected_uid = uid;
        }

        /// 試験用: 現在の連続 peer 拒否回数。
        #[cfg(test)]
        pub(super) fn peer_reject_streak(&self) -> u32 {
            self.peer_reject.streak
        }

        /// 試験用: peer 拒否または accept エラーの待ちが残っているか。
        #[cfg(test)]
        pub(super) fn has_backoff(&self) -> bool {
            self.backoff.is_some()
        }

        /// client が接続に使う socket のパス（`UdsListener::path`）。
        pub fn path(&self) -> &Path {
            self.listener.path()
        }
    }

    impl Stream for UdsIncoming {
        type Item = Result<tokio::net::UnixStream, std::io::Error>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = &mut *self;
            if let Some(sleep) = this.backoff.as_mut() {
                if sleep.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                this.backoff = None;
            }
            loop {
                match this.inner.poll_accept(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => {
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::Interrupted
                                | std::io::ErrorKind::ConnectionAborted
                                | std::io::ErrorKind::WouldBlock
                        ) {
                            continue;
                        }
                        this.backoff = Some(Box::pin(tokio::time::sleep(ACCEPT_ERROR_BACKOFF)));
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Ready(Ok((stream, _))) => {
                        // peer 認証は std の stream に対して行い、合格後に tokio へ戻す。
                        // 最初の read より前に検証が終わる（PLUG-12・TASK-124.6 と同じ不変条件）。
                        let Ok(std_stream) = stream.into_std() else {
                            continue;
                        };
                        if let Err(rej) =
                            crate::uds_security::verify_peer(&std_stream, this.expected_uid)
                        {
                            // 「切断 → 監査通知」の順（`transport` の accept と同じ。SEC-4）。
                            drop(std_stream);
                            let (streak, wait) = this.peer_reject.on_rejection();
                            this.observer.on_rejection(&crate::PeerAuthRejection {
                                op: crate::PeerAuthOp::Accept,
                                reason: rej.reason,
                                code: rej.error.code(),
                                expected_uid: this.expected_uid,
                                peer_uid: rej.peer_uid,
                                expected_pid: None,
                                peer_pid: None,
                                consecutive_rejections: Some(streak),
                                backoff_ms: Some(
                                    u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                                ),
                                socket_path: this.listener.path(),
                            });
                            if wait.is_zero() {
                                continue;
                            }
                            // 何も yield せず Pending を返すため、sleep をここで 1 回 poll して
                            // waker をタイマーへ登録する（しないと受け付けが止まる）。
                            let mut sleep = Box::pin(tokio::time::sleep(wait));
                            if sleep.as_mut().poll(cx).is_pending() {
                                this.backoff = Some(sleep);
                                return Poll::Pending;
                            }
                            continue;
                        }
                        match tokio::net::UnixStream::from_std(std_stream) {
                            Ok(s) => {
                                this.peer_reject.on_accepted();
                                return Poll::Ready(Some(Ok(s)));
                            }
                            Err(_) => continue,
                        }
                    }
                }
            }
        }
    }

    /// UDS へつなぐ tonic の connector（クライアント側。PLUG-2・PLUG-12）。
    ///
    /// `Channel` が再接続するたびに呼ばれるため、接続ごとに server の peer UID を検証する。不一致・取得不能は
    /// 何も送らず切断し、監査イベントを通知する。失敗の `PluginError` は `last_error` へ残し、
    /// [`connect_uds_channel`] が tonic の汎用エラーの代わりに返す（コード契約を `UdsStream::connect` と揃える）。
    ///
    /// close-on-exec（#3262）: client の socket は macOS では mio が `socket(2)` の後に `fcntl` で立てるため
    /// 非原子でゲート外（`spawn_gate` のモジュール doc を参照）。
    #[derive(Clone)]
    struct UdsConnector {
        path: Arc<PathBuf>,
        expected_uid: u32,
        connect_timeout: Duration,
        observer: Arc<Mutex<Box<dyn crate::PeerAuthObserver>>>,
        last_error: Arc<Mutex<Option<PluginError>>>,
    }

    impl UdsConnector {
        async fn connect_verified(&self) -> Result<tokio::net::UnixStream, PluginError> {
            let stream = match tokio::time::timeout(
                self.connect_timeout,
                tokio::net::UnixStream::connect(self.path.as_path()),
            )
            .await
            {
                Err(_) => {
                    return Err(crate::transport::map_connect_io_error(
                        std::io::ErrorKind::TimedOut,
                    ));
                }
                Ok(Err(e)) => return Err(crate::transport::map_connect_io_error(e.kind())),
                Ok(Ok(s)) => s,
            };
            let internal = || {
                PluginError::new(
                    PluginErrorCode::Internal,
                    "failed to configure connected stream",
                )
            };
            let std_stream = stream.into_std().map_err(|_| internal())?;
            // 偽 listener への誘導対策（PLUG-12）。最初の送信より前に検証し、不一致は何も送らず切断する。
            if let Err(rej) = crate::uds_security::verify_peer(&std_stream, self.expected_uid) {
                drop(std_stream);
                lock(&self.observer).on_rejection(&crate::PeerAuthRejection {
                    op: crate::PeerAuthOp::Connect,
                    reason: rej.reason,
                    code: rej.error.code(),
                    expected_uid: self.expected_uid,
                    peer_uid: rej.peer_uid,
                    expected_pid: None,
                    peer_pid: None,
                    consecutive_rejections: None,
                    backoff_ms: None,
                    socket_path: self.path.as_path(),
                });
                return Err(rej.error);
            }
            tokio::net::UnixStream::from_std(std_stream).map_err(|_| internal())
        }
    }

    impl tonic::codegen::Service<tonic::codegen::http::Uri> for UdsConnector {
        type Response = hyper_util::rt::TokioIo<tokio::net::UnixStream>;
        type Error = std::io::Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        /// URI は使わない（接続先は保持する socket パスのみ）。
        fn call(&mut self, _uri: tonic::codegen::http::Uri) -> Self::Future {
            let this = self.clone();
            Box::pin(async move {
                match this.connect_verified().await {
                    Ok(s) => Ok(hyper_util::rt::TokioIo::new(s)),
                    Err(e) => {
                        *lock(&this.last_error) = Some(e);
                        Err(std::io::Error::other("uds connect failed"))
                    }
                }
            })
        }
    }

    /// UDS 経由で gRPC の `Channel` を確立する（クライアント側。PLUG-2・PLUG-12・REPAIR-5）。
    ///
    /// 呼び出し元は core 側 proxy（TASK-114）。`path` は `UdsListener::path` 相当で、空・NUL・
    /// `sun_path` 超過は `InvalidArgument`。存在しなければ `NotFound`、listener 不在の stale socket は
    /// `Unavailable`、期限切れは `Timeout`、server の peer UID が自 UID でない場合は `PermissionDenied`
    /// （取得不能な環境は `Unimplemented`。fail-closed）。再接続のたびに peer UID を再検証する。
    /// 拒否は `observer` へ通知する（`UdsStream::connect` と同じ契約）。結果は [`grpc_stats`] の `connect` に記録する。
    pub async fn connect_uds_channel(
        path: &Path,
        config: &GrpcClientConfig,
        observer: Box<dyn crate::PeerAuthObserver>,
    ) -> Result<Channel, PluginError> {
        connect_uds_channel_with_uid(path, config, observer, crate::sys::effective_uid()).await
    }

    /// `connect_uds_channel` の本体。期待 UID を引数に取るのはテストで期待値をずらすためで、公開経路は
    /// 常に自 euid を渡す。
    pub(super) async fn connect_uds_channel_with_uid(
        path: &Path,
        config: &GrpcClientConfig,
        observer: Box<dyn crate::PeerAuthObserver>,
        expected_uid: u32,
    ) -> Result<Channel, PluginError> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        let precheck = if bytes.is_empty() || bytes.contains(&0) {
            Err(invalid("invalid socket path"))
        } else {
            crate::transport::check_sun_path_len(path)
        };
        connect_recorded(config.connect_timeout, async {
            // 検証を通る前に入力を複製しない（長さ上限検証 → アロケーションの順。巨大パスでの確保を防ぐ）。
            precheck?;
            let last_error = Arc::new(Mutex::new(None));
            let connector = UdsConnector {
                path: Arc::new(path.to_path_buf()),
                expected_uid,
                connect_timeout: config.connect_timeout,
                observer: Arc::new(Mutex::new(observer)),
                last_error: Arc::clone(&last_error),
            };
            // URI は connector が無視するダミー（HTTP/2 の :authority にだけ使われる）。
            let endpoint = Endpoint::from_shared("http://localhost")
                .map_err(|_| PluginError::new(PluginErrorCode::Internal, "invalid endpoint"))?;
            match config
                .apply(endpoint)
                .connect_with_connector(connector)
                .await
            {
                Ok(ch) => Ok(ch),
                Err(e) => Err(lock(&last_error)
                    .take()
                    .unwrap_or_else(|| transport_error_to_plugin(&e))),
            }
        })
        .await
    }
}

#[cfg(unix)]
pub use uds::{UdsIncoming, connect_uds_channel};

/// RPC 全体を期限で包む（REPAIR-5）。
///
/// `Endpoint::timeout` は応答ヘッダまでしか保護しないため、応答本文や trailers の読み取りまで含めて
/// 待つ future（unary の完了・`Streaming::message()`・`Streaming::trailers()` 等）をここへ渡す。
/// 期限切れは `Timeout`、`Status` は [`status_to_plugin_error`] で写す。結果は [`grpc_stats`] の
/// `call` に記録する。
pub async fn call_with_deadline<T, F>(fut: F, deadline: Duration) -> Result<T, PluginError>
where
    F: Future<Output = Result<T, tonic::Status>>,
{
    let started = Instant::now();
    let r = match check_duration(deadline, "call deadline") {
        Err(e) => Err(e),
        Ok(deadline) => match tokio::time::timeout(deadline, fut).await {
            Err(_) => Err(PluginError::new(
                PluginErrorCode::Timeout,
                "grpc call deadline exceeded",
            )),
            Ok(Err(status)) => Err(status_to_plugin_error(&status)),
            Ok(Ok(v)) => Ok(v),
        },
    };
    STATS_CALL.record(
        started.elapsed(),
        r.as_ref().map(|_| ()).map_err(|e| e.code()),
    );
    r
}

/// ストリーミング応答の次の 1 メッセージを期限付きで読む（REPAIR-5）。ストリーム終端は `Ok(None)`。
///
/// 1 メッセージごとに `deadline` を適用するため、本文が途中で止まったストリームも無期限には待たない。
pub async fn read_stream_message<T>(
    stream: &mut tonic::Streaming<T>,
    deadline: Duration,
) -> Result<Option<T>, PluginError> {
    call_with_deadline(stream.message(), deadline).await
}
/// tonic の転送エラーを `PluginError` へ写す。接続系は `Unavailable` に倒す。
pub fn transport_error_to_plugin(e: &tonic::transport::Error) -> PluginError {
    PluginError::new(
        PluginErrorCode::Unavailable,
        format!("grpc transport error: {e}"),
    )
}

/// tonic の `Status` を `PluginError` へ写す（上表）。message は上限長で切り詰められる。
pub fn status_to_plugin_error(status: &tonic::Status) -> PluginError {
    use tonic::Code;
    let code = match status.code() {
        // tonic のサーバー側タイムアウトは Cancelled "Timeout expired" で返る。
        Code::Cancelled if status.message() == "Timeout expired" => PluginErrorCode::Timeout,
        Code::Unavailable | Code::Aborted | Code::Cancelled => PluginErrorCode::Unavailable,
        Code::DeadlineExceeded => PluginErrorCode::Timeout,
        Code::InvalidArgument | Code::OutOfRange => PluginErrorCode::InvalidArgument,
        Code::NotFound => PluginErrorCode::NotFound,
        Code::AlreadyExists => PluginErrorCode::AlreadyExists,
        Code::PermissionDenied | Code::Unauthenticated => PluginErrorCode::PermissionDenied,
        Code::FailedPrecondition => PluginErrorCode::FailedPrecondition,
        Code::Unimplemented => PluginErrorCode::Unimplemented,
        Code::ResourceExhausted => PluginErrorCode::ResourceExhausted,
        Code::DataLoss => PluginErrorCode::DataLoss,
        _ => PluginErrorCode::Internal,
    };
    PluginError::new(code, status.message())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 接続上限: 上限到達で追加接続は拒否され、接続を drop すると枠が戻る（PLUG-12・REPAIR-12）。
    #[tokio::test]
    async fn max_connections_rejects_then_recovers() {
        use std::collections::VecDeque;
        use tokio::io::DuplexStream;

        struct Feed(Arc<Mutex<VecDeque<DuplexStream>>>);
        impl Stream for Feed {
            type Item = Result<DuplexStream, std::io::Error>;
            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Ready(self.0.lock().unwrap().pop_front().map(Ok))
            }
        }
        let q: Arc<Mutex<VecDeque<DuplexStream>>> = Arc::default();
        let switch = KillSwitch::new();
        let mut inc: KillableIncoming<Feed, DuplexStream, std::io::Error> = KillableIncoming {
            inner: Box::pin(Feed(Arc::clone(&q))),
            switch: Arc::clone(&switch),
            max_connections: 2,
            rejected: 0,
            _marker: PhantomData,
        };
        for _ in 0..3 {
            q.lock().unwrap().push_back(tokio::io::duplex(64).0);
        }
        let mut accepted = Vec::new();
        while let Some(r) = poll_fn(|cx| Pin::new(&mut inc).poll_next(cx)).await {
            accepted.push(r.unwrap());
        }
        assert_eq!(accepted.len(), 2);
        assert_eq!(switch.live(), 2);
        assert_eq!(inc.rejected, 1);
        assert!(grpc_rejected_connections() >= 1);
        accepted.pop();
        assert_eq!(switch.live(), 1);
        q.lock().unwrap().push_back(tokio::io::duplex(64).0);
        let again = poll_fn(|cx| Pin::new(&mut inc).poll_next(cx)).await;
        assert!(again.is_some());
        assert_eq!(switch.live(), 2);
        assert_eq!(inc.rejected, 1);
    }

    /// 拒否が無限に続く内側ストリームでも 1 poll の拒否数が上限で止まり、Pending と再 wake を返す（REPAIR-5）。
    #[tokio::test]
    async fn reject_burst_yields_pending_and_rewakes() {
        use std::sync::atomic::AtomicUsize;
        use std::task::{Wake, Waker};
        use tokio::io::DuplexStream;

        struct Endless;
        impl Stream for Endless {
            type Item = Result<DuplexStream, std::io::Error>;
            fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                Poll::Ready(Some(Ok(tokio::io::duplex(8).0)))
            }
        }
        struct Counter(AtomicUsize);
        impl Wake for Counter {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let switch = KillSwitch::new();
        let mut inc: KillableIncoming<Endless, DuplexStream, std::io::Error> = KillableIncoming {
            inner: Box::pin(Endless),
            switch: Arc::clone(&switch),
            max_connections: 0,
            rejected: 0,
            _marker: PhantomData,
        };
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counter));
        let mut cx = Context::from_waker(&waker);
        let r = Pin::new(&mut inc).poll_next(&mut cx);
        assert!(r.is_pending());
        assert_eq!(inc.rejected, MAX_REJECTS_PER_POLL as u64);
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn max_connections_validation() {
        assert_eq!(GrpcServerConfig::new().max_connections(), 64);
        assert_eq!(
            GrpcServerConfig::new()
                .with_max_connections(0)
                .unwrap_err()
                .code(),
            PluginErrorCode::InvalidArgument
        );
        assert_eq!(
            GrpcServerConfig::new()
                .with_max_connections(GRPC_CONCURRENCY_MAX + 1)
                .unwrap_err()
                .code(),
            PluginErrorCode::InvalidArgument
        );
        assert!(GrpcServerConfig::new().with_max_connections(1).is_ok());
    }

    /// 境界値: 上限ちょうどは成功し、0 と上限超過は InvalidArgument（REPAIR-2・REPAIR-5）。
    #[test]
    fn config_validation_boundaries() {
        assert!(
            GrpcServerConfig::new()
                .with_request_timeout(GRPC_TIMEOUT_MAX)
                .is_ok()
        );
        let e = GrpcServerConfig::new()
            .with_request_timeout(Duration::ZERO)
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        let e = GrpcServerConfig::new()
            .with_request_timeout(GRPC_TIMEOUT_MAX + Duration::from_secs(1))
            .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert!(
            GrpcServerConfig::new()
                .with_max_concurrent_streams(GRPC_CONCURRENCY_MAX)
                .is_ok()
        );
        assert_eq!(
            GrpcServerConfig::new()
                .with_max_concurrent_streams(0)
                .unwrap_err()
                .code(),
            PluginErrorCode::InvalidArgument
        );
        assert_eq!(
            GrpcServerConfig::new()
                .with_header_list_max_bytes(GRPC_HEADER_LIST_MAX_BYTES + 1)
                .unwrap_err()
                .code(),
            PluginErrorCode::InvalidArgument
        );
        assert_eq!(
            GrpcClientConfig::new()
                .with_connect_timeout(Duration::ZERO)
                .unwrap_err()
                .code(),
            PluginErrorCode::InvalidArgument
        );
    }

    /// ガードの破棄で KillSwitch が kill される（future 破棄経路。REPAIR-5）。
    #[test]
    fn kill_on_drop_kills_switch() {
        let switch = KillSwitch::new();
        assert!(!switch.is_killed());
        drop(KillOnDrop(Arc::clone(&switch)));
        assert!(switch.is_killed());
    }

    /// shutdown が永久に Pending の内側 IO でも kill で解除される（REPAIR-5）。
    #[tokio::test]
    async fn poll_shutdown_released_by_kill() {
        use tokio::io::AsyncWriteExt;
        struct Stuck;
        impl tokio::io::AsyncWrite for Stuck {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                b: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Poll::Ready(Ok(b.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Pending
            }
        }
        let switch = KillSwitch::new();
        let mut io = KillableIo::new(Stuck, Arc::clone(&switch));
        let killer = Arc::clone(&switch);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            killer.kill();
        });
        let r = tokio::time::timeout(Duration::from_secs(5), io.shutdown())
            .await
            .expect("shutdown must be released by kill");
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), killed_error().kind());
    }

    /// レイテンシ分布のバケット境界（REPAIR-4）。
    #[test]
    fn latency_bucket_boundaries() {
        assert_eq!(latency_bucket(0), 0);
        assert_eq!(latency_bucket(1), 1);
        assert_eq!(latency_bucket(2), 2);
        assert_eq!(latency_bucket(3), 2);
        assert_eq!(latency_bucket(4), 3);
        assert_eq!(latency_bucket(u64::MAX), LATENCY_BUCKETS - 1);
        let c = OpCounters::new();
        c.record(Duration::from_micros(3), Ok(()));
        c.record(Duration::from_micros(3), Ok(()));
        let snap = c.snapshot("t");
        assert_eq!(snap.latency_buckets[2], 2);
        assert_eq!(snap.latency_buckets.iter().sum::<u64>(), 2);
    }

    /// Status のコード対応表（モジュール doc の表）。
    #[test]
    fn status_mapping() {
        let m = |c| status_to_plugin_error(&tonic::Status::new(c, "x")).code();
        assert_eq!(m(tonic::Code::DeadlineExceeded), PluginErrorCode::Timeout);
        assert_eq!(m(tonic::Code::OutOfRange), PluginErrorCode::InvalidArgument);
        assert_eq!(
            m(tonic::Code::Unauthenticated),
            PluginErrorCode::PermissionDenied
        );
        assert_eq!(
            m(tonic::Code::ResourceExhausted),
            PluginErrorCode::ResourceExhausted
        );
        assert_eq!(m(tonic::Code::Unknown), PluginErrorCode::Internal);
    }
}

/// UDS 統合の peer 認証拒否経路（PLUG-12・SEC-4・TASK-108.2）。別 UID を実際には作れないため、
/// 期待 UID だけをずらして拒否を再現する（検証を省く経路ではない）。`peer_uid` が取得できる
/// 環境（`transport` のテストと同じ cfg）に限る。
#[cfg(all(
    test,
    any(
        target_os = "macos",
        all(
            target_os = "linux",
            target_pointer_width = "64",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod uds_peer_auth_tests {
    use super::uds::{UdsIncoming, connect_uds_channel_with_uid};
    use super::*;
    use crate::{
        PeerAuthObserver, PeerAuthOp, PeerAuthRejectReason, PeerAuthRejection, UdsListener,
    };
    use std::io::{Read, Write};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::net::UnixStream as StdStream;
    use std::sync::atomic::AtomicU32;

    type Events = Arc<Mutex<Vec<(PeerAuthOp, PeerAuthRejectReason)>>>;
    type BackoffEvents = Arc<Mutex<Vec<(Option<u32>, Option<u64>)>>>;

    struct BackoffRecorder(BackoffEvents);
    impl PeerAuthObserver for BackoffRecorder {
        fn on_rejection(&mut self, e: &PeerAuthRejection<'_>) {
            self.0
                .lock()
                .unwrap()
                .push((e.consecutive_rejections, e.backoff_ms));
        }
    }

    struct Recorder(Events);
    impl PeerAuthObserver for Recorder {
        fn on_rejection(&mut self, e: &PeerAuthRejection<'_>) {
            self.0.lock().unwrap().push((e.op, e.reason));
        }
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fcgp-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn other_uid() -> u32 {
        crate::sys::effective_uid().wrapping_add(1)
    }

    /// nonblocking の client stream が切断（EOF または reset 系）を観測するまで期限つきで待つ。
    /// 拒否側 server の close を待つ試験用の補助で、`set_read_timeout` が macOS で EINVAL になる
    /// 競合を避ける（`crates/io` の `is_peer_shutdown_einval` と同じ事情。#2711・PLUG-12・REPAIR-5）。
    /// 期限内に切断を観測できなければ panic する（期限切れを EOF 扱いにして通さない。REPAIR-12）。
    fn read_until_disconnect(c: &mut StdStream, deadline: std::time::Instant) -> usize {
        let mut buf = [0u8; 8];
        loop {
            match c.read(&mut buf) {
                Ok(n) => return n,
                Err(e) => match e.kind() {
                    std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe => return 0,
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "no disconnect observed from the rejecting server within the deadline"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    _ => panic!("unexpected read error: {e:?}"),
                },
            }
        }
    }

    /// サーバー側: 不一致の接続は切断され、Accept 拒否が 1 件通知され、
    /// incoming は終了せず継続する（PLUG-12・SEC-4）。
    #[tokio::test]
    async fn plug12_server_rejects_mismatched_peer_and_keeps_serving() {
        let dir = TempDir::new();
        let listener = UdsListener::bind(&dir.0.join("s.sock")).unwrap();
        let events: Events = Arc::default();
        let mut incoming = UdsIncoming::with_expected_uid(
            listener,
            Box::new(Recorder(Arc::clone(&events))),
            other_uid(),
        )
        .unwrap();
        let path = incoming.path().to_path_buf();
        let client = std::thread::spawn(move || {
            let mut c = StdStream::connect(path).unwrap();
            // macOS では相手が先に閉じた socket への setsockopt(SO_RCVTIMEO) が EINVAL になる
            // （サーバーの拒否・close と競合する。#2711）。set_read_timeout は使わず、
            // setsockopt を伴わない set_nonblocking（FIONBIO）と期限つきの待ちで期限を保つ。
            c.set_nonblocking(true).unwrap();
            // 先送りしたバイトは読まれない。切断されると EOF（Ok(0)）か reset になる。
            let _ = c.write_all(b"early");
            read_until_disconnect(&mut c, std::time::Instant::now() + Duration::from_secs(5))
        });
        // 拒否されるので stream は yield されず、Pending のまま（終了も Err もしない）。
        let polled = tokio::time::timeout(
            Duration::from_millis(500),
            poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx)),
        )
        .await;
        assert!(polled.is_err(), "rejected peer must not be yielded");
        assert_eq!(client.join().unwrap(), 0);
        assert_eq!(
            *events.lock().unwrap(),
            vec![(PeerAuthOp::Accept, PeerAuthRejectReason::UidMismatch)]
        );
    }

    /// クライアント側: 期待 UID と server の peer が不一致なら PermissionDenied で失敗し、
    /// Connect 拒否が 1 件通知される（偽 listener 対策。PLUG-12）。
    #[tokio::test]
    async fn plug12_client_rejects_mismatched_server() {
        let dir = TempDir::new();
        let listener = UdsListener::bind(&dir.0.join("s.sock")).unwrap();
        let events: Events = Arc::default();
        let cfg = GrpcClientConfig::new()
            .with_connect_timeout(Duration::from_secs(2))
            .unwrap();
        let e = connect_uds_channel_with_uid(
            listener.path(),
            &cfg,
            Box::new(Recorder(Arc::clone(&events))),
            other_uid(),
        )
        .await
        .unwrap_err();
        assert_eq!(e.code(), PluginErrorCode::PermissionDenied, "{e:?}");
        assert_eq!(
            *events.lock().unwrap(),
            vec![(PeerAuthOp::Connect, PeerAuthRejectReason::UidMismatch)]
        );
    }

    /// PLUG-12・REPAIR-5: 待ちの表を具体値で照合する。
    #[test]
    fn plug12_peer_reject_backoff_schedule() {
        let mut b = super::uds::PeerRejectBackoff::default();
        let ms = Duration::from_millis;
        let want = [
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 10),
            (5, 20),
            (6, 40),
            (7, 80),
            (8, 160),
            (9, 320),
            (10, 500),
            (11, 500),
            (12, 500),
        ];
        for (n, w) in want {
            assert_eq!(b.on_rejection(), (n, ms(w)));
        }
    }

    /// PLUG-12・REPAIR-5: 回数が増えても panic せず上限の待ちになる。
    #[test]
    fn plug12_peer_reject_backoff_saturates() {
        let mut b = super::uds::PeerRejectBackoff::default();
        for _ in 0..200 {
            b.on_rejection();
        }
        assert_eq!(b.on_rejection(), (201, Duration::from_millis(500)));
    }

    /// PLUG-12: 受理で連続回数が戻る。
    #[test]
    fn plug12_peer_reject_backoff_resets_on_accept() {
        let mut b = super::uds::PeerRejectBackoff::default();
        for _ in 0..5 {
            b.on_rejection();
        }
        b.on_accepted();
        assert_eq!(b.on_rejection(), (1, Duration::ZERO));
    }

    /// PLUG-12・REPAIR-5・REPAIR-4: 実ソケットで連続拒否に待ちが入り、正当な接続で解除される。
    #[tokio::test]
    async fn plug12_server_backs_off_on_consecutive_rejections_and_recovers() {
        let dir = TempDir::new();
        let listener = UdsListener::bind(&dir.0.join("s.sock")).unwrap();
        let events: BackoffEvents = Arc::default();
        let mut incoming = UdsIncoming::with_expected_uid(
            listener,
            Box::new(BackoffRecorder(Arc::clone(&events))),
            other_uid(),
        )
        .unwrap();
        let path = incoming.path().to_path_buf();
        let _clients: Vec<StdStream> = (0..5).map(|_| StdStream::connect(&path).unwrap()).collect();
        let polled = tokio::time::timeout(
            Duration::from_secs(1),
            poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx)),
        )
        .await;
        assert!(polled.is_err(), "rejected peers must not be yielded");
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                (Some(1), Some(0)),
                (Some(2), Some(0)),
                (Some(3), Some(0)),
                (Some(4), Some(10)),
                (Some(5), Some(20)),
            ]
        );
        assert_eq!(incoming.peer_reject_streak(), 5);

        incoming.set_expected_uid_for_test(crate::sys::effective_uid());
        let _good = StdStream::connect(&path).unwrap();
        let got = tokio::time::timeout(
            Duration::from_secs(5),
            poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx)),
        )
        .await
        .expect("legitimate peer must be accepted after the backoff");
        assert!(matches!(got, Some(Ok(_))));
        assert_eq!(incoming.peer_reject_streak(), 0);
        assert!(!incoming.has_backoff());
        assert_eq!(events.lock().unwrap().len(), 5);
    }
}
