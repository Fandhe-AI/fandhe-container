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
//! - 本基盤は認証を持たない。peer 認証・配置検証は `uds_security` の責務で、UDS 統合時に呼び出し側が
//!   通す（PLUG-12）。gRPC の内容検証（リクエストの意味検証）も上位の責務で、入力は untrusted として扱う。
//!
//! # 未実装（REPAIR-3）
//!
//! - UDS 上の tonic 統合（connector・listener・peer 認証との接続）は TASK-108.2（#454）。
//! - CRI proto の RPC による疎通は TASK-108.3（#455）。
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
    _marker: PhantomData<fn() -> (IO, IE)>,
}

impl<I, IO, IE> Stream for KillableIncoming<I, IO, IE>
where
    I: Stream<Item = Result<IO, IE>>,
{
    type Item = Result<KillableIo<IO>, IE>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let switch = Arc::clone(&self.switch);
        self.inner
            .as_mut()
            .poll_next(cx)
            .map(|o| o.map(|r| r.map(|io| KillableIo::new(io, switch))))
    }
}

/// 強制停止後に接続タスクの終了（IO の drop）を待つ上限。
const FORCE_RECLAIM_WAIT: Duration = Duration::from_secs(2);

/// `Router` を任意の incoming ストリームで起動し、`shutdown` の完了で graceful shutdown する。
///
/// shutdown 信号の後、`config` の shutdown 猶予内にサーバーが終わらなければ、受け付け済みの全接続を
/// 強制的に閉じ（tonic が起動した接続タスクの IO を打ち切る）、タスクの終了を [`FORCE_RECLAIM_WAIT`]
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
/// 結果は [`grpc_stats`] の `connect` に記録する。UDS 用の connector 経由の接続は TASK-108.2（#454）で
/// 追加する（未実装。PLUG-2・PLUG-12）。
pub async fn connect_channel(
    endpoint: Endpoint,
    connect_timeout: Duration,
) -> Result<Channel, PluginError> {
    let started = Instant::now();
    let r = match check_duration(connect_timeout, "connect timeout") {
        Err(e) => Err(e),
        Ok(connect_timeout) => {
            match tokio::time::timeout(connect_timeout, endpoint.connect()).await {
                Err(_) => Err(PluginError::new(
                    PluginErrorCode::Timeout,
                    "grpc connect timed out",
                )),
                Ok(Err(e)) => Err(transport_error_to_plugin(&e)),
                Ok(Ok(ch)) => Ok(ch),
            }
        }
    };
    STATS_CONNECT.record(
        started.elapsed(),
        r.as_ref().map(|_| ()).map_err(|e| e.code()),
    );
    r
}

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
