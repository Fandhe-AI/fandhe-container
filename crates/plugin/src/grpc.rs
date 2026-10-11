//! plugin 境界の gRPC（tonic）面の共通基盤（PLUG-2・TASK-108.1・#453）。
//!
//! wire 互換性が必要な CRI 標準準拠面だけが gRPC を使う（PLUG-2）。本モジュールは、その gRPC サーバー起動と
//! クライアント接続に共通する処理（タイムアウト・メッセージ上限・同時実行上限・エラー変換）を提供する。
//! 呼び出し元は将来の `fandhe-container-plugin-cri`（サーバー側）と core 側 proxy（クライアント側。TASK-114）。
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
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

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

/// リクエストタイムアウトの既定値。
pub const GRPC_REQUEST_TIMEOUT_DEFAULT: Duration = Duration::from_secs(30);

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

/// `Router` を任意の incoming ストリームで起動し、`shutdown` の完了で graceful shutdown する。
///
/// shutdown 信号の後、`config` の shutdown 猶予内にサーバーが終わらなければ `Timeout` を返す
/// （接続が居座っても無期限に待たない。REPAIR-5）。トランスポートの listener は呼び出し側が作る。
pub async fn serve_router<I, IO, IE, F>(
    router: Router,
    incoming: I,
    shutdown: F,
    config: &GrpcServerConfig,
) -> Result<(), PluginError>
where
    I: tonic::codegen::tokio_stream::Stream<Item = Result<IO, IE>>,
    IO: tokio::io::AsyncRead
        + tokio::io::AsyncWrite
        + tonic::transport::server::Connected
        + Unpin
        + Send
        + 'static,
    IE: Into<Box<dyn std::error::Error + Send + Sync>>,
    F: Future<Output = ()>,
{
    let fired = Arc::new(AtomicBool::new(false));
    let fired_in = Arc::clone(&fired);
    let serve = router.serve_with_incoming_shutdown(incoming, async move {
        shutdown.await;
        fired_in.store(true, Ordering::SeqCst);
    });
    let mut serve = pin!(serve);
    let mut deadline: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;
    let grace = config.shutdown_grace;
    poll_fn(|cx| {
        if let Poll::Ready(r) = serve.as_mut().poll(cx) {
            return Poll::Ready(r.map_err(|e| transport_error_to_plugin(&e)));
        }
        if fired.load(Ordering::SeqCst) {
            let sleep = deadline.get_or_insert_with(|| Box::pin(tokio::time::sleep(grace)));
            if sleep.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(PluginError::new(
                    PluginErrorCode::Timeout,
                    "grpc server did not shut down within the grace period",
                )));
            }
        }
        Poll::Pending
    })
    .await
}

/// 接続を確立する。`connect_timeout` で二重に保護し、期限切れは `Timeout`、接続失敗は `Unavailable`。
///
/// UDS 用の connector 経由の接続は TASK-108.2（#454）で追加する（未実装。PLUG-2・PLUG-12）。
pub async fn connect_channel(
    endpoint: Endpoint,
    connect_timeout: Duration,
) -> Result<Channel, PluginError> {
    let connect_timeout = check_duration(connect_timeout, "connect timeout")?;
    match tokio::time::timeout(connect_timeout, endpoint.connect()).await {
        Err(_) => Err(PluginError::new(
            PluginErrorCode::Timeout,
            "grpc connect timed out",
        )),
        Ok(Err(e)) => Err(transport_error_to_plugin(&e)),
        Ok(Ok(ch)) => Ok(ch),
    }
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
