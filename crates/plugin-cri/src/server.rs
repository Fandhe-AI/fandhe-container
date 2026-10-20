//! CRI `RuntimeService` を UDS 上の gRPC でサーブする（TASK-114.3.1・#849・PLUG-1・PLUG-2・PLUG-12・CRI-2）。
//!
//! 呼び出し元は `main.rs` の `Serve`。`adapter::CriPluginBackends::runtime_service` が組み立てた
//! `CriRuntimeService` を `RuntimeServiceServer` で包み、`fandhe-container-plugin::grpc` の
//! `UdsIncoming`（accept 直後・最初の read より前に peer UID を検証。別 UID は切断）と `serve_router` に載せる。
//! 呼び出し側（kubelet / crictl 相当の core 側クライアント）は `connect_uds_channel` で接続する。
//! TCP は一切待ち受けない。socket の配置検証（所有者・0700・symlink・`sun_path` 長・既存パスの拒否）は
//! `UdsListener::bind` に一本化し、本モジュールは再実装しない。
//!
//! 契約: メッセージ上限は `GRPC_MAX_MESSAGE_BYTES` を両方向に設定し、要求の期限・同時接続数・ヘッダ上限は
//! `GrpcServerConfig` に従う（REPAIR-5）。`UdsIncoming::new` は tokio ランタイムの内側で呼ぶ必要があるため
//! [`serve`] は async で、組み立てを関数内で行う。
//!
//! # 未実装（REPAIR-3）
//!
//! - `ImageService` は載せない（本 issue は RuntimeService の PodSandbox 系が対象）
//! - peer 認証の拒否は `JsonLinesPeerAuthObserver` の有界バッファに積むだけで、永続的な監査ログ（SEC-4）への
//!   配線は #1869 の積み残し
//! - SIGTERM による正常停止は未実装（`main.rs` は `pending()` を渡す）。残った socket は次回起動の
//!   `UdsListener::bind` が自 UID の stale socket として掃除する

use std::future::Future;
use std::path::Path;

use fandhe_container_cri::runtime::v1::runtime_service_server::RuntimeServiceServer;
use fandhe_container_cri::runtime_service::CriRuntimeService;
use fandhe_container_plugin::grpc::{
    GRPC_MAX_MESSAGE_BYTES, GrpcServerConfig, UdsIncoming, serve_router, server_builder,
};
use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginError, UdsListener};

/// `socket` に bind して `service` を `shutdown` の完了までサーブする。
///
/// bind の失敗（配置不備・既存パス・`sun_path` 超過）は `UdsListener::bind` の `PluginError` をそのまま返す。
pub async fn serve<F: Future<Output = ()>>(
    socket: &Path,
    service: CriRuntimeService,
    config: &GrpcServerConfig,
    shutdown: F,
) -> Result<(), PluginError> {
    let listener = UdsListener::bind(socket)?;
    let incoming = UdsIncoming::new(listener, Box::new(JsonLinesPeerAuthObserver::new()))?;
    let svc = RuntimeServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES);
    let router = server_builder(config).add_service(svc);
    serve_router(router, incoming, shutdown, config).await
}
