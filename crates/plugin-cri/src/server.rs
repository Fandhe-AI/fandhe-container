//! CRI `RuntimeService` と `ImageService` を同じ UDS 上の gRPC でサーブする（TASK-114.3.1・#849・#2592・PLUG-1・PLUG-2・PLUG-12・CRI-2・CRI-3）。
//!
//! 呼び出し元は `main.rs` の `Serve`。`adapter::CriPluginBackends::runtime_service` が組み立てた
//! `CriRuntimeService` を `RuntimeServiceServer` で、`image_service` が組み立てた `CriImageService` を
//! `ImageServiceServer` で包んで同じ router に載せ、`fandhe-container-plugin::grpc` の
//! `UdsIncoming`（accept 直後・最初の read より前に peer UID を検証。別 UID は切断）と `serve_router` に載せる。
//! 呼び出し側（kubelet / crictl 相当の core 側クライアント）は `connect_uds_channel` で接続する。
//! peer UID の検証は listener 単位（`UdsIncoming`）で行うため、同じ listener に載せた `ImageService` も別 UID の拒否と
//! 監査の対象になる。TCP は一切待ち受けない。socket の配置検証（所有者・0700・symlink・`sun_path` 長・既存パスの拒否）は
//! `UdsListener::bind` に一本化し、本モジュールは再実装しない。
//!
//! 契約: メッセージ上限は `GRPC_MAX_MESSAGE_BYTES` を両方向に設定し、要求の期限・同時接続数・ヘッダ上限は
//! `GrpcServerConfig` に従う（REPAIR-5）。`UdsIncoming::new` は tokio ランタイムの内側で呼ぶ必要があるため
//! [`serve`] は async で、組み立てを関数内で行う。
//!
//! # 未実装（REPAIR-3）
//!
//! - `ImageService` は [`serve_with_images`] / [`serve_with_audit`] に `Some` を渡したときだけ載せる（本番の `main.rs` は常に渡す。#2592）。
//!   [`serve`] は載せない旧形で試験用。在庫はプロセス内だけで、再起動でタグの対応は失われる（`adapter` の REPAIR-3）。
//!   PodSandbox 系は #849、Container 系 4 RPC は同じサービスで境界を越えて届き `tests/container_grpc.rs` で照合する（#850）。
//! - peer 認証の拒否は `telemetry` が 1 秒ごとに別 task で回収して stderr へ JSON Lines で書く（SEC-4）。
//!   `crates/core` の永続的な監査ログへは [`serve_with_audit`] に渡す `PeerAuditForwarder` が 1 件ずつ書く（#2484。Linux の
//!   `main.rs` が配線。非 Linux は #2430 の判断待ちで stderr のみ）。[`serve`] は記録先なしの旧形で、試験用
//! - SIGTERM による正常停止は未実装（`main.rs` は `pending()` を渡す）。残った socket は次回起動の
//!   `UdsListener::bind` が自 UID の stale socket として掃除する

use std::future::Future;
use std::path::Path;

use crate::telemetry::{self, PeerAuditForwarder, SharedPeerAuthObserver};
use fandhe_container_cri::image_service::CriImageService;
use fandhe_container_cri::runtime::v1::image_service_server::ImageServiceServer;
use fandhe_container_cri::runtime::v1::runtime_service_server::RuntimeServiceServer;
use fandhe_container_cri::runtime_service::CriRuntimeService;
use fandhe_container_plugin::grpc::{
    GRPC_MAX_MESSAGE_BYTES, GrpcServerConfig, UdsIncoming, serve_router, server_builder,
};
use fandhe_container_plugin::{PluginError, UdsListener};
use std::sync::Arc;

/// `socket` に bind して `service` を `shutdown` の完了までサーブする（監査の永続化なし。stderr のみ）。
///
/// bind の失敗（配置不備・既存パス・`sun_path` 超過）は `UdsListener::bind` の `PluginError` をそのまま返す。
/// 本番の `main.rs` は [`serve_with_audit`] を使う。
pub async fn serve<F: Future<Output = ()>>(
    socket: &Path,
    service: CriRuntimeService,
    config: &GrpcServerConfig,
    shutdown: F,
) -> Result<(), PluginError> {
    serve_with_audit(socket, service, None, config, None, shutdown).await
}

/// [`serve`] に `ImageService` を足した形（監査の永続化なし。試験用。#2592）。
pub async fn serve_with_images<F: Future<Output = ()>>(
    socket: &Path,
    service: CriRuntimeService,
    images: Option<CriImageService>,
    config: &GrpcServerConfig,
    shutdown: F,
) -> Result<(), PluginError> {
    serve_with_audit(socket, service, images, config, None, shutdown).await
}

/// [`serve`] に、peer 認証の拒否の永続化先（SEC-4・PLUG-12・#2484）を足した形。
///
/// `audit` が `Some` なら拒否 1 件ごとに `AuditRecord`（層 `plugin_peer`）を core の監査ログへ渡す。
pub async fn serve_with_audit<F: Future<Output = ()>>(
    socket: &Path,
    service: CriRuntimeService,
    images: Option<CriImageService>,
    config: &GrpcServerConfig,
    audit: Option<Arc<PeerAuditForwarder>>,
    shutdown: F,
) -> Result<(), PluginError> {
    let listener = UdsListener::bind(socket)?;
    let (observer, audit_buf) = SharedPeerAuthObserver::new();
    let observer = match &audit {
        Some(forwarder) => observer.with_audit(Arc::clone(forwarder)),
        None => observer,
    };
    let incoming = UdsIncoming::new(listener, Box::new(observer))?;
    let svc = RuntimeServiceServer::new(service)
        .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES)
        .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES);
    let router = server_builder(config).add_service(svc);
    // ImageService は同じ router・同じ listener に載せる（peer 認証・メッセージ上限・期限を RuntimeService と共有。#2592）。
    let router = match images {
        Some(image) => router.add_service(
            ImageServiceServer::new(image)
                .max_decoding_message_size(GRPC_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(GRPC_MAX_MESSAGE_BYTES),
        ),
        None => router,
    };
    // 受付を止めない別 task で回収する。終了時は残りを最後に書き出す。
    let pump = tokio::spawn(telemetry::audit_drain_loop(
        std::sync::Arc::clone(&audit_buf),
        telemetry::AUDIT_DRAIN_INTERVAL,
    ));
    let result = serve_router(router, incoming, shutdown, config).await;
    pump.abort();
    // 最後の回収。書き込み先が止まっていてもブロックしない（短い期限つきで待つ。REPAIR-5）。
    let sink = telemetry::stderr_sink();
    telemetry::drain_audit_to(&audit_buf, sink);
    sink.wait_idle(std::time::Duration::from_millis(200));
    if let Some(forwarder) = &audit {
        forwarder.wait_idle(std::time::Duration::from_millis(200));
    }
    result
}
