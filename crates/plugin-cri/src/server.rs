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
//! - `ImageService` は載せない（`RuntimeService` のみ。PodSandbox 系は #849、Container 系 4 RPC は同じサービスで境界を越えて届き
//!   `tests/container_grpc.rs` で照合する〔#850〕。本番の bundle 供給は #2433 で結線済み、start・kill・stop の本番結線は #2434 待ち）
//! - peer 認証の拒否は `telemetry` が 1 秒ごとに別 task で回収して stderr へ JSON Lines で書く（SEC-4）。
//!   `crates/core` の永続的な監査ログへは [`serve_with_audit`] に渡す `PeerAuditForwarder` が 1 件ずつ書く（#2484。Linux の
//!   `main.rs` が配線。非 Linux は #2430 の判断待ちで stderr のみ）。[`serve`] は記録先なしの旧形で、試験用
//! - SIGTERM による正常停止は未実装（`main.rs` は `pending()` を渡す）。残った socket は次回起動の
//!   `UdsListener::bind` が自 UID の stale socket として掃除する

use std::future::Future;
use std::path::Path;

use crate::telemetry::{self, PeerAuditForwarder, SharedPeerAuthObserver};
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
    serve_with_audit(socket, service, config, None, shutdown).await
}

/// [`serve`] に、peer 認証の拒否の永続化先（SEC-4・PLUG-12・#2484）を足した形。
///
/// `audit` が `Some` なら拒否 1 件ごとに `AuditRecord`（層 `plugin_peer`）を core の監査ログへ渡す。
pub async fn serve_with_audit<F: Future<Output = ()>>(
    socket: &Path,
    service: CriRuntimeService,
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
