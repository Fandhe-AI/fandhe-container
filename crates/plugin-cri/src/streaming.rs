//! plugin-cri のストリーミングサーバー（`Exec`・`Attach`・`PortForward` の URL の先）の起動と注入（#3754・CRI-6・REPAIR-5・REPAIR-3）。
//!
//! 呼び出し元: `main.rs` の `serve`。runtime の構築直後（UDS の bind より前）に [`bind_production_streaming`] で loopback の
//! `fandhe_container_cri::streaming::StreamingServer` を起動し、その `issuer()` を `CriRuntimeService::with_streaming` へ渡す。
//! 停止は [`stop_streaming_on`] で包んだ shutdown future が担い、SIGTERM・SIGINT（#3226）の受信と同時に TCP の待ち受けを閉じる。
//!
//! # 現状（REPAIR-3）
//! 結線済みの種別は Attach だけ（読み取り専用。[`log_attach::LogFollowAttachBackend`]。回転ログの follow で、stdin・tty は
//! `INVALID_ARGUMENT`。完全版は #3765 の設計。#3763）。Exec・PortForward は未結線で「`<kind> streaming is not wired`」の
//! `UNIMPLEMENTED` のまま。兄弟 issue（#3755 PortForward・#3761 Exec）が `with_exec` / `with_port_forward` を
//! [`production_stream_dispatcher`] へ足す。`wiring` は bind 時に 1 回だけ取られるため、
//! ハンドラは必ず bind より前に足す（[`bind_production_streaming`] が順序を固定する）。
//!
//! # 安全側の既定
//! 待ち受けは `127.0.0.1:0`・外部公開なし・トークンは単回使用で TTL 60 秒（`StreamingConfig::default()`）。
//! 外部公開（`allow_external`）は plugin-cri からは出さない（opt-in の口は未実装。REPAIR-3）。TLS と認証は無く、URL の
//! 256 ビットのトークンが唯一の認可なので、外部公開するなら前段の守りが前提になる。
//!
//! # 起動失敗
//! bind の失敗は fail-closed（起動しない）。縮退して動き続けると外から「未結線」と区別できないため。
//! エラーは固定文言とコードだけで、アドレスや OS のエラー文字列は出さない（REPAIR-4）。
//!
//! # 停止（REPAIR-5）
//! 停止は待ちを足さない（accept タスクの abort は同期）。受け付け済みで Upgrade しない接続はプロセス終了時の
//! `rt.shutdown_timeout` が打ち切るため、`shutdown::SHUTDOWN_TOTAL_BOUND` は変わらない。
//! Attach のセッションはランタイムの停止でタスクごと drop され、読み口の drop が取り消しの旗を立てて follow スレッドは
//! 1 ポーリング（200 ms）以内に抜ける。スレッドは detached でプロセスの停止を待たせない。
//! 他の種別の backend が入って Upgrade 後のセッションが生まれたら、停止時のドレイン方針を再評価する。
//! 設計は `docs/design/cri-streaming-server.md`。

pub mod log_attach;

use std::future::Future;
use std::sync::Arc;

use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::streaming::attach::{AttachBackend, AttachHandler};
use fandhe_container_cri::streaming::{StreamDispatcher, StreamingConfig, StreamingServer};
use fandhe_container_plugin::{PluginError, PluginErrorCode};

/// 起動失敗時の固定文言（アドレス・OS のエラーは含めない。REPAIR-4）。
pub const MSG_STREAMING_START_FAILED: &str = "failed to start the streaming server";

/// 本番の設定。loopback・外部公開なし・単回トークン TTL 60 秒の既定そのまま。
pub fn production_streaming_config() -> StreamingConfig {
    StreamingConfig::default()
}

/// 本番の `StreamDispatcher`。Attach（読み取り専用の `attach`）だけを結線する（#3763）。
///
/// 兄弟 issue（#3755・#3761）が `with_port_forward` / `with_exec` をここへ足す。期限は本番の設定
/// （[`production_streaming_config`]）の `session_limits()`。検証に失敗したら `Internal`（本番の既定では起きない）。
pub fn production_stream_dispatcher(
    attach: Arc<dyn AttachBackend>,
) -> Result<StreamDispatcher, PluginError> {
    let handler = AttachHandler::new(attach, production_streaming_config().session_limits())
        .map_err(|_| PluginError::new(PluginErrorCode::Internal, MSG_STREAMING_START_FAILED))?
        .read_only();
    Ok(StreamDispatcher::new().with_attach(Arc::new(handler)))
}

/// dispatcher を組んでから `StreamingServer` を起動する。`tokio` の実行時の中で呼ぶ。
///
/// 失敗は `Unavailable`（bind・アドレス取得）と `Internal`（設定検証。本番の既定では起きない）の固定文言に写す。
pub async fn bind_production_streaming(
    config: StreamingConfig,
    attach: Arc<dyn AttachBackend>,
) -> Result<StreamingServer, PluginError> {
    let dispatcher = production_stream_dispatcher(attach)?;
    StreamingServer::bind_with_handler(config, Arc::new(dispatcher))
        .await
        .map_err(|e| {
            let code = match e.code() {
                CriErrorCode::Unavailable => PluginErrorCode::Unavailable,
                _ => PluginErrorCode::Internal,
            };
            PluginError::new(code, MSG_STREAMING_START_FAILED)
        })
}

/// `shutdown` の完了で `server` の待ち受けを閉じる future。`serve_with_audit` の shutdown future として渡す。
///
/// future ごと drop されたときも `StreamingServer::drop` が閉じる。
pub async fn stop_streaming_on<F: Future<Output = ()>>(server: StreamingServer, shutdown: F) {
    shutdown.await;
    server.shutdown();
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use fandhe_container_cri::runtime::v1 as cri;
    use fandhe_container_cri::runtime::v1::runtime_service_server::RuntimeService;
    use fandhe_container_cri::runtime_service::CriRuntimeService;
    use fandhe_container_cri::streaming::{StreamKind, StreamWiring};
    use tonic::{Code, Request};

    use super::*;

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// 偽の probe と存在しないログ置き場の backend（結線の試験用。ログは読まれない）。
    fn fake_attach() -> Arc<dyn AttachBackend> {
        Arc::new(
            log_attach::LogFollowAttachBackend::new(
                std::env::temp_dir().join("fandhe-attach-unused"),
                log_attach::test_support::FakeProbe::running(),
            )
            .expect("backend"),
        )
    }

    async fn connect(addr: SocketAddr) -> std::io::Result<std::net::TcpStream> {
        tokio::task::spawn_blocking(move || {
            std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        })
        .await
        .expect("join")
    }

    #[test]
    fn cri6_3754_production_config_is_loopback_and_closed() {
        let c = production_streaming_config();
        assert_eq!(c.bind, SocketAddr::new(LOOPBACK, 0));
        assert!(!c.allow_external);
        assert_eq!(c.token_ttl, Duration::from_secs(60));
        assert_eq!(c.max_in_flight, 1000);
        assert_eq!(c.max_connections, 64);
    }

    #[tokio::test]
    async fn cri6_3754_production_server_listens_on_loopback_with_attach_only() {
        let server = bind_production_streaming(production_streaming_config(), fake_attach())
            .await
            .expect("bind");
        let addr = server.local_addr();
        assert_eq!(addr.ip(), LOOPBACK);
        assert_ne!(addr.port(), 0);
        let issuer = server.issuer();
        // 結線済みは Attach だけで、読み取り専用（stdin・tty を宣言しない。#3763）。
        assert_eq!(issuer.wiring(), StreamWiring::only(StreamKind::Attach));
        assert!(!issuer.wiring().attach_interactive());
        assert_eq!(
            issuer.base_url(),
            format!("http://127.0.0.1:{}", addr.port())
        );
        connect(addr).await.expect("connect to loopback listener");
    }

    /// 結線前（#3754 時点）の期待値。兄弟 issue が結線を足したら、その種別の期待値を更新する。
    #[tokio::test]
    async fn cri6_repair3_3754_injected_service_keeps_unwired_rpcs_unimplemented() {
        let server = bind_production_streaming(production_streaming_config(), fake_attach())
            .await
            .expect("bind");
        let svc = CriRuntimeService::new().with_streaming(server.issuer());
        let e = svc
            .exec(Request::new(cri::ExecRequest {
                container_id: "nope".into(),
                cmd: vec!["true".into()],
                ..Default::default()
            }))
            .await
            .expect_err("exec");
        assert_eq!(e.code(), Code::Unimplemented);
        assert_eq!(e.message(), "exec streaming is not wired");
        // Attach は結線済み（#3763）。未知の ID は存在照合の `NOT_FOUND` になる。
        let e = svc
            .attach(Request::new(cri::AttachRequest {
                container_id: "nope".into(),
                stdout: true,
                ..Default::default()
            }))
            .await
            .expect_err("attach");
        assert_eq!(e.code(), Code::NotFound);
        let e = svc
            .port_forward(Request::new(cri::PortForwardRequest {
                pod_sandbox_id: "nope".into(),
                ..Default::default()
            }))
            .await
            .expect_err("port_forward");
        assert_eq!(e.code(), Code::Unimplemented);
        assert_eq!(e.message(), "port-forward streaming is not wired");
    }

    #[tokio::test]
    async fn repair5_3754_streaming_listener_closes_on_shutdown() {
        let server = bind_production_streaming(production_streaming_config(), fake_attach())
            .await
            .expect("bind");
        let addr = server.local_addr();
        let flag = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&flag);
        let task = tokio::spawn(stop_streaming_on(server, async move {
            while !f.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }));
        connect(addr).await.expect("listening before shutdown");
        flag.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("stop within deadline")
            .expect("join");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            if connect(addr).await.is_err() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "listener must close within 1s"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn cri6_3754_bind_failure_is_fixed_vocabulary() {
        let held = std::net::TcpListener::bind((LOOPBACK, 0)).expect("hold");
        let busy = held.local_addr().expect("addr");
        let e =
            bind_production_streaming(production_streaming_config().with_bind(busy), fake_attach())
                .await
                .expect_err("busy port");
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(e.message(), MSG_STREAMING_START_FAILED);
        let ext = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let e =
            bind_production_streaming(production_streaming_config().with_bind(ext), fake_attach())
                .await
                .expect_err("external without opt-in");
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(e.message(), MSG_STREAMING_START_FAILED);
    }

    /// CRI-6・#3763: 本番構成（`bind_production_streaming` + `with_streaming`）の `Attach` RPC が URL を返す。
    /// stdin・tty つきは URL を返さず `INVALID_ARGUMENT`。
    #[tokio::test]
    async fn cri6_3763_production_attach_returns_url() {
        let server = bind_production_streaming(production_streaming_config(), fake_attach())
            .await
            .expect("bind");
        let issuer = server.issuer();
        assert!(issuer.wiring().is_wired(StreamKind::Attach));
        let svc = CriRuntimeService::new().with_streaming(Arc::clone(&issuer));
        let pod = cri::PodSandboxConfig {
            metadata: Some(cri::PodSandboxMetadata {
                name: "pod".into(),
                uid: "uid-1".into(),
                namespace: "ns".into(),
                attempt: 0,
            }),
            ..Default::default()
        };
        let sandbox = svc
            .run_pod_sandbox(Request::new(cri::RunPodSandboxRequest {
                config: Some(pod.clone()),
                runtime_handler: String::new(),
            }))
            .await
            .expect("sandbox")
            .into_inner()
            .pod_sandbox_id;
        let container = svc
            .create_container(Request::new(cri::CreateContainerRequest {
                pod_sandbox_id: sandbox,
                config: Some(cri::ContainerConfig {
                    metadata: Some(cri::ContainerMetadata {
                        name: "c".into(),
                        attempt: 0,
                    }),
                    image: Some(cri::ImageSpec {
                        image: "busybox:1.36".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                sandbox_config: Some(pod),
            }))
            .await
            .expect("container")
            .into_inner()
            .container_id;
        svc.start_container(Request::new(cri::StartContainerRequest {
            container_id: container.clone(),
        }))
        .await
        .expect("start");
        let url = svc
            .attach(Request::new(cri::AttachRequest {
                container_id: container.clone(),
                stdout: true,
                ..Default::default()
            }))
            .await
            .expect("attach url")
            .into_inner()
            .url;
        assert!(
            url.starts_with(&format!("{}/attach/", issuer.base_url())),
            "{url}"
        );
        let e = svc
            .attach(Request::new(cri::AttachRequest {
                container_id: container,
                stdin: true,
                stdout: true,
                ..Default::default()
            }))
            .await
            .expect_err("stdin refused");
        assert_eq!(e.code(), Code::InvalidArgument);
        assert_eq!(e.message(), "attach with stdin or tty is not supported");
    }
}
