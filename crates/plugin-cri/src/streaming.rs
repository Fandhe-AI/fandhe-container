//! plugin-cri のストリーミングサーバー（`Exec`・`Attach`・`PortForward` の URL の先）の起動と注入（#3754・CRI-6・REPAIR-5・REPAIR-3）。
//!
//! 呼び出し元: `main.rs` の `serve`。runtime の構築直後（UDS の bind より前）に [`bind_production_streaming`] で loopback の
//! `fandhe_container_cri::streaming::StreamingServer` を起動し、その `issuer()` を `CriRuntimeService::with_streaming` へ渡す。
//! 停止は [`stop_streaming_on`] で包んだ shutdown future が担い、SIGTERM・SIGINT（#3226）の受信と同時に TCP の待ち受けを閉じる。
//!
//! # 現状（REPAIR-3）
//! 結線済みは Attach（読み取り専用。[`log_attach::LogFollowAttachBackend`]。回転ログの follow で、stdin・tty は
//! `INVALID_ARGUMENT`。完全版は #3765 の設計。#3763）と、PortForward の NODE ネットワーク（hostNetwork）の pod
//! （#3755。[`NodeLoopbackDialer`]）。POD ネットワークの pod は RPC 時（cri）と dialer の両方で `UNIMPLEMENTED` で、
//! 保持役（#2877）と helper 方式（#3766）まで続く。Exec は Linux で結線済み（[`exec_launcher::SupervisorExecLauncher`]。
//! supervisor の `stream-exec` helper 経由。stdin・stdout・stderr のみで、tty と相対 `argv[0]` は RPC 時に `INVALID_ARGUMENT`。#3761）で、
//! 非 Linux は「exec streaming is not wired」の `UNIMPLEMENTED`。`wiring` は bind 時に 1 回だけ取られるため、
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
//! PortForward の Upgrade 後のセッションと実行中の blocking の dial（最長 `dial_timeout` 10 秒）も、プロセス終了時の
//! `rt.shutdown_timeout` が打ち切るため待ちは増えず、`SHUTDOWN_TOTAL_BOUND` は変わらない（#3755 で再評価）。
//! Exec のセッションは長寿命になりうるため、停止時に `exec_launcher` が追跡中の helper を kill する（`stop_streaming_on` の `on_stop`。
//! helper の期限は最長 1 時間）。ドレイン待ちは足さない。
//! 設計は `docs/design/cri-streaming-server.md`。

pub mod log_attach;

#[cfg(target_os = "linux")]
pub mod exec_launcher;

use std::future::Future;
use std::sync::Arc;

mod node_dialer;

pub use node_dialer::NodeLoopbackDialer;

use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::streaming::attach::{AttachBackend, AttachHandler};
use fandhe_container_cri::streaming::exec::{
    ExecStreamConfig, ExecStreamHandler, ExecStreamLauncher,
};
use fandhe_container_cri::streaming::port_forward::{PortForwardConfig, PortForwardHandler};
use fandhe_container_cri::streaming::{StreamDispatcher, StreamingConfig, StreamingServer};
use fandhe_container_plugin::{PluginError, PluginErrorCode};

/// 起動失敗時の固定文言（アドレス・OS のエラーは含めない。REPAIR-4）。
pub const MSG_STREAMING_START_FAILED: &str = "failed to start the streaming server";

/// 本番の設定。loopback・外部公開なし・単回トークン TTL 60 秒の既定そのまま。
pub fn production_streaming_config() -> StreamingConfig {
    StreamingConfig::default()
}

/// 本番の `StreamDispatcher`。Attach（読み取り専用の `attach`。#3763）・PortForward（NODE ネットワークの pod だけ。#3755）・
/// Exec（`exec` が `Some` のとき。stdin・stdout・stderr のみで tty なし、絶対パスの argv[0] のみ。#3761）を結線する。
///
/// 期限は本番の設定（[`production_streaming_config`]）の
/// `session_limits()`。ハンドラの構築失敗（設定検証。既定では起きない）は `Internal` の固定文言に写す。
pub fn production_stream_dispatcher(
    attach: Arc<dyn AttachBackend>,
    exec: Option<Arc<dyn ExecStreamLauncher>>,
) -> Result<StreamDispatcher, PluginError> {
    let attach_handler = AttachHandler::new(attach, production_streaming_config().session_limits())
        .map_err(|_| PluginError::new(PluginErrorCode::Internal, MSG_STREAMING_START_FAILED))?
        .read_only();
    let port_forward = PortForwardHandler::new(
        Arc::new(NodeLoopbackDialer::new()),
        PortForwardConfig::default(),
    )
    .map_err(|_| PluginError::new(PluginErrorCode::Internal, MSG_STREAMING_START_FAILED))?;
    let mut dispatcher = StreamDispatcher::new()
        .with_attach(Arc::new(attach_handler))
        .with_port_forward(Arc::new(port_forward));
    // Exec は起動役（Linux の supervisor helper 経由。#3761）がある構成だけ結線する。tty と相対 argv[0] は宣言せず、
    // RPC 時に `INVALID_ARGUMENT` で断る（supervisor 側の pty 結線と PATH 解決の判断が済むまで。REPAIR-3）。
    if let Some(launcher) = exec {
        let config = ExecStreamConfig {
            limits: production_streaming_config().session_limits(),
            ..ExecStreamConfig::default()
        };
        let exec_handler = ExecStreamHandler::new(launcher, config)
            .map_err(|_| PluginError::new(PluginErrorCode::Internal, MSG_STREAMING_START_FAILED))?
            .without_tty()
            .absolute_command_only();
        dispatcher = dispatcher.with_exec(Arc::new(exec_handler));
    }
    Ok(dispatcher)
}

/// dispatcher を組んでから `StreamingServer` を起動する。`tokio` の実行時の中で呼ぶ。
///
/// `exec` が `None`（非 Linux）なら Exec は未結線で `UNIMPLEMENTED` のまま。失敗は `Unavailable`（bind・アドレス取得）と `Internal`（設定検証。本番の既定では起きない）の固定文言に写す。
pub async fn bind_production_streaming(
    config: StreamingConfig,
    attach: Arc<dyn AttachBackend>,
    exec: Option<Arc<dyn ExecStreamLauncher>>,
) -> Result<StreamingServer, PluginError> {
    let dispatcher = production_stream_dispatcher(attach, exec)?;
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

/// `shutdown` の完了で `server` の待ち受けを閉じ、`on_stop`（exec の追跡中 helper の kill 等）を呼ぶ future。
/// `serve_with_audit` の shutdown future として渡す。
///
/// future ごと drop されたときも `StreamingServer::drop` が閉じる。
pub async fn stop_streaming_on<F: Future<Output = ()>>(
    server: StreamingServer,
    on_stop: impl FnOnce(),
    shutdown: F,
) {
    shutdown.await;
    server.shutdown();
    // 追跡中の exec helper を kill する（長寿命のセッションを残さない。REPAIR-5・#3761）。
    on_stop();
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
    async fn cri6_3754_production_server_listens_on_loopback_with_attach_and_port_forward() {
        let server = bind_production_streaming(production_streaming_config(), fake_attach(), None)
            .await
            .expect("bind");
        let addr = server.local_addr();
        assert_eq!(addr.ip(), LOOPBACK);
        assert_ne!(addr.port(), 0);
        let issuer = server.issuer();
        // 結線済みは Attach（読み取り専用。stdin・tty を宣言しない。#3763）と PortForward（NODE のみ。#3755）。
        assert_eq!(
            issuer.wiring(),
            StreamWiring::only(StreamKind::Attach).with(StreamKind::PortForward)
        );
        assert!(!issuer.wiring().attach_interactive());
        assert!(!issuer.wiring().port_forward_pod_network());
        assert_eq!(
            issuer.base_url(),
            format!("http://127.0.0.1:{}", addr.port())
        );
        connect(addr).await.expect("connect to loopback listener");
    }

    /// exec 起動役を渡さない構成（非 Linux 相当）では Exec は未結線の `UNIMPLEMENTED` のまま（#3761）。Attach・PortForward は結線済み。
    #[tokio::test]
    async fn cri6_repair3_3754_injected_service_without_exec_launcher_keeps_exec_unimplemented() {
        let server = bind_production_streaming(production_streaming_config(), fake_attach(), None)
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
        assert_eq!(e.code(), Code::NotFound);
        assert_eq!(e.message(), "pod sandbox not found");
    }

    /// CRI-6・REPAIR-3・SEC-1・#3755: 本番の結線で NODE の sandbox は URL を返し、POD の sandbox は `UNIMPLEMENTED`。
    #[tokio::test]
    async fn cri6_3755_production_port_forward_node_ok_pod_unimplemented() {
        let server = bind_production_streaming(production_streaming_config(), fake_attach(), None)
            .await
            .expect("bind");
        let svc = CriRuntimeService::new().with_streaming(server.issuer());
        async fn run(
            svc: &CriRuntimeService,
            name: &str,
            network: Option<cri::NamespaceMode>,
        ) -> String {
            let linux = network.map(|n| cri::LinuxPodSandboxConfig {
                security_context: Some(cri::LinuxSandboxSecurityContext {
                    namespace_options: Some(cri::NamespaceOption {
                        network: n as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            });
            svc.run_pod_sandbox(Request::new(cri::RunPodSandboxRequest {
                config: Some(cri::PodSandboxConfig {
                    metadata: Some(cri::PodSandboxMetadata {
                        name: name.into(),
                        uid: format!("uid-{name}"),
                        namespace: "ns".into(),
                        attempt: 0,
                    }),
                    linux,
                    ..Default::default()
                }),
                ..Default::default()
            }))
            .await
            .expect("run")
            .into_inner()
            .pod_sandbox_id
        }
        let node = run(&svc, "n", Some(cri::NamespaceMode::Node)).await;
        let pod = run(&svc, "p", None).await;
        let url = svc
            .port_forward(Request::new(cri::PortForwardRequest {
                pod_sandbox_id: node,
                port: vec![80],
            }))
            .await
            .expect("node url")
            .into_inner()
            .url;
        assert!(
            url.starts_with(&format!("{}/portforward/", server.issuer().base_url())),
            "unexpected url"
        );
        let e = svc
            .port_forward(Request::new(cri::PortForwardRequest {
                pod_sandbox_id: pod,
                port: vec![80],
            }))
            .await
            .expect_err("pod");
        assert_eq!(e.code(), Code::Unimplemented);
        assert_eq!(
            e.message(),
            "port-forward for pod network is not implemented"
        );
    }

    #[tokio::test]
    async fn repair5_3754_streaming_listener_closes_on_shutdown() {
        let server = bind_production_streaming(production_streaming_config(), fake_attach(), None)
            .await
            .expect("bind");
        let addr = server.local_addr();
        let flag = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&flag);
        let task = tokio::spawn(stop_streaming_on(server, || {}, async move {
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
        let e = bind_production_streaming(
            production_streaming_config().with_bind(busy),
            fake_attach(),
            None,
        )
        .await
        .expect_err("busy port");
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(e.message(), MSG_STREAMING_START_FAILED);
        let ext = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let e = bind_production_streaming(
            production_streaming_config().with_bind(ext),
            fake_attach(),
            None,
        )
        .await
        .expect_err("external without opt-in");
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(e.message(), MSG_STREAMING_START_FAILED);
    }

    /// CRI-6・#3763: 本番構成（`bind_production_streaming` + `with_streaming`）の `Attach` RPC が URL を返す。
    /// stdin・tty つきは URL を返さず `INVALID_ARGUMENT`。
    #[tokio::test]
    async fn cri6_3763_production_attach_returns_url() {
        let server = bind_production_streaming(production_streaming_config(), fake_attach(), None)
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

    /// 何も起動しない偽の起動役（結線の試験用。RPC の検証だけを見る）。
    #[cfg(target_os = "linux")]
    struct NeverLauncher;

    #[cfg(target_os = "linux")]
    impl ExecStreamLauncher for NeverLauncher {
        fn launch(
            &self,
            _req: fandhe_container_cri::streaming::exec::ExecLaunch,
        ) -> std::pin::Pin<
            Box<
                dyn Future<
                        Output = Result<
                            fandhe_container_cri::streaming::exec::ExecSession,
                            fandhe_container_cri::error::CriError,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async {
                Err(fandhe_container_cri::error::CriError::unimplemented(
                    "never launches",
                ))
            })
        }
    }

    /// CRI-6・SEC-1・#3761: 本番構成の `Exec` RPC が URL を返す。tty と相対 `argv[0]` は URL を返さず `INVALID_ARGUMENT`
    /// （固定文）。不在のコンテナは `NOT_FOUND`。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cri6_3761_production_exec_returns_url() {
        let launcher: Arc<dyn ExecStreamLauncher> = Arc::new(NeverLauncher);
        let server =
            bind_production_streaming(production_streaming_config(), fake_attach(), Some(launcher))
                .await
                .expect("bind");
        let issuer = server.issuer();
        let w = issuer.wiring();
        assert!(w.is_wired(StreamKind::Exec));
        assert!(!w.exec_tty());
        assert!(!w.exec_relative_command());
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
        let exec = |cmd: &str, tty: bool, id: &str| {
            svc.exec(Request::new(cri::ExecRequest {
                container_id: id.to_string(),
                cmd: vec![cmd.to_string()],
                stdout: true,
                tty,
                ..Default::default()
            }))
        };
        let url = exec("/bin/true", false, &container)
            .await
            .expect("exec url")
            .into_inner()
            .url;
        assert!(
            url.starts_with(&format!("{}/exec/", issuer.base_url())),
            "{url}"
        );
        let e = exec("/bin/true", true, &container).await.expect_err("tty");
        assert_eq!(e.code(), Code::InvalidArgument);
        assert_eq!(e.message(), "exec with tty is not supported");
        let e = exec("true", false, &container).await.expect_err("relative");
        assert_eq!(e.code(), Code::InvalidArgument);
        assert_eq!(e.message(), "exec command must be an absolute path");
        let e = exec("/bin/true", false, "nope").await.expect_err("missing");
        assert_eq!(e.code(), Code::NotFound);
    }
}
