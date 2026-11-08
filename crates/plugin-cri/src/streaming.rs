//! plugin-cri のストリーミングサーバー（`Exec`・`Attach`・`PortForward` の URL の先）の起動と注入（#3754・CRI-6・REPAIR-5・REPAIR-3）。
//!
//! 呼び出し元: `main.rs` の `serve`。runtime の構築直後（UDS の bind より前）に [`bind_production_streaming`] で loopback の
//! `fandhe_container_cri::streaming::StreamingServer` を起動し、その `issuer()` を `CriRuntimeService::with_streaming` へ渡す。
//! 停止は [`stop_streaming_on`] で包んだ shutdown future が担い、SIGTERM・SIGINT（#3226）の受信と同時に TCP の待ち受けを閉じる。
//!
//! # 現状（REPAIR-3）
//! 結線済みは Attach（Linux は完全版〔`supervisor_attach::SupervisorAttachBackend`。kind 9 の tap と fd の受け取り。#4077〕で、
//! stdin・tty・resize を扱い、RPC 時の整合検査は cri の `attach_impl`〔D7。#4078〕。実機の通しは `tests/cri_attach_real.rs`（#4079）。非 Linux は
//! 読み取り専用の [`log_attach::LogFollowAttachBackend`]〔回転ログの follow。#3763〕で、stdin・tty は RPC 時に `INVALID_ARGUMENT`）と、PortForward の NODE ネットワーク（hostNetwork）の pod
//! （#3755。[`NodeLoopbackDialer`]）。POD ネットワークの pod は RPC 時（cri）と dialer の両方で `UNIMPLEMENTED` で、
//! 保持役（#2877）と helper 方式（#3766）まで続く。Exec は Linux で結線済み（`exec_launcher::SupervisorExecLauncher`。
//! supervisor の `stream-exec` helper 経由。stdin・stdout・stderr のみで、tty と相対 `argv[0]` は RPC 時に `INVALID_ARGUMENT`。#3761）で、
//! 非 Linux は「exec streaming is not wired」の `UNIMPLEMENTED`。`wiring` は bind 時に 1 回だけ取られるため、
//! ハンドラは必ず bind より前に足す（[`bind_production_streaming`] が順序を固定する）。
//!
//! # 安全側の既定
//! 待ち受けは `127.0.0.1:0`・外部公開なし・トークンは単回使用で TTL 60 秒（`StreamingConfig::default()`）。
//! 外部公開は起動引数 `--streaming-bind` / `--streaming-allow-external` / `--streaming-advertise` を明示したときだけ開く
//! （[`production_streaming_config_with`]。#4110）。TLS と認証は無く、URL の 256 ビットのトークンが唯一の認可なので、
//! 外部公開するなら前段の守り（ネットワーク制限・リバースプロキシ）が前提になる。開いたときは起動時に
//! [`EXTERNAL_EXPOSURE_WARNING`] を 1 行出す。
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
//! 完全版の Attach（Linux。#4077）は、セッションの部品の drop で監視スレッドが 10 ms 以内に抜け、入力スレッドは socket の EOF か
//! 書き込みの失敗で抜ける（コンテナが stdin を読まないと止まるが、同時数 64 に数えられ有界）。待ちは足さない。
//! PortForward の Upgrade 後のセッションと実行中の blocking の dial（最長 `dial_timeout` 10 秒）も、プロセス終了時の
//! `rt.shutdown_timeout` が打ち切るため待ちは増えず、`SHUTDOWN_TOTAL_BOUND` は変わらない（#3755 で再評価）。
//! Exec のセッションは長寿命になりうるため、停止時に `exec_launcher` が追跡中の helper を kill する（`stop_streaming_on` の `on_stop`。
//! helper の期限は最長 1 時間）。ドレイン待ちは足さない。
//! 設計は `docs/design/cri-streaming-server.md`。

pub mod log_attach;

#[cfg(target_os = "linux")]
pub mod exec_launcher;

#[cfg(target_os = "linux")]
pub mod supervisor_attach;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::startup::StreamingOptions;

mod node_dialer;

pub use node_dialer::NodeLoopbackDialer;

use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::instrument::CriOpRecorder;
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

/// 起動引数（`--streaming-*`。#4110）を重ねた本番の設定。全未指定なら [`production_streaming_config`] と同値。
///
/// 検証は `startup::parse_args` が `validate()` で済ませるが、`bind_production_streaming` の bind も同じ検証を通る（多層防御）。
pub fn production_streaming_config_with(opts: &StreamingOptions) -> StreamingConfig {
    let mut c = production_streaming_config();
    if let Some(bind) = opts.bind {
        c = c.with_bind(bind);
    }
    c = c.with_allow_external(opts.allow_external);
    if let Some(adv) = opts.advertise {
        c = c.with_advertise_addr(adv);
    }
    c
}

/// 外部公開の opt-in 時に起動時に 1 回だけ出す警告行（固定文言。アドレス・ポートは含めない。REPAIR-4）。
pub const EXTERNAL_EXPOSURE_WARNING: &str = "{\"level\":\"warn\",\"event\":\"cri_streaming_external_exposure\",\"message\":\"cri streaming server listens on a non-loopback address without TLS or authentication; restrict access with network controls or a reverse proxy\"}";

/// 実際の待ち受けアドレスが非 loopback で opt-in 済みのときだけ警告行を返す（#4110・CRI-6）。
pub fn external_exposure_warning(
    config: &StreamingConfig,
    local: SocketAddr,
) -> Option<&'static str> {
    (config.allow_external && !local.ip().is_loopback()).then_some(EXTERNAL_EXPOSURE_WARNING)
}

/// 本番の Attach の backend と、それが対話（stdin・tty・resize）できるかの宣言（#4078）。
///
/// backend と読み取り専用の印の取り違え（対話できない backend を対話として宣言する等）を型で表せなくするため、
/// 構築口を backend の型で絞る。`main.rs` が Linux では `ProductionAttach::interactive`、非 Linux では
/// `ProductionAttach::read_only` で作る。
pub struct ProductionAttach {
    backend: Arc<dyn AttachBackend>,
    interactive: bool,
}

impl ProductionAttach {
    /// 完全版（kind 9 の fd と tap）。stdin・tty を RPC 時に受ける（整合検査は cri の `attach_impl`。D7）。
    #[cfg(target_os = "linux")]
    pub fn interactive(backend: Arc<supervisor_attach::SupervisorAttachBackend>) -> Self {
        Self {
            backend,
            interactive: true,
        }
    }

    /// 回転ログの follow（読み取り専用）。stdin・tty は RPC 時に `INVALID_ARGUMENT`（非 Linux の本番）。
    pub fn read_only(backend: Arc<log_attach::LogFollowAttachBackend>) -> Self {
        Self {
            backend,
            interactive: false,
        }
    }
}

/// 本番の `StreamDispatcher`。Attach（Linux は対話可能な完全版、非 Linux は読み取り専用。#3763・#4078）・PortForward（NODE ネットワークの pod だけ。#3755）・
/// Exec（`exec` が `Some` のとき。stdin・stdout・stderr のみで tty なし、絶対パスの `argv[0]` のみ。#3761）を結線する。
///
/// 期限は本番の設定（[`production_streaming_config`]）の
/// `session_limits()`。ハンドラの構築失敗（設定検証。既定では起きない）は `Internal` の固定文言に写す。
pub fn production_stream_dispatcher(
    attach: ProductionAttach,
    exec: Option<Arc<dyn ExecStreamLauncher>>,
    recorder: Arc<dyn CriOpRecorder>,
) -> Result<StreamDispatcher, PluginError> {
    let attach_handler = AttachHandler::new(
        attach.backend,
        production_streaming_config().session_limits(),
    )
    .map_err(|_| PluginError::new(PluginErrorCode::Internal, MSG_STREAMING_START_FAILED))?;
    let attach_handler = if attach.interactive {
        attach_handler
    } else {
        attach_handler.read_only()
    };
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
            .absolute_command_only()
            // 本番の記録先を注入する（既定の Noop だと統計出力に届かない。REPAIR-4）。
            .with_recorder(recorder);
        dispatcher = dispatcher.with_exec(Arc::new(exec_handler));
    }
    Ok(dispatcher)
}

/// dispatcher を組んでから `StreamingServer` を起動する。`tokio` の実行時の中で呼ぶ。
///
/// `exec` が `None`（非 Linux）なら Exec は未結線で `UNIMPLEMENTED` のまま。失敗は `Unavailable`（bind・アドレス取得）と `Internal`（設定検証。本番の既定では起きない）の固定文言に写す。
pub async fn bind_production_streaming(
    config: StreamingConfig,
    attach: ProductionAttach,
    exec: Option<Arc<dyn ExecStreamLauncher>>,
    recorder: Arc<dyn CriOpRecorder>,
) -> Result<StreamingServer, PluginError> {
    let dispatcher = production_stream_dispatcher(attach, exec, recorder)?;
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

/// drop されたときも `on_stop` を必ず 1 回呼ぶガード（future の取消・serve のエラーでも helper を残さない。REPAIR-5・#3761）。
struct StopGuard<G: FnOnce()>(Option<G>);

impl<G: FnOnce()> Drop for StopGuard<G> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// `shutdown` の完了で `server` の待ち受けを閉じ、`on_stop`（exec の追跡中 helper の kill 等）を呼ぶ future。
/// `serve_with_audit` の shutdown future として渡す。
///
/// future ごと drop されたときも `StreamingServer::drop` が閉じ、`on_stop` も drop ガードで呼ばれる。
pub async fn stop_streaming_on<F: Future<Output = ()>>(
    server: StreamingServer,
    on_stop: impl FnOnce(),
    shutdown: F,
) {
    // 追跡中の exec helper を kill する（長寿命のセッションを残さない）。完了・drop のどちらでも走る。
    let _guard = StopGuard(Some(on_stop));
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
    fn noop_recorder() -> Arc<dyn CriOpRecorder> {
        Arc::new(fandhe_container_cri::instrument::NoopCriOpRecorder)
    }

    /// 読み取り専用の本番構成（非 Linux の本番と同じ。ログは読まれない）。
    fn fake_attach() -> ProductionAttach {
        ProductionAttach::read_only(Arc::new(
            log_attach::LogFollowAttachBackend::new(
                std::env::temp_dir().join("fandhe-attach-unused"),
                log_attach::test_support::FakeProbe::running(),
            )
            .expect("backend"),
        ))
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

    /// CRI-6・#4110: 全未指定の起動引数は既定の設定と同値で、loopback・外部公開なし。
    #[test]
    fn cri6_4110_default_options_equal_default_config() {
        let c = production_streaming_config_with(&StreamingOptions::default());
        assert_eq!(c.bind, SocketAddr::new(LOOPBACK, 0));
        assert!(!c.allow_external);
        assert_eq!(c.advertise_addr, None);
        assert_eq!(c.token_ttl, Duration::from_secs(60));
    }

    /// CRI-6・#4110: opt-in でワイルドカードに bind し、広告アドレスの URL を発行する。
    #[tokio::test]
    async fn cri6_4110_opt_in_binds_wildcard_and_advertises() {
        let opts = StreamingOptions {
            bind: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            allow_external: true,
            advertise: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
        };
        let config = production_streaming_config_with(&opts);
        let server =
            bind_production_streaming(config.clone(), fake_attach(), None, noop_recorder())
                .await
                .expect("bind");
        let addr = server.local_addr();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_ne!(addr.port(), 0);
        assert_eq!(
            server.issuer().base_url(),
            format!("http://192.0.2.7:{}", addr.port())
        );
        connect(SocketAddr::new(LOOPBACK, addr.port()))
            .await
            .expect("connect via loopback to the wildcard listener");
        assert_eq!(
            external_exposure_warning(&config, addr),
            Some(EXTERNAL_EXPOSURE_WARNING)
        );
    }

    /// CRI-6・#4110・REPAIR-4: 警告は opt-in かつ非 loopback の待ち受けのときだけ。文言は固定でアドレスを含まない。
    #[test]
    fn cri6_4110_external_exposure_warning_only_when_opted_in() {
        let lo = SocketAddr::new(LOOPBACK, 4000);
        let ext = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 4000);
        let closed = production_streaming_config();
        assert_eq!(external_exposure_warning(&closed, lo), None);
        let opted = production_streaming_config().with_allow_external(true);
        assert_eq!(external_exposure_warning(&opted, lo), None);
        assert_eq!(
            external_exposure_warning(&opted, ext),
            Some(EXTERNAL_EXPOSURE_WARNING)
        );
        assert!(EXTERNAL_EXPOSURE_WARNING.contains("without TLS or authentication"));
        assert!(!EXTERNAL_EXPOSURE_WARNING.contains("192.0.2"));
    }

    /// 完全版の backend を `interactive` で渡すと、対話（stdin・tty）を宣言する結線になる（#4078）。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cri6_4078_supervisor_attach_backend_declares_interactive_wiring() {
        let backend = Arc::new(supervisor_attach::tests::backend_for_wiring());
        let server = bind_production_streaming(
            production_streaming_config(),
            ProductionAttach::interactive(backend),
            None,
            noop_recorder(),
        )
        .await
        .expect("bind");
        assert!(server.issuer().wiring().attach_interactive());
    }

    #[tokio::test]
    async fn cri6_3754_production_server_listens_on_loopback_with_attach_and_port_forward() {
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            None,
            noop_recorder(),
        )
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
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            None,
            noop_recorder(),
        )
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
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            None,
            noop_recorder(),
        )
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

    /// REPAIR-5・#3761: shutdown 未完了のまま future が drop されても `on_stop` が 1 回呼ばれる。
    #[tokio::test]
    async fn repair5_3761_on_stop_runs_when_future_is_dropped() {
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            None,
            noop_recorder(),
        )
        .await
        .expect("bind");
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let task = tokio::spawn(stop_streaming_on(
            server,
            move || {
                c.fetch_add(1, Ordering::SeqCst);
            },
            std::future::pending::<()>(),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();
        let _ = task.await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn repair5_3754_streaming_listener_closes_on_shutdown() {
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            None,
            noop_recorder(),
        )
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
            noop_recorder(),
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
            noop_recorder(),
        )
        .await
        .expect_err("external without opt-in");
        assert_eq!(e.code(), PluginErrorCode::Internal);
        assert_eq!(e.message(), MSG_STREAMING_START_FAILED);
    }

    /// CRI-6・CRI-2・#4078: 完全版（`interactive`）の本番構成では、stdin を開いたコンテナへの stdin つき `Attach` が URL を返し、
    /// stdin なしで作ったコンテナへの stdin の要求は `FAILED_PRECONDITION`（D7）。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cri6_cri2_4078_interactive_production_attach_checks_stdin_consistency() {
        let backend = Arc::new(supervisor_attach::tests::backend_for_wiring());
        let server = bind_production_streaming(
            production_streaming_config(),
            ProductionAttach::interactive(backend),
            None,
            noop_recorder(),
        )
        .await
        .expect("bind");
        let svc = CriRuntimeService::new().with_streaming(server.issuer());
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
        let mut ids = Vec::new();
        for (name, stdin) in [("with-stdin", true), ("no-stdin", false)] {
            let id = svc
                .create_container(Request::new(cri::CreateContainerRequest {
                    pod_sandbox_id: sandbox.clone(),
                    config: Some(cri::ContainerConfig {
                        metadata: Some(cri::ContainerMetadata {
                            name: name.into(),
                            attempt: 0,
                        }),
                        image: Some(cri::ImageSpec {
                            image: "busybox:1.36".into(),
                            ..Default::default()
                        }),
                        stdin,
                        ..Default::default()
                    }),
                    sandbox_config: Some(pod.clone()),
                }))
                .await
                .expect("container")
                .into_inner()
                .container_id;
            svc.start_container(Request::new(cri::StartContainerRequest {
                container_id: id.clone(),
            }))
            .await
            .expect("start");
            ids.push(id);
        }
        let url = svc
            .attach(Request::new(cri::AttachRequest {
                container_id: ids[0].clone(),
                stdin: true,
                stdout: true,
                ..Default::default()
            }))
            .await
            .expect("stdin attach to a stdin container")
            .into_inner()
            .url;
        assert!(url.contains("/attach/"), "{url}");
        let err = svc
            .attach(Request::new(cri::AttachRequest {
                container_id: ids[1].clone(),
                stdin: true,
                stdout: true,
                ..Default::default()
            }))
            .await
            .expect_err("stdin was not opened");
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(
            err.message(),
            "the container was not created with stdin open"
        );
    }

    /// CRI-6・#3763: 本番構成（`bind_production_streaming` + `with_streaming`）の `Attach` RPC が URL を返す。
    /// stdin・tty つきは URL を返さず `INVALID_ARGUMENT`。
    #[tokio::test]
    async fn cri6_3763_production_attach_returns_url() {
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            None,
            noop_recorder(),
        )
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
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            Some(launcher),
            noop_recorder(),
        )
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
