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
//! 外部公開（`allow_external`）は plugin-cri からは出さない（opt-in の口は未実装。REPAIR-3）。TLS と認証は無く、URL の
//! 256 ビットのトークンが唯一の認可なので、外部公開するなら前段の守りが前提になる。
//!
//! # 起動失敗
//! bind の失敗は fail-closed（起動しない）。縮退して動き続けると外から「未結線」と区別できないため。
//! エラーは固定文言とコードだけで、アドレスや OS のエラー文字列は出さない（REPAIR-4）。
//!
//! # 停止（REPAIR-5・#4164）
//! 停止は「期限つきドレイン、exec を止める、残りを強制クローズ」の順で行う（方針と理由は設計書の「停止時のセッションの扱い」）。
//! [`stop_streaming_on`] が返す shutdown future は、シグナルの受信で TCP の待ち受けを閉じて**すぐに**完了する
//! （gRPC の listener を閉じる契約〔#3226〕を遅らせないため、待ちは入れない）。待ちは `serve_with_audit` が戻った後に
//! [`StreamingStop::finish`] が行う。基準はシグナルの受信時刻 T の絶対時刻で、(1) T..T+[`STREAMING_DRAIN_WAIT`] は
//! セッションが自分で終わるのを待つ（全部閉じたら早く抜ける）、(2) 期限で `on_stop`（exec の追跡中 helper の kill と
//! 以後の launch の拒否）を呼び、(3) [`STREAMING_CLOSE_WAIT`] まで exec が閉じるのを待ち、(4) 残りを abort する。
//! (1)+(3) は `PLUGIN_SHUTDOWN_GRACE` 以内に収め、`shutdown::SHUTDOWN_TOTAL_BOUND` は変えない（試験で固定）。
//! 期限を過ぎて残った件数は [`StreamingStopReport::line`] の構造化ログ 1 行に出す。
//! PortForward の実行中の blocking の dial（最長 `dial_timeout` 10 秒）は abort できず、プロセス終了時の
//! `rt.shutdown_timeout` が打ち切る（待ちは増えない）。
//! 設計は `docs/design/cri-streaming-server.md`。

pub mod log_attach;

#[cfg(target_os = "linux")]
pub mod exec_launcher;

#[cfg(target_os = "linux")]
pub mod supervisor_attach;

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod node_dialer;

pub use node_dialer::NodeLoopbackDialer;

use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::instrument::CriOpRecorder;
use fandhe_container_cri::streaming::attach::{AttachBackend, AttachHandler};
use fandhe_container_cri::streaming::exec::{
    ExecStreamConfig, ExecStreamHandler, ExecStreamLauncher,
};
use fandhe_container_cri::streaming::port_forward::{PortForwardConfig, PortForwardHandler};
use fandhe_container_cri::streaming::{
    StreamDispatcher, StreamingConfig, StreamingServer, StreamingSessions,
};
use fandhe_container_plugin::{PluginError, PluginErrorCode};

/// 起動失敗時の固定文言（アドレス・OS のエラーは含めない。REPAIR-4）。
pub const MSG_STREAMING_START_FAILED: &str = "failed to start the streaming server";

/// 本番の設定。loopback・外部公開なし・単回トークン TTL 60 秒の既定そのまま。
pub fn production_streaming_config() -> StreamingConfig {
    StreamingConfig::default()
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

/// ドレインの待ち時間（シグナルの受信から）。kubelet の idle 4 時間・作成 30 秒より十分短く、cri の
/// `SessionLimits::default().drain_timeout`（終了後の流し切りの予算）と同じ 5 秒。暫定値で、オーナー確認は #4116 の対象
/// （承認は得ていない。#4164・REPAIR-5）。
pub const STREAMING_DRAIN_WAIT: Duration = Duration::from_secs(5);

/// `on_stop`（helper の kill）の後に、exec が終了を観測して閉じるのを待つ時間。`RUNTIME_SHUTDOWN_WAIT` と同じ 1 秒。
/// 暫定値で #4116 の対象（#4164・REPAIR-5）。
pub const STREAMING_CLOSE_WAIT: Duration = Duration::from_secs(1);

/// 強制クローズ（abort）の後に、タスクの破棄で枠が返るのを確かめる上限。
const STREAMING_FORCE_CONFIRM_WAIT: Duration = Duration::from_millis(100);

/// 停止の待ち時間の組。本番は [`PRODUCTION_STOP_LIMITS`]、試験は短くした値を渡す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamingStopLimits {
    /// ドレイン（自然に終わるのを待つ）時間。
    pub drain: Duration,
    /// `on_stop` の後に exec の終了を待つ時間。
    pub close: Duration,
}

/// 本番の停止の待ち時間。
pub const PRODUCTION_STOP_LIMITS: StreamingStopLimits = StreamingStopLimits {
    drain: STREAMING_DRAIN_WAIT,
    close: STREAMING_CLOSE_WAIT,
};

/// シグナルの受信時刻と、その時点で開いていた件数（shutdown future が記録し、`finish` が読む）。
type SignalCell = Arc<Mutex<Option<(Instant, usize)>>>;

/// [`stop_streaming_on`] が返す、`serve_with_audit` の後に行う停止処理の持ち主。
///
/// 呼び出し元は `main.rs` の `serve`。`finish` を呼ばずに drop されたとき（serve のエラー・future の取消）も、
/// `on_stop` を 1 回呼び、全セッションを abort する（helper を残さない。REPAIR-5・#3761）。
pub struct StreamingStop<G: FnOnce()> {
    sessions: StreamingSessions,
    signal: SignalCell,
    on_stop: Option<G>,
}

impl<G: FnOnce()> Drop for StreamingStop<G> {
    fn drop(&mut self) {
        if let Some(f) = self.on_stop.take() {
            f();
        }
        self.sessions.close_all();
    }
}

impl<G: FnOnce()> StreamingStop<G> {
    /// ドレイン、`on_stop`、強制クローズを行い、結果を返す。
    ///
    /// 期限はシグナルの受信時刻からの絶対時刻なので、`serve_with_audit` が期限より後に戻ったときは
    /// 待たずに即座に `on_stop` と強制クローズへ進む（停止の上限を延ばさない）。シグナルが記録されていない
    /// （serve が先にエラーで戻った）ときも待たない。
    pub async fn finish(mut self, limits: StreamingStopLimits) -> StreamingStopReport {
        let recorded = self
            .signal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let (t0, open_at_stop, drain_deadline, close_deadline) = match recorded {
            Some((t0, open)) => (
                t0,
                open,
                t0 + limits.drain,
                t0 + limits.drain + limits.close,
            ),
            None => {
                let now = Instant::now();
                (now, self.sessions.open(), now, now)
            }
        };
        let exceeded = self.sessions.wait_idle_until(drain_deadline).await;
        // 期限を超えたので exec を止める（helper の kill と以後の launch の拒否）。exec のセッションは終了を観測して閉じる。
        if let Some(f) = self.on_stop.take() {
            f();
        }
        let forced = self.sessions.wait_idle_until(close_deadline).await;
        if forced > 0 {
            self.sessions.close_all();
        }
        // close_all は予約済みの登録も止める。abort したタスクの破棄は次の poll で起きるため、枠が返るのを短く確かめる。
        let remaining = self
            .sessions
            .wait_idle_until(Instant::now() + STREAMING_FORCE_CONFIRM_WAIT)
            .await;
        StreamingStopReport {
            open_at_stop,
            drained: open_at_stop.saturating_sub(exceeded),
            exceeded,
            forced,
            remaining,
            elapsed_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// 停止時のセッションの扱いの結果（件数と経過だけ。トークン・コンテナ ID・アドレスは含めない。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamingStopReport {
    /// シグナルを受けた時点で開いていた接続・セッションの数。
    pub open_at_stop: usize,
    /// ドレインの期限までに自分で閉じた数。
    pub drained: usize,
    /// ドレインの期限を超えて残った数。
    pub exceeded: usize,
    /// `on_stop` の後の待ちを超えて残り、abort した数。
    pub forced: usize,
    /// abort の後も残った数（0 が正常）。
    pub remaining: usize,
    /// シグナルの受信から停止処理の終わりまでの経過（ミリ秒）。
    pub elapsed_ms: u64,
}

impl StreamingStopReport {
    /// 構造化ログの 1 行（`adapter::sweep_summary_line` と同じ JSON の形）。期限を超えたか残ったときは `warn`。
    pub fn line(&self) -> String {
        let level = if self.exceeded > 0 || self.remaining > 0 {
            "warn"
        } else {
            "info"
        };
        format!(
            "{{\"level\":\"{level}\",\"event\":\"cri_streaming_stop\",\"open_at_stop\":{},\"drained\":{},\"exceeded\":{},\"forced\":{},\"remaining\":{},\"elapsed_ms\":{}}}",
            self.open_at_stop,
            self.drained,
            self.exceeded,
            self.forced,
            self.remaining,
            self.elapsed_ms
        )
    }
}

/// `shutdown` の完了で `server` の待ち受けを閉じる future と、その後の停止処理 [`StreamingStop`] の組を返す。
/// 第 1 要素は `serve_with_audit` の shutdown future として渡し、第 2 要素は serve が戻った後に
/// [`StreamingStop::finish`] する。
///
/// 第 1 要素は待ちを持たない（gRPC の listener を閉じる契約を遅らせない）。ドロップされたときも
/// `StreamingServer::drop` が待ち受けを閉じ、`StreamingStop` の drop が `on_stop` を呼ぶ。
pub fn stop_streaming_on<F: Future<Output = ()>, G: FnOnce()>(
    server: StreamingServer,
    on_stop: G,
    shutdown: F,
) -> (impl Future<Output = ()>, StreamingStop<G>) {
    let sessions = server.sessions();
    let signal: SignalCell = Arc::new(Mutex::new(None));
    let stop = StreamingStop {
        sessions: sessions.clone(),
        signal: Arc::clone(&signal),
        on_stop: Some(on_stop),
    };
    let fut = async move {
        shutdown.await;
        let at = Instant::now();
        let open = sessions.open();
        *signal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((at, open));
        server.shutdown();
    };
    (fut, stop)
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

    /// REPAIR-5・#3761・#4164: `finish` されないまま `StreamingStop` が drop されても `on_stop` が 1 回呼ばれる。
    /// shutdown future だけが先に drop されても、`StreamingStop` が生きている間は呼ばれない。
    #[tokio::test]
    async fn repair5_3761_on_stop_runs_when_stop_is_dropped() {
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
        let (fut, stop) = stop_streaming_on(
            server,
            move || {
                c.fetch_add(1, Ordering::SeqCst);
            },
            std::future::pending::<()>(),
        );
        let task = tokio::spawn(fut);
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();
        let _ = task.await;
        assert_eq!(count.load(Ordering::SeqCst), 0);
        drop(stop);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// REPAIR-5・#3754・#4164: shutdown future の完了ですぐに待ち受けが閉じる（待ちを足さない）。
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
        let (fut, _stop) = stop_streaming_on(server, || {}, async move {
            while !f.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        let task = tokio::spawn(fut);
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

    /// 試験用の短い期限。
    const TEST_LIMITS: StreamingStopLimits = StreamingStopLimits {
        drain: Duration::from_millis(500),
        close: Duration::from_millis(200),
    };

    /// 何も送らない接続を `n` 本張り、サーバー側で `n` 件に数えられるまで待つ。
    async fn open_idle_connections(
        addr: SocketAddr,
        sessions: &StreamingSessions,
        n: usize,
    ) -> Vec<std::net::TcpStream> {
        let mut conns = Vec::new();
        for _ in 0..n {
            conns.push(connect(addr).await.expect("connect"));
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while sessions.open() < n && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(sessions.open(), n);
        conns
    }

    /// 読み取りが EOF（または接続の切断）で戻ることを確かめる。期限切れ（まだ開いている）は失敗。
    async fn assert_closed_by_peer(conn: std::net::TcpStream) {
        use std::io::Read;
        let result = tokio::task::spawn_blocking(move || {
            let mut conn = conn;
            conn.set_read_timeout(Some(Duration::from_secs(2)))
                .expect("timeout");
            let mut buf = [0u8; 16];
            conn.read(&mut buf)
        })
        .await
        .expect("join");
        match result {
            Ok(n) => assert_eq!(n, 0, "expected EOF"),
            Err(e) => assert!(
                !matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "connection must be closed, got {e}"
            ),
        }
    }

    /// CRI-6・REPAIR-5・#4164: 3 件を開いたまま停止しても、期限（ドレイン + 余裕）のうちに終わり、全部閉じられる。
    /// `on_stop` はちょうど 1 回で、強制クローズより前（3 件が開いたまま）に呼ばれる。
    #[tokio::test]
    async fn cri6_repair5_4164_stop_with_three_open_sessions_finishes_within_bound() {
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            None,
            noop_recorder(),
        )
        .await
        .expect("bind");
        let addr = server.local_addr();
        let sessions = server.sessions();
        let conns = open_idle_connections(addr, &sessions, 3).await;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let open_at_call = Arc::new(std::sync::atomic::AtomicUsize::new(usize::MAX));
        let (c, o, s2) = (
            Arc::clone(&calls),
            Arc::clone(&open_at_call),
            sessions.clone(),
        );
        let (fut, stop) = stop_streaming_on(
            server,
            move || {
                c.fetch_add(1, Ordering::SeqCst);
                o.store(s2.open(), Ordering::SeqCst);
            },
            std::future::ready(()),
        );
        fut.await;
        let started = Instant::now();
        let report = tokio::time::timeout(Duration::from_secs(5), stop.finish(TEST_LIMITS))
            .await
            .expect("finish must be bounded");
        assert!(
            started.elapsed() < TEST_LIMITS.drain + TEST_LIMITS.close + Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            (
                report.open_at_stop,
                report.drained,
                report.exceeded,
                report.forced,
                report.remaining
            ),
            (3, 0, 3, 3, 0)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(open_at_call.load(Ordering::SeqCst), 3);
        assert_eq!(sessions.open(), 0);
        for conn in conns {
            assert_closed_by_peer(conn).await;
        }
    }

    /// CRI-6・REPAIR-5・#4164: ドレインの期限内に自然に終わったセッションの応答は欠けない（残りだけが強制クローズ）。
    #[tokio::test]
    async fn cri6_repair5_4164_drain_delivers_response_finished_within_deadline() {
        use std::io::{Read, Write};
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            None,
            noop_recorder(),
        )
        .await
        .expect("bind");
        let addr = server.local_addr();
        let sessions = server.sessions();
        let mut conns = open_idle_connections(addr, &sessions, 3).await;
        let (fut, stop) = stop_streaming_on(server, || {}, std::future::ready(()));
        fut.await;
        // 停止を受けた後に、不正なトークンの要求を 1 本だけ送る。404 の応答全体を受け取って閉じるはず。
        let mut talker = conns.remove(0);
        let client = tokio::task::spawn_blocking(move || {
            talker
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("timeout");
            talker
                .write_all(b"GET /attach/zz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .expect("write");
            let mut out = Vec::new();
            let _ = talker.read_to_end(&mut out);
            String::from_utf8_lossy(&out).into_owned()
        });
        let report = tokio::time::timeout(Duration::from_secs(5), stop.finish(TEST_LIMITS))
            .await
            .expect("finish must be bounded");
        let response = client.await.expect("join");
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
        assert!(response.ends_with("not found"), "{response}");
        assert_eq!(
            (
                report.open_at_stop,
                report.drained,
                report.exceeded,
                report.forced,
                report.remaining
            ),
            (3, 1, 2, 2, 0)
        );
        for conn in conns {
            assert_closed_by_peer(conn).await;
        }
    }

    /// REPAIR-5・#4164: 期限は絶対時刻なので、serve が期限より後に戻ったときは追加の待ちが無い。
    #[tokio::test]
    async fn repair5_4164_finish_after_deadline_does_not_wait_again() {
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            None,
            noop_recorder(),
        )
        .await
        .expect("bind");
        let sessions = server.sessions();
        let _conns = open_idle_connections(server.local_addr(), &sessions, 1).await;
        let limits = StreamingStopLimits {
            drain: Duration::from_millis(100),
            close: Duration::from_millis(100),
        };
        let (fut, stop) = stop_streaming_on(server, || {}, std::future::ready(()));
        fut.await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let started = Instant::now();
        let report = stop.finish(limits).await;
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            (report.exceeded, report.forced, report.remaining),
            (1, 1, 0)
        );
    }

    /// REPAIR-5・#4164: シグナルが記録されないまま `finish` したとき（serve が先にエラーで戻った等）は待たずに止める。
    #[tokio::test]
    async fn repair5_4164_finish_without_signal_stops_immediately() {
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            None,
            noop_recorder(),
        )
        .await
        .expect("bind");
        let sessions = server.sessions();
        let conns = open_idle_connections(server.local_addr(), &sessions, 1).await;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let (_fut, stop) = stop_streaming_on(
            server,
            move || {
                c.fetch_add(1, Ordering::SeqCst);
            },
            std::future::pending::<()>(),
        );
        let started = Instant::now();
        let report = stop.finish(PRODUCTION_STOP_LIMITS).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            (report.open_at_stop, report.forced, report.remaining),
            (1, 1, 0)
        );
        for conn in conns {
            assert_closed_by_peer(conn).await;
        }
    }

    /// REPAIR-4・#4164: 停止の 1 行の形（info / warn。トークン・ID・アドレスを含まない）。
    #[test]
    fn repair4_4164_stop_report_line_is_fixed_shape() {
        let clean = StreamingStopReport {
            open_at_stop: 2,
            drained: 2,
            exceeded: 0,
            forced: 0,
            remaining: 0,
            elapsed_ms: 130,
        };
        assert_eq!(
            clean.line(),
            "{\"level\":\"info\",\"event\":\"cri_streaming_stop\",\"open_at_stop\":2,\"drained\":2,\"exceeded\":0,\"forced\":0,\"remaining\":0,\"elapsed_ms\":130}"
        );
        let exceeded = StreamingStopReport {
            open_at_stop: 3,
            drained: 1,
            exceeded: 2,
            forced: 2,
            remaining: 0,
            elapsed_ms: 6012,
        };
        assert_eq!(
            exceeded.line(),
            "{\"level\":\"warn\",\"event\":\"cri_streaming_stop\",\"open_at_stop\":3,\"drained\":1,\"exceeded\":2,\"forced\":2,\"remaining\":0,\"elapsed_ms\":6012}"
        );
    }

    /// REPAIR-5・#4164: ドレインと閉鎖の待ちの合計は gRPC の猶予以内で、停止の全体の上限（13.7 秒）は変わらない。
    #[test]
    fn repair5_4164_stop_waits_fit_within_grpc_grace_and_total_bound() {
        assert_eq!(STREAMING_DRAIN_WAIT, Duration::from_secs(5));
        assert_eq!(STREAMING_CLOSE_WAIT, Duration::from_secs(1));
        assert!(
            STREAMING_DRAIN_WAIT + STREAMING_CLOSE_WAIT <= crate::adapter::PLUGIN_SHUTDOWN_GRACE
        );
        assert_eq!(
            crate::shutdown::SHUTDOWN_TOTAL_BOUND,
            Duration::from_millis(13_700)
        );
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
