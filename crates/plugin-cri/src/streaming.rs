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
//! （#3755。[`NodeLoopbackDialer`]）。POD ネットワークの pod は、Linux・非 root で保持役を注入した構成だけ結線済み
//! （`ProductionPortForward::pod_network` の `PodNetnsDialer`。保持役の fd と `netns-dial` helper で pod の netns 内へ接続。#4484・#4486。
//! 実 helper を通す実機の段は `tests/cri_exec_real.rs` の段 F で照合済み。#4487）。保持役が無い構成（rootful・注入なし・別 provider）は [`ProductionPortForward::node_only`] で、
//! RPC 時（cri）に `UNIMPLEMENTED` のまま（host loopback へは縮退しない）。
//! Exec は Linux で結線済み（`exec_launcher::SupervisorExecLauncher`。
//! supervisor の `stream-exec` helper 経由。stdin・stdout・stderr と、tty（stdin・stdout・resize。stderr は RPC 時に `INVALID_ARGUMENT`。#4417）を扱い、相対 `argv[0]` は RPC 時に `INVALID_ARGUMENT`。#3761）で、
//! 非 Linux は「exec streaming is not wired」の `UNIMPLEMENTED`。`wiring` は bind 時に 1 回だけ取られるため、
//! ハンドラは必ず bind より前に足す（[`bind_production_streaming`] が順序を固定する）。
//!
//! 接続の受理・拒否・期限切れは `connection_observer::TelemetryConnectionObserver` が telemetry へ出す（#4163・REPAIR-4）。
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
//! # 停止（REPAIR-5・#4164）
//! 停止は「期限つきドレイン、exec を止める、残りを強制クローズ」の順で行う（方針と理由は設計書の「停止時のセッションの扱い」）。
//! [`stop_streaming_on`] が返す shutdown future は、シグナルの受信で TCP の待ち受けを閉じて**すぐに**完了する
//! （gRPC の listener を閉じる契約〔#3226〕を遅らせないため、待ちは入れない）。停止処理はシグナル受信時に別タスクとして起動し、`serve_with_audit` の戻りを待たない
//! （RPC が残って gRPC の猶予を使い切る間も期限どおり動く）。[`StreamingStop::finish`] はその結果を受け取る。基準はシグナルの受信時刻 T の絶対時刻で、(1) T..T+[`STREAMING_DRAIN_WAIT`] は
//! セッションが自分で終わるのを待つ（全部閉じたら早く抜ける）、(2) 期限で `on_stop`（exec の追跡中 helper の kill と
//! 以後の launch の拒否）を呼び、(3) [`STREAMING_CLOSE_WAIT`] まで exec が閉じるのを待ち、(4) 残りを abort する。
//! (1)+(3) は `PLUGIN_SHUTDOWN_GRACE` 以内に収め、`shutdown::SHUTDOWN_TOTAL_BOUND` を延ばさない（値は試験で固定。#4340 で op-stats の最後の書き出しが別に足された）。
//! 期限を過ぎて残った件数は [`StreamingStopReport::line`] の構造化ログ 1 行に出す。
//! PortForward の実行中の blocking の dial（最長 `dial_timeout` 10 秒）は abort できず、プロセス終了時の
//! `rt.shutdown_timeout` が打ち切る（待ちは増えない）。
//! 設計は `docs/design/cri-streaming-server.md`。

pub mod connection_observer;
pub mod log_attach;

#[cfg(target_os = "linux")]
pub mod exec_launcher;

#[cfg(target_os = "linux")]
pub mod supervisor_attach;

#[cfg(target_os = "linux")]
mod pod_dialer;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::startup::StreamingOptions;

mod node_dialer;

pub use node_dialer::NodeLoopbackDialer;

#[cfg(target_os = "linux")]
pub use pod_dialer::{
    CONNECT_MARGIN, HELPER_EXIT_WAIT, HELPER_REAP_WAIT, KILL_REAP_RESERVE,
    MAX_RETAINED_DIAL_HELPERS, NetnsDialSpawner, OP_PF_HELPER_RETAINED, OP_PF_RETAINED_FULL,
    OP_PF_RETAINED_OVER_LIMIT, PodDialTelemetry, PodNamespaceSource, PodNetnsDialer,
    SupervisorNetnsDialSpawner,
};

use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::instrument::CriOpRecorder;
use fandhe_container_cri::streaming::attach::{AttachBackend, AttachHandler};
use fandhe_container_cri::streaming::exec::{
    ExecStreamConfig, ExecStreamHandler, ExecStreamLauncher,
};
use fandhe_container_cri::streaming::port_forward::{
    PortForwardConfig, PortForwardDialer, PortForwardHandler,
};
use fandhe_container_cri::streaming::{
    ConnectionObserver, StreamDispatcher, StreamingConfig, StreamingServer, StreamingSessions,
};
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

/// 本番の PortForward の dialer と、POD ネットワークに対応するかの宣言（#4486・CRI-6・NET-3・SEC-1）。
///
/// 保持役（`PodNamespaceSource`）が無いと POD 対応の dialer を作れないよう、構築口を絞る。`main.rs` が
/// `CriPluginBackends::pod_namespace_source` の有無で選ぶ。`node_only` の構成では POD の PortForward は RPC 時（cri）に
/// `UNIMPLEMENTED` のままで、host loopback へは縮退しない。
pub struct ProductionPortForward {
    dialer: Arc<dyn PortForwardDialer>,
}

impl ProductionPortForward {
    /// NODE ネットワーク（hostNetwork）の pod だけ（[`NodeLoopbackDialer`]。`supports_pod_network` は偽）。
    pub fn node_only() -> Self {
        Self {
            dialer: Arc::new(NodeLoopbackDialer::new()),
        }
    }

    /// POD ネットワークにも対応する（Linux のみ。[`PodNetnsDialer`]。`supports_pod_network` は真）。
    /// `source` は cri へ渡す保持役 provider と同じ表を指すこと（`CriPluginBackends::pod_namespace_source` が保証する）。
    #[cfg(target_os = "linux")]
    /// `telemetry` は回収できない helper の保持・上限超過・満杯の拒否の観測（#4546。省けない）。
    pub fn pod_network(source: Arc<dyn PodNamespaceSource>, telemetry: PodDialTelemetry) -> Self {
        Self {
            dialer: Arc::new(PodNetnsDialer::new(source, telemetry)),
        }
    }
}

/// 本番の `StreamDispatcher`。Attach（Linux は対話可能な完全版、非 Linux は読み取り専用。#3763・#4078）・PortForward（NODE ネットワークの pod と、保持役がある Linux 構成の POD ネットワーク。#3755・#4486）・
/// Exec（`exec` が `Some` のとき。stdin・stdout・stderr と tty、絶対パスの `argv[0]` のみ。#3761・#4417）を結線する。
///
/// 期限は本番の設定（[`production_streaming_config`]）の
/// `session_limits()`。ハンドラの構築失敗（設定検証。既定では起きない）は `Internal` の固定文言に写す。
pub fn production_stream_dispatcher(
    attach: ProductionAttach,
    port_forward: ProductionPortForward,
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
    let port_forward =
        PortForwardHandler::new(port_forward.dialer, PortForwardConfig::default())
            .map_err(|_| PluginError::new(PluginErrorCode::Internal, MSG_STREAMING_START_FAILED))?;
    let mut dispatcher = StreamDispatcher::new()
        .with_attach(Arc::new(attach_handler))
        .with_port_forward(Arc::new(port_forward));
    // Exec は起動役（Linux の supervisor helper 経由。#3761）がある構成だけ結線する。相対 argv[0] は宣言せず
    // RPC 時に `INVALID_ARGUMENT` で断る（PATH 解決の判断が済むまで。#2439・REPAIR-3）。tty は #4417 で宣言する。
    if let Some(launcher) = exec {
        let config = ExecStreamConfig {
            limits: production_streaming_config().session_limits(),
            ..ExecStreamConfig::default()
        };
        let exec_handler = ExecStreamHandler::new(launcher, config)
            .map_err(|_| PluginError::new(PluginErrorCode::Internal, MSG_STREAMING_START_FAILED))?
            .absolute_command_only()
            // 本番の記録先を注入する（既定の Noop だと統計出力に届かない。REPAIR-4）。
            .with_recorder(recorder);
        dispatcher = dispatcher.with_exec(Arc::new(exec_handler));
    }
    Ok(dispatcher)
}

/// dispatcher を組んでから `StreamingServer` を起動する。`tokio` の実行時の中で呼ぶ。
///
/// `observer` は接続の受理・拒否・期限切れの観測口（本番は [`connection_observer::TelemetryConnectionObserver`]。#4163・REPAIR-4）。
/// `exec` が `None`（非 Linux）なら Exec は未結線で `UNIMPLEMENTED` のまま。失敗は `Unavailable`（bind・アドレス取得）と `Internal`（設定検証。本番の既定では起きない）の固定文言に写す。
pub async fn bind_production_streaming(
    config: StreamingConfig,
    attach: ProductionAttach,
    port_forward: ProductionPortForward,
    exec: Option<Arc<dyn ExecStreamLauncher>>,
    recorder: Arc<dyn CriOpRecorder>,
    observer: Arc<dyn ConnectionObserver>,
) -> Result<StreamingServer, PluginError> {
    let dispatcher = production_stream_dispatcher(attach, port_forward, exec, recorder)?;
    StreamingServer::bind_with_observer(config, Arc::new(dispatcher), observer)
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

/// シグナルを受けて起動した停止処理のタスク（結果の報告を返す）。
type StopTask = Arc<Mutex<Option<tokio::task::JoinHandle<StreamingStopReport>>>>;

/// [`stop_streaming_on`] が返す、停止処理の結果を受け取る持ち主。
///
/// 呼び出し元は `main.rs` の `serve`。ドレイン・`on_stop`・強制クローズはシグナルの受信時に shutdown future が
/// 別タスクとして起動し、`serve_with_audit`（gRPC の終了待ち）の戻りを待たずに、シグナルの受信時刻 T からの
/// 絶対時刻で進む（RPC が残って gRPC の猶予を使い切る間も期限どおりに動く。#4164・REPAIR-5）。`finish` はそのタスクの終了を待って
/// 結果を返す。`finish` を呼ばずに drop されたとき（serve のエラー・future の取消）も、`on_stop` を 1 回呼び、
/// 全セッションを abort する（helper を残さない。REPAIR-5・#3761）。
pub struct StreamingStop<G: FnOnce() + Send + 'static> {
    sessions: StreamingSessions,
    on_stop: Arc<Mutex<Option<G>>>,
    task: StopTask,
}

/// `on_stop` を（まだなら）1 回だけ呼ぶ。
fn take_and_run<G: FnOnce()>(on_stop: &Mutex<Option<G>>) {
    let f = on_stop
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(f) = f {
        f();
    }
}

impl<G: FnOnce() + Send + 'static> Drop for StreamingStop<G> {
    fn drop(&mut self) {
        if let Some(h) = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            h.abort();
        }
        take_and_run(&self.on_stop);
        self.sessions.close_all();
    }
}

/// シグナルの受信時刻 `t0` を起点にした停止処理の本体（別タスクで走る）。
async fn run_stop<G: FnOnce()>(
    sessions: StreamingSessions,
    on_stop: Arc<Mutex<Option<G>>>,
    limits: StreamingStopLimits,
    t0: Instant,
    open_at_stop: usize,
) -> StreamingStopReport {
    let exceeded = sessions.wait_idle_until(t0 + limits.drain).await;
    // 期限を超えたので exec を止める（helper の kill と以後の launch の拒否）。exec のセッションは終了を観測して閉じる。
    take_and_run(&on_stop);
    let forced = sessions
        .wait_idle_until(t0 + limits.drain + limits.close)
        .await;
    if forced > 0 {
        sessions.close_all();
    }
    // close_all は予約済みの登録も止める。abort したタスクの破棄は次の poll で起きるため、枠が返るのを短く確かめる。
    let remaining = sessions
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

impl<G: FnOnce() + Send + 'static> StreamingStop<G> {
    /// 停止処理の終了を待って結果を返す。
    ///
    /// 停止処理はシグナルの受信時に起動済みで、期限もその時刻が基準なので、ここでの待ちは期限を延ばさない。
    /// シグナルが記録されていない（serve が先にエラーで戻った）ときは待たずに `on_stop` と強制クローズへ進む。
    pub async fn finish(self) -> StreamingStopReport {
        let handle = self
            .task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        // タスクが panic した場合（`Err`）は下へ進み、止める処理を自分で行って残りを数える。
        if let Some(h) = handle
            && let Ok(report) = h.await
        {
            return report;
        }
        let t0 = Instant::now();
        let open_at_stop = self.sessions.open();
        take_and_run(&self.on_stop);
        self.sessions.close_all();
        let remaining = self
            .sessions
            .wait_idle_until(Instant::now() + STREAMING_FORCE_CONFIRM_WAIT)
            .await;
        StreamingStopReport {
            open_at_stop,
            drained: 0,
            exceeded: open_at_stop,
            forced: open_at_stop.saturating_sub(remaining),
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

/// `shutdown` の完了で `server` の待ち受けを閉じ、停止処理（ドレイン・`on_stop`・強制クローズ）を別タスクで起動する
/// future と、その結果を受け取る [`StreamingStop`] の組を返す。
///
/// 第 1 要素は `serve_with_audit` の shutdown future として渡す。待ちは持たず（gRPC の listener を閉じる契約を遅らせない）、
/// シグナル受信時刻 T を基準に停止処理のタスクを `tokio::spawn` して直ちに完了する。タスクは `serve_with_audit` の戻りと無関係に
/// 期限（T+`limits.drain` で `on_stop`、T+`limits.drain`+`limits.close` で強制クローズ）どおりに進む。
/// 第 2 要素は serve が戻った後に [`StreamingStop::finish`] する。`tokio` の実行時の中で polling されること。
pub fn stop_streaming_on<F: Future<Output = ()>, G: FnOnce() + Send + 'static>(
    server: StreamingServer,
    limits: StreamingStopLimits,
    on_stop: G,
    shutdown: F,
) -> (impl Future<Output = ()>, StreamingStop<G>) {
    let sessions = server.sessions();
    let on_stop = Arc::new(Mutex::new(Some(on_stop)));
    let task: StopTask = Arc::new(Mutex::new(None));
    let stop = StreamingStop {
        sessions: sessions.clone(),
        on_stop: Arc::clone(&on_stop),
        task: Arc::clone(&task),
    };
    let fut = async move {
        shutdown.await;
        let at = Instant::now();
        let open = sessions.open();
        server.shutdown();
        let handle = tokio::spawn(run_stop(sessions, on_stop, limits, at, open));
        *task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
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

    /// 何も観測しない口（観測を要さない既存試験用）。
    fn noop_observer() -> Arc<dyn ConnectionObserver> {
        Arc::new(fandhe_container_cri::streaming::NoopObserver)
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
        let server = bind_production_streaming(
            config.clone(),
            fake_attach(),
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
        )
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
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
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
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
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
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
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
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
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

    /// 偽の保持役 provider（#4486 の試験用。spawn は pid を返すだけ）。
    #[cfg(target_os = "linux")]
    struct FakeProvider;

    #[cfg(target_os = "linux")]
    impl fandhe_container_cri::adapter::PodNamespaceHolderProvider for FakeProvider {
        fn spawn(
            &self,
            _req: &fandhe_container_cri::adapter::PodHolderRequest<'_>,
        ) -> Result<fandhe_container_cri::adapter::PodHolder, fandhe_container_cri::error::CriError>
        {
            Ok(fandhe_container_cri::adapter::PodHolder::new(
                std::num::NonZeroU32::new(4242).expect("pid"),
            ))
        }
        fn release(
            &self,
            _sandbox_id: &str,
            _timeout: Duration,
        ) -> Result<(), fandhe_container_cri::error::CriError> {
            Ok(())
        }
        fn liveness(
            &self,
            _sandbox_id: &str,
        ) -> Result<
            fandhe_container_cri::adapter::PodHolderLiveness,
            fandhe_container_cri::error::CriError,
        > {
            Ok(fandhe_container_cri::adapter::PodHolderLiveness::Alive)
        }
    }

    /// `open_pod_namespaces` を呼ばれたら `Unavailable`（URL の発行では呼ばれない）。
    #[cfg(target_os = "linux")]
    struct UnusedSource;

    #[cfg(target_os = "linux")]
    impl PodNamespaceSource for UnusedSource {
        fn open_pod_namespaces(
            &self,
            _sandbox_id: &str,
        ) -> Result<
            crate::pod_holder::PodNamespaceFds,
            fandhe_container_core::traits::types::TraitError,
        > {
            Err(fandhe_container_core::traits::types::TraitError::new(
                fandhe_container_core::traits::types::ErrorCode::Unavailable,
                "unused",
            ))
        }
    }

    #[cfg(target_os = "linux")]
    async fn run_sandbox(
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

    /// `pod_network` に渡す観測（#4546。試験では出力先を捨てる）。
    #[cfg(target_os = "linux")]
    fn test_pod_telemetry() -> PodDialTelemetry {
        PodDialTelemetry::new(
            Arc::new(fandhe_container_core::observability::OpRecorder::new()),
            crate::telemetry::LineSink::spawn(Box::new(std::io::sink()), 2),
        )
        .expect("telemetry")
    }

    /// CRI-6・NET-3・PLUG-1・#4486: 保持役がある構成（`pod_network`）では POD の sandbox も NODE も URL を返す。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cri6_4486_production_port_forward_pod_with_holder_returns_url() {
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            ProductionPortForward::pod_network(Arc::new(UnusedSource), test_pod_telemetry()),
            None,
            noop_recorder(),
            noop_observer(),
        )
        .await
        .expect("bind");
        assert!(server.issuer().wiring().port_forward_pod_network());
        let svc = CriRuntimeService::new()
            .with_pod_holder(Arc::new(FakeProvider))
            .with_streaming(server.issuer());
        let prefix = format!("{}/portforward/", server.issuer().base_url());
        for (name, network) in [("p", None), ("n", Some(cri::NamespaceMode::Node))] {
            let id = run_sandbox(&svc, name, network).await;
            let url = svc
                .port_forward(Request::new(cri::PortForwardRequest {
                    pod_sandbox_id: id,
                    port: vec![80],
                }))
                .await
                .unwrap_or_else(|e| panic!("{name}: {e}"))
                .into_inner()
                .url;
            assert!(url.starts_with(&prefix), "{name}: unexpected url");
        }
    }

    /// CRI-6・#4485・#4486: `pod_network` の構成でも、記録に保持役が無い POD の sandbox は `FAILED_PRECONDITION`。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cri6_4486_pod_network_without_holder_record_is_failed_precondition() {
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            ProductionPortForward::pod_network(Arc::new(UnusedSource), test_pod_telemetry()),
            None,
            noop_recorder(),
            noop_observer(),
        )
        .await
        .expect("bind");
        let svc = CriRuntimeService::new().with_streaming(server.issuer());
        let id = run_sandbox(&svc, "p", None).await;
        let e = svc
            .port_forward(Request::new(cri::PortForwardRequest {
                pod_sandbox_id: id,
                port: vec![80],
            }))
            .await
            .expect_err("no holder");
        assert_eq!(e.code(), Code::FailedPrecondition);
        assert_eq!(e.message(), "sandbox holder is unavailable");
    }

    /// CRI-6・#4486: `supports_pod_network` は構築口に従う（`node_only` は偽、`pod_network` は真）。
    #[cfg(target_os = "linux")]
    #[test]
    fn cri6_4486_supports_pod_network_follows_constructor() {
        assert!(
            !ProductionPortForward::node_only()
                .dialer
                .supports_pod_network()
        );
        assert!(
            ProductionPortForward::pod_network(Arc::new(UnusedSource), test_pod_telemetry())
                .dialer
                .supports_pod_network()
        );
    }

    /// REPAIR-5・#3761・#4164: `finish` されないまま `StreamingStop` が drop されても `on_stop` が 1 回呼ばれる。
    /// shutdown future だけが先に drop されても、`StreamingStop` が生きている間は呼ばれない。
    #[tokio::test]
    async fn repair5_3761_on_stop_runs_when_stop_is_dropped() {
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
        )
        .await
        .expect("bind");
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = Arc::clone(&count);
        let (fut, stop) = stop_streaming_on(
            server,
            TEST_LIMITS,
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
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
        )
        .await
        .expect("bind");
        let addr = server.local_addr();
        let flag = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&flag);
        let (fut, _stop) = stop_streaming_on(server, TEST_LIMITS, || {}, async move {
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
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
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
            TEST_LIMITS,
            move || {
                c.fetch_add(1, Ordering::SeqCst);
                o.store(s2.open(), Ordering::SeqCst);
            },
            std::future::ready(()),
        );
        fut.await;
        let started = Instant::now();
        let report = tokio::time::timeout(Duration::from_secs(5), stop.finish())
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
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
        )
        .await
        .expect("bind");
        let addr = server.local_addr();
        let sessions = server.sessions();
        let mut conns = open_idle_connections(addr, &sessions, 3).await;
        let (fut, stop) = stop_streaming_on(server, TEST_LIMITS, || {}, std::future::ready(()));
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
        let report = tokio::time::timeout(Duration::from_secs(5), stop.finish())
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
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
        )
        .await
        .expect("bind");
        let sessions = server.sessions();
        let _conns = open_idle_connections(server.local_addr(), &sessions, 1).await;
        let limits = StreamingStopLimits {
            drain: Duration::from_millis(100),
            close: Duration::from_millis(100),
        };
        let (fut, stop) = stop_streaming_on(server, limits, || {}, std::future::ready(()));
        fut.await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let started = Instant::now();
        let report = stop.finish().await;
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
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
        )
        .await
        .expect("bind");
        let sessions = server.sessions();
        let conns = open_idle_connections(server.local_addr(), &sessions, 1).await;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let (_fut, stop) = stop_streaming_on(
            server,
            PRODUCTION_STOP_LIMITS,
            move || {
                c.fetch_add(1, Ordering::SeqCst);
            },
            std::future::pending::<()>(),
        );
        let started = Instant::now();
        let report = stop.finish().await;
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

    /// REPAIR-5・#4164: `finish` を呼ばないまま（serve が RPC の残りで戻らない状況）でも、期限どおりに
    /// `on_stop` が呼ばれ、全セッションが強制クローズされる。時間は具体値で確認する。
    #[tokio::test]
    async fn repair5_4164_stop_runs_on_deadline_without_finish() {
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
        )
        .await
        .expect("bind");
        let sessions = server.sessions();
        let conns = open_idle_connections(server.local_addr(), &sessions, 2).await;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let (fut, stop) = stop_streaming_on(
            server,
            TEST_LIMITS,
            move || {
                c.fetch_add(1, Ordering::SeqCst);
            },
            std::future::ready(()),
        );
        fut.await;
        let t0 = Instant::now();
        // ドレインの期限（500ms）の手前では on_stop はまだ呼ばれず、セッションも開いたまま。
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(sessions.open(), 2);
        // 強制クローズの期限（700ms）の後。finish は呼んでいない。
        tokio::time::sleep(Duration::from_millis(750).saturating_sub(t0.elapsed())).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(sessions.open(), 0);
        for conn in conns {
            assert_closed_by_peer(conn).await;
        }
        let report = stop.finish().await;
        assert_eq!(
            (report.open_at_stop, report.forced, report.remaining),
            (2, 2, 0)
        );
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

    /// REPAIR-5・#4164: ドレインと閉鎖の待ちの合計は gRPC の猶予以内で、streaming は停止の上限を延ばさない（全体の上限は #4340 で op-stats の最後の書き出し 1 秒が別に足されて 14.7 秒）。
    #[test]
    fn repair5_4164_stop_waits_fit_within_grpc_grace_and_total_bound() {
        assert_eq!(STREAMING_DRAIN_WAIT, Duration::from_secs(5));
        assert_eq!(STREAMING_CLOSE_WAIT, Duration::from_secs(1));
        assert!(
            STREAMING_DRAIN_WAIT + STREAMING_CLOSE_WAIT <= crate::adapter::PLUGIN_SHUTDOWN_GRACE
        );
        assert_eq!(
            crate::shutdown::SHUTDOWN_TOTAL_BOUND,
            Duration::from_millis(14_700)
        );
    }

    #[tokio::test]
    async fn cri6_3754_bind_failure_is_fixed_vocabulary() {
        let held = std::net::TcpListener::bind((LOOPBACK, 0)).expect("hold");
        let busy = held.local_addr().expect("addr");
        let e = bind_production_streaming(
            production_streaming_config().with_bind(busy),
            fake_attach(),
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
        )
        .await
        .expect_err("busy port");
        assert_eq!(e.code(), PluginErrorCode::Unavailable);
        assert_eq!(e.message(), MSG_STREAMING_START_FAILED);
        let ext = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let e = bind_production_streaming(
            production_streaming_config().with_bind(ext),
            fake_attach(),
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
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
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
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
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            noop_observer(),
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

    /// CRI-6・SEC-1・#3761: 本番構成の `Exec` RPC が URL を返す。tty は stderr なしなら URL を返し（#4417）、相対 `argv[0]` は URL を返さず `INVALID_ARGUMENT`
    /// （固定文）。不在のコンテナは `NOT_FOUND`。
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cri6_3761_production_exec_returns_url() {
        let launcher: Arc<dyn ExecStreamLauncher> = Arc::new(NeverLauncher);
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            ProductionPortForward::node_only(),
            Some(launcher),
            noop_recorder(),
            noop_observer(),
        )
        .await
        .expect("bind");
        let issuer = server.issuer();
        let w = issuer.wiring();
        assert!(w.is_wired(StreamKind::Exec));
        assert!(w.exec_tty());
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
        // tty は URL を返す（#4417）。stderr との併用だけ Attach と同じ検査で断る。
        let url = exec("/bin/true", true, &container)
            .await
            .expect("tty exec url")
            .into_inner()
            .url;
        assert!(
            url.starts_with(&format!("{}/exec/", issuer.base_url())),
            "{url}"
        );
        let e = svc
            .exec(Request::new(cri::ExecRequest {
                container_id: container.clone(),
                cmd: vec!["/bin/true".to_string()],
                stdout: true,
                stderr: true,
                tty: true,
                ..Default::default()
            }))
            .await
            .expect_err("tty with stderr");
        assert_eq!(e.code(), Code::InvalidArgument);
        assert_eq!(e.message(), "stderr must be false when tty is set");
        let e = exec("true", false, &container).await.expect_err("relative");
        assert_eq!(e.code(), Code::InvalidArgument);
        assert_eq!(e.message(), "exec command must be an absolute path");
        let e = exec("/bin/true", false, "nope").await.expect_err("missing");
        assert_eq!(e.code(), Code::NotFound);
    }

    // ---- #4163: 接続イベントの telemetry への結線 ----

    use std::io::{Read as _, Write as _};
    use std::sync::Mutex;

    use connection_observer::TelemetryConnectionObserver;
    use connection_observer::tests::Collect;
    use fandhe_container_core::observability::{OpName, OpRecorder};

    use crate::telemetry::{LineSink, export_op_stats_to};

    fn op_total(rec: &OpRecorder, name: &str) -> u64 {
        rec.snapshot_op(&OpName::new(name).expect("name"))
            .map_or(0, |s| s.success() + s.failure())
    }

    /// 要求を 1 本送り、応答を（期限つきで）読み切る。接続の失敗・切断は空文字列。
    async fn http_get(addr: SocketAddr, path: &str) -> String {
        let req = format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        tokio::task::spawn_blocking(move || {
            let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
                .expect("connect");
            s.set_read_timeout(Some(Duration::from_secs(3)))
                .expect("timeout");
            let _ = s.write_all(req.as_bytes());
            let mut out = Vec::new();
            let _ = s.read_to_end(&mut out);
            String::from_utf8_lossy(&out).into_owned()
        })
        .await
        .expect("join")
    }

    async fn wait_until(mut ok: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !ok() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "condition not met in 5s"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// 本番の bind 経由で接続が観測され、出力にトークン・コンテナ ID・入力の内容・パスが含まれない（CRI-6・REPAIR-4・#4163）。
    #[tokio::test]
    async fn cri6_repair4_4163_no_token_or_ids_in_output() {
        let rec = Arc::new(OpRecorder::new());
        let out = Collect::default();
        let sink = LineSink::spawn(Box::new(out.clone()), 64);
        let obs = Arc::new(
            TelemetryConnectionObserver::new(Arc::clone(&rec), sink.clone()).expect("obs"),
        );
        let server = bind_production_streaming(
            production_streaming_config(),
            fake_attach(),
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            obs,
        )
        .await
        .expect("bind");
        let url = server
            .issuer()
            .issue(fandhe_container_cri::streaming::StreamRequest::Attach(
                cri::AttachRequest {
                    container_id: "c4163-secret-container".into(),
                    stdout: true,
                    ..Default::default()
                },
            ))
            .expect("issue");
        let path = url
            .strip_prefix(server.issuer().base_url())
            .expect("prefix")
            .to_string();
        let token = path.rsplit('/').next().expect("token").to_string();
        assert!(token.len() >= 32, "token={token}");
        let _ = http_get(server.local_addr(), &path).await;
        let _ = http_get(
            server.local_addr(),
            &format!("/attach/{token}x?payload-4163"),
        )
        .await;
        wait_until(|| op_total(&rec, "cri.streaming.connection") >= 2).await;
        export_op_stats_to(&rec, &sink);
        sink.wait_idle(Duration::from_secs(2));
        let all = format!(
            "{}
{:?}",
            out.lines().join(
                "
"
            ),
            rec.snapshot()
        );
        for secret in [
            token.as_str(),
            "c4163-secret-container",
            "payload-4163",
            path.as_str(),
        ] {
            assert!(!all.contains(secret), "leaked {secret}");
        }
        assert!(all.contains("cri.streaming.connection"), "{all}");
    }

    /// 本番の bind で上限超過の拒否が件数と固定語彙の行で観測される（CRI-6・REPAIR-4・#4163）。
    #[tokio::test]
    async fn cri6_repair4_4163_production_bind_observes_rejection() {
        let rec = Arc::new(OpRecorder::new());
        let out = Collect::default();
        let sink = LineSink::spawn(Box::new(out.clone()), 64);
        let obs = Arc::new(TelemetryConnectionObserver::new(Arc::clone(&rec), sink).expect("obs"));
        let server = bind_production_streaming(
            production_streaming_config()
                .with_max_connections(1)
                .with_header_read_timeout(Duration::from_secs(2)),
            fake_attach(),
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            obs,
        )
        .await
        .expect("bind");
        let addr = server.local_addr();
        let _held = connect(addr).await.expect("hold the only slot");
        wait_until(|| true).await;
        let _second = connect(addr)
            .await
            .expect("tcp connect succeeds then is closed");
        wait_until(|| op_total(&rec, "cri.streaming.connection_rejected") == 1).await;
        wait_until(|| out.lines().len() == 1).await;
        assert_eq!(
            out.lines(),
            vec![
                "{\"event\":\"cri_streaming_connection\",\"op\":\"cri.streaming.connection_rejected\",\"outcome\":\"error\",\"reason\":\"max_connections\",\"count\":1}"
                    .to_string()
            ]
        );
    }

    /// 出力先が止まっていても accept・応答は待たされない（REPAIR-5・#4163）。
    #[tokio::test]
    async fn repair5_4163_stalled_sink_does_not_delay_accept() {
        struct Stall(Mutex<std::sync::mpsc::Receiver<()>>);
        impl std::io::Write for Stall {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                let _ = self.0.lock().expect("lock").recv();
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (gate, rx) = std::sync::mpsc::channel::<()>();
        let sink = LineSink::spawn(Box::new(Stall(Mutex::new(rx))), 1);
        let rec = Arc::new(OpRecorder::new());
        let obs = Arc::new(TelemetryConnectionObserver::new(Arc::clone(&rec), sink).expect("obs"));
        let server = bind_production_streaming(
            production_streaming_config()
                .with_max_connections(1)
                .with_header_read_timeout(Duration::from_secs(2)),
            fake_attach(),
            ProductionPortForward::node_only(),
            None,
            noop_recorder(),
            obs,
        )
        .await
        .expect("bind");
        let addr = server.local_addr();
        let held = connect(addr).await.expect("hold");
        // 拒否を 8 回起こす（行は 1, 2, 4, 8 の 4 本で、止まった書き込み口に積まれる）。
        for _ in 0..8 {
            let _ = connect(addr).await.expect("connect");
        }
        wait_until(|| op_total(&rec, "cri.streaming.connection_rejected") == 8).await;
        drop(held);
        // 枠が空いた後の要求が、止まった sink に関係なく期限内に応答される。
        let resp = tokio::time::timeout(Duration::from_secs(5), http_get(addr, "/exec/none"))
            .await
            .expect("response within deadline");
        assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
        drop(gate);
    }
}
