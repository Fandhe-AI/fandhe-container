//! Exec のストリーミング本体（SPDY/3.1 上の Kubernetes remotecommand v4・v3・v2。
//! CRI-6・TASK-63.2・#680・REPAIR-2・REPAIR-5・REPAIR-4。設計記録は `docs/design/cri-streaming-server.md`）。
//!
//! [`ExecStreamHandler`] は [`super::StreamHandler`] の実装で、[`super::StreamDispatcher::with_exec`] で登録する
//! （単独で `StreamingServer::bind_with_handler` に渡してもよい）。トークンの照合に成功した `Exec` の要求を受け、
//! HTTP/1.1 Upgrade（`SPDY/3.1`）で 101 を返したあと、error・stdin・stdout・stderr（tty なら resize）の各ストリームを
//! 受け付け、注入された [`ExecStreamLauncher`] が返す stdio とクライアントの間で双方向に中継する。
//! SPDY のフレーム codec（[`super::spdy`]）・握手と版の選択・`streamtype` の割り当て・Status・resize の解析・
//! 期限（[`super::remotecommand`]）は Attach（#681）と共通で、本モジュールは Exec 固有の起動・終了コードの
//! 通知・stdin の滞留の扱いだけを持つ。
//!
//! ## 未実装（REPAIR-3）
//!
//! [`ExecStreamLauncher`] の本番の実装は plugin-cri の `streaming::exec_launcher`（supervisor の `stream-exec` helper 経由。
//! #3761・PLUG-1）にあり、本 crate には置かない。本番では tty を宣言せず（[`ExecStreamHandler::without_tty`]。
//! supervisor 側の pty 結線が後続のため）、相対 `argv[0]` も断る（[`ExecStreamHandler::absolute_command_only`]）。
//! WebSocket（`v5.channel.k8s.io`）も未対応。
//!
//! ## プロトコルの要点（kubernetes v1.34 の kubelet / apimachinery と moby/spdystream で確認）
//!
//! - 交渉: [`super::remotecommand::negotiate`]（v4・v3・v2。クライアントの提示順で最初に対応する版）
//! - ストリーム: ヘッダ `streamtype` で種別を決める。保存済みの `ExecRequest` が求める組
//!   （[`StreamOptions::expected`]）だけを受け付け、想定外・重複は RST_STREAM で拒否する
//!   クライアントが RST_STREAM で閉じた stdin・stdout・stderr・error・resize は、以後その ID へ DATA・FIN を送らず、
//!   stdout・stderr の読み手は解放する（SPDY/3 §2.3.7。CRI-6・TASK-63.2）
//! - 計装: セッションの結果・所要時間と backend・通信路の読み書きの成否を [`CriOpRecorder`] へ渡す
//!   （[`ExecStreamHandler::with_recorder`]。REPAIR-4）
//! - 終了の通知: error ストリームへ書く。v4 は `metav1.Status` の JSON（成功は `Success`、非 0 は
//!   `NonZeroExitCode` と `ExitCode` の cause）。v3・v2 は成功時に何も書かず、非 0 は終了コードの文
//! - フロー制御: moby/spdystream は WINDOW_UPDATE を送らず、受けても無視する。したがってこちらも送信窓に従わず、
//!   受信した WINDOW_UPDATE・SETTINGS・HEADERS は読み捨てる（従うと Go のクライアントと 64 KiB で詰まる）。
//!   代わりに送信キューの上限（[`MAX_SEND_QUEUE_BYTES`]）と stdin の書き込み待ちで背圧を TCP に任せる

use std::collections::VecDeque;
use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;
use tonic::Code;

use super::remotecommand::{
    HEADER_STREAM_TYPE, MAX_SESSION_STEP_TIMEOUT, Protocol, ResizeParser, SessionLimits,
    StreamOptions, StreamType, TerminalSize, negotiate, status_success, upgrade_response,
};
use super::spdy::{
    Frame, FrameDecoder, FrameEncoder, Headers, MAX_INCOMING_PAYLOAD, MAX_OUTGOING_DATA, SpdyError,
    StreamId, goaway_status, rst_status,
};
use super::{
    ConnectionPermit, StreamBody, StreamHandler, StreamKind, StreamRequest, StreamWiring,
    plain_response,
};
use crate::error::CriError;
use crate::instrument::{CriOpKind, CriOpRecorder, CriOpSample, NoopCriOpRecorder};
use crate::runtime::v1;

/// 送信キュー（未送信バイト）の上限。超えそうなときは stdout / stderr を読まない（背圧）。
pub const MAX_SEND_QUEUE_BYTES: usize = 1024 * 1024;
/// `pump_output` が 1 回の呼び出しで読む回数の上限（stdout / stderr の公平化。1 周回 128 KiB まで）。
const MAX_OUTPUT_READS_PER_ROUND: usize = 4;
/// 受信バッファの 1 回の読み取りサイズ。
const READ_CHUNK_BYTES: usize = 16 * 1024;
/// 受信バッファの上限（最大の DATA フレーム + ヘッダ + 1 回の読み取り分）。
const MAX_RECV_BUF_BYTES: usize = MAX_INCOMING_PAYLOAD + 8 + READ_CHUNK_BYTES;
/// 1 回の `poll_run` で進展が続いても回す周回数の上限。超えたら wake して譲る。
const MAX_POLL_ROUNDS: usize = 32;
/// ストリームが揃う前に届いた stdin の DATA を保持する上限（バイト）。超えたら ProtocolError。
const MAX_EARLY_STDIN_BYTES: usize = 256 * 1024;
/// ストリームが揃う前に保持する resize の DATA の上限（バイト）。
const MAX_EARLY_RESIZE_BYTES: usize = 16 * 1024;
/// 保持した resize を [`ResizeParser`] へ渡す 1 回の大きさ（パーサーの滞留上限 4 KiB を超えないようにする）。
const EARLY_RESIZE_REPLAY_CHUNK: usize = 1024;

type BoxedRead = Box<dyn AsyncRead + Send + Unpin>;
type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin>;
type ExitFuture = Pin<Box<dyn Future<Output = Result<i32, CriError>> + Send>>;

/// Exec セッションの設定。既定値は安全側（kubelet の既定に合わせた期限）。
///
/// ストリーム作成・idle・流し切り・最後の送出の期限は Attach と共通の [`SessionLimits`]
/// （`StreamingConfig::session_limits()` の値を渡す）で、Exec 固有のものだけを足す。
/// `limits.backend_timeout` は Attach 用で、Exec は [`Self::launch_timeout`] を使う。
#[derive(Debug, Clone)]
pub struct ExecStreamConfig {
    /// Attach と共通の期限。
    pub limits: SessionLimits,
    /// [`ExecStreamLauncher::launch`] の期限。既定 30 秒。
    pub launch_timeout: Duration,
    /// 溜めた stdin をプロセスが読まないまま進展しない場合に閉じるまでの期限。既定 60 秒。
    /// 書き込み待ちの間はソケットを読まない（背圧）ため、クライアントの切断を検知できない時間の上限になる。
    pub stdin_stall_timeout: Duration,
}

impl Default for ExecStreamConfig {
    fn default() -> Self {
        Self {
            limits: SessionLimits::default(),
            launch_timeout: Duration::from_secs(30),
            stdin_stall_timeout: Duration::from_secs(60),
        }
    }
}

impl ExecStreamConfig {
    /// 0 の期限と上限超えを拒否する（fail-closed）。
    pub fn validate(&self) -> Result<(), CriError> {
        self.limits.validate()?;
        for (name, d) in [
            ("launch_timeout", self.launch_timeout),
            ("stdin_stall_timeout", self.stdin_stall_timeout),
        ] {
            if d.is_zero() || d > MAX_SESSION_STEP_TIMEOUT {
                return Err(CriError::invalid_argument(format!(
                    "{name} must be between 1ns and 600s"
                )));
            }
        }
        Ok(())
    }
}

/// [`ExecStreamLauncher::launch`] に渡す値。発行時に保存した `ExecRequest` から作る（通信路の内容は使わない。CRI-6）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecLaunch {
    /// 対象コンテナの ID。
    pub container_id: String,
    /// 実行するコマンド（argv）。
    pub cmd: Vec<String>,
    /// pty を割り当てるか。true のとき stdout に stderr も混ざり、`ExecSession::stderr` は `None`。
    pub tty: bool,
    /// stdin を接続するか。
    pub stdin: bool,
    /// stdout を接続するか。
    pub stdout: bool,
    /// stderr を接続するか（tty のときは false）。
    pub stderr: bool,
}

/// pty のサイズ変更の受け口。
pub trait TerminalResizer: Send {
    /// サイズを変更する。失敗は無視される（セッションは続く）。
    fn resize(&mut self, size: TerminalSize) -> Result<(), CriError>;
}

/// 起動済みの exec プロセスの入出力と終了待ち。
///
/// 要求された stdio だけを `Some` にする（食い違いは handler が内部エラーとして閉じる）。
/// 値を drop したらプロセスを止めること（接続が切れたときの後始末は実装の責務）。
pub struct ExecSession {
    /// プロセスの stdin への書き込み口。
    pub stdin: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    /// プロセスの stdout の読み取り口。
    pub stdout: Option<Box<dyn AsyncRead + Send + Unpin>>,
    /// プロセスの stderr の読み取り口（tty では `None`）。
    pub stderr: Option<Box<dyn AsyncRead + Send + Unpin>>,
    /// 終了コードを返す future。drop されたらプロセスを止めること。
    pub exit: Pin<Box<dyn Future<Output = Result<i32, CriError>> + Send>>,
    /// tty のときの端末サイズ変更口。
    pub resize: Option<Box<dyn TerminalResizer>>,
}

impl fmt::Debug for ExecSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecSession")
            .field("stdin", &self.stdin.is_some())
            .field("stdout", &self.stdout.is_some())
            .field("stderr", &self.stderr.is_some())
            .field("resize", &self.resize.is_some())
            .finish()
    }
}

/// stdio を持つ exec の起動役（注入トレイト。CRI-6・PLUG-1）。
///
/// 本番の実装は plugin-cri の `exec_launcher`（#3761。モジュール doc の「未実装」を参照）。実装が満たす契約:
///
/// - 起動したプロセスはコンテナの namespace・cgroup・seccomp・capability を継承し、広げない（SEC-1）
/// - `req` の `stdin` / `stdout` / `stderr` が true のものだけを `Some` で返す
/// - 返した [`ExecSession`] の drop でプロセスを止める
/// - panic しない。失敗は `CriError` で返す（メッセージに内部のパス・資格情報を含めない）
pub trait ExecStreamLauncher: Send + Sync + 'static {
    /// プロセスを起動して stdio を返す。呼び出し側が `launch_timeout` を付ける。
    fn launch(
        &self,
        req: ExecLaunch,
    ) -> Pin<Box<dyn Future<Output = Result<ExecSession, CriError>> + Send + '_>>;
}

/// セッションの結末（観測用。トークン・cmd・パスは含めない。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStreamOutcome {
    /// プロセスが終了し、状態を通知した。
    Exited {
        /// 終了コード。
        code: i32,
    },
    /// 終了待ちが失敗した（内部エラーの Status を通知した）。
    ExecFailed,
    /// stdout / stderr の読み取りが失敗した（内部エラーの Status を通知した）。
    OutputFailed,
    /// プロセス終了後の drain の期限までに出力を送り切れなかった（内部エラーの Status を通知した）。
    OutputTruncated,
    /// 起動に失敗した、または期限切れ・stdio の食い違い（内部エラーの Status を通知した）。
    LaunchFailed,
    /// 必要なストリームが期限内に揃わなかった（起動していない）。
    StreamCreationTimeout,
    /// 入出力が途絶えて閉じた。
    IdleTimeout,
    /// SPDY の規則違反で閉じた。
    ProtocolError,
    /// クライアントが先に切断した。
    PeerClosed,
    /// プロセスは終了したが、出力・Status を通信路へ送り切れなかった（書き込み失敗。REPAIR-4）。
    /// `code` は取得できた終了コード（取得できなければ `None`）。
    DeliveryFailed {
        /// 終了コード。
        code: Option<i32>,
    },
    /// プロセスは終了したが、出力・Status の送出が `close_timeout` までに終わらなかった
    /// （クライアントが受信を止めた場合。REPAIR-5）。
    DeliveryTimedOut {
        /// 終了コード。
        code: Option<i32>,
    },
}

/// [`ExecStreamOutcome`] の受け口。同期・短時間で返すこと。
pub trait ExecObserver: Send + Sync + 'static {
    /// セッションが終わった。`elapsed` は 101 応答後から終わるまで。
    fn observe(&self, outcome: ExecStreamOutcome, elapsed: Duration);
}

/// 何も記録しない既定の観測口。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopExecObserver;

impl ExecObserver for NoopExecObserver {
    fn observe(&self, _outcome: ExecStreamOutcome, _elapsed: Duration) {}
}

/// `Exec` を処理する [`StreamHandler`]。
pub struct ExecStreamHandler {
    /// tty を受けると宣言するか（既定 true。外すと RPC 時に tty を断る。#3761）。
    accepts_tty: bool,
    /// 相対 `argv[0]` を受けると宣言するか（既定 true。外すと RPC 時に断る。#3761）。
    accepts_relative_command: bool,
    launcher: Arc<dyn ExecStreamLauncher>,
    config: ExecStreamConfig,
    observer: Arc<dyn ExecObserver>,
    recorder: Arc<dyn CriOpRecorder>,
}

impl fmt::Debug for ExecStreamHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecStreamHandler")
            .field("config", &self.config)
            .finish()
    }
}

impl ExecStreamHandler {
    /// 設定を検証して作る。
    pub fn new(
        launcher: Arc<dyn ExecStreamLauncher>,
        config: ExecStreamConfig,
    ) -> Result<Self, CriError> {
        config.validate()?;
        Ok(Self {
            accepts_tty: true,
            accepts_relative_command: true,
            launcher,
            config,
            observer: Arc::new(NoopExecObserver),
            recorder: Arc::new(NoopCriOpRecorder),
        })
    }

    /// tty を受けないと宣言する（`wiring()` が `exec_tty` を立てず、RPC 時に `INVALID_ARGUMENT`。#3761・REPAIR-3）。
    pub fn without_tty(mut self) -> Self {
        self.accepts_tty = false;
        self
    }

    /// 絶対パスの `argv[0]` だけを受けると宣言する（相対は RPC 時に `INVALID_ARGUMENT`。#3761・#2439）。
    pub fn absolute_command_only(mut self) -> Self {
        self.accepts_relative_command = false;
        self
    }

    /// 観測口を差し替える（REPAIR-4）。
    pub fn with_observer(mut self, observer: Arc<dyn ExecObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// 操作別の計装先を差し替える（セッションの結果と、backend・通信路の読み書きの成否。CRI-6・TASK-63.2・REPAIR-4）。
    pub fn with_recorder(mut self, recorder: Arc<dyn CriOpRecorder>) -> Self {
        self.recorder = recorder;
        self
    }

    fn handle_exec(
        &self,
        req: v1::ExecRequest,
        http: Request<Incoming>,
        permit: ConnectionPermit,
    ) -> Response<StreamBody> {
        let protocol = match negotiate(http.headers()) {
            Ok(protocol) => protocol,
            Err(e) => return e.into_response(),
        };
        let options = StreamOptions::new(req.stdin, req.stdout, req.stderr, req.tty);
        let on_upgrade = hyper::upgrade::on(http);
        let launcher = Arc::clone(&self.launcher);
        let observer = Arc::clone(&self.observer);
        let recorder = Arc::clone(&self.recorder);
        let config = self.config.clone();
        permit.spawn_session(async move {
            let started = Instant::now();
            let (outcome, stats) = match on_upgrade.await {
                Ok(upgraded) => {
                    run_exec_session(
                        TokioIo::new(upgraded),
                        protocol,
                        options,
                        &req,
                        launcher.as_ref(),
                        &config,
                    )
                    .await
                }
                Err(_) => (ExecStreamOutcome::PeerClosed, IoStats::default()),
            };
            let elapsed = started.elapsed();
            record_session(recorder.as_ref(), outcome, &stats, elapsed);
            observer.observe(outcome, elapsed);
            // 枠は spawn_session がタスクの寿命まで保持する（#679 の契約。#4164）。
        });
        upgrade_response(protocol)
    }
}

impl StreamHandler for ExecStreamHandler {
    fn wiring(&self) -> StreamWiring {
        let mut wiring = StreamWiring::only(StreamKind::Exec);
        if self.accepts_tty {
            wiring = wiring.with_exec_tty();
        }
        if self.accepts_relative_command {
            wiring = wiring.with_exec_relative_command();
        }
        wiring
    }

    fn handle(
        &self,
        request: StreamRequest,
        http: Request<Incoming>,
        permit: ConnectionPermit,
    ) -> Pin<Box<dyn Future<Output = Response<StreamBody>> + Send + '_>> {
        Box::pin(async move {
            match request {
                StreamRequest::Exec(req) => self.handle_exec(req, http, permit),
                // 振り分けの誤り。到達しないが、別種別の要求を処理せず固定の応答にする。
                _ => plain_response(hyper::StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
            }
        })
    }
}

/// セッション内の読み書きの成否（成功と失敗は別に立てる。REPAIR-4）。内容・ID は持たない。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IoStats {
    /// backend の stdout / stderr を 1 回以上読めた。
    pub(crate) stream_read_ok: bool,
    /// backend の stdout / stderr の読み取りが失敗した。
    pub(crate) stream_read_failed: bool,
    /// backend の stdin へ 1 回以上書けた。
    pub(crate) stream_write_ok: bool,
    /// backend の stdin への書き込みが失敗した（入力を捨てて継続する場合を含む）。
    pub(crate) stream_write_failed: bool,
    /// 通信路から 1 回以上読めた。
    pub(crate) conn_read_ok: bool,
    /// 通信路の読み取りが失敗した。
    pub(crate) conn_read_failed: bool,
    /// 通信路へ 1 回以上書けた。
    pub(crate) conn_write_ok: bool,
    /// 通信路への書き込みが失敗した。
    pub(crate) conn_write_failed: bool,
}

/// 終わり方を gRPC のコードへ写す（操作別計装の結果区分。終了コードが非 0 でも運用上の失敗ではない）。
fn outcome_code(outcome: ExecStreamOutcome) -> Code {
    match outcome {
        ExecStreamOutcome::Exited { .. } => Code::Ok,
        ExecStreamOutcome::ExecFailed | ExecStreamOutcome::OutputFailed => Code::Internal,
        ExecStreamOutcome::OutputTruncated
        | ExecStreamOutcome::LaunchFailed
        | ExecStreamOutcome::DeliveryFailed { .. } => Code::Unavailable,
        ExecStreamOutcome::StreamCreationTimeout
        | ExecStreamOutcome::IdleTimeout
        | ExecStreamOutcome::DeliveryTimedOut { .. } => Code::DeadlineExceeded,
        ExecStreamOutcome::ProtocolError => Code::InvalidArgument,
        ExecStreamOutcome::PeerClosed => Code::Cancelled,
    }
}

/// セッションの結果・所要時間と、読み書きの成否を記録先へ渡す（CRI-6・TASK-63.2・REPAIR-4）。
///
/// ID・コマンド・内容は渡さない。失敗があれば成功より優先して失敗を 1 件記録する。
fn record_session(
    recorder: &dyn CriOpRecorder,
    outcome: ExecStreamOutcome,
    stats: &IoStats,
    latency: Duration,
) {
    recorder.record_cri_op(&CriOpSample::new(
        CriOpKind::ExecSession,
        outcome_code(outcome),
        latency,
    ));
    for (kind, ok, failed) in [
        (
            CriOpKind::ExecStreamRead,
            stats.stream_read_ok,
            stats.stream_read_failed,
        ),
        (
            CriOpKind::ExecStreamWrite,
            stats.stream_write_ok,
            stats.stream_write_failed,
        ),
        (
            CriOpKind::ExecConnRead,
            stats.conn_read_ok,
            stats.conn_read_failed,
        ),
        (
            CriOpKind::ExecConnWrite,
            stats.conn_write_ok,
            stats.conn_write_failed,
        ),
    ] {
        if failed {
            recorder.record_cri_op(&CriOpSample::new(kind, Code::Unavailable, latency));
        } else if ok {
            recorder.record_cri_op(&CriOpSample::new(kind, Code::Ok, latency));
        }
    }
}

/// 内部エラーの Status（v4 は JSON）。詳細（パス・内部のエラー文）は載せない。
const STATUS_INTERNAL_ERROR_V4: &str = r#"{"metadata":{},"status":"Failure","message":"Internal error occurred: error executing command in container","reason":"InternalError","details":{"causes":[{"message":"error executing command in container"}]},"code":500}"#;
/// 内部エラーの Status（v3・v2 は error ストリームにメッセージのテキストを書く）。
const STATUS_INTERNAL_ERROR_TEXT: &str = "error executing command in container";

/// 内部エラーの Status。
fn status_internal_error(protocol: Protocol) -> Vec<u8> {
    match protocol {
        Protocol::V4 => STATUS_INTERNAL_ERROR_V4.as_bytes().to_vec(),
        Protocol::V3 | Protocol::V2 => STATUS_INTERNAL_ERROR_TEXT.as_bytes().to_vec(),
    }
}

/// 期限切れ（idle・stdin の停滞）で打ち切る実行の Status（v4 は `reason: Timeout` の Failure。非 0 終了ではない一般エラー）。
const STATUS_TIMEOUT_V4: &str = r#"{"metadata":{},"status":"Failure","message":"command execution timed out","reason":"Timeout","code":504}"#;
/// 期限切れの Status（v3・v2 はメッセージのテキスト）。
const STATUS_TIMEOUT_TEXT: &str = "command execution timed out";

/// 期限切れで打ち切る実行の Status。error ストリームが空のまま閉じると client-go は成功とみなすため、必ず書く（CRI-6）。
fn status_timeout(protocol: Protocol) -> Vec<u8> {
    match protocol {
        Protocol::V4 => STATUS_TIMEOUT_V4.as_bytes().to_vec(),
        Protocol::V3 | Protocol::V2 => STATUS_TIMEOUT_TEXT.as_bytes().to_vec(),
    }
}

/// プロセスの終了コードを error ストリームへ書く内容にする。`None` は何も書かない（v3・v2 の成功）。
///
/// 非 0 の v4 は kubelet の `NonZeroExitCode`・`ExitCode` の cause（client-go が終了コードを読む）、
/// v3・v2 は kubelet の `ExitError` と同じ `command terminated with exit code N` のテキスト。
fn status_exit(protocol: Protocol, code: i32) -> Option<Vec<u8>> {
    if code == 0 {
        return status_success(protocol);
    }
    Some(match protocol {
        Protocol::V4 => format!(
            r#"{{"metadata":{{}},"status":"Failure","message":"command terminated with non-zero exit code: command terminated with exit code {code}","reason":"NonZeroExitCode","details":{{"causes":[{{"reason":"ExitCode","message":"{code}"}}]}}}}"#
        )
        .into_bytes(),
        Protocol::V3 | Protocol::V2 => format!("command terminated with exit code {code}").into_bytes(),
    })
}

/// 読み取りの停止理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadStop {
    /// 受信バッファが上限に達した（EOF と区別して ProtocolError にする）。
    Overflow,
    /// 下位 IO の読み取りエラー（切断として扱う）。
    Io,
}

/// 送信キュー上の 1 フレームの境界。リセットしたストリームの未送信フレームを取り除くために持つ。
#[derive(Debug, Clone, Copy)]
struct FrameMark {
    /// DATA フレームのストリーム ID（それ以外は `None`。除去の対象にならない）。
    stream_id: Option<StreamId>,
    /// このフレームの未送信の残りバイト数。
    len: usize,
}

/// [`Conn::goodbye`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Goodbye {
    /// 溜めた出力・Status を送り切った（GOAWAY とシャットダウンは最善努力）。
    Delivered,
    /// 溜めた出力・Status の書き込みが失敗した。
    Failed,
    /// 溜めた出力・Status を `timeout` までに送り切れなかった。
    TimedOut,
}

/// 接続の入出力（SPDY のフレームの組み立て・送信キュー・受信バッファ）。
struct Conn<T> {
    io: T,
    wbuf: Vec<u8>,
    wpos: usize,
    /// 未送信のバイトのフレーム境界（`len` は未送信の残りバイト数）。`wbuf[wpos..]` の並びと一致する。
    marks: VecDeque<FrameMark>,
    /// 先頭フレームを途中まで送った（途中で切れないよう送り切る必要がある）。
    front_partial: bool,
    dec: FrameDecoder,
    enc: FrameEncoder,
    /// 通信路の読み書きの成否（REPAIR-4）。
    stats: IoStats,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Conn<T> {
    fn new(io: T) -> Self {
        Self {
            io,
            wbuf: Vec::new(),
            wpos: 0,
            marks: VecDeque::new(),
            front_partial: false,
            dec: FrameDecoder::new(),
            enc: FrameEncoder::new(),
            stats: IoStats::default(),
        }
    }

    fn pending_write(&self) -> usize {
        self.wbuf.len().saturating_sub(self.wpos)
    }

    fn queue(&mut self, frame: &Frame) -> Result<(), SpdyError> {
        // 送信済み領域を追記前に取り除く。取り除かないと、書き込みが Pending のまま
        // 少量ずつ部分送信が進む場合に wbuf が累積送信量で増え、送信キューの上限
        // （MAX_SEND_QUEUE_BYTES）が未送信量しか数えないため無制限に伸びる。
        self.compact();
        let before = self.wbuf.len();
        if let Err(e) = self.enc.encode(frame, &mut self.wbuf) {
            self.wbuf.truncate(before);
            return Err(e);
        }
        let stream_id = match frame {
            Frame::Data { stream_id, .. } => Some(*stream_id),
            _ => None,
        };
        let len = self.wbuf.len().saturating_sub(before);
        self.marks.push_back(FrameMark { stream_id, len });
        Ok(())
    }

    /// 送信済み領域を取り除く（追記・除去の前に呼ぶ。以後 `wbuf` は未送信分だけを持つ）。
    fn compact(&mut self) {
        if self.wpos >= self.wbuf.len() {
            self.wbuf.clear();
            self.marks.clear();
            self.front_partial = false;
        } else {
            self.wbuf.drain(..self.wpos);
        }
        self.wpos = 0;
    }

    /// `n` バイト送れた分だけ先頭から境界を進める。
    fn advance_marks(&mut self, mut n: usize) {
        while n > 0 {
            let Some(front) = self.marks.front_mut() else {
                break;
            };
            let take = n.min(front.len);
            front.len -= take;
            n -= take;
            if front.len == 0 {
                self.marks.pop_front();
                self.front_partial = false;
            } else {
                self.front_partial = true;
            }
        }
    }

    /// リセットされたストリームの未送信フレームを取り除く（SPDY/3 §2.3.7。CRI-6・TASK-63.2）。
    ///
    /// すでに一部を送ったフレームは途中で切れないよう、そのフレームだけ送り切るために残す。
    fn purge_stream(&mut self, id: StreamId) {
        if !self.marks.iter().any(|m| m.stream_id == Some(id)) {
            return;
        }
        self.compact();
        let mut kept = Vec::with_capacity(self.wbuf.len());
        let mut kept_marks = VecDeque::with_capacity(self.marks.len());
        let mut offset = 0usize;
        for (index, mark) in self.marks.iter().enumerate() {
            let end = offset.saturating_add(mark.len).min(self.wbuf.len());
            let partially_sent = index == 0 && self.front_partial;
            if (partially_sent || mark.stream_id != Some(id))
                && let Some(bytes) = self.wbuf.get(offset..end)
            {
                kept.extend_from_slice(bytes);
                kept_marks.push_back(*mark);
            }
            offset = end;
        }
        self.wbuf = kept;
        self.marks = kept_marks;
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let chunk = self.wbuf.get(self.wpos..).unwrap_or(&[]);
            match Pin::new(&mut self.io).poll_write(cx, chunk) {
                Poll::Ready(Ok(0)) => {
                    self.stats.conn_write_failed = true;
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => {
                    self.stats.conn_write_ok = true;
                    self.wpos = self.wpos.saturating_add(n);
                    self.advance_marks(n);
                }
                Poll::Ready(Err(e)) => {
                    self.stats.conn_write_failed = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        self.wbuf.clear();
        self.wpos = 0;
        self.marks.clear();
        self.front_partial = false;
        Pin::new(&mut self.io).poll_flush(cx)
    }

    /// 受信バッファから 1 フレームを取り出す。
    fn try_next_frame(&mut self) -> Result<Option<Frame>, SpdyError> {
        self.dec.next_frame()
    }

    /// ソケットから読み足す。`Ready(Ok(0))` は EOF。
    fn poll_read_more(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, ReadStop>> {
        if self.dec.buffered_len() >= MAX_RECV_BUF_BYTES {
            return Poll::Ready(Err(ReadStop::Overflow));
        }
        let mut tmp = [0u8; READ_CHUNK_BYTES];
        let mut buf = ReadBuf::new(&mut tmp);
        match Pin::new(&mut self.io).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled();
                if !filled.is_empty() {
                    self.stats.conn_read_ok = true;
                }
                self.dec.extend(filled);
                Poll::Ready(Ok(filled.len()))
            }
            Poll::Ready(Err(_)) => {
                self.stats.conn_read_failed = true;
                Poll::Ready(Err(ReadStop::Io))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// 次のフレームを待つ。`Ok(None)` は EOF または読み取りエラー（切断）。
    async fn next_frame(&mut self) -> Result<Option<Frame>, SpdyError> {
        poll_fn(|cx| {
            loop {
                match self.try_next_frame() {
                    Ok(Some(frame)) => return Poll::Ready(Ok(Some(frame))),
                    Ok(None) => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
                match self.poll_read_more(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) | Poll::Ready(Err(ReadStop::Io)) => {
                        return Poll::Ready(Ok(None));
                    }
                    Poll::Ready(Err(ReadStop::Overflow)) => {
                        return Poll::Ready(Err(SpdyError::FrameTooLarge));
                    }
                    Poll::Ready(Ok(_)) => {}
                }
            }
        })
        .await
    }

    async fn flush(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_flush(cx)).await
    }

    /// 溜めた送信キューを書き出してから GOAWAY を送り、シャットダウンする。
    ///
    /// 全体を `timeout` で区切る。溜めた出力・Status の書き込み失敗と期限切れは結果で返し、
    /// 通信路の計装（`conn_write_failed`）にも残す。GOAWAY 以降の失敗は後始末の最善努力として無視する。
    async fn goodbye(&mut self, last_good: u32, status: u32, timeout: Duration) -> Goodbye {
        let deadline = tokio::time::Instant::now() + timeout;
        let result = match tokio::time::timeout_at(deadline, self.flush()).await {
            Err(_) => Goodbye::TimedOut,
            Ok(Err(_)) => Goodbye::Failed,
            Ok(Ok(())) => {
                // 溜めた分は送れた。以降は最善努力（同じ期限で打ち切り、失敗は無視する）。
                let _ = self.queue(&Frame::GoAway {
                    last_good_stream_id: last_good,
                    status,
                });
                let _ = tokio::time::timeout_at(deadline, async {
                    let _ = self.flush().await;
                    let _ = poll_fn(|cx| Pin::new(&mut self.io).poll_shutdown(cx)).await;
                })
                .await;
                Goodbye::Delivered
            }
        };
        if result != Goodbye::Delivered {
            self.stats.conn_write_failed = true;
        }
        result
    }
}

/// ストリームが揃う前に届いた stdin の入力（上限つき）と FIN 状態。Relay へ引き継ぐ。
#[derive(Debug, Default)]
struct EarlyStdin {
    buf: Vec<u8>,
    fin: bool,
    /// ストリームが揃う前に届いた resize の DATA（上限つき。Relay 起動後に端末サイズとして適用する。CRI-6）。
    resize: Vec<u8>,
    /// ストリームが揃う前に RST_STREAM で閉じられた ID（Relay へ引き継ぎ、以後は送らない。CRI-6）。
    reset: Vec<StreamId>,
}

/// 受け付けたストリームの ID。
#[derive(Debug, Default, Clone, Copy)]
struct Streams {
    error: Option<StreamId>,
    stdin: Option<StreamId>,
    stdout: Option<StreamId>,
    stderr: Option<StreamId>,
    resize: Option<StreamId>,
    /// 受け付けた最大のクライアント側ストリーム ID（GOAWAY の last-good-stream-id）。
    last_id: u32,
}

impl Streams {
    fn slot(&mut self, kind: StreamType) -> &mut Option<StreamId> {
        match kind {
            StreamType::Error => &mut self.error,
            StreamType::Stdin => &mut self.stdin,
            StreamType::Stdout => &mut self.stdout,
            StreamType::Stderr => &mut self.stderr,
            StreamType::Resize => &mut self.resize,
        }
    }

    fn get(&self, kind: StreamType) -> Option<StreamId> {
        match kind {
            StreamType::Error => self.error,
            StreamType::Stdin => self.stdin,
            StreamType::Stdout => self.stdout,
            StreamType::Stderr => self.stderr,
            StreamType::Resize => self.resize,
        }
    }

    /// 受け付け済みのストリームの ID か。
    fn is_known(&self, id: StreamId) -> bool {
        [
            self.error,
            self.stdin,
            self.stdout,
            self.stderr,
            self.resize,
        ]
        .contains(&Some(id))
    }

    fn complete(&self, expected: &[StreamType]) -> bool {
        expected.iter().all(|k| self.get(*k).is_some())
    }
}

enum StreamWait {
    Ready,
    Closed,
    Protocol,
}

/// ストリームが揃うまで SYN_STREAM を受け付ける（期限は呼び出し側が付ける）。
/// 揃う前に届いた stdin の DATA と FIN は上限つきで `early` に保持する（resize の DATA も上限つきで保持し、それ以外の DATA は読み捨てる）。
async fn await_streams<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<T>,
    expected: &[StreamType],
    streams: &mut Streams,
    early: &mut EarlyStdin,
) -> StreamWait {
    while !streams.complete(expected) {
        let frame = match conn.next_frame().await {
            Ok(Some(f)) => f,
            Ok(None) => return StreamWait::Closed,
            Err(_) => return StreamWait::Protocol,
        };
        let queued = match frame {
            Frame::SynStream {
                stream_id,
                headers,
                fin,
                ..
            } => {
                let before = streams.stdin;
                let r = accept_stream(conn, expected, streams, stream_id, &headers);
                // FIN は SYN_STREAM を受理して stdin に割り当てた場合だけ立てる（拒否した再送では立てない）。
                if fin && before.is_none() && streams.stdin == Some(stream_id) {
                    early.fin = true;
                }
                r
            }
            Frame::Data { stream_id, .. }
                if streams.stdin == Some(stream_id) && early.reset.contains(&stream_id) =>
            {
                // リセット済みのストリームの DATA は捨てる。
                Ok(())
            }
            Frame::Data { stream_id, .. } if streams.stdin == Some(stream_id) && early.fin => {
                // FIN 済みの送信方向への後続 DATA は拒否する（Attach と同じ。CRI-6）。
                early.buf.clear();
                early.reset.push(stream_id);
                conn.queue(&Frame::RstStream {
                    stream_id,
                    status: rst_status::STREAM_ALREADY_CLOSED,
                })
            }
            Frame::Data {
                stream_id,
                fin,
                data,
            } if streams.stdin == Some(stream_id) => {
                if early.buf.len().saturating_add(data.len()) > MAX_EARLY_STDIN_BYTES {
                    return StreamWait::Protocol;
                }
                early.buf.extend_from_slice(&data);
                early.fin |= fin;
                Ok(())
            }
            Frame::Data { stream_id, .. }
                if streams.resize == Some(stream_id) && early.reset.contains(&stream_id) =>
            {
                Ok(())
            }
            Frame::Data {
                stream_id, data, ..
            } if streams.resize == Some(stream_id) => {
                if early.resize.len().saturating_add(data.len()) > MAX_EARLY_RESIZE_BYTES {
                    return StreamWait::Protocol;
                }
                early.resize.extend_from_slice(&data);
                Ok(())
            }
            Frame::RstStream { stream_id, .. } if streams.is_known(stream_id) => {
                if streams.stdin == Some(stream_id) {
                    early.fin = true;
                }
                if !early.reset.contains(&stream_id) {
                    early.reset.push(stream_id);
                }
                Ok(())
            }
            Frame::Ping { id } if id % 2 == 1 => conn.queue(&Frame::Ping { id }),
            Frame::GoAway { .. } => return StreamWait::Closed,
            _ => Ok(()),
        };
        if queued.is_err() || conn.flush().await.is_err() {
            return StreamWait::Protocol;
        }
    }
    StreamWait::Ready
}

/// 1 本の SYN_STREAM を受け付けるか拒否する（拒否は RST_STREAM。接続は閉じない）。
fn accept_stream<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<T>,
    expected: &[StreamType],
    streams: &mut Streams,
    id: StreamId,
    headers: &Headers,
) -> Result<(), SpdyError> {
    let reject = |conn: &mut Conn<T>, status: u32| {
        conn.queue(&Frame::RstStream {
            stream_id: id,
            status,
        })
    };
    // クライアント側の ID は奇数で単調増加（SPDY/3 §2.3.2）。
    if id.get().is_multiple_of(2) || id.get() <= streams.last_id {
        return reject(conn, rst_status::PROTOCOL_ERROR);
    }
    // ID は受理・拒否の判定より前に消費する（拒否した ID の再利用を許さない。SPDY/3 §2.3.2）。
    streams.last_id = id.get();
    let Some(kind) = headers.get(HEADER_STREAM_TYPE).and_then(StreamType::parse) else {
        return reject(conn, rst_status::PROTOCOL_ERROR);
    };
    if !expected.contains(&kind) || streams.get(kind).is_some() {
        return reject(conn, rst_status::REFUSED_STREAM);
    }
    *streams.slot(kind) = Some(id);
    conn.queue(&Frame::SynReply {
        stream_id: id,
        fin: false,
        headers: Headers::new(),
    })
}

/// 出力側（stdout / stderr）の読み取り口。
struct Output {
    reader: BoxedRead,
    id: StreamId,
    eof: bool,
    /// 読み取りがエラーで終わった（正常 EOF と区別する）。
    failed: bool,
    /// 1 回以上データを読めた（操作別計装用。REPAIR-4）。
    read_ok: bool,
}

/// 中継の終わり方。
enum RelayEnd {
    Finished,
    /// drain の期限までに出力を送り切れなかった。
    DrainExpired,
    PeerClosed,
    Idle,
    Protocol,
}

/// 起動後の中継状態。
struct Relay<T> {
    conn: Conn<T>,
    streams: Streams,
    stdin: Option<BoxedWrite>,
    stdin_buf: Vec<u8>,
    stdin_pos: usize,
    stdin_fin: bool,
    /// 書いた内容の flush が未完了か（BufWriter 等の背後の溜めへ対処する）。
    stdin_flush_pending: bool,
    /// 溜めた stdin が進展しない時間の計測（バッファが空なら `None`）。
    stdin_stall: Option<Pin<Box<Sleep>>>,
    stdin_stall_timeout: Duration,
    stdout: Option<Output>,
    stderr: Option<Output>,
    /// 出力の処理順を周回ごとに入れ替える印（stdout / stderr の公平化）。
    stderr_first: bool,
    resizer: Option<Box<dyn TerminalResizer>>,
    resize_parser: ResizeParser,
    protocol: Protocol,
    close_timeout: Duration,
    exit: Option<ExitFuture>,
    exit_result: Option<Result<i32, CriError>>,
    drain: Option<Pin<Box<Sleep>>>,
    drain_timeout: Duration,
    idle: Pin<Box<Sleep>>,
    idle_timeout: Duration,
    /// RST_STREAM を受けたストリーム。以後そのストリームへは何も送らない（SPDY/3 §2.3.7。CRI-6）。
    reset_ids: Vec<StreamId>,
    /// backend 側（stdin・stdout・stderr）の読み書きの成否。閉じた出力の分もここへ畳む（REPAIR-4）。
    stats: IoStats,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Relay<T> {
    fn is_reset(&self, id: StreamId) -> bool {
        self.reset_ids.contains(&id)
    }

    /// クライアントがリセットした出力の読み手を解放する（以後その ID へ DATA・FIN を送らない）。
    fn retire_output(&mut self, id: StreamId) {
        for slot in [&mut self.stdout, &mut self.stderr] {
            if slot.as_ref().is_some_and(|o| o.id == id)
                && let Some(out) = slot.take()
            {
                self.stats.stream_read_ok |= out.read_ok;
                self.stats.stream_read_failed |= out.failed;
            }
        }
    }

    /// 通信路と backend の成否をまとめる（セッション終了時に呼ぶ）。
    fn collect_stats(&self) -> IoStats {
        let mut stats = self.stats;
        for out in [self.stdout.as_ref(), self.stderr.as_ref()]
            .into_iter()
            .flatten()
        {
            stats.stream_read_ok |= out.read_ok;
            stats.stream_read_failed |= out.failed;
        }
        stats.conn_read_ok = self.conn.stats.conn_read_ok;
        stats.conn_read_failed = self.conn.stats.conn_read_failed;
        stats.conn_write_ok = self.conn.stats.conn_write_ok;
        stats.conn_write_failed = self.conn.stats.conn_write_failed;
        stats
    }

    /// RST_STREAM を受けた既知のストリームを記録し、対応する資源を解放する。
    fn on_reset(&mut self, stream_id: StreamId) {
        if !self.streams.is_known(stream_id) || self.is_reset(stream_id) {
            return;
        }
        self.reset_ids.push(stream_id);
        if Some(stream_id) == self.streams.stdin {
            self.stdin_fin = true;
        }
        if Some(stream_id) == self.streams.resize {
            self.resizer = None;
        }
        self.retire_output(stream_id);
        // 背圧で送信キューに残っているこのストリームの DATA・FIN も送らない（§2.3.7）。
        self.conn.purge_stream(stream_id);
    }

    fn touch(&mut self) {
        self.idle
            .as_mut()
            .reset(tokio::time::Instant::now() + self.idle_timeout);
    }

    /// 受信した 1 フレームを処理する。`Err` は中継の終了。
    fn on_frame(&mut self, frame: Frame) -> Result<(), RelayEnd> {
        match frame {
            Frame::Data {
                stream_id,
                fin,
                data,
            } => {
                self.touch();
                if self.is_reset(stream_id) {
                    // リセット済みのストリームの DATA は捨てる。
                } else if Some(stream_id) == self.streams.stdin {
                    if self.stdin_fin {
                        // FIN 済みの送信方向への後続 DATA は拒否する（Attach と同じ。CRI-6）。
                        self.stdin_buf.clear();
                        self.stdin_pos = 0;
                        self.conn
                            .queue(&Frame::RstStream {
                                stream_id,
                                status: rst_status::STREAM_ALREADY_CLOSED,
                            })
                            .map_err(|_| RelayEnd::Protocol)?;
                        self.on_reset(stream_id);
                        return Ok(());
                    }
                    if self.stdin.is_some() {
                        self.stdin_buf.extend_from_slice(&data);
                    }
                    if fin {
                        self.stdin_fin = true;
                    }
                } else if Some(stream_id) == self.streams.resize {
                    self.feed_resize(&data);
                }
            }
            Frame::RstStream { stream_id, .. } => self.on_reset(stream_id),
            Frame::Ping { id } if id % 2 == 1 => {
                self.conn
                    .queue(&Frame::Ping { id })
                    .map_err(|_| RelayEnd::Protocol)?;
            }
            Frame::GoAway { .. } => return Err(RelayEnd::PeerClosed),
            Frame::SynStream { stream_id, .. } => {
                // 組が揃った後の追加ストリームは拒否する。
                self.conn
                    .queue(&Frame::RstStream {
                        stream_id,
                        status: rst_status::REFUSED_STREAM,
                    })
                    .map_err(|_| RelayEnd::Protocol)?;
            }
            // WINDOW_UPDATE・SETTINGS・HEADERS・SYN_REPLY・偶数の PING は読み捨てる（モジュール doc のフロー制御の項）。
            _ => {}
        }
        Ok(())
    }

    /// resize ストリームの DATA を [`ResizeParser`] で解析して端末へ反映する。
    /// 不正な値は捨てる（パーサーが滞留を消す）。フレーム境界をまたぐ JSON も読める。
    fn feed_resize(&mut self, data: &[u8]) {
        if let Ok(sizes) = self.resize_parser.push(data)
            && let Some(resizer) = self.resizer.as_mut()
        {
            for size in sizes {
                let _ = resizer.resize(size);
            }
        }
    }

    /// 全入力を同時に見て進められるだけ進める。
    ///
    /// 出力が続く間も 1 回の poll で回す周回数は `MAX_POLL_ROUNDS` までとし、
    /// 超えたら自身を wake して `Pending` で executor へ譲る（runtime スレッドの占有防止。REPAIR-5）。
    fn poll_run(&mut self, cx: &mut Context<'_>) -> Poll<RelayEnd> {
        let mut rounds = 0usize;
        loop {
            let mut progress = false;

            // プロセスの終了を stdin の期限や idle の判定より先に確かめる（終了済みの実行を
            // Timeout の Status にしない。CRI-6・REPAIR-5）。終了済みなら stdin の残りは捨てて通常の終了経路へ進む。
            if self.exit_result.is_none()
                && let Some(fut) = self.exit.as_mut()
                && let Poll::Ready(result) = fut.as_mut().poll(cx)
            {
                self.exit_result = Some(result);
                self.exit = None;
                self.drain = Some(Box::pin(tokio::time::sleep(self.drain_timeout)));
                self.stdin = None;
                self.stdin_buf.clear();
                self.stdin_pos = 0;
                self.stdin_flush_pending = false;
                self.stdin_stall = None;
                progress = true;
            }

            // 送信キューを書き出す。
            let before = self.conn.pending_write();
            if let Poll::Ready(Err(_)) = self.conn.poll_flush(cx) {
                return Poll::Ready(RelayEnd::PeerClosed);
            }
            if self.conn.pending_write() < before {
                progress = true;
            }

            // 溜めた stdin をプロセスへ書く。
            let mut stdin_progressed = false;
            if let Some(writer) = self.stdin.as_mut() {
                let mut broken = false;
                while self.stdin_pos < self.stdin_buf.len() {
                    let chunk = self.stdin_buf.get(self.stdin_pos..).unwrap_or(&[]);
                    match Pin::new(&mut *writer).poll_write(cx, chunk) {
                        Poll::Ready(Ok(n)) if n > 0 => {
                            self.stdin_pos = self.stdin_pos.saturating_add(n);
                            self.stats.stream_write_ok = true;
                            self.stdin_flush_pending = true;
                            progress = true;
                            stdin_progressed = true;
                        }
                        Poll::Ready(_) => {
                            broken = true;
                            break;
                        }
                        Poll::Pending => break,
                    }
                }
                if broken {
                    // プロセス側が閉じた。以後の stdin は捨てる（失敗は計装に残す。REPAIR-4）。
                    self.stats.stream_write_failed = true;
                    self.stdin = None;
                    self.stdin_flush_pending = false;
                    self.stdin_buf.clear();
                    self.stdin_pos = 0;
                    progress = true;
                } else if self.stdin_pos >= self.stdin_buf.len() {
                    self.stdin_buf.clear();
                    self.stdin_pos = 0;
                    // 書き終えた後も flush の完了まで駆動する。BufWriter 等は poll_write が
                    // 全量を受理しても内部に溜めるだけで、flush まで相手へ届かない（CRI-6）。
                    let mut closed = false;
                    if self.stdin_flush_pending {
                        match Pin::new(&mut *writer).poll_flush(cx) {
                            Poll::Ready(Ok(())) => {
                                self.stdin_flush_pending = false;
                                stdin_progressed = true;
                                progress = true;
                            }
                            Poll::Ready(Err(_)) => {
                                self.stats.stream_write_failed = true;
                                self.stdin_flush_pending = false;
                                closed = true;
                            }
                            Poll::Pending => {}
                        }
                    }
                    if !closed && !self.stdin_flush_pending && self.stdin_fin {
                        // shutdown の成否を分ける。Err は失敗として記録する（REPAIR-4）。
                        match Pin::new(&mut *writer).poll_shutdown(cx) {
                            Poll::Ready(Ok(())) => closed = true,
                            Poll::Ready(Err(_)) => {
                                self.stats.stream_write_failed = true;
                                closed = true;
                            }
                            Poll::Pending => {}
                        }
                    }
                    if closed {
                        self.stdin = None;
                        progress = true;
                    }
                }
            } else if !self.stdin_buf.is_empty() {
                self.stdin_buf.clear();
                self.stdin_pos = 0;
            }

            // 溜めた stdin が進展しない間はソケットを読めず切断を検知できないため、期限で打ち切る。
            // flush・shutdown の完了待ちにも同じ期限を適用する（REPAIR-5）。
            let stdin_busy = !self.stdin_buf.is_empty()
                || (self.stdin.is_some() && (self.stdin_flush_pending || self.stdin_fin));
            if !stdin_busy {
                self.stdin_stall = None;
            } else {
                let deadline = tokio::time::Instant::now() + self.stdin_stall_timeout;
                match self.stdin_stall.as_mut() {
                    Some(sleep) if !stdin_progressed => {
                        if sleep.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(RelayEnd::Idle);
                        }
                    }
                    Some(sleep) => sleep.as_mut().reset(deadline),
                    None => {
                        let mut sleep = Box::pin(tokio::time::sleep_until(deadline));
                        let _ = sleep.as_mut().poll(cx);
                        self.stdin_stall = Some(sleep);
                    }
                }
            }

            // クライアントのフレームを処理する。stdin の書き込み待ちが残る間は読まない（背圧）。
            // flush 待ちも同じ背圧にする（受理だけして flush しない writer への入力で期限が延びない。REPAIR-5）。
            while self.stdin_buf.is_empty()
                && !self.stdin_flush_pending
                && self.conn.pending_write() < MAX_SEND_QUEUE_BYTES
            {
                match self.conn.try_next_frame() {
                    Ok(Some(frame)) => {
                        progress = true;
                        if let Err(end) = self.on_frame(frame) {
                            return Poll::Ready(end);
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return Poll::Ready(RelayEnd::Protocol),
                }
            }
            if self.stdin_buf.is_empty()
                && !self.stdin_flush_pending
                && self.conn.pending_write() < MAX_SEND_QUEUE_BYTES
            {
                match self.conn.poll_read_more(cx) {
                    Poll::Ready(Ok(0)) | Poll::Ready(Err(ReadStop::Io)) => {
                        return Poll::Ready(RelayEnd::PeerClosed);
                    }
                    // 受信バッファの超過は切断ではなく規則違反として閉じる（EOF と区別する）。
                    Poll::Ready(Err(ReadStop::Overflow)) => {
                        return Poll::Ready(RelayEnd::Protocol);
                    }
                    Poll::Ready(Ok(_)) => progress = true,
                    Poll::Pending => {}
                }
            }

            // stdout / stderr をクライアントへ送る。
            // 先頭を毎周回入れ替え、片方が共有キューを使い切って他方が飢えるのを避ける。
            self.stderr_first = !self.stderr_first;
            for turn in 0..2 {
                let which = if self.stderr_first { 1 - turn } else { turn };
                let out = if which == 0 {
                    self.stdout.as_mut()
                } else {
                    self.stderr.as_mut()
                };
                if let Some(out) = out {
                    match pump_output(&mut self.conn, out, cx) {
                        Ok(true) => {
                            progress = true;
                            self.touch();
                        }
                        Ok(false) => {}
                        Err(_) => return Poll::Ready(RelayEnd::Protocol),
                    }
                }
            }

            if self.exit_result.is_some() {
                let outputs_done = self.stdout.as_ref().is_none_or(|o| o.eof)
                    && self.stderr.as_ref().is_none_or(|o| o.eof);
                let drain_expired = self
                    .drain
                    .as_mut()
                    .is_some_and(|s| s.as_mut().poll(cx).is_ready());
                if outputs_done {
                    return Poll::Ready(RelayEnd::Finished);
                }
                if drain_expired {
                    return Poll::Ready(RelayEnd::DrainExpired);
                }
            }

            if self.idle.as_mut().poll(cx).is_ready() {
                return Poll::Ready(RelayEnd::Idle);
            }
            if !progress {
                return Poll::Pending;
            }
            rounds = rounds.saturating_add(1);
            if rounds >= MAX_POLL_ROUNDS {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
    }

    /// 終わり方に応じて通知・GOAWAY・シャットダウンを行い、結末を返す。
    async fn finalize(&mut self, end: RelayEnd) -> ExecStreamOutcome {
        let last = self.streams.last_id;
        match end {
            RelayEnd::PeerClosed => ExecStreamOutcome::PeerClosed,
            RelayEnd::Idle => {
                // 終了コードが無いまま打ち切るため、失敗の Status を最善努力で届ける（期限は close_timeout）。
                // 送れなかった場合も結末は IdleTimeout のまま（送出失敗は通信路の計装に残る）。
                let status = status_timeout(self.protocol);
                self.finish_with(Some(&status), ExecStreamOutcome::IdleTimeout)
                    .await
            }
            RelayEnd::Protocol => {
                self.conn
                    .goodbye(last, goaway_status::PROTOCOL_ERROR, self.close_timeout)
                    .await;
                ExecStreamOutcome::ProtocolError
            }
            RelayEnd::DrainExpired => {
                // 出力を送り切れていない。終了コードによらず失敗として通知する。
                self.finish_failed(ExecStreamOutcome::OutputTruncated).await
            }
            RelayEnd::Finished => {
                let output_failed = [self.stdout.as_ref(), self.stderr.as_ref()]
                    .into_iter()
                    .flatten()
                    .any(|o| o.failed);
                if output_failed {
                    return self.finish_failed(ExecStreamOutcome::OutputFailed).await;
                }
                let (status, outcome) = match self.exit_result.take() {
                    Some(Ok(code)) => (
                        status_exit(self.protocol, code),
                        ExecStreamOutcome::Exited { code },
                    ),
                    _ => (
                        Some(status_internal_error(self.protocol)),
                        ExecStreamOutcome::ExecFailed,
                    ),
                };
                // 読み切れなかった出力ストリームにも FIN を付ける。
                let mut fins = Vec::new();
                for out in [self.stdout.as_ref(), self.stderr.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    if !out.eof {
                        fins.push(out.id);
                    }
                }
                let delivered = self.close_with_status(status.as_deref(), &fins).await;
                // 出力・Status を送り切れなかった結末は、成功にせず送出失敗として返す（REPAIR-4・REPAIR-5）。
                let code = match outcome {
                    ExecStreamOutcome::Exited { code } => Some(code),
                    _ => None,
                };
                match delivered {
                    Goodbye::Delivered => outcome,
                    Goodbye::Failed => ExecStreamOutcome::DeliveryFailed { code },
                    Goodbye::TimedOut => ExecStreamOutcome::DeliveryTimedOut { code },
                }
            }
        }
    }

    /// 内部エラーの Status（詳細なし）を通知し、読み切れなかった出力にも FIN を付けて閉じる。
    async fn finish_failed(&mut self, outcome: ExecStreamOutcome) -> ExecStreamOutcome {
        let status = status_internal_error(self.protocol);
        self.finish_with(Some(&status), outcome).await
    }

    /// `status` を error ストリームへ通知し、読み切れなかった出力にも FIN を付けて閉じる。結末は変えない。
    async fn finish_with(
        &mut self,
        status: Option<&[u8]>,
        outcome: ExecStreamOutcome,
    ) -> ExecStreamOutcome {
        let fins: Vec<StreamId> = [self.stdout.as_ref(), self.stderr.as_ref()]
            .into_iter()
            .flatten()
            .filter(|o| !o.eof)
            .map(|o| o.id)
            .collect();
        // 失敗の結末はすでに非成功。送出失敗は通信路の計装（conn_write_failed）に残る。
        let _ = self.close_with_status(status, &fins).await;
        outcome
    }

    async fn close_with_status(
        &mut self,
        status: Option<&[u8]>,
        extra_fins: &[StreamId],
    ) -> Goodbye {
        if let Some(error_id) = self.streams.error {
            send_status(
                &mut self.conn,
                error_id,
                status,
                extra_fins,
                &self.reset_ids,
                self.streams.last_id,
                self.close_timeout,
            )
            .await
        } else {
            Goodbye::Delivered
        }
    }
}

/// 出力 1 本を読めるだけクライアントへ送る。進展があれば `true`。EOF で FIN を送る。読み取りエラーも FIN を送るが `failed` を立てる。
fn pump_output<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<T>,
    out: &mut Output,
    cx: &mut Context<'_>,
) -> Result<bool, SpdyError> {
    let mut progressed = false;
    let mut reads = 0usize;
    // 1 周回あたりの読み取り回数に上限を付け、他方の出力にも送信キューを残す。
    while !out.eof
        && reads < MAX_OUTPUT_READS_PER_ROUND
        && conn.pending_write() < MAX_SEND_QUEUE_BYTES
    {
        reads += 1;
        let mut tmp = [0u8; MAX_OUTGOING_DATA];
        let mut buf = ReadBuf::new(&mut tmp);
        match Pin::new(&mut out.reader).poll_read(cx, &mut buf) {
            Poll::Pending => break,
            Poll::Ready(Ok(())) if !buf.filled().is_empty() => {
                out.read_ok = true;
                conn.queue(&Frame::Data {
                    stream_id: out.id,
                    fin: false,
                    data: buf.filled().to_vec(),
                })?;
                progressed = true;
            }
            Poll::Ready(result) => {
                out.eof = true;
                out.failed = result.is_err();
                conn.queue(&Frame::Data {
                    stream_id: out.id,
                    fin: true,
                    data: Vec::new(),
                })?;
                progressed = true;
            }
        }
    }
    Ok(progressed)
}

/// error ストリームに Status を書いて閉じ、`extra_fins` に FIN を付けて GOAWAY・シャットダウンする。
/// `status` が `None`（v3・v2 の成功）なら error ストリームには何も書かず FIN だけを送る。
async fn send_status<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<T>,
    error_id: StreamId,
    status: Option<&[u8]>,
    extra_fins: &[StreamId],
    reset: &[StreamId],
    last_good: u32,
    close_timeout: Duration,
) -> Goodbye {
    // クライアントがリセットしたストリームへは何も送らない（SPDY/3 §2.3.7）。
    if !reset.contains(&error_id) {
        let _ = conn.queue(&Frame::Data {
            stream_id: error_id,
            fin: true,
            data: status.map(<[u8]>::to_vec).unwrap_or_default(),
        });
    }
    for id in extra_fins.iter().filter(|id| !reset.contains(id)) {
        let _ = conn.queue(&Frame::Data {
            stream_id: *id,
            fin: true,
            data: Vec::new(),
        });
    }
    conn.goodbye(last_good, goaway_status::OK, close_timeout)
        .await
}

/// Upgrade 後の IO 1 本分の Exec セッションを最後まで駆動する。
///
/// `req` は発行時に保存した要求（通信路の内容から組み立てない）。`launcher` はストリームが揃った後にだけ呼ぶ。
pub(crate) async fn run_exec_session<T: AsyncRead + AsyncWrite + Unpin>(
    io: T,
    protocol: Protocol,
    options: StreamOptions,
    req: &v1::ExecRequest,
    launcher: &dyn ExecStreamLauncher,
    config: &ExecStreamConfig,
) -> (ExecStreamOutcome, IoStats) {
    let mut conn = Conn::new(io);
    let expected = options.expected(protocol);
    let close_timeout = config.limits.close_timeout;
    let mut streams = Streams::default();
    let mut early = EarlyStdin::default();

    // 1. 必要なストリームが揃うまで待つ（期限つき）。
    let waited = tokio::time::timeout(
        config.limits.stream_creation_timeout,
        await_streams(&mut conn, &expected, &mut streams, &mut early),
    )
    .await;
    match waited {
        Err(_) => {
            conn.goodbye(streams.last_id, goaway_status::OK, close_timeout)
                .await;
            return (ExecStreamOutcome::StreamCreationTimeout, conn.stats);
        }
        Ok(StreamWait::Closed) => return (ExecStreamOutcome::PeerClosed, conn.stats),
        Ok(StreamWait::Protocol) => {
            conn.goodbye(
                streams.last_id,
                goaway_status::PROTOCOL_ERROR,
                close_timeout,
            )
            .await;
            return (ExecStreamOutcome::ProtocolError, conn.stats);
        }
        Ok(StreamWait::Ready) => {}
    }
    let Some(error_id) = streams.error else {
        return (ExecStreamOutcome::ProtocolError, conn.stats);
    };

    // 2. 起動（期限つき）。
    let launch = ExecLaunch {
        container_id: req.container_id.clone(),
        cmd: req.cmd.clone(),
        tty: options.tty,
        stdin: options.stdin,
        stdout: options.stdout,
        stderr: options.stderr,
    };
    let session = match tokio::time::timeout(config.launch_timeout, launcher.launch(launch)).await {
        Ok(Ok(session)) if session_matches(&session, options) => session,
        _ => {
            let status = status_internal_error(protocol);
            send_status(
                &mut conn,
                error_id,
                Some(&status),
                &[],
                &early.reset,
                streams.last_id,
                close_timeout,
            )
            .await;
            return (ExecStreamOutcome::LaunchFailed, conn.stats);
        }
    };

    // 3. 中継。
    let ExecSession {
        stdin,
        stdout,
        stderr,
        exit,
        resize,
    } = session;
    // 揃う前にリセットされた出力は読み手を持たない（ここで drop して解放する）。
    let output = |reader: Option<BoxedRead>, id: Option<StreamId>| match (reader, id) {
        (Some(reader), Some(id)) if !early.reset.contains(&id) => Some(Output {
            reader,
            id,
            eof: false,
            failed: false,
            read_ok: false,
        }),
        _ => None,
    };
    let mut relay = Relay {
        conn,
        streams,
        stdin,
        stdin_buf: early.buf,
        stdin_pos: 0,
        stdin_fin: early.fin,
        stdin_flush_pending: false,
        stdin_stall: None,
        stdin_stall_timeout: config.stdin_stall_timeout,
        stdout: output(stdout, streams.stdout),
        stderr: output(stderr, streams.stderr),
        stderr_first: false,
        resizer: resize,
        resize_parser: ResizeParser::new(),
        protocol,
        close_timeout,
        exit: Some(exit),
        exit_result: None,
        drain: None,
        drain_timeout: config.limits.drain_timeout,
        idle: Box::pin(tokio::time::sleep(config.limits.stream_idle_timeout)),
        idle_timeout: config.limits.stream_idle_timeout,
        reset_ids: early.reset.clone(),
        stats: IoStats::default(),
    };
    // 確立前に届いた resize を適用する（初期サイズを落とさない。CRI-6）。
    for chunk in early.resize.chunks(EARLY_RESIZE_REPLAY_CHUNK) {
        relay.feed_resize(chunk);
    }
    let end = poll_fn(|cx| relay.poll_run(cx)).await;
    // relay を drop すると ExecSession 由来の資源が解放され、プロセスが止まる（契約）。
    let outcome = relay.finalize(end).await;
    (outcome, relay.collect_stats())
}

/// launcher が要求どおりの stdio を返したか。
fn session_matches(session: &ExecSession, options: StreamOptions) -> bool {
    session.stdin.is_some() == options.stdin
        && session.stdout.is_some() == options.stdout
        && session.stderr.is_some() == options.stderr
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1 回の `poll_write` で 1 バイトだけ受け、次は Pending を返す書き込み先。
    struct TrickleIo {
        accepted_last: bool,
    }

    impl AsyncRead for TrickleIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for TrickleIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.accepted_last {
                self.accepted_last = false;
                Poll::Pending
            } else {
                self.accepted_last = true;
                Poll::Ready(Ok(1))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// CRI-6: 部分送信と Pending が続いても、送信バッファの実長に送信済み領域が残らない。
    #[test]
    fn cri6_send_queue_does_not_retain_sent_bytes() {
        let mut conn = Conn::new(TrickleIo {
            accepted_last: false,
        });
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for _ in 0..200 {
            conn.queue(&Frame::Data {
                stream_id: StreamId::new(1).expect("stream id"),
                fin: false,
                data: vec![b'x'; 16],
            })
            .expect("queue");
            // 追記直後は送信済み領域が残らない（wbuf の実長 = 未送信量）。
            assert_eq!(conn.wpos, 0);
            assert_eq!(conn.wbuf.len(), conn.pending_write());
            let _ = conn.poll_flush(&mut cx);
        }
    }

    /// 常に読める無限の stdout。
    struct Endless;
    impl AsyncRead for Endless {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = buf.remaining();
            buf.put_slice(&vec![b'o'; n]);
            Poll::Ready(Ok(()))
        }
    }

    /// 1 バイトだけ返して EOF になる stderr。
    struct OneShot(bool);
    impl AsyncRead for OneShot {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if !self.0 {
                self.0 = true;
                buf.put_slice(b"e");
            }
            Poll::Ready(Ok(()))
        }
    }

    /// CRI-6・REPAIR-5: 常に読める stdout が 1 回の呼び出しで読む量は 128 KiB までで、続く stderr も送信キューに積まれる。
    #[test]
    fn cri6_pump_output_is_bounded_and_stderr_not_starved() {
        let mut conn = Conn::new(TrickleIo {
            accepted_last: true,
        });
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut stdout = Output {
            reader: Box::new(Endless),
            id: StreamId::new(3).expect("id"),
            eof: false,
            failed: false,
            read_ok: false,
        };
        let mut stderr = Output {
            reader: Box::new(OneShot(false)),
            id: StreamId::new(5).expect("id"),
            eof: false,
            failed: false,
            read_ok: false,
        };
        assert!(pump_output(&mut conn, &mut stdout, &mut cx).expect("stdout"));
        let after_stdout = conn.pending_write();
        // 4 回 x 32 KiB のペイロードに DATA ヘッダ 8 バイト x 4 を足した量。
        assert_eq!(after_stdout, 4 * (32 * 1024 + 8));
        assert!(pump_output(&mut conn, &mut stderr, &mut cx).expect("stderr"));
        // stderr は 1 バイトのデータ + FIN の 2 フレーム（ヘッダ 8 バイト x 2 + 1）。
        assert_eq!(conn.pending_write(), after_stdout + 8 + 1 + 8);
        assert!(stderr.eof);
    }

    /// CRI-6: 非 0 の終了コードは v4 では kubelet と同じ JSON、v3・v2 では終了コードの文になる。成功は v4 のみ JSON。
    #[test]
    fn cri6_status_exit_per_protocol() {
        assert_eq!(
            status_exit(Protocol::V4, 0).as_deref(),
            Some(br#"{"metadata":{},"status":"Success"}"#.as_slice())
        );
        assert_eq!(status_exit(Protocol::V3, 0), None);
        assert_eq!(status_exit(Protocol::V2, 0), None);
        assert_eq!(
            status_exit(Protocol::V4, 3).as_deref(),
            Some(
                br#"{"metadata":{},"status":"Failure","message":"command terminated with non-zero exit code: command terminated with exit code 3","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"3"}]}}"#.as_slice()
            )
        );
        assert_eq!(
            status_exit(Protocol::V3, 3).as_deref(),
            Some(b"command terminated with exit code 3".as_slice())
        );
        let v: serde_json::Value =
            serde_json::from_slice(&status_exit(Protocol::V4, -1).expect("status")).expect("json");
        assert_eq!(v["reason"], "NonZeroExitCode");
    }

    /// CRI-6: 内部エラーの Status は固定文（v4 は JSON の InternalError・500）。
    #[test]
    fn cri6_status_internal_error_fixed() {
        let v: serde_json::Value =
            serde_json::from_slice(&status_internal_error(Protocol::V4)).expect("json");
        assert_eq!(v["reason"], "InternalError");
        assert_eq!(v["code"], 500);
        assert_eq!(
            status_internal_error(Protocol::V2),
            b"error executing command in container".to_vec()
        );
    }

    /// CRI-6・REPAIR-5: 設定の検証（0 と上限超えを拒否）。
    #[test]
    fn cri6_exec_config_validate_bounds() {
        let base = ExecStreamConfig::default();
        assert!(base.validate().is_ok());
        let zero = Duration::ZERO;
        let mut c = base.clone();
        c.limits.stream_creation_timeout = zero;
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.limits.stream_idle_timeout = Duration::from_secs(24 * 60 * 60 + 1);
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.limits.drain_timeout = zero;
        assert!(c.validate().is_err());
        let c = ExecStreamConfig {
            launch_timeout: zero,
            ..base.clone()
        };
        assert!(c.validate().is_err());
        let c = ExecStreamConfig {
            stdin_stall_timeout: MAX_SESSION_STEP_TIMEOUT + Duration::from_secs(1),
            ..base
        };
        assert!(c.validate().is_err());
    }

    /// CRI-6: tty のとき stderr ストリームは求めず、v4・v3 では resize を求める（v2 は resize なし）。
    #[test]
    fn cri6_expected_streams_from_request() {
        let options = StreamOptions::new(true, true, true, true);
        assert!(!options.stderr);
        let v4 = options.expected(Protocol::V4);
        assert!(v4.contains(&StreamType::Stdin) && v4.contains(&StreamType::Resize));
        assert!(!v4.contains(&StreamType::Stderr));
        assert!(!options.expected(Protocol::V2).contains(&StreamType::Resize));
    }

    /// CRI-6・REPAIR-5: 受信バッファの超過は EOF（切断）ではなく規則違反として区別される。
    #[test]
    fn cri6_recv_overflow_is_not_eof() {
        struct NoIo;
        impl AsyncRead for NoIo {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for NoIo {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(data.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let mut conn = Conn::new(NoIo);
        conn.dec.extend(&vec![0u8; MAX_RECV_BUF_BYTES]);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            conn.poll_read_more(&mut cx),
            Poll::Ready(Err(ReadStop::Overflow))
        ));
    }

    /// 受け入れる総量に上限がある書き込み先（上限に達したら Pending。読み側は何も届かない）。
    struct LimitedIo {
        budget: usize,
        out: Vec<u8>,
        /// 読み取り側へ先に届けておく入力。
        input: Vec<u8>,
        fail_flush: bool,
    }

    impl LimitedIo {
        fn new(budget: usize) -> Self {
            Self {
                budget,
                out: Vec::new(),
                input: Vec::new(),
                fail_flush: false,
            }
        }
    }

    impl AsyncRead for LimitedIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.input.is_empty() {
                return Poll::Pending;
            }
            let n = self.input.len().min(buf.remaining());
            let chunk: Vec<u8> = self.input.drain(..n).collect();
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for LimitedIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.fail_flush {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
            }
            let n = self.budget.min(data.len());
            if n == 0 {
                return Poll::Pending;
            }
            self.budget -= n;
            if let Some(head) = data.get(..n) {
                self.out.extend_from_slice(head);
            }
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn data_frame(id: u32, fin: bool, data: &[u8]) -> Frame {
        Frame::Data {
            stream_id: StreamId::new(id).expect("stream id"),
            fin,
            data: data.to_vec(),
        }
    }

    fn decode_all(bytes: &[u8]) -> Vec<Frame> {
        let mut dec = FrameDecoder::new();
        dec.extend(bytes);
        let mut frames = Vec::new();
        while let Some(f) = dec.next_frame().expect("decode") {
            frames.push(f);
        }
        frames
    }

    /// CRI-6・TASK-63.2: 背圧で送信キューに残ったリセット済みストリームの DATA・FIN は送らない。
    /// ただし部分送信を始めたフレームは境界を保って送り切る（他ストリームのフレームは残る）。
    #[test]
    fn cri6_purge_drops_unsent_frames_of_reset_stream_but_finishes_partial_one() {
        let mut conn = Conn::new(LimitedIo::new(5));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        conn.queue(&data_frame(1, false, b"aaaa")).expect("queue a");
        conn.queue(&data_frame(3, false, b"bbbb")).expect("queue b");
        conn.queue(&data_frame(1, true, b"")).expect("queue c");
        conn.queue(&data_frame(1, false, b"dddd")).expect("queue d");
        // 先頭フレームの途中（5 バイト）まで送った状態で ID 1 がリセットされる。
        assert!(conn.poll_flush(&mut cx).is_pending());
        conn.purge_stream(StreamId::new(1).expect("stream id"));
        conn.io.budget = 10_000;
        assert!(conn.poll_flush(&mut cx).is_ready());
        let frames = decode_all(&conn.io.out);
        assert_eq!(
            frames,
            vec![data_frame(1, false, b"aaaa"), data_frame(3, false, b"bbbb")]
        );
    }

    /// CRI-6・TASK-63.2: 何も送っていないフレームはリセット済みストリームの分をすべて取り除く。
    #[test]
    fn cri6_purge_removes_all_frames_when_nothing_was_sent() {
        let mut conn = Conn::new(LimitedIo::new(0));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        conn.queue(&data_frame(1, false, b"aaaa")).expect("queue a");
        conn.queue(&data_frame(3, true, b"")).expect("queue b");
        conn.queue(&data_frame(1, true, b"")).expect("queue c");
        conn.purge_stream(StreamId::new(1).expect("stream id"));
        conn.io.budget = 10_000;
        assert!(conn.poll_flush(&mut cx).is_ready());
        assert_eq!(decode_all(&conn.io.out), vec![data_frame(3, true, b"")]);
        assert_eq!(conn.pending_write(), 0);
    }

    /// REPAIR-4・REPAIR-5: 溜めた出力を期限までに送れなければ `TimedOut` を返し、通信路の書き込み失敗を残す。
    #[tokio::test]
    async fn cri6_goodbye_reports_timeout_when_peer_stops_receiving() {
        let mut conn = Conn::new(LimitedIo::new(3));
        conn.queue(&data_frame(1, false, b"aaaa")).expect("queue");
        let r = conn
            .goodbye(0, goaway_status::OK, Duration::from_millis(50))
            .await;
        assert_eq!(r, Goodbye::TimedOut);
        assert!(conn.stats.conn_write_failed);
    }

    /// REPAIR-4: 溜めた出力の書き込みエラーは `Failed` で返る。送り切れれば `Delivered`。
    #[tokio::test]
    async fn cri6_goodbye_reports_failure_and_delivery() {
        let mut conn = Conn::new(LimitedIo::new(10_000));
        conn.io.fail_flush = true;
        conn.queue(&data_frame(1, false, b"aaaa")).expect("queue");
        let r = conn
            .goodbye(0, goaway_status::OK, Duration::from_secs(1))
            .await;
        assert_eq!(r, Goodbye::Failed);
        assert!(conn.stats.conn_write_failed);

        let mut ok = Conn::new(LimitedIo::new(10_000));
        ok.queue(&data_frame(1, false, b"aaaa")).expect("queue");
        let r = ok
            .goodbye(0, goaway_status::OK, Duration::from_secs(1))
            .await;
        assert_eq!(r, Goodbye::Delivered);
        assert!(!ok.stats.conn_write_failed);
    }

    /// 指定バイト数の `x` を返して EOF になる stdout。
    struct FixedOutput(usize);
    impl AsyncRead for FixedOutput {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = self.0.min(buf.remaining());
            buf.put_slice(&vec![b'x'; n]);
            self.0 -= n;
            Poll::Ready(Ok(()))
        }
    }

    struct OutputLauncher(usize);
    impl ExecStreamLauncher for OutputLauncher {
        fn launch(
            &self,
            _req: ExecLaunch,
        ) -> Pin<Box<dyn Future<Output = Result<ExecSession, CriError>> + Send + '_>> {
            let size = self.0;
            Box::pin(async move {
                Ok(ExecSession {
                    stdin: None,
                    stdout: Some(Box::new(FixedOutput(size))),
                    stderr: None,
                    exit: Box::pin(async { Ok(0) }),
                    resize: None,
                })
            })
        }
    }

    /// CRI-6・REPAIR-4・REPAIR-5: クライアントが受信を止めて出力・Status を送り切れないとき、
    /// セッションは成功（Exited）にならず `DeliveryTimedOut`（終了コードは保持）と通信路の書き込み失敗になる。
    #[tokio::test]
    async fn cri6_session_is_not_success_when_client_stops_receiving() {
        let mut enc = FrameEncoder::new();
        let mut input = Vec::new();
        for (id, kind) in [(1u32, "error"), (3, "stdout")] {
            let mut headers = Headers::new();
            headers.push("streamtype", kind);
            enc.encode(
                &Frame::SynStream {
                    stream_id: StreamId::new(id).expect("stream id"),
                    associated_to: 0,
                    priority: 0,
                    fin: false,
                    unidirectional: false,
                    headers,
                },
                &mut input,
            )
            .expect("encode syn");
        }
        // SYN_REPLY 2 本分は受けられるが、その後は一切受け取らない。
        let mut io = LimitedIo::new(4096);
        io.input = input;
        let mut config = ExecStreamConfig::default();
        config.limits.close_timeout = Duration::from_millis(100);
        let (outcome, stats) = run_exec_session(
            io,
            Protocol::V4,
            StreamOptions::new(false, true, false, false),
            &v1::ExecRequest::default(),
            &OutputLauncher(20_000),
            &config,
        )
        .await;
        assert_eq!(
            outcome,
            ExecStreamOutcome::DeliveryTimedOut { code: Some(0) }
        );
        assert!(stats.conn_write_failed);
        assert_eq!(outcome_code(outcome), Code::DeadlineExceeded);
    }
}
