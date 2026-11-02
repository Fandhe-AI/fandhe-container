//! Exec のストリーミング本体（SPDY/3.1 上の Kubernetes remotecommand `v4.channel.k8s.io`。
//! CRI-6・TASK-63.2・#680・REPAIR-2・REPAIR-5・REPAIR-4。設計記録は `docs/design/cri-streaming-server.md`）。
//!
//! [`ExecStreamHandler`] は [`super::StreamHandler`] の実装で、`StreamingServer::bind_with_handler` に渡す。
//! トークンの照合に成功した `Exec` の要求を受け、HTTP/1.1 Upgrade（`SPDY/3.1`）で 101 を返したあと、
//! error・stdin・stdout・stderr（tty なら resize）の各ストリームを受け付け、注入された [`ExecStreamLauncher`] が
//! 返す stdio とクライアントの間で双方向に中継する。`Exec` 以外の種別は `fallback`（既定 501）へ渡す
//! （Attach・PortForward は #681・#682 が同じ形で連ねる）。
//!
//! ## 未実装（REPAIR-3）
//!
//! [`ExecStreamLauncher`] の本番の実装は無い。core の `ContainerRuntime` は exec を持たず、shim v2 の
//! `TaskExecLauncher` は stdio を持たない（containerd の FIFO 前提）ため、stdio を持つ起動役を本モジュールで
//! 注入トレイトとして定義した。supervisor の exec 入口（pidfd 経由）へ stdio のパイプ・pty を付けて橋渡しする
//! 実装と、plugin-cri からの `StreamingServer` の起動・注入は後続の issue で行う。WebSocket（`v5.channel.k8s.io`）も未対応。
//!
//! ## プロトコルの要点（kubernetes v1.34 の kubelet / apimachinery と moby/spdystream で確認）
//!
//! - 交渉: 要求ヘッダ `X-Stream-Protocol-Version` をクライアントの並び順に見て、最初に `v4.channel.k8s.io` に
//!   一致した時点で採用する。一致しなければ 403、`Upgrade` ヘッダが無ければ 400。v1〜v3 は受けない
//! - ストリーム: ヘッダ `streamtype`（`error`・`stdin`・`stdout`・`stderr`・`resize`）で種別を決める。
//!   保存済みの `ExecRequest` が求める組だけを受け付け、想定外・重複は RST_STREAM で拒否する
//! - 終了の通知: error ストリームへ `metav1.Status` の JSON を書く（成功は `Success`、非 0 は
//!   `NonZeroExitCode` と `ExitCode` の cause）
//! - フロー制御: moby/spdystream は WINDOW_UPDATE を送らず、受けても無視する。したがってこちらも送信窓に従わず、
//!   受信した WINDOW_UPDATE・SETTINGS・HEADERS は読み捨てる（従うと Go のクライアントと 64 KiB で詰まる）。
//!   代わりに送信キューの上限（[`MAX_SEND_QUEUE_BYTES`]）と stdin の書き込み待ちで背圧を TCP に任せる
//!
//! 共通化の候補（#681 Attach）: 握手（`negotiate_protocol`・Upgrade の確認）・status JSON・resize の解析・
//! ストリーム待ちの組み立て。本 issue では抽象化せず `pub(crate)` に留める。

use std::fmt;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue, UPGRADE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

use super::spdy::{
    Frame, FrameEncoder, GoAwayStatus, Header, HeaderDecompressor, MAX_DATA_FRAME_BYTES,
    ProtocolError, RstStatus, StreamId, decode_frame,
};
use super::{
    ConnectionPermit, NotImplementedHandler, StreamBody, StreamHandler, StreamRequest,
    plain_response,
};
use crate::error::CriError;
use crate::runtime::v1;

/// 採用する唯一のサブプロトコル（remotecommand v4。error ストリームに JSON の Status を書く）。
pub const EXEC_PROTOCOL_V4: &str = "v4.channel.k8s.io";
/// 送信キュー（未送信バイト）の上限。超えそうなときは stdout / stderr を読まない（背圧）。
pub const MAX_SEND_QUEUE_BYTES: usize = 1024 * 1024;
/// stdout / stderr を 1 DATA フレームにする最大バイト数。
const OUTPUT_CHUNK_BYTES: usize = 32 * 1024;
/// 受信バッファの 1 回の読み取りサイズ。
const READ_CHUNK_BYTES: usize = 16 * 1024;
/// 受信バッファの上限（最大の DATA フレーム + ヘッダ + 1 回の読み取り分）。
const MAX_RECV_BUF_BYTES: usize = MAX_DATA_FRAME_BYTES + 8 + READ_CHUNK_BYTES;
/// resize ストリームの 1 行の上限（バイト）。
const MAX_RESIZE_LINE_BYTES: usize = 1024;
/// ストリームが揃う前に届いた stdin の DATA を保持する上限（バイト）。超えたら ProtocolError。
const MAX_EARLY_STDIN_BYTES: usize = 256 * 1024;
/// `X-Stream-Protocol-Version` などの複数値ヘッダで見る値の個数の上限。
const MAX_HEADER_VALUES: usize = 16;
/// 1 つのヘッダ値から見るカンマ区切りの要素数の上限と、各要素の長さの上限。
const MAX_TOKENS_PER_HEADER: usize = 16;
const MAX_TOKEN_BYTES: usize = 64;
/// 終了時の GOAWAY・状態の書き出しとシャットダウンの待ちの上限（REPAIR-5）。
const FINAL_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
/// `idle_timeout` の上限（kubelet の既定 4 時間を大きく超えない範囲）。
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

type BoxedRead = Box<dyn AsyncRead + Send + Unpin>;
type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin>;
type ExitFuture = Pin<Box<dyn Future<Output = Result<i32, CriError>> + Send>>;

/// Exec セッションの設定。既定値は安全側（kubelet の既定に合わせた期限）。
#[derive(Debug, Clone)]
pub struct ExecStreamConfig {
    /// Upgrade 後、必要なストリームが揃うまでの期限。既定 30 秒（kubelet の `DefaultStreamCreationTimeout`）。
    pub stream_creation_timeout: Duration,
    /// 入出力が途絶えてから閉じるまでの期限。既定 4 時間（kubelet の `StreamIdleTimeout`）。上限は [`MAX_IDLE_TIMEOUT`]。
    pub idle_timeout: Duration,
    /// [`ExecStreamLauncher::launch`] の期限。既定 30 秒。
    pub launch_timeout: Duration,
    /// プロセス終了後に stdout / stderr を EOF まで読み切る期限。既定 10 秒。
    pub drain_timeout: Duration,
    /// 溜めた stdin をプロセスが読まないまま進展しない場合に閉じるまでの期限。既定 60 秒。
    /// 書き込み待ちの間はソケットを読まない（背圧）ため、クライアントの切断を検知できない時間の上限になる。
    pub stdin_stall_timeout: Duration,
}

impl Default for ExecStreamConfig {
    fn default() -> Self {
        Self {
            stream_creation_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(4 * 60 * 60),
            launch_timeout: Duration::from_secs(30),
            drain_timeout: Duration::from_secs(10),
            stdin_stall_timeout: Duration::from_secs(60),
        }
    }
}

impl ExecStreamConfig {
    /// 0 の期限と上限超えを拒否する（fail-closed）。
    pub fn validate(&self) -> Result<(), CriError> {
        for (name, d) in [
            ("stream_creation_timeout", self.stream_creation_timeout),
            ("idle_timeout", self.idle_timeout),
            ("launch_timeout", self.launch_timeout),
            ("drain_timeout", self.drain_timeout),
            ("stdin_stall_timeout", self.stdin_stall_timeout),
        ] {
            if d.is_zero() {
                return Err(CriError::invalid_argument(format!(
                    "{name} must be greater than zero"
                )));
            }
        }
        if self.idle_timeout > MAX_IDLE_TIMEOUT {
            return Err(CriError::invalid_argument(
                "idle_timeout exceeds the maximum",
            ));
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

/// 端末のサイズ（resize ストリームで届く）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    /// 桁数。
    pub width: u16,
    /// 行数。
    pub height: u16,
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
/// 本番の実装は無い（REPAIR-3。モジュール doc の「未実装」を参照）。実装が満たす契約:
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
    launcher: Arc<dyn ExecStreamLauncher>,
    config: ExecStreamConfig,
    observer: Arc<dyn ExecObserver>,
    fallback: Arc<dyn StreamHandler>,
}

impl fmt::Debug for ExecStreamHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecStreamHandler")
            .field("config", &self.config)
            .finish()
    }
}

impl ExecStreamHandler {
    /// 設定を検証して作る。`Exec` 以外は 501 を返す既定の fallback へ渡す。
    pub fn new(
        launcher: Arc<dyn ExecStreamLauncher>,
        config: ExecStreamConfig,
    ) -> Result<Self, CriError> {
        config.validate()?;
        Ok(Self {
            launcher,
            config,
            observer: Arc::new(NoopExecObserver),
            fallback: Arc::new(NotImplementedHandler),
        })
    }

    /// 観測口を差し替える（REPAIR-4）。
    pub fn with_observer(mut self, observer: Arc<dyn ExecObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// `Exec` 以外の種別の処理口を差し替える（Attach・PortForward の handler を連ねる）。
    pub fn with_fallback(mut self, fallback: Arc<dyn StreamHandler>) -> Self {
        self.fallback = fallback;
        self
    }

    fn handle_exec(
        &self,
        req: v1::ExecRequest,
        http: Request<Incoming>,
        permit: ConnectionPermit,
    ) -> Response<StreamBody> {
        let headers = http.headers();
        if !header_has_token(headers, &CONNECTION, "upgrade")
            || !header_has_token(headers, &UPGRADE, "spdy/3.1")
        {
            return plain_response(
                StatusCode::BAD_REQUEST,
                "unable to upgrade: missing upgrade headers in request",
            );
        }
        let protocol_header = HeaderName::from_static("x-stream-protocol-version");
        let Some(protocol) = negotiate_protocol(headers, &protocol_header) else {
            return plain_response(
                StatusCode::FORBIDDEN,
                "unable to upgrade: unsupported stream protocol, supported: v4.channel.k8s.io",
            );
        };

        let on_upgrade = hyper::upgrade::on(http);
        let launcher = Arc::clone(&self.launcher);
        let observer = Arc::clone(&self.observer);
        let config = self.config.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let outcome = match on_upgrade.await {
                Ok(upgraded) => {
                    run_exec_session(TokioIo::new(upgraded), &req, launcher.as_ref(), &config).await
                }
                Err(_) => ExecStreamOutcome::PeerClosed,
            };
            observer.observe(outcome, started.elapsed());
            // 枠は IO の寿命まで保持する（#679 の契約。落とすと同時接続数の上限が破れる）。
            drop(permit);
        });

        let mut response = Response::new(StreamBody::empty());
        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
        let h = response.headers_mut();
        h.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        h.insert(UPGRADE, HeaderValue::from_static("SPDY/3.1"));
        h.insert(protocol_header, HeaderValue::from_static(protocol));
        response
    }
}

impl StreamHandler for ExecStreamHandler {
    fn handle(
        &self,
        request: StreamRequest,
        http: Request<Incoming>,
        permit: ConnectionPermit,
    ) -> Pin<Box<dyn Future<Output = Response<StreamBody>> + Send + '_>> {
        match request {
            StreamRequest::Exec(req) => {
                Box::pin(async move { self.handle_exec(req, http, permit) })
            }
            other => self.fallback.handle(other, http, permit),
        }
    }
}

/// 複数値・カンマ区切りのヘッダに `token` が（大文字小文字を区別せず）含まれるか。個数・長さに上限を付けて見る。
fn header_has_token(headers: &HeaderMap, name: &HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .take(MAX_HEADER_VALUES)
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(',').take(MAX_TOKENS_PER_HEADER))
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

/// `X-Stream-Protocol-Version` をクライアントの並び順に見て、対応するものがあれば返す（無ければ `None`）。
pub(crate) fn negotiate_protocol(headers: &HeaderMap, name: &HeaderName) -> Option<&'static str> {
    headers
        .get_all(name)
        .iter()
        .take(MAX_HEADER_VALUES)
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(',').take(MAX_TOKENS_PER_HEADER))
        .map(str::trim)
        .filter(|t| t.len() <= MAX_TOKEN_BYTES)
        .find(|t| *t == EXEC_PROTOCOL_V4)
        .map(|_| EXEC_PROTOCOL_V4)
}

/// 成功の Status（kubelet の `metav1.Status{Status: Success}` の JSON）。
pub(crate) const STATUS_SUCCESS: &str = r#"{"metadata":{},"status":"Success"}"#;

/// 内部エラーの Status。詳細（パス・内部のエラー文）は載せない。
pub(crate) const STATUS_INTERNAL_ERROR: &str = r#"{"metadata":{},"status":"Failure","message":"Internal error occurred: error executing command in container","reason":"InternalError","details":{"causes":[{"message":"error executing command in container"}]},"code":500}"#;

/// 非 0 終了の Status（kubelet の `NonZeroExitCode`・`ExitCode` の cause。client-go が終了コードを読む）。
pub(crate) fn status_non_zero_exit(code: i32) -> String {
    format!(
        r#"{{"metadata":{{}},"status":"Failure","message":"command terminated with non-zero exit code: command terminated with exit code {code}","reason":"NonZeroExitCode","details":{{"causes":[{{"reason":"ExitCode","message":"{code}"}}]}}}}"#
    )
}

/// resize ストリームの 1 行（`{"Width":80,"Height":24}`）を解析する。不正・範囲外・0 は `None`。
pub(crate) fn parse_resize_line(line: &[u8]) -> Option<TerminalSize> {
    let value: serde_json::Value = serde_json::from_slice(line).ok()?;
    let width = u16::try_from(value.get("Width")?.as_u64()?).ok()?;
    let height = u16::try_from(value.get("Height")?.as_u64()?).ok()?;
    if width == 0 || height == 0 {
        return None;
    }
    Some(TerminalSize { width, height })
}

/// 接続の入出力（SPDY のフレームの組み立て・送信キュー・受信バッファ）。
struct Conn<T> {
    io: T,
    rbuf: Vec<u8>,
    wbuf: Vec<u8>,
    wpos: usize,
    dec: HeaderDecompressor,
    enc: FrameEncoder,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Conn<T> {
    fn new(io: T) -> Result<Self, ProtocolError> {
        Ok(Self {
            io,
            rbuf: Vec::new(),
            wbuf: Vec::new(),
            wpos: 0,
            dec: HeaderDecompressor::new(),
            enc: FrameEncoder::new()?,
        })
    }

    fn pending_write(&self) -> usize {
        self.wbuf.len().saturating_sub(self.wpos)
    }

    fn queue(&mut self, frame: &Frame) -> Result<(), ProtocolError> {
        // 送信済み領域を追記前に取り除く。取り除かないと、書き込みが Pending のまま
        // 少量ずつ部分送信が進む場合に wbuf が累積送信量で増え、送信キューの上限
        // （MAX_SEND_QUEUE_BYTES）が未送信量しか数えないため無制限に伸びる。
        if self.wpos >= self.wbuf.len() {
            self.wbuf.clear();
            self.wpos = 0;
        } else if self.wpos > 0 {
            self.wbuf.drain(..self.wpos);
            self.wpos = 0;
        }
        self.enc.encode(frame, &mut self.wbuf)
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let chunk = self.wbuf.get(self.wpos..).unwrap_or(&[]);
            match Pin::new(&mut self.io).poll_write(cx, chunk) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => self.wpos = self.wpos.saturating_add(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.wbuf.clear();
        self.wpos = 0;
        Pin::new(&mut self.io).poll_flush(cx)
    }

    /// 受信バッファから 1 フレームを取り出す。
    fn try_next_frame(&mut self) -> Result<Option<Frame>, ProtocolError> {
        match decode_frame(&self.rbuf, &mut self.dec)? {
            Some((frame, used)) => {
                self.rbuf.drain(..used);
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }

    /// ソケットから読み足す。`Ready(Ok(0))` は EOF。
    fn poll_read_more(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if self.rbuf.len() >= MAX_RECV_BUF_BYTES {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::InvalidData)));
        }
        let mut tmp = [0u8; READ_CHUNK_BYTES];
        let mut buf = ReadBuf::new(&mut tmp);
        match Pin::new(&mut self.io).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => {
                let filled = buf.filled();
                self.rbuf.extend_from_slice(filled);
                Poll::Ready(Ok(filled.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// 次のフレームを待つ。`Ok(None)` は EOF または読み取りエラー（切断）。
    async fn next_frame(&mut self) -> Result<Option<Frame>, ProtocolError> {
        poll_fn(|cx| {
            loop {
                match self.try_next_frame() {
                    Ok(Some(frame)) => return Poll::Ready(Ok(Some(frame))),
                    Ok(None) => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
                match self.poll_read_more(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => return Poll::Ready(Ok(None)),
                    Poll::Ready(Ok(_)) => {}
                }
            }
        })
        .await
    }

    async fn flush(&mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll_flush(cx)).await
    }

    /// GOAWAY を送って期限つきで書き出し、シャットダウンする（失敗は無視。後始末の最善努力）。
    async fn goodbye(&mut self, last_good: u32, status: GoAwayStatus) {
        let _ = self.queue(&Frame::GoAway {
            last_good_stream_id: last_good,
            status,
        });
        let _ = tokio::time::timeout(FINAL_FLUSH_TIMEOUT, async {
            let _ = self.flush().await;
            let _ = poll_fn(|cx| Pin::new(&mut self.io).poll_shutdown(cx)).await;
        })
        .await;
    }
}

/// ストリームが揃う前に届いた stdin の入力（上限つき）と FIN 状態。Relay へ引き継ぐ。
#[derive(Debug, Default)]
struct EarlyStdin {
    buf: Vec<u8>,
    fin: bool,
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

/// 求められるストリームの組（保存済みの要求から決める。通信路の内容は使わない）。
#[derive(Debug, Clone, Copy)]
struct Need {
    stdin: bool,
    stdout: bool,
    stderr: bool,
    resize: bool,
}

impl Need {
    fn from_request(req: &v1::ExecRequest) -> Self {
        Self {
            stdin: req.stdin,
            stdout: req.stdout,
            // tty では stderr ストリームを作らない（kubelet と同じ。tty と stderr の併用は発行時に拒否済み）。
            stderr: req.stderr && !req.tty,
            resize: req.tty,
        }
    }

    fn complete(&self, s: &Streams) -> bool {
        s.error.is_some()
            && (!self.stdin || s.stdin.is_some())
            && (!self.stdout || s.stdout.is_some())
            && (!self.stderr || s.stderr.is_some())
            && (!self.resize || s.resize.is_some())
    }
}

fn header_value<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name == name)
        .map(|h| h.value.as_str())
}

enum StreamWait {
    Ready,
    Closed,
    Protocol,
}

/// ストリームが揃うまで SYN_STREAM を受け付ける（期限は呼び出し側が付ける）。
/// 揃う前に届いた stdin の DATA と FIN は上限つきで `early` に保持する（stdin 以外の DATA は読み捨てる）。
async fn await_streams<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<T>,
    need: Need,
    streams: &mut Streams,
    early: &mut EarlyStdin,
) -> StreamWait {
    while !need.complete(streams) {
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
                let r = accept_stream(conn, need, streams, stream_id, &headers);
                if fin && streams.stdin == Some(stream_id) {
                    early.fin = true;
                }
                r
            }
            Frame::Data {
                stream_id,
                fin,
                payload,
            } if streams.stdin == Some(stream_id) => {
                if early.buf.len().saturating_add(payload.len()) > MAX_EARLY_STDIN_BYTES {
                    return StreamWait::Protocol;
                }
                early.buf.extend_from_slice(&payload);
                early.fin |= fin;
                Ok(())
            }
            Frame::RstStream { stream_id, .. } if streams.stdin == Some(stream_id) => {
                early.fin = true;
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
    need: Need,
    streams: &mut Streams,
    id: StreamId,
    headers: &[Header],
) -> Result<(), ProtocolError> {
    let reject = |conn: &mut Conn<T>, status: RstStatus| {
        conn.queue(&Frame::RstStream {
            stream_id: id,
            status,
        })
    };
    // クライアント側の ID は奇数で単調増加（SPDY/3 §2.3.2）。
    if !id.is_client_initiated() || id.get() <= streams.last_id {
        return reject(conn, RstStatus::ProtocolError);
    }
    let slot = match header_value(headers, "streamtype") {
        Some("error") => Some((&mut streams.error, true)),
        Some("stdin") => Some((&mut streams.stdin, need.stdin)),
        Some("stdout") => Some((&mut streams.stdout, need.stdout)),
        Some("stderr") => Some((&mut streams.stderr, need.stderr)),
        Some("resize") => Some((&mut streams.resize, need.resize)),
        _ => None,
    };
    let Some((slot, wanted)) = slot else {
        return reject(conn, RstStatus::ProtocolError);
    };
    if !wanted || slot.is_some() {
        return reject(conn, RstStatus::RefusedStream);
    }
    *slot = Some(id);
    streams.last_id = id.get();
    conn.queue(&Frame::SynReply {
        stream_id: id,
        fin: false,
        headers: Vec::new(),
    })
}

/// 出力側（stdout / stderr）の読み取り口。
struct Output {
    reader: BoxedRead,
    id: StreamId,
    eof: bool,
    /// 読み取りがエラーで終わった（正常 EOF と区別する）。
    failed: bool,
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
    /// 溜めた stdin が進展しない時間の計測（バッファが空なら `None`）。
    stdin_stall: Option<Pin<Box<Sleep>>>,
    stdin_stall_timeout: Duration,
    stdout: Option<Output>,
    stderr: Option<Output>,
    resizer: Option<Box<dyn TerminalResizer>>,
    resize_line: Vec<u8>,
    resize_discard: bool,
    exit: Option<ExitFuture>,
    exit_result: Option<Result<i32, CriError>>,
    drain: Option<Pin<Box<Sleep>>>,
    drain_timeout: Duration,
    idle: Pin<Box<Sleep>>,
    idle_timeout: Duration,
}

impl<T: AsyncRead + AsyncWrite + Unpin> Relay<T> {
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
                payload,
            } => {
                self.touch();
                if Some(stream_id) == self.streams.stdin {
                    if self.stdin.is_some() {
                        self.stdin_buf.extend_from_slice(&payload);
                    }
                    if fin {
                        self.stdin_fin = true;
                    }
                } else if Some(stream_id) == self.streams.resize {
                    self.feed_resize(&payload);
                }
            }
            Frame::RstStream { stream_id, .. } => {
                if Some(stream_id) == self.streams.stdin {
                    self.stdin_fin = true;
                }
            }
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
                        status: RstStatus::RefusedStream,
                    })
                    .map_err(|_| RelayEnd::Protocol)?;
            }
            // WINDOW_UPDATE・SETTINGS・HEADERS・SYN_REPLY・偶数の PING は読み捨てる（モジュール doc のフロー制御の項）。
            _ => {}
        }
        Ok(())
    }

    /// resize ストリームの DATA を改行区切りで解析する。1 行が上限を超えたら次の改行まで捨てる。
    fn feed_resize(&mut self, payload: &[u8]) {
        for &b in payload {
            if self.resize_discard {
                if b == b'\n' {
                    self.resize_discard = false;
                }
                continue;
            }
            if b == b'\n' {
                if let (Some(size), Some(resizer)) =
                    (parse_resize_line(&self.resize_line), self.resizer.as_mut())
                {
                    let _ = resizer.resize(size);
                }
                self.resize_line.clear();
            } else {
                self.resize_line.push(b);
                if self.resize_line.len() > MAX_RESIZE_LINE_BYTES {
                    self.resize_line.clear();
                    self.resize_discard = true;
                }
            }
        }
    }

    /// 全入力を同時に見て進められるだけ進める。
    fn poll_run(&mut self, cx: &mut Context<'_>) -> Poll<RelayEnd> {
        loop {
            let mut progress = false;

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
                    // プロセス側が閉じた。以後の stdin は捨てる。
                    self.stdin = None;
                    self.stdin_buf.clear();
                    self.stdin_pos = 0;
                    progress = true;
                } else if self.stdin_pos >= self.stdin_buf.len() {
                    self.stdin_buf.clear();
                    self.stdin_pos = 0;
                    if self.stdin_fin && Pin::new(&mut *writer).poll_shutdown(cx).is_ready() {
                        self.stdin = None;
                        progress = true;
                    }
                }
            } else if !self.stdin_buf.is_empty() {
                self.stdin_buf.clear();
                self.stdin_pos = 0;
            }

            // 溜めた stdin が進展しない間はソケットを読めず切断を検知できないため、期限で打ち切る。
            if self.stdin_buf.is_empty() {
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
            while self.stdin_buf.is_empty() && self.conn.pending_write() < MAX_SEND_QUEUE_BYTES {
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
            if self.stdin_buf.is_empty() && self.conn.pending_write() < MAX_SEND_QUEUE_BYTES {
                match self.conn.poll_read_more(cx) {
                    Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => {
                        return Poll::Ready(RelayEnd::PeerClosed);
                    }
                    Poll::Ready(Ok(_)) => progress = true,
                    Poll::Pending => {}
                }
            }

            // stdout / stderr をクライアントへ送る。
            for which in 0..2 {
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

            // プロセスの終了。
            if self.exit_result.is_none()
                && let Some(fut) = self.exit.as_mut()
                && let Poll::Ready(result) = fut.as_mut().poll(cx)
            {
                self.exit_result = Some(result);
                self.exit = None;
                self.drain = Some(Box::pin(tokio::time::sleep(self.drain_timeout)));
                progress = true;
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
        }
    }

    /// 終わり方に応じて通知・GOAWAY・シャットダウンを行い、結末を返す。
    async fn finalize(&mut self, end: RelayEnd) -> ExecStreamOutcome {
        let last = self.streams.last_id;
        match end {
            RelayEnd::PeerClosed => ExecStreamOutcome::PeerClosed,
            RelayEnd::Idle => {
                self.conn.goodbye(last, GoAwayStatus::Ok).await;
                ExecStreamOutcome::IdleTimeout
            }
            RelayEnd::Protocol => {
                self.conn.goodbye(last, GoAwayStatus::ProtocolError).await;
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
                    Some(Ok(0)) => (
                        STATUS_SUCCESS.to_string(),
                        ExecStreamOutcome::Exited { code: 0 },
                    ),
                    Some(Ok(code)) => (
                        status_non_zero_exit(code),
                        ExecStreamOutcome::Exited { code },
                    ),
                    _ => (
                        STATUS_INTERNAL_ERROR.to_string(),
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
                self.close_with_status(&status, &fins).await;
                outcome
            }
        }
    }

    /// 内部エラーの Status（詳細なし）を通知し、読み切れなかった出力にも FIN を付けて閉じる。
    async fn finish_failed(&mut self, outcome: ExecStreamOutcome) -> ExecStreamOutcome {
        let fins: Vec<StreamId> = [self.stdout.as_ref(), self.stderr.as_ref()]
            .into_iter()
            .flatten()
            .filter(|o| !o.eof)
            .map(|o| o.id)
            .collect();
        self.close_with_status(STATUS_INTERNAL_ERROR, &fins).await;
        outcome
    }

    async fn close_with_status(&mut self, status: &str, extra_fins: &[StreamId]) {
        if let Some(error_id) = self.streams.error {
            send_status(
                &mut self.conn,
                error_id,
                status,
                extra_fins,
                self.streams.last_id,
            )
            .await;
        }
    }
}

/// 出力 1 本を読めるだけクライアントへ送る。進展があれば `true`。EOF で FIN を送る。読み取りエラーも FIN を送るが `failed` を立てる。
fn pump_output<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<T>,
    out: &mut Output,
    cx: &mut Context<'_>,
) -> Result<bool, ProtocolError> {
    let mut progressed = false;
    while !out.eof && conn.pending_write() < MAX_SEND_QUEUE_BYTES {
        let mut tmp = [0u8; OUTPUT_CHUNK_BYTES];
        let mut buf = ReadBuf::new(&mut tmp);
        match Pin::new(&mut out.reader).poll_read(cx, &mut buf) {
            Poll::Pending => break,
            Poll::Ready(Ok(())) if !buf.filled().is_empty() => {
                conn.queue(&Frame::Data {
                    stream_id: out.id,
                    fin: false,
                    payload: buf.filled().to_vec(),
                })?;
                progressed = true;
            }
            Poll::Ready(result) => {
                out.eof = true;
                out.failed = result.is_err();
                conn.queue(&Frame::Data {
                    stream_id: out.id,
                    fin: true,
                    payload: Vec::new(),
                })?;
                progressed = true;
            }
        }
    }
    Ok(progressed)
}

/// error ストリームに Status を書いて閉じ、`extra_fins` に FIN を付けて GOAWAY・シャットダウンする。
async fn send_status<T: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<T>,
    error_id: StreamId,
    status: &str,
    extra_fins: &[StreamId],
    last_good: u32,
) {
    let _ = conn.queue(&Frame::Data {
        stream_id: error_id,
        fin: true,
        payload: status.as_bytes().to_vec(),
    });
    for id in extra_fins {
        let _ = conn.queue(&Frame::Data {
            stream_id: *id,
            fin: true,
            payload: Vec::new(),
        });
    }
    conn.goodbye(last_good, GoAwayStatus::Ok).await;
}

/// Upgrade 後の IO 1 本分の Exec セッションを最後まで駆動する。
///
/// `req` は発行時に保存した要求（通信路の内容から組み立てない）。`launcher` はストリームが揃った後にだけ呼ぶ。
pub(crate) async fn run_exec_session<T: AsyncRead + AsyncWrite + Unpin>(
    io: T,
    req: &v1::ExecRequest,
    launcher: &dyn ExecStreamLauncher,
    config: &ExecStreamConfig,
) -> ExecStreamOutcome {
    let Ok(mut conn) = Conn::new(io) else {
        return ExecStreamOutcome::ProtocolError;
    };
    let need = Need::from_request(req);
    let mut streams = Streams::default();
    let mut early = EarlyStdin::default();

    // 1. 必要なストリームが揃うまで待つ（期限つき）。
    let waited = tokio::time::timeout(
        config.stream_creation_timeout,
        await_streams(&mut conn, need, &mut streams, &mut early),
    )
    .await;
    match waited {
        Err(_) => {
            conn.goodbye(streams.last_id, GoAwayStatus::Ok).await;
            return ExecStreamOutcome::StreamCreationTimeout;
        }
        Ok(StreamWait::Closed) => return ExecStreamOutcome::PeerClosed,
        Ok(StreamWait::Protocol) => {
            conn.goodbye(streams.last_id, GoAwayStatus::ProtocolError)
                .await;
            return ExecStreamOutcome::ProtocolError;
        }
        Ok(StreamWait::Ready) => {}
    }
    let Some(error_id) = streams.error else {
        return ExecStreamOutcome::ProtocolError;
    };

    // 2. 起動（期限つき）。
    let launch = ExecLaunch {
        container_id: req.container_id.clone(),
        cmd: req.cmd.clone(),
        tty: req.tty,
        stdin: need.stdin,
        stdout: need.stdout,
        stderr: need.stderr,
    };
    let session = match tokio::time::timeout(config.launch_timeout, launcher.launch(launch)).await {
        Ok(Ok(session)) if session_matches(&session, need) => session,
        _ => {
            send_status(
                &mut conn,
                error_id,
                STATUS_INTERNAL_ERROR,
                &[],
                streams.last_id,
            )
            .await;
            return ExecStreamOutcome::LaunchFailed;
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
    let output = |reader: Option<BoxedRead>, id: Option<StreamId>| match (reader, id) {
        (Some(reader), Some(id)) => Some(Output {
            reader,
            id,
            eof: false,
            failed: false,
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
        stdin_stall: None,
        stdin_stall_timeout: config.stdin_stall_timeout,
        stdout: output(stdout, streams.stdout),
        stderr: output(stderr, streams.stderr),
        resizer: resize,
        resize_line: Vec::new(),
        resize_discard: false,
        exit: Some(exit),
        exit_result: None,
        drain: None,
        drain_timeout: config.drain_timeout,
        idle: Box::pin(tokio::time::sleep(config.idle_timeout)),
        idle_timeout: config.idle_timeout,
    };
    let end = poll_fn(|cx| relay.poll_run(cx)).await;
    // relay を drop すると ExecSession 由来の資源が解放され、プロセスが止まる（契約）。
    relay.finalize(end).await
}

/// launcher が要求どおりの stdio を返したか。
fn session_matches(session: &ExecSession, need: Need) -> bool {
    session.stdin.is_some() == need.stdin
        && session.stdout.is_some() == need.stdout
        && session.stderr.is_some() == need.stderr
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
        })
        .expect("conn");
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for _ in 0..200 {
            conn.queue(&Frame::Data {
                stream_id: StreamId::new(1).expect("stream id"),
                fin: false,
                payload: vec![b'x'; 16],
            })
            .expect("queue");
            // 追記直後は送信済み領域が残らない（wbuf の実長 = 未送信量）。
            assert_eq!(conn.wpos, 0);
            assert_eq!(conn.wbuf.len(), conn.pending_write());
            let _ = conn.poll_flush(&mut cx);
        }
    }

    fn headers_with(values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for v in values {
            map.append(
                HeaderName::from_static("x-stream-protocol-version"),
                HeaderValue::from_str(v).expect("header value"),
            );
        }
        map
    }

    fn negotiate(values: &[&str]) -> Option<&'static str> {
        negotiate_protocol(
            &headers_with(values),
            &HeaderName::from_static("x-stream-protocol-version"),
        )
    }

    /// CRI-6: v4 を含めば採用する。並びやカンマ区切り、複数ヘッダでも同じ。
    #[test]
    fn cri6_negotiate_prefers_v4() {
        assert_eq!(negotiate(&["v4.channel.k8s.io"]), Some(EXEC_PROTOCOL_V4));
        assert_eq!(
            negotiate(&["v5.channel.k8s.io, v4.channel.k8s.io"]),
            Some(EXEC_PROTOCOL_V4)
        );
        assert_eq!(
            negotiate(&["v3.channel.k8s.io", "v4.channel.k8s.io"]),
            Some(EXEC_PROTOCOL_V4)
        );
        assert_eq!(negotiate(&[" v4.channel.k8s.io "]), Some(EXEC_PROTOCOL_V4));
    }

    /// CRI-6: v4 が無ければ `None`（v1〜v3・v5・無関係な値・ヘッダ無し）。
    #[test]
    fn cri6_negotiate_rejects_without_v4() {
        assert_eq!(negotiate(&[]), None);
        assert_eq!(negotiate(&["v3.channel.k8s.io"]), None);
        assert_eq!(negotiate(&["v1.channel.k8s.io, channel.k8s.io"]), None);
        assert_eq!(negotiate(&["v5.channel.k8s.io"]), None);
        assert_eq!(negotiate(&["V4.CHANNEL.K8S.IO"]), None);
    }

    /// CRI-6・REPAIR-5: 要素数の上限を超えた先にある v4 は見ない。
    #[test]
    fn cri6_negotiate_bounds_token_count() {
        let many = format!("{}v4.channel.k8s.io", "x,".repeat(MAX_TOKENS_PER_HEADER));
        assert_eq!(negotiate(&[&many]), None);
    }

    /// CRI-6: Status の JSON は kubelet と同じ文字列になる。
    #[test]
    fn cri6_status_json_exact() {
        assert_eq!(STATUS_SUCCESS, r#"{"metadata":{},"status":"Success"}"#);
        assert_eq!(
            status_non_zero_exit(3),
            r#"{"metadata":{},"status":"Failure","message":"command terminated with non-zero exit code: command terminated with exit code 3","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"3"}]}}"#
        );
        for json in [
            STATUS_SUCCESS,
            STATUS_INTERNAL_ERROR,
            &status_non_zero_exit(-1),
        ] {
            let v: serde_json::Value = serde_json::from_str(json).expect("valid json");
            assert!(v.get("status").is_some());
        }
        let v: serde_json::Value = serde_json::from_str(STATUS_INTERNAL_ERROR).expect("json");
        assert_eq!(v["reason"], "InternalError");
        assert_eq!(v["code"], 500);
    }

    /// CRI-6: resize の行の解析（正常・不正な JSON・範囲外・0・欠落）。
    #[test]
    fn cri6_parse_resize_line() {
        assert_eq!(
            parse_resize_line(br#"{"Width":80,"Height":24}"#),
            Some(TerminalSize {
                width: 80,
                height: 24
            })
        );
        assert_eq!(parse_resize_line(b"not json"), None);
        assert_eq!(parse_resize_line(br#"{"Width":70000,"Height":24}"#), None);
        assert_eq!(parse_resize_line(br#"{"Width":0,"Height":24}"#), None);
        assert_eq!(parse_resize_line(br#"{"Width":80}"#), None);
        assert_eq!(parse_resize_line(br#"{"Width":-1,"Height":2}"#), None);
    }

    /// CRI-6・REPAIR-5: 設定の検証（0 と上限超えを拒否）。
    #[test]
    fn cri6_exec_config_validate_bounds() {
        let base = ExecStreamConfig::default();
        assert!(base.validate().is_ok());
        let zero = Duration::ZERO;
        assert!(
            ExecStreamConfig {
                stream_creation_timeout: zero,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            ExecStreamConfig {
                idle_timeout: MAX_IDLE_TIMEOUT,
                ..base.clone()
            }
            .validate()
            .is_ok()
        );
        assert!(
            ExecStreamConfig {
                idle_timeout: MAX_IDLE_TIMEOUT + Duration::from_secs(1),
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            ExecStreamConfig {
                drain_timeout: zero,
                ..base.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            ExecStreamConfig {
                launch_timeout: zero,
                ..base
            }
            .validate()
            .is_err()
        );
    }

    /// CRI-6: tty のとき stderr ストリームは求めず、resize を求める。
    #[test]
    fn cri6_need_from_request() {
        let req = v1::ExecRequest {
            container_id: "c".into(),
            cmd: vec!["sh".into()],
            tty: true,
            stdin: true,
            stdout: true,
            stderr: true,
        };
        let need = Need::from_request(&req);
        assert!(need.stdin && need.stdout && need.resize);
        assert!(!need.stderr);
    }
}
