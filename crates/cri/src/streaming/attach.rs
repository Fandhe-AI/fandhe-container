//! Attach のストリーミング（CRI-6・TASK-63.3・#681。設計記録は `docs/design/cri-streaming-server.md`）。
//!
//! `RuntimeService.Attach` が返した URL（`/attach/<token>`）へ kubelet / crictl が接続したときの処理を持つ。
//! [`AttachHandler`] が [`super::StreamHandler`] として HTTP の Upgrade（SPDY/3.1 + remotecommand の交渉）を行い、
//! 101 の後は 1 接続 1 タスクのセッション（`run_session`）が SPDY のフレームと、実行中コンテナの
//! stdin / stdout / stderr（[`AttachBackend`] が供給する非同期 IO）を中継する。呼び出し元は
//! `StreamingServer`（`bind_with_handler` に [`super::StreamDispatcher`] 経由で渡す）。
//!
//! ## 未実装（REPAIR-3）: 本番の [`AttachBackend`]
//!
//! 実行中コンテナの stdio を渡す経路は core の `ContainerRuntime` にも supervisor にも無い（CRI-6・PLUG-1・SUP 系の
//! 設計判断が要る。`docs/design/cri-streaming-server.md`「Attach の本番 backend」）。本モジュールは注入点だけを持ち、
//! backend を注入しない構成では Attach は結線されず（`StreamHandler::wiring`）、RPC は URL を返さず `UNIMPLEMENTED` になる（#3753）。実装済みを装わない。
//!
//! ## セッションの構造
//!
//! tokio の `sync`・`io-util` feature を使わないため、チャネルもタスク分割も使わず、1 つのタスクが
//! `poll_fn` で SPDY の入出力・backend の stdio・期限を多重化する（`Session::poll_step`）。各 IO は
//! 滞留に上限があり（`OUT_HIGH_WATER`・`STDIN_PENDING_CAP`）、上限に達したら読むのをやめて背圧にする。
//!
//! 段階: ストリームの作成（`stream_creation_timeout`）→ backend の接続（`backend_timeout`）→ 中継
//! （`stream_idle_timeout`）→ コンテナ終了後の出力の流し切り（`drain_timeout`）→ 終了（Status・GOAWAY を
//! `close_timeout` 内に送る）。どの終了でも backend の stdio・終了通知は破棄（drop）して資源を解放する。

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::{Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use tonic::Code;

use super::remotecommand::{
    HEADER_STREAM_TYPE, Protocol, ResizeParser, SessionLimits, StreamOptions, StreamType,
    TerminalSize, negotiate, status_failure, status_success, upgrade_response,
};
use super::spdy::{
    Frame, FrameDecoder, FrameEncoder, Headers, MAX_OUTGOING_DATA, StreamId, goaway_status,
    rst_status,
};
use super::{
    ConnectionPermit, StreamBody, StreamHandler, StreamKind, StreamRequest, StreamWiring,
    plain_response,
};
use crate::error::CriError;
use crate::instrument::{CriOpKind, CriOpRecorder, CriOpSample, NoopCriOpRecorder};

/// 消費済みの先頭領域をこの大きさ以上溜めたら詰め直す（部分書き込みが続いても確保量を有界にする）。
const COMPACT_THRESHOLD: usize = 32 * 1024;
/// 1 回の IO 読み取りの大きさ。
const IO_CHUNK: usize = 16 * 1024;
/// 出力バッファがこれを超えている間は、backend の出力とクライアントの入力を読まない（背圧）。
const OUT_HIGH_WATER: usize = 128 * 1024;
/// backend の stdin へ未書き込みの滞留がこれ以上の間は、クライアントの入力を読まない（背圧）。
const STDIN_PENDING_CAP: usize = 128 * 1024;
/// 1 セッションで受け付けるストリーム数の上限（error・stdin・stdout・stderr・resize の 5 本）。
const MAX_STREAMS: usize = 5;
/// 1 回の `poll_step` で進捗があっても続ける最大反復（他のタスクへ譲る）。
const MAX_STEP_ITERATIONS: usize = 32;

/// backend に渡す接続先と要求（検証済みの値のみ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachTarget {
    /// 対象のコンテナ ID（`AttachRequest` の値。ログ・エラーに出さない）。
    pub container_id: String,
    /// stdin を渡すか。
    pub stdin: bool,
    /// stdout を受けるか。
    pub stdout: bool,
    /// stderr を受けるか（tty のときは常に false）。
    pub stderr: bool,
    /// tty か。
    pub tty: bool,
}

/// 実行中コンテナの stdio への接続。backend が [`AttachBackend::attach`] で返す。
///
/// セッションが終わると全フィールドが drop される。backend はそれを資源解放の契機にすること。
pub struct AttachSession {
    /// コンテナの stdin への書き口。書き込みはバッファしないこと（`poll_write` の成功 = 渡し終えた）。
    pub stdin: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    /// コンテナの stdout の読み口。EOF は出力の終端。
    pub stdout: Option<Box<dyn AsyncRead + Send + Unpin>>,
    /// コンテナの stderr の読み口（tty では None）。
    pub stderr: Option<Box<dyn AsyncRead + Send + Unpin>>,
    /// tty の寸法変更の受け口（tty でなければ None）。同期的に短時間で返すこと。
    pub resize: Option<Box<dyn FnMut(TerminalSize) + Send>>,
    /// コンテナの終了で完了する future。完了後は残りの出力を `drain_timeout` まで流して終える。
    pub exited: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl std::fmt::Debug for AttachSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachSession")
            .field("stdin", &self.stdin.is_some())
            .field("stdout", &self.stdout.is_some())
            .field("stderr", &self.stderr.is_some())
            .finish()
    }
}

/// 実行中コンテナの stdio をセッションへ渡す口（拡張点。本番の実装は未接続。モジュール doc の REPAIR-3 を参照）。
///
/// 返す future は `'static`（実装は必要な状態を clone して move する）。コンテナが running でなければ
/// `FAILED_PRECONDITION`、未知なら `NOT_FOUND` を返す（RPC 時の検証と接続時の間のレースをここで再確認する）。
/// 期限はセッション側が `backend_timeout` で打ち切る。
pub trait AttachBackend: Send + Sync + 'static {
    /// 接続先の stdio を開く。
    fn attach(
        &self,
        target: AttachTarget,
    ) -> Pin<Box<dyn Future<Output = Result<AttachSession, CriError>> + Send + 'static>>;
}

/// `Attach` の URL を処理する [`StreamHandler`]（Upgrade → セッション）。
pub struct AttachHandler {
    backend: Arc<dyn AttachBackend>,
    limits: SessionLimits,
    recorder: Arc<dyn CriOpRecorder>,
}

impl std::fmt::Debug for AttachHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachHandler")
            .field("limits", &self.limits)
            .finish()
    }
}

impl AttachHandler {
    /// backend と期限を指定して作る。期限は `StreamingConfig::session_limits()` の値を渡す。
    pub fn new(backend: Arc<dyn AttachBackend>, limits: SessionLimits) -> Result<Self, CriError> {
        limits.validate()?;
        Ok(Self {
            backend,
            limits,
            recorder: Arc::new(NoopCriOpRecorder),
        })
    }

    /// セッションの結果・所要時間・読み書きの成否の記録先を指定する（REPAIR-4）。既定は記録しない。
    pub fn with_recorder(mut self, recorder: Arc<dyn CriOpRecorder>) -> Self {
        self.recorder = recorder;
        self
    }
}

impl StreamHandler for AttachHandler {
    fn wiring(&self) -> StreamWiring {
        StreamWiring::only(StreamKind::Attach)
    }

    fn handle(
        &self,
        request: StreamRequest,
        http: hyper::Request<hyper::body::Incoming>,
        permit: ConnectionPermit,
    ) -> Pin<Box<dyn Future<Output = Response<StreamBody>> + Send + '_>> {
        Box::pin(async move {
            let StreamRequest::Attach(req) = request else {
                // 振り分けの誤り。到達しないが、別種別の要求を処理せず固定の応答にする。
                return plain_response(StatusCode::INTERNAL_SERVER_ERROR, "internal error");
            };
            let protocol = match negotiate(http.headers()) {
                Ok(protocol) => protocol,
                Err(e) => return e.into_response(),
            };
            let options = StreamOptions::new(req.stdin, req.stdout, req.stderr, req.tty);
            let target = AttachTarget {
                container_id: req.container_id,
                stdin: options.stdin,
                stdout: options.stdout,
                stderr: options.stderr,
                tty: options.tty,
            };
            let on_upgrade = hyper::upgrade::on(http);
            let backend = Arc::clone(&self.backend);
            let limits = self.limits;
            let recorder = Arc::clone(&self.recorder);
            tokio::spawn(async move {
                // 同時接続数の枠は IO の寿命まで保持する（`StreamHandler::handle` の契約）。
                let _permit = permit;
                let Ok(upgraded) = on_upgrade.await else {
                    return;
                };
                // 終わり方・所要時間・読み書きの成否は run_session が recorder へ記録する。
                let _end = run_session(
                    TokioIo::new(upgraded),
                    protocol,
                    options,
                    target,
                    backend,
                    limits,
                    recorder,
                )
                .await;
            });
            upgrade_response(protocol)
        })
    }
}

/// セッションの終わり方（試験・観測用。トークン・ID は含めない。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEnd {
    /// コンテナの終了で正常に終えた（Status を書いた）。
    Finished,
    /// クライアントが切断した（EOF または GOAWAY）。
    ClientClosed,
    /// ストリームの作成期限を超えた。
    CreationTimeout,
    /// idle の期限を超えた。
    IdleTimeout,
    /// SPDY の違反。
    ProtocolError,
    /// backend への接続に失敗した（Status に失敗を書いた）。
    BackendFailed,
    /// 下位の IO の失敗。
    IoError,
}

/// ストリーム ID の記録（種別ごとに最大 1 本）。
#[derive(Debug, Default)]
struct Opened {
    error: Option<StreamId>,
    stdin: Option<StreamId>,
    stdout: Option<StreamId>,
    stderr: Option<StreamId>,
    resize: Option<StreamId>,
}

impl Opened {
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

    fn kind_of(&self, id: StreamId) -> Option<StreamType> {
        [
            StreamType::Error,
            StreamType::Stdin,
            StreamType::Stdout,
            StreamType::Stderr,
            StreamType::Resize,
        ]
        .into_iter()
        .find(|kind| self.get(*kind) == Some(id))
    }

    fn count(&self) -> usize {
        [
            self.error,
            self.stdin,
            self.stdout,
            self.stderr,
            self.resize,
        ]
        .iter()
        .filter(|s| s.is_some())
        .count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// クライアントが必要なストリームを開くのを待っている。
    Gathering,
    /// backend の接続を待っている。
    Starting,
    /// 中継中。
    Running,
    /// コンテナが終了し、残りの出力を流している。
    Draining,
}

/// セッション内の読み書きの成否（記録用。値のみで内容は持たない）。
#[derive(Debug, Default, Clone, Copy)]
struct IoStats {
    read_ok: bool,
    read_failed: bool,
    write_ok: bool,
    write_failed: bool,
}

type BackendFuture = Pin<Box<dyn Future<Output = Result<AttachSession, CriError>> + Send>>;

struct Session<IO> {
    io: IO,
    decoder: FrameDecoder,
    encoder: FrameEncoder,
    out: Vec<u8>,
    out_pos: usize,
    read_buf: Box<[u8]>,
    scratch: Box<[u8]>,
    protocol: Protocol,
    options: StreamOptions,
    expected: Vec<StreamType>,
    target: AttachTarget,
    backend: Arc<dyn AttachBackend>,
    limits: SessionLimits,
    opened: Opened,
    last_stream_id: u32,
    phase: Phase,
    starting: Option<BackendFuture>,
    failure: Option<CriError>,
    stdin_writer: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    stdin_pending: Vec<u8>,
    stdin_pos: usize,
    stdin_fin: bool,
    /// RST_STREAM を受けたストリーム。以後そのストリームへは何も送らない。
    reset_ids: Vec<StreamId>,
    /// backend の出力の読み取りが失敗した（出力欠損。Success Status を返さない）。
    output_failed: bool,
    started: Instant,
    stats: IoStats,
    stdout_reader: Option<Box<dyn AsyncRead + Send + Unpin>>,
    stderr_reader: Option<Box<dyn AsyncRead + Send + Unpin>>,
    stdout_fin_sent: bool,
    stderr_fin_sent: bool,
    resize_fn: Option<Box<dyn FnMut(TerminalSize) + Send>>,
    pending_resize: Option<TerminalSize>,
    resize_parser: ResizeParser,
    exited: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    creation: Pin<Box<Sleep>>,
    idle: Pin<Box<Sleep>>,
    drain: Option<Pin<Box<Sleep>>>,
}

/// 1 接続のセッションを最後まで実行する。終わり方を返す。
///
/// `io` は Upgrade 後の IO。戻る時点で Status・GOAWAY の送出を試み（`close_timeout`）、backend の資源を解放済み。
pub(super) async fn run_session<IO>(
    io: IO,
    protocol: Protocol,
    options: StreamOptions,
    target: AttachTarget,
    backend: Arc<dyn AttachBackend>,
    limits: SessionLimits,
    recorder: Arc<dyn CriOpRecorder>,
) -> SessionEnd
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut session = Session::new(io, protocol, options, target, backend, limits);
    let end = poll_fn(|cx| session.poll_step(cx)).await;
    session.finish(end).await;
    session.record(end, recorder.as_ref());
    end
}

/// 現在から `after` 後の期限。検証済みの値では溢れないが、溢れても panic せず十分先の時刻にする。
fn deadline_after(after: std::time::Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(after)
        .or_else(|| now.checked_add(std::time::Duration::from_secs(86_400 * 365)))
        .unwrap_or(now)
}

impl<IO> Session<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    fn new(
        io: IO,
        protocol: Protocol,
        options: StreamOptions,
        target: AttachTarget,
        backend: Arc<dyn AttachBackend>,
        limits: SessionLimits,
    ) -> Self {
        let now = Instant::now();
        Self {
            io,
            decoder: FrameDecoder::new(),
            encoder: FrameEncoder::new(),
            out: Vec::new(),
            out_pos: 0,
            read_buf: vec![0u8; IO_CHUNK].into_boxed_slice(),
            scratch: vec![0u8; IO_CHUNK].into_boxed_slice(),
            expected: options.expected(protocol),
            protocol,
            options,
            target,
            backend,
            limits,
            opened: Opened::default(),
            last_stream_id: 0,
            phase: Phase::Gathering,
            starting: None,
            failure: None,
            stdin_writer: None,
            stdin_pending: Vec::new(),
            stdin_pos: 0,
            stdin_fin: false,
            reset_ids: Vec::new(),
            output_failed: false,
            started: now,
            stats: IoStats::default(),
            stdout_reader: None,
            stderr_reader: None,
            stdout_fin_sent: false,
            stderr_fin_sent: false,
            resize_fn: None,
            pending_resize: None,
            resize_parser: ResizeParser::new(),
            exited: None,
            creation: Box::pin(tokio::time::sleep_until(
                now + limits.stream_creation_timeout,
            )),
            idle: Box::pin(tokio::time::sleep_until(now + limits.stream_idle_timeout)),
            drain: None,
        }
    }

    /// セッションの結果・所要時間と、読み書きの成否を記録先へ渡す（REPAIR-4。ID・トークン・内容は渡さない）。
    fn record(&self, end: SessionEnd, recorder: &dyn CriOpRecorder) {
        let latency = self.started.elapsed();
        let code = match end {
            SessionEnd::Finished if self.output_failed => Code::Internal,
            SessionEnd::Finished => Code::Ok,
            SessionEnd::ClientClosed => Code::Cancelled,
            SessionEnd::CreationTimeout | SessionEnd::IdleTimeout => Code::DeadlineExceeded,
            SessionEnd::ProtocolError => Code::InvalidArgument,
            SessionEnd::BackendFailed | SessionEnd::IoError => Code::Unavailable,
        };
        recorder.record_cri_op(&CriOpSample::new(CriOpKind::AttachSession, code, latency));
        for (kind, ok, failed) in [
            (
                CriOpKind::AttachStreamRead,
                self.stats.read_ok,
                self.stats.read_failed,
            ),
            (
                CriOpKind::AttachStreamWrite,
                self.stats.write_ok,
                self.stats.write_failed,
            ),
        ] {
            if failed {
                recorder.record_cri_op(&CriOpSample::new(kind, Code::Unavailable, latency));
            } else if ok {
                recorder.record_cri_op(&CriOpSample::new(kind, Code::Ok, latency));
            }
        }
    }

    fn is_reset(&self, id: StreamId) -> bool {
        self.reset_ids.contains(&id)
    }

    fn touch(&mut self) {
        let deadline = deadline_after(self.limits.stream_idle_timeout);
        self.idle.as_mut().reset(deadline);
    }

    fn out_len(&self) -> usize {
        self.out.len().saturating_sub(self.out_pos)
    }

    /// フレームを出力バッファへ積む。符号化の失敗は内部の誤りとして呼び出し側が終了にする。
    fn queue(&mut self, frame: &Frame) -> bool {
        self.encoder.encode(frame, &mut self.out).is_ok()
    }

    /// DATA を `MAX_OUTGOING_DATA` ごとに分けて積む。
    fn queue_data(&mut self, stream_id: StreamId, data: &[u8], fin: bool) -> bool {
        // RST_STREAM 済みのストリームへは送らない。
        if self.is_reset(stream_id) {
            return true;
        }
        if data.is_empty() {
            return !fin
                || self.queue(&Frame::Data {
                    stream_id,
                    fin: true,
                    data: Vec::new(),
                });
        }
        let mut chunks = data.chunks(MAX_OUTGOING_DATA).peekable();
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            if !self.queue(&Frame::Data {
                stream_id,
                fin: fin && last,
                data: chunk.to_vec(),
            }) {
                return false;
            }
        }
        true
    }

    /// 出力バッファを下位 IO へ書く。進捗があれば `Ok(true)`。
    fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Result<bool, ()> {
        let mut progress = false;
        while self.out_pos < self.out.len() {
            let pending = self.out.get(self.out_pos..).unwrap_or(&[]);
            match Pin::new(&mut self.io).poll_write(cx, pending) {
                Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => return Err(()),
                Poll::Ready(Ok(n)) => {
                    self.out_pos += n;
                    progress = true;
                    // 消費済みの先頭領域を溜め続けない（部分書き込みが続いても確保量を有界にする）。
                    if self.out_pos >= COMPACT_THRESHOLD {
                        self.out.drain(..self.out_pos);
                        self.out_pos = 0;
                    }
                }
                Poll::Pending => return Ok(progress),
            }
        }
        if !self.out.is_empty() {
            self.out.clear();
            self.out_pos = 0;
        }
        match Pin::new(&mut self.io).poll_flush(cx) {
            Poll::Ready(Err(_)) => Err(()),
            _ => Ok(progress),
        }
    }

    fn poll_step(&mut self, cx: &mut Context<'_>) -> Poll<SessionEnd> {
        for _ in 0..MAX_STEP_ITERATIONS {
            let mut progress = false;

            match self.poll_flush_out(cx) {
                Err(()) => return Poll::Ready(SessionEnd::IoError),
                Ok(true) => {
                    progress = true;
                    self.touch();
                }
                Ok(false) => {}
            }

            // 期限。
            if self.phase == Phase::Gathering && self.creation.as_mut().poll(cx).is_ready() {
                return Poll::Ready(SessionEnd::CreationTimeout);
            }
            if self.idle.as_mut().poll(cx).is_ready() {
                return Poll::Ready(SessionEnd::IdleTimeout);
            }
            if let Some(drain) = self.drain.as_mut()
                && drain.as_mut().poll(cx).is_ready()
            {
                // EOF 未到達のまま打ち切った出力は欠損なので、Success Status にしない。
                if self.stdout_reader.is_some() || self.stderr_reader.is_some() {
                    self.output_failed = true;
                }
                return Poll::Ready(SessionEnd::Finished);
            }

            // backend の接続。
            if let Some(fut) = self.starting.as_mut()
                && let Poll::Ready(result) = fut.as_mut().poll(cx)
            {
                self.starting = None;
                progress = true;
                match result {
                    Ok(session) => {
                        if !self.start_relay(session) {
                            return Poll::Ready(SessionEnd::ProtocolError);
                        }
                    }
                    Err(e) => {
                        self.failure = Some(e);
                        return Poll::Ready(SessionEnd::BackendFailed);
                    }
                }
            }

            // クライアントからの入力。
            if self.out_len() < OUT_HIGH_WATER * 2
                && self.stdin_pending.len().saturating_sub(self.stdin_pos) < STDIN_PENDING_CAP
            {
                let mut rb = ReadBuf::new(&mut self.read_buf);
                match Pin::new(&mut self.io).poll_read(cx, &mut rb) {
                    Poll::Ready(Err(_)) => return Poll::Ready(SessionEnd::IoError),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(SessionEnd::ClientClosed);
                        }
                        let chunk = rb.filled().to_vec();
                        self.decoder.extend(&chunk);
                        progress = true;
                        self.touch();
                        if let Some(end) = self.drain_frames() {
                            return Poll::Ready(end);
                        }
                    }
                    Poll::Pending => {}
                }
            }

            // backend の stdin へ。
            progress |= self.poll_stdin(cx);

            // backend の出力をクライアントへ。
            match self.poll_outputs(cx) {
                Ok(p) => progress |= p,
                Err(end) => return Poll::Ready(end),
            }

            // コンテナの終了。
            if let Some(fut) = self.exited.as_mut()
                && fut.as_mut().poll(cx).is_ready()
            {
                self.exited = None;
                self.phase = Phase::Draining;
                self.stdin_writer = None;
                self.stdin_pending.clear();
                self.stdin_pos = 0;
                self.drain = Some(Box::pin(tokio::time::sleep_until(deadline_after(
                    self.limits.drain_timeout,
                ))));
                progress = true;
            }
            if self.phase == Phase::Draining
                && self.stdout_reader.is_none()
                && self.stderr_reader.is_none()
            {
                return Poll::Ready(SessionEnd::Finished);
            }

            if !progress {
                return Poll::Pending;
            }
        }
        // 進捗が続く間は他のタスクへ譲る。
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// 溜まったフレームを全て処理する。セッションを終えるべきときは終わり方を返す。
    fn drain_frames(&mut self) -> Option<SessionEnd> {
        loop {
            match self.decoder.next_frame() {
                Ok(None) => return None,
                Ok(Some(frame)) => {
                    if let Some(end) = self.handle_frame(frame) {
                        return Some(end);
                    }
                }
                Err(_) => return Some(SessionEnd::ProtocolError),
            }
        }
    }

    fn handle_frame(&mut self, frame: Frame) -> Option<SessionEnd> {
        match frame {
            Frame::SynStream {
                stream_id,
                fin,
                headers,
                ..
            } => self.open_stream(stream_id, fin, &headers),
            Frame::Data {
                stream_id,
                fin,
                data,
            } => self.client_data(stream_id, fin, &data),
            Frame::RstStream { stream_id, .. } => {
                // 開設済み（最大 5 本）のストリームだけ記録し、未知の ID は蓄積しない。
                if self.opened.kind_of(stream_id).is_some() && !self.reset_ids.contains(&stream_id)
                {
                    self.reset_ids.push(stream_id);
                }
                match self.opened.kind_of(stream_id) {
                    Some(StreamType::Stdin) => {
                        // 未転送の入力と書き口を解放する。
                        self.stdin_fin = true;
                        self.stdin_pending.clear();
                        self.stdin_pos = 0;
                        self.stdin_writer = None;
                    }
                    Some(StreamType::Stdout) => self.stdout_reader = None,
                    Some(StreamType::Stderr) => self.stderr_reader = None,
                    Some(StreamType::Resize) => {
                        self.resize_fn = None;
                        self.pending_resize = None;
                    }
                    _ => {}
                }
                None
            }
            // クライアント起点の PING は奇数 ID。そのまま返す（draft）。
            Frame::Ping { id } if id & 1 == 1 => {
                (!self.queue(&Frame::Ping { id })).then_some(SessionEnd::ProtocolError)
            }
            Frame::GoAway { .. } => Some(SessionEnd::ClientClosed),
            // flow control は強制しない（`spdy` のモジュール doc）。SETTINGS・WINDOW_UPDATE 等は受理して無視する。
            Frame::Ping { .. }
            | Frame::Settings { .. }
            | Frame::WindowUpdate { .. }
            | Frame::Headers { .. }
            | Frame::SynReply { .. }
            | Frame::Unknown { .. } => None,
        }
    }

    fn reset_stream(&mut self, stream_id: StreamId, status: u32) -> Option<SessionEnd> {
        (!self.queue(&Frame::RstStream { stream_id, status })).then_some(SessionEnd::ProtocolError)
    }

    fn open_stream(
        &mut self,
        stream_id: StreamId,
        fin: bool,
        headers: &Headers,
    ) -> Option<SessionEnd> {
        let id = stream_id.get();
        // クライアント起点のストリームは奇数で、単調に増える。
        if id & 1 == 0 || id <= self.last_stream_id {
            return self.reset_stream(stream_id, rst_status::PROTOCOL_ERROR);
        }
        self.last_stream_id = id;
        if self.opened.count() >= MAX_STREAMS {
            return self.reset_stream(stream_id, rst_status::REFUSED_STREAM);
        }
        let Some(kind) = headers.get(HEADER_STREAM_TYPE).and_then(StreamType::parse) else {
            return self.reset_stream(stream_id, rst_status::REFUSED_STREAM);
        };
        if !self.expected.contains(&kind) {
            return self.reset_stream(stream_id, rst_status::REFUSED_STREAM);
        }
        if self.opened.get(kind).is_some() {
            return self.reset_stream(stream_id, rst_status::STREAM_IN_USE);
        }
        *self.opened.slot(kind) = Some(stream_id);
        if !self.queue(&Frame::SynReply {
            stream_id,
            fin: false,
            headers: Headers::new(),
        }) {
            return Some(SessionEnd::ProtocolError);
        }
        if fin && kind == StreamType::Stdin {
            self.stdin_fin = true;
        }
        if self.phase == Phase::Gathering
            && self.expected.iter().all(|k| self.opened.get(*k).is_some())
        {
            self.phase = Phase::Starting;
            let fut = self.backend.attach(self.target.clone());
            let timeout = self.limits.backend_timeout;
            self.starting = Some(Box::pin(async move {
                match tokio::time::timeout(timeout, fut).await {
                    Ok(result) => result,
                    Err(_) => Err(CriError::timeout("attach backend timed out")),
                }
            }));
        }
        None
    }

    fn client_data(&mut self, stream_id: StreamId, fin: bool, data: &[u8]) -> Option<SessionEnd> {
        // RST_STREAM 済みのストリームの DATA は backend へ渡さない。
        if self.is_reset(stream_id) {
            return None;
        }
        match self.opened.kind_of(stream_id) {
            Some(StreamType::Stdin) => {
                // FIN 済みの送信方向への後続 DATA は拒否する（FIN フレーム自身のペイロードは下で転送する）。
                if self.stdin_fin {
                    self.stdin_pending.clear();
                    return self.reset_stream(stream_id, rst_status::STREAM_ALREADY_CLOSED);
                }
                // writer が無い（backend が stdin を渡さない・終了後）間は捨てる。接続前は溜める（上限で背圧）。
                let discard = self.phase == Phase::Draining
                    || (self.phase == Phase::Running && self.stdin_writer.is_none());
                if !discard {
                    self.stdin_pending.extend_from_slice(data);
                }
                if fin {
                    self.stdin_fin = true;
                }
                None
            }
            Some(StreamType::Resize) => {
                match self.resize_parser.push(data) {
                    Ok(sizes) => {
                        for size in sizes {
                            match self.resize_fn.as_mut() {
                                Some(resize) => resize(size),
                                None => self.pending_resize = Some(size),
                            }
                        }
                        None
                    }
                    // 不正な resize はそのストリームだけ閉じる（セッションは続ける）。
                    Err(_) => {
                        self.opened.resize = None;
                        self.resize_parser = ResizeParser::new();
                        self.reset_stream(stream_id, rst_status::PROTOCOL_ERROR)
                    }
                }
            }
            // error・stdout・stderr はサーバー→クライアント専用。クライアントが書いても捨てる。
            _ => None,
        }
    }

    /// backend の接続成功後に、stdio を取り込んで中継を始める。符号化失敗なら false。
    fn start_relay(&mut self, session: AttachSession) -> bool {
        let AttachSession {
            stdin,
            stdout,
            stderr,
            resize,
            exited,
        } = session;
        self.phase = Phase::Running;
        self.exited = Some(exited);
        self.stdin_writer = if self.options.stdin { stdin } else { None };
        self.stdout_reader = if self.options.stdout { stdout } else { None };
        self.stderr_reader = if self.options.stderr { stderr } else { None };
        self.resize_fn = if self.options.tty { resize } else { None };
        // 接続前に RST_STREAM を受けたストリームは再開しない。
        if self.opened.stdout.is_some_and(|id| self.is_reset(id)) {
            self.stdout_reader = None;
        }
        if self.opened.stderr.is_some_and(|id| self.is_reset(id)) {
            self.stderr_reader = None;
        }
        if self.opened.stdin.is_some_and(|id| self.is_reset(id)) {
            self.stdin_writer = None;
            self.stdin_fin = true;
        }
        if let (Some(resize), Some(size)) = (self.resize_fn.as_mut(), self.pending_resize.take()) {
            resize(size);
        }
        if self.stdin_writer.is_none() {
            self.stdin_pending.clear();
            self.stdin_pos = 0;
        }
        // 要求された出力で backend が渡さなかったものは、その場で終端（FIN）にする。
        for (kind, present) in [
            (StreamType::Stdout, self.stdout_reader.is_some()),
            (StreamType::Stderr, self.stderr_reader.is_some()),
        ] {
            let requested = self.expected.contains(&kind);
            if requested
                && !present
                && let Some(id) = self.opened.get(kind)
            {
                if !self.queue_data(id, &[], true) {
                    return false;
                }
                match kind {
                    StreamType::Stdout => self.stdout_fin_sent = true,
                    _ => self.stderr_fin_sent = true,
                }
            }
        }
        true
    }

    fn poll_stdin(&mut self, cx: &mut Context<'_>) -> bool {
        let mut progress = false;
        let Some(writer) = self.stdin_writer.as_mut() else {
            return false;
        };
        if self.stdin_pos < self.stdin_pending.len() {
            let pending = self.stdin_pending.get(self.stdin_pos..).unwrap_or(&[]);
            match Pin::new(writer).poll_write(cx, pending) {
                Poll::Ready(Ok(n)) if n > 0 => {
                    self.stdin_pos += n;
                    self.stats.write_ok = true;
                    progress = true;
                    // 消費済みの先頭領域を溜め続けない（backend が少量ずつ消費しても確保量を有界にする）。
                    if self.stdin_pos >= COMPACT_THRESHOLD {
                        self.stdin_pending.drain(..self.stdin_pos);
                        self.stdin_pos = 0;
                    }
                }
                // 書けない（backend が stdin を閉じた）。以降の入力は捨てる。
                Poll::Ready(_) => {
                    self.stats.write_failed = true;
                    self.stdin_writer = None;
                    self.stdin_pending.clear();
                    self.stdin_pos = 0;
                    return true;
                }
                Poll::Pending => {}
            }
            if self.stdin_pos >= self.stdin_pending.len() {
                self.stdin_pending.clear();
                self.stdin_pos = 0;
            }
        } else if self.stdin_fin && Pin::new(writer).poll_shutdown(cx).is_ready() {
            self.stdin_writer = None;
            progress = true;
        }
        progress
    }

    /// backend の stdout / stderr を読んで DATA にする。EOF は FIN。
    fn poll_outputs(&mut self, cx: &mut Context<'_>) -> Result<bool, SessionEnd> {
        let mut progress = false;
        for kind in [StreamType::Stdout, StreamType::Stderr] {
            if self.out_len() >= OUT_HIGH_WATER {
                break;
            }
            let reader = match kind {
                StreamType::Stdout => self.stdout_reader.as_mut(),
                _ => self.stderr_reader.as_mut(),
            };
            let Some(reader) = reader else {
                continue;
            };
            let mut rb = ReadBuf::new(&mut self.scratch);
            let eof = match Pin::new(reader).poll_read(cx, &mut rb) {
                Poll::Pending => continue,
                Poll::Ready(Ok(())) => {
                    let chunk = rb.filled().to_vec();
                    if chunk.is_empty() {
                        true
                    } else {
                        self.stats.read_ok = true;
                        let Some(id) = self.opened.get(kind) else {
                            continue;
                        };
                        if !self.queue_data(id, &chunk, false) {
                            return Err(SessionEnd::ProtocolError);
                        }
                        progress = true;
                        false
                    }
                }
                // 読み取りの失敗は出力の欠損として保持し、Success Status を返さない（終端の FIN は送る）。
                Poll::Ready(Err(_)) => {
                    self.stats.read_failed = true;
                    self.output_failed = true;
                    true
                }
            };
            if eof {
                progress = true;
                match kind {
                    StreamType::Stdout => self.stdout_reader = None,
                    _ => self.stderr_reader = None,
                }
                if let Some(id) = self.opened.get(kind) {
                    let sent = match kind {
                        StreamType::Stdout => &mut self.stdout_fin_sent,
                        _ => &mut self.stderr_fin_sent,
                    };
                    if !*sent {
                        *sent = true;
                        if !self.queue_data(id, &[], true) {
                            return Err(SessionEnd::ProtocolError);
                        }
                    }
                }
            }
        }
        Ok(progress)
    }

    /// 終わり方に応じた最後のフレーム（Status・FIN・GOAWAY）を `close_timeout` 内に送り、IO を閉じる。
    async fn finish(&mut self, end: SessionEnd) {
        // backend の資源を先に解放する。
        self.stdin_writer = None;
        self.stdout_reader = None;
        self.stderr_reader = None;
        self.exited = None;
        self.starting = None;
        self.resize_fn = None;

        let last_good = self.last_stream_id;
        let queued = match end {
            SessionEnd::ClientClosed | SessionEnd::IoError => true,
            SessionEnd::Finished | SessionEnd::BackendFailed => {
                let status = match (end, self.failure.as_ref()) {
                    (SessionEnd::BackendFailed, Some(e)) => Some(status_failure(self.protocol, e)),
                    // 固定メッセージ（下位のエラー文言は載せない）。
                    _ if self.output_failed => Some(status_failure(
                        self.protocol,
                        &CriError::internal("attach output read failed"),
                    )),
                    _ => status_success(self.protocol),
                };
                self.queue_final(status, last_good)
            }
            SessionEnd::CreationTimeout | SessionEnd::ProtocolError => self.queue(&Frame::GoAway {
                last_good_stream_id: last_good,
                status: goaway_status::PROTOCOL_ERROR,
            }),
            // idle の打ち切りは終了コードの無い失敗。error ストリームが空のまま閉じると client-go が成功とみなすため
            // Failure の Status を送る（CRI-6・REPAIR-5）。送出は close_timeout 内の最善努力で、結末は変えない。
            SessionEnd::IdleTimeout => {
                let status = status_timeout(self.protocol);
                self.queue_final(Some(status), last_good)
            }
        };
        if !queued {
            return;
        }
        let limit = self.limits.close_timeout;
        let _ = tokio::time::timeout(limit, async {
            let flushed = poll_fn(|cx| match self.poll_flush_out(cx) {
                Err(()) => Poll::Ready(false),
                Ok(_) if self.out_pos >= self.out.len() => Poll::Ready(true),
                Ok(_) => Poll::Pending,
            })
            .await;
            if flushed {
                let _ = poll_fn(|cx| Pin::new(&mut self.io).poll_shutdown(cx)).await;
            }
        })
        .await;
    }

    /// Status（error ストリーム）・未送の出力 FIN・GOAWAY を積む。
    fn queue_final(&mut self, status: Option<Vec<u8>>, last_good: u32) -> bool {
        if let Some(id) = self.opened.error {
            let data = status.unwrap_or_default();
            if !self.queue_data(id, &data, true) {
                return false;
            }
        }
        for (kind, sent) in [
            (StreamType::Stdout, self.stdout_fin_sent),
            (StreamType::Stderr, self.stderr_fin_sent),
        ] {
            if !sent
                && let Some(id) = self.opened.get(kind)
                && !self.queue_data(id, &[], true)
            {
                return false;
            }
        }
        self.queue(&Frame::GoAway {
            last_good_stream_id: last_good,
            status: goaway_status::OK,
        })
    }
}

/// idle で打ち切る attach の Status（v4 は `reason: Timeout` の Failure）。
///
/// Exec の期限切れ（PR #3690）と同じ形・同系統の文言。Exec と共通化するのは、両者が main に揃ってから検討する。
const STATUS_TIMEOUT_V4: &str = r#"{"metadata":{},"status":"Failure","message":"attach session timed out","reason":"Timeout","code":504}"#;
/// idle で打ち切る attach の Status（v3・v2 はメッセージのテキスト）。
const STATUS_TIMEOUT_TEXT: &str = "attach session timed out";

/// idle の打ち切りで error ストリームへ書く Status。空のまま閉じると client-go が成功と誤認するため必ず書く（CRI-6）。
fn status_timeout(protocol: Protocol) -> Vec<u8> {
    match protocol {
        Protocol::V4 => STATUS_TIMEOUT_V4.as_bytes().to_vec(),
        Protocol::V3 | Protocol::V2 => STATUS_TIMEOUT_TEXT.as_bytes().to_vec(),
    }
}
