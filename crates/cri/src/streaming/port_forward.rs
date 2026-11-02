//! CRI `PortForward` のストリーミング処理（CRI-6・TASK-63.4・#682。判断は #678、設計記録は
//! `docs/design/cri-streaming-server.md`）。
//!
//! [`super::StreamingServer`] がトークンを照合した `StreamRequest::PortForward` を受け取り、HTTP/1.1 の
//! `Upgrade: SPDY/3.1`（`X-Stream-Protocol-Version: portforward.k8s.io`）を成立させて、Upgrade 後の IO 上で
//! 「クライアントの error / data ストリームの対 ⇔ 転送先ポートの TCP 接続」を双方向に中継する。
//! 呼び出し元は [`super::StreamingServer::bind_with_handler`] に渡された本ハンドラ（kubelet / kubectl の接続が
//! 来たとき）。SPDY のフレーム処理は [`super::spdy`] を使う。
//!
//! ## 転送先への接続は注入点（REPAIR-3）
//!
//! 転送先（サンドボックスのネットワーク名前空間内のポート）への TCP 接続は [`PortForwardDialer`] に切り出した。
//! cri は名前空間の具象（setns・pod ネットワークの保持役）を知らない層のため、本 PR は接続の注入点と中継までを
//! 実装し、**本番の dialer と plugin-cri へのハンドラ注入は未実装**である（後続の issue）。既定でホストの
//! `127.0.0.1` へつなぐ実装は置かない（URL を知る者にホストのローカルサービスを晒す経路になるため）。
//!
//! ## 安全側の既定（REPAIR-5）
//!
//! 照合前に Upgrade しない・期待しないプロトコルは拒否する・保存済み要求の `port` 一覧が非空ならそれに限る。
//! dial・対の成立待ち・Upgrade 後の idle に期限を持ち、同時ストリーム数・フレーム長・書き込みの滞留量に上限を
//! 持つ（[`PortForwardConfig`]）。エラー文言とログにはトークン・パス・内部 ID を含めない。

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue, UPGRADE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::Sleep;

use super::spdy::{
    Frame, FrameDecoder, GOAWAY_OK, GOAWAY_PROTOCOL_ERROR, HeaderCompressor, RST_CANCEL,
    RST_PROTOCOL_ERROR, RST_REFUSED_STREAM, SpdyError, StreamId,
};
use super::{
    ConnectionPermit, NotImplementedHandler, StreamBody, StreamHandler, StreamRequest,
    plain_response,
};
use crate::error::CriError;

/// Upgrade で合意する HTTP の `Upgrade` ヘッダ値。
pub const UPGRADE_PROTOCOL: &str = "SPDY/3.1";
/// `X-Stream-Protocol-Version` で合意する値（client-go の portforward over SPDY）。
pub const STREAM_PROTOCOL_VERSION: &str = "portforward.k8s.io";
const STREAM_PROTOCOL_HEADER: &str = "x-stream-protocol-version";

/// 要求 ID（error と data の対を結ぶ）の最大バイト数。
const MAX_REQUEST_ID_BYTES: usize = 64;
/// TCP から 1 回に読んで DATA にするバイト数。
const DATA_CHUNK: usize = 32 * 1024;
/// SPDY 接続から 1 回に読むバイト数。
const READ_CHUNK: usize = 16 * 1024;
/// 書き込み済みの接頭辞をバッファから詰める閾値（消費済み領域の蓄積を防ぐ）。
const COMPACT_THRESHOLD: usize = 4 * 1024;
/// `poll` 1 回で回す最大ラウンド数（他のタスクを飢えさせない）。
const MAX_ROUNDS: usize = 64;

/// 転送先への TCP 接続の注入点。cri は名前空間の具象を知らない（CRI-7・PLUG-1）。
///
/// `StreamingServer` の Upgrade 後のタスクが `spawn_blocking` 上で呼ぶ（ブロッキングで構わない）。
/// 実装は `pod_sandbox_id`（保存済み要求の値。URL やヘッダから組み立て直さない）のネットワーク名前空間内の
/// `port` へ接続する。エラーにパス・内部情報を含めない。`timeout` を超えて待たないこと。
/// 呼び出し全体にも [`PortForwardConfig::dial_timeout`] の期限が掛かる。
pub trait PortForwardDialer: Send + Sync + 'static {
    /// 転送先へ接続する。
    fn dial(
        &self,
        pod_sandbox_id: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<std::net::TcpStream, CriError>;
}

/// PortForward の上限と期限（REPAIR-5）。
#[derive(Debug, Clone)]
pub struct PortForwardConfig {
    /// 転送先への接続の期限。既定 10 秒。
    pub dial_timeout: Duration,
    /// error と data の対が揃うまでの期限（kubelet の stream creation timeout 相当）。既定 30 秒。
    pub pair_timeout: Duration,
    /// Upgrade 後に全ストリームで送受信が無い時間の上限（kubelet の stream idle timeout 相当）。既定 4 時間。
    pub idle_timeout: Duration,
    /// 同時に持てるストリーム数（error と data の合計）。既定 128。
    pub max_streams: usize,
    /// 受け取るフレーム本体の最大バイト数。既定 1 MiB。
    pub max_frame_bytes: usize,
    /// 転送先への書き込み滞留量（全対の合計）と送信キューの上限。超えている間は SPDY 接続の読み取りを止める
    /// （バックプレッシャー。1 フレームが上限を超えても、`max_frame_bytes` 以内なら受け取って TCP へ排出する）。既定 256 KiB。
    pub max_pending_bytes: usize,
    /// ハンドラ全体（全セッション合計）で同時に持てる blocking の dial の件数（実行中と待機中の合計）。既定 32。
    ///
    /// future を捨てても blocking 処理は止まらないため、セッションを張り直しても枠は返らない（REPAIR-5）。
    pub max_inflight_dials: usize,
}

impl Default for PortForwardConfig {
    fn default() -> Self {
        Self {
            dial_timeout: Duration::from_secs(10),
            pair_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(4 * 60 * 60),
            max_streams: 128,
            max_frame_bytes: 1024 * 1024,
            max_pending_bytes: 256 * 1024,
            max_inflight_dials: 32,
        }
    }
}

impl PortForwardConfig {
    /// 設定を検証する（fail-closed）。
    pub fn validate(&self) -> Result<(), CriError> {
        if self.dial_timeout.is_zero() || self.pair_timeout.is_zero() || self.idle_timeout.is_zero()
        {
            return Err(CriError::invalid_argument(
                "port forward timeouts must be positive",
            ));
        }
        if !(2..=1024).contains(&self.max_streams) {
            return Err(CriError::invalid_argument(
                "port forward max_streams must be between 2 and 1024",
            ));
        }
        if !(1024..=super::spdy::MAX_FRAME_LEN).contains(&self.max_frame_bytes) {
            return Err(CriError::invalid_argument(
                "port forward max_frame_bytes is out of range",
            ));
        }
        if self.max_pending_bytes < DATA_CHUNK {
            return Err(CriError::invalid_argument(
                "port forward max_pending_bytes is too small",
            ));
        }
        if !(1..=256).contains(&self.max_inflight_dials) {
            return Err(CriError::invalid_argument(
                "port forward max_inflight_dials must be between 1 and 256",
            ));
        }
        Ok(())
    }
}

/// セッションの終了理由（REPAIR-4）。ポート・トークン・アドレスは含めない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortForwardEnd {
    /// クライアントの切断または GOAWAY で終わった。
    Completed,
    /// 送受信が無いまま idle の期限が切れた。
    IdleTimeout,
    /// SPDY の構造違反・IO の失敗・Upgrade の失敗。
    ProtocolError,
    /// フレーム長・バッファなどの上限を超えた。
    LimitExceeded,
}

/// [`PortForwardEnd`] の受け口。同期・短時間で返すこと。
pub trait PortForwardObserver: Send + Sync + 'static {
    /// セッションの終了を記録する。
    fn observe(&self, end: PortForwardEnd, elapsed: Duration);
}

/// 何も記録しない既定の観測口。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPortForwardObserver;

impl PortForwardObserver for NoopPortForwardObserver {
    fn observe(&self, _end: PortForwardEnd, _elapsed: Duration) {}
}

/// `PortForward` 要求だけを扱う [`StreamHandler`]。それ以外の種別は `fallback`（既定 501）へ委ねる。
///
/// #680（Exec）・#681（Attach）のハンドラも同じ形で `with_fallback` に連ねられる。
pub struct PortForwardHandler {
    dialer: Arc<dyn PortForwardDialer>,
    config: PortForwardConfig,
    fallback: Arc<dyn StreamHandler>,
    observer: Arc<dyn PortForwardObserver>,
    /// blocking の dial の実行中・待機中の件数。全セッションで共有する（`DialSlot` が増減する）。
    dial_inflight: Arc<AtomicUsize>,
}

impl std::fmt::Debug for PortForwardHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortForwardHandler")
            .field("config", &self.config)
            .finish()
    }
}

impl PortForwardHandler {
    /// dialer と設定を指定して作る。設定を検証する（fail-closed）。
    pub fn new(
        dialer: Arc<dyn PortForwardDialer>,
        config: PortForwardConfig,
    ) -> Result<Self, CriError> {
        config.validate()?;
        Ok(Self {
            dialer,
            config,
            fallback: Arc::new(NotImplementedHandler),
            observer: Arc::new(NoopPortForwardObserver),
            dial_inflight: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// PortForward 以外の種別を委ねるハンドラを指定する。
    pub fn with_fallback(mut self, fallback: Arc<dyn StreamHandler>) -> Self {
        self.fallback = fallback;
        self
    }

    /// 観測口を指定する（REPAIR-4）。
    pub fn with_observer(mut self, observer: Arc<dyn PortForwardObserver>) -> Self {
        self.observer = observer;
        self
    }

    /// 照合してから Upgrade し、Upgrade 後の IO を中継するタスクを起動する。
    fn start(
        &self,
        request: crate::runtime::v1::PortForwardRequest,
        http: Request<Incoming>,
        permit: ConnectionPermit,
    ) -> Response<StreamBody> {
        if let Err(message) = negotiate(http.headers()) {
            return plain_response(StatusCode::BAD_REQUEST, message);
        }
        let on_upgrade = hyper::upgrade::on(http);
        let dialer = Arc::clone(&self.dialer);
        let observer = Arc::clone(&self.observer);
        let config = self.config.clone();
        let dial_inflight = Arc::clone(&self.dial_inflight);
        // 0 は有効なポートに一致しないので、範囲外の値が一覧から消えて「任意」に化けることはない。
        let allowed: Vec<u16> = request
            .port
            .iter()
            .map(|p| u16::try_from(*p).unwrap_or(0))
            .collect();
        let sandbox = request.pod_sandbox_id;
        tokio::spawn(async move {
            let started = Instant::now();
            let end = match on_upgrade.await {
                Ok(upgraded) => {
                    match Session::new(
                        TokioIo::new(upgraded),
                        dialer,
                        sandbox,
                        allowed,
                        config,
                        dial_inflight,
                    ) {
                        Some(session) => session.run().await,
                        None => PortForwardEnd::ProtocolError,
                    }
                }
                Err(_) => PortForwardEnd::ProtocolError,
            };
            observer.observe(end, started.elapsed());
            // permit は IO の寿命まで保持する（同時接続数の契約。StreamHandler の doc）。
            drop(permit);
        });
        upgrade_response()
    }
}

impl StreamHandler for PortForwardHandler {
    fn handle(
        &self,
        request: StreamRequest,
        http: Request<Incoming>,
        permit: ConnectionPermit,
    ) -> Pin<Box<dyn Future<Output = Response<StreamBody>> + Send + '_>> {
        match request {
            StreamRequest::PortForward(pf) => {
                let response = self.start(pf, http, permit);
                Box::pin(async move { response })
            }
            other => self.fallback.handle(other, http, permit),
        }
    }
}

/// `Connection` / `Upgrade` / `X-Stream-Protocol-Version` の照合（純関数）。一致しなければ固定の英文を返す。
fn negotiate(headers: &HeaderMap) -> Result<(), &'static str> {
    fn has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
        headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }
    if !has_token(headers, CONNECTION, "upgrade") || !has_token(headers, UPGRADE, UPGRADE_PROTOCOL)
    {
        return Err("upgrade to SPDY/3.1 is required");
    }
    if !has_token(
        headers,
        HeaderName::from_static(STREAM_PROTOCOL_HEADER),
        STREAM_PROTOCOL_VERSION,
    ) {
        return Err("unsupported stream protocol version");
    }
    Ok(())
}

fn upgrade_response() -> Response<StreamBody> {
    let mut response = Response::new(StreamBody::empty());
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    let headers = response.headers_mut();
    headers.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static(UPGRADE_PROTOCOL));
    headers.insert(
        HeaderName::from_static(STREAM_PROTOCOL_HEADER),
        HeaderValue::from_static(STREAM_PROTOCOL_VERSION),
    );
    response
}

/// ポート番号を厳格に読む（10 進の数字のみ・1..=65535）。
fn parse_port(value: &str) -> Option<u16> {
    if value.is_empty() || value.len() > 5 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse::<u16>().ok().filter(|p| *p != 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Error,
    Data,
}

type DialFuture = Pin<Box<dyn Future<Output = Result<TcpStream, ()>> + Send>>;

struct Connected {
    tcp: TcpStream,
    write_shut: bool,
    tcp_eof: bool,
}

enum Phase {
    Waiting,
    Dialing(DialFuture),
    Connected(Connected),
}

/// 実行中の `spawn_blocking` の dial 1 件ぶんの枠。blocking 処理が終わる（クロージャが drop される）まで
/// 返らない。対がキャンセルされても dial は止まらないため、実行中・待機中の総数をこの枠で抑える（REPAIR-5）。
struct DialSlot(Arc<AtomicUsize>);

impl DialSlot {
    fn acquire(counter: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < limit).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(counter)))
    }
}

impl Drop for DialSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Pair {
    port: u16,
    error: Option<StreamId>,
    data: Option<StreamId>,
    created: Instant,
    to_tcp: Vec<u8>,
    to_tcp_pos: usize,
    peer_fin: bool,
    phase: Phase,
}

impl Pair {
    fn pending(&self) -> usize {
        self.to_tcp.len().saturating_sub(self.to_tcp_pos)
    }
}

/// 送信キュー。ヘッダブロックの圧縮文脈は送信順に進むので、フレームは必ずここへ積んだ順に送る。
struct Outbox {
    buf: Vec<u8>,
    pos: usize,
    comp: HeaderCompressor,
    failed: bool,
}

impl Outbox {
    fn send(&mut self, frame: &Frame) {
        match frame.encode(&mut self.comp) {
            Ok(bytes) => self.buf.extend_from_slice(&bytes),
            Err(_) => self.failed = true,
        }
    }

    fn pending(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// 書ける分だけ書く。進捗があれば `Ok(true)`、IO の失敗は `Err`。
    fn poll_flush<IO: AsyncWrite + Unpin>(
        &mut self,
        io: &mut IO,
        cx: &mut Context<'_>,
    ) -> Result<bool, ()> {
        let mut progress = false;
        while let Some(rest) = self.buf.get(self.pos..).filter(|r| !r.is_empty()) {
            match Pin::new(&mut *io).poll_write(cx, rest) {
                Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => return Err(()),
                Poll::Ready(Ok(n)) => {
                    self.pos += n;
                    progress = true;
                }
                Poll::Pending => break,
            }
        }
        if self.pos >= self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos >= COMPACT_THRESHOLD {
            // 未送信分が残り続けても消費済みの接頭辞が蓄積しないよう詰める。
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        Ok(progress)
    }
}

enum PairStep {
    Continue { progress: bool },
    Finished,
    Aborted,
}

/// Upgrade 後の 1 接続分の状態機械。1 つのタスクが `poll_fn` で全 IO を順に poll する
/// （crates/cri の tokio は `sync`・`io-util`・`macros` を持たないため、チャネルや select! に頼らない）。
struct Session<IO> {
    io: IO,
    decoder: FrameDecoder,
    outbox: Outbox,
    streams: HashMap<u32, (String, Kind)>,
    /// これまでに受けたクライアント起点の最大ストリーム ID（SPDY は単調増加で再利用しない）。
    last_syn_id: u32,
    pairs: HashMap<String, Pair>,
    dialer: Arc<dyn PortForwardDialer>,
    sandbox: String,
    allowed: Vec<u16>,
    config: PortForwardConfig,
    scratch: Vec<u8>,
    last_activity: Instant,
    /// 対の処理を始める位置。毎回進めて、送信キューの空きを先頭の対が独占しないようにする。
    pair_cursor: usize,
    /// blocking の dial の実行中・待機中の件数（`DialSlot` が増減する）。ハンドラの全セッションで共有する。
    dial_inflight: Arc<AtomicUsize>,
    tick: Pin<Box<Sleep>>,
    tick_every: Duration,
    end: Option<PortForwardEnd>,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> Session<IO> {
    fn new(
        io: IO,
        dialer: Arc<dyn PortForwardDialer>,
        sandbox: String,
        allowed: Vec<u16>,
        config: PortForwardConfig,
        dial_inflight: Arc<AtomicUsize>,
    ) -> Option<Self> {
        let tick_every = (config.pair_timeout.min(config.idle_timeout) / 4)
            .clamp(Duration::from_millis(10), Duration::from_secs(1));
        let comp = HeaderCompressor::new().ok()?;
        Some(Self {
            io,
            decoder: FrameDecoder::new(config.max_frame_bytes),
            outbox: Outbox {
                buf: Vec::new(),
                pos: 0,
                failed: false,
                comp,
            },
            streams: HashMap::new(),
            last_syn_id: 0,
            pairs: HashMap::new(),
            dialer,
            sandbox,
            allowed,
            scratch: vec![0u8; DATA_CHUNK],
            last_activity: Instant::now(),
            pair_cursor: 0,
            dial_inflight,
            tick: Box::pin(tokio::time::sleep(tick_every)),
            tick_every,
            end: None,
            config,
        })
    }

    async fn run(mut self) -> PortForwardEnd {
        std::future::poll_fn(|cx| self.poll_run(cx)).await
    }

    /// 終了を記録し GOAWAY を積む（最初の理由だけを残す）。
    fn finish(&mut self, reason: PortForwardEnd) {
        if self.end.is_none() {
            self.end = Some(reason);
            let status = if reason == PortForwardEnd::ProtocolError
                || reason == PortForwardEnd::LimitExceeded
            {
                GOAWAY_PROTOCOL_ERROR
            } else {
                GOAWAY_OK
            };
            self.outbox.send(&Frame::GoAway {
                last_good: 0,
                status,
            });
        }
    }

    fn finish_for(&mut self, err: SpdyError) {
        match err {
            SpdyError::LimitExceeded(_) => self.finish(PortForwardEnd::LimitExceeded),
            _ => self.finish(PortForwardEnd::ProtocolError),
        }
    }

    /// クライアントが読まない間に PING・SYN_STREAM 等への応答で送信キューが膨らまないよう、
    /// 送信キューが上限を超えている間は読み取りも止める（REPAIR-5。止まったままなら idle で終わる）。
    /// 転送先へ未書き込みの滞留が全対の合計で上限に達している間も読み取りを止める（バックプレッシャー）。
    /// 受け取った DATA は分割して TCP へ排出し、フレーム単位では拒否しない。滞留の上限は
    /// 「上限 + 復号器の容量」で有界になり、排出が進まないまま続けば idle で終わる。
    fn can_read(&self) -> bool {
        self.outbox.pending() <= self.config.max_pending_bytes
            && self
                .pairs
                .values()
                .fold(0usize, |a, p| a.saturating_add(p.pending()))
                < self.config.max_pending_bytes
    }

    fn poll_run(&mut self, cx: &mut Context<'_>) -> Poll<PortForwardEnd> {
        for _ in 0..MAX_ROUNDS {
            let mut progress = false;
            while self.tick.as_mut().poll(cx).is_ready() {
                self.housekeeping(Instant::now());
                self.tick
                    .as_mut()
                    .reset(tokio::time::Instant::now() + self.tick_every);
            }
            if self.outbox.failed {
                self.finish(PortForwardEnd::ProtocolError);
            }
            if let Some(reason) = self.end {
                // 最後の best-effort の flush（GOAWAY を届ける）。待たない。
                let _ = self.outbox.poll_flush(&mut self.io, cx);
                return Poll::Ready(reason);
            }
            match self.outbox.poll_flush(&mut self.io, cx) {
                Ok(p) => {
                    if p {
                        // 送信が進んでいる間は遅い受信側でも idle とみなさない。
                        self.last_activity = Instant::now();
                    }
                    progress |= p;
                }
                Err(()) => return Poll::Ready(PortForwardEnd::ProtocolError),
            }
            if self.can_read() {
                progress |= self.poll_read_io(cx);
                if self.end.is_some() {
                    continue;
                }
            }
            progress |= self.step_pairs(cx);
            if !progress {
                return Poll::Pending;
            }
        }
        // 他のタスクに譲り、すぐ再開する。
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn housekeeping(&mut self, now: Instant) {
        if now.duration_since(self.last_activity) >= self.config.idle_timeout {
            self.finish(PortForwardEnd::IdleTimeout);
            return;
        }
        let expired: Vec<String> = self
            .pairs
            .iter()
            .filter(|(_, p)| {
                matches!(p.phase, Phase::Waiting)
                    && now.duration_since(p.created) >= self.config.pair_timeout
            })
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            self.abort_pair(&key, None);
        }
    }

    /// SPDY 接続から読んでフレームを処理する。進捗があれば true。
    fn poll_read_io(&mut self, cx: &mut Context<'_>) -> bool {
        let mut chunk = [0u8; READ_CHUNK];
        // 復号器の残り容量までしか読まない（TCP のまとめ方で正常入力を拒否しない）。
        let limit = self.decoder.free_capacity().min(READ_CHUNK);
        if limit == 0 {
            self.finish_for(SpdyError::LimitExceeded("receive buffer is full"));
            return true;
        }
        let Some(window) = chunk.get_mut(..limit) else {
            self.finish_for(SpdyError::LimitExceeded("receive window out of range"));
            return true;
        };
        let mut buf = ReadBuf::new(window);
        match Pin::new(&mut self.io).poll_read(cx, &mut buf) {
            Poll::Pending => false,
            Poll::Ready(Err(_)) => {
                self.finish(PortForwardEnd::ProtocolError);
                true
            }
            Poll::Ready(Ok(())) => {
                let filled = buf.filled();
                if filled.is_empty() {
                    self.finish(PortForwardEnd::Completed);
                    return true;
                }
                self.last_activity = Instant::now();
                if let Err(e) = self.decoder.push(filled) {
                    self.finish_for(e);
                    return true;
                }
                loop {
                    match self.decoder.next_frame() {
                        Ok(Some(frame)) => self.on_frame(frame),
                        Ok(None) => break,
                        Err(e) => {
                            self.finish_for(e);
                            break;
                        }
                    }
                    if self.end.is_some() {
                        break;
                    }
                }
                true
            }
        }
    }

    fn refuse(&mut self, stream: StreamId) {
        self.outbox.send(&Frame::RstStream {
            stream,
            status: RST_REFUSED_STREAM,
        });
    }

    fn on_frame(&mut self, frame: Frame) {
        match frame {
            Frame::SynStream {
                stream,
                headers,
                fin,
                ..
            } => self.on_syn_stream(stream, &headers, fin),
            Frame::Data { stream, fin, data } => {
                if data.is_empty()
                    && matches!(self.streams.get(&stream.get()), Some((_, Kind::Error)))
                {
                    // error ストリームの空 FIN はクライアントの半閉じ。サーバー側の送信は保持する。
                    return;
                }
                if let Some((key, Kind::Data)) = self.streams.get(&stream.get()).cloned() {
                    let Some(pair) = self.pairs.get_mut(&key) else {
                        return;
                    };
                    if pair.peer_fin {
                        // 半閉じ後の DATA は不正。TCP へ転送せず、このストリームをリセットする。
                        self.outbox.send(&Frame::RstStream {
                            stream,
                            status: RST_PROTOCOL_ERROR,
                        });
                        self.abort_pair(&key, Some(stream));
                        return;
                    }
                    pair.to_tcp.extend_from_slice(&data);
                    if fin {
                        pair.peer_fin = true;
                    }
                } else {
                    // 未知のストリーム、または error ストリームへの DATA。
                    self.outbox.send(&Frame::RstStream {
                        stream,
                        status: RST_PROTOCOL_ERROR,
                    });
                }
            }
            Frame::RstStream { stream, .. } => {
                if let Some((key, _)) = self.streams.get(&stream.get()).cloned() {
                    self.abort_pair(&key, Some(stream));
                }
            }
            Frame::Ping(id) => self.outbox.send(&Frame::Ping(id)),
            Frame::GoAway { .. } => self.finish(PortForwardEnd::Completed),
            Frame::SynReply { .. } | Frame::Ignored => {}
        }
    }

    fn on_syn_stream(&mut self, stream: StreamId, headers: &[(String, String)], fin: bool) {
        // クライアント起点のストリーム ID は奇数で、重複しない。
        if stream.get().is_multiple_of(2)
            || stream.get() <= self.last_syn_id
            || self.streams.contains_key(&stream.get())
        {
            self.finish(PortForwardEnd::ProtocolError);
            return;
        }
        self.last_syn_id = stream.get();
        let find = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        let kind = match find("streamtype") {
            Some("error") => Kind::Error,
            Some("data") => Kind::Data,
            _ => return self.refuse(stream),
        };
        let Some(port) = find("port").and_then(parse_port) else {
            return self.refuse(stream);
        };
        let Some(request_id) = find("requestid")
            .filter(|r| !r.is_empty() && r.len() <= MAX_REQUEST_ID_BYTES)
            .map(str::to_string)
        else {
            return self.refuse(stream);
        };
        if !self.allowed.is_empty() && !self.allowed.contains(&port) {
            return self.refuse(stream);
        }
        if self.streams.len() >= self.config.max_streams {
            return self.refuse(stream);
        }
        let pair = self
            .pairs
            .entry(request_id.clone())
            .or_insert_with(|| Pair {
                port,
                error: None,
                data: None,
                created: Instant::now(),
                to_tcp: Vec::new(),
                to_tcp_pos: 0,
                peer_fin: false,
                phase: Phase::Waiting,
            });
        let slot = match kind {
            Kind::Error => &mut pair.error,
            Kind::Data => &mut pair.data,
        };
        if pair.port != port || slot.is_some() {
            // 新規に作った空の対が残らないようにする。
            if pair.error.is_none() && pair.data.is_none() {
                self.pairs.remove(&request_id);
            }
            return self.refuse(stream);
        }
        *slot = Some(stream);
        if kind == Kind::Data && fin {
            pair.peer_fin = true;
        }
        self.streams
            .insert(stream.get(), (request_id.clone(), kind));
        self.outbox.send(&Frame::SynReply {
            stream,
            fin: false,
            headers: Vec::new(),
        });
        if let Some(pair) = self.pairs.get_mut(&request_id)
            && pair.error.is_some()
            && pair.data.is_some()
            && matches!(pair.phase, Phase::Waiting)
        {
            // 対のキャンセル後も blocking の dial は残るため、総数に上限を設ける。取れなければ接続失敗として扱う。
            let slot = DialSlot::acquire(&self.dial_inflight, self.config.max_inflight_dials);
            pair.phase = Phase::Dialing(make_dial(
                Arc::clone(&self.dialer),
                self.sandbox.clone(),
                pair.port,
                self.config.dial_timeout,
                slot,
            ));
        }
    }

    /// 対を閉じる。`except` 以外のストリームへ RST_STREAM(CANCEL) を送る。
    fn abort_pair(&mut self, key: &str, except: Option<StreamId>) {
        if let Some(pair) = self.pairs.remove(key) {
            for id in [pair.error, pair.data].into_iter().flatten() {
                self.streams.remove(&id.get());
                if Some(id) != except {
                    self.outbox.send(&Frame::RstStream {
                        stream: id,
                        status: RST_CANCEL,
                    });
                }
            }
        }
    }

    fn step_pairs(&mut self, cx: &mut Context<'_>) -> bool {
        let mut progress = false;
        let mut done: Vec<(String, bool)> = Vec::new();
        let mut keys: Vec<String> = self.pairs.keys().cloned().collect();
        keys.sort();
        if !keys.is_empty() {
            let start = self.pair_cursor % keys.len();
            keys.rotate_left(start);
            self.pair_cursor = self.pair_cursor.wrapping_add(1);
        }
        for key in keys {
            let Some(pair) = self.pairs.get_mut(&key) else {
                continue;
            };
            match step_pair(
                pair,
                &mut self.outbox,
                cx,
                &mut self.scratch,
                &self.config,
                &mut self.last_activity,
            ) {
                PairStep::Continue { progress: p } => progress |= p,
                PairStep::Finished => done.push((key, false)),
                PairStep::Aborted => done.push((key, true)),
            }
        }
        for (key, aborted) in done {
            progress = true;
            if aborted {
                self.abort_pair(&key, None);
            } else if let Some(pair) = self.pairs.remove(&key) {
                for id in [pair.error, pair.data].into_iter().flatten() {
                    self.streams.remove(&id.get());
                }
            }
        }
        progress
    }
}

fn make_dial(
    dialer: Arc<dyn PortForwardDialer>,
    sandbox: String,
    port: u16,
    timeout: Duration,
    slot: Option<DialSlot>,
) -> DialFuture {
    Box::pin(async move {
        let Some(slot) = slot else {
            return Err(());
        };
        let join = tokio::task::spawn_blocking(move || {
            // 枠は blocking 処理が終わるまで保持する（future の drop では返さない）。
            let _slot = slot;
            dialer.dial(&sandbox, port, timeout)
        });
        match tokio::time::timeout(timeout, join).await {
            Ok(Ok(Ok(std_tcp))) => {
                std_tcp.set_nonblocking(true).map_err(|_| ())?;
                TcpStream::from_std(std_tcp).map_err(|_| ())
            }
            _ => Err(()),
        }
    })
}

/// 1 対ぶんの前進。error / data の両ストリームが揃ってから呼ばれる前提で、片方が欠ければ何もしない。
fn step_pair(
    pair: &mut Pair,
    outbox: &mut Outbox,
    cx: &mut Context<'_>,
    scratch: &mut [u8],
    config: &PortForwardConfig,
    last_activity: &mut Instant,
) -> PairStep {
    let (Some(error_id), Some(data_id)) = (pair.error, pair.data) else {
        return PairStep::Continue { progress: false };
    };
    let Pair {
        port,
        to_tcp,
        to_tcp_pos,
        peer_fin,
        phase,
        ..
    } = pair;
    let mut progress = false;
    if let Phase::Dialing(fut) = phase {
        match fut.as_mut().poll(cx) {
            Poll::Pending => return PairStep::Continue { progress: false },
            Poll::Ready(Ok(tcp)) => {
                *phase = Phase::Connected(Connected {
                    tcp,
                    write_shut: false,
                    tcp_eof: false,
                });
                progress = true;
            }
            Poll::Ready(Err(())) => {
                // 固定の英文のみ（内部情報を含めない）。
                outbox.send(&Frame::Data {
                    stream: error_id,
                    fin: true,
                    data: format!("error forwarding port {port}: connection failed").into_bytes(),
                });
                outbox.send(&Frame::Data {
                    stream: data_id,
                    fin: true,
                    data: Vec::new(),
                });
                return PairStep::Finished;
            }
        }
    }
    let Phase::Connected(conn) = phase else {
        return PairStep::Continue { progress };
    };
    // クライアント → TCP。
    while let Some(rest) = to_tcp.get(*to_tcp_pos..).filter(|r| !r.is_empty()) {
        match Pin::new(&mut conn.tcp).poll_write(cx, rest) {
            Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => return PairStep::Aborted,
            Poll::Ready(Ok(n)) => {
                *to_tcp_pos += n;
                progress = true;
                *last_activity = Instant::now();
            }
            Poll::Pending => break,
        }
    }
    if *to_tcp_pos < to_tcp.len() && *to_tcp_pos >= COMPACT_THRESHOLD {
        // 未送信分が残り続けても消費済みの接頭辞が蓄積しないよう詰める。
        to_tcp.drain(..*to_tcp_pos);
        *to_tcp_pos = 0;
    }
    if *to_tcp_pos >= to_tcp.len() {
        to_tcp.clear();
        *to_tcp_pos = 0;
        if *peer_fin
            && !conn.write_shut
            && let Poll::Ready(_) = Pin::new(&mut conn.tcp).poll_shutdown(cx)
        {
            conn.write_shut = true;
            progress = true;
        }
    }
    // TCP → クライアント。
    if !conn.tcp_eof {
        for _ in 0..4 {
            if outbox.pending() >= config.max_pending_bytes {
                break;
            }
            let mut buf = ReadBuf::new(scratch);
            match Pin::new(&mut conn.tcp).poll_read(cx, &mut buf) {
                Poll::Pending => break,
                Poll::Ready(Err(_)) => return PairStep::Aborted,
                Poll::Ready(Ok(())) => {
                    let filled = buf.filled();
                    progress = true;
                    *last_activity = Instant::now();
                    if filled.is_empty() {
                        conn.tcp_eof = true;
                        outbox.send(&Frame::Data {
                            stream: data_id,
                            fin: true,
                            data: Vec::new(),
                        });
                        break;
                    }
                    outbox.send(&Frame::Data {
                        stream: data_id,
                        fin: false,
                        data: filled.to_vec(),
                    });
                }
            }
        }
    }
    if conn.tcp_eof && conn.write_shut {
        outbox.send(&Frame::Data {
            stream: error_id,
            fin: true,
            data: Vec::new(),
        });
        return PairStep::Finished;
    }
    PairStep::Continue { progress }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (n, v) in pairs {
            map.append(HeaderName::from_static(n), HeaderValue::from_static(v));
        }
        map
    }

    /// CRI-6: 正しい Upgrade 要求は通り、`Connection` の複数トークンと大文字小文字の差を許す。
    #[test]
    fn cri6_negotiate_accepts_valid_upgrade() {
        let h = headers(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "spdy/3.1"),
            ("x-stream-protocol-version", "portforward.k8s.io"),
        ]);
        assert_eq!(negotiate(&h), Ok(()));
    }

    /// CRI-6: Upgrade の欠落・別プロトコル・別バージョンは固定の英文で拒否する。
    #[test]
    fn cri6_negotiate_rejects_bad_requests() {
        let proto = ("x-stream-protocol-version", "portforward.k8s.io");
        assert_eq!(
            negotiate(&headers(&[proto])),
            Err("upgrade to SPDY/3.1 is required")
        );
        assert_eq!(
            negotiate(&headers(&[
                ("connection", "Upgrade"),
                ("upgrade", "websocket"),
                proto
            ])),
            Err("upgrade to SPDY/3.1 is required")
        );
        assert_eq!(
            negotiate(&headers(&[
                ("connection", "Upgrade"),
                ("upgrade", "SPDY/3.1"),
                ("x-stream-protocol-version", "v4.channel.k8s.io"),
            ])),
            Err("unsupported stream protocol version")
        );
    }

    /// CRI-6: 101 応答は 3 つのヘッダを載せる。
    #[test]
    fn cri6_upgrade_response_headers() {
        let r = upgrade_response();
        assert_eq!(r.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(
            r.headers().get(CONNECTION).map(HeaderValue::as_bytes),
            Some(&b"Upgrade"[..])
        );
        assert_eq!(
            r.headers().get(UPGRADE).map(HeaderValue::as_bytes),
            Some(&b"SPDY/3.1"[..])
        );
        assert_eq!(
            r.headers()
                .get(HeaderName::from_static(STREAM_PROTOCOL_HEADER))
                .map(HeaderValue::as_bytes),
            Some(&b"portforward.k8s.io"[..])
        );
    }

    /// CRI-6: ポートの解析は 10 進の数字のみで 1..=65535。
    #[test]
    fn cri6_parse_port_is_strict() {
        assert_eq!(parse_port("1"), Some(1));
        assert_eq!(parse_port("65535"), Some(65535));
        for bad in [
            "", "0", "65536", "-1", "+80", " 80", "80 ", "0x50", "080000", "８０",
        ] {
            assert_eq!(parse_port(bad), None, "{bad:?}");
        }
    }

    /// CRI-6: 設定の境界を検証する。
    #[test]
    fn cri6_config_validation() {
        PortForwardConfig::default().validate().expect("default ok");
        let bad = [
            PortForwardConfig {
                dial_timeout: Duration::ZERO,
                ..Default::default()
            },
            PortForwardConfig {
                max_streams: 1,
                ..Default::default()
            },
            PortForwardConfig {
                max_frame_bytes: 10,
                ..Default::default()
            },
            PortForwardConfig {
                max_pending_bytes: 10,
                ..Default::default()
            },
            PortForwardConfig {
                max_inflight_dials: 0,
                ..Default::default()
            },
            PortForwardConfig {
                max_inflight_dials: 257,
                ..Default::default()
            },
        ];
        for cfg in bad {
            assert_eq!(
                cfg.validate().expect_err("bad").code(),
                crate::error::CriErrorCode::InvalidArgument
            );
        }
    }

    /// 門（フラグ）が開くまで blocking プール上で待つ dialer（枠の共有の試験用）。
    struct BlockingDialer {
        open: Arc<std::sync::atomic::AtomicBool>,
    }

    impl PortForwardDialer for BlockingDialer {
        fn dial(
            &self,
            _pod_sandbox_id: &str,
            _port: u16,
            _timeout: Duration,
        ) -> Result<std::net::TcpStream, CriError> {
            while !self.open.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(CriError::invalid_argument("test dial refused"))
        }
    }

    /// CRI-6・REPAIR-5・TASK-63.4: 遅い dial を残したままセッションを張り直しても、
    /// 同時に走る blocking の dial はハンドラの上限（ここでは 2）を超えず、future を捨てても
    /// blocking 処理が終わるまで枠は返らない。
    #[tokio::test]
    async fn cri6_dial_slots_are_shared_across_sessions_until_blocking_ends() {
        let open = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let dialer: Arc<dyn PortForwardDialer> = Arc::new(BlockingDialer {
            open: Arc::clone(&open),
        });
        let handler = PortForwardHandler::new(
            Arc::clone(&dialer),
            PortForwardConfig {
                max_inflight_dials: 2,
                ..Default::default()
            },
        )
        .expect("handler");
        let limit = handler.config.max_inflight_dials;
        assert_eq!(limit, 2);

        // セッション 1 と、張り直したセッション 2 が同じ枠（ハンドラ共有）を使う。
        let mut handles = Vec::new();
        for _session in 0..2 {
            let slot = DialSlot::acquire(&handler.dial_inflight, limit);
            assert!(slot.is_some());
            let fut = make_dial(
                Arc::clone(&dialer),
                "sb".to_string(),
                80,
                Duration::from_millis(50),
                slot,
            );
            handles.push(tokio::spawn(fut));
        }
        for h in handles {
            // timeout で future は完了・破棄されるが、blocking は門で止まったまま。
            assert!(h.await.expect("join").is_err());
        }
        assert_eq!(handler.dial_inflight.load(Ordering::Acquire), 2);
        assert!(DialSlot::acquire(&handler.dial_inflight, limit).is_none());

        open.store(true, Ordering::Release);
        for _ in 0..300 {
            if handler.dial_inflight.load(Ordering::Acquire) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(handler.dial_inflight.load(Ordering::Acquire), 0);
        assert!(DialSlot::acquire(&handler.dial_inflight, limit).is_some());
    }
}
