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
//! cri は名前空間の具象（setns・pod ネットワークの保持役）を知らない層のため、cri は接続の注入点と中継までを
//! 持つ。本番の dialer は NODE ネットワーク（hostNetwork）の pod だけ plugin-cri が実装する（#3755）。
//! POD ネットワークの pod は保持役（#2877）と helper 方式（#3766）まで `UNIMPLEMENTED` である（REPAIR-3）。
//! 既定でホストの `127.0.0.1` へつなぐ実装は cri には置かない（URL を知る者にホストのローカルサービスを
//! 晒す経路になるため。NODE に限って plugin-cri だけが置く）。
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
    Frame, FrameDecoder, FrameEncoder, Headers, MAX_INCOMING_PAYLOAD, SpdyError, StreamId,
    goaway_status, rst_status,
};
use super::{
    ConnectionPermit, StreamBody, StreamHandler, StreamKind, StreamRequest, StreamWiring,
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

/// 転送先の pod のネットワーク種別（CRI-6・SEC-1・#3755）。
///
/// `runtime_service` が RPC 時に sandbox の記録（`namespace_options.network`）から決め、発行時の要求に
/// 保存する。NODE（hostNetwork）と判定できたときだけ `Node` で、それ以外はすべて `Pod`（fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortForwardNetwork {
    /// host の network namespace を使う pod。host の loopback へ接続する。
    Node,
    /// pod 専用の network namespace を使う pod。保持役（#2877）が入るまで未実装（#3766）。
    Pod,
}

/// [`PortForwardDialer::dial`] に渡す転送先（保存済み要求の値。URL やヘッダから組み立て直さない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortForwardTarget {
    pod_sandbox_id: String,
    network: PortForwardNetwork,
}

impl PortForwardTarget {
    /// 転送先を作る。
    pub fn new(pod_sandbox_id: impl Into<String>, network: PortForwardNetwork) -> Self {
        Self {
            pod_sandbox_id: pod_sandbox_id.into(),
            network,
        }
    }

    /// sandbox ID。
    pub fn pod_sandbox_id(&self) -> &str {
        &self.pod_sandbox_id
    }

    /// pod のネットワーク種別。
    pub fn network(&self) -> PortForwardNetwork {
        self.network
    }
}

/// 転送先への TCP 接続の注入点。cri は名前空間の具象を知らない（CRI-7・PLUG-1）。
///
/// `StreamingServer` の Upgrade 後のタスクが `spawn_blocking` 上で呼ぶ（ブロッキングで構わない）。
/// 実装は `target` の pod のネットワーク内の `port` へ接続する。`target.network()` が実装の対応外
/// （POD など）なら `UNIMPLEMENTED` を返す。エラーにパス・内部情報を含めない。`timeout` を超えて待たないこと。
/// 呼び出し全体にも [`PortForwardConfig::dial_timeout`] の期限が掛かる。
pub trait PortForwardDialer: Send + Sync + 'static {
    /// 転送先へ接続する。
    fn dial(
        &self,
        target: &PortForwardTarget,
        port: u16,
        timeout: Duration,
    ) -> Result<std::net::TcpStream, CriError>;

    /// POD ネットワークの pod にも接続できるか。既定は false（fail-closed）。
    ///
    /// 真を返す実装を注入したときだけ、POD の pod の PortForward RPC が URL を発行する（#3766 が使う）。
    fn supports_pod_network(&self) -> bool {
        false
    }
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
    /// 受け取る DATA の 1 フレームあたりの最大バイト数（1024..=`MAX_INCOMING_PAYLOAD`）。既定は共通 codec の上限（256 KiB）。
    pub max_frame_bytes: usize,
    /// 転送先への書き込み滞留量（全対の合計）と送信キューの上限。超えている間は SPDY 接続の読み取りを止める
    /// （バックプレッシャー。1 フレームが上限を超えても、`max_frame_bytes` 以内なら受け取って TCP へ排出する）。既定 256 KiB。
    pub max_pending_bytes: usize,
    /// 転送先への書き込みが 1 バイトも進まないまま滞留が続いてよい時間（REPAIR-5）。既定 30 秒。
    ///
    /// 転送先が TCP を読まないと、滞留が上限に達して SPDY 接続全体の読み取りが止まり、同じ接続の別の対の
    /// DATA・新規 SYN_STREAM・RST_STREAM も処理できなくなる。この期間を超えた対は RST_STREAM(CANCEL) で閉じて
    /// 滞留分を捨て、受信を再開する。書き込みが進んでいる間（遅いが読んでいる転送先）は打ち切らない。
    pub write_stall_timeout: Duration,
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
            max_frame_bytes: MAX_INCOMING_PAYLOAD,
            max_pending_bytes: 256 * 1024,
            write_stall_timeout: Duration::from_secs(30),
            max_inflight_dials: 32,
        }
    }
}

impl PortForwardConfig {
    /// 設定を検証する（fail-closed）。
    pub fn validate(&self) -> Result<(), CriError> {
        if self.dial_timeout.is_zero()
            || self.pair_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.write_stall_timeout.is_zero()
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
        if !(1024..=MAX_INCOMING_PAYLOAD).contains(&self.max_frame_bytes) {
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

/// `PortForward` 要求だけを扱う [`StreamHandler`]。
///
/// 他の種別と同居させるときは [`super::StreamDispatcher::with_port_forward`] に登録する。
/// `PortForward` 以外の要求が届いた場合は 501 を返す（振り分けを誤った構成を実装済みと偽らない）。
pub struct PortForwardHandler {
    dialer: Arc<dyn PortForwardDialer>,
    config: PortForwardConfig,
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
            observer: Arc::new(NoopPortForwardObserver),
            dial_inflight: Arc::new(AtomicUsize::new(0)),
        })
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
        network: PortForwardNetwork,
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
        let target = PortForwardTarget::new(request.pod_sandbox_id, network);
        tokio::spawn(async move {
            let started = Instant::now();
            let end = match on_upgrade.await {
                Ok(upgraded) => {
                    match Session::new(
                        TokioIo::new(upgraded),
                        dialer,
                        target,
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
    fn wiring(&self) -> StreamWiring {
        let wiring = StreamWiring::only(StreamKind::PortForward);
        if self.dialer.supports_pod_network() {
            wiring.with_port_forward_pod_network()
        } else {
            wiring
        }
    }

    fn handle(
        &self,
        request: StreamRequest,
        http: Request<Incoming>,
        permit: ConnectionPermit,
    ) -> Pin<Box<dyn Future<Output = Response<StreamBody>> + Send + '_>> {
        match request {
            StreamRequest::PortForward { request, network } => {
                let response = self.start(request, network, http, permit);
                Box::pin(async move { response })
            }
            _ => Box::pin(async {
                plain_response(
                    StatusCode::NOT_IMPLEMENTED,
                    "streaming protocol is not implemented",
                )
            }),
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
    /// 転送先への書き込みが失敗（EPIPE・ECONNRESET・0 バイト）した時刻。以後は書き込みを諦めて、転送先から
    /// 受信済みの残りを読み切ってから閉じる。読み切りは `write_stall_timeout` で打ち切る（CRI-6・TASK-63.4）。
    write_broken: Option<Instant>,
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
    /// 転送先への書き込みが最後に進んだ時刻（滞留が 0 から増えた時刻でも更新する）。滞留の打ち切りに使う。
    last_write: Instant,
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
    enc: FrameEncoder,
    failed: bool,
}

impl Outbox {
    fn send(&mut self, frame: &Frame) {
        let before = self.buf.len();
        if self.enc.encode(frame, &mut self.buf).is_err() {
            // 途中まで書いた分を残さない（圧縮文脈は壊れたので、呼び出し側が接続を閉じる）。
            self.buf.truncate(before);
            self.failed = true;
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
    target: PortForwardTarget,
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
        target: PortForwardTarget,
        allowed: Vec<u16>,
        config: PortForwardConfig,
        dial_inflight: Arc<AtomicUsize>,
    ) -> Option<Self> {
        let tick_every = (config
            .pair_timeout
            .min(config.idle_timeout)
            .min(config.write_stall_timeout)
            / 4)
        .clamp(Duration::from_millis(10), Duration::from_secs(1));
        Some(Self {
            io,
            decoder: FrameDecoder::new(),
            outbox: Outbox {
                buf: Vec::new(),
                pos: 0,
                failed: false,
                enc: FrameEncoder::new(),
            },
            streams: HashMap::new(),
            last_syn_id: 0,
            pairs: HashMap::new(),
            dialer,
            target,
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
                goaway_status::PROTOCOL_ERROR
            } else {
                goaway_status::OK
            };
            self.outbox.send(&Frame::GoAway {
                last_good_stream_id: 0,
                status,
            });
        }
    }

    fn finish_for(&mut self, err: SpdyError) {
        match err {
            SpdyError::FrameTooLarge | SpdyError::HeaderBlockTooLarge => {
                self.finish(PortForwardEnd::LimitExceeded)
            }
            _ => self.finish(PortForwardEnd::ProtocolError),
        }
    }

    /// クライアントが読まない間に PING・SYN_STREAM 等への応答で送信キューが膨らまないよう、
    /// 送信キューが上限を超えている間は読み取りも止める（REPAIR-5。止まったままなら idle で終わる）。
    /// 転送先へ未書き込みの滞留が全対の合計で上限に達している間も読み取りを止める（バックプレッシャー）。
    /// 止まったままにならないよう、書き込みが [`PortForwardConfig::write_stall_timeout`] の間進まない対は
    /// `housekeeping` が閉じて滞留を捨てる（転送先が読まない対が接続全体を塞がない）。
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
        // 転送先が読まない対の滞留を打ち切る。放置すると `can_read` が false のまま続き、同じ接続の別の対の
        // DATA・RST_STREAM も処理できなくなる（CRI-6・REPAIR-5・TASK-63.4）。
        let stalled: Vec<String> = self
            .pairs
            .iter()
            .filter(|(_, p)| {
                match &p.phase {
                    Phase::Connected(c) => {
                        (p.pending() > 0
                            && now.duration_since(p.last_write) >= self.config.write_stall_timeout)
                            // 書き込み失敗後の読み切りも同じ期限で打ち切る（読み手が止まった場合の歯止め）。
                            || c.write_broken.is_some_and(|t| {
                                now.duration_since(t) >= self.config.write_stall_timeout
                            })
                    }
                    _ => false,
                }
            })
            .map(|(k, _)| k.clone())
            .collect();
        for key in stalled {
            self.abort_pair(&key, None);
        }
    }

    /// SPDY 接続から読んでフレームを処理する。進捗があれば true。
    fn poll_read_io(&mut self, cx: &mut Context<'_>) -> bool {
        let mut chunk = [0u8; READ_CHUNK];
        // 復号器は 1 回の読み取りの後に取り出せるだけ取り出すので、溜まるのは未完の 1 フレーム
        // （`MAX_INCOMING_PAYLOAD` で有界）と今回の読み取り分だけになる。
        let mut buf = ReadBuf::new(&mut chunk);
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
                self.decoder.extend(filled);
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
            stream_id: stream,
            status: rst_status::REFUSED_STREAM,
        });
    }

    fn on_frame(&mut self, frame: Frame) {
        match frame {
            Frame::SynStream {
                stream_id,
                headers,
                fin,
                ..
            } => self.on_syn_stream(stream_id, &headers, fin),
            Frame::Data {
                stream_id: stream,
                fin,
                data,
            } => {
                if data.len() > self.config.max_frame_bytes {
                    self.finish(PortForwardEnd::LimitExceeded);
                    return;
                }
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
                            stream_id: stream,
                            status: rst_status::PROTOCOL_ERROR,
                        });
                        self.abort_pair(&key, Some(stream));
                        return;
                    }
                    if pair.pending() == 0 {
                        pair.last_write = Instant::now();
                    }
                    pair.to_tcp.extend_from_slice(&data);
                    if fin {
                        pair.peer_fin = true;
                    }
                } else {
                    // 未知のストリーム、または error ストリームへの DATA。
                    self.outbox.send(&Frame::RstStream {
                        stream_id: stream,
                        status: rst_status::PROTOCOL_ERROR,
                    });
                }
            }
            Frame::RstStream {
                stream_id: stream, ..
            } => {
                if let Some((key, _)) = self.streams.get(&stream.get()).cloned() {
                    self.abort_pair(&key, Some(stream));
                }
            }
            Frame::Ping { id } => self.outbox.send(&Frame::Ping { id }),
            Frame::GoAway { .. } => self.finish(PortForwardEnd::Completed),
            // SETTINGS・WINDOW_UPDATE・HEADERS・未知の制御フレームは読み飛ばす（フロー制御は持たない）。
            Frame::SynReply { .. }
            | Frame::Settings { .. }
            | Frame::Headers { .. }
            | Frame::WindowUpdate { .. }
            | Frame::Unknown { .. } => {}
        }
    }

    fn on_syn_stream(&mut self, stream: StreamId, headers: &Headers, fin: bool) {
        // クライアント起点のストリーム ID は奇数で、重複しない。
        if stream.get().is_multiple_of(2)
            || stream.get() <= self.last_syn_id
            || self.streams.contains_key(&stream.get())
        {
            self.finish(PortForwardEnd::ProtocolError);
            return;
        }
        self.last_syn_id = stream.get();
        let find = |name: &str| headers.get(name);
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
                last_write: Instant::now(),
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
            stream_id: stream,
            fin: false,
            headers: Headers::new(),
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
                self.target.clone(),
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
                        stream_id: id,
                        status: rst_status::CANCEL,
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
    target: PortForwardTarget,
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
            dialer.dial(&target, port, timeout)
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
        last_write,
        phase,
        ..
    } = pair;
    let mut progress = false;
    if let Phase::Dialing(fut) = phase {
        match fut.as_mut().poll(cx) {
            Poll::Pending => return PairStep::Continue { progress: false },
            Poll::Ready(Ok(tcp)) => {
                *last_write = Instant::now();
                *phase = Phase::Connected(Connected {
                    tcp,
                    write_shut: false,
                    tcp_eof: false,
                    write_broken: None,
                });
                progress = true;
            }
            Poll::Ready(Err(())) => {
                // 固定の英文のみ（内部情報を含めない）。
                outbox.send(&Frame::Data {
                    stream_id: error_id,
                    fin: true,
                    data: format!("error forwarding port {port}: connection failed").into_bytes(),
                });
                outbox.send(&Frame::Data {
                    stream_id: data_id,
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
    // クライアント → TCP。書き込みが失敗しても即 Aborted にせず、転送先が閉じる前に書いた応答の残りを
    // 後段の読み取りで読み切ってから閉じる（RST_STREAM でなくデータと FIN を届ける。CRI-6・TASK-63.4）。
    if conn.write_broken.is_some() {
        to_tcp.clear();
        *to_tcp_pos = 0;
    }
    while conn.write_broken.is_none()
        && let Some(rest) = to_tcp.get(*to_tcp_pos..).filter(|r| !r.is_empty())
    {
        match Pin::new(&mut conn.tcp).poll_write(cx, rest) {
            Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => {
                conn.write_broken = Some(Instant::now());
                conn.write_shut = true;
                to_tcp.clear();
                *to_tcp_pos = 0;
                progress = true;
            }
            Poll::Ready(Ok(n)) => {
                *to_tcp_pos += n;
                *last_write = Instant::now();
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
                            stream_id: data_id,
                            fin: true,
                            data: Vec::new(),
                        });
                        break;
                    }
                    outbox.send(&Frame::Data {
                        stream_id: data_id,
                        fin: false,
                        data: filled.to_vec(),
                    });
                }
            }
        }
    }
    if conn.tcp_eof && conn.write_shut {
        outbox.send(&Frame::Data {
            stream_id: error_id,
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

    /// POD 対応を宣言する dialer（結線情報の試験用）。
    struct PodCapableDialer;

    impl PortForwardDialer for PodCapableDialer {
        fn dial(
            &self,
            _target: &PortForwardTarget,
            _port: u16,
            _timeout: Duration,
        ) -> Result<std::net::TcpStream, CriError> {
            Err(CriError::unavailable("unused"))
        }
        fn supports_pod_network(&self) -> bool {
            true
        }
    }

    /// CRI-6・REPAIR-3・#3755: `supports_pod_network` が既定（偽）の dialer では結線情報に POD 対応が立たず、
    /// 真を返す dialer のときだけ立つ。
    #[test]
    fn cri6_3755_wiring_pod_network_follows_dialer() {
        let open = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let plain = PortForwardHandler::new(
            Arc::new(BlockingDialer { open }),
            PortForwardConfig::default(),
        )
        .expect("handler");
        assert!(plain.wiring().is_wired(StreamKind::PortForward));
        assert!(!plain.wiring().port_forward_pod_network());
        let capable =
            PortForwardHandler::new(Arc::new(PodCapableDialer), PortForwardConfig::default())
                .expect("handler");
        assert!(capable.wiring().port_forward_pod_network());
    }

    /// 門（フラグ）が開くまで blocking プール上で待つ dialer（枠の共有の試験用）。
    struct BlockingDialer {
        open: Arc<std::sync::atomic::AtomicBool>,
    }

    impl PortForwardDialer for BlockingDialer {
        fn dial(
            &self,
            _target: &PortForwardTarget,
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
                PortForwardTarget::new("sb", PortForwardNetwork::Node),
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

    /// 転送先が応答を書いて閉じた後の対を 1 回進める。`rst` が真なら、転送先が未読の受信データを残して
    /// 閉じるので RST が返る（書き込み失敗を実際の RST で起こす）。偽なら、書き込み失敗を
    /// `write_broken` の直接設定で作り、RST を使わない。
    async fn drain_case(rst: bool) -> (PairStep, Vec<u8>) {
        use tokio::io::AsyncWriteExt;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let target = std::thread::spawn(move || {
            use std::io::Write;
            let (mut c, _) = listener.accept().expect("accept");
            c.write_all(b"tail-bytes").expect("write tail");
            rx.recv().expect("signal");
            // rst の場合は未読の受信データが残るため、close で相手へ RST が返る。
            drop(c);
        });
        let mut tcp = TcpStream::connect(addr).await.expect("connect");
        if rst {
            tcp.write_all(b"x").await.expect("first write");
        }
        tx.send(()).expect("signal");
        target.join().expect("target");
        tokio::time::sleep(Duration::from_millis(300)).await;

        let error_id = StreamId::new(1).expect("sid");
        let data_id = StreamId::new(3).expect("sid");
        let mut pair = Pair {
            port: 8080,
            error: Some(error_id),
            data: Some(data_id),
            created: Instant::now(),
            to_tcp: b"y".to_vec(),
            to_tcp_pos: 0,
            peer_fin: false,
            last_write: Instant::now(),
            phase: Phase::Connected(Connected {
                tcp,
                // 製品の書き込み失敗経路と同じく、失敗時は write_shut も立てる。
                write_shut: !rst,
                tcp_eof: false,
                write_broken: (!rst).then(Instant::now),
            }),
        };
        let mut outbox = Outbox {
            buf: Vec::new(),
            pos: 0,
            enc: FrameEncoder::new(),
            failed: false,
        };
        let mut scratch = vec![0u8; 4096];
        let config = PortForwardConfig::default();
        let mut last_activity = Instant::now();
        let step = std::future::poll_fn(|cx| {
            Poll::Ready(step_pair(
                &mut pair,
                &mut outbox,
                cx,
                &mut scratch,
                &config,
                &mut last_activity,
            ))
        })
        .await;
        (step, outbox.buf)
    }

    /// 送出済みフレームから、データストリーム 3 の DATA の連結と FIN を受けたストリーム ID の列を取り出す。
    fn decode_data(buf: &[u8]) -> (Vec<u8>, Vec<u32>) {
        let data_id = StreamId::new(3).expect("sid");
        let mut dec = FrameDecoder::new();
        dec.extend(buf);
        let mut got = Vec::new();
        let mut fins = Vec::new();
        while let Some(f) = dec.next_frame().expect("decode") {
            if let Frame::Data {
                stream_id,
                fin,
                data,
            } = f
            {
                if stream_id == data_id {
                    got.extend(data);
                }
                if fin {
                    fins.push(stream_id.get());
                }
            }
        }
        (got, fins)
    }

    /// 転送先が応答を書いて閉じ、その後クライアントの書き込みが失敗しても、残りの応答を DATA として届けて
    /// FIN で閉じる（RST_STREAM 相当の `Aborted` にしない）。CRI-6・TASK-63.4。
    /// 書き込み失敗は `write_broken` の直接設定で作る。RST に頼ると受信バッファの扱いが OS で異なる
    /// （下の `cri6_rst_discards_tail_per_platform`）ため、どの OS でも同じ結果になる形にしている。
    #[tokio::test]
    async fn cri6_write_failure_still_drains_target_tail() {
        let (step, buf) = drain_case(false).await;
        match step {
            PairStep::Finished => {}
            PairStep::Aborted => panic!("aborted: remaining target data was dropped"),
            PairStep::Continue { .. } => panic!("expected the pair to finish"),
        }
        let (got, fins) = decode_data(&buf);
        assert_eq!(got, b"tail-bytes");
        assert_eq!(fins, vec![3, 1]);
    }

    /// 転送先が未読データを残して close し RST を返した場合の挙動は OS で異なる。Linux は RST の前に受信済みの
    /// データを読ませるので残りを届けて閉じる。macOS（BSD）と Windows は RST を受けた時点で受信バッファを
    /// 捨てて `ECONNRESET` を返すため、製品は取り戻せないデータを `Aborted`（RST_STREAM）で扱う。
    /// どちらも製品として正しい挙動で、OS ごとの期待を明示して固定する。CRI-6・TASK-63.4。
    #[tokio::test]
    async fn cri6_rst_discards_tail_per_platform() {
        let (step, buf) = drain_case(true).await;
        if cfg!(target_os = "linux") {
            assert!(matches!(step, PairStep::Finished), "linux drains the tail");
            let (got, fins) = decode_data(&buf);
            assert_eq!(got, b"tail-bytes");
            assert_eq!(fins, vec![3, 1]);
        } else {
            assert!(
                matches!(step, PairStep::Aborted),
                "the receive buffer is discarded on RST outside linux"
            );
        }
    }
}
