//! CRI のストリーミングサーバー基盤と URL 発行（CRI-6・TASK-63.1・#679。判断は #678、設計記録は
//! `docs/design/cri-streaming-server.md`）。
//!
//! `Exec`・`Attach`・`PortForward` の RPC 自体はデータを流さず、kubelet / apiserver が後から HTTP で接続する
//! 「ストリーミングサーバーの URL」を返すだけである。本モジュールはその URL の発行（[`StreamingUrlIssuer`]）と、
//! URL を受ける HTTP/1.1 サーバー（[`StreamingServer`]）の土台を持つ。呼び出し元は
//! `runtime_service::CriRuntimeService` の `exec`・`attach`・`port_forward`（`with_streaming` で注入したときだけ）と、
//! 将来サーバーを起動して注入する `fandhe-container-plugin-cri`（後続の issue）。
//!
//! ## 未実装（REPAIR-3）
//!
//! 有効なトークンへの要求は、種別ごとのハンドラが無ければ [`NotImplementedHandler`] が `501 Not Implemented` を返す。
//! Attach は #681（TASK-63.3）が SPDY/3.1 の codec（[`spdy`]）・remotecommand の交渉（[`remotecommand`]）・
//! セッション（[`attach`]）を実装済みだが、実行中コンテナの stdio を渡す本番の `attach::AttachBackend` は未接続で、
//! 注入しない構成では 501 のまま。Exec は #680（TASK-63.2）、PortForward は #682（TASK-63.4）が
//! [`StreamDispatcher`] へハンドラを足して実装する。
//!
//! ## 安全側の既定
//!
//! - 待ち受けは loopback だけ。外部のアドレスは [`StreamingConfig::allow_external`] を明示したときだけ許す
//!   （TLS も認証も無いため、外へ出すなら前段で守ること）
//! - URL のトークンは OS の乱数から 256 ビット。単回使用で、TTL（既定 60 秒）で失効し、同時に保持できる件数に上限がある
//! - 照合に失敗した要求（未知・失効・使用済み・種別違い）はすべて同じ `404` にする（探索の手がかりを与えない）
//! - ヘッダ読み取り・接続全体・同時接続数に上限を設ける（REPAIR-5）

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{ALLOW, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::error::CriError;
use crate::runtime::v1;

pub mod attach;
pub mod port_forward;
pub mod remotecommand;
pub mod spdy;
mod spdy_dictionary;

/// トークン（小文字 hex）の長さ。32 バイトの乱数を 2 桁ずつ展開する。
const TOKEN_HEX_LEN: usize = 64;
/// 受け付けるパスの最大長（バイト）。`/portforward/` + トークンより十分大きい固定の上限。
const MAX_PATH_BYTES: usize = 256;
/// トークンの衝突時に引き直す最大回数。
const MAX_TOKEN_RETRIES: usize = 3;
/// 1 接続の読み取りバッファの上限（バイト。hyper の下限は 8192）。
const MAX_HEADER_BUF_BYTES: usize = 16 * 1024;
/// `token_ttl` の上限。kubelet のトークン TTL（1 分）より十分長い値で頭打ちにする。
pub const MAX_TOKEN_TTL: Duration = Duration::from_secs(600);

/// 要求に含める ID の最大長（バイト）。
const MAX_ID_BYTES: usize = 256;
/// `ExecRequest.cmd` の最大件数。
const MAX_EXEC_ARGS: usize = 256;
/// `ExecRequest.cmd` の引数全体の最大バイト数。
const MAX_EXEC_CMD_BYTES: usize = 64 * 1024;
/// `PortForwardRequest.port` の最大件数。
const MAX_FORWARD_PORTS: usize = 64;

/// ストリーミングの種別。URL のパスの接頭辞に対応する（kubelet の streaming server と同じ形）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamKind {
    /// `/exec/<token>`。
    Exec,
    /// `/attach/<token>`。
    Attach,
    /// `/portforward/<token>`。
    PortForward,
}

impl StreamKind {
    /// URL のパスの接頭辞（スラッシュなし）。
    pub fn path_prefix(self) -> &'static str {
        match self {
            StreamKind::Exec => "exec",
            StreamKind::Attach => "attach",
            StreamKind::PortForward => "portforward",
        }
    }

    fn from_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "exec" => Some(StreamKind::Exec),
            "attach" => Some(StreamKind::Attach),
            "portforward" => Some(StreamKind::PortForward),
            _ => None,
        }
    }
}

/// 発行時に保存する要求。消費側（#680〜#682）が URL ではなくこの値から処理を組み立てる（URL 経由で改ざんされない。CRI-6）。
#[derive(Debug, Clone, PartialEq)]
pub enum StreamRequest {
    /// `RuntimeService.Exec` の要求。
    Exec(v1::ExecRequest),
    /// `RuntimeService.Attach` の要求。
    Attach(v1::AttachRequest),
    /// `RuntimeService.PortForward` の要求。
    PortForward(v1::PortForwardRequest),
}

impl StreamRequest {
    /// この要求の種別。
    pub fn kind(&self) -> StreamKind {
        match self {
            StreamRequest::Exec(_) => StreamKind::Exec,
            StreamRequest::Attach(_) => StreamKind::Attach,
            StreamRequest::PortForward(_) => StreamKind::PortForward,
        }
    }
}

/// ストリーミングサーバーの設定（CRI-6・TASK-63.1）。既定値は安全側（loopback・短い TTL・上限あり）。
#[derive(Debug, Clone)]
pub struct StreamingConfig {
    /// 待ち受けアドレス。既定は `127.0.0.1:0`（OS が空きポートを選ぶ）。
    pub bind: SocketAddr,
    /// loopback 以外のアドレスでの待ち受けを許すか。既定は false（明示の opt-in。TLS も認証も無い）。
    pub allow_external: bool,
    /// 発行 URL に埋め込む広告アドレス（IP）。`bind` がワイルドカード（`0.0.0.0`・`::`）のときは必須
    /// （kubelet から到達できない `http://0.0.0.0:port` を発行しないため。CRI-6）。ポートは実際の待ち受けポートを使う。
    pub advertise_addr: Option<IpAddr>,
    /// トークンの有効期間。既定は 60 秒（kubelet のトークンキャッシュの TTL に合わせる）。
    pub token_ttl: Duration,
    /// 同時に保持できる未消費トークンの上限。既定は 1000（kubelet の上限に合わせる）。
    pub max_in_flight: usize,
    /// HTTP ヘッダの読み取り期限。既定は 10 秒（REPAIR-5）。
    pub header_read_timeout: Duration,
    /// 同時に受け付ける接続数の上限。既定は 64。超えた接続は即座に閉じる。
    pub max_connections: usize,
    /// Upgrade 後に必要なストリームが揃うまでの期限。既定は 30 秒（kubelet の既定。TASK-63.3・REPAIR-5）。
    pub stream_creation_timeout: Duration,
    /// Upgrade 後にどちら向きにもフレームが流れない期間の上限。既定は 4 時間（kubelet の既定。
    /// Attach はシェルを開いたまま長時間放置され得るため長い。TASK-63.3・REPAIR-5）。
    pub stream_idle_timeout: Duration,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            allow_external: false,
            advertise_addr: None,
            token_ttl: Duration::from_secs(60),
            max_in_flight: 1000,
            header_read_timeout: Duration::from_secs(10),
            max_connections: 64,
            stream_creation_timeout: Duration::from_secs(30),
            stream_idle_timeout: Duration::from_secs(4 * 60 * 60),
        }
    }
}

impl StreamingConfig {
    /// 待ち受けアドレスを指定する。
    pub fn with_bind(mut self, bind: SocketAddr) -> Self {
        self.bind = bind;
        self
    }

    /// 外部アドレスでの待ち受けを許すかを指定する。
    pub fn with_allow_external(mut self, allow_external: bool) -> Self {
        self.allow_external = allow_external;
        self
    }

    /// 発行 URL の広告アドレスを指定する。
    pub fn with_advertise_addr(mut self, advertise_addr: IpAddr) -> Self {
        self.advertise_addr = Some(advertise_addr);
        self
    }

    /// トークンの有効期間を指定する。
    pub fn with_token_ttl(mut self, token_ttl: Duration) -> Self {
        self.token_ttl = token_ttl;
        self
    }

    /// 未消費トークンの上限を指定する。
    pub fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }

    /// ヘッダ読み取りの期限を指定する。
    pub fn with_header_read_timeout(mut self, header_read_timeout: Duration) -> Self {
        self.header_read_timeout = header_read_timeout;
        self
    }

    /// 同時接続数の上限を指定する。
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// ストリーム作成の期限を指定する。
    pub fn with_stream_creation_timeout(mut self, stream_creation_timeout: Duration) -> Self {
        self.stream_creation_timeout = stream_creation_timeout;
        self
    }

    /// Upgrade 後の idle の期限を指定する。
    pub fn with_stream_idle_timeout(mut self, stream_idle_timeout: Duration) -> Self {
        self.stream_idle_timeout = stream_idle_timeout;
        self
    }

    /// Upgrade 後のセッションの期限（ハンドラ構築用。作成・idle 以外は既定値）。
    pub fn session_limits(&self) -> remotecommand::SessionLimits {
        remotecommand::SessionLimits {
            stream_creation_timeout: self.stream_creation_timeout,
            stream_idle_timeout: self.stream_idle_timeout,
            ..remotecommand::SessionLimits::default()
        }
    }

    /// 設定を検証する（fail-closed）。外部アドレス（`0.0.0.0`・`::` を含む）は `allow_external` が無ければ拒否する。
    pub fn validate(&self) -> Result<(), CriError> {
        if !self.bind.ip().is_loopback() && !self.allow_external {
            return Err(CriError::invalid_argument(
                "streaming server address must be loopback unless external exposure is explicitly enabled",
            ));
        }
        if let Some(adv) = self.advertise_addr
            && (adv.is_unspecified() || adv.is_multicast())
        {
            return Err(CriError::invalid_argument(
                "streaming advertise address must be a concrete unicast address",
            ));
        }
        if self.bind.ip().is_unspecified() && self.advertise_addr.is_none() {
            return Err(CriError::invalid_argument(
                "streaming advertise address is required when binding a wildcard address",
            ));
        }
        if self.token_ttl.is_zero() || self.token_ttl > MAX_TOKEN_TTL {
            return Err(CriError::invalid_argument(
                "streaming token ttl must be between 1ns and 600s",
            ));
        }
        if self.max_in_flight == 0 {
            return Err(CriError::invalid_argument(
                "streaming max_in_flight must be positive",
            ));
        }
        if self.max_connections == 0 {
            return Err(CriError::invalid_argument(
                "streaming max_connections must be positive",
            ));
        }
        if self.header_read_timeout.is_zero() {
            return Err(CriError::invalid_argument(
                "streaming header_read_timeout must be positive",
            ));
        }
        self.session_limits().validate()?;
        Ok(())
    }
}

/// 256 ビットの乱数を小文字 hex（64 文字）で返す。unix では `/dev/urandom` を読む。
///
/// 文字デバイスであることを確かめ、そうでなければ失敗にする（fail-closed）。新しい `unsafe` は使わない。
#[cfg(unix)]
fn random_token() -> Result<String, CriError> {
    use std::io::Read;
    use std::os::unix::fs::FileTypeExt;

    let unavailable = || CriError::unavailable("secure random source is not available");
    let mut file = std::fs::File::open("/dev/urandom").map_err(|_| unavailable())?;
    let is_char = file
        .metadata()
        .map(|m| m.file_type().is_char_device())
        .unwrap_or(false);
    if !is_char {
        return Err(unavailable());
    }
    let mut buf = [0u8; TOKEN_HEX_LEN / 2];
    file.read_exact(&mut buf).map_err(|_| unavailable())?;
    Ok(hex_lower(&buf))
}

/// unix 以外では安全な乱数源を用意していないため、弱い代替を作らずに失敗させる（CRI-6・fail-closed）。
#[cfg(not(unix))]
fn random_token() -> Result<String, CriError> {
    Err(CriError::unavailable(
        "secure random source is not available on this platform",
    ))
}

#[cfg(unix)]
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

struct TokenEntry {
    kind: StreamKind,
    request: StreamRequest,
    expires_at: Instant,
}

/// 未消費トークンの表。単回使用・TTL・件数上限を一手に持つ（CRI-6）。
///
/// 時刻は引数で受け、テストでは決定的な `Instant` を渡す。`Debug` はトークンを出さず件数だけ出す。
pub struct TokenCache {
    entries: Mutex<HashMap<String, TokenEntry>>,
    ttl: Duration,
    max_in_flight: usize,
}

impl fmt::Debug for TokenCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.entries.lock().map(|e| e.len()).ok();
        f.debug_struct("TokenCache")
            .field("entries", &len)
            .field("ttl", &self.ttl)
            .field("max_in_flight", &self.max_in_flight)
            .finish()
    }
}

impl TokenCache {
    /// 有効期間と件数上限を指定して作る。
    pub fn new(ttl: Duration, max_in_flight: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            max_in_flight,
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, TokenEntry>>, CriError> {
        self.entries
            .lock()
            .map_err(|_| CriError::internal("streaming token cache is unavailable"))
    }

    /// 期限切れを掃除してから要求を登録し、トークンを返す。`generate` は衝突時に最大 3 回まで引き直す。
    pub fn issue_at(
        &self,
        now: Instant,
        request: StreamRequest,
        mut generate: impl FnMut() -> Result<String, CriError>,
    ) -> Result<String, CriError> {
        let mut entries = self.lock()?;
        entries.retain(|_, e| e.expires_at > now);
        if entries.len() >= self.max_in_flight {
            return Err(CriError::resource_exhausted(
                "too many in-flight streaming requests",
            ));
        }
        let expires_at = now
            .checked_add(self.ttl)
            .ok_or_else(|| CriError::internal("streaming token expiry overflow"))?;
        for _ in 0..=MAX_TOKEN_RETRIES {
            let token = generate()?;
            if entries.contains_key(&token) {
                continue;
            }
            entries.insert(
                token.clone(),
                TokenEntry {
                    kind: request.kind(),
                    request,
                    expires_at,
                },
            );
            return Ok(token);
        }
        Err(CriError::internal("streaming token collision"))
    }

    /// トークンを消費して保存済みの要求を返す。見つかれば（種別違い・期限切れでも）必ず取り除く（単回使用）。
    /// 期限切れ・種別の不一致・未知は `None`。
    pub fn consume_at(&self, now: Instant, kind: StreamKind, token: &str) -> Option<StreamRequest> {
        let entry = self.entries.lock().ok()?.remove(token)?;
        (entry.kind == kind && entry.expires_at > now).then_some(entry.request)
    }

    /// 現在の保持件数（期限切れを含む。テスト・観測用）。
    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// 保持件数が 0 か。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// ストリーミング URL の発行口。`runtime_service` の `exec`・`attach`・`port_forward` が呼ぶ（CRI-6・TASK-63.1）。
///
/// 呼ぶたびに新しいトークンを作るため、コンテナ単位で URL を使い回さない。
pub struct StreamingUrlIssuer {
    base_url: String,
    cache: Arc<TokenCache>,
}

impl fmt::Debug for StreamingUrlIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingUrlIssuer")
            .field("base_url", &self.base_url)
            .field("cache", &self.cache)
            .finish()
    }
}

impl StreamingUrlIssuer {
    /// 要求を保存して URL（`http://<addr>/<kind>/<token>`）を返す。
    pub fn issue(&self, request: StreamRequest) -> Result<String, CriError> {
        let kind = request.kind();
        let token = self.cache.issue_at(Instant::now(), request, random_token)?;
        Ok(format!(
            "{}/{}/{}",
            self.base_url,
            kind.path_prefix(),
            token
        ))
    }

    /// URL の基底（`http://<addr>`）。
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// 応答の本体。`http-body-util` を直接依存にしないための、空または固定の短い英語メッセージ専用の型。
#[derive(Debug)]
pub struct StreamBody {
    data: Option<Bytes>,
}

impl StreamBody {
    /// 空の本体。
    pub fn empty() -> Self {
        Self { data: None }
    }

    /// 固定メッセージの本体。
    pub fn text(message: &'static str) -> Self {
        Self {
            data: Some(Bytes::from_static(message.as_bytes())),
        }
    }
}

impl Body for StreamBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.data.take().map(|b| Ok(Frame::data(b))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        let len = self.data.as_ref().map_or(0, |b| b.len());
        SizeHint::with_exact(u64::try_from(len).unwrap_or(0))
    }
}

fn plain_response(status: StatusCode, message: &'static str) -> Response<StreamBody> {
    let mut response = Response::new(StreamBody::text(message));
    *response.status_mut() = status;
    response
}

/// トークンの照合に成功した要求の処理口（拡張点）。
///
/// #680（Exec）・#681（Attach）・#682（PortForward）が実装し、`Upgrade` 後の SPDY/3.1 を扱う。
/// Upgrade 後の idle の期限もそちらが決める。本モジュールの接続全体の期限（`header_read_timeout * 3`）は
/// Upgrade しない要求のためのもので、101 応答で `Upgraded` へ IO を渡した接続には及ばない
/// （接続の future が Upgrade の引き渡しで完了するため。#679）。
pub trait StreamHandler: Send + Sync + 'static {
    /// 照合済みの要求と HTTP 要求（`hyper::upgrade::on` に渡せる）から応答を作る。
    ///
    /// `permit` は同時接続数（`max_connections`）の枠を表す。101 応答で `Upgraded` へ IO を渡すと
    /// サーバー側の接続タスクは終わるため、Upgrade 後の IO を使うタスクは `permit` を move して
    /// IO の寿命まで保持すること（落とすとその時点で枠が返り、上限の契約が破れる。CRI-6・REPAIR-5）。
    fn handle(
        &self,
        request: StreamRequest,
        http: Request<Incoming>,
        permit: ConnectionPermit,
    ) -> Pin<Box<dyn Future<Output = Response<StreamBody>> + Send + '_>>;
}

/// 既定のハンドラ。常に `501 Not Implemented` を返す（SPDY/3.1 は #680〜#682。REPAIR-3）。
#[derive(Debug, Default, Clone, Copy)]
pub struct NotImplementedHandler;

impl StreamHandler for NotImplementedHandler {
    fn handle(
        &self,
        _request: StreamRequest,
        _http: Request<Incoming>,
        _permit: ConnectionPermit,
    ) -> Pin<Box<dyn Future<Output = Response<StreamBody>> + Send + '_>> {
        Box::pin(async {
            plain_response(
                StatusCode::NOT_IMPLEMENTED,
                "streaming protocol is not implemented",
            )
        })
    }
}

/// 種別ごとに [`StreamHandler`] を振り分けるハンドラ（CRI-6・TASK-63.3）。
///
/// `StreamingServer::bind_with_handler` は 1 つのハンドラしか受けないため、Attach（#681）・Exec（#680）・
/// PortForward（#682）が同じサーバーに同居するための合流点になる。設定していない種別は
/// [`NotImplementedHandler`] と同じ `501` を返す（実装済みを装わない。REPAIR-3）。
#[derive(Default)]
pub struct StreamDispatcher {
    attach: Option<Arc<dyn StreamHandler>>,
    exec: Option<Arc<dyn StreamHandler>>,
    port_forward: Option<Arc<dyn StreamHandler>>,
}

impl fmt::Debug for StreamDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamDispatcher")
            .field("attach", &self.attach.is_some())
            .field("exec", &self.exec.is_some())
            .field("port_forward", &self.port_forward.is_some())
            .finish()
    }
}

impl StreamDispatcher {
    /// どの種別も未設定（全て 501）で作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach のハンドラを設定する。
    pub fn with_attach(mut self, handler: Arc<dyn StreamHandler>) -> Self {
        self.attach = Some(handler);
        self
    }

    /// Exec のハンドラを設定する（#680 が使う）。
    pub fn with_exec(mut self, handler: Arc<dyn StreamHandler>) -> Self {
        self.exec = Some(handler);
        self
    }

    /// PortForward のハンドラを設定する（#682 が使う）。
    pub fn with_port_forward(mut self, handler: Arc<dyn StreamHandler>) -> Self {
        self.port_forward = Some(handler);
        self
    }
}

impl StreamHandler for StreamDispatcher {
    fn handle(
        &self,
        request: StreamRequest,
        http: Request<Incoming>,
        permit: ConnectionPermit,
    ) -> Pin<Box<dyn Future<Output = Response<StreamBody>> + Send + '_>> {
        let handler = match request.kind() {
            StreamKind::Attach => self.attach.as_ref(),
            StreamKind::Exec => self.exec.as_ref(),
            StreamKind::PortForward => self.port_forward.as_ref(),
        };
        match handler {
            Some(handler) => handler.handle(request, http, permit),
            None => NotImplementedHandler.handle(request, http, permit),
        }
    }
}

/// パスと HTTP メソッドの分類結果。
#[derive(Debug, PartialEq, Eq)]
enum Route<'a> {
    MethodNotAllowed,
    NotFound,
    Stream { kind: StreamKind, token: &'a str },
}

/// ルーティングの純関数。トークンは小文字 hex の 64 文字以外を照合の前に `NotFound` にする。
fn classify<'a>(method: &Method, path: &'a str) -> Route<'a> {
    if method != Method::GET && method != Method::POST {
        return Route::MethodNotAllowed;
    }
    if path.len() > MAX_PATH_BYTES {
        return Route::NotFound;
    }
    let Some((prefix, token)) = path.strip_prefix('/').and_then(|p| p.split_once('/')) else {
        return Route::NotFound;
    };
    let Some(kind) = StreamKind::from_prefix(prefix) else {
        return Route::NotFound;
    };
    let valid = token.len() == TOKEN_HEX_LEN
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if valid {
        Route::Stream { kind, token }
    } else {
        Route::NotFound
    }
}

async fn route(
    request: Request<Incoming>,
    cache: &TokenCache,
    handler: &dyn StreamHandler,
    permit: ConnectionPermit,
) -> Response<StreamBody> {
    let matched = match classify(request.method(), request.uri().path()) {
        Route::MethodNotAllowed => {
            let mut response = plain_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            response
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET, POST"));
            return response;
        }
        Route::NotFound => None,
        Route::Stream { kind, token } => cache.consume_at(Instant::now(), kind, token),
    };
    match matched {
        Some(stream_request) => handler.handle(stream_request, request, permit).await,
        // 未知・失効・使用済み・種別違いを区別しない（探索の手がかりを与えない）。
        None => plain_response(StatusCode::NOT_FOUND, "not found"),
    }
}

/// 同時接続数の計数ガード。破棄で枠を返す。
struct ConnectionGuard(Arc<AtomicUsize>);

impl ConnectionGuard {
    fn acquire(counter: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        if counter.fetch_add(1, Ordering::AcqRel) >= max {
            counter.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Self(Arc::clone(counter)))
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// 同時接続数の枠の保持票（複製可。最後の複製が落ちたときに枠が返る）。
///
/// サーバーは接続の future が終わるまで 1 つ持ち、[`StreamHandler::handle`] にも 1 つ渡す。
/// Upgrade 後の IO を扱うタスクがこれを保持し続ける間は枠が返らない。
#[derive(Clone)]
pub struct ConnectionPermit {
    _guard: Arc<ConnectionGuard>,
}

impl fmt::Debug for ConnectionPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionPermit")
    }
}

/// 接続処理の結果（トークン・パス・相手アドレスは含めない。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOutcome {
    /// 接続の future が正常に終わった（Upgrade の引き渡しを含む）。
    Completed,
    /// HTTP の解析・読み書きの失敗（ヘッダ読み取りの期限切れを含む）。
    HttpError,
    /// 接続全体の期限（`header_read_timeout * 3`）で打ち切った。
    DeadlineExceeded,
}

/// 接続の観測イベント（REPAIR-4）。メトリクス・構造化ログの注入点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// `accept` の失敗。
    AcceptFailed,
    /// 同時接続数の上限超過で接続を閉じた。
    Rejected,
    /// 接続処理が終わった。`elapsed` は受け付けてから接続の future が終わるまで。
    Finished {
        /// 結果。
        outcome: ConnectionOutcome,
        /// 所要時間。
        elapsed: Duration,
    },
}

/// [`ConnectionEvent`] の受け口。同期・短時間で返すこと（accept のタスクから呼ばれる）。
pub trait ConnectionObserver: Send + Sync + 'static {
    /// イベントを記録する。
    fn observe(&self, event: ConnectionEvent);
}

/// 何も記録しない既定の観測口。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl ConnectionObserver for NoopObserver {
    fn observe(&self, _event: ConnectionEvent) {}
}

/// 発行 URL の基底（`http://host:port`。IPv6 は括弧つき）。ソケットを要さない純関数。
fn format_base_url(advertised: SocketAddr) -> String {
    format!("http://{advertised}")
}

/// 起動済みのストリーミングサーバー。破棄または [`Self::shutdown`] で待ち受けを止める。
///
/// 既に受け付けた接続は各自の期限（ヘッダ読み取りと接続全体）で終わる。
pub struct StreamingServer {
    local_addr: SocketAddr,
    issuer: Arc<StreamingUrlIssuer>,
    accept_task: JoinHandle<()>,
}

impl fmt::Debug for StreamingServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingServer")
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

impl StreamingServer {
    /// 既定のハンドラ（501）で起動する。tokio の実行時の中で呼ぶ。
    pub async fn bind(config: StreamingConfig) -> Result<Self, CriError> {
        Self::bind_with_handler(config, Arc::new(NotImplementedHandler)).await
    }

    /// ハンドラを指定して起動する（#680〜#682 が使う）。設定を検証してから待ち受ける（fail-closed）。
    pub async fn bind_with_handler(
        config: StreamingConfig,
        handler: Arc<dyn StreamHandler>,
    ) -> Result<Self, CriError> {
        Self::bind_with_observer(config, handler, Arc::new(NoopObserver)).await
    }

    /// ハンドラと観測口を指定して起動する（REPAIR-4）。
    pub async fn bind_with_observer(
        config: StreamingConfig,
        handler: Arc<dyn StreamHandler>,
        observer: Arc<dyn ConnectionObserver>,
    ) -> Result<Self, CriError> {
        config.validate()?;
        let listener = TcpListener::bind(config.bind)
            .await
            .map_err(|_| CriError::unavailable("failed to bind streaming server"))?;
        let local_addr = listener
            .local_addr()
            .map_err(|_| CriError::unavailable("failed to read streaming server address"))?;
        let cache = Arc::new(TokenCache::new(config.token_ttl, config.max_in_flight));
        let advertised = match config.advertise_addr {
            Some(ip) => SocketAddr::new(ip, local_addr.port()),
            None => local_addr,
        };
        let issuer = Arc::new(StreamingUrlIssuer {
            base_url: format_base_url(advertised),
            cache: Arc::clone(&cache),
        });
        let conns = Arc::new(AtomicUsize::new(0));
        let accept_task = tokio::spawn(accept_loop(
            listener, config, cache, handler, conns, observer,
        ));
        Ok(Self {
            local_addr,
            issuer,
            accept_task,
        })
    }

    /// 実際の待ち受けアドレス。
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// URL の発行口。`CriRuntimeService::with_streaming` へ渡す。
    pub fn issuer(&self) -> Arc<StreamingUrlIssuer> {
        Arc::clone(&self.issuer)
    }

    /// 待ち受けを止める。
    pub fn shutdown(self) {
        drop(self);
    }
}

impl Drop for StreamingServer {
    fn drop(&mut self) {
        self.accept_task.abort();
    }
}

async fn accept_loop(
    listener: TcpListener,
    config: StreamingConfig,
    cache: Arc<TokenCache>,
    handler: Arc<dyn StreamHandler>,
    conns: Arc<AtomicUsize>,
    observer: Arc<dyn ConnectionObserver>,
) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _peer)) => stream,
            Err(_) => {
                observer.observe(ConnectionEvent::AcceptFailed);
                // fd 枯渇などの一時的な失敗でビジー再試行しない。
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Some(guard) = ConnectionGuard::acquire(&conns, config.max_connections) else {
            drop(stream);
            observer.observe(ConnectionEvent::Rejected);
            continue;
        };
        let cache = Arc::clone(&cache);
        let handler = Arc::clone(&handler);
        let observer = Arc::clone(&observer);
        let header_read_timeout = config.header_read_timeout;
        tokio::spawn(async move {
            let started = Instant::now();
            let permit = ConnectionPermit {
                _guard: Arc::new(guard),
            };
            let service_permit = permit.clone();
            let service = service_fn(move |request| {
                let cache = Arc::clone(&cache);
                let handler = Arc::clone(&handler);
                let permit = service_permit.clone();
                async move {
                    Ok::<_, Infallible>(route(request, &cache, handler.as_ref(), permit).await)
                }
            });
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_read_timeout)
                .max_buf_size(MAX_HEADER_BUF_BYTES)
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades();
            // Upgrade しない要求の接続全体の期限（REPAIR-5）。hyper の `with_upgrades` 付き接続の future は、
            // 101 応答の送出後に IO を `Upgraded` へ渡した時点で完了する。よって Upgrade 後のストリームは
            // この期限の対象外で、期限は #680〜#682 が決める（試験 `cri6_upgraded_connection_survives_overall_deadline`）。
            let deadline = header_read_timeout.saturating_mul(3);
            let outcome = match tokio::time::timeout(deadline, connection).await {
                Ok(Ok(())) => ConnectionOutcome::Completed,
                Ok(Err(_)) => ConnectionOutcome::HttpError,
                Err(_) => ConnectionOutcome::DeadlineExceeded,
            };
            observer.observe(ConnectionEvent::Finished {
                outcome,
                elapsed: started.elapsed(),
            });
            // permit はここまで保持する。Upgrade 後の IO を持つタスクが複製を持つ間は枠が返らない。
            drop(permit);
        });
    }
}

fn check_id(value: &str, what: &'static str) -> Result<(), CriError> {
    if value.is_empty() {
        return Err(CriError::invalid_argument(format!("{what} is required")));
    }
    if value.len() > MAX_ID_BYTES {
        return Err(CriError::invalid_argument(format!("{what} is too long")));
    }
    Ok(())
}

/// `ExecRequest` の入力検証（存在照合の前。深い意味検証は #680）。
pub fn validate_exec_request(req: &v1::ExecRequest) -> Result<(), CriError> {
    check_id(&req.container_id, "container_id")?;
    if req.cmd.is_empty() {
        return Err(CriError::invalid_argument("cmd is required"));
    }
    if req.cmd.len() > MAX_EXEC_ARGS {
        return Err(CriError::invalid_argument("cmd has too many arguments"));
    }
    let total = req
        .cmd
        .iter()
        .fold(0usize, |acc, a| acc.saturating_add(a.len()));
    if total > MAX_EXEC_CMD_BYTES {
        return Err(CriError::invalid_argument("cmd is too large"));
    }
    if !(req.stdin || req.stdout || req.stderr) {
        return Err(CriError::invalid_argument(
            "one of stdin, stdout, or stderr must be set",
        ));
    }
    Ok(())
}

/// `AttachRequest` の入力検証（存在照合の前。CRI-6・TASK-63.3・#681）。
///
/// CRI の定義（`AttachRequest.stderr`）は tty のとき stderr を false に固定している（stdout と合流するため）。
/// 守らない要求は `INVALID_ARGUMENT`。接続時のハンドラは kubelet に合わせて、tty の stderr を無視する。
pub fn validate_attach_request(req: &v1::AttachRequest) -> Result<(), CriError> {
    check_id(&req.container_id, "container_id")?;
    if req.tty && req.stderr {
        return Err(CriError::invalid_argument(
            "stderr must be false when tty is set",
        ));
    }
    if !(req.stdin || req.stdout || req.stderr) {
        return Err(CriError::invalid_argument(
            "one of stdin, stdout, or stderr must be set",
        ));
    }
    Ok(())
}

/// `PortForwardRequest` の入力検証（存在照合の前。到達性の検証は #682）。
pub fn validate_port_forward_request(req: &v1::PortForwardRequest) -> Result<(), CriError> {
    check_id(&req.pod_sandbox_id, "pod_sandbox_id")?;
    if req.port.len() > MAX_FORWARD_PORTS {
        return Err(CriError::invalid_argument("too many ports"));
    }
    if req.port.iter().any(|p| !(1..=65535).contains(p)) {
        return Err(CriError::invalid_argument(
            "port must be between 1 and 65535",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec_req() -> StreamRequest {
        StreamRequest::Exec(v1::ExecRequest {
            container_id: "c1".to_string(),
            cmd: vec!["sh".to_string()],
            tty: false,
            stdin: false,
            stdout: true,
            stderr: false,
        })
    }

    fn attach_req() -> StreamRequest {
        StreamRequest::Attach(v1::AttachRequest {
            container_id: "c1".to_string(),
            stdin: false,
            tty: false,
            stdout: true,
            stderr: false,
        })
    }

    fn counter_gen() -> impl FnMut() -> Result<String, CriError> {
        let mut n = 0u32;
        move || {
            n += 1;
            Ok(format!("{n:064x}"))
        }
    }

    /// CRI-6: 同じ要求の 2 回の発行でトークンも URL も異なり、トークンは 64 文字の小文字 hex。
    #[cfg(unix)]
    #[test]
    fn cri6_token_unique_per_issue() {
        let issuer = StreamingUrlIssuer {
            base_url: "http://127.0.0.1:1".to_string(),
            cache: Arc::new(TokenCache::new(Duration::from_secs(60), 10)),
        };
        let a = issuer.issue(exec_req()).expect("issue a");
        let b = issuer.issue(exec_req()).expect("issue b");
        assert_ne!(a, b);
        for url in [&a, &b] {
            let token = url
                .strip_prefix("http://127.0.0.1:1/exec/")
                .expect("url prefix");
            assert_eq!(token.len(), 64);
            assert!(
                token
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            );
        }
    }

    /// CRI-6: unix 以外では乱数源が無く、弱い代替を作らずに `Unavailable` になる。
    #[cfg(not(unix))]
    #[test]
    fn cri6_issue_unavailable_without_random_source() {
        let issuer = StreamingUrlIssuer {
            base_url: "http://127.0.0.1:1".to_string(),
            cache: Arc::new(TokenCache::new(Duration::from_secs(60), 10)),
        };
        let err = issuer.issue(exec_req()).expect_err("must fail");
        assert_eq!(err.code(), crate::error::CriErrorCode::Unavailable);
    }

    /// CRI-6: TTL ちょうど手前までは消費でき、過ぎると `None`。
    #[test]
    fn cri6_token_expires_after_ttl() {
        let ttl = Duration::from_secs(60);
        let t0 = Instant::now();
        let cache = TokenCache::new(ttl, 10);
        let ms = Duration::from_millis(1);
        let t_ok = cache
            .issue_at(t0, exec_req(), counter_gen())
            .expect("issue");
        assert!(
            cache
                .consume_at(t0 + ttl - ms, StreamKind::Exec, &t_ok)
                .is_some()
        );
        let t_late = cache
            .issue_at(t0, exec_req(), || Ok(format!("{:064x}", 99)))
            .expect("issue");
        assert!(
            cache
                .consume_at(t0 + ttl + ms, StreamKind::Exec, &t_late)
                .is_none()
        );
    }

    /// CRI-6: 単回使用。
    #[test]
    fn cri6_token_single_use() {
        let t0 = Instant::now();
        let cache = TokenCache::new(Duration::from_secs(60), 10);
        let token = cache
            .issue_at(t0, exec_req(), counter_gen())
            .expect("issue");
        assert_eq!(
            cache.consume_at(t0, StreamKind::Exec, &token),
            Some(exec_req())
        );
        assert_eq!(cache.consume_at(t0, StreamKind::Exec, &token), None);
    }

    /// CRI-6: 種別違いの消費は `None` になり、トークンも消える。
    #[test]
    fn cri6_token_kind_mismatch_consumes() {
        let t0 = Instant::now();
        let cache = TokenCache::new(Duration::from_secs(60), 10);
        let token = cache
            .issue_at(t0, exec_req(), counter_gen())
            .expect("issue");
        assert_eq!(cache.consume_at(t0, StreamKind::Attach, &token), None);
        assert_eq!(cache.consume_at(t0, StreamKind::Exec, &token), None);
        assert!(cache.is_empty());
    }

    /// CRI-6: 件数上限で `ResourceExhausted`、期限が切れれば再び発行できる。
    #[test]
    fn cri6_in_flight_cap() {
        let ttl = Duration::from_secs(10);
        let t0 = Instant::now();
        let cache = TokenCache::new(ttl, 2);
        let mut idgen = counter_gen();
        cache.issue_at(t0, exec_req(), &mut idgen).expect("1");
        cache.issue_at(t0, attach_req(), &mut idgen).expect("2");
        let err = cache
            .issue_at(t0, exec_req(), &mut idgen)
            .expect_err("3rd must fail");
        assert_eq!(err.code(), crate::error::CriErrorCode::ResourceExhausted);
        cache
            .issue_at(t0 + ttl + Duration::from_millis(1), exec_req(), &mut idgen)
            .expect("after expiry");
    }

    /// CRI-6: トークンの衝突は引き直し、引き直しても衝突し続ければ `Internal`。
    #[test]
    fn cri6_token_collision_retries_then_fails() {
        let t0 = Instant::now();
        let cache = TokenCache::new(Duration::from_secs(60), 10);
        let same = || Ok("a".repeat(64));
        cache.issue_at(t0, exec_req(), same).expect("first");
        let err = cache
            .issue_at(t0, exec_req(), same)
            .expect_err("always colliding");
        assert_eq!(err.code(), crate::error::CriErrorCode::Internal);
        let mut calls = 0;
        let token = cache
            .issue_at(t0, exec_req(), || {
                calls += 1;
                Ok(if calls < 3 {
                    "a".repeat(64)
                } else {
                    "b".repeat(64)
                })
            })
            .expect("retry succeeds");
        assert_eq!(token, "b".repeat(64));
    }

    /// CRI-6: `Debug` にトークンを出さない。
    #[test]
    fn cri6_debug_does_not_leak_token() {
        let cache = TokenCache::new(Duration::from_secs(60), 10);
        let token = cache
            .issue_at(Instant::now(), exec_req(), counter_gen())
            .expect("issue");
        assert!(!format!("{cache:?}").contains(&token));
    }

    /// CRI-6: loopback 以外は opt-in が無ければ拒否、opt-in すれば通る。loopback は既定のまま通る。
    #[test]
    fn cri6_config_rejects_external_without_opt_in() {
        for addr in ["0.0.0.0:0", "192.0.2.1:0", "[::]:0"] {
            let cfg = StreamingConfig::default().with_bind(addr.parse().expect("addr"));
            let err = cfg.validate().expect_err(addr);
            assert_eq!(err.code(), crate::error::CriErrorCode::InvalidArgument);
            let cfg = cfg
                .with_allow_external(true)
                .with_advertise_addr("192.0.2.7".parse().expect("ip"));
            cfg.validate().expect("opt-in allows");
        }
        for addr in ["127.0.0.1:0", "[::1]:0"] {
            StreamingConfig::default()
                .with_bind(addr.parse().expect("addr"))
                .validate()
                .expect(addr);
        }
    }

    /// CRI-6: ワイルドカード bind は広告アドレスが無ければ拒否し、広告アドレスが未指定アドレスでも拒否する。
    #[test]
    fn cri6_config_wildcard_requires_advertise() {
        for addr in ["0.0.0.0:0", "[::]:0"] {
            let base = StreamingConfig::default()
                .with_bind(addr.parse().expect("addr"))
                .with_allow_external(true);
            let err = base.validate().expect_err(addr);
            assert_eq!(err.code(), crate::error::CriErrorCode::InvalidArgument);
            let bad = base
                .clone()
                .with_advertise_addr("0.0.0.0".parse().expect("ip"));
            assert!(bad.validate().is_err());
            base.with_advertise_addr("192.0.2.7".parse().expect("ip"))
                .validate()
                .expect("advertise ok");
        }
    }

    /// CRI-6: ワイルドカード bind でも発行 URL は広告アドレスと実ポートで組み立てる（IPv6 は括弧つき）。
    #[tokio::test]
    async fn cri6_base_url_uses_advertise_addr() {
        let server = StreamingServer::bind(
            StreamingConfig::default()
                .with_bind("0.0.0.0:0".parse().expect("addr"))
                .with_allow_external(true)
                .with_advertise_addr("192.0.2.7".parse().expect("ip")),
        )
        .await
        .expect("bind");
        let port = server.local_addr().port();
        assert_eq!(
            server.issuer().base_url(),
            format!("http://192.0.2.7:{port}")
        );
        // IPv6 の表現はソケットを要さない純関数で必ず照合する（環境の IPv6 可否に依らない）。
        assert_eq!(
            format_base_url("[2001:db8::1]:8443".parse().expect("addr")),
            "http://[2001:db8::1]:8443"
        );
    }

    /// CRI-6: TTL の 0 と上限超過は拒否する。
    #[test]
    fn cri6_config_rejects_bad_ttl() {
        for ttl in [Duration::ZERO, MAX_TOKEN_TTL + Duration::from_secs(1)] {
            let err = StreamingConfig::default()
                .with_token_ttl(ttl)
                .validate()
                .expect_err("bad ttl");
            assert_eq!(err.code(), crate::error::CriErrorCode::InvalidArgument);
        }
        StreamingConfig::default()
            .with_token_ttl(MAX_TOKEN_TTL)
            .validate()
            .expect("max ttl ok");
    }

    /// CRI-6: ルーティングの分類（メソッド・長さ・接頭辞・トークン形式）。
    #[test]
    fn cri6_classify_routes() {
        let tok = "0123456789abcdef".repeat(4);
        assert_eq!(
            classify(&Method::GET, &format!("/exec/{tok}")),
            Route::Stream {
                kind: StreamKind::Exec,
                token: &tok
            }
        );
        assert_eq!(
            classify(&Method::POST, &format!("/portforward/{tok}")),
            Route::Stream {
                kind: StreamKind::PortForward,
                token: &tok
            }
        );
        assert_eq!(
            classify(&Method::DELETE, &format!("/exec/{tok}")),
            Route::MethodNotAllowed
        );
        assert_eq!(classify(&Method::GET, "/unknown/abc"), Route::NotFound);
        assert_eq!(classify(&Method::GET, "/exec/xyz"), Route::NotFound);
        assert_eq!(
            classify(&Method::GET, &format!("/exec/{}", tok.to_uppercase())),
            Route::NotFound
        );
        assert_eq!(
            classify(&Method::GET, &format!("/exec/{tok}/extra")),
            Route::NotFound
        );
        let long = format!("/exec/{}", "a".repeat(300));
        assert_eq!(classify(&Method::GET, &long), Route::NotFound);
        assert_eq!(classify(&Method::GET, "/"), Route::NotFound);
    }

    /// CRI-6: 要求の入力検証の境界。
    #[test]
    fn cri6_request_validation() {
        let ok = v1::ExecRequest {
            container_id: "c".into(),
            cmd: vec!["ls".into()],
            tty: false,
            stdin: false,
            stdout: true,
            stderr: false,
        };
        validate_exec_request(&ok).expect("ok");
        let mut none = ok.clone();
        none.stdout = false;
        assert!(validate_exec_request(&none).is_err());
        let mut empty_cmd = ok.clone();
        empty_cmd.cmd.clear();
        assert!(validate_exec_request(&empty_cmd).is_err());
        let mut many = ok.clone();
        many.cmd = vec!["x".into(); MAX_EXEC_ARGS + 1];
        assert!(validate_exec_request(&many).is_err());

        let pf = v1::PortForwardRequest {
            pod_sandbox_id: "p".into(),
            port: vec![1, 65535],
        };
        validate_port_forward_request(&pf).expect("ok");
        for bad in [0, 65536, -1] {
            let r = v1::PortForwardRequest {
                pod_sandbox_id: "p".into(),
                port: vec![bad],
            };
            assert!(validate_port_forward_request(&r).is_err(), "port={bad}");
        }
    }
}
