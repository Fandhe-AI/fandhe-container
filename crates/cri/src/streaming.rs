//! CRI のストリーミングサーバー基盤と URL 発行（CRI-6・TASK-63.1・#679。判断は #678、設計記録は
//! `docs/design/cri-streaming-server.md`）。
//!
//! `Exec`・`Attach`・`PortForward` の RPC 自体はデータを流さず、kubelet / apiserver が後から HTTP で接続する
//! 「ストリーミングサーバーの URL」を返すだけである。本モジュールはその URL の発行（[`StreamingUrlIssuer`]）と、
//! URL を受ける HTTP/1.1 サーバー（[`StreamingServer`]）の土台を持つ。呼び出し元は
//! `runtime_service::CriRuntimeService` の `exec`・`attach`・`port_forward`（`with_streaming` で注入したときだけ）と、
//! サーバーを起動して注入する `fandhe-container-plugin-cri` の `streaming`（#3754）。
//!
//! ## 未実装（REPAIR-3）
//!
//! 結線していない種別（[`StreamHandler::wiring`] が答えない種別）の URL は発行しない。`Exec`・`Attach`・
//! `PortForward` の RPC は [`StreamingUrlIssuer::require_wired`] で `UNIMPLEMENTED` になり、URL を返してから
//! HTTP の 501 にする形にはしない（#3753・REPAIR-3）。多層防御として、有効なトークンへの要求でハンドラが
//! 無い種別は [`NotImplementedHandler`] が `501 Not Implemented` を返す（issuer を経る通常の経路では到達しない）。
//! Attach は #681（TASK-63.3）が SPDY/3.1 の codec（[`spdy`]）・remotecommand の交渉（[`remotecommand`]）・
//! セッション（[`attach`]）を実装済みで、実行中コンテナの stdio を渡す本番の `attach::AttachBackend` は
//! plugin-cri が注入した構成だけ結線する（Linux は完全版の `streaming::supervisor_attach`〔kind 9 の tap と fd。
//! #4077・#4078〕、非 Linux は読み取り専用の `streaming::log_attach`〔回転ログの follow。#3763〕。実機の通しは
//! plugin-cri の `tests/cri_attach_real.rs`〔#4079〕）。Exec は #680（TASK-63.2）の [`exec::ExecStreamHandler`] が
//! 同じ SPDY codec・交渉を使って実装済みで、stdio を持つ起動役 [`exec::ExecStreamLauncher`] の本番の実装は
//! plugin-cri の `streaming::exec_launcher`（supervisor の `stream-exec` helper 経由。#3761）にあり、Linux で
//! 注入した構成だけ結線する（実機の通しは plugin-cri の `tests/cri_exec_real.rs`〔#3762〕）。backend・起動役を
//! 注入しない構成（`with_streaming` の無い構成・非 Linux の Exec など）では、RPC は URL を返さず `UNIMPLEMENTED` のまま。
//! PortForward は #682（TASK-63.4）が実装し、NODE ネットワークの pod だけ plugin-cri が
//! 本番の dialer を注入する（#3755）。POD ネットワークの pod は、`supports_pod_network` が真の dialer を注入した構成（本番は plugin-cri の保持役のある構成の `PodNetnsDialer`。#3766・#4486）だけ結線し、それ以外は `UNIMPLEMENTED`。
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
use tokio::task::{AbortHandle, JoinHandle};

use crate::error::CriError;
use crate::runtime::v1;

pub mod attach;
pub mod exec;
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
/// attach の `stdin` 要求に対し、作成時に stdin を開いていないコンテナを断る固定文（#4078 の D7。
/// supervisor の kind 9 の `StdinNotOpen` と同じ文言。コンテナ ID・要求の中身は含めない）。
pub const MSG_ATTACH_STDIN_NOT_OPEN: &str = "the container was not created with stdin open";

/// attach の `tty` 要求がコンテナの端末構成と食い違うときの固定文（#4078 の D7。`TtyMismatch` と同じ文言）。
pub const MSG_ATTACH_TTY_MISMATCH: &str = "the requested tty mode does not match the container";

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
    /// `RuntimeService.Exec` の要求。`instance` は URL 発行時に実行層が報告したコンテナの
    /// インスタンス識別子（[`crate::adapter::RuntimeContainerStatus::instance`]。#4286・CRI-5・SEC-1・CORE-1）。
    /// 起動役が起動時に同じ状態読み取りで得た値と [`crate::adapter::instance_matches`] で比べる。
    /// `None` は報告なし（スタブ経路・識別子を報告しない実装・記録の無い旧い状態）。
    /// core の newtype ではなく `Option<u64>` なのは cri の境界の型に揃えるため。
    Exec {
        /// CRI の要求。
        request: v1::ExecRequest,
        /// 発行時のインスタンス識別子。
        instance: Option<u64>,
    },
    /// `RuntimeService.Attach` の要求。
    Attach(v1::AttachRequest),
    /// `RuntimeService.PortForward` の要求。`network` は RPC 時に sandbox の記録から決めた値で、
    /// 消費側（[`port_forward::PortForwardHandler`]）が dialer へ渡す（#3755）。
    PortForward {
        /// CRI の要求。
        request: v1::PortForwardRequest,
        /// 転送先の pod のネットワーク種別。
        network: port_forward::PortForwardNetwork,
    },
}

impl StreamRequest {
    /// インスタンス識別子を持たない（報告なしの）Exec 要求を作る。スタブ経路・試験用。
    pub fn exec(request: v1::ExecRequest) -> Self {
        StreamRequest::Exec {
            request,
            instance: None,
        }
    }

    /// この要求の種別。
    pub fn kind(&self) -> StreamKind {
        match self {
            StreamRequest::Exec { .. } => StreamKind::Exec,
            StreamRequest::Attach(_) => StreamKind::Attach,
            StreamRequest::PortForward { .. } => StreamKind::PortForward,
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
    /// 発行 URL に埋め込む広告アドレス（IP）。`bind` がワイルドカード（`0.0.0.0`・`::`・IPv4 射影形 `::ffff:0.0.0.0` を含む）のときは必須
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
    ///
    /// 広告アドレスは broadcast と IPv4 互換形 `::a.b.c.d`（`::` `::1` を除く）も拒否する（#4290）。
    /// 未指定・マルチキャスト・ワイルドカードの判定は `IpAddr::to_canonical()` で IPv4 射影形
    /// （`::ffff:0.0.0.0` 等）を IPv4 として扱う（到達できない URL の発行と広告アドレス必須の検査の
    /// すり抜けを防ぐ。CRI-6・SEC-1・#4238）。loopback の判定は正規化せず、`::ffff:127.0.0.1` は外部扱い
    /// （`allow_external` 必須）のままにする。緩める方向の変更をしないためと、plugin-cri の
    /// `streaming_is_consistent` の判定と揃えるため。
    pub fn validate(&self) -> Result<(), CriError> {
        let bind_canon = self.bind.ip().to_canonical();
        let adv_canon = self.advertise_addr.map(|a| a.to_canonical());
        if !self.bind.ip().is_loopback() && !self.allow_external {
            return Err(CriError::invalid_argument(
                "streaming server address must be loopback unless external exposure is explicitly enabled",
            ));
        }
        if let Some(adv) = adv_canon
            && (adv.is_unspecified() || adv.is_multicast() || is_unroutable_advertise(adv))
        {
            return Err(CriError::invalid_argument(
                "streaming advertise address must be a concrete unicast address",
            ));
        }
        if bind_canon.is_unspecified() && self.advertise_addr.is_none() {
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

/// 結線済みの種別の情報（CRI-6・REPAIR-3・#3753）。
///
/// [`StreamHandler::wiring`] が返し、[`StreamingUrlIssuer`] が起動時に 1 回だけ読む。結線していない種別の
/// RPC は URL を返さず `UNIMPLEMENTED` にする（URL を返してから 501 にしない。実装済みを装わない）。
/// 既定（[`Default`]）はどの種別も未結線で、宣言していない種別は出ない（fail-closed）。
///
/// 種別ごとの結線の有無に加え、attach が stdin・tty を受けるか（`attach_interactive`。#3763）と、PortForward が
/// POD ネットワークの pod にも対応するか（`port_forward_pod_network`。既定は偽で POD は `UNIMPLEMENTED`。#3755・#3766・#4486）を持つ。
/// exec が tty・相対 `argv[0]` を受けるか（`exec_tty`・`exec_relative_command`。いずれも既定 `false`。#3761）も持ち、
/// 受けないものは RPC 時に `INVALID_ARGUMENT` で断る（URL を返してから失敗させない。CRI-6・REPAIR-3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StreamWiring {
    exec: bool,
    attach: bool,
    port_forward: bool,
    /// attach が stdin・tty を扱えるか。既定は `false`（fail-closed。読み取り専用の backend が stdin・tty を黙って
    /// 無視する URL を出さない。REPAIR-3）。
    attach_interactive: bool,
    port_forward_pod_network: bool,
    /// exec が tty（pty）を扱えるか。既定は `false`（fail-closed。#3761）。
    exec_tty: bool,
    /// exec が相対パスの `argv[0]` を扱えるか。既定は `false`（fail-closed。PATH 解決の方式が決まるまで断る。#3761・#2439）。
    exec_relative_command: bool,
}

impl StreamWiring {
    /// どの種別も未結線。
    pub fn none() -> Self {
        Self::default()
    }

    /// 1 種別だけ結線済み。
    pub fn only(kind: StreamKind) -> Self {
        Self::none().with(kind)
    }

    /// 全種別が結線済み（PortForward の POD 対応を含む。試験用の「全機能」）。
    pub fn all() -> Self {
        Self::none()
            .with(StreamKind::Exec)
            .with(StreamKind::Attach)
            .with(StreamKind::PortForward)
            .with_attach_interactive()
            .with_port_forward_pod_network()
            .with_exec_tty()
            .with_exec_relative_command()
    }

    /// exec が tty を扱えると宣言して返す（Exec を結線済みにはしない）。
    pub fn with_exec_tty(mut self) -> Self {
        self.exec_tty = true;
        self
    }

    /// exec が tty を扱えるか（`false` なら RPC 時に `INVALID_ARGUMENT` で断る）。
    pub fn exec_tty(&self) -> bool {
        self.exec_tty
    }

    /// exec が相対パスの `argv[0]` を扱えると宣言して返す。
    pub fn with_exec_relative_command(mut self) -> Self {
        self.exec_relative_command = true;
        self
    }

    /// exec が相対パスの `argv[0]` を扱えるか（`false` なら RPC 時に `INVALID_ARGUMENT` で断る）。
    pub fn exec_relative_command(&self) -> bool {
        self.exec_relative_command
    }

    /// attach が stdin・tty を扱えると宣言して返す（Attach を結線済みにはしない）。
    pub fn with_attach_interactive(mut self) -> Self {
        self.attach_interactive = true;
        self
    }

    /// attach が stdin・tty を扱えるか（`false` なら RPC 時に `INVALID_ARGUMENT` で断る。#3763）。
    pub fn attach_interactive(&self) -> bool {
        self.attach_interactive
    }

    /// PortForward が POD ネットワークの pod にも対応することを宣言して返す。
    pub fn with_port_forward_pod_network(mut self) -> Self {
        self.port_forward_pod_network = true;
        self
    }

    /// PortForward が POD ネットワークの pod にも対応するか。
    pub fn port_forward_pod_network(&self) -> bool {
        self.port_forward_pod_network
    }

    /// `kind` を結線済みにして返す。
    pub fn with(mut self, kind: StreamKind) -> Self {
        match kind {
            StreamKind::Exec => self.exec = true,
            StreamKind::Attach => self.attach = true,
            StreamKind::PortForward => self.port_forward = true,
        }
        self
    }

    /// `kind` が結線済みか。
    pub fn is_wired(&self, kind: StreamKind) -> bool {
        match kind {
            StreamKind::Exec => self.exec,
            StreamKind::Attach => self.attach,
            StreamKind::PortForward => self.port_forward,
        }
    }
}

/// ストリーミング URL の発行口。`runtime_service` の `exec`・`attach`・`port_forward` が呼ぶ（CRI-6・TASK-63.1）。
///
/// 呼ぶたびに新しいトークンを作るため、コンテナ単位で URL を使い回さない。
///
/// 結線済みの種別（[`StreamHandler::wiring`] の起動時のスナップショット）だけ URL を発行する。未結線の種別は
/// [`StreamingUrlIssuer::require_wired`] で `UNIMPLEMENTED` になる（#3753・REPAIR-3）。
pub struct StreamingUrlIssuer {
    base_url: String,
    cache: Arc<TokenCache>,
    wiring: StreamWiring,
}

impl fmt::Debug for StreamingUrlIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingUrlIssuer")
            .field("base_url", &self.base_url)
            .field("cache", &self.cache)
            .field("wiring", &self.wiring)
            .finish()
    }
}

impl StreamingUrlIssuer {
    /// 結線済みの種別の情報。
    pub fn wiring(&self) -> StreamWiring {
        self.wiring
    }

    /// `kind` が結線済みか。
    pub fn is_wired(&self, kind: StreamKind) -> bool {
        self.wiring.is_wired(kind)
    }

    /// `kind` が未結線なら `UNIMPLEMENTED` を返す（REPAIR-3）。
    ///
    /// `runtime_service` の RPC が入力検証・存在照合より前に呼ぶ。メッセージは英語の固定文で、
    /// 要求の中身・トークンは含めない。
    pub fn require_wired(&self, kind: StreamKind) -> Result<(), CriError> {
        if self.wiring.is_wired(kind) {
            return Ok(());
        }
        Err(CriError::unimplemented(match kind {
            StreamKind::Exec => "exec streaming is not wired",
            StreamKind::Attach => "attach streaming is not wired",
            StreamKind::PortForward => "port-forward streaming is not wired",
        }))
    }

    /// attach の stdin・tty の要求を、backend が受けないとき `INVALID_ARGUMENT` で断る（#3763・REPAIR-3）。
    ///
    /// `runtime_service::attach_impl` が URL の発行より前に呼ぶ。メッセージは英語の固定文。
    pub fn require_attach_options(&self, stdin: bool, tty: bool) -> Result<(), CriError> {
        if (stdin || tty) && !self.wiring.attach_interactive() {
            return Err(CriError::invalid_argument(
                "attach with stdin or tty is not supported",
            ));
        }
        Ok(())
    }

    /// exec の tty・相対 `argv[0]` の要求を、起動役が受けないとき `INVALID_ARGUMENT` で断る（#3761・REPAIR-3・SEC-1）。
    ///
    /// `runtime_service::exec_impl` が URL の発行より前に呼ぶ。メッセージは英語の固定文で、argv を含めない。
    pub fn require_exec_options(&self, tty: bool, cmd: &[String]) -> Result<(), CriError> {
        if tty && !self.wiring.exec_tty() {
            return Err(CriError::invalid_argument("exec with tty is not supported"));
        }
        if !self.wiring.exec_relative_command()
            && let Some(first) = cmd.first()
            // コンテナ内のパスはホスト OS に依らない Unix 意味論なので、先頭が '/' かで判定する（Windows の `Path::is_absolute` は使わない）。
            && !first.starts_with('/')
        {
            return Err(CriError::invalid_argument(
                "exec command must be an absolute path",
            ));
        }
        Ok(())
    }

    /// PortForward の `network` が POD で未対応なら `UNIMPLEMENTED` を返す（REPAIR-3・#3755）。
    ///
    /// `runtime_service` が sandbox の照合の後、URL の発行の前に呼ぶ。固定の英語文で、ID を含めない。
    /// 保持役の記録の有無は、この後に `runtime_service` が検査する（#4485）。
    pub fn require_port_forward_network(
        &self,
        network: port_forward::PortForwardNetwork,
    ) -> Result<(), CriError> {
        if network == port_forward::PortForwardNetwork::Pod
            && !self.wiring.port_forward_pod_network()
        {
            return Err(CriError::unimplemented(
                "port-forward for pod network is not implemented",
            ));
        }
        Ok(())
    }

    /// 要求を保存して URL（`http://<addr>/<kind>/<token>`）を返す。
    ///
    /// 未結線の種別・未対応の PortForward の POD は、乱数源とトークン枠を消費する前に `UNIMPLEMENTED` で断る
    /// （多層防御）。attach の stdin・tty も、backend が受けないときは同じ位置で `INVALID_ARGUMENT` にする。
    pub fn issue(&self, request: StreamRequest) -> Result<String, CriError> {
        let kind = request.kind();
        self.require_wired(kind)?;
        if let StreamRequest::Attach(a) = &request {
            self.require_attach_options(a.stdin, a.tty)?;
        }
        if let StreamRequest::Exec { request: e, .. } = &request {
            self.require_exec_options(e.tty, &e.cmd)?;
        }
        if let StreamRequest::PortForward { network, .. } = &request {
            self.require_port_forward_network(*network)?;
        }
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
/// Exec（[`exec::ExecStreamHandler`]・#680）・Attach（[`attach::AttachHandler`]・#681）が実装済みで、
/// #682（PortForward）が同じ形で実装し、`Upgrade` 後の SPDY/3.1 を扱う。
/// Upgrade 後の idle の期限もそちらが決める。本モジュールの接続全体の期限（`header_read_timeout * 3`）は
/// Upgrade しない要求のためのもので、101 応答で `Upgraded` へ IO を渡した接続には及ばない
/// （接続の future が Upgrade の引き渡しで完了するため。#679）。
pub trait StreamHandler: Send + Sync + 'static {
    /// このハンドラが処理する（結線済みの）種別。
    ///
    /// 既定実装は無い（既定を全種別にすると未知のハンドラで fail-open になるため。REPAIR-3）。
    /// [`StreamingServer`] は起動時に 1 回だけ読むため、ハンドラの寿命の間は値を変えないこと。
    /// 結線済みと答えた種別の要求は 501 で返さず、実際に処理すること。
    fn wiring(&self) -> StreamWiring;

    /// 照合済みの要求と HTTP 要求（`hyper::upgrade::on` に渡せる）から応答を作る。
    ///
    /// `permit` は同時接続数（`max_connections`）の枠を表す。101 応答で `Upgraded` へ IO を渡すと
    /// サーバー側の接続タスクは終わるため、Upgrade 後の IO を使うタスクは `permit` を move して
    /// IO の寿命まで保持すること（落とすとその時点で枠が返り、上限の契約が破れる。CRI-6・REPAIR-5）。
    /// Upgrade 後の IO を扱うタスクは [`ConnectionPermit::spawn_session`] で起動すること。`tokio::spawn` で
    /// 起動したタスクは、停止時の強制クローズ（[`StreamingSessions::close_all`]）と残件数の対象外になる（#4164）。
    fn handle(
        &self,
        request: StreamRequest,
        http: Request<Incoming>,
        permit: ConnectionPermit,
    ) -> Pin<Box<dyn Future<Output = Response<StreamBody>> + Send + '_>>;
}

/// どの種別も結線しないハンドラ。到達した要求には `501 Not Implemented` を返す（多層防御。
/// issuer は未結線の種別の URL を発行しないため、通常の経路では到達しない。REPAIR-3）。
#[derive(Debug, Default, Clone, Copy)]
pub struct NotImplementedHandler;

impl StreamHandler for NotImplementedHandler {
    fn wiring(&self) -> StreamWiring {
        StreamWiring::none()
    }

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
/// PortForward（#682）が同じサーバーに同居するための合流点になる。設定していない種別は結線済みと答えず
/// （[`StreamHandler::wiring`]）、URL は発行されない。到達した場合の `501` は多層防御（REPAIR-3）。
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
    /// 登録済みの slot のうち、子ハンドラが同じ種別を結線済みと答えるものだけを結線済みとする
    /// （slot と子の種別が食い違う誤構成で、扱えない種別の URL を出さない）。
    fn wiring(&self) -> StreamWiring {
        let mut wiring = StreamWiring::none();
        for (kind, slot) in [
            (StreamKind::Attach, &self.attach),
            (StreamKind::Exec, &self.exec),
            (StreamKind::PortForward, &self.port_forward),
        ] {
            if let Some(child) = slot.as_ref().map(|h| h.wiring())
                && child.is_wired(kind)
            {
                wiring = wiring.with(kind);
                if kind == StreamKind::Attach && child.attach_interactive() {
                    wiring = wiring.with_attach_interactive();
                }
                if kind == StreamKind::Exec && child.exec_tty() {
                    wiring = wiring.with_exec_tty();
                }
                if kind == StreamKind::Exec && child.exec_relative_command() {
                    wiring = wiring.with_exec_relative_command();
                }
                if kind == StreamKind::PortForward && child.port_forward_pod_network() {
                    wiring = wiring.with_port_forward_pod_network();
                }
            }
        }
        wiring
    }

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

/// 接続・セッションのタスクの追跡簿（停止時の強制クローズと残件数の把握のため。CRI-6・REPAIR-5・#4164）。
///
/// 呼び出し元: `accept_loop`（Upgrade 前の接続タスク）と [`ConnectionPermit::spawn_session`]（Upgrade 後の
/// セッション）が登録し、[`StreamingSessions`] が停止時に読む。件数は `conns`（枠の数）で数え、Upgrade 前の
/// 接続も含む。追跡簿は終了済みを登録のたびに除くため、件数は同時接続数の上限の高々 2 倍で有界。
struct SessionRegistry {
    conns: Arc<AtomicUsize>,
    /// （強制クローズ済みか, 追跡中のタスク）。
    handles: Mutex<(bool, Vec<AbortHandle>)>,
}

impl SessionRegistry {
    fn new(conns: Arc<AtomicUsize>) -> Self {
        Self {
            conns,
            handles: Mutex::new((false, Vec::new())),
        }
    }

    /// タスクを登録する。強制クローズの後の登録は直ちに abort する（取りこぼしを作らない）。
    fn track(&self, handle: AbortHandle) {
        let mut guard = self
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.0 {
            handle.abort();
            return;
        }
        guard.1.retain(|h| !h.is_finished());
        guard.1.push(handle);
    }

    fn close_all(&self) {
        let handles = {
            let mut guard = self
                .handles
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.0 = true;
            std::mem::take(&mut guard.1)
        };
        for handle in handles {
            handle.abort();
        }
    }
}

/// 開いている接続・セッションの停止時の口（CRI-6・REPAIR-5・#4164）。
///
/// [`StreamingServer::sessions`] で得る。呼び出し元は `fandhe-container-plugin-cri` の停止の経路
/// （待ち受けを閉じた後に件数を数えて待ち、期限で [`Self::close_all`]）。
#[derive(Clone)]
pub struct StreamingSessions {
    registry: Arc<SessionRegistry>,
}

impl fmt::Debug for StreamingSessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingSessions")
            .field("open", &self.open())
            .finish()
    }
}

impl StreamingSessions {
    /// 同時接続数の枠を持つ件数（Upgrade 前の接続と Upgrade 後のセッションの合計）。
    pub fn open(&self) -> usize {
        self.registry.conns.load(Ordering::Acquire)
    }

    /// 追跡中の全タスクを abort する。以後に登録されるタスクも直ちに abort される。
    ///
    /// abort は次にタスクが poll される時点で future を drop する（IO が閉じ、枠が返る）。
    pub fn close_all(&self) {
        self.registry.close_all();
    }

    /// 件数が 0 になるか `deadline` に達するまで待ち、その時点の件数を返す（10 ms 周期）。
    pub async fn wait_idle_until(&self, deadline: Instant) -> usize {
        loop {
            let open = self.open();
            if open == 0 {
                return 0;
            }
            let now = Instant::now();
            if now >= deadline {
                return open;
            }
            tokio::time::sleep((deadline - now).min(Duration::from_millis(10))).await;
        }
    }
}

/// 同時接続数の枠の保持票（複製可。最後の複製が落ちたときに枠が返る）。
///
/// サーバーは接続の future が終わるまで 1 つ持ち、[`StreamHandler::handle`] にも 1 つ渡す。
/// Upgrade 後の IO を扱うタスクがこれを保持し続ける間は枠が返らない。
#[derive(Clone)]
pub struct ConnectionPermit {
    _guard: Arc<ConnectionGuard>,
    registry: Arc<SessionRegistry>,
}

impl ConnectionPermit {
    /// Upgrade 後のセッションのタスクを起動する。permit はタスクの寿命まで保持され、タスクは
    /// [`StreamingSessions::close_all`] の対象になる（枠の寿命とタスクの寿命を型で結ぶ。#4164）。
    pub fn spawn_session<F>(self, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let registry = Arc::clone(&self.registry);
        let task = tokio::spawn(async move {
            let _permit = self;
            fut.await;
        });
        registry.track(task.abort_handle());
    }
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

/// 広告アドレスとして到達できない形（正規化後の IPv4 broadcast、IPv4 互換形 `::a.b.c.d`）か。
/// `::`（未指定）は別の判定で拒否し、`::1`（loopback）は受理のままにする（#4290・CRI-6・SEC-1）。
fn is_unroutable_advertise(adv: IpAddr) -> bool {
    match adv {
        IpAddr::V4(v) => v.is_broadcast(),
        IpAddr::V6(v) => {
            // 配列分解で先頭 6 要素を取り出す（添字アクセスを使わない）。
            let [s0, s1, s2, s3, s4, s5, _, _] = v.segments();
            [s0, s1, s2, s3, s4, s5] == [0; 6] && !v.is_unspecified() && !v.is_loopback()
        }
    }
}

/// URL に出すソケットアドレス。広告アドレス（無ければ待ち受けの実アドレス）を `to_canonical()` で
/// IPv4 表記へ寄せ、ポートは実ポートを使う（射影形を括弧つき IPv6 で出さない。#4290）。
fn advertised_socket_addr(advertise: Option<IpAddr>, local: SocketAddr) -> SocketAddr {
    let ip = advertise.unwrap_or_else(|| local.ip()).to_canonical();
    SocketAddr::new(ip, local.port())
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
    registry: Arc<SessionRegistry>,
}

impl fmt::Debug for StreamingServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingServer")
            .field("local_addr", &self.local_addr)
            .finish()
    }
}

impl StreamingServer {
    /// どの種別も結線しない状態で起動する（URL は発行されず、全 RPC が `UNIMPLEMENTED`。REPAIR-3）。
    /// tokio の実行時の中で呼ぶ。
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
        let advertised = advertised_socket_addr(config.advertise_addr, local_addr);
        let issuer = Arc::new(StreamingUrlIssuer {
            base_url: format_base_url(advertised),
            cache: Arc::clone(&cache),
            wiring: handler.wiring(),
        });
        let conns = Arc::new(AtomicUsize::new(0));
        let registry = Arc::new(SessionRegistry::new(Arc::clone(&conns)));
        let accept_task = tokio::spawn(accept_loop(
            listener,
            config,
            cache,
            handler,
            conns,
            observer,
            Arc::clone(&registry),
        ));
        Ok(Self {
            local_addr,
            issuer,
            accept_task,
            registry,
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

    /// 開いている接続・セッションの停止時の口。待ち受けを閉じた後の待ちと強制クローズに使う（#4164）。
    pub fn sessions(&self) -> StreamingSessions {
        StreamingSessions {
            registry: Arc::clone(&self.registry),
        }
    }

    /// 待ち受けを止める。受け付け済みの接続・セッションは切らない（切るのは [`StreamingSessions::close_all`]）。
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
    registry: Arc<SessionRegistry>,
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
        let task_registry = Arc::clone(&registry);
        let task = tokio::spawn(async move {
            let started = Instant::now();
            let permit = ConnectionPermit {
                _guard: Arc::new(guard),
                registry: task_registry,
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
        // Upgrade 前の接続も強制クローズの対象にする（ヘッダ読み取りの期限まで残さない。#4164）。
        registry.track(task.abort_handle());
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

/// stdio と tty の組の検証（Exec・Attach 共通。kubelet の `NewOptions` / `ValidateExecRequest` と同じ規則）。
///
/// どれも false の要求と、tty と stderr の同時指定は拒否する（tty では stderr が stdout に合流するため。CRI-6）。
fn check_stdio_options(stdin: bool, stdout: bool, stderr: bool, tty: bool) -> Result<(), CriError> {
    if !(stdin || stdout || stderr) {
        return Err(CriError::invalid_argument(
            "one of stdin, stdout, or stderr must be set",
        ));
    }
    if tty && stderr {
        return Err(CriError::invalid_argument(
            "stderr must be false when tty is set",
        ));
    }
    Ok(())
}

/// `ExecRequest` の入力検証（存在照合の前。CRI-6・TASK-63.2・#680）。
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
    check_stdio_options(req.stdin, req.stdout, req.stderr, req.tty)
}

/// `AttachRequest` の入力検証（存在照合の前。CRI-6・TASK-63.3・#681）。
///
/// CRI の定義（`AttachRequest.stderr`）は tty のとき stderr を false に固定している（stdout と合流するため）。
/// 守らない要求は `INVALID_ARGUMENT`。接続時のハンドラは kubelet に合わせて、tty の stderr を無視する。
pub fn validate_attach_request(req: &v1::AttachRequest) -> Result<(), CriError> {
    check_id(&req.container_id, "container_id")?;
    check_stdio_options(req.stdin, req.stdout, req.stderr, req.tty)
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
        StreamRequest::exec(v1::ExecRequest {
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

    fn issuer_with(wiring: StreamWiring) -> StreamingUrlIssuer {
        StreamingUrlIssuer {
            base_url: "http://127.0.0.1:1".to_string(),
            cache: Arc::new(TokenCache::new(Duration::from_secs(60), 10)),
            wiring,
        }
    }

    /// CRI-6・REPAIR-3・#3753: 既定は全未結線で、`with` した種別だけ結線済みになる。
    #[test]
    fn cri6_repair3_wiring_none_by_default() {
        for w in [StreamWiring::default(), StreamWiring::none()] {
            assert!(!w.is_wired(StreamKind::Exec));
            assert!(!w.is_wired(StreamKind::Attach));
            assert!(!w.is_wired(StreamKind::PortForward));
        }
        let w = StreamWiring::none().with(StreamKind::Exec);
        assert!(w.is_wired(StreamKind::Exec));
        assert!(!w.is_wired(StreamKind::Attach));
        assert!(!w.is_wired(StreamKind::PortForward));
    }

    fn pf_req(network: port_forward::PortForwardNetwork) -> StreamRequest {
        StreamRequest::PortForward {
            request: v1::PortForwardRequest {
                pod_sandbox_id: "sb-1".to_string(),
                port: vec![80],
            },
            network,
        }
    }

    /// CRI-6・REPAIR-3・#3755: POD 対応の宣言は `only` では立たず、`all` と `with_port_forward_pod_network` で立つ。
    #[test]
    fn cri6_3755_pod_network_flag_defaults_to_false() {
        assert!(!StreamWiring::none().port_forward_pod_network());
        assert!(!StreamWiring::only(StreamKind::PortForward).port_forward_pod_network());
        assert!(StreamWiring::all().port_forward_pod_network());
        assert!(
            StreamWiring::only(StreamKind::PortForward)
                .with_port_forward_pod_network()
                .port_forward_pod_network()
        );
    }

    /// CRI-6・REPAIR-3・SEC-1・#3755: POD は未対応の結線では `Unimplemented` で、トークン枠を消費しない。NODE は発行できる。
    #[test]
    fn cri6_3755_issue_rejects_pod_network_without_consuming_slot() {
        let issuer = issuer_with(StreamWiring::only(StreamKind::PortForward));
        let err = issuer
            .issue(pf_req(port_forward::PortForwardNetwork::Pod))
            .expect_err("pod is unimplemented");
        assert_eq!(err.code(), crate::error::CriErrorCode::Unimplemented);
        assert_eq!(
            err.message(),
            "port-forward for pod network is not implemented"
        );
        assert_eq!(issuer.cache.len(), 0);
        assert!(
            issuer
                .require_port_forward_network(port_forward::PortForwardNetwork::Node)
                .is_ok()
        );
        let err = issuer
            .require_port_forward_network(port_forward::PortForwardNetwork::Pod)
            .expect_err("pod");
        assert_eq!(err.code(), crate::error::CriErrorCode::Unimplemented);
        let with_pod = issuer_with(StreamWiring::all());
        assert!(
            with_pod
                .require_port_forward_network(port_forward::PortForwardNetwork::Pod)
                .is_ok()
        );
    }

    /// CRI-6・REPAIR-3・SEC-1・#3761: exec の tty・相対 argv[0] は既定で断り、`all()` だけが受け、ディスパッチャが伝える。
    #[test]
    fn cri6_3761_exec_options_are_fail_closed_and_propagate() {
        assert!(!StreamWiring::default().exec_tty());
        assert!(!StreamWiring::only(StreamKind::Exec).exec_relative_command());
        assert!(StreamWiring::all().exec_tty());
        assert!(StreamWiring::all().exec_relative_command());
        let closed = issuer_with(StreamWiring::only(StreamKind::Exec));
        let abs = vec!["/bin/true".to_string()];
        let rel = vec!["true".to_string()];
        assert!(closed.require_exec_options(false, &abs).is_ok());
        let e = closed.require_exec_options(true, &abs).expect_err("tty");
        assert_eq!(e.code(), crate::error::CriErrorCode::InvalidArgument);
        assert_eq!(e.message(), "exec with tty is not supported");
        let e = closed
            .require_exec_options(false, &rel)
            .expect_err("relative");
        assert_eq!(e.code(), crate::error::CriErrorCode::InvalidArgument);
        assert_eq!(e.message(), "exec command must be an absolute path");
        let open = issuer_with(StreamWiring::all());
        assert!(open.require_exec_options(true, &rel).is_ok());
        let child: Arc<dyn StreamHandler> = Arc::new(StubHandler(
            StreamWiring::only(StreamKind::Exec).with_exec_tty(),
        ));
        let d = StreamDispatcher::new().with_exec(child);
        assert!(d.wiring().exec_tty());
        assert!(!d.wiring().exec_relative_command());
    }

    /// CRI-6・REPAIR-3・#3753: 未結線の種別の発行は `Unimplemented` で、トークン枠を消費しない。
    /// 検査は乱数源より前にあるため、乱数源の無い OS でも `Unavailable` ではなく `Unimplemented` になる。
    #[test]
    fn cri6_repair3_issue_rejects_unwired_kind_without_consuming_slot() {
        let issuer = issuer_with(StreamWiring::only(StreamKind::Exec).with_exec_relative_command());
        let err = issuer.issue(attach_req()).expect_err("attach is unwired");
        assert_eq!(err.code(), crate::error::CriErrorCode::Unimplemented);
        assert_eq!(issuer.cache.len(), 0);
        assert!(issuer.require_wired(StreamKind::Exec).is_ok());
        let err = issuer
            .require_wired(StreamKind::PortForward)
            .expect_err("port forward is unwired");
        assert_eq!(err.code(), crate::error::CriErrorCode::Unimplemented);
        #[cfg(unix)]
        {
            issuer.issue(exec_req()).expect("exec is wired");
            assert_eq!(issuer.cache.len(), 1);
        }
    }

    /// CRI-6・REPAIR-3・#3753: 未結線の発行を繰り返しても、結線済みの種別の発行枠（`max_in_flight`）を埋めない。
    #[cfg(unix)]
    #[test]
    fn cri6_repair3_unwired_requests_do_not_exhaust_token_slots() {
        let issuer = StreamingUrlIssuer {
            base_url: "http://127.0.0.1:1".to_string(),
            cache: Arc::new(TokenCache::new(Duration::from_secs(60), 2)),
            wiring: StreamWiring::only(StreamKind::Exec).with_exec_relative_command(),
        };
        for _ in 0..10 {
            issuer.issue(attach_req()).expect_err("unwired");
        }
        issuer.issue(exec_req()).expect("exec 1");
        issuer.issue(exec_req()).expect("exec 2");
    }

    /// CRI-6・REPAIR-3・#3753: ディスパッチャの結線は、登録した slot かつ子が同じ種別を扱うものだけ。
    #[test]
    fn cri6_repair3_dispatcher_wiring_follows_children() {
        let exec: Arc<dyn StreamHandler> =
            Arc::new(StubHandler(StreamWiring::only(StreamKind::Exec)));
        let d = StreamDispatcher::new().with_exec(Arc::clone(&exec));
        assert_eq!(d.wiring(), StreamWiring::only(StreamKind::Exec));
        // 誤構成: Attach の slot に Exec 用ハンドラを登録しても Attach は結線済みと答えない。
        let d = StreamDispatcher::new().with_attach(exec);
        assert_eq!(d.wiring(), StreamWiring::none());
        assert_eq!(StreamDispatcher::new().wiring(), StreamWiring::none());
        assert_eq!(NotImplementedHandler.wiring(), StreamWiring::none());
    }

    /// CRI-6・REPAIR-3・#3763: `attach_interactive` は既定 false（fail-closed）で、`all()` だけが立て、ディスパッチャが伝える。
    /// stdin・tty つきの発行は backend が受けないとき、トークン枠を消費せず `INVALID_ARGUMENT` になる。
    #[test]
    fn cri6_repair3_attach_interactive_is_fail_closed_and_propagates() {
        assert!(!StreamWiring::default().attach_interactive());
        assert!(!StreamWiring::only(StreamKind::Attach).attach_interactive());
        assert!(StreamWiring::all().attach_interactive());
        let ro: Arc<dyn StreamHandler> =
            Arc::new(StubHandler(StreamWiring::only(StreamKind::Attach)));
        let rw: Arc<dyn StreamHandler> = Arc::new(StubHandler(
            StreamWiring::only(StreamKind::Attach).with_attach_interactive(),
        ));
        let d = StreamDispatcher::new().with_attach(ro);
        assert!(d.wiring().is_wired(StreamKind::Attach));
        assert!(!d.wiring().attach_interactive());
        let d = StreamDispatcher::new().with_attach(rw);
        assert!(d.wiring().attach_interactive());

        let issuer = issuer_with(StreamWiring::only(StreamKind::Attach));
        for (stdin, tty) in [(true, false), (false, true), (true, true)] {
            let err = issuer
                .require_attach_options(stdin, tty)
                .expect_err("stdin or tty is refused");
            assert_eq!(err.code(), crate::error::CriErrorCode::InvalidArgument);
            assert_eq!(err.message(), "attach with stdin or tty is not supported");
            let req = StreamRequest::Attach(v1::AttachRequest {
                container_id: "c1".to_string(),
                stdin,
                tty,
                stdout: true,
                stderr: false,
            });
            let err = issuer.issue(req).expect_err("issue refuses too");
            assert_eq!(err.code(), crate::error::CriErrorCode::InvalidArgument);
        }
        assert_eq!(issuer.cache.len(), 0);
        assert!(issuer.require_attach_options(false, false).is_ok());
        let issuer = issuer_with(StreamWiring::all());
        assert!(issuer.require_attach_options(true, true).is_ok());
    }

    struct StubHandler(StreamWiring);

    impl StreamHandler for StubHandler {
        fn wiring(&self) -> StreamWiring {
            self.0
        }

        fn handle(
            &self,
            request: StreamRequest,
            http: Request<Incoming>,
            permit: ConnectionPermit,
        ) -> Pin<Box<dyn Future<Output = Response<StreamBody>> + Send + '_>> {
            NotImplementedHandler.handle(request, http, permit)
        }
    }

    /// CRI-6: 同じ要求の 2 回の発行でトークンも URL も異なり、トークンは 64 文字の小文字 hex。
    #[cfg(unix)]
    #[test]
    fn cri6_token_unique_per_issue() {
        let issuer = StreamingUrlIssuer {
            base_url: "http://127.0.0.1:1".to_string(),
            cache: Arc::new(TokenCache::new(Duration::from_secs(60), 10)),
            wiring: StreamWiring::all(),
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
            wiring: StreamWiring::all(),
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
        for addr in ["0.0.0.0:0", "[::]:0", "[::ffff:0.0.0.0]:0"] {
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

    /// CRI-6・SEC-1・#4238: IPv4 射影形の未指定・マルチキャストの広告アドレスを拒否し、具体アドレスは受理する。
    #[test]
    fn cri6_sec1_4238_mapped_unspecified_and_multicast_advertise_rejected() {
        let base = StreamingConfig::default()
            .with_bind("0.0.0.0:0".parse().expect("addr"))
            .with_allow_external(true);
        for adv in ["::ffff:0.0.0.0", "::ffff:224.0.0.1"] {
            let err = base
                .clone()
                .with_advertise_addr(adv.parse().expect("ip"))
                .validate()
                .expect_err(adv);
            assert_eq!(err.code(), crate::error::CriErrorCode::InvalidArgument);
        }
        base.with_advertise_addr("::ffff:192.0.2.7".parse().expect("ip"))
            .validate()
            .expect("mapped concrete ok");
    }

    /// CRI-6・SEC-1・#4290: broadcast と互換形の広告アドレスは拒否し、陽性対照は受理する。
    #[test]
    fn cri6_sec1_4290_broadcast_and_compat_advertise_rejected() {
        let base = StreamingConfig::default()
            .with_bind("0.0.0.0:0".parse().expect("addr"))
            .with_allow_external(true);
        for adv in ["255.255.255.255", "::ffff:255.255.255.255", "::192.0.2.7"] {
            let err = base
                .clone()
                .with_advertise_addr(adv.parse().expect("ip"))
                .validate()
                .expect_err(adv);
            assert_eq!(err.code(), crate::error::CriErrorCode::InvalidArgument);
        }
        for adv in ["::1", "192.0.2.7", "2001:db8::1"] {
            base.clone()
                .with_advertise_addr(adv.parse().expect("ip"))
                .validate()
                .expect(adv);
        }
    }

    /// CRI-6・#4290: URL 用のアドレスは射影形を IPv4 表記へ寄せ、実ポートを使う。
    #[test]
    fn cri6_sec1_4290_advertised_socket_addr_canonicalizes() {
        let local: SocketAddr = "0.0.0.0:4321".parse().expect("addr");
        let got = advertised_socket_addr(Some("::ffff:192.0.2.7".parse().expect("ip")), local);
        assert_eq!(got, "192.0.2.7:4321".parse::<SocketAddr>().expect("addr"));
        assert_eq!(format_base_url(got), "http://192.0.2.7:4321");
        let local: SocketAddr = "[::ffff:192.0.2.7]:4321".parse().expect("addr");
        assert_eq!(
            advertised_socket_addr(None, local),
            "192.0.2.7:4321".parse::<SocketAddr>().expect("addr")
        );
        let v6: IpAddr = "2001:db8::1".parse().expect("ip");
        assert_eq!(advertised_socket_addr(Some(v6), local).ip(), v6);
    }

    /// CRI-6・#4290: 射影形の広告アドレスでも発行 URL は IPv4 表記。
    #[tokio::test]
    async fn cri6_sec1_4290_base_url_canonical_for_mapped_advertise() {
        let server = StreamingServer::bind(
            StreamingConfig::default()
                .with_bind("0.0.0.0:0".parse().expect("addr"))
                .with_allow_external(true)
                .with_advertise_addr("::ffff:192.0.2.7".parse().expect("ip")),
        )
        .await
        .expect("bind");
        let port = server.local_addr().port();
        assert_eq!(
            server.issuer().base_url(),
            format!("http://192.0.2.7:{port}")
        );
    }

    /// CRI-6・SEC-1・#4238: `::ffff:127.0.0.1` は loopback と見なさず外部扱い（opt-in 必須）。
    /// 緩める方向に変えないためと plugin-cri の判定と揃えるため。
    #[test]
    fn cri6_sec1_4238_mapped_loopback_bind_requires_opt_in() {
        let base =
            StreamingConfig::default().with_bind("[::ffff:127.0.0.1]:0".parse().expect("addr"));
        let err = base.validate().expect_err("no opt-in");
        assert_eq!(err.code(), crate::error::CriErrorCode::InvalidArgument);
        base.with_allow_external(true)
            .validate()
            .expect("opt-in ok");
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
        // kubelet と同じく tty と stderr の同時指定は不正（#680）。tty 単独・stderr 単独は有効。
        let mut tty_stderr = ok.clone();
        tty_stderr.tty = true;
        tty_stderr.stderr = true;
        let err = validate_exec_request(&tty_stderr).expect_err("tty and stderr");
        assert_eq!(err.message(), "stderr must be false when tty is set");
        let mut tty_only = ok.clone();
        tty_only.tty = true;
        validate_exec_request(&tty_only).expect("tty only");
        let mut stderr_only = ok.clone();
        stderr_only.stderr = true;
        validate_exec_request(&stderr_only).expect("stderr only");

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
