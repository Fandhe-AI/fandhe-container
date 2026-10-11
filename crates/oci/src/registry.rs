//! レジストリクライアント基盤: 接続先 URL の組み立てと HTTP `Agent` の構築（TASK-51.1・OCI-1）。
//!
//! #402（manifest 取得）・#403（blob のストリーミング取得）が共通で使う土台。通信する公開メソッドは
//! 匿名トークン取得の `RegistryClient::authenticate_anonymous`（TASK-51.2・#401）のみで、manifest / blob の
//! 取得は未実装（#402・#403 が `pub(crate)` の accessor を通して `Agent` を使う。digest 検証は #405。REPAIR-3）。
//! OCI-3（資格情報つき認証）も未実装で、匿名のみ。
//!
//! 安全側の既定値:
//! - 平文 HTTP の経路を持たない（`https_only`。scheme は `https` 固定）
//! - HTTP の 4xx / 5xx を ureq のエラーにしない（`http_status_as_error(false)`。401 チャレンジを #401 が扱うため）
//! - リダイレクト先へ `Authorization` を送らない（`RedirectAuthHeaders::Never`）。回数・ヘッダサイズに上限
//! - DNS 解決・connect・リクエスト送信・応答ヘッダ待ちのタイムアウトは `Duration` 必須で、未設定にできない（REPAIR-5）
//!
//! 本文受信（`recv_body`）と全体（`global`）のタイムアウトは Agent 既定では無制限のまま。トークン取得は
//! リクエスト単位で全体期限（`token_request_timeout`）と本文上限を設ける。blob の長時間転送の設定は #403。
//! CA ファイルを指定する経路は範囲外（OS のストアと `SSL_CERT_FILE` / `SSL_CERT_DIR` のみ）。

use crate::auth::{RegistryAuth, parse_token_response, parse_www_authenticate};
use crate::error::{OciError, OciErrorCode, code_for_http_status};
use crate::instrument::{NoopOciOpRecorder, OciOpKind, OciOpRecorder, record_oci_op};
use crate::reference::{Digest, Reference, RegistryHost, Repository};
use crate::tls;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use ureq::Agent;
use ureq::config::{Config, RedirectAuthHeaders};
use ureq::http::Uri;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
use ureq::unversioned::resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{DefaultConnector, NextTimeout};

/// レジストリの接続先（`https://{host}[:port]/v2/` のベース）。
///
/// URL は検証済みの型（`RegistryHost`・`Repository`・`Reference`・`Digest`）からのみ組み立てる。
/// 各成分は `[A-Za-z0-9._:@/-]` のうち検証を通った文字に限られ、`?`・`#`・`%`・空白・`..` を含まないため、
/// パーセントエンコードは不要。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEndpoint {
    host: RegistryHost,
}

impl RegistryEndpoint {
    /// 検証済みホストから接続先を作る。
    pub fn new(host: RegistryHost) -> Self {
        Self { host }
    }

    /// `https://{authority}/v2/`（API バージョン確認・トークン要求の起点）。
    pub fn base_url(&self) -> String {
        format!("https://{}/v2/", self.host.authority())
    }

    /// `/v2/<name>/manifests/<reference>`。
    pub fn manifest_url(&self, repository: &Repository, reference: &Reference) -> String {
        format!(
            "https://{}/v2/{}/manifests/{}",
            self.host.authority(),
            repository.as_str(),
            reference.as_str()
        )
    }

    /// `/v2/<name>/blobs/<digest>`。
    pub fn blob_url(&self, repository: &Repository, digest: &Digest) -> String {
        format!(
            "https://{}/v2/{}/blobs/{}",
            self.host.authority(),
            repository.as_str(),
            digest.as_str()
        )
    }
}

/// `RegistryClient` の設定。`Default` は保守的な値（REPAIR-5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryClientConfig {
    /// TCP / TLS 接続のタイムアウト。
    pub connect_timeout: Duration,
    /// DNS 解決のタイムアウト。
    pub resolve_timeout: Duration,
    /// リクエスト送信（ヘッダ書き出し）のタイムアウト。
    pub send_request_timeout: Duration,
    /// リクエスト送信後、応答ヘッダを受け取るまでのタイムアウト。
    pub recv_response_timeout: Duration,
    /// 追従するリダイレクトの最大回数。
    pub max_redirects: u32,
    /// 応答ヘッダの最大バイト数。
    pub max_response_header_bytes: usize,
    /// トークン取得（`/v2/` のプローブと トークンエンドポイント）1 リクエストあたりの全体期限（REPAIR-5）。
    pub token_request_timeout: Duration,
    /// トークンエンドポイント応答本文の最大バイト数。
    pub max_token_response_bytes: u64,
}

impl Default for RegistryClientConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            resolve_timeout: Duration::from_secs(30),
            send_request_timeout: Duration::from_secs(30),
            recv_response_timeout: Duration::from_secs(60),
            max_redirects: 5,
            max_response_header_bytes: 64 * 1024,
            token_request_timeout: Duration::from_secs(30),
            max_token_response_bytes: 64 * 1024,
        }
    }
}

/// レジストリ通信の土台となる HTTP クライアント（TLS 設定済みの ureq `Agent` を保持する）。
///
/// 匿名トークン取得は実装済み（#401）。manifest（#402）・blob（#403）の取得は未実装（OCI-1）。
#[derive(Debug)]
pub struct RegistryClient {
    agent: Agent,
    transport: Arc<dyn RegistryTransport>,
    config: RegistryClientConfig,
    recorder: Arc<dyn OciOpRecorder>,
}

impl RegistryClient {
    /// 実 CPU の確認と OS のルート証明書で `Agent` を構築する。接続はしない。
    ///
    /// CPU 機能が不足していれば `Unimplemented`、ルート証明書が 0 件なら `FailedPrecondition`（fail-closed）。
    pub fn new(config: &RegistryClientConfig) -> Result<Self, OciError> {
        Self::new_with(
            config,
            tls::probe_cpu,
            rustls_native_certs::load_native_certs,
        )
    }

    /// 検出関数とルート証明書ローダーを注入して構築する（テスト用の差し込み口）。
    pub(crate) fn new_with(
        config: &RegistryClientConfig,
        cpu_check: impl FnOnce() -> Result<(), OciError>,
        root_loader: impl FnOnce() -> rustls_native_certs::CertificateResult,
    ) -> Result<Self, OciError> {
        let provider = tls::crypto_provider(cpu_check)?;
        let certs = tls::load_roots(root_loader)?;
        let tls_config = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(provider)
            .root_certs(RootCerts::new_with_certs(&certs))
            .build();
        let agent = build_agent(config, tls_config.clone(), true, None);
        // 接続先レジストリと別ホストの realm 専用。解決済み IP が公開アドレスのものだけへ接続する（SSRF 対策）。
        let public_only_agent = build_agent(
            config,
            tls_config,
            true,
            Some(PublicOnlyResolver::default()),
        );
        let transport = Arc::new(UreqTransport {
            agent: agent.clone(),
            public_only_agent,
        });
        Ok(Self {
            agent,
            transport,
            config: config.clone(),
            recorder: Arc::new(NoopOciOpRecorder),
        })
    }

    /// 計測の記録先を差し替える（REPAIR-4。既定は何も記録しない）。
    #[must_use]
    pub fn with_recorder(mut self, recorder: Arc<dyn OciOpRecorder>) -> Self {
        self.recorder = recorder;
        self
    }

    /// 後続の取得処理（#402・#403）が使う `Agent`（呼び出し元が入るまで未使用）。
    #[allow(dead_code)]
    pub(crate) fn agent(&self) -> &Agent {
        &self.agent
    }

    /// 資格情報なしで Distribution API のトークンを取得する（TASK-51.2・OCI-1）。
    ///
    /// 認証ヘッダなしで `/v2/` を叩き、200 なら `RegistryAuth::None`、401 の `WWW-Authenticate`（Bearer）
    /// に従って `realm` へ `service` と `scope=repository:<name>:pull` を付けて GET し、トークンを得る。
    /// scope は検証済みの `repository` から作り、レジストリ提示の scope は使わない。資格情報・
    /// `Authorization` は送らない。各リクエストに `token_request_timeout` の全体期限と応答本文の上限がある。
    /// Basic のみの提示は `Unimplemented`（OCI-3）。トークンのキャッシュ・再取得は未実装。
    ///
    /// プローブ・トークン要求ともリダイレクトは追従しない（`max_redirects(0)`。3xx は想定外ステータスの
    /// エラー）。realm 検証（`TokenRealm`）を通っていない遷移先へ接続しないため。成功・失敗とエラー code・
    /// 所要時間は `with_recorder` の記録先へ 1 件記録する（REPAIR-4。トークン値・URL は記録しない）。
    pub fn authenticate_anonymous(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
    ) -> Result<RegistryAuth, OciError> {
        record_oci_op(
            self.recorder.as_ref(),
            OciOpKind::AuthenticateAnonymous,
            || self.authenticate_anonymous_inner(endpoint, repository),
        )
    }

    fn authenticate_anonymous_inner(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
    ) -> Result<RegistryAuth, OciError> {
        anonymous_flow(self.transport.as_ref(), &self.config, endpoint, repository)
    }
}

/// 匿名トークン取得の手順（通信は `transport` に委ねる。テストでは差し替える）。
fn anonymous_flow(
    transport: &dyn RegistryTransport,
    config: &RegistryClientConfig,
    endpoint: &RegistryEndpoint,
    repository: &Repository,
) -> Result<RegistryAuth, OciError> {
    let timeout = config.token_request_timeout;
    let base_url = endpoint.base_url();
    let probe = transport.get(&TransportRequest {
        url: &base_url,
        query: &[],
        public_only: false,
        body_limit: None,
        timeout,
    })?;
    match probe.status {
        200 => return Ok(RegistryAuth::None),
        401 => {}
        s => return Err(status_error(s)),
    }
    let values: Vec<&str> = probe.www_authenticate.iter().map(String::as_str).collect();
    let challenge = parse_www_authenticate(&values, &endpoint.host)?;

    let scope = format!("repository:{}:pull", repository.as_str());
    let mut query: Vec<(&str, &str)> = vec![("scope", scope.as_str())];
    if let Some(service) = &challenge.service {
        query.push(("service", service.as_str()));
    }
    // トークンの寿命から差し引く経過時間は、トークン要求そのもの（送信から本文受信まで）に限る。
    // 直前の `/v2/` プローブの所要時間を含めると、新規発行のトークンが即失効扱いになりうる。
    let token_started = Instant::now();
    let resp = transport.get(&TransportRequest {
        url: challenge.realm.as_str(),
        query: &query,
        public_only: !challenge.realm.is_registry_host(),
        body_limit: Some(config.max_token_response_bytes),
        timeout,
    })?;
    if resp.status != 200 {
        return Err(status_error(resp.status));
    }
    let token = parse_token_response(
        &resp.body,
        Instant::now(),
        SystemTime::now(),
        token_started.elapsed(),
    )?;
    Ok(RegistryAuth::Bearer(token))
}

/// 1 回の GET の指定（redirect は常に追従しない）。
struct TransportRequest<'a> {
    url: &'a str,
    query: &'a [(&'a str, &'a str)],
    /// true なら解決済み IP が公開アドレスのものにだけ接続する（SSRF 対策）。
    public_only: bool,
    /// `Some` なら 200 のとき本文をこの上限まで読む。`None` は本文を読まない。
    body_limit: Option<u64>,
    /// リクエスト全体の期限（REPAIR-5）。
    timeout: Duration,
}

// 本文にトークンが含まれうるため、Debug はテストでのみ導出する（security.md）。
#[cfg_attr(test, derive(Debug))]
struct TransportResponse {
    status: u16,
    www_authenticate: Vec<String>,
    body: Vec<u8>,
}

/// トークン取得が使う通信の境界。実体は ureq、テストでは差し替える。
trait RegistryTransport: Debug + Send + Sync {
    fn get(&self, req: &TransportRequest<'_>) -> Result<TransportResponse, OciError>;
}

#[derive(Debug)]
struct UreqTransport {
    agent: Agent,
    public_only_agent: Agent,
}

impl RegistryTransport for UreqTransport {
    fn get(&self, req: &TransportRequest<'_>) -> Result<TransportResponse, OciError> {
        let agent = if req.public_only {
            &self.public_only_agent
        } else {
            &self.agent
        };
        let mut builder = agent
            .get(req.url)
            .config()
            .timeout_global(Some(req.timeout))
            .max_redirects(0)
            .build();
        for (k, v) in req.query {
            builder = builder.query(*k, *v);
        }
        let mut resp = builder.call().map_err(map_ureq_error)?;
        let status = resp.status().as_u16();
        let www_authenticate = resp
            .headers()
            .get_all("www-authenticate")
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();
        let body = match req.body_limit {
            Some(limit) if status == 200 => resp
                .body_mut()
                .with_config()
                .limit(limit)
                .read_to_vec()
                .map_err(map_ureq_error)?,
            _ => Vec::new(),
        };
        Ok(TransportResponse {
            status,
            www_authenticate,
            body,
        })
    }
}

/// 共通設定の `Agent` を作る。`resolver` があれば名前解決をそれに置き換える。
fn build_agent(
    config: &RegistryClientConfig,
    tls_config: TlsConfig,
    https_only: bool,
    resolver: Option<PublicOnlyResolver>,
) -> Agent {
    let cfg: Config = Agent::config_builder()
        .tls_config(tls_config)
        .https_only(https_only)
        .http_status_as_error(false)
        .redirect_auth_headers(RedirectAuthHeaders::Never)
        .max_redirects(config.max_redirects)
        .max_response_header_size(config.max_response_header_bytes)
        .timeout_resolve(Some(config.resolve_timeout))
        .timeout_connect(Some(config.connect_timeout))
        .timeout_send_request(Some(config.send_request_timeout))
        .timeout_recv_response(Some(config.recv_response_timeout))
        .user_agent(concat!("fandhe-container/", env!("CARGO_PKG_VERSION")))
        .build();
    match resolver {
        Some(r) => Agent::with_parts(cfg, DefaultConnector::default(), r),
        None => Agent::new_with_config(cfg),
    }
}

/// 公開アドレス以外（ループバック・プライベート・リンクローカル・CGNAT・予約・マルチキャスト等）なら false。
/// IPv4 を埋め込む IPv6（v4-mapped・NAT64・6to4・v4-compatible）は埋め込まれた IPv4 を検査する。
fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
                return false;
            }
            let embedded = |hi: u16, lo: u16| {
                let [a, b] = hi.to_be_bytes();
                let [c, d] = lo.to_be_bytes();
                is_public_v4(Ipv4Addr::new(a, b, c, d))
            };
            if s[..6] == [0, 0, 0, 0, 0, 0xffff] || s[..6] == [0; 6] {
                // ::ffff:a.b.c.d（v4-mapped）と ::a.b.c.d（v4-compatible）。
                return embedded(s[6], s[7]);
            }
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                // 64:ff9b::/96（well-known NAT64。RFC 6052）。埋め込まれた IPv4 を検査する。
                // 64:ff9b:1::/48（local-use NAT64。RFC 8215）は下の 2000::/3 判定で拒否される。
                return embedded(s[6], s[7]);
            }
            // fail-closed: グローバルユニキャスト 2000::/3 以外（ULA・リンクローカル・サイトローカル・
            // local-use NAT64・SRv6 SID・予約等）はすべて非公開として扱う。
            if s[0] & 0xe000 != 0x2000 {
                return false;
            }
            // 2001::/23（IETF プロトコル割り当て。Teredo 2001::/32 を含む）・2001:db8::/32（文書化用）・
            // 3fff::/20（文書化用。RFC 9637）。
            if (s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                || (s[0] == 0x3fff && s[1] < 0x1000)
            {
                return false;
            }
            if s[0] == 0x2002 {
                // 2002::/16（6to4）。
                return embedded(s[1], s[2]);
            }
            true
        }
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    !(v4.is_unspecified()
        || v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..=19).contains(&b))
        || a >= 240)
}

/// 既定の名前解決の結果から公開アドレスだけを残すリゾルバ。1 件も残らなければ接続しない。
/// 検査した結果をそのまま接続に使うため、検査後に DNS 応答が差し替わる攻撃（rebinding）を受けない。
#[derive(Debug, Default)]
struct PublicOnlyResolver {
    inner: DefaultResolver,
}

impl Resolver for PublicOnlyResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let all = self.inner.resolve(uri, config, timeout)?;
        let mut out = self.empty();
        for addr in all.iter().filter(|a| is_public_ip(a.ip())) {
            out.push(*addr);
        }
        if out.is_empty() {
            return Err(ureq::Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "resolved address is not public",
            )));
        }
        Ok(out)
    }
}

/// 想定外の HTTP ステータスをエラーにする（message は固定文。応答本文・URL は載せない）。
fn status_error(status: u16) -> OciError {
    OciError::new(
        code_for_http_status(status),
        "registry returned an error status",
    )
    .with_http_status(status)
}

/// ureq のエラーを `OciError` へ写像する。message は固定文のみ（URL・ヘッダ値を含め得る元メッセージは捨てる）。
fn map_ureq_error(e: ureq::Error) -> OciError {
    match e {
        ureq::Error::Timeout(_) => {
            OciError::new(OciErrorCode::Timeout, "registry request timed out")
        }
        ureq::Error::BodyExceedsLimit(_) => OciError::new(
            OciErrorCode::ResourceExhausted,
            "registry response body is too large",
        ),
        ureq::Error::Io(ref io) if io.kind() == std::io::ErrorKind::PermissionDenied => {
            OciError::new(
                OciErrorCode::PermissionDenied,
                "registry host resolves to a non-public address",
            )
        }
        ureq::Error::Protocol(_)
        | ureq::Error::LargeResponseHeader(_, _)
        | ureq::Error::TooManyRedirects
        | ureq::Error::RedirectFailed => {
            OciError::new(OciErrorCode::DataLoss, "invalid response from registry")
        }
        _ => OciError::new(OciErrorCode::Unavailable, "registry is unreachable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::OciErrorCode;
    use crate::reference::ImageReference;
    use rustls_native_certs::CertificateResult;

    /// OCI-1: manifest / blob URL の具体値。
    #[test]
    fn url_building() {
        let r = ImageReference::parse("alpine").expect("parse");
        let ep = RegistryEndpoint::new(r.registry().clone());
        assert_eq!(ep.base_url(), "https://registry-1.docker.io/v2/");
        assert_eq!(
            ep.manifest_url(r.repository(), r.reference()),
            "https://registry-1.docker.io/v2/library/alpine/manifests/latest"
        );
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let d = Digest::parse(&format!("sha256:{hex}")).expect("digest");
        let r = ImageReference::parse("localhost:5000/a/b").expect("parse");
        let ep = RegistryEndpoint::new(r.registry().clone());
        assert_eq!(
            ep.blob_url(r.repository(), &d),
            format!("https://localhost:5000/v2/a/b/blobs/sha256:{hex}")
        );
    }

    /// OCI-1・REPAIR-5: 設定の既定値（具体値）。
    #[test]
    fn config_defaults() {
        let c = RegistryClientConfig::default();
        assert_eq!(c.token_request_timeout, Duration::from_secs(30));
        assert_eq!(c.max_token_response_bytes, 65536);
    }

    /// OCI-1: ureq エラーの写像は固定文で、分類が具体値どおり。
    #[test]
    fn ureq_error_mapping() {
        let e = map_ureq_error(ureq::Error::Timeout(ureq::Timeout::Global));
        assert_eq!(e.code(), OciErrorCode::Timeout);
        let e = map_ureq_error(ureq::Error::BodyExceedsLimit(10));
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
        let e = map_ureq_error(ureq::Error::HostNotFound);
        assert_eq!(e.code(), OciErrorCode::Unavailable);
        let e = status_error(429);
        assert_eq!(e.code(), OciErrorCode::Unavailable);
        assert_eq!(e.http_status(), Some(429));
    }

    fn one_cert() -> CertificateResult {
        let mut r = CertificateResult::default();
        r.certs
            .push(rustls::pki_types::CertificateDer::from(vec![0x30, 0x00]));
        r
    }

    /// OCI-1: Agent の構築は接続せずに成功する（CPU 確認は偽装して通す。provider 生成は実物）。
    #[test]
    fn builds_agent_without_connecting() {
        let c = RegistryClient::new_with(&RegistryClientConfig::default(), || Ok(()), one_cert);
        assert!(c.is_ok());
    }

    /// OCI-1・ERR-1: CPU 機能が不足していれば Unimplemented で構築に失敗する。
    #[test]
    fn cpu_failure_propagates() {
        let e = RegistryClient::new_with(
            &RegistryClientConfig::default(),
            || Err(OciError::new(OciErrorCode::Unimplemented, "missing")),
            one_cert,
        )
        .expect_err("fail");
        assert_eq!(e.code(), OciErrorCode::Unimplemented);
    }

    /// OCI-1・ERR-1: ルート証明書が 0 件なら FailedPrecondition で構築に失敗する。
    #[test]
    fn empty_roots_fail_closed() {
        let e = RegistryClient::new_with(
            &RegistryClientConfig::default(),
            || Ok(()),
            CertificateResult::default,
        )
        .expect_err("fail");
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
    }

    // ---- 匿名トークン取得フローの照合（OCI-1・REPAIR-12。外部通信なし）----

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    type SeenRequest = (String, Vec<(String, String)>, bool, Option<u64>);

    /// 台本どおりに応答し、受けた要求（url・query・public_only・body_limit）を記録する偽の通信。
    #[derive(Debug)]
    struct FakeTransport {
        script: Mutex<Vec<Result<TransportResponse, OciError>>>,
        seen: Mutex<Vec<SeenRequest>>,
        delay_first: Duration,
    }

    impl FakeTransport {
        fn new(script: Vec<Result<TransportResponse, OciError>>) -> Self {
            Self {
                script: Mutex::new(script),
                seen: Mutex::new(Vec::new()),
                delay_first: Duration::ZERO,
            }
        }
    }

    impl RegistryTransport for FakeTransport {
        fn get(&self, req: &TransportRequest<'_>) -> Result<TransportResponse, OciError> {
            let first = self.seen.lock().expect("lock").is_empty();
            self.seen.lock().expect("lock").push((
                req.url.to_string(),
                req.query
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                req.public_only,
                req.body_limit,
            ));
            if first {
                std::thread::sleep(self.delay_first);
            }
            self.script.lock().expect("lock").remove(0)
        }
    }

    fn resp(status: u16, www: &[&str], body: &str) -> Result<TransportResponse, OciError> {
        Ok(TransportResponse {
            status,
            www_authenticate: www.iter().map(|s| s.to_string()).collect(),
            body: body.as_bytes().to_vec(),
        })
    }

    const HUB_CHALLENGE: &str =
        r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io""#;

    fn alpine() -> (RegistryEndpoint, Repository) {
        let r = ImageReference::parse("alpine").expect("parse");
        (
            RegistryEndpoint::new(r.registry().clone()),
            r.repository().clone(),
        )
    }

    fn run(t: &FakeTransport) -> Result<RegistryAuth, OciError> {
        let (ep, repo) = alpine();
        anonymous_flow(t, &RegistryClientConfig::default(), &ep, &repo)
    }

    /// OCI-1: /v2/ が 200 なら認証不要で、トークン要求は送らない。
    #[test]
    fn probe_200_needs_no_token() {
        let t = FakeTransport::new(vec![resp(200, &[], "")]);
        assert!(matches!(run(&t), Ok(RegistryAuth::None)));
        let seen = t.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "https://registry-1.docker.io/v2/");
        assert_eq!(seen[0].3, None);
    }

    /// OCI-1: 401 → realm へ scope / service を実際に付けて GET し、別ホスト宛は公開 IP のみの経路を使う。
    #[test]
    fn challenge_then_token_sends_scope_and_service() {
        let t = FakeTransport::new(vec![
            resp(401, &[HUB_CHALLENGE], ""),
            resp(200, &[], r#"{"token":"tok","expires_in":300}"#),
        ]);
        let auth = run(&t).expect("auth");
        let RegistryAuth::Bearer(tok) = auth else {
            panic!("expected bearer");
        };
        assert_eq!(tok.authorization_header_value(), "Bearer tok");
        assert!(!tok.is_expired(Instant::now()));
        let seen = t.seen.lock().expect("lock");
        assert_eq!(seen[1].0, "https://auth.docker.io/token");
        assert_eq!(
            seen[1].1,
            vec![
                (
                    "scope".to_string(),
                    "repository:library/alpine:pull".to_string()
                ),
                ("service".to_string(), "registry.docker.io".to_string()),
            ]
        );
        assert!(
            seen[1].2,
            "separate realm host must use the public-only path"
        );
        assert!(!seen[0].2);
        assert_eq!(seen[1].3, Some(65536));
    }

    /// OCI-1: service の無いチャレンジでは service を送らない。realm がレジストリ自身なら通常経路。
    #[test]
    fn no_service_and_same_host_realm() {
        let t = FakeTransport::new(vec![
            resp(
                401,
                &[r#"Bearer realm="https://registry-1.docker.io/token""#],
                "",
            ),
            resp(200, &[], r#"{"access_token":"x"}"#),
        ]);
        run(&t).expect("auth");
        let seen = t.seen.lock().expect("lock");
        assert_eq!(seen[1].1.len(), 1);
        assert!(!seen[1].2);
    }

    /// OCI-1: 異常応答は分類つきのエラー（Basic のみ・非 200・壊れた JSON・不正 realm・通信失敗）。
    #[test]
    fn abnormal_responses() {
        let t = FakeTransport::new(vec![resp(401, &[r#"Basic realm="x""#], "")]);
        assert_eq!(
            run(&t).expect_err("basic").code(),
            OciErrorCode::Unimplemented
        );
        let t = FakeTransport::new(vec![resp(500, &[], "")]);
        let e = run(&t).expect_err("probe 500");
        assert_eq!(
            (e.code(), e.http_status()),
            (OciErrorCode::Unavailable, Some(500))
        );
        let t = FakeTransport::new(vec![resp(401, &[HUB_CHALLENGE], ""), resp(403, &[], "")]);
        let e = run(&t).expect_err("token 403");
        assert_eq!(
            (e.code(), e.http_status()),
            (OciErrorCode::PermissionDenied, Some(403))
        );
        let t = FakeTransport::new(vec![resp(401, &[HUB_CHALLENGE], ""), resp(302, &[], "")]);
        assert_eq!(run(&t).expect_err("302").http_status(), Some(302));
        let t = FakeTransport::new(vec![
            resp(401, &[HUB_CHALLENGE], ""),
            resp(200, &[], "not json"),
        ]);
        assert_eq!(run(&t).expect_err("json").code(), OciErrorCode::DataLoss);
        let t = FakeTransport::new(vec![resp(
            401,
            &[r#"Bearer realm="https://127.0.0.1/token""#],
            "",
        )]);
        assert_eq!(run(&t).expect_err("realm").code(), OciErrorCode::DataLoss);
        assert_eq!(
            t.seen.lock().expect("lock").len(),
            1,
            "no request to a rejected realm"
        );
        let t = FakeTransport::new(vec![Err(OciError::new(OciErrorCode::Timeout, "t"))]);
        assert_eq!(run(&t).expect_err("timeout").code(), OciErrorCode::Timeout);
    }

    /// 偽の通信を差し込んだ `RegistryClient`（公開メソッド経由の照合用）。
    fn client_with(
        t: FakeTransport,
        rec: Arc<crate::instrument::testing::Collect>,
    ) -> RegistryClient {
        RegistryClient {
            agent: Agent::new_with_config(Config::default()),
            transport: Arc::new(t),
            config: RegistryClientConfig::default(),
            recorder: rec,
        }
    }

    /// OCI-1・REPAIR-4: 公開メソッド `authenticate_anonymous` の成功と失敗が記録先へ 1 件ずつ記録される。
    #[test]
    fn authenticate_anonymous_public_api_records_outcomes() {
        use crate::instrument::OciOpOutcome;
        let (ep, repo) = alpine();
        let rec = Arc::new(crate::instrument::testing::Collect::default());
        let ok = client_with(
            FakeTransport::new(vec![
                resp(401, &[HUB_CHALLENGE], ""),
                resp(200, &[], r#"{"token":"tok","expires_in":300}"#),
            ]),
            rec.clone(),
        );
        let RegistryAuth::Bearer(t) = ok.authenticate_anonymous(&ep, &repo).expect("auth") else {
            panic!("expected bearer");
        };
        assert_eq!(t.authorization_header_value(), "Bearer tok");
        let bad = client_with(
            FakeTransport::new(vec![resp(401, &[HUB_CHALLENGE], ""), resp(403, &[], "")]),
            rec.clone(),
        );
        let e = bad.authenticate_anonymous(&ep, &repo).expect_err("403");
        assert_eq!(e.code(), OciErrorCode::PermissionDenied);
        let items = rec.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].outcome(), OciOpOutcome::Success);
        assert_eq!(items[0].error_code(), None);
        assert_eq!(items[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(OciErrorCode::PermissionDenied));
    }

    /// OCI-1: 発行時刻が古い応答は取得直後でも失効扱い（期限切れの照合）。
    #[test]
    fn expired_token_is_reported_expired() {
        let t = FakeTransport::new(vec![
            resp(401, &[HUB_CHALLENGE], ""),
            resp(
                200,
                &[],
                r#"{"token":"a","expires_in":60,"issued_at":"2020-01-01T00:00:00Z"}"#,
            ),
        ]);
        let RegistryAuth::Bearer(tok) = run(&t).expect("auth") else {
            panic!("expected bearer");
        };
        assert!(tok.is_expired(Instant::now()));
    }

    /// OCI-1: プローブの所要時間はトークン寿命から差し引かない（遅いプローブの直後でも新規トークンは有効）。
    #[test]
    fn slow_probe_does_not_shorten_token_lifetime() {
        let mut t = FakeTransport::new(vec![
            resp(401, &[HUB_CHALLENGE], ""),
            resp(200, &[], r#"{"token":"a","expires_in":1}"#),
        ]);
        t.delay_first = Duration::from_millis(1200);
        let RegistryAuth::Bearer(tok) = run(&t).expect("auth") else {
            panic!("expected bearer");
        };
        assert!(!tok.is_expired(Instant::now()));
    }

    /// 1 接続だけ受けて、要求ヘッダを読み、`respond` の返す生の応答を書いて閉じる使い捨てサーバー。
    fn serve_once(respond: impl FnOnce(&str) -> Vec<u8> + Send + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[])).to_string();
                let out = respond(&head);
                let _ = s.write_all(&out);
                let _ = s.flush();
            }
        });
        format!("http://127.0.0.1:{port}/token")
    }

    /// テスト用: 平文 HTTP を許す（本番経路は https_only 固定）以外は本番と同じ設定の通信。
    fn loopback_transport(config: &RegistryClientConfig) -> UreqTransport {
        let agent = build_agent(config, TlsConfig::default(), false, None);
        UreqTransport {
            public_only_agent: agent.clone(),
            agent,
        }
    }

    fn get(
        t: &UreqTransport,
        url: &str,
        limit: Option<u64>,
        timeout: Duration,
    ) -> Result<TransportResponse, OciError> {
        t.get(&TransportRequest {
            url,
            query: &[("scope", "repository:a/b:pull"), ("service", "svc")],
            public_only: false,
            body_limit: limit,
            timeout,
        })
    }

    fn http_ok(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// OCI-1: 実 HTTP で scope / service が query として送られ、本文が返る。
    #[test]
    fn ureq_transport_sends_query_and_reads_body() {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let url = serve_once(move |head| {
            let _ = tx.send(head.to_string());
            http_ok(r#"{"token":"t"}"#)
        });
        let t = loopback_transport(&RegistryClientConfig::default());
        let r = get(&t, &url, Some(1024), Duration::from_secs(5)).expect("get");
        // サーバースレッド内の assert は失敗が伝わらないため、受けた要求を本スレッドで照合する。
        let head = rx.recv_timeout(Duration::from_secs(5)).expect("request");
        let line = head.lines().next().unwrap_or("").to_string();
        assert!(line.starts_with("GET /token?"), "{line}");
        assert!(
            line.contains("scope=repository%3Aa%2Fb%3Apull")
                || line.contains("scope=repository:a/b:pull"),
            "{line}"
        );
        assert!(line.contains("service=svc"), "{line}");
        assert!(!head.to_ascii_lowercase().contains("authorization:"));
        assert_eq!(
            (r.status, r.body.as_slice()),
            (200, br#"{"token":"t"}"#.as_slice())
        );
    }

    /// OCI-1・SEC: リダイレクトは追従せず、成功扱いにもしない。
    #[test]
    fn ureq_transport_does_not_follow_redirects() {
        let url = serve_once(|_| {
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        });
        let t = loopback_transport(&RegistryClientConfig::default());
        match get(&t, &url, Some(1024), Duration::from_secs(5)) {
            Ok(r) => assert_eq!(r.status, 302),
            Err(e) => assert_eq!(e.code(), OciErrorCode::DataLoss),
        }
    }

    /// OCI-1・REPAIR-5: 本文が上限を超えれば ResourceExhausted。
    #[test]
    fn ureq_transport_enforces_body_limit() {
        let url = serve_once(|_| http_ok(&"a".repeat(2000)));
        let t = loopback_transport(&RegistryClientConfig::default());
        let e = get(&t, &url, Some(1000), Duration::from_secs(5)).expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// OCI-1・REPAIR-5: 応答が来なければ全体期限で Timeout。
    #[test]
    fn ureq_transport_times_out() {
        let url = serve_once(|_| {
            std::thread::sleep(Duration::from_secs(3));
            Vec::new()
        });
        let t = loopback_transport(&RegistryClientConfig::default());
        let e = get(&t, &url, Some(1024), Duration::from_millis(300)).expect_err("timeout");
        assert_eq!(e.code(), OciErrorCode::Timeout);
    }

    /// OCI-1・SEC: 公開 IP のみの経路は、ループバックへ解決されるホストへ接続しない（SSRF）。
    #[test]
    fn public_only_agent_refuses_loopback() {
        let url = serve_once(|_| Vec::new());
        let config = RegistryClientConfig::default();
        let agent = build_agent(
            &config,
            TlsConfig::default(),
            false,
            Some(PublicOnlyResolver::default()),
        );
        let t = UreqTransport {
            public_only_agent: agent.clone(),
            agent,
        };
        let e = t
            .get(&TransportRequest {
                url: &url,
                query: &[],
                public_only: true,
                body_limit: Some(1024),
                timeout: Duration::from_secs(5),
            })
            .expect_err("loopback");
        assert_eq!(e.code(), OciErrorCode::PermissionDenied);
    }

    /// SEC: 公開 / 非公開アドレスの判定（具体値）。
    #[test]
    fn public_ip_classification() {
        let private = [
            "0.0.0.0",
            "10.1.2.3",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::10.0.0.1",
            "64:ff9b::a00:1",
            "2002:7f00:1::1",
            "2001:db8::1",
            "64:ff9b:1::a00:1",
            "64:ff9b:1::808:808",
            "64:ff9b::7f00:1",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "3fff::1",
            "5f00::1",
            "100::1",
            "fec0::1",
        ];
        for a in private {
            assert!(!is_public_ip(a.parse().expect("ip")), "{a}");
        }
        let public = [
            "8.8.8.8",
            "104.16.0.1",
            "100.63.255.255",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            "2002:0808:0808::1",
            "64:ff9b::808:808",
            "2001:4860:4860::8888",
        ];
        for a in public {
            assert!(is_public_ip(a.parse().expect("ip")), "{a}");
        }
    }

    /// OCI-1・ERR-1: 実 CPU・実 OS ストアでの構築は panic せず、Ok か想定内の分類のエラーを返す。
    #[test]
    fn real_construction_does_not_panic() {
        match RegistryClient::new(&RegistryClientConfig::default()) {
            Ok(_) => {}
            Err(e) => assert!(matches!(
                e.code(),
                OciErrorCode::Unimplemented | OciErrorCode::FailedPrecondition
            )),
        }
    }
}
