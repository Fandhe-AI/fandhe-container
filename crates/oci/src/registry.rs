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
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use ureq::Agent;
use ureq::config::RedirectAuthHeaders;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

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
        let agent: Agent = Agent::config_builder()
            .tls_config(tls_config)
            .https_only(true)
            .http_status_as_error(false)
            .redirect_auth_headers(RedirectAuthHeaders::Never)
            .max_redirects(config.max_redirects)
            .max_response_header_size(config.max_response_header_bytes)
            .timeout_resolve(Some(config.resolve_timeout))
            .timeout_connect(Some(config.connect_timeout))
            .timeout_send_request(Some(config.send_request_timeout))
            .timeout_recv_response(Some(config.recv_response_timeout))
            .user_agent(concat!("fandhe-container/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Self {
            agent,
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
        let started = Instant::now();
        let timeout = Some(self.config.token_request_timeout);
        let probe = self
            .agent
            .get(endpoint.base_url())
            .config()
            .timeout_global(timeout)
            .max_redirects(0)
            .build()
            .call()
            .map_err(map_ureq_error)?;
        match probe.status().as_u16() {
            200 => return Ok(RegistryAuth::None),
            401 => {}
            s => return Err(status_error(s)),
        }
        let values: Vec<&str> = probe
            .headers()
            .get_all("www-authenticate")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        let challenge = parse_www_authenticate(&values, &endpoint.host)?;

        let mut req = self
            .agent
            .get(challenge.realm.as_str())
            .config()
            .timeout_global(timeout)
            .max_redirects(0)
            .build()
            .query("scope", format!("repository:{}:pull", repository.as_str()));
        if let Some(service) = &challenge.service {
            req = req.query("service", service);
        }
        let mut resp = req.call().map_err(map_ureq_error)?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(status_error(status));
        }
        let body = resp
            .body_mut()
            .with_config()
            .limit(self.config.max_token_response_bytes)
            .read_to_vec()
            .map_err(map_ureq_error)?;
        let token =
            parse_token_response(&body, Instant::now(), SystemTime::now(), started.elapsed())?;
        Ok(RegistryAuth::Bearer(token))
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
