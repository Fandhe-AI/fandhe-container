//! レジストリクライアント基盤: 接続先 URL の組み立てと HTTP `Agent` の構築（TASK-51.1・OCI-1）。
//!
//! 後続の #401（トークン取得・`WWW-Authenticate` 解析）・#402（manifest 取得）・#403（blob のストリーミング取得）
//! が共通で使う土台。**本モジュールは通信する公開メソッドを持たない**（取得処理は未実装で、#401〜#403 で
//! `pub(crate)` の accessor を通して `Agent` を使う。digest 検証は #405。REPAIR-3）。
//!
//! 安全側の既定値:
//! - 平文 HTTP の経路を持たない（`https_only`。scheme は `https` 固定）
//! - HTTP の 4xx / 5xx を ureq のエラーにしない（`http_status_as_error(false)`。401 チャレンジを #401 が扱うため）
//! - リダイレクト先へ `Authorization` を送らない（`RedirectAuthHeaders::Never`）。回数・ヘッダサイズに上限
//! - DNS 解決・connect・リクエスト送信・応答ヘッダ待ちのタイムアウトは `Duration` 必須で、未設定にできない（REPAIR-5）
//!
//! 本文受信（`recv_body`）と全体（`global`）のタイムアウトは既定では無制限のまま。操作ごとの設定（blob の長時間転送を含む）は #401〜#403 で行う。
//! CA ファイルを指定する経路は範囲外（OS のストアと `SSL_CERT_FILE` / `SSL_CERT_DIR` のみ）。

use crate::error::OciError;
use crate::reference::{Digest, Reference, RegistryHost, Repository};
use crate::tls;
use std::time::Duration;
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
        }
    }
}

/// レジストリ通信の土台となる HTTP クライアント（TLS 設定済みの ureq `Agent` を保持する）。
///
/// 取得処理は未実装で、#401（トークン）・#402（manifest）・#403（blob）が追加する（OCI-1）。
#[derive(Debug)]
pub struct RegistryClient {
    agent: Agent,
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
        Ok(Self { agent })
    }

    /// 後続の取得処理（#401〜#403）が使う `Agent`。
    #[allow(dead_code)]
    pub(crate) fn agent(&self) -> &Agent {
        &self.agent
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
