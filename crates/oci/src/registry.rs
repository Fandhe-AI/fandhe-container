//! レジストリクライアント基盤: 接続先 URL の組み立てと HTTP `Agent` の構築（TASK-51.1・OCI-1）。
//!
//! #402（manifest 取得）・#403（blob のストリーミング取得）が共通で使う土台。通信する公開メソッドは
//! 匿名トークン取得の `RegistryClient::authenticate_anonymous`（TASK-51.2・#401）と manifest 取得の
//! `RegistryClient::fetch_manifest`（TASK-51.3・#402）と、blob のストリーミング取得
//! `RegistryClient::fetch_blob`（TASK-51.4・#403）。blob は `fetch_blob` では digest 未検証（`layer::verify_blob_digest` で別途検証する。#405。REPAIR-3）。
//! Basic 認証の検証 `RegistryClient::authenticate_basic`（TASK-54.1・OCI-3・#416）と、資格情報つき Bearer
//! トークン交換 `RegistryClient::authenticate_bearer`（TASK-54.2・OCI-3・#417）と、チャレンジに応じて
//! Basic / Bearer を自動選択する統一入口 `RegistryClient::authenticate`（TASK-54.3・OCI-3・#418）も持つ。
//! 新規利用は `authenticate` を推奨する。OAuth2 の POST フロー（`refresh_token`）は未実装。
//!
//! 安全側の既定値:
//! - 平文 HTTP の経路を持たない（`https_only`。scheme は `https` 固定）
//! - HTTP の 4xx / 5xx を ureq のエラーにしない（`http_status_as_error(false)`。401 チャレンジを #401 が扱うため）
//! - リダイレクト先へ `Authorization` を送らない（`RedirectAuthHeaders::Never`）。回数・ヘッダサイズに上限
//! - DNS 解決・connect・リクエスト送信・応答ヘッダ待ちのタイムアウトは `Duration` 必須で、未設定にできない（REPAIR-5）
//!
//! 本文受信（`recv_body`）と全体（`global`）のタイムアウトは Agent 既定では無制限のまま。トークン取得は
//! リクエスト単位で全体期限（`token_request_timeout`）と本文上限を設ける。blob の長時間転送は
//! `blob_request_timeout`（全体期限）と `max_blob_bytes`（許容サイズ）で縛る。
//! CA ファイルを指定する経路は範囲外（OS のストアと `SSL_CERT_FILE` / `SSL_CERT_DIR` のみ）。

use crate::auth::{
    BasicCredentials, BearerChallenge, RegistryAuth, challenge_offers_basic, parse_token_response,
    parse_www_authenticate, realm_may_receive_credentials,
};
use crate::error::{OciError, OciErrorCode, code_for_http_status};
use crate::image_management::StagedBlobWriter;
use crate::instrument::{NoopOciOpRecorder, OciOpKind, OciOpRecorder, record_oci_op};
use crate::manifest::{
    Descriptor, ImageManifest, MANIFEST_MAX_BYTES, MEDIA_TYPE_DOCKER_LIST,
    MEDIA_TYPE_DOCKER_MANIFEST, MEDIA_TYPE_OCI_INDEX, MEDIA_TYPE_OCI_MANIFEST, ParsedManifest,
    Platform, ensure_supported_layer_media_types, parse_manifest, select_manifest,
};
use crate::reference::{Digest, Reference, RegistryHost, Repository};
use crate::tls;
use sha2::{Digest as _, Sha256};
use std::fmt::Debug;
use std::io::{Read, Write};
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
    /// manifest 取得 1 リクエストあたりの全体期限（REPAIR-5）。
    pub manifest_request_timeout: Duration,
    /// manifest 応答本文の最大バイト数。
    pub max_manifest_bytes: u64,
    /// blob 取得 1 リクエスト（リダイレクトの 1 ホップ）あたりの全体期限（REPAIR-5）。長時間転送を許す値。
    pub blob_request_timeout: Duration,
    /// 1 blob の許容最大バイト数。`Descriptor::size` がこれを超えると通信前に `ResourceExhausted`。
    pub max_blob_bytes: u64,
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
            manifest_request_timeout: Duration::from_secs(30),
            max_manifest_bytes: MANIFEST_MAX_BYTES,
            blob_request_timeout: Duration::from_secs(30 * 60),
            max_blob_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
}

/// レジストリ通信の土台となる HTTP クライアント（TLS 設定済みの ureq `Agent` を保持する）。
///
/// 匿名トークン取得（#401）・manifest 取得（#402）・blob のストリーミング取得（#403）は実装済み（OCI-1）。
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

    /// 後続の取得処理が使う `Agent`（呼び出し元が入るまで未使用）。
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

    /// Basic 認証の資格情報を検証して `RegistryAuth::Basic` を得る（TASK-54.1・OCI-3・#416）。
    ///
    /// まず資格情報なしで `/v2/` を叩き、200 なら認証不要として `RegistryAuth::None`（資格情報は送らない）。
    /// 401 で Basic が提示されていれば、`Authorization: Basic` を付けて同じ `/v2/` を再度叩き、200 なら
    /// `RegistryAuth::Basic`。資格情報の送出先は `endpoint`（https 固定）の `/v2/` だけで、応答由来の
    /// `realm`・`Location` へは送らない。リダイレクトは追従しない。401 / 403 は `PermissionDenied`
    /// （message は固定文で、資格情報・応答本文を載せない）。Bearer のみの提示は `Unimplemented`
    /// （Bearer の資格情報つき交換は `authenticate_bearer`、統一入口は `authenticate`）。再試行はしない。成功・失敗とエラー code・
    /// 所要時間は `with_recorder` の記録先へ 1 件記録する（REPAIR-4。資格情報は記録しない）。
    pub fn authenticate_basic(
        &self,
        endpoint: &RegistryEndpoint,
        credentials: &BasicCredentials,
    ) -> Result<RegistryAuth, OciError> {
        record_oci_op(self.recorder.as_ref(), OciOpKind::AuthenticateBasic, || {
            basic_flow(self.transport.as_ref(), &self.config, endpoint, credentials)
        })
    }

    /// 資格情報つき Bearer トークン交換で `RegistryAuth::Bearer` を得る（TASK-54.2・OCI-3・MS-4・#417）。
    ///
    /// 資格情報なしで `/v2/` を叩き、200 なら認証不要として `RegistryAuth::None`（資格情報は送らない）。
    /// 401 の Bearer チャレンジの realm へ `Authorization: Basic` 付きで GET する（`service` と
    /// `scope=repository:<repo>:pull` を付ける Docker token 認証）。realm は非信頼 URL のため、接続先と同一
    /// ホスト・`trusted_realm_hosts` に明示されたホスト・組み込みの既知対（Docker Hub の `auth.docker.io`）
    /// 以外へは資格情報を送らず、通信せずに `PermissionDenied` を返す（fail-closed）。リダイレクトは追従しない。
    /// 401 / 403 は `PermissionDenied`（message は固定文で資格情報・応答本文を載せない）。Basic のみの提示は
    /// `Unimplemented`。再試行はしない。成功・失敗とエラー code・所要時間は `with_recorder` の記録先へ 1 件
    /// 記録する（REPAIR-4。資格情報・トークンは記録しない）。
    ///
    /// 未実装（将来仕様）: OAuth2 の POST フロー（`grant_type=password` / `refresh_token`。OCI-3）。
    pub fn authenticate_bearer(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        credentials: &BasicCredentials,
        trusted_realm_hosts: &[RegistryHost],
    ) -> Result<RegistryAuth, OciError> {
        record_oci_op(
            self.recorder.as_ref(),
            OciOpKind::AuthenticateBearer,
            || {
                bearer_flow(
                    self.transport.as_ref(),
                    &self.config,
                    endpoint,
                    repository,
                    Some((credentials, trusted_realm_hosts)),
                )
            },
        )
    }

    /// チャレンジに応じて Basic / Bearer を自動選択する統一入口（TASK-54.3・OCI-3・MS-4・#418）。
    ///
    /// 資格情報なしで `/v2/` を 1 回叩き、200 なら `RegistryAuth::None`（資格情報は送らない）。401 で Bearer が
    /// 提示されれば（Basic との併記でも）Bearer を優先し、`credentials` があれば `trusted_realm_hosts`・接続先
    /// 同一ホスト・組み込みの既知対に当たる realm にだけ Basic 資格情報を付けてトークンを取得する（不許可なら
    /// 通信せず `PermissionDenied`）。`credentials` が無ければ匿名取得。Basic のみの提示で `credentials` が
    /// あれば接続先 `/v2/` で検証して `RegistryAuth::Basic`。資格情報が無く Basic のみなら `Unimplemented`。
    /// 401 / 403 は `PermissionDenied`（message は固定文）。リダイレクトは追従せず再試行もしない。成功・失敗は
    /// `OciOpKind::Authenticate` として 1 件記録する（REPAIR-4。資格情報・トークン・URL は記録しない）。
    ///
    /// 未実装（将来仕様）: OAuth2 の POST フロー、トークンのキャッシュと失効時の再取得（OCI-3）。
    pub fn authenticate(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        credentials: Option<&BasicCredentials>,
        trusted_realm_hosts: &[RegistryHost],
    ) -> Result<RegistryAuth, OciError> {
        record_oci_op(self.recorder.as_ref(), OciOpKind::Authenticate, || {
            authenticate_flow(
                self.transport.as_ref(),
                &self.config,
                endpoint,
                repository,
                credentials,
                trusted_realm_hosts,
            )
        })
    }

    /// manifest を取得し、image index なら対象 platform の manifest まで解決する（TASK-51.3・OCI-1）。
    ///
    /// `reference` が tag / digest の image manifest ならそのまま、index / manifest list なら `platform` に
    /// 一致するエントリの digest で 2 回目の取得をする（入れ子は 1 段のみ。2 段目が index なら `DataLoss`）。
    /// `Authorization` は `auth` が Bearer のときだけ接続先レジストリへ送り、リダイレクトは追従しない。
    /// 期限切れの Bearer は通信せず `PermissionDenied`（再取得は呼び出し側）。各リクエストに
    /// `manifest_request_timeout` の全体期限と `max_manifest_bytes` の本文上限がある（REPAIR-5）。
    ///
    /// 未対応のレイヤーの mediaType（gzip 以外。zstd は #2029 で保留中）は、blob を取得する前に
    /// `Unimplemented` で拒否する（#2037・ERR-1）。
    ///
    /// 戻り値は本文 digest 未検証（本文ハッシュと参照 digest の突合は未実装）。成功・失敗とエラー code・所要時間は
    /// `with_recorder` の記録先へ 1 件記録する（REPAIR-4）。
    pub fn fetch_manifest(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        reference: &Reference,
        auth: &RegistryAuth,
        platform: &Platform,
    ) -> Result<ResolvedManifest, OciError> {
        record_oci_op(self.recorder.as_ref(), OciOpKind::FetchManifest, || {
            fetch_manifest_flow(
                self.transport.as_ref(),
                &self.config,
                endpoint,
                repository,
                reference,
                auth,
                platform,
            )
        })
    }

    /// blob（レイヤー・config）を `dest` へストリーミング保存する（TASK-51.4・OCI-1・#2765）。
    ///
    /// `descriptor.size` を期待サイズの正とし、`max_blob_bytes` 超過は通信前に `ResourceExhausted`。応答の
    /// `Content-Length` が期待サイズと食い違えば本文に触れず `DataLoss`。本文は固定長バッファで流し、
    /// `Content-Length` の値でアロケーションしない。本文のバイト数が期待サイズと一致することを確認して成功を返す。
    ///
    /// `dest` は `PullSession::open_staged_blob` が検証済み root の fd 起点で開いた書き込み先で、パスは受け取らない
    /// （OCI-7・SEC-1。root が差し替えられても書き込みは検査済みの実体にだけ届く）。`dest` の digest が
    /// `descriptor.digest` と違えば `InvalidArgument`、既に書き込み済み（失敗後の再利用）なら `FailedPrecondition` を
    /// 通信前に返す。再試行は writer を開き直す契約である。**確定（`StagedBlobWriter::commit`）は呼び出し側が行う**:
    /// この関数は本文を流してサイズを照合するだけで、失敗時の `.part` は writer の drop が消す。
    /// pull では成功後に `commit` → `PullSession::verify_staged_blob` → `PullSession::publish` の順に呼ぶ（#475）。
    ///
    /// CDN へのリダイレクト（301/302/303/307/308）は `max_redirects` 回まで手動で追従する。遷移先は絶対 https
    /// URL のみ許可し、`Authorization` を送らず公開 IP のみへ接続する（SSRF・資格情報漏えい対策）。Location は
    /// 署名付きで秘密を含みうるためエラー・記録に載せない。相対 Location は未対応（拒否）。
    ///
    /// 戻り値は digest 未検証（確定後に `PullSession::verify_staged_blob` で検証する。#405・TASK-52.1）。Range による再開は未対応。トークンの期限検査は開始時のみ。
    /// 成功・失敗とエラー code・所要時間は `with_recorder` の記録先へ 1 件記録する（REPAIR-4）。
    pub fn fetch_blob(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        descriptor: &Descriptor,
        auth: &RegistryAuth,
        dest: &mut StagedBlobWriter,
    ) -> Result<FetchedBlob, OciError> {
        record_oci_op(self.recorder.as_ref(), OciOpKind::FetchBlob, || {
            fetch_blob_flow(
                self.transport.as_ref(),
                &self.config,
                endpoint,
                repository,
                descriptor,
                auth,
                dest,
            )
        })
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
    bearer_flow(transport, config, endpoint, repository, None)
}

/// Bearer トークン取得の共通手順。`credentials` が `None` なら匿名、`Some` なら realm へ Basic 資格情報を
/// 付ける（その場合は `realm_may_receive_credentials` が許可した realm にだけ送る。TASK-54.2・OCI-3）。
fn bearer_flow(
    transport: &dyn RegistryTransport,
    config: &RegistryClientConfig,
    endpoint: &RegistryEndpoint,
    repository: &Repository,
    credentials: Option<(&BasicCredentials, &[RegistryHost])>,
) -> Result<RegistryAuth, OciError> {
    let Some(probe) = probe_v2(transport, config, endpoint)? else {
        return Ok(RegistryAuth::None);
    };
    let values: Vec<&str> = probe.www_authenticate.iter().map(String::as_str).collect();
    let challenge = parse_www_authenticate(&values, &endpoint.host)?;
    bearer_exchange(
        transport,
        config,
        endpoint,
        repository,
        &challenge,
        credentials,
    )
}

/// 資格情報なしで `/v2/` を 1 回叩く。200 なら `None`（認証不要）、401 なら応答（チャレンジ解析は呼び出し側）。
/// それ以外のステータスは分類済みエラー。Basic / Bearer / 統一入口が共有するプローブ（TASK-54.3・OCI-3）。
fn probe_v2(
    transport: &dyn RegistryTransport,
    config: &RegistryClientConfig,
    endpoint: &RegistryEndpoint,
) -> Result<Option<TransportResponse>, OciError> {
    let base_url = endpoint.base_url();
    let probe = transport.get(&TransportRequest {
        url: &base_url,
        query: &[],
        public_only: false,
        body_limit: None,
        timeout: config.token_request_timeout,
        headers: &[],
    })?;
    match probe.status {
        200 => Ok(None),
        401 => Ok(Some(probe)),
        s => Err(status_error(s)),
    }
}

/// 解析済み Bearer チャレンジの realm へトークンを取りにいく（プローブ後の段。TASK-54.2・54.3・OCI-3）。
///
/// `credentials` が `Some` なら `realm_may_receive_credentials` が許可した realm にだけ Basic 資格情報を送る
/// （不許可なら通信せず `PermissionDenied`。fail-closed）。`None` なら匿名取得。
fn bearer_exchange(
    transport: &dyn RegistryTransport,
    config: &RegistryClientConfig,
    endpoint: &RegistryEndpoint,
    repository: &Repository,
    challenge: &BearerChallenge,
    credentials: Option<(&BasicCredentials, &[RegistryHost])>,
) -> Result<RegistryAuth, OciError> {
    let timeout = config.token_request_timeout;
    // 資格情報は検証済みの送出先にだけ付ける。不許可なら通信せずに止める。
    let auth_header = match credentials {
        Some((c, trusted)) => {
            if !realm_may_receive_credentials(&challenge.realm, &endpoint.host, trusted) {
                return Err(OciError::new(
                    OciErrorCode::PermissionDenied,
                    "token realm is not trusted for credentials",
                ));
            }
            Some(c.authorization_header_value())
        }
        None => None,
    };
    let header_pairs: Vec<(&str, &str)> = match &auth_header {
        Some(h) => vec![("Authorization", *h)],
        None => Vec::new(),
    };

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
        headers: &header_pairs,
    })?;
    match resp.status {
        200 => {}
        s @ (401 | 403) if credentials.is_some() => {
            return Err(OciError::new(
                OciErrorCode::PermissionDenied,
                "registry rejected the credentials",
            )
            .with_http_status(s));
        }
        s => return Err(status_error(s)),
    }
    let token = parse_token_response(
        &resp.body,
        Instant::now(),
        SystemTime::now(),
        token_started.elapsed(),
    )?;
    Ok(RegistryAuth::Bearer(token))
}

/// Basic 認証の検証手順（通信は `transport` に委ねる。テストでは差し替える）。
fn basic_flow(
    transport: &dyn RegistryTransport,
    config: &RegistryClientConfig,
    endpoint: &RegistryEndpoint,
    credentials: &BasicCredentials,
) -> Result<RegistryAuth, OciError> {
    let Some(probe) = probe_v2(transport, config, endpoint)? else {
        return Ok(RegistryAuth::None);
    };
    let values: Vec<&str> = probe.www_authenticate.iter().map(String::as_str).collect();
    if !challenge_offers_basic(&values)? {
        // Bearer のみ（または challenge なし）。Basic を送らず、匿名経路の解析で分類する。
        parse_www_authenticate(&values, &endpoint.host)?;
        return Err(OciError::new(
            OciErrorCode::Unimplemented,
            "registry requires bearer token authentication (OCI-3, use authenticate_bearer)",
        ));
    }
    basic_verify(transport, config, endpoint, credentials)
}

/// Basic チャレンジを確認済みの接続先 `/v2/` へ、資格情報つきで再要求して検証する（TASK-54.1・54.3・OCI-3）。
/// 送出先は `endpoint` の `/v2/` に限り、応答由来の URL へは送らない。
fn basic_verify(
    transport: &dyn RegistryTransport,
    config: &RegistryClientConfig,
    endpoint: &RegistryEndpoint,
    credentials: &BasicCredentials,
) -> Result<RegistryAuth, OciError> {
    let timeout = config.token_request_timeout;
    let base_url = endpoint.base_url();
    let header = credentials.authorization_header_value();
    let resp = transport.get(&TransportRequest {
        url: &base_url,
        query: &[],
        public_only: false,
        body_limit: None,
        timeout,
        headers: &[("Authorization", header)],
    })?;
    match resp.status {
        200 => Ok(RegistryAuth::Basic(credentials.clone())),
        s @ (401 | 403) => Err(OciError::new(
            OciErrorCode::PermissionDenied,
            "registry rejected the credentials",
        )
        .with_http_status(s)),
        s => Err(status_error(s)),
    }
}

/// チャレンジに応じて Basic / Bearer を選ぶ統一入口の手順（TASK-54.3・OCI-3）。`/v2/` プローブは 1 回。
///
/// 200 は資格情報を送らず `None`。Bearer チャレンジがあれば Basic との併記でも Bearer を優先する
/// （realm 検証済みの経路に寄せる）。Bearer が無く Basic のみで `credentials` があれば接続先 `/v2/` で検証する。
/// 資格情報が無い場合や、Basic も Bearer も無い場合は通信を増やさず分類済みエラーを返す（fail-closed）。
fn authenticate_flow(
    transport: &dyn RegistryTransport,
    config: &RegistryClientConfig,
    endpoint: &RegistryEndpoint,
    repository: &Repository,
    credentials: Option<&BasicCredentials>,
    trusted_realm_hosts: &[RegistryHost],
) -> Result<RegistryAuth, OciError> {
    let Some(probe) = probe_v2(transport, config, endpoint)? else {
        return Ok(RegistryAuth::None);
    };
    let values: Vec<&str> = probe.www_authenticate.iter().map(String::as_str).collect();
    match parse_www_authenticate(&values, &endpoint.host) {
        Ok(challenge) => bearer_exchange(
            transport,
            config,
            endpoint,
            repository,
            &challenge,
            credentials.map(|c| (c, trusted_realm_hosts)),
        ),
        // Bearer が無く他スキームのみ。Basic が提示され資格情報があるときだけ Basic で検証する。
        Err(e) if e.code() == OciErrorCode::Unimplemented => match credentials {
            Some(c) if challenge_offers_basic(&values)? => {
                basic_verify(transport, config, endpoint, c)
            }
            _ => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// `fetch_manifest` の結果（将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedManifest {
    /// 解決された image manifest（digest 未検証。#405）。
    pub manifest: ImageManifest,
    /// image index から選んだ場合の、選択エントリの digest（直接取得した場合は `None`）。
    pub selected_digest: Option<Digest>,
    /// `manifest` の本文（生バイト列）の sha256。digest 参照・index 経由の選択エントリでは要求 digest と
    /// 突合済み（不一致は `DataLoss`。OCI-1）。tag 直指定の単一 manifest では本文から計算した値で、
    /// レジストリ応答が tag に対して正しいことまでは保証しない。
    pub manifest_digest: Digest,
    /// image index / manifest list を経由して解決したか。
    pub from_index: bool,
    /// index 経由の場合の、index 本文（生バイト列）の sha256。digest 参照では要求 digest と突合済み
    /// （不一致は `DataLoss`。OCI-1）。直接取得した単一 manifest では `None`。
    pub index_digest: Option<Digest>,
}

/// `Accept` に並べる manifest の `mediaType`（定数のみ）。
fn manifest_accept() -> String {
    [
        MEDIA_TYPE_OCI_MANIFEST,
        MEDIA_TYPE_OCI_INDEX,
        MEDIA_TYPE_DOCKER_MANIFEST,
        MEDIA_TYPE_DOCKER_LIST,
    ]
    .join(", ")
}

/// manifest 取得の手順（通信は `transport` に委ねる。テストでは差し替える）。
fn fetch_manifest_flow(
    transport: &dyn RegistryTransport,
    config: &RegistryClientConfig,
    endpoint: &RegistryEndpoint,
    repository: &Repository,
    reference: &Reference,
    auth: &RegistryAuth,
    platform: &Platform,
) -> Result<ResolvedManifest, OciError> {
    let authorization = auth.authorization_header(Instant::now())?;
    let accept = manifest_accept();
    let mut headers: Vec<(&str, &str)> = vec![("Accept", accept.as_str())];
    if let Some(a) = &authorization {
        headers.push(("Authorization", a.as_str()));
    }
    let fetch_one = |reference: &Reference| -> Result<(ParsedManifest, Digest), OciError> {
        let url = endpoint.manifest_url(repository, reference);
        let resp = transport.get(&TransportRequest {
            url: &url,
            query: &[],
            public_only: false,
            body_limit: Some(config.max_manifest_bytes),
            timeout: config.manifest_request_timeout,
            headers: &headers,
        })?;
        if resp.status != 200 {
            return Err(status_error(resp.status));
        }
        // digest 参照は本文のハッシュと突合する（レジストリ応答は非信頼。OCI-1）。
        let hex: String = Sha256::digest(&resp.body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let actual = Digest::parse(&format!("sha256:{hex}"))?;
        if let Reference::Digest(expected) = reference
            && *expected != actual
        {
            return Err(OciError::new(
                OciErrorCode::DataLoss,
                "manifest digest mismatch",
            ));
        }
        let parsed = parse_manifest(&resp.body, resp.content_type.as_deref())?;
        // 未対応のレイヤー（zstd 等）は blob を取得する前に拒否する（#2037・OCI-1・ERR-1）。
        if let ParsedManifest::Image(m) = &parsed {
            ensure_supported_layer_media_types(m)?;
        }
        Ok((parsed, actual))
    };
    match fetch_one(reference)? {
        (ParsedManifest::Image(manifest), manifest_digest) => Ok(ResolvedManifest {
            manifest,
            selected_digest: None,
            manifest_digest,
            from_index: false,
            index_digest: None,
        }),
        (ParsedManifest::Index(index), index_digest) => {
            let selected = select_manifest(&index, platform)?.digest.clone();
            match fetch_one(&Reference::Digest(selected.clone()))? {
                (ParsedManifest::Image(manifest), manifest_digest) => Ok(ResolvedManifest {
                    manifest,
                    selected_digest: Some(selected),
                    manifest_digest,
                    from_index: true,
                    index_digest: Some(index_digest),
                }),
                _ => Err(OciError::new(
                    OciErrorCode::DataLoss,
                    "nested image index is not supported",
                )),
            }
        }
    }
}

/// `fetch_blob` の結果（将来の項目追加に備え `non_exhaustive`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FetchedBlob {
    /// 書き込んだバイト数（`Descriptor::size` と一致を確認済み）。
    pub size: u64,
    /// 要求した digest。**本文のハッシュとは未突合**（確定後に `PullSession::verify_staged_blob` で検証する。検証前のファイルを信頼しない。#405・TASK-52.1）。
    pub digest: Digest,
}

/// リダイレクトとして追従するステータス。
fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// リダイレクト先 Location の検証。絶対 `https://` のみ許可する（レジストリ応答は非信頼。SSRF 対策）。
/// 相対・`http`・userinfo・空白 / 制御文字 / 非 ASCII・バックスラッシュ・過大な長さは `DataLoss`。
fn validate_redirect_location(location: &str) -> Result<(), OciError> {
    const MAX_LOCATION_BYTES: usize = 8 * 1024;
    let bad = || OciError::new(OciErrorCode::DataLoss, "invalid redirect from registry");
    if location.len() > MAX_LOCATION_BYTES
        || !location.is_ascii()
        || location
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || b == b'\\')
    {
        return Err(bad());
    }
    let rest = location.strip_prefix("https://").ok_or_else(bad)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(bad());
    }
    Ok(())
}

/// blob 取得の手順（通信は `transport` に委ねる。テストでは差し替える）。`dest` の検査（digest の一致・未書き込み）を
/// 通信前に行い、本文は [`stream_blob`] で流す。確定は呼び出し側（`StagedBlobWriter::commit`）。
fn fetch_blob_flow(
    transport: &dyn RegistryTransport,
    config: &RegistryClientConfig,
    endpoint: &RegistryEndpoint,
    repository: &Repository,
    descriptor: &Descriptor,
    auth: &RegistryAuth,
    dest: &mut StagedBlobWriter,
) -> Result<FetchedBlob, OciError> {
    if dest.digest() != &descriptor.digest {
        return Err(OciError::new(
            OciErrorCode::InvalidArgument,
            "blob destination does not match the descriptor",
        ));
    }
    if dest.bytes_written() != 0 {
        return Err(OciError::new(
            OciErrorCode::FailedPrecondition,
            "blob destination is already written",
        ));
    }
    let written = stream_blob(
        transport, config, endpoint, repository, descriptor, auth, dest,
    )?;
    Ok(FetchedBlob {
        size: written,
        digest: descriptor.digest.clone(),
    })
}

/// blob 本文を `sink` へ流してバイト数を返す（サイズ上限・リダイレクト追従・サイズ照合）。
fn stream_blob(
    transport: &dyn RegistryTransport,
    config: &RegistryClientConfig,
    endpoint: &RegistryEndpoint,
    repository: &Repository,
    descriptor: &Descriptor,
    auth: &RegistryAuth,
    sink: &mut dyn Write,
) -> Result<u64, OciError> {
    if descriptor.size > config.max_blob_bytes {
        return Err(OciError::new(
            OciErrorCode::ResourceExhausted,
            "blob size exceeds the configured limit",
        ));
    }
    let authorization = auth.authorization_header(Instant::now())?;

    let mut url = endpoint.blob_url(repository, &descriptor.digest);
    let mut hop: u32 = 0;
    let written = loop {
        // 資格情報は接続先レジストリへの最初のホップだけ。CDN 側（署名付き URL）へは送らない。
        let first = hop == 0;
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let (true, Some(a)) = (first, &authorization) {
            headers.push(("Authorization", a.as_str()));
        }
        let resp = transport.get_stream(
            &StreamRequest {
                url: &url,
                public_only: !first,
                headers: &headers,
                timeout: config.blob_request_timeout,
                expected_len: descriptor.size,
            },
            &mut *sink,
        )?;
        if resp.status == 200 {
            break resp.bytes_written;
        }
        if is_redirect(resp.status) {
            let location = resp.location.ok_or_else(|| {
                OciError::new(OciErrorCode::DataLoss, "invalid redirect from registry")
            })?;
            if hop >= config.max_redirects {
                return Err(OciError::new(
                    OciErrorCode::DataLoss,
                    "too many redirects from registry",
                ));
            }
            validate_redirect_location(&location)?;
            url = location;
            hop += 1;
            continue;
        }
        return Err(status_error(resp.status));
    };
    if written != descriptor.size {
        return Err(OciError::new(
            OciErrorCode::DataLoss,
            "blob size does not match the descriptor",
        ));
    }
    Ok(written)
}

/// ローカルファイル書き込み失敗の分類（message は固定文。パスは載せない）。
fn map_sink_error(e: std::io::Error) -> OciError {
    match e.kind() {
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => OciError::new(
            OciErrorCode::ResourceExhausted,
            "no space left for the blob",
        ),
        std::io::ErrorKind::AlreadyExists => OciError::new(
            OciErrorCode::FailedPrecondition,
            "blob staging file already exists",
        ),
        std::io::ErrorKind::PermissionDenied => {
            OciError::new(OciErrorCode::PermissionDenied, "cannot write the blob file")
        }
        _ => OciError::new(OciErrorCode::Internal, "cannot write the blob file"),
    }
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
    /// 追加のリクエストヘッダ（`Accept`・`Authorization`。値は呼び出し側が組み立てた固定形式のみ）。
    headers: &'a [(&'a str, &'a str)],
}

// 本文にトークンが含まれうるため、Debug はテストでのみ導出する（security.md）。
#[cfg_attr(test, derive(Debug))]
struct TransportResponse {
    status: u16,
    www_authenticate: Vec<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

/// blob のストリーミング GET の指定（redirect は常に追従しない。追従は呼び出し側が検証して行う）。
struct StreamRequest<'a> {
    url: &'a str,
    /// true なら解決済み IP が公開アドレスのものにだけ接続する（SSRF 対策）。
    public_only: bool,
    /// 追加のリクエストヘッダ（`Authorization` は呼び出し側が最初のホップにだけ付ける）。
    headers: &'a [(&'a str, &'a str)],
    /// リクエスト全体の期限（REPAIR-5）。
    timeout: Duration,
    /// 期待する本文長（`Descriptor::size`）。`Content-Length` との突合と読み取り上限に使う。
    expected_len: u64,
}

/// ストリーミング GET の結果。本文は `sink` へ流し済みで、ここには持たない。
#[cfg_attr(test, derive(Debug))]
struct StreamResponse {
    status: u16,
    /// 3xx のときの `Location`（本文は読まない）。
    location: Option<String>,
    /// 200 のとき `sink` へ書いたバイト数。
    bytes_written: u64,
}

/// レジストリ通信の境界。実体は ureq、テストでは差し替える。
trait RegistryTransport: Debug + Send + Sync {
    fn get(&self, req: &TransportRequest<'_>) -> Result<TransportResponse, OciError>;

    /// 200 の本文を固定長バッファで `sink` へ流す。`Content-Length` が `expected_len` と食い違う、
    /// または本文が `expected_len` を超える / 満たないなら `DataLoss`。
    fn get_stream(
        &self,
        req: &StreamRequest<'_>,
        sink: &mut dyn Write,
    ) -> Result<StreamResponse, OciError>;
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
        for (k, v) in req.headers {
            builder = builder.header(*k, *v);
        }
        let mut resp = builder.call().map_err(map_ureq_error)?;
        let status = resp.status().as_u16();
        let www_authenticate = resp
            .headers()
            .get_all("www-authenticate")
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok().map(str::to_string));
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
            content_type,
            body,
        })
    }

    fn get_stream(
        &self,
        req: &StreamRequest<'_>,
        sink: &mut dyn Write,
    ) -> Result<StreamResponse, OciError> {
        self.stream(req, sink)
    }
}

impl UreqTransport {
    fn stream(
        &self,
        req: &StreamRequest<'_>,
        sink: &mut dyn Write,
    ) -> Result<StreamResponse, OciError> {
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
        for (k, v) in req.headers {
            builder = builder.header(*k, *v);
        }
        let mut resp = builder.call().map_err(map_ureq_error)?;
        let status = resp.status().as_u16();
        let mismatch = || {
            OciError::new(
                OciErrorCode::DataLoss,
                "blob size does not match the descriptor",
            )
        };
        if (300..400).contains(&status) {
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok().map(str::to_string));
            return Ok(StreamResponse {
                status,
                location,
                bytes_written: 0,
            });
        }
        if status != 200 {
            return Ok(StreamResponse {
                status,
                location: None,
                bytes_written: 0,
            });
        }
        // アロケーション・書き込みの前に Content-Length を期待サイズと突合する。
        if let Some(v) = resp.headers().get("content-length") {
            let len = v.to_str().ok().and_then(|s| s.trim().parse::<u64>().ok());
            if len != Some(req.expected_len) {
                return Err(mismatch());
            }
        }
        let limit = req.expected_len.saturating_add(1);
        let mut reader = resp.body_mut().with_config().limit(limit).reader();
        // Content-Length の値ではなく固定長バッファで流す。
        let mut buf = vec![0u8; STREAM_BUF_BYTES];
        let mut total: u64 = 0;
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => return Err(map_stream_read_error(e)),
            };
            total = total.saturating_add(n as u64);
            if total > req.expected_len {
                return Err(mismatch());
            }
            let chunk = buf.get(..n).ok_or_else(mismatch)?;
            sink.write_all(chunk).map_err(map_sink_error)?;
        }
        if total != req.expected_len {
            return Err(mismatch());
        }
        Ok(StreamResponse {
            status,
            location: None,
            bytes_written: total,
        })
    }
}

/// ストリーミング用の読み取りバッファ長。
const STREAM_BUF_BYTES: usize = 64 * 1024;

/// 本文読み取り中の `io::Error` を分類する（ureq が包んだエラーは元の分類へ戻す）。
fn map_stream_read_error(e: std::io::Error) -> OciError {
    let kind = e.kind();
    match e.into_inner() {
        Some(inner) => match inner.downcast::<ureq::Error>() {
            Ok(ue) => map_ureq_error(*ue),
            Err(_) if kind == std::io::ErrorKind::TimedOut => {
                OciError::new(OciErrorCode::Timeout, "registry request timed out")
            }
            Err(_) => OciError::new(OciErrorCode::Unavailable, "registry is unreachable"),
        },
        None if kind == std::io::ErrorKind::TimedOut => {
            OciError::new(OciErrorCode::Timeout, "registry request timed out")
        }
        None => OciError::new(OciErrorCode::Unavailable, "registry is unreachable"),
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
            let [s0, s1, s2, s3, s4, s5, s6, s7] = v6.segments();
            if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() {
                return false;
            }
            let embedded = |hi: u16, lo: u16| {
                let [a, b] = hi.to_be_bytes();
                let [c, d] = lo.to_be_bytes();
                is_public_v4(Ipv4Addr::new(a, b, c, d))
            };
            if [s0, s1, s2, s3, s4, s5] == [0, 0, 0, 0, 0, 0xffff]
                || [s0, s1, s2, s3, s4, s5] == [0; 6]
            {
                // ::ffff:a.b.c.d（v4-mapped）と ::a.b.c.d（v4-compatible）。
                return embedded(s6, s7);
            }
            if [s0, s1, s2, s3, s4, s5] == [0x64, 0xff9b, 0, 0, 0, 0] {
                // 64:ff9b::/96（well-known NAT64。RFC 6052）。埋め込まれた IPv4 を検査する。
                // 64:ff9b:1::/48（local-use NAT64。RFC 8215）は下の 2000::/3 判定で拒否される。
                return embedded(s6, s7);
            }
            // fail-closed: グローバルユニキャスト 2000::/3 以外（ULA・リンクローカル・サイトローカル・
            // local-use NAT64・SRv6 SID・予約等）はすべて非公開として扱う。
            if s0 & 0xe000 != 0x2000 {
                return false;
            }
            // 2001::/23（IETF プロトコル割り当て。Teredo 2001::/32 を含む）・2001:db8::/32（文書化用）・
            // 3fff::/20（文書化用。RFC 9637）。
            if (s0 == 0x2001 && (s1 < 0x0200 || s1 == 0x0db8)) || (s0 == 0x3fff && s1 < 0x1000) {
                return false;
            }
            if s0 == 0x2002 {
                // 2002::/16（6to4）。
                return embedded(s1, s2);
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
    use crate::manifest::MEDIA_TYPE_OCI_LAYER_GZIP;
    use crate::reference::ImageReference;
    use rustls_native_certs::CertificateResult;
    use std::path::PathBuf;

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
        assert_eq!(c.manifest_request_timeout, Duration::from_secs(30));
        assert_eq!(c.max_manifest_bytes, 4 * 1024 * 1024);
        assert_eq!(c.blob_request_timeout, Duration::from_secs(1800));
        assert_eq!(c.max_blob_bytes, 8 * 1024 * 1024 * 1024);
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
    use std::sync::atomic::{AtomicBool, Ordering};

    type SeenRequest = (String, Vec<(String, String)>, bool, Option<u64>);

    /// 台本どおりに応答し、受けた要求（url・query・public_only・body_limit）を記録する偽の通信。
    #[derive(Debug)]
    struct FakeTransport {
        script: Mutex<Vec<Result<TransportResponse, OciError>>>,
        seen: Mutex<Vec<SeenRequest>>,
        seen_headers: Mutex<Vec<Vec<(String, String)>>>,
        delay_first: Duration,
    }

    impl FakeTransport {
        fn new(script: Vec<Result<TransportResponse, OciError>>) -> Self {
            Self {
                script: Mutex::new(script),
                seen: Mutex::new(Vec::new()),
                seen_headers: Mutex::new(Vec::new()),
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
            self.seen_headers.lock().expect("lock").push(
                req.headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            );
            if first {
                std::thread::sleep(self.delay_first);
            }
            self.script.lock().expect("lock").remove(0)
        }

        fn get_stream(
            &self,
            _req: &StreamRequest<'_>,
            _sink: &mut dyn Write,
        ) -> Result<StreamResponse, OciError> {
            Err(OciError::new(OciErrorCode::Internal, "unexpected stream"))
        }
    }

    fn resp(status: u16, www: &[&str], body: &str) -> Result<TransportResponse, OciError> {
        Ok(TransportResponse {
            status,
            www_authenticate: www.iter().map(|s| s.to_string()).collect(),
            content_type: None,
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

    // ---- manifest 取得フローの照合（OCI-1・TASK-51.3・REPAIR-12。外部通信なし）----

    const HX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn image_body() -> String {
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{MEDIA_TYPE_OCI_MANIFEST}","config":{{"mediaType":"c","digest":"sha256:{HX}","size":1}},"layers":[{{"mediaType":"{MEDIA_TYPE_OCI_LAYER_GZIP}","digest":"sha256:{HX}","size":2}}]}}"#
        )
    }

    /// arm64 用の image manifest（`image_body` と本文を変えて digest を分ける）。
    fn image_body_arm() -> String {
        image_body().replace(r#""size":2"#, r#""size":3"#)
    }

    fn sha_hex(body: &str) -> String {
        Sha256::digest(body.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn index_body() -> String {
        let (ha, hb) = (sha_hex(&image_body()), sha_hex(&image_body_arm()));
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{MEDIA_TYPE_OCI_INDEX}","manifests":[{{"mediaType":"{MEDIA_TYPE_OCI_MANIFEST}","digest":"sha256:{ha}","size":1,"platform":{{"architecture":"amd64","os":"linux"}}}},{{"mediaType":"{MEDIA_TYPE_OCI_MANIFEST}","digest":"sha256:{hb}","size":1,"platform":{{"architecture":"arm64","os":"linux"}}}}]}}"#
        )
    }

    fn manifest_resp(status: u16, body: &str) -> Result<TransportResponse, OciError> {
        Ok(TransportResponse {
            status,
            www_authenticate: Vec::new(),
            content_type: None,
            body: body.as_bytes().to_vec(),
        })
    }

    fn fetch(
        t: &FakeTransport,
        auth: &RegistryAuth,
        arch: &str,
    ) -> Result<ResolvedManifest, OciError> {
        let (ep, repo) = alpine();
        fetch_manifest_flow(
            t,
            &RegistryClientConfig::default(),
            &ep,
            &repo,
            &Reference::Tag(crate::reference::Tag::parse("latest").expect("tag")),
            auth,
            &Platform::for_arch(arch).expect("platform"),
        )
    }

    fn bearer(expires_in: u64) -> RegistryAuth {
        let t = FakeTransport::new(vec![
            resp(401, &[HUB_CHALLENGE], ""),
            resp(
                200,
                &[],
                &format!(r#"{{"token":"tok","expires_in":{expires_in}}}"#),
            ),
        ]);
        run(&t).expect("auth")
    }

    /// OCI-1・ERR-1: 未対応のレイヤーは blob を取得する前に `Unimplemented` で拒否する（#2037）。
    #[test]
    fn manifest_rejects_unsupported_layer_before_blob_fetch() {
        for mt in [
            "application/vnd.oci.image.layer.v1.tar+zstd",
            "application/vnd.oci.image.layer.v1.tar",
            "application/x-unknown",
        ] {
            let body = image_body().replace(MEDIA_TYPE_OCI_LAYER_GZIP, mt);
            let t = FakeTransport::new(vec![manifest_resp(200, &body)]);
            let e = fetch(&t, &bearer(300), "x86_64").expect_err(mt);
            assert_eq!(e.code(), OciErrorCode::Unimplemented);
            assert!(e.message().contains(mt), "{}", e.message());
            let seen = t.seen.lock().expect("lock");
            assert_eq!(seen.len(), 1, "only the manifest GET may happen");
            assert!(seen[0].0.ends_with("/manifests/latest"), "{}", seen[0].0);
        }
    }

    /// OCI-1: index から選ばれた manifest の zstd レイヤーも blob 取得前に拒否する。
    #[test]
    fn manifest_index_selected_manifest_with_zstd_layer_is_rejected() {
        let zstd = "application/vnd.oci.image.layer.v1.tar+zstd";
        let amd = image_body().replace(MEDIA_TYPE_OCI_LAYER_GZIP, zstd);
        let (ha, hb) = (sha_hex(&amd), sha_hex(&image_body_arm()));
        let index = index_body()
            .replace(&sha_hex(&image_body()), &ha)
            .replace(&sha_hex(&image_body_arm()), &hb);
        let t = FakeTransport::new(vec![manifest_resp(200, &index), manifest_resp(200, &amd)]);
        let e = fetch(&t, &bearer(300), "x86_64").expect_err("reject");
        assert_eq!(e.code(), OciErrorCode::Unimplemented);
        assert!(e.message().contains(zstd), "{}", e.message());
        assert_eq!(t.seen.lock().expect("lock").len(), 2);
    }

    /// OCI-1: tag の image manifest は 1 回の GET で解決し、Accept と Authorization を送る。
    #[test]
    fn manifest_direct_image() {
        let t = FakeTransport::new(vec![manifest_resp(200, &image_body())]);
        let r = fetch(&t, &bearer(300), "x86_64").expect("fetch");
        assert!(!r.from_index);
        assert_eq!(r.index_digest, None);
        assert_eq!(r.selected_digest, None);
        assert_eq!(r.manifest.layers.len(), 1);
        let seen = t.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].0,
            "https://registry-1.docker.io/v2/library/alpine/manifests/latest"
        );
        assert!(!seen[0].2, "must not use the public-only path");
        assert_eq!(seen[0].3, Some(MANIFEST_MAX_BYTES));
        let h = t.seen_headers.lock().expect("lock");
        assert_eq!(
            h[0],
            vec![
                (
                    "Accept".to_string(),
                    format!(
                        "{MEDIA_TYPE_OCI_MANIFEST}, {MEDIA_TYPE_OCI_INDEX}, {MEDIA_TYPE_DOCKER_MANIFEST}, {MEDIA_TYPE_DOCKER_LIST}"
                    )
                ),
                ("Authorization".to_string(), "Bearer tok".to_string()),
            ]
        );
    }

    const BASIC_CHALLENGE: &str = r#"Basic realm="Registry Realm""#;
    const ALADDIN: &str = "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==";

    fn aladdin() -> BasicCredentials {
        BasicCredentials::new("Aladdin", "open sesame").expect("credentials")
    }

    fn run_basic(t: &FakeTransport) -> Result<RegistryAuth, OciError> {
        let (ep, _) = alpine();
        basic_flow(t, &RegistryClientConfig::default(), &ep, &aladdin())
    }

    /// OCI-3: 401 Basic チャレンジ → 資格情報つき再要求で成功し、続く manifest 取得にも Basic が載る。
    #[test]
    fn basic_challenge_then_credentials_succeeds() {
        let t = FakeTransport::new(vec![resp(401, &[BASIC_CHALLENGE], ""), resp(200, &[], "")]);
        let auth = run_basic(&t).expect("basic");
        assert!(matches!(auth, RegistryAuth::Basic(_)));
        {
            let seen = t.seen.lock().expect("lock");
            assert_eq!(seen.len(), 2);
            for s in seen.iter() {
                assert_eq!(s.0, "https://registry-1.docker.io/v2/");
                assert!(!s.2, "must not use the public-only path");
            }
            let h = t.seen_headers.lock().expect("lock");
            assert!(h[0].is_empty(), "probe must not carry credentials");
            assert_eq!(
                h[1],
                vec![("Authorization".to_string(), ALADDIN.to_string())]
            );
        }
        let t2 = FakeTransport::new(vec![manifest_resp(200, &image_body())]);
        fetch(&t2, &auth, "x86_64").expect("fetch");
        let h = t2.seen_headers.lock().expect("lock");
        assert!(
            h[0].contains(&("Authorization".to_string(), ALADDIN.to_string())),
            "{:?}",
            h[0]
        );
    }

    /// OCI-3: /v2/ が 200 なら資格情報を送らず認証不要として扱う。
    #[test]
    fn basic_probe_200_sends_no_credentials() {
        let t = FakeTransport::new(vec![resp(200, &[], "")]);
        assert!(matches!(run_basic(&t), Ok(RegistryAuth::None)));
        assert_eq!(t.seen.lock().expect("lock").len(), 1);
    }

    /// OCI-3・SEC: 誤った資格情報は PermissionDenied。message に資格情報・本文を載せない。
    #[test]
    fn basic_rejected_credentials() {
        for status in [401u16, 403] {
            let t = FakeTransport::new(vec![
                resp(401, &[BASIC_CHALLENGE], ""),
                resp(status, &[], "open sesame"),
            ]);
            let e = run_basic(&t).expect_err("rejected");
            assert_eq!(e.code(), OciErrorCode::PermissionDenied);
            assert_eq!(e.http_status(), Some(status));
            assert_eq!(e.message(), "registry rejected the credentials");
        }
    }

    /// OCI-3: Bearer のみの提示は資格情報を送らず Unimplemented。challenge なしの 401 は DataLoss。
    #[test]
    fn basic_other_challenges_send_no_credentials() {
        let t = FakeTransport::new(vec![resp(401, &[HUB_CHALLENGE], "")]);
        let e = run_basic(&t).expect_err("bearer");
        assert_eq!(e.code(), OciErrorCode::Unimplemented);
        assert_eq!(t.seen.lock().expect("lock").len(), 1);
        let t = FakeTransport::new(vec![resp(401, &[], "")]);
        assert_eq!(
            run_basic(&t).expect_err("none").code(),
            OciErrorCode::DataLoss
        );
        assert_eq!(t.seen.lock().expect("lock").len(), 1);
    }

    /// OCI-3: 想定外ステータスとトランスポートエラーの分類。
    #[test]
    fn basic_abnormal_responses() {
        let t = FakeTransport::new(vec![resp(500, &[], "")]);
        let e = run_basic(&t).expect_err("500");
        assert_eq!(e.code(), OciErrorCode::Unavailable);
        let t = FakeTransport::new(vec![resp(401, &[BASIC_CHALLENGE], ""), resp(302, &[], "")]);
        assert_eq!(run_basic(&t).expect_err("302").http_status(), Some(302));
        let t = FakeTransport::new(vec![Err(OciError::new(OciErrorCode::Timeout, "t"))]);
        assert_eq!(
            run_basic(&t).expect_err("timeout").code(),
            OciErrorCode::Timeout
        );
        let t = FakeTransport::new(vec![
            resp(401, &[BASIC_CHALLENGE], ""),
            Err(OciError::new(OciErrorCode::Unavailable, "u")),
        ]);
        assert_eq!(
            run_basic(&t).expect_err("second").code(),
            OciErrorCode::Unavailable
        );
    }

    /// OCI-3・REPAIR-4: 公開メソッド `authenticate_basic` の成功と失敗が 1 件ずつ記録される。
    #[test]
    fn authenticate_basic_public_api_records_outcomes() {
        use crate::instrument::OciOpOutcome;
        let (ep, _) = alpine();
        let rec = Arc::new(crate::instrument::testing::Collect::default());
        let ok = client_with(
            FakeTransport::new(vec![resp(401, &[BASIC_CHALLENGE], ""), resp(200, &[], "")]),
            rec.clone(),
        );
        assert!(matches!(
            ok.authenticate_basic(&ep, &aladdin()),
            Ok(RegistryAuth::Basic(_))
        ));
        let bad = client_with(
            FakeTransport::new(vec![resp(401, &[BASIC_CHALLENGE], ""), resp(401, &[], "")]),
            rec.clone(),
        );
        bad.authenticate_basic(&ep, &aladdin()).expect_err("401");
        let items = rec.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind(), OciOpKind::AuthenticateBasic);
        assert_eq!(items[0].outcome(), OciOpOutcome::Success);
        assert_eq!(items[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(OciErrorCode::PermissionDenied));
    }

    fn run_bearer_at(
        reference: &str,
        t: &FakeTransport,
        trusted: &[RegistryHost],
    ) -> Result<RegistryAuth, OciError> {
        let r = ImageReference::parse(reference).expect("parse");
        let ep = RegistryEndpoint::new(r.registry().clone());
        bearer_flow(
            t,
            &RegistryClientConfig::default(),
            &ep,
            r.repository(),
            Some((&aladdin(), trusted)),
        )
    }

    fn run_bearer(t: &FakeTransport) -> Result<RegistryAuth, OciError> {
        run_bearer_at("alpine", t, &[])
    }

    /// OCI-3・TASK-54.2: スコープ付きトークンを Basic 資格情報で取得し、続く manifest 取得に Bearer が載る。
    #[test]
    fn bearer_exchange_sends_scope_service_and_basic_then_manifest_uses_bearer() {
        let t = FakeTransport::new(vec![
            resp(401, &[HUB_CHALLENGE], ""),
            resp(200, &[], r#"{"token":"tok-1","expires_in":300}"#),
        ]);
        let auth = run_bearer(&t).expect("bearer");
        assert!(matches!(auth, RegistryAuth::Bearer(_)));
        {
            let seen = t.seen.lock().expect("lock");
            assert_eq!(seen.len(), 2);
            assert_eq!(seen[0].0, "https://registry-1.docker.io/v2/");
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
            assert!(seen[1].2, "foreign realm must use the public-only path");
            assert_eq!(
                seen[1].3,
                Some(RegistryClientConfig::default().max_token_response_bytes)
            );
            let h = t.seen_headers.lock().expect("lock");
            assert!(h[0].is_empty(), "probe must not carry credentials");
            assert_eq!(
                h[1],
                vec![("Authorization".to_string(), ALADDIN.to_string())]
            );
        }
        let t2 = FakeTransport::new(vec![manifest_resp(200, &image_body())]);
        fetch(&t2, &auth, "x86_64").expect("fetch");
        let h = t2.seen_headers.lock().expect("lock");
        assert!(
            h[0].contains(&("Authorization".to_string(), "Bearer tok-1".to_string())),
            "{:?}",
            h[0]
        );
    }

    /// OCI-3: /v2/ が 200 なら資格情報を送らず認証不要として扱う。
    #[test]
    fn bearer_probe_200_sends_no_credentials() {
        let t = FakeTransport::new(vec![resp(200, &[], "")]);
        assert!(matches!(run_bearer(&t), Ok(RegistryAuth::None)));
        assert_eq!(t.seen.lock().expect("lock").len(), 1);
    }

    /// OCI-3: 接続先と同一ホストの realm は通常経路で資格情報を付ける。
    #[test]
    fn bearer_same_host_realm_is_allowed() {
        let t = FakeTransport::new(vec![
            resp(
                401,
                &[r#"Bearer realm="https://registry.example/token",service="r""#],
                "",
            ),
            resp(200, &[], r#"{"token":"t","expires_in":300}"#),
        ]);
        run_bearer_at("registry.example/team/app", &t, &[]).expect("bearer");
        let seen = t.seen.lock().expect("lock");
        assert_eq!(seen[1].0, "https://registry.example/token");
        assert!(!seen[1].2);
        assert_eq!(
            t.seen_headers.lock().expect("lock")[1],
            vec![("Authorization".to_string(), ALADDIN.to_string())]
        );
    }

    /// OCI-3・SEC: 未登録の別ホスト realm へは資格情報を送らず、通信 1 回（プローブのみ）で拒否する。
    #[test]
    fn bearer_untrusted_realm_never_receives_credentials() {
        let ch = r#"Bearer realm="https://evil.example/token",service="r""#;
        let t = FakeTransport::new(vec![resp(401, &[ch], "")]);
        let e = run_bearer_at("registry.example/team/app", &t, &[]).expect_err("untrusted");
        assert_eq!(e.code(), OciErrorCode::PermissionDenied);
        assert_eq!(e.message(), "token realm is not trusted for credentials");
        assert_eq!(t.seen.lock().expect("lock").len(), 1);
        assert!(t.seen_headers.lock().expect("lock")[0].is_empty());
        // 明示した信頼ホストなら送る。別ホストの信頼登録では送らない。
        let trusted = [RegistryHost::parse("evil.example").expect("host")];
        let t = FakeTransport::new(vec![
            resp(401, &[ch], ""),
            resp(200, &[], r#"{"token":"t","expires_in":300}"#),
        ]);
        run_bearer_at("registry.example/team/app", &t, &trusted).expect("trusted");
        let other = [RegistryHost::parse("other.example").expect("host")];
        let t = FakeTransport::new(vec![resp(401, &[ch], "")]);
        assert_eq!(
            run_bearer_at("registry.example/team/app", &t, &other)
                .expect_err("not listed")
                .code(),
            OciErrorCode::PermissionDenied
        );
    }

    /// OCI-3・SEC: トークン要求の失敗は分類つきの Result で返り、資格情報・本文を載せない。
    #[test]
    fn bearer_failures_are_classified_and_do_not_leak() {
        for status in [401u16, 403] {
            let t = FakeTransport::new(vec![
                resp(401, &[HUB_CHALLENGE], ""),
                resp(status, &[], "open sesame"),
            ]);
            let e = run_bearer(&t).expect_err("rejected");
            assert_eq!(e.code(), OciErrorCode::PermissionDenied);
            assert_eq!(e.http_status(), Some(status));
            assert_eq!(e.message(), "registry rejected the credentials");
        }
        let t = FakeTransport::new(vec![resp(401, &[HUB_CHALLENGE], ""), resp(500, &[], "")]);
        assert_eq!(
            run_bearer(&t).expect_err("500").code(),
            OciErrorCode::Unavailable
        );
        let t = FakeTransport::new(vec![resp(401, &[HUB_CHALLENGE], ""), resp(302, &[], "")]);
        assert_eq!(run_bearer(&t).expect_err("302").http_status(), Some(302));
        let t = FakeTransport::new(vec![
            resp(401, &[HUB_CHALLENGE], ""),
            Err(OciError::new(OciErrorCode::Timeout, "t")),
        ]);
        assert_eq!(
            run_bearer(&t).expect_err("timeout").code(),
            OciErrorCode::Timeout
        );
        for body in ["not json", r#"{"expires_in":300}"#] {
            let t = FakeTransport::new(vec![resp(401, &[HUB_CHALLENGE], ""), resp(200, &[], body)]);
            assert_eq!(
                run_bearer(&t).expect_err("bad token").code(),
                OciErrorCode::DataLoss
            );
        }
    }

    /// OCI-3: Basic のみの提示は資格情報を送らず Unimplemented。challenge なしの 401 は DataLoss。
    #[test]
    fn bearer_other_challenges_send_no_credentials() {
        let t = FakeTransport::new(vec![resp(401, &[BASIC_CHALLENGE], "")]);
        assert_eq!(
            run_bearer(&t).expect_err("basic").code(),
            OciErrorCode::Unimplemented
        );
        assert_eq!(t.seen.lock().expect("lock").len(), 1);
        let t = FakeTransport::new(vec![resp(401, &[], "")]);
        assert_eq!(
            run_bearer(&t).expect_err("none").code(),
            OciErrorCode::DataLoss
        );
    }

    /// OCI-3・REPAIR-4: 公開メソッド `authenticate_bearer` の成功と失敗が 1 件ずつ記録される。
    #[test]
    fn authenticate_bearer_public_api_records_outcomes() {
        use crate::instrument::OciOpOutcome;
        let (ep, repo) = alpine();
        let rec = Arc::new(crate::instrument::testing::Collect::default());
        let ok = client_with(
            FakeTransport::new(vec![
                resp(401, &[HUB_CHALLENGE], ""),
                resp(200, &[], r#"{"token":"t","expires_in":300}"#),
            ]),
            rec.clone(),
        );
        assert!(matches!(
            ok.authenticate_bearer(&ep, &repo, &aladdin(), &[]),
            Ok(RegistryAuth::Bearer(_))
        ));
        let bad = client_with(
            FakeTransport::new(vec![resp(401, &[HUB_CHALLENGE], ""), resp(401, &[], "")]),
            rec.clone(),
        );
        bad.authenticate_bearer(&ep, &repo, &aladdin(), &[])
            .expect_err("401");
        let items = rec.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind(), OciOpKind::AuthenticateBearer);
        assert_eq!(items[0].outcome(), OciOpOutcome::Success);
        assert_eq!(items[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(OciErrorCode::PermissionDenied));
    }
    /// OCI-1: 認証なしでは Authorization を送らない。
    #[test]
    fn manifest_without_auth_sends_no_authorization() {
        let t = FakeTransport::new(vec![manifest_resp(200, &image_body())]);
        fetch(&t, &RegistryAuth::None, "x86_64").expect("fetch");
        let h = t.seen_headers.lock().expect("lock");
        assert_eq!(h[0].len(), 1);
        assert_eq!(h[0][0].0, "Accept");
    }

    /// OCI-1: index はホスト platform の digest で 2 回目の GET をする（amd64 / arm64 の双方）。
    #[test]
    fn manifest_index_resolves_platform() {
        for (arch, body) in [("x86_64", image_body()), ("aarch64", image_body_arm())] {
            let want = sha_hex(&body);
            let t = FakeTransport::new(vec![
                manifest_resp(200, &index_body()),
                manifest_resp(200, &body),
            ]);
            let r = fetch(&t, &RegistryAuth::None, arch).expect("fetch");
            assert!(r.from_index);
            assert!(r.index_digest.is_some());
            assert_eq!(r.manifest_digest.as_str(), format!("sha256:{want}"));
            assert_eq!(
                r.selected_digest.as_ref().map(|d| d.as_str().to_string()),
                Some(format!("sha256:{want}"))
            );
            let seen = t.seen.lock().expect("lock");
            assert_eq!(seen.len(), 2);
            assert_eq!(
                seen[1].0,
                format!("https://registry-1.docker.io/v2/library/alpine/manifests/sha256:{want}")
            );
        }
    }

    /// OCI-1: index が指す digest と本文のハッシュが食い違えば DataLoss（改ざん・取り違えを登録しない）。
    #[test]
    fn manifest_index_selected_body_digest_mismatch_is_data_loss() {
        let t = FakeTransport::new(vec![
            manifest_resp(200, &index_body()),
            manifest_resp(200, &image_body_arm()),
        ]);
        let e = fetch(&t, &RegistryAuth::None, "x86_64").expect_err("mismatch");
        assert_eq!(e.code(), OciErrorCode::DataLoss);
    }

    /// OCI-1: digest 参照は本文のハッシュと突合する（一致で成功・不一致は DataLoss）。
    #[test]
    fn manifest_by_digest_is_verified_against_body() {
        let (ep, repo) = alpine();
        let run = |want: &str, body: &str| {
            let t = FakeTransport::new(vec![manifest_resp(200, body)]);
            fetch_manifest_flow(
                &t,
                &RegistryClientConfig::default(),
                &ep,
                &repo,
                &Reference::Digest(Digest::parse(&format!("sha256:{want}")).expect("digest")),
                &RegistryAuth::None,
                &Platform::for_arch("x86_64").expect("platform"),
            )
        };
        let body = image_body();
        let ok = run(&sha_hex(&body), &body).expect("match");
        assert_eq!(
            ok.manifest_digest.as_str(),
            format!("sha256:{}", sha_hex(&body))
        );
        let e = run(&sha_hex(&image_body_arm()), &body).expect_err("mismatch");
        assert_eq!(e.code(), OciErrorCode::DataLoss);
    }

    /// OCI-1: platform 不一致は NotFound で、2 回目の取得は起きない。
    #[test]
    fn manifest_index_without_platform_is_not_found() {
        let t = FakeTransport::new(vec![manifest_resp(200, &index_body())]);
        let e = fetch(&t, &RegistryAuth::None, "s390x").expect_err("none");
        assert_eq!(e.code(), OciErrorCode::NotFound);
        assert_eq!(t.seen.lock().expect("lock").len(), 1);
    }

    /// OCI-1: 入れ子の index は DataLoss（再帰しない）。
    #[test]
    fn manifest_nested_index_is_rejected() {
        let t = FakeTransport::new(vec![
            manifest_resp(200, &index_body()),
            manifest_resp(200, &index_body()),
        ]);
        let e = fetch(&t, &RegistryAuth::None, "x86_64").expect_err("nested");
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        assert_eq!(t.seen.lock().expect("lock").len(), 2);
    }

    /// OCI-1: HTTP ステータスと不正本文の分類（panic しない）。
    #[test]
    fn manifest_error_classification() {
        for (status, code) in [
            (404, OciErrorCode::NotFound),
            (401, OciErrorCode::PermissionDenied),
            (429, OciErrorCode::Unavailable),
            (500, OciErrorCode::Unavailable),
        ] {
            let t = FakeTransport::new(vec![manifest_resp(status, "")]);
            let e = fetch(&t, &RegistryAuth::None, "x86_64").expect_err("status");
            assert_eq!((e.code(), e.http_status()), (code, Some(status)));
        }
        let t = FakeTransport::new(vec![manifest_resp(200, "{broken")]);
        assert_eq!(
            fetch(&t, &RegistryAuth::None, "x86_64")
                .expect_err("json")
                .code(),
            OciErrorCode::DataLoss
        );
        let t = FakeTransport::new(vec![manifest_resp(
            200,
            r#"{"schemaVersion":2,"mediaType":"text/plain"}"#,
        )]);
        assert_eq!(
            fetch(&t, &RegistryAuth::None, "x86_64")
                .expect_err("type")
                .code(),
            OciErrorCode::Unimplemented
        );
    }

    /// OCI-1: 期限切れの Bearer では通信せず PermissionDenied。
    #[test]
    fn manifest_expired_token_makes_no_request() {
        let auth = {
            let t = FakeTransport::new(vec![
                resp(401, &[HUB_CHALLENGE], ""),
                resp(
                    200,
                    &[],
                    r#"{"token":"a","expires_in":60,"issued_at":"2020-01-01T00:00:00Z"}"#,
                ),
            ]);
            run(&t).expect("auth")
        };
        let t = FakeTransport::new(vec![]);
        let e = fetch(&t, &auth, "x86_64").expect_err("expired");
        assert_eq!(e.code(), OciErrorCode::PermissionDenied);
        assert!(t.seen.lock().expect("lock").is_empty());
    }

    /// OCI-1・REPAIR-4: 公開メソッド `fetch_manifest` の成功と失敗が 1 件ずつ記録される。
    #[test]
    fn fetch_manifest_public_api_records_outcomes() {
        use crate::instrument::{OciOpKind, OciOpOutcome};
        let (ep, repo) = alpine();
        let reference = Reference::Tag(crate::reference::Tag::parse("latest").expect("tag"));
        let p = Platform::for_arch("x86_64").expect("platform");
        let rec = Arc::new(crate::instrument::testing::Collect::default());
        let ok = client_with(
            FakeTransport::new(vec![manifest_resp(200, &image_body())]),
            rec.clone(),
        );
        ok.fetch_manifest(&ep, &repo, &reference, &RegistryAuth::None, &p)
            .expect("ok");
        let bad = client_with(
            FakeTransport::new(vec![manifest_resp(404, "")]),
            rec.clone(),
        );
        bad.fetch_manifest(&ep, &repo, &reference, &RegistryAuth::None, &p)
            .expect_err("404");
        let items = rec.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind(), OciOpKind::FetchManifest);
        assert_eq!(items[0].outcome(), OciOpOutcome::Success);
        assert_eq!(items[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(OciErrorCode::NotFound));
    }

    /// OCI-1: 実 HTTP で追加ヘッダが送られ、Content-Type が返る。
    #[test]
    fn ureq_transport_sends_headers_and_reads_content_type() {
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let (url, _srv) = serve_once(move |head| {
            let _ = tx.send(head.to_string());
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {MEDIA_TYPE_OCI_MANIFEST}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
            .into_bytes()
        });
        let t = loopback_transport(&RegistryClientConfig::default());
        let r = t
            .get(&TransportRequest {
                url: &url,
                query: &[],
                public_only: false,
                body_limit: Some(1024),
                timeout: Duration::from_secs(5),
                headers: &[
                    ("Accept", "application/x-test"),
                    ("Authorization", "Bearer t"),
                ],
            })
            .expect("get");
        let head = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("request")
            .to_ascii_lowercase();
        assert!(head.contains("accept: application/x-test"), "{head}");
        assert!(head.contains("authorization: bearer t"), "{head}");
        assert_eq!(r.content_type.as_deref(), Some(MEDIA_TYPE_OCI_MANIFEST));
        assert_eq!(r.body, b"{}");
    }

    /// `serve_once` のサーバースレッドの回収用ガード。drop で停止を通知して join する
    /// （接続が来なかったテストでもスレッドを残さない。REPAIR-5）。
    struct ServerGuard {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for ServerGuard {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    /// 1 接続だけ受けて、要求ヘッダを読み、`respond` の返す生の応答を書いて閉じる使い捨てサーバー。
    /// accept は非ブロッキングの定期確認で 10 秒の期限と停止通知を持ち、読み書きにも期限を付ける（REPAIR-5）。
    fn serve_once(respond: impl FnOnce(&str) -> Vec<u8> + Send + 'static) -> (String, ServerGuard) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_in = stop.clone();
        let handle = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stop_in.load(Ordering::SeqCst) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_nonblocking(false);
                        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                        let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
                        let mut buf = [0u8; 4096];
                        let n = s.read(&mut buf).unwrap_or(0);
                        let head = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[])).to_string();
                        let out = respond(&head);
                        let _ = s.write_all(&out);
                        let _ = s.flush();
                        return;
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        (
            format!("http://127.0.0.1:{port}/token"),
            ServerGuard {
                stop,
                handle: Some(handle),
            },
        )
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
            headers: &[],
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
        let (url, _srv) = serve_once(move |head| {
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
        let (url, _srv) = serve_once(|_| {
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
        let (url, _srv) = serve_once(|_| http_ok(&"a".repeat(2000)));
        let t = loopback_transport(&RegistryClientConfig::default());
        let e = get(&t, &url, Some(1000), Duration::from_secs(5)).expect_err("limit");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);
    }

    /// OCI-1・REPAIR-5: 応答が来なければ全体期限で Timeout。
    #[test]
    fn ureq_transport_times_out() {
        let (url, _srv) = serve_once(|_| {
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
        let (url, _srv) = serve_once(|_| Vec::new());
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
                headers: &[],
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

    // ---- blob 取得フローの照合（OCI-1・TASK-51.4・REPAIR-12。外部通信なし）----

    /// 台本 1 ステップ: 応答ステータス・Location・sink へ流すチャンク。
    struct StreamStep {
        status: u16,
        location: Option<&'static str>,
        chunks: Vec<Vec<u8>>,
    }

    fn step(status: u16, location: Option<&'static str>, chunks: Vec<Vec<u8>>) -> StreamStep {
        StreamStep {
            status,
            location,
            chunks,
        }
    }

    type SeenStream = (String, bool, Vec<(String, String)>, u64);

    /// `get_stream` の台本どおりに応答し、受けた要求を記録する偽の通信。
    #[derive(Debug)]
    struct FakeStream {
        script: Mutex<Vec<StreamStep>>,
        seen: Mutex<Vec<SeenStream>>,
    }

    impl Debug for StreamStep {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("StreamStep")
        }
    }

    impl FakeStream {
        fn new(script: Vec<StreamStep>) -> Self {
            Self {
                script: Mutex::new(script),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl RegistryTransport for FakeStream {
        fn get(&self, _req: &TransportRequest<'_>) -> Result<TransportResponse, OciError> {
            Err(OciError::new(OciErrorCode::Internal, "unexpected get"))
        }

        fn get_stream(
            &self,
            req: &StreamRequest<'_>,
            sink: &mut dyn Write,
        ) -> Result<StreamResponse, OciError> {
            self.seen.lock().expect("lock").push((
                req.url.to_string(),
                req.public_only,
                req.headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                req.expected_len,
            ));
            let s = self.script.lock().expect("lock").remove(0);
            let mut n = 0u64;
            for c in &s.chunks {
                sink.write_all(c).map_err(map_sink_error)?;
                n += c.len() as u64;
            }
            Ok(StreamResponse {
                status: s.status,
                location: s.location.map(str::to_string),
                bytes_written: n,
            })
        }
    }

    /// 一意な一時ストア root（0700。drop で削除）。`PullSession::open_staged_blob` の writer を得る土台。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fandhe-oci-blob-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&p).expect("mkdir");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))
                    .expect("chmod");
            }
            Self(p)
        }
        fn store(&self) -> crate::image_management::ImageStore {
            crate::image_management::ImageStore::open(&self.0).expect("open store")
        }
        /// ステージング配下の pull ディレクトリ内の名前の一覧（`@pull.lock` を除く。pull が 1 件の試験用）。
        fn staged_names(&self) -> Vec<String> {
            let mut out = Vec::new();
            let Ok(rd) = std::fs::read_dir(self.0.join("staging")) else {
                return out;
            };
            for e in rd.flatten() {
                for f in std::fs::read_dir(e.path())
                    .expect("read pull dir")
                    .flatten()
                {
                    let n = f.file_name().to_string_lossy().into_owned();
                    if n != crate::image_management::PULL_LOCK_FILE_NAME {
                        out.push(n);
                    }
                }
            }
            out.sort();
            out
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn desc(size: u64) -> Descriptor {
        Descriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            digest: Digest::parse(&format!("sha256:{HX}")).expect("digest"),
            size,
            platform: None,
        }
    }

    /// 本文を `Vec` へ流して `(書いたバイト数, 本文)` を返す（確定は `StagedBlobWriter` の試験が担う）。
    fn blob(
        t: &FakeStream,
        auth: &RegistryAuth,
        d: &Descriptor,
    ) -> Result<(u64, Vec<u8>), OciError> {
        let (ep, repo) = alpine();
        let mut sink: Vec<u8> = Vec::new();
        let n = stream_blob(
            t,
            &RegistryClientConfig::default(),
            &ep,
            &repo,
            d,
            auth,
            &mut sink,
        )?;
        Ok((n, sink))
    }

    const CDN: &str = "https://cdn.example.com/signed/abc?sig=1";

    /// OCI-1: 200 の本文がファイルへ書かれ、`.part` は残らず、固定の URL・ヘッダで 1 回だけ要求する。
    #[test]
    fn blob_direct_200_writes_file() {
        let t = FakeStream::new(vec![step(
            200,
            None,
            vec![b"hello ".to_vec(), b"world".to_vec()],
        )]);
        let (n, body) = blob(&t, &bearer(300), &desc(11)).expect("blob");
        assert_eq!(n, 11);
        assert_eq!(body, b"hello world");
        let seen = t.seen.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].0,
            format!("https://registry-1.docker.io/v2/library/alpine/blobs/sha256:{HX}")
        );
        assert!(!seen[0].1);
        assert_eq!(
            seen[0].2,
            vec![("Authorization".to_string(), "Bearer tok".to_string())]
        );
        assert_eq!(seen[0].3, 11);
    }

    /// OCI-1・SEC: CDN へのリダイレクトでは Authorization を送らず、公開 IP のみの経路を使う。
    #[test]
    fn blob_redirect_drops_authorization_and_uses_public_only() {
        let t = FakeStream::new(vec![
            step(307, Some(CDN), vec![]),
            step(200, None, vec![b"abc".to_vec()]),
        ]);
        let (_, body) = blob(&t, &bearer(300), &desc(3)).expect("blob");
        let seen = t.seen.lock().expect("lock");
        assert_eq!(seen.len(), 2);
        assert!(!seen[0].1 && seen[0].2.len() == 1);
        assert_eq!(seen[1].0, CDN);
        assert!(seen[1].1, "redirect target must use the public-only path");
        assert!(
            seen[1].2.is_empty(),
            "no Authorization to the redirect target"
        );
        assert_eq!(body, b"abc");
    }

    /// OCI-3・SEC: Basic でも最初のホップだけに Authorization を付け、CDN 側へは送らない。
    #[test]
    fn blob_redirect_drops_basic_authorization() {
        let t = FakeStream::new(vec![
            step(307, Some(CDN), vec![]),
            step(200, None, vec![b"abc".to_vec()]),
        ]);
        let auth = RegistryAuth::Basic(
            BasicCredentials::new("Aladdin", "open sesame").expect("credentials"),
        );
        blob(&t, &auth, &desc(3)).expect("blob");
        let seen = t.seen.lock().expect("lock");
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0].2,
            vec![(
                "Authorization".to_string(),
                "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==".to_string()
            )]
        );
        assert!(seen[1].1 && seen[1].2.is_empty());
    }

    /// OCI-1・SEC: 不正な Location（http・相対・userinfo・制御文字）は追従せず DataLoss。ファイルは残らない。
    #[test]
    fn blob_rejects_bad_redirect_locations() {
        for loc in [
            "http://cdn.example.com/x",
            "/relative/path",
            "//cdn.example.com/x",
            "https://user@cdn.example.com/x",
            "https://cdn.example.com/x y",
            "https://cdn.example.com/x\r\nHost: evil",
            "https:///x",
        ] {
            let t = FakeStream::new(vec![step(302, Some(loc), vec![])]);
            let e = blob(&t, &RegistryAuth::None, &desc(3)).expect_err(loc);
            assert_eq!(e.code(), OciErrorCode::DataLoss, "{loc:?}");
            assert_eq!(t.seen.lock().expect("lock").len(), 1);
        }
        let t = FakeStream::new(vec![step(302, None, vec![])]);
        let e = blob(&t, &RegistryAuth::None, &desc(3)).expect_err("no location");
        assert_eq!(e.code(), OciErrorCode::DataLoss);
    }

    /// OCI-1・REPAIR-5: リダイレクト回数が上限を超えたら DataLoss。
    #[test]
    fn blob_redirect_limit() {
        let n = RegistryClientConfig::default().max_redirects as usize + 1;
        let t = FakeStream::new((0..n).map(|_| step(302, Some(CDN), vec![])).collect());
        let e = blob(&t, &RegistryAuth::None, &desc(3)).expect_err("loop");
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        assert_eq!(t.seen.lock().expect("lock").len(), n);
    }

    /// OCI-1・REPAIR-5: 事前検査（サイズ上限・期限切れトークン）は通信 0 回で失敗する。
    #[test]
    fn blob_precondition_failures_make_no_request() {
        let (ep, repo) = alpine();
        let cfg = RegistryClientConfig::default();
        let t = FakeStream::new(vec![]);
        let mut sink: Vec<u8> = Vec::new();
        let e = stream_blob(
            &t,
            &cfg,
            &ep,
            &repo,
            &desc(cfg.max_blob_bytes + 1),
            &RegistryAuth::None,
            &mut sink,
        )
        .expect_err("too big");
        assert_eq!(e.code(), OciErrorCode::ResourceExhausted);

        let expired = {
            let t = FakeTransport::new(vec![
                resp(401, &[HUB_CHALLENGE], ""),
                resp(
                    200,
                    &[],
                    r#"{"token":"a","expires_in":60,"issued_at":"2020-01-01T00:00:00Z"}"#,
                ),
            ]);
            run(&t).expect("auth")
        };
        let e = blob(&t, &expired, &desc(3)).expect_err("expired");
        assert_eq!(e.code(), OciErrorCode::PermissionDenied);
        assert!(t.seen.lock().expect("lock").is_empty());
    }

    /// OCI-1・OCI-7・SEC-1（#2765）: `dest` の digest が descriptor と違えば `InvalidArgument`、書き込み済みの writer の
    /// 再利用は `FailedPrecondition`。どちらも通信 0 回で、writer の中身は変わらない。
    #[test]
    fn blob_dest_mismatch_and_reuse_make_no_request() {
        let tmp = TmpDir::new("dest-checks");
        let store = tmp.store();
        let mut session = store.begin_pull_generated().expect("begin");
        let (ep, repo) = alpine();
        let cfg = RegistryClientConfig::default();
        let t = FakeStream::new(vec![]);

        let other = Digest::parse(&format!("sha256:{}", "b".repeat(64))).expect("digest");
        let mut w = session.open_staged_blob(&other).expect("writer");
        let e = fetch_blob_flow(&t, &cfg, &ep, &repo, &desc(3), &RegistryAuth::None, &mut w)
            .expect_err("digest mismatch");
        assert_eq!(e.code(), OciErrorCode::InvalidArgument);
        assert_eq!(
            e.message(),
            "blob destination does not match the descriptor"
        );
        assert_eq!(w.bytes_written(), 0);
        drop(w);

        let d = desc(3);
        let mut w = session.open_staged_blob(&d.digest).expect("writer");
        w.write_all(b"x").expect("write");
        let e = fetch_blob_flow(&t, &cfg, &ep, &repo, &d, &RegistryAuth::None, &mut w)
            .expect_err("already written");
        assert_eq!(e.code(), OciErrorCode::FailedPrecondition);
        assert_eq!(w.bytes_written(), 1);
        assert!(t.seen.lock().expect("lock").is_empty());
        drop(w);
        let _ = session.abort();
    }

    /// OCI-1: 401 / 403 / 404 は分類つきのエラー。
    #[test]
    fn blob_status_errors() {
        for (status, code) in [
            (401, OciErrorCode::PermissionDenied),
            (403, OciErrorCode::PermissionDenied),
            (404, OciErrorCode::NotFound),
            (500, OciErrorCode::Unavailable),
        ] {
            let t = FakeStream::new(vec![step(status, None, vec![])]);
            let e = blob(&t, &RegistryAuth::None, &desc(3)).expect_err("status");
            assert_eq!((e.code(), e.http_status()), (code, Some(status)));
        }
    }

    /// OCI-1: 書いたサイズが descriptor と違えば DataLoss。
    #[test]
    fn blob_size_mismatch_is_data_loss() {
        for body in [b"toolong!".to_vec(), b"ab".to_vec()] {
            let t = FakeStream::new(vec![step(200, None, vec![body])]);
            let e = blob(&t, &RegistryAuth::None, &desc(3)).expect_err("mismatch");
            assert_eq!(e.code(), OciErrorCode::DataLoss);
        }
    }

    /// OCI-1: サイズ 0 の blob は空の本文で成功する。
    #[test]
    fn blob_zero_length_succeeds_with_empty_body() {
        let t = FakeStream::new(vec![step(200, None, vec![])]);
        let (n, body) = blob(&t, &RegistryAuth::None, &desc(0)).expect("blob");
        assert_eq!((n, body), (0, Vec::new()));
    }

    /// OCI-1・OCI-7（#2765）: 公開メソッド `fetch_blob` が検査済み root の fd 起点の writer へ書き、`commit` の後に
    /// `<hex>` だけが残る（`.part` なし）。失敗した取得は `.part` を残さない。成功と失敗は 1 件ずつ記録される。
    #[test]
    fn fetch_blob_public_api_writes_through_writer_and_records_outcomes() {
        use crate::instrument::{OciOpKind, OciOpOutcome};
        let (ep, repo) = alpine();
        let tmp = TmpDir::new("record");
        let store = tmp.store();
        let mut session = store.begin_pull_generated().expect("begin");
        let rec = Arc::new(crate::instrument::testing::Collect::default());
        let mk = |t: FakeStream| RegistryClient {
            agent: Agent::new_with_config(Config::default()),
            transport: Arc::new(t),
            config: RegistryClientConfig::default(),
            recorder: rec.clone(),
        };
        let d = desc(3);
        let mut w = session.open_staged_blob(&d.digest).expect("writer");
        let got = mk(FakeStream::new(vec![step(
            200,
            None,
            vec![b"abc".to_vec()],
        )]))
        .fetch_blob(&ep, &repo, &d, &RegistryAuth::None, &mut w)
        .expect("ok");
        assert_eq!(got.size, 3);
        assert_eq!(got.digest, d.digest);
        assert_eq!(tmp.staged_names(), vec![format!("{HX}.part")]);
        w.commit().expect("commit");
        assert_eq!(tmp.staged_names(), vec![HX.to_string()]);
        let _ = session.abort();

        let mut session = store.begin_pull_generated().expect("begin");
        let mut w = session.open_staged_blob(&d.digest).expect("writer");
        mk(FakeStream::new(vec![step(404, None, vec![])]))
            .fetch_blob(&ep, &repo, &d, &RegistryAuth::None, &mut w)
            .expect_err("404");
        drop(w);
        assert_eq!(tmp.staged_names(), Vec::<String>::new());
        let _ = session.abort();
        let items = rec.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind(), OciOpKind::FetchBlob);
        assert_eq!(items[0].outcome(), OciOpOutcome::Success);
        assert_eq!(items[1].outcome(), OciOpOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(OciErrorCode::NotFound));
    }

    // ---- UreqTransport::get_stream の実 HTTP 照合（ループバック）----

    fn stream_get(
        t: &UreqTransport,
        url: &str,
        expected_len: u64,
        timeout: Duration,
        sink: &mut Vec<u8>,
    ) -> Result<StreamResponse, OciError> {
        t.get_stream(
            &StreamRequest {
                url,
                public_only: false,
                headers: &[],
                timeout,
                expected_len,
            },
            sink,
        )
    }

    /// OCI-1: 64 KiB を超える本文（バッファ複数周回）が欠けず書かれる。
    #[test]
    fn stream_writes_large_body() {
        let body = "a".repeat(200_000);
        let b = body.clone();
        let (url, _srv) = serve_once(move |_| http_ok(&b));
        let t = loopback_transport(&RegistryClientConfig::default());
        let mut out = Vec::new();
        let r = stream_get(&t, &url, 200_000, Duration::from_secs(5), &mut out).expect("get");
        assert_eq!((r.status, r.bytes_written), (200, 200_000));
        assert_eq!(out, body.as_bytes());
    }

    /// OCI-1・REPAIR-5: Content-Length が期待サイズと違えば本文を書かずに DataLoss。
    #[test]
    fn stream_rejects_content_length_mismatch() {
        let (url, _srv) = serve_once(|_| http_ok("hello"));
        let t = loopback_transport(&RegistryClientConfig::default());
        let mut out = Vec::new();
        let e = stream_get(&t, &url, 3, Duration::from_secs(5), &mut out).expect_err("cl");
        assert_eq!(e.code(), OciErrorCode::DataLoss);
        assert!(out.is_empty());
    }

    /// OCI-1: Content-Length の無い（close 終端）応答でも期待サイズ超過・不足を検出する。
    #[test]
    fn stream_detects_overrun_and_underrun_without_content_length() {
        let raw = |n: usize| {
            let mut v = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
            v.extend(std::iter::repeat_n(b'a', n));
            v
        };
        for (sent, expected) in [(2000usize, 1000u64), (500, 1000)] {
            let (url, _srv) = serve_once(move |_| raw(sent));
            let t = loopback_transport(&RegistryClientConfig::default());
            let mut out = Vec::new();
            let e =
                stream_get(&t, &url, expected, Duration::from_secs(5), &mut out).expect_err("size");
            assert_eq!(e.code(), OciErrorCode::DataLoss);
            assert!(out.len() as u64 <= expected);
        }
    }

    /// OCI-1: 3xx は Location を返し、追従も本文の読み取りもしない。
    #[test]
    fn stream_returns_location_without_following() {
        let (url, _srv) = serve_once(|_| {
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://cdn.example.com/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        });
        let t = loopback_transport(&RegistryClientConfig::default());
        let mut out = Vec::new();
        let r = stream_get(&t, &url, 3, Duration::from_secs(5), &mut out).expect("get");
        assert_eq!(r.status, 307);
        assert_eq!(r.location.as_deref(), Some("https://cdn.example.com/x"));
        assert!(out.is_empty());
    }

    /// OCI-1・REPAIR-5: 応答が来なければ全体期限で Timeout。
    #[test]
    fn stream_times_out() {
        let (url, _srv) = serve_once(|_| {
            std::thread::sleep(Duration::from_secs(3));
            Vec::new()
        });
        let t = loopback_transport(&RegistryClientConfig::default());
        let mut out = Vec::new();
        let e = stream_get(&t, &url, 3, Duration::from_millis(300), &mut out).expect_err("to");
        assert_eq!(e.code(), OciErrorCode::Timeout);
    }

    /// OCI-1・SEC: 公開 IP のみの経路は、ループバックのリダイレクト先へ接続しない（SSRF）。
    #[test]
    fn stream_public_only_refuses_loopback() {
        let (url, _srv) = serve_once(|_| Vec::new());
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
        let mut out = Vec::new();
        let e = t
            .get_stream(
                &StreamRequest {
                    url: &url,
                    public_only: true,
                    headers: &[],
                    timeout: Duration::from_secs(5),
                    expected_len: 3,
                },
                &mut out,
            )
            .expect_err("loopback");
        assert_eq!(e.code(), OciErrorCode::PermissionDenied);
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

    // ---- 統一入口 authenticate と一連の pull の照合（OCI-3・TASK-54.3・REPAIR-12。外部通信なし）----

    use crate::instrument::OciOpOutcome as AuthOutcome;

    fn run_auth(
        t: &FakeTransport,
        creds: Option<&BasicCredentials>,
        trusted: &[RegistryHost],
    ) -> Result<RegistryAuth, OciError> {
        let (ep, repo) = alpine();
        authenticate_flow(
            t,
            &RegistryClientConfig::default(),
            &ep,
            &repo,
            creds,
            trusted,
        )
    }

    /// OCI-3: プローブが 200 なら資格情報があっても送らず `None`。通信は 1 回だけ。
    #[test]
    fn authenticate_probe_200_sends_no_credentials() {
        let t = FakeTransport::new(vec![resp(200, &[], "")]);
        assert!(matches!(
            run_auth(&t, Some(&aladdin()), &[]),
            Ok(RegistryAuth::None)
        ));
        assert_eq!(t.seen.lock().expect("lock").len(), 1);
        assert!(t.seen_headers.lock().expect("lock")[0].is_empty());
    }

    /// OCI-3: Bearer + 資格情報 → realm へ Basic・scope・service を付け、プローブは 1 回。
    #[test]
    fn authenticate_bearer_with_credentials_probes_once() {
        let t = FakeTransport::new(vec![
            resp(401, &[HUB_CHALLENGE], ""),
            resp(200, &[], r#"{"token":"tok","expires_in":300}"#),
        ]);
        let auth = run_auth(&t, Some(&aladdin()), &[]).expect("auth");
        assert!(matches!(auth, RegistryAuth::Bearer(_)));
        let seen = t.seen.lock().expect("lock");
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, "https://registry-1.docker.io/v2/");
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
        let h = t.seen_headers.lock().expect("lock");
        assert!(h[0].is_empty());
        assert_eq!(
            h[1],
            vec![("Authorization".to_string(), ALADDIN.to_string())]
        );
    }

    /// OCI-3: Bearer + 資格情報なし → 匿名取得（Authorization なし）。
    #[test]
    fn authenticate_bearer_without_credentials_is_anonymous() {
        let t = FakeTransport::new(vec![
            resp(401, &[HUB_CHALLENGE], ""),
            resp(200, &[], r#"{"token":"tok","expires_in":300}"#),
        ]);
        let auth = run_auth(&t, None, &[]).expect("auth");
        assert!(matches!(auth, RegistryAuth::Bearer(_)));
        let h = t.seen_headers.lock().expect("lock");
        assert!(h[0].is_empty() && h[1].is_empty());
    }

    /// OCI-3: Basic のみ + 資格情報 → 接続先 /v2/ を資格情報つきで再要求して `Basic`。
    #[test]
    fn authenticate_basic_only_verifies_on_endpoint() {
        let t = FakeTransport::new(vec![resp(401, &[BASIC_CHALLENGE], ""), resp(200, &[], "")]);
        let auth = run_auth(&t, Some(&aladdin()), &[]).expect("auth");
        assert!(matches!(auth, RegistryAuth::Basic(_)));
        let seen = t.seen.lock().expect("lock");
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].0, "https://registry-1.docker.io/v2/");
        assert!(!seen[1].2);
        let h = t.seen_headers.lock().expect("lock");
        assert!(h[0].is_empty());
        assert_eq!(
            h[1],
            vec![("Authorization".to_string(), ALADDIN.to_string())]
        );
    }

    /// OCI-3: Basic のみ + 資格情報なし → 追加通信せず Unimplemented（資格情報が必要）。
    #[test]
    fn authenticate_basic_only_without_credentials_is_classified() {
        let t = FakeTransport::new(vec![resp(401, &[BASIC_CHALLENGE], "")]);
        let e = run_auth(&t, None, &[]).expect_err("needs credentials");
        assert_eq!(e.code(), OciErrorCode::Unimplemented);
        assert_eq!(t.seen.lock().expect("lock").len(), 1);
    }

    /// OCI-3: Bearer と Basic の併記では Bearer を優先し、接続先 /v2/ へ資格情報を送らない。
    #[test]
    fn authenticate_prefers_bearer_over_basic() {
        let t = FakeTransport::new(vec![
            resp(401, &[BASIC_CHALLENGE, HUB_CHALLENGE], ""),
            resp(200, &[], r#"{"token":"tok","expires_in":300}"#),
        ]);
        let auth = run_auth(&t, Some(&aladdin()), &[]).expect("auth");
        assert!(matches!(auth, RegistryAuth::Bearer(_)));
        let seen = t.seen.lock().expect("lock");
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1].0, "https://auth.docker.io/token");
    }

    /// OCI-3・SEC: 不許可 realm には通信せず PermissionDenied（資格情報は realm に届かない）。
    #[test]
    fn authenticate_untrusted_realm_never_receives_credentials() {
        let t = FakeTransport::new(vec![resp(
            401,
            &[r#"Bearer realm="https://evil.example.net/token",service="x""#],
            "",
        )]);
        let e = run_auth(&t, Some(&aladdin()), &[]).expect_err("untrusted");
        assert_eq!(e.code(), OciErrorCode::PermissionDenied);
        assert_eq!(t.seen.lock().expect("lock").len(), 1);
        assert!(!e.message().contains("open sesame"));
    }

    /// OCI-3: 異常系の分類（拒否・5xx・タイムアウト・チャレンジ無し）。資格情報は message に出ない。
    #[test]
    fn authenticate_failures_are_classified() {
        for status in [401u16, 403] {
            let t = FakeTransport::new(vec![
                resp(401, &[HUB_CHALLENGE], ""),
                resp(status, &[], "open sesame"),
            ]);
            let e = run_auth(&t, Some(&aladdin()), &[]).expect_err("rejected");
            assert_eq!(e.code(), OciErrorCode::PermissionDenied);
            assert_eq!(e.http_status(), Some(status));
            assert!(!e.message().contains("open sesame"));
            assert!(!format!("{e:?}").contains("open sesame"));
        }
        let t = FakeTransport::new(vec![resp(503, &[], "")]);
        let e = run_auth(&t, Some(&aladdin()), &[]).expect_err("5xx");
        assert_eq!(e.code(), OciErrorCode::Unavailable);
        let t = FakeTransport::new(vec![Err(OciError::new(OciErrorCode::Timeout, "timed out"))]);
        let e = run_auth(&t, None, &[]).expect_err("timeout");
        assert_eq!(e.code(), OciErrorCode::Timeout);
        let t = FakeTransport::new(vec![resp(401, &[], "")]);
        let e = run_auth(&t, Some(&aladdin()), &[]).expect_err("no challenge");
        assert_eq!(e.code(), OciErrorCode::DataLoss);
    }

    /// `get`（probe・token・manifest）と `get_stream`（blob）の両方を台本で返す偽の通信。
    #[derive(Debug)]
    struct FakePull {
        get: FakeTransport,
        stream: FakeStream,
    }

    impl RegistryTransport for FakePull {
        fn get(&self, req: &TransportRequest<'_>) -> Result<TransportResponse, OciError> {
            self.get.get(req)
        }
        fn get_stream(
            &self,
            req: &StreamRequest<'_>,
            sink: &mut dyn Write,
        ) -> Result<StreamResponse, OciError> {
            self.stream.get_stream(req, sink)
        }
    }

    fn pull_client(
        pull: Arc<FakePull>,
        rec: Arc<crate::instrument::testing::Collect>,
    ) -> RegistryClient {
        RegistryClient {
            agent: Agent::new_with_config(Config::default()),
            transport: pull,
            config: RegistryClientConfig::default(),
            recorder: rec,
        }
    }

    /// OCI-3・TASK-54.3（受け入れ条件）: 認証が必要なレジストリで、公開メソッドだけで
    /// 認証 → manifest → blob の一連の pull が通り、各段に正しい Authorization が載る。
    #[test]
    fn full_pull_with_bearer_registry() {
        let tmp = TmpDir::new("pull-bearer");
        let store = tmp.store();
        let mut session = store.begin_pull_generated().expect("begin");
        let pull = Arc::new(FakePull {
            get: FakeTransport::new(vec![
                resp(401, &[HUB_CHALLENGE], ""),
                resp(200, &[], r#"{"token":"tok-9","expires_in":300}"#),
                manifest_resp(200, &image_body()),
            ]),
            stream: FakeStream::new(vec![step(200, None, vec![b"layer!".to_vec()])]),
        });
        let rec = Arc::new(crate::instrument::testing::Collect::default());
        let client = pull_client(pull.clone(), rec.clone());
        let (ep, repo) = alpine();
        let auth = client
            .authenticate(&ep, &repo, Some(&aladdin()), &[])
            .expect("auth");
        let reference = Reference::Tag(crate::reference::Tag::parse("latest").expect("tag"));
        let platform = Platform::for_arch("x86_64").expect("platform");
        client
            .fetch_manifest(&ep, &repo, &reference, &auth, &platform)
            .expect("manifest");
        let mut w = session.open_staged_blob(&desc(6).digest).expect("writer");
        let got = client
            .fetch_blob(&ep, &repo, &desc(6), &auth, &mut w)
            .expect("blob");
        assert_eq!(got.size, 6);
        w.commit().expect("commit");
        assert_eq!(
            std::fs::read(tmp.0.join("staging").join(session.id().as_str()).join(HX))
                .expect("read"),
            b"layer!"
        );
        let h = pull.get.seen_headers.lock().expect("lock");
        assert_eq!(h.len(), 3);
        assert!(h[0].is_empty());
        assert_eq!(
            h[1],
            vec![("Authorization".to_string(), ALADDIN.to_string())]
        );
        assert!(
            h[2].contains(&("Authorization".to_string(), "Bearer tok-9".to_string())),
            "{:?}",
            h[2]
        );
        let s = pull.stream.seen.lock().expect("lock");
        assert_eq!(
            s[0].2,
            vec![("Authorization".to_string(), "Bearer tok-9".to_string())]
        );
        let items = rec.items();
        assert_eq!(
            items.iter().map(|i| i.kind()).collect::<Vec<_>>(),
            vec![
                OciOpKind::Authenticate,
                OciOpKind::FetchManifest,
                OciOpKind::FetchBlob
            ]
        );
        assert!(items.iter().all(|i| i.outcome() == AuthOutcome::Success));
    }

    /// OCI-3・TASK-54.3: Basic のみのレジストリでも一連の pull が通り、manifest / blob に Basic が載る。
    /// blob が CDN へリダイレクトされても Authorization は漏れない。
    #[test]
    fn full_pull_with_basic_registry_does_not_leak_to_redirect() {
        let tmp = TmpDir::new("pull-basic");
        let store = tmp.store();
        let mut session = store.begin_pull_generated().expect("begin");
        let pull = Arc::new(FakePull {
            get: FakeTransport::new(vec![
                resp(401, &[BASIC_CHALLENGE], ""),
                resp(200, &[], ""),
                manifest_resp(200, &image_body()),
            ]),
            stream: FakeStream::new(vec![
                step(302, Some(CDN), vec![]),
                step(200, None, vec![b"layer!".to_vec()]),
            ]),
        });
        let rec = Arc::new(crate::instrument::testing::Collect::default());
        let client = pull_client(pull.clone(), rec.clone());
        let (ep, repo) = alpine();
        let auth = client
            .authenticate(&ep, &repo, Some(&aladdin()), &[])
            .expect("auth");
        assert!(matches!(auth, RegistryAuth::Basic(_)));
        let reference = Reference::Tag(crate::reference::Tag::parse("latest").expect("tag"));
        let platform = Platform::for_arch("x86_64").expect("platform");
        client
            .fetch_manifest(&ep, &repo, &reference, &auth, &platform)
            .expect("manifest");
        let mut w = session.open_staged_blob(&desc(6).digest).expect("writer");
        client
            .fetch_blob(&ep, &repo, &desc(6), &auth, &mut w)
            .expect("blob");
        w.commit().expect("commit");
        assert_eq!(
            std::fs::read(tmp.0.join("staging").join(session.id().as_str()).join(HX))
                .expect("read"),
            b"layer!"
        );
        let h = pull.get.seen_headers.lock().expect("lock");
        assert!(h[2].contains(&("Authorization".to_string(), ALADDIN.to_string())));
        let s = pull.stream.seen.lock().expect("lock");
        assert_eq!(s.len(), 2);
        assert_eq!(
            s[0].2,
            vec![("Authorization".to_string(), ALADDIN.to_string())]
        );
        assert_eq!(s[1].0, CDN);
        assert!(s[1].1, "redirect target must use the public-only path");
        assert!(
            s[1].2.is_empty(),
            "redirect target must not get credentials"
        );
    }

    /// OCI-3・REPAIR-4: 公開メソッド `authenticate` の成功と失敗が `Authenticate` として 1 件ずつ記録される。
    #[test]
    fn authenticate_public_api_records_outcomes() {
        let rec = Arc::new(crate::instrument::testing::Collect::default());
        let (ep, repo) = alpine();
        let ok = client_with(FakeTransport::new(vec![resp(200, &[], "")]), rec.clone());
        ok.authenticate(&ep, &repo, None, &[]).expect("ok");
        let bad = client_with(FakeTransport::new(vec![resp(500, &[], "")]), rec.clone());
        bad.authenticate(&ep, &repo, None, &[]).expect_err("500");
        let items = rec.items();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].kind(), OciOpKind::Authenticate);
        assert_eq!(items[0].outcome(), AuthOutcome::Success);
        assert_eq!(items[1].kind(), OciOpKind::Authenticate);
        assert_eq!(items[1].outcome(), AuthOutcome::Failure);
        assert_eq!(items[1].error_code(), Some(OciErrorCode::Unavailable));
    }
}
/// 取得の途中で割り込む試験用の通信（`root_swap_tests` が、本文の途中で staging を差し替える状況を再現する。
/// OCI-7・SEC-1・#2765）。fd 起点の試験（`root_swap_tests`）と同じ cfg に限る。
#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) mod test_support {
    use super::*;
    use std::sync::Mutex;

    type Hook = Box<dyn FnOnce() + Send>;

    /// 本文の前半を書き、`mid` を呼び、後半を書く通信（常に 200）。
    struct HookStream {
        body: Vec<u8>,
        mid: Mutex<Option<Hook>>,
    }

    impl Debug for HookStream {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HookStream").finish_non_exhaustive()
        }
    }

    impl RegistryTransport for HookStream {
        fn get(&self, _req: &TransportRequest<'_>) -> Result<TransportResponse, OciError> {
            Err(OciError::new(OciErrorCode::Unimplemented, "not used"))
        }

        fn get_stream(
            &self,
            _req: &StreamRequest<'_>,
            sink: &mut dyn Write,
        ) -> Result<StreamResponse, OciError> {
            let (first, second) = self.body.split_at(self.body.len() / 2);
            sink.write_all(first).map_err(map_sink_error)?;
            let hook = self
                .mid
                .lock()
                .map_err(|_| OciError::new(OciErrorCode::Internal, "poisoned test hook"))?
                .take();
            if let Some(f) = hook {
                f();
            }
            sink.write_all(second).map_err(map_sink_error)?;
            Ok(StreamResponse {
                status: 200,
                location: None,
                bytes_written: self.body.len() as u64,
            })
        }
    }

    /// `fetch_blob` と同じ事前検査・本文の流し込みを通し、本文の途中で `mid` を呼ぶ。
    pub(crate) fn fetch_blob_with_hook(
        dest: &mut StagedBlobWriter,
        body: &[u8],
        mid: impl FnOnce() + Send + 'static,
    ) -> Result<FetchedBlob, OciError> {
        let ep = RegistryEndpoint::new(
            crate::reference::RegistryHost::parse("registry.example").expect("host"),
        );
        let repo = Repository::parse("lib/app").expect("repo");
        let descriptor = Descriptor {
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
            digest: dest.digest().clone(),
            size: body.len() as u64,
            platform: None,
        };
        let transport = HookStream {
            body: body.to_vec(),
            mid: Mutex::new(Some(Box::new(mid))),
        };
        fetch_blob_flow(
            &transport,
            &RegistryClientConfig::default(),
            &ep,
            &repo,
            &descriptor,
            &RegistryAuth::None,
            dest,
        )
    }
}
