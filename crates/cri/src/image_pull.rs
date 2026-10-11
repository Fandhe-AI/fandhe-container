//! `PullImage` の取り込み手順（TASK-61.3・#446・CRI-4・OCI-1・OCI-3・ERR-3・REPAIR-4・REPAIR-5）。
//!
//! [`crate::image_service::CriImageService`] の `pull_image` ハンドラが、`spawn_blocking` 上で
//! [`ImagePuller::pull`] を呼ぶ。本モジュールは `fandhe-container-oci` の pull 経路を CRI の語彙へつなぐ層で、
//! 次の順に進める。
//!
//! 1. 参照の検証（`ImageReference::parse`）
//! 2. 認証（`RegistryClient::authenticate`。匿名・Basic・Bearer を oci が自動選択）
//! 3. manifest 取得と platform 解決（`fetch_manifest`）
//! 4. 通信前のサイズ検証（descriptor の合計が [`PullConfig::max_image_bytes`] 以下）
//! 5. config と各 layer の blob を一意なステージング領域へ取得し、sha256 digest を検証（`verify_blob_digest`）
//! 6. 検証済み blob をコンテンツアドレスのパス `<cache_dir>/blobs/sha256/<hex>` へ公開
//!
//! # 契約
//!
//! - 検証前のファイルをキャッシュへ公開しない。公開先のパスは検証済み `Digest` の 16 進部のみから組み立て、
//!   レジストリ・リクエスト由来の文字列をパス要素に使わない（パストラバーサル対策）
//! - ステージング領域は成否に関わらず後始末する（ステージング領域の `Drop` で削除）
//! - エラー文言は固定の英語で、イメージ名・資格情報・レジストリ応答の文言を含めない（`.claude/rules/security.md`）
//! - 資格情報は oci の `BasicCredentials` で検証され、`Debug` は伏せられる。zeroize は未対応（oci と同様。依存を足さない）
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - tar 展開（rootfs 化）・whiteout・diff_id 検証は TASK-52.3、永続イメージストアと展開後サイズの算出は
//!   TASK-183（OCI-7）の担当。本モジュールが返す `size` は config と全 layer の**圧縮サイズの合計**で、
//!   展開後サイズではない
//! - `AuthConfig.identity_token`（OAuth2）・`registry_token` は未対応で `UNIMPLEMENTED`（oci の OAuth2 POST フロー待ち。OCI-3）
//! - 実行中の blocking 処理は gRPC 側のキャンセルでは打ち切れず、[`PullConfig::pull_deadline`] のステップ間確認と
//!   oci の各リクエスト期限で有界化される。全体 timeout は plugin-cri（TASK-108・TASK-114）の責務
//! - UDS の権限・peer credential 検証（PLUG-12）は plugin-cri の責務

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fandhe_container_oci::auth::{BasicCredentials, RegistryAuth};
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::layer::verify_blob_digest;
use fandhe_container_oci::manifest::{Descriptor, ImageManifest, Platform};
use fandhe_container_oci::reference::{
    DOCKER_HUB_REGISTRY_HOST, Digest, ImageReference, Reference, RegistryHost, Repository,
};
use fandhe_container_oci::registry::{RegistryClient, RegistryClientConfig, RegistryEndpoint};
use tonic::Status;

use crate::image_service::{ImageRecord, MAX_IMAGE_FIELD_BYTES};
use crate::runtime::v1;

/// 1 回の pull が許す合計サイズ（config + 全 layer の圧縮サイズ）の既定上限。
pub const DEFAULT_MAX_IMAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// config blob の既定上限（1 MiB）。
pub const DEFAULT_MAX_CONFIG_BYTES: u64 = 1024 * 1024;
/// 1 回の pull の既定の全体期限（ステップ間で確認する。REPAIR-5）。
pub const DEFAULT_PULL_DEADLINE: Duration = Duration::from_secs(60 * 60);
/// `AuthConfig.auth`（base64 の `user:pass`）の最大バイト数。
const MAX_AUTH_FIELD_BYTES: usize = 8 * 1024;

/// pull の失敗。分類は oci の [`OciErrorCode`] を引き継ぎ、文言は固定の英語（入力値・応答文言を含めない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PullError {
    code: OciErrorCode,
    message: &'static str,
}

impl PullError {
    /// 分類と固定文言からエラーを作る。
    pub fn new(code: OciErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    /// oci のエラーを写す。oci の message はレジストリ由来の情報を含みうるため捨て、分類ごとの固定文言にする。
    pub fn from_oci(err: &OciError) -> Self {
        let message = match err.code() {
            OciErrorCode::InvalidArgument => "invalid image reference or credentials",
            OciErrorCode::Unimplemented => "unsupported registry feature",
            OciErrorCode::Unavailable => "registry is unavailable",
            OciErrorCode::Timeout => "registry request timed out",
            OciErrorCode::PermissionDenied => "registry access denied",
            OciErrorCode::NotFound => "image not found in registry",
            OciErrorCode::DataLoss => "registry data failed validation",
            OciErrorCode::ResourceExhausted => "image exceeds the size limit",
            OciErrorCode::FailedPrecondition => "image cache precondition failed",
            _ => "image pull failed",
        };
        Self::new(err.code(), message)
    }

    /// 機械可読な分類。
    pub fn code(&self) -> OciErrorCode {
        self.code
    }

    /// 固定の英語文言。
    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for PullError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for PullError {}

/// oci の分類を gRPC ステータスへ写す（ERR-3）。
impl From<PullError> for Status {
    fn from(err: PullError) -> Self {
        match err.code {
            OciErrorCode::InvalidArgument => Status::invalid_argument(err.message),
            OciErrorCode::Unimplemented => Status::unimplemented(err.message),
            OciErrorCode::Unavailable => Status::unavailable(err.message),
            OciErrorCode::Timeout => Status::deadline_exceeded(err.message),
            OciErrorCode::PermissionDenied => Status::permission_denied(err.message),
            OciErrorCode::NotFound => Status::not_found(err.message),
            OciErrorCode::DataLoss => Status::data_loss(err.message),
            OciErrorCode::ResourceExhausted => Status::resource_exhausted(err.message),
            OciErrorCode::FailedPrecondition => Status::failed_precondition(err.message),
            _ => Status::internal(err.message),
        }
    }
}

/// pull 1 回の入力。`Debug` は資格情報を伏せる（oci の `BasicCredentials` が伏せる）。
#[derive(Debug, Clone)]
pub struct PullRequest {
    /// 未検証のイメージ参照文字列（`ImageReference::parse` が検証する）。
    pub reference: String,
    /// レジストリ資格情報（無ければ匿名）。
    pub credentials: Option<BasicCredentials>,
}

/// 取り込み済みイメージ（[`ImageRecord`] の元になる値）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulledImage {
    /// イメージ ID（検証済みの config blob digest。`sha256:<hex>`）。
    pub id: String,
    /// 参照が tag のときの正規化タグ（`<registry>/<repo>:<tag>`）。
    pub repo_tags: Vec<String>,
    /// `<registry>/<repo>@<digest>`（取得できる範囲。上記「未実装範囲」参照）。
    pub repo_digests: Vec<String>,
    /// config と全 layer の圧縮サイズの合計（展開後サイズではない）。
    pub size: u64,
}

impl PulledImage {
    /// ストアへ登録するレコードに変換する。
    pub fn into_record(self) -> Result<ImageRecord, PullError> {
        ImageRecord::new(self.id, self.repo_tags, self.repo_digests, self.size)
            .map_err(|_| PullError::new(OciErrorCode::Internal, "image record is invalid"))
    }
}

/// 取り込みの境界（`CriImageService` が `spawn_blocking` 上で呼ぶ）。
///
/// 契約: 同期・有界時間で戻ること（REPAIR-5）。
pub trait ImagePuller: Send + Sync {
    /// 参照を解決してローカルキャッシュへ取り込む。
    fn pull(&self, request: &PullRequest) -> Result<PulledImage, PullError>;
}

/// `fetch_manifest` の結果（oci の `ResolvedManifest` は `non_exhaustive` で外から作れないため、境界用に写す）。
#[derive(Debug, Clone)]
pub struct PulledManifest {
    /// 解決済みの image manifest。
    pub manifest: ImageManifest,
    /// image index から選んだ場合の選択エントリの digest。
    pub selected_digest: Option<Digest>,
    /// `manifest` 本文のハッシュ。digest 参照・index 選択エントリでは oci が要求 digest と突合済み（OCI-1）。
    pub manifest_digest: Digest,
    /// image index 経由で解決した場合の index 本文のハッシュ（digest 参照では要求 digest と突合済み。OCI-1）。
    /// kubelet は `name@<index digest>` で再照会するため、repo_digests に併せて登録する（CRI-4）。
    pub index_digest: Option<Digest>,
}

/// oci の `RegistryClient` を呼ぶ最小の境界。実体は [`OciRegistryClient`]、試験では偽実装を差し込む
/// （oci の公開型は `non_exhaustive` が多く、transport も crate 内部のため cri の外から差し替えられない）。
pub trait RegistryPullClient: Send + Sync {
    /// 認証状態を得る（匿名・Basic・Bearer は oci が選ぶ）。
    fn authenticate(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        credentials: Option<&BasicCredentials>,
        trusted_realm_hosts: &[RegistryHost],
    ) -> Result<RegistryAuth, OciError>;

    /// manifest を取得し、index なら `platform` の manifest まで解決する。
    fn fetch_manifest(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        reference: &Reference,
        auth: &RegistryAuth,
        platform: &Platform,
    ) -> Result<PulledManifest, OciError>;

    /// blob を `dest` へ保存する。`dest` は未存在であること。digest 検証は呼び出し側が行う。
    fn fetch_blob(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        descriptor: &Descriptor,
        auth: &RegistryAuth,
        dest: &Path,
    ) -> Result<(), OciError>;
}

/// 共有所有のクライアントをそのまま渡せるようにする（試験で呼び出し回数を後から検査するため）。
impl<T: RegistryPullClient + ?Sized> RegistryPullClient for std::sync::Arc<T> {
    fn authenticate(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        credentials: Option<&BasicCredentials>,
        trusted_realm_hosts: &[RegistryHost],
    ) -> Result<RegistryAuth, OciError> {
        (**self).authenticate(endpoint, repository, credentials, trusted_realm_hosts)
    }

    fn fetch_manifest(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        reference: &Reference,
        auth: &RegistryAuth,
        platform: &Platform,
    ) -> Result<PulledManifest, OciError> {
        (**self).fetch_manifest(endpoint, repository, reference, auth, platform)
    }

    fn fetch_blob(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        descriptor: &Descriptor,
        auth: &RegistryAuth,
        dest: &Path,
    ) -> Result<(), OciError> {
        (**self).fetch_blob(endpoint, repository, descriptor, auth, dest)
    }
}

/// 実レジストリ向けの [`RegistryPullClient`]（oci の `RegistryClient` の薄いアダプタ）。
#[derive(Debug)]
pub struct OciRegistryClient {
    inner: RegistryClient,
}

impl OciRegistryClient {
    /// 設定から作る（TLS 設定済みの HTTP エージェントを構築する）。
    pub fn new(config: &RegistryClientConfig) -> Result<Self, OciError> {
        Ok(Self {
            inner: RegistryClient::new(config)?,
        })
    }
}

impl RegistryPullClient for OciRegistryClient {
    fn authenticate(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        credentials: Option<&BasicCredentials>,
        trusted_realm_hosts: &[RegistryHost],
    ) -> Result<RegistryAuth, OciError> {
        self.inner
            .authenticate(endpoint, repository, credentials, trusted_realm_hosts)
    }

    fn fetch_manifest(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        reference: &Reference,
        auth: &RegistryAuth,
        platform: &Platform,
    ) -> Result<PulledManifest, OciError> {
        let resolved = self
            .inner
            .fetch_manifest(endpoint, repository, reference, auth, platform)?;
        Ok(PulledManifest {
            manifest: resolved.manifest,
            selected_digest: resolved.selected_digest,
            manifest_digest: resolved.manifest_digest,
            index_digest: resolved.index_digest,
        })
    }

    fn fetch_blob(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        descriptor: &Descriptor,
        auth: &RegistryAuth,
        dest: &Path,
    ) -> Result<(), OciError> {
        self.inner
            .fetch_blob(endpoint, repository, descriptor, auth, dest)
            .map(|_| ())
    }
}

/// [`OciImagePuller`] の設定。
#[derive(Debug, Clone)]
pub struct PullConfig {
    /// キャッシュのルート。`blobs/sha256/<hex>` と `staging/` を配下に作る。
    pub cache_dir: PathBuf,
    /// 対象 platform（既定はホストの linux）。
    pub platform: Platform,
    /// config + 全 layer の圧縮サイズ合計の上限。通信前に descriptor で検証する。
    pub max_image_bytes: u64,
    /// config blob の上限。
    pub max_config_bytes: u64,
    /// pull 全体の期限（ステップ間で確認し、超過なら `Timeout`）。
    pub pull_deadline: Duration,
    /// 資格情報を送ってよい token realm の追加ホスト（既定は空。接続先と同一ホスト・oci の組み込み既知対は常に許可）。
    pub trusted_realm_hosts: Vec<RegistryHost>,
}

impl PullConfig {
    /// 既定値で作る（platform はホストの linux。写像できないアーキテクチャは `Unimplemented`）。
    pub fn new(cache_dir: impl Into<PathBuf>) -> Result<Self, PullError> {
        let platform = Platform::host().map_err(|e| PullError::from_oci(&e))?;
        Ok(Self {
            cache_dir: cache_dir.into(),
            platform,
            max_image_bytes: DEFAULT_MAX_IMAGE_BYTES,
            max_config_bytes: DEFAULT_MAX_CONFIG_BYTES,
            pull_deadline: DEFAULT_PULL_DEADLINE,
            trusted_realm_hosts: Vec::new(),
        })
    }
}

/// oci の pull 経路でキャッシュへ取り込む [`ImagePuller`]（CRI-4・OCI-1）。
#[derive(Debug)]
pub struct OciImagePuller<C: RegistryPullClient> {
    client: C,
    config: PullConfig,
}

impl<C: RegistryPullClient> OciImagePuller<C> {
    /// クライアントと設定から作る。
    pub fn new(client: C, config: PullConfig) -> Self {
        Self { client, config }
    }

    /// 認証状態を取り直す（token 失効・PermissionDenied 時。資格情報は pull 要求のものを再利用する）。
    fn reauthenticate(&self, ctx: &PullContext<'_>) -> Result<RegistryAuth, PullError> {
        self.client
            .authenticate(
                ctx.endpoint,
                ctx.repository,
                ctx.credentials,
                &self.config.trusted_realm_hosts,
            )
            .map_err(|e| PullError::from_oci(&e))
    }

    fn check_deadline(&self, started: Instant) -> Result<(), PullError> {
        if started.elapsed() >= self.config.pull_deadline {
            return Err(PullError::new(
                OciErrorCode::Timeout,
                "image pull exceeded its deadline",
            ));
        }
        Ok(())
    }

    /// `blobs/sha256` を作る（Unix では 0700）。
    fn blobs_dir(&self) -> Result<PathBuf, PullError> {
        prepare_private_dir(&self.config.cache_dir, &["blobs", "sha256"])
    }

    /// 検証済みなら取得を省き、そうでなければステージングへ取得 → 検証 → 公開する。
    fn ensure_blob(
        &self,
        request: &PullContext<'_>,
        auth: &mut RegistryAuth,
        staging: &StagingDir,
        blobs: &Path,
        descriptor: &Descriptor,
    ) -> Result<(), PullError> {
        let hex = digest_hex(&descriptor.digest);
        let final_path = blobs.join(hex);
        // キャッシュ命中: 通常ファイル（symlink は辿らない）かつ再検証に合格すれば再取得しない。
        // 再検証に失敗しても共有 blob は消さない（一過性の読み出しエラーで検証済み blob を失わないため）。
        // 取得・検証に成功した場合に限り、下の rename で置き換える。
        // サイズは読み取り上限ではなく宣言値との完全一致で確認する（短い blob の誤受理を防ぐ。OCI-1）。
        if let Ok(meta) = fs::symlink_metadata(&final_path)
            && meta.is_file()
            && verify_blob_digest(&final_path, &descriptor.digest, descriptor.size)
                .is_ok_and(|v| v.size == descriptor.size)
        {
            return Ok(());
        }
        let staged = staging.path().join(hex);
        // 長時間の pull では Bearer token が途中で失効する。取得前に失効を確認して再認証し、
        // 取得が PermissionDenied なら有限回（MAX_REAUTH_RETRIES）だけ再認証して再試行する（OCI-3）。
        let mut retries = 0u32;
        loop {
            if matches!(&*auth, RegistryAuth::Bearer(t) if t.is_expired(Instant::now())) {
                *auth = self.reauthenticate(request)?;
            }
            match self.client.fetch_blob(
                request.endpoint,
                request.repository,
                descriptor,
                auth,
                &staged,
            ) {
                Ok(()) => break,
                Err(e)
                    if e.code() == OciErrorCode::PermissionDenied
                        && retries < MAX_REAUTH_RETRIES =>
                {
                    retries += 1;
                    // fetch_blob は dest が未存在であることを要求する。部分ファイルを残さない。
                    let _ = fs::remove_file(&staged);
                    *auth = self.reauthenticate(request)?;
                }
                Err(e) => return Err(PullError::from_oci(&e)),
            }
        }
        let verified = verify_blob_digest(&staged, &descriptor.digest, descriptor.size)
            .map_err(|e| PullError::from_oci(&e))?;
        if verified.size != descriptor.size {
            return Err(PullError::new(
                OciErrorCode::DataLoss,
                "blob size does not match the descriptor",
            ));
        }
        fs::rename(&staged, &final_path).map_err(|_| {
            PullError::new(
                OciErrorCode::FailedPrecondition,
                "failed to publish blob to the image cache",
            )
        })
    }
}

/// 1 回の pull の間で共有する借用（引数の数を抑える）。
struct PullContext<'a> {
    endpoint: &'a RegistryEndpoint,
    repository: &'a Repository,
    credentials: Option<&'a BasicCredentials>,
}

/// blob 取得が PermissionDenied のときの再認証の最大回数。
const MAX_REAUTH_RETRIES: u32 = 2;

impl<C: RegistryPullClient> ImagePuller for OciImagePuller<C> {
    fn pull(&self, request: &PullRequest) -> Result<PulledImage, PullError> {
        let started = Instant::now();
        let image_ref =
            ImageReference::parse(&request.reference).map_err(|e| PullError::from_oci(&e))?;
        let endpoint = RegistryEndpoint::new(image_ref.registry().clone());
        let repository = image_ref.repository();

        let mut auth = self
            .client
            .authenticate(
                &endpoint,
                repository,
                request.credentials.as_ref(),
                &self.config.trusted_realm_hosts,
            )
            .map_err(|e| PullError::from_oci(&e))?;
        self.check_deadline(started)?;

        let resolved = self
            .client
            .fetch_manifest(
                &endpoint,
                repository,
                image_ref.reference(),
                &auth,
                &self.config.platform,
            )
            .map_err(|e| PullError::from_oci(&e))?;
        self.check_deadline(started)?;

        // 通信前に descriptor の宣言サイズで上限を検証する（無制限確保・巨大転送の防止）。
        let manifest = &resolved.manifest;
        if manifest.config.size > self.config.max_config_bytes {
            return Err(PullError::new(
                OciErrorCode::ResourceExhausted,
                "image config exceeds the size limit",
            ));
        }
        let mut total = manifest.config.size;
        for layer in &manifest.layers {
            total = total.checked_add(layer.size).ok_or(PullError::new(
                OciErrorCode::ResourceExhausted,
                "image exceeds the size limit",
            ))?;
        }
        if total > self.config.max_image_bytes {
            return Err(PullError::new(
                OciErrorCode::ResourceExhausted,
                "image exceeds the size limit",
            ));
        }
        if total == 0 {
            return Err(PullError::new(
                OciErrorCode::DataLoss,
                "image manifest declares no content",
            ));
        }

        let blobs = self.blobs_dir()?;
        let staging = StagingDir::create(&self.config.cache_dir)?;
        let ctx = PullContext {
            endpoint: &endpoint,
            repository,
            credentials: request.credentials.as_ref(),
        };
        // 同一 digest の重複（同じ layer を複数回使う manifest）は 1 回だけ取得する。
        // 同一 digest で宣言サイズが食い違う descriptor は不正な manifest として拒否する（OCI-1）。
        let mut seen: Vec<(&Digest, u64)> = Vec::new();
        for descriptor in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
            if let Some((_, size)) = seen.iter().find(|(d, _)| **d == descriptor.digest) {
                if *size != descriptor.size {
                    return Err(PullError::new(
                        OciErrorCode::DataLoss,
                        "duplicate blob descriptors declare different sizes",
                    ));
                }
                continue;
            }
            self.check_deadline(started)?;
            self.ensure_blob(&ctx, &mut auth, &staging, &blobs, descriptor)?;
            seen.push((&descriptor.digest, descriptor.size));
        }
        drop(staging);
        // 最後の blob の取得・検証で期限を超えた場合も成功を返さない（REPAIR-5）。
        self.check_deadline(started)?;

        let name = display_name(image_ref.registry(), repository);
        let mut repo_tags = Vec::new();
        let mut repo_digests = Vec::new();
        match image_ref.reference() {
            Reference::Tag(tag) => {
                repo_tags.push(format!("{name}:{}", tag.as_str()));
                // 検証済みの manifest digest のみ登録する（index 選択時は選択エントリ照合済み。OCI-1）。
                repo_digests.push(format!("{name}@{}", resolved.manifest_digest.as_str()));
            }
            Reference::Digest(_) => {
                // oci が本文ハッシュと要求 digest を突合済み（不一致は DataLoss）。
                repo_digests.push(format!("{name}@{}", resolved.manifest_digest.as_str()));
            }
        }
        // index 経由なら index 本文の digest も登録する（tag / digest 参照とも oci が検証済みの値のみ。
        // kubelet が `name@<index digest>` で ImageStatus / ListImages を引けるようにする。CRI-4）。
        if let Some(index_digest) = &resolved.index_digest {
            let entry = format!("{name}@{}", index_digest.as_str());
            if !repo_digests.contains(&entry) {
                repo_digests.push(entry);
            }
        }
        if repo_tags
            .iter()
            .chain(repo_digests.iter())
            .any(|s| s.len() > MAX_IMAGE_FIELD_BYTES)
        {
            return Err(PullError::new(
                OciErrorCode::InvalidArgument,
                "image reference is too long",
            ));
        }
        Ok(PulledImage {
            id: manifest.config.digest.as_str().to_owned(),
            repo_tags,
            repo_digests,
            size: total,
        })
    }
}

/// `sha256:` を除いた 16 進部（`Digest` の検証済み不変条件により小文字 hex 64 桁のみ。パス要素に安全）。
fn digest_hex(digest: &Digest) -> &str {
    digest.as_str().strip_prefix("sha256:").unwrap_or("")
}

/// タグ・digest 表示用の正規化名。Docker Hub の接続先は `docker.io` へ戻す。
fn display_name(registry: &RegistryHost, repository: &Repository) -> String {
    let host = if registry.port().is_none() && registry.host() == DOCKER_HUB_REGISTRY_HOST {
        "docker.io".to_owned()
    } else {
        registry.authority()
    };
    format!("{host}/{}", repository.as_str())
}

/// 参照文字列を `PullImage` が登録する形（`<registry>/<repo>:<tag>` または `<registry>/<repo>@<digest>`）へ
/// 正規化する。`ImageStatus`・`ListImages` が短縮名を pull と同じ規則で照会するために使う（CRI-4）。
/// 解釈できない文字列（イメージ ID の 16 進等）は `None`。
pub fn canonical_reference(input: &str) -> Option<String> {
    let image_ref = ImageReference::parse(input).ok()?;
    let name = display_name(image_ref.registry(), image_ref.repository());
    Some(match image_ref.reference() {
        Reference::Tag(tag) => format!("{name}:{}", tag.as_str()),
        Reference::Digest(digest) => format!("{name}@{}", digest.as_str()),
    })
}

/// キャッシュ配下のディレクトリを 1 要素ずつ作り、既存要素も検証する（SEC・OCI-1）。
///
/// `cache_dir` 自体は（親ごと）作成後に検証する。`components` は `cache_dir` 直下から順に非再帰で作成し
/// （既存は許容）、各要素について「symlink でない通常ディレクトリ」「呼び出しプロセスと同一所有者」
/// 「group / other 書き込み権限なし」（Unix）を確認する。検証済みの所有者専用ディレクトリは他ユーザーが
/// 差し替えられないため、検証後の blob 公開（rename）で未検証の内容が混入する経路を塞ぐ。
/// 0700 の指定は新規作成時にしか効かないので、既存ディレクトリは必ずここで検証する。
fn prepare_private_dir(cache_dir: &Path, components: &[&str]) -> Result<PathBuf, PullError> {
    let prep_err = || {
        PullError::new(
            OciErrorCode::FailedPrecondition,
            "failed to prepare the image cache directory",
        )
    };
    let mut root_builder = fs::DirBuilder::new();
    root_builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        root_builder.mode(0o700);
    }
    root_builder.create(cache_dir).map_err(|_| prep_err())?;
    let owner = owner_probe(cache_dir)?;
    verify_private_dir(cache_dir, owner)?;
    verify_ancestors(cache_dir, owner)?;
    let mut current = cache_dir.to_path_buf();
    for name in components {
        current.push(name);
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut single = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            single.mode(0o700);
        }
        match single.create(&current) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(prep_err()),
        }
        verify_private_dir(&current, owner)?;
    }
    Ok(current)
}

/// 呼び出しプロセスの実効 UID 相当の値（Unix）。自分が作ったファイルの所有者を読んで得る
/// （`unsafe` / libc を使わずに実効 UID を得るため）。非 Unix では 0 を返し所有者検査は行わない。
#[cfg(unix)]
fn owner_probe(dir: &Path) -> Result<u32, PullError> {
    use std::os::unix::fs::MetadataExt as _;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let probe = dir.join(format!(
        ".owner-probe-{}-{nanos}-{}",
        std::process::id(),
        STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let fail = || {
        PullError::new(
            OciErrorCode::FailedPrecondition,
            "failed to prepare the image cache directory",
        )
    };
    // create_new は既存（symlink を含む）を辿らず失敗する。
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|_| fail())?;
    let uid = fs::symlink_metadata(&probe).map(|m| m.uid());
    let _ = fs::remove_file(&probe);
    uid.map_err(|_| fail())
}

/// 非 Unix では所有者・ACL（DACL）を検証する手段が無い（`windows-sys` は未導入）ため、検証できないまま
/// キャッシュを使わず fail-closed で拒否する（SEC・OCI-1。Windows の ACL 検証は将来仕様）。
#[cfg(not(unix))]
fn owner_probe(_dir: &Path) -> Result<u32, PullError> {
    Err(PullError::new(
        OciErrorCode::Unimplemented,
        "image cache access control is not supported on this platform",
    ))
}

/// `cache_dir` の祖先ディレクトリを根まで検証する（Unix）。
///
/// 親を `canonicalize` して symlink を解決したうえで、親から根までの各ディレクトリが「呼び出しプロセスまたは
/// root の所有」かつ「group / other 書き込み不可、または sticky ビット付き（他ユーザーが他人のエントリを
/// rename / 削除できない `/tmp` 等）」であることを要求する。信頼できない祖先は fail-closed で拒否する。
/// 限界: 標準ライブラリだけでは openat 相当のディレクトリハンドル基準の操作ができないため、検証後に
/// 同一所有者・root 以外が祖先を差し替える経路は上記の所有者・権限条件で塞ぐ（TOCTOU 全体の排除ではない）。
#[cfg(unix)]
fn verify_ancestors(cache_dir: &Path, owner: u32) -> Result<(), PullError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let reject = |message: &'static str| PullError::new(OciErrorCode::FailedPrecondition, message);
    let parent = match cache_dir.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let canonical = fs::canonicalize(parent)
        .map_err(|_| reject("failed to resolve the image cache parent directory"))?;
    for ancestor in canonical.ancestors() {
        let meta = fs::symlink_metadata(ancestor)
            .map_err(|_| reject("failed to inspect an image cache ancestor directory"))?;
        if !meta.file_type().is_dir() {
            return Err(reject("image cache ancestor is not a plain directory"));
        }
        if meta.uid() != owner && meta.uid() != 0 {
            return Err(reject(
                "image cache ancestor directory has an untrusted owner",
            ));
        }
        let mode = meta.permissions().mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(reject(
                "image cache ancestor directory is writable by other users",
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_ancestors(_cache_dir: &Path, _owner: u32) -> Result<(), PullError> {
    Ok(())
}

/// `dir` が symlink でない通常ディレクトリで、`owner` の所有かつ他ユーザー書き込み不可であることを確認する。
fn verify_private_dir(dir: &Path, owner: u32) -> Result<(), PullError> {
    let reject = |message: &'static str| PullError::new(OciErrorCode::FailedPrecondition, message);
    let meta = fs::symlink_metadata(dir)
        .map_err(|_| reject("failed to prepare the image cache directory"))?;
    if !meta.file_type().is_dir() {
        return Err(reject("image cache path is not a plain directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if meta.uid() != owner {
            return Err(reject("image cache directory has an unexpected owner"));
        }
        if meta.permissions().mode() & 0o022 != 0 {
            return Err(reject("image cache directory is writable by other users"));
        }
    }
    #[cfg(not(unix))]
    let _ = owner;
    Ok(())
}

/// pull ごとに一意なステージング領域。`Drop` で成否に関わらず削除する（部分ファイルを残さない）。
#[derive(Debug)]
struct StagingDir {
    path: PathBuf,
}

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

impl StagingDir {
    fn create(cache_dir: &Path) -> Result<Self, PullError> {
        let root = prepare_private_dir(cache_dir, &["staging"])?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = format!(
            "{}-{nanos}-{}",
            std::process::id(),
            STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = root.join(name);
        // 非再帰の create は既存（symlink を含む）を辿らず失敗する。
        #[cfg(unix)]
        let builder = {
            use std::os::unix::fs::DirBuilderExt as _;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
        };
        #[cfg(not(unix))]
        let builder = fs::DirBuilder::new();
        builder.create(&path).map_err(|_| {
            PullError::new(
                OciErrorCode::FailedPrecondition,
                "failed to create the staging directory",
            )
        })?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// `AuthConfig` を oci の資格情報へ変換する（CRI-4・OCI-3）。
///
/// 対応: `username` + `password`、`auth`（base64 の `user:pass`）。`identity_token`・`registry_token` は未対応で
/// `Unimplemented`。資格情報が一切無ければ `Ok(None)`（匿名）。`server_address` は無視する（送出先は参照の
/// レジストリに固定。応答・リクエスト由来のホストへ資格情報を送らない）。
pub fn credentials_from_auth_config(
    auth: &v1::AuthConfig,
) -> Result<Option<BasicCredentials>, PullError> {
    if !auth.identity_token.is_empty() || !auth.registry_token.is_empty() {
        return Err(PullError::new(
            OciErrorCode::Unimplemented,
            "token based registry credentials are not supported",
        ));
    }
    let bad = || {
        PullError::new(
            OciErrorCode::InvalidArgument,
            "invalid registry credentials",
        )
    };
    if !auth.username.is_empty() || !auth.password.is_empty() {
        return BasicCredentials::new(&auth.username, &auth.password)
            .map(Some)
            .map_err(|_| bad());
    }
    if auth.auth.is_empty() {
        return Ok(None);
    }
    if auth.auth.len() > MAX_AUTH_FIELD_BYTES {
        return Err(bad());
    }
    let raw = decode_base64(&auth.auth).ok_or_else(bad)?;
    let text = String::from_utf8(raw).map_err(|_| bad())?;
    let (user, pass) = text.split_once(':').ok_or_else(bad)?;
    BasicCredentials::new(user, pass)
        .map(Some)
        .map_err(|_| bad())
}

/// 標準アルファベットの厳格な base64 デコード（末尾 `=` は任意。途中の `=`・空白・不正文字は拒否）。
/// 依存を足さないための最小実装で、`AuthConfig.auth` 専用。
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let trimmed = input.trim_end_matches('=');
    if input.len() - trimmed.len() > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for byte in trimmed.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    // 1 文字余り（6 ビット）は不正。余りビットは 0 でなければならない。
    if trimmed.len() % 4 == 1 || (acc & ((1u32 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// OCI-3: base64 デコーダの正常系・不正系。
    #[test]
    fn oci3_base64_decoder_is_strict() {
        assert_eq!(decode_base64("dXNlcjpwYXNz"), Some(b"user:pass".to_vec()));
        assert_eq!(decode_base64("YWJj"), Some(b"abc".to_vec()));
        assert_eq!(decode_base64("YWI="), Some(b"ab".to_vec()));
        assert_eq!(decode_base64("YWI"), Some(b"ab".to_vec()));
        assert_eq!(decode_base64("YQ=="), Some(b"a".to_vec()));
        assert_eq!(decode_base64(""), Some(Vec::new()));
        assert_eq!(decode_base64("Y"), None);
        assert_eq!(decode_base64("YQ==="), None);
        assert_eq!(decode_base64("Y Q=="), None);
        assert_eq!(decode_base64("YQ=a"), None);
        assert_eq!(decode_base64("Y*Q="), None);
        // 余りビットが 0 でない（正規形でない）入力は拒否する。
        assert_eq!(decode_base64("YR=="), None);
    }

    /// OCI-3: AuthConfig の変換（username/password・auth・無し・未対応のトークン・不正）。
    #[test]
    fn oci3_auth_config_conversion() {
        let none = v1::AuthConfig::default();
        assert!(matches!(credentials_from_auth_config(&none), Ok(None)));

        let basic = v1::AuthConfig {
            username: "u".into(),
            password: "p".into(),
            ..Default::default()
        };
        assert!(matches!(credentials_from_auth_config(&basic), Ok(Some(_))));

        let encoded = v1::AuthConfig {
            auth: "dXNlcjpwYXNz".into(),
            ..Default::default()
        };
        assert!(matches!(
            credentials_from_auth_config(&encoded),
            Ok(Some(_))
        ));

        for token in [
            v1::AuthConfig {
                identity_token: "t".into(),
                ..Default::default()
            },
            v1::AuthConfig {
                registry_token: "t".into(),
                ..Default::default()
            },
        ] {
            let err = credentials_from_auth_config(&token).expect_err("unsupported");
            assert_eq!(err.code(), OciErrorCode::Unimplemented);
        }

        for bad in [
            v1::AuthConfig {
                username: "u".into(),
                ..Default::default()
            },
            v1::AuthConfig {
                auth: "bm9jb2xvbg==".into(), // "nocolon"
                ..Default::default()
            },
            v1::AuthConfig {
                auth: "!!!".into(),
                ..Default::default()
            },
            v1::AuthConfig {
                auth: "A".repeat(MAX_AUTH_FIELD_BYTES + 1),
                ..Default::default()
            },
        ] {
            let err = credentials_from_auth_config(&bad).expect_err("invalid");
            assert_eq!(err.code(), OciErrorCode::InvalidArgument);
            assert_eq!(err.message(), "invalid registry credentials");
        }
    }

    /// ERR-3: oci の分類と gRPC ステータスの写像（全種）。文言は固定で入力値を含まない。
    #[test]
    fn err3_error_code_mapping() {
        use tonic::Code;
        let table = [
            (OciErrorCode::InvalidArgument, Code::InvalidArgument),
            (OciErrorCode::Unimplemented, Code::Unimplemented),
            (OciErrorCode::Unavailable, Code::Unavailable),
            (OciErrorCode::Timeout, Code::DeadlineExceeded),
            (OciErrorCode::PermissionDenied, Code::PermissionDenied),
            (OciErrorCode::NotFound, Code::NotFound),
            (OciErrorCode::DataLoss, Code::DataLoss),
            (OciErrorCode::ResourceExhausted, Code::ResourceExhausted),
            (OciErrorCode::FailedPrecondition, Code::FailedPrecondition),
            (OciErrorCode::Internal, Code::Internal),
        ];
        for (oci, grpc) in table {
            let err = OciError::new(oci, "secret-registry.example/private/repo token=abc");
            let status: Status = PullError::from_oci(&err).into();
            assert_eq!(status.code(), grpc);
            assert!(!status.message().contains("secret"));
            assert!(!status.message().contains("token"));
        }
    }

    /// CRI-4: 正規化名は Docker Hub を `docker.io` へ戻し、他レジストリはホストを保つ。
    #[test]
    fn cri4_display_name_normalization() {
        let hub = ImageReference::parse("alpine").expect("parse");
        assert_eq!(
            display_name(hub.registry(), hub.repository()),
            "docker.io/library/alpine"
        );
        let other = ImageReference::parse("registry.example.com:5000/team/app:v1").expect("parse");
        assert_eq!(
            display_name(other.registry(), other.repository()),
            "registry.example.com:5000/team/app"
        );
    }
}

#[cfg(all(test, not(unix)))]
mod non_unix_tests {
    use super::*;

    /// SEC・OCI-1: 非 Unix ではアクセス制御を検証できないため、キャッシュ準備は `Unimplemented` で拒否する。
    #[test]
    fn sec_cache_preparation_is_rejected_without_acl_verification() {
        let dir = std::env::temp_dir().join(format!("fandhe-cri-acl-{}", std::process::id()));
        let err = prepare_private_dir(&dir, &["staging"]).expect_err("rejected");
        assert_eq!(err.code(), OciErrorCode::Unimplemented);
        let _ = fs::remove_dir_all(&dir);
    }
}
