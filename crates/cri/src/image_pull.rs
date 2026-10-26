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
//! 5. oci の `ImageStore::begin_pull_generated` で pull セッションを始める（`<cache_dir>/staging/<id>` と生存確認用の
//!    `@pull.lock`。`cache_dir` は `ImageStore` の root と同一）
//! 6. config と各 layer の blob を確保する。既存 blob は先にリースを登録（`lease_existing_blob`）してから、開いた
//!    ハンドルで所有者・権限・ハードリンク数・digest を確かめて再利用する。それ以外はセッションのステージングへ
//!    取得し（`open_staged_blob` の writer へ書いて `commit`。#2765）、`verify_staged_blob` で信頼条件と sha256 digest を検証する
//! 7. config blob を symlink を辿らずに開き、同じハンドルで信頼条件と digest を確かめ、同じハンドルから上限つきで
//!    読んで `rootfs.diff_ids` を解析（`read_verified_config`）
//! 8. 各 layer を `VerifiedLayerBlob`（検証済みハンドル）で開き直し、セッションのステージングの `unpack/` 配下の
//!    `rootfs/` へ `extract_image_layers_with_options` で展開しながら diff_id を突合（#2323・OCI-1・OCI-2）
//! 9. 展開に成功したときだけ、組んだエントリ（`rootfs/` と展開設定の記録 `unpack-record`）を 1 回の `rename` で
//!    `<cache_dir>/rootfs/sha256/<config-hex>/` へ公開する（記録の無い rootfs が残らない）。公開済みで、
//!    記録（config・展開設定）と layer の表現が今回と一致するときだけ 8 を省く。layer の表現（圧縮 blob の digest・
//!    mediaType）だけ違うときは今回の descriptor で展開を検証し直す（公開はしない）。件数の照合は命中時も行い、
//!    設定が違えば FailedPrecondition で拒否する（既存の展開物は消さない）。所有者写像では root の期待所有者を
//!    写像先で照合する（冪等。[`OciImagePuller::unpacked_rootfs_dir`]）
//! 10. `PullSession::publish` で、検証済みの blob の `blobs/sha256` への公開・manifest（在庫）とタグの登録・
//!     リース解放を排他の下で行い、`@image-inventory.json` へ永続化する（#2539・OCI-1・OCI-7）。タグ参照の
//!     ときだけタグを付け、digest 参照にはタグを付けない。在庫のキーは選択された platform manifest の digest
//!     （index の digest ではない）。順序は「rootfs の公開（9）→ 在庫への公開（10）」で、10 が失敗して rootfs だけが
//!     残っても余分に残す側で無害（rootfs は config digest をキーにした冪等なキャッシュ）
//!
//! 在庫への登録は、本モジュールの [`OciImagePuller::pull`]（CRI の `PullImage` から呼ばれる唯一の pull 実装）が
//! 担う。CLI に `pull` サブコマンドは無く、同じ root を `--image-root` に渡した CLI の `image ls` / `create --image`
//! から見える。本番の `PullImage` へは plugin-cri の ImageService（#2592。`CriPluginBackends::image_service` が
//! 本番の `PullConfig` と本型を組む）から届く。判断の記録は `docs/design/pull-inventory-wiring.md`。
//!
//! キャッシュに同じ digest の blob が既にあれば 6 の取得を省くが、再利用するのは「信頼できる」既存 blob だけ
//! （下記「既存 blob の再利用条件」）。条件を満たさない既存 blob は、ステージングへ取得し直したファイルで置き換える
//! （公開が既存のエントリを置き換える。symlink の先には書き込まない）。
//!
//! # 契約
//!
//! - 検証前のファイルをキャッシュへ公開しない。公開先のパスは検証済み `Digest` の 16 進部のみから組み立て、
//!   レジストリ・リクエスト由来の文字列をパス要素に使わない（パストラバーサル対策）
//! - 失敗経路は必ず `PullSession::abort` を通してリースとステージングを片づける。本モジュールは `staging/<id>` を
//!   自分では消さない（消すのは `abort` / `publish` / 回収 GC だけ。永続化済みのリースだけが残る孤児リースを
//!   作らないため）。消してよいのは自分の作業領域 `unpack/` の子だけ（oci の `remove_extracted_tree`）
//! - 作りかけの rootfs を公開しない。展開はステージングの中だけで行い、diff_id の不一致・上限超過・未対応の
//!   mediaType などで失敗したらステージングごと消す（先行レイヤーの展開物も残らない）。展開後に中断した root が
//!   持つ 0555 等のディレクトリは、oci の `remove_extracted_tree` が権限を戻して消す
//! - 公開済み rootfs は読み取り専用の元として扱い、コンテナの rootfs として直接書き換えない。create 経路
//!   （`crate::bundle::ImageRootfsSource`。#2433）は、この rootfs に触れず、検証済み blob から bundle の `rootfs/` へ
//!   再展開する（複製の一形態。overlay の下位層は未実装）。公開先が信頼できない状態（symlink・他人所有など）なら
//!   消さずに拒否する
//! - エラー文言は固定の英語で、イメージ名・資格情報・レジストリ応答の文言を含めない（`.claude/rules/security.md`）
//! - 資格情報は oci の `BasicCredentials` で検証され、`Debug` は伏せられる。zeroize は未対応（oci と同様。依存を足さない）
//!
//! # 既存 blob の再利用条件（OCI-1・SEC）
//!
//! キャッシュのディレクトリを他ユーザー書き込み不可にしても、その中の既存 inode の書き換えは防げない
//! （他ユーザー所有・group / other 書き込み可のファイルや、別の場所からハードリンクされたファイルは、
//! 検証後にも内容を変えられる）。そのため既存 blob は、次をすべて満たすときだけ再取得を省く。
//!
//! - パスの最終要素が symlink でない通常ファイルである（`open_blob_nofollow`。symlink は辿らない）
//! - 所有者が呼び出しプロセスと同じ（キャッシュのディレクトリ検証と同じ基準）
//! - group / other の書き込み権限が無い
//! - ハードリンク数が 1（キャッシュ外の名前から同じ inode を書き換えられない）
//! - 内容の digest とサイズが descriptor と一致する
//!
//! 検査と利用の間の差し替え（TOCTOU）への対処: メタデータは開いたハンドルの fstat から読み、digest も同じ
//! ハンドルから計算する（パスを再解決しない）。条件を満たさない・開けない・読めない場合は再利用せず、
//! ステージングの所有者専用（0700）ディレクトリへ取得して同じ手順で検証したファイルを、oci の公開で置き換える
//! （置き換えは名前の差し替えだけで、symlink の先・ハードリンクされた元の inode には書き込まない）。
//! 公開するファイルは 0600 に揃えるため、次回の pull で上記の条件を満たす。
//!
//! 限界:
//!
//! - 本モジュールが保証するのは「この pull が確認した時点で、キャッシュのエントリが上記条件を満たす検証済みの
//!   ファイルである」ことまで。キャッシュの blob を後から読む処理は、パスを信頼せず同じ手順（symlink を辿らずに
//!   開く → ハンドルで条件を確認 → 同じハンドルから読む）で開き直すこと。tar 展開の実体は
//!   `fandhe_container_oci::layer::extract` にあり（TASK-52.3・TASK-52.4・TASK-53）、本モジュールは oci の契約を満たす
//!   入口 `VerifiedLayerBlob`（symlink を辿らずに開き、同じハンドルで信頼条件と digest を確かめた値）と
//!   `extract_image_layers_with_options` だけを使う（#2309・#2323）。パスを受け取って開き直す旧入口
//!   （`extract_layer_blob` / `extract_layer_blobs` 系）は、最終要素の symlink を辿り所有者・権限・ハードリンク数も
//!   確かめないため #2535 で oci から廃止した
//! - 各 layer は `ensure_blob`・`VerifiedLayerBlob::open`・展開のパス 1 とパス 3 で計 4 回読まれる（oci の契約に従った
//!   結果で、最適化していない）。開いておく fd の数は layer 数と同じで、oci の `MAX_LAYERS` が上限になる
//! - 同一 UID の別プロセスと root による書き換えは対象外（キャッシュの所有者自身のため防げない）。所有者または
//!   root が過去に権限を緩めていた間に他ユーザーが開いた書き込み用の記述子も、現在のメタデータからは検出できない
//! - 既存のキャッシュディレクトリが他ユーザーから辿れる権限（0755 等）で、OS が他人のファイルへのハードリンク作成を
//!   禁じていない場合、他ユーザーが blob へリンクを張るとリンク数が 2 になり、次の pull で取得し直しになる
//!   （内容は書き換えられず完全性は保たれるが、再取得を強制できる。本モジュールが新規に作るディレクトリは 0700）
//! - 非 Unix では所有者・権限を確認できないため再利用も公開もしない（キャッシュ準備の時点で `Unimplemented` で
//!   拒否する。fail-closed）
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - レイヤーの展開と diff_id の突合は配線済み（#2323）。残りは次のとおり。
//!   - 所有者・特殊ビットの選択肢は [`PullConfig::extract_options`] の受け口までで、既定は安全側（`Keep` + `Strip`）。
//!     本番の呼び出し元が渡す値も現状は既定の `Keep` + `Strip` で、rootless / rootful ごとの値（`ChownMapped`・
//!     `PreserveIfOwnerMapped`・`ChownInUserNamespace`）の配線は次の前提が済んでからになる（#2534・SEC-5・SEC-1。
//!     `docs/design/oci-layer-special-bits.md`）。`ChownMapped` は初期 user namespace の `CAP_CHOWN` が要り、
//!     rootful の可否が未決（#2241）。`ChownInUserNamespace` は core が user namespace へ入る配線が要る（#2315・#482）。
//!     本モジュールの `PullConfig` を組む本番の呼び出し元は plugin-cri の `CriPluginBackends`（#2592）で、既定値（`Keep` + `Strip`）を
//!     pull と create の両方へ同じ値で渡す（本番の値への切り替えは上記の前提待ち）。
//!     所有者の解決の部品（#2389 の `image_ownership`）は cli crate にあり、置き場所の判断も要る。
//!     pull と create は [`crate::bundle::ImageExtractConfig`] の 1 か所から同じ値を配る（食い違うと記録の照合で
//!     `FAILED_PRECONDITION` になる）
//!   - 展開済み rootfs の GC と `image rm` / `image prune` への接続は TASK-183（OCI-7）の担当。それまで削除しても
//!     `<cache_dir>/rootfs/sha256/<hex>` は残る
//!   - pull 時と start 時の subuid / subgid のずれは、展開時の所有者写像の記録（`unpack-record`）で検出する方針
//!     （`docs/design/pull-inventory-wiring.md`）。本番の値が `Keep` + `Strip` の間は写像が空で効かず、
//!     `ChownMapped` 等の配線時に start 側の写像との照合を足す（#2592・#2377・#2241・#482）
//!   - 異常終了で残ったステージング（展開途中の rootfs を含む）の回収は、blob のステージングと同じく起動時 GC の担当（#2315）
//!   - 展開中の処理は gRPC のキャンセルで打ち切れず、期限（[`PullConfig::pull_deadline`]）は展開の前後で確認する。
//!     展開中は外部の応答を待たず（検証済みのローカル blob だけを読む）、所要時間は `ExtractLimits` と
//!     `max_uncompressed_layer_bytes` で有界になる。展開の直後に期限を超えていれば公開も記録の書き込みもせず
//!     `Timeout` を返す（ステージングは `abort` が消す。#2534・REPAIR-5）。展開中に打ち切る協調キャンセルが要る場合は
//!     oci の展開 API の変更として別に扱う
//! - 永続イメージストアと展開後サイズの算出は TASK-183（OCI-7。展開後サイズは #2222）の担当。本モジュールが返す
//!   `size` は config と全 layer の**圧縮サイズの合計**で、展開後サイズではない
//! - `AuthConfig.identity_token`（OAuth2）・`registry_token` は未対応で `UNIMPLEMENTED`（oci の OAuth2 POST フロー待ち。OCI-3）
//! - 実行中の blocking 処理は gRPC 側のキャンセルでは打ち切れず、[`PullConfig::pull_deadline`] のステップ間確認と
//!   oci の各リクエスト期限で有界化される。全体 timeout は plugin-cri（TASK-108・TASK-114）の責務
//! - UDS の権限・peer credential 検証（PLUG-12）は plugin-cri の責務

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(any(unix, test))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::time::{SystemTime, UNIX_EPOCH};

use fandhe_container_oci::auth::{BasicCredentials, RegistryAuth};
use fandhe_container_oci::config::{ImageRootFs, MAX_CONFIG_BYTES, parse_image_config_rootfs};
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::image_management::{
    BlobReuse, ImageStore, ManifestComposition, PullPublishRequest, PullSession, StagedBlobWriter,
    TagKey,
};
use fandhe_container_oci::instrument::{NoopOciOpRecorder, OciOpRecorder};
use fandhe_container_oci::layer::extract::{
    ExtractLimits, ExtractOptions, OwnershipPolicy, extract_image_layers_with_options,
    image_layers_from, remove_extracted_tree,
};
use fandhe_container_oci::layer::{
    BlobFileFacts, BlobTrustViolation, DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES, VerifiedLayerBlob,
    check_blob_trust, open_blob_nofollow, verify_blob_file_digest, verify_bytes_digest,
};
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
    /// レジストリ由来の HTTP 状態（100..=599 のみ）。message には入れず別持ちする（#2898・CRI-3・OCI-1）。
    http_status: Option<u16>,
}

/// レジストリ応答由来の HTTP 状態を妥当な範囲（100..=599）に限る。範囲外は捨てる（fail-closed）。
fn registry_http_status(status: u16) -> Option<u16> {
    (100..=599).contains(&status).then_some(status)
}

impl PullError {
    /// 分類と固定文言からエラーを作る。
    pub fn new(code: OciErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            http_status: None,
        }
    }

    /// レジストリ由来の HTTP 状態を付ける。100..=599 の外は捨てて `None` のままにする。
    /// 値は `PullImage` の gRPC エラーのメタデータへだけ載り、message には入らない
    /// （契約は `crate::error` のモジュール doc。#2898・CRI-3・OCI-1・REPAIR-4）。
    pub fn with_http_status(mut self, status: u16) -> Self {
        self.http_status = registry_http_status(status);
        self
    }

    /// レジストリ由来の HTTP 状態（`from_oci` 経由のときだけ入る）。
    pub fn http_status(&self) -> Option<u16> {
        self.http_status
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
        // 429 だけは専用の固定文言にする（値は含めない）。メタデータを捨てる経路でも、
        // ログ上で他の UNAVAILABLE と見分けられるようにするため（#2898）。
        let message = if err.http_status() == Some(429) {
            "registry rate limit exceeded"
        } else {
            message
        };
        let mut out = Self::new(err.code(), message);
        if let Some(status) = err.http_status() {
            out = out.with_http_status(status);
        }
        out
    }

    /// ローカルのイメージストア（`ImageStore` / `PullSession`）の失敗を写す。レジストリ由来ではないため
    /// `from_oci` の「registry ...」文言を使わず、ストア用の固定文言にする（OCI-7）。
    pub fn from_store(err: &OciError) -> Self {
        let message = match err.code() {
            OciErrorCode::Timeout => "image store lock wait timed out",
            OciErrorCode::NotFound => "image store entry not found",
            OciErrorCode::DataLoss => "image store data failed validation",
            OciErrorCode::PermissionDenied => "image store access denied",
            OciErrorCode::Unavailable => "image store is unavailable",
            OciErrorCode::ResourceExhausted => "image store resource limit exceeded",
            OciErrorCode::FailedPrecondition => "image cache precondition failed",
            _ => "image store operation failed",
        };
        Self::new(err.code(), message)
    }

    /// レイヤー展開の失敗を写す。oci の message にはエントリ名等が入りうるため捨て、分類ごとの固定文言にする
    /// （`.claude/rules/security.md`。#2323・OCI-1・ERR-3）。
    pub fn from_extract(err: &OciError) -> Self {
        let message = match err.code() {
            OciErrorCode::DataLoss => "image layer failed validation",
            OciErrorCode::ResourceExhausted => "image layer exceeds the extraction limit",
            OciErrorCode::Unimplemented => "unsupported image layer format",
            OciErrorCode::InvalidArgument => "image layer contains an invalid entry",
            OciErrorCode::PermissionDenied => "image layer entry is not permitted",
            OciErrorCode::NotFound => "image layer references a missing entry",
            OciErrorCode::FailedPrecondition => "image rootfs precondition failed",
            OciErrorCode::AlreadyExists => "image layer has conflicting entries",
            OciErrorCode::Timeout => "image layer extraction exceeded its deadline",
            _ => "image layer extraction failed",
        };
        Self::new(err.code(), message)
    }

    /// image config の読み取り・解析の失敗を写す（固定文言。#2323・OCI-1・ERR-3）。
    pub fn from_config(err: &OciError) -> Self {
        let message = match err.code() {
            OciErrorCode::DataLoss => "image config failed validation",
            OciErrorCode::ResourceExhausted => "image config exceeds the size limit",
            OciErrorCode::Unimplemented => "unsupported image config",
            _ => "image config could not be read",
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

/// oci の分類を gRPC ステータスへ写す（ERR-3）。写像は `CriError` の `From<PullError>` に一本化している。
impl From<PullError> for Status {
    fn from(err: PullError) -> Self {
        Status::from(crate::error::CriError::from(err))
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

    /// blob の本文を `dest` へ書く。`dest` は `PullSession::open_staged_blob` が検査済み root の fd 起点で開いた
    /// 書き込み先で、パスは渡さない（OCI-7・SEC-1・#2765）。確定（`StagedBlobWriter::commit`）と digest 検証は
    /// 呼び出し側が行う（成功しても未検証。公開前に oci が信頼条件の確認と権限の 0600 化を行う）。
    fn fetch_blob(
        &self,
        endpoint: &RegistryEndpoint,
        repository: &Repository,
        descriptor: &Descriptor,
        auth: &RegistryAuth,
        dest: &mut StagedBlobWriter,
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
        dest: &mut StagedBlobWriter,
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

    /// 認証・manifest 取得・blob 取得の計測先を差し替える（`RegistryClient::with_recorder` への素通し。REPAIR-4・#2900）。
    ///
    /// plugin-cri などの上位が集計の実装（`OciOpRecorder`）を渡す入口。既定は何も記録しない。
    #[must_use]
    pub fn with_recorder(mut self, recorder: Arc<dyn OciOpRecorder>) -> Self {
        self.inner = self.inner.with_recorder(recorder);
        self
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
        dest: &mut StagedBlobWriter,
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
    /// pull 全体の期限（ステップ間と、展開の前後で確認し、超過なら `Timeout`。展開中は打ち切らず、`extract_limits` で
    /// 有界にする。#2534・REPAIR-5）。
    pub pull_deadline: Duration,
    /// 資格情報を送ってよい token realm の追加ホスト（既定は空。接続先と同一ホスト・oci の組み込み既知対は常に許可）。
    pub trusted_realm_hosts: Vec<RegistryHost>,
    /// 1 レイヤーあたりの展開後（tar）サイズの上限。
    pub max_uncompressed_layer_bytes: u64,
    /// レイヤー展開の上限（エントリ数・展開バイト数・入力バイト数・索引件数。全レイヤーで共有して累積する）。
    pub extract_limits: ExtractLimits,
    /// レイヤー展開の所有者・特殊ビットの選択肢。既定は `chown` しない（`Keep`）・特殊ビットは落とす（`Strip`）。
    /// rootless / rootful ごとの値（`ChownMapped`・`PreserveIfOwnerMapped` 等）は呼び出し元が決めるが、本番の値は
    /// 現状も既定のまま（配線の前提は #2241・#2315・#482。呼び出し元の配線は #2592 で済み。モジュール doc「未実装範囲」と
    /// `docs/design/oci-layer-special-bits.md`。#2534・SEC-5・SEC-1）。
    pub extract_options: ExtractOptions,
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
            max_uncompressed_layer_bytes: DEFAULT_MAX_UNCOMPRESSED_LAYER_BYTES,
            extract_limits: ExtractLimits::default(),
            extract_options: ExtractOptions::new(),
        })
    }
}

/// oci の pull 経路でキャッシュへ取り込む [`ImagePuller`]（CRI-4・OCI-1）。
#[derive(Debug)]
pub struct OciImagePuller<C: RegistryPullClient> {
    client: C,
    config: PullConfig,
    /// 展開（`ExtractLayer`）の計装の記録先。既定は何も記録しない（REPAIR-4）。
    recorder: Arc<dyn OciOpRecorder>,
}

impl<C: RegistryPullClient> OciImagePuller<C> {
    /// クライアントと設定から作る。
    pub fn new(client: C, config: PullConfig) -> Self {
        Self {
            client,
            config,
            recorder: Arc::new(NoopOciOpRecorder),
        }
    }

    /// 展開の計装（レイヤーごとの成否・エラー code・所要時間。REPAIR-4）の記録先を差し替える。
    /// plugin-cri などの上位が集計・構造化ログの実装を渡す入口。
    #[must_use]
    pub fn with_recorder(mut self, recorder: Arc<dyn OciOpRecorder>) -> Self {
        self.recorder = recorder;
        self
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
    fn blobs_dir(&self) -> Result<TrustedDir, PullError> {
        prepare_private_dir(&self.config.cache_dir, &["blobs", "sha256"])
    }

    /// 展開済み rootfs の公開先（`<cache_dir>/rootfs/sha256/<hex>/rootfs`。キーはイメージ ID = config digest）。
    ///
    /// 親の `<hex>/` エントリは `rootfs/`（展開物）と `unpack-record`（展開時の設定の記録）を持ち、1 回の `rename` で
    /// 一緒に公開される（記録の無い rootfs が残らない）。
    ///
    /// 公開済みなら、検証済み blob から pull が展開し終えた読み取り専用の元になる rootfs である。コンテナの rootfs として
    /// 直接書き換えず、複製・overlay の下位層として使うこと（create 経路は TASK-59.2 の担当）。
    pub fn unpacked_rootfs_dir(&self, image_id: &Digest) -> PathBuf {
        self.config
            .cache_dir
            .join("rootfs")
            .join("sha256")
            .join(digest_hex(image_id))
            .join(ROOTFS_SUBDIR)
    }

    /// 展開済み rootfs があれば省き、無ければステージングで展開して成功時だけ公開する（#2323・OCI-1）。
    ///
    /// 作りかけの rootfs は公開先に現れない。失敗時の root は呼び出し側が `unpack/` ごと消し、ステージングは `abort` が消す。
    fn ensure_rootfs(
        &self,
        paths: &BTreeMap<Digest, PathBuf>,
        blob_owner: u32,
        unpack_dir: &Path,
        manifest: &ImageManifest,
        rootfs_cfg: &ImageRootFs,
        started: Instant,
    ) -> Result<(), PullError> {
        let rootfs_dir = prepare_private_dir(&self.config.cache_dir, &["rootfs", "sha256"])?;
        let entry_path = rootfs_dir.path.join(digest_hex(&manifest.config.digest));
        // 公開済みでも件数の照合を飛ばさない（余分な layer を足した不整合な manifest を成功させない。OCI-1）。
        if manifest.layers.len() != rootfs_cfg.diff_ids().len() {
            return Err(PullError::new(
                OciErrorCode::DataLoss,
                "image layer count does not match the config",
            ));
        }
        let record = self.unpack_record(manifest)?;
        let root_owner = self.expected_root_owner(rootfs_dir.owner)?;
        // 公開済みの命中は、同じ config・同じ展開設定の記録があるときに限る。layer の表現（圧縮 blob の digest・
        // mediaType）が違うだけなら、config の diff_ids が同じため展開物は同じ。その場合は今回の descriptor で
        // 展開を検証するだけで（公開はしない）成功とする（OCI-1）。
        let mut verify_only = false;
        if inspect_published_rootfs(&entry_path, rootfs_dir.owner, root_owner)? {
            match check_unpack_record(&entry_path.join(RECORD_FILE), &record, rootfs_dir.owner)? {
                RecordMatch::Exact => return Ok(()),
                RecordMatch::SameImageOtherLayers => verify_only = true,
            }
        }
        // descriptor の数だけ開く（重複 digest も別ハンドル。`image_layers_from` が件数の一致を要求する）。
        let verified = manifest
            .layers
            .iter()
            .map(|d| {
                let path = paths.get(&d.digest).ok_or_else(|| {
                    PullError::new(OciErrorCode::Internal, "image layer blob path is missing")
                })?;
                VerifiedLayerBlob::open(path, &d.digest, d.size, blob_owner)
                    .map_err(|e| PullError::from_extract(&e))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let refs: Vec<&VerifiedLayerBlob> = verified.iter().collect();
        let layers = image_layers_from(&manifest.layers, &refs, rootfs_cfg)
            .map_err(|e| PullError::from_extract(&e))?;
        // ステージングの中でエントリ（`rootfs/` と記録）を組み立て、1 回の rename で公開する。
        create_private_dir(unpack_dir)?;
        let staged_entry = unpack_dir.join("entry");
        create_private_dir(&staged_entry)?;
        let root = staged_entry.join(ROOTFS_SUBDIR);
        create_private_dir(&root)?;
        self.check_deadline(started)?;
        extract_image_layers_with_options(
            self.recorder.as_ref(),
            &layers,
            &root,
            self.config.max_uncompressed_layer_bytes,
            self.config.extract_limits,
            &self.config.extract_options,
        )
        .map_err(|e| PullError::from_extract(&e))?;
        self.check_deadline(started)?;
        if verify_only {
            return Ok(());
        }
        write_unpack_record(&staged_entry.join(RECORD_FILE), &record)?;
        // 原子的に公開する。並行する pull が先に公開していて信頼できるなら、その展開設定が同じときだけ成功とする。
        if fs::rename(&staged_entry, &entry_path).is_err() {
            if inspect_published_rootfs(&entry_path, rootfs_dir.owner, root_owner).unwrap_or(false)
            {
                check_unpack_record(&entry_path.join(RECORD_FILE), &record, rootfs_dir.owner)?;
                return Ok(());
            }
            return Err(PullError::new(
                OciErrorCode::FailedPrecondition,
                "failed to publish image rootfs",
            ));
        }
        Ok(())
    }

    /// 展開結果を決める入力（config・所有者と特殊ビットの設定）と、今回の layer の表現を記録にする。
    /// 公開済み rootfs の再利用可否は、この記録が展開時のものと一致するかで決める（#2323・OCI-1・SEC-5）。
    fn unpack_record(&self, manifest: &ImageManifest) -> Result<UnpackRecord, PullError> {
        let settings = record_settings(&manifest.config.digest, &self.config.extract_options)?;
        let mut layers = String::new();
        for d in &manifest.layers {
            layers.push_str("layer=");
            layers.push_str(d.digest.as_str());
            layers.push(' ');
            layers.extend(d.media_type.chars().map(|c| {
                if c.is_control() || c.is_whitespace() {
                    '_'
                } else {
                    c
                }
            }));
            layers.push('\n');
        }
        Ok(UnpackRecord { settings, layers })
    }

    /// 公開済み rootfs の root が持つべき所有 uid。`ChownMapped` では展開が root を写像先（コンテナ uid 0 の
    /// ホスト側 ID）へ `chown` するため、それを期待値にする。それ以外は管理プロセスの uid（`owner`）。
    fn expected_root_owner(&self, owner: u32) -> Result<u32, PullError> {
        expected_root_owner_for(&self.config.extract_options, owner)
    }

    /// blob を「リース済みの信頼できる既存 blob」または「ステージングへ取得して検証した blob」として確保し、
    /// 以降の読み取り元のパスを返す（#2539・OCI-1・OCI-7）。公開（`blobs/sha256` への移動）は行わず、
    /// [`PullSession::publish`] が構成の blob をまとめて公開する。
    ///
    /// 既存 blob は、先にリースを登録してから信頼条件と内容を確かめる（確かめた後に GC に消されない順序）。
    /// 条件を満たさなければリースを外して取得し直す。
    fn ensure_blob(
        &self,
        request: &PullContext<'_>,
        auth: &mut RegistryAuth,
        session: &mut PullSession<'_>,
        blob_owner: u32,
        descriptor: &Descriptor,
    ) -> Result<PathBuf, PullError> {
        if let BlobReuse::Leased(token) = session
            .lease_existing_blob(&descriptor.digest)
            .map_err(|e| PullError::from_store(&e))?
        {
            let path = token.path().to_path_buf();
            // 不合格でも共有 blob はここでは消さない（一過性の読み出しエラーで検証済み blob を失わないため）。
            // 取得・検証に成功した場合に限り、公開が置き換える。
            if inspect_cached_blob(&path, &descriptor.digest, descriptor.size, blob_owner).is_ok() {
                return Ok(path);
            }
            session
                .release_leased(token)
                .map_err(|e| PullError::from_store(&e))?;
        }
        // 長時間の pull では Bearer token が途中で失効する。取得前に失効を確認して再認証し、
        // 取得が PermissionDenied なら有限回（MAX_REAUTH_RETRIES）だけ再認証して再試行する（OCI-3）。
        let mut retries = 0u32;
        loop {
            if matches!(&*auth, RegistryAuth::Bearer(t) if t.is_expired(Instant::now())) {
                *auth = self.reauthenticate(request)?;
            }
            // 試行ごとに書き込み先を開き直す（検査済み root の fd 起点の `<hex>.part`。#2765）。失敗した試行の
            // writer は drop で自分の `.part` を消すため、部分ファイルを次の試行へ持ち越さない。
            let mut writer = session
                .open_staged_blob(&descriptor.digest)
                .map_err(|e| PullError::from_store(&e))?;
            match self.client.fetch_blob(
                request.endpoint,
                request.repository,
                descriptor,
                auth,
                &mut writer,
            ) {
                Ok(()) => {
                    writer.commit().map_err(|e| PullError::from_store(&e))?;
                    break;
                }
                Err(e)
                    if e.code() == OciErrorCode::PermissionDenied
                        && retries < MAX_REAUTH_RETRIES =>
                {
                    retries += 1;
                    drop(writer);
                    *auth = self.reauthenticate(request)?;
                }
                Err(e) => return Err(PullError::from_oci(&e)),
            }
        }
        // 信頼条件の確認・権限の 0600 化・digest の検証は oci が root の fd 起点で行う。サイズは読み取り上限
        // ではなく宣言値との完全一致で確認する（短い blob の誤受理を防ぐ。OCI-1）。
        let verified = session
            .verify_staged_blob(&descriptor.digest, descriptor.size)
            .map_err(|e| PullError::from_store(&e))?;
        if verified.size != descriptor.size {
            return Err(PullError::new(
                OciErrorCode::DataLoss,
                "blob size does not match the descriptor",
            ));
        }
        // 読み取り用のパスは検証に成功した後にだけ得る（config の読み取りと展開の入力用。書き込みには使わない）。
        session
            .staged_blob_read_path(&descriptor.digest)
            .map_err(|e| PullError::from_store(&e))
    }

    /// 全 blob を確保し、config を検証して layer を展開する（公開の直前まで。#2539）。
    /// 失敗時の `abort` は呼び出し側が行う（本関数は `staging/<id>` を消さない）。
    fn stage_and_unpack(
        &self,
        session: &mut PullSession<'_>,
        ctx: &PullContext<'_>,
        auth: &mut RegistryAuth,
        blobs: &TrustedDir,
        manifest: &ImageManifest,
        started: Instant,
    ) -> Result<ManifestComposition, PullError> {
        // 同一 digest の重複（同じ layer を複数回使う manifest）は 1 回だけ取得する。
        // 同一 digest で宣言サイズが食い違う descriptor は不正な manifest として拒否する（OCI-1）。
        let mut paths: BTreeMap<Digest, PathBuf> = BTreeMap::new();
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
            let path = self.ensure_blob(ctx, auth, session, blobs.owner, descriptor)?;
            paths.insert(descriptor.digest.clone(), path);
            seen.push((&descriptor.digest, descriptor.size));
        }
        // 最後の blob の取得・検証で期限を超えた場合も成功を返さない（REPAIR-5）。
        self.check_deadline(started)?;

        // config を検証してから解析し、検証済みハンドルでレイヤーを展開する（#2323・OCI-1・OCI-2）。
        let config_path = paths.get(&manifest.config.digest).ok_or_else(|| {
            PullError::new(OciErrorCode::Internal, "image config blob path is missing")
        })?;
        let rootfs_cfg = read_verified_config(
            config_path,
            &manifest.config,
            blobs.owner,
            self.config.max_config_bytes,
        )?;
        let unpack_dir = session.staging_dir().join(UNPACK_SUBDIR);
        self.ensure_rootfs(
            &paths,
            blobs.owner,
            &unpack_dir,
            manifest,
            &rootfs_cfg,
            started,
        )?;
        self.check_deadline(started)?;
        ManifestComposition::new(
            manifest.config.digest.clone(),
            manifest.layers.iter().map(|d| d.digest.clone()).collect(),
        )
        .map_err(|e| PullError::from_oci(&e))
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

        // 在庫（`@image-inventory.json`）への登録は oci の `ImageStore` を通す（#2539・OCI-1・OCI-7）。
        // 取得・検証した blob は `PullSession` のステージングに置き、`publish` が `blobs/sha256` への公開・
        // manifest とタグの登録・リース解放を排他の下でまとめて行う。cri 自身は `blobs/sha256` へ置かない。
        let blobs = self.blobs_dir()?;
        let store = ImageStore::open(&self.config.cache_dir)
            .map_err(|e| PullError::from_store(&e))?
            .with_recorder(Arc::clone(&self.recorder));
        let mut session = store
            .begin_pull_generated()
            .map_err(|e| PullError::from_store(&e))?;
        let ctx = PullContext {
            endpoint: &endpoint,
            repository,
            credentials: request.credentials.as_ref(),
        };
        let prepared =
            self.stage_and_unpack(&mut session, &ctx, &mut auth, &blobs, manifest, started);
        // 展開の作業領域は `staging/<id>` を消さずに自分の子だけ消す（`staging/<id>` を消してよいのは
        // `abort` / `publish` / 回収 GC だけ。永続化済みのリースだけが残る孤児リースを作らないため）。
        // 検証だけの経路や失敗経路に残る展開物は 0555 等を含むため、oci の削除で消す。
        let unpack_dir = session.staging_dir().join(UNPACK_SUBDIR);
        if fs::symlink_metadata(&unpack_dir).is_ok() {
            let _ = remove_extracted_tree(&unpack_dir);
        }
        let composition = match prepared.and_then(|c| self.check_deadline(started).map(|()| c)) {
            Ok(c) => c,
            Err(e) => {
                // abort の失敗は元のエラーを優先する（残骸は回収 GC が拾う）。
                let _ = session.abort();
                return Err(e);
            }
        };
        let mut publish = PullPublishRequest::new(resolved.manifest_digest.clone(), composition);
        // タグ参照のときだけタグを付ける。digest 参照にはタグを付けず、index の digest は在庫のキーにしない
        // （在庫のキーは選択された platform manifest の digest）。
        if let Reference::Tag(tag) = image_ref.reference() {
            publish = publish.with_tag(TagKey::new(
                image_ref.registry().clone(),
                repository.clone(),
                tag.clone(),
            ));
        }
        // 失敗時の abort は publish が内部で行う。
        // publish が確定した後は期限超過でも成功を返す。ここで Timeout を返すと永続在庫に登録済みなのに
        // 呼び出し側（CriImageService）が自身の表示を更新せず食い違う（OCI-7）。期限は publish の前に確認済み。
        session
            .publish(publish)
            .map_err(|e| PullError::from_store(&e))?;

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
pub(crate) fn digest_hex(digest: &Digest) -> &str {
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
/// 副作用のない検証を作成より先に行う。まず `cache_dir` の既存部分（実在する最も深い祖先まで）を
/// `symlink_metadata` で辿り、利用者所有の symlink と `..` を拒否する。次にその既存祖先で所有者基準を取得し、
/// 祖先連鎖を検証してから、足りない要素を検証済みディレクトリの配下へ非再帰で 1 要素ずつ作る。
/// 検証前に再帰作成や probe ファイルの作成をしないため、他ユーザーが張った symlink 経由で
/// キャッシュ外にディレクトリ・ファイルが作られない。
/// `components` は `cache_dir` 直下から順に非再帰で作成し（既存は許容）、各要素について
/// 「symlink でない通常ディレクトリ」「呼び出しプロセスと同一所有者」「group / other 書き込み権限なし」
/// （Unix）を確認する。検証済みの所有者専用ディレクトリは他ユーザーが差し替えられないため、検証後の
/// blob 公開（rename）で未検証の内容が混入する経路を塞ぐ。ディレクトリの検証は配下の既存 inode の書き換えを
/// 防がないため、blob ファイル自体の所有者・権限・ハードリンク数は [`check_blob_trust`] で別に確認する。
/// 0700 の指定は新規作成時にしか効かないので、既存ディレクトリは必ずここで検証する。
pub(crate) fn prepare_private_dir(
    cache_dir: &Path,
    components: &[&str],
) -> Result<TrustedDir, PullError> {
    let prep_err = || {
        PullError::new(
            OciErrorCode::FailedPrecondition,
            "failed to prepare the image cache directory",
        )
    };
    let (existing, missing) = split_existing_prefix(cache_dir)?;
    let owner = owner_probe(&existing)?;
    // `verify_ancestors` は引数の親を起点に検証するため、既存部分の直下の仮想子を渡す。
    verify_ancestors(&existing.join("child"), owner)?;
    let mut current = existing;
    if missing.is_empty() {
        verify_private_dir(&current, owner)?;
    }
    let names = missing
        .iter()
        .map(|c| c.as_os_str())
        .chain(components.iter().map(std::ffi::OsStr::new));
    for name in names {
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
    Ok(TrustedDir {
        path: current,
        owner,
    })
}

/// 検証済みのキャッシュ配下ディレクトリと、検証に使った所有者基準（[`prepare_private_dir`] の戻り値）。
///
/// `owner` は呼び出しプロセスの実効 UID 相当（`owner_probe`）で、配下の blob ファイルの所有者確認
/// （[`check_blob_trust`]）にも同じ値を使う（基準を取り直さない）。
#[derive(Debug)]
pub(crate) struct TrustedDir {
    pub(crate) path: PathBuf,
    pub(crate) owner: u32,
}

/// 既存 blob を再利用しない理由（[`inspect_cached_blob`]）。いずれの場合も呼び出し側は取得し直す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CachedBlobRejection {
    /// 存在しない・symlink や通常ファイル以外・開けない・開く間に差し替えられた。
    Unopenable,
    /// メタデータを取得できず、信頼条件を確認できない（非 Unix を含む）。
    Unverifiable,
    /// 信頼条件を満たさない。
    Untrusted(BlobTrustViolation),
    /// 内容の digest またはサイズが descriptor と一致しない・読み出しに失敗した。
    ContentMismatch,
}

/// キャッシュの既存 blob を再利用してよいか確認する（OCI-1・SEC。`ensure_blob` のキャッシュ命中判定）。
///
/// symlink を辿らずに開いたハンドルで信頼条件（[`check_blob_trust`]）を確認し、同じハンドルから digest を
/// 計算して descriptor の `digest`・`size` と突合する。確認と読み取りの間でパスを再解決しないため、
/// 確認したファイルと検証したファイルは同一である。ファイルは変更も削除もしない。
fn inspect_cached_blob(
    path: &Path,
    digest: &Digest,
    size: u64,
    owner: u32,
) -> Result<(), CachedBlobRejection> {
    let file = open_blob_nofollow(path).map_err(|_| CachedBlobRejection::Unopenable)?;
    let facts = BlobFileFacts::from_file(&file).ok_or(CachedBlobRejection::Unverifiable)?;
    check_blob_trust(&facts, owner).map_err(CachedBlobRejection::Untrusted)?;
    // サイズは読み取り上限ではなく宣言値との完全一致で確認する（短い blob の誤受理を防ぐ。OCI-1）。
    match verify_blob_file_digest(&file, digest, size) {
        Ok(verified) if verified.size == size => Ok(()),
        _ => Err(CachedBlobRejection::ContentMismatch),
    }
}

/// config blob を信頼条件の確認つきで 1 回だけ読み、読んだ本文そのもののハッシュを digest と照合してから
/// rootfs 部だけ解析する（#2323・#2534・OCI-1）。
///
/// 手順: symlink を辿らず開く → 同じハンドルで所有者・権限・ハードリンク数を確認 → 同じハンドルを先頭から上限つきで
/// 1 回だけ読む → 長さと [`verify_bytes_digest`] で本文を照合 → `parse_image_config_rootfs`。ハッシュ計算と解析の
/// 読み取りを分けない（別々に読むと、その間に同じ inode を書き換えられて、検証していない `rootfs.diff_ids` を
/// 解析しうる。#2309 でレイヤーに対して塞いだのと同じ型の穴）。パスは開き直さない。上限は `max_bytes` と oci の
/// `MAX_CONFIG_BYTES` の小さい方で、`max_bytes` を大きくしても oci 側の 1 MiB で拒否される（fail-closed）。
fn read_verified_config(
    path: &Path,
    descriptor: &Descriptor,
    owner: u32,
    max_bytes: u64,
) -> Result<ImageRootFs, PullError> {
    read_verified_config_inner(path, descriptor, owner, max_bytes, &|| {})
}

/// [`read_verified_config`] の本体。`before_body_read` は信頼確認の後・本文を読む直前に呼ばれる試験用の差し込み口
/// （本番は空。確認後に同じ inode を書き換える競合を再現する。oci の `open_blob_nofollow_inner` と同じ形）。
fn read_verified_config_inner(
    path: &Path,
    descriptor: &Descriptor,
    owner: u32,
    max_bytes: u64,
    before_body_read: &dyn Fn(),
) -> Result<ImageRootFs, PullError> {
    let mut file = open_blob_nofollow(path).map_err(|e| PullError::from_config(&e))?;
    let untrusted = || {
        PullError::new(
            OciErrorCode::FailedPrecondition,
            "cached image config is not trusted",
        )
    };
    let facts = BlobFileFacts::from_file(&file).ok_or_else(untrusted)?;
    check_blob_trust(&facts, owner).map_err(|_| untrusted())?;
    let limit = max_bytes.min(MAX_CONFIG_BYTES);
    before_body_read();
    let mut body = Vec::new();
    (&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| PullError::new(OciErrorCode::DataLoss, "image config could not be read"))?;
    if body.len() as u64 > limit {
        return Err(PullError::new(
            OciErrorCode::ResourceExhausted,
            "image config exceeds the size limit",
        ));
    }
    let invalid = || PullError::new(OciErrorCode::DataLoss, "image config failed validation");
    if body.len() as u64 != descriptor.size {
        return Err(invalid());
    }
    verify_bytes_digest(&body, &descriptor.digest).map_err(|_| invalid())?;
    parse_image_config_rootfs(&body).map_err(|e| PullError::from_config(&e))
}

/// 公開済みエントリ内の展開物のディレクトリ名。
pub(crate) const ROOTFS_SUBDIR: &str = "rootfs";
/// 公開済みエントリ内の展開時の設定の記録のファイル名。
pub(crate) const RECORD_FILE: &str = "unpack-record";

/// 展開時の設定の記録。`settings` は展開結果を決める入力（config・所有者・特殊ビット）、`layers` は今回の layer の
/// 表現（圧縮 blob の digest と mediaType）。
struct UnpackRecord {
    settings: String,
    layers: String,
}

/// 記録との照合結果。
enum RecordMatch {
    /// 設定も layer の表現も一致する。
    Exact,
    /// 設定は一致し、layer の表現だけ違う（同じ config = 同じ diff_ids の再圧縮など）。
    SameImageOtherLayers,
}

/// `ExtractOptions` を固定書式で符号化する。`Debug` 出力は書式が安定しないため使わない（記録の互換性を保つ）。
/// 未知の選択肢（将来追加された variant）は黙って同一視せず `Unimplemented` で拒否する（fail-closed）。
pub(crate) fn encode_extract_options(options: &ExtractOptions) -> Result<String, PullError> {
    use fandhe_container_oci::layer::extract::{IdRange, SpecialBitsPolicy};
    fn range(r: &IdRange) -> String {
        format!("{}:{}:{}", r.container_id, r.host_id, r.count)
    }
    fn map_lines(lines: &[IdRange]) -> String {
        lines.iter().map(range).collect::<Vec<_>>().join(",")
    }
    let unsupported = || {
        PullError::new(
            OciErrorCode::Unimplemented,
            "unsupported layer extraction option",
        )
    };
    let ownership = match &options.ownership {
        OwnershipPolicy::Keep => "keep".to_owned(),
        OwnershipPolicy::ChownMapped { uid, gid } => {
            format!(
                "chown-mapped uid={} gid={}",
                map_lines(uid.lines()),
                map_lines(gid.lines())
            )
        }
        _ => return Err(unsupported()),
    };
    let special = match &options.special_bits {
        SpecialBitsPolicy::Strip => "strip".to_owned(),
        SpecialBitsPolicy::PreserveIfOwnerMapped { uid, gid } => {
            format!(
                "preserve-if-owner-mapped uid={} gid={}",
                range(uid),
                range(gid)
            )
        }
        SpecialBitsPolicy::PreserveIfChowned => "preserve-if-chowned".to_owned(),
        _ => return Err(unsupported()),
    };
    Ok(format!("ownership={ownership}\nspecial-bits={special}\n"))
}

/// 展開記録の `settings` 部（先頭〜special-bits 行）を組み立てる。pull（書き込み）と create（照合。#2433）が
/// 同じ書式を使い、展開設定の食い違いを検出する。
pub(crate) fn record_settings(
    config: &Digest,
    options: &ExtractOptions,
) -> Result<String, PullError> {
    let mut settings = format!("fandhe-rootfs-v2\nconfig={}\n", config.as_str());
    settings.push_str(&encode_extract_options(options)?);
    Ok(settings)
}

/// 公開済み rootfs の root が持つべき所有 uid（`ChownMapped` では写像先、それ以外は `owner`）。
pub(crate) fn expected_root_owner_for(
    options: &ExtractOptions,
    owner: u32,
) -> Result<u32, PullError> {
    match &options.ownership {
        OwnershipPolicy::ChownMapped { uid, .. } => uid.map_to_host(0).ok_or_else(|| {
            PullError::new(
                OciErrorCode::InvalidArgument,
                "id mapping does not cover the container root user",
            )
        }),
        _ => Ok(owner),
    }
}

/// 公開済みエントリの有無を確かめる。有って信頼できれば `true`、無ければ `false`、有るのに信頼できなければ拒否する
/// （消さない。#2323）。信頼条件はキャッシュのディレクトリと同じ（symlink でない・所有者一致・group/other 書き込みなし）。
/// エントリ（管理プロセス所有）と中の `rootfs/`（`root_owner` 所有）の両方を見る。
pub(crate) fn inspect_published_rootfs(
    entry: &Path,
    owner: u32,
    root_owner: u32,
) -> Result<bool, PullError> {
    let untrusted = || {
        PullError::new(
            OciErrorCode::FailedPrecondition,
            "image rootfs cache entry is not trusted",
        )
    };
    match fs::symlink_metadata(entry) {
        Ok(_) => {
            verify_private_dir(entry, owner).map_err(|_| untrusted())?;
            verify_private_dir(&entry.join(ROOTFS_SUBDIR), root_owner).map_err(|_| untrusted())?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(PullError::new(
            OciErrorCode::FailedPrecondition,
            "failed to inspect the image rootfs cache entry",
        )),
    }
}

/// 照合用の記録の読み取り上限。
pub(crate) const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// 展開記録を、種別の確認と同じハンドルから非ブロッキングで読む（#2534・OCI-1・SEC-5・REPAIR-5）。
///
/// pull の再利用判定（`check_unpack_record`）と create の `read_layers`（`bundle/image_rootfs.rs`）が共有する入口。
/// `open_blob_nofollow` は lstat で種別を確かめ、`O_NONBLOCK` で開き、fstat と lstat の dev / ino を照合する。
/// このため、lstat の後に FIFO へ差し替えられても open が無期限に止まらない。続けて同じハンドルの fstat で
/// 「通常ファイル・所有者が `owner`・ハードリンク数 1・group / other 書き込み不可」を確認する
/// （[`check_blob_trust`]）。上限は [`MAX_RECORD_BYTES`] で、超えたら黙って切り詰めず `ResourceExhausted` で
/// 拒否する（切り詰めると `SameImageOtherLayers` に化けて再展開になる）。
/// 失敗はいずれも固定文言で、パス・OS メッセージを含めない。
pub(crate) fn read_unpack_record_body(path: &Path, owner: u32) -> Result<Vec<u8>, PullError> {
    let mut file = open_blob_nofollow(path).map_err(|_| {
        PullError::new(
            OciErrorCode::FailedPrecondition,
            "image rootfs cache entry has no unpack record",
        )
    })?;
    let untrusted = || {
        PullError::new(
            OciErrorCode::FailedPrecondition,
            "image rootfs unpack record is not trusted",
        )
    };
    let facts = BlobFileFacts::from_file(&file).ok_or_else(untrusted)?;
    check_blob_trust(&facts, owner).map_err(|_| untrusted())?;
    let mut body = Vec::new();
    (&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| {
            PullError::new(
                OciErrorCode::DataLoss,
                "image rootfs unpack record could not be read",
            )
        })?;
    if body.len() as u64 > MAX_RECORD_BYTES {
        return Err(PullError::new(
            OciErrorCode::ResourceExhausted,
            "image rootfs unpack record exceeds the size limit",
        ));
    }
    Ok(body)
}

/// 公開済みエントリの記録を `expected` と照合する。記録が無い・信頼できない・上限超過・設定が食い違う場合は再利用せず
/// 拒否する（既存の展開物は消さない。コンテナの下位層として使われている可能性があるため）。読み取りは
/// [`read_unpack_record_body`]（非ブロッキング・同じハンドル）。
fn check_unpack_record(
    path: &Path,
    expected: &UnpackRecord,
    owner: u32,
) -> Result<RecordMatch, PullError> {
    let body = read_unpack_record_body(path, owner)?;
    let Some(rest) = body.strip_prefix(expected.settings.as_bytes()) else {
        return Err(PullError::new(
            OciErrorCode::FailedPrecondition,
            "image rootfs cache entry was unpacked with different settings",
        ));
    };
    if rest == expected.layers.as_bytes() {
        Ok(RecordMatch::Exact)
    } else {
        Ok(RecordMatch::SameImageOtherLayers)
    }
}

/// 記録を 0600 で `path`（ステージングのエントリ内）へ書く。公開は親ごとの rename で行うため、単体の rename はしない。
///
/// 失敗したら作ったファイルを消して何も残さない（#2796・OCI-1・REPAIR-5。ENOSPC 等の途中失敗で不完全な記録を
/// 残さない関数単体の契約）。現行の呼び出し元ではステージングごと片付けるため公開先には届かないが、再利用に備えて保証する。
/// 消す対象はこの関数が `create_new` で作ったファイルだけで、`remove_file` は最終要素の symlink を辿らない。
fn write_unpack_record(path: &Path, record: &UnpackRecord) -> Result<(), PullError> {
    use std::io::Write as _;
    write_unpack_record_with(path, record, &|f, r| {
        f.write_all(r.settings.as_bytes())?;
        f.write_all(r.layers.as_bytes())?;
        f.sync_all()
    })
}

/// [`write_unpack_record`] の本体。本文の書き込み（`write_body`）を差し替えられる（失敗の注入用）。
fn write_unpack_record_with(
    path: &Path,
    record: &UnpackRecord,
    write_body: &dyn Fn(&mut fs::File, &UnpackRecord) -> std::io::Result<()>,
) -> Result<(), PullError> {
    let fail = || {
        PullError::new(
            OciErrorCode::FailedPrecondition,
            "failed to record the image rootfs unpack settings",
        )
    };
    // 読み取り側が拒否する大きさの記録は公開しない（読めない記録を残すと、以後その entry は再利用できない）。
    if (record.settings.len() + record.layers.len()) as u64 > MAX_RECORD_BYTES {
        return Err(PullError::new(
            OciErrorCode::ResourceExhausted,
            "image rootfs unpack record exceeds the size limit",
        ));
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|_| fail())?;
    if write_body(&mut f, record).is_err() {
        // Windows は開いたファイルを消せないため、先にハンドルを閉じる。後始末の失敗は元のエラーを隠さない。
        drop(f);
        let _ = fs::remove_file(path);
        return Err(fail());
    }
    Ok(())
}

/// 非再帰で 0700 のディレクトリを作る（既存は拒否。展開の root は空であることが前提）。
pub(crate) fn create_private_dir(path: &Path) -> Result<(), PullError> {
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = fs::DirBuilder::new();
    builder.create(path).map_err(|_| {
        PullError::new(
            OciErrorCode::FailedPrecondition,
            "failed to create the image rootfs staging directory",
        )
    })
}

/// `cache_dir` を絶対化し、実在する最も深い祖先（またはパス自身）と、その下の未作成要素に分ける。
///
/// 辿る途中で `..` と利用者所有（root 以外）の symlink を拒否する（Unix）。何も作成しない。未作成要素が
/// ある場合、既存祖先が（root 所有の）symlink なら解決先の実体パスにする。
fn split_existing_prefix(
    cache_dir: &Path,
) -> Result<(PathBuf, Vec<std::ffi::OsString>), PullError> {
    let reject = |message: &'static str| PullError::new(OciErrorCode::FailedPrecondition, message);
    let absolute = std::path::absolute(cache_dir)
        .map_err(|_| reject("failed to resolve the image cache directory"))?;
    let comps: Vec<std::path::Component<'_>> = absolute.components().collect();
    let mut walked = PathBuf::new();
    let mut existing = PathBuf::new();
    let mut existing_len = 0;
    for (i, component) in comps.iter().enumerate() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(reject(
                "image cache path must not contain parent components",
            ));
        }
        walked.push(component);
        match fs::symlink_metadata(&walked) {
            Ok(meta) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt as _;
                    if meta.file_type().is_symlink() && meta.uid() != 0 {
                        return Err(reject("image cache path contains a user-owned symlink"));
                    }
                }
                #[cfg(not(unix))]
                let _ = &meta;
                existing = walked.clone();
                existing_len = i + 1;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => {
                return Err(reject(
                    "failed to inspect an image cache ancestor directory",
                ));
            }
        }
    }
    let mut missing = Vec::new();
    for component in &comps[existing_len..] {
        match component {
            std::path::Component::Normal(name) => missing.push((*name).to_os_string()),
            _ => return Err(reject("image cache path has an unexpected component")),
        }
    }
    if !missing.is_empty() {
        // 未作成要素の親になる既存祖先は symlink を解決して実体の通常ディレクトリであることを要求する。
        existing = fs::canonicalize(&existing)
            .map_err(|_| reject("failed to resolve the image cache ancestor directory"))?;
        if !fs::symlink_metadata(&existing).is_ok_and(|m| m.file_type().is_dir()) {
            return Err(reject("image cache ancestor is not a plain directory"));
        }
    }
    Ok((existing, missing))
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
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|_| fail())?;
    // 所有者は保持した File のハンドルから読む。パスを再照会すると差し替えられた別ファイルの UID を
    // 信頼基準にしてしまうため（パスは削除にしか使わない）。
    let uid = file.metadata().map(|m| m.uid());
    drop(file);
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
/// まず元のパスの各要素を `symlink_metadata` で辿り、root 所有でない symlink と `..` 要素を拒否する
/// （後続の staging・blob 公開・後始末は元の `cache_dir` を使うため、利用者所有の symlink が
/// 信頼できない祖先を隠して差し替え可能になる経路を塞ぐ）。root 所有の symlink（macOS の `/var` 等）は
/// 一般ユーザーが付け替えられないので許可し、解決後の連鎖も下記で検証する。
/// 次に親を `canonicalize` して symlink を解決したうえで、親から根までの各ディレクトリが「呼び出しプロセスまたは
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
    let absolute = std::path::absolute(parent)
        .map_err(|_| reject("failed to resolve the image cache parent directory"))?;
    let mut walked = PathBuf::new();
    for component in absolute.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(reject(
                "image cache path must not contain parent components",
            ));
        }
        walked.push(component);
        let meta = fs::symlink_metadata(&walked)
            .map_err(|_| reject("failed to inspect an image cache ancestor directory"))?;
        let kind = meta.file_type();
        if kind.is_symlink() {
            if meta.uid() != 0 {
                return Err(reject("image cache path contains a user-owned symlink"));
            }
        } else if !kind.is_dir() {
            return Err(reject("image cache ancestor is not a plain directory"));
        } else {
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
    }
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

/// 一時名の衝突回避用カウンタ（Unix の所有者検査とテストだけが使う）。
#[cfg(any(unix, test))]
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// 展開の作業領域の名前（`staging/<id>/unpack`。中に `entry/{rootfs,unpack-record}`）。
const UNPACK_SUBDIR: &str = "unpack";

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

    /// CRI-3・OCI-1: HTTP 状態を運ぶのは `from_oci` だけで、範囲外（100..=599 の外）は捨てる。
    #[test]
    fn cri3_only_registry_errors_carry_http_status() {
        let e = OciError::new(OciErrorCode::Unavailable, "x").with_http_status(500);
        assert_eq!(PullError::from_oci(&e).http_status(), Some(500));
        assert_eq!(PullError::from_store(&e).http_status(), None);
        assert_eq!(PullError::from_extract(&e).http_status(), None);
        assert_eq!(PullError::from_config(&e).http_status(), None);
        let n = PullError::new(OciErrorCode::Unavailable, "m");
        assert_eq!(n.with_http_status(99).http_status(), None);
        assert_eq!(n.with_http_status(600).http_status(), None);
        assert_eq!(n.with_http_status(599).http_status(), Some(599));
        assert_eq!(n.with_http_status(100).http_status(), Some(100));
    }

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

    /// OCI-1・SEC-5・#2534: 記録の最悪値（`ChownMapped` の写像が上限行数・全桁最大に近く、特殊ビットも保持、layer が
    /// 上限数・最長の mediaType）でも `MAX_RECORD_BYTES` に収まる。上限を超えた記録は読み取り側が明示エラーで拒否する
    /// ため、書き込める最大の記録が必ず読めることをここで固定する。
    #[test]
    fn oci1_unpack_record_worst_case_fits_within_the_limit() {
        use fandhe_container_oci::layer::LAYER_MEDIA_TYPES;
        use fandhe_container_oci::layer::extract::{IdMap, IdRange, SpecialBitsPolicy};
        use fandhe_container_oci::manifest::MAX_LAYERS;
        // container 側は 0 から 9_000_000 刻み、host 側は 1_000_000_000 から同じ刻み（範囲は重ならず u32 に収まる）。
        // 桁数を最大に近づけるため count は 7 桁にする。
        const MAX_ID_MAP_LINES_340: usize = 340; // oci の `MAX_ID_MAP_LINES`（非公開のため値を写す）
        let lines = |host_base: u32| -> Vec<IdRange> {
            (0..u32::try_from(MAX_ID_MAP_LINES_340).expect("lines"))
                .map(|i| IdRange {
                    container_id: i * 9_000_000,
                    host_id: host_base + i * 9_000_000,
                    count: 9_000_000 - 1,
                })
                .collect()
        };
        let uid = IdMap::new(lines(1_000_000_000)).expect("uid map");
        let gid = IdMap::new(lines(1_000_000_001)).expect("gid map");
        assert_eq!(uid.lines().len(), MAX_ID_MAP_LINES_340);
        let options = ExtractOptions::new()
            .with_ownership(OwnershipPolicy::ChownMapped { uid, gid })
            .with_special_bits(SpecialBitsPolicy::PreserveIfOwnerMapped {
                uid: IdRange {
                    container_id: 4_000_000_000,
                    host_id: 4_000_000_000,
                    count: 294_967_295,
                },
                gid: IdRange {
                    container_id: 4_000_000_000,
                    host_id: 4_000_000_000,
                    count: 294_967_295,
                },
            });
        let config = Digest::parse(&format!("sha256:{}", "f".repeat(64))).expect("config digest");
        let settings = record_settings(&config, &options).expect("settings");
        let longest = LAYER_MEDIA_TYPES
            .iter()
            .map(|e| e.media_type.len())
            .max()
            .expect("media types");
        // `layer=` + `sha256:<64>` + ' ' + mediaType + '\n'
        let layers_len = MAX_LAYERS * (6 + 71 + 1 + longest + 1);
        let total = settings.len() + layers_len;
        assert!(
            (total as u64) <= MAX_RECORD_BYTES,
            "worst-case record is {total} bytes (limit {MAX_RECORD_BYTES})"
        );
        // 具体値での余裕の確認: 設定だけで 40 KiB を超えない見積もり（上限 64 KiB の 2/3 以下）。
        assert!(total < 44_000, "worst-case record is {total} bytes");
    }

    /// OCI-1・#2534: 書き込み側は上限を超える記録を、ファイルを作る前に `ResourceExhausted` で拒否する。
    #[test]
    fn oci1_write_unpack_record_rejects_oversized_record_before_creating_it() {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-cri-record-size-{}-{}",
            std::process::id(),
            STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(RECORD_FILE);
        let record = UnpackRecord {
            settings: "s".repeat(MAX_RECORD_BYTES as usize),
            layers: "l".to_owned(),
        };
        let err = write_unpack_record(&path, &record).expect_err("oversized");
        assert_eq!(
            err,
            PullError::new(
                OciErrorCode::ResourceExhausted,
                "image rootfs unpack record exceeds the size limit"
            )
        );
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    fn record_test_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-cri-record-{tag}-{}-{}",
            std::process::id(),
            STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    /// OCI-1・REPAIR-5・#2796: 本文の書き込みが途中で失敗（ENOSPC 相当）したら作ったファイルを消す。
    #[test]
    fn oci1_repair5_write_unpack_record_removes_partial_file_on_write_failure() {
        use std::io::Write as _;
        let dir = record_test_dir("partial");
        let path = dir.join(RECORD_FILE);
        let record = UnpackRecord {
            settings: "settings".to_owned(),
            layers: "layers".to_owned(),
        };
        let err = write_unpack_record_with(&path, &record, &|f, r| {
            f.write_all(&r.settings.as_bytes()[..3])?;
            Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
        })
        .expect_err("write failure");
        assert_eq!(
            err,
            PullError::new(
                OciErrorCode::FailedPrecondition,
                "failed to record the image rootfs unpack settings"
            )
        );
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// OCI-1・REPAIR-5・#2796: 全部書いた後の `sync_all` 相当の失敗でもファイルを残さない。
    #[test]
    fn oci1_repair5_write_unpack_record_removes_file_on_sync_failure() {
        use std::io::Write as _;
        let dir = record_test_dir("sync");
        let path = dir.join(RECORD_FILE);
        let record = UnpackRecord {
            settings: "settings".to_owned(),
            layers: "layers".to_owned(),
        };
        let err = write_unpack_record_with(&path, &record, &|f, r| {
            f.write_all(r.settings.as_bytes())?;
            f.write_all(r.layers.as_bytes())?;
            Err(std::io::Error::from(std::io::ErrorKind::Other))
        })
        .expect_err("sync failure");
        assert_eq!(err.code(), OciErrorCode::FailedPrecondition);
        assert!(!path.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// OCI-1・#2796: 成功時は settings + layers をその順で書き、unix では 0600 になる。
    #[test]
    fn oci1_write_unpack_record_writes_settings_then_layers() {
        let dir = record_test_dir("ok");
        let path = dir.join(RECORD_FILE);
        let record = UnpackRecord {
            settings: "settings".to_owned(),
            layers: "layers".to_owned(),
        };
        write_unpack_record(&path, &record).expect("write");
        assert_eq!(fs::read(&path).expect("read"), b"settingslayers");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}

/// 実ファイルでの blob の信頼条件の試験（Unix。所有者の不一致は、基準側の `owner` をずらして再現する）。
#[cfg(all(test, unix))]
mod blob_trust_fs_tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    /// `abc` の sha256。
    const ABC: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "fandhe-cri-blob-trust-{tag}-{}-{}",
                std::process::id(),
                STAGING_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("mkdir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn abc() -> Digest {
        Digest::parse(ABC).expect("digest")
    }

    /// 内容 `abc`・権限 `mode` のファイルを作り、パスと実際の所有者 UID を返す。
    fn blob_with_mode(dir: &TempDir, name: &str, mode: u32) -> (PathBuf, u32) {
        let path = dir.0.join(name);
        fs::write(&path, b"abc").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
        let uid = fs::metadata(&path).expect("stat").uid();
        (path, uid)
    }

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).expect("stat").mode() & 0o777
    }

    /// OCI-1・SEC: 所有者専用・リンク数 1・内容一致の既存 blob は再利用でき、検査はファイルを変えない。
    #[test]
    fn sec_cached_blob_is_reusable_when_trusted_and_verified() {
        let dir = TempDir::new("ok");
        let (path, uid) = blob_with_mode(&dir, "blob", 0o600);
        assert_eq!(inspect_cached_blob(&path, &abc(), 3, uid), Ok(()));
        let (readable, _) = blob_with_mode(&dir, "readable", 0o644);
        assert_eq!(inspect_cached_blob(&readable, &abc(), 3, uid), Ok(()));
        assert_eq!(mode_of(&readable), 0o644);
        assert_eq!(fs::read(&path).expect("read"), b"abc");
    }

    /// OCI-1・SEC: 内容が正しくても、所有者が基準と異なる blob は再利用しない。
    #[test]
    fn sec_cached_blob_with_unexpected_owner_is_not_reused() {
        let dir = TempDir::new("owner");
        let (path, uid) = blob_with_mode(&dir, "blob", 0o600);
        let other = uid.wrapping_add(1);
        assert_eq!(
            inspect_cached_blob(&path, &abc(), 3, other),
            Err(CachedBlobRejection::Untrusted(
                BlobTrustViolation::UnexpectedOwner
            ))
        );
    }

    /// OCI-1・SEC: 内容が正しくても、group / other 書き込み可の blob は再利用しない。
    #[test]
    fn sec_cached_blob_writable_by_others_is_not_reused() {
        let dir = TempDir::new("mode");
        for mode in [0o620, 0o602, 0o664, 0o666] {
            let (path, uid) = blob_with_mode(&dir, &format!("blob-{mode:o}"), mode);
            assert_eq!(
                inspect_cached_blob(&path, &abc(), 3, uid),
                Err(CachedBlobRejection::Untrusted(
                    BlobTrustViolation::WritableByOthers
                )),
                "mode {mode:o}"
            );
            assert_eq!(mode_of(&path), mode, "inspection must not change the file");
        }
    }

    /// OCI-1・SEC: 内容が正しくても、別の名前からハードリンクされた blob（リンク数 2）は再利用しない。
    #[test]
    fn sec_cached_blob_with_extra_hard_link_is_not_reused() {
        let dir = TempDir::new("link");
        let (path, uid) = blob_with_mode(&dir, "blob", 0o600);
        fs::hard_link(&path, dir.0.join("alias")).expect("link");
        assert_eq!(fs::metadata(&path).expect("stat").nlink(), 2);
        assert_eq!(
            inspect_cached_blob(&path, &abc(), 3, uid),
            Err(CachedBlobRejection::Untrusted(
                BlobTrustViolation::UnexpectedLinkCount
            ))
        );
        // リンクを外せば（リンク数 1）再利用できる。
        fs::remove_file(dir.0.join("alias")).expect("unlink");
        assert_eq!(inspect_cached_blob(&path, &abc(), 3, uid), Ok(()));
    }

    /// OCI-1・SEC: symlink（先が信頼条件を満たす正しい blob でも）・ディレクトリ・未存在は開かずに再利用しない。
    #[test]
    fn sec_cached_blob_symlink_and_non_regular_are_not_reused() {
        let dir = TempDir::new("symlink");
        let (target, uid) = blob_with_mode(&dir, "target", 0o600);
        let link = dir.0.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert_eq!(
            inspect_cached_blob(&link, &abc(), 3, uid),
            Err(CachedBlobRejection::Unopenable)
        );
        assert_eq!(
            inspect_cached_blob(&dir.0, &abc(), 3, uid),
            Err(CachedBlobRejection::Unopenable)
        );
        assert_eq!(
            inspect_cached_blob(&dir.0.join("missing"), &abc(), 3, uid),
            Err(CachedBlobRejection::Unopenable)
        );
    }

    /// OCI-1: 信頼条件を満たしても、内容の digest・サイズが descriptor と一致しなければ再利用しない。
    #[test]
    fn oci1_cached_blob_with_wrong_content_or_size_is_not_reused() {
        let dir = TempDir::new("content");
        let (path, uid) = blob_with_mode(&dir, "blob", 0o600);
        // 宣言サイズが実サイズより大きい（読み取り上限としては通るが完全一致しない）。
        assert_eq!(
            inspect_cached_blob(&path, &abc(), 5, uid),
            Err(CachedBlobRejection::ContentMismatch)
        );
        // 宣言サイズが実サイズより小さい。
        assert_eq!(
            inspect_cached_blob(&path, &abc(), 2, uid),
            Err(CachedBlobRejection::ContentMismatch)
        );
        fs::write(&path, b"xyz").expect("corrupt");
        assert_eq!(
            inspect_cached_blob(&path, &abc(), 3, uid),
            Err(CachedBlobRejection::ContentMismatch)
        );
    }

    /// `{"rootfs":{"type":"layers","diff_ids":["sha256:<'a' x 64>"]}}`（115 バイト）。
    fn config_body(fill: char) -> Vec<u8> {
        let hex: String = std::iter::repeat_n(fill, 64).collect();
        format!(r#"{{"rootfs":{{"type":"layers","diff_ids":["sha256:{hex}"]}}}}"#).into_bytes()
    }

    /// `config_body('a')` の sha256（本文を書き出して `sha256sum` で求めた値）。
    const CONFIG_A_SHA256: &str =
        "sha256:92f01abd265e7d9faebfd85bfe110b4679fe209dec7826de52ae830cdcb0be6d";

    /// config の descriptor を manifest の解析経由で作る（`Descriptor` は外部 crate から直接組めない）。
    fn config_descriptor(digest: &str, size: usize) -> Descriptor {
        let layer = "1".repeat(64);
        let manifest = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{digest}","size":{size}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:{layer}","size":1}}]}}"#
        );
        match fandhe_container_oci::manifest::parse_manifest(manifest.as_bytes(), None)
            .expect("manifest")
        {
            fandhe_container_oci::manifest::ParsedManifest::Image(m) => m.config,
            _ => panic!("expected an image manifest"),
        }
    }

    /// OCI-1・SEC-5・#2534: 検証済みの config は 1 回の読み取りで解析され、`diff_ids` が具体値で返る。
    #[test]
    fn oci1_sec_config_is_parsed_from_the_hashed_bytes() {
        let dir = TempDir::new("cfg-ok");
        let path = dir.0.join("config");
        fs::write(&path, config_body('a')).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let uid = fs::metadata(&path).expect("stat").uid();
        let descriptor = config_descriptor(CONFIG_A_SHA256, 115);
        let root = read_verified_config(&path, &descriptor, uid, DEFAULT_MAX_CONFIG_BYTES)
            .expect("config");
        let ids: Vec<&str> = root.diff_ids().iter().map(Digest::as_str).collect();
        assert_eq!(ids, [format!("sha256:{}", "a".repeat(64))]);
    }

    /// OCI-1・SEC-5・#2534: 信頼確認の後・本文を読む直前に同じ inode を書き換えられても、読んだ本文のハッシュが
    /// descriptor と合わず `DataLoss` になる（書き換え後の `diff_ids` を解析しない）。ハッシュ後に読み直す実装へ
    /// 戻すと、この試験が書き換え後の値を `Ok` で返して落ちる。
    #[test]
    fn oci1_sec_config_rewritten_in_place_after_trust_check_is_rejected() {
        use std::io::Write as _;
        let dir = TempDir::new("cfg-rewrite");
        let path = dir.0.join("config");
        fs::write(&path, config_body('a')).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let meta = fs::metadata(&path).expect("stat");
        let (uid, ino) = (meta.uid(), meta.ino());
        let descriptor = config_descriptor(CONFIG_A_SHA256, 115);
        let rewrite = || {
            // 同じ inode を 0 から書き直す（rename ではなく in-place の上書き）。長さは同じ 115 バイト。
            let mut f = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .expect("reopen");
            f.write_all(&config_body('b')).expect("rewrite");
            assert_eq!(fs::metadata(&path).expect("stat").ino(), ino);
        };
        let err =
            read_verified_config_inner(&path, &descriptor, uid, DEFAULT_MAX_CONFIG_BYTES, &rewrite)
                .expect_err("rewritten config must be rejected");
        assert_eq!(
            err,
            PullError::new(OciErrorCode::DataLoss, "image config failed validation")
        );
    }

    /// OCI-1・#2534: 長さが descriptor の size と違う config は、ハッシュ以前に `DataLoss` で拒否する。
    #[test]
    fn oci1_config_with_wrong_length_is_rejected() {
        let dir = TempDir::new("cfg-len");
        let path = dir.0.join("config");
        fs::write(&path, config_body('a')).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let uid = fs::metadata(&path).expect("stat").uid();
        let descriptor = config_descriptor(CONFIG_A_SHA256, 114);
        let err = read_verified_config(&path, &descriptor, uid, DEFAULT_MAX_CONFIG_BYTES)
            .expect_err("length mismatch");
        assert_eq!(
            err,
            PullError::new(OciErrorCode::DataLoss, "image config failed validation")
        );
    }
}

/// エラー写像の単体試験（#2323・OCI-1・ERR-3）。
#[cfg(test)]
mod extract_cleanup_tests {
    use super::*;

    /// ERR-3: 展開・config の失敗は分類を引き継ぎ、文言は分類ごとの固定の英語になる。
    #[test]
    fn err3_extract_and_config_errors_have_fixed_messages() {
        let secret = "layer entry etc/shadow at /var/lib/secret";
        let extract = [
            (OciErrorCode::DataLoss, "image layer failed validation"),
            (
                OciErrorCode::ResourceExhausted,
                "image layer exceeds the extraction limit",
            ),
            (
                OciErrorCode::Unimplemented,
                "unsupported image layer format",
            ),
            (
                OciErrorCode::InvalidArgument,
                "image layer contains an invalid entry",
            ),
            (
                OciErrorCode::PermissionDenied,
                "image layer entry is not permitted",
            ),
            (
                OciErrorCode::NotFound,
                "image layer references a missing entry",
            ),
            (
                OciErrorCode::FailedPrecondition,
                "image rootfs precondition failed",
            ),
            (
                OciErrorCode::AlreadyExists,
                "image layer has conflicting entries",
            ),
            (OciErrorCode::Internal, "image layer extraction failed"),
        ];
        for (code, message) in extract {
            let e = PullError::from_extract(&OciError::new(code, secret));
            assert_eq!(e.code(), code);
            assert_eq!(e.message(), message);
        }
        let config = [
            (OciErrorCode::DataLoss, "image config failed validation"),
            (
                OciErrorCode::ResourceExhausted,
                "image config exceeds the size limit",
            ),
            (OciErrorCode::Unimplemented, "unsupported image config"),
            (OciErrorCode::NotFound, "image config could not be read"),
        ];
        for (code, message) in config {
            let e = PullError::from_config(&OciError::new(code, secret));
            assert_eq!(e.code(), code);
            assert_eq!(e.message(), message);
        }
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

    /// SEC・OCI-1: 非 Unix では blob の所有者・権限を確認できないため、既存 blob を再利用せず、公開もしない。
    #[test]
    fn sec_blobs_are_neither_reused_nor_published_without_metadata() {
        let dir = std::env::temp_dir().join(format!("fandhe-cri-blob-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("blob");
        fs::write(&path, b"abc").expect("write");
        let digest = Digest::parse(
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .expect("digest");
        assert_eq!(
            inspect_cached_blob(&path, &digest, 3, 0),
            Err(CachedBlobRejection::Unopenable)
        );
        let file = fs::File::open(&path).expect("open");
        assert_eq!(BlobFileFacts::from_file(&file), None);
        let _ = fs::remove_dir_all(&dir);
    }
}
