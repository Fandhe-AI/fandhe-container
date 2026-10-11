//! `ImageService` の CRI 実装の雛形と `ListImages`（TASK-61.1・#444・CRI-4・ERR-3・REPAIR-4）。
//!
//! `fandhe-container-plugin-cri`（TASK-108）が `ImageServiceServer` で包んで gRPC に載せる実装の本体。
//! `crictl images` 相当の一覧を、ローカルキャッシュの抽象 [`ImageStore`] から返す。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - 実装済みなのは `ListImages` のみ。`ImageStatus`（TASK-61.2）・`PullImage`（TASK-61.3）・
//!   `RemoveImage`・`StreamImages`・`ImageFsInfo` は `Unimplemented` を返す
//! - [`InMemoryImageStore`] はプロセス内メモリのスタブ。永続キャッシュと oci の pull 経路
//!   （digest 検証つきの取り込み。OCI-1）への接続は TASK-61.3・TASK-183（OCI-7）で置き換える
//! - エラーの正規化（TASK-97.2）は未適用。リスナー・メッセージ長上限・UDS の権限と peer credential
//!   検証（PLUG-12）は plugin-cri（TASK-108）の責務
//!
//! # 機微情報
//!
//! 計装（[`crate::instrument`]）とエラー文言にイメージ名・タグ・digest を出さない（`.claude/rules/security.md`）。

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use tonic::codegen::tokio_stream::Empty;
use tonic::{Request, Response, Status};

use crate::instrument::{CriOpKind, CriOpRecorder, CriOpTimer, NoopCriOpRecorder};
use crate::runtime::v1::{self, image_service_server::ImageService};

/// ストアが保持するイメージ数の上限（無制限確保の防止）。
pub const MAX_IMAGES: usize = 4096;
/// イメージ ID・タグ・digest 1 件あたりの最大バイト数（OCI の参照は 255 文字程度が実用上限）。
pub const MAX_IMAGE_FIELD_BYTES: usize = 1024;
/// 1 イメージが持つ `repo_tags`・`repo_digests` のそれぞれの最大件数。
pub const MAX_REFS_PER_IMAGE: usize = 64;
/// `ListImages` のフィルタ文字列の最大バイト数。
pub const MAX_FILTER_BYTES: usize = MAX_IMAGE_FIELD_BYTES;
/// `username` の最大バイト数。
const MAX_USERNAME_BYTES: usize = 256;

/// イメージストアの失敗（`#[non_exhaustive]`。文言は固定の英語で、入力値を含めない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImageStoreError {
    /// イメージ ID が空。
    EmptyId,
    /// `size` が 0（proto の「Must be > 0」）。
    ZeroSize,
    /// フィールドの長さが [`MAX_IMAGE_FIELD_BYTES`] などの上限を超えた。
    FieldTooLong,
    /// `repo_tags` / `repo_digests` の件数が [`MAX_REFS_PER_IMAGE`] を超えた。
    TooManyRefs,
    /// ストアの件数が [`MAX_IMAGES`] に達している。
    StoreFull,
    /// `uid` と非空の `username` が同時に指定された（proto の `Image.uid` / `username` は排他）。
    ConflictingUser,
    /// 内部状態の破損（ロックの毒化）。
    Poisoned,
}

impl fmt::Display for ImageStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ImageStoreError::EmptyId => "image id must not be empty",
            ImageStoreError::ZeroSize => "image size must be greater than zero",
            ImageStoreError::FieldTooLong => "image field exceeds the length limit",
            ImageStoreError::TooManyRefs => "image has too many references",
            ImageStoreError::StoreFull => "image store is full",
            ImageStoreError::ConflictingUser => "image uid and username are mutually exclusive",
            ImageStoreError::Poisoned => "image store is unavailable",
        })
    }
}

impl std::error::Error for ImageStoreError {}

/// ローカルキャッシュ上の 1 イメージ。[`ImageRecord::new`] で検証済みの値だけが存在する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRecord {
    id: String,
    repo_tags: Vec<String>,
    repo_digests: Vec<String>,
    size: u64,
    uid: Option<i64>,
    username: String,
    pinned: bool,
}

impl ImageRecord {
    /// 検証してレコードを作る（id 非空・size > 0・長さと件数の上限）。
    pub fn new(
        id: impl Into<String>,
        repo_tags: Vec<String>,
        repo_digests: Vec<String>,
        size: u64,
    ) -> Result<Self, ImageStoreError> {
        let id = id.into();
        if id.is_empty() {
            return Err(ImageStoreError::EmptyId);
        }
        if size == 0 {
            return Err(ImageStoreError::ZeroSize);
        }
        if repo_tags.len() > MAX_REFS_PER_IMAGE || repo_digests.len() > MAX_REFS_PER_IMAGE {
            return Err(ImageStoreError::TooManyRefs);
        }
        let too_long = |s: &String| s.len() > MAX_IMAGE_FIELD_BYTES;
        if too_long(&id) || repo_tags.iter().any(too_long) || repo_digests.iter().any(too_long) {
            return Err(ImageStoreError::FieldTooLong);
        }
        Ok(Self {
            id,
            repo_tags,
            repo_digests,
            size,
            uid: None,
            username: String::new(),
            pinned: false,
        })
    }

    /// 既定ユーザー（uid / username）を設定する。username が長すぎる場合、および
    /// uid と非空 username の同時指定（proto で mutually exclusive）は拒否する。
    pub fn with_user(mut self, uid: Option<i64>, username: &str) -> Result<Self, ImageStoreError> {
        if uid.is_some() && !username.is_empty() {
            return Err(ImageStoreError::ConflictingUser);
        }
        if username.len() > MAX_USERNAME_BYTES {
            return Err(ImageStoreError::FieldTooLong);
        }
        self.uid = uid;
        self.username = username.to_owned();
        Ok(self)
    }

    /// pinned フラグを設定する（GC 対象外の印）。
    pub fn with_pinned(mut self, pinned: bool) -> Self {
        self.pinned = pinned;
        self
    }

    /// イメージ ID。
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 絞り込みの完全一致判定（id・タグ・digest のいずれか。`sha256:` 無しの 16 進だけの指定は id にも一致）。
    fn matches(&self, wanted: &str) -> bool {
        self.id == wanted
            || self.id.strip_prefix("sha256:") == Some(wanted)
            || self.repo_tags.iter().any(|t| t == wanted)
            || self.repo_digests.iter().any(|d| d == wanted)
    }

    /// CRI の `Image` へ変換する。`spec.image` には ID を入れる（`ImageStatus`・`PullImage` の参照と揃える）。
    fn to_proto(&self) -> v1::Image {
        v1::Image {
            id: self.id.clone(),
            repo_tags: self.repo_tags.clone(),
            repo_digests: self.repo_digests.clone(),
            size: self.size,
            uid: self.uid.map(|value| v1::Int64Value { value }),
            username: self.username.clone(),
            spec: Some(v1::ImageSpec {
                image: self.id.clone(),
                ..Default::default()
            }),
            pinned: self.pinned,
        }
    }
}

/// ローカルイメージキャッシュの読み取り境界（CRI-4）。
///
/// `ImageStatus`（TASK-61.2）が `get` を足す。契約: 有界時間で戻ること（REPAIR-5）。
pub trait ImageStore: Send + Sync {
    /// 全イメージを ID 昇順で返す。
    fn list(&self) -> Result<Vec<ImageRecord>, ImageStoreError>;
}

/// プロセス内メモリのスタブ実装（REPAIR-3。永続キャッシュは TASK-61.3・TASK-183 で置換）。
#[derive(Debug, Default)]
pub struct InMemoryImageStore {
    images: Mutex<BTreeMap<String, ImageRecord>>,
}

impl InMemoryImageStore {
    /// 空のストアを作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// レコードを追加する（同一 ID は置換）。新規 ID で [`MAX_IMAGES`] を超えるなら拒否する。
    pub fn insert(&self, record: ImageRecord) -> Result<(), ImageStoreError> {
        let mut images = self.images.lock().map_err(|_| ImageStoreError::Poisoned)?;
        if !images.contains_key(record.id()) && images.len() >= MAX_IMAGES {
            return Err(ImageStoreError::StoreFull);
        }
        images.insert(record.id.clone(), record);
        Ok(())
    }

    /// 保持件数。
    pub fn len(&self) -> usize {
        self.images.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// 空かどうか。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ImageStore for InMemoryImageStore {
    fn list(&self) -> Result<Vec<ImageRecord>, ImageStoreError> {
        let images = self.images.lock().map_err(|_| ImageStoreError::Poisoned)?;
        Ok(images.values().cloned().collect())
    }
}

/// `ImageService` の実装（現状 `ListImages` のみ。TASK-61.1）。
pub struct CriImageService {
    store: Arc<dyn ImageStore>,
    recorder: Arc<dyn CriOpRecorder>,
}

impl CriImageService {
    /// 空のメモリストア・計測なしで作る。
    pub fn new() -> Self {
        Self::with_store_and_recorder(
            Arc::new(InMemoryImageStore::new()),
            Arc::new(NoopCriOpRecorder),
        )
    }

    /// ストアを指定して作る（計測なし）。
    pub fn with_store(store: Arc<dyn ImageStore>) -> Self {
        Self::with_store_and_recorder(store, Arc::new(NoopCriOpRecorder))
    }

    /// 記録先を指定して作る（空のメモリストア）。
    pub fn with_recorder(recorder: Arc<dyn CriOpRecorder>) -> Self {
        Self::with_store_and_recorder(Arc::new(InMemoryImageStore::new()), recorder)
    }

    /// ストアと記録先を指定して作る。
    pub fn with_store_and_recorder(
        store: Arc<dyn ImageStore>,
        recorder: Arc<dyn CriOpRecorder>,
    ) -> Self {
        Self { store, recorder }
    }

    /// `ListImages` の本体。フィルタ検証 → ストア読み取り → 絞り込み。
    fn list(&self, request: v1::ListImagesRequest) -> Result<v1::ListImagesResponse, Status> {
        let wanted = request
            .filter
            .and_then(|f| f.image)
            .map(|spec| spec.image)
            .unwrap_or_default();
        if wanted.len() > MAX_FILTER_BYTES {
            return Err(Status::invalid_argument("image filter is too long"));
        }
        let records = self
            .store
            .list()
            .map_err(|_| Status::internal("image store failure"))?;
        let images = records
            .iter()
            .filter(|r| wanted.is_empty() || r.matches(&wanted))
            .map(ImageRecord::to_proto)
            .collect();
        Ok(v1::ListImagesResponse { images })
    }
}

impl Default for CriImageService {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CriImageService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CriImageService").finish_non_exhaustive()
    }
}

#[tonic::async_trait]
impl ImageService for CriImageService {
    type StreamImagesStream = Empty<Result<v1::StreamImagesResponse, Status>>;

    /// ローカルキャッシュのイメージを ID 昇順で返す（絞り込みは完全一致。CRI-4・TASK-61.1）。
    async fn list_images(
        &self,
        request: Request<v1::ListImagesRequest>,
    ) -> Result<Response<v1::ListImagesResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::ListImages);
        let result = self.list(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
    }

    async fn stream_images(
        &self,
        _request: Request<v1::StreamImagesRequest>,
    ) -> Result<Response<Self::StreamImagesStream>, Status> {
        Err(Status::unimplemented("stream_images"))
    }

    // 以降は TASK-61.2（ImageStatus）・TASK-61.3（PullImage）などで順次実装する（REPAIR-3）。
    async fn image_status(
        &self,
        _request: Request<v1::ImageStatusRequest>,
    ) -> Result<Response<v1::ImageStatusResponse>, Status> {
        Err(Status::unimplemented("image_status"))
    }

    async fn pull_image(
        &self,
        _request: Request<v1::PullImageRequest>,
    ) -> Result<Response<v1::PullImageResponse>, Status> {
        Err(Status::unimplemented("pull_image"))
    }

    async fn remove_image(
        &self,
        _request: Request<v1::RemoveImageRequest>,
    ) -> Result<Response<v1::RemoveImageResponse>, Status> {
        Err(Status::unimplemented("remove_image"))
    }

    async fn image_fs_info(
        &self,
        _request: Request<v1::ImageFsInfoRequest>,
    ) -> Result<Response<v1::ImageFsInfoResponse>, Status> {
        Err(Status::unimplemented("image_fs_info"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instrument::CriOpOutcome;
    use crate::instrument::testing::Collect;
    use tonic::Code;

    fn rec(id: &str, tag: &str, digest: &str, size: u64) -> ImageRecord {
        ImageRecord::new(id, vec![tag.into()], vec![digest.into()], size).expect("valid record")
    }

    /// CRI-4: 不正なレコードは作れない。
    #[test]
    fn cri4_record_validation() {
        assert_eq!(
            ImageRecord::new("", vec![], vec![], 1),
            Err(ImageStoreError::EmptyId)
        );
        assert_eq!(
            ImageRecord::new("a", vec![], vec![], 0),
            Err(ImageStoreError::ZeroSize)
        );
        let long = "x".repeat(MAX_IMAGE_FIELD_BYTES + 1);
        assert_eq!(
            ImageRecord::new(long, vec![], vec![], 1),
            Err(ImageStoreError::FieldTooLong)
        );
        let tags = vec!["t".to_owned(); MAX_REFS_PER_IMAGE + 1];
        assert_eq!(
            ImageRecord::new("a", tags, vec![], 1),
            Err(ImageStoreError::TooManyRefs)
        );
    }

    /// CRI-4: uid と username の同時指定は拒否する（api.proto の排他契約）。
    #[test]
    fn cri4_user_uid_and_username_are_exclusive() {
        let base = || rec("a", "t", "d", 1);
        assert_eq!(
            base().with_user(Some(1000), "app").err(),
            Some(ImageStoreError::ConflictingUser)
        );
        assert!(base().with_user(Some(1000), "").is_ok());
        assert!(base().with_user(None, "app").is_ok());
    }

    /// CRI-4: ストアの件数上限。同一 ID の置換は上限に達していても許可する。
    #[test]
    fn cri4_store_capacity() {
        let store = InMemoryImageStore::new();
        for i in 0..MAX_IMAGES {
            store.insert(rec(&format!("id{i}"), "t", "d", 1)).unwrap();
        }
        assert_eq!(store.len(), MAX_IMAGES);
        assert_eq!(
            store.insert(rec("extra", "t", "d", 1)),
            Err(ImageStoreError::StoreFull)
        );
        assert_eq!(store.insert(rec("id0", "t2", "d", 2)), Ok(()));
        assert_eq!(store.len(), MAX_IMAGES);
    }

    struct Failing;
    impl ImageStore for Failing {
        fn list(&self) -> Result<Vec<ImageRecord>, ImageStoreError> {
            Err(ImageStoreError::Poisoned)
        }
    }

    /// CRI-4・REPAIR-4: ストア失敗は INTERNAL（内部詳細を含まない）で、失敗として記録される。
    #[test]
    fn cri4_store_failure_is_internal_and_recorded() {
        let c = Arc::new(Collect::default());
        let svc = CriImageService::with_store_and_recorder(Arc::new(Failing), c.clone());
        let err = svc
            .list(v1::ListImagesRequest::default())
            .expect_err("must fail");
        assert_eq!(err.code(), Code::Internal);
        assert_eq!(err.message(), "image store failure");
        let result: Result<(), Status> = Err(err);
        CriOpTimer::start(c.as_ref(), CriOpKind::ListImages).finish_with(&result);
        assert_eq!(
            c.outcomes(),
            vec![(CriOpKind::ListImages, CriOpOutcome::Failure, Code::Internal)]
        );
    }

    /// CRI-4: フィルタが長すぎれば INVALID_ARGUMENT（ERR-3）。
    #[test]
    fn cri4_oversized_filter_is_invalid_argument() {
        let svc = CriImageService::new();
        let req = v1::ListImagesRequest {
            filter: Some(v1::ImageFilter {
                image: Some(v1::ImageSpec {
                    image: "x".repeat(MAX_FILTER_BYTES + 1),
                    ..Default::default()
                }),
            }),
        };
        let err = svc.list(req).expect_err("must fail");
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    /// CRI-4: `sha256:` 無しの 16 進指定も ID に一致する。
    #[test]
    fn cri4_match_accepts_bare_hex_id() {
        let r = rec(
            "sha256:abc123",
            "docker.io/library/a:1",
            "docker.io/library/a@sha256:abc123",
            1,
        );
        assert!(r.matches("abc123"));
        assert!(r.matches("sha256:abc123"));
        assert!(r.matches("docker.io/library/a:1"));
        assert!(!r.matches("abc"));
    }
}
