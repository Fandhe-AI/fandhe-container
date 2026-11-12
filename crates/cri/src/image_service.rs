//! `ImageService` の CRI 実装の雛形と `ListImages`・`ImageStatus`（TASK-61.1・61.2・#444・#445・CRI-4・ERR-3・REPAIR-4）。
//!
//! `fandhe-container-plugin-cri`（TASK-108）が `ImageServiceServer` で包んで gRPC に載せる実装の本体。
//! `crictl images` 相当の一覧を、ローカルキャッシュの抽象 [`ImageStore`] から返す。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - 実装済みなのは `ListImages`・`ImageStatus`・`PullImage`（TASK-61.3）・`RemoveImage`（#4177。在庫の記録を
//!   外すだけで、blob・展開済み rootfs は消さない。回収は #471 系）。`StreamImages`・
//!   `ImageFsInfo` は `Unimplemented` を返す。`PullImage` は [`ImagePuller`] を注入されたときだけ動き、
//!   未設定なら従来どおり `Unimplemented`。取り込み手順と限界は [`crate::image_pull`] を参照。RPC が期限切れ・
//!   取り消しで破棄されたときは番人が旗を立て、worker は次の確認点で止まる（#2967・REPAIR-5）
//! - `PullImage` の `sandbox_config` は無視する（Pod 単位の pull 文脈は未対応）。同時 pull 数は
//!   [`DEFAULT_MAX_CONCURRENT_PULLS`] で制限する（blocking プールの枯渇防止。REPAIR-5）
//! - `ImageStatus` の `verbose` 拡張情報（`info`）は未実装で常に空。OCI image config 由来の情報は
//!   TASK-183（OCI-7）で追加する。取り込み時の digest 検証（OCI-1）は PullImage の責務で、
//!   本 RPC は読み取りのみ
//! - [`InMemoryImageStore`] はプロセス内メモリの実装で、試験・注入用。本番の永続実装は plugin-cri の
//!   `PersistentImageStore`（oci の ImageStore の root 直下へ記録を保存する。形式は [`encode_image_records`]。#4176）。
//!   展開後サイズの算出は TASK-183（OCI-7）
//! - 失敗は `CriError`（ERR-3。`crate::error`）で組み立て、トレイトの境界で `Status` へ変換する（TASK-97.2・#450）
//! - リスナー・メッセージ長上限・UDS の権限と peer credential
//!   検証（PLUG-12）は plugin-cri（TASK-108）の責務
//!
//! # 機微情報
//!
//! 計装（[`crate::instrument`]）とエラー文言にイメージ名・タグ・digest を出さない（`.claude/rules/security.md`）。

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tonic::codegen::tokio_stream::Empty;
use tonic::{Request, Response, Status};

use crate::error::CriError;
use crate::image_pull::{
    ImagePuller, PullRequest, canonical_reference, credentials_from_auth_config,
};
use crate::instrument::{CriOpKind, CriOpRecorder, CriOpTimer, NoopCriOpRecorder};
use crate::runtime::v1::{self, image_service_server::ImageService};

mod persist;
pub use persist::{MAX_IMAGE_RECORDS_FILE_BYTES, decode_image_records, encode_image_records};

/// ストアが保持するイメージ数の上限（無制限確保の防止）。
pub const MAX_IMAGES: usize = 4096;
/// イメージ ID・タグ・digest 1 件あたりの最大バイト数（OCI の参照は 255 文字程度が実用上限）。
pub const MAX_IMAGE_FIELD_BYTES: usize = 1024;
/// 1 イメージが持つ `repo_tags`・`repo_digests` のそれぞれの最大件数。
pub const MAX_REFS_PER_IMAGE: usize = 64;
/// `ListImages` のフィルタ文字列の最大バイト数。
pub const MAX_FILTER_BYTES: usize = MAX_IMAGE_FIELD_BYTES;
/// 同時に実行できる `PullImage` 数の既定上限（超過は `RESOURCE_EXHAUSTED`。blocking プールの枯渇防止）。
pub const DEFAULT_MAX_CONCURRENT_PULLS: usize = 4;

/// 同時 `RemoveImage` 数の既定上限（blocking プールの枯渇防止。共有 OCI ロックを最大 5 秒待つため。REPAIR-5）。
pub const DEFAULT_MAX_CONCURRENT_REMOVES: usize = 4;
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
    /// このストアは書き込みに対応していない（`upsert` 未実装の実装）。
    ReadOnly,
    /// 永続された在庫記録が壊れている・検証に反する（空の在庫として扱わない。#4176）。
    Corrupt,
    /// 永続された在庫記録の読み書きに失敗した（#4176）。
    Io,
    /// イメージをコンテナが使用中で、記録を外せない（`RemoveImage` が `FAILED_PRECONDITION` に写す。OCI-7・#2791）。
    InUse,
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
            ImageStoreError::ReadOnly => "image store is read-only",
            ImageStoreError::Corrupt => "image store data is corrupt",
            ImageStoreError::Io => "image store i/o failed",
            ImageStoreError::InUse => "image is in use by a container",
        })
    }
}

impl std::error::Error for ImageStoreError {}

/// ローカルキャッシュ上の 1 イメージ。[`ImageRecord::new`] で検証済みの値だけが存在する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRecord {
    id: String,
    repo_tags: Vec<String>,
    /// 先頭 `top_level_len` 件が top-level digest、残りが補助（プラットフォーム manifest）digest。各区間は辞書順。
    repo_digests: Vec<String>,
    top_level_len: usize,
    size: u64,
    uid: Option<i64>,
    username: String,
    pinned: bool,
}

/// 重複を除いて辞書順（バイト順）に並べる。containerd の `docker.Sort` と同じ結果になる
/// （前提: 正規化済みの Named 参照で、配列内の rank が揃っていること。distribution/reference v0.6.0 `sort.go`）。
fn sort_dedup(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items.dedup();
    items
}

impl ImageRecord {
    /// 検証してレコードを作る（id 非空・size > 0・長さと件数の上限）。
    ///
    /// `repo_digests` の先頭 1 件を top-level digest、残りを補助 digest として扱う（`PulledImage` と同じ契約）。
    /// 並びは containerd と同じ辞書順（#3038・CRI-2・OCI-1）。
    pub fn new(
        id: impl Into<String>,
        repo_tags: Vec<String>,
        repo_digests: Vec<String>,
        size: u64,
    ) -> Result<Self, ImageStoreError> {
        let mut iter = repo_digests.into_iter();
        let top: Vec<String> = iter.next().into_iter().collect();
        Self::from_parts(id, repo_tags, top, iter.collect(), size)
    }

    /// top-level digest 群と補助 digest 群を分けて受けて作る。永続在庫（#2945）が統合後の複数の
    /// top-level digest を失わずに読み戻すための入口。検証は [`ImageRecord::new`] と同じ。
    pub fn from_parts(
        id: impl Into<String>,
        repo_tags: Vec<String>,
        top_level_digests: Vec<String>,
        auxiliary_digests: Vec<String>,
        size: u64,
    ) -> Result<Self, ImageStoreError> {
        let id = id.into();
        if id.is_empty() {
            return Err(ImageStoreError::EmptyId);
        }
        if size == 0 {
            return Err(ImageStoreError::ZeroSize);
        }
        if repo_tags.len() > MAX_REFS_PER_IMAGE
            || top_level_digests
                .len()
                .saturating_add(auxiliary_digests.len())
                > MAX_REFS_PER_IMAGE
        {
            return Err(ImageStoreError::TooManyRefs);
        }
        let too_long = |s: &String| s.len() > MAX_IMAGE_FIELD_BYTES;
        if too_long(&id)
            || repo_tags.iter().any(too_long)
            || top_level_digests.iter().any(too_long)
            || auxiliary_digests.iter().any(too_long)
        {
            return Err(ImageStoreError::FieldTooLong);
        }
        let mut digests = sort_dedup(top_level_digests);
        let top_level_len = digests.len();
        let auxiliary: Vec<String> = auxiliary_digests
            .into_iter()
            .filter(|d| !digests.contains(d))
            .collect();
        digests.extend(sort_dedup(auxiliary));
        Ok(Self {
            id,
            repo_tags: sort_dedup(repo_tags),
            repo_digests: digests,
            top_level_len,
            size,
            uid: None,
            username: String::new(),
            pinned: false,
        })
    }

    /// タグ参照（`<repo>:<tag>`）の一覧（#2901・CRI-2・OCI-1。ContainerStatus の `image` の元。先頭が `repoTags[0]`）。
    pub fn repo_tags(&self) -> &[String] {
        &self.repo_tags
    }

    /// digest 参照（`<repo>@sha256:<digest>`）の一覧（#2831。ContainerStatus の `image_ref` の元）。
    /// 先頭は top-level digest 群（multi-arch では index digest。辞書順で containerd と同じ。#2969・#3038・CRI-2・OCI-1）、
    /// 続けて補助のプラットフォーム manifest digest（辞書順）。
    pub fn repo_digests(&self) -> &[String] {
        &self.repo_digests
    }

    /// top-level digest 群（辞書順）。永続在庫（#2945）の保存用。
    pub fn top_level_digests(&self) -> &[String] {
        self.repo_digests.get(..self.top_level_len).unwrap_or(&[])
    }

    /// 補助のプラットフォーム manifest digest 群（辞書順）。永続在庫（#2945）の保存用。
    pub fn auxiliary_digests(&self) -> &[String] {
        self.repo_digests.get(self.top_level_len..).unwrap_or(&[])
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

    /// 同一 ID の既存レコード（`self`）へ新しい取り込み結果を統合する（タグ・digest は和集合、size は新しい値、
    /// uid・username・pinned は既存を保つ。タグと digest は containerd と同じ辞書順で、補助 digest が別の pull で
    /// top-level になれば top へ移す。#2969・#3038）。件数が [`MAX_REFS_PER_IMAGE`] を超えるなら `TooManyRefs`。
    fn merged_with(self, newer: ImageRecord) -> Result<Self, ImageStoreError> {
        let mut tags = self.repo_tags.clone();
        tags.extend(newer.repo_tags.iter().cloned());
        let mut top = self.top_level_digests().to_vec();
        top.extend(newer.top_level_digests().iter().cloned());
        let mut aux = self.auxiliary_digests().to_vec();
        aux.extend(newer.auxiliary_digests().iter().cloned());
        // 件数上限の検査は `from_parts` が重複除去より前に行うため、和集合に落としてから渡す
        // （上限近くの同内容の再 pull を誤って拒否しない）。
        tags.sort();
        tags.dedup();
        top.sort();
        top.dedup();
        aux.sort();
        aux.dedup();
        aux.retain(|d| !top.contains(d));
        let mut merged = Self::from_parts(self.id.clone(), tags, top, aux, newer.size)?;
        merged.uid = self.uid;
        merged.username = self.username;
        merged.pinned = self.pinned;
        Ok(merged)
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
/// 契約: 有界時間で戻ること（REPAIR-5）。
pub trait ImageStore: Send + Sync {
    /// 全イメージを ID 昇順で返す。
    fn list(&self) -> Result<Vec<ImageRecord>, ImageStoreError>;

    /// 参照（id・タグ・digest の完全一致。`ListImages` の絞り込みと同じ規則）を 1 件に解決する。
    ///
    /// 複数一致する場合は id 完全一致を優先し、なければ ID 昇順で最初の 1 件（決定的）。
    /// 未取得は `Ok(None)`（`ImageStatus` が `image: None` の成功応答に写す。TASK-61.2）。
    fn get(&self, reference: &str) -> Result<Option<ImageRecord>, ImageStoreError>;

    /// 取り込み結果を登録する（`PullImage`。TASK-61.3）。
    ///
    /// 同一 ID があればタグ・digest を統合し、他イメージが持つ同一タグは外す（タグは 1 イメージにだけ付く）。
    /// 既定実装は書き込み非対応で [`ImageStoreError::ReadOnly`] を返す。
    fn upsert(&self, _record: ImageRecord) -> Result<(), ImageStoreError> {
        Err(ImageStoreError::ReadOnly)
    }

    /// 参照（[`Self::get`] と同じ解決規則）に当たる 1 件を、全タグ・全 digest ごと在庫から外す（`RemoveImage`。#4177・CRI-1・CRI-2）。
    ///
    /// 解決と削除は store 自身の排他の下で行う（照会と削除の間に割り込ませない）。blob・展開済み rootfs は消さない
    /// （回収は #471 系）。該当が無ければ [`RemoveOutcome::Absent`]（冪等）。有界時間で戻ること（REPAIR-5）。
    /// 既定実装は書き込み非対応で [`ImageStoreError::ReadOnly`] を返す。
    fn remove(&self, _reference: &str) -> Result<RemoveOutcome, ImageStoreError> {
        Err(ImageStoreError::ReadOnly)
    }

    /// `reference` を外し、当たらなければ `canonical`（短縮名の正規化形）で外す（`RemoveImage`。#4177・CRI-4）。
    ///
    /// 永続在庫は 2 回の試行を 1 回の排他区間で行うよう上書きする（1 回目の `Absent` と 2 回目の間に
    /// `PullImage` が割り込み、新規 pull したイメージを消す窓を作らない）。既定実装は [`Self::remove`] を順に呼ぶ。
    fn remove_resolving(
        &self,
        reference: &str,
        canonical: Option<&str>,
    ) -> Result<RemoveOutcome, ImageStoreError> {
        match self.remove(reference)? {
            RemoveOutcome::Absent => match canonical {
                Some(c) if c != reference => self.remove(c),
                _ => Ok(RemoveOutcome::Absent),
            },
            outcome => Ok(outcome),
        }
    }
}

/// [`ImageStore::remove`] の結果（真偽値にせず、将来の拡張に備える。#4177）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemoveOutcome {
    /// 記録を外した（外した記録の ID）。
    Removed {
        /// 外したイメージ ID。
        id: String,
    },
    /// 該当する記録が無かった（`RemoveImage` では冪等の成功に写す）。
    Absent,
}

/// 参照を 1 件の ID に解決する（id 完全一致を優先し、なければ ID 昇順で最初の一致。`get` と `remove` が共有）。
fn resolve_id(images: &BTreeMap<String, ImageRecord>, reference: &str) -> Option<String> {
    if images.contains_key(reference) {
        return Some(reference.to_owned());
    }
    images
        .values()
        .find(|r| r.matches(reference))
        .map(|r| r.id.clone())
}

/// プロセス内メモリの実装（試験・注入用。本番の永続実装は plugin-cri の `PersistentImageStore`。#4176）。
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

    fn get(&self, reference: &str) -> Result<Option<ImageRecord>, ImageStoreError> {
        let images = self.images.lock().map_err(|_| ImageStoreError::Poisoned)?;
        Ok(resolve_id(&images, reference).and_then(|id| images.get(&id).cloned()))
    }

    fn remove(&self, reference: &str) -> Result<RemoveOutcome, ImageStoreError> {
        let mut images = self.images.lock().map_err(|_| ImageStoreError::Poisoned)?;
        Ok(match resolve_id(&images, reference) {
            Some(id) => {
                images.remove(&id);
                RemoveOutcome::Removed { id }
            }
            None => RemoveOutcome::Absent,
        })
    }

    fn upsert(&self, record: ImageRecord) -> Result<(), ImageStoreError> {
        let mut images = self.images.lock().map_err(|_| ImageStoreError::Poisoned)?;
        let merged = match images.get(record.id()) {
            Some(existing) => existing.clone().merged_with(record)?,
            None if images.len() >= MAX_IMAGES => return Err(ImageStoreError::StoreFull),
            None => record,
        };
        for (id, other) in images.iter_mut() {
            if id != merged.id() {
                other.repo_tags.retain(|t| !merged.repo_tags.contains(t));
            }
        }
        images.insert(merged.id.clone(), merged);
        Ok(())
    }
}

/// 参照で `f` を呼び、当たらなければ短縮名を PullImage と同じ規則で正規化して再度呼ぶ（CRI-4。`status` と `remove` が共有）。
fn resolve_with_canonical<T>(
    reference: &str,
    f: impl Fn(&str) -> Result<Option<T>, ImageStoreError>,
) -> Result<Option<T>, ImageStoreError> {
    let first = f(reference)?;
    if first.is_some() {
        return Ok(first);
    }
    match canonical_reference(reference) {
        Some(canonical) if canonical != reference => f(&canonical),
        _ => Ok(None),
    }
}

/// 実行中の pull 数を数え、`Drop` で確実に解放するガード（上限超過は取得できない）。
struct PullSlot {
    counter: Arc<AtomicUsize>,
}

impl PullSlot {
    fn acquire(counter: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        let previous = counter.fetch_add(1, Ordering::AcqRel);
        if previous >= max {
            counter.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Self {
            counter: Arc::clone(counter),
        })
    }
}

impl Drop for PullSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `PullImage` の future が worker の完了前に破棄されたとき、取り消しの旗を立てる番人（#2967・CRI-3・REPAIR-5）。
///
/// RPC スレッド（tokio）で `Drop` が走るため、atomic の store だけを行い I/O もロックも持たない。
/// 旗は `ImagePuller::pull_cancellable` が次の確認点で読み、`Timeout` で止まる。
pub(crate) struct CancelOnDrop {
    pub(crate) cancel: Arc<AtomicBool>,
    pub(crate) armed: bool,
}

impl CancelOnDrop {
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.cancel.store(true, Ordering::Release);
        }
    }
}

/// `ImageService` の実装（`ListImages`・`ImageStatus`・`PullImage`。TASK-61.1・61.2・61.3）。
pub struct CriImageService {
    store: Arc<dyn ImageStore>,
    recorder: Arc<dyn CriOpRecorder>,
    puller: Option<Arc<dyn ImagePuller>>,
    pulls_in_flight: Arc<AtomicUsize>,
    max_concurrent_pulls: usize,
    removes_in_flight: Arc<AtomicUsize>,
    max_concurrent_removes: usize,
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
        Self {
            store,
            recorder,
            puller: None,
            pulls_in_flight: Arc::new(AtomicUsize::new(0)),
            max_concurrent_pulls: DEFAULT_MAX_CONCURRENT_PULLS,
            removes_in_flight: Arc::new(AtomicUsize::new(0)),
            max_concurrent_removes: DEFAULT_MAX_CONCURRENT_REMOVES,
        }
    }

    /// 同時 `RemoveImage` 数の上限を変える（0 は全拒否になるため 1 に切り上げる）。
    pub fn with_max_concurrent_removes(mut self, max: usize) -> Self {
        self.max_concurrent_removes = max.max(1);
        self
    }

    /// `PullImage` の取り込み実装を注入する（未設定の間は `PullImage` が `Unimplemented`。TASK-61.3）。
    pub fn with_puller(mut self, puller: Arc<dyn ImagePuller>) -> Self {
        self.puller = Some(puller);
        self
    }

    /// 同時 `PullImage` 数の上限を変える（0 は全拒否になるため 1 に切り上げる）。
    pub fn with_max_concurrent_pulls(mut self, max: usize) -> Self {
        self.max_concurrent_pulls = max.max(1);
        self
    }

    /// `PullImage` の本体（検証 → 資格情報変換 → 同時数制限 → blocking 実行 → ストア登録）。
    ///
    /// 文言にイメージ名・資格情報を含めない。`sandbox_config` は無視する。
    async fn pull(&self, request: v1::PullImageRequest) -> Result<v1::PullImageResponse, CriError> {
        let Some(puller) = self.puller.clone() else {
            return Err(CriError::unimplemented("pull_image"));
        };
        let reference = request.image.map(|spec| spec.image).unwrap_or_default();
        if reference.is_empty() {
            return Err(CriError::invalid_argument(
                "image reference must not be empty",
            ));
        }
        if reference.len() > MAX_FILTER_BYTES {
            return Err(CriError::invalid_argument("image reference is too long"));
        }
        let credentials = match request.auth {
            Some(auth) => credentials_from_auth_config(&auth).map_err(CriError::from)?,
            None => None,
        };
        let slot = PullSlot::acquire(&self.pulls_in_flight, self.max_concurrent_pulls)
            .ok_or_else(|| CriError::resource_exhausted("too many concurrent image pulls"))?;
        let pull_request = PullRequest {
            reference,
            credentials,
        };
        // RPC の future が期限切れ・取り消しで破棄されたら旗を立て、worker を次の確認点で止める（#2967・REPAIR-5）。
        let cancel = Arc::new(AtomicBool::new(false));
        let mut guard = CancelOnDrop {
            cancel: Arc::clone(&cancel),
            armed: true,
        };
        let store = Arc::clone(&self.store);
        // publish 確定後の登録（`into_record` と `upsert`）も worker の中で行う（#4178・OCI-7・CRI-2）。
        // RPC の future が破棄されても blocking タスクは最後まで走るため、oci の在庫に載った pull は
        // 必ず CRI の在庫へも載り、取り消しの窓（publish と upsert の間）が稼働中に開かない。
        // worker は publish の後に取り消しの旗を見ない。`upsert` が実行器のスレッドでロック待ちと
        // fsync の間ほかの RPC を止める問題もこれで外れる。
        let joined = tokio::task::spawn_blocking(move || {
            // スロットは登録の完了（成否・panic）まで保持する。
            let _slot = slot;
            let pulled = puller
                .pull_cancellable(&pull_request, Some(&cancel))
                .map_err(CriError::from)?;
            let record = pulled.into_record().map_err(CriError::from)?;
            let image_ref = record.id().to_owned();
            store
                .upsert(record)
                .map_err(|_| CriError::internal("image store failure"))?;
            Ok::<String, CriError>(image_ref)
        })
        .await;
        // worker が戻ったあとは旗を立てない（成否・panic を問わない）。
        guard.disarm();
        let image_ref = joined.map_err(|_| CriError::internal("image pull task failed"))??;
        Ok(v1::PullImageResponse { image_ref })
    }

    /// `ImageStatus` の本体。参照検証 → ストア解決 → 未取得は `image: None` の成功応答（CRI-4。api.proto の ImageStatus は未存在で nil Image）。
    ///
    /// 文言に参照（イメージ名・タグ・digest）を含めない。`verbose` の `info` は未実装で空（REPAIR-3）。
    fn status(&self, request: v1::ImageStatusRequest) -> Result<v1::ImageStatusResponse, CriError> {
        let reference = request.image.map(|spec| spec.image).unwrap_or_default();
        if reference.is_empty() {
            return Err(CriError::invalid_argument(
                "image reference must not be empty",
            ));
        }
        if reference.len() > MAX_FILTER_BYTES {
            return Err(CriError::invalid_argument("image reference is too long"));
        }
        let record = resolve_with_canonical(&reference, |r| self.store.get(r))
            .map_err(|_| CriError::internal("image store failure"))?;
        Ok(v1::ImageStatusResponse {
            image: record.map(|r| r.to_proto()),
            info: Default::default(),
        })
    }

    /// `RemoveImage` の本体（#4177・CRI-1・CRI-2）。参照検証 → 記録ごと外す。既に無ければ成功（冪等）。
    ///
    /// blob・展開済み rootfs は消さない（proto は資源の回収を非同期でよいとする。回収は #471 系）。
    /// 文言に参照を含めない。
    ///
    /// 本番の在庫の `remove` は `oci.lock()` の待機・記録の読み直し・fsync を行うため、`PullImage` と同じく
    /// `spawn_blocking` で実行し、current_thread ランタイムの他 RPC を止めない（REPAIR-5）。
    async fn remove(
        &self,
        request: v1::RemoveImageRequest,
    ) -> Result<v1::RemoveImageResponse, CriError> {
        let reference = request.image.map(|spec| spec.image).unwrap_or_default();
        if reference.is_empty() {
            return Err(CriError::invalid_argument(
                "image reference must not be empty",
            ));
        }
        if reference.len() > MAX_FILTER_BYTES {
            return Err(CriError::invalid_argument("image reference is too long"));
        }
        // Removed / Absent のどちらも成功（冪等）。Absent のときだけ正規化した参照で再度試す。
        // spawn 前に有限の枠を取る。枠は worker が完了まで保持し、RPC の取り消しでは解放されない（REPAIR-5）。
        let slot = PullSlot::acquire(&self.removes_in_flight, self.max_concurrent_removes)
            .ok_or_else(|| CriError::resource_exhausted("too many concurrent image removals"))?;
        let store = Arc::clone(&self.store);
        let joined = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let canonical = canonical_reference(&reference);
            store
                .remove_resolving(&reference, canonical.as_deref())
                .map_err(|e: ImageStoreError| match e {
                    // 使用中の拒否だけを前提条件違反にする（kubelet が再試行・報告できる）。文言にイメージ・コンテナ ID を含めない。
                    ImageStoreError::InUse => {
                        CriError::failed_precondition("image is in use by a container")
                    }
                    _ => CriError::internal("image store failure"),
                })
        })
        .await;
        joined.map_err(|_| CriError::internal("image remove task failed"))??;
        Ok(v1::RemoveImageResponse {})
    }

    /// `ListImages` の本体。フィルタ検証 → ストア読み取り → 絞り込み。
    fn list(&self, request: v1::ListImagesRequest) -> Result<v1::ListImagesResponse, CriError> {
        let wanted = request
            .filter
            .and_then(|f| f.image)
            .map(|spec| spec.image)
            .unwrap_or_default();
        if wanted.len() > MAX_FILTER_BYTES {
            return Err(CriError::invalid_argument("image filter is too long"));
        }
        let records = self
            .store
            .list()
            .map_err(|_| CriError::internal("image store failure"))?;
        let canonical = canonical_reference(&wanted);
        let images = records
            .iter()
            .filter(|r| {
                wanted.is_empty()
                    || r.matches(&wanted)
                    || canonical.as_deref().is_some_and(|c| r.matches(c))
            })
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
        let result = self.list(request.into_inner()).map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }

    async fn stream_images(
        &self,
        _request: Request<v1::StreamImagesRequest>,
    ) -> Result<Response<Self::StreamImagesStream>, Status> {
        Err(CriError::unimplemented("stream_images").into())
    }

    /// 参照（id・タグ・digest）に一致する取得済みイメージの詳細を返す。未取得は `image: None` の成功応答（CRI-4・TASK-61.2）。
    async fn image_status(
        &self,
        request: Request<v1::ImageStatusRequest>,
    ) -> Result<Response<v1::ImageStatusResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::ImageStatus);
        let result = self.status(request.into_inner()).map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// レジストリからイメージをローカルキャッシュへ取り込む（CRI-4・OCI-1・TASK-61.3）。
    ///
    /// 応答の `image_ref` はイメージ ID（`ListImages`・`ImageStatus` の `Image.id` と一致）。
    async fn pull_image(
        &self,
        request: Request<v1::PullImageRequest>,
    ) -> Result<Response<v1::PullImageResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::PullImage);
        let result = self.pull(request.into_inner()).await.map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// 参照（id・タグ・digest）のイメージを記録ごと在庫から外す。既に無ければ成功（冪等。CRI-1・CRI-2・#4177）。
    async fn remove_image(
        &self,
        request: Request<v1::RemoveImageRequest>,
    ) -> Result<Response<v1::RemoveImageResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::RemoveImage);
        let result = self
            .remove(request.into_inner())
            .await
            .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }

    // 以降は順次実装する（REPAIR-3）。

    async fn image_fs_info(
        &self,
        _request: Request<v1::ImageFsInfoRequest>,
    ) -> Result<Response<v1::ImageFsInfoResponse>, Status> {
        Err(CriError::unimplemented("image_fs_info").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRI-3・REPAIR-5・#2967: 番人は armed のまま破棄されたときだけ旗を立てる。
    #[test]
    fn cri3_repair5_cancel_on_drop_sets_flag_only_when_armed() {
        let flag = Arc::new(AtomicBool::new(false));
        drop(CancelOnDrop {
            cancel: Arc::clone(&flag),
            armed: true,
        });
        assert!(flag.load(Ordering::Acquire));

        let flag = Arc::new(AtomicBool::new(false));
        let mut g = CancelOnDrop {
            cancel: Arc::clone(&flag),
            armed: true,
        };
        g.disarm();
        drop(g);
        assert!(!flag.load(Ordering::Acquire));
    }
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

    fn digest_rec(d: &[&str]) -> ImageRecord {
        ImageRecord::new(
            "sha256:a",
            vec![],
            d.iter().map(|s| (*s).to_owned()).collect(),
            1,
        )
        .expect("record")
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    /// CRI-2・OCI-1（#3038）: 単一 pull の先頭は top-level digest（辞書順で大きくても先頭）。
    #[test]
    fn cri2_record_single_pull_head_is_top_level() {
        let r = digest_rec(&["reg/a@sha256:ff", "reg/a@sha256:00"]);
        assert_eq!(
            r.repo_digests(),
            strs(&["reg/a@sha256:ff", "reg/a@sha256:00"])
        );
        assert_eq!(r.top_level_digests(), strs(&["reg/a@sha256:ff"]));
        assert_eq!(r.auxiliary_digests(), strs(&["reg/a@sha256:00"]));
    }

    /// CRI-2・OCI-1（#3038）: 統合後の top-level digest は pull の順に依らず containerd と同じ辞書順。
    #[test]
    fn cri2_upsert_merge_sorts_digests_like_containerd() {
        for order in [0, 1] {
            let store = InMemoryImageStore::new();
            let by_platform = || digest_rec(&["reg/a@sha256:P"]);
            let by_tag = || digest_rec(&["reg/a@sha256:I", "reg/a@sha256:P"]);
            if order == 0 {
                store.upsert(by_platform()).expect("first");
                store.upsert(by_tag()).expect("merge");
            } else {
                store.upsert(by_tag()).expect("first");
                store.upsert(by_platform()).expect("merge");
            }
            let got = store.get("sha256:a").expect("get").expect("present");
            assert_eq!(
                got.repo_digests(),
                strs(&["reg/a@sha256:I", "reg/a@sha256:P"])
            );
            assert_eq!(got.top_level_digests().len(), 2);
            assert!(got.auxiliary_digests().is_empty());
        }
    }

    /// CRI-2・OCI-1（#3038）: 同じ内容の再 pull で並びも件数も変わらない。
    #[test]
    fn cri2_upsert_repull_keeps_sorted_order() {
        let store = InMemoryImageStore::new();
        let r = || {
            ImageRecord::new(
                "sha256:a",
                strs(&["reg/a:2", "reg/a:1"]),
                strs(&["reg/a@sha256:I", "reg/a@sha256:P"]),
                1,
            )
            .expect("record")
        };
        store.upsert(r()).expect("first");
        store.upsert(r()).expect("again");
        let got = store.get("sha256:a").expect("get").expect("present");
        assert_eq!(got.repo_tags(), strs(&["reg/a:1", "reg/a:2"]));
        assert_eq!(
            got.repo_digests(),
            strs(&["reg/a@sha256:I", "reg/a@sha256:P"])
        );
    }

    /// CRI-2・OCI-1（#3038）: 上限ちょうどの件数を同内容で再 pull しても和集合は上限内なので成功する。
    #[test]
    fn cri2_upsert_repull_at_limit_succeeds() {
        let store = InMemoryImageStore::new();
        let tags: Vec<String> = (0..MAX_REFS_PER_IMAGE)
            .map(|i| format!("reg/a:{i:03}"))
            .collect();
        let digs: Vec<String> = (0..MAX_REFS_PER_IMAGE)
            .map(|i| format!("reg/a@sha256:{i:03}"))
            .collect();
        let r = || ImageRecord::new("sha256:a", tags.clone(), digs.clone(), 1).expect("record");
        store.upsert(r()).expect("first");
        store.upsert(r()).expect("again");
        let got = store.get("sha256:a").expect("get").expect("present");
        assert_eq!(got.repo_tags().len(), MAX_REFS_PER_IMAGE);
        assert_eq!(got.repo_digests().len(), MAX_REFS_PER_IMAGE);
    }

    /// CRI-2・OCI-1（#3038）: タグ追加は挿入順でなくバイト順の辞書順になる。
    #[test]
    fn cri2_upsert_tag_addition_sorts_tags() {
        let store = InMemoryImageStore::new();
        let a =
            |tags: &[&str]| ImageRecord::new("sha256:a", strs(tags), vec![], 1).expect("record");
        store.upsert(a(&["reg/a:2"])).expect("first");
        store.upsert(a(&["reg/a:10", "reg/a:1"])).expect("add");
        let got = store.get("sha256:a").expect("get").expect("present");
        assert_eq!(got.repo_tags(), strs(&["reg/a:1", "reg/a:10", "reg/a:2"]));
    }

    /// CRI-2・OCI-1（#3038）: 補助だった digest が別の pull で top-level になれば top へ移る。
    #[test]
    fn cri2_upsert_promotes_auxiliary_to_top_level() {
        let store = InMemoryImageStore::new();
        store
            .upsert(digest_rec(&["reg/a@sha256:I", "reg/a@sha256:P"]))
            .expect("first");
        store
            .upsert(digest_rec(&["reg/a@sha256:P"]))
            .expect("by platform");
        let got = store.get("sha256:a").expect("get").expect("present");
        assert_eq!(
            got.top_level_digests(),
            strs(&["reg/a@sha256:I", "reg/a@sha256:P"])
        );
        assert!(got.auxiliary_digests().is_empty());
    }

    /// #2945 向け: 統合後の記録を `from_parts` で読み戻すと同じ並びになる。
    #[test]
    fn cri2_record_from_parts_round_trip() {
        let store = InMemoryImageStore::new();
        store
            .upsert(digest_rec(&["reg/a@sha256:P", "reg/a@sha256:Q"]))
            .expect("first");
        store
            .upsert(digest_rec(&["reg/a@sha256:I", "reg/a@sha256:P"]))
            .expect("merge");
        let got = store.get("sha256:a").expect("get").expect("present");
        let back = ImageRecord::from_parts(
            "sha256:a",
            got.repo_tags().to_vec(),
            got.top_level_digests().to_vec(),
            got.auxiliary_digests().to_vec(),
            1,
        )
        .expect("from_parts");
        assert_eq!(back.repo_digests(), got.repo_digests());
        assert_eq!(back.top_level_digests(), got.top_level_digests());
        assert_eq!(
            back.top_level_digests(),
            strs(&["reg/a@sha256:I", "reg/a@sha256:P"])
        );
        assert_eq!(back.auxiliary_digests(), strs(&["reg/a@sha256:Q"]));
    }

    /// CRI-4: `from_parts` も top と補助の合計件数・長さの上限を守る。
    #[test]
    fn cri4_from_parts_bounds() {
        let many: Vec<String> = (0..MAX_REFS_PER_IMAGE).map(|i| format!("d{i}")).collect();
        assert_eq!(
            ImageRecord::from_parts("a", vec![], many, strs(&["x"]), 1),
            Err(ImageStoreError::TooManyRefs)
        );
        let long = "x".repeat(MAX_IMAGE_FIELD_BYTES + 1);
        assert_eq!(
            ImageRecord::from_parts("a", vec![], vec![], vec![long], 1),
            Err(ImageStoreError::FieldTooLong)
        );
    }

    /// CRI-4: upsert は同一 ID のタグを統合し、他イメージの同一タグを外し、件数上限を守る。
    #[test]
    fn cri4_upsert_merges_moves_tags_and_bounds() {
        let store = InMemoryImageStore::new();
        let a = |tags: &[&str]| {
            ImageRecord::new(
                "sha256:a",
                tags.iter().map(|t| (*t).to_owned()).collect(),
                vec![],
                3,
            )
            .expect("record")
        };
        store.upsert(a(&["t1"])).expect("first");
        store.upsert(a(&["t2", "t1"])).expect("merge");
        let got = store.get("sha256:a").expect("get").expect("some");
        assert_eq!(got.repo_tags, vec!["t1".to_owned(), "t2".to_owned()]);

        let b = ImageRecord::new("sha256:b", vec!["t1".into()], vec![], 4).expect("record");
        store.upsert(b).expect("steal tag");
        let a_after = store.get("sha256:a").expect("get").expect("some");
        assert_eq!(a_after.repo_tags, vec!["t2".to_owned()]);

        let many: Vec<String> = (0..MAX_REFS_PER_IMAGE).map(|i| format!("m{i}")).collect();
        let full = ImageRecord::new("sha256:a", many, vec![], 3).expect("record");
        assert_eq!(store.upsert(full), Err(ImageStoreError::TooManyRefs));
    }

    struct Failing;
    impl ImageStore for Failing {
        fn list(&self) -> Result<Vec<ImageRecord>, ImageStoreError> {
            Err(ImageStoreError::Poisoned)
        }
        fn get(&self, _reference: &str) -> Result<Option<ImageRecord>, ImageStoreError> {
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
        assert_eq!(err.code().grpc_code(), Code::Internal);
        assert_eq!(err.message(), "image store failure");
        let result: Result<(), Status> = Err(Status::from(err));
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
        assert_eq!(err.code().grpc_code(), Code::InvalidArgument);
    }

    fn status_req(reference: &str) -> v1::ImageStatusRequest {
        v1::ImageStatusRequest {
            image: Some(v1::ImageSpec {
                image: reference.into(),
                ..Default::default()
            }),
            verbose: false,
        }
    }

    /// CRI-4・TASK-61.2: id・タグ・digest のいずれの参照でも同じイメージに解決し、id 完全一致を優先する。
    #[test]
    fn cri4_get_resolves_id_tag_digest_and_prefers_id() {
        let store = InMemoryImageStore::new();
        store
            .insert(rec("sha256:aa", "reg/a:1", "reg/a@sha256:aa", 100))
            .unwrap();
        // 別イメージが "sha256:aa" をタグとして持つ衝突を作り、id 完全一致が優先されることを確かめる。
        store
            .insert(rec("sha256:00", "sha256:aa", "reg/z@sha256:00", 5))
            .unwrap();
        for r in ["sha256:aa", "aa", "reg/a:1", "reg/a@sha256:aa"] {
            assert_eq!(
                store.get(r).unwrap().map(|x| x.id),
                Some("sha256:aa".to_owned()),
                "{r}"
            );
        }
        assert_eq!(store.get("reg/none:9").unwrap(), None);
    }

    /// CRI-4・TASK-61.2: 未取得は成功応答で `image` が None（NOT_FOUND にしない）。
    #[test]
    fn cri4_status_missing_returns_none() {
        let svc = CriImageService::new();
        let resp = svc.status(status_req("reg/secret:1")).expect("ok");
        assert_eq!(resp.image, None);
        assert!(resp.info.is_empty());
    }

    /// CRI-4・TASK-61.2: 取得済みなら digest・サイズ・タグを返し、info は空。
    #[test]
    fn cri4_status_returns_image() {
        let store = Arc::new(InMemoryImageStore::new());
        store
            .insert(rec("sha256:aa", "reg/a:1", "reg/a@sha256:aa", 100))
            .unwrap();
        let svc = CriImageService::with_store(store);
        let mut req = status_req("reg/a:1");
        req.verbose = true;
        let resp = svc.status(req).expect("ok");
        let image = resp.image.expect("image");
        assert_eq!(image.id, "sha256:aa");
        assert_eq!(image.size, 100);
        assert_eq!(image.repo_digests, vec!["reg/a@sha256:aa".to_owned()]);
        assert!(resp.info.is_empty());
    }

    /// ERR-3: 空・None・長すぎる参照は INVALID_ARGUMENT。
    #[test]
    fn cri4_status_empty_or_oversized_is_invalid_argument() {
        let svc = CriImageService::new();
        let none = v1::ImageStatusRequest::default();
        assert_eq!(
            svc.status(none).expect_err("e").code().grpc_code(),
            Code::InvalidArgument
        );
        assert_eq!(
            svc.status(status_req(""))
                .expect_err("e")
                .code()
                .grpc_code(),
            Code::InvalidArgument
        );
        let long = "x".repeat(MAX_FILTER_BYTES + 1);
        assert_eq!(
            svc.status(status_req(&long))
                .expect_err("e")
                .code()
                .grpc_code(),
            Code::InvalidArgument
        );
    }

    /// CRI-4: ストア失敗は INTERNAL（内部詳細を含まない）。
    #[test]
    fn cri4_status_store_failure_is_internal() {
        let svc = CriImageService::with_store(Arc::new(Failing));
        let err = svc.status(status_req("a")).expect_err("must fail");
        assert_eq!(err.code().grpc_code(), Code::Internal);
        assert_eq!(err.message(), "image store failure");
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

    /// CRI-1・#4177: remove は id・タグ・digest で記録ごと外し、無ければ Absent。既定実装は ReadOnly。
    #[test]
    fn cri1_remove_resolves_like_get_and_drops_whole_record() {
        let store = InMemoryImageStore::new();
        let r = ImageRecord::new(
            "sha256:aa",
            vec!["t1".into(), "t2".into()],
            vec!["r@sha256:aa".into()],
            1,
        )
        .expect("record");
        store.insert(r).expect("insert");
        store
            .insert(ImageRecord::new("sha256:bb", vec!["t3".into()], vec![], 1).expect("record"))
            .expect("insert");
        assert_eq!(
            store.remove("t2"),
            Ok(RemoveOutcome::Removed {
                id: "sha256:aa".into()
            })
        );
        assert_eq!(store.get("t1"), Ok(None));
        assert_eq!(store.get("r@sha256:aa"), Ok(None));
        assert_eq!(store.len(), 1);
        assert_eq!(store.remove("t2"), Ok(RemoveOutcome::Absent));

        struct NoWrite;
        impl ImageStore for NoWrite {
            fn list(&self) -> Result<Vec<ImageRecord>, ImageStoreError> {
                Ok(vec![])
            }
            fn get(&self, _: &str) -> Result<Option<ImageRecord>, ImageStoreError> {
                Ok(None)
            }
        }
        assert_eq!(NoWrite.remove("x"), Err(ImageStoreError::ReadOnly));
    }
    /// REPAIR-5・CRI-2・#4177: 同時 `RemoveImage` の枠を使い切ると `ResourceExhausted`。RPC を取り消しても worker の完了まで枠は戻らない。
    #[test]
    fn repair5_remove_image_slots_held_until_worker_finishes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        struct Gate(Arc<AtomicBool>);
        impl ImageStore for Gate {
            fn list(&self) -> Result<Vec<ImageRecord>, ImageStoreError> {
                Ok(vec![])
            }
            fn get(&self, _: &str) -> Result<Option<ImageRecord>, ImageStoreError> {
                Ok(None)
            }
            fn remove(&self, _: &str) -> Result<RemoveOutcome, ImageStoreError> {
                let end = Instant::now() + Duration::from_secs(5);
                while !self.0.load(Ordering::SeqCst) && Instant::now() < end {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(RemoveOutcome::Absent)
            }
        }
        let release = Arc::new(AtomicBool::new(false));
        let svc = CriImageService::with_store(Arc::new(Gate(Arc::clone(&release))))
            .with_max_concurrent_removes(1);
        let req = || {
            Request::new(v1::RemoveImageRequest {
                image: Some(v1::ImageSpec {
                    image: "a".into(),
                    ..Default::default()
                }),
            })
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        rt.block_on(async {
            // 1 件目は期限で取り消す（worker は残る）。
            let first = tokio::time::timeout(Duration::from_millis(100), svc.remove_image(req()));
            assert!(first.await.is_err(), "first must still be running");
            let second = svc.remove_image(req()).await.expect_err("slot held");
            assert_eq!(second.code(), tonic::Code::ResourceExhausted);
            release.store(true, Ordering::SeqCst);
            // worker 完了後は枠が戻る。
            let mut ok = false;
            for _ in 0..200 {
                if svc.remove_image(req()).await.is_ok() {
                    ok = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(ok, "slot must be released after the worker finishes");
        });
    }

    /// REPAIR-5・CRI-2・#4177: `RemoveImage` の store 操作がブロックしても current_thread ランタイムの他タスクは進む。
    #[test]
    fn repair5_remove_image_does_not_block_current_thread_runtime() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        struct SlowRemove(Arc<AtomicBool>);
        impl ImageStore for SlowRemove {
            fn list(&self) -> Result<Vec<ImageRecord>, ImageStoreError> {
                Ok(vec![])
            }
            fn get(&self, _: &str) -> Result<Option<ImageRecord>, ImageStoreError> {
                Ok(None)
            }
            fn remove(&self, _: &str) -> Result<RemoveOutcome, ImageStoreError> {
                // 別タスクが旗を立てるまで待つ。ランタイムのスレッドで走ると旗が立たず期限で失敗する。
                let end = Instant::now() + Duration::from_secs(5);
                while !self.0.load(Ordering::SeqCst) {
                    if Instant::now() >= end {
                        return Err(ImageStoreError::ReadOnly);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(RemoveOutcome::Absent)
            }
        }

        let flag = Arc::new(AtomicBool::new(false));
        let svc = CriImageService::with_store(Arc::new(SlowRemove(Arc::clone(&flag))));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime");
        let (resp, ticked) = rt.block_on(async {
            let remove = svc.remove_image(Request::new(v1::RemoveImageRequest {
                image: Some(v1::ImageSpec {
                    image: "a".into(),
                    ..Default::default()
                }),
            }));
            let ticker = async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                flag.store(true, Ordering::SeqCst);
                "ticked"
            };
            tokio::join!(remove, ticker)
        });
        assert_eq!(ticked, "ticked");
        assert!(resp.is_ok(), "remove must succeed once released: {resp:?}");
    }
}
