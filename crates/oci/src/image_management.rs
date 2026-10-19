//! ローカルイメージ管理の参照テーブル（OCI-7・TASK-183.1・MS-4・#472）。
//!
//! `image rm` / `image prune` の GC が「参照あり」を判定する正の情報源は、このテーブルだけである
//! （`StateStore`〔CRI-7・OCI-5〕は判定に使わない）。参照は次の 3 種類に限る。
//!
//! 1. コンテナ → manifest（`create` で登録し `delete` 後に解除する）
//! 2. タグ → manifest（`image tag` で登録・付け替え、`image rm` の untag で解除する）
//! 3. 進行中の `pull` の一時参照（リース）。blob ごとに `PullId` の集合で持ち、各 `pull` は自分の
//!    `PullId` だけを登録・解放する。集合が空でない限り当該 blob は参照ありとする。
//!
//! `register_manifest` で登録する在庫（manifest と blob 構成）は参照ではない。blob ごとの参照数を
//! 数えるための構成情報であり、無参照の manifest が含むだけの blob は参照なしと判定する。
//!
//! ストア単位の排他（TASK-183.2・OCI-7・#473）は [`ImageStore`] が担う。テーブルはそのガード越しにだけ
//! 変更でき、永続化前はプロセスごとのメモリ上の別物である（契約と前提は `store` モジュールの doc）。
//!
//! 未実装（後続 issue の担当。実装済みを装わない。REPAIR-3）:
//! - ディスクへの永続化・再起動時の照合（#853・#854・#851）
//! - `image rm` の既定の削除拒否判定は `remove` モジュールで実装済み。`--force`・実削除は #481
//! - `image tag` の API は `tag`（#479・TASK-183.4）で実装済み（CLI 経路と永続化は未実装）
//! - GC 本体・`prune`・`rm` の CLI 配線（#480・#481・#476）。`image ls`/`system df` の集計 API は
//!   `usage`（#478・TASK-183.3）で実装済み（CLI 経路は未実装）、pull へのリース組み込み（#474・#475）
//! - テーブル全体の件数上限（永続化の読み込み側で判断する）
//!
//! core の `ContainerId` との対応づけ（#853・TASK-183.8.1）: core は oci に依存せず、core 側の
//! `ContainerImageRefs`（`oci_runtime`）を、oci と core の両方に依存するアダプタが
//! [`ImageStore::register_container_ref`] / [`ImageStore::release_container_ref`] で満たす。
//! `ContainerId` → `ContainerRefId` は同じ規則なので `ContainerRefId::new(id.as_str())` で失敗しない。
//! 本番のアダプタと CLI / plugin の配線は未実装（REPAIR-3）。

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

mod container_ref;
pub use container_ref::{ContainerRefRegistration, ContainerRefRelease};

mod remove;
pub use remove::{ImageInUse, ImageRmCandidate, ImageRmDecision, ImageRmTarget};

use crate::error::{OciError, OciErrorCode};
use crate::reference::{Digest, RegistryHost, Repository, Tag};

mod usage;

pub use usage::{CacheUsage, DiskUsage, ImageEntry, ImageList, ImageUsage, MAX_CACHE_SCAN_ENTRIES};

mod tag;
pub use tag::{ImageTagChange, ImageTagOutcome, ImageTagSource};

mod store;
pub use store::{
    IMAGE_STORE_LOCK_FILE_NAME, IMAGE_STORE_LOCK_TIMEOUT, ImageStore, ImageStoreGuard,
};

/// `ContainerRefId` の最大バイト数（core の `ContainerId` と同じ）。
pub const CONTAINER_REF_ID_MAX_BYTES: usize = 255;
/// `PullId` の最大バイト数。
pub const PULL_ID_MAX_BYTES: usize = 128;
/// manifest 構成の layers 件数の上限（`manifest::MAX_LAYERS` と同じ）。
pub const MAX_COMPOSITION_LAYERS: usize = crate::manifest::MAX_LAYERS;

fn err(code: OciErrorCode, msg: impl Into<String>) -> OciError {
    OciError::new(code, msg)
}

/// 識別子の共通検証（空・`.`・`..`・文字種・長さ）。永続化時にパス要素になっても安全な形に限る。
fn validate_id(kind: &str, s: &str, max: usize) -> Result<(), OciError> {
    if s.is_empty() || s == "." || s == ".." {
        return Err(err(
            OciErrorCode::InvalidArgument,
            format!("invalid {kind}"),
        ));
    }
    if s.len() > max {
        return Err(err(
            OciErrorCode::InvalidArgument,
            format!("{kind} too long"),
        ));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(err(
            OciErrorCode::InvalidArgument,
            format!("{kind} contains invalid characters"),
        ));
    }
    Ok(())
}

/// コンテナ参照の識別子（検証済み）。core の `ContainerId` と同じ規則。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContainerRefId(String);

impl ContainerRefId {
    /// 識別子を検証して作る（`[A-Za-z0-9._-]`・255 バイト以下・`.`/`..` 不可）。
    pub fn new(s: &str) -> Result<Self, OciError> {
        validate_id("container id", s, CONTAINER_REF_ID_MAX_BYTES)?;
        Ok(Self(s.to_string()))
    }

    /// 検証済みの文字列を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ContainerRefId {
    type Error = OciError;
    fn try_from(s: &str) -> Result<Self, OciError> {
        Self::new(s)
    }
}

impl fmt::Display for ContainerRefId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 進行中の `pull` の識別子（検証済みの不透明値）。生成方法・形式は #474・#852 が決める。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PullId(String);

impl PullId {
    /// 識別子を検証して作る（`[A-Za-z0-9._-]`・128 バイト以下・`.`/`..` 不可）。
    pub fn new(s: &str) -> Result<Self, OciError> {
        validate_id("pull id", s, PULL_ID_MAX_BYTES)?;
        Ok(Self(s.to_string()))
    }

    /// 検証済みの文字列を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for PullId {
    type Error = OciError;
    fn try_from(s: &str) -> Result<Self, OciError> {
        Self::new(s)
    }
}

impl fmt::Display for PullId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// タグの一意キー（レジストリ・repository・タグの組）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TagKey {
    /// レジストリのホスト。
    pub host: RegistryHost,
    /// repository 名。
    pub repository: Repository,
    /// タグ。
    pub tag: Tag,
}

impl TagKey {
    /// 3 要素から作る。
    pub fn new(host: RegistryHost, repository: Repository, tag: Tag) -> Self {
        Self {
            host,
            repository,
            tag,
        }
    }
}

impl fmt::Display for TagKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}:{}", self.host, self.repository, self.tag)
    }
}

/// manifest が使う blob の構成（config と layers）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestComposition {
    config: Digest,
    layers: Vec<Digest>,
}

impl ManifestComposition {
    /// 構成を作る。layers が `MAX_COMPOSITION_LAYERS` を超えると `ResourceExhausted`。
    pub fn new(config: Digest, layers: Vec<Digest>) -> Result<Self, OciError> {
        if layers.len() > MAX_COMPOSITION_LAYERS {
            return Err(err(
                OciErrorCode::ResourceExhausted,
                "too many layers in composition",
            ));
        }
        Ok(Self { config, layers })
    }

    /// config blob の digest。
    pub fn config(&self) -> &Digest {
        &self.config
    }

    /// layer blob の digest（manifest の並び）。
    pub fn layers(&self) -> &[Digest] {
        &self.layers
    }

    /// config と layers を重複除去して列挙する（digest の昇順）。
    pub fn blobs(&self) -> BTreeSet<&Digest> {
        let mut set: BTreeSet<&Digest> = self.layers.iter().collect();
        set.insert(&self.config);
        set
    }

    fn contains(&self, blob: &Digest) -> bool {
        &self.config == blob || self.layers.iter().any(|l| l == blob)
    }
}

/// manifest に対する参照の一覧。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManifestReferences {
    /// この manifest を参照するコンテナ（昇順）。
    pub containers: Vec<ContainerRefId>,
    /// この manifest を指すタグ（昇順）。
    pub tags: Vec<TagKey>,
}

impl ManifestReferences {
    /// 参照の総数。
    pub fn count(&self) -> usize {
        self.containers.len() + self.tags.len()
    }

    /// 1 件でも参照があるか。
    pub fn is_referenced(&self) -> bool {
        self.count() > 0
    }
}

/// blob に対する参照の一覧。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlobReferences {
    /// 構成にこの blob を含む全 manifest（昇順。無参照のものも含む）。
    pub referencing_manifests: Vec<Digest>,
    /// そのうちコンテナまたはタグの参照を 1 件以上持つ manifest の数。
    pub referenced_via_manifests: usize,
    /// この blob を保護している pull リース（昇順）。
    pub leases: Vec<PullId>,
}

impl BlobReferences {
    /// 参照ありか（参照を持つ manifest 経由、またはリースが残っている）。
    pub fn is_referenced(&self) -> bool {
        self.referenced_via_manifests > 0 || !self.leases.is_empty()
    }
}

/// `acquire_lease` の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseAcquired {
    /// 新規に登録されたか（既に同じ pull ID が登録済みなら false）。
    pub newly_added: bool,
}

/// 参照テーブル本体。単体では排他を持たない。ストアとしては [`ImageStore::lock`] のガード越しに使う。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReferenceTable {
    manifests: BTreeMap<Digest, ManifestComposition>,
    container_refs: BTreeMap<ContainerRefId, Digest>,
    tag_refs: BTreeMap<TagKey, Digest>,
    pull_leases: BTreeMap<Digest, BTreeSet<PullId>>,
}

impl ReferenceTable {
    /// 空のテーブルを作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// 登録済み manifest と blob 構成を digest 昇順で返す（`image ls` / `system df` の読み取り口）。
    pub fn manifests(&self) -> impl Iterator<Item = (&Digest, &ManifestComposition)> {
        self.manifests.iter()
    }

    /// 登録済みタグと指す manifest を `TagKey` 昇順で返す（`image ls` の読み取り口）。
    pub fn tags(&self) -> impl Iterator<Item = (&TagKey, &Digest)> {
        self.tag_refs.iter()
    }

    /// manifest の在庫と blob 構成を登録する。同一構成なら冪等、異なる構成は `AlreadyExists`。
    pub fn register_manifest(
        &mut self,
        digest: Digest,
        composition: ManifestComposition,
    ) -> Result<(), OciError> {
        match self.manifests.get(&digest) {
            Some(existing) if existing == &composition => Ok(()),
            Some(_) => Err(err(
                OciErrorCode::AlreadyExists,
                format!("manifest {digest} already registered with a different composition"),
            )),
            None => {
                self.manifests.insert(digest, composition);
                Ok(())
            }
        }
    }

    /// 在庫から manifest を外し、構成を返す。参照が残る場合は `FailedPrecondition`、無ければ `NotFound`。
    pub fn remove_manifest(&mut self, digest: &Digest) -> Result<ManifestComposition, OciError> {
        if !self.manifests.contains_key(digest) {
            return Err(err(
                OciErrorCode::NotFound,
                format!("manifest {digest} not found"),
            ));
        }
        let refs = self.manifest_references(digest);
        if refs.is_referenced() {
            return Err(err(
                OciErrorCode::FailedPrecondition,
                format!("manifest {digest} still has {} reference(s)", refs.count()),
            ));
        }
        self.manifests
            .remove(digest)
            .ok_or_else(|| err(OciErrorCode::Internal, "manifest vanished during removal"))
    }

    /// コンテナ → manifest の参照を登録する。manifest が在庫に無ければ `NotFound`。
    /// 同 id が別 manifest を指していれば `AlreadyExists`、同じなら冪等。
    pub fn register_container(
        &mut self,
        id: ContainerRefId,
        manifest: &Digest,
    ) -> Result<(), OciError> {
        self.require_manifest(manifest)?;
        match self.container_refs.get(&id) {
            Some(cur) if cur == manifest => Ok(()),
            Some(cur) => Err(err(
                OciErrorCode::AlreadyExists,
                format!("container {id} already references {cur}"),
            )),
            None => {
                self.container_refs.insert(id, manifest.clone());
                Ok(())
            }
        }
    }

    /// コンテナの参照を解除し、参照していた manifest を返す。無ければ `NotFound`。
    pub fn unregister_container(&mut self, id: &ContainerRefId) -> Result<Digest, OciError> {
        self.container_refs
            .remove(id)
            .ok_or_else(|| err(OciErrorCode::NotFound, format!("container {id} not found")))
    }

    /// タグ → manifest を登録する（既存タグは付け替え）。直前の付け先を返す。manifest 不在は `NotFound`。
    pub fn register_tag(
        &mut self,
        key: TagKey,
        manifest: &Digest,
    ) -> Result<Option<Digest>, OciError> {
        self.require_manifest(manifest)?;
        Ok(self.tag_refs.insert(key, manifest.clone()))
    }

    /// タグを解除し、外した manifest を返す。無ければ `NotFound`。
    pub fn unregister_tag(&mut self, key: &TagKey) -> Result<Digest, OciError> {
        self.tag_refs
            .remove(key)
            .ok_or_else(|| err(OciErrorCode::NotFound, format!("tag {key} not found")))
    }

    /// blob に pull リースを登録する。同じ pull ID の重複は冪等。
    pub fn acquire_lease(&mut self, blob: Digest, pull: PullId) -> LeaseAcquired {
        let newly_added = self.pull_leases.entry(blob).or_default().insert(pull);
        LeaseAcquired { newly_added }
    }

    /// 指定の pull ID のリースだけを解放する。登録が無ければ `NotFound`（他の pull ID には触れない）。
    pub fn release_lease(&mut self, blob: &Digest, pull: &PullId) -> Result<(), OciError> {
        let Some(set) = self.pull_leases.get_mut(blob) else {
            return Err(err(OciErrorCode::NotFound, format!("no lease on {blob}")));
        };
        if !set.remove(pull) {
            return Err(err(
                OciErrorCode::NotFound,
                format!("pull {pull} holds no lease on {blob}"),
            ));
        }
        if set.is_empty() {
            self.pull_leases.remove(blob);
        }
        Ok(())
    }

    /// pull ID のリースを全 blob から解放し、解放した blob を返す（pull の失敗・中断時用）。
    pub fn release_all_leases(&mut self, pull: &PullId) -> Vec<Digest> {
        let mut released = Vec::new();
        self.pull_leases.retain(|blob, set| {
            if set.remove(pull) {
                released.push(blob.clone());
            }
            !set.is_empty()
        });
        released
    }

    /// manifest への参照を数える。
    pub fn manifest_references(&self, digest: &Digest) -> ManifestReferences {
        ManifestReferences {
            containers: self
                .container_refs
                .iter()
                .filter(|(_, d)| *d == digest)
                .map(|(id, _)| id.clone())
                .collect(),
            tags: self
                .tag_refs
                .iter()
                .filter(|(_, d)| *d == digest)
                .map(|(k, _)| k.clone())
                .collect(),
        }
    }

    /// blob への参照を数える。
    pub fn blob_references(&self, blob: &Digest) -> BlobReferences {
        let referencing_manifests: Vec<Digest> = self
            .manifests
            .iter()
            .filter(|(_, c)| c.contains(blob))
            .map(|(d, _)| d.clone())
            .collect();
        let referenced_via_manifests = referencing_manifests
            .iter()
            .filter(|d| self.manifest_references(d).is_referenced())
            .count();
        let leases = self
            .pull_leases
            .get(blob)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        BlobReferences {
            referencing_manifests,
            referenced_via_manifests,
            leases,
        }
    }

    fn require_manifest(&self, digest: &Digest) -> Result<(), OciError> {
        if self.manifests.contains_key(digest) {
            Ok(())
        } else {
            Err(err(
                OciErrorCode::NotFound,
                format!("manifest {digest} not registered"),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }
    fn cid(s: &str) -> ContainerRefId {
        ContainerRefId::new(s).unwrap()
    }
    fn pid(s: &str) -> PullId {
        PullId::new(s).unwrap()
    }
    fn tk(t: &str) -> TagKey {
        TagKey::new(
            RegistryHost::parse("registry.example").unwrap(),
            Repository::parse("lib/app").unwrap(),
            Tag::parse(t).unwrap(),
        )
    }
    fn code(e: OciError) -> OciErrorCode {
        e.code()
    }

    // manifest A=0xa0 (config 0xc1, layers L=0x10, La=0x11), B=0xb0 (config 0xc2, layers L, Lb=0x12)
    fn fixture() -> ReferenceTable {
        let mut t = ReferenceTable::new();
        t.register_manifest(
            d(0xa0),
            ManifestComposition::new(d(0xc1), vec![d(0x10), d(0x11)]).unwrap(),
        )
        .unwrap();
        t.register_manifest(
            d(0xb0),
            ManifestComposition::new(d(0xc2), vec![d(0x10), d(0x12)]).unwrap(),
        )
        .unwrap();
        t
    }

    /// OCI-7: manifest ごとのコンテナ・タグ参照が数えられる。
    #[test]
    fn oci7_counts_container_and_tag_refs_per_manifest() {
        let mut t = fixture();
        t.register_container(cid("c1"), &d(0xa0)).unwrap();
        t.register_container(cid("c2"), &d(0xa0)).unwrap();
        t.register_tag(tk("t1"), &d(0xa0)).unwrap();
        t.register_tag(tk("t2"), &d(0xb0)).unwrap();
        let a = t.manifest_references(&d(0xa0));
        assert_eq!(a.containers, vec![cid("c1"), cid("c2")]);
        assert_eq!(a.tags, vec![tk("t1")]);
        assert_eq!(a.count(), 3);
        let b = t.manifest_references(&d(0xb0));
        assert_eq!(b.containers, vec![]);
        assert_eq!(b.tags, vec![tk("t2")]);
    }

    /// OCI-7: 共有 blob の参照数が manifest 経由で数えられる。
    #[test]
    fn oci7_counts_shared_blob_refs() {
        let mut t = fixture();
        t.register_container(cid("c1"), &d(0xa0)).unwrap();
        t.register_tag(tk("t2"), &d(0xb0)).unwrap();
        let l = t.blob_references(&d(0x10));
        assert_eq!(l.referencing_manifests, vec![d(0xa0), d(0xb0)]);
        assert_eq!(l.referenced_via_manifests, 2);
        assert_eq!(t.blob_references(&d(0x11)).referenced_via_manifests, 1);
        assert_eq!(t.blob_references(&d(0x12)).referenced_via_manifests, 1);
    }

    /// OCI-7: コンテナ解除で参照数が減り、戻り値が manifest。
    #[test]
    fn oci7_unregister_container_decrements_count() {
        let mut t = fixture();
        t.register_container(cid("c1"), &d(0xa0)).unwrap();
        t.register_container(cid("c2"), &d(0xa0)).unwrap();
        assert_eq!(t.unregister_container(&cid("c1")).unwrap(), d(0xa0));
        assert_eq!(t.manifest_references(&d(0xa0)).containers, vec![cid("c2")]);
    }

    /// OCI-7: 全参照を外すと専有 blob は参照なし、共有 blob は他 manifest 経由で残る。
    #[test]
    fn oci7_shared_blob_kept_while_other_manifest_tagged() {
        let mut t = fixture();
        t.register_container(cid("c1"), &d(0xa0)).unwrap();
        t.register_tag(tk("t1"), &d(0xa0)).unwrap();
        t.register_tag(tk("t2"), &d(0xb0)).unwrap();
        t.unregister_container(&cid("c1")).unwrap();
        t.unregister_tag(&tk("t1")).unwrap();
        assert!(!t.manifest_references(&d(0xa0)).is_referenced());
        assert!(!t.blob_references(&d(0x11)).is_referenced());
        let l = t.blob_references(&d(0x10));
        assert_eq!(l.referenced_via_manifests, 1);
        assert!(l.is_referenced());
    }

    /// OCI-7: タグの付け替えで参照が移る。
    #[test]
    fn oci7_retag_moves_reference() {
        let mut t = fixture();
        assert_eq!(t.register_tag(tk("t1"), &d(0xa0)).unwrap(), None);
        t.register_tag(tk("t2"), &d(0xb0)).unwrap();
        assert_eq!(t.register_tag(tk("t1"), &d(0xb0)).unwrap(), Some(d(0xa0)));
        assert_eq!(t.manifest_references(&d(0xa0)).tags, vec![]);
        assert_eq!(
            t.manifest_references(&d(0xb0)).tags,
            vec![tk("t1"), tk("t2")]
        );
    }

    /// OCI-7: pull ID ごとのリースは独立に解放できる。
    #[test]
    fn oci7_pull_leases_are_released_independently() {
        let mut t = ReferenceTable::new();
        let x = d(0x01);
        assert!(t.acquire_lease(x.clone(), pid("p1")).newly_added);
        assert!(t.acquire_lease(x.clone(), pid("p2")).newly_added);
        assert!(!t.acquire_lease(x.clone(), pid("p2")).newly_added);
        assert_eq!(t.blob_references(&x).leases, vec![pid("p1"), pid("p2")]);
        t.release_lease(&x, &pid("p1")).unwrap();
        let r = t.blob_references(&x);
        assert_eq!(r.leases, vec![pid("p2")]);
        assert!(r.is_referenced());
        assert_eq!(
            code(t.release_lease(&x, &pid("p1")).unwrap_err()),
            OciErrorCode::NotFound
        );
        assert_eq!(t.blob_references(&x).leases, vec![pid("p2")]);
        t.release_lease(&x, &pid("p2")).unwrap();
        let r = t.blob_references(&x);
        assert_eq!(r.leases, vec![]);
        assert!(!r.is_referenced());
    }

    /// OCI-7: release_all_leases は自分の pull ID だけに作用する。
    #[test]
    fn oci7_release_all_leases_only_affects_own_pull_id() {
        let mut t = ReferenceTable::new();
        let (x, y) = (d(0x01), d(0x02));
        t.acquire_lease(x.clone(), pid("p1"));
        t.acquire_lease(y.clone(), pid("p1"));
        t.acquire_lease(y.clone(), pid("p2"));
        assert_eq!(t.release_all_leases(&pid("p1")), vec![x.clone(), y.clone()]);
        assert_eq!(t.blob_references(&x).leases, vec![]);
        assert_eq!(t.blob_references(&y).leases, vec![pid("p2")]);
    }

    /// OCI-7: 在庫に無い blob でもリースがあれば参照あり。
    #[test]
    fn oci7_lease_only_blob_is_referenced_without_manifest() {
        let mut t = ReferenceTable::new();
        t.acquire_lease(d(0x77), pid("p1"));
        let r = t.blob_references(&d(0x77));
        assert_eq!(r.referencing_manifests, vec![]);
        assert!(r.is_referenced());
    }

    /// OCI-7: 未登録 manifest への参照登録は NotFound で、テーブルは変化しない。
    #[test]
    fn oci7_register_ref_to_unknown_manifest_is_not_found() {
        let mut t = fixture();
        let before = t.clone();
        assert_eq!(
            code(t.register_container(cid("c1"), &d(0xee)).unwrap_err()),
            OciErrorCode::NotFound
        );
        assert_eq!(
            code(t.register_tag(tk("t1"), &d(0xee)).unwrap_err()),
            OciErrorCode::NotFound
        );
        assert_eq!(t, before);
    }

    /// OCI-7: 未登録の参照の解除は NotFound。
    #[test]
    fn oci7_unregister_missing_ref_is_not_found() {
        let mut t = fixture();
        assert_eq!(
            code(t.unregister_container(&cid("nope")).unwrap_err()),
            OciErrorCode::NotFound
        );
        assert_eq!(
            code(t.unregister_tag(&tk("nope")).unwrap_err()),
            OciErrorCode::NotFound
        );
    }

    /// OCI-7: コンテナの再登録の意味論。
    #[test]
    fn oci7_container_reregistration_semantics() {
        let mut t = fixture();
        t.register_container(cid("c1"), &d(0xa0)).unwrap();
        t.register_container(cid("c1"), &d(0xa0)).unwrap();
        assert_eq!(t.manifest_references(&d(0xa0)).containers, vec![cid("c1")]);
        assert_eq!(
            code(t.register_container(cid("c1"), &d(0xb0)).unwrap_err()),
            OciErrorCode::AlreadyExists
        );
    }

    /// OCI-7: 参照が残る manifest は外せず、外した後は構成を返す。
    #[test]
    fn oci7_remove_manifest_requires_no_refs() {
        let mut t = fixture();
        t.register_container(cid("c1"), &d(0xa0)).unwrap();
        assert_eq!(
            code(t.remove_manifest(&d(0xa0)).unwrap_err()),
            OciErrorCode::FailedPrecondition
        );
        t.unregister_container(&cid("c1")).unwrap();
        let comp = t.remove_manifest(&d(0xa0)).unwrap();
        assert_eq!(comp.config(), &d(0xc1));
        assert_eq!(comp.layers(), &[d(0x10), d(0x11)]);
        assert_eq!(
            code(t.remove_manifest(&d(0xa0)).unwrap_err()),
            OciErrorCode::NotFound
        );
        let other = ManifestComposition::new(d(0xc9), vec![]).unwrap();
        assert_eq!(
            code(t.register_manifest(d(0xb0), other).unwrap_err()),
            OciErrorCode::AlreadyExists
        );
    }

    /// OCI-7: ID の newtype は不正入力を拒否し、layers 件数に上限がある。
    #[test]
    fn oci7_id_newtypes_reject_invalid_input() {
        for bad in ["", ".", "..", "a/b", "a\0b", "a b"] {
            assert_eq!(
                code(ContainerRefId::new(bad).unwrap_err()),
                OciErrorCode::InvalidArgument
            );
            assert_eq!(
                code(PullId::new(bad).unwrap_err()),
                OciErrorCode::InvalidArgument
            );
        }
        assert!(ContainerRefId::new(&"a".repeat(255)).is_ok());
        assert_eq!(
            code(ContainerRefId::new(&"a".repeat(256)).unwrap_err()),
            OciErrorCode::InvalidArgument
        );
        assert!(PullId::new(&"a".repeat(128)).is_ok());
        assert_eq!(
            code(PullId::new(&"a".repeat(129)).unwrap_err()),
            OciErrorCode::InvalidArgument
        );
        let too_many = vec![d(1); MAX_COMPOSITION_LAYERS + 1];
        assert_eq!(
            code(ManifestComposition::new(d(2), too_many).unwrap_err()),
            OciErrorCode::ResourceExhausted
        );
    }
}
