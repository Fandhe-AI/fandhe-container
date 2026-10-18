//! create / delete とイメージ参照テーブルの結合試験（OCI-7・TASK-183.8.1・#853）。
//!
//! core の `ContainerImageRefs` を `ImageStore` で満たす試験用アダプタ（本番のアダプタは後続。core は
//! oci に依存しないため、oci 側の試験が dev 依存の core を使って通しを確かめる）を介し、
//! `create_with_image` の後は参照が 1 件、`delete_releasing_image_ref` の後は 0 件になることを確かめる。

use std::path::{Path, PathBuf};

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    CgroupRemoval, ContainerCgroupRemover, ContainerImage, ContainerImageRefs, ImageManifestDigest,
    ImageRefGeneration, ImageRefRegistration, ImageRefRelease, create_with_image,
    delete_releasing_image_ref,
};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    CgroupScope, ContainerId, CreateRequest, DeleteRequest, ErrorCode, StateRevision, TraitError,
};
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::image_management::{
    ContainerRefId, ContainerRefRegistration, ContainerRefRelease, ImageStore, ManifestComposition,
};
use fandhe_container_oci::reference::Digest;

const MANIFEST: &str = "sha256:a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";

fn digest(s: &str) -> Digest {
    Digest::parse(s).expect("digest")
}

fn map_err(e: OciError) -> TraitError {
    let code = match e.code() {
        OciErrorCode::NotFound => ErrorCode::NotFound,
        OciErrorCode::AlreadyExists => ErrorCode::AlreadyExists,
        OciErrorCode::Timeout => ErrorCode::Timeout,
        OciErrorCode::InvalidArgument => ErrorCode::InvalidArgument,
        _ => ErrorCode::Internal,
    };
    TraitError::new(code, "image store error")
}

/// 登録 1 件分の試験用の記録（世代と、結び付いた状態の revision）。
type Entry = (u64, Option<u64>);

/// core のトレイトを `ImageStore` で満たす試験用アダプタ。
///
/// 登録世代と状態への結び付けは `ImageStore` がまだ持たないため、アダプタ側で持つ（試験専用。
/// 世代の比較と解除が 1 回の排他にならないので、本番のアダプタは oci 側で原子的に行う）。
struct StoreRefs<'a> {
    store: &'a ImageStore,
    generations: std::sync::Mutex<(u64, std::collections::HashMap<String, Entry>)>,
}

impl<'a> StoreRefs<'a> {
    fn new(store: &'a ImageStore) -> Self {
        Self {
            store,
            generations: std::sync::Mutex::new((0, std::collections::HashMap::new())),
        }
    }
}

impl ContainerImageRefs for StoreRefs<'_> {
    fn bind(&self, id: &ContainerId, revision: StateRevision) -> Result<(), TraitError> {
        let mut g = self.generations.lock().unwrap_or_else(|e| e.into_inner());
        match g.1.get_mut(id.as_str()) {
            Some(entry) if entry.1.is_none() => {
                entry.1 = Some(revision.value());
                Ok(())
            }
            _ => Err(TraitError::new(ErrorCode::NotFound, "no unbound reference")),
        }
    }

    fn registration(
        &self,
        id: &ContainerId,
        revision: StateRevision,
    ) -> Result<Option<ImageRefGeneration>, TraitError> {
        let g = self.generations.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.1
            .get(id.as_str())
            .filter(|e| e.1 == Some(revision.value()))
            .map(|e| ImageRefGeneration::from_raw(e.0)))
    }

    fn release_if(
        &self,
        id: &ContainerId,
        expected: ImageRefGeneration,
    ) -> Result<ImageRefRelease, TraitError> {
        {
            let mut g = self.generations.lock().unwrap_or_else(|e| e.into_inner());
            match g.1.get(id.as_str()) {
                Some(e) if e.0 == expected.as_raw() => {
                    g.1.remove(id.as_str());
                }
                _ => return Ok(ImageRefRelease::NotRegistered),
            }
        }
        self.release(id)
    }

    fn register(
        &self,
        id: &ContainerId,
        manifest: &ImageManifestDigest,
    ) -> Result<ImageRefRegistration, TraitError> {
        let cid = id;
        let id = ContainerRefId::new(id.as_str()).map_err(map_err)?;
        let digest = Digest::parse(manifest.as_str()).map_err(map_err)?;
        Ok(
            match self
                .store
                .register_container_ref(&id, &digest)
                .map_err(map_err)?
            {
                ContainerRefRegistration::Registered => {
                    let mut g = self.generations.lock().unwrap_or_else(|e| e.into_inner());
                    g.0 += 1;
                    let n = g.0;
                    g.1.insert(cid.as_str().to_owned(), (n, None));
                    ImageRefRegistration::Registered
                }
                _ => ImageRefRegistration::AlreadyRegistered,
            },
        )
    }

    fn release(&self, id: &ContainerId) -> Result<ImageRefRelease, TraitError> {
        let id = ContainerRefId::new(id.as_str()).map_err(map_err)?;
        Ok(
            match self.store.release_container_ref(&id).map_err(map_err)? {
                ContainerRefRelease::Released(_) => ImageRefRelease::Released,
                _ => ImageRefRelease::NotRegistered,
            },
        )
    }
}

/// cgroup を作らないので触れない `ContainerCgroupRemover`。
struct NoCgroup;

impl ContainerCgroupRemover for NoCgroup {
    fn scope(&self) -> Result<CgroupScope, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn remove(&self, _: &ContainerId, _: StateRevision) -> Result<CgroupRemoval, TraitError> {
        Ok(CgroupRemoval::NotPresent)
    }
}

/// 一意な一時ディレクトリ（終了時に削除）。
struct Tmp(PathBuf);

impl Tmp {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("fandhe-oci-cimg-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        Self(dir)
    }
    fn sub(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::create_dir_all(&p).expect("sub dir");
        p
    }
    /// 状態ルート用。所有者のみ（0700）でないと `FileStateStore` が拒否する。
    fn private_sub(&self, name: &str) -> PathBuf {
        let p = self.sub(name);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        p
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn make_bundle(dir: &Path) {
    let config = r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/true"],"cwd":"/"}}"#;
    std::fs::write(dir.join("config.json"), config).expect("config");
    std::fs::create_dir_all(dir.join("rootfs")).expect("rootfs");
}

fn containers_of(store: &ImageStore) -> Vec<ContainerRefId> {
    store
        .lock()
        .expect("lock")
        .manifest_references(&digest(MANIFEST))
        .containers
}

/// OCI-7: create_with_image で参照が 1 件になり、delete_releasing_image_ref で 0 件になる。
#[test]
fn oci7_create_then_delete_registers_and_releases_reference() {
    let tmp = Tmp::new("flow");
    let image_root = tmp.sub("images");
    let bundle = tmp.sub("bundle");
    make_bundle(&bundle);
    let state = FileStateStore::open(
        StateRoot::from_override(tmp.private_sub("state")).expect("state root"),
    )
    .expect("state store");

    let images = ImageStore::open(&image_root).expect("image store");
    images
        .lock()
        .expect("lock")
        .register_manifest(
            digest(MANIFEST),
            ManifestComposition::new(
                digest("sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"),
                vec![],
            )
            .expect("comp"),
        )
        .expect("register manifest");

    let refs = StoreRefs::new(&images);
    let manifest = ImageManifestDigest::new(MANIFEST).expect("manifest");
    let id = ContainerId::new("c1").expect("id");
    let rec = OpRecorder::new();

    create_with_image(
        &state,
        &rec,
        ContainerImage::new(&refs, &manifest),
        &CreateRequest::new(id.clone(), bundle).expect("req"),
    )
    .expect("create");
    assert_eq!(
        containers_of(&images),
        vec![ContainerRefId::new("c1").expect("id")]
    );

    delete_releasing_image_ref(&state, &rec, &NoCgroup, &refs, &DeleteRequest::new(id))
        .expect("delete");
    assert_eq!(containers_of(&images), vec![]);
}

/// OCI-7: 在庫に無いイメージの create は NotFound で、状態も参照も残らない。
#[test]
fn oci7_create_with_unknown_manifest_leaves_nothing() {
    let tmp = Tmp::new("unknown");
    let bundle = tmp.sub("bundle");
    make_bundle(&bundle);
    let state = FileStateStore::open(
        StateRoot::from_override(tmp.private_sub("state")).expect("state root"),
    )
    .expect("state store");
    let images = ImageStore::open(&tmp.sub("images")).expect("image store");
    let refs = StoreRefs::new(&images);
    let manifest = ImageManifestDigest::new(MANIFEST).expect("manifest");

    let err = create_with_image(
        &state,
        &OpRecorder::new(),
        ContainerImage::new(&refs, &manifest),
        &CreateRequest::new(ContainerId::new("c1").expect("id"), bundle).expect("req"),
    )
    .expect_err("manifest missing");
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(containers_of(&images), vec![]);
}

/// OCI-7: 参照なしの既存コンテナの delete が、登録後〜状態作成前に止まった並行 create の参照を外さない
/// （#2265 の競合）。状態作成の後に結び付けた参照は新しい状態に属し、その delete で外れる（上の通しの試験）。
#[test]
fn oci7_delete_keeps_reference_of_create_stalled_before_state_create() {
    let tmp = Tmp::new("race");
    let bundle = tmp.sub("bundle");
    make_bundle(&bundle);
    let state = FileStateStore::open(
        StateRoot::from_override(tmp.private_sub("state")).expect("state root"),
    )
    .expect("state store");
    let images = ImageStore::open(&tmp.sub("images")).expect("image store");
    images
        .lock()
        .expect("lock")
        .register_manifest(
            digest(MANIFEST),
            ManifestComposition::new(
                digest("sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1"),
                vec![],
            )
            .expect("comp"),
        )
        .expect("register manifest");
    let refs = StoreRefs::new(&images);
    let manifest = ImageManifestDigest::new(MANIFEST).expect("manifest");
    let id = ContainerId::new("c1").expect("id");
    let rec = OpRecorder::new();

    // 参照なしの既存コンテナ（bundle 直指定の create）。
    fandhe_container_core::oci_runtime::create(
        &state,
        &rec,
        &CreateRequest::new(id.clone(), bundle.clone()).expect("req"),
    )
    .expect("plain create");
    // 並行する create_with_image が参照だけ登録して止まった状態。
    refs.register(&id, &manifest).expect("register");

    delete_releasing_image_ref(
        &state,
        &rec,
        &NoCgroup,
        &refs,
        &DeleteRequest::new(id.clone()),
    )
    .expect("delete");
    assert_eq!(
        containers_of(&images),
        vec![ContainerRefId::new("c1").expect("id")],
        "unbound reference must survive the delete of another state"
    );
}
