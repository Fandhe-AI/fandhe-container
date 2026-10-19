//! `create_with_image` + `ImageRootfsUnpacker` の結合試験（OCI-7・TASK-183.8 追補・#2342）。
//!
//! 公開 API（`create_with_image`・`ContainerImage::with_unpacker`・`ContainerImageRefs`・
//! `ImageRootfsUnpacker`・実 `FileStateStore`）だけを crate の外から呼び、展開後の状態作成、
//! 展開失敗時の rootfs の削除と参照の解除、書き込みの有無が曖昧な状態作成の失敗・並行する通常の
//! create の成功時の rootfs と参照の保持を具体値で確かめる。`FileStateStore` は Linux 限定のため
//! 本ファイルの試験も Linux のみ（root 不要。他 OS の挙動は `oci_runtime::create` のユニットテストが担う）。

#![cfg(target_os = "linux")]

use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    ContainerImage, ContainerImageRefs, ImageManifestDigest, ImageRefGeneration,
    ImageRefRegistration, ImageRefRelease, ImageRootfsUnpacked, ImageRootfsUnpacker,
    create_with_image,
};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, CreateRequest, CreateStateRequest, DeleteStateRequest,
    DeleteStateResponse, ErrorCode, GetStateRequest, ListStateRequest, StateList, StateRecord,
    StateStore, TraitError, UpdateStateRequest,
};
use serde_json::json;

const MANIFEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

static SEQ: AtomicU32 = AtomicU32::new(0);

/// テストごとに排他作成する一時ディレクトリ（bundle と状態ルートの親。終了時に削除）。
struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let tmp = std::fs::canonicalize(std::env::temp_dir()).expect("tmp");
        let dir = tmp.join(format!(
            "fandhe-core-create-image-it-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("sandbox");
        let bundle = dir.join("bundle");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&bundle)
            .expect("bundle");
        std::fs::write(
            bundle.join("config.json"),
            serde_json::to_vec(&json!({
                "ociVersion": "1.2.0",
                "root": {"path": "rootfs"},
                "process": {"user": {"uid": 0, "gid": 0}, "args": ["/bin/true"], "cwd": "/"}
            }))
            .expect("ser"),
        )
        .expect("config");
        Self { dir }
    }

    fn bundle(&self) -> PathBuf {
        self.dir.join("bundle")
    }

    fn rootfs(&self) -> PathBuf {
        self.bundle().join("rootfs")
    }

    fn store(&self) -> FileStateStore {
        let root = self.dir.join("state");
        FileStateStore::open(StateRoot::from_override(root).expect("root")).expect("open store")
    }

    fn request(&self) -> CreateRequest {
        CreateRequest::new(ContainerId::new("c1").expect("id"), self.bundle()).expect("request")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 呼び出しを記録する `ContainerImageRefs`。
#[derive(Default)]
struct Refs {
    calls: Mutex<Vec<&'static str>>,
}

impl Refs {
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    fn push(&self, c: &'static str) {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).push(c);
    }
}

impl ContainerImageRefs for Refs {
    fn register(
        &self,
        _id: &ContainerId,
        _manifest: &ImageManifestDigest,
    ) -> Result<ImageRefRegistration, TraitError> {
        self.push("register");
        Ok(ImageRefRegistration::Registered)
    }
    fn release(&self, _id: &ContainerId) -> Result<ImageRefRelease, TraitError> {
        self.push("release");
        Ok(ImageRefRelease::Released)
    }
    fn bind(&self, _id: &ContainerId) -> Result<ImageRefGeneration, TraitError> {
        self.push("bind");
        Ok(ImageRefGeneration::from_raw(1))
    }
    fn registration(&self, _id: &ContainerId) -> Result<Option<ImageRefGeneration>, TraitError> {
        Ok(None)
    }
    fn release_if(
        &self,
        _id: &ContainerId,
        _expected: ImageRefGeneration,
    ) -> Result<ImageRefRelease, TraitError> {
        self.push("release_if");
        Ok(ImageRefRelease::NotRegistered)
    }
}

/// rootfs に木を作り、必要なら失敗する展開器。
struct Unpacker {
    fail: bool,
}

impl ImageRootfsUnpacker for Unpacker {
    fn unpack(
        &self,
        _manifest: &ImageManifestDigest,
        rootfs: &Path,
    ) -> Result<ImageRootfsUnpacked, TraitError> {
        std::fs::create_dir(rootfs.join("bin")).expect("bin");
        std::fs::write(rootfs.join("bin").join("true"), b"#!").expect("file");
        if self.fail {
            return Err(TraitError::new(ErrorCode::Internal, "unpack failed"));
        }
        Ok(ImageRootfsUnpacked::default())
    }
}

/// 実 `FileStateStore` を包み、`create` の結果を差し替える。
struct Wrapped<'a> {
    inner: &'a FileStateStore,
    /// 指定すると、`create` は（`inject_winner` なら先に実際の create を行ってから）このコードで失敗する。
    create_error: Option<ErrorCode>,
    inject_winner: bool,
}

impl StateStore for Wrapped<'_> {
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        if let Some(code) = self.create_error {
            if self.inject_winner {
                self.inner.create(req)?;
            }
            return Err(TraitError::new(code, "injected"));
        }
        self.inner.create(req)
    }
    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        self.inner.update(req)
    }
    fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
        self.inner.get(req)
    }
    fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError> {
        self.inner.list(req)
    }
    fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        self.inner.delete(req)
    }
}

fn run(
    store: &dyn StateStore,
    refs: &Refs,
    unpacker: &Unpacker,
    sb: &Sandbox,
) -> Result<StateRecord, fandhe_container_core::oci_runtime::OciRuntimeError> {
    let manifest = ImageManifestDigest::new(MANIFEST).expect("digest");
    create_with_image(
        store,
        &OpRecorder::new(),
        ContainerImage::new(refs, &manifest).with_unpacker(unpacker),
        &sb.request(),
    )
}

fn get(store: &FileStateStore) -> Result<StateRecord, TraitError> {
    store.get(&GetStateRequest::new(ContainerId::new("c1").expect("id")))
}

/// OCI-7: 展開に成功すると rootfs に木が残り、実ストアに created の状態ができ、参照は確定される。
#[test]
fn oci7_create_with_unpacker_unpacks_and_creates_state() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    let record = run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    assert_eq!(record.status().state(), ContainerState::Created);
    assert_eq!(record.bundle(), sb.bundle());
    assert_eq!(
        std::fs::read(sb.rootfs().join("bin").join("true")).expect("read"),
        b"#!"
    );
    assert_eq!(get(&store).expect("stored"), record);
    assert_eq!(refs.calls(), vec!["register", "bind"]);
}

/// OCI-7: 展開に失敗すると rootfs を消し、参照を外し、状態は作られない。
#[test]
fn oci7_create_with_unpacker_failure_removes_rootfs_and_ref() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    let err = run(&store, &refs, &Unpacker { fail: true }, &sb).expect_err("fail");
    assert_eq!(err.code(), ErrorCode::Internal);
    assert!(!sb.rootfs().exists());
    assert_eq!(get(&store).expect_err("none").code(), ErrorCode::NotFound);
    assert_eq!(refs.calls(), vec!["register", "release"]);
}

/// OCI-7: 書き込みの有無が曖昧な状態作成の失敗（Internal）では、rootfs も参照も残す。
#[test]
fn oci7_create_with_unpacker_ambiguous_state_failure_keeps_rootfs_and_ref() {
    let sb = Sandbox::new();
    let inner = sb.store();
    let store = Wrapped {
        inner: &inner,
        create_error: Some(ErrorCode::Internal),
        inject_winner: false,
    };
    let refs = Refs::default();
    let err = run(&store, &refs, &Unpacker { fail: false }, &sb).expect_err("fail");
    assert_eq!(err.code(), ErrorCode::Internal);
    assert!(sb.rootfs().join("bin").join("true").is_file());
    assert_eq!(refs.calls(), vec!["register"]);
}

/// OCI-7: 展開の間に同じ ID・bundle の状態が別に作られて AlreadyExists になっても、その状態が使う
/// rootfs は消さず、先に作られた状態も壊さない（参照だけ外す）。
#[test]
fn oci7_create_with_unpacker_keeps_rootfs_used_by_concurrent_create() {
    let sb = Sandbox::new();
    let inner = sb.store();
    let store = Wrapped {
        inner: &inner,
        create_error: Some(ErrorCode::AlreadyExists),
        inject_winner: true,
    };
    let refs = Refs::default();
    let err = run(&store, &refs, &Unpacker { fail: false }, &sb).expect_err("fail");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    assert!(sb.rootfs().join("bin").join("true").is_file());
    assert_eq!(
        get(&inner).expect("winner").status().state(),
        ContainerState::Created
    );
    assert_eq!(refs.calls(), vec!["register", "release"]);
}
