//! `create_with_image` + `ImageRootfsUnpacker` の結合試験（OCI-7・TASK-183.8 追補・#2342）。
//!
//! 公開 API（`create_with_image`・`ContainerImage::with_unpacker`・`ContainerImageRefs`・
//! `ImageRootfsUnpacker`・実 `FileStateStore`）だけを crate の外から呼び、展開後の状態作成、
//! 展開失敗時の rootfs の削除と参照の解除、書き込みの有無が曖昧な状態作成の失敗・並行する通常の
//! create の成功時の rootfs と参照の保持を具体値で確かめる。`FileStateStore` は Linux 限定のため
//! 本ファイルの試験も Linux のみ（root 不要。他 OS の挙動は `oci_runtime::create` のユニットテストが担う）。

#![cfg(target_os = "linux")]

use std::num::NonZeroU32;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use fandhe_container_core::observability::{OpName, OpRecorder};
use fandhe_container_core::oci_runtime::{
    CgroupRemoval, ContainerCgroupRemover, ContainerImage, ContainerImageRefs, ImageManifestDigest,
    ImageRefGeneration, ImageRefRegistration, ImageRefRelease, ImageRootfsUnpacked,
    ImageRootfsUnpacker, create_with_image, delete_releasing_image_ref,
};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    CgroupScope, CleanupOutcome, ContainerId, ContainerState, ContainerStatus, CreateRequest,
    CreateStateRequest, DeleteRequest, DeleteResponse, DeleteStateRequest, DeleteStateResponse,
    ErrorCode, GetStateRequest, ListStateRequest, StateList, StateRecord, StateRevision,
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
/// 記録のある rootfs しか持たないため cgroup には触れない `ContainerCgroupRemover`（`create` は cgroup を記録しない）。
struct NoCgroup;

impl ContainerCgroupRemover for NoCgroup {
    fn scope(&self) -> Result<CgroupScope, TraitError> {
        CgroupScope::new("/user.slice/user-1000.slice/a.scope")
    }
    fn remove(
        &self,
        _id: &ContainerId,
        _instance: StateRevision,
    ) -> Result<CgroupRemoval, TraitError> {
        Err(TraitError::new(
            ErrorCode::Internal,
            "cgroup must not be touched",
        ))
    }
}

fn delete_c1(
    store: &dyn StateStore,
    rec: &OpRecorder,
    refs: &Refs,
) -> Result<DeleteResponse, fandhe_container_core::oci_runtime::OciRuntimeError> {
    delete_releasing_image_ref(
        store,
        rec,
        &NoCgroup,
        refs,
        &DeleteRequest::new(ContainerId::new("c1").expect("id")),
    )
}

/// `image_rootfs_remove` の (成功件数, 失敗件数)。
fn rootfs_remove_counts(rec: &OpRecorder) -> (u64, u64) {
    let name = OpName::new("image_rootfs_remove").expect("name");
    rec.snapshot_op(&name)
        .map_or((0, 0), |s| (s.success(), s.failure()))
}

/// OCI-7・OCI-5: core が作った rootfs は delete が状態削除の後に消す（bundle と config.json は残る）。
#[test]
fn oci7_delete_removes_core_created_rootfs() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    let record = run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    assert!(record.image_rootfs().is_some());
    assert!(sb.rootfs().join("bin").join("true").is_file());
    let rec = OpRecorder::new();
    let resp = delete_c1(&store, &rec, &refs).expect("delete");
    assert_eq!(resp.image_rootfs(), CleanupOutcome::Removed);
    assert_eq!(resp.kept().count(), 0);
    assert!(!sb.rootfs().exists());
    assert!(sb.bundle().join("config.json").is_file());
    assert_eq!(get(&store).expect_err("gone").code(), ErrorCode::NotFound);
    assert_eq!(rootfs_remove_counts(&rec), (1, 0));
}

/// OCI-7: delete の後、同じ bundle・同じ ID で `create_with_image` を再実行できる（従来は `AlreadyExists`）。
#[test]
fn oci7_delete_then_recreate_same_bundle_succeeds() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    delete_c1(&store, &OpRecorder::new(), &refs).expect("delete");
    let again = run(&store, &refs, &Unpacker { fail: false }, &sb).expect("recreate");
    assert_eq!(again.status().state(), ContainerState::Created);
    assert!(sb.rootfs().join("bin").join("true").is_file());
}

/// OCI-5・OCI-7: update（status の変更）の後も記録は引き継がれ、Stopped の delete で rootfs が消える。
#[test]
fn oci5_delete_after_update_still_removes_rootfs() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    let created = run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    let id = ContainerId::new("c1").expect("id");
    let stopped = store
        .update(&UpdateStateRequest::new(
            ContainerStatus::stopped(id, Some(0)),
            created.revision(),
        ))
        .expect("update");
    assert_eq!(stopped.image_rootfs(), created.image_rootfs());
    let rec = OpRecorder::new();
    delete_c1(&store, &rec, &refs).expect("delete");
    assert!(!sb.rootfs().exists());
    assert_eq!(rootfs_remove_counts(&rec), (1, 0));
}

/// OCI-7: 利用者が用意した rootfs（展開器なしの `create_with_image`）は delete が消さない。
#[test]
fn oci7_delete_keeps_user_supplied_rootfs() {
    let sb = Sandbox::new();
    std::fs::create_dir(sb.rootfs()).expect("rootfs");
    std::fs::write(sb.rootfs().join("user-data"), b"keep").expect("data");
    let store = sb.store();
    let refs = Refs::default();
    let manifest = ImageManifestDigest::new(MANIFEST).expect("digest");
    let record = create_with_image(
        &store,
        &OpRecorder::new(),
        ContainerImage::new(&refs, &manifest),
        &sb.request(),
    )
    .expect("create");
    assert!(record.image_rootfs().is_none());
    let rec = OpRecorder::new();
    let resp = delete_c1(&store, &rec, &refs).expect("delete");
    assert_eq!(resp.image_rootfs(), CleanupOutcome::NotApplicable);
    assert_eq!(
        std::fs::read(sb.rootfs().join("user-data")).expect("kept"),
        b"keep"
    );
    assert_eq!(rootfs_remove_counts(&rec), (0, 0));
}

/// SEC-1: 作った後に別のディレクトリへ差し替えられた rootfs は消さず、delete 自体は成功する（失敗は記録）。
#[test]
fn sec1_delete_keeps_replaced_rootfs_and_succeeds() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    std::fs::rename(sb.rootfs(), sb.bundle().join("moved")).expect("move");
    std::fs::create_dir(sb.rootfs()).expect("replacement");
    std::fs::write(sb.rootfs().join("marker"), b"other").expect("marker");
    let rec = OpRecorder::new();
    let resp = delete_c1(&store, &rec, &refs).expect("delete succeeds");
    assert_eq!(
        resp.image_rootfs(),
        CleanupOutcome::Kept {
            code: ErrorCode::FailedPrecondition
        }
    );
    assert_eq!(
        std::fs::read(sb.rootfs().join("marker")).expect("kept"),
        b"other"
    );
    assert!(sb.bundle().join("moved").join("bin").join("true").is_file());
    assert_eq!(rootfs_remove_counts(&rec), (0, 1));
    assert_eq!(
        delete_c1(&store, &rec, &refs).expect_err("second").code(),
        ErrorCode::NotFound
    );
}

/// OCI-7・SEC-1（#2378）: bundle の所有ロックを他が保持している間の delete は、状態も rootfs も変えず
/// `FailedPrecondition` で再試行を促す。保持が外れれば削除できる（状態削除から rootfs の後始末まで排他するため）。
#[test]
fn oci7_delete_is_refused_while_bundle_lock_is_held() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    let holder = std::fs::File::open(sb.bundle()).expect("open bundle");
    holder.try_lock().expect("lock");
    let rec = OpRecorder::new();
    let e = delete_c1(&store, &rec, &refs).expect_err("locked");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert!(get(&store).is_ok());
    assert!(sb.rootfs().join("bin").join("true").is_file());
    assert_eq!(rootfs_remove_counts(&rec), (0, 0));
    holder.unlock().expect("unlock");
    delete_c1(&store, &rec, &refs).expect("delete");
    assert!(!sb.rootfs().exists());
}

/// OCI-7・SEC-1（#2378）: 通常の create も、bundle の所有ロック（delete が rootfs の後始末の間保持する）が
/// 取れなければ状態を作らず `FailedPrecondition` で拒否する。
#[test]
fn oci7_plain_create_is_refused_while_bundle_lock_is_held() {
    let sb = Sandbox::new();
    std::fs::create_dir(sb.rootfs()).expect("rootfs");
    let store = sb.store();
    let holder = std::fs::File::open(sb.bundle()).expect("open bundle");
    holder.try_lock().expect("lock");
    let e = fandhe_container_core::oci_runtime::create(&store, &OpRecorder::new(), &sb.request())
        .expect_err("locked");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(get(&store).expect_err("none").code(), ErrorCode::NotFound);
    holder.unlock().expect("unlock");
    fandhe_container_core::oci_runtime::create(&store, &OpRecorder::new(), &sb.request())
        .expect("create after unlock");
}

/// OCI-7・SEC-1（#2378）: 記録の bundle の経路に symlink があっても、delete は bundle の実体にロックを取る。
/// 実体を他が保持している間は状態も rootfs も変えず `FailedPrecondition`。保持が外れれば実体の rootfs を消す
/// （表記の違う bundle 経由で排他が外れ、状態削除の後に同じ実体を採用した create の rootfs を消す窓を作らない）。
#[test]
fn sec1_delete_through_symlinked_bundle_locks_the_real_bundle() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    // 記録の bundle の経路を、同じ実体への symlink にする。
    let real = sb.dir.join("real");
    std::fs::rename(sb.bundle(), &real).expect("move bundle");
    std::os::unix::fs::symlink(&real, sb.bundle()).expect("symlink bundle");
    let holder = std::fs::File::open(&real).expect("open real bundle");
    holder.try_lock().expect("lock");
    let rec = OpRecorder::new();
    let e = delete_c1(&store, &rec, &refs).expect_err("locked");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert!(get(&store).is_ok());
    assert!(real.join("rootfs").join("bin").join("true").is_file());
    assert_eq!(rootfs_remove_counts(&rec), (0, 0));
    holder.unlock().expect("unlock");
    delete_c1(&store, &rec, &refs).expect("delete");
    assert_eq!(get(&store).expect_err("gone").code(), ErrorCode::NotFound);
    assert!(!real.join("rootfs").exists());
    assert_eq!(rootfs_remove_counts(&rec), (1, 0));
}

/// OCI-7・SEC-1（#2378）: 通常の create も bundle の実体にロックを取る。symlink 経由の表記で同じ bundle を指す
/// create は、実体のロックの保持中は状態を作らず `FailedPrecondition` で拒否し、外れれば成功する。
#[test]
fn sec1_plain_create_through_symlinked_bundle_locks_the_real_bundle() {
    let sb = Sandbox::new();
    std::fs::create_dir(sb.rootfs()).expect("rootfs");
    let store = sb.store();
    let link = sb.dir.join("link");
    std::os::unix::fs::symlink(sb.bundle(), &link).expect("symlink bundle");
    let req = CreateRequest::new(ContainerId::new("c1").expect("id"), link).expect("request");
    let holder = std::fs::File::open(sb.bundle()).expect("open bundle");
    holder.try_lock().expect("lock");
    let e = fandhe_container_core::oci_runtime::create(&store, &OpRecorder::new(), &req)
        .expect_err("locked");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(get(&store).expect_err("none").code(), ErrorCode::NotFound);
    holder.unlock().expect("unlock");
    fandhe_container_core::oci_runtime::create(&store, &OpRecorder::new(), &req)
        .expect("create after unlock");
}

/// OCI-7・REPAIR-4: rootfs が既に無い（手動で消された）delete は成功し、`AlreadyAbsent` を返す。
#[test]
fn oci7_delete_reports_already_absent_rootfs() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    std::fs::remove_dir_all(sb.rootfs()).expect("manual removal");
    let rec = OpRecorder::new();
    let resp = delete_c1(&store, &rec, &refs).expect("delete");
    assert_eq!(resp.image_rootfs(), CleanupOutcome::AlreadyAbsent);
}

/// SEC-1: rootfs が symlink に差し替えられても、symlink の先は消さない。
#[test]
fn sec1_delete_does_not_follow_symlinked_rootfs() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    let outside = sb.dir.join("outside");
    std::fs::create_dir(&outside).expect("outside");
    std::fs::write(outside.join("marker"), b"x").expect("marker");
    std::fs::rename(sb.rootfs(), sb.bundle().join("moved")).expect("move");
    std::os::unix::fs::symlink(&outside, sb.rootfs()).expect("symlink");
    let rec = OpRecorder::new();
    let resp = delete_c1(&store, &rec, &refs).expect("delete succeeds");
    assert_eq!(
        resp.image_rootfs(),
        CleanupOutcome::Kept {
            code: ErrorCode::FailedPrecondition
        }
    );
    assert_eq!(std::fs::read(outside.join("marker")).expect("kept"), b"x");
    assert_eq!(rootfs_remove_counts(&rec), (0, 1));
}

/// OCI-6・OCI-7: 状態を削除できない（Running 等）delete は rootfs に触れない。
#[test]
fn oci7_delete_failure_before_state_removal_keeps_rootfs() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    let created = run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    let id = ContainerId::new("c1").expect("id");
    store
        .update(&UpdateStateRequest::new(
            ContainerStatus::running(id, NonZeroU32::new(4242)),
            created.revision(),
        ))
        .expect("running");
    let rec = OpRecorder::new();
    let err = delete_c1(&store, &rec, &refs).expect_err("live");
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);
    assert!(sb.rootfs().join("bin").join("true").is_file());
    assert_eq!(rootfs_remove_counts(&rec), (0, 0));
}
// ---- 公開済みで状態の無い rootfs（孤児）の回収（#2540・OCI-7）----

/// 記録つきで `create_with_image` を呼ぶ（要求は呼び出し側が組む）。
fn run_recorded(
    store: &dyn StateStore,
    refs: &Refs,
    rec: &OpRecorder,
    req: &CreateRequest,
) -> Result<StateRecord, fandhe_container_core::oci_runtime::OciRuntimeError> {
    let manifest = ImageManifestDigest::new(MANIFEST).expect("digest");
    create_with_image(
        store,
        rec,
        ContainerImage::new(refs, &manifest).with_unpacker(&Unpacker { fail: false }),
        req,
    )
}

/// `image_rootfs_orphan_reap` の (成功件数, 失敗件数)。
fn orphan_reap_counts(rec: &OpRecorder) -> (u64, u64) {
    let name = OpName::new("image_rootfs_orphan_reap").expect("name");
    rec.snapshot_op(&name)
        .map_or((0, 0), |s| (s.success(), s.failure()))
}

/// 状態の喪失を模す（状態ディレクトリごと消す。rootfs は残る）。
fn lose_state(sb: &Sandbox) {
    std::fs::remove_dir_all(sb.dir.join("state").join("c1")).expect("lose state");
}

const MARKER_NAME: &str = ".fandhe-container-rootfs-owner";

fn write_marker(path: &Path, content: &[u8]) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::remove_file(path);
    std::fs::write(path, content).expect("write marker");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).expect("mode");
}

/// OCI-7・#2540: 公開後に状態を失った rootfs（印は v2）は、同じ bundle の次の create が孤児として回収し、
/// `AlreadyExists` で塞がれない。古い木の中身は残らず、操作 `image_rootfs_orphan_reap` が成功 1 件。
#[test]
fn oci7_orphan_published_rootfs_is_reclaimed_by_next_create() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    std::fs::write(sb.rootfs().join("stale"), b"old").expect("stale");
    lose_state(&sb);
    let rec = OpRecorder::new();
    let again = run_recorded(&store, &refs, &rec, &sb.request()).expect("recreate");
    assert_eq!(again.status().state(), ContainerState::Created);
    assert!(sb.rootfs().join("bin").join("true").is_file());
    assert!(!sb.rootfs().join("stale").exists());
    assert_eq!(orphan_reap_counts(&rec), (1, 0));
}

/// OCI-7・#2540: 状態を持つコンテナ（同じ bundle・同じ印）の rootfs は孤児ではないので消さない。
/// 別 ID の create は `AlreadyExists` で拒否され、既存の木は残る。
#[test]
fn oci7_orphan_reap_keeps_rootfs_used_by_existing_state() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create c1");
    std::fs::write(sb.rootfs().join("keep"), b"x").expect("keep");
    let rec = OpRecorder::new();
    let req = CreateRequest::new(ContainerId::new("c2").expect("id"), sb.bundle()).expect("req");
    let err = run_recorded(&store, &refs, &rec, &req).expect_err("blocked");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    assert!(sb.rootfs().join("keep").is_file());
    assert_eq!(orphan_reap_counts(&rec), (0, 1));
}

/// OCI-7・#2540: 印の無い rootfs（利用者のデータ）は消さない。
#[test]
fn oci7_orphan_reap_keeps_user_data_without_marker() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    std::fs::create_dir(sb.rootfs()).expect("rootfs");
    std::fs::write(sb.rootfs().join("mine"), b"x").expect("mine");
    let rec = OpRecorder::new();
    let err = run_recorded(&store, &refs, &rec, &sb.request()).expect_err("blocked");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    assert!(sb.rootfs().join("mine").is_file());
    assert_eq!(orphan_reap_counts(&rec), (0, 1));
}

/// OCI-7・#2540: 旧形式（v1。トークンだけ）の印は同一性を確かめられないので消さない。
#[test]
fn oci7_orphan_reap_keeps_rootfs_with_v1_marker() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    let marker = sb.rootfs().join(MARKER_NAME);
    let text = std::fs::read_to_string(&marker).expect("marker");
    let token = text.lines().next().expect("token").to_owned();
    write_marker(&marker, token.as_bytes());
    lose_state(&sb);
    let rec = OpRecorder::new();
    let err = run_recorded(&store, &refs, &rec, &sb.request()).expect_err("blocked");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    assert!(sb.rootfs().join("bin").join("true").is_file());
    assert_eq!(orphan_reap_counts(&rec), (0, 1));
}

/// OCI-7・#2540: `cp -a` 等で別の bundle へ複製された木（印の同一性が新しい inode と一致しない）は消さない。
#[test]
fn oci7_orphan_reap_keeps_copied_tree() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    let marker = std::fs::read(sb.rootfs().join(MARKER_NAME)).expect("marker");
    let sb2 = Sandbox::new();
    std::fs::create_dir(sb2.rootfs()).expect("copy root");
    write_marker(&sb2.rootfs().join(MARKER_NAME), &marker);
    std::fs::write(sb2.rootfs().join("mine"), b"x").expect("mine");
    let rec = OpRecorder::new();
    let err = run_recorded(&sb2.store(), &refs, &rec, &sb2.request()).expect_err("blocked");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    assert!(sb2.rootfs().join("mine").is_file());
    assert_eq!(orphan_reap_counts(&rec), (0, 1));
}

/// OCI-7・#2540: 木の `flock` を他が持つ（生きている create）なら消さない。bundle の所有ロックを他が持つ
/// （delete の後始末の最中）ときも消さない。どちらも `AlreadyExists` で、ロックを外せば回収される。
#[test]
fn oci7_orphan_reap_keeps_rootfs_while_locks_are_held() {
    let sb = Sandbox::new();
    let store = sb.store();
    let refs = Refs::default();
    run(&store, &refs, &Unpacker { fail: false }, &sb).expect("create");
    lose_state(&sb);

    let tree_lock = std::fs::File::open(sb.rootfs()).expect("open rootfs");
    tree_lock.try_lock().expect("lock rootfs");
    let rec = OpRecorder::new();
    let err = run_recorded(&store, &refs, &rec, &sb.request()).expect_err("alive");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    assert!(sb.rootfs().join("bin").join("true").is_file());
    drop(tree_lock);

    let bundle_lock = std::fs::File::open(sb.bundle()).expect("open bundle");
    bundle_lock.try_lock().expect("lock bundle");
    let rec = OpRecorder::new();
    let err = run_recorded(&store, &refs, &rec, &sb.request()).expect_err("held");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    assert_eq!(orphan_reap_counts(&rec), (0, 1));
    drop(bundle_lock);

    let rec = OpRecorder::new();
    run_recorded(&store, &refs, &rec, &sb.request()).expect("reclaimed");
    assert_eq!(orphan_reap_counts(&rec), (1, 0));
}

/// OCI-7・REPAIR-4・#2540: 状態の一覧に失敗すると全件を確かめられないので消さない。
#[test]
fn oci7_orphan_reap_keeps_rootfs_when_state_list_fails() {
    struct ListFails<'a>(&'a FileStateStore);
    impl StateStore for ListFails<'_> {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            self.0.create(req)
        }
        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            self.0.update(req)
        }
        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            self.0.get(req)
        }
        fn list(&self, _req: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "list failed"))
        }
        fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            self.0.delete(req)
        }
    }
    let sb = Sandbox::new();
    let inner = sb.store();
    let refs = Refs::default();
    run(&inner, &refs, &Unpacker { fail: false }, &sb).expect("create");
    lose_state(&sb);
    let rec = OpRecorder::new();
    let err = run_recorded(&ListFails(&inner), &refs, &rec, &sb.request()).expect_err("keep");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    assert!(sb.rootfs().join("bin").join("true").is_file());
    assert_eq!(orphan_reap_counts(&rec), (0, 1));
}
