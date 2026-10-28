//! 起動時の記録の再採用の手順（R9 #2938。CRI-1・CRI-2・CORE-1・REPAIR-4・REPAIR-5）の結合試験。
//!
//! 一時ディレクトリを状態ルートに見立て、実の `InstanceLock`・`bundle_provider_in`・`FileRecordStore` と、何も無いと答える
//! 偽の実行層で、4 段の順序・要約行の固定語彙・`Err` の素通し・ロックの要求を具体値で固定する。unix 限定。
//! 本番バイナリでの再起動（SIGKILL → 同じ状態ルート）は `tests/container_grpc.rs` の段 D。

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, CreateStateRequest, DeleteRequest,
    DeleteResponse, DeleteStateRequest, DeleteStateResponse, ErrorCode, GetStateRequest,
    KillRequest, ListStateRequest, StartRequest, StateList, StateRecord, StateRequest, StateStore,
    StopRequest, TraitError, UpdateStateRequest,
};
use fandhe_container_cri::adapter::RuntimeAdapter;
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::runtime_service::{
    FileRecordStore, ListBudget, RecordId, RecordKind, RecordStore,
};
use fandhe_container_plugin_cri::adapter::{
    CriPluginBackends, UnimplementedNetwork, bundle_provider_in,
};
use fandhe_container_plugin_cri::instance_lock::acquire_instance_lock_in;
use fandhe_container_plugin_cri::orphan_bundles::OrphanScan;
use fandhe_container_plugin_cri::record_readoption::run_startup_readoption;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "fandhe-plugin-cri-readopt-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&p).expect("mkdir");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
        Self(fs::canonicalize(&p).expect("canonicalize"))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn id(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

fn unused() -> TraitError {
    TraitError::new(ErrorCode::Unimplemented, "unused")
}

/// どの ID も core に無い（`NOT_FOUND`）と答える偽の実行層。
struct EmptyRuntime;

impl ContainerRuntime for EmptyRuntime {
    fn create(&self, _: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        Err(unused())
    }
    fn start(&self, _: &StartRequest) -> Result<ContainerStatus, TraitError> {
        Err(unused())
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(unused())
    }
    fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Err(unused())
    }
    fn delete(&self, _: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        Err(unused())
    }
    fn state(&self, _: &StateRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::NotFound, "gone"))
    }
}

struct NoState;

impl StateStore for NoState {
    fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        Err(unused())
    }
    fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
        Err(unused())
    }
    fn update(&self, _: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        Err(unused())
    }
    fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        Err(unused())
    }
    fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
        Err(unused())
    }
}

fn backends() -> CriPluginBackends {
    CriPluginBackends::new(
        Arc::new(EmptyRuntime),
        Arc::new(NoState),
        Arc::new(UnimplementedNetwork),
    )
}

fn budget() -> ListBudget {
    ListBudget {
        per_record: Duration::from_millis(500),
        total: Duration::from_secs(20),
    }
}

/// 空の状態ルートでは 4 段とも空で、要約行は出さない（`is_empty`）。
#[test]
fn cri1_empty_state_root_reports_empty() {
    let tmp = TempDir::new("empty");
    let root = &tmp.0;
    let bundles = bundle_provider_in(root).expect("provider");
    let store: Arc<FileRecordStore> = Arc::new(FileRecordStore::open(root).expect("store"));
    let lock = Arc::new(acquire_instance_lock_in(root, Duration::from_secs(1)).expect("lock"));
    let b = backends();
    let svc = b.runtime_service_with_record_store(
        Arc::clone(&bundles) as Arc<dyn fandhe_container_cri::adapter::BundleProvider>,
        Arc::clone(&store) as Arc<dyn RecordStore>,
    );
    let runtime = RuntimeAdapter::new(Arc::clone(b.runtime()));
    let out = run_startup_readoption(&svc, &lock, &bundles, &*store, &runtime, budget())
        .expect("readoption");
    assert!(out.is_empty());
    assert_eq!(out.orphans.scan, OrphanScan::Completed);
}

/// 壊れた記録は数えるだけで起動を止めず、記録の無い孤児 bundle は 4 段目で回収される。要約行は固定語彙で ID を含まない。
#[test]
fn repair4_broken_records_are_counted_and_orphans_reclaimed() {
    let tmp = TempDir::new("broken");
    let root = &tmp.0;
    let bundles = bundle_provider_in(root).expect("provider");
    let store: Arc<FileRecordStore> = Arc::new(FileRecordStore::open(root).expect("store"));
    let lock = Arc::new(acquire_instance_lock_in(root, Duration::from_secs(1)).expect("lock"));
    store
        .put(
            RecordKind::Sandbox,
            &RecordId::new(&id('a')).unwrap(),
            b"garbage",
        )
        .expect("put sandbox");
    store
        .put(
            RecordKind::Container,
            &RecordId::new(&id('b')).unwrap(),
            b"garbage",
        )
        .expect("put container");
    let orphan = root.join(".cri/bundles").join(id('c'));
    fs::create_dir_all(orphan.join("rootfs")).expect("orphan bundle");

    let b = backends();
    let svc = b.runtime_service_with_record_store(
        Arc::clone(&bundles) as Arc<dyn fandhe_container_cri::adapter::BundleProvider>,
        Arc::clone(&store) as Arc<dyn RecordStore>,
    );
    let runtime = RuntimeAdapter::new(Arc::clone(b.runtime()));
    let out = run_startup_readoption(&svc, &lock, &bundles, &*store, &runtime, budget())
        .expect("readoption");
    assert!(!out.is_empty());
    assert_eq!(
        (out.sandboxes.adopted, out.sandboxes.broken.malformed),
        (0, 1)
    );
    assert_eq!(
        (out.containers.adopted, out.containers.broken.malformed),
        (0, 1)
    );
    assert_eq!((out.orphans.scanned, out.orphans.reclaimed), (1, 1));
    assert!(!orphan.exists());
    // 壊れた記録は消さない。
    assert!(
        root.join(".cri/records/sandboxes")
            .join(format!("{}.rec", id('a')))
            .is_file()
    );
    assert!(
        root.join(".cri/records/containers")
            .join(format!("{}.rec", id('b')))
            .is_file()
    );

    let line = out.summary_line();
    assert_eq!(
        line,
        "cri record readoption: kind=sandbox adopted=0 pending_unresolved=0 broken=1 malformed=1 not_regular_file=0 too_long=0 unreadable=0 unrecognized=0 duplicate_metadata=0 | cri record readoption: kind=container adopted=0 present=0 absent_exited=0 remove_pending=0 undetermined=0 stale_create=0 broken=1 malformed=1 not_regular_file=0 too_long=0 unreadable=0 unrecognized=0 duplicate_metadata=0 parentless=0 | cri stale create release: released=0 kept=0 release_failed=0 record_remove_failed=0 not_attempted=0 skipped=0 | cri orphan bundle reclamation: scan=completed scanned=1 reclaimed=1 kept_has_record=0 kept_present=0 kept_undetermined=0 release_failed=0 release_timed_out=0 skipped_unrecognized=0 skipped_not_dir=0 not_attempted=0"
    );
}

/// 件数の上限を超える記録は `Err`（`FAILED_PRECONDITION`）のまま返り、孤児回収まで進まない（fail-closed）。
#[test]
fn cri2_limit_exceeded_error_passes_through_and_stops_before_orphans() {
    let tmp = TempDir::new("limit");
    let root = &tmp.0;
    let bundles = bundle_provider_in(root).expect("provider");
    let store: Arc<FileRecordStore> = Arc::new(FileRecordStore::open(root).expect("store"));
    let lock = Arc::new(acquire_instance_lock_in(root, Duration::from_secs(1)).expect("lock"));
    for i in 0..=1024u32 {
        store
            .put(
                RecordKind::Sandbox,
                &RecordId::new(&format!("{i:064x}")).unwrap(),
                b"garbage",
            )
            .expect("put");
    }
    let orphan = root.join(".cri/bundles").join(id('c'));
    fs::create_dir_all(orphan.join("rootfs")).expect("orphan bundle");
    let b = backends();
    let svc = b.runtime_service_with_record_store(
        Arc::clone(&bundles) as Arc<dyn fandhe_container_cri::adapter::BundleProvider>,
        Arc::clone(&store) as Arc<dyn RecordStore>,
    );
    let runtime = RuntimeAdapter::new(Arc::clone(b.runtime()));
    let e = run_startup_readoption(&svc, &lock, &bundles, &*store, &runtime, budget())
        .expect_err("limit");
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert!(orphan.exists(), "orphan bundles must not be touched");
}

/// 注入で組んだ backends（インスタンスロックなし）では何も触らず `FAILED_PRECONDITION`。
#[test]
fn core1_readopt_records_requires_instance_lock() {
    let tmp = TempDir::new("nolock");
    let root = &tmp.0;
    let bundles = bundle_provider_in(root).expect("provider");
    let store: Arc<FileRecordStore> = Arc::new(FileRecordStore::open(root).expect("store"));
    let b = backends();
    let svc = b.runtime_service_with_record_store(
        Arc::clone(&bundles) as Arc<dyn fandhe_container_cri::adapter::BundleProvider>,
        Arc::clone(&store) as Arc<dyn RecordStore>,
    );
    let e = b
        .readopt_records(&svc, &bundles, &*store, budget())
        .expect_err("no lock");
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "instance lock is not held");
}
