//! 孤児 bundle の回収（R8 #2937。OCI-7・CRI-1・SEC-1・REPAIR-5）の結合試験。
//!
//! 一時ディレクトリを状態ルートに見立て、実の `InstanceLock`・`bundle_provider_in`・`FileRecordStore` と、
//! 照会結果を ID ごとに返す偽の実行層で、回収するもの・しないものを具体値で固定する。unix 限定。

#![cfg(unix)]

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_core::traits::{
    ContainerId, ContainerRuntime, ContainerStatus, CreateRequest, CreateStateRequest,
    DeleteRequest, DeleteResponse, DeleteStateRequest, DeleteStateResponse, ErrorCode,
    GetStateRequest, KillRequest, ListStateRequest, StartRequest, StateList, StateRecord,
    StateRequest, StateStore, StopRequest, TraitError, UpdateStateRequest,
};
use fandhe_container_cri::adapter::RuntimeAdapter;
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::runtime_service::{
    FileRecordStore, ListBudget, ListLimits, RecordId, RecordKind, RecordListing, RecordStore,
};
use fandhe_container_plugin_cri::adapter::{
    CriPluginBackends, UnimplementedNetwork, bundle_provider_in,
};
use fandhe_container_plugin_cri::instance_lock::acquire_instance_lock_in;
use fandhe_container_plugin_cri::orphan_bundles::{
    OrphanBundleReclamation, OrphanScan, reclaim_orphan_bundles,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "fandhe-plugin-cri-orphan-{tag}-{}-{nanos}",
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

/// 照会結果を ID ごとに固定する偽の実行層（`state` 以外は使わない）。
#[derive(Clone, Copy)]
enum Answer {
    Running,
    Internal,
    Sleep(Duration),
}

struct FakeRuntime(HashMap<String, Answer>);

fn unused() -> TraitError {
    TraitError::new(ErrorCode::Unimplemented, "unused")
}

impl ContainerRuntime for FakeRuntime {
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
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        let cid: ContainerId = r.id().clone();
        match self.0.get(r.id().as_str()).copied() {
            None => Err(TraitError::new(ErrorCode::NotFound, "gone")),
            Some(Answer::Running) => Ok(ContainerStatus::running(cid, None)),
            Some(Answer::Internal) => Err(TraitError::new(ErrorCode::Internal, "failed")),
            Some(Answer::Sleep(d)) => {
                std::thread::sleep(d);
                Ok(ContainerStatus::running(cid, None))
            }
        }
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

/// 列挙が必ず失敗する記録ストア。
#[derive(Debug)]
struct FailingList;

impl RecordStore for FailingList {
    fn put(
        &self,
        _: RecordKind,
        _: &RecordId,
        _: &[u8],
    ) -> Result<(), fandhe_container_cri::error::CriError> {
        Ok(())
    }
    fn remove(
        &self,
        _: RecordKind,
        _: &RecordId,
    ) -> Result<(), fandhe_container_cri::error::CriError> {
        Ok(())
    }
    fn list(
        &self,
        _: RecordKind,
        _: ListBudget,
        _: ListLimits,
    ) -> Result<RecordListing, fandhe_container_cri::error::CriError> {
        Err(fandhe_container_cri::error::CriError::internal("injected"))
    }
}

fn budget() -> ListBudget {
    ListBudget {
        per_record: Duration::from_millis(500),
        total: Duration::from_secs(20),
    }
}

fn bundles_dir(root: &Path) -> PathBuf {
    root.join(".cri/bundles")
}

fn mkbundle(root: &Path, name: &str) {
    let dir = bundles_dir(root).join(name);
    fs::create_dir_all(dir.join("rootfs")).expect("mkdir bundle");
    fs::write(dir.join("config.json"), b"{}").expect("config");
}

fn exists(root: &Path, name: &str) -> bool {
    fs::symlink_metadata(bundles_dir(root).join(name)).is_ok()
}

/// OCI-7・CRI-1: 回収するもの・しないものを具体値で固定する。
#[test]
fn oci7_orphan_bundles_reclaim_only_unowned_absent_directories() {
    let tmp = TempDir::new("table");
    let root = &tmp.0;
    let provider = bundle_provider_in(root).expect("provider");
    let store = FileRecordStore::open(root).expect("record store");
    let lock = acquire_instance_lock_in(root, Duration::from_secs(1)).expect("lock");

    // A: 記録なし・core に無い -> 回収。B: core に Running。C: 照会が INTERNAL。C2: 照会が期限切れ。
    // D: 壊れた記録。E: 記録あり。F: 不正名。G: 採番の形の symlink。
    for c in ['a', 'b', 'c', 'd', 'e', 'f'] {
        mkbundle(root, &id(c));
    }
    mkbundle(root, &id('1'));
    mkbundle(root, "not-an-id");
    let outside = root.join("outside");
    fs::create_dir_all(&outside).expect("outside");
    fs::write(outside.join("keep"), b"x").expect("keep");
    std::os::unix::fs::symlink(&outside, bundles_dir(root).join(id('9'))).expect("symlink");

    store
        .put(
            RecordKind::Container,
            &RecordId::new(&id('d')).unwrap(),
            b"garbage",
        )
        .expect("broken record");
    store
        .put(
            RecordKind::Container,
            &RecordId::new(&id('e')).unwrap(),
            b"another",
        )
        .expect("record");

    let answers = HashMap::from([
        (id('b'), Answer::Running),
        (id('c'), Answer::Internal),
        (id('1'), Answer::Sleep(Duration::from_secs(3))),
        // 記録のある ID は core が NOT_FOUND でも照会せず残す。
    ]);
    let runtime = RuntimeAdapter::new(Arc::new(FakeRuntime(answers)));
    let out = reclaim_orphan_bundles(&lock, &provider, &store, &runtime, budget());

    assert_eq!(out.scan, OrphanScan::Completed);
    assert_eq!(
        (
            out.scanned,
            out.reclaimed,
            out.kept_has_record,
            out.kept_present,
            out.kept_undetermined,
            out.release_failed,
            out.release_timed_out,
            out.skipped_unrecognized,
            out.skipped_not_dir,
            out.not_attempted,
        ),
        (7, 2, 2, 1, 2, 0, 0, 1, 1, 0)
    );
    // 回収されたのは記録なし × core に無い (a と f) だけ。
    assert!(!exists(root, &id('a')));
    assert!(!exists(root, &id('f')));
    for kept in [
        id('b'),
        id('c'),
        id('d'),
        id('e'),
        id('1'),
        "not-an-id".to_owned(),
    ] {
        assert!(exists(root, &kept), "{kept}");
    }
    // symlink もリンク先も残る。
    assert!(fs::symlink_metadata(bundles_dir(root).join(id('9'))).is_ok());
    assert!(outside.join("keep").exists());
}

/// REPAIR-4: 要約行は固定語彙（文字列全体）で ID・パスを含まない。
#[test]
fn repair4_orphan_summary_line_is_fixed_vocabulary() {
    let tmp = TempDir::new("summary");
    let root = &tmp.0;
    let provider = bundle_provider_in(root).expect("provider");
    let store = FileRecordStore::open(root).expect("record store");
    let lock = acquire_instance_lock_in(root, Duration::from_secs(1)).expect("lock");
    mkbundle(root, &id('a'));
    let runtime = RuntimeAdapter::new(Arc::new(FakeRuntime(HashMap::new())));
    let out: OrphanBundleReclamation =
        reclaim_orphan_bundles(&lock, &provider, &store, &runtime, budget());
    assert_eq!(
        out.summary_line(),
        "cri orphan bundle reclamation: scan=completed scanned=1 reclaimed=1 kept_has_record=0 kept_present=0 kept_undetermined=0 release_failed=0 release_timed_out=0 skipped_unrecognized=0 skipped_not_dir=0 not_attempted=0"
    );
}

/// SEC-1: 記録の列挙に失敗したら、記録の無さを確かめられないので何も消さない。
#[test]
fn sec1_orphan_bundles_untouched_when_record_listing_fails() {
    let tmp = TempDir::new("listfail");
    let root = &tmp.0;
    let provider = bundle_provider_in(root).expect("provider");
    let lock = acquire_instance_lock_in(root, Duration::from_secs(1)).expect("lock");
    mkbundle(root, &id('a'));
    let runtime = RuntimeAdapter::new(Arc::new(FakeRuntime(HashMap::new())));
    let out = reclaim_orphan_bundles(&lock, &provider, &FailingList, &runtime, budget());
    assert_eq!(out.scan, OrphanScan::ListFailed("INTERNAL"));
    assert_eq!(out.reclaimed, 0);
    assert!(exists(root, &id('a')));
}

/// REPAIR-5: 全体の期限が尽きていたら照会も解放も試みない。
#[test]
fn repair5_orphan_bundles_total_deadline_stops() {
    let tmp = TempDir::new("deadline");
    let root = &tmp.0;
    let provider = bundle_provider_in(root).expect("provider");
    let store = FileRecordStore::open(root).expect("record store");
    let lock = acquire_instance_lock_in(root, Duration::from_secs(1)).expect("lock");
    mkbundle(root, &id('a'));
    mkbundle(root, &id('b'));
    let runtime = RuntimeAdapter::new(Arc::new(FakeRuntime(HashMap::new())));
    let b = ListBudget {
        per_record: Duration::from_secs(5),
        total: Duration::from_nanos(1),
    };
    let out = reclaim_orphan_bundles(&lock, &provider, &store, &runtime, b);
    // 列挙の期限が尽きていれば何も回収せず TimedOut（余分に残す側）。
    assert_eq!((out.scan, out.reclaimed), (OrphanScan::TimedOut, 0));
    assert!(exists(root, &id('a')) && exists(root, &id('b')));
}

/// SEC-1・CORE-1: インスタンスロックを持たない backends（注入で組んだもの）では何も回収しない。
#[test]
fn sec1_orphan_bundles_not_reclaimed_without_instance_lock() {
    let tmp = TempDir::new("nolock");
    let root = &tmp.0;
    let provider = bundle_provider_in(root).expect("provider");
    let store = FileRecordStore::open(root).expect("record store");
    mkbundle(root, &id('a'));
    let backends = CriPluginBackends::new(
        Arc::new(FakeRuntime(HashMap::new())),
        Arc::new(NoState),
        Arc::new(UnimplementedNetwork),
    );
    let e = backends
        .reclaim_orphan_bundles(&provider, &store, budget())
        .expect_err("no lock");
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "instance lock is not held");
    assert!(exists(root, &id('a')));
}

/// 列挙の上限: エントリ数が上限を超えたら `FAILED_PRECONDITION`（何も返さない）。root の差し替えも拒否する。
#[test]
fn sec1_list_bundle_ids_enforces_limit_and_root_identity() {
    let tmp = TempDir::new("limit");
    let root = &tmp.0;
    let provider = bundle_provider_in(root).expect("provider");
    mkbundle(root, &id('a'));
    mkbundle(root, &id('b'));
    let listing = provider.list_bundle_ids(2).expect("ok at limit-1 boundary");
    assert_eq!(listing.ids, vec![id('a'), id('b')]);
    let e = provider.list_bundle_ids(1).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    // root を別のディレクトリに差し替える（dev/ino が変わる）。
    let moved = root.join(".cri/bundles-moved");
    fs::rename(bundles_dir(root), &moved).expect("rename");
    fs::create_dir(bundles_dir(root)).expect("new root");
    let e = provider.list_bundle_ids(10).unwrap_err();
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
}
