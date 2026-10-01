//! OCI Runtime `delete` の結合試験（CORE-2・OCI-6・REPAIR-4・TASK-30.2・TASK-30.3）。
//!
//! 公開 API（`create`・`delete`・`StateStore`・`OpRecorder`）だけを crate の外から呼び、
//! create → delete の流れと、実行中コンテナの delete 拒否・停止後の delete・二重 delete の契約を
//! 具体値で確かめる。start 経路は `oci_lifecycle.rs` が担うため、Running の状態は supervisor の代わりに
//! `StateStore` へ直接作る（3 OS で同じ経路。root 不要・skip なし）。
//!
//! cgroup の削除は OS 非依存の記録用 fake（`RecordingCgroup`）で「いつ・どの ID で呼ばれるか」を照合する
//! （TASK-30.3 の受入基準 2 の機械照合）。cgroup を削除するのは状態に cgroup スコープが記録されたレコード
//! だけで（`oci_runtime::create` は記録しないため、記録つきのレコードは `StateStore::create` で直接作る）、
//! 記録と異なる委譲スコープからの delete は状態記録を残して拒否される。実 cgroup での削除は実機前提の
//! `cgroup_delete.rs`、状態ファイルの削除（受入基準 1）は実 `FileStateStore` を使う `state_store.rs` が照合する。

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Mutex;

use fandhe_container_core::observability::{OpName, OpRecorder};
use fandhe_container_core::oci_runtime::{CgroupRemoval, ContainerCgroupRemover, create, delete};
use fandhe_container_core::traits::{
    CgroupScope, ContainerId, ContainerState, ContainerStatus, CreateRequest, CreateStateRequest,
    DeleteRequest, DeleteResponse, DeleteStateRequest, DeleteStateResponse, ErrorCode,
    GetStateRequest, ListStateRequest, StateList, StateRecord, StateRevision, StateStore,
    TraitError, UpdateStateRequest,
};
use serde_json::{Value, json};

/// テストで記録する委譲スコープ。
const SCOPE: &str = "/user.slice/user-1000.slice/a.scope";

/// テスト専用の記録用 `ContainerCgroupRemover`。委譲スコープ `scope` を持ち、`remove` で呼ばれた ID を順に
/// 記録して常に `Removed` を返す。
struct RecordingCgroup {
    scope: CgroupScope,
    calls: Mutex<Vec<ContainerId>>,
}

impl RecordingCgroup {
    fn in_scope(scope: &str) -> Self {
        Self {
            scope: CgroupScope::new(scope).expect("scope"),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<ContainerId> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl ContainerCgroupRemover for RecordingCgroup {
    fn scope(&self) -> Result<CgroupScope, TraitError> {
        Ok(self.scope.clone())
    }

    fn remove(&self, id: &ContainerId) -> Result<CgroupRemoval, TraitError> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(id.clone());
        Ok(CgroupRemoval::Removed)
    }
}

/// テスト専用のインメモリ `StateStore`。`update` / `delete` は revision を照合する。
///
/// revision は `StateStore::create` / `update` の契約どおりストア全体で 1 から単調に採番し、同じ ID の
/// 削除・再作成でも過去の値を再発行しない（`last_revision` は最後に払い出した値）。
struct MemStateStore {
    records: Mutex<HashMap<ContainerId, StateRecord>>,
    last_revision: Mutex<u64>,
}

impl MemStateStore {
    fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            last_revision: Mutex::new(0),
        }
    }

    /// ストア全体で一意な revision を 1 つ払い出す。
    fn allocate_revision(&self) -> StateRevision {
        let mut last = self.last_revision.lock().unwrap_or_else(|e| e.into_inner());
        *last = last.checked_add(1).expect("revision overflow");
        StateRevision::from_raw(*last)
    }

    fn record_of(&self, id: &str) -> Result<StateRecord, TraitError> {
        self.get(&GetStateRequest::new(cid(id)))
    }
}

impl StateStore for MemStateStore {
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if records.contains_key(req.id()) {
            return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
        }
        let mut record = StateRecord::new(
            req.status().clone(),
            req.bundle().to_path_buf(),
            self.allocate_revision(),
        )?;
        if let Some(scope) = req.cgroup_scope() {
            record = record.with_cgroup_scope(scope.clone());
        }
        records.insert(req.id().clone(), record.clone());
        Ok(record)
    }

    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let cur = records
            .get(req.status().id())
            .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))?;
        if cur.revision() != req.expected_revision() {
            return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
        }
        let mut next = StateRecord::new(
            req.status().clone(),
            cur.bundle().to_path_buf(),
            self.allocate_revision(),
        )?;
        // `StateStore` の契約どおり cgroup スコープは update で変えずに引き継ぐ（TASK-30.3）。
        if let Some(scope) = cur.cgroup_scope() {
            next = next.with_cgroup_scope(scope.clone());
        }
        records.insert(req.status().id().clone(), next.clone());
        Ok(next)
    }

    fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
        let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        records
            .get(req.id())
            .cloned()
            .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))
    }

    fn list(&self, _req: &ListStateRequest) -> Result<StateList, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }

    fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let cur = records
            .get(req.id())
            .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))?;
        if cur.revision() != req.expected_revision() {
            return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
        }
        records.remove(req.id());
        Ok(DeleteStateResponse::new())
    }
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).expect("id")
}

/// テスト専用の bundle ディレクトリ（drop で削除する）。
struct Bundle {
    dir: PathBuf,
}

impl Bundle {
    fn ready(name: &str, config: &Value) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-core-delete-it-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rootfs")).expect("create bundle dir");
        std::fs::write(
            dir.join("config.json"),
            serde_json::to_vec(config).expect("serialize"),
        )
        .expect("write config");
        Self { dir }
    }

    fn create_request(&self, id: &str) -> CreateRequest {
        CreateRequest::new(cid(id), self.dir.clone()).expect("absolute bundle")
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn config() -> Value {
    json!({
        "ociVersion": "1.2.0",
        "root": {"path": "rootfs"},
        "process": {
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/echo", "delete"],
            "env": ["PATH=/usr/bin:/bin"],
            "cwd": "/"
        },
        "hostname": "delete",
        "linux": {"namespaces": [
            {"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"}, {"type": "ipc"}
        ]}
    })
}

fn op_stats(rec: &OpRecorder, name: &str) -> (u64, u64) {
    let stats = rec
        .snapshot_op(&OpName::new(name).expect("name"))
        .expect("recorded");
    (stats.success(), stats.failure())
}

/// OCI-6・CORE-2: create した直後（未起動）のコンテナは delete でき、再 delete は `NotFound`。
/// `oci_runtime::create` は cgroup スコープを記録しない（cgroup を作らない）ので、cgroup には触れない（TASK-30.3）。
#[test]
fn oci6_core2_create_then_delete() {
    let b = Bundle::ready("create", &config());
    let store = MemStateStore::new();
    let rec = OpRecorder::new();
    let id = "del-create";
    let created = create(&store, &rec, &b.create_request(id)).expect("create");
    assert_eq!(created.cgroup_scope(), None);

    let cg = RecordingCgroup::in_scope(SCOPE);
    let res = delete(&store, &rec, &cg, &DeleteRequest::new(cid(id))).expect("delete");
    assert_eq!(cg.calls(), Vec::<ContainerId>::new());
    assert_eq!(res, DeleteResponse::new());
    assert_eq!(
        store.record_of(id).expect_err("gone").code(),
        ErrorCode::NotFound
    );

    let err = delete(&store, &rec, &cg, &DeleteRequest::new(cid(id))).expect_err("second delete");
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(cg.calls(), Vec::<ContainerId>::new());
    assert_eq!(op_stats(&rec, "delete"), (1, 1));
}

/// cgroup スコープ `scope` を記録した Created（pid なし）のレコードを `StateStore::create` で直接作る
/// （cgroup を作る将来の launcher が create 時に記録する経路の代わり。TASK-30.3）。
fn create_scoped(store: &MemStateStore, b: &Bundle, id: &str, scope: &str) -> StateRecord {
    store
        .create(
            &CreateStateRequest::new(ContainerStatus::created(cid(id), None), b.dir.clone())
                .expect("absolute bundle")
                .with_cgroup_scope(CgroupScope::new(scope).expect("scope")),
        )
        .expect("create scoped record")
}

/// OCI-6・CORE-2: 実行中は拒否され、停止（supervisor の代わりにテストが遷移）後に削除できる。
#[test]
fn oci6_core2_delete_rejected_until_stopped() {
    let b = Bundle::ready("running", &config());
    let store = MemStateStore::new();
    let rec = OpRecorder::new();
    let id = "del-running";
    let cg = RecordingCgroup::in_scope(SCOPE);
    // cgroup の削除まで照合するため、スコープを記録したレコードで始める（TASK-30.3）。
    let created = create_scoped(&store, &b, id, SCOPE);

    // start 済み相当（Running・pid あり）を revision 照合つきの update で作る。
    let pid = NonZeroU32::new(4242).expect("pid");
    let running = store
        .update(&UpdateStateRequest::new(
            ContainerStatus::running(cid(id), Some(pid)),
            created.revision(),
        ))
        .expect("running");
    assert_eq!(running.revision().value(), 2);

    for force in [false, true] {
        let err = delete(
            &store,
            &rec,
            &cg,
            &DeleteRequest::new(cid(id)).with_force(force),
        )
        .expect_err("rejected while running");
        if force {
            assert_eq!(err.code(), ErrorCode::Unimplemented);
        } else {
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(err.message(), "container is still running");
        }
        assert_eq!(store.record_of(id).expect("kept"), running);
        // 拒否された状態では cgroup に触れない。
        assert_eq!(cg.calls(), Vec::<ContainerId>::new());
    }

    // supervisor（TASK-157）の代わりに Stopped へ遷移させる。
    let stopped = store
        .update(&UpdateStateRequest::new(
            ContainerStatus::stopped(cid(id), Some(0)),
            running.revision(),
        ))
        .expect("stopped");
    assert_eq!(stopped.status().state(), ContainerState::Stopped);

    delete(&store, &rec, &cg, &DeleteRequest::new(cid(id))).expect("delete");
    assert_eq!(cg.calls(), vec![cid(id)]);
    let err = delete(&store, &rec, &cg, &DeleteRequest::new(cid(id))).expect_err("second delete");
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(cg.calls(), vec![cid(id)]);
    assert_eq!(op_stats(&rec, "delete"), (1, 3));
}
