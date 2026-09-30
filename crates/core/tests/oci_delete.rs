//! OCI Runtime `delete` の結合試験（CORE-2・OCI-6・REPAIR-4・TASK-30.2）。
//!
//! 公開 API（`create`・`delete`・`StateStore`・`OpRecorder`）だけを crate の外から呼び、
//! create → delete の流れと、実行中コンテナの delete 拒否・停止後の delete・二重 delete の契約を
//! 具体値で確かめる。start 経路は `oci_lifecycle.rs` が担うため、Running の状態は supervisor の代わりに
//! `StateStore` へ直接作る（3 OS で同じ経路。root 不要・skip なし）。
//!
//! 本 Issue の範囲は `StateStore` のレコード削除まで。状態ファイル・cgroup の削除は TASK-30.3 の範囲。

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Mutex;

use fandhe_container_core::observability::{OpName, OpRecorder};
use fandhe_container_core::oci_runtime::{create, delete};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ContainerStatus, CreateRequest, CreateStateRequest, DeleteRequest,
    DeleteResponse, DeleteStateRequest, DeleteStateResponse, ErrorCode, GetStateRequest,
    ListStateRequest, StateList, StateRecord, StateRevision, StateStore, TraitError,
    UpdateStateRequest,
};
use serde_json::{Value, json};

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
        let record = StateRecord::new(
            req.status().clone(),
            req.bundle().to_path_buf(),
            self.allocate_revision(),
        )?;
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
        let next = StateRecord::new(
            req.status().clone(),
            cur.bundle().to_path_buf(),
            self.allocate_revision(),
        )?;
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
#[test]
fn oci6_core2_create_then_delete() {
    let b = Bundle::ready("create", &config());
    let store = MemStateStore::new();
    let rec = OpRecorder::new();
    let id = "del-create";
    create(&store, &rec, &b.create_request(id)).expect("create");

    let res = delete(&store, &rec, &DeleteRequest::new(cid(id))).expect("delete");
    assert_eq!(res, DeleteResponse::new());
    assert_eq!(
        store.record_of(id).expect_err("gone").code(),
        ErrorCode::NotFound
    );

    let err = delete(&store, &rec, &DeleteRequest::new(cid(id))).expect_err("second delete");
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(op_stats(&rec, "delete"), (1, 1));
}

/// OCI-6・CORE-2: 実行中は拒否され、停止（supervisor の代わりにテストが遷移）後に削除できる。
#[test]
fn oci6_core2_delete_rejected_until_stopped() {
    let b = Bundle::ready("running", &config());
    let store = MemStateStore::new();
    let rec = OpRecorder::new();
    let id = "del-running";
    let created = create(&store, &rec, &b.create_request(id)).expect("create");

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
        let err = delete(&store, &rec, &DeleteRequest::new(cid(id)).with_force(force))
            .expect_err("rejected while running");
        if force {
            assert_eq!(err.code(), ErrorCode::Unimplemented);
        } else {
            assert_eq!(err.code(), ErrorCode::FailedPrecondition);
            assert_eq!(err.message(), "container is still running");
        }
        assert_eq!(store.record_of(id).expect("kept"), running);
    }

    // supervisor（TASK-157）の代わりに Stopped へ遷移させる。
    let stopped = store
        .update(&UpdateStateRequest::new(
            ContainerStatus::stopped(cid(id), Some(0)),
            running.revision(),
        ))
        .expect("stopped");
    assert_eq!(stopped.status().state(), ContainerState::Stopped);

    delete(&store, &rec, &DeleteRequest::new(cid(id))).expect("delete");
    let err = delete(&store, &rec, &DeleteRequest::new(cid(id))).expect_err("second delete");
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(op_stats(&rec, "delete"), (1, 3));
}
