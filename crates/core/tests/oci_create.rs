//! `oci_runtime::create` の結合試験（OCI-4・CORE-2・SEC-1・REPAIR-4・TASK-29.2）。
//!
//! 公開 API（`create`・`StateStore` トレイト）だけを crate の外から呼び、bundle 検証から
//! `StateStore` への状態作成までの連携を具体値で確かめる。実機権限は不要で 3 OS の既定のテスト集合で動く。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use fandhe_container_core::observability::{OpName, OpRecorder};
use fandhe_container_core::oci_runtime::create;
use fandhe_container_core::traits::{
    ContainerId, ContainerState, CreateRequest, CreateStateRequest, DeleteStateRequest,
    DeleteStateResponse, ErrorCode, GetStateRequest, ListStateRequest, StateList, StateRecord,
    StateRevision, StateStore, TraitError, UpdateStateRequest,
};
use serde_json::{Value, json};

/// テスト専用のインメモリ `StateStore`。
struct MemStateStore {
    records: Mutex<HashMap<ContainerId, StateRecord>>,
}

impl MemStateStore {
    fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
        }
    }

    fn len(&self) -> usize {
        self.records.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl StateStore for MemStateStore {
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if records.contains_key(req.id()) {
            return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
        }
        let revision = StateRevision::from_raw(records.len() as u64 + 1);
        let record = StateRecord::new(req.status().clone(), req.bundle().to_path_buf(), revision)?;
        records.insert(req.id().clone(), record.clone());
        Ok(record)
    }

    fn update(&self, _req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
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

    fn delete(&self, _req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
}

/// テストごとに一意な bundle ディレクトリ（終了時に削除）。
struct Bundle {
    dir: PathBuf,
}

impl Bundle {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-core-create-it-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create bundle dir");
        Self { dir }
    }

    fn write_config(&self, v: &Value) {
        std::fs::write(
            self.dir.join("config.json"),
            serde_json::to_vec(v).expect("serialize"),
        )
        .expect("write config");
    }

    fn request(&self, id: &str) -> CreateRequest {
        CreateRequest::new(ContainerId::new(id).expect("id"), self.dir.clone())
            .expect("absolute bundle")
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn valid_config() -> Value {
    json!({
        "ociVersion": "1.2.0",
        "root": {"path": "rootfs"},
        "process": {
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/true"],
            "cwd": "/"
        }
    })
}

fn ready_bundle(name: &str) -> Bundle {
    let b = Bundle::new(name);
    b.write_config(&valid_config());
    std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
    b
}

/// OCI-4・CORE-2: 正しい bundle で created・pid なしの状態が作られ、StateStore から同じ値が取れる。
#[test]
fn oci4_create_stores_created_state_via_state_store() {
    let b = ready_bundle("ok");
    let store = MemStateStore::new();
    let req = b.request("c1");
    let record = create(&store, &OpRecorder::new(), &req).expect("create succeeds");
    assert_eq!(record.status().state(), ContainerState::Created);
    assert_eq!(record.status().pid(), None);
    assert_eq!(record.bundle(), req.bundle());
    let got = store
        .get(&GetStateRequest::new(req.id().clone()))
        .expect("stored");
    assert_eq!(got, record);
    assert_eq!(store.len(), 1);
}

/// CORE-2: 同じ ID の 2 回目は AlreadyExists で、ストアの件数は 1 のまま。
#[test]
fn core2_create_twice_returns_already_exists() {
    let b = ready_bundle("twice");
    let store = MemStateStore::new();
    create(&store, &OpRecorder::new(), &b.request("c1")).expect("first");
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("second");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    assert_eq!(store.len(), 1);
}

/// OCI-4: 検証失敗（config 不在・rootfs 不在・process 無し）ではストアに何も書かれない。
#[test]
fn oci4_create_failure_leaves_store_empty() {
    let store = MemStateStore::new();

    let b = Bundle::new("noconfig");
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("no config");
    assert_eq!(err.code(), ErrorCode::NotFound);

    b.write_config(&valid_config());
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("no rootfs");
    assert_eq!(err.code(), ErrorCode::NotFound);

    let mut cfg = valid_config();
    cfg.as_object_mut().expect("obj").remove("process");
    b.write_config(&cfg);
    std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("no process");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(store.len(), 0);
}

/// SEC-1・CORE-5: 未解釈の指定を含む config は Unimplemented で拒否し、ストアへ書かない。
#[test]
fn sec1_create_rejects_unapplied_fields() {
    let b = ready_bundle("unapplied");
    let mut cfg = valid_config();
    cfg["linux"] = json!({"seccomp": {"defaultAction": "SCMP_ACT_ERRNO"}});
    b.write_config(&cfg);
    let store = MemStateStore::new();
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::Unimplemented);
    assert!(err.message().contains("linux.seccomp"), "{}", err.message());
    assert_eq!(store.len(), 0);
}

/// SEC-1: `root.path` の `..` は InvalidArgument で拒否する。
#[test]
fn sec1_create_rejects_parent_dir_in_root_path() {
    let b = ready_bundle("dotdot");
    let mut cfg = valid_config();
    cfg["root"]["path"] = json!("../x");
    b.write_config(&cfg);
    let store = MemStateStore::new();
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(store.len(), 0);
}

/// SEC-1: 中間要素の symlink 経由で bundle 外を指す rootfs を拒否する（symlink 作成は Unix のみ）。
#[cfg(unix)]
#[test]
fn sec1_create_rejects_intermediate_symlink_rootfs() {
    let b = Bundle::new("midlink");
    let outside = Bundle::new("midlink-outside");
    std::fs::create_dir(outside.dir.join("rootfs")).expect("outside rootfs");
    std::os::unix::fs::symlink(&outside.dir, b.dir.join("link")).expect("symlink");
    let mut cfg = valid_config();
    cfg["root"]["path"] = json!("link/rootfs");
    b.write_config(&cfg);
    let store = MemStateStore::new();
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(store.len(), 0);
}

/// SEC-1: Windows の junction 経由で bundle 外を指す rootfs を拒否する（`mklink /J` で作成）。
#[cfg(windows)]
#[test]
fn sec1_create_rejects_junction_rootfs() {
    let b = Bundle::new("junction");
    let outside = Bundle::new("junction-outside");
    std::fs::create_dir(outside.dir.join("rootfs")).expect("outside rootfs");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(b.dir.join("link"))
        .arg(&outside.dir)
        .output()
        .expect("mklink")
        .status;
    assert!(status.success(), "mklink /J failed");
    let mut cfg = valid_config();
    cfg["root"]["path"] = json!("link/rootfs");
    b.write_config(&cfg);
    let store = MemStateStore::new();
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(store.len(), 0);
}

/// REPAIR-4: 成功・失敗の両経路が操作名 `create` で 1 件ずつ記録される。
#[test]
fn repair4_create_records_success_and_failure() {
    let b = ready_bundle("rec");
    let store = MemStateStore::new();
    let rec = OpRecorder::new();
    create(&store, &rec, &b.request("c1")).expect("first");
    create(&store, &rec, &b.request("c1")).expect_err("dup");
    let stats = rec
        .snapshot_op(&OpName::new("create").expect("name"))
        .expect("recorded");
    assert_eq!(stats.success(), 1);
    assert_eq!(stats.failure(), 1);
}
