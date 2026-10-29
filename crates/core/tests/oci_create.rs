//! `oci_runtime::create` の結合試験（OCI-4・CORE-2・SEC-1・REPAIR-4・TASK-29.2）。
//!
//! 公開 API（`create`・`StateStore` トレイト）だけを crate の外から呼び、bundle 検証から
//! `StateStore` への状態作成までの連携を具体値で確かめる。実機権限は不要で 3 OS の既定のテスト集合で動く。

#[cfg(windows)]
#[path = "support/reap.rs"]
mod reap;
#[path = "support/scratch_root.rs"]
mod scratch_root;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use fandhe_container_core::observability::{OpName, OpRecorder};
use fandhe_container_core::oci_runtime::{ByteLimit, LifecycleOp, create, load_resource_limits};
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
    /// bundle の親（tmpfiles の flock 走査から守る。最後に drop される）。
    _scratch: scratch_root::ScratchDir,
}

impl Bundle {
    fn new(name: &str) -> Self {
        let scratch = scratch_root::ScratchDir::new(
            &format!("fandhe-core-create-it-{name}"),
            std::time::Duration::from_secs(10),
        );
        let dir = scratch.path().join("bundle");
        std::fs::create_dir_all(&dir).expect("create bundle dir");
        Self {
            dir,
            _scratch: scratch,
        }
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

/// SEC-2・OCI-4（#1852）: `maskedPaths` / `readonlyPaths` は解釈済みで、これだけの config は create できる。
/// 他の未解釈プロパティと併記したときのエラーは、そちらだけを挙げる。
#[test]
fn sec2_create_accepts_masked_and_readonly_paths() {
    let b = ready_bundle("masked-readonly");
    let mut cfg = valid_config();
    cfg["linux"] = json!({
        "maskedPaths": ["/proc/kcore"],
        "readonlyPaths": ["/proc/sys"],
    });
    b.write_config(&cfg);
    let store = MemStateStore::new();
    create(&store, &OpRecorder::new(), &b.request("c1")).expect("must succeed");
    assert_eq!(store.len(), 1);

    cfg["linux"]["seccomp"] = json!({"defaultAction": "SCMP_ACT_ERRNO"});
    b.write_config(&cfg);
    let store = MemStateStore::new();
    let err = create(&store, &OpRecorder::new(), &b.request("c2")).expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::Unimplemented);
    assert!(err.message().contains("linux.seccomp"), "{}", err.message());
    assert!(
        !err.message().contains("linux.maskedPaths"),
        "{}",
        err.message()
    );
    assert_eq!(store.len(), 0);
}

/// #2019・CORE-3: 対応する `linux.resources`（memory・cpu・pids・blockIO）を含む config は create でき、
/// `load_resource_limits` が具体値を返す。`linux.resources` が無い bundle は `None`。
#[test]
fn core3_create_accepts_supported_resources_and_exposes_values() {
    let b = ready_bundle("resources-ok");
    let mut cfg = valid_config();
    cfg["linux"] = json!({"resources": {
        "memory": {"limit": 67108864, "swap": 67108864},
        "cpu": {"quota": 50000, "period": 100000},
        "pids": {"limit": 64},
        "blockIO": {
            "weight": 500,
            "throttleReadBpsDevice": [{"major": 8, "minor": 0, "rate": 1048576}]
        }
    }});
    b.write_config(&cfg);
    let store = MemStateStore::new();
    create(&store, &OpRecorder::new(), &b.request("c1")).expect("must succeed");
    assert_eq!(store.len(), 1);

    let limits = load_resource_limits(&b.dir)
        .expect("loads")
        .expect("resources present");
    assert_eq!(limits.memory_max(), Some(ByteLimit::Bytes(67_108_864)));
    assert_eq!(limits.memory_swap_max(), Some(ByteLimit::Bytes(0)));
    assert_eq!(limits.cpu_quota(), Some(50_000));
    assert_eq!(limits.cpu_period(), Some(100_000));
    assert_eq!(limits.pids_limit(), Some(64));
    assert_eq!(limits.blkio_weight(), Some(500));
    assert_eq!(limits.io_throttles().len(), 1);
    assert_eq!(limits.io_throttles()[0].rbps(), Some(1_048_576));

    b.write_config(&valid_config());
    assert_eq!(load_resource_limits(&b.dir).expect("loads"), None);
}

/// #2019・SEC-1: setter の無い resources の項目と、未知のキーは構造化エラーで拒否し、ストアへ書かない。
#[test]
fn sec1_create_rejects_unsupported_and_unknown_resources() {
    let b = ready_bundle("resources-unsupported");
    let store = MemStateStore::new();
    let mut cfg = valid_config();
    cfg["linux"] = json!({"resources": {
        "memory": {"limit": 67108864},
        "hugepageLimits": [{"pageSize": "2MB", "limit": 1}]
    }});
    b.write_config(&cfg);
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::Unimplemented);
    assert_eq!(
        err.message(),
        "unsupported config fields: linux.resources.hugepageLimits"
    );

    cfg["linux"] = json!({"resources": {"cpu": {"shares": 512}, "devices": []}});
    b.write_config(&cfg);
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::Unimplemented);
    assert_eq!(
        err.message(),
        "unsupported config fields: linux.resources.cpu.shares, linux.resources.devices"
    );

    cfg["linux"] = json!({"resources": {"someFutureLimit": 1}});
    b.write_config(&cfg);
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert!(
        !err.message().contains("someFutureLimit"),
        "{}",
        err.message()
    );
    assert_eq!(store.len(), 0);
}

/// #2019・CORE-3: cgroup v2 の範囲外の値（`cpu.period` の範囲）は Linux では create の時点で拒否する。
#[cfg(target_os = "linux")]
#[test]
fn core3_create_rejects_resources_outside_the_cgroup_range() {
    let b = ready_bundle("resources-range");
    let mut cfg = valid_config();
    cfg["linux"] = json!({"resources": {"cpu": {"quota": 50000, "period": 0}}});
    b.write_config(&cfg);
    let store = MemStateStore::new();
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        err.message(),
        "config.json: linux.resources has a value outside the cgroup v2 range"
    );
    assert_eq!(store.len(), 0);
}

/// #2019・CORE-3: `linux.cgroupsPath` は値を配置に使わない方針のため、値に関わらず指定があれば Unimplemented で拒否する
/// （黙って無視しない。#2010 で方針を確定）。値はメッセージに載せない。
#[test]
fn core3_sec1_create_rejects_cgroups_path() {
    let b = ready_bundle("cgroups-path");
    for path in [
        "/machine.slice/secret-name",
        "../escape",
        "a/../../b",
        "/sys/fs/cgroup",
        "fc/child",
        "machine.slice:prefix:name",
    ] {
        let mut cfg = valid_config();
        cfg["linux"] = json!({ "cgroupsPath": path });
        b.write_config(&cfg);
        let store = MemStateStore::new();
        let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("must fail");
        assert_eq!(err.code(), ErrorCode::Unimplemented, "{path}");
        assert_eq!(
            err.message(),
            "linux.cgroupsPath is not supported yet; the container cgroup is placed under the delegated scope",
            "{path}"
        );
        assert_eq!(store.len(), 0, "{path}");
    }
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
    let mut mklink = std::process::Command::new("cmd");
    mklink
        .args(["/C", "mklink", "/J"])
        .arg(b.dir.join("link"))
        .arg(&outside.dir);
    // 期限なしの `output()` を避ける（REPAIR-5・#3409）。
    let status = reap::output_within(&mut mklink, reap::reap_within())
        .unwrap_or_else(|e| panic!("mklink /J: {e}"))
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

/// ERR-2・TASK-96.2: ID 重複の失敗が公開 API 経由で op = create・code = ALREADY_EXISTS・終了コード 4・
/// 構造化 1 行 JSON（キーは op / code / message のみ）になる。
#[test]
fn err2_create_duplicate_yields_structured_error() {
    let b = ready_bundle("err2-dup");
    let store = MemStateStore::new();
    create(&store, &OpRecorder::new(), &b.request("c1")).expect("first");
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("dup");
    assert_eq!(err.op(), LifecycleOp::Create);
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    assert_eq!(err.exit_code().get(), 4);
    let mut out = Vec::new();
    err.write_json_line(&mut out).expect("write");
    let line = String::from_utf8(out).expect("utf8");
    assert!(line.ends_with('\n'));
    assert_eq!(line.matches('\n').count(), 1);
    let v: Value = serde_json::from_str(line.trim_end()).expect("json");
    assert_eq!(v.as_object().expect("obj").len(), 3);
    assert_eq!(v["op"], "create");
    assert_eq!(v["code"], "ALREADY_EXISTS");
    assert_eq!(v["message"], err.message());
}

/// ERR-2・TASK-96.2: 検証段階の失敗（config.json 不在）は NOT_FOUND・終了コード 3、
/// 未解釈指定は UNIMPLEMENTED・終了コード 8 で、いずれも op = create。
#[test]
fn err2_create_validation_failures_map_to_exit_codes() {
    let store = MemStateStore::new();
    let b = Bundle::new("err2-noconfig");
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("no config");
    assert_eq!(err.op(), LifecycleOp::Create);
    assert_eq!(err.code().as_str(), "NOT_FOUND");
    assert_eq!(err.exit_code().get(), 3);

    let mut cfg = valid_config();
    cfg["linux"] = json!({"seccomp": {"defaultAction": "SCMP_ACT_ERRNO"}});
    b.write_config(&cfg);
    std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
    let err = create(&store, &OpRecorder::new(), &b.request("c1")).expect_err("unapplied");
    assert_eq!(err.op(), LifecycleOp::Create);
    assert_eq!(err.code().as_str(), "UNIMPLEMENTED");
    assert_eq!(err.exit_code().get(), 8);
    assert_eq!(store.len(), 0);
}
/// `create_audited` の結合試験用の収集 sink（SEC-4・OCI-4・#2480）。
struct CollectSink(Mutex<Vec<fandhe_container_core::audit_log::AuditRecord>>);

impl fandhe_container_core::audit_log::AuditSink for CollectSink {
    fn record(
        &self,
        record: &fandhe_container_core::audit_log::AuditRecord,
    ) -> Result<(), TraitError> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record.clone());
        Ok(())
    }
}

fn config_with_destination(dest: &str) -> Value {
    let mut v = valid_config();
    v["mounts"] = json!([{"destination": dest, "type": "bind", "source": "/tmp"}]);
    v
}

/// SEC-4・OCI-4: 遡り・rootfs 全体・相対 `..` の 3 種が InvalidArgument で拒否され、mount 層 1 件ずつ記録される（#2480）。
#[test]
fn sec4_2480_create_audited_records_destination_rejections() {
    use fandhe_container_core::audit_log::AuditLayer;
    use fandhe_container_core::oci_runtime::create_audited;
    for (n, dest) in ["/../..", "/", "run/../../.."].into_iter().enumerate() {
        let b = Bundle::new(&format!("audit-dest-{n}"));
        b.write_config(&config_with_destination(dest));
        std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
        let store = MemStateStore::new();
        let sink = CollectSink(Mutex::new(Vec::new()));
        let req = b.request("cx");
        let err = create_audited(&store, &OpRecorder::new(), &req, &sink)
            .expect_err("destination must be rejected");
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "dest={dest}");
        assert_eq!(store.len(), 0);
        let g = sink.0.lock().expect("lock");
        assert_eq!(g.len(), 1, "dest={dest}");
        assert_eq!(g[0].layer(), AuditLayer::Mount);
        assert_eq!(g[0].path(), None);
        assert_eq!(g[0].container_id().map(|c| c.as_str()), Some("cx"));
        // 監査なしの create と同じ拒否（code・message）になる。
        let plain = create(&store, &OpRecorder::new(), &req).expect_err("rejected");
        assert_eq!(plain.code(), err.code());
        assert_eq!(plain.message(), err.message());
    }
}

/// SEC-4: destination 以外の拒否は記録せず、エラーは従来と同じ。正常な create でも記録しない（#2480）。
#[test]
fn sec4_2480_create_audited_ignores_other_outcomes() {
    use fandhe_container_core::oci_runtime::create_audited;
    let b = Bundle::new("audit-other");
    let mut v = valid_config();
    v.as_object_mut().expect("obj").remove("process");
    b.write_config(&v);
    std::fs::create_dir(b.dir.join("rootfs")).expect("rootfs");
    let store = MemStateStore::new();
    let sink = CollectSink(Mutex::new(Vec::new()));
    let req = b.request("cy");
    let err = create_audited(&store, &OpRecorder::new(), &req, &sink).expect_err("no process");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(sink.0.lock().expect("lock").len(), 0);

    let ok = ready_bundle("audit-ok");
    create_audited(&store, &OpRecorder::new(), &ok.request("cz"), &sink).expect("ok");
    assert_eq!(sink.0.lock().expect("lock").len(), 0);
}
