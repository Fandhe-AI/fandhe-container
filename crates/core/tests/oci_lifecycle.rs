//! OCI Runtime ライフサイクル `create` → `start` の一連フローの結合試験（CORE-2・OCI-4・REPAIR-4・TASK-29.4）。
//!
//! 公開 API（`create`・`start`・`StateStore`・`ProcessLauncher`・`LaunchedProcess`・`OpRecorder`）だけを
//! crate の外から呼び、各遷移で観測できる副作用（状態・revision・`LaunchSpec` の全フィールド・観測記録・
//! ハンドルの引き渡し）を具体値で確かめる。
//!
//! `oci_start.rs` との分担: 本ファイルは正常系の一連フローの契約を扱い、start の異常系・タイムアウト・
//! 中断回復・後始末の経路は `oci_start.rs` が扱う。
//!
//! launcher は模擬で、実プロセスの exec・namespace 分離は行わない。本番の `ProcessLauncher` は後続の
//! sub-issue で提供される（実装済みを装わない。REPAIR-3）。rootfs を fd で固定する start の成功経路は
//! Linux 限定のため、Linux 以外では create 成功後に start が `Unimplemented` で拒否されること（fail-closed。
//! SEC-1・CLI-1）を確かめる。実機権限（root 等）は不要で、3 OS の既定のテスト集合で動く。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::observability::{OpName, OpRecorder};
use fandhe_container_core::oci_runtime::{ProcessLauncher, StartTimeouts, create, start};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ContainerStatus, CreateRequest, CreateStateRequest,
    DeleteStateRequest, DeleteStateResponse, ErrorCode, GetStateRequest, ListStateRequest,
    StartRequest, StateList, StateRecord, StateRevision, StateStore, TraitError,
    UpdateStateRequest,
};
use serde_json::{Value, json};

#[cfg(target_os = "linux")]
use std::num::NonZeroU32;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicU32};

#[cfg(target_os = "linux")]
use fandhe_container_core::oci_runtime::{LaunchSpec, LaunchedProcess, NamespaceKind, ProcessExit};

/// テスト専用のインメモリ `StateStore`。revision を 1 から `next()` で進め、`update` は照合する。
struct MemStateStore {
    records: Mutex<HashMap<ContainerId, StateRecord>>,
}

impl MemStateStore {
    fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
        }
    }

    fn record_of(&self, id: &str) -> Result<StateRecord, TraitError> {
        self.get(&GetStateRequest::new(ContainerId::new(id)?))
    }

    fn status_of(&self, id: &str) -> ContainerStatus {
        self.record_of(id).expect("stored").status().clone()
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
            StateRevision::from_raw(1),
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
            cur.revision().next()?,
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

    fn delete(&self, _req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
}

/// `launch` に渡された `LaunchSpec` を所有値で写し取った記録。
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq)]
struct LaunchRecord {
    rootfs: PathBuf,
    args: Vec<String>,
    env: Vec<String>,
    hostname: Option<String>,
    namespaces: Vec<NamespaceKind>,
}

/// `LaunchSpec` を記録し、呼び出し順に pid（101, 102, ...）を払い出す模擬 launcher。
struct RecordingLauncher {
    #[cfg(target_os = "linux")]
    records: Mutex<Vec<LaunchRecord>>,
    launches: AtomicUsize,
    #[cfg(target_os = "linux")]
    next_pid: AtomicU32,
}

impl RecordingLauncher {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            #[cfg(target_os = "linux")]
            records: Mutex::new(Vec::new()),
            launches: AtomicUsize::new(0),
            #[cfg(target_os = "linux")]
            next_pid: AtomicU32::new(101),
        })
    }

    fn launches(&self) -> usize {
        self.launches.load(Ordering::SeqCst)
    }

    #[cfg(target_os = "linux")]
    fn records(&self) -> std::sync::MutexGuard<'_, Vec<LaunchRecord>> {
        self.records.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// 模擬プロセス（固定 pid。terminate 前の wait は `None`、terminate 後は SIGKILL 相当で終了済み）。
#[cfg(target_os = "linux")]
struct FakeProcess {
    pid: NonZeroU32,
    terminated: AtomicBool,
}

#[cfg(target_os = "linux")]
impl LaunchedProcess for FakeProcess {
    fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    fn wait(&self, _timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        if self.terminated.load(Ordering::SeqCst) {
            Ok(Some(ProcessExit::Signaled(9)))
        } else {
            Ok(None)
        }
    }

    fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
        self.terminated.store(true, Ordering::SeqCst);
        Ok(())
    }
}

impl ProcessLauncher for RecordingLauncher {
    #[cfg(target_os = "linux")]
    fn launch(
        &self,
        spec: &LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        self.launches.fetch_add(1, Ordering::SeqCst);
        self.records().push(LaunchRecord {
            rootfs: spec.rootfs().to_path_buf(),
            args: spec.args().to_vec(),
            env: spec.env().to_vec(),
            hostname: spec.hostname().map(str::to_string),
            namespaces: spec.namespaces().to_vec(),
        });
        let pid = NonZeroU32::new(self.next_pid.fetch_add(1, Ordering::SeqCst))
            .ok_or_else(|| TraitError::new(ErrorCode::Internal, "pid overflow"))?;
        Ok(Box::new(FakeProcess {
            pid,
            terminated: AtomicBool::new(false),
        }))
    }

    #[cfg(not(target_os = "linux"))]
    fn launch(
        &self,
        _spec: &fandhe_container_core::oci_runtime::LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn fandhe_container_core::oci_runtime::LaunchedProcess>, TraitError> {
        self.launches.fetch_add(1, Ordering::SeqCst);
        Err(TraitError::new(
            ErrorCode::Internal,
            "launch must not be reached off Linux",
        ))
    }

    fn confirm_no_process(&self, _id: &ContainerId, _timeout: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

/// テストごとに一意な bundle ディレクトリ（`rootfs/` と `config.json` を持ち、終了時に削除）。
struct Bundle {
    dir: PathBuf,
}

impl Bundle {
    fn ready(name: &str, config: &Value) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-core-lifecycle-it-{name}-{}",
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
        CreateRequest::new(ContainerId::new(id).expect("id"), self.dir.clone())
            .expect("absolute bundle")
    }
}

impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// start の fail-closed 検査に当たらない起動可能な最小 config（`tag` で args を区別する）。
fn lifecycle_config(tag: &str) -> Value {
    json!({
        "ociVersion": "1.2.0",
        "root": {"path": "rootfs"},
        "process": {
            "user": {"uid": 0, "gid": 0},
            "args": ["/bin/echo", tag],
            "env": ["PATH=/usr/bin:/bin", "LIFECYCLE=1"],
            "cwd": "/"
        },
        "hostname": "lifecycle",
        "linux": {"namespaces": [
            {"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"}, {"type": "ipc"}
        ]}
    })
}

fn start_req(id: &str) -> StartRequest {
    StartRequest::new(ContainerId::new(id).expect("id"))
}

fn op_stats(rec: &OpRecorder, name: &str) -> (u64, u64) {
    let stats = rec
        .snapshot_op(&OpName::new(name).expect("name"))
        .expect("recorded");
    (stats.success(), stats.failure())
}

/// CORE-2・OCI-4: create → start の一連フロー。各遷移の状態・revision・`LaunchSpec`・観測記録・
/// ハンドルの引き渡しを具体値で確かめる。
#[cfg(target_os = "linux")]
#[test]
fn oci4_core2_create_then_start_full_lifecycle() {
    let b = Bundle::ready("full", &lifecycle_config("lifecycle"));
    let store = MemStateStore::new();
    let rec = OpRecorder::new();
    let launcher = RecordingLauncher::new();
    let dynl: Arc<dyn ProcessLauncher> = launcher.clone();
    let id = "lc-full";

    // create 前は状態なし・start は NotFound（launcher は呼ばれない）。
    assert_eq!(
        store.record_of(id).expect_err("absent").code(),
        ErrorCode::NotFound
    );
    let err = start(
        &store,
        &rec,
        &dynl,
        &start_req(id),
        &StartTimeouts::default(),
    )
    .expect_err("start before create");
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(launcher.launches(), 0);

    // create: Created・pid なし・revision 1。
    let created = create(&store, &rec, &b.create_request(id)).expect("create");
    assert_eq!(created.status().state(), ContainerState::Created);
    assert_eq!(created.status().pid(), None);
    assert_eq!(created.bundle(), b.dir.as_path());
    assert_eq!(created.revision().value(), 1);
    assert_eq!(store.record_of(id).expect("stored"), created);

    // 重複 create は AlreadyExists で状態を変えない。
    let err = create(&store, &rec, &b.create_request(id)).expect_err("duplicate create");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    assert_eq!(store.record_of(id).expect("stored"), created);

    // start: Running・launcher が払い出した pid・store と一致。
    let started = start(
        &store,
        &rec,
        &dynl,
        &start_req(id),
        &StartTimeouts::default(),
    )
    .expect("start");
    assert_eq!(started.record().status().state(), ContainerState::Running);
    assert_eq!(started.record().status().pid(), NonZeroU32::new(101));
    assert_eq!(started.record().bundle(), b.dir.as_path());
    assert_eq!(&store.record_of(id).expect("stored"), started.record());
    // 起動権の予約 update と Running 記録の update の 2 回で revision 1 → 3。
    assert_eq!(started.record().revision().value(), 3);

    // LaunchSpec の全フィールド。
    assert_eq!(launcher.launches(), 1);
    assert_eq!(
        *launcher.records(),
        [LaunchRecord {
            rootfs: b.dir.join("rootfs"),
            args: vec!["/bin/echo".to_string(), "lifecycle".to_string()],
            env: vec!["PATH=/usr/bin:/bin".to_string(), "LIFECYCLE=1".to_string()],
            hostname: Some("lifecycle".to_string()),
            namespaces: vec![
                NamespaceKind::Pid,
                NamespaceKind::Mount,
                NamespaceKind::User,
                NamespaceKind::Uts,
                NamespaceKind::Ipc,
            ],
        }]
    );

    // 再 start は FailedPrecondition で launcher を呼ばない。
    let err = start(
        &store,
        &rec,
        &dynl,
        &start_req(id),
        &StartTimeouts::default(),
    )
    .expect_err("second start");
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);
    assert_eq!(err.message(), "container is not in created state");
    assert_eq!(launcher.launches(), 1);

    // 観測記録（REPAIR-4）: create は成功 1・失敗 1、start は成功 1・失敗 2。
    assert_eq!(op_stats(&rec, "create"), (1, 1));
    assert_eq!(op_stats(&rec, "start"), (1, 2));

    // ハンドルは呼び出し元へ引き渡され、所有者が回収する（CORE-1）。
    let (_, process) = started.into_parts();
    assert_eq!(process.pid(), NonZeroU32::new(101).expect("nonzero"));
    assert_eq!(process.wait(Duration::ZERO).expect("wait"), None);
    process
        .terminate(Duration::from_secs(1))
        .expect("terminate");
    assert_eq!(
        process.wait(Duration::ZERO).expect("wait"),
        Some(ProcessExit::Signaled(9))
    );
}

/// CORE-2・OCI-4: 同一 store の 2 コンテナが互いに干渉せず Running に至る（pid・bundle・args が個別）。
#[cfg(target_os = "linux")]
#[test]
fn oci4_core2_independent_containers_reach_running() {
    let ba = Bundle::ready("indep-a", &lifecycle_config("alpha"));
    let bb = Bundle::ready("indep-b", &lifecycle_config("beta"));
    let store = MemStateStore::new();
    let rec = OpRecorder::new();
    let launcher = RecordingLauncher::new();
    let dynl: Arc<dyn ProcessLauncher> = launcher.clone();

    create(&store, &rec, &ba.create_request("lc-indep-a")).expect("create a");
    create(&store, &rec, &bb.create_request("lc-indep-b")).expect("create b");

    let a = start(
        &store,
        &rec,
        &dynl,
        &start_req("lc-indep-a"),
        &StartTimeouts::default(),
    )
    .expect("start a");
    // a の start は b（Created・revision 1）に影響しない。
    assert_eq!(
        store.status_of("lc-indep-b").state(),
        ContainerState::Created
    );
    assert_eq!(
        store.record_of("lc-indep-b").expect("b").revision().value(),
        1
    );

    let b = start(
        &store,
        &rec,
        &dynl,
        &start_req("lc-indep-b"),
        &StartTimeouts::default(),
    )
    .expect("start b");

    assert_eq!(a.record().status().state(), ContainerState::Running);
    assert_eq!(b.record().status().state(), ContainerState::Running);
    assert_eq!(a.record().status().pid(), NonZeroU32::new(101));
    assert_eq!(b.record().status().pid(), NonZeroU32::new(102));
    assert_eq!(a.record().bundle(), ba.dir.as_path());
    assert_eq!(b.record().bundle(), bb.dir.as_path());
    assert_eq!(launcher.launches(), 2);
    let args: Vec<Vec<String>> = launcher.records().iter().map(|r| r.args.clone()).collect();
    assert_eq!(
        args,
        [
            vec!["/bin/echo".to_string(), "alpha".to_string()],
            vec!["/bin/echo".to_string(), "beta".to_string()],
        ]
    );

    for started in [a, b] {
        let (_, process) = started.into_parts();
        process
            .terminate(Duration::from_secs(1))
            .expect("terminate");
        assert_eq!(
            process.wait(Duration::ZERO).expect("wait"),
            Some(ProcessExit::Signaled(9))
        );
    }
}

/// SEC-1・CLI-1・CORE-2・OCI-4: Linux 以外は create まで成功し、start は launch 前に Unimplemented で
/// 拒否する（状態は Created・revision 1 のまま）。
#[cfg(not(target_os = "linux"))]
#[test]
fn oci4_core2_lifecycle_fails_closed_off_linux() {
    let b = Bundle::ready("nolinux", &lifecycle_config("lifecycle"));
    let store = MemStateStore::new();
    let rec = OpRecorder::new();
    let launcher = RecordingLauncher::new();
    let dynl: Arc<dyn ProcessLauncher> = launcher.clone();
    let id = "lc-nolinux";

    let created = create(&store, &rec, &b.create_request(id)).expect("create");
    assert_eq!(created.status().state(), ContainerState::Created);
    let err = start(
        &store,
        &rec,
        &dynl,
        &start_req(id),
        &StartTimeouts::default(),
    )
    .expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::Unimplemented);
    assert_eq!(
        err.message(),
        "start requires Linux to pin the rootfs directory"
    );
    assert_eq!(launcher.launches(), 0);
    assert_eq!(store.status_of(id).state(), ContainerState::Created);
    assert_eq!(store.record_of(id).expect("stored").revision().value(), 1);
    assert_eq!(op_stats(&rec, "create"), (1, 0));
    assert_eq!(op_stats(&rec, "start"), (0, 1));
}
