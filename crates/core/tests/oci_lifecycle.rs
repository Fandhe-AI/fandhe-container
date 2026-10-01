//! OCI Runtime ライフサイクル `create` → `start` の一連フローの結合試験（CORE-2・OCI-4・REPAIR-4・TASK-29.4）。
//!
//! 末尾で create / start / kill / delete が 1 つの `OpRecorder` を共有した際の操作別の成功・失敗・所要時間の
//! 反映も照合する（REPAIR-4・TASK-84.4・TASK-30.2）。delete 単体の契約は `oci_delete.rs` が扱う。
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
use fandhe_container_core::oci_runtime::{
    CgroupRemoval, ContainerCgroupRemover, KillTimeout, ProcessLauncher, ProcessSignaler,
    StartTimeouts, create, delete, kill, start,
};
use fandhe_container_core::traits::{
    CgroupScope, ContainerId, ContainerState, ContainerStatus, CreateRequest, CreateStateRequest,
    DeleteRequest, DeleteResponse, DeleteStateRequest, DeleteStateResponse, ErrorCode,
    GetStateRequest, KillRequest, ListStateRequest, Signal, StartRequest, StateList, StateRecord,
    StateRevision, StateStore, TraitError, UpdateStateRequest,
};
use serde_json::{Value, json};

#[cfg(target_os = "linux")]
use std::num::NonZeroU32;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, AtomicU32};

#[cfg(target_os = "linux")]
use fandhe_container_core::oci_runtime::{LaunchSpec, LaunchedProcess, NamespaceKind, ProcessExit};

/// テスト専用の `ContainerCgroupRemover`。cgroup は常に存在しない（`NotPresent`）として扱い、実 cgroup には
/// 触れない（OS 非依存。cgroup 削除の結線は `oci_delete.rs`・`cgroup_delete.rs` が照合する。TASK-30.3）。
/// `oci_runtime::create` は cgroup スコープを記録しないため、delete は本 fake を呼ばない。呼ばれた場合に
/// 気付けるよう `scope` はエラーを返す（delete は照合できず失敗する）。
struct NoCgroup;

impl ContainerCgroupRemover for NoCgroup {
    fn scope(&self) -> Result<CgroupScope, TraitError> {
        Err(TraitError::new(
            ErrorCode::Internal,
            "no delegated cgroup in this test",
        ))
    }
    fn remove(
        &self,
        _id: &ContainerId,
        _instance: StateRevision,
    ) -> Result<CgroupRemoval, TraitError> {
        Ok(CgroupRemoval::NotPresent)
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

/// `launch` に渡された `LaunchSpec` を所有値で写し取った記録。
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq)]
struct LaunchRecord {
    rootfs: PathBuf,
    /// `LaunchSpec::rootfs_dir()` の固定ハンドルを fstat した (st_dev, st_ino)（SEC-1。fd 固定契約の検証用）。
    pinned_rootfs_id: (u64, u64),
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
        use std::os::unix::fs::MetadataExt;
        self.launches.fetch_add(1, Ordering::SeqCst);
        // 固定ハンドルが有効な fd であることを fstat で確かめ、指す inode を記録する。
        let pinned = std::fs::File::from(
            spec.rootfs_dir()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| TraitError::new(ErrorCode::Internal, "pinned rootfs fd is invalid"))?,
        )
        .metadata()
        .map_err(|_| TraitError::new(ErrorCode::Internal, "pinned rootfs fstat failed"))?;
        self.records().push(LaunchRecord {
            rootfs: spec.rootfs().to_path_buf(),
            pinned_rootfs_id: (pinned.dev(), pinned.ino()),
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
    // 固定ハンドルは bundle の rootfs ディレクトリそのもの（bundle 直下ではない）を指す（SEC-1）。
    let expected_rootfs = std::fs::metadata(b.dir.join("rootfs")).expect("stat rootfs");
    let bundle_meta = std::fs::metadata(&b.dir).expect("stat bundle");
    let pinned_id = {
        use std::os::unix::fs::MetadataExt;
        let id = launcher.records()[0].pinned_rootfs_id;
        assert_eq!(id, (expected_rootfs.dev(), expected_rootfs.ino()));
        assert_ne!(id, (bundle_meta.dev(), bundle_meta.ino()));
        id
    };
    assert_eq!(
        *launcher.records(),
        [LaunchRecord {
            rootfs: b.dir.join("rootfs"),
            pinned_rootfs_id: pinned_id,
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
    // a の start は b（Created・revision 2）に影響しない。revision はストア全体の単調採番のため、
    // a は create 1 → 予約 3 → Running 4、b は create 2 のまま（OCI-5）。
    assert_eq!(
        store.status_of("lc-indep-b").state(),
        ContainerState::Created
    );
    assert_eq!(
        store.record_of("lc-indep-b").expect("b").revision().value(),
        2
    );
    assert_eq!(a.record().revision().value(), 4);

    let b = start(
        &store,
        &rec,
        &dynl,
        &start_req("lc-indep-b"),
        &StartTimeouts::default(),
    )
    .expect("start b");
    assert_eq!(b.record().revision().value(), 6);

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

/// 受け取った引数を捨てて常に成功を返す模擬 `ProcessSignaler`（実プロセスへは送信しない）。
/// 本番実装は supervisor（TASK-157）側で提供される。
struct NoopSignaler;

impl ProcessSignaler for NoopSignaler {
    fn signal(
        &self,
        _id: &ContainerId,
        _pid: std::num::NonZeroU32,
        _signal: Signal,
        _deadline: std::time::Instant,
    ) -> Result<(), TraitError> {
        Ok(())
    }
}

/// `export_json_lines` の出力を行単位で取り出す。
#[cfg(target_os = "linux")]
fn export_lines(rec: &OpRecorder) -> Vec<String> {
    let mut buf: Vec<u8> = Vec::new();
    rec.export_json_lines(Some(&mut buf)).expect("export");
    String::from_utf8(buf)
        .expect("utf8")
        .lines()
        .map(str::to_string)
        .collect()
}

/// REPAIR-4・TASK-84.4・TASK-30.2: create → start → kill → delete が 1 つの `OpRecorder` を共有し、操作ごとの
/// 成功・失敗件数と所要時間が `OpStats` に反映され、JSON Lines にも出ること（受け入れ条件の機械照合）。
///
/// kill は状態を更新しないため、kill 直後の delete は Running・pid ありとして `FailedPrecondition` になる
/// （CORE-2）。Stopped への遷移は起動ハンドルの所有者（supervisor。TASK-157）の責務のため、本テストでは
/// ハンドルの回収後にその代わりとして `StateStore::update` で Stopped を書き、delete が成功して以後の get が
/// `NotFound` になること（OCI-6）を確かめる。p95 等の分布の検証は TASK-84.6（`tests/observability.rs`）の範囲。
#[cfg(target_os = "linux")]
#[test]
fn repair4_task84_4_lifecycle_ops_share_one_recorder() {
    let b = Bundle::ready("shared-rec", &lifecycle_config("shared"));
    let store = MemStateStore::new();
    let rec = OpRecorder::new();
    let launcher = RecordingLauncher::new();
    let dynl: Arc<dyn ProcessLauncher> = launcher.clone();
    let signaler: Arc<dyn ProcessSignaler> = Arc::new(NoopSignaler);
    let id = "lc-shared";

    // 成功: create → start → kill。
    create(&store, &rec, &b.create_request(id)).expect("create");
    let started = start(
        &store,
        &rec,
        &dynl,
        &start_req(id),
        &StartTimeouts::default(),
    )
    .expect("start");
    kill(
        &store,
        &rec,
        &signaler,
        &KillRequest::new(ContainerId::new(id).expect("id"), Signal::SIGTERM),
        &KillTimeout::default(),
    )
    .expect("kill");

    // 失敗: kill 直後（Running・pid あり）の delete は拒否され、状態は残る（CORE-2）。
    let cid = ContainerId::new(id).expect("id");
    let err = delete(&store, &rec, &NoCgroup, &DeleteRequest::new(cid.clone()))
        .expect_err("delete running");
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);
    assert_eq!(err.message(), "container is still running");
    let running = store.record_of(id).expect("kept");
    assert_eq!(running.status().state(), ContainerState::Running);

    // 失敗: 重複 create・Running への再 start・未 create ID への kill。
    let err = create(&store, &rec, &b.create_request(id)).expect_err("duplicate create");
    assert_eq!(err.code(), ErrorCode::AlreadyExists);
    let err = start(
        &store,
        &rec,
        &dynl,
        &start_req(id),
        &StartTimeouts::default(),
    )
    .expect_err("second start");
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);
    let err = kill(
        &store,
        &rec,
        &signaler,
        &KillRequest::new(ContainerId::new("lc-missing").expect("id"), Signal::SIGTERM),
        &KillTimeout::default(),
    )
    .expect_err("kill missing");
    assert_eq!(err.code(), ErrorCode::NotFound);

    // 成功: ハンドルを回収し、supervisor（TASK-157）の代わりに Stopped を書いてから delete する（OCI-6）。
    let (_, process) = started.into_parts();
    process
        .terminate(Duration::from_secs(1))
        .expect("terminate");
    store
        .update(&UpdateStateRequest::new(
            ContainerStatus::stopped(cid.clone(), Some(137)),
            running.revision(),
        ))
        .expect("stopped");
    assert_eq!(
        delete(&store, &rec, &NoCgroup, &DeleteRequest::new(cid.clone())).expect("delete stopped"),
        DeleteResponse::new()
    );
    assert_eq!(
        store.record_of(id).expect_err("deleted").code(),
        ErrorCode::NotFound
    );

    // 操作名は名前昇順でちょうど 4 件。各操作は成功 1・失敗 1・所要時間あり。
    let snap = rec.snapshot();
    let names: Vec<&str> = snap.iter().map(|s| s.name().as_str()).collect();
    assert_eq!(names, ["create", "delete", "kill", "start"]);
    for s in &snap {
        assert_eq!(s.success(), 1, "{}", s.name().as_str());
        assert_eq!(s.failure(), 1, "{}", s.name().as_str());
        assert_eq!(s.total(), 2, "{}", s.name().as_str());
        assert!(s.latency().is_some(), "{}", s.name().as_str());
    }

    // JSON Lines: op 行 4 件 + メタ行（レイテンシ値は非決定のため値照合しない）。
    let lines = export_lines(&rec);
    assert_eq!(lines.len(), 5);
    for (line, op) in lines.iter().zip(["create", "delete", "kill", "start"]) {
        assert!(line.contains(&format!("\"op\":\"{op}\"")), "{line}");
        assert!(
            line.contains("\"success\":1,\"failure\":1,\"count\":2"),
            "{line}"
        );
    }
    assert_eq!(
        lines[4],
        "{\"event\":\"op_stats_meta\",\"ops\":4,\"dropped_records\":0}"
    );
}

/// REPAIR-4・TASK-84.4: Linux 以外でも create 成功・start（`Unimplemented`）・kill（pid なしの Created で
/// `FailedPrecondition`）・delete（成功と二重 delete の `NotFound`。TASK-30.2）の結果が 1 つの `OpRecorder` に
/// 操作別で反映される。
#[cfg(not(target_os = "linux"))]
#[test]
fn repair4_task84_4_lifecycle_ops_share_one_recorder_off_linux() {
    let b = Bundle::ready("shared-rec-nolinux", &lifecycle_config("shared"));
    let store = MemStateStore::new();
    let rec = OpRecorder::new();
    let launcher = RecordingLauncher::new();
    let dynl: Arc<dyn ProcessLauncher> = launcher.clone();
    let signaler: Arc<dyn ProcessSignaler> = Arc::new(NoopSignaler);
    let id = "lc-shared-nolinux";

    create(&store, &rec, &b.create_request(id)).expect("create");
    let err = start(
        &store,
        &rec,
        &dynl,
        &start_req(id),
        &StartTimeouts::default(),
    )
    .expect_err("start off linux");
    assert_eq!(err.code(), ErrorCode::Unimplemented);
    let err = kill(
        &store,
        &rec,
        &signaler,
        &KillRequest::new(ContainerId::new(id).expect("id"), Signal::SIGTERM),
        &KillTimeout::default(),
    )
    .expect_err("kill created without pid");
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);

    // start が予約の前に拒否したため Created・pid なしのままで、delete は成功し、二重 delete は NotFound
    // （OCI-6・TASK-30.2）。
    let req = DeleteRequest::new(ContainerId::new(id).expect("id"));
    assert_eq!(
        delete(&store, &rec, &NoCgroup, &req).expect("delete created"),
        DeleteResponse::new()
    );
    let err = delete(&store, &rec, &NoCgroup, &req).expect_err("second delete");
    assert_eq!(err.code(), ErrorCode::NotFound);

    assert_eq!(op_stats(&rec, "create"), (1, 0));
    assert_eq!(op_stats(&rec, "start"), (0, 1));
    assert_eq!(op_stats(&rec, "kill"), (0, 1));
    assert_eq!(op_stats(&rec, "delete"), (1, 1));
}
