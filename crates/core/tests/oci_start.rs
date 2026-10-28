//! `oci_runtime::start` の結合試験（OCI-4・CORE-1・CORE-2・OCI-5・SUP-6・SEC-1・REPAIR-5・TASK-29.3）。
//!
//! 公開 API（`create`・`start`・`recover_interrupted_start`・`StateStore`・`ProcessLauncher`・
//! `LaunchedProcess`）だけを crate の外から呼び、create → start の状態遷移・launcher との連携・
//! 応答待ちの上限超過時の後始末を具体値で確かめる。実プロセスは起動しない（launcher は模擬）。
//! 状態ストアは既定でインメモリの模擬だが、`launch_isolation` の往復（OCI-5・SUP-6・#2239）だけは
//! 実 `FileStateStore`（`state.json`）を使う（Linux 限定）。
//!
//! rootfs を fd で固定する start の成功経路は Linux 限定（Linux 以外は起動前に `Unimplemented`）のため、
//! 成功を前提とする試験と中断回復（起動権の所有ロックも Linux 限定）の試験は `cfg(target_os = "linux")`、
//! Linux 以外では fail-closed の拒否を具体値で確かめる。設定検証の試験は 3 OS の既定のテスト集合で動く。
//! 実機権限（root 等）は不要。
//!
//! 待ちの上限は CI の `platform-ci` ジョブが設定する `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`
//! （既定 10 秒。AGENTS.md「推奨タイムアウト値」・REPAIR-5）から組み立てる。

#[path = "support/scratch_root.rs"]
mod scratch_root;

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use fandhe_container_core::dev_mounts::ImplicitDevMount;
use fandhe_container_core::launch_isolation::LaunchIsolationRecord;
#[cfg(target_os = "linux")]
use fandhe_container_core::launch_isolation::{
    RecordedLandlock, RecordedLandlockAudit, RecordedRule, RecordedTarget, RootIdentity,
};
use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    EffectiveNetwork, LaunchNetworkMode, LaunchSpec, LaunchedProcess, LifecycleOp, OciRuntimeError,
    ProcessExit, ProcessLauncher, StartTimeouts, create, recover_interrupted_start, start,
};
#[cfg(target_os = "linux")]
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
#[cfg(target_os = "linux")]
use fandhe_container_core::traits::SupervisionState;
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ContainerStatus, CreateRequest, CreateStateRequest,
    DeleteStateRequest, DeleteStateResponse, ErrorCode, GetStateRequest, ListStateRequest,
    StartRequest, StateList, StateRecord, StateRevision, StateStore, TraitError,
    UpdateStateRequest,
};
use serde_json::{Value, json};

/// 1 件の待ちの上限（`FANDHE_CONTAINER_TEST_TIMEOUT_SECS`。未設定・不正値なら 10 秒）。
#[cfg(target_os = "linux")]
fn test_timeout() -> Duration {
    let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(10);
    Duration::from_secs(secs)
}

/// `cond` が真になるまで `test_timeout()` までポーリングする（固定 sleep に頼らない）。
#[cfg(target_os = "linux")]
fn eventually(cond: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + test_timeout();
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    cond()
}

/// 起動待ち 200ms・終了待ち 1s・確認待ち 200ms の短い上限。
#[cfg(target_os = "linux")]
fn short_timeouts() -> StartTimeouts {
    StartTimeouts::new(
        Duration::from_millis(200),
        Duration::from_secs(1),
        Duration::from_millis(200),
    )
    .expect("timeouts")
}

/// テスト専用のインメモリ `StateStore`。`update` は revision を照合し、n 回目の失敗注入ができる。
struct MemStateStore {
    records: Mutex<HashMap<ContainerId, StateRecord>>,
    fail_update_at: Option<usize>,
    update_calls: AtomicUsize,
    state_root: PathBuf,
    /// 状態ルートの親（tmpfiles の flock 走査から守る）。
    _scratch: scratch_root::ScratchDir,
}

impl MemStateStore {
    fn new(fail_update_at: Option<usize>) -> Self {
        let scratch = scratch_root::ScratchDir::new(
            "fandhe-core-start-it-mem",
            std::time::Duration::from_secs(10),
        );
        Self {
            records: Mutex::new(HashMap::new()),
            fail_update_at,
            update_calls: AtomicUsize::new(0),
            state_root: scratch.path().to_path_buf(),
            _scratch: scratch,
        }
    }

    fn status_of(&self, id: &str) -> ContainerStatus {
        self.get(&GetStateRequest::new(ContainerId::new(id).expect("id")))
            .expect("stored")
            .status()
            .clone()
    }
}

impl StateStore for MemStateStore {
    /// bind mount の検証を通すための状態ルート（実在し、bind の元にならない場所）。
    fn host_state_root(&self) -> Option<&std::path::Path> {
        Some(self.state_root.as_path())
    }

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
        let n = self.update_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_update_at == Some(n) {
            return Err(TraitError::new(ErrorCode::FailedPrecondition, "conflict"));
        }
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

/// 開くまで呼び出しを塞ぐ門（上限を守らず戻らない launcher の模擬）。
struct Gate {
    open: Mutex<bool>,
    cvar: Condvar,
}

impl Gate {
    fn new(open: bool) -> Self {
        Self {
            open: Mutex::new(open),
            cvar: Condvar::new(),
        }
    }

    #[cfg(target_os = "linux")]
    fn set_open(&self, open: bool) {
        *self.open.lock().unwrap_or_else(|e| e.into_inner()) = open;
        self.cvar.notify_all();
    }

    /// 門が開くまで待つ（試験が固まらないよう最大 30 秒で諦める）。
    fn pass(&self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        while !*open {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            open = self
                .cvar
                .wait_timeout(open, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

/// 起動を記録して固定 pid 7 の模擬プロセスを返す launcher。
struct FakeLauncher {
    launched_args: Mutex<Vec<Vec<String>>>,
    /// 起動ごとに渡された bind mount の (宛先, 元)(#1915)。
    launched_binds: Mutex<Vec<Vec<(String, String)>>>,
    terminated: Arc<AtomicUsize>,
    confirms_no_process: AtomicBool,
    /// 起動した模擬プロセスの terminate を失敗させるか。
    fail_terminate: AtomicBool,
    gate: Gate,
    /// `network_mode` が返す起動オプションのモード（既定 `FromConfig`。NET-6・#3058）。
    network_mode: Mutex<LaunchNetworkMode>,
    /// 起動ごとに渡された spec の実効 network（NET-6・#3058）。
    launched_networks: Mutex<Vec<EffectiveNetwork>>,
    /// 起動した模擬プロセスが返す launch 時の分離の記録（既定は `None`）。
    #[cfg(target_os = "linux")]
    isolation: Mutex<Option<LaunchIsolationRecord>>,
}

impl FakeLauncher {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            launched_args: Mutex::new(Vec::new()),
            launched_binds: Mutex::new(Vec::new()),
            terminated: Arc::new(AtomicUsize::new(0)),
            confirms_no_process: AtomicBool::new(true),
            fail_terminate: AtomicBool::new(false),
            gate: Gate::new(true),
            network_mode: Mutex::new(LaunchNetworkMode::FromConfig),
            launched_networks: Mutex::new(Vec::new()),
            #[cfg(target_os = "linux")]
            isolation: Mutex::new(None),
        })
    }

    fn set_network_mode(&self, mode: LaunchNetworkMode) {
        *self.network_mode.lock().unwrap_or_else(|e| e.into_inner()) = mode;
    }

    #[cfg(target_os = "linux")]
    fn set_isolation(&self, rec: LaunchIsolationRecord) {
        *self.isolation.lock().unwrap_or_else(|e| e.into_inner()) = Some(rec);
    }

    /// 模擬プロセスへ持たせる分離の記録（Linux 以外では常に `None`）。
    fn current_isolation(&self) -> Option<LaunchIsolationRecord> {
        #[cfg(target_os = "linux")]
        {
            self.isolation
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    fn launches(&self) -> usize {
        self.launched_args
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    #[cfg(target_os = "linux")]
    fn terminations(&self) -> usize {
        self.terminated.load(Ordering::SeqCst)
    }
}

/// 模擬プロセス（terminate の回数を数え、terminate 後は SIGKILL 相当で終了済みになる。第 2 要素が
/// 真なら terminate は失敗を返す）。
struct FakeProcess(Arc<AtomicUsize>, bool, Option<LaunchIsolationRecord>);

impl LaunchedProcess for FakeProcess {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(7).expect("nonzero")
    }

    fn launch_isolation(&self) -> Option<&LaunchIsolationRecord> {
        self.2.as_ref()
    }

    fn wait(&self, _timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        if self.0.load(Ordering::SeqCst) > 0 {
            Ok(Some(ProcessExit::Signaled(9)))
        } else {
            Ok(None)
        }
    }

    fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        if self.1 {
            return Err(TraitError::new(ErrorCode::Internal, "terminate failed"));
        }
        Ok(())
    }
}

impl ProcessLauncher for FakeLauncher {
    fn network_mode(&self) -> LaunchNetworkMode {
        *self.network_mode.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn launch(
        &self,
        spec: &LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        self.launched_args
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(spec.args().to_vec());
        self.launched_networks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(spec.network());
        self.launched_binds
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(
                spec.bind_mounts()
                    .mounts()
                    .iter()
                    .map(|m| (m.destination().as_str().to_owned(), m.source().to_owned()))
                    .collect(),
            );
        self.gate.pass();
        Ok(Box::new(FakeProcess(
            self.terminated.clone(),
            self.fail_terminate.load(Ordering::SeqCst),
            self.current_isolation(),
        )))
    }

    fn confirm_no_process(&self, _id: &ContainerId, _timeout: Duration) -> Result<(), TraitError> {
        self.gate.pass();
        if self.confirms_no_process.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(TraitError::new(ErrorCode::Unimplemented, "cannot confirm"))
        }
    }
}

fn dynl(l: &Arc<FakeLauncher>) -> Arc<dyn ProcessLauncher> {
    l.clone()
}

/// テストごとに一意な bundle ディレクトリ（終了時に削除）。
struct Bundle {
    dir: PathBuf,
    /// bundle の親（tmpfiles の flock 走査から守る。最後に drop される）。
    _scratch: scratch_root::ScratchDir,
}

impl Bundle {
    fn ready(name: &str, config: &Value) -> Self {
        let scratch = scratch_root::ScratchDir::new(
            &format!("fandhe-core-start-it-{name}"),
            std::time::Duration::from_secs(10),
        );
        let dir = scratch.path().join("bundle");
        std::fs::create_dir_all(dir.join("rootfs")).expect("create bundle dir");
        std::fs::write(
            dir.join("config.json"),
            serde_json::to_vec(config).expect("serialize"),
        )
        .expect("write config");
        Self {
            dir,
            _scratch: scratch,
        }
    }

    fn create(&self, store: &dyn StateStore, id: &str) {
        let req = CreateRequest::new(ContainerId::new(id).expect("id"), self.dir.clone())
            .expect("absolute bundle");
        create(store, &OpRecorder::new(), &req).expect("create");
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
            "args": ["/bin/echo", "it"],
            "cwd": "/"
        },
        "linux": {"namespaces": [
            {"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"}, {"type": "ipc"}
        ]}
    })
}

fn start_req(id: &str) -> StartRequest {
    StartRequest::new(ContainerId::new(id).expect("id"))
}

/// OCI-4・CORE-1・CORE-2: create → start で Running・pid 7 へ遷移し、起動済みプロセスのハンドルが
/// 呼び出し元へ引き渡される。再 start は FailedPrecondition で launcher を呼ばない。
#[cfg(target_os = "linux")]
#[test]
fn oci4_create_then_start_hands_over_running_process() {
    let b = Bundle::ready("ok", &valid_config());
    let store = MemStateStore::new(None);
    b.create(&store, "it-ok");
    let launcher = FakeLauncher::new();
    let started = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-ok"),
        &StartTimeouts::default(),
    )
    .expect("start");
    assert_eq!(started.record().status().state(), ContainerState::Running);
    assert_eq!(started.record().status().pid(), NonZeroU32::new(7));
    assert_eq!(store.status_of("it-ok"), started.record().status().clone());
    assert_eq!(
        *launcher.launched_args.lock().expect("lock"),
        [vec!["/bin/echo".to_string(), "it".to_string()]]
    );
    let err = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-ok"),
        &StartTimeouts::default(),
    )
    .expect_err("second start");
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);
    assert_eq!(err.message(), "container is not in created state");
    assert_eq!(launcher.launches(), 1);
    let (_, process) = started.into_parts();
    process
        .terminate(Duration::from_secs(1))
        .expect("terminate");
    assert_eq!(
        process.wait(Duration::ZERO).expect("wait"),
        Some(ProcessExit::Signaled(9))
    );
}

/// SEC-1・CLI-1: Linux 以外は rootfs を fd で固定できないため、予約・launch の前に Unimplemented で拒否する。
#[cfg(not(target_os = "linux"))]
#[test]
fn sec1_start_fails_closed_off_linux() {
    let b = Bundle::ready("nolinux", &valid_config());
    let store = MemStateStore::new(None);
    b.create(&store, "it-nolinux");
    let launcher = FakeLauncher::new();
    let err = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-nolinux"),
        &StartTimeouts::default(),
    )
    .expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::Unimplemented);
    assert_eq!(
        err.message(),
        "start requires Linux to pin the rootfs directory"
    );
    assert_eq!(launcher.launches(), 0);
    assert_eq!(
        store.status_of("it-nolinux").state(),
        ContainerState::Created
    );
}

/// SEC-1・CORE-1: create 後に UTS namespace を外した config は、launcher を呼ばずに InvalidArgument。
#[test]
fn sec1_start_rejects_config_rewritten_without_uts() {
    let b = Bundle::ready("nouts", &valid_config());
    let store = MemStateStore::new(None);
    b.create(&store, "it-nouts");
    let mut cfg = valid_config();
    cfg["linux"]["namespaces"] =
        json!([{"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "ipc"}]);
    std::fs::write(
        b.dir.join("config.json"),
        serde_json::to_vec(&cfg).expect("serialize"),
    )
    .expect("rewrite");
    let launcher = FakeLauncher::new();
    let err = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-nouts"),
        &StartTimeouts::default(),
    )
    .expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(err.message(), "the UTS namespace is required");
    assert_eq!(launcher.launches(), 0);
    assert_eq!(store.status_of("it-nouts").state(), ContainerState::Created);
}

/// REPAIR-5・CORE-2: launch が戻らなければ start は有限時間で Timeout を返し、予約を残す。launch が
/// 進行中の間は回復も拒否し、遅れて返ったプロセスを terminate した後に回復できる。
#[cfg(target_os = "linux")]
#[test]
fn repair5_start_bounds_hanging_launch_and_cleans_up_late_process() {
    let b = Bundle::ready("hang", &valid_config());
    let store = MemStateStore::new(None);
    b.create(&store, "it-hang");
    let launcher = FakeLauncher::new();
    launcher.gate.set_open(false);
    let begin = Instant::now();
    let err = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-hang"),
        &short_timeouts(),
    )
    .expect_err("must time out");
    assert!(begin.elapsed() < test_timeout(), "{:?}", begin.elapsed());
    assert_eq!(err.code(), ErrorCode::Timeout);
    let status = store.status_of("it-hang");
    assert_eq!(
        (status.state(), status.pid()),
        (ContainerState::Running, None)
    );
    let id = ContainerId::new("it-hang").expect("id");
    let err = recover_interrupted_start(&store, &dynl(&launcher), &id, &short_timeouts())
        .expect_err("launch in flight");
    assert_eq!(err.message(), "container start is already in progress");
    // 別プロセスからは、launch の進行中は所有ロック（bundle の flock）が取れないことで観測できる。
    let probe = std::fs::File::open(&b.dir).expect("open bundle");
    assert!(matches!(
        probe.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    launcher.gate.set_open(true);
    assert!(eventually(|| launcher.terminations() == 1));
    assert!(eventually(|| probe.try_lock().is_ok()));
    drop(probe);
    assert!(eventually(|| {
        recover_interrupted_start(&store, &dynl(&launcher), &id, &short_timeouts()).is_ok()
    }));
    assert_eq!(store.status_of("it-hang").state(), ContainerState::Created);
    assert_eq!(launcher.launches(), 1);
}

/// REPAIR-5・CORE-2: Running の記録に失敗したら起動済みプロセスを terminate し、予約を Created へ戻す。
#[cfg(target_os = "linux")]
#[test]
fn repair5_start_terminates_process_when_recording_fails() {
    let b = Bundle::ready("recfail", &valid_config());
    // update の 0 回目は起動権の予約、1 回目が Running（pid 付き）の記録。
    let store = MemStateStore::new(Some(1));
    b.create(&store, "it-recfail");
    let launcher = FakeLauncher::new();
    let err = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-recfail"),
        &short_timeouts(),
    )
    .expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);
    assert_eq!(launcher.terminations(), 1);
    let status = store.status_of("it-recfail");
    assert_eq!(
        (status.state(), status.pid()),
        (ContainerState::Created, None)
    );
}

/// REPAIR-5・CORE-1: 記録失敗後の terminate も失敗したら Internal を返して予約を残し、回収を確認
/// できなかったハンドルは `take_unreaped_processes` で監視側が引き取れる（この結合試験で未回収を作るのは
/// 本試験だけ）。
#[cfg(target_os = "linux")]
#[test]
fn repair5_unreaped_handle_is_handed_to_monitor() {
    let b = Bundle::ready("unreaped", &valid_config());
    let store = MemStateStore::new(Some(1));
    b.create(&store, "it-unreaped");
    let launcher = FakeLauncher::new();
    launcher.fail_terminate.store(true, Ordering::SeqCst);
    let err = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-unreaped"),
        &short_timeouts(),
    )
    .expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::Internal);
    assert_eq!(
        err.message(),
        "failed to record running state and failed to terminate the launched process"
    );
    let status = store.status_of("it-unreaped");
    assert_eq!(
        (status.state(), status.pid()),
        (ContainerState::Running, None)
    );
    use fandhe_container_core::oci_runtime::take_unreaped_processes;
    let kept = take_unreaped_processes();
    let pids: Vec<u32> = kept.iter().map(|p| p.pid().get()).collect();
    assert_eq!(pids, [7]);
    assert!(take_unreaped_processes().is_empty());
}

/// 中断された予約（Running・pid なし）を手で作る（start のプロセスが launch 中に異常終了した状態）。
fn claim_interrupted(store: &MemStateStore, id: &ContainerId) {
    let rec = store.get(&GetStateRequest::new(id.clone())).expect("get");
    store
        .update(&UpdateStateRequest::new(
            ContainerStatus::running(id.clone(), None),
            rec.revision(),
        ))
        .expect("claim");
}

/// CORE-2・SEC-1: 別プロセスが起動権の所有ロック（bundle ディレクトリの flock）を持つ間は回復を拒否し、
/// 所有者が終了してロックが外れれば回復できる（呼び出し元の事前確認に依存しない）。flock は同一
/// プロセス内でも別に開いた記述子同士で競合するため、別の記述子で別プロセスの所有者を模す。
#[cfg(target_os = "linux")]
#[test]
fn core2_recover_waits_for_owner_process_across_processes() {
    let b = Bundle::ready("owner", &valid_config());
    let store = MemStateStore::new(None);
    b.create(&store, "it-owner");
    let id = ContainerId::new("it-owner").expect("id");
    claim_interrupted(&store, &id);
    let other_owner = std::fs::File::open(&b.dir).expect("open bundle");
    other_owner.try_lock().expect("lock bundle");
    let launcher = FakeLauncher::new();
    let err = recover_interrupted_start(&store, &dynl(&launcher), &id, &short_timeouts())
        .expect_err("owner alive");
    assert_eq!(err.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        err.message(),
        "container start is in progress in another process"
    );
    assert_eq!(store.status_of("it-owner").state(), ContainerState::Running);
    drop(other_owner);
    let got = recover_interrupted_start(&store, &dynl(&launcher), &id, &short_timeouts())
        .expect("owner gone");
    assert_eq!(got.status().state(), ContainerState::Created);
}

/// SEC-1・CLI-1: Linux 以外は所有ロックを取れないため、回復は Unimplemented で予約を残す。
#[cfg(not(target_os = "linux"))]
#[test]
fn core2_recover_fails_closed_off_linux() {
    let b = Bundle::ready("recover-nolinux", &valid_config());
    let store = MemStateStore::new(None);
    b.create(&store, "it-recover-nolinux");
    let id = ContainerId::new("it-recover-nolinux").expect("id");
    claim_interrupted(&store, &id);
    let launcher = FakeLauncher::new();
    let err = recover_interrupted_start(&store, &dynl(&launcher), &id, &StartTimeouts::default())
        .expect_err("must fail");
    assert_eq!(err.code(), ErrorCode::Unimplemented);
    assert_eq!(
        err.message(),
        "start requires Linux to lock the bundle directory"
    );
    assert_eq!(
        store.status_of("it-recover-nolinux").state(),
        ContainerState::Running
    );
}

/// REPAIR-5・CORE-2: 中断回復の生存確認が戻らなければ Timeout で予約を残し、確認が戻れば回復できる。
#[cfg(target_os = "linux")]
#[test]
fn repair5_recover_bounds_hanging_confirmation() {
    let b = Bundle::ready("confirm", &valid_config());
    let store = MemStateStore::new(None);
    b.create(&store, "it-confirm");
    let id = ContainerId::new("it-confirm").expect("id");
    claim_interrupted(&store, &id);
    let launcher = FakeLauncher::new();
    launcher.gate.set_open(false);
    let begin = Instant::now();
    let err = recover_interrupted_start(&store, &dynl(&launcher), &id, &short_timeouts())
        .expect_err("must time out");
    assert!(begin.elapsed() < test_timeout(), "{:?}", begin.elapsed());
    assert_eq!(err.code(), ErrorCode::Timeout);
    assert_eq!(
        store.status_of("it-confirm").state(),
        ContainerState::Running
    );
    // 確認が終わるまでは回復の再試行を拒否する（遅れた確認が後続のプロセスを終了させないため）。
    let err = recover_interrupted_start(&store, &dynl(&launcher), &id, &short_timeouts())
        .expect_err("confirmation in flight");
    assert_eq!(err.message(), "container start is already in progress");
    launcher.gate.set_open(true);
    assert!(eventually(|| {
        recover_interrupted_start(&store, &dynl(&launcher), &id, &short_timeouts()).is_ok()
    }));
    assert_eq!(
        store.status_of("it-confirm").state(),
        ContainerState::Created
    );
}

/// ERR-2・TASK-96.2: 未作成コンテナの start は launcher を呼ばず、op = start・code = NOT_FOUND・
/// 終了コード 3・構造化 1 行 JSON で失敗する。
#[test]
fn err2_start_unknown_container_yields_structured_error() {
    let store = MemStateStore::new(None);
    let launcher = FakeLauncher::new();
    let err = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-err2-missing"),
        &StartTimeouts::default(),
    )
    .expect_err("must fail");
    assert_eq!(err.op(), LifecycleOp::Start);
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert_eq!(err.exit_code().get(), 3);
    assert_eq!(launcher.launches(), 0);
    let mut out = Vec::new();
    err.write_json_line(&mut out).expect("write");
    let line = String::from_utf8(out).expect("utf8");
    let v: Value = serde_json::from_str(line.trim_end()).expect("json");
    assert_eq!(v["op"], "start");
    assert_eq!(v["code"], "NOT_FOUND");
    assert_eq!(v["message"], err.message());
}

/// OCI-4・SEC-1(#1915): bind mount つきの config は検証を通って launcher へ `bind_mounts()` として渡る。
#[cfg(target_os = "linux")]
#[test]
fn oci4_start_hands_validated_bind_mounts_to_launcher() {
    let mut cfg = valid_config();
    cfg["mounts"] = json!([
        {"destination": "/data", "type": "bind", "source": "/srv/data", "options": ["rbind", "rw"]},
        {"destination": "/cache", "type": "bind", "source": "/srv/cache", "options": ["bind", "noexec"]}
    ]);
    let b = Bundle::ready("binds", &cfg);
    let store = MemStateStore::new(None);
    b.create(&store, "it-binds");
    let launcher = FakeLauncher::new();
    let started = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-binds"),
        &StartTimeouts::default(),
    )
    .expect("start");
    assert_eq!(
        *launcher.launched_binds.lock().expect("lock"),
        [vec![
            ("/data".to_string(), "/srv/data".to_string()),
            ("/cache".to_string(), "/srv/cache".to_string())
        ]]
    );
    let (_, process) = started.into_parts();
    process
        .terminate(Duration::from_secs(1))
        .expect("terminate");
}

/// OCI-4・SEC-1・ERR-2(#1915): 検証を通らない bind は launcher を呼ばず、op = start・code = INVALID_ARGUMENT・
/// 終了コード 2 の構造化エラーで失敗し、状態は Created のまま。
#[test]
fn err2_start_rejects_invalid_bind_mount_with_structured_error() {
    let mut cfg = valid_config();
    cfg["mounts"] = json!([
        {"destination": "/data", "type": "bind", "source": "/srv/data", "options": ["bind", "suid"]}
    ]);
    let b = Bundle::ready("badbind", &valid_config());
    let store = MemStateStore::new(None);
    b.create(&store, "it-badbind");
    std::fs::write(
        b.dir.join("config.json"),
        serde_json::to_vec(&cfg).expect("serialize"),
    )
    .expect("rewrite");
    let launcher = FakeLauncher::new();
    let err = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-badbind"),
        &StartTimeouts::default(),
    )
    .expect_err("must fail");
    assert_eq!(err.op(), LifecycleOp::Start);
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(err.exit_code().get(), 2);
    assert_eq!(
        err.message(),
        "mounts[0]: mount option lifts a mandatory restriction"
    );
    assert_eq!(launcher.launches(), 0);
    assert_eq!(
        store.status_of("it-badbind").state(),
        ContainerState::Created
    );
}

/// 試験用の launch 時の分離の記録。`/`（先頭必須）と暗黙の `/dev` の 2 ルールで、監査の記録も載せる。
#[cfg(target_os = "linux")]
fn iso_record(
    dev: u64,
    ino: u64,
    dev_allowed: u64,
    audit: RecordedLandlockAudit,
) -> LaunchIsolationRecord {
    let landlock = RecordedLandlock::new(
        0x3f,
        vec![
            RecordedRule::new(RecordedTarget::Root, 0x0f),
            RecordedRule::new(RecordedTarget::Implicit(ImplicitDevMount::Dev), dev_allowed),
        ],
    )
    .expect("landlock")
    .with_audit(audit)
    .expect("audit");
    LaunchIsolationRecord::from_parts(RootIdentity::new(dev, ino), landlock)
}

/// 記録の中身を `==`（`Debug` が値を出さない）とは別に、値ごとに照合する。
#[cfg(target_os = "linux")]
fn assert_iso_values(
    rec: Option<&LaunchIsolationRecord>,
    dev: u64,
    ino: u64,
    dev_allowed: u64,
    audit: RecordedLandlockAudit,
) {
    let rec = rec.expect("launch isolation recorded");
    assert_eq!((rec.root().dev(), rec.root().ino()), (dev, ino));
    assert_eq!(rec.landlock().handled(), 0x3f);
    let rules: Vec<(String, u64)> = rec
        .landlock()
        .rules()
        .iter()
        .map(|r| (r.target().as_str().to_owned(), r.allowed()))
        .collect();
    assert_eq!(
        rules,
        [("/".to_owned(), 0x0f), ("/dev".to_owned(), dev_allowed)]
    );
    assert_eq!(rec.landlock().audit(), audit);
}

/// 実 `FileStateStore` 用の状態ルートの親（終了時に削除）。ルート本体は `open` が 0700 で作る。
#[cfg(target_os = "linux")]
struct StateDir {
    dir: PathBuf,
    _scratch: scratch_root::ScratchDir,
}

#[cfg(target_os = "linux")]
impl StateDir {
    fn new(name: &str) -> Self {
        let scratch = scratch_root::ScratchDir::new(
            &format!("fandhe-core-start-it-state-{name}"),
            std::time::Duration::from_secs(10),
        );
        let dir = scratch.path().join("state-parent");
        std::fs::create_dir_all(&dir).expect("create state parent");
        // 状態ルートの祖先は group / other 書き込み不可でなければ `open` が拒否する（umask に依らず 0700 にする）。
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod state parent");
        }
        Self {
            dir,
            _scratch: scratch,
        }
    }

    fn root(&self) -> PathBuf {
        self.dir.join("state")
    }

    /// 同じルートを開き直す（別プロセスからの読み戻しのモデル）。
    fn open_store(&self) -> FileStateStore {
        FileStateStore::open(StateRoot::from_override(self.root()).expect("state root"))
            .expect("open state store")
    }
}

#[cfg(target_os = "linux")]
impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(target_os = "linux")]
fn get_record(store: &FileStateStore, id: &str) -> StateRecord {
    store
        .get(&GetStateRequest::new(ContainerId::new(id).expect("id")))
        .expect("get")
}

/// OCI-5・SUP-6・CORE-2・REPAIR-12（#2239）: `start` が書いた `launch_isolation` が、実 `FileStateStore` の
/// `state.json` を経て同じ値で読み戻せる（同じストア・開き直したストア・生の JSON の 3 経路）。
#[cfg(target_os = "linux")]
#[test]
fn core2_oci5_sup6_start_persists_launch_isolation_through_file_state_store() {
    let b = Bundle::ready("fiso", &valid_config());
    let sd = StateDir::new("fiso");
    let store = sd.open_store();
    b.create(&store, "it-fiso");
    let launcher = FakeLauncher::new();
    let audit = RecordedLandlockAudit::KernelAuditRequested;
    let rec1 = iso_record(7, 11, 0x3f, audit);
    launcher.set_isolation(rec1.clone());
    let started = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-fiso"),
        &StartTimeouts::default(),
    )
    .expect("start");
    assert_eq!(started.record().status().state(), ContainerState::Running);
    assert_eq!(started.record().status().pid(), NonZeroU32::new(7));
    assert_eq!(started.record().launch_isolation(), Some(&rec1));

    let same = get_record(&store, "it-fiso");
    assert_eq!(same.launch_isolation(), Some(&rec1));
    let reopened = get_record(&sd.open_store(), "it-fiso");
    assert_eq!(reopened.status().state(), ContainerState::Running);
    assert_eq!(reopened.launch_isolation(), Some(&rec1));
    assert_iso_values(reopened.launch_isolation(), 7, 11, 0x3f, audit);

    let raw = std::fs::read(sd.root().join("it-fiso").join("state.json")).expect("state.json");
    let json: Value = serde_json::from_slice(&raw).expect("json");
    assert_eq!(
        json["launchIsolation"],
        json!({
            "root": {"dev": 7, "ino": 11},
            "landlock": {
                "handled": 0x3f,
                "rules": [
                    {"path": "/", "allowed": 0x0f, "origin": "root"},
                    {"path": "/dev", "allowed": 0x3f, "origin": "implicit"}
                ],
                "audit": {"mode": "kernel_audit_requested"}
            }
        })
    );

    let (_, process) = started.into_parts();
    process
        .terminate(Duration::from_secs(1))
        .expect("terminate");
}

/// OCI-5・SUP-6・CORE-2・REPAIR-12（#2239）: restart がストアへ出す書き込みの後も `launch_isolation` が
/// 契約 12 どおりに保たれ・置き換わる。supervisor の `write_relaunched` そのものではなく、それが出す
/// `UpdateStateRequest` を同じ公開型で再現したモデル（supervisor 経由の通し試験は #2238・#2043 の範囲）。
///
/// 注意（#2238 未決定）: 段 2 の「記録の指定が無い Running 更新は前の記録を引き継ぐ」は現行の契約 12 の
/// 照合で、#2238 で「記録の無い再 launch では消す」へ契約が変わるとこのアサーションは反転する。
#[cfg(target_os = "linux")]
#[test]
fn core2_oci5_sup6_launch_isolation_survives_and_is_replaced_across_restart_writes() {
    let b = Bundle::ready("riso", &valid_config());
    let sd = StateDir::new("riso");
    let store = sd.open_store();
    b.create(&store, "it-riso");
    let launcher = FakeLauncher::new();
    let rec1 = iso_record(7, 11, 0x3f, RecordedLandlockAudit::KernelAuditRequested);
    launcher.set_isolation(rec1.clone());
    let started = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req("it-riso"),
        &StartTimeouts::default(),
    )
    .expect("start");
    let id = ContainerId::new("it-riso").expect("id");
    let (_, process) = started.into_parts();
    process
        .terminate(Duration::from_secs(1))
        .expect("terminate");

    // 段 1: supervisor の終了記録（Stopped。記録の指定なし）では消えない。
    let rev = get_record(&sd.open_store(), "it-riso").revision();
    store
        .update(&UpdateStateRequest::new(
            ContainerStatus::stopped(id.clone(), Some(1)),
            rev,
        ))
        .expect("stopped");
    let got = get_record(&sd.open_store(), "it-riso");
    assert_eq!(got.status().state(), ContainerState::Stopped);
    assert_iso_values(
        got.launch_isolation(),
        7,
        11,
        0x3f,
        RecordedLandlockAudit::KernelAuditRequested,
    );

    // 段 2: 記録を持たない再 launch のモデル（Running(8)・記録の指定なし）。現行の契約 12 は引き継ぎ。
    // #2238 で契約が変わると、このアサーションは `None` へ反転する。
    let sup1 = SupervisionState::new(None, None, 1);
    let rev = got.revision();
    store
        .update(
            &UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), NonZeroU32::new(8)),
                rev,
            )
            .with_supervision(sup1),
        )
        .expect("relaunch without record");
    let got = get_record(&sd.open_store(), "it-riso");
    assert_eq!(got.status().pid(), NonZeroU32::new(8));
    assert_eq!(got.launch_isolation(), Some(&rec1));

    // 段 3: 記録を持つ再 launch（本番 launcher のモデル）は置き換える。
    let audit2 = RecordedLandlockAudit::Unavailable { detected_abi: 5 };
    let rec2 = iso_record(8, 12, 0x1f, audit2);
    let rev = got.revision();
    store
        .update(
            &UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), NonZeroU32::new(9)),
                rev,
            )
            .with_supervision(SupervisionState::new(None, None, 2))
            .with_launch_isolation(rec2.clone()),
        )
        .expect("relaunch with record");
    let got = get_record(&sd.open_store(), "it-riso");
    assert_eq!(got.status().pid(), NonZeroU32::new(9));
    assert_eq!(got.restart_count(), 2);
    assert_eq!(got.launch_isolation(), Some(&rec2));
    assert!(got.launch_isolation() != Some(&rec1));
    assert_iso_values(got.launch_isolation(), 8, 12, 0x1f, audit2);

    // 段 4: restart 後の監視の更新（記録の指定なし）でも置き換え後の記録は消えない。
    let rev = got.revision();
    store
        .update(
            &UpdateStateRequest::new(ContainerStatus::running(id, NonZeroU32::new(9)), rev)
                .with_supervision(SupervisionState::new(None, None, 2)),
        )
        .expect("status update");
    let got = get_record(&sd.open_store(), "it-riso");
    assert_eq!(got.launch_isolation(), Some(&rec2));
}

/// network エントリを足した config。
fn config_with_network_entry(entry: Value) -> Value {
    let mut cfg = valid_config();
    cfg["linux"]["namespaces"]
        .as_array_mut()
        .expect("array")
        .push(entry);
    cfg
}

/// 指定モードで start を試み、予約の前に拒否される（launcher 0 回・記録は Created のまま）ときの誤りを返す。
fn net6_start_rejected(name: &str, cfg: &Value, mode: LaunchNetworkMode) -> OciRuntimeError {
    let b = Bundle::ready(name, cfg);
    let store = MemStateStore::new(None);
    b.create(&store, name);
    let launcher = FakeLauncher::new();
    launcher.set_network_mode(mode);
    let err = start(
        &store,
        &OpRecorder::new(),
        &dynl(&launcher),
        &start_req(name),
        &StartTimeouts::default(),
    )
    .expect_err("must be rejected");
    assert_eq!(launcher.launches(), 0, "{name}");
    assert_eq!(
        store.status_of(name).state(),
        ContainerState::Created,
        "{name}"
    );
    err
}

/// NET-6・NET-9・SEC-1（#3058・#1939）: `Host` / `Loopback` / `Attachable` と path 付きの network エントリの衝突は `InvalidArgument`。
#[test]
fn net6_sec1_start_rejects_network_mode_conflicting_with_path() {
    let cfg = config_with_network_entry(json!({"type": "network", "path": "/run/netns/x"}));
    for (name, mode) in [
        ("it-net6-host-path", LaunchNetworkMode::Host),
        ("it-net6-loop-path", LaunchNetworkMode::Loopback),
        ("it-net9-attach-path", LaunchNetworkMode::Attachable),
    ] {
        let err = net6_start_rejected(name, &cfg, mode);
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{name}");
        assert_eq!(
            err.message(),
            "the network mode conflicts with a linux.namespaces network path",
            "{name}"
        );
    }
}

/// NET-6・SEC-1（#3058）: `Host` で `net.*` の sysctl はホストの値を書き換えるため `InvalidArgument`。
#[test]
fn net6_sec1_start_rejects_net_sysctl_in_host_mode() {
    let mut cfg = config_with_network_entry(json!({"type": "network"}));
    cfg["linux"]["sysctl"] = json!({"net.ipv4.ip_forward": "1"});
    let err = net6_start_rejected("it-net6-host-sysctl", &cfg, LaunchNetworkMode::Host);
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        err.message(),
        "linux.sysctl net.* requires a network namespace"
    );
}

/// NET-6（#3058）: 既定の `FromConfig` で network エントリありは従来どおり `Unimplemented`（launcher 0 回）。
#[test]
fn net6_start_from_config_with_network_entry_is_unimplemented() {
    let cfg = config_with_network_entry(json!({"type": "network"}));
    let err = net6_start_rejected("it-net6-fromcfg", &cfg, LaunchNetworkMode::FromConfig);
    assert_eq!(err.code(), ErrorCode::Unimplemented);
    assert_eq!(
        err.message(),
        "start does not support yet: network / cgroup / time namespace"
    );
}

/// NET-6（#3058）: `Host` + path 無しの network エントリは受理され、spec の実効 network は `HostShared`。
/// `Loopback` / `Attachable` + path 無しは `NewLoopback`（実体の作成は #3064 で実装済み。`Attachable` は #1939）。
#[cfg(target_os = "linux")]
#[test]
fn net6_start_accepts_pathless_entry_and_reports_effective_network() {
    for (name, mode, expected) in [
        (
            "it-net6-host-ok",
            LaunchNetworkMode::Host,
            EffectiveNetwork::HostShared,
        ),
        (
            "it-net6-loop-ok",
            LaunchNetworkMode::Loopback,
            EffectiveNetwork::NewLoopback,
        ),
        (
            "it-net9-attach-ok",
            LaunchNetworkMode::Attachable,
            EffectiveNetwork::NewLoopback,
        ),
    ] {
        let b = Bundle::ready(name, &config_with_network_entry(json!({"type": "network"})));
        let store = MemStateStore::new(None);
        b.create(&store, name);
        let launcher = FakeLauncher::new();
        launcher.set_network_mode(mode);
        let _started = start(
            &store,
            &OpRecorder::new(),
            &dynl(&launcher),
            &start_req(name),
            &short_timeouts(),
        )
        .expect("start");
        assert_eq!(
            *launcher.launched_networks.lock().expect("lock"),
            vec![expected],
            "{name}"
        );
    }
}
