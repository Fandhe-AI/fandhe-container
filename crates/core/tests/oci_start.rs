//! `oci_runtime::start` の結合試験（OCI-4・CORE-1・CORE-2・SEC-1・REPAIR-5・TASK-29.3）。
//!
//! 公開 API（`create`・`start`・`recover_interrupted_start`・`StateStore`・`ProcessLauncher`・
//! `LaunchedProcess`）だけを crate の外から呼び、create → start の状態遷移・launcher との連携・
//! 応答待ちの上限超過時の後始末を具体値で確かめる。実プロセスは起動しない（launcher は模擬）。
//!
//! rootfs を fd で固定する start の成功経路は Linux 限定（Linux 以外は起動前に `Unimplemented`）のため、
//! 成功を前提とする試験と中断回復（起動権の所有ロックも Linux 限定）の試験は `cfg(target_os = "linux")`、
//! Linux 以外では fail-closed の拒否を具体値で確かめる。設定検証の試験は 3 OS の既定のテスト集合で動く。
//! 実機権限（root 等）は不要。
//!
//! 待ちの上限は CI の `integration-test` ジョブが設定する `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`
//! （既定 10 秒。AGENTS.md「推奨タイムアウト値」・REPAIR-5）から組み立てる。

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, StartTimeouts, create,
    recover_interrupted_start, start,
};
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
}

impl MemStateStore {
    fn new(fail_update_at: Option<usize>) -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            fail_update_at,
            update_calls: AtomicUsize::new(0),
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
    terminated: Arc<AtomicUsize>,
    confirms_no_process: AtomicBool,
    /// 起動した模擬プロセスの terminate を失敗させるか。
    fail_terminate: AtomicBool,
    gate: Gate,
}

impl FakeLauncher {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            launched_args: Mutex::new(Vec::new()),
            terminated: Arc::new(AtomicUsize::new(0)),
            confirms_no_process: AtomicBool::new(true),
            fail_terminate: AtomicBool::new(false),
            gate: Gate::new(true),
        })
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
struct FakeProcess(Arc<AtomicUsize>, bool);

impl LaunchedProcess for FakeProcess {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(7).expect("nonzero")
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
    fn launch(
        &self,
        spec: &LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        self.launched_args
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(spec.args().to_vec());
        self.gate.pass();
        Ok(Box::new(FakeProcess(
            self.terminated.clone(),
            self.fail_terminate.load(Ordering::SeqCst),
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
}

impl Bundle {
    fn ready(name: &str, config: &Value) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-core-start-it-{name}-{}",
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

    fn create(&self, store: &MemStateStore, id: &str) {
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
