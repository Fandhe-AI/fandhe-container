//! shim の serve の起動時の走査の試験（CRI-5・SUP-7・REPAIR-4・REPAIR-5・#4280）。
//!
//! 親の `startup_sweep` から `#[cfg(test)]` で取り込む。実の `FileStateStore` と実の `RotatingFileSink` を使い、root は要らない。

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpRecorder};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
    ErrorCode, GetStateRequest, ListStateRequest, StateList, StateRecord, StateStore, TraitError,
    UpdateStateRequest,
};
use fandhe_container_supervisor::logs::{
    LogSink as _, RotatingFileSink, StreamKind, container_log_dir, container_log_rotation_config,
};

use super::*;
use crate::test_root;

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).unwrap()
}

/// 0700 の状態ルートでストアを開く。
fn open_store(base: &Path) -> (Arc<dyn StateStore>, PathBuf) {
    let root = StateRoot::resolve(Some(base.join("state"))).unwrap();
    let store: Arc<dyn StateStore> = Arc::new(FileStateStore::open(root).unwrap());
    let root = store.host_state_root().unwrap().to_path_buf();
    (store, root)
}

/// sink を開いて 1 行書く（再 open の競合は期限つきで再試行する）。
fn open_sink(root: &Path, name: &str) -> RotatingFileSink {
    let dir = container_log_dir(root);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let sink = loop {
        match RotatingFileSink::open(&dir, &cid(name), container_log_rotation_config()) {
            Ok(s) => break s,
            Err(e) if e.code() == ErrorCode::FailedPrecondition && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("open sink: {e:?}"),
        }
    };
    sink.append(StreamKind::Stdout, format!("hello {name}").as_bytes())
        .unwrap();
    sink.flush().unwrap();
    sink
}

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// 要約行を積む `emit`。
type Emit = Arc<dyn Fn(String) + Send + Sync>;

fn collector() -> (Arc<Mutex<Vec<String>>>, Emit) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let l2 = Arc::clone(&lines);
    (lines, Arc::new(move |s| l2.lock().unwrap().push(s)))
}

fn spawned(s: StartupSweep) -> SweepHandle {
    match s {
        StartupSweep::Spawned(h) => h,
        other => panic!(
            "sweep must spawn: {}",
            matches!(other, StartupSweep::SpawnFailed)
        ),
    }
}

/// CRI-5・SUP-7・REPAIR-4・#4280: 記録の無い閉じた ID のログだけが消え、記録のある ID と生きている sink のログは残る。
#[test]
fn cri5_sup7_4280_startup_sweep_removes_only_closed_unrecorded_logs() {
    let guard = test_root::test_root("shim", "sweep1");
    let (store, root) = open_store(&guard);
    let bundle = guard.join("bundle");
    std::fs::create_dir_all(&bundle).unwrap();
    store
        .create(
            &CreateStateRequest::new(ContainerStatus::created(cid("present1"), None), bundle)
                .unwrap(),
        )
        .unwrap();
    drop(open_sink(&root, "present1"));
    drop(open_sink(&root, "closed1"));
    let _live = open_sink(&root, "live1");

    let recorder = Arc::new(OpRecorder::new());
    let (lines, emit) = collector();
    let h = spawned(spawn_startup_log_sweep(
        Arc::clone(&store),
        Arc::clone(&recorder),
        Duration::from_secs(30),
        emit,
    ));
    let report = h
        .wait_within(Duration::from_secs(20))
        .expect("sweep finishes")
        .expect("report");
    assert_eq!(report.reclaimed_ids, 1);
    assert_eq!(report.removed_files, 1);
    assert_eq!(report.skipped_live, 1);
    assert_eq!(report.skipped_present, 1);
    assert_eq!(report.failed, 0);
    assert!(!report.timed_out);
    assert_eq!(
        names(&container_log_dir(&root)),
        ["live1.log", "live1.log.lock", "present1.log"]
    );
    // 要約行は emit が thread の中で送り終えてから結果を送るので、結果を受けた時点で積まれている。
    let got = lines.lock().unwrap().clone();
    assert_eq!(got, vec![crate::adapter::sweep_summary_line(&report)]);
    let snap = recorder
        .snapshot_op(&OpName::new("container_log_reclaim").unwrap())
        .unwrap();
    assert_eq!((snap.success(), snap.failure()), (1, 0));
}

/// REPAIR-4・#4280: 何も無いときは行を出さない（`@container-logs` が無い状態ルート）。
#[test]
fn cri5_sup7_4280_startup_sweep_silent_when_nothing_to_do() {
    let guard = test_root::test_root("shim", "sweep2");
    let (store, _root) = open_store(&guard);
    let (lines, emit) = collector();
    let h = spawned(spawn_startup_log_sweep(
        store,
        Arc::new(OpRecorder::new()),
        Duration::from_secs(30),
        emit,
    ));
    let report = h
        .wait_within(Duration::from_secs(20))
        .expect("sweep finishes")
        .expect("report");
    assert_eq!(report, SweepReport::default());
    assert!(lines.lock().unwrap().is_empty());
}

/// `get` が解放されるまで止まる `StateStore`（guard の停止の偽物）。
struct BlockedGet {
    inner: Arc<dyn StateStore>,
    entered: Mutex<Sender<()>>,
    release: Mutex<Receiver<()>>,
}

impl StateStore for BlockedGet {
    fn create(&self, r: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        self.inner.create(r)
    }
    fn update(&self, r: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        self.inner.update(r)
    }
    fn get(&self, r: &GetStateRequest) -> Result<StateRecord, TraitError> {
        let _ = self.entered.lock().unwrap().send(());
        // 解放されるか、送り側が drop されるまで待つ。期限つき（REPAIR-5）。
        let _ = self
            .release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(30));
        self.inner.get(r)
    }
    fn list(&self, r: &ListStateRequest) -> Result<StateList, TraitError> {
        self.inner.list(r)
    }
    fn delete(&self, r: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        self.inner.delete(r)
    }
    fn host_state_root(&self) -> Option<&Path> {
        self.inner.host_state_root()
    }
}

/// REPAIR-5・#4280: guard が止まっても起動は待たされず（呼び出しは戻る）、走査は期限で戻り、止まった ID のログは消さない。
#[test]
fn cri5_repair5_4280_startup_sweep_does_not_block_and_returns_by_budget() {
    let guard = test_root::test_root("shim", "sweep3");
    let (inner, root) = open_store(&guard);
    drop(open_sink(&root, "closed1"));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let store: Arc<dyn StateStore> = Arc::new(BlockedGet {
        inner,
        entered: Mutex::new(entered_tx),
        release: Mutex::new(release_rx),
    });
    let (_lines, emit) = collector();
    let h = spawned(spawn_startup_log_sweep(
        store,
        Arc::new(OpRecorder::new()),
        Duration::from_secs(1),
        emit,
    ));
    // 呼び出しが戻った後に guard が止まっていることを順序で確かめる（時間の比較にしない）。
    entered_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("guard entered");
    assert!(matches!(
        h.wait_within(Duration::ZERO),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    let report = h
        .wait_within(Duration::from_secs(20))
        .expect("sweep returns by budget")
        .expect("report");
    assert!(report.timed_out);
    assert_eq!(report.reclaimed_ids, 0);
    assert!(container_log_dir(&root).join("closed1.log").exists());
    // 止まった作業スレッドを解放する（他の試験へ作業枠を残さない）。
    drop(release_tx);
}
