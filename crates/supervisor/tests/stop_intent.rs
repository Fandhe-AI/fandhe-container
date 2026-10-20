//! 明示 stop の意図の伝達と、restart の対象外化の結合試験（SUP-9・SUP-3・SUP-1・SEC-1・CLI-1・#2162）。
//!
//! 実 `FileStateStore`・実 UDS（`control::install` が結線する制御チャネル）・`run_supervised`（監視と restart の
//! ループ）を通し、CLI の stop が使う `ControlSignaler::for_stop` が送った SIGTERM による終了が、
//! `always`・`on-failure`・`unless-stopped` でも再 launch されないことを、終了コード・`restart_count`・状態の
//! 具体値で照合する。対照として、意図を立てない `ControlSignaler::new`（kind 2。将来の `kill`）の SIGTERM では
//! `always` が再 launch されることも照合する。
//!
//! コンテナ役は SIGTERM を受けたら次の `wait` で `Signaled(15)` を返す模擬の起動ハンドルで、namespace・cgroup は
//! 含まない。root 不要で既定のテスト集合で動く。`FileStateStore` は Linux 限定のため全体を Linux に限る。

#![cfg(target_os = "linux")]

use std::fs;
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit, StartTimeouts};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ContainerStatus, CreateStateRequest, ErrorCode, Signal,
    StateStore, SupervisionState, TraitError,
};
use fandhe_container_supervisor::control::{ControlSignaler, install};
use fandhe_container_supervisor::restart::{Relauncher, RestartPolicy};
use fandhe_container_supervisor::run::{ExplicitStopState, StopToken};
use fandhe_container_supervisor::start_entry::{Running, run_supervised};
use fandhe_container_supervisor::state::{SupervisedState, open_default_store};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 一意な一時ディレクトリ（0700。drop で削除）。
struct TmpRoot(PathBuf);

impl TmpRoot {
    fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!(
            "fandhe-sup-stopintent-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}

impl Drop for TmpRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// SIGTERM(15) を受けたら次の `wait` で `Signaled(15)` を返す模擬のコンテナ。
struct Sim {
    pid: u32,
    terminated: AtomicBool,
    signals: Arc<Mutex<Vec<(u32, u8)>>>,
}

impl LaunchedProcess for Sim {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(self.pid).unwrap()
    }
    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        if self.terminated.load(Ordering::SeqCst) {
            return Ok(Some(ProcessExit::Signaled(15)));
        }
        std::thread::sleep(timeout.min(Duration::from_millis(5)));
        Ok(None)
    }
    fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
        self.terminated.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn signal(&self, signal: Signal, _deadline: Instant) -> Result<(), TraitError> {
        self.signals
            .lock()
            .unwrap()
            .push((self.pid, signal.as_u8()));
        if signal.as_u8() == 15 {
            self.terminated.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
}

/// 再 launch の回数を数え、新しい pid（301, 302, ...）の模擬を返す。
struct CountingRelauncher {
    calls: Arc<AtomicU32>,
    signals: Arc<Mutex<Vec<(u32, u8)>>>,
}

impl Relauncher for CountingRelauncher {
    fn relaunch(&self, _timeout: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Box::new(Sim {
            pid: 300 + n,
            terminated: AtomicBool::new(false),
            signals: Arc::clone(&self.signals),
        }))
    }
}

struct Rig {
    _tmp: TmpRoot,
    root: PathBuf,
    id: ContainerId,
    store: Arc<dyn StateStore>,
    stop: StopToken,
    relaunches: Arc<AtomicU32>,
    signals: Arc<Mutex<Vec<(u32, u8)>>>,
    exit: std::sync::mpsc::Receiver<u8>,
    _worker: std::thread::JoinHandle<()>,
}

/// `Running(pid 100)` の状態を作り、制御チャネルを結線して `run_supervised` を別スレッドで回す。
fn start(tag: &str, policy: &str) -> Rig {
    let tmp = TmpRoot::new(tag);
    let root = tmp.0.join("state");
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let id = ContainerId::new("c1").unwrap();
    let store: Arc<dyn StateStore> = open_default_store(Some(root.clone())).unwrap();
    store
        .create(
            &CreateStateRequest::new(
                ContainerStatus::created(id.clone(), None),
                tmp.0.join("bundle"),
            )
            .unwrap(),
        )
        .unwrap();
    let mut state = SupervisedState::attach(Arc::clone(&store), id.clone()).unwrap();
    state
        .write(
            ContainerStatus::running(id.clone(), NonZeroU32::new(100)),
            SupervisionState::new(None, None, 0),
        )
        .unwrap();
    drop(state);

    let signals = Arc::new(Mutex::new(Vec::new()));
    let relaunches = Arc::new(AtomicU32::new(0));
    let stop = StopToken::new();
    let running = Running {
        process: Box::new(Sim {
            pid: 100,
            terminated: AtomicBool::new(false),
            signals: Arc::clone(&signals),
        }),
        relauncher: Arc::new(CountingRelauncher {
            calls: Arc::clone(&relaunches),
            signals: Arc::clone(&signals),
        }),
        instance: None,
        logs: None,
        seccomp: None,
    };
    let (running, handle) = install(&root, &id, running, &stop, None);
    assert!(handle.failure().is_none(), "control channel install failed");

    let policy: RestartPolicy = policy.parse().unwrap();
    let (tx, exit) = channel();
    let (w_store, w_id, w_stop) = (Arc::clone(&store), id.clone(), stop.clone());
    let worker = std::thread::spawn(move || {
        let code = run_supervised(
            w_store,
            w_id,
            running,
            policy,
            &StartTimeouts::default(),
            &w_stop,
        );
        let code = handle.exit_code(code);
        drop(handle);
        let _ = tx.send(code);
    });
    Rig {
        _tmp: tmp,
        root,
        id,
        store,
        stop,
        relaunches,
        signals,
        exit,
        _worker: worker,
    }
}

impl Rig {
    fn record(&self) -> (ContainerState, Option<i32>, u32, Option<u32>) {
        let s = SupervisedState::attach(Arc::clone(&self.store), self.id.clone()).unwrap();
        let r = s.record();
        (
            r.status().state(),
            r.status().exit_code(),
            r.restart_count(),
            r.status().pid().map(NonZeroU32::get),
        )
    }

    /// 状態が `pred` を満たすまで待つ（期限つき。REPAIR-5）。
    fn wait_record(&self, pred: impl Fn(&(ContainerState, Option<i32>, u32, Option<u32>)) -> bool) {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let rec = self.record();
            if pred(&rec) {
                return;
            }
            assert!(Instant::now() < end, "state did not converge: {rec:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn send(&self, signaler: &ControlSignaler, pid: u32) -> Result<(), TraitError> {
        use fandhe_container_core::oci_runtime::ProcessSignaler as _;
        signaler.signal(
            &self.id,
            NonZeroU32::new(pid).unwrap(),
            Signal::SIGTERM,
            Instant::now() + Duration::from_secs(5),
        )
    }

    fn exit_code(&self) -> u8 {
        self.exit
            .recv_timeout(Duration::from_secs(10))
            .expect("run_supervised did not return in time")
    }
}

/// SUP-9・SUP-3: stop（意図つき）の SIGTERM による終了は、`always`・`unless-stopped`・`on-failure`・`on-failure:3`
/// のどれでも再 launch されない。supervisor は 0 で終わり、`Stopped`・終了コード 143・`restart_count` 0・pid なし。
#[test]
fn sup9_sup3_stop_intent_prevents_restart_under_every_policy() {
    for policy in ["always", "unless-stopped", "on-failure", "on-failure:3"] {
        let rig = start("every", policy);
        assert_eq!(rig.record().0, ContainerState::Running, "{policy}");
        rig.send(&ControlSignaler::for_stop(rig.root.clone()), 100)
            .unwrap_or_else(|e| panic!("{policy}: {e:?}"));
        assert_eq!(rig.exit_code(), 0, "{policy}");
        assert_eq!(
            rig.record(),
            (ContainerState::Stopped, Some(143), 0, None),
            "{policy}"
        );
        assert_eq!(rig.relaunches.load(Ordering::SeqCst), 0, "{policy}");
        assert_eq!(*rig.signals.lock().unwrap(), vec![(100, 15)], "{policy}");
        assert_eq!(
            rig.stop.explicit_stop_state(),
            ExplicitStopState::Requested,
            "{policy}"
        );
        assert!(!rig.stop.is_stop_requested(), "{policy}");
    }
}

/// SUP-9・SUP-3（対照）: 意図を立てない kind 2 の SIGTERM では `always` が再 launch される。
/// 続けて stop で止めると、`restart_count` は 1 のまま `Stopped` になる。
#[test]
fn sup9_sup3_plain_signal_restarts_but_stop_after_it_does_not() {
    let rig = start("contrast", "always");
    rig.send(&ControlSignaler::new(rig.root.clone()), 100)
        .unwrap();
    assert_eq!(
        rig.stop.explicit_stop_state(),
        ExplicitStopState::NotRequested
    );
    rig.wait_record(|r| r.0 == ContainerState::Running && r.2 == 1 && r.3 == Some(301));
    assert_eq!(rig.relaunches.load(Ordering::SeqCst), 1);

    rig.send(&ControlSignaler::for_stop(rig.root.clone()), 301)
        .unwrap();
    assert_eq!(rig.exit_code(), 0);
    assert_eq!(rig.record(), (ContainerState::Stopped, Some(143), 1, None));
    assert_eq!(rig.relaunches.load(Ordering::SeqCst), 1);
    assert_eq!(*rig.signals.lock().unwrap(), vec![(100, 15), (301, 15)]);
}

/// SUP-9・SEC-1: pid 不一致の stop は意図を立てず、シグナルも送らない（コンテナは動き続ける）。
#[test]
fn sup9_sec1_pid_mismatch_stop_does_not_mark_intent() {
    let rig = start("mismatch", "always");
    let e = rig
        .send(&ControlSignaler::for_stop(rig.root.clone()), 999)
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        e.message(),
        "the process id does not match the launched process"
    );
    assert_eq!(
        rig.stop.explicit_stop_state(),
        ExplicitStopState::NotRequested
    );
    assert!(rig.signals.lock().unwrap().is_empty());
    assert_eq!(rig.record().0, ContainerState::Running);
    // 片付け: 正しい pid で止める。
    rig.send(&ControlSignaler::for_stop(rig.root.clone()), 100)
        .unwrap();
    assert_eq!(rig.exit_code(), 0);
}
