//! restart の単一スレッド再 launch と exec のガードの共存の結合試験（SUP-3・SUP-6・REPAIR-5・REPAIR-12・#2043・#2626）。
//!
//! core の本番 launcher は再 launch の時点で `Threads: 1` を要求する。pidfd を渡した接続を預かるガードのスレッド
//! （`control-exec-guard`）は、`PausableServer::pause`（`ControlledRelauncher` が再 launch の前に呼ぶ）が accept ループと
//! ともに止め、通知済みのガードは旧世代の exec 子 cgroup を回収してから終わる。スレッドは `/proc/self/task/*/comm`
//! （15 文字に切り詰め）で数える。試験どうしが互いのスレッドを見ないよう、すべて 1 本の `Mutex` で直列化する。
//! root・実コンテナは不要。

#![cfg(target_os = "linux")]

use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::exec::ExecCgroupName;
use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{ContainerId, Signal, TraitError};
use fandhe_container_supervisor::control::listener::{ControlListener, effective_uid};
use fandhe_container_supervisor::control::observe::ControlObserver;
use fandhe_container_supervisor::control::server::{PausableServer, ServeConfig};
use fandhe_container_supervisor::control::target::{
    ControlledProcess, ControlledRelauncher, SignalSlot,
};
use fandhe_container_supervisor::control::{
    ControlExecHandover, ExecCgroupReclaimer, ExecGuardLimits, ExecGuardPool, ExecPidfdSource,
    ReclaimOutcome,
};
use fandhe_container_supervisor::restart::Relauncher;

const PID: u32 = 4321;
/// 試験どうしの直列化（スレッド数を数えるため）。
static SERIAL: Mutex<()> = Mutex::new(());

struct Fake {
    fd: OwnedFd,
}

impl LaunchedProcess for Fake {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(PID).unwrap()
    }
    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        std::thread::sleep(timeout.min(Duration::from_millis(5)));
        Ok(None)
    }
    fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
        Ok(())
    }
    fn signal(&self, _signal: Signal, _deadline: Instant) -> Result<(), TraitError> {
        Ok(())
    }
    fn launch_pidfd(&self) -> Option<BorrowedFd<'_>> {
        Some(self.fd.as_fd())
    }
}

#[derive(Default)]
struct FakeReclaimer {
    calls: Mutex<Vec<String>>,
    /// 回収を遅らせる時間（ミリ秒）。`release` で打ち切れる。
    delay_ms: AtomicU64,
    release: AtomicBool,
}

impl ExecCgroupReclaimer for FakeReclaimer {
    fn reclaim(&self, name: &ExecCgroupName) -> ReclaimOutcome {
        self.calls.lock().unwrap().push(name.as_str().to_owned());
        let end = Instant::now() + Duration::from_millis(self.delay_ms.load(Ordering::SeqCst));
        while Instant::now() < end && !self.release.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        ReclaimOutcome::Removed
    }
}

/// 名前が `prefix`（comm は 15 文字まで）で始まる自プロセスのスレッド数。
fn threads_named(prefix: &str) -> usize {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|e| std::fs::read_to_string(e.path().join("comm")).ok())
        .filter(|c| c.trim_end().starts_with(prefix))
        .count()
}

/// `threads_named(prefix)` が `want` になるまで最大 5 秒待ち、最後に数えた値を返す。スレッドの名前は生成後に
/// そのスレッド自身が付けるため、生成直後の 1 回の数え上げでは負荷時に名前の付く前を数えてしまう（REPAIR-12）。
fn wait_threads_named(prefix: &str, want: usize) -> usize {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let n = threads_named(prefix);
        if n == want || std::time::Instant::now() >= deadline {
            return n;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

const GUARD_COMM: &str = "control-exec-gu";
const ACCEPT_COMM: &str = "control-channel";

struct Rig {
    root: PathBuf,
    id: ContainerId,
    slot: SignalSlot,
    server: Arc<PausableServer>,
    pool: Arc<ExecGuardPool>,
    reclaimer: Arc<FakeReclaimer>,
    _process: ControlledProcess,
    _listener: ControlListener,
}

impl Rig {
    fn start(tag: &str) -> Self {
        Self::start_with(tag, ServeConfig::default())
    }

    fn start_with(tag: &str, config: ServeConfig) -> Self {
        use std::os::unix::fs::DirBuilderExt as _;
        let root = std::env::temp_dir().join(format!("fc-guardrl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(root.join(tag))
            .unwrap();
        let id = ContainerId::new(tag).unwrap();
        let listener = ControlListener::bind(&root, &id).unwrap();
        let slot = SignalSlot::new();
        let fd = OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
        let process = ControlledProcess::new(Box::new(Fake { fd }), slot.clone());
        let reclaimer = Arc::new(FakeReclaimer::default());
        let observer = Arc::new(ControlObserver::new(None, None));
        let pool = ExecGuardPool::new(
            Arc::clone(&reclaimer) as Arc<dyn ExecCgroupReclaimer>,
            Arc::clone(&observer),
            ExecGuardLimits {
                hold_grace: Duration::from_secs(30),
                ..ExecGuardLimits::default()
            },
        );
        let server = Arc::new(
            PausableServer::spawn_with_exec_guard(
                listener.try_clone_listener().unwrap(),
                slot.clone(),
                effective_uid().unwrap(),
                config,
                observer,
                Some(Arc::clone(&pool)),
            )
            .unwrap(),
        );
        Self {
            root,
            id,
            slot,
            server,
            pool,
            reclaimer,
            _process: process,
            _listener: listener,
        }
    }

    fn obtain(&self) -> fandhe_container_supervisor::control::ExecHandover {
        ControlExecHandover::new(self.root.clone())
            .obtain(
                &self.id,
                NonZeroU32::new(PID).unwrap(),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap()
    }

    fn calls(&self) -> Vec<String> {
        self.reclaimer.calls.lock().unwrap().clone()
    }

    fn wait_calls(&self, n: usize) -> Vec<String> {
        let until = Instant::now() + Duration::from_secs(3);
        while self.calls().len() < n && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.calls()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.reclaimer.release.store(true, Ordering::SeqCst);
        self.server.shutdown();
        let _ = self.pool.shutdown_all(Duration::from_secs(3));
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn name(s: &str) -> ExecCgroupName {
    ExecCgroupName::new(s).unwrap()
}

fn hold() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

/// SUP-3・SUP-6・REPAIR-5・#2043: 通知済みで接続を開いたままのガードは、pause で旧世代の cgroup を回収して終わり、
/// ガードと accept のスレッドが残らない（core の `Threads: 1` 検査の前提）。
#[test]
fn sup3_sup6_repair5_pause_reclaims_notified_guard_and_joins_threads() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rig = Rig::start("held");
    let handover = rig.obtain();
    handover
        .notify_created(&name("exec-100-0"), hold())
        .unwrap();
    assert_eq!(wait_threads_named(GUARD_COMM, 1), 1);
    assert_eq!(rig.pool.active(), 1);
    let started = Instant::now();
    rig.server.pause(Duration::from_secs(5)).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(rig.calls(), vec!["exec-100-0".to_owned()]);
    assert_eq!(threads_named(GUARD_COMM), 0);
    assert_eq!(threads_named(ACCEPT_COMM), 0);
    assert_eq!(rig.pool.active(), 0);
    drop(handover);
    rig.server.resume().unwrap();
}

/// SUP-3・SUP-6・#2043: 通知前のガードも pause で終わり、何も回収しない。
#[test]
fn sup3_sup6_pause_ends_unnotified_guard_without_reclaim() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rig = Rig::start("unnotified");
    let handover = rig.obtain();
    assert_eq!(wait_threads_named(GUARD_COMM, 1), 1);
    rig.server.pause(Duration::from_secs(5)).unwrap();
    assert_eq!(rig.calls(), Vec::<String>::new());
    assert_eq!(threads_named(GUARD_COMM), 0);
    assert_eq!(rig.pool.active(), 0);
    drop(handover);
    rig.server.resume().unwrap();
}

/// SUP-3・SUP-6・REPAIR-5・#2043: 停止の後に resume すると、新しい handover・通知・回収が通る。
#[test]
fn sup3_sup6_resume_accepts_new_guards_after_pause() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rig = Rig::start("resume");
    let old = rig.obtain();
    old.notify_created(&name("exec-1-1"), hold()).unwrap();
    rig.server.pause(Duration::from_secs(5)).unwrap();
    assert_eq!(rig.calls(), vec!["exec-1-1".to_owned()]);
    drop(old);
    rig.server.resume().unwrap();
    let fresh = rig.obtain();
    fresh.notify_created(&name("exec-2-2"), hold()).unwrap();
    assert_eq!(wait_threads_named(GUARD_COMM, 1), 1);
    drop(fresh);
    assert_eq!(
        rig.wait_calls(2),
        vec!["exec-1-1".to_owned(), "exec-2-2".to_owned()]
    );
}

/// 再 launch の直前に見えるスレッドを記録する偽の relauncher。
struct Probe {
    seen: Mutex<Vec<(usize, usize)>>,
}

impl Relauncher for Probe {
    fn relaunch(&self, _timeout: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        self.seen
            .lock()
            .unwrap()
            .push((threads_named(GUARD_COMM), threads_named(ACCEPT_COMM)));
        Err(TraitError::new(
            fandhe_container_core::traits::ErrorCode::Internal,
            "probe relaunch",
        ))
    }
}

/// SUP-3・SUP-6・REPAIR-5・REPAIR-12・#2043: ガードを保持したまま `ControlledRelauncher` で再 launch すると、内側の launch の
/// 時点でガードも accept のスレッドも 0 本で、旧世代の cgroup は回収済み。launch の後は新しいガードを受けられる。
#[test]
fn sup3_sup6_repair12_relaunch_sees_no_guard_threads_and_resume_reopens() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rig = Rig::start("relaunch");
    let handover = rig.obtain();
    handover.notify_created(&name("exec-9-9"), hold()).unwrap();
    let probe = Arc::new(Probe {
        seen: Mutex::new(Vec::new()),
    });
    let relauncher =
        ControlledRelauncher::new(Arc::clone(&probe) as Arc<dyn Relauncher>, rig.slot.clone())
            .with_pause(Arc::clone(&rig.server) as Arc<_>);
    let _ = relauncher.relaunch(Duration::from_secs(10));
    assert_eq!(*probe.seen.lock().unwrap(), vec![(0, 0)]);
    assert_eq!(rig.calls(), vec!["exec-9-9".to_owned()]);
    drop(handover);
    let again = rig.obtain();
    again.notify_created(&name("exec-9-10"), hold()).unwrap();
    drop(again);
    assert_eq!(rig.wait_calls(2).len(), 2);
}

/// SUP-3・SUP-6・REPAIR-5・#2043: ガードの回収が期限を過ぎると pause は `Timeout` で失敗するが、止まらなかったガードは
/// プールに残り、次の pause（accept が既に止まっていても）が再び join して 0 本にする。
#[test]
fn sup3_sup6_repair5_pause_timeout_keeps_stuck_guard_and_next_pause_joins_it() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rig = Rig::start("stuck");
    rig.reclaimer.delay_ms.store(30_000, Ordering::SeqCst);
    let handover = rig.obtain();
    handover.notify_created(&name("exec-5-5"), hold()).unwrap();
    // 合計 1.5 秒 → ガードの予算は 0.75 秒。回収が終わらないので Timeout。
    let e = rig.server.pause(Duration::from_millis(1500)).unwrap_err();
    assert_eq!(e.code(), fandhe_container_core::traits::ErrorCode::Timeout);
    assert_eq!(e.message(), "exec guards did not stop in time");
    assert_eq!(rig.calls(), vec!["exec-5-5".to_owned()]);
    assert_eq!(wait_threads_named(GUARD_COMM, 1), 1);
    assert_eq!(threads_named(ACCEPT_COMM), 0);
    // 回収が終われば、accept が止まったままでも次の pause が残ったガードを join する。
    rig.reclaimer.release.store(true, Ordering::SeqCst);
    rig.server.pause(Duration::from_secs(5)).unwrap();
    assert_eq!(threads_named(GUARD_COMM), 0);
    assert_eq!(rig.pool.active(), 0);
    drop(handover);
}

/// SUP-3・REPAIR-5・#2043: 再 launch の pause が失敗しても launch はせず、制御チャネル（accept）は復旧する
/// （止めたままだと稼働中のコンテナを stop できないため）。復旧後は新しい handover を受けられる。
#[test]
fn sup3_repair5_failed_pause_does_not_relaunch_and_restores_control_channel() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rig = Rig::start("restore");
    rig.reclaimer.delay_ms.store(30_000, Ordering::SeqCst);
    let handover = rig.obtain();
    handover.notify_created(&name("exec-6-6"), hold()).unwrap();
    let probe = Arc::new(Probe {
        seen: Mutex::new(Vec::new()),
    });
    let relauncher =
        ControlledRelauncher::new(Arc::clone(&probe) as Arc<dyn Relauncher>, rig.slot.clone())
            .with_pause(Arc::clone(&rig.server) as Arc<_>);
    // relaunch の timeout 2 秒 → pause の予算 2 秒（ガード 1 秒）。回収が終わらず失敗する。
    assert!(relauncher.relaunch(Duration::from_secs(2)).is_err());
    assert_eq!(*probe.seen.lock().unwrap(), Vec::<(usize, usize)>::new());
    assert_eq!(wait_threads_named(ACCEPT_COMM, 1), 1);
    // 復旧した accept が新しい handover を受ける。
    rig.reclaimer.release.store(true, Ordering::SeqCst);
    let again = rig.obtain();
    again.notify_created(&name("exec-6-7"), hold()).unwrap();
    drop((again, handover));
}

/// SUP-3・REPAIR-5・#2043: accept の停止に時間がかかっても、ガードの停止の予算は削られない
/// （合計 2 秒 → ガード 1 秒・accept 1 秒。accept の poll が 600ms で、0.3 秒かかる回収が収まる）。
#[test]
fn sup3_repair5_guard_budget_survives_slow_accept_stop() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let rig = Rig::start_with(
        "split",
        ServeConfig {
            poll_interval: Duration::from_millis(600),
            ..ServeConfig::default()
        },
    );
    rig.reclaimer.delay_ms.store(300, Ordering::SeqCst);
    let handover = rig.obtain();
    handover.notify_created(&name("exec-7-7"), hold()).unwrap();
    let started = Instant::now();
    rig.server.pause(Duration::from_secs(2)).unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(300),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(rig.calls(), vec!["exec-7-7".to_owned()]);
    assert_eq!(threads_named(GUARD_COMM), 0);
    drop(handover);
}
