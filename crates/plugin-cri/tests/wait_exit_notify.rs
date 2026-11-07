//! `CoreLifecycleRuntime::wait_exit` が supervisor の終了通知で起きること、通知が使えないときは照会へ退避すること、
//! 期限・取り消しの戻り値が core の既定実装と同じであることの結合試験（CRI-1・SUP-1・REPAIR-5・REPAIR-12・#3683）。
//!
//! 通知口は偽の `ExitNotifier`（`ExitNotifierSource` で注入）で、状態ストアは書き換えられる模擬の世界。実際の制御チャネルは
//! supervisor 側の結合試験（`crates/supervisor/tests/control_channel.rs`）が実 UDS で通す。Linux 限定・root 不要。
//! 時間の上限には余裕を持たせる（例: 1 秒未満を主張する場面の実測は数十ミリ秒）。

#![cfg(target_os = "linux")]

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LifecycleOp, OciRuntimeError, ProcessSignaler};
use fandhe_container_core::traits::{
    ContainerId, ContainerLogPath, ContainerRuntime, ContainerState, ContainerStatus,
    CreateRequest, CreateStateRequest, DeleteRequest, DeleteResponse, DeleteStateRequest,
    DeleteStateResponse, ErrorCode, GetStateRequest, KillRequest, ListStateRequest, StartRequest,
    StateList, StateRecord, StateRequest, StateRevision, StateStore, StopRequest, TraitError,
    WaitExitRequest,
};
use fandhe_container_plugin_cri::adapter::CoreLifecycleRuntime;
use fandhe_container_plugin_cri::supervised::{
    ExitNotifierSource, SignalerSource, SupervisedLifecycle, SupervisorStarter,
};
use fandhe_container_supervisor::control::{ExitNotifier, ExitWatchOutcome, UnavailableSignaler};

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).expect("valid id")
}

fn pid(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).expect("nonzero")
}

/// 書き換えられる模擬の世界（状態と `get` の呼び出し回数）。
struct World {
    status: Mutex<ContainerStatus>,
    gets: AtomicU32,
    /// 真なら `get` が `NotFound`（待ちの途中で削除された場面）。
    missing: AtomicBool,
    root: Option<PathBuf>,
}

impl World {
    fn new(status: ContainerStatus, root: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(status),
            gets: AtomicU32::new(0),
            missing: AtomicBool::new(false),
            root,
        })
    }

    fn set(&self, status: ContainerStatus) {
        *self.status.lock().expect("lock") = status;
    }

    fn gets(&self) -> u32 {
        self.gets.load(Ordering::SeqCst)
    }
}

struct WorldStore(Arc<World>);

fn unused() -> TraitError {
    TraitError::new(ErrorCode::Unimplemented, "unused")
}

impl StateStore for WorldStore {
    fn create(&self, _r: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        Err(unused())
    }
    fn get(&self, _r: &GetStateRequest) -> Result<StateRecord, TraitError> {
        self.0.gets.fetch_add(1, Ordering::SeqCst);
        if self.0.missing.load(Ordering::SeqCst) {
            return Err(TraitError::new(ErrorCode::NotFound, "deleted"));
        }
        let status = self.0.status.lock().expect("lock").clone();
        StateRecord::new(
            status,
            PathBuf::from("/nonexistent/bundle"),
            StateRevision::INITIAL,
        )
    }
    fn update(
        &self,
        _r: &fandhe_container_core::traits::UpdateStateRequest,
    ) -> Result<StateRecord, TraitError> {
        Err(unused())
    }
    fn delete(&self, _r: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        Err(unused())
    }
    fn list(&self, _r: &ListStateRequest) -> Result<StateList, TraitError> {
        Err(unused())
    }
    fn host_state_root(&self) -> Option<&Path> {
        self.0.root.as_deref()
    }
}

/// core の既定の `wait_exit`（上書きなし）を持つ参照実装。`state` だけが世界を読む。
struct DefaultRef(Arc<World>);

impl ContainerRuntime for DefaultRef {
    fn create(&self, _r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        Err(unused())
    }
    fn start(&self, _r: &StartRequest) -> Result<ContainerStatus, TraitError> {
        Err(unused())
    }
    fn kill(&self, _r: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(unused())
    }
    fn stop(&self, _r: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Err(unused())
    }
    fn delete(&self, _r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        Err(unused())
    }
    fn state(&self, _r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        self.0.gets.fetch_add(1, Ordering::SeqCst);
        if self.0.missing.load(Ordering::SeqCst) {
            return Err(TraitError::new(ErrorCode::NotFound, "deleted"));
        }
        Ok(self.0.status.lock().expect("lock").clone())
    }
}

/// 通知口の振る舞い: (呼び出し番号, `until`, 取り消し判定) から結果を返す。
type Behavior = dyn Fn(u32, Instant, &dyn Fn() -> bool) -> ExitWatchOutcome + Send + Sync;

struct FakeNotifier {
    calls: AtomicU32,
    behavior: Box<Behavior>,
}

impl FakeNotifier {
    fn new(
        behavior: impl Fn(u32, Instant, &dyn Fn() -> bool) -> ExitWatchOutcome + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicU32::new(0),
            behavior: Box::new(behavior),
        })
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ExitNotifier for FakeNotifier {
    fn watch(
        &self,
        _id: &ContainerId,
        _pid: NonZeroU32,
        until: Instant,
        cancel: &dyn Fn() -> bool,
    ) -> ExitWatchOutcome {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        (self.behavior)(n, until, cancel)
    }
}

/// `gate` が開く・`until` に達する・取り消されるまで 5ms 刻みで待ち、結果を返す（実 supervisor の購読の写し）。
fn wait_gate(
    gate: &AtomicBool,
    until: Instant,
    cancel: &dyn Fn() -> bool,
    opened: ExitWatchOutcome,
) -> ExitWatchOutcome {
    loop {
        if cancel() {
            return ExitWatchOutcome::Cancelled;
        }
        if gate.load(Ordering::SeqCst) {
            return opened;
        }
        if Instant::now() >= until {
            return ExitWatchOutcome::Expired;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

struct Source(Arc<FakeNotifier>);

impl ExitNotifierSource for Source {
    fn notifier(&self, _store: &dyn StateStore) -> Option<Arc<dyn ExitNotifier>> {
        Some(Arc::clone(&self.0) as Arc<dyn ExitNotifier>)
    }
}

struct NoStart;

impl SupervisorStarter for NoStart {
    fn start(
        &self,
        _root: &Path,
        _log_path: Option<&ContainerLogPath>,
        _id: &ContainerId,
    ) -> (Result<NonZeroU32, OciRuntimeError>, Option<Child>) {
        (
            Err(OciRuntimeError::new(
                LifecycleOp::Start,
                ErrorCode::Unimplemented,
                "unused",
            )),
            None,
        )
    }
}

struct NoSignalers;

impl SignalerSource for NoSignalers {
    fn plain(&self, _store: &dyn StateStore) -> Arc<dyn ProcessSignaler> {
        Arc::new(UnavailableSignaler)
    }
    fn for_stop(&self, _store: &dyn StateStore) -> Arc<dyn ProcessSignaler> {
        Arc::new(UnavailableSignaler)
    }
}

fn runtime(world: &Arc<World>, notifier: Option<&Arc<FakeNotifier>>) -> CoreLifecycleRuntime {
    let rt = CoreLifecycleRuntime::new(Arc::new(WorldStore(Arc::clone(world))));
    match notifier {
        Some(n) => rt.with_supervision(
            SupervisedLifecycle::new(Arc::new(NoStart), Arc::new(NoSignalers))
                .with_exit_notifiers(Arc::new(Source(Arc::clone(n)))),
        ),
        None => rt,
    }
}

fn root() -> Option<PathBuf> {
    Some(PathBuf::from("/nonexistent/root"))
}

fn req(
    id: &str,
    timeout: Duration,
    poll: Duration,
    cancel: Option<&'static (dyn Fn() -> bool + Sync)>,
) -> WaitExitRequest<'static> {
    let r = WaitExitRequest::new(cid(id), timeout)
        .expect("timeout")
        .with_poll_interval(poll)
        .expect("poll");
    match cancel {
        Some(c) => r.with_cancel(c),
        None => r,
    }
}

/// CRI-1・SUP-1・#3683: 終了通知で起きた wait は、照会間隔（10 秒）より十分短い時間で `Stopped`（終了コード 7）を返す。
#[test]
fn cri1_sup1_3683_wait_exit_wakes_on_notification() {
    let world = World::new(ContainerStatus::running(cid("w1"), Some(pid(100))), root());
    let gate = Arc::new(AtomicBool::new(false));
    let g = Arc::clone(&gate);
    let notifier = FakeNotifier::new(move |_n, until, cancel| {
        wait_gate(&g, until, cancel, ExitWatchOutcome::Woken)
    });
    let rt = runtime(&world, Some(&notifier));
    let w = Arc::clone(&world);
    let g = Arc::clone(&gate);
    let flipper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        w.set(ContainerStatus::stopped(cid("w1"), Some(7)));
        g.store(true, Ordering::SeqCst);
    });
    let started = Instant::now();
    let st = rt
        .wait_exit(&req(
            "w1",
            Duration::from_secs(30),
            Duration::from_secs(10),
            None,
        ))
        .expect("woken by notification");
    let took = started.elapsed();
    flipper.join().expect("join");
    assert_eq!(st.state(), ContainerState::Stopped);
    assert_eq!(st.exit_code(), Some(7));
    assert!(took >= Duration::from_millis(150), "{took:?}");
    assert!(took < Duration::from_secs(1), "{took:?}");
    assert_eq!(notifier.calls(), 1);
    assert!(world.gets() >= 2 && world.gets() <= 6, "{}", world.gets());
}

/// CRI-1・#3683: 通知の直後に state.json がまだ `Running` でも、起床前の状態を返さず `Stopped` の記録を待って返す。
#[test]
fn cri1_3683_wait_exit_settles_until_stopped_is_recorded() {
    let world = World::new(ContainerStatus::running(cid("w2"), Some(pid(100))), root());
    let notifier = FakeNotifier::new(|_n, until, cancel| {
        // 100ms で通知する（状態はまだ Running）。
        let wake = Instant::now() + Duration::from_millis(100);
        while Instant::now() < wake.min(until) {
            if cancel() {
                return ExitWatchOutcome::Cancelled;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        ExitWatchOutcome::Woken
    });
    let rt = runtime(&world, Some(&notifier));
    let w = Arc::clone(&world);
    let flipper = std::thread::spawn(move || {
        // 通知の 50ms 後に Stopped が記録される。
        std::thread::sleep(Duration::from_millis(150));
        w.set(ContainerStatus::stopped(cid("w2"), Some(0)));
    });
    let started = Instant::now();
    let st = rt
        .wait_exit(&req(
            "w2",
            Duration::from_secs(30),
            Duration::from_secs(10),
            None,
        ))
        .expect("stopped");
    flipper.join().expect("join");
    assert_eq!(st.state(), ContainerState::Stopped);
    assert_eq!(st.exit_code(), Some(0));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(notifier.calls(), 1);
}

/// REPAIR-5・#3683: 期限切れの戻り値（code と message）は core の既定実装と同じ。
#[test]
fn repair5_3683_wait_exit_timeout_matches_default() {
    let world = World::new(ContainerStatus::running(cid("w3"), Some(pid(100))), root());
    let notifier = FakeNotifier::new(|_n, until, cancel| {
        // 実購読と同じく、期限までの間に 20ms 刻みで Expired を返す。
        let end = (Instant::now() + Duration::from_millis(20)).min(until);
        while Instant::now() < end {
            if cancel() {
                return ExitWatchOutcome::Cancelled;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        ExitWatchOutcome::Expired
    });
    let rt = runtime(&world, Some(&notifier));
    let started = Instant::now();
    let ours = rt
        .wait_exit(&req(
            "w3",
            Duration::from_millis(100),
            Duration::from_secs(10),
            None,
        ))
        .expect_err("timeout");
    let took = started.elapsed();
    let theirs = DefaultRef(Arc::clone(&world))
        .wait_exit(&req(
            "w3",
            Duration::from_millis(100),
            Duration::from_millis(30),
            None,
        ))
        .expect_err("timeout");
    assert_eq!(ours.code(), ErrorCode::Timeout);
    assert_eq!(ours.message(), "wait exceeded its deadline");
    assert_eq!(ours.code(), theirs.code());
    assert_eq!(ours.message(), theirs.message());
    assert!(took >= Duration::from_millis(100), "{took:?}");
    assert!(took < Duration::from_secs(1), "{took:?}");
}

static RAISED: AtomicBool = AtomicBool::new(false);
fn raised() -> bool {
    RAISED.load(Ordering::SeqCst)
}

/// REPAIR-5・#3683: 購読中の取り消しは、`Unavailable`「wait cancelled」（既定と同じ）で、取り消しから 100ms 未満で戻る。
/// 購読の前に既に取り消されていれば、通知口を呼ばずに同じ戻り値になる。
#[test]
fn repair5_3683_wait_exit_cancel_matches_default() {
    let world = World::new(ContainerStatus::running(cid("w4"), Some(pid(100))), root());
    let gate = Arc::new(AtomicBool::new(false));
    let g = Arc::clone(&gate);
    let notifier = FakeNotifier::new(move |_n, until, cancel| {
        wait_gate(&g, until, cancel, ExitWatchOutcome::Woken)
    });
    let rt = runtime(&world, Some(&notifier));
    RAISED.store(false, Ordering::SeqCst);
    let flipper = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(100));
        RAISED.store(true, Ordering::SeqCst);
        Instant::now()
    });
    let ours = rt
        .wait_exit(&req(
            "w4",
            Duration::from_secs(30),
            Duration::from_secs(10),
            Some(&raised),
        ))
        .expect_err("cancelled");
    let back = Instant::now();
    let at = flipper.join().expect("join");
    assert!(
        back.saturating_duration_since(at) < Duration::from_millis(100),
        "{:?}",
        back.saturating_duration_since(at)
    );
    // 既に取り消し済みの状態で、既定と我々の戻り値を比べる。
    let calls_before = notifier.calls();
    let ours_pre = rt
        .wait_exit(&req(
            "w4",
            Duration::from_secs(30),
            Duration::from_secs(10),
            Some(&raised),
        ))
        .expect_err("cancelled");
    let theirs = DefaultRef(Arc::clone(&world))
        .wait_exit(&req(
            "w4",
            Duration::from_secs(30),
            Duration::from_millis(30),
            Some(&raised),
        ))
        .expect_err("cancelled");
    RAISED.store(false, Ordering::SeqCst);
    assert_eq!(ours.code(), ErrorCode::Unavailable);
    assert_eq!(ours.message(), "wait cancelled");
    assert_eq!(ours_pre.code(), theirs.code());
    assert_eq!(ours_pre.message(), theirs.message());
    assert_eq!(ours.code(), theirs.code());
    assert_eq!(ours.message(), theirs.message());
    assert_eq!(notifier.calls(), calls_before);
}

/// REPAIR-5・#3683: 状態の取得の失敗（待ちの途中の削除による `NotFound`）は、既定と同じくそのまま返す。
#[test]
fn repair5_3683_wait_exit_state_error_is_returned_as_is() {
    let world = World::new(ContainerStatus::running(cid("w5"), Some(pid(100))), root());
    world.missing.store(true, Ordering::SeqCst);
    let notifier = FakeNotifier::new(|_n, _u, _c| ExitWatchOutcome::Expired);
    let rt = runtime(&world, Some(&notifier));
    let ours = rt
        .wait_exit(&req(
            "w5",
            Duration::from_secs(5),
            Duration::from_secs(1),
            None,
        ))
        .expect_err("not found");
    let theirs = DefaultRef(Arc::clone(&world))
        .wait_exit(&req(
            "w5",
            Duration::from_secs(5),
            Duration::from_secs(1),
            None,
        ))
        .expect_err("not found");
    assert_eq!(ours.code(), ErrorCode::NotFound);
    assert_eq!(ours.code(), theirs.code());
    assert_eq!(ours.message(), theirs.message());
    assert_eq!(notifier.calls(), 0);
}

/// CRI-1・SUP-1・#3683: supervisor が無い（`NoSupervisor`）ときは照会へ退避する。通知口は 1 回だけ試し、以後その呼び出しでは再購読しない。
#[test]
fn cri1_3683_wait_exit_falls_back_to_polling_without_supervisor() {
    let world = World::new(ContainerStatus::running(cid("w6"), Some(pid(100))), root());
    let notifier = FakeNotifier::new(|_n, _u, _c| ExitWatchOutcome::NoSupervisor);
    let rt = runtime(&world, Some(&notifier));
    let w = Arc::clone(&world);
    let flipper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        w.set(ContainerStatus::stopped(cid("w6"), Some(3)));
    });
    let st = rt
        .wait_exit(&req(
            "w6",
            Duration::from_secs(10),
            Duration::from_millis(30),
            None,
        ))
        .expect("polled");
    flipper.join().expect("join");
    assert_eq!(st.exit_code(), Some(3));
    assert_eq!(notifier.calls(), 1);
    // 300ms / 30ms 間隔 = 約 10 回 + 初回と最後。
    assert!(world.gets() >= 6 && world.gets() <= 20, "{}", world.gets());
}

/// CRI-1・#3683: 状態ルートの無いストアでは通知口が作られず、照会だけで待つ（本番の購読口は `None`）。
#[test]
fn cri1_3683_wait_exit_without_host_state_root_polls() {
    let world = World::new(ContainerStatus::running(cid("w7"), Some(pid(100))), None);
    let rt = runtime(&world, None);
    let w = Arc::clone(&world);
    let flipper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        w.set(ContainerStatus::stopped(cid("w7"), Some(1)));
    });
    let st = rt
        .wait_exit(&req(
            "w7",
            Duration::from_secs(10),
            Duration::from_millis(30),
            None,
        ))
        .expect("polled");
    flipper.join().expect("join");
    assert_eq!(st.exit_code(), Some(1));
}

/// REPAIR-5・#3683: 一時的な失敗（`Transient`）は 1 回分を照会で待ち、次の周回で購読をやり直す。
#[test]
fn repair5_3683_wait_exit_transient_retries_subscription() {
    let world = World::new(ContainerStatus::running(cid("w8"), Some(pid(100))), root());
    let gate = Arc::new(AtomicBool::new(false));
    let g = Arc::clone(&gate);
    let notifier = FakeNotifier::new(move |n, until, cancel| {
        if n == 0 {
            ExitWatchOutcome::Transient
        } else {
            wait_gate(&g, until, cancel, ExitWatchOutcome::Woken)
        }
    });
    let rt = runtime(&world, Some(&notifier));
    let w = Arc::clone(&world);
    let g = Arc::clone(&gate);
    let flipper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        w.set(ContainerStatus::stopped(cid("w8"), Some(9)));
        g.store(true, Ordering::SeqCst);
    });
    let st = rt
        .wait_exit(&req(
            "w8",
            Duration::from_secs(10),
            Duration::from_millis(30),
            None,
        ))
        .expect("woken");
    flipper.join().expect("join");
    assert_eq!(st.exit_code(), Some(9));
    assert_eq!(notifier.calls(), 2);
}

/// CRI-1・#3683: `Created`（pid なし）の間は購読しない。通知口を呼ばず照会で待つ。
#[test]
fn cri1_3683_wait_exit_does_not_subscribe_while_created() {
    let world = World::new(ContainerStatus::created(cid("w9"), None), root());
    let notifier = FakeNotifier::new(|_n, _u, _c| ExitWatchOutcome::Woken);
    let rt = runtime(&world, Some(&notifier));
    let w = Arc::clone(&world);
    let flipper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        w.set(ContainerStatus::stopped(cid("w9"), Some(0)));
    });
    let st = rt
        .wait_exit(&req(
            "w9",
            Duration::from_secs(10),
            Duration::from_millis(30),
            None,
        ))
        .expect("polled");
    flipper.join().expect("join");
    assert_eq!(st.state(), ContainerState::Stopped);
    assert_eq!(notifier.calls(), 0);
}
