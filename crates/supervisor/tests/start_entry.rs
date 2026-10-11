//! supervisor の bin の入口（起動の処理順・報告・後始末・relaunch アダプタ）の結合試験
//! （TASK-157 追補・#1717・SUP-1・SUP-3・CORE-2・CORE-3・REPAIR-3・REPAIR-5）。
//!
//! 公開 API だけを使い、フェイクの `StartDeps` と `ProcessLauncher`、実物の `FileStateStore`・bundle で
//! `run_start` / `run_supervised` を通す。root 不要で既定のテスト集合で動く。`FileStateStore` と rootfs の
//! fd 固定は Linux 限定のため、全体を `cfg(target_os = "linux")` に置く（Linux 以外の fail-closed は
//! core 側の試験が照合する）。

#![cfg(target_os = "linux")]

use std::io::Write;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, StartTimeouts, create, exit_code_for,
};
use fandhe_container_core::traits::{
    CgroupScope, ContainerId, ContainerState, CreateRequest, ErrorCode, GetStateRequest,
    StartRequest, StateRecord, StateStore, TraitError, UpdateStateRequest,
};
use fandhe_container_supervisor::restart::RestartPolicy;
use fandhe_container_supervisor::run::StopToken;
use fandhe_container_supervisor::start_contract::StartReport;
use fandhe_container_supervisor::start_entry::{Running, StartDeps, run_start, run_supervised};
use fandhe_container_supervisor::state::open_default_store;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 状態ルートと bundle を持つ一時ディレクトリ（drop で削除）。
struct Env {
    /// テストごとに一意なコンテナ ID（core の start の予約はプロセス内で ID 単位に排他するため、並列テストで共有しない）。
    id: String,
    base: PathBuf,
    store: Arc<dyn StateStore>,
}

impl Env {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base =
            std::env::temp_dir().join(format!("fandhe-sup-start-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("bundle/rootfs")).unwrap();
        std::fs::write(
            base.join("bundle/config.json"),
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},
"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},
"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
        )
        .unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = base.join("state");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = open_default_store(Some(root)).unwrap();
        Self {
            id: format!("c-{tag}-{n}"),
            base,
            store,
        }
    }

    fn create(&self, id: &str) {
        let req = CreateRequest::new(cid(id), self.base.join("bundle")).unwrap();
        create(self.store.as_ref(), &OpRecorder::new(), &req).unwrap();
    }

    fn record(&self, id: &str) -> StateRecord {
        self.store.get(&GetStateRequest::new(cid(id))).unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).unwrap()
}

/// 起動待ち 100ms・終了待ち 1s・確認待ち 500ms の短い上限。
fn short_timeouts() -> StartTimeouts {
    StartTimeouts::new(
        Duration::from_millis(100),
        Duration::from_secs(1),
        Duration::from_millis(500),
    )
    .unwrap()
}

type Calls = Arc<Mutex<Vec<&'static str>>>;

fn calls_of(c: &Calls) -> Vec<&'static str> {
    c.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[derive(Clone, Copy)]
enum WaitMode {
    Pending,
    Error(ErrorCode),
    ExitedOk,
}

/// 模擬プロセス（terminate の回数を数える）。
struct FakeProcess {
    pid: u32,
    terminated: Arc<AtomicUsize>,
    wait_mode: WaitMode,
    fail_terminate: bool,
}

impl LaunchedProcess for FakeProcess {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(self.pid).unwrap()
    }

    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        match self.wait_mode {
            WaitMode::Pending => {
                std::thread::sleep(timeout.min(Duration::from_millis(10)));
                Ok(None)
            }
            WaitMode::Error(code) => Err(TraitError::new(code, "wait failed")),
            WaitMode::ExitedOk => Ok(Some(ProcessExit::Exited(0))),
        }
    }

    fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
        self.terminated.fetch_add(1, Ordering::SeqCst);
        if self.fail_terminate {
            return Err(TraitError::new(ErrorCode::Internal, "terminate failed"));
        }
        Ok(())
    }
}

/// 模擬 launcher（起動の仕様・回数・確認の回数を記録する）。
struct FakeLauncher {
    calls: Calls,
    specs: Mutex<Vec<LaunchSpec>>,
    timeouts: Mutex<Vec<Duration>>,
    terminated: Arc<AtomicUsize>,
    confirms: AtomicUsize,
    launch_error: Option<ErrorCode>,
    delay: Duration,
    confirm_ok: bool,
    wait_mode: WaitMode,
    fail_terminate: bool,
}

impl FakeLauncher {
    fn new(calls: &Calls) -> Self {
        Self {
            calls: Arc::clone(calls),
            specs: Mutex::new(Vec::new()),
            timeouts: Mutex::new(Vec::new()),
            terminated: Arc::new(AtomicUsize::new(0)),
            confirms: AtomicUsize::new(0),
            launch_error: None,
            delay: Duration::ZERO,
            confirm_ok: true,
            wait_mode: WaitMode::Pending,
            fail_terminate: false,
        }
    }

    fn launches(&self) -> usize {
        self.specs.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl ProcessLauncher for FakeLauncher {
    fn launch(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push("launch");
        self.specs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(spec.clone());
        self.timeouts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(timeout);
        std::thread::sleep(self.delay);
        if let Some(code) = self.launch_error {
            return Err(TraitError::new(code, "launch failed"));
        }
        Ok(Box::new(FakeProcess {
            pid: 4242,
            terminated: Arc::clone(&self.terminated),
            wait_mode: self.wait_mode,
            fail_terminate: self.fail_terminate,
        }))
    }

    fn confirm_no_process(&self, _id: &ContainerId, _timeout: Duration) -> Result<(), TraitError> {
        self.confirms.fetch_add(1, Ordering::SeqCst);
        if self.confirm_ok {
            Ok(())
        } else {
            Err(TraitError::new(ErrorCode::Unimplemented, "cannot confirm"))
        }
    }
}

/// 呼ばれた順を記録するフェイクの `StartDeps`。`fail_at` の段で `Internal` を返す。
struct FakeDeps {
    calls: Calls,
    launcher: Arc<FakeLauncher>,
    fail_at: Option<&'static str>,
    unavailable: bool,
}

impl FakeDeps {
    fn step(&self, name: &'static str) -> Result<(), TraitError> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(name);
        if self.fail_at == Some(name) {
            return Err(TraitError::new(ErrorCode::PermissionDenied, "step failed"));
        }
        Ok(())
    }
}

impl StartDeps for FakeDeps {
    fn check_launcher_available(&self) -> Result<(), TraitError> {
        self.step("check")?;
        if self.unavailable {
            return Err(TraitError::new(
                ErrorCode::Unimplemented,
                "production process launcher is not available yet",
            ));
        }
        Ok(())
    }

    fn prepare_cgroup(
        &mut self,
        _store: &dyn StateStore,
        _observed: &StateRecord,
    ) -> Result<(), TraitError> {
        self.step("prepare")
    }

    fn build_audit_sink(&mut self) -> Result<(), TraitError> {
        self.step("audit")
    }

    fn build_launcher(&mut self) -> Result<Arc<dyn ProcessLauncher>, TraitError> {
        self.step("build")?;
        Ok(self.launcher.clone())
    }

    fn release_cgroup(&mut self) -> Result<(), TraitError> {
        self.step("release")
    }
}

fn deps(calls: &Calls, launcher: FakeLauncher) -> (FakeDeps, Arc<FakeLauncher>) {
    let launcher = Arc::new(launcher);
    (
        FakeDeps {
            calls: Arc::clone(calls),
            launcher: Arc::clone(&launcher),
            fail_at: None,
            unavailable: false,
        },
        launcher,
    )
}

fn new_calls() -> Calls {
    Arc::new(Mutex::new(Vec::new()))
}

fn start_with(
    env: &Env,
    deps: &mut FakeDeps,
    id: &str,
    timeouts: &StartTimeouts,
    out: &mut dyn Write,
) -> Result<Running, std::num::NonZeroU8> {
    run_start(
        deps,
        env.store.as_ref(),
        &OpRecorder::new(),
        &StartRequest::new(cid(id)),
        timeouts,
        out,
    )
}

fn report_of(out: &[u8]) -> StartReport {
    StartReport::decode(out).expect("a valid report line")
}

/// SUP-1: 成功時の呼び出し順・報告・状態。
#[test]
fn sup1_start_order_on_success() {
    let env = Env::new("order");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
    let mut out = Vec::new();
    let running = start_with(&env, &mut d, &env.id, &short_timeouts(), &mut out)
        .unwrap_or_else(|_| panic!("started: {}", String::from_utf8_lossy(&out)));
    assert_eq!(
        calls_of(&calls),
        ["check", "prepare", "audit", "build", "launch"]
    );
    assert_eq!(out, b"FCSUP1 OK 4242\n");
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Running);
    assert_eq!(rec.status().pid(), NonZeroU32::new(4242));
    drop(running);
}

/// REPAIR-3: launcher が使えない間は副作用の前に止まり、状態にも cgroup にも何も残さない。
#[test]
fn repair3_start_stops_before_side_effects_when_launcher_unavailable() {
    let env = Env::new("unavail");
    env.create(&env.id);
    let before = env.record(&env.id);
    let calls = new_calls();
    let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
    d.unavailable = true;
    let mut out = Vec::new();
    let code = start_with(&env, &mut d, &env.id, &short_timeouts(), &mut out)
        .err()
        .expect("must fail");
    assert_eq!(calls_of(&calls), ["check"]);
    let after = env.record(&env.id);
    assert_eq!(after.status().state(), ContainerState::Created);
    assert_eq!(after.revision(), before.revision());
    assert!(after.cgroup().is_none());
    assert_eq!(code, exit_code_for(ErrorCode::Unimplemented));
    match report_of(&out) {
        StartReport::Failed {
            code: c,
            exit_code,
            message,
        } => {
            assert_eq!(c, ErrorCode::Unimplemented);
            assert_eq!(exit_code, exit_code_for(ErrorCode::Unimplemented));
            assert_eq!(
                message.as_str(),
                "production process launcher is not available yet"
            );
        }
        other => panic!("unexpected report: {other:?}"),
    }
}

/// CORE-3: cgroup の準備に失敗したら launch せず、作った cgroup を解放し、状態は Created のまま。
#[test]
fn core3_start_failure_in_prepare_cgroup_does_not_launch() {
    let env = Env::new("prep");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, l) = deps(&calls, FakeLauncher::new(&calls));
    d.fail_at = Some("prepare");
    let mut out = Vec::new();
    assert!(start_with(&env, &mut d, &env.id, &short_timeouts(), &mut out).is_err());
    assert_eq!(calls_of(&calls), ["check", "prepare", "release"]);
    assert_eq!(l.launches(), 0);
    assert_eq!(
        env.record(&env.id).status().state(),
        ContainerState::Created
    );
    match report_of(&out) {
        StartReport::Failed { code, .. } => assert_eq!(code, ErrorCode::PermissionDenied),
        other => panic!("unexpected report: {other:?}"),
    }
}

/// CORE-2: launch 失敗で cgroup を解放し、予約は Created へ戻り、生存プロセスは残らない。
#[test]
fn core2_launch_failure_releases_cgroup_and_reverts() {
    let env = Env::new("launchfail");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.launch_error = Some(ErrorCode::Internal);
    let (mut d, l) = deps(&calls, fl);
    let mut out = Vec::new();
    assert!(start_with(&env, &mut d, &env.id, &short_timeouts(), &mut out).is_err());
    assert_eq!(
        calls_of(&calls),
        ["check", "prepare", "audit", "build", "launch", "release"]
    );
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Created);
    assert!(rec.status().pid().is_none());
    assert_eq!(l.terminated.load(Ordering::SeqCst), 0);
    match report_of(&out) {
        StartReport::Failed { code, .. } => assert_eq!(code, ErrorCode::Internal),
        other => panic!("unexpected report: {other:?}"),
    }
}

/// REPAIR-5: launch が上限を超えたら、遅れて返ったプロセスを terminate し、予約を Created へ戻して TIMEOUT を報告する。
#[test]
fn repair5_launch_timeout_terminates_late_process_and_recovers() {
    let env = Env::new("timeout");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.delay = Duration::from_millis(2500);
    let (mut d, l) = deps(&calls, fl);
    let mut out = Vec::new();
    assert!(start_with(&env, &mut d, &env.id, &short_timeouts(), &mut out).is_err());
    assert_eq!(l.terminated.load(Ordering::SeqCst), 1);
    assert!(l.confirms.load(Ordering::SeqCst) >= 1);
    assert_eq!(
        env.record(&env.id).status().state(),
        ContainerState::Created
    );
    assert_eq!(calls_of(&calls).last(), Some(&"release"));
    match report_of(&out) {
        StartReport::Failed { code, .. } => assert_eq!(code, ErrorCode::Timeout),
        other => panic!("unexpected report: {other:?}"),
    }
}

/// REPAIR-5: 生存プロセスが無いと確認できなければ予約を残し、cgroup も消さずに INTERNAL を報告する。
#[test]
fn repair5_launch_timeout_without_confirmation_reports_internal() {
    let env = Env::new("noconfirm");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.delay = Duration::from_millis(2500);
    fl.confirm_ok = false;
    let (mut d, _l) = deps(&calls, fl);
    let mut out = Vec::new();
    assert!(start_with(&env, &mut d, &env.id, &short_timeouts(), &mut out).is_err());
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Running);
    assert!(rec.status().pid().is_none());
    assert!(!calls_of(&calls).contains(&"release"));
    match report_of(&out) {
        StartReport::Failed { code, .. } => assert_eq!(code, ErrorCode::Internal),
        other => panic!("unexpected report: {other:?}"),
    }
}

/// 報告先が壊れていても（EPIPE 等）起動済みのハンドルを返して監視へ進める。
#[test]
fn sup1_report_write_failure_keeps_monitoring() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let env = Env::new("broken");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
    let running =
        start_with(&env, &mut d, &env.id, &short_timeouts(), &mut Broken).expect("started");
    assert_eq!(running.process.pid().get(), 4242);
    assert_eq!(
        env.record(&env.id).status().state(),
        ContainerState::Running
    );
}

/// 記録済みの cgroup スコープがあれば、cgroup の準備より前に FailedPrecondition で止まる（スコープの再追記を試みない）。
#[test]
fn sup1_recorded_scope_rejects_restart() {
    let env = Env::new("scope");
    env.create(&env.id);
    let rec = env.record(&env.id);
    let req = UpdateStateRequest::new(rec.status().clone(), rec.revision())
        .with_cgroup_scope(CgroupScope::new("/sys/fs/cgroup/user/fandhe").unwrap());
    env.store.update(&req).unwrap();
    let calls = new_calls();
    let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
    let mut out = Vec::new();
    assert!(start_with(&env, &mut d, &env.id, &short_timeouts(), &mut out).is_err());
    assert!(calls_of(&calls).is_empty());
    match report_of(&out) {
        StartReport::Failed { code, message, .. } => {
            assert_eq!(code, ErrorCode::FailedPrecondition);
            assert_eq!(
                message.as_str(),
                "cgroup scope is already recorded; delete and recreate the container"
            );
        }
        other => panic!("unexpected report: {other:?}"),
    }
}

/// 未 create の ID は NOT_FOUND を報告し、何も呼ばない。
#[test]
fn sup1_unknown_container_reports_not_found() {
    let env = Env::new("nf");
    let calls = new_calls();
    let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
    let mut out = Vec::new();
    assert!(start_with(&env, &mut d, "nope", &short_timeouts(), &mut out).is_err());
    assert!(calls_of(&calls).is_empty());
    match report_of(&out) {
        StartReport::Failed { code, .. } => assert_eq!(code, ErrorCode::NotFound),
        other => panic!("unexpected report: {other:?}"),
    }
}

/// CORE-1: 監視が返したハンドルは終了前に terminate する。回収できなければ Internal の終了コード。
#[test]
fn sup1_monitor_exit_disposes_returned_handles() {
    // terminate 成功: 監視の失敗コードがそのまま終了コードになる。
    let env = Env::new("dispose");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.wait_mode = WaitMode::Error(ErrorCode::Timeout);
    let (mut d, l) = deps(&calls, fl);
    let running =
        start_with(&env, &mut d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
    let code = run_supervised(
        env.store.clone(),
        cid(&env.id),
        running,
        RestartPolicy::No,
        &short_timeouts(),
        &StopToken::new(),
    );
    assert_eq!(l.terminated.load(Ordering::SeqCst), 1);
    assert_eq!(code, exit_code_for(ErrorCode::Timeout).get());

    // terminate 失敗: Err で戻ったハンドルは 1 回だけ再試行し（初回＋再試行の 2 回）、なお失敗なら
    // 回収を確かめられないので Internal（CORE-1・REPAIR-5）。
    let env = Env::new("dispose2");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.wait_mode = WaitMode::Error(ErrorCode::Timeout);
    fl.fail_terminate = true;
    let (mut d, l) = deps(&calls, fl);
    let running =
        start_with(&env, &mut d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
    let code = run_supervised(
        env.store.clone(),
        cid(&env.id),
        running,
        RestartPolicy::No,
        &short_timeouts(),
        &StopToken::new(),
    );
    assert_eq!(l.terminated.load(Ordering::SeqCst), 2);
    assert_eq!(code, exit_code_for(ErrorCode::Internal).get());
}

/// SUP-1: ポリシー `no` で正常終了したら Stopped を記録して終了コード 0。
#[test]
fn sup1_supervised_exit_is_recorded_and_returns_zero() {
    let env = Env::new("finished");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.wait_mode = WaitMode::ExitedOk;
    let (mut d, l) = deps(&calls, fl);
    let running =
        start_with(&env, &mut d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
    let code = run_supervised(
        env.store.clone(),
        cid(&env.id),
        running,
        RestartPolicy::No,
        &short_timeouts(),
        &StopToken::new(),
    );
    assert_eq!(code, 0);
    assert_eq!(
        env.record(&env.id).status().state(),
        ContainerState::Stopped
    );
    assert_eq!(l.terminated.load(Ordering::SeqCst), 0);
}

/// SUP-3: relaunch は start で捕捉した spec と launcher をそのまま使い、timeout をそのまま渡す。
/// 終了したら policy `always` で同じ spec が再度 launch される。
#[test]
fn sup3_launcher_relauncher_uses_same_launcher_and_spec() {
    let env = Env::new("relaunch");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, l) = deps(&calls, FakeLauncher::new(&calls));
    let running =
        start_with(&env, &mut d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
    let again = running
        .relauncher
        .relaunch(Duration::from_millis(1234))
        .expect("relaunch");
    assert_eq!(again.pid().get(), 4242);
    assert_eq!(l.launches(), 2);
    let specs = l.specs.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(specs[0], specs[1]);
    assert_eq!(
        l.timeouts.lock().unwrap_or_else(|e| e.into_inner())[1],
        Duration::from_millis(1234)
    );
    assert_eq!(specs[0].args(), ["/bin/echo", "it"]);
    assert!(Path::new(specs[0].rootfs()).ends_with("bundle/rootfs"));
}

/// 書き込みが戻らない書き手。
struct StuckWriter(std::sync::mpsc::Receiver<()>);

impl Write for StuckWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = self.0.recv();
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// REPAIR-5・SUP-1: 結果チャネルの書き込みが止まっても、期限で `TimedOut` を返して先へ進める。
#[test]
fn repair5_bounded_writer_times_out_on_stuck_reader() {
    let (release, stuck) = std::sync::mpsc::channel();
    let mut w = fandhe_container_supervisor::start_entry::BoundedWriter::new(
        StuckWriter(stuck),
        Duration::from_millis(100),
    );
    let started = std::time::Instant::now();
    let err = w.write_all(b"FCSUP1 OK 1\n").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(5));
    let _ = release.send(());
}
