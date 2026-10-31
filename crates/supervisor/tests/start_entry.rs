//! supervisor の bin の入口（起動の処理順・報告・後始末・relaunch アダプタ）の結合試験
//! （TASK-157 追補・#1717・SUP-1・SUP-3・CORE-2・CORE-3・REPAIR-3・REPAIR-5）。
//!
//! 公開 API だけを使い、フェイクの `StartDeps` と `ProcessLauncher`、実物の `FileStateStore`・bundle で
//! `run_start` / `run_supervised` を通す。root 不要で既定のテスト集合で動く。`FileStateStore` と rootfs の
//! fd 固定は Linux 限定のため、全体を `cfg(target_os = "linux")` に置く（Linux 以外の fail-closed は
//! core 側の試験が照合する）。

#![cfg(target_os = "linux")]

// 一時領域の親を tmpfiles の flock 走査から守る共有部品（#3026・CORE-5・REPAIR-12）。
#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

use std::io::Write;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::audit_log::{AuditLayer, AuditRecord, AuditSink, PastaVerifyRejection};
use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    LaunchMode, LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, StartTimeouts, create,
    exit_code_for,
};
use fandhe_container_core::traits::{
    CgroupScope, ContainerId, ContainerState, ContainerStatus, CreateRequest, ErrorCode,
    GetStateRequest, StartRequest, StateRecord, StateRevision, StateStore, TraitError,
    UpdateStateRequest,
};
use fandhe_container_supervisor::pasta_attach::PastaLogBuffer;
use fandhe_container_supervisor::restart::RestartPolicy;
use fandhe_container_supervisor::run::StopToken;
use fandhe_container_supervisor::start_contract::{StartReport, result_deadline};
use fandhe_container_supervisor::start_entry::{
    DEADLINE_EXCEEDED_MESSAGE, LATE_DRAIN_BUDGET, REPORT_RESERVE, Running, START_OP, StartDeps,
    TAMPER_AUDIT_BUDGET, run_start, run_start_after_options_worker_for_test, run_start_until,
    run_supervised, start_metrics_line,
};
use fandhe_container_supervisor::state::open_default_store;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 状態ルートと bundle を持つ一時ディレクトリ（drop で削除）。
struct Env {
    /// テストごとに一意なコンテナ ID（core の start の予約はプロセス内で ID 単位に排他するため、並列テストで共有しない）。
    id: String,
    base: PathBuf,
    store: Arc<dyn StateStore>,
    /// tmpfiles の flock 走査から守る親（#3026）。`base` はその子。最後のフィールドで、`Drop` の後に親が消える。
    _scratch: scratch_root::ScratchDir,
}

impl Env {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let scratch =
            scratch_root::ScratchDir::new("fandhe-sup-start", std::time::Duration::from_secs(10));
        let base = scratch.path().join(format!("{tag}-{n}"));
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
            _scratch: scratch,
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
    /// 終了コード 7 で終わる(restart の `on-failure` の試験用。#2043)。
    ExitedFailure,
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
            WaitMode::ExitedFailure => Ok(Some(ProcessExit::Exited(7))),
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
    /// `true` なら本番 launcher と同じ `SelfBounded` を宣言する（入口が呼び出しスレッドで直接 launch する。#1819）。
    self_bounded: bool,
    /// `true` なら launch の失敗で「子が残り得る」と答える（`last_launch_may_have_left_process`）。
    left_process: bool,
    /// `Some(n)` なら n 回目（1 始まり）以降の launch を、単一スレッドの要求を満たさない呼び出しの拒否
    /// （`FailedPrecondition`）として失敗させる。
    reject_from: Option<usize>,
    /// `true` なら `fandhe-relaunch` スレッド（別スレッドでの再 launch）から呼ばれた launch を、単一スレッドの要求を
    /// 満たさない呼び出しとして拒否する（本番 launcher の `Threads: 1` の代わり。#2043）。
    reject_on_relaunch_thread: bool,
    /// launch を呼んだスレッドの ID と名前。
    launch_threads: Mutex<Vec<(std::thread::ThreadId, Option<String>)>>,
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
            self_bounded: false,
            left_process: false,
            reject_from: None,
            reject_on_relaunch_thread: false,
            launch_threads: Mutex::new(Vec::new()),
        }
    }

    fn launches(&self) -> usize {
        self.specs.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl ProcessLauncher for FakeLauncher {
    fn launch_mode(&self) -> LaunchMode {
        if self.self_bounded {
            LaunchMode::SelfBounded
        } else {
            LaunchMode::CallerBounded
        }
    }

    fn last_launch_may_have_left_process(&self) -> bool {
        self.left_process
    }

    fn launch(
        &self,
        spec: &LaunchSpec,
        timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push("launch");
        self.launch_threads
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((
                std::thread::current().id(),
                std::thread::current().name().map(str::to_owned),
            ));
        let nth = {
            let mut specs = self.specs.lock().unwrap_or_else(|e| e.into_inner());
            specs.push(spec.clone());
            specs.len()
        };
        self.timeouts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(timeout);
        std::thread::sleep(self.delay);
        let on_relaunch_thread = std::thread::current().name() == Some("fandhe-relaunch");
        if self.reject_from.is_some_and(|n| nth >= n)
            || (self.reject_on_relaunch_thread && on_relaunch_thread)
        {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "launch requires a single-threaded process",
            ));
        }
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
    /// `prepare_cgroup` が返す準備した世代（既定 `None` = スコープを記録しない）。
    prepared_instance: Option<StateRevision>,
    /// `true` なら `prepare_cgroup` が本番と同じくスコープを状態へ記録し、その instance を返す。
    record_scope: bool,
    /// `prepare_cgroup` の所要時間（期限超過の試験で起動処理を止める）。
    prepare_delay: Duration,
    /// `true` なら `release_cgroup` が失敗する。
    release_fails: bool,
    /// `recover_interrupted` が返すエラーの code（`None` なら成功。#2011）。
    recover_fails: Option<ErrorCode>,
    /// `true` なら `prepare_network` / `release_network` / `network_log_mode` を実装して呼び出しを記録する(#1873・D14)。
    net_hooks: bool,
    /// 遅延バッファに積まれた行（`flush_deferred_logs` が取り出す。#3359）。
    deferred: Arc<Mutex<Vec<String>>>,
    /// `flush_deferred_logs` が出した行と時刻（#3359）。
    flushed: Arc<Mutex<Vec<(std::time::Instant, String)>>>,
    /// `flush_deferred_logs` の呼び出し回数（#3359）。
    flushes: Arc<AtomicUsize>,
    /// `check_launcher_available` が `unavailable` より先に返す 2c の失敗(本番の `container_options_error` と同じ位置。#3473)。
    options_error: Option<TraitError>,
    /// 設定すると `flush_deferred_logs` がこのバッファも取り出す(本番の `pasta_logs.flush()` と同じ。#3473)。
    pasta_logs: Option<Arc<PastaLogBuffer>>,
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
        if let Some(e) = &self.options_error {
            return Err(e.clone());
        }
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
        store: &dyn StateStore,
        observed: &StateRecord,
    ) -> Result<Option<StateRevision>, TraitError> {
        self.step("prepare")?;
        let instance = if self.record_scope {
            let req = UpdateStateRequest::new(observed.status().clone(), observed.revision())
                .with_cgroup_scope(CgroupScope::new("/sys/fs/cgroup/user/fandhe").unwrap());
            store.update(&req)?.cgroup().map(|c| c.instance())
        } else {
            self.prepared_instance
        };
        std::thread::sleep(self.prepare_delay);
        Ok(instance)
    }

    fn prepare_network(&mut self, _id: &ContainerId) -> Result<(), TraitError> {
        if self.net_hooks {
            self.step("net")?;
        }
        Ok(())
    }

    fn release_network(&mut self) -> Result<(), TraitError> {
        if self.net_hooks {
            self.step("release_net")?;
        }
        Ok(())
    }

    fn network_log_mode(&self) -> Option<&'static str> {
        self.net_hooks.then_some("host")
    }

    fn build_audit_sink(&mut self) -> Result<(), TraitError> {
        self.step("audit")
    }

    fn flush_deferred_logs(&self) {
        let mut lines =
            std::mem::take(&mut *self.deferred.lock().unwrap_or_else(|e| e.into_inner()));
        if let Some(logs) = &self.pasta_logs {
            lines.extend(logs.take());
        }
        let now = std::time::Instant::now();
        self.flushed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(lines.into_iter().map(|l| (now, l)));
        self.flushes.fetch_add(1, Ordering::SeqCst);
    }

    fn build_launcher(&mut self) -> Result<Arc<dyn ProcessLauncher>, TraitError> {
        self.step("build")?;
        Ok(self.launcher.clone())
    }

    fn recover_interrupted(
        &mut self,
        _store: &dyn StateStore,
        _id: &ContainerId,
        _timeouts: &StartTimeouts,
    ) -> Result<(), TraitError> {
        self.step("recover")?;
        match self.recover_fails {
            Some(code) => Err(TraitError::new(code, "recover failed")),
            None => Ok(()),
        }
    }

    fn release_cgroup(&mut self) -> Result<(), TraitError> {
        self.step("release")?;
        if self.release_fails {
            return Err(TraitError::new(ErrorCode::Internal, "release failed"));
        }
        Ok(())
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
            prepared_instance: None,
            record_scope: false,
            prepare_delay: Duration::ZERO,
            release_fails: false,
            recover_fails: None,
            net_hooks: false,
            deferred: Arc::new(Mutex::new(Vec::new())),
            flushed: Arc::new(Mutex::new(Vec::new())),
            flushes: Arc::new(AtomicUsize::new(0)),
            options_error: None,
            pasta_logs: None,
        },
        launcher,
    )
}

fn new_calls() -> Calls {
    Arc::new(Mutex::new(Vec::new()))
}

fn start_with(
    env: &Env,
    deps: FakeDeps,
    id: &str,
    timeouts: &StartTimeouts,
    out: &mut dyn Write,
) -> Result<Running, std::num::NonZeroU8> {
    run_start(
        Box::new(deps),
        &env.store,
        &Arc::new(OpRecorder::new()),
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
    let (d, _l) = deps(&calls, FakeLauncher::new(&calls));
    let mut out = Vec::new();
    let running = start_with(&env, d, &env.id, &short_timeouts(), &mut out)
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
    let code = start_with(&env, d, &env.id, &short_timeouts(), &mut out)
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
    assert!(start_with(&env, d, &env.id, &short_timeouts(), &mut out).is_err());
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
    let (d, l) = deps(&calls, fl);
    let mut out = Vec::new();
    assert!(start_with(&env, d, &env.id, &short_timeouts(), &mut out).is_err());
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
    let (d, l) = deps(&calls, fl);
    let mut out = Vec::new();
    assert!(start_with(&env, d, &env.id, &short_timeouts(), &mut out).is_err());
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

/// REPAIR-5: launch の Timeout はそのまま報告し、報告の後の後始末で生存プロセスが無いと確認できなければ予約を残し、
/// cgroup も消さずに INTERNAL の終了コードで終わる（報告は後始末を待たない）。
#[test]
fn repair5_launch_timeout_without_confirmation_exits_internal() {
    let env = Env::new("noconfirm");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.delay = Duration::from_millis(2500);
    fl.confirm_ok = false;
    let (d, _l) = deps(&calls, fl);
    let mut out = TimedWriter::default();
    let started = std::time::Instant::now();
    let code = start_with(&env, d, &env.id, &short_timeouts(), &mut out)
        .err()
        .expect("start must fail");
    assert_eq!(code, exit_code_for(ErrorCode::Internal));
    // 報告は契約の内部上限内に届く（REPAIR-5）。
    assert!(out.reported_at().unwrap() - started <= result_deadline(&short_timeouts()));
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Running);
    assert!(rec.status().pid().is_none());
    assert!(!calls_of(&calls).contains(&"release"));
    match report_of(&out.bytes()) {
        StartReport::Failed { code, .. } => assert_eq!(code, ErrorCode::Timeout),
        other => panic!("unexpected report: {other:?}"),
    }
}

/// 書いた内容と、最初に書いた時刻を記録する書き手（報告が後始末より前に出たかの照合用）。
#[derive(Default)]
struct TimedWriter {
    buf: Vec<u8>,
    at: Option<std::time::Instant>,
    signal: Option<std::sync::mpsc::Sender<()>>,
}

impl TimedWriter {
    fn reported_at(&self) -> Option<std::time::Instant> {
        self.at
    }
    fn bytes(&self) -> Vec<u8> {
        self.buf.clone()
    }
}

impl Write for TimedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.at.is_none() {
            self.at = Some(std::time::Instant::now());
        }
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(tx) = self.signal.take() {
            let _ = tx.send(());
        }
        Ok(())
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
    let (d, _l) = deps(&calls, FakeLauncher::new(&calls));
    let running = start_with(&env, d, &env.id, &short_timeouts(), &mut Broken).expect("started");
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
    let (d, _l) = deps(&calls, FakeLauncher::new(&calls));
    let mut out = Vec::new();
    assert!(start_with(&env, d, &env.id, &short_timeouts(), &mut out).is_err());
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

/// 予約（Running・pid なし）だけが残るコンテナを作る。
fn reserve(env: &Env, id: &str) {
    env.create(id);
    let rec = env.record(id);
    env.store
        .update(&UpdateStateRequest::new(
            ContainerStatus::running(cid(id), None),
            rec.revision(),
        ))
        .unwrap();
}

/// CORE-2・SEC-1（#2011）: 前の supervisor が落ちて残った予約（Running・pid なし）は、次の start が手順 3 で
/// `recover_interrupted` を 1 回だけ呼び、成功しても launch せず cgroup にも触れず `FailedPrecondition` を報告する。
#[test]
fn core2_issue2011_reserved_container_is_recovered_without_launch() {
    let env = Env::new("recover-ok");
    reserve(&env, &env.id);
    let calls = new_calls();
    let (d, launcher) = deps(&calls, FakeLauncher::new(&calls));
    let mut out = Vec::new();
    let code = start_with(&env, d, &env.id, &short_timeouts(), &mut out)
        .err()
        .expect("must not start");
    assert_eq!(calls_of(&calls), ["recover"]);
    assert_eq!(launcher.launches(), 0);
    assert_eq!(code, exit_code_for(ErrorCode::FailedPrecondition));
    match report_of(&out) {
        StartReport::Failed { code, message, .. } => {
            assert_eq!(code, ErrorCode::FailedPrecondition);
            assert_eq!(
                message.as_str(),
                "an interrupted start was recovered; delete and recreate the container"
            );
        }
        other => panic!("unexpected report: {other:?}"),
    }
}

/// CORE-2（#2011）: 回復に失敗したらそのエラーの code を報告し、launch せず cgroup に触れない。
#[test]
fn core2_issue2011_recovery_failure_is_reported_as_is() {
    let env = Env::new("recover-ng");
    reserve(&env, &env.id);
    let calls = new_calls();
    let (mut d, launcher) = deps(&calls, FakeLauncher::new(&calls));
    d.recover_fails = Some(ErrorCode::Timeout);
    let mut out = Vec::new();
    assert!(start_with(&env, d, &env.id, &short_timeouts(), &mut out).is_err());
    assert_eq!(calls_of(&calls), ["recover"]);
    assert_eq!(launcher.launches(), 0);
    match report_of(&out) {
        StartReport::Failed { code, message, .. } => {
            assert_eq!(code, ErrorCode::Timeout);
            assert_eq!(message.as_str(), "recover failed");
        }
        other => panic!("unexpected report: {other:?}"),
    }
}

/// 未 create の ID は NOT_FOUND を報告し、何も呼ばない。
#[test]
fn sup1_unknown_container_reports_not_found() {
    let env = Env::new("nf");
    let calls = new_calls();
    let (d, _l) = deps(&calls, FakeLauncher::new(&calls));
    let mut out = Vec::new();
    assert!(start_with(&env, d, "nope", &short_timeouts(), &mut out).is_err());
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
    let (d, l) = deps(&calls, fl);
    let running =
        start_with(&env, d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
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
    let (d, l) = deps(&calls, fl);
    let running =
        start_with(&env, d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
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
    let (d, l) = deps(&calls, fl);
    let running =
        start_with(&env, d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
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
    let (d, l) = deps(&calls, FakeLauncher::new(&calls));
    let running =
        start_with(&env, d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
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

/// drop されたことを印に残す書き手。
struct DropFlagWriter(Arc<std::sync::atomic::AtomicBool>);

impl Write for DropFlagWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for DropFlagWriter {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// SUP-1・REPAIR-5・SEC-1（#3453・#2070）: 書き込みが成功して戻った後に `BoundedWriter` を drop すれば、
/// 作業スレッドの完了を待たずに書き手が同期的に閉じる（入口の後に結果チャネルの複製 fd が残らない）。
#[test]
fn sup1_3453_bounded_writer_releases_inner_before_returning() {
    for round in 0..300 {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut w = fandhe_container_supervisor::start_entry::BoundedWriter::new(
            DropFlagWriter(Arc::clone(&dropped)),
            Duration::from_secs(5),
        );
        w.write_all(b"FCSUP1 OK 1\n").unwrap();
        drop(w);
        assert!(
            dropped.load(Ordering::SeqCst),
            "writer still alive after BoundedWriter drop (round {round})"
        );
    }
}

/// CORE-2・CORE-3・SEC-1: 準備した cgroup の世代と launch 時点（起動権の予約の後）のレコードが食い違えば
/// （準備の後に同じ ID が削除・再作成された）launch せず、予約を Created へ戻して準備した cgroup を消す。
#[test]
fn core2_recreated_after_prepare_is_not_launched() {
    let env = Env::new("regen");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, l) = deps(&calls, FakeLauncher::new(&calls));
    // 準備した世代はあるが、レコードにはスコープが無い（再作成された別世代のレコード）。
    d.prepared_instance = Some(StateRevision::from_raw(1));
    let mut out = Vec::new();
    assert!(start_with(&env, d, &env.id, &short_timeouts(), &mut out).is_err());
    assert_eq!(
        calls_of(&calls),
        ["check", "prepare", "audit", "build", "release"]
    );
    assert!(l.specs.lock().unwrap().is_empty());
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Created);
    assert!(rec.status().pid().is_none());
    match report_of(&out) {
        StartReport::Failed { code, message, .. } => {
            assert_eq!(code, ErrorCode::FailedPrecondition);
            assert_eq!(
                message.as_str(),
                "the container was recreated after its cgroup was prepared"
            );
        }
        other => panic!("unexpected report: {other:?}"),
    }
}

/// REPAIR-5・CORE-1・SUP-1・#1819: 準備（手順 3〜7）が期限までに終わらなければ、期限内に TIMEOUT（期限超過。ERR-3・#3557）を
/// 報告し、後始末は報告の後に行う。報告の後・後始末の前に同じ ID の start を試みても、記録済みのスコープ（予約）の
/// 照合で FailedPrecondition として拒否される。準備が後から終わっても launch せず、作った cgroup を解放して状態は
/// Created のままにする（launch は入口スレッドが準備の完了後に行うため、期限超過の後に新しいプロセスは作られない）。
#[test]
fn repair5_deadline_exceeded_in_prepare_reports_first_and_never_launches() {
    let env = Env::new("overdue");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, l) = deps(&calls, FakeLauncher::new(&calls));
    d.record_scope = true;
    d.prepare_delay = Duration::from_millis(1500);
    let (signal, reported) = std::sync::mpsc::channel();
    let store = env.store.clone();
    let id = env.id.clone();
    let t0 = std::time::Instant::now();
    // 報告の待ちは deadline − REPORT_RESERVE（1s）まで。起動処理は prepare で 1.5s 止まる。
    let deadline = t0.checked_add(Duration::from_millis(1300));
    let first = std::thread::spawn(move || {
        let mut out = TimedWriter {
            signal: Some(signal),
            ..TimedWriter::default()
        };
        let r = run_start_until(
            Box::new(d),
            &store,
            &Arc::new(OpRecorder::new()),
            &StartRequest::new(cid(&id)),
            &short_timeouts(),
            deadline,
            &mut out,
        );
        (r.err(), out)
    });
    reported
        .recv_timeout(Duration::from_secs(5))
        .expect("the report must be written before cleanup");
    // 報告の後・後始末の前の再試行は、記録済みのスコープで拒否される（同じ ID は予約中）。
    let retry_calls = new_calls();
    let (d2, l2) = deps(&retry_calls, FakeLauncher::new(&retry_calls));
    let mut out2 = Vec::new();
    assert!(start_with(&env, d2, &env.id, &short_timeouts(), &mut out2).is_err());
    match report_of(&out2) {
        StartReport::Failed { code, message, .. } => {
            assert_eq!(code, ErrorCode::FailedPrecondition);
            assert_eq!(
                message.as_str(),
                "cgroup scope is already recorded; delete and recreate the container"
            );
        }
        other => panic!("unexpected report: {other:?}"),
    }
    assert!(l2.specs.lock().unwrap().is_empty());
    let (code, out) = first.join().unwrap();
    // 報告は期限内で、起動処理（1.5s）の完了より前。
    let at = out.reported_at().unwrap() - t0;
    assert!(at < Duration::from_millis(1300), "reported at {at:?}");
    assert!(at < Duration::from_millis(1500), "reported at {at:?}");
    match report_of(&out.bytes()) {
        StartReport::Failed { code, message, .. } => {
            assert_eq!(code, ErrorCode::Timeout);
            assert_eq!(message.as_str(), DEADLINE_EXCEEDED_MESSAGE);
        }
        other => panic!("unexpected report: {other:?}"),
    }
    assert_eq!(code, Some(exit_code_for(ErrorCode::Timeout)));
    // 後から準備が終わっても launch せず、作った cgroup を解放する（子は作られず、terminate もしない）。
    assert!(l.specs.lock().unwrap().is_empty());
    assert_eq!(l.terminated.load(Ordering::SeqCst), 0);
    assert_eq!(
        calls_of(&calls),
        ["check", "prepare", "audit", "build", "release"]
    );
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Created);
    assert!(rec.status().pid().is_none());
    assert!(rec.supervision().supervisor_pid().is_none());
}

/// ERR-3・REPAIR-5・SEC-4・#3557: 準備の期限超過の報告は、期限の配分(1300ms・2000ms。どちらも
/// `deadline − REPORT_RESERVE` が準備の 1.5s より先に切れる)に依らず `TIMEOUT`(期限超過の message)で、
/// 後始末を確かめられれば終了コードも `Timeout`。launch せず作った cgroup を解放する。
#[test]
fn repair4_sec4_3557_prepare_overdue_reports_timeout_regardless_of_deadline_split() {
    for deadline_ms in [1300u64, 2000] {
        let env = Env::new(&format!("ovtm{deadline_ms}"));
        env.create(&env.id);
        let calls = new_calls();
        let (mut d, l) = deps(&calls, FakeLauncher::new(&calls));
        d.record_scope = true;
        d.prepare_delay = Duration::from_millis(1500);
        let t0 = std::time::Instant::now();
        let deadline = t0.checked_add(Duration::from_millis(deadline_ms));
        let mut out = TimedWriter::default();
        let r = run_start_until(
            Box::new(d),
            &env.store,
            &Arc::new(OpRecorder::new()),
            &StartRequest::new(cid(&env.id)),
            &short_timeouts(),
            deadline,
            &mut out,
        );
        assert_eq!(
            r.err(),
            Some(exit_code_for(ErrorCode::Timeout)),
            "deadline={deadline_ms}"
        );
        match report_of(&out.bytes()) {
            StartReport::Failed { code, message, .. } => {
                assert_eq!(code, ErrorCode::Timeout, "deadline={deadline_ms}");
                assert_eq!(message.as_str(), DEADLINE_EXCEEDED_MESSAGE);
            }
            other => panic!("unexpected report: {other:?}"),
        }
        let at = out.reported_at().unwrap() - t0;
        assert!(
            at < Duration::from_millis(deadline_ms),
            "reported at {at:?}"
        );
        assert!(l.specs.lock().unwrap().is_empty());
        assert_eq!(
            calls_of(&calls),
            ["check", "prepare", "audit", "build", "release"]
        );
        assert_eq!(
            env.record(&env.id).status().state(),
            ContainerState::Created
        );
    }
}

/// ERR-3・CORE-3・#3557: 準備の期限超過で報告は `TIMEOUT` のまま、遅れて戻った準備の後始末(cgroup の解放)を
/// 確かめられなければ終了コードだけ `Internal`(後始末の失敗を成功扱いにしない)。
#[test]
fn repair4_sec4_3557_prepare_overdue_unconfirmed_cleanup_exits_internal() {
    let env = Env::new("ovint");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, l) = deps(&calls, FakeLauncher::new(&calls));
    d.record_scope = true;
    d.prepare_delay = Duration::from_millis(1500);
    d.release_fails = true;
    let deadline = std::time::Instant::now().checked_add(Duration::from_millis(1300));
    let mut out = TimedWriter::default();
    let r = run_start_until(
        Box::new(d),
        &env.store,
        &Arc::new(OpRecorder::new()),
        &StartRequest::new(cid(&env.id)),
        &short_timeouts(),
        deadline,
        &mut out,
    );
    assert_eq!(r.err(), Some(exit_code_for(ErrorCode::Internal)));
    match report_of(&out.bytes()) {
        StartReport::Failed { code, message, .. } => {
            assert_eq!(code, ErrorCode::Timeout);
            assert_eq!(message.as_str(), DEADLINE_EXCEEDED_MESSAGE);
        }
        other => panic!("unexpected report: {other:?}"),
    }
    assert!(l.specs.lock().unwrap().is_empty());
}

/// SEC-4・NET-9・REPAIR-5(#3359): 準備の期限を超えた start でも、積んだ `pasta_verify` の拒否行が報告の後に
/// ちょうど 1 度だけ出る(`abandoned_cleanup` の先頭)。出す処理は報告の期限を延ばさない。
#[test]
fn sec4_3359_deadline_exceeded_flushes_pasta_verify_once() {
    let env = Env::new("flushovr");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
    d.record_scope = true;
    d.prepare_delay = Duration::from_millis(1500);
    let line = format!(
        "{{\"component\":\"supervisor\",\"event\":\"pasta_verify\",\"container\":\"{}\",\"elapsed_ms\":1,\"result\":\"rejected\",\"code\":\"PERMISSION_DENIED\",\"tamper_suspected\":\"true\"}}\n",
        env.id
    );
    d.deferred.lock().unwrap().push(line.clone());
    let (deferred, flushed, flushes) = (
        Arc::clone(&d.deferred),
        Arc::clone(&d.flushed),
        Arc::clone(&d.flushes),
    );
    let store = env.store.clone();
    let id = env.id.clone();
    let t0 = std::time::Instant::now();
    let deadline = t0.checked_add(Duration::from_millis(1300));
    let mut out = TimedWriter::default();
    let r = run_start_until(
        Box::new(d),
        &store,
        &Arc::new(OpRecorder::new()),
        &StartRequest::new(cid(&id)),
        &short_timeouts(),
        deadline,
        &mut out,
    );
    assert_eq!(r.err(), Some(exit_code_for(ErrorCode::Timeout)));
    match report_of(&out.bytes()) {
        StartReport::Failed { code, message, .. } => {
            assert_eq!(code, ErrorCode::Timeout);
            assert_eq!(message.as_str(), DEADLINE_EXCEEDED_MESSAGE);
        }
        other => panic!("unexpected report: {other:?}"),
    }
    let reported = out.reported_at().unwrap();
    assert!(reported - t0 < Duration::from_millis(1300));
    // 入口スレッドが待つ間は作業スレッドが deps を持つ。戻らなければ flush は後から(有限の期限で待つ)。
    let until = std::time::Instant::now() + Duration::from_secs(10);
    while flushes.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
    }
    let got = flushed.lock().unwrap().clone();
    assert_eq!(
        got.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>(),
        [line.as_str()]
    );
    assert!(got[0].0 >= reported, "flush must follow the report");
    assert_eq!(flushes.load(Ordering::SeqCst), 1);
    assert!(deferred.lock().unwrap().is_empty());
}

/// REPAIR-5・#1819: 準備が済んでも手順 8 の見込み（`launch_step_budget`）が期限内に残らなければ、launch せず
/// TIMEOUT（期限超過。ERR-3・#3557）を報告し、作った cgroup を解放する（期限内に終わらない launch を始めない）。
#[test]
fn repair5_insufficient_budget_skips_launch() {
    let env = Env::new("nobudget");
    env.create(&env.id);
    let before = env.record(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.self_bounded = true;
    let (d, l) = deps(&calls, fl);
    let mut out = Vec::new();
    // 見込み（short_timeouts で 4.6s）に足りない期限（準備は即座に終わるので待ちの期限内には入る）。
    let deadline = std::time::Instant::now().checked_add(Duration::from_secs(3));
    let code = run_start_until(
        Box::new(d),
        &env.store,
        &Arc::new(OpRecorder::new()),
        &StartRequest::new(cid(&env.id)),
        &short_timeouts(),
        deadline,
        &mut out,
    )
    .err()
    .expect("start must fail");
    assert_eq!(code, exit_code_for(ErrorCode::Timeout));
    assert!(l.specs.lock().unwrap().is_empty());
    assert_eq!(
        calls_of(&calls),
        ["check", "prepare", "audit", "build", "release"]
    );
    let after = env.record(&env.id);
    assert_eq!(after.status().state(), ContainerState::Created);
    // 予約（Created → Running）と報告後の解放（Running → Created）で revision は 2 進む。
    assert_eq!(before.revision(), StateRevision::from_raw(0));
    assert_eq!(after.revision(), StateRevision::from_raw(2));
    match report_of(&out) {
        StartReport::Failed { code, message, .. } => {
            assert_eq!(code, ErrorCode::Timeout);
            assert_eq!(message.as_str(), DEADLINE_EXCEEDED_MESSAGE);
        }
        other => panic!("unexpected report: {other:?}"),
    }
}

/// CORE-1・REPAIR-5・#1819: `SelfBounded` の launcher は、`run_start` を呼んだスレッドで直接 launch される
/// （作業スレッド `supervisor-start` ではない）。作業スレッドの消滅そのもの（`/proc/self/task`）は、並列に走る
/// 他の試験のスレッドと区別できないため、実機前提の `supervisor_bin_real` が照合する。
#[test]
fn repair5_sup1_launch_runs_on_the_calling_thread() {
    let env = Env::new("callthread");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.self_bounded = true;
    let (d, l) = deps(&calls, fl);
    let running =
        start_with(&env, d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
    let threads = l
        .launch_threads
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let me = std::thread::current();
    assert_eq!(threads, [(me.id(), me.name().map(str::to_owned))]);
    assert_ne!(threads[0].1.as_deref(), Some("supervisor-start"));
    drop(running);
}

/// CORE-1・CORE-2・#1819: 単一スレッドの要求を満たさない呼び出しは launcher が拒否する（`FailedPrecondition`・
/// 子なし）。報告は FAILED_PRECONDITION、状態は Created に戻り（pid なしの Running を残さない）、cgroup は解放され、
/// 終了コードは FAILED_PRECONDITION の写像のまま（後始末は確かめられた）。
#[test]
fn core1_multithreaded_launch_is_rejected_without_side_effects() {
    let env = Env::new("mtreject");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.self_bounded = true;
    fl.reject_from = Some(1);
    let (d, l) = deps(&calls, fl);
    let mut out = Vec::new();
    let code = start_with(&env, d, &env.id, &short_timeouts(), &mut out)
        .err()
        .expect("start must fail");
    assert_eq!(code, exit_code_for(ErrorCode::FailedPrecondition));
    assert_eq!(
        calls_of(&calls),
        ["check", "prepare", "audit", "build", "launch", "release"]
    );
    assert_eq!(l.terminated.load(Ordering::SeqCst), 0);
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Created);
    assert!(rec.status().pid().is_none());
    match report_of(&out) {
        StartReport::Failed { code, message, .. } => {
            assert_eq!(code, ErrorCode::FailedPrecondition);
            assert_eq!(
                message.as_str(),
                "launch requires a single-threaded process"
            );
        }
        other => panic!("unexpected report: {other:?}"),
    }
}

/// CORE-2・REPAIR-5・#1819: launch が失敗して子が残り得る場合、予約は戻らない。入口は `confirm_no_process` で
/// 消滅を確かめて Created へ戻し、cgroup を解放する。
#[test]
fn core2_left_process_is_confirmed_before_release() {
    let env = Env::new("leftok");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.self_bounded = true;
    fl.launch_error = Some(ErrorCode::Internal);
    fl.left_process = true;
    let (d, l) = deps(&calls, fl);
    let mut out = Vec::new();
    let code = start_with(&env, d, &env.id, &short_timeouts(), &mut out)
        .err()
        .expect("start must fail");
    assert_eq!(code, exit_code_for(ErrorCode::Internal));
    assert!(l.confirms.load(Ordering::SeqCst) >= 1);
    assert_eq!(calls_of(&calls).last(), Some(&"release"));
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Created);
    assert!(rec.status().pid().is_none());
}

/// CORE-2・REPAIR-5・#1819: 子が残り得て消滅を確かめられない場合、cgroup は消さず、予約（Running・pid なし）を
/// 残したまま INTERNAL の終了コードで終わる。pid つきの Running は残さない。
#[test]
fn core2_unconfirmed_left_process_keeps_reservation_and_cgroup() {
    let env = Env::new("leftng");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.self_bounded = true;
    fl.launch_error = Some(ErrorCode::Internal);
    fl.left_process = true;
    fl.confirm_ok = false;
    let (d, _l) = deps(&calls, fl);
    let mut out = Vec::new();
    let code = start_with(&env, d, &env.id, &short_timeouts(), &mut out)
        .err()
        .expect("start must fail");
    assert_eq!(code, exit_code_for(ErrorCode::Internal));
    assert!(!calls_of(&calls).contains(&"release"));
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Running);
    assert!(rec.status().pid().is_none());
    match report_of(&out) {
        StartReport::Failed { code, .. } => assert_eq!(code, ErrorCode::Internal),
        other => panic!("unexpected report: {other:?}"),
    }
}

/// SUP-3・CORE-1・#1819・#2043: restart の再 launch が単一スレッドの要求で拒否される間は fail-closed に止まる。
/// 初回の起動は成功し、2 回目の launch が拒否されると、新しい子は作られず、restart ポリシー `always` でも
/// 再起動せず、状態は Stopped で、終了コードは FAILED_PRECONDITION の写像になる。
/// 再 launch が拒否される場合の fail-closed の保証として残す（#2043 の再構成後も、拒否は同じ結末になる）。
#[test]
fn sup3_core1_single_thread_launcher_rejection_fails_closed() {
    let env = Env::new("relrej");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.self_bounded = true;
    fl.reject_from = Some(2);
    fl.wait_mode = WaitMode::ExitedOk;
    let (d, l) = deps(&calls, fl);
    let running =
        start_with(&env, d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
    let code = run_supervised(
        env.store.clone(),
        cid(&env.id),
        running,
        RestartPolicy::Always,
        &short_timeouts(),
        &StopToken::new(),
    );
    assert_eq!(code, exit_code_for(ErrorCode::FailedPrecondition).get());
    // 初回と、拒否された 1 回の再 launch だけ。拒否された launch は子を作らない。
    assert_eq!(l.launches(), 2);
    assert_eq!(l.terminated.load(Ordering::SeqCst), 0);
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Stopped);
    assert!(rec.status().pid().is_none());
}

/// SUP-3・CORE-1・REPAIR-5・#2043: `SelfBounded` の launcher の再 launch は、監視ループを回すスレッド（入口スレッド）で
/// 直接呼ばれ、別スレッド `fandhe-relaunch` では呼ばれない。別スレッドでの launch を拒否する launcher でも
/// restart が成り立ち、`restart_count` が 1 進んで 2 回目の起動が記録される。
#[test]
fn sup3_core1_2043_relaunch_runs_on_the_calling_thread() {
    let env = Env::new("relthread");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.self_bounded = true;
    fl.reject_on_relaunch_thread = true;
    fl.wait_mode = WaitMode::ExitedFailure;
    let (d, l) = deps(&calls, fl);
    let running =
        start_with(&env, d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
    let code = run_supervised(
        env.store.clone(),
        cid(&env.id),
        running,
        RestartPolicy::OnFailure {
            max_retries: std::num::NonZeroU32::new(1),
        },
        &short_timeouts(),
        &StopToken::new(),
    );
    // 上限(1 回)まで再起動して終わる(supervisor 自身の終了コードは 0)。再 launch は 1 回で、拒否されていない。
    assert_eq!(code, 0);
    assert_eq!(l.launches(), 2);
    let threads = l
        .launch_threads
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let me = std::thread::current();
    assert_eq!(
        threads,
        [
            (me.id(), me.name().map(str::to_owned)),
            (me.id(), me.name().map(str::to_owned)),
        ]
    );
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Stopped);
    assert_eq!(rec.restart_count(), 1);
}

/// REPAIR-4: 起動の計測結果は英語のキーの 1 行 JSON で、操作ごとの成功・失敗数とレイテンシを載せる。
#[test]
fn repair4_start_metrics_line_has_counts_and_latency() {
    let recorder = OpRecorder::new();
    assert_eq!(
        start_metrics_line(&recorder),
        "{\"component\":\"supervisor\",\"event\":\"start_metrics\",\"ops\":[],\"dropped_records\":0}\n"
    );
    let name = fandhe_container_core::observability::OpName::new(START_OP).unwrap();
    recorder
        .record(
            &name,
            fandhe_container_core::observability::OpOutcome::Failure,
            Duration::from_micros(250),
        )
        .unwrap();
    assert_eq!(
        start_metrics_line(&recorder),
        "{\"component\":\"supervisor\",\"event\":\"start_metrics\",\"ops\":[{\"op\":\"supervisor.start\",\"success\":0,\"failure\":1,\"p95_us\":250,\"max_us\":250}],\"dropped_records\":0}\n"
    );
}

/// REPAIR-4: run_start は起動の成否を START_OP に記録する（事前確認で止まった失敗も数える）。
#[test]
fn repair4_run_start_records_start_outcome() {
    let env = Env::new("metrics");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
    d.unavailable = true;
    let recorder = Arc::new(OpRecorder::new());
    let mut out = Vec::new();
    assert!(
        run_start(
            Box::new(d),
            &env.store,
            &recorder,
            &StartRequest::new(cid(&env.id)),
            &short_timeouts(),
            &mut out,
        )
        .is_err()
    );
    let name = fandhe_container_core::observability::OpName::new(START_OP).unwrap();
    let stats = recorder.snapshot_op(&name).expect("recorded");
    assert_eq!((stats.success(), stats.failure()), (0, 1));
}

/// CORE-3: 報告の後の cgroup の削除に失敗したら、元のエラーを報告したまま終了コードは INTERNAL にする。
#[test]
fn core3_release_failure_after_report_exits_internal() {
    let env = Env::new("relfail");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
    d.fail_at = Some("audit");
    d.release_fails = true;
    let mut out = Vec::new();
    let code = start_with(&env, d, &env.id, &short_timeouts(), &mut out)
        .err()
        .expect("start must fail");
    assert_eq!(code, exit_code_for(ErrorCode::Internal));
    assert_eq!(calls_of(&calls), ["check", "prepare", "audit", "release"]);
    match report_of(&out) {
        StartReport::Failed { code, .. } => assert_eq!(code, ErrorCode::PermissionDenied),
        other => panic!("unexpected report: {other:?}"),
    }
}

/// Stopped への書き込みだけを、指定回数まで FailedPrecondition（revision 競合の代わり）で失敗させる状態ストア。
struct FlakyStoppedStore {
    inner: Arc<dyn StateStore>,
    fail_stopped: Mutex<u32>,
}

impl StateStore for FlakyStoppedStore {
    fn create(
        &self,
        req: &fandhe_container_core::traits::CreateStateRequest,
    ) -> Result<StateRecord, TraitError> {
        self.inner.create(req)
    }
    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        let fail = req.status().state() == ContainerState::Stopped && {
            let mut left = self.fail_stopped.lock().unwrap();
            let fail = *left > 0;
            *left = left.saturating_sub(1);
            fail
        };
        if fail {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "revision conflict",
            ));
        }
        self.inner.update(req)
    }
    fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
        self.inner.get(req)
    }
    fn list(
        &self,
        req: &fandhe_container_core::traits::ListStateRequest,
    ) -> Result<fandhe_container_core::traits::StateList, TraitError> {
        self.inner.list(req)
    }
    fn delete(
        &self,
        req: &fandhe_container_core::traits::DeleteStateRequest,
    ) -> Result<fandhe_container_core::traits::DeleteStateResponse, TraitError> {
        self.inner.delete(req)
    }
}

/// 監視の失敗で回収したあとに Stopped の記録を試みる（試験用の共通手順）。`fail_stopped` 回だけ Stopped の書き込みが
/// 失敗する。終了コードと最終的な状態を返す。
fn dispose_with_flaky_stopped(tag: &str, fail_stopped: u32) -> (u8, ContainerState) {
    let env = Env::new(tag);
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.wait_mode = WaitMode::Error(ErrorCode::Timeout);
    let (d, _l) = deps(&calls, fl);
    let running =
        start_with(&env, d, &env.id, &short_timeouts(), &mut Vec::new()).expect("started");
    let flaky: Arc<dyn StateStore> = Arc::new(FlakyStoppedStore {
        inner: env.store.clone(),
        fail_stopped: Mutex::new(fail_stopped),
    });
    let code = run_supervised(
        flaky,
        cid(&env.id),
        running,
        RestartPolicy::No,
        &short_timeouts(),
        &StopToken::new(),
    );
    (code, env.record(&env.id).status().state())
}

/// SUP-1・CORE-2: Stopped の記録が一時的に失敗しても、照合を保った再試行で記録して元の終了コードで終わる。
#[test]
fn sup1_mark_stopped_retries_transient_failures() {
    let (code, state) = dispose_with_flaky_stopped("mkretry", 2);
    assert_eq!(code, exit_code_for(ErrorCode::Timeout).get());
    assert_eq!(state, ContainerState::Stopped);
}

/// SUP-1・CORE-2: Stopped の記録が再試行の上限（3 回）まで失敗したら、終了コードは INTERNAL。
#[test]
fn sup1_mark_stopped_failure_exits_internal() {
    let (code, state) = dispose_with_flaky_stopped("mkfail", 3);
    assert_eq!(code, exit_code_for(ErrorCode::Internal).get());
    assert_eq!(state, ContainerState::Running);
}

/// CORE-3・CORE-2: launcher 自身が期限内に Timeout を返した場合（core が予約を Created へ戻し済み）は、予約の解放を
/// 確かめて cgroup を消し、TIMEOUT を報告して TIMEOUT の終了コードで終わる（後始末の失敗扱いにしない）。
#[test]
fn core3_launcher_timeout_within_deadline_releases_cgroup() {
    let env = Env::new("lto");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.launch_error = Some(ErrorCode::Timeout);
    let (d, l) = deps(&calls, fl);
    let mut out = Vec::new();
    let code = start_with(&env, d, &env.id, &short_timeouts(), &mut out)
        .err()
        .expect("start must fail");
    assert_eq!(code, exit_code_for(ErrorCode::Timeout));
    assert_eq!(
        calls_of(&calls),
        ["check", "prepare", "audit", "build", "launch", "release"]
    );
    let rec = env.record(&env.id);
    assert_eq!(rec.status().state(), ContainerState::Created);
    assert!(rec.status().pid().is_none());
    assert_eq!(l.terminated.load(Ordering::SeqCst), 0);
    match report_of(&out) {
        StartReport::Failed { code, .. } => assert_eq!(code, ErrorCode::Timeout),
        other => panic!("unexpected report: {other:?}"),
    }
}

/// NET-6・NET-12・D14(#1873): 手順 4b は起動権の予約の後(cgroup・監査 sink・launcher 構築の後、launch の前)に呼ばれ、
/// 成功時は生成ファイルを残す。
#[test]
fn net12_prepare_network_runs_after_claim_before_launch() {
    let env = Env::new("net-order");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
    d.net_hooks = true;
    let mut out = Vec::new();
    let running = start_with(&env, d, &env.id, &short_timeouts(), &mut out)
        .unwrap_or_else(|_| panic!("started: {}", String::from_utf8_lossy(&out)));
    assert_eq!(
        calls_of(&calls),
        ["check", "prepare", "audit", "build", "net", "launch"]
    );
    drop(running);
}

/// NET-12・D14(#1873): 手順 4b の失敗は launch へ進まず、予約を手放す前に `release_net` が呼ばれ、続けて cgroup を消す。
#[test]
fn net12_prepare_network_failure_skips_cgroup_and_releases() {
    let env = Env::new("net-fail");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, l) = deps(&calls, FakeLauncher::new(&calls));
    d.net_hooks = true;
    d.fail_at = Some("net");
    let mut out = Vec::new();
    assert!(start_with(&env, d, &env.id, &short_timeouts(), &mut out).is_err());
    assert_eq!(
        calls_of(&calls),
        [
            "check",
            "prepare",
            "audit",
            "build",
            "net",
            "release_net",
            "release",
            "release_net"
        ]
    );
    assert_eq!(l.launches(), 0);
    assert_eq!(
        env.record(&env.id).status().state(),
        ContainerState::Created
    );
}

/// NET-12・D14(#1873): 監査 sink・launcher 構築の失敗は `release` → `release_net` の逆順で巻き戻す。launch の失敗
/// (予約を手放した後)は別世代の生成物を消さないよう `release_net` を呼ばない(CORE-2・SEC-1)。
#[test]
fn net12_later_failures_release_cgroup_then_network() {
    for step in ["audit", "build"] {
        let env = Env::new(&format!("net-late-{step}"));
        env.create(&env.id);
        let calls = new_calls();
        let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
        d.net_hooks = true;
        d.fail_at = Some(step);
        let mut out = Vec::new();
        assert!(start_with(&env, d, &env.id, &short_timeouts(), &mut out).is_err());
        let got = calls_of(&calls);
        assert_eq!(&got[got.len() - 2..], ["release", "release_net"], "{step}");
    }
    let env = Env::new("net-late-launch");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.launch_error = Some(ErrorCode::Internal);
    let (mut d, _l) = deps(&calls, fl);
    d.net_hooks = true;
    let mut out = Vec::new();
    assert!(start_with(&env, d, &env.id, &short_timeouts(), &mut out).is_err());
    assert_eq!(
        calls_of(&calls),
        [
            "check", "prepare", "audit", "build", "net", "launch", "release"
        ]
    );
}

/// NET-12・D14(#1873): 生成ファイル(手順 4b)を作った後の失敗でも、cgroup の削除に失敗した経路では生存し得る
/// コンテナの bind 元を消さない(`release_net` を呼ばない)。`net` を通した後の失敗(launch)で照合する。
#[test]
fn net12_release_failure_keeps_generated_files() {
    let env = Env::new("net-keep");
    env.create(&env.id);
    let calls = new_calls();
    let mut fl = FakeLauncher::new(&calls);
    fl.launch_error = Some(ErrorCode::Internal);
    let (mut d, _l) = deps(&calls, fl);
    d.net_hooks = true;
    d.release_fails = true;
    let mut out = Vec::new();
    assert!(start_with(&env, d, &env.id, &short_timeouts(), &mut out).is_err());
    assert_eq!(
        calls_of(&calls),
        [
            "check", "prepare", "audit", "build", "net", "launch", "release"
        ]
    );
}

/// NET-12・D14(#1873): 手順 4b の後の cgroup 削除の失敗(予約を握ったまま `DiscardClaim`)でも、予約を手放す前に
/// 生成物を消し、cgroup の削除失敗の後は `release_net` を再度呼ばない(2 回目は no-op のため記録は 1 回分)。
#[test]
fn net12_discard_claim_releases_network_before_cgroup() {
    let env = Env::new("net-discard");
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
    d.net_hooks = true;
    d.fail_at = Some("net");
    d.release_fails = true;
    let mut out = Vec::new();
    assert!(start_with(&env, d, &env.id, &short_timeouts(), &mut out).is_err());
    assert_eq!(
        calls_of(&calls),
        [
            "check",
            "prepare",
            "audit",
            "build",
            "net",
            "release_net",
            "release"
        ]
    );
}
/// 記録した時刻つきで監査レコードを受ける試験用の記録先(#3473)。
#[derive(Default)]
struct RecordingSink {
    got: Mutex<Vec<(std::time::Instant, AuditRecord)>>,
}

impl AuditSink for RecordingSink {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        self.got
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((std::time::Instant::now(), record.clone()));
        Ok(())
    }
}

/// 2c の作業本体の `LOG_PREPARE_DEADLINE`(supervisor 内の非公開定数。5 秒)。
const OPTIONS_WORKER_LIMIT: Duration = Duration::from_secs(5);

/// 既存の試験の起動の期限(2c の待ちが本番の 5 秒で切れる配分)。
const DEFAULT_DEADLINE_AFTER: Duration = Duration::from_secs(7);

/// 期限超過した 2c の拒否の結果(#3473)。
struct TimeoutRun {
    result: Result<Running, std::num::NonZeroU8>,
    t0: std::time::Instant,
    t_end: std::time::Instant,
    out: TimedWriter,
    flushed: Vec<(std::time::Instant, String)>,
    flushes: usize,
    audit: Vec<(std::time::Instant, AuditRecord)>,
    tamper_placed_at: Option<std::time::Instant>,
    logs: Arc<PastaLogBuffer>,
    /// 継ぎ目が戻った直後(作業スレッドの解放前)に logs に残っていた行。
    logs_at_return: Vec<String>,
    calls: Vec<&'static str>,
    env: Env,
    /// 起動の期限(t0 からの相対)。
    deadline_after: Duration,
}

/// 2c の作業スレッドが報告の後 `late_after` を待って改ざんの印を置く構成で、期限超過の拒否を通す。`late_after` が
/// `None` なら作業スレッドは継ぎ目が戻るまで解放しない(戻らない作業スレッド)。
fn run_options_timeout(
    tag: &str,
    late_after: Option<Duration>,
    deadline_after: Duration,
) -> TimeoutRun {
    let env = Env::new(tag);
    env.create(&env.id);
    let calls = new_calls();
    let (mut d, _l) = deps(&calls, FakeLauncher::new(&calls));
    let logs = Arc::new(PastaLogBuffer::new());
    d.pasta_logs = Some(Arc::clone(&logs));
    let (flushed, flushes) = (Arc::clone(&d.flushed), Arc::clone(&d.flushes));
    let sink = Arc::new(RecordingSink::default());
    let sink_dyn: Arc<dyn AuditSink> = sink.clone();

    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let placed = Arc::new(Mutex::new(None));
    let (wl, wplaced, id) = (Arc::clone(&logs), Arc::clone(&placed), env.id.clone());
    let work = move || {
        wl.mark_verify_started();
        let _ = go_rx.recv_timeout(Duration::from_secs(30));
        wl.set_tamper(PastaVerifyRejection::PermissionDenied);
        wl.push(format!(
            "{{\"component\":\"supervisor\",\"event\":\"pasta_verify\",\"container\":\"{id}\",\"elapsed_ms\":1,\"result\":\"rejected\",\"code\":\"PERMISSION_DENIED\",\"tamper_suspected\":\"true\"}}\n"
        ));
        *wplaced.lock().unwrap() = Some(std::time::Instant::now());
        Ok(())
    };

    // 報告の flush を合図に、作業スレッドを `late_after` の後に解放する(報告の後に置かれた印の再現)。
    let (sig_tx, sig_rx) = std::sync::mpsc::channel::<()>();
    let releaser = late_after.map(|after| {
        let go = go_tx.clone();
        std::thread::spawn(move || {
            if sig_rx.recv_timeout(Duration::from_secs(30)).is_ok() {
                std::thread::sleep(after);
                let _ = go.send(());
            }
        })
    });
    let mut out = TimedWriter {
        signal: late_after.map(|_| sig_tx),
        ..TimedWriter::default()
    };

    let t0 = std::time::Instant::now();
    // 期限の配分に依らず TIMEOUT で確定する(手順 3 以降へ進まない。#3509)。
    let deadline = t0 + deadline_after;
    let result = run_start_after_options_worker_for_test(
        work,
        |e| {
            d.options_error = e;
            Box::new(d)
        },
        &logs,
        Some(&sink_dyn),
        &env.store,
        &StartRequest::new(cid(&env.id)),
        &short_timeouts(),
        Some(deadline),
        &mut out,
    );
    let t_end = std::time::Instant::now();
    let logs_at_return = logs.take();
    let _ = go_tx.send(());
    if let Some(h) = releaser {
        h.join().unwrap();
    }
    let tamper_placed_at = *placed.lock().unwrap();
    let flushed = flushed.lock().unwrap().clone();
    let audit = sink.got.lock().unwrap().clone();
    TimeoutRun {
        result,
        t0,
        t_end,
        out,
        flushed,
        flushes: flushes.load(Ordering::SeqCst),
        audit,
        tamper_placed_at,
        logs,
        logs_at_return,
        calls: calls_of(&calls),
        env,
        deadline_after,
    }
}

fn assert_timeout_report_and_flush(r: &TimeoutRun) -> std::time::Instant {
    assert_eq!(
        r.result.as_ref().err(),
        Some(&exit_code_for(ErrorCode::Timeout))
    );
    match report_of(&r.out.bytes()) {
        StartReport::Failed { code, message, .. } => {
            assert_eq!(code, ErrorCode::Timeout);
            assert_eq!(message.as_str(), "container options preparation timed out");
        }
        other => panic!("unexpected report: {other:?}"),
    }
    let reported = r.out.reported_at().expect("reported");
    let min_wait = OPTIONS_WORKER_LIMIT.min(r.deadline_after - REPORT_RESERVE);
    assert!(reported - r.t0 >= min_wait, "{:?}", reported - r.t0);
    assert!(
        reported <= r.t0 + r.deadline_after,
        "report must fit the deadline"
    );
    // deps の flush は報告の後にちょうど 1 回で、期限超過の行が 1 度だけ出る。
    assert_eq!(r.flushes, 1);
    assert_eq!(r.flushed.len(), 1, "{:?}", r.flushed);
    let (at, line) = &r.flushed[0];
    assert!(*at >= reported, "flush must follow the report");
    assert!(
        line.starts_with(&format!(
            "{{\"component\":\"supervisor\",\"event\":\"pasta_verify\",\"container\":\"{}\",\"elapsed_ms\":",
            r.env.id
        )),
        "{line}"
    );
    assert!(
        line.ends_with(",\"result\":\"timeout\",\"stage\":\"verify\"}\n"),
        "{line}"
    );
    // 手順 3 以降へ進まない(check も呼ばれない。#3509)。
    assert_eq!(r.calls, Vec::<&str>::new());
    let rec = r.env.record(&r.env.id);
    assert_eq!(rec.status().state(), ContainerState::Created);
    assert!(rec.status().pid().is_none());
    reported
}

/// SEC-4・NET-9・REPAIR-5・REPAIR-12(#3473・#3431): 2c の期限超過で拒否した start は、拒否の報告 → deps の
/// flush(ちょうど 1 回) → 報告の後に作業スレッドが置いた改ざんの印の監査 1 件、の順で進み、報告の後の
/// 待ちは `LATE_DRAIN_BUDGET + TAMPER_AUDIT_BUDGET` に収まる。所要は約 5〜6 秒。
#[test]
fn sec4_repair5_3473_options_timeout_reports_then_flushes_once_and_audits_late_tamper() {
    const RELEASE_AFTER: Duration = Duration::from_millis(200);
    assert!(RELEASE_AFTER < LATE_DRAIN_BUDGET);
    let r = run_options_timeout("opttmo", Some(RELEASE_AFTER), DEFAULT_DEADLINE_AFTER);
    let reported = assert_timeout_report_and_flush(&r);

    let placed = r.tamper_placed_at.expect("tamper placed after the report");
    assert!(placed >= reported + RELEASE_AFTER, "placed before release");
    assert!(placed < reported + LATE_DRAIN_BUDGET);

    assert_eq!(r.audit.len(), 1, "{:?}", r.audit);
    let (at, rec) = &r.audit[0];
    assert!(*at >= placed, "audit must follow the late tamper mark");
    assert_eq!(rec.layer(), AuditLayer::PastaVerify);
    assert_eq!(rec.layer().as_str(), "pasta_verify");
    assert_eq!(
        *rec.event(),
        PastaVerifyRejection::PermissionDenied.audit_event()
    );
    assert_eq!(rec.container_id(), Some(&cid(&r.env.id)));

    // 遅れて積まれた拒否行は報告の後始末の flush で出し済みで、印も取り出し済み。
    assert!(r.logs.take().is_empty());
    assert!(r.logs.take_tamper().is_none());

    let budget = LATE_DRAIN_BUDGET + TAMPER_AUDIT_BUDGET + Duration::from_secs(2);
    assert!(r.t_end - reported <= budget, "{:?}", r.t_end - reported);
}

/// REPAIR-5・SEC-4(#3473): 作業スレッドが戻らないときは、報告の後の待ちが `LATE_DRAIN_BUDGET` で打ち切られ、
/// 監査は配送されず、期限超過の行が終端の記録になる。
#[test]
fn repair5_3473_options_timeout_unreturned_worker_is_bounded_and_sends_no_audit() {
    let r = run_options_timeout("optnoret", None, DEFAULT_DEADLINE_AFTER);
    let reported = assert_timeout_report_and_flush(&r);
    assert!(r.audit.is_empty(), "{:?}", r.audit);
    let waited = r.t_end - reported;
    assert!(waited >= LATE_DRAIN_BUDGET, "{waited:?}");
    assert!(
        waited <= LATE_DRAIN_BUDGET + Duration::from_secs(2),
        "{waited:?}"
    );
    assert!(r.logs_at_return.is_empty(), "{:?}", r.logs_at_return);
}

/// SEC-4・REPAIR-4・REPAIR-5(#3509): 起動の期限が先に尽きる配分(2c の待ちが `deadline - REPORT_RESERVE` で切れ、
/// 手順 3 以降に残りが無い)でも、報告のコードは `INTERNAL` に揺れず `TIMEOUT` に固定される。
#[test]
fn repair4_sec4_3509_options_timeout_reports_timeout_when_deadline_runs_out_first() {
    const RELEASE_AFTER: Duration = Duration::from_millis(200);
    let r = run_options_timeout(
        "opttmo3509",
        Some(RELEASE_AFTER),
        REPORT_RESERVE + Duration::from_millis(500),
    );
    let reported = assert_timeout_report_and_flush(&r);
    assert_eq!(r.audit.len(), 1, "{:?}", r.audit);
    let budget = LATE_DRAIN_BUDGET + TAMPER_AUDIT_BUDGET + Duration::from_secs(2);
    assert!(r.t_end - reported <= budget, "{:?}", r.t_end - reported);
}
