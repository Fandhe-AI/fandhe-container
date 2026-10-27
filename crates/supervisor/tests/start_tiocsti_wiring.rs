//! 起動成功の経路から `dev.tty.legacy_tiocsti` の警告が共有の `stderr_sink` へ届く結線の結合試験
//! （#2008・CORE-5・SEC-1・REPAIR-4・REPAIR-12）。
//!
//! 共有の出口はプロセス単位のグローバル状態で差し込み後に初期化し直せないため、`#[test]` を 1 本だけ置く
//! 別バイナリ（= 別プロセス）にしている。観測値は `run_start_until_observing` で注入し、host の sysctl に依らない。

#![cfg(target_os = "linux")]

// 一時領域の親を tmpfiles の flock 走査から守る共有部品（#3026・CORE-5・REPAIR-12）。
#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

use std::io::Write;
use std::num::NonZeroU32;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::legacy_tiocsti::LegacyTiocsti;
use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    LaunchMode, LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, StartTimeouts, create,
};
use fandhe_container_core::traits::{
    ContainerId, CreateRequest, StartRequest, StateRecord, StateRevision, StateStore, TraitError,
};
use fandhe_container_supervisor::start_entry::{StartDeps, run_start_until_observing};
use fandhe_container_supervisor::state::open_default_store;
use fandhe_container_supervisor::stderr_sink::{EmitOutcome, flush_stderr, install_stderr_writer};

const LEGACY_LINE: &str = r#"{"level":"warn","event":"legacy_tiocsti_enabled","sysctl":"dev.tty.legacy_tiocsti","value":1}"#;

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct FakeProcess;

impl LaunchedProcess for FakeProcess {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(4242).unwrap()
    }
    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        std::thread::sleep(timeout.min(Duration::from_millis(10)));
        Ok(None)
    }
    fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

struct FakeLauncher;

impl ProcessLauncher for FakeLauncher {
    fn launch_mode(&self) -> LaunchMode {
        LaunchMode::CallerBounded
    }
    fn launch(
        &self,
        _spec: &LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        Ok(Box::new(FakeProcess))
    }
    fn confirm_no_process(&self, _id: &ContainerId, _timeout: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

struct FakeDeps;

impl StartDeps for FakeDeps {
    fn check_launcher_available(&self) -> Result<(), TraitError> {
        Ok(())
    }
    fn prepare_cgroup(
        &mut self,
        _store: &dyn StateStore,
        _observed: &StateRecord,
    ) -> Result<Option<StateRevision>, TraitError> {
        Ok(None)
    }
    fn build_audit_sink(&mut self) -> Result<(), TraitError> {
        Ok(())
    }
    fn build_launcher(&mut self) -> Result<Arc<dyn ProcessLauncher>, TraitError> {
        Ok(Arc::new(FakeLauncher))
    }
    fn release_cgroup(&mut self) -> Result<(), TraitError> {
        Ok(())
    }
}

fn enabled() -> LegacyTiocsti {
    LegacyTiocsti::Enabled
}

fn disabled() -> LegacyTiocsti {
    LegacyTiocsti::Disabled
}

/// コンテナを create して start を 1 回通し、共有 sink の書き込みを待つ。
fn start_once(base: &Path, id: &str, observe: fn() -> LegacyTiocsti) {
    let store = open_default_store(Some(base.join("state"))).unwrap();
    let cid = ContainerId::new(id).unwrap();
    let req = CreateRequest::new(cid.clone(), base.join("bundle")).unwrap();
    create(store.as_ref(), &OpRecorder::new(), &req).unwrap();
    let timeouts = StartTimeouts::new(
        Duration::from_millis(100),
        Duration::from_secs(1),
        Duration::from_millis(500),
    )
    .unwrap();
    let mut out = Vec::new();
    let running = run_start_until_observing(
        Box::new(FakeDeps),
        &store,
        &Arc::new(OpRecorder::new()),
        &StartRequest::new(cid),
        &timeouts,
        Instant::now().checked_add(Duration::from_secs(30)),
        &mut out,
        observe,
    )
    .unwrap_or_else(|_| panic!("started: {}", String::from_utf8_lossy(&out)));
    drop(running);
    assert_eq!(flush_stderr(Duration::from_secs(5)), EmitOutcome::Written);
}

fn count_legacy(buf: &SharedBuf) -> usize {
    let bytes = buf.0.lock().unwrap().clone();
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter(|l| *l == LEGACY_LINE)
        .count()
}

/// CORE-5・SEC-1・REPAIR-4・REPAIR-12(#2008): 観測が有効なら保存先へ固定警告がちょうど 1 行届き、無効なら届かない。
#[test]
fn core5_2008_started_path_delivers_exactly_one_warning_line_to_shared_sink() {
    use std::os::unix::fs::PermissionsExt;
    // tmpfiles の flock 走査から守る親（#3026）。bundle・状態ルートはその子に作り、関数の最後まで保持する。
    let scratch =
        scratch_root::ScratchDir::new("fandhe-sup-tiocsti", std::time::Duration::from_secs(10));
    let base = scratch.path().join("b");
    std::fs::create_dir_all(base.join("bundle/rootfs")).unwrap();
    std::fs::write(
        base.join("bundle/config.json"),
        br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},
"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},
"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let state = base.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();

    let buf = SharedBuf::default();
    install_stderr_writer(Box::new(buf.clone())).expect("install before first use");

    start_once(&base, "c-tiocsti-on", enabled);
    assert_eq!(count_legacy(&buf), 1);

    // 無効の観測では増えない（有効のときだけ警告する）。
    start_once(&base, "c-tiocsti-off", disabled);
    assert_eq!(count_legacy(&buf), 1);

    let _ = std::fs::remove_dir_all(&base);
}
