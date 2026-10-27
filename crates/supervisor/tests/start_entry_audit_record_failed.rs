//! 縮退の監査記録を書けなかった事実が、公開の `run_start` を通して `state.json` と supervisor のログへ届く
//! ことの結合試験（SEC-4・REPAIR-4・#2468）。
//!
//! 共有の stderr 出口（`stderr_sink`）はプロセス単位のグローバル状態のため、この試験バイナリには `#[test]` を
//! 1 本だけ置く。root 不要で既定のテスト集合で動く。`FileStateStore` は Linux 限定のため全体を Linux に置く。

#![cfg(target_os = "linux")]

// 一時領域の親を tmpfiles の flock 走査から守る共有部品（#3026・CORE-5・REPAIR-12）。
#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

use std::io::Write;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::audit_log::{
    AuditCoverage, AuditCoveragePolicy, DegradeReason, KernelAuditLayerStatus,
};
use fandhe_container_core::launch_isolation::{
    AuditCoverageRecordOutcome, LaunchIsolationRecord, RecordedLandlock, RecordedRule,
    RecordedTarget, RootIdentity,
};
use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    LaunchMode, LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, StartTimeouts, create,
};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, CreateRequest, GetStateRequest, StartRequest, StateRecord,
    StateRevision, StateStore, TraitError,
};
use fandhe_container_supervisor::start_entry::{StartDeps, run_start};
use fandhe_container_supervisor::state::open_default_store;
use fandhe_container_supervisor::stderr_sink::{EmitOutcome, flush_stderr, install_stderr_writer};

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

/// 縮退を評価済みで、その監査記録を書けなかった launch の記録。
fn failed_record() -> LaunchIsolationRecord {
    LaunchIsolationRecord::from_parts(
        RootIdentity::new(44, 1234),
        RecordedLandlock::new(0xFFFF, vec![RecordedRule::new(RecordedTarget::Root, 0x7)]).unwrap(),
    )
    .with_audit_coverage(
        AuditCoveragePolicy::BestEffort,
        AuditCoverage::new(
            KernelAuditLayerStatus::Degraded(DegradeReason::SeccompKillNotLogged),
            KernelAuditLayerStatus::Degraded(DegradeReason::LandlockAuditAbiTooOld),
        ),
    )
    .with_audit_coverage_record_failed()
    .unwrap()
}

struct Proc {
    record: LaunchIsolationRecord,
}

impl LaunchedProcess for Proc {
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
    fn launch_isolation(&self) -> Option<&LaunchIsolationRecord> {
        Some(&self.record)
    }
}

struct Launcher;

impl ProcessLauncher for Launcher {
    fn launch_mode(&self) -> LaunchMode {
        LaunchMode::CallerBounded
    }
    fn launch(
        &self,
        _spec: &LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        Ok(Box::new(Proc {
            record: failed_record(),
        }))
    }
    fn confirm_no_process(&self, _id: &ContainerId, _timeout: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

struct Deps;

impl StartDeps for Deps {
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
        Ok(Arc::new(Launcher))
    }
    fn recover_interrupted(
        &mut self,
        _store: &dyn StateStore,
        _id: &ContainerId,
        _timeouts: &StartTimeouts,
    ) -> Result<(), TraitError> {
        Ok(())
    }
    fn release_cgroup(&mut self) -> Result<(), TraitError> {
        Ok(())
    }
}

/// SEC-4・REPAIR-4(#2468): 記録失敗を持つ launch を `run_start` で起動すると、`state.json` を読み戻した値に
/// 失敗が残り、supervisor のログへ縮退の行に続けて記録失敗の固定 1 行が出る。
#[test]
fn sec4_repair4_2468_record_failure_reaches_state_and_supervisor_log() {
    use std::os::unix::fs::PermissionsExt;
    // tmpfiles の flock 走査から守る親（#3026）。bundle・状態ルートはその子に作り、関数の最後まで保持する。
    let scratch =
        scratch_root::ScratchDir::new("fandhe-sup-2468", std::time::Duration::from_secs(10));
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
    let root = base.join("state");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let store = open_default_store(Some(root)).unwrap();
    let id = ContainerId::new("c-2468").unwrap();
    let req = CreateRequest::new(id.clone(), base.join("bundle")).unwrap();
    create(store.as_ref(), &OpRecorder::new(), &req).unwrap();

    let buf = SharedBuf::default();
    install_stderr_writer(Box::new(buf.clone())).expect("install");

    let timeouts = StartTimeouts::new(
        Duration::from_millis(100),
        Duration::from_secs(1),
        Duration::from_millis(500),
    )
    .unwrap();
    let mut out = Vec::new();
    let running = run_start(
        Box::new(Deps),
        &store,
        &Arc::new(OpRecorder::new()),
        &StartRequest::new(id.clone()),
        &timeouts,
        &mut out,
    )
    .unwrap_or_else(|_| panic!("started: {}", String::from_utf8_lossy(&out)));
    assert_eq!(out, b"FCSUP1 OK 4242\n");

    // 状態: 読み戻した記録に縮退と記録失敗が残る。
    let rec = store.get(&GetStateRequest::new(id)).unwrap();
    assert_eq!(rec.status().state(), ContainerState::Running);
    let iso = rec.launch_isolation().expect("launch isolation persisted");
    assert_eq!(
        iso.audit_coverage_record(),
        AuditCoverageRecordOutcome::Failed
    );

    // ログ: 縮退の行 + 記録失敗の行。
    assert_eq!(flush_stderr(Duration::from_secs(5)), EmitOutcome::Written);
    let expected = concat!(
        r#"{"component":"core.audit","operation":"audit_coverage","outcome":"degraded","#,
        r#""seccomp_kill":"seccomp_kill_not_logged","landlock":"landlock_audit_abi_too_old"}"#,
        "\n",
        r#"{"component":"core.audit","operation":"audit_coverage_record","outcome":"failed"}"#,
        "\n"
    );
    // 前後にはホストの sysctl 次第で legacy_tiocsti の警告行や start の計測行（start_metrics）が付くため、
    // 先頭一致ではなく、2 行が連続した部分列として含まれることを照合する（ホストの sysctl に依存しない）。
    let logged = String::from_utf8_lossy(buf.0.lock().unwrap().as_slice()).into_owned();
    assert!(
        logged.contains(expected),
        "unexpected supervisor log: {logged}"
    );
    drop(running);
    let _ = std::fs::remove_dir_all(&base);
}
