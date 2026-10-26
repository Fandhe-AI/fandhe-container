//! `CoreLifecycleRuntime` の start・kill・stop・delete が supervisor 経由の本番経路へ結線されていることの結合試験
//! （CRI-2・PLUG-1・SUP-1・SUP-9・REPAIR-5・TASK-114 追補・#2434）。Linux 限定・root 不要で既定のテスト集合に入る。
//!
//! 偽の systemd-run・supervisor（一時ディレクトリの sh スクリプト）を `FixedLaunchStarter` で注入して、成功の分岐と
//! fail-closed の分岐を具体値で照合する。実際の systemd・委譲 cgroup・制御チャネルは使わない（実機での通しは #850・#2062）。
//! スクリプトはプロセスで 1 回だけ書いてから使う（並行する試験が書き込み中のファイルを exec して ETXTBSY になるのを避ける）。

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpRecorder};
use fandhe_container_core::oci_runtime::{
    CgroupRemoval, ContainerCgroupRemover, ProcessSignaler, StartTimeouts,
};
use fandhe_container_core::traits::{
    CgroupPlacement, CgroupScope, ContainerId, ContainerLogPath, ContainerRuntime, ContainerState,
    ContainerStatus, CreateStateRequest, DeleteRequest, DeleteStateRequest, DeleteStateResponse,
    ErrorCode, GetStateRequest, KillRequest, ListStateRequest, Signal, StartRequest, StateList,
    StateRecord, StateRevision, StateStore, StopRequest, TraitError, UpdateStateRequest,
};
use fandhe_container_plugin_cri::adapter::{CoreLifecycleRuntime, PLUGIN_RUNTIME_TIMEOUT};
use fandhe_container_plugin_cri::supervised::{
    FixedLaunchStarter, MSG_START_REPORT_MISMATCH, MSG_STOP_DEADLINE, MSG_TOO_MANY_SUPERVISORS,
    SignalerSource, SupervisedLifecycle,
};
use fandhe_container_supervisor::cgroup_remover::{DetectedCgroupRemover, detect_error};
use fandhe_container_supervisor::start_client::SupervisorLaunch;
use fandhe_container_supervisor::start_contract::cli_receive_deadline;

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).expect("valid id")
}

fn pid(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).expect("nonzero")
}

/// 偽の systemd-run と supervisor の置き場（プロセスで 1 回だけ作る）。
struct Scripts {
    dir: PathBuf,
    systemd_run: PathBuf,
    supervisor: PathBuf,
}

/// 偽の supervisor。引数は `start --root <root> <id>`（契約の argv）で、`<id>` で報告を切り替える。
const FAKE_SUPERVISOR: &str = r#"#!/bin/sh
if [ "$4" = "--cri-log-path" ]; then
  printf '%s %s\n' "$5" "$6" > "$3/cri-log-arg"
  printf 'FCSUP1 OK 4242\n'; exec sleep 3
fi
case "$4" in
  c-ok) printf 'FCSUP1 OK 4242\n'; exec sleep 3;;
  c-err) printf 'FCSUP1 ERR FAILED_PRECONDITION 5 container is not created\n'; exit 0;;
  c-eof) exit 0;;
  c-bad) printf 'garbage\n'; exec sleep 3;;
  c-hang) exec sleep 3;;
  c-reported-timeout) printf 'FCSUP1 ERR TIMEOUT 7 launch timed out\n'; sleep 1; touch "$3/cleanup-done"; exit 0;;
  c-quick) printf 'FCSUP1 OK 4242\n'; exit 0;;
  c-exec-notfound) printf 'FCSUP1 ERR NOT_FOUND 3 container launch failed in the Exec stage\n'; exit 0;;
  c-exec-denied) printf 'FCSUP1 ERR PERMISSION_DENIED 6 container launch failed in the Exec stage\n'; exit 0;;
  c-exec-invalid) printf 'FCSUP1 ERR INVALID_ARGUMENT 2 container launch failed in the Exec stage\n'; exit 0;;
  *) printf 'FCSUP1 ERR INTERNAL 1 unexpected id\n'; exit 0;;
esac
"#;

/// 偽の systemd-run。`--` までの scope 指定を読み飛ばし、残り（supervisor と契約の引数）を exec する。
const FAKE_SYSTEMD_RUN: &str = r#"#!/bin/sh
while [ "$1" != "--" ]; do shift; done
shift
exec "$@"
"#;

fn scripts() -> &'static Scripts {
    static SCRIPTS: OnceLock<Scripts> = OnceLock::new();
    SCRIPTS.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("fc-2434-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let write = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).expect("write");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            p
        };
        let systemd_run = write("systemd-run", FAKE_SYSTEMD_RUN);
        let supervisor = write("fandhe-container-supervisor", FAKE_SUPERVISOR);
        Scripts {
            dir,
            systemd_run,
            supervisor,
        }
    })
}

fn starter(within: Duration) -> Arc<FixedLaunchStarter> {
    let s = scripts();
    Arc::new(FixedLaunchStarter::new(
        SupervisorLaunch::new(
            s.systemd_run.clone(),
            s.supervisor.clone(),
            OsString::from("/run/user/1000"),
        ),
        within,
    ))
}

/// signaler の種別（stop の意図つきか、意図なしか）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Stop,
    Plain,
}

/// 状態ストアと signaler が共有する模擬の世界。signaler が特定のシグナルを受けたら Stopped へ遷移させる。
struct Sim {
    status: Mutex<ContainerStatus>,
    calls: Mutex<Vec<(Kind, Signal)>>,
    stop_on: Mutex<Option<Signal>>,
    /// `Some` なら signal が最初に呼ばれたとき Stopped に遷移させたうえでこのコードで失敗する（終了との競合）。
    race: Mutex<Option<ErrorCode>>,
    /// `Some` なら signal はこのコードで失敗する（状態は変えない）。
    fail: Mutex<Option<ErrorCode>>,
    cgroup: bool,
    root: PathBuf,
    deletes: AtomicU32,
    /// 状態ストアの `delete` が呼ばれたら立ち、以後 `get` は `NotFound` を返す（ログ削除の guard が通るように）。
    deleted: AtomicBool,
}

impl Sim {
    fn new(status: ContainerStatus) -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(status),
            calls: Mutex::new(Vec::new()),
            stop_on: Mutex::new(None),
            race: Mutex::new(None),
            fail: Mutex::new(None),
            cgroup: false,
            root: scripts().dir.clone(),
            deletes: AtomicU32::new(0),
            deleted: AtomicBool::new(false),
        })
    }

    /// `root` を指定して作る（ログを実ファイルで扱う試験用。`scripts().dir` はプロセスで共有のため使わない）。
    fn running_in(root: PathBuf, id: &str, p: u32) -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(ContainerStatus::running(cid(id), Some(pid(p)))),
            calls: Mutex::new(Vec::new()),
            stop_on: Mutex::new(None),
            race: Mutex::new(None),
            fail: Mutex::new(None),
            cgroup: false,
            root,
            deletes: AtomicU32::new(0),
            deleted: AtomicBool::new(false),
        })
    }

    fn with_cgroup(status: ContainerStatus) -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(status),
            calls: Mutex::new(Vec::new()),
            stop_on: Mutex::new(None),
            race: Mutex::new(None),
            fail: Mutex::new(None),
            cgroup: true,
            root: scripts().dir.clone(),
            deletes: AtomicU32::new(0),
            deleted: AtomicBool::new(false),
        })
    }

    fn calls(&self) -> Vec<(Kind, Signal)> {
        self.calls.lock().expect("lock").clone()
    }

    fn state(&self) -> ContainerState {
        self.status.lock().expect("lock").state()
    }
}

/// `Sim` を `StateStore` として見せる（`host_state_root` を持つので signaler・起動の経路が動く）。
struct SimStore(Arc<Sim>);

fn unused() -> TraitError {
    TraitError::new(ErrorCode::Unimplemented, "unused")
}

impl StateStore for SimStore {
    fn create(&self, _r: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        Err(unused())
    }
    fn get(&self, _r: &GetStateRequest) -> Result<StateRecord, TraitError> {
        if self.0.deleted.load(Ordering::SeqCst) {
            return Err(TraitError::new(ErrorCode::NotFound, "deleted"));
        }
        let status = self.0.status.lock().expect("lock").clone();
        let record = StateRecord::new(status, self.0.root.join("bundle"), StateRevision::INITIAL)?;
        Ok(if self.0.cgroup {
            record.with_cgroup(CgroupPlacement::new(
                CgroupScope::new("/fc").expect("scope"),
                StateRevision::INITIAL,
            ))
        } else {
            record
        })
    }
    fn update(&self, _r: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        Err(unused())
    }
    fn delete(&self, _r: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        self.0.deletes.fetch_add(1, Ordering::SeqCst);
        self.0.deleted.store(true, Ordering::SeqCst);
        Ok(DeleteStateResponse::new())
    }
    fn list(&self, _r: &ListStateRequest) -> Result<StateList, TraitError> {
        Err(unused())
    }
    fn host_state_root(&self) -> Option<&Path> {
        Some(&self.0.root)
    }
}

/// 呼び出しを記録し、設定に応じて Stopped へ遷移させる偽の signaler。
struct SimSignaler {
    kind: Kind,
    sim: Arc<Sim>,
}

impl ProcessSignaler for SimSignaler {
    fn signal(
        &self,
        id: &ContainerId,
        _pid: NonZeroU32,
        signal: Signal,
        _deadline: Instant,
    ) -> Result<(), TraitError> {
        self.sim
            .calls
            .lock()
            .expect("lock")
            .push((self.kind, signal));
        if let Some(code) = *self.sim.fail.lock().expect("lock") {
            return Err(TraitError::new(code, "injected signaler failure"));
        }
        let stop = |sim: &Sim| {
            *sim.status.lock().expect("lock") = ContainerStatus::stopped(id.clone(), Some(143));
        };
        if let Some(code) = self.sim.race.lock().expect("lock").take() {
            stop(&self.sim);
            return Err(TraitError::new(code, "exited before delivery"));
        }
        if *self.sim.stop_on.lock().expect("lock") == Some(signal) {
            stop(&self.sim);
        }
        Ok(())
    }
}

struct SimSignalers(Arc<Sim>);

impl SignalerSource for SimSignalers {
    fn plain(&self, _store: &dyn StateStore) -> Arc<dyn ProcessSignaler> {
        Arc::new(SimSignaler {
            kind: Kind::Plain,
            sim: Arc::clone(&self.0),
        })
    }

    fn for_stop(&self, _store: &dyn StateStore) -> Arc<dyn ProcessSignaler> {
        Arc::new(SimSignaler {
            kind: Kind::Stop,
            sim: Arc::clone(&self.0),
        })
    }
}

struct Harness {
    rt: CoreLifecycleRuntime,
    sim: Arc<Sim>,
}

fn harness(sim: Arc<Sim>, within: Duration) -> Harness {
    let rt = CoreLifecycleRuntime::new(Arc::new(SimStore(Arc::clone(&sim)))).with_supervision(
        SupervisedLifecycle::new(starter(within), Arc::new(SimSignalers(Arc::clone(&sim)))),
    );
    Harness { rt, sim }
}

fn running(id: &str, p: u32) -> Arc<Sim> {
    Sim::new(ContainerStatus::running(cid(id), Some(pid(p))))
}

const LONG: Duration = Duration::from_secs(10);

/// CRI-2・SUP-1: 偽の supervisor の OK 報告を受け、記録と一致する Running の status（pid 4242）を返す。
#[test]
fn cri2_start_reports_running_status() {
    let h = harness(running("c-ok", 4242), LONG);
    let status = h.rt.start(&StartRequest::new(cid("c-ok"))).expect("start");
    assert_eq!(status.state(), ContainerState::Running);
    assert_eq!(status.pid(), Some(pid(4242)));
    assert_eq!(h.rt.tracked_supervisors(), 1);
}

/// CRI-2・SUP-4（#2671）: `StartRequest` の CRI ログの書き先は supervisor の argv `--cri-log-path <path> <id>` として渡る。
#[test]
fn cri2_start_passes_cri_log_path_to_supervisor_argv() {
    let root = temp_root("crilog");
    let h = harness(Sim::running_in(root.clone(), "c-log", 4242), LONG);
    let lp = ContainerLogPath::new("/var/log/pods/ns_p_u/c/0.log").expect("log path");
    let req = StartRequest::new(cid("c-log")).with_log_path(lp);
    let status = h.rt.start(&req).expect("start");
    assert_eq!(status.state(), ContainerState::Running);
    let seen = std::fs::read_to_string(root.join("cri-log-arg")).expect("fake supervisor argv");
    assert_eq!(seen, "/var/log/pods/ns_p_u/c/0.log c-log\n");
    let _ = std::fs::remove_dir_all(&root);
}

/// ERR-2・CRI-2: supervisor の ERR 報告は code と message をそのまま写す。
#[test]
fn cri2_start_maps_supervisor_err_code() {
    let h = harness(running("c-err", 1), LONG);
    let e =
        h.rt.start(&StartRequest::new(cid("c-err")))
            .expect_err("err report");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "container is not created");
}

/// SEC-4・CORE-5・CRI-2・ERR-1（#2716）: launch の `Exec` 段の失敗（`R` の後の `execveat` の errno 分類）は、
/// `TraitError` の code と固定文言のまま届き、CRI の gRPC Status は NotFound / PermissionDenied / InvalidArgument
/// と同じ固定文言になる（パス・errno は載らない）。
#[test]
fn sec4_2716_start_exec_stage_failure_maps_to_grpc_status() {
    use fandhe_container_cri::error::CriError;
    use tonic::Code;

    for (id, code, grpc) in [
        ("c-exec-notfound", ErrorCode::NotFound, Code::NotFound),
        (
            "c-exec-denied",
            ErrorCode::PermissionDenied,
            Code::PermissionDenied,
        ),
        (
            "c-exec-invalid",
            ErrorCode::InvalidArgument,
            Code::InvalidArgument,
        ),
    ] {
        let h = harness(running(id, 1), LONG);
        let e =
            h.rt.start(&StartRequest::new(cid(id)))
                .expect_err("exec stage failure");
        assert_eq!(e.code(), code, "{id}");
        assert_eq!(e.message(), "container launch failed in the Exec stage");
        let status = tonic::Status::from(CriError::from(&e));
        assert_eq!(status.code(), grpc, "{id}");
        assert_eq!(
            status.message(),
            "container launch failed in the Exec stage"
        );
    }
}

/// REPAIR-5: 報告が期限内に来なければ TIMEOUT（結果不明）で、supervisor は kill しない。
#[test]
fn repair5_start_times_out_without_report() {
    let h = harness(running("c-hang", 1), Duration::from_millis(300));
    let t = Instant::now();
    let e =
        h.rt.start(&StartRequest::new(cid("c-hang")))
            .expect_err("timeout");
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert_eq!(
        e.message(),
        "supervisor did not report a start result within the deadline; check the container state"
    );
    assert!(t.elapsed() >= Duration::from_millis(300));
    assert!(t.elapsed() < Duration::from_secs(5));
    // 報告の無い supervisor は kill され、入口の回収で一覧から外れる（補助スレッドを残さない）。
    let deadline = Instant::now() + Duration::from_secs(10);
    while h.rt.tracked_supervisors() != 0 {
        assert!(
            Instant::now() < deadline,
            "timed-out child was not reclaimed"
        );
        let _ = h.rt.kill(&KillRequest::new(cid("c-hang"), Signal::SIGTERM));
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// CORE-2・REPAIR-5: supervisor が報告した TIMEOUT では、後始末の途中の supervisor を kill しない（後始末が完了する）。
#[test]
fn core2_reported_timeout_does_not_kill_cleaning_supervisor() {
    let marker = scripts().dir.join("cleanup-done");
    let _ = std::fs::remove_file(&marker);
    let h = harness(running("c-reported-timeout", 1), LONG);
    let e =
        h.rt.start(&StartRequest::new(cid("c-reported-timeout")))
            .expect_err("reported timeout");
    assert_eq!(e.code(), ErrorCode::Timeout);
    // kill されていれば後始末の印が作られない。
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "supervisor was killed during cleanup"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = std::fs::remove_file(&marker);
}

/// SUP-1: 1 行も無いまま EOF なら INTERNAL。
#[test]
fn cri2_start_eof_is_internal() {
    let h = harness(running("c-eof", 1), LONG);
    let e =
        h.rt.start(&StartRequest::new(cid("c-eof")))
            .expect_err("eof");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert_eq!(
        e.message(),
        "supervisor exited without reporting a start result (systemd-run may have failed to create the user scope)"
    );
}

/// REPAIR-2: 壊れた報告は INTERNAL で fail-closed。
#[test]
fn cri2_start_malformed_report_is_internal() {
    let h = harness(running("c-bad", 1), LONG);
    let e =
        h.rt.start(&StartRequest::new(cid("c-bad")))
            .expect_err("malformed");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert_eq!(e.message(), "supervisor start report is malformed");
}

/// SEC-1: 報告された pid（4242）と記録の pid（4243）が食い違うなら INTERNAL で fail-closed。
#[test]
fn cri2_start_pid_mismatch_fails_closed() {
    let h = harness(running("c-ok", 4243), LONG);
    let e =
        h.rt.start(&StartRequest::new(cid("c-ok")))
            .expect_err("mismatch");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert_eq!(e.message(), MSG_START_REPORT_MISMATCH);
}

/// 報告の直後に終了して Stopped が記録済みなら、その status を返す（CRI 側が終了済みとして扱う）。
#[test]
fn cri2_start_returns_stopped_when_exited_immediately() {
    let sim = Sim::new(ContainerStatus::stopped(cid("c-quick"), Some(0)));
    let h = harness(sim, LONG);
    let status =
        h.rt.start(&StartRequest::new(cid("c-quick")))
            .expect("start");
    assert_eq!(status.state(), ContainerState::Stopped);
}

/// D7: 終了済みの supervisor の子は次の呼び出しで回収され、追跡数が 0 に戻る（ゾンビを溜めない）。
#[test]
fn cri2_reaps_exited_supervisors() {
    let h = harness(
        Sim::new(ContainerStatus::stopped(cid("c-quick"), Some(0))),
        LONG,
    );
    h.rt.start(&StartRequest::new(cid("c-quick")))
        .expect("start");
    assert_eq!(h.rt.tracked_supervisors(), 1);
    let deadline = Instant::now() + Duration::from_secs(10);
    while h.rt.tracked_supervisors() != 0 {
        assert!(Instant::now() < deadline, "exited child was not reaped");
        // kill は Stopped で失敗するが、入口で回収する。
        let _ =
            h.rt.kill(&KillRequest::new(cid("c-quick"), Signal::SIGTERM));
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// CRI-2・ERR-3・PLUG-1・REPAIR-4: 追跡枠（上限 1）が埋まっている間の start は `RESOURCE_EXHAUSTED` と固定文言で断り、
/// 新しい supervisor を起動しない。先の子が終了して回収されれば枠が戻り、次の start は成功する（#2609）。
#[test]
fn cri2_start_rejects_when_tracking_limit_reached_resource_exhausted() {
    let sim = running("c-ok", 4242);
    let rt = CoreLifecycleRuntime::new(Arc::new(SimStore(Arc::clone(&sim)))).with_supervision(
        SupervisedLifecycle::with_tracking_limit(
            starter(LONG),
            Arc::new(SimSignalers(Arc::clone(&sim))),
            1,
        ),
    );
    rt.start(&StartRequest::new(cid("c-ok"))).expect("first");
    assert_eq!(rt.tracked_supervisors(), 1);
    let e = rt
        .start(&StartRequest::new(cid("c-ok")))
        .expect_err("limit reached");
    assert_eq!(e.code(), ErrorCode::ResourceExhausted);
    assert_eq!(e.code().as_str(), "RESOURCE_EXHAUSTED");
    assert_eq!(e.message(), MSG_TOO_MANY_SUPERVISORS);
    // 断った start は子を増やさない。
    assert_eq!(rt.tracked_supervisors(), 1);
    // 偽 supervisor（3 秒で終了）が回収されれば枠が戻る。
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match rt.start(&StartRequest::new(cid("c-ok"))) {
            Ok(status) => {
                assert_eq!(status.state(), ContainerState::Running);
                break;
            }
            Err(e) => {
                assert_eq!(e.code(), ErrorCode::ResourceExhausted);
                assert!(Instant::now() < deadline, "slot was not released");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// SUP-9: stop は stop の意図つきで SIGTERM を 1 回だけ送り、Stopped になったらその status を返す。
#[test]
fn sup9_stop_sends_stop_intent_then_returns_stopped() {
    let sim = running("c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGTERM);
    let h = harness(sim, LONG);
    let status =
        h.rt.stop(&StopRequest::new(cid("c1"), Duration::from_secs(5)).expect("req"))
            .expect("stop");
    assert_eq!(status.state(), ContainerState::Stopped);
    assert_eq!(status.exit_code(), Some(143));
    assert_eq!(h.sim.calls(), [(Kind::Stop, Signal::SIGTERM)]);
}

/// SUP-9・REPAIR-5: 猶予（0）を過ぎても Running なら、意図なしの signaler で SIGKILL へ昇格する。
#[test]
fn sup9_stop_escalates_to_sigkill_after_grace() {
    let sim = running("c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGKILL);
    let h = harness(sim, LONG);
    let status =
        h.rt.stop(&StopRequest::new(cid("c1"), Duration::ZERO).expect("req"))
            .expect("stop");
    assert_eq!(status.state(), ContainerState::Stopped);
    assert_eq!(
        h.sim.calls(),
        [
            (Kind::Stop, Signal::SIGTERM),
            (Kind::Plain, Signal::SIGKILL)
        ]
    );
}

/// SUP-9・CRI-2（#2668）: `StopRequest::with_signal` の指定シグナルを stop の意図つきで送る。
#[test]
fn sup9_stop_sends_requested_signal_with_stop_intent() {
    let sigint = Signal::new(2).expect("2 is valid");
    let sim = running("c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(sigint);
    let h = harness(sim, LONG);
    let req = StopRequest::new(cid("c1"), Duration::from_secs(5))
        .expect("req")
        .with_signal(sigint);
    let status = h.rt.stop(&req).expect("stop");
    assert_eq!(status.state(), ContainerState::Stopped);
    assert_eq!(h.sim.calls(), [(Kind::Stop, sigint)]);
}

/// SUP-9・REPAIR-5・CRI-2（#2668）: 指定シグナルで止まらなくても、猶予後は無条件に SIGKILL へ昇格する。
#[test]
fn sup9_stop_custom_signal_still_escalates_to_sigkill() {
    let sigint = Signal::new(2).expect("2 is valid");
    let sim = running("c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGKILL);
    let h = harness(sim, LONG);
    let req = StopRequest::new(cid("c1"), Duration::ZERO)
        .expect("req")
        .with_signal(sigint);
    let status = h.rt.stop(&req).expect("stop");
    assert_eq!(status.state(), ContainerState::Stopped);
    assert_eq!(
        h.sim.calls(),
        [(Kind::Stop, sigint), (Kind::Plain, Signal::SIGKILL)]
    );
}

/// 冪等: Stopped には何も送らず、その status を返す。
#[test]
fn sup9_stop_already_stopped_is_idempotent() {
    let h = harness(Sim::new(ContainerStatus::stopped(cid("c1"), Some(0))), LONG);
    let status =
        h.rt.stop(&StopRequest::new(cid("c1"), Duration::from_secs(1)).expect("req"))
            .expect("stop");
    assert_eq!(status.state(), ContainerState::Stopped);
    assert_eq!(h.sim.calls(), []);
}

/// 未起動の Created（pid なし）は何も送らず停止済みとして返す（CRI-2。StartContainer 前の StopPodSandbox）。
#[test]
fn sup9_stop_created_without_pid_is_reported_stopped() {
    let h = harness(Sim::new(ContainerStatus::created(cid("c1"), None)), LONG);
    let s =
        h.rt.stop(&StopRequest::new(cid("c1"), Duration::from_secs(1)).expect("req"))
            .expect("created is already stopped");
    assert_eq!(s.state(), ContainerState::Stopped);
    assert_eq!(h.sim.calls(), []);
}

/// REPAIR-5: SIGKILL の後も Stopped にならなければ、5 秒で打ち切って TIMEOUT。
#[test]
fn repair5_stop_times_out_when_never_stopped() {
    let h = harness(running("c1", 4242), LONG);
    let t = Instant::now();
    let e =
        h.rt.stop(&StopRequest::new(cid("c1"), Duration::ZERO).expect("req"))
            .expect_err("never stops");
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert_eq!(e.message(), MSG_STOP_DEADLINE);
    assert!(t.elapsed() >= Duration::from_secs(5), "{:?}", t.elapsed());
    assert!(t.elapsed() < Duration::from_secs(15), "{:?}", t.elapsed());
}

/// signaler の失敗（UNAVAILABLE）はコードを保ったまま返り、SIGKILL へは進まない。
#[test]
fn sup9_stop_keeps_signaler_error_code() {
    let sim = running("c1", 4242);
    *sim.fail.lock().expect("lock") = Some(ErrorCode::Unavailable);
    let h = harness(sim, LONG);
    let e =
        h.rt.stop(&StopRequest::new(cid("c1"), Duration::ZERO).expect("req"))
            .expect_err("unavailable");
    assert_eq!(e.code(), ErrorCode::Unavailable);
    assert_eq!(h.sim.calls(), [(Kind::Stop, Signal::SIGTERM)]);
}

/// 送信の直前に終了していた（signaler が FAILED_PRECONDITION を返し、記録は Stopped）なら成功として扱う。
#[test]
fn sup9_stop_race_exit_before_delivery_is_ok() {
    let sim = running("c1", 4242);
    *sim.race.lock().expect("lock") = Some(ErrorCode::FailedPrecondition);
    let h = harness(sim, LONG);
    let status =
        h.rt.stop(&StopRequest::new(cid("c1"), Duration::from_secs(1)).expect("req"))
            .expect("stop");
    assert_eq!(status.state(), ContainerState::Stopped);
    assert_eq!(h.sim.state(), ContainerState::Stopped);
}

/// 制御チャネルが消えた（signaler が UNAVAILABLE を返し、記録は Stopped）場合も成功として扱う（CRI-2）。
#[test]
fn cri2_stop_race_channel_gone_unavailable_is_ok() {
    let sim = running("c1", 4242);
    *sim.race.lock().expect("lock") = Some(ErrorCode::Unavailable);
    let h = harness(sim, LONG);
    let status =
        h.rt.stop(&StopRequest::new(cid("c1"), Duration::from_secs(1)).expect("req"))
            .expect("stop");
    assert_eq!(status.state(), ContainerState::Stopped);
}

/// kill は意図なしの signaler で 1 回だけ送り、終了は待たない（Running のまま返る）。
#[test]
fn cri2_kill_uses_plain_signal_without_intent() {
    let h = harness(running("c1", 4242), LONG);
    let status =
        h.rt.kill(&KillRequest::new(cid("c1"), Signal::SIGTERM))
            .expect("kill");
    assert_eq!(status.state(), ContainerState::Running);
    assert_eq!(h.sim.calls(), [(Kind::Plain, Signal::SIGTERM)]);
}

/// 何もしない remover（scope は記録の `/fc` と一致させる）。`remove` の呼び出し回数を数える。
struct CountingRemover {
    removes: AtomicU32,
}

impl ContainerCgroupRemover for CountingRemover {
    fn scope(&self) -> Result<CgroupScope, TraitError> {
        Ok(CgroupScope::new("/fc").expect("scope"))
    }
    fn remove(&self, _id: &ContainerId, _i: StateRevision) -> Result<CgroupRemoval, TraitError> {
        self.removes.fetch_add(1, Ordering::SeqCst);
        Ok(CgroupRemoval::Removed)
    }
    fn remove_recorded(
        &self,
        _id: &ContainerId,
        _p: &CgroupPlacement,
        _r: &OpRecorder,
    ) -> Result<CgroupRemoval, TraitError> {
        Err(unused())
    }
}

/// CRI-2・OCI-6: cgroup を記録したコンテナの delete は注入した remover を 1 回呼び、store.delete まで進む。
/// 成功後の supervisor ログ削除は記録器の `supervisor_log_remove` に成功として計上される。
#[test]
fn cri2_delete_with_cgroup_uses_injected_remover() {
    let sim = Sim::with_cgroup(ContainerStatus::stopped(cid("c1"), Some(0)));
    let remover = Arc::new(CountingRemover {
        removes: AtomicU32::new(0),
    });
    let recorder = Arc::new(OpRecorder::new());
    let rt = CoreLifecycleRuntime::with_recorder(
        Arc::new(SimStore(Arc::clone(&sim))),
        Arc::clone(&recorder),
    )
    .with_cgroup_remover(Arc::clone(&remover) as Arc<dyn ContainerCgroupRemover>);
    rt.delete(&DeleteRequest::new(cid("c1"))).expect("delete");
    assert_eq!(remover.removes.load(Ordering::SeqCst), 1);
    assert_eq!(sim.deletes.load(Ordering::SeqCst), 1);
    let stats = recorder
        .snapshot_op(&OpName::new("supervisor_log_remove").expect("name"))
        .expect("log removal recorded");
    assert_eq!((stats.success(), stats.failure()), (1, 0));
    // コンテナログ（#2593）は `@container-logs` が無くても 0 件で成功として計上される。
    let stats = recorder
        .snapshot_op(&OpName::new("container_log_remove").expect("name"))
        .expect("container log removal recorded");
    assert_eq!((stats.success(), stats.failure()), (1, 0));
}

/// fail-closed: 委譲 cgroup の検出に失敗したら cgroup も状態記録も残したまま、コードを保った固定文言で失敗する。
#[test]
fn cri2_delete_cgroup_detection_failure_keeps_record() {
    let sim = Sim::with_cgroup(ContainerStatus::stopped(cid("c1"), Some(0)));
    let remover = DetectedCgroupRemover::new(|| -> Result<CountingRemover, TraitError> {
        Err(detect_error(ErrorCode::FailedPrecondition))
    });
    let rt = CoreLifecycleRuntime::new(Arc::new(SimStore(Arc::clone(&sim))))
        .with_cgroup_remover(Arc::new(remover));
    let e = rt
        .delete(&DeleteRequest::new(cid("c1")))
        .expect_err("detection failed");
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "failed to detect the delegated cgroup");
    assert_eq!(sim.deletes.load(Ordering::SeqCst), 0);
}

/// REPAIR-5: CRI の待ち上限は supervisor の起動結果の受信期限（約 58.9 秒）より長い（結果不明へ先に倒れない）。
#[test]
fn repair5_plugin_runtime_timeout_exceeds_supervisor_deadline() {
    let receive = cli_receive_deadline(&StartTimeouts::default());
    assert_eq!(receive, Duration::from_millis(58_900));
    assert_eq!(PLUGIN_RUNTIME_TIMEOUT, receive + Duration::from_secs(2));
}

/// 試験ごとの一時ルート（mode 0700）。
fn temp_root(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let p = std::env::temp_dir().join(format!(
        "fc-2634-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&p).expect("mkdir");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    p
}

fn open_log_sink(root: &Path, id: &str) -> fandhe_container_supervisor::logs::RotatingFileSink {
    use fandhe_container_supervisor::logs::{
        LogSink as _, RotatingFileSink, StreamKind, container_log_dir,
        container_log_rotation_config,
    };
    let dir = container_log_dir(root);
    std::fs::create_dir_all(&dir).expect("logdir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let sink =
        RotatingFileSink::open(&dir, &cid(id), container_log_rotation_config()).expect("open");
    sink.append(StreamKind::Stdout, b"hello").expect("append");
    sink.flush().expect("flush");
    sink
}

fn log_dir_names(root: &Path) -> Vec<String> {
    let dir = fandhe_container_supervisor::logs::container_log_dir(root);
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn op_counts(rec: &OpRecorder, name: &str) -> Option<(u64, u64)> {
    rec.snapshot_op(&OpName::new(name).expect("name"))
        .map(|s| (s.success(), s.failure()))
}

fn force_runtime(sim: &Arc<Sim>, rec: &Arc<OpRecorder>, wait: Duration) -> CoreLifecycleRuntime {
    CoreLifecycleRuntime::with_recorder(Arc::new(SimStore(Arc::clone(sim))), Arc::clone(rec))
        .with_supervision(SupervisedLifecycle::new(
            starter(LONG),
            Arc::new(SimSignalers(Arc::clone(sim))),
        ))
        .with_container_log_lock_wait(wait)
}

/// SUP-7・CRI-2・#2634: running への force 削除で、`Stopped` の後に supervisor が sink を閉じるまでの窓を待ち、
/// ログとロックファイルを消す。
#[test]
fn sup7_cri2_force_delete_running_waits_for_sink_and_removes_logs() {
    let root = temp_root("force-ok");
    let sim = Sim::running_in(root.clone(), "c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGTERM);
    let sink = open_log_sink(&root, "c1");
    assert_eq!(log_dir_names(&root), ["c1.log", "c1.log.lock"]);
    let rec = Arc::new(OpRecorder::new());
    let rt = force_runtime(&sim, &rec, Duration::from_secs(5));
    // 状態が Stopped になった後で supervisor が drain してから sink を閉じる窓を模す。
    let closer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(sink);
    });
    rt.delete(&DeleteRequest::new(cid("c1")).with_force(true))
        .expect("force delete");
    closer.join().expect("join");
    assert_eq!(sim.calls(), [(Kind::Stop, Signal::SIGTERM)]);
    assert_eq!(log_dir_names(&root), Vec::<String>::new());
    assert_eq!(op_counts(&rec, "container_log_remove"), Some((1, 0)));
    assert_eq!(
        op_counts(&rec, "container_log_remove.failed_precondition"),
        None
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// SUP-7・CRI-2・REPAIR-4・REPAIR-5・#2634: 待ちの期限までに sink が閉じなければ、`delete` は `Ok` のままログを残し、
/// 失敗を `failed_precondition` の内訳つきで計上する。
#[test]
fn sup7_cri2_force_delete_running_keeps_logs_after_wait_deadline() {
    let root = temp_root("force-deadline");
    let sim = Sim::running_in(root.clone(), "c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGTERM);
    let _sink = open_log_sink(&root, "c1");
    let rec = Arc::new(OpRecorder::new());
    let rt = force_runtime(&sim, &rec, Duration::from_millis(200));
    rt.delete(&DeleteRequest::new(cid("c1")).with_force(true))
        .expect("force delete");
    assert_eq!(log_dir_names(&root), ["c1.log", "c1.log.lock"]);
    assert_eq!(op_counts(&rec, "container_log_remove"), Some((0, 1)));
    assert_eq!(
        op_counts(&rec, "container_log_remove.failed_precondition"),
        Some((0, 1))
    );
    for other in ["timeout", "invalid_argument", "internal", "other"] {
        assert_eq!(
            op_counts(&rec, &format!("container_log_remove.{other}")),
            None
        );
    }
    drop(_sink);
    let _ = std::fs::remove_dir_all(&root);
}

/// REPAIR-5・#2634・#2760: running への force 削除の最悪所要（stop + supervisor ログ + コンテナログの待ち + 起動オプション
/// 文書の掃除）は `PLUGIN_RUNTIME_TIMEOUT` に収まる。
#[test]
fn repair5_force_delete_worst_case_fits_runtime_timeout() {
    use fandhe_container_core::oci_runtime::KillTimeout;
    use fandhe_container_plugin_cri::supervised::STOP_KILL_WAIT;
    use fandhe_container_supervisor::container_options::store::OPTIONS_REMOVE_TIMEOUT;
    use fandhe_container_supervisor::logs::{
        CONTAINER_LOG_LOCK_WAIT, CONTAINER_LOG_REMOVE_TIMEOUT,
    };
    use fandhe_container_supervisor::supervisor_log::SUPERVISOR_LOG_REMOVE_TIMEOUT;
    let stop = (KillTimeout::DEFAULT + Duration::from_secs(1)) * 2 + STOP_KILL_WAIT;
    assert_eq!(stop, Duration::from_secs(17));
    let logs =
        SUPERVISOR_LOG_REMOVE_TIMEOUT + CONTAINER_LOG_LOCK_WAIT + CONTAINER_LOG_REMOVE_TIMEOUT;
    assert_eq!(logs, Duration::from_secs(20));
    assert_eq!(OPTIONS_REMOVE_TIMEOUT, Duration::from_secs(10));
    assert_eq!(
        stop + logs + OPTIONS_REMOVE_TIMEOUT,
        Duration::from_secs(47)
    );
    assert!(stop + logs + OPTIONS_REMOVE_TIMEOUT < PLUGIN_RUNTIME_TIMEOUT);
}

/// REPAIR-5・#2760: `create` の最悪所要（ログ回収 + 起動オプション文書の掃除 + 状態ロック + 監査記録 2 回）は
/// `PLUGIN_RUNTIME_TIMEOUT` に収まる。bundle の用意と core の create の I/O 自体は含めない（既存の残余）。
#[test]
fn repair5_create_worst_case_fits_runtime_timeout() {
    use fandhe_container_core::audit_log::RECORD_WAIT_LIMIT;
    use fandhe_container_core::state_store::STATE_LOCK_TIMEOUT;
    use fandhe_container_supervisor::container_options::store::OPTIONS_REMOVE_TIMEOUT;
    use fandhe_container_supervisor::logs::CONTAINER_LOG_REMOVE_TIMEOUT;
    let reclaim = CONTAINER_LOG_REMOVE_TIMEOUT + OPTIONS_REMOVE_TIMEOUT;
    assert_eq!(reclaim, Duration::from_secs(15));
    let audit = RECORD_WAIT_LIMIT * 2;
    assert_eq!(audit, Duration::from_millis(22_900));
    let total = reclaim + STATE_LOCK_TIMEOUT + audit;
    assert_eq!(total, Duration::from_millis(42_900));
    assert!(total < PLUGIN_RUNTIME_TIMEOUT);
}
