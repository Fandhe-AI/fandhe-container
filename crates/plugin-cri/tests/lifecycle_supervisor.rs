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
    CgroupPlacement, CgroupScope, CleanupOutcome, ContainerId, ContainerLogPath, ContainerRuntime,
    ContainerState, ContainerStatus, CreateStateRequest, DeleteRequest, DeleteStateRequest,
    DeleteStateResponse, ErrorCode, GetStateRequest, KillRequest, ListStateRequest, Signal,
    StartRequest, StateList, StateRecord, StateRevision, StateStore, StopRequest, TraitError,
    UpdateStateRequest,
};
use fandhe_container_plugin_cri::adapter::{
    CoreLifecycleRuntime, PLUGIN_ROOTFS_DEADLINE, PLUGIN_RUNTIME_TIMEOUT,
};
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
    /// 状態ストアの `delete` に入れる遅延（ミリ秒。core の delete が長引く場面の再現。#3027）。
    delete_delay_ms: std::sync::atomic::AtomicU64,
    /// true なら `delete` の後も `get` が記録を返し続ける（同じ ID が再作成済みの場面の再現。guard が偽になる。#3027）。
    recreate_after_delete: AtomicBool,
    /// 状態ストアの `get` が呼ばれた回数（`StateStore` の呼び出し回数の数え方の照合。#3143）。
    gets: AtomicU32,
    /// 状態ストアの `get` に入れる遅延（ミリ秒。状態ロックの待ちが予算を食う場面の再現。#3143）。
    get_delay_ms: std::sync::atomic::AtomicU64,
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
            delete_delay_ms: std::sync::atomic::AtomicU64::new(0),
            recreate_after_delete: AtomicBool::new(false),
            gets: AtomicU32::new(0),
            get_delay_ms: std::sync::atomic::AtomicU64::new(0),
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
            delete_delay_ms: std::sync::atomic::AtomicU64::new(0),
            recreate_after_delete: AtomicBool::new(false),
            gets: AtomicU32::new(0),
            get_delay_ms: std::sync::atomic::AtomicU64::new(0),
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
            delete_delay_ms: std::sync::atomic::AtomicU64::new(0),
            recreate_after_delete: AtomicBool::new(false),
            gets: AtomicU32::new(0),
            get_delay_ms: std::sync::atomic::AtomicU64::new(0),
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
        self.0.gets.fetch_add(1, Ordering::SeqCst);
        let delay = self.0.get_delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }
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
        let delay = self.0.delete_delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }
        self.0.deletes.fetch_add(1, Ordering::SeqCst);
        if !self.0.recreate_after_delete.load(Ordering::SeqCst) {
            self.0.deleted.store(true, Ordering::SeqCst);
        }
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

/// REPAIR-5・CRI-2・#3143: 送信が終了との競合（FAILED_PRECONDITION / UNAVAILABLE）で失敗し、読み直しで Stopped を観測済みなら、
/// 予算つきの stop は追加の状態読み取りをせずに成功する（読み取りは入口・core の kill・読み直しの 3 回だけ）。
#[test]
fn repair5_3143_stop_within_observed_stopped_skips_extra_read() {
    for code in [ErrorCode::FailedPrecondition, ErrorCode::Unavailable] {
        let sim = running("c1", 4242);
        *sim.race.lock().expect("lock") = Some(code);
        let lifecycle =
            SupervisedLifecycle::new(starter(LONG), Arc::new(SimSignalers(Arc::clone(&sim))));
        let store = SimStore(Arc::clone(&sim));
        let rec = OpRecorder::new();
        let stop = StopRequest::new(cid("c1"), Duration::ZERO).expect("stop");
        let status = lifecycle
            .stop_within(&store, &rec, &stop, Some(Duration::from_secs(22)))
            .expect("stop");
        assert_eq!(status.state(), ContainerState::Stopped);
        assert_eq!(sim.gets.load(Ordering::SeqCst), 3, "{code:?}");
    }
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

/// 警告行を捕捉する出力先つきに差し替える。
fn capture_warnings(rt: CoreLifecycleRuntime) -> (CoreLifecycleRuntime, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let rt = rt.with_cleanup_warning_sink(Arc::new(move |l| sink.lock().expect("lock").push(l)));
    (rt, lines)
}

fn supervisor_log_names(root: &Path) -> Vec<String> {
    let dir = fandhe_container_supervisor::supervisor_log::log_dir(root);
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// SUP-7・CRI-2・REPAIR-5・#2964: supervisor ログの flock が drain 中に保持されていても、解放を期限つきで待って消す。
#[test]
fn sup7_cri2_2964_force_delete_waits_for_supervisor_log_release() {
    let root = temp_root("suplog-ok");
    let sim = Sim::running_in(root.clone(), "c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGTERM);
    let writer =
        fandhe_container_supervisor::supervisor_log::open(&root, &cid("c1")).expect("open");
    assert!(!supervisor_log_names(&root).is_empty());
    let rec = Arc::new(OpRecorder::new());
    let (rt, warnings) = capture_warnings(force_runtime(&sim, &rec, Duration::from_secs(3)));
    let closer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(writer);
    });
    let resp = rt
        .delete(&DeleteRequest::new(cid("c1")).with_force(true))
        .expect("force delete");
    closer.join().expect("join");
    assert_eq!(resp.supervisor_log(), CleanupOutcome::Removed);
    assert_eq!(resp.container_log(), CleanupOutcome::Removed);
    assert_eq!(supervisor_log_names(&root), Vec::<String>::new());
    assert!(warnings.lock().expect("lock").is_empty());
    assert_eq!(op_counts(&rec, "supervisor_log_remove"), Some((1, 0)));
    let _ = std::fs::remove_dir_all(&root);
}

/// SUP-7・CRI-2・REPAIR-4・REPAIR-5・#2964: 待ちの期限までロックが解放されなければ、`delete` は `Ok` のまま
/// supervisor ログを残し、`FailedPrecondition`・`sink_open_after_wait` の警告と Failure の計上で知らせる。
#[test]
fn sup7_repair5_2964_force_delete_keeps_supervisor_log_when_lock_outlives_wait() {
    let root = temp_root("suplog-keep");
    let sim = Sim::running_in(root.clone(), "c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGTERM);
    let _writer =
        fandhe_container_supervisor::supervisor_log::open(&root, &cid("c1")).expect("open");
    let rec = Arc::new(OpRecorder::new());
    let (rt, warnings) = capture_warnings(force_runtime(&sim, &rec, Duration::from_millis(200)));
    let started = Instant::now();
    let resp = rt
        .delete(&DeleteRequest::new(cid("c1")).with_force(true))
        .expect("force delete");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(
        resp.supervisor_log(),
        CleanupOutcome::Kept {
            code: ErrorCode::FailedPrecondition
        }
    );
    assert_eq!(supervisor_log_names(&root), ["c1.log", "c1.log.lock"]);
    assert_eq!(
        *warnings.lock().expect("lock"),
        [
            "{\"level\":\"warn\",\"event\":\"container_delete_cleanup\",\"id\":\"c1\",\"target\":\"supervisor_log\",\"code\":\"FAILED_PRECONDITION\",\"reason\":\"sink_open_after_wait\",\"message\":\"cleanup after delete left resources behind\"}"
        ]
    );
    assert_eq!(op_counts(&rec, "supervisor_log_remove"), Some((0, 1)));
    let _ = std::fs::remove_dir_all(&root);
}

/// REPAIR-5・#2964: 2 つのログの待ちは共有され、独立に待つ場合（2 倍）より短く済む。
#[test]
fn repair5_2964_force_delete_shares_wait_between_both_logs() {
    let root = temp_root("suplog-share");
    let sim = Sim::running_in(root.clone(), "c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGTERM);
    let _writer =
        fandhe_container_supervisor::supervisor_log::open(&root, &cid("c1")).expect("open");
    let _sink = open_log_sink(&root, "c1");
    let rec = Arc::new(OpRecorder::new());
    let rt = force_runtime(&sim, &rec, Duration::from_millis(300));
    let started = Instant::now();
    let resp = rt
        .delete(&DeleteRequest::new(cid("c1")).with_force(true))
        .expect("force delete");
    let elapsed = started.elapsed();
    let kept = CleanupOutcome::Kept {
        code: ErrorCode::FailedPrecondition,
    };
    assert_eq!(resp.supervisor_log(), kept);
    assert_eq!(resp.container_log(), kept);
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(590), "{elapsed:?}");
    let _ = std::fs::remove_dir_all(&root);
}

/// REPAIR-5・#2634・#2760・#3027・#3143: 後始末（ログ 2 件〔待ちは共有〕+ 起動オプション文書の掃除）の最悪は 30 秒で、
/// force delete の stop の予算（22 秒）と、前置きの読み取り 5 秒・core の delete 20 秒を足すと
/// `PLUGIN_FORCE_DELETE_DEADLINE`（47 秒）にちょうど一致する。
///
/// 17 秒は signaler の期限だけを数えた名目で、状態ロックの待ちを含めた stop の厳密な最悪は 42 秒である。
/// 厳密な値のまま前置きと core の delete を足すと 67 秒になり `PLUGIN_RUNTIME_TIMEOUT` を超える（予算を持たせる理由の証跡）。
#[test]
fn repair5_force_delete_worst_case_fits_runtime_timeout() {
    use fandhe_container_core::cgroups::EXEC_SWEEP_DELETE_TIMEOUT;
    use fandhe_container_core::oci_runtime::{KillTimeout, LAUNCHER_REPLY_GRACE};
    use fandhe_container_core::state_store::STATE_LOCK_TIMEOUT;
    use fandhe_container_plugin_cri::adapter::PLUGIN_FORCE_DELETE_DEADLINE;
    use fandhe_container_plugin_cri::supervised::{FORCE_DELETE_STOP_BUDGET, STOP_KILL_WAIT};
    use fandhe_container_supervisor::container_options::store::OPTIONS_REMOVE_TIMEOUT;
    use fandhe_container_supervisor::logs::{
        CONTAINER_LOG_LOCK_WAIT, CONTAINER_LOG_REMOVE_TIMEOUT,
    };
    use fandhe_container_supervisor::supervisor_log::SUPERVISOR_LOG_REMOVE_TIMEOUT;
    // 名目: signaler の期限だけを数えた stop。
    let nominal = (KillTimeout::DEFAULT + LAUNCHER_REPLY_GRACE) * 2 + STOP_KILL_WAIT;
    assert_eq!(nominal, Duration::from_secs(17));
    // 厳密: 入口の読み取り 5 + 送信 11 + 読み取り 5 + 送信 11 + 期限つきの待ち 10。
    let send = STATE_LOCK_TIMEOUT + KillTimeout::DEFAULT + LAUNCHER_REPLY_GRACE;
    assert_eq!(send, Duration::from_secs(11));
    let strict = STATE_LOCK_TIMEOUT
        + send
        + STATE_LOCK_TIMEOUT
        + send
        + (STOP_KILL_WAIT + STATE_LOCK_TIMEOUT);
    assert_eq!(strict, Duration::from_secs(42));
    let core = STATE_LOCK_TIMEOUT * 3 + EXEC_SWEEP_DELETE_TIMEOUT;
    assert_eq!(core, Duration::from_secs(20));
    assert_eq!(strict + STATE_LOCK_TIMEOUT + core, Duration::from_secs(67));
    assert!(strict + STATE_LOCK_TIMEOUT + core > PLUGIN_RUNTIME_TIMEOUT);
    // 予算: 47 - 前置き 5 - core 20 = 22 秒。
    assert_eq!(
        PLUGIN_FORCE_DELETE_DEADLINE - STATE_LOCK_TIMEOUT - core,
        FORCE_DELETE_STOP_BUDGET
    );
    assert_eq!(FORCE_DELETE_STOP_BUDGET, Duration::from_secs(22));
    // ログ 2 件は待ち（CONTAINER_LOG_LOCK_WAIT）を共有する: 共有の待ち + 各ログの最後の試行（#2964）。
    assert_eq!(CONTAINER_LOG_LOCK_WAIT, Duration::from_secs(10));
    let logs =
        CONTAINER_LOG_LOCK_WAIT + SUPERVISOR_LOG_REMOVE_TIMEOUT + CONTAINER_LOG_REMOVE_TIMEOUT;
    assert_eq!(logs, Duration::from_secs(20));
    assert_eq!(OPTIONS_REMOVE_TIMEOUT, Duration::from_secs(10));
    let cleanup = logs + OPTIONS_REMOVE_TIMEOUT;
    assert_eq!(cleanup, Duration::from_secs(30));
    assert_eq!(
        FORCE_DELETE_STOP_BUDGET + STATE_LOCK_TIMEOUT + core,
        PLUGIN_FORCE_DELETE_DEADLINE
    );
    assert_eq!(PLUGIN_FORCE_DELETE_DEADLINE, Duration::from_secs(47));
    assert!(PLUGIN_FORCE_DELETE_DEADLINE < PLUGIN_RUNTIME_TIMEOUT);
}

/// REPAIR-5・CRI-2・#3027・#3143: `RemoveContainer`（running への force delete）の最悪を、core の delete を含めて数える。
/// 数え方の規則は「`StateStore` の呼び出し 1 回につき `STATE_LOCK_TIMEOUT` を 1 回」。後始末の前の合計は
/// 前置きの読み取り 5 + stop の予算 22 + core の delete 20 = 47 秒で、全体の期限（47 秒）に一致し、全体の最悪は期限で決まる。
/// 期限を共有しない場合の合計（77 秒）は `PLUGIN_RUNTIME_TIMEOUT` を超える（採らない形が崩れることの証跡）。
#[test]
fn repair5_cri2_3027_remove_container_worst_case_fits_runtime_timeout() {
    use fandhe_container_core::cgroups::EXEC_SWEEP_DELETE_TIMEOUT;
    use fandhe_container_core::state_store::STATE_LOCK_TIMEOUT;
    use fandhe_container_plugin_cri::adapter::PLUGIN_FORCE_DELETE_DEADLINE;
    use fandhe_container_plugin_cri::supervised::FORCE_DELETE_STOP_BUDGET;
    // stop_live_before_force_delete の状態の読み取り（1 回）。
    let pre_get = STATE_LOCK_TIMEOUT;
    assert_eq!(pre_get, Duration::from_secs(5));
    assert_eq!(FORCE_DELETE_STOP_BUDGET, Duration::from_secs(22));
    // core の delete: get 2 回 + StateStore::delete 1 回 + exec 掃除（oci_runtime::delete の module doc「待ちの上限」）。
    assert_eq!(EXEC_SWEEP_DELETE_TIMEOUT, Duration::from_secs(5));
    let core = STATE_LOCK_TIMEOUT * 3 + EXEC_SWEEP_DELETE_TIMEOUT;
    assert_eq!(core, Duration::from_secs(20));
    let before_cleanup = pre_get + FORCE_DELETE_STOP_BUDGET + core;
    assert_eq!(before_cleanup, Duration::from_secs(47));
    assert_eq!(PLUGIN_FORCE_DELETE_DEADLINE, Duration::from_secs(47));
    // 後始末は期限までの残りで頭打ちなので、全体は max(47, 47) = 47 秒。
    let worst = before_cleanup.max(PLUGIN_FORCE_DELETE_DEADLINE);
    assert_eq!(worst, Duration::from_secs(47));
    assert!(worst < PLUGIN_RUNTIME_TIMEOUT);
    // 期限を共有しない場合（後始末 30 秒をそのまま足す）は収まらない。
    let unshared = before_cleanup + Duration::from_secs(30);
    assert_eq!(unshared, Duration::from_secs(77));
    assert!(unshared > PLUGIN_RUNTIME_TIMEOUT);
}

/// REPAIR-5・#3143: `StopContainer`（予算なしの stop）の厳密な最悪は `grace + 42 秒` で、CRI 側の待ち
/// （`PLUGIN_RUNTIME_TIMEOUT + grace`）に収まる。
#[test]
fn repair5_3143_stop_strict_count_fits_stop_container_timeout() {
    use fandhe_container_core::oci_runtime::{KillTimeout, LAUNCHER_REPLY_GRACE};
    use fandhe_container_core::state_store::STATE_LOCK_TIMEOUT;
    use fandhe_container_plugin_cri::supervised::STOP_KILL_WAIT;
    let send = STATE_LOCK_TIMEOUT + KillTimeout::DEFAULT + LAUNCHER_REPLY_GRACE;
    let strict = STATE_LOCK_TIMEOUT
        + send
        + STATE_LOCK_TIMEOUT
        + send
        + (STOP_KILL_WAIT + STATE_LOCK_TIMEOUT);
    assert_eq!(strict, Duration::from_secs(42));
    for (grace, expect) in [(0u64, 42u64), (30, 72)] {
        let grace = Duration::from_secs(grace);
        assert_eq!(strict + grace, Duration::from_secs(expect));
        assert!(strict + grace < PLUGIN_RUNTIME_TIMEOUT + grace);
    }
}

/// REPAIR-5・#3143: 最悪の分岐（SIGTERM で止まらず SIGKILL で止まる）の stop が `StateStore::get` を 5 回だけ呼ぶ
/// （入口・SIGTERM の core kill・猶予 0 の確認・SIGKILL の core kill・SIGKILL 後の確認）。数え方の規則の照合。
#[test]
fn repair5_3143_force_delete_stop_store_calls_are_bounded() {
    let sim = running("c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGKILL);
    let lifecycle =
        SupervisedLifecycle::new(starter(LONG), Arc::new(SimSignalers(Arc::clone(&sim))));
    let store = SimStore(Arc::clone(&sim));
    let rec = OpRecorder::new();
    let stop = StopRequest::new(cid("c1"), Duration::ZERO).expect("stop");
    let status = lifecycle
        .stop_within(&store, &rec, &stop, Some(Duration::from_secs(22)))
        .expect("stop");
    assert_eq!(status.state(), ContainerState::Stopped);
    assert_eq!(sim.gets.load(Ordering::SeqCst), 5);
    assert_eq!(
        sim.calls(),
        [
            (Kind::Stop, Signal::SIGTERM),
            (Kind::Plain, Signal::SIGKILL)
        ]
    );
}

/// REPAIR-5・#3143: 予算の残りがその段の最悪の所要（送信 11 秒）に満たなければ、その段を始めずに固定文言の `Timeout` で止める。
/// 状態の読み取りに 200ms かかる世界で予算 11.3 秒 → 入口の読み取りと SIGTERM は始められ、SIGKILL は始められない。
#[test]
fn repair5_3143_force_delete_refuses_stop_stage_when_budget_short() {
    let sim = running("c1", 4242);
    sim.get_delay_ms.store(200, Ordering::SeqCst);
    let lifecycle =
        SupervisedLifecycle::new(starter(LONG), Arc::new(SimSignalers(Arc::clone(&sim))));
    let store = SimStore(Arc::clone(&sim));
    let rec = OpRecorder::new();
    let stop = StopRequest::new(cid("c1"), Duration::ZERO).expect("stop");
    let started = Instant::now();
    let err = lifecycle
        .stop_within(&store, &rec, &stop, Some(Duration::from_millis(11_300)))
        .expect_err("budget short");
    assert_eq!(err.code(), ErrorCode::Timeout);
    assert_eq!(
        err.message(),
        "container stop did not fit in the delete budget"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(sim.calls(), [(Kind::Stop, Signal::SIGTERM)]);
    assert_eq!(sim.state(), ContainerState::Running);
}

/// REPAIR-5・CRI-2・SUP-7・#3027: core の delete が長引いて全体の期限までの残りが少ないとき、後始末の各段は残りで
/// 頭打ちになり、期限を大きく超えない（頭打ちが無ければ共有の待ち 3 秒と試行で 3 秒以上かかる）。
/// 消せなかったログは残し（`FailedPrecondition`）、`delete` 自体は `Ok` のまま。
#[test]
fn repair5_cri2_3027_force_delete_cuts_cleanup_at_deadline() {
    let root = temp_root("deadline-cut");
    let sim = Sim::running_in(root.clone(), "c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGTERM);
    sim.delete_delay_ms.store(300, Ordering::SeqCst);
    let _writer =
        fandhe_container_supervisor::supervisor_log::open(&root, &cid("c1")).expect("open");
    let _sink = open_log_sink(&root, "c1");
    let rec = Arc::new(OpRecorder::new());
    let (rt, warnings) = capture_warnings(
        force_runtime(&sim, &rec, Duration::from_secs(3))
            .with_delete_deadline(Duration::from_millis(700)),
    );
    let started = Instant::now();
    let resp = rt
        .delete(&DeleteRequest::new(cid("c1")).with_force(true))
        .expect("force delete");
    let elapsed = started.elapsed();
    let kept = CleanupOutcome::Kept {
        code: ErrorCode::FailedPrecondition,
    };
    assert_eq!(resp.supervisor_log(), kept);
    assert_eq!(resp.container_log(), kept);
    assert!(elapsed >= Duration::from_millis(550), "{elapsed:?}");
    assert!(elapsed < Duration::from_millis(1000), "{elapsed:?}");
    assert_eq!(supervisor_log_names(&root), ["c1.log", "c1.log.lock"]);
    assert_eq!(log_dir_names(&root), ["c1.log", "c1.log.lock"]);
    assert_eq!(warnings.lock().expect("lock").len(), 2);
    drop(_sink);
    let _ = std::fs::remove_dir_all(&root);
}

/// REPAIR-5・CRI-2・REPAIR-4・#3027: core の delete だけで全体の期限を使い切ったときは、後始末の段を試さず
/// `Timeout` として残す（ログは消さない）。警告行は固定語彙の code だけで知らせる。
#[test]
fn repair5_cri2_3027_force_delete_skips_cleanup_when_deadline_exhausted() {
    let root = temp_root("deadline-spent");
    let sim = Sim::running_in(root.clone(), "c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGTERM);
    sim.delete_delay_ms.store(300, Ordering::SeqCst);
    let writer =
        fandhe_container_supervisor::supervisor_log::open(&root, &cid("c1")).expect("open");
    drop(writer);
    let rec = Arc::new(OpRecorder::new());
    let (rt, warnings) = capture_warnings(
        force_runtime(&sim, &rec, Duration::from_secs(3))
            .with_delete_deadline(Duration::from_millis(200)),
    );
    let started = Instant::now();
    let resp = rt
        .delete(&DeleteRequest::new(cid("c1")).with_force(true))
        .expect("force delete");
    assert!(started.elapsed() < Duration::from_millis(800));
    let timeout = CleanupOutcome::Kept {
        code: ErrorCode::Timeout,
    };
    assert_eq!(resp.supervisor_log(), timeout);
    assert_eq!(resp.container_log(), timeout);
    assert_eq!(supervisor_log_names(&root), ["c1.log", "c1.log.lock"]);
    assert_eq!(op_counts(&rec, "supervisor_log_remove"), Some((0, 1)));
    assert_eq!(op_counts(&rec, "container_log_remove"), Some((0, 1)));
    assert_eq!(
        op_counts(&rec, "container_log_remove.timeout"),
        Some((0, 1))
    );
    let lines = warnings.lock().expect("lock").clone();
    for target in ["supervisor_log", "container_log"] {
        let needle = format!("\"target\":\"{target}\",\"code\":\"TIMEOUT\"");
        assert_eq!(
            lines.iter().filter(|l| l.contains(&needle)).count(),
            1,
            "{lines:?}"
        );
    }
    // 試さなかった起動オプション文書の段は、存在を確かめていないことを `existence` で示す（#3143）。
    let options: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("\"target\":\"container_options\""))
        .collect();
    assert_eq!(options.len(), 1, "{lines:?}");
    assert!(
        options[0].contains("\"code\":\"TIMEOUT\",\"existence\":\"unverified\""),
        "{lines:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// SUP-7・CRI-2・SEC-1・#3027・#3143: 同じ ID が再作成済み（guard が偽）のとき、plugin-cri の経路でも supervisor ログを消さない。
/// 結果は `Superseded`（`Removed` と報告しない）で、警告行は出さない。
#[test]
fn sup7_cri2_3027_force_delete_keeps_supervisor_log_when_id_recreated() {
    let root = temp_root("recreated");
    let sim = Sim::running_in(root.clone(), "c1", 4242);
    *sim.stop_on.lock().expect("lock") = Some(Signal::SIGTERM);
    sim.recreate_after_delete.store(true, Ordering::SeqCst);
    let writer =
        fandhe_container_supervisor::supervisor_log::open(&root, &cid("c1")).expect("open");
    drop(writer);
    assert_eq!(supervisor_log_names(&root), ["c1.log", "c1.log.lock"]);
    let rec = Arc::new(OpRecorder::new());
    let (rt, warnings) = capture_warnings(force_runtime(&sim, &rec, Duration::from_millis(200)));
    let resp = rt
        .delete(&DeleteRequest::new(cid("c1")).with_force(true))
        .expect("force delete");
    assert_eq!(sim.deletes.load(Ordering::SeqCst), 1);
    assert_eq!(supervisor_log_names(&root), ["c1.log"]);
    assert_eq!(resp.supervisor_log(), CleanupOutcome::Superseded);
    assert!(warnings.lock().expect("lock").is_empty());
    assert_eq!(op_counts(&rec, "supervisor_log_remove"), Some((1, 0)));
    let _ = std::fs::remove_dir_all(&root);
}

/// REPAIR-5・#2760: `create` の最悪所要（ログ回収 + 起動オプション文書の掃除 + 状態ロック + 監査記録 2 回）は
/// `PLUGIN_RUNTIME_TIMEOUT` に収まる（RPC 側の内訳）。bundle の用意は worker 側の上限
/// （`repair5_create_worker_residual_is_bounded`）で別に示す。
///
/// 状態ロックを 1 回と数えるのは、#3027 の規則（`StateStore` の呼び出し 1 回につき `STATE_LOCK_TIMEOUT` を 1 回）に照らして
/// 正しい（#3143）: create の経路は `lock_for_create`（`try_lock` で待たない）、検証、`StateStore::create` の順で、
/// `StateStore` の呼び出しは 1 回だけ（`tests/adapter.rs` の `repair5_3143_create_calls_state_store_once`）。
/// 回収の guard の `get` は期限つきの作業スレッド（ログ 5 秒・文書 10 秒）の中で評価され、その期限に含まれる。
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

/// REPAIR-5・#2821: `create` の worker の残存は rootfs の期限 + core の create の 42.9 秒で有限になり、RPC の応答は
/// worker を待たず `PLUGIN_RUNTIME_TIMEOUT` で打ち切られる。分割できない区間（blob 1 本の検証・展開全体）は大きさの上限で有界。
#[test]
fn repair5_create_worker_residual_is_bounded() {
    use fandhe_container_cri::image_pull::DEFAULT_MAX_IMAGE_BYTES;
    use fandhe_container_oci::layer::extract::{
        DEFAULT_MAX_EXTRACTED_BYTES, DEFAULT_MAX_LAYER_ENTRIES,
    };
    assert_eq!(PLUGIN_ROOTFS_DEADLINE, Duration::from_secs(600));
    let core_create = Duration::from_millis(42_900);
    assert_eq!(
        PLUGIN_ROOTFS_DEADLINE + core_create,
        Duration::from_millis(642_900)
    );
    assert!(PLUGIN_RUNTIME_TIMEOUT < PLUGIN_ROOTFS_DEADLINE);
    // #2899: RPC の期限切れの後、dispatch 前の worker は取り消しで止まる。dispatch 後は打ち切れず、
    // core の create（42.9 秒）+ 失敗時の削除確認（confirm_removed は PLUGIN_RUNTIME_TIMEOUT まで）で有限になる。
    assert_eq!(
        core_create + PLUGIN_RUNTIME_TIMEOUT,
        Duration::from_millis(103_800)
    );
    assert!(core_create + PLUGIN_RUNTIME_TIMEOUT < PLUGIN_ROOTFS_DEADLINE);
    // #3142: 巻き戻しの release も `PLUGIN_RUNTIME_TIMEOUT` で打ち切られる（従来は上限が無かった）。
    assert_eq!(
        core_create + PLUGIN_RUNTIME_TIMEOUT + PLUGIN_RUNTIME_TIMEOUT,
        Duration::from_millis(164_700)
    );
    assert!(core_create + PLUGIN_RUNTIME_TIMEOUT * 2 < PLUGIN_ROOTFS_DEADLINE);
    assert_eq!(DEFAULT_MAX_IMAGE_BYTES, 16 * 1024 * 1024 * 1024);
    assert_eq!(DEFAULT_MAX_LAYER_ENTRIES, 1_000_000);
    assert_eq!(DEFAULT_MAX_EXTRACTED_BYTES, 8 * 1024 * 1024 * 1024);
}

/// REPAIR-5・CRI-2・#3142: RemovePodSandbox の最悪は pod 単位の合計期限（`PLUGIN_RUNTIME_TIMEOUT` 1 回分）で決まり、
/// 配下の数によらず kubelet の `--runtime-request-timeout` の既定（2 分。`defaults.go`）に収まる。従来の逐次
/// （配下 1 件ごとに `PLUGIN_RUNTIME_TIMEOUT`）は 2 件で既定を超えていた（採らない形が崩れることの証跡）。
#[test]
fn repair5_cri2_3142_remove_pod_sandbox_worst_case_fits_kubelet_timeout() {
    let kubelet_default = Duration::from_secs(120);
    assert_eq!(PLUGIN_RUNTIME_TIMEOUT, Duration::from_millis(60_900));
    // 従来: 2 件の配下で 2 × 60.9 = 121.8 秒。
    let sequential_two = PLUGIN_RUNTIME_TIMEOUT * 2;
    assert_eq!(sequential_two, Duration::from_millis(121_800));
    assert!(sequential_two > kubelet_default);
    // 新: 合計期限 1 回分。余裕は 59.1 秒（同期部分の ε を含めても収まる）。
    assert!(PLUGIN_RUNTIME_TIMEOUT < kubelet_default);
    assert_eq!(
        kubelet_default - PLUGIN_RUNTIME_TIMEOUT,
        Duration::from_millis(59_100)
    );
}

/// REPAIR-5・CRI-2・#3142: RemoveContainer の bundle 解放は RPC と同じ `PLUGIN_RUNTIME_TIMEOUT` の期限を共有する。
/// core の後始末までの最悪（`PLUGIN_FORCE_DELETE_DEADLINE` 47 秒）の残りが解放の取り分で、RPC の期限を超えない。
#[test]
fn repair5_cri2_3142_remove_container_release_within_runtime_timeout() {
    use fandhe_container_plugin_cri::adapter::PLUGIN_FORCE_DELETE_DEADLINE;
    assert_eq!(PLUGIN_FORCE_DELETE_DEADLINE, Duration::from_secs(47));
    assert_eq!(
        PLUGIN_RUNTIME_TIMEOUT - PLUGIN_FORCE_DELETE_DEADLINE,
        Duration::from_millis(13_900)
    );
}
