//! `stop`・`kill` の本番 signaler（supervisor の制御チャネル経由）の結合試験（CLI-1・#1902・SEC-1・ERR-2・SUP-1・SUP-9・SUP-3・#2059・#2162・#2440）。
//!
//! 本番入口 `commands::run_to` から、フェイクの supervisor（`ControlServer` と模擬の起動ハンドル）の UDS までを
//! 実際に通し、終了コードと stderr の JSON を具体値で照合する。root・実コンテナは不要で既定のテスト集合で動く。
//! 別 uid の接続元の拒否は第 2 の uid が要るため、supervisor 側の `sec1_peer_with_other_uid_is_disconnected_without_a_byte`
//! と `peer_allowed` の単体テストが担う。期限切れ（TIMEOUT）は 5 秒の既定期限を避け、cli の単体テスト
//! （`err2_stop_with_silent_supervisor_times_out`）が担う。状態ディレクトリが 0700 でない場合は core の `get` が
//! 先に拒否するため（PERMISSION_DENIED）、`ControlSignaler` 側の同検証は supervisor の `client` の試験が担う。

#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_cli::commands::run_to;
use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, StartTimeouts, StartedContainer,
    start,
};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, GetStateRequest, Signal, StartRequest, StateStore, TraitError,
    UpdateStateRequest,
};
use fandhe_container_supervisor::control::listener::{ControlListener, effective_uid};
use fandhe_container_supervisor::control::observe::ControlObserver;
use fandhe_container_supervisor::control::server::{ControlServer, ServeConfig};
use fandhe_container_supervisor::control::target::{ControlledProcess, SignalSlot};
use fandhe_container_supervisor::run::{ExplicitStopState, StopToken};

/// 送られたシグナル番号を記録する模擬の起動ハンドル（supervisor が保持する側）。
struct Fake {
    pid: u32,
    signals: Arc<Mutex<Vec<u8>>>,
}

impl LaunchedProcess for Fake {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(self.pid).unwrap()
    }
    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        std::thread::sleep(timeout.min(Duration::from_millis(5)));
        Ok(None)
    }
    fn terminate(&self, _t: Duration) -> Result<(), TraitError> {
        Ok(())
    }
    fn signal(&self, signal: Signal, _d: Instant) -> Result<(), TraitError> {
        self.signals.lock().unwrap().push(signal.as_u8());
        Ok(())
    }
}

/// 最初の `wait` で終了を返す模擬の起動ハンドル（スロットを `Exited` にする。バックオフ中の supervisor に相当）。
struct ExitedFake(u32);

impl LaunchedProcess for ExitedFake {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(self.0).unwrap()
    }
    fn wait(&self, _timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        Ok(Some(ProcessExit::Exited(1)))
    }
    fn terminate(&self, _t: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

/// core の start に pid を記録させるための起動役（CLI 側から見える pid）。
struct PidLauncher(u32);

struct PidProcess(u32);

impl LaunchedProcess for PidProcess {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(self.0).unwrap()
    }
    fn wait(&self, _t: Duration) -> Result<Option<ProcessExit>, TraitError> {
        Ok(None)
    }
    fn terminate(&self, _t: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

impl ProcessLauncher for PidLauncher {
    fn launch(
        &self,
        _s: &LaunchSpec,
        _t: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        Ok(Box::new(PidProcess(self.0)))
    }
}

// 一時領域の親を tmpfiles の flock 走査から守る共有部品（#3026・CORE-5・REPAIR-12）。
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

/// 第 2 フィールドは tmpfiles の flock 走査から守る親（最後のため `Drop` の削除の後に消える。#3026）。
struct Tmp(
    PathBuf,
    #[allow(dead_code)] scratch_root::ScratchDir, // 保持が目的（drop で親を消す）
);

impl Tmp {
    fn new(tag: &str) -> Self {
        let scratch =
            scratch_root::ScratchDir::new("fc-cli-stopctl", std::time::Duration::from_secs(10));
        // 制御用 UDS のパス長を抑えるため子の名前は短くする。
        let p = scratch.path().join(tag);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(p, scratch)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// フェイクの supervisor（制御チャネルのサーバと監視役）。Drop で止める。
struct FakeSupervisor {
    signals: Arc<Mutex<Vec<u8>>>,
    /// stop の意図の書き先（restart の判定に渡すトークンに当たる）。
    intent: StopToken,
    stop: Arc<AtomicBool>,
    monitor: Option<std::thread::JoinHandle<()>>,
    server: Option<ControlServer>,
    listener: Option<ControlListener>,
}

impl FakeSupervisor {
    fn start(root: &Path, id: &ContainerId, pid: u32, with_handle: bool) -> Self {
        Self::start_with(root, id, pid, with_handle, true)
    }

    /// `with_intent_sink` が false なら、stop の意図の書き先を持たない supervisor（古い版に相当）。
    fn start_with(
        root: &Path,
        id: &ContainerId,
        pid: u32,
        with_handle: bool,
        with_intent_sink: bool,
    ) -> Self {
        let listener = ControlListener::bind(root, id).unwrap();
        let intent = StopToken::new();
        let slot = if with_intent_sink {
            SignalSlot::with_stop_intent(intent.clone())
        } else {
            SignalSlot::new()
        };
        let signals = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let monitor = with_handle.then(|| {
            let p = ControlledProcess::new(
                Box::new(Fake {
                    pid,
                    signals: Arc::clone(&signals),
                }),
                slot.clone(),
            );
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let _ = p.wait(Duration::from_millis(100));
                }
            })
        });
        let server = ControlServer::spawn(
            listener.try_clone_listener().unwrap(),
            slot,
            effective_uid().unwrap(),
            ServeConfig::default(),
            Arc::new(ControlObserver::new(None, None)),
        )
        .unwrap();
        Self {
            signals,
            intent,
            stop,
            monitor,
            server: Some(server),
            listener: Some(listener),
        }
    }

    /// 起動ハンドルが既に終了している supervisor（バックオフ中・再 launch 中。スロットは `Exited`）。
    fn start_exited(root: &Path, id: &ContainerId, pid: u32) -> Self {
        let listener = ControlListener::bind(root, id).unwrap();
        let intent = StopToken::new();
        let slot = SignalSlot::with_stop_intent(intent.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let p = ControlledProcess::new(Box::new(ExitedFake(pid)), slot.clone());
        let monitor = Some({
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let _ = p.wait(Duration::from_millis(100));
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
        });
        let server = ControlServer::spawn(
            listener.try_clone_listener().unwrap(),
            slot,
            effective_uid().unwrap(),
            ServeConfig::default(),
            Arc::new(ControlObserver::new(None, None)),
        )
        .unwrap();
        Self {
            signals: Arc::new(Mutex::new(Vec::new())),
            intent,
            stop,
            monitor,
            server: Some(server),
            listener: Some(listener),
        }
    }

    fn recorded(&self) -> Vec<u8> {
        self.signals.lock().unwrap().clone()
    }
}

impl Drop for FakeSupervisor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(m) = self.monitor.take() {
            let _ = m.join();
        }
        drop(self.server.take());
        drop(self.listener.take());
    }
}

struct Env {
    _tmp: Tmp,
    root: PathBuf,
    id: ContainerId,
    _started: StartedContainer,
}

fn argv(root: &Path, rest: &[&str]) -> Vec<OsString> {
    let mut v: Vec<OsString> = vec!["--root".into(), root.into()];
    v.extend(rest.iter().map(OsString::from));
    v
}

/// create → core の start（pid を `pid` に記録）まで進める。
fn running_container(tag: &str, pid: u32) -> Env {
    let tmp = Tmp::new(tag);
    let root = tmp.0.join("state");
    let bundle = tmp.0.join("bundle");
    std::fs::create_dir_all(bundle.join("rootfs")).unwrap();
    std::fs::write(
        bundle.join("config.json"),
        r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
    )
    .unwrap();
    let mut out = Vec::new();
    let ex = run_to(
        argv(
            &root,
            &["create", "--bundle", bundle.to_str().unwrap(), tag],
        ),
        &mut out,
    );
    // 失敗時の原因（TIMEOUT か ResourceExhausted か等）を見分けられるよう stderr を assert の文言へ含める（#2834）。
    let mut err = Vec::new();
    ex.write_stderr(&mut err).unwrap();
    assert_eq!(
        ex.exit_code(),
        0,
        "create failed: {}",
        String::from_utf8_lossy(&err)
    );
    let id = ContainerId::new(tag).unwrap();
    let store = FileStateStore::open(StateRoot::from_override(root.clone()).unwrap()).unwrap();
    let launcher: Arc<dyn ProcessLauncher> = Arc::new(PidLauncher(pid));
    let started = start(
        &store,
        &OpRecorder::new(),
        &launcher,
        &StartRequest::new(id.clone()),
        &StartTimeouts::default(),
    )
    .unwrap();
    Env {
        root,
        id,
        _tmp: tmp,
        _started: started,
    }
}

fn open_store(env: &Env) -> FileStateStore {
    FileStateStore::open(StateRoot::from_override(env.root.clone()).unwrap()).unwrap()
}

/// 記録を `Stopped`（終了コード 1）にする（終了を検知した後のバックオフ中の記録に相当）。
fn mark_stopped(env: &Env) {
    let store = open_store(env);
    let rec = store.get(&GetStateRequest::new(env.id.clone())).unwrap();
    store
        .update(&UpdateStateRequest::new(
            ContainerStatus::stopped(env.id.clone(), Some(1)),
            rec.revision(),
        ))
        .unwrap();
}

fn stop(env: &Env) -> (u8, String, String) {
    let mut out = Vec::new();
    let ex = run_to(argv(&env.root, &["stop", env.id.as_str()]), &mut out);
    let mut err = Vec::new();
    ex.write_stderr(&mut err).unwrap();
    (
        ex.exit_code(),
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn stop_with_signal(env: &Env, signal: &str) -> (u8, String, String) {
    let mut out = Vec::new();
    let ex = run_to(
        argv(&env.root, &["stop", "--signal", signal, env.id.as_str()]),
        &mut out,
    );
    let mut err = Vec::new();
    ex.write_stderr(&mut err).unwrap();
    (
        ex.exit_code(),
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn kill_cmd(env: &Env, extra: &[&str]) -> (u8, String, String) {
    let mut rest = vec!["kill", env.id.as_str()];
    rest.extend_from_slice(extra);
    let mut out = Vec::new();
    let ex = run_to(argv(&env.root, &rest), &mut out);
    let mut err = Vec::new();
    ex.write_stderr(&mut err).unwrap();
    (
        ex.exit_code(),
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn err_line(code: &str, message: &str) -> String {
    format!("{{\"op\":\"kill\",\"code\":\"{code}\",\"message\":\"{message}\"}}\n")
}

/// CLI-1・SEC-1: pid が一致すれば SIGTERM（15）が supervisor の起動ハンドルへ届き、成功（0・出力なし）。
#[test]
fn cli1_sec1_stop_delivers_sigterm_via_supervisor() {
    let env = running_container("stopok", 4242);
    let sup = FakeSupervisor::start(&env.root, &env.id, 4242, true);
    let (code, out, err) = stop(&env);
    assert_eq!((code, out.as_str(), err.as_str()), (0, "", ""));
    assert_eq!(sup.recorded(), vec![15]);
    // SUP-9: stop は意図を記録してから送る（監視の打ち切りではない）。
    assert_eq!(
        sup.intent.explicit_stop_state(),
        ExplicitStopState::Requested
    );
    assert!(!sup.intent.is_stop_requested());
}

/// CLI-1・SEC-1(#2775): `--signal SIGKILL` は番号 9 が supervisor の起動ハンドルへ 1 回だけ届く(意図の記録は SIGTERM と同じ)。
#[test]
fn cli1_stop_signal_delivers_the_requested_number_via_supervisor() {
    let env = running_container("stopsig", 4243);
    let sup = FakeSupervisor::start(&env.root, &env.id, 4243, true);
    let (code, out, err) = stop_with_signal(&env, "SIGKILL");
    assert_eq!((code, out.as_str(), err.as_str()), (0, "", ""));
    assert_eq!(sup.recorded(), vec![9]);
}

/// CLI-1・ERR-1(#2775): 不正な `--signal` は INVALID_ARGUMENT(2)で、supervisor には何も届かない。
#[test]
fn cli1_stop_invalid_signal_is_rejected_before_any_delivery() {
    let env = running_container("stopbadsig", 4244);
    let sup = FakeSupervisor::start(&env.root, &env.id, 4244, true);
    for bad in ["BOGUS", "65", "32", ""] {
        let (code, out, err) = stop_with_signal(&env, bad);
        assert_eq!(code, 2, "{bad}");
        assert_eq!(out, "");
        assert_eq!(
            err,
            err_line("INVALID_ARGUMENT", "signal is invalid"),
            "{bad}"
        );
    }
    assert_eq!(sup.recorded(), Vec::<u8>::new());
}

/// CLI-1・SEC-1・#1902: `kill <id>` は SIGTERM（15）を 1 回送り、stop と違って明示 stop の意図は立てない（kind 2）。
#[test]
fn cli1_sec1_kill_delivers_sigterm_by_default_via_supervisor() {
    let env = running_container("killok", 4250);
    let sup = FakeSupervisor::start(&env.root, &env.id, 4250, true);
    let (code, out, err) = kill_cmd(&env, &[]);
    assert_eq!((code, out.as_str(), err.as_str()), (0, "", ""));
    assert_eq!(sup.recorded(), vec![15]);
    assert_eq!(
        sup.intent.explicit_stop_state(),
        ExplicitStopState::NotRequested
    );
}

/// CLI-1・#1902: 指定した名前・番号がそのまま 1 回だけ届き、意図は立たない。
#[test]
fn cli1_kill_delivers_requested_signal_via_supervisor() {
    for (tag, sig, want) in [("killnine", "KILL", 9u8), ("killten", "10", 10)] {
        let env = running_container(tag, 4251);
        let sup = FakeSupervisor::start(&env.root, &env.id, 4251, true);
        let (code, out, err) = kill_cmd(&env, &[sig]);
        assert_eq!((code, out.as_str(), err.as_str()), (0, "", ""), "{sig}");
        assert_eq!(sup.recorded(), vec![want], "{sig}");
        assert_eq!(
            sup.intent.explicit_stop_state(),
            ExplicitStopState::NotRequested
        );
    }
}

/// CLI-1・ERR-1・#1902: 不正なシグナルは INVALID_ARGUMENT（2）で、supervisor には何も届かない。
#[test]
fn cli1_kill_invalid_signal_is_rejected_before_any_delivery() {
    let env = running_container("killbadsig", 4252);
    let sup = FakeSupervisor::start(&env.root, &env.id, 4252, true);
    for bad in ["BOGUS", "term", "RTMIN+1", ""] {
        let (code, out, err) = kill_cmd(&env, &[bad]);
        assert_eq!(code, 2, "{bad}");
        assert_eq!(out, "");
        assert_eq!(
            err,
            err_line("INVALID_ARGUMENT", "signal is invalid"),
            "{bad}"
        );
    }
    // 範囲外の番号は core の `Signal::new` が固定文言で拒否する。
    let (code, _out, err) = kill_cmd(&env, &["65"]);
    assert_eq!(code, 2);
    assert_eq!(
        err,
        err_line("INVALID_ARGUMENT", "signal number must be in 1..=64")
    );
    assert_eq!(sup.recorded(), Vec::<u8>::new());
}

/// SEC-1・ERR-2・#1902: supervisor が無ければ UNAVAILABLE（9）で、pid へ kill(2) で縮退しない。
#[test]
fn sec1_err2_kill_without_supervisor_is_unavailable_and_does_not_kill() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let env = running_container("killnosup", child.id());
    let (code, _out, err) = kill_cmd(&env, &[]);
    let alive = child.try_wait().unwrap().is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(code, 9);
    assert_eq!(
        err,
        err_line(
            "UNAVAILABLE",
            "the supervisor control channel is unavailable"
        )
    );
    assert!(alive, "kill must not fall back to kill(2)");
}

/// SUP-9・ERR-2: 意図を記録できない supervisor には SIGTERM を送らず、FAILED_PRECONDITION（5）で失敗する。
#[test]
fn sup9_err2_stop_without_intent_sink_fails_closed_and_sends_nothing() {
    let env = running_container("stopnosink", 4242);
    let sup = FakeSupervisor::start_with(&env.root, &env.id, 4242, true, false);
    let (code, out, err) = stop(&env);
    assert_eq!(code, 5);
    assert_eq!(out, "");
    assert_eq!(
        err,
        err_line(
            "FAILED_PRECONDITION",
            "the supervisor cannot record the stop intent"
        )
    );
    assert!(sup.recorded().is_empty());
    assert_eq!(
        sup.intent.explicit_stop_state(),
        ExplicitStopState::NotRequested
    );
}

/// SEC-1・ERR-2: supervisor が無ければ UNAVAILABLE（9）で失敗し、pid へ kill(2) で縮退しない。
#[test]
fn sec1_err2_stop_without_supervisor_is_unavailable_and_does_not_kill() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let env = running_container("stopnosup", child.id());
    let (code, _out, err) = stop(&env);
    let alive = child.try_wait().unwrap().is_none();
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(code, 9);
    assert_eq!(
        err,
        err_line(
            "UNAVAILABLE",
            "the supervisor control channel is unavailable"
        )
    );
    assert!(alive, "stop must not fall back to kill(2)");
}

/// SEC-1・ERR-2: pid 不一致は FAILED_PRECONDITION（5）で、シグナルは送られない。
#[test]
fn sec1_err2_stop_pid_mismatch_is_failed_precondition() {
    let env = running_container("stopmis", 4242);
    let sup = FakeSupervisor::start(&env.root, &env.id, 4243, true);
    let (code, _out, err) = stop(&env);
    assert_eq!(code, 5);
    assert_eq!(
        err,
        err_line(
            "FAILED_PRECONDITION",
            "the process id does not match the launched process"
        )
    );
    assert!(sup.recorded().is_empty());
}

/// SUP-1・ERR-2: supervisor が起動ハンドルを保持していなければ FAILED_PRECONDITION（5）。
#[test]
fn sup1_err2_stop_without_handle_is_failed_precondition() {
    let env = running_container("stopnohd", 4242);
    let _sup = FakeSupervisor::start(&env.root, &env.id, 4242, false);
    let (code, _out, err) = stop(&env);
    assert_eq!(code, 5);
    assert_eq!(
        err,
        err_line(
            "FAILED_PRECONDITION",
            "the supervisor holds no launched process"
        )
    );
}
/// SUP-9・SUP-3・CLI-1・#2440: 記録が `Stopped`（バックオフ中）で supervisor のスロットが `Exited` なら、`stop` は
/// 保留中の再起動の取り消しを依頼して成功する（0・出力なし）。supervisor には明示 stop の意図が立ち、シグナルは送られない。
#[test]
fn sup9_sup3_stop_in_backoff_cancels_pending_restart() {
    let env = running_container("stopbackoff", 4242);
    mark_stopped(&env);
    let sup = FakeSupervisor::start_exited(&env.root, &env.id, 4242);
    let (code, out, err) = stop(&env);
    assert_eq!((code, out.as_str(), err.as_str()), (0, "", ""));
    assert_eq!(
        sup.intent.explicit_stop_state(),
        ExplicitStopState::Requested
    );
    assert!(!sup.intent.is_stop_requested());
    assert!(sup.recorded().is_empty());
}

/// SUP-9・ERR-2・#2440: 記録が `Stopped` で届く supervisor が無ければ、従来どおり core の `kill` が
/// FAILED_PRECONDITION（5）`container is not running` で失敗する（取り消しの導入で挙動を変えない）。
#[test]
fn sup9_err2_stop_of_stopped_container_without_supervisor_keeps_not_running_error() {
    let env = running_container("stopstopped", 4242);
    mark_stopped(&env);
    let (code, out, err) = stop(&env);
    assert_eq!(code, 5);
    assert_eq!(out, "");
    assert_eq!(
        err,
        err_line("FAILED_PRECONDITION", "container is not running")
    );
}

/// SUP-9・SUP-3・#2440: 取り消しの時点で新しいプロセスが動いていた（スロットが `Active`）場合は、記録を読み直し、
/// `Running` になったら通常の stop（StopRequest）をやり直す。シグナル 15 が 1 回だけ届き、成功する。
#[test]
fn sup9_sup3_stop_retries_as_plain_stop_when_the_container_is_running_again() {
    let env = running_container("stoprerun", 4242);
    mark_stopped(&env);
    let sup = FakeSupervisor::start(&env.root, &env.id, 4242, true);
    let root = env.root.clone();
    let id = env.id.clone();
    let flip = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        let store = FileStateStore::open(StateRoot::from_override(root).unwrap()).unwrap();
        let rec = store.get(&GetStateRequest::new(id.clone())).unwrap();
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id, NonZeroU32::new(4242)),
                rec.revision(),
            ))
            .unwrap();
    });
    let (code, out, err) = stop(&env);
    flip.join().unwrap();
    assert_eq!((code, out.as_str(), err.as_str()), (0, "", ""));
    assert_eq!(sup.recorded(), vec![15]);
    assert_eq!(
        sup.intent.explicit_stop_state(),
        ExplicitStopState::Requested
    );
}
