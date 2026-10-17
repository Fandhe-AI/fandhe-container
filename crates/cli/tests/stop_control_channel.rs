//! `stop` の本番 signaler（supervisor の制御チャネル経由）の結合試験（CLI-1・SEC-1・ERR-2・SUP-1・#2059）。
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
use fandhe_container_core::traits::{ContainerId, Signal, StartRequest, TraitError};
use fandhe_container_supervisor::control::listener::{ControlListener, effective_uid};
use fandhe_container_supervisor::control::observe::ControlObserver;
use fandhe_container_supervisor::control::server::{ControlServer, ServeConfig};
use fandhe_container_supervisor::control::target::{ControlledProcess, SignalSlot};

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

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p =
            std::env::temp_dir().join(format!("fc-cli-stopctl-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
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
    stop: Arc<AtomicBool>,
    monitor: Option<std::thread::JoinHandle<()>>,
    server: Option<ControlServer>,
    listener: Option<ControlListener>,
}

impl FakeSupervisor {
    fn start(root: &Path, id: &ContainerId, pid: u32, with_handle: bool) -> Self {
        let listener = ControlListener::bind(root, id).unwrap();
        let slot = SignalSlot::new();
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
    assert_eq!(ex.exit_code(), 0);
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
