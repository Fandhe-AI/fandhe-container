//! 制御チャネル（supervisor の UDS）の結合試験（SUP-1・SEC-1・REPAIR-2・REPAIR-5・#2058）。
//!
//! 実際の UDS の上で、`ControlSignaler`（クライアント入口）→ `ControlServer` → `ControlledProcess`（監視役の
//! `wait`）→ 模擬の起動ハンドルまでを通す。root・実コンテナは不要で、既定のテスト集合で動く。
//! 模擬ハンドルは送られたシグナル番号を記録し、具体値で照合する。

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit, ProcessSignaler};
use fandhe_container_core::traits::{ContainerId, ErrorCode, Signal, TraitError};
use fandhe_container_supervisor::control::listener::{
    CONTROL_SOCKET_NAME, ControlListener, effective_uid,
};
use fandhe_container_supervisor::control::protocol::{
    ControlReason, HEADER_LEN, RESPONSE_LEN, ResponseFrame,
};
use fandhe_container_supervisor::control::server::{
    ControlServer, PeerCred, ServeConfig, peer_allowed, serve_connection,
};
use fandhe_container_supervisor::control::target::{ControlledProcess, SignalSlot};
use fandhe_container_supervisor::control::{ControlSignaler, install};
use fandhe_container_supervisor::restart::Relauncher;
use fandhe_container_supervisor::run::StopToken;
use fandhe_container_supervisor::start_entry::Running;

const PID: u32 = 4321;

/// 送られたシグナル番号を記録する模擬の起動ハンドル。
struct Fake {
    signals: Arc<Mutex<Vec<u8>>>,
    exited: Arc<AtomicBool>,
}

impl LaunchedProcess for Fake {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(PID).unwrap()
    }
    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        if self.exited.load(Ordering::SeqCst) {
            return Ok(Some(ProcessExit::Exited(0)));
        }
        std::thread::sleep(timeout.min(Duration::from_millis(5)));
        Ok(None)
    }
    fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
        self.exited.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn signal(&self, signal: Signal, _deadline: Instant) -> Result<(), TraitError> {
        if self.exited.load(Ordering::SeqCst) {
            return Err(TraitError::new(ErrorCode::FailedPrecondition, "reaped"));
        }
        self.signals.lock().unwrap().push(signal.as_u8());
        Ok(())
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("fc-ctl-it-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 起動した制御チャネル一式（監視役のスレッドを含む）。
struct Rig {
    _root: TempRoot,
    root_path: PathBuf,
    id: ContainerId,
    signals: Arc<Mutex<Vec<u8>>>,
    exited: Arc<AtomicBool>,
    stop_monitor: Arc<AtomicBool>,
    monitor: Option<std::thread::JoinHandle<()>>,
    server: Option<ControlServer>,
    listener: Option<ControlListener>,
}

impl Rig {
    /// `with_process` が偽なら起動ハンドルを登録しない（スロットは空）。`run_monitor` が偽なら監視役を回さない。
    fn start(tag: &str, with_process: bool, run_monitor: bool, config: ServeConfig) -> Self {
        let root = TempRoot::new(tag);
        let dir = root.0.join(tag);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let id = ContainerId::new(tag).unwrap();
        let listener = ControlListener::bind(&root.0, &id).unwrap();
        let slot = SignalSlot::new();
        let signals = Arc::new(Mutex::new(Vec::new()));
        let exited = Arc::new(AtomicBool::new(false));
        let stop_monitor = Arc::new(AtomicBool::new(false));
        let process = with_process.then(|| {
            ControlledProcess::new(
                Box::new(Fake {
                    signals: Arc::clone(&signals),
                    exited: Arc::clone(&exited),
                }),
                slot.clone(),
            )
        });
        let monitor = process.map(|p| (p, run_monitor)).map(|(p, run)| {
            let stop = Arc::clone(&stop_monitor);
            if run {
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        let _ = p.wait(Duration::from_millis(100));
                    }
                })
            } else {
                // 監視役が wait を呼ばない状態を作る（ハンドルは保持したまま止まっている）。
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    // 停止後に 1 回だけ回す（期限切れの要求が送られないことの確認用）。
                    let _ = p.wait(Duration::from_millis(1));
                })
            }
        });
        let server = ControlServer::spawn(
            listener.try_clone_listener().unwrap(),
            slot.clone(),
            effective_uid().unwrap(),
            config,
        )
        .unwrap();
        Self {
            root_path: root.0.clone(),
            _root: root,
            id,
            signals,
            exited,
            stop_monitor,
            monitor,
            server: Some(server),
            listener: Some(listener),
        }
    }

    fn signaler(&self) -> ControlSignaler {
        ControlSignaler::new(self.root_path.clone())
    }

    fn signal(&self, pid: u32, sig: u8, within: Duration) -> Result<(), TraitError> {
        self.signaler().signal(
            &self.id,
            NonZeroU32::new(pid).unwrap(),
            Signal::new(sig).unwrap(),
            Instant::now() + within,
        )
    }

    fn recorded(&self) -> Vec<u8> {
        self.signals.lock().unwrap().clone()
    }

    fn socket(&self) -> PathBuf {
        self.root_path
            .join(self.id.as_str())
            .join(CONTROL_SOCKET_NAME)
    }

    fn finish(&mut self) {
        self.stop_monitor.store(true, Ordering::SeqCst);
        if let Some(m) = self.monitor.take() {
            m.join().unwrap();
        }
        drop(self.server.take());
        drop(self.listener.take());
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.finish();
    }
}

/// SUP-1・SEC-1: 正常系。pid が一致すればシグナル 15 が起動ハンドルへ届く（番号は具体値で照合）。
#[test]
fn sup1_sec1_signal_is_delivered_to_the_launched_process() {
    let rig = Rig::start("normal", true, true, ServeConfig::default());
    rig.signal(PID, 15, Duration::from_secs(2)).unwrap();
    assert_eq!(rig.recorded(), vec![15]);
    rig.signal(PID, 9, Duration::from_secs(2)).unwrap();
    assert_eq!(rig.recorded(), vec![15, 9]);
}

/// SUP-1・SEC-1: pid 不一致は送らず、固定文言の FAILED_PRECONDITION を返す。
#[test]
fn sup1_sec1_pid_mismatch_is_rejected_without_signal() {
    let rig = Rig::start("pidmis", true, true, ServeConfig::default());
    let e = rig.signal(PID + 1, 15, Duration::from_secs(2)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        e.message(),
        "the process id does not match the launched process"
    );
    assert!(rig.recorded().is_empty());
}

/// SUP-1: ハンドルが無い（スロットが空）ときと、終了済みのときの構造化エラー。
#[test]
fn sup1_no_handle_and_exited_are_failed_precondition() {
    let rig = Rig::start("nohandle", false, false, ServeConfig::default());
    let e = rig.signal(PID, 15, Duration::from_secs(2)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "the supervisor holds no launched process");

    let rig = Rig::start("exited", true, true, ServeConfig::default());
    rig.exited.store(true, Ordering::SeqCst);
    // 監視役が終了を検知してスロットが Exited になるまで待つ。
    let deadline = Instant::now() + Duration::from_secs(3);
    let e = loop {
        let e = rig.signal(PID, 15, Duration::from_secs(1)).unwrap_err();
        if e.message() == "the container process has already exited" || Instant::now() > deadline {
            break e;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "the container process has already exited");
    assert!(rig.recorded().is_empty());
}

/// SEC-1: 別 uid 相当の接続は、何も書かずに切断する（Hello も送らない）。
#[test]
fn sec1_peer_with_other_uid_is_disconnected_without_a_byte() {
    assert!(!peer_allowed(1000, 1001));
    assert!(peer_allowed(1000, 1000));

    let euid = effective_uid().unwrap();
    let slot = SignalSlot::new();
    let (mut client, server_side) = UnixStream::pair().unwrap();
    let handle = std::thread::spawn(move || {
        let peer = PeerCred {
            pid: 1,
            uid: euid.wrapping_add(1),
            gid: 0,
        };
        serve_connection(server_side, peer, euid, &slot, &ServeConfig::default());
    });
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(client.read(&mut buf).unwrap(), 0, "expected EOF");
    handle.join().unwrap();
}

/// REPAIR-2・SEC-1: 長すぎる要求（payload_len = 4096）は payload を読まずに TooLarge で拒否する。
#[test]
fn repair2_sec1_oversized_request_is_rejected_with_too_large() {
    let rig = Rig::start("toolarge", true, true, ServeConfig::default());
    let mut s = UnixStream::connect(rig.socket()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut hello = [0u8; HEADER_LEN];
    s.read_exact(&mut hello).unwrap();
    assert_eq!(hello, [b'F', b'C', b'S', b'C', 1, 1, 0, 0]);
    // magic・version・kind(2) は正しく、payload_len だけ 4096。
    s.write_all(&[b'F', b'C', b'S', b'C', 1, 2, 0x10, 0x00])
        .unwrap();
    let mut resp = [0u8; RESPONSE_LEN];
    s.read_exact(&mut resp).unwrap();
    assert_eq!(resp, [b'F', b'C', b'S', b'C', 1, 3, 0, 1, 7]);
    let mut rest = [0u8; 1];
    assert_eq!(s.read(&mut rest).unwrap(), 0, "connection must be closed");
    assert!(rig.recorded().is_empty());
}

/// REPAIR-5: 期限切れ (a) 要求を送ってこないクライアントは、読み取り期限で切られる。
#[test]
fn repair5_silent_client_is_cut_off_at_the_read_deadline() {
    let config = ServeConfig {
        read_deadline: Duration::from_millis(50),
        ..ServeConfig::default()
    };
    let rig = Rig::start("silent", true, true, config);
    let mut s = UnixStream::connect(rig.socket()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut hello = [0u8; HEADER_LEN];
    s.read_exact(&mut hello).unwrap();
    let started = Instant::now();
    let mut resp = [0u8; RESPONSE_LEN];
    s.read_exact(&mut resp).unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        ResponseFrame::decode_payload(&[resp[RESPONSE_LEN - 1]]).reason,
        ControlReason::Malformed
    );
    assert!(rig.recorded().is_empty());
}

/// REPAIR-5: 期限切れ (b) クライアントの期限がすでに過ぎていれば接続せず TIMEOUT。
#[test]
fn repair5_expired_deadline_returns_timeout_without_connecting() {
    let rig = Rig::start("expired", true, true, ServeConfig::default());
    let e = rig
        .signaler()
        .signal(
            &rig.id,
            NonZeroU32::new(PID).unwrap(),
            Signal::SIGTERM,
            Instant::now(),
        )
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert!(rig.recorded().is_empty());
}

/// REPAIR-5・SEC-1: 期限切れ (c) 監視役が wait を呼ばないまま期限が過ぎたら TIMEOUT で、
/// その後に wait を回してもシグナルは届かない。
#[test]
fn repair5_sec1_signal_is_not_delivered_after_the_deadline() {
    let mut rig = Rig::start("late", true, false, ServeConfig::default());
    let e = rig.signal(PID, 15, Duration::from_millis(300)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Timeout);
    // 監視役を再開させる（停止要求後に 1 回だけ wait を回す）。
    rig.finish();
    assert!(rig.recorded().is_empty());
}

/// 起動のたびに失敗する relauncher（install の結線の試験用）。
struct NoRelaunch;

impl Relauncher for NoRelaunch {
    fn relaunch(&self, _timeout: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "no relaunch"))
    }
}

fn running_with(fake: Fake) -> Running {
    Running {
        process: Box::new(fake),
        relauncher: Arc::new(NoRelaunch),
        instance: None,
        logs: None,
    }
}

/// SUP-1・SEC-1: `install` が起動ハンドルを包み、監視役の wait 経由でシグナル 15 が届く。
/// ハンドルを落とすとソケットが消え、停止は要求されない。
#[test]
fn sup1_sec1_install_wires_process_and_cleans_up() {
    let root = TempRoot::new("install");
    let dir = root.0.join("inst");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let id = ContainerId::new("inst").unwrap();
    let signals = Arc::new(Mutex::new(Vec::new()));
    let fake = Fake {
        signals: Arc::clone(&signals),
        exited: Arc::new(AtomicBool::new(false)),
    };
    let stop = StopToken::new();
    let (running, handle) = install(&root.0, &id, running_with(fake), &stop);
    assert!(!stop.is_stop_requested());
    let process = running.process;
    let done = Arc::new(AtomicBool::new(false));
    let monitor = {
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let _ = process.wait(Duration::from_millis(100));
            }
        })
    };
    ControlSignaler::new(root.0.clone())
        .signal(
            &id,
            NonZeroU32::new(PID).unwrap(),
            Signal::new(15).unwrap(),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
    assert_eq!(*signals.lock().unwrap(), vec![15]);
    done.store(true, Ordering::SeqCst);
    monitor.join().unwrap();
    drop(handle);
    assert!(std::fs::symlink_metadata(dir.join(CONTROL_SOCKET_NAME)).is_err());
}

/// SEC-1・SUP-1: 作成に失敗（状態ディレクトリが緩い）したら、停止できないコンテナを残さず停止を要求する。
#[test]
fn sec1_install_failure_requests_stop_fail_closed() {
    let root = TempRoot::new("installfail");
    let dir = root.0.join("loose");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let id = ContainerId::new("loose").unwrap();
    let fake = Fake {
        signals: Arc::new(Mutex::new(Vec::new())),
        exited: Arc::new(AtomicBool::new(false)),
    };
    let stop = StopToken::new();
    let (_running, _handle) = install(&root.0, &id, running_with(fake), &stop);
    assert!(stop.is_stop_requested());
    assert!(std::fs::symlink_metadata(dir.join(CONTROL_SOCKET_NAME)).is_err());
}

/// SUP-1: ハンドル保持側が終わる（`ControlHandle` の drop 相当）とソケットが消える。
#[test]
fn sup1_socket_is_removed_when_the_channel_is_dropped() {
    let mut rig = Rig::start("cleanup", true, true, ServeConfig::default());
    assert!(std::fs::symlink_metadata(rig.socket()).is_ok());
    rig.finish();
    assert!(std::fs::symlink_metadata(rig.socket()).is_err());
}
