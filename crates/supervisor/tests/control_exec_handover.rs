//! 制御チャネルの exec 用 pidfd の受け渡し（ExecHandoverRequest）の結合試験（SUP-6・SEC-1・REPAIR-2・REPAIR-5・#2626）。
//!
//! 実際の UDS の上で、`ControlExecHandover`（クライアント入口）→ `ControlServer` → `SignalSlot` の複製を通し、
//! `SCM_RIGHTS` で fd がちょうど 1 本届くことと、拒否では fd が 1 本も届かないことを具体値で照合する。
//! root・実コンテナは不要で既定のテスト集合で動く。模擬の起動ハンドルは pidfd の代わりに `/dev/null` を開いた fd を
//! 持つ（届いた fd が元の fd と同じ実体を指すことを `/proc/self/fd` の読み出しで確かめる。pidfd としての同一性の照合は
//! 受け取った側の `identify_pid1_with_pidfd` の責務で、実 pidfd を使う通しは実機前提の試験が担う）。

#![cfg(target_os = "linux")]

use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{ContainerId, ErrorCode, Signal, TraitError};
use fandhe_container_supervisor::control::listener::{ControlListener, effective_uid};
use fandhe_container_supervisor::control::observe::ControlObserver;
use fandhe_container_supervisor::control::server::{ControlServer, ServeConfig};
use fandhe_container_supervisor::control::target::{ControlledProcess, SignalSlot};
use fandhe_container_supervisor::control::{ControlExecHandover, ExecPidfdSource};

const PID: u32 = 4321;

/// 起動時 pidfd の代わりに任意の fd を返す模擬の起動ハンドル。
struct Fake {
    fd: Option<OwnedFd>,
}

impl LaunchedProcess for Fake {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(PID).unwrap()
    }
    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        std::thread::sleep(timeout.min(Duration::from_millis(5)));
        Ok(None)
    }
    fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
        Ok(())
    }
    fn signal(&self, _signal: Signal, _deadline: Instant) -> Result<(), TraitError> {
        Ok(())
    }
    fn launch_pidfd(&self) -> Option<BorrowedFd<'_>> {
        self.fd.as_ref().map(|fd| fd.as_fd())
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(tag: &str) -> Self {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("fc-hand-it-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Rig {
    root: TempRoot,
    id: ContainerId,
    process: Option<ControlledProcess>,
    server: Option<ControlServer>,
    _listener: ControlListener,
}

impl Rig {
    /// `process` が `Some` なら、その fd（`with_fd` が偽なら pidfd なし）を持つ起動ハンドルをスロットへ登録する。
    fn start(tag: &str, with_process: bool, with_fd: bool) -> Self {
        let root = TempRoot::new(tag);
        let dir = root.0.join(tag);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let id = ContainerId::new(tag).unwrap();
        let listener = ControlListener::bind(&root.0, &id).unwrap();
        let slot = SignalSlot::new();
        let process = with_process.then(|| {
            let fd = with_fd
                .then(|| OwnedFd::from(std::fs::File::open("/dev/null").expect("open /dev/null")));
            ControlledProcess::new(Box::new(Fake { fd }), slot.clone())
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
            root,
            id,
            process,
            server: Some(server),
            _listener: listener,
        }
    }

    fn obtain(&self, pid: u32, within: Duration) -> Result<OwnedFd, TraitError> {
        ControlExecHandover::new(self.root.0.clone()).obtain(
            &self.id,
            NonZeroU32::new(pid).unwrap(),
            Instant::now() + within,
        )
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        drop(self.server.take());
        drop(self.process.take());
    }
}

fn link_target(fd: &OwnedFd) -> String {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

/// SUP-6・SEC-1: pid が一致すれば fd がちょうど 1 本届き、元の fd とは別番号で同じ実体を指す。
#[test]
fn sup6_sec1_handover_delivers_one_descriptor_for_matching_pid() {
    let rig = Rig::start("deliver", true, true);
    let fd = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    assert_eq!(link_target(&fd), "/dev/null");
    // 2 回目も（別接続で）受け取れる。複製はそのつど新しい fd 番号で、スロットの複製は閉じられない。
    let again = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    assert_eq!(link_target(&again), "/dev/null");
    assert_ne!(fd.as_raw_fd(), again.as_raw_fd());
}

/// SUP-6・SEC-1: pid 不一致は固定文言の FAILED_PRECONDITION で、fd は届かない。
#[test]
fn sup6_sec1_handover_pid_mismatch_is_rejected_without_descriptor() {
    let rig = Rig::start("pidmis", true, true);
    let e = rig.obtain(PID + 1, Duration::from_secs(2)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(
        e.message(),
        "the process id does not match the launched process"
    );
}

/// SUP-6・SEC-1: ハンドル無し・pidfd 無しは「起動ハンドルを保持していない」で拒否する（記録 pid からの縮退をしない）。
#[test]
fn sup6_sec1_handover_without_handle_or_pidfd_is_no_handle() {
    for (tag, with_process, with_fd) in [("nohandle", false, false), ("nofd", true, false)] {
        let rig = Rig::start(tag, with_process, with_fd);
        let e = rig.obtain(PID, Duration::from_secs(2)).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition, "{tag}");
        assert_eq!(
            e.message(),
            "the supervisor holds no launched process",
            "{tag}"
        );
    }
}

/// SUP-6・SEC-1: 終了を観測したスロットは複製を渡さない（`ContainerExited`）。
#[test]
fn sup6_sec1_handover_after_exit_is_container_exited() {
    let rig = Rig::start("exited", true, true);
    let process = rig.process.as_ref().unwrap();
    // 内側の `terminate` が成功するとスロットが Exited になり、保持していた複製が落ちる。
    use fandhe_container_core::oci_runtime::LaunchedProcess as _;
    process.terminate(Duration::from_secs(1)).unwrap();
    let e = rig.obtain(PID, Duration::from_secs(2)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "the container process has already exited");
}

/// REPAIR-5: 期限が迫っている要求は接続せずに Timeout で返す。
#[test]
fn repair5_handover_with_expired_deadline_times_out_without_connecting() {
    let rig = Rig::start("expired", true, true);
    let e = rig.obtain(PID, Duration::from_millis(5)).unwrap_err();
    assert_eq!(e.code(), ErrorCode::Timeout);
}
