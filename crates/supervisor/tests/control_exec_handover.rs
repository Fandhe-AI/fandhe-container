//! 制御チャネルの exec 用 pidfd の受け渡し（ExecHandoverRequest）の結合試験（SUP-6・SEC-1・REPAIR-2・REPAIR-5・#2626）。
//!
//! 実際の UDS の上で、`ControlExecHandover`（クライアント入口）→ `ControlServer` → `SignalSlot` の複製を通し、
//! `SCM_RIGHTS` で fd がちょうど 1 本届くことと、拒否では fd が 1 本も届かないことを具体値で照合する。
//! root・実コンテナは不要で既定のテスト集合で動く。模擬の起動ハンドルは pidfd の代わりに `/dev/null` を開いた fd を
//! 持つ（届いた fd が元の fd と同じ実体を指すことを `/proc/self/fd` の読み出しで確かめる。pidfd としての同一性の照合は
//! 受け取った側の `identify_pid1_with_pidfd` の責務で、実 pidfd を使う通しは実機前提の試験が担う）。
//!
//! 追加（#2626 の codex P1）: pidfd を渡した接続を supervisor のガードが預かり、CLI の作成通知（ExecCgroupNotify）の後に
//! 接続が切れる（CLI の消滅を含む）か保持期限が来たら、偽の回収役が通知された名前で 1 回だけ呼ばれることを照合する
//! （SUP-6・REPAIR-5・REPAIR-4）。実 cgroup の回収は実機前提の試験が担う。

#![cfg(target_os = "linux")]

use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fandhe_container_core::exec::ExecCgroupName;
use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{ContainerId, ErrorCode, Signal, TraitError};
use fandhe_container_supervisor::control::listener::{ControlListener, effective_uid};
use fandhe_container_supervisor::control::observe::ControlObserver;
use fandhe_container_supervisor::control::protocol::{
    ControlReason, ExecHandoverRequestFrame, HEADER_LEN, RESPONSE_LEN, ResponseFrame,
    SignalDeadline,
};
use fandhe_container_supervisor::control::server::{ControlServer, ServeConfig};
use fandhe_container_supervisor::control::target::{ControlledProcess, SignalSlot};
use fandhe_container_supervisor::control::{
    ControlExecHandover, ExecCgroupReclaimer, ExecGuardLimits, ExecGuardPool, ExecHandover,
    ExecPidfdSource, ReclaimOutcome,
};
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

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
    /// 0700 で排他的に作る（既存エントリは採用せず、別名で再試行する。共有 `/tmp` での symlink 差し替えを避ける。SEC-1）。
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::DirBuilderExt as _;
        for attempt in 0..64u32 {
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir().join(format!(
                "fc-hand-it-{tag}-{}-{n}-{attempt}",
                std::process::id()
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => return Self(p),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create temp root: {e}"),
            }
        }
        panic!("could not create a unique temp root");
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 回収された名前を記録する偽の回収役。
#[derive(Default)]
struct FakeReclaimer {
    calls: Mutex<Vec<String>>,
}

impl ExecCgroupReclaimer for FakeReclaimer {
    fn reclaim(&self, name: &ExecCgroupName) -> ReclaimOutcome {
        self.calls.lock().unwrap().push(name.as_str().to_owned());
        ReclaimOutcome::Removed
    }
}

impl FakeReclaimer {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    /// 呼び出しが `count` 件に達するまで最大 `within` 待つ。
    fn wait_for(&self, count: usize, within: Duration) -> Vec<String> {
        let until = Instant::now() + within;
        loop {
            let c = self.calls();
            if c.len() >= count || Instant::now() >= until {
                return c;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// 試験用のガードの期限（猶予を 0 にして保持期限の到来を速く観測する）。
fn test_limits(max_guards: usize) -> ExecGuardLimits {
    ExecGuardLimits {
        max_guards,
        notify_wait: Duration::from_secs(5),
        hold_grace: Duration::ZERO,
        write_timeout: Duration::from_secs(1),
    }
}

struct Rig {
    root: TempRoot,
    id: ContainerId,
    process: Option<ControlledProcess>,
    server: Option<ControlServer>,
    reclaimer: Arc<FakeReclaimer>,
    pool: Option<Arc<ExecGuardPool>>,
    _listener: ControlListener,
}

impl Rig {
    /// `process` が `Some` なら、その fd（`with_fd` が偽なら pidfd なし）を持つ起動ハンドルをスロットへ登録する。
    fn start(tag: &str, with_process: bool, with_fd: bool) -> Self {
        Self::start_with(tag, with_process, with_fd, Some(test_limits(16)))
    }

    /// `limits` が `None` なら回収役を結線しない（ExecHandoverRequest は断られる）。
    fn start_with(
        tag: &str,
        with_process: bool,
        with_fd: bool,
        limits: Option<ExecGuardLimits>,
    ) -> Self {
        let root = TempRoot::new(tag);
        let dir = root.0.join(tag);
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        }
        let id = ContainerId::new(tag).unwrap();
        let listener = ControlListener::bind(&root.0, &id).unwrap();
        let slot = SignalSlot::new();
        let process = with_process.then(|| {
            let fd = with_fd
                .then(|| OwnedFd::from(std::fs::File::open("/dev/null").expect("open /dev/null")));
            ControlledProcess::new(Box::new(Fake { fd }), slot.clone())
        });
        let reclaimer = Arc::new(FakeReclaimer::default());
        let observer = Arc::new(ControlObserver::new(None, None));
        let pool = limits.map(|l| {
            ExecGuardPool::new(
                Arc::clone(&reclaimer) as Arc<dyn ExecCgroupReclaimer>,
                Arc::clone(&observer),
                l,
            )
        });
        let server = ControlServer::spawn_with_exec_guard(
            listener.try_clone_listener().unwrap(),
            slot,
            effective_uid().unwrap(),
            ServeConfig::default(),
            observer,
            pool.clone(),
        )
        .unwrap();
        Self {
            root,
            id,
            process,
            server: Some(server),
            reclaimer,
            pool,
            _listener: listener,
        }
    }

    fn obtain(&self, pid: u32, within: Duration) -> Result<ExecHandover, TraitError> {
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

fn link_target(handover: &ExecHandover) -> String {
    let fd = handover.pidfd();
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
    assert_ne!(fd.pidfd().as_raw_fd(), again.pidfd().as_raw_fd());
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

fn name(s: &str) -> ExecCgroupName {
    ExecCgroupName::new(s).unwrap()
}

/// 保持期限として渡す exec 全体の期限（今から `secs` 秒後）。
fn hold_in(secs: f64) -> Instant {
    Instant::now() + Duration::from_secs_f64(secs)
}

/// SUP-6・REPAIR-5・#2626: 通知 → ack → 接続の drop（CLI の消滅相当）で、偽の回収役が通知された名前で 1 回だけ呼ばれる。
#[test]
fn sup6_repair5_guard_reclaims_notified_name_when_connection_drops() {
    let rig = Rig::start("reclaim", true, true);
    let handover = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    handover
        .notify_created(&name("exec-1234-0"), hold_in(60.0))
        .unwrap();
    // 接続を保持している間は回収されない。
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(rig.reclaimer.calls(), Vec::<String>::new());
    drop(handover);
    assert_eq!(
        rig.reclaimer.wait_for(1, Duration::from_secs(3)),
        vec!["exec-1234-0".to_owned()]
    );
    // 追加の呼び出しは起きない（1 回だけ）。
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(rig.reclaimer.calls().len(), 1);
}

/// SUP-6・#2626: 通知しないまま接続を drop した場合は何も回収しない（cgroup の作成前に死んだ。残骸は既存の掃除が担う）。
#[test]
fn sup6_guard_without_notify_does_not_reclaim() {
    let rig = Rig::start("nonotify", true, true);
    let handover = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    drop(handover);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(rig.reclaimer.calls(), Vec::<String>::new());
    // ガードの枠は戻っている。
    let pool = rig.pool.as_ref().unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    while pool.active() != 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(pool.active(), 0);
}

/// REPAIR-5・SUP-6・#2626: 接続を保持したまま保持期限が来たら回収する（無期限に見張らない）。
#[test]
fn repair5_sup6_guard_reclaims_at_hold_deadline() {
    let rig = Rig::start("holddl", true, true);
    let handover = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    handover
        .notify_created(&name("exec-77-3"), hold_in(0.5))
        .unwrap();
    assert_eq!(
        rig.reclaimer.wait_for(1, Duration::from_secs(5)),
        vec!["exec-77-3".to_owned()]
    );
    drop(handover);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(rig.reclaimer.calls().len(), 1);
}

/// 生の接続で pidfd の受け渡しまで済ませ、ExecCgroupNotify を手で書けるようにする（検証の拒否の照合用）。
fn raw_handover(rig: &Rig) -> UnixStream {
    let path = rig.root.0.join(rig.id.as_str()).join("supervisor.sock");
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut hello = [0u8; HEADER_LEN];
    stream.read_exact(&mut hello).unwrap();
    let frame = ExecHandoverRequestFrame {
        pid: NonZeroU32::new(PID).unwrap(),
        deadline: SignalDeadline::from_now(Duration::from_secs(3)).unwrap(),
    };
    stream.write_all(&frame.encode()).unwrap();
    // 応答（Response(Ok) + SCM_RIGHTS）。通常の read は添付 fd を捨てるので、本文 9 バイトだけ読む。
    let mut resp = [0u8; RESPONSE_LEN];
    stream.read_exact(&mut resp).unwrap();
    assert_eq!(resp.get(HEADER_LEN).copied(), Some(ControlReason::Ok as u8));
    stream
}

/// SEC-1・REPAIR-2・SUP-6・#2626: 不正な名前の通知は `Malformed` で拒否され、回収役は呼ばれない。
#[test]
fn sec1_repair2_guard_rejects_invalid_name_without_reclaim() {
    let rig = Rig::start("badname", true, true);
    let mut stream = raw_handover(&rig);
    // kind 7・payload = 保持期限 8 バイト + 不正な名前（大文字・接頭辞なし）。
    let mut frame = vec![b'F', b'C', b'S', b'C', 1, 7, 0, 8 + 8];
    frame.extend_from_slice(&u64::MAX.to_be_bytes());
    frame.extend_from_slice(b"Exec_BAD");
    stream.write_all(&frame).unwrap();
    let mut resp = [0u8; RESPONSE_LEN];
    stream.read_exact(&mut resp).unwrap();
    let (_, payload) = resp.split_first_chunk::<HEADER_LEN>().unwrap();
    assert_eq!(
        ResponseFrame::decode_payload(&[payload[0]]).reason,
        ControlReason::Malformed
    );
    drop(stream);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(rig.reclaimer.calls(), Vec::<String>::new());
}

/// SEC-1・SUP-6・#2626: 保持期限が過去の通知も拒否する（回収役は呼ばれない）。
#[test]
fn repair5_guard_rejects_expired_hold_deadline() {
    let rig = Rig::start("expiredhold", true, true);
    let mut stream = raw_handover(&rig);
    let mut frame = vec![b'F', b'C', b'S', b'C', 1, 7, 0, 8 + 10];
    frame.extend_from_slice(&1u64.to_be_bytes());
    frame.extend_from_slice(b"exec-12-34");
    stream.write_all(&frame).unwrap();
    let mut resp = [0u8; RESPONSE_LEN];
    stream.read_exact(&mut resp).unwrap();
    assert_eq!(
        resp.get(HEADER_LEN).copied(),
        Some(ControlReason::Timeout as u8)
    );
    drop(stream);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(rig.reclaimer.calls(), Vec::<String>::new());
}

/// SUP-6・REPAIR-5・#2626: ガードの上限（ここでは 2）に達すると、pidfd を渡す前に RESOURCE_EXHAUSTED で断る。
/// 枠が戻れば再び受けられる。
#[test]
fn sup6_repair5_guard_limit_refuses_handover_without_descriptor() {
    let rig = Rig::start_with("limit", true, true, Some(test_limits(2)));
    let first = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    let second = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    let e = rig
        .obtain(PID, Duration::from_secs(2))
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::ResourceExhausted);
    assert_eq!(
        e.message(),
        "the supervisor has too many exec cgroup guards"
    );
    drop(first);
    let until = Instant::now() + Duration::from_secs(3);
    let third = loop {
        match rig.obtain(PID, Duration::from_secs(2)) {
            Ok(h) => break h,
            Err(e) => {
                assert_eq!(e.code(), ErrorCode::ResourceExhausted);
                assert!(Instant::now() < until, "the guard slot was not returned");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    drop((second, third));
}

/// SUP-6・REPAIR-5・#2626: ガードが接続を保持している間も accept ループは先へ進む（別の要求が期限内に処理される）。
#[test]
fn sup6_repair5_held_guard_does_not_block_other_requests() {
    let rig = Rig::start("noblock", true, true);
    let held = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    held.notify_created(&name("exec-9-9"), hold_in(60.0))
        .unwrap();
    let started = Instant::now();
    let e = rig
        .obtain(PID + 1, Duration::from_secs(2))
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    let again = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    // 既定の読み取り期限（1 秒）の影響を受けず速やかに処理される。
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
    drop((held, again));
}

/// SEC-1・SUP-6・#2626: 回収役が結線されていない supervisor は pidfd を渡さない（fail-closed）。
#[test]
fn sec1_sup6_handover_without_reclaimer_is_refused() {
    let rig = Rig::start_with("noreclaimer", true, true, None);
    let e = rig
        .obtain(PID, Duration::from_secs(2))
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "the supervisor cannot reclaim exec cgroups");
}
