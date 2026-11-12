//! 制御チャネルの exec 用 pidfd の受け渡し（ExecHandoverRequest）の結合試験（SUP-6・SEC-1・REPAIR-2・REPAIR-5・#2626）。
//!
//! 実際の UDS の上で、`ControlExecHandover`（クライアント入口）→ `ControlServer` → `SignalSlot` の複製を通し、
//! `SCM_RIGHTS` で fd がちょうど 1 本届くことと、拒否では fd が 1 本も届かないことを具体値で照合する。
//! root・実コンテナは不要で既定のテスト集合で動く。模擬の起動ハンドルは pidfd の代わりに `/dev/null` を開いた fd を
//! 持つ（届いた fd が元の fd と同じ実体を指すことを `/proc/self/fd` の読み出しで確かめる。pidfd としての同一性の照合は
//! 受け取った側の `identify_pid1_with_pidfd` の責務で、実 pidfd を使う通しは実機前提の試験が担う）。
//!
//! 追加（#4277・REPAIR-12）: 生の UDS と試験専用の受信入口 `recv_response_raw_for_test`（制御バッファは fd 4 本分）で、
//! 拒否の応答は `SCM_RIGHTS` が 0 本かつ `MSG_CTRUNC` なし、成功は 1 本であることを照合する（クライアント入口は
//! 拒否に付いた fd を黙って閉じるため、サーバが fd を添えていないことはここでしか観測できない）。
//!
//! 追加（#4328・REPAIR-12）: kind 6 の成功の後、同じ接続で kind 7（ExecCgroupNotify）の拒否の応答を生受信し、
//! `SCM_RIGHTS` 0 本・`MSG_CTRUNC` なしを照合する（成功の ack も 0 本）。応答を書かない分岐（途中までの送信・読み取り期限切れ）
//! と到達できない分岐（名前の長さ超過・`get_mut` の `None`）は観測できないため対象外。
//!
//! 追加（#4573・SUP-6・REPAIR-4）: kind 6 の結果は `control_signal` ではなく `control_exec` に数える。
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
use fandhe_container_supervisor::control::client::recv_response_raw_for_test;
use fandhe_container_supervisor::control::listener::{ControlListener, effective_uid};
use fandhe_container_supervisor::control::observe::ControlObserver;
use fandhe_container_supervisor::control::protocol::{
    ControlReason, ExecHandoverRequestFrame, HEADER_LEN, RESPONSE_LEN, ResponseFrame,
    SignalDeadline, encode_hello,
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
    /// 回収に掛かる時間の模擬（既定は 0）。
    delay: Mutex<Duration>,
}

impl ExecCgroupReclaimer for FakeReclaimer {
    fn reclaim(&self, name: &ExecCgroupName) -> ReclaimOutcome {
        let delay = *self.delay.lock().unwrap();
        std::thread::sleep(delay);
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
    observer: Arc<ControlObserver>,
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
            Arc::clone(&observer),
            pool.clone(),
        )
        .unwrap();
        Self {
            root,
            id,
            process,
            server: Some(server),
            reclaimer,
            observer,
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

/// この試験プロセスの pid を持つ exec 子 cgroup の名前（`exec-<pid>-<seq>`）。作成通知の名前は接続の所有と結びつく
/// （通知の名前の pid が `SO_PEERCRED` の pid と一致すること。SEC-1・#3808）ため、固定の偽名は使えない。
fn own_name(seq: u32) -> String {
    format!("exec-{}-{seq}", std::process::id())
}

/// SUP-6・SUP-8・SEC-1・SEC-4・#2766: supervisor 不在（制御ソケットが無い・残骸だけ・Hello 前に切断）は、
/// 本物の取得元で固定文言の `Unavailable` になり、fd は届かない（`state.json` の pid からの `pidfd_open` へ縮退しない。
/// 縮退の否定は cli の `sup6_sup8_sec4_2766_*` が生きている pid で照合する）。
#[test]
fn sup6_sup8_sec4_2766_absent_supervisor_is_unavailable() {
    use std::os::unix::net::UnixListener;
    for scenario in ["no-socket", "stale-socket", "closes-before-hello"] {
        let root = TempRoot::new("absent");
        let id = ContainerId::new("absent").unwrap();
        let dir = root.0.join("absent");
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        }
        let sock = dir.join("supervisor.sock");
        let mut hold = None;
        match scenario {
            "stale-socket" => drop(UnixListener::bind(&sock).unwrap()),
            "closes-before-hello" => {
                let l = UnixListener::bind(&sock).unwrap();
                let t = std::thread::spawn(move || {
                    if let Ok((s, _)) = l.accept() {
                        drop(s);
                    }
                });
                hold = Some(t);
            }
            _ => {}
        }
        let started = Instant::now();
        let e = ControlExecHandover::new(root.0.clone())
            .obtain(
                &id,
                NonZeroU32::new(std::process::id()).unwrap(),
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::Unavailable, "{scenario}");
        assert_eq!(
            e.message(),
            "the supervisor control channel is unavailable",
            "{scenario}"
        );
        assert!(started.elapsed() < Duration::from_secs(3), "{scenario}");
        if let Some(t) = hold {
            t.join().unwrap();
        }
    }
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
        .notify_created(&name(&own_name(1234)), hold_in(60.0))
        .unwrap();
    // 接続を保持している間は回収されない。
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(rig.reclaimer.calls(), Vec::<String>::new());
    drop(handover);
    assert_eq!(
        rig.reclaimer.wait_for(1, Duration::from_secs(3)),
        vec![own_name(1234)]
    );
    // 追加の呼び出しは起きない（1 回だけ）。
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(rig.reclaimer.calls().len(), 1);
}

/// REPAIR-4・SUP-6・#2626: 回収に 50ms 掛かる回収役のとき、観測へ記録される `exec_cgroup_reclaim` のレイテンシは
/// 0 でなく遅延以上になる（実測した経過時間を渡す。固定の 0 を渡さない）。
#[test]
fn repair4_sup6_guard_records_actual_reclaim_latency() {
    let rig = Rig::start("latency", true, true);
    let delay = Duration::from_millis(50);
    *rig.reclaimer.delay.lock().unwrap() = delay;
    let handover = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    handover
        .notify_created(&name(&own_name(1234)), hold_in(60.0))
        .unwrap();
    drop(handover);
    assert_eq!(rig.reclaimer.wait_for(1, Duration::from_secs(3)).len(), 1);
    let op = fandhe_container_core::observability::OpName::new("exec_cgroup_reclaim").unwrap();
    // 記録は回収役の戻りの直後に行われるため、現れるまで短く待つ。
    let until = Instant::now() + Duration::from_secs(3);
    let stats = loop {
        if let Some(s) = rig.observer.recorder().snapshot_op(&op) {
            break s;
        }
        assert!(Instant::now() < until, "reclaim was not recorded");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(stats.success(), 1);
    let max = stats.latency().expect("latency summary").max();
    assert!(
        max >= delay && max < Duration::from_secs(3),
        "recorded latency {max:?} must cover the {delay:?} reclaim"
    );
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
        .notify_created(&name(&own_name(77)), hold_in(0.5))
        .unwrap();
    assert_eq!(
        rig.reclaimer.wait_for(1, Duration::from_secs(5)),
        vec![own_name(77)]
    );
    drop(handover);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(rig.reclaimer.calls().len(), 1);
}

/// kind 6 の生の要求を送り、応答の理由・添付 fd・`MSG_CTRUNC` を受けたまま返す。`ControlExecHandover` を通さないので
/// 添付 fd を黙って捨てない。制御バッファは fd 4 本分あるため「0 本かつ切り詰めなし」は実際に添えられていないことを意味する。
/// 成功ではガードが接続を預かるため、呼び出し側が drop の時点を決められるよう stream も返す。
fn raw_handover_with_fds(
    rig: &Rig,
    frame: &[u8],
) -> (ControlReason, Vec<OwnedFd>, bool, UnixStream) {
    let path = rig.root.0.join(rig.id.as_str()).join("supervisor.sock");
    let mut s = UnixStream::connect(path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut hello = [0u8; HEADER_LEN];
    s.read_exact(&mut hello).unwrap();
    assert_eq!(hello, encode_hello());
    s.write_all(frame).unwrap();
    let raw = recv_response_raw_for_test(&s, Instant::now() + Duration::from_secs(5)).unwrap();
    let mut resp = raw.bytes;
    if resp.len() < RESPONSE_LEN {
        let mut rest = vec![0u8; RESPONSE_LEN - resp.len()];
        s.read_exact(&mut rest).unwrap();
        resp.extend_from_slice(&rest);
    }
    let expected_head: [u8; HEADER_LEN] = [b'F', b'C', b'S', b'C', 1, 3, 0, 1];
    assert_eq!(resp.get(..HEADER_LEN), Some(&expected_head[..]));
    let reason = ControlReason::from_u8(*resp.last().unwrap()).unwrap();
    (reason, raw.fds, raw.truncated, s)
}

/// kind 6 の要求 frame（20 バイト）。
fn handover_frame(pid: u32, deadline: SignalDeadline) -> [u8; 20] {
    ExecHandoverRequestFrame {
        pid: NonZeroU32::new(pid).unwrap(),
        deadline,
    }
    .encode()
}

/// 生の接続で pidfd の受け渡しまで済ませ、ExecCgroupNotify を手で書けるようにする（検証の拒否の照合用）。
fn raw_handover(rig: &Rig) -> UnixStream {
    let frame = handover_frame(
        PID,
        SignalDeadline::from_now(Duration::from_secs(3)).unwrap(),
    );
    let (reason, fds, truncated, stream) = raw_handover_with_fds(rig, &frame);
    assert_eq!(
        (reason, fds.len(), truncated),
        (ControlReason::Ok, 1, false)
    );
    stream
}

/// SUP-6・SEC-1・REPAIR-12・#4277: kind 6 の拒否の応答は `SCM_RIGHTS` の fd を 0 本しか持たず、`MSG_CTRUNC` も立たない。
#[test]
fn sup6_sec1_repair12_4277_rejections_carry_no_scm_rights() {
    let none = |reason| (reason, 0usize, false);
    let observe = |rig: &Rig, frame: &[u8]| {
        let (reason, fds, truncated, _s) = raw_handover_with_fds(rig, frame);
        (reason, fds.len(), truncated)
    };
    let soon = || SignalDeadline::from_now(Duration::from_secs(3)).unwrap();

    // 共通の Rig で足りる場面（pid 不一致・Malformed 2 件・Timeout）。
    let rig = Rig::start("rf-common", true, true);
    assert_eq!(
        observe(&rig, &handover_frame(PID + 1, soon())),
        none(ControlReason::PidMismatch),
        "pid mismatch"
    );
    assert_eq!(
        observe(
            &rig,
            &handover_frame(
                PID,
                SignalDeadline::from_now(Duration::from_secs(30)).unwrap()
            )
        ),
        none(ControlReason::Malformed),
        "deadline beyond the cap"
    );
    let mut zero_pid = handover_frame(PID, soon());
    zero_pid[8..12].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        observe(&rig, &zero_pid),
        none(ControlReason::Malformed),
        "pid 0"
    );
    assert_eq!(
        observe(
            &rig,
            &handover_frame(PID, SignalDeadline::from_nanos(1).unwrap())
        ),
        none(ControlReason::Timeout),
        "past deadline"
    );
    assert_eq!(rig.reclaimer.calls(), Vec::<String>::new());

    let rig = Rig::start("rf-empty", false, false);
    assert_eq!(
        observe(&rig, &handover_frame(PID, soon())),
        none(ControlReason::NoHandle),
        "empty slot"
    );
    let rig = Rig::start("rf-nofd", true, false);
    assert_eq!(
        observe(&rig, &handover_frame(PID, soon())),
        none(ControlReason::NoHandle),
        "no pidfd duplicate"
    );
    let rig = Rig::start("rf-exit", true, true);
    {
        use fandhe_container_core::oci_runtime::LaunchedProcess as _;
        rig.process
            .as_ref()
            .unwrap()
            .terminate(Duration::from_secs(1))
            .unwrap();
    }
    assert_eq!(
        observe(&rig, &handover_frame(PID, soon())),
        none(ControlReason::ContainerExited),
        "exited"
    );
    let rig = Rig::start_with("rf-norec", true, true, None);
    assert_eq!(
        observe(&rig, &handover_frame(PID, soon())),
        none(ControlReason::ExecReclaimUnavailable),
        "no reclaimer"
    );
    let rig = Rig::start_with("rf-limit", true, true, Some(test_limits(2)));
    let held = (
        rig.obtain(PID, Duration::from_secs(2)).unwrap(),
        rig.obtain(PID, Duration::from_secs(2)).unwrap(),
    );
    assert_eq!(
        observe(&rig, &handover_frame(PID, soon())),
        none(ControlReason::ExecGuardExhausted),
        "guard limit"
    );
    drop(held);
}

/// SUP-6・SEC-1・REPAIR-12・#4277（対照）: 成功の応答は fd をちょうど 1 本持つ。0 本の照合が受信経路の見落としでないことを示す。
#[test]
fn sup6_sec1_repair12_4277_ok_carries_exactly_one_descriptor() {
    let rig = Rig::start("ok-one", true, true);
    let frame = handover_frame(
        PID,
        SignalDeadline::from_now(Duration::from_secs(3)).unwrap(),
    );
    let (reason, fds, truncated, stream) = raw_handover_with_fds(&rig, &frame);
    assert_eq!(
        (reason, fds.len(), truncated),
        (ControlReason::Ok, 1, false)
    );
    let link = std::fs::read_link(format!("/proc/self/fd/{}", fds[0].as_raw_fd())).unwrap();
    assert_eq!(link.to_string_lossy(), "/dev/null");
    drop((fds, stream));
    let pool = rig.pool.as_ref().unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    while pool.active() != 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(pool.active(), 0);
}

/// 同じ接続へ kind 7 などの生の frame を送り、応答の理由・添付 fd の本数・`MSG_CTRUNC` を返す。
/// `ControlExecHandover::notify_created` を通さず応答を判定せずに受ける（制御バッファは fd 4 本分）。
fn raw_notify_with_fds(stream: &mut UnixStream, frame: &[u8]) -> (ControlReason, usize, bool) {
    stream.write_all(frame).unwrap();
    let raw = recv_response_raw_for_test(stream, Instant::now() + Duration::from_secs(5)).unwrap();
    let mut resp = raw.bytes;
    if resp.len() < RESPONSE_LEN {
        let mut rest = vec![0u8; RESPONSE_LEN - resp.len()];
        stream.read_exact(&mut rest).unwrap();
        resp.extend_from_slice(&rest);
    }
    let expected_head: [u8; HEADER_LEN] = [b'F', b'C', b'S', b'C', 1, 3, 0, 1];
    assert_eq!(resp.get(..HEADER_LEN), Some(&expected_head[..]));
    let reason = ControlReason::from_u8(*resp.last().unwrap()).unwrap();
    (reason, raw.fds.len(), raw.truncated)
}

/// kind 7 の frame（ヘッダ 8 バイト + 保持期限 + 名前）。壊れた値を作るための試験専用の手組み。
fn notify_bytes(head: [u8; HEADER_LEN], hold: u64, name: &[u8]) -> Vec<u8> {
    let mut v = head.to_vec();
    v.extend_from_slice(&hold.to_be_bytes());
    v.extend_from_slice(name);
    v
}

/// SUP-6・SEC-1・REPAIR-12・#4328: kind 7 の拒否の応答は `SCM_RIGHTS` の fd を 0 本しか持たず、`MSG_CTRUNC` も立たない。
/// 成功の ack も 0 本。対照は同じ接続の直前の kind 6（`raw_handover` が fd ちょうど 1 本を assert）。
#[test]
fn sup6_sec1_repair12_4328_notify_rejections_carry_no_scm_rights() {
    let rig = Rig::start_with("nf-reject", true, true, Some(test_limits(32)));
    let h = |version: u8, kind: u8, len: u8| [b'F', b'C', b'S', b'C', version, kind, 0, len];
    // 所有の照合（#3808）のため、名前の pid は接続する本人（この試験プロセス）の pid にする。
    let own = own_name(34);
    let name = own.as_bytes();
    let nlen = u8::try_from(8 + name.len()).unwrap();
    let cases: Vec<(&str, Vec<u8>, ControlReason)> = vec![
        (
            "bad magic",
            [b'X', b'C', b'S', b'C', 1, 7, 0, 18].to_vec(),
            ControlReason::Malformed,
        ),
        (
            "bad version",
            h(2, 7, 18).to_vec(),
            ControlReason::UnsupportedVersion,
        ),
        ("too large", h(1, 7, 65).to_vec(), ControlReason::TooLarge),
        ("wrong kind", h(1, 6, 12).to_vec(), ControlReason::Malformed),
        ("too short", h(1, 7, 8).to_vec(), ControlReason::Malformed),
        (
            "hold zero",
            notify_bytes(h(1, 7, nlen), 0, name),
            ControlReason::Malformed,
        ),
        (
            "name not utf8",
            notify_bytes(h(1, 7, 10), u64::MAX, &[0xff, 0xfe]),
            ControlReason::Malformed,
        ),
        (
            "name bad format",
            notify_bytes(h(1, 7, 16), u64::MAX, b"Exec_BAD"),
            ControlReason::Malformed,
        ),
        (
            "name prefix only",
            notify_bytes(h(1, 7, 13), u64::MAX, b"exec-"),
            ControlReason::Malformed,
        ),
        (
            "hold in the past",
            notify_bytes(h(1, 7, nlen), 1, name),
            ControlReason::Timeout,
        ),
        (
            "hold beyond cap",
            notify_bytes(h(1, 7, nlen), u64::MAX, name),
            ControlReason::Malformed,
        ),
    ];
    for (label, frame, reason) in cases {
        let mut s = raw_handover(&rig);
        // ヘッダで拒否される場合、サーバは payload を読まない。余りを送らず、ヘッダ 8 バイトだけにする。
        let frame = if matches!(
            label,
            "bad magic" | "bad version" | "too large" | "wrong kind" | "too short"
        ) {
            frame.get(..HEADER_LEN).unwrap().to_vec()
        } else {
            frame
        };
        assert_eq!(
            raw_notify_with_fds(&mut s, &frame),
            (reason, 0, false),
            "{label}"
        );
    }

    // 受け付け前（kind 6 の無い新しい接続）の kind 7。
    let frame = notify_bytes(h(1, 7, nlen), u64::MAX, name);
    let (reason, fds, truncated, _s) = raw_handover_with_fds(&rig, &frame);
    assert_eq!(
        (reason, fds.len(), truncated),
        (ControlReason::Malformed, 0, false)
    );

    // 成功の ack も fd を持たない。保持期限は kind 6 と同じ時計の絶対時刻で今から 30 秒後。
    let hold = SignalDeadline::from_now(Duration::from_secs(30))
        .unwrap()
        .as_nanos();
    let mut s = raw_handover(&rig);
    assert_eq!(
        raw_notify_with_fds(&mut s, &notify_bytes(h(1, 7, nlen), hold, name)),
        (ControlReason::Ok, 0, false),
        "ack"
    );
    drop(s);

    // 拒否では回収せず、ack の接続を閉じたときだけ 1 回回収する。ガードの枠は全て戻る。
    assert_eq!(rig.reclaimer.wait_for(1, Duration::from_secs(3)), vec![own]);
    let pool = rig.pool.as_ref().unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    while pool.active() != 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(pool.active(), 0);
    assert_eq!(rig.reclaimer.calls().len(), 1);
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
    let own = own_name(34);
    let mut frame = vec![
        b'F',
        b'C',
        b'S',
        b'C',
        1,
        7,
        0,
        u8::try_from(8 + own.len()).unwrap(),
    ];
    frame.extend_from_slice(&1u64.to_be_bytes());
    frame.extend_from_slice(own.as_bytes());
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
    held.notify_created(&name(&own_name(99)), hold_in(60.0))
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

/// 記録は応答を書いた後なので、`op` の (success, failure) が期待値になるまで 3 秒を上限に待つ。
fn wait_op_counts(rig: &Rig, op: &str, want: (u64, u64)) {
    let op = fandhe_container_core::observability::OpName::new(op).unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(s) = rig.observer.recorder().snapshot_op(&op)
            && (s.success(), s.failure()) == want
        {
            assert!(s.latency().is_some());
            return;
        }
        assert!(
            Instant::now() < until,
            "control_exec did not reach {want:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_no_control_signal(rig: &Rig) {
    let sig = fandhe_container_core::observability::OpName::new("control_signal").unwrap();
    assert!(rig.observer.recorder().snapshot_op(&sig).is_none());
}

/// SUP-6・REPAIR-4・#4573: exec の受け渡しの成功と失敗は `control_exec` に数え、`control_signal` には入れない。
#[test]
fn repair4_sup6_4573_exec_handover_is_counted_as_control_exec() {
    let rig = Rig::start("opname", true, true);
    let _ok = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    let e = rig
        .obtain(PID + 1, Duration::from_secs(2))
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    wait_op_counts(&rig, "control_exec", (1, 1));
    assert_no_control_signal(&rig);
}

/// SUP-6・REPAIR-4・#4573: payload を読んだ後の拒否（回収役なし）も `control_exec` の失敗に数える。
#[test]
fn repair4_sup6_4573_exec_refusal_without_reclaimer_is_counted_as_control_exec_failure() {
    let rig = Rig::start_with("opnorec", true, true, None);
    let e = rig
        .obtain(PID, Duration::from_secs(2))
        .map(|_| ())
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    wait_op_counts(&rig, "control_exec", (0, 1));
    assert_no_control_signal(&rig);
}

/// SUP-6・SEC-1・#3808: 同じ名前を別の接続が二重に通知すると、2 本目は ack の前に `Malformed` で拒否され、
/// 拒否された接続の切断では回収されない。名前を持つ 1 本目が切断されたときだけ 1 回回収する。
#[test]
fn sup6_sec1_3808_duplicate_name_is_rejected_and_not_reclaimed() {
    let rig = Rig::start("dupname", true, true);
    let first = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    first
        .notify_created(&name(&own_name(1)), hold_in(60.0))
        .unwrap();
    let second = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    assert!(
        second
            .notify_created(&name(&own_name(1)), hold_in(60.0))
            .is_err(),
        "a second notification of a live name must be refused"
    );
    drop(second);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(rig.reclaimer.calls(), Vec::<String>::new());
    drop(first);
    assert_eq!(
        rig.reclaimer.wait_for(1, Duration::from_secs(3)),
        vec![own_name(1)]
    );
}

/// SUP-6・SEC-1・#3808: 回収を終えたガードの名前は手放され、同じ名前を再び通知できる。
#[test]
fn sup6_sec1_3808_name_is_released_after_reclaim() {
    let rig = Rig::start("namerelease", true, true);
    let first = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    first
        .notify_created(&name(&own_name(2)), hold_in(60.0))
        .unwrap();
    drop(first);
    assert_eq!(
        rig.reclaimer.wait_for(1, Duration::from_secs(3)),
        vec![own_name(2)]
    );
    // 枠が戻る（ガードのスレッドが名前も手放して終わる）まで待つ。
    let pool = rig.pool.as_ref().unwrap();
    let until = Instant::now() + Duration::from_secs(3);
    while pool.active() != 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    let again = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    again
        .notify_created(&name(&own_name(2)), hold_in(60.0))
        .unwrap();
    drop(again);
    assert_eq!(
        rig.reclaimer.wait_for(2, Duration::from_secs(3)),
        vec![own_name(2), own_name(2)]
    );
}

/// SUP-6・SEC-1・#3808: 名前の pid が接続の本人（`SO_PEERCRED` の pid）と違う通知は拒否され、回収されない。
#[test]
fn sup6_sec1_3808_name_with_foreign_pid_is_rejected() {
    let rig = Rig::start("foreignpid", true, true);
    let foreign = format!("exec-{}-0", std::process::id().wrapping_add(1));
    let h = rig.obtain(PID, Duration::from_secs(2)).unwrap();
    assert!(
        h.notify_created(&name(&foreign), hold_in(60.0)).is_err(),
        "a name carrying another pid must be refused"
    );
    drop(h);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(rig.reclaimer.calls(), Vec::<String>::new());
}
