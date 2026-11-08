//! `ShimExecLauncher` の試験（CRI-5・CRI-1・SEC-1・REPAIR-5・#4148）。root も実コンテナも使わず、偽の helper
//! （`/bin/sleep` を helper の `Child` とし、channel の相手は試験スレッドが演じる）で終了コードの写像・kill の範囲・
//! 未確認の保持・期限・drop の契約を具体値で照合する。実 supervisor と実コンテナでの通しは #4150。

use std::os::fd::OwnedFd;
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{ContainerStatus, CreateStateRequest, UpdateStateRequest};
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::shim_v2::exec::{PROCESS_TYPE_URL, parse_process_spec};
use fandhe_container_cri::shim_v2::task_api::Any;
use fandhe_container_supervisor::stream_exec::channel::{
    recv_stdio_handover, send_result, send_started,
};
use fandhe_container_supervisor::stream_exec::wire::{ExitSignal, StdioMask};

use super::*;
use crate::streaming::log_attach::test_support::TempDir;

const WAIT: Duration = Duration::from_secs(5);

type Script = Arc<dyn Fn(UnixStream, StdioMask) + Send + Sync>;

fn deadline() -> Instant {
    Instant::now() + WAIT
}

/// 偽の helper の起動口。`Child` は `/bin/sleep 60` で、channel の相手は `script` が演じる。
struct FakeSpawner {
    script: Script,
    pids: Arc<Mutex<Vec<u32>>>,
}

impl HelperSpawner for FakeSpawner {
    fn spawn(&self, args: &StreamExecArgs) -> Result<SpawnedHelper, CriError> {
        let (plugin_end, helper_end) = UnixStream::pair().expect("pair");
        let script_end = helper_end.try_clone().expect("clone");
        let child = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::from(OwnedFd::from(helper_end)))
            .spawn()
            .expect("spawn sleep");
        self.pids.lock().expect("lock").push(child.id());
        let script = Arc::clone(&self.script);
        let mask = args.stdio();
        std::thread::spawn(move || script(script_end, mask));
        Ok(SpawnedHelper {
            child,
            channel: plugin_end,
        })
    }

    fn capabilities(&self) -> crate::streaming::exec_launcher::HelperCapabilities {
        Default::default()
    }
}

/// 試験が結果を切り替えられる probe（0: Unknown、1: Confirmed、2: Failed）。
struct FakeProbe(AtomicU8);

impl ExecExtinctionProbe for FakeProbe {
    fn confirm(&self, _c: &ContainerId) -> ExtinctionOutcome {
        match self.0.load(Ordering::SeqCst) {
            1 => ExtinctionOutcome::Confirmed,
            2 => ExtinctionOutcome::Failed,
            _ => ExtinctionOutcome::Unknown,
        }
    }
}

struct Fixture {
    dir: TempDir,
    store: Arc<FileStateStore>,
    /// 記録の pid に書く init 役の実プロセス。kill が届かないことの照合に使う。
    init: Child,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.init.kill();
        let _ = self.init.wait();
    }
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let dir = TempDir::new(tag);
        let root = dir.0.join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .expect("root");
        let store = Arc::new(
            FileStateStore::open(StateRoot::from_override(root).expect("root")).expect("open"),
        );
        let bundle = dir.0.join("bundle");
        std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
        std::fs::write(bundle.join("config.json"), "{}").expect("config");
        let init = Command::new("/bin/sleep").arg("60").spawn().expect("init");
        for name in ["run1", "created1", "stopped1"] {
            let id = ContainerId::new(name).expect("id");
            let created = store
                .create(
                    &CreateStateRequest::new(
                        ContainerStatus::created(id.clone(), None),
                        bundle.clone(),
                    )
                    .expect("req"),
                )
                .expect("create");
            let next = match name {
                "run1" => Some(ContainerStatus::running(id, NonZeroU32::new(init.id()))),
                "stopped1" => Some(ContainerStatus::stopped(id, Some(0))),
                _ => None,
            };
            if let Some(next) = next {
                store
                    .update(&UpdateStateRequest::new(next, created.revision()))
                    .expect("update");
            }
        }
        Self { dir, store, init }
    }

    fn launcher(
        &self,
        script: Script,
        probe: Arc<FakeProbe>,
        budgets: ExecBudgets,
    ) -> (ShimExecLauncher, Arc<Mutex<Vec<u32>>>) {
        let pids = Arc::new(Mutex::new(Vec::new()));
        let spawner = FakeSpawner {
            script,
            pids: Arc::clone(&pids),
        };
        let l = ShimExecLauncher::with_budgets(
            self.dir.0.join("state"),
            Arc::clone(&self.store) as Arc<dyn StateStore>,
            Arc::new(spawner),
            probe,
            budgets,
        );
        (l, pids)
    }
}

fn probe(v: u8) -> Arc<FakeProbe> {
    Arc::new(FakeProbe(AtomicU8::new(v)))
}

fn short() -> ExecBudgets {
    ExecBudgets {
        handover: WAIT,
        started: Duration::from_millis(300),
        session: Duration::from_millis(200),
        result_grace: Duration::from_millis(200),
    }
}

fn spec_of(json: &str) -> ExecProcessSpec {
    parse_process_spec(&Any {
        type_url: PROCESS_TYPE_URL.into(),
        value: json.as_bytes().to_vec(),
    })
    .expect("spec")
}

fn ok_spec() -> ExecProcessSpec {
    spec_of(r#"{"cwd":"/","args":["/bin/true"]}"#)
}

fn eid() -> ExecId {
    ExecId::new("e1").expect("exec id")
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).expect("id")
}

fn gone(pid: u32) -> bool {
    let until = Instant::now() + WAIT;
    while Instant::now() < until {
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// zombie でない生存。
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map(|s| !s.contains(") Z "))
        .unwrap_or(false)
}

/// 受理後に `Started` を送り、続けて `outcome` を返す script。
fn finishing(outcome: StreamExecOutcome) -> Script {
    let outcome = Mutex::new(Some(outcome));
    Arc::new(move |end, mask| {
        recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, deadline()).expect("started");
        if let Some(o) = outcome.lock().expect("lock").take() {
            send_result(&end, &o, deadline()).expect("result");
        }
    })
}

/// `Started` の後は何も送らず保持する script（最長 10 秒）。
fn holding() -> Script {
    Arc::new(|end, mask| {
        recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, deadline()).expect("started");
        std::thread::sleep(Duration::from_secs(10));
    })
}

fn never_cancel() -> bool {
    false
}

/// CRI-5: 終了コード 0 と 3 が status と wait_exit に具体値で届く。
#[test]
fn cri5_4148_exit_codes_reach_status_and_wait() {
    for code in [0u8, 3] {
        let fx = Fixture::new("exit");
        let (l, _) = fx.launcher(
            finishing(StreamExecOutcome::Exited(code)),
            probe(0),
            ExecBudgets::default(),
        );
        let p = l.launch(&cid("run1"), &eid(), &ok_spec()).expect("launch");
        assert_eq!(p.pid(), None);
        let got = p.wait_exit(WAIT, Duration::from_millis(10), &never_cancel);
        assert_eq!(got, Ok(Some(i32::from(code))));
        assert_eq!(
            p.status(),
            Ok(ExecProcessStatus::Exited {
                code: Some(i32::from(code))
            })
        );
        assert_eq!(
            p.signal(Signal::SIGKILL).err().map(|e| e.code()),
            Some(CriErrorCode::NotFound)
        );
    }
}

/// CRI-5: シグナルで終わった exec は 128 + 番号。
#[test]
fn cri5_4148_signaled_exit_is_128_plus_signal() {
    let fx = Fixture::new("sig");
    let (l, _) = fx.launcher(
        finishing(StreamExecOutcome::Signaled(
            ExitSignal::new(9).expect("sig"),
        )),
        probe(0),
        ExecBudgets::default(),
    );
    let p = l.launch(&cid("run1"), &eid(), &ok_spec()).expect("launch");
    assert_eq!(
        p.wait_exit(WAIT, Duration::from_millis(10), &never_cancel),
        Ok(Some(137))
    );
}

/// SEC-1: SIGKILL は helper だけに届き init には届かない。以後は未確認を保ち、probe が Confirmed のときだけ終了へ進む。
#[test]
fn sec1_4148_sigkill_hits_only_helper_and_stays_unconfirmed() {
    let fx = Fixture::new("kill");
    let pr = probe(0);
    let (l, pids) = fx.launcher(holding(), Arc::clone(&pr), ExecBudgets::default());
    let p = l.launch(&cid("run1"), &eid(), &ok_spec()).expect("launch");
    assert_eq!(p.status(), Ok(ExecProcessStatus::Running));
    assert_eq!(l.tracked_helpers(), 1);
    let helper = *pids.lock().expect("lock").first().expect("helper pid");
    assert_ne!(helper, fx.init.id());

    assert_eq!(
        p.signal(Signal::new(15).expect("sig"))
            .err()
            .map(|e| e.code()),
        Some(CriErrorCode::Unimplemented)
    );
    assert!(alive(helper));

    p.signal(Signal::SIGKILL).expect("kill");
    assert!(gone(helper), "helper must be reaped");
    assert!(alive(fx.init.id()), "init must survive");
    assert_eq!(l.tracked_helpers(), 0);

    for _ in 0..2 {
        let e = p.status().expect_err("unconfirmed");
        assert_eq!(e.code(), CriErrorCode::Unavailable);
        assert_eq!(e.message(), "exec termination is not confirmed");
    }
    assert_eq!(
        p.wait_exit(
            Duration::from_millis(200),
            Duration::from_millis(10),
            &never_cancel
        )
        .err()
        .map(|e| e.code()),
        Some(CriErrorCode::Unavailable)
    );
    // 未確認の間の 2 回目の SIGKILL も成功する（helper が無ければ止まっている）。
    p.signal(Signal::SIGKILL).expect("second kill");

    pr.0.store(2, Ordering::SeqCst);
    assert!(p.status().is_err());
    pr.0.store(1, Ordering::SeqCst);
    assert_eq!(p.status(), Ok(ExecProcessStatus::Exited { code: None }));
    assert_eq!(
        p.wait_exit(WAIT, Duration::from_millis(10), &never_cancel),
        Ok(None)
    );
}

/// CRI-5・REPAIR-3: `Started` の後の `Failed` は未確認になり、Confirmed で終了へ進む。
#[test]
fn cri5_4148_failed_after_started_is_unconfirmed() {
    let fx = Fixture::new("failed");
    let pr = probe(0);
    let (l, _) = fx.launcher(
        finishing(StreamExecOutcome::Failed(ErrorCode::Timeout)),
        Arc::clone(&pr),
        ExecBudgets::default(),
    );
    let p = l.launch(&cid("run1"), &eid(), &ok_spec()).expect("launch");
    let until = Instant::now() + WAIT;
    let err = loop {
        if let Err(e) = p.status() {
            break e;
        }
        assert!(Instant::now() < until, "must become unconfirmed");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(err.code(), CriErrorCode::Timeout);
    pr.0.store(1, Ordering::SeqCst);
    assert_eq!(p.status(), Ok(ExecProcessStatus::Exited { code: None }));
}

/// CRI-5: 起動の失敗は固定語彙の種別になり、helper は起動しないか止まっている。
#[test]
fn cri5_4148_launch_failures_map_to_fixed_codes() {
    let fx = Fixture::new("fail");
    let (l, pids) = fx.launcher(holding(), probe(0), ExecBudgets::default());
    let code = |c: &str, s: &ExecProcessSpec| l.launch(&cid(c), &eid(), s).err().expect("err");
    let e = code("nosuch", &ok_spec());
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::NotFound, "container not found")
    );
    for c in ["stopped1", "created1"] {
        let e = code(c, &ok_spec());
        assert_eq!(
            (e.code(), e.message()),
            (CriErrorCode::FailedPrecondition, "container is not running")
        );
    }
    let e = code(
        "run1",
        &spec_of(r#"{"cwd":"/","args":["/bin/true"],"env":["A=b"]}"#),
    );
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::Unimplemented, "exec env is not supported")
    );
    let e = code("run1", &spec_of(r#"{"cwd":"/tmp","args":["/bin/true"]}"#));
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::Unimplemented, "exec cwd is not supported")
    );
    let e = code(
        "run1",
        &spec_of(r#"{"cwd":"/","args":["/bin/true"],"user":{"uid":1}}"#),
    );
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::Unimplemented, "exec user is not supported")
    );
    let e = code("run1", &spec_of(r#"{"cwd":"/","args":["true"]}"#));
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::InvalidArgument, "exec request was rejected")
    );
    assert!(
        pids.lock().expect("lock").is_empty(),
        "no helper may be spawned"
    );
    assert_eq!(l.tracked_helpers(), 0);
}

/// CRI-5: `Started` より前の `Result(Failed)` は起動の失敗として写され、helper は止まる。
#[test]
fn cri5_4148_result_before_started_is_launch_failure() {
    let fx = Fixture::new("early");
    let script: Script = Arc::new(|end, mask| {
        recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_result(
            &end,
            &StreamExecOutcome::Failed(ErrorCode::FailedPrecondition),
            deadline(),
        )
        .expect("result");
        std::thread::sleep(Duration::from_secs(1));
    });
    let (l, pids) = fx.launcher(script, probe(0), ExecBudgets::default());
    let e = l
        .launch(&cid("run1"), &eid(), &ok_spec())
        .err()
        .expect("err");
    assert_eq!(
        (e.code(), e.message()),
        (
            CriErrorCode::FailedPrecondition,
            "exec target is not running"
        )
    );
    let helper = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(helper));
    assert_eq!(l.tracked_helpers(), 0);
}

/// REPAIR-5: `Result` が来ないときは受信期限で helper を kill して未確認にし、wait は期限で `DEADLINE_EXCEEDED` になる。
#[test]
fn repair5_4148_result_deadline_kills_helper() {
    let fx = Fixture::new("deadline");
    let (l, pids) = fx.launcher(holding(), probe(0), short());
    let p = l.launch(&cid("run1"), &eid(), &ok_spec()).expect("launch");
    let e = p
        .wait_exit(
            Duration::from_millis(50),
            Duration::from_millis(10),
            &never_cancel,
        )
        .expect_err("timeout");
    assert_eq!(e.code(), CriErrorCode::Timeout);
    let helper = *pids.lock().expect("lock").first().expect("pid");
    assert!(
        gone(helper),
        "helper must be reaped after the result deadline"
    );
    let until = Instant::now() + WAIT;
    while p.status().is_ok() {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        p.status().err().map(|e| e.code()),
        Some(CriErrorCode::Unavailable)
    );
    assert_eq!(l.tracked_helpers(), 0);
}

/// REPAIR-5: `Started` が来なければ期限で失敗し、helper が回収される。
#[test]
fn repair5_4148_started_deadline_kills_helper() {
    let fx = Fixture::new("started");
    let script: Script = Arc::new(|end, mask| {
        recv_stdio_handover(&end, mask, deadline()).expect("handover");
        std::thread::sleep(Duration::from_secs(2));
    });
    let (l, pids) = fx.launcher(script, probe(0), short());
    let e = l
        .launch(&cid("run1"), &eid(), &ok_spec())
        .err()
        .expect("err");
    assert_eq!(e.code(), CriErrorCode::Timeout);
    let helper = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(helper));
    assert_eq!(l.tracked_helpers(), 0);
}

/// REPAIR-5: wait は取り消しで `UNAVAILABLE` になる。
#[test]
fn repair5_4148_wait_is_cancellable() {
    let fx = Fixture::new("cancel");
    let (l, _) = fx.launcher(holding(), probe(0), ExecBudgets::default());
    let p = l.launch(&cid("run1"), &eid(), &ok_spec()).expect("launch");
    let e = p
        .wait_exit(WAIT, Duration::from_millis(10), &|| true)
        .expect_err("cancelled");
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::Unavailable, "wait cancelled")
    );
    l.shutdown_all();
}

/// 契約: ハンドルの drop は helper を止めない。shutdown_all で止まり、以後の launch は拒否される。
#[test]
fn repair5_4148_drop_keeps_helper_and_shutdown_stops_it() {
    let fx = Fixture::new("drop");
    let (l, pids) = fx.launcher(holding(), probe(0), ExecBudgets::default());
    let p = l.launch(&cid("run1"), &eid(), &ok_spec()).expect("launch");
    let helper = *pids.lock().expect("lock").first().expect("pid");
    drop(p);
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        alive(helper),
        "dropping the handle must not stop the helper"
    );
    assert_eq!(l.tracked_helpers(), 1);
    l.shutdown_all();
    assert!(gone(helper));
    let e = l
        .launch(&cid("run1"), &eid(), &ok_spec())
        .err()
        .expect("stopped");
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::Unavailable, "exec launcher is stopped")
    );
}
