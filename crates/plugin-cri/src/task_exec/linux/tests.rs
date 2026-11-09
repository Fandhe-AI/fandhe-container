//! `ShimExecLauncher` の試験（CRI-5・CRI-1・SEC-1・REPAIR-5・#4148）。root も実コンテナも使わず、偽の helper
//! （`/bin/sleep` を helper の `Child` とし、channel の相手は試験スレッドが演じる）で終了コードの写像・kill の範囲・
//! 未確認の保持・期限・drop の契約を具体値で照合する。実 supervisor と実コンテナでの通しは #4150。
//! #4221 の消滅確認（`Started` が運ぶ exec 子 cgroup の名前を probe へ渡す・確認できた exec だけ終了へ進める・版の不一致は拒否）も
//! 偽の probe で照合する。Delete が登録を除去する側（`Exited` なら除去・`Err` なら拒否）は cri の
//! `task_service` の試験（`cri5_3681_delete_exec_each_status` ほか）が `TaskExecProcess` の状態ごとに照合している。

use std::os::fd::OwnedFd;
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};

use fandhe_container_core::exec::ExecError;
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ListStateRequest,
    StateList, StateRecord, TraitError, UpdateStateRequest,
};
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::shim_v2::exec::{PROCESS_TYPE_URL, parse_process_spec};
use fandhe_container_cri::shim_v2::task_api::Any;
use fandhe_container_supervisor::stream_exec::channel::{
    recv_stdio_handover, send_result, send_signal_ack, send_spawned, send_started,
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
            diagnostics: None,
        })
    }

    fn capabilities(&self) -> crate::streaming::exec_launcher::HelperCapabilities {
        Default::default()
    }
}

/// 偽の helper が `Started` で運ぶ exec 子 cgroup の名前。
const CG: &str = "exec-4242-0";

fn cg() -> ExecCgroupName {
    ExecCgroupName::new(CG).expect("name")
}

/// 試験が結果を切り替えられる probe（0: Unknown、1: Confirmed、2: Failed）。受け取った target も記録する。
struct FakeProbe(AtomicU8, Mutex<Vec<ExecExtinctionTarget>>);

impl ExecExtinctionProbe for FakeProbe {
    fn confirm(&self, t: &ExecExtinctionTarget) -> ExtinctionOutcome {
        self.1.lock().expect("lock").push(t.clone());
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

    /// 状態記録が今報告しているインスタンス識別子（登録時の値の代わりに渡す。存在しなければ `None`）。
    fn instance(&self, name: &str) -> Option<u64> {
        let id = ContainerId::new(name).expect("id");
        self.store
            .get(&GetStateRequest::new(id))
            .ok()
            .and_then(|r| r.instance().map(ContainerInstance::value))
    }

    /// 同じ ID のコンテナを外側（CLI 等）で削除・再作成して Running にする（インスタンスが変わる。#4323）。
    fn recreate_running(&self, name: &str, pid: u32) {
        let id = ContainerId::new(name).expect("id");
        let old = self
            .store
            .get(&GetStateRequest::new(id.clone()))
            .expect("get");
        self.store
            .delete(&DeleteStateRequest::new(id.clone(), old.revision()))
            .expect("delete");
        let created = self
            .store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(id.clone(), None),
                    self.dir.0.join("bundle"),
                )
                .expect("req"),
            )
            .expect("create");
        self.store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id, NonZeroU32::new(pid)),
                created.revision(),
            ))
            .expect("running");
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
    Arc::new(FakeProbe(AtomicU8::new(v), Mutex::new(Vec::new())))
}

fn short() -> ExecBudgets {
    ExecBudgets {
        handover: WAIT,
        started: Duration::from_millis(300),
        session: Duration::from_millis(200),
        result_grace: Duration::from_millis(200),
        extinction_grace: Duration::from_millis(300),
        signal_ack: Duration::from_millis(400),
        spawned: Duration::from_millis(100),
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
        send_started(&end, &cg(), deadline()).expect("started");
        if let Some(o) = outcome.lock().expect("lock").take() {
            send_result(&end, &o, deadline()).expect("result");
        }
    })
}

/// `Started` の後は何も送らず保持する script（最長 10 秒）。
fn holding() -> Script {
    Arc::new(|end, mask| {
        recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg(), deadline()).expect("started");
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
        let p = l
            .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
            .expect("launch");
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
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
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
    let budgets = ExecBudgets {
        extinction_grace: Duration::from_millis(100),
        ..ExecBudgets::default()
    };
    let (l, pids) = fx.launcher(holding(), Arc::clone(&pr), budgets);
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    assert_eq!(p.status(), Ok(ExecProcessStatus::Running));
    assert_eq!(l.tracked_helpers(), 1);
    let helper = *pids.lock().expect("lock").first().expect("helper pid");
    assert_ne!(helper, fx.init.id());

    // 許可リスト外（SIGSTOP 19・SIGCONT 18）は従来どおり `UNIMPLEMENTED`（#4282）。helper は無傷。
    for n in [19u8, 18] {
        assert_eq!(
            p.signal(Signal::new(n).expect("sig"))
                .err()
                .map(|e| e.code()),
            Some(CriErrorCode::Unimplemented),
            "signal {n}"
        );
    }
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
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
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

/// `Started` の後に `Spawned(4242)` を送り（`gap` の後）、続けて `then` を実行して保持する script（#4316）。
fn spawning(gap: Duration, spawn_count: usize, outcome: Option<StreamExecOutcome>) -> Script {
    let outcome = Mutex::new(outcome);
    Arc::new(move |end, mask| {
        recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg(), deadline()).expect("started");
        std::thread::sleep(gap);
        for _ in 0..spawn_count {
            send_spawned(&end, NonZeroU32::new(4242).expect("pid"), deadline()).expect("spawned");
        }
        if let Some(o) = outcome.lock().expect("lock").take() {
            send_result(&end, &o, deadline()).expect("result");
        }
        std::thread::sleep(Duration::from_secs(10));
    })
}

/// CRI-5・SUP-6・#4318: launch は `Spawned` を待ってから返すため、戻りの時点で `pid()` は具体値 4242。`Result` の後も保たれる。
#[test]
fn cri5_4318_launch_waits_for_spawned() {
    let fx = Fixture::new("spawned");
    let (l, _) = fx.launcher(
        spawning(
            Duration::from_millis(300),
            1,
            Some(StreamExecOutcome::Exited(0)),
        ),
        probe(0),
        ExecBudgets::default(),
    );
    let t = Instant::now();
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    assert_eq!(p.pid(), NonZeroU32::new(4242));
    assert!(t.elapsed() >= Duration::from_millis(300));
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(
        p.wait_exit(WAIT, Duration::from_millis(10), &never_cancel),
        Ok(Some(0))
    );
    assert_eq!(p.pid(), NonZeroU32::new(4242));
}

/// CRI-5・SUP-6・#4318: 予算内に `Spawned` が届かなければ launch は成功したまま `pid()` は `None`。後で届けば値になる。
#[test]
fn cri5_4318_spawned_after_budget_is_none_then_value() {
    let fx = Fixture::new("spawnedlate");
    let budgets = ExecBudgets {
        spawned: Duration::from_millis(50),
        ..ExecBudgets::default()
    };
    let (l, _) = fx.launcher(
        spawning(
            Duration::from_millis(400),
            1,
            Some(StreamExecOutcome::Exited(0)),
        ),
        probe(0),
        budgets,
    );
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    assert_eq!(p.pid(), None, "Spawned has not arrived within the budget");
    assert_eq!(
        p.wait_exit(WAIT, Duration::from_millis(10), &never_cancel),
        Ok(Some(0))
    );
    assert_eq!(p.pid(), NonZeroU32::new(4242));
}

/// REPAIR-5・CRI-5・#4318: `Spawned` も `Result` も来ない保持では、待ちは `spawned` の予算で打ち切られ pid 不明の Running を返す。
#[test]
fn repair5_4318_holding_without_spawned_is_bounded() {
    let fx = Fixture::new("spawnedhold");
    let budgets = ExecBudgets {
        spawned: Duration::from_millis(200),
        ..ExecBudgets::default()
    };
    let (l, _) = fx.launcher(holding(), probe(0), budgets);
    let t = Instant::now();
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    assert!(t.elapsed() >= Duration::from_millis(200));
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(p.pid(), None);
    assert_eq!(p.status(), Ok(ExecProcessStatus::Running));
}

/// CRI-5・SUP-6・#4316: `Spawned` が無いまま `Result` が来ても正当で、`pid()` は `None` のまま。`wait_exit` は終了コードを返す。
#[test]
fn cri5_4316_shim_result_without_spawned_keeps_pid_none() {
    let fx = Fixture::new("nospawn");
    let budgets = ExecBudgets {
        spawned: Duration::from_secs(5),
        ..ExecBudgets::default()
    };
    let (l, _) = fx.launcher(
        spawning(Duration::ZERO, 0, Some(StreamExecOutcome::Exited(0))),
        probe(0),
        budgets,
    );
    let t = Instant::now();
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    assert!(
        t.elapsed() < Duration::from_secs(1),
        "a Result without Spawned must not consume the budget"
    );
    assert_eq!(
        p.wait_exit(WAIT, Duration::from_millis(10), &never_cancel),
        Ok(Some(0))
    );
    assert_eq!(p.pid(), None);
}

/// SEC-1・SUP-6・#4316: `Spawned` が 2 回来るのはプロトコル違反。helper を止めて未確認に倒し、最初の pid を保つ。
#[test]
fn sec1_4316_shim_duplicate_spawned_is_unconfirmed() {
    let fx = Fixture::new("dupspawn");
    let (l, pids) = fx.launcher(
        spawning(Duration::from_millis(50), 2, None),
        probe(0),
        ExecBudgets::default(),
    );
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    let helper = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(helper), "helper must be killed");
    assert_eq!(
        p.status().expect_err("unconfirmed").code(),
        CriErrorCode::Unavailable
    );
    assert_eq!(p.pid(), NonZeroU32::new(4242));
}

/// CRI-5: 起動の失敗は固定語彙の種別になり、helper は起動しないか止まっている。
#[test]
fn cri5_4148_launch_failures_map_to_fixed_codes() {
    let fx = Fixture::new("fail");
    let (l, pids) = fx.launcher(holding(), probe(0), ExecBudgets::default());
    let code = |c: &str, s: &ExecProcessSpec| {
        l.launch(&cid(c), &eid(), s, fx.instance(c))
            .err()
            .expect("err")
    };
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
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
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
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
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
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
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
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
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
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
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
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .err()
        .expect("stopped");
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::Unavailable, "exec launcher is stopped")
    );
}

/// 材料を 1 つ書き換えた `FakeProbe` の記録を取り出す。
fn recorded(pr: &FakeProbe) -> Vec<ExecExtinctionTarget> {
    pr.1.lock().expect("lock").clone()
}

/// CRI-5・SEC-1・#4221: kill の後の確認で、`Started` が運んだ exec 子 cgroup の名前と launch 時のコンテナが probe へ渡る。
#[test]
fn cri5_4221_started_cgroup_name_reaches_probe() {
    let fx = Fixture::new("name");
    let pr = probe(0);
    let (l, _) = fx.launcher(holding(), Arc::clone(&pr), ExecBudgets::default());
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    p.signal(Signal::SIGKILL).expect("kill");
    assert!(p.status().is_err());
    let got = recorded(&pr);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].cgroup.as_str(), "exec-4242-0");
    assert_eq!(got[0].container.as_str(), "run1");
    // fixture の記録には cgroup 配置が無い（launch の時点の値を保持する）。
    assert!(got[0].placement.is_none());
}

/// CRI-5・REPAIR-5・#4221: kill した exec は、回収が少し遅れて確認できても Wait が終了（コード無し）を返す。
#[test]
fn cri5_4221_kill_then_confirmed_wait_returns_exit() {
    let fx = Fixture::new("killwait");
    let pr = probe(0);
    let budgets = ExecBudgets {
        extinction_grace: Duration::from_secs(5),
        ..ExecBudgets::default()
    };
    let (l, _) = fx.launcher(holding(), Arc::clone(&pr), budgets);
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    p.signal(Signal::SIGKILL).expect("kill");
    let flip = Arc::clone(&pr);
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        flip.0.store(1, Ordering::SeqCst);
    });
    assert_eq!(
        p.wait_exit(WAIT, Duration::from_millis(10), &never_cancel),
        Ok(None)
    );
    t.join().expect("join");
    assert_eq!(p.status(), Ok(ExecProcessStatus::Exited { code: None }));
    assert!(
        recorded(&pr).len() >= 2,
        "the probe is polled during the wait"
    );
}

/// CRI-5・REPAIR-5・#4221: 監視期限が切れた exec も、確認できれば Wait が終了を返す（確認できなければ猶予後に UNAVAILABLE）。
#[test]
fn cri5_4221_expired_then_confirmed_wait_returns_exit() {
    let fx = Fixture::new("expired");
    let pr = probe(0);
    let budgets = ExecBudgets {
        extinction_grace: Duration::from_secs(5),
        ..short()
    };
    let (l, _) = fx.launcher(holding(), Arc::clone(&pr), budgets);
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    let flip = Arc::clone(&pr);
    // session 200ms + grace 200ms で監視期限が切れた後に回収が済んだ想定。
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(600));
        flip.0.store(1, Ordering::SeqCst);
    });
    assert_eq!(
        p.wait_exit(WAIT, Duration::from_millis(10), &never_cancel),
        Ok(None)
    );
    t.join().expect("join");
}

/// CRI-5・REPAIR-3・#4221: helper 自身の `Failed(Timeout)` の後も、確認できれば Wait が終了を返す。
#[test]
fn cri5_4221_helper_failed_then_confirmed_wait_returns_exit() {
    let fx = Fixture::new("hfailed");
    let (l, _) = fx.launcher(
        finishing(StreamExecOutcome::Failed(ErrorCode::Timeout)),
        probe(1),
        ExecBudgets::default(),
    );
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    assert_eq!(
        p.wait_exit(WAIT, Duration::from_millis(10), &never_cancel),
        Ok(None)
    );
}

/// SEC-1・CRI-5・#4221: 確認できないままなら `UNAVAILABLE` を保つ（猶予の後に同じコードで失敗し、status も未確認）。
#[test]
fn sec1_4221_unconfirmed_keeps_unavailable_after_grace() {
    let fx = Fixture::new("keep");
    let pr = probe(0);
    let budgets = ExecBudgets {
        extinction_grace: Duration::from_millis(200),
        ..ExecBudgets::default()
    };
    let (l, _) = fx.launcher(holding(), Arc::clone(&pr), budgets);
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    p.signal(Signal::SIGKILL).expect("kill");
    let t = Instant::now();
    let e = p
        .wait_exit(WAIT, Duration::from_millis(10), &never_cancel)
        .expect_err("unconfirmed");
    assert_eq!(
        (e.code(), e.message()),
        (
            CriErrorCode::Unavailable,
            "exec termination is not confirmed"
        )
    );
    assert!(t.elapsed() >= Duration::from_millis(200));
    assert!(t.elapsed() < Duration::from_secs(3));
    let e = p.status().expect_err("still unconfirmed");
    assert_eq!(e.code(), CriErrorCode::Unavailable);
}

/// REPAIR-5・#4221: Wait 全体の期限が確認の猶予より先に来たら `DEADLINE_EXCEEDED`、取り消しは `UNAVAILABLE`。
#[test]
fn repair5_4221_wait_deadline_and_cancel_win_over_grace() {
    let fx = Fixture::new("order");
    let (l, _) = fx.launcher(holding(), probe(0), ExecBudgets::default());
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    p.signal(Signal::SIGKILL).expect("kill");
    let e = p
        .wait_exit(
            Duration::from_millis(100),
            Duration::from_millis(10),
            &never_cancel,
        )
        .expect_err("timeout");
    assert_eq!(e.code(), CriErrorCode::Timeout);
    let e = p
        .wait_exit(WAIT, Duration::from_millis(10), &|| true)
        .expect_err("cancelled");
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::Unavailable, "wait cancelled")
    );
}

/// SEC-1・#4221: 本番の probe は記録に cgroup 配置が無ければ確認の材料が無く `Unknown`（fail-closed）。
#[test]
fn sec1_4221_production_probe_without_placement_is_unknown() {
    let t = ExecExtinctionTarget {
        container: cid("run1"),
        placement: None,
        cgroup: cg(),
    };
    assert_eq!(
        CgroupExtinctionProbe.confirm(&t),
        ExtinctionOutcome::Unknown
    );
}

/// SEC-1・#4221: core の確認結果の写像。不在だけが `Confirmed`、残っている・失敗は `Unknown`。
#[test]
fn sec1_4221_production_probe_mapping() {
    let map = CgroupExtinctionProbe::map_presence;
    assert_eq!(
        map(Ok(ExecCgroupPresence::Absent)),
        ExtinctionOutcome::Confirmed
    );
    assert_eq!(
        map(Ok(ExecCgroupPresence::ContainerCgroupAbsent)),
        ExtinctionOutcome::Confirmed
    );
    assert_eq!(
        map(Ok(ExecCgroupPresence::Present)),
        ExtinctionOutcome::Unknown
    );
    let err: ExecError = ExecCgroupName::new("bad").expect_err("invalid name");
    assert_eq!(map(Err(err)), ExtinctionOutcome::Unknown);
}

/// SEC-1・REPAIR-3・#4221: 旧い version 1 の `Started`（payload なし）は拒否され、launch は失敗して helper は止まり、probe は呼ばれない。
/// 不正な名前欄の `Started`（version 4）と、version 2・3 の正しい `Started`（#4282・#4316）も同じ。確認済みとして扱わない（fail-closed）。
#[test]
fn sec1_4221_v1_or_malformed_started_is_rejected_and_never_confirmed() {
    use std::io::Write as _;
    let frames: [Vec<u8>; 4] = [
        // version 1 の `Started`（header のみ）。
        b"FCSX\x01\x02\x00\x00".to_vec(),
        // version 4 だが名前欄が不正（name_len = 0）。
        {
            let mut v = b"FCSX\x04\x02\x00\x41".to_vec();
            v.extend_from_slice(&[0u8; 65]);
            v
        },
        // version 2・3 の正しい `Started`（name_len = 11 の `exec-4242-0`。v4 の相手とは混在させない。#4282・#4316）。
        {
            let mut v = b"FCSX\x02\x02\x00\x41".to_vec();
            let mut name = [0u8; 65];
            name[0] = 11;
            name[1..12].copy_from_slice(b"exec-4242-0");
            v.extend_from_slice(&name);
            v
        },
        {
            let mut v = b"FCSX\x03\x02\x00\x41".to_vec();
            let mut name = [0u8; 65];
            name[0] = 11;
            name[1..12].copy_from_slice(b"exec-4242-0");
            v.extend_from_slice(&name);
            v
        },
    ];
    for bytes in frames {
        let fx = Fixture::new("v1");
        let bytes = Arc::new(bytes);
        let script: Script = Arc::new(move |mut end, mask| {
            recv_stdio_handover(&end, mask, deadline()).expect("handover");
            end.write_all(&bytes).expect("raw frame");
            std::thread::sleep(Duration::from_secs(1));
        });
        let pr = probe(1);
        let (l, pids) = fx.launcher(script, Arc::clone(&pr), ExecBudgets::default());
        let e = l
            .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
            .err()
            .expect("rejected");
        assert_eq!(e.code(), CriErrorCode::InvalidArgument);
        assert_eq!(l.tracked_helpers(), 0);
        let helper = *pids.lock().expect("lock").first().expect("pid");
        assert!(gone(helper), "helper must be reaped");
        assert!(recorded(&pr).is_empty(), "probe must never be consulted");
    }
}

/// 偽の helper が `Signal` frame を受けたときの応答（#4282）。
#[derive(Clone, Copy)]
enum Reply {
    /// この code の `SignalAck` を返し、保持を続ける。
    Ack(SignalAckCode),
    /// 何も返さない。
    Silent,
    /// 要求と違う番号（SIGHUP）の ack を返す。
    WrongNumber,
    /// `delivered` の ack の後に `Result(Signaled(15))` を返す。
    DeliveredThenTerminated,
    /// 1 件目だけ `delay` 待ってから `delivered` の ack を返し、2 件目以降は即座に返す（期限切れ後の遅延 ack の再現）。
    FirstAckDelayed(Duration),
}

/// `Started` の後に `Signal` frame（生の 9 バイト）を読み、`log` へ積んで `reply` に従う script（最長 10 秒保持）。
fn signal_script(reply: Reply, log: Arc<Mutex<Vec<Vec<u8>>>>) -> Script {
    use std::io::Read as _;
    Arc::new(move |mut end, mask| {
        recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg(), deadline()).expect("started");
        end.set_read_timeout(Some(Duration::from_millis(500)))
            .expect("timeout");
        let end_until = Instant::now() + Duration::from_secs(10);
        let mut seen = 0usize;
        while Instant::now() < end_until {
            let mut frame = [0u8; 9];
            match end.read_exact(&mut frame) {
                Ok(()) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => return,
            }
            log.lock().expect("lock").push(frame.to_vec());
            let requested = ExecSignal::new(frame[8]).expect("allowed signal");
            seen += 1;
            match reply {
                Reply::FirstAckDelayed(delay) => {
                    if seen == 1 {
                        std::thread::sleep(delay);
                    }
                    send_signal_ack(&end, requested, SignalAckCode::Delivered, deadline())
                        .expect("ack");
                }
                Reply::Ack(code) => {
                    send_signal_ack(&end, requested, code, deadline()).expect("ack");
                }
                Reply::Silent => {}
                Reply::WrongNumber => {
                    send_signal_ack(
                        &end,
                        ExecSignal::new(1).expect("hup"),
                        SignalAckCode::Delivered,
                        deadline(),
                    )
                    .expect("ack");
                }
                Reply::DeliveredThenTerminated => {
                    send_signal_ack(&end, requested, SignalAckCode::Delivered, deadline())
                        .expect("ack");
                    send_result(
                        &end,
                        &StreamExecOutcome::Signaled(ExitSignal::new(15).expect("15")),
                        deadline(),
                    )
                    .expect("result");
                    return;
                }
            }
        }
    })
}

fn new_log() -> Arc<Mutex<Vec<Vec<u8>>>> {
    Arc::new(Mutex::new(Vec::new()))
}

/// CRI-5・SUP-6・SEC-1・#4282: SIGTERM は `Signal` frame の生のバイト列（版 3・kind 5・番号 15）で helper へ届き、
/// `delivered` の ack で `Ok`。helper が返す `Signaled(15)` は 143 になる。
#[test]
fn cri5_4282_sigterm_is_sent_as_a_signal_frame_and_ends_with_143() {
    let fx = Fixture::new("sigterm");
    let log = new_log();
    let (l, _) = fx.launcher(
        signal_script(Reply::DeliveredThenTerminated, Arc::clone(&log)),
        probe(0),
        ExecBudgets::default(),
    );
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    p.signal(Signal::SIGTERM).expect("signal");
    assert_eq!(
        *log.lock().expect("lock"),
        vec![b"FCSX\x04\x05\x00\x01\x0f".to_vec()]
    );
    assert_eq!(
        p.wait_exit(WAIT, Duration::from_millis(10), &never_cancel),
        Ok(Some(143))
    );
    assert_eq!(
        p.signal(Signal::SIGTERM).err().map(|e| e.code()),
        Some(CriErrorCode::NotFound),
        "finished exec"
    );
}

/// CRI-5・SUP-6・#4282: ack の code ごとの CRI の結果（not_started → `FAILED_PRECONDITION`・exited → `NOT_FOUND`・
/// unavailable → `UNAVAILABLE`）。exec は Running のまま、helper は生きている。
#[test]
fn cri5_4282_ack_codes_map_to_cri_errors() {
    for (code, expect, message) in [
        (
            SignalAckCode::NotStarted,
            CriErrorCode::FailedPrecondition,
            "exec process is not started yet",
        ),
        (
            SignalAckCode::Exited,
            CriErrorCode::NotFound,
            "process already finished",
        ),
        (
            SignalAckCode::Unavailable,
            CriErrorCode::Unavailable,
            "exec signal could not be delivered",
        ),
    ] {
        let fx = Fixture::new("ackmap");
        let log = new_log();
        let (l, pids) = fx.launcher(
            signal_script(Reply::Ack(code), Arc::clone(&log)),
            probe(0),
            ExecBudgets::default(),
        );
        let p = l
            .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
            .expect("launch");
        let e = p.signal(Signal::SIGTERM).expect_err("rejected");
        assert_eq!(e.code(), expect);
        assert_eq!(e.message(), message);
        assert_eq!(p.status(), Ok(ExecProcessStatus::Running));
        let helper = *pids.lock().expect("lock").first().expect("pid");
        assert!(alive(helper));
        // 次の要求も同じ経路で通る（1 件ずつ排他して順に処理される）。
        let e2 = p.signal(Signal::new(10).expect("usr1")).expect_err("again");
        assert_eq!(e2.code(), expect);
        assert_eq!(log.lock().expect("lock").len(), 2);
    }
}

/// REPAIR-5・#4282: ack が来なければ期限で `DEADLINE_EXCEEDED`（Timeout）。exec は Running のまま。
#[test]
fn repair5_4282_missing_ack_times_out() {
    let fx = Fixture::new("noack");
    let log = new_log();
    let (l, _) = fx.launcher(
        signal_script(Reply::Silent, Arc::clone(&log)),
        probe(0),
        short_with_long_session(),
    );
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    let begin = Instant::now();
    let e = p.signal(Signal::SIGTERM).expect_err("no ack");
    assert_eq!(e.code(), CriErrorCode::Timeout);
    assert_eq!(e.message(), "exec signal was not acknowledged");
    assert!(begin.elapsed() >= Duration::from_millis(400));
    assert_eq!(p.status(), Ok(ExecProcessStatus::Running));
}

/// REPAIR-5・SUP-6・CRI-6・#4282: 期限切れの要求に遅れて届く正常な ack では exec を止めない（helper は無傷で Running のまま）。
#[test]
fn repair5_4282_late_ack_after_timeout_does_not_kill_exec() {
    let fx = Fixture::new("lateack");
    let log = new_log();
    let (l, pids) = fx.launcher(
        signal_script(
            Reply::FirstAckDelayed(Duration::from_millis(900)),
            Arc::clone(&log),
        ),
        probe(0),
        short_with_long_session(),
    );
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    let e = p.signal(Signal::SIGTERM).expect_err("timeout");
    assert_eq!(e.code(), CriErrorCode::Timeout);
    // 遅れた ack が届く時間を待つ。
    std::thread::sleep(Duration::from_millis(900));
    let helper = *pids.lock().expect("lock").first().expect("pid");
    assert!(alive(helper), "late ack must not stop the helper");
    assert_eq!(p.status(), Ok(ExecProcessStatus::Running));
    // 以後の要求は通常どおり成功する。
    p.signal(Signal::SIGTERM).expect("next request succeeds");
    assert_eq!(log.lock().expect("lock").len(), 2);
}

/// REPAIR-5・#4282: 期限切れ → 再要求のとき、古い ack は新要求の成功にならず消費され、2 件目の ack が新要求の成功になる（停止なし）。
#[test]
fn repair5_4282_timeout_then_retry_with_two_acks_succeeds_once() {
    let fx = Fixture::new("retryack");
    let log = new_log();
    let (l, pids) = fx.launcher(
        signal_script(
            Reply::FirstAckDelayed(Duration::from_millis(700)),
            Arc::clone(&log),
        ),
        probe(0),
        short_with_long_session(),
    );
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    let e = p.signal(Signal::SIGTERM).expect_err("timeout");
    assert_eq!(e.code(), CriErrorCode::Timeout);
    // 再要求: 古い ack（約 700ms）を消費したあと、2 件目の ack で成功する。
    p.signal(Signal::SIGTERM).expect("retry succeeds");
    std::thread::sleep(Duration::from_millis(500));
    let helper = *pids.lock().expect("lock").first().expect("pid");
    assert!(alive(helper), "no ack may stop the helper");
    assert_eq!(p.status(), Ok(ExecProcessStatus::Running));
    assert_eq!(log.lock().expect("lock").len(), 2);
}

/// SEC-1・REPAIR-3・#4282: 要求と違う番号の ack はプロトコル違反。helper を止めて未確認にし、要求は `UNAVAILABLE`。
#[test]
fn sec1_4282_wrong_number_ack_kills_helper_and_stays_unconfirmed() {
    let fx = Fixture::new("wrongack");
    let log = new_log();
    let (l, pids) = fx.launcher(
        signal_script(Reply::WrongNumber, Arc::clone(&log)),
        probe(0),
        short_with_long_session(),
    );
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    let e = p.signal(Signal::SIGTERM).expect_err("violation");
    assert_eq!(e.code(), CriErrorCode::Unavailable);
    let helper = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(helper), "helper must be killed");
    assert_eq!(
        p.status().expect_err("unconfirmed").code(),
        CriErrorCode::Unavailable
    );
    // 未確認の exec へ許可されたシグナルは送らない。
    let e = p.signal(Signal::SIGTERM).expect_err("unconfirmed");
    assert_eq!(e.code(), CriErrorCode::Unavailable);
    assert_eq!(log.lock().expect("lock").len(), 1);
}

/// SEC-1・#4282: 許可リスト外（SIGSTOP・SIGCONT・SIGWINCH・実時間シグナル）の番号は `UNIMPLEMENTED` で、frame を 1 バイトも送らない。
#[test]
fn sec1_4282_disallowed_signals_send_no_frame() {
    let fx = Fixture::new("disallowed");
    let log = new_log();
    let (l, pids) = fx.launcher(
        signal_script(Reply::Ack(SignalAckCode::Delivered), Arc::clone(&log)),
        probe(0),
        ExecBudgets::default(),
    );
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    for n in [19u8, 18, 28, 34, 64, 20] {
        let e = p
            .signal(Signal::new(n).expect("sig"))
            .expect_err("rejected");
        assert_eq!(e.code(), CriErrorCode::Unimplemented, "signal {n}");
        assert_eq!(e.message(), "exec signal is not supported");
    }
    std::thread::sleep(Duration::from_millis(700));
    assert!(log.lock().expect("lock").is_empty(), "no frame may be sent");
    let helper = *pids.lock().expect("lock").first().expect("pid");
    assert!(alive(helper));
    assert_eq!(p.status(), Ok(ExecProcessStatus::Running));
}

/// 保持が長く、`signal_ack` だけ短い期限（ack の待ちが先に切れる構成）。
fn short_with_long_session() -> ExecBudgets {
    ExecBudgets {
        started: WAIT,
        session: Duration::from_secs(20),
        result_grace: Duration::from_secs(5),
        signal_ack: Duration::from_millis(500),
        ..ExecBudgets::default()
    }
}

/// 識別子を報告しない（instance を外した record を返す）状態ストア。旧い記録の模擬（#4323）。
struct NoInstanceStore(Arc<FileStateStore>);

impl StateStore for NoInstanceStore {
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        self.0.create(req)
    }
    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        self.0.update(req)
    }
    fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
        let r = self.0.get(req)?;
        StateRecord::new(r.status().clone(), r.bundle().to_path_buf(), r.revision())
    }
    fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError> {
        self.0.list(req)
    }
    fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        self.0.delete(req)
    }
}

/// CRI-5・SEC-1・CORE-1（#4323）: 登録時と同じインスタンスなら起動する。
#[test]
fn cri5_4323_matching_instance_launches() {
    let fx = Fixture::new("t4323-match");
    let (l, pids) = fx.launcher(holding(), probe(0), ExecBudgets::default());
    let inst = fx.instance("run1");
    assert!(inst.is_some(), "store reports an instance");
    l.launch(&cid("run1"), &eid(), &ok_spec(), inst)
        .expect("launch");
    assert_eq!(pids.lock().expect("lock").len(), 1);
}

/// SEC-1・CORE-1（#4323）: 登録後（shim の purge_mismatched の後）に外で作り直されたコンテナへは、
/// 旧登録の argv を起動せず `FAILED_PRECONDITION` で拒否し、helper を起動しない。
#[test]
fn sec1_4323_recreated_between_reads_is_rejected_without_helper() {
    let fx = Fixture::new("t4323-recreate");
    let (l, pids) = fx.launcher(holding(), probe(0), ExecBudgets::default());
    let registered = fx.instance("run1");
    fx.recreate_running("run1", fx.init.id());
    let current = fx.instance("run1");
    assert!(registered.is_some() && current.is_some());
    assert_ne!(registered, current, "recreation changes the instance");
    let e = l
        .launch(&cid("run1"), &eid(), &ok_spec(), registered)
        .err()
        .expect("recreated");
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::FailedPrecondition, MSG_EXEC_INSTANCE_CHANGED)
    );
    assert!(pids.lock().expect("lock").is_empty(), "no helper started");
    assert_eq!(l.tracked_helpers(), 0);
    // 新しい値を控え直した登録は起動する。
    l.launch(&cid("run1"), &eid(), &ok_spec(), current)
        .expect("relaunch");
    assert_eq!(pids.lock().expect("lock").len(), 1);
}

/// 照合は Running の確認より先（#4323）: 作り直された後に停止したコンテナも "not running" ではなく recreated になる。
#[test]
fn sec1_4323_recreated_then_stopped_reports_recreated() {
    let fx = Fixture::new("t4323-stopped");
    let (l, pids) = fx.launcher(holding(), probe(0), ExecBudgets::default());
    let registered = fx.instance("stopped1");
    // stopped1 を別インスタンスに差し替える（Created のまま）。
    let id = cid("stopped1");
    let old = fx
        .store
        .get(&GetStateRequest::new(id.clone()))
        .expect("get");
    fx.store
        .delete(&DeleteStateRequest::new(id.clone(), old.revision()))
        .expect("delete");
    fx.store
        .create(
            &CreateStateRequest::new(
                ContainerStatus::created(id.clone(), None),
                fx.dir.0.join("bundle"),
            )
            .expect("req"),
        )
        .expect("create");
    let e = l
        .launch(&id, &eid(), &ok_spec(), registered)
        .err()
        .expect("err");
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::FailedPrecondition, MSG_EXEC_INSTANCE_CHANGED)
    );
    assert!(pids.lock().expect("lock").is_empty());
}

/// SEC-1（#4323）: 片側だけ None（登録に識別子があり記録に無い・その逆）は拒否する。
#[test]
fn sec1_4323_one_sided_none_is_rejected() {
    let fx = Fixture::new("t4323-onesided");
    let pids = Arc::new(Mutex::new(Vec::new()));
    let l = ShimExecLauncher::with_budgets(
        fx.dir.0.join("state"),
        Arc::new(NoInstanceStore(Arc::clone(&fx.store))) as Arc<dyn StateStore>,
        Arc::new(FakeSpawner {
            script: holding(),
            pids: Arc::clone(&pids),
        }),
        probe(0),
        ExecBudgets::default(),
    );
    // 登録に Some、記録（instance を外した）が None。
    let some = fx.instance("run1");
    assert!(some.is_some());
    let e = l
        .launch(&cid("run1"), &eid(), &ok_spec(), some)
        .err()
        .expect("one-sided");
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::FailedPrecondition, MSG_EXEC_INSTANCE_CHANGED)
    );
    assert!(pids.lock().expect("lock").is_empty());
    // 登録が None、記録が Some（通常の FileStateStore）。
    let (l2, pids2) = fx.launcher(holding(), probe(0), ExecBudgets::default());
    let e = l2
        .launch(&cid("run1"), &eid(), &ok_spec(), None)
        .err()
        .expect("one-sided reverse");
    assert_eq!(e.message(), MSG_EXEC_INSTANCE_CHANGED);
    assert!(pids2.lock().expect("lock").is_empty());
}

/// 残余の固定（#4323）: 両側 None（識別子を報告しない実装・旧い記録）は判定できないので起動する（保護されない）。
#[test]
fn cri5_4323_unreported_instance_on_both_sides_is_not_protected() {
    let fx = Fixture::new("t4323-none");
    let pids = Arc::new(Mutex::new(Vec::new()));
    let l = ShimExecLauncher::with_budgets(
        fx.dir.0.join("state"),
        Arc::new(NoInstanceStore(Arc::clone(&fx.store))) as Arc<dyn StateStore>,
        Arc::new(FakeSpawner {
            script: holding(),
            pids: Arc::clone(&pids),
        }),
        probe(0),
        ExecBudgets::default(),
    );
    l.launch(&cid("run1"), &eid(), &ok_spec(), None)
        .expect("launch");
    assert_eq!(pids.lock().expect("lock").len(), 1);
}

/// 起動役の記録器から操作名の (success, failure) を読む。未記録は `None`（#4379）。
fn counts(l: &ShimExecLauncher, name: &str) -> Option<(u64, u64)> {
    l.recorder()
        .snapshot_op(&fandhe_container_core::observability::OpName::new(name).expect("name"))
        .map(|s| (s.success(), s.failure()))
}

/// REPAIR-4・CRI-5・#4379: `Spawned` が予算内に届かない回は 1 回につきちょうど 1 数える。launch は成功し pid は不明のまま。
#[test]
fn repair4_4379_spawned_budget_expiry_counts_once() {
    let fx = Fixture::new("t4379-expiry");
    let budgets = ExecBudgets {
        spawned: Duration::from_millis(100),
        ..ExecBudgets::default()
    };
    let (l, _) = fx.launcher(holding(), probe(0), budgets);
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    assert_eq!(p.pid(), None);
    assert_eq!(counts(&l, "shim_exec_pid_unreported"), Some((0, 1)));
    l.launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("second launch");
    assert_eq!(counts(&l, "shim_exec_pid_unreported"), Some((0, 2)));
    assert_eq!(counts(&l, "shim_exec_instance_changed"), None);
}

/// #4379・REPAIR-4: 計数と同時に発生時の行が出る（serve 開始後も外から観測できる）。
#[test]
fn repair4_4379_expiry_emits_event_line() {
    let fx = Fixture::new("t4379-emit");
    let budgets = ExecBudgets {
        spawned: Duration::from_millis(100),
        ..ExecBudgets::default()
    };
    let (l, _) = fx.launcher(holding(), probe(0), budgets);
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&lines);
    let l = l.with_event_emit(Arc::new(move |s| sink.lock().unwrap().push(s)));
    l.launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    let got = lines.lock().unwrap().clone();
    assert_eq!(got.len(), 1);
    assert!(
        got[0].starts_with(r#"{"event":"shim_exec_pid_unreported","elapsed_ms":"#)
            && got[0].ends_with('}'),
        "{got:?}"
    );
}

/// #4379: 予算内に `Spawned` が届いた回は数えない。
#[test]
fn repair4_4379_spawned_in_time_is_not_counted() {
    let fx = Fixture::new("t4379-intime");
    let (l, _) = fx.launcher(
        spawning(Duration::from_millis(50), 1, None),
        probe(0),
        ExecBudgets::default(),
    );
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    assert_eq!(p.pid(), NonZeroU32::new(4242));
    assert_eq!(counts(&l, "shim_exec_pid_unreported"), None);
}

/// #4379: `Spawned` 無しで `Result` が来て終わる回（予算の不足ではない）は数えない。
#[test]
fn repair4_4379_result_without_spawned_is_not_counted() {
    let fx = Fixture::new("t4379-nospawn");
    let budgets = ExecBudgets {
        spawned: Duration::from_secs(5),
        ..ExecBudgets::default()
    };
    let (l, _) = fx.launcher(
        spawning(Duration::ZERO, 0, Some(StreamExecOutcome::Exited(0))),
        probe(0),
        budgets,
    );
    let p = l
        .launch(&cid("run1"), &eid(), &ok_spec(), fx.instance("run1"))
        .expect("launch");
    assert_eq!(p.pid(), None);
    assert_eq!(counts(&l, "shim_exec_pid_unreported"), None);
}

/// SEC-1・CRI-5・#4379: インスタンス不一致の拒否は 1 回につき 1 数え、helper を起動しない。pid 未着は数えない。
#[test]
fn repair4_4379_instance_changed_counts_once_without_helper() {
    let fx = Fixture::new("t4379-instance");
    let (l, pids) = fx.launcher(holding(), probe(0), ExecBudgets::default());
    let registered = fx.instance("run1");
    fx.recreate_running("run1", fx.init.id());
    let e = l
        .launch(&cid("run1"), &eid(), &ok_spec(), registered)
        .err()
        .expect("recreated");
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::FailedPrecondition, MSG_EXEC_INSTANCE_CHANGED)
    );
    assert!(pids.lock().expect("lock").is_empty());
    assert_eq!(l.tracked_helpers(), 0);
    assert_eq!(counts(&l, "shim_exec_instance_changed"), Some((0, 1)));
    assert_eq!(counts(&l, "shim_exec_pid_unreported"), None);
}

/// #4379: ほかの拒否（not running・not found）では照合拒否の計数は増えない。
#[test]
fn repair4_4379_other_rejections_are_not_counted() {
    let fx = Fixture::new("t4379-other");
    let (l, _) = fx.launcher(holding(), probe(0), ExecBudgets::default());
    for name in ["stopped1", "created1"] {
        let e = l
            .launch(&cid(name), &eid(), &ok_spec(), fx.instance(name))
            .err()
            .expect("not running");
        assert_eq!(
            (e.code(), e.message()),
            (CriErrorCode::FailedPrecondition, "container is not running")
        );
    }
    let e = l
        .launch(&cid("nosuch"), &eid(), &ok_spec(), None)
        .err()
        .expect("not found");
    assert_eq!(e.message(), "container not found");
    assert_eq!(counts(&l, "shim_exec_instance_changed"), None);
    assert_eq!(counts(&l, "shim_exec_pid_unreported"), None);
}
