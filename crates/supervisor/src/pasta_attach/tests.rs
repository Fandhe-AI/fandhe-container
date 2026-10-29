//! `pasta_attach` の単体試験(NET-9・CORE-1・REPAIR-4・REPAIR-5・#1940)。
//!
//! フェイクの backend とフェイクのプロセスで、起動順序・拒否の分類・逆順の巻き戻し・途中死の扱い・回収の順序を
//! 具体値で照合する。実 pasta と本番 launcher の通し確認は #3331(実機前提)。

use super::*;
use std::fs::File;
use std::num::NonZeroU32;

type Events = Arc<Mutex<Vec<String>>>;

fn push(ev: &Events, s: impl Into<String>) {
    ev.lock().unwrap().push(s.into());
}

fn events(ev: &Events) -> Vec<String> {
    ev.lock().unwrap().clone()
}

/// 呼ばれた順を記録するフェイクの helper。
struct FakeHelper {
    name: &'static str,
    pid: u32,
    alive: Arc<AtomicBool>,
    ev: Events,
    stop_delay: Duration,
}

impl HelperHandle for FakeHelper {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn is_alive(&mut self) -> Result<bool, TraitError> {
        Ok(self.alive.load(Ordering::SeqCst))
    }
    fn stop(&mut self, detach_ok: bool) -> StopReport {
        std::thread::sleep(self.stop_delay);
        push(&self.ev, format!("stop {} detach={detach_ok}", self.name));
        StopReport {
            kind: StopKind::Stopped,
            exit: ExitInfo {
                code: Some(0),
                signal: None,
                stderr: String::new(),
            },
            elapsed: Duration::from_millis(3),
        }
    }
}

struct FakeBackend {
    ev: Events,
    holder_result: Mutex<Option<TraitError>>,
    pasta_result: Mutex<Option<TraitError>>,
    holder_alive: Arc<AtomicBool>,
    pasta_alive: Arc<AtomicBool>,
    stop_delay: Mutex<Duration>,
}

impl FakeBackend {
    fn new(ev: &Events) -> Arc<Self> {
        Arc::new(Self {
            ev: Arc::clone(ev),
            holder_result: Mutex::new(None),
            pasta_result: Mutex::new(None),
            holder_alive: Arc::new(AtomicBool::new(true)),
            pasta_alive: Arc::new(AtomicBool::new(true)),
            stop_delay: Mutex::new(Duration::ZERO),
        })
    }
}

impl PastaAttachBackend for FakeBackend {
    fn spawn_holder(&self, _u: OwnedFd, _n: OwnedFd, _d: Instant) -> Result<Spawned, TraitError> {
        push(&self.ev, "spawn holder");
        if let Some(e) = self.holder_result.lock().unwrap().take() {
            return Err(e);
        }
        Ok(Spawned {
            handle: Box::new(FakeHelper {
                name: "holder",
                pid: 4242,
                alive: Arc::clone(&self.holder_alive),
                ev: Arc::clone(&self.ev),
                stop_delay: *self.stop_delay.lock().unwrap(),
            }),
            ready_ms: 7,
            generation: None,
        })
    }
    fn spawn_pasta(&self, holder_pid: u32, _d: Instant) -> Result<Spawned, TraitError> {
        push(&self.ev, format!("spawn pasta target={holder_pid}"));
        if let Some(e) = self.pasta_result.lock().unwrap().take() {
            return Err(e);
        }
        Ok(Spawned {
            handle: Box::new(FakeHelper {
                name: "pasta",
                pid: 4343,
                alive: Arc::clone(&self.pasta_alive),
                ev: Arc::clone(&self.ev),
                stop_delay: *self.stop_delay.lock().unwrap(),
            }),
            ready_ms: 11,
            generation: Some(1),
        })
    }
    fn remove_run_dir(&self, _g: Option<u64>) -> Result<(), TraitError> {
        push(&self.ev, "remove run_dir");
        Ok(())
    }
}

/// コンテナ本体のフェイク。シグナルと terminate を記録し、`wait` は積んだ結果を順に返す。
struct FakeProcess {
    ev: Events,
    waits: Mutex<Vec<Option<ProcessExit>>>,
}

impl FakeProcess {
    fn new(ev: &Events, waits: Vec<Option<ProcessExit>>) -> Box<Self> {
        Box::new(Self {
            ev: Arc::clone(ev),
            waits: Mutex::new(waits),
        })
    }
}

impl LaunchedProcess for FakeProcess {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(77).unwrap()
    }
    fn wait(&self, _t: Duration) -> Result<Option<ProcessExit>, TraitError> {
        let mut w = self.waits.lock().unwrap();
        if w.is_empty() {
            Ok(None)
        } else {
            Ok(w.remove(0))
        }
    }
    fn terminate(&self, _t: Duration) -> Result<(), TraitError> {
        push(&self.ev, "container terminate");
        Ok(())
    }
    fn signal(&self, signal: Signal, _d: Instant) -> Result<(), TraitError> {
        push(&self.ev, format!("container signal {}", signal.as_u8()));
        Ok(())
    }
}

fn wiring(backend: &Arc<FakeBackend>) -> (PastaWiring, Arc<PastaLogBuffer>) {
    let buffer = Arc::new(PastaLogBuffer::new());
    let logger = Logger {
        container: Arc::from("web1"),
        buffer: Arc::clone(&buffer),
    };
    let backend: Arc<dyn PastaAttachBackend> = Arc::clone(backend) as Arc<dyn PastaAttachBackend>;
    (PastaWiring::with_backend(backend, logger), buffer)
}

fn fds() -> (OwnedFd, OwnedFd) {
    (
        OwnedFd::from(File::open("/dev/null").unwrap()),
        OwnedFd::from(File::open("/dev/null").unwrap()),
    )
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn attach(w: &PastaWiring) -> Result<(), TraitError> {
    let (u, n) = fds();
    w.hook.attach_fds(u, n, soon())
}

fn launcher(w: &PastaWiring) -> PastaAttachingLauncher {
    PastaAttachingLauncher {
        inner: Arc::new(NullLauncher),
        slot: Arc::clone(&w.slot),
        _backend: Arc::clone(&w.backend),
        logger: w.logger.clone(),
    }
}

struct NullLauncher;
impl ProcessLauncher for NullLauncher {
    fn launch(
        &self,
        _s: &LaunchSpec,
        _t: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "unused"))
    }
}

/// NET-9・12.2: holder の後に pasta を起動し、pasta の対象は holder の pid。準備完了のログは遅延バッファに積まれる。
#[test]
fn net9_attach_orders_holder_then_pasta_and_defers_ready_logs() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, buffer) = wiring(&backend);
    attach(&w).expect("attach");
    assert_eq!(events(&ev), ["spawn holder", "spawn pasta target=4242"]);
    assert!(lock(&w.slot).is_some());
    assert_eq!(
        buffer.take(),
        [
            "{\"component\":\"supervisor\",\"event\":\"netns_holder_ready\",\"container\":\"web1\",\"elapsed_ms\":7}\n",
            "{\"component\":\"supervisor\",\"event\":\"pasta_ready\",\"container\":\"web1\",\"elapsed_ms\":11}\n",
        ]
    );
}

/// NET-9・ERR-1: holder の失敗は pasta を起動せず、コードを保って返す。slot は空のまま。
#[test]
fn net9_holder_failure_keeps_code_and_starts_no_pasta() {
    for code in [
        ErrorCode::Timeout,
        ErrorCode::PermissionDenied,
        ErrorCode::FailedPrecondition,
    ] {
        let ev: Events = Arc::default();
        let backend = FakeBackend::new(&ev);
        *backend.holder_result.lock().unwrap() = Some(TraitError::new(code, "fixed holder"));
        let (w, _b) = wiring(&backend);
        let e = attach(&w).expect_err("holder fails");
        assert_eq!((e.code(), e.message()), (code, "fixed holder"));
        assert_eq!(events(&ev), ["spawn holder"]);
        assert!(lock(&w.slot).is_none());
    }
}

/// NET-9・REPAIR-5: pasta の失敗では run dir を消してから holder を止める(逆順)。回収スレッドは作らない(detach=false)。
#[test]
fn net9_pasta_failure_rolls_back_in_reverse_order() {
    for code in [
        ErrorCode::FailedPrecondition,
        ErrorCode::Timeout,
        ErrorCode::PermissionDenied,
    ] {
        let ev: Events = Arc::default();
        let backend = FakeBackend::new(&ev);
        *backend.pasta_result.lock().unwrap() = Some(TraitError::new(code, "fixed pasta"));
        let (w, _b) = wiring(&backend);
        let e = attach(&w).expect_err("pasta fails");
        assert_eq!((e.code(), e.message()), (code, "fixed pasta"));
        assert_eq!(
            events(&ev),
            [
                "spawn holder",
                "spawn pasta target=4242",
                "stop holder detach=false"
            ]
        );
        assert!(lock(&w.slot).is_none());
        // 置き場所の削除は単一スレッド区間のフックでは行わず(スレッドを作らない)、launch 失敗の後始末へ渡る。
        let l = launcher(&w);
        let _ = l.adopt(Err(TraitError::new(code, "launch failed")));
        assert_eq!(
            events(&ev).last().map(String::as_str),
            Some("remove run_dir")
        );
        assert_eq!(
            events(&ev)
                .iter()
                .filter(|x| *x == "remove run_dir")
                .count(),
            1
        );
    }
}

/// REPAIR-5: 期限を過ぎていれば何も起動しない。
#[test]
fn repair5_expired_deadline_spawns_nothing() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    let (u, n) = fds();
    let e = w
        .hook
        .attach_fds(u, n, Instant::now() - Duration::from_secs(1))
        .expect_err("expired");
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert!(events(&ev).is_empty());
}

/// 二重の attach は fail-closed で拒否し、何も起動しない。
#[test]
fn net9_second_attach_without_collection_is_refused() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("first");
    let e = attach(&w).expect_err("second");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert_eq!(events(&ev).len(), 2);
}

/// NET-9・CORE-1: launch が Err なら残った分を pasta → holder → run dir の順に止める(単一スレッドなので detach=false)。
#[test]
fn net9_launch_error_tears_down_in_order() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, buffer) = wiring(&backend);
    attach(&w).expect("attach");
    buffer.take();
    ev.lock().unwrap().clear();
    let l = launcher(&w);
    let e = l
        .adopt(Err(TraitError::new(ErrorCode::Timeout, "launch failed")))
        .err()
        .expect("passes the error through");
    assert_eq!(
        (e.code(), e.message()),
        (ErrorCode::Timeout, "launch failed")
    );
    assert_eq!(
        events(&ev),
        [
            "stop pasta detach=false",
            "stop holder detach=false",
            "remove run_dir"
        ]
    );
    assert!(lock(&w.slot).is_none());
    // 後始末の記録は遅延バッファに積まれ、その場では出ない。
    let lines = buffer.take();
    assert_eq!(lines.len(), 2);
    assert!(
        lines[0].contains("\"event\":\"pasta_exit\"")
            && lines[0].contains("\"reason\":\"launch_failed\"")
    );
    assert!(lines[1].contains("\"event\":\"netns_holder_exit\""));
}

/// フックが走らなかった launch の Ok は、プロセスを止めて Internal で拒否する(ネットワーク無しで走らせない)。
#[test]
fn net9_launch_ok_without_attachment_terminates_process() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    let l = launcher(&w);
    let e = l
        .adopt(Ok(FakeProcess::new(&ev, vec![])))
        .err()
        .expect("refused");
    assert_eq!(e.code(), ErrorCode::Internal);
    assert_eq!(events(&ev), ["container terminate", "remove run_dir"]);
}

/// 成功した launch は Guarded に載り、PID 1 の回収後に pasta → holder → run dir の順で 1 回だけ止める。
#[test]
fn net9_container_exit_stops_pasta_then_holder_once() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let l = launcher(&w);
    let p = l
        .adopt(Ok(FakeProcess::new(
            &ev,
            vec![None, Some(ProcessExit::Exited(3))],
        )))
        .unwrap_or_else(|e| panic!("guarded: {:?}", e.code()));
    assert_eq!(p.pid().get(), 77);
    // 生きている間は何も止めない。
    assert!(p.wait(WAIT_BUDGET).expect("wait").is_none());
    assert!(events(&ev).is_empty());
    // 期限が 0 のときの後始末は専用スレッドで継続する(REPAIR-5)。終了は後始末の完了後にだけ返る(CORE-2)。
    let until = Instant::now() + Duration::from_secs(5);
    let mut exit = None;
    while exit.is_none() && Instant::now() < until {
        exit = p.wait(WAIT_BUDGET).expect("wait");
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(exit, Some(ProcessExit::Exited(3)));
    assert_eq!(
        events(&ev),
        [
            "stop pasta detach=true",
            "stop holder detach=true",
            "remove run_dir"
        ]
    );
    // 2 回目以降・drop では重複して止めない。
    drop(p);
    assert_eq!(events(&ev).len(), 3);
}

/// NET-9・REPAIR-5: pasta が先に死んだら、分離を緩めずコンテナへ SIGTERM を 1 回送り、猶予を超えたら SIGKILL を 1 回送る。
#[test]
fn net9_helper_death_terminates_container_without_relaxing_isolation() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, buffer) = wiring(&backend);
    attach(&w).expect("attach");
    buffer.take();
    ev.lock().unwrap().clear();
    let mut guarded = PastaGuardedProcess::new(
        FakeProcess::new(&ev, vec![]),
        lock(&w.slot).take().expect("attachment"),
        w.logger.clone(),
    );
    guarded.term_grace = Duration::from_millis(50);
    backend.pasta_alive.store(false, Ordering::SeqCst);
    assert!(guarded.wait(WAIT_BUDGET).expect("wait").is_none());
    assert!(guarded.wait(WAIT_BUDGET).expect("wait").is_none());
    assert_eq!(events(&ev), ["container signal 15"]);
    std::thread::sleep(Duration::from_millis(80));
    assert!(guarded.wait(WAIT_BUDGET).expect("wait").is_none());
    assert!(guarded.wait(WAIT_BUDGET).expect("wait").is_none());
    assert_eq!(events(&ev), ["container signal 15", "container signal 9"]);
    // helper は PID 1 の回収まで止めない(止めるのは回収後)。
    assert!(!events(&ev).iter().any(|e| e.starts_with("stop ")));
}

/// holder が先に死んだ場合も同じ扱い。
#[test]
fn net9_holder_death_terminates_container() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let guarded = PastaGuardedProcess::new(
        FakeProcess::new(&ev, vec![]),
        lock(&w.slot).take().expect("attachment"),
        w.logger.clone(),
    );
    backend.holder_alive.store(false, Ordering::SeqCst);
    assert!(guarded.wait(WAIT_BUDGET).expect("wait").is_none());
    assert_eq!(events(&ev), ["container signal 15"]);
}

/// terminate は内側の結果を返し、helper を止めて run dir を消す。
#[test]
fn net9_terminate_tears_down_helpers() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let guarded = PastaGuardedProcess::new(
        FakeProcess::new(&ev, vec![]),
        lock(&w.slot).take().expect("attachment"),
        w.logger.clone(),
    );
    guarded
        .terminate(Duration::from_secs(1))
        .expect("terminate");
    assert_eq!(
        events(&ev),
        [
            "container terminate",
            "stop pasta detach=true",
            "stop holder detach=true",
            "remove run_dir"
        ]
    );
}

/// 回収前にハンドルが手放されても helper を残さない。
#[test]
fn net9_drop_without_wait_tears_down_helpers() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let guarded = PastaGuardedProcess::new(
        FakeProcess::new(&ev, vec![]),
        lock(&w.slot).take().expect("attachment"),
        w.logger.clone(),
    );
    drop(guarded);
    assert_eq!(
        events(&ev),
        [
            "stop pasta detach=false",
            "stop holder detach=false",
            "remove run_dir"
        ]
    );
}

/// 内側の launcher への転送(転送漏れは降格・監査の欠落になる)。
#[test]
fn net9_launcher_forwards_mode_methods_to_inner() {
    struct Inner;
    impl ProcessLauncher for Inner {
        fn launch_mode(&self) -> fandhe_container_core::oci_runtime::LaunchMode {
            fandhe_container_core::oci_runtime::LaunchMode::SelfBounded
        }
        fn network_mode(&self) -> fandhe_container_core::oci_runtime::LaunchNetworkMode {
            fandhe_container_core::oci_runtime::LaunchNetworkMode::Attachable
        }
        fn last_launch_may_have_left_process(&self) -> bool {
            true
        }
        fn launch(
            &self,
            _s: &LaunchSpec,
            _t: Duration,
        ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "unused"))
        }
    }
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    let wrapped = w.wrap(Arc::new(Inner));
    assert_eq!(
        wrapped.launch_mode(),
        fandhe_container_core::oci_runtime::LaunchMode::SelfBounded
    );
    assert_eq!(
        wrapped.network_mode(),
        fandhe_container_core::oci_runtime::LaunchNetworkMode::Attachable
    );
    assert!(wrapped.last_launch_may_have_left_process());
}

/// REPAIR-4: 構造化ログの行は固定の形で、パス・argv を含まない。
#[test]
fn repair4_log_lines_have_a_fixed_shape() {
    assert_eq!(
        json_line(
            "pasta_exit",
            "web1",
            &[
                ("reason", Val::S("container_exit")),
                ("stop", Val::S("stopped")),
                ("elapsed_ms", Val::U(12)),
                ("status", Val::U(0)),
            ],
        ),
        "{\"component\":\"supervisor\",\"event\":\"pasta_exit\",\"container\":\"web1\",\"reason\":\"container_exit\",\"stop\":\"stopped\",\"elapsed_ms\":12,\"status\":0}\n"
    );
    let b = PastaLogBuffer::new();
    log_pasta_verify(&b, "web1", Ok(20_260_120), Duration::from_millis(5));
    log_pasta_verify(
        &b,
        "web1",
        Err((ErrorCode::PermissionDenied, true)),
        Duration::from_millis(1),
    );
    assert_eq!(
        b.take(),
        [
            "{\"component\":\"supervisor\",\"event\":\"pasta_verify\",\"container\":\"web1\",\"elapsed_ms\":5,\"result\":\"ok\",\"version_date\":20260120}\n",
            "{\"component\":\"supervisor\",\"event\":\"pasta_verify\",\"container\":\"web1\",\"elapsed_ms\":1,\"result\":\"rejected\",\"code\":\"PERMISSION_DENIED\",\"tamper_suspected\":\"true\"}\n",
        ]
    );
}

/// 遅延バッファは 64 行で頭打ち(無制限確保を避ける)。
#[test]
fn net9_log_buffer_is_bounded() {
    let b = PastaLogBuffer::new();
    for i in 0..200 {
        b.push(format!("{i}\n"));
    }
    assert_eq!(b.take().len(), 64);
}

/// CLI の delete が呼ぶ残骸の削除は、無ければ成功し、あれば消す(記録の pid でのプロセス操作はしない)。
#[test]
fn net9_remove_leftovers_is_idempotent() {
    let dir = std::env::temp_dir().join(format!("fandhe-pasta-attach-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let id = ContainerId::new("web1".to_owned()).unwrap();
    remove_pasta_leftovers(&dir, &id).expect("absent is ok");
    let run = dir.join("@pasta").join("web1");
    {
        // net の検査どおり、所有者が自分で 0700 のディレクトリだけを受ける。
        use std::os::unix::fs::DirBuilderExt as _;
        let mut b = std::fs::DirBuilder::new();
        b.mode(0o700);
        b.create(dir.join("@pasta")).unwrap();
        b.create(&run).unwrap();
    }
    std::fs::write(run.join("pid"), "123\n").unwrap();
    remove_pasta_leftovers(&dir, &id).expect("removes");
    assert!(!run.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// REPAIR-4・#1940: helper の stderr(二重引用符・バックスラッシュ・`\xNN`・制御文字)を含んでも 1 行になり、
/// JSON のエスケープが完全一致で付く。
#[test]
fn repair4_text_value_is_json_encoded() {
    let raw = "bad \"quote\" \\x80 tab\t nl\n ctl\u{1} end";
    let line = json_line(
        "pasta_failed",
        "web1",
        &[("stderr", Val::Text(raw.to_owned()))],
    );
    assert_eq!(
        line,
        "{\"component\":\"supervisor\",\"event\":\"pasta_failed\",\"container\":\"web1\",\"stderr\":\"bad \\\"quote\\\" \\\\x80 tab\\t nl\\n ctl\\u0001 end\"}\n"
    );
    assert_eq!(line.matches('\n').count(), 1);
}

/// SEC-4・#3330: 改ざんの疑いは最初の 1 件を残し、取り出すと空になる。
#[test]
fn sec4_3330_tamper_slot_keeps_first_and_drains() {
    use fandhe_container_core::audit_log::PastaVerifyRejection as R;
    let b = PastaLogBuffer::new();
    assert_eq!(b.take_tamper(), None);
    b.set_tamper(R::RecordChanged);
    b.set_tamper(R::PermissionDenied);
    assert_eq!(b.take_tamper(), Some(R::RecordChanged));
    assert_eq!(b.take_tamper(), None);
}
// ---------------------------------------------------------------------------------------------
// #3334 のレビュー指摘への試験(後始末の追跡・シグナル失敗の再試行・実プロセスの回収)
// ---------------------------------------------------------------------------------------------

/// 送信の成否を制御できるコンテナのフェイク。
struct FlakySignalProcess {
    ev: Events,
    fail_term: std::sync::atomic::AtomicU32,
    fail_kill: std::sync::atomic::AtomicU32,
}

impl LaunchedProcess for FlakySignalProcess {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(78).unwrap()
    }
    fn wait(&self, _t: Duration) -> Result<Option<ProcessExit>, TraitError> {
        Ok(None)
    }
    fn terminate(&self, _t: Duration) -> Result<(), TraitError> {
        push(&self.ev, "container terminate");
        Ok(())
    }
    fn signal(&self, signal: Signal, _d: Instant) -> Result<(), TraitError> {
        let counter = if signal == Signal::SIGKILL {
            &self.fail_kill
        } else {
            &self.fail_term
        };
        let left = counter.load(Ordering::SeqCst);
        if left > 0 {
            counter.store(left - 1, Ordering::SeqCst);
            push(
                &self.ev,
                format!("container signal {} failed", signal.as_u8()),
            );
            return Err(TraitError::new(ErrorCode::Timeout, "send timeout"));
        }
        push(&self.ev, format!("container signal {}", signal.as_u8()));
        Ok(())
    }
}

fn guarded_flaky(
    w: &PastaWiring,
    ev: &Events,
    fail_term: u32,
    fail_kill: u32,
) -> PastaGuardedProcess {
    let mut g = PastaGuardedProcess::new(
        Box::new(FlakySignalProcess {
            ev: Arc::clone(ev),
            fail_term: fail_term.into(),
            fail_kill: fail_kill.into(),
        }),
        lock(&w.slot).take().expect("attachment"),
        w.logger.clone(),
    );
    g.term_grace = Duration::from_millis(10);
    g
}

/// REPAIR-5: SIGTERM の送信失敗は送信済みに数えず、次の周期で再試行する。
#[test]
fn repair5_failed_sigterm_is_retried_not_counted_as_sent() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let g = guarded_flaky(&w, &ev, 1, 0);
    backend.pasta_alive.store(false, Ordering::SeqCst);
    g.wait(WAIT_BUDGET).expect("wait");
    g.wait(WAIT_BUDGET).expect("wait");
    assert_eq!(
        events(&ev),
        ["container signal 15 failed", "container signal 15"]
    );
}

/// REPAIR-5: SIGKILL の送信失敗は再試行し、成功するまで killed にしない。
#[test]
fn repair5_failed_sigkill_is_retried() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let g = guarded_flaky(&w, &ev, 0, 1);
    backend.pasta_alive.store(false, Ordering::SeqCst);
    g.wait(WAIT_BUDGET).expect("wait");
    std::thread::sleep(Duration::from_millis(30));
    g.wait(WAIT_BUDGET).expect("wait");
    g.wait(WAIT_BUDGET).expect("wait");
    g.wait(WAIT_BUDGET).expect("wait");
    assert_eq!(
        events(&ev),
        [
            "container signal 15",
            "container signal 9 failed",
            "container signal 9"
        ]
    );
}

/// REPAIR-5: SIGKILL が上限回数失敗したら terminate で回収へ進める。
#[test]
fn repair5_persistent_sigkill_failure_falls_back_to_terminate() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let g = guarded_flaky(&w, &ev, 0, 100);
    backend.pasta_alive.store(false, Ordering::SeqCst);
    g.wait(WAIT_BUDGET).expect("wait");
    std::thread::sleep(Duration::from_millis(30));
    for _ in 0..6 {
        g.wait(WAIT_BUDGET).expect("wait");
    }
    let e = events(&ev);
    assert_eq!(
        e.iter()
            .filter(|x| *x == "container signal 9 failed")
            .count(),
        3
    );
    assert_eq!(e.iter().filter(|x| *x == "container terminate").count(), 1);
}

/// REPAIR-1・REPAIR-5: 期限内に終わらない後始末は追跡され、drop が完了まで回収する。
#[test]
fn repair1_slow_teardown_is_joined_before_drop_returns() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    *backend.stop_delay.lock().unwrap() = Duration::from_millis(150);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let g = PastaGuardedProcess::new(
        FakeProcess::new(&ev, vec![Some(ProcessExit::Exited(0))]),
        lock(&w.slot).take().expect("attachment"),
        w.logger.clone(),
    );
    let t = Instant::now();
    // 期限内に後始末が終わらないときは終了を返さない(Stopped の記録が後始末より先に起きない。CORE-2)。
    assert_eq!(g.wait(Duration::ZERO).expect("wait"), None);
    assert!(t.elapsed() < Duration::from_millis(100));
    let until = Instant::now() + Duration::from_secs(5);
    let mut exit = None;
    while exit.is_none() && Instant::now() < until {
        exit = g.wait(Duration::from_millis(20)).expect("wait");
    }
    assert_eq!(exit, Some(ProcessExit::Exited(0)));
    assert_eq!(events(&ev).len(), 3);
    drop(g);
    assert_eq!(
        events(&ev),
        [
            "stop pasta detach=true",
            "stop holder detach=true",
            "remove run_dir"
        ]
    );
}

/// 実プロセス(sleep)を helper にする backend。回収と run dir の削除を OS 上で照合する。
struct RealProcBackend {
    run_dir: std::path::PathBuf,
    fail_pasta: bool,
    pids: Mutex<Vec<u32>>,
}

struct ChildHelper(std::process::Child);

impl HelperHandle for ChildHelper {
    fn pid(&self) -> u32 {
        self.0.id()
    }
    fn is_alive(&mut self) -> Result<bool, TraitError> {
        match self.0.try_wait() {
            Ok(None) => Ok(true),
            Ok(Some(_)) => Ok(false),
            Err(_) => Err(TraitError::new(ErrorCode::Internal, "try_wait")),
        }
    }
    fn stop(&mut self, _detach_ok: bool) -> StopReport {
        let _ = self.0.kill();
        let st = self.0.wait().ok();
        StopReport {
            kind: StopKind::Killed,
            exit: ExitInfo {
                code: st.and_then(|s| s.code()),
                signal: None,
                stderr: String::new(),
            },
            elapsed: Duration::ZERO,
        }
    }
}

impl RealProcBackend {
    fn child(&self) -> Spawned {
        let c = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep");
        self.pids.lock().unwrap().push(c.id());
        Spawned {
            handle: Box::new(ChildHelper(c)),
            ready_ms: 1,
            generation: None,
        }
    }
}

impl PastaAttachBackend for RealProcBackend {
    fn spawn_holder(&self, _u: OwnedFd, _n: OwnedFd, _d: Instant) -> Result<Spawned, TraitError> {
        std::fs::create_dir_all(&self.run_dir).expect("mkdir");
        Ok(self.child())
    }
    fn spawn_pasta(&self, _h: u32, _d: Instant) -> Result<Spawned, TraitError> {
        if self.fail_pasta {
            return Err(TraitError::new(ErrorCode::Internal, "pasta failed"));
        }
        Ok(self.child())
    }
    fn remove_run_dir(&self, _g: Option<u64>) -> Result<(), TraitError> {
        let _ = std::fs::remove_dir_all(&self.run_dir);
        Ok(())
    }
}

fn real_wiring(tag: &str, fail_pasta: bool) -> (PastaWiring, Arc<RealProcBackend>) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let run_dir = std::env::temp_dir().join(format!(
        "fc-pasta-attach-{tag}-{}-{nanos}",
        std::process::id()
    ));
    let backend = Arc::new(RealProcBackend {
        run_dir,
        fail_pasta,
        pids: Mutex::new(Vec::new()),
    });
    let logger = Logger {
        container: Arc::from("web1"),
        buffer: Arc::new(PastaLogBuffer::new()),
    };
    let dynb: Arc<dyn PastaAttachBackend> = Arc::clone(&backend) as Arc<dyn PastaAttachBackend>;
    (PastaWiring::with_backend(dynb, logger), backend)
}

fn gone(pid: u32) -> bool {
    !std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn gone_or_zombie(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(s) => s
            .rsplit(')')
            .next()
            .is_some_and(|r| r.trim_start().starts_with('Z')),
    }
}

/// NET-9・REPAIR-12: 実プロセスの helper が、コンテナの正常終了で回収され、run dir が消える。
#[test]
fn net9_real_helpers_are_reaped_on_container_exit() {
    let (w, b) = real_wiring("exit", false);
    attach(&w).expect("attach");
    let ev: Events = Arc::default();
    let g = launcher(&w)
        .adopt(Ok(FakeProcess::new(
            &ev,
            vec![Some(ProcessExit::Exited(0))],
        )))
        .unwrap_or_else(|e| panic!("guarded: {:?}", e.code()));
    g.wait(Duration::from_secs(5)).expect("wait");
    drop(g);
    let pids = b.pids.lock().unwrap().clone();
    assert_eq!(pids.len(), 2);
    assert!(pids.iter().all(|p| gone(*p)));
    assert!(!b.run_dir.exists());
}

/// NET-9・REPAIR-12: 起動失敗(pasta)で、起動済みの holder が回収され、run dir が消える。
#[test]
fn net9_real_helpers_are_reaped_on_spawn_failure() {
    let (w, b) = real_wiring("fail", true);
    assert!(attach(&w).is_err());
    let pids = b.pids.lock().unwrap().clone();
    assert_eq!(pids.len(), 1);
    assert!(gone(pids[0]));
    assert!(lock(&w.slot).is_none());
    // フックは helper の回収だけを行い、run dir は launch 失敗の後始末(単一スレッド区間の外)が消す。
    let l = launcher(&w);
    let _ = l.adopt(Err(TraitError::new(ErrorCode::Internal, "launch failed")));
    assert!(!b.run_dir.exists());
}

/// NET-9・REPAIR-12: helper が途中で死んだら SIGTERM が送られ、終了後に残りの helper も回収される。
#[test]
fn net9_real_helper_mid_death_signals_container_and_reaps_the_rest() {
    let (w, b) = real_wiring("mid", false);
    attach(&w).expect("attach");
    let ev: Events = Arc::default();
    let g = launcher(&w)
        .adopt(Ok(FakeProcess::new(
            &ev,
            vec![None, None, Some(ProcessExit::Signaled(15))],
        )))
        .unwrap_or_else(|e| panic!("guarded: {:?}", e.code()));
    let pasta_pid = b.pids.lock().unwrap()[1];
    // 試験が起動した sleep を外部コマンドで終了させる(unsafe を使わない)。
    let status = std::process::Command::new("kill")
        .args(["-9", &pasta_pid.to_string()])
        .status()
        .expect("kill");
    assert!(status.success());
    let until = Instant::now() + Duration::from_secs(5);
    while !gone_or_zombie(pasta_pid) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    g.wait(WAIT_BUDGET).expect("wait");
    assert_eq!(events(&ev), ["container signal 15"]);
    g.wait(WAIT_BUDGET).expect("wait");
    g.wait(Duration::from_secs(5)).expect("wait");
    drop(g);
    let pids = b.pids.lock().unwrap().clone();
    assert!(pids.iter().all(|p| gone(*p)));
    assert!(!b.run_dir.exists());
}

/// CORE-2: 世代が古い後始末は、再作成された新しい置き場所を消さない。最新の世代・無条件(巻き戻し)は消す。
#[test]
fn core2_stale_generation_does_not_remove_newer_run_dir() {
    let gens = RunDirGenerations::default();
    let (g1, ()) = gens.advance_with(|| ());
    let (g2, ()) = gens.advance_with(|| ());
    assert_eq!((g1, g2), (1, 2));
    let mut removed = 0;
    let stale: Result<bool, ()> = gens.remove_if_current(Some(g1), || {
        removed += 1;
        Ok(true)
    });
    assert_eq!(stale, Ok(false));
    assert_eq!(removed, 0);
    let current: Result<bool, ()> = gens.remove_if_current(Some(g2), || {
        removed += 1;
        Ok(true)
    });
    assert_eq!(current, Ok(true));
    let rollback: Result<bool, ()> = gens.remove_if_current(None, || {
        removed += 1;
        Ok(true)
    });
    assert_eq!(rollback, Ok(true));
    assert_eq!(removed, 2);
}

/// CORE-2: 本物の `@pasta/<id>/` に対しても、旧い世代の削除は新しい置き場所(pid ファイルつき)を残す。
#[test]
fn core2_stale_generation_keeps_real_recreated_dir() {
    use fandhe_container_net::pasta::PastaRunDir;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!("fc-gen-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root).expect("mkdir");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let fd = open_state_root(&root).expect("open");
    let gens = RunDirGenerations::default();
    let (g1, r1) = gens.advance_with(|| PastaRunDir::prepare(fd.as_fd(), "web1"));
    drop(r1.expect("prepare 1"));
    let (_g2, r2) = gens.advance_with(|| PastaRunDir::prepare(fd.as_fd(), "web1"));
    let run2 = r2.expect("prepare 2");
    std::fs::write(run2.pid_path(), b"1\n").expect("pid");
    let skipped = gens.remove_if_current(Some(g1), || {
        remove_pasta_run_dir(fd.as_fd(), "web1").map(|()| true)
    });
    assert!(matches!(skipped, Ok(false)));
    assert!(run2.pid_path().exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// NET-9: terminate の失敗は完了扱いにせず、SIGKILL の再試行へ戻る。
#[test]
fn net9_failed_final_terminate_is_not_marked_done() {
    struct FailTerminate(Events);
    impl LaunchedProcess for FailTerminate {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(77).unwrap()
        }
        fn wait(&self, _t: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(None)
        }
        fn terminate(&self, _t: Duration) -> Result<(), TraitError> {
            push(&self.0, "container terminate");
            Err(TraitError::new(ErrorCode::Internal, "terminate failed"))
        }
        fn signal(&self, signal: Signal, _d: Instant) -> Result<(), TraitError> {
            if signal == Signal::SIGKILL {
                push(&self.0, "container signal 9 failed");
                Err(TraitError::new(ErrorCode::Internal, "kill failed"))
            } else {
                Ok(())
            }
        }
    }
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let attachment = lock(&w.slot).take().expect("attachment");
    let mut g = PastaGuardedProcess::new(
        Box::new(FailTerminate(Arc::clone(&ev))),
        attachment,
        w.logger.clone(),
    );
    g.term_grace = Duration::ZERO;
    backend.pasta_alive.store(false, Ordering::SeqCst);
    for _ in 0..12 {
        g.wait(WAIT_BUDGET).expect("wait");
    }
    let e = events(&ev);
    let terminates = e.iter().filter(|x| *x == "container terminate").count();
    assert!(terminates >= 2, "terminate must be retried: {e:?}");
    assert!(!lock(&g.signals).killed);
}

/// 途中死の処理（シグナルの送信・回収）に使える `wait` の予算。`Duration::ZERO` では繰り越す契約のため別に置く。
const WAIT_BUDGET: Duration = Duration::from_millis(50);

/// REPAIR-5: 予算のない `wait`(timeout 0)は、helper の死亡を見つけてもシグナルを送らず次の周期へ繰り越す。
#[test]
fn repair5_zero_budget_wait_defers_helper_death_handling() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let g = guarded_flaky(&w, &ev, 0, 0);
    backend.pasta_alive.store(false, Ordering::SeqCst);
    let t = Instant::now();
    assert_eq!(g.wait(Duration::ZERO).expect("wait"), None);
    assert_eq!(events(&ev), Vec::<String>::new());
    assert!(t.elapsed() < Duration::from_millis(100));
    // 予算のある次の周期で SIGTERM が送られる。
    assert_eq!(g.wait(WAIT_BUDGET).expect("wait"), None);
    assert_eq!(events(&ev), ["container signal 15"]);
}

/// CORE-2・NET-9: helper の後始末が期限内に終わらなかった terminate は成功を返さず(Timeout)、
/// 完了後の再試行で成功する。
#[test]
fn core2_terminate_with_pending_teardown_is_not_success() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    *backend.stop_delay.lock().unwrap() = Duration::from_millis(150);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let g = PastaGuardedProcess::new(
        FakeProcess::new(&ev, vec![]),
        lock(&w.slot).take().expect("attachment"),
        w.logger.clone(),
    );
    let e = g
        .terminate(Duration::from_millis(10))
        .expect_err("teardown still pending");
    assert_eq!(e.code(), ErrorCode::Timeout);
    let until = Instant::now() + Duration::from_secs(5);
    let mut done = false;
    while !done && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(20));
        done = g.terminate(Duration::from_millis(10)).is_ok();
    }
    assert!(done, "terminate must succeed after the teardown finished");
    assert!(
        events(&ev).contains(&"remove run_dir".to_owned()),
        "{:?}",
        events(&ev)
    );
}

/// 本番の `ContainerChildProcess::wait` を模す。コンテナが生存していると渡された timeout を使い切って `None` を返す。
struct SleepyProcess(Events);

impl LaunchedProcess for SleepyProcess {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(88).unwrap()
    }
    fn wait(&self, t: Duration) -> Result<Option<ProcessExit>, TraitError> {
        std::thread::sleep(t);
        Ok(None)
    }
    fn terminate(&self, _t: Duration) -> Result<(), TraitError> {
        Ok(())
    }
    fn signal(&self, signal: Signal, _d: Instant) -> Result<(), TraitError> {
        push(&self.0, format!("container signal {}", signal.as_u8()));
        Ok(())
    }
}

/// NET-9・REPAIR-5: 生存中の wait が timeout を使い切る本番の挙動でも、helper の途中死は同じ周期内で SIGTERM、
/// 猶予後の次の周期で SIGKILL が送られ、各 wait は期限(timeout + 余裕)内に戻る。
#[test]
fn net9_helper_death_is_signaled_even_when_wait_consumes_its_timeout() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    ev.lock().unwrap().clear();
    let mut g = PastaGuardedProcess::new(
        Box::new(SleepyProcess(Arc::clone(&ev))),
        lock(&w.slot).take().expect("attachment"),
        w.logger.clone(),
    );
    g.term_grace = Duration::from_millis(10);
    backend.pasta_alive.store(false, Ordering::SeqCst);
    let t = Instant::now();
    assert_eq!(g.wait(Duration::from_millis(100)).expect("wait"), None);
    assert!(
        t.elapsed() < Duration::from_millis(400),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(events(&ev), ["container signal 15"]);
    assert_eq!(g.wait(Duration::from_millis(100)).expect("wait"), None);
    assert_eq!(events(&ev), ["container signal 15", "container signal 9"]);
}

/// REPAIR-5・NET-9: 状態ルートの I/O の期限つき実行は、止まった job を待ち続けず `Timeout` で戻り、
/// 終わった job の値はそのまま返す。
#[test]
fn repair5_run_dir_io_is_bounded() {
    let t = Instant::now();
    let r = run_dir_io_bounded(Duration::from_millis(50), || {
        std::thread::sleep(Duration::from_millis(600));
        7u32
    });
    assert!(
        t.elapsed() < Duration::from_millis(400),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(r.expect_err("timed out").code(), ErrorCode::Timeout);
    assert_eq!(
        run_dir_io_bounded(Duration::from_secs(5), || 42u32).expect("done"),
        42
    );
}

/// REPAIR-5・CORE-2: 後始末が終わらない間も、drop は上限(`reap_cap`)で戻る(無期限に join しない)。
#[test]
fn repair5_drop_does_not_join_a_stuck_teardown_forever() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    *backend.stop_delay.lock().unwrap() = Duration::from_millis(1500);
    let (w, _b) = wiring(&backend);
    attach(&w).expect("attach");
    let mut g = PastaGuardedProcess::new(
        FakeProcess::new(&ev, vec![Some(ProcessExit::Exited(0))]),
        lock(&w.slot).take().expect("attachment"),
        w.logger.clone(),
    );
    g.reap_cap = Duration::from_millis(100);
    // 期限内に後始末が終わらず、worker が追跡される。
    assert_eq!(g.wait(Duration::ZERO).expect("wait"), None);
    let t = Instant::now();
    drop(g);
    assert!(
        t.elapsed() < Duration::from_millis(1000),
        "{:?}",
        t.elapsed()
    );
}

/// 試験用の状態ルート(0700)と fd。
fn scratch_root(tag: &str) -> (std::path::PathBuf, OwnedFd) {
    use std::os::unix::fs::PermissionsExt as _;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!("fc-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root).expect("mkdir");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let fd = open_state_root(&root).expect("open");
    (root, fd)
}

/// CORE-2・REPAIR-5・NET-9: 期限切れで残った旧い削除は、別の起動が作り直した `@pasta/<id>` には触れない
/// (同一性 `(st_dev, st_ino)` が違えば何もせず終える)。同一なら消す。pid ファイルつきの新しい置き場所が残ることを確かめる。
#[test]
fn core2_stale_removal_keeps_recreated_run_dir_by_identity() {
    use fandhe_container_net::pasta::PastaRunDir;
    let (root, fd) = scratch_root("ident");
    // 旧い起動: 準備して同一性を控える。
    let old = PastaRunDir::prepare(fd.as_fd(), "web1").expect("prepare old");
    let old_id = run_dir_identity(fd.as_fd(), "web1")
        .expect("stat")
        .expect("exists");
    // 旧い起動の置き場所が取り除かれ(旧い inode は別名で生かし、再利用で同一に見えないようにする)、
    // 別の起動が同じ ID で作り直して pid を置く。
    drop(old);
    std::fs::rename(root.join("@pasta/web1"), root.join("@pasta/old-keep")).expect("rename");
    let new = PastaRunDir::prepare(fd.as_fd(), "web1").expect("prepare new");
    std::fs::write(new.pid_path(), b"4242\n").expect("pid");
    let new_id = run_dir_identity(fd.as_fd(), "web1")
        .expect("stat")
        .expect("exists");
    assert_ne!(new_id, old_id);
    // 期限切れで残っていた旧い削除が今動き出しても、新しい置き場所と pid は残る。
    assert!(!remove_run_dir_if_ours(fd.as_fd(), "web1", Some(old_id)).expect("stale remove"));
    assert_eq!(std::fs::read(new.pid_path()).expect("pid"), b"4242\n");
    // 自分のものが無い(未準備・見限り済み)ときも触れない。
    assert!(!remove_run_dir_if_ours(fd.as_fd(), "web1", None).expect("not ours"));
    assert!(new.pid_path().exists());
    // 同一性が一致する後始末は消す。消す対象が既に無ければ成功。
    assert!(remove_run_dir_if_ours(fd.as_fd(), "web1", Some(new_id)).expect("own remove"));
    assert!(!root.join("@pasta/web1").exists());
    assert!(remove_run_dir_if_ours(fd.as_fd(), "web1", Some(new_id)).expect("already gone"));
    let _ = std::fs::remove_dir_all(&root);
}

/// REPAIR-5・CORE-2: 期限切れで見限った準備が後から作り終えても、その成果物は渡されず(新しい起動が使わない)、
/// 自分のものとしても控えられない。見限っていない準備は渡される。
#[test]
fn repair5_abandoned_prepare_is_not_delivered() {
    use fandhe_container_net::pasta::PastaRunDir;
    let (root, fd) = scratch_root("abandon");
    let slot = Mutex::new(PreparedSlot::default());
    let late = AtomicBool::new(false);
    let dir = PastaRunDir::prepare(fd.as_fd(), "web1").expect("prepare");
    let ours = run_dir_identity(fd.as_fd(), "web1").expect("stat");
    assert!(ours.is_some());
    // 呼び出し側が期限切れで見限った後に、作業スレッドが作り終えた。
    abandon_prepared(&slot, &late);
    assert!(!deliver_prepared(&slot, &late, 1, dir, ours));
    {
        let g = lock(&slot);
        assert!(g.ready.is_none());
        assert_eq!(g.ours, None);
    }
    // 見限っていない準備は渡され、同一性が控えられる。
    let ok = AtomicBool::new(false);
    let dir = PastaRunDir::prepare(fd.as_fd(), "web1").expect("prepare again");
    assert!(deliver_prepared(&slot, &ok, 2, dir, ours));
    {
        let g = lock(&slot);
        assert_eq!(g.ready.as_ref().map(|(n, _)| *n), Some(2));
        assert_eq!(g.ours, ours);
    }
    let _ = std::fs::remove_dir_all(&root);
}

fn io_job(root: &std::path::Path, fd: &Arc<OwnedFd>, id: &str) -> IoJob {
    IoJob {
        state_root: Arc::clone(fd),
        root_path: root.to_path_buf(),
        container: ContainerId::new(id).expect("id"),
        id: id.to_owned(),
    }
}

/// CORE-2・REPAIR-5・NET-9: 別の supervisor / CLI が同じコンテナのロックを持つ間、準備も削除もロックを待って
/// 期限で失敗し、状態ルートに何も作らず何も消さない(fail-closed)。
#[test]
fn core2_run_dir_ops_do_not_touch_anything_without_the_id_lock() {
    use fandhe_container_net::pasta::PastaRunDir;
    let (root, fd) = scratch_root("lock");
    let fd = Arc::new(fd);
    let job = io_job(&root, &fd, "web1");
    let id = ContainerId::new("web1").unwrap();
    let other = crate::container_options::store::acquire_lock(&root, &id, Duration::from_secs(5))
        .expect("other process holds the id lock");
    let gens = RunDirGenerations::default();
    let slot = Mutex::new(PreparedSlot::default());
    let never = AtomicBool::new(false);
    let e = prepare_run_dir_job(&job, Duration::from_millis(50), &gens, &slot, &never)
        .expect_err("lock not acquired");
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert!(!root.join("@pasta").exists());
    assert!(lock(&slot).ready.is_none());
    // 既存の置き場所(別の起動のもの)は、ロックが無ければ消えない。
    let theirs = PastaRunDir::prepare(fd.as_fd(), "web1").expect("their dir");
    std::fs::write(theirs.pid_path(), b"7\n").expect("pid");
    let ours = run_dir_identity(fd.as_fd(), "web1").expect("stat");
    let e = remove_run_dir_job(&job, Duration::from_millis(50), &gens, None, ours, &never)
        .expect_err("lock not acquired");
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert_eq!(std::fs::read(theirs.pid_path()).expect("pid"), b"7\n");
    drop(other);
    let _ = std::fs::remove_dir_all(&root);
}

/// CORE-2・REPAIR-5: 期限切れで見限った worker は、後からロックを取れても何にも触れない。
/// その間に CLI 相当(ロックの下の delete・再作成)が作った新世代は、pid ファイルごと残る。
#[test]
fn core2_abandoned_worker_cannot_touch_the_new_generation_after_it_gets_the_lock() {
    use fandhe_container_net::pasta::PastaRunDir;
    let (root, fd) = scratch_root("late");
    let fd = Arc::new(fd);
    let id = ContainerId::new("web1").unwrap();
    // 旧い起動: 準備済みで同一性を控えている。
    let old = PastaRunDir::prepare(fd.as_fd(), "web1").expect("old");
    let ours = run_dir_identity(fd.as_fd(), "web1").expect("stat");
    drop(old);
    // 別プロセス(CLI)がロックを持ち、旧い worker はそれを待っている。
    let cli = crate::container_options::store::acquire_lock(&root, &id, Duration::from_secs(5))
        .expect("cli lock");
    let abandoned = Arc::new(AtomicBool::new(false));
    let worker = {
        let (job, a) = (io_job(&root, &fd, "web1"), Arc::clone(&abandoned));
        std::thread::spawn(move || {
            let gens = RunDirGenerations::default();
            remove_run_dir_job(&job, Duration::from_secs(10), &gens, None, ours, &a)
        })
    };
    std::thread::sleep(Duration::from_millis(100));
    // 呼び出し側は期限切れで見限る。CLI は delete・再作成(新しい世代)を行ってからロックを手放す。
    abandoned.store(true, Ordering::SeqCst);
    remove_pasta_run_dir(fd.as_fd(), "web1").expect("cli delete");
    std::fs::create_dir_all(root.join("@pasta")).expect("mkdir");
    let new = PastaRunDir::prepare(fd.as_fd(), "web1").expect("new generation");
    std::fs::write(new.pid_path(), b"4242\n").expect("pid");
    drop(cli);
    let r = worker.join().expect("worker");
    assert_eq!(r.expect_err("abandoned").code(), ErrorCode::Timeout);
    assert_eq!(std::fs::read(new.pid_path()).expect("pid"), b"4242\n");
    let _ = std::fs::remove_dir_all(&root);
}

/// CORE-2・NET-9: ロックを取れた準備は置き場所を作って渡し、同じロックの下の削除は自分のものだけを消す。
#[test]
fn core2_prepare_then_remove_under_the_id_lock_round_trips() {
    let (root, fd) = scratch_root("rt");
    let fd = Arc::new(fd);
    let job = io_job(&root, &fd, "web1");
    let gens = RunDirGenerations::default();
    let slot = Mutex::new(PreparedSlot::default());
    let never = AtomicBool::new(false);
    prepare_run_dir_job(&job, Duration::from_secs(5), &gens, &slot, &never).expect("prepare");
    let (ours, generation) = {
        let g = lock(&slot);
        (g.ours, g.ready.as_ref().map(|(n, _)| *n))
    };
    assert_eq!(generation, Some(1));
    assert!(ours.is_some());
    assert!(root.join("@pasta/web1").is_dir());
    let removed = remove_run_dir_job(&job, Duration::from_secs(5), &gens, None, ours, &never)
        .expect("remove");
    assert!(removed);
    assert!(!root.join("@pasta/web1").exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// CORE-2・NET-9(#3355): 準備の job は保持している fd の同一性を `ours` に記録し、既存の dir の古い pid は
/// 観測と一致するので消す。
#[test]
fn core2_prepare_job_records_identity_of_held_dir_and_clears_stale_pid() {
    use std::os::unix::fs::MetadataExt as _;
    let (root, fd) = scratch_root("heldid");
    let fd = Arc::new(fd);
    drop(PastaRunDir::prepare(fd.as_fd(), "web1").expect("seed"));
    std::fs::write(root.join("@pasta/web1/pid"), b"4242\n").expect("pid");
    let job = io_job(&root, &fd, "web1");
    let gens = RunDirGenerations::default();
    let slot = Mutex::new(PreparedSlot::default());
    let never = AtomicBool::new(false);
    prepare_run_dir_job(&job, Duration::from_secs(5), &gens, &slot, &never).expect("prepare");
    let (ours, generation) = {
        let g = lock(&slot);
        (g.ours, g.ready.as_ref().map(|(n, _)| *n))
    };
    let md = std::fs::symlink_metadata(root.join("@pasta/web1")).expect("md");
    assert_eq!(generation, Some(1));
    assert_eq!(ours, Some((md.dev(), md.ino())));
    assert!(!root.join("@pasta/web1/pid").exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// NET-9・CORE-2: launch が attach の前に失敗した(フックが走らない・holder の起動失敗など)ときも、準備済みの
/// 置き場所を回収する。`discard`(起動権の予約を握った後の後始末)も同じ回収を行う。
#[test]
fn net9_launch_failure_without_attachment_reclaims_prepared_run_dir() {
    let ev: Events = Arc::default();
    let backend = FakeBackend::new(&ev);
    let (w, _b) = wiring(&backend);
    let l = launcher(&w);
    let e = l
        .adopt(Err(TraitError::new(ErrorCode::Timeout, "launch failed")))
        .err()
        .expect("passes the error through");
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert_eq!(events(&ev), ["remove run_dir"]);
    ev.lock().unwrap().clear();
    w.discard().expect("discard");
    assert_eq!(events(&ev), ["remove run_dir"]);
}
