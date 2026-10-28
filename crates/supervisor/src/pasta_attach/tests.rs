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
}

impl HelperHandle for FakeHelper {
    fn pid(&self) -> u32 {
        self.pid
    }
    fn is_alive(&mut self) -> Result<bool, TraitError> {
        Ok(self.alive.load(Ordering::SeqCst))
    }
    fn stop(&mut self, detach_ok: bool) -> StopReport {
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
}

impl FakeBackend {
    fn new(ev: &Events) -> Arc<Self> {
        Arc::new(Self {
            ev: Arc::clone(ev),
            holder_result: Mutex::new(None),
            pasta_result: Mutex::new(None),
            holder_alive: Arc::new(AtomicBool::new(true)),
            pasta_alive: Arc::new(AtomicBool::new(true)),
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
            }),
            ready_ms: 7,
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
            }),
            ready_ms: 11,
        })
    }
    fn remove_run_dir(&self) -> Result<(), TraitError> {
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
                "remove run_dir",
                "stop holder detach=false"
            ]
        );
        assert!(lock(&w.slot).is_none());
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
    assert_eq!(events(&ev), ["container terminate"]);
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
    assert!(p.wait(Duration::ZERO).expect("wait").is_none());
    assert!(events(&ev).is_empty());
    let exit = p.wait(Duration::ZERO).expect("wait").expect("exited");
    assert_eq!(exit, ProcessExit::Exited(3));
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
    assert!(guarded.wait(Duration::ZERO).expect("wait").is_none());
    assert!(guarded.wait(Duration::ZERO).expect("wait").is_none());
    assert_eq!(events(&ev), ["container signal 15"]);
    std::thread::sleep(Duration::from_millis(80));
    assert!(guarded.wait(Duration::ZERO).expect("wait").is_none());
    assert!(guarded.wait(Duration::ZERO).expect("wait").is_none());
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
    assert!(guarded.wait(Duration::ZERO).expect("wait").is_none());
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
