//! `exec` の配線（`exec_in_container`）の単体テスト（SUP-6・SEC-4・SEC-1・REPAIR-5・#2626）。
//!
//! 実コマンドも実 supervisor も使わず、状態ストアは実物（一時ディレクトリの `FileStateStore`）、pidfd の取得元・
//! 実行役・監査 sink は偽物に差し替える。本番の `FileAuditSink` は記録のたびに子プロセスを fork する（多スレッドの
//! libtest では fork できない）ため、ここでは使わない。本番 sink が状態ルートの `@audit.log` を指すこと
//! （`default_audit_sink`）の確認は `core` の `audit_sink_isolation` と実機前提の通し試験が担い、本テストは
//! 「状態ストアの `host_state_root` が sink の生成口へそのまま渡り、実行役へ渡る」配線を具体値で固定する。

use std::num::NonZeroU32;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use fandhe_container_core::audit_log::{AuditDelivery, AuditRecord, record_exit_signal};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    Annotations, ContainerStatus, CreateStateRequest, UpdateStateRequest,
};
use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
use fandhe_container_supervisor::container_options::store::{GENERATION_ANNOTATION, write_new};
use fandhe_container_supervisor::control::{ExecCreatedNotifier, ExecHandover};

use super::*;

const PID: u32 = 4242;

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        // 予測可能な共有 /tmp 上の名前なので、排他的作成（`create_dir`）だけを使い、既存エントリ（symlink を含む）は
        // 採用せず別名で再試行する。作成時から 0700（`set_permissions` で symlink の参照先を chmod しない）。
        use std::os::unix::fs::DirBuilderExt as _;
        let p = loop {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p =
                std::env::temp_dir().join(format!("fc-cli-exec-{tag}-{}-{n}", std::process::id()));
            match std::fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => break p,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("mkdir: {e}"),
            }
        };
        Self(p)
    }

    fn state_root(&self) -> PathBuf {
        self.0.join("state")
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn id(s: &str) -> ContainerId {
    ContainerId::new(s).expect("id")
}

fn open(base: &TmpDir) -> FileStateStore {
    let root = StateRoot::from_override(base.state_root()).expect("root");
    FileStateStore::open(root).expect("open")
}

/// `name` の記録を作る（Created。`running` なら Running(PID) へ更新する）。
fn seed(base: &TmpDir, store: &FileStateStore, name: &str, running: bool) {
    seed_with_generation(base, store, name, running, None);
}

/// [`seed`] に、create の起動オプション文書の世代注釈（`GENERATION_ANNOTATION`）を付けられるようにしたもの。
fn seed_with_generation(
    base: &TmpDir,
    store: &FileStateStore,
    name: &str,
    running: bool,
    generation: Option<&str>,
) {
    seed_with_pid(base, store, name, running, generation, PID);
}

/// [`seed_with_generation`] に、Running の記録の pid を指定できるようにしたもの（#2766）。
fn seed_with_pid(
    base: &TmpDir,
    store: &FileStateStore,
    name: &str,
    running: bool,
    generation: Option<&str>,
    pid: u32,
) {
    let bundle = base.0.join("bundle");
    std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(bundle.join("config.json"), "{}").expect("config");
    let mut request =
        CreateStateRequest::new(ContainerStatus::created(id(name), None), bundle).expect("req");
    if let Some(g) = generation {
        let annotations =
            Annotations::new([(GENERATION_ANNOTATION.to_owned(), g.to_owned())]).expect("ann");
        request = request.with_annotations(annotations);
    }
    let created = store.create(&request).expect("create");
    if running {
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id(name), NonZeroU32::new(pid)),
                created.revision(),
            ))
            .expect("running");
    }
}

/// 記録を数えるだけの偽の監査 sink。
struct CountingSink(Arc<AtomicUsize>);

impl AuditSink for CountingSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), TraitError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// 偽の sink 生成口: 渡された状態ルートを記録し、`records` を数える sink を返す。
#[derive(Clone, Default)]
struct Probe {
    roots: Arc<Mutex<Vec<PathBuf>>>,
    records: Arc<AtomicUsize>,
}

impl Probe {
    fn make(&self, root: &Path) -> Result<Box<dyn AuditSink>, TraitError> {
        self.roots.lock().expect("lock").push(root.to_path_buf());
        Ok(Box::new(CountingSink(Arc::clone(&self.records))))
    }
}

/// 偽の作成通知の口: 通知された名前と保持期限（全体の期限）を記録し、設定があれば失敗する。
#[derive(Default)]
struct NotifyLog {
    names: Mutex<Vec<(String, Instant)>>,
    fail: Option<ErrorCode>,
    /// 接続（`ExecHandover`）が drop された回数。
    dropped: AtomicUsize,
}

struct FakeNotifier(Arc<NotifyLog>);

impl ExecCreatedNotifier for FakeNotifier {
    fn notify_created(&self, name: &ExecCgroupName, hold_until: Instant) -> Result<(), TraitError> {
        self.0
            .names
            .lock()
            .expect("lock")
            .push((name.as_str().to_owned(), hold_until));
        match self.0.fail {
            Some(code) => Err(TraitError::new(code, "fake notify failure")),
            None => Ok(()),
        }
    }
}

impl Drop for FakeNotifier {
    fn drop(&mut self) {
        self.0.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// 偽の取得元: 呼ばれた pid を記録し、`/dev/null` を開いた fd と偽の通知の口を返す（または失敗する）。
struct FakeSource {
    calls: Mutex<Vec<u32>>,
    fail: Option<ErrorCode>,
    notify: Arc<NotifyLog>,
}

impl FakeSource {
    fn ok() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fail: None,
            notify: Arc::new(NotifyLog::default()),
        }
    }

    /// 通知が失敗する取得元。
    fn notify_fails(code: ErrorCode) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fail: None,
            notify: Arc::new(NotifyLog {
                fail: Some(code),
                ..NotifyLog::default()
            }),
        }
    }
}

impl ExecPidfdSource for FakeSource {
    fn obtain(
        &self,
        _id: &ContainerId,
        pid: NonZeroU32,
        _deadline: Instant,
    ) -> Result<ExecHandover, TraitError> {
        self.calls.lock().expect("lock").push(pid.get());
        match self.fail {
            Some(code) => Err(TraitError::new(code, "fake handover failure")),
            None => Ok(ExecHandover::new(
                OwnedFd::from(std::fs::File::open("/dev/null").expect("open /dev/null")),
                Box::new(FakeNotifier(Arc::clone(&self.notify))),
            )),
        }
    }
}

/// 偽の実行役が見た入力と、返す結果。
struct FakeRun {
    seen: Mutex<Vec<(u32, bool)>>,
    /// 実行役へ渡った launch 時の env 上書き（呼び出しごと）。
    launch_envs: Mutex<Vec<Vec<String>>>,
    result: Mutex<Option<Result<ExecExit, AuditedRejection<TraitError>>>>,
}

impl FakeRun {
    fn returning(result: Result<ExecExit, AuditedRejection<TraitError>>) -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
            launch_envs: Mutex::new(Vec::new()),
            result: Mutex::new(Some(result)),
        }
    }

    /// 呼ばれてはならない場面用（呼ばれたら `seen` に残り、各テストが空であることを確かめる）。
    fn must_not_run() -> Self {
        Self::returning(Err(AuditedRejection::not_applicable(TraitError::new(
            ErrorCode::Internal,
            "must not run",
        ))))
    }

    fn run(
        &self,
        record: &StateRecord,
        pidfd: BorrowedFd<'_>,
        request: &ExecRequest,
        ctx: &RunContext<'_>,
        _timeout: Duration,
        audit: &dyn AuditSink,
    ) -> Result<ExecExit, AuditedRejection<TraitError>> {
        self.launch_envs
            .lock()
            .expect("lock")
            .push(ctx.launch_env.to_vec());
        self.seen.lock().expect("lock").push((
            record.status().pid().map_or(0, NonZeroU32::get),
            pidfd.as_raw_fd() >= 0,
        ));
        assert_eq!(request.path(), Path::new("/bin/true"));
        // 本番の実行役と同じく、cgroup の作成直後に通知する。失敗は worker の fork 前の中止（fail-closed）。
        if let Err(e) = (ctx.on_created)(&ExecCgroupName::new("exec-4242-0").expect("name")) {
            return Err(AuditedRejection::not_applicable(e));
        }
        // 配線の検証: 実行役へ渡った sink へ記録すると、生成口が作った sink の件数が増える。
        let delivery = record_exit_signal(31, 1234, Some(record.status().id()), audit);
        assert_eq!(delivery, AuditDelivery::Recorded);
        self.result.lock().expect("lock").take().expect("one call")
    }
}

/// 実行役の戻り値（`Runner` と同じ）。
type RunResult = Result<ExecExit, AuditedRejection<TraitError>>;

fn runner(
    fake: &FakeRun,
) -> impl Fn(
    &StateRecord,
    BorrowedFd<'_>,
    &ExecRequest,
    &RunContext<'_>,
    Duration,
    &dyn AuditSink,
) -> RunResult
+ '_ {
    move |r, fd, req, ctx, t, a| fake.run(r, fd, req, ctx, t, a)
}

fn req() -> ExecRequest {
    ExecRequest::new("/bin/true", ["/bin/true"]).expect("request")
}

fn run_with(
    store: &FileStateStore,
    probe: &Probe,
    fake: &FakeRun,
    source: &FakeSource,
    name: &str,
) -> Result<u8, TraitError> {
    exec_in_container(
        store,
        source,
        &|root| probe.make(root),
        &runner(fake),
        &id(name),
        &req(),
        Duration::from_secs(30),
    )
}

/// SUP-6: 終了状態 → プロセスの終了コードの写像（具体値）。
#[test]
fn sup6_child_exit_code_mapping() {
    assert_eq!(child_exit_code(ChildExit::Exited(0)), 0);
    assert_eq!(child_exit_code(ChildExit::Exited(3)), 3);
    assert_eq!(child_exit_code(ChildExit::Exited(125)), 125);
    assert_eq!(child_exit_code(ChildExit::Exited(127)), 127);
    assert_eq!(child_exit_code(ChildExit::Exited(255)), 255);
    assert_eq!(child_exit_code(ChildExit::Signaled(9)), 137);
    assert_eq!(child_exit_code(ChildExit::Signaled(15)), 143);
    // 範囲外は捏造せず Internal(1) に倒す。
    assert_eq!(child_exit_code(ChildExit::Exited(256)), 1);
    assert_eq!(child_exit_code(ChildExit::Exited(-1)), 1);
    assert_eq!(child_exit_code(ChildExit::Signaled(200)), 1);
}

/// SUP-6・#2626: `ExecExit` の写像は起動の有無によらず子の終了状態を使う（SetupFailed の 125 / 126 / 127 をそのまま返す）。
#[test]
fn sup6_setup_failed_keeps_child_exit_status() {
    let exit = ExecExit::SetupFailed {
        exit: ChildExit::Exited(127),
        violation: None,
        code: ErrorCode::NotFound,
        step: None,
    };
    assert_eq!(child_exit_code(exit.child_exit()), 127);
    assert_eq!(
        child_exit_code(ExecExit::Command(ChildExit::Signaled(9)).child_exit()),
        137
    );
}

/// SUP-6・SEC-4・#2626: 成功経路の終了コード。`Exited(0)` → 0、`Exited(3)` → 3（OCI_EXIT と重なる値もそのまま）、
/// `Signaled(9)` → 137、`SetupFailed(127)` → 127。pidfd は記録 pid で 1 回受け渡され、sink の生成口は
/// 状態ストアの `host_state_root` を受け取り、実行役へ渡った sink に記録できる。
#[test]
fn sup6_exit_codes_pass_through_the_wiring() {
    for (exit, expected) in [
        (ExecExit::Command(ChildExit::Exited(0)), 0u8),
        (ExecExit::Command(ChildExit::Exited(3)), 3),
        (ExecExit::Command(ChildExit::Signaled(9)), 137),
        (
            ExecExit::SetupFailed {
                exit: ChildExit::Exited(127),
                violation: None,
                code: ErrorCode::NotFound,
                step: None,
            },
            127,
        ),
    ] {
        let base = TmpDir::new("exitcodes");
        let store = open(&base);
        seed(&base, &store, "c1", true);
        let (probe, source, fake) = (
            Probe::default(),
            FakeSource::ok(),
            FakeRun::returning(Ok(exit)),
        );
        assert_eq!(run_with(&store, &probe, &fake, &source, "c1"), Ok(expected));
        assert_eq!(*source.calls.lock().unwrap(), vec![PID]);
        assert_eq!(*fake.seen.lock().unwrap(), vec![(PID, true)]);
        // 起動オプション文書の無い（世代注釈の無い）記録では launch 時の env 上書きは空。
        assert_eq!(
            *fake.launch_envs.lock().unwrap(),
            vec![Vec::<String>::new()]
        );
        assert_eq!(
            *probe.roots.lock().unwrap(),
            vec![store.host_state_root().expect("root").to_path_buf()]
        );
        assert_eq!(probe.records.load(Ordering::SeqCst), 1);
    }
}

/// SEC-4・SUP-6・#2626: 拒否は構造化エラーで返り（覆らない）、終了コードは ERR-2 の表
/// （PERMISSION_DENIED = 6）。
#[test]
fn sec4_sup6_rejection_is_returned_with_err2_exit_code() {
    let base = TmpDir::new("reject");
    let store = open(&base);
    seed(&base, &store, "c1", true);
    let (probe, source) = (Probe::default(), FakeSource::ok());
    let fake = FakeRun::returning(Err(AuditedRejection::not_applicable(TraitError::new(
        ErrorCode::PermissionDenied,
        "exec target pidfd mismatch",
    ))));
    let e = run_with(&store, &probe, &fake, &source, "c1").unwrap_err();
    assert_eq!(e.code(), ErrorCode::PermissionDenied);
    assert_eq!(probe.records.load(Ordering::SeqCst), 1);
    match failure(&e) {
        CliExit::Error(err) => {
            assert_eq!(err.exit_code().get(), 6);
            assert_eq!(err.code_str(), "PERMISSION_DENIED");
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// SEC-4: 記録先を作れなければ pidfd の受け渡しも exec もしない（fail-closed）。
#[test]
fn sec4_sink_failure_stops_before_handover_and_run() {
    let base = TmpDir::new("sinkfail");
    let store = open(&base);
    seed(&base, &store, "c1", true);
    let (source, fake) = (FakeSource::ok(), FakeRun::must_not_run());
    let failing = |_: &Path| -> Result<Box<dyn AuditSink>, TraitError> {
        Err(TraitError::new(ErrorCode::Unavailable, "no audit sink"))
    };
    let e = exec_in_container(
        &store,
        &source,
        &failing,
        &runner(&fake),
        &id("c1"),
        &req(),
        Duration::from_secs(30),
    )
    .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unavailable);
    assert!(source.calls.lock().unwrap().is_empty());
    assert!(fake.seen.lock().unwrap().is_empty());
}

/// SUP-6: 稼働中でない（Created）・存在しないコンテナは exec しない（sink も pidfd も要求しない）。
#[test]
fn sup6_not_running_and_missing_are_rejected_before_anything_else() {
    let base = TmpDir::new("state");
    let store = open(&base);
    seed(&base, &store, "created", false);
    let (probe, source, fake) = (Probe::default(), FakeSource::ok(), FakeRun::must_not_run());
    let e = run_with(&store, &probe, &fake, &source, "created").unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    let e = run_with(&store, &probe, &fake, &source, "missing").unwrap_err();
    assert_eq!(e.code(), ErrorCode::NotFound);
    assert!(probe.roots.lock().unwrap().is_empty());
    assert!(source.calls.lock().unwrap().is_empty());
    assert!(fake.seen.lock().unwrap().is_empty());
}

/// SEC-1: pidfd を受け取れなければ（supervisor 不在・pid 不一致・古い版）exec せず、その構造化エラーを返す。
#[test]
fn sec1_handover_failure_stops_before_run() {
    let base = TmpDir::new("handover");
    let store = open(&base);
    seed(&base, &store, "c1", true);
    let probe = Probe::default();
    let source = FakeSource {
        fail: Some(ErrorCode::Unavailable),
        ..FakeSource::ok()
    };
    let fake = FakeRun::must_not_run();
    let e = run_with(&store, &probe, &fake, &source, "c1").unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unavailable);
    assert!(fake.seen.lock().unwrap().is_empty());
    // 取得の失敗では監査に何も書かない（拒否の記録は run_command_with_pidfd の責務）。
    assert_eq!(probe.records.load(Ordering::SeqCst), 0);
}

/// SUP-6・SUP-8・SEC-1・SEC-4・#2766: supervisor 不在（制御ソケットが無い・残骸だけ・Hello 前に切断）のとき、
/// 本物の取得元（`production_exec_pidfd_source`）が `Unavailable` を返し、記録の pid（ここでは生きている自プロセス）
/// からの `pidfd_open` へ縮退しない。縮退があれば実行役が呼ばれる。`sec1_handover_failure_stops_before_run`
/// （偽の取得元）を補う。
#[test]
fn sup6_sup8_sec4_2766_absent_supervisor_is_unavailable_without_pidfd_fallback() {
    use std::os::unix::net::UnixListener;
    let live_pid = std::process::id();
    for scenario in ["no-socket", "stale-socket", "closes-before-hello"] {
        let base = TmpDir::new("absent-sup");
        let store = open(&base);
        seed_with_pid(&base, &store, "c1", true, None, live_pid);
        let sock_dir = base.state_root().join("c1");
        let hold = match scenario {
            "no-socket" => None,
            "stale-socket" => {
                // bind して閉じ、ソケットファイルの残骸だけを残す（接続拒否）。
                let l = UnixListener::bind(sock_dir.join("supervisor.sock")).expect("bind");
                drop(l);
                None
            }
            _ => {
                let l = UnixListener::bind(sock_dir.join("supervisor.sock")).expect("bind");
                let l2 = l.try_clone().expect("clone");
                let t = std::thread::spawn(move || {
                    // 受け付けてすぐ閉じる（Hello を返さずに切れる）。
                    if let Ok((s, _)) = l2.accept() {
                        drop(s);
                    }
                });
                Some((l, t))
            }
        };
        let probe = Probe::default();
        let fake = FakeRun::must_not_run();
        let source = fandhe_container_supervisor::control::production_exec_pidfd_source(&store);
        let e = exec_in_container(
            &store,
            &*source,
            &|root| probe.make(root),
            &runner(&fake),
            &id("c1"),
            &req(),
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::Unavailable, "{scenario}");
        assert_eq!(
            e.message(),
            "the supervisor control channel is unavailable",
            "{scenario}"
        );
        assert!(fake.seen.lock().unwrap().is_empty(), "{scenario}");
        assert_eq!(probe.records.load(Ordering::SeqCst), 0, "{scenario}");
        if let Some((l, t)) = hold {
            // 接続は 1 回で accept が済む。済まなければ自分で 1 回つないで解除する。
            let _ = std::os::unix::net::UnixStream::connect(sock_dir.join("supervisor.sock"));
            let _ = t.join();
            drop(l);
        }
    }
}

/// REPAIR-5: 全体の期限が尽きていれば（pidfd の受け渡しの後に残りが無い）exec せず Timeout。
#[test]
fn repair5_exhausted_timeout_does_not_run() {
    let base = TmpDir::new("timeout");
    let store = open(&base);
    seed(&base, &store, "c1", true);
    let (probe, source, fake) = (Probe::default(), FakeSource::ok(), FakeRun::must_not_run());
    let e = exec_in_container(
        &store,
        &source,
        &|root| probe.make(root),
        &runner(&fake),
        &id("c1"),
        &req(),
        Duration::ZERO,
    )
    .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Timeout);
    assert!(fake.seen.lock().unwrap().is_empty());
}

/// 本番の記録先の生成口は、検査済みの状態ルートから作れる（`default_audit_sink`。ファイルは開かない）。
/// 親が存在しない状態ルートは作れず `NotFound`（exec しない）。
#[test]
fn sec4_production_sink_factory_opens_state_root() {
    let base = TmpDir::new("sinkroot");
    let store = open(&base);
    let root = store.host_state_root().expect("root").to_path_buf();
    assert!(production_sink(&root).is_ok());
    let missing_parent = base.0.join("no-such-parent").join("state");
    assert_eq!(
        production_sink(&missing_parent).err().map(|e| e.code()),
        Some(ErrorCode::NotFound)
    );
}

/// 要求の構築: 絶対パス以外は fork する前に InvalidArgument、`--env` つきの正常な要求は作れる。
#[test]
fn sup6_build_request_validates_before_anything_else() {
    use super::super::super::args::parse_exec;
    let parse = |a: &[&str]| parse_exec(a.iter().map(std::ffi::OsString::from).collect());
    let ok = parse(&["--env", "A=1", "c1", "/bin/echo", "hi"]).expect("parse");
    assert!(build_request(&ok).is_ok());
    let relative = parse(&["c1", "echo"]).expect("parse");
    assert_eq!(
        build_request(&relative).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

/// SUP-6・CORE-3・#2626: 委譲スコープでの再実行の argv・環境は固定（systemd-run の引数 + 自分 + 元の argv。目印の環境変数つき）。
#[test]
fn sup6_core3_scoped_command_is_fixed() {
    use std::ffi::OsString;
    let cmd = scoped_command(
        std::path::Path::new("/usr/bin/systemd-run"),
        std::path::Path::new("/opt/fc/fandhe-container"),
        ["--root", "/r", "exec", "c1", "/bin/true"].map(OsString::from),
        std::ffi::OsStr::new("/run/user/1000"),
    );
    assert_eq!(cmd.get_program(), "/usr/bin/systemd-run");
    let args: Vec<_> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        args,
        [
            "--user",
            "--scope",
            "--quiet",
            "-p",
            "Delegate=yes",
            "--",
            "/opt/fc/fandhe-container",
            "--root",
            "/r",
            "exec",
            "c1",
            "/bin/true"
        ]
    );
    let envs: Vec<_> = cmd
        .get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect();
    assert!(envs.contains(&("XDG_RUNTIME_DIR".into(), Some("/run/user/1000".into()))));
    assert!(envs.contains(&(IN_SCOPE_ENV.into(), Some("1".into()))));
}

/// SUP-6・#2626: 子の終了状態の写像（通常終了は値そのまま、シグナルは 128 + s）。
#[test]
fn sup6_status_to_code_maps_exit_and_signal() {
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::ExitStatus;
    assert_eq!(status_to_code(ExitStatus::from_raw(7 << 8)), 7);
    assert_eq!(status_to_code(ExitStatus::from_raw(9)), 137);
}

/// SUP-6・REPAIR-5・#2626: 環境変数が無ければ子の期限は `--timeout` のまま（並列実行のため set はしない）。
#[test]
fn sup6_scoped_timeout_never_extends() {
    if std::env::var_os(DEADLINE_MS_ENV).is_none() {
        assert_eq!(
            scoped_timeout(Duration::from_secs(30)),
            Duration::from_secs(30)
        );
    }
}

/// REPAIR-5・#2626: 絶対期限から残りを算出する（起動に使った時間が差し引かれる。過ぎていれば 1ms）。
#[test]
fn repair5_remaining_is_derived_from_absolute_deadline() {
    assert_eq!(
        remaining_until(100_000, 92_500),
        Duration::from_millis(7_500)
    );
    assert_eq!(remaining_until(100_000, 100_000), Duration::from_millis(1));
    assert_eq!(remaining_until(100_000, 200_000), Duration::from_millis(1));
}

/// REPAIR-5・CLI-1: 準備段（ストアのロック待ち等）に使った時間は `--timeout` から差し引かれ、使い切ったら
/// 再実行せず期限切れにする（全量の予算を与え直さない）。
#[test]
fn repair5_cli1_preparation_time_is_deducted_from_timeout() {
    let one = Duration::from_secs(1);
    assert_eq!(
        remaining_budget(one, Duration::from_millis(250)),
        Some(Duration::from_millis(750))
    );
    assert_eq!(remaining_budget(one, one), None);
    assert_eq!(remaining_budget(one, Duration::from_secs(4)), None);
    assert_eq!(remaining_budget(one, Duration::ZERO), Some(one));
    match budget_exhausted() {
        CliExit::Error(e) => {
            assert_eq!(e.code(), ErrorCode::Timeout);
            assert_eq!(e.message(), "exec timed out before the command started");
        }
        _ => panic!("expected a structured timeout error"),
    }
}

/// #2626: `/proc/uptime` の本文の解釈（10ms 刻み。壊れていれば None）。
#[test]
fn sup6_parse_uptime_ms() {
    assert_eq!(parse_uptime_ms("12345.67 9999.00\n"), Some(12_345_670));
    assert_eq!(parse_uptime_ms("5.1 0.0"), Some(5_100));
    assert_eq!(parse_uptime_ms("7 0"), Some(7_000));
    assert_eq!(parse_uptime_ms("abc 1"), None);
    assert_eq!(parse_uptime_ms("1.x 1"), None);
    assert_eq!(parse_uptime_ms(""), None);
    assert!(monotonic_now_ms().is_some());
}

/// ERR-1・ERR-2: 開始行は同じ read に wrapper の診断と子の出力が混ざっても位置で切れる（時刻・ファイルに依らない）。
#[test]
fn err1_start_line_splits_wrapper_diagnostic_from_child_output() {
    let needle = format!("{START_LINE_PREFIX}n1\n").into_bytes();
    let tail = b"{\"code\":1}\n".as_slice();
    let mixed = [b"Failed to connect to bus\n".as_slice(), &needle, tail].concat();
    let end = find_after(&mixed, &needle).expect("start line present");
    assert_eq!(mixed.get(end..), Some(tail));
    assert_eq!(find_after(b"Failed to connect to bus\n", &needle), None);
    assert_eq!(find_after(&needle[..needle.len() - 1], &needle), None);
}

/// SUP-12・SUP-6・#2713・#2626: create の起動オプション文書の env（世代が記録と一致するもの）は、launch と同じく
/// exec の実行役へ launch 時の env 上書きとして渡る（healthcheck と同じ env の規則）。
#[test]
fn sup12_sup6_launch_env_reaches_exec_runner() {
    let base = TmpDir::new("launchenv");
    let store = open(&base);
    seed_with_generation(&base, &store, "c1", true, Some("g1"));
    let root = store.host_state_root().expect("root").to_path_buf();
    let document = ContainerOptionsDocument::new(
        Vec::new(),
        vec!["TOKEN=dummy-value".into(), "MODE=exec".into()],
        None,
        None,
        Vec::new(),
    )
    .expect("doc")
    .with_generation("g1".into())
    .expect("generation");
    write_new(&root, &id("c1"), &document).expect("write");
    let (probe, source) = (Probe::default(), FakeSource::ok());
    let fake = FakeRun::returning(Ok(ExecExit::Command(ChildExit::Exited(0))));
    assert_eq!(run_with(&store, &probe, &fake, &source, "c1"), Ok(0));
    assert_eq!(
        *fake.launch_envs.lock().unwrap(),
        vec![vec!["TOKEN=dummy-value".to_owned(), "MODE=exec".to_owned()]]
    );
    assert_eq!(*source.calls.lock().unwrap(), vec![PID]);
}

/// SUP-12・SUP-6・#2713・#2626: 記録が世代注釈を持つのに起動オプション文書が無いときは FailedPrecondition（5）で
/// 拒否し、監査の記録先も作らず、supervisor へ pidfd を求めず、実行役も呼ばない（オプションを黙って落とさない）。
#[test]
fn sup12_sup6_missing_options_document_rejects_before_handover() {
    let base = TmpDir::new("launchenv-missing");
    let store = open(&base);
    seed_with_generation(&base, &store, "c1", true, Some("g1"));
    let (probe, source, fake) = (Probe::default(), FakeSource::ok(), FakeRun::must_not_run());
    let e = run_with(&store, &probe, &fake, &source, "c1").unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "the container options file is missing");
    assert!(probe.roots.lock().unwrap().is_empty());
    assert!(source.calls.lock().unwrap().is_empty());
    assert!(fake.seen.lock().unwrap().is_empty());
}

/// 親追従の試験で、試験バイナリ自身を別の役で起動するための環境変数（`mid` / `leaf`）。
const PDEATH_ROLE_ENV: &str = "FANDHE_CONTAINER_TEST_PDEATH_ROLE";
/// 役が自分の pid を書き出すファイルの環境変数。
const PDEATH_PIDFILE_ENV: &str = "FANDHE_CONTAINER_TEST_PDEATH_PIDFILE";

/// プロセスが生きているか（`/proc/<pid>/stat` の状態が無い・ゾンビ・死亡なら生きていない）。
fn pid_alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| {
            s.rsplit_once(')')
                .and_then(|(_, rest)| rest.trim_start().chars().next())
        })
        .is_some_and(|state| !matches!(state, 'Z' | 'X'))
}

/// 期限つきで `path` の pid を読む（REPAIR-5）。
fn wait_pid_file(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Some(pid) = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
        {
            return pid;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("pid file {} was not written", path.display());
}

/// SUP-6・CLI-1・REPAIR-5・REPAIR-12: 委譲スコープ内の子が `bind_to_parent_lifetime`（`PR_SET_PDEATHSIG` と親 pid の照合）を
/// 通ったあとは、親が SIGKILL で死ぬと子も止まる。試験バイナリを 3 世代（orchestrator → mid → leaf）で起動し、
/// leaf が本物の `bind_to_parent_lifetime` を呼んで待つ。mid を殺して leaf の消滅を期限つきで確かめる。
/// 併せて、親 pid の環境変数が実際の親と違えば fail-closed で `Unavailable`（"the exec parent is gone"）になる。
#[test]
fn sup6_cli1_child_stops_when_parent_dies() {
    let role = std::env::var(PDEATH_ROLE_ENV).ok();
    let test_name = format!("{}::sup6_cli1_child_stops_when_parent_dies", module_path!());
    let test_name = test_name
        .split_once("::")
        .map_or(test_name.as_str(), |(_, rest)| rest)
        .to_owned();
    let pidfile = std::env::var_os(PDEATH_PIDFILE_ENV).map(PathBuf::from);
    let spawn_role = |role: &str, pidfile: &Path, parent_env: Option<String>| {
        let mut cmd = Command::new(std::env::current_exe().expect("current_exe"));
        cmd.args(["--exact", &test_name, "--test-threads=1", "--nocapture"])
            .env(PDEATH_ROLE_ENV, role)
            .env(PDEATH_PIDFILE_ENV, pidfile)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if let Some(p) = parent_env {
            cmd.env(PARENT_PID_ENV, p);
        }
        cmd.spawn().expect("spawn role")
    };
    match (role.as_deref(), pidfile) {
        (Some("leaf"), Some(pidfile)) => {
            // 本物の入口。親 pid の環境変数は mid が自分の pid を渡している。
            bind_to_parent_lifetime().expect("bind to parent");
            std::fs::write(&pidfile, std::process::id().to_string()).expect("write pid");
            std::thread::sleep(Duration::from_secs(120));
        }
        (Some("mid"), Some(pidfile)) => {
            let leaf_pid_file = pidfile.with_extension("leaf");
            let mut leaf = spawn_role("leaf", &leaf_pid_file, Some(std::process::id().to_string()));
            // leaf の pid を orchestrator へ転記してから待つ（leaf は mid の子）。
            let pid = wait_pid_file(&leaf_pid_file);
            std::fs::write(&pidfile, pid.to_string()).expect("write leaf pid");
            let _ = leaf.wait();
        }
        (Some("mismatch"), _) => {
            // 親 pid の環境変数が実際の親と違えば、設定後の照合で失敗する。
            let err = bind_to_parent_lifetime().expect_err("must fail");
            assert_eq!(err.code(), ErrorCode::Unavailable);
            assert_eq!(err.message(), "the exec parent is gone");
        }
        _ => {
            let base = TmpDir::new("pdeath");
            let pidfile = base.0.join("leaf.pid");
            // 実際の親と違う親 pid を渡した子は、確認で失敗して成功終了する（役の中の assert が通る）。
            let mut mismatch =
                spawn_role("mismatch", &pidfile.with_extension("mm"), Some("1".into()));
            let deadline = Instant::now() + Duration::from_secs(20);
            let status = loop {
                if let Some(st) = mismatch.try_wait().expect("try_wait") {
                    break st;
                }
                assert!(Instant::now() < deadline, "mismatch role did not exit");
                std::thread::sleep(Duration::from_millis(20));
            };
            assert!(status.success(), "mismatch role failed: {status:?}");
            let mut mid = spawn_role("mid", &pidfile, None);
            let leaf_pid = wait_pid_file(&pidfile);
            assert!(pid_alive(leaf_pid), "leaf must be running before the kill");
            mid.kill().expect("kill mid");
            let _ = mid.wait();
            let deadline = Instant::now() + Duration::from_secs(10);
            while pid_alive(leaf_pid) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            let alive = pid_alive(leaf_pid);
            if alive {
                // 失敗しても孤児を残さない。
                let _ = Command::new("kill")
                    .arg("-KILL")
                    .arg(leaf_pid.to_string())
                    .status();
            }
            assert!(!alive, "leaf {leaf_pid} must stop when its parent dies");
        }
    }
}

/// SUP-6・REPAIR-5・#2626: 実行役は cgroup の作成直後に通知し、その名前と全体の期限が supervisor 側の口へ渡る。
/// 接続は run が戻るまで保持され、exec_in_container が戻ったときに drop される（切断が回収の合図）。
#[test]
fn sup6_repair5_created_cgroup_is_notified_and_connection_outlives_run() {
    let base = TmpDir::new("notify");
    let store = open(&base);
    seed(&base, &store, "c1", true);
    let (probe, source) = (Probe::default(), FakeSource::ok());
    let fake = FakeRun::returning(Ok(ExecExit::Command(ChildExit::Exited(0))));
    let before = Instant::now();
    assert_eq!(run_with(&store, &probe, &fake, &source, "c1"), Ok(0));
    let names = source.notify.names.lock().unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].0, "exec-4242-0");
    // 保持期限は exec 全体の期限（呼び出し時刻 + 30 秒）で、それより長くならない。
    assert!(names[0].1 > before + Duration::from_secs(29));
    assert!(names[0].1 <= Instant::now() + Duration::from_secs(30));
    // 戻った後は接続（通知の口）が drop されている。
    assert_eq!(source.notify.dropped.load(Ordering::SeqCst), 1);
}

/// SUP-6・REPAIR-5・#2626: 通知（ack）に失敗したら exec は成立せず、その構造化エラーを返す（fail-closed）。接続も drop される。
#[test]
fn sup6_repair5_notify_failure_fails_closed() {
    let base = TmpDir::new("notifyfail");
    let store = open(&base);
    seed(&base, &store, "c1", true);
    let (probe, source) = (
        Probe::default(),
        FakeSource::notify_fails(ErrorCode::Unavailable),
    );
    // 通知の失敗は実行役の中止になる。成功の戻り値は使われない。
    let fake = FakeRun::returning(Ok(ExecExit::Command(ChildExit::Exited(0))));
    let e = run_with(&store, &probe, &fake, &source, "c1").unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unavailable);
    assert_eq!(e.message(), "fake notify failure");
    assert_eq!(source.notify.names.lock().unwrap().len(), 1);
    assert_eq!(source.notify.dropped.load(Ordering::SeqCst), 1);
}

/// REPAIR-5・SUP-6・#2626: 制御チャネルの保持期限の上限（supervisor の `MAX_EXEC_HOLD_SECS`）は、`exec --timeout` の
/// 上限以上である（上限を超える exec の通知が拒否されない）。
#[test]
fn repair5_hold_cap_covers_exec_max_timeout() {
    use fandhe_container_supervisor::control::protocol::MAX_EXEC_HOLD_SECS;
    const { assert!(super::super::super::args::EXEC_MAX_TIMEOUT_SECS <= MAX_EXEC_HOLD_SECS) };
}
