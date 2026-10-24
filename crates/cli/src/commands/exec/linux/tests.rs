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
use fandhe_container_core::traits::{ContainerStatus, CreateStateRequest, UpdateStateRequest};

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
    let bundle = base.0.join("bundle");
    std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(bundle.join("config.json"), "{}").expect("config");
    let created = store
        .create(
            &CreateStateRequest::new(ContainerStatus::created(id(name), None), bundle)
                .expect("req"),
        )
        .expect("create");
    if running {
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id(name), NonZeroU32::new(PID)),
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

/// 偽の取得元: 呼ばれた pid を記録し、`/dev/null` を開いた fd を返す（または失敗する）。
struct FakeSource {
    calls: Mutex<Vec<u32>>,
    fail: Option<ErrorCode>,
}

impl FakeSource {
    fn ok() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fail: None,
        }
    }
}

impl ExecPidfdSource for FakeSource {
    fn obtain(
        &self,
        _id: &ContainerId,
        pid: NonZeroU32,
        _deadline: Instant,
    ) -> Result<OwnedFd, TraitError> {
        self.calls.lock().expect("lock").push(pid.get());
        match self.fail {
            Some(code) => Err(TraitError::new(code, "fake handover failure")),
            None => Ok(OwnedFd::from(
                std::fs::File::open("/dev/null").expect("open /dev/null"),
            )),
        }
    }
}

/// 偽の実行役が見た入力と、返す結果。
struct FakeRun {
    seen: Mutex<Vec<(u32, bool)>>,
    result: Mutex<Option<Result<ExecExit, AuditedRejection<TraitError>>>>,
}

impl FakeRun {
    fn returning(result: Result<ExecExit, AuditedRejection<TraitError>>) -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
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
        _timeout: Duration,
        audit: &dyn AuditSink,
    ) -> Result<ExecExit, AuditedRejection<TraitError>> {
        self.seen.lock().expect("lock").push((
            record.status().pid().map_or(0, NonZeroU32::get),
            pidfd.as_raw_fd() >= 0,
        ));
        assert_eq!(request.path(), Path::new("/bin/true"));
        // 配線の検証: 実行役へ渡った sink へ記録すると、生成口が作った sink の件数が増える。
        let delivery = record_exit_signal(31, 1234, Some(record.status().id()), audit);
        assert_eq!(delivery, AuditDelivery::Recorded);
        self.result.lock().expect("lock").take().expect("one call")
    }
}

fn runner(
    fake: &FakeRun,
) -> impl Fn(
    &StateRecord,
    BorrowedFd<'_>,
    &ExecRequest,
    Duration,
    &dyn AuditSink,
) -> Result<ExecExit, AuditedRejection<TraitError>>
+ '_ {
    move |r, fd, req, t, a| fake.run(r, fd, req, t, a)
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
        calls: Mutex::new(Vec::new()),
        fail: Some(ErrorCode::Unavailable),
    };
    let fake = FakeRun::must_not_run();
    let e = run_with(&store, &probe, &fake, &source, "c1").unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unavailable);
    assert!(fake.seen.lock().unwrap().is_empty());
    // 取得の失敗では監査に何も書かない（拒否の記録は run_command_with_pidfd の責務）。
    assert_eq!(probe.records.load(Ordering::SeqCst), 0);
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
