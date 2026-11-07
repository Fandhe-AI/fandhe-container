//! stream-exec helper の結合試験（既定のテスト集合。SUP-6・SEC-1・SEC-4・REPAIR-5・REPAIR-12・#3760）。
//!
//! 実コンテナも root も使わない。次の 2 系統を具体値で固定する。
//! - `serve` の配線: 状態ストアは実物（一時ディレクトリの `FileStateStore`）、pidfd の取得元・監査 sink・実行役は偽物。
//!   「前提が崩れたら pidfd の要求も exec もしない」「作成通知の後に `Started`」「mask の不一致で exec しない」を数える。
//! - 本物の bin を `stream-exec` で起動した入口: 不正な引数は `Result(Failed(InvalidArgument))`、fd 0 が socket でなければ
//!   終了コード 1 と構造化された診断行。実コンテナへ通す試験は実機前提の `stream_exec_real`。

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::Read as _;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::audit_log::{AuditRecord, AuditSink, AuditedRejection};
use fandhe_container_core::exec::{ChildExit, ExecCgroupName, ExecExit};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, CreateStateRequest, ErrorCode, StateStore as _, TraitError,
    UpdateStateRequest,
};
use fandhe_container_supervisor::control::{ExecCreatedNotifier, ExecHandover, ExecPidfdSource};
use fandhe_container_supervisor::stream_exec::channel::{
    ChannelError, HelperMessage, StdioSend, recv_from_helper, send_stdio_handover,
};
use fandhe_container_supervisor::stream_exec::helper::{Deps, StreamExecArgs, serve};
use fandhe_container_supervisor::stream_exec::wire::{StdioMask, StreamExecOutcome};

const PID: u32 = 4242;

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let p = loop {
            let n = SEQ.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("fc-se-{tag}-{}-{n}", std::process::id()));
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

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).expect("id")
}

fn open(base: &Tmp) -> FileStateStore {
    FileStateStore::open(StateRoot::from_override(base.state_root()).expect("root")).expect("open")
}

fn seed(base: &Tmp, store: &FileStateStore, name: &str, running_pid: Option<u32>) {
    let bundle = base.0.join("bundle");
    std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
    std::fs::write(bundle.join("config.json"), "{}").expect("config");
    let created = store
        .create(
            &CreateStateRequest::new(ContainerStatus::created(cid(name), None), bundle)
                .expect("req"),
        )
        .expect("create");
    if let Some(pid) = running_pid {
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(cid(name), NonZeroU32::new(pid)),
                created.revision(),
            ))
            .expect("running");
    }
}

#[derive(Default)]
struct Counts {
    sink: AtomicUsize,
    source: AtomicUsize,
    run: AtomicUsize,
    /// 順序の記録（`notify` → `run-done` など）。
    events: Mutex<Vec<&'static str>>,
}

impl Counts {
    fn event(&self, e: &'static str) {
        self.events.lock().expect("lock").push(e);
    }
}

struct NoopSink;

impl AuditSink for NoopSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), TraitError> {
        Ok(())
    }
}

struct FakeNotifier {
    counts: Arc<Counts>,
    fail: bool,
}

impl ExecCreatedNotifier for FakeNotifier {
    fn notify_created(&self, _name: &ExecCgroupName, _hold: Instant) -> Result<(), TraitError> {
        self.counts.event("notify");
        if self.fail {
            Err(TraitError::new(ErrorCode::Unavailable, "notify failed"))
        } else {
            Ok(())
        }
    }
}

struct FakeSource {
    counts: Arc<Counts>,
    unavailable: bool,
    notify_fails: bool,
}

impl ExecPidfdSource for FakeSource {
    fn obtain(
        &self,
        _id: &ContainerId,
        _pid: NonZeroU32,
        _deadline: Instant,
    ) -> Result<ExecHandover, TraitError> {
        self.counts.source.fetch_add(1, Ordering::SeqCst);
        if self.unavailable {
            return Err(TraitError::new(ErrorCode::Unavailable, "no supervisor"));
        }
        let fd = OwnedFd::from(File::open("/dev/null").expect("devnull"));
        Ok(ExecHandover::new(
            fd,
            Box::new(FakeNotifier {
                counts: Arc::clone(&self.counts),
                fail: self.notify_fails,
            }),
        ))
    }
}

struct Scenario {
    sink_fails: bool,
    source_unavailable: bool,
    notify_fails: bool,
    exit: ExecExit,
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            sink_fails: false,
            source_unavailable: false,
            notify_fails: false,
            exit: ExecExit::Command(ChildExit::Exited(3)),
        }
    }
}

fn args_for(base: &Tmp, name: &str, pid: u32, stdio: u8) -> StreamExecArgs {
    StreamExecArgs::new(
        base.state_root(),
        cid(name),
        NonZeroU32::new(pid).expect("pid"),
        Duration::from_secs(30),
        StdioMask::new(stdio).expect("mask"),
        vec!["/bin/echo".into(), "hi".into()],
    )
    .expect("args")
}

/// `serve` を偽の依存で回す。戻り値は (結果, 数え上げ, plugin 側の channel の端)。
fn drive(
    store: &FileStateStore,
    args: &StreamExecArgs,
    stdio: &StdioSend<'_>,
    sc: &Scenario,
) -> (StreamExecOutcome, Arc<Counts>, UnixStream) {
    let counts = Arc::new(Counts::default());
    let (plugin, helper) = UnixStream::pair().expect("pair");
    send_stdio_handover(&plugin, stdio, Instant::now() + Duration::from_secs(5)).expect("send");
    let source = FakeSource {
        counts: Arc::clone(&counts),
        unavailable: sc.source_unavailable,
        notify_fails: sc.notify_fails,
    };
    let make_sink = |_: &Path| -> Result<Box<dyn AuditSink>, TraitError> {
        counts.sink.fetch_add(1, Ordering::SeqCst);
        if sc.sink_fails {
            Err(TraitError::new(ErrorCode::Internal, "sink failed"))
        } else {
            Ok(Box::new(NoopSink))
        }
    };
    let launch_env = |_: &Path, _: &_| -> Result<Vec<String>, TraitError> { Ok(Vec::new()) };
    let run = |_: &_,
               _: std::os::fd::BorrowedFd<'_>,
               _: &_,
               _: Duration,
               _: &dyn AuditSink,
               io: fandhe_container_supervisor::exec::ExecLaunchIo<'_>|
     -> Result<ExecExit, AuditedRejection<TraitError>> {
        counts.run.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = io.on_created {
            let name = ExecCgroupName::new("exec-4242-0").expect("name");
            if let Err(e) = hook(&name) {
                return Err(AuditedRejection::not_applicable(e));
            }
        }
        counts.event("run-done");
        Ok(sc.exit)
    };
    let deps = Deps {
        store,
        source: &source,
        make_sink: &make_sink,
        launch_env: &launch_env,
        run: &run,
    };
    let outcome = serve(&helper, args, &deps);
    (outcome, counts, plugin)
}

fn assert_nothing_ran(counts: &Counts, source: usize) {
    assert_eq!(counts.source.load(Ordering::SeqCst), source, "source calls");
    assert_eq!(counts.run.load(Ordering::SeqCst), 0, "run calls");
}

/// SUP-6・SEC-1（#3760）: 稼働中でない記録と pid の不一致では、sink も pidfd の要求も exec もしない。
#[test]
fn sup6_3760_stale_record_never_reaches_pidfd_or_exec() {
    let base = Tmp::new("stale");
    let store = open(&base);
    seed(&base, &store, "created1", None);
    seed(&base, &store, "run1", Some(PID));
    let none = StdioSend::default();
    let sc = Scenario::default();

    let args = args_for(&base, "created1", PID, 0);
    let (out, counts, _p) = drive(&store, &args, &none, &sc);
    assert_eq!(
        out,
        StreamExecOutcome::Failed(ErrorCode::FailedPrecondition)
    );
    assert_eq!(counts.sink.load(Ordering::SeqCst), 0);
    assert_nothing_ran(&counts, 0);

    let args = args_for(&base, "run1", PID + 1, 0);
    let (out, counts, _p) = drive(&store, &args, &none, &sc);
    assert_eq!(
        out,
        StreamExecOutcome::Failed(ErrorCode::FailedPrecondition)
    );
    assert_eq!(counts.sink.load(Ordering::SeqCst), 0);
    assert_nothing_ran(&counts, 0);

    let args = args_for(&base, "absent", PID, 0);
    let (out, counts, _p) = drive(&store, &args, &none, &sc);
    assert_eq!(out, StreamExecOutcome::Failed(ErrorCode::NotFound));
    assert_nothing_ran(&counts, 0);
}

/// SEC-4・SEC-1（#3760）: 監査 sink を作れなければ pidfd を要求せず exec もしない。孤児（kind 6 の `Unavailable`）は
/// 縮退せずそのまま失敗する。
#[test]
fn sec4_3760_sink_failure_and_orphan_do_not_exec() {
    let base = Tmp::new("sink");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let none = StdioSend::default();
    let args = args_for(&base, "run1", PID, 0);

    let sc = Scenario {
        sink_fails: true,
        ..Scenario::default()
    };
    let (out, counts, _p) = drive(&store, &args, &none, &sc);
    assert_eq!(out, StreamExecOutcome::Failed(ErrorCode::Internal));
    assert_eq!(counts.sink.load(Ordering::SeqCst), 1);
    assert_nothing_ran(&counts, 0);

    let sc = Scenario {
        source_unavailable: true,
        ..Scenario::default()
    };
    let (out, counts, _p) = drive(&store, &args, &none, &sc);
    assert_eq!(out, StreamExecOutcome::Failed(ErrorCode::Unavailable));
    assert_nothing_ran(&counts, 1);
}

/// SUP-6・REPAIR-2（#3760）: `--stdio` と受け取った mask が違えば exec しない。
#[test]
fn sup6_3760_mask_mismatch_does_not_exec() {
    let base = Tmp::new("mask");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let out_file = File::create(base.0.join("out")).expect("file");
    // 引数は stdout を要求するが、送るのは stdin だけ。
    let stdio = StdioSend {
        stdin: Some(out_file.as_fd()),
        ..StdioSend::default()
    };
    let args = args_for(&base, "run1", PID, 0b010);
    let (out, counts, _p) = drive(&store, &args, &stdio, &Scenario::default());
    assert_eq!(out, StreamExecOutcome::Failed(ErrorCode::InvalidArgument));
    assert_nothing_ran(&counts, 1);
}

/// SUP-6・REPAIR-5（#3760）: 作成通知の後に `Started`、続いて実行役の終了状態が `Result` の値になる。
/// 通知に失敗したら `Started` を送らず exec を中止する。
#[test]
fn sup6_3760_started_follows_notify_and_failure_aborts() {
    let base = Tmp::new("started");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let none = StdioSend::default();
    let args = args_for(&base, "run1", PID, 0);

    let (out, counts, plugin) = drive(&store, &args, &none, &Scenario::default());
    assert_eq!(out, StreamExecOutcome::Exited(3));
    assert_eq!(
        *counts.events.lock().expect("lock"),
        vec!["notify", "run-done"]
    );
    let msg = recv_from_helper(&plugin, Instant::now() + Duration::from_secs(5)).expect("started");
    assert!(matches!(msg, HelperMessage::Started), "{msg:?}");

    let sc = Scenario {
        notify_fails: true,
        ..Scenario::default()
    };
    let (out, counts, plugin) = drive(&store, &args, &none, &sc);
    assert_eq!(out, StreamExecOutcome::Failed(ErrorCode::Unavailable));
    assert_eq!(*counts.events.lock().expect("lock"), vec!["notify"]);
    // `Started` は届かない（helper 側の端は drive の戻りで drop され、EOF になる）。
    let err = recv_from_helper(&plugin, Instant::now() + Duration::from_secs(5)).unwrap_err();
    assert_eq!(err, ChannelError::Closed);
}

/// 本物の bin を `stream-exec` で起動する（診断の受け口として stderr を pipe にする）。
fn spawn_helper(args: &[&str], stdin: Stdio) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_fandhe-container-supervisor"))
        .arg("stream-exec")
        .args(args)
        .env_clear()
        .current_dir("/")
        .stdin(stdin)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn")
}

/// helper の終了を期限つきで待つ（REPAIR-5・#3760）。期限超過なら kill して回収してから panic する。
/// stderr は別スレッドで集め、受け取りにも有限の期限を置く（試験自身で有界化し CI の watchdog に頼らない）。
fn wait_bounded(mut child: std::process::Child, limit: Duration) -> (Option<i32>, String) {
    let reader = child.stderr.take().map(|mut e| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = String::new();
            let _ = e.read_to_string(&mut buf);
            let _ = tx.send(buf);
        });
        rx
    });
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(st) => break st,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("helper did not exit within {limit:?}");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let err = reader
        .map(|rx| {
            rx.recv_timeout(Duration::from_secs(10))
                .expect("stderr reader timed out")
        })
        .unwrap_or_default();
    (status.code(), err)
}

const COMMON: [&str; 8] = [
    "--root",
    "/tmp",
    "--id",
    "a1",
    "--expect-pid",
    "10",
    "--timeout-ms",
    "1000",
];

fn with(extra: &[&str]) -> Vec<String> {
    COMMON
        .iter()
        .chain(extra.iter())
        .map(|s| (*s).to_owned())
        .collect()
}

/// SEC-1・REPAIR-5（#3760）: 上限超え・不正な引数は `Result(Failed(InvalidArgument))` で、helper は終了コード 0。
#[test]
fn sec1_3760_real_bin_rejects_invalid_args_with_result_frame() {
    let mut over = with(&["--stdio", "0", "--", "/b"]);
    over.extend((0..4096).map(|_| "x".to_owned()));
    let mut unknown = vec!["--env".to_owned(), "A=B".to_owned()];
    unknown.extend(with(&["--stdio", "0", "--", "/bin/echo"]));
    let cases: Vec<(&str, Vec<String>)> = vec![
        ("over the argv limit", over),
        ("relative argv0", with(&["--stdio", "0", "--", "echo"])),
        (
            "reserved stdio bit",
            with(&["--stdio", "8", "--", "/bin/echo"]),
        ),
        ("env is not accepted", unknown),
    ];
    for (why, args) in cases {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let (plugin, helper_end) = UnixStream::pair().expect("pair");
        let child = spawn_helper(&refs, Stdio::from(OwnedFd::from(helper_end)));
        let msg = recv_from_helper(&plugin, Instant::now() + Duration::from_secs(20)).expect(why);
        assert!(
            matches!(
                msg,
                HelperMessage::Result(StreamExecOutcome::Failed(ErrorCode::InvalidArgument))
            ),
            "{why}: {msg:?}"
        );
        assert_eq!(
            wait_bounded(child, Duration::from_secs(20)).0,
            Some(0),
            "{why}"
        );
    }
}

/// SUP-6・REPAIR-5（#3760）: 存在しない記録は `NotFound` で、exec へ進まない。
#[test]
fn sup6_3760_real_bin_reports_missing_record() {
    let base = Tmp::new("missing");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(base.state_root())
        .expect("root");
    let root = base.state_root();
    let (plugin, helper_end) = UnixStream::pair().expect("pair");
    let child = spawn_helper(
        &[
            "--root",
            root.to_str().expect("utf8"),
            "--id",
            "ghost1",
            "--expect-pid",
            "10",
            "--timeout-ms",
            "1000",
            "--stdio",
            "0",
            "--",
            "/bin/echo",
            "hi",
        ],
        Stdio::from(OwnedFd::from(helper_end)),
    );
    let msg = recv_from_helper(&plugin, Instant::now() + Duration::from_secs(20)).expect("result");
    assert!(
        matches!(
            msg,
            HelperMessage::Result(StreamExecOutcome::Failed(ErrorCode::NotFound))
        ),
        "{msg:?}"
    );
    assert_eq!(wait_bounded(child, Duration::from_secs(20)).0, Some(0));
}

/// SEC-1（#3760）: fd 0 が socket でなければ fail-closed（終了コード 1 と構造化された診断行）。
#[test]
fn sec1_3760_real_bin_requires_a_socket_on_fd0() {
    let child = spawn_helper(&["--root", "/tmp", "--id", "a1"], Stdio::null());
    let (code, err) = wait_bounded(child, Duration::from_secs(20));
    assert_eq!(code, Some(1));
    assert_eq!(
        err,
        "{\"code\":\"invalid-argument\",\"message\":\"stream-exec requires a socket on fd 0\"}\n"
    );
}
