//! stream-exec helper の結合試験（既定のテスト集合。SUP-6・SEC-1・SEC-4・REPAIR-5・REPAIR-12・#3760）。
//!
//! 実コンテナも root も使わない。次の 2 系統を具体値で固定する。
//! - `serve` の配線: 状態ストアは実物（一時ディレクトリの `FileStateStore`）、pidfd の取得元・監査 sink・実行役は偽物。
//!   「前提が崩れたら pidfd の要求も exec もしない」「作成通知の後に `Started`」「mask の不一致で exec しない」を数える。
//! - 本物の bin を `stream-exec` で起動した入口: 不正な引数は `Result(Failed(InvalidArgument))`、fd 0 が socket でなければ
//!   終了コード 1 と構造化された診断行。実コンテナへ通す試験は実機前提の `stream_exec_real`。

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::num::{NonZeroU8, NonZeroU32};
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

#[path = "../../core/tests/support/reap.rs"]
mod reap;
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
use fandhe_container_supervisor::control::{
    ControlExecHandover, ExecControlFailure, ExecCreatedNotifier, ExecHandover, ExecPidfdSource,
};
use fandhe_container_supervisor::exec::{CommandSignaler, ExecSignalDelivery};
use fandhe_container_supervisor::stream_exec::channel::{
    ChannelError, HelperMessage, StdioSend, recv_from_helper, send_stdio_handover,
};
use fandhe_container_supervisor::stream_exec::diag::HelperStage;
use fandhe_container_supervisor::stream_exec::helper::{
    Deps, RunnerExit, ServeReport, StreamExecArgs, serve_reporting,
};
use fandhe_container_supervisor::stream_exec::wire::{SignalAckCode, StdioMask, StreamExecOutcome};

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
    /// 偽の signaler が受けたシグナル番号（`deliver` の呼び出しごと。#4282）。
    signals: Mutex<Vec<u8>>,
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
    /// 失敗時に添える OS の errno（#4284）。
    errno: Option<i32>,
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

    fn notify_created_with_errno(
        &self,
        name: &ExecCgroupName,
        hold: Instant,
    ) -> Result<(), ExecControlFailure> {
        self.notify_created(name, hold)
            .map_err(|e| ExecControlFailure::new(e, self.errno))
    }
}

struct FakeSource {
    counts: Arc<Counts>,
    unavailable: bool,
    notify_fails: bool,
    /// 取得失敗・通知失敗に添える OS の errno（#4284）。
    errno: Option<i32>,
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
                errno: self.errno,
            }),
        ))
    }

    fn obtain_with_errno(
        &self,
        id: &ContainerId,
        pid: NonZeroU32,
        deadline: Instant,
    ) -> Result<ExecHandover, ExecControlFailure> {
        self.obtain(id, pid, deadline)
            .map_err(|e| ExecControlFailure::new(e, self.errno))
    }
}

struct Scenario {
    sink_fails: bool,
    source_unavailable: bool,
    notify_fails: bool,
    /// 取得・通知の失敗に添える errno（#4284）。
    errno: Option<i32>,
    /// 真なら launch 時 env の読み込みが失敗する（#4284）。
    launch_env_fails: bool,
    exit: ExecExit,
    /// 真なら偽の実行役が `io.cancel` を 10 ms 刻みでこの長さの間見続ける（`serve` の取り消し判定の配線の照合。#4166）。
    /// 真になれば `Unavailable` の拒否で終わり、最後まで偽なら `exit` で終わる。`None` は見ない。
    watch_cancel: Option<Duration>,
    /// `Some` なら、`serve` の開始直後からこの時間の後に plugin 側の channel の端を別スレッドで閉じる
    /// （要求元の消滅の模擬。戻り値の端は別の socketpair のダミーになる）。
    close_plugin_after: Option<Duration>,
    /// `serve` の開始前に plugin 側から送っておく生のバイト列（`Signal` frame と、壊れた frame の注入。#4282）。
    pre_send: Vec<Vec<u8>>,
    /// `Some` なら偽の実行役が `io.signal` のフックを 10 ms 刻みでこの長さの間呼び続ける（偽の signaler 付き。#4282）。
    signal_watch: Option<Duration>,
    /// 偽の signaler の `deliver` の結果の列（足りない分は最後の値の繰り返し。空なら `Unavailable`）。
    deliveries: Vec<ExecSignalDelivery>,
    /// 偽の実行役が成功側で返すコマンドの pid（`Spawned` を後始末で送る経路の照合。#4316）。
    runner_pid: Option<u32>,
    /// 偽の signaler の `command_pid` が返す pid（刻みで `Spawned` を送る経路の照合。#4316）。
    signaler_pid: Option<u32>,
}

/// 偽の [`CommandSignaler`]（呼ばれた番号を `Counts::signals` に記録し、決めた列で結果を返す。#4282）。
struct FakeSignaler<'a> {
    counts: &'a Counts,
    deliveries: &'a [ExecSignalDelivery],
    calls: AtomicUsize,
    pid: Option<u32>,
}

impl CommandSignaler for FakeSignaler<'_> {
    fn command_pid(&self) -> Option<NonZeroU32> {
        self.pid.and_then(NonZeroU32::new)
    }

    fn deliver(&self, number: NonZeroU8) -> ExecSignalDelivery {
        self.counts.signals.lock().expect("lock").push(number.get());
        let i = self.calls.fetch_add(1, Ordering::SeqCst);
        self.deliveries
            .get(i)
            .or(self.deliveries.last())
            .copied()
            .unwrap_or(ExecSignalDelivery::Unavailable)
    }
}

/// 版 4 の `Signal` frame の生のバイト列（#4282。`version` は壊れた版の注入にも使う）。
fn signal_bytes(version: u8, number: u8) -> Vec<u8> {
    vec![b'F', b'C', b'S', b'X', version, 5, 0, 1, number]
}

impl Default for Scenario {
    fn default() -> Self {
        Self {
            sink_fails: false,
            source_unavailable: false,
            notify_fails: false,
            errno: None,
            launch_env_fails: false,
            exit: ExecExit::Command(ChildExit::Exited(3)),
            watch_cancel: None,
            close_plugin_after: None,
            pre_send: Vec::new(),
            signal_watch: None,
            deliveries: Vec::new(),
            runner_pid: None,
            signaler_pid: None,
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
    let (report, counts, plugin) = drive_reporting(store, args, stdio, sc);
    (report.outcome, counts, plugin)
}

/// [`drive`] と同じだが、起動の失敗の段・errno も返す（#4284）。
fn drive_reporting(
    store: &FileStateStore,
    args: &StreamExecArgs,
    stdio: &StdioSend<'_>,
    sc: &Scenario,
) -> (ServeReport, Arc<Counts>, UnixStream) {
    let counts = Arc::new(Counts::default());
    let (plugin, helper) = UnixStream::pair().expect("pair");
    send_stdio_handover(&plugin, stdio, Instant::now() + Duration::from_secs(5)).expect("send");
    for bytes in &sc.pre_send {
        (&plugin).write_all(bytes).expect("pre-send bytes");
    }
    let source = FakeSource {
        counts: Arc::clone(&counts),
        unavailable: sc.source_unavailable,
        notify_fails: sc.notify_fails,
        errno: sc.errno,
    };
    let make_sink = |_: &Path| -> Result<Box<dyn AuditSink>, TraitError> {
        counts.sink.fetch_add(1, Ordering::SeqCst);
        if sc.sink_fails {
            Err(TraitError::new(ErrorCode::Internal, "sink failed"))
        } else {
            Ok(Box::new(NoopSink))
        }
    };
    let launch_env = |_: &Path, _: &_| -> Result<Vec<String>, TraitError> {
        if sc.launch_env_fails {
            Err(TraitError::new(ErrorCode::Internal, "launch env failed"))
        } else {
            Ok(Vec::new())
        }
    };
    let run = |_: &_,
               _: std::os::fd::BorrowedFd<'_>,
               _: &_,
               _: Duration,
               _: &dyn AuditSink,
               io: fandhe_container_supervisor::exec::ExecLaunchIo<'_>|
     -> Result<RunnerExit, AuditedRejection<TraitError>> {
        counts.run.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = io.on_created {
            let name = ExecCgroupName::new("exec-4242-0").expect("name");
            if let Err(e) = hook(&name) {
                return Err(AuditedRejection::not_applicable(e));
            }
        }
        if let Some(span) = sc.watch_cancel {
            let begin = Instant::now();
            let cancel = io.cancel.expect("serve must pass the cancel hook (#4166)");
            while begin.elapsed() < span {
                if cancel() {
                    return Err(AuditedRejection::not_applicable(TraitError::new(
                        ErrorCode::Unavailable,
                        "exec cancelled",
                    )));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if let Some(span) = sc.signal_watch {
            let hook = io.signal.expect("serve must pass the signal hook (#4282)");
            let signaler = FakeSignaler {
                counts: &counts,
                deliveries: &sc.deliveries,
                calls: AtomicUsize::new(0),
                pid: sc.signaler_pid,
            };
            let begin = Instant::now();
            while begin.elapsed() < span {
                hook(&signaler);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        counts.event("run-done");
        Ok(RunnerExit {
            exit: sc.exit,
            command_pid: sc.runner_pid.and_then(NonZeroU32::new),
        })
    };
    let deps = Deps {
        store,
        source: &source,
        make_sink: &make_sink,
        launch_env: &launch_env,
        run: &run,
    };
    let (plugin, closer) = match sc.close_plugin_after {
        Some(after) => {
            let closer = std::thread::spawn(move || {
                std::thread::sleep(after);
                drop(plugin);
            });
            (UnixStream::pair().expect("dummy pair").0, Some(closer))
        }
        None => (plugin, None),
    };
    let report = serve_reporting(&helper, args, &deps);
    if let Some(closer) = closer {
        closer.join().expect("closer thread");
    }
    (report, counts, plugin)
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

/// SUP-6・SEC-1（#3761）: stdio の fd は socket か FIFO だけを受ける。通常ファイル・ディレクトリ・文字デバイスは
/// fork も通知もせず `InvalidArgument`。
#[test]
fn sup6_3761_stdio_fd_kinds_are_socket_or_fifo_only() {
    let base = Tmp::new("kinds");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let args = args_for(&base, "run1", PID, 0b010);

    let regular = File::create(base.0.join("out")).expect("file");
    let dir = File::open(&base.0).expect("dir");
    let null = File::options().write(true).open("/dev/null").expect("null");
    for (label, fd) in [("regular", &regular), ("directory", &dir), ("char", &null)] {
        let stdio = StdioSend {
            stdout: Some(fd.as_fd()),
            ..StdioSend::default()
        };
        let (out, counts, _p) = drive(&store, &args, &stdio, &Scenario::default());
        assert_eq!(
            out,
            StreamExecOutcome::Failed(ErrorCode::InvalidArgument),
            "{label}"
        );
        assert_nothing_ran(&counts, 1);
        assert!(counts.events.lock().expect("lock").is_empty(), "{label}");
    }

    // socket と FIFO は受理され、実行役が 1 回だけ呼ばれる。
    let (sock, _peer) = UnixStream::pair().expect("pair");
    let (pipe_r, pipe_w) = std::io::pipe().expect("pipe");
    for (label, fd) in [("socket", sock.as_fd()), ("fifo", pipe_w.as_fd())] {
        let stdio = StdioSend {
            stdout: Some(fd),
            ..StdioSend::default()
        };
        let (out, counts, _p) = drive(&store, &args, &stdio, &Scenario::default());
        assert_eq!(out, StreamExecOutcome::Exited(3), "{label}");
        assert_eq!(counts.run.load(Ordering::SeqCst), 1, "{label}");
    }
    drop(pipe_r);
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
    // `Started` は on_created に渡った exec 子 cgroup の名前を運ぶ（wire v2・#4221）。
    match msg {
        HelperMessage::Started(name) => assert_eq!(name.as_str(), "exec-4242-0"),
        other => panic!("expected Started, got {other:?}"),
    }

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

/// 起動した helper と、その fd 2 の受け口（診断は AF_UNIX socket にだけ書かれる。本番の supervisor と同じ構成）。
struct Spawned {
    child: std::process::Child,
    diag: UnixStream,
}

/// 本物の bin を `stream-exec` で起動する（fd 2 に socketpair の片端を渡し、診断行の受け口にする）。
fn spawn_helper(args: &[&str], stdin: Stdio) -> Spawned {
    let (parent_end, child_end) = UnixStream::pair().expect("socketpair");
    let child = Command::new(env!("CARGO_BIN_EXE_fandhe-container-supervisor"))
        .arg("stream-exec")
        .args(args)
        .env_clear()
        .current_dir("/")
        .stdin(stdin)
        .stdout(Stdio::null())
        .stderr(Stdio::from(OwnedFd::from(child_end)))
        .spawn()
        .expect("spawn");
    Spawned {
        child,
        diag: parent_end,
    }
}

/// helper の終了を期限つきで待つ（REPAIR-5・#3760）。期限超過なら kill して回収してから panic する。
/// stderr は別スレッドで集め、受け取りにも有限の期限を置く（試験自身で有界化し CI の watchdog に頼らない）。
fn wait_bounded(spawned: Spawned, limit: Duration) -> (Option<i32>, String) {
    let Spawned {
        mut child,
        diag: mut e,
    } = spawned;
    let reader = {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = String::new();
            let _ = e.read_to_string(&mut buf);
            let _ = tx.send(buf);
        });
        Some(rx)
    };
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(st) => break st,
            None if Instant::now() >= deadline => {
                reap::reap_or_report(&mut child, reap::reap_within());
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
        "{\"component\":\"supervisor.stream_exec\",\"stage\":\"helper_channel\",\"code\":\"INVALID_ARGUMENT\",\"errno\":\"none\"}\n"
    );
}

/// SUP-6・SEC-1・REPAIR-5（#4166）: 要求元（plugin 側の channel の端）が消えたら、`serve` が渡した取り消し判定が真になり、
/// 実行役が `Unavailable` で終わる。消滅（端を閉じた時刻）から `serve` の戻りまで 2 秒以内。
#[test]
fn sup6_4166_serve_passes_a_cancel_hook_that_fires_when_the_requester_closes() {
    let base = Tmp::new("cancel");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let none = StdioSend::default();
    let args = args_for(&base, "run1", PID, 0);
    let sc = Scenario {
        // 実行役は最長 10 秒見続ける。端は 200 ms 後に閉じる。
        watch_cancel: Some(Duration::from_secs(10)),
        close_plugin_after: Some(Duration::from_millis(200)),
        ..Scenario::default()
    };
    let begin = Instant::now();
    let (out, counts, _p) = drive(&store, &args, &none, &sc);
    let elapsed = begin.elapsed();
    assert_eq!(out, StreamExecOutcome::Failed(ErrorCode::Unavailable));
    assert!(
        elapsed >= Duration::from_millis(200) && elapsed < Duration::from_millis(2_200),
        "took {elapsed:?}"
    );
    assert_eq!(counts.run.load(Ordering::SeqCst), 1);
}

/// SUP-6・REPAIR-5（#4166）: 要求元が開いたまま（データが届いただけの状態を含む）なら、取り消し判定は一度も真にならず、
/// 実行役は本来の終了（`Exited(3)`）まで走る（誤検知しない）。
#[test]
fn sup6_4166_open_requester_never_fires_the_cancel_hook() {
    let base = Tmp::new("nocancel");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let none = StdioSend::default();
    let args = args_for(&base, "run1", PID, 0);
    let sc = Scenario {
        watch_cancel: Some(Duration::from_millis(1_500)),
        ..Scenario::default()
    };
    let begin = Instant::now();
    let (out, counts, plugin) = drive(&store, &args, &none, &sc);
    assert!(begin.elapsed() >= Duration::from_millis(1_500));
    assert_eq!(out, StreamExecOutcome::Exited(3));
    assert_eq!(counts.run.load(Ordering::SeqCst), 1);
    drop(plugin);
}

/// 診断行に秘密（コンテナ ID・argv・状態ルート名）が現れないことを照合する（SEC-1・#4284）。
fn assert_no_secrets(text: &str, secrets: &[&str]) {
    for secret in secrets {
        assert!(!text.contains(secret), "secret {secret:?} leaked: {text:?}");
    }
}

fn line_of(report: &ServeReport) -> String {
    report
        .failure
        .expect("failure must be reported")
        .diagnostic_line()
}

/// SUP-6・REPAIR-4・SEC-1（#4284）: 起動前の各段の失敗は、段名・分類・errno が具体値で報告される。
#[test]
fn sup6_4284_serve_reports_the_failing_stage_and_errno() {
    let base = Tmp::new("diag");
    let store = open(&base);
    seed(&base, &store, "created1", None);
    seed(&base, &store, "run1", Some(PID));
    let none = StdioSend::default();
    let prefix = "{\"component\":\"supervisor.stream_exec\",";

    // 記録なし: 状態の取得（errno なし）。
    let args = args_for(&base, "ghost1", PID, 0);
    let (r, _c, _p) = drive_reporting(&store, &args, &none, &Scenario::default());
    assert_eq!(r.outcome, StreamExecOutcome::Failed(ErrorCode::NotFound));
    assert_eq!(
        line_of(&r),
        format!(
            "{prefix}\"stage\":\"helper_state_get\",\"code\":\"NOT_FOUND\",\"errno\":\"none\"}}"
        )
    );
    // 稼働中でない・pid 不一致: 状態の照合。
    let args = args_for(&base, "created1", PID, 0);
    let (r, _c, _p) = drive_reporting(&store, &args, &none, &Scenario::default());
    assert_eq!(
        line_of(&r),
        format!(
            "{prefix}\"stage\":\"helper_state_mismatch\",\"code\":\"FAILED_PRECONDITION\",\"errno\":\"none\"}}"
        )
    );
    // launch env・sink の失敗。
    let args = args_for(&base, "run1", PID, 0);
    let sc = Scenario {
        launch_env_fails: true,
        ..Scenario::default()
    };
    let (r, _c, _p) = drive_reporting(&store, &args, &none, &sc);
    assert_eq!(
        line_of(&r),
        format!(
            "{prefix}\"stage\":\"helper_launch_env\",\"code\":\"INTERNAL\",\"errno\":\"none\"}}"
        )
    );
    let sc = Scenario {
        sink_fails: true,
        ..Scenario::default()
    };
    let (r, _c, _p) = drive_reporting(&store, &args, &none, &sc);
    assert_eq!(
        line_of(&r),
        format!(
            "{prefix}\"stage\":\"helper_audit_sink\",\"code\":\"INTERNAL\",\"errno\":\"none\"}}"
        )
    );
    // pidfd の取得の失敗: OS の errno（ECONNREFUSED = 111）が運ばれる。
    let sc = Scenario {
        source_unavailable: true,
        errno: Some(111),
        ..Scenario::default()
    };
    let (r, _c, _p) = drive_reporting(&store, &args, &none, &sc);
    assert_eq!(r.outcome, StreamExecOutcome::Failed(ErrorCode::Unavailable));
    assert_eq!(
        line_of(&r),
        format!(
            "{prefix}\"stage\":\"helper_pidfd_handover\",\"code\":\"UNAVAILABLE\",\"errno\":111}}"
        )
    );
    // mask の不一致（stdin を要求したが fd を送っていない）: stdio の受信。
    let args_mask = args_for(&base, "run1", PID, 7);
    let (r, _c, _p) = drive_reporting(&store, &args_mask, &none, &Scenario::default());
    let failure = r.failure.expect("failure");
    assert_eq!(failure.stage, HelperStage::StdioHandover);
    assert_eq!(failure.errno, None);
    assert_eq!(r.outcome, StreamExecOutcome::Failed(failure.code));
    // 通知の失敗: kind 7（EPIPE = 32）。
    let sc = Scenario {
        notify_fails: true,
        errno: Some(32),
        ..Scenario::default()
    };
    let (r, _c, _p) = drive_reporting(&store, &args, &none, &sc);
    assert_eq!(
        line_of(&r),
        format!(
            "{prefix}\"stage\":\"helper_cgroup_notify\",\"code\":\"UNAVAILABLE\",\"errno\":32}}"
        )
    );
    // 秘密は行に現れない（ID・argv・状態ルートの名前）。
    let root_name = base.state_root().display().to_string();
    assert_no_secrets(&line_of(&r), &["run1", "/bin/echo", "hi", &root_name]);
}

/// SUP-6・REPAIR-4（#4284）: 正常終了と子の段の失敗（`NotStarted`）では、失敗の段は報告されない（`Result` frame が運ぶ）。
#[test]
fn sup6_4284_serve_reports_no_failure_on_success_or_child_exit() {
    let base = Tmp::new("diag-ok");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let none = StdioSend::default();
    let args = args_for(&base, "run1", PID, 0);
    let (r, _c, _p) = drive_reporting(&store, &args, &none, &Scenario::default());
    assert_eq!(r.outcome, StreamExecOutcome::Exited(3));
    assert_eq!(r.failure, None);
    // `serve` は従来どおり結果だけを返す。
    let (out, _c, _p) = drive(&store, &args, &none, &Scenario::default());
    assert_eq!(out, StreamExecOutcome::Exited(3));
}

/// SUP-6・REPAIR-4（#4284）: 本物の bin の失敗は fd 2 の 1 行に段名・分類・errno が出て、`Result` frame の値と矛盾しない。
#[test]
fn sup6_4284_real_bin_writes_the_stage_line_to_fd2() {
    let prefix = "{\"component\":\"supervisor.stream_exec\",";
    // 不正な引数（絶対でない argv0）: 引数の解釈。
    let args = with(&["--stdio", "0", "--", "echo"]);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (plugin, helper_end) = UnixStream::pair().expect("pair");
    let child = spawn_helper(&refs, Stdio::from(OwnedFd::from(helper_end)));
    let msg = recv_from_helper(&plugin, Instant::now() + Duration::from_secs(20)).expect("result");
    assert!(matches!(
        msg,
        HelperMessage::Result(StreamExecOutcome::Failed(ErrorCode::InvalidArgument))
    ));
    let (code, err) = wait_bounded(child, Duration::from_secs(20));
    assert_eq!(code, Some(0));
    assert_eq!(
        err,
        format!(
            "{prefix}\"stage\":\"helper_args\",\"code\":\"INVALID_ARGUMENT\",\"errno\":\"none\"}}\n"
        )
    );

    // 記録なし: 状態の取得。
    let base = Tmp::new("diag-bin");
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
    assert!(matches!(
        msg,
        HelperMessage::Result(StreamExecOutcome::Failed(ErrorCode::NotFound))
    ));
    let (code, err) = wait_bounded(child, Duration::from_secs(20));
    assert_eq!(code, Some(0));
    assert_eq!(
        err,
        format!(
            "{prefix}\"stage\":\"helper_state_get\",\"code\":\"NOT_FOUND\",\"errno\":\"none\"}}\n"
        )
    );
    assert_no_secrets(&err, &["ghost1", "/bin/echo", root.to_str().expect("utf8")]);
}

/// SUP-6・REPAIR-4（#4284）: 本番の制御クライアントは、状態ディレクトリを開けない失敗の OS の errno（ENOENT = 2）を
/// 構造化エラー（`Unavailable`）と一緒に返し、別の呼び出しの errno を引きずらない。
#[test]
fn sup6_4284_control_client_carries_the_os_errno() {
    let base = Tmp::new("diag-ctl");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(base.state_root())
        .expect("root");
    let source = ControlExecHandover::new(base.state_root());
    let deadline = Instant::now() + Duration::from_secs(2);
    let pid = NonZeroU32::new(PID).expect("pid");
    let failure = source
        .obtain_with_errno(&cid("ghost1"), pid, deadline)
        .expect_err("no state directory");
    assert_eq!(failure.error().code(), ErrorCode::Unavailable);
    assert_eq!(failure.errno(), Some(2));
    // 続く OS 由来でない失敗（期限切れ）は、前回の errno を引きずらない。
    let expired = source
        .obtain_with_errno(&cid("ghost1"), pid, Instant::now())
        .expect_err("expired");
    assert_eq!(expired.error().code(), ErrorCode::Timeout);
    assert_eq!(expired.errno(), None);
}

/// `serve` の後に plugin 側で受けられる frame を集める（`Started` は数えず、`SignalAck` は (番号, code) にする。
/// 何も無くなる〔`Timeout`〕か、閉じるまで）。#4282
fn collect_acks(plugin: &UnixStream) -> (bool, Vec<(u8, SignalAckCode)>) {
    let mut started = false;
    let mut acks = Vec::new();
    loop {
        match recv_from_helper(plugin, Instant::now() + Duration::from_millis(150)) {
            Ok(HelperMessage::Started(_)) => started = true,
            Ok(HelperMessage::SignalAck { signal, code }) => acks.push((signal.get(), code)),
            // `Spawned` は順序の照合（`collect_events`）で見る。ここでは数えない（#4316）。
            Ok(HelperMessage::Spawned { .. }) => {}
            Ok(other) => panic!("unexpected {other:?}"),
            Err(ChannelError::Timeout | ChannelError::Closed) => return (started, acks),
            Err(e) => panic!("unexpected channel error {e:?}"),
        }
    }
}

fn signal_scenario(pre_send: Vec<Vec<u8>>, deliveries: Vec<ExecSignalDelivery>) -> Scenario {
    Scenario {
        pre_send,
        deliveries,
        signal_watch: Some(Duration::from_millis(300)),
        ..Scenario::default()
    }
}

/// SUP-6・SEC-1・CRI-5（#4282）: `serve` はシグナルのフックを渡す。SIGTERM の frame は偽の signaler へ 15 として届き、
/// `Started` の後に `SignalAck(15, delivered)` が 1 件だけ返る。結果の値は変わらない。
#[test]
fn sup6_4282_signal_frame_is_delivered_and_acked_once() {
    let base = Tmp::new("sigok");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let args = args_for(&base, "run1", PID, 0);
    let sc = signal_scenario(
        vec![signal_bytes(4, 15)],
        vec![ExecSignalDelivery::Delivered],
    );
    let (out, counts, plugin) = drive(&store, &args, &StdioSend::default(), &sc);
    assert_eq!(out, StreamExecOutcome::Exited(3));
    assert_eq!(*counts.signals.lock().expect("lock"), vec![15]);
    let (started, acks) = collect_acks(&plugin);
    assert!(started);
    assert_eq!(acks, vec![(15, SignalAckCode::Delivered)]);
}

/// SUP-6・REPAIR-5（#4282）: 配送の結果（exited・unavailable）は固定語彙の ack になる。
#[test]
fn sup6_4282_delivery_results_map_to_ack_codes() {
    for (delivery, code) in [
        (ExecSignalDelivery::Exited, SignalAckCode::Exited),
        (ExecSignalDelivery::Unavailable, SignalAckCode::Unavailable),
    ] {
        let base = Tmp::new("sigmap");
        let store = open(&base);
        seed(&base, &store, "run1", Some(PID));
        let args = args_for(&base, "run1", PID, 0);
        let sc = signal_scenario(vec![signal_bytes(4, 2)], vec![delivery]);
        let (_out, counts, plugin) = drive(&store, &args, &StdioSend::default(), &sc);
        assert_eq!(*counts.signals.lock().expect("lock"), vec![2]);
        let (_started, acks) = collect_acks(&plugin);
        assert_eq!(acks, vec![(2, code)], "{delivery:?}");
    }
}

/// SUP-6・REPAIR-5（#4282）: pidfd が届かない間は保留して再試行し、猶予（2 秒）を過ぎたら `not_started`。
#[test]
fn sup6_4282_pending_signal_times_out_as_not_started() {
    let base = Tmp::new("signs");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let args = args_for(&base, "run1", PID, 0);
    let mut sc = signal_scenario(
        vec![signal_bytes(4, 15)],
        vec![ExecSignalDelivery::NotStarted],
    );
    sc.signal_watch = Some(Duration::from_millis(2_600));
    let (_out, counts, plugin) = drive(&store, &args, &StdioSend::default(), &sc);
    assert!(
        counts.signals.lock().expect("lock").len() > 10,
        "the pending signal must be retried on every tick"
    );
    let (_started, acks) = collect_acks(&plugin);
    assert_eq!(acks, vec![(15, SignalAckCode::NotStarted)]);
}

/// SUP-6・REPAIR-5（#4282）: exec が終わった時点で保留が残っていれば、`Result` の前（`serve` の戻りの前）に ack を返す。
/// コマンドが終わっていれば `exited`、起動に失敗していれば `not_started`。
#[test]
fn sup6_4282_pending_signal_at_exec_end_gets_an_ack() {
    for (exit, code) in [
        (
            ExecExit::Command(ChildExit::Exited(0)),
            SignalAckCode::Exited,
        ),
        (
            ExecExit::SetupFailed {
                exit: ChildExit::Exited(127),
                violation: None,
                code: ErrorCode::NotFound,
                step: None,
            },
            SignalAckCode::NotStarted,
        ),
    ] {
        let base = Tmp::new("sigend");
        let store = open(&base);
        seed(&base, &store, "run1", Some(PID));
        let args = args_for(&base, "run1", PID, 0);
        let mut sc = signal_scenario(
            vec![signal_bytes(4, 1)],
            vec![ExecSignalDelivery::NotStarted],
        );
        sc.signal_watch = Some(Duration::from_millis(100));
        sc.exit = exit;
        let (_out, _counts, plugin) = drive(&store, &args, &StdioSend::default(), &sc);
        let (_started, acks) = collect_acks(&plugin);
        assert_eq!(acks, vec![(1, code)]);
    }
}

/// SUP-6・SEC-1・REPAIR-2（#4282）: 許可外の番号（SIGKILL）・旧い版・範囲外の frame を受けたら、以後は正しい frame にも
/// 反応せず（signaler を呼ばず）ack も返さない。exec は止めず従来の結果で終わる。
#[test]
fn sec1_4282_malformed_signal_frame_disables_further_signals() {
    for (label, bad) in [
        ("sigkill", signal_bytes(4, 9)),
        ("v2", signal_bytes(2, 15)),
        ("zero", signal_bytes(4, 0)),
        ("out of range", signal_bytes(4, 65)),
    ] {
        let base = Tmp::new("sigbad");
        let store = open(&base);
        seed(&base, &store, "run1", Some(PID));
        let args = args_for(&base, "run1", PID, 0);
        let sc = signal_scenario(
            vec![bad, signal_bytes(4, 15)],
            vec![ExecSignalDelivery::Delivered],
        );
        let (out, counts, plugin) = drive(&store, &args, &StdioSend::default(), &sc);
        assert_eq!(out, StreamExecOutcome::Exited(3), "{label}");
        assert!(
            counts.signals.lock().expect("lock").is_empty(),
            "{label}: the signaler must not be called"
        );
        let (started, acks) = collect_acks(&plugin);
        assert!(started, "{label}");
        assert_eq!(acks, vec![], "{label}");
    }
}

/// SEC-1・REPAIR-2（#4282）: 向きの違う frame（`SignalAck`）と fd 付きの `Signal` も同様に拒否され、以後は受けない。
#[test]
fn sec1_4282_wrong_direction_signal_ack_frame_is_rejected() {
    let base = Tmp::new("sigdir");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let args = args_for(&base, "run1", PID, 0);
    let wrong = vec![b'F', b'C', b'S', b'X', 4, 6, 0, 2, 15, 1];
    let sc = signal_scenario(
        vec![wrong, signal_bytes(4, 15)],
        vec![ExecSignalDelivery::Delivered],
    );
    let (out, counts, plugin) = drive(&store, &args, &StdioSend::default(), &sc);
    assert_eq!(out, StreamExecOutcome::Exited(3));
    assert!(counts.signals.lock().expect("lock").is_empty());
    let (_started, acks) = collect_acks(&plugin);
    assert_eq!(acks, vec![]);
}

/// `serve` の後に plugin 側で受けられる frame を、届いた順に固定語彙の文字列にして集める（#4316）。
fn collect_events(plugin: &UnixStream) -> Vec<String> {
    let mut events = Vec::new();
    loop {
        match recv_from_helper(plugin, Instant::now() + Duration::from_millis(150)) {
            Ok(HelperMessage::Started(_)) => events.push("started".to_owned()),
            Ok(HelperMessage::Spawned { pid }) => events.push(format!("spawned:{}", pid.get())),
            Ok(HelperMessage::SignalAck { signal, code }) => {
                events.push(format!("ack:{}:{code:?}", signal.get()));
            }
            Ok(other) => panic!("unexpected {other:?}"),
            Err(ChannelError::Timeout | ChannelError::Closed) => return events,
            Err(e) => panic!("unexpected channel error {e:?}"),
        }
    }
}

/// SUP-6・CRI-5・#4316: 刻みで pid が届けば `Started` → `Spawned(4242)` の順にちょうど 1 回（後始末で二重に送らない）。
#[test]
fn sup6_4316_spawned_follows_started_exactly_once() {
    let base = Tmp::new("spawn1");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let args = args_for(&base, "run1", PID, 0);
    let mut sc = signal_scenario(vec![], vec![]);
    sc.signaler_pid = Some(4242);
    sc.runner_pid = Some(4242);
    let (out, _counts, plugin) = drive(&store, &args, &StdioSend::default(), &sc);
    assert_eq!(out, StreamExecOutcome::Exited(3));
    assert_eq!(collect_events(&plugin), vec!["started", "spawned:4242"]);
}

/// SUP-6・CRI-5・#4316: 刻みより先に終わった短命なコマンドでも、結果の pid から `Spawned` を `SignalAck` より前に送る。
#[test]
fn sup6_4316_fast_exit_still_sends_spawned_from_the_outcome() {
    let base = Tmp::new("spawn2");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let args = args_for(&base, "run1", PID, 0);
    let mut sc = Scenario {
        pre_send: vec![signal_bytes(4, 15)],
        deliveries: vec![ExecSignalDelivery::NotStarted],
        signal_watch: Some(Duration::from_millis(100)),
        exit: ExecExit::Command(ChildExit::Exited(0)),
        ..Scenario::default()
    };
    sc.runner_pid = Some(5150);
    let (out, _counts, plugin) = drive(&store, &args, &StdioSend::default(), &sc);
    assert_eq!(out, StreamExecOutcome::Exited(0));
    assert_eq!(
        collect_events(&plugin),
        vec!["started", "spawned:5150", "ack:15:Exited"]
    );
}

/// SUP-6・CRI-5・#4316: pid が無ければ（起動しなかった・中継できなかった）`Spawned` は送らない（pid 無しの結果を固定する）。
#[test]
fn sup6_4316_no_pid_means_no_spawned() {
    let base = Tmp::new("spawn3");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let args = args_for(&base, "run1", PID, 0);
    for exit in [
        ExecExit::Command(ChildExit::Exited(0)),
        ExecExit::SetupFailed {
            exit: ChildExit::Exited(127),
            violation: None,
            code: ErrorCode::NotFound,
            step: None,
        },
    ] {
        let sc = Scenario {
            signal_watch: Some(Duration::from_millis(100)),
            exit,
            ..Scenario::default()
        };
        let (_out, _counts, plugin) = drive(&store, &args, &StdioSend::default(), &sc);
        assert_eq!(collect_events(&plugin), vec!["started"]);
    }
}

/// SUP-6・CRI-5・#4316: 同じ刻みに pid と `Signal` が来ても、`Spawned` → `SignalAck` の順。
#[test]
fn sup6_4316_spawned_precedes_signal_ack() {
    let base = Tmp::new("spawn4");
    let store = open(&base);
    seed(&base, &store, "run1", Some(PID));
    let args = args_for(&base, "run1", PID, 0);
    let mut sc = signal_scenario(
        vec![signal_bytes(4, 15)],
        vec![ExecSignalDelivery::Delivered],
    );
    sc.signaler_pid = Some(4242);
    sc.runner_pid = Some(4242);
    let (_out, _counts, plugin) = drive(&store, &args, &StdioSend::default(), &sc);
    assert_eq!(
        collect_events(&plugin),
        vec!["started", "spawned:4242", "ack:15:Delivered"]
    );
}
