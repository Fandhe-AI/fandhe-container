//! `exec_launcher` の試験（CRI-6・SEC-1・SUP-6・REPAIR-5・#3761）。root も実コンテナも使わず、偽の helper
//! （`/bin/sleep` のプロセスを helper の `Child` とし、channel の相手は試験スレッドが演じる）で stdio の選択・drop での停止・
//! resize の転送・終了コードの写像を具体値で照合する。実 supervisor と実コンテナでの通しは #3762。

use std::future::poll_fn;
use std::os::fd::OwnedFd;
use std::os::unix::fs::DirBuilderExt as _;
use std::process::Command;
use std::sync::mpsc;

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ListStateRequest,
    StateList, StateRecord, TraitError, UpdateStateRequest,
};
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_supervisor::stream_exec::channel::{
    recv_stdio_handover, send_pty_master, send_result, send_spawned, send_started,
};
use fandhe_container_supervisor::stream_exec::wire::ExitSignal;
use tokio::io::ReadBuf;

use super::*;
use crate::streaming::log_attach::test_support::TempDir;

const PID: u32 = 4242;

/// 偽の helper が `Started` で運ぶ exec 子 cgroup の名前（CRI の Exec は名前を使わず読み捨てる。#4221）。
fn cg_name() -> fandhe_container_core::exec::ExecCgroupName {
    fandhe_container_core::exec::ExecCgroupName::new("exec-4242-0").expect("name")
}
const WAIT: Duration = Duration::from_secs(5);

type Script = Arc<dyn Fn(StdUnixStream, StdioMask) + Send + Sync>;
/// helper の fd 2 の helper 側の端を受けて演じる役（#4171）。
type DiagScript = Arc<dyn Fn(StdUnixStream) + Send + Sync>;

/// 偽の helper の起動口。`Child` は `/bin/sleep 60`（stdin に channel の helper 側の端を持たせる）で、channel の相手は
/// `script` が演じる。
struct FakeSpawner {
    tty: bool,
    script: Script,
    diag: Option<DiagScript>,
    pids: Arc<Mutex<Vec<u32>>>,
    /// 起動のたびに受けた引数の写し（tty・stdio の mask・`to_args()`。#4417）。
    seen: SeenArgs,
}

/// `FakeSpawner` が記録する引数の列（#4417）。
type SeenArgs = Arc<Mutex<Vec<(bool, u8, Vec<std::ffi::OsString>)>>>;

impl HelperSpawner for FakeSpawner {
    fn spawn(&self, args: &StreamExecArgs) -> Result<SpawnedHelper, CriError> {
        let (plugin_end, helper_end) = StdUnixStream::pair().expect("pair");
        let script_end = helper_end.try_clone().expect("clone");
        let child = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::from(OwnedFd::from(helper_end)))
            .spawn()
            .expect("spawn sleep");
        self.pids.lock().expect("lock").push(child.id());
        self.seen
            .lock()
            .expect("lock")
            .push((args.tty(), args.stdio().bits(), args.to_args()));
        let script = Arc::clone(&self.script);
        let mask = args.stdio();
        std::thread::spawn(move || script(script_end, mask));
        let diagnostics = self.diag.as_ref().map(|d| {
            let (plugin_diag, helper_diag) = StdUnixStream::pair().expect("diag pair");
            let d = Arc::clone(d);
            std::thread::spawn(move || d(helper_diag));
            plugin_diag
        });
        Ok(SpawnedHelper {
            child,
            channel: plugin_end,
            diagnostics,
        })
    }

    fn capabilities(&self) -> HelperCapabilities {
        HelperCapabilities { tty: self.tty }
    }
}

struct Fixture {
    dir: TempDir,
    store: Arc<FileStateStore>,
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
        for (name, pid) in [("run1", Some(PID)), ("created1", None)] {
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
            if let Some(pid) = pid {
                store
                    .update(&UpdateStateRequest::new(
                        ContainerStatus::running(id, NonZeroU32::new(pid)),
                        created.revision(),
                    ))
                    .expect("running");
            }
        }
        Self { dir, store }
    }

    fn launcher(
        &self,
        tty: bool,
        script: Script,
    ) -> (SupervisorExecLauncher, Arc<Mutex<Vec<u32>>>) {
        self.launcher_with_diag(tty, script, None)
    }

    fn launcher_with_diag(
        &self,
        tty: bool,
        script: Script,
        diag: Option<DiagScript>,
    ) -> (SupervisorExecLauncher, Arc<Mutex<Vec<u32>>>) {
        let pids = Arc::new(Mutex::new(Vec::new()));
        let spawner = FakeSpawner {
            tty,
            script,
            diag,
            pids: Arc::clone(&pids),
            seen: SeenArgs::default(),
        };
        let l = SupervisorExecLauncher::new(
            self.dir.0.join("state"),
            Arc::clone(&self.store) as Arc<dyn StateStore>,
            Arc::new(spawner),
        );
        (l, pids)
    }

    /// 同じ ID のコンテナを外側（CLI 等）で削除・再作成して Running にする（インスタンスが変わる）。
    fn recreate_running(&self, name: &str) {
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
                ContainerStatus::running(id, NonZeroU32::new(PID)),
                created.revision(),
            ))
            .expect("running");
    }

    /// 状態ストアが今報告しているインスタンス識別子を `instance` に入れた起動要求（記録が無ければ `None`）。
    fn req(&self, id: &str, stdin: bool, stdout: bool, stderr: bool, tty: bool) -> ExecLaunch {
        let instance = ContainerId::new(id)
            .ok()
            .and_then(|id| self.store.get(&GetStateRequest::new(id)).ok())
            .and_then(|r| r.instance())
            .map(|i| i.value());
        ExecLaunch {
            container_id: id.to_string(),
            cmd: vec!["/bin/true".to_string()],
            tty,
            stdin,
            stdout,
            stderr,
            instance,
        }
    }
}

fn deadline() -> Instant {
    Instant::now() + WAIT
}

async fn read_all(r: &mut Box<dyn AsyncRead + Send + Unpin>) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut chunk = [0u8; 256];
        let mut rb = ReadBuf::new(&mut chunk);
        tokio::time::timeout(
            WAIT,
            poll_fn(|cx| Pin::new(&mut **r).poll_read(cx, &mut rb)),
        )
        .await
        .expect("read timed out")
        .expect("read");
        if rb.filled().is_empty() {
            return out;
        }
        out.extend_from_slice(rb.filled());
    }
}

async fn write_all(w: &mut Box<dyn AsyncWrite + Send + Unpin>, mut data: &[u8]) {
    while !data.is_empty() {
        let n = poll_fn(|cx| Pin::new(&mut **w).poll_write(cx, data))
            .await
            .expect("write");
        data = data.get(n..).expect("slice");
    }
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

/// 選ばれた stdio だけを helper 役が受け、出力のバイト列が別々に届き、終了コードが返る。
#[tokio::test]
async fn cri6_3761_stdio_selection_bytes_and_exit_code() {
    for (stdin, stdout, stderr) in [
        (true, true, true),
        (false, true, false),
        (false, false, true),
        (true, false, false),
        (false, false, false),
    ] {
        let fx = Fixture::new("stdio");
        let (seen_tx, seen_rx) = mpsc::channel::<(u8, Vec<u8>)>();
        let seen_tx = Mutex::new(seen_tx);
        let script: Script = Arc::new(move |end, mask| {
            let fds = recv_stdio_handover(&end, mask, deadline()).expect("handover");
            let tx = seen_tx.lock().expect("lock").clone();
            if let Some(fd) = fds.stdout {
                File::from(fd).write_all(b"out-line\n").expect("out");
            }
            if let Some(fd) = fds.stderr {
                File::from(fd).write_all(b"err-line\n").expect("err");
            }
            send_started(&end, &cg_name(), deadline()).expect("started");
            let mut got = Vec::new();
            if let Some(fd) = fds.stdin {
                File::from(fd).read_to_end(&mut got).expect("stdin");
            }
            tx.send((mask.bits(), got)).expect("seen");
            send_result(&end, &StreamExecOutcome::Exited(3), deadline()).expect("result");
        });
        let (launcher, _pids) = fx.launcher(false, script);
        let mut session = launcher
            .launch(fx.req("run1", stdin, stdout, stderr, false))
            .await
            .expect("launch");
        assert_eq!(session.stdin.is_some(), stdin);
        assert_eq!(session.stdout.is_some(), stdout);
        assert_eq!(session.stderr.is_some(), stderr);
        assert!(session.resize.is_none());
        if let Some(r) = session.stdout.as_mut() {
            assert_eq!(read_all(r).await, b"out-line\n");
        }
        if let Some(r) = session.stderr.as_mut() {
            assert_eq!(read_all(r).await, b"err-line\n");
        }
        if let Some(mut w) = session.stdin.take() {
            write_all(&mut w, b"in-line\n").await;
            poll_fn(|cx| Pin::new(&mut *w).poll_shutdown(cx))
                .await
                .expect("shutdown");
        }
        let code = tokio::time::timeout(WAIT, &mut session.exit)
            .await
            .expect("exit timed out")
            .expect("exit");
        assert_eq!(code, 3);
        let (bits, got) = seen_rx.recv_timeout(WAIT).expect("seen");
        assert_eq!(
            bits,
            u8::from(stdin) | (u8::from(stdout) << 1) | (u8::from(stderr) << 2)
        );
        assert_eq!(
            got,
            if stdin {
                b"in-line\n".to_vec()
            } else {
                Vec::new()
            }
        );
    }
}

/// セッションの drop で helper が SIGKILL され、回収されて枠が戻る。
#[tokio::test]
async fn cri6_3761_dropping_the_session_kills_the_helper() {
    let fx = Fixture::new("drop");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        std::thread::sleep(Duration::from_secs(30));
    });
    let (launcher, pids) = fx.launcher(false, script);
    let session = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect("launch");
    assert_eq!(launcher.active_sessions(), 1);
    let pid = *pids.lock().expect("lock").first().expect("pid");
    assert!(std::path::Path::new(&format!("/proc/{pid}")).exists());
    drop(session);
    assert!(gone(pid), "helper {pid} must be killed and reaped");
    assert_eq!(launcher.active_sessions(), 0);
}

/// `shutdown_all` は追跡中の helper をすべて kill する。
#[tokio::test]
async fn cri6_3761_shutdown_all_kills_tracked_helpers() {
    let fx = Fixture::new("shutdown");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        std::thread::sleep(Duration::from_secs(30));
    });
    let (launcher, pids) = fx.launcher(false, script);
    let _s1 = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect("launch");
    let _s2 = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect("launch");
    launcher.shutdown_all();
    for pid in pids.lock().expect("lock").iter() {
        assert!(gone(*pid), "helper {pid}");
    }
}

/// `Started` の前に `Result` が来たら起動の失敗で、helper は kill される。
#[tokio::test]
async fn cri6_3761_result_before_started_is_a_launch_error() {
    let fx = Fixture::new("early");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_result(
            &end,
            &StreamExecOutcome::Failed(ErrorCode::FailedPrecondition),
            deadline(),
        )
        .expect("result");
    });
    let (launcher, pids) = fx.launcher(false, script);
    let err = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect_err("launch must fail");
    assert_eq!(err.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(err.message(), "exec target is not running");
    let pid = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(pid));
    assert_eq!(launcher.active_sessions(), 0);
}

/// 終了の写像（SIGNAL は 128 + 番号・NotStarted は子の終了状態・Failed は固定文のエラー）。
#[test]
fn cri6_3761_outcome_mapping_is_fixed() {
    let sig = |n| ExitSignal::new(n).expect("signal");
    assert_eq!(map_outcome(StreamExecOutcome::Exited(3)).expect("ok"), 3);
    assert_eq!(
        map_outcome(StreamExecOutcome::Signaled(sig(9))).expect("ok"),
        137
    );
    assert_eq!(
        map_outcome(StreamExecOutcome::NotStarted {
            exit: ChildStatus::Exited(126),
            step: None,
            code: ErrorCode::Internal,
        })
        .expect("ok"),
        126
    );
    assert_eq!(
        map_outcome(StreamExecOutcome::NotStarted {
            exit: ChildStatus::Signaled(sig(11)),
            step: None,
            code: ErrorCode::Internal,
        })
        .expect("ok"),
        139
    );
    let e = map_outcome(StreamExecOutcome::Failed(ErrorCode::Unavailable)).expect_err("err");
    assert_eq!(e.code(), CriErrorCode::Unavailable);
    assert_eq!(e.message(), "exec helper is unavailable");
    let e = map_outcome(StreamExecOutcome::Failed(ErrorCode::PermissionDenied)).expect_err("err");
    assert_eq!(e.code(), CriErrorCode::Internal);
}

/// `Result` frame が exit future まで届く（シグナル死は 137）。
#[tokio::test]
async fn cri6_3761_signaled_result_reaches_the_exit_future() {
    let fx = Fixture::new("signaled");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        send_result(
            &end,
            &StreamExecOutcome::Signaled(ExitSignal::new(9).expect("signal")),
            deadline(),
        )
        .expect("result");
    });
    let (launcher, _pids) = fx.launcher(false, script);
    let mut session = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect("launch");
    let code = tokio::time::timeout(WAIT, &mut session.exit)
        .await
        .expect("timed out")
        .expect("exit");
    assert_eq!(code, 137);
}

/// CRI-6・SUP-6・#4316: `Started` と `Result` の間の `Spawned`（コマンドのホスト側 pid）は読み捨てられ、exit future は終了コードで終わる。
#[tokio::test]
async fn cri6_4316_spawned_before_result_is_accepted() {
    let fx = Fixture::new("spawned");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        send_spawned(
            &end,
            std::num::NonZeroU32::new(4242).expect("pid"),
            deadline(),
        )
        .expect("spawned");
        send_result(&end, &StreamExecOutcome::Exited(0), deadline()).expect("result");
    });
    let (launcher, pids) = fx.launcher(false, script);
    let mut session = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect("launch");
    let code = tokio::time::timeout(WAIT, &mut session.exit)
        .await
        .expect("timed out")
        .expect("exit");
    assert_eq!(code, 0);
    drop(pids);
}

/// SEC-1・SUP-6・#4316: `Spawned` が 2 回来るのは違反で内部エラーになり、helper は kill される。
#[tokio::test]
async fn sec1_4316_duplicate_spawned_is_internal_and_kills_the_helper() {
    let fx = Fixture::new("dupspawned");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        let pid = std::num::NonZeroU32::new(4242).expect("pid");
        send_spawned(&end, pid, deadline()).expect("spawned");
        send_spawned(&end, pid, deadline()).expect("spawned again");
        std::thread::sleep(Duration::from_secs(10));
    });
    let (launcher, pids) = fx.launcher(false, script);
    let mut session = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect("launch");
    let err = tokio::time::timeout(WAIT, &mut session.exit)
        .await
        .expect("timed out")
        .expect_err("protocol violation");
    assert_eq!(err.code(), CriErrorCode::Internal);
    let pid = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(pid), "helper must be killed");
}

/// SEC-1・SUP-6・#4316: `Started` より前の `Spawned` は順序違反で起動の失敗になり、helper は kill される。
#[tokio::test]
async fn sec1_4316_spawned_before_started_fails_the_launch() {
    let fx = Fixture::new("earlyspawn");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_spawned(
            &end,
            std::num::NonZeroU32::new(4242).expect("pid"),
            deadline(),
        )
        .expect("spawned");
        std::thread::sleep(Duration::from_secs(10));
    });
    let (launcher, pids) = fx.launcher(false, script);
    let err = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect_err("launch must fail");
    assert_eq!(err.code(), CriErrorCode::Internal);
    let pid = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(pid));
    assert_eq!(launcher.active_sessions(), 0);
}

/// 拒否: 能力の無い tty・相対 argv[0]・不在・稼働していない。
#[tokio::test]
async fn cri6_3761_rejections_use_fixed_codes() {
    let fx = Fixture::new("reject");
    let script: Script = Arc::new(|_end, _mask| {});
    let (launcher, pids) = fx.launcher(false, script);

    let e = launcher
        .launch(fx.req("run1", false, true, false, true))
        .await
        .expect_err("tty");
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert_eq!(e.message(), "exec with tty is not supported");

    let mut relative = fx.req("run1", false, true, false, false);
    relative.cmd = vec!["true".to_string()];
    let e = launcher.launch(relative).await.expect_err("relative");
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert_eq!(e.message(), "exec request was rejected");

    let e = launcher
        .launch(fx.req("nope", false, true, false, false))
        .await
        .expect_err("missing");
    assert_eq!(e.code(), CriErrorCode::NotFound);

    let e = launcher
        .launch(fx.req("created1", false, true, false, false))
        .await
        .expect_err("not running");
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "container is not running");

    assert!(pids.lock().expect("lock").is_empty(), "no helper started");
    assert_eq!(launcher.active_sessions(), 0);
}

/// 同時数と保持の上限は `RESOURCE_EXHAUSTED`。枠を返せば再び取れる。
#[test]
fn cri6_3761_limits_are_resource_exhausted() {
    let shared = Arc::new(Shared::default());
    let mut slots: Vec<Slot> = (0..MAX_EXEC_SESSIONS)
        .map(|_| shared.acquire().expect("slot"))
        .collect();
    let e = shared.acquire().err().expect("over limit");
    assert_eq!(e.code(), CriErrorCode::ResourceExhausted);
    assert_eq!(e.message(), "too many exec sessions");
    slots.pop();
    assert!(shared.acquire().is_ok());
    drop(slots);

    let stuck: Vec<Child> = (0..MAX_STUCK_HELPERS)
        .map(|_| Command::new("/bin/sleep").arg("60").spawn().expect("sleep"))
        .collect();
    *shared.stuck.lock().expect("lock") = stuck;
    let e = shared.acquire().err().expect("stuck full");
    assert_eq!(e.code(), CriErrorCode::ResourceExhausted);
    assert_eq!(e.message(), "too many exec helpers");
    for c in shared.stuck.lock().expect("lock").iter_mut() {
        let _ = c.kill();
        let _ = c.wait();
    }
}

/// tty の受け側: `PtyMaster` を検証して受け、resize が master の `TIOCSWINSZ` に届く。
#[tokio::test]
async fn cri6_3761_resize_is_forwarded_to_the_pty_master() {
    let fx = Fixture::new("resize");
    let probe: Arc<Mutex<Option<File>>> = Arc::new(Mutex::new(None));
    let probe2 = Arc::clone(&probe);
    let script: Script = Arc::new(move |end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        let master = File::options()
            .read(true)
            .write(true)
            .open("/dev/ptmx")
            .expect("open /dev/ptmx");
        *probe2.lock().expect("lock") = Some(master.try_clone().expect("clone"));
        send_pty_master(&end, std::os::fd::AsFd::as_fd(&master), deadline()).expect("pty");
        std::thread::sleep(Duration::from_secs(30));
    });
    let (launcher, _pids) = fx.launcher(true, script);
    let mut session = launcher
        .launch(fx.req("run1", true, true, false, true))
        .await
        .expect("launch");
    assert!(session.stdin.is_some());
    assert!(session.stdout.is_some());
    assert!(session.stderr.is_none());
    let mut resizer = session.resize.take().expect("resizer");
    resizer
        .resize(TerminalSize {
            width: 120,
            height: 40,
        })
        .expect("resize");
    let dup = probe.lock().expect("lock").take().expect("master dup");
    let master = PtyMaster::from_received(OwnedFd::from(dup)).expect("master");
    let size = master.window_size().expect("size");
    assert_eq!((size.rows(), size.cols()), (40, 120));
}

/// 受け取った fd が pty master でなければ（文字デバイスの `/dev/null`）起動を失敗にし、helper を kill する。
#[tokio::test]
async fn cri6_3761_non_pty_master_fails_the_launch() {
    let fx = Fixture::new("badpty");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        let null = File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("null");
        send_pty_master(&end, std::os::fd::AsFd::as_fd(&null), deadline()).expect("pty");
        std::thread::sleep(Duration::from_secs(30));
    });
    let (launcher, pids) = fx.launcher(true, script);
    let e = launcher
        .launch(fx.req("run1", false, true, false, true))
        .await
        .expect_err("must fail");
    assert_eq!(e.code(), CriErrorCode::Internal);
    assert_eq!(e.message(), "exec pty is invalid");
    let pid = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(pid));
}

/// 偽の helper の script から tty の契約順（`Started` → `PtyMaster` → `Spawned` → `Result`）で流す共通部品（#4417）。
fn open_ptmx() -> File {
    File::options()
        .read(true)
        .write(true)
        .open("/dev/ptmx")
        .expect("open /dev/ptmx")
}

/// CRI-6・SEC-1・#4417: tty の要求は helper に `--tty` を付け、stdio の mask は 0 のまま。非 tty には `--tty` を付けない。
#[tokio::test]
async fn cri6_4417_tty_launch_passes_tty_flag_and_zero_mask() {
    let fx = Fixture::new("ttyflag");
    for tty in [true, false] {
        let seen = SeenArgs::default();
        let pids = Arc::new(Mutex::new(Vec::new()));
        let script: Script = Arc::new(move |end, mask| {
            let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
            send_started(&end, &cg_name(), deadline()).expect("started");
            if tty {
                let master = open_ptmx();
                send_pty_master(&end, std::os::fd::AsFd::as_fd(&master), deadline()).expect("pty");
            }
            send_result(&end, &StreamExecOutcome::Exited(0), deadline()).expect("result");
        });
        let spawner = FakeSpawner {
            tty,
            script,
            diag: None,
            pids: Arc::clone(&pids),
            seen: Arc::clone(&seen),
        };
        let launcher = SupervisorExecLauncher::new(
            fx.dir.0.join("state"),
            Arc::clone(&fx.store) as Arc<dyn StateStore>,
            Arc::new(spawner),
        );
        let _session = launcher
            .launch(fx.req("run1", tty, true, false, tty))
            .await
            .expect("launch");
        let seen = seen.lock().expect("lock");
        let (got_tty, bits, argv) = seen.first().expect("spawned").clone();
        assert_eq!(got_tty, tty);
        let flags = argv.iter().filter(|a| *a == "--tty").count();
        assert_eq!(flags, usize::from(tty), "argv: {argv:?}");
        if tty {
            assert_eq!(bits, 0, "tty must not hand over stdio fds");
        }
    }
}

/// CRI-6・SEC-1・#4417: 契約の順序 `Started` → `PtyMaster` → `Spawned` → `Result` で起動に成功し、終了コード 0 で終わる。
#[tokio::test]
async fn cri6_4417_tty_contract_order_is_accepted() {
    let fx = Fixture::new("ttyorder");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        let master = open_ptmx();
        send_pty_master(&end, std::os::fd::AsFd::as_fd(&master), deadline()).expect("pty");
        send_spawned(
            &end,
            std::num::NonZeroU32::new(4242).expect("pid"),
            deadline(),
        )
        .expect("spawned");
        send_result(&end, &StreamExecOutcome::Exited(0), deadline()).expect("result");
    });
    let (launcher, _pids) = fx.launcher(true, script);
    let mut session = launcher
        .launch(fx.req("run1", true, true, false, true))
        .await
        .expect("launch");
    assert!(session.stdin.is_some());
    assert!(session.stdout.is_some());
    assert!(session.stderr.is_none());
    assert!(session.resize.is_some());
    let code = tokio::time::timeout(WAIT, &mut session.exit)
        .await
        .expect("timed out")
        .expect("exit");
    assert_eq!(code, 0);
}

/// SEC-1・#4417: tty で `Started` の次が `Spawned`（`PtyMaster` の欠落）なら起動の失敗で、helper は kill される。
#[tokio::test]
async fn sec1_4417_spawned_instead_of_pty_master_fails_the_launch() {
    let fx = Fixture::new("ttynopty");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        send_spawned(
            &end,
            std::num::NonZeroU32::new(4242).expect("pid"),
            deadline(),
        )
        .expect("spawned");
        std::thread::sleep(Duration::from_secs(10));
    });
    let (launcher, pids) = fx.launcher(true, script);
    let e = launcher
        .launch(fx.req("run1", true, true, false, true))
        .await
        .expect_err("must fail");
    assert_eq!(e.code(), CriErrorCode::Internal);
    let pid = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(pid));
    assert_eq!(launcher.active_sessions(), 0);
}

/// SEC-1・#4417: `PtyMaster` が 2 回届くのは違反で、exit future は内部エラーになり helper は kill される。
#[tokio::test]
async fn sec1_4417_duplicate_pty_master_is_internal_and_kills_the_helper() {
    let fx = Fixture::new("ttydup");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        let master = open_ptmx();
        send_pty_master(&end, std::os::fd::AsFd::as_fd(&master), deadline()).expect("pty");
        send_pty_master(&end, std::os::fd::AsFd::as_fd(&master), deadline()).expect("pty again");
        std::thread::sleep(Duration::from_secs(10));
    });
    let (launcher, pids) = fx.launcher(true, script);
    let mut session = launcher
        .launch(fx.req("run1", true, true, false, true))
        .await
        .expect("launch");
    let err = tokio::time::timeout(WAIT, &mut session.exit)
        .await
        .expect("timed out")
        .expect_err("protocol violation");
    assert_eq!(err.code(), CriErrorCode::Internal);
    let pid = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(pid), "helper must be killed");
}

/// SEC-1・#4417: tty でないのに届いた `PtyMaster` は違反で、exit future は内部エラーになり helper は kill される。
#[tokio::test]
async fn sec1_4417_pty_master_without_tty_is_internal_and_kills_the_helper() {
    let fx = Fixture::new("notty-pty");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        let master = open_ptmx();
        send_pty_master(&end, std::os::fd::AsFd::as_fd(&master), deadline()).expect("pty");
        std::thread::sleep(Duration::from_secs(10));
    });
    let (launcher, pids) = fx.launcher(false, script);
    let mut session = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect("launch");
    let err = tokio::time::timeout(WAIT, &mut session.exit)
        .await
        .expect("timed out")
        .expect_err("protocol violation");
    assert_eq!(err.code(), CriErrorCode::Internal);
    let pid = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(pid), "helper must be killed");
}

/// SEC-1・#4417: `Started` より前の `PtyMaster` は順序違反で起動の失敗になり、helper は kill される。
#[tokio::test]
async fn sec1_4417_pty_master_before_started_fails_the_launch() {
    let fx = Fixture::new("ptyearly");
    let script: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        let master = open_ptmx();
        send_pty_master(&end, std::os::fd::AsFd::as_fd(&master), deadline()).expect("pty");
        std::thread::sleep(Duration::from_secs(10));
    });
    let (launcher, pids) = fx.launcher(true, script);
    let e = launcher
        .launch(fx.req("run1", true, true, false, true))
        .await
        .expect_err("must fail");
    assert_eq!(e.code(), CriErrorCode::Internal);
    let pid = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(pid));
    assert_eq!(launcher.active_sessions(), 0);
}

/// 本番の spawner は tty の能力を持つ（`--tty` の helper と supervisor の pty 結線が入った後。#4416・#4417）。
#[test]
fn cri6_4417_production_spawner_has_tty_capability() {
    assert!(ProductionHelperSpawner.capabilities().tty);
}

/// 停止後の `launch` は拒否され、helper を起動しない（REPAIR-5・#3761）。
#[tokio::test]
async fn cri6_3761_launch_after_shutdown_is_rejected() {
    let fx = Fixture::new("after-stop");
    let script: Script = Arc::new(|_end, _mask| {});
    let (launcher, pids) = fx.launcher(false, script);
    launcher.shutdown_all();
    let Err(e) = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
    else {
        panic!("launch after shutdown must be rejected");
    };
    assert_eq!(e.code(), CriErrorCode::Unavailable);
    assert!(pids.lock().expect("lock").is_empty());
    assert_eq!(launcher.active_sessions(), 0);
}

/// 取消済みの `LaunchCancel` には helper を登録できず、登録済みなら取消で kill される（REPAIR-5・#3761）。
#[test]
fn repair5_3761_launch_cancel_kills_registered_helper_and_rejects_late_register() {
    let shared = Arc::new(Shared::default());
    let mk = |shared: &Arc<Shared>| {
        let child = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep");
        let slot = shared.acquire().expect("slot");
        Arc::new(HelperGuard {
            child: Mutex::new(Some(child)),
            shared: Arc::clone(shared),
            diag_stop: Arc::new(AtomicBool::new(false)),
            _slot: slot,
        })
    };
    let cancel = LaunchCancel::default();
    let guard = mk(&shared);
    assert!(cancel.register(&guard));
    cancel.cancel();
    assert!(cancel.is_cancelled());
    assert!(
        guard
            .child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_none(),
        "cancel must take and kill the child"
    );
    let late = mk(&shared);
    assert!(!cancel.register(&late), "late register must be refused");
}
// ---- fd 2 の診断の転送（#4171・CRI-6・SUP-6・SEC-1・REPAIR-4・REPAIR-5） ----

/// 捕捉用の書き出し先。
struct Collect(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Collect {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn collecting_sink() -> (LineSink, Arc<Mutex<Vec<u8>>>) {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let sink = LineSink::spawn(Box::new(Collect(Arc::clone(&buf))), 256);
    (sink, buf)
}

fn collected_lines(sink: &LineSink, buf: &Arc<Mutex<Vec<u8>>>) -> Vec<String> {
    sink.wait_idle(WAIT);
    let bytes = buf.lock().expect("lock").clone();
    String::from_utf8(bytes)
        .expect("utf8")
        .lines()
        .map(str::to_string)
        .collect()
}

/// started を返してすぐ結果を返す helper 役（診断は別の diag スクリプトが書く）。
fn quick_script() -> Script {
    Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        std::thread::sleep(Duration::from_millis(300));
        let _ = send_result(&end, &StreamExecOutcome::Exited(0), deadline());
    })
}

/// 1 helper が上限を超える出力（各 4 KiB の行 1000 本）を出しても止まらず、転送行は上限以下で、切り捨ての件数が具体値で出る。
#[tokio::test]
async fn repair5_4171_flood_is_bounded_and_counted() {
    let fx = Fixture::new("flood");
    let (sink, buf) = collecting_sink();
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let done_tx = Mutex::new(done_tx);
    let diag: DiagScript = Arc::new(move |mut end| {
        let mut out = Vec::new();
        for _ in 0..40 {
            out.extend_from_slice(b"stage=setsid errno=13\n");
        }
        let mut big = vec![b'a'; 4095];
        big.push(b'\n');
        for _ in 0..1000 {
            out.extend_from_slice(&big);
        }
        end.write_all(&out).expect("flood");
        drop(end);
        done_tx.lock().expect("lock").send(()).expect("done");
    });
    let (launcher, _pids) = fx.launcher_with_diag(false, quick_script(), Some(diag));
    let launcher = launcher.with_diagnostic_sink(sink.clone());
    let mut session = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect("launch");
    done_rx
        .recv_timeout(WAIT)
        .expect("the flooding writer must not block");
    let code = tokio::time::timeout(WAIT, &mut session.exit)
        .await
        .expect("exit timed out")
        .expect("exit");
    assert_eq!(code, 0);
    assert_eq!(launcher.wait_diagnostics_idle(WAIT), 0);
    let lines = collected_lines(&sink, &buf);
    let forwarded = lines
        .iter()
        .filter(|l| l.contains("\"event\":\"cri_exec_helper_diagnostic\""))
        .count();
    assert_eq!(forwarded, 32);
    let summaries: Vec<&String> = lines
        .iter()
        .filter(|l| l.contains("cri_exec_helper_diagnostics"))
        .collect();
    assert_eq!(summaries.len(), 1);
    let expected_bytes = 8 * 22 + 1000 * 4096;
    assert_eq!(
        summaries[0],
        &format!(
            "{{\"event\":\"cri_exec_helper_diagnostics\",\"outcome\":\"error\",\"end\":\"eof\",\"forwarded\":32,\"ignored\":0,\"unparsed\":0,\"dropped_lines\":1008,\"dropped_bytes\":{expected_bytes}}}"
        )
    );
}

/// 段名と errno を持つ行は 1 件のログ行になり、値が一致する。要約行は出ない。
#[tokio::test]
async fn cri6_4171_stage_and_errno_line_is_logged_once() {
    let fx = Fixture::new("oneline");
    let (sink, buf) = collecting_sink();
    let diag: DiagScript = Arc::new(|mut end| {
        end.write_all(b"stage=open_entrypoint errno=13\n")
            .expect("w");
    });
    let (launcher, _pids) = fx.launcher_with_diag(false, quick_script(), Some(diag));
    let launcher = launcher.with_diagnostic_sink(sink.clone());
    let mut session = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect("launch");
    let _ = tokio::time::timeout(WAIT, &mut session.exit).await;
    assert_eq!(launcher.wait_diagnostics_idle(WAIT), 0);
    assert_eq!(
        collected_lines(&sink, &buf),
        ["{\"event\":\"cri_exec_helper_diagnostic\",\"stage\":\"open_entrypoint\",\"errno\":13}"]
    );
}

/// argv・コンテナ ID・トークンに見える文字列は、診断行へ混ざってもログに出ない（件数だけ数える）。
#[tokio::test]
async fn sec1_4171_argv_container_id_and_token_are_not_logged() {
    let fx = Fixture::new("secret");
    let (sink, buf) = collecting_sink();
    let diag: DiagScript = Arc::new(|mut end| {
        end.write_all(b"argv=/bin/argv-marker-4171 run1 tok_AbCdEf0123456789\n")
            .expect("w");
        end.write_all(b"stage=setsid errno=13 container=run1 token=tok_AbCdEf0123456789\n")
            .expect("w");
        end.write_all(
            b"{\"code\":\"INTERNAL\",\"message\":\"run1 /bin/argv-marker-4171 tok_AbCdEf0123456789\"}\n",
        )
        .expect("w");
    });
    let (launcher, _pids) = fx.launcher_with_diag(false, quick_script(), Some(diag));
    let launcher = launcher.with_diagnostic_sink(sink.clone());
    let mut launch = fx.req("run1", false, true, false, false);
    launch.cmd = vec!["/bin/argv-marker-4171".to_string()];
    let mut session = launcher.launch(launch).await.expect("launch");
    let _ = tokio::time::timeout(WAIT, &mut session.exit).await;
    assert_eq!(launcher.wait_diagnostics_idle(WAIT), 0);
    let lines = collected_lines(&sink, &buf);
    let all = lines.join("\n");
    for needle in ["argv-marker-4171", "run1", "tok_AbCdEf0123456789"] {
        assert!(!all.contains(needle), "{needle} leaked: {all}");
    }
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(
        lines.first().map(String::as_str),
        Some("{\"event\":\"cri_exec_helper_diagnostic\",\"code\":\"INTERNAL\"}")
    );
    assert_eq!(
        lines.get(1).map(String::as_str),
        Some(
            "{\"event\":\"cri_exec_helper_diagnostics\",\"outcome\":\"error\",\"end\":\"eof\",\"forwarded\":1,\"ignored\":0,\"unparsed\":2,\"dropped_lines\":0,\"dropped_bytes\":0}"
        )
    );
}

/// helper が終了せず fd 2 を持ち続けても、`shutdown_all` は待たず、読み手は停止フラグで上限時間内に終わる。
#[tokio::test]
async fn repair5_4171_shutdown_all_is_bounded_when_stderr_is_held() {
    let fx = Fixture::new("held");
    let (sink, _buf) = collecting_sink();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = Mutex::new(release_rx);
    let diag: DiagScript = Arc::new(move |mut end| {
        end.write_all(b"stage=setsid errno=13\n").expect("w");
        let _ = release_rx.lock().expect("lock").recv();
        drop(end);
    });
    let hold: Script = Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        std::thread::sleep(Duration::from_secs(30));
    });
    let (launcher, pids) = fx.launcher_with_diag(false, hold, Some(diag));
    let launcher = launcher.with_diagnostic_sink(sink.clone());
    let _session = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect("launch");
    let t0 = Instant::now();
    launcher.shutdown_all();
    assert!(
        t0.elapsed() < Duration::from_millis(200),
        "shutdown_all must not wait: {:?}",
        t0.elapsed()
    );
    assert_eq!(
        launcher.wait_diagnostics_idle(diagnostics::DIAG_JOIN_BUDGET),
        0
    );
    assert!(
        t0.elapsed() < diagnostics::DIAG_JOIN_BUDGET + Duration::from_millis(500),
        "diagnostic readers must stop in time: {:?}",
        t0.elapsed()
    );
    release_tx.send(()).expect("release");
    for pid in pids.lock().expect("lock").iter() {
        assert!(gone(*pid), "helper {pid}");
    }
}

/// 識別子を報告しない（instance を外した record を返す）状態ストア。旧い記録・識別子を報告しない実装の模擬。
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

fn hold_script() -> Script {
    Arc::new(|end, mask| {
        let _ = recv_stdio_handover(&end, mask, deadline()).expect("handover");
        send_started(&end, &cg_name(), deadline()).expect("started");
        std::thread::sleep(Duration::from_secs(30));
    })
}

/// CRI-5・SEC-1・CORE-1（#4286）: 発行時と同じインスタンスなら起動する。
#[tokio::test]
async fn cri5_4286_matching_instance_launches() {
    let fx = Fixture::new("inst-match");
    let (launcher, pids) = fx.launcher(false, hold_script());
    let launch = fx.req("run1", false, true, false, false);
    assert!(launch.instance.is_some(), "store reports an instance");
    let _session = launcher.launch(launch).await.expect("launch");
    assert_eq!(pids.lock().expect("lock").len(), 1);
}

/// SEC-1・CORE-1（#4286）: 発行後に外で削除・再作成されたコンテナへは、helper を起動せず拒否する。
#[tokio::test]
async fn sec1_4286_recreated_container_is_rejected_without_helper() {
    let fx = Fixture::new("inst-recreate");
    let (launcher, pids) = fx.launcher(false, hold_script());
    let issued = fx.req("run1", false, true, false, false);
    fx.recreate_running("run1");
    let e = launcher.launch(issued).await.expect_err("recreated");
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(e.message(), MSG_EXEC_INSTANCE_CHANGED);
    assert!(pids.lock().expect("lock").is_empty(), "no helper started");
    assert_eq!(launcher.active_sessions(), 0);
    // 新しいインスタンスを控え直した要求は起動する。
    let _session = launcher
        .launch(fx.req("run1", false, true, false, false))
        .await
        .expect("relaunch");
    assert_eq!(pids.lock().expect("lock").len(), 1);
}

/// SEC-1（#4286）: 発行時に識別子があり、起動時の記録に無い（片側だけ None）なら拒否する。
#[tokio::test]
async fn sec1_4286_one_sided_none_is_rejected() {
    let fx = Fixture::new("inst-onesided");
    let issued = fx.req("run1", false, true, false, false);
    assert!(issued.instance.is_some());
    let pids = Arc::new(Mutex::new(Vec::new()));
    let spawner = FakeSpawner {
        tty: false,
        script: hold_script(),
        diag: None,
        pids: Arc::clone(&pids),
        seen: SeenArgs::default(),
    };
    let launcher = SupervisorExecLauncher::new(
        fx.dir.0.join("state"),
        Arc::new(NoInstanceStore(Arc::clone(&fx.store))) as Arc<dyn StateStore>,
        Arc::new(spawner),
    );
    let e = launcher.launch(issued).await.expect_err("one-sided");
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(e.message(), MSG_EXEC_INSTANCE_CHANGED);
    assert!(pids.lock().expect("lock").is_empty());
}

/// 残余の固定（#4286）: 識別子を報告しない実装・旧い記録（両側 None）は判定できないので起動する（保護されない）。
#[tokio::test]
async fn cri5_4286_unreported_instance_on_both_sides_is_not_protected() {
    let fx = Fixture::new("inst-none");
    let mut issued = fx.req("run1", false, true, false, false);
    issued.instance = None;
    let pids = Arc::new(Mutex::new(Vec::new()));
    let spawner = FakeSpawner {
        tty: false,
        script: hold_script(),
        diag: None,
        pids: Arc::clone(&pids),
        seen: SeenArgs::default(),
    };
    let launcher = SupervisorExecLauncher::new(
        fx.dir.0.join("state"),
        Arc::new(NoInstanceStore(Arc::clone(&fx.store))) as Arc<dyn StateStore>,
        Arc::new(spawner),
    );
    let _session = launcher.launch(issued).await.expect("launch");
    assert_eq!(pids.lock().expect("lock").len(), 1);
}
// ---- #4499: 本番の spawner の bin 検査（共通口 `open_supervisor_beside_at` を exe と euid の注入で通す） ----

mod bin_check_4499 {
    use std::path::Path;

    use fandhe_container_core::traits::ErrorCode as TraitCode;

    use super::*;
    use crate::pod_holder::bin_fixture::{BinFixture, assert_untrusted};
    use crate::pod_holder::{current_euid, open_supervisor_beside_at};

    fn args() -> StreamExecArgs {
        StreamExecArgs::new(
            PathBuf::from("/tmp"),
            ContainerId::new("c1").expect("id"),
            NonZeroU32::new(PID).expect("pid"),
            Duration::from_secs(5),
            StdioMask::from_presence(false, false, false),
            vec!["/bin/true".to_owned()],
        )
        .expect("args")
    }

    /// 本番の `spawn` と同じ組み合わせ（検査 → 検証済み fd で起動）に、exe と euid を注入した版。
    fn spawn_at(exe: &Path, euid: u32) -> Result<SpawnedHelper, CriError> {
        let verified = open_supervisor_beside_at(exe, euid).map_err(|e| CriError::from(&e))?;
        spawn_verified(&verified, &args())
    }

    fn expect_untrusted(r: Result<SpawnedHelper, CriError>) {
        let e = r.err().expect("rejected");
        assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
        assert_untrusted(TraitCode::FailedPrecondition, e.message());
    }

    /// 所有者違い（euid を root でも自分でもない値へずらす）は拒否する。euid 0 では root 所有が常に許されるため飛ばす。
    #[test]
    fn cri6_plug11_4499_helper_spawner_rejects_foreign_owner() {
        let euid = current_euid().expect("euid");
        if euid == 0 {
            return;
        }
        let fx = BinFixture::new("exec-owner");
        fx.place_elf(0o755);
        expect_untrusted(spawn_at(&fx.exe, euid + 1));
    }

    #[test]
    fn cri6_plug11_4499_helper_spawner_rejects_group_writable_bin() {
        let euid = current_euid().expect("euid");
        let fx = BinFixture::new("exec-gw");
        fx.place_elf(0o775);
        expect_untrusted(spawn_at(&fx.exe, euid));
    }

    #[test]
    fn cri6_plug11_4499_helper_spawner_rejects_writable_ancestor() {
        let euid = current_euid().expect("euid");
        let fx = BinFixture::new("exec-anc");
        fx.place_elf(0o755);
        fx.set_dir_mode(0o775);
        expect_untrusted(spawn_at(&fx.exe, euid));
    }

    /// FIFO は open でブロックしない（`O_NONBLOCK`）ため、別スレッドでも 10 秒以内に拒否が返る。
    #[test]
    fn cri6_plug11_4499_helper_spawner_rejects_fifo_without_blocking() {
        let euid = current_euid().expect("euid");
        let fx = BinFixture::new("exec-fifo");
        fx.place_fifo();
        let exe = fx.exe.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(spawn_at(&exe, euid));
        });
        expect_untrusted(
            rx.recv_timeout(Duration::from_secs(10))
                .expect("did not block"),
        );
    }

    /// 成功系: 検証済み fd 経由で ELF が実際に起動し、終了コード 0 で終わる。
    #[test]
    fn cri6_plug11_4499_helper_spawner_execs_verified_fd() {
        let euid = current_euid().expect("euid");
        let fx = BinFixture::new("exec-ok");
        fx.place_elf(0o755);
        let r = spawn_at(&fx.exe, euid);
        if !fx.ancestors_ok(euid) {
            assert!(r.is_err());
            return;
        }
        let mut helper = r.expect("spawned");
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(st) = helper.child.try_wait().expect("try_wait") {
                break st;
            }
            assert!(Instant::now() < deadline, "helper did not exit");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(0));
    }
}
