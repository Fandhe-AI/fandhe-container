//! `exec_launcher` の試験（CRI-6・SEC-1・SUP-6・REPAIR-5・#3761）。root も実コンテナも使わず、偽の helper
//! （`/bin/sleep` のプロセスを helper の `Child` とし、channel の相手は試験スレッドが演じる）で stdio の選択・drop での停止・
//! resize の転送・終了コードの写像を具体値で照合する。実 supervisor と実コンテナでの通しは #3762。

use std::future::poll_fn;
use std::os::fd::OwnedFd;
use std::os::unix::fs::DirBuilderExt as _;
use std::process::Command;
use std::sync::mpsc;

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{ContainerStatus, CreateStateRequest, UpdateStateRequest};
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_supervisor::stream_exec::channel::{
    recv_stdio_handover, send_pty_master, send_result, send_started,
};
use fandhe_container_supervisor::stream_exec::wire::ExitSignal;
use tokio::io::ReadBuf;

use super::*;
use crate::streaming::log_attach::test_support::TempDir;

const PID: u32 = 4242;
const WAIT: Duration = Duration::from_secs(5);

type Script = Arc<dyn Fn(StdUnixStream, StdioMask) + Send + Sync>;

/// 偽の helper の起動口。`Child` は `/bin/sleep 60`（stdin に channel の helper 側の端を持たせる）で、channel の相手は
/// `script` が演じる。
struct FakeSpawner {
    tty: bool,
    script: Script,
    pids: Arc<Mutex<Vec<u32>>>,
}

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
        let script = Arc::clone(&self.script);
        let mask = args.stdio();
        std::thread::spawn(move || script(script_end, mask));
        Ok(SpawnedHelper {
            child,
            channel: plugin_end,
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
        let pids = Arc::new(Mutex::new(Vec::new()));
        let spawner = FakeSpawner {
            tty,
            script,
            pids: Arc::clone(&pids),
        };
        let l = SupervisorExecLauncher::new(
            self.dir.0.join("state"),
            Arc::clone(&self.store) as Arc<dyn StateStore>,
            Arc::new(spawner),
        );
        (l, pids)
    }
}

fn req(id: &str, stdin: bool, stdout: bool, stderr: bool, tty: bool) -> ExecLaunch {
    ExecLaunch {
        container_id: id.to_string(),
        cmd: vec!["/bin/true".to_string()],
        tty,
        stdin,
        stdout,
        stderr,
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
            send_started(&end, deadline()).expect("started");
            let mut got = Vec::new();
            if let Some(fd) = fds.stdin {
                File::from(fd).read_to_end(&mut got).expect("stdin");
            }
            tx.send((mask.bits(), got)).expect("seen");
            send_result(&end, &StreamExecOutcome::Exited(3), deadline()).expect("result");
        });
        let (launcher, _pids) = fx.launcher(false, script);
        let mut session = launcher
            .launch(req("run1", stdin, stdout, stderr, false))
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
        send_started(&end, deadline()).expect("started");
        std::thread::sleep(Duration::from_secs(30));
    });
    let (launcher, pids) = fx.launcher(false, script);
    let session = launcher
        .launch(req("run1", false, true, false, false))
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
        send_started(&end, deadline()).expect("started");
        std::thread::sleep(Duration::from_secs(30));
    });
    let (launcher, pids) = fx.launcher(false, script);
    let _s1 = launcher
        .launch(req("run1", false, true, false, false))
        .await
        .expect("launch");
    let _s2 = launcher
        .launch(req("run1", false, true, false, false))
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
        .launch(req("run1", false, true, false, false))
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
        send_started(&end, deadline()).expect("started");
        send_result(
            &end,
            &StreamExecOutcome::Signaled(ExitSignal::new(9).expect("signal")),
            deadline(),
        )
        .expect("result");
    });
    let (launcher, _pids) = fx.launcher(false, script);
    let mut session = launcher
        .launch(req("run1", false, true, false, false))
        .await
        .expect("launch");
    let code = tokio::time::timeout(WAIT, &mut session.exit)
        .await
        .expect("timed out")
        .expect("exit");
    assert_eq!(code, 137);
}

/// 拒否: 能力の無い tty・相対 argv[0]・不在・稼働していない。
#[tokio::test]
async fn cri6_3761_rejections_use_fixed_codes() {
    let fx = Fixture::new("reject");
    let script: Script = Arc::new(|_end, _mask| {});
    let (launcher, pids) = fx.launcher(false, script);

    let e = launcher
        .launch(req("run1", false, true, false, true))
        .await
        .expect_err("tty");
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert_eq!(e.message(), "exec with tty is not supported");

    let mut relative = req("run1", false, true, false, false);
    relative.cmd = vec!["true".to_string()];
    let e = launcher.launch(relative).await.expect_err("relative");
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert_eq!(e.message(), "exec request was rejected");

    let e = launcher
        .launch(req("nope", false, true, false, false))
        .await
        .expect_err("missing");
    assert_eq!(e.code(), CriErrorCode::NotFound);

    let e = launcher
        .launch(req("created1", false, true, false, false))
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
        send_started(&end, deadline()).expect("started");
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
        .launch(req("run1", true, true, false, true))
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
        send_started(&end, deadline()).expect("started");
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
        .launch(req("run1", false, true, false, true))
        .await
        .expect_err("must fail");
    assert_eq!(e.code(), CriErrorCode::Internal);
    assert_eq!(e.message(), "exec pty is invalid");
    let pid = *pids.lock().expect("lock").first().expect("pid");
    assert!(gone(pid));
}

/// 本番の spawner は tty の能力を持たない（supervisor 側の pty 結線が入るまで fail-closed）。
#[test]
fn cri6_3761_production_spawner_has_no_tty_capability() {
    assert!(!ProductionHelperSpawner.capabilities().tty);
}

/// 停止後の `launch` は拒否され、helper を起動しない（REPAIR-5・#3761）。
#[tokio::test]
async fn cri6_3761_launch_after_shutdown_is_rejected() {
    let fx = Fixture::new("after-stop");
    let script: Script = Arc::new(|_end, _mask| {});
    let (launcher, pids) = fx.launcher(false, script);
    launcher.shutdown_all();
    let Err(e) = launcher
        .launch(req("run1", false, true, false, false))
        .await
    else {
        panic!("launch after shutdown must be rejected");
    };
    assert_eq!(e.code(), CriErrorCode::Unavailable);
    assert!(pids.lock().expect("lock").is_empty());
    assert_eq!(launcher.active_sessions(), 0);
}
