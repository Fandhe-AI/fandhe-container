//! `supervisor_attach` の試験（CRI-6・SEC-1・SUP-4・REPAIR-5・#4077）。root も実コンテナも使わず、偽の `AttachIoSource`・
//! `ExitNotifier` と実の `FileStateStore` で、fd の形の照合（不正の拒否と fd の閉鎖）・エラーの写像・事前確認・resize の具体値・
//! stdin の往復・tap の中継・`exited`・同時数を照合する。実コンテナでの通しは #4079。

use std::future::poll_fn;
use std::os::unix::fs::DirBuilderExt as _;

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{ContainerStatus, CreateStateRequest, UpdateStateRequest};
use fandhe_container_cri::error::CriErrorCode;

use super::*;
use crate::streaming::log_attach::test_support::TempDir;

const PID: u32 = 4242;
const WAIT: Duration = Duration::from_secs(5);

type SourceFn = Box<dyn FnMut(AttachIoRequest) -> Result<AttachIo, TraitError> + Send>;

struct FakeSource {
    calls: AtomicUsize,
    f: Mutex<SourceFn>,
}

impl FakeSource {
    fn new(f: SourceFn) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            f: Mutex::new(f),
        })
    }
}

impl AttachIoSource for FakeSource {
    fn obtain(
        &self,
        _id: &ContainerId,
        _pid: NonZeroU32,
        request: AttachIoRequest,
        _deadline: Instant,
    ) -> Result<AttachIo, TraitError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.f.lock().expect("lock"))(request)
    }
}

type WatchFn = Box<dyn Fn(&dyn Fn() -> bool) -> ExitWatchOutcome + Send + Sync>;

struct FakeNotifier {
    f: WatchFn,
}

impl ExitNotifier for FakeNotifier {
    fn watch(
        &self,
        _id: &ContainerId,
        _pid: NonZeroU32,
        _until: Instant,
        cancel: &dyn Fn() -> bool,
    ) -> ExitWatchOutcome {
        (self.f)(cancel)
    }
}

/// 取り消しが立つまで待ち、立ったら `seen` を真にして `Cancelled` を返す購読。
fn idle_notifier(seen: Arc<AtomicBool>) -> Arc<FakeNotifier> {
    Arc::new(FakeNotifier {
        f: Box::new(move |cancel| {
            loop {
                if cancel() {
                    seen.store(true, Ordering::SeqCst);
                    return ExitWatchOutcome::Cancelled;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }),
    })
}

struct Fixture {
    _dir: TempDir,
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
        Self { _dir: dir, store }
    }

    fn stop(&self, name: &str) {
        let id = ContainerId::new(name).expect("id");
        let rec = self
            .store
            .get(&GetStateRequest::new(id.clone()))
            .expect("get");
        self.store
            .update(&UpdateStateRequest::new(
                ContainerStatus::stopped(id, Some(0)),
                rec.revision(),
            ))
            .expect("stop");
    }

    fn backend(
        &self,
        source: Arc<FakeSource>,
        notifier: Arc<FakeNotifier>,
    ) -> SupervisorAttachBackend {
        SupervisorAttachBackend::new(
            Arc::clone(&self.store) as Arc<dyn StateStore>,
            source,
            notifier,
        )
    }
}

/// `streaming.rs` の結線の試験用。状態は読まれない。
pub(crate) fn backend_for_wiring() -> SupervisorAttachBackend {
    let fx = Fixture::new("wiring");
    let source = FakeSource::new(Box::new(|_| {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }));
    fx.backend(source, idle_notifier(Arc::new(AtomicBool::new(false))))
}

fn target(stdin: bool, stdout: bool, stderr: bool, tty: bool) -> AttachTarget {
    AttachTarget {
        container_id: "run1".to_string(),
        stdin,
        stdout,
        stderr,
        tty,
    }
}

fn sock_pair() -> (StdUnixStream, StdUnixStream) {
    StdUnixStream::pair().expect("pair")
}

fn plain_source() -> Arc<FakeSource> {
    FakeSource::new(Box::new(|_| {
        Ok(AttachIo {
            input: None,
            stdout: Some(sock_pair().0),
            stderr: None,
        })
    }))
}

async fn read_some(r: &mut (dyn AsyncRead + Send + Unpin)) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = poll_fn(|cx| {
        let mut rb = ReadBuf::new(&mut buf);
        match Pin::new(&mut *r).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => Poll::Ready(rb.filled().len()),
            Poll::Ready(Err(_)) => Poll::Ready(0),
            Poll::Pending => Poll::Pending,
        }
    })
    .await;
    buf[..n].to_vec()
}

async fn write_all(w: &mut (dyn AsyncWrite + Send + Unpin), data: &[u8]) {
    let mut off = 0;
    while off < data.len() {
        let n = poll_fn(|cx| Pin::new(&mut *w).poll_write(cx, &data[off..]))
            .await
            .expect("write");
        off += n;
    }
}

async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

fn wait_active_zero(b: &SupervisorAttachBackend) {
    let end = Instant::now() + WAIT;
    while b.active_sessions() != 0 {
        assert!(Instant::now() < end, "slots were not returned");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn open_ptmx() -> File {
    File::options()
        .read(true)
        .write(true)
        .open("/dev/ptmx")
        .expect("open /dev/ptmx")
}

fn fd_flags(f: &File) -> u32 {
    let text = std::fs::read_to_string(format!(
        "/proc/self/fdinfo/{}",
        std::os::fd::AsRawFd::as_raw_fd(f)
    ))
    .expect("fdinfo");
    let line = text
        .lines()
        .find(|l| l.starts_with("flags:"))
        .expect("flags line");
    u32::from_str_radix(line.trim_start_matches("flags:").trim(), 8).expect("octal")
}

fn assert_invalid_io(e: &CriError) {
    assert_eq!(e.code(), CriErrorCode::Internal);
    assert_eq!(e.message(), MSG_INVALID_IO);
}

fn rejected(t: &AttachTarget, io: AttachIo) -> CriError {
    match validate_attach_io(t, io) {
        Ok(_) => panic!("io was accepted"),
        Err(e) => e,
    }
}

// ---- 形の照合（不正な fd の拒否。SEC-1・D9） ----

#[test]
fn cri6_sec1_4077_tty_with_pipe_input_is_rejected_and_fd_is_closed() {
    let (mut r, w) = std::io::pipe().expect("pipe");
    let io = AttachIo {
        input: Some(AttachInput::Pipe(OwnedFd::from(w))),
        stdout: Some(sock_pair().0),
        stderr: None,
    };
    assert_invalid_io(&rejected(&target(true, true, false, true), io));
    let mut buf = [0u8; 1];
    assert_eq!(r.read(&mut buf).expect("eof"), 0);
}

#[test]
fn cri6_sec1_4077_non_tty_with_pty_input_is_rejected() {
    let master = PtyMaster::from_received(OwnedFd::from(open_ptmx())).expect("master");
    let io = AttachIo {
        input: Some(AttachInput::Pty(master)),
        stdout: Some(sock_pair().0),
        stderr: None,
    };
    assert_invalid_io(&rejected(&target(true, true, false, false), io));
}

#[test]
fn cri6_sec1_4077_missing_requested_input_is_rejected() {
    let io = AttachIo {
        input: None,
        stdout: Some(sock_pair().0),
        stderr: None,
    };
    assert_invalid_io(&rejected(&target(true, true, false, false), io));
}

#[test]
fn cri6_sec1_4077_unrequested_input_or_taps_are_rejected() {
    let (_r, w) = std::io::pipe().expect("pipe");
    let io = AttachIo {
        input: Some(AttachInput::Pipe(OwnedFd::from(w))),
        stdout: Some(sock_pair().0),
        stderr: None,
    };
    assert_invalid_io(&rejected(&target(false, true, false, false), io));
    let io = AttachIo {
        input: None,
        stdout: Some(sock_pair().0),
        stderr: None,
    };
    assert_invalid_io(&rejected(&target(false, false, true, false), io));
    let io = AttachIo {
        input: None,
        stdout: None,
        stderr: Some(sock_pair().0),
    };
    assert_invalid_io(&rejected(&target(false, false, false, true), io));
}

#[test]
fn cri6_sec1_4077_regular_file_directory_and_pipe_tap_are_rejected() {
    let dir = TempDir::new("badfd");
    let file_path = dir.0.join("f");
    std::fs::write(&file_path, b"x").expect("file");
    for fd in [
        OwnedFd::from(File::open(&file_path).expect("open file")),
        OwnedFd::from(File::open(&dir.0).expect("open dir")),
    ] {
        let io = AttachIo {
            input: Some(AttachInput::Pipe(fd)),
            stdout: Some(sock_pair().0),
            stderr: None,
        };
        assert_invalid_io(&rejected(&target(true, true, false, false), io));
    }
    let (r, _w) = std::io::pipe().expect("pipe");
    let io = AttachIo {
        input: None,
        stdout: Some(StdUnixStream::from(OwnedFd::from(r))),
        stderr: None,
    };
    assert_invalid_io(&rejected(&target(false, true, false, false), io));
}

#[tokio::test]
async fn cri6_sec1_4077_attach_rejects_invalid_io_end_to_end() {
    let fx = Fixture::new("badio");
    let source = FakeSource::new(Box::new(|_| {
        // tty の要求に Pipe を返す。
        let (_r, w) = std::io::pipe().expect("pipe");
        Ok(AttachIo {
            input: Some(AttachInput::Pipe(OwnedFd::from(w))),
            stdout: Some(sock_pair().0),
            stderr: None,
        })
    }));
    let b = fx.backend(source, idle_notifier(Arc::new(AtomicBool::new(false))));
    let e = within(b.attach(target(true, true, false, true)))
        .await
        .expect_err("rejected");
    assert_invalid_io(&e);
    wait_active_zero(&b);
}

// ---- エラーの写像・事前確認 ----

#[test]
fn cri6_4077_trait_errors_map_to_fixed_cri_errors() {
    let cases = [
        (
            ErrorCode::NotFound,
            CriErrorCode::NotFound,
            "container not found",
        ),
        (
            ErrorCode::FailedPrecondition,
            CriErrorCode::FailedPrecondition,
            "attach is not possible in the current container state",
        ),
        (
            ErrorCode::Unavailable,
            CriErrorCode::Unavailable,
            "attach is unavailable",
        ),
        (
            ErrorCode::Timeout,
            CriErrorCode::Timeout,
            "attach timed out",
        ),
        (
            ErrorCode::ResourceExhausted,
            CriErrorCode::ResourceExhausted,
            "attach resources are exhausted",
        ),
        (
            ErrorCode::InvalidArgument,
            CriErrorCode::InvalidArgument,
            "attach request was rejected",
        ),
        (
            ErrorCode::Unimplemented,
            CriErrorCode::Unimplemented,
            "attach is not supported",
        ),
        (ErrorCode::Internal, CriErrorCode::Internal, "attach failed"),
    ];
    for (code, want, msg) in cases {
        let e = map_trait_error(&TraitError::new(code, "secret-detail run1"));
        assert_eq!((e.code(), e.message()), (want, msg));
    }
}

#[tokio::test]
async fn cri6_4077_source_failure_is_mapped_through_attach() {
    let fx = Fixture::new("mapfail");
    let source = FakeSource::new(Box::new(|_| {
        Err(TraitError::new(
            ErrorCode::FailedPrecondition,
            "tty mismatch",
        ))
    }));
    let b = fx.backend(source, idle_notifier(Arc::new(AtomicBool::new(false))));
    let e = within(b.attach(target(true, true, false, false)))
        .await
        .expect_err("failed");
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    wait_active_zero(&b);
}

#[tokio::test]
async fn cri6_4077_state_checks_run_before_obtain() {
    let fx = Fixture::new("state");
    let source = FakeSource::new(Box::new(|_| {
        Err(TraitError::new(ErrorCode::Internal, "must not be called"))
    }));
    let b = fx.backend(
        Arc::clone(&source),
        idle_notifier(Arc::new(AtomicBool::new(false))),
    );
    let mut t = target(false, true, false, false);
    t.container_id = "created1".to_string();
    let e = within(b.attach(t.clone())).await.expect_err("rejected");
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::FailedPrecondition, "container is not running")
    );
    fx.stop("run1");
    let e = within(b.attach(target(false, true, false, false)))
        .await
        .expect_err("rejected");
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    t.container_id = "nosuch".to_string();
    let e = within(b.attach(t.clone())).await.expect_err("rejected");
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::NotFound, "container not found")
    );
    t.container_id = "../bad".to_string();
    let e = within(b.attach(t)).await.expect_err("rejected");
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    wait_active_zero(&b);
}

#[tokio::test]
async fn cri6_4077_tty_with_stderr_is_invalid_argument() {
    let fx = Fixture::new("ttyerr");
    let source = plain_source();
    let b = fx.backend(
        Arc::clone(&source),
        idle_notifier(Arc::new(AtomicBool::new(false))),
    );
    let e = within(b.attach(target(true, true, true, true)))
        .await
        .expect_err("rejected");
    assert_eq!(e.code(), CriErrorCode::InvalidArgument);
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
}

// ---- resize の具体値 ----

#[tokio::test]
async fn cri6_4077_resize_reaches_the_pty_master() {
    let fx = Fixture::new("resize");
    let probe: Arc<Mutex<Option<File>>> = Arc::new(Mutex::new(None));
    let probe2 = Arc::clone(&probe);
    let source = FakeSource::new(Box::new(move |_| {
        let master = open_ptmx();
        *probe2.lock().expect("lock") = Some(master.try_clone().expect("clone"));
        Ok(AttachIo {
            input: Some(AttachInput::Pty(
                PtyMaster::from_received(OwnedFd::from(master)).expect("master"),
            )),
            stdout: Some(sock_pair().0),
            stderr: None,
        })
    }));
    let b = fx.backend(source, idle_notifier(Arc::new(AtomicBool::new(false))));
    let mut session = within(b.attach(target(true, true, false, true)))
        .await
        .expect("attach");
    assert!(session.stdin.is_some() && session.stdout.is_some() && session.stderr.is_none());
    let mut resize = session.resize.take().expect("resize");
    resize(TerminalSize {
        width: 132,
        height: 43,
    });
    let dup = probe.lock().expect("lock").take().expect("dup");
    let master = PtyMaster::from_received(OwnedFd::from(dup)).expect("master");
    let size = master.window_size().expect("size");
    assert_eq!((size.rows(), size.cols()), (43, 132));
}

#[tokio::test]
async fn cri6_4077_non_tty_has_no_resize() {
    let fx = Fixture::new("noresize");
    let b = fx.backend(
        plain_source(),
        idle_notifier(Arc::new(AtomicBool::new(false))),
    );
    let session = within(b.attach(target(false, true, false, false)))
        .await
        .expect("attach");
    assert!(session.resize.is_none());
}

// ---- stdin の往復・tap・exited ----

#[tokio::test]
async fn cri6_4077_stdin_roundtrip_and_shutdown_closes_the_pipe() {
    let fx = Fixture::new("stdin");
    let (mut r, w) = std::io::pipe().expect("pipe");
    let w = Mutex::new(Some(w));
    let flag_probe: Arc<Mutex<Option<File>>> = Arc::new(Mutex::new(None));
    let fp = Arc::clone(&flag_probe);
    let source = FakeSource::new(Box::new(move |_| {
        let w = w.lock().expect("lock").take().expect("once");
        *fp.lock().expect("lock") = Some(File::from(OwnedFd::from(w.try_clone().expect("dup"))));
        Ok(AttachIo {
            input: Some(AttachInput::Pipe(OwnedFd::from(w))),
            stdout: Some(sock_pair().0),
            stderr: None,
        })
    }));
    let b = fx.backend(source, idle_notifier(Arc::new(AtomicBool::new(false))));
    let mut session = within(b.attach(target(true, true, false, false)))
        .await
        .expect("attach");
    let mut stdin = session.stdin.take().expect("stdin");
    within(write_all(&mut *stdin, b"hello\n")).await;
    let got = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 6];
        r.read_exact(&mut buf).expect("read");
        (buf, r)
    })
    .await
    .expect("join");
    assert_eq!(&got.0, b"hello\n");
    // O_NONBLOCK（04000）が元の記述に立っていない（supervisor 側の記述へ波及させない）。
    let dup = flag_probe.lock().expect("lock").take().expect("dup");
    assert_eq!(fd_flags(&dup) & 0o4000, 0);
    // shutdown と全部品の drop、probe の dup の drop で、読み端が EOF になる。
    within(poll_fn(|cx| Pin::new(&mut *stdin).poll_shutdown(cx)))
        .await
        .expect("shutdown");
    drop(stdin);
    drop(session);
    drop(dup);
    let mut r = got.1;
    let n = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 1];
        r.read(&mut buf).expect("eof")
    })
    .await
    .expect("join");
    assert_eq!(n, 0);
    wait_active_zero(&b);
}

/// コンテナが stdin を読まず pipe が満杯でも、セッションの drop で入力スレッドが抜けて枠が返る（REPAIR-5）。
#[tokio::test]
async fn cri6_repair5_4077_stalled_stdin_write_is_reclaimed_on_drop() {
    let fx = Fixture::new("stall");
    let (r, w) = std::io::pipe().expect("pipe");
    let w = Mutex::new(Some(w));
    let source = FakeSource::new(Box::new(move |_| {
        let w = w.lock().expect("lock").take().expect("once");
        Ok(AttachIo {
            input: Some(AttachInput::Pipe(OwnedFd::from(w))),
            stdout: Some(sock_pair().0),
            stderr: None,
        })
    }));
    let b = fx.backend(source, idle_notifier(Arc::new(AtomicBool::new(false))));
    let mut session = within(b.attach(target(true, true, false, false)))
        .await
        .expect("attach");
    let mut stdin = session.stdin.take().expect("stdin");
    // 読まれない pipe（既定 64 KiB）と socketpair のバッファを十分に超える量を、書き込みが止まるまで送る。
    let chunk = vec![b'x'; 8192];
    for _ in 0..64 {
        let _ =
            tokio::time::timeout(Duration::from_millis(50), write_all(&mut *stdin, &chunk)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(stdin);
    drop(session);
    wait_active_zero(&b);
    drop(r);
}

/// stdout だけが閉じても `exited` は完了せず、残りの stderr も読める。両方閉じて初めて完了する（CRI-6・#4077）。
#[tokio::test]
async fn cri6_4077_one_sided_tap_eof_does_not_complete_exited() {
    let fx = Fixture::new("onesided");
    let (out_ours, out_theirs) = sock_pair();
    let (err_ours, mut err_theirs) = sock_pair();
    let taps = Mutex::new(Some((out_ours, err_ours)));
    let source = FakeSource::new(Box::new(move |_| {
        let (o, e) = taps.lock().expect("lock").take().expect("once");
        Ok(AttachIo {
            input: None,
            stdout: Some(o),
            stderr: Some(e),
        })
    }));
    let b = fx.backend(source, idle_notifier(Arc::new(AtomicBool::new(false))));
    let mut session = within(b.attach(target(false, true, true, false)))
        .await
        .expect("attach");
    let mut stdout = session.stdout.take().expect("stdout");
    let mut stderr = session.stderr.take().expect("stderr");
    drop(out_theirs);
    assert!(within(read_some(&mut *stdout)).await.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut session.exited)
            .await
            .is_err(),
        "exited completed on a one-sided EOF"
    );
    std::io::Write::write_all(&mut err_theirs, b"late-err").expect("write");
    assert_eq!(within(read_some(&mut *stderr)).await, b"late-err");
    drop(err_theirs);
    assert!(within(read_some(&mut *stderr)).await.is_empty());
    within(&mut session.exited).await;
}

/// 同じ pipe へ並行する複数セッションの書き込みが、調停の下でバイトを失わず完了する（REPAIR-5）。
#[tokio::test]
async fn cri6_repair5_4077_concurrent_writers_to_one_pipe_all_complete() {
    let fx = Fixture::new("arbiter");
    let (mut r, w) = std::io::pipe().expect("pipe");
    let w = Arc::new(Mutex::new(w));
    let source = FakeSource::new(Box::new(move |_| {
        let dup = w.lock().expect("lock").try_clone().expect("dup");
        Ok(AttachIo {
            input: Some(AttachInput::Pipe(OwnedFd::from(dup))),
            stdout: Some(sock_pair().0),
            stderr: None,
        })
    }));
    let b = fx.backend(source, idle_notifier(Arc::new(AtomicBool::new(false))));
    let mut sessions = Vec::new();
    for _ in 0..3 {
        sessions.push(
            within(b.attach(target(true, true, false, false)))
                .await
                .expect("attach"),
        );
    }
    let total = 3 * 20_000;
    let reader = tokio::task::spawn_blocking(move || {
        let mut got = 0usize;
        let mut buf = [0u8; 8192];
        while got < total {
            let n = r.read(&mut buf).expect("read");
            assert!(n > 0, "unexpected EOF");
            got += n;
        }
        got
    });
    let mut joins = Vec::new();
    for s in &mut sessions {
        let mut stdin = s.stdin.take().expect("stdin");
        joins.push(tokio::spawn(async move {
            let data = vec![b'y'; 20_000];
            write_all(&mut *stdin, &data).await;
            stdin
        }));
    }
    for j in joins {
        within(j).await.expect("join");
    }
    assert_eq!(within(reader).await.expect("join"), total);
}

#[tokio::test]
async fn cri6_4077_tap_is_relayed_and_eof_completes_exited() {
    let fx = Fixture::new("tap");
    let (tap_ours, mut tap_theirs) = sock_pair();
    let tap_ours = Mutex::new(Some(tap_ours));
    let source = FakeSource::new(Box::new(move |_| {
        Ok(AttachIo {
            input: None,
            stdout: Some(tap_ours.lock().expect("lock").take().expect("once")),
            stderr: None,
        })
    }));
    let b = fx.backend(source, idle_notifier(Arc::new(AtomicBool::new(false))));
    let mut session = within(b.attach(target(false, true, false, false)))
        .await
        .expect("attach");
    let mut stdout = session.stdout.take().expect("stdout");
    std::io::Write::write_all(&mut tap_theirs, b"out-bytes").expect("write");
    assert_eq!(within(read_some(&mut *stdout)).await, b"out-bytes");
    drop(tap_theirs);
    assert!(within(read_some(&mut *stdout)).await.is_empty());
    within(&mut session.exited).await;
}

#[tokio::test]
async fn cri6_4077_exit_notification_completes_exited_when_the_store_says_gone() {
    let fx = Fixture::new("woken");
    let notifier = Arc::new(FakeNotifier {
        f: Box::new(|_| ExitWatchOutcome::Woken),
    });
    let b = fx.backend(plain_source(), notifier);
    let mut session = within(b.attach(target(false, true, false, false)))
        .await
        .expect("attach");
    fx.stop("run1");
    within(&mut session.exited).await;
}

#[tokio::test]
async fn cri6_4077_spurious_wakeup_does_not_complete_exited_while_running() {
    let fx = Fixture::new("spurious");
    let notifier = Arc::new(FakeNotifier {
        f: Box::new(|_| ExitWatchOutcome::Woken),
    });
    let b = fx.backend(plain_source(), notifier);
    let mut session = within(b.attach(target(false, true, false, false)))
        .await
        .expect("attach");
    // 通知接続だけが切れた起床では、稼働中のコンテナの attach を終了扱いにしない。
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), &mut session.exited)
            .await
            .is_err()
    );
    fx.stop("run1");
    within(&mut session.exited).await;
}

#[tokio::test]
async fn cri6_repair5_4077_dropping_the_session_cancels_the_watcher_and_returns_the_slot() {
    let fx = Fixture::new("dropcancel");
    let seen = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(AtomicBool::new(false));
    let (seen2, entered2) = (Arc::clone(&seen), Arc::clone(&entered));
    let notifier = Arc::new(FakeNotifier {
        f: Box::new(move |cancel| {
            entered2.store(true, Ordering::SeqCst);
            loop {
                if cancel() {
                    seen2.store(true, Ordering::SeqCst);
                    return ExitWatchOutcome::Cancelled;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }),
    });
    let b = fx.backend(plain_source(), notifier);
    let session = within(b.attach(target(false, true, false, false)))
        .await
        .expect("attach");
    assert_eq!(b.active_sessions(), 1);
    // 監視スレッドが購読に入ってから drop する（入る前の取り消しは購読を呼ばずに抜ける）。
    let end = Instant::now() + WAIT;
    while !entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < end, "watcher did not start");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    drop(session);
    wait_active_zero(&b);
    assert!(seen.load(Ordering::SeqCst));
}

#[tokio::test]
async fn cri6_4077_transient_and_no_supervisor_fall_back_to_the_state_store() {
    for outcome in [ExitWatchOutcome::Transient, ExitWatchOutcome::NoSupervisor] {
        let fx = Fixture::new("fallback");
        let notifier = Arc::new(FakeNotifier {
            f: Box::new(move |_| outcome),
        });
        let b = fx.backend(plain_source(), notifier);
        let mut session = within(b.attach(target(false, true, false, false)))
            .await
            .expect("attach");
        fx.stop("run1");
        within(&mut session.exited).await;
    }
}

// ---- 同時数 ----

#[tokio::test]
async fn cri6_repair5_4077_concurrent_sessions_are_bounded() {
    let fx = Fixture::new("limit");
    let b = fx.backend(
        plain_source(),
        idle_notifier(Arc::new(AtomicBool::new(false))),
    );
    let mut held = Vec::new();
    for _ in 0..MAX_ATTACH_SESSIONS {
        held.push(
            within(b.attach(target(false, true, false, false)))
                .await
                .expect("attach"),
        );
    }
    let e = within(b.attach(target(false, true, false, false)))
        .await
        .expect_err("limit");
    assert_eq!(
        (e.code(), e.message()),
        (CriErrorCode::ResourceExhausted, "too many attach sessions")
    );
    held.pop();
    let end = Instant::now() + WAIT;
    loop {
        if within(b.attach(target(false, true, false, false)))
            .await
            .is_ok()
        {
            break;
        }
        assert!(Instant::now() < end, "slot was not returned");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
