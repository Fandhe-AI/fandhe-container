//! 完全版 `SupervisorAttachBackend` の境界越しの結合試験（CRI-6・SEC-1・REPAIR-5・REPAIR-10・REPAIR-12・#4077）。
//!
//! 公開 API（`streaming::supervisor_attach` と cri の `AttachBackend` / `AttachSession`）だけを通し、
//! 実の `FileStateStore`・実の pipe / socketpair / fd（`AttachIoSource` の注入は supervisor 側クライアントの代役）で
//! stdin の往復・tap の中継・片側 EOF・形が違う fd の拒否・drop での枠の返却を具体値で照合する。root・実コンテナ・
//! 特権は不要で既定のテスト集合で走る。実コンテナでの通しは #4079。待ちはすべて期限つき。

#![cfg(target_os = "linux")]

#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

use std::future::poll_fn;
use std::io::{Read as _, Write as _};
use std::num::NonZeroU32;
use std::os::fd::OwnedFd;
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerStatus, CreateStateRequest, ErrorCode, StateStore as _, TraitError,
    UpdateStateRequest,
};
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::streaming::attach::{AttachBackend, AttachTarget};
use fandhe_container_plugin_cri::streaming::supervisor_attach::SupervisorAttachBackend;
use fandhe_container_supervisor::control::{
    AttachInput, AttachIo, AttachIoRequest, AttachIoSource, ExitNotifier, ExitWatchOutcome,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const WAIT: Duration = Duration::from_secs(10);

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Source(Mutex<Option<AttachIo>>);

impl AttachIoSource for Source {
    fn obtain(
        &self,
        _id: &ContainerId,
        _pid: NonZeroU32,
        _request: AttachIoRequest,
        _deadline: Instant,
    ) -> Result<AttachIo, TraitError> {
        self.0
            .lock()
            .expect("lock")
            .take()
            .ok_or_else(|| TraitError::new(ErrorCode::Internal, "exhausted"))
    }
}

struct IdleNotifier;

impl ExitNotifier for IdleNotifier {
    fn watch(
        &self,
        _id: &ContainerId,
        _pid: NonZeroU32,
        _until: Instant,
        cancel: &dyn Fn() -> bool,
    ) -> ExitWatchOutcome {
        loop {
            if cancel() {
                return ExitWatchOutcome::Cancelled;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn backend(tag: &str, io: AttachIo) -> (TempDir, SupervisorAttachBackend) {
    let dir = TempDir(exclusive_dir::create(&format!("fcsa-{tag}")).expect("temp dir"));
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
    let id = ContainerId::new("run1").expect("id");
    let created = store
        .create(
            &CreateStateRequest::new(ContainerStatus::created(id.clone(), None), bundle)
                .expect("req"),
        )
        .expect("create");
    store
        .update(&UpdateStateRequest::new(
            ContainerStatus::running(id, NonZeroU32::new(4242)),
            created.revision(),
        ))
        .expect("running");
    let b = SupervisorAttachBackend::new(
        store,
        Arc::new(Source(Mutex::new(Some(io)))),
        Arc::new(IdleNotifier),
    );
    (dir, b)
}

fn target(stdin: bool, stdout: bool, stderr: bool) -> AttachTarget {
    AttachTarget {
        container_id: "run1".to_string(),
        stdin,
        stdout,
        stderr,
        tty: false,
    }
}

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
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

fn wait_slots_zero(b: &SupervisorAttachBackend) {
    let end = Instant::now() + WAIT;
    while b.active_sessions() != 0 {
        assert!(Instant::now() < end, "slots were not returned");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// stdin の往復・stdout / stderr の中継・片側 EOF では終えず両側 EOF で `exited`・drop で枠を返す。
#[tokio::test]
async fn cri6_4077_boundary_stdin_roundtrip_taps_and_exit() {
    let (mut pr, pw) = std::io::pipe().expect("pipe");
    let (out_ours, mut out_theirs) = UnixStream::pair().expect("pair");
    let (err_ours, mut err_theirs) = UnixStream::pair().expect("pair");
    let (_dir, b) = backend(
        "rt",
        AttachIo {
            input: Some(AttachInput::Pipe(OwnedFd::from(pw))),
            stdout: Some(out_ours),
            stderr: Some(err_ours),
        },
    );
    let mut s = within(b.attach(target(true, true, true)))
        .await
        .expect("attach");
    assert_eq!(b.active_sessions(), 1);
    assert!(s.resize.is_none());

    let mut stdin = s.stdin.take().expect("stdin");
    within(write_all(&mut *stdin, b"ping\n")).await;
    let got = tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 5];
        pr.read_exact(&mut buf).expect("read");
        buf
    })
    .await
    .expect("join");
    assert_eq!(&got, b"ping\n");

    let mut stdout = s.stdout.take().expect("stdout");
    let mut stderr = s.stderr.take().expect("stderr");
    out_theirs.write_all(b"OUT").expect("w");
    err_theirs.write_all(b"ERR").expect("w");
    assert_eq!(within(read_some(&mut *stdout)).await, b"OUT");
    assert_eq!(within(read_some(&mut *stderr)).await, b"ERR");

    drop(out_theirs);
    assert!(within(read_some(&mut *stdout)).await.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut s.exited)
            .await
            .is_err(),
        "exited completed on a one-sided EOF"
    );
    drop(err_theirs);
    assert!(within(read_some(&mut *stderr)).await.is_empty());
    within(&mut s.exited).await;

    drop(stdin);
    drop(stdout);
    drop(stderr);
    drop(s);
    wait_slots_zero(&b);
}

/// 要求していない入力は固定文言の INTERNAL で拒否する（SEC-1）。
#[tokio::test]
async fn cri6_sec1_4077_boundary_invalid_io_is_rejected() {
    let (_pr, pw) = std::io::pipe().expect("pipe");
    let (_dir, b) = backend(
        "bad",
        AttachIo {
            input: Some(AttachInput::Pipe(OwnedFd::from(pw))),
            stdout: Some(UnixStream::pair().expect("pair").0),
            stderr: None,
        },
    );
    let e = within(b.attach(target(false, true, false)))
        .await
        .expect_err("must be rejected");
    assert_eq!(e.code(), CriErrorCode::Internal);
    assert_eq!(e.message(), "attach io is invalid");
    wait_slots_zero(&b);
}

/// 読まれない stdin に書き続けていても、セッションの drop で入力スレッドが抜けて枠が返る（REPAIR-5）。
#[tokio::test]
async fn cri6_repair5_4077_boundary_stalled_stdin_is_reclaimed() {
    let (_pr, pw) = std::io::pipe().expect("pipe");
    let (_dir, b) = backend(
        "stall",
        AttachIo {
            input: Some(AttachInput::Pipe(OwnedFd::from(pw))),
            stdout: Some(UnixStream::pair().expect("pair").0),
            stderr: None,
        },
    );
    let mut s = within(b.attach(target(true, true, false)))
        .await
        .expect("attach");
    let mut stdin = s.stdin.take().expect("stdin");
    let chunk = vec![b'x'; 8192];
    for _ in 0..64 {
        let _ =
            tokio::time::timeout(Duration::from_millis(50), write_all(&mut *stdin, &chunk)).await;
    }
    drop(stdin);
    drop(s);
    wait_slots_zero(&b);
}
