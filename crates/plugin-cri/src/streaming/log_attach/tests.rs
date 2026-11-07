//! `log_attach` の試験（CRI-6・SUP-4・REPAIR-3・REPAIR-5・#3763）。root も外部プロセスも使わず、一時ディレクトリの
//! 回転ログと偽の probe だけで動く。

use std::future::poll_fn;

use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_supervisor::logs::{LogSink as _, RotatingFileSink, StreamKind};

use super::test_support::{FakeProbe, TempDir, fast_follow};
use super::*;

const WAIT: Duration = Duration::from_secs(5);

fn target(stdin: bool, stdout: bool, stderr: bool, tty: bool) -> AttachTarget {
    AttachTarget {
        container_id: "c1".to_string(),
        stdin,
        stdout,
        stderr,
        tty,
    }
}

fn backend(dir: &TempDir, probe: Arc<FakeProbe>, deadline: Duration) -> LogFollowAttachBackend {
    LogFollowAttachBackend::new(dir.0.clone(), probe)
        .expect("backend")
        .with_follow_options(fast_follow(deadline))
}

fn open_sink(dir: &TempDir) -> RotatingFileSink {
    RotatingFileSink::open(
        &dir.0,
        &ContainerId::new("c1").expect("id"),
        container_log_rotation_config(),
    )
    .expect("sink")
}

type Reader = Box<dyn AsyncRead + Send + Unpin>;

/// 読み口から EOF（`Ok(0)`）または失敗までを読み切る。
async fn read_to_end(r: &mut Reader) -> (Vec<u8>, io::Result<()>) {
    let mut out = Vec::new();
    loop {
        let mut chunk = [0u8; 256];
        let mut rb = ReadBuf::new(&mut chunk);
        let res = tokio::time::timeout(
            WAIT,
            poll_fn(|cx| Pin::new(&mut **r).poll_read(cx, &mut rb)),
        )
        .await
        .expect("read within deadline");
        match res {
            Ok(()) if rb.filled().is_empty() => return (out, Ok(())),
            Ok(()) => out.extend_from_slice(rb.filled()),
            Err(e) => return (out, Err(e)),
        }
    }
}

/// 少なくとも `min` バイトが届くまで読む。
async fn read_at_least(r: &mut Reader, min: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while out.len() < min {
        let mut chunk = [0u8; 256];
        let mut rb = ReadBuf::new(&mut chunk);
        tokio::time::timeout(
            WAIT,
            poll_fn(|cx| Pin::new(&mut **r).poll_read(cx, &mut rb)),
        )
        .await
        .expect("read within deadline")
        .expect("read");
        assert!(!rb.filled().is_empty(), "unexpected EOF");
        out.extend_from_slice(rb.filled());
    }
    out
}

async fn wait_followers(b: &LogFollowAttachBackend, n: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while b.active_followers() != n {
        assert!(
            tokio::time::Instant::now() < deadline,
            "followers={} want={n}",
            b.active_followers()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// CRI-6・SUP-4・#3763: 回転ログに書いた行がタグを外して stdout / stderr の読み口へ届く。attach 前の行は出ない（tail 0）。
#[tokio::test]
async fn cri6_3763_attach_streams_log_records() {
    let dir = TempDir::new("stream");
    let sink = Arc::new(open_sink(&dir));
    sink.append(StreamKind::Stdout, b"old").expect("old");
    sink.flush().expect("flush");
    let b = backend(&dir, FakeProbe::running(), Duration::from_secs(30));
    let mut session = b
        .attach(target(false, true, true, false))
        .await
        .expect("attach");
    // attach が返った時点で追従開始位置は確定済みなので、一度だけ書けば取りこぼさない（決定的。#3763）。
    sink.append(StreamKind::Stdout, b"hello").expect("out");
    sink.append(StreamKind::Stderr, b"oops").expect("err");
    sink.flush().expect("flush");
    let mut out_r = session.stdout.take().expect("stdout");
    let mut err_r = session.stderr.take().expect("stderr");
    let out = read_at_least(&mut out_r, 6).await;
    let err = read_at_least(&mut err_r, 5).await;
    assert!(out.starts_with(b"hello\n"), "{out:?}");
    assert_eq!(out, b"hello\n");
    assert!(err.starts_with(b"oops\n"), "{err:?}");
    assert!(session.stdin.is_none() && session.resize.is_none());
    drop((out_r, err_r, session));
    wait_followers(&b, 0).await;
}

/// CRI-6・REPAIR-3・#3763: stdout だけの要求では stderr の読み口が無い。
#[tokio::test]
async fn cri6_3763_attach_stdout_only_has_no_stderr_reader() {
    let dir = TempDir::new("stdout-only");
    let _sink = open_sink(&dir);
    let b = backend(&dir, FakeProbe::running(), Duration::from_secs(30));
    let session = b
        .attach(target(false, true, false, false))
        .await
        .expect("attach");
    assert!(session.stdout.is_some());
    assert!(session.stderr.is_none());
}

/// CRI-6・REPAIR-3・#3763: stdin・tty は `INVALID_ARGUMENT` で、follower を作らない。
#[tokio::test]
async fn cri6_repair3_3763_attach_rejects_stdin_and_tty() {
    let dir = TempDir::new("reject");
    let b = backend(&dir, FakeProbe::running(), Duration::from_secs(30));
    for t in [
        target(true, true, true, false),
        target(false, true, false, true),
    ] {
        let e = b.attach(t).await.expect_err("refused");
        assert_eq!(e.code(), CriErrorCode::InvalidArgument);
        assert_eq!(e.message(), MSG_ATTACH_INTERACTIVE_UNSUPPORTED);
    }
    assert_eq!(b.active_followers(), 0);
}

/// CRI-6・#3763: 不在は `NOT_FOUND`、Running でなければ `FAILED_PRECONDITION`。
#[tokio::test]
async fn cri6_3763_attach_precheck_maps_state() {
    let dir = TempDir::new("precheck");
    let probe = FakeProbe::running();
    let b = backend(&dir, Arc::clone(&probe), Duration::from_secs(30));
    probe.0.store(2, Ordering::SeqCst);
    let e = b
        .attach(target(false, true, false, false))
        .await
        .expect_err("absent");
    assert_eq!(e.code(), CriErrorCode::NotFound);
    probe.0.store(1, Ordering::SeqCst);
    let e = b
        .attach(target(false, true, false, false))
        .await
        .expect_err("stopped");
    assert_eq!(e.code(), CriErrorCode::FailedPrecondition);
    assert_eq!(b.active_followers(), 0);
}

/// REPAIR-5・CRI-6・#3763: コンテナの終了（sink の解放と状態の非 Running）で `exited` が完了し、読み口が EOF になる。
#[tokio::test]
async fn repair5_3763_attach_closes_on_container_exit() {
    let dir = TempDir::new("exit");
    let sink = open_sink(&dir);
    let probe = FakeProbe::running();
    let b = backend(&dir, Arc::clone(&probe), Duration::from_secs(30));
    let mut session = b
        .attach(target(false, true, true, false))
        .await
        .expect("attach");
    tokio::time::sleep(Duration::from_millis(100)).await;
    probe.0.store(1, Ordering::SeqCst);
    drop(sink);
    tokio::time::timeout(WAIT, &mut session.exited)
        .await
        .expect("exited within deadline");
    let mut out_r = session.stdout.take().expect("stdout");
    let mut err_r = session.stderr.take().expect("stderr");
    let (_, r) = read_to_end(&mut out_r).await;
    r.expect("stdout EOF is clean");
    let (_, r) = read_to_end(&mut err_r).await;
    r.expect("stderr EOF is clean");
    drop((out_r, err_r, session));
    wait_followers(&b, 0).await;
}

/// REPAIR-5・#3763: セッションを drop すると取り消しの旗で follower が抜ける（稼働中のままでも）。
#[tokio::test]
async fn repair5_3763_attach_drop_cancels_follower() {
    let dir = TempDir::new("cancel");
    let _sink = open_sink(&dir);
    let b = backend(&dir, FakeProbe::running(), Duration::from_secs(30));
    let session = b
        .attach(target(false, true, true, false))
        .await
        .expect("attach");
    wait_followers(&b, 1).await;
    drop(session);
    wait_followers(&b, 0).await;
}

/// REPAIR-5・REPAIR-3・#3763: 期限切れは EOF の後に読み口が失敗し（成功を装わない）、`exited` は完了する。
#[tokio::test]
async fn repair5_3763_attach_deadline_is_reported_as_failure() {
    let dir = TempDir::new("deadline");
    let _sink = open_sink(&dir);
    let b = backend(&dir, FakeProbe::running(), Duration::from_millis(100));
    let mut session = b
        .attach(target(false, true, false, false))
        .await
        .expect("attach");
    tokio::time::timeout(WAIT, &mut session.exited)
        .await
        .expect("exited within deadline");
    let mut out_r = session.stdout.take().expect("stdout");
    let (bytes, r) = read_to_end(&mut out_r).await;
    assert!(bytes.is_empty());
    assert!(r.is_err(), "deadline must not look like a clean EOF");
}

/// REPAIR-5・#3763: 同時 follow 数の上限を超えたら `RESOURCE_EXHAUSTED`。
#[tokio::test]
async fn repair5_3763_attach_limits_concurrent_followers() {
    let dir = TempDir::new("limit");
    let _sink = open_sink(&dir);
    let b = backend(&dir, FakeProbe::running(), Duration::from_secs(30));
    let mut sessions = Vec::new();
    for _ in 0..MAX_ATTACH_FOLLOWERS {
        sessions.push(
            b.attach(target(false, true, false, false))
                .await
                .expect("attach"),
        );
    }
    let e = b
        .attach(target(false, true, false, false))
        .await
        .expect_err("over limit");
    assert_eq!(e.code(), CriErrorCode::ResourceExhausted);
    drop(sessions);
    wait_followers(&b, 0).await;
}

/// REPAIR-5・#3763: 書き込みが詰まったままでも、追従の絶対期限を過ぎたら再試行を打ち切る（`TimedOut`）。
#[test]
fn repair5_3763_writer_stops_at_absolute_deadline() {
    let (a, _b) = StdUnixStream::pair().expect("pair");
    a.set_write_timeout(Some(Duration::from_millis(10)))
        .expect("timeout");
    let mut w = CancellableWriter {
        sock: a,
        cancel: Arc::new(AtomicBool::new(false)),
        deadline: Instant::now() + Duration::from_millis(100),
    };
    // 読み手が読まないので、バッファが満杯になった後の書き込みは詰まる。
    let chunk = [0u8; 8192];
    let started = Instant::now();
    let err = loop {
        if let Err(e) = w.write(&chunk) {
            break e;
        }
        assert!(started.elapsed() < WAIT, "writer never stopped");
    };
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
}
