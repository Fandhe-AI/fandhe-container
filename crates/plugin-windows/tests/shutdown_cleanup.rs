//! SIGTERM（停止フラグ）時に保持中の共有マウントを解除する契約の結合試験（TASK-116.5・#396。WIN-1・WIN-2・REPAIR-12）。
//!
//! 生成バイナリは unix では実バックエンドの create が `UNIMPLEMENTED` でマウントを保持できないため、
//! バイナリ入口と同じ `serve_session`（serve → shutdown 行 → `release_all` → cleanup 行）を、
//! 実 UDS 上で偽バックエンドと組み合わせて駆動する。SIGTERM は `sys::install_sigterm_flag` が立てる
//! 停止フラグと同じ `AtomicBool` を立てて模擬する（バイナリへの実 SIGTERM は `frame_loop.rs` の試験が担う）。
//! 待ちはすべて期限つき（REPAIR-5）。実行環境は unix のみ。
#![cfg(unix)]

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_platform_windows::error::{WinError, WinErrorCode};
use fandhe_container_platform_windows::wsl2::{DistroName, LaunchRequest, SharedTransport};
use fandhe_container_plugin::{
    ControlMessage, JsonLinesPeerAuthObserver, MessageId, RpcTimeout, UdsListener, UdsStream,
    decode_message, encode_message,
};
use fandhe_container_plugin_windows::adapter::{
    BackendFailure, GuestStart, LaunchOutcome, SessionOutcome, WindowsBackend,
    WindowsRuntimeAdapter, serve_session,
};
use fandhe_container_plugin_windows::frame_loop::LoopExit;

struct FakePrepared;

/// 呼び出し記録つきの偽バックエンド。`fail_release` が真なら解除は失敗し、所有情報を返さない。
struct FakeBackend {
    calls: Arc<Mutex<Vec<String>>>,
    fail_release: bool,
}

impl WindowsBackend for FakeBackend {
    type Prepared = FakePrepared;

    fn check_distro(&self, _d: &DistroName, _budget: Duration) -> Result<(), WinError> {
        Ok(())
    }

    fn launch(
        &self,
        req: &LaunchRequest,
        guest: &dyn GuestStart<FakePrepared>,
        _budget: Duration,
        _cancel: &dyn Fn() -> bool,
    ) -> Result<LaunchOutcome<FakePrepared>, BackendFailure<FakePrepared>> {
        self.calls
            .lock()
            .expect("lock")
            .push(format!("launch:{}", req.distro().as_str()));
        guest.start(&FakePrepared)?;
        Ok(LaunchOutcome {
            prepared: FakePrepared,
            transport: Some(SharedTransport::Virtiofs),
            warning: None,
        })
    }

    fn release(
        &self,
        _p: &FakePrepared,
        _budget: Duration,
    ) -> Result<(), BackendFailure<FakePrepared>> {
        self.calls.lock().expect("lock").push("release".to_string());
        if self.fail_release {
            return Err(BackendFailure {
                error: WinError::new(WinErrorCode::Timeout, "fake release timeout"),
                unreleased: None,
                warning: None,
            });
        }
        Ok(())
    }
}

struct OkGuest;

impl GuestStart<FakePrepared> for OkGuest {
    fn start(&self, _p: &FakePrepared) -> Result<(), WinError> {
        Ok(())
    }
}

fn create_unique_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    for n in 0..100u32 {
        let p = PathBuf::from("/tmp").join(format!("fc-pws-{}-{nanos:x}-{n}", std::process::id()));
        match std::fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return p,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create test dir: {e}"),
        }
    }
    panic!("could not create a unique test dir");
}

fn call(stream: &mut UdsStream, id: u64, body: &[&str]) -> Vec<String> {
    let f = encode_message(&ControlMessage::Request {
        id: MessageId::new(id),
        body: body.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
    })
    .expect("encode");
    stream
        .write_frame(&f, RpcTimeout::default())
        .expect("write");
    let r = stream.read_frame(RpcTimeout::default()).expect("read");
    match decode_message::<Vec<String>>(&r).expect("decode") {
        ControlMessage::Response { id: got, body } => {
            assert_eq!(got.get(), id);
            body
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// create → start でマウントを 1 件保持させ、停止フラグを立てて `serve_session` の結果と呼び出し記録を返す。
fn run_sigterm_with_held_mount(fail_release: bool) -> (SessionOutcome, Vec<String>) {
    let dir = create_unique_dir();
    let sock = dir.join("p.sock");
    let listener = UdsListener::bind(&sock).expect("bind");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));

    let worker = {
        let calls = Arc::clone(&calls);
        let stop = Arc::clone(&stop);
        let sock = sock.clone();
        std::thread::spawn(move || {
            let mut obs = JsonLinesPeerAuthObserver::new();
            let mut stream =
                UdsStream::connect(&sock, Duration::from_secs(5), &mut obs).expect("connect");
            let backend = FakeBackend {
                calls,
                fail_release,
            };
            let mut adapter = WindowsRuntimeAdapter::new(backend, OkGuest);
            serve_session(&mut stream, &mut adapter, &stop)
        })
    };

    let mut obs = JsonLinesPeerAuthObserver::new();
    let mut stream = listener
        .accept(Duration::from_secs(20), &mut obs)
        .expect("accept");
    let create = [
        "create",
        "c1",
        "Ubuntu",
        "prefer-virtiofs",
        "d",
        "C:\\data\\app",
        "ro",
    ];
    assert_eq!(call(&mut stream, 1, &create), vec!["created", "", ""]);
    assert_eq!(
        call(&mut stream, 2, &["start", "c1"]),
        vec!["running", "virtiofs", ""]
    );
    // SIGTERM 相当。接続は開いたまま（相手の切断ではなく停止要求で抜けることを確かめる）。
    stop.store(true, Ordering::SeqCst);

    let start = std::time::Instant::now();
    while !worker.is_finished() {
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "serve_session did not return within deadline"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let outcome = worker.join().expect("worker panicked");
    drop(stream);
    let _ = std::fs::remove_dir_all(&dir); // 排他作成した自前のディレクトリのみ
    let recorded = calls.lock().expect("lock").clone();
    (outcome, recorded)
}

#[test]
fn task116_5_win2_sigterm_releases_held_shared_mount() {
    let (outcome, calls) = run_sigterm_with_held_mount(false);
    assert!(
        matches!(outcome.result, Ok(LoopExit::ShutdownRequested)),
        "{:?}",
        outcome.result
    );
    assert_eq!(outcome.cleanup.released, 1);
    assert_eq!(outcome.cleanup.remaining, 0);
    assert_eq!(calls, vec!["launch:Ubuntu", "release"]);
}

#[test]
fn task116_5_win2_sigterm_reports_remaining_when_release_fails() {
    let (outcome, calls) = run_sigterm_with_held_mount(true);
    assert!(
        matches!(outcome.result, Ok(LoopExit::ShutdownRequested)),
        "{:?}",
        outcome.result
    );
    assert_eq!(outcome.cleanup.released, 0);
    assert_eq!(outcome.cleanup.remaining, 1);
    // 失敗した解除は release_all 内で再試行しない（1 回のみ。Drop も explicit 後は再試行しない）。
    assert_eq!(calls, vec!["launch:Ubuntu", "release"]);
}
