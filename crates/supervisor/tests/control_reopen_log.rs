//! 制御チャネルの CRI ログの開き直し（ReopenLogRequest。kind 10）の結合試験
//! （CRI-2・SUP-7・REPAIR-4・REPAIR-5・REPAIR-12・#4652）。
//!
//! 実際の UDS の上で、`ControlReopenLog`（クライアント入口）→ `ControlServer` → `SignalSlot` → `CaptureHub` →
//! `TeeLogSink` → `CriFileSink` を通し、kubelet と同じ手順（rename → 開き直し）で新しいファイルへ追記が再開することを
//! 具体値で照合する。root・実コンテナは不要で既定のテスト集合で動く。

#![cfg(target_os = "linux")]

use std::io::{Read as _, Write as _};
use std::num::NonZeroU32;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{ContainerId, ContainerLogPath, ErrorCode, TraitError};
use fandhe_container_supervisor::control::ControlReopenLog;
use fandhe_container_supervisor::control::listener::{ControlListener, effective_uid};
use fandhe_container_supervisor::control::observe::ControlObserver;
use fandhe_container_supervisor::control::protocol::{
    CancelRestartRequestFrame, ControlReason, HEADER_LEN, REOPEN_LOG_REQUEST_LEN, RESPONSE_LEN,
    ReopenLogRequestFrame, ResponseFrame, SignalDeadline, encode_hello,
};
use fandhe_container_supervisor::control::server::{ControlServer, ServeConfig};
use fandhe_container_supervisor::control::target::{ControlledProcess, SignalSlot};
use fandhe_container_supervisor::log_pipeline::CaptureHub;
use fandhe_container_supervisor::logs::cri::{CriFileSink, TeeLogSink};
use fandhe_container_supervisor::logs::{
    LogSink, MemoryLogSink, ReopenGate, RetiredWriter, StreamKind,
};

struct Fake;

impl LaunchedProcess for Fake {
    fn pid(&self) -> NonZeroU32 {
        NonZeroU32::new(4321).unwrap()
    }
    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        std::thread::sleep(timeout.min(Duration::from_millis(5)));
        Ok(None)
    }
    fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    /// 0750 で排他的に作る（CRI ログの親ディレクトリ検査を通すため group 書き込みなし）。
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::DirBuilderExt as _;
        for attempt in 0..64u32 {
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir().join(format!(
                "fc-rol-it-{tag}-{}-{n}-{attempt}",
                std::process::id()
            ));
            match std::fs::DirBuilder::new().mode(0o750).create(&p) {
                Ok(()) => return Self(std::fs::canonicalize(&p).unwrap()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create temp root: {e}"),
            }
        }
        panic!("could not create a unique temp root");
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Rig {
    root: TempRoot,
    id: ContainerId,
    log: PathBuf,
    rotated: PathBuf,
    sink: Arc<dyn LogSink>,
    process: Option<ControlledProcess>,
    _server: ControlServer,
    _listener: ControlListener,
}

impl Rig {
    /// `cri`: CRI ログ付き（Tee）か。`running`: 稼働中のハンドルを持たせるか。
    fn start(tag: &str, cri: bool, running: bool) -> Self {
        Self::start_with(tag, cri, running, None)
    }

    /// `custom`: 指定すると CRI ログの代わりにこの sink を使う（止まる sink の注入用）。
    fn start_with(tag: &str, cri: bool, running: bool, custom: Option<Arc<dyn LogSink>>) -> Self {
        use std::os::unix::fs::DirBuilderExt as _;
        let root = TempRoot::new(tag);
        let state = root.0.join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .unwrap();
        let id = ContainerId::new(tag).unwrap();
        let dir = state.join(id.as_str());
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let listener = ControlListener::bind(&state, &id).unwrap();

        let logs = root.0.join("logs");
        std::fs::DirBuilder::new()
            .mode(0o750)
            .create(&logs)
            .unwrap();
        let log = logs.join("0.log");
        let rotated = logs.join("0.log.1");
        let sink: Arc<dyn LogSink> = if let Some(c) = custom {
            c
        } else if cri {
            let path = ContainerLogPath::new(log.to_str().unwrap().to_owned()).unwrap();
            Arc::new(TeeLogSink::new(
                Arc::new(MemoryLogSink::default()),
                Arc::new(CriFileSink::open(&path).unwrap()),
            ))
        } else {
            Arc::new(MemoryLogSink::default())
        };
        let hub = Arc::new(CaptureHub::new(Arc::clone(&sink)));
        let slot = SignalSlot::new().with_output_capture(Some(Arc::clone(&hub)));
        let process = running.then(|| ControlledProcess::new(Box::new(Fake), slot.clone()));
        let server = ControlServer::spawn(
            listener.try_clone_listener().unwrap(),
            slot,
            effective_uid().unwrap(),
            ServeConfig::default(),
            Arc::new(ControlObserver::new(None, None)),
        )
        .unwrap();
        Self {
            root,
            id,
            log,
            rotated,
            sink,
            process,
            _server: server,
            _listener: listener,
        }
    }

    fn state(&self) -> PathBuf {
        self.root.0.join("state")
    }

    fn reopen(&self) -> Result<(), TraitError> {
        ControlReopenLog::new(self.state())
            .reopen(&self.id, Instant::now() + Duration::from_secs(5))
    }
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap()
}

/// 行（`<ts> stdout F <text>`）の本文だけを並べる。
fn texts(p: &Path) -> Vec<String> {
    read(p)
        .lines()
        .map(|l| l.splitn(4, ' ').nth(3).unwrap().to_owned())
        .collect()
}

/// CRI-2・SUP-7・#4652: 稼働中のコンテナは rename の後の開き直しで新しいファイルへ追記が再開し、旧ファイルは変わらない。
#[test]
fn cri2_sup7_4652_running_reopen_resumes_on_new_file() {
    let rig = Rig::start("run", true, true);
    rig.sink.append(StreamKind::Stdout, b"before").unwrap();
    rig.sink.flush().unwrap();
    std::fs::rename(&rig.log, &rig.rotated).unwrap();
    assert!(!rig.log.exists());
    rig.reopen().unwrap();
    rig.sink.append(StreamKind::Stdout, b"after").unwrap();
    rig.sink.flush().unwrap();
    assert_eq!(texts(&rig.rotated), vec!["before"]);
    assert_eq!(texts(&rig.log), vec!["after"]);
}

/// CRI-2・#4652: 稼働中でない（ハンドル無し・終了後）は `FailedPrecondition`: `container is not running` で、
/// 新しいファイルを作らない。
#[test]
fn cri2_4652_not_running_is_refused_and_creates_no_file() {
    let rig = Rig::start("idle", true, false);
    std::fs::rename(&rig.log, &rig.rotated).unwrap();
    let e = rig.reopen().unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "container is not running");
    assert!(!rig.log.exists());

    // 稼働中だったハンドルを落とした後も同じ。
    let mut rig = Rig::start("gone", true, true);
    rig.process.take();
    std::fs::rename(&rig.log, &rig.rotated).unwrap();
    let e = rig.reopen().unwrap_err();
    assert_eq!(e.message(), "container is not running");
    assert!(!rig.log.exists());
}

/// CRI-2・#4652: CRI ログのパスが無い構成は `FailedPrecondition`: `the container has no CRI log path`。
#[test]
fn cri2_4652_no_cri_log_path_is_failed_precondition() {
    let rig = Rig::start("nocri", false, true);
    let e = rig.reopen().unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "the container has no CRI log path");
}

/// CRI-2・#4652: 開けない（親が消えた）ときは `FailedPrecondition`: `the cri log file cannot be reopened`。
/// 既存の書き込み先（rename 済みの旧ファイル）は変わらず追記でき、新しいファイルは作られない。
#[test]
fn cri2_4652_failed_reopen_keeps_old_writer_and_creates_nothing() {
    let rig = Rig::start("fail", true, true);
    let sink = &rig.sink;
    sink.append(StreamKind::Stdout, b"one").unwrap();
    sink.flush().unwrap();
    let logs = rig.log.parent().unwrap().to_owned();
    let moved = rig.root.0.join("logs-moved");
    std::fs::rename(&logs, &moved).unwrap();
    let e = rig.reopen().unwrap_err();
    assert_eq!(e.code(), ErrorCode::FailedPrecondition);
    assert_eq!(e.message(), "the cri log file cannot be reopened");
    assert!(!logs.exists());
    sink.append(StreamKind::Stdout, b"two").unwrap();
    sink.flush().unwrap();
    assert_eq!(texts(&moved.join("0.log")), vec!["one", "two"]);
}

/// REPAIR-5・SUP-7・#4652: 古い supervisor が kind 10 に返す `Malformed`（と `TooLarge`・`UnsupportedVersion`）を
/// クライアントは `Unavailable` として扱う。
#[test]
fn sup7_4652_old_supervisor_malformed_is_unavailable() {
    use std::os::unix::fs::DirBuilderExt as _;
    for (i, reason) in [
        ControlReason::Malformed,
        ControlReason::TooLarge,
        ControlReason::UnsupportedVersion,
    ]
    .into_iter()
    .enumerate()
    {
        let root = TempRoot::new(&format!("old{i}"));
        let tag = format!("old{i}");
        let state = root.0.join("state");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(state.join(&tag))
            .unwrap();
        let id = ContainerId::new(&tag).unwrap();
        let listener = ControlListener::bind(&state, &id).unwrap();
        let l = listener.try_clone_listener().unwrap();
        l.set_nonblocking(false).unwrap();
        let handle = std::thread::spawn(move || {
            let _keep = listener;
            let (mut s, _) = l.accept().unwrap();
            s.write_all(&encode_hello()).unwrap();
            let mut req = [0u8; REOPEN_LOG_REQUEST_LEN];
            s.read_exact(&mut req).unwrap();
            // 要求は kind 10・payload 8 で届いている。
            assert_eq!(
                req.get(..HEADER_LEN),
                Some(&[b'F', b'C', b'S', b'C', 1, 10, 0, 8][..])
            );
            s.write_all(&ResponseFrame { reason }.encode()).unwrap();
        });
        let e = ControlReopenLog::new(state)
            .reopen(&id, Instant::now() + Duration::from_secs(5))
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::Unavailable, "{reason:?}");
        assert_eq!(e.message(), "the supervisor control channel is unavailable");
        handle.join().unwrap();
    }
}

/// REPAIR-5・#4652: supervisor 不在（ソケット無し）は `Unavailable`。
#[test]
fn sup7_4652_no_supervisor_is_unavailable() {
    use std::os::unix::fs::DirBuilderExt as _;
    let root = TempRoot::new("nosup");
    let state = root.0.join("state");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(state.join("nosup"))
        .unwrap();
    let id = ContainerId::new("nosup").unwrap();
    let e = ControlReopenLog::new(state)
        .reopen(&id, Instant::now() + Duration::from_secs(2))
        .unwrap_err();
    assert_eq!(e.code(), ErrorCode::Unavailable);
}

/// 生の接続で kind 10 を送り、理由コードを読む（期限切れ・応答の形の照合用）。
#[test]
fn repair5_4652_raw_request_reason_codes() {
    let rig = Rig::start("raw", true, true);
    let path = rig.state().join(rig.id.as_str()).join("supervisor.sock");
    let exchange = |frame: &[u8]| {
        let mut s = UnixStream::connect(&path).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut hello = [0u8; HEADER_LEN];
        s.read_exact(&mut hello).unwrap();
        s.write_all(frame).unwrap();
        let mut resp = [0u8; RESPONSE_LEN];
        s.read_exact(&mut resp).unwrap();
        ControlReason::from_u8(*resp.last().unwrap()).unwrap()
    };
    let ok = ReopenLogRequestFrame {
        deadline: SignalDeadline::from_now(Duration::from_secs(3)).unwrap(),
    }
    .encode();
    assert_eq!(exchange(&ok), ControlReason::Ok);
    // 残りが 10 秒を超える期限は断る。
    let far = ReopenLogRequestFrame {
        deadline: SignalDeadline::from_now(Duration::from_secs(30)).unwrap(),
    }
    .encode();
    assert_eq!(exchange(&far), ControlReason::Malformed);
}

/// 生の接続で 1 要求を送り、理由コードを読む（応答が来ること自体が「受け付けられた」ことの照合）。
fn exchange_raw(path: &Path, frame: &[u8]) -> ControlReason {
    let mut s = UnixStream::connect(path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut hello = [0u8; HEADER_LEN];
    s.read_exact(&mut hello).unwrap();
    s.write_all(frame).unwrap();
    let mut resp = [0u8; RESPONSE_LEN];
    s.read_exact(&mut resp).unwrap();
    ControlReason::from_u8(*resp.last().unwrap()).unwrap()
}

/// 開き直しの途中で止まる sink（ログのファイルシステムが応答しない場面）。解放後に、sink が見る期限と許可を記録する。
struct StalledSink {
    entered: std::sync::Mutex<std::sync::mpsc::Sender<()>>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    /// 解放後の `(期限は過ぎている, 続行の許可)`。
    seen: Arc<std::sync::Mutex<Option<(bool, bool)>>>,
}

impl LogSink for StalledSink {
    fn append(&self, _: StreamKind, _: &[u8]) -> Result<(), TraitError> {
        Ok(())
    }
    fn reopen(&self, deadline: Instant, gate: ReopenGate<'_>) -> Result<RetiredWriter, TraitError> {
        self.entered.lock().unwrap().send(()).unwrap();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .expect("sync point not reached: release signal for the stalled reopen");
        *self.seen.lock().unwrap() = Some((Instant::now() >= deadline, gate(&mut || {})));
        Ok(RetiredWriter::default())
    }
}

/// REPAIR-5・CRI-2・SUP-7・#4652（A・B）: ログの開き直しが止まっても accept ループは他の要求を有限時間で処理し
/// （別の開き直しは `Busy`、他の kind は通常どおり応答）、クライアントが期限切れで返った後に解放された sink は
/// 期限切れを見る（公開・差し替えをしない根拠。実ファイルの側の拒否は sink の単体試験）。
#[test]
fn repair5_4652_stalled_reopen_does_not_block_other_requests() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let seen = Arc::new(std::sync::Mutex::new(None));
    let stalled = Arc::new(StalledSink {
        entered: std::sync::Mutex::new(entered_tx),
        release: std::sync::Mutex::new(release_rx),
        seen: Arc::clone(&seen),
    });
    let rig = Rig::start_with("stall", false, true, Some(stalled));
    let sock = rig.state().join(rig.id.as_str()).join("supervisor.sock");
    let state = rig.state();
    let id = rig.id.clone();
    let client = std::thread::spawn(move || {
        ControlReopenLog::new(state).reopen(&id, Instant::now() + Duration::from_millis(600))
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    // 止まっている間も、別の開き直しは Busy で、他の kind の要求も有限時間で応答する。
    let started = Instant::now();
    let reopen = ReopenLogRequestFrame {
        deadline: SignalDeadline::from_now(Duration::from_secs(3)).unwrap(),
    }
    .encode();
    assert_eq!(exchange_raw(&sock, &reopen), ControlReason::Busy);
    let cancel = CancelRestartRequestFrame {
        deadline: SignalDeadline::from_now(Duration::from_secs(3)).unwrap(),
    }
    .encode();
    // 取り消す再起動は無いので理由は何でもよいが、応答が返ること自体が目的（Timeout・Internal は不可）。
    let reason = exchange_raw(&sock, &cancel);
    assert!(
        !matches!(reason, ControlReason::Timeout | ControlReason::Internal),
        "{reason:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));

    // クライアントは期限で返る。その後に解放された sink は、期限切れを見る。
    let e = client.join().unwrap().unwrap_err();
    assert_eq!(e.code(), ErrorCode::Timeout);
    release_tx.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while seen.lock().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(*seen.lock().unwrap(), Some((true, true)));
}
