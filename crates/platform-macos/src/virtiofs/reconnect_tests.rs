//! `reconnect` のユニットテスト（MAC-1・REPAIR-5・ERR-1・TASK-65.5）。サーバー往復は `tests/virtiofs_reconnect.rs`。

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use fandhe_container_io::{FrameKind, NoopSendObserver, WireRequestId, decode_request, encode_ack};

use super::*;
use crate::error::PlatformError;
use crate::virtiofs::SharedDirectoryPath;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let raw = std::env::temp_dir().join(format!(
            "fandhe-macos-virtiofs-reconnect-{tag}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&raw).expect("create temp dir");
        Self(std::fs::canonicalize(&raw).expect("canonicalize temp dir"))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn share(dir: &TempDir, access: ShareAccess) -> VirtiofsShareSpec {
    VirtiofsShareSpec::new(
        VirtiofsTag::try_new("work").expect("tag"),
        SharedDirectoryPath::try_new(&dir.0).expect("dir"),
        access,
    )
}

fn secs(n: u64) -> IoTimeout {
    IoTimeout::new(Duration::from_secs(n)).expect("timeout")
}

/// 受信の挙動。
#[derive(Clone, Copy)]
enum Mode {
    /// 送信済みリクエストへ正しい ACK を返す。
    Healthy,
    /// 受信すると接続断（`Unavailable`）を返す。
    DieOnRecv,
    /// 受信するとタイムアウトを返す。
    TimeoutOnRecv,
    /// 送信すると接続断（`Unavailable`）を返す（相手がフレームを受理したか不明な送信失敗）。
    DieOnSend,
}

type SentLog = Arc<Mutex<Vec<FrameKind>>>;

struct MockTransport {
    mode: Mode,
    pending: VecDeque<(FrameKind, WireRequestId)>,
    sent: SentLog,
}

impl FrameSender for MockTransport {
    type Frame = Frame;
    fn send_frame(&mut self, frame: &Frame, _t: IoTimeout) -> Result<(), IoError> {
        if matches!(self.mode, Mode::DieOnSend) {
            return Err(IoError::new(
                IoErrorCode::Unavailable,
                "peer closed on send",
            ));
        }
        let env = decode_request(frame)?;
        self.sent.lock().expect("lock").push(env.kind());
        self.pending.push_back((env.kind(), env.id()));
        Ok(())
    }
}

impl FrameReceiver for MockTransport {
    type Frame = Frame;
    fn recv_frame(&mut self, _t: IoTimeout) -> Result<Frame, IoError> {
        match self.mode {
            Mode::DieOnRecv | Mode::DieOnSend => {
                Err(IoError::new(IoErrorCode::Unavailable, "peer closed"))
            }
            Mode::TimeoutOnRecv => Err(IoError::new(IoErrorCode::Timeout, "recv timed out")),
            Mode::Healthy => {
                let (kind, id) = self
                    .pending
                    .pop_front()
                    .ok_or_else(|| IoError::new(IoErrorCode::Timeout, "no pending request"))?;
                let ack_kind = match kind {
                    FrameKind::Flush => FrameKind::FlushAck,
                    _ => FrameKind::Ack,
                };
                encode_ack(ack_kind, id)
            }
        }
    }
}

/// 接続結果の台本。`Ok(mode)` で接続成功、`Err` で失敗。尽きたら失敗し続ける。
struct ScriptedConnector {
    script: VecDeque<Result<Mode, IoError>>,
    calls: Rc<RefCell<u32>>,
    /// 接続ごとに作った送信ログ（接続の順）。
    logs: Rc<RefCell<Vec<SentLog>>>,
}

impl VirtiofsConnector for ScriptedConnector {
    type Transport = MockTransport;
    fn connect(&mut self, _timeout: IoTimeout) -> Result<MockTransport, IoError> {
        *self.calls.borrow_mut() += 1;
        match self.script.pop_front() {
            Some(Ok(mode)) => {
                let sent: SentLog = Arc::default();
                self.logs.borrow_mut().push(Arc::clone(&sent));
                Ok(MockTransport {
                    mode,
                    pending: VecDeque::new(),
                    sent,
                })
            }
            Some(Err(e)) => Err(e),
            None => Err(IoError::new(IoErrorCode::Unavailable, "connect refused")),
        }
    }
}

struct Harness {
    calls: Rc<RefCell<u32>>,
    logs: Rc<RefCell<Vec<SentLog>>>,
    pauses: Rc<RefCell<Vec<Duration>>>,
}

type Client = ReconnectingVirtiofsIoClient<ScriptedConnector, NoopSendObserver>;

fn policy(attempts: u32, interval_ms: u64) -> ReconnectPolicy {
    ReconnectPolicy::try_new(attempts, Duration::from_millis(interval_ms), secs(1)).expect("policy")
}

fn build(
    dir: &TempDir,
    access: ShareAccess,
    limit: usize,
    script: Vec<Result<Mode, IoError>>,
    policy: ReconnectPolicy,
) -> (Result<Client, VirtiofsIoError>, Harness) {
    let h = Harness {
        calls: Rc::default(),
        logs: Rc::default(),
        pauses: Rc::default(),
    };
    let connector = ScriptedConnector {
        script: script.into(),
        calls: Rc::clone(&h.calls),
        logs: Rc::clone(&h.logs),
    };
    let pauses = Rc::clone(&h.pauses);
    let client = Client::connect_with_pause(
        &share(dir, access),
        connector,
        InFlightLimit::new(limit).expect("limit"),
        NoopSendObserver,
        VirtiofsIoTimeouts::new(secs(1), secs(1), secs(1)),
        policy,
        Box::new(move |d| pauses.borrow_mut().push(d)),
    );
    (client, h)
}

fn refused() -> IoError {
    IoError::new(IoErrorCode::Unavailable, "connect refused")
}

/// REPAIR-5・TASK-65.5: 既定ポリシーは 3 回・500ms・接続タイムアウト 5s。
#[test]
fn default_policy_values() {
    let p = ReconnectPolicy::try_default().expect("default");
    assert_eq!(p.max_attempts(), 3);
    assert_eq!(p.interval(), Duration::from_millis(500));
    assert_eq!(p.connect_timeout().as_duration(), Duration::from_secs(5));
}

/// REPAIR-5・ERR-1・TASK-65.5: 範囲外のポリシー値は field 名つきで拒否する。
#[test]
fn policy_bounds_are_rejected() {
    let ms = Duration::from_millis;
    for (attempts, interval, field) in [
        (0, ms(10), "max_attempts"),
        (11, ms(10), "max_attempts"),
        (3, Duration::ZERO, "interval"),
        (3, Duration::from_secs(11), "interval"),
    ] {
        let err = ReconnectPolicy::try_new(attempts, interval, secs(1)).expect_err("rejected");
        assert_eq!(err.code(), "virtiofs_io.invalid_reconnect_policy");
        assert_eq!(
            err.message(),
            format!("virtiofs io reconnect policy {field} is outside the allowed range")
        );
    }
    assert!(ReconnectPolicy::try_new(10, Duration::from_secs(10), secs(1)).is_ok());
}

/// MAC-1・TASK-65.5: ReadOnly 共有と in-flight 上限不足は connector を一度も呼ばずに拒否する。
#[test]
fn invalid_construction_never_calls_connector() {
    let dir = TempDir::new("ctor");
    let (res, h) = build(&dir, ShareAccess::ReadOnly, 4, vec![], policy(3, 1));
    assert_eq!(
        res.err().expect("rejected").code(),
        "virtiofs_io.read_only_share"
    );
    assert_eq!(*h.calls.borrow(), 0);

    let (res, h) = build(&dir, ShareAccess::ReadWrite, 1, vec![], policy(3, 1));
    assert_eq!(
        res.err().expect("rejected").code(),
        "virtiofs_io.in_flight_limit_too_small"
    );
    assert_eq!(*h.calls.borrow(), 0);
}

/// REPAIR-5・ERR-1・TASK-65.5: 失敗し続ける connector では回数ちょうど試行し、間隔は N-1 回で、構造化エラーを返す。
#[test]
fn exhausted_attempts_return_reconnect_failed() {
    let dir = TempDir::new("exhaust");
    let (res, h) = build(&dir, ShareAccess::ReadWrite, 4, vec![], policy(3, 7));
    let err = res.err().expect("must fail");
    assert_eq!(*h.calls.borrow(), 3);
    assert_eq!(*h.pauses.borrow(), vec![Duration::from_millis(7); 2]);
    assert_eq!(err.code(), "virtiofs_io.reconnect_failed");
    assert_eq!(
        err.message(),
        "virtiofs io reconnect failed after 3 attempt(s): UNAVAILABLE: connect refused"
    );
    let source = std::error::Error::source(&err).expect("source");
    assert_eq!(source.to_string(), "UNAVAILABLE: connect refused");

    let platform = PlatformError::from(err.clone());
    assert_eq!(platform.code(), err.code());
    assert_eq!(platform.message(), err.message());
}

/// MAC-1・TASK-65.5: 2 回失敗して 3 回目で成功すれば、続く write / flush が成功する。
#[test]
fn succeeds_on_third_attempt() {
    let dir = TempDir::new("third");
    let script = vec![Err(refused()), Err(refused()), Ok(Mode::Healthy)];
    let (res, h) = build(&dir, ShareAccess::ReadWrite, 4, script, policy(3, 1));
    let mut c = res.expect("connected");
    assert_eq!(*h.calls.borrow(), 3);
    assert!(c.is_connected());
    c.write(b"a").expect("write");
    let report = c.flush().expect("flush");
    assert_eq!(report.acked_writes, 1);
    assert_eq!(c.unflushed_writes(), 0);
}

/// MAC-1・IO-2・ERR-1・TASK-65.5: flush 中の切断は再接続して ConnectionLost を返し、未確定 Write は再送しない。
#[test]
fn connection_loss_reconnects_without_resend() {
    let dir = TempDir::new("lost");
    let script = vec![Ok(Mode::DieOnRecv), Ok(Mode::Healthy)];
    let (res, h) = build(&dir, ShareAccess::ReadWrite, 8, script, policy(3, 1));
    let mut c = res.expect("connected");
    c.write(b"a").expect("write 1");
    c.write(b"b").expect("write 2");
    assert_eq!(c.unflushed_writes(), 2);

    let err = c.flush().expect_err("connection lost");
    assert_eq!(err.code(), "virtiofs_io.connection_lost");
    assert_eq!(
        err.message(),
        "virtiofs io flush failed because the connection was lost; reconnected=true, \
         2 unflushed write(s) must be re-issued"
    );
    assert!(matches!(
        err,
        VirtiofsIoError::ConnectionLost {
            unflushed_writes: 2,
            reconnected: true,
            ..
        }
    ));
    assert_eq!(c.unflushed_writes(), 0);
    assert_eq!(c.reconnects(), 1);
    assert!(c.is_connected());

    // 新しい接続には何も送られていない（自動再送なし）。
    let logs = h.logs.borrow();
    assert_eq!(logs.len(), 2);
    assert!(logs[1].lock().expect("lock").is_empty());
    drop(logs);

    // 呼び出し元がコミット単位を再発行すれば確定できる。
    let report = c.write_all_and_flush(&[b"a", b"b"]).expect("re-issue");
    assert_eq!(report.acked_writes, 2);
}

/// REPAIR-5・ERR-1・TASK-65.5: 切断後の再接続にも失敗したら ReconnectFailed を返し、panic しない。
#[test]
fn connection_loss_then_reconnect_failure() {
    let dir = TempDir::new("lost-fail");
    let script = vec![Ok(Mode::DieOnRecv)];
    let (res, h) = build(&dir, ShareAccess::ReadWrite, 8, script, policy(2, 3));
    let mut c = res.expect("connected");
    c.write(b"a").expect("write");
    let err = c.flush().expect_err("must fail");
    assert_eq!(err.code(), "virtiofs_io.reconnect_failed");
    assert!(matches!(
        err,
        VirtiofsIoError::ReconnectFailed {
            attempts: 2,
            unflushed_writes: 1,
            ..
        }
    ));
    assert_eq!(c.unflushed_writes(), 0);
    assert!(!c.is_connected());
    assert_eq!(*h.calls.borrow(), 3);
    assert_eq!(*h.pauses.borrow(), vec![Duration::from_millis(3)]);
}

/// REPAIR-5・TASK-65.5: 接続断以外のエラーは元のまま返し、次の呼び出しで再接続する。
#[test]
fn non_disconnect_error_passes_through_then_reconnects_next_call() {
    let dir = TempDir::new("timeout");
    let script = vec![Ok(Mode::TimeoutOnRecv), Ok(Mode::Healthy)];
    let (res, h) = build(&dir, ShareAccess::ReadWrite, 8, script, policy(3, 1));
    let mut c = res.expect("connected");
    c.write(b"a").expect("write");
    let err = c.flush().expect_err("timeout");
    assert_eq!(err.code(), "virtiofs_io.timeout");
    assert_eq!(*h.calls.borrow(), 1);
    assert!(!c.is_connected());

    // poison 後の再接続では旧接続の未確定 Write(1 件) を黙って捨てず ConnectionLost で明示する。
    let err = c.write(b"b").expect_err("unflushed must be reported");
    assert!(matches!(
        err,
        VirtiofsIoError::ConnectionLost {
            op: VirtiofsIoOp::Write,
            unflushed_writes: 1,
            reconnected: true,
            ..
        }
    ));
    assert_eq!(*h.calls.borrow(), 2);
    assert_eq!(c.reconnects(), 1);
    assert_eq!(c.unflushed_writes(), 0);
    c.write(b"b").expect("write after acknowledged loss");
    assert_eq!(c.unflushed_writes(), 1);
}

/// IO-2・TASK-65.5: 通常 ACK だけでは件数を減らさないが、暗黙 flush の FLUSH ACK 確認分は除く。
/// limit=4（Write 枠 3）で 6 件送ると 4 件目で暗黙 flush が走り、その時点の 3 件は永続化確認済み。
#[test]
fn implicit_flush_ack_reduces_unflushed() {
    let dir = TempDir::new("implicit");
    let script = vec![Ok(Mode::Healthy)];
    let (res, _h) = build(&dir, ShareAccess::ReadWrite, 4, script, policy(3, 1));
    let mut c = res.expect("connected");
    let mut acked = 0;
    for _ in 0..6 {
        acked += c.write(b"x").expect("write").acked_writes;
    }
    assert_eq!(acked, 3, "implicit flush acks the first 3 writes");
    assert_eq!(c.unflushed_writes(), 3);
    c.flush().expect("flush");
    assert_eq!(c.unflushed_writes(), 0);
}

/// IO-2・TASK-65.5: 送信に失敗した Write も未確定として数え、最初の Write の失敗でも件数が 1 になる。
#[test]
fn failed_send_counts_as_ambiguous_unflushed() {
    let dir = TempDir::new("send-fail");
    let script = vec![Ok(Mode::DieOnSend), Ok(Mode::Healthy)];
    let (res, _h) = build(&dir, ShareAccess::ReadWrite, 8, script, policy(3, 1));
    let mut c = res.expect("connected");
    let err = c.write(b"a").expect_err("send fails");
    assert!(matches!(
        err,
        VirtiofsIoError::ConnectionLost {
            op: VirtiofsIoOp::Write,
            unflushed_writes: 1,
            reconnected: true,
            ..
        }
    ));
    assert_eq!(c.unflushed_writes(), 0);
}
