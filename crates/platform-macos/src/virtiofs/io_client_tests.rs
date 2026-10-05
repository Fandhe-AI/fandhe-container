//! `io_client` のユニットテスト（MAC-1・TASK-65.2・REPAIR-5）。サーバー往復は `tests/virtiofs_io_client.rs`。

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fandhe_container_io::{NoopSendObserver, WireRequestId, decode_request, encode_ack};

use super::*;
use crate::virtiofs::SharedDirectoryPath;

/// テスト専用の一時ディレクトリ（macOS の `/var` symlink を避けるため実体化する）。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let raw = std::env::temp_dir().join(format!(
            "fandhe-macos-virtiofs-io-{tag}-{}",
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

/// 受信時に渡された `IoTimeout` を記録し、送信済みリクエストへ正しい ACK を返す mock。
struct RecordingTransport {
    sent: VecDeque<(FrameKind, WireRequestId)>,
    recv_timeouts: Arc<Mutex<Vec<Duration>>>,
}

impl RecordingTransport {
    fn new(log: &Arc<Mutex<Vec<Duration>>>) -> Self {
        Self {
            sent: VecDeque::new(),
            recv_timeouts: Arc::clone(log),
        }
    }
}

impl FrameSender for RecordingTransport {
    type Frame = Frame;
    fn send_frame(&mut self, frame: &Frame, _t: IoTimeout) -> Result<(), IoError> {
        let env = decode_request(frame)?;
        self.sent.push_back((env.kind(), env.id()));
        Ok(())
    }
}

impl FrameReceiver for RecordingTransport {
    type Frame = Frame;
    fn recv_frame(&mut self, t: IoTimeout) -> Result<Frame, IoError> {
        if let Ok(mut v) = self.recv_timeouts.lock() {
            v.push(t.as_duration());
        }
        let (kind, id) = self
            .sent
            .pop_front()
            .ok_or_else(|| IoError::new(IoErrorCode::Timeout, "no pending request"))?;
        let ack_kind = match kind {
            FrameKind::Flush => FrameKind::FlushAck,
            _ => FrameKind::Ack,
        };
        encode_ack(ack_kind, id)
    }
}

type MockClient = VirtiofsIoClient<RecordingTransport, NoopSendObserver>;

fn recording_client(
    dir: &TempDir,
    limit: usize,
    timeouts: VirtiofsIoTimeouts,
) -> (MockClient, Arc<Mutex<Vec<Duration>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let client = VirtiofsIoClient::new(
        &share(dir, ShareAccess::ReadWrite),
        RecordingTransport::new(&log),
        InFlightLimit::new(limit).expect("limit"),
        NoopSendObserver,
        timeouts,
    )
    .expect("client");
    (client, log)
}

/// MAC-1・TASK-65.2: ReadOnly 共有は fail-closed で拒否する。
#[test]
fn read_only_share_is_rejected() {
    let dir = TempDir::new("ro");
    let log = Arc::new(Mutex::new(Vec::new()));
    let err = VirtiofsIoClient::new(
        &share(&dir, ShareAccess::ReadOnly),
        RecordingTransport::new(&log),
        InFlightLimit::new(4).expect("limit"),
        NoopSendObserver,
        VirtiofsIoTimeouts::try_default().expect("defaults"),
    )
    .err()
    .expect("must be rejected");
    assert_eq!(err.code(), "virtiofs_io.read_only_share");
    assert_eq!(
        err.message(),
        "virtiofs share 'work' is read-only; a write-back client cannot be created"
    );
}

/// MAC-1・TASK-65.2: ReadWrite 共有では構築でき、タグが保持される。
#[test]
fn read_write_share_keeps_tag() {
    let dir = TempDir::new("rw");
    let (client, _) = recording_client(
        &dir,
        4,
        VirtiofsIoTimeouts::try_default().expect("defaults"),
    );
    assert_eq!(client.tag().as_str(), "work");
    assert!(!client.is_poisoned());
    assert_eq!(client.in_flight(), 0);
}

/// REPAIR-5・TASK-65.2: 既定タイムアウトは send 5s / ack 10s / flush_ack 10s。
#[test]
fn default_timeouts_are_concrete() {
    let t = VirtiofsIoTimeouts::try_default().expect("defaults");
    assert_eq!(t.send().as_duration(), Duration::from_secs(5));
    assert_eq!(t.ack().as_duration(), Duration::from_secs(10));
    assert_eq!(t.flush_ack().as_duration(), Duration::from_secs(10));
}

/// ERR-1・TASK-65.2: IoErrorCode から `virtiofs_io.*` への写像。
#[test]
fn protocol_error_code_mapping() {
    let cases = [
        (IoErrorCode::InvalidArgument, "virtiofs_io.invalid_argument"),
        (IoErrorCode::Timeout, "virtiofs_io.timeout"),
        (IoErrorCode::Unavailable, "virtiofs_io.unavailable"),
        (IoErrorCode::Unimplemented, "virtiofs_io.unimplemented"),
        (IoErrorCode::Internal, "virtiofs_io.internal"),
        (IoErrorCode::DataLoss, "virtiofs_io.data_loss"),
        (
            IoErrorCode::ResourceExhausted,
            "virtiofs_io.resource_exhausted",
        ),
        (IoErrorCode::AlreadyExists, "virtiofs_io.already_exists"),
    ];
    for (io_code, expected) in cases {
        let e = VirtiofsIoError::Protocol {
            op: VirtiofsIoOp::Write,
            source: IoError::new(io_code, "x"),
        };
        assert_eq!(e.code(), expected);
    }
    let e = VirtiofsIoError::UnexpectedAck {
        op: VirtiofsIoOp::Flush,
    };
    assert_eq!(e.code(), "virtiofs_io.unexpected_ack");
}

/// ERR-1・TASK-65.2: PlatformError へ束ねても code / message が変わらない。
#[test]
fn platform_error_wraps_virtiofs_io_error() {
    let inner = VirtiofsIoError::Protocol {
        op: VirtiofsIoOp::Flush,
        source: IoError::new(IoErrorCode::Timeout, "recv timed out"),
    };
    let e = crate::error::PlatformError::from(inner);
    assert_eq!(e.code(), "virtiofs_io.timeout");
    assert_eq!(
        e.message(),
        "virtiofs io flush failed: TIMEOUT: recv timed out"
    );
}

/// REPAIR-5・TASK-65.2: write の暗黙 flush と flush の受け取りはいずれも flush_ack 値を渡す。
#[test]
fn timeout_values_are_wired_to_recv() {
    let dir = TempDir::new("wire");
    let timeouts = VirtiofsIoTimeouts::new(secs(1), secs(2), secs(3));
    let (mut client, log) = recording_client(&dir, 2, timeouts);

    let first = client.write(b"a").expect("first write");
    assert_eq!(first.acked_writes, 0);
    // 2 件目は Write 容量（上限 - 1 = 1）に達しているため、先に暗黙 flush で a を確定する（ACK 1 件 + FlushAck）。
    let second = client.write(b"b").expect("second write");
    assert_eq!(second.acked_writes, 1);
    // 各 recv には Flush 全体の期限（3s）の残り時間が渡る（0 超 3s 以下）。
    for d in log.lock().expect("lock").iter() {
        assert!(*d > Duration::ZERO && *d <= Duration::from_secs(3), "{d:?}");
    }
    assert_eq!(log.lock().expect("lock").len(), 2);

    // flush: Flush 用の予約枠で送信でき、b の通常 ACK と FlushAck を受け取る。
    let report = client.flush().expect("flush");
    assert_eq!(report.acked_writes, 1);
    assert_eq!(log.lock().expect("lock").len(), 4);
    assert_eq!(client.in_flight(), 0);
    assert!(!client.is_poisoned());
}

/// 受信ごとに固定時間 sleep してから ACK を返す mock（Flush 全体の期限検証用）。
struct SlowTransport {
    inner: RecordingTransport,
    delay: Duration,
}

impl FrameSender for SlowTransport {
    type Frame = Frame;
    fn send_frame(&mut self, frame: &Frame, t: IoTimeout) -> Result<(), IoError> {
        self.inner.send_frame(frame, t)
    }
}

impl FrameReceiver for SlowTransport {
    type Frame = Frame;
    fn recv_frame(&mut self, t: IoTimeout) -> Result<Frame, IoError> {
        std::thread::sleep(self.delay);
        self.inner.recv_frame(t)
    }
}

/// REPAIR-5・TASK-65.2: 各 ACK が個別の期限内に届いても、Flush 全体の期限を超えたら Timeout になる。
#[test]
fn flush_total_deadline_is_enforced_across_acks() {
    let dir = TempDir::new("deadline");
    let log = Arc::new(Mutex::new(Vec::new()));
    let flush_ack = IoTimeout::new(Duration::from_millis(150)).expect("timeout");
    let timeouts = VirtiofsIoTimeouts::new(secs(1), secs(1), flush_ack);
    let mut client = VirtiofsIoClient::new(
        &share(&dir, ShareAccess::ReadWrite),
        SlowTransport {
            inner: RecordingTransport::new(&log),
            delay: Duration::from_millis(60),
        },
        InFlightLimit::new(8).expect("limit"),
        NoopSendObserver,
        timeouts,
    )
    .expect("client");
    for _ in 0..4 {
        client.write(b"x").expect("write");
    }
    // 受信 5 回（通常 ACK 4 + FlushAck）× 60ms = 300ms > 150ms。各 recv は 150ms 未満で完了するため、
    // 従来実装（毎回 150ms を渡す）では成功してしまう境界ケース。
    let err = client.flush().expect_err("total deadline must expire");
    assert_eq!(err.code(), "virtiofs_io.timeout");
    assert!(client.is_poisoned());
    // 渡された期限は単調に減り、元の値（150ms）を超えない。
    let seen = log.lock().expect("lock").clone();
    assert!(seen.len() >= 2 && seen.len() < 5, "{seen:?}");
    assert!(seen.iter().all(|d| *d <= Duration::from_millis(150)));
    assert!(seen.windows(2).all(|w| w[1] <= w[0]), "{seen:?}");
}

/// REPAIR-5: 期限到達済み（残り 0）と加算オーバーフローはいずれも Timeout（fail-closed）。
#[test]
fn remaining_until_expired_or_overflow_is_timeout() {
    type C = VirtiofsIoClient<RecordingTransport, NoopSendObserver>;
    let past = Instant::now();
    std::thread::sleep(Duration::from_millis(2));
    let e = C::remaining_until(Some(past)).expect_err("expired");
    assert_eq!(e.code(), "virtiofs_io.timeout");
    let e = C::remaining_until(None).expect_err("overflow");
    assert_eq!(e.code(), "virtiofs_io.timeout");
    let ok = C::remaining_until(Instant::now().checked_add(Duration::from_secs(5))).expect("ok");
    assert!(ok.as_duration() > Duration::ZERO && ok.as_duration() <= Duration::from_secs(5));
}

/// MAC-1・IO-2・TASK-65.2（D3）: 上限 1 は Flush 用の予約枠を取れないため構築を拒否する。
#[test]
fn in_flight_limit_below_minimum_is_rejected() {
    let dir = TempDir::new("limit1");
    let log = Arc::new(Mutex::new(Vec::new()));
    let err = VirtiofsIoClient::new(
        &share(&dir, ShareAccess::ReadWrite),
        RecordingTransport::new(&log),
        InFlightLimit::new(1).expect("limit"),
        NoopSendObserver,
        VirtiofsIoTimeouts::try_default().expect("defaults"),
    )
    .err()
    .expect("must be rejected");
    assert_eq!(err.code(), "virtiofs_io.in_flight_limit_too_small");
    assert_eq!(
        err.message(),
        "virtiofs io in-flight limit 1 is too small; at least 2 is required (one slot is reserved for flush)"
    );
}
