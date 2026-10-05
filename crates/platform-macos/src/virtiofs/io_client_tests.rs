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

/// REPAIR-5・TASK-65.2: write が枠を空けるときは ack 値、flush の受け取りは flush_ack 値を渡す。
#[test]
fn timeout_values_are_wired_to_recv() {
    let dir = TempDir::new("wire");
    let timeouts = VirtiofsIoTimeouts::new(secs(1), secs(2), secs(3));
    let (mut client, log) = recording_client(&dir, 1, timeouts);

    let first = client.write(b"a").expect("first write");
    assert_eq!(first.acked_writes, 0);
    // 2 件目は満杯のため先に ack タイムアウトで 1 件受け取る。
    let second = client.write(b"b").expect("second write");
    assert_eq!(second.acked_writes, 1);
    assert_eq!(*log.lock().expect("lock"), vec![Duration::from_secs(2)]);

    // flush: 満杯なので枠空け（ack=2s）→ Flush 送信 → FlushAck 受信（flush_ack=3s）。
    // 枠空けで通常 ACK 1 件（b）、Flush 送信後の drain は FlushAck のみなので通常 ACK は合計 1 件。
    let report = client.flush().expect("flush");
    assert_eq!(report.acked_writes, 1);
    assert_eq!(
        *log.lock().expect("lock"),
        vec![
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(3)
        ]
    );
    assert_eq!(client.in_flight(), 0);
    assert!(!client.is_poisoned());
}
