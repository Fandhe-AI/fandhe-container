//! `ReconnectingVirtiofsIoClient` と io crate のサーバー（`writeback::serve_connection`）の往復結合試験
//! （MAC-1・IO-2・REPAIR-5・ERR-1・TASK-65.5）。
//!
//! 3 OS で動くメモリ内トランスポートを使い、実機（VZ）を要しない。1 本目の接続は相手を落として切断を起こし、
//! 2 本目の接続は実サーバーへ繋いで、再発行したコミット単位が FLUSH ACK で確定することを確認する。

use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use fandhe_container_io::{
    Batch, BatchConfig, BatchSink, Frame, FrameReceiver, FrameSender, InFlightLimit, IoError,
    IoErrorCode, IoTimeout, NoopSendObserver, SinkPersistReport, SinkWriteReport, WritebackReport,
    WritebackTimeouts, decode_request, serve_connection,
};
use fandhe_container_platform_macos::virtiofs::{
    ReconnectPolicy, ReconnectingVirtiofsIoClient, ShareAccess, SharedDirectoryPath,
    VirtiofsConnector, VirtiofsIoTimeouts, VirtiofsShareSpec, VirtiofsTag,
};

fn secs(n: u64) -> IoTimeout {
    IoTimeout::new(Duration::from_secs(n)).expect("timeout")
}

/// `std::sync::mpsc` による二方向トランスポート。io の `tests/consistency/harness.rs` の `DuplexEnd` は
/// crate をまたいで import できないため同じ方針で複製した。エラー後は `Unavailable` を返す（poison 契約）。
struct DuplexEnd {
    tx: mpsc::Sender<Frame>,
    rx: mpsc::Receiver<Frame>,
    poisoned: bool,
}

fn duplex() -> (DuplexEnd, DuplexEnd) {
    let (tx_a, rx_a) = mpsc::channel();
    let (tx_b, rx_b) = mpsc::channel();
    (
        DuplexEnd {
            tx: tx_a,
            rx: rx_b,
            poisoned: false,
        },
        DuplexEnd {
            tx: tx_b,
            rx: rx_a,
            poisoned: false,
        },
    )
}

fn unavailable(msg: &'static str) -> IoError {
    IoError::new(IoErrorCode::Unavailable, msg)
}

impl FrameSender for DuplexEnd {
    type Frame = Frame;
    fn send_frame(&mut self, frame: &Frame, _t: IoTimeout) -> Result<(), IoError> {
        if self.poisoned {
            return Err(unavailable("duplex end is poisoned"));
        }
        self.tx.send(frame.clone()).map_err(|_| {
            self.poisoned = true;
            unavailable("duplex peer has disconnected")
        })
    }
}

impl FrameReceiver for DuplexEnd {
    type Frame = Frame;
    fn recv_frame(&mut self, t: IoTimeout) -> Result<Frame, IoError> {
        if self.poisoned {
            return Err(unavailable("duplex end is poisoned"));
        }
        match self.rx.recv_timeout(t.as_duration()) {
            Ok(f) => Ok(f),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.poisoned = true;
                Err(IoError::new(IoErrorCode::Timeout, "duplex recv timed out"))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.poisoned = true;
                Err(unavailable("duplex peer has disconnected"))
            }
        }
    }
}

/// インメモリの `BatchSink`。`persist` は常に成功する（実ファイルの永続化可否に依存しない）。
#[derive(Clone, Default)]
struct MemorySink(Arc<Mutex<Vec<u8>>>);

impl BatchSink for MemorySink {
    fn write_batch(&mut self, batch: &Batch) -> Result<SinkWriteReport, IoError> {
        let mut data = self
            .0
            .lock()
            .map_err(|_| IoError::new(IoErrorCode::Internal, "sink lock poisoned"))?;
        let mut bytes: u64 = 0;
        for frame in batch.frames() {
            let env = decode_request(frame)?;
            data.extend_from_slice(env.body());
            bytes += env.body().len() as u64;
        }
        Ok(SinkWriteReport::new(batch.len(), bytes))
    }

    fn persist(&mut self) -> Result<SinkPersistReport, IoError> {
        Ok(SinkPersistReport::new(Duration::ZERO))
    }
}

fn spawn_server(
    mut conn: DuplexEnd,
    batch_size: usize,
    mut sink: MemorySink,
) -> JoinHandle<WritebackReport> {
    std::thread::spawn(move || {
        serve_connection(
            &mut conn,
            BatchConfig::new(batch_size).expect("batch config"),
            &mut sink,
            WritebackTimeouts {
                recv: secs(5),
                send: secs(5),
            },
        )
    })
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let raw = std::env::temp_dir().join(format!(
            "fandhe-macos-virtiofs-it-{tag}-{}",
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

fn read_write_share(dir: &TempDir) -> VirtiofsShareSpec {
    VirtiofsShareSpec::new(
        VirtiofsTag::try_new("work").expect("tag"),
        SharedDirectoryPath::try_new(&dir.0).expect("dir"),
        ShareAccess::ReadWrite,
    )
}

/// 接続ごとに異なる相手を返す connector。1 本目は呼び出し側が落とせる無応答の相手、2 本目以降は実サーバー。
struct TestConnector {
    calls: usize,
    silent_peer: Arc<Mutex<Option<DuplexEnd>>>,
    sink: MemorySink,
    servers: Arc<Mutex<Vec<JoinHandle<WritebackReport>>>>,
}

impl VirtiofsConnector for TestConnector {
    type Transport = DuplexEnd;
    fn connect(&mut self, _timeout: IoTimeout) -> Result<DuplexEnd, IoError> {
        self.calls += 1;
        let (client_end, server_end) = duplex();
        if self.calls == 1 {
            *self.silent_peer.lock().expect("lock") = Some(server_end);
        } else {
            let handle = spawn_server(server_end, 4, self.sink.clone());
            self.servers.lock().expect("lock").push(handle);
        }
        Ok(client_end)
    }
}

/// MAC-1・IO-2・ERR-1・REPAIR-5・TASK-65.5: 切断後に再接続し、再発行したコミット単位が FLUSH ACK まで確定する。
#[test]
fn reconnects_after_disconnect_and_commit_unit_is_reissued() {
    let dir = TempDir::new("reconnect");
    let silent_peer = Arc::new(Mutex::new(None));
    let servers = Arc::new(Mutex::new(Vec::new()));
    let sink = MemorySink::default();
    let connector = TestConnector {
        calls: 0,
        silent_peer: Arc::clone(&silent_peer),
        sink: sink.clone(),
        servers: Arc::clone(&servers),
    };
    let policy = ReconnectPolicy::try_new(3, Duration::from_millis(10), secs(1)).expect("policy");
    let mut c = ReconnectingVirtiofsIoClient::connect(
        &read_write_share(&dir),
        connector,
        InFlightLimit::new(8).expect("limit"),
        NoopSendObserver,
        VirtiofsIoTimeouts::new(secs(5), secs(5), secs(5)),
        policy,
    )
    .expect("connect");

    c.write(b"aa").expect("write 1");
    c.write(b"bb").expect("write 2");
    // 相手を落として接続断を起こす。
    drop(silent_peer.lock().expect("lock").take());

    let err = c.flush().expect_err("connection lost");
    assert_eq!(err.code(), "virtiofs_io.connection_lost");
    assert_eq!(
        err.message(),
        "virtiofs io flush failed because the connection was lost; reconnected=true, \
         up to 2 unflushed write(s) may or may not be persisted; \
         re-issue only idempotent writes, otherwise verify the committed range first"
    );
    assert_eq!(c.reconnects(), 1);
    assert_eq!(c.unflushed_writes(), 0);
    // 失敗したコミット単位は自動再送されていない。
    assert_eq!(*sink.0.lock().expect("lock"), Vec::<u8>::new());

    let report = c
        .write_all_and_flush(&[b"aa".as_slice(), b"bb"])
        .expect("re-issue on the new connection");
    assert_eq!(report.acked_writes, 2);
    assert_eq!(*sink.0.lock().expect("lock"), b"aabb".to_vec());

    drop(c);
    let handles: Vec<_> = servers.lock().expect("lock").drain(..).collect();
    assert_eq!(handles.len(), 1);
    for h in handles {
        let end = h.join().expect("server thread").end;
        assert_eq!(end.code(), IoErrorCode::Unavailable);
    }
}

/// REPAIR-5・ERR-1・TASK-65.5: 接続先が存在しない場合は構造化エラーで返り、ハングも panic もしない。
#[test]
fn unreachable_peer_returns_structured_error() {
    struct Refusing;
    impl VirtiofsConnector for Refusing {
        type Transport = DuplexEnd;
        fn connect(&mut self, _t: IoTimeout) -> Result<DuplexEnd, IoError> {
            Err(IoError::new(IoErrorCode::Unavailable, "connect refused"))
        }
    }
    let dir = TempDir::new("unreachable");
    let policy = ReconnectPolicy::try_new(2, Duration::from_millis(5), secs(1)).expect("policy");
    let err = ReconnectingVirtiofsIoClient::connect(
        &read_write_share(&dir),
        Refusing,
        InFlightLimit::new(4).expect("limit"),
        NoopSendObserver,
        VirtiofsIoTimeouts::new(secs(1), secs(1), secs(1)),
        policy,
    )
    .err()
    .expect("must fail");
    assert_eq!(err.code(), "virtiofs_io.reconnect_failed");
}
