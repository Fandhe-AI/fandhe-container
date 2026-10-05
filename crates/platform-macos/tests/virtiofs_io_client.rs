//! `VirtiofsIoClient` と io crate のサーバー（`writeback::serve_connection`）の往復結合試験
//! （MAC-1・IO-1・IO-2・REPAIR-5・TASK-65.2）。
//!
//! 3 OS で動くメモリ内トランスポートを使い、実機（VZ）を要しない。VZ vsock・ゲスト mount は別タスク
//! （TASK-65.3・TASK-115）。

use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fandhe_container_io::{
    Batch, BatchConfig, BatchSink, Frame, FrameReceiver, FrameSender, InFlightLimit, IoError,
    IoErrorCode, IoTimeout, NoopSendObserver, SinkPersistReport, SinkWriteReport, WritebackReport,
    WritebackTimeouts, decode_request, serve_connection,
};
use fandhe_container_platform_macos::virtiofs::{
    ShareAccess, SharedDirectoryPath, VirtiofsIoClient, VirtiofsIoTimeouts, VirtiofsShareSpec,
    VirtiofsTag,
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

fn client(
    dir: &TempDir,
    transport: DuplexEnd,
    limit: usize,
    timeouts: VirtiofsIoTimeouts,
) -> VirtiofsIoClient<DuplexEnd, NoopSendObserver> {
    VirtiofsIoClient::new(
        &read_write_share(dir),
        transport,
        InFlightLimit::new(limit).expect("limit"),
        NoopSendObserver,
        timeouts,
    )
    .expect("client")
}

/// MAC-1・IO-1・IO-2・TASK-65.2: 10 件を write_all_and_flush すると sink に順序どおり届き FlushAck で確定する。
#[test]
fn write_all_and_flush_round_trips_in_order() {
    let dir = TempDir::new("roundtrip");
    let (client_end, server_end) = duplex();
    let sink = MemorySink::default();
    let server = spawn_server(server_end, 4, sink.clone());
    let mut c = client(
        &dir,
        client_end,
        4,
        VirtiofsIoTimeouts::new(secs(5), secs(5), secs(5)),
    );

    let bodies: Vec<Vec<u8>> = (0u8..10).map(|i| vec![i; 3]).collect();
    let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
    let report = c.write_all_and_flush(&refs).expect("write_all_and_flush");

    assert_eq!(report.acked_writes, 10);
    assert!(!c.is_poisoned());
    assert_eq!(c.in_flight(), 0);
    let expected: Vec<u8> = bodies.concat();
    assert_eq!(*sink.0.lock().expect("lock"), expected);

    drop(c);
    let end = server.join().expect("server thread").end;
    assert_eq!(end.code(), IoErrorCode::Unavailable);
}

/// IO-2・TASK-65.2（D3）: batch_size 未満の 3 件でも flush で確定できる。
#[test]
fn flush_commits_writes_below_batch_size() {
    let dir = TempDir::new("below-batch");
    let (client_end, server_end) = duplex();
    let sink = MemorySink::default();
    let server = spawn_server(server_end, 4, sink.clone());
    let mut c = client(
        &dir,
        client_end,
        8,
        VirtiofsIoTimeouts::new(secs(5), secs(5), secs(5)),
    );

    for body in [b"aa".as_slice(), b"bb", b"cc"] {
        let r = c.write(body).expect("write");
        assert_eq!(r.acked_writes, 0);
    }
    assert_eq!(c.in_flight(), 3);
    let report = c.flush().expect("flush");

    assert_eq!(report.acked_writes, 3);
    assert_eq!(*sink.0.lock().expect("lock"), b"aabbcc".to_vec());
    assert_eq!(c.in_flight(), 0);

    drop(c);
    let end = server.join().expect("server thread").end;
    assert_eq!(end.code(), IoErrorCode::Unavailable);
}

/// REPAIR-5・TASK-65.2: 生きているが無応答の相手に対し ACK 待ちがタイムアウトし、以後の呼び出しは拒否される。
#[test]
fn ack_wait_times_out_and_poisons() {
    let dir = TempDir::new("timeout");
    let (client_end, silent_peer) = duplex();
    let timeouts = VirtiofsIoTimeouts::new(
        secs(5),
        secs(5),
        IoTimeout::new(Duration::from_millis(50)).expect("t"),
    );
    let mut c = client(&dir, client_end, 2, timeouts);

    c.write(b"a").expect("first write fits");
    let started = Instant::now();
    let err = c
        .write(b"b")
        .expect_err("must time out waiting for flush ack");
    assert_eq!(err.code(), "virtiofs_io.timeout");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(c.is_poisoned());

    let next = c.write(b"c").expect_err("poisoned client must refuse");
    assert_eq!(next.code(), "virtiofs_io.unavailable");

    drop(silent_peer);
}

/// REPAIR-5・TASK-65.2: 無応答の相手に対し FlushAck 待ちもタイムアウトする。
#[test]
fn flush_ack_wait_times_out() {
    let dir = TempDir::new("flush-timeout");
    let (client_end, silent_peer) = duplex();
    let timeouts = VirtiofsIoTimeouts::new(
        secs(5),
        secs(5),
        IoTimeout::new(Duration::from_millis(50)).expect("t"),
    );
    let mut c = client(&dir, client_end, 4, timeouts);

    c.write(b"a").expect("write");
    let started = Instant::now();
    let err = c.flush().expect_err("must time out waiting for flush ack");
    assert_eq!(err.code(), "virtiofs_io.timeout");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(c.is_poisoned());

    let next = c.flush().expect_err("poisoned client must refuse");
    assert_eq!(next.code(), "virtiofs_io.unavailable");

    drop(silent_peer);
}

/// IO-2・TASK-65.2（D3）: in-flight 上限 4 < サーバー batch_size 8 でも、Flush 用の予約枠により
/// 上限まで Write を積んだ後の flush と、上限を超える連続 write がタイムアウトせず確定する。
#[test]
fn flush_works_when_in_flight_limit_is_below_server_batch_size() {
    let dir = TempDir::new("limit-below-batch");
    let (client_end, server_end) = duplex();
    let sink = MemorySink::default();
    let server = spawn_server(server_end, 8, sink.clone());
    let mut c = client(
        &dir,
        client_end,
        4,
        VirtiofsIoTimeouts::new(secs(5), secs(5), secs(5)),
    );

    let bodies: Vec<Vec<u8>> = (0u8..10).map(|i| vec![i; 2]).collect();
    let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
    let report = c.write_all_and_flush(&refs).expect("write_all_and_flush");

    assert_eq!(report.acked_writes, 10);
    assert!(!c.is_poisoned());
    assert_eq!(c.in_flight(), 0);
    assert_eq!(*sink.0.lock().expect("lock"), bodies.concat());

    // 予約枠を除く 3 件（上限 4 - 1）を積んだ直後の flush も確定できる。
    for body in [b"x".as_slice(), b"y", b"z"] {
        c.write(body).expect("write");
    }
    assert_eq!(c.in_flight(), 3);
    let report = c.flush().expect("flush");
    assert_eq!(report.acked_writes, 3);

    drop(c);
    server.join().expect("server thread");
}
