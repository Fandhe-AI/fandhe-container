//! 共通の受信ループ `frame_loop` の結合試験（PLUG-1・PLUG-12・REPAIR-5・REPAIR-12。#3774）。
//! 試験本体が core 役（`UdsListener::bind`・accept）、別スレッドが plugin 役（connect → `serve_until`）を担う。
//! 子プロセスは使わない。待ちはすべて有限の期限つきで、超えたら失敗にする。
#![cfg(unix)]

#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fandhe_container_plugin::frame_loop::{IDLE_POLL, LoopExit, serve_until};
use fandhe_container_plugin::{
    ControlMessage, FRAME_HEADER_LEN, Frame, FrameHeader, JsonLinesPeerAuthObserver, MessageId,
    PluginError, PluginErrorCode, UdsListener, UdsStream, decode_message, encode_message,
};

const WAIT: Duration = Duration::from_secs(5);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        Self(exclusive_dir::create("fcfl").unwrap())
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

type Msg = ControlMessage<Vec<String>>;
type Outcome = Result<LoopExit, PluginError>;

fn req(id: u64, body: &[&str]) -> Frame {
    encode_message(&ControlMessage::Request {
        id: MessageId::new(id),
        body: body.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
    })
    .unwrap()
}

fn send(s: &mut UdsStream, f: &Frame) {
    s.write_all(&f.encode()).unwrap();
    s.flush().unwrap();
}

fn recv(s: &mut UdsStream) -> Msg {
    let mut head = [0u8; FRAME_HEADER_LEN];
    s.read_exact(&mut head).unwrap();
    let header = FrameHeader::from_bytes(head).unwrap();
    let mut body = vec![0u8; header.body_len()];
    s.read_exact(&mut body).unwrap();
    decode_message(&Frame::decode_body(header, &body).unwrap()).unwrap()
}

/// plugin 役のスレッドを起動し、core 役の接続済みストリームと結果の受け口を返す。
fn start(
    dir: &TempDir,
    stop: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
) -> (UdsStream, mpsc::Receiver<Outcome>, JoinHandle<()>) {
    let l = UdsListener::bind(&dir.0.join("s.sock")).unwrap();
    let path = l.path().to_path_buf();
    let (tx, rx) = mpsc::channel();
    // サーバー側の accept（peer 照合と io timeout の設定）が終わるまで client を閉じない。
    // stop が先に立つ場合 `serve_until` が即戻り、macOS では閉じた socket への setsockopt が
    // EINVAL になるため（#3861）。待ちは有限の期限つき。
    let (accepted_tx, accepted_rx) = mpsc::channel::<()>();
    let h = std::thread::spawn(move || {
        let mut c = UdsStream::connect(&path, WAIT, &mut JsonLinesPeerAuthObserver::new()).unwrap();
        let _ = accepted_rx.recv_timeout(WAIT);
        let mut handler = |b: &[String]| -> Result<Vec<String>, PluginError> {
            calls.fetch_add(1, Ordering::SeqCst);
            if b.is_empty() {
                return Err(PluginError::new(PluginErrorCode::InvalidArgument, "empty"));
            }
            Ok(b.to_vec())
        };
        let _ = tx.send(serve_until(&mut c, &mut handler, &stop));
    });
    let s = l
        .accept(WAIT, &mut JsonLinesPeerAuthObserver::new())
        .unwrap();
    accepted_tx.send(()).unwrap();
    (s, rx, h)
}

#[test]
fn plug1_frame_loop_sequential_requests_then_peer_closed() {
    let dir = TempDir::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let (mut s, rx, h) = start(&dir, Arc::new(AtomicBool::new(false)), calls.clone());
    for i in 1..=3u64 {
        send(&mut s, &req(i, &["op", "x"]));
        match recv(&mut s) {
            ControlMessage::Response { id, body } => {
                assert_eq!(id.get(), i);
                assert_eq!(body, vec!["op".to_string(), "x".to_string()]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    drop(s);
    let out = rx.recv_timeout(WAIT + IDLE_POLL).expect("loop must end");
    assert_eq!(out.unwrap(), LoopExit::PeerClosed);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    h.join().unwrap();
}

#[test]
fn plug1_frame_loop_empty_body_gets_invalid_argument_and_connection_stays() {
    let dir = TempDir::new();
    let (mut s, rx, h) = start(
        &dir,
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicUsize::new(0)),
    );
    send(&mut s, &req(9, &[]));
    match recv(&mut s) {
        ControlMessage::Error { id, error } => {
            assert_eq!(id.get(), 9);
            assert_eq!(error.code(), PluginErrorCode::InvalidArgument);
        }
        other => panic!("unexpected {other:?}"),
    }
    send(&mut s, &req(10, &["ok"]));
    assert!(matches!(recv(&mut s), ControlMessage::Response { .. }));
    drop(s);
    assert_eq!(
        rx.recv_timeout(WAIT + IDLE_POLL).unwrap().unwrap(),
        LoopExit::PeerClosed
    );
    h.join().unwrap();
}

#[test]
fn plug1_repair5_frame_loop_stop_flag_while_idle_exits_within_idle_poll() {
    let dir = TempDir::new();
    let stop = Arc::new(AtomicBool::new(false));
    let (s, rx, h) = start(&dir, stop.clone(), Arc::new(AtomicUsize::new(0)));
    let t0 = Instant::now();
    stop.store(true, Ordering::SeqCst);
    let out = rx
        .recv_timeout(IDLE_POLL * 3 + WAIT)
        .expect("loop must observe the stop flag");
    assert_eq!(out.unwrap(), LoopExit::ShutdownRequested);
    assert!(t0.elapsed() < IDLE_POLL * 3, "elapsed {:?}", t0.elapsed());
    drop(s);
    h.join().unwrap();
}

#[test]
fn plug1_frame_loop_request_after_stop_flag_is_not_handled() {
    let dir = TempDir::new();
    let stop = Arc::new(AtomicBool::new(true));
    let calls = Arc::new(AtomicUsize::new(0));
    let (mut s, rx, h) = start(&dir, stop, calls.clone());
    let out = rx.recv_timeout(IDLE_POLL * 3 + WAIT).unwrap();
    assert_eq!(out.unwrap(), LoopExit::ShutdownRequested);
    // 抜けた後に送っても応答は無く、ハンドラは 1 回も呼ばれない。
    let _ = s.write_all(&req(1, &["op"]).encode());
    h.join().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn plug1_frame_loop_corrupted_header_checksum_ends_with_error() {
    let dir = TempDir::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let (mut s, rx, h) = start(&dir, Arc::new(AtomicBool::new(false)), calls.clone());
    let mut bytes = req(1, &["op"]).encode();
    if let Some(b) = bytes.get_mut(0) {
        *b ^= 0xff;
    }
    s.write_all(&bytes).unwrap();
    s.flush().unwrap();
    let out = rx.recv_timeout(WAIT + IDLE_POLL).expect("loop must end");
    let err = out.unwrap_err();
    assert_eq!(err.code(), PluginErrorCode::DataLoss);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(s);
    h.join().unwrap();
}
