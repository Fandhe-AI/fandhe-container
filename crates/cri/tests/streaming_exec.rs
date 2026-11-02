//! Exec ストリーミング（SPDY/3.1・remotecommand v4）の結合試験（CRI-6・TASK-63.2・#680・REPAIR-5）。
//!
//! 実サーバー（`StreamingServer` + `ExecStreamHandler`）に loopback の TCP で接続し、クライアント側は crate の
//! `streaming::spdy` で SYN_STREAM / DATA を組む。プロセス側は注入トレイト `ExecStreamLauncher` の偽実装（メモリ内の
//! パイプ）で、本物のコンテナ・crictl との疎通は #683（TASK-63.5）の範囲。クライアントは std の `TcpStream` を
//! `spawn_blocking` で回す（読み取りに期限を付け、ハングは失敗にする）。トークンの乱数源が unix のみのため全体を
//! `cfg(unix)` にする。

#![cfg(unix)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::{Future, poll_fn};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1;
use fandhe_container_cri::streaming::exec::{
    ExecLaunch, ExecObserver, ExecSession, ExecStreamConfig, ExecStreamHandler, ExecStreamLauncher,
    ExecStreamOutcome, TerminalResizer, TerminalSize,
};
use fandhe_container_cri::streaming::spdy::{
    Frame, FrameEncoder, GoAwayStatus, Header, HeaderDecompressor, RstStatus, StreamId,
    decode_frame,
};
use fandhe_container_cri::streaming::{StreamRequest, StreamingConfig, StreamingServer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const STATUS_SUCCESS: &str = r#"{"metadata":{},"status":"Success"}"#;

// ---------------------------------------------------------------------------------------------
// 偽のプロセス（メモリ内パイプ）
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct PipeInner {
    buf: VecDeque<u8>,
    closed: bool,
    waker: Option<Waker>,
}

#[derive(Clone, Default)]
struct Pipe(Arc<Mutex<PipeInner>>);

impl Pipe {
    fn send(&self, data: &[u8]) {
        let mut g = self.0.lock().expect("lock");
        g.buf.extend(data.iter().copied());
        if let Some(w) = g.waker.take() {
            w.wake();
        }
    }

    fn close(&self) {
        let mut g = self.0.lock().expect("lock");
        g.closed = true;
        if let Some(w) = g.waker.take() {
            w.wake();
        }
    }

    /// 溜まった分を返す。空の Vec は EOF。
    async fn recv(&self) -> Vec<u8> {
        poll_fn(|cx| {
            let mut g = self.0.lock().expect("lock");
            if !g.buf.is_empty() {
                Poll::Ready(g.buf.drain(..).collect())
            } else if g.closed {
                Poll::Ready(Vec::new())
            } else {
                g.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }
}

struct PipeReader(Pipe);

impl AsyncRead for PipeReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut g = self.0.0.lock().expect("lock");
        if !g.buf.is_empty() {
            let n = g.buf.len().min(buf.remaining());
            let chunk: Vec<u8> = g.buf.drain(..n).collect();
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        } else if g.closed {
            Poll::Ready(Ok(()))
        } else {
            g.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

struct PipeWriter(Pipe);

impl AsyncWrite for PipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.send(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.0.close();
        Poll::Ready(Ok(()))
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        self.0.close();
    }
}

#[derive(Default)]
struct ExitInner {
    code: Option<i32>,
    waker: Option<Waker>,
}

#[derive(Clone, Default)]
struct ExitCell(Arc<Mutex<ExitInner>>);

impl ExitCell {
    fn set(&self, code: i32) {
        let mut g = self.0.lock().expect("lock");
        g.code = Some(code);
        if let Some(w) = g.waker.take() {
            w.wake();
        }
    }
}

/// 終了コードを待つ future。drop を記録する（セッションの後始末の契約の照合）。
struct ExitWait {
    cell: ExitCell,
    dropped: Arc<AtomicBool>,
}

impl Future for ExitWait {
    type Output = Result<i32, CriError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut g = self.cell.0.lock().expect("lock");
        match g.code {
            Some(code) => Poll::Ready(Ok(code)),
            None => {
                g.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl Drop for ExitWait {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct RecordingResizer(Arc<Mutex<Vec<(u16, u16)>>>);

impl TerminalResizer for RecordingResizer {
    fn resize(&mut self, size: TerminalSize) -> Result<(), CriError> {
        self.0.lock().expect("lock").push((size.width, size.height));
        Ok(())
    }
}

#[derive(Default)]
struct FakeLauncher {
    launches: AtomicUsize,
    dropped: Arc<AtomicBool>,
    resizes: Arc<Mutex<Vec<(u16, u16)>>>,
    last: Mutex<Option<ExecLaunch>>,
}

impl ExecStreamLauncher for FakeLauncher {
    fn launch(
        &self,
        req: ExecLaunch,
    ) -> Pin<Box<dyn Future<Output = Result<ExecSession, CriError>> + Send + '_>> {
        Box::pin(async move {
            self.launches.fetch_add(1, Ordering::SeqCst);
            *self.last.lock().expect("lock") = Some(req.clone());
            let program = req.cmd.first().cloned().unwrap_or_default();
            if program == "fail-launch" {
                return Err(CriError::internal("secret-path /var/lib/fandhe/x"));
            }
            let (stdin_p, stdout_p, stderr_p) = (Pipe::default(), Pipe::default(), Pipe::default());
            let cell = ExitCell::default();
            match program.as_str() {
                "echo-exit" => {
                    let code = req
                        .cmd
                        .get(1)
                        .and_then(|c| c.parse::<i32>().ok())
                        .unwrap_or(0);
                    let (stdin_p, stdout_p, stderr_p, cell) = (
                        stdin_p.clone(),
                        stdout_p.clone(),
                        stderr_p.clone(),
                        cell.clone(),
                    );
                    let (has_stdin, has_stderr) = (req.stdin, req.stderr);
                    tokio::spawn(async move {
                        if has_stdin {
                            loop {
                                let chunk = stdin_p.recv().await;
                                if chunk.is_empty() {
                                    break;
                                }
                                stdout_p.send(&chunk);
                            }
                        }
                        if has_stderr {
                            stderr_p.send(b"bye-from-stderr\n");
                        }
                        stdout_p.close();
                        stderr_p.close();
                        cell.set(code);
                    });
                }
                "tty-resize" => {
                    let (stdout_p, cell, resizes) =
                        (stdout_p.clone(), cell.clone(), Arc::clone(&self.resizes));
                    tokio::spawn(async move {
                        stdout_p.send(b"ready\n");
                        for _ in 0..500 {
                            if resizes.lock().expect("lock").len() >= 2 {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        stdout_p.send(b"ok\n");
                        stdout_p.close();
                        cell.set(0);
                    });
                }
                _ => {} // "hang": 終了しない。
            }
            Ok(ExecSession {
                stdin: req
                    .stdin
                    .then(|| Box::new(PipeWriter(stdin_p)) as Box<dyn AsyncWrite + Send + Unpin>),
                stdout: req
                    .stdout
                    .then(|| Box::new(PipeReader(stdout_p)) as Box<dyn AsyncRead + Send + Unpin>),
                stderr: req
                    .stderr
                    .then(|| Box::new(PipeReader(stderr_p)) as Box<dyn AsyncRead + Send + Unpin>),
                exit: Box::pin(ExitWait {
                    cell,
                    dropped: Arc::clone(&self.dropped),
                }),
                resize: req.tty.then(|| {
                    Box::new(RecordingResizer(Arc::clone(&self.resizes)))
                        as Box<dyn TerminalResizer>
                }),
            })
        })
    }
}

#[derive(Default)]
struct Obs(Mutex<Vec<ExecStreamOutcome>>);

impl ExecObserver for Obs {
    fn observe(&self, outcome: ExecStreamOutcome, _elapsed: Duration) {
        self.0.lock().expect("lock").push(outcome);
    }
}

// ---------------------------------------------------------------------------------------------
// フィクスチャとクライアント
// ---------------------------------------------------------------------------------------------

struct Fixture {
    server: StreamingServer,
    launcher: Arc<FakeLauncher>,
    obs: Arc<Obs>,
}

impl Fixture {
    async fn new(config: ExecStreamConfig, max_connections: usize) -> Self {
        let launcher = Arc::new(FakeLauncher::default());
        let obs = Arc::new(Obs::default());
        let handler =
            ExecStreamHandler::new(Arc::clone(&launcher) as Arc<dyn ExecStreamLauncher>, config)
                .expect("handler")
                .with_observer(Arc::clone(&obs) as Arc<dyn ExecObserver>);
        let server = StreamingServer::bind_with_handler(
            StreamingConfig::default().with_max_connections(max_connections),
            Arc::new(handler),
        )
        .await
        .expect("bind");
        Self {
            server,
            launcher,
            obs,
        }
    }

    fn addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    fn exec_path(
        &self,
        cmd: &[&str],
        tty: bool,
        stdin: bool,
        stdout: bool,
        stderr: bool,
    ) -> String {
        let url = self
            .server
            .issuer()
            .issue(StreamRequest::Exec(v1::ExecRequest {
                container_id: "c1".to_string(),
                cmd: cmd.iter().map(|s| s.to_string()).collect(),
                tty,
                stdin,
                stdout,
                stderr,
            }))
            .expect("issue");
        let rest = url.strip_prefix("http://").expect("http url");
        rest[rest.find('/').expect("path")..].to_string()
    }

    async fn wait_outcomes(&self, n: usize) -> Vec<ExecStreamOutcome> {
        let start = Instant::now();
        loop {
            let got = self.obs.0.lock().expect("lock").clone();
            if got.len() >= n {
                return got;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "outcome timeout: {got:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn wait_dropped(&self) {
        let start = Instant::now();
        while !self.launcher.dropped.load(Ordering::SeqCst) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "session was not dropped"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

fn fast_config() -> ExecStreamConfig {
    ExecStreamConfig {
        stream_creation_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(30),
        launch_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(2),
    }
}

fn sid(v: u32) -> StreamId {
    StreamId::new(v).expect("stream id")
}

struct Client {
    tcp: TcpStream,
    rbuf: Vec<u8>,
    dec: HeaderDecompressor,
    enc: FrameEncoder,
}

impl Client {
    /// Upgrade の要求を送り、応答ヘッダ（先頭部分の文字列）と接続済みのクライアントを返す。
    fn connect_raw(addr: SocketAddr, path: &str, extra: &str) -> (Option<Self>, String) {
        let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
        tcp.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let req = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n");
        let _ = tcp.write_all(req.as_bytes());
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let head_end = loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break Some(i + 4);
            }
            match tcp.read(&mut tmp) {
                Ok(0) | Err(_) => break None,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
            }
        };
        let Some(end) = head_end else {
            return (None, String::from_utf8_lossy(&buf).into_owned());
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        let rbuf = buf[end..].to_vec();
        let ok = head.starts_with("HTTP/1.1 101");
        let client = ok.then(|| Self {
            tcp,
            rbuf,
            dec: HeaderDecompressor::new(),
            enc: FrameEncoder::new().expect("encoder"),
        });
        (client, head)
    }

    fn upgrade(addr: SocketAddr, path: &str) -> Self {
        let (client, head) = Self::connect_raw(
            addr,
            path,
            "Connection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: v5.channel.k8s.io, v4.channel.k8s.io\r\n",
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("x-stream-protocol-version: v4.channel.k8s.io"),
            "head: {head}"
        );
        assert!(
            head.to_ascii_lowercase().contains("upgrade: spdy/3.1"),
            "head: {head}"
        );
        client.expect("101 switching protocols")
    }

    fn send(&mut self, frame: &Frame) {
        let mut out = Vec::new();
        self.enc.encode(frame, &mut out).expect("encode");
        self.tcp.write_all(&out).expect("write");
    }

    fn send_raw(&mut self, bytes: &[u8]) {
        self.tcp.write_all(bytes).expect("write");
    }

    fn syn(&mut self, id: u32, streamtype: &str) {
        self.send(&Frame::SynStream {
            stream_id: sid(id),
            associated_to: 0,
            priority: 0,
            fin: false,
            unidirectional: false,
            headers: vec![Header {
                name: "streamtype".to_string(),
                value: streamtype.to_string(),
            }],
        });
    }

    fn data(&mut self, id: u32, payload: &[u8], fin: bool) {
        self.send(&Frame::Data {
            stream_id: sid(id),
            fin,
            payload: payload.to_vec(),
        });
    }

    /// 次のフレーム。`None` は EOF / 切断。読み取り期限切れは失敗にする。
    fn recv(&mut self) -> Option<Frame> {
        loop {
            if let Some((frame, used)) = decode_frame(&self.rbuf, &mut self.dec).expect("decode") {
                self.rbuf.drain(..used);
                return Some(frame);
            }
            let mut tmp = [0u8; 16 * 1024];
            match self.tcp.read(&mut tmp) {
                Ok(0) => return None,
                Ok(n) => self.rbuf.extend_from_slice(&tmp[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::TimedOut
                        || e.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    panic!("read timed out (hang)")
                }
                Err(_) => return None,
            }
        }
    }

    fn expect_reply(&mut self, id: u32) {
        match self.recv() {
            Some(Frame::SynReply { stream_id, .. }) => assert_eq!(stream_id, sid(id)),
            other => panic!("expected SYN_REPLY {id}, got {other:?}"),
        }
    }

    /// GOAWAY か EOF まで集める。
    fn collect(&mut self) -> Collected {
        let mut c = Collected::default();
        while let Some(frame) = self.recv() {
            match frame {
                Frame::Data {
                    stream_id,
                    fin,
                    payload,
                } => {
                    c.data
                        .entry(stream_id.get())
                        .or_default()
                        .extend_from_slice(&payload);
                    if fin {
                        c.fins.insert(stream_id.get());
                    }
                }
                Frame::RstStream { stream_id, status } => c.rst.push((stream_id.get(), status)),
                Frame::GoAway { status, .. } => {
                    c.goaway = Some(status);
                    break;
                }
                _ => {}
            }
        }
        c
    }
}

#[derive(Default)]
struct Collected {
    data: HashMap<u32, Vec<u8>>,
    fins: HashSet<u32>,
    rst: Vec<(u32, RstStatus)>,
    goaway: Option<GoAwayStatus>,
}

impl Collected {
    fn text(&self, id: u32) -> String {
        String::from_utf8_lossy(self.data.get(&id).map(Vec::as_slice).unwrap_or(&[])).into_owned()
    }
}

// ---------------------------------------------------------------------------------------------
// シナリオ
// ---------------------------------------------------------------------------------------------

/// CRI-6（受け入れ条件）: tty なしで stdin・stdout・stderr を双方向に送受信でき、成功の Status・FIN・GOAWAY で終わる。
#[tokio::test]
async fn cri6_exec_bidirectional_stdio_and_success_status() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["echo-exit"], false, true, true, true);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        client.syn(7, "stderr");
        for id in [1, 3, 5, 7] {
            client.expect_reply(id);
        }
        client.data(3, b"hello\n", true);
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(c.text(5), "hello\n");
    assert_eq!(c.text(7), "bye-from-stderr\n");
    assert_eq!(c.text(1), STATUS_SUCCESS);
    for id in [1, 5, 7] {
        assert!(c.fins.contains(&id), "FIN on stream {id}");
    }
    assert_eq!(c.goaway, Some(GoAwayStatus::Ok));
    assert_eq!(fx.launcher.launches.load(Ordering::SeqCst), 1);
    let launch = fx
        .launcher
        .last
        .lock()
        .expect("lock")
        .clone()
        .expect("launch");
    assert_eq!(launch.container_id, "c1");
    assert_eq!(launch.cmd, vec!["echo-exit".to_string()]);
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::Exited { code: 0 }]
    );
    fx.wait_dropped().await;
}

/// CRI-6: 非 0 終了は NonZeroExitCode の Status で、cause の message に終了コードが入る。
#[tokio::test]
async fn cri6_exec_non_zero_exit_status() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["echo-exit", "3"], false, false, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdout");
        client.expect_reply(1);
        client.expect_reply(3);
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(
        c.text(1),
        r#"{"metadata":{},"status":"Failure","message":"command terminated with non-zero exit code: command terminated with exit code 3","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"3"}]}}"#
    );
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::Exited { code: 3 }]
    );
}

/// CRI-6・REPAIR-2: 64 KiB（SPDY の初期窓）を超える 256 KiB の stdin が欠けず往復する（窓に従わない判断の回帰）。
#[tokio::test]
async fn cri6_exec_large_stdin_roundtrip_beyond_window() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["echo-exit"], false, true, true, false);
    let addr = fx.addr();
    let payload: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        // 受信を止めないよう、送信は別スレッド（DATA はヘッダ圧縮を使わないので別の符号化器でよい）。
        let mut writer = client.tcp.try_clone().expect("clone");
        let sender = std::thread::spawn(move || {
            let mut enc = FrameEncoder::new().expect("encoder");
            let chunks: Vec<&[u8]> = payload.chunks(32 * 1024).collect();
            let last = chunks.len() - 1;
            for (i, chunk) in chunks.iter().enumerate() {
                let mut out = Vec::new();
                enc.encode(
                    &Frame::Data {
                        stream_id: sid(3),
                        fin: i == last,
                        payload: chunk.to_vec(),
                    },
                    &mut out,
                )
                .expect("encode");
                writer.write_all(&out).expect("write");
            }
        });
        let c = client.collect();
        sender.join().expect("sender");
        c
    })
    .await
    .expect("join");
    assert_eq!(c.data.get(&5).map(Vec::len), Some(expected.len()));
    assert_eq!(c.data.get(&5), Some(&expected));
    assert_eq!(c.text(1), STATUS_SUCCESS);
}

/// CRI-6・REPAIR-5: ストリームを作らずに待つと閉じられ、launcher は呼ばれず、`StreamCreationTimeout` になる。
#[tokio::test]
async fn cri6_exec_stream_creation_timeout() {
    let config = ExecStreamConfig {
        stream_creation_timeout: Duration::from_millis(200),
        ..fast_config()
    };
    let fx = Fixture::new(config, 8).await;
    let path = fx.exec_path(&["hang"], false, false, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.expect_reply(1);
        // stdout を作らない。
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(c.goaway, Some(GoAwayStatus::Ok));
    assert_eq!(fx.launcher.launches.load(Ordering::SeqCst), 0);
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::StreamCreationTimeout]
    );
}

/// CRI-6: tty では stdout と resize を使い、resize の JSON が端末サイズとして launcher に届く。
#[tokio::test]
async fn cri6_exec_tty_resize() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["tty-resize"], true, false, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdout");
        client.syn(5, "resize");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        client.data(
            5,
            b"{\"Width\":80,\"Height\":24}\n{\"Width\":100,\"Height\":30}\n",
            false,
        );
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(c.text(3), "ready\nok\n");
    assert_eq!(c.text(1), STATUS_SUCCESS);
    assert_eq!(
        *fx.launcher.resizes.lock().expect("lock"),
        vec![(80, 24), (100, 30)]
    );
    let launch = fx
        .launcher
        .last
        .lock()
        .expect("lock")
        .clone()
        .expect("launch");
    assert!(launch.tty && !launch.stderr);
}

/// CRI-6・REPAIR-5: 想定外の streamType と重複は RST_STREAM、上限を超える長さのフレームは `ProtocolError` で閉じる。
#[tokio::test]
async fn cri6_exec_rejects_unexpected_streams_and_oversized_frames() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["hang"], false, false, true, false);
    let addr = fx.addr();
    let (c, replies) = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "bogus");
        client.syn(5, "stdout");
        client.syn(7, "stdout");
        let mut replies = Vec::new();
        let mut rst = Vec::new();
        while replies.len() < 2 || rst.len() < 2 {
            match client.recv().expect("frame") {
                Frame::SynReply { stream_id, .. } => replies.push(stream_id.get()),
                Frame::RstStream { stream_id, status } => rst.push((stream_id.get(), status)),
                other => panic!("unexpected {other:?}"),
            }
        }
        // 制御フレームの長さが上限（16 KiB）を超える。
        client.send_raw(&[0x80, 0x03, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff]);
        let mut c = client.collect();
        c.rst = rst;
        (c, replies)
    })
    .await
    .expect("join");
    assert_eq!(replies, vec![1, 5]);
    assert_eq!(
        c.rst,
        vec![(3, RstStatus::ProtocolError), (7, RstStatus::RefusedStream)]
    );
    assert_eq!(c.goaway, Some(GoAwayStatus::ProtocolError));
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::ProtocolError]
    );
    fx.wait_dropped().await;
}

/// CRI-6・REPAIR-5: 実行中にクライアントが切断すると、セッションが drop され（プロセスを止める契約）`PeerClosed` になる。
#[tokio::test]
async fn cri6_exec_peer_close_drops_session() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["hang"], false, false, true, false);
    let addr = fx.addr();
    let launcher = Arc::clone(&fx.launcher);
    tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdout");
        client.expect_reply(1);
        client.expect_reply(3);
        let start = Instant::now();
        while launcher.launches.load(Ordering::SeqCst) == 0 {
            assert!(start.elapsed() < Duration::from_secs(5), "launch timeout");
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(client);
    })
    .await
    .expect("join");
    fx.wait_dropped().await;
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::PeerClosed]
    );
}

/// CRI-6・REPAIR-5: 入出力が途絶えると idle の期限で閉じ、`IdleTimeout` になる。
#[tokio::test]
async fn cri6_exec_idle_timeout() {
    let config = ExecStreamConfig {
        idle_timeout: Duration::from_millis(300),
        ..fast_config()
    };
    let fx = Fixture::new(config, 8).await;
    let path = fx.exec_path(&["hang"], false, false, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdout");
        client.expect_reply(1);
        client.expect_reply(3);
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(c.goaway, Some(GoAwayStatus::Ok));
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::IdleTimeout]
    );
    fx.wait_dropped().await;
}

/// CRI-6・REPAIR-5: Exec のセッションが続く間は同時接続数の枠が返らず、終わった後は再び受け付ける。
#[tokio::test]
async fn cri6_exec_holds_connection_permit_while_session_lives() {
    let fx = Fixture::new(fast_config(), 1).await;
    let addr = fx.addr();
    let first_path = fx.exec_path(&["hang"], false, false, true, false);
    let second_path = fx.exec_path(&["hang"], false, false, true, false);
    // 枠が返るのは非同期なので、再試行用に新しいトークンを複数用意する。
    let third_paths: Vec<String> = (0..50)
        .map(|_| fx.exec_path(&["hang"], false, false, true, false))
        .collect();
    tokio::task::spawn_blocking(move || {
        let upgrade = "Connection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: v4.channel.k8s.io\r\n";
        let mut first = Client::upgrade(addr, &first_path);
        first.syn(1, "error");
        first.syn(3, "stdout");
        first.expect_reply(1);
        first.expect_reply(3);
        // 枠が 1 つしか無いので、2 本目は 101 を得られず閉じられる。
        let (second, _head) = Client::connect_raw(addr, &second_path, upgrade);
        assert!(second.is_none(), "second connection must be rejected");
        drop(first);
        let mut accepted = false;
        for path in &third_paths {
            let (third, _) = Client::connect_raw(addr, path, upgrade);
            if third.is_some() {
                accepted = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(accepted, "permit was never released after the session ended");
    })
    .await
    .expect("join");
}

/// CRI-6: 起動に失敗したら内部エラーの Status を返し、内部の詳細（パス等）を漏らさない。
#[tokio::test]
async fn cri6_exec_launch_failure_hides_details() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["fail-launch"], false, false, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdout");
        client.expect_reply(1);
        client.expect_reply(3);
        client.collect()
    })
    .await
    .expect("join");
    let status = c.text(1);
    assert!(
        status.contains(r#""reason":"InternalError""#),
        "status: {status}"
    );
    assert!(!status.contains("secret-path"), "status: {status}");
    assert!(!status.contains("/var/lib"), "status: {status}");
    assert_eq!(c.goaway, Some(GoAwayStatus::Ok));
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::LaunchFailed]
    );
}

/// CRI-6: 握手の失敗（Upgrade ヘッダ無しは 400、対応しないサブプロトコルは 403）と、Exec 以外の種別は 501 になる。
#[tokio::test]
async fn cri6_exec_handshake_errors_and_fallback() {
    let fx = Fixture::new(fast_config(), 8).await;
    let addr = fx.addr();
    let no_upgrade = fx.exec_path(&["hang"], false, false, true, false);
    let v3_only = fx.exec_path(&["hang"], false, false, true, false);
    let attach_url = fx
        .server
        .issuer()
        .issue(StreamRequest::Attach(v1::AttachRequest {
            container_id: "c1".to_string(),
            stdin: false,
            tty: false,
            stdout: true,
            stderr: false,
        }))
        .expect("issue attach");
    let attach_path = attach_url[attach_url.find("/attach/").expect("attach path")..].to_string();
    let (a, b, c) = tokio::task::spawn_blocking(move || {
        let (_, a) = Client::connect_raw(addr, &no_upgrade, "Connection: close\r\n");
        let (_, b) = Client::connect_raw(
            addr,
            &v3_only,
            "Connection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: v3.channel.k8s.io\r\n",
        );
        let (_, c) = Client::connect_raw(
            addr,
            &attach_path,
            "Connection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: v4.channel.k8s.io\r\n",
        );
        (a, b, c)
    })
    .await
    .expect("join");
    assert!(a.starts_with("HTTP/1.1 400"), "a: {a}");
    assert!(b.starts_with("HTTP/1.1 403"), "b: {b}");
    assert!(c.starts_with("HTTP/1.1 501"), "c: {c}");
    assert_eq!(fx.launcher.launches.load(Ordering::SeqCst), 0);
}
