//! Exec ストリーミング（SPDY/3.1・remotecommand v4）の結合試験（CRI-6・TASK-63.2・#680・REPAIR-5）。
//!
//! 実サーバー（`StreamingServer` + `ExecStreamHandler`）に loopback の TCP で接続し、クライアント側は crate の
//! `streaming::spdy` で SYN_STREAM / DATA を組む。プロセス側は注入トレイト `ExecStreamLauncher` の偽実装（メモリ内の
//! パイプ）で、crictl 相当の疎通は `tests/streaming.rs`（#683・TASK-63.5）で、本物のコンテナ・実 crictl との照合は本番 backend の結線後。クライアントは std の `TcpStream` を
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
use fandhe_container_cri::instrument::{CriOpKind, CriOpRecorder, CriOpSample};
use fandhe_container_cri::runtime::v1;
use fandhe_container_cri::streaming::exec::{
    ExecLaunch, ExecObserver, ExecSession, ExecStreamConfig, ExecStreamHandler, ExecStreamLauncher,
    ExecStreamOutcome, MSG_EXEC_INSTANCE_CHANGED, TerminalResizer,
};
use fandhe_container_cri::streaming::remotecommand::TerminalSize;
use fandhe_container_cri::streaming::spdy::{
    Frame, FrameDecoder, FrameEncoder, Headers, StreamId, goaway_status, rst_status,
};
use fandhe_container_cri::streaming::{
    StreamDispatcher, StreamRequest, StreamingConfig, StreamingServer,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tonic::Code;

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

/// 書き込みが常に失敗する stdin（backend が stdin を閉じた状況の再現）。
struct BrokenWriter;

impl AsyncWrite for BrokenWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// poll_write は全量を受理して内部に溜め、flush まで相手へ届けない stdin（BufWriter 相当。CRI-6）。
struct BufferedWriter {
    pipe: Pipe,
    held: Vec<u8>,
}

impl AsyncWrite for BufferedWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.held.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let held = std::mem::take(&mut self.held);
        if !held.is_empty() {
            self.pipe.send(&held);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.pipe.close();
        Poll::Ready(Ok(()))
    }
}

/// shutdown だけが失敗する stdin（REPAIR-4）。
struct ShutdownErrWriter;

impl AsyncWrite for ShutdownErrWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }
}

/// flush が完了しない stdin（REPAIR-5）。
struct StuckFlushWriter;

impl AsyncWrite for StuckFlushWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
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
            if program == "instance-changed" {
                return Err(CriError::failed_precondition(MSG_EXEC_INSTANCE_CHANGED));
            }
            if program == "not-running" {
                return Err(CriError::failed_precondition("container is not running"));
            }
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
                "echo-once" => {
                    // 最初の 1 塊を stdout へ返して 0 で終わる（BufWriter の flush 試験）。
                    let (stdin_p, stdout_p, cell) =
                        (stdin_p.clone(), stdout_p.clone(), cell.clone());
                    tokio::spawn(async move {
                        let chunk = stdin_p.recv().await;
                        stdout_p.send(&chunk);
                        stdout_p.close();
                        cell.set(0);
                    });
                }
                "broken-stdin" | "shutdown-err" => {
                    // stdin の書き込みは失敗するが、プロセスは少し後に 0 で終わる。
                    let (stdout_p, cell) = (stdout_p.clone(), cell.clone());
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        stdout_p.close();
                        cell.set(0);
                    });
                }
                "exit3-stuck-flush" => {
                    // flush が完了しない stdin のまま、少し後に終了コード 3 で終わる。
                    let (stdout_p, cell) = (stdout_p.clone(), cell.clone());
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        stdout_p.close();
                        cell.set(3);
                    });
                }
                "exit-no-close" => {
                    // 終了コード 0 で終わるが stdout を閉じない（drain の期限切れの再現）。
                    stdout_p.send(b"partial\n");
                    cell.set(0);
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
                stdin: req.stdin.then(|| {
                    if program == "broken-stdin" {
                        Box::new(BrokenWriter) as Box<dyn AsyncWrite + Send + Unpin>
                    } else if program == "shutdown-err" {
                        Box::new(ShutdownErrWriter) as Box<dyn AsyncWrite + Send + Unpin>
                    } else if program == "stuck-flush" || program == "exit3-stuck-flush" {
                        Box::new(StuckFlushWriter) as Box<dyn AsyncWrite + Send + Unpin>
                    } else if program == "echo-once" {
                        Box::new(BufferedWriter {
                            pipe: stdin_p,
                            held: Vec::new(),
                        }) as Box<dyn AsyncWrite + Send + Unpin>
                    } else {
                        Box::new(PipeWriter(stdin_p)) as Box<dyn AsyncWrite + Send + Unpin>
                    }
                }),
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

/// 操作別計装の記録先（種別とコードだけを保持する）。
#[derive(Default)]
struct Rec(Mutex<Vec<(CriOpKind, Code)>>);

impl CriOpRecorder for Rec {
    fn record_cri_op(&self, sample: &CriOpSample) {
        self.0
            .lock()
            .expect("lock")
            .push((sample.kind(), sample.code()));
    }
}

// ---------------------------------------------------------------------------------------------
// フィクスチャとクライアント
// ---------------------------------------------------------------------------------------------

struct Fixture {
    server: StreamingServer,
    launcher: Arc<FakeLauncher>,
    obs: Arc<Obs>,
    rec: Arc<Rec>,
}

impl Fixture {
    async fn new(config: ExecStreamConfig, max_connections: usize) -> Self {
        let launcher = Arc::new(FakeLauncher::default());
        let obs = Arc::new(Obs::default());
        let rec = Arc::new(Rec::default());
        let handler =
            ExecStreamHandler::new(Arc::clone(&launcher) as Arc<dyn ExecStreamLauncher>, config)
                .expect("handler")
                .with_observer(Arc::clone(&obs) as Arc<dyn ExecObserver>)
                .with_recorder(Arc::clone(&rec) as Arc<dyn CriOpRecorder>);
        // 共通の振り分け（StreamDispatcher）に Exec を登録する。Attach は未登録で 501 になる。
        let dispatcher = StreamDispatcher::new().with_exec(Arc::new(handler));
        let server = StreamingServer::bind_with_handler(
            StreamingConfig::default().with_max_connections(max_connections),
            Arc::new(dispatcher),
        )
        .await
        .expect("bind");
        Self {
            server,
            launcher,
            obs,
            rec,
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
            .issue(StreamRequest::exec(v1::ExecRequest {
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

    /// 計装の記録（セッションの記録が出るまで待つ。observer より後に呼ばれるため observer の後で読む）。
    fn recorded(&self) -> Vec<(CriOpKind, Code)> {
        self.rec.0.lock().expect("lock").clone()
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
    let mut config = ExecStreamConfig {
        launch_timeout: Duration::from_secs(5),
        stdin_stall_timeout: Duration::from_secs(5),
        ..ExecStreamConfig::default()
    };
    config.limits.stream_creation_timeout = Duration::from_secs(5);
    config.limits.stream_idle_timeout = Duration::from_secs(30);
    config.limits.drain_timeout = Duration::from_secs(2);
    config
}

fn sid(v: u32) -> StreamId {
    StreamId::new(v).expect("stream id")
}

struct Client {
    tcp: TcpStream,
    dec: FrameDecoder,
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
        let mut dec = FrameDecoder::new();
        dec.extend(&buf[end..]);
        let ok = head.starts_with("HTTP/1.1 101");
        let client = ok.then(|| Self {
            tcp,
            dec,
            enc: FrameEncoder::new(),
        });
        (client, head)
    }

    /// 指定のサブプロトコルだけを提示して Upgrade し、応答で選ばれた版を返す。
    fn upgrade_with_version(addr: SocketAddr, path: &str, version: &str) -> Self {
        let extra = format!(
            "Connection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: {version}\r\n"
        );
        let (client, head) = Self::connect_raw(addr, path, &extra);
        assert!(
            head.to_ascii_lowercase()
                .contains(&format!("x-stream-protocol-version: {version}")),
            "head: {head}"
        );
        client.expect("101 switching protocols")
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
            headers: {
                let mut h = Headers::new();
                h.push("streamtype", streamtype);
                h
            },
        });
    }

    fn data(&mut self, id: u32, payload: &[u8], fin: bool) {
        self.send(&Frame::Data {
            stream_id: sid(id),
            fin,
            data: payload.to_vec(),
        });
    }

    /// 次のフレーム。`None` は EOF / 切断。読み取り期限切れは失敗にする。
    fn recv(&mut self) -> Option<Frame> {
        loop {
            if let Some(frame) = self.dec.next_frame().expect("decode") {
                return Some(frame);
            }
            let mut tmp = [0u8; 16 * 1024];
            match self.tcp.read(&mut tmp) {
                Ok(0) => return None,
                Ok(n) => self.dec.extend(&tmp[..n]),
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
                    data,
                } => {
                    c.data
                        .entry(stream_id.get())
                        .or_default()
                        .extend_from_slice(&data);
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
    rst: Vec<(u32, u32)>,
    goaway: Option<u32>,
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
    assert_eq!(c.goaway, Some(goaway_status::OK));
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

/// CRI-6: v3 では成功時に error ストリームへ何も書かず FIN だけ、非 0 は終了コードの文になる（kubelet と同じ）。
#[tokio::test]
async fn cri6_exec_v3_status_is_text() {
    let fx = Fixture::new(fast_config(), 8).await;
    let ok_path = fx.exec_path(&["echo-exit", "0"], false, false, true, false);
    let ng_path = fx.exec_path(&["echo-exit", "7"], false, false, true, false);
    let addr = fx.addr();
    let (ok, ng) = tokio::task::spawn_blocking(move || {
        let run = |path: &str| {
            let mut client = Client::upgrade_with_version(addr, path, "v3.channel.k8s.io");
            client.syn(1, "error");
            client.syn(3, "stdout");
            client.expect_reply(1);
            client.expect_reply(3);
            client.collect()
        };
        (run(&ok_path), run(&ng_path))
    })
    .await
    .expect("join");
    assert_eq!(ok.text(1), "");
    assert!(ok.fins.contains(&1));
    assert_eq!(ng.text(1), "command terminated with exit code 7");
    assert_eq!(ng.goaway, Some(goaway_status::OK));
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
            let mut enc = FrameEncoder::new();
            let chunks: Vec<&[u8]> = payload.chunks(32 * 1024).collect();
            let last = chunks.len() - 1;
            for (i, chunk) in chunks.iter().enumerate() {
                let mut out = Vec::new();
                enc.encode(
                    &Frame::Data {
                        stream_id: sid(3),
                        fin: i == last,
                        data: chunk.to_vec(),
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
    let mut config = fast_config();
    config.limits.stream_creation_timeout = Duration::from_millis(200);
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
    assert_eq!(c.goaway, Some(goaway_status::OK));
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

/// CRI-6: error → resize → resize の初期サイズ DATA → stdout の順で張っても、確立前の resize が落ちない。
#[tokio::test]
async fn cri6_exec_tty_resize_data_before_all_streams_is_kept() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["tty-resize"], true, false, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "resize");
        client.data(3, b"{\"Width\":120,\"Height\":40}\n", false);
        client.syn(5, "stdout");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        client.data(3, b"{\"Width\":90,\"Height\":25}\n", false);
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(c.text(1), STATUS_SUCCESS);
    assert_eq!(
        *fx.launcher.resizes.lock().expect("lock"),
        vec![(120, 40), (90, 25)]
    );
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
        vec![
            (3, rst_status::PROTOCOL_ERROR),
            (7, rst_status::REFUSED_STREAM)
        ]
    );
    assert_eq!(c.goaway, Some(goaway_status::PROTOCOL_ERROR));
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
    let mut config = fast_config();
    config.limits.stream_idle_timeout = Duration::from_millis(300);
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
    assert_eq!(c.goaway, Some(goaway_status::OK));
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
    assert_eq!(c.goaway, Some(goaway_status::OK));
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::LaunchFailed]
    );
}

/// 起動失敗を 1 件起こして Status と記録を集める補助。
async fn run_launch_failure(cmd: &str) -> (String, Vec<ExecStreamOutcome>, Vec<(CriOpKind, Code)>) {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&[cmd], false, false, true, false);
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
    assert_eq!(c.goaway, Some(goaway_status::OK));
    let outcomes = fx.wait_outcomes(1).await;
    (c.text(1), outcomes, fx.recorded())
}

/// CRI-6・REPAIR-4・#4324: インスタンス不一致による拒否は別の結果と別の操作名で数え、
/// クライアントへは他の起動失敗と同じ内部エラーの Status のまま。
#[tokio::test]
async fn cri6_repair4_4324_instance_changed_is_distinct_outcome() {
    let (status, outcomes, recorded) = run_launch_failure("instance-changed").await;
    assert!(
        status.contains(r#""reason":"InternalError""#),
        "status: {status}"
    );
    assert!(!status.contains("recreated"), "status: {status}");
    assert_eq!(outcomes, vec![ExecStreamOutcome::InstanceChanged]);
    let count = |kind, code| recorded.iter().filter(|r| **r == (kind, code)).count();
    assert_eq!(count(CriOpKind::ExecSession, Code::FailedPrecondition), 1);
    assert_eq!(
        count(CriOpKind::ExecInstanceChanged, Code::FailedPrecondition),
        1
    );
    assert_eq!(count(CriOpKind::ExecSession, Code::Unavailable), 0);
}

/// CRI-6・REPAIR-4・#4324: 他の起動失敗（同じ `FAILED_PRECONDITION` でも文が違うものを含む）は
/// `LaunchFailed` のままで、不一致の操作名には数えない。
#[tokio::test]
async fn cri6_repair4_4324_other_launch_failures_stay_launch_failed() {
    for cmd in ["fail-launch", "not-running"] {
        let (_, outcomes, recorded) = run_launch_failure(cmd).await;
        assert_eq!(outcomes, vec![ExecStreamOutcome::LaunchFailed], "{cmd}");
        assert!(
            recorded.contains(&(CriOpKind::ExecSession, Code::Unavailable)),
            "{cmd}: {recorded:?}"
        );
        assert!(
            !recorded
                .iter()
                .any(|r| r.0 == CriOpKind::ExecInstanceChanged),
            "{cmd}: {recorded:?}"
        );
    }
}

/// CRI-6・REPAIR-3・#3753: 握手の失敗（版ヘッダ無しは 400、対応しないサブプロトコルは 403）と、
/// 未登録の種別（Attach）は URL を発行せず `UNIMPLEMENTED` になる（URL を返してから 501 にしない）。
#[tokio::test]
async fn cri6_exec_handshake_errors_and_fallback() {
    let fx = Fixture::new(fast_config(), 8).await;
    let addr = fx.addr();
    let no_upgrade = fx.exec_path(&["hang"], false, false, true, false);
    let v1_only = fx.exec_path(&["hang"], false, false, true, false);
    let attach_err = fx
        .server
        .issuer()
        .issue(StreamRequest::Attach(v1::AttachRequest {
            container_id: "c1".to_string(),
            stdin: false,
            tty: false,
            stdout: true,
            stderr: false,
        }))
        .expect_err("attach is not wired");
    assert_eq!(
        attach_err.code(),
        fandhe_container_cri::error::CriErrorCode::Unimplemented
    );
    let (a, b) = tokio::task::spawn_blocking(move || {
        let (_, a) = Client::connect_raw(addr, &no_upgrade, "Connection: close\r\n");
        let (_, b) = Client::connect_raw(
            addr,
            &v1_only,
            "Connection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: v1.channel.k8s.io\r\n",
        );
        (a, b)
    })
    .await
    .expect("join");
    assert!(a.starts_with("HTTP/1.1 400"), "a: {a}");
    assert!(b.starts_with("HTTP/1.1 403"), "b: {b}");
    assert_eq!(fx.launcher.launches.load(Ordering::SeqCst), 0);
}

/// CRI-6: stdout より前に stdin の DATA と FIN を送っても欠けずに届く（ストリーム確立前の入力の保持）。
#[tokio::test]
async fn cri6_exec_stdin_data_before_all_streams_is_kept() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["echo-exit"], false, true, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.data(3, b"early\n", true);
        client.syn(5, "stdout");
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(c.text(5), "early\n");
    assert_eq!(c.text(1), STATUS_SUCCESS);
}

/// CRI-6・REPAIR-5: 終了コード 0 でも drain の期限までに出力が閉じなければ成功にせず、失敗 Status と `OutputTruncated` にする。
#[tokio::test]
async fn cri6_exec_drain_expiry_is_not_success() {
    let mut config = fast_config();
    config.limits.drain_timeout = Duration::from_millis(200);
    let fx = Fixture::new(config, 8).await;
    let path = fx.exec_path(&["exit-no-close"], false, false, true, false);
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
    assert_ne!(c.text(1), STATUS_SUCCESS);
    assert!(c.text(1).contains("InternalError"), "{}", c.text(1));
    assert!(c.fins.contains(&3));
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::OutputTruncated]
    );
}

/// CRI-6・TASK-63.2: クライアントが stdout を RST_STREAM した後は、その ID へ DATA・FIN を送らない。
/// 他のストリーム（stderr・error）は続き、成功の Status で終わる。
#[tokio::test]
async fn cri6_exec_reset_stdout_stops_sending_to_that_stream_only() {
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
        client.data(3, b"a", false);
        // stdout の最初の DATA を確認してからリセットする。
        loop {
            match client.recv() {
                Some(Frame::Data {
                    stream_id, data, ..
                }) if stream_id == sid(5) => {
                    assert_eq!(data, b"a".to_vec());
                    break;
                }
                Some(_) => {}
                None => panic!("closed before stdout data"),
            }
        }
        client.send(&Frame::RstStream {
            stream_id: sid(5),
            status: rst_status::CANCEL,
        });
        // リセット後の入力はプロセスが stdout へ書くが、クライアントへは送られない。
        client.data(3, b"b", false);
        client.data(3, b"", true);
        client.collect()
    })
    .await
    .expect("join");
    assert!(
        !c.data.contains_key(&5),
        "DATA after RST: {:?}",
        c.data.get(&5)
    );
    assert!(!c.fins.contains(&5), "FIN after RST");
    assert_eq!(c.text(7), "bye-from-stderr\n");
    assert_eq!(c.text(1), STATUS_SUCCESS);
    assert!(c.fins.contains(&1) && c.fins.contains(&7));
    assert_eq!(c.goaway, Some(goaway_status::OK));
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::Exited { code: 0 }]
    );
}

/// CRI-6・TASK-63.2: error ストリームを RST_STREAM した後は、終了の Status もその ID へ送らない。
#[tokio::test]
async fn cri6_exec_reset_error_stream_gets_no_status() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["echo-exit"], false, true, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        client.send(&Frame::RstStream {
            stream_id: sid(1),
            status: rst_status::CANCEL,
        });
        client.data(3, b"x", true);
        client.collect()
    })
    .await
    .expect("join");
    assert!(!c.data.contains_key(&1), "DATA on reset error stream");
    assert!(!c.fins.contains(&1));
    assert_eq!(c.text(5), "x");
    assert!(c.fins.contains(&5));
    assert_eq!(c.goaway, Some(goaway_status::OK));
}

/// CRI-6・TASK-63.2: ストリームが揃う前に stdout をリセットしても、その ID へは何も送らない。
#[tokio::test]
async fn cri6_exec_reset_before_all_streams_is_honored() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["echo-exit"], false, true, true, true);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        client.send(&Frame::RstStream {
            stream_id: sid(5),
            status: rst_status::CANCEL,
        });
        client.syn(7, "stderr");
        for id in [1, 3, 5, 7] {
            client.expect_reply(id);
        }
        client.data(3, b"early", true);
        client.collect()
    })
    .await
    .expect("join");
    assert!(!c.data.contains_key(&5));
    assert!(!c.fins.contains(&5));
    assert_eq!(c.text(7), "bye-from-stderr\n");
    assert_eq!(c.text(1), STATUS_SUCCESS);
}

/// REPAIR-4・CRI-6・TASK-63.2: 正常終了では、セッションと backend・通信路の読み書きが成功として記録される。
#[tokio::test]
async fn cri6_exec_records_session_and_io_operations() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["echo-exit"], false, true, true, true);
    let addr = fx.addr();
    tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        client.syn(7, "stderr");
        for id in [1, 3, 5, 7] {
            client.expect_reply(id);
        }
        client.data(3, b"hello", true);
        client.collect()
    })
    .await
    .expect("join");
    fx.wait_outcomes(1).await;
    let mut got = fx.recorded();
    got.sort_by_key(|(k, _)| k.as_str());
    let mut want = vec![
        (CriOpKind::ExecSession, Code::Ok),
        (CriOpKind::ExecStreamRead, Code::Ok),
        (CriOpKind::ExecStreamWrite, Code::Ok),
        (CriOpKind::ExecConnRead, Code::Ok),
        (CriOpKind::ExecConnWrite, Code::Ok),
    ];
    want.sort_by_key(|(k, _)| k.as_str());
    assert_eq!(got, want);
}

/// REPAIR-4・CRI-6・TASK-63.2: stdin の書き込み失敗は、最終結果が Exited でも書き込みの失敗として記録される。
#[tokio::test]
async fn cri6_exec_records_stdin_write_failure_even_when_exited() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["broken-stdin"], false, true, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        client.data(3, b"x", false);
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(c.text(1), STATUS_SUCCESS);
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::Exited { code: 0 }]
    );
    let got = fx.recorded();
    assert!(got.contains(&(CriOpKind::ExecSession, Code::Ok)), "{got:?}");
    assert!(
        got.contains(&(CriOpKind::ExecStreamWrite, Code::Unavailable)),
        "{got:?}"
    );
    assert!(
        !got.contains(&(CriOpKind::ExecStreamWrite, Code::Ok)),
        "{got:?}"
    );
}

/// CRI-6: poll_write が全量を受理しても flush まで届かない stdin（BufWriter 相当）へ、FIN なしの短い入力が届く。
#[tokio::test]
async fn cri6_exec_stdin_is_flushed_without_fin() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["echo-once"], false, true, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        client.data(3, b"short\n", false);
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(c.text(5), "short\n");
    assert_eq!(c.text(1), STATUS_SUCCESS);
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::Exited { code: 0 }]
    );
}

/// CRI-6・REPAIR-5: flush が完了しない stdin は stdin_stall_timeout で打ち切られる。
#[tokio::test]
async fn cri6_exec_stuck_flush_hits_stdin_stall_timeout() {
    let mut config = fast_config();
    config.stdin_stall_timeout = Duration::from_millis(300);
    let fx = Fixture::new(config, 8).await;
    let path = fx.exec_path(&["stuck-flush"], false, true, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        client.data(3, b"x", false);
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(c.goaway, Some(goaway_status::OK));
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::IdleTimeout]
    );
}

/// REPAIR-4・CRI-6: stdin の shutdown が Err を返したら ExecStreamWrite を失敗として記録する。
#[tokio::test]
async fn cri6_exec_records_stdin_shutdown_failure() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["shutdown-err"], false, true, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        client.data(3, b"x", true);
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(c.text(1), STATUS_SUCCESS);
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::Exited { code: 0 }]
    );
    let got = fx.recorded();
    assert!(
        got.contains(&(CriOpKind::ExecStreamWrite, Code::Unavailable)),
        "{got:?}"
    );
    assert!(
        !got.contains(&(CriOpKind::ExecStreamWrite, Code::Ok)),
        "{got:?}"
    );
}

/// 上限（16 KiB）を超える制御フレームを送ってセッションを `ProtocolError` で閉じる。
fn finish_with_oversized_frame(client: &mut Client) -> Collected {
    client.send_raw(&[0x80, 0x03, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff]);
    client.collect()
}

/// CRI-6: 拒否した SYN_STREAM の ID も消費され、同じ ID の後続は PROTOCOL_ERROR になる（SPDY/3 §2.3.2。Attach と同じ）。
#[tokio::test]
async fn cri6_exec_rejected_stream_id_cannot_be_reused() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["hang"], false, false, true, false);
    let addr = fx.addr();
    let (c, replies) = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin"); // stdin なしの要求なので REFUSED_STREAM
        client.syn(3, "stdout"); // 拒否済みの ID の再利用
        client.syn(5, "stdout");
        let mut replies = Vec::new();
        let mut rst = Vec::new();
        while replies.len() < 2 || rst.len() < 2 {
            match client.recv().expect("frame") {
                Frame::SynReply { stream_id, .. } => replies.push(stream_id.get()),
                Frame::RstStream { stream_id, status } => rst.push((stream_id.get(), status)),
                other => panic!("unexpected {other:?}"),
            }
        }
        let mut c = finish_with_oversized_frame(&mut client);
        c.rst = rst;
        (c, replies)
    })
    .await
    .expect("join");
    assert_eq!(replies, vec![1, 5]);
    assert_eq!(
        c.rst,
        vec![
            (3, rst_status::REFUSED_STREAM),
            (3, rst_status::PROTOCOL_ERROR)
        ]
    );
}

/// CRI-6: stdin の FIN 後の DATA は STREAM_ALREADY_CLOSED の RST_STREAM で拒否する（Attach と同じ）。
#[tokio::test]
async fn cri6_exec_data_after_stdin_fin_is_rejected() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["hang"], false, true, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        client.data(3, b"a", true);
        client.data(3, b"b", false);
        finish_with_oversized_frame(&mut client)
    })
    .await
    .expect("join");
    assert_eq!(c.rst, vec![(3, rst_status::STREAM_ALREADY_CLOSED)]);
    assert_eq!(c.goaway, Some(goaway_status::PROTOCOL_ERROR));
}

/// CRI-6: 組が揃う前（SYN_STREAM と同時に届く場合を含む）の FIN 後の DATA も同じく拒否する。
#[tokio::test]
async fn cri6_exec_data_after_stdin_fin_is_rejected_when_sent_with_syn() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["hang"], false, true, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.data(3, b"a", true);
        client.data(3, b"b", false);
        client.syn(5, "stdout");
        finish_with_oversized_frame(&mut client)
    })
    .await
    .expect("join");
    assert_eq!(c.rst, vec![(3, rst_status::STREAM_ALREADY_CLOSED)]);
}

/// CRI-6: RST_STREAM 済みの stdin への DATA は無視し、追加の RST_STREAM を返さない。
#[tokio::test]
async fn cri6_exec_data_after_stdin_reset_is_ignored() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["hang"], false, true, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        client.send(&Frame::RstStream {
            stream_id: sid(3),
            status: rst_status::CANCEL,
        });
        client.data(3, b"x", false);
        finish_with_oversized_frame(&mut client)
    })
    .await
    .expect("join");
    assert_eq!(c.rst, Vec::<(u32, u32)>::new());
    assert_eq!(c.goaway, Some(goaway_status::PROTOCOL_ERROR));
}

/// REPAIR-5・CRI-6: flush が完了しない stdin へ stdin_stall_timeout より短い間隔で DATA を送り続けても、
/// 期限（300ms）の規定時間内に打ち切られる（flush 待ちの間は追加の stdin を読まず、期限もリセットされない）。
#[tokio::test]
async fn cri6_exec_stuck_flush_not_extended_by_continuous_stdin() {
    let mut config = fast_config();
    config.stdin_stall_timeout = Duration::from_millis(300);
    let fx = Fixture::new(config, 8).await;
    let path = fx.exec_path(&["stuck-flush"], false, true, true, false);
    let addr = fx.addr();
    let started = Instant::now();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        // 100ms 間隔で最大 3 秒送る。サーバーが閉じたら書き込みが失敗して止まる。
        let mut tcp = client.tcp.try_clone().expect("clone");
        let sender = std::thread::spawn(move || {
            let mut enc = FrameEncoder::new();
            for _ in 0..30 {
                let mut out = Vec::new();
                enc.encode(
                    &Frame::Data {
                        stream_id: sid(3),
                        fin: false,
                        data: b"x".to_vec(),
                    },
                    &mut out,
                )
                .expect("encode");
                if tcp.write_all(&out).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let c = client.collect();
        let _ = sender.join();
        c
    })
    .await
    .expect("join");
    assert_eq!(c.goaway, Some(goaway_status::OK));
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::IdleTimeout]
    );
    assert!(
        started.elapsed() < Duration::from_millis(2000),
        "elapsed {:?}",
        started.elapsed()
    );
}

const STATUS_TIMEOUT_V4: &str = r#"{"metadata":{},"status":"Failure","message":"command execution timed out","reason":"Timeout","code":504}"#;
const STATUS_TIMEOUT_TEXT: &str = "command execution timed out";

/// CRI-6・REPAIR-5: idle の期限切れでも error ストリームへ Failure の Status を送ってから FIN・GOAWAY で閉じる。
/// 結末は `IdleTimeout` のまま。v4 は JSON、v3 はテキスト。
#[tokio::test]
async fn cri6_exec_idle_timeout_notifies_failure_status() {
    for (version, expected) in [
        ("v4.channel.k8s.io", STATUS_TIMEOUT_V4),
        ("v3.channel.k8s.io", STATUS_TIMEOUT_TEXT),
    ] {
        let mut config = fast_config();
        config.limits.stream_idle_timeout = Duration::from_millis(300);
        let fx = Fixture::new(config, 8).await;
        let path = fx.exec_path(&["hang"], false, false, true, false);
        let addr = fx.addr();
        let c = tokio::task::spawn_blocking(move || {
            let mut client = Client::upgrade_with_version(addr, &path, version);
            client.syn(1, "error");
            client.syn(3, "stdout");
            client.expect_reply(1);
            client.expect_reply(3);
            client.collect()
        })
        .await
        .expect("join");
        assert_eq!(c.text(1), expected, "{version}");
        assert!(c.fins.contains(&1) && c.fins.contains(&3), "{version}");
        assert_eq!(c.goaway, Some(goaway_status::OK), "{version}");
        assert_eq!(
            fx.wait_outcomes(1).await,
            vec![ExecStreamOutcome::IdleTimeout],
            "{version}"
        );
    }
}

/// CRI-6・REPAIR-5: stdin_stall_timeout での打ち切りでも error ストリームへ Failure の Status を送ってから閉じる。
#[tokio::test]
async fn cri6_exec_stdin_stall_timeout_notifies_failure_status() {
    for (version, expected) in [
        ("v4.channel.k8s.io", STATUS_TIMEOUT_V4),
        ("v2.channel.k8s.io", STATUS_TIMEOUT_TEXT),
    ] {
        let mut config = fast_config();
        config.stdin_stall_timeout = Duration::from_millis(300);
        let fx = Fixture::new(config, 8).await;
        let path = fx.exec_path(&["stuck-flush"], false, true, true, false);
        let addr = fx.addr();
        let c = tokio::task::spawn_blocking(move || {
            let mut client = Client::upgrade_with_version(addr, &path, version);
            client.syn(1, "error");
            client.syn(3, "stdin");
            client.syn(5, "stdout");
            for id in [1, 3, 5] {
                client.expect_reply(id);
            }
            client.data(3, b"x", false);
            client.collect()
        })
        .await
        .expect("join");
        assert_eq!(c.text(1), expected, "{version}");
        assert!(c.fins.contains(&1) && c.fins.contains(&5), "{version}");
        assert_eq!(c.goaway, Some(goaway_status::OK), "{version}");
        assert_eq!(
            fx.wait_outcomes(1).await,
            vec![ExecStreamOutcome::IdleTimeout],
            "{version}"
        );
    }
}

/// CRI-6・REPAIR-5: flush 待ちの stdin の間にプロセスが終了コード 3 で終わったら、期限切れ（Timeout）ではなく
/// 実際の終了コードの Status（v4 の NonZeroExitCode）と `Exited { code: 3 }` を返す。
#[tokio::test]
async fn cri6_exec_exit_wins_over_stdin_stall_timeout() {
    let mut config = fast_config();
    config.stdin_stall_timeout = Duration::from_millis(600);
    let fx = Fixture::new(config, 8).await;
    let path = fx.exec_path(&["exit3-stuck-flush"], false, true, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.syn(5, "stdout");
        for id in [1, 3, 5] {
            client.expect_reply(id);
        }
        client.data(3, b"x", false);
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(
        c.text(1),
        r#"{"metadata":{},"status":"Failure","message":"command terminated with non-zero exit code: command terminated with exit code 3","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"3"}]}}"#
    );
    assert_eq!(c.goaway, Some(goaway_status::OK));
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::Exited { code: 3 }]
    );
}

/// CRI-6: 拒否された FIN 付きの再送 SYN_STREAM（stdin の ID の再利用）は early の FIN を立てず、
/// その後の正当な stdin DATA がプロセスへ届く。
#[tokio::test]
async fn cri6_exec_rejected_fin_syn_does_not_close_early_stdin() {
    let fx = Fixture::new(fast_config(), 8).await;
    let path = fx.exec_path(&["echo-once"], false, true, true, false);
    let addr = fx.addr();
    let c = tokio::task::spawn_blocking(move || {
        let mut client = Client::upgrade(addr, &path);
        client.syn(1, "error");
        client.syn(3, "stdin");
        client.send(&Frame::SynStream {
            stream_id: sid(3),
            associated_to: 0,
            priority: 0,
            fin: true,
            unidirectional: false,
            headers: {
                let mut h = Headers::new();
                h.push("streamtype", "stdin");
                h
            },
        });
        client.data(3, b"ok\n", false);
        client.syn(5, "stdout");
        client.collect()
    })
    .await
    .expect("join");
    assert_eq!(c.rst, vec![(3, rst_status::PROTOCOL_ERROR)]);
    assert_eq!(c.text(5), "ok\n");
    assert_eq!(c.text(1), STATUS_SUCCESS);
    assert_eq!(
        fx.wait_outcomes(1).await,
        vec![ExecStreamOutcome::Exited { code: 0 }]
    );
}
