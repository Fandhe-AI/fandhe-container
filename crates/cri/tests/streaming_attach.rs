//! Attach の SPDY/3.1 ストリーミングの結合試験（CRI-6・TASK-63.3・#681）。
//!
//! loopback の TCP だけで完結し、root も外部ネットワークも要らない。クライアントは本 crate の公開 codec
//! （`streaming::spdy`）で組んだ最小の SPDY クライアントで、サーバーと同じ codec を使うため「codec の自己照合」
//! である（他実装との互換は `spdy` の単体試験が CPython の zlib が作ったブロックの復号で固定している）。
//! crictl 相当の疎通は `tests/streaming.rs`（#683・TASK-63.5）。実クライアントとの照合は本番 backend の結線後。コンテナ側の stdio は
//! `UnixStream::pair()` の fake backend で与える。各試験は期限つきで書き、ハングしない（REPAIR-5）。
//! トークンの乱数源が unix のみのため、全体を `cfg(unix)` にする。
#![cfg(unix)]

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_cri::error::{CriError, CriErrorCode};
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use fandhe_container_cri::streaming::attach::{
    AttachBackend, AttachHandler, AttachSession, AttachTarget,
};
use fandhe_container_cri::streaming::remotecommand::TerminalSize;
use fandhe_container_cri::streaming::spdy::{
    Frame, FrameDecoder, FrameEncoder, Headers, StreamId, goaway_status, rst_status,
};
use fandhe_container_cri::streaming::{StreamDispatcher, StreamingConfig, StreamingServer};
use tonic::Request;

const STATUS_SUCCESS_V4: &[u8] = br#"{"metadata":{},"status":"Success"}"#;

/// コンテナ側（テストが操作する側）の stdio。
struct ContainerEnds {
    stdin: StdUnixStream,
    stdout: StdUnixStream,
    stderr: StdUnixStream,
}

/// fake backend。`attach` のたびにコンテナ側の端をテストへ渡す。
struct FakeBackend {
    ends: Arc<Mutex<Option<ContainerEnds>>>,
    exited: Arc<AtomicBool>,
    resizes: Arc<Mutex<Vec<TerminalSize>>>,
    targets: Arc<Mutex<Vec<AttachTarget>>>,
    fail: Option<CriErrorCode>,
}

impl FakeBackend {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            ends: Arc::new(Mutex::new(None)),
            exited: Arc::new(AtomicBool::new(false)),
            resizes: Arc::new(Mutex::new(Vec::new())),
            targets: Arc::new(Mutex::new(Vec::new())),
            fail: None,
        })
    }

    fn failing(code: CriErrorCode) -> Arc<Self> {
        Arc::new(Self {
            ends: Arc::new(Mutex::new(None)),
            exited: Arc::new(AtomicBool::new(false)),
            resizes: Arc::new(Mutex::new(Vec::new())),
            targets: Arc::new(Mutex::new(Vec::new())),
            fail: Some(code),
        })
    }

    /// backend が接続されるのを待って、コンテナ側の端を受け取る（5 秒で諦める）。
    fn take_ends(&self) -> ContainerEnds {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(ends) = self.ends.lock().expect("lock").take() {
                // 期限は `attach` の `pair` で端を作った時点に設定済み（閉じた端への
                // setsockopt は macOS で EINVAL になるため、ここでは設定しない。#3700）。
                return ends;
            }
            assert!(
                Instant::now() < deadline,
                "backend was not attached in time"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn mark_exited(&self) {
        self.exited.store(true, Ordering::SeqCst);
    }
}

impl AttachBackend for FakeBackend {
    fn attach(
        &self,
        target: AttachTarget,
    ) -> Pin<Box<dyn Future<Output = Result<AttachSession, CriError>> + Send + 'static>> {
        let ends = Arc::clone(&self.ends);
        let exited = Arc::clone(&self.exited);
        let resizes = Arc::clone(&self.resizes);
        let targets = Arc::clone(&self.targets);
        let fail = self.fail;
        Box::pin(async move {
            targets.lock().expect("lock").push(target.clone());
            if let Some(code) = fail {
                return Err(CriError::new(code, "internal detail secret-container-id"));
            }
            let pair = || {
                let (session, container) = StdUnixStream::pair().expect("pair");
                session.set_nonblocking(true).expect("nonblocking");
                // ハンドラへ渡す前に期限を設定する。ハンドラが先に端を閉じた後の setsockopt は
                // macOS（XNU）で EINVAL になる（CRI-6・REPAIR-5・#3700）。
                container
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                container
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .expect("write timeout");
                (
                    tokio::net::UnixStream::from_std(session).expect("from_std"),
                    container,
                )
            };
            let (stdin_s, stdin_c) = pair();
            let (stdout_s, stdout_c) = pair();
            let (stderr_s, stderr_c) = pair();
            *ends.lock().expect("lock") = Some(ContainerEnds {
                stdin: stdin_c,
                stdout: stdout_c,
                stderr: stderr_c,
            });
            Ok(AttachSession {
                stdin: target.stdin.then(|| Box::new(stdin_s) as _),
                stdout: target.stdout.then(|| Box::new(stdout_s) as _),
                stderr: target.stderr.then(|| Box::new(stderr_s) as _),
                resize: target
                    .tty
                    .then(|| Box::new(move |size| resizes.lock().expect("lock").push(size)) as _),
                exited: Box::pin(async move {
                    while !exited.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }),
            })
        })
    }
}

/// 最小の SPDY クライアント（ブロッキング）。受信したフレームを蓄積する。
struct Client {
    sock: TcpStream,
    enc: FrameEncoder,
    dec: FrameDecoder,
    next_id: u32,
    data: HashMap<u32, Vec<u8>>,
    fin: HashSet<u32>,
    replies: Vec<u32>,
    rsts: Vec<(u32, u32)>,
    pings: Vec<u32>,
    goaway: Option<u32>,
    eof: bool,
}

fn upgrade_request(path: &str, protocols: Option<&str>) -> String {
    let mut raw = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n"
    );
    if let Some(p) = protocols {
        raw.push_str(&format!("X-Stream-Protocol-Version: {p}\r\n"));
    }
    raw.push_str("\r\n");
    raw
}

/// 応答のヘッダ部（空行まで）を 1 バイトずつ読む（後続の SPDY フレームを読み過ぎない）。
fn read_head(sock: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 8192, "response head is too long");
        let n = sock.read(&mut byte).expect("read head");
        assert!(n == 1, "connection closed before the response head ended");
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

impl Client {
    fn connect_raw(addr: SocketAddr, raw: &str) -> (TcpStream, String) {
        let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout");
        sock.write_all(raw.as_bytes()).expect("write");
        let head = read_head(&mut sock);
        (sock, head)
    }

    /// `v4.channel.k8s.io` で Upgrade し、101 を確認して返す。
    fn connect(addr: SocketAddr, path: &str) -> Self {
        Self::connect_with_version(addr, path, "v4.channel.k8s.io")
    }

    /// 指定の版で Upgrade し、101 と選ばれた版を確認して返す。
    fn connect_with_version(addr: SocketAddr, path: &str, version: &str) -> Self {
        let (sock, head) = Self::connect_raw(addr, &upgrade_request(path, Some(version)));
        assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
        let lower = head.to_ascii_lowercase();
        assert!(lower.contains("upgrade: spdy/3.1"), "{head}");
        assert!(
            lower.contains(&format!("x-stream-protocol-version: {version}")),
            "{head}"
        );
        Self {
            sock,
            enc: FrameEncoder::new(),
            dec: FrameDecoder::new(),
            next_id: 1,
            data: HashMap::new(),
            fin: HashSet::new(),
            replies: Vec::new(),
            rsts: Vec::new(),
            pings: Vec::new(),
            goaway: None,
            eof: false,
        }
    }

    fn send(&mut self, frame: &Frame) {
        let mut out = Vec::new();
        self.enc.encode(frame, &mut out).expect("encode");
        self.sock.write_all(&out).expect("send");
    }

    fn open(&mut self, kind: &str) -> StreamId {
        let id = StreamId::new(self.next_id).expect("id");
        self.next_id += 2;
        let mut headers = Headers::new();
        headers.push("streamType", kind);
        self.send(&Frame::SynStream {
            stream_id: id,
            associated_to: 0,
            priority: 0,
            fin: false,
            unidirectional: false,
            headers,
        });
        id
    }

    fn send_data(&mut self, id: StreamId, data: &[u8], fin: bool) {
        self.send(&Frame::Data {
            stream_id: id,
            fin,
            data: data.to_vec(),
        });
    }

    fn data_of(&self, id: StreamId) -> &[u8] {
        self.data.get(&id.get()).map_or(&[], Vec::as_slice)
    }

    /// 条件が満たされるまでフレームを読んで蓄積する。EOF や期限切れ（読み取り 10 秒）は失敗にする。
    fn pump_until(&mut self, cond: impl Fn(&Client) -> bool) {
        while !cond(self) {
            assert!(!self.eof, "connection closed before the condition held");
            let frame = loop {
                match self.dec.next_frame().expect("decode") {
                    Some(frame) => break Some(frame),
                    None => {
                        let mut buf = [0u8; 8192];
                        match self.sock.read(&mut buf) {
                            Ok(0) => break None,
                            Ok(n) => self.dec.extend(&buf[..n]),
                            Err(e) => panic!("read failed: {e}"),
                        }
                    }
                }
            };
            let Some(frame) = frame else {
                self.eof = true;
                continue;
            };
            match frame {
                Frame::SynReply { stream_id, .. } => self.replies.push(stream_id.get()),
                Frame::RstStream { stream_id, status } => self.rsts.push((stream_id.get(), status)),
                Frame::Ping { id } => self.pings.push(id),
                Frame::GoAway { status, .. } => self.goaway = Some(status),
                Frame::Data {
                    stream_id,
                    fin,
                    data,
                } => {
                    self.data.entry(stream_id.get()).or_default().extend(data);
                    if fin {
                        self.fin.insert(stream_id.get());
                    }
                }
                _ => {}
            }
        }
    }
}

fn pod_config() -> PodSandboxConfig {
    PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "pod".into(),
            uid: "uid-1".into(),
            namespace: "ns".into(),
            attempt: 0,
        }),
        ..Default::default()
    }
}

/// サーバー・サービス・running のコンテナを用意する。
async fn setup(
    config: StreamingConfig,
    backend: Option<Arc<FakeBackend>>,
) -> (StreamingServer, CriRuntimeService, String) {
    let mut dispatcher = StreamDispatcher::new();
    if let Some(backend) = backend {
        let handler = AttachHandler::new(backend, config.session_limits()).expect("handler");
        dispatcher = dispatcher.with_attach(Arc::new(handler));
    }
    let server = StreamingServer::bind_with_handler(config, Arc::new(dispatcher))
        .await
        .expect("bind");
    let service = CriRuntimeService::new().with_streaming(server.issuer());
    let sandbox = service
        .run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
            config: Some(pod_config()),
            runtime_handler: String::new(),
        }))
        .await
        .expect("sandbox")
        .into_inner()
        .pod_sandbox_id;
    let container = service
        .create_container(Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox,
            config: Some(ContainerConfig {
                metadata: Some(ContainerMetadata {
                    name: "c".into(),
                    attempt: 0,
                }),
                image: Some(ImageSpec {
                    image: "busybox:1.36".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            sandbox_config: Some(pod_config()),
        }))
        .await
        .expect("container")
        .into_inner()
        .container_id;
    service
        .start_container(Request::new(v1::StartContainerRequest {
            container_id: container.clone(),
        }))
        .await
        .expect("start");
    (server, service, container)
}

/// `Attach` RPC で URL を発行し、パス部分を返す（単回トークンなので接続のたびに発行する）。
async fn attach_path(
    service: &CriRuntimeService,
    container: &str,
    stdin: bool,
    stdout: bool,
    stderr: bool,
    tty: bool,
) -> String {
    let url = service
        .attach(Request::new(v1::AttachRequest {
            container_id: container.to_string(),
            stdin,
            tty,
            stdout,
            stderr,
        }))
        .await
        .expect("attach rpc")
        .into_inner()
        .url;
    let rest = url.strip_prefix("http://").expect("http url");
    rest[rest.find('/').expect("path")..].to_string()
}

/// CRI-6: stdout・stderr がコンテナから届き、stdin がコンテナへ届く。終了で Status(Success)・FIN・GOAWAY で閉じる。
#[tokio::test]
async fn cri6_attach_streams_stdout_stderr_and_stdin() {
    let backend = FakeBackend::new();
    let (server, service, container) =
        setup(StreamingConfig::default(), Some(backend.clone())).await;
    let path = attach_path(&service, &container, true, true, true, false).await;
    let addr = server.local_addr();
    let b = backend.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(addr, &path);
        let err = c.open("error");
        let stdin = c.open("stdin");
        let stdout = c.open("stdout");
        let stderr = c.open("stderr");
        c.pump_until(|c| c.replies.len() == 4);
        assert_eq!(
            c.replies,
            [err.get(), stdin.get(), stdout.get(), stderr.get()]
        );
        let mut ends = b.take_ends();
        assert_eq!(
            b.targets.lock().expect("lock").as_slice(),
            [AttachTarget {
                container_id: container.clone(),
                stdin: true,
                stdout: true,
                stderr: true,
                tty: false,
            }]
        );

        ends.stdout.write_all(b"hello-out").expect("stdout");
        ends.stderr.write_all(b"hello-err").expect("stderr");
        c.pump_until(|c| c.data_of(stdout) == b"hello-out" && c.data_of(stderr) == b"hello-err");

        c.send_data(stdin, b"ping\n", false);
        let mut got = [0u8; 5];
        ends.stdin.read_exact(&mut got).expect("stdin");
        assert_eq!(&got, b"ping\n");
        // クライアントの stdin の FIN は、コンテナ側の stdin の EOF になる。
        c.send_data(stdin, b"", true);
        let mut rest = Vec::new();
        ends.stdin.read_to_end(&mut rest).expect("stdin eof");
        assert!(rest.is_empty());

        b.mark_exited();
        drop(ends);
        c.pump_until(|c| c.eof);
        assert_eq!(c.data_of(err), STATUS_SUCCESS_V4);
        for id in [err, stdout, stderr] {
            assert!(
                c.fin.contains(&id.get()),
                "stream {} must be finished",
                id.get()
            );
        }
        assert_eq!(c.goaway, Some(goaway_status::OK));
    })
    .await
    .expect("join");
}

/// CRI-6: tty では resize ストリームの JSON（フレームをまたぐ分割を含む）が backend の resize に届く。
#[tokio::test]
async fn cri6_attach_tty_resize() {
    let backend = FakeBackend::new();
    let (server, service, container) =
        setup(StreamingConfig::default(), Some(backend.clone())).await;
    // tty では stderr を要求しない（要求しても RPC が拒否する）。
    let path = attach_path(&service, &container, false, true, false, true).await;
    let addr = server.local_addr();
    let b = backend.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(addr, &path);
        let err = c.open("error");
        let stdout = c.open("stdout");
        let resize = c.open("resize");
        c.pump_until(|c| c.replies.len() == 3);
        let ends = b.take_ends();
        c.send_data(resize, br#"{"Width":120,"He"#, false);
        c.send_data(resize, br#"ight":40}{"Width":80,"Height":24}"#, false);
        let deadline = Instant::now() + Duration::from_secs(5);
        while b.resizes.lock().expect("lock").len() < 2 {
            assert!(Instant::now() < deadline, "resize did not arrive");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            b.resizes.lock().expect("lock").as_slice(),
            [
                TerminalSize {
                    width: 120,
                    height: 40
                },
                TerminalSize {
                    width: 80,
                    height: 24
                }
            ]
        );
        b.mark_exited();
        drop(ends);
        c.pump_until(|c| c.eof);
        assert_eq!(c.data_of(err), STATUS_SUCCESS_V4);
        assert!(c.fin.contains(&stdout.get()));
    })
    .await
    .expect("join");
}

/// CRI-6: backend の失敗は error ストリームの Failure Status（固定の英語。入力・内部の文言を含めない）になる。
#[tokio::test]
async fn cri6_attach_backend_failure_status() {
    let backend = FakeBackend::failing(CriErrorCode::FailedPrecondition);
    let (server, service, container) = setup(StreamingConfig::default(), Some(backend)).await;
    let path = attach_path(&service, &container, false, true, false, false).await;
    let addr = server.local_addr();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(addr, &path);
        let err = c.open("error");
        let _stdout = c.open("stdout");
        c.pump_until(|c| c.eof);
        let status: serde_json::Value =
            serde_json::from_slice(c.data_of(err)).expect("status json");
        assert_eq!(
            status,
            serde_json::json!({
                "metadata": {},
                "status": "Failure",
                "message": "error attaching to container: container is not running",
                "reason": "Conflict",
                "code": 409,
            })
        );
        assert!(!String::from_utf8_lossy(c.data_of(err)).contains("secret-container-id"));
        assert!(c.fin.contains(&err.get()));
    })
    .await
    .expect("join");
}

/// CRI-6: 64 KiB を超える出力が、クライアントが WINDOW_UPDATE を一切送らなくても欠けずに届く
/// （実クライアントの spdystream は flow control を実装しない。窓を強制するとここで止まる）。
#[tokio::test]
async fn cri6_attach_flow_control_large_output() {
    let backend = FakeBackend::new();
    let (server, service, container) =
        setup(StreamingConfig::default(), Some(backend.clone())).await;
    let path = attach_path(&service, &container, false, true, false, false).await;
    let addr = server.local_addr();
    let b = backend.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(addr, &path);
        let err = c.open("error");
        let stdout = c.open("stdout");
        c.pump_until(|c| c.replies.len() == 2);
        let ends = b.take_ends();
        let total = 256 * 1024;
        let pattern: Vec<u8> = (0..total)
            .map(|i| u8::try_from(i % 251).expect("byte"))
            .collect();
        let to_write = pattern.clone();
        let mut out = ends.stdout.try_clone().expect("clone");
        let writer = std::thread::spawn(move || {
            out.write_all(&to_write).expect("write large output");
        });
        c.pump_until(|c| c.data_of(stdout).len() >= total);
        writer.join().expect("writer");
        assert_eq!(c.data_of(stdout), pattern.as_slice());
        b.mark_exited();
        drop(ends);
        c.pump_until(|c| c.eof);
        assert_eq!(c.data_of(err), STATUS_SUCCESS_V4);
    })
    .await
    .expect("join");
}

/// CRI-6・REPAIR-5: 必要なストリームが揃わなければ作成期限で閉じ、接続枠が返る（枠 1 でも次の接続が通る）。
#[tokio::test]
async fn cri6_attach_stream_creation_timeout_releases_slot() {
    let backend = FakeBackend::new();
    let config = StreamingConfig::default()
        .with_max_connections(1)
        .with_stream_creation_timeout(Duration::from_millis(300));
    let (server, service, container) = setup(config, Some(backend.clone())).await;
    let path = attach_path(&service, &container, false, true, false, false).await;
    let addr = server.local_addr();
    let started = Instant::now();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(addr, &path);
        let _err = c.open("error"); // stdout を開かない。
        c.pump_until(|c| c.eof);
        assert_eq!(c.goaway, Some(goaway_status::PROTOCOL_ERROR));
    })
    .await
    .expect("join");
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(250), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");

    // 枠が返っていれば、同じ枠 1 の設定で次のセッションが通る。
    let path = attach_path(&service, &container, false, true, false, false).await;
    let b = backend.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.open("error");
        c.open("stdout");
        c.pump_until(|c| c.replies.len() == 2);
        let ends = b.take_ends();
        b.mark_exited();
        drop(ends);
        c.pump_until(|c| c.eof);
    })
    .await
    .expect("join");
}

/// CRI-6・REPAIR-5: idle の期限で閉じ、backend の stdio が解放される（コンテナ側から EOF が見える）。
#[tokio::test]
async fn cri6_attach_idle_timeout_releases_backend() {
    let backend = FakeBackend::new();
    let config = StreamingConfig::default().with_stream_idle_timeout(Duration::from_millis(400));
    let (server, service, container) = setup(config, Some(backend.clone())).await;
    let path = attach_path(&service, &container, true, true, false, false).await;
    let addr = server.local_addr();
    let b = backend.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.open("error");
        c.open("stdin");
        c.open("stdout");
        c.pump_until(|c| c.replies.len() == 3);
        let mut ends = b.take_ends();
        let started = Instant::now();
        c.pump_until(|c| c.eof);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(c.goaway, Some(goaway_status::OK));
        // セッションが backend の stdin の書き口を drop したので、コンテナ側は EOF を読む。
        let mut buf = Vec::new();
        ends.stdin.read_to_end(&mut buf).expect("eof");
        assert!(buf.is_empty());
    })
    .await
    .expect("join");
}

const STATUS_TIMEOUT_V4: &str = r#"{"metadata":{},"status":"Failure","message":"attach session timed out","reason":"Timeout","code":504}"#;
const STATUS_TIMEOUT_TEXT: &str = "attach session timed out";

/// CRI-6・REPAIR-5: idle の打ち切りでも error ストリームへ Failure の Status を送り、出力の FIN・GOAWAY(OK) で閉じる。
/// v4 は JSON、v3・v2 はテキスト。
#[tokio::test]
async fn cri6_attach_idle_timeout_notifies_failure_status() {
    for (version, expected) in [
        ("v4.channel.k8s.io", STATUS_TIMEOUT_V4),
        ("v3.channel.k8s.io", STATUS_TIMEOUT_TEXT),
        ("v2.channel.k8s.io", STATUS_TIMEOUT_TEXT),
    ] {
        let backend = FakeBackend::new();
        let config =
            StreamingConfig::default().with_stream_idle_timeout(Duration::from_millis(300));
        let (server, service, container) = setup(config, Some(backend.clone())).await;
        let path = attach_path(&service, &container, false, true, false, false).await;
        let addr = server.local_addr();
        let b = backend.clone();
        tokio::task::spawn_blocking(move || {
            let mut c = Client::connect_with_version(addr, &path, version);
            let err = c.open("error");
            let stdout = c.open("stdout");
            c.pump_until(|c| c.replies.len() == 2);
            let _ends = b.take_ends();
            c.pump_until(|c| c.eof);
            assert_eq!(c.data_of(err), expected.as_bytes(), "{version}");
            assert!(c.fin.contains(&err.get()), "{version}");
            assert!(c.fin.contains(&stdout.get()), "{version}");
            assert_eq!(c.goaway, Some(goaway_status::OK), "{version}");
        })
        .await
        .expect("join");
    }
}

/// CRI-6: Attach の backend を注入しない構成では従来どおり 501（実装済みを装わない）。
#[tokio::test]
async fn cri6_attach_without_backend_is_501() {
    let (server, service, container) = setup(StreamingConfig::default(), None).await;
    let path = attach_path(&service, &container, false, true, false, false).await;
    let addr = server.local_addr();
    tokio::task::spawn_blocking(move || {
        let (mut sock, head) =
            Client::connect_raw(addr, &upgrade_request(&path, Some("v4.channel.k8s.io")));
        assert!(head.starts_with("HTTP/1.1 501 "), "{head}");
        let mut rest = Vec::new();
        let _ = sock.read_to_end(&mut rest);
    })
    .await
    .expect("join");
}

/// CRI-6: 交渉の失敗は 403（対応版を列挙）・400。Upgrade せず、トークンは消費済み。
#[tokio::test]
async fn cri6_attach_handshake_failures() {
    let backend = FakeBackend::new();
    let (server, service, container) =
        setup(StreamingConfig::default(), Some(backend.clone())).await;
    let addr = server.local_addr();

    let path = attach_path(&service, &container, false, true, false, false).await;
    let head = tokio::task::spawn_blocking(move || {
        Client::connect_raw(
            addr,
            &upgrade_request(&path, Some("channel.k8s.io, v5.channel.k8s.io")),
        )
        .1
    })
    .await
    .expect("join");
    assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    let lower = head.to_ascii_lowercase();
    assert!(
        lower.contains("x-accepted-stream-protocol-versions: v4.channel.k8s.io"),
        "{head}"
    );
    assert!(
        lower.contains("x-accepted-stream-protocol-versions: v2.channel.k8s.io"),
        "{head}"
    );

    let path = attach_path(&service, &container, false, true, false, false).await;
    let head = tokio::task::spawn_blocking(move || {
        Client::connect_raw(addr, &upgrade_request(&path, None)).1
    })
    .await
    .expect("join");
    assert!(head.starts_with("HTTP/1.1 400 "), "{head}");
    assert!(backend.targets.lock().expect("lock").is_empty());
}

/// CRI-6: PING はそのまま返り、未知の streamType・要求外の種別・重複は RST_STREAM、不正なフレームは GOAWAY で閉じる。
#[tokio::test]
async fn cri6_attach_ping_rst_and_protocol_error() {
    let backend = FakeBackend::new();
    let (server, service, container) =
        setup(StreamingConfig::default(), Some(backend.clone())).await;
    let path = attach_path(&service, &container, false, true, false, false).await;
    let addr = server.local_addr();
    let b = backend.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.send(&Frame::Ping { id: 7 });
        let bogus = c.open("bogus");
        let stdin = c.open("stdin"); // 要求していない種別。
        let err = c.open("error");
        let dup = c.open("error"); // 重複。
        let stdout = c.open("stdout");
        c.pump_until(|c| c.pings == [7] && c.rsts.len() == 3 && c.replies.len() == 2);
        assert_eq!(
            c.rsts,
            [
                (bogus.get(), rst_status::REFUSED_STREAM),
                (stdin.get(), rst_status::REFUSED_STREAM),
                (dup.get(), rst_status::STREAM_IN_USE),
            ]
        );
        assert_eq!(c.replies, [err.get(), stdout.get()]);
        let ends = b.take_ends();
        // 壊れた制御フレーム（PING の長さ不正）でセッションを閉じる。
        c.sock
            .write_all(&[0x80, 0x03, 0x00, 0x06, 0, 0, 0, 3, 0, 0, 0])
            .expect("garbage");
        c.pump_until(|c| c.eof);
        assert_eq!(c.goaway, Some(goaway_status::PROTOCOL_ERROR));
        drop(ends);
    })
    .await
    .expect("join");
}
/// CRI-6: RST_STREAM 済みの stdin・resize への DATA は backend へ渡らず、stdin の書き口は閉じる。
#[tokio::test]
async fn cri6_attach_data_after_rst_is_ignored() {
    let backend = FakeBackend::new();
    let (server, service, container) =
        setup(StreamingConfig::default(), Some(backend.clone())).await;
    let path = attach_path(&service, &container, true, true, false, true).await;
    let addr = server.local_addr();
    let b = backend.clone();
    tokio::task::spawn_blocking(move || {
        let mut c = Client::connect(addr, &path);
        c.open("error");
        let stdin = c.open("stdin");
        c.open("stdout");
        let resize = c.open("resize");
        c.pump_until(|c| c.replies.len() == 4);
        let mut ends = b.take_ends();
        for id in [stdin, resize] {
            c.send(&Frame::RstStream {
                stream_id: id,
                status: rst_status::CANCEL,
            });
        }
        c.send_data(stdin, b"late\n", false);
        c.send_data(resize, br#"{"Width":1,"Height":2}"#, false);
        std::thread::sleep(Duration::from_millis(300));
        assert!(b.resizes.lock().expect("lock").is_empty());
        // 書き口が閉じるので、コンテナ側は何も受け取らず EOF を読む。
        let mut buf = Vec::new();
        ends.stdin.read_to_end(&mut buf).expect("eof");
        assert!(buf.is_empty());
    })
    .await
    .expect("join");
}
