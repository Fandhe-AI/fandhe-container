//! crictl 相当の操作でストリーミング系 RPC（Exec・Attach・PortForward）が通ることの疎通試験（CRI-6・TASK-63.5・#683）。
//!
//! 既存の `streaming_{server,exec,attach,portforward}.rs` は 1 種類のハンドラの細部（期限・RST・不正入力など）を
//! 照合する。本ファイルは視点が違い、3 種類のハンドラを 1 つの `StreamDispatcher` に同居させ、
//! `CriRuntimeService` の RPC で URL を得て、client-go（crictl / kubectl が使う SPDY 実装）が送る要求の形と手順で
//! 操作する。差分は次の 3 点。
//!
//! - 要求は `POST` で、`X-Stream-Protocol-Version` を 1 版 1 行で複数行送る（`v4` → `v3` → `v2` → `channel`）。
//! - ストリームは lock-step で作る。client-go の `CreateStream` は SYN_REPLY を受けるまで次へ進まないため、
//!   SYN_STREAM を 1 本送るたびにその ID の SYN_REPLY を待つ（既存の試験は全部送ってからまとめて待つ）。
//! - Exec / Attach の終了は error ストリームの `metav1.Status`（v4 の JSON）で判定し、portforward は
//!   error / data の対を `requestid` で複数張る（同じ SPDY セッションを使い回す）。
//!
//! 既定の集合で動く理由: loopback の TCP とプロセス内の偽 backend だけを使い、root も外部プロセスも要らない。
//! 偽 backend は SEC-1（namespace・capability を広げない）を検証しない。NODE ネットワークの本番 dialer
//! （`NodeLoopbackDialer`）と plugin-cri の結線の通しは `crates/plugin-cri/tests/streaming_grpc.rs`（#3756）で
//! 照合する（SPDY クライアントは `support/spdy_client.rs` を共有）。Exec・Attach の本番結線は #3761・#3763、
//! POD ネットワークは #3766、実 crictl・kubectl での照合は後続 issue
//! （`docs/design/cri-streaming-server.md`「残るもの」）で行う（REPAIR-3）。
//! 各試験は読み書きと全体に期限を付け、ハングしない（REPAIR-5）。トークンの乱数源が unix のみのため `cfg(unix)`。
#![cfg(unix)]

#[path = "support/spdy_client.rs"]
mod spdy_client;

use std::future::Future;
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use fandhe_container_cri::streaming::attach::{
    AttachBackend, AttachHandler, AttachSession, AttachTarget,
};
use fandhe_container_cri::streaming::exec::{
    ExecLaunch, ExecSession, ExecStreamConfig, ExecStreamHandler, ExecStreamLauncher,
    TerminalResizer,
};
use fandhe_container_cri::streaming::port_forward::{
    PortForwardConfig, PortForwardDialer, PortForwardHandler, PortForwardNetwork, PortForwardTarget,
};
use fandhe_container_cri::streaming::remotecommand::TerminalSize;
use fandhe_container_cri::streaming::spdy::{Frame, goaway_status};
use fandhe_container_cri::streaming::{StreamDispatcher, StreamingConfig, StreamingServer};
use spdy_client::{Spdy, open_pf_pair, plain_post_status, spawn_echo, split_url};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::sync::oneshot;
use tonic::Request;

/// 試験全体の上限（REPAIR-5）。個々の読み取りは 5 秒で打ち切る。
const TEST_DEADLINE: Duration = Duration::from_secs(60);
/// client-go の SPDY executor が提示する版の順（新しい順）。
const EXEC_VERSIONS: [&str; 4] = [
    "v4.channel.k8s.io",
    "v3.channel.k8s.io",
    "v2.channel.k8s.io",
    "channel.k8s.io",
];
const PF_VERSION: &str = "portforward.k8s.io";

// ---------------------------------------------------------------------------------------------
// 偽 backend（プロセス内。外部プロセスは起動しない）
// ---------------------------------------------------------------------------------------------

/// Exec の起動役。cmd は発行時に保存された `ExecLaunch` からだけ読み、通信路の内容からは組み立てない。
#[derive(Default)]
struct FakeLauncher {
    launches: Mutex<Vec<ExecLaunch>>,
    resizes: Arc<Mutex<Vec<(u16, u16)>>>,
}

struct RecordingResizer(Arc<Mutex<Vec<(u16, u16)>>>);

impl TerminalResizer for RecordingResizer {
    fn resize(&mut self, size: TerminalSize) -> Result<(), CriError> {
        self.0.lock().expect("lock").push((size.width, size.height));
        Ok(())
    }
}

impl ExecStreamLauncher for FakeLauncher {
    fn launch(
        &self,
        req: ExecLaunch,
    ) -> Pin<Box<dyn Future<Output = Result<ExecSession, CriError>> + Send + '_>> {
        Box::pin(async move {
            self.launches.lock().expect("lock").push(req.clone());
            let (exit_tx, exit_rx) = oneshot::channel::<i32>();
            // サーバー側が読む端 (r) と、偽プロセスが書く端 (w)。
            let (stdout_r, stdout_w) = duplex(64 * 1024);
            let (stderr_r, stderr_w) = duplex(64 * 1024);
            // サーバー側が書く端 (w) と、偽プロセスが読む端 (r)。
            let (stdin_w, stdin_r) = duplex(64 * 1024);
            let argv = req.cmd.clone();
            tokio::spawn(fake_process(argv, stdin_r, stdout_w, stderr_w, exit_tx));
            Ok(ExecSession {
                stdin: req
                    .stdin
                    .then(|| Box::new(stdin_w) as Box<dyn tokio::io::AsyncWrite + Send + Unpin>),
                stdout: req
                    .stdout
                    .then(|| Box::new(stdout_r) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
                stderr: req
                    .stderr
                    .then(|| Box::new(stderr_r) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
                exit: Box::pin(async move {
                    exit_rx
                        .await
                        .map_err(|_| CriError::internal("fake process vanished"))
                }),
                resize: req.tty.then(|| {
                    Box::new(RecordingResizer(Arc::clone(&self.resizes)))
                        as Box<dyn TerminalResizer>
                }),
            })
        })
    }
}

/// 偽のプロセス本体。`echo ...` は引数を連結して出力、`sh -c "exit N"` は終了コード N、`cat` は stdin を写す。
async fn fake_process(
    argv: Vec<String>,
    mut stdin: DuplexStream,
    mut stdout: DuplexStream,
    stderr: DuplexStream,
    exit: oneshot::Sender<i32>,
) {
    let program = argv.first().map(String::as_str).unwrap_or_default();
    let code = match program {
        "echo" => {
            let line = format!("{}\n", argv.get(1..).unwrap_or_default().join(" "));
            let _ = stdout.write_all(line.as_bytes()).await;
            0
        }
        "sh" => argv
            .get(2)
            .and_then(|s| s.strip_prefix("exit "))
            .and_then(|n| n.trim().parse::<i32>().ok())
            .unwrap_or(127),
        "cat" => {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdin.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                if stdout
                    .write_all(buf.get(..n).unwrap_or_default())
                    .await
                    .is_err()
                {
                    break;
                }
            }
            0
        }
        _ => 127,
    };
    // 出力の終端（EOF）を先に伝えてから終了コードを返す。
    drop(stdout);
    drop(stderr);
    let _ = exit.send(code);
}

/// Attach の backend。接続されたら stdout に `out\n`、stderr に `err\n` を書いて閉じ、コンテナの終了を通知する。
struct FakeAttach {
    targets: Mutex<Vec<AttachTarget>>,
}

impl AttachBackend for FakeAttach {
    fn attach(
        &self,
        target: AttachTarget,
    ) -> Pin<Box<dyn Future<Output = Result<AttachSession, CriError>> + Send + 'static>> {
        self.targets.lock().expect("lock").push(target.clone());
        Box::pin(async move {
            let (stdout_r, mut stdout_w) = duplex(64 * 1024);
            let (stderr_r, mut stderr_w) = duplex(64 * 1024);
            let (done_tx, done_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                let _ = stdout_w.write_all(b"out\n").await;
                let _ = stderr_w.write_all(b"err\n").await;
                drop(stdout_w);
                drop(stderr_w);
                let _ = done_tx.send(());
            });
            Ok(AttachSession {
                stdin: None,
                stdout: target
                    .stdout
                    .then(|| Box::new(stdout_r) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
                stderr: target
                    .stderr
                    .then(|| Box::new(stderr_r) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
                resize: None,
                exited: Box::pin(async move {
                    let _ = done_rx.await;
                }),
            })
        })
    }
}

/// PortForward の dialer。`pod_sandbox_id` とポートを照合してから loopback の echo サーバーへ接続する。
struct FakeDialer {
    sandbox: String,
    echo: SocketAddr,
}

impl PortForwardDialer for FakeDialer {
    fn dial(
        &self,
        target: &PortForwardTarget,
        port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, CriError> {
        if target.pod_sandbox_id() != self.sandbox
            || target.network() != PortForwardNetwork::Node
            || port != 80
        {
            return Err(CriError::unavailable("no route"));
        }
        TcpStream::connect_timeout(&self.echo, timeout)
            .map_err(|_| CriError::unavailable("refused"))
    }
}

// ---------------------------------------------------------------------------------------------
// fixture: 3 ハンドラを同居させたサーバーと CRI サービス
// ---------------------------------------------------------------------------------------------

struct Fixture {
    server: StreamingServer,
    service: CriRuntimeService,
    sandbox: String,
    container: String,
    launcher: Arc<FakeLauncher>,
    attach: Arc<FakeAttach>,
}

fn pod_config() -> PodSandboxConfig {
    PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "pod".into(),
            uid: "uid-1".into(),
            namespace: "ns".into(),
            attempt: 0,
        }),
        // PortForward は NODE の pod だけ結線済み（POD は #3766 まで UNIMPLEMENTED。#3755）。
        linux: Some(v1::LinuxPodSandboxConfig {
            security_context: Some(v1::LinuxSandboxSecurityContext {
                namespace_options: Some(v1::NamespaceOption {
                    network: v1::NamespaceMode::Node as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn setup_all() -> Fixture {
    let launcher = Arc::new(FakeLauncher::default());
    let attach = Arc::new(FakeAttach {
        targets: Mutex::new(Vec::new()),
    });
    let streaming = StreamingConfig::default();
    let exec_handler = ExecStreamHandler::new(
        Arc::clone(&launcher) as Arc<dyn ExecStreamLauncher>,
        ExecStreamConfig::default(),
    )
    .expect("exec handler");
    let attach_handler = AttachHandler::new(
        Arc::clone(&attach) as Arc<dyn AttachBackend>,
        streaming.session_limits(),
    )
    .expect("attach handler");

    let service_probe = CriRuntimeService::new();
    let sandbox = service_probe
        .run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
            config: Some(pod_config()),
            runtime_handler: String::new(),
        }))
        .await
        .expect("sandbox")
        .into_inner()
        .pod_sandbox_id;
    // dialer は sandbox ID を照合する。ID はサービスが採番するため、同じサービスを後で server と結ぶ。
    let pf_handler = PortForwardHandler::new(
        Arc::new(FakeDialer {
            sandbox: sandbox.clone(),
            echo: spawn_echo(),
        }),
        PortForwardConfig::default(),
    )
    .expect("pf handler");
    let dispatcher = StreamDispatcher::new()
        .with_exec(Arc::new(exec_handler))
        .with_attach(Arc::new(attach_handler))
        .with_port_forward(Arc::new(pf_handler));
    let server = StreamingServer::bind_with_handler(streaming, Arc::new(dispatcher))
        .await
        .expect("bind");
    let service = service_probe.with_streaming(server.issuer());
    let container = service
        .create_container(Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox.clone(),
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
    Fixture {
        server,
        service,
        sandbox,
        container,
        launcher,
        attach,
    }
}

impl Fixture {
    fn addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    /// `crictl exec` 相当の `Exec` RPC。`interactive` は `-it`（stdin + tty、stderr なし）。
    async fn exec_path(&self, cmd: &[&str], interactive: bool) -> String {
        let url = self
            .service
            .exec(Request::new(v1::ExecRequest {
                container_id: self.container.clone(),
                cmd: cmd.iter().map(|s| s.to_string()).collect(),
                tty: interactive,
                stdin: interactive,
                stdout: true,
                // crictl は stderr = !tty を送る。
                stderr: !interactive,
            }))
            .await
            .expect("exec rpc")
            .into_inner()
            .url;
        split_url(&url).1
    }

    /// `crictl attach`（既定。stdin なし・tty なし）相当。
    async fn attach_url(&self) -> String {
        self.service
            .attach(Request::new(v1::AttachRequest {
                container_id: self.container.clone(),
                stdin: false,
                tty: false,
                stdout: true,
                stderr: true,
            }))
            .await
            .expect("attach rpc")
            .into_inner()
            .url
    }

    /// `crictl port-forward <pod> L:80` 相当。
    async fn port_forward_url(&self) -> String {
        self.service
            .port_forward(Request::new(v1::PortForwardRequest {
                pod_sandbox_id: self.sandbox.clone(),
                port: vec![80],
            }))
            .await
            .expect("port-forward rpc")
            .into_inner()
            .url
    }
}

// ---------------------------------------------------------------------------------------------
// client-go 相当の SPDY クライアント（ブロッキング）
// ---------------------------------------------------------------------------------------------

/// remotecommand の stdio ストリームを client-go の順で作る。戻りは (error, stdin?, stdout, stderr?, resize?)。
struct RemoteStreams {
    error: u32,
    stdin: Option<u32>,
    stdout: u32,
    stderr: Option<u32>,
    resize: Option<u32>,
}

/// error → stdin（要求時のみ）→ stdout → stderr（tty でないときのみ）→ resize（tty のときのみ）。
fn create_remote_streams(c: &mut Spdy, stdin: bool, tty: bool) -> RemoteStreams {
    let error = c.create_stream(&[("streamtype", "error")]);
    let stdin = stdin.then(|| c.create_stream(&[("streamtype", "stdin")]));
    let stdout = c.create_stream(&[("streamtype", "stdout")]);
    let stderr = (!tty).then(|| c.create_stream(&[("streamtype", "stderr")]));
    let resize = tty.then(|| c.create_stream(&[("streamtype", "resize")]));
    RemoteStreams {
        error,
        stdin,
        stdout,
        stderr,
        resize,
    }
}

/// error ストリームの `metav1.Status`（v4 の JSON）を解析する。
fn status_of(raw: &[u8]) -> serde_json::Value {
    serde_json::from_slice(raw)
        .unwrap_or_else(|e| panic!("status is not JSON ({e}): {}", String::from_utf8_lossy(raw)))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::time::timeout(TEST_DEADLINE, tokio::task::spawn_blocking(f))
        .await
        .expect("test deadline")
        .expect("join")
}

// ---------------------------------------------------------------------------------------------
// シナリオ
// ---------------------------------------------------------------------------------------------

/// CRI-6・TASK-63.5: `crictl exec <id> echo hello world` 相当が成功する（stdin なし・stdout + stderr・tty なし）。
#[tokio::test]
async fn cri6_crictl_exec_echo_succeeds() {
    let fx = setup_all().await;
    let path = fx.exec_path(&["echo", "hello", "world"], false).await;
    let addr = fx.addr();
    blocking(move || {
        let mut c = Spdy::connect(addr, &path, &EXEC_VERSIONS, "v4.channel.k8s.io");
        let s = create_remote_streams(&mut c, false, false);
        let stderr = s.stderr.expect("stderr");
        assert_eq!(c.read_until_fin(s.stdout), b"hello world\n");
        assert_eq!(c.read_until_fin(stderr), b"");
        let status = status_of(&c.read_until_fin(s.error));
        assert_eq!(status["status"], "Success", "{status}");
        assert_eq!(c.wait_goaway(), goaway_status::OK);
    })
    .await;
    let launches = fx.launcher.launches.lock().expect("lock").clone();
    assert_eq!(launches.len(), 1);
    assert_eq!(launches[0].cmd, ["echo", "hello", "world"]);
    assert_eq!(
        (
            launches[0].stdin,
            launches[0].stdout,
            launches[0].stderr,
            launches[0].tty
        ),
        (false, true, true, false)
    );
}

/// CRI-6・TASK-63.5: 非 0 終了は `NonZeroExitCode` の Status になる。crictl は cause の message を終了コードにする。
#[tokio::test]
async fn cri6_crictl_exec_non_zero_exit_reports_exit_code() {
    let fx = setup_all().await;
    let path = fx.exec_path(&["sh", "-c", "exit 3"], false).await;
    let addr = fx.addr();
    blocking(move || {
        let mut c = Spdy::connect(addr, &path, &EXEC_VERSIONS, "v4.channel.k8s.io");
        let s = create_remote_streams(&mut c, false, false);
        let status = status_of(&c.read_until_fin(s.error));
        assert_eq!(status["status"], "Failure", "{status}");
        assert_eq!(status["reason"], "NonZeroExitCode", "{status}");
        let causes = status["details"]["causes"].as_array().expect("causes");
        assert_eq!(causes.len(), 1, "{status}");
        assert_eq!(causes[0]["reason"], "ExitCode", "{status}");
        assert_eq!(causes[0]["message"], "3", "{status}");
        assert_eq!(c.wait_goaway(), goaway_status::OK);
    })
    .await;
}

/// CRI-6・TASK-63.5: `crictl exec -it` 相当（stdin + tty、stderr なし、resize あり）が成功する。
#[tokio::test]
async fn cri6_crictl_exec_interactive_tty_with_stdin_and_resize() {
    let fx = setup_all().await;
    let path = fx.exec_path(&["cat"], true).await;
    let addr = fx.addr();
    let resizes = Arc::clone(&fx.launcher.resizes);
    blocking(move || {
        let mut c = Spdy::connect(addr, &path, &EXEC_VERSIONS, "v4.channel.k8s.io");
        let s = create_remote_streams(&mut c, true, true);
        let (stdin, resize) = (s.stdin.expect("stdin"), s.resize.expect("resize"));
        assert!(s.stderr.is_none());
        c.send_data(resize, br#"{"Width":80,"Height":24}"#, false);
        c.send_data(stdin, b"ping\n", false);
        assert_eq!(c.read_at_least(s.stdout, 5), b"ping\n");
        // resize は stdin より先に送ったため、echo が返った時点で記録済みのはず（念のため期限つきで待つ）。
        let deadline = Instant::now() + Duration::from_secs(5);
        while resizes.lock().expect("lock").is_empty() {
            assert!(Instant::now() < deadline, "resize was not delivered");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(resizes.lock().expect("lock").as_slice(), [(80, 24)]);
        // client-go は stdin の EOF で stdin ストリームを閉じる。cat は EOF で終わる。
        c.send_data(stdin, b"", true);
        let status = status_of(&c.read_until_fin(s.error));
        assert_eq!(status["status"], "Success", "{status}");
        assert_eq!(c.wait_goaway(), goaway_status::OK);
    })
    .await;
    let launches = fx.launcher.launches.lock().expect("lock").clone();
    assert_eq!(launches.len(), 1);
    assert_eq!(
        (
            launches[0].stdin,
            launches[0].stdout,
            launches[0].stderr,
            launches[0].tty
        ),
        (true, true, false, true)
    );
}

/// CRI-6・TASK-63.5: `crictl attach <id>`（既定）相当。stdout・stderr が届き、Status(Success)・FIN・GOAWAY で終わる。
#[tokio::test]
async fn cri6_crictl_attach_streams_stdio_and_status() {
    let fx = setup_all().await;
    let url = fx.attach_url().await;
    assert!(url.contains("/attach/"), "{url}");
    let path = split_url(&url).1;
    let addr = fx.addr();
    blocking(move || {
        let mut c = Spdy::connect(addr, &path, &EXEC_VERSIONS, "v4.channel.k8s.io");
        let s = create_remote_streams(&mut c, false, false);
        let stderr = s.stderr.expect("stderr");
        assert_eq!(c.read_until_fin(s.stdout), b"out\n");
        assert_eq!(c.read_until_fin(stderr), b"err\n");
        let status = status_of(&c.read_until_fin(s.error));
        assert_eq!(status["status"], "Success", "{status}");
        assert_eq!(c.wait_goaway(), goaway_status::OK);
    })
    .await;
    let targets = fx.attach.targets.lock().expect("lock").clone();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].container_id, fx.container);
    assert_eq!(
        (
            targets[0].stdin,
            targets[0].stdout,
            targets[0].stderr,
            targets[0].tty
        ),
        (false, true, true, false)
    );
}

/// CRI-6・TASK-63.5: `crictl port-forward <pod> L:80` 相当。同じ SPDY セッションで 2 つの接続が往復できる。
#[tokio::test]
async fn cri6_crictl_port_forward_round_trip_two_connections() {
    let fx = setup_all().await;
    let url = fx.port_forward_url().await;
    assert!(url.contains("/portforward/"), "{url}");
    let path = split_url(&url).1;
    let addr = fx.addr();
    blocking(move || {
        let mut c = Spdy::connect(addr, &path, &[PF_VERSION], PF_VERSION);
        let (error0, data0) = open_pf_pair(&mut c, "80", "0");
        c.send_data(data0, b"hello", false);
        assert_eq!(c.read_at_least(data0, 5), b"hello");
        // 奇数 ID の PING は同じ ID で返る。
        c.send(&Frame::Ping { id: 1 });
        while c.pings.is_empty() {
            c.pump_one();
        }
        assert_eq!(c.pings, [1]);
        // 同じ SPDY セッションで 2 対目を張る。
        let (error1, data1) = open_pf_pair(&mut c, "80", "1");
        c.send_data(data1, b"again", false);
        assert_eq!(c.read_at_least(data1, 5), b"again");
        // 1 対目を閉じると、data と error の両方が FIN で閉じ、error にエラー文は無い。
        c.send_data(data0, b"", true);
        assert_eq!(c.read_until_fin(data0), b"hello");
        assert_eq!(c.read_until_fin(error0), b"");
        c.send_data(data1, b"", true);
        assert_eq!(c.read_until_fin(data1), b"again");
        assert_eq!(c.read_until_fin(error1), b"");
        assert!(c.rsts.is_empty(), "{:?}", c.rsts);
    })
    .await;
}

/// CRI-6・TASK-63.5: exec と port-forward を同時に張っても互いを塞がない。使用済み・種別違いのトークンは 404 になる。
#[tokio::test]
async fn cri6_crictl_kinds_share_one_server_concurrently() {
    let fx = setup_all().await;
    let exec_path = fx.exec_path(&["cat"], true).await;
    let pf_path = split_url(&fx.port_forward_url().await).1;
    let addr = fx.addr();
    blocking(move || {
        // exec（cat。stdin を開いたまま）を張ったまま、port-forward の往復を行う。
        let mut ex = Spdy::connect(addr, &exec_path, &EXEC_VERSIONS, "v4.channel.k8s.io");
        let es = create_remote_streams(&mut ex, true, true);
        let stdin = es.stdin.expect("stdin");
        ex.send_data(stdin, b"one\n", false);

        let mut pf = Spdy::connect(addr, &pf_path, &[PF_VERSION], PF_VERSION);
        let (_error, data) = open_pf_pair(&mut pf, "80", "0");
        pf.send_data(data, b"two", false);
        assert_eq!(pf.read_at_least(data, 3), b"two");

        assert_eq!(ex.read_at_least(es.stdout, 4), b"one\n");
        ex.send_data(stdin, b"", true);
        let status = status_of(&ex.read_until_fin(es.error));
        assert_eq!(status["status"], "Success", "{status}");

        // 使用済みトークンは再利用できない（単回使用）。
        assert!(
            plain_post_status(addr, &exec_path).contains(" 404 "),
            "exec token must be single-use"
        );
        assert!(
            plain_post_status(addr, &pf_path).contains(" 404 "),
            "port-forward token must be single-use"
        );
    })
    .await;
}

/// CRI-6・TASK-63.5: 3 つの RPC が返す URL は、同じリスナー（`local_addr`）の種別ごとの接頭辞を指す。
/// 種別違いの接頭辞に未使用のトークンを載せても 404 になる（種別の束縛）。
#[tokio::test]
async fn cri6_crictl_urls_are_served_by_same_listener() {
    let fx = setup_all().await;
    let exec_url = fx
        .service
        .exec(Request::new(v1::ExecRequest {
            container_id: fx.container.clone(),
            cmd: vec!["echo".into()],
            stdout: true,
            stderr: true,
            ..Default::default()
        }))
        .await
        .expect("exec rpc")
        .into_inner()
        .url;
    let urls = [
        ("/exec/", exec_url.clone()),
        ("/attach/", fx.attach_url().await),
        ("/portforward/", fx.port_forward_url().await),
    ];
    let expect_authority = fx.addr().to_string();
    for (prefix, url) in urls {
        let (authority, path) = split_url(&url);
        assert_eq!(authority, expect_authority, "{url}");
        assert!(path.starts_with(prefix), "{url}");
    }
    let addr = fx.addr();
    let token = split_url(&exec_url)
        .1
        .rsplit('/')
        .next()
        .expect("token")
        .to_string();
    let status = blocking(move || plain_post_status(addr, &format!("/attach/{token}"))).await;
    assert!(status.contains(" 404 "), "{status}");
}
