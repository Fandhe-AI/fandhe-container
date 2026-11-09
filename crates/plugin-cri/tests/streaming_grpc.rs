//! 本番構成の `fandhe-container-plugin-cri` が返す PortForward の URL と、NODE ネットワークの往復バイト列の一致を
//! 照合する結合試験（CRI-6・SEC-1・REPAIR-5・REPAIR-12・#3756。親 #3726・#3754・#3755）。
//!
//! バイナリ（`main.rs` の `serve` が `runtime_service_with_record_store` の後に `with_streaming` を注入した本番構成）を
//! 絶対パスで spawn し、UDS＋gRPC で RunPodSandbox（hostNetwork）→ PortForward の順に呼ぶ。得た URL へ
//! client-go 相当の SPDY で接続し、plugin 内の本番 dialer（`NodeLoopbackDialer`）が試験プロセスの loopback の
//! echo へつなぐ往復を、バイト列の完全一致と期限内の終了で照合する。プロセス内で `with_streaming` を足す試験では
//! `main.rs` の注入が消えても検出できないため、本番バイナリを使う。
//!
//! Exec は結線済みと検証の順序を照合する（#3761。URL の発行と実コンテナへの exec は `cri_exec_real.rs` の実機前提試験が照合する。#3762）。Attach の URL の照合は #3763 が足す。POD ネットワークは #3766 まで `UNIMPLEMENTED`
//! （単体試験で照合済み）。root・特権・外部プロセスは不要で、既定のテスト集合で走る。待ちはすべて期限つき。
//!
//! Linux 限定の理由: `CriPluginBackends::production()` の既定の状態ルートは Linux でだけ定義される
//! （`pod_sandbox_grpc.rs` と同じ扱い）。

#![cfg(target_os = "linux")]

// 残骸・PID 再利用と衝突しない排他作成の補助（REPAIR-12・#3435）。
#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;
// client-go 相当の SPDY クライアント（cri の試験と共有。cri へ逆依存できないため `#[path]`）。
#[path = "../../cri/tests/support/spdy_client.rs"]
mod spdy_client;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fandhe_container_cri::runtime::v1 as cri;
use fandhe_container_cri::runtime::v1::runtime_service_client::RuntimeServiceClient;
use fandhe_container_plugin::grpc::{GrpcClientConfig, call_with_deadline, connect_uds_channel};
use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginErrorCode};
use tonic::transport::Channel;

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-cri");
const WATCHDOG: Duration = Duration::from_secs(60);
const STARTUP_DEADLINE: Duration = Duration::from_secs(10);
const RPC_DEADLINE: Duration = Duration::from_secs(5);
const REAP_GRACE: Duration = Duration::from_secs(5);
/// SPDY 往復の部分の上限（REPAIR-5）。
const ROUND_TRIP_DEADLINE: Duration = Duration::from_secs(30);
const PF_VERSION: &str = "portforward.k8s.io";
/// 往復させるバイト数。`MAX_OUTGOING_DATA`（32 KiB）を超え、複数フレームに分かれる大きさにする。
const PAYLOAD_LEN: usize = 192 * 1024;
/// 送信の 1 回の大きさ。一度に押し込むと書き込みの滞留の上限で RST になるため、交互に送受信する。
const CHUNK: usize = 16 * 1024;

/// 0700 の一時ディレクトリ（Drop で削除）。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        Self(exclusive_dir::create(&format!("fcpc-{tag}")).expect("create temp dir"))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 子プロセスのガード。Drop で kill し、期限つきで回収する（REPAIR-5）。
struct ChildGuard(Child);

impl ChildGuard {
    fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.0.try_wait().ok().flatten()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let start = Instant::now();
        while start.elapsed() < REAP_GRACE {
            if matches!(self.0.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn spawn_server(sock: &Path, xdg: &Path) -> ChildGuard {
    spawn_server_with(sock, xdg, &[])
}

/// `--streaming-*` 等の追加引数つきで起動する（#4110）。
fn spawn_server_with(sock: &Path, xdg: &Path, extra: &[&str]) -> ChildGuard {
    let child = Command::new(BIN)
        .arg("--socket")
        .arg(sock)
        .args(extra)
        .env_clear()
        .env("XDG_RUNTIME_DIR", xdg)
        // 既定の集合では本番の保持役（AppArmor の緩和と supervisor の bin が要る）を注入しない。実機前提の試験は注入する（H6・#2877）。
        .env("FANDHE_CONTAINER_TEST_POD_HOLDER", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn plugin binary");
    ChildGuard(child)
}

/// socket の出現と接続の成功を、全体の期限内で待つ。子が先に終了したら診断つきで失敗する。
async fn connect_when_ready(sock: &Path, guard: &mut ChildGuard) -> Channel {
    let start = Instant::now();
    loop {
        if let Some(status) = guard.exited() {
            let mut err = String::new();
            if let Some(mut s) = guard.0.stderr.take() {
                use std::io::Read;
                let _ = s.read_to_string(&mut err);
            }
            panic!("plugin binary exited early: {status:?}: {err}");
        }
        if sock.exists() {
            match connect_uds_channel(
                sock,
                &GrpcClientConfig::new(),
                Box::new(JsonLinesPeerAuthObserver::new()),
            )
            .await
            {
                Ok(ch) => return ch,
                Err(e)
                    if matches!(
                        e.code(),
                        PluginErrorCode::NotFound | PluginErrorCode::Unavailable
                    ) => {}
                Err(e) => panic!("connect failed: {:?}", e.code()),
            }
        }
        assert!(start.elapsed() < STARTUP_DEADLINE, "startup deadline");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// hostNetwork（NODE ネットワーク）の sandbox を作る要求。
fn run_node_req(name: &str) -> cri::RunPodSandboxRequest {
    cri::RunPodSandboxRequest {
        config: Some(cri::PodSandboxConfig {
            metadata: Some(cri::PodSandboxMetadata {
                name: name.into(),
                uid: "uid-1".into(),
                namespace: "default".into(),
                attempt: 0,
            }),
            linux: Some(cri::LinuxPodSandboxConfig {
                security_context: Some(cri::LinuxSandboxSecurityContext {
                    namespace_options: Some(cri::NamespaceOption {
                        network: cri::NamespaceMode::Node as i32,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// 全バイト値を含む決定的なペイロード（乱数の依存を足さない）。
fn payload() -> Vec<u8> {
    (0..PAYLOAD_LEN)
        .map(|i| (i.wrapping_mul(31).wrapping_add(i / 256)) as u8)
        .collect()
}

/// 接続先へ SPDY で接続し、`payload` を往復させて返りを返す（ブロッキング）。
fn round_trip(addr: SocketAddr, path: &str, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut c = spdy_client::Spdy::connect(addr, path, &[PF_VERSION], PF_VERSION);
    let (error, data) = spdy_client::open_pf_pair(&mut c, &port.to_string(), "0");
    let mut sent = 0;
    for chunk in payload.chunks(CHUNK) {
        c.send_data(data, chunk, false);
        sent += chunk.len();
        c.read_at_least(data, sent);
    }
    c.send_data(data, b"", true);
    let echoed = c.read_until_fin(data);
    assert!(
        c.read_until_fin(error).is_empty(),
        "error stream must be empty"
    );
    assert!(c.rsts.is_empty(), "no RST_STREAM expected");
    assert!(
        matches!(c.goaway, None | Some(0)),
        "no abnormal GOAWAY expected"
    );
    echoed
}

/// CRI-6・SEC-1・REPAIR-5・#3756: 本番構成で NODE の sandbox への PortForward が `UNIMPLEMENTED` ではなく
/// loopback の URL を返し、その URL 経由で `NodeLoopbackDialer` が試験の echo とつなぎ、往復バイト列が完全一致する。
#[tokio::test]
async fn cri6_3756_production_binary_node_port_forward_round_trip() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new("pfsock");
        let xdg = TempDir::new("pfxdg");
        let sock = dir.0.join("s.sock");
        let mut guard = spawn_server(&sock, &xdg.0);
        let ch = connect_when_ready(&sock, &mut guard).await;
        let mut c = RuntimeServiceClient::new(ch.clone());

        let sandbox = call_with_deadline(c.run_pod_sandbox(run_node_req("pf-node")), RPC_DEADLINE)
            .await
            .expect("run node sandbox")
            .into_inner()
            .pod_sandbox_id;

        let echo = spdy_client::spawn_echo();
        let url = call_with_deadline(
            c.port_forward(cri::PortForwardRequest {
                pod_sandbox_id: sandbox.clone(),
                port: vec![i32::from(echo.port())],
            }),
            RPC_DEADLINE,
        )
        .await
        .expect("port-forward must return a url, not UNIMPLEMENTED")
        .into_inner()
        .url;
        // 外部へ公開しない既定（SEC-1）。値そのものは出力しない。
        assert!(url.starts_with("http://127.0.0.1:"), "url must be loopback");
        assert!(
            url.contains("/portforward/"),
            "url must be a portforward path"
        );
        let (authority, path) = spdy_client::split_url(&url);
        let addr: SocketAddr = authority.parse().expect("authority is a socket address");

        let want = payload();
        let port = echo.port();
        let start = Instant::now();
        let got = tokio::time::timeout(
            ROUND_TRIP_DEADLINE,
            tokio::task::spawn_blocking({
                let want = want.clone();
                move || round_trip(addr, &path, port, &want)
            }),
        )
        .await
        .expect("round trip deadline")
        .expect("round trip task");
        assert!(start.elapsed() < ROUND_TRIP_DEADLINE, "round trip too slow");
        assert_eq!(got.len(), want.len(), "echoed length");
        assert!(got == want, "echoed bytes must match exactly");

        call_with_deadline(
            c.stop_pod_sandbox(cri::StopPodSandboxRequest {
                pod_sandbox_id: sandbox.clone(),
            }),
            RPC_DEADLINE,
        )
        .await
        .expect("stop");
        call_with_deadline(
            c.remove_pod_sandbox(cri::RemovePodSandboxRequest {
                pod_sandbox_id: sandbox,
            }),
            RPC_DEADLINE,
        )
        .await
        .expect("remove");
        drop((c, ch));
        assert!(guard.exited().is_none(), "server must still be running");
    })
    .await
    .expect("watchdog");
}

/// CRI-6・SEC-1・REPAIR-3・#3761: 本番構成で `Exec` が `UNIMPLEMENTED` ではなく結線済みで、検証の順序が固定である
/// （tty と相対 `argv[0]` は URL の発行前に `INVALID_ARGUMENT`、不在のコンテナは `NOT_FOUND`）。
/// `main.rs` の exec 起動役の注入が消えれば `UNIMPLEMENTED` に戻って検出できる。実コンテナでの通しは #3762。
#[tokio::test]
async fn cri6_3761_production_binary_exec_is_wired_and_fail_closed() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new("exsock");
        let xdg = TempDir::new("exxdg");
        let sock = dir.0.join("s.sock");
        let mut guard = spawn_server(&sock, &xdg.0);
        let ch = connect_when_ready(&sock, &mut guard).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        let exec = |cmd: &str, tty: bool| cri::ExecRequest {
            container_id: "no-such-container".to_string(),
            cmd: vec![cmd.to_string()],
            stdout: true,
            tty,
            ..Default::default()
        };

        let e = call_with_deadline(c.exec(exec("/bin/true", false)), RPC_DEADLINE)
            .await
            .expect_err("missing container");
        assert_eq!(e.code(), PluginErrorCode::NotFound, "exec must be wired");

        let e = call_with_deadline(c.exec(exec("/bin/true", true)), RPC_DEADLINE)
            .await
            .expect_err("tty");
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), "exec with tty is not supported");

        let e = call_with_deadline(c.exec(exec("true", false)), RPC_DEADLINE)
            .await
            .expect_err("relative");
        assert_eq!(e.code(), PluginErrorCode::InvalidArgument);
        assert_eq!(e.message(), "exec command must be an absolute path");

        drop((c, ch));
        assert!(guard.exited().is_none(), "server must still be running");
    })
    .await
    .expect("watchdog");
}

/// SIGTERM で正常停止させ、期限つきで回収して stderr 全体を返す（#4110。警告行の照合用）。
async fn terminate_and_read_stderr(guard: &mut ChildGuard) -> String {
    let pid = guard.0.id().to_string();
    let st = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("kill");
    assert!(st.success(), "kill -TERM");
    let start = Instant::now();
    while guard.exited().is_none() {
        assert!(
            start.elapsed() < REAP_GRACE * 2,
            "server must stop on SIGTERM"
        );
        // 同期の sleep だと current-thread のランタイムが止まり、クライアント接続の後始末が進まず停止が猶予まで延びる。
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut err = String::new();
    if let Some(mut s) = guard.0.stderr.take() {
        use std::io::Read;
        let _ = s.read_to_string(&mut err);
    }
    err
}

/// 警告行（固定 JSON 1 行）の出現回数。
fn count_warning(stderr: &str) -> usize {
    stderr
        .lines()
        .filter(|l| l.contains("cri_streaming_external_exposure"))
        .count()
}

/// CRI-6・REPAIR-3・SEC-1・#4110: 既定は loopback の URL を返し、警告行を出さない。
#[tokio::test]
async fn cri6_4110_production_binary_default_is_loopback_without_warning() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new("dfsock");
        let xdg = TempDir::new("dfxdg");
        let sock = dir.0.join("s.sock");
        let mut guard = spawn_server(&sock, &xdg.0);
        let ch = connect_when_ready(&sock, &mut guard).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        let sandbox = call_with_deadline(c.run_pod_sandbox(run_node_req("df-node")), RPC_DEADLINE)
            .await
            .expect("run node sandbox")
            .into_inner()
            .pod_sandbox_id;
        let url = call_with_deadline(
            c.port_forward(cri::PortForwardRequest {
                pod_sandbox_id: sandbox,
                port: vec![8080],
            }),
            RPC_DEADLINE,
        )
        .await
        .expect("port-forward url")
        .into_inner()
        .url;
        assert!(url.starts_with("http://127.0.0.1:"), "url must be loopback");
        drop((c, ch));
        let err = terminate_and_read_stderr(&mut guard).await;
        assert_eq!(count_warning(&err), 0, "no warning by default: {err}");
    })
    .await
    .expect("watchdog");
}

/// CRI-6・REPAIR-3・SEC-1・#4110: opt-in で 0.0.0.0 に bind し、広告アドレスの URL を返し、警告行をちょうど 1 回出す。
/// 広告アドレス（192.0.2.7、TEST-NET-1）は到達できないので、authority を 127.0.0.1 に差し替えてワイルドカード bind を実証する。
#[tokio::test]
async fn cri6_4110_production_binary_opt_in_binds_wildcard_and_advertises() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new("optsock");
        let xdg = TempDir::new("optxdg");
        let sock = dir.0.join("s.sock");
        let mut guard = spawn_server_with(
            &sock,
            &xdg.0,
            &[
                "--streaming-bind=0.0.0.0:0",
                "--streaming-allow-external",
                "--streaming-advertise=192.0.2.7",
            ],
        );
        let ch = connect_when_ready(&sock, &mut guard).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        let sandbox = call_with_deadline(c.run_pod_sandbox(run_node_req("opt-node")), RPC_DEADLINE)
            .await
            .expect("run node sandbox")
            .into_inner()
            .pod_sandbox_id;
        let echo = spdy_client::spawn_echo();
        let url = call_with_deadline(
            c.port_forward(cri::PortForwardRequest {
                pod_sandbox_id: sandbox,
                port: vec![i32::from(echo.port())],
            }),
            RPC_DEADLINE,
        )
        .await
        .expect("port-forward url")
        .into_inner()
        .url;
        assert!(
            url.starts_with("http://192.0.2.7:"),
            "url must carry the advertise address"
        );
        let (authority, path) = spdy_client::split_url(&url);
        let port: u16 = authority
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .expect("advertised port");
        assert_ne!(port, 0);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("loopback addr");
        let want = payload();
        let echo_port = echo.port();
        let got = tokio::time::timeout(
            ROUND_TRIP_DEADLINE,
            tokio::task::spawn_blocking({
                let want = want.clone();
                move || round_trip(addr, &path, echo_port, &want)
            }),
        )
        .await
        .expect("round trip deadline")
        .expect("round trip task");
        assert!(got == want, "echoed bytes must match exactly");
        drop((c, ch));
        let err = terminate_and_read_stderr(&mut guard).await;
        assert_eq!(count_warning(&err), 1, "exactly one warning: {err}");
        assert!(err.contains("without TLS or authentication"), "{err}");
        assert!(!err.contains("192.0.2.7"), "address must not be logged");
    })
    .await
    .expect("watchdog");
}
