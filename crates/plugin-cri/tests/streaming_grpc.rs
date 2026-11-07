//! 本番構成の `fandhe-container-plugin-cri` が返す PortForward の URL と、NODE ネットワークの往復バイト列の一致を
//! 照合する結合試験（CRI-6・SEC-1・REPAIR-5・REPAIR-12・#3756。親 #3726・#3754・#3755）。
//!
//! バイナリ（`main.rs` の `serve` が `runtime_service_with_record_store` の後に `with_streaming` を注入した本番構成）を
//! 絶対パスで spawn し、UDS＋gRPC で RunPodSandbox（hostNetwork）→ PortForward の順に呼ぶ。得た URL へ
//! client-go 相当の SPDY で接続し、plugin 内の本番 dialer（`NodeLoopbackDialer`）が試験プロセスの loopback の
//! echo へつなぐ往復を、バイト列の完全一致と期限内の終了で照合する。プロセス内で `with_streaming` を足す試験では
//! `main.rs` の注入が消えても検出できないため、本番バイナリを使う。
//!
//! Exec は結線済みと検証の順序を照合する（#3761。URL の発行は実コンテナが要るため #3762）。Attach の URL の照合は #3763 が足す。POD ネットワークは #3766 まで `UNIMPLEMENTED`
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
    let child = Command::new(BIN)
        .arg("--socket")
        .arg(sock)
        .env_clear()
        .env("XDG_RUNTIME_DIR", xdg)
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
