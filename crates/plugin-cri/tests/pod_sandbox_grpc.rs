//! 別プロセスの `fandhe-container-plugin-cri` を UDS＋gRPC で呼ぶ PodSandbox 系 RPC の結合試験
//! （TASK-114.3.1・#849・PLUG-1・PLUG-2・PLUG-12・CRI-1・CRI-2・CRI-7・REPAIR-5・REPAIR-12）。
//!
//! バイナリを絶対パスで spawn し（PATH 探索なし）、`connect_uds_channel`（peer UID 検証つき）で接続して
//! RunPodSandbox・StopPodSandbox・RemovePodSandbox が境界を越えて成功することを具体値で照合する。
//! root・特権は不要で、既定のテスト集合で走る。待ちはすべて期限つき。
//!
//! Linux 限定の理由: `CriPluginBackends::production()` の既定の状態ルートは Linux（ゲスト）でだけ
//! 定義され、macOS / Windows では `Unimplemented` になるため（`tests/adapter.rs` と同じ扱い。黙って通すのではなく
//! この明示を残す）。

#![cfg(target_os = "linux")]

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
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

/// 0700 の一時ディレクトリ（Drop で削除）。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fcpc-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&p)
            .expect("create temp dir");
        Self(p)
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

fn run_req(name: &str) -> cri::RunPodSandboxRequest {
    cri::RunPodSandboxRequest {
        config: Some(cri::PodSandboxConfig {
            metadata: Some(cri::PodSandboxMetadata {
                name: name.into(),
                uid: "uid-1".into(),
                namespace: "default".into(),
                attempt: 0,
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn status_state(
    c: &mut RuntimeServiceClient<Channel>,
    id: &str,
) -> Result<i32, tonic::Status> {
    let r = call_with_deadline(
        c.pod_sandbox_status(cri::PodSandboxStatusRequest {
            pod_sandbox_id: id.into(),
            verbose: false,
        }),
        RPC_DEADLINE,
    )
    .await
    .map_err(into_status)?;
    Ok(r.into_inner().status.expect("status").state)
}

/// `call_with_deadline` の PluginError を gRPC コードへ戻して照合しやすくする。
fn into_status(e: fandhe_container_plugin::PluginError) -> tonic::Status {
    let code = match e.code() {
        PluginErrorCode::NotFound => tonic::Code::NotFound,
        PluginErrorCode::InvalidArgument => tonic::Code::InvalidArgument,
        PluginErrorCode::Timeout => tonic::Code::DeadlineExceeded,
        _ => tonic::Code::Unknown,
    };
    tonic::Status::new(code, e.message().to_string())
}

/// PLUG-1・CRI-2・CRI-7: Run → Status → Stop（冪等）→ Remove が別プロセスへ届き、成功の応答が返る。
#[tokio::test]
async fn pod_sandbox_rpcs_cross_the_uds_grpc_boundary() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new("sock");
        let xdg = TempDir::new("xdg");
        let sock = dir.0.join("s.sock");
        let mut guard = spawn_server(&sock, &xdg.0);
        let ch = connect_when_ready(&sock, &mut guard).await;
        let mut c = RuntimeServiceClient::new(ch.clone());

        let id = call_with_deadline(c.run_pod_sandbox(run_req("pod-a")), RPC_DEADLINE)
            .await
            .expect("run")
            .into_inner()
            .pod_sandbox_id;
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(
            status_state(&mut c, &id).await.expect("status"),
            cri::PodSandboxState::SandboxReady as i32
        );

        for _ in 0..2 {
            call_with_deadline(
                c.stop_pod_sandbox(cri::StopPodSandboxRequest {
                    pod_sandbox_id: id.clone(),
                }),
                RPC_DEADLINE,
            )
            .await
            .expect("stop (idempotent)");
        }
        assert_eq!(
            status_state(&mut c, &id).await.expect("status"),
            cri::PodSandboxState::SandboxNotready as i32
        );

        call_with_deadline(
            c.remove_pod_sandbox(cri::RemovePodSandboxRequest {
                pod_sandbox_id: id.clone(),
            }),
            RPC_DEADLINE,
        )
        .await
        .expect("remove");
        let st = status_state(&mut c, &id).await.expect_err("removed");
        assert_eq!(st.code(), tonic::Code::NotFound);

        // 未知の ID の Stop は NotFound として境界を越えて返る。
        let st = call_with_deadline(
            c.stop_pod_sandbox(cri::StopPodSandboxRequest {
                pod_sandbox_id: "0".repeat(64),
            }),
            RPC_DEADLINE,
        )
        .await
        .expect_err("unknown id");
        assert_eq!(st.code(), PluginErrorCode::NotFound);

        drop((c, ch));
        assert!(guard.exited().is_none(), "server must still be running");
    })
    .await
    .expect("watchdog");
}
