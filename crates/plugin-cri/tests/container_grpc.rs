//! Container 系 RPC（Create・Start・Stop・RemoveContainer）の UDS＋gRPC 境界越しの結合試験
//! （TASK-114.3.2・#850・PLUG-1・PLUG-2・PLUG-12・CRI-2・CRI-7・REPAIR-5・REPAIR-12）。
//!
//! 2 段で確かめる。段 A は実バイナリ `fandhe-container-plugin-cri` を絶対パスで spawn し（PATH 探索なし）、
//! Container 系 4 RPC が境界を越えて届くことを本番バックエンドの現状の応答（具体値）で固定する。
//! 段 B は同じ `server::serve`（実 UDS・peer UID 検証つき）にフェイクの実行層を注入した `CriRuntimeService` を
//! 載せ、PodSandbox 作成からコンテナの作成・起動・停止・削除・サンドボックスの停止・削除までの一連が
//! `connect_uds_channel` 越しに成功することを確かめる。
//!
//! 本番バックエンドでの一連は未達（REPAIR-3）: 本番の `BundleProvider` は #2433、supervisor 経由の
//! start / stop と cgroup remover の結線は #2434 で入る。それまで段 A の CreateContainer は
//! `UNIMPLEMENTED`（イメージ参照の未解決）で終わるため、成功経路へ切り替える際は段 A の期待値を意識的に書き換える。
//! ハーネス（TempDir・ChildGuard・接続待ち）は `pod_sandbox_grpc.rs` と同じもの（試験 crate 間でモジュールを共有できないため複製）。
//! 段 B のフェイクは `crates/cri/tests/adapter_integration.rs` の `LifecycleRuntime` を最小化して写したもの。
//!
//! root・特権は不要で、既定のテスト集合で走る。待ちはすべて期限つき。
//! Linux 限定の理由: `CriPluginBackends::production()` の既定の状態ルートは Linux（ゲスト）でだけ
//! 定義され、macOS / Windows では `Unimplemented` になるため（`tests/adapter.rs` と同じ扱い。黙って通すのではなく
//! この明示を残す）。段 B も試験の構成を揃えるため Linux 限定にする。

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerState, ContainerStatus, CreateRequest, DeleteRequest,
    DeleteResponse, ErrorCode, KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{BundleProvider, BundleRequest, RuntimeAdapter};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1 as cri;
use fandhe_container_cri::runtime::v1::runtime_service_client::RuntimeServiceClient;
use fandhe_container_cri::runtime_service::CriRuntimeService;
use fandhe_container_plugin::grpc::{
    GrpcClientConfig, GrpcServerConfig, call_with_deadline, connect_uds_channel,
};
use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginError, PluginErrorCode};
use fandhe_container_plugin_cri::server;
use tonic::transport::Channel;

const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-cri");
const WATCHDOG: Duration = Duration::from_secs(60);
const STARTUP_DEADLINE: Duration = Duration::from_secs(10);
const RPC_DEADLINE: Duration = Duration::from_secs(5);
const REAP_GRACE: Duration = Duration::from_secs(5);
/// 停止時にフェイクが返す終了コード（SIGTERM 相当。境界越しの反映確認用の具体値）。
const STOP_EXIT_CODE: i32 = 143;

/// 0700 の一時ディレクトリ（Drop で削除）。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "fccg-{tag}-{}-{}",
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

/// プロセス内サーバー task のガード。Drop で abort する（`tokio::sync` は承認範囲外のため使わない）。
struct ServeGuard(tokio::task::JoinHandle<()>);

impl Drop for ServeGuard {
    fn drop(&mut self) {
        self.0.abort();
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

/// socket の出現と接続の成功を、全体の期限内で待つ。`guard` があり子が先に終了したら診断つきで失敗する。
async fn connect_when_ready(sock: &Path, mut guard: Option<&mut ChildGuard>) -> Channel {
    let start = Instant::now();
    loop {
        if let Some(guard) = guard.as_deref_mut()
            && let Some(status) = guard.exited()
        {
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

// ---- クライアント側の要求の組み立てと呼び出し ----

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

fn create_req(sandbox_id: &str, name: &str) -> cri::CreateContainerRequest {
    cri::CreateContainerRequest {
        pod_sandbox_id: sandbox_id.into(),
        config: Some(cri::ContainerConfig {
            metadata: Some(cri::ContainerMetadata {
                name: name.into(),
                attempt: 0,
            }),
            image: Some(cri::ImageSpec {
                image: "busybox:1.36".into(),
                ..Default::default()
            }),
            ..Default::default()
        }),
        sandbox_config: None,
    }
}

type Client = RuntimeServiceClient<Channel>;

async fn run_sandbox(c: &mut Client, name: &str) -> String {
    let id = call_with_deadline(c.run_pod_sandbox(run_req(name)), RPC_DEADLINE)
        .await
        .expect("run sandbox")
        .into_inner()
        .pod_sandbox_id;
    assert_eq!(id.len(), 64);
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    id
}

async fn stop_sandbox(c: &mut Client, id: &str) -> Result<(), PluginError> {
    call_with_deadline(
        c.stop_pod_sandbox(cri::StopPodSandboxRequest {
            pod_sandbox_id: id.into(),
        }),
        RPC_DEADLINE,
    )
    .await
    .map(|_| ())
}

async fn remove_sandbox(c: &mut Client, id: &str) -> Result<(), PluginError> {
    call_with_deadline(
        c.remove_pod_sandbox(cri::RemovePodSandboxRequest {
            pod_sandbox_id: id.into(),
        }),
        RPC_DEADLINE,
    )
    .await
    .map(|_| ())
}

async fn sandbox_state(c: &mut Client, id: &str) -> Result<i32, PluginError> {
    call_with_deadline(
        c.pod_sandbox_status(cri::PodSandboxStatusRequest {
            pod_sandbox_id: id.into(),
            verbose: false,
        }),
        RPC_DEADLINE,
    )
    .await
    .map(|r| r.into_inner().status.expect("status body").state)
}

async fn create_container(
    c: &mut Client,
    sandbox_id: &str,
    name: &str,
) -> Result<String, PluginError> {
    call_with_deadline(
        c.create_container(create_req(sandbox_id, name)),
        RPC_DEADLINE,
    )
    .await
    .map(|r| r.into_inner().container_id)
}

async fn start_container(c: &mut Client, id: &str) -> Result<(), PluginError> {
    call_with_deadline(
        c.start_container(cri::StartContainerRequest {
            container_id: id.into(),
        }),
        RPC_DEADLINE,
    )
    .await
    .map(|_| ())
}

async fn stop_container(c: &mut Client, id: &str, timeout: i64) -> Result<(), PluginError> {
    call_with_deadline(
        c.stop_container(cri::StopContainerRequest {
            container_id: id.into(),
            timeout,
        }),
        RPC_DEADLINE,
    )
    .await
    .map(|_| ())
}

async fn remove_container(c: &mut Client, id: &str) -> Result<(), PluginError> {
    call_with_deadline(
        c.remove_container(cri::RemoveContainerRequest {
            container_id: id.into(),
        }),
        RPC_DEADLINE,
    )
    .await
    .map(|_| ())
}

async fn container_status(c: &mut Client, id: &str) -> Result<cri::ContainerStatus, PluginError> {
    call_with_deadline(
        c.container_status(cri::ContainerStatusRequest {
            container_id: id.into(),
            verbose: false,
        }),
        RPC_DEADLINE,
    )
    .await
    .map(|r| r.into_inner().status.expect("status body"))
}

async fn list_containers_len(c: &mut Client) -> usize {
    call_with_deadline(
        c.list_containers(cri::ListContainersRequest { filter: None }),
        RPC_DEADLINE,
    )
    .await
    .expect("list containers")
    .into_inner()
    .containers
    .len()
}

/// 段 A（PLUG-1・CRI-2・CRI-7）: Container 系 4 RPC が実バイナリへ届き、本番バックエンドの現状の応答が
/// 境界を越えて返る。作成の失敗は半端な記録を残さず、未知 ID は状態を変えない。
#[tokio::test]
async fn container_rpcs_reach_the_plugin_binary() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new("sock");
        let xdg = TempDir::new("xdg");
        let sock = dir.0.join("s.sock");
        let mut guard = spawn_server(&sock, &xdg.0);
        let ch = connect_when_ready(&sock, Some(&mut guard)).await;
        let mut c = RuntimeServiceClient::new(ch.clone());

        let sb = run_sandbox(&mut c, "pod-a").await;

        // 本番の `BundleProvider`（#2433）はイメージ参照の解決まで進む。`ImageStore` 未注入のため
        // image ID 以外の参照は UNIMPLEMENTED で、半端な記録は残さない。
        let err = create_container(&mut c, &sb, "c")
            .await
            .expect_err("image reference resolution is unavailable");
        assert_eq!(err.code(), PluginErrorCode::Unimplemented);
        assert_eq!(
            err.message(),
            "image reference resolution is not available; use the image id"
        );
        assert_eq!(list_containers_len(&mut c).await, 0);

        // 未知の 64 桁 hex の ID。
        let unknown = "0".repeat(64);
        let err = start_container(&mut c, &unknown).await.expect_err("start");
        assert_eq!(err.code(), PluginErrorCode::NotFound);
        let err = stop_container(&mut c, &unknown, 10)
            .await
            .expect_err("stop");
        assert_eq!(err.code(), PluginErrorCode::NotFound);
        // RemoveContainer の未知 ID は成功（冪等。proto コメント）。
        remove_container(&mut c, &unknown).await.expect("remove");
        assert_eq!(list_containers_len(&mut c).await, 0);

        // サンドボックスの片付けは成功し、サーバーは生き続ける。
        stop_sandbox(&mut c, &sb).await.expect("stop sandbox");
        remove_sandbox(&mut c, &sb).await.expect("remove sandbox");
        drop((c, ch));
        assert!(guard.exited().is_none(), "server must still be running");
    })
    .await
    .expect("watchdog");
}

/// 状態を保持し遷移規則を守るフェイクの実行層。呼び出し列も記録する
/// （`crates/cri/tests/adapter_integration.rs` の `LifecycleRuntime` の最小化）。
#[derive(Default)]
struct FakeRuntime {
    calls: Mutex<Vec<String>>,
    states: Mutex<HashMap<String, ContainerState>>,
}

impl FakeRuntime {
    fn log(&self, line: String) {
        self.calls.lock().unwrap().push(line);
    }
    /// `state` 以外の呼び出し列（状態確認の問い合わせは件数が実装依存のため除く）。
    fn mutating_calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| !c.starts_with("state "))
            .cloned()
            .collect()
    }
}

struct SharedRuntime(Arc<FakeRuntime>);

fn no_such() -> TraitError {
    TraitError::new(ErrorCode::NotFound, "no such container")
}

impl ContainerRuntime for SharedRuntime {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        let id = r.id().as_str().to_owned();
        self.0.log(format!("create {id} {}", r.bundle().display()));
        let mut states = self.0.states.lock().unwrap();
        if states.contains_key(&id) {
            return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
        }
        states.insert(id, ContainerState::Created);
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
    fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
        let id = r.id().as_str().to_owned();
        self.0.log(format!("start {id}"));
        let mut states = self.0.states.lock().unwrap();
        match states.get(&id) {
            None => Err(no_such()),
            Some(ContainerState::Created) => {
                states.insert(id, ContainerState::Running);
                Ok(ContainerStatus::running(
                    r.id().clone(),
                    std::num::NonZeroU32::new(4242),
                ))
            }
            Some(_) => Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "not created",
            )),
        }
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
        let id = r.id().as_str().to_owned();
        self.0.log(format!("stop {id} {}s", r.grace().as_secs()));
        let mut states = self.0.states.lock().unwrap();
        match states.get(&id) {
            None => Err(no_such()),
            Some(ContainerState::Running | ContainerState::Created) => {
                states.insert(id, ContainerState::Stopped);
                Ok(ContainerStatus::stopped(
                    r.id().clone(),
                    Some(STOP_EXIT_CODE),
                ))
            }
            Some(_) => Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "not running",
            )),
        }
    }
    fn delete(&self, r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        let id = r.id().as_str().to_owned();
        self.0.log(format!("delete {id} force={}", r.force()));
        let mut states = self.0.states.lock().unwrap();
        match states.get(&id) {
            None => Err(no_such()),
            Some(ContainerState::Running) if !r.force() => Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "running without force",
            )),
            Some(_) => {
                states.remove(&id);
                Ok(DeleteResponse::new())
            }
        }
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        let id = r.id().as_str();
        self.0.log(format!("state {id}"));
        match self.0.states.lock().unwrap().get(id).copied() {
            None => Err(no_such()),
            Some(ContainerState::Created) => Ok(ContainerStatus::created(r.id().clone(), None)),
            Some(ContainerState::Running) => Ok(ContainerStatus::running(
                r.id().clone(),
                std::num::NonZeroU32::new(4242),
            )),
            Some(_) => Ok(ContainerStatus::stopped(
                r.id().clone(),
                Some(STOP_EXIT_CODE),
            )),
        }
    }
}

/// bundle の用意・解放を記録するフェイク。実ディレクトリは作らず絶対パスだけを返す。
#[derive(Default)]
struct RecordingBundles(Mutex<Vec<String>>);

impl BundleProvider for RecordingBundles {
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PathBuf, CriError> {
        let (container_id, sandbox_id, config) = (req.container_id, req.sandbox_id, req.config);
        let name = config.metadata.as_ref().map_or("", |m| m.name.as_str());
        self.0
            .lock()
            .unwrap()
            .push(format!("prepare {container_id} {sandbox_id} {name}"));
        Ok(PathBuf::from("/bundles").join(container_id))
    }
    fn release(&self, container_id: &str) -> Result<(), CriError> {
        self.0
            .lock()
            .unwrap()
            .push(format!("release {container_id}"));
        Ok(())
    }
}

/// 段 B（PLUG-1・CRI-2・CRI-7・REPAIR-12）: 実 UDS＋gRPC（`server::serve`・peer UID 検証つき）越しに、
/// PodSandbox 作成→コンテナ作成→起動→停止→削除→サンドボックスの停止・削除の一連が成功し、
/// 各段階の状態と実行層・bundle の呼び出し列が具体値で一致する。
#[tokio::test]
async fn container_lifecycle_crosses_the_uds_grpc_boundary() {
    tokio::time::timeout(WATCHDOG, async {
        let runtime = Arc::new(FakeRuntime::default());
        let bundles = Arc::new(RecordingBundles::default());
        let service = CriRuntimeService::new().with_runtime(
            RuntimeAdapter::new(Arc::new(SharedRuntime(Arc::clone(&runtime)))),
            bundles.clone(),
        );
        let dir = TempDir::new("sock");
        let sock = dir.0.join("s.sock");
        let serve_sock = sock.clone();
        let _serve = ServeGuard(tokio::spawn(async move {
            let _ = server::serve(
                &serve_sock,
                service,
                &GrpcServerConfig::new(),
                std::future::pending(),
            )
            .await;
        }));
        let ch = connect_when_ready(&sock, None).await;
        let mut c = RuntimeServiceClient::new(ch);

        let sb = run_sandbox(&mut c, "pod-b").await;
        assert_eq!(
            sandbox_state(&mut c, &sb).await.expect("sandbox status"),
            cri::PodSandboxState::SandboxReady as i32
        );

        let id = create_container(&mut c, &sb, "c").await.expect("create");
        let st = container_status(&mut c, &id).await.expect("status");
        assert_eq!(st.state, cri::ContainerState::ContainerCreated as i32);
        assert_eq!(st.started_at, 0);

        start_container(&mut c, &id).await.expect("start");
        let st = container_status(&mut c, &id).await.expect("status");
        assert_eq!(st.state, cri::ContainerState::ContainerRunning as i32);

        stop_container(&mut c, &id, 10).await.expect("stop");
        let st = container_status(&mut c, &id).await.expect("status");
        assert_eq!(st.state, cri::ContainerState::ContainerExited as i32);
        assert_eq!(st.exit_code, STOP_EXIT_CODE);

        remove_container(&mut c, &id).await.expect("remove");
        assert_eq!(list_containers_len(&mut c).await, 0);
        let err = container_status(&mut c, &id).await.expect_err("removed");
        assert_eq!(err.code(), PluginErrorCode::NotFound);

        stop_sandbox(&mut c, &sb).await.expect("stop sandbox");
        assert_eq!(
            sandbox_state(&mut c, &sb).await.expect("sandbox status"),
            cri::PodSandboxState::SandboxNotready as i32
        );
        remove_sandbox(&mut c, &sb).await.expect("remove sandbox");
        let err = sandbox_state(&mut c, &sb).await.expect_err("removed");
        assert_eq!(err.code(), PluginErrorCode::NotFound);

        // 境界越しの RPC が実行層まで届いたことを、呼び出し列で確かめる。
        assert_eq!(
            runtime.mutating_calls(),
            vec![
                format!("create {id} /bundles/{id}"),
                format!("start {id}"),
                format!("stop {id} 10s"),
                format!("delete {id} force=true"),
            ]
        );
        assert_eq!(
            bundles.0.lock().unwrap().clone(),
            vec![format!("prepare {id} {sb} c"), format!("release {id}")]
        );
        assert!(runtime.states.lock().unwrap().is_empty());
    })
    .await
    .expect("watchdog");
}
