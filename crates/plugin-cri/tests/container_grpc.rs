//! Container 系 RPC と ImageService の UDS＋gRPC 境界越しの結合試験
//! （TASK-114.3.2・#850・#2592・PLUG-1・PLUG-2・PLUG-12・CRI-2・CRI-3・CRI-7・REPAIR-5・REPAIR-12）。
//!
//! 3 段で確かめる。
//!
//! - 段 A（既定の集合・root 不要・ネットワーク不要）: 実バイナリ `fandhe-container-plugin-cri` を絶対パスで spawn し（PATH 探索なし）、
//!   同じ UDS で `ImageService` がサーブされていること（`ListImages`・`ImageStatus`・`PullImage` の入力検証）と、Container 系 RPC が
//!   境界を越えて届き成功することを具体値で固定する。バイナリが起動して作った状態ルートの `.cri/images` に、偽のレジストリクライアントで
//!   pull 済みキャッシュを用意し、image ID（`sha256:<hex>`）で CreateContainer → Status → Remove まで通す。タグの解決は在庫が
//!   プロセス内だけで、CI ではレジストリへ出られないため、ここでは「未知のタグは `NOT_FOUND`（半端な記録を残さない）」で照合し、
//!   成功側は段 C に置く。
//! - 段 B: 同じ `server::serve`（実 UDS・peer UID 検証つき）にフェイクの実行層を注入した `CriRuntimeService` を載せ、
//!   PodSandbox 作成からコンテナの作成・起動・停止・削除・サンドボックスの停止・削除までの一連が `connect_uds_channel` 越しに
//!   成功することを確かめる。
//! - 段 C（`#[ignore]`・実機前提）: 本番バイナリで `PullImage`（実レジストリ）→ タグで CreateContainer → Start → Stop → Remove →
//!   サンドボックスの停止・削除まで通す。理由と前提は該当の試験の doc コメントを参照（`AGENTS.md`「実機前提テスト」）。
//!
//! ハーネス（TempDir・ChildGuard・接続待ち）は `pod_sandbox_grpc.rs` と同じもの（試験 crate 間でモジュールを共有できないため複製）。
//! 段 A のキャッシュ用の偽クライアント・tar の組み立ては `crates/cri/tests/bundle_image_rootfs.rs` を最小化して写したもの
//! （sha256 は oci の `Digest::sha256_of`）。段 B のフェイクは `crates/cri/tests/adapter_integration.rs` の `LifecycleRuntime` を
//! 最小化して写したもの。待ちはすべて期限つき。
//!
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
use fandhe_container_cri::adapter::{
    BundleProvider, BundleRequest, PreparedBundle, RuntimeAdapter,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::image_pull::{
    ImagePuller, OciImagePuller, PullConfig, PullRequest, PulledManifest, RegistryPullClient,
};
use fandhe_container_cri::runtime::v1 as cri;
use fandhe_container_cri::runtime::v1::image_service_client::ImageServiceClient;
use fandhe_container_cri::runtime::v1::runtime_service_client::RuntimeServiceClient;
use fandhe_container_cri::runtime_service::CriRuntimeService;
use fandhe_container_oci::auth::{BasicCredentials, RegistryAuth};
use fandhe_container_oci::error::{OciError, OciErrorCode};
use fandhe_container_oci::image_management::StagedBlobWriter;
use fandhe_container_oci::manifest::{
    Descriptor, ImageManifest, ParsedManifest, Platform, parse_manifest,
};
use fandhe_container_oci::reference::{Digest, Reference, RegistryHost, Repository};
use fandhe_container_oci::registry::RegistryEndpoint;
use fandhe_container_plugin::grpc::{
    GrpcClientConfig, GrpcServerConfig, call_with_deadline, connect_uds_channel,
};
use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PluginError, PluginErrorCode};
use fandhe_container_plugin_cri::server;
use std::io::Write as _;
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
async fn connect_when_ready(sock: &Path, guard: Option<&mut ChildGuard>) -> Channel {
    connect_when_ready_with(sock, guard, GrpcClientConfig::new()).await
}

/// `connect_when_ready` の設定指定版。Channel の request timeout（既定 10 秒）が
/// `call_with_deadline` の長い期限（PullImage 300 秒等）より先に効かないよう、実機経路で使う（REPAIR-5）。
async fn connect_when_ready_with(
    sock: &Path,
    mut guard: Option<&mut ChildGuard>,
    config: GrpcClientConfig,
) -> Channel {
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
            match connect_uds_channel(sock, &config, Box::new(JsonLinesPeerAuthObserver::new()))
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

fn create_req(sandbox_id: &str, name: &str, image: &str) -> cri::CreateContainerRequest {
    cri::CreateContainerRequest {
        pod_sandbox_id: sandbox_id.into(),
        config: Some(cri::ContainerConfig {
            metadata: Some(cri::ContainerMetadata {
                name: name.into(),
                attempt: 0,
            }),
            image: Some(image_spec(image)),
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
    image: &str,
) -> Result<String, PluginError> {
    call_with_deadline(
        c.create_container(create_req(sandbox_id, name, image)),
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

// ---- 段 A のキャッシュ用 fixture（偽レジストリ。`crates/cri/tests/bundle_image_rootfs.rs` の最小版）----

fn tar_entry(name: &str, mode: u32, data: &[u8], dir: bool) -> Vec<u8> {
    let mut h = [0u8; 512];
    let mut put = |off: usize, bytes: &[u8]| h[off..off + bytes.len()].copy_from_slice(bytes);
    put(0, name.as_bytes());
    put(100, format!("{mode:07o}\0").as_bytes());
    put(108, b"0000000\0");
    put(116, b"0000000\0");
    put(124, format!("{:011o}\0", data.len()).as_bytes());
    put(136, b"00000000000\0");
    put(148, b"        ");
    put(156, if dir { b"5" } else { b"0" });
    put(257, b"ustar\0");
    put(263, b"00");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    out.resize(512 + data.len().div_ceil(512) * 512, 0);
    out
}

/// 偽レジストリ: blob を digest から返す。manifest は固定。
struct FakeClient {
    manifest: ImageManifest,
    blobs: HashMap<String, Vec<u8>>,
}

impl RegistryPullClient for FakeClient {
    fn authenticate(
        &self,
        _e: &RegistryEndpoint,
        _r: &Repository,
        _c: Option<&BasicCredentials>,
        _t: &[RegistryHost],
    ) -> Result<RegistryAuth, OciError> {
        Ok(RegistryAuth::None)
    }

    fn fetch_manifest(
        &self,
        _e: &RegistryEndpoint,
        _r: &Repository,
        _reference: &Reference,
        _a: &RegistryAuth,
        _p: &Platform,
    ) -> Result<PulledManifest, OciError> {
        Ok(PulledManifest {
            manifest: self.manifest.clone(),
            selected_digest: None,
            manifest_digest: Digest::sha256_of(b"manifest"),
            index_digest: None,
        })
    }

    fn fetch_blob(
        &self,
        _e: &RegistryEndpoint,
        _r: &Repository,
        d: &Descriptor,
        _a: &RegistryAuth,
        dest: &mut StagedBlobWriter,
    ) -> Result<(), OciError> {
        let hex = d.digest.as_str().trim_start_matches("sha256:");
        let body = self
            .blobs
            .get(hex)
            .ok_or_else(|| OciError::new(OciErrorCode::NotFound, "blob"))?;
        dest.write_all(body)
            .map_err(|_| OciError::new(OciErrorCode::Internal, "write"))
    }
}

/// 最小の 1 層イメージ（`bin/sh` だけ）を `cache_dir` へ pull して image ID（`sha256:<config hex>`）を返す。
/// 設定はバイナリの本番値と同じ既定（`PullConfig::new`。`Keep` + `Strip`）。展開記録の照合が一致するため、
/// 偽のクライアントで作ったキャッシュを本番バイナリの CreateContainer が再展開できる。
fn pull_fixture_image(cache_dir: &Path) -> String {
    let mut layer = Vec::new();
    layer.extend(tar_entry("bin/", 0o755, b"", true));
    layer.extend(tar_entry("bin/sh", 0o755, b"#!fixture", false));
    layer.extend_from_slice(&[0u8; 1024]);
    let layer_digest = Digest::sha256_of(&layer);
    let arch = Platform::host().expect("host platform");
    let config = format!(
        r#"{{"architecture":"{}","os":"linux","config":{{"Cmd":["/bin/sh"]}},"rootfs":{{"type":"layers","diff_ids":["{}"]}}}}"#,
        arch.architecture(),
        layer_digest.as_str()
    )
    .into_bytes();
    let config_digest = Digest::sha256_of(&config);
    let manifest_json = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{}","size":{}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{}","size":{}}}]}}"#,
        config_digest.as_str(),
        config.len(),
        layer_digest.as_str(),
        layer.len()
    );
    let manifest = match parse_manifest(
        manifest_json.as_bytes(),
        Some("application/vnd.oci.image.manifest.v1+json"),
    )
    .expect("manifest")
    {
        ParsedManifest::Image(m) => m,
        _ => panic!("image manifest expected"),
    };
    let hex = |d: &Digest| d.as_str().trim_start_matches("sha256:").to_owned();
    let blobs = HashMap::from([(hex(&config_digest), config), (hex(&layer_digest), layer)]);
    let pull = PullConfig::new(cache_dir).expect("pull config");
    let pulled = OciImagePuller::new(FakeClient { manifest, blobs }, pull)
        .pull(&PullRequest {
            reference: "busybox:1.36".to_owned(),
            credentials: None,
        })
        .expect("pull fixture image");
    assert_eq!(pulled.id, config_digest.as_str());
    pulled.id
}

fn image_spec(image: &str) -> cri::ImageSpec {
    cri::ImageSpec {
        image: image.into(),
        ..Default::default()
    }
}

async fn pull_image(
    c: &mut ImageServiceClient<Channel>,
    image: &str,
    deadline: Duration,
) -> Result<String, PluginError> {
    call_with_deadline(
        c.pull_image(cri::PullImageRequest {
            image: Some(image_spec(image)),
            auth: None,
            sandbox_config: None,
        }),
        deadline,
    )
    .await
    .map(|r| r.into_inner().image_ref)
}

/// 段 A（PLUG-1・CRI-2・CRI-3・CRI-7）: 同じ UDS で ImageService がサーブされ、Container 系 RPC が実バイナリへ届いて
/// 本番バックエンドの応答が境界を越えて返る。タグが未知の作成は `NOT_FOUND` で半端な記録を残さず、image ID の作成は成功する。
#[tokio::test]
async fn container_rpcs_reach_the_plugin_binary() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new("sock");
        let xdg = TempDir::new("xdg");
        let sock = dir.0.join("s.sock");
        let mut guard = spawn_server(&sock, &xdg.0);
        let ch = connect_when_ready(&sock, Some(&mut guard)).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        let mut images = ImageServiceClient::new(ch.clone());

        // ImageService が同じ UDS でサーブされている（RuntimeService と同じ listener・peer 認証）。
        let listed = call_with_deadline(
            images.list_images(cri::ListImagesRequest { filter: None }),
            RPC_DEADLINE,
        )
        .await
        .expect("list images")
        .into_inner();
        assert_eq!(listed.images.len(), 0);
        let status = call_with_deadline(
            images.image_status(cri::ImageStatusRequest {
                image: Some(image_spec("busybox:1.36")),
                verbose: false,
            }),
            RPC_DEADLINE,
        )
        .await
        .expect("image status")
        .into_inner();
        assert!(status.image.is_none());
        // PullImage は puller が配線されている（未配線なら UNIMPLEMENTED）。参照の検証はレジストリへ出る前に済む。
        let err = pull_image(&mut images, "", RPC_DEADLINE)
            .await
            .expect_err("empty reference");
        assert_eq!(err.code(), PluginErrorCode::InvalidArgument);

        let sb = run_sandbox(&mut c, "pod-a").await;

        // 在庫に無いタグは NOT_FOUND で、半端な記録は残さない。
        let err = create_container(&mut c, &sb, "c", "busybox:1.36")
            .await
            .expect_err("unknown tag");
        assert_eq!(err.code(), PluginErrorCode::NotFound);
        assert_eq!(err.message(), "image reference is not found");
        assert_eq!(list_containers_len(&mut c).await, 0);

        // バイナリが起動時に作った状態ルートのキャッシュ置き場へ pull 済みイメージを用意する。image ID の作成は在庫に
        // 依らず、検証済みキャッシュから再展開されて成功する。
        let cache = xdg.0.join("fandhe-container/.cri/images");
        assert!(cache.is_dir(), "binary must have prepared the image cache");
        let image_id = pull_fixture_image(&cache);
        let id = create_container(&mut c, &sb, "c", &image_id)
            .await
            .expect("create by image id");
        assert_eq!(id.len(), 64);
        let st = container_status(&mut c, &id).await.expect("status");
        assert_eq!(st.state, cri::ContainerState::ContainerCreated as i32);
        // 在庫に無い image ID の指定なので digest 参照は無く、image_ref も image ID（#2831・CRI-2・OCI-1）。
        assert_eq!(st.image_id, image_id);
        assert_eq!(st.image_ref, image_id);
        assert_eq!(list_containers_len(&mut c).await, 1);
        remove_container(&mut c, &id).await.expect("remove");
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
        drop((c, images, ch));
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
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
        let (container_id, sandbox_id, config) = (req.container_id, req.sandbox_id, req.config);
        let name = config.metadata.as_ref().map_or("", |m| m.name.as_str());
        self.0
            .lock()
            .unwrap()
            .push(format!("prepare {container_id} {sandbox_id} {name}"));
        Ok(PreparedBundle::new(
            PathBuf::from("/bundles").join(container_id),
        ))
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

        let id = create_container(&mut c, &sb, "c", "busybox:1.36")
            .await
            .expect("create");
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

/// 環境を引き継いで `bin` の本番バイナリを spawn する（段 C 用。`XDG_RUNTIME_DIR`・`DBUS_SESSION_BUS_ADDRESS` 等を
/// systemd --user の委譲 scope・user manager の private ソケットへ届けるため `env_clear` しない）。
fn spawn_server_inherit_env(bin: &Path, sock: &Path) -> ChildGuard {
    let child = Command::new(bin)
        .arg("--socket")
        .arg(sock)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn plugin binary");
    ChildGuard(child)
}

/// 段 C（実機前提・`#[ignore]`。PLUG-1・CRI-1・CRI-2・CRI-3・#2592）: 本番バイナリ越しに、`PullImage`（実レジストリ）→
/// 正規化タグが `ImageStatus`・`ListImages` に見える → ホストの network namespace の sandbox → **タグで** CreateContainer →
/// StartContainer（`CONTAINER_RUNNING`）→ StopContainer（`CONTAINER_EXITED`）→ RemoveContainer → StopPodSandbox → RemovePodSandbox
/// の一連が成功する。
///
/// `#[ignore]` の理由（既定の集合から分ける）: (1) StartContainer は supervisor 経由の本番経路で、`systemd --user` の委譲 cgroup scope の
/// 中で動かす必要がある（Landlock ABI・user manager の private ソケット・`XDG_RUNTIME_DIR` も要る）、(2) 外向き HTTPS で実レジストリ
/// （Docker Hub）から取得する、(3) supervisor の bin を plugin の bin と同じ `target/<profile>/` に先にビルドしておく
/// （`cargo build -p fandhe-container-supervisor --bin fandhe-container-supervisor`）。試験は plugin と supervisor だけを
/// 専用ディレクトリへ複製し、隣に特権ランチャー（`fandhe-container-launcher`）が無い構成（SUP-14 の rootful 経路に入らない）で
/// 実行する。前提が欠けていれば skip せず失敗させる（`start_stop_delete_real` と同じ扱い）。
/// CI では `platform-ci`（ubuntu）が委譲スコープの中で実行する（#2818）。実機確認は人間担当（結果は #442）。実行例:
/// `systemd-run --user --scope -p Delegate=yes cargo test -p fandhe-container-plugin-cri --test container_grpc -- --ignored --exact production_binary_full_lifecycle_real`
#[tokio::test]
#[ignore = "requires systemd --user delegated scope, supervisor bin, and outbound HTTPS to a registry (CRI-1/CRI-2/CRI-3, #2592)"]
async fn production_binary_full_lifecycle_real() {
    const IMAGE: &str = "docker.io/library/busybox:1.36";
    // 取得は ImageService の pull 期限（540 秒）に収まる範囲で待つ。
    const PULL_DEADLINE: Duration = Duration::from_secs(300);
    tokio::time::timeout(Duration::from_secs(900), async {
        let dir = TempDir::new("sock-real");
        let sock = dir.0.join("s.sock");
        // plugin と supervisor だけを専用ディレクトリへ複製する。`target/<profile>/` の隣に launcher があると
        // ProductionStarter が信頼できるランチャーとみなし、file capability の無い rootful 経路に入るため（SUP-14）。
        let bin_dir = TempDir::new("bin-real");
        let plugin_src = Path::new(BIN);
        let sup_name = "fandhe-container-supervisor";
        let sup_src = plugin_src
            .parent()
            .expect("plugin binary parent")
            .join(sup_name);
        assert!(
            sup_src.is_file(),
            "supervisor binary is not built next to the plugin binary; run cargo build -p fandhe-container-supervisor --bin fandhe-container-supervisor"
        );
        let plugin_bin = bin_dir.0.join("fandhe-container-plugin-cri");
        std::fs::copy(plugin_src, &plugin_bin).expect("copy plugin binary");
        std::fs::copy(&sup_src, bin_dir.0.join(sup_name)).expect("copy supervisor binary");
        assert!(
            !bin_dir.0.join("fandhe-container-launcher").exists(),
            "a privileged launcher must not sit next to the plugin binary"
        );
        let mut guard = spawn_server_inherit_env(&plugin_bin, &sock);
        // Channel の request timeout を pull の期限（300 秒）以上にする。既定の 10 秒だと
        // call_with_deadline の長い期限より先に打ち切られる（REPAIR-5・REPAIR-12）。
        let config = GrpcClientConfig::new()
            .with_request_timeout(Duration::from_secs(600))
            .expect("request timeout");
        let ch = connect_when_ready_with(&sock, Some(&mut guard), config).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        let mut images = ImageServiceClient::new(ch.clone());

        let image_ref = pull_image(&mut images, IMAGE, PULL_DEADLINE)
            .await
            .expect("pull image");
        assert!(image_ref.starts_with("sha256:"), "image ref: {image_ref}");
        let status = call_with_deadline(
            images.image_status(cri::ImageStatusRequest {
                image: Some(image_spec(IMAGE)),
                verbose: false,
            }),
            RPC_DEADLINE,
        )
        .await
        .expect("image status")
        .into_inner();
        let record = status.image.expect("pulled image is visible by tag");
        assert!(record.repo_tags.iter().any(|t| t == IMAGE));
        let listed = call_with_deadline(
            images.list_images(cri::ListImagesRequest { filter: None }),
            RPC_DEADLINE,
        )
        .await
        .expect("list images")
        .into_inner();
        assert!(listed.images.iter().any(|i| i.id == record.id));

        // pod.json (scripts/testdata/cri/pod.json) と同じく、core の start が受けられる NODE の network namespace にする。
        let mut run = run_req("pod-real");
        run.config
            .as_mut()
            .expect("config")
            .linux
            .get_or_insert_with(Default::default)
            .security_context
            .get_or_insert_with(Default::default)
            .namespace_options = Some(cri::NamespaceOption {
            network: cri::NamespaceMode::Node as i32,
            ..Default::default()
        });
        let sb = call_with_deadline(c.run_pod_sandbox(run), RPC_DEADLINE)
            .await
            .expect("run sandbox")
            .into_inner()
            .pod_sandbox_id;

        // タグで作る（在庫から image ID へ解決される）。
        let long = Duration::from_secs(120);
        let id = call_with_deadline(
            c.create_container(cri::CreateContainerRequest {
                pod_sandbox_id: sb.clone(),
                config: Some(cri::ContainerConfig {
                    metadata: Some(cri::ContainerMetadata {
                        name: "c".into(),
                        attempt: 0,
                    }),
                    image: Some(image_spec(IMAGE)),
                    command: vec!["/bin/sleep".into(), "300".into()],
                    ..Default::default()
                }),
                sandbox_config: None,
            }),
            long,
        )
        .await
        .expect("create by tag")
        .into_inner()
        .container_id;
        call_with_deadline(
            c.start_container(cri::StartContainerRequest {
                container_id: id.clone(),
            }),
            long,
        )
        .await
        .expect("start");
        let st = container_status(&mut c, &id).await.expect("status");
        assert_eq!(st.state, cri::ContainerState::ContainerRunning as i32);
        // 解決結果の報告（#2831）: image_id は PullImage の image_ref と同じ（proto の MUST）、image_ref は digest 参照。
        assert_eq!(st.image_id, image_ref);
        let repo = IMAGE.rsplit_once(':').map_or(IMAGE, |(r, _)| r);
        assert!(
            st.image_ref.contains(&format!("{}@sha256:", repo.rsplit('/').next().unwrap_or(repo))),
            "image_ref: {}",
            st.image_ref
        );

        call_with_deadline(
            c.stop_container(cri::StopContainerRequest {
                container_id: id.clone(),
                timeout: 2,
            }),
            long,
        )
        .await
        .expect("stop");
        let st = container_status(&mut c, &id).await.expect("status");
        assert_eq!(st.state, cri::ContainerState::ContainerExited as i32);

        remove_container(&mut c, &id).await.expect("remove");
        assert_eq!(list_containers_len(&mut c).await, 0);
        stop_sandbox(&mut c, &sb).await.expect("stop sandbox");
        remove_sandbox(&mut c, &sb).await.expect("remove sandbox");
        drop((c, images, ch));
        assert!(guard.exited().is_none(), "server must still be running");
    })
    .await
    .expect("watchdog");
}
