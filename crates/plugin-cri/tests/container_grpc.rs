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
//!   成功側は段 C に置く。あわせて `Version`・`UpdateRuntimeConfig`（#2896）の応答も境界越しに具体値で照合する。
//! - 段 B: 同じ `server::serve`（実 UDS・peer UID 検証つき）にフェイクの実行層を注入した `CriRuntimeService` を載せ、
//!   PodSandbox 作成からコンテナの作成・起動・停止・削除・サンドボックスの停止・削除までの一連が `connect_uds_channel` 越しに
//!   成功することを確かめる。
//! - 段 C（`#[ignore]`・実機前提）: 本番バイナリで `PullImage`（実レジストリ）→ タグで CreateContainer → Start → Stop → Remove →
//!   サンドボックスの停止・削除まで通す。理由と前提は該当の試験の doc コメントを参照（`AGENTS.md`「実機前提テスト」）。
//! - 段 E（`#[ignore]`・実機前提。#3225）: running のコンテナを残して plugin-cri だけを SIGKILL し、同じ（本物の）状態ルートで
//!   起動し直した後の再採用（running のまま・要約行・壊れた記録）と、Stop・Remove・サンドボックスの停止・削除までを通す。
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

// 残骸・PID 再利用と衝突しない排他作成の補助（REPAIR-12・#3435）。
#[path = "../../net/tests/support/exclusive_dir.rs"]
mod exclusive_dir;

#[path = "../../core/tests/support/reap.rs"]
mod reap;

use std::collections::HashMap;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
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
/// 停止シグナルから終了までの期限（停止の全体の上限 13.7 秒 + 余裕。`shutdown::SHUTDOWN_TOTAL_BOUND`）。
const STOP_DEADLINE: Duration = Duration::from_secs(15);
/// 停止時にフェイクが返す終了コード（SIGTERM 相当。境界越しの反映確認用の具体値）。
const STOP_EXIT_CODE: i32 = 143;

/// 0700 の一時ディレクトリ（Drop で削除）。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        // 残骸・PID 再利用との衝突を避ける排他作成（既存のパスは消さず連番を進める。REPAIR-12・#3435）。
        // 別 UID（root）の `#[ignore]` の場面を持つ試験があるため、予測できる名前を消す補助は使わない。
        Self(exclusive_dir::create(&format!("fccg-{tag}")).expect("create temp dir"))
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

/// 段 C 専用の `PullImage`。`call_with_deadline`（`PluginError` へ写してメタデータを捨てる）を通さず、
/// 生の `tonic::Status` を返してレジストリの HTTP 状態（トレーラーメタデータ。#2898）を読めるようにする（#2966）。
/// 期限切れは `DEADLINE_EXCEEDED` の固定文言の `Status` へ写す。
async fn pull_image_raw(
    c: &mut ImageServiceClient<Channel>,
    image: &str,
    deadline: Duration,
) -> Result<String, tonic::Status> {
    let call = c.pull_image(cri::PullImageRequest {
        image: Some(image_spec(image)),
        auth: None,
        sandbox_config: None,
    });
    match tokio::time::timeout(deadline, call).await {
        Ok(r) => r.map(|r| r.into_inner().image_ref),
        Err(_) => Err(tonic::Status::deadline_exceeded("pull deadline exceeded")),
    }
}

/// `pull_image_raw` の失敗を、HTTP 状態の区分つきの固定の 1 行にする（#2966・CRI-3・REPAIR-4）。
/// 429 は Docker Hub の匿名 pull の rate limit と分かる専用の行にする。生の message・参照・URL は出さない
/// （`status.message()` を読まない）。
fn pull_failure_line(status: &tonic::Status) -> String {
    pull_failure_line_for("production_binary_full_lifecycle_real", status)
}

/// `pull_failure_line` の試験名つき版（#3225。再起動の実機前提試験も同じ書式の固定行を出す）。
fn pull_failure_line_for(test: &str, status: &tonic::Status) -> String {
    use fandhe_container_cri::error::registry_http_status_from_metadata;
    use fandhe_container_cri::instrument::{RegistryHttpClass, code_name};
    let class = registry_http_status_from_metadata(status.metadata())
        .and_then(RegistryHttpClass::from_http_status);
    match class {
        Some(RegistryHttpClass::RateLimited) => format!(
            "{test}: registry rate limit (HTTP 429); docker hub anonymous pull rate limit is likely exhausted"
        ),
        Some(c) => format!(
            "{test}: pull failed with code {} registry_http={}",
            code_name(status.code()),
            c.as_str()
        ),
        None => format!(
            "{test}: pull failed with code {} registry_http=none",
            code_name(status.code())
        ),
    }
}

/// 失敗行の書式の固定（#2966・CRI-3）。既定の集合で回り、実レジストリを要しない。
#[test]
fn cri3_pull_failure_line_identifies_rate_limit() {
    use fandhe_container_cri::error::REGISTRY_HTTP_STATUS_METADATA_KEY;
    use tonic::metadata::{MetadataMap, MetadataValue};
    let with = |code: tonic::Code, msg: &str, http: Option<&str>| {
        let mut md = MetadataMap::new();
        if let Some(h) = http {
            md.insert(
                REGISTRY_HTTP_STATUS_METADATA_KEY,
                h.parse::<MetadataValue<_>>().expect("ascii"),
            );
        }
        tonic::Status::with_metadata(code, msg, md)
    };
    let l429 = pull_failure_line(&with(
        tonic::Code::Unavailable,
        "registry rate limit exceeded",
        Some("429"),
    ));
    assert_eq!(
        l429,
        "production_binary_full_lifecycle_real: registry rate limit (HTTP 429); docker hub anonymous pull rate limit is likely exhausted"
    );
    assert!(l429.contains("429") && l429.contains("rate limit"));
    let l503 = pull_failure_line(&with(
        tonic::Code::Unavailable,
        "registry is unavailable",
        Some("503"),
    ));
    assert_eq!(
        l503,
        "production_binary_full_lifecycle_real: pull failed with code UNAVAILABLE registry_http=server_error"
    );
    assert!(!l503.contains("429") && !l503.contains("rate limit"));
    assert_eq!(
        pull_failure_line(&with(
            tonic::Code::Unavailable,
            "registry is unavailable",
            None
        )),
        "production_binary_full_lifecycle_real: pull failed with code UNAVAILABLE registry_http=none"
    );
    assert_eq!(
        pull_failure_line(&with(tonic::Code::PermissionDenied, "x", Some("401"))),
        "production_binary_full_lifecycle_real: pull failed with code PERMISSION_DENIED registry_http=unauthorized"
    );
}

/// `Status` を UDS＋gRPC 越しに呼び、実行層ありで pod network 無しの構成の応答を具体値で照合する
/// （`RuntimeReady`=true・`NetworkReady`=false〔`NetworkPluginNotReady`〕・既定ハンドラ 1 件・features・空の `info`）。
/// 本番は core の network namespace の join が未実装で `with_pod_network` を差さないため、段 A も同じ値になる
/// （CRI-1・CRI-2・#2830・`docs/design/cri-status-rpc.md`）。
async fn assert_status_runtime_ready_network_not_ready(c: &mut Client, verbose: bool) {
    let resp = call_with_deadline(c.status(cri::StatusRequest { verbose }), RPC_DEADLINE)
        .await
        .expect("status")
        .into_inner();
    let cond = |t: &str, status: bool, reason: &str, message: &str| cri::RuntimeCondition {
        r#type: t.into(),
        status,
        reason: reason.into(),
        message: message.into(),
    };
    assert_eq!(
        resp.status.expect("runtime status").conditions,
        vec![
            cond("RuntimeReady", true, "", ""),
            cond(
                "NetworkReady",
                false,
                "NetworkPluginNotReady",
                "pod network provider is not configured"
            ),
        ]
    );
    assert_eq!(
        resp.runtime_handlers,
        vec![cri::RuntimeHandler {
            name: String::new(),
            features: Some(cri::RuntimeHandlerFeatures {
                recursive_read_only_mounts: false,
                user_namespaces: false,
            }),
        }]
    );
    assert_eq!(
        resp.features,
        Some(cri::RuntimeFeatures {
            supplemental_groups_policy: true,
            user_namespaces_host_network: false,
            mount_options: false,
        })
    );
    assert!(resp.info.is_empty());
}

/// `Version` と `UpdateRuntimeConfig` を UDS＋gRPC 越しに呼び、具体値で照合する（CRI-1・CRI-2・#2896・
/// `docs/design/cri-status-rpc.md`）。kubelet は `version == "0.1.0"` でなければ起動しない。
async fn assert_version_and_update_runtime_config(c: &mut Client) {
    let v = call_with_deadline(
        c.version(cri::VersionRequest {
            version: "0.1.0".into(),
        }),
        RPC_DEADLINE,
    )
    .await
    .expect("version")
    .into_inner();
    assert_eq!(v.version, "0.1.0");
    assert_eq!(v.runtime_name, "fandhe-container");
    assert!(!v.runtime_version.is_empty());
    assert_eq!(v.runtime_api_version, "v1");

    let update = |cidr: &str| cri::UpdateRuntimeConfigRequest {
        runtime_config: Some(cri::RuntimeConfig {
            network_config: Some(cri::NetworkConfig {
                pod_cidr: cidr.into(),
            }),
        }),
    };
    call_with_deadline(
        c.update_runtime_config(update("10.244.0.0/24,fd00:10:244::/64")),
        RPC_DEADLINE,
    )
    .await
    .expect("update runtime config");
    let err = call_with_deadline(c.update_runtime_config(update("10.0.0.0/33")), RPC_DEADLINE)
        .await
        .expect_err("invalid pod_cidr");
    assert_eq!(err.code(), PluginErrorCode::InvalidArgument);
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

        assert_status_runtime_ready_network_not_ready(&mut c, false).await;
        assert_status_runtime_ready_network_not_ready(&mut c, true).await;
        assert_version_and_update_runtime_config(&mut c).await;

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
    /// `start` の遅延（ミリ秒。0 = なし）。実行中の RPC を作って停止の契約を試す段 E 用（#3226）。
    start_delay_ms: std::sync::atomic::AtomicU64,
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
        let delay = self.0.start_delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }
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

        assert_status_runtime_ready_network_not_ready(&mut c, false).await;

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

/// plugin と supervisor だけを 0700 の専用ディレクトリへ複製して返す（段 C / 段 E 共通。SUP-14）。
/// `target/<profile>/` の隣に launcher があると ProductionStarter が信頼できるランチャーとみなし、
/// file capability の無い rootful 経路に入るため、launcher を置かないことも assert する。
fn production_bin_dir(tag: &str) -> (TempDir, PathBuf) {
    let bin_dir = TempDir::new(tag);
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
    (bin_dir, plugin_bin)
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
/// pull の失敗時はレジストリの HTTP 状態を `production_binary_full_lifecycle_real:` で始まる固定行で出す（429 は rate limit と識別。#2966）。
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
        let (bin_dir, plugin_bin) = production_bin_dir("bin-real");
        let _keep_bin_dir = &bin_dir;
        let mut guard = spawn_server_inherit_env(&plugin_bin, &sock);
        // Channel の request timeout を pull の期限（300 秒）以上にする。既定の 10 秒だと
        // call_with_deadline の長い期限より先に打ち切られる（REPAIR-5・REPAIR-12）。
        let config = GrpcClientConfig::new()
            .with_request_timeout(Duration::from_secs(600))
            .expect("request timeout");
        let ch = connect_when_ready_with(&sock, Some(&mut guard), config).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        let mut images = ImageServiceClient::new(ch.clone());

        // 失敗時はレジストリの HTTP 状態を固定行で出す（429 は rate limit と分かる。#2966）。成否の判定は変えない。
        let image_ref = match pull_image_raw(&mut images, IMAGE, PULL_DEADLINE).await {
            Ok(r) => r,
            Err(st) => {
                let line = pull_failure_line(&st);
                eprintln!("{line}");
                panic!("pull image: {line}");
            }
        };
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
            st.image_ref.contains(&format!(
                "{}@sha256:",
                repo.rsplit('/').next().unwrap_or(repo)
            )),
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
// ---- 段 D: 同じ状態ルートで 2 回起動する再起動（R9 #2938。CRI-1・CRI-2・CORE-1・REPAIR-4・REPAIR-5）----

/// 子を kill して回収し、そこまでの stderr 全体を返す（読み手は別スレッドで期限つき。pipe を詰まらせない）。
fn kill_and_collect_stderr(mut guard: ChildGuard) -> String {
    let stderr = guard.0.stderr.take();
    let _ = guard.0.kill();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut out = String::new();
        if let Some(mut s) = stderr {
            use std::io::Read as _;
            let _ = s.read_to_string(&mut out);
        }
        let _ = tx.send(out);
    });
    // `guard` の Drop が期限つきで回収する。
    rx.recv_timeout(REAP_GRACE).unwrap_or_default()
}

/// 停止シグナルを送って正常停止を待ち、終了コード 0 を確かめて stderr 全体を返す（全体の期限つき。#3226・REPAIR-5）。
async fn terminate_and_collect_stderr(mut guard: ChildGuard, signal: &str) -> String {
    let pid = guard.0.id().to_string();
    let mut kill = Command::new("kill");
    kill.args(["-s", signal, &pid]);
    let sent = reap::run_within(&mut kill, reap::REAP_WITHIN)
        .unwrap_or_else(|e| panic!("send SIG{signal} to plugin {pid}: {e}"));
    assert!(sent.success(), "kill -s {signal} {pid}");
    let start = Instant::now();
    let status = loop {
        if let Some(s) = guard.exited() {
            break s;
        }
        assert!(
            start.elapsed() < STOP_DEADLINE,
            "plugin must stop within {STOP_DEADLINE:?} after SIG{signal}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let mut err = String::new();
    if let Some(mut s) = guard.0.stderr.take() {
        use std::io::Read as _;
        let _ = s.read_to_string(&mut err);
    }
    assert_eq!(status.code(), Some(0), "graceful stop exit code: {err}");
    assert!(!err.contains("error:"), "{err}");
    err
}

/// 状態ルート配下の記録の置き場（`<XDG>/fandhe-container/.cri/records/<kind>`）。
fn records_dir(xdg: &Path, kind: &str) -> PathBuf {
    xdg.join("fandhe-container/.cri/records").join(kind)
}

/// 0600 の記録ファイルを置く（中身は固定のゴミ。復号に失敗する）。
fn write_garbage_record(dir: &Path, name_hex: &str) {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join(format!("{name_hex}.rec")))
        .expect("create garbage record");
    f.write_all(b"garbage").expect("write garbage record");
}

/// 段 D（CRI-1・CRI-2・CORE-1・REPAIR-4）: 1 回目の起動で作った sandbox とコンテナが、SIGKILL 後の同じ状態ルートでの
/// 2 回目の起動で見える。sandbox は `SANDBOX_NOTREADY`、コンテナは core の状態どおり（Created）。壊れた記録は起動を止めず
/// 件数に出て、記録の無い孤児 bundle は回収される。root 不要・ネットワーク不要。
#[tokio::test]
async fn cri1_cri2_core1_records_survive_plugin_restart() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new("sock-rs");
        let xdg = TempDir::new("xdg-rs");
        let sock_a = dir.0.join("a.sock");
        let sock_b = dir.0.join("b.sock");
        let state_root = xdg.0.join("fandhe-container");

        // 1 回目: sandbox とコンテナを作り、記録が書かれたことを確かめて SIGKILL する。
        let mut guard = spawn_server(&sock_a, &xdg.0);
        let ch = connect_when_ready(&sock_a, Some(&mut guard)).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        let sb = run_sandbox(&mut c, "pod-restart").await;
        let image_id = pull_fixture_image(&state_root.join(".cri/images"));
        let cid = create_container(&mut c, &sb, "c-restart", &image_id)
            .await
            .expect("create by image id");
        let before = container_status(&mut c, &cid).await.expect("status");
        assert_eq!(before.state, cri::ContainerState::ContainerCreated as i32);
        assert!(records_dir(&xdg.0, "sandboxes").join(format!("{sb}.rec")).is_file());
        assert!(records_dir(&xdg.0, "containers").join(format!("{cid}.rec")).is_file());
        drop((c, ch));
        let first_stderr = kill_and_collect_stderr(guard);
        // 初回起動は何も再採用しないので要約行は出ない（静かな起動）。
        assert!(
            !first_stderr.contains("cri record readoption"),
            "first start must be quiet: {first_stderr}"
        );

        // 故障の注入（root 不要）: 壊れたコンテナ記録 1 件と、記録の無い孤児 bundle 1 件。
        let garbage = format!("{:064x}", 0xdead_u32);
        write_garbage_record(&records_dir(&xdg.0, "containers"), &garbage);
        let orphan = format!("{:064x}", 0xbeef_u32);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(state_root.join(".cri/bundles").join(&orphan))
            .expect("orphan bundle dir");

        // 2 回目: 同じ状態ルート・別 socket。
        let mut guard = spawn_server(&sock_b, &xdg.0);
        let ch = connect_when_ready(&sock_b, Some(&mut guard)).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        assert_eq!(
            sandbox_state(&mut c, &sb).await.expect("sandbox status"),
            cri::PodSandboxState::SandboxNotready as i32
        );
        assert_eq!(list_containers_len(&mut c).await, 1);
        let after = container_status(&mut c, &cid).await.expect("status");
        assert_eq!(after.state, cri::ContainerState::ContainerCreated as i32);
        assert_eq!(after.image_id, before.image_id);
        assert_eq!(after.image_ref, before.image_ref);
        assert_eq!(
            after.metadata.as_ref().map(|m| m.name.as_str()),
            Some("c-restart")
        );
        // 親 sandbox が NotReady なので start は拒否される。
        let err = start_container(&mut c, &cid).await.expect_err("start");
        assert_eq!(err.code(), PluginErrorCode::FailedPrecondition);
        // 孤児 bundle は回収済み。再採用したコンテナの bundle は残る。
        assert!(!state_root.join(".cri/bundles").join(&orphan).exists());
        assert!(state_root.join(".cri/bundles").join(&cid).is_dir());

        // 後片付け: 所有が復元されているので Remove が通り、記録が消える。壊れた記録は消さない。
        remove_container(&mut c, &cid).await.expect("remove container");
        assert_eq!(list_containers_len(&mut c).await, 0);
        stop_sandbox(&mut c, &sb).await.expect("stop sandbox");
        remove_sandbox(&mut c, &sb).await.expect("remove sandbox");
        assert!(!state_root.join(".cri/bundles").join(&cid).exists());
        assert!(!records_dir(&xdg.0, "containers").join(format!("{cid}.rec")).exists());
        assert!(!records_dir(&xdg.0, "sandboxes").join(format!("{sb}.rec")).exists());
        assert!(records_dir(&xdg.0, "containers").join(format!("{garbage}.rec")).is_file());
        drop((c, ch));
        // 2 回目の停止は SIGTERM（正常停止。#3226）。1 回目の SIGKILL（クラッシュ経路）は残す。
        let second_stderr = terminate_and_collect_stderr(guard, "TERM").await;
        assert!(
            second_stderr.contains("cri plugin shutdown: signal=SIGTERM stage=serve"),
            "{second_stderr}"
        );
        assert!(!sock_b.exists(), "socket must be removed by the graceful stop");
        for want in [
            "cri record readoption: kind=sandbox adopted=1 pending_unresolved=0 broken=0 ",
            "cri record readoption: kind=container adopted=1 present=1 absent_exited=0 remove_pending=0 undetermined=0 stale_create=0 broken=1 malformed=1 ",
            "cri stale create release: released=0 kept=0 release_failed=0 record_remove_failed=0 not_attempted=0 skipped=0",
            "cri orphan bundle reclamation: scan=completed scanned=2 reclaimed=1 kept_has_record=1 ",
        ] {
            assert!(second_stderr.contains(want), "missing {want:?} in: {second_stderr}");
        }
        assert!(!second_stderr.contains(&sb) && !second_stderr.contains(&cid));

        // 3 回目: 壊れた記録だけが残っていても起動は止まらず、件数だけが出る。正常停止の後なので同じ socket のパスで再 bind できる。
        let mut guard = spawn_server(&sock_b, &xdg.0);
        let ch = connect_when_ready(&sock_b, Some(&mut guard)).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        assert_eq!(list_containers_len(&mut c).await, 0);
        drop((c, ch));
        let third_stderr = kill_and_collect_stderr(guard);
        assert!(
            third_stderr.contains(
                "cri record readoption: kind=container adopted=0 present=0 absent_exited=0 remove_pending=0 undetermined=0 stale_create=0 broken=1 malformed=1 "
            ),
            "{third_stderr}"
        );
    })
    .await
    .expect("watchdog");
}

/// 段 D（CRI-2・REPAIR-5）: 記録の件数が上限を超えていたら、起動を止める（fail-closed。socket も作らない）。
#[tokio::test]
async fn cri2_record_limit_exceeded_stops_startup() {
    tokio::time::timeout(WATCHDOG, async {
        let dir = TempDir::new("sock-lim");
        let xdg = TempDir::new("xdg-lim");
        let sock_a = dir.0.join("a.sock");
        let sock_b = dir.0.join("b.sock");

        // 1 回目で置き場を正規の権限で作らせてから止める。
        let mut guard = spawn_server(&sock_a, &xdg.0);
        let ch = connect_when_ready(&sock_a, Some(&mut guard)).await;
        drop(ch);
        let _ = kill_and_collect_stderr(guard);

        // sandbox の件数の上限（1024）を 1 件超える壊れた記録。
        let sandboxes = records_dir(&xdg.0, "sandboxes");
        for i in 0..=1024u32 {
            write_garbage_record(&sandboxes, &format!("{i:064x}"));
        }

        let mut guard = spawn_server(&sock_b, &xdg.0);
        let start = Instant::now();
        let status = loop {
            if let Some(s) = guard.exited() {
                break s;
            }
            assert!(start.elapsed() < Duration::from_secs(30), "must exit");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(status.code(), Some(1));
        assert!(!sock_b.exists());
        let mut err = String::new();
        if let Some(mut s) = guard.0.stderr.take() {
            use std::io::Read as _;
            let _ = s.read_to_string(&mut err);
        }
        assert!(
            err.contains("error: FAILED_PRECONDITION: failed to readopt cri records"),
            "{err}"
        );
    })
    .await
    .expect("watchdog");
}

// ---- 段 E: SIGTERM / SIGINT による正常停止（#3226。CRI-1・CORE-1・PLUG-12・REPAIR-4・REPAIR-5）----

/// フラグが立つまで待つ shutdown future（`tokio::sync` は承認範囲外のためポーリング）。
async fn wait_flag(flag: Arc<std::sync::atomic::AtomicBool>) {
    while !flag.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// 段 E の共通の準備で組み立てたサーバーと周辺の束。
struct SlowStartServer {
    serve: tokio::task::JoinHandle<Result<(), PluginError>>,
    flag: Arc<std::sync::atomic::AtomicBool>,
    client: Client,
    container_id: String,
    runtime: Arc<FakeRuntime>,
    sock: PathBuf,
    _dir: TempDir,
}

/// 遅い `start` を持つフェイクを載せたサーバーを起動し、Created のコンテナまで作る。
async fn start_slow_start_server(grace: Duration) -> SlowStartServer {
    let runtime = Arc::new(FakeRuntime::default());
    let bundles = Arc::new(RecordingBundles::default());
    let service = CriRuntimeService::new().with_runtime(
        RuntimeAdapter::new(Arc::new(SharedRuntime(Arc::clone(&runtime)))),
        bundles,
    );
    let dir = TempDir::new("sock-e");
    let sock = dir.0.join("s.sock");
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let config = GrpcServerConfig::new()
        .with_shutdown_grace(grace)
        .expect("shutdown grace");
    let serve_sock = sock.clone();
    let serve_flag = Arc::clone(&flag);
    let serve = tokio::spawn(async move {
        server::serve(&serve_sock, service, &config, wait_flag(serve_flag)).await
    });
    let ch = connect_when_ready(&sock, None).await;
    let mut client = RuntimeServiceClient::new(ch);
    let sb = run_sandbox(&mut client, "pod-e").await;
    let container_id = create_container(&mut client, &sb, "c", "busybox:1.36")
        .await
        .expect("create");
    SlowStartServer {
        serve,
        flag,
        client,
        container_id,
        runtime,
        sock,
        _dir: dir,
    }
}

/// 実行層に `start` が届くまで待つ（期限つき）。
async fn wait_start_reached(runtime: &FakeRuntime) {
    let t0 = Instant::now();
    while !runtime
        .mutating_calls()
        .iter()
        .any(|l| l.starts_with("start "))
    {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "start must reach the runtime"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// 段 E-1（CRI-1・REPAIR-5）: 実行中の RPC がある間に shutdown が完了すると、新しい接続は受け付けられず（socket が消える）、
/// 実行中の RPC は成功で返り、サーバーは猶予内に `Ok` で終わる。
#[tokio::test]
async fn cri1_shutdown_stops_accepting_and_waits_for_inflight_rpc() {
    tokio::time::timeout(WATCHDOG, async {
        let s = start_slow_start_server(Duration::from_secs(2)).await;
        s.runtime.start_delay_ms.store(500, Ordering::SeqCst);
        let mut c_inflight = s.client.clone();
        let inflight_id = s.container_id.clone();
        let inflight =
            tokio::spawn(async move { start_container(&mut c_inflight, &inflight_id).await });
        wait_start_reached(&s.runtime).await;
        s.flag.store(true, Ordering::SeqCst);

        // (i) 受付の停止: socket が 1 秒以内に消え、新しい接続は失敗する。
        let t1 = Instant::now();
        while s.sock.exists() {
            assert!(
                t1.elapsed() < Duration::from_secs(1),
                "socket must be removed promptly"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            connect_uds_channel(
                &s.sock,
                &GrpcClientConfig::new(),
                Box::new(JsonLinesPeerAuthObserver::new())
            )
            .await
            .is_err(),
            "new connections must be refused after shutdown"
        );
        // (ii) 実行中の RPC は成功で返る。
        inflight
            .await
            .expect("join")
            .expect("in-flight start succeeds");
        // (iii) 猶予内に Ok で終わる。
        let r = tokio::time::timeout(Duration::from_secs(5), s.serve)
            .await
            .expect("serve must finish")
            .expect("join");
        assert!(r.is_ok(), "{:?}", r.err().map(|e| e.code()));
    })
    .await
    .expect("watchdog");
}

/// 段 E-2（REPAIR-5）: 実行中の RPC が猶予より長引くと、接続を強制的に閉じて `TIMEOUT` で返る（上限内）。socket は消えている。
#[tokio::test]
async fn repair5_shutdown_grace_expiry_force_closes_and_times_out() {
    tokio::time::timeout(WATCHDOG, async {
        let s = start_slow_start_server(Duration::from_secs(1)).await;
        s.runtime.start_delay_ms.store(5_000, Ordering::SeqCst);
        let mut c_inflight = s.client.clone();
        let inflight_id = s.container_id.clone();
        let inflight = tokio::spawn(async move {
            let _ = start_container(&mut c_inflight, &inflight_id).await;
        });
        wait_start_reached(&s.runtime).await;
        let stop_at = Instant::now();
        s.flag.store(true, Ordering::SeqCst);
        let r = tokio::time::timeout(Duration::from_secs(5), s.serve)
            .await
            .expect("serve must finish within grace + reclaim")
            .expect("join");
        let e = r.expect_err("grace expiry must be an error");
        assert_eq!(e.code(), PluginErrorCode::Timeout);
        assert!(
            stop_at.elapsed() < Duration::from_secs(4),
            "{:?}",
            stop_at.elapsed()
        );
        assert!(!s.sock.exists(), "socket must be removed");
        let _ = inflight.await;
    })
    .await
    .expect("watchdog");
}

/// 本番バイナリで停止シグナルを送り、終了コード 0・固定行・socket の削除・ロックの解放・同じパスでの再 bind を確かめる。
async fn assert_binary_graceful_stop(signal: &str, signal_name: &str) {
    let dir = TempDir::new("sock-e3");
    let xdg = TempDir::new("xdg-e3");
    let sock = dir.0.join("s.sock");
    let state_root = xdg.0.join("fandhe-container");
    let mut guard = spawn_server(&sock, &xdg.0);
    let ch = connect_when_ready(&sock, Some(&mut guard)).await;
    drop(ch);
    let err = terminate_and_collect_stderr(guard, signal).await;
    assert!(
        err.contains(&format!(
            "cri plugin shutdown: signal={signal_name} stage=serve"
        )),
        "{err}"
    );
    assert!(!sock.exists(), "socket must be removed");
    // ロックファイルは消さず（二重取得を防ぐ契約）、ロック自体は解放されている。
    assert!(state_root.join(".cri/@instance.lock").is_file());
    let lock = fandhe_container_plugin_cri::instance_lock::acquire_instance_lock_in(
        &state_root,
        Duration::ZERO,
    )
    .expect("instance lock must be released");
    drop(lock);
    // 同じ socket のパスで再起動して、すぐ接続できる。
    let mut guard = spawn_server(&sock, &xdg.0);
    let ch = connect_when_ready(&sock, Some(&mut guard)).await;
    drop(ch);
    let _ = terminate_and_collect_stderr(guard, signal).await;
}

/// 段 E-3（CRI-1・PLUG-12・CORE-1・REPAIR-4）: SIGTERM で正常停止する。
#[tokio::test]
async fn cri1_sigterm_stops_the_binary_gracefully() {
    tokio::time::timeout(WATCHDOG, assert_binary_graceful_stop("TERM", "SIGTERM"))
        .await
        .expect("watchdog");
}

/// 段 E-4（CRI-1）: SIGINT も SIGTERM と同じ扱いで正常停止する。
#[tokio::test]
async fn cri1_sigint_stops_the_binary_gracefully() {
    tokio::time::timeout(WATCHDOG, assert_binary_graceful_stop("INT", "SIGINT"))
        .await
        .expect("watchdog");
}

// ---- 段 E（実機前提）: running のコンテナを残した plugin-cri の再起動（#3225。CRI-1・CRI-2・CORE-1）----

/// 自分が作ったファイルだけを Drop で消すガード（壊れた記録の後始末。plugin は壊れた記録を消さない仕様のため）。
struct OwnedFile(PathBuf);

impl Drop for OwnedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// ディレクトリ内の指定拡張子のエントリ数（ディレクトリが無ければ 0）。
fn count_entries(dir: &Path, ext: Option<&str>) -> usize {
    match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .filter(|e| match ext {
                Some(x) => e.path().extension().is_some_and(|y| y == x),
                None => true,
            })
            .count(),
        Err(_) => 0,
    }
}

/// `ListContainers` の素の結果（フィルタなし）。
async fn list_containers(c: &mut Client) -> Vec<cri::Container> {
    call_with_deadline(
        c.list_containers(cri::ListContainersRequest { filter: None }),
        RPC_DEADLINE,
    )
    .await
    .expect("list containers")
    .into_inner()
    .containers
}

/// 再起動をまたいで同一であるべき `ContainerStatus` の部分（走り直していないことの証拠）。
fn identity_of(st: &cri::ContainerStatus) -> (String, i64, i64, String, String, Option<String>) {
    (
        st.id.clone(),
        st.created_at,
        st.started_at,
        st.image_id.clone(),
        st.image_ref.clone(),
        st.metadata.as_ref().map(|m| m.name.clone()),
    )
}

const RESTART_TEST: &str = "production_binary_restart_readopts_running_container_real";

/// 段 E（実機前提・`#[ignore]`。CRI-1・CRI-2・CORE-1・SUP-5・REPAIR-4・REPAIR-12・#3225・#2942）: running のコンテナ
/// （本番の supervisor・委譲 cgroup つき）と sandbox を残したまま plugin-cri だけを SIGKILL し、同じ状態ルートで起動し直した
/// 新しいプロセスが記録を再採用すること（sandbox は NOTREADY、コンテナは core の状態どおり running で同一の実体）、
/// 壊れた記録 1 件があっても起動が止まらず固定語彙の要約行に件数が出ること、自分で spawn していない supervisor を通して
/// Stop・Remove・StopPodSandbox・RemovePodSandbox が通ることを具体値で固定する。
///
/// `#[ignore]` の理由: `production_binary_full_lifecycle_real` と同じ（委譲 cgroup scope・supervisor の bin・外向き HTTPS）。
/// 加えて、supervisor の起動が本物の `XDG_RUNTIME_DIR/systemd/private` を要するため `XDG_RUNTIME_DIR` を一時ディレクトリへ
/// 向けられず、本物の状態ルート（`$XDG_RUNTIME_DIR/fandhe-container`）を共有する。そのため前提検査として記録と bundle が
/// 空であることを確かめ、満たさなければ何も消さずに失敗する（fail-closed）。試験が消すのは自分で作った壊れた記録 1 件だけ。
/// 同じバイナリの `#[ignore]` 試験とはインスタンスロックのため直列（`--test-threads=1`）で実行する。
/// sandbox は NODE の network namespace（core の start が pod の netns への join をまだ受けないための試験専用の設定）。
/// 失敗で running のコンテナが残った場合は `docs/setup/cri-record-recovery.md` で手動回収する。
/// 実行例（Agent は手元で実行しない。`AGENTS.md`「実機前提テスト」）:
/// `systemd-run --user --scope -p Delegate=yes cargo test -p fandhe-container-plugin-cri --test container_grpc -- --ignored --exact production_binary_restart_readopts_running_container_real`
#[tokio::test]
#[ignore = "requires systemd --user delegated scope, supervisor bin, real XDG_RUNTIME_DIR state root, and outbound HTTPS to a registry (CRI-1/CRI-2/CORE-1, #3225)"]
async fn production_binary_restart_readopts_running_container_real() {
    const IMAGE: &str = "docker.io/library/busybox:1.36";
    const PULL_DEADLINE: Duration = Duration::from_secs(300);
    tokio::time::timeout(Duration::from_secs(600), async {
        let xdg = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").expect("XDG_RUNTIME_DIR"));
        assert!(xdg.is_absolute(), "XDG_RUNTIME_DIR must be absolute");
        let state_root = xdg.join("fandhe-container");

        // 前提検査（何も消さない）。
        let dirty = count_entries(&records_dir(&xdg, "sandboxes"), Some("rec"))
            + count_entries(&records_dir(&xdg, "containers"), Some("rec"))
            + count_entries(&state_root.join(".cri/bundles"), None);
        assert_eq!(
            dirty, 0,
            "{RESTART_TEST}: state root is not clean; see docs/setup/cri-record-recovery.md"
        );

        let dir = TempDir::new("sock-restart");
        let (bin_dir, plugin_bin) = production_bin_dir("bin-restart");
        let _keep_bin_dir = &bin_dir;
        let long = Duration::from_secs(120);
        let new_config = || {
            GrpcClientConfig::new()
                .with_request_timeout(Duration::from_secs(600))
                .expect("request timeout")
        };

        // 1 回目: pull → NODE sandbox → タグで create → start（running）。
        let sock_a = dir.0.join("a.sock");
        let mut guard = spawn_server_inherit_env(&plugin_bin, &sock_a);
        let ch = connect_when_ready_with(&sock_a, Some(&mut guard), new_config()).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        let mut images = ImageServiceClient::new(ch.clone());
        let image_ref = match pull_image_raw(&mut images, IMAGE, PULL_DEADLINE).await {
            Ok(r) => r,
            Err(st) => {
                let line = pull_failure_line_for(RESTART_TEST, &st);
                eprintln!("{line}");
                panic!("pull image: {line}");
            }
        };
        assert!(image_ref.starts_with("sha256:"), "image ref: {image_ref}");
        let mut run = run_req("pod-restart-real");
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
        let cid = call_with_deadline(
            c.create_container(cri::CreateContainerRequest {
                pod_sandbox_id: sb.clone(),
                config: Some(cri::ContainerConfig {
                    metadata: Some(cri::ContainerMetadata {
                        name: "c-restart-real".into(),
                        attempt: 0,
                    }),
                    image: Some(image_spec(IMAGE)),
                    command: vec!["/bin/sleep".into(), "600".into()],
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
                container_id: cid.clone(),
            }),
            long,
        )
        .await
        .expect("start");
        let before = container_status(&mut c, &cid).await.expect("status");
        assert_eq!(before.state, cri::ContainerState::ContainerRunning as i32);
        assert_eq!(before.image_id, image_ref);
        assert!(
            before.image_ref.contains("busybox@sha256:"),
            "image_ref: {}",
            before.image_ref
        );
        let ident = identity_of(&before);
        let sb_rec = records_dir(&xdg, "sandboxes").join(format!("{sb}.rec"));
        let c_rec = records_dir(&xdg, "containers").join(format!("{cid}.rec"));
        let bundle = state_root.join(".cri/bundles").join(&cid);
        let c_state_dir = state_root.join(&cid);
        assert!(sb_rec.is_file() && c_rec.is_file() && bundle.is_dir());
        let had_state_dir = c_state_dir.is_dir();
        drop((c, images, ch));
        let first_stderr = kill_and_collect_stderr(guard);
        assert!(
            !first_stderr.contains("cri record readoption"),
            "first start must be quiet: {first_stderr}"
        );

        // 2 回目: 再採用。running のまま同じ実体が見える。
        let sock_b = dir.0.join("b.sock");
        let mut guard = spawn_server_inherit_env(&plugin_bin, &sock_b);
        let ch = connect_when_ready_with(&sock_b, Some(&mut guard), new_config()).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        assert_eq!(
            sandbox_state(&mut c, &sb).await.expect("sandbox status"),
            cri::PodSandboxState::SandboxNotready as i32
        );
        let listed = list_containers(&mut c).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, cid);
        assert_eq!(listed[0].state, cri::ContainerState::ContainerRunning as i32);
        let after = container_status(&mut c, &cid).await.expect("status");
        assert_eq!(after.state, cri::ContainerState::ContainerRunning as i32);
        assert_eq!(identity_of(&after), ident);
        assert!(guard.exited().is_none(), "server must still be running");
        drop((c, ch));
        let second_stderr = kill_and_collect_stderr(guard);
        for want in [
            "cri record readoption: kind=sandbox adopted=1 pending_unresolved=0 broken=0 malformed=0 ",
            "cri record readoption: kind=container adopted=1 present=1 absent_exited=0 remove_pending=0 undetermined=0 stale_create=0 broken=0 malformed=0 ",
            "cri stale create release: released=0 kept=0 release_failed=0 record_remove_failed=0 not_attempted=0 skipped=0",
            "cri orphan bundle reclamation: scan=completed scanned=1 reclaimed=0 kept_has_record=1 ",
        ] {
            assert!(second_stderr.contains(want), "missing {want:?} in: {second_stderr}");
        }
        assert!(!second_stderr.contains(&sb) && !second_stderr.contains(&cid));

        // 壊れた記録 1 件を注入（自分のファイルだけを Drop で消す）。
        let garbage_name = format!("{:064x}", 0x3225_u32);
        write_garbage_record(&records_dir(&xdg, "containers"), &garbage_name);
        let garbage = OwnedFile(records_dir(&xdg, "containers").join(format!("{garbage_name}.rec")));

        // 3 回目: 壊れた記録があっても起動は止まらず、再採用は冪等。後始末を kubelet の順で通す。
        let sock_c = dir.0.join("c.sock");
        let mut guard = spawn_server_inherit_env(&plugin_bin, &sock_c);
        let ch = connect_when_ready_with(&sock_c, Some(&mut guard), new_config()).await;
        let mut c = RuntimeServiceClient::new(ch.clone());
        assert_eq!(
            sandbox_state(&mut c, &sb).await.expect("sandbox status"),
            cri::PodSandboxState::SandboxNotready as i32
        );
        let listed = list_containers(&mut c).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state, cri::ContainerState::ContainerRunning as i32);
        let again = container_status(&mut c, &cid).await.expect("status");
        assert_eq!(identity_of(&again), ident);

        call_with_deadline(
            c.stop_container(cri::StopContainerRequest {
                container_id: cid.clone(),
                timeout: 2,
            }),
            long,
        )
        .await
        .expect("stop");
        let st = container_status(&mut c, &cid).await.expect("status");
        assert_eq!(st.state, cri::ContainerState::ContainerExited as i32);
        assert_ne!(st.finished_at, 0);
        call_with_deadline(
            c.remove_container(cri::RemoveContainerRequest {
                container_id: cid.clone(),
            }),
            long,
        )
        .await
        .expect("remove container");
        assert_eq!(list_containers_len(&mut c).await, 0);
        assert!(!c_rec.exists() && !bundle.exists());
        if had_state_dir {
            assert!(!c_state_dir.exists(), "container state dir must be deleted");
        }
        stop_sandbox(&mut c, &sb).await.expect("stop sandbox");
        remove_sandbox(&mut c, &sb).await.expect("remove sandbox");
        assert!(!sb_rec.exists());
        assert!(garbage.0.is_file(), "broken record must be left in place");
        assert!(guard.exited().is_none(), "server must still be running");
        drop((c, ch));
        let third_stderr = kill_and_collect_stderr(guard);
        for want in [
            "cri record readoption: kind=sandbox adopted=1 pending_unresolved=0 broken=0 malformed=0 ",
            "cri record readoption: kind=container adopted=1 present=1 absent_exited=0 remove_pending=0 undetermined=0 stale_create=0 broken=1 malformed=1 ",
            "cri orphan bundle reclamation: scan=completed scanned=1 reclaimed=0 kept_has_record=1 ",
        ] {
            assert!(third_stderr.contains(want), "missing {want:?} in: {third_stderr}");
        }
        assert!(!third_stderr.contains(&sb) && !third_stderr.contains(&cid));
        drop(garbage);
        println!("{RESTART_TEST}: running container readopted after plugin restart");
    })
    .await
    .expect("watchdog");
}
