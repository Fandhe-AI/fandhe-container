//! `CreateContainer` が自 sandbox の保持役の pid から作った user＋ipc namespace のパスを bundle へ渡す配線の試験
//! （CRI-2・CORE-3・SEC-5・REPAIR-12。#2876）。
//!
//! フェイクの保持役 provider（sandbox ごとに別の pid を払い出す）と、渡された `BundleRequest::pod_namespaces` から
//! 実際に `linux.namespaces` を生成して記録するフェイクの `BundleProvider` を注入し、pod A・B のコンテナの config の
//! path が自分の保持役の pid と一致し、他方の pid と一致しないことを具体値で確かめる。本番の provider は H6（#2877）。

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, ErrorCode,
    KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{
    BundleProvider, BundleRequest, HolderIdentity, NamespaceIdentity, PodHolder, PodHolderLiveness,
    PodHolderRequest, PodNamespaceHolderProvider, PreparedBundle, RuntimeAdapter,
};
use fandhe_container_cri::bundle::{ImageDefaults, build_runtime_config_with_pod_namespaces};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use tonic::{Code, Request};

/// sandbox ごとに別の pid を払い出すフェイクの保持役。
struct PerSandboxHolder {
    next: AtomicU32,
    pids: Mutex<HashMap<String, u32>>,
    exited: Mutex<bool>,
    force_pid: Mutex<Option<u32>>,
    /// 真なら pod の pid ns の素性つきの保持役を返す（pid を共有する sandbox。#4817）。
    share_pid: Mutex<bool>,
}

impl PerSandboxHolder {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU32::new(4242),
            pids: Mutex::new(HashMap::new()),
            exited: Mutex::new(false),
            force_pid: Mutex::new(None),
            share_pid: Mutex::new(false),
        })
    }
    fn pid_of(&self, sandbox_id: &str) -> u32 {
        *self.pids.lock().unwrap().get(sandbox_id).unwrap()
    }
}

impl PodNamespaceHolderProvider for PerSandboxHolder {
    fn spawn(&self, req: &PodHolderRequest<'_>) -> Result<PodHolder, CriError> {
        let pid = match *self.force_pid.lock().unwrap() {
            Some(p) => p,
            None => self.next.fetch_add(1111, Ordering::SeqCst),
        };
        self.pids
            .lock()
            .unwrap()
            .insert(req.sandbox_id.to_owned(), pid);
        if !*self.share_pid.lock().unwrap() {
            return Ok(PodHolder::new(pid.try_into().unwrap()));
        }
        let ns = |ino| NamespaceIdentity { dev: 4, ino };
        let identity = HolderIdentity::new(pid, 1, ns(11), ns(12), ns(13), shm_id())
            .and_then(|i| i.with_pid_ns(ns(14)))
            .unwrap();
        Ok(PodHolder::from_identity(identity))
    }
    fn release(&self, _sandbox_id: &str, _timeout: Duration) -> Result<(), CriError> {
        Ok(())
    }
    fn liveness(&self, _sandbox_id: &str) -> Result<PodHolderLiveness, CriError> {
        if *self.exited.lock().unwrap() {
            Ok(PodHolderLiveness::Exited)
        } else {
            Ok(PodHolderLiveness::Alive)
        }
    }
}

/// 1 回の `prepare` の観測（sandbox ID・渡されたパス・そこから生成した config の user・ipc の path）。
#[derive(Clone, Debug)]
struct Seen {
    sandbox_id: String,
    supplied: Option<(String, String)>,
    user_path: Option<String>,
    ipc_path: Option<String>,
    /// 供給された保持役の net と、生成した config の network の path（#2878・NET-3）。
    supplied_net: Option<String>,
    net_path: Option<String>,
    /// 生成した config の pid の path（#4817）。
    pid_path: Option<String>,
}

#[derive(Default)]
struct RecordingBundles(Mutex<Vec<Seen>>);

impl RecordingBundles {
    fn seen(&self) -> Vec<Seen> {
        self.0.lock().unwrap().clone()
    }
}

fn ns_path(config: &serde_json::Value, kind: &str) -> Option<String> {
    config["linux"]["namespaces"]
        .as_array()?
        .iter()
        .find(|n| n["type"] == kind)?["path"]
        .as_str()
        .map(str::to_owned)
}

impl BundleProvider for RecordingBundles {
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
        let json = build_runtime_config_with_pod_namespaces(
            req.sandbox_config,
            req.config,
            &ImageDefaults::default(),
            req.pod_namespaces,
        )?;
        let value: serde_json::Value = serde_json::from_slice(json.as_bytes()).unwrap();
        self.0.lock().unwrap().push(Seen {
            sandbox_id: req.sandbox_id.to_owned(),
            supplied: req
                .pod_namespaces
                .map(|p| (p.user().to_owned(), p.ipc().to_owned())),
            user_path: ns_path(&value, "user"),
            ipc_path: ns_path(&value, "ipc"),
            supplied_net: req.pod_namespaces.map(|p| p.net().to_owned()),
            net_path: ns_path(&value, "network"),
            pid_path: ns_path(&value, "pid"),
        });
        // bundle のパスは絶対パスで返す（Windows はドライブ接頭辞を要する。CLI-1）。
        let root = if cfg!(windows) {
            PathBuf::from(r"C:\bundles")
        } else {
            PathBuf::from("/bundles")
        };
        Ok(PreparedBundle::new(root.join(req.container_id)))
    }
    fn release(&self, _: &str) -> Result<(), CriError> {
        Ok(())
    }
}

/// pod の `/dev/shm` の tmpfs の素性（READY の shm。dev は nsfs〔4〕と違う）。
fn shm_id() -> NamespaceIdentity {
    NamespaceIdentity { dev: 48, ino: 2 }
}

/// `start` が受けた pod_shm の `(パス, dev, ino)`。
type SeenShm = Option<(String, u64, u64)>;

#[derive(Default)]
struct StubRuntime {
    created: Mutex<HashMap<String, ()>>,
    /// `start` が受けた要求の `(コンテナ ID, pod_shm の (パス, dev, ino))`（#4823）。
    starts: Mutex<Vec<(String, SeenShm)>>,
}

impl ContainerRuntime for StubRuntime {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        self.created
            .lock()
            .unwrap()
            .insert(r.id().as_str().to_owned(), ());
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
    fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
        self.starts.lock().unwrap().push((
            r.id().as_str().to_owned(),
            r.pod_shm().map(|p| {
                let (dev, ino) = p.identity();
                (p.path().to_string_lossy().into_owned(), dev, ino)
            }),
        ));
        // 起動した結果は使わない（受けた要求だけを見る）。
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Ok(ContainerStatus::stopped(r.id().clone(), Some(0)))
    }
    fn delete(&self, r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        self.created.lock().unwrap().remove(r.id().as_str());
        Ok(DeleteResponse::new())
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        if self.created.lock().unwrap().contains_key(r.id().as_str()) {
            Ok(ContainerStatus::created(r.id().clone(), None))
        } else {
            Err(TraitError::new(ErrorCode::NotFound, "no such container"))
        }
    }
}

fn sandbox_config(name: &str) -> PodSandboxConfig {
    PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: name.into(),
            uid: format!("uid-{name}"),
            namespace: "ns".into(),
            attempt: 0,
        }),
        ..Default::default()
    }
}

async fn run(svc: &CriRuntimeService, name: &str) -> String {
    RuntimeService::run_pod_sandbox(
        svc,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(sandbox_config(name)),
            runtime_handler: String::new(),
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .pod_sandbox_id
}

async fn create(
    svc: &CriRuntimeService,
    sandbox: &str,
    name: &str,
    ann: BTreeMap<String, String>,
) -> Result<String, tonic::Status> {
    RuntimeService::create_container(
        svc,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox.into(),
            config: Some(ContainerConfig {
                metadata: Some(ContainerMetadata {
                    name: name.into(),
                    attempt: 0,
                }),
                image: Some(ImageSpec {
                    image: "busybox:1.36".into(),
                    ..Default::default()
                }),
                command: vec!["/bin/sh".into(), "-c".into(), "sleep 30".into()],
                annotations: ann.clone(),
                labels: ann,
                ..Default::default()
            }),
            sandbox_config: None,
        }),
    )
    .await
    .map(|r| r.into_inner().container_id)
}

async fn list_container_ids(svc: &CriRuntimeService) -> Vec<String> {
    RuntimeService::list_containers(svc, Request::new(v1::ListContainersRequest::default()))
        .await
        .unwrap()
        .into_inner()
        .containers
        .into_iter()
        .map(|c| c.id)
        .collect()
}

fn service(
    holder: &Arc<PerSandboxHolder>,
    bundles: &Arc<RecordingBundles>,
    with_holder: bool,
) -> CriRuntimeService {
    service_with(
        holder,
        bundles,
        with_holder,
        Arc::new(StubRuntime::default()),
    )
}

fn service_with(
    holder: &Arc<PerSandboxHolder>,
    bundles: &Arc<RecordingBundles>,
    with_holder: bool,
    runtime: Arc<StubRuntime>,
) -> CriRuntimeService {
    let svc = CriRuntimeService::new();
    let svc = if with_holder {
        svc.with_pod_holder(holder.clone())
    } else {
        svc
    };
    svc.with_runtime(RuntimeAdapter::new(runtime), bundles.clone())
        .with_runtime_timeout(Duration::from_secs(5))
}

fn paths(pid: u32) -> (String, String) {
    (
        format!("/proc/{pid}/ns/user"),
        format!("/proc/{pid}/ns/ipc"),
    )
}

#[tokio::test]
async fn sec5_pod_a_and_b_containers_join_only_their_own_holder() {
    let holder = PerSandboxHolder::new();
    let bundles = Arc::new(RecordingBundles::default());
    let svc = service(&holder, &bundles, true);
    let a = run(&svc, "a").await;
    let b = run(&svc, "b").await;
    let (pid_a, pid_b) = (holder.pid_of(&a), holder.pid_of(&b));
    assert_ne!(pid_a, pid_b, "the test needs distinct holder pids");

    // 順序に依存しないことの確認として B → A → B → A の順に作る。
    for (i, sb) in [&b, &a, &b, &a].into_iter().enumerate() {
        create(&svc, sb, &format!("c{i}"), BTreeMap::new())
            .await
            .unwrap();
    }
    let seen = bundles.seen();
    assert_eq!(seen.len(), 4);
    for s in &seen {
        let (own, other) = if s.sandbox_id == a {
            (pid_a, pid_b)
        } else {
            assert_eq!(s.sandbox_id, b);
            (pid_b, pid_a)
        };
        let (u, i) = paths(own);
        assert_eq!(s.supplied, Some((u.clone(), i.clone())));
        assert_eq!(s.user_path.as_deref(), Some(u.as_str()));
        assert_eq!(s.ipc_path.as_deref(), Some(i.as_str()));
        let (ou, oi) = paths(other);
        assert_ne!(s.user_path.as_deref(), Some(ou.as_str()));
        assert_ne!(s.ipc_path.as_deref(), Some(oi.as_str()));
    }
}

#[tokio::test]
async fn sec5_request_values_do_not_influence_namespace_paths() {
    let holder = PerSandboxHolder::new();
    let bundles = Arc::new(RecordingBundles::default());
    let svc = service(&holder, &bundles, true);
    let a = run(&svc, "a").await;
    let b = run(&svc, "b").await;
    let (pid_a, pid_b) = (holder.pid_of(&a), holder.pid_of(&b));
    let hostile: BTreeMap<String, String> = [
        ("k1".to_owned(), "/proc/9999/ns/user".to_owned()),
        ("k2".to_owned(), format!("/proc/{pid_b}/ns/ipc")),
    ]
    .into();
    create(&svc, &a, "c", hostile).await.unwrap();
    let seen = bundles.seen();
    assert_eq!(seen.len(), 1);
    let (u, i) = paths(pid_a);
    assert_eq!(seen[0].user_path.as_deref(), Some(u.as_str()));
    assert_eq!(seen[0].ipc_path.as_deref(), Some(i.as_str()));
    assert!(!format!("{:?}", seen[0]).contains("9999"));
    assert!(!format!("{:?}", seen[0]).contains(&format!("/proc/{pid_b}/")));
}

#[tokio::test]
async fn cri2_without_holder_provider_paths_are_not_supplied() {
    let holder = PerSandboxHolder::new();
    let bundles = Arc::new(RecordingBundles::default());
    let svc = service(&holder, &bundles, false);
    let a = run(&svc, "a").await;
    create(&svc, &a, "c", BTreeMap::new()).await.unwrap();
    let seen = bundles.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].supplied, None);
    assert_eq!(seen[0].user_path, None);
    assert_eq!(seen[0].ipc_path, None);
}

#[tokio::test]
async fn cri2_dead_holder_rejects_create_before_bundle_prepare() {
    let holder = PerSandboxHolder::new();
    let bundles = Arc::new(RecordingBundles::default());
    let svc = service(&holder, &bundles, true);
    let a = run(&svc, "a").await;
    *holder.exited.lock().unwrap() = true;
    let e = create(&svc, &a, "c", BTreeMap::new()).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    assert!(bundles.seen().is_empty());
    assert!(list_container_ids(&svc).await.is_empty());
}

#[tokio::test]
async fn cri2_out_of_range_holder_pid_is_internal_and_leaves_no_record() {
    let holder = PerSandboxHolder::new();
    *holder.force_pid.lock().unwrap() = Some(i32::MAX as u32 + 1);
    let bundles = Arc::new(RecordingBundles::default());
    let svc = service(&holder, &bundles, true);
    let a = run(&svc, "a").await;
    let e = create(&svc, &a, "c", BTreeMap::new()).await.unwrap_err();
    assert_eq!(e.code(), Code::Internal);
    assert!(bundles.seen().is_empty());
    assert!(list_container_ids(&svc).await.is_empty());
}

/// NET-3・SEC-5（#2878）: provider なしの `POD`（network 既定）で、各コンテナの network は自 sandbox の保持役の
/// `/proc/<pid>/ns/net` へ join し、別 pod の pid のパスは出ない。
#[tokio::test]
async fn net3_pod_network_joins_only_own_holder_net() {
    let holder = PerSandboxHolder::new();
    let bundles = Arc::new(RecordingBundles::default());
    let svc = service(&holder, &bundles, true);
    let a = run(&svc, "a").await;
    let b = run(&svc, "b").await;
    let (pid_a, pid_b) = (holder.pid_of(&a), holder.pid_of(&b));
    for (i, sb) in [&b, &a].into_iter().enumerate() {
        create(&svc, sb, &format!("n{i}"), BTreeMap::new())
            .await
            .unwrap();
    }
    for s in bundles.seen() {
        let own = if s.sandbox_id == a { pid_a } else { pid_b };
        let other = if s.sandbox_id == a { pid_b } else { pid_a };
        let want = format!("/proc/{own}/ns/net");
        assert_eq!(s.supplied_net.as_deref(), Some(want.as_str()));
        assert_eq!(s.net_path.as_deref(), Some(want.as_str()));
        assert_ne!(
            s.net_path.as_deref(),
            Some(format!("/proc/{other}/ns/net").as_str())
        );
    }
}

/// CRI-2・CORE-3・SEC-5・#4817: 素性に pod の pid ns がある保持役の sandbox では、コンテナの config の pid が自分の
/// 保持役の `pid_for_children` へ join する。素性の無い保持役（pid を共有しない）では path なしのまま。
#[tokio::test]
async fn cri2_4817_pid_is_joined_only_when_the_holder_has_a_pid_namespace() {
    let holder = PerSandboxHolder::new();
    let bundles = Arc::new(RecordingBundles::default());
    let svc = service(&holder, &bundles, true);
    let plain = run(&svc, "plain").await;
    *holder.share_pid.lock().unwrap() = true;
    let shared = run(&svc, "shared").await;
    create(&svc, &plain, "c-plain", BTreeMap::new())
        .await
        .unwrap();
    create(&svc, &shared, "c-shared", BTreeMap::new())
        .await
        .unwrap();
    let seen = bundles.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].sandbox_id, plain);
    assert_eq!(seen[0].pid_path, None);
    assert_eq!(seen[1].sandbox_id, shared);
    assert_eq!(
        seen[1].pid_path.as_deref(),
        Some(format!("/proc/{}/ns/pid_for_children", holder.pid_of(&shared)).as_str())
    );
    assert_eq!(seen[1].ipc_path, Some(paths(holder.pid_of(&shared)).1));
}

/// コンテナの ipc と mounts を指定して作る（#4823）。
async fn create_shm_case(
    svc: &CriRuntimeService,
    sandbox: &str,
    name: &str,
    ipc: Option<v1::NamespaceMode>,
    shm_mount: bool,
) -> String {
    let linux = ipc.map(|mode| v1::LinuxContainerConfig {
        security_context: Some(v1::LinuxContainerSecurityContext {
            namespace_options: Some(v1::NamespaceOption {
                ipc: mode as i32,
                // ipc を join しない構成では pid・network の `POD` は `UNIMPLEMENTED` になるため、合わせて pod にしない。
                pid: v1::NamespaceMode::Container as i32,
                network: v1::NamespaceMode::Container as i32,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    });
    let mounts = if shm_mount {
        let host = std::env::temp_dir().join("fc-4823-shm-src");
        vec![v1::Mount {
            container_path: "/dev/shm".into(),
            host_path: host.to_string_lossy().into_owned(),
            ..Default::default()
        }]
    } else {
        Vec::new()
    };
    RuntimeService::create_container(
        svc,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox.into(),
            config: Some(ContainerConfig {
                metadata: Some(ContainerMetadata {
                    name: name.into(),
                    attempt: 0,
                }),
                image: Some(ImageSpec {
                    image: "busybox:1.36".into(),
                    ..Default::default()
                }),
                command: vec!["/bin/sleep".into(), "30".into()],
                linux,
                mounts,
                ..Default::default()
            }),
            sandbox_config: None,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .container_id
}

async fn start(svc: &CriRuntimeService, id: &str) -> Result<(), tonic::Status> {
    RuntimeService::start_container(
        svc,
        Request::new(v1::StartContainerRequest {
            container_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

/// CRI-2・CORE-3・SEC-1・#4823: ipc `POD`（既定）で `/dev/shm` の mount が無いコンテナの Start は、自 sandbox の保持役の
/// pid の mnt namespace と READY の shm の素性を渡す（config の user の path の pid と一致）。別 sandbox の値は出ない。
#[tokio::test]
async fn cri2_4823_start_passes_own_holder_pod_shm_only() {
    let holder = PerSandboxHolder::new();
    *holder.share_pid.lock().unwrap() = true;
    let bundles = Arc::new(RecordingBundles::default());
    let rt = Arc::new(StubRuntime::default());
    let svc = service_with(&holder, &bundles, true, rt.clone());
    let a = run(&svc, "a").await;
    let b = run(&svc, "b").await;
    let (pid_a, pid_b) = (holder.pid_of(&a), holder.pid_of(&b));
    assert_ne!(pid_a, pid_b);
    let ca = create_shm_case(&svc, &a, "ca", None, false).await;
    let cb = create_shm_case(&svc, &b, "cb", None, false).await;
    for id in [&ca, &cb] {
        let _ = start(&svc, id).await;
    }
    let starts = rt.starts.lock().unwrap().clone();
    assert_eq!(starts.len(), 2);
    for (id, pid) in [(&ca, pid_a), (&cb, pid_b)] {
        let got = starts.iter().find(|(i, _)| i == id).unwrap();
        assert_eq!(
            got.1,
            Some((format!("/proc/{pid}/ns/mnt"), 48, 2)),
            "container {id}"
        );
    }
    // config の user の path の pid と同じ保持役から作られている。
    for s in bundles.seen() {
        let own = if s.sandbox_id == a { pid_a } else { pid_b };
        assert_eq!(s.user_path, Some(format!("/proc/{own}/ns/user")));
    }
}

/// CRI-2・SEC-1・#4823: 共有の条件に当たらないコンテナには pod shm を渡さない。`/dev/shm` の mount あり・ipc
/// `CONTAINER`・provider なし・素性なしの保持役（pid を共有しない構成の `PodHolder::new`）。
#[tokio::test]
async fn cri2_4823_start_passes_no_pod_shm_outside_the_condition() {
    // 素性つきの保持役・provider あり: mount あり・ipc CONTAINER。
    let holder = PerSandboxHolder::new();
    *holder.share_pid.lock().unwrap() = true;
    let bundles = Arc::new(RecordingBundles::default());
    let rt = Arc::new(StubRuntime::default());
    let svc = service_with(&holder, &bundles, true, rt.clone());
    let a = run(&svc, "a").await;
    let with_mount = create_shm_case(&svc, &a, "m", None, true).await;
    let container_ipc =
        create_shm_case(&svc, &a, "c", Some(v1::NamespaceMode::Container), false).await;
    for id in [&with_mount, &container_ipc] {
        let _ = start(&svc, id).await;
    }
    // provider なし。
    let holder2 = PerSandboxHolder::new();
    let rt2 = Arc::new(StubRuntime::default());
    let svc2 = service_with(
        &holder2,
        &Arc::new(RecordingBundles::default()),
        false,
        rt2.clone(),
    );
    let b = run(&svc2, "b").await;
    let no_provider = create_shm_case(&svc2, &b, "n", None, false).await;
    let _ = start(&svc2, &no_provider).await;
    // 素性なしの保持役（share_pid 偽）。
    let holder3 = PerSandboxHolder::new();
    let rt3 = Arc::new(StubRuntime::default());
    let svc3 = service_with(
        &holder3,
        &Arc::new(RecordingBundles::default()),
        true,
        rt3.clone(),
    );
    let c = run(&svc3, "c").await;
    let no_identity = create_shm_case(&svc3, &c, "i", None, false).await;
    let _ = start(&svc3, &no_identity).await;

    for rt in [&rt, &rt2, &rt3] {
        let starts = rt.starts.lock().unwrap().clone();
        assert!(!starts.is_empty());
        assert!(starts.iter().all(|(_, shm)| shm.is_none()), "{starts:?}");
    }
    assert_eq!(rt.starts.lock().unwrap().len(), 2);
}

/// CRI-2・SEC-1（#4895・案 a）: `selinux_relabel` つきの `/dev/termination-log` の mount は、CreateContainer が
/// gRPC `Unimplemented`（固定の文言）で拒否し、実行層（create）を呼ばず記録も残さない。
/// sandbox の `selinux_options` は RunPodSandbox では受け、CreateContainer の bundle 生成で同じ拒否になる。
#[tokio::test]
async fn cri2_sec1_4895_selinux_relabel_mount_rejected_without_runtime_call_or_record() {
    let (holder, bundles) = (
        PerSandboxHolder::new(),
        Arc::new(RecordingBundles::default()),
    );
    let runtime = Arc::new(StubRuntime::default());
    let svc = service_with(&holder, &bundles, false, runtime.clone());
    let sb = run(&svc, "a").await;
    let req = |relabel: bool| v1::CreateContainerRequest {
        pod_sandbox_id: sb.clone(),
        config: Some(ContainerConfig {
            metadata: Some(ContainerMetadata {
                name: "c".into(),
                attempt: 0,
            }),
            image: Some(ImageSpec {
                image: "busybox:1.36".into(),
                ..Default::default()
            }),
            command: vec!["/bin/sleep".into(), "30".into()],
            mounts: vec![v1::Mount {
                container_path: "/dev/termination-log".into(),
                host_path: "/var/lib/kubelet/pods/p/containers/c/1".into(),
                selinux_relabel: relabel,
                ..Default::default()
            }],
            ..Default::default()
        }),
        sandbox_config: None,
    };
    let st = RuntimeService::create_container(&svc, Request::new(req(true)))
        .await
        .expect_err("rejected");
    assert_eq!(st.code(), Code::Unimplemented);
    assert_eq!(st.message(), "mounts.selinux_relabel is not supported");
    assert!(runtime.created.lock().unwrap().is_empty());
    assert!(list_container_ids(&svc).await.is_empty());
    // 対照: relabel なしなら同じ mount で通る。
    RuntimeService::create_container(&svc, Request::new(req(false)))
        .await
        .expect("control");

    // sandbox の selinux_options: RunPodSandbox は受け、CreateContainer で拒否する。RunPodSandbox で受けるのは残余の
    // 現状の固定で要件ではない。拒否を RunPodSandbox へ早めてよく、そのときはこの段を RunPodSandbox の拒否の照合へ
    // 置き換える（docs/design/cri-config-acceptance.md「SELinux の受け入れ方式」の残余）。
    let mut cfg = sandbox_config("b");
    cfg.linux = Some(v1::LinuxPodSandboxConfig {
        security_context: Some(v1::LinuxSandboxSecurityContext {
            selinux_options: Some(Default::default()),
            ..Default::default()
        }),
        ..Default::default()
    });
    let sb2 = RuntimeService::run_pod_sandbox(
        &svc,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(cfg),
            runtime_handler: String::new(),
        }),
    )
    .await
    .expect("RunPodSandbox accepts selinux_options")
    .into_inner()
    .pod_sandbox_id;
    let mut r = req(false);
    r.pod_sandbox_id = sb2;
    let st = RuntimeService::create_container(&svc, Request::new(r))
        .await
        .expect_err("rejected");
    assert_eq!(st.code(), Code::Unimplemented);
    assert_eq!(st.message(), "selinux_options is not supported");
    assert_eq!(runtime.created.lock().unwrap().len(), 1);
}
