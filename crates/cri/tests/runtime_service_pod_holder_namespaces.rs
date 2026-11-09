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
    BundleProvider, BundleRequest, PodHolder, PodHolderLiveness, PodHolderRequest,
    PodNamespaceHolderProvider, PreparedBundle, RuntimeAdapter,
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
}

impl PerSandboxHolder {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU32::new(4242),
            pids: Mutex::new(HashMap::new()),
            exited: Mutex::new(false),
            force_pid: Mutex::new(None),
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
        Ok(PodHolder::new(pid.try_into().unwrap()))
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

#[derive(Default)]
struct StubRuntime(Mutex<HashMap<String, ()>>);

impl ContainerRuntime for StubRuntime {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        self.0
            .lock()
            .unwrap()
            .insert(r.id().as_str().to_owned(), ());
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
    fn start(&self, _: &StartRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Ok(ContainerStatus::stopped(r.id().clone(), Some(0)))
    }
    fn delete(&self, r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        self.0.lock().unwrap().remove(r.id().as_str());
        Ok(DeleteResponse::new())
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        if self.0.lock().unwrap().contains_key(r.id().as_str()) {
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
    let svc = CriRuntimeService::new();
    let svc = if with_holder {
        svc.with_pod_holder(holder.clone())
    } else {
        svc
    };
    svc.with_runtime(
        RuntimeAdapter::new(Arc::new(StubRuntime::default())),
        bundles.clone(),
    )
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
