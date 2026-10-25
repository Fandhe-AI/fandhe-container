//! pod の netns を `PodNetworkProvider` 経由で作って結線する経路の試験（CRI-2・NET-1・PLUG-1・REPAIR-5・REPAIR-12。#2675）。
//!
//! フェイクの `PodNetworkProvider`・`BundleProvider`・実行層を注入し、`RunPodSandbox` / `CreateContainer` /
//! `StopPodSandbox` / `RemovePodSandbox` の呼び出し列と記録の残り方を具体値で確かめる。
//! 本番（plugin-cri）はコア側の network namespace の join が入るまで provider を差さない（`docs/design/cri-config-acceptance.md`）。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, ErrorCode,
    KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{
    BundleProvider, BundleRequest, PodNetns, PodNetworkProvider, PodNetworkRequest, RuntimeAdapter,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, LinuxPodSandboxConfig,
    LinuxSandboxSecurityContext, NamespaceMode, NamespaceOption, PodSandboxConfig,
    PodSandboxMetadata, runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use tonic::{Code, Request};

fn netns_path(id: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\state\.netns").join(id)
    } else {
        PathBuf::from("/state/.netns").join(id)
    }
}

#[derive(Clone, Copy, PartialEq)]
enum SetUp {
    Ok,
    Fail,
    BadPath,
    Hang,
}

struct FakeNetwork {
    calls: Mutex<Vec<String>>,
    set_up: Mutex<SetUp>,
    tear_down_fails: Mutex<bool>,
}

impl FakeNetwork {
    fn new(set_up: SetUp) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            set_up: Mutex::new(set_up),
            tear_down_fails: Mutex::new(false),
        })
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl PodNetworkProvider for FakeNetwork {
    fn set_up(&self, req: &PodNetworkRequest<'_>) -> Result<PodNetns, CriError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("set_up {}", req.sandbox_id));
        match *self.set_up.lock().unwrap() {
            SetUp::Ok => PodNetns::new(netns_path(req.sandbox_id)),
            SetUp::Fail => Err(CriError::failed_precondition("network unavailable")),
            SetUp::BadPath => PodNetns::new(PathBuf::from("relative/ns")),
            SetUp::Hang => {
                std::thread::sleep(Duration::from_secs(3));
                PodNetns::new(netns_path(req.sandbox_id))
            }
        }
    }
    fn tear_down(&self, sandbox_id: &str) -> Result<(), CriError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("tear_down {sandbox_id}"));
        if *self.tear_down_fails.lock().unwrap() {
            Err(CriError::internal("tear down failed"))
        } else {
            Ok(())
        }
    }
}

/// `BundleRequest::pod_netns_path` を記録するフェイク。
#[derive(Default)]
struct RecordingBundles(Mutex<Vec<Option<PathBuf>>>);

impl BundleProvider for RecordingBundles {
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PathBuf, CriError> {
        self.0
            .lock()
            .unwrap()
            .push(req.pod_netns_path.map(|p| p.to_path_buf()));
        Ok(PathBuf::from("/bundles").join(req.container_id))
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

fn sandbox_config(network: Option<NamespaceMode>) -> PodSandboxConfig {
    PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "pod".into(),
            uid: "uid-1".into(),
            namespace: "ns".into(),
            attempt: 0,
        }),
        linux: network.map(|m| LinuxPodSandboxConfig {
            security_context: Some(LinuxSandboxSecurityContext {
                namespace_options: Some(NamespaceOption {
                    network: m as i32,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn run(
    svc: &CriRuntimeService,
    network: Option<NamespaceMode>,
) -> Result<String, tonic::Status> {
    RuntimeService::run_pod_sandbox(
        svc,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(sandbox_config(network)),
            runtime_handler: String::new(),
        }),
    )
    .await
    .map(|r| r.into_inner().pod_sandbox_id)
}

async fn list_ids(svc: &CriRuntimeService) -> Vec<String> {
    RuntimeService::list_pod_sandbox(svc, Request::new(v1::ListPodSandboxRequest::default()))
        .await
        .unwrap()
        .into_inner()
        .items
        .into_iter()
        .map(|i| i.id)
        .collect()
}

async fn stop(svc: &CriRuntimeService, id: &str) -> Result<(), tonic::Status> {
    RuntimeService::stop_pod_sandbox(
        svc,
        Request::new(v1::StopPodSandboxRequest {
            pod_sandbox_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

async fn remove(svc: &CriRuntimeService, id: &str) -> Result<(), tonic::Status> {
    RuntimeService::remove_pod_sandbox(
        svc,
        Request::new(v1::RemovePodSandboxRequest {
            pod_sandbox_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

async fn create_container(svc: &CriRuntimeService, sandbox: &str) -> Result<String, tonic::Status> {
    RuntimeService::create_container(
        svc,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox.into(),
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
            sandbox_config: None,
        }),
    )
    .await
    .map(|r| r.into_inner().container_id)
}

fn service(net: &Arc<FakeNetwork>) -> CriRuntimeService {
    CriRuntimeService::new().with_pod_network(net.clone())
}

#[tokio::test]
async fn pod_mode_calls_set_up_once_with_the_sandbox_id() {
    let net = FakeNetwork::new(SetUp::Ok);
    let svc = service(&net);
    let id = run(&svc, None).await.unwrap();
    assert_eq!(net.calls(), vec![format!("set_up {id}")]);
    let id2 = {
        let svc = service(&net);
        run(&svc, Some(NamespaceMode::Pod)).await.unwrap()
    };
    assert_eq!(net.calls()[1], format!("set_up {id2}"));
}

#[tokio::test]
async fn node_mode_does_not_touch_the_network() {
    let net = FakeNetwork::new(SetUp::Ok);
    let svc = service(&net);
    let id = run(&svc, Some(NamespaceMode::Node)).await.unwrap();
    assert!(net.calls().is_empty());
    stop(&svc, &id).await.unwrap();
    remove(&svc, &id).await.unwrap();
    assert!(net.calls().is_empty());
}

#[tokio::test]
async fn set_up_failure_registers_nothing_and_tears_down() {
    let net = FakeNetwork::new(SetUp::Fail);
    let svc = service(&net);
    let e = run(&svc, None).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    let calls = net.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(calls[0].starts_with("set_up "));
    assert!(calls[1].starts_with("tear_down "));
    assert!(list_ids(&svc).await.is_empty());
}

#[tokio::test]
async fn set_up_failure_with_failed_tear_down_keeps_a_notready_record() {
    let net = FakeNetwork::new(SetUp::Fail);
    *net.tear_down_fails.lock().unwrap() = true;
    let svc = service(&net);
    assert!(run(&svc, None).await.is_err());
    let ids = list_ids(&svc).await;
    assert_eq!(ids.len(), 1);
    // set_up の失敗後は notready で、配下のコンテナを作れない（Ready のまま残らない）。
    assert!(create_container(&svc, &ids[0]).await.is_err());
    // 回収の再試行（Remove）が成功すれば記録は消える。
    *net.tear_down_fails.lock().unwrap() = false;
    remove(&svc, &ids[0]).await.unwrap();
    assert!(list_ids(&svc).await.is_empty());
}

#[tokio::test]
async fn malformed_netns_path_from_provider_is_rejected() {
    let net = FakeNetwork::new(SetUp::BadPath);
    let svc = service(&net);
    // provider 側の `PodNetns::new` が INTERNAL で拒否する。
    let e = run(&svc, None).await.unwrap_err();
    assert_eq!(e.code(), Code::Internal);
    assert!(list_ids(&svc).await.is_empty());
}

#[test]
fn pod_netns_new_validates_the_path() {
    for bad in ["", "rel/ns", "/", "/a/../b", "/a/./b"] {
        assert!(PodNetns::new(PathBuf::from(bad)).is_err(), "{bad}");
    }
    let long = format!("/{}", "a".repeat(4096));
    assert!(PodNetns::new(PathBuf::from(long)).is_err());
    if !cfg!(windows) {
        let ok = PodNetns::new(PathBuf::from("/state/.netns/abc")).unwrap();
        assert_eq!(ok.path(), std::path::Path::new("/state/.netns/abc"));
    }
}

#[tokio::test]
async fn timeout_keeps_a_notready_record_and_remove_tears_down() {
    let net = FakeNetwork::new(SetUp::Hang);
    let svc = CriRuntimeService::new()
        .with_pod_network(net.clone())
        .with_runtime_timeout(Duration::from_millis(200));
    let e = run(&svc, None).await.unwrap_err();
    assert_eq!(e.code(), Code::DeadlineExceeded);
    let ids = list_ids(&svc).await;
    assert_eq!(ids.len(), 1);
    // 期限超過では同時に tear_down を呼ばない。
    assert_eq!(net.calls(), vec![format!("set_up {}", ids[0])]);
    // set_up がまだ走っている間は Stop・Remove を拒否し、tear_down と競合させない（資源の漏れ防止）。
    let e = remove(&svc, &ids[0]).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    let e = stop(&svc, &ids[0]).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    assert_eq!(net.calls().len(), 1, "{:?}", net.calls());
    // worker の完了後（pending 解除後）は Remove が tear_down で回収して記録を消す。
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match remove(&svc, &ids[0]).await {
            Ok(()) => break,
            Err(e) => {
                assert_eq!(e.code(), Code::FailedPrecondition);
                assert!(
                    std::time::Instant::now() < deadline,
                    "set_up never finished"
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    assert_eq!(net.calls()[1], format!("tear_down {}", ids[0]));
    assert!(list_ids(&svc).await.is_empty());
}

/// CRI-2・NET-1: 期限超過で DEADLINE_EXCEEDED を返した後に worker の set_up が成功しても、
/// sandbox は NotReady のまま（Ready に戻さず、CreateContainer も通さない）。
#[tokio::test]
async fn late_set_up_success_after_timeout_never_becomes_ready() {
    let net = FakeNetwork::new(SetUp::Hang);
    let svc = CriRuntimeService::new()
        .with_pod_network(net.clone())
        .with_runtime_timeout(Duration::from_millis(200));
    let e = run(&svc, None).await.unwrap_err();
    assert_eq!(e.code(), Code::DeadlineExceeded);
    let id = list_ids(&svc).await.remove(0);
    // Hang の set_up（3 秒）が完了するまで待つ。pending が外れれば Stop が受理される。
    tokio::time::sleep(Duration::from_millis(3600)).await;
    let list = svc
        .list_pod_sandbox(Request::new(v1::ListPodSandboxRequest { filter: None }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(list.items.len(), 1);
    assert_eq!(
        list.items[0].state,
        v1::PodSandboxState::SandboxNotready as i32
    );
    let e = create_container(&svc, &id).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn stop_tears_down_once_and_remove_does_not_repeat() {
    let net = FakeNetwork::new(SetUp::Ok);
    let svc = service(&net);
    let id = run(&svc, None).await.unwrap();
    stop(&svc, &id).await.unwrap();
    stop(&svc, &id).await.unwrap();
    remove(&svc, &id).await.unwrap();
    assert_eq!(
        net.calls(),
        vec![format!("set_up {id}"), format!("tear_down {id}")]
    );
}

#[tokio::test]
async fn failed_tear_down_keeps_the_record_and_can_be_retried() {
    let net = FakeNetwork::new(SetUp::Ok);
    let svc = service(&net);
    let id = run(&svc, None).await.unwrap();
    *net.tear_down_fails.lock().unwrap() = true;
    let e = remove(&svc, &id).await.unwrap_err();
    assert_eq!(e.code(), Code::Internal);
    assert_eq!(list_ids(&svc).await, vec![id.clone()]);
    *net.tear_down_fails.lock().unwrap() = false;
    remove(&svc, &id).await.unwrap();
    assert!(list_ids(&svc).await.is_empty());
    assert_eq!(
        net.calls(),
        vec![
            format!("set_up {id}"),
            format!("tear_down {id}"),
            format!("tear_down {id}")
        ]
    );
}

#[tokio::test]
async fn create_container_receives_the_pod_netns_path() {
    let net = FakeNetwork::new(SetUp::Ok);
    let bundles = Arc::new(RecordingBundles::default());
    let svc = CriRuntimeService::new()
        .with_pod_network(net.clone())
        .with_runtime(
            RuntimeAdapter::new(Arc::new(StubRuntime::default())),
            bundles.clone(),
        );
    let id = run(&svc, None).await.unwrap();
    create_container(&svc, &id).await.unwrap();
    assert_eq!(*bundles.0.lock().unwrap(), vec![Some(netns_path(&id))]);
}

#[tokio::test]
async fn create_container_gets_no_path_without_provider_or_in_node_mode() {
    let bundles = Arc::new(RecordingBundles::default());
    let svc = CriRuntimeService::new().with_runtime(
        RuntimeAdapter::new(Arc::new(StubRuntime::default())),
        bundles.clone(),
    );
    let id = run(&svc, None).await.unwrap();
    create_container(&svc, &id).await.unwrap();
    assert_eq!(*bundles.0.lock().unwrap(), vec![None]);

    let net = FakeNetwork::new(SetUp::Ok);
    let bundles = Arc::new(RecordingBundles::default());
    let svc = CriRuntimeService::new().with_pod_network(net).with_runtime(
        RuntimeAdapter::new(Arc::new(StubRuntime::default())),
        bundles.clone(),
    );
    let id = run(&svc, Some(NamespaceMode::Node)).await.unwrap();
    create_container(&svc, &id).await.unwrap();
    assert_eq!(*bundles.0.lock().unwrap(), vec![None]);
}
