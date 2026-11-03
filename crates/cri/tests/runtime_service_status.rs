//! `RuntimeService.Status` の応答の試験（CRI-1・CRI-2・REPAIR-3・REPAIR-4・REPAIR-5・#2830）。
//!
//! 公開の `RuntimeService` トレイトを plugin-cri と同じ立場で呼び、condition・runtime_handlers・features・info を
//! 具体値で照合する。kubelet は `RuntimeReady`・`NetworkReady` を見る（`docs/design/cri-status-rpc.md`）。

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, ErrorCode,
    KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{
    BundleProvider, BundleRequest, PodNetns, PodNetworkProvider, PodNetworkRequest, PreparedBundle,
    RuntimeAdapter,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::instrument::{CriOpKind, CriOpRecorder, CriOpSample};
use fandhe_container_cri::runtime::v1::{self, runtime_service_server::RuntimeService};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use tonic::{Code, Request};

/// どのメソッドも呼ばれない実行層（`Status` が実行層を呼ばないことの裏づけにもなる）。
struct UnusedRuntime;

impl ContainerRuntime for UnusedRuntime {
    fn create(&self, _: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        panic!("Status must not call the runtime");
    }
    fn start(&self, _: &StartRequest) -> Result<ContainerStatus, TraitError> {
        panic!("Status must not call the runtime");
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
        panic!("Status must not call the runtime");
    }
    fn delete(&self, _: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        panic!("Status must not call the runtime");
    }
    fn state(&self, _: &StateRequest) -> Result<ContainerStatus, TraitError> {
        panic!("Status must not call the runtime");
    }
}

struct UnusedBundles;

impl BundleProvider for UnusedBundles {
    fn prepare(&self, _: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
        panic!("Status must not prepare a bundle");
    }
    fn release(&self, _: &str) -> Result<(), CriError> {
        panic!("Status must not release a bundle");
    }
}

/// 呼び出し回数を数える `PodNetworkProvider`（`Status` が呼ばないことの照合用）。
#[derive(Default)]
struct CountingNetwork(Mutex<u32>);

impl PodNetworkProvider for CountingNetwork {
    fn set_up(&self, req: &PodNetworkRequest<'_>) -> Result<PodNetns, CriError> {
        *self.0.lock().unwrap() += 1;
        PodNetns::new(PathBuf::from(format!("/state/.netns/{}", req.sandbox_id)))
    }
    fn tear_down(&self, _: &str) -> Result<(), CriError> {
        *self.0.lock().unwrap() += 1;
        Ok(())
    }
}

#[derive(Default)]
struct Collect(Mutex<Vec<CriOpSample>>);

impl CriOpRecorder for Collect {
    fn record_cri_op(&self, sample: &CriOpSample) {
        self.0.lock().unwrap().push(*sample);
    }
}

fn adapter() -> RuntimeAdapter {
    RuntimeAdapter::new(Arc::new(UnusedRuntime))
}

async fn status(service: &CriRuntimeService, verbose: bool) -> v1::StatusResponse {
    service
        .status(Request::new(v1::StatusRequest { verbose }))
        .await
        .expect("status")
        .into_inner()
}

fn cond(kind: &str, status: bool, reason: &str, message: &str) -> v1::RuntimeCondition {
    v1::RuntimeCondition {
        r#type: kind.into(),
        status,
        reason: reason.into(),
        message: message.into(),
    }
}

fn not_connected() -> v1::RuntimeCondition {
    cond(
        "RuntimeReady",
        false,
        "RuntimeNotConnected",
        "container runtime backend is not connected",
    )
}

fn network_not_ready() -> v1::RuntimeCondition {
    cond(
        "NetworkReady",
        false,
        "NetworkPluginNotReady",
        "pod network provider is not configured",
    )
}

/// CRI-1・CRI-2: 実行層も pod network も無い構成は両方 false（実装済みを装わない。REPAIR-3）。
#[tokio::test]
async fn cri_1_status_without_backends_reports_both_conditions_false() {
    let resp = status(&CriRuntimeService::new(), false).await;
    assert_eq!(
        resp.status.expect("status").conditions,
        vec![not_connected(), network_not_ready()]
    );
    assert_eq!(
        resp.runtime_handlers,
        vec![v1::RuntimeHandler {
            name: String::new(),
            features: Some(v1::RuntimeHandlerFeatures {
                recursive_read_only_mounts: false,
                user_namespaces: false,
            }),
        }]
    );
    assert_eq!(
        resp.features,
        Some(v1::RuntimeFeatures {
            supplemental_groups_policy: true,
            user_namespaces_host_network: false,
            mount_options: false,
        })
    );
    assert!(resp.info.is_empty());
}

/// CRI-2: 実行層だけ注入すると RuntimeReady が true、NetworkReady は false のまま（本番 plugin-cri の形）。
#[tokio::test]
async fn cri_2_status_with_runtime_only_is_runtime_ready_network_not_ready() {
    let service = CriRuntimeService::new().with_runtime(adapter(), Arc::new(UnusedBundles));
    let resp = status(&service, false).await;
    assert_eq!(
        resp.status.expect("status").conditions,
        vec![cond("RuntimeReady", true, "", ""), network_not_ready()]
    );
}

/// CRI-2: pod network も注入すると両方 true。`Status` は provider も実行層も呼ばない（待ちと副作用が無い）。
#[tokio::test]
async fn cri_2_status_with_runtime_and_network_is_ready_without_calling_them() {
    let network = Arc::new(CountingNetwork::default());
    let service = CriRuntimeService::new()
        .with_runtime(adapter(), Arc::new(UnusedBundles))
        .with_pod_network(network.clone());
    let resp = status(&service, false).await;
    assert_eq!(
        resp.status.expect("status").conditions,
        vec![
            cond("RuntimeReady", true, "", ""),
            cond("NetworkReady", true, "", "")
        ]
    );
    assert_eq!(*network.0.lock().unwrap(), 0);
}

/// CRI-2: `verbose` でも `info` は空で、応答は verbose=false と同じ（内部のパス・構成を出さない）。
#[tokio::test]
async fn cri_2_status_verbose_keeps_info_empty() {
    let service = CriRuntimeService::new().with_runtime(adapter(), Arc::new(UnusedBundles));
    let plain = status(&service, false).await;
    let verbose = status(&service, true).await;
    assert!(verbose.info.is_empty());
    assert_eq!(plain, verbose);
}

/// REPAIR-4: `cri.status` が `OK` で 1 件だけ記録される。
#[tokio::test]
async fn repair_4_status_records_one_ok_sample() {
    let recorder = Arc::new(Collect::default());
    let service = CriRuntimeService::with_recorder(recorder.clone());
    status(&service, true).await;
    let samples = recorder.0.lock().unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].kind(), CriOpKind::Status);
    assert_eq!(samples[0].code(), Code::Ok);
}
/// CRI-2: provider だけ注入した構成（実行層なし）は RuntimeReady が false、NetworkReady が true。
/// 実行層の有無と provider の有無は独立に判定され、provider は呼ばれない（#2897）。
#[tokio::test]
async fn cri_2_status_with_network_only_is_network_ready_runtime_not_connected() {
    let network = Arc::new(CountingNetwork::default());
    let service = CriRuntimeService::new().with_pod_network(network.clone());
    let resp = status(&service, false).await;
    assert_eq!(
        resp.status.expect("status").conditions,
        vec![not_connected(), cond("NetworkReady", true, "", "")]
    );
    assert_eq!(*network.0.lock().unwrap(), 0);
}

/// 呼ばれたら回数を数えて最大 30 秒止まる実行層（`Status` が待たないことの照合用。無期限には待たない。REPAIR-5）。
#[derive(Default)]
struct BlockingRuntime(Mutex<u32>);

impl BlockingRuntime {
    fn hit<T>(&self) -> Result<T, TraitError> {
        *self.0.lock().unwrap() += 1;
        std::thread::park_timeout(std::time::Duration::from_secs(30));
        Err(TraitError::new(ErrorCode::Unimplemented, "blocked"))
    }
}

impl ContainerRuntime for BlockingRuntime {
    fn create(&self, _: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        self.hit()
    }
    fn start(&self, _: &StartRequest) -> Result<ContainerStatus, TraitError> {
        self.hit()
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        self.hit()
    }
    fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
        self.hit()
    }
    fn delete(&self, _: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        self.hit()
    }
    fn state(&self, _: &StateRequest) -> Result<ContainerStatus, TraitError> {
        self.hit()
    }
}

/// 呼ばれたら回数を数えて最大 30 秒止まる `PodNetworkProvider`。
#[derive(Default)]
struct BlockingNetwork(Mutex<u32>);

impl BlockingNetwork {
    fn hit<T>(&self) -> Result<T, CriError> {
        *self.0.lock().unwrap() += 1;
        std::thread::park_timeout(std::time::Duration::from_secs(30));
        Err(CriError::unimplemented("blocked"))
    }
}

impl PodNetworkProvider for BlockingNetwork {
    fn set_up(&self, _: &PodNetworkRequest<'_>) -> Result<PodNetns, CriError> {
        self.hit()
    }
    fn tear_down(&self, _: &str) -> Result<(), CriError> {
        self.hit()
    }
}

/// CRI-1・CRI-2・REPAIR-5・#2897: 実行層・provider が応答しなくても `Status` は待たずに返る。
/// 死活確認を足さない判断（`docs/design/cri-status-rpc.md`）の不変条件で、将来 `Status` が両者を
/// 呼ぶ変更が入ると、応答が 2 秒の期限を超えるか呼び出し回数が 0 でなくなって失敗する。
#[test]
fn repair_5_status_returns_without_waiting_on_blocked_backends() {
    let runtime = Arc::new(BlockingRuntime::default());
    let network = Arc::new(BlockingNetwork::default());
    let service = CriRuntimeService::new()
        .with_runtime(
            RuntimeAdapter::new(runtime.clone()),
            Arc::new(UnusedBundles),
        )
        .with_pod_network(network.clone());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let resp = rt.block_on(status(&service, false));
        let _ = tx.send(resp);
    });
    let resp = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("Status must return within the deadline");
    assert_eq!(
        resp.status.expect("status").conditions,
        vec![
            cond("RuntimeReady", true, "", ""),
            cond("NetworkReady", true, "", "")
        ]
    );
    assert_eq!(*runtime.0.lock().unwrap(), 0);
    assert_eq!(*network.0.lock().unwrap(), 0);
}
