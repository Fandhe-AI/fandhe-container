//! shim v2 の `TaskService` と CRI の `RuntimeService` が同じ `ContainerRuntime` 実装を共有できることの結合試験
//! （TASK-62.5・CRI-5・CRI-7・REPAIR-12・MS-7）。
//!
//! 1 つのフェイクの実行層から作った `RuntimeAdapter` を clone して両アダプタへ渡し、
//! 一方で作ったコンテナが他方から見えること・呼び出し列が 1 本になることを具体値で確かめる。
//! 依存の向き（shim_v2 が core の `traits` だけを参照する）の静的照合は `shim_v2_runtime_boundary.rs`。
//! UDS は使わず `ServiceRegistry::dispatch` を直接呼ぶため全 OS で動く。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerState, ContainerStatus, CreateRequest, DeleteRequest,
    DeleteResponse, ErrorCode, KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{
    BundleProvider, BundleRequest, PreparedBundle, RuntimeAdapter,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use fandhe_container_cri::shim_v2::{
    CreateTaskRequest, ServiceRegistry, StartRequest as ShimStart, StartResponse, TaskApiVersion,
    TaskService, TtrpcRequest, TtrpcResponse, WaitRequest, WaitResponse,
};
use prost::Message;
use tonic::Request;

/// 停止時にフェイクが返す終了コード（SIGTERM 相当。反映の確認用の具体値）。
const STOP_EXIT_CODE: i32 = 143;

/// ID ごとの状態を保持し、遷移規則を守るフェイクの実行層。呼び出し列も記録する。
#[derive(Default)]
struct LifecycleRuntime {
    calls: Mutex<Vec<String>>,
    states: Mutex<HashMap<String, ContainerState>>,
}

impl LifecycleRuntime {
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
    fn state_of(&self, id: &str) -> Option<ContainerState> {
        self.states.lock().unwrap().get(id).copied()
    }
}

struct Shared(Arc<LifecycleRuntime>);

impl ContainerRuntime for Shared {
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
            None => Err(TraitError::new(ErrorCode::NotFound, "no such container")),
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
            None => Err(TraitError::new(ErrorCode::NotFound, "no such container")),
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
            None => Err(TraitError::new(ErrorCode::NotFound, "no such container")),
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
        match self.0.state_of(id) {
            None => Err(TraitError::new(ErrorCode::NotFound, "no such container")),
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

fn bundle_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\bundles")
    } else {
        PathBuf::from("/bundles")
    }
}

/// bundle の用意・解放を記録するフェイク。
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
        Ok(PreparedBundle::new(bundle_root().join(container_id)))
    }
    fn release(&self, container_id: &str) -> Result<(), CriError> {
        self.0
            .lock()
            .unwrap()
            .push(format!("release {container_id}"));
        Ok(())
    }
}

fn shim_call(
    reg: &ServiceRegistry,
    version: TaskApiVersion,
    method: &str,
    payload: Vec<u8>,
) -> TtrpcResponse {
    reg.dispatch(&TtrpcRequest {
        service: version.service_name().into(),
        method: method.into(),
        payload,
        ..Default::default()
    })
}

fn create_payload(id: &str) -> Vec<u8> {
    CreateTaskRequest {
        id: id.into(),
        bundle: bundle_root().join(id).display().to_string(),
        ..Default::default()
    }
    .encode_to_vec()
}

async fn cri_container(svc: &CriRuntimeService) -> String {
    let sandbox = RuntimeService::run_pod_sandbox(
        svc,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "pod".into(),
                    uid: "uid-1".into(),
                    namespace: "ns".into(),
                    attempt: 0,
                }),
                ..Default::default()
            }),
            runtime_handler: String::new(),
        }),
    )
    .await
    .expect("run sandbox")
    .into_inner()
    .pod_sandbox_id;
    let id = RuntimeService::create_container(
        svc,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox,
            config: Some(ContainerConfig {
                metadata: Some(ContainerMetadata {
                    name: "app".into(),
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
    .expect("create container")
    .into_inner()
    .container_id;
    RuntimeService::start_container(
        svc,
        Request::new(v1::StartContainerRequest {
            container_id: id.clone(),
        }),
    )
    .await
    .expect("start container");
    id
}

/// CRI-5・CRI-7: 同じ実装を指す adapter の clone を両アダプタへ渡すと、状態と呼び出し列を共有する。
#[tokio::test]
async fn cri7_shim_v2_and_runtime_service_share_one_container_runtime() {
    for version in [TaskApiVersion::V2, TaskApiVersion::V3] {
        let runtime = Arc::new(LifecycleRuntime::default());
        let bundles = Arc::new(RecordingBundles::default());
        let adapter = RuntimeAdapter::new(Arc::new(Shared(runtime.clone())));
        let cri = CriRuntimeService::new().with_runtime(adapter.clone(), bundles);
        let mut reg = ServiceRegistry::new();
        reg.register(Arc::new(TaskService::new(version, adapter)))
            .expect("register");

        // a. shim の Create -> Start
        let r = shim_call(&reg, version, "Create", create_payload("shim-c1"));
        assert!(r.status.is_none(), "{r:?}");
        let r = shim_call(
            &reg,
            version,
            "Start",
            ShimStart {
                id: "shim-c1".into(),
                exec_id: String::new(),
            }
            .encode_to_vec(),
        );
        assert!(r.status.is_none(), "{r:?}");
        assert_eq!(StartResponse::decode(&r.payload[..]).unwrap().pid, 4242);
        assert_eq!(runtime.state_of("shim-c1"), Some(ContainerState::Running));

        // b. CRI で作ったコンテナの ID を shim の Create で重ねると、同じ実装の状態を見て ALREADY_EXISTS(6)
        let cri_id = cri_container(&cri).await;
        assert_eq!(runtime.state_of(&cri_id), Some(ContainerState::Running));
        let r = shim_call(&reg, version, "Create", create_payload(&cri_id));
        assert_eq!(r.status.expect("already exists").code, 6);

        // c. CRI の StopContainer の後、shim の Wait が停止の終了コードを返す
        RuntimeService::stop_container(
            &cri,
            Request::new(v1::StopContainerRequest {
                container_id: cri_id.clone(),
                timeout: 5,
            }),
        )
        .await
        .expect("stop container");
        let r = shim_call(
            &reg,
            version,
            "Wait",
            WaitRequest {
                id: cri_id.clone(),
                exec_id: String::new(),
            }
            .encode_to_vec(),
        );
        assert!(r.status.is_none(), "{r:?}");
        assert_eq!(
            WaitResponse::decode(&r.payload[..]).unwrap().exit_status,
            STOP_EXIT_CODE as u32
        );

        // d. 両アダプタからの呼び出しが 1 本の列に入っている
        let calls = runtime.mutating_calls();
        let bundle = |id: &str| format!("create {id} {}", bundle_root().join(id).display());
        assert_eq!(
            calls.first().map(String::as_str),
            Some(bundle("shim-c1").as_str())
        );
        assert_eq!(calls.get(1).map(String::as_str), Some("start shim-c1"));
        assert!(calls.contains(&bundle(&cri_id)), "{calls:?}");
        assert!(calls.contains(&format!("start {cri_id}")), "{calls:?}");
        assert!(calls.contains(&format!("stop {cri_id} 5s")), "{calls:?}");
    }
}
