//! `CriRuntimeService` の `CreateContainer`・`StartContainer`・`StopContainer`・`RemoveContainer` を
//! 公開 API だけで検証する結合試験（TASK-58.1・58.2・58.3・#433・#434・#435・CRI-1・ERR-3・REPAIR-4）。
//!
//! plugin-cri（TASK-108）と同じ外部利用者の立場で、生成された `RuntimeService` トレイト経由で呼ぶ。
//! 状態は `ContainerStatus`・`ListContainers`（TASK-58.3・#435）で直接照合する。

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use fandhe_container_cri::instrument::{CriOpRecorder, CriOpSample, code_name};
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use tonic::{Code, Request, Status};

/// テスト用の最小 executor（tokio 非依存）。
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("future must complete without waiting"),
    }
}

#[derive(Default)]
struct Collect(Mutex<Vec<CriOpSample>>);

impl CriOpRecorder for Collect {
    fn record_cri_op(&self, sample: &CriOpSample) {
        if let Ok(mut samples) = self.0.lock() {
            samples.push(*sample);
        }
    }
}

impl Collect {
    fn lines(&self) -> Vec<(&'static str, &'static str, &'static str)> {
        self.0
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default()
            .iter()
            .map(|s| (s.kind().as_str(), s.outcome().as_str(), code_name(s.code())))
            .collect()
    }
}

fn run_sandbox(service: &CriRuntimeService) -> String {
    let config = PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "pod".into(),
            uid: "uid-1".into(),
            namespace: "ns".into(),
            attempt: 0,
        }),
        ..Default::default()
    };
    block_on(RuntimeService::run_pod_sandbox(
        service,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(config),
            runtime_handler: String::new(),
        }),
    ))
    .expect("run sandbox")
    .into_inner()
    .pod_sandbox_id
}

fn container(name: &str) -> ContainerConfig {
    ContainerConfig {
        metadata: Some(ContainerMetadata {
            name: name.into(),
            attempt: 0,
        }),
        image: Some(ImageSpec {
            image: "busybox:1.36".into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn create(
    service: &CriRuntimeService,
    sandbox_id: &str,
    config: Option<ContainerConfig>,
) -> Result<String, Status> {
    block_on(RuntimeService::create_container(
        service,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox_id.into(),
            config,
            sandbox_config: None,
        }),
    ))
    .map(|r| r.into_inner().container_id)
}

fn start(service: &CriRuntimeService, id: &str) -> Result<(), Status> {
    block_on(RuntimeService::start_container(
        service,
        Request::new(v1::StartContainerRequest {
            container_id: id.into(),
        }),
    ))
    .map(|_| ())
}

/// CRI-1・TASK-58.1: `RunPodSandbox` → `CreateContainer` → `StartContainer` の中核フローが成功する。
#[test]
fn task_58_1_core_flow_succeeds() {
    let service = CriRuntimeService::new();
    let sandbox = run_sandbox(&service);
    let id = create(&service, &sandbox, Some(container("c"))).expect("create");
    assert_eq!(id.len(), 64);
    assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    start(&service, &id).expect("start");
    // running へ遷移済みのため、2 回目の Start は前提違反になる（間接的な状態確認）。
    assert_eq!(
        start(&service, &id).expect_err("already running").code(),
        Code::FailedPrecondition
    );
}

/// ERR-3・TASK-58.1: 同一 sandbox の同一 (name, attempt) は ALREADY_EXISTS、未知 sandbox は NOT_FOUND、
/// 必須欠落は INVALID_ARGUMENT、未知コンテナの Start は NOT_FOUND。
#[test]
fn task_58_1_error_code_mapping() {
    let service = CriRuntimeService::new();
    let sandbox = run_sandbox(&service);
    create(&service, &sandbox, Some(container("c"))).expect("first create");
    assert_eq!(
        create(&service, &sandbox, Some(container("c")))
            .expect_err("duplicate")
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        create(&service, &"0".repeat(64), Some(container("c")))
            .expect_err("unknown sandbox")
            .code(),
        Code::NotFound
    );
    assert_eq!(
        create(&service, &sandbox, None)
            .expect_err("missing config")
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        start(&service, &"0".repeat(64))
            .expect_err("unknown container")
            .code(),
        Code::NotFound
    );
    assert_eq!(
        start(&service, "").expect_err("empty id").code(),
        Code::InvalidArgument
    );
}

/// REPAIR-4・TASK-58.1: 操作名・結果・コード名が記録先へ渡る。
#[test]
fn task_58_1_operations_are_recorded() {
    let collect = Arc::new(Collect::default());
    let service = CriRuntimeService::with_recorder(collect.clone());
    let sandbox = run_sandbox(&service);
    let id = create(&service, &sandbox, Some(container("c"))).expect("create");
    create(&service, &sandbox, Some(container("c"))).expect_err("duplicate");
    start(&service, &id).expect("start");
    start(&service, &id).expect_err("second start");
    assert_eq!(
        collect.lines()[1..],
        [
            ("cri.create_container", "success", "OK"),
            ("cri.create_container", "failure", "ALREADY_EXISTS"),
            ("cri.start_container", "success", "OK"),
            ("cri.start_container", "failure", "FAILED_PRECONDITION"),
        ]
    );
}
fn stop(service: &CriRuntimeService, id: &str, timeout: i64) -> Result<(), Status> {
    block_on(RuntimeService::stop_container(
        service,
        Request::new(v1::StopContainerRequest {
            container_id: id.into(),
            timeout,
        }),
    ))
    .map(|_| ())
}

fn remove(service: &CriRuntimeService, id: &str) -> Result<(), Status> {
    block_on(RuntimeService::remove_container(
        service,
        Request::new(v1::RemoveContainerRequest {
            container_id: id.into(),
        }),
    ))
    .map(|_| ())
}

/// CRI-1・TASK-58.2: `run → create → start → stop → remove` の中核フロー。Stop 後の Start は前提違反、
/// Remove 後の Stop・Start は NOT_FOUND、Remove の再実行は冪等に成功する。
#[test]
fn task_58_2_stop_remove_core_flow() {
    let service = CriRuntimeService::new();
    let sandbox = run_sandbox(&service);
    let id = create(&service, &sandbox, Some(container("c"))).expect("create");
    start(&service, &id).expect("start");
    stop(&service, &id, 10).expect("stop");
    stop(&service, &id, 0).expect("stop is idempotent");
    assert_eq!(
        start(&service, &id).expect_err("start after stop").code(),
        Code::FailedPrecondition
    );
    remove(&service, &id).expect("remove");
    remove(&service, &id).expect("remove is idempotent");
    assert_eq!(
        stop(&service, &id, 0).expect_err("stop removed").code(),
        Code::NotFound
    );
    assert_eq!(
        start(&service, &id).expect_err("start removed").code(),
        Code::NotFound
    );
    // 除去後は同じ (name, attempt) を再作成できる。
    create(&service, &sandbox, Some(container("c"))).expect("recreate");
}

/// ERR-3・TASK-58.2: エラーコードの対応（空 ID・負の timeout は INVALID_ARGUMENT、未知 ID の Stop は
/// NOT_FOUND・Remove は成功、created の Stop は成功）。
#[test]
fn task_58_2_error_code_mapping() {
    let service = CriRuntimeService::new();
    let sandbox = run_sandbox(&service);
    let id = create(&service, &sandbox, Some(container("c"))).expect("create");
    assert_eq!(
        stop(&service, "", 0).expect_err("empty id").code(),
        Code::InvalidArgument
    );
    assert_eq!(
        stop(&service, &id, -1).expect_err("negative").code(),
        Code::InvalidArgument
    );
    assert_eq!(
        stop(&service, &"0".repeat(64), 0)
            .expect_err("unknown")
            .code(),
        Code::NotFound
    );
    stop(&service, &id, 0).expect("created stop is ok");
    assert_eq!(
        remove(&service, "").expect_err("empty id").code(),
        Code::InvalidArgument
    );
    remove(&service, &"0".repeat(64)).expect("unknown remove is ok");
}

/// REPAIR-4・TASK-58.2: Stop・Remove の操作名・結果・コード名が記録先へ渡る。
#[test]
fn task_58_2_operations_are_recorded() {
    let collect = Arc::new(Collect::default());
    let service = CriRuntimeService::with_recorder(collect.clone());
    let sandbox = run_sandbox(&service);
    let id = create(&service, &sandbox, Some(container("c"))).expect("create");
    stop(&service, &id, 0).expect("created");
    start(&service, &id).expect("start");
    stop(&service, &id, 0).expect("stop");
    remove(&service, &id).expect("remove");
    remove(&service, "").expect_err("empty");
    assert_eq!(
        collect.lines()[2..],
        [
            ("cri.stop_container", "success", "OK"),
            ("cri.start_container", "success", "OK"),
            ("cri.stop_container", "success", "OK"),
            ("cri.remove_container", "success", "OK"),
            ("cri.remove_container", "failure", "INVALID_ARGUMENT"),
        ]
    );
}

fn list(service: &CriRuntimeService) -> Vec<v1::Container> {
    block_on(RuntimeService::list_containers(
        service,
        Request::new(v1::ListContainersRequest::default()),
    ))
    .expect("list")
    .into_inner()
    .containers
}

fn status(service: &CriRuntimeService, id: &str) -> Result<v1::ContainerStatus, Status> {
    block_on(RuntimeService::container_status(
        service,
        Request::new(v1::ContainerStatusRequest {
            container_id: id.into(),
            verbose: false,
        }),
    ))
    .map(|r| r.into_inner().status.expect("status"))
}

/// CRI-1・TASK-58.3: Create → List → Start → Status → Stop → Status → Remove → List の流れで、
/// 一覧と状態が各操作と整合し、結果が REPAIR-4 の計測に残る。
#[test]
fn task_58_3_list_and_status_follow_lifecycle() {
    let collect = Arc::new(Collect::default());
    let service = CriRuntimeService::with_recorder(collect.clone());
    let sandbox = run_sandbox(&service);
    let id = create(&service, &sandbox, Some(container("c"))).expect("create");
    let listed = list(&service);
    assert_eq!(listed.len(), 1);
    assert_eq!((listed[0].id.as_str(), listed[0].state), (id.as_str(), 0));
    assert_eq!(status(&service, &id).expect("status").state, 0);
    start(&service, &id).expect("start");
    assert_eq!(status(&service, &id).expect("status").state, 1);
    assert_eq!(list(&service)[0].state, 1);
    block_on(RuntimeService::stop_container(
        &service,
        Request::new(v1::StopContainerRequest {
            container_id: id.clone(),
            timeout: 0,
        }),
    ))
    .expect("stop");
    assert_eq!(status(&service, &id).expect("status").state, 2);
    block_on(RuntimeService::remove_container(
        &service,
        Request::new(v1::RemoveContainerRequest {
            container_id: id.clone(),
        }),
    ))
    .expect("remove");
    assert!(list(&service).is_empty());
    assert_eq!(
        status(&service, &id).expect_err("removed").code(),
        Code::NotFound
    );
    let lines = collect.lines();
    assert!(lines.contains(&("cri.list_containers", "success", "OK")));
    assert!(lines.contains(&("cri.container_status", "failure", "NOT_FOUND")));
}
