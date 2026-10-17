//! `CreateContainer`・`StartContainer` を `ContainerRuntime` アダプタへ接続した経路の結合試験
//! （TASK-59.2・#438・CRI-2・CRI-7・ERR-3・REPAIR-4）。
//!
//! フェイクの `ContainerRuntime` と `BundleProvider` を `CriRuntimeService::with_runtime` へ注入し、
//! plugin-cri（TASK-108）と同じ立場で生成された `RuntimeService` トレイト経由で呼ぶ。実際の namespace
//! 分離プロセスの確認は実機前提の `runtime_service_namespaces.rs`（`#[ignore]`）で行う。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, ErrorCode,
    KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{BundleProvider, RuntimeAdapter};
use fandhe_container_cri::instrument::{CriOpRecorder, CriOpSample, code_name};
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ContainerState as S, ImageSpec, PodSandboxConfig,
    PodSandboxMetadata, runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use tonic::{Code, Request, Status};

/// フェイクの実行層。呼び出しを記録し、失敗・返す状態・start の保留を注入できる。
#[derive(Default)]
struct FakeRuntime {
    calls: Mutex<Vec<String>>,
    fail_create: Mutex<Option<ErrorCode>>,
    fail_start: Mutex<Option<ErrorCode>>,
    /// true のとき start は created を返す（running でない応答の検証用）。
    start_returns_created: AtomicBool,
    /// true のとき create は running を返す（created 以外の応答の検証用）。
    create_returns_running: AtomicBool,
    /// true の間、start は保留する（並行 Start の検証用）。
    hold_start: AtomicBool,
    /// true の間、create は保留する（期限超過・中断の検証用）。
    hold_create: AtomicBool,
    /// true のとき start は stopped を返す（終了済みの応答の検証用）。
    start_returns_stopped: AtomicBool,
}

impl FakeRuntime {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

struct Shared(Arc<FakeRuntime>);

impl ContainerRuntime for Shared {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        self.0.calls.lock().unwrap().push(format!(
            "create {} {}",
            r.id().as_str(),
            r.bundle().display()
        ));
        while self.0.hold_create.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        if let Some(c) = *self.0.fail_create.lock().unwrap() {
            return Err(TraitError::new(c, "create failed"));
        }
        if self.0.create_returns_running.load(Ordering::SeqCst) {
            return Ok(ContainerStatus::running(r.id().clone(), None));
        }
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
    fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push(format!("start {}", r.id().as_str()));
        while self.0.hold_start.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        if let Some(c) = *self.0.fail_start.lock().unwrap() {
            return Err(TraitError::new(c, "start failed"));
        }
        if self.0.start_returns_stopped.load(Ordering::SeqCst) {
            return Ok(ContainerStatus::stopped(r.id().clone(), Some(0)));
        }
        if self.0.start_returns_created.load(Ordering::SeqCst) {
            return Ok(ContainerStatus::created(r.id().clone(), None));
        }
        Ok(ContainerStatus::running(
            r.id().clone(),
            std::num::NonZeroU32::new(4242),
        ))
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn delete(&self, _: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn state(&self, _: &StateRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
}

/// フェイクの bundle 供給元。
#[derive(Default)]
struct FakeBundles {
    calls: Mutex<Vec<String>>,
    fail: AtomicBool,
}

fn bundle_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\bundles")
    } else {
        PathBuf::from("/bundles")
    }
}

impl BundleProvider for FakeBundles {
    fn prepare(
        &self,
        container_id: &str,
        sandbox_id: &str,
        config: &ContainerConfig,
    ) -> Result<PathBuf, Status> {
        let name = config.metadata.as_ref().map(|m| m.name.as_str());
        self.calls.lock().unwrap().push(format!(
            "prepare {container_id} {sandbox_id} {}",
            name.unwrap_or("")
        ));
        if self.fail.load(Ordering::SeqCst) {
            return Err(Status::resource_exhausted("no space"));
        }
        Ok(bundle_root().join(container_id))
    }
    fn release(&self, container_id: &str) {
        self.calls
            .lock()
            .unwrap()
            .push(format!("release {container_id}"));
    }
}

#[derive(Default)]
struct Collect(Mutex<Vec<CriOpSample>>);

impl CriOpRecorder for Collect {
    fn record_cri_op(&self, sample: &CriOpSample) {
        self.0.lock().unwrap().push(*sample);
    }
}

struct Harness {
    service: CriRuntimeService,
    runtime: Arc<FakeRuntime>,
    bundles: Arc<FakeBundles>,
    recorder: Arc<Collect>,
}

fn harness() -> Harness {
    let runtime = Arc::new(FakeRuntime::default());
    let bundles = Arc::new(FakeBundles::default());
    let recorder = Arc::new(Collect::default());
    let service = CriRuntimeService::with_recorder(recorder.clone()).with_runtime(
        RuntimeAdapter::new(Arc::new(Shared(runtime.clone()))),
        bundles.clone(),
    );
    Harness {
        service,
        runtime,
        bundles,
        recorder,
    }
}

async fn run_sandbox(service: &CriRuntimeService) -> String {
    let config = PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "pod".into(),
            uid: "uid-1".into(),
            namespace: "ns".into(),
            attempt: 0,
        }),
        ..Default::default()
    };
    RuntimeService::run_pod_sandbox(
        service,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(config),
            runtime_handler: String::new(),
        }),
    )
    .await
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

async fn create(service: &CriRuntimeService, sandbox: &str, name: &str) -> Result<String, Status> {
    RuntimeService::create_container(
        service,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox.into(),
            config: Some(container(name)),
            sandbox_config: None,
        }),
    )
    .await
    .map(|r| r.into_inner().container_id)
}

async fn start(service: &CriRuntimeService, id: &str) -> Result<(), Status> {
    RuntimeService::start_container(
        service,
        Request::new(v1::StartContainerRequest {
            container_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

async fn status(service: &CriRuntimeService, id: &str) -> v1::ContainerStatus {
    RuntimeService::container_status(
        service,
        Request::new(v1::ContainerStatusRequest {
            container_id: id.into(),
            verbose: false,
        }),
    )
    .await
    .expect("status")
    .into_inner()
    .status
    .expect("status body")
}

async fn remove(service: &CriRuntimeService, id: &str) -> Result<(), Status> {
    RuntimeService::remove_container(
        service,
        Request::new(v1::RemoveContainerRequest {
            container_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

async fn list_count(service: &CriRuntimeService) -> usize {
    RuntimeService::list_containers(
        service,
        Request::new(v1::ListContainersRequest { filter: None }),
    )
    .await
    .expect("list")
    .into_inner()
    .containers
    .len()
}

/// CRI-2: Create は bundle を用意して `ContainerRuntime::create` を呼び、Start は `start` を呼んで running にする。
#[tokio::test]
async fn task_59_2_create_and_start_reach_the_runtime() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    assert_eq!(id.len(), 64);
    let bundle = bundle_root().join(&id);
    assert_eq!(
        h.bundles.calls.lock().unwrap().clone(),
        vec![format!("prepare {id} {sb} c")]
    );
    assert_eq!(
        h.runtime.calls(),
        vec![format!("create {id} {}", bundle.display())]
    );
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerCreated as i32
    );

    start(&h.service, &id).await.expect("start");
    assert_eq!(h.runtime.calls().last().unwrap(), &format!("start {id}"));
    let st = status(&h.service, &id).await;
    assert_eq!(st.state, S::ContainerRunning as i32);
    assert!(st.started_at > 0);
}

/// ERR-3: create 失敗は実行層のコードへ写され、記録・重複キー・件数を巻き戻して再作成できる。
#[tokio::test]
async fn task_59_2_create_failure_is_rolled_back() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    for (code, expect) in [
        (ErrorCode::AlreadyExists, Code::AlreadyExists),
        (ErrorCode::Timeout, Code::DeadlineExceeded),
        (ErrorCode::Unavailable, Code::Unavailable),
    ] {
        *h.runtime.fail_create.lock().unwrap() = Some(code);
        let err = create(&h.service, &sb, "c").await.expect_err("create");
        assert_eq!(err.code(), expect);
        assert_eq!(list_count(&h.service).await, 0);
    }
    // 失敗のたびに bundle を解放している。
    let releases = h
        .bundles
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c.starts_with("release "))
        .count();
    assert_eq!(releases, 3);
    // 同じ (name, attempt) で再作成できる。
    *h.runtime.fail_create.lock().unwrap() = None;
    create(&h.service, &sb, "c").await.expect("retry");
    assert_eq!(list_count(&h.service).await, 1);
}

/// ERR-3: bundle の用意に失敗したら実行層を呼ばず、記録を巻き戻す。
#[tokio::test]
async fn task_59_2_bundle_failure_skips_the_runtime() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    h.bundles.fail.store(true, Ordering::SeqCst);
    let err = create(&h.service, &sb, "c").await.expect_err("create");
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert!(h.runtime.calls().is_empty());
    assert_eq!(list_count(&h.service).await, 0);
}

/// ERR-3・fail-closed: start 失敗は created のまま残り、再試行できる（記録上だけ running にしない）。
#[tokio::test]
async fn task_59_2_start_failure_keeps_created() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    *h.runtime.fail_start.lock().unwrap() = Some(ErrorCode::FailedPrecondition);
    let err = start(&h.service, &id).await.expect_err("start");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerCreated as i32
    );
    *h.runtime.fail_start.lock().unwrap() = None;
    start(&h.service, &id).await.expect("retry");
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerRunning as i32
    );
}

/// 実行層が created 以外を返したら INTERNAL とし、記録を巻き戻して bundle を解放する（CRI-2）。
#[tokio::test]
async fn task_59_2_unexpected_create_state_releases_bundle() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    h.runtime
        .create_returns_running
        .store(true, Ordering::SeqCst);
    let err = create(&h.service, &sb, "c").await.expect_err("create");
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(list_count(&h.service).await, 0);
    let releases = h
        .bundles
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c.starts_with("release "))
        .count();
    assert_eq!(releases, 1);
}

/// 実行層が running 以外を返したら INTERNAL とし、created のまま残す。
#[tokio::test]
async fn task_59_2_unexpected_runtime_state_is_internal() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    h.runtime
        .start_returns_created
        .store(true, Ordering::SeqCst);
    let err = start(&h.service, &id).await.expect_err("start");
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerCreated as i32
    );
}

/// REPAIR-5・fail-closed: 応答不明の失敗（Timeout・Unavailable・Internal）は exited にし、再 Start させない。
#[tokio::test]
async fn task_59_2_ambiguous_start_failure_marks_exited() {
    for code in [
        ErrorCode::Timeout,
        ErrorCode::Unavailable,
        ErrorCode::Internal,
    ] {
        let h = harness();
        let sb = run_sandbox(&h.service).await;
        let id = create(&h.service, &sb, "c").await.expect("create");
        *h.runtime.fail_start.lock().unwrap() = Some(code);
        start(&h.service, &id).await.expect_err("start");
        assert_eq!(
            status(&h.service, &id).await.state,
            S::ContainerExited as i32
        );
        *h.runtime.fail_start.lock().unwrap() = None;
        let err = start(&h.service, &id).await.expect_err("restart");
        assert_eq!(err.code(), Code::FailedPrecondition);
        let starts = h
            .runtime
            .calls()
            .iter()
            .filter(|c| c.starts_with("start "))
            .count();
        assert_eq!(starts, 1);
    }
}

/// Start の実行中に StopPodSandbox が入っても、停止済みサンドボックス配下で running を確定しない。
#[tokio::test]
async fn task_59_2_stop_sandbox_during_start_does_not_commit_running() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    h.runtime.hold_start.store(true, Ordering::SeqCst);
    let (first, ()) = tokio::join!(start(&h.service, &id), async {
        RuntimeService::stop_pod_sandbox(
            &h.service,
            Request::new(v1::StopPodSandboxRequest {
                pod_sandbox_id: sb.clone(),
            }),
        )
        .await
        .expect("stop sandbox");
        h.runtime.hold_start.store(false, Ordering::SeqCst);
    });
    assert_eq!(first.expect_err("start").code(), Code::FailedPrecondition);
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerExited as i32
    );
}

/// 並行する Start は一方だけが実行層へ到達し、他方は FAILED_PRECONDITION。実行中の Remove も拒否する。
#[tokio::test]
async fn task_59_2_concurrent_start_reaches_runtime_once() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    h.runtime.hold_start.store(true, Ordering::SeqCst);
    let (first, (second, removal)) = tokio::join!(start(&h.service, &id), async {
        let second = start(&h.service, &id).await;
        let removal = remove(&h.service, &id).await;
        h.runtime.hold_start.store(false, Ordering::SeqCst);
        (second, removal)
    });
    first.expect("first start");
    assert_eq!(second.expect_err("second").code(), Code::FailedPrecondition);
    assert_eq!(
        removal.expect_err("remove").code(),
        Code::FailedPrecondition
    );
    let starts = h
        .runtime
        .calls()
        .iter()
        .filter(|c| c.starts_with("start "))
        .count();
    assert_eq!(starts, 1);
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerRunning as i32
    );
}

/// 停止済み（notready）のサンドボックスへの Create・Start は実行層を呼ばず FAILED_PRECONDITION。
#[tokio::test]
async fn task_59_2_notready_sandbox_never_reaches_the_runtime() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    RuntimeService::stop_pod_sandbox(
        &h.service,
        Request::new(v1::StopPodSandboxRequest {
            pod_sandbox_id: sb.clone(),
        }),
    )
    .await
    .expect("stop sandbox");
    let before = h.runtime.calls().len();
    assert_eq!(
        create(&h.service, &sb, "d")
            .await
            .expect_err("create")
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        start(&h.service, &id).await.expect_err("start").code(),
        Code::FailedPrecondition
    );
    assert_eq!(h.runtime.calls().len(), before);
}

/// REPAIR-4: 実行層経由でも全経路で 1 件ずつ記録し、コード名は期待どおり。
#[tokio::test]
async fn task_59_2_outcomes_are_recorded() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    *h.runtime.fail_start.lock().unwrap() = Some(ErrorCode::Timeout);
    let _ = start(&h.service, &id).await;
    *h.runtime.fail_start.lock().unwrap() = None;
    let _ = start(&h.service, &id).await;
    let lines: Vec<_> = h
        .recorder
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|s| (s.kind().as_str(), code_name(s.code())))
        .filter(|(k, _)| k.contains("container"))
        .collect();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(lines[0].1, "OK");
    assert_eq!(lines[1].1, "DEADLINE_EXCEEDED");
    // タイムアウトは結果不明のため exited になり、再 Start は拒否される。
    assert_eq!(lines[2].1, "FAILED_PRECONDITION");
}

/// 未注入の `CriRuntimeService::new()` は従来どおりスタブ動作で、実行層を持たない。
#[tokio::test]
async fn task_59_2_without_runtime_keeps_stub_behavior() {
    let service = CriRuntimeService::new();
    let sb = run_sandbox(&service).await;
    let id = create(&service, &sb, "c").await.expect("create");
    start(&service, &id).await.expect("start");
    assert_eq!(
        status(&service, &id).await.state,
        S::ContainerRunning as i32
    );
}

/// 実行層が stopped を返したら created へ戻さず exited にし、再 Start を実行層へ届けない（P1 指摘）。
#[tokio::test]
async fn task_59_2_stopped_start_response_marks_exited() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    h.runtime
        .start_returns_stopped
        .store(true, Ordering::SeqCst);
    start(&h.service, &id).await.expect_err("start");
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerExited as i32
    );
    h.runtime
        .start_returns_stopped
        .store(false, Ordering::SeqCst);
    let err = start(&h.service, &id).await.expect_err("restart");
    assert_eq!(err.code(), Code::FailedPrecondition);
    let starts = h
        .runtime
        .calls()
        .iter()
        .filter(|c| c.starts_with("start "))
        .count();
    assert_eq!(starts, 1);
}

/// 実行層の応答が期限を超えたら DEADLINE_EXCEEDED。worker は最後まで走って記録を確定する（REPAIR-5）。
#[tokio::test]
async fn task_59_2_start_timeout_is_bounded_and_worker_finalizes() {
    let h = harness();
    let service = h.service.with_runtime_timeout(Duration::from_millis(50));
    let sb = run_sandbox(&service).await;
    let id = create(&service, &sb, "c").await.expect("create");
    h.runtime.hold_start.store(true, Ordering::SeqCst);
    let err = start(&service, &id).await.expect_err("start");
    assert_eq!(err.code(), Code::DeadlineExceeded);
    // worker が終わるまでは in_flight のまま（再 Start・Remove は拒否される）。
    assert_eq!(
        start(&service, &id).await.expect_err("restart").code(),
        Code::FailedPrecondition
    );
    h.runtime.hold_start.store(false, Ordering::SeqCst);
    for _ in 0..500 {
        if status(&service, &id).await.state == S::ContainerRunning as i32 {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("worker did not finalize the record");
}

/// Create が期限超過しても、実行層の処理中は bundle を解放せず、worker の完了後に巻き戻す。
#[tokio::test]
async fn task_59_2_create_timeout_defers_release_until_worker_finishes() {
    let h = harness();
    let service = h.service.with_runtime_timeout(Duration::from_millis(50));
    let sb = run_sandbox(&service).await;
    h.runtime.hold_create.store(true, Ordering::SeqCst);
    h.runtime
        .fail_create
        .lock()
        .unwrap()
        .replace(ErrorCode::Internal);
    let err = create(&service, &sb, "c").await.expect_err("create");
    assert_eq!(err.code(), Code::DeadlineExceeded);
    assert!(
        !h.bundles
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.starts_with("release ")),
        "release must wait for the worker"
    );
    h.runtime.hold_create.store(false, Ordering::SeqCst);
    for _ in 0..500 {
        let released = h
            .bundles
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.starts_with("release "));
        if released && list_count(&service).await == 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("worker did not roll back");
}
