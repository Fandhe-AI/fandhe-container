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
use fandhe_container_cri::error::CriError;
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
    /// true のとき delete は成功する（実行層の削除完了の確認用。偽なら Unimplemented で失敗する）。
    delete_ok: AtomicBool,
    /// true のとき state は running を返す（FailedPrecondition が Created 以外でも返る場合の検証用）。
    state_running: AtomicBool,
    /// true のとき create・start・state は creating を返す（作成途中の応答の検証用）。
    returns_creating: AtomicBool,
    /// true のとき start は creating を返す。
    start_returns_creating: AtomicBool,
    /// true のとき state は creating を返す。
    state_creating: AtomicBool,
    /// true の間、delete は保留する（後始末の期限の検証用）。
    hold_delete: AtomicBool,
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
        if self.0.returns_creating.load(Ordering::SeqCst) {
            return Ok(ContainerStatus::creating(r.id().clone()));
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
        if self.0.start_returns_creating.load(Ordering::SeqCst) {
            return Ok(ContainerStatus::creating(r.id().clone()));
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
    fn delete(&self, r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push(format!("delete {}", r.id().as_str()));
        while self.0.hold_delete.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        if self.0.delete_ok.load(Ordering::SeqCst) {
            return Ok(DeleteResponse::new());
        }
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        if self.0.state_creating.load(Ordering::SeqCst) {
            return Ok(ContainerStatus::creating(r.id().clone()));
        }
        if self.0.state_running.load(Ordering::SeqCst) {
            return Ok(ContainerStatus::running(r.id().clone(), None));
        }
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
}

/// フェイクの bundle 供給元。
#[derive(Default)]
struct FakeBundles {
    calls: Mutex<Vec<String>>,
    fail: AtomicBool,
    fail_release: AtomicBool,
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
    ) -> Result<PathBuf, CriError> {
        let name = config.metadata.as_ref().map(|m| m.name.as_str());
        self.calls.lock().unwrap().push(format!(
            "prepare {container_id} {sandbox_id} {}",
            name.unwrap_or("")
        ));
        if self.fail.load(Ordering::SeqCst) {
            return Err(CriError::resource_exhausted("no space"));
        }
        Ok(bundle_root().join(container_id))
    }
    fn release(&self, container_id: &str) -> Result<(), CriError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("release {container_id}"));
        if self.fail_release.load(Ordering::SeqCst) {
            return Err(CriError::internal("release failed"));
        }
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
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
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

/// bundle の解放に失敗したら記録と件数枠を保持する（資源の追跡を失わない。CRI-2・REPAIR-5）。
#[tokio::test]
async fn task_59_2_release_failure_keeps_record() {
    let h = harness();
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
    let sb = run_sandbox(&h.service).await;
    h.bundles.fail_release.store(true, Ordering::SeqCst);
    h.runtime
        .create_returns_running
        .store(true, Ordering::SeqCst);
    let err = create(&h.service, &sb, "c").await.expect_err("create");
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(list_count(&h.service).await, 1);
}

/// 実行層が created 以外を返したら INTERNAL とし、記録を巻き戻して bundle を解放する（CRI-2）。
#[tokio::test]
async fn task_59_2_unexpected_create_state_releases_bundle() {
    let h = harness();
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
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

/// REPAIR-5・fail-closed: 応答不明の失敗（Timeout・Unavailable・Internal）は CONTAINER_UNKNOWN にし（CRI-2）、再 Start させない。
#[tokio::test]
async fn task_59_2_ambiguous_start_failure_marks_unknown() {
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
            S::ContainerUnknown as i32
        );
        // 生存中かもしれないプロセスを終了済みとして公開しない(終了時刻・終了コード未設定)。
        let st = status(&h.service, &id).await;
        assert_eq!((st.finished_at, st.exit_code), (0, 0));
        // 再 Start・Stop・Remove は拒否される(停止の確認は TASK-59.3)。
        assert_eq!(
            stop_c(&h.service, &id).await.unwrap_err().code(),
            Code::FailedPrecondition
        );
        assert_eq!(
            remove(&h.service, &id).await.unwrap_err().code(),
            Code::FailedPrecondition
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

/// CRI-1・REPAIR-3: Start の実行中の StopPodSandbox は TASK-59.3(停止の接続)まで拒否し、Start は running を確定する。
#[tokio::test]
async fn task_59_3_stop_sandbox_during_start_is_rejected() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    h.runtime.hold_start.store(true, Ordering::SeqCst);
    let (first, stop) = tokio::join!(start(&h.service, &id), async {
        let r = stop_sb(&h.service, &sb).await;
        h.runtime.hold_start.store(false, Ordering::SeqCst);
        r
    });
    first.expect("start");
    assert_eq!(stop.expect_err("stop").code(), Code::FailedPrecondition);
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerRunning as i32
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

/// 停止済み（notready）のサンドボックスへの Create は実行層を呼ばず FAILED_PRECONDITION。
/// 実行層の資源を持つコンテナが無い sandbox だけが停止できる(TASK-59.3 まで)。Start 側は lib の
/// `task_59_3_start_in_notready_sandbox_never_reaches_the_runtime` が検証する。
#[tokio::test]
async fn task_59_2_notready_sandbox_never_reaches_the_runtime() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    stop_sb(&h.service, &sb).await.expect("stop empty sandbox");
    assert_eq!(
        create(&h.service, &sb, "d")
            .await
            .expect_err("create")
            .code(),
        Code::FailedPrecondition
    );
    assert_eq!(h.runtime.calls().len(), 0);
    assert_eq!(h.bundles.calls.lock().unwrap().len(), 0);
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
    // タイムアウトは結果不明のため unknown(CONTAINER_UNKNOWN)になり、再 Start は拒否される。
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
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
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

fn release_count(h: &Harness) -> usize {
    h.bundles
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c.starts_with("release "))
        .count()
}

/// REPAIR-5: 結果不明の create 失敗で削除完了を確認できなければ、記録（unknown）と bundle を保持する。
#[tokio::test]
async fn task_59_2_ambiguous_create_failure_retains_record_and_bundle() {
    for code in [
        ErrorCode::Timeout,
        ErrorCode::Unavailable,
        ErrorCode::Internal,
    ] {
        let h = harness();
        let sb = run_sandbox(&h.service).await;
        *h.runtime.fail_create.lock().unwrap() = Some(code);
        create(&h.service, &sb, "c").await.expect_err("create");
        // 削除を確認できない（delete は Unimplemented）ため、追跡情報と bundle を失わせない。
        assert_eq!(list_count(&h.service).await, 1);
        assert_eq!(release_count(&h), 0);
        assert!(h.runtime.calls().iter().any(|c| c.starts_with("delete ")));
    }
}

/// 確定失敗（実行層が処理前に拒否）は delete を試さず全解放する。
#[tokio::test]
async fn task_59_2_definite_create_failure_skips_remove_and_releases() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    *h.runtime.fail_create.lock().unwrap() = Some(ErrorCode::InvalidArgument);
    create(&h.service, &sb, "c").await.expect_err("create");
    assert_eq!(list_count(&h.service).await, 0);
    assert_eq!(release_count(&h), 1);
    assert!(!h.runtime.calls().iter().any(|c| c.starts_with("delete ")));
}

/// created 以外の応答のあと delete が失敗したら、実行層に残った資源の追跡のため記録と bundle を保持する。
#[tokio::test]
async fn task_59_2_unexpected_create_state_with_failed_remove_retains() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    h.runtime
        .create_returns_running
        .store(true, Ordering::SeqCst);
    let err = create(&h.service, &sb, "c").await.expect_err("create");
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(list_count(&h.service).await, 1);
    assert_eq!(release_count(&h), 0);
}

/// REPAIR-5: 実行層がハングして blocking pool が埋まっても、期限で DEADLINE_EXCEEDED を返す。
#[test]
fn task_59_2_timeout_does_not_depend_on_blocking_pool() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .build()
        .expect("runtime");
    rt.block_on(async {
        let h = harness();
        let service = h.service.with_runtime_timeout(Duration::from_millis(100));
        let sb = run_sandbox(&service).await;
        // blocking pool の唯一のスレッドを塞ぐ。
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let blocker = tokio::task::spawn_blocking(move || {
            while !stop2.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        h.runtime.hold_create.store(true, Ordering::SeqCst);
        let started = std::time::Instant::now();
        let err = create(&service, &sb, "c").await.expect_err("create");
        assert_eq!(err.code(), Code::DeadlineExceeded);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "must return near the deadline"
        );
        h.runtime.hold_create.store(false, Ordering::SeqCst);
        stop.store(true, Ordering::SeqCst);
        blocker.await.expect("blocker");
    });
}

/// REPAIR-5: Start の FailedPrecondition でも state が Created 以外なら結果不明として unknown にする。
#[tokio::test]
async fn task_59_2_start_precondition_failure_with_non_created_state_marks_unknown() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    *h.runtime.fail_start.lock().unwrap() = Some(ErrorCode::FailedPrecondition);
    h.runtime.state_running.store(true, Ordering::SeqCst);
    start(&h.service, &id).await.expect_err("start");
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerUnknown as i32
    );
}

/// 結果不明の create で資源が残りうるコンテナは、削除接続まで RemoveContainer / RemovePodSandbox を拒否する。
#[tokio::test]
async fn task_59_2_leaked_container_rejects_remove() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    *h.runtime.fail_create.lock().unwrap() = Some(ErrorCode::Internal);
    create(&h.service, &sb, "c").await.expect_err("create");
    assert_eq!(list_count(&h.service).await, 1);
    let id = {
        let resp = RuntimeService::list_containers(
            &h.service,
            Request::new(v1::ListContainersRequest::default()),
        )
        .await
        .expect("list")
        .into_inner();
        resp.containers[0].id.clone()
    };
    let err = remove(&h.service, &id).await.expect_err("remove");
    assert_eq!(err.code(), Code::FailedPrecondition);
    let err = RuntimeService::remove_pod_sandbox(
        &h.service,
        Request::new(v1::RemovePodSandboxRequest {
            pod_sandbox_id: sb.clone(),
        }),
    )
    .await
    .expect_err("remove sandbox");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(list_count(&h.service).await, 1);
}

/// 実行層に資源が残る成功後の記録（Create・Start 後）は、削除の接続（TASK-59.3）まで Remove を拒否して保持する。
#[tokio::test]
async fn task_59_2_connected_container_is_retained_on_remove() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    let err = remove(&h.service, &id).await.expect_err("remove created");
    assert_eq!(err.code(), Code::FailedPrecondition);
    start(&h.service, &id).await.expect("start");
    let err = remove(&h.service, &id).await.expect_err("remove running");
    assert_eq!(err.code(), Code::FailedPrecondition);
    let err = RuntimeService::remove_pod_sandbox(
        &h.service,
        Request::new(v1::RemovePodSandboxRequest {
            pod_sandbox_id: sb.clone(),
        }),
    )
    .await
    .expect_err("remove sandbox");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(list_count(&h.service).await, 1);
}

/// REPAIR-5: 後始末の delete が止まっても、期限で打ち切って in_flight を解く。
#[tokio::test]
async fn task_59_2_hung_cleanup_delete_is_bounded() {
    let h = harness();
    let service = h.service.with_runtime_timeout(Duration::from_millis(100));
    let sb = run_sandbox(&service).await;
    *h.runtime.fail_create.lock().unwrap() = Some(ErrorCode::Internal);
    h.runtime.hold_delete.store(true, Ordering::SeqCst);
    create(&service, &sb, "c").await.expect_err("create");
    // delete は止まったままでも、worker が期限で打ち切って記録を unknown にして in_flight を解く。
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let id = loop {
        let resp = RuntimeService::list_containers(
            &service,
            Request::new(v1::ListContainersRequest::default()),
        )
        .await
        .expect("list")
        .into_inner();
        if let Some(c) = resp.containers.first()
            && c.state == S::ContainerUnknown as i32
        {
            break c.id.clone();
        }
        assert!(std::time::Instant::now() < deadline, "worker must finish");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(
        status(&service, &id).await.state,
        S::ContainerUnknown as i32
    );
    h.runtime.hold_delete.store(false, Ordering::SeqCst);
}

async fn stop_c(service: &CriRuntimeService, id: &str) -> Result<(), Status> {
    RuntimeService::stop_container(
        service,
        Request::new(v1::StopContainerRequest {
            container_id: id.into(),
            timeout: 0,
        }),
    )
    .await
    .map(|_| ())
}

async fn stop_sb(service: &CriRuntimeService, id: &str) -> Result<(), Status> {
    RuntimeService::stop_pod_sandbox(
        service,
        Request::new(v1::StopPodSandboxRequest {
            pod_sandbox_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

/// CRI-1・REPAIR-3: 実行層経由のコンテナは、TASK-59.3(停止の接続)まで StopContainer を拒否する。
/// 記録は Running のまま、実行層の stop 相当(stop・delete)も呼ばれない。
#[tokio::test]
async fn task_59_3_pending_stop_container_is_rejected_with_runtime() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    start(&h.service, &id).await.expect("start");
    let err = stop_c(&h.service, &id).await.unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerRunning as i32
    );
    assert_eq!(h.runtime.calls().len(), 2);
}

/// CRI-1・REPAIR-3: Created のみ(Start 前)のコンテナでも、init が fork 済みの可能性があるため
/// StopPodSandbox を TASK-59.3 まで拒否する。
#[tokio::test]
async fn task_59_3_stop_sandbox_with_created_only_container_is_rejected() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    let err = stop_sb(&h.service, &sb).await.unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerCreated as i32
    );
}

/// CRI-1・REPAIR-3: Create 実行中(in_flight)の sandbox の停止も拒否する(停止後に create が完了する競合の防止)。
#[tokio::test]
async fn task_59_3_stop_sandbox_during_create_is_rejected() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    h.runtime.hold_create.store(true, Ordering::SeqCst);
    let (created, stop) = tokio::join!(create(&h.service, &sb, "c"), async {
        let r = stop_sb(&h.service, &sb).await;
        h.runtime.hold_create.store(false, Ordering::SeqCst);
        r
    });
    created.expect("create");
    assert_eq!(stop.unwrap_err().code(), Code::FailedPrecondition);
}

/// CRI-1・REPAIR-3: 実行層のコンテナを含む sandbox の StopPodSandbox も TASK-59.3 まで拒否する。
#[tokio::test]
async fn task_59_3_pending_stop_sandbox_is_rejected_with_runtime() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    start(&h.service, &id).await.expect("start");
    let err = stop_sb(&h.service, &sb).await.unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerRunning as i32
    );
    assert_eq!(h.runtime.calls().len(), 2);
    // 拒否後も sandbox は Ready のままで、新しいコンテナを作れる。
    create(&h.service, &sb, "d")
        .await
        .expect("sandbox still ready");
}

/// CRI-1: 実行層未接続の経路は従来どおり記録上の停止が成功する。
#[tokio::test]
async fn task_59_3_without_runtime_stop_still_succeeds() {
    let service = CriRuntimeService::new();
    let sb = run_sandbox(&service).await;
    let id = create(&service, &sb, "c").await.expect("create");
    start(&service, &id).await.expect("start");
    stop_c(&service, &id).await.expect("stop container");
    assert_eq!(status(&service, &id).await.state, S::ContainerExited as i32);
    stop_sb(&service, &sb).await.expect("stop sandbox");
}

/// CRI-2・REPAIR-5: create が creating を返しても作成完了とは見なさない。CreateContainer は INTERNAL で
/// 失敗し、Start は実行層へ届かない（資源は削除を確認して解放する）。
#[tokio::test]
async fn cri_2_repair_5_create_returning_creating_is_not_complete() {
    let h = harness();
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
    h.runtime.returns_creating.store(true, Ordering::SeqCst);
    let sb = run_sandbox(&h.service).await;
    let err = create(&h.service, &sb, "c").await.expect_err("create");
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(list_count(&h.service).await, 0);
    assert!(h.runtime.calls().iter().all(|c| !c.starts_with("start ")));
}

/// CRI-2・REPAIR-5: start 失敗後の状態照会が creating でも「created のまま」と確定せず、unknown にする。
#[tokio::test]
async fn cri_2_repair_5_start_failure_with_creating_state_is_not_definite() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    *h.runtime.fail_start.lock().unwrap() = Some(ErrorCode::FailedPrecondition);
    h.runtime.state_creating.store(true, Ordering::SeqCst);
    start(&h.service, &id).await.expect_err("start");
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerUnknown as i32
    );
}

/// CRI-2・REPAIR-5: start が creating を返しても created へ戻さず unknown にする。
#[tokio::test]
async fn cri_2_repair_5_start_returning_creating_marks_unknown() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    h.runtime
        .start_returns_creating
        .store(true, Ordering::SeqCst);
    assert_eq!(
        start(&h.service, &id).await.expect_err("start").code(),
        Code::Internal
    );
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerUnknown as i32
    );
}

/// CRI-2・REPAIR-5: Create の結果不明(Timeout)も CONTAINER_UNKNOWN で保持し、exit_code・finished_at を設定せず、
/// Start・Stop・Remove を拒否する。
#[tokio::test]
async fn cri_2_repair_5_ambiguous_create_is_unknown_and_rejects_operations() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    *h.runtime.fail_create.lock().unwrap() = Some(ErrorCode::Timeout);
    create(&h.service, &sb, "c").await.expect_err("create");
    let resp = RuntimeService::list_containers(
        &h.service,
        Request::new(v1::ListContainersRequest::default()),
    )
    .await
    .expect("list")
    .into_inner();
    let id = resp.containers[0].id.clone();
    let st = status(&h.service, &id).await;
    assert_eq!(st.state, S::ContainerUnknown as i32);
    assert_eq!((st.finished_at, st.exit_code), (0, 0));
    for r in [
        start(&h.service, &id).await,
        stop_c(&h.service, &id).await,
        remove(&h.service, &id).await,
    ] {
        assert_eq!(r.unwrap_err().code(), Code::FailedPrecondition);
    }
}
