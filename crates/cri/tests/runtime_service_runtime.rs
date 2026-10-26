//! `CreateContainer`・`StartContainer` を `ContainerRuntime` アダプタへ接続した経路の結合試験
//! （TASK-59.2・#438・CRI-2・CRI-7・ERR-3・REPAIR-4）。
//!
//! フェイクの `ContainerRuntime` と `BundleProvider` を `CriRuntimeService::with_runtime` へ注入し、
//! plugin-cri（TASK-108）と同じ立場で生成された `RuntimeService` トレイト経由で呼ぶ。実際の namespace
//! 分離プロセスの確認は実機前提の `runtime_service_namespaces.rs`（`#[ignore]`）で行う。

use fandhe_container_oci::reference::Digest;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, ErrorCode,
    KillRequest, StartRequest, StateRequest, StopRequest, TerminationReason, TraitError,
};
use fandhe_container_cri::adapter::{
    BundleProvider, BundleRequest, PreparedBundle, RuntimeAdapter,
};
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
    /// stop が受けたシグナル番号（CRI-2・#2668）。
    stop_signals: Mutex<Vec<u8>>,
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
    /// 設定されていれば delete はそのコードで失敗する（NOT_FOUND は実行層に既にコンテナが無い場合。TASK-59.3）。
    fail_delete: Mutex<Option<ErrorCode>>,
    /// 設定されていれば stop はそのコードで失敗する（TASK-59.3）。
    fail_stop: Mutex<Option<ErrorCode>>,
    /// true の間、stop は保留する（並行操作・期限の検証用）。
    hold_stop: AtomicBool,
    /// true のとき stop は running を返す（想定外の応答の検証用）。
    stop_returns_running: AtomicBool,
    /// stop が返す終了コード（既定 0。137 等の検証用）。
    stop_exit_code: std::sync::atomic::AtomicI32,
    /// start が stopped を返すときの終了コード（既定 0。CRI-2・REPAIR-3 の検証用）。
    start_exit_code: std::sync::atomic::AtomicI32,
    /// true のとき stop が OOM の停止を報告する（CRI-2・CORE-4 の検証用）。
    stop_oom_killed: AtomicBool,
    /// true のとき start の stopped 応答が OOM の停止を報告する（同上）。
    start_oom_killed: AtomicBool,
    /// start が受けた `StartRequest::log_path()`（CRI-2・SUP-4・#2671 の検証用）。
    start_log_paths: Mutex<Vec<Option<String>>>,
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
        self.0
            .start_log_paths
            .lock()
            .unwrap()
            .push(r.log_path().map(|p| p.as_str().to_owned()));
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
            let code = Some(self.0.start_exit_code.load(Ordering::SeqCst));
            if self.0.start_oom_killed.load(Ordering::SeqCst) {
                return Ok(ContainerStatus::stopped_with_reason(
                    r.id().clone(),
                    code,
                    TerminationReason::OomKilled,
                ));
            }
            return Ok(ContainerStatus::stopped(r.id().clone(), code));
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
    fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
        self.0.stop_signals.lock().unwrap().push(r.signal().as_u8());
        self.0.calls.lock().unwrap().push(format!(
            "stop {} {}s",
            r.id().as_str(),
            r.grace().as_secs()
        ));
        while self.0.hold_stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        if let Some(c) = *self.0.fail_stop.lock().unwrap() {
            return Err(TraitError::new(c, "stop failed"));
        }
        if self.0.stop_returns_running.load(Ordering::SeqCst) {
            return Ok(ContainerStatus::running(r.id().clone(), None));
        }
        let code = Some(self.0.stop_exit_code.load(Ordering::SeqCst));
        if self.0.stop_oom_killed.load(Ordering::SeqCst) {
            return Ok(ContainerStatus::stopped_with_reason(
                r.id().clone(),
                code,
                TerminationReason::OomKilled,
            ));
        }
        Ok(ContainerStatus::stopped(r.id().clone(), code))
    }
    fn delete(&self, r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        self.0.calls.lock().unwrap().push(format!(
            "delete {} force={}",
            r.id().as_str(),
            r.force()
        ));
        while self.0.hold_delete.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        if let Some(c) = *self.0.fail_delete.lock().unwrap() {
            return Err(TraitError::new(c, "delete failed"));
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
    /// prepare に渡った sandbox_config の hostname（登録記録の複製が渡ることの検証用。#2395）。
    sandbox_hostnames: Mutex<Vec<String>>,
    fail: AtomicBool,
    fail_release: AtomicBool,
    /// 設定されていれば prepare が報告する識別情報（#2771）。
    report_user: Mutex<Option<fandhe_container_cri::bundle::AppliedUser>>,
    /// 設定されていれば prepare が報告する解決済みの stop signal（#2771）。
    report_stop_signal: Mutex<Option<v1::Signal>>,
    /// 設定されていれば prepare が報告する解決済みイメージ（#2831）。
    report_image: Mutex<Option<fandhe_container_cri::bundle::ResolvedImage>>,
}

fn bundle_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\bundles")
    } else {
        PathBuf::from("/bundles")
    }
}

impl BundleProvider for FakeBundles {
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
        let (container_id, sandbox_id, config) = (req.container_id, req.sandbox_id, req.config);
        let name = config.metadata.as_ref().map(|m| m.name.as_str());
        self.sandbox_hostnames
            .lock()
            .unwrap()
            .push(req.sandbox_config.hostname.clone());
        self.calls.lock().unwrap().push(format!(
            "prepare {container_id} {sandbox_id} {}",
            name.unwrap_or("")
        ));
        if self.fail.load(Ordering::SeqCst) {
            return Err(CriError::resource_exhausted("no space"));
        }
        let mut prepared = PreparedBundle::new(bundle_root().join(container_id));
        if let Some(u) = self.report_user.lock().unwrap().clone() {
            prepared = prepared.with_user(u);
        }
        if let Some(sig) = *self.report_stop_signal.lock().unwrap() {
            prepared = prepared.with_stop_signal(sig);
        }
        if let Some(i) = self.report_image.lock().unwrap().clone() {
            prepared = prepared.with_image(i);
        }
        Ok(prepared)
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

async fn create_with_signal(
    service: &CriRuntimeService,
    sandbox: &str,
    name: &str,
    stop_signal: v1::Signal,
) -> Result<String, Status> {
    let mut config = container(name);
    config.stop_signal = stop_signal as i32;
    RuntimeService::create_container(
        service,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox.into(),
            config: Some(config),
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

/// CRI-1・CRI-2（#2395）: bundle 供給元へ渡る sandbox_config は登録記録の値で、
/// CreateContainer 要求の `sandbox_config` に別の値が入っていても使われない。
#[tokio::test]
async fn cri_1_bundle_request_carries_registered_sandbox_config() {
    let h = harness();
    let mut cfg = PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "pod".into(),
            uid: "uid-9".into(),
            namespace: "ns".into(),
            attempt: 0,
        }),
        ..Default::default()
    };
    cfg.hostname = "registered-host".into();
    let sb = RuntimeService::run_pod_sandbox(
        &h.service,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(cfg.clone()),
            runtime_handler: String::new(),
        }),
    )
    .await
    .expect("run sandbox")
    .into_inner()
    .pod_sandbox_id;
    cfg.hostname = "forged-host".into();
    RuntimeService::create_container(
        &h.service,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sb,
            config: Some(container("c")),
            sandbox_config: Some(cfg),
        }),
    )
    .await
    .expect("create");
    assert_eq!(
        h.bundles.sandbox_hostnames.lock().unwrap().clone(),
        vec!["registered-host".to_owned()]
    );
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
/// Stop・Remove 側の挙動は TASK-59.3 で接続済みのため `task_59_3_*` で検証する。
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
/// Start 側は lib の `task_59_3_start_in_notready_sandbox_never_reaches_the_runtime` が検証する。
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
    let st = status(&h.service, &id).await;
    assert_eq!(
        (st.state, st.exit_code, st.reason.as_str()),
        (S::ContainerExited as i32, 0, "Completed")
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

// ---- TASK-59.3（#439）: Stop・Remove の実行層への接続 ----

async fn stop_t(service: &CriRuntimeService, id: &str, timeout: i64) -> Result<(), Status> {
    RuntimeService::stop_container(
        service,
        Request::new(v1::StopContainerRequest {
            container_id: id.into(),
            timeout,
        }),
    )
    .await
    .map(|_| ())
}

async fn remove_sb(service: &CriRuntimeService, id: &str) -> Result<(), Status> {
    RuntimeService::remove_pod_sandbox(
        service,
        Request::new(v1::RemovePodSandboxRequest {
            pod_sandbox_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

async fn running_container(h: &Harness, sb: &str, name: &str) -> String {
    let id = create(&h.service, sb, name).await.expect("create");
    start(&h.service, &id).await.expect("start");
    id
}

async fn state_of(service: &CriRuntimeService, id: &str) -> i32 {
    status(service, id).await.state
}

/// bundle 供給元の release 呼び出し回数。
fn count_releases(h: &Harness) -> usize {
    h.bundles
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|c| c.starts_with("release "))
        .count()
}

fn count_calls(h: &Harness, prefix: &str) -> usize {
    h.runtime
        .calls()
        .iter()
        .filter(|c| c.starts_with(prefix))
        .count()
}

/// worker の終了後に unknown になるまで待つ（期限超過の後始末の検証用）。
async fn wait_unknown(service: &CriRuntimeService, id: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while state_of(service, id).await != S::ContainerUnknown as i32 {
        assert!(std::time::Instant::now() < deadline, "worker must finish");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// CRI-2: StopContainer は ContainerRuntime::stop（猶予つき）へ届き、exited と終了時刻を記録する。
#[tokio::test]
async fn task_59_3_stop_container_reaches_runtime_and_marks_exited() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "c").await;
    stop_t(&h.service, &id, 5).await.expect("stop");
    assert_eq!(h.runtime.calls().last().unwrap(), &format!("stop {id} 5s"));
    let st = status(&h.service, &id).await;
    assert_eq!(st.state, S::ContainerExited as i32);
    assert!(st.finished_at > 0);
}

/// CRI-2: exited への再 Stop は冪等で実行層を呼ばない。
#[tokio::test]
async fn task_59_3_stop_exited_is_idempotent_without_runtime_call() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "c").await;
    stop_t(&h.service, &id, 0).await.expect("stop");
    stop_t(&h.service, &id, 0).await.expect("stop again");
    assert_eq!(count_calls(&h, "stop "), 1);
}

/// CRI-2・ERR-3・#2032: created の Stop は成功し、実行層を呼ばず状態も変えない。
#[tokio::test]
async fn task_59_3_stop_created_succeeds_without_runtime_call() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    stop_t(&h.service, &id, 0).await.expect("stop created");
    assert_eq!(count_calls(&h, "stop "), 0);
    assert_eq!(state_of(&h.service, &id).await, S::ContainerCreated as i32);
}

/// CRI-2・ERR-3: 24 時間超の timeout は仮登録の前に拒否する。
#[tokio::test]
async fn task_59_3_oversized_timeout_is_rejected() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let rid = running_container(&h, &sb, "r").await;
    assert_eq!(
        stop_t(&h.service, &rid, 24 * 60 * 60 + 1)
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(count_calls(&h, "stop "), 0);
    assert_eq!(state_of(&h.service, &rid).await, S::ContainerRunning as i32);
    // 上限ちょうどは受理される。
    stop_t(&h.service, &rid, 24 * 60 * 60).await.expect("stop");
    assert_eq!(count_calls(&h, "stop "), 1);
}

/// REPAIR-5: 確定失敗は running のまま、結果不明は unknown。unknown からの再 Stop で exited に回復できる。
#[tokio::test]
async fn task_59_3_stop_failure_classification_and_recovery() {
    for code in [ErrorCode::FailedPrecondition, ErrorCode::PermissionDenied] {
        let h = harness();
        let sb = run_sandbox(&h.service).await;
        let id = running_container(&h, &sb, "c").await;
        *h.runtime.fail_stop.lock().unwrap() = Some(code);
        stop_t(&h.service, &id, 0).await.expect_err("stop");
        assert_eq!(state_of(&h.service, &id).await, S::ContainerRunning as i32);
    }
    for code in [
        ErrorCode::Timeout,
        ErrorCode::Unavailable,
        ErrorCode::Internal,
    ] {
        let h = harness();
        let sb = run_sandbox(&h.service).await;
        let id = running_container(&h, &sb, "c").await;
        *h.runtime.fail_stop.lock().unwrap() = Some(code);
        stop_t(&h.service, &id, 0).await.expect_err("stop");
        let st = status(&h.service, &id).await;
        assert_eq!(st.state, S::ContainerUnknown as i32);
        assert_eq!(st.finished_at, 0);
        *h.runtime.fail_stop.lock().unwrap() = None;
        stop_t(&h.service, &id, 0).await.expect("retry");
        assert_eq!(state_of(&h.service, &id).await, S::ContainerExited as i32);
    }
}

/// CRI-2: 実行層にコンテナが無い（NOT_FOUND）なら exited に確定する。想定外の応答（running）は unknown。
#[tokio::test]
async fn task_59_3_stop_not_found_exits_and_unexpected_state_is_unknown() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "c").await;
    *h.runtime.fail_stop.lock().unwrap() = Some(ErrorCode::NotFound);
    stop_t(&h.service, &id, 0).await.expect("stop");
    assert_eq!(state_of(&h.service, &id).await, S::ContainerExited as i32);

    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "c").await;
    h.runtime.stop_returns_running.store(true, Ordering::SeqCst);
    let err = stop_t(&h.service, &id, 0).await.unwrap_err();
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(state_of(&h.service, &id).await, S::ContainerUnknown as i32);
}

/// CRI-2: RemoveContainer は delete(force) → bundle 解放の順に呼び、記録と枠と名前キーを解放する。
#[tokio::test]
async fn task_59_3_remove_container_deletes_with_force_and_releases_bundle() {
    let h = harness();
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "c").await;
    remove(&h.service, &id).await.expect("remove");
    assert_eq!(
        h.runtime.calls().last().unwrap(),
        &format!("delete {id} force=true")
    );
    assert_eq!(
        h.bundles.calls.lock().unwrap().last().unwrap(),
        &format!("release {id}")
    );
    assert_eq!(list_count(&h.service).await, 0);
    // 名前キーと件数枠が解放され、同じ (name, attempt) で作り直せる。
    create(&h.service, &sb, "c").await.expect("recreate");
    // 未知 ID は冪等に成功する。
    remove(&h.service, &id).await.expect("idempotent");
}

/// REPAIR-5: delete の確定失敗は記録を保持し、結果不明は unknown で保持する。再試行で削除できる。
#[tokio::test]
async fn task_59_3_remove_failure_retains_record_and_retry_succeeds() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "c").await;
    // delete_ok が偽のとき delete は Unimplemented（確定失敗）。
    assert_eq!(
        remove(&h.service, &id).await.unwrap_err().code(),
        Code::Unimplemented
    );
    assert_eq!(state_of(&h.service, &id).await, S::ContainerRunning as i32);
    assert_eq!(count_releases(&h), 0);
    assert_eq!(list_count(&h.service).await, 1);
    // 結果不明（INTERNAL）は unknown で保持する。
    *h.runtime.fail_delete.lock().unwrap() = Some(ErrorCode::Internal);
    assert_eq!(
        remove(&h.service, &id).await.unwrap_err().code(),
        Code::Internal
    );
    assert_eq!(state_of(&h.service, &id).await, S::ContainerUnknown as i32);
    assert_eq!(count_releases(&h), 0);
    // unknown からの再試行で削除できる。
    *h.runtime.fail_delete.lock().unwrap() = None;
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
    remove(&h.service, &id).await.expect("retry");
    assert_eq!(list_count(&h.service).await, 0);
    assert_eq!(count_releases(&h), 1);
}

/// REPAIR-5: bundle の解放に失敗したら記録を保持し、再試行で解放できる。
#[tokio::test]
async fn task_59_3_remove_release_failure_retains_record() {
    let h = harness();
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "c").await;
    h.bundles.fail_release.store(true, Ordering::SeqCst);
    assert_eq!(
        remove(&h.service, &id).await.unwrap_err().code(),
        Code::Internal
    );
    assert_eq!(list_count(&h.service).await, 1);
    h.bundles.fail_release.store(false, Ordering::SeqCst);
    remove(&h.service, &id).await.expect("retry");
    assert_eq!(list_count(&h.service).await, 0);
}

/// CRI-2: 実行層に既にコンテナが無い（delete が NOT_FOUND）なら削除済みとして bundle を解放し記録を除去する。
#[tokio::test]
async fn task_59_3_remove_not_found_from_runtime_is_removed() {
    let h = harness();
    *h.runtime.fail_delete.lock().unwrap() = Some(ErrorCode::NotFound);
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    remove(&h.service, &id).await.expect("remove");
    assert_eq!(list_count(&h.service).await, 0);
    assert_eq!(count_releases(&h), 1);
}

/// CRI-2: 実行中の Stop・Remove・Start・親 sandbox の操作は FAILED_PRECONDITION で、実行層へは 1 回だけ届く。
#[tokio::test]
async fn task_59_3_concurrent_operations_during_stop_are_rejected() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "c").await;
    h.runtime.hold_stop.store(true, Ordering::SeqCst);
    let (first, others) = tokio::join!(stop_t(&h.service, &id, 0), async {
        let codes = [
            stop_t(&h.service, &id, 0).await.unwrap_err().code(),
            remove(&h.service, &id).await.unwrap_err().code(),
            start(&h.service, &id).await.unwrap_err().code(),
            stop_sb(&h.service, &sb).await.unwrap_err().code(),
            remove_sb(&h.service, &sb).await.unwrap_err().code(),
        ];
        h.runtime.hold_stop.store(false, Ordering::SeqCst);
        codes
    });
    first.expect("stop");
    assert_eq!(others, [Code::FailedPrecondition; 5]);
    assert_eq!(count_calls(&h, "stop "), 1);
    assert_eq!(count_calls(&h, "delete "), 0);
    assert_eq!(state_of(&h.service, &id).await, S::ContainerExited as i32);
}

/// REPAIR-5: stop が止まっても期限（runtime_timeout + 猶予）で DEADLINE_EXCEEDED を返し、worker の終了後に unknown になる。
#[tokio::test]
async fn task_59_3_stop_timeout_is_bounded_and_worker_finalizes() {
    let h = harness();
    let service = h.service.with_runtime_timeout(Duration::from_millis(100));
    let sb = run_sandbox(&service).await;
    let id = create(&service, &sb, "c").await.expect("create");
    start(&service, &id).await.expect("start");
    h.runtime.hold_stop.store(true, Ordering::SeqCst);
    *h.runtime.fail_stop.lock().unwrap() = Some(ErrorCode::Internal);
    let started = std::time::Instant::now();
    let err = stop_t(&service, &id, 0).await.unwrap_err();
    assert_eq!(err.code(), Code::DeadlineExceeded);
    assert!(started.elapsed() < Duration::from_secs(10));
    // 保留を解くと worker は結果不明（INTERNAL）で終わり、記録は unknown で残る。
    h.runtime.hold_stop.store(false, Ordering::SeqCst);
    wait_unknown(&service, &id).await;
    *h.runtime.fail_stop.lock().unwrap() = None;
    stop_t(&service, &id, 0).await.expect("recover");
    assert_eq!(state_of(&service, &id).await, S::ContainerExited as i32);
}

/// CRI-2: StopPodSandbox は配下の running を猶予 0 で停止して notready にする。created も停止して exited にし（init を持ちうる）、停止後の Create は拒否する。
#[tokio::test]
async fn task_59_3_stop_sandbox_stops_runtime_containers() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let run_id = running_container(&h, &sb, "r").await;
    let created_id = create(&h.service, &sb, "c").await.expect("create");
    stop_sb(&h.service, &sb).await.expect("stop sandbox");
    assert!(h.runtime.calls().contains(&format!("stop {run_id} 0s")));
    assert!(h.runtime.calls().contains(&format!("stop {created_id} 0s")));
    assert_eq!(count_calls(&h, "stop "), 2);
    assert_eq!(
        state_of(&h.service, &run_id).await,
        S::ContainerExited as i32
    );
    assert_eq!(
        state_of(&h.service, &created_id).await,
        S::ContainerExited as i32
    );
    assert_eq!(
        create(&h.service, &sb, "d").await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        start(&h.service, &created_id).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    // 冪等: 再呼び出しは実行層を呼ばない。
    stop_sb(&h.service, &sb).await.expect("again");
    assert_eq!(count_calls(&h, "stop "), 2);
}

/// CRI-2: StopPodSandbox の一部失敗は最初のエラーを返し、再呼び出しで残りを再試行できる。
#[tokio::test]
async fn task_59_3_stop_sandbox_partial_failure_is_retryable() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "r").await;
    *h.runtime.fail_stop.lock().unwrap() = Some(ErrorCode::Unavailable);
    assert_eq!(
        stop_sb(&h.service, &sb).await.unwrap_err().code(),
        Code::Unavailable
    );
    assert_eq!(state_of(&h.service, &id).await, S::ContainerUnknown as i32);
    *h.runtime.fail_stop.lock().unwrap() = None;
    stop_sb(&h.service, &sb).await.expect("retry");
    assert_eq!(state_of(&h.service, &id).await, S::ContainerExited as i32);
}

/// CRI-2: RemovePodSandbox は配下を全件 delete(force) と bundle 解放で回収してから sandbox を除去する。
#[tokio::test]
async fn task_59_3_remove_sandbox_deletes_all_runtime_containers() {
    let h = harness();
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
    let sb = run_sandbox(&h.service).await;
    let a = running_container(&h, &sb, "a").await;
    let b = create(&h.service, &sb, "b").await.expect("create");
    remove_sb(&h.service, &sb).await.expect("remove sandbox");
    let calls = h.runtime.calls();
    assert!(calls.contains(&format!("delete {a} force=true")));
    assert!(calls.contains(&format!("delete {b} force=true")));
    assert_eq!(count_calls(&h, "delete "), 2);
    assert_eq!(count_releases(&h), 2);
    assert_eq!(list_count(&h.service).await, 0);
    let err = RuntimeService::pod_sandbox_status(
        &h.service,
        Request::new(v1::PodSandboxStatusRequest {
            pod_sandbox_id: sb.clone(),
            verbose: false,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
}

/// CRI-2: delete が失敗したら sandbox と記録を保持し、復旧後の再呼び出しで除去できる。
#[tokio::test]
async fn task_59_3_remove_sandbox_failure_retains_sandbox() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    running_container(&h, &sb, "a").await;
    assert_eq!(
        remove_sb(&h.service, &sb).await.unwrap_err().code(),
        Code::Unimplemented
    );
    assert_eq!(list_count(&h.service).await, 1);
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
    remove_sb(&h.service, &sb).await.expect("retry");
    assert_eq!(list_count(&h.service).await, 0);
}

/// REPAIR-5・fail-closed: Create の結果不明（unknown）の記録も、Start は拒否したまま Stop・Remove は実行層へ届く。
#[tokio::test]
async fn task_59_3_ambiguous_create_is_recoverable_via_stop_and_remove() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    *h.runtime.fail_create.lock().unwrap() = Some(ErrorCode::Timeout);
    create(&h.service, &sb, "c").await.expect_err("create");
    let id = RuntimeService::list_containers(
        &h.service,
        Request::new(v1::ListContainersRequest::default()),
    )
    .await
    .expect("list")
    .into_inner()
    .containers[0]
        .id
        .clone();
    let st = status(&h.service, &id).await;
    assert_eq!(
        (st.state, st.finished_at, st.exit_code),
        (S::ContainerUnknown as i32, 0, 0)
    );
    assert_eq!(
        start(&h.service, &id).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    // delete が失敗する間は記録を保持する。
    assert_eq!(
        remove(&h.service, &id).await.unwrap_err().code(),
        Code::Unimplemented
    );
    assert_eq!(list_count(&h.service).await, 1);
    stop_t(&h.service, &id, 0).await.expect("stop");
    assert_eq!(state_of(&h.service, &id).await, S::ContainerExited as i32);
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
    remove(&h.service, &id).await.expect("remove");
    assert_eq!(list_count(&h.service).await, 0);
}

/// REPAIR-4: 実行層経由の 4 RPC も結果を 1 件ずつ記録する。
#[tokio::test]
async fn task_59_3_outcomes_are_recorded() {
    let h = harness();
    h.runtime.delete_ok.store(true, Ordering::SeqCst);
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "c").await;
    stop_t(&h.service, &id, 0).await.expect("stop");
    remove(&h.service, &id).await.expect("remove");
    stop_sb(&h.service, &sb).await.expect("stop sb");
    remove_sb(&h.service, &sb).await.expect("remove sb");
    let samples = h.recorder.0.lock().unwrap().clone();
    let names: Vec<_> = samples.iter().map(|s| code_name(s.code())).collect();
    // run, create, start, stop, remove, stop sb, remove sb: すべて OK。
    assert_eq!(names, vec!["OK"; 7]);
}

/// CRI-2・TASK-59.3: 実行層の Stop 応答の終了コード（137）が ContainerStatus.exit_code に反映される
/// （StopContainer・StopPodSandbox の両経路）。
#[tokio::test]
async fn task_59_3_stop_exit_code_is_reflected_in_status() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    start(&h.service, &id).await.expect("start");
    h.runtime.stop_exit_code.store(137, Ordering::SeqCst);
    stop_c(&h.service, &id).await.expect("stop container");
    let st = status(&h.service, &id).await;
    assert_eq!(
        (st.state, st.exit_code, st.reason.as_str()),
        (S::ContainerExited as i32, 137, "Error")
    );

    let id2 = create(&h.service, &sb, "d").await.expect("create");
    start(&h.service, &id2).await.expect("start");
    h.runtime.stop_exit_code.store(143, Ordering::SeqCst);
    stop_sb(&h.service, &sb).await.expect("stop sandbox");
    let st = status(&h.service, &id2).await;
    assert_eq!(
        (st.state, st.exit_code, st.reason.as_str()),
        (S::ContainerExited as i32, 143, "Error")
    );
}

/// CRI-2・CORE-4: 実行層が OOM の停止を報告したら reason は `OOMKilled`（Stop・StopPodSandbox の経路。終了コード 0 でも OOMKilled）。message は REPAIR-3 のスタブで空。image_ref・image_id・user は報告の無い経路では空（#2831）。
#[tokio::test]
async fn cri_2_oom_killed_is_reflected_in_reason() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;

    let id = running_container(&h, &sb, "c").await;
    h.runtime.stop_exit_code.store(137, Ordering::SeqCst);
    h.runtime.stop_oom_killed.store(true, Ordering::SeqCst);
    stop_c(&h.service, &id).await.expect("stop container");
    let st = status(&h.service, &id).await;
    assert_eq!(
        (st.state, st.exit_code, st.reason.as_str()),
        (S::ContainerExited as i32, 137, "OOMKilled")
    );
    assert_eq!(
        (
            st.message.as_str(),
            st.image_ref.as_str(),
            st.image_id.as_str()
        ),
        ("", "", "")
    );
    assert_eq!(st.user, None);

    // 終了コード 0 でも OOM の報告があれば OOMKilled。StopPodSandbox の経路。
    let id2 = running_container(&h, &sb, "d").await;
    h.runtime.stop_exit_code.store(0, Ordering::SeqCst);
    stop_sb(&h.service, &sb).await.expect("stop sandbox");
    let st = status(&h.service, &id2).await;
    assert_eq!(
        (st.state, st.exit_code, st.reason.as_str()),
        (S::ContainerExited as i32, 0, "OOMKilled")
    );
}

/// CRI-2・CORE-4: Start の応答が OOM の停止だった経路も `OOMKilled` になる。
#[tokio::test]
async fn cri_2_oom_killed_start_response_is_reflected_in_reason() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id3 = create(&h.service, &sb, "e").await.expect("create");
    h.runtime.start_exit_code.store(137, Ordering::SeqCst);
    h.runtime
        .start_returns_stopped
        .store(true, Ordering::SeqCst);
    h.runtime.start_oom_killed.store(true, Ordering::SeqCst);
    start(&h.service, &id3).await.expect_err("start");
    let st = status(&h.service, &id3).await;
    assert_eq!(
        (st.state, st.exit_code, st.reason.as_str()),
        (S::ContainerExited as i32, 137, "OOMKilled")
    );
}

/// CRI-2・REPAIR-3: 終了コード 0 の Stop は reason `Completed`。停止前の running は reason が空。
#[tokio::test]
async fn cri_2_repair_3_stop_exit_zero_reports_completed() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "c").await;
    let st = status(&h.service, &id).await;
    assert_eq!(
        (st.state, st.exit_code, st.reason.as_str()),
        (S::ContainerRunning as i32, 0, "")
    );
    stop_c(&h.service, &id).await.expect("stop");
    let st = status(&h.service, &id).await;
    assert_eq!(
        (st.state, st.exit_code, st.reason.as_str()),
        (S::ContainerExited as i32, 0, "Completed")
    );
    assert!(st.finished_at > 0);
}

/// CRI-2・REPAIR-3: 実行層にコンテナが無く終了コードが不明な Stop は、Completed と見せず reason を空にする。
#[tokio::test]
async fn cri_2_repair_3_stop_not_found_leaves_reason_empty() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = running_container(&h, &sb, "c").await;
    *h.runtime.fail_stop.lock().unwrap() = Some(ErrorCode::NotFound);
    stop_c(&h.service, &id).await.expect("stop");
    let st = status(&h.service, &id).await;
    assert_eq!(
        (st.state, st.exit_code, st.reason.as_str()),
        (S::ContainerExited as i32, 0, "")
    );
}

/// CRI-2・REPAIR-3: Start の応答が stopped のとき、その終了コードが記録へ反映される。
#[tokio::test]
async fn cri_2_repair_3_stopped_start_response_reflects_exit_code() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    h.runtime
        .start_returns_stopped
        .store(true, Ordering::SeqCst);
    h.runtime.start_exit_code.store(1, Ordering::SeqCst);
    start(&h.service, &id).await.expect_err("start");
    let st = status(&h.service, &id).await;
    assert_eq!(
        (st.state, st.exit_code, st.reason.as_str()),
        (S::ContainerExited as i32, 1, "Error")
    );
}

/// CRI-2・SUP-4（#2671）: log_directory と log_path は結合され、status と StartRequest に同じ値で現れる。
#[tokio::test]
async fn cri_2_log_path_is_joined_and_reaches_start_request() {
    let h = harness();
    let sb = RuntimeService::run_pod_sandbox(
        &h.service,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "pod".into(),
                    uid: "uid-1".into(),
                    namespace: "ns".into(),
                    attempt: 0,
                }),
                log_directory: "/var/log/pods/ns_pod_uid-1".into(),
                ..Default::default()
            }),
            runtime_handler: String::new(),
        }),
    )
    .await
    .expect("run sandbox")
    .into_inner()
    .pod_sandbox_id;
    let mut cfg = container("c");
    cfg.log_path = "c/0.log".into();
    let id = RuntimeService::create_container(
        &h.service,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sb.clone(),
            config: Some(cfg),
            sandbox_config: None,
        }),
    )
    .await
    .expect("create")
    .into_inner()
    .container_id;
    let expected = "/var/log/pods/ns_pod_uid-1/c/0.log";
    assert_eq!(status(&h.service, &id).await.log_path, expected);
    start(&h.service, &id).await.expect("start");
    assert_eq!(
        h.runtime.start_log_paths.lock().unwrap().clone(),
        vec![Some(expected.to_owned())]
    );
    assert_eq!(status(&h.service, &id).await.log_path, expected);
}

/// CRI-2・SUP-4（#2671）: log_path だけ（基点なし）の CreateContainer は INVALID_ARGUMENT で、記録を残さない。
#[tokio::test]
async fn cri_2_log_path_without_directory_is_rejected_on_create() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let mut cfg = container("c");
    cfg.log_path = "c/0.log".into();
    let err = RuntimeService::create_container(
        &h.service,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sb,
            config: Some(cfg),
            sandbox_config: None,
        }),
    )
    .await
    .expect_err("must be rejected");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(list_count(&h.service).await, 0);
}

/// CRI-2・SUP-4（#2671）: 実行層が Unimplemented（supervisor が CRI ログを受けられない構成）で
/// start に失敗したら確定失敗として created へ戻る。
#[tokio::test]
async fn cri_2_start_unimplemented_returns_to_created() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "c").await.expect("create");
    *h.runtime.fail_start.lock().unwrap() = Some(ErrorCode::Unimplemented);
    let err = start(&h.service, &id).await.expect_err("start");
    assert_eq!(err.code(), Code::Unimplemented);
    assert_eq!(
        status(&h.service, &id).await.state,
        S::ContainerCreated as i32
    );
}

/// CRI-2・PLUG-1（#2668）: StopContainer は作成時の stop_signal を Linux の番号へ写して実行層へ渡す（既定は SIGTERM）。
#[tokio::test]
async fn cri2_stop_container_uses_config_stop_signal() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let a = create_with_signal(&h.service, &sb, "a", v1::Signal::Sigint)
        .await
        .expect("create a");
    start(&h.service, &a).await.expect("start a");
    stop_c(&h.service, &a).await.expect("stop a");
    let b = create(&h.service, &sb, "b").await.expect("create b");
    start(&h.service, &b).await.expect("start b");
    stop_c(&h.service, &b).await.expect("stop b");
    assert_eq!(h.runtime.stop_signals.lock().unwrap().clone(), vec![2, 15]);
}

/// CRI-2・PLUG-1（#2668）: StopPodSandbox はコンテナごとの stop_signal を使う。
#[tokio::test]
async fn cri2_stop_pod_sandbox_uses_each_container_stop_signal() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    for (name, sig) in [("a", v1::Signal::Sigint), ("b", v1::Signal::Sigusr1)] {
        let id = create_with_signal(&h.service, &sb, name, sig)
            .await
            .expect("create");
        start(&h.service, &id).await.expect("start");
    }
    stop_sb(&h.service, &sb).await.expect("stop sandbox");
    let mut got = h.runtime.stop_signals.lock().unwrap().clone();
    got.sort_unstable();
    assert_eq!(got, vec![2, 10]);
}

/// CRI-2・OCI-1・SEC-5（#2771）: 報告された識別情報と解決済みの stop signal が ContainerStatus と stop に反映される。
#[tokio::test]
async fn cri2_status_reports_applied_user_and_resolved_stop_signal() {
    let h = harness();
    *h.bundles.report_user.lock().unwrap() = Some(fandhe_container_cri::bundle::AppliedUser::new(
        1000,
        2000,
        vec![3000],
    ));
    *h.bundles.report_stop_signal.lock().unwrap() = Some(v1::Signal::Sigint);
    let sb = run_sandbox(&h.service).await;
    // config は RUNTIME_DEFAULT。
    let id = create(&h.service, &sb, "a").await.expect("create");
    let st = status(&h.service, &id).await;
    assert_eq!(st.stop_signal, v1::Signal::Sigint as i32);
    let linux = st.user.expect("user").linux.expect("linux");
    assert_eq!(
        (linux.uid, linux.gid, linux.supplemental_groups),
        (1000, 2000, vec![3000])
    );
    start(&h.service, &id).await.expect("start");
    stop_c(&h.service, &id).await.expect("stop");
    assert_eq!(h.runtime.stop_signals.lock().unwrap().clone(), vec![2]);
}

/// CRI-2・SEC-5（#2771）: 補助グループが空の識別情報は、core が起動元のグループを現状維持し得る
/// （`KeptSetgroupsDenied`）ため実プロセスとの一致を保証できず、user は未報告になる。
#[tokio::test]
async fn cri2_status_omits_user_when_supplemental_groups_empty() {
    let h = harness();
    *h.bundles.report_user.lock().unwrap() = Some(fandhe_container_cri::bundle::AppliedUser::new(
        1000,
        2000,
        Vec::new(),
    ));
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "a").await.expect("create");
    let st = status(&h.service, &id).await;
    assert!(st.user.is_none());
}

/// CRI-2・OCI-1（#2831）: 報告された解決結果が ContainerStatus と ListContainers の image_ref・image_id になる。
/// Status の image_ref は digest 参照、image_id と List の両項目は image ID（containerd main cfb18c4）。
#[tokio::test]
async fn cri2_status_and_list_report_resolved_image() {
    use fandhe_container_cri::bundle::ResolvedImage;
    let hex = "a".repeat(64);
    let id = Digest::parse(&format!("sha256:{hex}")).unwrap();
    let digest_ref = format!("docker.io/library/alpine@sha256:{}", "b".repeat(64));
    let h = harness();
    *h.bundles.report_image.lock().unwrap() =
        Some(ResolvedImage::new(id, Some(digest_ref.clone())));
    let sb = run_sandbox(&h.service).await;
    let cid = create(&h.service, &sb, "a").await.expect("create");
    let st = status(&h.service, &cid).await;
    assert_eq!(st.image_ref, digest_ref);
    assert_eq!(st.image_id, format!("sha256:{hex}"));
    let list = RuntimeService::list_containers(
        &h.service,
        Request::new(v1::ListContainersRequest { filter: None }),
    )
    .await
    .expect("list")
    .into_inner()
    .containers;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].image_ref, format!("sha256:{hex}"));
    assert_eq!(list[0].image_id, format!("sha256:{hex}"));
}

/// CRI-2・OCI-1（#2831）: digest 参照が無い解決結果は image_ref も image ID。報告が無い経路は空。
#[tokio::test]
async fn cri2_status_image_without_digest_ref_and_without_report() {
    use fandhe_container_cri::bundle::ResolvedImage;
    let hex = "c".repeat(64);
    let h = harness();
    *h.bundles.report_image.lock().unwrap() = Some(ResolvedImage::new(
        Digest::parse(&format!("sha256:{hex}")).unwrap(),
        None,
    ));
    let sb = run_sandbox(&h.service).await;
    let cid = create(&h.service, &sb, "a").await.expect("create");
    let st = status(&h.service, &cid).await;
    assert_eq!(
        (st.image_ref.as_str(), st.image_id.as_str()),
        (
            format!("sha256:{hex}").as_str(),
            format!("sha256:{hex}").as_str()
        )
    );
    let h2 = harness();
    let sb2 = run_sandbox(&h2.service).await;
    let cid2 = create(&h2.service, &sb2, "a").await.expect("create");
    let st2 = status(&h2.service, &cid2).await;
    assert_eq!((st2.image_ref.as_str(), st2.image_id.as_str()), ("", ""));
}

/// CRI-2（#2771）: 報告の無い bundle 供給元では user は未報告で、RUNTIME_DEFAULT は SIGTERM（23）と報告される。
#[tokio::test]
async fn cri2_status_without_report_has_no_user_and_defaults_to_sigterm() {
    let h = harness();
    let sb = run_sandbox(&h.service).await;
    let id = create(&h.service, &sb, "a").await.expect("create");
    let st = status(&h.service, &id).await;
    assert!(st.user.is_none());
    assert_eq!(st.stop_signal, v1::Signal::Sigterm as i32);
}

/// CRI-2・REPAIR-5（#2771）: 報告された識別情報が保持量の上限を超えたら FAILED_PRECONDITION で、記録と bundle を残さない。
#[tokio::test]
async fn cri2_applied_user_over_retained_limit_is_rejected_and_rolled_back() {
    let runtime = Arc::new(FakeRuntime::default());
    let bundles = Arc::new(FakeBundles::default());
    let service = CriRuntimeService::new()
        .with_container_limits(
            fandhe_container_cri::runtime_service::ContainerLimits::default()
                .with_max_retained_bytes(8 * 1024),
        )
        .with_runtime(
            RuntimeAdapter::new(Arc::new(Shared(runtime.clone()))),
            bundles.clone(),
        );
    *bundles.report_user.lock().unwrap() = Some(fandhe_container_cri::bundle::AppliedUser::new(
        1000,
        2000,
        (1..=4000).collect(),
    ));
    let sb = run_sandbox(&service).await;
    let err = create(&service, &sb, "a").await.expect_err("over limit");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert_eq!(list_count(&service).await, 0);
    assert!(
        bundles
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.starts_with("release "))
    );
    assert_eq!(runtime.calls().len(), 0);
}

/// OCI-1・CRI-2（#2771）: runtime_features は supplemental_groups_policy だけを真にする。
#[test]
fn cri2_runtime_features_enable_supplemental_groups_policy() {
    let f = fandhe_container_cri::runtime_service::runtime_features();
    assert!(f.supplemental_groups_policy);
    assert!(!f.user_namespaces_host_network);
    assert!(!f.mount_options);
}
