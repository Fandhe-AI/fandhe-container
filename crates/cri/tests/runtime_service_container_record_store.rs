//! コンテナ記録の書く・消す時点の試験（CRI-1・OCI-7・CRI-2・REPAIR-3・REPAIR-5。#2934・R5）。
//!
//! フェイクの `RecordStore`・`ContainerRuntime`・`BundleProvider` が同じイベント列へ書く順序を、具体値で照合する。
//! 書かれたバイト列は公開 API から復号できないため、固定ヘッダの行（`state=` `in_flight=` 等）で照合する。
//! 全待機に上限を置く（REPAIR-5）。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, ErrorCode,
    KillRequest, StartRequest, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{
    BundleProvider, BundleRequest, PreparedBundle, RuntimeAdapter,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, KeyValue, PodSandboxConfig,
    PodSandboxMetadata, runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::{
    CriRuntimeService, ListBudget, ListLimits, RecordId, RecordKind, RecordListing, RecordStore,
};
use tonic::{Code, Request};

/// 試験内の全待機の上限（回帰時にも有限時間で失敗させる。REPAIR-5）。
const WAIT: Duration = Duration::from_secs(10);
const ENV_SENTINEL: &str = "FANDHE_R5_ENV_SENTINEL_value";
const LABEL_VALUE: &str = "fandhe-r5-label-value";

#[derive(Debug, Clone, PartialEq)]
enum Ev {
    SbPut(String),
    SbRemove,
    CPut {
        state: String,
        in_flight: String,
        exit_code: String,
    },
    CRemove,
    Prepare,
    Create,
    Start,
    Stop,
    Delete,
    Release,
}

fn cput(state: &str, in_flight: &str, exit_code: &str) -> Ev {
    Ev::CPut {
        state: state.into(),
        in_flight: in_flight.into(),
        exit_code: exit_code.into(),
    }
}

type Log = Arc<Mutex<Vec<Ev>>>;

fn header(bytes: &[u8], key: &str) -> String {
    let text = String::from_utf8_lossy(bytes);
    let prefix = format!("{key}=");
    text.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()).map(str::to_owned))
        .unwrap_or_default()
}

#[derive(Debug)]
struct FakeStore {
    log: Log,
    container_puts: Mutex<usize>,
    container_removes: Mutex<usize>,
    fail_container_put_at: Mutex<Vec<usize>>,
    fail_container_remove_at: Mutex<Vec<usize>>,
    block_container_put_at: Mutex<Option<usize>>,
    /// 書かれたコンテナ記録のバイト列（`envs` を書かないことの照合用）。
    container_bytes: Mutex<Vec<Vec<u8>>>,
    /// 書かれたコンテナ記録のヘッダ（started_at / finished_at / user / image_id / stop_signal の照合用）。
    container_headers: Mutex<Vec<Vec<(String, String)>>>,
    entered: Mutex<Sender<()>>,
    release: Mutex<Receiver<()>>,
}

struct Gate {
    entered: Receiver<()>,
    release: Sender<()>,
}

impl FakeStore {
    fn new(log: &Log) -> (Arc<Self>, Gate) {
        let (entered_tx, entered_rx) = channel();
        let (release_tx, release_rx) = channel();
        (
            Arc::new(Self {
                log: Arc::clone(log),
                container_puts: Mutex::new(0),
                container_removes: Mutex::new(0),
                fail_container_put_at: Mutex::new(Vec::new()),
                fail_container_remove_at: Mutex::new(Vec::new()),
                block_container_put_at: Mutex::new(None),
                container_bytes: Mutex::new(Vec::new()),
                container_headers: Mutex::new(Vec::new()),
                entered: Mutex::new(entered_tx),
                release: Mutex::new(release_rx),
            }),
            Gate {
                entered: entered_rx,
                release: release_tx,
            },
        )
    }
}

impl RecordStore for FakeStore {
    fn put(&self, kind: RecordKind, _id: &RecordId, bytes: &[u8]) -> Result<(), CriError> {
        match kind {
            RecordKind::Sandbox => {
                self.log
                    .lock()
                    .unwrap()
                    .push(Ev::SbPut(header(bytes, "state")));
                Ok(())
            }
            RecordKind::Container => {
                let n = {
                    let mut p = self.container_puts.lock().unwrap();
                    let n = *p;
                    *p += 1;
                    n
                };
                if *self.block_container_put_at.lock().unwrap() == Some(n) {
                    self.entered.lock().unwrap().send(()).unwrap();
                    if self.release.lock().unwrap().recv_timeout(WAIT).is_err() {
                        return Err(CriError::timeout("test gate was not released"));
                    }
                }
                if self.fail_container_put_at.lock().unwrap().contains(&n) {
                    return Err(CriError::timeout("injected"));
                }
                self.container_bytes.lock().unwrap().push(bytes.to_vec());
                let keys = [
                    "started_at",
                    "finished_at",
                    "user",
                    "image_id",
                    "stop_signal",
                ];
                self.container_headers.lock().unwrap().push(
                    keys.iter()
                        .map(|k| ((*k).to_owned(), header(bytes, k)))
                        .collect(),
                );
                self.log.lock().unwrap().push(Ev::CPut {
                    state: header(bytes, "state"),
                    in_flight: header(bytes, "in_flight"),
                    exit_code: header(bytes, "exit_code"),
                });
                Ok(())
            }
        }
    }

    fn remove(&self, kind: RecordKind, _id: &RecordId) -> Result<(), CriError> {
        match kind {
            RecordKind::Sandbox => {
                self.log.lock().unwrap().push(Ev::SbRemove);
                Ok(())
            }
            RecordKind::Container => {
                let n = {
                    let mut r = self.container_removes.lock().unwrap();
                    let n = *r;
                    *r += 1;
                    n
                };
                if self.fail_container_remove_at.lock().unwrap().contains(&n) {
                    return Err(CriError::timeout("injected"));
                }
                self.log.lock().unwrap().push(Ev::CRemove);
                Ok(())
            }
        }
    }

    fn list(
        &self,
        _kind: RecordKind,
        _budget: ListBudget,
        _limits: ListLimits,
    ) -> Result<RecordListing, CriError> {
        Err(CriError::internal("not used"))
    }
}

#[derive(Default)]
struct FakeRuntime {
    log: Mutex<Option<Log>>,
    fail_create: Mutex<Option<ErrorCode>>,
    delete_code: Mutex<Option<ErrorCode>>,
    stop_exit_code: std::sync::atomic::AtomicI32,
    create_started: AtomicBool,
}

struct Shared(Arc<FakeRuntime>);

impl Shared {
    fn push(&self, ev: Ev) {
        if let Some(log) = self.0.log.lock().unwrap().as_ref() {
            log.lock().unwrap().push(ev);
        }
    }
}

impl ContainerRuntime for Shared {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        self.push(Ev::Create);
        self.0.create_started.store(true, Ordering::SeqCst);
        if let Some(c) = *self.0.fail_create.lock().unwrap() {
            return Err(TraitError::new(c, "create failed"));
        }
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
    fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
        self.push(Ev::Start);
        Ok(ContainerStatus::running(
            r.id().clone(),
            std::num::NonZeroU32::new(4242),
        ))
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
    }
    fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
        self.push(Ev::Stop);
        let code = Some(self.0.stop_exit_code.load(Ordering::SeqCst));
        Ok(ContainerStatus::stopped(r.id().clone(), code))
    }
    fn delete(&self, _r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        self.push(Ev::Delete);
        if let Some(c) = *self.0.delete_code.lock().unwrap() {
            return Err(TraitError::new(c, "delete failed"));
        }
        Ok(DeleteResponse::new())
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
}

struct FakeBundles {
    log: Log,
    hold_prepare_until: Mutex<Option<Instant>>,
    prepared: AtomicBool,
}

impl BundleProvider for FakeBundles {
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
        self.prepared.store(true, Ordering::SeqCst);
        self.log.lock().unwrap().push(Ev::Prepare);
        let root = if cfg!(windows) {
            PathBuf::from(r"C:\bundles")
        } else {
            PathBuf::from("/bundles")
        };
        let mut prepared = PreparedBundle::new(root.join(req.container_id));
        prepared = prepared.with_stop_signal(v1::Signal::Sigint);
        Ok(prepared)
    }
    fn release(&self, _container_id: &str) -> Result<(), CriError> {
        self.log.lock().unwrap().push(Ev::Release);
        Ok(())
    }
}

struct H {
    service: CriRuntimeService,
    runtime: Arc<FakeRuntime>,
    store: Arc<FakeStore>,
    gate: Gate,
    bundles: Arc<FakeBundles>,
    log: Log,
}

fn build(with_store: bool, with_runtime: bool, timeout: Option<Duration>) -> H {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let (store, gate) = FakeStore::new(&log);
    let runtime = Arc::new(FakeRuntime::default());
    *runtime.log.lock().unwrap() = Some(Arc::clone(&log));
    let bundles = Arc::new(FakeBundles {
        log: Arc::clone(&log),
        hold_prepare_until: Mutex::new(None),
        prepared: AtomicBool::new(false),
    });
    let mut service = CriRuntimeService::new();
    if let Some(t) = timeout {
        service = service.with_runtime_timeout(t);
    }
    if with_store {
        service = service.with_record_store(store.clone());
    }
    if with_runtime {
        service = service.with_runtime(
            RuntimeAdapter::new(Arc::new(Shared(runtime.clone()))),
            bundles.clone(),
        );
    }
    H {
        service,
        runtime,
        store,
        gate,
        bundles,
        log,
    }
}

fn harness() -> H {
    build(true, true, None)
}

fn events(h: &H) -> Vec<Ev> {
    h.log.lock().unwrap().clone()
}

fn clear(h: &H) {
    h.log.lock().unwrap().clear();
}

async fn run_sandbox(h: &H) -> String {
    let config = PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: "pod".into(),
            uid: "uid-1".into(),
            namespace: "ns".into(),
            attempt: 0,
        }),
        ..Default::default()
    };
    let id = RuntimeService::run_pod_sandbox(
        &h.service,
        Request::new(v1::RunPodSandboxRequest {
            config: Some(config),
            runtime_handler: String::new(),
        }),
    )
    .await
    .expect("run sandbox")
    .into_inner()
    .pod_sandbox_id;
    clear(h);
    id
}

fn container_config(name: &str) -> ContainerConfig {
    ContainerConfig {
        metadata: Some(ContainerMetadata {
            name: name.into(),
            attempt: 0,
        }),
        image: Some(ImageSpec {
            image: "busybox:1.36".into(),
            ..Default::default()
        }),
        envs: vec![KeyValue {
            key: "SECRET".into(),
            value: ENV_SENTINEL.into(),
        }],
        labels: [("k".to_owned(), LABEL_VALUE.to_owned())].into(),
        ..Default::default()
    }
}

async fn create(h: &H, sandbox: &str, name: &str) -> Result<String, tonic::Status> {
    RuntimeService::create_container(
        &h.service,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox.into(),
            config: Some(container_config(name)),
            sandbox_config: None,
        }),
    )
    .await
    .map(|r| r.into_inner().container_id)
}

async fn start(h: &H, id: &str) -> Result<(), tonic::Status> {
    RuntimeService::start_container(
        &h.service,
        Request::new(v1::StartContainerRequest {
            container_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

async fn stop(h: &H, id: &str) -> Result<(), tonic::Status> {
    RuntimeService::stop_container(
        &h.service,
        Request::new(v1::StopContainerRequest {
            container_id: id.into(),
            timeout: 0,
        }),
    )
    .await
    .map(|_| ())
}

async fn remove(h: &H, id: &str) -> Result<(), tonic::Status> {
    RuntimeService::remove_container(
        &h.service,
        Request::new(v1::RemoveContainerRequest {
            container_id: id.into(),
        }),
    )
    .await
    .map(|_| ())
}

async fn status(h: &H, id: &str) -> v1::ContainerStatus {
    RuntimeService::container_status(
        &h.service,
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

async fn list_count(h: &H) -> usize {
    RuntimeService::list_containers(
        &h.service,
        Request::new(v1::ListContainersRequest { filter: None }),
    )
    .await
    .expect("list")
    .into_inner()
    .containers
    .len()
}

const INTERNAL_PERSIST: &str = "container record could not be persisted";
const INTERNAL_UNPERSIST: &str = "container record could not be removed";

/// CRI-1・OCI-7: Create は write-ahead（`in_flight=create`）→ prepare → create → 確定版の順で書く。
/// 確定版には prepare が報告した stop signal（CRI の SIGINT）が入り、`envs` は書かない。
#[tokio::test]
async fn cri_1_create_writes_ahead_then_confirms_without_envs() {
    let h = harness();
    let sb = run_sandbox(&h).await;
    let id = create(&h, &sb, "c").await.expect("create");
    assert_eq!(
        events(&h),
        vec![
            cput("created", "create", "-"),
            Ev::Prepare,
            Ev::Create,
            cput("created", "-", "-"),
        ]
    );
    let headers = h.store.container_headers.lock().unwrap().clone();
    let stop_signal = |i: usize| {
        headers[i]
            .iter()
            .find(|(k, _)| k == "stop_signal")
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    assert_eq!(stop_signal(1), (v1::Signal::Sigint as i32).to_string());
    assert_eq!(
        status(&h, &id).await.state,
        v1::ContainerState::ContainerCreated as i32
    );
    // envs は書かない（陽性対照として label の値は書く）。
    let all = h.store.container_bytes.lock().unwrap().clone();
    assert_eq!(all.len(), 2);
    for bytes in &all {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains(ENV_SENTINEL));
        assert!(text.contains(LABEL_VALUE));
    }
}

/// CRI-1・OCI-7: Start・Stop・Remove の書く順序（成功後に状態を書き、削除と解放の後に消す）。
#[tokio::test]
async fn cri_1_start_stop_remove_write_points_in_order() {
    let h = harness();
    h.runtime.stop_exit_code.store(137, Ordering::SeqCst);
    let sb = run_sandbox(&h).await;
    let id = create(&h, &sb, "c").await.expect("create");
    clear(&h);

    start(&h, &id).await.expect("start");
    assert_eq!(events(&h), vec![Ev::Start, cput("running", "-", "-")]);
    let started = status(&h, &id).await.started_at;
    assert!(started > 0);
    let headers = h.store.container_headers.lock().unwrap().clone();
    let started_hdr = headers.last().unwrap()[0].1.clone();
    assert_eq!(started_hdr, started.to_string());
    clear(&h);

    stop(&h, &id).await.expect("stop");
    assert_eq!(events(&h), vec![Ev::Stop, cput("exited", "-", "137")]);
    clear(&h);

    remove(&h, &id).await.expect("remove");
    assert_eq!(events(&h), vec![Ev::Delete, Ev::Release, Ev::CRemove]);
    assert_eq!(list_count(&h).await, 0);
}

/// CRI-1: Create の write-ahead の put が失敗したら、prepare も create も呼ばず固定文言の `INTERNAL`。
/// 書きかけが残りうるため記録の削除を試み、同じ名前の再 Create が成功する。
#[tokio::test]
async fn cri_1_write_ahead_failure_has_no_side_effect() {
    let h = harness();
    let sb = run_sandbox(&h).await;
    h.store.fail_container_put_at.lock().unwrap().push(0);
    let err = create(&h, &sb, "c").await.expect_err("create");
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(err.message(), INTERNAL_PERSIST);
    assert!(!h.bundles.prepared.load(Ordering::SeqCst));
    assert_eq!(events(&h), vec![Ev::Release, Ev::CRemove]);
    assert_eq!(list_count(&h).await, 0);
    clear(&h);
    create(&h, &sb, "c").await.expect("re-create");
}

/// CRI-2: 実行層が確定失敗を返した Create は、解放の後に記録を消す。
#[tokio::test]
async fn cri_2_definite_create_failure_removes_record_after_release() {
    let h = harness();
    let sb = run_sandbox(&h).await;
    *h.runtime.fail_create.lock().unwrap() = Some(ErrorCode::InvalidArgument);
    let err = create(&h, &sb, "c").await.expect_err("create");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(
        events(&h),
        vec![
            cput("created", "create", "-"),
            Ev::Prepare,
            Ev::Create,
            Ev::Release,
            Ev::CRemove,
        ]
    );
    assert_eq!(list_count(&h).await, 0);
}

/// CRI-2・REPAIR-5: 結果不明の Create（削除を確認できない）は記録ファイルを消さず、メモリも unknown で保持する。
#[tokio::test]
async fn cri_2_unknown_create_keeps_record() {
    let h = harness();
    *h.runtime.fail_create.lock().unwrap() = Some(ErrorCode::Unavailable);
    *h.runtime.delete_code.lock().unwrap() = Some(ErrorCode::Unavailable);
    let sb = run_sandbox(&h).await;
    create(&h, &sb, "c").await.expect_err("create");
    let ev = events(&h);
    assert!(!ev.contains(&Ev::CRemove) && !ev.contains(&Ev::Release));
    assert_eq!(
        ev,
        vec![
            cput("created", "create", "-"),
            Ev::Prepare,
            Ev::Create,
            Ev::Delete,
        ]
    );
    assert_eq!(list_count(&h).await, 1);
}

/// CRI-2: 確定失敗の Create で記録ファイルの削除に失敗したら、メモリの記録を保持し（unknown）、
/// 続く RemoveContainer が delete → release → 記録の削除で回収する。
#[tokio::test]
async fn cri_2_failed_record_removal_keeps_memory_then_remove_recovers() {
    let h = harness();
    let sb = run_sandbox(&h).await;
    *h.runtime.fail_create.lock().unwrap() = Some(ErrorCode::InvalidArgument);
    h.store.fail_container_remove_at.lock().unwrap().push(0);
    create(&h, &sb, "c").await.expect_err("create");
    assert_eq!(list_count(&h).await, 1);
    clear(&h);
    let id = RuntimeService::list_containers(
        &h.service,
        Request::new(v1::ListContainersRequest { filter: None }),
    )
    .await
    .unwrap()
    .into_inner()
    .containers[0]
        .id
        .clone();
    *h.runtime.delete_code.lock().unwrap() = Some(ErrorCode::NotFound);
    remove(&h, &id).await.expect("remove");
    assert_eq!(events(&h), vec![Ev::Delete, Ev::Release, Ev::CRemove]);
    assert_eq!(list_count(&h).await, 0);
}

/// CRI-1: 確定版の put の失敗はメモリを確定したまま `INTERNAL`（実行層に資源があるため巻き戻さず、delete も呼ばない）。
#[tokio::test]
async fn cri_1_confirm_put_failure_keeps_created() {
    let h = harness();
    let sb = run_sandbox(&h).await;
    h.store.fail_container_put_at.lock().unwrap().push(1);
    let err = create(&h, &sb, "c").await.expect_err("create");
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(err.message(), INTERNAL_PERSIST);
    assert_eq!(
        events(&h),
        vec![cput("created", "create", "-"), Ev::Prepare, Ev::Create]
    );
    assert_eq!(list_count(&h).await, 1);
}

/// CRI-1: Start の put の失敗は running を確定したまま `INTERNAL`。
#[tokio::test]
async fn cri_1_start_put_failure_keeps_running() {
    let h = harness();
    let sb = run_sandbox(&h).await;
    let id = create(&h, &sb, "c").await.expect("create");
    h.store.fail_container_put_at.lock().unwrap().push(2);
    let err = start(&h, &id).await.expect_err("start");
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(err.message(), INTERNAL_PERSIST);
    assert_eq!(
        status(&h, &id).await.state,
        v1::ContainerState::ContainerRunning as i32
    );
}

/// CRI-1: Stop の put の失敗は exited を確定したまま `INTERNAL`。
#[tokio::test]
async fn cri_1_stop_put_failure_keeps_exited() {
    let h = harness();
    let sb = run_sandbox(&h).await;
    let id = create(&h, &sb, "c").await.expect("create");
    start(&h, &id).await.expect("start");
    h.store.fail_container_put_at.lock().unwrap().push(3);
    let err = stop(&h, &id).await.expect_err("stop");
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(err.message(), INTERNAL_PERSIST);
    assert_eq!(
        status(&h, &id).await.state,
        v1::ContainerState::ContainerExited as i32
    );
}

/// CRI-2: 記録の削除に失敗した Remove は `INTERNAL`、記録は exited で保持され、再試行で回収できる。
#[tokio::test]
async fn cri_2_remove_record_failure_is_retryable() {
    let h = harness();
    let sb = run_sandbox(&h).await;
    let id = create(&h, &sb, "c").await.expect("create");
    clear(&h);
    h.store.fail_container_remove_at.lock().unwrap().push(0);
    let err = remove(&h, &id).await.expect_err("remove");
    assert_eq!(err.code(), Code::Internal);
    assert_eq!(err.message(), INTERNAL_UNPERSIST);
    assert_eq!(events(&h), vec![Ev::Delete, Ev::Release]);
    assert_eq!(
        status(&h, &id).await.state,
        v1::ContainerState::ContainerExited as i32
    );
    clear(&h);
    *h.runtime.delete_code.lock().unwrap() = Some(ErrorCode::NotFound);
    remove(&h, &id).await.expect("retry");
    assert_eq!(events(&h), vec![Ev::Delete, Ev::Release, Ev::CRemove]);
    assert_eq!(list_count(&h).await, 0);
}

/// CRI-2: StopPodSandbox は配下の `Stop → put(exited)` の後に sandbox の状態を書く。
#[tokio::test]
async fn cri_2_stop_sandbox_writes_children_before_sandbox() {
    let h = harness();
    let sb = run_sandbox(&h).await;
    let id = create(&h, &sb, "c").await.expect("create");
    start(&h, &id).await.expect("start");
    clear(&h);
    RuntimeService::stop_pod_sandbox(
        &h.service,
        Request::new(v1::StopPodSandboxRequest {
            pod_sandbox_id: sb.clone(),
        }),
    )
    .await
    .expect("stop sandbox");
    let ev = events(&h);
    let child = ev
        .iter()
        .position(|e| *e == cput("exited", "-", "0"))
        .expect("child exited put");
    assert_eq!(ev[0], Ev::Stop);
    assert_eq!(child, 1);
    assert_eq!(ev.last(), Some(&Ev::SbPut("notready".into())));
}

/// CRI-2: RemovePodSandbox は配下の記録の削除がすべて sandbox の記録の削除より前になる。
#[tokio::test]
async fn cri_2_remove_sandbox_removes_children_before_sandbox() {
    let h = harness();
    let sb = run_sandbox(&h).await;
    create(&h, &sb, "a").await.expect("create a");
    create(&h, &sb, "b").await.expect("create b");
    clear(&h);
    RuntimeService::remove_pod_sandbox(
        &h.service,
        Request::new(v1::RemovePodSandboxRequest {
            pod_sandbox_id: sb.clone(),
        }),
    )
    .await
    .expect("remove sandbox");
    let ev = events(&h);
    let sb_remove = ev
        .iter()
        .position(|e| *e == Ev::SbRemove)
        .expect("sandbox remove");
    let child_removes: Vec<usize> = ev
        .iter()
        .enumerate()
        .filter(|(_, e)| **e == Ev::CRemove)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(child_removes.len(), 2);
    assert!(child_removes.iter().all(|i| *i < sb_remove));
}

/// REPAIR-3: スタブ経路（`with_runtime` 未注入）と記録ストア未注入では、コンテナ記録を書かない。
#[tokio::test]
async fn repair_3_stub_and_storeless_paths_write_no_container_records() {
    for (with_store, with_runtime) in [(true, false), (false, true)] {
        let h = build(with_store, with_runtime, None);
        let sb = run_sandbox(&h).await;
        let id = create(&h, &sb, "c").await.expect("create");
        start(&h, &id).await.expect("start");
        stop(&h, &id).await.expect("stop");
        remove(&h, &id).await.expect("remove");
        let ev = events(&h);
        assert!(
            !ev.iter()
                .any(|e| matches!(e, Ev::CPut { .. } | Ev::CRemove)),
            "unexpected container record I/O: {ev:?}"
        );
    }
}

/// REPAIR-5: write-ahead の put が止まったまま RPC の期限が切れたら `DEADLINE_EXCEEDED`。ゲート解放後、
/// worker は prepare せず（手放し済み）記録を消してメモリを除去する。
#[tokio::test]
async fn repair_5_abandoned_create_does_not_prepare_and_cleans_up() {
    let h = build(true, true, Some(Duration::from_millis(200)));
    let sb = run_sandbox(&h).await;
    *h.store.block_container_put_at.lock().unwrap() = Some(0);
    let err = create(&h, &sb, "c").await.expect_err("create");
    assert_eq!(err.code(), Code::DeadlineExceeded);
    h.gate.entered.recv_timeout(WAIT).expect("put entered");
    h.gate.release.send(()).unwrap();
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if events(&h).contains(&Ev::CRemove) && list_count(&h).await == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!h.bundles.prepared.load(Ordering::SeqCst));
    assert!(!h.runtime.create_started.load(Ordering::SeqCst));
    assert!(events(&h).contains(&Ev::CRemove));
    assert_eq!(list_count(&h).await, 0);
    let _ = h.bundles.hold_prepare_until.lock().unwrap().take();
}
