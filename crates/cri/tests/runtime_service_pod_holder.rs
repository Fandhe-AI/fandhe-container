//! pod の namespace の保持役（`PodNamespaceHolderProvider`）の注入点と、sandbox 記録への pid の保持の試験
//! （CRI-2・CORE-3・REPAIR-3・REPAIR-5・REPAIR-12。#2871）。
//!
//! フェイクの provider だけで、`RunPodSandbox` の起動・失敗・期限超過、Stop・Remove の解放の冪等と再試行、
//! 保持役の死亡の Status・List・`CreateContainer` への反映を具体値で確かめる。本番の provider は H6（#2877）。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_cri::adapter::{
    PodHolder, PodHolderLiveness, PodHolderRequest, PodNamespaceHolderProvider, PodNetns,
    PodNetworkProvider, PodNetworkRequest,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    PodSandboxState, runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::{
    CriRuntimeService, ListBudget, ListLimits, RecordId, RecordKind, RecordListing, RecordStore,
};
use tonic::{Code, Request};

type Log = Arc<Mutex<Vec<String>>>;

#[derive(Clone, Copy, PartialEq)]
enum Spawn {
    Ok,
    Fail(Code),
    /// 解除されるまで待つ（`unblock` を立てる）。
    Hang,
}

#[derive(Clone, Copy, PartialEq)]
enum Live {
    Alive,
    Exited,
    Unknown,
}

struct FakeHolder {
    log: Log,
    spawn: Mutex<Spawn>,
    release_fails: AtomicBool,
    live: Mutex<Live>,
    unblock: AtomicBool,
    pid: u32,
}

impl FakeHolder {
    fn new(log: &Log, spawn: Spawn) -> Arc<Self> {
        Arc::new(Self {
            log: Arc::clone(log),
            spawn: Mutex::new(spawn),
            release_fails: AtomicBool::new(false),
            live: Mutex::new(Live::Alive),
            unblock: AtomicBool::new(false),
            pid: 4242,
        })
    }
    fn count(&self, prefix: &str) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with(prefix))
            .count()
    }
}

impl PodNamespaceHolderProvider for FakeHolder {
    fn spawn(&self, req: &PodHolderRequest<'_>) -> Result<PodHolder, CriError> {
        self.log
            .lock()
            .unwrap()
            .push(format!("spawn {}", req.sandbox_id));
        match *self.spawn.lock().unwrap() {
            Spawn::Ok => Ok(PodHolder::new(self.pid.try_into().unwrap())),
            Spawn::Fail(Code::DeadlineExceeded) => Err(CriError::timeout("holder not ready")),
            Spawn::Fail(_) => Err(CriError::failed_precondition("holder unavailable")),
            Spawn::Hang => {
                let start = Instant::now();
                while !self.unblock.load(Ordering::SeqCst)
                    && start.elapsed() < Duration::from_secs(10)
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(PodHolder::new(self.pid.try_into().unwrap()))
            }
        }
    }
    fn release(&self, sandbox_id: &str, _timeout: Duration) -> Result<(), CriError> {
        self.log
            .lock()
            .unwrap()
            .push(format!("release {sandbox_id}"));
        if self.release_fails.load(Ordering::SeqCst) {
            Err(CriError::internal("release failed"))
        } else {
            Ok(())
        }
    }
    fn liveness(&self, _sandbox_id: &str) -> Result<PodHolderLiveness, CriError> {
        match *self.live.lock().unwrap() {
            Live::Alive => Ok(PodHolderLiveness::Alive),
            Live::Exited => Ok(PodHolderLiveness::Exited),
            Live::Unknown => Err(CriError::internal("liveness unknown")),
        }
    }
}

struct FakeNet {
    log: Log,
    fail_set_up: bool,
}

impl PodNetworkProvider for FakeNet {
    fn set_up(&self, req: &PodNetworkRequest<'_>) -> Result<PodNetns, CriError> {
        self.log.lock().unwrap().push("set_up".into());
        if self.fail_set_up {
            return Err(CriError::failed_precondition("network unavailable"));
        }
        PodNetns::new(std::path::PathBuf::from(format!(
            "/state/.netns/{}",
            req.sandbox_id
        )))
    }
    fn tear_down(&self, _sandbox_id: &str) -> Result<(), CriError> {
        self.log.lock().unwrap().push("tear_down".into());
        Ok(())
    }
}

/// 書き込みの順序だけを記録するフェイクの記録ストア（`put` は `pending` の値を行に残す）。
#[derive(Debug)]
struct FakeStore {
    log: Log,
}

impl RecordStore for FakeStore {
    fn put(&self, _kind: RecordKind, _id: &RecordId, bytes: &[u8]) -> Result<(), CriError> {
        let text = String::from_utf8_lossy(bytes);
        let pending = text
            .lines()
            .find_map(|l| l.strip_prefix("pending="))
            .unwrap_or("?")
            .to_owned();
        self.log
            .lock()
            .unwrap()
            .push(format!("put pending={pending}"));
        Ok(())
    }
    fn remove(&self, _kind: RecordKind, _id: &RecordId) -> Result<(), CriError> {
        self.log.lock().unwrap().push("remove".into());
        Ok(())
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

fn new_log() -> Log {
    Arc::new(Mutex::new(Vec::new()))
}

fn service(holder: &Arc<FakeHolder>) -> CriRuntimeService {
    CriRuntimeService::new()
        .with_pod_holder(holder.clone())
        .with_runtime_timeout(Duration::from_millis(300))
}

fn run_req() -> v1::RunPodSandboxRequest {
    v1::RunPodSandboxRequest {
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
    }
}

async fn run(svc: &CriRuntimeService) -> Result<String, tonic::Status> {
    RuntimeService::run_pod_sandbox(svc, Request::new(run_req()))
        .await
        .map(|r| r.into_inner().pod_sandbox_id)
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

async fn state_of(svc: &CriRuntimeService, id: &str) -> i32 {
    RuntimeService::pod_sandbox_status(
        svc,
        Request::new(v1::PodSandboxStatusRequest {
            pod_sandbox_id: id.into(),
            verbose: false,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .status
    .unwrap()
    .state
}

async fn list(svc: &CriRuntimeService) -> Vec<(String, i32)> {
    RuntimeService::list_pod_sandbox(svc, Request::new(v1::ListPodSandboxRequest::default()))
        .await
        .unwrap()
        .into_inner()
        .items
        .into_iter()
        .map(|i| (i.id, i.state))
        .collect()
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

const READY: i32 = PodSandboxState::SandboxReady as i32;
const NOTREADY: i32 = PodSandboxState::SandboxNotready as i32;

#[tokio::test]
async fn cri2_run_spawns_the_holder_once_and_becomes_ready() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let svc = service(&holder);
    let id = run(&svc).await.unwrap();
    assert_eq!(*log.lock().unwrap(), vec![format!("spawn {id}")]);
    assert_eq!(state_of(&svc, &id).await, READY);
    assert!(create_container(&svc, &id).await.is_ok());
}

#[tokio::test]
async fn cri2_spawn_failure_registers_nothing_and_allows_rerun() {
    for code in [Code::FailedPrecondition, Code::DeadlineExceeded] {
        let log = new_log();
        let holder = FakeHolder::new(&log, Spawn::Fail(code));
        let svc = service(&holder);
        let e = run(&svc).await.unwrap_err();
        assert_eq!(e.code(), code);
        assert!(list(&svc).await.is_empty());
        assert_eq!(holder.count("release"), 0);
        // 予約が戻っているので、同じ metadata の再 Run が成功する。
        *holder.spawn.lock().unwrap() = Spawn::Ok;
        let id = run(&svc).await.unwrap();
        assert_eq!(state_of(&svc, &id).await, READY);
    }
}

#[tokio::test]
async fn repair5_outer_deadline_keeps_a_notready_record_and_releases_the_late_holder() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Hang);
    let svc = service(&holder);
    let e = run(&svc).await.unwrap_err();
    assert_eq!(e.code(), Code::DeadlineExceeded);
    let items = list(&svc).await;
    assert_eq!(items.len(), 1);
    let id = items[0].0.clone();
    assert_eq!(items[0].1, NOTREADY);
    // worker の完了までは Stop・Remove・Create が拒否される。
    assert_eq!(
        stop(&svc, &id).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        remove(&svc, &id).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        create_container(&svc, &id).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    // 遅れて完了した保持役は NotReady のまま記録にだけ残り、Remove の解放で消える。
    holder.unblock.store(true, Ordering::SeqCst);
    let start = Instant::now();
    loop {
        match remove(&svc, &id).await {
            Ok(()) => break,
            Err(e) => {
                assert_eq!(e.code(), Code::FailedPrecondition);
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "remove never succeeded"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    assert_eq!(holder.count("release"), 1);
    assert!(list(&svc).await.is_empty());
}

/// 保持役の起動待ち中に RunPodSandbox の future が破棄されても `network_pending` が残らず、
/// Stop・Remove と同 metadata の再 Run が通ること（#2871・CRI-2・REPAIR-5）。
#[tokio::test]
async fn repair5_dropped_run_during_holder_spawn_does_not_leave_network_pending() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Hang);
    let net = Arc::new(FakeNet {
        log: Arc::clone(&log),
        fail_set_up: false,
    });
    let svc = service(&holder).with_pod_network(net);
    let dropped = tokio::time::timeout(Duration::from_millis(50), run(&svc)).await;
    assert!(dropped.is_err(), "run must still be awaiting the holder");
    let items = list(&svc).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].1, NOTREADY);
    let id = items[0].0.clone();
    // 保持役の worker が終わると、Remove が解放して記録を消せる（network_pending で塞がれない）。
    holder.unblock.store(true, Ordering::SeqCst);
    let start = Instant::now();
    loop {
        match remove(&svc, &id).await {
            Ok(()) => break,
            Err(e) => {
                assert_eq!(e.code(), Code::FailedPrecondition);
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "remove never succeeded"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    assert_eq!(holder.count("release"), 1);
    assert!(list(&svc).await.is_empty());
    assert!(!log.lock().unwrap().iter().any(|l| l == "set_up"));
    // 同じ metadata の再 Run が通る。
    *holder.spawn.lock().unwrap() = Spawn::Ok;
    run(&svc).await.unwrap();
}

#[tokio::test]
async fn cri2_stop_releases_once_and_is_idempotent() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let svc = service(&holder);
    let id = run(&svc).await.unwrap();
    stop(&svc, &id).await.unwrap();
    assert_eq!(holder.count("release"), 1);
    stop(&svc, &id).await.unwrap();
    assert_eq!(holder.count("release"), 1);
    assert_eq!(state_of(&svc, &id).await, NOTREADY);
    remove(&svc, &id).await.unwrap();
    assert_eq!(holder.count("release"), 1);
    assert!(list(&svc).await.is_empty());
}

#[tokio::test]
async fn repair5_release_failure_keeps_the_record_and_retry_succeeds() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let svc = service(&holder);
    let id = run(&svc).await.unwrap();
    holder.release_fails.store(true, Ordering::SeqCst);
    assert_eq!(stop(&svc, &id).await.unwrap_err().code(), Code::Internal);
    assert_eq!(remove(&svc, &id).await.unwrap_err().code(), Code::Internal);
    assert_eq!(list(&svc).await.len(), 1);
    assert_eq!(holder.count("release"), 2);
    holder.release_fails.store(false, Ordering::SeqCst);
    remove(&svc, &id).await.unwrap();
    assert_eq!(holder.count("release"), 3);
    assert!(list(&svc).await.is_empty());
}

#[tokio::test]
async fn cri2_remove_of_a_ready_sandbox_releases_before_removal() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let svc = service(&holder);
    let id = run(&svc).await.unwrap();
    remove(&svc, &id).await.unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec![format!("spawn {id}"), format!("release {id}")]
    );
    assert!(list(&svc).await.is_empty());
}

#[tokio::test]
async fn cri2_dead_holder_makes_status_list_and_create_notready() {
    for dead in [Live::Exited, Live::Unknown] {
        let log = new_log();
        let holder = FakeHolder::new(&log, Spawn::Ok);
        let svc = service(&holder);
        let id = run(&svc).await.unwrap();
        *holder.live.lock().unwrap() = dead;
        assert_eq!(state_of(&svc, &id).await, NOTREADY);
        assert_eq!(list(&svc).await, vec![(id.clone(), NOTREADY)]);
        let e = create_container(&svc, &id).await.unwrap_err();
        assert_eq!(e.code(), Code::FailedPrecondition);
        assert_eq!(e.message(), "sandbox is not ready");
        // 一方向: Alive に戻っても Ready へは戻らない。
        *holder.live.lock().unwrap() = Live::Alive;
        assert_eq!(state_of(&svc, &id).await, NOTREADY);
        // 死んだ保持役の記録も Stop・Remove で解放して消せる。
        remove(&svc, &id).await.unwrap();
        assert_eq!(holder.count("release"), 1);
    }
}

#[tokio::test]
async fn cri2_create_checks_liveness_without_a_prior_status() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let svc = service(&holder);
    let id = run(&svc).await.unwrap();
    *holder.live.lock().unwrap() = Live::Exited;
    let e = create_container(&svc, &id).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn cri2_holder_is_spawned_before_set_up_and_released_after_tear_down() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let net = Arc::new(FakeNet {
        log: Arc::clone(&log),
        fail_set_up: false,
    });
    let svc = service(&holder).with_pod_network(net);
    let id = run(&svc).await.unwrap();
    stop(&svc, &id).await.unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            format!("spawn {id}"),
            "set_up".to_owned(),
            "tear_down".to_owned(),
            format!("release {id}"),
        ]
    );
}

#[tokio::test]
async fn cri2_set_up_failure_unwinds_in_reverse_order() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let net = Arc::new(FakeNet {
        log: Arc::clone(&log),
        fail_set_up: true,
    });
    let svc = service(&holder).with_pod_network(net);
    let e = run(&svc).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    let calls = log.lock().unwrap().clone();
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert!(calls[0].starts_with("spawn "));
    assert_eq!(calls[1], "set_up");
    assert_eq!(calls[2], "tear_down");
    assert!(calls[3].starts_with("release "));
    assert!(list(&svc).await.is_empty());
}

#[tokio::test]
async fn cri1_write_ahead_pending_precedes_spawn_and_confirm_follows() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let store = Arc::new(FakeStore {
        log: Arc::clone(&log),
    });
    let svc = service(&holder).with_record_store(store);
    let id = run(&svc).await.unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "put pending=1".to_owned(),
            format!("spawn {id}"),
            "put pending=0".to_owned(),
        ]
    );
}

#[tokio::test]
async fn cri1_spawn_failure_removes_the_pending_record_file() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Fail(Code::FailedPrecondition));
    let store = Arc::new(FakeStore {
        log: Arc::clone(&log),
    });
    let svc = service(&holder).with_record_store(store);
    assert!(run(&svc).await.is_err());
    let calls = log.lock().unwrap().clone();
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert_eq!(calls[0], "put pending=1");
    assert!(calls[1].starts_with("spawn "));
    assert_eq!(calls[2], "remove");
    assert!(list(&svc).await.is_empty());
}

#[tokio::test]
async fn cri2_without_a_holder_provider_nothing_is_called() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let svc = CriRuntimeService::new();
    let id = run(&svc).await.unwrap();
    assert_eq!(state_of(&svc, &id).await, READY);
    stop(&svc, &id).await.unwrap();
    remove(&svc, &id).await.unwrap();
    assert!(log.lock().unwrap().is_empty());
    assert_eq!(holder.count(""), 0);
}
