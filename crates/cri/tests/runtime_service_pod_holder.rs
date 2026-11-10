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
    /// 回収を確認できない子が残る失敗（資源残存の印つき）。
    FailRetained,
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
    release_hangs: AtomicBool,
    /// `release` が受け取った期限の記録（#4418。時間に依存しない照合用）。
    release_timeouts: Mutex<Vec<Duration>>,
    pid: u32,
}

impl FakeHolder {
    fn new(log: &Log, spawn: Spawn) -> Arc<Self> {
        Self::with_pid(log, spawn, 4242)
    }
    fn with_pid(log: &Log, spawn: Spawn, pid: u32) -> Arc<Self> {
        Arc::new(Self {
            log: Arc::clone(log),
            spawn: Mutex::new(spawn),
            release_fails: AtomicBool::new(false),
            live: Mutex::new(Live::Alive),
            unblock: AtomicBool::new(false),
            release_hangs: AtomicBool::new(false),
            release_timeouts: Mutex::new(Vec::new()),
            pid,
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
            Spawn::FailRetained => {
                Err(CriError::timeout("holder not ready").with_resource_retained())
            }
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
    fn release(&self, sandbox_id: &str, timeout: Duration) -> Result<(), CriError> {
        self.release_timeouts.lock().unwrap().push(timeout);
        self.log
            .lock()
            .unwrap()
            .push(format!("release {sandbox_id}"));
        if self.release_hangs.load(Ordering::SeqCst) {
            let start = Instant::now();
            while !self.unblock.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(3) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
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

#[derive(Default)]
struct FakeNet {
    log: Log,
    fail_set_up: bool,
    /// 保持役の netns と違うパスを返す（契約違反の provider。#2878）。
    wrong_path: bool,
    /// `set_up` が受けた保持役の (user, ipc, net)。
    seen: Mutex<Vec<Option<(String, String, String)>>>,
}

impl PodNetworkProvider for FakeNet {
    fn set_up(&self, req: &PodNetworkRequest<'_>) -> Result<PodNetns, CriError> {
        self.log.lock().unwrap().push("set_up".into());
        if self.fail_set_up {
            return Err(CriError::failed_precondition("network unavailable"));
        }
        self.seen.lock().unwrap().push(
            req.holder_namespaces()
                .map(|h| (h.user().to_owned(), h.ipc().to_owned(), h.net().to_owned())),
        );
        // 契約: 保持役があるときはその netns をそのまま返す（#2878）。
        match req.holder_namespaces() {
            Some(h) if !self.wrong_path => PodNetns::new(std::path::PathBuf::from(h.net())),
            _ => PodNetns::new(std::path::PathBuf::from(format!(
                "/state/.netns/{}",
                req.sandbox_id
            ))),
        }
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

/// 試験で使う `runtime_timeout`（共有期限）。
const RUNTIME_TIMEOUT: Duration = Duration::from_millis(300);

/// `src/runtime_service/pod_holder.rs` の private 定数 `HOLDER_OUTER_SLACK`（外側の余裕 500ms）の写し。
/// 本体の値を変えたらここも直す（#4418。公開 API は広げない）。
const HOLDER_OUTER_SLACK: Duration = Duration::from_millis(500);

fn service(holder: &Arc<FakeHolder>) -> CriRuntimeService {
    CriRuntimeService::new()
        .with_pod_holder(holder.clone())
        .with_runtime_timeout(RUNTIME_TIMEOUT)
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

/// REPAIR-5・CRI-2: 資源残存の印つきの起動失敗は記録を消さず、Stop・Remove の `release` が再試行できる。
#[tokio::test]
async fn repair5_retained_spawn_failure_keeps_the_record_and_release_retries() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::FailRetained);
    let svc = service(&holder);
    let e = run(&svc).await.unwrap_err();
    assert_eq!(e.code(), Code::DeadlineExceeded);
    let listed = list(&svc).await;
    assert_eq!(listed.len(), 1);
    assert_ne!(listed[0].1, READY);
    let id = listed[0].0.clone();
    holder.release_fails.store(true, Ordering::SeqCst);
    assert_eq!(remove(&svc, &id).await.unwrap_err().code(), Code::Internal);
    assert_eq!(list(&svc).await.len(), 1);
    holder.release_fails.store(false, Ordering::SeqCst);
    remove(&svc, &id).await.unwrap();
    assert_eq!(holder.count("release"), 2);
    assert!(list(&svc).await.is_empty());
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
        ..Default::default()
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

/// network なしの Run が保持役の起動待ち中に取り消され、worker が後から成功しても Ready を公開せず
/// CreateContainer が通らないこと（CRI-2 の fail-closed・REPAIR-5・#2871）。
#[tokio::test]
async fn cri2_dropped_run_then_late_holder_success_stays_notready() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Hang);
    let svc = service(&holder);
    let dropped = tokio::time::timeout(Duration::from_millis(50), run(&svc)).await;
    assert!(dropped.is_err(), "run must still be awaiting the holder");
    let items = list(&svc).await;
    assert_eq!(items.len(), 1);
    let id = items[0].0.clone();
    holder.unblock.store(true, Ordering::SeqCst);
    // worker が成功を確定するまで待つ（Remove が受理される = 保持役の確定後）が、その前に状態を観測する。
    let start = Instant::now();
    loop {
        assert_eq!(state_of(&svc, &id).await, NOTREADY);
        assert!(create_container(&svc, &id).await.is_err());
        if start.elapsed() > Duration::from_millis(500) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(state_of(&svc, &id).await, NOTREADY);
    assert!(create_container(&svc, &id).await.is_err());
    remove(&svc, &id).await.unwrap();
    assert_eq!(holder.count("release"), 1);
}

/// 記録ストアなしでも、保持役の起動中は並行する Stop・Remove が `FAILED_PRECONDITION` で拒否され、
/// 起動の完了後は受理されること（予約時に `holder_pending` を立てる。CRI-2・REPAIR-5・#2871）。
#[tokio::test]
async fn cri2_stop_and_remove_are_rejected_while_holder_spawn_is_in_flight() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Hang);
    let svc = Arc::new(service(&holder));
    let run_svc = Arc::clone(&svc);
    let task = tokio::spawn(async move { run(&run_svc).await });
    let start = Instant::now();
    let id = loop {
        let items = list(&svc).await;
        if let Some((id, _)) = items.first() {
            break id.clone();
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert_eq!(
        stop(&svc, &id).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    assert_eq!(
        remove(&svc, &id).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    assert_eq!(holder.count("release"), 0);
    holder.unblock.store(true, Ordering::SeqCst);
    assert_eq!(task.await.unwrap().unwrap(), id);
    assert_eq!(state_of(&svc, &id).await, READY);
    stop(&svc, &id).await.unwrap();
    assert_eq!(holder.count("release"), 1);
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

/// REPAIR-5・CRI-2（#3142・#4418）: release が戻らなくても Remove 全体は runtime_timeout（300ms）で頭打ちになる
/// （外側の余裕 500ms を足して約 800ms 待たない）。
///
/// 閾値の根拠: 正しい実装は約 300ms。回帰（期限なし分岐と同じ `outer = 300 + 500`）は
/// `recv_timeout` が期限より早く戻らないため 800ms 以上が決定的に保証される。上限は 650ms とし、
/// 正しい値から 350ms の揺れ（macOS で観測した超過は約 153ms）を吸収しつつ回帰の下限より 150ms 短く保つ。
/// 時間に依存しない補強として、provider へ渡された期限が共有期限の半分以下であることも照合する。
#[tokio::test]
async fn repair5_remove_with_hanging_release_is_capped_at_runtime_timeout() {
    let upper = RUNTIME_TIMEOUT + HOLDER_OUTER_SLACK - Duration::from_millis(150);
    assert!(upper > RUNTIME_TIMEOUT);
    assert!(upper < RUNTIME_TIMEOUT + HOLDER_OUTER_SLACK);
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let svc = service(&holder);
    let id = run(&svc).await.unwrap();
    holder.release_hangs.store(true, Ordering::SeqCst);
    let start = Instant::now();
    let err = remove(&svc, &id).await.unwrap_err();
    let elapsed = start.elapsed();
    holder.unblock.store(true, Ordering::SeqCst);
    assert_eq!(err.code(), Code::DeadlineExceeded);
    assert!(
        elapsed < upper,
        "remove waited {elapsed:?}, upper bound {upper:?}"
    );
    let timeouts = holder.release_timeouts.lock().unwrap().clone();
    assert_eq!(timeouts.len(), 1, "release timeouts: {timeouts:?}");
    assert!(
        timeouts[0] <= RUNTIME_TIMEOUT / 2,
        "release got {:?}",
        timeouts[0]
    );
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
        ..Default::default()
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
        ..Default::default()
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

/// 確定版（pending=0）の put だけを一定時間止める記録ストア。
#[derive(Debug)]
struct SlowConfirmStore;

impl RecordStore for SlowConfirmStore {
    fn put(&self, _kind: RecordKind, _id: &RecordId, bytes: &[u8]) -> Result<(), CriError> {
        if String::from_utf8_lossy(bytes)
            .lines()
            .any(|l| l == "pending=0")
        {
            std::thread::sleep(Duration::from_millis(400));
        }
        Ok(())
    }
    fn remove(&self, _kind: RecordKind, _id: &RecordId) -> Result<(), CriError> {
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

/// 保持役の起動後・確定版の記録が書き終わる前に RunPodSandbox の future が破棄されても、sandbox は
/// NotReady のままで CreateContainer が拒否されること（CRI-2 の fail-closed・REPAIR-5・#2871）。
#[tokio::test]
async fn cri2_run_dropped_after_holder_ready_before_confirm_stays_notready() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let svc = service(&holder).with_record_store(Arc::new(SlowConfirmStore));
    let dropped = tokio::time::timeout(Duration::from_millis(100), run(&svc)).await;
    assert!(dropped.is_err(), "run must still be awaiting the confirm");
    let items = list(&svc).await;
    assert_eq!(items.len(), 1);
    let id = items[0].0.clone();
    assert_eq!(items[0].1, NOTREADY);
    assert_eq!(state_of(&svc, &id).await, NOTREADY);
    assert!(create_container(&svc, &id).await.is_err());
}

/// NET-3・SEC-5（#2878）: `set_up` は自 sandbox の保持役の pid の `/proc/<pid>/ns/{user,ipc,net}` を受ける。
#[tokio::test]
async fn net3_set_up_receives_the_holder_namespaces_of_its_own_sandbox() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let net = Arc::new(FakeNet {
        log: Arc::clone(&log),
        ..Default::default()
    });
    let svc = service(&holder).with_pod_network(net.clone());
    run(&svc).await.unwrap();
    assert_eq!(
        *net.seen.lock().unwrap(),
        vec![Some((
            "/proc/4242/ns/user".to_owned(),
            "/proc/4242/ns/ipc".to_owned(),
            "/proc/4242/ns/net".to_owned()
        ))]
    );
}

/// NET-3（#2878）: 保持役の netns と違うパスを返す provider は採用せず、逆順に回収して記録を残さない。
#[tokio::test]
async fn net3_provider_path_mismatch_is_internal_and_unwinds() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let net = Arc::new(FakeNet {
        log: Arc::clone(&log),
        wrong_path: true,
        ..Default::default()
    });
    let svc = service(&holder).with_pod_network(net);
    let e = run(&svc).await.unwrap_err();
    assert_eq!(e.code(), Code::Internal);
    assert_eq!(
        e.message(),
        "pod network provider did not wire the holder network namespace"
    );
    let calls = log.lock().unwrap().clone();
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert!(calls[0].starts_with("spawn "));
    assert_eq!(calls[1], "set_up");
    assert_eq!(calls[2], "tear_down");
    assert!(calls[3].starts_with("release "));
    assert!(list(&svc).await.is_empty());
}

/// CRI-2・REPAIR-5（#2878）: 保持役の pid が範囲外（i32::MAX 超）で巻き戻しの解放待ち中に RunPodSandbox の
/// future が破棄されても `network_pending` が残らず、Stop・Remove が拒否され続けないこと。
#[tokio::test]
async fn repair5_dropped_run_during_out_of_range_pid_rollback_does_not_leave_network_pending() {
    let log = new_log();
    let holder = FakeHolder::with_pid(&log, Spawn::Ok, i32::MAX as u32 + 1);
    holder.release_hangs.store(true, Ordering::SeqCst);
    let net = Arc::new(FakeNet {
        log: Arc::clone(&log),
        ..Default::default()
    });
    let svc = service(&holder).with_pod_network(net);
    let dropped = tokio::time::timeout(Duration::from_millis(100), run(&svc)).await;
    assert!(dropped.is_err(), "run must still be awaiting the rollback");
    assert!(!log.lock().unwrap().iter().any(|l| l == "set_up"));
    let items = list(&svc).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].1, NOTREADY);
    let id = items[0].0.clone();
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
    assert!(list(&svc).await.is_empty());
}

/// NET-3・CRI-2（#2878）: provider なし・保持役ありの `POD` は `NetworkReady` を偽に保ち、Status の network は空。
#[tokio::test]
async fn net3_without_provider_status_network_stays_empty() {
    let log = new_log();
    let holder = FakeHolder::new(&log, Spawn::Ok);
    let svc = service(&holder);
    let id = run(&svc).await.unwrap();
    let st = RuntimeService::pod_sandbox_status(
        &svc,
        Request::new(v1::PodSandboxStatusRequest {
            pod_sandbox_id: id,
            verbose: false,
        }),
    )
    .await
    .unwrap()
    .into_inner()
    .status
    .unwrap();
    assert!(st.network.is_none_or(|n| n.ip.is_empty()));
}
