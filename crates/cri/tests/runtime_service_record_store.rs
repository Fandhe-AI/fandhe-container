//! sandbox 記録の書く・消す時点と `with_record_store` の注入点の試験（CRI-1・CRI-2・REPAIR-3・REPAIR-5。#2933）。
//!
//! フェイクの `RecordStore` と `PodNetworkProvider` が同じイベント列へ書く順序を、具体値で照合する。
//! 書かれたバイト列は公開 API から復号できないため、固定ヘッダの行（`pending=` `state=` 等）で照合する。

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_cri::adapter::{PodNetns, PodNetworkProvider, PodNetworkRequest};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ImageSpec, PodSandboxConfig, PodSandboxMetadata,
    runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::{
    CriRuntimeService, ListBudget, ListLimits, RecordId, RecordKind, RecordListing, RecordStore,
};
use tonic::{Code, Request};

#[derive(Debug, Clone, PartialEq)]
enum Ev {
    /// `put`（ヘッダから読んだ値）。
    Put {
        pending: bool,
        state: String,
        owned: bool,
        net_pending: bool,
    },
    Remove,
    SetUp,
    TearDown,
}

/// 試験内の全待機の上限（回帰時にも有限時間で失敗させる。REPAIR-5）。
const WAIT: Duration = Duration::from_secs(10);

type Log = Arc<Mutex<Vec<Ev>>>;

fn header(bytes: &[u8], key: &str) -> String {
    let text = String::from_utf8_lossy(bytes);
    let prefix = format!("{key}=");
    text.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()).map(str::to_owned))
        .unwrap_or_default()
}

/// N 回目（0 起点）の `put` / `remove` を `DEADLINE_EXCEEDED` で失敗させ、任意の `put` で止められるフェイク。
#[derive(Debug)]
struct FakeStore {
    log: Log,
    puts: Mutex<usize>,
    removes: Mutex<usize>,
    fail_put_at: Mutex<Vec<usize>>,
    fail_remove_at: Mutex<Vec<usize>>,
    block_put_at: Mutex<Option<usize>>,
    block_remove_at: Mutex<Option<usize>>,
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
                puts: Mutex::new(0),
                removes: Mutex::new(0),
                fail_put_at: Mutex::new(Vec::new()),
                fail_remove_at: Mutex::new(Vec::new()),
                block_put_at: Mutex::new(None),
                block_remove_at: Mutex::new(None),
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
        assert_eq!(kind, RecordKind::Sandbox);
        let n = {
            let mut p = self.puts.lock().unwrap();
            let n = *p;
            *p += 1;
            n
        };
        if *self.block_put_at.lock().unwrap() == Some(n) {
            self.entered.lock().unwrap().send(()).unwrap();
            let released = self.release.lock().unwrap().recv_timeout(WAIT).is_ok();
            if !released {
                return Err(CriError::timeout("test gate was not released"));
            }
        }
        if self.fail_put_at.lock().unwrap().contains(&n) {
            return Err(CriError::timeout("injected"));
        }
        self.log.lock().unwrap().push(Ev::Put {
            pending: header(bytes, "pending") == "1",
            state: header(bytes, "state"),
            owned: header(bytes, "network_owned") == "1",
            net_pending: header(bytes, "network_pending") == "1",
        });
        Ok(())
    }

    fn remove(&self, kind: RecordKind, _id: &RecordId) -> Result<(), CriError> {
        assert_eq!(kind, RecordKind::Sandbox);
        let n = {
            let mut r = self.removes.lock().unwrap();
            let n = *r;
            *r += 1;
            n
        };
        if *self.block_remove_at.lock().unwrap() == Some(n) {
            self.entered.lock().unwrap().send(()).unwrap();
            if self.release.lock().unwrap().recv_timeout(WAIT).is_err() {
                return Err(CriError::timeout("test gate was not released"));
            }
        }
        if self.fail_remove_at.lock().unwrap().contains(&n) {
            return Err(CriError::timeout("injected"));
        }
        self.log.lock().unwrap().push(Ev::Remove);
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

struct FakeNet {
    log: Log,
    fail_set_up: bool,
}

impl PodNetworkProvider for FakeNet {
    fn set_up(&self, req: &PodNetworkRequest<'_>) -> Result<PodNetns, CriError> {
        self.log.lock().unwrap().push(Ev::SetUp);
        if self.fail_set_up {
            return Err(CriError::failed_precondition("network unavailable"));
        }
        PodNetns::new(std::path::PathBuf::from(format!(
            "/state/.netns/{}",
            req.sandbox_id
        )))
    }
    fn tear_down(&self, _sandbox_id: &str) -> Result<(), CriError> {
        self.log.lock().unwrap().push(Ev::TearDown);
        Ok(())
    }
}

fn put(pending: bool, state: &str, owned: bool, net_pending: bool) -> Ev {
    Ev::Put {
        pending,
        state: state.to_owned(),
        owned,
        net_pending,
    }
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

async fn list(svc: &CriRuntimeService) -> Vec<v1::PodSandbox> {
    RuntimeService::list_pod_sandbox(svc, Request::new(v1::ListPodSandboxRequest::default()))
        .await
        .unwrap()
        .into_inner()
        .items
}

fn events(log: &Log) -> Vec<Ev> {
    log.lock().unwrap().clone()
}

fn plain() -> (CriRuntimeService, Arc<FakeStore>, Gate, Log) {
    let log: Log = Arc::default();
    let (store, gate) = FakeStore::new(&log);
    (
        CriRuntimeService::new().with_record_store(store.clone()),
        store,
        gate,
        log,
    )
}

fn networked(fail_set_up: bool) -> (CriRuntimeService, Arc<FakeStore>, Gate, Log) {
    let log: Log = Arc::default();
    let (store, gate) = FakeStore::new(&log);
    let net = Arc::new(FakeNet {
        log: Arc::clone(&log),
        fail_set_up,
    });
    (
        CriRuntimeService::new()
            .with_pod_network(net)
            .with_record_store(store.clone()),
        store,
        gate,
        log,
    )
}

/// CRI-1: ネットワークなしの Run は確定版を 1 回だけ書く。
#[tokio::test]
async fn plain_run_writes_the_confirmed_record_once() {
    let (svc, _s, _g, log) = plain();
    run(&svc).await.unwrap();
    assert_eq!(events(&log), vec![put(false, "ready", false, false)]);
}

/// CRI-2: pod network ありの Run は pending → set_up → 確定の順に書く（write-ahead）。
#[tokio::test]
async fn networked_run_writes_pending_before_set_up_then_confirms() {
    let (svc, _s, _g, log) = networked(false);
    run(&svc).await.unwrap();
    assert_eq!(
        events(&log),
        vec![
            put(true, "notready", false, true),
            Ev::SetUp,
            put(false, "ready", true, false),
        ]
    );
}

/// 副作用の前の書き込みが失敗したら set_up を呼ばず、`INTERNAL` で失敗し、予約も残さない。
#[tokio::test]
async fn failed_write_ahead_skips_set_up_and_leaves_no_reservation() {
    let (svc, store, _g, log) = networked(false);
    store.fail_put_at.lock().unwrap().push(0);
    let e = run(&svc).await.unwrap_err();
    assert_eq!(e.code(), Code::Internal);
    assert_eq!(e.message(), "sandbox record could not be persisted");
    assert!(!events(&log).contains(&Ev::SetUp));
    assert!(list(&svc).await.is_empty());
    // 同じ metadata で再実行できる。
    run(&svc).await.unwrap();
}

/// 確定の書き込みが失敗したら成功を装わず、メモリの記録は NotReady で残る。
#[tokio::test]
async fn failed_confirmation_keeps_a_notready_record_and_returns_internal() {
    let (svc, store, _g, _log) = networked(false);
    store.fail_put_at.lock().unwrap().push(1);
    let e = run(&svc).await.unwrap_err();
    assert_eq!(e.code(), Code::Internal);
    let items = list(&svc).await;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].state, v1::PodSandboxState::SandboxNotready as i32);
}

/// ネットワークなしで書き込みが失敗したら、記録は残さない。
#[tokio::test]
async fn failed_plain_write_registers_nothing() {
    let (svc, store, _g, _log) = plain();
    store.fail_put_at.lock().unwrap().push(0);
    assert_eq!(run(&svc).await.unwrap_err().code(), Code::Internal);
    assert!(list(&svc).await.is_empty());
}

/// set_up が失敗して回収できたら、記録を消す。
#[tokio::test]
async fn set_up_failure_with_reclaim_removes_the_pending_record() {
    let (svc, _s, _g, log) = networked(true);
    assert!(run(&svc).await.is_err());
    assert_eq!(
        events(&log),
        vec![
            put(true, "notready", false, true),
            Ev::SetUp,
            Ev::TearDown,
            Ev::Remove,
        ]
    );
    assert!(list(&svc).await.is_empty());
}

/// Stop は回収後に状態を書く。
#[tokio::test]
async fn stop_writes_notready_after_tear_down() {
    let (svc, _s, _g, log) = networked(false);
    let id = run(&svc).await.unwrap();
    log.lock().unwrap().clear();
    stop(&svc, &id).await.unwrap();
    assert_eq!(
        events(&log),
        vec![Ev::TearDown, put(false, "notready", false, false)]
    );
}

/// Stop の書き込みが失敗しても、メモリは Stop 後の状態で `INTERNAL`。
#[tokio::test]
async fn failed_stop_write_returns_internal_and_keeps_memory_stopped() {
    let (svc, store, _g, _log) = plain();
    let id = run(&svc).await.unwrap();
    store.fail_put_at.lock().unwrap().push(1);
    let e = stop(&svc, &id).await.unwrap_err();
    assert_eq!(e.code(), Code::Internal);
    assert_eq!(
        list(&svc).await[0].state,
        v1::PodSandboxState::SandboxNotready as i32
    );
    // 次の Stop は書き込みが通れば成功する（フラグが残っていない）。
    stop(&svc, &id).await.unwrap();
}

/// Remove は記録ファイルを消してからメモリを除去する。
#[tokio::test]
async fn remove_deletes_the_record_then_the_memory() {
    let (svc, _s, _g, log) = plain();
    let id = run(&svc).await.unwrap();
    log.lock().unwrap().clear();
    remove(&svc, &id).await.unwrap();
    assert_eq!(events(&log), vec![Ev::Remove]);
    assert!(list(&svc).await.is_empty());
}

/// 削除に失敗したらメモリの記録を残して `INTERNAL`。再試行で消える。
#[tokio::test]
async fn failed_remove_keeps_the_record_and_a_retry_succeeds() {
    let (svc, store, _g, log) = plain();
    let id = run(&svc).await.unwrap();
    store.fail_remove_at.lock().unwrap().push(0);
    let e = remove(&svc, &id).await.unwrap_err();
    assert_eq!(e.code(), Code::Internal);
    assert_eq!(e.message(), "sandbox record could not be removed");
    assert_eq!(list(&svc).await.len(), 1);
    remove(&svc, &id).await.unwrap();
    assert!(list(&svc).await.is_empty());
    assert_eq!(events(&log).last(), Some(&Ev::Remove));
}

/// 未知 ID の Remove は成功し、ストアに触れない。
#[tokio::test]
async fn removing_an_unknown_id_touches_no_file() {
    let (svc, _s, _g, log) = plain();
    remove(&svc, &"0".repeat(64)).await.unwrap();
    assert!(events(&log).is_empty());
}

/// 配下のスタブコンテナがあっても、sandbox の記録ファイルは 1 回だけ消す（コンテナ記録は R5 #2934）。
#[tokio::test]
async fn remove_with_stub_children_deletes_only_the_sandbox_record() {
    let (svc, _s, _g, log) = plain();
    let id = run(&svc).await.unwrap();
    create_container(&svc, &id).await.unwrap();
    log.lock().unwrap().clear();
    remove(&svc, &id).await.unwrap();
    assert_eq!(events(&log), vec![Ev::Remove]);
}

/// 注入しなければ何も書かない（回帰）。
#[tokio::test]
async fn without_a_store_nothing_is_written() {
    let svc = CriRuntimeService::new();
    let id = run(&svc).await.unwrap();
    stop(&svc, &id).await.unwrap();
    remove(&svc, &id).await.unwrap();
    assert!(list(&svc).await.is_empty());
}

/// 別スレッドで future を走らせ、結果を期限つきで待つ（`join` の無期限待ちを避ける）。
struct Joiner<T>(Receiver<T>);

impl<T> Joiner<T> {
    fn join(self) -> Result<T, &'static str> {
        self.0
            .recv_timeout(WAIT)
            .map_err(|_| "thread did not finish in time")
    }
}

fn on_thread<T: Send + 'static>(
    f: impl std::future::Future<Output = T> + Send + 'static,
) -> Joiner<T> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let out = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f);
        let _ = tx.send(out);
    });
    Joiner(rx)
}

/// 記録ストアの `put` が戻らなくても、RPC は `runtime_timeout` で `INTERNAL` を返す（REPAIR-5・#2933）。
/// 予約は巻き戻され、一覧に残らない。
#[tokio::test]
async fn hung_put_is_bounded_by_the_runtime_timeout() {
    let log: Log = Arc::default();
    let (store, gate) = FakeStore::new(&log);
    let svc = CriRuntimeService::new()
        .with_runtime_timeout(Duration::from_millis(200))
        .with_record_store(store.clone());
    *store.block_put_at.lock().unwrap() = Some(0);
    let e = tokio::time::timeout(WAIT, run(&svc))
        .await
        .expect("run must return within a bounded time")
        .unwrap_err();
    assert_eq!(e.code(), Code::Internal);
    gate.release.send(()).unwrap();
    assert!(list(&svc).await.is_empty());
}

/// 有限時間でログに `Put` の直後の `Remove` が現れるのを待つ。
async fn wait_for_put_then_remove(log: &Log) {
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        let evs = events(log);
        if let Some(i) = evs.iter().position(|e| matches!(e, Ev::Put { .. }))
            && evs
                .get(i + 1..)
                .is_some_and(|rest| rest.contains(&Ev::Remove))
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "late put was not followed by a remove: {evs:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// 期限超過した巻き戻し用の put が遅れて書けても、worker が書いた直後に自分で消す（所有者の無い記録を
/// 残さない。#2933・REPAIR-5）。ネットワークなし・ありの両方。
#[tokio::test]
async fn late_put_after_timeout_is_removed_by_its_own_worker() {
    for networked_path in [false, true] {
        let log: Log = Arc::default();
        let (store, gate) = FakeStore::new(&log);
        let mut svc = CriRuntimeService::new()
            .with_runtime_timeout(Duration::from_millis(200))
            .with_record_store(store.clone());
        if networked_path {
            svc = svc.with_pod_network(Arc::new(FakeNet {
                log: Arc::clone(&log),
                fail_set_up: false,
            }));
        }
        *store.block_put_at.lock().unwrap() = Some(0);
        let e = run(&svc).await.unwrap_err();
        assert_eq!(e.code(), Code::Internal);
        gate.release.send(()).unwrap();
        wait_for_put_then_remove(&log).await;
    }
}

/// write-ahead の待機中に RPC の future が破棄されても、予約は戻り、遅れて書けた記録は消され、
/// 同じ metadata の Run が重複として拒否され続けない（#2933・CRI-2）。
#[tokio::test]
async fn dropped_run_during_write_ahead_releases_the_reservation() {
    let (svc, store, gate, log) = networked(false);
    *store.block_put_at.lock().unwrap() = Some(0);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), run(&svc))
            .await
            .is_err()
    );
    assert!(list(&svc).await.is_empty());
    gate.release.send(()).unwrap();
    wait_for_put_then_remove(&log).await;
    run(&svc).await.expect("same metadata must not be rejected");
}

/// fsync 中は registry のロックを持たない（List が返る）。同じ ID への並行 Stop・Remove・
/// CreateContainer は `FAILED_PRECONDITION`。解放後は通常どおり操作できる。
#[tokio::test]
async fn concurrent_operations_during_run_write_are_rejected_without_the_lock() {
    let (svc, store, gate, log) = plain();
    let svc = Arc::new(svc);
    *store.block_put_at.lock().unwrap() = Some(0);
    let runner = {
        let svc = Arc::clone(&svc);
        on_thread(async move { run(&svc).await })
    };
    gate.entered
        .recv_timeout(WAIT)
        .expect("put did not reach the gate in time");
    let items = list(&svc).await;
    assert_eq!(items.len(), 1);
    let id = items[0].id.clone();
    for e in [
        stop(&svc, &id).await.unwrap_err(),
        remove(&svc, &id).await.unwrap_err(),
        create_container(&svc, &id).await.unwrap_err(),
    ] {
        assert_eq!(e.code(), Code::FailedPrecondition);
    }
    gate.release.send(()).unwrap();
    assert_eq!(runner.join().unwrap().unwrap(), id);
    assert_eq!(events(&log), vec![put(false, "ready", false, false)]);
    remove(&svc, &id).await.unwrap();
    assert_eq!(events(&log).last(), Some(&Ev::Remove));
}

/// Stop の書き込み中の Remove は拒否され、Stop の後に所有者の無い記録が残らない。
#[tokio::test]
async fn remove_during_stop_write_is_rejected() {
    let (svc, store, gate, log) = plain();
    let svc = Arc::new(svc);
    let id = run(&svc).await.unwrap();
    *store.block_put_at.lock().unwrap() = Some(1);
    let stopper = {
        let svc = Arc::clone(&svc);
        let id = id.clone();
        on_thread(async move { stop(&svc, &id).await })
    };
    gate.entered
        .recv_timeout(WAIT)
        .expect("put did not reach the gate in time");
    assert_eq!(
        remove(&svc, &id).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    gate.release.send(()).unwrap();
    stopper.join().unwrap().unwrap();
    assert_eq!(
        events(&log),
        vec![
            put(false, "ready", false, false),
            put(false, "notready", false, false)
        ]
    );
}

/// 期限超過した Remove の削除が遅れて完了しても、worker がメモリの除去まで確定する。完了までは sandbox が
/// 残っても CreateContainer は拒否され、完了後に「ファイルは無いのにメモリは Ready」が残らない
/// （#2933・CRI-2・REPAIR-5）。
#[tokio::test]
async fn late_remove_after_timeout_also_removes_the_memory_record() {
    let log: Log = Arc::default();
    let (store, gate) = FakeStore::new(&log);
    let svc = CriRuntimeService::new()
        .with_runtime_timeout(Duration::from_millis(200))
        .with_record_store(store.clone());
    let id = run(&svc).await.unwrap();
    *store.block_remove_at.lock().unwrap() = Some(0);
    let e = tokio::time::timeout(WAIT, remove(&svc, &id))
        .await
        .expect("remove must return within a bounded time")
        .unwrap_err();
    assert_eq!(e.code(), Code::Internal);
    assert_eq!(
        create_container(&svc, &id).await.unwrap_err().code(),
        Code::FailedPrecondition
    );
    gate.entered
        .recv_timeout(WAIT)
        .expect("remove did not reach the gate in time");
    gate.release.send(()).unwrap();
    let deadline = std::time::Instant::now() + WAIT;
    while !list(&svc).await.is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "late remove did not drop the memory record"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        create_container(&svc, &id).await.unwrap_err().code(),
        Code::NotFound
    );
}
