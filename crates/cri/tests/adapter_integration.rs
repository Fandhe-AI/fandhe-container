//! CRI の RuntimeService を `ContainerRuntime` 境界経由で実行層へ接続した全ライフサイクルの結合試験
//! （TASK-59.4・#440・CRI-2・CRI-7・REPAIR-4・REPAIR-12）。
//!
//! 状態を追跡するフェイクの実行層（`LifecycleRuntime`）を `CriRuntimeService::with_runtime` へ注入し、
//! plugin-cri（TASK-108）と同じ立場で生成された `RuntimeService` トレイト経由で、PodSandbox 作成から
//! コンテナの作成・起動・停止・削除・サンドボックスの停止・削除までを 1 本で通して各段階の状態を具体値で確かめる。
//! RPC ごとの個別検証は `runtime_service_runtime.rs`、namespace 分離の実機前提試験は
//! `runtime_service_namespaces.rs` が担う。本番経路（plugin-cri が supervisor 経由で core の本番 launcher を使う。#2434）の通しは `crates/plugin-cri/tests/container_grpc.rs` の `production_binary_full_lifecycle_real`（実機前提）が担い、本試験の範囲外。
//!
//! CRI 層がホストのプロセスを直接起動せず、実行層（plugin 側の実装）だけが起動・回収することは、
//! 静的照合（src に `Command::new` が無い）と Linux の実プロセス試験の両方で確かめる。

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
use fandhe_container_cri::instrument::{CriOpRecorder, CriOpSample, code_name};
use fandhe_container_cri::runtime::v1::{
    self, ContainerConfig, ContainerMetadata, ContainerState as S, ImageSpec, PodSandboxConfig,
    PodSandboxMetadata, PodSandboxState, runtime_service_server::RuntimeService,
};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use tonic::{Code, Request, Status};

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
    fn is_empty(&self) -> bool {
        self.states.lock().unwrap().is_empty()
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

#[derive(Default)]
struct Collect(Mutex<Vec<CriOpSample>>);

impl CriOpRecorder for Collect {
    fn record_cri_op(&self, sample: &CriOpSample) {
        self.0.lock().unwrap().push(*sample);
    }
}

impl Collect {
    /// 記録された結果区分の名前の列。
    fn names(&self) -> Vec<&'static str> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|s| code_name(s.code()))
            .collect()
    }
}

struct Harness {
    service: CriRuntimeService,
    runtime: Arc<LifecycleRuntime>,
    bundles: Arc<RecordingBundles>,
    recorder: Arc<Collect>,
}

fn harness() -> Harness {
    let runtime = Arc::new(LifecycleRuntime::default());
    let bundles = Arc::new(RecordingBundles::default());
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

async fn run_sandbox(svc: &CriRuntimeService) -> String {
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
        svc,
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

async fn create(svc: &CriRuntimeService, sandbox: &str, name: &str) -> String {
    let config = ContainerConfig {
        metadata: Some(ContainerMetadata {
            name: name.into(),
            attempt: 0,
        }),
        image: Some(ImageSpec {
            image: "busybox:1.36".into(),
            ..Default::default()
        }),
        ..Default::default()
    };
    RuntimeService::create_container(
        svc,
        Request::new(v1::CreateContainerRequest {
            pod_sandbox_id: sandbox.into(),
            config: Some(config),
            sandbox_config: None,
        }),
    )
    .await
    .expect("create container")
    .into_inner()
    .container_id
}

async fn start(svc: &CriRuntimeService, id: &str) {
    RuntimeService::start_container(
        svc,
        Request::new(v1::StartContainerRequest {
            container_id: id.into(),
        }),
    )
    .await
    .expect("start container");
}

async fn stop_c(svc: &CriRuntimeService, id: &str, timeout: i64) {
    RuntimeService::stop_container(
        svc,
        Request::new(v1::StopContainerRequest {
            container_id: id.into(),
            timeout,
        }),
    )
    .await
    .expect("stop container");
}

async fn remove(svc: &CriRuntimeService, id: &str) {
    RuntimeService::remove_container(
        svc,
        Request::new(v1::RemoveContainerRequest {
            container_id: id.into(),
        }),
    )
    .await
    .expect("remove container");
}

async fn stop_sb(svc: &CriRuntimeService, id: &str) {
    RuntimeService::stop_pod_sandbox(
        svc,
        Request::new(v1::StopPodSandboxRequest {
            pod_sandbox_id: id.into(),
        }),
    )
    .await
    .expect("stop sandbox");
}

async fn remove_sb(svc: &CriRuntimeService, id: &str) {
    RuntimeService::remove_pod_sandbox(
        svc,
        Request::new(v1::RemovePodSandboxRequest {
            pod_sandbox_id: id.into(),
        }),
    )
    .await
    .expect("remove sandbox");
}

async fn container_status(
    svc: &CriRuntimeService,
    id: &str,
) -> Result<v1::ContainerStatus, Status> {
    RuntimeService::container_status(
        svc,
        Request::new(v1::ContainerStatusRequest {
            container_id: id.into(),
            verbose: false,
        }),
    )
    .await
    .map(|r| r.into_inner().status.expect("status body"))
}

async fn sandbox_state(svc: &CriRuntimeService, id: &str) -> Result<i32, Status> {
    RuntimeService::pod_sandbox_status(
        svc,
        Request::new(v1::PodSandboxStatusRequest {
            pod_sandbox_id: id.into(),
            verbose: false,
        }),
    )
    .await
    .map(|r| r.into_inner().status.expect("status body").state)
}

async fn list_containers_len(svc: &CriRuntimeService) -> usize {
    RuntimeService::list_containers(
        svc,
        Request::new(v1::ListContainersRequest { filter: None }),
    )
    .await
    .expect("list containers")
    .into_inner()
    .containers
    .len()
}

async fn list_sandboxes_len(svc: &CriRuntimeService) -> usize {
    RuntimeService::list_pod_sandbox(
        svc,
        Request::new(v1::ListPodSandboxRequest { filter: None }),
    )
    .await
    .expect("list sandboxes")
    .into_inner()
    .items
    .len()
}

/// CRI-2: kubelet の通常の順序で全ライフサイクルが実行層経由で成功し、各段階の状態が期待どおりになる。
#[tokio::test]
async fn task_59_4_full_lifecycle_via_runtime() {
    let h = harness();
    let svc = &h.service;

    let sb = run_sandbox(svc).await;
    assert_eq!(
        sandbox_state(svc, &sb).await.unwrap(),
        PodSandboxState::SandboxReady as i32
    );
    assert_eq!(list_sandboxes_len(svc).await, 1);

    let id = create(svc, &sb, "c").await;
    let st = container_status(svc, &id).await.unwrap();
    assert_eq!(st.state, S::ContainerCreated as i32);
    assert!(st.created_at > 0);
    assert_eq!(st.started_at, 0);
    assert_eq!(st.finished_at, 0);
    assert_eq!(h.runtime.state_of(&id), Some(ContainerState::Created));

    start(svc, &id).await;
    let st = container_status(svc, &id).await.unwrap();
    assert_eq!(st.state, S::ContainerRunning as i32);
    assert!(st.started_at >= st.created_at);
    assert_eq!(h.runtime.state_of(&id), Some(ContainerState::Running));

    stop_c(svc, &id, 10).await;
    let stopped = container_status(svc, &id).await.unwrap();
    assert_eq!(stopped.state, S::ContainerExited as i32);
    assert!(stopped.finished_at >= stopped.started_at);
    assert_eq!(stopped.exit_code, STOP_EXIT_CODE);
    assert_eq!(h.runtime.state_of(&id), Some(ContainerState::Stopped));

    remove(svc, &id).await;
    assert_eq!(list_containers_len(svc).await, 0);
    assert_eq!(
        container_status(svc, &id).await.unwrap_err().code(),
        Code::NotFound
    );

    stop_sb(svc, &sb).await;
    assert_eq!(
        sandbox_state(svc, &sb).await.unwrap(),
        PodSandboxState::SandboxNotready as i32
    );
    remove_sb(svc, &sb).await;
    assert_eq!(
        sandbox_state(svc, &sb).await.unwrap_err().code(),
        Code::NotFound
    );
    assert_eq!(list_sandboxes_len(svc).await, 0);

    // 実行層の呼び出し列は 4 件のみ。exited のコンテナに対し sandbox の停止・削除は追加の stop / delete を出さない。
    let bundle = bundle_root().join(&id);
    assert_eq!(
        h.runtime.mutating_calls(),
        vec![
            format!("create {id} {}", bundle.display()),
            format!("start {id}"),
            format!("stop {id} 10s"),
            format!("delete {id} force=true"),
        ]
    );
    assert_eq!(
        h.bundles.0.lock().unwrap().clone(),
        vec![format!("prepare {id} {sb} c"), format!("release {id}")]
    );
    assert!(h.runtime.is_empty());

    // 成功した RPC はすべて OK で記録され、NOT_FOUND は確認のために意図して呼んだ 2 回だけ（REPAIR-4）。
    let names = h.recorder.names();
    assert_eq!(names.iter().filter(|n| **n == "NOT_FOUND").count(), 2);
    assert!(names.iter().all(|n| *n == "OK" || *n == "NOT_FOUND"));
}

/// CRI-2: kubelet が pod をまとめて片付ける順序で、StopPodSandbox が連鎖停止し RemovePodSandbox が連鎖削除する。
#[tokio::test]
async fn task_59_4_sandbox_teardown_cascades_via_runtime() {
    let h = harness();
    let svc = &h.service;

    let sb = run_sandbox(svc).await;
    let id = create(svc, &sb, "c").await;
    start(svc, &id).await;
    assert_eq!(
        container_status(svc, &id).await.unwrap().state,
        S::ContainerRunning as i32
    );

    stop_sb(svc, &sb).await;
    assert_eq!(
        sandbox_state(svc, &sb).await.unwrap(),
        PodSandboxState::SandboxNotready as i32
    );
    let st = container_status(svc, &id).await.unwrap();
    assert_eq!(st.state, S::ContainerExited as i32);
    assert_eq!(st.exit_code, STOP_EXIT_CODE);

    remove_sb(svc, &sb).await;
    assert_eq!(
        sandbox_state(svc, &sb).await.unwrap_err().code(),
        Code::NotFound
    );
    assert_eq!(list_containers_len(svc).await, 0);

    let bundle = bundle_root().join(&id);
    assert_eq!(
        h.runtime.mutating_calls(),
        vec![
            format!("create {id} {}", bundle.display()),
            format!("start {id}"),
            format!("stop {id} 0s"),
            format!("delete {id} force=true"),
        ]
    );
    assert_eq!(
        h.bundles.0.lock().unwrap().clone(),
        vec![format!("prepare {id} {sb} c"), format!("release {id}")]
    );
    assert!(h.runtime.is_empty());
    let names = h.recorder.names();
    assert_eq!(names.iter().filter(|n| **n == "NOT_FOUND").count(), 1);
    assert!(names.iter().all(|n| *n == "OK" || *n == "NOT_FOUND"));
}

/// 指定ディレクトリ以下の `.rs` を再帰的に集める。
fn rust_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// CRI-2・CRI-7: CRI 層（本 crate の src）はホストのプロセスを直接起動しない。起動は実行層の責務。
#[test]
fn task_59_4_cri_layer_never_spawns_host_processes() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(!files.is_empty());
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read source");
        for line in text.lines().filter(|l| !l.trim_start().starts_with("//")) {
            assert!(
                !line.contains("Command::new") && !line.contains("process::Command"),
                "CRI layer must not spawn processes: {}: {line}",
                file.display()
            );
        }
    }
}

/// Linux 限定の実プロセス試験。import・ヘルパーごと閉じ込め、他 OS での未使用警告を避ける。
#[cfg(target_os = "linux")]
mod real_process {
    use super::*;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// REPAIR-5: 子の回収の期限。
    const REAP_DEADLINE: Duration = Duration::from_secs(10);

    fn kill_and_reap(child: &mut Child) -> bool {
        let _ = child.kill();
        let deadline = Instant::now() + REAP_DEADLINE;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => return false,
            }
        }
        false
    }

    /// `start` で素の `sleep 60` を起動し、`stop`・`delete` で kill して回収する実行層。
    /// 起動したプロセスの PID は実行層側の記録から取る（CRI 層は起動しない）。
    #[derive(Default)]
    struct SleepRuntime {
        children: Mutex<HashMap<String, Child>>,
    }

    impl SleepRuntime {
        fn pid_of(&self, id: &str) -> u32 {
            self.children.lock().unwrap().get(id).expect("child").id()
        }
        fn reap(&self, id: &str) -> Result<(), TraitError> {
            let mut children = self.children.lock().unwrap();
            let child = children
                .get_mut(id)
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "no such container"))?;
            if kill_and_reap(child) {
                Ok(())
            } else {
                Err(TraitError::new(ErrorCode::Internal, "child was not reaped"))
            }
        }
    }

    struct Rt(Arc<SleepRuntime>);

    impl ContainerRuntime for Rt {
        fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
            Ok(ContainerStatus::created(r.id().clone(), None))
        }
        fn start(&self, r: &StartRequest) -> Result<ContainerStatus, TraitError> {
            let child = Command::new("sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| TraitError::new(ErrorCode::Unavailable, "failed to spawn sleep"))?;
            let pid = std::num::NonZeroU32::new(child.id());
            self.0
                .children
                .lock()
                .unwrap()
                .insert(r.id().as_str().to_owned(), child);
            Ok(ContainerStatus::running(r.id().clone(), pid))
        }
        fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
        }
        fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
            self.0.reap(r.id().as_str())?;
            Ok(ContainerStatus::stopped(r.id().clone(), None))
        }
        fn delete(&self, r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
            self.0.reap(r.id().as_str())?;
            self.0.children.lock().unwrap().remove(r.id().as_str());
            Ok(DeleteResponse::new())
        }
        fn state(&self, _: &StateRequest) -> Result<ContainerStatus, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "not used"))
        }
    }

    /// テストが途中で失敗しても子を残さない。
    struct Reaper(Arc<SleepRuntime>);

    impl Drop for Reaper {
        fn drop(&mut self) {
            if let Ok(mut children) = self.0.children.lock() {
                for child in children.values_mut() {
                    let _ = kill_and_reap(child);
                }
            }
        }
    }

    /// 起動と回収が注入した実行層だけで行われ、CRI の状態遷移と実プロセスの有無が一致する。
    #[tokio::test]
    async fn task_59_4_real_process_lifecycle_via_runtime() {
        let rt = Arc::new(SleepRuntime::default());
        let _reaper = Reaper(rt.clone());
        let svc = CriRuntimeService::default().with_runtime(
            RuntimeAdapter::new(Arc::new(Rt(rt.clone()))),
            Arc::new(RecordingBundles::default()),
        );

        let sb = run_sandbox(&svc).await;
        let id = create(&svc, &sb, "c").await;
        assert_eq!(
            container_status(&svc, &id).await.unwrap().state,
            S::ContainerCreated as i32
        );

        start(&svc, &id).await;
        assert_eq!(
            container_status(&svc, &id).await.unwrap().state,
            S::ContainerRunning as i32
        );
        let proc_dir = PathBuf::from(format!("/proc/{}", rt.pid_of(&id)));
        assert!(proc_dir.exists(), "process must exist after Start");

        stop_c(&svc, &id, 5).await;
        assert_eq!(
            container_status(&svc, &id).await.unwrap().state,
            S::ContainerExited as i32
        );
        assert!(!proc_dir.exists(), "process must be reaped after Stop");

        remove(&svc, &id).await;
        stop_sb(&svc, &sb).await;
        remove_sb(&svc, &sb).await;
        assert_eq!(list_containers_len(&svc).await, 0);
        assert_eq!(list_sandboxes_len(&svc).await, 0);
        assert!(rt.children.lock().unwrap().is_empty());
    }
}
