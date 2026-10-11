//! `RuntimeService` の CRI 実装（TASK-57.1・#429・CRI-1・ERR-3）。
//!
//! `fandhe-container-plugin-cri`（TASK-108）が gRPC サーバーへ載せる `RuntimeService` 実装の本体。
//! 本ファイルの時点で実装済みなのは `RunPodSandbox` のみで、他の RPC は `Unimplemented` を返す
//! （Stop/Remove は #430、Status/List は #431、Container 系は TASK-58 で追加する）。
//!
//! **スタブの明示（REPAIR-3）**: サンドボックスの状態はプロセス内メモリのレジストリにだけ持つ。
//! 実行層（core）には未接続で、永続化もしない。TASK-59 で `StateStore` / `ContainerRuntime` へ置き換える
//! （常駐デーモンを前提にしない CORE-1 とは、置換後の状態管理で整合させる）。
//! リスナー（UDS・peer credential 検証。PLUG-12）や gRPC のメッセージ長上限の設定は TASK-108 の責務で、
//! ここでは作らない。`config` のパス類（`log_directory` 等）は保持するだけで検証していない。
//! 実際にファイルへ触れる TASK-58 / TASK-59 で検証する。

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use tonic::codegen::tokio_stream::Empty;
use tonic::{Request, Response, Status};

use crate::runtime::v1::{
    self, PodSandboxConfig, PodSandboxState, runtime_service_server::RuntimeService,
};

/// 受け付けるサンドボックス数の上限（無制限確保の防止。ERR-3 の `FAILED_PRECONDITION`）。
pub const MAX_SANDBOXES: usize = 1024;

/// サポートする `runtime_handler`。空文字（既定ハンドラ）のみ。未知のハンドラは拒否する（CRI の規定）。
const SUPPORTED_RUNTIME_HANDLERS: &[&str] = &[""];

/// ID 採番の衝突時に再試行する回数の上限。
const ID_RETRY_LIMIT: usize = 8;

/// サンドボックスの内部状態（CRI の `PodSandboxState` に対応）。
///
/// `NotReady` への遷移は StopPodSandbox（#430）が使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SandboxState {
    Ready,
    #[allow(dead_code)]
    NotReady,
}

impl SandboxState {
    /// CRI の列挙値へ変換する（Status/List〔#431〕が使うまで未使用）。
    #[allow(dead_code)]
    fn to_proto(self) -> PodSandboxState {
        match self {
            Self::Ready => PodSandboxState::SandboxReady,
            Self::NotReady => PodSandboxState::SandboxNotready,
        }
    }
}

/// レジストリに保持するサンドボックス 1 件分の記録。
///
/// `config` は無加工で保持する（annotations を書き換えない CRI の要件。Status/List〔#431〕と
/// TASK-58 が再利用する）。
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SandboxRecord {
    config: PodSandboxConfig,
    state: SandboxState,
    created_at_nanos: i64,
    runtime_handler: String,
}

/// サンドボックスのメモリ上レジストリ（TASK-59 で `StateStore` に置換するスタブ。REPAIR-3）。
#[derive(Debug, Default)]
struct SandboxRegistry {
    records: HashMap<String, SandboxRecord>,
}

/// CRI `RuntimeService` の実装（TASK-57.1）。
///
/// `fandhe-container-plugin-cri`（TASK-108）が `RuntimeServiceServer` で包んで公開する。
/// 状態はプロセス内メモリのみのスタブで、実行層へは接続していない（REPAIR-3）。
#[derive(Debug)]
pub struct CriRuntimeService {
    registry: Mutex<SandboxRegistry>,
    max_sandboxes: usize,
}

impl Default for CriRuntimeService {
    fn default() -> Self {
        Self::new()
    }
}

impl CriRuntimeService {
    /// 既定の上限（`MAX_SANDBOXES`）で作る。
    pub fn new() -> Self {
        Self::with_max_sandboxes(MAX_SANDBOXES)
    }

    /// サンドボックス数の上限を指定して作る（上限超過の検証用）。
    pub fn with_max_sandboxes(max_sandboxes: usize) -> Self {
        Self {
            registry: Mutex::new(SandboxRegistry::default()),
            max_sandboxes,
        }
    }

    /// 登録済みサンドボックス数（テスト用）。
    #[cfg(test)]
    fn sandbox_count(&self) -> usize {
        self.registry.lock().map(|r| r.records.len()).unwrap_or(0)
    }
}

/// 64 文字の小文字 16 進 ID を採番する（containerd・crictl の慣習に合わせる）。
///
/// ID は秘密値ではなく暗号強度は不要。OS 乱数で鍵が初期化される `RandomState` に
/// カウンタと時刻を混ぜ、衝突は登録時に検査する。クライアントが ID を指定する経路はない。
fn generate_sandbox_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut id = String::with_capacity(64);
    for _ in 0..4 {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
        hasher.write_u128(nanos);
        id.push_str(&format!("{:016x}", hasher.finish()));
    }
    id
}

/// `RunPodSandbox` の入力検証（ERR-3: 必須欠落・値域外は `INVALID_ARGUMENT`）。
fn validate_run_request(req: &v1::RunPodSandboxRequest) -> Result<(), Status> {
    let config = req
        .config
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("config is required"))?;
    let metadata = config
        .metadata
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("config.metadata is required"))?;
    if metadata.name.is_empty() {
        return Err(Status::invalid_argument("config.metadata.name is required"));
    }
    if !SUPPORTED_RUNTIME_HANDLERS.contains(&req.runtime_handler.as_str()) {
        return Err(Status::invalid_argument("unknown runtime_handler"));
    }
    Ok(())
}

#[tonic::async_trait]
impl RuntimeService for CriRuntimeService {
    type StreamPodSandboxesStream = Empty<Result<v1::StreamPodSandboxesResponse, Status>>;
    type StreamContainersStream = Empty<Result<v1::StreamContainersResponse, Status>>;
    type StreamContainerStatsStream = Empty<Result<v1::StreamContainerStatsResponse, Status>>;
    type StreamPodSandboxStatsStream = Empty<Result<v1::StreamPodSandboxStatsResponse, Status>>;
    type GetContainerEventsStream = Empty<Result<v1::ContainerEventResponse, Status>>;
    type StreamPodSandboxMetricsStream = Empty<Result<v1::StreamPodSandboxMetricsResponse, Status>>;

    /// サンドボックス ID を採番し、状態 ready で登録する（CRI-1・TASK-57.1）。
    ///
    /// 失敗時はレジストリを変更しない。
    async fn run_pod_sandbox(
        &self,
        request: Request<v1::RunPodSandboxRequest>,
    ) -> Result<Response<v1::RunPodSandboxResponse>, Status> {
        let req = request.into_inner();
        validate_run_request(&req)?;
        let config = req
            .config
            .ok_or_else(|| Status::invalid_argument("config is required"))?;

        let created_at_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_nanos()).ok())
            .filter(|n| *n > 0)
            .ok_or_else(|| Status::internal("system clock is invalid"))?;

        let mut registry = self
            .registry
            .lock()
            .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
        if registry.records.len() >= self.max_sandboxes {
            return Err(Status::failed_precondition("too many sandboxes"));
        }
        let mut pod_sandbox_id = None;
        for _ in 0..ID_RETRY_LIMIT {
            let candidate = generate_sandbox_id();
            if !registry.records.contains_key(&candidate) {
                pod_sandbox_id = Some(candidate);
                break;
            }
        }
        let pod_sandbox_id =
            pod_sandbox_id.ok_or_else(|| Status::internal("failed to allocate sandbox id"))?;
        registry.records.insert(
            pod_sandbox_id.clone(),
            SandboxRecord {
                config,
                state: SandboxState::Ready,
                created_at_nanos,
                runtime_handler: req.runtime_handler,
            },
        );
        Ok(Response::new(v1::RunPodSandboxResponse { pod_sandbox_id }))
    }

    async fn version(
        &self,
        _request: Request<v1::VersionRequest>,
    ) -> Result<Response<v1::VersionResponse>, Status> {
        Err(Status::unimplemented("version"))
    }
    async fn stop_pod_sandbox(
        &self,
        _request: Request<v1::StopPodSandboxRequest>,
    ) -> Result<Response<v1::StopPodSandboxResponse>, Status> {
        Err(Status::unimplemented("stop_pod_sandbox"))
    }
    async fn remove_pod_sandbox(
        &self,
        _request: Request<v1::RemovePodSandboxRequest>,
    ) -> Result<Response<v1::RemovePodSandboxResponse>, Status> {
        Err(Status::unimplemented("remove_pod_sandbox"))
    }
    async fn pod_sandbox_status(
        &self,
        _request: Request<v1::PodSandboxStatusRequest>,
    ) -> Result<Response<v1::PodSandboxStatusResponse>, Status> {
        Err(Status::unimplemented("pod_sandbox_status"))
    }
    async fn list_pod_sandbox(
        &self,
        _request: Request<v1::ListPodSandboxRequest>,
    ) -> Result<Response<v1::ListPodSandboxResponse>, Status> {
        Err(Status::unimplemented("list_pod_sandbox"))
    }
    async fn stream_pod_sandboxes(
        &self,
        _request: Request<v1::StreamPodSandboxesRequest>,
    ) -> Result<Response<Self::StreamPodSandboxesStream>, Status> {
        Err(Status::unimplemented("stream_pod_sandboxes"))
    }
    async fn create_container(
        &self,
        _request: Request<v1::CreateContainerRequest>,
    ) -> Result<Response<v1::CreateContainerResponse>, Status> {
        Err(Status::unimplemented("create_container"))
    }
    async fn start_container(
        &self,
        _request: Request<v1::StartContainerRequest>,
    ) -> Result<Response<v1::StartContainerResponse>, Status> {
        Err(Status::unimplemented("start_container"))
    }
    async fn stop_container(
        &self,
        _request: Request<v1::StopContainerRequest>,
    ) -> Result<Response<v1::StopContainerResponse>, Status> {
        Err(Status::unimplemented("stop_container"))
    }
    async fn remove_container(
        &self,
        _request: Request<v1::RemoveContainerRequest>,
    ) -> Result<Response<v1::RemoveContainerResponse>, Status> {
        Err(Status::unimplemented("remove_container"))
    }
    async fn list_containers(
        &self,
        _request: Request<v1::ListContainersRequest>,
    ) -> Result<Response<v1::ListContainersResponse>, Status> {
        Err(Status::unimplemented("list_containers"))
    }
    async fn stream_containers(
        &self,
        _request: Request<v1::StreamContainersRequest>,
    ) -> Result<Response<Self::StreamContainersStream>, Status> {
        Err(Status::unimplemented("stream_containers"))
    }
    async fn container_status(
        &self,
        _request: Request<v1::ContainerStatusRequest>,
    ) -> Result<Response<v1::ContainerStatusResponse>, Status> {
        Err(Status::unimplemented("container_status"))
    }
    async fn update_container_resources(
        &self,
        _request: Request<v1::UpdateContainerResourcesRequest>,
    ) -> Result<Response<v1::UpdateContainerResourcesResponse>, Status> {
        Err(Status::unimplemented("update_container_resources"))
    }
    async fn reopen_container_log(
        &self,
        _request: Request<v1::ReopenContainerLogRequest>,
    ) -> Result<Response<v1::ReopenContainerLogResponse>, Status> {
        Err(Status::unimplemented("reopen_container_log"))
    }
    async fn exec_sync(
        &self,
        _request: Request<v1::ExecSyncRequest>,
    ) -> Result<Response<v1::ExecSyncResponse>, Status> {
        Err(Status::unimplemented("exec_sync"))
    }
    async fn exec(
        &self,
        _request: Request<v1::ExecRequest>,
    ) -> Result<Response<v1::ExecResponse>, Status> {
        Err(Status::unimplemented("exec"))
    }
    async fn attach(
        &self,
        _request: Request<v1::AttachRequest>,
    ) -> Result<Response<v1::AttachResponse>, Status> {
        Err(Status::unimplemented("attach"))
    }
    async fn port_forward(
        &self,
        _request: Request<v1::PortForwardRequest>,
    ) -> Result<Response<v1::PortForwardResponse>, Status> {
        Err(Status::unimplemented("port_forward"))
    }
    async fn container_stats(
        &self,
        _request: Request<v1::ContainerStatsRequest>,
    ) -> Result<Response<v1::ContainerStatsResponse>, Status> {
        Err(Status::unimplemented("container_stats"))
    }
    async fn list_container_stats(
        &self,
        _request: Request<v1::ListContainerStatsRequest>,
    ) -> Result<Response<v1::ListContainerStatsResponse>, Status> {
        Err(Status::unimplemented("list_container_stats"))
    }
    async fn stream_container_stats(
        &self,
        _request: Request<v1::StreamContainerStatsRequest>,
    ) -> Result<Response<Self::StreamContainerStatsStream>, Status> {
        Err(Status::unimplemented("stream_container_stats"))
    }
    async fn pod_sandbox_stats(
        &self,
        _request: Request<v1::PodSandboxStatsRequest>,
    ) -> Result<Response<v1::PodSandboxStatsResponse>, Status> {
        Err(Status::unimplemented("pod_sandbox_stats"))
    }
    async fn list_pod_sandbox_stats(
        &self,
        _request: Request<v1::ListPodSandboxStatsRequest>,
    ) -> Result<Response<v1::ListPodSandboxStatsResponse>, Status> {
        Err(Status::unimplemented("list_pod_sandbox_stats"))
    }
    async fn stream_pod_sandbox_stats(
        &self,
        _request: Request<v1::StreamPodSandboxStatsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxStatsStream>, Status> {
        Err(Status::unimplemented("stream_pod_sandbox_stats"))
    }
    async fn update_runtime_config(
        &self,
        _request: Request<v1::UpdateRuntimeConfigRequest>,
    ) -> Result<Response<v1::UpdateRuntimeConfigResponse>, Status> {
        Err(Status::unimplemented("update_runtime_config"))
    }
    async fn status(
        &self,
        _request: Request<v1::StatusRequest>,
    ) -> Result<Response<v1::StatusResponse>, Status> {
        Err(Status::unimplemented("status"))
    }
    async fn checkpoint_container(
        &self,
        _request: Request<v1::CheckpointContainerRequest>,
    ) -> Result<Response<v1::CheckpointContainerResponse>, Status> {
        Err(Status::unimplemented("checkpoint_container"))
    }
    async fn checkpoint_pod(
        &self,
        _request: Request<v1::CheckpointPodRequest>,
    ) -> Result<Response<v1::CheckpointPodResponse>, Status> {
        Err(Status::unimplemented("checkpoint_pod"))
    }
    async fn restore_pod(
        &self,
        _request: Request<v1::RestorePodRequest>,
    ) -> Result<Response<v1::RestorePodResponse>, Status> {
        Err(Status::unimplemented("restore_pod"))
    }
    async fn get_container_events(
        &self,
        _request: Request<v1::GetEventsRequest>,
    ) -> Result<Response<Self::GetContainerEventsStream>, Status> {
        Err(Status::unimplemented("get_container_events"))
    }
    async fn list_metric_descriptors(
        &self,
        _request: Request<v1::ListMetricDescriptorsRequest>,
    ) -> Result<Response<v1::ListMetricDescriptorsResponse>, Status> {
        Err(Status::unimplemented("list_metric_descriptors"))
    }
    async fn list_pod_sandbox_metrics(
        &self,
        _request: Request<v1::ListPodSandboxMetricsRequest>,
    ) -> Result<Response<v1::ListPodSandboxMetricsResponse>, Status> {
        Err(Status::unimplemented("list_pod_sandbox_metrics"))
    }
    async fn stream_pod_sandbox_metrics(
        &self,
        _request: Request<v1::StreamPodSandboxMetricsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxMetricsStream>, Status> {
        Err(Status::unimplemented("stream_pod_sandbox_metrics"))
    }
    async fn runtime_config(
        &self,
        _request: Request<v1::RuntimeConfigRequest>,
    ) -> Result<Response<v1::RuntimeConfigResponse>, Status> {
        Err(Status::unimplemented("runtime_config"))
    }
    async fn update_pod_sandbox_resources(
        &self,
        _request: Request<v1::UpdatePodSandboxResourcesRequest>,
    ) -> Result<Response<v1::UpdatePodSandboxResourcesResponse>, Status> {
        Err(Status::unimplemented("update_pod_sandbox_resources"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};
    use tonic::Code;

    /// テスト用の最小 executor（tokio 非依存）。Pending なら失敗。
    fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => v,
            Poll::Pending => panic!("future must complete without waiting"),
        }
    }

    fn config(name: &str) -> PodSandboxConfig {
        let mut c = PodSandboxConfig {
            metadata: Some(v1::PodSandboxMetadata {
                name: name.into(),
                uid: "uid-1".into(),
                namespace: "ns".into(),
                attempt: 2,
            }),
            ..Default::default()
        };
        c.labels.insert("k".into(), "v".into());
        c.annotations.insert("a".into(), "b".into());
        c
    }

    fn run(
        svc: &CriRuntimeService,
        config: Option<PodSandboxConfig>,
        handler: &str,
    ) -> Result<Response<v1::RunPodSandboxResponse>, Status> {
        block_on(svc.run_pod_sandbox(Request::new(v1::RunPodSandboxRequest {
            config,
            runtime_handler: handler.into(),
        })))
    }

    /// CRI-1・TASK-57.1: ID が 64 文字の小文字 16 進で返り、状態が ready で登録される。
    #[test]
    fn task_57_1_run_pod_sandbox_returns_id_and_ready() {
        let svc = CriRuntimeService::new();
        let id = run(&svc, Some(config("p")), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        let reg = svc.registry.lock().unwrap();
        let rec = reg.records.get(&id).unwrap();
        assert_eq!(rec.state.to_proto(), PodSandboxState::SandboxReady);
        assert_eq!(rec.state.to_proto() as i32, 0);
        assert!(rec.created_at_nanos > 0);
    }

    /// CRI-1・TASK-57.1: config（metadata・labels・annotations）と runtime_handler を書き換えず保持する。
    #[test]
    fn task_57_1_config_is_preserved() {
        let svc = CriRuntimeService::new();
        let cfg = config("p");
        let id = run(&svc, Some(cfg.clone()), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        let reg = svc.registry.lock().unwrap();
        let rec = reg.records.get(&id).unwrap();
        assert_eq!(rec.config, cfg);
        assert_eq!(
            rec.config.annotations.get("a").map(String::as_str),
            Some("b")
        );
        assert_eq!(rec.runtime_handler, "");
    }

    /// CRI-1・TASK-57.1: 連続呼び出しで ID が異なり、件数が 2 になる。
    #[test]
    fn task_57_1_ids_are_unique() {
        let svc = CriRuntimeService::new();
        let a = run(&svc, Some(config("p")), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        let b = run(&svc, Some(config("p")), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        assert_ne!(a, b);
        assert_eq!(svc.sandbox_count(), 2);
    }

    /// ERR-3・TASK-57.1: 必須欠落・未知ハンドラは INVALID_ARGUMENT で、レジストリは変わらない。
    #[test]
    fn task_57_1_invalid_arguments_are_rejected() {
        let svc = CriRuntimeService::new();
        let cases: Vec<(Option<PodSandboxConfig>, &str)> = vec![
            (None, ""),
            (Some(PodSandboxConfig::default()), ""),
            (Some(config("")), ""),
            (Some(config("p")), "unknown-handler"),
        ];
        for (cfg, handler) in cases {
            let err = run(&svc, cfg, handler).unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
        }
        assert_eq!(svc.sandbox_count(), 0);
    }

    /// ERR-3・TASK-57.1: 上限到達で FAILED_PRECONDITION。
    #[test]
    fn task_57_1_limit_returns_failed_precondition() {
        let svc = CriRuntimeService::with_max_sandboxes(1);
        run(&svc, Some(config("p")), "").unwrap();
        let err = run(&svc, Some(config("p")), "").unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(svc.sandbox_count(), 1);
    }

    /// 未実装の RPC は Unimplemented のまま（#430 で stop_pod_sandbox を実装する際にこのテストを差し替える）。
    #[test]
    fn task_57_1_other_rpcs_remain_unimplemented() {
        let svc = CriRuntimeService::new();
        let err =
            block_on(svc.stop_pod_sandbox(Request::new(v1::StopPodSandboxRequest::default())))
                .unwrap_err();
        assert_eq!(err.code(), Code::Unimplemented);
    }
}
