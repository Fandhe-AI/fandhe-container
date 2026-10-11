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
//!
//! **保持量の上限**: レジストリは件数（[`MAX_SANDBOXES`]）と、保持する `config` の量
//! （1 件の符号化長 [`MAX_CONFIG_ENCODED_BYTES`]・可変長要素の件数と長さ・合計の見積もり
//! [`MAX_RETAINED_CONFIG_BYTES`]）の両方で有限に保つ。gRPC の受信上限に頼らないのは、本トレイトを
//! 直接呼ぶ経路にも効かせるためと、受信上限では累積を縛れないため。検証の詳細は `config_limits`
//! サブモジュール。
//!
//! **可観測性（REPAIR-4）**: `RunPodSandbox` は全終了経路（成功・入力不正・上限超過・内部エラー）で、
//! 結果のステータスコードと所要時間を [`CriOpRecorder`] へ 1 件渡す。記録先は
//! [`CriRuntimeService::with_recorder`] で注入する（既定は記録しない）。`config`・labels・annotations・
//! エラー文言は記録先へ渡さない。

mod config_limits;

use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tonic::codegen::tokio_stream::Empty;
use tonic::{Request, Response, Status};

use crate::instrument::{CriOpKind, CriOpRecorder, CriOpTimer, NoopCriOpRecorder};
use crate::runtime::v1::{
    self, PodSandboxConfig, PodSandboxState, runtime_service_server::RuntimeService,
};
use config_limits::BoundedConfig;

pub use config_limits::{
    MAX_CONFIG_COLLECTION_ENTRIES, MAX_CONFIG_ENCODED_BYTES, MAX_METADATA_FIELD_BYTES,
    MAX_RETAINED_CONFIG_BYTES, RETAINED_BYTES_PER_ENTRY, RETAINED_BYTES_PER_RECORD,
};

/// 受け付けるサンドボックス数の上限（無制限確保の防止。ERR-3 の `FAILED_PRECONDITION`）。
///
/// 根拠: kubelet の既定の Pod 数上限は 1 ノード 110（`--max-pods`）で、1024 はその約 9 倍。
/// 終了済みで未削除のサンドボックスが残る分を見込んでも届かない値とした。
pub const MAX_SANDBOXES: usize = 1024;

/// サポートする `runtime_handler`。空文字（既定ハンドラ）のみ。未知のハンドラは拒否する（CRI の規定）。
const SUPPORTED_RUNTIME_HANDLERS: &[&str] = &[""];

/// ID 採番の衝突時に再試行する回数の上限。
const ID_RETRY_LIMIT: usize = 8;

/// レジストリの保持量の上限（件数と `config` の保持量の見積もりの合計）。
///
/// 既定値（[`MAX_SANDBOXES`]・[`MAX_RETAINED_CONFIG_BYTES`]）より大きい値は指定できない（既定値へ丸める）。
/// 設定で上限を外せると「保持量が有限」という前提が崩れるため、絞る方向にだけ変えられる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxLimits {
    max_sandboxes: usize,
    max_retained_bytes: usize,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            max_sandboxes: MAX_SANDBOXES,
            max_retained_bytes: MAX_RETAINED_CONFIG_BYTES,
        }
    }
}

impl SandboxLimits {
    /// 既定の上限。
    pub fn new() -> Self {
        Self::default()
    }

    /// サンドボックス数の上限を絞る（[`MAX_SANDBOXES`] を超える値は [`MAX_SANDBOXES`] になる）。
    pub fn with_max_sandboxes(mut self, max_sandboxes: usize) -> Self {
        self.max_sandboxes = max_sandboxes.min(MAX_SANDBOXES);
        self
    }

    /// `config` の保持量の見積もりの合計の上限を絞る（[`MAX_RETAINED_CONFIG_BYTES`] を超える値は
    /// [`MAX_RETAINED_CONFIG_BYTES`] になる）。
    pub fn with_max_retained_bytes(mut self, max_retained_bytes: usize) -> Self {
        self.max_retained_bytes = max_retained_bytes.min(MAX_RETAINED_CONFIG_BYTES);
        self
    }

    /// サンドボックス数の上限。
    pub fn max_sandboxes(&self) -> usize {
        self.max_sandboxes
    }

    /// `config` の保持量の見積もりの合計の上限（バイト）。
    pub fn max_retained_bytes(&self) -> usize {
        self.max_retained_bytes
    }
}

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
/// `config` は内容を変えずに保持する（annotations を書き換えない CRI の要件。Status/List〔#431〕と
/// TASK-58 が再利用する）。サイズ・件数の検証を通過したものだけが入る（`config_limits`）。
/// `retained_bytes` はこの記録がレジストリの保持量へ計上した見積もりで、削除（#430）のときに
/// `SandboxRegistry::retained_bytes` から同じ値を引く。
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SandboxRecord {
    config: PodSandboxConfig,
    state: SandboxState,
    created_at_nanos: i64,
    runtime_handler: &'static str,
    retained_bytes: usize,
}

/// サンドボックスのメモリ上レジストリ（TASK-59 で `StateStore` に置換するスタブ。REPAIR-3）。
///
/// 不変条件: `retained_bytes` は `records` の各記録の `retained_bytes` の合計に等しい。
#[derive(Debug, Default)]
struct SandboxRegistry {
    records: HashMap<String, SandboxRecord>,
    retained_bytes: usize,
}

/// CRI `RuntimeService` の実装（TASK-57.1）。
///
/// `fandhe-container-plugin-cri`（TASK-108）が `RuntimeServiceServer` で包んで公開する。
/// 状態はプロセス内メモリのみのスタブで、実行層へは接続していない（REPAIR-3）。
pub struct CriRuntimeService {
    registry: Mutex<SandboxRegistry>,
    limits: SandboxLimits,
    recorder: Arc<dyn CriOpRecorder>,
}

impl fmt::Debug for CriRuntimeService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // レジストリの中身（config・labels・annotations）は出さない。
        f.debug_struct("CriRuntimeService")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Default for CriRuntimeService {
    fn default() -> Self {
        Self::new()
    }
}

impl CriRuntimeService {
    /// 既定の上限（[`SandboxLimits::default`]）・計測なしで作る。
    pub fn new() -> Self {
        Self::with_recorder(Arc::new(NoopCriOpRecorder))
    }

    /// サンドボックス数の上限を指定して、計測なしで作る（上限超過の検証用）。
    pub fn with_max_sandboxes(max_sandboxes: usize) -> Self {
        Self::with_limits_and_recorder(
            SandboxLimits::default().with_max_sandboxes(max_sandboxes),
            Arc::new(NoopCriOpRecorder),
        )
    }

    /// 既定の上限で、操作の結果と所要時間の記録先を指定して作る（REPAIR-4）。
    pub fn with_recorder(recorder: Arc<dyn CriOpRecorder>) -> Self {
        Self::with_limits_and_recorder(SandboxLimits::default(), recorder)
    }

    /// 上限と記録先の両方を指定して作る。
    pub fn with_limits_and_recorder(
        limits: SandboxLimits,
        recorder: Arc<dyn CriOpRecorder>,
    ) -> Self {
        Self {
            registry: Mutex::new(SandboxRegistry::default()),
            limits,
            recorder,
        }
    }

    /// 登録済みサンドボックス数（テスト用）。
    #[cfg(test)]
    fn sandbox_count(&self) -> usize {
        self.registry.lock().map(|r| r.records.len()).unwrap_or(0)
    }

    /// レジストリの保持量の見積もりの合計（テスト用）。
    #[cfg(test)]
    fn retained_bytes(&self) -> usize {
        self.registry.lock().map(|r| r.retained_bytes).unwrap_or(0)
    }

    /// `RunPodSandbox` の本体。検証・採番・登録を行い、失敗時はレジストリを変更しない。
    ///
    /// 計測（[`CriOpTimer`]）の内側で呼ばれる。レジストリのロックは本関数の中で解放するため、
    /// 記録先はロックの外で呼ばれる。
    fn reserve_sandbox(
        &self,
        req: v1::RunPodSandboxRequest,
    ) -> Result<v1::RunPodSandboxResponse, Status> {
        let ValidatedRun {
            config,
            runtime_handler,
        } = validate_run_request(req)?;
        let retained_bytes = config.retained_bytes();

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
        if registry.records.len() >= self.limits.max_sandboxes {
            return Err(Status::failed_precondition("too many sandboxes"));
        }
        let total_retained_bytes = registry
            .retained_bytes
            .checked_add(retained_bytes)
            .filter(|total| *total <= self.limits.max_retained_bytes)
            .ok_or_else(|| Status::failed_precondition("sandbox config storage is full"))?;
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
                config: config.into_config(),
                state: SandboxState::Ready,
                created_at_nanos,
                runtime_handler,
                retained_bytes,
            },
        );
        registry.retained_bytes = total_retained_bytes;
        Ok(v1::RunPodSandboxResponse { pod_sandbox_id })
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

/// 入力検証を通過した `RunPodSandbox` の要求。
///
/// `runtime_handler` は要求の文字列を持ち回さず、一致したサポート済みハンドラの定数を持つ
/// （要求側の文字列の容量を保持しないため）。
struct ValidatedRun {
    config: BoundedConfig,
    runtime_handler: &'static str,
}

/// `RunPodSandbox` の入力検証（ERR-3: 必須欠落・値域外・サイズ超過は `INVALID_ARGUMENT`）。
///
/// 必須フィールドとハンドラを先に確かめ、最後に `config` のサイズ・件数を検証して保持用に作り直す
/// （`BoundedConfig::new`）。状態には触れない。
fn validate_run_request(req: v1::RunPodSandboxRequest) -> Result<ValidatedRun, Status> {
    let v1::RunPodSandboxRequest {
        config,
        runtime_handler,
    } = req;
    let config = config.ok_or_else(|| Status::invalid_argument("config is required"))?;
    let metadata = config
        .metadata
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("config.metadata is required"))?;
    if metadata.name.is_empty() {
        return Err(Status::invalid_argument("config.metadata.name is required"));
    }
    let runtime_handler = SUPPORTED_RUNTIME_HANDLERS
        .iter()
        .copied()
        .find(|supported| *supported == runtime_handler.as_str())
        .ok_or_else(|| Status::invalid_argument("unknown runtime_handler"))?;
    let config = BoundedConfig::new(config)?;
    Ok(ValidatedRun {
        config,
        runtime_handler,
    })
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
    /// 失敗時はレジストリを変更しない。成功・失敗のどちらでも、結果のステータスコードと所要時間を
    /// 記録先へ 1 件渡す（REPAIR-4。未確定のまま抜けた場合はガードが `Internal` として記録する）。
    async fn run_pod_sandbox(
        &self,
        request: Request<v1::RunPodSandboxRequest>,
    ) -> Result<Response<v1::RunPodSandboxResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::RunPodSandbox);
        let result = self.reserve_sandbox(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
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
    use crate::instrument::CriOpOutcome;
    use crate::instrument::testing::Collect;
    use prost::Message;
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

    /// ERR-3・TASK-57.1: サイズ・件数の上限を超える config は INVALID_ARGUMENT で、レジストリは変わらない
    /// （境界値と全フィールドの照合は `config_limits` のユニットテスト）。
    #[test]
    fn task_57_1_oversized_config_is_rejected_without_state_change() {
        let svc = CriRuntimeService::new();

        let mut too_large = config("p");
        too_large.log_directory = "d".repeat(MAX_CONFIG_ENCODED_BYTES);
        let encoded_len = too_large.encoded_len();
        let err = run(&svc, Some(too_large), "").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.message(),
            format!("config is too large: {encoded_len} bytes exceeds the limit of 524288 bytes")
        );

        let mut too_many = config("p");
        too_many.annotations = (0..=MAX_CONFIG_COLLECTION_ENTRIES)
            .map(|i| (i.to_string(), String::new()))
            .collect();
        let err = run(&svc, Some(too_many), "").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.message(),
            "config.annotations has too many entries: 1025 exceeds the limit of 1024"
        );

        let err = run(&svc, Some(config(&"n".repeat(254))), "").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(
            err.message(),
            "config.metadata.name is too long: 254 bytes exceeds the limit of 253 bytes"
        );

        assert_eq!(svc.sandbox_count(), 0);
        assert_eq!(svc.retained_bytes(), 0);
    }

    /// TASK-57.1: 登録のたびに保持量の見積もり（符号化長＋要素数×256＋4096）が積算され、
    /// 合計は各記録の計上分の和に等しい。
    #[test]
    fn task_57_1_retained_bytes_are_accounted() {
        let svc = CriRuntimeService::new();
        let cfg = config("p");
        // `config()` は labels 1 件・annotations 1 件を持つ。
        let per_sandbox = cfg.encoded_len() + 2 * 256 + 4096;
        run(&svc, Some(cfg.clone()), "").unwrap();
        assert_eq!(svc.retained_bytes(), per_sandbox);
        run(&svc, Some(cfg), "").unwrap();
        assert_eq!(svc.retained_bytes(), 2 * per_sandbox);
        let reg = svc.registry.lock().unwrap();
        let sum: usize = reg.records.values().map(|r| r.retained_bytes).sum();
        assert_eq!(sum, reg.retained_bytes);
    }

    /// ERR-3・TASK-57.1: 保持量の合計は上限ちょうどまで受け付け、1 バイトでも超えると
    /// FAILED_PRECONDITION でレジストリは変わらない。
    #[test]
    fn task_57_1_retained_bytes_limit_returns_failed_precondition() {
        let cfg = config("p");
        let per_sandbox = cfg.encoded_len() + 2 * 256 + 4096;
        let service = |max_retained_bytes: usize| {
            CriRuntimeService::with_limits_and_recorder(
                SandboxLimits::default().with_max_retained_bytes(max_retained_bytes),
                Arc::new(NoopCriOpRecorder),
            )
        };

        let exact = service(2 * per_sandbox);
        run(&exact, Some(cfg.clone()), "").unwrap();
        run(&exact, Some(cfg.clone()), "").unwrap();
        let err = run(&exact, Some(cfg.clone()), "").unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(err.message(), "sandbox config storage is full");
        assert_eq!(exact.sandbox_count(), 2);
        assert_eq!(exact.retained_bytes(), 2 * per_sandbox);

        let one_short = service(2 * per_sandbox - 1);
        run(&one_short, Some(cfg.clone()), "").unwrap();
        let err = run(&one_short, Some(cfg), "").unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(one_short.sandbox_count(), 1);
        assert_eq!(one_short.retained_bytes(), per_sandbox);
    }

    /// TASK-57.1: 上限は絞る方向にだけ変えられる（既定値を超える指定は既定値へ丸める）。
    #[test]
    fn task_57_1_limits_cannot_exceed_defaults() {
        let default = SandboxLimits::new();
        assert_eq!(default.max_sandboxes(), 1024);
        assert_eq!(default.max_retained_bytes(), 64 * 1024 * 1024);
        let raised = SandboxLimits::new()
            .with_max_sandboxes(usize::MAX)
            .with_max_retained_bytes(usize::MAX);
        assert_eq!(raised, default);
        let lowered = SandboxLimits::new()
            .with_max_sandboxes(3)
            .with_max_retained_bytes(8192);
        assert_eq!(lowered.max_sandboxes(), 3);
        assert_eq!(lowered.max_retained_bytes(), 8192);
    }

    /// TASK-57.1: 1 件あたりの固定の上乗せ（4096 バイト）は、レジストリのスロット（伸長分を見込んで
    /// 3 倍）と ID の文字列（64 バイト）を収める。構造体が大きくなって収まらなくなったら検出する。
    #[test]
    fn task_57_1_record_overhead_covers_registry_slot() {
        let slot = std::mem::size_of::<(String, SandboxRecord)>();
        assert!(
            3 * slot + 64 <= RETAINED_BYTES_PER_RECORD,
            "registry slot is {slot} bytes"
        );
    }

    /// REPAIR-4・TASK-57.1: 成功・入力不正・件数超過・保持量超過・内部エラーの全終了経路で、
    /// 結果とステータスコードが 1 回の呼び出しにつき 1 件記録される。
    #[test]
    fn task_57_1_every_exit_path_is_recorded() {
        let collect = Arc::new(Collect::default());
        let cfg = config("p");
        let per_sandbox = cfg.encoded_len() + 2 * 256 + 4096;
        let service = |limits: SandboxLimits| {
            CriRuntimeService::with_limits_and_recorder(limits, collect.clone())
        };

        let svc = service(SandboxLimits::new().with_max_sandboxes(1));
        run(&svc, Some(cfg.clone()), "").unwrap();
        run(&svc, None, "").unwrap_err();
        run(&svc, Some(cfg.clone()), "").unwrap_err();

        let svc = service(SandboxLimits::new().with_max_retained_bytes(per_sandbox - 1));
        run(&svc, Some(cfg.clone()), "").unwrap_err();

        // レジストリのロックを保持したまま panic させ、ロックを poison して内部エラーの経路を通す。
        let svc = service(SandboxLimits::new());
        let poisoned = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = svc.registry.lock().unwrap();
                    panic!("poison the registry lock");
                })
                .join()
        });
        assert!(poisoned.is_err());
        let err = run(&svc, Some(cfg), "").unwrap_err();
        assert_eq!(err.code(), Code::Internal);
        assert_eq!(err.message(), "sandbox registry is unavailable");

        let kind = CriOpKind::RunPodSandbox;
        assert_eq!(
            collect.outcomes(),
            vec![
                (kind, CriOpOutcome::Success, Code::Ok),
                (kind, CriOpOutcome::Failure, Code::InvalidArgument),
                (kind, CriOpOutcome::Failure, Code::FailedPrecondition),
                (kind, CriOpOutcome::Failure, Code::FailedPrecondition),
                (kind, CriOpOutcome::Failure, Code::Internal),
            ]
        );
    }

    /// REPAIR-4・TASK-57.1: 未実装の RPC は計測の対象外で、記録先へ何も渡さない
    /// （種別は RPC の実装と一緒に追加する）。
    #[test]
    fn task_57_1_unimplemented_rpcs_are_not_recorded() {
        let collect = Arc::new(Collect::default());
        let svc = CriRuntimeService::with_recorder(collect.clone());
        block_on(svc.stop_pod_sandbox(Request::new(v1::StopPodSandboxRequest::default())))
            .unwrap_err();
        assert_eq!(collect.outcomes(), vec![]);
    }

    /// `Debug` 出力はレジストリの中身（config・labels・annotations）を含まない。
    #[test]
    fn task_57_1_debug_output_omits_registry_contents() {
        let svc = CriRuntimeService::new();
        let mut cfg = config("p");
        cfg.annotations
            .insert("token".into(), "do-not-print".into());
        run(&svc, Some(cfg), "").unwrap();
        let debug = format!("{svc:?}");
        assert!(debug.starts_with("CriRuntimeService { limits: SandboxLimits {"));
        assert!(!debug.contains("do-not-print"));
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
