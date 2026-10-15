//! `RuntimeService` の CRI 実装（TASK-57.1〜57.3・TASK-58.1・#429・#430・#431・#433・CRI-1・ERR-3）。
//!
//! `fandhe-container-plugin-cri`（TASK-108）が gRPC サーバーへ載せる `RuntimeService` 実装の本体。
//! 本ファイルの時点で実装済みなのは `RunPodSandbox`・`StopPodSandbox`・`RemovePodSandbox`・
//! `PodSandboxStatus`・`ListPodSandbox` と、`CreateContainer`・`StartContainer`（TASK-58.1）で、
//! 他の RPC は `Unimplemented` を返す（Stop/Remove/List/Status の Container 系は TASK-58.2・58.3）。
//!
//! **Create/Start の扱い（CRI-1・ERR-3・TASK-58.1）**: cri-api の `CreateContainerRequest` にクライアント指定の
//! ID はなく、ID はサービスが採番する。proto は `(metadata.name, metadata.attempt)` を sandbox 内で一意と
//! 定めるため、同一サンドボックスで同じ組の再作成を `ALREADY_EXISTS`（「同一 ID の再作成」）とする。未知の
//! サンドボックスは `NOT_FOUND`、停止済み（notready）のサンドボックスへの作成・起動は `FAILED_PRECONDITION`。
//! `StartContainer` は created から running へ遷移し、二重起動は `FAILED_PRECONDITION`（冪等にしない）。
//! 実行層は呼ばず、プロセスも起動しない記録上の遷移で、TASK-59（CRI-2）で `ContainerRuntime` 経由の起動へ
//! 置き換える（REPAIR-3）。コンテナの記録の型と上限は `container` サブモジュール。
//!
//! **Status/List の扱い（CRI-1・ERR-3・TASK-57.3）**: `PodSandboxStatus` は未知 ID を `NOT_FOUND`、空 ID を
//! `INVALID_ARGUMENT` にする。`ListPodSandbox` は未知の ID や一致なしをエラーにせず空の一覧を返し、
//! 未知の state 値と過大な `label_selector`（件数・文字列長・合計バイト数） だけを `INVALID_ARGUMENT` にする。並びは `(created_at, id)` の昇順。
//! どちらも読み取り専用で、labels・annotations は保持した値を無改変で返す。`network`・`linux`・`info`・
//! `containers_statuses` は空のスタブで、Container 連携（TASK-58）・net 連携（TASK-59 以降）で埋める（REPAIR-3）。
//!
//! **Stop/Remove の未知 ID の扱い（ERR-3）**: `StopPodSandbox` は存在しない ID を `NOT_FOUND` にする
//! （受け入れ基準）。cri-api の proto コメントは回収済みならエラーにしない冪等性を求めるため差異があり、
//! 受け入れ基準を優先している。`RemovePodSandbox` は proto コメントどおり未知 ID を成功（冪等）とする。
//! どちらも空の `pod_sandbox_id` は `INVALID_ARGUMENT`。既に停止済みの Stop は成功で状態は変わらない。
//! Stop は枠（件数・保持量）を解放せず、Remove だけが解放する。ready のままの Remove は強制削除で、
//! 配下のコンテナ記録も連鎖して除去する（プロセスの強制終了は TASK-59 で追加する。REPAIR-3）。
//! Stop 時の配下コンテナの停止（Exited 遷移）は TASK-58.2（#434）で追加する。
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
//! **可観測性（REPAIR-4）**: `RunPodSandbox`・`StopPodSandbox`・`RemovePodSandbox`・`PodSandboxStatus`・`ListPodSandbox`・`CreateContainer`・`StartContainer` は全終了経路（成功・入力不正・上限超過・内部エラー）で、
//! 結果のステータスコードと所要時間を [`CriOpRecorder`] へ 1 件渡す。記録先は
//! [`CriRuntimeService::with_recorder`] で注入する（既定は記録しない）。`config`・labels・annotations・
//! エラー文言は記録先へ渡さない。

mod config_limits;
mod container;

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
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
use container::{ContainerRecord, ContainerState, ValidatedCreate, validate_create_request};

pub use container::{ContainerLimits, MAX_CONTAINERS, MAX_RETAINED_CONTAINER_CONFIG_BYTES};

pub use config_limits::{
    MAX_CONFIG_COLLECTION_ENTRIES, MAX_CONFIG_ENCODED_BYTES, MAX_METADATA_FIELD_BYTES,
    MAX_RETAINED_CONFIG_BYTES, RETAINED_BYTES_PER_ENTRY, RETAINED_BYTES_PER_RECORD,
};

/// 受け付けるサンドボックス数の上限（無制限確保の防止。ERR-3 の `FAILED_PRECONDITION`）。
///
/// 根拠: kubelet の既定の Pod 数上限は 1 ノード 110（`--max-pods`）で、1024 はその約 9 倍。
/// 終了済みで未削除のサンドボックスが残る分を見込んでも届かない値とした。
pub const MAX_SANDBOXES: usize = 1024;

/// `ListPodSandbox` の `label_selector` 1 つのキー・値の最大バイト数（CRI-1・TASK-57.3）。
///
/// レジストリのロック中に各サンドボックスでハッシュされるため、入力サイズ×登録件数の処理に
/// なる。公開トレイトの直接呼び出しでは gRPC の受信上限が効かないので、走査前に自前で拒否する。
pub const MAX_LABEL_SELECTOR_STRING_BYTES: usize = 1024;

/// `label_selector` 全体（全キー・全値・`id` の合計）の最大バイト数（CRI-1・TASK-57.3）。
pub const MAX_LABEL_SELECTOR_TOTAL_BYTES: usize = 16 * 1024;

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
/// `NotReady` への遷移は StopPodSandbox（#430）が行い、Status/List（#431）が応答へ写す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SandboxState {
    Ready,
    NotReady,
}

impl SandboxState {
    /// CRI の列挙値へ変換する（Status/List〔TASK-57.3〕が応答に使う）。
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
struct SandboxRecord {
    config: PodSandboxConfig,
    state: SandboxState,
    created_at_nanos: i64,
    runtime_handler: &'static str,
    retained_bytes: usize,
}

/// サンドボックスのメモリ上レジストリ（TASK-59 で `StateStore` に置換するスタブ。REPAIR-3）。
///
/// 不変条件: `retained_bytes` は `records` の、`container_retained_bytes` は `containers` の各記録の
/// `retained_bytes` の合計に等しい。`container_keys` は `containers` と 1 対 1 に対応する。
#[derive(Debug, Default)]
struct SandboxRegistry {
    records: HashMap<String, SandboxRecord>,
    retained_bytes: usize,
    /// コンテナ ID → 記録（TASK-58.1。TASK-59 で `StateStore` に置換するスタブ）。
    containers: HashMap<String, ContainerRecord>,
    /// `(sandbox_id, name, attempt)` の重複判定用。`containers` と 1 対 1 に対応する。
    container_keys: HashSet<(String, String, u32)>,
    /// コンテナ記録の `retained_bytes` の合計（不変条件）。
    container_retained_bytes: usize,
}

/// CRI `RuntimeService` の実装（TASK-57.1）。
///
/// `fandhe-container-plugin-cri`（TASK-108）が `RuntimeServiceServer` で包んで公開する。
/// 状態はプロセス内メモリのみのスタブで、実行層へは接続していない（REPAIR-3）。
pub struct CriRuntimeService {
    registry: Mutex<SandboxRegistry>,
    limits: SandboxLimits,
    container_limits: ContainerLimits,
    recorder: Arc<dyn CriOpRecorder>,
}

impl fmt::Debug for CriRuntimeService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // レジストリの中身（config・labels・annotations）は出さない。
        f.debug_struct("CriRuntimeService")
            .field("limits", &self.limits)
            .field("container_limits", &self.container_limits)
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
            container_limits: ContainerLimits::default(),
            recorder,
        }
    }

    /// コンテナ用の上限を指定する（既定値より大きくはできない。TASK-58.1）。
    pub fn with_container_limits(mut self, container_limits: ContainerLimits) -> Self {
        self.container_limits = container_limits;
        self
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

    /// コンテナ数（テスト用）。
    #[cfg(test)]
    fn container_count(&self) -> usize {
        self.registry
            .lock()
            .map(|r| r.containers.len())
            .unwrap_or(0)
    }

    /// コンテナ記録の保持量の見積もりの合計（テスト用）。
    #[cfg(test)]
    fn container_retained_bytes(&self) -> usize {
        self.registry
            .lock()
            .map(|r| r.container_retained_bytes)
            .unwrap_or(0)
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

        let created_at_nanos = now_nanos()?;

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
            let candidate = generate_id();
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

    /// `StopPodSandbox` の本体。ready を notready へ遷移させる（冪等。CRI-1・TASK-57.2）。
    ///
    /// 未知 ID は `NOT_FOUND`、空 ID は `INVALID_ARGUMENT`。件数・保持量の枠は解放しない。
    /// エラー文言には入力の ID を含めない。
    fn stop_sandbox(
        &self,
        req: v1::StopPodSandboxRequest,
    ) -> Result<v1::StopPodSandboxResponse, Status> {
        if req.pod_sandbox_id.is_empty() {
            return Err(Status::invalid_argument("pod_sandbox_id is required"));
        }
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
        let record = registry
            .records
            .get_mut(&req.pod_sandbox_id)
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        record.state = SandboxState::NotReady;
        Ok(v1::StopPodSandboxResponse {})
    }

    /// `RemovePodSandbox` の本体。記録を除去し、件数と保持量の枠を解放する（CRI-1・TASK-57.2）。
    ///
    /// 未知 ID は成功（冪等）。保持量の合計が記録の和と食い違う場合は、レジストリを変更せず
    /// `INTERNAL` で失敗する。ready のままでも強制削除する（コンテナの強制終了は TASK-58）。
    fn remove_sandbox(
        &self,
        req: v1::RemovePodSandboxRequest,
    ) -> Result<v1::RemovePodSandboxResponse, Status> {
        if req.pod_sandbox_id.is_empty() {
            return Err(Status::invalid_argument("pod_sandbox_id is required"));
        }
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
        let Some(record) = registry.records.get(&req.pod_sandbox_id) else {
            return Ok(v1::RemovePodSandboxResponse {});
        };
        // 先に引けることを確かめてから除去し、失敗時にレジストリを変更しない。
        let remaining = registry
            .retained_bytes
            .checked_sub(record.retained_bytes)
            .ok_or_else(|| Status::internal("sandbox registry is inconsistent"))?;
        // 配下のコンテナ記録も連鎖して除去する（孤児と保持量の取りこぼしを防ぐ。TASK-58.1）。
        let mut released: usize = 0;
        for c in registry
            .containers
            .values()
            .filter(|c| c.pod_sandbox_id == req.pod_sandbox_id)
        {
            released = released
                .checked_add(c.retained_bytes)
                .ok_or_else(|| Status::internal("container registry is inconsistent"))?;
        }
        let remaining_containers = registry
            .container_retained_bytes
            .checked_sub(released)
            .ok_or_else(|| Status::internal("container registry is inconsistent"))?;
        let pod_sandbox_id = &req.pod_sandbox_id;
        registry
            .containers
            .retain(|_, c| c.pod_sandbox_id != *pod_sandbox_id);
        registry
            .container_keys
            .retain(|(sandbox_id, _, _)| sandbox_id != pod_sandbox_id);
        registry.container_retained_bytes = remaining_containers;
        registry.records.remove(&req.pod_sandbox_id);
        registry.retained_bytes = remaining;
        Ok(v1::RemovePodSandboxResponse {})
    }

    /// `CreateContainer` の本体。検証・採番・登録を行い、失敗時はレジストリを変更しない（TASK-58.1）。
    ///
    /// 状態は `Created`。実行層は呼ばない（TASK-59 で `ContainerRuntime` 経由にする。REPAIR-3）。
    /// エラー文言には入力値（ID・名前・labels）を含めない。
    fn create_container_impl(
        &self,
        req: v1::CreateContainerRequest,
    ) -> Result<v1::CreateContainerResponse, Status> {
        let ValidatedCreate {
            pod_sandbox_id,
            name,
            attempt,
            config,
        } = validate_create_request(req)?;
        let retained_bytes = config.retained_bytes();
        let created_at_nanos = now_nanos()?;

        let mut registry = self
            .registry
            .lock()
            .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
        let sandbox = registry
            .records
            .get(&pod_sandbox_id)
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        if sandbox.state != SandboxState::Ready {
            return Err(Status::failed_precondition("sandbox is not ready"));
        }
        let key = (pod_sandbox_id, name, attempt);
        if registry.container_keys.contains(&key) {
            return Err(Status::already_exists("container already exists"));
        }
        if registry.containers.len() >= self.container_limits.max_containers() {
            return Err(Status::failed_precondition("too many containers"));
        }
        let total_retained_bytes = registry
            .container_retained_bytes
            .checked_add(retained_bytes)
            .filter(|total| *total <= self.container_limits.max_retained_bytes())
            .ok_or_else(|| Status::failed_precondition("container config storage is full"))?;
        let mut container_id = None;
        for _ in 0..ID_RETRY_LIMIT {
            let candidate = generate_id();
            if !registry.containers.contains_key(&candidate) {
                container_id = Some(candidate);
                break;
            }
        }
        let container_id =
            container_id.ok_or_else(|| Status::internal("failed to allocate container id"))?;
        registry.containers.insert(
            container_id.clone(),
            ContainerRecord {
                pod_sandbox_id: key.0.clone(),
                config: config.into_config(),
                state: ContainerState::Created,
                created_at_nanos,
                started_at_nanos: 0,
                retained_bytes,
            },
        );
        registry.container_keys.insert(key);
        registry.container_retained_bytes = total_retained_bytes;
        Ok(v1::CreateContainerResponse { container_id })
    }

    /// `StartContainer` の本体。created を running へ遷移させる（TASK-58.1）。
    ///
    /// 空 ID は `INVALID_ARGUMENT`、未知 ID は `NOT_FOUND`。running の再起動と、停止済みサンドボックス
    /// 配下の起動は `FAILED_PRECONDITION`（冪等にしない）。プロセスは起動しない記録上の遷移で、
    /// TASK-59（CRI-2）で `ContainerRuntime` 経由の namespace 分離起動に置き換える（REPAIR-3）。
    fn start_container_impl(
        &self,
        req: v1::StartContainerRequest,
    ) -> Result<v1::StartContainerResponse, Status> {
        if req.container_id.is_empty() {
            return Err(Status::invalid_argument("container_id is required"));
        }
        let started_at_nanos = now_nanos()?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
        let record = registry
            .containers
            .get(&req.container_id)
            .ok_or_else(|| Status::not_found("container not found"))?;
        let sandbox = registry
            .records
            .get(&record.pod_sandbox_id)
            .ok_or_else(|| Status::internal("container registry is inconsistent"))?;
        if sandbox.state != SandboxState::Ready {
            return Err(Status::failed_precondition("sandbox is not ready"));
        }
        if record.state != ContainerState::Created {
            return Err(Status::failed_precondition(
                "container is not in created state",
            ));
        }
        if let Some(record) = registry.containers.get_mut(&req.container_id) {
            record.state = ContainerState::Running;
            record.started_at_nanos = started_at_nanos;
        }
        Ok(v1::StartContainerResponse {})
    }

    /// `PodSandboxStatus` の本体。読み取り専用（CRI-1・ERR-3・TASK-57.3）。
    ///
    /// 空 ID は `INVALID_ARGUMENT`、未知 ID は `NOT_FOUND`（文言に入力 ID を含めない）。
    /// `verbose` でも `info` は空のスタブ（詳細情報は TASK-58 / TASK-59 で追加。REPAIR-3）。
    fn status_sandbox(
        &self,
        req: v1::PodSandboxStatusRequest,
    ) -> Result<v1::PodSandboxStatusResponse, Status> {
        if req.pod_sandbox_id.is_empty() {
            return Err(Status::invalid_argument("pod_sandbox_id is required"));
        }
        let status = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
            let record = registry
                .records
                .get(&req.pod_sandbox_id)
                .ok_or_else(|| Status::not_found("sandbox not found"))?;
            record.to_status(&req.pod_sandbox_id)
        };
        let timestamp = now_nanos()?;
        Ok(v1::PodSandboxStatusResponse {
            status: Some(status),
            info: HashMap::new(),
            containers_statuses: Vec::new(),
            timestamp,
        })
    }

    /// `ListPodSandbox` の本体。フィルタは AND、並びは `(created_at, id)` の昇順（CRI-1・TASK-57.3）。
    ///
    /// 一致なしは空の一覧。未知の state 値と、件数が [`MAX_CONFIG_COLLECTION_ENTRIES`] を超える
    /// `label_selector` は `INVALID_ARGUMENT`。
    fn list_sandboxes(
        &self,
        req: v1::ListPodSandboxRequest,
    ) -> Result<v1::ListPodSandboxResponse, Status> {
        let filter = ValidatedFilter::new(req.filter)?;
        let mut items = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
            registry
                .records
                .iter()
                .filter(|(id, record)| filter.matches(id, record))
                .map(|(id, record)| record.to_summary(id))
                .collect::<Vec<_>>()
        };
        items.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        Ok(v1::ListPodSandboxResponse { items })
    }
}

/// 現在時刻（UNIX epoch からの ns）。0 以下・変換不能は `INTERNAL`。
fn now_nanos() -> Result<i64, Status> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| Status::internal("system clock is invalid"))
}

impl SandboxRecord {
    /// Status 応答用の変換。labels・annotations は保持した値を無改変でコピーする。
    fn to_status(&self, id: &str) -> v1::PodSandboxStatus {
        v1::PodSandboxStatus {
            id: id.to_owned(),
            metadata: self.config.metadata.clone(),
            state: self.state.to_proto() as i32,
            created_at: self.created_at_nanos,
            network: None,
            linux: None,
            labels: self.config.labels.clone(),
            annotations: self.config.annotations.clone(),
            runtime_handler: self.runtime_handler.to_owned(),
        }
    }

    /// List 応答用の変換（Status と同じ項目の部分集合）。
    fn to_summary(&self, id: &str) -> v1::PodSandbox {
        v1::PodSandbox {
            id: id.to_owned(),
            metadata: self.config.metadata.clone(),
            state: self.state.to_proto() as i32,
            created_at: self.created_at_nanos,
            labels: self.config.labels.clone(),
            annotations: self.config.annotations.clone(),
            runtime_handler: self.runtime_handler.to_owned(),
        }
    }
}

/// 検証済みの `ListPodSandbox` フィルタ（全条件 AND）。
struct ValidatedFilter {
    id: String,
    state: Option<SandboxState>,
    label_selector: HashMap<String, String>,
}

impl ValidatedFilter {
    fn new(filter: Option<v1::PodSandboxFilter>) -> Result<Self, Status> {
        let Some(filter) = filter else {
            return Ok(Self {
                id: String::new(),
                state: None,
                label_selector: HashMap::new(),
            });
        };
        if filter.label_selector.len() > MAX_CONFIG_COLLECTION_ENTRIES {
            return Err(Status::invalid_argument(
                "label_selector has too many entries",
            ));
        }
        let mut total = filter.id.len();
        for (k, v) in &filter.label_selector {
            if k.len() > MAX_LABEL_SELECTOR_STRING_BYTES
                || v.len() > MAX_LABEL_SELECTOR_STRING_BYTES
            {
                return Err(Status::invalid_argument(
                    "label_selector key or value is too long",
                ));
            }
            total = total.saturating_add(k.len()).saturating_add(v.len());
        }
        if total > MAX_LABEL_SELECTOR_TOTAL_BYTES {
            return Err(Status::invalid_argument("label_selector is too large"));
        }
        let state = match filter.state {
            None => None,
            Some(value) => match PodSandboxState::try_from(value.state) {
                Ok(PodSandboxState::SandboxReady) => Some(SandboxState::Ready),
                Ok(PodSandboxState::SandboxNotready) => Some(SandboxState::NotReady),
                Err(_) => return Err(Status::invalid_argument("unknown state filter")),
            },
        };
        Ok(Self {
            id: filter.id,
            state,
            label_selector: filter.label_selector,
        })
    }

    fn matches(&self, id: &str, record: &SandboxRecord) -> bool {
        (self.id.is_empty() || self.id == id)
            && self.state.is_none_or(|s| s == record.state)
            && self
                .label_selector
                .iter()
                .all(|(k, v)| record.config.labels.get(k) == Some(v))
    }
}

/// 64 文字の小文字 16 進 ID（サンドボックス・コンテナ共通）を採番する（containerd・crictl の慣習に合わせる）。
///
/// ID は秘密値ではなく暗号強度は不要。OS 乱数で鍵が初期化される `RandomState` に
/// カウンタと時刻を混ぜ、衝突は登録時に検査する。クライアントが ID を指定する経路はない。
fn generate_id() -> String {
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
    /// サンドボックスを notready にする（冪等。未知 ID は `NOT_FOUND`。CRI-1・ERR-3・TASK-57.2）。
    async fn stop_pod_sandbox(
        &self,
        request: Request<v1::StopPodSandboxRequest>,
    ) -> Result<Response<v1::StopPodSandboxResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::StopPodSandbox);
        let result = self.stop_sandbox(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// サンドボックスの記録を除去する（冪等。未知 ID は成功。CRI-1・ERR-3・TASK-57.2）。
    async fn remove_pod_sandbox(
        &self,
        request: Request<v1::RemovePodSandboxRequest>,
    ) -> Result<Response<v1::RemovePodSandboxResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::RemovePodSandbox);
        let result = self.remove_sandbox(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// サンドボックスの状態を返す（読み取り専用。未知 ID は `NOT_FOUND`。CRI-1・ERR-3・TASK-57.3）。
    async fn pod_sandbox_status(
        &self,
        request: Request<v1::PodSandboxStatusRequest>,
    ) -> Result<Response<v1::PodSandboxStatusResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::PodSandboxStatus);
        let result = self.status_sandbox(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// フィルタに一致するサンドボックスを `(created_at, id)` 昇順で返す（CRI-1・TASK-57.3）。
    async fn list_pod_sandbox(
        &self,
        request: Request<v1::ListPodSandboxRequest>,
    ) -> Result<Response<v1::ListPodSandboxResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::ListPodSandbox);
        let result = self.list_sandboxes(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
    }
    async fn stream_pod_sandboxes(
        &self,
        _request: Request<v1::StreamPodSandboxesRequest>,
    ) -> Result<Response<Self::StreamPodSandboxesStream>, Status> {
        Err(Status::unimplemented("stream_pod_sandboxes"))
    }
    /// コンテナ ID を採番し、状態 created で登録する（同一 sandbox 内の `(name, attempt)` 重複は
    /// `ALREADY_EXISTS`。CRI-1・ERR-3・TASK-58.1）。
    async fn create_container(
        &self,
        request: Request<v1::CreateContainerRequest>,
    ) -> Result<Response<v1::CreateContainerResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::CreateContainer);
        let result = self.create_container_impl(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// コンテナを running にする（二重起動は `FAILED_PRECONDITION`。CRI-1・ERR-3・TASK-58.1）。
    async fn start_container(
        &self,
        request: Request<v1::StartContainerRequest>,
    ) -> Result<Response<v1::StartContainerResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::StartContainer);
        let result = self.start_container_impl(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
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
        block_on(svc.container_status(Request::new(v1::ContainerStatusRequest::default())))
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

    /// 未実装の RPC は Unimplemented のまま（TASK-58 で container_status を実装する際にこのテストを差し替える）。
    #[test]
    fn task_57_1_other_rpcs_remain_unimplemented() {
        let svc = CriRuntimeService::new();
        let err =
            block_on(svc.container_status(Request::new(v1::ContainerStatusRequest::default())))
                .unwrap_err();
        assert_eq!(err.code(), Code::Unimplemented);
    }

    fn stop(
        svc: &CriRuntimeService,
        id: &str,
    ) -> Result<Response<v1::StopPodSandboxResponse>, Status> {
        block_on(
            svc.stop_pod_sandbox(Request::new(v1::StopPodSandboxRequest {
                pod_sandbox_id: id.into(),
            })),
        )
    }

    fn remove(
        svc: &CriRuntimeService,
        id: &str,
    ) -> Result<Response<v1::RemovePodSandboxResponse>, Status> {
        block_on(
            svc.remove_pod_sandbox(Request::new(v1::RemovePodSandboxRequest {
                pod_sandbox_id: id.into(),
            })),
        )
    }

    fn run_id(svc: &CriRuntimeService) -> String {
        run(svc, Some(config("p")), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id
    }

    /// ERR-3・TASK-57.2: 存在しない ID の Stop は NOT_FOUND で、レジストリは変わらない。
    #[test]
    fn task_57_2_stop_unknown_id_returns_not_found() {
        let svc = CriRuntimeService::new();
        run_id(&svc);
        let before = svc.retained_bytes();
        let err = stop(&svc, &"0".repeat(64)).unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        assert_eq!(err.message(), "sandbox not found");
        assert_eq!(svc.sandbox_count(), 1);
        assert_eq!(svc.retained_bytes(), before);
    }

    /// CRI-1・TASK-57.2: Stop で notready になり、再度の Stop も成功で状態・config・保持量は変わらない。
    #[test]
    fn task_57_2_stop_marks_notready_and_is_idempotent() {
        let svc = CriRuntimeService::new();
        let id = run_id(&svc);
        let retained = svc.retained_bytes();
        for _ in 0..2 {
            stop(&svc, &id).unwrap();
            let reg = svc.registry.lock().unwrap();
            let rec = reg.records.get(&id).unwrap();
            assert_eq!(rec.state.to_proto(), PodSandboxState::SandboxNotready);
            assert_eq!(rec.config, config("p"));
            assert_eq!(rec.retained_bytes, retained);
        }
        assert_eq!(svc.retained_bytes(), retained);
    }

    /// CRI-1・TASK-57.2: Stop だけでは枠を解放しない。
    #[test]
    fn task_57_2_stop_does_not_free_slot() {
        let svc = CriRuntimeService::with_max_sandboxes(1);
        let id = run_id(&svc);
        stop(&svc, &id).unwrap();
        let err = run(&svc, Some(config("p")), "").unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    /// CRI-1・TASK-57.2: Remove で記録と保持量の計上の両方が消える。
    #[test]
    fn task_57_2_remove_deletes_record_and_retained_bytes() {
        let svc = CriRuntimeService::new();
        let a = run_id(&svc);
        let b = run_id(&svc);
        let per_sandbox = svc.retained_bytes() / 2;
        remove(&svc, &a).unwrap();
        {
            let reg = svc.registry.lock().unwrap();
            assert!(!reg.records.contains_key(&a));
            let sum: usize = reg.records.values().map(|r| r.retained_bytes).sum();
            assert_eq!(sum, reg.retained_bytes);
        }
        assert_eq!(svc.sandbox_count(), 1);
        assert_eq!(svc.retained_bytes(), per_sandbox);
        remove(&svc, &b).unwrap();
        assert_eq!(svc.sandbox_count(), 0);
        assert_eq!(svc.retained_bytes(), 0);
    }

    /// CRI-1・TASK-57.2: ready のままでも Remove でき、その後の Stop は NOT_FOUND。
    #[test]
    fn task_57_2_remove_ready_sandbox_forces_removal() {
        let svc = CriRuntimeService::new();
        let id = run_id(&svc);
        remove(&svc, &id).unwrap();
        assert_eq!(svc.sandbox_count(), 0);
        assert_eq!(stop(&svc, &id).unwrap_err().code(), Code::NotFound);
    }

    /// ERR-3・TASK-57.2: 未知 ID の Remove は成功（冪等）で、状態は変わらない。
    #[test]
    fn task_57_2_remove_unknown_id_is_idempotent_ok() {
        let svc = CriRuntimeService::new();
        let id = run_id(&svc);
        let retained = svc.retained_bytes();
        remove(&svc, &"f".repeat(64)).unwrap();
        remove(&svc, &"f".repeat(64)).unwrap();
        assert_eq!(svc.sandbox_count(), 1);
        assert_eq!(svc.retained_bytes(), retained);
        remove(&svc, &id).unwrap();
        remove(&svc, &id).unwrap();
        assert_eq!(svc.sandbox_count(), 0);
    }

    /// CRI-1・TASK-57.2: Remove で件数の枠が空き、次の Run が成功する。
    #[test]
    fn task_57_2_remove_frees_slot_for_new_run() {
        let svc = CriRuntimeService::with_max_sandboxes(1);
        let id = run_id(&svc);
        remove(&svc, &id).unwrap();
        run(&svc, Some(config("p")), "").unwrap();
        assert_eq!(svc.sandbox_count(), 1);
    }

    /// ERR-3・TASK-57.2: 空の pod_sandbox_id は Stop・Remove とも INVALID_ARGUMENT。
    #[test]
    fn task_57_2_empty_id_is_invalid_argument() {
        let svc = CriRuntimeService::new();
        for err in [stop(&svc, "").unwrap_err(), remove(&svc, "").unwrap_err()] {
            assert_eq!(err.code(), Code::InvalidArgument);
            assert_eq!(err.message(), "pod_sandbox_id is required");
        }
    }

    /// TASK-57.2: 保持量が記録の和より小さい不整合は INTERNAL で失敗し、レジストリを変更しない。
    #[test]
    fn task_57_2_remove_inconsistent_retained_bytes_fails_without_change() {
        let svc = CriRuntimeService::new();
        let id = run_id(&svc);
        svc.registry.lock().unwrap().retained_bytes = 0;
        let err = remove(&svc, &id).unwrap_err();
        assert_eq!(err.code(), Code::Internal);
        assert_eq!(err.message(), "sandbox registry is inconsistent");
        assert_eq!(svc.sandbox_count(), 1);
        assert_eq!(svc.retained_bytes(), 0);
    }

    /// REPAIR-4・TASK-57.2: Stop・Remove の全終了経路で結果とコードが 1 件ずつ記録される。
    #[test]
    fn task_57_2_every_exit_path_is_recorded() {
        let collect = Arc::new(Collect::default());
        let svc = CriRuntimeService::with_recorder(collect.clone());
        let id = run_id(&svc);
        stop(&svc, &id).unwrap();
        stop(&svc, &"0".repeat(64)).unwrap_err();
        stop(&svc, "").unwrap_err();
        remove(&svc, &id).unwrap();
        remove(&svc, &id).unwrap();
        remove(&svc, "").unwrap_err();

        let svc = CriRuntimeService::with_recorder(collect.clone());
        let poisoned = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = svc.registry.lock().unwrap();
                    panic!("poison the registry lock");
                })
                .join()
        });
        assert!(poisoned.is_err());
        stop(&svc, "x").unwrap_err();
        remove(&svc, "x").unwrap_err();

        let (run_k, s, r) = (
            CriOpKind::RunPodSandbox,
            CriOpKind::StopPodSandbox,
            CriOpKind::RemovePodSandbox,
        );
        assert_eq!(
            collect.outcomes(),
            vec![
                (run_k, CriOpOutcome::Success, Code::Ok),
                (s, CriOpOutcome::Success, Code::Ok),
                (s, CriOpOutcome::Failure, Code::NotFound),
                (s, CriOpOutcome::Failure, Code::InvalidArgument),
                (r, CriOpOutcome::Success, Code::Ok),
                (r, CriOpOutcome::Success, Code::Ok),
                (r, CriOpOutcome::Failure, Code::InvalidArgument),
                (s, CriOpOutcome::Failure, Code::Internal),
                (r, CriOpOutcome::Failure, Code::Internal),
            ]
        );
    }

    fn ids_of(svc: &CriRuntimeService, filter: Option<v1::PodSandboxFilter>) -> Vec<String> {
        block_on(svc.list_pod_sandbox(Request::new(v1::ListPodSandboxRequest { filter })))
            .unwrap()
            .into_inner()
            .items
            .into_iter()
            .map(|i| i.id)
            .collect()
    }

    fn status_of(
        svc: &CriRuntimeService,
        id: &str,
    ) -> Result<v1::PodSandboxStatusResponse, Status> {
        block_on(
            svc.pod_sandbox_status(Request::new(v1::PodSandboxStatusRequest {
                pod_sandbox_id: id.into(),
                verbose: false,
            })),
        )
        .map(Response::into_inner)
    }

    fn stop_id(svc: &CriRuntimeService, id: &str) {
        block_on(
            svc.stop_pod_sandbox(Request::new(v1::StopPodSandboxRequest {
                pod_sandbox_id: id.into(),
            })),
        )
        .unwrap();
    }

    fn remove_id(svc: &CriRuntimeService, id: &str) {
        block_on(
            svc.remove_pod_sandbox(Request::new(v1::RemovePodSandboxRequest {
                pod_sandbox_id: id.into(),
            })),
        )
        .unwrap();
    }

    /// 作成順（created_at, id）の ID 列をレジストリから期待値として作る。
    fn expected_order(svc: &CriRuntimeService) -> Vec<String> {
        let reg = svc.registry.lock().unwrap();
        let mut v: Vec<(i64, String)> = reg
            .records
            .iter()
            .map(|(id, r)| (r.created_at_nanos, id.clone()))
            .collect();
        v.sort();
        v.into_iter().map(|(_, id)| id).collect()
    }

    /// CRI-1・TASK-57.3: Run 直後の Status は ready で config を無改変で返す。Stop で notready、Remove で NOT_FOUND。
    #[test]
    fn task_57_3_status_reflects_lifecycle() {
        let svc = CriRuntimeService::new();
        let cfg = config("p");
        let id = run(&svc, Some(cfg.clone()), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        let resp = status_of(&svc, &id).unwrap();
        let st = resp.status.unwrap();
        assert_eq!(st.id, id);
        assert_eq!(st.metadata, cfg.metadata);
        assert_eq!(st.state, PodSandboxState::SandboxReady as i32);
        assert_eq!(st.labels, cfg.labels);
        assert_eq!(st.annotations, cfg.annotations);
        assert_eq!(st.runtime_handler, "");
        assert!(st.created_at > 0 && resp.timestamp >= st.created_at);
        assert!(resp.containers_statuses.is_empty() && resp.info.is_empty());
        assert!(st.network.is_none() && st.linux.is_none());

        stop_id(&svc, &id);
        let st2 = status_of(&svc, &id).unwrap().status.unwrap();
        assert_eq!(st2.state, PodSandboxState::SandboxNotready as i32);
        assert_eq!(st2.created_at, st.created_at);
        assert_eq!(st2.annotations, st.annotations);

        remove_id(&svc, &id);
        assert_eq!(status_of(&svc, &id).unwrap_err().code(), Code::NotFound);
    }

    /// ERR-3・TASK-57.3: 空 ID は INVALID_ARGUMENT、未知 ID は NOT_FOUND で、文言に入力 ID を含めない。
    #[test]
    fn task_57_3_status_rejects_bad_ids() {
        let svc = CriRuntimeService::new();
        assert_eq!(
            status_of(&svc, "").unwrap_err().code(),
            Code::InvalidArgument
        );
        let err = status_of(&svc, "secret-id-xyz").unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        assert!(!err.message().contains("secret-id-xyz"));
        assert_eq!(svc.sandbox_count(), 0);
    }

    /// CRI-1・TASK-57.3（受け入れ基準）: 作成・停止・削除の後の List がレジストリの状態と整合する。
    #[test]
    fn task_57_3_list_matches_registry_after_create_stop_remove() {
        let svc = CriRuntimeService::new();
        let ids: Vec<String> = (0..3)
            .map(|i| {
                run(&svc, Some(config(&format!("p{i}"))), "")
                    .unwrap()
                    .into_inner()
                    .pod_sandbox_id
            })
            .collect();
        assert_eq!(ids_of(&svc, None), expected_order(&svc));
        assert_eq!(ids_of(&svc, None).len(), 3);

        stop_id(&svc, &ids[1]);
        let items = block_on(
            svc.list_pod_sandbox(Request::new(v1::ListPodSandboxRequest { filter: None })),
        )
        .unwrap()
        .into_inner()
        .items;
        for item in &items {
            let expect = if item.id == ids[1] {
                PodSandboxState::SandboxNotready
            } else {
                PodSandboxState::SandboxReady
            };
            assert_eq!(item.state, expect as i32);
        }

        remove_id(&svc, &ids[0]);
        remove_id(&svc, &ids[0]);
        let after = ids_of(&svc, None);
        assert_eq!(after.len(), 2);
        assert!(!after.contains(&ids[0]));
        assert_eq!(after, expected_order(&svc));
        assert_eq!(after.len(), svc.sandbox_count());
    }

    /// CRI-1・TASK-57.3: フィルタは AND で、一致なしは空の一覧、不正な値は INVALID_ARGUMENT。
    #[test]
    fn task_57_3_list_filters() {
        let svc = CriRuntimeService::new();
        let mut c1 = config("a");
        c1.labels.insert("tier".into(), "web".into());
        let a = run(&svc, Some(c1), "").unwrap().into_inner().pod_sandbox_id;
        let b = run(&svc, Some(config("b")), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        stop_id(&svc, &b);
        let f = |id: &str, state: Option<i32>, labels: &[(&str, &str)]| v1::PodSandboxFilter {
            id: id.into(),
            state: state.map(|state| v1::PodSandboxStateValue { state }),
            label_selector: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        };
        assert_eq!(ids_of(&svc, Some(f(&a, None, &[]))), vec![a.clone()]);
        assert_eq!(ids_of(&svc, Some(f("", Some(0), &[]))), vec![a.clone()]);
        assert_eq!(ids_of(&svc, Some(f("", Some(1), &[]))), vec![b.clone()]);
        assert_eq!(
            ids_of(&svc, Some(f("", None, &[("tier", "web")]))),
            vec![a.clone()]
        );
        assert_eq!(ids_of(&svc, Some(f("", None, &[("k", "v")]))).len(), 2);
        assert!(ids_of(&svc, Some(f("", None, &[("k", "other")]))).is_empty());
        assert!(ids_of(&svc, Some(f("", None, &[("k", "v"), ("tier", "db")]))).is_empty());
        assert!(ids_of(&svc, Some(f(&a, Some(1), &[]))).is_empty());
        assert!(ids_of(&svc, Some(f("unknown", None, &[]))).is_empty());

        for bad in [
            f("", Some(99), &[]),
            v1::PodSandboxFilter {
                label_selector: [(
                    "k".repeat(MAX_LABEL_SELECTOR_STRING_BYTES + 1),
                    String::new(),
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            v1::PodSandboxFilter {
                label_selector: (0..16)
                    .map(|i| {
                        (
                            format!("{i:0>2}"),
                            "v".repeat(MAX_LABEL_SELECTOR_STRING_BYTES),
                        )
                    })
                    .collect(),
                ..Default::default()
            },
            v1::PodSandboxFilter {
                label_selector: (0..=MAX_CONFIG_COLLECTION_ENTRIES)
                    .map(|i| (format!("k{i}"), String::new()))
                    .collect(),
                ..Default::default()
            },
        ] {
            let err = block_on(
                svc.list_pod_sandbox(Request::new(v1::ListPodSandboxRequest {
                    filter: Some(bad),
                })),
            )
            .unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
        }
        assert_eq!(svc.sandbox_count(), 2);
    }

    /// REPAIR-4・TASK-57.3: Status/List は成功・失敗の双方で 1 件ずつ記録され、機微情報を含まない。
    #[test]
    fn task_57_3_status_and_list_are_recorded() {
        let collect = Arc::new(Collect::default());
        let svc = CriRuntimeService::with_recorder(collect.clone());
        let id = run(&svc, Some(config("p")), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        status_of(&svc, &id).unwrap();
        status_of(&svc, "nope").unwrap_err();
        ids_of(&svc, None);
        let bad = v1::PodSandboxFilter {
            state: Some(v1::PodSandboxStateValue { state: 99 }),
            ..Default::default()
        };
        block_on(
            svc.list_pod_sandbox(Request::new(v1::ListPodSandboxRequest {
                filter: Some(bad),
            })),
        )
        .unwrap_err();
        let samples = collect.items();
        let lines: Vec<(&str, CriOpOutcome, Code)> = samples
            .iter()
            .skip(1)
            .map(|s| (s.kind().as_str(), s.outcome(), s.code()))
            .collect();
        assert_eq!(
            lines,
            vec![
                ("cri.pod_sandbox_status", CriOpOutcome::Success, Code::Ok),
                (
                    "cri.pod_sandbox_status",
                    CriOpOutcome::Failure,
                    Code::NotFound
                ),
                ("cri.list_pod_sandbox", CriOpOutcome::Success, Code::Ok),
                (
                    "cri.list_pod_sandbox",
                    CriOpOutcome::Failure,
                    Code::InvalidArgument
                ),
            ]
        );
        assert!(!format!("{samples:?}").contains(&id));
    }

    fn container_config(name: &str, attempt: u32) -> v1::ContainerConfig {
        let mut c = v1::ContainerConfig {
            metadata: Some(v1::ContainerMetadata {
                name: name.into(),
                attempt,
            }),
            image: Some(v1::ImageSpec {
                image: "busybox:1.36".into(),
                ..Default::default()
            }),
            command: vec!["/bin/sh".into()],
            ..Default::default()
        };
        c.labels.insert("k".into(), "v".into());
        c.annotations.insert("a".into(), "b".into());
        c
    }

    fn create(
        svc: &CriRuntimeService,
        sandbox_id: &str,
        config: Option<v1::ContainerConfig>,
    ) -> Result<String, Status> {
        block_on(
            svc.create_container(Request::new(v1::CreateContainerRequest {
                pod_sandbox_id: sandbox_id.into(),
                config,
                sandbox_config: None,
            })),
        )
        .map(|r| r.into_inner().container_id)
    }

    fn start(svc: &CriRuntimeService, id: &str) -> Result<(), Status> {
        block_on(svc.start_container(Request::new(v1::StartContainerRequest {
            container_id: id.into(),
        })))
        .map(|_| ())
    }

    /// CRI-1・TASK-58.1: Create は 64 文字の小文字 16 進 ID を返し、状態 created で登録する。
    #[test]
    fn task_58_1_create_registers_created_container() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let cfg = container_config("c", 0);
        let id = create(&svc, &sb, Some(cfg.clone())).unwrap();
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        let reg = svc.registry.lock().unwrap();
        let rec = reg.containers.get(&id).unwrap();
        assert_eq!(rec.state.to_proto() as i32, 0);
        assert_eq!(rec.pod_sandbox_id, sb);
        assert!(rec.created_at_nanos > 0);
        assert_eq!(rec.started_at_nanos, 0);
        // labels・annotations を含む config を無改変で保持する。
        assert_eq!(rec.config, cfg);
        assert_eq!(reg.container_keys.len(), 1);
        assert_eq!(reg.container_retained_bytes, rec.retained_bytes);
    }

    /// CRI-1・TASK-58.1（受け入れ条件）: Create の後の Start で running になる。
    #[test]
    fn task_58_1_create_then_start_makes_running() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let id = create(&svc, &sb, Some(container_config("c", 0))).unwrap();
        start(&svc, &id).unwrap();
        let reg = svc.registry.lock().unwrap();
        let rec = reg.containers.get(&id).unwrap();
        assert_eq!(rec.state, ContainerState::Running);
        assert_eq!(rec.state.to_proto() as i32, 1);
        assert!(rec.started_at_nanos >= rec.created_at_nanos);
    }

    /// ERR-3・TASK-58.1（受け入れ条件）: 同一 sandbox で同じ (name, attempt) の再作成は ALREADY_EXISTS で、
    /// レジストリは変わらない。attempt が違う・別 sandbox なら成功する。
    #[test]
    fn task_58_1_duplicate_container_returns_already_exists() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let other = run_id(&svc);
        create(&svc, &sb, Some(container_config("c", 0))).unwrap();
        let (count, bytes) = (svc.container_count(), svc.container_retained_bytes());
        let err = create(&svc, &sb, Some(container_config("c", 0))).unwrap_err();
        assert_eq!(err.code(), Code::AlreadyExists);
        assert_eq!(err.message(), "container already exists");
        assert_eq!(svc.container_count(), count);
        assert_eq!(svc.container_retained_bytes(), bytes);
        create(&svc, &sb, Some(container_config("c", 1))).unwrap();
        create(&svc, &other, Some(container_config("c", 0))).unwrap();
        assert_eq!(svc.container_count(), 3);
    }

    /// ERR-3・TASK-58.1: Create の前提違反のコード対応。
    #[test]
    fn task_58_1_create_error_codes() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        assert_eq!(
            create(&svc, "", Some(container_config("c", 0)))
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
        assert_eq!(
            create(&svc, &sb, None).unwrap_err().code(),
            Code::InvalidArgument
        );
        let err = create(&svc, &"0".repeat(64), Some(container_config("c", 0))).unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        stop(&svc, &sb).unwrap();
        let err = create(&svc, &sb, Some(container_config("c", 0))).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(svc.container_count(), 0);
    }

    /// ERR-3・TASK-58.1: Start のコード対応（空 ID・未知 ID・二重 Start・停止済み sandbox）。
    #[test]
    fn task_58_1_start_error_codes() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        assert_eq!(start(&svc, "").unwrap_err().code(), Code::InvalidArgument);
        assert_eq!(
            start(&svc, &"0".repeat(64)).unwrap_err().code(),
            Code::NotFound
        );
        let id = create(&svc, &sb, Some(container_config("c", 0))).unwrap();
        start(&svc, &id).unwrap();
        let err = start(&svc, &id).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        // 停止済み sandbox 配下の created コンテナは起動できない。
        let sb2 = run_id(&svc);
        let id2 = create(&svc, &sb2, Some(container_config("c", 0))).unwrap();
        stop(&svc, &sb2).unwrap();
        let err = start(&svc, &id2).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        let reg = svc.registry.lock().unwrap();
        assert_eq!(
            reg.containers.get(&id2).unwrap().state,
            ContainerState::Created
        );
    }

    /// TASK-58.1: 件数・保持量の上限超過は FAILED_PRECONDITION。
    #[test]
    fn task_58_1_limits_are_enforced() {
        let svc = CriRuntimeService::new()
            .with_container_limits(ContainerLimits::new().with_max_containers(1));
        let sb = run_id(&svc);
        create(&svc, &sb, Some(container_config("a", 0))).unwrap();
        let err = create(&svc, &sb, Some(container_config("b", 0))).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(svc.container_count(), 1);

        let svc = CriRuntimeService::new()
            .with_container_limits(ContainerLimits::new().with_max_retained_bytes(1));
        let sb = run_id(&svc);
        let err = create(&svc, &sb, Some(container_config("a", 0))).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(svc.container_count(), 0);
        assert_eq!(svc.container_retained_bytes(), 0);
    }

    /// TASK-58.1: RemovePodSandbox は配下のコンテナと保持量を解放し、同名の再作成が通る。
    #[test]
    fn task_58_1_remove_sandbox_releases_containers() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let keep = run_id(&svc);
        create(&svc, &sb, Some(container_config("c", 0))).unwrap();
        create(&svc, &keep, Some(container_config("c", 0))).unwrap();
        let kept_bytes = {
            let reg = svc.registry.lock().unwrap();
            reg.containers
                .values()
                .filter(|c| c.pod_sandbox_id == keep)
                .map(|c| c.retained_bytes)
                .sum::<usize>()
        };
        remove(&svc, &sb).unwrap();
        assert_eq!(svc.container_count(), 1);
        assert_eq!(svc.container_retained_bytes(), kept_bytes);
        assert_eq!(svc.registry.lock().unwrap().container_keys.len(), 1);
    }

    /// REPAIR-4・TASK-58.1: 全終了経路が 1 件ずつ記録され、config の内容は記録先へ渡らない。
    #[test]
    fn task_58_1_outcomes_are_recorded_without_content() {
        let collect = Arc::new(Collect::default());
        let svc = CriRuntimeService::with_recorder(collect.clone());
        let sb = run_id(&svc);
        let mut cfg = container_config("c", 0);
        cfg.envs.push(v1::KeyValue {
            key: "TOKEN".into(),
            value: "do-not-record".into(),
        });
        let id = create(&svc, &sb, Some(cfg.clone())).unwrap();
        create(&svc, &sb, Some(cfg)).unwrap_err();
        start(&svc, &id).unwrap();
        start(&svc, &id).unwrap_err();
        let (c, s) = (CriOpKind::CreateContainer, CriOpKind::StartContainer);
        assert_eq!(
            collect.outcomes()[1..],
            [
                (c, CriOpOutcome::Success, Code::Ok),
                (c, CriOpOutcome::Failure, Code::AlreadyExists),
                (s, CriOpOutcome::Success, Code::Ok),
                (s, CriOpOutcome::Failure, Code::FailedPrecondition),
            ]
        );
        let dump = format!("{:?}{svc:?}", collect.items());
        assert!(!dump.contains("do-not-record") && !dump.contains(&id));
    }

    /// TASK-58.1: 並行 Create でも ID は一意で、件数の上限を超えない。
    #[test]
    fn task_58_1_concurrent_create_respects_limit() {
        let svc = CriRuntimeService::new()
            .with_container_limits(ContainerLimits::new().with_max_containers(8));
        let sb = run_id(&svc);
        let ids: Vec<Result<String, Status>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16u32)
                .map(|i| {
                    let (svc, sb) = (&svc, &sb);
                    scope.spawn(move || create(svc, sb, Some(container_config("c", i))))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let ok: Vec<&String> = ids.iter().filter_map(|r| r.as_ref().ok()).collect();
        assert_eq!(ok.len(), 8);
        let unique: HashSet<&&String> = ok.iter().collect();
        assert_eq!(unique.len(), 8);
        assert_eq!(svc.container_count(), 8);
    }
}
