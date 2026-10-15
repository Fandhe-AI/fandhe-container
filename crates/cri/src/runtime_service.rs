//! `RuntimeService` の CRI 実装（TASK-57.1〜57.3・TASK-58.1・#429・#430・#431・#433・CRI-1・ERR-3）。
//!
//! `fandhe-container-plugin-cri`（TASK-108）が gRPC サーバーへ載せる `RuntimeService` 実装の本体。
//! 本ファイルの時点で実装済みなのは `RunPodSandbox`・`StopPodSandbox`・`RemovePodSandbox`・
//! `PodSandboxStatus`・`ListPodSandbox` と、`CreateContainer`・`StartContainer`（TASK-58.1）・
//! `StopContainer`・`RemoveContainer`（TASK-58.2・#434）・`ListContainers`・`ContainerStatus`
//! （TASK-58.3・#435）で、他の RPC は `Unimplemented` を返す。
//!
//! **Create/Start の扱い（CRI-1・ERR-3・TASK-58.1）**: cri-api の `CreateContainerRequest` にクライアント指定の
//! ID はなく、ID はサービスが採番する。proto は `(metadata.name, metadata.attempt)` を sandbox 内で一意と
//! 定めるため、同一サンドボックスで同じ組の再作成を `ALREADY_EXISTS`（「同一 ID の再作成」）とする。未知の
//! サンドボックスは `NOT_FOUND`、停止済み（notready）のサンドボックスへの作成・起動は `FAILED_PRECONDITION`。
//! `StartContainer` は created から running へ遷移し、二重起動は `FAILED_PRECONDITION`（冪等にしない）。
//! 実行層は既定では呼ばず、プロセスも起動しない記録上の遷移である。
//!
//! **実行層への接続（CRI-2・CRI-7・TASK-59.2・#438）**: [`CriRuntimeService::with_runtime`] で
//! [`RuntimeAdapter`] と [`BundleProvider`] を注入すると、`CreateContainer` は bundle を用意して
//! `ContainerRuntime::create`、`StartContainer` は `ContainerRuntime::start` を `spawn_blocking` 上で呼ぶ。
//! 呼び出し中はレジストリのロックを持たず、記録の `in_flight` フラグで二重 Start・Remove・親サンドボックスの
//! 除去を `FAILED_PRECONDITION` にする。実行層が失敗したら記録を巻き戻し（Create）・Created へ戻し（Start）、
//! 「記録上だけ running」のフォールバックはしない（fail-closed）。注入しない場合は従来のスタブ動作のまま。
//! 未実装（REPAIR-3）: `RunPodSandbox` は実行層に対応操作が無く記録のみ（共有 namespace・net 連携は後続）。
//! bundle の生成の本体（image 展開・`ContainerConfig` から `config.json`）と Stop・Remove の kill・delete
//! 接続（TASK-59.3・#439）は未提供で、呼び出し元の中断で実行層側に残った資源の回収も
//! 後続（TASK-59.3・TASK-114）で扱う。コンテナの記録の型と上限は `container` サブモジュール。
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
//! Stop 時は配下の running コンテナを exited へ遷移させる（TASK-58.2・#434。created は変えない）。
//!
//! **StopContainer/RemoveContainer の扱い（CRI-1・ERR-3・TASK-58.2・#434）**: `StopContainer` は空 ID と負の
//! `timeout` を `INVALID_ARGUMENT`、未知 ID を `NOT_FOUND` にし、running を exited へ遷移させて
//! `finished_at` を記録する。停止済み（exited）は冪等に成功し状態を変えない（proto コメント）。未起動
//! （created）の Stop は前提違反として `FAILED_PRECONDITION`（ERR-3 の「`running` でないコンテナへの
//! `StopContainer`」の読み分け。kubelet 運用で問題になれば実機確認の TASK-60 で見直す）。`timeout` は
//! 猶予秒数で、スタブはプロセスを持たず待たないため検証だけして破棄する。`RemoveContainer` は空 ID を
//! `INVALID_ARGUMENT`、未知 ID を成功（冪等。proto コメント）とし、どの状態でも記録・重複判定キー・保持量を
//! 解放する（running の強制削除。プロセスの強制終了と、実待機の上限・REPAIR-5 のタイムアウトは TASK-59 で
//! 追加する。REPAIR-3）。
//!
//! **ListContainers/ContainerStatus の扱い（CRI-1・ERR-3・TASK-58.3・#435）**: 読み取り専用。
//! `ContainerStatus` は空 ID を `INVALID_ARGUMENT`、未知 ID（Remove 済みを含む）を `NOT_FOUND` にする。
//! `ListContainers` は一致なし・未知 ID・`CONTAINER_UNKNOWN` を空の一覧とし、未知の state 値と過大な
//! `label_selector` だけを `INVALID_ARGUMENT` にする。並びは `(created_at, id)` の昇順。labels・annotations は
//! 無改変で返し、`envs` は返さない。`exit_code`・`reason`・`image_ref`・`user`・`info` は空・0 のスタブで、
//! 実値は TASK-59（CRI-2）で埋める（REPAIR-3）。
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
//! **可観測性（REPAIR-4）**: `RunPodSandbox`・`StopPodSandbox`・`RemovePodSandbox`・`PodSandboxStatus`・`ListPodSandbox`・`CreateContainer`・`StartContainer`・`StopContainer`・`RemoveContainer`・`ListContainers`・`ContainerStatus` は全終了経路（成功・入力不正・上限超過・内部エラー）で、
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

use crate::adapter::{BundleProvider, RuntimeAdapter};
use crate::instrument::{CriOpKind, CriOpRecorder, CriOpTimer, NoopCriOpRecorder};
use crate::runtime::v1::{
    self, ContainerState as CriContainerState, PodSandboxConfig, PodSandboxState,
    runtime_service_server::RuntimeService,
};
use config_limits::BoundedConfig;
use container::{
    ContainerRecord, ContainerState, ValidatedContainerFilter, ValidatedCreate,
    validate_create_request,
};

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
    /// 実行層への接続（TASK-59.2）。`None` のときは記録上の遷移だけのスタブ動作。
    runtime: Option<RuntimeBinding>,
}

/// 実行層への接続（アダプタと bundle の供給元。CRI-2・CRI-7）。
#[derive(Clone)]
struct RuntimeBinding {
    adapter: RuntimeAdapter,
    bundles: Arc<dyn BundleProvider>,
}

/// 実行層を呼び出し中の操作の種類（[`InFlightGuard`] が巻き戻しの方法を選ぶ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InFlightKind {
    Create,
    Start,
}

/// 実行層の呼び出し中に立てた `in_flight` を、確定されないまま破棄されたら巻き戻す番人（TASK-59.2）。
///
/// 失敗（`?`）・panic・クライアント中断による future の破棄のどれでも `Drop` で巻き戻すため、
/// 件数・保持量の枠と `in_flight` を残さない。確定は [`InFlightGuard::commit`]。
struct InFlightGuard<'a> {
    service: &'a CriRuntimeService,
    id: String,
    kind: InFlightKind,
    committed: bool,
}

impl<'a> InFlightGuard<'a> {
    fn new(service: &'a CriRuntimeService, id: String, kind: InFlightKind) -> Self {
        Self {
            service,
            id,
            kind,
            committed: false,
        }
    }

    /// 実行層の成功を記録へ反映して確定する。反映に失敗したら巻き戻される。
    fn commit(mut self) -> Result<(), Status> {
        self.service.commit_in_flight(&self.id, self.kind)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.service.rollback_in_flight(&self.id, self.kind);
        }
    }
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
            runtime: None,
        }
    }

    /// `CreateContainer`・`StartContainer` を実行層（`ContainerRuntime`）へ接続する（TASK-59.2・CRI-2）。
    ///
    /// 呼ばなければ従来のスタブ動作（プロセスを起動しない記録上の遷移）のまま。接続後は両 RPC が
    /// `spawn_blocking` を使うため tokio ランタイム上で呼ぶこと。
    pub fn with_runtime(
        mut self,
        adapter: RuntimeAdapter,
        bundles: Arc<dyn BundleProvider>,
    ) -> Self {
        self.runtime = Some(RuntimeBinding { adapter, bundles });
        self
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
        let finished_at_nanos = now_nanos()?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
        let record = registry
            .records
            .get_mut(&req.pod_sandbox_id)
            .ok_or_else(|| Status::not_found("sandbox not found"))?;
        record.state = SandboxState::NotReady;
        // 配下の running コンテナを exited にする（TASK-58.2。created・停止済みは変えない）。
        for c in registry.containers.values_mut().filter(|c| {
            c.pod_sandbox_id == req.pod_sandbox_id && c.state == ContainerState::Running
        }) {
            c.state = ContainerState::Exited;
            c.finished_at_nanos = finished_at_nanos;
        }
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
        // 配下に実行層を呼び出し中のコンテナがあれば除去しない（実行層に資源が残るため。TASK-59.2）。
        if registry
            .containers
            .values()
            .any(|c| c.pod_sandbox_id == req.pod_sandbox_id && c.in_flight)
        {
            return Err(Status::failed_precondition(
                "container operation in progress",
            ));
        }
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

    /// `CreateContainer` の本体（スタブ経路）。検証・採番・登録を行い、失敗時はレジストリを変更しない（TASK-58.1）。
    ///
    /// 状態は `Created`。実行層は呼ばない（実行層接続時は `create_container_runtime`。REPAIR-3）。
    /// エラー文言には入力値（ID・名前・labels）を含めない。
    fn create_container_impl(
        &self,
        req: v1::CreateContainerRequest,
    ) -> Result<v1::CreateContainerResponse, Status> {
        let (container_id, _, _) = self.reserve_container(req, false)?;
        Ok(v1::CreateContainerResponse { container_id })
    }

    /// 検証・採番・登録を行う（`in_flight` は実行層を呼び出し中として登録するか）。
    ///
    /// 戻り値は `(container_id, pod_sandbox_id, config)`。`config` は `in_flight` のときだけ複製して返す
    /// （bundle の供給元へ渡すため。上限検証済みで有界）。
    fn reserve_container(
        &self,
        req: v1::CreateContainerRequest,
        in_flight: bool,
    ) -> Result<(String, String, Option<v1::ContainerConfig>), Status> {
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
        // 要求由来の String は余分な capacity を持ちうる。照合に成功した ID（最大 64 文字）と名前は、
        // 内容長ちょうどの新しい String へ複製して保持し、要求側の確保領域を削除まで残さない
        // （retained_bytes は内容長の見積もりのため、capacity の保持は累積上限を迂回する）。
        let key = (
            String::from(pod_sandbox_id.as_str()),
            String::from(name.as_str()),
            attempt,
        );
        drop((pod_sandbox_id, name));
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
        let config = config.into_config();
        let provider_config = in_flight.then(|| config.clone());
        let sandbox_id = key.0.clone();
        registry.containers.insert(
            container_id.clone(),
            ContainerRecord {
                pod_sandbox_id: sandbox_id.clone(),
                config,
                state: ContainerState::Created,
                created_at_nanos,
                started_at_nanos: 0,
                finished_at_nanos: 0,
                retained_bytes,
                in_flight,
            },
        );
        registry.container_keys.insert(key);
        registry.container_retained_bytes = total_retained_bytes;
        Ok((container_id, sandbox_id, provider_config))
    }

    /// 実行層接続時の `CreateContainer`（TASK-59.2・CRI-2）。
    ///
    /// 仮登録（`in_flight`）→ ロックを外して bundle 用意と `ContainerRuntime::create`（`spawn_blocking`）→
    /// 確定、の 2 相。どの失敗・中断でも [`InFlightGuard`] が記録を巻き戻し、上限の枠を残さない。
    async fn create_container_runtime(
        &self,
        binding: &RuntimeBinding,
        req: v1::CreateContainerRequest,
    ) -> Result<v1::CreateContainerResponse, Status> {
        let (container_id, sandbox_id, config) = self.reserve_container(req, true)?;
        let guard = InFlightGuard::new(self, container_id.clone(), InFlightKind::Create);
        let config = config.ok_or_else(|| Status::internal("container config is unavailable"))?;
        let adapter = binding.adapter.clone();
        let bundles = Arc::clone(&binding.bundles);
        let id = container_id.clone();
        let status = tokio::task::spawn_blocking(move || {
            let bundle = bundles.prepare(&id, &sandbox_id, &config)?;
            adapter
                .create(&id, bundle)
                .inspect_err(|_| bundles.release(&id))
        })
        .await
        .map_err(|_| Status::internal("runtime task failed"))??;
        if status.state != CriContainerState::ContainerCreated {
            return Err(Status::internal("runtime returned an unexpected state"));
        }
        guard.commit()?;
        Ok(v1::CreateContainerResponse { container_id })
    }

    /// `StartContainer` の本体（スタブ経路）。created を running へ遷移させる（TASK-58.1）。
    ///
    /// 空 ID は `INVALID_ARGUMENT`、未知 ID は `NOT_FOUND`。running の再起動と、停止済みサンドボックス
    /// 配下の起動は `FAILED_PRECONDITION`（冪等にしない）。プロセスは起動しない記録上の遷移（実行層接続時は
    /// `start_container_runtime`。REPAIR-3）。
    fn start_container_impl(
        &self,
        req: v1::StartContainerRequest,
    ) -> Result<v1::StartContainerResponse, Status> {
        self.begin_start(req, false)?;
        Ok(v1::StartContainerResponse {})
    }

    /// Start の前提検査。`via_runtime` なら `in_flight` を立てて返し、そうでなければ running へ遷移させる。
    fn begin_start(&self, req: v1::StartContainerRequest, via_runtime: bool) -> Result<(), Status> {
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
        if record.state != ContainerState::Created || record.in_flight {
            return Err(Status::failed_precondition(
                "container is not in created state",
            ));
        }
        if let Some(record) = registry.containers.get_mut(&req.container_id) {
            if via_runtime {
                record.in_flight = true;
            } else {
                record.state = ContainerState::Running;
                record.started_at_nanos = started_at_nanos;
            }
        }
        Ok(())
    }

    /// 実行層接続時の `StartContainer`（TASK-59.2・CRI-2）。
    ///
    /// 前提検査と `in_flight` 化をロック下で行い、ロックを外して `ContainerRuntime::start`
    /// （`spawn_blocking`）を呼ぶ。成功して running が返ったときだけ記録を running にし、失敗・中断では
    /// created へ戻す（[`InFlightGuard`]）。
    async fn start_container_runtime(
        &self,
        binding: &RuntimeBinding,
        req: v1::StartContainerRequest,
    ) -> Result<v1::StartContainerResponse, Status> {
        let id = req.container_id.clone();
        self.begin_start(req, true)?;
        let guard = InFlightGuard::new(self, id.clone(), InFlightKind::Start);
        let adapter = binding.adapter.clone();
        let status = tokio::task::spawn_blocking(move || adapter.start(&id))
            .await
            .map_err(|_| Status::internal("runtime task failed"))??;
        if status.state != CriContainerState::ContainerRunning {
            return Err(Status::internal("runtime returned an unexpected state"));
        }
        guard.commit()?;
        Ok(v1::StartContainerResponse {})
    }

    /// 実行層の成功を記録へ反映する（Create は `in_flight` 解除、Start は running へ遷移）。
    fn commit_in_flight(&self, id: &str, kind: InFlightKind) -> Result<(), Status> {
        let started_at_nanos = now_nanos()?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
        let record = registry
            .containers
            .get_mut(id)
            .ok_or_else(|| Status::internal("container registry is inconsistent"))?;
        record.in_flight = false;
        if kind == InFlightKind::Start {
            record.state = ContainerState::Running;
            record.started_at_nanos = started_at_nanos;
        }
        Ok(())
    }

    /// 実行層の呼び出しが失敗・中断したときの巻き戻し。Create は記録を除去し、Start は `in_flight` を解く。
    ///
    /// ロックの汚染時は何もできない（汚染済みのレジストリは以後の RPC が `INTERNAL` で拒否する）。
    fn rollback_in_flight(&self, id: &str, kind: InFlightKind) {
        match kind {
            InFlightKind::Create => {
                let _ = self.drop_container(id, true);
            }
            InFlightKind::Start => {
                if let Ok(mut registry) = self.registry.lock()
                    && let Some(record) = registry.containers.get_mut(id)
                {
                    record.in_flight = false;
                }
            }
        }
    }

    /// `StopContainer` の本体。running を exited へ遷移させる（CRI-1・ERR-3・TASK-58.2）。
    ///
    /// 空 ID・負の `timeout` は `INVALID_ARGUMENT`、未知 ID は `NOT_FOUND`、created は
    /// `FAILED_PRECONDITION`。exited は冪等に成功し状態を変えない。`timeout`（猶予秒数）はスタブが
    /// 待たないため検証のみで破棄する（実待機は TASK-59 で上限と REPAIR-5 のタイムアウトつきで追加）。
    /// プロセスは終了させない記録上の遷移（REPAIR-3）。件数・保持量の枠は解放しない。
    fn stop_container_impl(
        &self,
        req: v1::StopContainerRequest,
    ) -> Result<v1::StopContainerResponse, Status> {
        if req.container_id.is_empty() {
            return Err(Status::invalid_argument("container_id is required"));
        }
        if req.timeout < 0 {
            return Err(Status::invalid_argument("timeout must not be negative"));
        }
        let finished_at_nanos = now_nanos()?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
        let record = registry
            .containers
            .get_mut(&req.container_id)
            .ok_or_else(|| Status::not_found("container not found"))?;
        match record.state {
            ContainerState::Running => {
                record.state = ContainerState::Exited;
                record.finished_at_nanos = finished_at_nanos;
                Ok(v1::StopContainerResponse {})
            }
            ContainerState::Exited => Ok(v1::StopContainerResponse {}),
            ContainerState::Created => Err(Status::failed_precondition(
                "container is not in running state",
            )),
        }
    }

    /// `RemoveContainer` の本体。記録・重複判定キー・保持量を解放する（CRI-1・TASK-58.2）。
    ///
    /// 未知 ID は成功（冪等）。どの状態でも除去する（running の強制削除。プロセスの強制終了は
    /// TASK-59。REPAIR-3）。キーの復元や保持量の引き算が不整合なら、レジストリを変更せず `INTERNAL`。
    fn remove_container_impl(
        &self,
        req: v1::RemoveContainerRequest,
    ) -> Result<v1::RemoveContainerResponse, Status> {
        if req.container_id.is_empty() {
            return Err(Status::invalid_argument("container_id is required"));
        }
        self.drop_container(&req.container_id, false)?;
        Ok(v1::RemoveContainerResponse {})
    }

    /// 記録・重複判定キー・保持量を除去する（未知 ID は何もしない）。
    ///
    /// `include_in_flight` が偽のとき、実行層の呼び出し中（`in_flight`）の記録は `FAILED_PRECONDITION`
    /// で拒否する（Create の巻き戻しだけが真で呼ぶ）。
    fn drop_container(&self, container_id: &str, include_in_flight: bool) -> Result<(), Status> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
        let Some(record) = registry.containers.get(container_id) else {
            return Ok(());
        };
        if record.in_flight && !include_in_flight {
            return Err(Status::failed_precondition(
                "container operation in progress",
            ));
        }
        // 先に検証してから変更し、失敗時にレジストリを変更しない。
        let inconsistent = || Status::internal("container registry is inconsistent");
        let metadata = record.config.metadata.as_ref().ok_or_else(inconsistent)?;
        let key = (
            record.pod_sandbox_id.clone(),
            metadata.name.clone(),
            metadata.attempt,
        );
        let remaining = registry
            .container_retained_bytes
            .checked_sub(record.retained_bytes)
            .ok_or_else(inconsistent)?;
        if !registry.container_keys.contains(&key) {
            return Err(inconsistent());
        }
        registry.containers.remove(container_id);
        registry.container_keys.remove(&key);
        registry.container_retained_bytes = remaining;
        Ok(())
    }

    /// `ContainerStatus` の本体。読み取り専用（CRI-1・ERR-3・TASK-58.3・#435）。
    ///
    /// 空 ID は `INVALID_ARGUMENT`、未知 ID（Remove 済みを含む）は `NOT_FOUND`（文言に入力 ID を含めない）。
    /// `verbose` でも `info` は空のスタブ（REPAIR-3）。`envs` 等は応答に含めない。
    fn container_status_impl(
        &self,
        req: v1::ContainerStatusRequest,
    ) -> Result<v1::ContainerStatusResponse, Status> {
        if req.container_id.is_empty() {
            return Err(Status::invalid_argument("container_id is required"));
        }
        let status = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
            let record = registry
                .containers
                .get(&req.container_id)
                .ok_or_else(|| Status::not_found("container not found"))?;
            record.to_status(&req.container_id)
        };
        Ok(v1::ContainerStatusResponse {
            status: Some(status),
            info: HashMap::new(),
        })
    }

    /// `ListContainers` の本体。フィルタは AND、並びは `(created_at, id)` の昇順（CRI-1・TASK-58.3・#435）。
    ///
    /// 一致なし・未知 ID・`CONTAINER_UNKNOWN` は空の一覧。未知の state 値と過大な `label_selector` は
    /// `INVALID_ARGUMENT`。件数はレジストリの上限（[`MAX_CONTAINERS`]）で有界。
    fn list_containers_impl(
        &self,
        req: v1::ListContainersRequest,
    ) -> Result<v1::ListContainersResponse, Status> {
        let filter = ValidatedContainerFilter::new(req.filter)?;
        let mut containers = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| Status::internal("sandbox registry is unavailable"))?;
            registry
                .containers
                .iter()
                .filter(|(id, record)| filter.matches(id, record))
                .map(|(id, record)| record.to_summary(id))
                .collect::<Vec<_>>()
        };
        containers.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        Ok(v1::ListContainersResponse { containers })
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

/// `label_selector` の件数・キー値長・合計バイト数（`extra_bytes` は同じフィルタの id 等の長さ）を検証する。
///
/// `ListPodSandbox`・`ListContainers`（TASK-58.3）が共用する。走査（レジストリのロック中）の前に拒否し、
/// 入力サイズ×登録件数の処理を有限にする（ERR-3）。長さの加算は飽和演算で行う。
fn validate_label_selector(
    selector: &HashMap<String, String>,
    extra_bytes: usize,
) -> Result<(), Status> {
    if selector.len() > MAX_CONFIG_COLLECTION_ENTRIES {
        return Err(Status::invalid_argument(
            "label_selector has too many entries",
        ));
    }
    let mut total = extra_bytes;
    for (k, v) in selector {
        if k.len() > MAX_LABEL_SELECTOR_STRING_BYTES || v.len() > MAX_LABEL_SELECTOR_STRING_BYTES {
            return Err(Status::invalid_argument(
                "label_selector key or value is too long",
            ));
        }
        total = total.saturating_add(k.len()).saturating_add(v.len());
    }
    if total > MAX_LABEL_SELECTOR_TOTAL_BYTES {
        return Err(Status::invalid_argument("label_selector is too large"));
    }
    Ok(())
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
        validate_label_selector(&filter.label_selector, filter.id.len())?;
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
        let req = request.into_inner();
        let result = match &self.runtime {
            Some(binding) => self.create_container_runtime(binding, req).await,
            None => self.create_container_impl(req),
        };
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// コンテナを running にする（二重起動は `FAILED_PRECONDITION`。CRI-1・ERR-3・TASK-58.1）。
    async fn start_container(
        &self,
        request: Request<v1::StartContainerRequest>,
    ) -> Result<Response<v1::StartContainerResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::StartContainer);
        let req = request.into_inner();
        let result = match &self.runtime {
            Some(binding) => self.start_container_runtime(binding, req).await,
            None => self.start_container_impl(req),
        };
        timer.finish_with(&result);
        result.map(Response::new)
    }
    /// コンテナを exited にする（停止済みは冪等・created は `FAILED_PRECONDITION`。
    /// CRI-1・ERR-3・TASK-58.2）。
    async fn stop_container(
        &self,
        request: Request<v1::StopContainerRequest>,
    ) -> Result<Response<v1::StopContainerResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::StopContainer);
        let result = self.stop_container_impl(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// コンテナの記録を除去する（未知 ID は冪等に成功。CRI-1・TASK-58.2）。
    async fn remove_container(
        &self,
        request: Request<v1::RemoveContainerRequest>,
    ) -> Result<Response<v1::RemoveContainerResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::RemoveContainer);
        let result = self.remove_container_impl(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
    }
    /// コンテナの一覧を返す（読み取り専用。CRI-1・TASK-58.3・#435）。
    async fn list_containers(
        &self,
        request: Request<v1::ListContainersRequest>,
    ) -> Result<Response<v1::ListContainersResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::ListContainers);
        let result = self.list_containers_impl(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
    }
    async fn stream_containers(
        &self,
        _request: Request<v1::StreamContainersRequest>,
    ) -> Result<Response<Self::StreamContainersStream>, Status> {
        Err(Status::unimplemented("stream_containers"))
    }
    /// コンテナの状態を返す（読み取り専用。CRI-1・TASK-58.3・#435）。
    async fn container_status(
        &self,
        request: Request<v1::ContainerStatusRequest>,
    ) -> Result<Response<v1::ContainerStatusResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::ContainerStatus);
        let result = self.container_status_impl(request.into_inner());
        timer.finish_with(&result);
        result.map(Response::new)
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
        block_on(svc.update_container_resources(Request::new(
            v1::UpdateContainerResourcesRequest::default(),
        )))
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

    /// 未実装の RPC は Unimplemented のまま（update_container_resources を実装する際にこのテストを差し替える）。
    #[test]
    fn task_57_1_other_rpcs_remain_unimplemented() {
        let svc = CriRuntimeService::new();
        let err = block_on(svc.update_container_resources(Request::new(
            v1::UpdateContainerResourcesRequest::default(),
        )))
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

    /// TASK-58.1・REPAIR-9（リソース上限）: 過大 capacity の ID・名前を渡しても、保持する key と
    /// 記録の String は内容長ちょうどの確保になる。
    #[test]
    fn task_58_1_retained_strings_do_not_keep_oversized_capacity() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let mut big_id = String::with_capacity(1 << 20);
        big_id.push_str(&sb);
        let mut big_name = String::with_capacity(1 << 20);
        big_name.push('c');
        let mut cfg = container_config("c", 0);
        cfg.metadata.as_mut().unwrap().name = big_name;
        let id = block_on(
            svc.create_container(Request::new(v1::CreateContainerRequest {
                pod_sandbox_id: big_id,
                config: Some(cfg),
                sandbox_config: None,
            })),
        )
        .unwrap()
        .into_inner()
        .container_id;
        let reg = svc.registry.lock().unwrap();
        for (sid, name, _) in &reg.container_keys {
            assert_eq!(sid.capacity(), 64);
            assert_eq!(name.capacity(), 1);
        }
        let rec = reg.containers.get(&id).unwrap();
        assert_eq!(rec.pod_sandbox_id.capacity(), 64);
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

    fn stop_c(svc: &CriRuntimeService, id: &str, timeout: i64) -> Result<(), Status> {
        block_on(svc.stop_container(Request::new(v1::StopContainerRequest {
            container_id: id.into(),
            timeout,
        })))
        .map(|_| ())
    }

    fn remove_c(svc: &CriRuntimeService, id: &str) -> Result<(), Status> {
        block_on(
            svc.remove_container(Request::new(v1::RemoveContainerRequest {
                container_id: id.into(),
            })),
        )
        .map(|_| ())
    }

    fn running(svc: &CriRuntimeService, sb: &str, name: &str) -> String {
        let id = create(svc, sb, Some(container_config(name, 0))).unwrap();
        start(svc, &id).unwrap();
        id
    }

    /// CRI-1・TASK-58.2: running の Stop で exited になり finished_at が記録され、枠は解放されない。
    #[test]
    fn task_58_2_stop_running_becomes_exited() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let id = running(&svc, &sb, "c");
        let (count, bytes) = (svc.container_count(), svc.container_retained_bytes());
        stop_c(&svc, &id, 30).unwrap();
        let reg = svc.registry.lock().unwrap();
        let rec = reg.containers.get(&id).unwrap();
        assert_eq!(rec.state, ContainerState::Exited);
        assert_eq!(rec.state.to_proto() as i32, 2);
        assert!(rec.finished_at_nanos >= rec.started_at_nanos);
        drop(reg);
        assert_eq!(
            (svc.container_count(), svc.container_retained_bytes()),
            (count, bytes)
        );
    }

    /// CRI-1・TASK-58.2: 停止済みの Stop は成功し、状態も finished_at も変えない。timeout 0・最大値も通る。
    #[test]
    fn task_58_2_stop_is_idempotent_on_exited() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let id = running(&svc, &sb, "c");
        stop_c(&svc, &id, 0).unwrap();
        let first = svc.registry.lock().unwrap().containers[&id].finished_at_nanos;
        stop_c(&svc, &id, i64::MAX).unwrap();
        let reg = svc.registry.lock().unwrap();
        assert_eq!(reg.containers[&id].state, ContainerState::Exited);
        assert_eq!(reg.containers[&id].finished_at_nanos, first);
    }

    /// ERR-3・TASK-58.2（受け入れ条件）: created（running でない）の Stop は FAILED_PRECONDITION で状態不変。
    #[test]
    fn task_58_2_stop_created_is_failed_precondition() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let id = create(&svc, &sb, Some(container_config("c", 0))).unwrap();
        let err = stop_c(&svc, &id, 0).unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(err.message(), "container is not in running state");
        let reg = svc.registry.lock().unwrap();
        assert_eq!(reg.containers[&id].state, ContainerState::Created);
        assert_eq!(reg.containers[&id].finished_at_nanos, 0);
    }

    /// ERR-3・TASK-58.2: 空 ID・負の timeout は INVALID_ARGUMENT（状態不変）、未知 ID は NOT_FOUND。
    #[test]
    fn task_58_2_stop_error_codes() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let id = running(&svc, &sb, "c");
        assert_eq!(
            stop_c(&svc, "", 0).unwrap_err().code(),
            Code::InvalidArgument
        );
        assert_eq!(
            stop_c(&svc, &id, -1).unwrap_err().code(),
            Code::InvalidArgument
        );
        assert_eq!(
            svc.registry.lock().unwrap().containers[&id].state,
            ContainerState::Running
        );
        let err = stop_c(&svc, &"0".repeat(64), 0).unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        assert!(!err.message().contains(&"0".repeat(64)));
    }

    /// CRI-1・TASK-58.2（受け入れ条件）: Remove は created / running / exited のいずれでも記録・キー・
    /// 保持量を解放し、同じ (name, attempt) を再作成でき、他コンテナは変わらない。
    #[test]
    fn task_58_2_remove_releases_all_state() {
        for kind in 0..3 {
            let svc = CriRuntimeService::new();
            let sb = run_id(&svc);
            let other = create(&svc, &sb, Some(container_config("other", 0))).unwrap();
            let other_bytes = svc.container_retained_bytes();
            let id = match kind {
                0 => create(&svc, &sb, Some(container_config("c", 0))).unwrap(),
                1 => running(&svc, &sb, "c"),
                _ => {
                    let id = running(&svc, &sb, "c");
                    stop_c(&svc, &id, 0).unwrap();
                    id
                }
            };
            remove_c(&svc, &id).unwrap();
            let reg = svc.registry.lock().unwrap();
            assert!(!reg.containers.contains_key(&id));
            assert!(reg.containers.contains_key(&other));
            assert_eq!(reg.container_keys.len(), 1);
            assert_eq!(reg.container_retained_bytes, other_bytes);
            drop(reg);
            create(&svc, &sb, Some(container_config("c", 0))).unwrap();
            assert_eq!(svc.container_count(), 2);
        }
    }

    /// CRI-1・TASK-58.2: 空 ID は INVALID_ARGUMENT、未知 ID と 2 回目の Remove は成功。
    #[test]
    fn task_58_2_remove_is_idempotent_and_validates() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let id = create(&svc, &sb, Some(container_config("c", 0))).unwrap();
        assert_eq!(
            remove_c(&svc, "").unwrap_err().code(),
            Code::InvalidArgument
        );
        remove_c(&svc, &"0".repeat(64)).unwrap();
        remove_c(&svc, &id).unwrap();
        remove_c(&svc, &id).unwrap();
        assert_eq!(
            (svc.container_count(), svc.container_retained_bytes()),
            (0, 0)
        );
    }

    /// TASK-58.2: 保持量が記録より小さい不整合では INTERNAL で失敗し、レジストリを変更しない。
    #[test]
    fn task_58_2_remove_inconsistent_registry_fails_without_change() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let id = create(&svc, &sb, Some(container_config("c", 0))).unwrap();
        svc.registry.lock().unwrap().container_retained_bytes = 1;
        let err = remove_c(&svc, &id).unwrap_err();
        assert_eq!(err.code(), Code::Internal);
        let reg = svc.registry.lock().unwrap();
        assert_eq!(reg.containers.len(), 1);
        assert_eq!(reg.container_keys.len(), 1);
        assert_eq!(reg.container_retained_bytes, 1);
    }

    /// CRI-1・TASK-58.2: StopPodSandbox は配下の running を exited にし、created は変えない。再実行で
    /// finished_at は変わらない。
    #[test]
    fn task_58_2_stop_sandbox_stops_running_containers() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let r = running(&svc, &sb, "r");
        let c = create(&svc, &sb, Some(container_config("c", 0))).unwrap();
        stop(&svc, &sb).unwrap();
        let first = {
            let reg = svc.registry.lock().unwrap();
            assert_eq!(reg.containers[&r].state, ContainerState::Exited);
            assert!(reg.containers[&r].finished_at_nanos > 0);
            assert_eq!(reg.containers[&c].state, ContainerState::Created);
            reg.containers[&r].finished_at_nanos
        };
        stop(&svc, &sb).unwrap();
        assert_eq!(
            svc.registry.lock().unwrap().containers[&r].finished_at_nanos,
            first
        );
    }

    /// REPAIR-4・TASK-58.2: Stop・Remove の全終了経路が 1 件ずつ記録され、ID を含まない。
    #[test]
    fn task_58_2_outcomes_are_recorded_without_content() {
        let collect = Arc::new(Collect::default());
        let svc = CriRuntimeService::with_recorder(collect.clone());
        let sb = run_id(&svc);
        let id = running(&svc, &sb, "c");
        stop_c(&svc, &id, 0).unwrap();
        stop_c(&svc, "", 0).unwrap_err();
        remove_c(&svc, &id).unwrap();
        remove_c(&svc, "").unwrap_err();
        let samples = collect.items();
        let tail: Vec<(&str, CriOpOutcome, Code)> = samples[samples.len() - 4..]
            .iter()
            .map(|s| (s.kind().as_str(), s.outcome(), s.code()))
            .collect();
        assert_eq!(
            tail,
            [
                ("cri.stop_container", CriOpOutcome::Success, Code::Ok),
                (
                    "cri.stop_container",
                    CriOpOutcome::Failure,
                    Code::InvalidArgument
                ),
                ("cri.remove_container", CriOpOutcome::Success, Code::Ok),
                (
                    "cri.remove_container",
                    CriOpOutcome::Failure,
                    Code::InvalidArgument
                ),
            ]
        );
        assert!(!format!("{samples:?}{svc:?}").contains(&id));
    }

    /// TASK-58.2: 同じコンテナへの並行 Stop は全て成功し、遷移は 1 回だけ。
    #[test]
    fn task_58_2_concurrent_stop_transitions_once() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let id = running(&svc, &sb, "c");
        let results: Vec<Result<(), Status>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let (svc, id) = (&svc, &id);
                    scope.spawn(move || stop_c(svc, id, 0))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(
            svc.registry.lock().unwrap().containers[&id].state,
            ContainerState::Exited
        );
    }

    fn list_c(
        svc: &CriRuntimeService,
        filter: Option<v1::ContainerFilter>,
    ) -> Result<Vec<v1::Container>, Status> {
        block_on(svc.list_containers(Request::new(v1::ListContainersRequest { filter })))
            .map(|r| r.into_inner().containers)
    }

    fn status_c(svc: &CriRuntimeService, id: &str) -> Result<v1::ContainerStatus, Status> {
        block_on(
            svc.container_status(Request::new(v1::ContainerStatusRequest {
                container_id: id.into(),
                verbose: true,
            })),
        )
        .map(|r| r.into_inner().status.unwrap())
    }

    fn state_filter(state: i32) -> Option<v1::ContainerFilter> {
        Some(v1::ContainerFilter {
            state: Some(v1::ContainerStateValue { state }),
            ..Default::default()
        })
    }

    /// 一覧の (id, state) を並びのまま取り出す。
    fn id_states(list: &[v1::Container]) -> Vec<(String, i32)> {
        list.iter().map(|c| (c.id.clone(), c.state)).collect()
    }

    /// CRI-1・TASK-58.3: Create・Start・Stop・Remove の各操作後の List が状態と整合し、Status とも一致する。
    #[test]
    fn task_58_3_list_reflects_create_stop_remove() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        assert!(list_c(&svc, None).unwrap().is_empty());
        let a = create(&svc, &sb, Some(container_config("a", 0))).unwrap();
        let b = create(&svc, &sb, Some(container_config("b", 0))).unwrap();
        let by_id =
            |list: &[v1::Container], id: &str| list.iter().find(|c| c.id == id).map(|c| c.state);
        let list = list_c(&svc, None).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(by_id(&list, &a), Some(0));
        assert_eq!(by_id(&list, &b), Some(0));
        start(&svc, &a).unwrap();
        let list = list_c(&svc, None).unwrap();
        assert_eq!(by_id(&list, &a), Some(1));
        assert_eq!(by_id(&list, &b), Some(0));
        assert_eq!(status_c(&svc, &a).unwrap().state, 1);
        stop_c(&svc, &a, 0).unwrap();
        let list = list_c(&svc, None).unwrap();
        assert_eq!(by_id(&list, &a), Some(2));
        assert_eq!(status_c(&svc, &a).unwrap().state, 2);
        remove_c(&svc, &a).unwrap();
        let list = list_c(&svc, None).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(by_id(&list, &b), Some(0));
        assert_eq!(
            status_c(&svc, &a).unwrap_err().code(),
            Code::NotFound,
            "removed container must not remain"
        );
        remove(&svc, &sb).unwrap();
        assert!(list_c(&svc, None).unwrap().is_empty());
        assert_eq!(status_c(&svc, &b).unwrap_err().code(), Code::NotFound);
    }

    /// CRI-1・TASK-58.3: 並びは (created_at, id) の昇順で決定的。
    #[test]
    fn task_58_3_list_is_sorted_by_created_at_then_id() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        for i in 0..6 {
            create(&svc, &sb, Some(container_config(&format!("c{i}"), 0))).unwrap();
        }
        let list = list_c(&svc, None).unwrap();
        assert_eq!(list.len(), 6);
        let keys: Vec<(i64, String)> = list.iter().map(|c| (c.created_at, c.id.clone())).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert_eq!(id_states(&list), id_states(&list_c(&svc, None).unwrap()));
    }

    /// CRI-1・TASK-58.3: フィルタは AND。一致なし・未知 ID・CONTAINER_UNKNOWN は空の一覧。
    #[test]
    fn task_58_3_list_filters_are_and_combined() {
        let svc = CriRuntimeService::new();
        let sb1 = run_id(&svc);
        let sb2 = run(&svc, Some(config("q")), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        let a = running(&svc, &sb1, "a");
        let b = create(&svc, &sb1, Some(container_config("b", 0))).unwrap();
        let mut cfg = container_config("c", 0);
        cfg.labels.insert("k".into(), "other".into());
        let c = create(&svc, &sb2, Some(cfg)).unwrap();
        let f = |id: &str, state: Option<i32>, pod: &str, labels: &[(&str, &str)]| {
            Some(v1::ContainerFilter {
                id: id.into(),
                state: state.map(|state| v1::ContainerStateValue { state }),
                pod_sandbox_id: pod.into(),
                label_selector: labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            })
        };
        let ids = |filter| {
            let mut v: Vec<String> = list_c(&svc, filter)
                .unwrap()
                .into_iter()
                .map(|c| c.id)
                .collect();
            v.sort();
            v
        };
        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        assert_eq!(ids(f(&a, None, "", &[])), vec![a.clone()]);
        assert_eq!(ids(f("", Some(1), "", &[])), vec![a.clone()]);
        assert_eq!(
            ids(f("", Some(0), "", &[])),
            sorted(vec![b.clone(), c.clone()])
        );
        assert_eq!(
            ids(f("", None, &sb1, &[])),
            sorted(vec![a.clone(), b.clone()])
        );
        assert_eq!(ids(f("", None, &sb2, &[])), vec![c.clone()]);
        assert_eq!(
            ids(f("", None, "", &[("k", "v")])),
            sorted(vec![a.clone(), b.clone()])
        );
        assert_eq!(ids(f("", Some(0), &sb1, &[("k", "v")])), vec![b.clone()]);
        assert!(ids(f(&a, Some(0), "", &[])).is_empty());
        assert!(ids(f(&"0".repeat(64), None, "", &[])).is_empty());
        assert!(ids(f("", None, "", &[("k", "nope")])).is_empty());
        assert!(ids(f("", None, "unknown-sandbox", &[])).is_empty());
        assert!(list_c(&svc, state_filter(3)).unwrap().is_empty());
        assert_eq!(list_c(&svc, state_filter(2)).unwrap().len(), 0);
    }

    /// ERR-3・TASK-58.3: 未知 state と label_selector の上限超過は INVALID_ARGUMENT。上限ちょうどは通る。
    #[test]
    fn task_58_3_list_validates_filter() {
        let svc = CriRuntimeService::new();
        assert_eq!(
            list_c(&svc, state_filter(99)).unwrap_err().code(),
            Code::InvalidArgument
        );
        let selector = |n: usize, klen: usize, vlen: usize| {
            Some(v1::ContainerFilter {
                label_selector: (0..n)
                    .map(|i| (format!("{i:0>klen$}"), "v".repeat(vlen)))
                    .collect(),
                ..Default::default()
            })
        };
        list_c(&svc, selector(MAX_CONFIG_COLLECTION_ENTRIES, 4, 1)).unwrap();
        assert_eq!(
            list_c(&svc, selector(MAX_CONFIG_COLLECTION_ENTRIES + 1, 4, 1))
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
        list_c(
            &svc,
            selector(
                1,
                MAX_LABEL_SELECTOR_STRING_BYTES,
                MAX_LABEL_SELECTOR_STRING_BYTES,
            ),
        )
        .unwrap();
        assert_eq!(
            list_c(&svc, selector(1, MAX_LABEL_SELECTOR_STRING_BYTES + 1, 1))
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
        assert_eq!(
            list_c(&svc, selector(1, 1, MAX_LABEL_SELECTOR_STRING_BYTES + 1))
                .unwrap_err()
                .code(),
            Code::InvalidArgument
        );
        // 合計: id と pod_sandbox_id の長さも加算され、上限ちょうどは通り +1 で拒否される。
        let total = |extra: usize| {
            Some(v1::ContainerFilter {
                id: "i".repeat(MAX_LABEL_SELECTOR_STRING_BYTES),
                pod_sandbox_id: "p".repeat(extra),
                ..Default::default()
            })
        };
        let room = MAX_LABEL_SELECTOR_TOTAL_BYTES - MAX_LABEL_SELECTOR_STRING_BYTES;
        list_c(&svc, total(room)).unwrap();
        assert_eq!(
            list_c(&svc, total(room + 1)).unwrap_err().code(),
            Code::InvalidArgument
        );
    }

    /// ERR-3・TASK-58.3: ContainerStatus の空 ID は INVALID_ARGUMENT、未知 ID は NOT_FOUND。
    #[test]
    fn task_58_3_status_error_codes() {
        let svc = CriRuntimeService::new();
        let err = status_c(&svc, "").unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        let unknown = "f".repeat(64);
        let err = status_c(&svc, &unknown).unwrap_err();
        assert_eq!(err.code(), Code::NotFound);
        assert!(!err.message().contains(&unknown));
    }

    /// CRI-1・TASK-58.3: Status の時刻が遷移ごとに記録され、config の値は無改変、未実装項目はスタブ値。
    #[test]
    fn task_58_3_status_content() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let mut cfg = container_config("c", 2);
        cfg.log_path = "c/0.log".into();
        cfg.stop_signal = 15;
        cfg.mounts.push(v1::Mount {
            container_path: "/data".into(),
            host_path: "/srv/data".into(),
            readonly: true,
            ..Default::default()
        });
        cfg.envs.push(v1::KeyValue {
            key: "SECRET".into(),
            value: "hunter2".into(),
        });
        cfg.linux = Some(v1::LinuxContainerConfig {
            resources: Some(v1::LinuxContainerResources {
                cpu_shares: 512,
                ..Default::default()
            }),
            ..Default::default()
        });
        let id = create(&svc, &sb, Some(cfg.clone())).unwrap();
        let created = status_c(&svc, &id).unwrap();
        assert_eq!(created.id, id);
        assert_eq!(created.state, 0);
        assert!(created.created_at > 0);
        assert_eq!((created.started_at, created.finished_at), (0, 0));
        assert_eq!(created.metadata, cfg.metadata);
        assert_eq!(created.image, cfg.image);
        assert_eq!(created.labels, cfg.labels);
        assert_eq!(created.annotations, cfg.annotations);
        assert_eq!(created.mounts, cfg.mounts);
        assert_eq!(created.log_path, "c/0.log");
        assert_eq!(created.stop_signal, 15);
        assert_eq!(
            created.resources.clone().unwrap().linux.unwrap().cpu_shares,
            512
        );
        assert_eq!(created.exit_code, 0);
        assert_eq!(created.image_ref, "");
        assert_eq!(created.reason, "");
        assert_eq!(created.message, "");
        assert!(!format!("{created:?}").contains("hunter2"));
        start(&svc, &id).unwrap();
        let running = status_c(&svc, &id).unwrap();
        assert_eq!(running.state, 1);
        assert!(running.started_at >= running.created_at);
        assert_eq!(running.finished_at, 0);
        stop_c(&svc, &id, 0).unwrap();
        let exited = status_c(&svc, &id).unwrap();
        assert_eq!(exited.state, 2);
        assert_eq!(exited.started_at, running.started_at);
        assert!(exited.finished_at >= exited.started_at);
        let resp = block_on(
            svc.container_status(Request::new(v1::ContainerStatusRequest {
                container_id: id,
                verbose: true,
            })),
        )
        .unwrap()
        .into_inner();
        assert!(resp.info.is_empty());
    }

    /// REPAIR-4・TASK-58.3: List・Status の全終了経路が 1 件ずつ記録され、ID を含まない。
    #[test]
    fn task_58_3_outcomes_are_recorded_without_content() {
        let collect = Arc::new(Collect::default());
        let svc = CriRuntimeService::with_recorder(collect.clone());
        let sb = run_id(&svc);
        let id = running(&svc, &sb, "c");
        list_c(&svc, None).unwrap();
        list_c(&svc, state_filter(99)).unwrap_err();
        status_c(&svc, &id).unwrap();
        status_c(&svc, "").unwrap_err();
        status_c(&svc, &"e".repeat(64)).unwrap_err();
        let samples = collect.items();
        let tail: Vec<(&str, CriOpOutcome, Code)> = samples[samples.len() - 5..]
            .iter()
            .map(|s| (s.kind().as_str(), s.outcome(), s.code()))
            .collect();
        assert_eq!(
            tail,
            [
                ("cri.list_containers", CriOpOutcome::Success, Code::Ok),
                (
                    "cri.list_containers",
                    CriOpOutcome::Failure,
                    Code::InvalidArgument
                ),
                ("cri.container_status", CriOpOutcome::Success, Code::Ok),
                (
                    "cri.container_status",
                    CriOpOutcome::Failure,
                    Code::InvalidArgument
                ),
                (
                    "cri.container_status",
                    CriOpOutcome::Failure,
                    Code::NotFound
                ),
            ]
        );
        assert!(!format!("{samples:?}").contains(&id));
    }

    /// TASK-58.3: Create/Remove を繰り返す間の List は、常に内部で整合した結果を返す。
    #[test]
    fn task_58_3_list_during_concurrent_create_remove_is_consistent() {
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                for i in 0..50 {
                    let id =
                        create(&svc, &sb, Some(container_config(&format!("w{i}"), 0))).unwrap();
                    remove_c(&svc, &id).unwrap();
                }
            });
            for _ in 0..50 {
                for c in list_c(&svc, None).unwrap() {
                    assert_eq!(c.pod_sandbox_id, sb);
                    assert_eq!(c.state, 0);
                    // 一覧に出た ID は、直後に Remove されていても NOT_FOUND 以外のエラーにはならない。
                    if let Err(e) = status_c(&svc, &c.id) {
                        assert_eq!(e.code(), Code::NotFound);
                    }
                }
            }
            writer.join().unwrap();
        });
        assert!(list_c(&svc, None).unwrap().is_empty());
    }
}
