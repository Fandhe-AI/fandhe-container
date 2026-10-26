//! コンテナ記録・入力検証・保持量の上限（TASK-58.1・#433・CRI-1・ERR-3）。
//!
//! 親モジュール（`runtime_service`）の `CreateContainer` / `StartContainer` が使う、コンテナ固有の
//! 部品を置く。`ContainerConfig` は CRI クライアント（kubelet・crictl）由来の外部入力で、
//! サンドボックスの `config_limits` と同じ 3 段（符号化長・可変長要素の件数と長さ・累積の保持量）で
//! 有限の上限を課す。`envs` に秘密値が入り得るため、エラー文言・計装へ `config` の内容を出さない。
//!
//! ListContainers・ContainerStatus（TASK-58.3・#435）の応答への変換（`to_summary`・`to_status`）と
//! フィルタ検証（`ValidatedContainerFilter`）もここに置く。`message`・`info` は方針として常に空（#2901。`image_ref`・`image_id` は CreateContainer 時の解決結果を返し、報告の無い経路は空。#2831。`image` は在庫のタグ）（`user` は実行層の経路のみ報告。#2771）（REPAIR-3。項目ごとの扱いは `to_status` の doc）。`exit_code`・`reason` は実行層の報告に基づく（`exit_reason`）。
//!
//! **スタブの明示（REPAIR-3）**: 状態はプロセス内メモリにあるだけで、実行層（core）には未接続。
//! `Running` は記録上の状態で、プロセスは起動しない。StopContainer / RemoveContainer（TASK-58.2・#434）も
//! 記録上の遷移と除去だけで、プロセスの終了・猶予待ちは行わない。TASK-59（CRI-2）で `ContainerRuntime`
//! 経由の namespace 分離起動・終了と `StateStore` へ置き換える。
//! `command`・`mounts` 等のパス類は保持するだけで検証していない（ホストへ触れる TASK-59 で検証する）。
//! `log_path` は実行層接続時に `log_directory` と結合・検証した値を別途保持する（`resolved_log_path`。#2671）。

use std::collections::HashMap;

use crate::adapter::RuntimeTerminationReason;
use crate::bundle::{AppliedUser, ResolvedImage};
use crate::error::CriError;
use fandhe_container_core::traits::ContainerLogPath;
use prost::Message;

use super::config_limits::{
    MAX_CONFIG_COLLECTION_ENTRIES, MAX_CONFIG_ENCODED_BYTES, MAX_METADATA_FIELD_BYTES,
    RETAINED_BYTES_PER_ENTRY, RETAINED_BYTES_PER_RECORD,
};
use super::validate_label_selector;
use crate::runtime::v1::{
    self, Capability, ContainerConfig, ContainerState as ProtoContainerState, LinuxContainerConfig,
    LinuxContainerResources, LinuxContainerSecurityContext, NamespaceOption, UserNamespace,
    WindowsContainerConfig, WindowsContainerResources,
};

/// 受け付けるコンテナ数の上限（無制限確保の防止。ERR-3 の `FAILED_PRECONDITION`）。
///
/// 根拠: kubelet の既定の Pod 数上限（1 ノード 110）に Pod あたり数コンテナ（init・sidecar を含む）を
/// 掛けても、4096 はその約 10 倍の余裕がある。
pub const MAX_CONTAINERS: usize = 4096;

/// レジストリが保持する全コンテナ `config` の保持量の見積もりの合計の上限: 128 MiB。
///
/// 根拠: 典型的なコンテナ（符号化長 数 KiB・要素 数十件）の見積もりは 1 件 16 KiB 前後で、件数の
/// 上限まで登録しても 64 MiB 程度。サンドボックス側（64 MiB）の 2 倍とし、コンテナ数が多めの運用で
/// 件数の上限より先に尽きないようにした。
pub const MAX_RETAINED_CONTAINER_CONFIG_BYTES: usize = 128 * 1024 * 1024;

/// コンテナ用レジストリの保持量の上限（件数と `config` の保持量の見積もりの合計）。
///
/// 既定値（[`MAX_CONTAINERS`]・[`MAX_RETAINED_CONTAINER_CONFIG_BYTES`]）より大きい値は指定できず
/// 既定値へ丸める（絞る方向にだけ変えられる。`SandboxLimits` と同じ方針）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerLimits {
    max_containers: usize,
    max_retained_bytes: usize,
}

impl Default for ContainerLimits {
    fn default() -> Self {
        Self {
            max_containers: MAX_CONTAINERS,
            max_retained_bytes: MAX_RETAINED_CONTAINER_CONFIG_BYTES,
        }
    }
}

impl ContainerLimits {
    /// 既定の上限。
    pub fn new() -> Self {
        Self::default()
    }

    /// コンテナ数の上限を絞る（[`MAX_CONTAINERS`] を超える値は [`MAX_CONTAINERS`] になる）。
    pub fn with_max_containers(mut self, max_containers: usize) -> Self {
        self.max_containers = max_containers.min(MAX_CONTAINERS);
        self
    }

    /// 保持量の見積もりの合計の上限を絞る（[`MAX_RETAINED_CONTAINER_CONFIG_BYTES`] を超える値は
    /// [`MAX_RETAINED_CONTAINER_CONFIG_BYTES`] になる）。
    pub fn with_max_retained_bytes(mut self, max_retained_bytes: usize) -> Self {
        self.max_retained_bytes = max_retained_bytes.min(MAX_RETAINED_CONTAINER_CONFIG_BYTES);
        self
    }

    /// コンテナ数の上限。
    pub fn max_containers(&self) -> usize {
        self.max_containers
    }

    /// 保持量の見積もりの合計の上限（バイト）。
    pub fn max_retained_bytes(&self) -> usize {
        self.max_retained_bytes
    }
}

/// コンテナの内部状態（CRI の `ContainerState` に対応）。
///
/// `Exited`（停止済み）は StopContainer（TASK-58.2・#434）で `Running` から遷移する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ContainerState {
    Created,
    Running,
    Exited,
    /// 実行層の結果が不明（Start・Create の応答不明で、プロセスが生存しているかもしれない）。
    /// 外向きは `CONTAINER_UNKNOWN`。停止を確認できるまで `Exited` にしない fail-closed
    /// （CRI-2・REPAIR-5。停止の確認と回収は TASK-59.3）。
    Unknown,
}

impl ContainerState {
    /// CRI の列挙値へ変換する（ContainerStatus / ListContainers〔TASK-58.3〕が応答に使う）。
    pub(super) fn to_proto(self) -> ProtoContainerState {
        match self {
            Self::Created => ProtoContainerState::ContainerCreated,
            Self::Running => ProtoContainerState::ContainerRunning,
            Self::Exited => ProtoContainerState::ContainerExited,
            Self::Unknown => ProtoContainerState::ContainerUnknown,
        }
    }
}

/// レジストリに保持するコンテナ 1 件分の記録。
///
/// `config` は内容を変えずに保持する（annotations を書き換えない CRI の要件）。`retained_bytes` は
/// 作成時にレジストリの保持量へ計上した見積もりで、除去のときに同じ値を引く。
#[derive(Debug, Clone)]
pub(super) struct ContainerRecord {
    pub(super) pod_sandbox_id: String,
    pub(super) config: ContainerConfig,
    pub(super) state: ContainerState,
    pub(super) created_at_nanos: i64,
    pub(super) started_at_nanos: i64,
    /// 停止（`Exited` 遷移）の時刻。未停止は 0（TASK-58.2。ContainerStatus〔TASK-58.3〕が応答に使う）。
    pub(super) finished_at_nanos: i64,
    /// 実行層が報告した終了コード（CRI-2）。未停止・不明は None（ContainerStatus.exit_code は 0、reason は空）。
    pub(super) exit_code: Option<i32>,
    /// 実行層が報告した特別な終了理由（OOM 等。CRI-2・CORE-4）。未報告は None。
    pub(super) termination: Option<RuntimeTerminationReason>,
    pub(super) retained_bytes: usize,
    /// `log_directory` と `log_path` を結合・検証した CRI ログの書き先（実行層接続時の CreateContainer のみ。
    /// CRI-2・SUP-4・#2671）。`ContainerStatus.log_path` に返し（kubelet・crictl が直接開く）、StartContainer が
    /// supervisor へ渡す。スタブ経路・両方空・`log_directory` だけのときは `None`。
    pub(super) resolved_log_path: Option<ContainerLogPath>,
    /// 実行層（`ContainerRuntime`）の create・start・stop・delete を呼び出し中（TASK-59.2・#438、TASK-59.3・#439）。
    ///
    /// 状態は呼び出し前のまま、並行する Start・Stop・Remove・親サンドボックスの停止・除去を `FAILED_PRECONDITION` で
    /// 拒否するためのフラグ。実行層を呼ぶ間はレジストリのロックを持たないので、このフラグで二重実行と
    /// 取りこぼし（記録だけ消えて実行層に残る）を防ぐ。
    pub(super) in_flight: bool,
    /// 実行層に資源（コンテナ・bundle）がある（Create 成功、または結果不明で残りうる。TASK-59.2）。
    ///
    /// 真の間、Stop・Remove は記録上の遷移ではなく実行層の stop・delete を経由する（TASK-59.3）。
    /// 意味は「実行層が所有する」。
    pub(super) runtime_owned: bool,
    /// 実際に stop で使うシグナル（CRI の `Signal` の i32。`RUNTIME_DEFAULT`（0）は入れない。#2771・CRI-2・OCI-1）。
    ///
    /// 作成時は config の値（`RUNTIME_DEFAULT` なら `SIGTERM`）で、`BundleProvider` が解決済みの値を報告したら
    /// イメージ config の `StopSignal` を反映した値で上書きされる。`ContainerStatus.stop_signal` と
    /// StopContainer / StopPodSandbox が使う。プロセス内メモリにあるだけで、plugin-cri の再起動で失われる
    /// （`exit_code`・`resolved_log_path` と同じ寿命。config の annotations には書かない）。
    pub(super) stop_signal: i32,
    /// 起動時に適用する識別情報（`ContainerStatus.user.linux` の元。#2771・CRI-2・SEC-5・KEP-3619）。
    ///
    /// 実行層の経路で `SpecBundleProvider` が config.json に書いた値だけが入る。報告の無い経路は `None`
    /// （root を作り出さない）。寿命は `stop_signal` と同じ。
    pub(super) applied_user: Option<AppliedUser>,
    /// CreateContainer 時に解決したイメージ（`image_ref`・`image_id` の元。#2831・CRI-2・OCI-1）。
    ///
    /// 置き場所はプロセス内メモリのレジストリで、寿命は `applied_user`・`stop_signal` と同じ（annotations にも
    /// `StateStore` にも書かない。plugin-cri の再起動で失われる）。報告の無い経路（スタブ・外部 bundle）は `None`。
    pub(super) resolved_image: Option<ResolvedImage>,
}

/// 新しい記録の `stop_signal` の初期値（config の値。`RUNTIME_DEFAULT` は `SIGTERM`）。
pub(super) fn initial_stop_signal(configured: i32) -> i32 {
    if configured == v1::Signal::RuntimeDefault as i32 {
        v1::Signal::Sigterm as i32
    } else {
        configured
    }
}

/// 終了コード 0 の `ContainerStatus.reason`（containerd・kubelet の慣例に合わせた CamelCase。CRI-2）。
const REASON_COMPLETED: &str = "Completed";
/// 非 0 の終了コード（シグナル終了の 137・143 を含む）の `ContainerStatus.reason`（CRI-2）。
const REASON_ERROR: &str = "Error";
/// 実行層が OOM による終了を報告したときの `ContainerStatus.reason`（containerd・kubelet の慣例。CRI-2・CORE-4）。
const REASON_OOM_KILLED: &str = "OOMKilled";

/// 実行層が報告した終了の内容（終了コードと特別な終了理由）。guard から記録へ反映する単位（CRI-2）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct ExitReport {
    pub(super) code: Option<i32>,
    pub(super) termination: Option<RuntimeTerminationReason>,
}

/// 実行層が報告した終了コードから `ContainerStatus.reason` を導く（CRI-2）。
///
/// `to_status` から呼ばれる。終了済みで実行層が OOM を報告していれば、終了コードに関係なく（不明でも）
/// `OOMKilled` にする（containerd・kubelet の慣例）。それ以外は終了コードで決め、不明（`None`）または
/// 未終了のときは空を返して不明な終了を `Completed` と見せない（fail-closed。REPAIR-3）。
/// OOM の検出（`memory.events` の読み取り）は実行層・supervisor 側の責務で、本関数は報告を写すだけ
/// （cri-api の規定は `api.proto` の `ContainerStatus.reason`）。値は固定文字列のみで、実行層の応答文字列を外へ出さない。
fn exit_reason(
    state: ContainerState,
    exit_code: Option<i32>,
    termination: Option<RuntimeTerminationReason>,
) -> &'static str {
    match (state, exit_code, termination) {
        (ContainerState::Exited, _, Some(RuntimeTerminationReason::OomKilled)) => REASON_OOM_KILLED,
        (ContainerState::Exited, Some(0), _) => REASON_COMPLETED,
        (ContainerState::Exited, Some(_), _) => REASON_ERROR,
        _ => "",
    }
}

impl ContainerRecord {
    /// ContainerStatus 応答用の変換（CRI-1・TASK-58.3・#435）。
    ///
    /// labels・annotations・mounts は保持した値を無改変で返す。`log_path` は結合済みの絶対パス（`resolved_log_path`。
    /// containerd と同じ。kubelet の GetContainerLogs と crictl logs が直接開く）があればそれ、無ければ保持した値を返す。`envs`・`command`・`args` は
    /// 応答項目に無く（秘密値が入り得る）、返さない。`exit_code` は実行層が報告した値（不明は 0）、
    /// `reason` は `exit_reason` で導く（`Completed`・`Error`・`OOMKilled`）。
    ///
    /// - `image`（#2901）: CreateContainer 時に在庫から得た `repo_tags[0]` があれば、containerd と同じく新しい `ImageSpec`
    ///   （`image` のみ。annotations・`user_specified_image` は落ちる）に置き換える。タグが無い・報告の無い経路は `config.image` のまま。
    ///   containerd b7a2526 の `container_status.go` L65 は Status のたびに在庫を引くが、本実装は create 時のスナップショット。
    ///   `to_summary`（ListContainers）は containerd の `toCRIContainer` と同じく置き換えず `config.image` を返す。
    ///
    /// **方針として空の項目と未実装の明示（REPAIR-3・CRI-2）**:
    /// - `image_ref`・`image_id`（#2831）: `BundleProvider` が報告した CreateContainer 時の解決結果を返す。
    ///   `image_id` は image ID（`sha256:<config digest>`。`PullImageResponse.image_ref` と同じ）、`image_ref` は在庫の
    ///   `repo_digests[0]`（無ければ image ID）。報告の無い経路（スタブ・外部 bundle）は両方空（digest を推測しない。
    ///   containerd は空を返さない本リポ固有の挙動）。containerd b7a2526 は Status の時点で在庫を引き直すが、
    ///   本実装は create 時のスナップショットを返し続ける（既知の差。`docs/design/cri-config-acceptance.md`）。
    /// - `user`: 実行層の経路で `BundleProvider` が報告した config.json の `process.user`（起動時に適用する値。
    ///   `applied_user`）を返す。報告の無い経路（スタブ等）と、補助グループが空で実プロセスのグループと一致を保証できない場合は `None`。`supplemental_groups` は重複除去後の最終の
    ///   集合で、主 gid は自動では含めない（containerd は含めることがある既知の差）。`stop_signal` は実際に
    ///   stop で使う解決済みの値（#2771）。
    /// - `message`: 常に空（決定。#2901）。containerd が書くのは start 失敗の `retErr.Error()` だけで、実行層の応答文字列を
    ///   外へ出さない方針に合わない。OOM でも空。
    /// - `info`（verbose）: 常に空（決定。#2901）。containerd の `info` は config（envs）・OCI spec（ホストパス）等で、
    ///   内部のパス・構成を出さない方針に合わない。将来値を入れる場合も、キーは `"info"` の 1 つで値は JSON 文字列とする。
    ///
    /// 差の詳細は `docs/design/cri-config-acceptance.md`。
    pub(super) fn to_status(&self, id: &str) -> v1::ContainerStatus {
        let linux = self
            .config
            .linux
            .as_ref()
            .and_then(|linux| linux.resources.clone());
        let windows = self
            .config
            .windows
            .as_ref()
            .and_then(|windows| windows.resources.clone());
        let resources = if linux.is_none() && windows.is_none() {
            None
        } else {
            Some(v1::ContainerResources { linux, windows })
        };
        v1::ContainerStatus {
            id: id.to_owned(),
            metadata: self.config.metadata.clone(),
            state: self.state.to_proto() as i32,
            created_at: self.created_at_nanos,
            started_at: self.started_at_nanos,
            finished_at: self.finished_at_nanos,
            exit_code: self.exit_code.unwrap_or(0),
            image: self
                .resolved_image
                .as_ref()
                .and_then(ResolvedImage::tag)
                .map(|tag| v1::ImageSpec {
                    image: tag.to_owned(),
                    ..Default::default()
                })
                .or_else(|| self.config.image.clone()),
            image_ref: self
                .resolved_image
                .as_ref()
                .map_or_else(String::new, |i| i.image_ref().to_owned()),
            reason: exit_reason(self.state, self.exit_code, self.termination).to_owned(),
            message: String::new(),
            labels: self.config.labels.clone(),
            annotations: self.config.annotations.clone(),
            mounts: self.config.mounts.clone(),
            log_path: self
                .resolved_log_path
                .as_ref()
                .map_or_else(|| self.config.log_path.clone(), |p| p.as_str().to_owned()),
            resources,
            image_id: self
                .resolved_image
                .as_ref()
                .map_or_else(String::new, |i| i.id_str().to_owned()),
            // 補助グループが明示（非空）のときだけ報告する。空の指定は core が `setgroups(0)` で消去するが、
            // `RootlessSingleId` のように user namespace が `setgroups` を禁じる構成では起動元の補助グループを
            // 現状維持して起動を続ける（`KeptSetgroupsDenied`）。cri 側では実際に残るグループを知り得ず、
            // 空を報告すると実プロセスと食い違うため、その場合は user を未報告にする（CRI-2・SEC-5。
            // 実行層が確定した初期グループを記録へ返す経路は未実装）。非空は適用できなければ起動が失敗する。
            user: self
                .applied_user
                .as_ref()
                .filter(|u| !u.additional_gids().is_empty())
                .map(|u| v1::ContainerUser {
                    linux: Some(v1::LinuxContainerUser {
                        uid: i64::from(u.uid()),
                        gid: i64::from(u.gid()),
                        supplemental_groups: u
                            .additional_gids()
                            .iter()
                            .map(|g| i64::from(*g))
                            .collect(),
                    }),
                }),
            stop_signal: self.stop_signal,
        }
    }

    /// ListContainers 応答用の変換（Status の部分集合）。
    ///
    /// `image_ref`・`image_id` はどちらも image ID（containerd b7a2526 の `toCRIContainer` と同じ）。
    /// 報告の無い経路は空（#2831）。
    pub(super) fn to_summary(&self, id: &str) -> v1::Container {
        v1::Container {
            id: id.to_owned(),
            pod_sandbox_id: self.pod_sandbox_id.clone(),
            metadata: self.config.metadata.clone(),
            image: self.config.image.clone(),
            image_ref: self
                .resolved_image
                .as_ref()
                .map_or_else(String::new, |i| i.id_str().to_owned()),
            state: self.state.to_proto() as i32,
            created_at: self.created_at_nanos,
            labels: self.config.labels.clone(),
            annotations: self.config.annotations.clone(),
            image_id: self
                .resolved_image
                .as_ref()
                .map_or_else(String::new, |i| i.id_str().to_owned()),
        }
    }
}

/// 検証済みの `ListContainers` フィルタ（全条件 AND。CRI-1・TASK-58.3）。
///
/// `state` が `CONTAINER_UNKNOWN` のとき、レジストリには Unknown 状態の記録が無いため `matches_none`
/// で空の一覧にする。
pub(super) struct ValidatedContainerFilter {
    id: String,
    state: Option<ContainerState>,
    matches_none: bool,
    pod_sandbox_id: String,
    label_selector: HashMap<String, String>,
}

impl ValidatedContainerFilter {
    /// 件数・文字列長・合計バイト数の上限と state 値を検証する（ERR-3: `INVALID_ARGUMENT`）。
    pub(super) fn new(filter: Option<v1::ContainerFilter>) -> Result<Self, CriError> {
        let Some(filter) = filter else {
            return Ok(Self {
                id: String::new(),
                state: None,
                matches_none: false,
                pod_sandbox_id: String::new(),
                label_selector: HashMap::new(),
            });
        };
        validate_label_selector(
            &filter.label_selector,
            filter.id.len().saturating_add(filter.pod_sandbox_id.len()),
        )?;
        let (state, matches_none) = match filter.state {
            None => (None, false),
            Some(value) => match ProtoContainerState::try_from(value.state) {
                Ok(ProtoContainerState::ContainerCreated) => (Some(ContainerState::Created), false),
                Ok(ProtoContainerState::ContainerRunning) => (Some(ContainerState::Running), false),
                Ok(ProtoContainerState::ContainerExited) => (Some(ContainerState::Exited), false),
                Ok(ProtoContainerState::ContainerUnknown) => (Some(ContainerState::Unknown), false),
                Err(_) => return Err(CriError::invalid_argument("unknown state filter")),
            },
        };
        Ok(Self {
            id: filter.id,
            state,
            matches_none,
            pod_sandbox_id: filter.pod_sandbox_id,
            label_selector: filter.label_selector,
        })
    }

    /// 全条件を AND で判定する。
    pub(super) fn matches(&self, id: &str, record: &ContainerRecord) -> bool {
        !self.matches_none
            && (self.id.is_empty() || self.id == id)
            && (self.pod_sandbox_id.is_empty() || self.pod_sandbox_id == record.pod_sandbox_id)
            && self.state.is_none_or(|s| s == record.state)
            && self
                .label_selector
                .iter()
                .all(|(k, v)| record.config.labels.get(k) == Some(v))
    }
}

/// 入力検証を通過した `CreateContainer` の要求。
pub(super) struct ValidatedCreate {
    pub(super) pod_sandbox_id: String,
    pub(super) name: String,
    pub(super) attempt: u32,
    pub(super) config: BoundedContainerConfig,
}

/// `CreateContainer` の入力検証（ERR-3: 必須欠落・値域外・サイズ超過は `INVALID_ARGUMENT`）。
///
/// 状態には触れない。`sandbox_config` は保持せず（サンドボックス記録側が正）、符号化長の上限だけ検査する。
pub(super) fn validate_create_request(
    req: v1::CreateContainerRequest,
) -> Result<ValidatedCreate, CriError> {
    let v1::CreateContainerRequest {
        pod_sandbox_id,
        config,
        sandbox_config,
    } = req;
    if pod_sandbox_id.is_empty() {
        return Err(CriError::invalid_argument("pod_sandbox_id is required"));
    }
    let config = config.ok_or_else(|| CriError::invalid_argument("config is required"))?;
    let metadata = config
        .metadata
        .as_ref()
        .ok_or_else(|| CriError::invalid_argument("config.metadata is required"))?;
    if metadata.name.is_empty() {
        return Err(CriError::invalid_argument(
            "config.metadata.name is required",
        ));
    }
    let image = config
        .image
        .as_ref()
        .ok_or_else(|| CriError::invalid_argument("config.image is required"))?;
    if image.image.is_empty() {
        return Err(CriError::invalid_argument("config.image.image is required"));
    }
    if let Some(sandbox_config) = sandbox_config.as_ref()
        && sandbox_config.encoded_len() > MAX_CONFIG_ENCODED_BYTES
    {
        return Err(CriError::invalid_argument("sandbox_config is too large"));
    }
    // 複製の前に、参照のまま名前長と config 全体の符号化長を検証する（確保前に上限検証）。
    if metadata.name.len() > MAX_METADATA_FIELD_BYTES {
        return Err(CriError::invalid_argument(format!(
            "config.metadata.name is too long: {} bytes exceeds the limit of {MAX_METADATA_FIELD_BYTES} bytes",
            metadata.name.len()
        )));
    }
    let encoded_len = config.encoded_len();
    if encoded_len > MAX_CONFIG_ENCODED_BYTES {
        return Err(CriError::invalid_argument(format!(
            "config is too large: {encoded_len} bytes exceeds the limit of {MAX_CONFIG_ENCODED_BYTES} bytes"
        )));
    }
    let name = metadata.name.clone();
    let attempt = metadata.attempt;
    let config = BoundedContainerConfig::new(config)?;
    Ok(ValidatedCreate {
        pod_sandbox_id,
        name,
        attempt,
        config,
    })
}

/// サイズ・件数の検証を通過し、保持用に作り直した `ContainerConfig`。
///
/// [`BoundedContainerConfig::new`] だけが作れるため、未検証の `config` がレジストリへ入る経路はない。
#[derive(Debug)]
pub(super) struct BoundedContainerConfig {
    config: ContainerConfig,
    retained_bytes: usize,
}

impl BoundedContainerConfig {
    /// `config` を検証し、保持用に作り直す。上限超過は `INVALID_ARGUMENT`（ERR-3）。
    ///
    /// 作り直し（符号化して復号）は内容を変えず、呼び出し元が確保した余分な容量を捨てる。
    pub(super) fn new(config: ContainerConfig) -> Result<Self, CriError> {
        let retained_bytes = retained_bytes(&config)?;
        let encoded = config.encode_to_vec();
        drop(config);
        let config = ContainerConfig::decode(encoded.as_slice())
            .map_err(|_| CriError::internal("failed to rebuild container config"))?;
        Ok(Self {
            config,
            retained_bytes,
        })
    }

    /// 検証済みの `config` を借りる（CRI ログの書き先の結合に使う）。
    pub(super) fn config(&self) -> &ContainerConfig {
        &self.config
    }

    /// 保持量の見積もり。
    pub(super) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    /// 検証済みの `config` を取り出す。
    pub(super) fn into_config(self) -> ContainerConfig {
        self.config
    }
}

/// `config` を検証し、保持量の見積もりを返す（アロケーションなし。演算は checked）。
fn retained_bytes(config: &ContainerConfig) -> Result<usize, CriError> {
    let encoded_len = config.encoded_len();
    if encoded_len > MAX_CONFIG_ENCODED_BYTES {
        return Err(CriError::invalid_argument(format!(
            "config is too large: {encoded_len} bytes exceeds the limit of {MAX_CONFIG_ENCODED_BYTES} bytes"
        )));
    }
    if let Some(metadata) = config.metadata.as_ref()
        && metadata.name.len() > MAX_METADATA_FIELD_BYTES
    {
        return Err(CriError::invalid_argument(format!(
            "config.metadata.name is too long: {} bytes exceeds the limit of {MAX_METADATA_FIELD_BYTES} bytes",
            metadata.name.len()
        )));
    }
    let mut entries: usize = 0;
    for_each_collection(config, &mut |field, len| {
        if len > MAX_CONFIG_COLLECTION_ENTRIES {
            return Err(CriError::invalid_argument(format!(
                "config.{field} has too many entries: {len} exceeds the limit of {MAX_CONFIG_COLLECTION_ENTRIES}"
            )));
        }
        entries = entries
            .checked_add(len)
            .ok_or_else(|| CriError::invalid_argument("config has too many entries"))?;
        Ok(())
    })?;
    entries
        .checked_mul(RETAINED_BYTES_PER_ENTRY)
        .and_then(|overhead| overhead.checked_add(mounts_struct_bytes(config.mounts.len())?))
        .and_then(|overhead| overhead.checked_add(encoded_len))
        .and_then(|bytes| bytes.checked_add(RETAINED_BYTES_PER_RECORD))
        .ok_or_else(|| CriError::invalid_argument("config is too large"))
}

/// `mounts` の要素（`Mount` 本体）の保持量の上乗せ（符号化長・[`RETAINED_BYTES_PER_ENTRY`] に含まれない分）。
///
/// `Mount` は複数の `String`・`Vec` とインラインの `Option<ImageSpec>` を持ち、構造体自体が
/// `RETAINED_BYTES_PER_ENTRY` を超える。空の `Mount` は符号化長がほぼ 0 のため、要素ごとの
/// 見積もりが無いと実保持量を過小に数える。復号後の `Vec` は倍々に伸びて最大 2 倍の容量を持ち得るため
/// `size_of::<Mount>()` の 2 倍で計上する（保守側。TASK-58.1・ERR-3）。オーバーフローは `None`。
fn mounts_struct_bytes(count: usize) -> Option<usize> {
    count.checked_mul(std::mem::size_of::<v1::Mount>().checked_mul(2)?)
}

type Visit<'a> = &'a mut dyn FnMut(&'static str, usize) -> Result<(), CriError>;

/// `config` から辿れる repeated / map フィールドを、(フィールド名, 件数) で順に `visit` へ渡す。
///
/// 各メッセージを `..` なしで分解し、cri-api の更新でフィールドが増えたらコンパイルエラーにして
/// 件数検証の入れ忘れを防ぐ（REPAIR-12。`config_limits` と同じ狙い）。
fn for_each_collection(config: &ContainerConfig, visit: Visit<'_>) -> Result<(), CriError> {
    let ContainerConfig {
        metadata: _,
        image,
        command,
        args,
        working_dir: _,
        envs,
        mounts,
        devices,
        labels,
        annotations,
        log_path: _,
        stdin: _,
        stdin_once: _,
        tty: _,
        linux,
        windows,
        cdi_devices,
        stop_signal: _,
    } = config;
    if let Some(image) = image {
        let v1::ImageSpec {
            image: _,
            annotations,
            user_specified_image: _,
            runtime_handler: _,
            image_ref: _,
        } = image;
        visit("image.annotations", annotations.len())?;
    }
    visit("command", command.len())?;
    visit("args", args.len())?;
    visit("envs", envs.len())?;
    visit("mounts", mounts.len())?;
    for mount in mounts {
        let v1::Mount {
            container_path: _,
            host_path: _,
            readonly: _,
            selinux_relabel: _,
            propagation: _,
            uid_mappings,
            gid_mappings,
            recursive_read_only: _,
            image,
            image_sub_path: _,
            mount_options,
        } = mount;
        if let Some(v1::ImageSpec {
            image: _,
            annotations,
            user_specified_image: _,
            runtime_handler: _,
            image_ref: _,
        }) = image
        {
            visit("mounts.image.annotations", annotations.len())?;
        }
        visit("mounts.mount_options", mount_options.len())?;
        visit("mounts.uid_mappings", uid_mappings.len())?;
        visit("mounts.gid_mappings", gid_mappings.len())?;
    }
    visit("devices", devices.len())?;
    visit("labels", labels.len())?;
    visit("annotations", annotations.len())?;
    visit("CDI_devices", cdi_devices.len())?;
    if let Some(LinuxContainerConfig {
        resources,
        security_context,
    }) = linux
    {
        if let Some(resources) = resources {
            visit_linux_resources(resources, visit)?;
        }
        if let Some(security_context) = security_context {
            visit_linux_security_context(security_context, visit)?;
        }
    }
    if let Some(WindowsContainerConfig {
        resources,
        security_context: _,
    }) = windows
        && let Some(WindowsContainerResources {
            cpu_shares: _,
            cpu_count: _,
            cpu_maximum: _,
            memory_limit_in_bytes: _,
            rootfs_size_in_bytes: _,
            affinity_cpus,
        }) = resources
    {
        visit("windows.resources.affinity_cpus", affinity_cpus.len())?;
    }
    Ok(())
}

/// `LinuxContainerResources` の repeated / map フィールドを `visit` へ渡す。
fn visit_linux_resources(
    resources: &LinuxContainerResources,
    visit: Visit<'_>,
) -> Result<(), CriError> {
    let LinuxContainerResources {
        cpu_period: _,
        cpu_quota: _,
        cpu_shares: _,
        memory_limit_in_bytes: _,
        oom_score_adj: _,
        cpuset_cpus: _,
        cpuset_mems: _,
        hugepage_limits,
        unified,
        memory_swap_limit_in_bytes: _,
    } = resources;
    visit("linux.resources.hugepage_limits", hugepage_limits.len())?;
    visit("linux.resources.unified", unified.len())
}

/// `LinuxContainerSecurityContext` の repeated フィールドを `visit` へ渡す。
// 非推奨の `apparmor_profile`・`seccomp_profile_path` も分解に含める（フィールドの増減を検出するため。値は読まない）。
#[allow(deprecated)]
fn visit_linux_security_context(
    security_context: &LinuxContainerSecurityContext,
    visit: Visit<'_>,
) -> Result<(), CriError> {
    let LinuxContainerSecurityContext {
        capabilities,
        privileged: _,
        namespace_options,
        selinux_options: _,
        run_as_user: _,
        run_as_group: _,
        run_as_username: _,
        readonly_rootfs: _,
        supplemental_groups,
        supplemental_groups_policy: _,
        no_new_privs: _,
        masked_paths,
        readonly_paths,
        seccomp: _,
        apparmor: _,
        apparmor_profile: _,
        seccomp_profile_path: _,
    } = security_context;
    if let Some(Capability {
        add_capabilities,
        drop_capabilities,
        add_ambient_capabilities,
    }) = capabilities
    {
        visit(
            "linux.security_context.capabilities.add_capabilities",
            add_capabilities.len(),
        )?;
        visit(
            "linux.security_context.capabilities.drop_capabilities",
            drop_capabilities.len(),
        )?;
        visit(
            "linux.security_context.capabilities.add_ambient_capabilities",
            add_ambient_capabilities.len(),
        )?;
    }
    visit(
        "linux.security_context.supplemental_groups",
        supplemental_groups.len(),
    )?;
    visit("linux.security_context.masked_paths", masked_paths.len())?;
    visit(
        "linux.security_context.readonly_paths",
        readonly_paths.len(),
    )?;
    if let Some(NamespaceOption {
        network: _,
        pid: _,
        ipc: _,
        target_id: _,
        userns_options,
    }) = namespace_options
        && let Some(UserNamespace {
            mode: _,
            uids,
            gids,
        }) = userns_options
    {
        visit(
            "linux.security_context.namespace_options.userns_options.uids",
            uids.len(),
        )?;
        visit(
            "linux.security_context.namespace_options.userns_options.gids",
            gids.len(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    fn base_config() -> ContainerConfig {
        ContainerConfig {
            metadata: Some(v1::ContainerMetadata {
                name: "c".into(),
                attempt: 0,
            }),
            image: Some(v1::ImageSpec {
                image: "busybox".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn request(config: Option<ContainerConfig>) -> v1::CreateContainerRequest {
        v1::CreateContainerRequest {
            pod_sandbox_id: "sb".into(),
            config,
            sandbox_config: None,
        }
    }

    /// CRI-2・REPAIR-3: 終了コードから reason を導く。不明・未終了は空。
    #[test]
    fn cri_2_repair_3_exit_reason_mapping() {
        use ContainerState::*;
        let oom = Some(RuntimeTerminationReason::OomKilled);
        assert_eq!(exit_reason(Exited, Some(0), None), "Completed");
        assert_eq!(exit_reason(Exited, Some(137), None), "Error");
        assert_eq!(exit_reason(Exited, Some(-1), None), "Error");
        assert_eq!(exit_reason(Exited, None, None), "");
        assert_eq!(exit_reason(Running, None, None), "");
        assert_eq!(exit_reason(Created, None, None), "");
        assert_eq!(exit_reason(Unknown, None, None), "");
        // OOM は終了コードに関係なく OOMKilled（未終了では空のまま）。
        assert_eq!(exit_reason(Exited, Some(137), oom), "OOMKilled");
        assert_eq!(exit_reason(Exited, Some(0), oom), "OOMKilled");
        assert_eq!(exit_reason(Exited, None, oom), "OOMKilled");
        assert_eq!(exit_reason(Running, None, oom), "");
    }

    fn code_of(req: v1::CreateContainerRequest) -> Code {
        validate_create_request(req)
            .err()
            .map(|s| s.code().grpc_code())
            .unwrap()
    }

    /// ERR-3・TASK-58.1: 必須フィールドの欠落は `INVALID_ARGUMENT`。
    #[test]
    fn task_58_1_missing_required_fields_are_invalid_argument() {
        let mut no_sandbox = request(Some(base_config()));
        no_sandbox.pod_sandbox_id.clear();
        assert_eq!(code_of(no_sandbox), Code::InvalidArgument);
        assert_eq!(code_of(request(None)), Code::InvalidArgument);
        let mut c = base_config();
        c.metadata = None;
        assert_eq!(code_of(request(Some(c))), Code::InvalidArgument);
        let mut c = base_config();
        c.metadata.as_mut().unwrap().name.clear();
        assert_eq!(code_of(request(Some(c))), Code::InvalidArgument);
        let mut c = base_config();
        c.image = None;
        assert_eq!(code_of(request(Some(c))), Code::InvalidArgument);
        let mut c = base_config();
        c.image.as_mut().unwrap().image.clear();
        assert_eq!(code_of(request(Some(c))), Code::InvalidArgument);
    }

    /// ERR-3・TASK-58.1: command / args が空でも許容する（イメージの Entrypoint / Cmd を使うため）。
    #[test]
    fn task_58_1_empty_command_is_accepted() {
        let v = validate_create_request(request(Some(base_config()))).unwrap();
        assert_eq!(v.name, "c");
        assert_eq!(v.attempt, 0);
        assert_eq!(
            v.config.retained_bytes(),
            base_config().encoded_len() + RETAINED_BYTES_PER_RECORD
        );
    }

    /// ERR-3・TASK-58.1: 件数の境界（上限ちょうどは通り、1 件超過は拒否）。
    #[test]
    fn task_58_1_collection_limit_boundary() {
        let mut c = base_config();
        c.command = vec![String::new(); MAX_CONFIG_COLLECTION_ENTRIES];
        assert!(BoundedContainerConfig::new(c).is_ok());
        let mut c = base_config();
        c.command = vec![String::new(); MAX_CONFIG_COLLECTION_ENTRIES + 1];
        assert_eq!(
            BoundedContainerConfig::new(c)
                .unwrap_err()
                .code()
                .grpc_code(),
            Code::InvalidArgument
        );
        let mut c = base_config();
        c.linux = Some(LinuxContainerConfig {
            security_context: Some(LinuxContainerSecurityContext {
                masked_paths: vec![String::new(); MAX_CONFIG_COLLECTION_ENTRIES + 1],
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(
            BoundedContainerConfig::new(c)
                .unwrap_err()
                .code()
                .grpc_code(),
            Code::InvalidArgument
        );
        let mut c = base_config();
        c.mounts = vec![v1::Mount {
            uid_mappings: vec![v1::IdMapping::default(); MAX_CONFIG_COLLECTION_ENTRIES + 1],
            ..Default::default()
        }];
        assert_eq!(
            BoundedContainerConfig::new(c)
                .unwrap_err()
                .code()
                .grpc_code(),
            Code::InvalidArgument
        );
    }

    /// ERR-3・TASK-58.1: 符号化長の境界と name 長の境界。
    #[test]
    fn task_58_1_size_limit_boundary() {
        let mut c = base_config();
        c.log_path = "x".repeat(MAX_CONFIG_ENCODED_BYTES);
        assert_eq!(
            BoundedContainerConfig::new(c)
                .unwrap_err()
                .code()
                .grpc_code(),
            Code::InvalidArgument
        );
        let mut c = base_config();
        c.metadata.as_mut().unwrap().name = "n".repeat(MAX_METADATA_FIELD_BYTES);
        assert!(BoundedContainerConfig::new(c).is_ok());
        let mut c = base_config();
        c.metadata.as_mut().unwrap().name = "n".repeat(MAX_METADATA_FIELD_BYTES + 1);
        assert_eq!(
            BoundedContainerConfig::new(c)
                .unwrap_err()
                .code()
                .grpc_code(),
            Code::InvalidArgument
        );
    }

    /// ERR-3・TASK-58.1: 過大な `sandbox_config` は拒否する。
    #[test]
    fn task_58_1_mount_image_annotations_are_limited_and_counted() {
        let mount_with = |n: usize| v1::Mount {
            image: Some(v1::ImageSpec {
                annotations: (0..n).map(|i| (i.to_string(), String::new())).collect(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut c = base_config();
        let base = BoundedContainerConfig::new(c.clone())
            .unwrap()
            .retained_bytes();
        c.mounts = vec![mount_with(MAX_CONFIG_COLLECTION_ENTRIES)];
        let ok = BoundedContainerConfig::new(c.clone()).unwrap();
        assert!(
            ok.retained_bytes() >= base + MAX_CONFIG_COLLECTION_ENTRIES * RETAINED_BYTES_PER_ENTRY
        );
        c.mounts = vec![mount_with(MAX_CONFIG_COLLECTION_ENTRIES + 1)];
        assert_eq!(
            BoundedContainerConfig::new(c)
                .unwrap_err()
                .code()
                .grpc_code(),
            Code::InvalidArgument
        );
    }

    /// ERR-3・TASK-58.1: 空の `Mount` を大量に含む設定は、構造体のサイズ分を保持量に計上する。
    #[test]
    fn task_58_1_empty_mounts_count_struct_size() {
        let mut c = base_config();
        let base = BoundedContainerConfig::new(c.clone())
            .unwrap()
            .retained_bytes();
        c.mounts = vec![v1::Mount::default(); MAX_CONFIG_COLLECTION_ENTRIES];
        let retained = BoundedContainerConfig::new(c).unwrap().retained_bytes();
        let per_mount = 2 * std::mem::size_of::<v1::Mount>() + RETAINED_BYTES_PER_ENTRY;
        assert!(retained >= base + MAX_CONFIG_COLLECTION_ENTRIES * per_mount);
        assert!(2 * std::mem::size_of::<v1::Mount>() > RETAINED_BYTES_PER_ENTRY);
    }

    #[test]
    fn task_58_1_oversized_sandbox_config_is_rejected() {
        let mut req = request(Some(base_config()));
        req.sandbox_config = Some(v1::PodSandboxConfig {
            log_directory: "x".repeat(MAX_CONFIG_ENCODED_BYTES),
            ..Default::default()
        });
        assert_eq!(code_of(req), Code::InvalidArgument);
    }

    /// 上限は既定値より大きくできない。
    #[test]
    fn task_58_1_limits_never_exceed_defaults() {
        let l = ContainerLimits::new()
            .with_max_containers(usize::MAX)
            .with_max_retained_bytes(usize::MAX);
        assert_eq!(l.max_containers(), 4096);
        assert_eq!(l.max_retained_bytes(), 128 * 1024 * 1024);
        let l = l.with_max_containers(2).with_max_retained_bytes(10);
        assert_eq!((l.max_containers(), l.max_retained_bytes()), (2, 10));
    }

    /// 状態の proto 値。
    #[test]
    fn task_58_1_state_proto_values() {
        assert_eq!(ContainerState::Created.to_proto() as i32, 0);
        assert_eq!(ContainerState::Running.to_proto() as i32, 1);
        assert_eq!(ContainerState::Exited.to_proto() as i32, 2);
    }

    /// 作り直しは内容を変えない（labels・annotations 無改変）。
    #[test]
    fn task_58_1_rebuild_preserves_content() {
        let mut c = base_config();
        c.labels.insert("k".into(), "v".into());
        c.annotations.insert("a".into(), "b".into());
        let rebuilt = BoundedContainerConfig::new(c.clone())
            .unwrap()
            .into_config();
        assert_eq!(rebuilt, c);
    }
}
