//! CRI サーバー層から `ContainerRuntime` トレイト境界を呼ぶアダプタ（TASK-59.1・#437・CRI-2・CRI-7・MS-4）。
//!
//! `runtime_service` の RPC ハンドラ（`CreateContainer`・`StartContainer` 等）が、実行層の具象型を
//! 一切知らずにコンテナのライフサイクルを操作するための薄い変換層である。参照してよい core の
//! 項目は `fandhe_container_core::traits` のみで、`oci_runtime`・`exec`・`cgroups` 等の具象モジュールへ
//! 依存しない（CRI-7。依存の向きは cri → core の一方向で、core 側は cri に依存しない）。
//!
//! CRI の語彙（ID 文字列・秒・bool）を受け、`ContainerRuntime` の検証つき要求型へ変換して呼び、
//! 結果のエラーを `CriError`（ERR-3）へ写す。core の型は公開 API へ漏らさず、
//! [`RuntimeContainerStatus`] へ写して返す。
//!
//! **同期 API**: `ContainerRuntime` は同期トレイトで、plugin 越しの実装は REPAIR-5 のタイムアウトを持つ
//! RPC になり得る。async ハンドラからは `tokio::task::spawn_blocking` 上で呼ぶこと（`image_pull` の前例）。
//!
//! **未実装・簡易実装（REPAIR-3）**: 本モジュールは呼び出し境界だけを提供する。RPC ハンドラへの接続は
//! create・start が TASK-59.2（#438。`CriRuntimeService::with_runtime` で注入したときだけ有効）、
//! stop・delete が TASK-59.3（#439。接続済み）、全ライフサイクルの結合試験は TASK-59.4（#440。`tests/adapter_integration.rs`）で実施済みで、
//! `ContainerRuntime` の実装（plugin 側。TASK-114）も本モジュールの範囲外である
//! （bundle の供給は [`BundleProvider`] の注入点だけを定義し、config 変換と bundle の寿命は `crate::bundle`）。

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fandhe_container_core::traits::{
    CleanupOutcome, ContainerId, ContainerLogPath, ContainerRuntime, ContainerState,
    ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, KillRequest, Signal,
    StartRequest, StateRequest, StopRequest, TerminationReason, TraitError,
};
use tonic::Status;

use crate::error::{CriError, CriErrorCode};
use crate::port_mapping::PodPortPublish;
use crate::runtime::v1::ContainerState as CriContainerState;
use crate::runtime::v1::{ContainerConfig, PodSandboxConfig};

/// 実行層が報告した生の状態（CRI の外向き状態へ写す前の区別。CRI-2・REPAIR-5）。
///
/// CRI の `ContainerCreated` は実行層の Creating と Created を区別しない。しかし作成完了の検査や
/// 「未起動と確定できるか」の判定では、Creating（作成途中で結果が不確定）を Created と同一視してはならない。
/// 判定は [`RuntimeContainerStatus::lifecycle`] のこの値で行う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeLifecycle {
    /// 作成途中（完了未確定）。
    Creating,
    /// 作成完了・未起動。
    Created,
    /// 実行中。
    Running,
    /// 停止済み。
    Stopped,
    /// 未知の状態（将来追加される状態を含む）。
    Unknown,
}

/// 実行層が報告した特別な終了理由（core の `TerminationReason` を写した値。CRI-2・CORE-4）。
///
/// core の型を cri の公開 API へ漏らさないための型。`ContainerStatus.reason` の `OOMKilled` の元になる。
/// 将来の理由追加に備えて `#[non_exhaustive]` とする。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeTerminationReason {
    /// cgroup の OOM killer によって kill された。
    OomKilled,
}

impl RuntimeTerminationReason {
    /// core の理由を写す。未知の理由（将来追加分）は `None`（理由なしとして扱い、reason を捏造しない）。
    fn from_core(reason: TerminationReason) -> Option<Self> {
        match reason {
            TerminationReason::OomKilled => Some(Self::OomKilled),
            _ => None,
        }
    }
}

/// `ContainerRuntime` の状態照会結果を CRI 側の語彙へ写した値（CRI-2）。
///
/// core の型を cri の公開 API へ漏らさないための型。将来の拡張に備えて `#[non_exhaustive]` とする。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RuntimeContainerStatus {
    /// コンテナ ID。
    pub id: String,
    /// CRI の状態。Creating・Created は `ContainerCreated`、Running は `ContainerRunning`、
    /// Stopped は `ContainerExited`、将来追加される未知の状態は `ContainerUnknown` に写す。
    pub state: CriContainerState,
    /// 実行層が報告した生の状態。完了・未起動の厳密な判定はこちらで行う（`state` は Creating を Created に写す）。
    pub lifecycle: RuntimeLifecycle,
    /// init プロセスの PID（判明していれば）。
    pub pid: Option<u32>,
    /// 終了コード（Stopped で判明していれば）。
    pub exit_code: Option<i32>,
    /// 特別な終了理由（実行層が報告したときだけ。`None` は「OOM ではない」と「未検出」を区別しない。CRI-2・CORE-4）。
    pub termination: Option<RuntimeTerminationReason>,
}

impl From<&ContainerStatus> for RuntimeContainerStatus {
    fn from(s: &ContainerStatus) -> Self {
        let (state, lifecycle) = match s.state() {
            ContainerState::Creating => (
                CriContainerState::ContainerCreated,
                RuntimeLifecycle::Creating,
            ),
            ContainerState::Created => (
                CriContainerState::ContainerCreated,
                RuntimeLifecycle::Created,
            ),
            ContainerState::Running => (
                CriContainerState::ContainerRunning,
                RuntimeLifecycle::Running,
            ),
            ContainerState::Stopped => (
                CriContainerState::ContainerExited,
                RuntimeLifecycle::Stopped,
            ),
            _ => (
                CriContainerState::ContainerUnknown,
                RuntimeLifecycle::Unknown,
            ),
        };
        Self {
            id: s.id().as_str().to_owned(),
            state,
            lifecycle,
            pid: s.pid().map(|p| p.get()),
            exit_code: s.exit_code(),
            termination: s
                .termination_reason()
                .and_then(RuntimeTerminationReason::from_core),
        }
    }
}

/// delete の後始末 1 件の結果を CRI 側の語彙へ写した値（core の `CleanupOutcome` を写す。
/// OCI-7・CRI-2・SUP-7・REPAIR-4・#2633）。
///
/// core の型を公開 API へ漏らさないための型。`Kept` の `code` は core の `ErrorCode` を
/// [`CriError`] の写像表（`From<&TraitError>`）と同じ規則で写した値。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeCleanupOutcome {
    /// この層では対象が無い。既定値。
    #[default]
    NotApplicable,
    /// 消した。
    Removed,
    /// 既に無かった。
    AlreadyAbsent,
    /// 消せずに残した。
    Kept {
        /// 残した理由の分類。
        code: CriErrorCode,
    },
}

impl RuntimeCleanupOutcome {
    /// core の結果を写す。未知の値（将来追加分）は成功に見せず `Kept { Internal }` へ倒す（fail-closed）。
    fn from_core(outcome: CleanupOutcome) -> Self {
        match outcome {
            CleanupOutcome::NotApplicable => Self::NotApplicable,
            CleanupOutcome::Removed => Self::Removed,
            CleanupOutcome::AlreadyAbsent => Self::AlreadyAbsent,
            CleanupOutcome::Kept { code } => Self::Kept {
                code: CriError::from(&TraitError::new(code, "")).code(),
            },
            _ => Self::Kept {
                code: CriErrorCode::Internal,
            },
        }
    }
}

/// `ContainerRuntime::delete` の結果を CRI 側の語彙へ写した値（CRI-2）。
///
/// core の `DeleteResponse` を公開 API へ漏らさず、将来の拡張に備えて `#[non_exhaustive]` とする。
/// 後始末（rootfs・ログ）の結果を載せる。cri-api の `RemoveContainerResponse` にはフィールドが無い
/// （無改変。CRI-3）ため、`runtime_service` は結果を応答へ載せない。残した資源は後始末をした層
/// （`fandhe-container-plugin-cri`）が構造化ログで出す。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RuntimeDeleteResult {
    /// イメージ由来 rootfs の後始末の結果。
    pub image_rootfs: RuntimeCleanupOutcome,
    /// supervisor ログの後始末の結果。
    pub supervisor_log: RuntimeCleanupOutcome,
    /// コンテナログの後始末の結果。
    pub container_log: RuntimeCleanupOutcome,
}

impl From<&DeleteResponse> for RuntimeDeleteResult {
    fn from(resp: &DeleteResponse) -> Self {
        Self {
            image_rootfs: RuntimeCleanupOutcome::from_core(resp.image_rootfs()),
            supervisor_log: RuntimeCleanupOutcome::from_core(resp.supervisor_log()),
            container_log: RuntimeCleanupOutcome::from_core(resp.container_log()),
        }
    }
}

/// `ContainerRuntime` のエラーを ERR-3 の gRPC ステータスへ写す。
///
/// 写像は [`CriError`] の `From<&TraitError>`（`crate::error`）に一本化されており、本関数はその薄いラッパー
/// （未知のコードは `Internal`、メッセージは 4096 バイトへ切り詰め）。
pub fn trait_error_to_status(err: &TraitError) -> Status {
    Status::from(CriError::from(err))
}

/// [`BundleProvider::prepare`] への入力（CRI-1・CRI-2・#2395）。
///
/// `sandbox_config` は要求ではなくサンドボックスの登録記録（RunPodSandbox 時に上限検証済み）の複製で、
/// hostname・namespace_options の正は登録記録である。`CreateContainerRequest.sandbox_config` は使わない。
/// 将来の項目追加に備えて `#[non_exhaustive]` とし、外部 crate は [`BundleRequest::new`] で作る。
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct BundleRequest<'a> {
    /// コンテナ ID（`CreateContainer` が採番した値）。
    pub container_id: &'a str,
    /// 所属サンドボックスの ID。
    pub sandbox_id: &'a str,
    /// 所属サンドボックスの登録済み設定。
    pub sandbox_config: &'a PodSandboxConfig,
    /// 作成するコンテナの設定。
    pub config: &'a ContainerConfig,
    /// 所属サンドボックスの pod network namespace のパス（[`PodNetworkProvider::set_up`] が返した値。
    /// 無ければ `None`）。`namespace_options.network` が `POD` のときだけ `linux.namespaces` の network に
    /// `path` として出す（#2675・CRI-2・NET-1）。
    pub pod_netns_path: Option<&'a Path>,
    /// pod の保持役が作った user・ipc namespace のパス（CRI-2・CORE-3。#2674）。`Some` で ipc が `POD` のとき
    /// だけ ipc を join にする。供給元（保持役）は未実装のため、`CriRuntimeService` は当面 `None` を渡す。
    pub pod_namespaces: Option<&'a crate::bundle::PodNamespacePaths>,
}

impl<'a> BundleRequest<'a> {
    /// 各項目から入力を作る。
    pub fn new(
        container_id: &'a str,
        sandbox_id: &'a str,
        sandbox_config: &'a PodSandboxConfig,
        config: &'a ContainerConfig,
    ) -> Self {
        Self {
            container_id,
            sandbox_id,
            sandbox_config,
            config,
            pod_netns_path: None,
            pod_namespaces: None,
        }
    }

    /// pod network namespace のパスを足す（#2675）。
    #[must_use]
    pub fn with_pod_netns_path(mut self, path: Option<&'a Path>) -> Self {
        self.pod_netns_path = path;
        self
    }

    /// pod の user・ipc namespace のパスを足す（#2674）。
    #[must_use]
    pub fn with_pod_namespaces(
        mut self,
        pod_namespaces: &'a crate::bundle::PodNamespacePaths,
    ) -> Self {
        self.pod_namespaces = Some(pod_namespaces);
        self
    }
}

/// pod の network namespace を `NetworkPlugin` 経由で作って結線する注入点（#2675・CRI-2・NET-1・PLUG-1）。
///
/// `RunPodSandbox`（`namespace_options.network` が `POD`）が worker スレッドから [`PodNetworkProvider::set_up`] を、
/// `StopPodSandbox`・`RemovePodSandbox` が [`PodNetworkProvider::tear_down`] を呼ぶ。実装は plugin-cri が
/// `NetworkPlugin`（core のトレイト境界）へ写して差す。cri は net の具象型を知らない（CRI-7）。
///
/// **未実装・簡易実装（REPAIR-3）**: コンテナが netns へ入る側（core の `linux.namespaces[].path` の受け入れ）は
/// 未実装で、注入しても start は `UNIMPLEMENTED` で拒否される。本番の plugin-cri は注入しない
/// （`docs/design/cri-config-acceptance.md` の順 13）。
/// エラー文言に config の値・パスを含めないこと。
pub trait PodNetworkProvider: Send + Sync {
    /// サンドボックスの netns を作って結線し、そのパスを返す。失敗時は資源を残さない（残るなら `Err` で報告）。
    fn set_up(&self, req: &PodNetworkRequest<'_>) -> Result<PodNetns, CriError>;

    /// `set_up` で用意した資源を解放する。冪等で、未知の ID・不在は `Ok`。失敗は資源が残るとみなされる。
    fn tear_down(&self, sandbox_id: &str) -> Result<(), CriError>;
}

/// [`PodNetworkProvider::set_up`] への入力。将来の項目追加に備えて `#[non_exhaustive]`。
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct PodNetworkRequest<'a> {
    /// サンドボックス ID（`RunPodSandbox` が採番した値）。
    pub sandbox_id: &'a str,
    /// サンドボックスの設定（dns_config 等。現状の実装は読まない）。公開指定は [`Self::port_publishes`] を使い、
    /// `config.port_mappings` を直接読まない（検証済みの値だけを下流へ流すため）。
    pub config: &'a PodSandboxConfig,
    /// 検証済みの公開指定（`port_mappings` のうち `host_port > 0` のもの。#2676・CRI-2・NET-3）。
    port_publishes: &'a [PodPortPublish],
}

impl<'a> PodNetworkRequest<'a> {
    /// 各項目から入力を作る。公開指定は空（[`Self::with_port_publishes`] で足す）。
    pub fn new(sandbox_id: &'a str, config: &'a PodSandboxConfig) -> Self {
        Self {
            sandbox_id,
            config,
            port_publishes: &[],
        }
    }

    /// 検証済みの公開指定を足す。
    pub fn with_port_publishes(mut self, port_publishes: &'a [PodPortPublish]) -> Self {
        self.port_publishes = port_publishes;
        self
    }

    /// 検証済みの公開指定。`set_up` はこれをすべて公開するか、失敗して資源を残さない。
    pub fn port_publishes(&self) -> &'a [PodPortPublish] {
        self.port_publishes
    }
}

/// [`PodNetworkProvider::set_up`] の結果（結線済みの pod network namespace）。
///
/// 将来の項目（IP の報告等）の追加に備えて `#[non_exhaustive]` とし、[`PodNetns::new`] で作る。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PodNetns {
    path: PathBuf,
}

impl PodNetns {
    /// Linux 側の netns の絶対パスから作る。bundle の `linux.namespaces[].path` へ載せる値なので、ホスト OS に
    /// よらず `SpecBundleProvider` と同じ規則（`crate::bundle::spec` の `check_host_source`: `/` 始まり・`\` 無し・
    /// `.`・`..`・空要素無し・4096 バイト以内・NUL 無し）で検証する（provider が受けたパスを bundle が拒否する
    /// 食い違いを作らない。壊れた値を bundle へ流さない多層防御。違反は `INTERNAL`）。
    pub fn new(path: PathBuf) -> Result<Self, CriError> {
        let ok = path
            .to_str()
            .is_some_and(|s| crate::bundle::spec::check_host_source("pod netns path", s).is_ok());
        if ok {
            Ok(Self { path })
        } else {
            Err(CriError::internal("invalid pod network namespace path"))
        }
    }

    /// netns のパス。
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// [`BundleProvider::prepare`] の結果（bundle のパスと、実際に適用する値の報告。#2771・CRI-2・OCI-1・SEC-5）。
///
/// 将来の報告項目の追加に備えて `#[non_exhaustive]` とし、[`PreparedBundle::new`] と `with_*` で作る。
/// `CriRuntimeService` が受け取って `ContainerRecord` に記録し、`ContainerStatus` の `user`・`stop_signal` と
/// StopContainer が使うシグナルに反映する。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PreparedBundle {
    path: PathBuf,
    user: Option<crate::bundle::AppliedUser>,
    stop_signal: Option<crate::runtime::v1::Signal>,
}

impl PreparedBundle {
    /// 報告なしで bundle のパスだけを返す。
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            user: None,
            stop_signal: None,
        }
    }
    /// 起動時に適用する uid・gid・補助グループの報告を足す。
    pub fn with_user(mut self, user: crate::bundle::AppliedUser) -> Self {
        self.user = Some(user);
        self
    }
    /// 実際に stop で使うシグナル（解決済み。`RUNTIME_DEFAULT` ではない）の報告を足す。
    pub fn with_stop_signal(mut self, signal: crate::runtime::v1::Signal) -> Self {
        self.stop_signal = Some(signal);
        self
    }
    /// bundle の絶対パス。
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// 適用する識別情報（報告が無ければ `None`。root を作り出さない）。
    pub fn user(&self) -> Option<&crate::bundle::AppliedUser> {
        self.user.as_ref()
    }
    /// 解決済みの stop signal（報告が無ければ `None`）。
    pub fn stop_signal(&self) -> Option<crate::runtime::v1::Signal> {
        self.stop_signal
    }
}

/// CRI の `ContainerConfig` から OCI bundle（rootfs と `config.json`）を用意する注入点（TASK-59.2・#438・CRI-2）。
///
/// `CreateContainer` ハンドラが `ContainerRuntime::create` を呼ぶ直前に呼ぶ。CRI の要求は bundle の
/// パスを持たないため、image の展開と `ContainerConfig` から `config.json` への変換は本トレイトの実装側の
/// 責務とする。同期 API で、ハンドラは tokio の blocking pool を使わず専用スレッド（worker）上から呼ぶ。
///
/// 汎用の実装として `crate::bundle::SpecBundleProvider`（config 変換と bundle ディレクトリの寿命。#2395）がある。
///
/// 本番の rootfs 供給は `crate::bundle::ImageRootfsSource`（pull 済みイメージの再展開と既定値の読み取り。#2433）で、
/// plugin-cri が `SpecBundleProvider` と組んで差す。タグの解決は未実装（REPAIR-3。image ID のみ受ける）。
/// `config` の内容（envs 等の秘密値を含みうる）をエラー文言へ含めないこと。
pub trait BundleProvider: Send + Sync {
    /// コンテナ用の bundle を用意し、その絶対パスと実際に適用する値の報告を返す。失敗は ERR-3 の gRPC ステータスで返す。
    ///
    /// 報告（[`PreparedBundle::user`]・[`PreparedBundle::stop_signal`]）の無い実装は [`PreparedBundle::new`] だけを返す。
    /// その場合 `ContainerStatus.user` は未報告（`None`）、stop signal は CRI の config の値だけで解決する。
    fn prepare(&self, req: &BundleRequest<'_>) -> Result<PreparedBundle, CriError>;

    /// `prepare` で用意した資源を解放する（`create` 失敗時の後始末。stop・delete は TASK-59.3 で接続済み）。
    ///
    /// 削除・解除に失敗したら `Err` を返す。呼び出し側は `Err` のとき資源が残っているとみなし、
    /// コンテナの記録と件数枠を保持して追跡を失わない（fail-closed）。不在は `Ok` としてよい。
    fn release(&self, container_id: &str) -> Result<(), CriError>;
}

/// RPC ハンドラから `ContainerRuntime` を呼ぶアダプタ（CRI-2・CRI-7）。
///
/// トレイトオブジェクト（[`RuntimeAdapter::new`]）とジェネリクス（[`RuntimeAdapter::from_runtime`]）の
/// 両方で受けられ、core の具象実装に依存しない。`Clone` は `Arc` の複製で安価。
#[derive(Clone)]
pub struct RuntimeAdapter {
    runtime: Arc<dyn ContainerRuntime>,
}

impl fmt::Debug for RuntimeAdapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeAdapter").finish_non_exhaustive()
    }
}

impl RuntimeAdapter {
    /// トレイトオブジェクトからアダプタを作る（plugin proxy 等を `Arc<dyn ContainerRuntime>` で渡す経路）。
    pub fn new(runtime: Arc<dyn ContainerRuntime>) -> Self {
        Self { runtime }
    }

    /// 具象型（ジェネリクス）からアダプタを作る。
    pub fn from_runtime<R: ContainerRuntime + 'static>(runtime: R) -> Self {
        Self::new(Arc::new(runtime))
    }

    /// CRI 由来の ID 文字列を検証して [`ContainerId`] にする（不正は `INVALID_ARGUMENT`）。
    fn id(id: &str) -> Result<ContainerId, CriError> {
        ContainerId::new(id).map_err(|e| CriError::from(&e))
    }

    /// OCI bundle（絶対パス）からコンテナを作成する。
    pub fn create(&self, id: &str, bundle: PathBuf) -> Result<RuntimeContainerStatus, CriError> {
        let req = CreateRequest::new(Self::id(id)?, bundle).map_err(|e| CriError::from(&e))?;
        Self::finish(id, self.runtime.create(&req))
    }

    /// `created` 状態のコンテナを開始する。
    pub fn start(&self, id: &str) -> Result<RuntimeContainerStatus, CriError> {
        self.start_with_log_path(id, None)
    }

    /// CRI ログの書き先つきで開始する（CRI-2・SUP-4・#2671）。`None` は [`Self::start`] と同じ。
    pub fn start_with_log_path(
        &self,
        id: &str,
        log_path: Option<ContainerLogPath>,
    ) -> Result<RuntimeContainerStatus, CriError> {
        let mut req = StartRequest::new(Self::id(id)?);
        if let Some(log_path) = log_path {
            req = req.with_log_path(log_path);
        }
        Self::finish(id, self.runtime.start(&req))
    }

    /// SIGTERM 後 `timeout_secs` 秒で SIGKILL へ切り替えて停止する。
    ///
    /// 負値は 0（即時 SIGKILL）に丸める。上限（24 時間。REPAIR-5）超過は `INVALID_ARGUMENT`。
    pub fn stop(&self, id: &str, timeout_secs: i64) -> Result<RuntimeContainerStatus, CriError> {
        self.stop_with_signal(id, timeout_secs, Signal::SIGTERM.as_u8())
    }

    /// 最初に送るシグナル（Linux の番号 1..=64。範囲外は `INVALID_ARGUMENT`）を指定して停止する。
    ///
    /// CRI の `stop_signal`（`stop_signal::linux_stop_signal` で写した番号。CRI-2・PLUG-1。#2668）を
    /// `StopRequest::with_signal` で実行層へ運ぶ。猶予後の SIGKILL への切り替えは実行層が無条件に行う。
    pub fn stop_with_signal(
        &self,
        id: &str,
        timeout_secs: i64,
        signal: u8,
    ) -> Result<RuntimeContainerStatus, CriError> {
        let signal = Signal::new(signal).map_err(|e| CriError::from(&e))?;
        let grace = Duration::from_secs(u64::try_from(timeout_secs).unwrap_or(0));
        let req = StopRequest::new(Self::id(id)?, grace)
            .map_err(|e| CriError::from(&e))?
            .with_signal(signal);
        Self::finish(id, self.runtime.stop(&req))
    }

    /// コンテナの資源を解放する（`ContainerRuntime::delete`）。`force` は実行中でも停止してから削除する。
    pub fn remove(&self, id: &str, force: bool) -> Result<RuntimeDeleteResult, CriError> {
        let req = DeleteRequest::new(Self::id(id)?).with_force(force);
        self.runtime
            .delete(&req)
            .as_ref()
            .map(RuntimeDeleteResult::from)
            .map_err(CriError::from)
    }

    /// シグナル番号（1..=64）を送る。範囲外は `INVALID_ARGUMENT`。
    pub fn kill(&self, id: &str, signal: u8) -> Result<RuntimeContainerStatus, CriError> {
        let signal = Signal::new(signal).map_err(|e| CriError::from(&e))?;
        let req = KillRequest::new(Self::id(id)?, signal);
        Self::finish(id, self.runtime.kill(&req))
    }

    /// コンテナの現在状態を照会する。
    pub fn state(&self, id: &str) -> Result<RuntimeContainerStatus, CriError> {
        let req = StateRequest::new(Self::id(id)?);
        Self::finish(id, self.runtime.state(&req))
    }

    /// 実行層の応答を CRI の語彙へ写す。応答の ID が要求の ID と異なれば plugin の不正な応答として
    /// `INTERNAL`（結果不明）で拒否する（plugin 入力は untrusted。別コンテナの状態を受理しない）。
    fn finish(
        expected_id: &str,
        r: Result<ContainerStatus, TraitError>,
    ) -> Result<RuntimeContainerStatus, CriError> {
        let status = r.as_ref().map_err(CriError::from)?;
        if status.id().as_str() != expected_id {
            return Err(CriError::internal(
                "runtime returned a status for a different container id",
            ));
        }
        Ok(RuntimeContainerStatus::from(status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::STATUS_MESSAGE_MAX_BYTES;
    use fandhe_container_core::traits::ErrorCode;
    use std::num::NonZeroU32;
    use tonic::Code;

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).unwrap()
    }

    /// CRI-2: core の状態を CRI の状態へ具体値で写す。
    #[test]
    fn cri2_state_mapping() {
        let pid = NonZeroU32::new(42);
        let cases = [
            (
                ContainerStatus::creating(cid("a")),
                CriContainerState::ContainerCreated,
                None,
                None,
            ),
            (
                ContainerStatus::created(cid("a"), pid),
                CriContainerState::ContainerCreated,
                Some(42),
                None,
            ),
            (
                ContainerStatus::running(cid("a"), pid),
                CriContainerState::ContainerRunning,
                Some(42),
                None,
            ),
            (
                ContainerStatus::stopped(cid("a"), Some(137)),
                CriContainerState::ContainerExited,
                None,
                Some(137),
            ),
        ];
        let lifecycles = [
            RuntimeLifecycle::Creating,
            RuntimeLifecycle::Created,
            RuntimeLifecycle::Running,
            RuntimeLifecycle::Stopped,
        ];
        for ((src, state, pid, code), lifecycle) in cases.into_iter().zip(lifecycles) {
            let got = RuntimeContainerStatus::from(&src);
            assert_eq!(got.lifecycle, lifecycle);
            assert_eq!(got.id, "a");
            assert_eq!(got.state, state);
            assert_eq!(got.pid, pid);
            assert_eq!(got.exit_code, code);
            assert_eq!(got.termination, None);
        }
    }

    /// CRI-2・CORE-4: 実行層が報告した OOM の停止は終了コードと独立に写る。
    #[test]
    fn cri2_oom_termination_is_mapped() {
        let src =
            ContainerStatus::stopped_with_reason(cid("a"), Some(137), TerminationReason::OomKilled);
        let got = RuntimeContainerStatus::from(&src);
        assert_eq!(got.exit_code, Some(137));
        assert_eq!(got.termination, Some(RuntimeTerminationReason::OomKilled));
    }

    /// CRI-2: 応答の ID が要求と異なれば拒否する。
    #[test]
    fn cri2_finish_rejects_mismatched_id() {
        let ok = RuntimeAdapter::finish("a", Ok(ContainerStatus::creating(cid("a"))));
        assert_eq!(ok.unwrap().id, "a");
        let err = RuntimeAdapter::finish("a", Ok(ContainerStatus::created(cid("b"), None)))
            .expect_err("mismatch");
        assert_eq!(err.code().grpc_code(), Code::Internal);
    }

    /// CRI-2: 削除応答を CRI 側の型へ写す。
    #[test]
    fn cri2_delete_result_mapping() {
        assert_eq!(
            RuntimeDeleteResult::from(&DeleteResponse::new()),
            RuntimeDeleteResult::default()
        );
    }

    /// OCI-7・CRI-2・REPAIR-4: 後始末の結果（残した理由を含む）を CRI の語彙へ具体値で写す。
    #[test]
    fn oci7_delete_result_maps_cleanup_outcomes() {
        let resp = DeleteResponse::new()
            .with_image_rootfs(CleanupOutcome::AlreadyAbsent)
            .with_supervisor_log(CleanupOutcome::Kept {
                code: ErrorCode::Timeout,
            })
            .with_container_log(CleanupOutcome::Kept {
                code: ErrorCode::FailedPrecondition,
            });
        let got = RuntimeDeleteResult::from(&resp);
        assert_eq!(got.image_rootfs, RuntimeCleanupOutcome::AlreadyAbsent);
        assert_eq!(
            got.supervisor_log,
            RuntimeCleanupOutcome::Kept {
                code: CriErrorCode::Timeout
            }
        );
        assert_eq!(
            got.container_log,
            RuntimeCleanupOutcome::Kept {
                code: CriErrorCode::FailedPrecondition
            }
        );
    }

    /// ERR-3: ErrorCode を gRPC コードへ具体値で写す。
    #[test]
    fn err3_error_code_mapping() {
        let cases = [
            (ErrorCode::InvalidArgument, Code::InvalidArgument),
            (ErrorCode::NotFound, Code::NotFound),
            (ErrorCode::AlreadyExists, Code::AlreadyExists),
            (ErrorCode::FailedPrecondition, Code::FailedPrecondition),
            (ErrorCode::Unimplemented, Code::Unimplemented),
            (ErrorCode::PermissionDenied, Code::PermissionDenied),
            (ErrorCode::Timeout, Code::DeadlineExceeded),
            (ErrorCode::Unavailable, Code::Unavailable),
        ];
        for (ec, code) in cases {
            let st = trait_error_to_status(&TraitError::new(ec, "msg"));
            assert_eq!(st.code(), code);
            assert_eq!(st.message(), "msg");
        }
    }

    /// ERR-3: 長いメッセージは文字境界で 4096 バイト以下に切る。
    #[test]
    fn err3_message_truncated_on_char_boundary() {
        let long = "あ".repeat(2000);
        let st = trait_error_to_status(&TraitError::new(ErrorCode::NotFound, long));
        assert!(st.message().len() <= STATUS_MESSAGE_MAX_BYTES);
        assert_eq!(st.message().len(), 4095);
    }
}
