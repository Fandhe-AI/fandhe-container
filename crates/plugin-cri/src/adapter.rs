//! plugin プロセス側で `ContainerRuntime`・`StateStore`・`NetworkPlugin` の実装を選んで組み立てる口
//! （TASK-114.2・#458・PLUG-1・CRI-2・CRI-7）。
//!
//! 呼び出し元: 将来は `main.rs` の `Run`（サーバーの起動。TASK-114.3 以降の #459・#849・#850）が
//! [`CriPluginBackends::production`] で組み立て、[`CriPluginBackends::runtime_service`] で
//! `fandhe-container-cri` の `CriRuntimeService` を得る。現状 `main.rs` はまだ呼ばない（REPAIR-3）。
//!
//! 依存の向きは plugin-cri → cri・core の一方向で、core・cri から plugin-cri への辺は無い（CRI-7）。
//! [`CriPluginBackends`] は trait object だけを持ち、具象型を型として露出しない。
//!
//! # 実装の置き場（CRI-7・PLUG-1）
//!
//! - `ContainerRuntime`: 実装は plugin 側（[`CoreLifecycleRuntime`]）。core のライブラリ関数
//!   （`oci_runtime::create` / `delete` と状態ストアの読み取り）へ委ねる
//! - `StateStore`: 既定実装 `FileStateStore` は core にある。本モジュールは二つ目の実装を作らず、
//!   選んで開き注入するだけ（別実装への差し替えは [`CriPluginBackends::new`] の注入口）
//! - `NetworkPlugin`: [`UnimplementedNetwork`]（netsetup への対応付けは TASK-114.4・#460）
//! - `VolumeProvider`: 実装は core 側に置く（データパスに接するため。ここには置かない）
//!
//! # 未実装・簡易実装（REPAIR-3）
//!
//! - `start`・`kill`・`stop` は `Unimplemented`。本番 launcher は単一スレッドのプロセスを要求し
//!   （CORE-1）、`ProcessSignaler` の本番実装は supervisor 側にあるため、tokio 上の CRI プロセスから
//!   直接呼べない。結線は supervisor 起動の経路と #459 以降
//! - `delete` は cgroup の配置を持つ記録では fail-closed（`UnavailableCgroupRemover`）で、記録を残す
//! - [`UnimplementedBundleProvider`]: 本番の bundle 供給（image 展開と ContainerConfig → config.json 変換）は
//!   未実装
//! - 状態ルートは既定（`StateRoot::resolve(None)`）に固定し、外部入力から受けない

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    self, CgroupRemoval, ContainerCgroupRemover, OciRuntimeError,
};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    AttachRequest, AttachResponse, CgroupPlacement, CgroupScope, ContainerId, ContainerRuntime,
    ContainerStatus, CreateNetnsRequest, CreateNetworkRequest, CreateRequest, DeleteNetworkRequest,
    DeleteNetworkResponse, DeleteRequest, DeleteResponse, DetachRequest, DetachResponse, ErrorCode,
    GetStateRequest, KillRequest, NetnsStatus, NetworkPlugin, NetworkStatus, PortMapping,
    PublishPortRequest, StartRequest, StateRequest, StateRevision, StateStore, StopRequest,
    TraitError,
};
use fandhe_container_cri::adapter::{BundleProvider, RuntimeAdapter};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::runtime::v1::ContainerConfig;
use fandhe_container_cri::runtime_service::CriRuntimeService;

/// 起動・シグナル系の未実装文言（固定。入力を含めない）。
pub const MSG_LAUNCH_UNAVAILABLE: &str =
    "container start/kill/stop is not available in the CRI plugin yet";
/// ネットワーク系の未実装文言。
pub const MSG_NETWORK_UNAVAILABLE: &str = "network plugin is not available in the CRI plugin yet";
/// bundle 供給の未実装文言。
pub const MSG_BUNDLE_UNAVAILABLE: &str =
    "bundle provisioning is not available in the CRI plugin yet";
/// cgroup 削除の未実装文言。
const MSG_CGROUP_UNAVAILABLE: &str =
    "container cgroup removal is not available in the CRI plugin yet";

/// plugin プロセスが core のトレイト境界へ差す実装の組（trait object だけを持つ。CRI-7）。
#[derive(Clone)]
pub struct CriPluginBackends {
    runtime: Arc<dyn ContainerRuntime>,
    state: Arc<dyn StateStore>,
    network: Arc<dyn NetworkPlugin>,
}

impl fmt::Debug for CriPluginBackends {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CriPluginBackends").finish_non_exhaustive()
    }
}

impl CriPluginBackends {
    /// 実装を注入して組む（試験と、別実装への差し替え。PLUG-1）。
    pub fn new(
        runtime: Arc<dyn ContainerRuntime>,
        state: Arc<dyn StateStore>,
        network: Arc<dyn NetworkPlugin>,
    ) -> Self {
        Self {
            runtime,
            state,
            network,
        }
    }

    /// 既定の組み合わせを作る（`FileStateStore`・[`CoreLifecycleRuntime`]・[`UnimplementedNetwork`]）。
    ///
    /// 状態ルートは既定の解決（`StateRoot::resolve(None)`）に固定する。解決できない OS では
    /// `Unimplemented` をそのまま返す（fail-closed）。
    pub fn production() -> Result<Self, TraitError> {
        let root = StateRoot::resolve(None)?;
        let state: Arc<dyn StateStore> = Arc::new(FileStateStore::open(root)?);
        let runtime = Arc::new(CoreLifecycleRuntime::new(Arc::clone(&state)));
        Ok(Self::new(runtime, state, Arc::new(UnimplementedNetwork)))
    }

    /// `ContainerRuntime` の実装。
    pub fn runtime(&self) -> &Arc<dyn ContainerRuntime> {
        &self.runtime
    }

    /// `StateStore` の実装。
    pub fn state(&self) -> &Arc<dyn StateStore> {
        &self.state
    }

    /// `NetworkPlugin` の実装（SetUpPod 系への配線は TASK-114.4・#460。現状は呼び出し元が無い）。
    pub fn network(&self) -> &Arc<dyn NetworkPlugin> {
        &self.network
    }

    /// 実行層を接続した `CriRuntimeService` を作る。serve はしない（起動は #459 以降）。
    pub fn runtime_service(&self, bundles: Arc<dyn BundleProvider>) -> CriRuntimeService {
        CriRuntimeService::new()
            .with_runtime(RuntimeAdapter::new(Arc::clone(&self.runtime)), bundles)
    }
}

/// core の `oci_runtime` のライブラリ関数へ委ねる plugin 側の `ContainerRuntime`（CRI-2）。
///
/// supervisor のプロセスが無くても core の呼び出しだけで完結する `create`・`state`・`delete` だけを
/// 実装する。`start`・`kill`・`stop` は `Unimplemented`（モジュール doc の REPAIR-3）。
pub struct CoreLifecycleRuntime {
    store: Arc<dyn StateStore>,
    recorder: OpRecorder,
}

impl fmt::Debug for CoreLifecycleRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreLifecycleRuntime")
            .finish_non_exhaustive()
    }
}

impl CoreLifecycleRuntime {
    /// 状態ストアを受けて作る。
    pub fn new(store: Arc<dyn StateStore>) -> Self {
        Self {
            store,
            recorder: OpRecorder::new(),
        }
    }
}

/// core の失敗を `ErrorCode` を保ったまま `TraitError` へ戻す（REPAIR-5 の `Timeout` 等を潰さない）。
fn to_trait_error(e: OciRuntimeError) -> TraitError {
    TraitError::new(e.code(), e.message())
}

fn launch_unavailable() -> TraitError {
    TraitError::new(ErrorCode::Unimplemented, MSG_LAUNCH_UNAVAILABLE)
}

impl ContainerRuntime for CoreLifecycleRuntime {
    fn create(&self, req: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        oci_runtime::create(&*self.store, &self.recorder, req)
            .map(|r| r.status().clone())
            .map_err(to_trait_error)
    }

    fn start(&self, _req: &StartRequest) -> Result<ContainerStatus, TraitError> {
        Err(launch_unavailable())
    }

    fn kill(&self, _req: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(launch_unavailable())
    }

    fn stop(&self, _req: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Err(launch_unavailable())
    }

    fn delete(&self, req: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        oci_runtime::delete(&*self.store, &self.recorder, &UnavailableCgroupRemover, req)
            .map_err(to_trait_error)
    }

    fn state(&self, req: &StateRequest) -> Result<ContainerStatus, TraitError> {
        self.store
            .get(&GetStateRequest::new(req.id().clone()))
            .map(|r| r.status().clone())
    }
}

/// cgroup を消せない remover（fail-closed）。cgroup の配置を持つ記録の `delete` は失敗し、記録を残す。
///
/// cgroup の配置が無い記録（プロセスを起動していない `Created`）では core の `delete` は remover に
/// 触れないため、そのまま削除できる（REPAIR-3。本番の remover の接続は supervisor 起動の経路と同時）。
#[derive(Debug, Clone, Copy)]
struct UnavailableCgroupRemover;

fn cgroup_unavailable() -> TraitError {
    TraitError::new(ErrorCode::Unimplemented, MSG_CGROUP_UNAVAILABLE)
}

impl ContainerCgroupRemover for UnavailableCgroupRemover {
    fn scope(&self) -> Result<CgroupScope, TraitError> {
        Err(cgroup_unavailable())
    }

    fn remove(
        &self,
        _id: &ContainerId,
        _instance: StateRevision,
    ) -> Result<CgroupRemoval, TraitError> {
        Err(cgroup_unavailable())
    }

    fn remove_recorded(
        &self,
        _id: &ContainerId,
        _placement: &CgroupPlacement,
        _recorder: &OpRecorder,
    ) -> Result<CgroupRemoval, TraitError> {
        Err(cgroup_unavailable())
    }
}

/// 全メソッドが `Unimplemented` を返す `NetworkPlugin`（CRI-7。TASK-139 の netsetup への対応付けは #460）。
#[derive(Debug, Clone, Copy, Default)]
pub struct UnimplementedNetwork;

fn network_unavailable() -> TraitError {
    TraitError::new(ErrorCode::Unimplemented, MSG_NETWORK_UNAVAILABLE)
}

impl NetworkPlugin for UnimplementedNetwork {
    fn create_network(&self, _req: &CreateNetworkRequest) -> Result<NetworkStatus, TraitError> {
        Err(network_unavailable())
    }

    fn create_netns(&self, _req: &CreateNetnsRequest) -> Result<NetnsStatus, TraitError> {
        Err(network_unavailable())
    }

    fn attach(&self, _req: &AttachRequest) -> Result<AttachResponse, TraitError> {
        Err(network_unavailable())
    }

    fn publish_port(&self, _req: &PublishPortRequest) -> Result<PortMapping, TraitError> {
        Err(network_unavailable())
    }

    fn detach(&self, _req: &DetachRequest) -> Result<DetachResponse, TraitError> {
        Err(network_unavailable())
    }

    fn delete_network(
        &self,
        _req: &DeleteNetworkRequest,
    ) -> Result<DeleteNetworkResponse, TraitError> {
        Err(network_unavailable())
    }
}

/// bundle を供給できない `BundleProvider`（REPAIR-3）。`prepare` は `UNIMPLEMENTED`、`release` は
/// 解放する資源が無いので `Ok`。`config`（envs に秘密値を含みうる）は文言へ含めない。
#[derive(Debug, Clone, Copy, Default)]
pub struct UnimplementedBundleProvider;

impl BundleProvider for UnimplementedBundleProvider {
    fn prepare(
        &self,
        _container_id: &str,
        _sandbox_id: &str,
        _config: &ContainerConfig,
    ) -> Result<PathBuf, CriError> {
        Err(CriError::unimplemented(MSG_BUNDLE_UNAVAILABLE))
    }

    fn release(&self, _container_id: &str) -> Result<(), CriError> {
        Ok(())
    }
}
