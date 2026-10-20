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
//! - `NetworkPlugin`: Linux では [`crate::netsetup::NetsetupNetwork`]（netsetup の操作単位へ対応づけ、`fandhe-container-net` の
//!   TASK-139 統合 API を呼ぶ。TASK-114.4・#460）。他 OS は `production()` 自体が `Unimplemented` で、
//!   注入口では [`UnimplementedNetwork`] を差せる
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

#[cfg(target_os = "linux")]
use crate::netsetup::{LinuxNetsetup, NetsetupNetwork};
use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
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
use fandhe_container_cri::instrument::{CriOpOutcome, CriOpRecorder, CriOpSample};
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
    /// 実行層（`oci_runtime`）と CRI サービスが共有する記録器（REPAIR-4）。
    recorder: Arc<OpRecorder>,
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
        Self::with_recorder(runtime, state, network, Arc::new(OpRecorder::new()))
    }

    /// 実装と共有の記録器を注入して組む。`runtime` が同じ記録器へ書くように作られている前提で、
    /// [`Self::op_recorder`] で件数・レイテンシを取り出せる（REPAIR-4）。
    pub fn with_recorder(
        runtime: Arc<dyn ContainerRuntime>,
        state: Arc<dyn StateStore>,
        network: Arc<dyn NetworkPlugin>,
        recorder: Arc<OpRecorder>,
    ) -> Self {
        Self {
            runtime,
            state,
            network,
            recorder,
        }
    }

    /// 既定の組み合わせを作る（`FileStateStore`・[`CoreLifecycleRuntime`]・`NetworkPlugin` は Linux で
    /// [`crate::netsetup::NetsetupNetwork`]、他 OS では状態ルートの解決が `Unimplemented` で失敗する）。
    ///
    /// 状態ルートは既定の解決（`StateRoot::resolve(None)`）に固定する。解決できない OS では
    /// `Unimplemented` をそのまま返す（fail-closed）。
    pub fn production() -> Result<Self, TraitError> {
        let root = StateRoot::resolve(None)?;
        // netns の pin の置き場は状態ルート配下の固定の場所（要求の入力からは受けない。TASK-114.4）。
        #[cfg(target_os = "linux")]
        let network: Arc<dyn NetworkPlugin> = Arc::new(NetsetupNetwork::new(LinuxNetsetup::new(
            root.path().join("netns"),
        )));
        #[cfg(not(target_os = "linux"))]
        let network: Arc<dyn NetworkPlugin> = Arc::new(UnimplementedNetwork);
        let state: Arc<dyn StateStore> = Arc::new(FileStateStore::open(root)?);
        let recorder = Arc::new(OpRecorder::new());
        let runtime = Arc::new(CoreLifecycleRuntime::with_recorder(
            Arc::clone(&state),
            Arc::clone(&recorder),
        ));
        Ok(Self::with_recorder(runtime, state, network, recorder))
    }

    /// `ContainerRuntime` の実装。
    pub fn runtime(&self) -> &Arc<dyn ContainerRuntime> {
        &self.runtime
    }

    /// `StateStore` の実装。
    pub fn state(&self) -> &Arc<dyn StateStore> {
        &self.state
    }

    /// `NetworkPlugin` の実装（CRI の RPC からの呼び出しは #459 以降。写像は [`crate::pod_network`]。現状は呼び出し元が無い）。
    pub fn network(&self) -> &Arc<dyn NetworkPlugin> {
        &self.network
    }

    /// 共有の記録器。`snapshot`・`export_json_lines` で操作ごとの成功・失敗件数とレイテンシを取り出す
    /// （実行層の `create`・`delete` と CRI の各 RPC が同じ記録器へ書く。REPAIR-4）。
    pub fn op_recorder(&self) -> &Arc<OpRecorder> {
        &self.recorder
    }

    /// 実行層を接続した `CriRuntimeService` を作る。serve はしない（起動は #459 以降）。
    ///
    /// CRI 側の計測は共有記録器（[`Self::op_recorder`]）へ `cri.*` の操作名で記録する。
    pub fn runtime_service(&self, bundles: Arc<dyn BundleProvider>) -> CriRuntimeService {
        CriRuntimeService::with_recorder(Arc::new(CoreCriRecorder(Arc::clone(&self.recorder))))
            .with_runtime(RuntimeAdapter::new(Arc::clone(&self.runtime)), bundles)
    }
}

/// core の `oci_runtime` のライブラリ関数へ委ねる plugin 側の `ContainerRuntime`（CRI-2）。
///
/// supervisor のプロセスが無くても core の呼び出しだけで完結する `create`・`state`・`delete` だけを
/// 実装する。`start`・`kill`・`stop` は `Unimplemented`（モジュール doc の REPAIR-3）。
pub struct CoreLifecycleRuntime {
    store: Arc<dyn StateStore>,
    recorder: Arc<OpRecorder>,
}

/// cri の計測結果を core の `OpRecorder` へ流す橋渡し（操作名は `CriOpKind::as_str`）。
/// 記録の失敗（名前種類の上限等）は `dropped_records` に計上され、RPC の結果は変えない。
struct CoreCriRecorder(Arc<OpRecorder>);

impl CriOpRecorder for CoreCriRecorder {
    fn record_cri_op(&self, sample: &CriOpSample) {
        let Ok(name) = OpName::new(sample.kind().as_str()) else {
            return;
        };
        let outcome = match sample.outcome() {
            CriOpOutcome::Success => OpOutcome::Success,
            _ => OpOutcome::Failure,
        };
        let _ = self.0.record(&name, outcome, sample.latency());
    }
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
        Self::with_recorder(store, Arc::new(OpRecorder::new()))
    }

    /// 状態ストアと共有の記録器を受けて作る（`create`・`delete` の観測値を呼び出し元と共有する。REPAIR-4）。
    pub fn with_recorder(store: Arc<dyn StateStore>, recorder: Arc<OpRecorder>) -> Self {
        Self { store, recorder }
    }

    /// 記録器。`snapshot` 等で `create`・`delete` の件数とレイテンシを取り出せる。
    pub fn recorder(&self) -> &Arc<OpRecorder> {
        &self.recorder
    }
}

/// core の失敗を `ErrorCode` を保ったまま `TraitError` へ戻す（REPAIR-5 の `Timeout` 等を潰さない）。
pub(crate) fn to_trait_error(e: OciRuntimeError) -> TraitError {
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
#[cfg(test)]
mod tests {
    //! 単体テスト（エラー変換のコード保持・cgroup 配置を持つ記録の delete の fail-closed・記録器の共有。
    //! CRI-2・REPAIR-4・REPAIR-5）。

    use std::sync::Mutex;

    use fandhe_container_core::oci_runtime::LifecycleOp;
    use fandhe_container_core::traits::{
        CreateStateRequest, DeleteStateRequest, DeleteStateResponse, ListStateRequest, StateList,
        StateRecord, UpdateStateRequest,
    };
    use fandhe_container_cri::instrument::{CriOpKind, CriOpTimer};

    use super::*;

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("valid id")
    }

    /// 1 件の記録だけを持つ `StateStore`。`delete` の呼び出し回数を数える。
    struct OneRecord {
        record: StateRecord,
        deletes: Mutex<u32>,
    }

    impl OneRecord {
        fn new(record: StateRecord) -> Self {
            Self {
                record,
                deletes: Mutex::new(0),
            }
        }
    }

    fn unused() -> TraitError {
        TraitError::new(ErrorCode::Unimplemented, "unused")
    }

    impl StateStore for OneRecord {
        fn create(&self, _r: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(unused())
        }
        fn get(&self, _r: &GetStateRequest) -> Result<StateRecord, TraitError> {
            Ok(self.record.clone())
        }
        fn update(&self, _r: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            Err(unused())
        }
        fn delete(&self, _r: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            *self.deletes.lock().expect("lock") += 1;
            Err(unused())
        }
        fn list(&self, _r: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(unused())
        }
    }

    fn record(with_cgroup: bool) -> StateRecord {
        let r = StateRecord::new(
            ContainerStatus::created(cid("c1"), None),
            // Windows では `/bundle` が絶対パスにならないため、OS ごとの絶対パスを使う。
            PathBuf::from(if cfg!(windows) {
                r"C:\bundle"
            } else {
                "/bundle"
            }),
            StateRevision::INITIAL,
        )
        .expect("record");
        if with_cgroup {
            r.with_cgroup(CgroupPlacement::new(
                CgroupScope::new("/fc").expect("scope"),
                StateRevision::INITIAL,
            ))
        } else {
            r
        }
    }

    /// `ErrorCode` を潰さずに `TraitError` へ戻す（REPAIR-5 の `Timeout` 等）。
    #[test]
    fn to_trait_error_preserves_code_and_message() {
        for code in [
            ErrorCode::Timeout,
            ErrorCode::NotFound,
            ErrorCode::AlreadyExists,
        ] {
            let e = to_trait_error(OciRuntimeError::new(LifecycleOp::Delete, code, "boom"));
            assert_eq!(e.code(), code);
            assert_eq!(e.message(), "boom");
        }
    }

    /// cgroup の配置を持つ記録の delete は fail-closed で、状態記録を消さず失敗を記録する（CRI-2・REPAIR-3・REPAIR-4）。
    #[test]
    fn delete_with_cgroup_placement_fails_closed_and_keeps_record() {
        let store = Arc::new(OneRecord::new(record(true)));
        let recorder = Arc::new(OpRecorder::new());
        let rt = CoreLifecycleRuntime::with_recorder(store.clone(), Arc::clone(&recorder));
        let e = rt
            .delete(&DeleteRequest::new(cid("c1")))
            .expect_err("cgroup unavailable");
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert_eq!(e.message(), MSG_CGROUP_UNAVAILABLE);
        assert_eq!(*store.deletes.lock().expect("lock"), 0);
        let stats = recorder
            .snapshot_op(&OpName::new("delete").expect("name"))
            .expect("delete recorded");
        assert_eq!((stats.success(), stats.failure()), (0, 1));
    }

    /// cgroup の配置が無い記録の delete は remover に触れず store.delete まで進む。
    #[test]
    fn delete_without_cgroup_placement_reaches_store_delete() {
        let store = Arc::new(OneRecord::new(record(false)));
        let rt = CoreLifecycleRuntime::new(store.clone());
        let e = rt
            .delete(&DeleteRequest::new(cid("c1")))
            .expect_err("fake store delete fails");
        assert_eq!(e.message(), "unused");
        assert_eq!(*store.deletes.lock().expect("lock"), 1);
    }

    /// 注入した記録器が CRI 計測の橋渡しにも使われ、`op_recorder` から件数を読める（REPAIR-4）。
    #[test]
    fn cri_recorder_bridge_writes_to_shared_recorder() {
        let store: Arc<dyn StateStore> = Arc::new(OneRecord::new(record(false)));
        let recorder = Arc::new(OpRecorder::new());
        let rt = Arc::new(CoreLifecycleRuntime::with_recorder(
            Arc::clone(&store),
            Arc::clone(&recorder),
        ));
        let backends = CriPluginBackends::with_recorder(
            rt,
            store,
            Arc::new(UnimplementedNetwork),
            Arc::clone(&recorder),
        );
        assert!(Arc::ptr_eq(backends.op_recorder(), &recorder));
        let bridge = CoreCriRecorder(Arc::clone(backends.op_recorder()));
        // 成功は `Ok(())`（Status 型は推論される）、未確定のまま Drop した場合は Internal の失敗。
        CriOpTimer::start(&bridge, CriOpKind::CreateContainer).finish_with(&Ok(()));
        drop(CriOpTimer::start(&bridge, CriOpKind::CreateContainer));
        let stats = recorder
            .snapshot_op(&OpName::new("cri.create_container").expect("name"))
            .expect("recorded");
        assert_eq!((stats.success(), stats.failure()), (1, 1));
    }
}
