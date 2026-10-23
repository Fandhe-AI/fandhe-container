//! plugin プロセス側で `ContainerRuntime`・`StateStore`・`NetworkPlugin` の実装を選んで組み立てる口
//! （TASK-114.2・#458・PLUG-1・CRI-2・CRI-7）。
//!
//! 呼び出し元: 将来は `main.rs` の `Run`（サーバーの起動。TASK-114.3 以降の #459・#849・#850）が
//! [`CriPluginBackends::production`] で組み立て、[`CriPluginBackends::runtime_service`] で
//! `fandhe-container-cri` の `CriRuntimeService` を得る。`main.rs` の `Serve`（`--socket`）が `server::serve` で UDS＋gRPC にサーブする（#849）。
//!
//! 依存の向きは plugin-cri → cri・core の一方向で、core・cri から plugin-cri への辺は無い（CRI-7）。
//! この向きは `crates/cri/tests/dependency_direction.rs` が `cargo metadata` で機械照合する（#2435）。
//! [`CriPluginBackends`] は trait object だけを持ち、具象型を型として露出しない。
//!
//! # 実装の置き場（CRI-7・PLUG-1）
//!
//! - `ContainerRuntime`: 実装は plugin 側（[`CoreLifecycleRuntime`]）。core のライブラリ関数
//!   （`oci_runtime::create` / `delete` と状態ストアの読み取り）へ委ねる
//! - `StateStore`: 既定実装 `FileStateStore` は core にある。本モジュールは二つ目の実装を作らず、
//!   選んで開き注入するだけ（別実装への差し替えは [`CriPluginBackends::new`] の注入口）
//! - `NetworkPlugin`: Linux では [`crate::netsetup::NetsetupNetwork`]（netsetup の操作単位へ対応づけ、`fandhe-container-net` の
//!   TASK-139 統合 API を呼ぶ。TASK-114.4・#460・MS-4）。他 OS は `production()` 自体が `Unimplemented` で、
//!   注入口では [`UnimplementedNetwork`] を差せる
//! - `VolumeProvider`: 実装は core 側に置く（データパスに接するため。ここには置かない）
//!
//! # 未実装・簡易実装（REPAIR-3）
//!
//! - `start`・`kill`・`stop` は Linux で supervisor 経由の本番経路へ結線済み（`crate::supervised`。#2434）。契約・期限・
//!   子プロセスの回収・前提（supervisor を plugin の実体と同じディレクトリに置く・`XDG_RUNTIME_DIR` が環境にある・rootful は
//!   `UNIMPLEMENTED`）は同 module の doc に従う。実機での通し（委譲 scope 内）は未実施（#850・#2062）。非 Linux では
//!   従来どおり `Unimplemented`（`MSG_LAUNCH_UNAVAILABLE`）
//! - `delete` の cgroup 削除は本番の `DetectedCgroupRemover`（`fandhe_container_supervisor::cgroup_remover`。CLI と共有）で、
//!   plugin プロセス自身の cgroup から委譲スコープを遅延検出する。plugin を委譲されたスコープの外（ログインセッション等）で
//!   動かすと検出に失敗し、cgroup の配置を記録したコンテナの `delete` は記録を残したまま失敗する（fail-closed。CLI と同じ
//!   方針で、検出の失敗を記録の経路へ回すかはオーナー判断待ち。#2133・#2060）。非 Linux は常に `Unimplemented`。
//!   core の `delete` が成功した後に限り、supervisor の構造化ログ（`<root>/@supervisor-logs/<id>.log*`）を期限つきで
//!   best effort で消す（失敗は戻り値に影響させず、期限切れは記録器の `supervisor_log_remove` の失敗として計上する）。
//!   続けてコンテナログ（`<root>/@container-logs/<id>.log*`・ロック。#2593・SUP-7・CRI-2・CLI-1）も CLI の `delete` と同じ
//!   `remove_container_logs_guarded_bounded` で消す（期限 5 秒・同じ ID の sink が生きていれば `FailedPrecondition` で何も消さない・
//!   stderr へは書かない）。消せなくても `delete` は `Ok` のままにする: CRI 層は `Err` で記録を残して再試行するが、再試行は
//!   core の `NOT_FOUND` で止まりログ削除まで届かないため、CLI と同じく成功として扱い、失敗は記録器の `container_log_remove`
//!   の失敗として計上する（構造化エラーは [`CoreLifecycleRuntime::remove_container_log`] の `TraitError`）。最悪の上乗せは
//!   supervisor ログと合わせて 10 秒。記録器にエラーコード別の内訳は無い（REPAIR-3）。既知の制約として、running への force
//!   `RemoveContainer` は supervisor の終了が sink を閉じきる前だとロックが取れず、ログが残る（1 ID あたり世代数 × 上限に収まる）
//! - bundle 供給: 本番は `CriPluginBackends::production_bundle_provider`（unix のみ）（pull 済みイメージの再展開と
//!   ContainerConfig → config.json 変換。#2433）。`ImageService` をサーブしていないためタグは解決できず、
//!   image ID（`sha256:<hex>`）だけを受ける（イメージ取り込みの結線と合わせて別途。REPAIR-3）。
//!   [`UnimplementedBundleProvider`] は試験と非 unix 用に残す
//! - `create` の `mounts[].destination` の拒否（宛先の遡り・rootfs 全体・相対 `..`）の監査記録（SEC-4・OCI-4・CRI-7・#2594）は、
//!   記録先を注入したときだけ行う（[`CriPluginBackends::production_with_audit_sink`]。Linux の本番はこちら）。プロセスが常に複数
//!   スレッド（`spawn_blocking` 等）のため `FileAuditSink` を直接渡せず、`main.rs` が単一スレッドの間に作った
//!   `ControlAuditRelay` を渡す。`production()` と非 Linux（永続化経路が未実装。#2430 の判断待ち）では記録しない。
//!   `start` の再検証は supervisor（`fandhe_container_supervisor::start_client` が起動する bin）側で記録する
//! - 状態ルートは既定（`StateRoot::resolve(None)`）に固定し、外部入力から受けない

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use crate::netsetup::{LinuxNetsetup, NetsetupNetwork};
#[cfg(target_os = "linux")]
use crate::supervised::SupervisedLifecycle;
use fandhe_container_core::audit_log::{AuditRecord, AuditSink, RECORD_WAIT_LIMIT};
use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::oci_runtime::{self, ContainerCgroupRemover, OciRuntimeError};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    AttachRequest, AttachResponse, ContainerId, ContainerRuntime, ContainerStatus,
    CreateNetnsRequest, CreateNetworkRequest, CreateRequest, DeleteNetworkRequest,
    DeleteNetworkResponse, DeleteRequest, DeleteResponse, DetachRequest, DetachResponse, ErrorCode,
    GetStateRequest, KillRequest, NetnsStatus, NetworkPlugin, NetworkStatus, PortMapping,
    PublishPortRequest, StartRequest, StateRequest, StateStore, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{BundleProvider, BundleRequest, RuntimeAdapter};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::instrument::{CriOpOutcome, CriOpRecorder, CriOpSample};
use fandhe_container_cri::runtime_service::CriRuntimeService;
use fandhe_container_supervisor::cgroup_remover::production_cgroup_remover;
use fandhe_container_supervisor::logs::{
    CONTAINER_LOG_REMOVE_TIMEOUT, RemovedLogs, remove_container_logs_guarded_bounded,
};
use fandhe_container_supervisor::supervisor_log::{
    LogRemoval, SUPERVISOR_LOG_REMOVE_TIMEOUT, remove_bounded,
};

/// 起動・シグナル系の未実装文言（固定。入力を含めない。非 Linux でだけ返す。Linux は supervisor 経由で結線済み）。
#[cfg(not(target_os = "linux"))]
pub const MSG_LAUNCH_UNAVAILABLE: &str =
    "container start/kill/stop is not available in the CRI plugin yet";
/// ネットワーク系の未実装文言。
pub const MSG_NETWORK_UNAVAILABLE: &str = "network plugin is not available in the CRI plugin yet";
/// bundle 供給の未実装文言。
pub const MSG_BUNDLE_UNAVAILABLE: &str =
    "bundle provisioning is not available in the CRI plugin yet";

/// plugin プロセスが core のトレイト境界へ差す実装の組（trait object だけを持つ。CRI-7）。
#[derive(Clone)]
pub struct CriPluginBackends {
    runtime: Arc<dyn ContainerRuntime>,
    state: Arc<dyn StateStore>,
    network: Arc<dyn NetworkPlugin>,
    /// 実行層（`oci_runtime`）と CRI サービスが共有する記録器（REPAIR-4）。
    recorder: Arc<OpRecorder>,
    /// `production()` が解決した状態ルート（bundle とイメージキャッシュの置き場の親。注入で組んだときは `None`）。
    state_root: Option<PathBuf>,
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
            state_root: None,
        }
    }

    /// 既定の組み合わせを作る（`FileStateStore`・[`CoreLifecycleRuntime`]・`NetworkPlugin` は Linux で
    /// [`crate::netsetup::NetsetupNetwork`]、他 OS では状態ルートの解決が `Unimplemented` で失敗する）。
    ///
    /// 状態ルートは既定の解決（`StateRoot::resolve(None)`）に固定する。解決できない OS では
    /// `Unimplemented` をそのまま返す（fail-closed）。
    pub fn production() -> Result<Self, TraitError> {
        Self::production_inner(None)
    }

    /// [`Self::production`] に、`create` の `mounts[].destination` 拒否の監査の記録先を足したもの（SEC-4・OCI-4・CRI-7・#2594）。
    ///
    /// Linux の本番（`main.rs`）はこちらを呼び、`sink` に単一スレッドの間に作った `ControlAuditRelay` を渡す。
    /// `production()` の `create` はこの拒否を記録しない。記録に失敗しても拒否の `code`・`message` は変えず、失敗は固定語彙の
    /// 1 行を stderr へ出す（relay の待ちは有界。`PLUGIN_RUNTIME_TIMEOUT` の内側）。
    pub fn production_with_audit_sink(sink: Arc<dyn AuditSink>) -> Result<Self, TraitError> {
        Self::production_inner(Some(sink))
    }

    fn production_inner(create_audit: Option<Arc<dyn AuditSink>>) -> Result<Self, TraitError> {
        let root = StateRoot::resolve(None)?;
        let state_root = root.path().to_path_buf();
        let recorder = Arc::new(OpRecorder::new());
        // netns の pin の置き場は状態ルート配下の固定の場所（要求の入力からは受けない。TASK-114.4）。
        // 先頭が `.` のため、英数字始まりの `ContainerId` の状態ディレクトリと衝突しない。
        #[cfg(target_os = "linux")]
        let network: Arc<dyn NetworkPlugin> = Arc::new(NetsetupNetwork::with_recorder(
            LinuxNetsetup::with_recorder(
                root.path().join(".netns"),
                Arc::new(CoreNetRecorder(Arc::clone(&recorder))),
            ),
            Arc::clone(&recorder),
        ));
        #[cfg(not(target_os = "linux"))]
        let network: Arc<dyn NetworkPlugin> = Arc::new(UnimplementedNetwork);
        let state: Arc<dyn StateStore> = Arc::new(FileStateStore::open(root)?);
        let mut runtime =
            CoreLifecycleRuntime::with_recorder(Arc::clone(&state), Arc::clone(&recorder));
        if let Some(sink) = create_audit {
            runtime = runtime.with_create_audit_sink(sink);
        }
        let runtime = Arc::new(runtime);
        let mut backends = Self::with_recorder(runtime, state, network, recorder);
        backends.state_root = Some(state_root);
        Ok(backends)
    }

    /// 本番の bundle 供給を作る（状態ルート配下の固定位置。要求の入力から受けない。#2433）。
    ///
    /// `production()` で組んだときだけ使え、注入で組んだときは `FAILED_PRECONDITION`。詳細は `bundle_provider_in`。
    #[cfg(unix)]
    pub fn production_bundle_provider(&self) -> Result<Arc<dyn BundleProvider>, CriError> {
        match &self.state_root {
            Some(root) => bundle_provider_in(root),
            None => Err(CriError::failed_precondition(
                "state root is not configured",
            )),
        }
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

    /// 実行層を接続した `CriRuntimeService` を作る。サーブは `server::serve` が担う（#849）。
    ///
    /// CRI 側の計測は共有記録器（[`Self::op_recorder`]）へ `cri.*` の操作名で記録する。
    ///
    /// 実行層の呼び出しの待ち上限は [`PLUGIN_RUNTIME_TIMEOUT`] にする（CRI の既定 10 秒では supervisor の起動の受信期限
    /// 〔約 58.9 秒〕より先に結果不明へ倒れるため。#2434・REPAIR-5）。
    pub fn runtime_service(&self, bundles: Arc<dyn BundleProvider>) -> CriRuntimeService {
        CriRuntimeService::with_recorder(Arc::new(CoreCriRecorder(Arc::clone(&self.recorder))))
            .with_runtime_timeout(PLUGIN_RUNTIME_TIMEOUT)
            .with_runtime(RuntimeAdapter::new(Arc::clone(&self.runtime)), bundles)
    }
}

/// CRI サービスが実行層の呼び出しを待つ上限（REPAIR-5・#2434）。
///
/// supervisor の起動結果の受信期限（`start_contract::cli_receive_deadline`）に 2 秒の余裕を足した値。CRI の既定
/// （10 秒）のままだと、起動が成功しても結果不明（exited）に倒れる。`stop` の待ちは CRI 側がこれに SIGTERM の猶予を足す。
pub const PLUGIN_RUNTIME_TIMEOUT: Duration = Duration::from_millis(60_900);

/// core の `oci_runtime` のライブラリ関数へ委ねる plugin 側の `ContainerRuntime`（CRI-2）。
///
/// `create`・`state`・`delete` は core の呼び出しで完結する。`start`・`kill`・`stop` は Linux で supervisor 経由
/// （`crate::supervised`）、非 Linux では `Unimplemented`（モジュール doc の REPAIR-3）。
pub struct CoreLifecycleRuntime {
    store: Arc<dyn StateStore>,
    recorder: Arc<OpRecorder>,
    /// `delete` が cgroup の配置を記録したコンテナを消すための remover（本番は遅延検出。注入で差し替えられる）。
    cgroups: Arc<dyn ContainerCgroupRemover>,
    /// `create` の `mounts[].destination` 拒否の記録先（`with_create_audit_sink`。#2594）。無ければ記録しない。
    create_audit: Option<Arc<dyn AuditSink>>,
    #[cfg(target_os = "linux")]
    supervised: SupervisedLifecycle,
}

/// `create` の拒否の記録先を包み、記録の失敗を固定語彙の 1 行で stderr へ残す（結果は内側のまま返す。#2594）。
///
/// 記録の失敗で拒否は覆さない（fail-closed）が、失敗が見えなくなるのも避ける。supervisor の `ObservedRejectionSink` と同じ趣旨。
/// 通知行はエラーコードのトークンだけで、メッセージ・入力値を含めない。
struct ObservedCreateAudit {
    inner: Arc<dyn AuditSink>,
}

impl ObservedCreateAudit {
    /// 失敗なら `log` へコードを渡してから、同じ結果を返す（`log` は試験で差し替える）。
    fn observe(
        result: Result<(), TraitError>,
        log: impl FnOnce(ErrorCode),
    ) -> Result<(), TraitError> {
        if let Err(e) = &result {
            log(e.code());
        }
        result
    }
}

/// 失敗の通知行（固定語彙とコードのトークンのみ）を作る。
fn create_audit_failure_line(code: ErrorCode) -> String {
    format!(
        "{{\"component\":\"plugin-cri\",\"event\":\"create_audit_record_failed\",\"outcome\":\"error\",\"code\":\"{}\"}}\n",
        code.as_str()
    )
}

fn log_create_audit_failure(code: ErrorCode) {
    let _ = crate::telemetry::stderr_sink().submit(create_audit_failure_line(code));
}

/// create の destination 拒否 1 件の記録に許す合計時間（ロック取得と配送の合計。REPAIR-5・SEC-4・#2594）。
///
/// relay は peer 認証の転送スレッドと共有するため、ロック待ち 1 回分と配送 1 回分で `RECORD_WAIT_LIMIT` の 2 倍。
/// `PLUGIN_RUNTIME_TIMEOUT` に収まる。
const CREATE_AUDIT_BUDGET: Duration = RECORD_WAIT_LIMIT.saturating_mul(2);

impl AuditSink for ObservedCreateAudit {
    /// 期限なしの `record` は relay のロックを無期限に待つため、入口で絶対期限を決めて `record_until` へ渡す。
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        self.record_until(record, Instant::now() + CREATE_AUDIT_BUDGET)
    }

    fn record_until(&self, record: &AuditRecord, deadline: Instant) -> Result<(), TraitError> {
        Self::observe(
            self.inner.record_until(record, deadline),
            log_create_audit_failure,
        )
    }
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

/// net の計測結果を core の `OpRecorder` へ流す橋渡し（操作名は `NetOpKind::as_str`。REPAIR-4）。
#[cfg(target_os = "linux")]
struct CoreNetRecorder(Arc<OpRecorder>);

#[cfg(target_os = "linux")]
impl fandhe_container_net::instrument::NetOpRecorder for CoreNetRecorder {
    fn record_net_op(&self, sample: &fandhe_container_net::instrument::NetOpSample) {
        use fandhe_container_net::instrument::NetOpOutcome;
        let Ok(name) = OpName::new(sample.kind().as_str()) else {
            return;
        };
        let outcome = match sample.outcome() {
            NetOpOutcome::Success => OpOutcome::Success,
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
        Self {
            store,
            recorder,
            cgroups: Arc::new(production_cgroup_remover()),
            create_audit: None,
            #[cfg(target_os = "linux")]
            supervised: SupervisedLifecycle::production(),
        }
    }

    /// cgroup remover を差し替える（結合試験と別実装。本番の既定は supervisor crate の遅延検出つき remover）。
    #[must_use]
    pub fn with_cgroup_remover(mut self, cgroups: Arc<dyn ContainerCgroupRemover>) -> Self {
        self.cgroups = cgroups;
        self
    }

    /// `create` の `mounts[].destination` 拒否（SEC-4・OCI-4・#2594）の記録先を設定する。
    ///
    /// プロセスが複数スレッドのため `FileAuditSink` は直接渡せない。単一スレッドの間に作った `ControlAuditRelay` を渡す
    /// （呼び出し元は `main.rs`。[`CriPluginBackends::production_with_audit_sink`] 経由）。記録の待ちは有界で、relay を
    /// peer 認証の転送スレッドと共有するため最悪で `RECORD_WAIT_LIMIT` の約 2 倍待つが `PLUGIN_RUNTIME_TIMEOUT` に収まる。
    #[must_use]
    pub fn with_create_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.create_audit = Some(Arc::new(ObservedCreateAudit { inner: sink }));
        self
    }

    /// supervisor の起動・signaler の組を差し替える（結合試験と別実装。Linux のみ）。
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn with_supervision(mut self, supervised: SupervisedLifecycle) -> Self {
        self.supervised = supervised;
        self
    }

    /// 起動した supervisor の子プロセスの追跡数（回収の観測用。Linux のみ）。
    #[cfg(target_os = "linux")]
    pub fn tracked_supervisors(&self) -> usize {
        self.supervised.tracked_children()
    }

    /// 記録器。`snapshot` 等で `create`・`delete` の件数とレイテンシを取り出せる。
    pub fn recorder(&self) -> &Arc<OpRecorder> {
        &self.recorder
    }

    /// core の `delete` が成功した後に、supervisor の構造化ログを期限つきで best effort に消す（#2067・#2434・REPAIR-4・REPAIR-5）。
    ///
    /// 失敗・期限切れでも `delete` の結果は変えない（状態の削除は完了済み）。期限切れは記録器の操作名
    /// `supervisor_log_remove` の失敗として計上し、観測できるようにする。
    fn remove_supervisor_log(&self, id: &ContainerId) {
        let Some(root) = self.store.host_state_root() else {
            return;
        };
        let started = Instant::now();
        let outcome = remove_bounded(root, id, SUPERVISOR_LOG_REMOVE_TIMEOUT);
        if let Ok(name) = OpName::new("supervisor_log_remove") {
            let result = match outcome {
                LogRemoval::Finished => OpOutcome::Success,
                LogRemoval::TimedOut => OpOutcome::Failure,
            };
            let _ = self.recorder.record(&name, result, started.elapsed());
        }
    }

    /// コンテナログ（現在ログ・全世代・ロック）を消す。core の `delete` が成功した後にだけ呼ぶ（失敗した delete で
    /// 稼働中のコンテナのログを消さないため。#2593・SUP-7・CRI-2・CLI-1）。
    ///
    /// CLI の `delete` と同じ supervisor の関数・契約で、期限は 5 秒（同時実行枠は supervisor ログの削除と共有）、
    /// stderr へは何も書かない。ロック取得後に状態ストアで ID が `NotFound` のままであることを確かめ、
    /// 読み取りに失敗したら fail-closed で削除を見送る（同じ ID で再作成されたインスタンスのログを消さない）。
    /// 状態ルートが無い（ホスト上のパスを持たない）ストアでは何もせず `Ok`。
    ///
    /// # Errors
    /// supervisor の `TraitError` をそのまま返す。`FailedPrecondition`（同じ ID の sink が生きている）・
    /// `Timeout`（期限切れか枠の満杯）・`InvalidArgument`（名前空間の不正）・`Internal`（ディレクトリ検査の失敗）。
    pub fn remove_container_log(&self, id: &ContainerId) -> Result<RemovedLogs, TraitError> {
        let Some(root) = self.store.host_state_root() else {
            return Ok(RemovedLogs::default());
        };
        let store = Arc::clone(&self.store);
        let guard_id = id.clone();
        remove_container_logs_guarded_bounded(root, id, CONTAINER_LOG_REMOVE_TIMEOUT, move || {
            matches!(
                store.get(&GetStateRequest::new(guard_id.clone())),
                Err(e) if e.code() == ErrorCode::NotFound
            )
        })
    }

    /// [`Self::remove_container_log`] の結果を記録器の `container_log_remove` に計上する（戻り値には影響させない）。
    fn record_container_log_removal(&self, id: &ContainerId) {
        if self.store.host_state_root().is_none() {
            return;
        }
        let started = Instant::now();
        let result = match self.remove_container_log(id) {
            Ok(_) => OpOutcome::Success,
            Err(_) => OpOutcome::Failure,
        };
        if let Ok(name) = OpName::new("container_log_remove") {
            let _ = self.recorder.record(&name, result, started.elapsed());
        }
    }
}

/// core の失敗を `ErrorCode` を保ったまま `TraitError` へ戻す（REPAIR-5 の `Timeout` 等を潰さない）。
pub(crate) fn to_trait_error(e: OciRuntimeError) -> TraitError {
    TraitError::new(e.code(), e.message())
}

impl CoreLifecycleRuntime {
    /// force 削除の前に、生きている（Running・pid あり、または pid あり Created）コンテナを停止して終了を確認する。
    ///
    /// 猶予 0 で SIGTERM の直後に SIGKILL へ進み、最長 `STOP_KILL_WAIT` で有界（REPAIR-5）。記録が無い・停止済み・
    /// pid の無い状態は何もせず、core の delete の判定に任せる。
    #[cfg(target_os = "linux")]
    fn stop_live_before_force_delete(&self, id: &ContainerId) -> Result<(), TraitError> {
        use fandhe_container_core::traits::ContainerState;
        let status = match self.store.get(&GetStateRequest::new(id.clone())) {
            Ok(r) => r.status().clone(),
            Err(e) if e.code() == ErrorCode::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let live = matches!(
            status.state(),
            ContainerState::Running | ContainerState::Created
        ) && status.pid().is_some();
        if live {
            let stop = StopRequest::new(id.clone(), Duration::ZERO)?;
            self.supervised.stop(&*self.store, &self.recorder, &stop)?;
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn launch_unavailable() -> TraitError {
    TraitError::new(ErrorCode::Unimplemented, MSG_LAUNCH_UNAVAILABLE)
}

impl ContainerRuntime for CoreLifecycleRuntime {
    fn create(&self, req: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        let created = match &self.create_audit {
            Some(sink) => {
                oci_runtime::create_audited(&*self.store, &self.recorder, req, sink.as_ref())
            }
            None => oci_runtime::create(&*self.store, &self.recorder, req),
        };
        created.map(|r| r.status().clone()).map_err(to_trait_error)
    }

    #[cfg(target_os = "linux")]
    fn start(&self, req: &StartRequest) -> Result<ContainerStatus, TraitError> {
        self.supervised.start(&*self.store, req.id())
    }

    #[cfg(not(target_os = "linux"))]
    fn start(&self, _req: &StartRequest) -> Result<ContainerStatus, TraitError> {
        Err(launch_unavailable())
    }

    #[cfg(target_os = "linux")]
    fn kill(&self, req: &KillRequest) -> Result<ContainerStatus, TraitError> {
        self.supervised.kill(&*self.store, &self.recorder, req)
    }

    #[cfg(not(target_os = "linux"))]
    fn kill(&self, _req: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(launch_unavailable())
    }

    #[cfg(target_os = "linux")]
    fn stop(&self, req: &StopRequest) -> Result<ContainerStatus, TraitError> {
        self.supervised.stop(&*self.store, &self.recorder, req)
    }

    #[cfg(not(target_os = "linux"))]
    fn stop(&self, _req: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Err(launch_unavailable())
    }

    fn delete(&self, req: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        #[cfg(target_os = "linux")]
        {
            self.supervised.reap();
            // force は停止してから削除する（ContainerRuntime::delete の契約。CORE-2・CRI-2）。core の delete は
            // 生きたコンテナの force を拒否するため、ここで停止と終了確認を済ませる。
            if req.force() {
                self.stop_live_before_force_delete(req.id())?;
            }
        }
        let response = oci_runtime::delete(&*self.store, &self.recorder, &*self.cgroups, req)
            .map_err(to_trait_error)?;
        self.remove_supervisor_log(req.id());
        self.record_container_log_removal(req.id());
        Ok(response)
    }

    fn state(&self, req: &StateRequest) -> Result<ContainerStatus, TraitError> {
        self.store
            .get(&GetStateRequest::new(req.id().clone()))
            .map(|r| r.status().clone())
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

/// bundle の置き場（状態ルート直下。先頭が `.` のため `ContainerId` の状態ディレクトリと衝突しない）。
#[cfg(unix)]
const BUNDLES_DIR: &str = ".cri/bundles";
/// pull 済みイメージのキャッシュの置き場（`ImageService` の pull が使うキャッシュと同じ位置を想定する）。
#[cfg(unix)]
const IMAGES_DIR: &str = ".cri/images";

/// 状態ルート `state_root` 配下に bundle の置き場とイメージキャッシュを用意し、本番の [`BundleProvider`] を作る
/// （CRI-2・OCI-4・SEC-1。#2433）。
///
/// 置き場は `<state_root>/.cri/{bundles,images}` の固定位置で、各ディレクトリは 0700 で作る。既存のものは symlink でなく、
/// 状態ルートと同じ所有者で、group / other の権限が無いことを確かめ、反すれば消さずに拒否する（fail-closed）。
/// 失敗の文言は固定で、パスや OS の文字列を含めない。
#[cfg(unix)]
pub fn bundle_provider_in(
    state_root: &std::path::Path,
) -> Result<Arc<dyn BundleProvider>, CriError> {
    use fandhe_container_cri::bundle::{ImageExtractConfig, ImageRootfsSource, SpecBundleProvider};
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};

    let fail = || CriError::failed_precondition("failed to prepare the bundle store");
    let owner = std::fs::symlink_metadata(state_root)
        .map_err(|_| fail())?
        .uid();
    let mut dirs = Vec::new();
    for rel in [BUNDLES_DIR, IMAGES_DIR] {
        let mut cur = state_root.to_path_buf();
        for part in rel.split('/') {
            cur.push(part);
            match std::fs::DirBuilder::new().mode(0o700).create(&cur) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(fail()),
            }
            let m = std::fs::symlink_metadata(&cur).map_err(|_| fail())?;
            if !m.file_type().is_dir() || m.uid() != owner || m.permissions().mode() & 0o077 != 0 {
                return Err(fail());
            }
        }
        dirs.push(cur);
    }
    let [bundles, images] = <[PathBuf; 2]>::try_from(dirs).map_err(|_| fail())?;
    // SpecBundleProvider は root の正規化済みパスを要求する（途中の symlink を拒否する）。
    let bundles = std::fs::canonicalize(bundles).map_err(|_| fail())?;
    let source = ImageRootfsSource::new(ImageExtractConfig::new(images)?);
    Ok(Arc::new(SpecBundleProvider::new(
        bundles,
        Arc::new(source),
    )?))
}

/// bundle を供給できない `BundleProvider`（REPAIR-3）。`prepare` は `UNIMPLEMENTED`、`release` は
/// 解放する資源が無いので `Ok`。`config`（envs に秘密値を含みうる）は文言へ含めない。
#[derive(Debug, Clone, Copy, Default)]
pub struct UnimplementedBundleProvider;

impl BundleProvider for UnimplementedBundleProvider {
    fn prepare(&self, _req: &BundleRequest<'_>) -> Result<PathBuf, CriError> {
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

    use fandhe_container_core::oci_runtime::{CgroupRemoval, LifecycleOp};
    use fandhe_container_core::traits::{
        CgroupPlacement, CgroupScope, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
        ListStateRequest, StateList, StateRecord, StateRevision, UpdateStateRequest,
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

    const MSG_CGROUP_UNAVAILABLE: &str =
        "container cgroup removal is not available in the CRI plugin yet";

    /// 常に失敗する remover（本番の遅延検出は実環境の cgroup に依存するため、注入して fail-closed の経路を固定する）。
    struct UnavailableRemover;

    fn cgroup_unavailable() -> TraitError {
        TraitError::new(ErrorCode::Unimplemented, MSG_CGROUP_UNAVAILABLE)
    }

    impl ContainerCgroupRemover for UnavailableRemover {
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

    /// cgroup の配置を持つ記録の delete は、remover の失敗で fail-closed になり、状態記録を消さず失敗を記録する
    /// （CRI-2・REPAIR-4。remover は注入。本番の遅延検出の失敗は `tests/lifecycle_supervisor.rs`）。
    #[test]
    fn delete_with_cgroup_placement_fails_closed_and_keeps_record() {
        let store = Arc::new(OneRecord::new(record(true)));
        let recorder = Arc::new(OpRecorder::new());
        let rt = CoreLifecycleRuntime::with_recorder(store.clone(), Arc::clone(&recorder))
            .with_cgroup_remover(Arc::new(UnavailableRemover));
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

    /// CRI-2・CORE-2: 未起動（pid なし）の Created への stop は FAILED_PRECONDITION にならず、停止済みを返す。
    #[cfg(target_os = "linux")]
    #[test]
    fn stop_on_created_without_pid_reports_stopped() {
        let store = Arc::new(OneRecord::new(record(false)));
        let rt = CoreLifecycleRuntime::new(store);
        let status = rt
            .stop(&StopRequest::new(cid("c1"), Duration::ZERO).expect("req"))
            .expect("created is already stopped");
        assert_eq!(
            status.state(),
            fandhe_container_core::traits::ContainerState::Stopped
        );
    }

    /// CRI-2・CORE-2: force 削除は、停止対象の無い pid なし Created をそのまま core の delete へ渡す。
    #[test]
    fn force_delete_on_created_without_pid_reaches_store_delete() {
        let store = Arc::new(OneRecord::new(record(false)));
        let rt = CoreLifecycleRuntime::new(store.clone());
        let e = rt
            .delete(&DeleteRequest::new(cid("c1")).with_force(true))
            .expect_err("fake store delete fails");
        assert_eq!(e.message(), "unused");
        assert_eq!(*store.deletes.lock().expect("lock"), 1);
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

    /// SEC-4・REPAIR-4（#2594）: 記録の失敗は固定語彙の 1 行にだけ出し、結果（`code`）は内側のまま返す。成功では何も出さない。
    #[test]
    fn sec4_2594_observed_create_audit_logs_only_failures() {
        let seen = std::cell::RefCell::new(Vec::new());
        let log = |c: ErrorCode| seen.borrow_mut().push(c);
        assert!(ObservedCreateAudit::observe(Ok(()), log).is_ok());
        assert!(seen.borrow().is_empty());
        let e = ObservedCreateAudit::observe(
            Err(TraitError::new(ErrorCode::Unavailable, "secret detail")),
            log,
        )
        .expect_err("passes the failure through");
        assert_eq!(e.code(), ErrorCode::Unavailable);
        assert_eq!(seen.borrow().as_slice(), [ErrorCode::Unavailable]);
        let line = create_audit_failure_line(ErrorCode::Unavailable);
        assert!(
            line.contains(r#""event":"create_audit_record_failed""#),
            "{line}"
        );
        assert!(line.contains(r#""outcome":"error""#), "{line}");
        assert!(
            line.contains(&format!(r#""code":"{}""#, ErrorCode::Unavailable.as_str())),
            "{line}"
        );
        assert!(!line.contains("secret"), "{line}");
        assert!(line.ends_with('\n'));
    }

    /// REPAIR-5・SEC-4・#2594: `record` は期限なしの内側の `record` を呼ばず、`CREATE_AUDIT_BUDGET` 以内の
    /// 絶対期限つきで `record_until` を呼ぶ（ロック待ちを含む合計の制限）。期限切れの `Timeout` はそのまま返る。
    #[test]
    fn repair5_2594_create_audit_record_uses_a_bounded_deadline() {
        use std::sync::Mutex;
        struct Probe(Mutex<Vec<Instant>>);
        impl AuditSink for Probe {
            fn record(&self, _: &AuditRecord) -> Result<(), TraitError> {
                panic!("unbounded record must not be used");
            }
            fn record_until(&self, _: &AuditRecord, d: Instant) -> Result<(), TraitError> {
                self.0.lock().expect("lock").push(d);
                Err(TraitError::new(ErrorCode::Timeout, "deadline"))
            }
        }
        let probe = Arc::new(Probe(Mutex::new(Vec::new())));
        let observed = ObservedCreateAudit {
            inner: Arc::clone(&probe) as Arc<dyn AuditSink>,
        };
        let rec = fandhe_container_core::audit_log::AuditRecord::new(
            fandhe_container_core::audit_log::AuditTimestamp::from_unix_duration(Duration::new(
                1_700_000_000,
                0,
            )),
            fandhe_container_core::audit_log::AuditPid::new(4242).expect("pid"),
            fandhe_container_core::audit_log::AuditEvent::Mount {
                path: None,
                reason: None,
            },
        );
        let before = Instant::now();
        let e = observed.record(&rec).expect_err("timeout passes through");
        assert_eq!(e.code(), ErrorCode::Timeout);
        let seen = probe.0.lock().expect("lock");
        assert_eq!(seen.len(), 1);
        assert!(seen[0] > before && seen[0] <= Instant::now() + CREATE_AUDIT_BUDGET);
        assert_eq!(CREATE_AUDIT_BUDGET, RECORD_WAIT_LIMIT * 2);
    }

    /// SEC-4・#2594: 常に失敗する sink でも `create` の拒否の `code`・`message` は変わらない（fail-closed）。
    #[test]
    fn sec4_2594_create_rejection_is_unchanged_when_the_audit_sink_fails() {
        struct Failing;
        impl AuditSink for Failing {
            fn record(&self, _: &AuditRecord) -> Result<(), TraitError> {
                Err(TraitError::new(ErrorCode::Internal, "sink down"))
            }
        }
        let dir = std::env::temp_dir().join(format!("fc-cri-2594-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rootfs")).expect("rootfs");
        std::fs::write(
            dir.join("config.json"),
            r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/true"],"cwd":"/"},"mounts":[{"destination":"/../..","type":"bind","source":"/srv/x","options":["bind","rw"]}]}"#,
        )
        .expect("config");
        let req =
            CreateRequest::new(ContainerId::new("c1").expect("id"), dir.clone()).expect("req");
        let store: Arc<dyn StateStore> = Arc::new(OneRecord::new(record(false)));
        let plain = CoreLifecycleRuntime::new(Arc::clone(&store))
            .create(&req)
            .expect_err("rejected");
        let audited = CoreLifecycleRuntime::new(store)
            .with_create_audit_sink(Arc::new(Failing))
            .create(&req)
            .expect_err("rejected");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(audited.code(), ErrorCode::InvalidArgument);
        assert_eq!(audited.code(), plain.code());
        assert_eq!(audited.message(), plain.message());
    }

    /// SEC-4・#2594: Linux の本番の入口は、単一スレッドの間に作った relay を create の記録先として渡す。
    /// 実プロセスの結線は単一スレッド条件のためソースで固定する。
    #[test]
    fn sec4_2594_main_wires_the_relay_to_create() {
        let src = include_str!("main.rs");
        let wire = src
            .find("CriPluginBackends::production_with_audit_sink(")
            .expect("main passes the relay to the backends");
        assert!(src[wire..].contains("std::sync::Arc::clone(&audit_sink)"));
        let forwarder = src
            .find("telemetry::PeerAuditForwarder::spawn(")
            .expect("the forwarder keeps the original sink");
        assert!(wire < forwarder);
    }
}
