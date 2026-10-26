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
//!   `remove_container_logs_guarded_bounded_waiting` で消す（同じ ID の sink が生きていれば `FailedPrecondition` で何も消さず、
//!   最大 10 秒まで 50ms 間隔で試し直して sink の閉鎖を待つ。1 回の試行の期限は 5 秒。設計は
//!   `docs/design/container-log-removal-wait.md`・#2634。削除関数そのものは stderr へ書かない）。残した結果は `DeleteResponse` の
//!   `supervisor_log`・`container_log` に載せ（`Kept { code }`。rootfs の欄は core が埋める。#2633）、`Kept` が 1 件でもあれば
//!   1 件につき 1 行の構造化ログ（`event: container_delete_cleanup`。パス・errno は含めない）を `LineSink`（有界キュー。待たない）経由で出す。
//!   消せなくても `delete` は `Ok` のままにする: CRI 層は `Err` で記録を残して再試行するが、再試行は
//!   core の `NOT_FOUND` で止まりログ削除まで届かないため、CLI と同じく成功として扱い、失敗は記録器の `container_log_remove`
//!   の失敗として計上する（構造化エラーは [`CoreLifecycleRuntime::remove_container_log`] の `TraitError`）。最悪の上乗せは
//!   supervisor ログと合わせて 20 秒。失敗は `container_log_remove.<code>`（`failed_precondition`・`timeout`・`invalid_argument`・
//!   `internal`・`other`）の操作名でも計上する（REPAIR-4）。待ち切れなかった失敗（`FailedPrecondition`）は警告行に `reason: sink_open_after_wait` を足して他の失敗と区別する（#2760。terminate を設定する経路が無く、待ちを伸ばさない判断は `docs/design/container-log-removal-wait.md`）。待ちを超えて残ったログは、plugin の起動時の走査（[`sweep_leftover_container_logs`]）と同じ ID の `create` の前の回収（`reclaim_before_create`）で消える（生きている sink・状態がある ID・帰属できない名前は残り、手動で消す。docs/setup/container-log-recovery.md）。
//!   core の `delete` の成功後には起動オプション文書（`<root>/@container-options/<id>`）の残骸も、記録の無い ID に限りロックの下で期限つきに消す（失敗は `container_options_remove` の Failure と `target: container_options` の警告行。`create` の前にも同じ掃除をする。SUP-12・#2760）
//! - bundle 供給: 本番は `CriPluginBackends::production_bundle_provider`（unix のみ）（pull 済みイメージの再展開と
//!   ContainerConfig → config.json 変換。#2433）。`ImageService` は同じ UDS でサーブし（`CriPluginBackends::image_service`。#2592）、
//!   `PullImage` が登録したタグ・digest・image ID を同じ在庫から解決する（未知の参照は `NOT_FOUND`）。
//!   在庫は cri の `InMemoryImageStore`（プロセス内だけ）で、plugin-cri の再起動でタグの対応は失われる
//!   （ディスク上のキャッシュは残るので `PullImage` をやり直せば blob を再取得せずに戻る）。oci の永続の在庫
//!   〔TASK-183・OCI-7・#2315・#2380〕への配線は別途（REPAIR-3）。展開の所有者写像は既定の `Keep` + `Strip` のまま
//!   （#2241・#2315・#482 が前提）。展開の計装（`OciOpRecorder`）は未配線で何も記録しない。
//!   起動時の残り pull の回収 GC（`ImageStore::recover_stale_pulls`）は `CriPluginBackends::recover_stale_image_pulls` で配線済み（#2819）。
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
    AttachRequest, AttachResponse, CleanupOutcome, CleanupTarget, ContainerId, ContainerRuntime,
    ContainerStatus, CreateNetnsRequest, CreateNetworkRequest, CreateRequest, DeleteNetworkRequest,
    DeleteNetworkResponse, DeleteRequest, DeleteResponse, DetachRequest, DetachResponse, ErrorCode,
    GetStateRequest, KillRequest, NetnsStatus, NetworkPlugin, NetworkStatus, PortMapping,
    PublishPortRequest, StartRequest, StateRequest, StateStore, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::{
    BundleProvider, BundleRequest, PreparedBundle, RuntimeAdapter,
};
use fandhe_container_cri::error::CriError;
#[cfg(unix)]
use fandhe_container_cri::image_pull::PullConfig;
#[cfg(unix)]
use fandhe_container_cri::image_service::CriImageService;
use fandhe_container_cri::image_service::{ImageStore, InMemoryImageStore};
use fandhe_container_cri::instrument::{CriOpOutcome, CriOpRecorder, CriOpSample};
use fandhe_container_cri::runtime_service::CriRuntimeService;
#[cfg(unix)]
use fandhe_container_oci::registry::RegistryClientConfig;
use fandhe_container_supervisor::cgroup_remover::production_cgroup_remover;
use fandhe_container_supervisor::logs::{
    CONTAINER_LOG_LOCK_WAIT, CONTAINER_LOG_REMOVE_TIMEOUT, RemovedLogs, StaleLogReclaim,
    container_log_removal_reason, reclaim_stale_container_logs,
    remove_container_logs_guarded_bounded_waiting,
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
    /// `ImageService`（`PullImage` の登録先）と本番の `BundleProvider`（`CreateContainer` のタグ解決）が共有する在庫。
    /// プロセス内だけで永続化しない（再起動でタグの対応は失われる。モジュール doc の REPAIR-3）。
    images: Arc<dyn ImageStore>,
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
            images: Arc::new(InMemoryImageStore::new()),
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
        // 状態ルートの作成・検証・初期化（`FileStateStore::open`）を先に済ませる。`ReclaimStore::open` はルートが
        // 既にあることを前提にし、先に `.cri` を作ると新規ストアの判定を壊すため（NET-1・#2604）。
        let state: Arc<dyn StateStore> = Arc::new(FileStateStore::open(root)?);
        // netns の pin の置き場は状態ルート配下の固定の場所（要求の入力からは受けない。TASK-114.4）。
        // 先頭が `.` のため、英数字始まりの `ContainerId` の状態ディレクトリと衝突しない。
        #[cfg(target_os = "linux")]
        let network: Arc<dyn NetworkPlugin> = Arc::new(NetsetupNetwork::with_reclaim_store(
            LinuxNetsetup::with_recorder(
                state_root.join(".netns"),
                Arc::new(CoreNetRecorder(Arc::clone(&recorder))),
            ),
            // 作成失敗の回収待ちの記録は状態ルート配下の固定の場所に残し、再起動後に読み込む（NET-1・#2604）。
            crate::netsetup::ReclaimStore::open(&state_root)?,
            Some(Arc::clone(&recorder)),
        )?);
        #[cfg(not(target_os = "linux"))]
        let network: Arc<dyn NetworkPlugin> = Arc::new(UnimplementedNetwork);
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
            Some(root) => bundle_provider_with(root, Some(Arc::clone(&self.images))),
            None => Err(CriError::failed_precondition(
                "state root is not configured",
            )),
        }
    }

    /// 本番の `ImageService`（`PullImage`・`ImageStatus`・`ListImages`・`RemoveImage`・`ImageFsInfo`）を作る（CRI-3・CRI-4・PLUG-1。#2592）。
    ///
    /// `production_bundle_provider` と同じ在庫（[`Self::images`]）と、同じ `PullConfig`（キャッシュは
    /// `<state_root>/.cri/images`）を共有するため、`PullImage` で登録したタグを `CreateContainer` が解決でき、
    /// pull と create の展開設定が食い違わない。`production()` で組んだときだけ使え、注入で組んだときは
    /// `FAILED_PRECONDITION`。レジストリクライアント（OS のルート証明書の読み込み）を作れなければエラーを返す。
    /// 呼び出しは `production_bundle_provider` の後にする（置き場の作成と検証を先に済ませるため）。
    #[cfg(unix)]
    pub fn image_service(&self) -> Result<CriImageService, CriError> {
        use fandhe_container_cri::image_pull::{OciImagePuller, OciRegistryClient};
        let Some(root) = &self.state_root else {
            return Err(CriError::failed_precondition(
                "state root is not configured",
            ));
        };
        let pull = production_pull_config(root)?;
        let client = OciRegistryClient::new(&production_registry_config())
            .map_err(|_| CriError::failed_precondition("failed to prepare the registry client"))?;
        Ok(CriImageService::with_store_and_recorder(
            Arc::clone(&self.images),
            Arc::new(CoreCriRecorder(Arc::clone(&self.recorder))),
        )
        .with_puller(Arc::new(OciImagePuller::new(client, pull))))
    }

    /// 起動時に 1 回、`<state_root>/.cri/images` に残った pull のステージングとリースを回収する（OCI-7・OCI-1。#2819）。
    ///
    /// `image_service` の成功後、RPC を受け付ける前に `main.rs` の `serve` が呼ぶ。期限は [`STARTUP_PULL_RECOVERY_BUDGET`]。
    /// 結果の扱い（どれで起動を止めるか）は `main.rs` と `docs/design/pull-inventory-wiring.md`。注入で組んだ場合は
    /// `Failed("FAILED_PRECONDITION")`。
    #[cfg(unix)]
    pub fn recover_stale_image_pulls(&self, budget: Duration) -> StartupPullRecovery {
        let Some(root) = &self.state_root else {
            return StartupPullRecovery::Failed("FAILED_PRECONDITION");
        };
        let images_root = root.join(IMAGES_DIR);
        let recorder = Arc::clone(&self.recorder);
        run_startup_pull_recovery(
            move || recover_stale_image_pulls_in(&images_root, &recorder),
            budget,
        )
    }

    /// `ImageService` と bundle 供給が共有する在庫。
    pub fn images(&self) -> &Arc<dyn ImageStore> {
        &self.images
    }

    /// `ContainerRuntime` の実装。
    pub fn runtime(&self) -> &Arc<dyn ContainerRuntime> {
        &self.runtime
    }

    /// `StateStore` の実装。
    pub fn state(&self) -> &Arc<dyn StateStore> {
        &self.state
    }

    /// `NetworkPlugin` の実装。写像は [`crate::pod_network`]（`NetsetupPodNetwork` が cri の `PodNetworkProvider` を実装）。
    /// 本番の RPC からはまだ呼ばれない: core の network namespace の join が入るまで `with_pod_network` を差さない
    /// （差すと RunPodSandbox が bridge・netns・veth を作るのに start が `UNIMPLEMENTED` で失敗する。#2675・REPAIR-3）。
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
///
/// `create` の最悪（#2760）: ログ回収 5 秒 + 起動オプション文書の掃除 10 秒 + 状態ロック 5 秒 + 監査記録 2 回（22.9 秒）= 42.9 秒。
/// running への force `delete` の最悪: stop 17 秒 + supervisor ログ 5 秒 + コンテナログ 15 秒 + 起動オプション文書 10 秒 = 47 秒。
/// どちらもこの値に収まる（`tests/lifecycle_supervisor.rs` の `repair5_*_worst_case_fits_runtime_timeout` で照合する）。
/// bundle の用意（`BundleProvider::prepare`）と core の create のファイル I/O は 2 段で上限づける（#2821）。RPC の応答は
/// この値で打ち切られ（DEADLINE_EXCEEDED）、worker の残存は [`PLUGIN_ROOTFS_DEADLINE`] + 分割できない区間 1 つ分 + 42.9 秒で有限になる
/// （内訳は `docs/design/container-log-removal-wait.md`、照合は `repair5_create_worker_residual_is_bounded`）。
pub const PLUGIN_RUNTIME_TIMEOUT: Duration = Duration::from_millis(60_900);

/// イメージ由来 rootfs の用意（blob の検証と展開）の期限（REPAIR-5・#2821）。
///
/// `CreateContainer` の worker が `prepare` に使える時間の上限で、blob 1 本ごとと展開の前後で確かめる。RPC の応答は
/// [`PLUGIN_RUNTIME_TIMEOUT`] で先に打ち切られるが、worker は打ち切れず、記録と件数枠はその終了まで残る。
/// 値は既定（600 秒）のまま。変更はオーナー判断（本 issue では変えない）。
pub const PLUGIN_ROOTFS_DEADLINE: Duration = fandhe_container_cri::bundle::DEFAULT_ROOTFS_DEADLINE;

/// 本番の rootfs 展開設定（`ImageService` の pull と同じ値 + [`PLUGIN_ROOTFS_DEADLINE`] の明示）。
#[cfg(unix)]
fn production_extract_config(
    state_root: &std::path::Path,
) -> Result<fandhe_container_cri::bundle::ImageExtractConfig, CriError> {
    let pull = production_pull_config(state_root)?;
    let mut cfg = fandhe_container_cri::bundle::ImageExtractConfig::from_pull_config(&pull);
    cfg.deadline = PLUGIN_ROOTFS_DEADLINE;
    Ok(cfg)
}

/// 起動時の残りログの走査の全体の期限（#2760・REPAIR-5。サーブの開始は待たせず、別スレッドで走る）。
pub const STARTUP_LOG_SWEEP_BUDGET: Duration = Duration::from_secs(30);

/// plugin の起動時に 1 回、状態の記録が無い ID の残りコンテナログを回収する（#2760・CRI-2・SUP-7・REPAIR-4）。
///
/// CRI は ID を使い回さないため、delete の待ちを超えて残ったログは同じ ID の `create` では回収されない。ここで
/// `@container-logs` を走査し、状態ストアに記録が無く、sink も生きていない ID のログだけを消す
/// （`fandhe_container_supervisor::logs::sweep_stale_container_logs`。生きている sink・記録のある ID・帰属できない名前は残す。
/// 読み取りに失敗した ID も消さない）。状態ルートを持たないストアでは `None`。消せた ID ごとに記録器の
/// `container_log_reclaim` へ Success を計上する。呼び出し元は `main.rs` の `serve`（ブロッキングスレッド）。
/// 走査はこの時点で存在する残りだけを対象にし、稼働中に発生した残りは次の起動まで残る（設計: `docs/design/container-log-removal-wait.md`）。
pub fn sweep_leftover_container_logs(
    store: &Arc<dyn StateStore>,
    recorder: &OpRecorder,
    budget: Duration,
) -> Option<fandhe_container_supervisor::logs::SweepReport> {
    let root = store.host_state_root()?;
    let started = Instant::now();
    let guard_store = Arc::clone(store);
    let report = fandhe_container_supervisor::logs::sweep_stale_container_logs(
        root,
        Arc::new(move |id| CoreLifecycleRuntime::id_is_absent(&guard_store, id)),
        budget,
    );
    if report.reclaimed_ids > 0
        && let Ok(name) = OpName::new("container_log_reclaim")
    {
        let each = started.elapsed() / u32::try_from(report.reclaimed_ids).unwrap_or(u32::MAX);
        for _ in 0..report.reclaimed_ids {
            let _ = recorder.record(&name, OpOutcome::Success, each);
        }
    }
    Some(report)
}

/// 起動時の走査の結果の構造化ログ 1 行（`event: container_log_sweep`。#2760・REPAIR-4）。件数だけで、パス・ID は含めない。
pub fn sweep_summary_line(r: &fandhe_container_supervisor::logs::SweepReport) -> String {
    format!(
        "{{\"level\":\"info\",\"event\":\"container_log_sweep\",\"scanned\":{},\"reclaimed_ids\":{},\"removed_files\":{},\"skipped_live\":{},\"skipped_present\":{},\"skipped_undecodable\":{},\"failed\":{},\"timed_out\":{}}}",
        r.scanned,
        r.reclaimed_ids,
        r.removed_files,
        r.skipped_live,
        r.skipped_present,
        r.skipped_undecodable,
        r.failed,
        r.timed_out
    )
}

/// 起動時の pull 回収 GC の全体の期限（#2819・REPAIR-5）。超えたら起動しない（取り残した worker が `@lock` を握ったまま受け付けないため）。
#[cfg(unix)]
pub const STARTUP_PULL_RECOVERY_BUDGET: Duration = Duration::from_secs(60);

/// 起動時の pull 回収 GC の結果の件数（パス・pull ID は含めない。REPAIR-4）。
#[cfg(unix)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PullRecoveryCounts {
    /// ステージングを消した pull の数。
    pub reclaimed: usize,
    /// 解放したリースの合計。
    pub released_leases: usize,
    /// 生きている pull のため残した数。
    pub kept_live: usize,
    /// 不在を確認できず残した数。
    pub kept_undetermined: usize,
    /// 削除に失敗した数（1 以上なら warn）。
    pub failed: usize,
    /// 触らなかったエントリ数。
    pub foreign_entries: usize,
}

#[cfg(unix)]
impl PullRecoveryCounts {
    /// oci の回収結果から件数だけを写す（リースの和は飽和加算）。
    pub fn from_recovery(r: &fandhe_container_oci::image_management::StalePullRecovery) -> Self {
        Self {
            reclaimed: r.reclaimed().len(),
            released_leases: r
                .released_leases()
                .iter()
                .fold(0usize, |acc, (_, n)| acc.saturating_add(*n)),
            kept_live: r.kept_live().len(),
            kept_undetermined: r.kept_undetermined().len(),
            failed: r.failed().len(),
            foreign_entries: r.foreign_entries(),
        }
    }

    /// 構造化ログ 1 行（`event: image_pull_recovery`）。`failed` が 1 以上なら `warn`。
    pub fn summary_line(&self) -> String {
        format!(
            "{{\"level\":\"{}\",\"event\":\"image_pull_recovery\",\"reclaimed\":{},\"released_leases\":{},\"kept_live\":{},\"kept_undetermined\":{},\"failed\":{},\"foreign_entries\":{}}}",
            if self.failed > 0 { "warn" } else { "info" },
            self.reclaimed,
            self.released_leases,
            self.kept_live,
            self.kept_undetermined,
            self.failed,
            self.foreign_entries
        )
    }
}

/// 起動時の結果の構造化ログ 1 行（`event: image_pull_recovery`。#2819・REPAIR-4）。件数だけで、パス・ID は含めない。
#[cfg(unix)]
pub fn pull_recovery_summary_line(
    r: &fandhe_container_oci::image_management::StalePullRecovery,
) -> String {
    PullRecoveryCounts::from_recovery(r).summary_line()
}

/// 起動時の pull 回収 GC の結末（#2819。`main.rs` の `serve` が分岐する）。
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupPullRecovery {
    /// 回収を終えた（一部失敗は `failed` 件数に出る。起動は続ける）。
    Completed(PullRecoveryCounts),
    /// 開けない・排他を取れない等（エラーコード文字列）。起動しない。
    Failed(&'static str),
    /// 期限内に終わらなかった。起動しない。
    TimedOut,
    /// worker を作れなかった。起動しない。
    SpawnFailed,
}

/// `images_root` の在庫を開いて `recover_stale_pulls` を 1 回呼び、`image_pull_recovery` を記録器へ計上する
/// （OCI-7・OCI-1・REPAIR-4。#2819）。生存判定は `@pull.lock` の OS ロックで、生きている pull は回収しない。
/// root は呼び出し側が状態ルート配下の固定位置を渡す（外部入力から受けない）。
#[cfg(unix)]
pub fn recover_stale_image_pulls_in(
    images_root: &std::path::Path,
    recorder: &OpRecorder,
) -> Result<
    fandhe_container_oci::image_management::StalePullRecovery,
    fandhe_container_oci::error::OciError,
> {
    let started = Instant::now();
    let r = fandhe_container_oci::image_management::ImageStore::open(images_root)
        .and_then(|store| store.recover_stale_pulls());
    if let Ok(name) = OpName::new("image_pull_recovery") {
        let ok = matches!(&r, Ok(v) if v.failed().is_empty());
        let outcome = if ok {
            OpOutcome::Success
        } else {
            OpOutcome::Failure
        };
        let _ = recorder.record(&name, outcome, started.elapsed());
    }
    r
}

/// `f` を別スレッドで走らせ、`budget` 内の結果を待つ（REPAIR-5）。超えたら `TimedOut`（worker は取り残すため、
/// 呼び出し側は起動を中止してプロセスを終える。ロックは終了時に OS が解放する）。
#[cfg(unix)]
pub fn run_startup_pull_recovery<F>(f: F, budget: Duration) -> StartupPullRecovery
where
    F: FnOnce() -> Result<
            fandhe_container_oci::image_management::StalePullRecovery,
            fandhe_container_oci::error::OciError,
        > + Send
        + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let spawned = std::thread::Builder::new()
        .name("pull-recovery".to_owned())
        .spawn(move || {
            let _ = tx.send(f());
        });
    if spawned.is_err() {
        return StartupPullRecovery::SpawnFailed;
    }
    match rx.recv_timeout(budget) {
        Ok(Ok(r)) => StartupPullRecovery::Completed(PullRecoveryCounts::from_recovery(&r)),
        Ok(Err(e)) => StartupPullRecovery::Failed(e.code().as_str()),
        Err(_) => StartupPullRecovery::TimedOut,
    }
}

/// gRPC サーバーが 1 リクエストを待つ上限（REPAIR-5・#2592）。`GrpcServerConfig` の既定（10 秒）では `PullImage`
/// （ネットワーク越し）も `StartContainer`（[`PLUGIN_RUNTIME_TIMEOUT`]）も途中で切れるため、`GRPC_TIMEOUT_MAX`（600 秒）以下で
/// 引き上げる。クライアントが付ける `grpc-timeout` はこれより短ければそちらが効く。
pub const PLUGIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(600);

/// `PullImage` 全体の期限（[`PLUGIN_REQUEST_TIMEOUT`] より短くする）。gRPC 側が先に切れても、裏の `spawn_blocking` の取り込みが
/// 有界時間で終わるようにするため（oci の既定は pull 1 時間・blob 30 分で、request timeout より長い）。
pub const PLUGIN_PULL_DEADLINE: Duration = Duration::from_secs(540);

/// 本番の `PullConfig`（キャッシュは `<state_root>/.cri/images`。pull と create の展開設定の単一の出所）。
///
/// 所有者・特殊ビットは既定の `Keep` + `Strip` のまま（`ChownMapped` 等の本番値は #2241・#2315・#482 が前提。REPAIR-3）。
#[cfg(unix)]
fn production_pull_config(state_root: &std::path::Path) -> Result<PullConfig, CriError> {
    let mut pull = PullConfig::new(state_root.join(IMAGES_DIR))?;
    pull.pull_deadline = PLUGIN_PULL_DEADLINE;
    Ok(pull)
}

/// 本番のレジストリクライアント設定。blob 1 本の期限を [`PLUGIN_PULL_DEADLINE`] に揃える。
#[cfg(unix)]
fn production_registry_config() -> RegistryClientConfig {
    RegistryClientConfig {
        blob_request_timeout: PLUGIN_PULL_DEADLINE,
        ..RegistryClientConfig::default()
    }
}

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
    /// コンテナログ削除で sink の閉鎖を待つ上限（`CONTAINER_LOG_LOCK_WAIT` 以下。#2634・REPAIR-5）。
    container_log_lock_wait: Duration,
    /// `delete` の後始末で残した資源の構造化ログ 1 行の出力先（本番は stderr の `LineSink`。試験で差し替える。#2633）。
    cleanup_warn: Arc<dyn Fn(String) + Send + Sync>,
    #[cfg(target_os = "linux")]
    supervised: SupervisedLifecycle,
}

/// `delete` の後始末で残した資源 1 件の構造化ログ 1 行（末尾の改行は付けない。`LineSink` が書き込み時に付ける）を作る（OCI-7・CRI-2・SUP-7・REPAIR-4）。
///
/// 値は `ContainerId`（検証済みの文字種）・`CleanupTarget::as_str`・`ErrorCode::as_str` の固定語彙だけで組み、
/// パス・errno・外部入力の文字列を含めない（ERR-1・ERR-2）。
fn cleanup_warning_line(id: &ContainerId, target: CleanupTarget, code: ErrorCode) -> String {
    // コンテナログが「待ちを使い切っても sink が閉じなかった」ときだけ `reason` を足す（他の失敗と見分ける。#2760・REPAIR-4）。
    let reason = match target {
        CleanupTarget::ContainerLog => container_log_removal_reason(code),
        _ => None,
    }
    .map(|r| format!(",\"reason\":\"{r}\""))
    .unwrap_or_default();
    format!(
        "{{\"level\":\"warn\",\"event\":\"container_delete_cleanup\",\"id\":\"{}\",\"target\":\"{}\",\"code\":\"{}\"{reason},\"message\":\"cleanup after delete left resources behind\"}}",
        id.as_str(),
        target.as_str(),
        code.as_str()
    )
}

/// `delete` の後の起動オプション文書の掃除に失敗した旨の構造化ログ 1 行（#2760・SUP-12・REPAIR-4）。
///
/// `CleanupTarget`（plugin 境界の型）には語彙を足さないため、`target` はこの module の固定文字列 `container_options` を使う。
/// 値は `ContainerId`・`ErrorCode::as_str` の固定語彙だけで、パス・errno・文書の中身（env の値）を含めない（ERR-1・ERR-2）。
fn options_cleanup_warning_line(id: &ContainerId, code: ErrorCode) -> String {
    format!(
        "{{\"level\":\"warn\",\"event\":\"container_delete_cleanup\",\"id\":\"{}\",\"target\":\"container_options\",\"code\":\"{}\",\"message\":\"cleanup after delete left resources behind\"}}",
        id.as_str(),
        code.as_str()
    )
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
            container_log_lock_wait: CONTAINER_LOG_LOCK_WAIT,
            cleanup_warn: Arc::new(|line| {
                let _ = crate::telemetry::stderr_sink().submit(line);
            }),
            #[cfg(target_os = "linux")]
            supervised: SupervisedLifecycle::production(),
        }
    }

    /// `delete` の後始末で残した資源の構造化ログの出力先を差し替える（試験用。本番の既定は stderr の `LineSink`。#2633）。
    #[must_use]
    pub fn with_cleanup_warning_sink(mut self, sink: Arc<dyn Fn(String) + Send + Sync>) -> Self {
        self.cleanup_warn = sink;
        self
    }

    /// cgroup remover を差し替える（結合試験と別実装。本番の既定は supervisor crate の遅延検出つき remover）。
    #[must_use]
    pub fn with_cgroup_remover(mut self, cgroups: Arc<dyn ContainerCgroupRemover>) -> Self {
        self.cgroups = cgroups;
        self
    }

    /// コンテナログ削除で sink の閉鎖を待つ上限を変える（試験用。`CONTAINER_LOG_LOCK_WAIT` を超える値は切り詰める。
    /// `PLUGIN_RUNTIME_TIMEOUT` に収まる予算の不変条件を壊さないため。#2634・REPAIR-5）。
    #[must_use]
    pub fn with_container_log_lock_wait(mut self, wait: Duration) -> Self {
        self.container_log_lock_wait = wait.min(CONTAINER_LOG_LOCK_WAIT);
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
    fn remove_supervisor_log(&self, id: &ContainerId) -> CleanupOutcome {
        let Some(root) = self.store.host_state_root() else {
            return CleanupOutcome::NotApplicable;
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
        // `Finished` は期限内に作業を終えた best effort（個々の失敗は削除関数が握る）。
        match outcome {
            LogRemoval::Finished => CleanupOutcome::Removed,
            LogRemoval::TimedOut => CleanupOutcome::Kept {
                code: ErrorCode::Timeout,
            },
        }
    }

    /// コンテナログ（現在ログ・全世代・ロック）を消す。core の `delete` が成功した後にだけ呼ぶ（失敗した delete で
    /// 稼働中のコンテナのログを消さないため。#2593・SUP-7・CRI-2・CLI-1）。
    ///
    /// CLI の `delete` と同じ契約に、sink の閉鎖待ちを足したもの。`FailedPrecondition` のあいだ最大
    /// `container_log_lock_wait`（既定 10 秒）まで 50ms 間隔で試し直し、1 回の試行の期限は 5 秒（同時実行枠は
    /// supervisor ログの削除と共有し、試行の間だけ占める）。running への force 削除では `Stopped` の記録後に supervisor が
    /// drain してから sink を閉じるため、この待ちで窓を覆う（#2634）。stderr へは何も書かない。ロック取得後に状態ストアで ID が `NotFound` のままであることを確かめ、
    /// 読み取りに失敗したら fail-closed で削除を見送る（同じ ID で再作成されたインスタンスのログを消さない）。
    /// 状態ルートが無い（ホスト上のパスを持たない）ストアでは何もせず `Ok`。
    ///
    /// # Errors
    /// supervisor の `TraitError` をそのまま返す。`FailedPrecondition`（待ちの期限まで同じ ID の sink が閉じなかった）・
    /// `Timeout`（期限切れか枠の満杯）・`InvalidArgument`（名前空間の不正）・`Internal`（ディレクトリ検査の失敗）。
    pub fn remove_container_log(&self, id: &ContainerId) -> Result<RemovedLogs, TraitError> {
        let Some(root) = self.store.host_state_root() else {
            return Ok(RemovedLogs::default());
        };
        let store = Arc::clone(&self.store);
        let guard_id = id.clone();
        remove_container_logs_guarded_bounded_waiting(
            root,
            id,
            self.container_log_lock_wait,
            CONTAINER_LOG_REMOVE_TIMEOUT,
            Arc::new(move || {
                matches!(
                    store.get(&GetStateRequest::new(guard_id.clone())),
                    Err(e) if e.code() == ErrorCode::NotFound
                )
            }),
        )
    }

    /// [`Self::remove_container_log`] の結果を記録器の `container_log_remove` に計上する（戻り値には影響させない）。
    fn record_container_log_removal(&self, id: &ContainerId) -> CleanupOutcome {
        if self.store.host_state_root().is_none() {
            return CleanupOutcome::NotApplicable;
        }
        let started = Instant::now();
        let removed = self.remove_container_log(id);
        let elapsed = started.elapsed();
        let result = match &removed {
            Ok(_) => OpOutcome::Success,
            Err(_) => OpOutcome::Failure,
        };
        if let Ok(name) = OpName::new("container_log_remove") {
            let _ = self.recorder.record(&name, result, elapsed);
        }
        // エラーコード別の内訳（固定語彙 5 種。失敗したときだけ名前を作る。REPAIR-4・#2634）。
        if let Err(e) = &removed
            && let Ok(name) = OpName::new(container_log_remove_failure_op(e.code()))
        {
            let _ = self.recorder.record(&name, OpOutcome::Failure, elapsed);
        }
        match removed {
            Ok(_) => CleanupOutcome::Removed,
            Err(e) => CleanupOutcome::Kept { code: e.code() },
        }
    }
}

impl CoreLifecycleRuntime {
    /// 状態ストアに `id` の記録が無い（`NotFound`）ときだけ `true`。読み取りに失敗したら `false`（fail-closed）。
    ///
    /// ログ・起動オプション文書の回収の guard（ロック保持中に評価される）。記録のある ID の資源は消さない。
    fn id_is_absent(store: &Arc<dyn StateStore>, id: &ContainerId) -> bool {
        matches!(
            store.get(&GetStateRequest::new(id.clone())),
            Err(e) if e.code() == ErrorCode::NotFound
        )
    }

    /// core の `create` の前に、同じ ID の前のインスタンスが残したコンテナログを回収し、起動オプション文書の残骸を掃除する
    /// （CLI の `create` と同じ契約。#2760・CRI-2・SUP-7・SUP-12・REPAIR-4・REPAIR-5）。
    ///
    /// CRI は ID を使い回さないため通常は何も無いが、`CreateContainer` が失敗した後の再試行や、手動で ID を指定した再作成で
    /// 残りが新しい sink に混ざるのを防ぐ。待たずに 1 回だけ試し（ログ 5 秒・文書 10 秒が上限）、生きている sink・状態が既にある
    /// ID には触れない。ログ回収が期限切れなら、作業スレッドが残り得るため core を呼ばずに `Timeout` で失敗させる
    /// （後続の監査記録は単一スレッド前提の fork を要する。SEC-4）。それ以外の失敗は best effort で create を続ける。
    /// 状態ルートを持たないストアでは何もしない。
    ///
    /// # Errors
    /// ログ回収が期限切れのとき `Timeout`。
    fn reclaim_before_create(&self, id: &ContainerId) -> Result<(), TraitError> {
        let Some(root) = self.store.host_state_root() else {
            return Ok(());
        };
        let started = Instant::now();
        let store = Arc::clone(&self.store);
        let guard_id = id.clone();
        let reclaim =
            reclaim_stale_container_logs(root, id, move || Self::id_is_absent(&store, &guard_id));
        let result = reclaim_timeout_result(reclaim);
        let outcome = match reclaim {
            StaleLogReclaim::Removed(_) => Some(OpOutcome::Success),
            StaleLogReclaim::Nothing => None,
            StaleLogReclaim::Failed(_) | StaleLogReclaim::TimedOut => Some(OpOutcome::Failure),
        };
        if let Some(outcome) = outcome
            && let Ok(name) = OpName::new("container_log_reclaim")
        {
            let _ = self.recorder.record(&name, outcome, started.elapsed());
        }
        result?;
        // 起動オプション文書の残骸（best effort。失敗しても create は続ける。文書は世代の照合で採用されない）。
        let _ = self.remove_stale_options(id);
        Ok(())
    }

    /// 状態の記録が無い ID の起動オプション文書を、ID 単位のロックの下で期限つきに消す（#2760・SUP-12・REPAIR-5）。
    ///
    /// 同じ ID の記録がある（作り直された新しいインスタンスかもしれない）ときは消さない。文書が無ければロックも作らない。
    /// 失敗は記録器の `container_options_remove` の Failure として計上する。Linux 以外は文書を書く経路が無く
    /// （`Unimplemented`）、対象外として `Ok` を返し何も計上しない。戻り値は呼び出し元が警告行を出すかの判断に使う。
    fn remove_stale_options(&self, id: &ContainerId) -> Result<(), ErrorCode> {
        use fandhe_container_supervisor::container_options::store as options_store;
        let Some(root) = self.store.host_state_root() else {
            return Ok(());
        };
        let started = Instant::now();
        let store = Arc::clone(&self.store);
        let guard_id = id.clone();
        let removed = options_store::remove_stale_bounded(
            root,
            id,
            move || Self::id_is_absent(&store, &guard_id),
            options_store::OPTIONS_LOCK_WAIT,
            options_store::OPTIONS_REMOVE_TIMEOUT,
        );
        match removed {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ErrorCode::Unimplemented => Ok(()),
            Err(e) => {
                if let Ok(name) = OpName::new("container_options_remove") {
                    let _ = self
                        .recorder
                        .record(&name, OpOutcome::Failure, started.elapsed());
                }
                Err(e.code())
            }
        }
    }
}

/// create 前のログ回収の結果を、core を呼ぶかの判断へ写す（期限切れだけが失敗。#2760・SEC-4・REPAIR-5）。
fn reclaim_timeout_result(reclaim: StaleLogReclaim) -> Result<(), TraitError> {
    match reclaim {
        StaleLogReclaim::TimedOut => Err(TraitError::new(
            ErrorCode::Timeout,
            "stale container log reclaim did not finish within the deadline",
        )),
        _ => Ok(()),
    }
}

/// コンテナログ削除の失敗をコード別に計上する操作名（固定語彙 5 種。ID・パス・errno は入れない。ERR-1・REPAIR-4・#2634）。
///
/// 記録器の名前の種類には上限（`MAX_TRACKED_OPS`）があるため、語彙を絞り、失敗したときだけ作る。
fn container_log_remove_failure_op(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::FailedPrecondition => "container_log_remove.failed_precondition",
        ErrorCode::Timeout => "container_log_remove.timeout",
        ErrorCode::InvalidArgument => "container_log_remove.invalid_argument",
        ErrorCode::Internal => "container_log_remove.internal",
        _ => "container_log_remove.other",
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
        self.reclaim_before_create(req.id())?;
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
        self.supervised
            .start(&*self.store, req.id(), req.log_path())
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
        let supervisor_log = self.remove_supervisor_log(req.id());
        let container_log = self.record_container_log_removal(req.id());
        // 起動オプション文書の残骸（記録の無くなった ID の分。失敗は応答に載せず、計上と構造化ログで知らせる。#2760）。
        if let Err(code) = self.remove_stale_options(req.id()) {
            (self.cleanup_warn)(options_cleanup_warning_line(req.id(), code));
        }
        let response = response
            .with_supervisor_log(supervisor_log)
            .with_container_log(container_log);
        // 残した資源は `Err` にせず、応答と構造化ログで知らせる（再試行は core の `NOT_FOUND` で止まるため。#2633）。
        for (target, code) in response.kept() {
            (self.cleanup_warn)(cleanup_warning_line(req.id(), target, code));
        }
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
///
/// 展開設定（所有者・特殊ビット）は既定（`Keep` + `Strip`）のままで、`ChownMapped` 等の
/// 本番の値は渡さない。配線の前提は #2241・#2315・#482（#2534・SEC-5。`fandhe_container_cri::image_pull` の
/// 「未実装範囲」を参照）。
#[cfg(unix)]
pub fn bundle_provider_in(
    state_root: &std::path::Path,
) -> Result<Arc<dyn BundleProvider>, CriError> {
    bundle_provider_with(state_root, None)
}

/// [`bundle_provider_in`] に、タグ・digest 参照を image ID へ解決する在庫 `store` を足した形（CRI-2・CRI-3。#2592）。
///
/// `store` は `ImageService` と同じものを渡す。`None` なら image ID（`sha256:<hex>`）だけを受ける。展開設定は
/// `production_pull_config`（`ImageService` の pull と同じ値）から `ImageExtractConfig::from_pull_config` で作る。
#[cfg(unix)]
pub fn bundle_provider_with(
    state_root: &std::path::Path,
    store: Option<Arc<dyn ImageStore>>,
) -> Result<Arc<dyn BundleProvider>, CriError> {
    use fandhe_container_cri::bundle::{ImageRootfsSource, SpecBundleProvider};
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
    let [bundles, _images] = <[PathBuf; 2]>::try_from(dirs).map_err(|_| fail())?;
    // SpecBundleProvider は root の正規化済みパスを要求する（途中の symlink を拒否する）。
    let bundles = std::fs::canonicalize(bundles).map_err(|_| fail())?;
    let mut source = ImageRootfsSource::new(production_extract_config(state_root)?);
    if let Some(store) = store {
        source = source.with_image_store(store);
    }
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
    fn prepare(&self, _req: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
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

    /// REPAIR-5・#2821: 本番の rootfs 展開設定は `PLUGIN_ROOTFS_DEADLINE`（600 秒）を明示して使う。
    #[cfg(unix)]
    #[test]
    fn repair5_production_extract_config_uses_plugin_rootfs_deadline() {
        let dir = std::env::temp_dir().join(format!("fcpc-extract-cfg-{}", std::process::id()));
        let cfg = production_extract_config(&dir).expect("config");
        assert_eq!(cfg.deadline, PLUGIN_ROOTFS_DEADLINE);
        assert_eq!(cfg.deadline, Duration::from_secs(600));
    }

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

    /// #2760・SEC-4: create 前のログ回収は期限切れのときだけ create を失敗（`Timeout`）させ、それ以外は続ける。
    #[test]
    fn repair5_cri2_reclaim_timeout_fails_create_only_on_timeout() {
        let e = reclaim_timeout_result(StaleLogReclaim::TimedOut).expect_err("timeout");
        assert_eq!(e.code(), ErrorCode::Timeout);
        for ok in [
            StaleLogReclaim::Removed(2),
            StaleLogReclaim::Nothing,
            StaleLogReclaim::Failed(ErrorCode::FailedPrecondition),
            // 作業スレッドの枠が満杯（何も実行していない）。create を恒久的に失敗させない（#2760）。
            StaleLogReclaim::Failed(ErrorCode::ResourceExhausted),
        ] {
            assert!(reclaim_timeout_result(ok).is_ok());
        }
    }

    /// #2760・REPAIR-4: 警告行の `reason` は、コンテナログが待ち切れなかった失敗にだけ付く。options 用の行は固定語彙。
    #[test]
    fn repair4_cri2_cleanup_warning_reason_only_for_sink_open() {
        let id = cid("c1");
        assert_eq!(
            cleanup_warning_line(
                &id,
                CleanupTarget::ContainerLog,
                ErrorCode::FailedPrecondition
            ),
            "{\"level\":\"warn\",\"event\":\"container_delete_cleanup\",\"id\":\"c1\",\"target\":\"container_log\",\"code\":\"FAILED_PRECONDITION\",\"reason\":\"sink_open_after_wait\",\"message\":\"cleanup after delete left resources behind\"}"
        );
        assert!(
            !cleanup_warning_line(&id, CleanupTarget::ContainerLog, ErrorCode::Timeout)
                .contains("reason")
        );
        assert!(
            !cleanup_warning_line(
                &id,
                CleanupTarget::SupervisorLog,
                ErrorCode::FailedPrecondition
            )
            .contains("reason")
        );
        assert_eq!(
            options_cleanup_warning_line(&id, ErrorCode::Timeout),
            "{\"level\":\"warn\",\"event\":\"container_delete_cleanup\",\"id\":\"c1\",\"target\":\"container_options\",\"code\":\"TIMEOUT\",\"message\":\"cleanup after delete left resources behind\"}"
        );
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

    /// REPAIR-4・#2634: コンテナログ削除のコード別の操作名は固定語彙 5 種で、記録器の名前の規則に収まる。
    #[test]
    fn repair4_container_log_failure_op_names_are_valid_and_bounded() {
        use fandhe_container_core::observability::OpName;
        let cases = [
            (
                ErrorCode::FailedPrecondition,
                "container_log_remove.failed_precondition",
            ),
            (ErrorCode::Timeout, "container_log_remove.timeout"),
            (
                ErrorCode::InvalidArgument,
                "container_log_remove.invalid_argument",
            ),
            (ErrorCode::Internal, "container_log_remove.internal"),
            (ErrorCode::NotFound, "container_log_remove.other"),
            (ErrorCode::AlreadyExists, "container_log_remove.other"),
            (ErrorCode::Unimplemented, "container_log_remove.other"),
            (ErrorCode::PermissionDenied, "container_log_remove.other"),
            (ErrorCode::Unavailable, "container_log_remove.other"),
            (ErrorCode::ResourceExhausted, "container_log_remove.other"),
        ];
        let mut names = std::collections::BTreeSet::new();
        for (code, expected) in cases {
            let name = container_log_remove_failure_op(code);
            assert_eq!(name, expected);
            assert!(OpName::new(name).is_ok(), "{name}");
            names.insert(name);
        }
        assert_eq!(names.len(), 5);
    }

    /// REPAIR-5: 期限を超えたら待たずに `TimedOut`（#2819）。
    #[cfg(unix)]
    #[test]
    fn repair5_startup_pull_recovery_times_out() {
        let r = run_startup_pull_recovery(
            || {
                std::thread::sleep(Duration::from_secs(2));
                Ok(Default::default())
            },
            Duration::from_millis(50),
        );
        assert_eq!(r, StartupPullRecovery::TimedOut);
    }

    /// OCI-7: 結果は `Completed` / `Failed(code)` に写る（#2819）。
    #[cfg(unix)]
    #[test]
    fn oci7_startup_pull_recovery_maps_outcomes() {
        let ok = run_startup_pull_recovery(|| Ok(Default::default()), Duration::from_secs(5));
        assert_eq!(
            ok,
            StartupPullRecovery::Completed(PullRecoveryCounts::default())
        );
        let ng = run_startup_pull_recovery(
            || {
                Err(fandhe_container_oci::error::OciError::new(
                    fandhe_container_oci::error::OciErrorCode::Timeout,
                    "x",
                ))
            },
            Duration::from_secs(5),
        );
        assert_eq!(ng, StartupPullRecovery::Failed("TIMEOUT"));
    }

    /// REPAIR-4: `failed` が 1 以上なら warn、0 なら info（#2819）。
    #[cfg(unix)]
    #[test]
    fn repair4_pull_recovery_summary_level_follows_failed() {
        let warn = PullRecoveryCounts {
            failed: 1,
            ..Default::default()
        };
        assert_eq!(
            warn.summary_line(),
            "{\"level\":\"warn\",\"event\":\"image_pull_recovery\",\"reclaimed\":0,\"released_leases\":0,\"kept_live\":0,\"kept_undetermined\":0,\"failed\":1,\"foreign_entries\":0}"
        );
        assert!(
            PullRecoveryCounts::default()
                .summary_line()
                .starts_with("{\"level\":\"info\"")
        );
    }
}
