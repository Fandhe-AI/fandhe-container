//! `RuntimeService` の CRI 実装（TASK-57.1〜57.3・TASK-58.1・#429・#430・#431・#433・CRI-1・ERR-3）。
//!
//! `fandhe-container-plugin-cri`（TASK-108）が gRPC サーバーへ載せる `RuntimeService` 実装の本体。
//! 本ファイルの時点で実装済みなのは `RunPodSandbox`・`StopPodSandbox`・`RemovePodSandbox`・
//! `PodSandboxStatus`・`ListPodSandbox` と、`CreateContainer`・`StartContainer`（TASK-58.1）・
//! `StopContainer`・`RemoveContainer`（TASK-58.2・#434）・`ListContainers`・`ContainerStatus`
//! （TASK-58.3・#435）と `Status`（#2830。待ちのない準備状態の報告。`docs/design/cri-status-rpc.md`）・`Version`・`UpdateRuntimeConfig`（#2896。同 doc）で、他の RPC は `Unimplemented` を返す。
//!
//! **Create/Start の扱い（CRI-1・ERR-3・TASK-58.1）**: cri-api の `CreateContainerRequest` にクライアント指定の
//! ID はなく、ID はサービスが採番する。proto は `(metadata.name, metadata.attempt)` を sandbox 内で一意と
//! 定めるため、同一サンドボックスで同じ組の再作成を `ALREADY_EXISTS`（「同一 ID の再作成」）とする。未知の
//! サンドボックスは `NOT_FOUND`、停止済み（notready）のサンドボックスへの作成・起動は `FAILED_PRECONDITION`。
//! `StartContainer` は created から running へ遷移し、二重起動は `FAILED_PRECONDITION`（冪等にしない）。
//! 実行層は既定では呼ばず、プロセスも起動しない記録上の遷移である。
//!
//! **Pod サンドボックスの重複（CRI-1・ERR-3・TASK-57）**: `RunPodSandboxRequest` にクライアント指定の ID は
//! なく、ID はサービスが採番する。ERR-3 の対応表に従い、metadata の 4 項目（name・namespace・uid・attempt）が
//! すべて一致する再作成を `ALREADY_EXISTS` とする（`attempt` などが 1 項目でも違えば別の Pod）。
//! 記録が残る間は予約が保たれ、`StopPodSandbox` では解放されず、`RemovePodSandbox` で解放される。
//!
//! **実行層への接続（CRI-2・CRI-7・TASK-59.2・#438）**: [`CriRuntimeService::with_runtime`] で
//! [`RuntimeAdapter`] と [`BundleProvider`] を注入すると、`CreateContainer` は bundle を用意して
//! `ContainerRuntime::create`、`StartContainer` は `ContainerRuntime::start` を専用スレッド上で呼ぶ
//! （tokio の blocking pool を使わず、期限の監視もプールの空きに依存させない。REPAIR-5）。
//! 呼び出し中はレジストリのロックを持たず、記録の `in_flight` フラグで二重 Start・Remove・親サンドボックスの
//! 除去を `FAILED_PRECONDITION` にする。実行層が失敗したら記録を巻き戻し（Create）・Created へ戻し（Start）、
//! 「記録上だけ running」のフォールバックはしない（fail-closed）。注入しない場合は従来のスタブ動作のまま。
//! 未実装（REPAIR-3）: `RunPodSandbox` は実行層に対応操作が無く記録のみ（共有 namespace は後続）。pod の netns は
//! [`CriRuntimeService::with_pod_network`] で `PodNetworkProvider` を注入したときだけ、`namespace_options.network` が `POD`
//! の `RunPodSandbox` が作って結線し、`StopPodSandbox`・`RemovePodSandbox` が回収し、`CreateContainer` が bundle へ
//! netns のパスを渡す（#2675・CRI-2・NET-1）。core の start は network namespace の join を未実装で拒否するため、
//! 本番（plugin-cri）は注入していない（`docs/design/cri-config-acceptance.md` の順 13）。
//! bundle の生成（config 変換・bundle ディレクトリの寿命・image 展開の `ImageRootfsSource`）は `crate::bundle`（#2395・#2433）で、
//! plugin-cri への結線は #2433 で済み、core の本番 launcher との結線は TASK-114、一連の結合試験は TASK-59.4 で扱う。Start 後に中断・確定失敗した場合は、
//! 実行層が running の可能性があるため記録を unknown にして再 Start を拒否する（fail-closed）。
//!
//! **Stop・Remove の接続（CRI-2・TASK-59.3・#439）**: 実行層接続時、実行層の資源を持つコンテナ
//! （`runtime_owned`）への `StopContainer` は `ContainerRuntime::stop`、`RemoveContainer` は
//! `delete(force)` と bundle の解放を経て記録を除去する。`StopPodSandbox` は配下の running・unknown を
//! 猶予 0 で停止し、`RemovePodSandbox` は配下を 1 件ずつ回収してから sandbox を除去する。結果不明
//! （期限超過・想定外の応答）は unknown で記録を保持し、Stop・Remove の再試行で回復できる。待ちは
//! すべて期限つき（REPAIR-5）。
//! コンテナの記録の型と上限は `container` サブモジュール。
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
//! （created）の Stop も冪等に成功し、状態（created・`finished_at` 0）を変えない。実行層接続時も実行層を
//! 呼ばない（proto コメントと containerd v2.1.4 の挙動に合わせる。kubelet の `killContainer` は NotFound
//! 以外のエラーを失敗として扱うため。ERR-3・CRI-1・#2032）。`timeout` は
//! 猶予秒数で、スタブはプロセスを持たず待たないため検証だけして破棄する。`RemoveContainer` は空 ID を
//! `INVALID_ARGUMENT`、未知 ID を成功（冪等。proto コメント）とし、どの状態でも記録・重複判定キー・保持量を
//! 解放する（running の強制削除。プロセスの強制終了と、実待機の上限・REPAIR-5 のタイムアウトは TASK-59 で
//! 追加する。REPAIR-3）。
//!
//! **ListContainers/ContainerStatus の扱い（CRI-1・ERR-3・TASK-58.3・#435）**: 読み取り専用。
//! `ContainerStatus` は空 ID を `INVALID_ARGUMENT`、未知 ID（Remove 済みを含む）を `NOT_FOUND` にする。
//! `ListContainers` は一致なし・未知 ID・`CONTAINER_UNKNOWN` を空の一覧とし、未知の state 値と過大な
//! `label_selector` だけを `INVALID_ARGUMENT` にする。並びは `(created_at, id)` の昇順。labels・annotations は
//! 無改変で返し、`envs` は返さない。`image_ref`・`image_id` は CreateContainer 時の解決結果（報告の無い経路は空。#2831）を返し、`image` は在庫の `repo_tags[0]`（無ければ `config.image`。#2901）、
//! `info`・`message` は方針として常に空（内部のパス・構成・実行層の応答文字列を出さない。理由と containerd との差は
//! `docs/design/cri-config-acceptance.md`。#2901・CRI-2・OCI-1）。
//! `exit_code` は実行層が報告した値を反映し、`reason` は実行層の報告から導く（OOM の報告があれば `OOMKilled`、
//! 0 は `Completed`、非 0 は `Error`、不明は空）。
//!
//! **スタブの明示（REPAIR-3）**: サンドボックスの状態はプロセス内メモリのレジストリにだけ持つ。
//! 実行層（core）には未接続で、永続化もしない。TASK-59 で `StateStore` / `ContainerRuntime` へ置き換える
//! （常駐デーモンを前提にしない CORE-1 とは、置換後の状態管理で整合させる）。
//! リスナー（UDS・peer credential 検証。PLUG-12）や gRPC のメッセージ長上限の設定は TASK-108 の責務で、
//! ここでは作らない。`config` のパス類は保持するだけで検証していない（実際にファイルへ触れる TASK-58 / TASK-59 で検証する）。
//! 例外として `log_directory` と `log_path` は実行層接続時の CreateContainer で結合・検証して保持し、
//! StartContainer が `StartRequest` で supervisor へ渡す（`resolve_log_path`。CRI-2・SUP-4・#2671）。
//! `ReopenContainerLog` は `UNIMPLEMENTED` のまま（kubelet のログ回転は後続 issue）。
//!
//! **保持量の上限**: レジストリは件数（[`MAX_SANDBOXES`]）と、保持する `config` の量
//! （1 件の符号化長 [`MAX_CONFIG_ENCODED_BYTES`]・可変長要素の件数と長さ・合計の見積もり
//! [`MAX_RETAINED_CONFIG_BYTES`]）の両方で有限に保つ。gRPC の受信上限に頼らないのは、本トレイトを
//! 直接呼ぶ経路にも効かせるためと、受信上限では累積を縛れないため。検証の詳細は `config_limits`
//! サブモジュール。
//!
//! **記録ストア（CRI-1・OCI-7。#2932）**: sandbox・コンテナの記録 1 件分のバイト列（`record` サブモジュール）を
//! `<状態ルート>/.cri/records/` に 1 件 1 ファイルで置く層が `record_store` サブモジュール
//! （トレイト [`RecordStore`] とファイル実装 `FileRecordStore`〔unix のみ〕）。
//! sandbox 記録の書く・消す時点は [`CriRuntimeService::with_record_store`] で注入すると有効になる（R4 #2933）。
//! コンテナ記録（R5）・起動時の再採用（R6・R7）・本番の配線（R9）は後続の単位で、未実装（REPAIR-3）。
//!
//! **可観測性（REPAIR-4）**: `RunPodSandbox`・`StopPodSandbox`・`RemovePodSandbox`・`PodSandboxStatus`・`ListPodSandbox`・`CreateContainer`・`StartContainer`・`StopContainer`・`RemoveContainer`・`ListContainers`・`ContainerStatus` は全終了経路（成功・入力不正・上限超過・内部エラー）で、
//! 結果のステータスコードと所要時間を [`CriOpRecorder`] へ 1 件渡す。記録先は
//! [`CriRuntimeService::with_recorder`] で注入する（既定は記録しない）。`config`・labels・annotations・
//! エラー文言は記録先へ渡さない。

mod config_limits;
mod container;
mod record;
mod record_store;
mod runtime_config;

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tonic::codegen::tokio_stream::Empty;
use tonic::{Request, Response, Status};

use crate::bundle::resolve_log_path;
use crate::error::{CriError, CriErrorCode};
use fandhe_container_core::traits::ContainerLogPath;

use crate::adapter::{
    BundleProvider, BundleRequest, PodNetns, PodNetworkProvider, PodNetworkRequest, PreparedBundle,
    RuntimeAdapter, RuntimeContainerStatus, RuntimeLifecycle,
};
use crate::instrument::{CriOpKind, CriOpRecorder, CriOpTimer, NoopCriOpRecorder};
use crate::port_mapping::{PodPortPublish, parse_port_mappings};
use crate::runtime::v1::{
    self, ContainerState as CriContainerState, PodSandboxConfig, PodSandboxState,
    runtime_service_server::RuntimeService,
};
use config_limits::BoundedConfig;
use container::{
    ContainerRecord, ContainerState, ExitReport, ValidatedContainerFilter, ValidatedCreate,
    initial_stop_signal, validate_create_request,
};
use record::SandboxRecordData;
use runtime_config::parse_pod_cidrs;

#[cfg(unix)]
pub use record_store::FileRecordStore;
pub use record_store::{
    DEFAULT_LIST_TIMEOUT, DEFAULT_RECORD_READ_TIMEOUT, ListBudget, ListLimits, ListedRecord,
    MAX_CONTAINER_LISTING_BYTES, MAX_SANDBOX_LISTING_BYTES, NoopRecordStoreOpRecorder, RecordId,
    RecordKind, RecordListing, RecordReadFailure, RecordStore, RecordStoreOp,
    RecordStoreOpRecorder, RecordStoreOpSample, RecordStoreOutcome,
};
pub use runtime_config::{MAX_POD_CIDR_BYTES, MAX_POD_CIDRS, PodCidr, PodCidrs};

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
    /// pod の netns を `PodNetworkProvider::set_up` で用意している最中（#2675・CRI-2・NET-1）。真の間は
    /// 配下のコンテナの作成と Stop・Remove を拒否する（set_up の完了前に記録が消えて資源が漏れるのを防ぐ）。
    network_pending: bool,
    /// `PodNetworkProvider` の資源が残りうる（set_up の成功、または結果不明）。Stop・Remove が `tear_down` で
    /// 回収し、成功したら偽に戻す。回収に失敗したら真のまま保持して再試行できるようにする（fail-closed）。
    network_owned: bool,
    /// `tear_down` の worker が走っている間は真（Stop・Remove の重複起動を拒否する。REPAIR-5・CRI-2）。
    /// 期限超過で RPC が返っても worker が終わるまで偽に戻らない（[`NetworkTearDownGuard`] が解除する）。
    network_teardown: bool,
    /// set_up が返した、結線済みの pod network namespace。配下のコンテナの bundle へ渡す。
    pod_netns: Option<PodNetns>,
    /// 記録ストアへの書き込み・削除の最中（#2933・CRI-1・CRI-2）。真の間は同じ ID への Stop・Remove・
    /// CreateContainer を `FAILED_PRECONDITION` で拒否する（fsync を registry の `Mutex` の外で行うため、
    /// 並行操作が古いスナップショットを後から書いたり、所有者の無い記録ファイルを残したりするのを防ぐ）。
    /// 記録ストアを注入していないときは 0。[`SandboxRecordWriteGuard`] 1 つにつき 1 を数え、guard の Drop が
    /// 減らす（手放した put の後始末スレッドが追加の guard を持つため、真偽ではなく件数で持つ）。
    record_write: u32,
}

/// サンドボックスのメモリ上レジストリ（TASK-59 で `StateStore` に置換するスタブ。REPAIR-3）。
///
/// 不変条件: `retained_bytes` は `records` の、`container_retained_bytes` は `containers` の各記録の
/// `retained_bytes` の合計に等しい。`container_keys` は `containers` と 1 対 1 に対応する。
///
/// サンドボックスの重複判定（ERR-3・CRI-1・TASK-57）は専用の索引を持たず、`records` の metadata
/// 4 項目（name・namespace・uid・attempt）を走査して行う。件数は上限（既定 1024）で有界で、
/// 索引を持たないため metadata の写しによる保持量の二重計上と、記録との不整合が起きない。
/// Stop では記録が残るため解放されず、Remove で記録とともに解放される。
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
    /// 実行層の呼び出し（worker）が RPC の future より長く生きても記録を確定できるよう `Arc` で共有する。
    registry: Arc<Mutex<SandboxRegistry>>,
    limits: SandboxLimits,
    container_limits: ContainerLimits,
    recorder: Arc<dyn CriOpRecorder>,
    /// 実行層への接続（TASK-59.2）。`None` のときは記録上の遷移だけのスタブ動作。
    runtime: Option<RuntimeBinding>,
    /// 実行層の応答待ちの上限（REPAIR-5）。
    runtime_timeout: Duration,
    /// pod の netns を作って結線する注入点（#2675・CRI-2・NET-1）。`None` のときは従来どおり何も呼ばない。
    pod_network: Option<Arc<dyn PodNetworkProvider>>,
    /// `UpdateRuntimeConfig` で最後に受け入れた pod CIDR（#2896）。レジストリとは別のロックで、保持は一瞬。
    /// 読む利用者はまだ無い（REPAIR-3。結線は後続）。
    pod_cidrs: Mutex<Option<PodCidrs>>,
    /// sandbox 記録の書き込み先（#2933・CRI-1・CRI-2）。`None` のときは何も書かない（従来どおり）。
    record_store: Option<Arc<dyn RecordStore>>,
}

/// kubelet の `kubeRuntimeAPIVersion`。`Version` の応答の `version` はこれと完全一致が必須
/// （違うと kubelet の runtime manager が作れず起動に失敗する。kubernetes v1.37.1
/// `pkg/kubelet/kuberuntime/kuberuntime_manager.go` 82・307〜311 行。CRI-1・#2896）。
pub const CRI_KUBE_API_VERSION: &str = "0.1.0";

/// `Version` の `runtime_name`（node の `ContainerRuntimeVersion` が `fandhe-container://<版>` になる）。
pub const RUNTIME_NAME: &str = "fandhe-container";

/// `Version` の `runtime_version`。`fandhe-container-cri` の crate 版（現状 `0.0.0`。版数方針の決定に自動で追随する）。
pub const RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `Version` の `runtime_api_version`。containerd v2.1.4 `internal/cri/constants` の `CRIVersion` と同値
/// （proto のコメントは semver 互換だが、kubelet は `ParseGeneric` で解釈する）。
pub const RUNTIME_API_VERSION: &str = "v1";

/// `Version` の応答（定数のみ。要求は読まない。CRI-1・#2896）。
pub fn version_response() -> v1::VersionResponse {
    v1::VersionResponse {
        version: CRI_KUBE_API_VERSION.to_string(),
        runtime_name: RUNTIME_NAME.to_string(),
        runtime_version: RUNTIME_VERSION.to_string(),
        runtime_api_version: RUNTIME_API_VERSION.to_string(),
    }
}

/// 実行層への接続（アダプタと bundle の供給元。CRI-2・CRI-7）。
#[derive(Clone)]
struct RuntimeBinding {
    adapter: RuntimeAdapter,
    bundles: Arc<dyn BundleProvider>,
}

/// 実行層（bundle 供給元・`ContainerRuntime`）の応答待ちの既定の上限（REPAIR-5）。
///
/// AGENTS.md「推奨タイムアウト値」の新規応答待ちの既定（5〜10 秒）に合わせて 10 秒とする。
const DEFAULT_RUNTIME_TIMEOUT: Duration = Duration::from_secs(10);

/// `reserve_container` の戻り値（登録したコンテナの識別子と、bundle 供給元へ渡す設定）。
struct ReservedContainer {
    container_id: String,
    pod_sandbox_id: String,
    /// `in_flight` 登録のときだけ `Some`（上限検証済みの複製）。
    provider_config: Option<v1::ContainerConfig>,
    /// `in_flight` 登録のときだけ `Some`。所属サンドボックスの登録記録の複製（RunPodSandbox で上限検証済み。
    /// bundle 供給元が hostname・namespace_options を読む。要求の `sandbox_config` は使わない。#2395）。
    provider_sandbox_config: Option<PodSandboxConfig>,
    /// 所属サンドボックスの結線済み pod netns のパス（`in_flight` 登録のときだけ。#2675）。
    provider_pod_netns: Option<std::path::PathBuf>,
}

/// 実行層を呼び出し中の操作の種類（[`InFlightGuard`] が巻き戻しの方法を選ぶ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InFlightKind {
    Create,
    Start,
    /// `ContainerRuntime::stop`（TASK-59.3）。成功で Exited、確定失敗で元の状態、結果不明で Unknown。
    Stop,
    /// `ContainerRuntime::delete(force)` と bundle の解放（TASK-59.3）。成功で記録を除去する。
    Remove,
}

/// `StopContainer` の `timeout`（猶予秒数）の上限。core の `ContainerRuntime::stop` の上限（24 時間）と
/// 同じ値で、超過は仮登録の前に `INVALID_ARGUMENT` にする（REPAIR-5）。
const STOP_GRACE_MAX_SECS: i64 = 24 * 60 * 60;

/// `StopPodSandbox` が配下のコンテナを停止するときの猶予秒数。要求に timeout が無く、残ったコンテナは
/// 強制停止するのが CRI の意味であるため 0（即時 SIGKILL）とする（CRI-2）。
const SANDBOX_STOP_GRACE_SECS: i64 = 0;

/// `ContainerRuntime::create`・`start` のエラーコードのうち「何も起きていない」と確定できるものか（REPAIR-5）。
///
/// 入力・状態・権限の拒否は実行層が処理前に弾いた確定失敗。`DeadlineExceeded`・`Unavailable`・
/// `Internal` 等は応答不明で実行層が running の可能性があり、再 Start の二重起動を避けるため含めない。
fn is_definite_failure(code: CriErrorCode) -> bool {
    matches!(
        code,
        CriErrorCode::InvalidArgument
            | CriErrorCode::NotFound
            | CriErrorCode::AlreadyExists
            | CriErrorCode::FailedPrecondition
            | CriErrorCode::Unimplemented
            | CriErrorCode::PermissionDenied
    )
}

/// 実行層の呼び出し中に立てた `in_flight` を、確定されないまま破棄されたら巻き戻す番人（TASK-59.2）。
///
/// worker（専用スレッド上のクロージャ）が所有する。RPC の future が中断・タイムアウトしても
/// worker は走り続け（Create は dispatch 前なら `AbandonOnDrop` で打ち切られ、dispatch 後は最後まで走る。#2899）、その終了時（失敗・panic を含む）に `Drop` で巻き戻すため、実行層が処理中の間に
/// 記録・件数枠・bundle だけが先に解放されることはない。確定は [`InFlightGuard::commit`]。
struct InFlightGuard {
    registry: Arc<Mutex<SandboxRegistry>>,
    id: String,
    kind: InFlightKind,
    committed: bool,
    /// Create の巻き戻しで `release` を呼ぶ bundle の供給元。
    bundles: Option<Arc<dyn BundleProvider>>,
    /// 実行層の結果が不明（呼び出し後で、確定失敗・削除完了が確認できていない）か。
    /// 真のまま破棄されたら、Start は実行層で running かもしれないため created へ戻さず exited にし、
    /// Create は実行層に資源が残るかもしれないため記録と bundle を保持する（exited にして追跡を残す）。
    outcome_unknown: bool,
    /// 実行層が停止済みと報告した（Start の応答が Stopped）。破棄時に結果不明ではなく exited へ反映する。
    confirmed_exited: bool,
    /// 実行層が報告した終了の内容（終了コードと OOM 等の終了理由。Stop の commit と Start の終了済み応答の
    /// 後始末で記録へ反映する。不明は None のままで、reason を空にする。CRI-2・CORE-4・REPAIR-3）。
    exit: ExitReport,
}

impl InFlightGuard {
    fn new(registry: Arc<Mutex<SandboxRegistry>>, id: String, kind: InFlightKind) -> Self {
        Self {
            registry,
            id,
            kind,
            committed: false,
            bundles: None,
            outcome_unknown: false,
            confirmed_exited: false,
            exit: ExitReport::default(),
        }
    }

    /// 実行層が報告した終了コードと終了理由を、commit または破棄時の exited 反映で記録へ書くよう保持する（CRI-2・CORE-4）。
    fn set_exit(&mut self, status: &RuntimeContainerStatus) {
        self.exit = ExitReport {
            code: status.exit_code,
            termination: status.termination,
        };
    }

    /// 実行層が停止済みと報告した。破棄時に exited（終了時刻つき）へ反映する（結果不明の unknown にしない）。
    fn mark_confirmed_exited(&mut self) {
        self.confirmed_exited = true;
    }

    /// Create の巻き戻し時に bundle を解放するよう設定する（bundle の解放責務を持たせる）。
    ///
    /// worker スレッドの先頭、`BundleProvider::prepare` の直前でだけ呼ぶ。worker が起動する前は呼ばない。
    /// 起動前（スレッド生成の失敗でクロージャが RPC スレッド上で破棄される場合）の guard は解放責務を持たず、
    /// `release`（外部処理）が RPC スレッドで走って期限を無視するのを防ぐ。起動前は `prepare` も未実行で、
    /// 解放すべき bundle が無いためリークにならない（REPAIR-5・CRI-2）。
    fn arm_bundles(&mut self, bundles: Arc<dyn BundleProvider>) {
        self.bundles = Some(bundles);
    }

    /// 実行層の呼び出しを開始した（以後、中断・commit 失敗では結果が不明になる）。
    fn mark_dispatched(&mut self) {
        self.outcome_unknown = true;
    }

    /// 実行層が「何も起きていない」（Start は created のまま、Create は未作成または削除完了）と確定できた。
    fn mark_definitely_failed(&mut self) {
        self.outcome_unknown = false;
    }

    /// 実行層の成功を記録へ反映して確定する。反映に失敗したら巻き戻される。
    fn commit(&mut self) -> Result<(), CriError> {
        commit_in_flight(&self.registry, &self.id, self.kind, self.exit)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if !self.committed {
            // 確定失敗の Create は、bundle の解放を終えてから記録（件数枠・名前キー）を除去する。
            // `release` が停止しても記録は `in_flight` のまま残り、枠は空かない。停止した worker の数は
            // 件数の上限（MAX_CONTAINERS）で有界になり、枠を超えて worker や未解放資源が溜まらない
            // （REPAIR-5・リソース上限）。結果不明のときは実行層に資源が残りうるため bundle を解放しない
            // （削除完了を確認できた場合だけ `mark_definitely_failed` 経由で解放する。fail-closed）。
            // 解放に失敗したら資源が残るため結果不明と同じ扱い（記録と件数枠を保持して追跡を残す）。
            if self.kind == InFlightKind::Create
                && !self.outcome_unknown
                && let Some(bundles) = &self.bundles
                && bundles.release(&self.id).is_err()
            {
                self.outcome_unknown = true;
            }
            rollback_in_flight(
                &self.registry,
                &self.id,
                self.kind,
                self.outcome_unknown,
                self.confirmed_exited,
                self.exit,
            );
        }
    }
}

/// 仮登録（`in_flight`）済みだが、まだ実行層へ渡していないコンテナの一覧（sandbox 系 RPC 用。TASK-59.3）。
///
/// RPC の future が途中で中断されたら、未処理の記録の `in_flight` を解く（解かないと Start・Remove・
/// sandbox の除去が永久に `FAILED_PRECONDITION` になる）。処理に回した 1 件は [`InFlightGuard`] が引き継ぐ。
struct PendingMarks {
    registry: Arc<Mutex<SandboxRegistry>>,
    ids: std::collections::VecDeque<String>,
}

impl PendingMarks {
    fn new(registry: Arc<Mutex<SandboxRegistry>>, ids: Vec<String>) -> Self {
        Self {
            registry,
            ids: ids.into(),
        }
    }

    /// 次の 1 件を取り出し、その `in_flight` の責務を持つ番人を返す（同期処理。await をまたがない）。
    fn next_guard(&mut self, kind: InFlightKind) -> Option<InFlightGuard> {
        let id = self.ids.pop_front()?;
        Some(InFlightGuard::new(Arc::clone(&self.registry), id, kind))
    }
}

impl Drop for PendingMarks {
    fn drop(&mut self) {
        if self.ids.is_empty() {
            return;
        }
        if let Ok(mut registry) = self.registry.lock() {
            for id in self.ids.drain(..) {
                if let Some(record) = registry.containers.get_mut(&id) {
                    record.in_flight = false;
                }
            }
        }
    }
}

/// 実行層からコンテナの削除完了（または不在）を確認できたか。成功と `NOT_FOUND` を確認済みとする。
///
/// 失敗・タイムアウト・結果不明は未確認（偽）。偽のとき呼び出し側は記録と bundle を保持する。
///
/// 実行層の削除が止まっても worker が終わらなくなるのを避けるため、`timeout` で打ち切って未確認（偽）とする
/// （REPAIR-5）。打ち切った後も削除の呼び出しは切り離したスレッドで走り続ける。
fn confirm_removed(adapter: &RuntimeAdapter, id: &str, timeout: Duration) -> bool {
    let adapter = adapter.clone();
    let id = id.to_owned();
    call_with_deadline(timeout, move || match adapter.remove(&id, true) {
        Ok(_) => true,
        Err(err) => err.code() == CriErrorCode::NotFound,
    })
    .unwrap_or(false)
}

/// Start の失敗が「実行層は created のまま」と確定できるか（REPAIR-5）。
///
/// `FailedPrecondition`・`NotFound` は実行層が Created 以外（Running・Stopped）でも返しうるため、
/// 状態照会で Created を確認できた場合だけ確定とする。照会の失敗・期限超過・Created 以外は結果不明。
fn start_failure_is_definite(
    adapter: &RuntimeAdapter,
    id: &str,
    code: CriErrorCode,
    timeout: Duration,
) -> bool {
    match code {
        CriErrorCode::FailedPrecondition | CriErrorCode::NotFound => {
            let adapter = adapter.clone();
            let id = id.to_owned();
            call_with_deadline(timeout, move || adapter.state(&id))
                .is_some_and(|r| r.is_ok_and(|s| s.lifecycle == RuntimeLifecycle::Created))
        }
        other => is_definite_failure(other),
    }
}

/// 同期呼び出しを切り離したスレッドで走らせ、`timeout` までに終わらなければ `None`（REPAIR-5）。
fn call_with_deadline<T, F>(timeout: Duration, f: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("cri-runtime-call".into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .ok()?;
    rx.recv_timeout(timeout).ok()
}

/// `run_bounded` が使う名前つきスレッドの生成（テストでは生成失敗を注入できる）。
///
/// 失敗時はクロージャがこの関数内（呼び出し側のスレッド）で破棄される。クロージャが持つ値の `Drop` は
/// 呼び出し側（RPC スレッド）で走るため、外部処理を伴う `Drop` を持たせてはならない（REPAIR-5）。
fn spawn_runtime_thread<F>(name: &str, f: F) -> std::io::Result<()>
where
    F: FnOnce() + Send + 'static,
{
    #[cfg(test)]
    if tests::take_spawn_failure() {
        return Err(std::io::Error::other("injected spawn failure"));
    }
    std::thread::Builder::new()
        .name(name.into())
        .spawn(f)
        .map(|_| ())
}

/// `run_bounded` の完了待ちの共有状態（結果と、待っている future の waker）。
struct WaitState<T> {
    result: Option<Result<T, CriError>>,
    waker: Option<std::task::Waker>,
}

/// 専用の監視スレッドが結果を置くまで待つ future（tokio の `time` feature に依存しない）。
struct BoundedWait<T>(Arc<Mutex<WaitState<T>>>);

impl<T> std::future::Future for BoundedWait<T> {
    type Output = Result<T, CriError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let Ok(mut state) = self.0.lock() else {
            return std::task::Poll::Ready(Err(CriError::internal("runtime task failed")));
        };
        match state.result.take() {
            Some(result) => std::task::Poll::Ready(result),
            None => {
                state.waker = Some(cx.waker().clone());
                std::task::Poll::Pending
            }
        }
    }
}

/// `RunPodSandbox` の `set_up` の結果を、worker と呼び出し側のどちらが先に確定したか（#2675・CRI-2・NET-1）。
///
/// どちらも registry のロック下で 1 度だけ遷移を試み、先に遷移した側だけが確定する。期限超過の判定から
/// 呼び出し側がロックを取るまでの間に worker が完了しても、worker が確定したなら呼び出し側は結果不明として
/// 失敗を返さず（Ready を公開したまま失敗を返す食い違いを防ぐ）、呼び出し側が先に手放したなら worker は
/// Ready を公開しない。
struct SetUpSettlement(AtomicU8);

impl SetUpSettlement {
    const PENDING: u8 = 0;
    const BY_WORKER: u8 = 1;
    const ABANDONED: u8 = 2;
    /// 巻き戻し用の put で、worker の確定後に呼び出し側が結果を受け取った状態（後始末の責任が消える）。
    const ACCEPTED: u8 = 3;

    fn new() -> Self {
        Self(AtomicU8::new(Self::PENDING))
    }

    /// worker が結果を確定する。呼び出し側が先に結果不明として手放していたら偽（Ready を公開しない）。
    fn settle_by_worker(&self) -> bool {
        self.0
            .compare_exchange(
                Self::PENDING,
                Self::BY_WORKER,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /// 呼び出し側が worker の確定済みの結果を受け取った（以後は記録の後始末を呼び出し側の経路が持つ）。
    fn accept(&self) -> bool {
        self.0
            .compare_exchange(
                Self::BY_WORKER,
                Self::ACCEPTED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /// 巻き戻し用の put が失敗した worker が、後始末（記録の削除と予約の解放）の責任を自分で負う印を付ける。
    /// 以後は呼び出し側の手放し（`abandon`・`abandon_put`・`accept`）が何もしない（二重の後始末を防ぐ。#2933・CRI-2）。
    fn take_failed_cleanup(&self) {
        self.0.store(Self::ACCEPTED, Ordering::SeqCst);
    }

    /// 巻き戻し用の put を呼び出し側が結果の受領前に手放す。worker が既に書き終えて確定していた
    /// （受領前）なら真で、ファイルだけが残るため呼び出し側が消す責任を負う（#2933・CRI-2）。
    fn abandon_put(&self) -> bool {
        if self.abandon() {
            return false;
        }
        self.0
            .compare_exchange(
                Self::BY_WORKER,
                Self::ABANDONED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /// 呼び出し側が手放し済みか（`CreateContainer` の worker が bundle 用意の前に見る。#2899）。
    fn is_abandoned(&self) -> bool {
        self.0.load(Ordering::SeqCst) == Self::ABANDONED
    }

    /// 呼び出し側が結果不明として手放す。worker が先に確定していたら偽（記録は worker の確定どおり）。
    fn abandon(&self) -> bool {
        self.0
            .compare_exchange(
                Self::PENDING,
                Self::ABANDONED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }
}

/// `CreateContainer` の RPC 側が、worker を手放したことを伝える番人（REPAIR-5・CRI-2・#2899）。
///
/// 期限切れ（`run_bounded` の `Timeout`）と future の破棄（kubelet の取り消し・grpc-timeout）の両方で、
/// 実行層への dispatch より前の worker を打ち切る。`Drop` は atomic の store だけで外部処理を持たない
/// （RPC スレッドで走るため。`spawn_runtime_thread` の注意）。worker が dispatch 済み（先に確定済み）なら
/// 手放しは負けて何も起きず、worker は従来どおり最後まで走る。結果を受け取れた経路は `disarm` する。
struct AbandonOnDrop {
    settlement: Arc<SetUpSettlement>,
    cancel: Arc<AtomicBool>,
    armed: bool,
}

impl AbandonOnDrop {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for AbandonOnDrop {
    fn drop(&mut self) {
        if self.armed {
            // dispatch 前の worker だけが負ける。取り消しの旗は rootfs 展開をエントリ単位で止める。
            self.settlement.abandon();
            self.cancel.store(true, Ordering::Release);
        }
    }
}

/// `set_up` の worker が正常に確定できないまま終わった（panic・起動されないままの破棄）とき、
/// `network_pending` を解除して資源が残りうる印（`network_owned`・notready）へ倒す guard（#2675・CRI-2・NET-1）。
///
/// 正常な完了では worker が先に `network_pending` を偽にするため何もしない。解除しないと Stop・Remove が
/// 永久に `FAILED_PRECONDITION` になる。
struct NetworkSetUpGuard {
    registry: Arc<Mutex<SandboxRegistry>>,
    id: String,
}

impl Drop for NetworkSetUpGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock()
            && let Some(record) = registry.records.get_mut(&self.id)
            && record.network_pending
        {
            record.network_pending = false;
            record.network_owned = true;
            record.state = SandboxState::NotReady;
        }
    }
}

/// `tear_down` の worker が終わるまで `network_teardown` を保つ guard（worker へ move する）。
///
/// 期限超過で呼び出し側が先に返っても worker の終了（panic 含む）で解除されるため、ハングした worker が
/// 残っている間の重複起動を拒否できる（REPAIR-5）。
struct NetworkTearDownGuard {
    registry: Arc<Mutex<SandboxRegistry>>,
    id: String,
}

impl Drop for NetworkTearDownGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock()
            && let Some(record) = registry.records.get_mut(&self.id)
        {
            record.network_teardown = false;
        }
    }
}

/// 記録ストアへの 1 回の I/O（worker へ渡す。#2933）。
enum StoreCall {
    /// 書き込み。`rollback` が `Some` のときは「書けなかった予約の巻き戻し」用の put で、呼び出し側が
    /// 手放した（期限超過・future の破棄）後に worker が遅れて書けた場合は、worker 自身が書いた直後に
    /// 削除する（削除を put の完了に順序付ける。所有者の無い記録を残さない。#2933・REPAIR-5）。
    Put(RecordId, Vec<u8>, Option<PutRollback>),
    /// 削除。`Some` のときは、ファイルを消せた worker 自身がメモリの記録の除去まで確定する（期限超過で
    /// 呼び出し側が先に返っても、遅れて完了した削除が「ファイルは無いのにメモリは Ready」を残さない。
    /// `record_write` の guard は除去の後に解除される。#2933・CRI-2）。
    Remove(RecordId, Option<RemoveFinalize>),
}

/// `persist_sandbox_inner` の put の種類（#2933）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum PutMode {
    /// 状態の更新（Stop）。失敗してもメモリの記録は変えない。
    Plain,
    /// 予約の put（Run の write-ahead・ネットワークなしの確定版）。失敗・手放しの後始末は worker が持つ。
    Reservation,
    /// set_up 成功後の確定版。失敗したら worker が notready にする。
    Confirm,
}

/// 巻き戻し用の put の引数（#2933・CRI-2・REPAIR-5）。
///
/// 手放された put の worker は、書けた記録ファイルを消したあとに `registry` の予約（件数・保持量）も
/// 戻す。予約は worker が終わるまで保たれるため、put のハングで worker と予約が上限を超えて溜まらない。
#[derive(Clone)]
struct PutRollback {
    settlement: Arc<SetUpSettlement>,
    registry: Arc<Mutex<SandboxRegistry>>,
    sandbox_id: String,
    /// worker のスレッドを起動できなかったか（起動失敗の put は何も書かないため、呼び出し側が予約を戻す。
    /// 期限超過とは区別する。起動済みの worker は後から put を実行するので、予約は worker が戻す）。
    spawn_failed: Arc<AtomicBool>,
    /// 確定版の put か。真なら put の失敗を worker が notready にするだけで、予約の解放はしない
    /// （確定版の失敗でも資源は既にあり、記録は Stop・Remove で回収できる状態で残す。#2933・CRI-2）。
    confirm: bool,
}

impl PutRollback {
    /// メモリの予約を戻す（冪等。ロックだけで外部処理を持たない）。
    fn release_reservation(&self) {
        if let Ok(mut registry) = self.registry.lock() {
            remove_sandbox_record(&mut registry, &self.sandbox_id);
        }
    }

    /// 記録ファイルの削除の結果に応じて予約を扱う。消せたときだけ予約を戻す。消せなかった（ファイルが
    /// 残りうる）ときは予約を捨てず、Stop・Remove で回収できる notready の記録へ倒す（#2933・REPAIR-3）。
    fn settle_after_remove(&self, removed: bool) {
        if removed {
            self.release_reservation();
        } else {
            self.make_recoverable();
        }
    }

    /// put に進めなかった（符号化の失敗）ときの扱い。予約の put なら予約を戻し、確定版なら notready にする。
    fn settle_unwritten(&self) {
        if self.confirm {
            self.make_recoverable();
        } else {
            self.release_reservation();
        }
    }

    /// 予約を回復可能な状態へ倒す（`network_pending` を外し notready にする。冪等。ロックだけ）。
    ///
    /// write-ahead の put の時点では `set_up` は始まっていないため、資源は無い。外した後は利用者が
    /// Stop・Remove で記録を回収できる（pending のまま永久に塞がない。#2933・CRI-2）。
    fn make_recoverable(&self) {
        if let Ok(mut registry) = self.registry.lock()
            && let Some(record) = registry.records.get_mut(&self.sandbox_id)
        {
            record.network_pending = false;
            record.state = SandboxState::NotReady;
        }
    }
}

/// put の worker が panic で終わったとき、予約を回復可能な状態へ倒す番人（#2933・CRI-2）。
///
/// 正常終了（`defuse` 済み）や、worker が走らずに破棄された場合（呼び出し側が戻す）は何もしない。
struct PutWorkerGuard {
    rollback: Option<PutRollback>,
}

impl PutWorkerGuard {
    fn defuse(&mut self) {
        self.rollback = None;
    }
}

impl Drop for PutWorkerGuard {
    fn drop(&mut self) {
        if std::thread::panicking()
            && let Some(rb) = self.rollback.take()
        {
            rb.make_recoverable();
        }
    }
}

/// `StoreCall::Remove` の worker がメモリの除去まで行うための引数。
struct RemoveFinalize {
    registry: Arc<Mutex<SandboxRegistry>>,
    sandbox_id: String,
}

/// ファイルを消せた後に、ロック下で検査し直してメモリの記録を除去する（worker 側。#2933・CRI-2）。
///
/// 検査が通らない（配下の操作が始まった等）ときは、ファイルを書き直して（best effort）検査のエラーを返す。
fn finalize_sandbox_removal(
    store: &Arc<dyn RecordStore>,
    finalize: &RemoveFinalize,
) -> Result<(), CriError> {
    let id = finalize.sandbox_id.as_str();
    let rewrite = {
        let mut registry = finalize
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        match plan_sandbox_removal(&registry, id) {
            Ok(Some(plan)) => {
                apply_sandbox_removal(&mut registry, id, plan);
                return Ok(());
            }
            Ok(None) => return Ok(()),
            Err(err) => {
                let data = registry
                    .records
                    .get(id)
                    .map(|r| SandboxRecordData::from_registry(id, r, false));
                (err, data)
            }
        }
    };
    let (err, data) = rewrite;
    if let Some(data) = data
        && let Ok(bytes) = data.encode()
        && let Ok(record_id) = RecordId::new(id)
    {
        let _ = store.put(RecordKind::Sandbox, &record_id, &bytes);
    }
    Err(err)
}

/// 巻き戻し用の put を呼び出し側が手放したことを worker へ伝える番人。
///
/// worker が先に書き終えて確定済みでも、呼び出し側が結果を受け取る前（`accept` 前）に破棄されたら、
/// ファイルとメモリの予約が残る。その場合は切り離したスレッドで記録を消し、予約を戻す
/// （`Drop` 自体は I/O をせず atomic の CAS とスレッド起動だけ。worker がまだ put 中なら worker が
/// 同じ後始末を終えるまで予約を保つ。#2933・CRI-2・REPAIR-5）。
struct AbandonPutOnDrop {
    rollback: Option<PutRollback>,
    store: Option<Arc<dyn RecordStore>>,
    id: Option<RecordId>,
    /// 後始末スレッドへ引き継ぐ追加の書き込み guard。削除と予約の解除が終わるまで `record_write` を保つ。
    extra_guard: Option<SandboxRecordWriteGuard>,
}

impl Drop for AbandonPutOnDrop {
    fn drop(&mut self) {
        let Some(rollback) = self.rollback.take() else {
            return;
        };
        let extra_guard = self.extra_guard.take();
        if rollback.settlement.abandon_put()
            && let (Some(store), Some(id)) = (self.store.take(), self.id.take())
        {
            let for_failure = rollback.clone();
            let spawned = spawn_runtime_thread("cri-record-cleanup", move || {
                // 削除に成功したときだけ予約を戻す。書き込み guard はその後に解除する。
                let removed = store.remove(RecordKind::Sandbox, &id).is_ok();
                rollback.settle_after_remove(removed);
                drop(extra_guard);
            });
            if spawned.is_err() {
                // 後始末を引き継げなかった。予約を永久に塞がず、回収できる状態へ倒す。
                for_failure.make_recoverable();
            }
        }
    }
}

/// sandbox 記録の書き込み・削除が終わるまで `record_write` を保つ guard（#2933・CRI-1・CRI-2）。
///
/// `RunPodSandbox`・`StopPodSandbox`・`RemovePodSandbox` が書く時点の前後で持つ。future が中断されても
/// Drop が解除する。Drop はロックとフラグ解除だけで外部処理を持たない（`NetworkTearDownGuard` と同じ形）。
struct SandboxRecordWriteGuard {
    registry: Arc<Mutex<SandboxRegistry>>,
    id: String,
}

impl Drop for SandboxRecordWriteGuard {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock()
            && let Some(record) = registry.records.get_mut(&self.id)
        {
            record.record_write = record.record_write.saturating_sub(1);
        }
    }
}

/// 記録ストアの書き込み失敗の固定文言（ID・パス・errno を載せない。REPAIR-4）。
const SANDBOX_PERSIST_FAILED: &str = "sandbox record could not be persisted";
/// 記録ストアの削除失敗の固定文言。
const SANDBOX_UNPERSIST_FAILED: &str = "sandbox record could not be removed";
/// 記録の書き込み中の並行操作を拒否する固定文言。
const SANDBOX_RECORD_BUSY: &str = "sandbox record update is in progress";

/// 実行層の呼び出しを専用スレッドで走らせ、結果を `timeout` まで待つ（REPAIR-5）。
///
/// 期限を過ぎたら `DEADLINE_EXCEEDED` を返すが、worker はここからは打ち切れない（`CreateContainer` だけは
/// 呼び出し側が `AbandonOnDrop` で dispatch 前の worker を打ち切る。#2899）。worker は自分の
/// [`InFlightGuard`] で記録を最後まで確定・巻き戻すため、呼び出し側は結果不明として扱ってよい。
/// worker も期限の監視も tokio の blocking pool を使わない。実行層のハングで pool が埋まっても、
/// 期限の監視は開始され、`timeout` で応答を返す。
async fn run_bounded<T, F>(timeout: Duration, work: F) -> Result<T, CriError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let state = Arc::new(Mutex::new(WaitState {
        result: None,
        waker: None,
    }));
    let waiter_state = Arc::clone(&state);
    // 監視スレッドを先に起こす。起動に失敗したら worker は走らせない（クロージャの破棄で guard が巻き戻す）。
    spawn_runtime_thread("cri-runtime-wait", move || {
        let result = match rx.recv_timeout(timeout) {
            Ok(value) => Ok(value),
            Err(RecvTimeoutError::Timeout) => Err(CriError::timeout("runtime operation timed out")),
            // worker の panic（guard の Drop が後始末する）。
            Err(RecvTimeoutError::Disconnected) => Err(CriError::internal("runtime task failed")),
        };
        if let Ok(mut state) = waiter_state.lock() {
            state.result = Some(result);
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        }
    })
    .map_err(|_| CriError::unavailable("cannot start runtime wait thread"))?;
    // worker は切り離す（join しない）。panic は guard の Drop が後始末する。
    spawn_runtime_thread("cri-runtime-worker", move || {
        let _ = tx.send(work());
    })
    .map_err(|_| CriError::unavailable("cannot start runtime worker thread"))?;
    BoundedWait(state).await
}

/// `RunPodSandbox` の設定が pod の network namespace を求めるか（`namespace_options.network` が `POD`。
/// 未指定は既定値の `POD`。#2675・CRI-2・NET-1）。未知の値は求めない（後続の検証が拒否する）。
fn wants_pod_network(config: Option<&PodSandboxConfig>) -> bool {
    let mode = config
        .and_then(|c| c.linux.as_ref())
        .and_then(|l| l.security_context.as_ref())
        .and_then(|s| s.namespace_options.as_ref())
        .map_or(v1::NamespaceMode::Pod as i32, |o| o.network);
    mode == v1::NamespaceMode::Pod as i32
}

/// `remove_sandbox` が検査の段階で計算した、除去後の保持量（#2933）。
struct SandboxRemovalPlan {
    remaining: usize,
    remaining_containers: usize,
}

/// sandbox の除去が可能かをレジストリを変更せずに検査し、除去後の保持量を返す（未知 ID は `None`）。
///
/// 配下に実行層を呼び出し中のコンテナがある・実行層の資源が残りうるコンテナがある・保持量が不整合な
/// ときは除去しない（TASK-59.2・CRI-1）。
fn plan_sandbox_removal(
    registry: &SandboxRegistry,
    id: &str,
) -> Result<Option<SandboxRemovalPlan>, CriError> {
    let Some(record) = registry.records.get(id) else {
        return Ok(None);
    };
    // 先に引けることを確かめてから除去し、失敗時にレジストリを変更しない。
    let remaining = registry
        .retained_bytes
        .checked_sub(record.retained_bytes)
        .ok_or_else(|| CriError::internal("sandbox registry is inconsistent"))?;
    // 配下に実行層を呼び出し中のコンテナがあれば除去しない（実行層に資源が残るため。TASK-59.2）。
    if registry
        .containers
        .values()
        .any(|c| c.pod_sandbox_id == id && c.in_flight)
    {
        return Err(CriError::failed_precondition(
            "container operation in progress",
        ));
    }
    // 実行層に資源が残りうるコンテナ（Create の結果不明）がある間は除去しない（追跡情報を失わない）。
    if registry
        .containers
        .values()
        .any(|c| c.pod_sandbox_id == id && c.runtime_owned)
    {
        return Err(CriError::failed_precondition(
            "container resources are pending runtime cleanup",
        ));
    }
    // 配下のコンテナ記録も連鎖して除去する（孤児と保持量の取りこぼしを防ぐ。TASK-58.1）。
    let mut released: usize = 0;
    for c in registry
        .containers
        .values()
        .filter(|c| c.pod_sandbox_id == id)
    {
        released = released
            .checked_add(c.retained_bytes)
            .ok_or_else(|| CriError::internal("container registry is inconsistent"))?;
    }
    let remaining_containers = registry
        .container_retained_bytes
        .checked_sub(released)
        .ok_or_else(|| CriError::internal("container registry is inconsistent"))?;
    Ok(Some(SandboxRemovalPlan {
        remaining,
        remaining_containers,
    }))
}

/// [`plan_sandbox_removal`] の結果を適用する（配下のコンテナ記録を連鎖して除去し、保持量を解放する）。
fn apply_sandbox_removal(registry: &mut SandboxRegistry, id: &str, plan: SandboxRemovalPlan) {
    registry.containers.retain(|_, c| c.pod_sandbox_id != id);
    registry
        .container_keys
        .retain(|(sandbox_id, _, _)| sandbox_id != id);
    registry.container_retained_bytes = plan.remaining_containers;
    registry.records.remove(id);
    registry.retained_bytes = plan.remaining;
}

/// 件数・保持量を整合させたままサンドボックスの記録 1 件を除去する（配下のコンテナが無い前提。
/// `run_sandbox_networked` の回収済みの後始末だけが使う）。不整合なら何もしない。
fn remove_sandbox_record(registry: &mut SandboxRegistry, id: &str) {
    // 配下のコンテナが残っているなら親だけを消さない（孤児のコンテナ記録を作らない）。
    if registry.container_keys.iter().any(|(sid, _, _)| sid == id) {
        return;
    }
    if let Some(record) = registry.records.get(id)
        && let Some(remaining) = registry.retained_bytes.checked_sub(record.retained_bytes)
    {
        registry.records.remove(id);
        registry.retained_bytes = remaining;
    }
}

/// 実行層の成功を記録へ反映する（Create は `in_flight` 解除、Start は running へ遷移）。
fn commit_in_flight(
    registry: &Mutex<SandboxRegistry>,
    id: &str,
    kind: InFlightKind,
    exit: ExitReport,
) -> Result<(), CriError> {
    let at_nanos = now_nanos()?;
    if kind == InFlightKind::Remove {
        // 実行層の削除と bundle の解放を終えた。記録・名前キー・件数枠を解放する（ロックは中で取る）。
        return drop_container_in(registry, id, true);
    }
    let mut registry = registry
        .lock()
        .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
    // Start の実行中に StopPodSandbox が入った場合、親が Ready でなければ running を確定しない。
    // Err を返すと guard の Drop が（結果不明として）exited へ倒す。
    if kind == InFlightKind::Start {
        let parent_ready = registry
            .containers
            .get(id)
            .and_then(|c| registry.records.get(&c.pod_sandbox_id))
            .is_some_and(|s| s.state == SandboxState::Ready);
        if !parent_ready {
            return Err(CriError::failed_precondition("sandbox is not ready"));
        }
    }
    let record = registry
        .containers
        .get_mut(id)
        .ok_or_else(|| CriError::internal("container registry is inconsistent"))?;
    record.in_flight = false;
    if kind == InFlightKind::Create {
        // 実行層に資源（コンテナ・bundle）が存在する。Remove は実行層の delete 経由で解放し
        // （TASK-59.3）、それまで追跡情報・名前キー・件数枠を保持する。
        record.runtime_owned = true;
    }
    if kind == InFlightKind::Stop {
        // 実行層が停止済みと報告した。現在時刻を終了時刻とする。
        record.state = ContainerState::Exited;
        record.finished_at_nanos = at_nanos;
        // 実行層が返した終了コード（137 等）を保持する。不明（None）は None のままで reason は空になる。
        record.exit_code = exit.code;
        record.termination = exit.termination;
    }
    if kind == InFlightKind::Start {
        record.state = ContainerState::Running;
        record.started_at_nanos = at_nanos;
    }
    Ok(())
}

/// 実行層の呼び出しが失敗・中断したときの巻き戻し。Create は記録を除去し、Start は `in_flight` を解く。
///
/// Create で `outcome_unknown` のときは、実行層に資源が残る可能性があるため記録を除去せず unknown として
/// 残す（追跡情報と件数枠を保持。回収は Remove の実行層 delete〔TASK-59.3〕と TASK-114）。
///
/// ロックの汚染時は何もできない（汚染済みのレジストリは以後の RPC が `INTERNAL` で拒否する）。
///
/// Start で `outcome_unknown` のときは、実行層が running の可能性があるため created へ戻さず
/// unknown（外向きは CONTAINER_UNKNOWN。終了時刻は設定しない）にする（再 Start による二重起動を防ぐ fail-closed。
/// Stop・Remove の再試行で実状態を照合する〔TASK-59.3〕）。
///
/// Stop・Remove の `outcome_unknown` も unknown で保持する（記録と `runtime_owned` を残し、再試行で回復できる）。
/// 確定失敗は `in_flight` を解くだけで状態を変えない。
fn rollback_in_flight(
    registry: &Mutex<SandboxRegistry>,
    id: &str,
    kind: InFlightKind,
    outcome_unknown: bool,
    confirmed_exited: bool,
    exit: ExitReport,
) {
    match kind {
        InFlightKind::Create if !outcome_unknown => {
            let _ = drop_container_in(registry, id, true);
        }
        InFlightKind::Stop | InFlightKind::Remove => {
            let finished_at_nanos = if confirmed_exited {
                now_nanos().unwrap_or(0)
            } else {
                0
            };
            if let Ok(mut registry) = registry.lock()
                && let Some(record) = registry.containers.get_mut(id)
            {
                record.in_flight = false;
                if confirmed_exited && !outcome_unknown {
                    // 実行層の削除完了後に bundle の解放だけが失敗した（Remove）。
                    if record.state != ContainerState::Exited {
                        record.state = ContainerState::Exited;
                        record.finished_at_nanos = finished_at_nanos;
                    }
                } else if outcome_unknown {
                    record.state = ContainerState::Unknown;
                }
            }
        }
        InFlightKind::Create | InFlightKind::Start => {
            let finished_at_nanos = if confirmed_exited {
                now_nanos().unwrap_or(0)
            } else {
                0
            };
            if let Ok(mut registry) = registry.lock()
                && let Some(record) = registry.containers.get_mut(id)
            {
                record.in_flight = false;
                if confirmed_exited {
                    record.state = ContainerState::Exited;
                    record.finished_at_nanos = finished_at_nanos;
                    // 実行層が終了済みと報告した応答の終了コード。不明（None）は reason を空のままにする。
                    record.exit_code = exit.code;
                    record.termination = exit.termination;
                } else if outcome_unknown {
                    // 停止を確認できないため exited にせず unknown で保持する（終了時刻・終了コードは設定しない。
                    // 生存中のプロセスを終了済みと公開して重複実行を招かない。CRI-2・REPAIR-5）。
                    record.state = ContainerState::Unknown;
                    // Create の結果不明は実行層に資源が残りうる。Remove は実行層の delete 経由で行う（TASK-59.3）。
                    if kind == InFlightKind::Create {
                        record.runtime_owned = true;
                    }
                }
            }
        }
    }
}

/// 報告された補助グループ 1 件あたりの保持量の見積もり（u32 の大きさ）。
const APPLIED_GID_RETAINED_BYTES: usize = 4;
/// `AppliedUser` 1 件の保持量の固定分の見積もり（uid・gid・Vec の管理領域）。
const APPLIED_USER_RETAINED_BASE_BYTES: usize = 64;
/// `ResolvedImage` 1 件の保持量の固定分の見積もり（String の管理領域・Digest の管理領域。#2831）。
const RESOLVED_IMAGE_RETAINED_BASE_BYTES: usize = 64;

/// `BundleProvider::prepare` が報告した識別情報と stop signal を、実行層へ渡す前に記録へ反映する（#2771・CRI-2）。
///
/// `create_container_runtime` の worker から呼ぶ。識別情報の保持量（補助グループは最大 65,536 件）を
/// `container_retained_bytes` と記録の `retained_bytes` の両方へ足す（`drop_container_in` が同じ量を引き戻すため
/// 枠は漏れない）。累積が上限を超えたら `FAILED_PRECONDITION`（黙って切り詰めない）。記録が無い・矛盾は `INTERNAL`。
fn attach_prepared(
    registry: &Mutex<SandboxRegistry>,
    container_id: &str,
    prepared: &PreparedBundle,
    max_retained_bytes: usize,
) -> Result<(), CriError> {
    let user_extra = prepared.user().map_or(0, |u| {
        u.additional_gids()
            .len()
            .saturating_mul(APPLIED_GID_RETAINED_BYTES)
            .saturating_add(APPLIED_USER_RETAINED_BASE_BYTES)
    });
    // image の報告分（参照文字列と image ID。長さは `ResolvedImage` が上限内に保つ。#2831）。
    let image_extra = prepared.image().map_or(0, |i| {
        i.image_ref()
            .len()
            .saturating_add(i.id_str().len())
            .saturating_add(i.tag().map_or(0, str::len))
            .saturating_add(RESOLVED_IMAGE_RETAINED_BASE_BYTES)
    });
    let extra = user_extra.saturating_add(image_extra);
    let mut registry = registry
        .lock()
        .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
    let total = registry
        .container_retained_bytes
        .checked_add(extra)
        .filter(|total| *total <= max_retained_bytes)
        .ok_or_else(|| CriError::failed_precondition("container config storage is full"))?;
    let record = registry
        .containers
        .get_mut(container_id)
        .ok_or_else(|| CriError::internal("container registry is inconsistent"))?;
    let retained = record
        .retained_bytes
        .checked_add(extra)
        .ok_or_else(|| CriError::internal("container registry is inconsistent"))?;
    record.retained_bytes = retained;
    record.applied_user = prepared.user().cloned();
    record.resolved_image = prepared.image().cloned();
    if let Some(signal) = prepared.stop_signal() {
        record.stop_signal = signal as i32;
    }
    registry.container_retained_bytes = total;
    Ok(())
}

/// kubelet に伝える実行時の機能フラグ（`StatusResponse.features`。KEP-3619 等。#2771・#2830・CRI-2）。
///
/// `supplemental_groups_policy` は、`supplemental_groups` と `supplemental_groups_policy`（Merge / Strict）の受け入れ、
/// `ContainerStatus.user.linux` の報告、イメージ config の StopSignal の解釈が揃ったため真にする。
/// `mount_options`・`user_namespaces_host_network` は、対応する入力（`mounts.mount_options`・userns 写像）を
/// bundle の変換が拒否している間は偽のままにする（`docs/design/cri-status-rpc.md`）。
/// `Status` RPC の応答の `features` にそのまま乗る（CRI-1・CRI-2）。
pub fn runtime_features() -> v1::RuntimeFeatures {
    v1::RuntimeFeatures {
        supplemental_groups_policy: true,
        ..Default::default()
    }
}

/// `RuntimeReady` の condition 種別（kubelet が見る固定の語彙。CRI-1）。
const CONDITION_RUNTIME_READY: &str = "RuntimeReady";
/// `NetworkReady` の condition 種別（kubelet が見る固定の語彙。CRI-1）。
const CONDITION_NETWORK_READY: &str = "NetworkReady";

/// `Status` が報告する runtime handler の一覧（`SUPPORTED_RUNTIME_HANDLERS` から組み立てる。#2830・CRI-2）。
///
/// 既定ハンドラ（名前が空）だけを返す。各フラグは、対応する入力を bundle の変換が拒否している間は偽にする
/// （`recursive_read_only_mounts` は `mounts.recursive_read_only`、`user_namespaces` は userns 写像〔#2240〕の拒否）。
/// その拒否を外す変更は、ここのフラグも真にすること（REPAIR-3）。
pub fn runtime_handlers() -> Vec<v1::RuntimeHandler> {
    SUPPORTED_RUNTIME_HANDLERS
        .iter()
        .map(|name| v1::RuntimeHandler {
            name: (*name).to_string(),
            features: Some(v1::RuntimeHandlerFeatures {
                recursive_read_only_mounts: false,
                user_namespaces: false,
            }),
        })
        .collect()
}

/// `RuntimeCondition` を組み立てる（`Status` 専用。reason・message は固定の英語文言で、入力や内部パスを含めない）。
fn condition(kind: &str, status: bool, reason: &str, message: &str) -> v1::RuntimeCondition {
    v1::RuntimeCondition {
        r#type: kind.to_string(),
        status,
        reason: reason.to_string(),
        message: message.to_string(),
    }
}

/// コンテナ記録の除去（件数・保持量の枠と名前キーの解放）。worker からも呼ぶため registry を直接受ける。
fn drop_container_in(
    registry: &Mutex<SandboxRegistry>,
    container_id: &str,
    include_in_flight: bool,
) -> Result<(), CriError> {
    let mut registry = registry
        .lock()
        .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
    let Some(record) = registry.containers.get(container_id) else {
        return Ok(());
    };
    if record.in_flight && !include_in_flight {
        return Err(CriError::failed_precondition(
            "container operation in progress",
        ));
    }
    if record.runtime_owned && !include_in_flight {
        return Err(CriError::failed_precondition(
            "container resources are pending runtime cleanup",
        ));
    }
    // 先に検証してから変更し、失敗時にレジストリを変更しない。
    let inconsistent = || CriError::internal("container registry is inconsistent");
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
            registry: Arc::new(Mutex::new(SandboxRegistry::default())),
            limits,
            container_limits: ContainerLimits::default(),
            recorder,
            runtime: None,
            runtime_timeout: DEFAULT_RUNTIME_TIMEOUT,
            pod_network: None,
            pod_cidrs: Mutex::new(None),
            record_store: None,
        }
    }

    /// `UpdateRuntimeConfig` で最後に受け入れた pod CIDR（未受信・空のみなら `None`）。
    ///
    /// 未実装（REPAIR-3）: 読む利用者はまだ無く、`PodSubnetPool` への結線は pod network の本番注入と一緒に後続で行う。
    pub fn pod_cidrs(&self) -> Option<PodCidrs> {
        self.pod_cidrs.lock().ok().and_then(|g| g.clone())
    }

    /// `RunPodSandbox`（`namespace_options.network` が `POD`）で pod の netns を `NetworkPlugin` 経由で
    /// 作って結線する注入点を差す（#2675・CRI-2・NET-1・PLUG-1）。
    ///
    /// 呼ばなければ従来どおりネットワークに触れない。`StopPodSandbox`・`RemovePodSandbox` が `tear_down` で
    /// 回収し、`CreateContainer` が結線済みの netns のパスを bundle の `linux.namespaces` へ渡す。
    /// **注意（REPAIR-3）**: core の start は network namespace の join を未実装で拒否する
    /// （`docs/design/cri-config-acceptance.md` の順 13）。core の対応まで本番では差さない。
    pub fn with_pod_network(mut self, provider: Arc<dyn PodNetworkProvider>) -> Self {
        self.pod_network = Some(provider);
        self
    }

    /// sandbox 記録の書き込み先を差す注入点（#2933・CRI-1・CRI-2・REPAIR-3。設計は
    /// `docs/design/cri-record-readoption.md`）。
    ///
    /// 呼ばなければ従来どおり何も書かない。差すと次の時点で記録を書く・消す。
    /// - `RunPodSandbox`: 副作用の前に `pending` つきで書き（write-ahead。pod network ありの経路のみ）、
    ///   成功したら確定版へ置き換える。副作用の前の書き込みが失敗したら副作用を起こさず `INTERNAL` で失敗する
    /// - `StopPodSandbox`: 回収まで済んだら状態を書く。`RemovePodSandbox`: 資源の回収と検査が済んだら記録を消す
    ///
    /// 書き込み・削除の失敗は、ストアのコードによらず固定文言の `INTERNAL` に正規化する（成功を装わない。
    /// 確定・更新の失敗ではメモリの記録を残す）。`put` / `remove` は registry のロックの外で、専用スレッドの
    /// worker に `runtime_timeout` の期限つきで渡す（`store_io_bounded`。tokio の worker を塞がない）。
    /// 同じ ID への並行操作は `SandboxRecord::record_write` で拒否し、その guard は worker が持つため、期限超過
    /// 後も worker の完了まで保たれる。予約の巻き戻し用の `put` が期限超過・future の破棄で手放された場合は、
    /// 遅れて書けた worker が自分で記録を消す（別 worker の削除と競合させない）。副作用の前に future が破棄
    /// されたときも、予約（件数・保持量）は put の worker が終わって記録を消すまで保たれる。
    ///
    /// 未実装（REPAIR-3）: コンテナ記録の書く・消す時点は R5 #2934、起動時の読み込みと再採用は R6 #2935・
    /// R7 #2936、本番の配線は R9 #2938。
    pub fn with_record_store(mut self, store: Arc<dyn RecordStore>) -> Self {
        self.record_store = Some(store);
        self
    }

    /// `CreateContainer`・`StartContainer` を実行層（`ContainerRuntime`）へ接続する（TASK-59.2・CRI-2）。
    ///
    /// 呼ばなければ従来のスタブ動作（プロセスを起動しない記録上の遷移）のまま。接続後は両 RPC が
    /// 実行層の呼び出しは専用スレッドで行い、完了待ちは呼び出し元の future が担う。
    pub fn with_runtime(
        mut self,
        adapter: RuntimeAdapter,
        bundles: Arc<dyn BundleProvider>,
    ) -> Self {
        self.runtime = Some(RuntimeBinding { adapter, bundles });
        self
    }

    /// `Status` の応答を組み立てる（CRI-1・CRI-2・REPAIR-3・REPAIR-5・#2830）。
    ///
    /// kubelet が約 5 秒ごとに呼ぶため待ちを持たない: I/O・スレッド生成・実行層の呼び出し・レジストリのロック取得を
    /// 一切せず、持っている構成だけで判定する（REPAIR-5 の期限は構造上いらない）。
    /// 死活確認は足さない（#2897。判断と再評価条件は `docs/design/cri-status-rpc.md`）。
    ///
    /// - `RuntimeReady`: 実行層を注入済み（`with_runtime`）かつレジストリが poisoned でないとき真。未接続は
    ///   `RuntimeNotConnected`、poisoned は `RuntimeStateUnavailable` で偽（記録だけの構成を ready と装わない）。
    ///   poisoned でも RPC は `OK` で返す（kubelet はどちらもランタイム停止として扱い、condition なら理由が伝わる）
    /// - `NetworkReady`: `PodNetworkProvider` を注入済み（`with_pod_network`）なら真、無ければ
    ///   `NetworkPluginNotReady`（containerd と同じ語彙）で偽。本番の plugin-cri は core の network namespace の
    ///   join が入るまで注入しないため偽になり、kubelet は hostNetwork でない Pod を拒否する
    /// - `verbose` は受け付けるが `info` は常に空（内部のパス・構成を応答に出さない。proto は空の `info` を許す）
    fn status_response(&self, _req: &v1::StatusRequest) -> Result<v1::StatusResponse, CriError> {
        let runtime_condition = if self.runtime.is_none() {
            condition(
                CONDITION_RUNTIME_READY,
                false,
                "RuntimeNotConnected",
                "container runtime backend is not connected",
            )
        } else if self.registry.is_poisoned() {
            condition(
                CONDITION_RUNTIME_READY,
                false,
                "RuntimeStateUnavailable",
                "runtime state registry is unavailable",
            )
        } else {
            condition(CONDITION_RUNTIME_READY, true, "", "")
        };
        let network_condition = if self.pod_network.is_some() {
            condition(CONDITION_NETWORK_READY, true, "", "")
        } else {
            condition(
                CONDITION_NETWORK_READY,
                false,
                "NetworkPluginNotReady",
                "pod network provider is not configured",
            )
        };
        Ok(v1::StatusResponse {
            status: Some(v1::RuntimeStatus {
                conditions: vec![runtime_condition, network_condition],
            }),
            info: HashMap::new(),
            runtime_handlers: runtime_handlers(),
            features: Some(runtime_features()),
        })
    }

    /// 実行層の応答待ちの上限を指定する（既定 10 秒。REPAIR-5）。超過した RPC は `DEADLINE_EXCEEDED`。
    pub fn with_runtime_timeout(mut self, timeout: Duration) -> Self {
        self.runtime_timeout = timeout;
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
    ///
    /// `network_pending` が真なら、pod の netns の用意が終わるまで配下の作成と Stop・Remove を拒否する印を付ける。
    fn reserve_sandbox(
        &self,
        req: v1::RunPodSandboxRequest,
        network_pending: bool,
    ) -> Result<(v1::RunPodSandboxResponse, Vec<PodPortPublish>), CriError> {
        let ValidatedRun {
            config,
            runtime_handler,
        } = validate_run_request(req)?;
        // port_mappings は資源・記録を作る前に検証する。公開できるのは provider 注入下の POD だけで
        // （`network_pending` はその経路の印）、それ以外で公開する要素があれば `UNIMPLEMENTED`（CRI-2・NET-3）。
        let publishes = parse_port_mappings(config.port_mappings())?;
        if !network_pending && !publishes.is_empty() {
            return Err(CriError::unimplemented("port_mappings is not supported"));
        }
        let retained_bytes = config.retained_bytes();

        let created_at_nanos = now_nanos()?;

        let mut registry = self
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        // 重複判定は上限検査より先に行う（満杯でも具体的な ALREADY_EXISTS を返す。ERR-3）。
        let duplicate = config.metadata().is_some_and(|m| {
            registry.records.values().any(|r| {
                r.config.metadata.as_ref().is_some_and(|e| {
                    e.name == m.name
                        && e.namespace == m.namespace
                        && e.uid == m.uid
                        && e.attempt == m.attempt
                })
            })
        });
        if duplicate {
            return Err(CriError::already_exists("sandbox already exists"));
        }
        if registry.records.len() >= self.limits.max_sandboxes {
            return Err(CriError::failed_precondition("too many sandboxes"));
        }
        let total_retained_bytes = registry
            .retained_bytes
            .checked_add(retained_bytes)
            .filter(|total| *total <= self.limits.max_retained_bytes)
            .ok_or_else(|| CriError::failed_precondition("sandbox config storage is full"))?;
        let mut pod_sandbox_id = None;
        for _ in 0..ID_RETRY_LIMIT {
            let candidate = generate_id();
            if !registry.records.contains_key(&candidate) {
                pod_sandbox_id = Some(candidate);
                break;
            }
        }
        let pod_sandbox_id =
            pod_sandbox_id.ok_or_else(|| CriError::internal("failed to allocate sandbox id"))?;
        registry.records.insert(
            pod_sandbox_id.clone(),
            SandboxRecord {
                config: config.into_config(),
                // netns の用意が済むまでは Ready にしない（List・Status に未完了の sandbox を見せない。CRI-2）。
                // `run_sandbox_networked` の worker が set_up 成功を確定するロック内で Ready へ遷移させる。
                state: if network_pending {
                    SandboxState::NotReady
                } else {
                    SandboxState::Ready
                },
                created_at_nanos,
                runtime_handler,
                retained_bytes,
                network_pending,
                network_owned: false,
                network_teardown: false,
                pod_netns: None,
                // ストアを注入しているときは、確定の書き込みが済むまで並行操作を拒否する。
                record_write: u32::from(self.record_store.is_some()),
            },
        );
        registry.retained_bytes = total_retained_bytes;
        Ok((v1::RunPodSandboxResponse { pod_sandbox_id }, publishes))
    }

    /// pod の netns を作って結線する `RunPodSandbox`（#2675・CRI-2・NET-1・PLUG-1）。
    ///
    /// 予約（重複・上限の確定。`network_pending` つき）→ ロックを外して worker スレッドで `set_up`
    /// （期限つき。REPAIR-5）→ 成功なら記録へ netns を入れて確定、の順。失敗した場合は `tear_down` で回収を試み、
    /// 回収できたら記録を除去して元のエラーを返す。回収に失敗した・期限超過で結果が不明な場合は、資源が
    /// 残りうるため記録を notready で残し（`network_owned`）、Stop・Remove の `tear_down` で回収できるようにする。
    /// 期限超過の判定から記録を取るまでの間に worker が成功を確定した場合は成功として返す（[`SetUpSettlement`]）。
    async fn run_sandbox_networked(
        &self,
        provider: &Arc<dyn PodNetworkProvider>,
        req: v1::RunPodSandboxRequest,
    ) -> Result<v1::RunPodSandboxResponse, CriError> {
        let (resp, publishes) = self.reserve_sandbox(req, true)?;
        let id = resp.pod_sandbox_id.clone();
        // 確定の書き込みが済むまで（set_up を含む全体）同じ ID への並行操作を拒否する。
        let mut write_guard = self.write_guard(&id);
        // write-ahead: set_up（副作用）の前に pending つきで書く。失敗したら副作用を起こさず巻き戻す
        // （#2933・CRI-2・REPAIR-3）。失敗・破棄時の予約（`network_pending`・重複判定・件数・保持量）の巻き戻しは
        // `persist_sandbox_rollbackable` が持つ。手放した put は worker が遅れて書けた記録を消し、予約を戻す。
        self.persist_sandbox_rollbackable(&id, true, &mut write_guard)
            .await?;
        // 以降は await を挟まず `NetworkSetUpGuard` が引き継ぐ。
        let config = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            registry
                .records
                .get(&id)
                .map(|r| r.config.clone())
                .ok_or_else(|| CriError::internal("sandbox record is unavailable"))?
        };
        let worker_provider = Arc::clone(provider);
        let worker_id = id.clone();
        let worker_registry = Arc::clone(&self.registry);
        // 記録の確定は worker 自身が set_up の完了直後に行う。期限超過で呼び出し側が先に結果不明として
        // 返っても、遅れて完了した set_up が `network_pending` を解除し、作った資源を `network_owned` で
        // 追跡させる（完了前の Stop・Remove の tear_down との競合で資源が漏れるのを防ぐ。CRI-2・NET-1）。
        let ran = Arc::new(AtomicBool::new(false));
        let worker_ran = Arc::clone(&ran);
        // 結果の確定権。worker と呼び出し側（期限超過・待ち受け失敗で結果不明として返す側）がロック下で
        // 奪い合い、呼び出し側が先なら遅れて成功しても Ready へは戻さず NotReady のまま資源だけ記録する
        // （失敗扱いで返した sandbox を Ready として公開しない。CRI-2・NET-1）。
        let settlement = Arc::new(SetUpSettlement::new());
        let worker_settlement = Arc::clone(&settlement);
        let guard = NetworkSetUpGuard {
            registry: Arc::clone(&self.registry),
            id: id.clone(),
        };
        let set_up = run_bounded(self.runtime_timeout, move || {
            let _guard = guard;
            worker_ran.store(true, Ordering::SeqCst);
            let result = worker_provider.set_up(
                &PodNetworkRequest::new(&worker_id, &config).with_port_publishes(&publishes),
            );
            let (netns, outcome) = match result {
                Ok(netns) => (Some(netns), Ok(())),
                Err(err) => (None, Err(err)),
            };
            if let Ok(mut registry) = worker_registry.lock()
                && let Some(record) = registry.records.get_mut(&worker_id)
            {
                // 失敗でも資源が残りうるため、回収の印は付ける（呼び出し側が回収後に外す）。
                // 失敗時は notready を worker がロック下で確定する（Ready のまま CreateContainer が通らないように）。
                record.network_owned = true;
                record.network_pending = false;
                let settled = worker_settlement.settle_by_worker();
                record.state = if outcome.is_ok() && settled {
                    SandboxState::Ready
                } else {
                    SandboxState::NotReady
                };
                record.pod_netns = netns;
            }
            outcome
        })
        .await
        .and_then(|r| r);
        match set_up {
            Ok(()) => {
                // 確定版（pending=0・ready・network_owned）へ置き換える。失敗したら成功を装わず、
                // メモリの記録は NotReady で残して（network_owned のまま Stop・Remove が回収できる）INTERNAL を返す。
                self.confirm_run(&id, &mut write_guard, resp).await
            }
            Err(err) => {
                // worker を起動できなかった（`ran` が偽の `UNAVAILABLE`）なら資源は作られていない。
                // 予約を巻き戻して記録を除去する（pending を残して Stop・Remove を塞がない）。
                if err.code() == CriErrorCode::Unavailable && !ran.load(Ordering::SeqCst) {
                    self.release_unwritten_sandbox(&id, &mut write_guard).await;
                    return Err(err);
                }
                // 期限超過・待ち受け側の失敗は worker がまだ走っている可能性があり、tear_down を同時に呼ばない。
                // `network_pending` を残し、worker の完了が解除するまで Stop・Remove を拒否する。
                let unknown = matches!(
                    err.code(),
                    CriErrorCode::Timeout | CriErrorCode::Unavailable
                );
                let mut published_ready = false;
                let reclaimed = if unknown {
                    false
                } else {
                    match self.reserve_tear_down(&id) {
                        Ok(Some(guard)) => {
                            self.tear_down_bounded(provider, &id, guard).await.is_ok()
                        }
                        _ => false,
                    }
                };
                if reclaimed {
                    // 資源は無い。記録ファイルを消せた worker が件数枠ごとメモリの記録を除去する
                    // （失敗しても元のエラーを返す。消せなければ notready の記録のまま残り Remove で回収できる）。
                    self.release_unwritten_sandbox(&id, &mut write_guard).await;
                } else if let Ok(mut registry) = self.registry.lock()
                    && let Some(record) = registry.records.get_mut(&id)
                {
                    // 期限超過の判定の後、ロックを取るまでに worker が成功を確定して Ready を公開していたら、
                    // set_up は完了しているので成功として返す（公開済みの Ready と失敗の応答を食い違わせない）。
                    if unknown && !settlement.abandon() && record.state == SandboxState::Ready {
                        published_ready = true;
                    } else {
                        record.state = SandboxState::NotReady;
                        record.network_owned = true;
                        // 結果不明のときは worker の完了まで pending を保つ。
                        if !unknown {
                            record.network_pending = false;
                        }
                    }
                }
                if published_ready {
                    // 成功として返す前に、この経路でも確定版（pending=0）を書く（ディスクに pending=1 を残さない）。
                    return self.confirm_run(&id, &mut write_guard, resp).await;
                }
                Err(err)
            }
        }
    }

    /// set_up の成功後に確定版（pending=0・ready・network_owned）を書いて応答を返す。失敗したら成功を
    /// 装わず、メモリの記録は NotReady で残して（Stop・Remove が回収できる）INTERNAL を返す。
    async fn confirm_run(
        &self,
        id: &str,
        guard: &mut Option<SandboxRecordWriteGuard>,
        resp: v1::RunPodSandboxResponse,
    ) -> Result<v1::RunPodSandboxResponse, CriError> {
        if let Err(err) = self.persist_sandbox_confirm(id, guard).await {
            if let Ok(mut registry) = self.registry.lock()
                && let Some(record) = registry.records.get_mut(id)
            {
                record.state = SandboxState::NotReady;
            }
            return Err(err);
        }
        Ok(resp)
    }

    /// 回収の開始をロック下で予約する（既に回収中・set_up 中なら `FAILED_PRECONDITION`）。
    ///
    /// 戻り値の guard を `tear_down_bounded` へ渡す。記録が無ければ `None`。
    fn reserve_tear_down(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<NetworkTearDownGuard>, CriError> {
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        let Some(record) = registry.records.get_mut(sandbox_id) else {
            return Ok(None);
        };
        if record.network_pending || record.network_teardown {
            return Err(CriError::failed_precondition(
                "sandbox network setup or teardown is in progress",
            ));
        }
        record.network_teardown = true;
        Ok(Some(NetworkTearDownGuard {
            registry: Arc::clone(&self.registry),
            id: sandbox_id.to_owned(),
        }))
    }

    /// `PodNetworkProvider::tear_down` を worker スレッドで期限つきに呼ぶ（REPAIR-5）。
    ///
    /// 成功は worker がロック下で `network_owned` を外して確定する（期限超過後に遅れて成功しても反映される）。
    /// guard は worker が終わるまで重複起動を拒否する。
    async fn tear_down_bounded(
        &self,
        provider: &Arc<dyn PodNetworkProvider>,
        sandbox_id: &str,
        guard: NetworkTearDownGuard,
    ) -> Result<(), CriError> {
        let provider = Arc::clone(provider);
        let id = sandbox_id.to_owned();
        let registry = Arc::clone(&self.registry);
        run_bounded(self.runtime_timeout, move || {
            let _guard = guard;
            let result = provider.tear_down(&id);
            if result.is_ok()
                && let Ok(mut registry) = registry.lock()
                && let Some(record) = registry.records.get_mut(&id)
            {
                record.network_owned = false;
                record.pod_netns = None;
            }
            result
        })
        .await
        .and_then(|r| r)
    }

    /// 資源が残りうる pod network を回収し、成功したら記録の印を外す（Stop・Remove から呼ぶ）。
    ///
    /// 注入が無い・印が無い場合は何もしない。set_up の最中は `FAILED_PRECONDITION`。失敗時は印を残して
    /// 再試行できるようにする（#2675・CRI-2・NET-1）。
    async fn release_pod_network(&self, sandbox_id: &str) -> Result<(), CriError> {
        let Some(provider) = &self.pod_network else {
            return Ok(());
        };
        {
            let registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            let Some(record) = registry.records.get(sandbox_id) else {
                return Ok(());
            };
            if record.network_pending {
                return Err(CriError::failed_precondition(
                    "sandbox network setup is in progress",
                ));
            }
            if !record.network_owned {
                return Ok(());
            }
        }
        let Some(guard) = self.reserve_tear_down(sandbox_id)? else {
            return Ok(());
        };
        self.tear_down_bounded(provider, sandbox_id, guard).await
    }

    /// `StopPodSandbox` 本体（実行層の有無で分岐）に、pod network の回収を足したもの。
    ///
    /// 配下の停止が成功したときだけネットワークを回収する（失敗時は配下が生きているため触れない）。
    async fn stop_sandbox_with_network(
        &self,
        req: v1::StopPodSandboxRequest,
    ) -> Result<v1::StopPodSandboxResponse, CriError> {
        self.ensure_record_not_writing(&req.pod_sandbox_id)?;
        if self.pod_network.is_some() && !req.pod_sandbox_id.is_empty() {
            self.ensure_network_not_pending(&req.pod_sandbox_id)?;
        }
        let id = req.pod_sandbox_id.clone();
        let resp = match &self.runtime {
            Some(binding) => self.stop_sandbox_runtime(binding, req).await,
            None => self.stop_sandbox(req),
        }?;
        self.release_pod_network(&id).await?;
        // 停止とネットワークの回収が済んだ時点の状態を書く（途中の失敗では書かない: ディスクの古い ready は
        // 安全側で、R6 は常に NotReady として再採用する）。失敗してもメモリは Stop 後のまま INTERNAL を返す。
        // 記録が無い（並行する Remove が完了した・未知 ID）ときは書く対象が無く、成功のまま返す。
        let Some(guard) = self.begin_record_write(&id)? else {
            return Ok(resp);
        };
        let mut write_guard = Some(guard);
        self.persist_sandbox(&id, false, &mut write_guard).await?;
        Ok(resp)
    }

    /// `RemovePodSandbox` 本体に、pod network の回収を足したもの。
    ///
    /// 資源が残りうるときは、先に配下の停止とネットワークの回収（Stop と同じ手順）を済ませ、成功してから
    /// 記録を除去する。失敗したら記録を残してエラーを返す。
    async fn remove_sandbox_with_network(
        &self,
        req: v1::RemovePodSandboxRequest,
    ) -> Result<v1::RemovePodSandboxResponse, CriError> {
        self.ensure_record_not_writing(&req.pod_sandbox_id)?;
        if self.pod_network.is_some() && !req.pod_sandbox_id.is_empty() {
            self.ensure_network_not_pending(&req.pod_sandbox_id)?;
            let owned = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?
                .records
                .get(&req.pod_sandbox_id)
                .is_some_and(|r| r.network_owned);
            if owned {
                self.stop_sandbox_with_network(v1::StopPodSandboxRequest {
                    pod_sandbox_id: req.pod_sandbox_id.clone(),
                })
                .await?;
            }
        }
        match &self.runtime {
            Some(binding) => self.remove_sandbox_runtime(binding, req).await,
            None => self.remove_sandbox(req).await,
        }
    }

    /// 記録ストアを注入しているときだけ、sandbox の `record_write` の guard を作る（フラグは立て済みであること）。
    fn write_guard(&self, id: &str) -> Option<SandboxRecordWriteGuard> {
        self.record_store.as_ref()?;
        Some(SandboxRecordWriteGuard {
            registry: Arc::clone(&self.registry),
            id: id.to_owned(),
        })
    }

    /// 既存の記録に `record_write` を 1 つ加えた guard を作る（手放した put の後始末スレッド用）。
    fn extra_write_guard(&self, id: &str) -> Option<SandboxRecordWriteGuard> {
        self.record_store.as_ref()?;
        let mut registry = self.registry.lock().ok()?;
        let record = registry.records.get_mut(id)?;
        record.record_write = record.record_write.saturating_add(1);
        Some(SandboxRecordWriteGuard {
            registry: Arc::clone(&self.registry),
            id: id.to_owned(),
        })
    }

    /// Stop・Remove が書く直前に、ロック下で `record_write` を確かめて立てる（#2933）。
    ///
    /// ストア未注入・記録なし（未知 ID）なら `None`（何もしない）。既に書き込み中なら `FAILED_PRECONDITION`。
    fn begin_record_write(&self, id: &str) -> Result<Option<SandboxRecordWriteGuard>, CriError> {
        if self.record_store.is_none() {
            return Ok(None);
        }
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        let Some(record) = registry.records.get_mut(id) else {
            return Ok(None);
        };
        if record.record_write > 0 {
            return Err(CriError::failed_precondition(SANDBOX_RECORD_BUSY));
        }
        record.record_write = 1;
        Ok(self.write_guard(id))
    }

    /// 入口の検査: 記録の書き込み中なら `FAILED_PRECONDITION`（ストア未注入・未知 ID は何もしない）。
    fn ensure_record_not_writing(&self, id: &str) -> Result<(), CriError> {
        if self.record_store.is_none() {
            return Ok(());
        }
        let registry = self
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        if registry.records.get(id).is_some_and(|r| r.record_write > 0) {
            return Err(CriError::failed_precondition(SANDBOX_RECORD_BUSY));
        }
        Ok(())
    }

    /// sandbox の現在の記録をスナップショットして記録ストアへ書く（#2933・CRI-1・CRI-2）。
    ///
    /// ストア未注入なら何もしない。スナップショットはロック下で取り、符号化はロックを外して行い、`put`
    /// （fsync）は専用 worker で期限つきに走らせる（[`Self::store_io_bounded`]。REPAIR-5）。失敗・期限超過は
    /// 種別によらず固定文言の `INTERNAL`。呼び出し側は `record_write` の guard を `guard` に渡すこと。
    async fn persist_sandbox(
        &self,
        id: &str,
        pending: bool,
        guard: &mut Option<SandboxRecordWriteGuard>,
    ) -> Result<(), CriError> {
        self.persist_sandbox_inner(id, pending, guard, PutMode::Plain)
            .await
    }

    /// 確定版（set_up 成功後）の put。失敗・期限超過・future の破棄のあとに worker が失敗しても、worker 自身が
    /// メモリの記録を notready にする（Ready のまま CreateContainer を通さない。#2933・CRI-2）。
    async fn persist_sandbox_confirm(
        &self,
        id: &str,
        guard: &mut Option<SandboxRecordWriteGuard>,
    ) -> Result<(), CriError> {
        self.persist_sandbox_inner(id, false, guard, PutMode::Confirm)
            .await
    }

    /// 書けなかったらメモリの予約ごと巻き戻す put。期限超過・future の
    /// 破棄で手放したあとに遅れて書けた記録は、worker が書いた直後に自分で消す。
    async fn persist_sandbox_rollbackable(
        &self,
        id: &str,
        pending: bool,
        guard: &mut Option<SandboxRecordWriteGuard>,
    ) -> Result<(), CriError> {
        self.persist_sandbox_inner(id, pending, guard, PutMode::Reservation)
            .await
    }

    async fn persist_sandbox_inner(
        &self,
        id: &str,
        pending: bool,
        guard: &mut Option<SandboxRecordWriteGuard>,
        mode: PutMode,
    ) -> Result<(), CriError> {
        if self.record_store.is_none() {
            return Ok(());
        }
        let confirm = mode == PutMode::Confirm;
        let reservation = mode == PutMode::Reservation;
        let rollback = (reservation || confirm).then(|| PutRollback {
            settlement: Arc::new(SetUpSettlement::new()),
            registry: Arc::clone(&self.registry),
            sandbox_id: id.to_owned(),
            spawn_failed: Arc::new(AtomicBool::new(false)),
            confirm,
        });
        let prepared = self.encode_sandbox(id, pending);
        let (record_id, bytes) = match prepared {
            Ok(v) => v,
            Err(err) => {
                // put に進めなかった（worker は無い）。予約の put なら予約を戻し、確定版なら notready にする。
                if let Some(rb) = &rollback {
                    rb.settle_unwritten();
                }
                return Err(err);
            }
        };
        // 巻き戻し用の put は、この future が破棄・期限超過で手放した時点で worker へ手放しを伝える。
        let extra_guard = if reservation {
            self.extra_write_guard(id)
        } else {
            None
        };
        let abandon = AbandonPutOnDrop {
            rollback: rollback.clone().filter(|rb| !rb.confirm),
            store: self.record_store.as_ref().map(Arc::clone),
            id: Some(record_id.clone()),
            extra_guard,
        };
        let result = self
            .store_io_bounded(StoreCall::Put(record_id, bytes, rollback.clone()), guard)
            .await;
        if let Some(rb) = rollback.as_ref().filter(|rb| !rb.confirm) {
            if result.is_ok() {
                // 書けた結果を受け取れた。以後の後始末は呼び出し側の経路が持つ。
                rb.settlement.accept();
            } else if rb.spawn_failed.load(Ordering::SeqCst) {
                // worker のスレッドを起動できなかった。ファイルは書かれないため予約を戻す。期限超過は
                // 起動済みの worker が後から put を実行するので、ここでは戻さない（worker が戻す）。
                rb.release_reservation();
            } else {
                // 期限超過なら worker へ手放しを伝える。put の失敗・遅れた完了の後始末（削除と予約の解放）は
                // worker 自身が行うため、ここでは削除も予約の解放もしない（中断で漏れない。#2933・CRI-2）。
                // worker が既に失敗の後始末を引き取っていれば何もしない。
                rb.settlement.abandon();
            }
        } else if let Some(rb) = &rollback
            && result.is_err()
            && rb.spawn_failed.load(Ordering::SeqCst)
        {
            // 確定版の put の worker を起動できなかった。メモリの記録を notready にする。
            rb.make_recoverable();
        }
        drop(abandon);
        result
    }

    /// 記録のスナップショットを取り、符号化する（ロックは符号化の前に外す）。
    fn encode_sandbox(&self, id: &str, pending: bool) -> Result<(RecordId, Vec<u8>), CriError> {
        let data = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            let record = registry
                .records
                .get(id)
                .ok_or_else(|| CriError::internal("sandbox record is unavailable"))?;
            SandboxRecordData::from_registry(id, record, pending)
        };
        let record_id =
            RecordId::new(id).map_err(|_| CriError::internal(SANDBOX_PERSIST_FAILED))?;
        let bytes = data.encode()?;
        Ok((record_id, bytes))
    }

    /// 記録ファイルを期限つきで消す（無ければ成功）。失敗・期限超過は固定文言の `INTERNAL`。
    async fn unpersist_sandbox(
        &self,
        id: &str,
        guard: &mut Option<SandboxRecordWriteGuard>,
        finalize: bool,
    ) -> Result<(), CriError> {
        if self.record_store.is_none() {
            return Ok(());
        }
        let record_id =
            RecordId::new(id).map_err(|_| CriError::internal(SANDBOX_UNPERSIST_FAILED))?;
        let finalize = finalize.then(|| RemoveFinalize {
            registry: Arc::clone(&self.registry),
            sandbox_id: id.to_owned(),
        });
        self.store_io_bounded(StoreCall::Remove(record_id, finalize), guard)
            .await
    }

    /// 記録ストアの I/O を専用 worker で走らせ、`runtime_timeout` まで待つ（REPAIR-5）。
    ///
    /// `put` / `remove` は fsync で無期限に止まりうるため、async の RPC から直接呼ばない。`guard` は worker へ
    /// 移し、成功したときだけ呼び出し側へ戻す。期限超過・失敗後は worker が完了するまで `record_write` が
    /// 立ったままになり（worker が guard を Drop する）、遅れて完了する書き込みと並行操作が交錯しない。
    async fn store_io_bounded(
        &self,
        call: StoreCall,
        guard: &mut Option<SandboxRecordWriteGuard>,
    ) -> Result<(), CriError> {
        let Some(store) = self.record_store.as_ref().map(Arc::clone) else {
            return Ok(());
        };
        let failure = match call {
            StoreCall::Put(..) => SANDBOX_PERSIST_FAILED,
            StoreCall::Remove(..) => SANDBOX_UNPERSIST_FAILED,
        };
        let moved = guard.take();
        let spawn_failed = match &call {
            StoreCall::Put(_, _, Some(rb)) => Some(Arc::clone(&rb.spawn_failed)),
            _ => None,
        };
        let outcome = run_bounded(self.runtime_timeout, move || {
            let result = match &call {
                StoreCall::Put(id, bytes, rollback) => {
                    // panic したら予約を回復可能な状態へ倒す（スロットを塞いだままにしない）。後始末の削除も
                    // 守るため、番人は後始末が済むまで外さない。
                    let mut panic_guard = PutWorkerGuard {
                        rollback: rollback.clone(),
                    };
                    let result = store.put(RecordKind::Sandbox, id, bytes);
                    // 巻き戻し用の put の後始末（ファイルの削除と予約の解放）は worker 自身が持つ。呼び出し側が
                    // 手放した（期限超過・future の破棄）場合と、put 自体が失敗した場合（書きかけが残りうる）は、
                    // 完了の直後にここで消す（別 worker の削除と競合させず、await の途中で中断されても
                    // 予約の解放・回復可能化が漏れない）。予約は削除に成功したときだけ戻す（失敗時は Stop・Remove で
                    // 回収できる notready の記録として残す。#2933・CRI-2・REPAIR-3・REPAIR-5）。
                    // 確定版の put が失敗したら notready にする（削除はしない。資源は既にある）。
                    if let Some(rb) = rollback {
                        let failed = result.is_err();
                        if rb.confirm {
                            if failed {
                                rb.make_recoverable();
                            }
                        } else {
                            if failed {
                                rb.settlement.take_failed_cleanup();
                            }
                            if failed || !rb.settlement.settle_by_worker() {
                                let removed = store.remove(RecordKind::Sandbox, id).is_ok();
                                rb.settle_after_remove(removed);
                            }
                        }
                    }
                    panic_guard.defuse();
                    result.map_err(|_| CriError::internal(SANDBOX_PERSIST_FAILED))
                }
                StoreCall::Remove(id, finalize) => match store.remove(RecordKind::Sandbox, id) {
                    Err(_) => Err(CriError::internal(SANDBOX_UNPERSIST_FAILED)),
                    Ok(()) => match finalize {
                        Some(f) => finalize_sandbox_removal(&store, f),
                        None => Ok(()),
                    },
                },
            };
            (result, moved)
        })
        .await;
        match outcome {
            Ok((result, returned)) => {
                *guard = returned;
                result
            }
            // 期限超過・起動失敗: guard は worker（または破棄されたクロージャ）が持つ。
            Err(err) => {
                // スレッドを起動できなかった（`UNAVAILABLE`）なら worker は走らない。期限超過とは区別する。
                if err.code() == CriErrorCode::Unavailable
                    && let Some(flag) = spawn_failed
                {
                    flag.store(true, Ordering::SeqCst);
                }
                Err(CriError::internal(failure))
            }
        }
    }

    /// 資源の無い sandbox の記録（予約・pending 記録）を、記録ファイルの削除に順序付けて解放する（失敗しても
    /// 元のエラーを優先して無視する）。
    ///
    /// 予約を先にメモリから外さない（削除がハングしたときに同じ metadata の Run が worker と pending ファイルを
    /// 無制限に積めてしまうため）。メモリの記録を notready・`network_pending=false` にしてから、ファイルを消せた
    /// worker が件数・保持量ごと除去する。削除が失敗・期限超過したときは notready の記録が残り、worker の完了まで
    /// `record_write` が重複 Run・Stop・Remove を拒否する。ストア未注入ならその場でメモリから除去する
    /// （#2933・CRI-2・REPAIR-3・REPAIR-5）。
    async fn release_unwritten_sandbox(
        &self,
        id: &str,
        guard: &mut Option<SandboxRecordWriteGuard>,
    ) {
        if let Ok(mut registry) = self.registry.lock() {
            if let Some(record) = registry.records.get_mut(id) {
                record.network_pending = false;
                record.network_owned = false;
                record.state = SandboxState::NotReady;
            }
            if self.record_store.is_none() {
                remove_sandbox_record(&mut registry, id);
                return;
            }
        }
        let _ = self.unpersist_sandbox(id, guard, true).await;
    }

    /// ネットワークなしの `RunPodSandbox`。予約 → 確定版を 1 回書く。
    ///
    /// 現時点では副作用が無いため pending を書かない（pending を書くと R6 が所有情報不足として保持し続ける）。
    /// 保持役の起動を入れる #2871 は、その前に pending の書き込みを足すこと（REPAIR-3）。
    async fn run_sandbox_plain(
        &self,
        req: v1::RunPodSandboxRequest,
    ) -> Result<v1::RunPodSandboxResponse, CriError> {
        let (resp, _) = self.reserve_sandbox(req, false)?;
        let id = resp.pod_sandbox_id.clone();
        let mut write_guard = self.write_guard(&id);
        // 予約の巻き戻しは `persist_sandbox_rollbackable` が持つ（put の worker が終わるまで予約を保つ）。
        self.persist_sandbox_rollbackable(&id, false, &mut write_guard)
            .await?;
        Ok(resp)
    }

    /// set_up の最中なら `FAILED_PRECONDITION`（未知 ID は何もしない）。
    fn ensure_network_not_pending(&self, sandbox_id: &str) -> Result<(), CriError> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        if registry
            .records
            .get(sandbox_id)
            .is_some_and(|r| r.network_pending || r.network_teardown)
        {
            return Err(CriError::failed_precondition(
                "sandbox network setup or teardown is in progress",
            ));
        }
        Ok(())
    }

    /// `StopPodSandbox` の本体。ready を notready へ遷移させる（冪等。CRI-1・TASK-57.2）。
    ///
    /// 未知 ID は `NOT_FOUND`、空 ID は `INVALID_ARGUMENT`。件数・保持量の枠は解放しない。
    /// エラー文言には入力の ID を含めない。
    fn stop_sandbox(
        &self,
        req: v1::StopPodSandboxRequest,
    ) -> Result<v1::StopPodSandboxResponse, CriError> {
        if req.pod_sandbox_id.is_empty() {
            return Err(CriError::invalid_argument("pod_sandbox_id is required"));
        }
        let finished_at_nanos = now_nanos()?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        if !registry.records.contains_key(&req.pod_sandbox_id) {
            return Err(CriError::not_found("sandbox not found"));
        }
        // 実行層の資源を持つ、または実行層を呼び出し中のコンテナを含む場合は、この経路（スタブ用）で
        // 停止済みと返さない。実行層接続時は `stop_sandbox_runtime` が担う（TASK-59.3）ため、ここに来るのは
        // 実行層未接続の異常系だけで、生きたプロセスを停止済みと返さない fail-closed。CRI-1・REPAIR-3。
        if registry
            .containers
            .values()
            .any(|c| c.pod_sandbox_id == req.pod_sandbox_id && (c.in_flight || c.runtime_owned))
        {
            return Err(CriError::failed_precondition(
                "container resources are pending runtime cleanup",
            ));
        }
        let Some(record) = registry.records.get_mut(&req.pod_sandbox_id) else {
            return Err(CriError::not_found("sandbox not found"));
        };
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
    ///
    /// 記録ストアを注入しているときは「検査と `record_write` の設定（ロック下）→ 記録ファイルの削除
    /// （ロック外）→ メモリの除去（ロック下）」の順で行う（#2933・CRI-1・CRI-2）。この時点で実行層・
    /// ネットワークの資源は回収済みで、所有の証明（ファイル）を先に消しても回収不能な資源は残らない。
    /// 削除に失敗したらメモリの記録を残して `INTERNAL`（再試行でファイルを消し直せる）。
    async fn remove_sandbox(
        &self,
        req: v1::RemovePodSandboxRequest,
    ) -> Result<v1::RemovePodSandboxResponse, CriError> {
        if req.pod_sandbox_id.is_empty() {
            return Err(CriError::invalid_argument("pod_sandbox_id is required"));
        }
        let id = req.pod_sandbox_id.as_str();
        if self.record_store.is_none() {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            if let Some(plan) = plan_sandbox_removal(&registry, id)? {
                apply_sandbox_removal(&mut registry, id, plan);
            }
            return Ok(v1::RemovePodSandboxResponse {});
        }
        // 検査を通ったときだけ record_write を立てる（拒否の応答でフラグを残さない）。
        let mut write_guard = {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            if plan_sandbox_removal(&registry, id)?.is_none() {
                return Ok(v1::RemovePodSandboxResponse {});
            }
            let Some(record) = registry.records.get_mut(id) else {
                return Ok(v1::RemovePodSandboxResponse {});
            };
            if record.record_write > 0 {
                return Err(CriError::failed_precondition(SANDBOX_RECORD_BUSY));
            }
            record.record_write = 1;
            self.write_guard(id)
        };
        // ファイルの削除とメモリの除去（再検査つき）は同じ worker が続けて行う。期限超過で先に返っても、
        // 遅れて完了した削除が「ファイルは無いのにメモリは Ready」を残さず、その間は `record_write` が
        // CreateContainer・Stop・Remove を拒否する（#2933・CRI-2）。再検査の失敗時は worker がファイルを
        // 書き直す（best effort）。
        self.unpersist_sandbox(id, &mut write_guard, true).await?;
        Ok(v1::RemovePodSandboxResponse {})
    }

    /// `CreateContainer` の本体（スタブ経路）。検証・採番・登録を行い、失敗時はレジストリを変更しない（TASK-58.1）。
    ///
    /// 状態は `Created`。実行層は呼ばない（実行層接続時は `create_container_runtime`。REPAIR-3）。
    /// エラー文言には入力値（ID・名前・labels）を含めない。
    fn create_container_impl(
        &self,
        req: v1::CreateContainerRequest,
    ) -> Result<v1::CreateContainerResponse, CriError> {
        let container_id = self.reserve_container(req, false)?.container_id;
        Ok(v1::CreateContainerResponse { container_id })
    }

    /// 検証・採番・登録を行う（`in_flight` は実行層を呼び出し中として登録するか）。
    ///
    /// 戻り値は [`ReservedContainer`]。`provider_config` は `in_flight` のときだけ複製して返す
    /// （bundle の供給元へ渡すため。上限検証済みで有界）。
    fn reserve_container(
        &self,
        req: v1::CreateContainerRequest,
        in_flight: bool,
    ) -> Result<ReservedContainer, CriError> {
        let ValidatedCreate {
            pod_sandbox_id,
            name,
            attempt,
            config,
        } = validate_create_request(req)?;
        let mut retained_bytes = config.retained_bytes();
        let created_at_nanos = now_nanos()?;

        let mut registry = self
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        let sandbox = registry
            .records
            .get(&pod_sandbox_id)
            .ok_or_else(|| CriError::not_found("sandbox not found"))?;
        if sandbox.state != SandboxState::Ready {
            return Err(CriError::failed_precondition("sandbox is not ready"));
        }
        if sandbox.network_pending {
            return Err(CriError::failed_precondition(
                "sandbox network setup is in progress",
            ));
        }
        if sandbox.record_write > 0 {
            return Err(CriError::failed_precondition(SANDBOX_RECORD_BUSY));
        }
        // CRI ログの書き先は実行層接続時だけ結合して保持する（検証は bundle の供給元と同じ関数。#2671）。
        let resolved_log_path = if in_flight {
            resolve_log_path(&sandbox.config, config.config())?
        } else {
            None
        };
        if let Some(path) = &resolved_log_path {
            retained_bytes = retained_bytes
                .checked_add(path.as_str().len())
                .ok_or_else(|| CriError::invalid_argument("config is too large"))?;
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
            return Err(CriError::already_exists("container already exists"));
        }
        if registry.containers.len() >= self.container_limits.max_containers() {
            return Err(CriError::failed_precondition("too many containers"));
        }
        let total_retained_bytes = registry
            .container_retained_bytes
            .checked_add(retained_bytes)
            .filter(|total| *total <= self.container_limits.max_retained_bytes())
            .ok_or_else(|| CriError::failed_precondition("container config storage is full"))?;
        let mut container_id = None;
        for _ in 0..ID_RETRY_LIMIT {
            let candidate = generate_id();
            if !registry.containers.contains_key(&candidate) {
                container_id = Some(candidate);
                break;
            }
        }
        let container_id =
            container_id.ok_or_else(|| CriError::internal("failed to allocate container id"))?;
        let config = config.into_config();
        let stop_signal = initial_stop_signal(config.stop_signal);
        let provider_config = in_flight.then(|| config.clone());
        let provider_sandbox_config = in_flight.then(|| sandbox.config.clone());
        let provider_pod_netns = in_flight
            .then(|| sandbox.pod_netns.as_ref().map(|n| n.path().to_path_buf()))
            .flatten();
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
                exit_code: None,
                termination: None,
                retained_bytes,
                resolved_log_path,
                in_flight,
                runtime_owned: false,
                stop_signal,
                applied_user: None,
                resolved_image: None,
            },
        );
        registry.container_keys.insert(key);
        registry.container_retained_bytes = total_retained_bytes;
        Ok(ReservedContainer {
            container_id,
            pod_sandbox_id: sandbox_id,
            provider_config,
            provider_sandbox_config,
            provider_pod_netns,
        })
    }

    /// 実行層接続時の `CreateContainer`（TASK-59.2・CRI-2）。
    ///
    /// 仮登録（`in_flight`）→ ロックを外して bundle 用意と `ContainerRuntime::create`（専用スレッド）→
    /// 確定、の 2 相。どの失敗・中断でも [`InFlightGuard`] が記録を巻き戻し、上限の枠を残さない。
    async fn create_container_runtime(
        &self,
        binding: &RuntimeBinding,
        req: v1::CreateContainerRequest,
    ) -> Result<v1::CreateContainerResponse, CriError> {
        let reserved = self.reserve_container(req, true)?;
        let container_id = reserved.container_id;
        let sandbox_id = reserved.pod_sandbox_id;
        let config = reserved
            .provider_config
            .ok_or_else(|| CriError::internal("container config is unavailable"))?;
        let sandbox_config = reserved
            .provider_sandbox_config
            .ok_or_else(|| CriError::internal("sandbox config is unavailable"))?;
        let pod_netns = reserved.provider_pod_netns;
        // bundle の用意・create・確定・巻き戻し・bundle の解放はすべて worker が所有する。RPC の future が
        // 中断・タイムアウトしても、実行層が処理中の間に記録・件数枠・bundle だけが解放されることはない。
        let mut guard = InFlightGuard::new(
            Arc::clone(&self.registry),
            container_id.clone(),
            InFlightKind::Create,
        );
        let adapter = binding.adapter.clone();
        let bundles = Arc::clone(&binding.bundles);
        let id = container_id.clone();
        let timeout = self.runtime_timeout;
        let registry = Arc::clone(&self.registry);
        let max_retained_bytes = self.container_limits.max_retained_bytes();
        // RPC の期限切れ・future の破棄で、dispatch 前の worker を打ち切る（#2899）。dispatch 後は打ち切らない
        // （core の create は外部プロセスとファイル I/O を伴い、途中で止める口が無い。docs/design/container-log-removal-wait.md）。
        let settlement = Arc::new(SetUpSettlement::new());
        let cancel = Arc::new(AtomicBool::new(false));
        let mut abandon_on_drop = AbandonOnDrop {
            settlement: Arc::clone(&settlement),
            cancel: Arc::clone(&cancel),
            armed: true,
        };
        let outcome = run_bounded(self.runtime_timeout, move || -> Result<(), CriError> {
            // worker が実際に走り出してから bundle の解放責務を持つ（起動失敗時は RPC スレッドで release しない）。
            guard.arm_bundles(Arc::clone(&bundles));
            // 起動前に手放されていたら prepare もしない（guard の Drop が release と記録の巻き戻しを行う）。
            if settlement.is_abandoned() {
                return Err(CriError::timeout("runtime operation timed out"));
            }
            // pod の ipc 共有（BundleRequest::with_pod_namespaces）は pod の保持役が未実装のため当面渡さない
            // （常に新しい namespace。CRI-2・CORE-3。#2674 の後続 issue で保持役とともに結線する）。
            // 結線するときは sandbox の記録の保持役の pid から PodNamespacePaths::for_holder_pid で作る（#2776）。
            let bundle = bundles.prepare(
                &BundleRequest::new(&id, &sandbox_id, &sandbox_config, &config)
                    .with_pod_netns_path(pod_netns.as_deref())
                    .with_cancel(&cancel),
            )?;
            // 実行層へ渡す前に、報告された識別情報と解決済みの stop signal を記録へ反映する。保持量の上限を
            // 超えたらここで失敗し、guard が bundle の解放と記録の巻き戻しを行う（#2771）。
            attach_prepared(&registry, &id, &bundle, max_retained_bytes)?;
            // dispatch の可否は呼び出し側との compare_exchange 1 回で決める。負けたら（手放し済み）まだ何も
            // 実行層へ渡していないため、`outcome_unknown` は偽のまま guard が bundle を解放し記録を除去する。
            if !settlement.settle_by_worker() {
                return Err(CriError::timeout("runtime operation timed out"));
            }
            // 以後は実行層に資源が残りうる。確定失敗または削除完了を確認できた場合だけ解放する（fail-closed）。
            guard.mark_dispatched();
            let status = match adapter.create(&id, bundle.path().to_path_buf()) {
                Ok(status) => status,
                Err(status) => {
                    if is_definite_failure(status.code()) || confirm_removed(&adapter, &id, timeout)
                    {
                        guard.mark_definitely_failed();
                    }
                    return Err(status);
                }
            };
            // 完了契約: 厳密に Created のときだけ成功とする（Creating は CRI 上 ContainerCreated に写るが、
            // 作成途中で未完了のため成功にせず、削除を確認できるまで資源を保持する。REPAIR-5・CRI-2）。
            if status.lifecycle != RuntimeLifecycle::Created {
                if confirm_removed(&adapter, &id, timeout) {
                    guard.mark_definitely_failed();
                }
                return Err(CriError::internal("runtime returned an unexpected state"));
            }
            if let Err(status) = guard.commit() {
                if confirm_removed(&adapter, &id, timeout) {
                    guard.mark_definitely_failed();
                }
                return Err(status);
            }
            Ok(())
        })
        .await;
        // 結果を受け取れた（worker が最後まで走った）ときだけ手放さない。期限切れ・worker の失敗は手放す。
        if outcome.is_ok() {
            abandon_on_drop.disarm();
        }
        outcome??;
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
    ) -> Result<v1::StartContainerResponse, CriError> {
        self.begin_start(req, false)?;
        Ok(v1::StartContainerResponse {})
    }

    /// Start の前提検査。`via_runtime` なら `in_flight` を立てて返し、そうでなければ running へ遷移させる。
    fn begin_start(
        &self,
        req: v1::StartContainerRequest,
        via_runtime: bool,
    ) -> Result<(), CriError> {
        if req.container_id.is_empty() {
            return Err(CriError::invalid_argument("container_id is required"));
        }
        let started_at_nanos = now_nanos()?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        let record = registry
            .containers
            .get(&req.container_id)
            .ok_or_else(|| CriError::not_found("container not found"))?;
        let sandbox = registry
            .records
            .get(&record.pod_sandbox_id)
            .ok_or_else(|| CriError::internal("container registry is inconsistent"))?;
        if sandbox.state != SandboxState::Ready {
            return Err(CriError::failed_precondition("sandbox is not ready"));
        }
        if record.state != ContainerState::Created || record.in_flight {
            return Err(CriError::failed_precondition(
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

    /// 記録に保持した CRI ログの書き先を取り出す（無ければ `None`）。保持時に検証済みで、ここで失敗しない想定。
    fn start_log_path(&self, id: &str) -> Result<Option<ContainerLogPath>, CriError> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        Ok(registry
            .containers
            .get(id)
            .and_then(|r| r.resolved_log_path.clone()))
    }

    /// 実行層接続時の `StartContainer`（TASK-59.2・CRI-2）。
    ///
    /// 前提検査と `in_flight` 化をロック下で行い、ロックを外して `ContainerRuntime::start`
    /// （専用スレッド）を呼ぶ。成功して running が返ったときだけ記録を running にし、失敗・中断では
    /// created へ戻す（[`InFlightGuard`]）。
    async fn start_container_runtime(
        &self,
        binding: &RuntimeBinding,
        req: v1::StartContainerRequest,
    ) -> Result<v1::StartContainerResponse, CriError> {
        let id = req.container_id.clone();
        self.begin_start(req, true)?;
        let mut guard =
            InFlightGuard::new(Arc::clone(&self.registry), id.clone(), InFlightKind::Start);
        // 書き先の取得に失敗しても、実行層を呼ぶ前なので guard の破棄で created へ戻る。
        let log_path = self.start_log_path(&id)?;
        let adapter = binding.adapter.clone();
        let timeout = self.runtime_timeout;
        // 結果の確定と巻き戻しは worker が所有する。期限超過・中断では結果不明のまま worker が終わるのを待ち、
        // その間 `in_flight` が残る（新たな Start・Remove は拒否される）。
        run_bounded(self.runtime_timeout, move || -> Result<(), CriError> {
            // 専用スレッドの起動に失敗した場合は未送信なので、送信の直前に結果不明へ倒す。
            guard.mark_dispatched();
            let status = match adapter.start_with_log_path(&id, log_path) {
                Ok(status) => status,
                Err(status) => {
                    // 確定失敗のコードに限り created へ戻す。タイムアウト・Unavailable・Internal 等は
                    // 実行層が起動済みの可能性があるため、unknown のまま破棄して exited にする（fail-closed）。
                    if start_failure_is_definite(&adapter, &id, status.code(), timeout) {
                        guard.mark_definitely_failed();
                    }
                    return Err(status);
                }
            };
            match status.state {
                CriContainerState::ContainerRunning => guard.commit(),
                // Creating は未起動と確定できない（結果不明のまま exited へ倒す）。
                CriContainerState::ContainerCreated
                    if status.lifecycle != RuntimeLifecycle::Created =>
                {
                    Err(CriError::internal("runtime returned an unexpected state"))
                }
                // 実行層は created のままと報告した（起動していない）ため、created へ戻してよい。
                CriContainerState::ContainerCreated => {
                    guard.mark_definitely_failed();
                    Err(CriError::internal("runtime returned an unexpected state"))
                }
                // 終了済みは created へ戻さず、guard の破棄で exited へ反映する（再 Start を実行層へ届けない）。
                CriContainerState::ContainerExited => {
                    guard.set_exit(&status);
                    guard.mark_confirmed_exited();
                    Err(CriError::failed_precondition(
                        "container has already exited",
                    ))
                }
                // 結果不明は exited（fail-closed）。
                _ => Err(CriError::internal("runtime returned an unexpected state")),
            }
        })
        .await??;
        Ok(v1::StartContainerResponse {})
    }

    /// 実行層接続時の `StopContainer`（TASK-59.3・CRI-2）。
    ///
    /// 実行層の資源を持つ記録（`runtime_owned`）だけを `ContainerRuntime::stop` へ渡す。それ以外
    /// （スタブ経路の記録）は従来の記録上の遷移。exited・created は冪等に成功し実行層を呼ばない
    /// （created の init は残り、回収は `RemoveContainer` の `delete(force)` が担う。#2032）。
    /// running と unknown（結果不明の回復）は仮登録して実行層を呼ぶ。
    async fn stop_container_runtime(
        &self,
        binding: &RuntimeBinding,
        req: v1::StopContainerRequest,
    ) -> Result<v1::StopContainerResponse, CriError> {
        if req.container_id.is_empty() {
            return Err(CriError::invalid_argument("container_id is required"));
        }
        if req.timeout < 0 {
            return Err(CriError::invalid_argument("timeout must not be negative"));
        }
        if req.timeout > STOP_GRACE_MAX_SECS {
            return Err(CriError::invalid_argument("timeout is too large"));
        }
        let guard = {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            let record = registry
                .containers
                .get_mut(&req.container_id)
                .ok_or_else(|| CriError::not_found("container not found"))?;
            if !record.runtime_owned {
                drop(registry);
                return self.stop_container_impl(req);
            }
            if record.in_flight {
                return Err(CriError::failed_precondition(
                    "container operation in progress",
                ));
            }
            match record.state {
                // created は冪等に成功し、実行層を呼ばず状態も変えない（#2032）。
                ContainerState::Exited | ContainerState::Created => {
                    return Ok(v1::StopContainerResponse {});
                }
                ContainerState::Running | ContainerState::Unknown => {}
            }
            // 写像に失敗したら in_flight を立てる前に失敗する（SIGTERM へ黙って落とさない。fail-closed）。
            let signal = crate::stop_signal::linux_stop_signal(record.stop_signal)
                .map_err(|_| CriError::internal("stop_signal could not be resolved"))?;
            record.in_flight = true;
            (
                InFlightGuard::new(
                    Arc::clone(&self.registry),
                    req.container_id.clone(),
                    InFlightKind::Stop,
                ),
                signal,
            )
        };
        let (guard, signal) = guard;
        self.runtime_stop_one(binding, guard, req.timeout, signal)
            .await?;
        Ok(v1::StopContainerResponse {})
    }

    /// 仮登録済み（`in_flight`）のコンテナ 1 件を `ContainerRuntime::stop` で停止する（TASK-59.3）。
    ///
    /// 実行層が停止済みを報告するか、コンテナの不在（`NOT_FOUND`。プロセスは無い）を返したら exited に
    /// 確定する。確定失敗は元の状態のまま、結果不明（期限超過・`UNAVAILABLE`・想定外の応答）は unknown で
    /// 保持する。待ちの上限は `runtime_timeout` に SIGTERM の猶予を足した値で有界（REPAIR-5）。
    async fn runtime_stop_one(
        &self,
        binding: &RuntimeBinding,
        mut guard: InFlightGuard,
        grace_secs: i64,
        signal: u8,
    ) -> Result<(), CriError> {
        let adapter = binding.adapter.clone();
        let id = guard.id.clone();
        let grace = Duration::from_secs(u64::try_from(grace_secs).unwrap_or(0));
        run_bounded(
            self.runtime_timeout.saturating_add(grace),
            move || -> Result<(), CriError> {
                guard.mark_dispatched();
                match adapter.stop_with_signal(&id, grace_secs, signal) {
                    Ok(status) if status.lifecycle == RuntimeLifecycle::Stopped => {
                        guard.set_exit(&status);
                        guard.commit()
                    }
                    Ok(_) => Err(CriError::internal("runtime returned an unexpected state")),
                    Err(status) if status.code() == CriErrorCode::NotFound => guard.commit(),
                    Err(status) => {
                        if is_definite_failure(status.code()) {
                            guard.mark_definitely_failed();
                        }
                        Err(status)
                    }
                }
            },
        )
        .await?
    }

    /// 実行層接続時の `RemoveContainer`（TASK-59.3・CRI-2）。
    ///
    /// 実行層の資源を持つ記録は、状態を問わず（running は強制削除）`ContainerRuntime::delete(force)` と
    /// bundle の解放を終えてから記録を除去する。それ以外は従来の記録上の除去。
    async fn remove_container_runtime(
        &self,
        binding: &RuntimeBinding,
        req: v1::RemoveContainerRequest,
    ) -> Result<v1::RemoveContainerResponse, CriError> {
        if req.container_id.is_empty() {
            return Err(CriError::invalid_argument("container_id is required"));
        }
        let guard = {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            let Some(record) = registry.containers.get_mut(&req.container_id) else {
                return Ok(v1::RemoveContainerResponse {});
            };
            if !record.runtime_owned {
                drop(registry);
                return self.remove_container_impl(req);
            }
            if record.in_flight {
                return Err(CriError::failed_precondition(
                    "container operation in progress",
                ));
            }
            record.in_flight = true;
            InFlightGuard::new(
                Arc::clone(&self.registry),
                req.container_id.clone(),
                InFlightKind::Remove,
            )
        };
        self.runtime_remove_one(binding, guard).await?;
        Ok(v1::RemoveContainerResponse {})
    }

    /// 仮登録済み（`in_flight`）のコンテナ 1 件を `delete(force)` と bundle の解放で回収し、記録を除去する。
    ///
    /// 削除済み（成功または `NOT_FOUND`）を確認できたときだけ bundle を解放して記録を解放する。
    /// 確定失敗・解放の失敗は記録を保持して再試行できるようにし（再試行では delete が `NOT_FOUND` になる）、
    /// 結果不明は unknown で保持する（REPAIR-5）。
    ///
    /// 待ちの上限（#3027・REPAIR-5）: `adapter.remove` の実行層側（plugin-cri は全体の期限 `PLUGIN_FORCE_DELETE_DEADLINE` で
    /// 後始末を頭打ちにする）と、`bundles.release` はどちらも worker 内で動く。`release` にはロックの待ちが無く、I/O の量は
    /// 件数の上限で抑えられているが、時間の定数の上限は無い。RPC の応答は `run_bounded` が `runtime_timeout` で打ち切り、
    /// worker は取り消されず走り続ける（記録は `in_flight` のままで、再試行は worker が終わるまで `FAILED_PRECONDITION`）。
    /// 設計と kubelet の `--runtime-request-timeout` との関係は `docs/design/container-log-removal-wait.md`。
    async fn runtime_remove_one(
        &self,
        binding: &RuntimeBinding,
        mut guard: InFlightGuard,
    ) -> Result<(), CriError> {
        let adapter = binding.adapter.clone();
        let bundles = Arc::clone(&binding.bundles);
        let id = guard.id.clone();
        run_bounded(self.runtime_timeout, move || -> Result<(), CriError> {
            guard.mark_dispatched();
            match adapter.remove(&id, true) {
                Ok(_) => {}
                Err(status) if status.code() == CriErrorCode::NotFound => {}
                Err(status) => {
                    if is_definite_failure(status.code()) {
                        guard.mark_definitely_failed();
                    }
                    return Err(status);
                }
            }
            // 実行層の資源は無い。bundle の解放に失敗したら記録を保持して再試行できるようにする。
            if let Err(status) = bundles.release(&id) {
                // 実行層の削除は完了している。状態は exited（終了時刻つき）にして記録と件数枠だけを
                // 再試行用に保持する（実プロセスが消えたのに running と公開し続けない）。
                guard.mark_confirmed_exited();
                guard.mark_definitely_failed();
                return Err(status);
            }
            guard.commit()
        })
        .await?
    }

    /// 実行層接続時の `StopPodSandbox`（TASK-59.3・CRI-2）。
    ///
    /// 配下に実行中の操作（`in_flight`）があれば拒否する。それ以外は sandbox を notready にし、配下の
    /// 実行層経由の running・unknown・created コンテナ（created も init を持ちうる）を猶予 0（即時 SIGKILL）で
    /// 停止し、確認できなければ成功を返さない。スタブ経路の running は
    /// 記録上 exited にする。1 件でも失敗したら最初のエラーを返し、sandbox は notready のまま残る
    /// （冪等なので再呼び出しで残りを再試行できる）。所要時間の上限は「対象数（`MAX_CONTAINERS` で有界）
    /// × `runtime_timeout`」。
    async fn stop_sandbox_runtime(
        &self,
        binding: &RuntimeBinding,
        req: v1::StopPodSandboxRequest,
    ) -> Result<v1::StopPodSandboxResponse, CriError> {
        if req.pod_sandbox_id.is_empty() {
            return Err(CriError::invalid_argument("pod_sandbox_id is required"));
        }
        let finished_at_nanos = now_nanos()?;
        let pending = {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            if !registry.records.contains_key(&req.pod_sandbox_id) {
                return Err(CriError::not_found("sandbox not found"));
            }
            if registry
                .containers
                .values()
                .any(|c| c.pod_sandbox_id == req.pod_sandbox_id && c.in_flight)
            {
                return Err(CriError::failed_precondition(
                    "container operation in progress",
                ));
            }
            if let Some(record) = registry.records.get_mut(&req.pod_sandbox_id) {
                record.state = SandboxState::NotReady;
            }
            let mut ids = Vec::new();
            // コンテナごとの停止シグナル（Linux の番号）。写像に失敗した件は停止を呼ばず INTERNAL にする。
            let mut signals: HashMap<String, Result<u8, CriError>> = HashMap::new();
            for (id, c) in registry
                .containers
                .iter_mut()
                .filter(|(_, c)| c.pod_sandbox_id == req.pod_sandbox_id)
            {
                match (c.runtime_owned, c.state) {
                    (
                        true,
                        ContainerState::Running | ContainerState::Unknown | ContainerState::Created,
                    ) => {
                        c.in_flight = true;
                        ids.push(id.clone());
                        signals.insert(
                            id.clone(),
                            crate::stop_signal::linux_stop_signal(c.stop_signal).map_err(|_| {
                                CriError::internal("stop_signal could not be resolved")
                            }),
                        );
                    }
                    (false, ContainerState::Running) => {
                        c.state = ContainerState::Exited;
                        c.finished_at_nanos = finished_at_nanos;
                    }
                    _ => {}
                }
            }
            (PendingMarks::new(Arc::clone(&self.registry), ids), signals)
        };
        let (mut pending, mut signals) = pending;
        let mut first_error = None;
        while let Some(guard) = pending.next_guard(InFlightKind::Stop) {
            let signal = match signals.remove(&guard.id) {
                Some(Ok(signal)) => signal,
                Some(Err(status)) => {
                    // guard の drop が in_flight を戻す。他の件の停止は続ける。
                    first_error.get_or_insert(status);
                    continue;
                }
                None => {
                    first_error
                        .get_or_insert(CriError::internal("stop_signal could not be resolved"));
                    continue;
                }
            };
            if let Err(status) = self
                .runtime_stop_one(binding, guard, SANDBOX_STOP_GRACE_SECS, signal)
                .await
            {
                first_error.get_or_insert(status);
            }
        }
        first_error.map_or(Ok(v1::StopPodSandboxResponse {}), Err)
    }

    /// 実行層接続時の `RemovePodSandbox`（TASK-59.3・CRI-2）。
    ///
    /// 配下に実行中の操作があれば拒否する。実行層の資源を持つ配下のコンテナを 1 件ずつ `delete(force)` と
    /// bundle の解放で回収し、全件が成功したときだけ sandbox と残りの記録を除去する。1 件でも失敗したら
    /// sandbox と未回収の記録を保持して最初のエラーを返す（成功した分は個別に解放済み）。
    async fn remove_sandbox_runtime(
        &self,
        binding: &RuntimeBinding,
        req: v1::RemovePodSandboxRequest,
    ) -> Result<v1::RemovePodSandboxResponse, CriError> {
        if req.pod_sandbox_id.is_empty() {
            return Err(CriError::invalid_argument("pod_sandbox_id is required"));
        }
        let mut pending = {
            let mut registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            if !registry.records.contains_key(&req.pod_sandbox_id) {
                return Ok(v1::RemovePodSandboxResponse {});
            }
            if registry
                .containers
                .values()
                .any(|c| c.pod_sandbox_id == req.pod_sandbox_id && c.in_flight)
            {
                return Err(CriError::failed_precondition(
                    "container operation in progress",
                ));
            }
            // 子の削除中に並行する CreateContainer が新しい子を足さないよう、先に notready にする。
            if let Some(record) = registry.records.get_mut(&req.pod_sandbox_id) {
                record.state = SandboxState::NotReady;
            }
            let mut ids = Vec::new();
            for (id, c) in registry
                .containers
                .iter_mut()
                .filter(|(_, c)| c.pod_sandbox_id == req.pod_sandbox_id && c.runtime_owned)
            {
                c.in_flight = true;
                ids.push(id.clone());
            }
            PendingMarks::new(Arc::clone(&self.registry), ids)
        };
        let mut first_error = None;
        while let Some(guard) = pending.next_guard(InFlightKind::Remove) {
            if let Err(status) = self.runtime_remove_one(binding, guard).await {
                first_error.get_or_insert(status);
            }
        }
        if let Some(status) = first_error {
            return Err(status);
        }
        self.remove_sandbox(req).await
    }

    /// `StopContainer` の本体。running を exited へ遷移させる（CRI-1・ERR-3・TASK-58.2）。
    ///
    /// 空 ID・負の `timeout` は `INVALID_ARGUMENT`、未知 ID は `NOT_FOUND`。created と
    /// exited は冪等に成功し状態を変えない（created は #2032）。`timeout`（猶予秒数）はスタブが
    /// 待たないため検証のみで破棄する（実待機は TASK-59 で上限と REPAIR-5 のタイムアウトつきで追加）。
    /// プロセスは終了させない記録上の遷移（REPAIR-3）。件数・保持量の枠は解放しない。
    fn stop_container_impl(
        &self,
        req: v1::StopContainerRequest,
    ) -> Result<v1::StopContainerResponse, CriError> {
        if req.container_id.is_empty() {
            return Err(CriError::invalid_argument("container_id is required"));
        }
        if req.timeout < 0 {
            return Err(CriError::invalid_argument("timeout must not be negative"));
        }
        let finished_at_nanos = now_nanos()?;
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
        let record = registry
            .containers
            .get_mut(&req.container_id)
            .ok_or_else(|| CriError::not_found("container not found"))?;
        // 実行層の資源を持つ記録の停止は `stop_container_runtime`（実行層の stop）が担う。この経路は
        // 実行層未接続のスタブ用で、記録だけ Exited にすると実プロセスが生存したまま「停止済み」と返るため
        // 念のため拒否する（CRI-1・REPAIR-3。fail-closed。Remove 系と同じ code）。
        if record.runtime_owned {
            return Err(CriError::failed_precondition(
                "container resources are pending runtime cleanup",
            ));
        }
        match record.state {
            ContainerState::Running => {
                record.state = ContainerState::Exited;
                record.finished_at_nanos = finished_at_nanos;
                Ok(v1::StopContainerResponse {})
            }
            ContainerState::Exited | ContainerState::Created => Ok(v1::StopContainerResponse {}),
            // 結果不明は停止を確認できないため拒否する（通常は runtime_owned の拒否が先に効く）。
            ContainerState::Unknown => Err(CriError::failed_precondition(
                "container resources are pending runtime cleanup",
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
    ) -> Result<v1::RemoveContainerResponse, CriError> {
        if req.container_id.is_empty() {
            return Err(CriError::invalid_argument("container_id is required"));
        }
        self.drop_container(&req.container_id, false)?;
        Ok(v1::RemoveContainerResponse {})
    }

    /// 記録・重複判定キー・保持量を除去する（未知 ID は何もしない）。
    ///
    /// `include_in_flight` が偽のとき、実行層の呼び出し中（`in_flight`）の記録は `FAILED_PRECONDITION`
    /// で拒否する（Create の巻き戻しだけが真で呼ぶ）。
    fn drop_container(&self, container_id: &str, include_in_flight: bool) -> Result<(), CriError> {
        drop_container_in(&self.registry, container_id, include_in_flight)
    }

    /// `ContainerStatus` の本体。読み取り専用（CRI-1・ERR-3・TASK-58.3・#435）。
    ///
    /// Create の実行層呼び出し中（`in_flight` の仮登録）も created として見える。実行層にはまだ
    /// 存在しない可能性があり、`ListContainers` も同様（仕様。Remove は `FAILED_PRECONDITION`）。
    ///
    /// 空 ID は `INVALID_ARGUMENT`、未知 ID（Remove 済みを含む）は `NOT_FOUND`（文言に入力 ID を含めない）。
    /// `verbose` でも `info` は方針として空（内部のパス・構成を出さない。#2901・`docs/design/cri-config-acceptance.md`）。
    /// `envs` 等は応答に含めない。
    fn container_status_impl(
        &self,
        req: v1::ContainerStatusRequest,
    ) -> Result<v1::ContainerStatusResponse, CriError> {
        if req.container_id.is_empty() {
            return Err(CriError::invalid_argument("container_id is required"));
        }
        let status = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            let record = registry
                .containers
                .get(&req.container_id)
                .ok_or_else(|| CriError::not_found("container not found"))?;
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
    ) -> Result<v1::ListContainersResponse, CriError> {
        let filter = ValidatedContainerFilter::new(req.filter)?;
        let mut containers = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
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
    ) -> Result<v1::PodSandboxStatusResponse, CriError> {
        if req.pod_sandbox_id.is_empty() {
            return Err(CriError::invalid_argument("pod_sandbox_id is required"));
        }
        let status = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
            let record = registry
                .records
                .get(&req.pod_sandbox_id)
                .ok_or_else(|| CriError::not_found("sandbox not found"))?;
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
    ) -> Result<v1::ListPodSandboxResponse, CriError> {
        let filter = ValidatedFilter::new(req.filter)?;
        let mut items = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| CriError::internal("sandbox registry is unavailable"))?;
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
fn now_nanos() -> Result<i64, CriError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| CriError::internal("system clock is invalid"))
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
            labels: self.config.labels.clone().into_iter().collect(),
            annotations: self.config.annotations.clone().into_iter().collect(),
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
            labels: self.config.labels.clone().into_iter().collect(),
            annotations: self.config.annotations.clone().into_iter().collect(),
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
) -> Result<(), CriError> {
    if selector.len() > MAX_CONFIG_COLLECTION_ENTRIES {
        return Err(CriError::invalid_argument(
            "label_selector has too many entries",
        ));
    }
    let mut total = extra_bytes;
    for (k, v) in selector {
        if k.len() > MAX_LABEL_SELECTOR_STRING_BYTES || v.len() > MAX_LABEL_SELECTOR_STRING_BYTES {
            return Err(CriError::invalid_argument(
                "label_selector key or value is too long",
            ));
        }
        total = total.saturating_add(k.len()).saturating_add(v.len());
    }
    if total > MAX_LABEL_SELECTOR_TOTAL_BYTES {
        return Err(CriError::invalid_argument("label_selector is too large"));
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
    fn new(filter: Option<v1::PodSandboxFilter>) -> Result<Self, CriError> {
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
                Err(_) => return Err(CriError::invalid_argument("unknown state filter")),
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

/// `PodSandboxConfig` の metadata 必須・name 非空を検査する（`validate_sandbox_config` の前半）。
fn check_sandbox_metadata(config: &PodSandboxConfig) -> Result<(), CriError> {
    let metadata = config
        .metadata
        .as_ref()
        .ok_or_else(|| CriError::invalid_argument("config.metadata is required"))?;
    if metadata.name.is_empty() {
        return Err(CriError::invalid_argument(
            "config.metadata.name is required",
        ));
    }
    Ok(())
}

/// `PodSandboxConfig` の必須項目と上限を検証し、保持用に作り直す（RunPodSandbox と記録の復号が共有する。
/// #2930・CRI-1・REPAIR-1・REPAIR-2）。
fn validate_sandbox_config(config: PodSandboxConfig) -> Result<BoundedConfig, CriError> {
    check_sandbox_metadata(&config)?;
    BoundedConfig::new(config)
}

/// `RunPodSandbox` の入力検証（ERR-3: 必須欠落・値域外・サイズ超過は `INVALID_ARGUMENT`）。
///
/// 必須フィールドとハンドラを先に確かめ、最後に `config` のサイズ・件数を検証して保持用に作り直す
/// （`BoundedConfig::new`）。状態には触れない。
fn validate_run_request(req: v1::RunPodSandboxRequest) -> Result<ValidatedRun, CriError> {
    let v1::RunPodSandboxRequest {
        config,
        runtime_handler,
    } = req;
    let config = config.ok_or_else(|| CriError::invalid_argument("config is required"))?;
    // metadata の必須検査は validate_sandbox_config と同じ順序（handler 照合より前）に保つ。
    check_sandbox_metadata(&config)?;
    let runtime_handler = SUPPORTED_RUNTIME_HANDLERS
        .iter()
        .copied()
        .find(|supported| *supported == runtime_handler.as_str())
        .ok_or_else(|| CriError::invalid_argument("unknown runtime_handler"))?;
    let config = validate_sandbox_config(config)?;
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
    /// 同一 metadata（name・namespace・uid・attempt の 4 項目）の再作成は `ALREADY_EXISTS`（ERR-3）。
    /// 失敗時はレジストリを変更しない。成功・失敗のどちらでも、結果のステータスコードと所要時間を
    /// 記録先へ 1 件渡す（REPAIR-4。未確定のまま抜けた場合はガードが `Internal` として記録する）。
    async fn run_pod_sandbox(
        &self,
        request: Request<v1::RunPodSandboxRequest>,
    ) -> Result<Response<v1::RunPodSandboxResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::RunPodSandbox);
        let req = request.into_inner();
        let result = match &self.pod_network {
            Some(provider) if wants_pod_network(req.config.as_ref()) => {
                self.run_sandbox_networked(provider, req).await
            }
            _ => self.run_sandbox_plain(req).await,
        }
        .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }

    async fn version(
        &self,
        _request: Request<v1::VersionRequest>,
    ) -> Result<Response<v1::VersionResponse>, Status> {
        // 要求の `version` は読まない（containerd と同じ。値を反射せず、拒否もしない）。待ちは持たない。
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::Version);
        let result: Result<v1::VersionResponse, Status> = Ok(version_response());
        timer.finish_with(&result);
        result.map(Response::new)
    }
    /// サンドボックスを notready にする（冪等。未知 ID は `NOT_FOUND`。CRI-1・ERR-3・TASK-57.2）。
    async fn stop_pod_sandbox(
        &self,
        request: Request<v1::StopPodSandboxRequest>,
    ) -> Result<Response<v1::StopPodSandboxResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::StopPodSandbox);
        let req = request.into_inner();
        let result = self
            .stop_sandbox_with_network(req)
            .await
            .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// サンドボックスの記録を除去する（冪等。未知 ID は成功。CRI-1・ERR-3・TASK-57.2）。
    async fn remove_pod_sandbox(
        &self,
        request: Request<v1::RemovePodSandboxRequest>,
    ) -> Result<Response<v1::RemovePodSandboxResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::RemovePodSandbox);
        let req = request.into_inner();
        let result = self
            .remove_sandbox_with_network(req)
            .await
            .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// サンドボックスの状態を返す（読み取り専用。未知 ID は `NOT_FOUND`。CRI-1・ERR-3・TASK-57.3）。
    async fn pod_sandbox_status(
        &self,
        request: Request<v1::PodSandboxStatusRequest>,
    ) -> Result<Response<v1::PodSandboxStatusResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::PodSandboxStatus);
        let result = self
            .status_sandbox(request.into_inner())
            .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// フィルタに一致するサンドボックスを `(created_at, id)` 昇順で返す（CRI-1・TASK-57.3）。
    async fn list_pod_sandbox(
        &self,
        request: Request<v1::ListPodSandboxRequest>,
    ) -> Result<Response<v1::ListPodSandboxResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::ListPodSandbox);
        let result = self
            .list_sandboxes(request.into_inner())
            .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }
    async fn stream_pod_sandboxes(
        &self,
        _request: Request<v1::StreamPodSandboxesRequest>,
    ) -> Result<Response<Self::StreamPodSandboxesStream>, Status> {
        Err(CriError::unimplemented("stream_pod_sandboxes").into())
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
        }
        .map_err(Status::from);
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
        }
        .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }
    /// コンテナを exited にする（停止済み・created は冪等に成功し状態不変。
    /// CRI-1・ERR-3・TASK-58.2・#2032）。
    async fn stop_container(
        &self,
        request: Request<v1::StopContainerRequest>,
    ) -> Result<Response<v1::StopContainerResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::StopContainer);
        let req = request.into_inner();
        let result = match &self.runtime {
            Some(binding) => self.stop_container_runtime(binding, req).await,
            None => self.stop_container_impl(req),
        }
        .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }

    /// コンテナの記録を除去する（未知 ID は冪等に成功。CRI-1・TASK-58.2）。
    async fn remove_container(
        &self,
        request: Request<v1::RemoveContainerRequest>,
    ) -> Result<Response<v1::RemoveContainerResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::RemoveContainer);
        let req = request.into_inner();
        let result = match &self.runtime {
            Some(binding) => self.remove_container_runtime(binding, req).await,
            None => self.remove_container_impl(req),
        }
        .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }
    /// コンテナの一覧を返す（読み取り専用。CRI-1・TASK-58.3・#435）。
    async fn list_containers(
        &self,
        request: Request<v1::ListContainersRequest>,
    ) -> Result<Response<v1::ListContainersResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::ListContainers);
        let result = self
            .list_containers_impl(request.into_inner())
            .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }
    async fn stream_containers(
        &self,
        _request: Request<v1::StreamContainersRequest>,
    ) -> Result<Response<Self::StreamContainersStream>, Status> {
        Err(CriError::unimplemented("stream_containers").into())
    }
    /// コンテナの状態を返す（読み取り専用。CRI-1・TASK-58.3・#435）。
    async fn container_status(
        &self,
        request: Request<v1::ContainerStatusRequest>,
    ) -> Result<Response<v1::ContainerStatusResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::ContainerStatus);
        let result = self
            .container_status_impl(request.into_inner())
            .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }
    async fn update_container_resources(
        &self,
        _request: Request<v1::UpdateContainerResourcesRequest>,
    ) -> Result<Response<v1::UpdateContainerResourcesResponse>, Status> {
        Err(CriError::unimplemented("update_container_resources").into())
    }
    /// 未実装（kubelet のログ回転に要る。CRI-2・SUP-7。#2671 の後続 issue）。CRI ログの書き出し自体は実装済みで、
    /// 回転が無い間は総量に上限が無い（`docs/design/cri-config-acceptance.md`）。
    async fn reopen_container_log(
        &self,
        _request: Request<v1::ReopenContainerLogRequest>,
    ) -> Result<Response<v1::ReopenContainerLogResponse>, Status> {
        Err(CriError::unimplemented("reopen_container_log").into())
    }
    async fn exec_sync(
        &self,
        _request: Request<v1::ExecSyncRequest>,
    ) -> Result<Response<v1::ExecSyncResponse>, Status> {
        Err(CriError::unimplemented("exec_sync").into())
    }
    async fn exec(
        &self,
        _request: Request<v1::ExecRequest>,
    ) -> Result<Response<v1::ExecResponse>, Status> {
        Err(CriError::unimplemented("exec").into())
    }
    async fn attach(
        &self,
        _request: Request<v1::AttachRequest>,
    ) -> Result<Response<v1::AttachResponse>, Status> {
        Err(CriError::unimplemented("attach").into())
    }
    async fn port_forward(
        &self,
        _request: Request<v1::PortForwardRequest>,
    ) -> Result<Response<v1::PortForwardResponse>, Status> {
        Err(CriError::unimplemented("port_forward").into())
    }
    async fn container_stats(
        &self,
        _request: Request<v1::ContainerStatsRequest>,
    ) -> Result<Response<v1::ContainerStatsResponse>, Status> {
        Err(CriError::unimplemented("container_stats").into())
    }
    async fn list_container_stats(
        &self,
        _request: Request<v1::ListContainerStatsRequest>,
    ) -> Result<Response<v1::ListContainerStatsResponse>, Status> {
        Err(CriError::unimplemented("list_container_stats").into())
    }
    async fn stream_container_stats(
        &self,
        _request: Request<v1::StreamContainerStatsRequest>,
    ) -> Result<Response<Self::StreamContainerStatsStream>, Status> {
        Err(CriError::unimplemented("stream_container_stats").into())
    }
    async fn pod_sandbox_stats(
        &self,
        _request: Request<v1::PodSandboxStatsRequest>,
    ) -> Result<Response<v1::PodSandboxStatsResponse>, Status> {
        Err(CriError::unimplemented("pod_sandbox_stats").into())
    }
    async fn list_pod_sandbox_stats(
        &self,
        _request: Request<v1::ListPodSandboxStatsRequest>,
    ) -> Result<Response<v1::ListPodSandboxStatsResponse>, Status> {
        Err(CriError::unimplemented("list_pod_sandbox_stats").into())
    }
    async fn stream_pod_sandbox_stats(
        &self,
        _request: Request<v1::StreamPodSandboxStatsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxStatsStream>, Status> {
        Err(CriError::unimplemented("stream_pod_sandbox_stats").into())
    }
    /// kubelet が渡す pod CIDR を検証して記録する（CRI-1・CRI-2・#2896）。
    ///
    /// 未指定・空は何もせず `OK`。不正は `INVALID_ARGUMENT` で、記録は直前のまま（all-or-nothing）。
    /// 記録を読む利用者はまだ無い（REPAIR-3）。待ち・I/O・実行層の呼び出しは無い。
    async fn update_runtime_config(
        &self,
        request: Request<v1::UpdateRuntimeConfigRequest>,
    ) -> Result<Response<v1::UpdateRuntimeConfigResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::UpdateRuntimeConfig);
        let req = request.into_inner();
        let raw = req
            .runtime_config
            .and_then(|c| c.network_config)
            .map(|n| n.pod_cidr)
            .unwrap_or_default();
        let result = parse_pod_cidrs(&raw)
            .and_then(|parsed| match parsed {
                None => Ok(()),
                Some(cidrs) => match self.pod_cidrs.lock() {
                    Ok(mut guard) => {
                        *guard = Some(cidrs);
                        Ok(())
                    }
                    Err(_) => Err(CriError::internal("runtime config state is unavailable")),
                },
            })
            .map(|()| v1::UpdateRuntimeConfigResponse {})
            .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }
    async fn status(
        &self,
        request: Request<v1::StatusRequest>,
    ) -> Result<Response<v1::StatusResponse>, Status> {
        let timer = CriOpTimer::start(self.recorder.as_ref(), CriOpKind::Status);
        let result = self
            .status_response(&request.into_inner())
            .map_err(Status::from);
        timer.finish_with(&result);
        result.map(Response::new)
    }
    async fn checkpoint_container(
        &self,
        _request: Request<v1::CheckpointContainerRequest>,
    ) -> Result<Response<v1::CheckpointContainerResponse>, Status> {
        Err(CriError::unimplemented("checkpoint_container").into())
    }
    async fn checkpoint_pod(
        &self,
        _request: Request<v1::CheckpointPodRequest>,
    ) -> Result<Response<v1::CheckpointPodResponse>, Status> {
        Err(CriError::unimplemented("checkpoint_pod").into())
    }
    async fn restore_pod(
        &self,
        _request: Request<v1::RestorePodRequest>,
    ) -> Result<Response<v1::RestorePodResponse>, Status> {
        Err(CriError::unimplemented("restore_pod").into())
    }
    async fn get_container_events(
        &self,
        _request: Request<v1::GetEventsRequest>,
    ) -> Result<Response<Self::GetContainerEventsStream>, Status> {
        Err(CriError::unimplemented("get_container_events").into())
    }
    async fn list_metric_descriptors(
        &self,
        _request: Request<v1::ListMetricDescriptorsRequest>,
    ) -> Result<Response<v1::ListMetricDescriptorsResponse>, Status> {
        Err(CriError::unimplemented("list_metric_descriptors").into())
    }
    async fn list_pod_sandbox_metrics(
        &self,
        _request: Request<v1::ListPodSandboxMetricsRequest>,
    ) -> Result<Response<v1::ListPodSandboxMetricsResponse>, Status> {
        Err(CriError::unimplemented("list_pod_sandbox_metrics").into())
    }
    async fn stream_pod_sandbox_metrics(
        &self,
        _request: Request<v1::StreamPodSandboxMetricsRequest>,
    ) -> Result<Response<Self::StreamPodSandboxMetricsStream>, Status> {
        Err(CriError::unimplemented("stream_pod_sandbox_metrics").into())
    }
    async fn runtime_config(
        &self,
        _request: Request<v1::RuntimeConfigRequest>,
    ) -> Result<Response<v1::RuntimeConfigResponse>, Status> {
        Err(CriError::unimplemented("runtime_config").into())
    }
    async fn update_pod_sandbox_resources(
        &self,
        _request: Request<v1::UpdatePodSandboxResourcesRequest>,
    ) -> Result<Response<v1::UpdatePodSandboxResourcesResponse>, Status> {
        Err(CriError::unimplemented("update_pod_sandbox_resources").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// CRI-2・NET-1（#2675）: set_up の結果の確定権は先に遷移した側だけが得る。worker が先なら呼び出し側は
    /// 手放せず（成功として返す）、呼び出し側が先なら worker は確定できない（Ready を公開しない）。
    #[test]
    fn set_up_settlement_is_won_by_exactly_one_side() {
        let worker_first = SetUpSettlement::new();
        assert!(worker_first.settle_by_worker());
        assert!(!worker_first.abandon());
        assert!(!worker_first.settle_by_worker());

        let caller_first = SetUpSettlement::new();
        assert!(caller_first.abandon());
        assert!(!caller_first.settle_by_worker());
        assert!(!caller_first.abandon());
    }

    /// CRI-2・REPAIR-5（#2933）: worker が書き終えて確定した後でも、呼び出し側が受領前に手放したら
    /// ファイルの後始末の責任は呼び出し側にある（真）。受領後は責任が無い（偽）。
    #[test]
    fn put_settlement_keeps_cleanup_duty_until_accepted() {
        let unaccepted = SetUpSettlement::new();
        assert!(unaccepted.settle_by_worker());
        assert!(unaccepted.abandon_put());

        let accepted = SetUpSettlement::new();
        assert!(accepted.settle_by_worker());
        assert!(accepted.accept());
        assert!(!accepted.abandon_put());

        let before_put = SetUpSettlement::new();
        assert!(!before_put.abandon_put());
        assert!(!before_put.settle_by_worker());
    }

    thread_local! {
        /// 現スレッドの N 回目（0 起点）のスレッド生成を失敗させる（`None` で無効）。
        static FAIL_SPAWN_AT: Cell<Option<u32>> = const { Cell::new(None) };
    }

    /// `spawn_runtime_thread` から呼ばれる。注入した回数に達したら true を返して注入を解除する。
    pub(super) fn take_spawn_failure() -> bool {
        FAIL_SPAWN_AT.with(|c| match c.get() {
            Some(0) => {
                c.set(None);
                true
            }
            Some(n) => {
                c.set(Some(n - 1));
                false
            }
            None => false,
        })
    }
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

    /// 起動できない実行層（呼ばれたら失敗）。スレッド生成失敗の注入テスト用。
    struct NeverRuntime;

    impl fandhe_container_core::traits::ContainerRuntime for NeverRuntime {
        fn create(
            &self,
            _: &fandhe_container_core::traits::CreateRequest,
        ) -> Result<
            fandhe_container_core::traits::ContainerStatus,
            fandhe_container_core::traits::TraitError,
        > {
            Err(unused())
        }
        fn start(
            &self,
            _: &fandhe_container_core::traits::StartRequest,
        ) -> Result<
            fandhe_container_core::traits::ContainerStatus,
            fandhe_container_core::traits::TraitError,
        > {
            Err(unused())
        }
        fn kill(
            &self,
            _: &fandhe_container_core::traits::KillRequest,
        ) -> Result<
            fandhe_container_core::traits::ContainerStatus,
            fandhe_container_core::traits::TraitError,
        > {
            Err(unused())
        }
        fn stop(
            &self,
            _: &fandhe_container_core::traits::StopRequest,
        ) -> Result<
            fandhe_container_core::traits::ContainerStatus,
            fandhe_container_core::traits::TraitError,
        > {
            Err(unused())
        }
        fn delete(
            &self,
            _: &fandhe_container_core::traits::DeleteRequest,
        ) -> Result<
            fandhe_container_core::traits::DeleteResponse,
            fandhe_container_core::traits::TraitError,
        > {
            Err(unused())
        }
        fn state(
            &self,
            _: &fandhe_container_core::traits::StateRequest,
        ) -> Result<
            fandhe_container_core::traits::ContainerStatus,
            fandhe_container_core::traits::TraitError,
        > {
            Err(unused())
        }
    }

    fn unused() -> fandhe_container_core::traits::TraitError {
        fandhe_container_core::traits::TraitError::new(
            fandhe_container_core::traits::ErrorCode::Unimplemented,
            "not used",
        )
    }

    /// `release` を永久に止める bundle 供給元。`prepare` と `release` の呼び出し元スレッドを記録する。
    #[derive(Default)]
    struct HangingRelease {
        prepares: std::sync::atomic::AtomicUsize,
        releases: std::sync::atomic::AtomicUsize,
    }

    impl BundleProvider for HangingRelease {
        fn prepare(&self, _: &BundleRequest<'_>) -> Result<PreparedBundle, CriError> {
            self.prepares
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(PreparedBundle::new(std::path::PathBuf::from("/bundles/x")))
        }
        fn release(&self, _: &str) -> Result<(), CriError> {
            self.releases
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            loop {
                std::thread::park();
            }
        }
    }

    /// CRI-1・REPAIR-3: NotReady の sandbox 配下の Start は実行層を呼ばず FAILED_PRECONDITION
    /// (実行層未接続のスタブ経路では資源を持つ記録を作れないため、レジストリを直接操作して状態を作る)。
    #[test]
    fn task_59_3_start_in_notready_sandbox_never_reaches_the_runtime() {
        let svc = CriRuntimeService::new();
        let sb = run(&svc, Some(config("p")), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        let id = block_on(
            svc.create_container(Request::new(v1::CreateContainerRequest {
                pod_sandbox_id: sb.clone(),
                config: Some(container_config("c", 0)),
                sandbox_config: None,
            })),
        )
        .unwrap()
        .into_inner()
        .container_id;
        let svc = svc.with_runtime(
            crate::adapter::RuntimeAdapter::new(Arc::new(NeverRuntime)),
            Arc::new(HangingRelease::default()),
        );
        svc.registry
            .lock()
            .unwrap()
            .records
            .get_mut(&sb)
            .unwrap()
            .state = SandboxState::NotReady;
        let err = block_on(
            svc.start_container(Request::new(v1::StartContainerRequest { container_id: id })),
        )
        .unwrap_err();
        // NeverRuntime に届けば Unimplemented になる。届かないので FAILED_PRECONDITION。
        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    /// CRI-2・REPAIR-3（#2830）: レジストリが poisoned なら `RuntimeReady` は false（`RuntimeStateUnavailable`）で、
    /// RPC 自体は OK のまま condition で理由を伝える。ロックは取らないので待たない。
    #[test]
    fn cri_2_status_reports_runtime_not_ready_when_registry_is_poisoned() {
        let svc = CriRuntimeService::new().with_runtime(
            crate::adapter::RuntimeAdapter::new(Arc::new(NeverRuntime)),
            Arc::new(HangingRelease::default()),
        );
        let ready = block_on(svc.status(Request::new(v1::StatusRequest { verbose: false })))
            .unwrap()
            .into_inner();
        assert!(ready.status.unwrap().conditions[0].status);

        let poisoned = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _guard = svc.registry.lock().unwrap();
                    panic!("poison the registry lock");
                })
                .join()
        });
        assert!(poisoned.is_err());
        let resp = block_on(svc.status(Request::new(v1::StatusRequest { verbose: false })))
            .unwrap()
            .into_inner();
        let conditions = resp.status.unwrap().conditions;
        assert_eq!(conditions.len(), 2);
        assert_eq!(conditions[0].r#type, "RuntimeReady");
        assert!(!conditions[0].status);
        assert_eq!(conditions[0].reason, "RuntimeStateUnavailable");
        assert_eq!(
            conditions[0].message,
            "runtime state registry is unavailable"
        );
    }

    /// REPAIR-5・CRI-2: worker / 監視スレッドの生成に失敗しても、bundle の `release`（外部処理）は
    /// RPC スレッドで走らず、応答は期限内に `UNAVAILABLE` で返り、仮登録（件数枠）は巻き戻る。
    /// 起動前は `prepare` も未実行なので解放すべき bundle は無く、リークしない。
    #[test]
    fn repair_5_cri_2_create_spawn_failure_never_releases_on_rpc_thread() {
        for fail_at in [0u32, 1] {
            let bundles = Arc::new(HangingRelease::default());
            let svc = CriRuntimeService::new()
                .with_runtime(
                    crate::adapter::RuntimeAdapter::new(Arc::new(NeverRuntime)),
                    bundles.clone(),
                )
                .with_runtime_timeout(Duration::from_millis(500));
            let sb = run(&svc, Some(config("p")), "")
                .unwrap()
                .into_inner()
                .pod_sandbox_id;
            FAIL_SPAWN_AT.with(|c| c.set(Some(fail_at)));
            let started = std::time::Instant::now();
            let err = block_on(
                svc.create_container(Request::new(v1::CreateContainerRequest {
                    pod_sandbox_id: sb,
                    config: Some(v1::ContainerConfig {
                        metadata: Some(v1::ContainerMetadata {
                            name: "c".into(),
                            attempt: 0,
                        }),
                        image: Some(v1::ImageSpec {
                            image: "busybox:1.36".into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    sandbox_config: None,
                })),
            )
            .unwrap_err();
            FAIL_SPAWN_AT.with(|c| c.set(None));
            assert_eq!(err.code(), Code::Unavailable);
            assert!(started.elapsed() < Duration::from_millis(400));
            assert_eq!(
                bundles.releases.load(std::sync::atomic::Ordering::SeqCst),
                0
            );
            assert_eq!(
                bundles.prepares.load(std::sync::atomic::Ordering::SeqCst),
                0
            );
            assert_eq!(svc.registry.lock().unwrap().containers.len(), 0);
        }
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
        let b = run(&svc, Some(config("q")), "")
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
        let err = run(&svc, Some(config("q")), "").unwrap_err();
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
        run(&svc, Some(cfg), "").unwrap();
        assert_eq!(svc.retained_bytes(), per_sandbox);
        // 同じ長さの別名（同一 metadata は ALREADY_EXISTS になるため）。
        run(&svc, Some(config("q")), "").unwrap();
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
        run(&exact, Some(config("q")), "").unwrap();
        let err = run(&exact, Some(config("r")), "").unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(err.message(), "sandbox config storage is full");
        assert_eq!(exact.sandbox_count(), 2);
        assert_eq!(exact.retained_bytes(), 2 * per_sandbox);

        let one_short = service(2 * per_sandbox - 1);
        run(&one_short, Some(cfg), "").unwrap();
        let err = run(&one_short, Some(config("q")), "").unwrap_err();
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
        run(&svc, Some(config("q")), "").unwrap_err();
        // 同一 metadata の重複は ALREADY_EXISTS（件数超過より先に判定する。ERR-3）。
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
                (kind, CriOpOutcome::Failure, Code::AlreadyExists),
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

    /// 呼び出しごとに一意な name で Run する（同一 metadata は ALREADY_EXISTS になるため。ERR-3）。
    fn run_id(svc: &CriRuntimeService) -> String {
        static SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        run(svc, Some(config(&format!("p{}", n % 10_000))), "")
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
        let original = svc.registry.lock().unwrap().records[&id].config.clone();
        for _ in 0..2 {
            stop(&svc, &id).unwrap();
            let reg = svc.registry.lock().unwrap();
            let rec = reg.records.get(&id).unwrap();
            assert_eq!(rec.state.to_proto(), PodSandboxState::SandboxNotready);
            assert_eq!(rec.config, original);
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

    /// CRI-1・TASK-57.2・REPAIR-12: Remove で記録と保持量の計上の両方が消える。
    ///
    /// 保持量は metadata の name の長さに比例する。2 件の name の長さを意図的に変え
    /// （`p9` と `p10`）、連番の桁上がりで 1 バイト差になる場合を決定的に覆う（#2723）。
    /// 期待値は記録の読み返しではなく、config から式で独立に求める。
    #[test]
    fn task_57_2_remove_deletes_record_and_retained_bytes() {
        let svc = CriRuntimeService::new();
        let (cfg_a, cfg_b) = (config("p9"), config("p10"));
        // config() は labels 1 件と annotations 1 件を持つので要素数は 2。
        let expect = |c: &PodSandboxConfig| {
            c.encoded_len() + 2 * RETAINED_BYTES_PER_ENTRY + RETAINED_BYTES_PER_RECORD
        };
        let (ra, rb) = (expect(&cfg_a), expect(&cfg_b));
        assert_ne!(ra, rb);
        let a = run(&svc, Some(cfg_a), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        let b = run(&svc, Some(cfg_b), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        {
            let reg = svc.registry.lock().unwrap();
            assert_eq!(reg.records[&a].retained_bytes, ra);
            assert_eq!(reg.records[&b].retained_bytes, rb);
        }
        assert_eq!(svc.sandbox_count(), 2);
        assert_eq!(svc.retained_bytes(), ra + rb);
        remove(&svc, &a).unwrap();
        {
            let reg = svc.registry.lock().unwrap();
            assert!(!reg.records.contains_key(&a));
            let sum: usize = reg.records.values().map(|r| r.retained_bytes).sum();
            assert_eq!(sum, reg.retained_bytes);
        }
        assert_eq!(svc.sandbox_count(), 1);
        assert_eq!(svc.retained_bytes(), rb);
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

    /// ERR-3・CRI-1・TASK-57.1: metadata 4 項目が一致する 2 回目の Run は ALREADY_EXISTS で、
    /// 件数と保持量は増えない。
    #[test]
    fn task_57_1_duplicate_metadata_returns_already_exists() {
        let svc = CriRuntimeService::new();
        run(&svc, Some(config("p")), "").unwrap();
        let (count, bytes) = (svc.sandbox_count(), svc.retained_bytes());
        let err = run(&svc, Some(config("p")), "").unwrap_err();
        assert_eq!(err.code(), Code::AlreadyExists);
        assert_eq!(err.message(), "sandbox already exists");
        assert_eq!((svc.sandbox_count(), svc.retained_bytes()), (count, bytes));
    }

    /// ERR-3・TASK-57.1: 4 項目のうち 1 つだけ違う要求は別の Pod として受け付ける。
    #[test]
    fn task_57_1_metadata_differing_in_one_field_is_accepted() {
        let svc = CriRuntimeService::new();
        run(&svc, Some(config("p")), "").unwrap();
        for field in 0..4 {
            let mut c = config("p");
            let m = c.metadata.as_mut().unwrap();
            match field {
                0 => m.name = "other".into(),
                1 => m.namespace = "other".into(),
                2 => m.uid = "other".into(),
                _ => m.attempt += 1,
            }
            run(&svc, Some(c), "").unwrap();
        }
        assert_eq!(svc.sandbox_count(), 5);
    }

    /// ERR-3・TASK-57.1: 件数上限に達していても、同一 metadata は ALREADY_EXISTS を優先する。
    #[test]
    fn task_57_1_duplicate_is_checked_before_limit() {
        let svc = CriRuntimeService::with_max_sandboxes(1);
        run(&svc, Some(config("p")), "").unwrap();
        let err = run(&svc, Some(config("p")), "").unwrap_err();
        assert_eq!(err.code(), Code::AlreadyExists);
    }

    /// ERR-3・TASK-57.1: 同じ要求が並行しても成功は 1 件だけで、残りは ALREADY_EXISTS。
    #[test]
    fn task_57_1_concurrent_duplicate_run_succeeds_once() {
        let svc = CriRuntimeService::new();
        let results: Vec<Result<_, Status>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| {
                    let svc = &svc;
                    scope.spawn(move || run(svc, Some(config("p")), ""))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        for err in results.iter().filter_map(|r| r.as_ref().err()) {
            assert_eq!(err.code(), Code::AlreadyExists);
        }
        assert_eq!(svc.sandbox_count(), 1);
        assert_eq!(
            svc.retained_bytes(),
            config("p").encoded_len() + 2 * 256 + 4096
        );
    }

    /// ERR-3・CRI-1・TASK-57.2: Stop では同一 metadata の予約が残り、Remove で解放されて作り直せる。
    #[test]
    fn task_57_2_remove_releases_metadata_reservation() {
        let svc = CriRuntimeService::new();
        let id = run(&svc, Some(config("p")), "")
            .unwrap()
            .into_inner()
            .pod_sandbox_id;
        stop(&svc, &id).unwrap();
        let err = run(&svc, Some(config("p")), "").unwrap_err();
        assert_eq!(err.code(), Code::AlreadyExists);
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
        assert_eq!(st.labels, cfg.labels.clone().into_iter().collect());
        assert_eq!(
            st.annotations,
            cfg.annotations.clone().into_iter().collect()
        );
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

    /// ERR-3・TASK-58.2（受け入れ条件）: created（running でない）の Stop は成功で状態不変。
    #[test]
    fn task_58_2_stop_created_succeeds_and_keeps_state() {
        // ERR-3・CRI-1・#2032: created の Stop は成功で、状態も finished_at も変えない（冪等）。
        let svc = CriRuntimeService::new();
        let sb = run_id(&svc);
        let id = create(&svc, &sb, Some(container_config("c", 0))).unwrap();
        let (count, bytes) = (svc.container_count(), svc.container_retained_bytes());
        stop_c(&svc, &id, 0).unwrap();
        stop_c(&svc, &id, 0).unwrap();
        let st = status_c(&svc, &id).unwrap();
        assert_eq!(st.state, v1::ContainerState::ContainerCreated as i32);
        assert_eq!(st.finished_at, 0);
        assert_eq!(svc.container_count(), count);
        assert_eq!(svc.container_retained_bytes(), bytes);
        start(&svc, &id).unwrap();
        let st = status_c(&svc, &id).unwrap();
        assert_eq!(st.state, v1::ContainerState::ContainerRunning as i32);
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
        assert_eq!(created.labels, cfg.labels.clone().into_iter().collect());
        assert_eq!(
            created.annotations,
            cfg.annotations.clone().into_iter().collect()
        );
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
        assert_eq!((exited.exit_code, exited.reason.as_str()), (0, ""));
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
