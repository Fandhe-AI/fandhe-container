//! containerd Task API の Create / Start / Delete / Exec / Wait / State / Kill / Shutdown を `ContainerRuntime` へつなぐサービス（CRI-5・ERR-3・TASK-62.2・TASK-62.3.1・TASK-62.3.2・TASK-62.4・TASK-62.7.2・MS-7）。
//!
//! [`ServiceRegistry::dispatch`](super::service::ServiceRegistry::dispatch) から呼ばれる同期ハンドラで、
//! 接続ごとのスレッド上で動く。コンテナの作成・起動は [`RuntimeAdapter`] 経由で行い、core の具象型には
//! 依存しない（CRI-7・PLUG-1）。ランタイム側の失敗は `crate::error` の表（ERR-3）で gRPC コードへ写し、
//! ttrpc の `Response.status` に載せる。
//!
//! 未対応の欄は黙って無視せず `UNIMPLEMENTED` で拒否する（fail-closed。REPAIR-3）:
//! `rootfs`・`options`・`terminal`・`stdin`/`stdout`/`stderr`・`checkpoint`/`parent_checkpoint`。
//! `Exec`・`Start(exec_id)` と、`exec_id` つきの `State`・`Kill`・`Wait`・`Delete` は [`TaskExecLauncher`] が差し込まれた
//! ときだけ動き、無ければ `UNIMPLEMENTED`（"exec_id is not supported"。何も登録できないため。TASK-62.4・#3681）。
//! `rootfs` と `options`（型に持たない）は repeated / 入れ子の確保を避けるため、復号前に走査して拒否する。
//!
//! 検査の順序（Create）: 復号前の走査（rootfs → options）→ 復号 → id → bundle → terminal → stdio → checkpoint。
//! 検査の順序（Exec）: 起動役の有無 → 復号 → id → exec_id → terminal / stdio → spec（type URL・上限・JSON・各欄）
//! → コンテナが Running か → 登録（重複・上限）。起動は `Start(exec_id)` が行う（containerd の意味論）。
//!
//! Delete の検査の順序: 復号（repeated / `Any` の欄が無いので走査は不要）→ exec_id があれば exec の経路 → id（アダプタ）。
//! 手順は state（削除前の pid・終了コードを採る）→ `remove(force=false)`。containerd の Delete に force は
//! 無く、実行中のコンテナは core の `FailedPrecondition`（9）で拒否される。応答の `exit_status` は
//! 終了コード（不明は 255）、`exited_at` は停止済みで core が記録した終了検知時刻（未記録は未設定。#3682）。
//! 既知の制約: state と remove の間に状態が変わりうる（その場合の `exit_status` は不正確）。pid のある
//! `Created` は core の契約で force=false では削除できない。plugin 越しでは最悪 2 回分の待ちになる。
//!
//! Wait（TASK-62.3.2）の検査の順序: 復号 → exec_id（空以外は exec の経路）→ id（アダプタの state）。
//! `RuntimeAdapter::wait_exit`（core の `ContainerRuntime::wait_exit`）で `Stopped` を待ち、終了コードを返す。期限は
//! `min(timeout_nano, WaitConfig::timeout)`（`timeout_nano` が 0 なら `WaitConfig` だけ）で、超えたら `DEADLINE_EXCEEDED`（4）。負の `timeout_nano` は runtime を呼ばずに 4。
//! 未起動の `Created` は終了扱いにしない。照会のエラー（待ちの途中の削除による NOT_FOUND を含む）は再試行せず返す。
//! サーバーは要求を接続内で並行 dispatch するため待ちは他の RPC を止めず、停止・切断の通知を受けた Wait は期限前に取り消される。
//!
//! Connect（TASK-62.6）: `id` をアダプタの state で確かめ、`shim_pid`（自プロセス）と `task_pid`（無ければ 0）を返す。`version` は空。
//!
//! State / Kill / Shutdown（TASK-62.7.2）:
//! - State: 状態は Creating / Created → CREATED、Running → RUNNING、Stopped → STOPPED、
//!   それ以外 → UNKNOWN。`exit_status` は STOPPED のときだけ終了コード（不明は 255）。`exited_at` は STOPPED で core が記録した終了検知時刻だけ
//!   （他の状態・未記録は未設定。値は壁時計で、誤差は wait の刻み程度。#3682）。`bundle`・stdio・`terminal` は
//!   shim が持たないため空・未設定（REPAIR-3）。
//! - Kill: `signal` は 1..=64 以外を `INVALID_ARGUMENT` にする。`all = true`
//!   （containerd の `WithKillAll`）はコンテナの cgroup 全体へ `cgroup.kill` で送り（core の `KillTarget::AllProcesses`。
//!   CRI-5・CORE-4）、SIGKILL 以外は `INVALID_ARGUMENT`。cgroup 配置の記録が無ければ `FAILED_PRECONDITION`（init だけへ
//!   縮退しない）。cgroup が既に無い・空なら成功。停止済みは runc shim と同じく `NOT_FOUND`（"process already finished"）。state と kill の間の競合は core の応答をそのまま返す。
//! - Shutdown: [`ShutdownSignal`] が差し込まれているときだけ動く。`now = true` かコンテナが残っていない（state が `NOT_FOUND`）とき
//!   終了を要求し、コンテナが残っていれば何もせず成功を返す（runc shim と同じ）。state の他のエラーは終了せずに返す（fail-closed）。冪等。
//!
//! exec_id つきの State / Kill / Wait / Delete（#3681・CRI-5・CRI-1。`adapter` は呼ばず、`created` も触らない）:
//! 検査の順序は 復号 → 起動役の有無 → `all`（Kill のみ）→ id → exec_id → signal の範囲（Kill のみ）→ 登録簿
//! （未登録は `NOT_FOUND` "exec not found"）。段階と戻り値は containerd v2.1.4 の意味論に合わせる
//! （`cmd/containerd-shim-runc-v2/task/service.go`・`process/exec.go`・`internal/cri/server/container_execsync.go`）:
//! - State: 未起動（Created / Starting）は CREATED・pid 0、実行中は RUNNING・pid、終了済みは STOPPED・pid・終了コード
//!   （不明・負値は 255）。応答の `id` は exec ID（runc と同じ。`exec_id` 欄は空）。
//! - Kill: 未起動は `FAILED_PRECONDITION`（"process not created"）、終了済みは `NOT_FOUND`（"process already finished"）、
//!   実行中は `TaskExecProcess::signal` の結果をそのまま返す。`status()` が `Err` でも SIGKILL のときは `signal` へ進む（消滅未確認の exec への再 kill。#4148）。`exec_id` と `all = true` の組は `UNIMPLEMENTED` のまま
//!   （runc の exec は `all` を無視するが、containerd v2.1.4 の `core/runtime/v2/process.go` は `all` を shim へ送らない。
//!   未対応の欄を黙って無視しない〔REPAIR-3〕ため拒否を保つ。別のクライアントで必要になれば条件を外すだけで戻せる）。
//! - Wait: containerd の CRI は `Wait` を `Start` より前に呼ぶ（ExecSync）ため、未起動は `Started` になるまで待ち、続けて終了を待つ。
//!   期限は `min(timeout_nano, WaitConfig::timeout)` で、超えたら `DEADLINE_EXCEEDED`。待ち中に登録が除去・再作成されたら
//!   `NOT_FOUND`（別登録へ乗り移らない）。`Started` を見つけた後はハンドルだけで待ち、Delete / purge が走っても終了コードを返す。
//! - Delete: 未起動と終了済みは登録を除去して pid・終了コード（未起動は 0）を返す。実行中は `FAILED_PRECONDITION`
//!   （"cannot delete a running process"）で除去しない。`status()` の失敗は除去せず返す（fail-closed）。コンテナのゲートを取り、
//!   `Start(exec_id)` の起動と直列にする。State / Kill / Wait はゲートを取らない。
//!
//! exec 登録の回収（#4058・CRI-5・REPAIR-5）: 登録簿は shim の外でコンテナが消えても残りうるため、次の契機で除去する。
//! いずれも当該コンテナのゲートを保持したまま実行層の `NOT_FOUND` を観測し、同じゲートの中で除去する
//! （`NOT_FOUND` 以外では除去しない。fail-closed）。
//! - T1 コンテナの Delete で state / remove が `NOT_FOUND`。T2 Exec / Start(exec_id) の Running 確認が `NOT_FOUND`。
//! - T3 shim の Create の成功（同じ ID の旧登録を引き継がない）。
//! - T4 Exec が全体上限（`MAX_EXECS_TOTAL`）で失敗したとき、ゲートを手放して登録のある別コンテナを `try_lock` で
//!   1 つずつ照会し、`NOT_FOUND` のものを除去してから 1 回だけやり直す（コンテナ単位の上限では掃除しない。
//!   照会は登録のあるコンテナ数以下で、全体上限を埋められる呼び出し元は peer UID 照合済み〔PLUG-12・#803〕のため
//!   レート制限は設けない）。v2 と v3 は [`TaskService::with_shared_created`] で登録簿を共有する。
//! - T5 インスタンスの照合（#4220・CRI-5・SEC-1・CORE-1）: shim の外で削除され、さらに外で同じ ID で作り直されると
//!   `state` は `NOT_FOUND` を返さず T1〜T4 に当たらない。そこで登録時のインスタンス識別子
//!   （[`RuntimeContainerStatus::instance`]）を持たせ、Exec・Start(exec_id)・T4 の掃除で、ゲート保持中に `state` が返した
//!   値と照合して違う登録を除去する。Start(exec_id) は除去後に `begin_start` が `NOT_FOUND`（"exec not found"。T1 と
//!   同じ結果）を返し、起動役を呼ばない。Exec は旧い登録を除いてから登録するため、同じ exec_id の再登録・
//!   コンテナ単位の上限も回復する。`None` 同士は判定できないので残す（片側だけ `None` は除去する）。
//!   exec_id つきの State / Kill / Wait / Delete は照合しない（adapter を呼ばない不変条件を保つ）ため、作り直された後の
//!   未起動の exec は次の Exec・Start(exec_id)・T4 で除去されるまで見えたままになるが、起動はされない。
//! - RuntimeService 側の Exec（ストリーミング）も同じ規則 `adapter::instance_matches` で、URL 発行時に記録した値を
//!   起動時に照合する（#4286。実装は plugin-cri の `exec_launcher`）。
//! - 残余: 識別子を報告しない実行層の実装と、識別子の記録が無い旧い状態のコンテナは T5 で保護されない。状態ルートを
//!   消して作り直すと revision の採番が初めからになるが、shim の寿命の中では現実には起きない。
//!
//! 未起動（Created）の exec の Wait は、コンテナが停止しても期限まで待つ（#4058・CRI-1。早期には返さない）。
//! 理由: (1) runc shim と同じ挙動（containerd v2.1.4 の `process/exec.go` の `Wait` は `waitBlock` を待ち、
//! `SetExited` は起動済みプロセスにだけ呼ばれる）。(2) 実際のクライアント（CRI の ExecSync）は Start が失敗すると
//! `Delete(exec_id)` を呼び、本 shim では登録が除去されて Wait が 1 刻み以内に `NOT_FOUND` で戻る。上記の回収でも同じ。
//! (3) それ以外は REPAIR-5 の期限が上限。(4) 早く返すには刻みごとに `adapter.state` を照会することになり、
//! 「exec_id つきの State / Kill / Wait / Delete は adapter を呼ばない」不変条件が崩れ、restart による一時的な
//! Stopped を終了と誤認しうる。
//!
//! 期限（REPAIR-5）: Wait は上記の期限を持つ。他のメソッドは `ContainerRuntime` の契約で実装側が期限を持ち、
//! shim は追加の期限を設けない。socket の権限・peer UID の照合は #803（TASK-62.7）の範囲。

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use prost::Message;

use super::exec::{
    ExecId, ExecPhase, ExecProcessStatus, ExecRegistry, TaskExecLauncher, parse_process_spec,
    sleep_until,
};
use super::message::{RpcStatus, count_top_level_field};
use super::publish::{
    EventGuard, EventPublisher, PublishFailure, PublishStage, TaskCreate, TaskDelete, TaskEvent,
    TaskExecAdded, TaskExecStarted, TaskExit, TaskIo, TaskStart,
};
use super::service::shutdown_gate_failure;
use super::service::{CallContext, TaskApiVersion, TtrpcService, unimplemented_status};
use super::shutdown::ShutdownSignal;
use super::task_api::{
    ConnectRequest, ConnectResponse, CreateTaskRequest, CreateTaskResponse, DeleteRequest,
    DeleteResponse, ExecProcessRequest, KillRequest, ShutdownRequest, StartRequest, StartResponse,
    StateRequest, StateResponse, TaskStatus, Timestamp, WaitRequest, WaitResponse,
};
use super::wait::WaitConfig;
use crate::adapter::{RuntimeAdapter, RuntimeContainerStatus, RuntimeLifecycle};
use crate::error::{CriError, CriErrorCode};
use fandhe_container_core::traits::{ContainerId, Signal};

/// `bundle` の最大バイト数（PATH_MAX 相当）。
pub(crate) const BUNDLE_MAX_LEN: usize = 4096;
/// `CreateTaskRequest.rootfs` のフィールド番号。
const FIELD_ROOTFS: u64 = 3;
/// `CreateTaskRequest.options`（`Any`）のフィールド番号。型には持たない。
const FIELD_OPTIONS: u64 = 10;

/// 終了コードが不明なときの `exit_status`。containerd クライアントの `UnknownExitStatus` に倣う。
const UNKNOWN_EXIT_STATUS: u32 = 255;
/// 同時に動かす終了 watcher の上限（`CREATED_MAX` と同じ。REPAIR-5）。
const MAX_EXIT_WATCHERS: usize = CREATED_MAX;
/// 終了 watcher の作成世代の採番（プロセス内で単調増加）。
static NEXT_WATCH_GENERATION: AtomicU64 = AtomicU64::new(1);
/// 照会の失敗が続いたときに watcher が諦めるまでの連続回数。
const EXIT_WATCH_MAX_ERRORS: u32 = 3;
/// 記録しておく作成済み ID の上限。Delete で除去するが、除去されない経路でも無制限に増やさない（REPAIR-5）。
const CREATED_MAX: usize = 1024;

/// Create / Start / Delete / Exec / Wait を処理する Task サービス。他のメソッドは `Unimplemented`。
///
/// `ContainerRuntime` 境界の RuntimeService とは別のアダプタで、[`RuntimeAdapter`] だけを通して実行層を呼ぶ
/// （TASK-62.5・CRI-5・CRI-7）。`CriRuntimeService::with_runtime` に渡すものと同じ `RuntimeAdapter` を
/// clone して [`TaskService::new`] に渡せば、同じ実装（同一の `Arc<dyn ContainerRuntime>`）を共有する。
pub struct TaskService {
    version: TaskApiVersion,
    adapter: RuntimeAdapter,
    exec_launcher: Option<Arc<dyn TaskExecLauncher>>,
    /// exec の登録簿。v2 と v3 で共有し（[`TaskService::with_shared_created`]）、どちらの Delete でも消える。
    execs: Arc<ExecRegistry>,
    wait_config: WaitConfig,
    shutdown: Option<ShutdownSignal>,
    /// この shim の Create で作ったコンテナ ID。Shutdown が「残っているか」を全 ID で判定し、
    /// Create と Shutdown の判定を排他する（ロックは Create / 判定の間だけ持つ）。
    ///
    /// v2 と v3 を同じ shim に登録するときは [`TaskService::with_shared_created`] で共有する。
    created: Arc<Mutex<BTreeSet<String>>>,
    /// イベント 6 種の送り先。無ければ Create・Start・Delete・Exec・Start(exec_id) は送らず、終了 watcher も起こさない（#4155・#4156・#4281・CRI-5）。
    event_publisher: Option<Arc<dyn EventPublisher>>,
    /// 稼働中の終了 watcher の ID。v2 と v3 で共有し、同じ ID の watcher を重複させず、数を `MAX_EXIT_WATCHERS` で抑える。
    /// 値は作成世代のトークン。Delete が登録を外し、世代が違う watcher は publish しない（#4155）。
    exit_watchers: WatchRegistry,
}

impl std::fmt::Debug for TaskService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskService")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl TaskService {
    /// 版とランタイムのアダプタから作る。`adapter` は RuntimeService と clone して共有してよい（CRI-7）。
    pub fn new(version: TaskApiVersion, adapter: RuntimeAdapter) -> Self {
        Self {
            version,
            adapter,
            exec_launcher: None,
            execs: Arc::new(ExecRegistry::new()),
            wait_config: WaitConfig::default(),
            shutdown: None,
            created: Arc::new(Mutex::new(BTreeSet::new())),
            event_publisher: None,
            exit_watchers: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// イベントの送り先を差し込む。差し込むと、Create・Start・Delete の成功ごとにイベントを投入し、init の `Start` 成功ごとに終了 watcher を 1 本起こし、
    /// 終了を観測したら 1 回だけ publish する（#4155・CRI-5・REPAIR-5）。Start・Wait・State・Delete の応答は変えない。
    ///
    /// watcher は `RuntimeAdapter::wait_exit` を期限つきで繰り返す。plugin-cri の `CoreLifecycleRuntime` は呼び出しごとに
    /// supervisor の終了通知を購読し（枠はコンテナごとに 8、超えたら照会へ縮退）、containerd の Wait RPC と並んでも壊れない。
    /// 待ち 1 回は [`WaitConfig`] の期限で有界だが、watcher の寿命全体は有界でない（コンテナが動く間は続く）。
    /// 数は `MAX_EXIT_WATCHERS` が上限。Wait・State の経路からは publish しない。Delete は watcher と送信権（`exit_claim`）を取り合い、未送信なら TaskDelete の直前に代わりに送る（#4224）。
    ///
    /// `Exec`・`Start(exec_id)` の成功では TaskExecAdded・TaskExecStarted も送る（#4281）。`Delete(exec_id)` は runc shim と同じく送らない。
    /// exec の TaskExit は送らない（exec 用の終了 watcher が無い。後続候補）。
    ///
    /// 残余: restart による一時的な Stopped は対象外。
    pub fn with_event_publisher(mut self, publisher: Arc<dyn EventPublisher>) -> Self {
        self.event_publisher = Some(publisher);
        self
    }

    /// Shutdown RPC の終了要求の送り先を差し込む。無ければ `Shutdown` は `UNIMPLEMENTED`（TASK-62.7.2）。
    pub fn with_shutdown(mut self, signal: ShutdownSignal) -> Self {
        self.shutdown = Some(signal);
        self
    }

    /// 作成済み ID の記録・判定用ロックと exec の登録簿（ゲートを含む）を `other` と共有する。
    /// 同じ shim に v2・v3 を登録するとき、Create と Shutdown の判定、および Delete による exec 登録の
    /// 回収をサービスをまたいで揃えるために使う（TASK-62.7.2・#4058・CRI-5）。
    pub fn with_shared_created(mut self, other: &TaskService) -> Self {
        self.created = Arc::clone(&other.created);
        self.execs = Arc::clone(&other.execs);
        self.exit_watchers = Arc::clone(&other.exit_watchers);
        self
    }

    /// Wait の期限と照会間隔を差し替える（既定は 60 秒・100 ミリ秒。REPAIR-5）。
    pub fn with_wait_config(mut self, cfg: WaitConfig) -> Self {
        self.wait_config = cfg;
        self
    }

    /// exec プロセスの起動役を差し込む。無ければ `Exec` と `Start(exec_id)` は `UNIMPLEMENTED`（TASK-62.4）。
    pub fn with_exec_launcher(mut self, launcher: Arc<dyn TaskExecLauncher>) -> Self {
        self.exec_launcher = Some(launcher);
        self
    }

    /// `State`: コンテナの現在状態を返す（TASK-62.7.2）。
    fn state(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = StateRequest::decode(payload).map_err(|_| decode_failure())?;
        if !req.exec_id.is_empty() {
            return self.state_exec(&req);
        }
        let st = self.adapter.state(&req.id).map_err(|e| to_status(&e))?;
        let (status, exit_status) = match st.lifecycle {
            RuntimeLifecycle::Creating | RuntimeLifecycle::Created => (TaskStatus::Created, 0),
            // 起動の途中（Running を記録したが init の pid がまだ無い）は未起動として返す。RUNNING・pid 0 を返すと
            // containerd が実在しない pid の RUNNING を見る（#4104・CRI-5）。pid が判明すれば RUNNING になる。
            RuntimeLifecycle::Running if st.pid.is_none() => (TaskStatus::Created, 0),
            RuntimeLifecycle::Running => (TaskStatus::Running, 0),
            RuntimeLifecycle::Stopped => (TaskStatus::Stopped, stopped_exit_status(&st)),
            _ => (TaskStatus::Unknown, 0),
        };
        Ok(StateResponse {
            id: req.id,
            pid: st.pid.unwrap_or(0),
            status: status as i32,
            exit_status,
            exited_at: exited_at_of(&st),
            ..Default::default()
        }
        .encode_to_vec())
    }

    /// `State(exec_id)`: 登録簿とハンドルから exec の状態を返す（#3681・CRI-5）。
    fn state_exec(&self, req: &StateRequest) -> Result<Vec<u8>, RpcStatus> {
        let (container, exec_id) = self.exec_target(&req.id, &req.exec_id)?;
        let snap = self
            .execs
            .snapshot(&container, &exec_id)
            .map_err(|e| to_status(&e))?;
        let (status, pid, exit_status) = match snap.phase {
            ExecPhase::Created | ExecPhase::Starting => (TaskStatus::Created, 0, 0),
            ExecPhase::Started { process } => {
                let pid = process.pid().map_or(0, NonZeroU32::get);
                match process.status().map_err(|e| to_status(&e))? {
                    ExecProcessStatus::Running => (TaskStatus::Running, pid, 0),
                    ExecProcessStatus::Exited { code } => {
                        (TaskStatus::Stopped, pid, exit_status_from_code(code))
                    }
                }
            }
        };
        Ok(StateResponse {
            id: req.exec_id.clone(),
            pid,
            status: status as i32,
            exit_status,
            ..Default::default()
        }
        .encode_to_vec())
    }

    /// exec 系 RPC の共通検証。起動役が無ければ `UNIMPLEMENTED`、続けて id・exec_id を検証する。
    fn exec_target(&self, id: &str, exec_id: &str) -> Result<(ContainerId, ExecId), RpcStatus> {
        if self.exec_launcher.is_none() {
            return Err(unsupported("exec_id is not supported"));
        }
        let container = ContainerId::new(id).map_err(|e| to_status(&CriError::from(&e)))?;
        let exec_id = ExecId::new(exec_id).map_err(|e| to_status(&e))?;
        Ok((container, exec_id))
    }

    /// `Connect`: shim デーモンと init プロセスの PID を返す（TASK-62.6・CRI-5）。
    ///
    /// containerd の `shimTask.PID` が Create の直後と Wait の前に呼び、失敗すると Create 全体が失敗する
    /// （containerd v2.1.4 `plugins/services/tasks/local.go`・`core/runtime/v2/shim.go`）。未起動は `task_pid = 0`。
    fn connect(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = ConnectRequest::decode(payload).map_err(|_| decode_failure())?;
        let st = self.adapter.state(&req.id).map_err(|e| to_status(&e))?;
        Ok(ConnectResponse {
            shim_pid: std::process::id(),
            task_pid: st.pid.unwrap_or(0),
            version: String::new(),
        }
        .encode_to_vec())
    }

    /// `Kill`: init プロセス（`all = true` はコンテナの cgroup 全体）へシグナルを送る（TASK-62.7.2・CRI-5）。
    fn kill(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = KillRequest::decode(payload).map_err(|_| decode_failure())?;
        if !req.exec_id.is_empty() {
            return self.kill_exec(&req);
        }
        // 状態の照会より前に検証する（停止済み・不在の ID でも範囲外は INVALID_ARGUMENT）。
        let signal = checked_signal(req.signal)?;
        if req.all {
            RuntimeAdapter::check_kill_all_signal(signal).map_err(|e| to_status(&e))?;
        }
        let st = self.adapter.state(&req.id).map_err(|e| to_status(&e))?;
        if st.lifecycle == RuntimeLifecycle::Stopped {
            return Err(RpcStatus::from_code(
                CriErrorCode::NotFound,
                "process already finished",
            ));
        }
        if req.all {
            self.adapter
                .kill_all(&req.id, signal)
                .map_err(|e| to_status(&e))?;
        } else {
            self.adapter
                .kill(&req.id, signal)
                .map_err(|e| to_status(&e))?;
        }
        Ok(Vec::new())
    }

    /// `Kill(exec_id)`: 実行中の exec プロセスへシグナルを送る（#3681・CRI-5）。
    fn kill_exec(&self, req: &KillRequest) -> Result<Vec<u8>, RpcStatus> {
        if self.exec_launcher.is_none() {
            return Err(unsupported("exec_id is not supported"));
        }
        if req.all {
            return Err(unsupported("kill all is not supported"));
        }
        let (container, exec_id) = self.exec_target(&req.id, &req.exec_id)?;
        let signal =
            Signal::new(checked_signal(req.signal)?).map_err(|e| to_status(&CriError::from(&e)))?;
        let snap = self
            .execs
            .snapshot(&container, &exec_id)
            .map_err(|e| to_status(&e))?;
        let ExecPhase::Started { process } = snap.phase else {
            return Err(to_status(&CriError::failed_precondition(
                "process not created",
            )));
        };
        match process.status() {
            Ok(ExecProcessStatus::Exited { .. }) => Err(RpcStatus::from_code(
                CriErrorCode::NotFound,
                "process already finished",
            )),
            Ok(ExecProcessStatus::Running) => {
                process.signal(signal).map_err(|e| to_status(&e))?;
                Ok(Vec::new())
            }
            // 状態を確定できなくても SIGKILL だけは届ける（kill 済みで消滅未確認の exec への再 kill を拒まない。
            // 起動役が自分で判断する。#4148・CRI-5）。SIGKILL 以外は fail-closed で状態のエラーを返す。
            Err(_) if signal == Signal::SIGKILL => {
                process.signal(signal).map_err(|e| to_status(&e))?;
                Ok(Vec::new())
            }
            Err(e) => Err(to_status(&e)),
        }
    }

    /// `Shutdown`: デーモンの終了を要求する（TASK-62.7.2）。コンテナが残っていれば何もしない。
    fn shutdown(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let Some(signal) = self.shutdown.as_ref() else {
            return Err(unsupported("shutdown is not supported"));
        };
        let req = ShutdownRequest::decode(payload).map_err(|_| decode_failure())?;
        if req.now {
            // 並行する Create と排他するため、要求を立てる間も `created` を持つ。
            let _created = self.created.lock().unwrap_or_else(|p| p.into_inner());
            signal.request().map_err(|_| shutdown_gate_failure())?;
            return Ok(Vec::new());
        }
        // 要求された ID だけでなく、この shim が作った全コンテナを確認する（別 ID の Shutdown で
        // 実行中のコンテナの接続を失わない）。Create とは `created` のロックで排他する。
        let mut created = self.created.lock().unwrap_or_else(|p| p.into_inner());
        let mut ids: Vec<String> = created.iter().cloned().collect();
        if !created.contains(&req.id) {
            ids.push(req.id.clone());
        }
        for id in ids {
            match self.adapter.state(&id) {
                Err(e) if e.code() == CriErrorCode::NotFound => {
                    created.remove(&id);
                }
                Err(e) => return Err(to_status(&e)),
                // 残っているコンテナがあれば終了を要求しない。
                Ok(_) => return Ok(Vec::new()),
            }
        }
        // 判定の完了まで `created` を持ったまま要求を立てる（以後の Create は拒否される）。
        signal.request().map_err(|_| shutdown_gate_failure())?;
        Ok(Vec::new())
    }

    /// 実行層が `NOT_FOUND` を返したときだけ、そのコンテナの exec 登録を除去する（#4058・CRI-5）。
    ///
    /// 呼び出し元は当該コンテナのゲートを保持したまま観測していること（観測から除去までに新しい登録が
    /// 割り込まない）。`NOT_FOUND` 以外（一時的な不達など）では除去しない（fail-closed）。
    fn purge_if_not_found(&self, container: &ContainerId, err: &CriError) {
        if err.code() == CriErrorCode::NotFound {
            // 登録簿が毒されていれば除去できないが、元のエラーを優先して返す。
            let _ = self.execs.purge_container(container);
        }
    }

    /// `adapter.state` を呼び、`NOT_FOUND` なら exec 登録を除去する（ゲート保持中に呼ぶ）。
    fn state_purging(&self, container: &ContainerId) -> Result<RuntimeContainerStatus, CriError> {
        self.adapter.state(container.as_str()).inspect_err(|e| {
            self.purge_if_not_found(container, e);
        })
    }

    /// 全体上限に達したときの掃除（#4058・CRI-5・REPAIR-5）。登録のある別コンテナを照会し、
    /// 実行層が `NOT_FOUND` を返すものの登録だけを除去する。
    ///
    /// ゲートは呼び出し元が手放してから呼ぶ。他コンテナのゲートは `try_lock` で 1 つずつ取り
    /// （同時に 2 つ以上持たない。取れない・毒されたものは飛ばす）、別コンテナの Start の完了待ちに巻き込まれない。
    /// 照会回数は登録のあるコンテナ数（`MAX_EXECS_TOTAL` 以下）で、各 `state` は `ContainerRuntime` の契約で有界。
    /// `NOT_FOUND` 以外のエラーでは除去しない。
    fn reclaim_gone_containers(&self, skip: &ContainerId) {
        let Ok(containers) = self.execs.containers() else {
            return;
        };
        for c in containers.iter().filter(|c| *c != skip) {
            let Ok(Some(_gate)) = self.execs.try_lock_container(c) else {
                continue;
            };
            match self.adapter.state(c.as_str()) {
                Err(e) => self.purge_if_not_found(c, &e),
                // 外で作り直されたコンテナの旧い登録も除去する（T5。#4220）。
                Ok(st) => {
                    let _ = self.execs.purge_mismatched(c, st.instance);
                }
            }
        }
    }

    /// `Exec`: exec プロセスを登録するだけで起動はしない（起動は `Start(exec_id)`）。
    fn exec(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        if self.exec_launcher.is_none() {
            return Err(unsupported("exec is not supported"));
        }
        let req = ExecProcessRequest::decode(payload).map_err(|_| decode_failure())?;
        let container = ContainerId::new(&req.id).map_err(|e| to_status(&CriError::from(&e)))?;
        let exec_id = ExecId::new(&req.exec_id).map_err(|e| to_status(&e))?;
        if req.terminal {
            return Err(unsupported("terminal is not supported"));
        }
        if !req.stdin.is_empty() || !req.stdout.is_empty() || !req.stderr.is_empty() {
            return Err(unsupported("stdio is not supported"));
        }
        let any = req.spec.as_ref().ok_or_else(|| {
            RpcStatus::from_code(CriErrorCode::InvalidArgument, "exec spec is required")
        })?;
        let spec = parse_process_spec(any).map_err(|e| to_status(&e))?;
        // 状態確認から登録までを Delete と排他する（削除途中の旧コンテナへ登録しない・purge に消されない）。
        let mut gate = self
            .execs
            .lock_container(&container)
            .map_err(|e| to_status(&e))?;
        let mut swept = false;
        loop {
            let status = self.state_purging(&container).map_err(|e| to_status(&e))?;
            if status.lifecycle != RuntimeLifecycle::Running {
                return Err(to_status(&CriError::failed_precondition(
                    "container is not running",
                )));
            }
            // 外で作り直されたコンテナの旧い登録を除いてから登録する（T5。#4220）。
            self.execs
                .purge_mismatched(&container, status.instance)
                .map_err(|e| to_status(&e))?;
            match self
                .execs
                .register(&container, &exec_id, spec.clone(), status.instance)
            {
                Ok(()) => {
                    // #4281: 成功する直前（ゲート保持中）に投入する。失敗した Exec では出さない。
                    self.emit(TaskEvent::ExecAdded(TaskExecAdded {
                        container_id: container.as_str().to_owned(),
                        exec_id: exec_id.as_str().to_owned(),
                    }));
                    return Ok(Vec::new());
                }
                // 全体上限のときだけ、外で消えたコンテナの登録を掃除して 1 回だけやり直す。
                // コンテナ単位の上限では掃除しても空きは生まれない。
                Err(e)
                    if !swept
                        && e.code() == CriErrorCode::ResourceExhausted
                        && self.execs.is_total_full().unwrap_or(false)
                        && !self.execs.is_container_full(&container).unwrap_or(true) =>
                {
                    swept = true;
                    drop(gate);
                    self.reclaim_gone_containers(&container);
                    gate = self
                        .execs
                        .lock_container(&container)
                        .map_err(|e| to_status(&e))?;
                }
                Err(e) => return Err(to_status(&e)),
            }
        }
    }

    /// `Start(exec_id)`: 登録済みの exec を起動役で起動する。
    ///
    /// 状態確認から起動役の完了・結果の反映までコンテナ単位のゲートを保持し、Delete と排他する
    /// （起動中に Delete と同じ ID の再作成が割り込み、旧登録の spec が新コンテナへ起動されるのを防ぐ。CRI-5）。
    /// 起動役は期限を自前で持つ契約（REPAIR-5）で、ゲートを保持したまま shim のサービスへ再入しない。
    fn start_exec(&self, req: &StartRequest) -> Result<Vec<u8>, RpcStatus> {
        let Some(launcher) = self.exec_launcher.as_ref() else {
            return Err(unsupported("exec_id is not supported"));
        };
        let container = ContainerId::new(&req.id).map_err(|e| to_status(&CriError::from(&e)))?;
        let exec_id = ExecId::new(&req.exec_id).map_err(|e| to_status(&e))?;
        let _gate = self
            .execs
            .lock_container(&container)
            .map_err(|e| to_status(&e))?;
        // Exec 後に停止したコンテナへ起動役を呼ばないよう、起動の直前にも Running を再確認する。
        let status = self.state_purging(&container).map_err(|e| to_status(&e))?;
        if status.lifecycle != RuntimeLifecycle::Running {
            return Err(to_status(&CriError::failed_precondition(
                "container is not running",
            )));
        }
        // 外で作り直されたコンテナの旧い登録を除去する。除去された登録は `begin_start` が `NOT_FOUND` にし、
        // 旧い spec は起動しない（T5。#4220・SEC-1）。
        self.execs
            .purge_mismatched(&container, status.instance)
            .map_err(|e| to_status(&e))?;
        let ticket = self
            .execs
            .begin_start(&container, &exec_id)
            .map_err(|e| to_status(&e))?;
        let result = launcher.launch(&container, &exec_id, &ticket.spec);
        self.execs
            .finish_start(&container, &exec_id, &ticket, result.as_ref().ok().cloned())
            .map_err(|e| to_status(&e))?;
        let process = result.map_err(|e| to_status(&e))?;
        let pid = process.pid().map_or(0, NonZeroU32::get);
        // #4281: 成功する直前（ゲート保持中）に投入する。pid は応答と同じ値（本番の起動役は 0）。
        self.emit(TaskEvent::ExecStarted(TaskExecStarted {
            container_id: container.as_str().to_owned(),
            exec_id: exec_id.as_str().to_owned(),
            pid,
        }));
        Ok(StartResponse { pid }.encode_to_vec())
    }

    fn create(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        reject_undecodable_fields(payload)?;
        let req = CreateTaskRequest::decode(payload).map_err(|_| decode_failure())?;
        let bundle = checked_bundle(&req.bundle)?;
        if req.terminal {
            return Err(unsupported("terminal is not supported"));
        }
        if !req.stdin.is_empty() || !req.stdout.is_empty() || !req.stderr.is_empty() {
            return Err(unsupported("stdio is not supported"));
        }
        if !req.checkpoint.is_empty() || !req.parent_checkpoint.is_empty() {
            return Err(unsupported("checkpoint is not supported"));
        }
        // 同じ ID の旧 exec 登録を成功後に除去するため、exec のゲートを `created` より先に取る
        // （Delete と同じ順。#4058）。ID が不正ならゲートは取らず、アダプタが拒否する。
        let container = ContainerId::new(&req.id).ok();
        let _gate = match &container {
            Some(c) => Some(self.execs.lock_container(c).map_err(|e| to_status(&e))?),
            None => None,
        };
        // Shutdown の判定と排他する。終了要求後の Create は受けない（接続が失われるため）。
        let mut created = self.created.lock().unwrap_or_else(|p| p.into_inner());
        if self
            .shutdown
            .as_ref()
            .is_some_and(ShutdownSignal::is_requested)
        {
            return Err(RpcStatus::from_code(
                CriErrorCode::Unavailable,
                "shim is shutting down",
            ));
        }
        if created.len() >= CREATED_MAX && !created.contains(&req.id) {
            return Err(RpcStatus::from_code(
                CriErrorCode::ResourceExhausted,
                "too many containers created in this shim",
            ));
        }
        let status = self
            .adapter
            .create(&req.id, bundle)
            .map_err(|e| to_status(&e))?;
        created.insert(req.id.clone());
        // 外で消えたコンテナの旧 watcher も取り消す（旧インスタンスの TaskExit を新コンテナの後に出さない。#4155）。
        self.revoke_watcher(&req.id);
        // 作成に成功した＝その ID は直前まで存在しなかったので、外で消えたコンテナの旧登録を引き継がない。
        if let Some(container) = &container {
            self.execs
                .purge_container(container)
                .map_err(|e| to_status(&e))?;
        }
        let pid = status.pid.unwrap_or(0);
        // #4156: 成功する直前（ゲート保持中）に投入する。失敗した RPC では出さない。
        self.emit(TaskEvent::Create(TaskCreate {
            container_id: req.id.clone(),
            bundle: req.bundle.clone(),
            rootfs: Vec::new(),
            io: Some(TaskIo::default()),
            checkpoint: String::new(),
            pid,
        }));
        Ok(CreateTaskResponse { pid }.encode_to_vec())
    }

    /// Create・Start・Delete・Exec・Start(exec_id) の成功イベントを投入する（#4156・#4281）。publisher が無ければ何もしない。
    /// 世代の guard は使わない（完了済みの RPC の事実の記録で、投入順はコンテナのゲートが決める）。
    fn emit(&self, event: TaskEvent) {
        if let Some(publisher) = &self.event_publisher {
            publisher.publish(event);
        }
    }

    fn start(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = StartRequest::decode(payload).map_err(|_| decode_failure())?;
        if !req.exec_id.is_empty() {
            return self.start_exec(&req);
        }
        // 実行層の Start から終了 watcher の登録までを、Create・Delete と同じコンテナ単位のゲートで排他する。
        // ゲート無しだと、旧 Start が中断中に旧コンテナの Delete・同 ID の再作成が済み、旧 pid の watcher が
        // 再作成後に登録されて新コンテナの TaskExit が `instance_mismatch` で捨てられる（CRI-5・#4155）。
        let container = ContainerId::new(&req.id).ok();
        let _gate = match &container {
            Some(c) => Some(self.execs.lock_container(c).map_err(|e| to_status(&e))?),
            None => None,
        };
        let status = self.adapter.start(&req.id).map_err(|e| to_status(&e))?;
        let pid = status.pid.unwrap_or(0);
        // TaskStart を TaskExit より先に投入する（速く終わるコンテナでも順序を保つ。#4156）。
        self.emit(TaskEvent::Start(TaskStart {
            container_id: req.id.clone(),
            pid,
        }));
        self.spawn_exit_watcher(&req.id, pid);
        Ok(StartResponse { pid }.encode_to_vec())
    }

    /// Delete が同じ ID の終了 watcher の登録を取り出す（#4224）。`revoked` は立てない。
    /// 登録表から外れるので、まだ観測していない watcher は黙って終わる。送信権（`exit_claim`）の取り合いは呼び出し側が行う。
    fn take_watcher_for_delete(&self, id: &str) -> Option<WatchEntry> {
        self.exit_watchers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(id)
    }

    /// Create・再 Start の置き換え専用: 同じ ID の旧世代の終了 watcher を取り消す。取り消しの印（`revoked`）を先に立ててから登録表から外す。
    /// 登録表のロックを持ったまま行うので、登録が無いと見えた側は必ず印を見る（#4155）。
    /// Delete は使わない（Delete は印を立てず `exit_claim` で TaskExit の送信権を取る。#4224）。
    fn revoke_watcher(&self, id: &str) {
        let mut set = self.exit_watchers.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(old) = set.get(id) {
            old.revoked.store(true, Ordering::Release);
        }
        set.remove(id);
    }

    /// init の終了 watcher を起こす（#4155）。publisher が無い場合は何もしない。既存の同じ ID の登録は置き換える。
    /// 上限超過とスレッドの起動失敗は構造化ログを 1 件出して起こさない（Start の応答は変えない）。
    fn spawn_exit_watcher(&self, id: &str, start_pid: u32) {
        let Some(publisher) = &self.event_publisher else {
            return;
        };
        let generation = NEXT_WATCH_GENERATION.fetch_add(1, Ordering::Relaxed);
        let revoked = Arc::new(AtomicBool::new(false));
        let exit_claim = Arc::new(Mutex::new(false));
        {
            let mut set = self.exit_watchers.lock().unwrap_or_else(|p| p.into_inner());
            // Delete・Create が取り消さずに残った旧世代（外で消えたコンテナ等）は、Start 成功の時点で
            // 現在のインスタンスのものではない。印を先に立ててから置き換える（#4155）。
            if let Some(old) = set.remove(id) {
                old.revoked.store(true, Ordering::SeqCst);
            }
            if set.values().filter(|e| !e.done).count() >= MAX_EXIT_WATCHERS {
                drop(set);
                publisher.report(PublishFailure::new(PublishStage::WatchLimit, None));
                return;
            }
            set.insert(
                id.to_owned(),
                WatchEntry {
                    generation,
                    done: false,
                    revoked: Arc::clone(&revoked),
                    exit_claim: Arc::clone(&exit_claim),
                    start_pid,
                },
            );
        }
        let ctx = ExitWatch {
            adapter: self.adapter.clone(),
            publisher: Arc::clone(publisher),
            wait: self.wait_config,
            shutdown: self.shutdown.clone(),
            id: id.to_owned(),
            start_pid,
            generation,
            revoked,
            exit_claim,
            watchers: Arc::clone(&self.exit_watchers),
        };
        let watchers = Arc::clone(&self.exit_watchers);
        let spawned = std::thread::Builder::new()
            .name("shim-exit-watch".into())
            .spawn(move || {
                ctx.run();
                ctx.unregister();
            });
        if spawned.is_err() {
            let mut set = watchers.lock().unwrap_or_else(|p| p.into_inner());
            if set.get(id).is_some_and(|e| e.generation == generation) {
                set.remove(id);
            }
            drop(set);
            publisher.report(PublishFailure::new(PublishStage::WatchSpawn, None));
        }
    }

    fn delete(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = DeleteRequest::decode(payload).map_err(|_| decode_failure())?;
        if !req.exec_id.is_empty() {
            return self.delete_exec(&req);
        }
        // remove から purge までを同じコンテナの Exec / Start と排他する（CRI-5）。
        let container = ContainerId::new(&req.id).ok();
        let _gate = match &container {
            Some(c) => Some(self.execs.lock_container(c).map_err(|e| to_status(&e))?),
            None => None,
        };
        // 実行層の削除から `created` の登録除去までを、Create・Shutdown と同じロックで排他する。
        // 放すと並行する Create が同じ ID を再作成して登録した後に、その新しい登録を消してしまい、
        // Shutdown(now=false) が生存コンテナを見落として終了を要求する（CRI-5・TASK-62.7.2）。
        let mut created = self.created.lock().unwrap_or_else(|p| p.into_inner());
        // 状態を採れなければ削除しない（fail-closed。NotFound はそのまま 5）。
        // shim の外で消えたコンテナ（NOT_FOUND）の exec 登録はここで除去する（#4058）。
        let gone = |e: CriError| {
            if let Some(c) = &container {
                self.purge_if_not_found(c, &e);
            }
            to_status(&e)
        };
        let before = self.adapter.state(&req.id).map_err(gone)?;
        self.adapter.remove(&req.id, false).map_err(gone)?;
        created.remove(&req.id);
        drop(created);
        // 旧コンテナの終了 watcher の登録を外す（同じ ID の再作成・再 Start で新しい世代が登録できる。#4155）。
        // `revoked` は立てない。watcher が既に TaskExit をキューへ入れていれば TaskDelete より先に届き、
        // まだなら Delete が送信権を取って代わりに送る（Wait 直後の Delete でも取り逃さない。#4224）。
        let watcher = self.take_watcher_for_delete(&req.id);
        if self.event_publisher.is_some() && before.lifecycle == RuntimeLifecycle::Stopped {
            let start_pid = watcher.as_ref().map_or(0, |w| w.start_pid);
            let claim = watcher.as_ref().map(|w| Arc::clone(&w.exit_claim));
            // 順序は claim → registry（登録表のロックは上で解放済み）。watcher の enqueue の完了まで待つ。
            let mut guard = claim
                .as_ref()
                .map(|c| c.lock().unwrap_or_else(|p| p.into_inner()));
            let claimed = guard.as_deref().copied().unwrap_or(false);
            if !claimed {
                if let Some(g) = guard.as_deref_mut() {
                    *g = true;
                }
                match task_exit_from(&req.id, start_pid, &before) {
                    Ok(exit) => self.emit(TaskEvent::Exit(exit)),
                    Err(failure) => {
                        if let Some(publisher) = &self.event_publisher {
                            publisher.report(failure);
                        }
                    }
                }
            }
            drop(guard);
        }
        // 削除成功後に旧コンテナの exec 登録を除去する（同じ ID の再作成で引き継がない。CRI-5）。
        if let Some(container) = &container {
            self.execs
                .purge_container(container)
                .map_err(|e| to_status(&e))?;
        }
        let resp = DeleteResponse {
            pid: before.pid.unwrap_or(0),
            exit_status: exit_status_of(&before),
            exited_at: exited_at_of(&before),
        };
        self.emit(TaskEvent::Delete(TaskDelete {
            container_id: req.id.clone(),
            pid: resp.pid,
            exit_status: resp.exit_status,
            exited_at: resp.exited_at.clone(),
            // runc shim v2 の `Delete` は init の TaskDelete に `ID` を設定しない（省略 = init。containerd v2.1.4
            // `cmd/containerd-shim-runc-v2/task/service.go`・`api/events/task.proto`。#4222）。TaskExit だけが `p.ID()` を持つ。
            id: String::new(),
        }));
        Ok(resp.encode_to_vec())
    }

    /// `Delete(exec_id)`: 未起動または終了済みの exec の登録を除去する（#3681・CRI-5）。
    ///
    /// コンテナのゲートを取り、`Start(exec_id)` の起動と直列にする（Created から Starting への遷移と除去が交差しない）。
    /// ハンドルの照会はロック（登録簿の内部ロック）を持たずに行う。
    fn delete_exec(&self, req: &DeleteRequest) -> Result<Vec<u8>, RpcStatus> {
        let (container, exec_id) = self.exec_target(&req.id, &req.exec_id)?;
        let _gate = self
            .execs
            .lock_container(&container)
            .map_err(|e| to_status(&e))?;
        let snap = self
            .execs
            .snapshot(&container, &exec_id)
            .map_err(|e| to_status(&e))?;
        let running = || {
            to_status(&CriError::failed_precondition(
                "cannot delete a running process",
            ))
        };
        let (pid, exit_status) = match snap.phase {
            ExecPhase::Created => (0, 0),
            // ゲート保持中に Starting を見るのは起動役の panic で残った場合だけ。生きているかもしれないので除去しない。
            ExecPhase::Starting => return Err(running()),
            ExecPhase::Started { process } => match process.status().map_err(|e| to_status(&e))? {
                ExecProcessStatus::Running => return Err(running()),
                ExecProcessStatus::Exited { code } => (
                    process.pid().map_or(0, NonZeroU32::get),
                    exit_status_from_code(code),
                ),
            },
        };
        self.execs
            .remove(&container, &exec_id)
            .map_err(|e| to_status(&e))?;
        Ok(DeleteResponse {
            pid,
            exit_status,
            exited_at: None,
        }
        .encode_to_vec())
    }

    /// `Wait(exec_id)`: exec が起動して終了するまで待ち、終了コードを返す（#3681・CRI-5・CRI-1・REPAIR-5）。
    ///
    /// containerd の CRI は `Wait` を `Start` より前に呼ぶため、未起動の間は登録簿を刻みごとに見て `Started` を待つ。
    /// ゲートは取らない（Kill / Delete を止めない）。`Started` になったらハンドルだけで待つ。
    fn wait_exec(&self, req: &WaitRequest, ctx: &CallContext<'_>) -> Result<Vec<u8>, RpcStatus> {
        let (container, exec_id) = self.exec_target(&req.id, &req.exec_id)?;
        let deadline_exceeded = || to_status(&CriError::timeout("wait exceeded its deadline"));
        let cancelled = || to_status(&CriError::unavailable("wait cancelled"));
        let Some(timeout) = ctx
            .deadline
            .limit_from(Instant::now(), self.wait_config.timeout())
        else {
            return Err(deadline_exceeded());
        };
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| to_status(&CriError::internal("wait deadline overflow")))?;
        let poll = self.wait_config.poll_interval();
        let first = self
            .execs
            .snapshot(&container, &exec_id)
            .map_err(|e| to_status(&e))?;
        let mut current = first.clone();
        let process = loop {
            if let ExecPhase::Started { process } = &current.phase {
                break Arc::clone(process);
            }
            if (ctx.cancelled)() {
                return Err(cancelled());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(deadline_exceeded());
            }
            if !sleep_until(now + poll.min(deadline - now), ctx.cancelled) {
                return Err(cancelled());
            }
            current = self
                .execs
                .snapshot(&container, &exec_id)
                .map_err(|e| to_status(&e))?;
            // 削除・再作成で別の登録になったら乗り移らない。
            if !current.is_same_registration(&first) {
                return Err(to_status(&CriError::not_found("exec not found")));
            }
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let code = process
            .wait_exit(remaining, poll, ctx.cancelled)
            .map_err(|e| to_status(&e))?;
        Ok(WaitResponse {
            exit_status: exit_status_from_code(code),
            exited_at: None,
        }
        .encode_to_vec())
    }

    /// `Wait`: コンテナが `Stopped` になるまで `RuntimeAdapter::wait_exit` で待ち、終了コードを返す
    /// （TASK-62.3.2・CRI-1）。
    ///
    /// exec のゲート（`execs.lock_container`）は意図して取らない。取ると待っている間ずっと同じコンテナの
    /// Delete / Exec / Start(exec_id) が止まる。期限は `min(timeout_nano, WaitConfig::timeout)`
    /// （`timeout_nano` が 0 なら `WaitConfig` だけ。REPAIR-5）で、負値と残り 0 は runtime を呼ばずに
    /// `DEADLINE_EXCEEDED`。検査の順序は 復号 → exec_id → id → 期限。Wait だけが期限を使う
    /// （他のメソッドは短く、`ContainerRuntime` の契約で有界）。`exited_at` は core が記録した終了検知時刻
    /// （未記録は未設定。#3682）。
    fn wait(&self, payload: &[u8], ctx: &CallContext<'_>) -> Result<Vec<u8>, RpcStatus> {
        let req = WaitRequest::decode(payload).map_err(|_| decode_failure())?;
        if !req.exec_id.is_empty() {
            return self.wait_exec(&req, ctx);
        }
        ContainerId::new(&req.id).map_err(|e| to_status(&CriError::from(&e)))?;
        let Some(timeout) = ctx
            .deadline
            .limit_from(Instant::now(), self.wait_config.timeout())
        else {
            return Err(to_status(&CriError::timeout("wait exceeded its deadline")));
        };
        let st = self
            .adapter
            .wait_exit(
                &req.id,
                timeout,
                self.wait_config.poll_interval(),
                ctx.cancelled,
            )
            .map_err(|e| to_status(&e))?;
        Ok(WaitResponse {
            exit_status: stopped_exit_status(&st),
            exited_at: exited_at_of(&st),
        }
        .encode_to_vec())
    }
}

/// 終了 watcher の登録表（ID → 登録）。v2 と v3 で共有する。
type WatchRegistry = Arc<Mutex<BTreeMap<String, WatchEntry>>>;

/// 登録 1 件。`revoked` は Create（外で消えた ID）と再 Start の置き換えだけが立てる。watcher が終了して登録を外しても立たないため、
/// キューで待つ TaskExit は「置き換えられた旧世代」だけを送信直前の再確認で捨てられる（CRI-5・#4155）。
/// Delete は `revoked` を立てず、`exit_claim` で TaskExit の送信権を watcher と取り合う（#4224）。
#[derive(Debug, Clone)]
struct WatchEntry {
    generation: u64,
    /// watcher の thread が終わった。登録は Delete まで残し、同じ ID の再 Start では置き換える。
    done: bool,
    revoked: Arc<AtomicBool>,
    /// TaskExit の送信権の印。真なら watcher が送信済み（キュー投入済み）。保持中に enqueue まで行う直列化ロックを兼ねる。
    /// ロック順は claim → 登録表で固定する。
    exit_claim: Arc<Mutex<bool>>,
    /// Start 時の pid。Delete が watcher と同じ pid 食い違い規則を適用するため。
    start_pid: u32,
}

/// 終了 watcher 1 本の持ち物（#4155）。`TaskService::spawn_exit_watcher` が起こすスレッドが所有する。
struct ExitWatch {
    adapter: RuntimeAdapter,
    publisher: Arc<dyn EventPublisher>,
    wait: WaitConfig,
    shutdown: Option<ShutdownSignal>,
    id: String,
    start_pid: u32,
    /// この watcher の作成世代。登録表の値と一致する間だけ有効（Delete で外れる）。
    generation: u64,
    revoked: Arc<AtomicBool>,
    /// [`WatchEntry::exit_claim`] と同じ印。取った側だけが TaskExit を送る。
    exit_claim: Arc<Mutex<bool>>,
    watchers: WatchRegistry,
}

impl ExitWatch {
    /// 登録表の世代が自分のものか。Delete・再作成で外れていれば false。
    fn is_current(&self) -> bool {
        self.watchers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&self.id)
            .is_some_and(|e| e.generation == self.generation)
    }

    /// 自分の世代の登録を終了済みにする（新しい世代の登録は触らない）。登録自体は Delete まで残し、
    /// キューで待つ TaskExit の取り消し先（`revoked`）を失わない。
    fn unregister(&self) {
        let mut set = self.watchers.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(e) = set.get_mut(&self.id)
            && e.generation == self.generation
        {
            e.done = true;
        }
    }

    /// 終了を観測して TaskExit を 1 回だけ publish する。`Timeout` は周回を続け、`NotFound`（観測前の削除）と取り消しは黙って終わる。
    /// その他の失敗は照会間隔だけ待って再試行し、連続 [`EXIT_WATCH_MAX_ERRORS`] 回で `watch` を 1 件記録して諦める。
    fn run(&self) {
        let cancelled = || {
            self.shutdown
                .as_ref()
                .is_some_and(ShutdownSignal::is_requested)
                || !self.is_current()
        };
        let mut errors = 0;
        loop {
            if cancelled() {
                return;
            }
            match self.adapter.wait_exit(
                &self.id,
                self.wait.timeout(),
                self.wait.poll_interval(),
                &cancelled,
            ) {
                Ok(st) => {
                    self.publish_exit(&st);
                    return;
                }
                Err(e) => match e.code() {
                    CriErrorCode::Timeout => errors = 0,
                    CriErrorCode::NotFound => return,
                    _ => {
                        errors += 1;
                        if cancelled() {
                            return;
                        }
                        if errors >= EXIT_WATCH_MAX_ERRORS {
                            self.publisher
                                .report(PublishFailure::new(PublishStage::Watch, None));
                            return;
                        }
                        sleep_until(Instant::now() + self.wait.poll_interval(), &cancelled);
                    }
                },
            }
        }
    }

    /// 停止済みの状態から TaskExit を組み立てて送る。pid が Start 時と食い違えば作り直しとみなして送らない。
    /// 送信権（`exit_claim`）を取った側だけが送る。Delete が先に取っていれば何もしない（#4224）。
    fn publish_exit(&self, st: &RuntimeContainerStatus) {
        // 順序は claim → 登録表。Delete は登録表のロックを放してから claim を取る。
        let mut claimed = self.exit_claim.lock().unwrap_or_else(|p| p.into_inner());
        if *claimed || self.revoked.load(Ordering::Acquire) {
            return;
        }
        // 登録表から外れた世代（Delete 済みで Delete が送信する・再作成）は送らない。
        if !self.is_current() {
            return;
        }
        let exit = match task_exit_from(&self.id, self.start_pid, st) {
            Ok(exit) => exit,
            Err(failure) => {
                self.publisher.report(failure);
                return;
            }
        };
        *claimed = true;
        // 確認後に再作成・再 Start が割り込んでも、キューの中と送信直前で世代を再確認して旧世代を捨てる。
        let revoked = Arc::clone(&self.revoked);
        let guard: EventGuard = Arc::new(move || !revoked.load(Ordering::Acquire));
        self.publisher.publish_guarded(TaskEvent::Exit(exit), guard);
    }
}

/// 停止済みの状態から TaskExit を組み立てる。watcher と Delete が共有する（#4224）。
/// pid が Start 時と食い違えば別インスタンスとみなして `InstanceMismatch` を返す（`start_pid == 0` は検査しない）。
fn task_exit_from(
    id: &str,
    start_pid: u32,
    st: &RuntimeContainerStatus,
) -> Result<TaskExit, PublishFailure> {
    if let Some(p) = st.pid
        && start_pid != 0
        && p != start_pid
    {
        return Err(PublishFailure::new(
            PublishStage::InstanceMismatch,
            Some(super::publish::TASK_EXIT_TOPIC),
        ));
    }
    Ok(TaskExit {
        container_id: id.to_owned(),
        id: id.to_owned(),
        pid: st.pid.unwrap_or(start_pid),
        exit_status: stopped_exit_status(st),
        exited_at: exited_at_of(st),
    })
}

/// 停止済みの状態から `exited_at` を決める。Stopped 以外・未記録・負値は未設定（値を捏造しない。CRI-5・#3682）。
pub(crate) fn exited_at_of(status: &RuntimeContainerStatus) -> Option<Timestamp> {
    if status.lifecycle != RuntimeLifecycle::Stopped {
        return None;
    }
    let nanos = u64::try_from(status.exited_at_nanos?).ok()?;
    Some(Timestamp::from_unix_duration(
        std::time::Duration::from_nanos(nanos),
    ))
}

/// 停止済みの状態から `exit_status` を決める。終了コード不明・負値は 255。
fn stopped_exit_status(status: &RuntimeContainerStatus) -> u32 {
    exit_status_from_code(status.exit_code)
}

/// 終了コードから `exit_status` を決める。不明・負値は 255。
fn exit_status_from_code(code: Option<i32>) -> u32 {
    code.and_then(|c| u32::try_from(c).ok())
        .unwrap_or(UNKNOWN_EXIT_STATUS)
}

/// `Kill.signal` を 1..=64 に検査する（範囲外は `INVALID_ARGUMENT`）。
fn checked_signal(signal: u32) -> Result<u8, RpcStatus> {
    u8::try_from(signal)
        .ok()
        .filter(|n| (1..=64).contains(n))
        .ok_or_else(|| {
            RpcStatus::from_code(
                CriErrorCode::InvalidArgument,
                "signal number must be in 1..=64",
            )
        })
}

/// 削除前の状態から `exit_status` を決める。未起動の Created は 0、終了コード不明・負値は 255。
pub(crate) fn exit_status_of(status: &RuntimeContainerStatus) -> u32 {
    match (status.lifecycle, status.exit_code) {
        (RuntimeLifecycle::Stopped, _) => stopped_exit_status(status),
        (RuntimeLifecycle::Created, _) if status.pid.is_none() => 0,
        _ => UNKNOWN_EXIT_STATUS,
    }
}

impl TtrpcService for TaskService {
    fn name(&self) -> &str {
        self.version.service_name()
    }

    fn handle(&self, method: &str, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        match method {
            "Create" => self.create(payload),
            "Start" => self.start(payload),
            "Delete" => self.delete(payload),
            "Exec" => self.exec(payload),
            "Wait" => self.wait(payload, &CallContext::none()),
            "State" => self.state(payload),
            "Kill" => self.kill(payload),
            "Shutdown" => self.shutdown(payload),
            "Connect" => self.connect(payload),
            _ => Err(unimplemented_status("method", method)),
        }
    }

    /// Wait だけ取り消しとクライアントの期限を伝える。他のメソッドは短時間で終わるため `handle` と同じ。
    fn handle_with_context(
        &self,
        method: &str,
        payload: &[u8],
        ctx: &CallContext<'_>,
    ) -> Result<Vec<u8>, RpcStatus> {
        match method {
            "Wait" => self.wait(payload, ctx),
            _ => self.handle(method, payload),
        }
    }
}

/// `CriError` を ttrpc の status へ写す（ERR-3 の写像は `CriErrorCode::grpc_code` に一本化済み）。
fn to_status(err: &CriError) -> RpcStatus {
    RpcStatus::from_code(err.code(), err.message())
}

fn unsupported(msg: &str) -> RpcStatus {
    RpcStatus::from_code(CriErrorCode::Unimplemented, msg)
}

/// 固定の英語文だけを返す（payload の内容はエコーしない）。
fn decode_failure() -> RpcStatus {
    RpcStatus::from_code(CriErrorCode::InvalidArgument, "malformed request payload")
}

/// 復号前の走査で `rootfs`・`options` の存在を検出して拒否する（確保を避ける。不安全な設計への対策）。
fn reject_undecodable_fields(payload: &[u8]) -> Result<(), RpcStatus> {
    for (field, msg) in [
        (FIELD_ROOTFS, "rootfs mounts are not supported"),
        (FIELD_OPTIONS, "options are not supported"),
    ] {
        match count_top_level_field(payload, field, 0) {
            None => return Err(decode_failure()),
            Some(0) => {}
            Some(_) => return Err(unsupported(msg)),
        }
    }
    Ok(())
}

/// `bundle` の形式を検査する（空・NUL・`..`・長さ超過を拒否。絶対パスの確認は `CreateRequest::new`）。
fn checked_bundle(bundle: &str) -> Result<PathBuf, RpcStatus> {
    let invalid = |m: &str| RpcStatus::from_code(CriErrorCode::InvalidArgument, m);
    if bundle.is_empty() {
        return Err(invalid("bundle must not be empty"));
    }
    if bundle.len() > BUNDLE_MAX_LEN {
        return Err(invalid("bundle path is too long"));
    }
    if bundle.contains('\0') {
        return Err(invalid("bundle must not contain NUL"));
    }
    let path = Path::new(bundle);
    if path.components().any(|c| c == Component::ParentDir) {
        return Err(invalid("bundle must not contain '..'"));
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::num::NonZeroU32;
    use std::sync::{Arc, Mutex};

    use fandhe_container_core::traits::{
        ContainerId as RtId, ContainerInstance, ContainerRuntime, ContainerState, ContainerStatus,
        CreateRequest, DeleteRequest as RtDelete, DeleteResponse as RtDeleteResponse, ErrorCode,
        KillRequest, StartRequest as RtStart, StateRequest, StopRequest, TraitError,
    };

    use super::super::exec::{ExecProcessSpec, PROCESS_TYPE_URL, TaskExecProcess};
    use super::super::service::RequestDeadline;
    use super::super::task_api::{
        Any, ConnectRequest, ConnectResponse, KillRequest as WireKill, Mount,
        StateRequest as WireState,
    };
    use super::*;

    /// 呼び出しと状態を記録する偽のランタイム。
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        states: Mutex<HashMap<String, ContainerState>>,
        create_pid: Option<u32>,
        wrong_id: bool,
        /// state が返す状態の上書き（終了コード等を差し込む）。
        preset: Mutex<HashMap<String, ContainerStatus>>,
        /// `Kill(all=true)` を配置の記録が無いコンテナと同じ `FailedPrecondition` で失敗させる（#4055）。
        kill_all_err: bool,
        /// state が UNAVAILABLE を返す ID（一時的な不達の注入。#4058）。
        fail_state: Mutex<std::collections::HashSet<String>>,
        /// state が報告するインスタンス識別子（ID ごと。無ければ報告しない。#4220）。
        instances: Mutex<HashMap<String, u64>>,
    }

    struct Shared(Arc<Fake>);

    impl ContainerRuntime for Shared {
        fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
            let id = r.id().as_str().to_owned();
            self.0
                .calls
                .lock()
                .unwrap()
                .push(format!("create {id} {}", r.bundle().display()));
            let mut st = self.0.states.lock().unwrap();
            if st.contains_key(&id) {
                return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
            }
            st.insert(id.clone(), ContainerState::Created);
            let rid = if self.0.wrong_id {
                fandhe_container_core::traits::ContainerId::new("other").unwrap()
            } else {
                r.id().clone()
            };
            Ok(ContainerStatus::created(
                rid,
                self.0.create_pid.and_then(NonZeroU32::new),
            ))
        }
        fn start(&self, r: &RtStart) -> Result<ContainerStatus, TraitError> {
            let id = r.id().as_str().to_owned();
            self.0.calls.lock().unwrap().push(format!("start {id}"));
            let mut st = self.0.states.lock().unwrap();
            match st.get(&id) {
                None => Err(TraitError::new(ErrorCode::NotFound, "none")),
                Some(ContainerState::Created) => {
                    st.insert(id, ContainerState::Running);
                    Ok(ContainerStatus::running(
                        r.id().clone(),
                        NonZeroU32::new(4242),
                    ))
                }
                Some(_) => Err(TraitError::new(ErrorCode::FailedPrecondition, "state")),
            }
        }
        fn kill(&self, r: &KillRequest) -> Result<ContainerStatus, TraitError> {
            let id = r.id().as_str().to_owned();
            self.0.calls.lock().unwrap().push(match r.target() {
                fandhe_container_core::traits::KillTarget::AllProcesses => {
                    format!("kill-all {id} {}", r.signal().as_u8())
                }
                _ => format!("kill {id} {}", r.signal().as_u8()),
            });
            if self.0.kill_all_err
                && matches!(
                    r.target(),
                    fandhe_container_core::traits::KillTarget::AllProcesses
                )
            {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "no cgroup placement recorded",
                ));
            }
            Ok(ContainerStatus::running(
                r.id().clone(),
                NonZeroU32::new(4242),
            ))
        }
        fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }
        fn delete(&self, r: &RtDelete) -> Result<RtDeleteResponse, TraitError> {
            let id = r.id().as_str().to_owned();
            self.0
                .calls
                .lock()
                .unwrap()
                .push(format!("delete {id} force={}", r.force()));
            let mut st = self.0.states.lock().unwrap();
            match st.get(&id) {
                None => Err(TraitError::new(ErrorCode::NotFound, "none")),
                Some(ContainerState::Running) => {
                    Err(TraitError::new(ErrorCode::FailedPrecondition, "running"))
                }
                Some(_) => {
                    st.remove(&id);
                    Ok(RtDeleteResponse::new())
                }
            }
        }
        fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
            let id = r.id().as_str().to_owned();
            self.0.calls.lock().unwrap().push(format!("state {id}"));
            if self.0.fail_state.lock().unwrap().contains(&id) {
                return Err(TraitError::new(ErrorCode::Unavailable, "unavailable"));
            }
            if let Some(p) = self.0.preset.lock().unwrap().get(&id) {
                return Ok(p.clone());
            }
            let instance = self.0.instances.lock().unwrap().get(&id).copied();
            let status = match self.0.states.lock().unwrap().get(&id) {
                None => Err(TraitError::new(ErrorCode::NotFound, "none")),
                Some(ContainerState::Running) => Ok(ContainerStatus::running(
                    r.id().clone(),
                    NonZeroU32::new(4242),
                )),
                Some(_) => Ok(ContainerStatus::created(r.id().clone(), None)),
            };
            status.map(|st| match instance {
                Some(i) => st.with_instance(ContainerInstance::from_raw(i)),
                None => st,
            })
        }
    }

    /// 終了を外から注入でき、受けたシグナルを記録する偽の exec プロセス。
    #[derive(Default)]
    struct FakeProc {
        pid: Option<NonZeroU32>,
        status: Mutex<Option<ExecProcessStatus>>,
        signals: Mutex<Vec<u8>>,
        status_fails: Mutex<bool>,
    }

    impl FakeProc {
        fn new(pid: u32) -> Arc<Self> {
            Arc::new(Self {
                pid: NonZeroU32::new(pid),
                ..Default::default()
            })
        }
        fn exit(&self, code: Option<i32>) {
            *self.status.lock().unwrap() = Some(ExecProcessStatus::Exited { code });
        }
    }

    impl TaskExecProcess for FakeProc {
        fn pid(&self) -> Option<NonZeroU32> {
            self.pid
        }
        fn status(&self) -> Result<ExecProcessStatus, CriError> {
            if *self.status_fails.lock().unwrap() {
                return Err(CriError::unavailable("status failed"));
            }
            Ok((*self.status.lock().unwrap()).unwrap_or(ExecProcessStatus::Running))
        }
        fn signal(&self, signal: Signal) -> Result<(), CriError> {
            self.signals.lock().unwrap().push(signal.as_u8());
            Ok(())
        }
    }

    /// 引数を記録する偽の起動役。起動したプロセスは `last` から引ける。
    #[derive(Default)]
    struct FakeLauncher {
        launched: Mutex<Vec<(String, String, ExecProcessSpec)>>,
        procs: Mutex<Vec<Arc<FakeProc>>>,
        fail: Mutex<bool>,
    }

    impl FakeLauncher {
        fn last(&self) -> Arc<FakeProc> {
            Arc::clone(self.procs.lock().unwrap().last().unwrap())
        }
    }

    impl TaskExecLauncher for FakeLauncher {
        fn launch(
            &self,
            c: &ContainerId,
            e: &ExecId,
            s: &ExecProcessSpec,
        ) -> Result<Arc<dyn TaskExecProcess>, CriError> {
            if *self.fail.lock().unwrap() {
                return Err(CriError::unavailable("launch failed"));
            }
            self.launched
                .lock()
                .unwrap()
                .push((c.as_str().into(), e.as_str().into(), s.clone()));
            let p = FakeProc::new(5151);
            self.procs.lock().unwrap().push(Arc::clone(&p));
            Ok(p)
        }
    }

    fn svc_exec(version: TaskApiVersion) -> (TaskService, Arc<Fake>, Arc<FakeLauncher>) {
        let (s, f) = svc(version, Fake::default());
        let l = Arc::new(FakeLauncher::default());
        (s.with_exec_launcher(l.clone()), f, l)
    }

    const SPEC: &str = r#"{"cwd":"/","args":["/bin/sh","-c","id"],"env":["A=b"],"user":{"uid":1000,"gid":1001,"additionalGids":[2000,3000]}}"#;

    fn exec_req(id: &str, eid: &str, json: &str) -> Vec<u8> {
        ExecProcessRequest {
            id: id.into(),
            exec_id: eid.into(),
            spec: Some(Any {
                type_url: PROCESS_TYPE_URL.into(),
                value: json.as_bytes().to_vec(),
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn start_exec_req(id: &str, eid: &str) -> Vec<u8> {
        StartRequest {
            id: id.into(),
            exec_id: eid.into(),
        }
        .encode_to_vec()
    }

    fn running_container(s: &TaskService, id: &str) {
        s.handle("Create", &create_req(id, &abs("/b"))).unwrap();
        s.handle("Start", &start_req(id)).unwrap();
    }

    /// CRI-5: V2 / V3 の両方で Create → Start → Exec → Start(exec_id) が通り、起動役へ具体値が渡る。
    #[test]
    fn cri5_exec_then_start_launches_process() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, _, l) = svc_exec(v);
            running_container(&s, "c1");
            let out = s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
            assert!(out.is_empty());
            assert!(l.launched.lock().unwrap().is_empty());
            let out = s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
            assert_eq!(StartResponse::decode(&out[..]).unwrap().pid, 5151);
            let launched = l.launched.lock().unwrap();
            assert_eq!(launched.len(), 1);
            let (c, e, spec) = &launched[0];
            assert_eq!((c.as_str(), e.as_str()), ("c1", "e1"));
            assert_eq!(spec.args(), ["/bin/sh", "-c", "id"]);
            assert_eq!(spec.env(), ["A=b"]);
            assert_eq!(spec.cwd(), "/");
            let u = spec.user().unwrap();
            assert_eq!((u.uid, u.gid), (1000, 1001));
            assert_eq!(u.additional_gids, vec![2000, 3000]);
        }
    }

    /// CRI-5: 起動役が無ければ Exec も Start(exec_id) も UNIMPLEMENTED。
    #[test]
    fn cri5_exec_without_launcher_unimplemented() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        running_container(&s, "c1");
        let (code, msg) = err_code(s.handle("Exec", &exec_req("c1", "e1", SPEC)));
        assert_eq!((code, msg.as_str()), (UNIMPL, "exec is not supported"));
        let (code, msg) = err_code(s.handle("Start", &start_exec_req("c1", "e1")));
        assert_eq!((code, msg.as_str()), (UNIMPL, "exec_id is not supported"));
    }

    /// CRI-5: 不正な入力は INVALID_ARGUMENT で、起動役は呼ばれず登録もされない。
    #[test]
    fn cri5_exec_invalid_inputs() {
        let (s, f, l) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c1");
        let before = f.calls.lock().unwrap().len();
        let long = "a".repeat(256);
        for (id, eid) in [
            ("", "e"),
            ("..", "e"),
            ("bad id!", "e"),
            ("c1", ""),
            ("c1", ".."),
            ("c1", "bad id!"),
            ("c1", long.as_str()),
        ] {
            assert_eq!(
                err_code(s.handle("Exec", &exec_req(id, eid, SPEC))).0,
                INVALID,
                "{id:?} {eid:?}"
            );
        }
        for j in [
            "",
            "not json",
            r#"{"cwd":"/"}"#,
            r#"{"cwd":"/","args":[""]}"#,
            r#"{"cwd":"rel","args":["a"]}"#,
            r#"{"cwd":"/","args":["a"],"env":["NOEQ"]}"#,
            r#"{"cwd":"/","args":["a"],"bogus":1}"#,
        ] {
            assert_eq!(
                err_code(s.handle("Exec", &exec_req("c1", "e1", j))).0,
                INVALID,
                "{j}"
            );
        }
        let no_spec = ExecProcessRequest {
            id: "c1".into(),
            exec_id: "e1".into(),
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(err_code(s.handle("Exec", &no_spec)).0, INVALID);
        let bad_url = ExecProcessRequest {
            id: "c1".into(),
            exec_id: "e1".into(),
            spec: Some(Any {
                type_url: "x".into(),
                value: SPEC.as_bytes().to_vec(),
            }),
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(err_code(s.handle("Exec", &bad_url)).0, INVALID);
        assert_eq!(err_code(s.handle("Exec", &[0x0a, 5, 1])).0, INVALID);
        assert_eq!(f.calls.lock().unwrap().len(), before);
        assert!(l.launched.lock().unwrap().is_empty());
        assert_eq!(
            err_code(s.handle("Start", &start_exec_req("c1", "e1"))).0,
            NOT_FOUND
        );
    }

    /// CRI-5・SEC-1: 未対応の欄は UNIMPLEMENTED で、ランタイムは呼ばれない。
    #[test]
    fn cri5_exec_unsupported_fields() {
        let (s, f, _) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c1");
        let before = f.calls.lock().unwrap().len();
        let base = || ExecProcessRequest {
            id: "c1".into(),
            exec_id: "e1".into(),
            spec: Some(Any {
                type_url: PROCESS_TYPE_URL.into(),
                value: SPEC.as_bytes().to_vec(),
            }),
            ..Default::default()
        };
        let mut r = base();
        r.terminal = true;
        let (code, msg) = err_code(s.handle("Exec", &r.encode_to_vec()));
        assert_eq!((code, msg.as_str()), (UNIMPL, "terminal is not supported"));
        for which in 0..3 {
            let mut r = base();
            match which {
                0 => r.stdin = "/f".into(),
                1 => r.stdout = "/f".into(),
                _ => r.stderr = "/f".into(),
            }
            let (code, msg) = err_code(s.handle("Exec", &r.encode_to_vec()));
            assert_eq!((code, msg.as_str()), (UNIMPL, "stdio is not supported"));
        }
        let caps = r#"{"cwd":"/","args":["a"],"capabilities":{"bounding":["CAP_SYS_ADMIN"]}}"#;
        let (code, msg) = err_code(s.handle("Exec", &exec_req("c1", "e1", caps)));
        assert_eq!(
            (code, msg.as_str()),
            (UNIMPL, "capabilities is not supported")
        );
        assert_eq!(f.calls.lock().unwrap().len(), before);
    }

    /// ERR-3・CRI-5: 状態に関する失敗と再試行。
    #[test]
    fn cri5_exec_lifecycle_errors() {
        let (s, _, l) = svc_exec(TaskApiVersion::V2);
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("nope", "e1", SPEC))).0,
            NOT_FOUND
        );
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("c1", "e1", SPEC))).0,
            PRECOND
        );
        s.handle("Start", &start_req("c1")).unwrap();
        s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("c1", "e1", SPEC))).0,
            EXISTS
        );
        // launch の失敗は ERR-3 のコードで返り、再試行できる。
        *l.fail.lock().unwrap() = true;
        assert_eq!(
            err_code(s.handle("Start", &start_exec_req("c1", "e1"))).0,
            UNAVAILABLE
        );
        *l.fail.lock().unwrap() = false;
        s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
        assert_eq!(
            err_code(s.handle("Start", &start_exec_req("c1", "e1"))).0,
            PRECOND
        );
        assert_eq!(
            err_code(s.handle("Start", &start_exec_req("c1", "zz"))).0,
            NOT_FOUND
        );
        assert_eq!(l.launched.lock().unwrap().len(), 1);
    }

    /// CRI-5: 1 コンテナあたりの登録上限は RESOURCE_EXHAUSTED。
    #[test]
    fn cri5_exec_registry_limit() {
        let (s, _, _) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c1");
        for i in 0..super::super::exec::MAX_EXECS_PER_CONTAINER {
            s.handle("Exec", &exec_req("c1", &format!("e{i}"), SPEC))
                .unwrap();
        }
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("c1", "over", SPEC))).0,
            RESOURCE_EXHAUSTED
        );
    }

    /// CRI-5: Delete 成功で exec 登録が消え、同じ ID の再作成で同じ exec_id を再登録でき、
    /// 旧登録での Start は NOT_FOUND、登録数（上限）も回復する。
    #[test]
    fn cri5_delete_purges_exec_registrations() {
        let (s, f, l) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c1");
        for i in 0..super::super::exec::MAX_EXECS_PER_CONTAINER {
            s.handle("Exec", &exec_req("c1", &format!("e{i}"), SPEC))
                .unwrap();
        }
        stopped(&f, "c1", Some(0));
        s.handle("Delete", &delete_req("c1", "")).unwrap();
        f.preset.lock().unwrap().remove("c1");
        running_container(&s, "c1");
        // 旧登録では起動できない。
        assert_eq!(
            err_code(s.handle("Start", &start_exec_req("c1", "e0"))).0,
            NOT_FOUND
        );
        assert!(l.launched.lock().unwrap().is_empty());
        // 同じ exec_id を再登録でき、上限も回復している。
        for i in 0..super::super::exec::MAX_EXECS_PER_CONTAINER {
            s.handle("Exec", &exec_req("c1", &format!("e{i}"), SPEC))
                .unwrap();
        }
        s.handle("Start", &start_exec_req("c1", "e0")).unwrap();
        assert_eq!(l.launched.lock().unwrap().len(), 1);
    }

    /// CRI-5: Start(exec_id) の起動中は Delete が待たされ、起動の完了後にだけ進む
    /// （起動中の Delete と同じ ID の再作成で旧 spec が新コンテナへ起動されない）。
    #[test]
    fn cri5_delete_waits_for_exec_launch() {
        struct SlowLauncher {
            fake: Arc<Fake>,
            events: Arc<Mutex<Vec<&'static str>>>,
            entered: Mutex<std::sync::mpsc::Sender<()>>,
        }
        impl TaskExecLauncher for SlowLauncher {
            fn launch(
                &self,
                _c: &ContainerId,
                _e: &ExecId,
                _s: &ExecProcessSpec,
            ) -> Result<Arc<dyn TaskExecProcess>, CriError> {
                // 起動中に init が停止した場面を作ってから Delete を走らせる。
                stopped(&self.fake, "c1", Some(0));
                self.entered.lock().unwrap().send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(300));
                self.events.lock().unwrap().push("launch-end");
                Ok(FakeProc::new(5151))
            }
        }
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        let events = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let s = s.with_exec_launcher(Arc::new(SlowLauncher {
            fake: f.clone(),
            events: events.clone(),
            entered: Mutex::new(tx),
        }));
        running_container(&s, "c1");
        s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
        std::thread::scope(|sc| {
            let start = sc.spawn(|| s.handle("Start", &start_exec_req("c1", "e1")));
            rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            let del = sc.spawn(|| {
                let r = s.handle("Delete", &delete_req("c1", ""));
                events.lock().unwrap().push("delete-done");
                r
            });
            assert!(start.join().unwrap().is_ok());
            assert!(del.join().unwrap().is_ok());
        });
        assert_eq!(*events.lock().unwrap(), vec!["launch-end", "delete-done"]);
    }

    fn svc(version: TaskApiVersion, fake: Fake) -> (TaskService, Arc<Fake>) {
        let f = Arc::new(fake);
        let s = TaskService::new(version, RuntimeAdapter::from_runtime(Shared(f.clone())));
        (s, f)
    }

    fn create_req(id: &str, bundle: &str) -> Vec<u8> {
        CreateTaskRequest {
            id: id.into(),
            bundle: bundle.into(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn start_req(id: &str) -> Vec<u8> {
        StartRequest {
            id: id.into(),
            exec_id: String::new(),
        }
        .encode_to_vec()
    }

    fn delete_req(id: &str, exec_id: &str) -> Vec<u8> {
        DeleteRequest {
            id: id.into(),
            exec_id: exec_id.into(),
        }
        .encode_to_vec()
    }

    fn stopped(f: &Fake, id: &str, code: Option<i32>) {
        f.preset.lock().unwrap().insert(
            id.into(),
            ContainerStatus::stopped(RtId::new(id).unwrap(), code),
        );
        f.states
            .lock()
            .unwrap()
            .insert(id.into(), ContainerState::Stopped);
    }

    fn err_code(r: Result<Vec<u8>, RpcStatus>) -> (i32, String) {
        let s = r.unwrap_err();
        (s.code, s.message)
    }

    /// 試験用の絶対パス。`Path::is_absolute` は Windows では `/b` を偽とするため、
    /// Windows では `C:` を前置して区切りを `\` にし、3 OS で絶対パスにする（CRI-5）。
    fn abs(unix_style: &str) -> String {
        if cfg!(windows) {
            format!("C:{}", unix_style.replace('/', "\\"))
        } else {
            unix_style.to_string()
        }
    }

    const INVALID: i32 = 3;
    const NOT_FOUND: i32 = 5;
    const EXISTS: i32 = 6;
    const UNIMPL: i32 = 12;
    const PRECOND: i32 = 9;
    const INTERNAL: i32 = 13;
    const RESOURCE_EXHAUSTED: i32 = 8;
    const UNAVAILABLE: i32 = 14;

    fn state_of(s: &TaskService, id: &str) -> StateResponse {
        let req = WireState {
            id: id.into(),
            exec_id: String::new(),
        };
        let out = s.handle("State", &req.encode_to_vec()).unwrap();
        StateResponse::decode(&out[..]).unwrap()
    }

    fn kill_req(id: &str, signal: u32, all: bool, eid: &str) -> Vec<u8> {
        WireKill {
            id: id.into(),
            exec_id: eid.into(),
            signal,
            all,
        }
        .encode_to_vec()
    }

    /// CRI-5・TASK-62.7.2: State が Created / Running / Stopped を具体値で返す。
    #[test]
    fn cri5_873_state_reports_each_lifecycle() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, f) = svc(v, Fake::default());
            s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
            let r = state_of(&s, "c1");
            assert_eq!(
                (r.id.as_str(), r.pid, r.status, r.exit_status),
                ("c1", 0, TaskStatus::Created as i32, 0)
            );
            assert!(r.bundle.is_empty() && r.exited_at.is_none() && !r.terminal);
            s.handle("Start", &start_req("c1")).unwrap();
            let r = state_of(&s, "c1");
            assert_eq!(
                (r.pid, r.status, r.exit_status),
                (4242, TaskStatus::Running as i32, 0)
            );
            let id = RtId::new("c1").unwrap();
            f.preset
                .lock()
                .unwrap()
                .insert("c1".into(), ContainerStatus::stopped(id.clone(), Some(3)));
            let r = state_of(&s, "c1");
            assert_eq!((r.status, r.exit_status), (TaskStatus::Stopped as i32, 3));
            f.preset
                .lock()
                .unwrap()
                .insert("c1".into(), ContainerStatus::stopped(id, None));
            assert_eq!(state_of(&s, "c1").exit_status, 255);
        }
    }

    /// CRI-5・#4104: 起動途中（Running だが pid 未判明）の State は RUNNING・pid 0 ではなく CREATED を返す。
    #[test]
    fn cri5_4104_state_running_without_pid_is_created() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        f.preset.lock().unwrap().insert(
            "c1".into(),
            ContainerStatus::running(RtId::new("c1").unwrap(), None),
        );
        let r = state_of(&s, "c1");
        assert_eq!((r.pid, r.status), (0, TaskStatus::Created as i32));
    }

    /// CRI-5・TASK-62.6: Connect は Created で task_pid 0・Running で pid・shim_pid は自 pid を返す。
    #[test]
    fn cri5_676_connect_reports_pids() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, _) = svc(v, Fake::default());
            let conn = |id: &str| {
                s.handle("Connect", &ConnectRequest { id: id.into() }.encode_to_vec())
                    .map(|o| ConnectResponse::decode(&o[..]).unwrap())
            };
            s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
            let r = conn("c1").unwrap();
            assert_eq!(
                (r.shim_pid, r.task_pid, r.version.as_str()),
                (std::process::id(), 0, "")
            );
            s.handle("Start", &start_req("c1")).unwrap();
            assert_eq!(conn("c1").unwrap().task_pid, 4242);
            assert_eq!(conn("nope").unwrap_err().code, NOT_FOUND);
            assert_eq!(err_code(s.handle("Connect", &[0xff, 0xff])).0, INVALID);
        }
    }

    /// CRI-5・TASK-62.7.2: State の NOT_FOUND・exec_id 拒否・不正 payload。
    #[test]
    fn cri5_873_state_errors() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        let req = WireState {
            id: "nope".into(),
            exec_id: String::new(),
        };
        assert_eq!(
            err_code(s.handle("State", &req.encode_to_vec())).0,
            NOT_FOUND
        );
        let req = WireState {
            id: "c1".into(),
            exec_id: "e".into(),
        };
        let (code, msg) = err_code(s.handle("State", &req.encode_to_vec()));
        assert_eq!((code, msg.as_str()), (UNIMPL, "exec_id is not supported"));
        assert_eq!(err_code(s.handle("State", &[0xff, 0xff])).0, INVALID);
    }

    /// CRI-5・TASK-62.7.2: Kill は 1 と 64 を adapter へ渡し、範囲外・all・exec_id を拒否する。
    #[test]
    fn cri5_873_kill_boundaries() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        running_container(&s, "c1");
        for sig in [1u32, 15, 64] {
            let out = s.handle("Kill", &kill_req("c1", sig, false, "")).unwrap();
            assert!(out.is_empty());
        }
        let calls = f.calls.lock().unwrap().clone();
        let kills: Vec<&str> = calls
            .iter()
            .filter(|c| c.starts_with("kill"))
            .map(String::as_str)
            .collect();
        assert_eq!(kills, ["kill c1 1", "kill c1 15", "kill c1 64"]);
        for sig in [0u32, 65, 256, u32::MAX] {
            assert_eq!(
                err_code(s.handle("Kill", &kill_req("c1", sig, false, ""))).0,
                INVALID,
                "{sig}"
            );
        }
        // all=true は SIGKILL だけを cgroup 全体へ送る。SIGKILL 以外は状態照会より前に拒否。
        s.handle("Kill", &kill_req("c1", 9, true, "")).unwrap();
        assert_eq!(f.calls.lock().unwrap().last().unwrap(), "kill-all c1 9");
        for sig in [1u32, 15, 64] {
            let (code, msg) = err_code(s.handle("Kill", &kill_req("c1", sig, true, "")));
            assert_eq!(
                (code, msg.as_str()),
                (INVALID, "kill all supports only SIGKILL")
            );
        }
        assert_eq!(
            err_code(s.handle("Kill", &kill_req("zz", 15, true, ""))).0,
            INVALID
        );
        assert_eq!(
            err_code(s.handle("Kill", &kill_req("zz", 9, true, ""))).0,
            NOT_FOUND
        );
        let (code, msg) = err_code(s.handle("Kill", &kill_req("c1", 9, false, "e")));
        assert_eq!((code, msg.as_str()), (UNIMPL, "exec_id is not supported"));
        assert_eq!(
            f.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.starts_with("kill "))
                .count(),
            3
        );
        assert_eq!(
            err_code(s.handle("Kill", &kill_req("zz", 9, false, ""))).0,
            NOT_FOUND
        );
    }

    /// CRI-5・CORE-4・#4055: 配置の記録が無いコンテナへの `Kill(all=true)` は core の `FailedPrecondition` が
    /// shim の層で code 9 に写る（init だけを殺す縮退をしない）。`all=false` は影響を受けない。
    /// core 側は `cri5_kill_all_without_placement_is_failed_precondition`、実 cgroup の照合は `shim_v2_kill_all_real`。
    #[test]
    fn cri5_4055_kill_all_failed_precondition_maps_to_code_9() {
        let (s, f) = svc(
            TaskApiVersion::V2,
            Fake {
                kill_all_err: true,
                ..Fake::default()
            },
        );
        running_container(&s, "c1");
        let (code, _) = err_code(s.handle("Kill", &kill_req("c1", 9, true, "")));
        assert_eq!(code, PRECOND);
        assert_eq!(f.calls.lock().unwrap().last().unwrap(), "kill-all c1 9");
        s.handle("Kill", &kill_req("c1", 9, false, "")).unwrap();
    }

    /// CRI-5・TASK-62.7.2: 停止済みへの Kill は NOT_FOUND で、シグナルを送らない。
    #[test]
    fn cri5_873_kill_stopped_is_not_found() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        running_container(&s, "c1");
        f.preset.lock().unwrap().insert(
            "c1".into(),
            ContainerStatus::stopped(RtId::new("c1").unwrap(), Some(0)),
        );
        let (code, msg) = err_code(s.handle("Kill", &kill_req("c1", 9, false, "")));
        assert_eq!(
            (code, msg.as_str()),
            (NOT_FOUND, "process already finished")
        );
        assert!(
            !f.calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.starts_with("kill"))
        );
    }

    /// CRI-5・TASK-62.7.2: Shutdown はコンテナが残っていれば要求せず、無い・now なら要求する。
    #[test]
    fn cri5_873_shutdown_semantics() {
        let sig = ShutdownSignal::new();
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        let s = s.with_shutdown(sig.clone());
        let req = |id: &str, now: bool| ShutdownRequest { id: id.into(), now }.encode_to_vec();
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        assert!(s.handle("Shutdown", &req("c1", false)).unwrap().is_empty());
        assert!(!sig.is_requested());
        assert_eq!(err_code(s.handle("Shutdown", &[0xff, 0xff])).0, INVALID);
        assert!(!sig.is_requested());
        s.handle(
            "Delete",
            &DeleteRequest {
                id: "c1".into(),
                exec_id: String::new(),
            }
            .encode_to_vec(),
        )
        .unwrap();
        assert!(s.handle("Shutdown", &req("c1", false)).unwrap().is_empty());
        assert!(sig.is_requested());
        // 2 回目も成功する（冪等）。
        assert!(s.handle("Shutdown", &req("c1", false)).unwrap().is_empty());

        // 別 ID（存在しない c9）の Shutdown は、実行中の c1 が残っていれば要求しない。
        let sig3 = ShutdownSignal::new();
        let (s3, _) = svc(TaskApiVersion::V2, Fake::default());
        let s3 = s3.with_shutdown(sig3.clone());
        s3.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        assert!(s3.handle("Shutdown", &req("c9", false)).unwrap().is_empty());
        assert!(!sig3.is_requested());

        let sig2 = ShutdownSignal::new();
        let (s2, _) = svc(TaskApiVersion::V2, Fake::default());
        let s2 = s2.with_shutdown(sig2.clone());
        s2.handle("Create", &create_req("c2", &abs("/b"))).unwrap();
        s2.handle("Shutdown", &req("c2", true)).unwrap();
        assert!(sig2.is_requested());
        // 終了要求後の Create は受けない。
        assert_eq!(
            err_code(s2.handle("Create", &create_req("c3", &abs("/b")))).0,
            UNAVAILABLE
        );
    }

    /// CRI-5・TASK-62.7.2・REPAIR-5: 作成済み ID は Delete で除去され、上限を超える Create は拒否する。
    #[test]
    fn cri5_873_created_ids_bounded_and_purged() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        for i in 0..CREATED_MAX {
            s.handle("Create", &create_req(&format!("c{i}"), &abs("/b")))
                .unwrap();
        }
        assert_eq!(
            err_code(s.handle("Create", &create_req("over", &abs("/b")))).0,
            RESOURCE_EXHAUSTED
        );
        s.handle("Delete", &delete_req("c0", "")).unwrap();
        assert_eq!(s.created.lock().unwrap().len(), CREATED_MAX - 1);
        s.handle("Create", &create_req("over", &abs("/b"))).unwrap();
    }

    /// CRI-5・TASK-62.7.2: Delete は実行層の削除から登録除去まで `created` を持ち、並行する Create・Shutdown と排他する。
    /// 他者が `created` を持つ間は実行層を呼ばず、放した後に完了して登録を除去する。
    #[test]
    fn cri5_873_delete_excludes_create_via_created_lock() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        let calls_before = f.calls.lock().unwrap().len();
        let guard = s.created.lock().unwrap();
        std::thread::scope(|sc| {
            let del = sc.spawn(|| s.handle("Delete", &delete_req("c1", "")));
            std::thread::sleep(std::time::Duration::from_millis(200));
            // ロックを持つ間は state・delete のどちらも実行層へ届かない。
            assert_eq!(f.calls.lock().unwrap().len(), calls_before);
            drop(guard);
            assert!(del.join().unwrap().is_ok());
        });
        assert!(!s.created.lock().unwrap().contains("c1"));
        assert!(
            f.calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c == "delete c1 force=false")
        );
    }

    /// CRI-5・TASK-62.7.2: v2 と v3 で作成済み ID を共有すると、別サービスの Create も Shutdown の判定に効く。
    #[test]
    fn cri5_873_shutdown_sees_other_version_creates() {
        let sig = ShutdownSignal::new();
        let (v2, f) = svc(TaskApiVersion::V2, Fake::default());
        let v3 = TaskService::new(
            TaskApiVersion::V3,
            RuntimeAdapter::from_runtime(Shared(f.clone())),
        )
        .with_shared_created(&v2)
        .with_shutdown(sig.clone());
        v2.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        let req = ShutdownRequest {
            id: "c9".into(),
            now: false,
        }
        .encode_to_vec();
        assert!(v3.handle("Shutdown", &req).unwrap().is_empty());
        assert!(!sig.is_requested());
    }

    /// CRI-5・TASK-62.7.2: 範囲外シグナルは状態の照会より前に INVALID_ARGUMENT になる。
    #[test]
    fn cri5_873_kill_signal_checked_before_state() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        for sig in [0u32, 65] {
            assert_eq!(
                err_code(s.handle("Kill", &kill_req("nope", sig, false, ""))).0,
                INVALID
            );
        }
    }

    /// CRI-5・TASK-62.7.2: シグナル未注入の Shutdown は UNIMPLEMENTED。
    #[test]
    fn cri5_873_shutdown_without_signal_unimplemented() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        let req = ShutdownRequest {
            id: "c1".into(),
            now: true,
        }
        .encode_to_vec();
        assert_eq!(err_code(s.handle("Shutdown", &req)).0, UNIMPL);
    }

    /// CRI-5・CRI-7: V2 / V3 の両方で Create → Start が通り、pid と ID・bundle が具体値で一致する。
    #[test]
    fn cri5_create_start_both_versions() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, f) = svc(
                v,
                Fake {
                    create_pid: Some(100),
                    ..Default::default()
                },
            );
            let out = s
                .handle("Create", &create_req("c1", &abs("/run/b1")))
                .unwrap();
            assert_eq!(CreateTaskResponse::decode(&out[..]).unwrap().pid, 100);
            let out = s.handle("Start", &start_req("c1")).unwrap();
            assert_eq!(StartResponse::decode(&out[..]).unwrap().pid, 4242);
            assert_eq!(
                *f.calls.lock().unwrap(),
                vec![
                    format!("create c1 {}", abs("/run/b1")),
                    "start c1".to_string()
                ]
            );
        }
    }

    /// CRI-5: create 直後に PID が不明なら 0。
    #[test]
    fn cri5_create_pid_none_is_zero() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        let out = s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        assert_eq!(CreateTaskResponse::decode(&out[..]).unwrap().pid, 0);
    }

    /// ERR-3: ランタイムの失敗は表のコードで返る。
    #[test]
    fn cri5_runtime_errors_map_to_err3() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        assert_eq!(
            err_code(s.handle("Create", &create_req("c1", &abs("/b")))).0,
            EXISTS
        );
        assert_eq!(err_code(s.handle("Start", &start_req("nope"))).0, NOT_FOUND);
        s.handle("Start", &start_req("c1")).unwrap();
        assert_eq!(err_code(s.handle("Start", &start_req("c1"))).0, PRECOND);
    }

    /// 入力の検査: 不正 ID・bundle・壊れた payload は INVALID_ARGUMENT で、ランタイムは呼ばれない。
    #[test]
    fn cri5_invalid_inputs() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        let (b, dotdot, nul) = (abs("/b"), abs("/a/../b"), abs("/a\0b"));
        for (id, b) in [
            ("", b.as_str()),
            ("bad id!", b.as_str()),
            ("c1", ""),
            ("c1", "relative/path"),
            ("c1", dotdot.as_str()),
            ("c1", nul.as_str()),
        ] {
            assert_eq!(
                err_code(s.handle("Create", &create_req(id, b))).0,
                INVALID,
                "{id:?} {b:?}"
            );
        }
        let long = abs(&format!("/{}", "a".repeat(BUNDLE_MAX_LEN)));
        assert_eq!(
            err_code(s.handle("Create", &create_req("c1", &long))).0,
            INVALID
        );
        let (code, msg) = err_code(s.handle("Create", &[0x0a, 5, 1]));
        assert_eq!((code, msg.as_str()), (INVALID, "malformed request payload"));
        assert_eq!(err_code(s.handle("Start", &[0x0a, 5, 1])).0, INVALID);
        assert!(f.calls.lock().unwrap().is_empty());
    }

    /// 未対応の欄は UNIMPLEMENTED で、ランタイムは呼ばれない。
    #[test]
    fn cri5_unsupported_fields_rejected() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        let base = || CreateTaskRequest {
            id: "c1".into(),
            bundle: abs("/b"),
            ..Default::default()
        };
        let mut cases: Vec<(CreateTaskRequest, &str)> = Vec::new();
        let mut r = base();
        r.rootfs = vec![Mount::default()];
        cases.push((r, "rootfs mounts are not supported"));
        let mut r = base();
        r.terminal = true;
        cases.push((r, "terminal is not supported"));
        for which in 0..3 {
            let mut r = base();
            match which {
                0 => r.stdin = "/f".into(),
                1 => r.stdout = "/f".into(),
                _ => r.stderr = "/f".into(),
            }
            cases.push((r, "stdio is not supported"));
        }
        let mut r = base();
        r.checkpoint = "c".into();
        cases.push((r, "checkpoint is not supported"));
        let mut r = base();
        r.parent_checkpoint = "c".into();
        cases.push((r, "checkpoint is not supported"));
        for (r, m) in cases {
            let (code, msg) = err_code(s.handle("Create", &r.encode_to_vec()));
            assert_eq!((code, msg.as_str()), (UNIMPL, m));
        }
        // options（番号 10）は型に持たないので手で組む。
        let mut raw = create_req("c1", &abs("/b"));
        raw.extend_from_slice(&[0x52, 0x00]);
        let (code, msg) = err_code(s.handle("Create", &raw));
        assert_eq!((code, msg.as_str()), (UNIMPL, "options are not supported"));
        let exec = StartRequest {
            id: "c1".into(),
            exec_id: "e".into(),
        }
        .encode_to_vec();
        assert_eq!(err_code(s.handle("Start", &exec)).0, UNIMPL);
        assert!(f.calls.lock().unwrap().is_empty());
    }

    /// 復号前の走査: 10 万件の空 rootfs でも確保せず UNIMPLEMENTED。切れた入力は INVALID_ARGUMENT。
    #[test]
    fn cri5_rootfs_flood_rejected_before_decode() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        let flood = [0x1a, 0x00].repeat(100_000);
        assert_eq!(err_code(s.handle("Create", &flood)).0, UNIMPL);
        assert_eq!(err_code(s.handle("Create", &[0x1a])).0, INVALID);
    }

    /// 応答の ID が要求と違えば INTERNAL。
    #[test]
    fn cri5_mismatched_response_id_is_internal() {
        let (s, _) = svc(
            TaskApiVersion::V2,
            Fake {
                wrong_id: true,
                ..Default::default()
            },
        );
        assert_eq!(
            err_code(s.handle("Create", &create_req("c1", &abs("/b")))).0,
            INTERNAL
        );
    }

    /// 他のメソッドは Unimplemented。サービス名は版に従う。
    #[test]
    fn cri5_other_methods_unimplemented() {
        let (s, _) = svc(TaskApiVersion::V3, Fake::default());
        assert_eq!(s.name(), "containerd.task.v3.Task");
        let (code, msg) = err_code(s.handle("Pause", &[]));
        assert_eq!((code, msg.as_str()), (UNIMPL, "method Pause"));
    }

    /// CRI-5: V2 / V3 で Delete が通り、pid・exit_status が具体値で返る。再度の Delete は NOT_FOUND。
    #[test]
    fn cri5_delete_both_versions() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, f) = svc(v, Fake::default());
            s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
            stopped(&f, "c1", Some(137));
            let out = s.handle("Delete", &delete_req("c1", "")).unwrap();
            let r = DeleteResponse::decode(&out[..]).unwrap();
            assert_eq!((r.pid, r.exit_status, r.exited_at), (0, 137, None));
            let calls = f.calls.lock().unwrap().clone();
            assert_eq!(
                calls[calls.len() - 2..],
                ["state c1".to_string(), "delete c1 force=false".to_string()]
            );
            assert_eq!(
                err_code(s.handle("Delete", &delete_req("c1", ""))).0,
                NOT_FOUND
            );
        }
    }

    /// CRI-5: 一度も起動していない Created の Delete は exit_status 0。
    #[test]
    fn cri5_delete_created_never_started() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        let out = s.handle("Delete", &delete_req("c1", "")).unwrap();
        let r = DeleteResponse::decode(&out[..]).unwrap();
        assert_eq!((r.pid, r.exit_status), (0, 0));
    }

    /// ERR-3: 存在しない ID は NOT_FOUND で、delete は呼ばれない。
    #[test]
    fn cri5_delete_not_found_err3() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        assert_eq!(
            err_code(s.handle("Delete", &delete_req("nope", ""))).0,
            NOT_FOUND
        );
        assert_eq!(*f.calls.lock().unwrap(), vec!["state nope".to_string()]);
    }

    /// 実行中は FAILED_PRECONDITION で、コンテナは残る。
    #[test]
    fn cri5_delete_running_is_failed_precondition() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        assert_eq!(
            err_code(s.handle("Delete", &delete_req("c1", ""))).0,
            PRECOND
        );
        assert!(s.adapter.state("c1").is_ok());
    }

    /// 不正な入力はランタイムを呼ばずに拒否する。
    #[test]
    fn cri5_delete_invalid_inputs() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        assert_eq!(err_code(s.handle("Delete", &delete_req("", ""))).0, INVALID);
        assert_eq!(
            err_code(s.handle("Delete", &delete_req("bad id!", ""))).0,
            INVALID
        );
        let (code, msg) = err_code(s.handle("Delete", &[0x0a, 5, 1]));
        assert_eq!((code, msg.as_str()), (INVALID, "malformed request payload"));
        let (code, msg) = err_code(s.handle("Delete", &delete_req("c1", "e")));
        assert_eq!((code, msg.as_str()), (UNIMPL, "exec_id is not supported"));
        assert!(f.calls.lock().unwrap().is_empty());
    }

    const DEADLINE: i32 = 4;

    fn wait_req(id: &str, exec_id: &str) -> Vec<u8> {
        WaitRequest {
            id: id.into(),
            exec_id: exec_id.into(),
        }
        .encode_to_vec()
    }

    fn fast_wait(s: TaskService, timeout_ms: u64) -> TaskService {
        s.with_wait_config(
            WaitConfig::new(
                std::time::Duration::from_millis(timeout_ms),
                std::time::Duration::from_millis(10),
            )
            .unwrap(),
        )
    }

    /// CRI-5: 停止済みなら V2 / V3 とも即座に exit_status が返り、exited_at は未設定。
    #[test]
    fn cri5_wait_returns_exit_status_when_stopped() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, f) = svc(v, Fake::default());
            s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
            stopped(&f, "c1", Some(137));
            let out = s.handle("Wait", &wait_req("c1", "")).unwrap();
            let r = WaitResponse::decode(&out[..]).unwrap();
            assert_eq!((r.exit_status, r.exited_at), (137, None));
        }
    }

    /// 停止済みで core が終了検知時刻を記録していた状態を差し込む（#3682）。
    fn stopped_with_time(f: &Fake, id: &str, code: Option<i32>, nanos: i64) {
        stopped(f, id, code);
        f.preset.lock().unwrap().insert(
            id.into(),
            ContainerStatus::stopped_at(
                RtId::new(id).unwrap(),
                code,
                fandhe_container_core::traits::ExitTime::from_unix_nanos(nanos),
            ),
        );
    }

    /// CRI-5・OCI-5（#3682）: State・Wait・Delete は停止済みで core の終了検知時刻を具体値で返し、
    /// 実行中・未起動・時刻なしの停止では未設定のまま返す。
    #[test]
    fn cri5_3682_exited_at_is_returned_only_for_stopped_with_time() {
        let want = Some(Timestamp {
            seconds: 1_700_000_000,
            nanos: 5,
        });
        let at = 1_700_000_000_000_000_005_i64;
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, f) = svc(v, Fake::default());
            s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
            assert_eq!(state_of(&s, "c1").exited_at, None);
            s.handle("Start", &start_req("c1")).unwrap();
            assert_eq!(state_of(&s, "c1").exited_at, None);
            // 時刻なしの停止（導入前の記録・時計の異常）は未設定のまま。
            stopped(&f, "c1", Some(3));
            assert_eq!(state_of(&s, "c1").exited_at, None);
            stopped_with_time(&f, "c1", Some(3), at);
            assert_eq!(state_of(&s, "c1").exited_at, want.clone());
            let out = s.handle("Wait", &wait_req("c1", "")).unwrap();
            assert_eq!(
                WaitResponse::decode(&out[..]).unwrap().exited_at,
                want.clone()
            );
            let out = s.handle("Delete", &delete_req("c1", "")).unwrap();
            let r = DeleteResponse::decode(&out[..]).unwrap();
            assert_eq!((r.exit_status, r.exited_at), (3, want.clone()));
            // pid なしの Created の Delete は未設定。
            s.handle("Create", &create_req("c2", &abs("/b"))).unwrap();
            let out = s.handle("Delete", &delete_req("c2", "")).unwrap();
            assert_eq!(DeleteResponse::decode(&out[..]).unwrap().exited_at, None);
        }
    }

    /// `exited_at_of` は Stopped 以外と未記録を `None` にする（lifecycle で絞る）。
    #[test]
    fn cri5_3682_exited_at_of_requires_stopped_lifecycle() {
        let id = || RtId::new("c1").unwrap();
        let t = fandhe_container_core::traits::ExitTime::from_unix_nanos(1_999_999_999);
        let m = |s: ContainerStatus| exited_at_of(&RuntimeContainerStatus::from(&s));
        assert_eq!(
            m(ContainerStatus::stopped_at(id(), None, t)),
            Some(Timestamp {
                seconds: 1,
                nanos: 999_999_999
            })
        );
        assert_eq!(m(ContainerStatus::stopped(id(), Some(0))), None);
        assert_eq!(m(ContainerStatus::running(id(), None)), None);
        assert_eq!(m(ContainerStatus::created(id(), None)), None);
    }

    /// 終了コードが不明・負値なら 255。
    #[test]
    fn cri5_wait_unknown_exit_code_is_255() {
        for code in [None, Some(-1)] {
            let (s, f) = svc(TaskApiVersion::V2, Fake::default());
            s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
            stopped(&f, "c1", code);
            let out = s.handle("Wait", &wait_req("c1", "")).unwrap();
            assert_eq!(WaitResponse::decode(&out[..]).unwrap().exit_status, 255);
        }
    }

    /// REPAIR-5・CRI-5: 実行中は終了まで返らず、停止後に終了コードが返る。
    #[test]
    fn cri5_wait_blocks_until_exit() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        let s = fast_wait(s, 5000);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        let t0 = std::time::Instant::now();
        let out = std::thread::scope(|sc| {
            sc.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(100));
                stopped(&f, "c1", Some(7));
            });
            s.handle("Wait", &wait_req("c1", ""))
        })
        .unwrap();
        assert!(t0.elapsed() >= std::time::Duration::from_millis(100));
        assert_eq!(WaitResponse::decode(&out[..]).unwrap().exit_status, 7);
    }

    /// REPAIR-5: 終わらなければ DEADLINE_EXCEEDED（4）。期限を過ぎてから返り、無期限には待たない。
    #[test]
    fn cri5_wait_timeout_deadline_exceeded() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        let s = fast_wait(s, 50);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        let t0 = std::time::Instant::now();
        let (code, msg) = err_code(s.handle("Wait", &wait_req("c1", "")));
        let el = t0.elapsed();
        assert_eq!(
            (code, msg.as_str()),
            (DEADLINE, "wait exceeded its deadline")
        );
        assert!(el >= std::time::Duration::from_millis(50), "{el:?}");
        assert!(el < std::time::Duration::from_secs(2), "{el:?}");
    }

    /// 未起動の Created は終了扱いにせず（0 を返さず）、期限切れになる。
    #[test]
    fn cri5_wait_created_not_started_times_out() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        let s = fast_wait(s, 50);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        assert_eq!(err_code(s.handle("Wait", &wait_req("c1", ""))).0, DEADLINE);
    }

    /// ERR-3: 存在しない ID は NOT_FOUND。待ちの途中で削除されても NOT_FOUND。
    #[test]
    fn cri5_wait_not_found_and_deleted_during_wait() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        let s = fast_wait(s, 5000);
        assert_eq!(
            err_code(s.handle("Wait", &wait_req("nope", ""))).0,
            NOT_FOUND
        );
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        let r = std::thread::scope(|sc| {
            sc.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                f.states.lock().unwrap().remove("c1");
            });
            s.handle("Wait", &wait_req("c1", ""))
        });
        assert_eq!(err_code(r).0, NOT_FOUND);
    }

    /// 不正な入力はランタイムを呼ばずに拒否する。
    #[test]
    fn cri5_wait_invalid_inputs() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        assert_eq!(
            err_code(s.handle("Wait", &wait_req("bad id!", ""))).0,
            INVALID
        );
        let (code, msg) = err_code(s.handle("Wait", &[0x0a, 5, 1]));
        assert_eq!((code, msg.as_str()), (INVALID, "malformed request payload"));
        let (code, msg) = err_code(s.handle("Wait", &wait_req("c1", "e")));
        assert_eq!((code, msg.as_str()), (UNIMPL, "exec_id is not supported"));
        assert!(f.calls.lock().unwrap().is_empty());
    }

    /// Wait の待ち中も同じコンテナの exec ゲートは取れる（Delete 等を止めない）。
    #[test]
    fn cri5_wait_does_not_hold_exec_gate() {
        let (s, f) = svc(TaskApiVersion::V2, Fake::default());
        let s = fast_wait(s, 5000);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        let id = ContainerId::new("c1").unwrap();
        let out = std::thread::scope(|sc| {
            let w = sc.spawn(|| s.handle("Wait", &wait_req("c1", "")));
            std::thread::sleep(std::time::Duration::from_millis(100));
            let t0 = std::time::Instant::now();
            drop(s.execs.lock_container(&id).unwrap());
            assert!(t0.elapsed() < std::time::Duration::from_secs(2));
            stopped(&f, "c1", Some(0));
            w.join().unwrap()
        })
        .unwrap();
        assert_eq!(WaitResponse::decode(&out[..]).unwrap().exit_status, 0);
    }

    /// exit_status の写像。
    #[test]
    fn cri5_exit_status_mapping() {
        let id = || RtId::new("c1").unwrap();
        let m = |s: ContainerStatus| exit_status_of(&RuntimeContainerStatus::from(&s));
        assert_eq!(m(ContainerStatus::stopped(id(), Some(0))), 0);
        assert_eq!(m(ContainerStatus::stopped(id(), Some(137))), 137);
        assert_eq!(m(ContainerStatus::stopped(id(), None)), 255);
        assert_eq!(m(ContainerStatus::stopped(id(), Some(-1))), 255);
        assert_eq!(m(ContainerStatus::created(id(), None)), 0);
    }

    type WaitFn = Option<
        fn(
            &fandhe_container_core::traits::WaitExitRequest<'_>,
        ) -> Result<ContainerStatus, TraitError>,
    >;

    /// `state` の回数を数え、`wait_exit` を上書きできる偽ランタイム（Wait の期限と上書きの照合用）。
    struct Probe {
        inner: Shared,
        state_calls: Arc<std::sync::atomic::AtomicUsize>,
        wait_override: WaitFn,
    }

    impl ContainerRuntime for Probe {
        fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
            self.inner.create(r)
        }
        fn start(&self, r: &RtStart) -> Result<ContainerStatus, TraitError> {
            self.inner.start(r)
        }
        fn kill(&self, r: &KillRequest) -> Result<ContainerStatus, TraitError> {
            self.inner.kill(r)
        }
        fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
            self.inner.stop(r)
        }
        fn delete(&self, r: &RtDelete) -> Result<RtDeleteResponse, TraitError> {
            self.inner.delete(r)
        }
        fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
            self.state_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.state(r)
        }
        fn wait_exit(
            &self,
            req: &fandhe_container_core::traits::WaitExitRequest<'_>,
        ) -> Result<ContainerStatus, TraitError> {
            match self.wait_override {
                Some(f) => f(req),
                None => {
                    // 既定の本体と同じ契約で、このモジュールの Probe 経由の state を使う。
                    let end = std::time::Instant::now() + req.timeout();
                    loop {
                        if req.is_cancelled() {
                            return Err(TraitError::new(ErrorCode::Unavailable, "wait cancelled"));
                        }
                        let st = self.state(&StateRequest::new(req.id().clone()))?;
                        if st.state() == ContainerState::Stopped {
                            return Ok(st);
                        }
                        if std::time::Instant::now() >= end {
                            return Err(TraitError::new(
                                ErrorCode::Timeout,
                                "wait exceeded its deadline",
                            ));
                        }
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                }
            }
        }
    }

    fn probe_svc(
        timeout_ms: u64,
        poll_ms: u64,
        wait_override: WaitFn,
    ) -> (TaskService, Arc<Fake>, Arc<std::sync::atomic::AtomicUsize>) {
        let f = Arc::new(Fake::default());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rt = Probe {
            inner: Shared(f.clone()),
            state_calls: calls.clone(),
            wait_override,
        };
        let s = TaskService::new(TaskApiVersion::V2, RuntimeAdapter::from_runtime(rt))
            .with_wait_config(
                WaitConfig::new(
                    std::time::Duration::from_millis(timeout_ms),
                    std::time::Duration::from_millis(poll_ms),
                )
                .unwrap(),
            );
        (s, f, calls)
    }

    fn wait_with(
        s: &TaskService,
        deadline: RequestDeadline,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, RpcStatus> {
        s.handle_with_context(
            "Wait",
            &wait_req("c1", ""),
            &CallContext::new(cancelled, deadline),
        )
    }

    /// CRI-1: `timeout_nano` が WaitConfig より短ければその期限（100ms）で 4。
    #[test]
    fn cri1_wait_timeout_nano_shorter_than_config() {
        let (s, _f, _c) = probe_svc(10_000, 10, None);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        let t0 = std::time::Instant::now();
        let d = RequestDeadline::from_timeout_nano(t0, 100_000_000);
        let (code, msg) = err_code(wait_with(&s, d, &|| false));
        let el = t0.elapsed();
        assert_eq!(
            (code, msg.as_str()),
            (DEADLINE, "wait exceeded its deadline")
        );
        assert!(el >= std::time::Duration::from_millis(100), "{el:?}");
        assert!(el < std::time::Duration::from_secs(1), "{el:?}");
    }

    /// REPAIR-5: `timeout_nano` が WaitConfig（100ms）より長くても WaitConfig で切れる。0 も同じ。
    #[test]
    fn repair5_wait_timeout_nano_capped_by_config() {
        for nano in [10_000_000_000i64, 0] {
            let (s, _f, _c) = probe_svc(100, 10, None);
            s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
            s.handle("Start", &start_req("c1")).unwrap();
            let t0 = std::time::Instant::now();
            let d = RequestDeadline::from_timeout_nano(t0, nano);
            assert_eq!(err_code(wait_with(&s, d, &|| false)).0, DEADLINE);
            let el = t0.elapsed();
            assert!(el >= std::time::Duration::from_millis(100), "{el:?}");
            assert!(el < std::time::Duration::from_secs(2), "{el:?}");
        }
    }

    /// CRI-1: 負の `timeout_nano` は runtime（state）を呼ばずに 4。ただし id の検査は先に行う。
    #[test]
    fn cri1_wait_negative_timeout_nano_skips_runtime() {
        let (s, _f, calls) = probe_svc(10_000, 10, None);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        let d = RequestDeadline::from_timeout_nano(std::time::Instant::now(), -5);
        let (code, msg) = err_code(wait_with(&s, d, &|| false));
        assert_eq!(
            (code, msg.as_str()),
            (DEADLINE, "wait exceeded its deadline")
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        let bad = s.handle_with_context(
            "Wait",
            &wait_req("bad id!", ""),
            &CallContext::new(&|| false, RequestDeadline::Expired),
        );
        assert_eq!(err_code(bad).0, INVALID);
    }

    /// REPAIR-5: 取り消しは UNAVAILABLE（14）の "wait cancelled"。
    #[test]
    fn repair5_wait_cancelled_is_unavailable() {
        let (s, _f, _c) = probe_svc(10_000, 10, None);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        let flag = std::sync::atomic::AtomicBool::new(false);
        let cancelled = || flag.load(std::sync::atomic::Ordering::SeqCst);
        let t0 = std::time::Instant::now();
        let r = std::thread::scope(|sc| {
            sc.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            });
            wait_with(&s, RequestDeadline::None, &cancelled)
        });
        let (code, msg) = err_code(r);
        assert_eq!((code, msg.as_str()), (14, "wait cancelled"));
        assert!(t0.elapsed() < std::time::Duration::from_secs(1));
    }

    /// CRI-1: 上書きされた `wait_exit` が使われる（照会間隔 10 秒でも即座に返り、state は呼ばれない）。
    #[test]
    fn cri1_wait_uses_overridden_wait_exit() {
        let (s, _f, calls) = probe_svc(
            10_000,
            10_000,
            Some(|req| Ok(ContainerStatus::stopped(req.id().clone(), Some(33)))),
        );
        let t0 = std::time::Instant::now();
        let out = wait_with(&s, RequestDeadline::None, &|| false).unwrap();
        assert_eq!(WaitResponse::decode(&out[..]).unwrap().exit_status, 33);
        assert!(t0.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// PLUG-1: 上書きが `Stopped` 以外を返したら plugin の不正な応答として INTERNAL（13）。
    #[test]
    fn plug1_wait_rejects_non_stopped_override() {
        let (s, _f, _c) = probe_svc(
            10_000,
            10,
            Some(|req| {
                Ok(ContainerStatus::running(
                    req.id().clone(),
                    NonZeroU32::new(1),
                ))
            }),
        );
        let (code, _msg) = err_code(wait_with(&s, RequestDeadline::None, &|| false));
        assert_eq!(code, 13);
    }

    // ---- exec_id つきの State / Kill / Wait / Delete（#3681・CRI-5・CRI-1・REPAIR-5）----

    fn state_exec_req(id: &str, eid: &str) -> Vec<u8> {
        WireState {
            id: id.into(),
            exec_id: eid.into(),
        }
        .encode_to_vec()
    }

    fn state_exec_of(s: &TaskService, id: &str, eid: &str) -> StateResponse {
        let out = s.handle("State", &state_exec_req(id, eid)).unwrap();
        StateResponse::decode(&out[..]).unwrap()
    }

    /// Running のコンテナに exec を登録する（未起動）。
    fn registered(version: TaskApiVersion) -> (TaskService, Arc<Fake>, Arc<FakeLauncher>) {
        let (s, f, l) = svc_exec(version);
        running_container(&s, "c1");
        s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
        (s, f, l)
    }

    /// Running のコンテナで exec を起動済みにする。
    fn started(version: TaskApiVersion) -> (TaskService, Arc<Fake>, Arc<FakeLauncher>) {
        let (s, f, l) = registered(version);
        s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
        (s, f, l)
    }

    fn wait_exec_req(eid: &str) -> Vec<u8> {
        wait_req("c1", eid)
    }

    fn wait_exit_of(r: Result<Vec<u8>, RpcStatus>) -> u32 {
        WaitResponse::decode(&r.unwrap()[..]).unwrap().exit_status
    }

    fn wait_exec_with(
        s: &TaskService,
        deadline: RequestDeadline,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, RpcStatus> {
        let ctx = CallContext::new(cancelled, deadline);
        s.handle_with_context("Wait", &wait_exec_req("e1"), &ctx)
    }

    /// CRI-5: State(exec_id) は Created・実行中・終了済みを具体値で返す。id は exec ID、exec_id 欄は空。
    #[test]
    fn cri5_3681_state_exec_reports_each_status() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, f, l) = registered(v);
            let r = state_exec_of(&s, "c1", "e1");
            assert_eq!(
                (
                    r.id.as_str(),
                    r.pid,
                    r.status,
                    r.exit_status,
                    r.exec_id.as_str()
                ),
                ("e1", 0, TaskStatus::Created as i32, 0, "")
            );
            s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
            let r = state_exec_of(&s, "c1", "e1");
            assert_eq!(
                (r.id.as_str(), r.pid, r.status, r.exit_status),
                ("e1", 5151, TaskStatus::Running as i32, 0)
            );
            l.last().exit(Some(3));
            let r = state_exec_of(&s, "c1", "e1");
            assert_eq!(
                (r.pid, r.status, r.exit_status),
                (5151, TaskStatus::Stopped as i32, 3)
            );
            l.last().exit(None);
            assert_eq!(state_exec_of(&s, "c1", "e1").exit_status, 255);
            l.last().exit(Some(-1));
            assert_eq!(state_exec_of(&s, "c1", "e1").exit_status, 255);
            // exec の経路はランタイムを触らない。
            assert!(
                !f.calls
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|c| c.starts_with("kill"))
            );
        }
    }

    /// CRI-5: Kill(exec_id) はシグナルを送り、範囲外・未起動・終了済みを具体値で拒否する。
    #[test]
    fn cri5_3681_kill_exec_signals_process() {
        let (s, f, l) = registered(TaskApiVersion::V2);
        let (code, msg) = err_code(s.handle("Kill", &kill_req("c1", 9, false, "e1")));
        assert_eq!((code, msg.as_str()), (PRECOND, "process not created"));
        s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
        let out = s.handle("Kill", &kill_req("c1", 15, false, "e1")).unwrap();
        assert!(out.is_empty());
        assert_eq!(*l.last().signals.lock().unwrap(), vec![15]);
        for bad in [0, 65] {
            let (code, _) = err_code(s.handle("Kill", &kill_req("c1", bad, false, "e1")));
            assert_eq!(code, INVALID);
        }
        l.last().exit(Some(0));
        let (code, msg) = err_code(s.handle("Kill", &kill_req("c1", 9, false, "e1")));
        assert_eq!(
            (code, msg.as_str()),
            (NOT_FOUND, "process already finished")
        );
        assert_eq!(*l.last().signals.lock().unwrap(), vec![15]);
        assert!(
            !f.calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.starts_with("kill"))
        );
    }

    /// CRI-5: exec_id と all の組は UNIMPLEMENTED で、シグナルは送られない（containerd は exec に all を送らない）。
    #[test]
    fn cri5_3681_kill_exec_all_is_rejected() {
        let (s, _, l) = started(TaskApiVersion::V2);
        let (code, msg) = err_code(s.handle("Kill", &kill_req("c1", 9, true, "e1")));
        assert_eq!((code, msg.as_str()), (UNIMPL, "kill all is not supported"));
        assert!(l.last().signals.lock().unwrap().is_empty());
    }

    /// CRI-5: Wait(exec_id) は終了コードを返す（不明は 255）。
    #[test]
    fn cri5_3681_wait_exec_returns_exit_status() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, _, l) = started(v);
            let s = fast_wait(s, 5_000);
            l.last().exit(Some(3));
            assert_eq!(wait_exit_of(s.handle("Wait", &wait_exec_req("e1"))), 3);
            l.last().exit(None);
            assert_eq!(wait_exit_of(s.handle("Wait", &wait_exec_req("e1"))), 255);
        }
    }

    /// CRI-5: Wait は Start の前に呼ばれてもよい（ExecSync の順序）。Start 後の終了で戻る。
    #[test]
    fn cri5_3681_wait_exec_before_start() {
        let (s, _, l) = registered(TaskApiVersion::V2);
        let s = fast_wait(s, 10_000);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|sc| {
            let w = sc.spawn(|| {
                tx.send(()).unwrap();
                s.handle("Wait", &wait_exec_req("e1"))
            });
            rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
            s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
            l.last().exit(Some(7));
            assert_eq!(wait_exit_of(w.join().unwrap()), 7);
        });
    }

    /// REPAIR-5: Wait(exec_id) の期限切れは DEADLINE_EXCEEDED（未起動・起動済みの両方）。
    /// 期限切れ済みの要求は登録簿を見ずに 4（未登録でも 4）。
    #[test]
    fn cri5_3681_wait_exec_deadline() {
        let (s, _, _) = registered(TaskApiVersion::V2);
        let s = fast_wait(s, 60);
        let (code, msg) = err_code(s.handle("Wait", &wait_exec_req("e1")));
        assert_eq!(
            (code, msg.as_str()),
            (DEADLINE, "wait exceeded its deadline")
        );
        s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
        let (code, msg) = err_code(s.handle("Wait", &wait_exec_req("e1")));
        assert_eq!(
            (code, msg.as_str()),
            (DEADLINE, "wait exceeded its deadline")
        );
        let (code, _) = err_code(wait_exec_with(&s, RequestDeadline::Expired, &|| false));
        assert_eq!(code, DEADLINE);
        let (code, _) = err_code(s.handle_with_context(
            "Wait",
            &wait_req("c1", "nope"),
            &CallContext::new(&|| false, RequestDeadline::Expired),
        ));
        assert_eq!(code, DEADLINE);
    }

    /// REPAIR-5: 取り消しは UNAVAILABLE（未起動・起動済みの両方）。
    #[test]
    fn cri5_3681_wait_exec_cancelled() {
        let (s, _, _) = registered(TaskApiVersion::V2);
        let s = fast_wait(s, 10_000);
        for phase in 0..2 {
            if phase == 1 {
                s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
            }
            let flag = std::sync::atomic::AtomicBool::new(false);
            let cancelled = || flag.load(std::sync::atomic::Ordering::SeqCst);
            let t0 = std::time::Instant::now();
            let r = std::thread::scope(|sc| {
                sc.spawn(|| {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                });
                wait_exec_with(&s, RequestDeadline::None, &cancelled)
            });
            let (code, msg) = err_code(r);
            assert_eq!((code, msg.as_str()), (UNAVAILABLE, "wait cancelled"));
            assert!(t0.elapsed() < std::time::Duration::from_secs(5));
        }
    }

    /// CRI-5: 未起動の待ち中に登録が除去・再作成されたら NOT_FOUND（別の登録へ乗り移らない）。
    #[test]
    fn cri5_3681_wait_exec_registration_replaced() {
        let (s, _, _) = registered(TaskApiVersion::V2);
        let s = fast_wait(s, 10_000);
        for recreate in [false, true] {
            let r = std::thread::scope(|sc| {
                let w = sc.spawn(|| s.handle("Wait", &wait_exec_req("e1")));
                std::thread::sleep(std::time::Duration::from_millis(60));
                s.handle("Delete", &delete_req("c1", "e1")).unwrap();
                if recreate {
                    s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
                }
                w.join().unwrap()
            });
            let (code, msg) = err_code(r);
            assert_eq!((code, msg.as_str()), (NOT_FOUND, "exec not found"));
            if !recreate {
                s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
            }
            s.handle("Delete", &delete_req("c1", "e1")).unwrap();
            s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
        }
    }

    /// CRI-5: 起動済みの exec を待っている間に Delete(exec_id) されても、Wait は終了コードを返す。
    #[test]
    fn cri5_3681_wait_exec_survives_delete() {
        let (s, _, l) = started(TaskApiVersion::V2);
        let s = fast_wait(s, 10_000);
        std::thread::scope(|sc| {
            let w = sc.spawn(|| s.handle("Wait", &wait_exec_req("e1")));
            std::thread::sleep(std::time::Duration::from_millis(60));
            l.last().exit(Some(4));
            // Wait が Started を掴んだ後でも、除去後でも終了コードは返る。
            s.handle("Delete", &delete_req("c1", "e1")).unwrap();
            assert_eq!(wait_exit_of(w.join().unwrap()), 4);
        });
    }

    /// CRI-5: Delete(exec_id) は段階ごとの戻り値を返し、除去後はすべての RPC が NOT_FOUND。
    #[test]
    fn cri5_3681_delete_exec_each_status() {
        let (s, f, l) = registered(TaskApiVersion::V2);
        // Created は除去して pid 0・exit 0。
        let out = s.handle("Delete", &delete_req("c1", "e1")).unwrap();
        let r = DeleteResponse::decode(&out[..]).unwrap();
        assert_eq!((r.pid, r.exit_status), (0, 0));
        // 実行中は拒否して残る。
        s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
        s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
        let (code, msg) = err_code(s.handle("Delete", &delete_req("c1", "e1")));
        assert_eq!(
            (code, msg.as_str()),
            (PRECOND, "cannot delete a running process")
        );
        assert_eq!(
            state_exec_of(&s, "c1", "e1").status,
            TaskStatus::Running as i32
        );
        // 終了済みは pid と終了コードを返して除去。
        l.last().exit(Some(3));
        let out = s.handle("Delete", &delete_req("c1", "e1")).unwrap();
        let r = DeleteResponse::decode(&out[..]).unwrap();
        assert_eq!((r.pid, r.exit_status), (5151, 3));
        assert!(r.exited_at.is_none());
        // 除去後はすべて NOT_FOUND。
        let calls: [(&str, Vec<u8>); 4] = [
            ("State", state_exec_req("c1", "e1")),
            ("Kill", kill_req("c1", 9, false, "e1")),
            ("Wait", wait_exec_req("e1")),
            ("Delete", delete_req("c1", "e1")),
        ];
        for (m, req) in calls {
            let (code, msg) = err_code(s.handle(m, &req));
            assert_eq!((code, msg.as_str()), (NOT_FOUND, "exec not found"), "{m}");
        }
        // コンテナの状態は変わらず、ランタイムの delete は呼ばれない。
        assert_eq!(state_of(&s, "c1").status, TaskStatus::Running as i32);
        assert!(
            !f.calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.starts_with("delete"))
        );
    }

    /// CRI-5: Delete(exec_id) で上限が回復し、同じ exec_id を再登録できる。
    #[test]
    fn cri5_3681_delete_exec_recovers_limit() {
        let (s, _, _) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c1");
        for i in 0..super::super::exec::MAX_EXECS_PER_CONTAINER {
            s.handle("Exec", &exec_req("c1", &format!("e{i}"), SPEC))
                .unwrap();
        }
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("c1", "over", SPEC))).0,
            RESOURCE_EXHAUSTED
        );
        s.handle("Delete", &delete_req("c1", "e0")).unwrap();
        s.handle("Exec", &exec_req("c1", "e0", SPEC)).unwrap();
    }

    /// CRI-5・REPAIR-5（#4148）: status() が失敗でも SIGKILL は届き、他のシグナルは状態のエラーを返して送らない。
    #[test]
    fn cri5_4148_kill_exec_status_failure_only_sigkill_passes() {
        let (s, _, l) = started(TaskApiVersion::V2);
        *l.last().status_fails.lock().unwrap() = true;
        let (code, msg) = err_code(s.handle("Kill", &kill_req("c1", 15, false, "e1")));
        assert_eq!((code, msg.as_str()), (UNAVAILABLE, "status failed"));
        assert!(l.last().signals.lock().unwrap().is_empty());
        let out = s.handle("Kill", &kill_req("c1", 9, false, "e1")).unwrap();
        assert!(out.is_empty());
        assert_eq!(*l.last().signals.lock().unwrap(), vec![9]);
    }

    /// REPAIR-5・fail-closed: status() の失敗は写像して返し、登録は残る。
    #[test]
    fn cri5_3681_delete_exec_status_failure_keeps_entry() {
        let (s, _, l) = started(TaskApiVersion::V2);
        *l.last().status_fails.lock().unwrap() = true;
        let (code, msg) = err_code(s.handle("Delete", &delete_req("c1", "e1")));
        assert_eq!((code, msg.as_str()), (UNAVAILABLE, "status failed"));
        *l.last().status_fails.lock().unwrap() = false;
        l.last().exit(Some(0));
        assert!(s.handle("Delete", &delete_req("c1", "e1")).is_ok());
    }

    /// CRI-5: 起動中の Delete(exec_id) は起動の完了後にだけ進む。
    #[test]
    fn cri5_3681_delete_exec_waits_for_launch() {
        struct SlowLauncher {
            events: Arc<Mutex<Vec<&'static str>>>,
            entered: Mutex<std::sync::mpsc::Sender<()>>,
        }
        impl TaskExecLauncher for SlowLauncher {
            fn launch(
                &self,
                _c: &ContainerId,
                _e: &ExecId,
                _s: &ExecProcessSpec,
            ) -> Result<Arc<dyn TaskExecProcess>, CriError> {
                self.entered.lock().unwrap().send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(300));
                self.events.lock().unwrap().push("launch-end");
                let p = FakeProc::new(5151);
                p.exit(Some(0));
                Ok(p)
            }
        }
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        let events = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        let s = s.with_exec_launcher(Arc::new(SlowLauncher {
            events: events.clone(),
            entered: Mutex::new(tx),
        }));
        running_container(&s, "c1");
        s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
        std::thread::scope(|sc| {
            let start = sc.spawn(|| s.handle("Start", &start_exec_req("c1", "e1")));
            rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
            let del = sc.spawn(|| {
                let r = s.handle("Delete", &delete_req("c1", "e1"));
                events.lock().unwrap().push("delete-done");
                r
            });
            assert!(start.join().unwrap().is_ok());
            let r = del.join().unwrap().unwrap();
            let r = DeleteResponse::decode(&r[..]).unwrap();
            assert_eq!((r.pid, r.exit_status), (5151, 0));
        });
        assert_eq!(*events.lock().unwrap(), vec!["launch-end", "delete-done"]);
    }

    /// 入力検査: 不正な ID は INVALID_ARGUMENT、未登録は NOT_FOUND（4 RPC すべて）。
    #[test]
    fn cri5_3681_exec_id_rejected_and_unregistered() {
        let (s, _, _) = started(TaskApiVersion::V2);
        let make = |id: &str, eid: &str| -> [(&'static str, Vec<u8>); 4] {
            [
                ("State", state_exec_req(id, eid)),
                ("Kill", kill_req(id, 9, false, eid)),
                ("Wait", wait_req(id, eid)),
                ("Delete", delete_req(id, eid)),
            ]
        };
        for (id, eid) in [
            ("c1", ".."),
            ("c1", "bad id!"),
            ("..", "e1"),
            ("bad id!", "e1"),
        ] {
            for (m, req) in make(id, eid) {
                assert_eq!(err_code(s.handle(m, &req)).0, INVALID, "{m} {id} {eid}");
            }
        }
        for (m, req) in make("c1", "nope") {
            let (code, msg) = err_code(s.handle(m, &req));
            assert_eq!((code, msg.as_str()), (NOT_FOUND, "exec not found"), "{m}");
        }
    }

    /// CRI-5: コンテナの Delete で exec の登録が消え、4 RPC とも NOT_FOUND。
    #[test]
    fn cri5_3681_container_delete_purges_exec() {
        let (s, f, _) = started(TaskApiVersion::V2);
        stopped(&f, "c1", Some(0));
        s.handle("Delete", &delete_req("c1", "")).unwrap();
        for (m, req) in [
            ("State", state_exec_req("c1", "e1")),
            ("Kill", kill_req("c1", 9, false, "e1")),
            ("Wait", wait_exec_req("e1")),
            ("Delete", delete_req("c1", "e1")),
        ] {
            assert_eq!(err_code(s.handle(m, &req)).0, NOT_FOUND, "{m}");
        }
    }

    // ---- exec 登録の回収と Created の exec の Wait（#4058・CRI-1・CRI-5・REPAIR-5）----

    /// shim の外でのコンテナ削除（RuntimeService / CLI による削除）を表す。
    fn remove_externally(f: &Fake, id: &str) {
        f.states.lock().unwrap().remove(id);
        f.preset.lock().unwrap().remove(id);
    }

    fn exec_state_code(s: &TaskService, id: &str, eid: &str) -> (i32, String) {
        err_code(s.handle("State", &state_exec_req(id, eid)))
    }

    /// 最後に起動した FakeProc の強参照数（起動役の記録 + 登録簿が握っていれば +1、いま取った分 +1）。
    fn proc_handles(l: &FakeLauncher) -> usize {
        Arc::strong_count(&l.last())
    }

    /// #4058・CRI-5（T1）: 外で消えたコンテナへの shim の Delete は NOT_FOUND のまま、exec 登録とハンドルを解放する。
    #[test]
    fn cri5_4058_delete_after_external_remove_purges_exec() {
        let (s, f, l) = started(TaskApiVersion::V2);
        let held = proc_handles(&l);
        remove_externally(&f, "c1");
        assert_eq!(
            err_code(s.handle("Delete", &delete_req("c1", ""))).0,
            NOT_FOUND
        );
        let (code, msg) = exec_state_code(&s, "c1", "e1");
        assert_eq!((code, msg.as_str()), (NOT_FOUND, "exec not found"));
        assert_eq!(proc_handles(&l), held - 1);
    }

    /// #4058・CRI-5（T2）: Exec / Start(exec_id) が NOT_FOUND を観測したら登録を除去する。
    #[test]
    fn cri5_4058_exec_and_start_on_gone_container_purge() {
        for via_start in [false, true] {
            let (s, f, _) = registered(TaskApiVersion::V2);
            remove_externally(&f, "c1");
            let r = if via_start {
                s.handle("Start", &start_exec_req("c1", "e1"))
            } else {
                s.handle("Exec", &exec_req("c1", "e2", SPEC))
            };
            assert_eq!(err_code(r).0, NOT_FOUND);
            let (code, msg) = exec_state_code(&s, "c1", "e1");
            assert_eq!((code, msg.as_str()), (NOT_FOUND, "exec not found"));
        }
    }

    /// #4058・CRI-5（T2）: 一時的な不達（UNAVAILABLE）では登録を除去しない。
    #[test]
    fn cri5_4058_non_not_found_error_keeps_registration() {
        let (s, f, _) = registered(TaskApiVersion::V2);
        f.fail_state.lock().unwrap().insert("c1".into());
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("c1", "e2", SPEC))).0,
            UNAVAILABLE
        );
        assert_eq!(
            err_code(s.handle("Delete", &delete_req("c1", ""))).0,
            UNAVAILABLE
        );
        f.fail_state.lock().unwrap().clear();
        assert_eq!(
            state_exec_of(&s, "c1", "e1").status,
            TaskStatus::Created as i32
        );
    }

    /// #4058・CRI-5（T3）: shim の Create の成功で、同じ ID の旧登録を引き継がない。
    #[test]
    fn cri5_4058_create_purges_stale_registrations() {
        let (s, f, _) = started(TaskApiVersion::V2);
        remove_externally(&f, "c1");
        running_container(&s, "c1");
        assert_eq!(exec_state_code(&s, "c1", "e1").0, NOT_FOUND);
        s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
        let r = state_exec_of(&s, "c1", "e1");
        assert_eq!((r.pid, r.status), (0, TaskStatus::Created as i32));
    }

    /// #4058・CRI-5（T3）: Create の失敗では旧登録を消さない。
    #[test]
    fn cri5_4058_failed_create_keeps_registrations() {
        let (s, _, _) = registered(TaskApiVersion::V2);
        // 既に存在する ID の Create は失敗する。
        assert!(s.handle("Create", &create_req("c1", &abs("/b"))).is_err());
        assert_eq!(
            state_exec_of(&s, "c1", "e1").status,
            TaskStatus::Created as i32
        );
    }

    /// 全体上限まで 16 コンテナ × 64 で埋める。
    fn fill_total(s: &TaskService) {
        assert_eq!(
            super::super::exec::MAX_EXECS_PER_CONTAINER * 16,
            super::super::exec::MAX_EXECS_TOTAL
        );
        for c in 0..16 {
            let id = format!("c{c}");
            running_container(s, &id);
            for i in 0..super::super::exec::MAX_EXECS_PER_CONTAINER {
                s.handle("Exec", &exec_req(&id, &format!("e{i}"), SPEC))
                    .unwrap();
            }
        }
    }

    /// #4058・CRI-5・REPAIR-5（T4）: 全体上限では外で消えたコンテナの登録だけを掃除して 1 回だけやり直す。
    #[test]
    fn cri5_4058_total_limit_sweep_reclaims_gone_containers() {
        let (s, f, _) = svc_exec(TaskApiVersion::V2);
        fill_total(&s);
        remove_externally(&f, "c3");
        remove_externally(&f, "c9");
        running_container(&s, "c16");
        s.handle("Exec", &exec_req("c16", "e0", SPEC)).unwrap();
        for gone in ["c3", "c9"] {
            assert_eq!(exec_state_code(&s, gone, "e0").0, NOT_FOUND, "{gone}");
        }
        for live in ["c0", "c15"] {
            assert_eq!(
                state_exec_of(&s, live, "e0").status,
                TaskStatus::Created as i32,
                "{live}"
            );
        }
    }

    /// 外で消して同じ ID で作り直した状態を作る（shim の Delete / Create は通さず、識別子だけが変わる。#4220）。
    fn recreate_externally(f: &Fake, id: &str, instance: u64) {
        f.instances.lock().unwrap().insert(id.into(), instance);
    }

    fn set_instance(f: &Fake, id: &str, instance: u64) {
        recreate_externally(f, id, instance);
    }

    const SPEC_NEW: &str = r#"{"cwd":"/","args":["/bin/true"],"env":["N=1"]}"#;

    /// #4220・CRI-5・SEC-1（T5）: 外で作り直されたコンテナでは旧い exec 登録を起動せず `NOT_FOUND` で失敗し、
    /// 登録は除去されて同じ exec_id を新しい spec で再登録・起動できる（V2 / V3）。
    #[test]
    fn cri5_4220_recreated_outside_start_exec_is_not_found_and_not_launched() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, f, l) = svc_exec(v);
            running_container(&s, "c1");
            set_instance(&f, "c1", 1);
            s.handle("Exec", &exec_req("c1", "e0", SPEC)).unwrap();
            recreate_externally(&f, "c1", 2);
            let (code, msg) = err_code(s.handle("Start", &start_exec_req("c1", "e0")));
            assert_eq!((code, msg.as_str()), (NOT_FOUND, "exec not found"));
            assert!(l.launched.lock().unwrap().is_empty());
            s.handle("Exec", &exec_req("c1", "e0", SPEC_NEW)).unwrap();
            s.handle("Start", &start_exec_req("c1", "e0")).unwrap();
            let launched = l.launched.lock().unwrap();
            assert_eq!(launched.len(), 1);
            assert_eq!(launched[0].2.args(), ["/bin/true"]);
            assert_eq!(launched[0].2.env(), ["N=1"]);
        }
    }

    /// #4220: Exec は旧い登録を除いてから登録するので、コンテナ単位の上限も同じ exec_id の再登録も回復する。
    #[test]
    fn cri5_4220_recreated_outside_exec_recovers_per_container_cap() {
        let (s, f, _) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c1");
        set_instance(&f, "c1", 1);
        for i in 0..super::super::exec::MAX_EXECS_PER_CONTAINER {
            s.handle("Exec", &exec_req("c1", &format!("e{i}"), SPEC))
                .unwrap();
        }
        recreate_externally(&f, "c1", 2);
        s.handle("Exec", &exec_req("c1", "e0", SPEC)).unwrap();
        s.handle("Exec", &exec_req("c1", "fresh", SPEC)).unwrap();
        // 旧い登録は 1 件も残らない（e1 は除去済み）。
        assert_eq!(exec_state_code(&s, "c1", "e1").0, NOT_FOUND);
    }

    /// #4220: 識別子が変わらなければ（状態の照会が挟まっても）従来どおり起動される。
    #[test]
    fn cri5_4220_same_instance_across_state_queries_still_launches() {
        let (s, f, l) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c1");
        set_instance(&f, "c1", 7);
        s.handle("Exec", &exec_req("c1", "e0", SPEC)).unwrap();
        s.handle("State", &state_exec_req("c1", "")).unwrap();
        s.handle("Start", &start_exec_req("c1", "e0")).unwrap();
        assert_eq!(l.launched.lock().unwrap().len(), 1);
    }

    /// #4220（fail-closed）: 登録時に識別子があり、現在は報告が無ければ起動しない。
    #[test]
    fn cri5_4220_instance_lost_is_not_launched() {
        let (s, f, l) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c1");
        set_instance(&f, "c1", 1);
        s.handle("Exec", &exec_req("c1", "e0", SPEC)).unwrap();
        f.instances.lock().unwrap().remove("c1");
        let (code, msg) = err_code(s.handle("Start", &start_exec_req("c1", "e0")));
        assert_eq!((code, msg.as_str()), (NOT_FOUND, "exec not found"));
        assert!(l.launched.lock().unwrap().is_empty());
    }

    /// #4220（T4 + T5）: 全体上限の掃除は、外で作り直された別コンテナの旧い登録も除去して空きを作る。
    #[test]
    fn cri5_4220_reclaim_purges_recreated_instance() {
        let (s, f, _) = svc_exec(TaskApiVersion::V2);
        for c in 0..16 {
            set_instance(&f, &format!("c{c}"), 1);
        }
        fill_total(&s);
        recreate_externally(&f, "c3", 2);
        running_container(&s, "c16");
        s.handle("Exec", &exec_req("c16", "e0", SPEC)).unwrap();
        assert_eq!(exec_state_code(&s, "c3", "e0").0, NOT_FOUND);
        assert_eq!(
            state_exec_of(&s, "c0", "e0").status,
            TaskStatus::Created as i32
        );
    }

    /// REPAIR-5: 消えたコンテナが無ければ上限は弱めず RESOURCE_EXHAUSTED で、既存の登録は残る。
    #[test]
    fn repair5_4058_total_limit_without_gone_containers_still_exhausted() {
        let (s, _, _) = svc_exec(TaskApiVersion::V2);
        fill_total(&s);
        running_container(&s, "c16");
        let (code, msg) = err_code(s.handle("Exec", &exec_req("c16", "e0", SPEC)));
        assert_eq!((code, msg.as_str()), (RESOURCE_EXHAUSTED, "too many execs"));
        assert_eq!(
            state_exec_of(&s, "c0", "e0").status,
            TaskStatus::Created as i32
        );
    }

    /// #4058: 照会が NOT_FOUND 以外で失敗したコンテナの登録は掃除で消さない。
    #[test]
    fn cri5_4058_sweep_keeps_entries_on_non_not_found_error() {
        let (s, f, _) = svc_exec(TaskApiVersion::V2);
        fill_total(&s);
        f.fail_state.lock().unwrap().insert("c3".into());
        running_container(&s, "c16");
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("c16", "e0", SPEC))).0,
            RESOURCE_EXHAUSTED
        );
        f.fail_state.lock().unwrap().clear();
        assert_eq!(
            state_exec_of(&s, "c3", "e0").status,
            TaskStatus::Created as i32
        );
    }

    /// #4058: 対象コンテナが 64 件で全体も 1024 件のときも掃除せず、他コンテナを照会しない。
    #[test]
    fn cri5_4058_per_container_and_total_full_does_not_sweep() {
        let (s, f, _) = svc_exec(TaskApiVersion::V2);
        fill_total(&s);
        f.calls.lock().unwrap().clear();
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("c0", "over", SPEC))).0,
            RESOURCE_EXHAUSTED
        );
        assert_eq!(*f.calls.lock().unwrap(), vec!["state c0".to_owned()]);
    }

    /// #4058: コンテナ単位の上限では掃除せず、他コンテナを照会しない。
    #[test]
    fn cri5_4058_per_container_limit_does_not_sweep() {
        let (s, f, _) = svc_exec(TaskApiVersion::V2);
        running_container(&s, "c2");
        s.handle("Exec", &exec_req("c2", "e0", SPEC)).unwrap();
        running_container(&s, "c1");
        for i in 0..super::super::exec::MAX_EXECS_PER_CONTAINER {
            s.handle("Exec", &exec_req("c1", &format!("e{i}"), SPEC))
                .unwrap();
        }
        f.calls.lock().unwrap().clear();
        assert_eq!(
            err_code(s.handle("Exec", &exec_req("c1", "over", SPEC))).0,
            RESOURCE_EXHAUSTED
        );
        assert_eq!(*f.calls.lock().unwrap(), vec!["state c1".to_owned()]);
    }

    /// #4058・CRI-5: v2 と v3 は exec の登録簿を共有し、どちらの Delete でも両方から消える。
    #[test]
    fn cri5_4058_v2_v3_share_exec_registry() {
        let (v2, f, l) = svc_exec(TaskApiVersion::V2);
        let v3 = TaskService::new(
            TaskApiVersion::V3,
            RuntimeAdapter::from_runtime(Shared(f.clone())),
        )
        .with_exec_launcher(l.clone())
        .with_shared_created(&v2);
        running_container(&v2, "c1");
        v2.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
        assert_eq!(
            state_exec_of(&v3, "c1", "e1").status,
            TaskStatus::Created as i32
        );
        stopped(&f, "c1", Some(0));
        v3.handle("Delete", &delete_req("c1", "")).unwrap();
        assert_eq!(exec_state_code(&v2, "c1", "e1").0, NOT_FOUND);
    }

    /// #4058・CRI-1（D2）: Created の exec は、コンテナが停止しても期限まで待つ。
    /// アダプタを呼ばない不変条件（exec_id つきの Wait は実行層を照会しない）も固定する。
    #[test]
    fn cri5_4058_wait_exec_created_on_stopped_container_waits_until_deadline() {
        let (s, f, _) = registered(TaskApiVersion::V2);
        stopped(&f, "c1", Some(0));
        let s = fast_wait(s, 200);
        f.calls.lock().unwrap().clear();
        let t0 = std::time::Instant::now();
        let (code, msg) = err_code(s.handle("Wait", &wait_exec_req("e1")));
        assert_eq!(
            (code, msg.as_str()),
            (DEADLINE, "wait exceeded its deadline")
        );
        assert!(t0.elapsed() >= std::time::Duration::from_millis(200));
        assert!(f.calls.lock().unwrap().is_empty());
    }

    /// #4058・CRI-1: 未起動の exec の Wait は、登録が除去されれば期限より十分前に NOT_FOUND で戻る
    /// （Delete(exec_id)・停止後のコンテナ Delete・外で消えた後の Delete）。
    #[test]
    fn cri5_4058_wait_exec_created_ends_on_purge() {
        for case in 0..3 {
            let (s, f, _) = registered(TaskApiVersion::V2);
            let s = fast_wait(s, 10_000);
            let t0 = std::time::Instant::now();
            let r = std::thread::scope(|sc| {
                let w = sc.spawn(|| s.handle("Wait", &wait_exec_req("e1")));
                std::thread::sleep(std::time::Duration::from_millis(60));
                match case {
                    0 => {
                        s.handle("Delete", &delete_req("c1", "e1")).unwrap();
                    }
                    1 => {
                        stopped(&f, "c1", Some(0));
                        s.handle("Delete", &delete_req("c1", "")).unwrap();
                    }
                    _ => {
                        remove_externally(&f, "c1");
                        assert_eq!(
                            err_code(s.handle("Delete", &delete_req("c1", ""))).0,
                            NOT_FOUND
                        );
                    }
                }
                w.join().unwrap()
            });
            let (code, msg) = err_code(r);
            assert_eq!(
                (code, msg.as_str()),
                (NOT_FOUND, "exec not found"),
                "{case}"
            );
            assert!(t0.elapsed() < std::time::Duration::from_secs(5), "{case}");
        }
    }

    /// 起動役が無い TaskService では、exec_id つきの 4 RPC は UNIMPLEMENTED（何も登録できない）。
    #[test]
    fn cri5_3681_exec_id_without_launcher_unimplemented() {
        let (s, _) = svc(TaskApiVersion::V2, Fake::default());
        running_container(&s, "c1");
        for (m, req) in [
            ("State", state_exec_req("c1", "e1")),
            ("Kill", kill_req("c1", 9, false, "e1")),
            ("Wait", wait_exec_req("e1")),
            ("Delete", delete_req("c1", "e1")),
        ] {
            let (code, msg) = err_code(s.handle(m, &req));
            assert_eq!(
                (code, msg.as_str()),
                (UNIMPL, "exec_id is not supported"),
                "{m}"
            );
        }
    }

    // ---- TaskExit の終了 watcher（#4155・CRI-5・REPAIR-5） ----

    use super::super::publish::testkit::{CapturePublisher, wait_until};
    use super::super::publish::{PublishStage as Stage, TaskEvent as Ev};

    fn svc_pub(fake: Fake) -> (TaskService, Arc<Fake>, Arc<CapturePublisher>) {
        let (s, f) = svc(TaskApiVersion::V2, fake);
        let cap = Arc::new(CapturePublisher::default());
        let s = fast_wait(s, 100).with_event_publisher(cap.clone());
        (s, f, cap)
    }

    // ---- Create・Start・Delete のイベント（#4156・CRI-5・REPAIR-5） ----

    /// CRI-5・#4156: V2 / V3 の両方で、Create → Start → 停止 → Delete が TaskCreate・TaskStart・TaskExit・TaskDelete を
    /// この順に具体値で投入し、Delete の値は `DeleteResponse` と一致する。
    #[test]
    fn cri5_4156_create_start_delete_publish_events_in_order() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let fake = Fake {
                create_pid: Some(4242),
                ..Fake::default()
            };
            let (s, f) = svc(v, fake);
            let cap = Arc::new(CapturePublisher::default());
            let s = fast_wait(s, 100).with_event_publisher(cap.clone());
            let created = s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
            assert_eq!(CreateTaskResponse::decode(&created[..]).unwrap().pid, 4242);
            s.handle("Start", &start_req("c1")).unwrap();
            stopped_with_time(&f, "c1", Some(3), 1_700_000_000_000_000_005);
            assert!(wait_until(std::time::Duration::from_secs(10), || {
                cap.events.lock().unwrap().len() >= 3
            }));
            let out = s.handle("Delete", &delete_req("c1", "")).unwrap();
            let resp = DeleteResponse::decode(&out[..]).unwrap();
            let evs = cap.events.lock().unwrap().clone();
            assert_eq!(evs.len(), 4, "{v:?}: {evs:?}");
            assert_eq!(
                evs[0],
                Ev::Create(TaskCreate {
                    container_id: "c1".into(),
                    bundle: abs("/b"),
                    rootfs: Vec::new(),
                    io: Some(TaskIo::default()),
                    checkpoint: String::new(),
                    pid: 4242,
                })
            );
            assert_eq!(
                evs[1],
                Ev::Start(TaskStart {
                    container_id: "c1".into(),
                    pid: 4242
                })
            );
            assert!(matches!(&evs[2], Ev::Exit(_)));
            assert_eq!(
                evs[3],
                Ev::Delete(TaskDelete {
                    container_id: "c1".into(),
                    pid: resp.pid,
                    exit_status: 3,
                    exited_at: resp.exited_at.clone(),
                    id: String::new(),
                })
            );
            assert_eq!(resp.exit_status, 3);
            assert!(resp.exited_at.is_some());
            assert!(cap.failures.lock().unwrap().is_empty());
        }
    }

    /// CRI-5・#4156: 失敗した Create・Start・Delete はイベントを出さない。
    #[test]
    fn cri5_4156_failed_rpcs_publish_nothing() {
        let (s, _f, cap) = svc_pub(Fake::default());
        // Create の拒否（相対 bundle・terminal・stdio）。
        assert!(s.handle("Create", &create_req("c1", "rel/b")).is_err());
        let term = CreateTaskRequest {
            id: "c1".into(),
            bundle: abs("/b"),
            terminal: true,
            ..Default::default()
        }
        .encode_to_vec();
        assert!(s.handle("Create", &term).is_err());
        let io = CreateTaskRequest {
            id: "c1".into(),
            bundle: abs("/b"),
            stdout: "/x".into(),
            ..Default::default()
        }
        .encode_to_vec();
        assert!(s.handle("Create", &io).is_err());
        // 存在しない ID の Start・Delete。
        assert!(s.handle("Start", &start_req("nope")).is_err());
        assert!(s.handle("Delete", &delete_req("nope", "")).is_err());
        assert!(cap.events.lock().unwrap().is_empty());
        // 実行中のコンテナの Delete は拒否され、増えるのは Create・Start の 2 件だけ。
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        assert!(s.handle("Delete", &delete_req("c1", "")).is_err());
        let evs = cap.events.lock().unwrap().clone();
        assert!(
            matches!(evs.as_slice(), [Ev::Create(_), Ev::Start(_)]),
            "{evs:?}"
        );
    }

    /// CRI-5・#4281: Exec で TaskExecAdded、Start(exec_id) で TaskExecStarted を具体値で送る。Delete(exec_id) は送らない。
    #[test]
    fn cri5_4281_exec_paths_publish_exec_added_and_started() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let (s, _f, l) = svc_exec(v);
            let cap = Arc::new(CapturePublisher::default());
            let s = fast_wait(s, 100).with_event_publisher(cap.clone());
            running_container(&s, "c1");
            s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
            let out = s.handle("Start", &start_exec_req("c1", "e1")).unwrap();
            assert_eq!(StartResponse::decode(&out[..]).unwrap().pid, 5151);
            l.last().exit(Some(0));
            s.handle("Delete", &delete_req("c1", "e1")).unwrap();
            let evs = cap.events.lock().unwrap().clone();
            assert!(matches!(&evs[0], Ev::Create(_)), "{evs:?}");
            assert!(matches!(&evs[1], Ev::Start(_)), "{evs:?}");
            assert_eq!(
                evs[2..],
                [
                    Ev::ExecAdded(TaskExecAdded {
                        container_id: "c1".into(),
                        exec_id: "e1".into()
                    }),
                    Ev::ExecStarted(TaskExecStarted {
                        container_id: "c1".into(),
                        exec_id: "e1".into(),
                        pid: 5151
                    }),
                ]
            );
            assert!(cap.failures.lock().unwrap().is_empty());
        }
    }

    /// CRI-5・#4281: 失敗した Exec・Start(exec_id) はイベントを出さない。
    #[test]
    fn cri5_4281_failed_exec_rpcs_publish_nothing() {
        let (s, _f, l) = svc_exec(TaskApiVersion::V2);
        let cap = Arc::new(CapturePublisher::default());
        let s = fast_wait(s, 100).with_event_publisher(cap.clone());
        // Created（未起動）への Exec は拒否。
        s.handle("Create", &create_req("c0", &abs("/b"))).unwrap();
        assert!(s.handle("Exec", &exec_req("c0", "e1", SPEC)).is_err());
        running_container(&s, "c1");
        // 不正な spec。
        assert!(s.handle("Exec", &exec_req("c1", "e1", "{")).is_err());
        // 未登録の exec_id の Start。
        assert!(s.handle("Start", &start_exec_req("c1", "e1")).is_err());
        // 二重の Exec は 2 回目が失敗し、ExecAdded は 1 件だけ。
        s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap();
        assert!(s.handle("Exec", &exec_req("c1", "e1", SPEC)).is_err());
        // 起動役の失敗。
        *l.fail.lock().unwrap() = true;
        assert!(s.handle("Start", &start_exec_req("c1", "e1")).is_err());
        let evs = cap.events.lock().unwrap().clone();
        let added = evs.iter().filter(|e| matches!(e, Ev::ExecAdded(_))).count();
        let started = evs
            .iter()
            .filter(|e| matches!(e, Ev::ExecStarted(_)))
            .count();
        assert_eq!((added, started), (1, 0), "{evs:?}");
    }

    /// CRI-5・#4155: Start 成功後の watcher が終了を観測し、TaskExit を具体値で 1 回だけ送る。
    /// 同じ ID の watcher は重複しない。
    #[test]
    fn cri5_4155_start_spawns_watcher_publishing_exit_once() {
        let fake = Fake {
            create_pid: Some(4242),
            ..Fake::default()
        };
        let (s, f, cap) = svc_pub(fake);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        s.spawn_exit_watcher("c1", 4242);
        assert_eq!(s.exit_watchers.lock().unwrap().len(), 1);
        std::thread::sleep(std::time::Duration::from_millis(250));
        let head = vec![
            Ev::Create(TaskCreate {
                container_id: "c1".into(),
                bundle: abs("/b"),
                rootfs: Vec::new(),
                io: Some(TaskIo::default()),
                checkpoint: String::new(),
                pid: 4242,
            }),
            Ev::Start(TaskStart {
                container_id: "c1".into(),
                pid: 4242,
            }),
        ];
        assert_eq!(
            *cap.events.lock().unwrap(),
            head,
            "running: Create and Start only"
        );
        stopped_with_time(&f, "c1", Some(3), 1_700_000_000_000_000_005);
        assert!(wait_until(std::time::Duration::from_secs(10), || {
            cap.events.lock().unwrap().len() > 2
        }));
        std::thread::sleep(std::time::Duration::from_millis(300));
        let got = cap.events.lock().unwrap().clone();
        let mut want = head;
        want.push(Ev::Exit(TaskExit {
            container_id: "c1".into(),
            id: "c1".into(),
            pid: 4242,
            exit_status: 3,
            exited_at: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 5,
            }),
        }));
        assert_eq!(got, want);
        assert!(cap.failures.lock().unwrap().is_empty());
        assert!(wait_until(std::time::Duration::from_secs(5), || {
            s.exit_watchers.lock().unwrap().values().all(|e| e.done)
        }));
    }

    /// CRI-5・#4155: 観測前に削除された（`NOT_FOUND`）ときは何も送らず、ログも出さず、watcher の登録も消える。
    #[test]
    fn cri5_4155_watcher_is_silent_when_container_vanishes() {
        let (s, f, cap) = svc_pub(Fake::default());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        f.states.lock().unwrap().remove("c1");
        assert!(wait_until(std::time::Duration::from_secs(5), || {
            s.exit_watchers.lock().unwrap().values().all(|e| e.done)
        }));
        // Exit は出ない（Create・Start だけ。#4156）。
        let got = cap.events.lock().unwrap().clone();
        assert!(
            matches!(got.as_slice(), [Ev::Create(_), Ev::Start(_)]),
            "{got:?}"
        );
        assert!(cap.failures.lock().unwrap().is_empty());
    }

    /// CRI-5・#4155: publisher が無ければ watcher を起こさない。
    #[test]
    fn cri5_4155_no_publisher_no_watcher() {
        let (s, _f) = svc(TaskApiVersion::V2, Fake::default());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        assert!(s.exit_watchers.lock().unwrap().is_empty());
    }

    /// CRI-5・SEC-1・#4155: Stopped の状態の pid が Start 時と食い違えば作り直しとみなして送らず、`instance_mismatch` を 1 件。
    /// pid が無ければ Start 時の pid を使う。
    #[test]
    fn cri5_4155_pid_mismatch_is_not_published() {
        let cap = Arc::new(CapturePublisher::default());
        let (adapter, _f) = {
            let f = Arc::new(Fake::default());
            (RuntimeAdapter::from_runtime(Shared(f.clone())), f)
        };
        let watch = ExitWatch {
            adapter,
            publisher: cap.clone(),
            wait: WaitConfig::default(),
            shutdown: None,
            id: "c1".into(),
            start_pid: 4242,
            generation: 7,
            revoked: Arc::new(AtomicBool::new(false)),
            exit_claim: Arc::new(Mutex::new(false)),
            watchers: Arc::new(Mutex::new(BTreeMap::from([(
                "c1".to_owned(),
                WatchEntry {
                    generation: 7,
                    done: false,
                    revoked: Arc::new(AtomicBool::new(false)),
                    exit_claim: Arc::new(Mutex::new(false)),
                    start_pid: 0,
                },
            )]))),
        };
        let mut st = RuntimeContainerStatus::from(&ContainerStatus::stopped(
            RtId::new("c1").unwrap(),
            Some(0),
        ));
        st.pid = Some(9999);
        watch.publish_exit(&st);
        assert!(cap.events.lock().unwrap().is_empty()); // watch を直接呼ぶのでサービスのイベントは無い
        let fails = cap.failures.lock().unwrap().clone();
        assert_eq!(fails.len(), 1);
        assert_eq!(fails[0].stage, Stage::InstanceMismatch);
        st.pid = None;
        watch.publish_exit(&st);
        let evs = cap.events.lock().unwrap().clone();
        assert_eq!(evs.len(), 1);
        let Ev::Exit(e) = &evs[0] else {
            panic!("{evs:?}")
        };
        assert_eq!((e.pid, e.exit_status, e.exited_at.clone()), (4242, 0, None));
    }

    /// CRI-5・#4155: init の Start はコンテナ単位のゲートを取り、Delete・再作成の最中は watcher を登録しない。
    #[test]
    fn cri5_4155_start_waits_for_container_gate() {
        let fake = Fake {
            create_pid: Some(111),
            ..Fake::default()
        };
        let (s, _f, _cap) = svc_pub(fake);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        let c1 = ContainerId::new("c1").unwrap();
        let gate = s.execs.lock_container(&c1).unwrap();
        std::thread::scope(|scope| {
            let h = scope.spawn(|| s.handle("Start", &start_req("c1")).unwrap());
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(!h.is_finished(), "Start must wait for the container gate");
            assert!(s.exit_watchers.lock().unwrap().is_empty());
            drop(gate);
            h.join().unwrap();
        });
        assert_eq!(s.exit_watchers.lock().unwrap().len(), 1);
    }

    /// CRI-5・#4155: Delete 後に同じ ID で Create・Start し直すと、旧 watcher は取り消されて旧 pid を publish せず、
    /// 新しい watcher が登録される（世代違いの終了は送らない）。
    #[test]
    fn cri5_4155_recreate_after_delete_replaces_watcher() {
        let fake = Fake {
            create_pid: Some(111),
            ..Fake::default()
        };
        let (s, f, cap) = svc_pub(fake);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        let old = s
            .exit_watchers
            .lock()
            .unwrap()
            .get("c1")
            .unwrap()
            .generation;
        // 旧コンテナを停止させずに削除する（force なしで通る状態にするため停止にしてから）。
        stopped_with_time(&f, "c1", Some(0), 1_700_000_000_000_000_000);
        s.handle("Delete", &delete_req("c1", "")).unwrap();
        assert!(s.exit_watchers.lock().unwrap().get("c1").is_none());
        f.preset.lock().unwrap().remove("c1");
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        let new = s
            .exit_watchers
            .lock()
            .unwrap()
            .get("c1")
            .unwrap()
            .generation;
        assert_ne!(old, new);
        std::thread::sleep(std::time::Duration::from_millis(400));
        // 旧世代の watcher の終了後も新しい登録は残る。
        assert_eq!(
            s.exit_watchers
                .lock()
                .unwrap()
                .get("c1")
                .unwrap()
                .generation,
            new
        );
        let evs = cap.events.lock().unwrap().clone();
        assert!(
            evs.iter()
                .all(|e| !matches!(e, Ev::Exit(x) if x.exit_status != 0)),
            "{evs:?}"
        );
        // Create・Start・Delete・Create・Start の並び（Exit は旧世代の取り消しで揺れるため除く。#4156）。
        let kinds: Vec<&str> = evs
            .iter()
            .filter_map(|e| match e {
                Ev::Create(_) => Some("create"),
                Ev::Start(_) => Some("start"),
                Ev::Delete(_) => Some("delete"),
                _ => None,
            })
            .collect();
        assert_eq!(kinds, ["create", "start", "delete", "create", "start"]);
    }

    /// CRI-5・#4224: キュー投入後に Delete・再作成されても、Delete 前に投入済みの TaskExit の述語は有効のまま残る
    /// （#4155 では Delete が無効にして TaskDelete だけが届いたが、#4224 で TaskExit を捨てない仕様へ改めた。残余 (3) の解消）。
    #[test]
    fn cri5_4224_guard_of_exit_queued_before_delete_survives_delete_and_recreate() {
        use super::super::publish::EventGuard;
        #[derive(Default)]
        struct Holding(Mutex<Vec<EventGuard>>);
        impl EventPublisher for Holding {
            fn publish(&self, _: TaskEvent) {}
            fn publish_guarded(&self, _: TaskEvent, g: EventGuard) {
                self.0.lock().unwrap().push(g);
            }
            fn report(&self, _: PublishFailure) {}
        }
        let fake = Fake {
            create_pid: Some(111),
            ..Fake::default()
        };
        let h = Arc::new(Holding::default());
        let (s, f) = svc(TaskApiVersion::V2, fake);
        let s = fast_wait(s, 100).with_event_publisher(h.clone());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        stopped_with_time(&f, "c1", Some(0), 1_700_000_000_000_000_000);
        assert!(wait_until(std::time::Duration::from_secs(5), || !h
            .0
            .lock()
            .unwrap()
            .is_empty()));
        let guard = h.0.lock().unwrap()[0].clone();
        assert!(guard());
        s.handle("Delete", &delete_req("c1", "")).unwrap();
        assert!(guard(), "Delete must not revoke an already queued TaskExit");
        f.preset.lock().unwrap().remove("c1");
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        // Delete が登録を外し済みなので、再作成・再 Start は旧世代の述語に触れない。
        assert!(guard());
    }

    /// CRI-5・#4224: Wait の直後（watcher の照会間隔より短い間隔）に Delete しても、TaskExit が TaskDelete より先にちょうど 1 件届く。
    /// V2 / V3 の両方。Exit は watcher と同じ規則（pid は Start 時の値）、Delete は `DeleteResponse` と一致する。
    #[test]
    fn cri5_4224_wait_then_delete_publishes_exit_before_delete() {
        for v in [TaskApiVersion::V2, TaskApiVersion::V3] {
            let fake = Fake {
                create_pid: Some(4242),
                ..Fake::default()
            };
            let (s, f) = svc(v, fake);
            let cap = Arc::new(CapturePublisher::default());
            let s = s
                .with_wait_config(
                    WaitConfig::new(
                        std::time::Duration::from_secs(30),
                        std::time::Duration::from_secs(5),
                    )
                    .unwrap(),
                )
                .with_event_publisher(cap.clone());
            s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
            s.handle("Start", &start_req("c1")).unwrap();
            // watcher の初回照会（running）を済ませ、次の照会は 5 秒後にする。
            std::thread::sleep(std::time::Duration::from_millis(300));
            stopped_with_time(&f, "c1", Some(3), 1_700_000_000_000_000_005);
            let w = s.handle("Wait", &wait_req("c1", "")).unwrap();
            assert_eq!(WaitResponse::decode(&w[..]).unwrap().exit_status, 3);
            let d = s.handle("Delete", &delete_req("c1", "")).unwrap();
            let d = DeleteResponse::decode(&d[..]).unwrap();
            let ts = Timestamp {
                seconds: 1_700_000_000,
                nanos: 5,
            };
            assert_eq!(
                (d.pid, d.exit_status, d.exited_at.clone()),
                (0, 3, Some(ts.clone())) // 停止後の状態に pid は無い（既存の Delete の規則）
            );
            std::thread::sleep(std::time::Duration::from_millis(500));
            let evs = cap.events.lock().unwrap().clone();
            assert_eq!(evs.len(), 4, "{evs:?}");
            assert_eq!(
                evs[2],
                Ev::Exit(TaskExit {
                    container_id: "c1".into(),
                    id: "c1".into(),
                    pid: 4242,
                    exit_status: 3,
                    exited_at: Some(ts.clone()),
                })
            );
            assert_eq!(
                evs[3],
                Ev::Delete(TaskDelete {
                    container_id: "c1".into(),
                    pid: 0,
                    exit_status: 3,
                    exited_at: Some(ts),
                    id: String::new(),
                })
            );
            assert!(cap.failures.lock().unwrap().is_empty());
            assert!(s.exit_watchers.lock().unwrap().get("c1").is_none());
        }
    }

    /// CRI-5・#4224: watcher が先に TaskExit を送った後に Wait・Delete しても、TaskExit は重複せず 1 件だけ。
    #[test]
    fn cri5_4224_watcher_first_then_delete_publishes_exit_once() {
        let fake = Fake {
            create_pid: Some(4242),
            ..Fake::default()
        };
        let (s, f, cap) = svc_pub(fake);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        stopped_with_time(&f, "c1", Some(3), 1_700_000_000_000_000_005);
        assert!(wait_until(std::time::Duration::from_secs(10), || {
            cap.events.lock().unwrap().len() > 2
        }));
        s.handle("Wait", &wait_req("c1", "")).unwrap();
        s.handle("Delete", &delete_req("c1", "")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let evs = cap.events.lock().unwrap().clone();
        let kinds: Vec<&str> = evs
            .iter()
            .map(|e| match e {
                Ev::Create(_) => "create",
                Ev::Start(_) => "start",
                Ev::Exit(_) => "exit",
                Ev::Delete(_) => "delete",
                Ev::ExecAdded(_) => "exec-added",
                Ev::ExecStarted(_) => "exec-started",
            })
            .collect();
        assert_eq!(kinds, ["create", "start", "exit", "delete"], "{evs:?}");
        assert!(cap.failures.lock().unwrap().is_empty());
    }

    /// CRI-5・#4224: watcher が送信権（`exit_claim`）を保持している間、Delete はその enqueue の完了を待ち、
    /// 既に送信済みなら TaskExit を足さず TaskDelete だけを投入する。
    #[test]
    fn cri5_4224_delete_waits_for_watcher_claim() {
        let fake = Fake {
            create_pid: Some(4242),
            ..Fake::default()
        };
        let (s, f, cap) = svc_pub(fake);
        let s = Arc::new(s);
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        let claim = Arc::clone(
            &s.exit_watchers
                .lock()
                .unwrap()
                .get("c1")
                .unwrap()
                .exit_claim,
        );
        let mut held = claim.lock().unwrap();
        stopped_with_time(&f, "c1", Some(0), 1_700_000_000_000_000_000);
        let s2 = Arc::clone(&s);
        let h = std::thread::spawn(move || s2.handle("Delete", &delete_req("c1", "")));
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!h.is_finished(), "Delete must wait for the claim holder");
        *held = true;
        drop(held);
        h.join().unwrap().unwrap();
        let evs = cap.events.lock().unwrap().clone();
        assert_eq!(evs.len(), 3, "{evs:?}");
        assert!(matches!(evs[2], Ev::Delete(_)), "{evs:?}");
    }

    /// CRI-5・#4155: Delete を経ずに外で消えた ID を Create し直すと、旧 watcher の印が先に立って登録が外れ、
    /// キュー済みの旧 TaskExit の述語が無効になる。再 Start は新しい世代で watcher を起こす。
    #[test]
    fn cri5_4155_create_revokes_stale_watcher_and_start_respawns() {
        use super::super::publish::EventGuard;
        #[derive(Default)]
        struct Holding(Mutex<Vec<EventGuard>>);
        impl EventPublisher for Holding {
            fn publish(&self, _: TaskEvent) {}
            fn publish_guarded(&self, _: TaskEvent, g: EventGuard) {
                self.0.lock().unwrap().push(g);
            }
            fn report(&self, _: PublishFailure) {}
        }
        let fake = Fake {
            create_pid: Some(111),
            ..Fake::default()
        };
        let h = Arc::new(Holding::default());
        let (s, f) = svc(TaskApiVersion::V2, fake);
        let s = fast_wait(s, 100).with_event_publisher(h.clone());
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        s.handle("Start", &start_req("c1")).unwrap();
        let old = s
            .exit_watchers
            .lock()
            .unwrap()
            .get("c1")
            .unwrap()
            .generation;
        stopped_with_time(&f, "c1", Some(0), 1_700_000_000_000_000_000);
        assert!(wait_until(std::time::Duration::from_secs(5), || !h
            .0
            .lock()
            .unwrap()
            .is_empty()));
        let guard = h.0.lock().unwrap()[0].clone();
        assert!(guard());
        // Delete を経ずにコンテナが外で消え、同じ ID が再作成される。
        remove_externally(&f, "c1");
        s.handle("Create", &create_req("c1", &abs("/b"))).unwrap();
        assert!(!guard());
        assert!(s.exit_watchers.lock().unwrap().get("c1").is_none());
        s.handle("Start", &start_req("c1")).unwrap();
        let new = s
            .exit_watchers
            .lock()
            .unwrap()
            .get("c1")
            .unwrap()
            .generation;
        assert_ne!(old, new);
        assert!(!guard());
    }

    /// REPAIR-5・#4155: watcher の数の上限を超えたら起こさず、`watch_limit` を 1 件記録する（Start の応答は変えない）。
    #[test]
    fn repair5_4155_watcher_limit() {
        let (s, _f, cap) = svc_pub(Fake::default());
        {
            let mut set = s.exit_watchers.lock().unwrap();
            for i in 0..MAX_EXIT_WATCHERS {
                set.insert(
                    format!("w{i}"),
                    WatchEntry {
                        generation: 0,
                        done: false,
                        revoked: Arc::new(AtomicBool::new(false)),
                        exit_claim: Arc::new(Mutex::new(false)),
                        start_pid: 0,
                    },
                );
            }
        }
        s.spawn_exit_watcher("extra", 1);
        let fails = cap.failures.lock().unwrap().clone();
        assert_eq!(fails.len(), 1);
        assert_eq!(fails[0].stage, Stage::WatchLimit);
        assert_eq!(s.exit_watchers.lock().unwrap().len(), MAX_EXIT_WATCHERS);
    }

    /// REPAIR-5・CRI-5・#4155: publish バイナリが非 0 終了・期限超過でも、Start・State・Wait・Delete の応答は
    /// publisher 無しと同じバイト列で、ログの失敗は 4 件（create・start・exit・delete の順。#4156）。
    #[cfg(unix)]
    #[test]
    fn repair5_4155_rpc_responses_unchanged_when_publish_fails() {
        use super::super::bootstrap::{PublishBinary, ServeContext, ShimIdentifier};
        use super::super::publish::testkit::{
            CaptureLog, failing_body, make_script, sleeping_body,
        };
        use super::super::publish::{PublishConfig, exec_publisher_for_with};
        use crate::test_root;

        let run = |s: &TaskService, f: &Fake| -> Vec<Vec<u8>> {
            let out = vec![
                s.handle("Create", &create_req("c1", &abs("/b"))).unwrap(),
                s.handle("Start", &start_req("c1")).unwrap(),
            ];
            stopped_with_time(f, "c1", Some(3), 1_700_000_000_000_000_005);
            out
        };
        let tail = |s: &TaskService| -> Vec<Vec<u8>> {
            vec![
                s.handle(
                    "State",
                    &WireState {
                        id: "c1".into(),
                        exec_id: String::new(),
                    }
                    .encode_to_vec(),
                )
                .unwrap(),
                s.handle("Wait", &wait_req("c1", "")).unwrap(),
                s.handle("Delete", &delete_req("c1", "")).unwrap(),
            ]
        };
        for (name, deadline_stage) in [("fail", Stage::ExitStatus), ("sleep", Stage::Deadline)] {
            let dir = test_root::test_root("pubsvc", name);
            let body = if name == "fail" {
                failing_body()
            } else {
                sleeping_body(&dir)
            };
            let bin = make_script(&dir, "fake", &body);
            let log = Arc::new(CaptureLog::default());
            let ctx = ServeContext::new(ShutdownSignal::new(), None)
                .with_origin(
                    Some(ShimIdentifier::parse("default").unwrap()),
                    Some("/run/x.sock".into()),
                )
                .with_publish_binary(Some(PublishBinary::verify(&bin).unwrap()));
            let publisher = exec_publisher_for_with(
                &ctx,
                PublishConfig::new(std::time::Duration::from_millis(400)).unwrap(),
                log.clone(),
            )
            .unwrap();

            let (with_pub, f1) = svc(TaskApiVersion::V2, Fake::default());
            let with_pub = fast_wait(with_pub, 100).with_event_publisher(publisher);
            let mut a = run(&with_pub, &f1);
            // Create・Start・Exit の 3 件の publish が失敗してから残りを呼ぶ（先に Delete すると
            // 世代 guard が Exit を捨てて件数が揺れる。#4156）。
            assert!(wait_until(std::time::Duration::from_secs(20), || {
                log.0.lock().unwrap().len() >= 3
            }));
            a.extend(tail(&with_pub));

            let (plain, f2) = svc(TaskApiVersion::V2, Fake::default());
            let plain = fast_wait(plain, 100);
            let mut b = run(&plain, &f2);
            b.extend(tail(&plain));

            assert_eq!(a, b, "{name}");
            assert!(wait_until(std::time::Duration::from_secs(20), || {
                log.0.lock().unwrap().len() >= 4
            }));
            let got = log.0.lock().unwrap().clone();
            assert_eq!(got.len(), 4, "{name}: {got:?}");
            let topics: Vec<_> = got.iter().map(|f| f.topic).collect();
            assert_eq!(
                topics,
                [
                    Some("/tasks/create"),
                    Some("/tasks/start"),
                    Some("/tasks/exit"),
                    Some("/tasks/delete")
                ],
                "{name}"
            );
            assert!(got.iter().all(|f| f.stage == deadline_stage), "{name}");
        }
    }

    /// REPAIR-5・REPAIR-4・CRI-5・#4281: exec の 2 種の publish が失敗・期限切れでも Exec・Start(exec_id)・State(exec_id) の応答は
    /// publisher 無しと同じバイト列で、ログの失敗は 4 件（create・start・exec-added・exec-started の順）。ID はログに出ない。
    #[cfg(unix)]
    #[test]
    fn repair5_4281_exec_rpc_responses_unchanged_when_publish_fails() {
        use super::super::bootstrap::{PublishBinary, ServeContext, ShimIdentifier};
        use super::super::publish::testkit::{
            CaptureLog, failing_body, make_script, sleeping_body,
        };
        use super::super::publish::{PublishConfig, exec_publisher_for_with};
        use crate::test_root;

        let run = |s: &TaskService| -> Vec<Vec<u8>> {
            running_container(s, "c1");
            vec![
                s.handle("Exec", &exec_req("c1", "e1", SPEC)).unwrap(),
                s.handle("Start", &start_exec_req("c1", "e1")).unwrap(),
                s.handle(
                    "State",
                    &WireState {
                        id: "c1".into(),
                        exec_id: "e1".into(),
                    }
                    .encode_to_vec(),
                )
                .unwrap(),
            ]
        };
        for (name, deadline_stage) in [("fail", Stage::ExitStatus), ("sleep", Stage::Deadline)] {
            let dir = test_root::test_root("pubsvc", &format!("exec-{name}"));
            let body = if name == "fail" {
                failing_body()
            } else {
                sleeping_body(&dir)
            };
            let bin = make_script(&dir, "fake", &body);
            let log = Arc::new(CaptureLog::default());
            let ctx = ServeContext::new(ShutdownSignal::new(), None)
                .with_origin(
                    Some(ShimIdentifier::parse("default").unwrap()),
                    Some("/run/x.sock".into()),
                )
                .with_publish_binary(Some(PublishBinary::verify(&bin).unwrap()));
            let publisher = exec_publisher_for_with(
                &ctx,
                PublishConfig::new(std::time::Duration::from_millis(400)).unwrap(),
                log.clone(),
            )
            .unwrap();

            let (with_pub, _f1, _l1) = svc_exec(TaskApiVersion::V2);
            let with_pub = fast_wait(with_pub, 100).with_event_publisher(publisher);
            let a = run(&with_pub);
            let (plain, _f2, _l2) = svc_exec(TaskApiVersion::V2);
            let plain = fast_wait(plain, 100);
            let b = run(&plain);
            assert_eq!(a, b, "{name}");
            assert!(wait_until(std::time::Duration::from_secs(20), || {
                log.0.lock().unwrap().len() >= 4
            }));
            let got = log.0.lock().unwrap().clone();
            assert_eq!(got.len(), 4, "{name}: {got:?}");
            let topics: Vec<_> = got.iter().map(|f| f.topic).collect();
            assert_eq!(
                topics,
                [
                    Some("/tasks/create"),
                    Some("/tasks/start"),
                    Some("/tasks/exec-added"),
                    Some("/tasks/exec-started")
                ],
                "{name}"
            );
            assert!(got.iter().all(|f| f.stage == deadline_stage), "{name}");
            for f in &got {
                let line = f.to_json_line();
                assert!(!line.contains("c1") && !line.contains("e1"), "{line}");
            }
        }
    }
}
