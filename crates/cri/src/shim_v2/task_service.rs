//! containerd Task API の Create / Start / Delete / Exec / Wait / State / Kill / Shutdown を `ContainerRuntime` へつなぐサービス（CRI-5・ERR-3・TASK-62.2・TASK-62.3.1・TASK-62.3.2・TASK-62.4・TASK-62.7.2・MS-7）。
//!
//! [`ServiceRegistry::dispatch`](super::service::ServiceRegistry::dispatch) から呼ばれる同期ハンドラで、
//! 接続ごとのスレッド上で動く。コンテナの作成・起動は [`RuntimeAdapter`] 経由で行い、core の具象型には
//! 依存しない（CRI-7・PLUG-1）。ランタイム側の失敗は `crate::error` の表（ERR-3）で gRPC コードへ写し、
//! ttrpc の `Response.status` に載せる。
//!
//! 未対応の欄は黙って無視せず `UNIMPLEMENTED` で拒否する（fail-closed。REPAIR-3）:
//! `rootfs`・`options`・`terminal`・`stdin`/`stdout`/`stderr`・`checkpoint`/`parent_checkpoint`・`exec_id`（Delete）。
//! `Exec` と `Start(exec_id)` は [`TaskExecLauncher`] が差し込まれたときだけ動き、無ければ `UNIMPLEMENTED`（TASK-62.4）。
//! `rootfs` と `options`（型に持たない）は repeated / 入れ子の確保を避けるため、復号前に走査して拒否する。
//!
//! 検査の順序（Create）: 復号前の走査（rootfs → options）→ 復号 → id → bundle → terminal → stdio → checkpoint。
//! 検査の順序（Exec）: 起動役の有無 → 復号 → id → exec_id → terminal / stdio → spec（type URL・上限・JSON・各欄）
//! → コンテナが Running か → 登録（重複・上限）。起動は `Start(exec_id)` が行う（containerd の意味論）。
//!
//! Delete の検査の順序: 復号（repeated / `Any` の欄が無いので走査は不要）→ exec_id → id（アダプタ）。
//! 手順は state（削除前の pid・終了コードを採る）→ `remove(force=false)`。containerd の Delete に force は
//! 無く、実行中のコンテナは core の `FailedPrecondition`（9）で拒否される。応答の `exit_status` は
//! 終了コード（不明は 255）、`exited_at` は停止済みで core が記録した終了検知時刻（未記録は未設定。#3682）。
//! 既知の制約: state と remove の間に状態が変わりうる（その場合の `exit_status` は不正確）。pid のある
//! `Created` は core の契約で force=false では削除できない。plugin 越しでは最悪 2 回分の待ちになる。
//!
//! Wait（TASK-62.3.2）の検査の順序: 復号 → exec_id（空以外は `UNIMPLEMENTED`）→ id（アダプタの state）。
//! `RuntimeAdapter::wait_exit`（core の `ContainerRuntime::wait_exit`）で `Stopped` を待ち、終了コードを返す。期限は
//! `min(timeout_nano, WaitConfig::timeout)`（`timeout_nano` が 0 なら `WaitConfig` だけ）で、超えたら `DEADLINE_EXCEEDED`（4）。負の `timeout_nano` は runtime を呼ばずに 4。
//! 未起動の `Created` は終了扱いにしない。照会のエラー（待ちの途中の削除による NOT_FOUND を含む）は再試行せず返す。
//! サーバーは要求を接続内で並行 dispatch するため待ちは他の RPC を止めず、停止・切断の通知を受けた Wait は期限前に取り消される。
//!
//! Connect（TASK-62.6）: `id` をアダプタの state で確かめ、`shim_pid`（自プロセス）と `task_pid`（無ければ 0）を返す。`version` は空。
//!
//! State / Kill / Shutdown（TASK-62.7.2）:
//! - State: `exec_id` 非空は `UNIMPLEMENTED`。状態は Creating / Created → CREATED、Running → RUNNING、Stopped → STOPPED、
//!   それ以外 → UNKNOWN。`exit_status` は STOPPED のときだけ終了コード（不明は 255）。`exited_at` は STOPPED で core が記録した終了検知時刻だけ
//!   （他の状態・未記録は未設定。値は壁時計で、誤差は wait の刻み程度。#3682）。`bundle`・stdio・`terminal` は
//!   shim が持たないため空・未設定（REPAIR-3）。
//! - Kill: `exec_id` 非空と `all = true` は `UNIMPLEMENTED`（core の kill は init プロセスにしか送れず、cgroup 全体へ送る経路が
//!   無い。containerd の猶予切れ SIGKILL〔`WithKillAll`〕は未結線）。`signal` は 1..=64 以外を `INVALID_ARGUMENT` にする。
//!   停止済みは runc shim と同じく `NOT_FOUND`（"process already finished"）。state と kill の間の競合は core の応答をそのまま返す。
//! - Shutdown: [`ShutdownSignal`] が差し込まれているときだけ動く。`now = true` かコンテナが残っていない（state が `NOT_FOUND`）とき
//!   終了を要求し、コンテナが残っていれば何もせず成功を返す（runc shim と同じ）。state の他のエラーは終了せずに返す（fail-closed）。冪等。
//!
//! 期限（REPAIR-5）: Wait は上記の期限を持つ。他のメソッドは `ContainerRuntime` の契約で実装側が期限を持ち、
//! shim は追加の期限を設けない。socket の権限・peer UID の照合は #803（TASK-62.7）の範囲。

use std::collections::BTreeSet;
use std::num::NonZeroU32;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use prost::Message;

use super::exec::{ExecId, ExecRegistry, TaskExecLauncher, parse_process_spec};
use super::message::{RpcStatus, count_top_level_field};
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
use fandhe_container_core::traits::ContainerId;

/// `bundle` の最大バイト数（PATH_MAX 相当）。
const BUNDLE_MAX_LEN: usize = 4096;
/// `CreateTaskRequest.rootfs` のフィールド番号。
const FIELD_ROOTFS: u64 = 3;
/// `CreateTaskRequest.options`（`Any`）のフィールド番号。型には持たない。
const FIELD_OPTIONS: u64 = 10;

/// 終了コードが不明なときの `exit_status`。containerd クライアントの `UnknownExitStatus` に倣う。
const UNKNOWN_EXIT_STATUS: u32 = 255;
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
    execs: ExecRegistry,
    wait_config: WaitConfig,
    shutdown: Option<ShutdownSignal>,
    /// この shim の Create で作ったコンテナ ID。Shutdown が「残っているか」を全 ID で判定し、
    /// Create と Shutdown の判定を排他する（ロックは Create / 判定の間だけ持つ）。
    ///
    /// v2 と v3 を同じ shim に登録するときは [`TaskService::with_shared_created`] で共有する。
    created: Arc<Mutex<BTreeSet<String>>>,
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
            execs: ExecRegistry::new(),
            wait_config: WaitConfig::default(),
            shutdown: None,
            created: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }

    /// Shutdown RPC の終了要求の送り先を差し込む。無ければ `Shutdown` は `UNIMPLEMENTED`（TASK-62.7.2）。
    pub fn with_shutdown(mut self, signal: ShutdownSignal) -> Self {
        self.shutdown = Some(signal);
        self
    }

    /// 作成済み ID の記録と判定用ロックを `other` と共有する。同じ shim に v2・v3 を登録するとき、
    /// Create と Shutdown の判定をサービスをまたいで揃えるために使う（TASK-62.7.2）。
    pub fn with_shared_created(mut self, other: &TaskService) -> Self {
        self.created = Arc::clone(&other.created);
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
            return Err(unsupported("exec_id is not supported"));
        }
        let st = self.adapter.state(&req.id).map_err(|e| to_status(&e))?;
        let (status, exit_status) = match st.lifecycle {
            RuntimeLifecycle::Creating | RuntimeLifecycle::Created => (TaskStatus::Created, 0),
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

    /// `Kill`: init プロセスへシグナルを送る（TASK-62.7.2）。
    fn kill(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = KillRequest::decode(payload).map_err(|_| decode_failure())?;
        if !req.exec_id.is_empty() {
            return Err(unsupported("exec_id is not supported"));
        }
        if req.all {
            return Err(unsupported("kill all is not supported"));
        }
        // 状態の照会より前に検証する（停止済み・不在の ID でも範囲外は INVALID_ARGUMENT）。
        let signal = u8::try_from(req.signal)
            .ok()
            .filter(|n| (1..=64).contains(n))
            .ok_or_else(|| {
                RpcStatus::from_code(
                    CriErrorCode::InvalidArgument,
                    "signal number must be in 1..=64",
                )
            })?;
        let st = self.adapter.state(&req.id).map_err(|e| to_status(&e))?;
        if st.lifecycle == RuntimeLifecycle::Stopped {
            return Err(RpcStatus::from_code(
                CriErrorCode::NotFound,
                "process already finished",
            ));
        }
        self.adapter
            .kill(&req.id, signal)
            .map_err(|e| to_status(&e))?;
        Ok(Vec::new())
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
        let _gate = self
            .execs
            .lock_container(&container)
            .map_err(|e| to_status(&e))?;
        let status = self
            .adapter
            .state(container.as_str())
            .map_err(|e| to_status(&e))?;
        if status.lifecycle != RuntimeLifecycle::Running {
            return Err(to_status(&CriError::failed_precondition(
                "container is not running",
            )));
        }
        self.execs
            .register(&container, &exec_id, spec)
            .map_err(|e| to_status(&e))?;
        Ok(Vec::new())
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
        let status = self
            .adapter
            .state(container.as_str())
            .map_err(|e| to_status(&e))?;
        if status.lifecycle != RuntimeLifecycle::Running {
            return Err(to_status(&CriError::failed_precondition(
                "container is not running",
            )));
        }
        let ticket = self
            .execs
            .begin_start(&container, &exec_id)
            .map_err(|e| to_status(&e))?;
        let result = launcher.launch(&container, &exec_id, &ticket.spec);
        self.execs
            .finish_start(&container, &exec_id, &ticket, result.is_ok())
            .map_err(|e| to_status(&e))?;
        let pid = result.map_err(|e| to_status(&e))?;
        Ok(StartResponse {
            pid: pid.map_or(0, NonZeroU32::get),
        }
        .encode_to_vec())
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
        Ok(CreateTaskResponse {
            pid: status.pid.unwrap_or(0),
        }
        .encode_to_vec())
    }

    fn start(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = StartRequest::decode(payload).map_err(|_| decode_failure())?;
        if !req.exec_id.is_empty() {
            return self.start_exec(&req);
        }
        let status = self.adapter.start(&req.id).map_err(|e| to_status(&e))?;
        Ok(StartResponse {
            pid: status.pid.unwrap_or(0),
        }
        .encode_to_vec())
    }

    fn delete(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = DeleteRequest::decode(payload).map_err(|_| decode_failure())?;
        if !req.exec_id.is_empty() {
            return Err(unsupported("exec_id is not supported"));
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
        let before = self.adapter.state(&req.id).map_err(|e| to_status(&e))?;
        self.adapter
            .remove(&req.id, false)
            .map_err(|e| to_status(&e))?;
        created.remove(&req.id);
        drop(created);
        // 削除成功後に旧コンテナの exec 登録を除去する（同じ ID の再作成で引き継がない。CRI-5）。
        if let Some(container) = &container {
            self.execs
                .purge_container(container)
                .map_err(|e| to_status(&e))?;
        }
        Ok(DeleteResponse {
            pid: before.pid.unwrap_or(0),
            exit_status: exit_status_of(&before),
            exited_at: exited_at_of(&before),
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
            return Err(unsupported("exec_id is not supported"));
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

/// 停止済みの状態から `exited_at` を決める。Stopped 以外・未記録・負値は未設定（値を捏造しない。CRI-5・#3682）。
fn exited_at_of(status: &RuntimeContainerStatus) -> Option<Timestamp> {
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
    status
        .exit_code
        .and_then(|c| u32::try_from(c).ok())
        .unwrap_or(UNKNOWN_EXIT_STATUS)
}

/// 削除前の状態から `exit_status` を決める。未起動の Created は 0、終了コード不明・負値は 255。
fn exit_status_of(status: &RuntimeContainerStatus) -> u32 {
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
        ContainerId as RtId, ContainerRuntime, ContainerState, ContainerStatus, CreateRequest,
        DeleteRequest as RtDelete, DeleteResponse as RtDeleteResponse, ErrorCode, KillRequest,
        StartRequest as RtStart, StateRequest, StopRequest, TraitError,
    };

    use super::super::exec::{ExecProcessSpec, PROCESS_TYPE_URL};
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
            self.0
                .calls
                .lock()
                .unwrap()
                .push(format!("kill {id} {}", r.signal().as_u8()));
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
            if let Some(p) = self.0.preset.lock().unwrap().get(&id) {
                return Ok(p.clone());
            }
            match self.0.states.lock().unwrap().get(&id) {
                None => Err(TraitError::new(ErrorCode::NotFound, "none")),
                Some(ContainerState::Running) => Ok(ContainerStatus::running(
                    r.id().clone(),
                    NonZeroU32::new(4242),
                )),
                Some(_) => Ok(ContainerStatus::created(r.id().clone(), None)),
            }
        }
    }

    /// 引数を記録する偽の起動役。
    #[derive(Default)]
    struct FakeLauncher {
        launched: Mutex<Vec<(String, String, ExecProcessSpec)>>,
        fail: Mutex<bool>,
    }

    impl TaskExecLauncher for FakeLauncher {
        fn launch(
            &self,
            c: &ContainerId,
            e: &ExecId,
            s: &ExecProcessSpec,
        ) -> Result<Option<NonZeroU32>, CriError> {
            if *self.fail.lock().unwrap() {
                return Err(CriError::unavailable("launch failed"));
            }
            self.launched
                .lock()
                .unwrap()
                .push((c.as_str().into(), e.as_str().into(), s.clone()));
            Ok(NonZeroU32::new(5151))
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
            ) -> Result<Option<NonZeroU32>, CriError> {
                // 起動中に init が停止した場面を作ってから Delete を走らせる。
                stopped(&self.fake, "c1", Some(0));
                self.entered.lock().unwrap().send(()).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(300));
                self.events.lock().unwrap().push("launch-end");
                Ok(NonZeroU32::new(5151))
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
        let (code, msg) = err_code(s.handle("Kill", &kill_req("c1", 9, true, "")));
        assert_eq!((code, msg.as_str()), (UNIMPL, "kill all is not supported"));
        let (code, msg) = err_code(s.handle("Kill", &kill_req("c1", 9, false, "e")));
        assert_eq!((code, msg.as_str()), (UNIMPL, "exec_id is not supported"));
        assert_eq!(
            f.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.starts_with("kill"))
                .count(),
            3
        );
        assert_eq!(
            err_code(s.handle("Kill", &kill_req("zz", 9, false, ""))).0,
            NOT_FOUND
        );
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
}
