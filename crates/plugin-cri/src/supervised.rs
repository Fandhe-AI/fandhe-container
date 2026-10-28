//! supervisor 経由の `start`・`kill`・`stop`（Linux 専用。CRI-2・PLUG-1・SUP-1・SUP-9・CORE-1・TASK-114 追補・#2434）。
//!
//! [`crate::adapter::CoreLifecycleRuntime`] の `ContainerRuntime::{start, kill, stop}` が呼ぶ実装部で、CLI の `start` /
//! `stop` と同じ本番経路を plugin から使えるようにする。実処理は `fandhe-container-supervisor` の公開 API にある
//! （`start_client`・`control::production_signaler` / `production_stop_signaler`。CLI の private 実装から移設した共有物。REPAIR-1）。
//! 常駐デーモンは作らず（CORE-1）、コンテナごとの supervisor を委譲 scope で起動し、制御チャネル経由でシグナルを届ける。
//!
//! # 契約
//! - `start`: supervisor を `systemd-run --user --scope` で起動し、結果の 1 行を期限つきで受ける（期限は CLI と同じ
//!   `start_contract::cli_receive_deadline`。REPAIR-5）。報告された pid を状態ストアの記録と照合し、Running で pid が
//!   一致するか、直後に終了して Stopped が記録済みのときだけ成功とする。それ以外は `INTERNAL` で fail-closed。
//! - `kill`: 意図なしの `ProcessSignaler` で core の `oci_runtime::kill` を呼ぶ（終了は待たない）。
//! - `stop`: `StopRequest::signal`（既定 SIGTERM。CRI の stop_signal。#2668）を stop の意図つきで送り（SUP-9。supervisor が意図を記録してから届けるので、`always` /
//!   `on-failure` / `unless-stopped` でも再起動されない）、`grace` まで Stopped への遷移を状態ストアで待ち、超えたら
//!   SIGKILL を送って最長 [`STOP_KILL_WAIT`] 待つ。待っても Stopped にならなければ `TIMEOUT`。
//!   上限は `StateStore` の呼び出し 1 回を `STATE_LOCK_TIMEOUT`（期限つきのポーリングは within + `STATE_LOCK_TIMEOUT`）、
//!   signaler の呼び出し 1 回を `KillTimeout` + `LAUNCHER_REPLY_GRACE` と数えて `grace + 42 秒`
//!   （入口の読み取り 5 + 送信 11 + 読み取り 5 + 送信 11 + 待ち 10。REPAIR-5・#3143）。
//! - `stop_within`: force delete 用。stop 全体に予算を持たせ、各段を「残り ≥ その段の最悪の所要」のときだけ始める。
//!   始められなければ固定文言の `TIMEOUT` で止め（状態は消さない。再試行で回収される）、`delete` 全体の最悪を
//!   [`FORCE_DELETE_STOP_BUDGET`] で頭打ちにする（#3143）。
//! - `state.json` の pid へ生の `kill(2)` を送る縮退は持たない（PID 再利用で無関係なプロセスを止めない。SEC-1・CORE-1）。
//!   状態ストアが `host_state_root()` を持たなければ signaler は `UNIMPLEMENTED` で失敗する。
//!
//! # 子プロセスの回収（D7）
//! CLI は `start` の直後に終了するが、plugin-cri は常駐するため、起動した supervisor（実体は systemd-run の子）が
//! plugin の子のまま残り、終了後にゾンビになる。spawn した `Child` を上限つき（[`MAX_TRACKED_SUPERVISORS`]）の一覧に
//! 保持し、`start`・`kill`・`stop`・`delete` の入口で `try_wait` により終了済みのものだけを回収する。`kill` も `wait`
//! もしない（supervisor は plugin より長く生きる前提。CORE-1・SUP-5）。上限に達して空きが無いときは起動せず `RESOURCE_EXHAUSTED`（CRI では gRPC `RESOURCE_EXHAUSTED`。CRI-2・#2609）で失敗する。
//!
//! # 未実装・簡易実装（REPAIR-3）
//! - supervisor の実行ファイルは plugin-cri の実体パス（`current_exe()`）と同じディレクトリの固定名から解決する
//!   （`PATH` 探索・環境変数・引数による上書きは作らない。`docs/setup/linux.md`）。
//! - 権限モデルは CLI と同じ共有クライアントの規則: 実体の隣に信頼できるランチャーがあればランチャー経由、無ければ直接経路。
//!   uid 0 は spawn の前に `UNIMPLEMENTED`（#2442・#2241）。
//! - `XDG_RUNTIME_DIR` が plugin の環境に必要（将来の plugin proxy が環境を空にすると `FAILED_PRECONDITION`。#1869）。
//! - 実機での通し（委譲 scope 内での plugin-cri → supervisor → delete）は未実施（#850・#2062）。

use std::num::NonZeroU32;
use std::path::Path;
use std::process::Child;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    KillTimeout, LAUNCHER_REPLY_GRACE, LifecycleOp, OciRuntimeError, ProcessSignaler, kill,
};
use fandhe_container_core::state_store::STATE_LOCK_TIMEOUT;
use fandhe_container_core::traits::{
    ContainerId, ContainerLogPath, ContainerState, ContainerStatus, ErrorCode, GetStateRequest,
    KillRequest, Signal, StateStore, StopRequest, TraitError,
};
use fandhe_container_supervisor::control::{production_signaler, production_stop_signaler};
use fandhe_container_supervisor::start_client::{
    SupervisorLaunch, production_deadline, start_with_cri_log,
};

/// 追跡する supervisor の子プロセスの上限。超えたら（回収しても空きが無ければ）新しい起動を拒否する（無制限の蓄積を防ぐ）。
pub const MAX_TRACKED_SUPERVISORS: usize = 1024;
/// SIGKILL を送った後に Stopped への遷移を待つ上限（REPAIR-5）。
pub const STOP_KILL_WAIT: Duration = Duration::from_secs(5);
/// force delete の stop 全体に持たせる予算（REPAIR-5・CRI-2・#3143）。
///
/// `PLUGIN_FORCE_DELETE_DEADLINE`（47 秒）から、stop の前の状態の読み取り 1 回（`STATE_LOCK_TIMEOUT` 5 秒）と core の
/// delete の最悪 20 秒（状態ロック 3 回 + exec 掃除 5 秒）を引いた値。stop を始めた時点からの相対値で、
/// [`SupervisedLifecycle::stop_within`] が各段の admission に使う。
pub const FORCE_DELETE_STOP_BUDGET: Duration = Duration::from_secs(22);
/// 予算を使い切って stop の次の段を始められなかったときの固定文言。
pub const MSG_STOP_BUDGET: &str = "container stop did not fit in the delete budget";
/// Stopped への遷移を状態ストアで見る間隔。
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// 起動の結果の固定文言（記録と報告の不一致。値〔pid・パス〕は載せない。ERR-2）。
pub const MSG_START_REPORT_MISMATCH: &str =
    "supervisor start report does not match the recorded state";
/// 追跡数が上限のときの固定文言。
pub const MSG_TOO_MANY_SUPERVISORS: &str = "too many supervisor processes are tracked";
/// 猶予後の SIGKILL でも Stopped にならなかったときの固定文言。
pub const MSG_STOP_DEADLINE: &str = "container did not stop within the deadline";

/// supervisor の起動を行う口（本番は [`ProductionStarter`]。結合試験は偽の systemd-run・supervisor を指す [`FixedLaunchStarter`]）。
///
/// [`SupervisedLifecycle::start`] だけが呼ぶ。戻りの `Child` は呼び出し側が回収する（wait も kill もこの口では行わない）。
pub trait SupervisorStarter: Send + Sync {
    /// `root`（状態ルートの絶対パス）の `id` を起動し、pid か構造化エラーを期限つきで受け取る。
    ///
    /// `log_path` は CRI ログの書き先（supervisor の `--cri-log-path`。CRI-2・SUP-4・#2671）。`None` は従来どおり。
    fn start(
        &self,
        root: &Path,
        log_path: Option<&ContainerLogPath>,
        id: &ContainerId,
    ) -> (Result<NonZeroU32, OciRuntimeError>, Option<Child>);
}

/// 本番の起動: plugin-cri の実体パスの隣の supervisor を、本番の検査（rootful 拒否・信頼できる systemd-run・user マネージャ）の
/// うえで委譲 scope から起動し、受信期限は CLI と同じ [`production_deadline`] とする（D4・D5）。
#[derive(Debug, Clone, Copy, Default)]
pub struct ProductionStarter;

impl SupervisorStarter for ProductionStarter {
    fn start(
        &self,
        root: &Path,
        log_path: Option<&ContainerLogPath>,
        id: &ContainerId,
    ) -> (Result<NonZeroU32, OciRuntimeError>, Option<Child>) {
        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(_) => {
                return (
                    Err(OciRuntimeError::new(
                        LifecycleOp::Start,
                        ErrorCode::FailedPrecondition,
                        "cannot resolve the plugin executable path",
                    )),
                    None,
                );
            }
        };
        match SupervisorLaunch::resolve_beside(&exe) {
            Ok(launch) => start_with_cri_log(&launch, root, log_path, id, production_deadline()),
            Err(e) => (Err(e), None),
        }
    }
}

/// 解決済みの起動依存と受信期限を固定した起動（結合試験が偽の systemd-run・supervisor を注入する口。D11）。
///
/// 環境変数・引数・RPC から構築する経路は作らない。製品コードは [`ProductionStarter`] だけを使う。
#[derive(Debug, Clone)]
pub struct FixedLaunchStarter {
    launch: SupervisorLaunch,
    within: Duration,
}

impl FixedLaunchStarter {
    /// 起動依存と受信期限から作る。
    pub fn new(launch: SupervisorLaunch, within: Duration) -> Self {
        Self { launch, within }
    }
}

impl SupervisorStarter for FixedLaunchStarter {
    fn start(
        &self,
        root: &Path,
        log_path: Option<&ContainerLogPath>,
        id: &ContainerId,
    ) -> (Result<NonZeroU32, OciRuntimeError>, Option<Child>) {
        start_with_cri_log(&self.launch, root, log_path, id, self.within)
    }
}

/// シグナル送信口の組み立て（stop の意図つきと意図なし。本番は [`ProductionSignalers`]）。
pub trait SignalerSource: Send + Sync {
    /// 意図なしの signaler（`kill` と、stop の SIGKILL 段階。意図は SIGTERM の段階で記録済み）。
    fn plain(&self, store: &dyn StateStore) -> Arc<dyn ProcessSignaler>;
    /// stop の意図を supervisor に記録させてから届ける signaler（SUP-9）。
    fn for_stop(&self, store: &dyn StateStore) -> Arc<dyn ProcessSignaler>;
}

/// 本番の signaler: 制御チャネル経由で supervisor に届け、縮退しない（SEC-1・CORE-1）。
#[derive(Debug, Clone, Copy, Default)]
pub struct ProductionSignalers;

impl SignalerSource for ProductionSignalers {
    fn plain(&self, store: &dyn StateStore) -> Arc<dyn ProcessSignaler> {
        production_signaler(store)
    }

    fn for_stop(&self, store: &dyn StateStore) -> Arc<dyn ProcessSignaler> {
        production_stop_signaler(store)
    }
}

/// supervisor の起動・シグナル送信と、起動した子プロセスの回収を束ねる（Linux 専用）。
pub struct SupervisedLifecycle {
    starter: Arc<dyn SupervisorStarter>,
    signalers: Arc<dyn SignalerSource>,
    children: Mutex<Vec<Child>>,
    /// 起動の結果待ちで枠だけ予約している件数。`children` のロックを持つ間だけ増減する（並行 start の上限超過を防ぐ）。
    reserved: AtomicUsize,
    /// 追跡する子の上限。本番は [`MAX_TRACKED_SUPERVISORS`]（[`Self::with_tracking_limit`] だけが変える）。
    limit: usize,
}

impl SupervisedLifecycle {
    /// 本番の起動・signaler で作る。
    pub fn production() -> Self {
        Self::new(Arc::new(ProductionStarter), Arc::new(ProductionSignalers))
    }

    /// 起動口と signaler を注入して作る（結合試験と別実装への差し替え）。
    pub fn new(starter: Arc<dyn SupervisorStarter>, signalers: Arc<dyn SignalerSource>) -> Self {
        Self::with_tracking_limit(starter, signalers, MAX_TRACKED_SUPERVISORS)
    }

    /// 追跡する子の上限を指定して作る（結合試験と別実装への差し替え用。本番は [`Self::new`] の `MAX_TRACKED_SUPERVISORS`）。
    ///
    /// 上限超過の経路（`RESOURCE_EXHAUSTED`・CRI-2）を実プロセス 1024 個なしで試験するための口。0 は全拒否の設定に
    /// なるため `limit` が 0 のときは 1 に切り上げる。環境変数・引数による上書きは作らない。
    pub fn with_tracking_limit(
        starter: Arc<dyn SupervisorStarter>,
        signalers: Arc<dyn SignalerSource>,
        limit: usize,
    ) -> Self {
        Self {
            starter,
            signalers,
            children: Mutex::new(Vec::new()),
            reserved: AtomicUsize::new(0),
            limit: limit.max(1),
        }
    }

    /// 追跡中の子プロセスの件数（終了済みの回収は入口の [`Self::reap`] が行う）。試験が回収を観測するための口。
    pub fn tracked_children(&self) -> usize {
        self.lock_children().len()
    }

    fn lock_children(&self) -> std::sync::MutexGuard<'_, Vec<Child>> {
        self.children.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 終了済みの子だけを `try_wait` で回収する（終了していない子は触らない。kill も wait もしない）。
    ///
    /// `try_wait` の失敗した子も一覧から外す（回収できない子を抱えて上限を食い潰さない）。
    pub fn reap(&self) {
        self.lock_children()
            .retain_mut(|c| matches!(c.try_wait(), Ok(None)));
    }

    /// supervisor を起動して Running を返す（D6）。
    ///
    /// `log_path` は CRI ログの書き先（`StartRequest::log_path`。CRI-2・SUP-4・#2671）。supervisor へ `--cri-log-path` で渡し、
    /// supervisor が再検証して CRI 形式で追記する（特権ランチャー経由では supervisor が拒否する）。
    pub fn start(
        &self,
        store: &dyn StateStore,
        id: &ContainerId,
        log_path: Option<&ContainerLogPath>,
    ) -> Result<ContainerStatus, TraitError> {
        self.reap();
        let Some(root) = store.host_state_root() else {
            return Err(TraitError::new(
                ErrorCode::FailedPrecondition,
                "state root is not available for starting a container",
            ));
        };
        // 追跡数と予約数の合計で上限を検査し、同じロックの下で枠を予約する（検査と追加の間に並行 start が割り込めない）。
        {
            let children = self.lock_children();
            if children.len() + self.reserved.load(Ordering::SeqCst) >= self.limit {
                return Err(TraitError::new(
                    ErrorCode::ResourceExhausted,
                    MSG_TOO_MANY_SUPERVISORS,
                ));
            }
            self.reserved.fetch_add(1, Ordering::SeqCst);
        }
        let (result, child) = self.starter.start(root, log_path, id);
        {
            // 予約を解放し、Child を得たなら同じロックの下で追跡枠へ移す。
            let mut children = self.lock_children();
            self.reserved.fetch_sub(1, Ordering::SeqCst);
            if let Some(child) = child {
                children.push(child);
            }
        }
        let pid = result.map_err(|e| TraitError::new(e.code(), e.message()))?;
        let status = read_status(store, id)?;
        match (status.state(), status.pid()) {
            (ContainerState::Running, Some(p)) if p == pid => Ok(status),
            // 報告の直後に終了して Stopped が記録済み。呼び出し側（CRI）は終了済みとして扱う。
            (ContainerState::Stopped, _) => Ok(status),
            _ => Err(TraitError::new(
                ErrorCode::Internal,
                MSG_START_REPORT_MISMATCH,
            )),
        }
    }

    /// 意図なしの signaler で `req` のシグナルを 1 回送る（終了は待たない）。
    pub fn kill(
        &self,
        store: &dyn StateStore,
        recorder: &OpRecorder,
        req: &KillRequest,
    ) -> Result<ContainerStatus, TraitError> {
        self.reap();
        let signaler = self.signalers.plain(store);
        kill(store, recorder, &signaler, req, &KillTimeout::default()).map_err(to_trait_error)
    }

    /// `req.signal()`（既定 SIGTERM。stop の意図つき）→ `grace` 待ち → SIGKILL → 最長 [`STOP_KILL_WAIT`] 待ち。
    ///
    /// 予算なし（`StopContainer` の経路。厳密に数えても `grace + 42 秒` で `PLUGIN_RUNTIME_TIMEOUT` に収まる。#3143）。
    pub fn stop(
        &self,
        store: &dyn StateStore,
        recorder: &OpRecorder,
        req: &StopRequest,
    ) -> Result<ContainerStatus, TraitError> {
        self.stop_within(store, recorder, req, None)
    }

    /// [`Self::stop`] に予算 `budget` を持たせたもの（force delete の経路は [`FORCE_DELETE_STOP_BUDGET`]。#3143）。
    ///
    /// 各段（状態の読み取り・シグナル送信）は、予算の残りがその段の最悪の所要以上のときだけ始める。
    /// 始められない段があれば `Timeout`（固定文言 [`MSG_STOP_BUDGET`]）で止め、後続を送らない（fail-closed）。
    /// `None` は予算なしで従来どおり。
    pub fn stop_within(
        &self,
        store: &dyn StateStore,
        recorder: &OpRecorder,
        req: &StopRequest,
        budget: Option<Duration>,
    ) -> Result<ContainerStatus, TraitError> {
        self.reap();
        let budget = StopBudget::start(budget);
        let id = req.id();
        let status = read_status_admitted(store, id, &budget)?;
        match status.state() {
            // 冪等: 停止済みには何も送らない。
            ContainerState::Stopped => return Ok(status),
            ContainerState::Running => {}
            // 未起動（pid なし）の Created は止めるプロセスが無く、既に停止済みと同じである。記録は書き換えず
            // 停止済みの状態を返す（削除は core が pid なしの Created を許す。CRI-2・CORE-2）。
            ContainerState::Created if status.pid().is_none() => {
                return Ok(ContainerStatus::stopped(id.clone(), None));
            }
            // pid つきの Created は生きているため Running と同じく停止する。
            ContainerState::Created => {}
            // Creating と、将来追加される状態は送らずに拒否する（fail-closed）。
            _ => {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "container is not running",
                ));
            }
        }
        let term = self.signalers.for_stop(store);
        let first = KillRequest::new(id.clone(), req.signal());
        send_or_observe_exit(store, recorder, &term, &first, &budget)?;
        if let Some(s) = wait_stopped(store, id, req.grace(), &budget)? {
            return Ok(s);
        }
        // 意図は最初のシグナルの段階で記録済みのため、SIGKILL は意図なしの signaler で送る。
        let plain = self.signalers.plain(store);
        let sigkill = KillRequest::new(id.clone(), Signal::SIGKILL);
        send_or_observe_exit(store, recorder, &plain, &sigkill, &budget)?;
        match wait_stopped(store, id, STOP_KILL_WAIT, &budget)? {
            Some(s) => Ok(s),
            None => Err(TraitError::new(ErrorCode::Timeout, MSG_STOP_DEADLINE)),
        }
    }
}

/// `stop_within` の予算。stop を始めた時点からの期限を持ち、各段を「残り ≥ その段の最悪の所要」のときだけ許す（#3143）。
///
/// `deadline` が `None` なら予算なし（常に許す）。
struct StopBudget {
    deadline: Option<Instant>,
}

/// 状態の読み取り 1 回の最悪の所要（`StateStore` の呼び出し 1 回 = `STATE_LOCK_TIMEOUT`）。
const GET_NEED: Duration = STATE_LOCK_TIMEOUT;
/// シグナル送信 1 段の最悪の所要: core の `kill` の中の `get`（`STATE_LOCK_TIMEOUT`）+ signaler の期限
/// （`KillTimeout::DEFAULT` + `LAUNCHER_REPLY_GRACE`）。
const KILL_NEED: Duration = STATE_LOCK_TIMEOUT
    .saturating_add(KillTimeout::DEFAULT)
    .saturating_add(LAUNCHER_REPLY_GRACE);

impl StopBudget {
    fn start(budget: Option<Duration>) -> Self {
        Self {
            deadline: budget.and_then(|b| Instant::now().checked_add(b)),
        }
    }

    /// 残りが `need` 以上なら許す。足りなければ固定文言の `Timeout`。
    fn admit(&self, need: Duration) -> Result<(), TraitError> {
        match self.deadline {
            Some(d) if d.saturating_duration_since(Instant::now()) < need => {
                Err(TraitError::new(ErrorCode::Timeout, MSG_STOP_BUDGET))
            }
            _ => Ok(()),
        }
    }
}

/// core の失敗を `ErrorCode` を保ったまま `TraitError` へ戻す（REPAIR-5 の `Timeout` 等を潰さない）。
fn to_trait_error(e: OciRuntimeError) -> TraitError {
    TraitError::new(e.code(), e.message())
}

fn read_status(store: &dyn StateStore, id: &ContainerId) -> Result<ContainerStatus, TraitError> {
    store
        .get(&GetStateRequest::new(id.clone()))
        .map(|r| r.status().clone())
}

/// 予算の許す範囲で状態を 1 回読む（`StateStore` の呼び出し 1 回 = `STATE_LOCK_TIMEOUT` を数える。#3143）。
fn read_status_admitted(
    store: &dyn StateStore,
    id: &ContainerId,
    budget: &StopBudget,
) -> Result<ContainerStatus, TraitError> {
    budget.admit(GET_NEED)?;
    read_status(store, id)
}

/// シグナルを 1 回送る。直前に終了していて core が `FAILED_PRECONDITION` を返したときは、記録を読み直し
/// Stopped ならそれを成功として扱う（stop の競合）。それ以外の失敗はコードを保ったまま返す。
///
/// 送信の前に [`KILL_NEED`] を、失敗後の読み直しの前に [`GET_NEED`] を予算に照らす。読み直しを許されなければ
/// 元の失敗をそのまま返す（#3143）。
fn send_or_observe_exit(
    store: &dyn StateStore,
    recorder: &OpRecorder,
    signaler: &Arc<dyn ProcessSignaler>,
    req: &KillRequest,
    budget: &StopBudget,
) -> Result<(), TraitError> {
    budget.admit(KILL_NEED)?;
    match kill(store, recorder, signaler, req, &KillTimeout::default()) {
        Ok(_) => Ok(()),
        Err(e) => {
            let e = to_trait_error(e);
            // 直前に終了した場合、core は FAILED_PRECONDITION を返し、本番の制御チャネルは supervisor が
            // ソケットを閉じた後の接続・読み取りの失敗を UNAVAILABLE で返す。どちらも記録を読み直す（CRI-2）。
            if matches!(
                e.code(),
                ErrorCode::FailedPrecondition | ErrorCode::Unavailable
            ) && read_status_admitted(store, req.id(), budget)
                .is_ok_and(|s| s.state() == ContainerState::Stopped)
            {
                return Ok(());
            }
            Err(e)
        }
    }
}

/// `within` まで状態ストアを見て、Stopped になれば状態を返す（`within` が 0 なら 1 回だけ見る。REPAIR-5）。
///
/// 期限つきのポーリングの最悪は `within + STATE_LOCK_TIMEOUT`（最後の読み取りが期限の直前に始まりうる）。
/// 各読み取りは予算に照らして許されたときだけ出す（#3143）。
fn wait_stopped(
    store: &dyn StateStore,
    id: &ContainerId,
    within: Duration,
    budget: &StopBudget,
) -> Result<Option<ContainerStatus>, TraitError> {
    let deadline = Instant::now().checked_add(within);
    loop {
        let status = read_status_admitted(store, id, budget)?;
        if status.state() == ContainerState::Stopped {
            return Ok(Some(status));
        }
        let remaining = match deadline {
            Some(d) => d.saturating_duration_since(Instant::now()),
            None => within,
        };
        if remaining.is_zero() {
            return Ok(None);
        }
        std::thread::sleep(remaining.min(STOP_POLL_INTERVAL));
    }
}
