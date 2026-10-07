//! コンテナ終了の分類・restart ポリシー評価と、再起動ループ（`restart_count` 管理・state.json 反映）
//! （TASK-159.1・#487／TASK-159.2・#488／TASK-159.3・#489・SUP-3・MS-9。関連: SUP-1・REPAIR-3・REPAIR-4・REPAIR-5）。
//!
//! [`crate::run::monitor`] が回収した [`ProcessExit`] を、正常終了・異常終了（非 0 終了コード）・
//! シグナル終了に分類する。分類結果は [`evaluate_restart`]（restart ポリシー `no` / `on-failure[:N]` /
//! `always` / `unless-stopped` の純粋な再起動要否判定）の入力になる。状態ファイルへ書く終了コードの写像
//! （`exit_code_of`）もここに置く。
//!
//! [`supervise_with_restart`] は `monitor` を周回させる外側のループで、終了検知 → [`evaluate_restart`] →
//! バックオフ → [`Relauncher::relaunch`] → `Running(新 pid)` と `restart_count + 1` の同時記録を行う。
//! `restart_count` は「実施済み再起動の回数」で、再 launch に成功し `Running` を記録できた 1 回の書き込みでだけ
//! 1 進む（再 launch 失敗・記録失敗は数えない）。
//!
//! # 未実装の将来仕様（REPAIR-3）
//! - 本番の再 launch（core の `ProcessLauncher` 経由）は未提供のため、[`Relauncher`] を呼び出し側から注入する
//!   （SUP-3。supervisor のバイナリ入口も未実装）。実機でのレイテンシ実測・合否判定は #490・#491（TASK-160）の担当。
//! - 明示的な stop の検知は SUP-9 の担当で、本モジュールは [`StopToken`] を [`StopIntent`] へ写すだけ。
//!   再 launch 時の `unless-stopped` と `always` の差（stop 済みを復帰させるか）も未実装（SUP-3・SUP-9）。
//! - [`crate::run::MonitorOutcome::ExitedUnrecorded`]（終了は回収済みだが記録失敗）の回復は未実装で、
//!   再 launch せずに [`SuperviseOutcome::MonitorFailed`] で返す（状態が不確かなまま再起動しない。fail-closed）。
//! - 指数バックオフ等の高度な間隔制御は未実装（固定の [`RestartConfig::backoff`] のみ）。
//! - 再起動をまたぐログ捕捉の引き継ぎ（`monitor_with_capture` との統合）は未実装（SUP-7・TASK-164）。
//!
//! # 外部入力の扱い
//! ポリシー文字列（将来 TOML・CLI から届く）は長さを上限検証し、完全一致と ASCII 数字のみの `N` だけを受理する
//! （`unwrap` / 添字アクセスなし。エラー文言に入力を埋め込まない）。
//! 終了状態はカーネル応答に由来するため、シグナル番号は範囲検証し、`128 + s` は `checked_add` で計算する
//! （panic しない）。回収済みの値だけを入力とし、記録済み pid への `kill` / `waitpid` は行わない（SEC-1）。
//! 待ち（バックオフ・再 launch・後始末の terminate）はすべて有限時間で、上限定数で検証する（REPAIR-5）。

use std::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{
    ContainerStatus, ErrorCode, Signal, StateRecord, SupervisionState, TraitError,
};

use crate::run::{
    MonitorConfig, MonitorEvent, MonitorObserver, MonitorOperation, MonitorOutcome, StopToken,
    is_running_with_pid, monitor_with_observer, write_with_retry_when,
};
use crate::state::SupervisedState;

/// 終了の分類結果（SUP-3・TASK-159.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitClass {
    /// 終了コード 0 の正常終了。
    Success,
    /// 非 0 の終了コードでの終了。
    Failure {
        /// 終了コード（負値を含み得る）。
        code: i32,
    },
    /// 有効範囲（1..=64）のシグナルによる終了。
    Signaled {
        /// 終了させたシグナル。
        signal: Signal,
    },
    /// 分類できない終了（範囲外のシグナル番号、または未知の終了種別）。
    Unknown,
}

impl ExitClass {
    /// 異常終了（`Failure` / `Signaled`）か。`Unknown` は根拠なく異常扱いしない。
    ///
    /// 範囲外シグナルは `Unknown` のため `false`（`on-failure` は再起動せず `UnclassifiedExit` になる）。
    pub fn is_abnormal(self) -> bool {
        matches!(self, ExitClass::Failure { .. } | ExitClass::Signaled { .. })
    }
}

/// 回収済みの終了状態を分類する。
pub fn classify_exit(exit: ProcessExit) -> ExitClass {
    match exit {
        ProcessExit::Exited(0) => ExitClass::Success,
        ProcessExit::Exited(code) => ExitClass::Failure { code },
        ProcessExit::Signaled(s) => u8::try_from(s)
            .ok()
            .and_then(|n| Signal::new(n).ok())
            .map_or(ExitClass::Unknown, |signal| ExitClass::Signaled { signal }),
        _ => ExitClass::Unknown,
    }
}

/// 終了状態を状態ファイルへ記録する終了コードへ写す（`Signaled(s)` は `128 + s`。あふれたら `None`）。
pub(crate) fn exit_code_of(exit: ProcessExit) -> Option<i32> {
    match exit {
        ProcessExit::Exited(c) => Some(c),
        ProcessExit::Signaled(s) => 128i32.checked_add(s),
        _ => None,
    }
}

/// ポリシー文字列の最大長（バイト）。外部入力の長さを先に検証する（DoS 防止）。
const MAX_POLICY_LEN: usize = 32;

/// restart ポリシー（SUP-3・TASK-159.2）。既定は `No`（設定が無ければ再起動しない。fail-closed）。
///
/// 4 ポリシーの名前のみ spec が定め、細部は Docker の慣行に合わせた解釈。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RestartPolicy {
    /// 再起動しない（`no`）。
    #[default]
    No,
    /// 異常終了（`Failure` / `Signaled`）のときのみ再起動する（`on-failure[:N]`）。
    OnFailure {
        /// 再起動回数の上限。`None` は無制限。`on-failure:0` は曖昧なためパーサが拒否する。
        max_retries: Option<NonZeroU32>,
    },
    /// 終了種別に関わらず再起動する（`always`）。
    Always,
    /// 明示的 stop を除き再起動する（`unless-stopped`）。
    UnlessStopped,
}

impl FromStr for RestartPolicy {
    type Err = TraitError;

    /// `no` / `always` / `unless-stopped` / `on-failure` / `on-failure:N`（N は 1 以上の `u32`）の完全一致のみ受理する。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || TraitError::new(ErrorCode::InvalidArgument, "invalid restart policy");
        if s.len() > MAX_POLICY_LEN {
            return Err(invalid());
        }
        match s.split_once(':') {
            None => match s {
                "no" => Ok(RestartPolicy::No),
                "always" => Ok(RestartPolicy::Always),
                "unless-stopped" => Ok(RestartPolicy::UnlessStopped),
                "on-failure" => Ok(RestartPolicy::OnFailure { max_retries: None }),
                _ => Err(invalid()),
            },
            Some(("on-failure", n)) => {
                if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid());
                }
                let n = n.parse::<u32>().map_err(|_| invalid())?;
                let n = NonZeroU32::new(n).ok_or_else(invalid)?;
                Ok(RestartPolicy::OnFailure {
                    max_retries: Some(n),
                })
            }
            Some(_) => Err(invalid()),
        }
    }
}

/// 明示的 stop の有無（[`evaluate_restart`] の入力）。検知は SUP-9 の担当で、本モジュールは行わない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StopIntent {
    /// stop 要求なし。
    NotRequested,
    /// stop 要求あり。
    Requested,
}

/// 再起動要否の判定結果（SUP-3・TASK-159.2）。#489 がバックオフ等を足せるよう真偽値にしない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RestartDecision {
    /// 再起動する。
    Restart,
    /// 再起動しない。
    DoNotRestart {
        /// 再起動しない理由。
        reason: NoRestartReason,
    },
}

/// 再起動しない理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoRestartReason {
    /// ポリシーが `no`。
    PolicyNo,
    /// 正常終了（`on-failure`）。
    ExitedSuccessfully,
    /// `on-failure:N` の上限に達した。
    RetriesExhausted,
    /// 明示的 stop が要求された。
    ExplicitStop,
    /// 終了を分類できず異常と判断しない（`on-failure`）。
    UnclassifiedExit,
}

impl NoRestartReason {
    /// 構造化ログ向けの機械可読な識別子（REPAIR-4）。
    pub fn as_str(self) -> &'static str {
        match self {
            NoRestartReason::PolicyNo => "policy_no",
            NoRestartReason::ExitedSuccessfully => "exited_successfully",
            NoRestartReason::RetriesExhausted => "retries_exhausted",
            NoRestartReason::ExplicitStop => "explicit_stop",
            NoRestartReason::UnclassifiedExit => "unclassified_exit",
        }
    }
}

/// 終了検知後の再起動要否を判定する純粋関数（状態・I/O なし。SUP-3・TASK-159.2）。
///
/// 評価順: 明示的 stop（全ポリシーで再起動しない。Docker 互換）→ `no` → `always` / `unless-stopped`
/// （常に再起動）→ `on-failure`。このため終了検知時点では `always` と `unless-stopped` は同じ結果になり、
/// 差は再 launch 時の挙動（未実装。SUP-3・SUP-9）にある。
///
/// `restart_count` は「これまでに行った再起動の回数」として受ける。呼び出し元は [`supervise_with_restart`]
/// （#489・TASK-159.3）で、state.json の `restart_count`（再 launch 成功ごとに 1 進む）をそのまま渡す。
pub fn evaluate_restart(
    policy: RestartPolicy,
    exit: ExitClass,
    restart_count: u32,
    stop: StopIntent,
) -> RestartDecision {
    let no = |reason| RestartDecision::DoNotRestart { reason };
    if stop == StopIntent::Requested {
        return no(NoRestartReason::ExplicitStop);
    }
    match policy {
        RestartPolicy::No => no(NoRestartReason::PolicyNo),
        RestartPolicy::Always | RestartPolicy::UnlessStopped => RestartDecision::Restart,
        RestartPolicy::OnFailure { max_retries } => match exit {
            ExitClass::Success => no(NoRestartReason::ExitedSuccessfully),
            ExitClass::Unknown => no(NoRestartReason::UnclassifiedExit),
            ExitClass::Failure { .. } | ExitClass::Signaled { .. } => match max_retries {
                Some(n) if restart_count >= n.get() => no(NoRestartReason::RetriesExhausted),
                _ => RestartDecision::Restart,
            },
        },
    }
}

/// 再 launch の既定の上限。
pub const DEFAULT_RELAUNCH_TIMEOUT: Duration = Duration::from_secs(10);
/// 再 launch・後始末の待ち上限の最大値。これを超える設定は拒否する（REPAIR-5）。
pub const MAX_RELAUNCH_TIMEOUT: Duration = Duration::from_secs(60);
/// 再 launch 後の記録失敗時の後始末（新プロセスの terminate）の既定の上限。
pub const DEFAULT_TERMINATE_TIMEOUT: Duration = Duration::from_secs(5);
/// バックオフの既定値（暫定）。0 は再起動ストームになり得るため、明示指定のときだけ使う（SUP-3）。
pub const DEFAULT_BACKOFF: Duration = Duration::from_millis(100);
/// バックオフの最大値。これを超える設定は拒否する（REPAIR-5）。
pub const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// 再 launch の応答を `relaunch_timeout` の後に待つ猶予（実装が自力で期限内に Err を返す余地）。
pub const RELAUNCH_REPLY_GRACE: Duration = Duration::from_millis(500);
/// バックオフ待ちが停止要求を確認する刻み。
const BACKOFF_SLICE: Duration = Duration::from_millis(10);

/// 同じコンテナのプロセスを再 launch する拡張点（SUP-3・TASK-159.3）。
///
/// 本番の `ProcessLauncher` は core に未提供のため、[`supervise_with_restart`] へ呼び出し側から注入する
/// （本番実装は未実装。REPAIR-3）。
///
/// 期限は実装への依頼だけに頼らず、[`supervise_with_restart`] が別スレッド上の呼び出し境界で強制する
/// （上限＋[`RELAUNCH_REPLY_GRACE`] で待ちをやめる。REPAIR-5）。そのため `Send + Sync` を要求する。
/// 実装が戻らない場合、実行スレッドはプロセス終了まで残り得る（Rust にスレッドの強制停止は無い）が、
/// 監視ループは上限で戻る。期限後に戻った新プロセスは実行スレッド上で terminate する。
pub trait Relauncher: Send + Sync {
    /// 同じコンテナのプロセスを再起動し、新しい起動ハンドルを返す。待ちは `timeout` まで（REPAIR-5）。
    fn relaunch(&self, timeout: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError>;
}

/// 再起動ループの設定。検証付きコンストラクタ経由でのみ作れる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartConfig {
    policy: RestartPolicy,
    backoff: Duration,
    relaunch_timeout: Duration,
    terminate_timeout: Duration,
}

impl RestartConfig {
    /// 既定のバックオフ（[`DEFAULT_BACKOFF`]）・タイムアウトで作る。
    pub fn new(policy: RestartPolicy) -> Self {
        Self {
            policy,
            backoff: DEFAULT_BACKOFF,
            relaunch_timeout: DEFAULT_RELAUNCH_TIMEOUT,
            terminate_timeout: DEFAULT_TERMINATE_TIMEOUT,
        }
    }

    /// バックオフを設定する（0 可。SUP-3 のレイテンシ目標はバックオフ 0 が前提）。[`MAX_BACKOFF`] 超は `InvalidArgument`。
    pub fn with_backoff(self, backoff: Duration) -> Result<Self, TraitError> {
        if backoff > MAX_BACKOFF {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "backoff is out of range",
            ));
        }
        Ok(Self { backoff, ..self })
    }

    /// 再 launch の待ち上限を設定する。0 または [`MAX_RELAUNCH_TIMEOUT`] 超は `InvalidArgument`。
    pub fn with_relaunch_timeout(self, relaunch_timeout: Duration) -> Result<Self, TraitError> {
        if relaunch_timeout.is_zero() || relaunch_timeout > MAX_RELAUNCH_TIMEOUT {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "relaunch timeout is out of range",
            ));
        }
        Ok(Self {
            relaunch_timeout,
            ..self
        })
    }

    /// 後始末の terminate の上限を設定する。0 または [`MAX_RELAUNCH_TIMEOUT`] 超は `InvalidArgument`。
    pub fn with_terminate_timeout(self, terminate_timeout: Duration) -> Result<Self, TraitError> {
        if terminate_timeout.is_zero() || terminate_timeout > MAX_RELAUNCH_TIMEOUT {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "terminate timeout is out of range",
            ));
        }
        Ok(Self {
            terminate_timeout,
            ..self
        })
    }

    /// restart ポリシー。
    pub fn policy(&self) -> RestartPolicy {
        self.policy
    }

    /// 再起動前のバックオフ。
    pub fn backoff(&self) -> Duration {
        self.backoff
    }

    /// 再 launch の待ち上限。
    pub fn relaunch_timeout(&self) -> Duration {
        self.relaunch_timeout
    }

    /// 後始末の terminate の上限。
    pub fn terminate_timeout(&self) -> Duration {
        self.terminate_timeout
    }
}

/// terminate に失敗した（生存の可能性がある）プロセスのハンドルと失敗理由。
pub type LateOrphan = (Box<dyn LaunchedProcess>, TraitError);

/// 期限超過後に戻った再 launch のプロセスのうち、terminate に失敗して生存の可能性が残るものの受け皿。
///
/// 期限超過で [`SuperviseOutcome::RelaunchFailed`] を返した後に実行スレッドへ戻った新プロセスは、
/// 実行スレッドが terminate する。その terminate が失敗したとき、ハンドルと失敗理由をここへ積む。
/// 実行スレッドは期限後も動き続けるため、空の [`LateOrphans::take`] だけでは回収完了を判定できない。
/// 呼び出し側は [`LateOrphans::wait_settled`]（または [`LateOrphans::is_settled`]）で実行スレッドの終了を
/// 確認してから [`LateOrphans::take`] で取り出して回収する（REPAIR-5。`Clone` は同じ受け皿を共有する）。
#[derive(Clone, Default)]
pub struct LateOrphans {
    inner: Arc<(Mutex<LateInner>, Condvar)>,
}

#[derive(Default)]
struct LateInner {
    orphans: Vec<LateOrphan>,
    /// 動作中の再 launch 実行スレッドの数（0 なら以後ハンドルが積まれない）。
    active_workers: u32,
}

impl LateOrphans {
    fn lock(&self) -> std::sync::MutexGuard<'_, LateInner> {
        self.inner.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 実行スレッドの起動前に呼ぶ。
    fn worker_started(&self) {
        let mut g = self.lock();
        g.active_workers = g.active_workers.saturating_add(1);
    }

    /// 実行スレッドの終了時（panic・起動失敗を含む）に呼ぶ。待機者を起こす。
    fn worker_finished(&self) {
        let mut g = self.lock();
        g.active_workers = g.active_workers.saturating_sub(1);
        drop(g);
        self.inner.1.notify_all();
    }

    fn push(&self, process: Box<dyn LaunchedProcess>, error: TraitError) {
        self.lock().orphans.push((process, error));
    }

    /// 再 launch の実行スレッドがすべて終了済みで、以後ハンドルが積まれないとき `true`。
    pub fn is_settled(&self) -> bool {
        self.lock().active_workers == 0
    }

    /// 実行スレッドの終了を `timeout` まで待つ。終了していれば `true`（以後の [`LateOrphans::take`] が最終結果）。
    /// `false` は relaunch が戻らず未完了で、呼び出し側は受け皿を保持して後で再確認する（REPAIR-5）。
    pub fn wait_settled(&self, timeout: Duration) -> bool {
        let end = Instant::now().checked_add(timeout);
        let mut g = self.lock();
        while g.active_workers > 0 {
            let remaining = match end {
                Some(e) => match e.checked_duration_since(Instant::now()) {
                    Some(r) if !r.is_zero() => r,
                    _ => return false,
                },
                None => timeout,
            };
            g = self
                .inner
                .1
                .wait_timeout(g, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }

    /// 積まれている（terminate に失敗した）プロセスとその失敗理由をすべて取り出す。
    pub fn take(&self) -> Vec<LateOrphan> {
        std::mem::take(&mut self.lock().orphans)
    }
}

/// 実行スレッド終了時に必ず [`LateOrphans::worker_finished`] を呼ぶガード。
struct WorkerGuard(LateOrphans);

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.worker_finished();
    }
}

/// 実行スレッドの生成関数（名前と本体を受け取る）。本番は [`spawn_os_thread`] で、テストは失敗する関数を渡す。
type SpawnFn = fn(&str, Box<dyn FnOnce() + Send + 'static>) -> std::io::Result<()>;

/// OS スレッドを生成する（[`SpawnFn`] の本番実装。join はせず、終了は [`LateOrphans`] の実行スレッド数で追う）。
fn spawn_os_thread(name: &str, run: Box<dyn FnOnce() + Send + 'static>) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name(name.to_owned())
        .spawn(run)
        .map(drop)
}

/// `late` の実行スレッド数に数えたスレッドを起動する（REPAIR-5）。
///
/// [`terminate_bounded`]・[`relaunch_bounded`] の実行スレッドはここからだけ起動する。数の増減を 1 か所で対にする:
/// 起動前に 1 増やし（起動直後に [`LateOrphans::is_settled`] が 0 を観測しないため）、`body` の終了時
/// （panic を含む）にスレッド上のガードで 1 減らす。スレッドを生成できなかった場合はここで 1 減らしてから
/// `Err` を返すので、起動失敗で `late` が未完了のまま残ることはない。ガードはスレッドの中で作るため、
/// 未実行の `body` が破棄されても数は動かない（二重に減らさない）。
fn spawn_tracked(
    spawn: SpawnFn,
    name: &str,
    late: &LateOrphans,
    body: impl FnOnce() + Send + 'static,
) -> std::io::Result<()> {
    late.worker_started();
    let worker_late = late.clone();
    let spawned = spawn(
        name,
        Box::new(move || {
            let _guard = WorkerGuard(worker_late);
            body();
        }),
    );
    if spawned.is_err() {
        late.worker_finished();
    }
    spawned
}

impl fmt::Debug for LateOrphans {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let g = self.lock();
        f.debug_struct("LateOrphans")
            .field("pending", &g.orphans.len())
            .field("active_workers", &g.active_workers)
            .finish()
    }
}

/// [`supervise_with_restart`] の結果。`restarts` はこの呼び出し中に実施した再起動の回数。
#[non_exhaustive]
pub enum SuperviseOutcome {
    /// ポリシー（または明示的 stop）により再起動せず終了した。最終状態は `Stopped`。
    Finished {
        /// 最後の `monitor` の結果（`Exited`）。
        last: MonitorOutcome,
        /// 再起動しなかった理由。
        reason: NoRestartReason,
        /// 実施した再起動の回数。
        restarts: u32,
    },
    /// 停止要求で監視をやめた。`process` は生存中のハンドルで、回収責任は呼び出し側にある
    /// （`MonitorOutcome::StopRequested` と同じ契約）。バックオフ中の停止では `None`（プロセスは既に回収済み）。
    /// 再起動の `Running` 記録の直後に見つけた停止要求で新プロセスの終了を確認できなかった場合は、`process` は
    /// `None` で、ハンドルは `late` に入る（状態は `Running(新 pid)` のまま。[`supervise_with_restart`] 参照）。
    Stopped {
        /// 最後の `monitor` の結果。
        last: MonitorOutcome,
        /// 生存中の起動ハンドル。
        process: Option<Box<dyn LaunchedProcess>>,
        /// 停止要求後に戻った新プロセスの terminate が失敗・超過したハンドルの受け皿（回収責任は呼び出し側。REPAIR-5）。
        /// 超過時は実行スレッドが未完了のため [`LateOrphans::wait_settled`] で確認してから `take` する。
        late: LateOrphans,
        /// 実施した再起動の回数。
        restarts: u32,
    },
    /// 再 launch に失敗した（`restart_count` は進めていない。状態は `Stopped`）。
    RelaunchFailed {
        /// 直前のプロセスの終了状態。
        exit: ProcessExit,
        /// 再 launch の失敗理由。
        error: TraitError,
        /// 期限超過後に戻ったプロセスの terminate 失敗の受け皿（回収責任は呼び出し側。REPAIR-5）。
        late: LateOrphans,
        /// 実施した再起動の回数。
        restarts: u32,
    },
    /// 再 launch には成功したが `Running` の記録に失敗したため、新プロセスを terminate した。
    /// 停止要求で取り消した再起動（新プロセスは終了確認済み）の記録を `Stopped` へ戻せなかった場合もこれを返す
    /// （状態は終了済みの pid で `Running` のまま残り得る）。
    RestartUnrecorded {
        /// 記録の失敗理由。
        error: TraitError,
        /// 新プロセスの terminate が失敗した場合の理由（成功なら `None`）。
        terminate_error: Option<TraitError>,
        /// terminate で終了を確認できなかった生存の可能性があるプロセスの受け皿（回収責任は呼び出し側。REPAIR-5）。
        /// terminate が超過した場合は実行スレッドが未完了のため [`LateOrphans::wait_settled`] で確認してから `take` する。
        late: LateOrphans,
        /// 実施した再起動の回数（この失敗した 1 回は含まない）。
        restarts: u32,
    },
    /// `monitor` が状態の不確かな結果（`ExitedUnrecorded` 等）を返したため、再起動せずに戻った（fail-closed）。
    MonitorFailed {
        /// `monitor` の結果。
        last: MonitorOutcome,
        /// 終了を確認できていない（生存の可能性がある）起動ハンドル。回収責任は呼び出し側（REPAIR-5）。
        /// 終了が回収済みの `ExitedUnrecorded` では `None`。
        process: Option<Box<dyn LaunchedProcess>>,
        /// 実施した再起動の回数。
        restarts: u32,
    },
    /// `monitor` 自体が `Err`（事前条件違反・wait 失敗）で戻った。終了は確認できていないため、
    /// 起動ハンドルを返す（回収責任は呼び出し側。REPAIR-5）。再起動はしない（fail-closed）。
    MonitorError {
        /// `monitor` の失敗理由。
        error: TraitError,
        /// 生存の可能性がある起動ハンドル。
        process: Box<dyn LaunchedProcess>,
        /// 実施した再起動の回数。
        restarts: u32,
    },
}

impl fmt::Debug for SuperviseOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Finished {
                last,
                reason,
                restarts,
            } => f
                .debug_struct("Finished")
                .field("last", last)
                .field("reason", reason)
                .field("restarts", restarts)
                .finish(),
            Self::Stopped {
                last,
                process,
                late,
                restarts,
            } => f
                .debug_struct("Stopped")
                .field("last", last)
                .field("has_process", &process.is_some())
                .field("late", late)
                .field("restarts", restarts)
                .finish(),
            Self::RelaunchFailed {
                exit,
                error,
                late,
                restarts,
            } => f
                .debug_struct("RelaunchFailed")
                .field("exit", exit)
                .field("error", error)
                .field("late", late)
                .field("restarts", restarts)
                .finish(),
            Self::RestartUnrecorded {
                error,
                terminate_error,
                late,
                restarts,
            } => f
                .debug_struct("RestartUnrecorded")
                .field("error", error)
                .field("terminate_error", terminate_error)
                .field("late", late)
                .field("restarts", restarts)
                .finish(),
            Self::MonitorFailed {
                last,
                process,
                restarts,
            } => f
                .debug_struct("MonitorFailed")
                .field("last", last)
                .field("has_process", &process.is_some())
                .field("restarts", restarts)
                .finish(),
            Self::MonitorError {
                error, restarts, ..
            } => f
                .debug_struct("MonitorError")
                .field("error", error)
                .field("restarts", restarts)
                .finish(),
        }
    }
}

/// バックオフ待ち。`stop` を [`BACKOFF_SLICE`] ごとに確認し、停止要求なら `false`（待ちを打ち切る）を返す。
fn sleep_unless_stopped(backoff: Duration, stop: &StopToken) -> bool {
    let end = Instant::now() + backoff;
    loop {
        if stop.is_stop_requested() {
            return false;
        }
        let now = Instant::now();
        if now >= end {
            return true;
        }
        std::thread::sleep(BACKOFF_SLICE.min(end - now));
    }
}

/// [`terminate_bounded`] の結果の受け渡し枠。
type TerminateSlot = (Mutex<Option<Result<(), TraitError>>>, Condvar);

/// 起動済みプロセスを上限つきで terminate する。確認できたら `Ok`（REPAIR-5）。
///
/// 実装が `timeout` を守らず戻らなくても、呼び出し側は `timeout`＋[`RELAUNCH_REPLY_GRACE`] で待ちをやめて
/// `Timeout` を返す（core の `LaunchedProcess::terminate` 契約と同じく呼び出し境界でも上限を強制する）。
/// terminate は追跡つきの別スレッドで実行し、`Err` で戻ったハンドルは `late` へ積む（超過後に戻る場合も）。
/// 戻らない間は `late` の実行スレッド数が 0 にならないため、呼び出し側は [`LateOrphans::wait_settled`] で
/// 未完了を判別し、受け皿を保持して後で [`LateOrphans::take`] できる。実行スレッドを作れない場合も
/// ハンドルを `late` へ積む。
fn terminate_bounded(
    process: Box<dyn LaunchedProcess>,
    timeout: Duration,
    late: &LateOrphans,
    spawn: SpawnFn,
) -> Result<(), TraitError> {
    let cell = Arc::new(Mutex::new(Some(process)));
    let result: Arc<TerminateSlot> = Arc::new((Mutex::new(None), Condvar::new()));
    let (worker_cell, worker_result, worker_late) =
        (Arc::clone(&cell), Arc::clone(&result), late.clone());
    // `Err` のハンドルの push は、実行スレッド終了の通知（[`spawn_tracked`] のガード）より先に行う。
    let spawned = spawn_tracked(spawn, "fandhe-terminate", late, move || {
        let taken = worker_cell
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(proc) = taken else {
            return;
        };
        let r = proc.terminate(timeout);
        if let Err(e) = &r {
            worker_late.push(proc, e.clone());
        }
        let (lock, cvar) = &*worker_result;
        *lock.lock().unwrap_or_else(PoisonError::into_inner) = Some(r);
        cvar.notify_all();
    });
    if spawned.is_err() {
        let left = cell.lock().unwrap_or_else(PoisonError::into_inner).take();
        let error = TraitError::new(ErrorCode::Unavailable, "failed to spawn terminate thread");
        if let Some(proc) = left {
            late.push(proc, error.clone());
        }
        return Err(error);
    }
    let deadline = Instant::now().checked_add(timeout.saturating_add(RELAUNCH_REPLY_GRACE));
    let (lock, cvar) = &*result;
    let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        if let Some(r) = slot.take() {
            return r;
        }
        let now = Instant::now();
        let remaining = match deadline {
            Some(d) if d > now => d - now,
            _ => return Err(TraitError::new(ErrorCode::Timeout, "terminate timed out")),
        };
        slot = cvar
            .wait_timeout(slot, remaining)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

/// [`relaunch_bounded`] の結果の受け渡し枠。
enum Slot {
    Pending,
    Done(Result<Box<dyn LaunchedProcess>, TraitError>),
    /// 呼び出し側が期限超過で待つのをやめた。以後に戻ったプロセスは実行スレッドが terminate する。
    Abandoned,
}

/// `relauncher.relaunch` を別スレッドで実行し、上限（＋[`RELAUNCH_REPLY_GRACE`]）までに戻った結果だけを返す（REPAIR-5）。
///
/// 期限後に戻ったプロセスは受け渡し枠の `Mutex` の下で「待つのをやめた」印を見て、実行スレッド上で
/// terminate する。terminate に失敗したらハンドルと理由を `late` へ積み、捨てない（REPAIR-5）。
fn relaunch_bounded(
    relauncher: &Arc<dyn Relauncher>,
    timeout: Duration,
    terminate_timeout: Duration,
    late: &LateOrphans,
    spawn: SpawnFn,
) -> Result<Box<dyn LaunchedProcess>, TraitError> {
    let shared = Arc::new((Mutex::new(Slot::Pending), Condvar::new()));
    let worker = Arc::clone(&shared);
    let r = Arc::clone(relauncher);
    // terminate 失敗の push は、実行スレッド終了の通知（[`spawn_tracked`] のガード。panic を含む）より先に行う。
    let worker_late = late.clone();
    spawn_tracked(spawn, "fandhe-relaunch", late, move || {
        let value = r.relaunch(timeout);
        let (lock, cvar) = &*worker;
        let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
        if matches!(*slot, Slot::Abandoned) {
            drop(slot);
            if let Ok(proc) = value {
                // 期限後に戻った生存プロセスを残さない（記録も回収手段も無いため）。
                // terminate にも呼び出し境界で上限を強制する。失敗・超過したハンドルは `late` に積まれる。
                let _ = terminate_bounded(proc, terminate_timeout, &worker_late, spawn);
            }
            return;
        }
        *slot = Slot::Done(value);
        cvar.notify_all();
    })
    .map_err(|_| TraitError::new(ErrorCode::Unavailable, "failed to spawn relaunch thread"))?;
    let deadline = Instant::now().checked_add(timeout.saturating_add(RELAUNCH_REPLY_GRACE));
    let (lock, cvar) = &*shared;
    let mut slot = lock.lock().unwrap_or_else(PoisonError::into_inner);
    loop {
        match std::mem::replace(&mut *slot, Slot::Abandoned) {
            Slot::Done(value) => return value,
            other => *slot = other,
        }
        let now = Instant::now();
        let remaining = match deadline {
            Some(d) if d > now => d - now,
            _ => {
                *slot = Slot::Abandoned;
                return Err(TraitError::new(ErrorCode::Timeout, "relaunch timed out"));
            }
        };
        slot = cvar
            .wait_timeout(slot, remaining)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

/// `monitor` を周回させ、ポリシーに従って再起動する（SUP-3・TASK-159.3）。
///
/// 将来の supervisor 入口（コンテナごとの別プロセス）が [`crate::state::SupervisedState::attach`] 後に呼ぶ。
/// 1 周: `monitor`（監視権取得・終了検知・`Stopped` 記録）→ [`evaluate_restart`]（`restart_count` は state.json の値）→
/// バックオフ → [`Relauncher::relaunch`] → `Running(新 pid)` と `restart_count + 1` を 1 回の書き込みで記録。
/// `Running` 再記録では `supervisor_pid` は `None` のままで、次周の `monitor` が監視権を取り直す。
///
/// [`MonitorOperation::Restart`] を再起動 1 回ごとに通知する。`elapsed` は終了検知（`Stopped` 記録の前）から `Running` 記録完了までで、
/// バックオフ時間を含む（バックオフ 0 のとき SUP-3 の「再起動レイテンシ中央値 100ms 以下」に相当）。
///
/// `monitor` 自体が失敗しても終了を確認できていない `process` は捨てず、[`SuperviseOutcome::MonitorError`] /
/// [`SuperviseOutcome::MonitorFailed`] で呼び出し側へ返す（REPAIR-5）。
/// 停止要求はポリシー評価時・バックオフ中・relaunch の直前と直後（`Running` 記録の前）・`Running` 記録の直後に確認する。
/// 再 launch の待ちは境界で強制する（[`Relauncher`]）。
///
/// `Running` 記録の直後に停止要求が立っていた場合（最終確認と書き込みの間に届いた停止要求）は、記録が自分の書き込みの
/// ままであることを読み直して確かめ、新プロセスを terminate する。結果は次のとおり。
/// - 終了を確認でき、元の終了記録（`Stopped`・元の `restart_count`）へ戻せた: 記録前に届いた場合と同じ
///   [`SuperviseOutcome::Stopped`]（`process` は `None`・`restarts` は進まない）。
/// - 終了を確認できない（terminate の失敗・超過）: 記録は `Running(新 pid)` のまま動かさず、ハンドルを `late` に積んで
///   [`SuperviseOutcome::Stopped`] を返す（`restarts` は記録済みの 1 回を含む。回収責任は呼び出し側。REPAIR-5）。
/// - 終了は確認できたが記録を戻せない: [`SuperviseOutcome::RestartUnrecorded`]（`terminate_error` は `None`）。
/// - 記録が自分の書き込みでない（別の処理が監視権を取った・状態を遷移させた）: terminate せず、記録済みの再起動として
///   次周の `monitor` に委ねる（別の処理が所有し得るプロセスを kill しない。ハンドルは呼び出し側へ返る）。
///
/// この確認より後に届いた停止要求は、次周の `monitor` が「稼働中の停止要求」として扱う。
pub fn supervise_with_restart(
    state: &mut SupervisedState,
    process: Box<dyn LaunchedProcess>,
    relauncher: &Arc<dyn Relauncher>,
    monitor_config: &MonitorConfig,
    restart_config: &RestartConfig,
    stop: &StopToken,
    obs: &dyn MonitorObserver,
) -> Result<SuperviseOutcome, TraitError> {
    let mut process = process;
    let mut restarts: u32 = 0;
    // 後始末の terminate が失敗・超過したハンドルの受け皿。`Stopped` / `RestartUnrecorded` で呼び出し側へ渡す。
    let cleanup_late = LateOrphans::default();
    loop {
        let last = match monitor_with_observer(state, process.as_ref(), monitor_config, stop, obs) {
            Ok(last) => last,
            Err(error) => {
                return Ok(SuperviseOutcome::MonitorError {
                    error,
                    process,
                    restarts,
                });
            }
        };
        let (exit, restart_count, detected, exited_status) = match &last {
            MonitorOutcome::Exited {
                exit,
                record,
                detected_at,
            } => (
                *exit,
                record.restart_count(),
                *detected_at,
                record.status().clone(),
            ),
            MonitorOutcome::StopRequested { .. } => {
                return Ok(SuperviseOutcome::Stopped {
                    last,
                    process: Some(process),
                    late: cleanup_late,
                    restarts,
                });
            }
            _ => {
                // 回収済みの終了（ExitedUnrecorded）以外は終了未確認のためハンドルを返す。
                let process =
                    (!matches!(last, MonitorOutcome::ExitedUnrecorded { .. })).then_some(process);
                return Ok(SuperviseOutcome::MonitorFailed {
                    last,
                    process,
                    restarts,
                });
            }
        };
        let intent = if stop.is_stop_requested() {
            StopIntent::Requested
        } else {
            StopIntent::NotRequested
        };
        if let RestartDecision::DoNotRestart { reason } = evaluate_restart(
            restart_config.policy,
            classify_exit(exit),
            restart_count,
            intent,
        ) {
            return Ok(SuperviseOutcome::Finished {
                last,
                reason,
                restarts,
            });
        }
        if !restart_config.backoff.is_zero() && !sleep_unless_stopped(restart_config.backoff, stop)
        {
            return Ok(SuperviseOutcome::Stopped {
                last,
                process: None,
                late: cleanup_late,
                restarts,
            });
        }
        // バックオフ 0 でも relaunch の直前に停止要求を確認する（停止後に再起動しない。SUP-3）。
        if stop.is_stop_requested() {
            return Ok(SuperviseOutcome::Stopped {
                last,
                process: None,
                late: cleanup_late,
                restarts,
            });
        }
        let observe = |error_code: Option<ErrorCode>| {
            obs.observe(&MonitorEvent {
                operation: MonitorOperation::Restart,
                error_code,
                elapsed: detected.elapsed(),
            });
        };
        let late = LateOrphans::default();
        let new_process = match relaunch_bounded(
            relauncher,
            restart_config.relaunch_timeout,
            restart_config.terminate_timeout,
            &late,
            spawn_os_thread,
        ) {
            Ok(p) => p,
            Err(error) => {
                observe(Some(error.code()));
                return Ok(SuperviseOutcome::RelaunchFailed {
                    exit,
                    error,
                    late,
                    restarts,
                });
            }
        };
        // 再 launch 中に停止要求が来ていたら、Running を記録せず新プロセスを終了・回収する（SUP-3）。
        if stop.is_stop_requested() {
            // 上限を呼び出し境界で強制する。終了未確認のハンドルは `cleanup_late` に積まれる（REPAIR-5）。
            let _ = terminate_bounded(
                new_process,
                restart_config.terminate_timeout,
                &cleanup_late,
                spawn_os_thread,
            );
            return Ok(SuperviseOutcome::Stopped {
                last,
                process: None,
                late: cleanup_late,
                restarts,
            });
        }
        let new_pid = new_process.pid();
        let id = state.id().clone();
        // 自分が監視して記録した終了記録（同一の `Stopped` 状態・監視権なし・同じ `restart_count`）のままであることを確かめて書く。
        // 別処理が再起動して同じ終了で再び `Stopped` になっても `restart_count` が進むため、別の終了記録と取り違えない。
        // 競合後に stop / delete / 再作成など別の遷移が入っていれば書かない（health 更新による revision 変化は許容）。
        let written = write_with_retry_when(
            state,
            |rec| {
                rec.status() == &exited_status
                    && rec.supervision().supervisor_pid().is_none()
                    && rec.restart_count() == restart_count
            },
            |rec| {
                // 競合後の refresh で他者の更新を消さないよう、書き込みごとに最新値から加算する（上限で頭打ち）。
                Ok((
                    ContainerStatus::running(id.clone(), Some(new_pid)),
                    SupervisionState::new(
                        None,
                        rec.health(),
                        rec.restart_count().saturating_add(1),
                    ),
                ))
            },
        );
        match written {
            Ok(_) => {
                // 最終確認から書き込みまでの間に停止要求が届いていたら、停止後に再起動した状態を残さない（SUP-3）。
                // 記録が自分の書き込み（`Running(新 pid)`・監視権なし・加算後の回数）のままなら新プロセスを
                // terminate し、終了を確認できてから元の終了記録へ戻す。別の処理が状態を動かしていれば
                // terminate せず、次周の `monitor` に委ねる（関数 doc 参照）。
                let recorded = restart_count.saturating_add(1);
                let is_own_record = |rec: &StateRecord| {
                    is_running_with_pid(rec, new_pid)
                        && rec.supervision().supervisor_pid().is_none()
                        && rec.restart_count() == recorded
                };
                if stop.is_stop_requested() && state.refresh().is_ok_and(|rec| is_own_record(rec)) {
                    // 終了を確認できるまで `Running` の記録は動かさない（生存し得るのに `Stopped` と書かない。REPAIR-5）。
                    // 上限を呼び出し境界で強制する。終了未確認のハンドルは `cleanup_late` に積まれる。
                    if terminate_bounded(
                        new_process,
                        restart_config.terminate_timeout,
                        &cleanup_late,
                        spawn_os_thread,
                    )
                    .is_err()
                    {
                        // 記録は `Running(新 pid)` のまま残す。再起動 1 回は記録済みとして数える。
                        observe(None);
                        return Ok(SuperviseOutcome::Stopped {
                            last,
                            process: None,
                            late: cleanup_late,
                            restarts: restarts.saturating_add(1),
                        });
                    }
                    let reverted = write_with_retry_when(state, is_own_record, |rec| {
                        Ok((
                            exited_status.clone(),
                            SupervisionState::new(None, rec.health(), restart_count),
                        ))
                    });
                    return Ok(match reverted {
                        Ok(_) => SuperviseOutcome::Stopped {
                            last,
                            process: None,
                            late: cleanup_late,
                            restarts,
                        },
                        Err(error) => {
                            observe(Some(error.code()));
                            SuperviseOutcome::RestartUnrecorded {
                                error,
                                terminate_error: None,
                                late: cleanup_late,
                                restarts,
                            }
                        }
                    });
                }
                observe(None);
                restarts = restarts.saturating_add(1);
                process = new_process;
            }
            Err(error) => {
                observe(Some(error.code()));
                // 記録できない生存プロセスを残さない（core `start` の後始末と同じ方針）。
                // 上限を呼び出し境界で強制し、終了未確認のハンドルは `cleanup_late` から回収できる（REPAIR-5）。
                let terminate_error = terminate_bounded(
                    new_process,
                    restart_config.terminate_timeout,
                    &cleanup_late,
                    spawn_os_thread,
                )
                .err();
                return Ok(SuperviseOutcome::RestartUnrecorded {
                    error,
                    terminate_error,
                    late: cleanup_late,
                    restarts,
                });
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::ContainerState;

    fn sig(n: u8) -> ExitClass {
        ExitClass::Signaled {
            signal: Signal::new(n).expect("valid signal"),
        }
    }

    /// SUP-3・TASK-159.1: 終了コードの分類。
    #[test]
    fn sup3_task159_1_classify_exited() {
        assert_eq!(classify_exit(ProcessExit::Exited(0)), ExitClass::Success);
        assert_eq!(
            classify_exit(ProcessExit::Exited(1)),
            ExitClass::Failure { code: 1 }
        );
        assert_eq!(
            classify_exit(ProcessExit::Exited(255)),
            ExitClass::Failure { code: 255 }
        );
        assert_eq!(
            classify_exit(ProcessExit::Exited(-1)),
            ExitClass::Failure { code: -1 }
        );
    }

    /// SUP-3・TASK-159.1: シグナル種別の判別。
    #[test]
    fn sup3_task159_1_classify_signaled() {
        assert_eq!(
            classify_exit(ProcessExit::Signaled(9)),
            ExitClass::Signaled {
                signal: Signal::SIGKILL
            }
        );
        assert_eq!(
            classify_exit(ProcessExit::Signaled(15)),
            ExitClass::Signaled {
                signal: Signal::SIGTERM
            }
        );
        assert_eq!(classify_exit(ProcessExit::Signaled(64)), sig(64));
    }

    /// SUP-3・TASK-159.1: 範囲外シグナルは Unknown。
    #[test]
    fn sup3_task159_1_classify_out_of_range_signal() {
        for s in [0, 65, -1, i32::MAX] {
            assert_eq!(classify_exit(ProcessExit::Signaled(s)), ExitClass::Unknown);
        }
    }

    /// SUP-3・TASK-159.1: 状態ファイルへ書く終了コードの写像。
    #[test]
    fn sup3_task159_1_exit_code_of_table() {
        assert_eq!(exit_code_of(ProcessExit::Exited(0)), Some(0));
        assert_eq!(exit_code_of(ProcessExit::Exited(255)), Some(255));
        assert_eq!(exit_code_of(ProcessExit::Exited(-1)), Some(-1));
        assert_eq!(exit_code_of(ProcessExit::Signaled(9)), Some(137));
        assert_eq!(exit_code_of(ProcessExit::Signaled(15)), Some(143));
        assert_eq!(exit_code_of(ProcessExit::Signaled(64)), Some(192));
        assert_eq!(exit_code_of(ProcessExit::Signaled(0)), Some(128));
        assert_eq!(exit_code_of(ProcessExit::Signaled(65)), Some(193));
        assert_eq!(exit_code_of(ProcessExit::Signaled(-1)), Some(127));
        assert_eq!(exit_code_of(ProcessExit::Signaled(i32::MAX)), None);
    }

    /// SUP-3・TASK-159.1: 分類の異常判定（範囲外シグナルは `Unknown` で異常扱いしない）。
    #[test]
    fn sup3_task159_1_is_abnormal_classification() {
        assert!(!classify_exit(ProcessExit::Exited(0)).is_abnormal());
        assert!(classify_exit(ProcessExit::Exited(1)).is_abnormal());
        assert!(classify_exit(ProcessExit::Signaled(15)).is_abnormal());
        assert!(!classify_exit(ProcessExit::Signaled(65)).is_abnormal());
    }

    fn nz(n: u32) -> Option<NonZeroU32> {
        NonZeroU32::new(n)
    }

    fn dn(reason: NoRestartReason) -> RestartDecision {
        RestartDecision::DoNotRestart { reason }
    }

    fn ev(p: RestartPolicy, e: ExitClass, c: u32) -> RestartDecision {
        evaluate_restart(p, e, c, StopIntent::NotRequested)
    }

    fn all_exits() -> [ExitClass; 4] {
        [
            ExitClass::Success,
            ExitClass::Failure { code: 1 },
            sig(9),
            ExitClass::Unknown,
        ]
    }

    /// SUP-3・TASK-159.2: `no` は常に再起動しない。
    #[test]
    fn sup3_task159_2_policy_no() {
        for e in all_exits() {
            for c in [0, 5] {
                assert_eq!(ev(RestartPolicy::No, e, c), dn(NoRestartReason::PolicyNo));
            }
        }
    }

    /// SUP-3・TASK-159.2: `on-failure`（無制限）。
    #[test]
    fn sup3_task159_2_on_failure_unlimited() {
        let p = RestartPolicy::OnFailure { max_retries: None };
        assert_eq!(
            ev(p, ExitClass::Success, 0),
            dn(NoRestartReason::ExitedSuccessfully)
        );
        assert_eq!(
            ev(p, ExitClass::Unknown, 0),
            dn(NoRestartReason::UnclassifiedExit)
        );
        for e in [
            ExitClass::Failure { code: 1 },
            ExitClass::Failure { code: -1 },
            sig(15),
        ] {
            assert_eq!(ev(p, e, 0), RestartDecision::Restart);
            assert_eq!(ev(p, e, u32::MAX), RestartDecision::Restart);
        }
    }

    /// SUP-3・TASK-159.2: `on-failure:N` の上限。
    #[test]
    fn sup3_task159_2_on_failure_limited() {
        let p3 = RestartPolicy::OnFailure { max_retries: nz(3) };
        let f = ExitClass::Failure { code: 2 };
        for c in [0, 2] {
            assert_eq!(ev(p3, f, c), RestartDecision::Restart);
        }
        for c in [3, 4, u32::MAX] {
            assert_eq!(ev(p3, f, c), dn(NoRestartReason::RetriesExhausted));
        }
        assert_eq!(
            ev(p3, ExitClass::Success, 0),
            dn(NoRestartReason::ExitedSuccessfully)
        );
        let p1 = RestartPolicy::OnFailure { max_retries: nz(1) };
        assert_eq!(ev(p1, sig(9), 0), RestartDecision::Restart);
        assert_eq!(ev(p1, sig(9), 1), dn(NoRestartReason::RetriesExhausted));
    }

    /// SUP-3・TASK-159.2: `always` / `unless-stopped` は stop 要求なしなら常に再起動。
    #[test]
    fn sup3_task159_2_always_and_unless_stopped() {
        for p in [RestartPolicy::Always, RestartPolicy::UnlessStopped] {
            for e in all_exits() {
                for c in [0, u32::MAX] {
                    assert_eq!(ev(p, e, c), RestartDecision::Restart);
                }
            }
        }
    }

    /// SUP-3・TASK-159.2: stop 要求ありは全ポリシーで再起動しない。
    #[test]
    fn sup3_task159_2_explicit_stop() {
        let policies = [
            RestartPolicy::No,
            RestartPolicy::OnFailure { max_retries: None },
            RestartPolicy::OnFailure { max_retries: nz(3) },
            RestartPolicy::Always,
            RestartPolicy::UnlessStopped,
        ];
        for p in policies {
            for e in all_exits() {
                assert_eq!(
                    evaluate_restart(p, e, 0, StopIntent::Requested),
                    dn(NoRestartReason::ExplicitStop)
                );
            }
        }
    }

    /// SUP-3・TASK-159.2: `classify_exit` との連結（範囲外シグナルは Unknown）。
    #[test]
    fn sup3_task159_2_with_classify_exit() {
        let e = classify_exit(ProcessExit::Signaled(65));
        assert_eq!(
            ev(RestartPolicy::OnFailure { max_retries: None }, e, 0),
            dn(NoRestartReason::UnclassifiedExit)
        );
        assert_eq!(ev(RestartPolicy::Always, e, 0), RestartDecision::Restart);
    }

    /// SUP-3・TASK-159.2: ポリシー文字列の受理。
    #[test]
    fn sup3_task159_2_parse_accepts() {
        let cases = [
            ("no", RestartPolicy::No),
            ("always", RestartPolicy::Always),
            ("unless-stopped", RestartPolicy::UnlessStopped),
            ("on-failure", RestartPolicy::OnFailure { max_retries: None }),
            (
                "on-failure:1",
                RestartPolicy::OnFailure { max_retries: nz(1) },
            ),
            (
                "on-failure:4294967295",
                RestartPolicy::OnFailure {
                    max_retries: nz(u32::MAX),
                },
            ),
        ];
        for (s, want) in cases {
            assert_eq!(s.parse::<RestartPolicy>().expect(s), want);
        }
    }

    /// SUP-3・TASK-159.2: ポリシー文字列の拒否（`on-failure:0` は曖昧なため fail-closed）。
    #[test]
    fn sup3_task159_2_parse_rejects() {
        let long = "a".repeat(MAX_POLICY_LEN + 1);
        let cases = [
            "",
            "NO",
            " no",
            "no ",
            "always:1",
            "no:0",
            "on-failure:",
            "on-failure:0",
            "on-failure:-1",
            "on-failure:+1",
            "on-failure:1x",
            "on-failure:4294967296",
            "on-failure:1:2",
            "restart",
            long.as_str(),
        ];
        for s in cases {
            let err = s.parse::<RestartPolicy>().expect_err(s);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{s}");
        }
    }

    /// SUP-3・TASK-159.2: 既定値と理由の識別子。
    #[test]
    fn sup3_task159_2_default_and_reason_strings() {
        assert_eq!(RestartPolicy::default(), RestartPolicy::No);
        assert_eq!(NoRestartReason::PolicyNo.as_str(), "policy_no");
        assert_eq!(
            NoRestartReason::ExitedSuccessfully.as_str(),
            "exited_successfully"
        );
        assert_eq!(
            NoRestartReason::RetriesExhausted.as_str(),
            "retries_exhausted"
        );
        assert_eq!(NoRestartReason::ExplicitStop.as_str(), "explicit_stop");
        assert_eq!(
            NoRestartReason::UnclassifiedExit.as_str(),
            "unclassified_exit"
        );
    }
    // ---- supervise_with_restart（SUP-3・TASK-159.3。メモリ上の fake で 3 OS 共通に検証） ----

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use fandhe_container_core::traits::{
        ContainerId, CreateStateRequest, DeleteStateRequest, DeleteStateResponse, GetStateRequest,
        HealthStatus, ListStateRequest, StateList, StateRecord, StateRevision, StateStore,
        UpdateStateRequest,
    };

    fn cid() -> ContainerId {
        ContainerId::new("c1").unwrap()
    }

    fn pidn(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    /// メモリ上の 1 レコードストア。`conflicts` 回だけ外部更新（health の反転。restart_count は変えない）で競合させる。
    struct Store {
        rec: Mutex<StateRecord>,
        conflicts: Mutex<u32>,
        /// `restart_count` を進める書き込み（再起動の `Running` 記録）の成功直前に停止要求を立てる。
        /// `true` なら、その書き込みの直後に別の supervisor（pid 999）が監視権を取った状態にする。
        stop_on_restart_write: Mutex<Option<(StopToken, bool)>>,
    }

    impl StateStore for Store {
        fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "fake"))
        }
        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            let mut g = self.rec.lock().unwrap();
            let mut c = self.conflicts.lock().unwrap();
            let bump = |g: &StateRecord, sup: SupervisionState, st: ContainerStatus| {
                StateRecord::new(
                    st,
                    g.bundle().to_path_buf(),
                    StateRevision::from_raw(g.revision().value() + 1),
                )
                .unwrap()
                .with_supervision(sup)
            };
            if *c > 0 {
                *c -= 1;
                let sup = g.supervision();
                let flipped = match sup.health() {
                    Some(HealthStatus::Healthy) => HealthStatus::Unhealthy,
                    _ => HealthStatus::Healthy,
                };
                let s =
                    SupervisionState::new(sup.supervisor_pid(), Some(flipped), sup.restart_count());
                *g = bump(&g, s, g.status().clone());
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            if g.revision() != req.expected_revision() {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            let s = req.supervision().unwrap_or_else(|| g.supervision());
            let hook = if s.restart_count() > g.restart_count() {
                self.stop_on_restart_write.lock().unwrap().clone()
            } else {
                None
            };
            let next = bump(&g, s, req.status().clone());
            *g = next.clone();
            if let Some((stop, foreign_claim)) = hook {
                stop.request_stop();
                if foreign_claim {
                    let claimed =
                        SupervisionState::new(Some(pidn(999)), s.health(), s.restart_count());
                    *g = bump(&g, claimed, g.status().clone());
                }
            }
            Ok(next)
        }
        fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
            Ok(self.rec.lock().unwrap().clone())
        }
        fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "fake"))
        }
        fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "fake"))
        }
    }

    fn store(initial_count: u32, first_pid: u32) -> Arc<Store> {
        let rec = StateRecord::new(
            ContainerStatus::running(cid(), Some(pidn(first_pid))),
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .unwrap()
        .with_supervision(SupervisionState::new(
            None,
            Some(HealthStatus::Healthy),
            initial_count,
        ));
        Arc::new(Store {
            rec: Mutex::new(rec),
            conflicts: Mutex::new(0),
            stop_on_restart_write: Mutex::new(None),
        })
    }

    fn attach(store: &Arc<Store>) -> SupervisedState {
        SupervisedState::attach(store.clone(), cid()).unwrap()
    }

    /// 最初の `wait` で `exit` を返す疑似プロセス。`terminate` の呼び出し回数を共有カウンタへ数える。
    struct Fp {
        pid: u32,
        exit: ProcessExit,
        terminated: Arc<AtomicU32>,
    }

    impl LaunchedProcess for Fp {
        fn pid(&self) -> NonZeroU32 {
            pidn(self.pid)
        }
        fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(Some(self.exit))
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            self.terminated.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// 用意した (pid, exit) を順に返し、尽きたら `Unavailable` で失敗する再 launch。
    struct Queue {
        items: Mutex<VecDeque<(u32, ProcessExit)>>,
        calls: AtomicU32,
        terminated: Arc<AtomicU32>,
        /// 再 launch の直前に store を競合させる（`Running` 記録を失敗させる）。
        sabotage: Option<Arc<Store>>,
    }

    impl Queue {
        fn new(items: &[(u32, ProcessExit)]) -> Self {
            Self {
                items: Mutex::new(items.iter().copied().collect()),
                calls: AtomicU32::new(0),
                terminated: Arc::new(AtomicU32::new(0)),
                sabotage: None,
            }
        }
    }

    impl Relauncher for Queue {
        fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(s) = &self.sabotage {
                *s.conflicts.lock().unwrap() = 100;
            }
            let next = self.items.lock().unwrap().pop_front();
            match next {
                Some((pid, exit)) => Ok(Box::new(Fp {
                    pid,
                    exit,
                    terminated: self.terminated.clone(),
                })),
                None => Err(TraitError::new(ErrorCode::Unavailable, "no more processes")),
            }
        }
    }

    #[derive(Default)]
    struct Events(Mutex<Vec<(MonitorOperation, Option<ErrorCode>)>>);

    impl MonitorObserver for Events {
        fn observe(&self, e: &MonitorEvent) {
            self.0.lock().unwrap().push((e.operation, e.error_code));
        }
    }

    impl Events {
        fn count(&self, op: MonitorOperation) -> usize {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(o, _)| *o == op)
                .count()
        }
    }

    fn first(exit: ProcessExit) -> Box<dyn LaunchedProcess> {
        Box::new(Fp {
            pid: 42,
            exit,
            terminated: Arc::new(AtomicU32::new(0)),
        })
    }

    fn cfg(policy: &str) -> RestartConfig {
        RestartConfig::new(policy.parse().unwrap())
            .with_backoff(Duration::ZERO)
            .unwrap()
    }

    /// テスト用: 具象の再 launch を trait object の `Arc` へ写す。
    fn rl<T: Relauncher + 'static>(q: &Arc<T>) -> Arc<dyn Relauncher> {
        q.clone()
    }

    fn run(
        store: &Arc<Store>,
        policy: &str,
        exit: ProcessExit,
        q: &Arc<Queue>,
        stop: &StopToken,
        obs: &Events,
    ) -> SuperviseOutcome {
        let mut s = attach(store);
        supervise_with_restart(
            &mut s,
            first(exit),
            &rl(q),
            &MonitorConfig::default(),
            &cfg(policy),
            stop,
            obs,
        )
        .unwrap()
    }

    const FAIL: ProcessExit = ProcessExit::Exited(1);

    /// SUP-3・TASK-159.3: `always` は再起動ごとに restart_count が 1・2・3 と増え、
    /// 再 launch が尽きた時点（3 回再起動後）で RelaunchFailed・restart_count == 3・状態は Stopped。
    #[test]
    fn sup3_task159_3_always_counts_each_restart() {
        let st = store(0, 42);
        let q = Arc::new(Queue::new(&[
            (43, FAIL),
            (44, ProcessExit::Exited(0)),
            (45, FAIL),
        ]));
        let obs = Events::default();
        let out = run(&st, "always", FAIL, &q, &StopToken::new(), &obs);
        let SuperviseOutcome::RelaunchFailed { exit, restarts, .. } = out else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(exit, FAIL);
        assert_eq!(restarts, 3);
        let g = st.rec.lock().unwrap();
        assert_eq!(g.restart_count(), 3);
        assert_eq!(g.status().state(), ContainerState::Stopped);
        assert_eq!(g.health(), Some(HealthStatus::Healthy));
        assert_eq!(obs.count(MonitorOperation::Restart), 4);
        assert_eq!(
            obs.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(o, c)| *o == MonitorOperation::Restart && c.is_none())
                .count(),
            3
        );
    }

    /// SUP-3・TASK-159.3: `on-failure:2` は異常終了 3 回で再起動 2 回、restart_count == 2、RetriesExhausted。
    #[test]
    fn sup3_task159_3_on_failure_limit_stops_at_n() {
        let st = store(0, 42);
        let q = Arc::new(Queue::new(&[(43, FAIL), (44, FAIL), (45, FAIL)]));
        let out = run(
            &st,
            "on-failure:2",
            FAIL,
            &q,
            &StopToken::new(),
            &Events::default(),
        );
        let SuperviseOutcome::Finished {
            reason, restarts, ..
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(reason, NoRestartReason::RetriesExhausted);
        assert_eq!(restarts, 2);
        assert_eq!(q.calls.load(Ordering::SeqCst), 2);
        let g = st.rec.lock().unwrap();
        assert_eq!(g.restart_count(), 2);
        assert_eq!(g.status().state(), ContainerState::Stopped);
        assert_eq!(g.supervisor_pid(), None);
    }

    /// SUP-3・TASK-159.3: `on-failure` は正常終了で再起動せず、restart_count は不変。
    #[test]
    fn sup3_task159_3_on_failure_does_not_restart_on_success() {
        let st = store(4, 42);
        let q = Arc::new(Queue::new(&[(43, FAIL)]));
        let out = run(
            &st,
            "on-failure",
            ProcessExit::Exited(0),
            &q,
            &StopToken::new(),
            &Events::default(),
        );
        let SuperviseOutcome::Finished {
            reason, restarts, ..
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(reason, NoRestartReason::ExitedSuccessfully);
        assert_eq!(restarts, 0);
        assert_eq!(q.calls.load(Ordering::SeqCst), 0);
        assert_eq!(st.rec.lock().unwrap().restart_count(), 4);
    }

    /// SUP-3・TASK-159.3: `no` は異常終了でも再起動せず、restart_count は不変。
    #[test]
    fn sup3_task159_3_policy_no_does_not_restart() {
        let st = store(0, 42);
        let q = Arc::new(Queue::new(&[(43, FAIL)]));
        let out = run(&st, "no", FAIL, &q, &StopToken::new(), &Events::default());
        let SuperviseOutcome::Finished { reason, .. } = out else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(reason, NoRestartReason::PolicyNo);
        assert_eq!(st.rec.lock().unwrap().restart_count(), 0);
        assert_eq!(q.calls.load(Ordering::SeqCst), 0);
    }

    /// SUP-3・TASK-159.3: 再 launch 失敗は restart_count を進めず、状態は Stopped のまま。
    #[test]
    fn sup3_task159_3_relaunch_failure_does_not_count() {
        let st = store(1, 42);
        let q = Arc::new(Queue::new(&[]));
        let obs = Events::default();
        let out = run(&st, "always", FAIL, &q, &StopToken::new(), &obs);
        let SuperviseOutcome::RelaunchFailed {
            error, restarts, ..
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert_eq!(restarts, 0);
        let g = st.rec.lock().unwrap();
        assert_eq!(g.restart_count(), 1);
        assert_eq!(g.status().state(), ContainerState::Stopped);
        assert_eq!(
            obs.0.lock().unwrap().last(),
            Some(&(MonitorOperation::Restart, Some(ErrorCode::Unavailable)))
        );
    }

    /// SUP-3・TASK-159.3: `Running` の再記録に失敗したら新プロセスを terminate し（1 回）、restart_count は進めない。
    #[test]
    fn sup3_task159_3_unrecorded_restart_terminates_new_process() {
        let st = store(0, 42);
        let mut q = Queue::new(&[(43, FAIL)]);
        q.sabotage = Some(st.clone());
        let q = Arc::new(q);
        let out = run(
            &st,
            "always",
            FAIL,
            &q,
            &StopToken::new(),
            &Events::default(),
        );
        let SuperviseOutcome::RestartUnrecorded {
            error,
            terminate_error,
            late,
            restarts,
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(error.code(), ErrorCode::FailedPrecondition);
        assert!(terminate_error.is_none());
        assert!(late.wait_settled(Duration::from_secs(5)));
        assert!(late.take().is_empty());
        assert_eq!(restarts, 0);
        assert_eq!(q.terminated.load(Ordering::SeqCst), 1);
        let g = st.rec.lock().unwrap();
        assert_eq!(g.status().state(), ContainerState::Stopped);
        // 競合は health の反転のみで、自分の加算は載らない。
        assert_eq!(g.restart_count(), 0);
    }

    /// SUP-3・TASK-159.3: 競合 1 回（外部が health を更新）の後も外部の更新を消さず、自分の +1 が載る（1 -> 2）。
    #[test]
    fn sup3_task159_3_increment_survives_revision_conflict() {
        let st = store(1, 42);
        // 競合は再 launch 直後の書き込みで 1 回だけ起こす。
        struct OneConflict(Queue, Arc<Store>);
        impl Relauncher for OneConflict {
            fn relaunch(&self, t: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
                *self.1.conflicts.lock().unwrap() = 1;
                self.0.relaunch(t)
            }
        }
        let q = Arc::new(OneConflict(
            Queue::new(&[(43, ProcessExit::Exited(0))]),
            st.clone(),
        ));
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            first(FAIL),
            &rl(&q),
            &MonitorConfig::default(),
            &cfg("always"),
            &StopToken::new(),
            &Events::default(),
        )
        .unwrap();
        // 2 周目の終了後は再 launch が尽きて失敗する。
        assert!(matches!(out, SuperviseOutcome::RelaunchFailed { .. }));
        // 初期 1 + 自分の再起動 1 = 2（競合は health のみで、再 launch 失敗は数えない）。
        assert_eq!(st.rec.lock().unwrap().restart_count(), 2);
    }

    /// SUP-3・TASK-159.3: 競合後に別の遷移（別の終了コードの Stopped）が入っていたら Running で上書きせず、
    /// 新プロセスを後始末して RestartUnrecorded で戻る。
    #[test]
    fn sup3_task159_3_changed_exit_record_aborts_restart() {
        let st = store(0, 42);
        struct Interleave(Queue, Arc<Store>);
        impl Relauncher for Interleave {
            fn relaunch(&self, t: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
                // 再 launch 中に別処理が Stopped（別コード）へ書き換え、直後の書き込みを競合させる。
                {
                    let mut g = self.1.rec.lock().unwrap();
                    let next = StateRecord::new(
                        ContainerStatus::stopped(cid(), Some(99)),
                        g.bundle().to_path_buf(),
                        StateRevision::from_raw(g.revision().value() + 1),
                    )
                    .unwrap()
                    .with_supervision(g.supervision());
                    *g = next;
                }
                *self.1.conflicts.lock().unwrap() = 1;
                self.0.relaunch(t)
            }
        }
        let q = Arc::new(Interleave(
            Queue::new(&[(43, ProcessExit::Exited(0))]),
            st.clone(),
        ));
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            first(FAIL),
            &rl(&q),
            &MonitorConfig::default(),
            &cfg("always"),
            &StopToken::new(),
            &Events::default(),
        )
        .unwrap();
        assert!(matches!(out, SuperviseOutcome::RestartUnrecorded { .. }));
        let g = st.rec.lock().unwrap();
        assert_eq!(g.status().state(), ContainerState::Stopped);
        assert_eq!(g.status().exit_code(), Some(99));
        // 自分の再起動は数えない。
        assert_eq!(g.restart_count(), 0);
    }

    /// SUP-3・TASK-159.3: 別処理が再起動して同じ終了コードで再び Stopped になっても（restart_count が進む）、
    /// 自分の終了記録ではないため Running で上書きせず、新プロセスを回収して中止する。
    #[test]
    fn sup3_task159_3_same_exit_after_foreign_restart_aborts() {
        let st = store(0, 42);
        struct Foreign(Queue, Arc<Store>);
        impl Relauncher for Foreign {
            fn relaunch(&self, t: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
                // 別処理が再起動し（count +1）、同じ終了コードで再び Stopped へ戻した状態を作る。
                {
                    let mut g = self.1.rec.lock().unwrap();
                    let sup = g.supervision();
                    let next = StateRecord::new(
                        g.status().clone(),
                        g.bundle().to_path_buf(),
                        StateRevision::from_raw(g.revision().value() + 1),
                    )
                    .unwrap()
                    .with_supervision(SupervisionState::new(
                        None,
                        sup.health(),
                        sup.restart_count() + 1,
                    ));
                    *g = next;
                }
                *self.1.conflicts.lock().unwrap() = 1;
                self.0.relaunch(t)
            }
        }
        let q = Arc::new(Foreign(
            Queue::new(&[(43, ProcessExit::Exited(0))]),
            st.clone(),
        ));
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            first(FAIL),
            &rl(&q),
            &MonitorConfig::default(),
            &cfg("always"),
            &StopToken::new(),
            &Events::default(),
        )
        .unwrap();
        let SuperviseOutcome::RestartUnrecorded {
            terminate_error,
            late,
            restarts,
            ..
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert!(terminate_error.is_none());
        assert!(late.wait_settled(Duration::from_secs(5)));
        assert!(late.take().is_empty());
        assert_eq!(restarts, 0);
        assert_eq!(q.0.terminated.load(Ordering::SeqCst), 1);
        let g = st.rec.lock().unwrap();
        assert_eq!(g.status().state(), ContainerState::Stopped);
        assert_eq!(g.restart_count(), 1);
    }

    /// SUP-3・TASK-159.3: restart_count は u32::MAX で頭打ちになり panic しない。
    #[test]
    fn sup3_task159_3_restart_count_saturates() {
        let st = store(u32::MAX, 42);
        let q = Arc::new(Queue::new(&[(43, FAIL)]));
        let out = run(
            &st,
            "always",
            FAIL,
            &q,
            &StopToken::new(),
            &Events::default(),
        );
        assert!(matches!(
            out,
            SuperviseOutcome::RelaunchFailed { restarts: 1, .. }
        ));
        assert_eq!(st.rec.lock().unwrap().restart_count(), u32::MAX);
    }

    /// SUP-3・TASK-159.3: 終了後に停止要求があれば `ExplicitStop` で再起動しない。
    #[test]
    fn sup3_task159_3_stop_requested_after_exit_does_not_restart() {
        let st = store(0, 42);
        let q = Arc::new(Queue::new(&[(43, FAIL)]));
        let stop = StopToken::new();
        // 周回の先頭の確認をすり抜けるよう、wait 中に停止を要求する疑似プロセスを使う。
        struct StopsOnWait(StopToken);
        impl LaunchedProcess for StopsOnWait {
            fn pid(&self) -> NonZeroU32 {
                pidn(42)
            }
            fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
                self.0.request_stop();
                Ok(Some(FAIL))
            }
            fn terminate(&self, _: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            Box::new(StopsOnWait(stop.clone())),
            &rl(&q),
            &MonitorConfig::default(),
            &cfg("always"),
            &stop,
            &Events::default(),
        )
        .unwrap();
        let SuperviseOutcome::Finished { reason, .. } = out else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(reason, NoRestartReason::ExplicitStop);
        assert_eq!(q.calls.load(Ordering::SeqCst), 0);
    }

    /// SUP-3・TASK-159.3・REPAIR-5: バックオフ中の停止要求で再 launch せず、有限時間で戻る。
    #[test]
    fn sup3_task159_3_stop_during_backoff_returns_without_relaunch() {
        let st = store(0, 42);
        let q = Arc::new(Queue::new(&[(43, FAIL)]));
        let stop = StopToken::new();
        let config = RestartConfig::new(RestartPolicy::Always)
            .with_backoff(Duration::from_secs(30))
            .unwrap();
        let t = stop.clone();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            t.request_stop();
        });
        let started = Instant::now();
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            first(FAIL),
            &rl(&q),
            &MonitorConfig::default(),
            &config,
            &stop,
            &Events::default(),
        )
        .unwrap();
        h.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        let SuperviseOutcome::Stopped {
            process, restarts, ..
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert!(process.is_none());
        assert_eq!(restarts, 0);
        assert_eq!(q.calls.load(Ordering::SeqCst), 0);
    }

    /// terminate が必ず失敗する起動ハンドル。
    struct StuckProc(u32);

    impl LaunchedProcess for StuckProc {
        fn pid(&self) -> NonZeroU32 {
            pidn(self.0)
        }
        fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(None)
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            Err(TraitError::new(ErrorCode::Timeout, "stuck"))
        }
    }

    struct StuckRelauncher(Arc<Store>);

    impl Relauncher for StuckRelauncher {
        fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            *self.0.conflicts.lock().unwrap() = 100;
            Ok(Box::new(StuckProc(43)))
        }
    }

    /// SUP-3・REPAIR-5・TASK-159.3: 記録失敗後に terminate も失敗したら、新プロセスのハンドルを呼び出し側へ返す。
    #[test]
    fn sup3_task159_3_unrecorded_and_terminate_failed_returns_handle() {
        let st = store(0, 42);
        let q: Arc<dyn Relauncher> = Arc::new(StuckRelauncher(st.clone()));
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            first(FAIL),
            &q,
            &MonitorConfig::default(),
            &cfg("always"),
            &StopToken::new(),
            &Events::default(),
        )
        .unwrap();
        let SuperviseOutcome::RestartUnrecorded {
            terminate_error,
            late,
            ..
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(terminate_error.map(|e| e.code()), Some(ErrorCode::Timeout));
        assert!(late.wait_settled(Duration::from_secs(5)));
        let got = late.take();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.pid().get(), 43);
    }

    /// 期限を超えて応答しない再 launch（戻った後は生存プロセスを返す）。
    struct SlowRelauncher {
        delay: Duration,
        terminated: Arc<AtomicU32>,
    }

    impl Relauncher for SlowRelauncher {
        fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            std::thread::sleep(self.delay);
            Ok(Box::new(Fp {
                pid: 43,
                exit: FAIL,
                terminated: self.terminated.clone(),
            }))
        }
    }

    /// REPAIR-5・SUP-3・TASK-159.3: 応答しない再 launch でも監視ループは上限で戻り（Timeout・count 不変）、
    /// 期限後に戻ったプロセスは terminate される。
    #[test]
    fn sup3_task159_3_unresponsive_relaunch_is_bounded() {
        let st = store(0, 42);
        let terminated = Arc::new(AtomicU32::new(0));
        let q: Arc<dyn Relauncher> = Arc::new(SlowRelauncher {
            delay: Duration::from_millis(1500),
            terminated: terminated.clone(),
        });
        let config = cfg("always")
            .with_relaunch_timeout(Duration::from_millis(50))
            .unwrap();
        let started = Instant::now();
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            first(FAIL),
            &q,
            &MonitorConfig::default(),
            &config,
            &StopToken::new(),
            &Events::default(),
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_millis(1400));
        let SuperviseOutcome::RelaunchFailed {
            error, restarts, ..
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(error.code(), ErrorCode::Timeout);
        assert_eq!(restarts, 0);
        assert_eq!(st.rec.lock().unwrap().restart_count(), 0);
        let end = Instant::now() + Duration::from_secs(5);
        while terminated.load(Ordering::SeqCst) == 0 && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(terminated.load(Ordering::SeqCst), 1);
    }

    /// SUP-3・TASK-159.3: 状態が不確かな終了（ExitedUnrecorded）では再 launch しない（fail-closed）。
    #[test]
    fn sup3_task159_3_unrecorded_exit_does_not_relaunch() {
        let st = store(0, 42);
        let q = Arc::new(Queue::new(&[(43, FAIL)]));
        struct Racy(Arc<Store>);
        impl LaunchedProcess for Racy {
            fn pid(&self) -> NonZeroU32 {
                pidn(42)
            }
            fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
                *self.0.conflicts.lock().unwrap() = 100;
                Ok(Some(FAIL))
            }
            fn terminate(&self, _: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            Box::new(Racy(st.clone())),
            &rl(&q),
            &MonitorConfig::default(),
            &cfg("always"),
            &StopToken::new(),
            &Events::default(),
        )
        .unwrap();
        assert!(matches!(
            out,
            SuperviseOutcome::MonitorFailed { restarts: 0, .. }
        ));
        assert_eq!(q.calls.load(Ordering::SeqCst), 0);
    }

    /// wait が常に失敗する起動ハンドル（終了未確認のまま monitor が Err になる）。
    struct WaitFails;

    impl LaunchedProcess for WaitFails {
        fn pid(&self) -> NonZeroU32 {
            pidn(42)
        }
        fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "wait failure"))
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            Ok(())
        }
    }

    /// SUP-3・REPAIR-5・TASK-159.3: monitor が Err（wait 失敗）で戻っても、生存の可能性がある起動ハンドルを
    /// 捨てず呼び出し側へ返す。再 launch はしない。
    #[test]
    fn sup3_task159_3_monitor_error_returns_handle() {
        let st = store(0, 42);
        let q = Arc::new(Queue::new(&[(43, FAIL)]));
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            Box::new(WaitFails),
            &rl(&q),
            &MonitorConfig::default(),
            &cfg("always"),
            &StopToken::new(),
            &Events::default(),
        )
        .unwrap();
        let SuperviseOutcome::MonitorError {
            error,
            process,
            restarts,
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(error.code(), ErrorCode::Internal);
        assert_eq!(process.pid().get(), 42);
        assert_eq!(restarts, 0);
        assert_eq!(q.calls.load(Ordering::SeqCst), 0);
    }

    /// 期限後に terminate 不能なプロセスを返す再 launch。
    struct SlowStuckRelauncher;

    impl Relauncher for SlowStuckRelauncher {
        fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            std::thread::sleep(Duration::from_millis(1200));
            Ok(Box::new(StuckProc(44)))
        }
    }

    /// REPAIR-5・SUP-3・TASK-159.3: 期限超過後に戻ったプロセスの terminate が失敗したら、
    /// ハンドルと失敗理由を `LateOrphans` から回収できる（捨てない）。
    #[test]
    fn sup3_task159_3_late_relaunch_terminate_failure_is_recoverable() {
        let st = store(0, 42);
        let q: Arc<dyn Relauncher> = Arc::new(SlowStuckRelauncher);
        let config = cfg("always")
            .with_relaunch_timeout(Duration::from_millis(50))
            .unwrap();
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            first(FAIL),
            &q,
            &MonitorConfig::default(),
            &config,
            &StopToken::new(),
            &Events::default(),
        )
        .unwrap();
        let SuperviseOutcome::RelaunchFailed { error, late, .. } = out else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(error.code(), ErrorCode::Timeout);
        // 実行スレッドの完了を待ってから回収する（空の take で終えない。REPAIR-5）。
        assert!(late.wait_settled(Duration::from_secs(5)));
        assert!(late.is_settled());
        let got = late.take();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.pid().get(), 44);
        assert_eq!(got[0].1.code(), ErrorCode::Timeout);
    }

    /// 再 launch 中に停止要求を立てて新プロセスを返す再 launch。
    struct StopsDuringRelaunch {
        stop: StopToken,
        stuck: bool,
        terminated: Arc<AtomicU32>,
    }

    impl Relauncher for StopsDuringRelaunch {
        fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            self.stop.request_stop();
            if self.stuck {
                return Ok(Box::new(StuckProc(43)));
            }
            Ok(Box::new(Fp {
                pid: 43,
                exit: FAIL,
                terminated: self.terminated.clone(),
            }))
        }
    }

    /// SUP-3・TASK-159.3: 再 launch 中に停止要求が来たら、Running を記録せず新プロセスを terminate して戻る。
    /// restart_count は進まず、状態は Stopped のまま。
    #[test]
    fn sup3_task159_3_stop_during_relaunch_terminates_new_process() {
        let st = store(0, 42);
        let stop = StopToken::new();
        let terminated = Arc::new(AtomicU32::new(0));
        let q: Arc<dyn Relauncher> = Arc::new(StopsDuringRelaunch {
            stop: stop.clone(),
            stuck: false,
            terminated: terminated.clone(),
        });
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            first(FAIL),
            &q,
            &MonitorConfig::default(),
            &cfg("always"),
            &stop,
            &Events::default(),
        )
        .unwrap();
        let SuperviseOutcome::Stopped {
            process,
            late,
            restarts,
            ..
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert!(process.is_none());
        assert!(late.wait_settled(Duration::from_secs(5)));
        assert!(late.take().is_empty());
        assert_eq!(restarts, 0);
        assert_eq!(terminated.load(Ordering::SeqCst), 1);
        let rec = st.rec.lock().unwrap();
        assert_eq!(rec.restart_count(), 0);
        assert_eq!(rec.status().state(), ContainerState::Stopped);
    }

    /// SUP-3・TASK-159.3: 最終確認と `Running` 記録の間に届いた停止要求では、記録を元の終了記録へ戻して
    /// 新プロセスを terminate する。restart_count == 0・状態は Stopped（終了コード 1）・監視権なしで、
    /// 再起動は数えず（restarts == 0・Restart 通知 0 件）、以後の再 launch もしない（relaunch は 1 回のまま）。
    #[test]
    fn sup3_task159_3_stop_racing_running_record_reverts_and_terminates() {
        let st = store(0, 42);
        let stop = StopToken::new();
        *st.stop_on_restart_write.lock().unwrap() = Some((stop.clone(), false));
        let q = Arc::new(Queue::new(&[(43, FAIL), (44, FAIL)]));
        let obs = Events::default();
        let out = run(&st, "always", FAIL, &q, &stop, &obs);
        let SuperviseOutcome::Stopped {
            process,
            late,
            restarts,
            ..
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert!(process.is_none());
        assert_eq!(restarts, 0);
        assert!(late.wait_settled(Duration::from_secs(5)));
        assert!(late.take().is_empty());
        assert_eq!(q.calls.load(Ordering::SeqCst), 1);
        assert_eq!(q.terminated.load(Ordering::SeqCst), 1);
        assert_eq!(obs.count(MonitorOperation::Restart), 0);
        let rec = st.rec.lock().unwrap();
        assert_eq!(rec.restart_count(), 0);
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(rec.status().exit_code(), Some(1));
        assert_eq!(rec.status().pid(), None);
        assert_eq!(rec.supervision().supervisor_pid(), None);
        assert_eq!(rec.health(), Some(HealthStatus::Healthy));
    }

    /// SUP-3・REPAIR-5・TASK-159.3: 停止要求と競合した `Running` 記録を、別の supervisor（pid 999）が監視権を
    /// 取ったため戻せない場合は、新プロセスを terminate せずハンドル（pid 43）を返す。記録は Running(43)・
    /// restart_count == 1・監視権 999 のまま（他者の遷移を上書きしない）で、再起動 1 回として数える。
    #[test]
    fn sup3_task159_3_stop_racing_running_record_keeps_foreign_claim() {
        let st = store(0, 42);
        let stop = StopToken::new();
        *st.stop_on_restart_write.lock().unwrap() = Some((stop.clone(), true));
        let q = Arc::new(Queue::new(&[(43, FAIL), (44, FAIL)]));
        let obs = Events::default();
        let out = run(&st, "always", FAIL, &q, &stop, &obs);
        let SuperviseOutcome::MonitorError {
            error,
            process,
            restarts,
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(error.code(), ErrorCode::FailedPrecondition);
        assert_eq!(process.pid().get(), 43);
        assert_eq!(restarts, 1);
        assert_eq!(q.calls.load(Ordering::SeqCst), 1);
        assert_eq!(q.terminated.load(Ordering::SeqCst), 0);
        assert_eq!(obs.count(MonitorOperation::Restart), 1);
        let rec = st.rec.lock().unwrap();
        assert_eq!(rec.restart_count(), 1);
        assert_eq!(rec.status().state(), ContainerState::Running);
        assert_eq!(rec.status().pid().map(NonZeroU32::get), Some(43));
        assert_eq!(
            rec.supervision().supervisor_pid().map(NonZeroU32::get),
            Some(999)
        );
    }

    /// 新プロセスを 1 回だけ返す再 launch（テストごとに terminate の挙動を変える）。
    struct Once(Mutex<Option<Box<dyn LaunchedProcess>>>);

    impl Relauncher for Once {
        fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            self.0
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| TraitError::new(ErrorCode::Unavailable, "no more processes"))
        }
    }

    fn run_once(
        st: &Arc<Store>,
        proc: Box<dyn LaunchedProcess>,
        stop: &StopToken,
    ) -> SuperviseOutcome {
        let q: Arc<dyn Relauncher> = Arc::new(Once(Mutex::new(Some(proc))));
        let mut s = attach(st);
        supervise_with_restart(
            &mut s,
            first(FAIL),
            &q,
            &MonitorConfig::default(),
            &cfg("always"),
            stop,
            &Events::default(),
        )
        .unwrap()
    }

    /// SUP-3・REPAIR-5・TASK-159.3: 停止要求と競合した `Running` 記録の取り消しで、新プロセスの終了を確認できない
    /// （terminate が Timeout）場合は `Stopped` へ戻さない。記録は Running(43)・restart_count == 1 のままで、
    /// ハンドル（pid 43）は `late` から回収でき、restarts は記録済みの 1 回を含む。
    #[test]
    fn sup3_task159_3_stop_racing_running_record_keeps_running_when_terminate_fails() {
        let st = store(0, 42);
        let stop = StopToken::new();
        *st.stop_on_restart_write.lock().unwrap() = Some((stop.clone(), false));
        let out = run_once(&st, Box::new(StuckProc(43)), &stop);
        let SuperviseOutcome::Stopped {
            process,
            late,
            restarts,
            ..
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert!(process.is_none());
        assert_eq!(restarts, 1);
        assert!(late.wait_settled(Duration::from_secs(5)));
        let got = late.take();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.pid().get(), 43);
        assert_eq!(got[0].1.code(), ErrorCode::Timeout);
        let rec = st.rec.lock().unwrap();
        assert_eq!(rec.restart_count(), 1);
        assert_eq!(rec.status().state(), ContainerState::Running);
        assert_eq!(rec.status().pid().map(NonZeroU32::get), Some(43));
    }

    /// terminate に成功するが、その間に別の supervisor（pid 999）が監視権を取る起動ハンドル。
    struct ClaimedWhileTerminating(Arc<Store>);

    impl LaunchedProcess for ClaimedWhileTerminating {
        fn pid(&self) -> NonZeroU32 {
            pidn(43)
        }
        fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(None)
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            let mut g = self.0.rec.lock().unwrap();
            let claimed = SupervisionState::new(Some(pidn(999)), g.health(), g.restart_count());
            let next = StateRecord::new(
                g.status().clone(),
                g.bundle().to_path_buf(),
                StateRevision::from_raw(g.revision().value() + 1),
            )
            .unwrap()
            .with_supervision(claimed);
            *g = next;
            Ok(())
        }
    }

    /// SUP-3・REPAIR-5・TASK-159.3: 新プロセスの終了確認後に記録を戻せない（別の supervisor が監視権を取った）場合は
    /// `RestartUnrecorded`（FailedPrecondition・terminate_error なし・restarts == 0）で返し、他者の記録
    /// （Running(43)・restart_count == 1・監視権 999）を上書きしない。
    #[test]
    fn sup3_task159_3_stop_racing_running_record_reports_unreverted_record() {
        let st = store(0, 42);
        let stop = StopToken::new();
        *st.stop_on_restart_write.lock().unwrap() = Some((stop.clone(), false));
        let out = run_once(&st, Box::new(ClaimedWhileTerminating(st.clone())), &stop);
        let SuperviseOutcome::RestartUnrecorded {
            error,
            terminate_error,
            late,
            restarts,
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(error.code(), ErrorCode::FailedPrecondition);
        assert_eq!(terminate_error.map(|e| e.code()), None);
        assert_eq!(restarts, 0);
        assert!(late.wait_settled(Duration::from_secs(5)));
        assert!(late.take().is_empty());
        let rec = st.rec.lock().unwrap();
        assert_eq!(rec.restart_count(), 1);
        assert_eq!(rec.status().state(), ContainerState::Running);
        assert_eq!(rec.status().pid().map(NonZeroU32::get), Some(43));
        assert_eq!(
            rec.supervision().supervisor_pid().map(NonZeroU32::get),
            Some(999)
        );
    }

    /// SUP-3・REPAIR-5・TASK-159.3: 停止要求後の新プロセスの terminate が失敗したらハンドルを返す。
    #[test]
    fn sup3_task159_3_stop_during_relaunch_terminate_failure_returns_handle() {
        let st = store(0, 42);
        let stop = StopToken::new();
        let q: Arc<dyn Relauncher> = Arc::new(StopsDuringRelaunch {
            stop: stop.clone(),
            stuck: true,
            terminated: Arc::new(AtomicU32::new(0)),
        });
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            first(FAIL),
            &q,
            &MonitorConfig::default(),
            &cfg("always"),
            &stop,
            &Events::default(),
        )
        .unwrap();
        let SuperviseOutcome::Stopped { late, .. } = out else {
            panic!("unexpected outcome: {out:?}")
        };
        assert!(late.wait_settled(Duration::from_secs(5)));
        let got = late.take();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.pid().get(), 43);
    }

    /// terminate が timeout を無視して長く戻らない起動ハンドル（戻った後は失敗する）。
    struct HangingProc(u32, Duration);

    impl LaunchedProcess for HangingProc {
        fn pid(&self) -> NonZeroU32 {
            pidn(self.0)
        }
        fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(None)
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            std::thread::sleep(self.1);
            Err(TraitError::new(ErrorCode::Timeout, "hung"))
        }
    }

    struct HangingRelauncher(Arc<Store>);

    impl Relauncher for HangingRelauncher {
        fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            *self.0.conflicts.lock().unwrap() = 100;
            Ok(Box::new(HangingProc(43, Duration::from_millis(1500))))
        }
    }

    /// REPAIR-5・SUP-3・TASK-159.3: 後始末の terminate が timeout を無視して戻らなくても、
    /// 監視ループは上限で戻り、未完了ハンドルは `late` で追跡して後から回収できる。
    #[test]
    fn sup3_task159_3_hanging_terminate_is_bounded_and_trackable() {
        let st = store(0, 42);
        let q: Arc<dyn Relauncher> = Arc::new(HangingRelauncher(st.clone()));
        let config = cfg("always")
            .with_terminate_timeout(Duration::from_millis(50))
            .unwrap();
        let mut s = attach(&st);
        let started = Instant::now();
        let out = supervise_with_restart(
            &mut s,
            first(FAIL),
            &q,
            &MonitorConfig::default(),
            &config,
            &StopToken::new(),
            &Events::default(),
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_millis(1200));
        let SuperviseOutcome::RestartUnrecorded {
            terminate_error,
            late,
            ..
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(terminate_error.map(|e| e.code()), Some(ErrorCode::Timeout));
        // terminate はまだ戻っておらず、未完了として判別できる。
        assert!(!late.is_settled());
        assert!(late.take().is_empty());
        assert!(late.wait_settled(Duration::from_secs(5)));
        let got = late.take();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.pid().get(), 43);
    }

    /// 期限後に戻る再 launch が terminate の戻らない（ただし timeout を無視する）プロセスを返す。
    struct SlowHangingRelauncher;

    impl Relauncher for SlowHangingRelauncher {
        fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            // 待ち上限＋猶予（550ms）を超えてから戻る。
            std::thread::sleep(Duration::from_millis(1000));
            Ok(Box::new(HangingProc(44, Duration::from_millis(1200))))
        }
    }

    /// REPAIR-5・SUP-3・TASK-159.3: 期限超過後に戻ったプロセスの terminate が戻らなくても、
    /// 再 launch の実行スレッドは上限で完了し、未完了の terminate は `late` で追跡できる。
    #[test]
    fn sup3_task159_3_late_relaunch_hanging_terminate_is_tracked() {
        let st = store(0, 42);
        let q: Arc<dyn Relauncher> = Arc::new(SlowHangingRelauncher);
        let config = cfg("always")
            .with_relaunch_timeout(Duration::from_millis(50))
            .unwrap()
            .with_terminate_timeout(Duration::from_millis(50))
            .unwrap();
        let mut s = attach(&st);
        let out = supervise_with_restart(
            &mut s,
            first(FAIL),
            &q,
            &MonitorConfig::default(),
            &config,
            &StopToken::new(),
            &Events::default(),
        )
        .unwrap();
        let SuperviseOutcome::RelaunchFailed { late, .. } = out else {
            panic!("unexpected outcome: {out:?}")
        };
        assert!(late.wait_settled(Duration::from_secs(5)));
        let got = late.take();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.pid().get(), 44);
    }

    /// SUP-3・TASK-159.3: 設定の境界値（バックオフ上限・タイムアウト 0 / 超過は InvalidArgument）。
    #[test]
    fn sup3_task159_3_restart_config_validation() {
        let base = RestartConfig::new(RestartPolicy::No);
        assert_eq!(base.backoff(), DEFAULT_BACKOFF);
        assert_eq!(base.relaunch_timeout(), DEFAULT_RELAUNCH_TIMEOUT);
        assert_eq!(base.terminate_timeout(), DEFAULT_TERMINATE_TIMEOUT);
        assert_eq!(base.policy(), RestartPolicy::No);
        assert!(base.with_backoff(MAX_BACKOFF).is_ok());
        let e = base
            .with_backoff(MAX_BACKOFF + Duration::from_millis(1))
            .unwrap_err();
        assert_eq!(e.code(), ErrorCode::InvalidArgument);
        for bad in [
            Duration::ZERO,
            MAX_RELAUNCH_TIMEOUT + Duration::from_millis(1),
        ] {
            assert_eq!(
                base.with_relaunch_timeout(bad).unwrap_err().code(),
                ErrorCode::InvalidArgument
            );
            assert_eq!(
                base.with_terminate_timeout(bad).unwrap_err().code(),
                ErrorCode::InvalidArgument
            );
        }
        assert!(base.with_relaunch_timeout(MAX_RELAUNCH_TIMEOUT).is_ok());
    }

    // ---- 実行スレッドの起動失敗（REPAIR-5・SUP-3・TASK-159.3） ----

    /// 常に失敗する [`SpawnFn`]（スレッド生成の失敗を再現する。`run` は実行せずに破棄する）。
    fn failing_spawn(_: &str, _: Box<dyn FnOnce() + Send + 'static>) -> std::io::Result<()> {
        Err(std::io::Error::other("forced spawn failure"))
    }

    fn active_workers(late: &LateOrphans) -> u32 {
        late.lock().active_workers
    }

    /// REPAIR-5・SUP-3・TASK-159.3: 起動に失敗した実行スレッドは数に残らない。動作中の別スレッド 1 本は
    /// 数えたまま（二重に減らさない）で、未実行の `body` は 1 度も走らない。
    #[test]
    fn sup3_task159_3_spawn_failure_restores_worker_count_exactly_once() {
        let late = LateOrphans::default();
        let (release, gate) = std::sync::mpsc::channel::<()>();
        spawn_tracked(spawn_os_thread, "t-live", &late, move || {
            let _ = gate.recv();
        })
        .unwrap();
        assert_eq!(active_workers(&late), 1);

        let ran = Arc::new(AtomicU32::new(0));
        let ran2 = ran.clone();
        let err = spawn_tracked(failing_spawn, "t-fail", &late, move || {
            ran2.fetch_add(1, Ordering::SeqCst);
        })
        .expect_err("forced failure");
        assert_eq!(err.to_string(), "forced spawn failure");
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        // 失敗した 1 本ぶんだけ戻り、動作中の 1 本は残る。
        assert_eq!(active_workers(&late), 1);
        assert!(!late.is_settled());

        release.send(()).unwrap();
        assert!(late.wait_settled(Duration::from_secs(5)));
        assert_eq!(active_workers(&late), 0);
    }

    /// REPAIR-5・SUP-3・TASK-159.3: 実行スレッドの終了（正常・panic）で数が 0 に戻る。
    #[test]
    fn sup3_task159_3_spawn_tracked_settles_on_return_and_panic() {
        let late = LateOrphans::default();
        spawn_tracked(spawn_os_thread, "t-ok", &late, || {}).unwrap();
        spawn_tracked(spawn_os_thread, "t-panic", &late, || {
            panic!("worker panic (expected in test)")
        })
        .unwrap();
        assert!(late.wait_settled(Duration::from_secs(5)));
        assert_eq!(active_workers(&late), 0);
    }

    /// REPAIR-5・SUP-3・TASK-159.3: terminate の実行スレッドを作れないとき、`Unavailable` を返し、
    /// ハンドル 1 件を `late` へ積み、`late` は完了済み（実行スレッド数 0）になる。terminate は呼ばれない。
    #[test]
    fn sup3_task159_3_terminate_spawn_failure_settles_and_keeps_handle() {
        let late = LateOrphans::default();
        let terminated = Arc::new(AtomicU32::new(0));
        let proc = Box::new(Fp {
            pid: 43,
            exit: FAIL,
            terminated: terminated.clone(),
        });
        let err =
            terminate_bounded(proc, Duration::from_millis(50), &late, failing_spawn).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert_eq!(active_workers(&late), 0);
        assert!(late.is_settled());
        assert!(late.wait_settled(Duration::ZERO));
        assert_eq!(terminated.load(Ordering::SeqCst), 0);
        let got = late.take();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.pid().get(), 43);
        assert_eq!(got[0].1.code(), ErrorCode::Unavailable);

        // 失敗の後も同じ受け皿で terminate でき、完了を確認できる。
        let proc = Box::new(Fp {
            pid: 44,
            exit: FAIL,
            terminated: terminated.clone(),
        });
        terminate_bounded(proc, Duration::from_millis(50), &late, spawn_os_thread).unwrap();
        assert!(late.wait_settled(Duration::from_secs(5)));
        assert_eq!(terminated.load(Ordering::SeqCst), 1);
        assert!(late.take().is_empty());
    }

    /// REPAIR-5・SUP-3・TASK-159.3: 再 launch の実行スレッドを作れないとき、`Unavailable` を返し、
    /// `relaunch` は呼ばれず、`late` は完了済み（実行スレッド数 0・ハンドル 0 件）になる。
    /// 同じ受け皿での次の再 launch は成功する。
    #[test]
    fn sup3_task159_3_relaunch_spawn_failure_settles_and_next_relaunch_works() {
        let late = LateOrphans::default();
        let q = Arc::new(Queue::new(&[(43, FAIL)]));
        let Err(err) = relaunch_bounded(
            &rl(&q),
            Duration::from_millis(50),
            Duration::from_millis(50),
            &late,
            failing_spawn,
        ) else {
            panic!("forced failure must be reported")
        };
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert_eq!(q.calls.load(Ordering::SeqCst), 0);
        assert_eq!(active_workers(&late), 0);
        assert!(late.is_settled());
        assert!(late.wait_settled(Duration::ZERO));
        assert!(late.take().is_empty());

        let Ok(proc) = relaunch_bounded(
            &rl(&q),
            Duration::from_secs(5),
            Duration::from_millis(50),
            &late,
            spawn_os_thread,
        ) else {
            panic!("relaunch after a spawn failure must succeed")
        };
        assert_eq!(proc.pid().get(), 43);
        assert_eq!(q.calls.load(Ordering::SeqCst), 1);
        assert!(late.wait_settled(Duration::from_secs(5)));
        assert_eq!(active_workers(&late), 0);
    }

    /// REPAIR-5・SUP-3・TASK-159.3: 期限後に戻った再 launch の後始末で terminate の実行スレッドを作れないとき、
    /// ハンドル（pid 43）を `Unavailable` とともに `late` へ積み、実行スレッド数は 0 に戻る。
    #[test]
    fn sup3_task159_3_late_terminate_spawn_failure_settles_and_keeps_handle() {
        /// 再 launch の実行スレッドだけ生成し、後始末の terminate の実行スレッドは生成に失敗する。
        fn relaunch_only(n: &str, run: Box<dyn FnOnce() + Send + 'static>) -> std::io::Result<()> {
            if n == "fandhe-relaunch" {
                spawn_os_thread(n, run)
            } else {
                failing_spawn(n, run)
            }
        }
        struct Slow(Arc<AtomicU32>);
        impl Relauncher for Slow {
            fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
                // 待ち上限＋猶予（550ms）を超えてから戻る。
                std::thread::sleep(Duration::from_millis(1000));
                Ok(Box::new(Fp {
                    pid: 43,
                    exit: FAIL,
                    terminated: self.0.clone(),
                }))
            }
        }
        let late = LateOrphans::default();
        let terminated = Arc::new(AtomicU32::new(0));
        let q: Arc<dyn Relauncher> = Arc::new(Slow(terminated.clone()));
        let Err(err) = relaunch_bounded(
            &q,
            Duration::from_millis(50),
            Duration::from_millis(50),
            &late,
            relaunch_only,
        ) else {
            panic!("relaunch must time out")
        };
        assert_eq!(err.code(), ErrorCode::Timeout);
        assert!(!late.is_settled());
        assert!(late.wait_settled(Duration::from_secs(5)));
        assert_eq!(active_workers(&late), 0);
        assert_eq!(terminated.load(Ordering::SeqCst), 0);
        let got = late.take();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.pid().get(), 43);
        assert_eq!(got[0].1.code(), ErrorCode::Unavailable);
    }
}
