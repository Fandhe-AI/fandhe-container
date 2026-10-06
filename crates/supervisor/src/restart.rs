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
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{
    ContainerState, ContainerStatus, ErrorCode, Signal, SupervisionState, TraitError,
};

use crate::run::{
    MonitorConfig, MonitorEvent, MonitorObserver, MonitorOperation, MonitorOutcome, StopToken,
    monitor_with_observer, write_with_retry_when,
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
/// バックオフ待ちが停止要求を確認する刻み。
const BACKOFF_SLICE: Duration = Duration::from_millis(10);

/// 同じコンテナのプロセスを再 launch する拡張点（SUP-3・TASK-159.3）。
///
/// 本番の `ProcessLauncher` は core に未提供のため、[`supervise_with_restart`] へ呼び出し側から注入する
/// （本番実装は未実装。REPAIR-3）。
pub trait Relauncher {
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
    Stopped {
        /// 最後の `monitor` の結果。
        last: MonitorOutcome,
        /// 生存中の起動ハンドル。
        process: Option<Box<dyn LaunchedProcess>>,
        /// 実施した再起動の回数。
        restarts: u32,
    },
    /// 再 launch に失敗した（`restart_count` は進めていない。状態は `Stopped`）。
    RelaunchFailed {
        /// 直前のプロセスの終了状態。
        exit: ProcessExit,
        /// 再 launch の失敗理由。
        error: TraitError,
        /// 実施した再起動の回数。
        restarts: u32,
    },
    /// 再 launch には成功したが `Running` の記録に失敗したため、新プロセスを terminate した。
    RestartUnrecorded {
        /// 記録の失敗理由。
        error: TraitError,
        /// 新プロセスの terminate が失敗した場合の理由（成功なら `None`）。
        terminate_error: Option<TraitError>,
        /// 実施した再起動の回数（この失敗した 1 回は含まない）。
        restarts: u32,
    },
    /// `monitor` が状態の不確かな結果（`ExitedUnrecorded` 等）を返したため、再起動せずに戻った（fail-closed）。
    MonitorFailed {
        /// `monitor` の結果。
        last: MonitorOutcome,
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
                restarts,
            } => f
                .debug_struct("Stopped")
                .field("last", last)
                .field("has_process", &process.is_some())
                .field("restarts", restarts)
                .finish(),
            Self::RelaunchFailed {
                exit,
                error,
                restarts,
            } => f
                .debug_struct("RelaunchFailed")
                .field("exit", exit)
                .field("error", error)
                .field("restarts", restarts)
                .finish(),
            Self::RestartUnrecorded {
                error,
                terminate_error,
                restarts,
            } => f
                .debug_struct("RestartUnrecorded")
                .field("error", error)
                .field("terminate_error", terminate_error)
                .field("restarts", restarts)
                .finish(),
            Self::MonitorFailed { last, restarts } => f
                .debug_struct("MonitorFailed")
                .field("last", last)
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

/// `monitor` を周回させ、ポリシーに従って再起動する（SUP-3・TASK-159.3）。
///
/// 将来の supervisor 入口（コンテナごとの別プロセス）が [`crate::state::SupervisedState::attach`] 後に呼ぶ。
/// 1 周: `monitor`（監視権取得・終了検知・`Stopped` 記録）→ [`evaluate_restart`]（`restart_count` は state.json の値）→
/// バックオフ → [`Relauncher::relaunch`] → `Running(新 pid)` と `restart_count + 1` を 1 回の書き込みで記録。
/// `Running` 再記録では `supervisor_pid` は `None` のままで、次周の `monitor` が監視権を取り直す。
///
/// [`MonitorOperation::Restart`] を再起動 1 回ごとに通知する。`elapsed` は終了検知から `Running` 記録完了までで、
/// バックオフ時間を含む（バックオフ 0 のとき SUP-3 の「再起動レイテンシ中央値 100ms 以下」に相当）。
///
/// `Err` は `monitor` 自体の失敗（事前条件違反・wait 失敗）で、`process` は呼び出し側に返らず破棄される。
pub fn supervise_with_restart(
    state: &mut SupervisedState,
    process: Box<dyn LaunchedProcess>,
    relauncher: &dyn Relauncher,
    monitor_config: &MonitorConfig,
    restart_config: &RestartConfig,
    stop: &StopToken,
    obs: &dyn MonitorObserver,
) -> Result<SuperviseOutcome, TraitError> {
    let mut process = process;
    let mut restarts: u32 = 0;
    loop {
        let last = monitor_with_observer(state, process.as_ref(), monitor_config, stop, obs)?;
        let (exit, restart_count) = match &last {
            MonitorOutcome::Exited { exit, record } => (*exit, record.restart_count()),
            MonitorOutcome::StopRequested { .. } => {
                return Ok(SuperviseOutcome::Stopped {
                    last,
                    process: Some(process),
                    restarts,
                });
            }
            _ => return Ok(SuperviseOutcome::MonitorFailed { last, restarts }),
        };
        let detected = Instant::now();
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
        let new_process = match relauncher.relaunch(restart_config.relaunch_timeout) {
            Ok(p) => p,
            Err(error) => {
                observe(Some(error.code()));
                return Ok(SuperviseOutcome::RelaunchFailed {
                    exit,
                    error,
                    restarts,
                });
            }
        };
        let new_pid = new_process.pid();
        let id = state.id().clone();
        // 前回の終了記録（`Stopped`・監視権なし）のままであることを確かめて書く。delete 等で変わっていれば書かない。
        let written = write_with_retry_when(
            state,
            |rec| {
                rec.status().state() == ContainerState::Stopped
                    && rec.supervision().supervisor_pid().is_none()
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
                observe(None);
                restarts = restarts.saturating_add(1);
                process = new_process;
            }
            Err(error) => {
                observe(Some(error.code()));
                // 記録できない生存プロセスを残さない（core `start` の後始末と同じ方針）。
                let terminate_error = new_process
                    .terminate(restart_config.terminate_timeout)
                    .err();
                return Ok(SuperviseOutcome::RestartUnrecorded {
                    error,
                    terminate_error,
                    restarts,
                });
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

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

    use crate::run::MAX_WRITE_ATTEMPTS;

    fn cid() -> ContainerId {
        ContainerId::new("c1").unwrap()
    }

    fn pidn(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    /// メモリ上の 1 レコードストア。`conflicts` 回だけ外部更新（restart_count +1）で競合させる。
    struct Store {
        rec: Mutex<StateRecord>,
        conflicts: Mutex<u32>,
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
                let s = SupervisionState::new(
                    sup.supervisor_pid(),
                    sup.health(),
                    sup.restart_count() + 1,
                );
                *g = bump(&g, s, g.status().clone());
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            if g.revision() != req.expected_revision() {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            let s = req.supervision().unwrap_or_else(|| g.supervision());
            let next = bump(&g, s, req.status().clone());
            *g = next.clone();
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

    fn run(
        store: &Arc<Store>,
        policy: &str,
        exit: ProcessExit,
        q: &Queue,
        stop: &StopToken,
        obs: &Events,
    ) -> SuperviseOutcome {
        let mut s = attach(store);
        supervise_with_restart(
            &mut s,
            first(exit),
            q,
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
        let q = Queue::new(&[(43, FAIL), (44, ProcessExit::Exited(0)), (45, FAIL)]);
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
        let q = Queue::new(&[(43, FAIL), (44, FAIL), (45, FAIL)]);
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
        let q = Queue::new(&[(43, FAIL)]);
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
        let q = Queue::new(&[(43, FAIL)]);
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
        let q = Queue::new(&[]);
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
            restarts,
        } = out
        else {
            panic!("unexpected outcome: {out:?}")
        };
        assert_eq!(error.code(), ErrorCode::FailedPrecondition);
        assert!(terminate_error.is_none());
        assert_eq!(restarts, 0);
        assert_eq!(q.terminated.load(Ordering::SeqCst), 1);
        let g = st.rec.lock().unwrap();
        assert_eq!(g.status().state(), ContainerState::Stopped);
        // 競合ごとの外部加算だけが残り、自分の加算は載らない。
        assert_eq!(g.restart_count(), MAX_WRITE_ATTEMPTS);
    }

    /// SUP-3・TASK-159.3: 競合 1 回（外部が +1）の後も外部の更新を消さず、自分の +1 が載る（1 -> 3）。
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
        let q = OneConflict(Queue::new(&[(43, ProcessExit::Exited(0))]), st.clone());
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
        // 2 周目の終了後は再 launch が尽きて失敗する。
        assert!(matches!(out, SuperviseOutcome::RelaunchFailed { .. }));
        // 初期 1 + 競合の外部加算 1 + 自分の再起動 1 = 3（再 launch 失敗は数えない）。
        assert_eq!(st.rec.lock().unwrap().restart_count(), 3);
    }

    /// SUP-3・TASK-159.3: restart_count は u32::MAX で頭打ちになり panic しない。
    #[test]
    fn sup3_task159_3_restart_count_saturates() {
        let st = store(u32::MAX, 42);
        let q = Queue::new(&[(43, FAIL)]);
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
        let q = Queue::new(&[(43, FAIL)]);
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
            &q,
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
        let q = Queue::new(&[(43, FAIL)]);
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
            &q,
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

    /// SUP-3・TASK-159.3: 状態が不確かな終了（ExitedUnrecorded）では再 launch しない（fail-closed）。
    #[test]
    fn sup3_task159_3_unrecorded_exit_does_not_relaunch() {
        let st = store(0, 42);
        let q = Queue::new(&[(43, FAIL)]);
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
            &q,
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
}
