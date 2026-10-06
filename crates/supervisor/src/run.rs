//! 1 コンテナ分の監視ループ（生存確認と終了検知）の基本実装（TASK-157.4・#238・SUP-1。restart の土台は TASK-157.5・#239・SUP-3。関連: CORE-1・D-19・REPAIR-3・REPAIR-5・SEC-1）。
//!
//! 将来の supervisor 入口（コンテナごとの別プロセス）が [`crate::state::open_default_store`] →
//! [`crate::state::SupervisedState::attach`] → [`monitor`] の順に呼ぶ。1 回の [`monitor`] 呼び出しは
//! 1 コンテナ・1 起動ハンドルだけを扱い、グローバルなレジストリや複数コンテナを束ねる構造を持たない
//! （常駐デーモンを前提にしない。CORE-1・D-19）。
//!
//! # 実装範囲の線引き（REPAIR-3）
//! - 本番の `ProcessLauncher` は core に未提供のため、起動ハンドル（`LaunchedProcess`）は呼び出し側から注入する。
//!   supervisor のバイナリ入口（`main.rs`）は本 issue では追加しない（実プロセスを起動できないため実装済みを装わない）。
//!   「コンテナ 0 個で supervisor プロセスが残存しない」ことの検証は結合テスト（#242・TASK-157.8）の担当。
//! - restart ポリシーの配線と `restart_count` の加算は [`crate::restart`]（TASK-159.3・#489）。次節に未実装の範囲を記す。
//!   stdout / stderr 捕捉の土台は [`crate::logs`] と [`monitor_with_capture`]（#241・TASK-157.7）。永続化・ローテーションは未実装
//!   （SUP-7・TASK-164）で、実パイプは core が未提供のため注入式。
//!   `health` を書くフックは [`crate::health`] で提供済み（#240・SUP-4）。healthcheck コマンドの実行と周期実行は未実装（TASK-161）で、
//!   ループ内の統合点は手順 3 の生存確認の周回（本 issue ではループ本体へ組み込まない）。
//!   終了検知後の分岐（再起動するか Stopped に落とすか）は、[`monitor`] の手順 4 が拡張点になる。
//!
//! # 処理順（[`monitor`]）
//! 1. 事前確認: 状態が `Running` で、`status.pid()` が起動ハンドルの pid と一致すること。違えば `FailedPrecondition`。
//! 2. 監視開始の記録: `supervisor_pid` が `None` のときだけ自プロセスの pid を書く（自 pid を含め既に記録があれば `FailedPrecondition`。
//!    同一プロセス内の二重 monitor を revision 競合後の `refresh` 経由でも開始させないため。`health`・`restart_count` は既存値を保つ）。
//! 3. ループ: 周回の先頭で停止要求を確認し、`wait(poll_interval)` で生存確認する。`Ok(None)` は生存、
//!    `Ok(Some(_))` は終了（回収済み）、`Err` は握りつぶさず返す。ただし返す前に記録済みの `supervisor_pid` を
//!    解除する（監視していないのに自 pid が残るのを防ぐ）。解除にも失敗したら [`MonitorOutcome::WaitFailedUnreleased`] で
//!    wait の失敗と解除の失敗の両方を返し、呼び出し側が識別できるようにする。
//! 4. 終了の記録: `Stopped` と終了コードを書き、`supervisor_pid` を `None` に戻す（`health`・`restart_count` は保つ。
//!    `restart_count` は実施済み再起動の回数で、加算は再 launch 成功時に [`crate::restart`] が行う。#489・TASK-159.3）。
//!    回収後の書き込み失敗は `Err` にせず [`MonitorOutcome::ExitedUnrecorded`] で終了状態ごと返す
//!    （プロセスは回収済みで再 wait 不可）。この回復は未実装（SUP-3）。
//!    [`monitor`] 単体はループ終了 = 監視なしで、再起動を続ける外側のループは [`crate::restart::supervise_with_restart`]。
//! 5. 停止要求（[`StopToken`]）: 監視をやめるだけで、プロセスは終了させない。状態は `Running` のまま
//!    `supervisor_pid` だけ `None` に戻す。起動ハンドルは参照渡しのため所有権は常に呼び出し側に残り、
//!    回収責任（終了・`wait` での回収、または別の監視への引き継ぎ）は呼び出し側が負う契約とする
//!    （[`MonitorOutcome::StopRequested`] の doc 参照）。
//!
//! # restart と未実装の将来仕様（TASK-157.5・TASK-159.3・SUP-3。REPAIR-3）
//! [`monitor`] 自体は再起動しない。ポリシー（`no` / `on-failure[:N]` / `always` / `unless-stopped`）の評価・バックオフ・再 launch・`restart_count` の加算・`Running` の再記録は
//! [`crate::restart::supervise_with_restart`]（#489・TASK-159.3）が [`monitor_with_observer`] を周回させて行う
//! （TASK-157.5 の土台だった「異常終了の検知回数」の加算は廃止し、`restart_count` を実施済み再起動回数に統一した）。
//!
//! 未実装（将来仕様と対応ビヘイビア ID）:
//! - 本番 `ProcessLauncher` による再 launch（core の launcher 提供が前提。現状は [`crate::restart::Relauncher`] を注入する。SUP-3）。
//! - 明示的な停止（`stop`）の検知と異常終了の区別、停止シグナル・猶予時間、再 launch 時の `unless-stopped` と `always` の差（SUP-9）。
//! - 指数バックオフ等の高度な間隔制御（現状は固定のバックオフ。SUP-3）。
//! - [`MonitorOutcome::ExitedUnrecorded`] の回復（SUP-3）。
//!
//! # 可観測性（REPAIR-4）
//! 監視開始・wait・終了記録・停止・解除の各操作について、成功 / 失敗とレイテンシを [`MonitorObserver`] へ通知する。
//! [`monitor`] は [`StderrLogObserver`]（1 行 1 JSON の構造化ログを stderr へ出す）を使い、差し替えたい場合は
//! [`monitor_with_observer`] を使う。`ExitedUnrecorded` は `record_exit` の失敗として必ず通知される。
//!
//! 終了コードの写像: `Exited(c)` は `Some(c)`、`Signaled(s)` はシェル慣習に合わせ `Some(128 + s)`
//! （あふれたら `None`）。生の [`ProcessExit`] は [`MonitorOutcome::Exited`] で返す。
//!
//! # pid 再利用対策（SEC-1）
//! 生存確認と回収は保持する起動ハンドル経由のみで行う。状態に記録された pid を `kill(2)`・`waitpid(2)`・
//! `/proc` の宛先に使わない（記録値は再利用され得る）。
//!
//! # 書き込みの再試行（REPAIR-5）
//! state.rs が呼び出し側に委ねた判断として、revision 不一致（`FailedPrecondition`）のときだけ
//! `refresh` して再構築・再書き込みする。回数は [`MAX_WRITE_ATTEMPTS`] で打ち切り、待ち時間は入れない。
//! 再試行のたびに `health`・`restart_count` を読み直し、他者の更新を上書きで消さない。`refresh` 後に状態が
//! 「`Running` かつ自分の pid」でなくなっていれば書かずに `FailedPrecondition` を返す。書き込み排他の最終仕様
//! （TASK-157.9・#1069）の意味論には依存しない。

use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{
    ContainerState, ContainerStatus, ErrorCode, StateRecord, SupervisionState, TraitError,
};

use crate::logs::{CaptureSummary, LogCapture, LogSink, OutputStreams, StreamSummary};
use crate::restart::exit_code_of;
use crate::state::SupervisedState;

/// 捕捉の終端待ち（drain）の既定の上限。
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// `drain_timeout` の上限。これを超える値は拒否する（REPAIR-5）。[`LogCapture::drain`] の上限と同じ値。
pub const MAX_DRAIN_TIMEOUT: Duration = crate::logs::MAX_DRAIN_TIMEOUT;

/// 1 回の `wait` の既定の上限。
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// `poll_interval` の上限。これを超える値は拒否する（停止要求への反応が遅れ過ぎるのを防ぐ。REPAIR-5）。
pub const MAX_POLL_INTERVAL: Duration = Duration::from_secs(60);

/// 状態書き込みの試行回数の上限（初回を含む）。
pub const MAX_WRITE_ATTEMPTS: u32 = 3;

/// 監視ループの設定。検証付きコンストラクタ経由でのみ作れる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitorConfig {
    poll_interval: Duration,
    drain_timeout: Duration,
}

impl MonitorConfig {
    /// `poll_interval` が 0 または [`MAX_POLL_INTERVAL`] 超なら `InvalidArgument`。
    pub fn new(poll_interval: Duration) -> Result<Self, TraitError> {
        if poll_interval.is_zero() || poll_interval > MAX_POLL_INTERVAL {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "poll interval is out of range",
            ));
        }
        Ok(Self {
            poll_interval,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        })
    }

    /// 捕捉の終端待ちの上限を設定する（[`monitor_with_capture`] のみが使う）。
    /// 0 または [`MAX_DRAIN_TIMEOUT`] 超なら `InvalidArgument`。
    pub fn with_drain_timeout(self, drain_timeout: Duration) -> Result<Self, TraitError> {
        if drain_timeout.is_zero() || drain_timeout > MAX_DRAIN_TIMEOUT {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "drain timeout is out of range",
            ));
        }
        Ok(Self {
            drain_timeout,
            ..self
        })
    }

    /// 捕捉の終端待ちの上限。
    pub fn drain_timeout(&self) -> Duration {
        self.drain_timeout
    }

    /// 1 回の `wait` の上限。
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }
}

/// 監視ループを有限時間で止めるための取り消しトークン（複製して共有できる）。
///
/// テストと将来の停止経路（SUP 系）が使う。
#[derive(Debug, Clone, Default)]
pub struct StopToken(Arc<AtomicBool>);

impl StopToken {
    /// 停止要求のないトークンを作る。
    pub fn new() -> Self {
        Self::default()
    }

    /// 停止を要求する。
    pub fn request_stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// 停止が要求済みか。
    pub fn is_stop_requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// [`monitor`] の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MonitorOutcome {
    /// 終了を検知し、`Stopped` を記録した。`record.restart_count()` は終了前の値のまま（加算は再 launch 成功時。
    /// [`crate::restart::supervise_with_restart`]。SUP-3・TASK-159.3）。
    Exited {
        /// 起動ハンドルが回収した終了状態。
        exit: ProcessExit,
        /// 書き込み後のレコード。
        record: StateRecord,
    },
    /// 終了を検知しプロセスは回収済みだが、`Stopped` の書き込みに失敗した（状態は `Running` のまま、
    /// `supervisor_pid` も自 pid のまま残り得る）。再 `wait` はできないため、終了状態を失わないよう
    /// `exit` と書き込み失敗の `error` を呼び出し側へ返す。終了の記録が永続化されていない。
    /// 回復（再書き込み・再起動判断）は未実装（SUP-3）。再起動ループは再 launch せずに戻る。
    ExitedUnrecorded {
        /// 起動ハンドルが回収した終了状態。
        exit: ProcessExit,
        /// 状態書き込みの失敗理由。
        error: TraitError,
    },
    /// `wait` が失敗し、記録済みの `supervisor_pid` の解除にも失敗した（状態に自 pid が残り得る）。
    /// 解除に成功した場合は従来どおり `Err(wait_error)` で返る。
    WaitFailedUnreleased {
        /// `wait` の失敗理由。
        wait_error: TraitError,
        /// `supervisor_pid` 解除の失敗理由。
        release_error: TraitError,
    },
    /// 監視開始後の準備（ログ捕捉の開始）に失敗し、記録済みの `supervisor_pid` の解除にも失敗した
    /// （状態に自 pid が残り得る）。解除に成功した場合は `Err(start_error)` で返る。
    StartFailedUnreleased {
        /// 準備（捕捉開始）の失敗理由。
        start_error: TraitError,
        /// `supervisor_pid` 解除の失敗理由。
        release_error: TraitError,
    },
    /// 停止要求で監視をやめた（プロセスは kill せず、状態は `Running` のまま）。
    ///
    /// 起動ハンドルの回収責任は呼び出し側に残る（`monitor` は参照でしか受け取らない）。呼び出し側は
    /// `terminate` と `wait` で終了・回収するか、再度 [`monitor`] へ渡して監視を引き継ぐこと。
    /// 放置するとプロセスが無監視のまま残る。
    StopRequested {
        /// 書き込み後のレコード（`supervisor_pid` は `None`）。
        record: StateRecord,
    },
}

/// 可観測性の対象となる操作（REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MonitorOperation {
    /// 監視開始（`supervisor_pid` の記録）。
    Start,
    /// 生存確認（1 回の `wait`）。
    Wait,
    /// 終了状態の記録（失敗は `ExitedUnrecorded`）。
    RecordExit,
    /// 停止要求に伴う `supervisor_pid` の解除。
    Stop,
    /// `wait` 失敗後の `supervisor_pid` 解除。
    ReleaseAfterWaitError,
    /// healthcheck の判定結果（`health`）の記録（#240・SUP-4。[`crate::health`]）。
    RecordHealth,
    /// healthcheck 判定の実行（成功・失敗・期限超過とレイテンシ。#240・REPAIR-4）。
    Probe,
    /// 再起動 1 回（終了検知からバックオフ・再 launch・`Running` 再記録まで。#489・SUP-3。[`crate::restart`]）。
    Restart,
    /// 出力捕捉の開始（リーダースレッドの起動。#241）。
    CaptureStart,
    /// 終了検知後の出力捕捉の終端待ち（#241）。
    CaptureDrain,
}

impl MonitorOperation {
    /// ログ・メトリクスのラベルに使う安定名。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Wait => "wait",
            Self::RecordExit => "record_exit",
            Self::Stop => "stop",
            Self::ReleaseAfterWaitError => "release_after_wait_error",
            Self::RecordHealth => "record_health",
            Self::Probe => "probe",
            Self::Restart => "restart",
            Self::CaptureStart => "capture_start",
            Self::CaptureDrain => "capture_drain",
        }
    }
}

/// 1 操作の観測結果（成功 / 失敗とレイテンシ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorEvent {
    /// 操作の種類。
    pub operation: MonitorOperation,
    /// 失敗時のエラーコード。成功なら `None`。
    pub error_code: Option<ErrorCode>,
    /// 操作に要した時間。
    pub elapsed: Duration,
}

/// 監視操作の成功・失敗とレイテンシを受け取る（構造化ログ・メトリクスへの橋渡し。REPAIR-4）。
pub trait MonitorObserver {
    /// 1 操作の完了を通知する。
    fn observe(&self, event: &MonitorEvent);
}

/// 1 行 1 JSON の構造化ログを stderr へ出す既定の観測器（値は固定語彙・数値のみ）。
#[derive(Debug, Clone, Copy, Default)]
pub struct StderrLogObserver;

impl MonitorObserver for StderrLogObserver {
    fn observe(&self, event: &MonitorEvent) {
        let result = if event.error_code.is_none() {
            "ok"
        } else {
            "error"
        };
        let code = event
            .error_code
            .map(|c| c.as_str().to_owned())
            .unwrap_or_default();
        eprintln!(
            "{{\"component\":\"supervisor.monitor\",\"operation\":\"{}\",\"result\":\"{}\",\"code\":\"{}\",\"elapsed_us\":{}}}",
            event.operation.as_str(),
            result,
            code,
            event.elapsed.as_micros()
        );
    }
}

/// 操作を実行して所要時間と成否を通知する。
pub(crate) fn observed<T>(
    obs: &dyn MonitorObserver,
    operation: MonitorOperation,
    f: impl FnOnce() -> Result<T, TraitError>,
) -> Result<T, TraitError> {
    let started = Instant::now();
    let r = f();
    obs.observe(&MonitorEvent {
        operation,
        error_code: r.as_ref().err().map(TraitError::code),
        elapsed: started.elapsed(),
    });
    r
}

/// [`monitor_with_observer`] を [`StderrLogObserver`] で呼ぶ。
pub fn monitor(
    state: &mut SupervisedState,
    process: &dyn LaunchedProcess,
    config: &MonitorConfig,
    stop: &StopToken,
) -> Result<MonitorOutcome, TraitError> {
    monitor_with_observer(state, process, config, stop, &StderrLogObserver)
}

/// 起動ハンドルの生存確認と終了検知を行い、結果を状態へ記録する（処理順は module doc）。
///
/// 参照で受けるのは、後続の restart ポリシー実装（SUP-3）が同じハンドル・状態で再起動処理を続けられるようにするため。
pub fn monitor_with_observer(
    state: &mut SupervisedState,
    process: &dyn LaunchedProcess,
    config: &MonitorConfig,
    stop: &StopToken,
    obs: &dyn MonitorObserver,
) -> Result<MonitorOutcome, TraitError> {
    monitor_after_claim(state, process, config, stop, obs, &mut || Ok(()))
}

/// [`monitor_with_observer`] の本体。監視権の取得（`supervisor_pid` 記録）に成功した直後、待機ループへ入る前に
/// `after_claim` を一度だけ呼ぶ。`after_claim` が `Err` なら記録済みの自 pid を戻して `Err` を返す。
/// ログ捕捉（#241）を「監視権を得られた場合のみ」開始するための拡張点で、権限を得られなかった supervisor が
/// 出力ストリームを消費しない（ログの欠落・重複を防ぐ）ことを保証する。
fn monitor_after_claim(
    state: &mut SupervisedState,
    process: &dyn LaunchedProcess,
    config: &MonitorConfig,
    stop: &StopToken,
    obs: &dyn MonitorObserver,
    after_claim: &mut dyn FnMut() -> Result<(), TraitError>,
) -> Result<MonitorOutcome, TraitError> {
    let pid = process.pid();
    if !is_running_with_pid(state.record(), pid) {
        return Err(precondition(
            "container is not running with the launched pid",
        ));
    }

    let self_pid = NonZeroU32::new(std::process::id())
        .ok_or_else(|| TraitError::new(ErrorCode::Internal, "own pid is zero"))?;
    observed(obs, MonitorOperation::Start, || {
        write_with_retry(state, pid, |rec| {
            // 既に誰かが監視中なら（自 pid でも）開始しない（SUP-1: コンテナごとの監視所有権）。
            // 自 pid 一致を許すと同一プロセス内の二重 monitor が revision 競合後の refresh 経由で
            // 開始でき、同じ起動ハンドルを二重に wait して回収・状態記録が競合する。
            // 状態ファイルの CAS（revision）だけで排他するため、グローバル状態は持たない。
            if rec.supervision().supervisor_pid().is_some() {
                return Err(precondition("monitoring is already owned by a supervisor"));
            }
            Ok((
                rec.status().clone(),
                SupervisionState::new(Some(self_pid), rec.health(), rec.restart_count()),
            ))
        })
    })?;

    if let Err(e) = after_claim() {
        // 監視を始められないので、記録済みの自 pid を残さない。解放にも失敗したら両方を返す。
        return match observed(obs, MonitorOperation::ReleaseAfterWaitError, || {
            release_supervisor_pid(state, pid, self_pid)
        }) {
            Ok(_) => Err(e),
            Err(release_error) => Ok(MonitorOutcome::StartFailedUnreleased {
                start_error: e,
                release_error,
            }),
        };
    }

    loop {
        if stop.is_stop_requested() {
            let record = observed(obs, MonitorOperation::Stop, || {
                release_supervisor_pid(state, pid, self_pid)
            })?;
            return Ok(MonitorOutcome::StopRequested { record });
        }
        match observed(obs, MonitorOperation::Wait, || {
            process.wait(config.poll_interval())
        }) {
            Ok(None) => continue,
            Ok(Some(exit)) => {
                let code = exit_code_of(exit);
                let id = state.id().clone();
                // 回収後は再 wait できないため、書き込み失敗でも終了状態を返す。
                let written = observed(obs, MonitorOperation::RecordExit, || {
                    write_with_retry(state, pid, |rec| {
                        ensure_owner(rec, self_pid)?;
                        // `restart_count` は実施済み再起動の回数で、加算は再 launch 成功時（[`crate::restart`]）だけが行う。
                        // 終了記録では最新値を保つ（競合後の refresh で他者の更新も消さない）。
                        Ok((
                            ContainerStatus::stopped(id.clone(), code),
                            SupervisionState::new(None, rec.health(), rec.restart_count()),
                        ))
                    })
                });
                return Ok(match written {
                    Ok(record) => MonitorOutcome::Exited { exit, record },
                    Err(error) => MonitorOutcome::ExitedUnrecorded { exit, error },
                });
            }
            Err(wait_error) => {
                // 監視をやめるので、記録済みの自 pid を残さない。
                return match observed(obs, MonitorOperation::ReleaseAfterWaitError, || {
                    release_supervisor_pid(state, pid, self_pid)
                }) {
                    Ok(_) => Err(wait_error),
                    Err(release_error) => Ok(MonitorOutcome::WaitFailedUnreleased {
                        wait_error,
                        release_error,
                    }),
                };
            }
        }
    }
}

/// [`monitor_with_capture`] の結果。監視結果を捕捉の失敗で失わないよう、両者を別々に返す。
#[derive(Debug)]
pub struct MonitoredWithCapture {
    outcome: MonitorOutcome,
    capture: Option<CaptureSummary>,
    capture_error: Option<TraitError>,
    live_capture: Option<LogCapture>,
}

impl MonitoredWithCapture {
    /// 監視ループの結果。
    pub fn outcome(&self) -> &MonitorOutcome {
        &self.outcome
    }
    /// 捕捉の集計。プロセス終了を検知し終端待ちに成功した場合のみ `Some`。
    pub fn capture(&self) -> Option<&CaptureSummary> {
        self.capture.as_ref()
    }
    /// 終端待ちの失敗（`Timeout` 等）。監視結果とは独立。
    pub fn capture_error(&self) -> Option<&TraitError> {
        self.capture_error.as_ref()
    }
    /// 継続中の捕捉の取っ手を取り出す（1 回だけ `Some`）。
    ///
    /// 捕捉を開始したが終端待ちをしなかった結果（`StopRequested`・`WaitFailedUnreleased`）で `Some` になる。
    /// 呼び出し側は [`LogCapture::cancel`] で止めるか、保持して後で [`LogCapture::drain`] する。
    /// 取り出さずに破棄するとリーダーは EOF まで走り続け、止める手段が無くなる。
    pub fn take_live_capture(&mut self) -> Option<LogCapture> {
        self.live_capture.take()
    }
}

/// [`monitor_with_capture`] の失敗。監視の失敗理由に加え、開始済みだった捕捉の取っ手を呼び出し側へ返す
/// （失敗で取っ手を失うと、リーダーを止める手段も引き継ぐ手段も無くなるため。REPAIR-5）。
///
/// `TraitError` への暗黙変換（`From`）は意図的に提供しない（`?` で取っ手を黙って捨てないようにする）。
#[derive(Debug)]
pub struct MonitorWithCaptureError {
    error: TraitError,
    live_capture: Option<LogCapture>,
}

impl MonitorWithCaptureError {
    /// 監視の失敗理由。
    pub fn error(&self) -> &TraitError {
        &self.error
    }
    /// 継続中の捕捉の取っ手を取り出す（1 回だけ `Some`）。
    ///
    /// 捕捉の開始後に監視が失敗した場合（`wait` の失敗・停止時の監視権解放の失敗）に `Some`。
    /// 事前条件違反・監視権の取得失敗・捕捉開始の失敗では `None`（ストリームは未読のまま呼び出し側に残る）。
    pub fn take_live_capture(&mut self) -> Option<LogCapture> {
        self.live_capture.take()
    }
    /// 失敗理由と取っ手へ分解する。
    pub fn into_parts(self) -> (TraitError, Option<LogCapture>) {
        (self.error, self.live_capture)
    }
}

impl std::fmt::Display for MonitorWithCaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for MonitorWithCaptureError {}

/// [`monitor_with_observer`] に stdout / stderr の行単位捕捉（[`crate::logs`]。#241・TASK-157.7）を加える。
///
/// 事前条件（`Running` かつ pid 一致）を満たさない、または他の supervisor が既に監視権を持つ場合は、スレッドを起こさず
/// （ストリームを読まず）`FailedPrecondition`。この場合 `streams` は呼び出し側に残る（取り出すのは監視権の取得後のみ）。
/// 捕捉開始の失敗で監視権の解放にも失敗したら [`MonitorOutcome::StartFailedUnreleased`] を返す。捕捉は監視権の取得後に開始し、開始に失敗したら監視権を解放して `Err`（`streams` は未読のまま呼び出し側へ戻り、再試行できる）。プロセスの終了（`Exited` / `ExitedUnrecorded`）を検知したときだけ、`drain_timeout` を上限に
/// 全ストリームの EOF を待って集計を返す。`StopRequested` などプロセスが生存し得る結果では待たない
/// （EOF が来ないため）。永続化・ローテーションは未実装（SUP-7・TASK-164）。
///
/// # 終端待ちをしなかった場合の捕捉の扱い
/// 捕捉を開始した後は、ストリームの所有権がリーダーへ移っており再注入できない。そこで、終端待ちをしなかった
/// 全経路で継続中の捕捉の取っ手（[`LogCapture`]）を呼び出し側へ返す。
/// - `StopRequested`・`WaitFailedUnreleased`: [`MonitoredWithCapture::take_live_capture`]
/// - 捕捉の開始後の `Err`（`wait` の失敗・停止時の監視権解放の失敗）: [`MonitorWithCaptureError::take_live_capture`]
///
/// 呼び出し側は [`LogCapture::cancel`] で捕捉を止めるか、取っ手を保持して捕捉を続け（再監視は
/// [`monitor_with_observer`] で行う）、後で [`LogCapture::drain`] する。取っ手を破棄するとリーダーは EOF まで走り、
/// 止める手段が無くなる。捕捉の引き継ぎの本実装は #239・TASK-164 で扱う。
///
/// 生存リーダー数は `streams` を作るときに渡した [`crate::logs::ReaderBudget`] で数える（省略できない）。
/// 過去の捕捉で終端待ちが期限切れになり残ったリーダーも同じ予算に数えられ、上限に達していれば捕捉開始は
/// `Unavailable`（`too many log reader threads are still alive`）で失敗して上記の開始失敗の扱いになる（REPAIR-5）。
/// 呼び出し側は supervisor プロセスにつき 1 つの予算を、再起動・再捕捉をまたいで使い回すこと。
/// 終端待ちが失敗（`Timeout` 等）した場合、捕捉は取り消され、以後 sink への新しい追記は始まらない。
/// sink の追記が止まっていても終端待ちは `drain_timeout` 以内に返る（[`LogCapture::drain`]）。
pub fn monitor_with_capture(
    state: &mut SupervisedState,
    process: &dyn LaunchedProcess,
    streams: &mut OutputStreams,
    sink: Arc<dyn LogSink>,
    config: &MonitorConfig,
    stop: &StopToken,
    obs: &dyn MonitorObserver,
) -> Result<MonitoredWithCapture, MonitorWithCaptureError> {
    if !is_running_with_pid(state.record(), process.pid()) {
        return Err(MonitorWithCaptureError {
            error: precondition("container is not running with the launched pid"),
            live_capture: None,
        });
    }
    // 監視権の取得後に捕捉を開始する。権限を得られない場合・開始失敗の場合に出力ストリームを消費しない。
    // `streams` は可変参照で受け、監視権の取得に成功した場合のみ中身を取り出す。取得失敗時は呼び出し側の手元に残る。
    let mut capture: Option<LogCapture> = None;
    let monitored = monitor_after_claim(state, process, config, stop, obs, &mut || {
        capture = Some(observed(obs, MonitorOperation::CaptureStart, || {
            // 開始失敗時は streams が呼び出し側へ戻るため、捕捉を再試行できる。
            LogCapture::start_from(streams, Arc::clone(&sink))
        })?);
        Ok(())
    });
    let outcome = match monitored {
        Ok(outcome) => outcome,
        // 捕捉の開始後の失敗では、取っ手を返して呼び出し側が止められる・引き継げるようにする。
        Err(error) => {
            return Err(MonitorWithCaptureError {
                error,
                live_capture: capture,
            });
        }
    };
    let exited = matches!(
        outcome,
        MonitorOutcome::Exited { .. } | MonitorOutcome::ExitedUnrecorded { .. }
    );
    if !exited {
        // プロセスが生存し得るので EOF を待たない。継続中の捕捉は取っ手ごと呼び出し側へ返す。
        return Ok(MonitoredWithCapture {
            outcome,
            capture: None,
            capture_error: None,
            live_capture: capture,
        });
    }
    let Some(capture) = capture else {
        return Ok(MonitoredWithCapture {
            outcome,
            capture: None,
            capture_error: None,
            live_capture: None,
        });
    };
    // 読み取り・sink 追記の失敗は集計（StreamSummary::error_code）にだけ残り drain 自体は Ok になるため、
    // 観測イベントには集計内の最初の失敗コードを載せる（失敗カウント・監視に現れるように。REPAIR-4）。
    let drain_started = Instant::now();
    let drained = capture.drain(config.drain_timeout());
    obs.observe(&MonitorEvent {
        operation: MonitorOperation::CaptureDrain,
        error_code: match &drained {
            Ok(summary) => summary
                .stdout()
                .and_then(StreamSummary::error_code)
                .or_else(|| summary.stderr().and_then(StreamSummary::error_code)),
            Err(e) => Some(e.code()),
        },
        elapsed: drain_started.elapsed(),
    });
    Ok(match drained {
        Ok(summary) => MonitoredWithCapture {
            outcome,
            capture: Some(summary),
            capture_error: None,
            live_capture: None,
        },
        Err(e) => MonitoredWithCapture {
            outcome,
            capture: None,
            capture_error: Some(e),
            live_capture: None,
        },
    })
}

/// `supervisor_pid` を `None` に戻す（`health`・`restart_count` は保つ）。
fn release_supervisor_pid(
    state: &mut SupervisedState,
    pid: NonZeroU32,
    self_pid: NonZeroU32,
) -> Result<StateRecord, TraitError> {
    write_with_retry(state, pid, |rec| {
        ensure_owner(rec, self_pid)?;
        Ok((
            rec.status().clone(),
            SupervisionState::new(None, rec.health(), rec.restart_count()),
        ))
    })
}

/// 記録上の `supervisor_pid` が自 pid であること（他 supervisor の記録を消さないため。SUP-1）。
pub(crate) fn ensure_owner(rec: &StateRecord, self_pid: NonZeroU32) -> Result<(), TraitError> {
    if rec.supervision().supervisor_pid() == Some(self_pid) {
        Ok(())
    } else {
        Err(precondition(
            "supervisor ownership lost to another supervisor",
        ))
    }
}

pub(crate) fn precondition(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::FailedPrecondition, msg)
}

pub(crate) fn is_running_with_pid(rec: &StateRecord, pid: NonZeroU32) -> bool {
    rec.status().state() == ContainerState::Running && rec.status().pid() == Some(pid)
}

/// revision 不一致のときだけ `refresh` して再構築・再書き込みする（上限 [`MAX_WRITE_ATTEMPTS`]）。
/// 再試行時は「`Running` かつ `pid`」であることを確かめてから書く。
pub(crate) fn write_with_retry<F>(
    state: &mut SupervisedState,
    pid: NonZeroU32,
    build: F,
) -> Result<StateRecord, TraitError>
where
    F: Fn(&StateRecord) -> Result<(ContainerStatus, SupervisionState), TraitError>,
{
    write_with_retry_when(state, |rec| is_running_with_pid(rec, pid), build)
}

/// [`write_with_retry`] の事前条件を述語で受ける版。`refresh` 後に `still_valid` が偽なら書かず `FailedPrecondition`。
///
/// [`crate::restart`] が `Stopped` から `Running(新 pid)` へ戻す書き込みで使う（条件が「自 pid で Running」ではないため）。
pub(crate) fn write_with_retry_when<P, F>(
    state: &mut SupervisedState,
    still_valid: P,
    build: F,
) -> Result<StateRecord, TraitError>
where
    P: Fn(&StateRecord) -> bool,
    F: Fn(&StateRecord) -> Result<(ContainerStatus, SupervisionState), TraitError>,
{
    let mut last_err = precondition("state write attempts exhausted");
    for attempt in 0..MAX_WRITE_ATTEMPTS {
        if attempt > 0 {
            state.refresh()?;
            if !still_valid(state.record()) {
                return Err(precondition(
                    "container state changed while writing supervision",
                ));
            }
        }
        let (status, supervision) = build(state.record())?;
        match state.write(status, supervision) {
            Ok(rec) => return Ok(rec.clone()),
            Err(e) if e.code() == ErrorCode::FailedPrecondition => last_err = e,
            Err(e) => return Err(e),
        }
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU32;

    use crate::logs::ReaderBudget;

    use fandhe_container_core::traits::{
        ContainerId, CreateStateRequest, DeleteStateRequest, DeleteStateResponse, GetStateRequest,
        HealthStatus, ListStateRequest, StateList, StateRevision, StateStore, UpdateStateRequest,
    };

    fn cid() -> ContainerId {
        ContainerId::new("c1").unwrap()
    }

    fn pid(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    fn next_record(cur: &StateRecord, status: ContainerStatus, s: SupervisionState) -> StateRecord {
        StateRecord::new(
            status,
            cur.bundle().to_path_buf(),
            StateRevision::from_raw(cur.revision().value() + 1),
        )
        .unwrap()
        .with_supervision(s)
    }

    /// メモリ上の 1 レコードストア。`conflicts` 回だけ外部更新（restart_count +1）で競合させる。
    struct FakeStore {
        rec: Mutex<StateRecord>,
        conflicts: Mutex<u32>,
        updates: AtomicU32,
    }

    impl StateStore for FakeStore {
        fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "fake"))
        }
        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            self.updates.fetch_add(1, Ordering::SeqCst);
            let mut g = self.rec.lock().unwrap();
            let mut c = self.conflicts.lock().unwrap();
            let sup = g.supervision();
            if *c > 0 {
                *c -= 1;
                let s = SupervisionState::new(
                    sup.supervisor_pid(),
                    sup.health(),
                    sup.restart_count() + 1,
                );
                *g = next_record(&g, g.status().clone(), s);
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            if g.revision() != req.expected_revision() {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            let s = req.supervision().unwrap_or(sup);
            let next = next_record(&g, req.status().clone(), s);
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

    fn store_with(
        status: ContainerStatus,
        sup: SupervisionState,
        conflicts: u32,
    ) -> Arc<FakeStore> {
        let rec = StateRecord::new(
            status,
            std::env::temp_dir().join("b"),
            StateRevision::from_raw(1),
        )
        .unwrap()
        .with_supervision(sup);
        Arc::new(FakeStore {
            rec: Mutex::new(rec),
            conflicts: Mutex::new(conflicts),
            updates: AtomicU32::new(0),
        })
    }

    fn running_store(conflicts: u32) -> Arc<FakeStore> {
        store_with(
            ContainerStatus::running(cid(), Some(pid(42))),
            SupervisionState::default(),
            conflicts,
        )
    }

    /// `exit_at` 回目の `wait` で終了を返す（`None` なら常に生存）。`fail` なら常に Err。
    struct FakeProc {
        exit_at: Option<(u32, ProcessExit)>,
        fail: bool,
        waits: AtomicU32,
    }

    impl FakeProc {
        fn new(exit_at: Option<(u32, ProcessExit)>, fail: bool) -> Self {
            Self {
                exit_at,
                fail,
                waits: AtomicU32::new(0),
            }
        }
        fn exiting(at: u32, e: ProcessExit) -> Self {
            Self::new(Some((at, e)), false)
        }
        fn alive() -> Self {
            Self::new(None, false)
        }
        fn failing() -> Self {
            Self::new(None, true)
        }
        fn waits(&self) -> u32 {
            self.waits.load(Ordering::SeqCst)
        }
    }

    impl LaunchedProcess for FakeProc {
        fn pid(&self) -> NonZeroU32 {
            pid(42)
        }
        fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
            let n = self.waits.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail {
                return Err(TraitError::new(ErrorCode::Internal, "fake wait failure"));
            }
            Ok(match self.exit_at {
                Some((at, e)) if n >= at => Some(e),
                _ => None,
            })
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            Ok(())
        }
    }

    fn attach(store: &Arc<FakeStore>) -> SupervisedState {
        SupervisedState::attach(store.clone(), cid()).unwrap()
    }

    /// SUP-1・TASK-157.4: 3 回目の wait で exit を検知し Stopped を記録する。
    #[test]
    fn sup1_task157_4_detects_exit() {
        let store = running_store(0);
        let mut s = attach(&store);
        let p = FakeProc::exiting(3, ProcessExit::Exited(7));
        let out = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap();
        let MonitorOutcome::Exited { exit, record } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(exit, ProcessExit::Exited(7));
        assert_eq!(record.status().state(), ContainerState::Stopped);
        assert_eq!(record.status().exit_code(), Some(7));
        assert_eq!(record.status().pid(), None);
        assert_eq!(record.supervisor_pid(), None);
        assert_eq!(p.waits(), 3);
        // 初期 1 + 監視開始 + 終了
        assert_eq!(record.revision().value(), 3);
    }

    /// TASK-157.4: シグナル終了は 128 + 番号。
    #[test]
    fn sup1_task157_4_signal_exit_code() {
        let store = running_store(0);
        let mut s = attach(&store);
        let p = FakeProc::exiting(1, ProcessExit::Signaled(9));
        let out = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap();
        let MonitorOutcome::Exited { exit, record } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(exit, ProcessExit::Signaled(9));
        assert_eq!(record.status().exit_code(), Some(137));
        assert_eq!(exit_code_of(ProcessExit::Signaled(i32::MAX)), None);
    }

    /// TASK-157.4: 監視中（wait 内）に supervisor_pid が自プロセスの pid で記録されている。
    #[test]
    fn sup1_task157_4_records_supervisor_pid_while_alive() {
        let store = running_store(0);
        let mut s = attach(&store);
        let observed: Mutex<Vec<Option<NonZeroU32>>> = Mutex::new(Vec::new());
        struct Obs<'a> {
            store: &'a FakeStore,
            observed: &'a Mutex<Vec<Option<NonZeroU32>>>,
        }
        impl LaunchedProcess for Obs<'_> {
            fn pid(&self) -> NonZeroU32 {
                pid(42)
            }
            fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
                let sp = self
                    .store
                    .rec
                    .lock()
                    .unwrap()
                    .supervision()
                    .supervisor_pid();
                self.observed.lock().unwrap().push(sp);
                Ok(Some(ProcessExit::Exited(0)))
            }
            fn terminate(&self, _: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }
        let p = Obs {
            store: &store,
            observed: &observed,
        };
        let out = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap();
        assert_eq!(
            *observed.lock().unwrap(),
            vec![NonZeroU32::new(std::process::id())]
        );
        let MonitorOutcome::Exited { record, .. } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(record.supervisor_pid(), None);
    }

    /// TASK-157.4: 回収後の書き込み失敗でも終了状態を失わず ExitedUnrecorded で返す。
    #[test]
    fn sup1_task157_4_exit_survives_write_failure() {
        let store = running_store(0);
        let mut s = attach(&store);
        // 監視開始の書き込み後、終了の書き込みだけが競合し続けるよう wait 内で競合を仕込む。
        struct Racy<'a>(&'a FakeStore);
        impl LaunchedProcess for Racy<'_> {
            fn pid(&self) -> NonZeroU32 {
                pid(42)
            }
            fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
                *self.0.conflicts.lock().unwrap() = 100;
                Ok(Some(ProcessExit::Exited(5)))
            }
            fn terminate(&self, _: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }
        let p = Racy(&store);
        let out = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap();
        let MonitorOutcome::ExitedUnrecorded { exit, error } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(exit, ProcessExit::Exited(5));
        assert_eq!(error.code(), ErrorCode::FailedPrecondition);
        assert_eq!(
            store.rec.lock().unwrap().status().state(),
            ContainerState::Running
        );
    }

    /// TASK-157.4: health・restart_count は終了後も保持される。
    #[test]
    fn sup1_task157_4_preserves_health_and_restart_count() {
        let store = store_with(
            ContainerStatus::running(cid(), Some(pid(42))),
            SupervisionState::new(None, Some(HealthStatus::Healthy), 2),
            0,
        );
        let mut s = attach(&store);
        let p = FakeProc::exiting(2, ProcessExit::Exited(0));
        let out = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap();
        let MonitorOutcome::Exited { record, .. } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(record.health(), Some(HealthStatus::Healthy));
        assert_eq!(record.restart_count(), 2);
    }

    /// SUP-1・TASK-157.4: 自プロセス pid が既に記録されていても（同一プロセス内の二重監視）開始を拒否する。
    #[test]
    fn sup1_task157_4_rejects_own_pid_owner_at_start() {
        let me = pid(std::process::id());
        let store = store_with(
            ContainerStatus::running(cid(), Some(pid(42))),
            SupervisionState::new(Some(me), SupervisionState::default().health(), 0),
            0,
        );
        let mut s = attach(&store);
        let p = FakeProc::alive();
        let e = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(p.waits(), 0);
    }

    /// SUP-1・TASK-157.4: revision 競合後の refresh で他方の自 pid 記録を見たら、二重に開始しない。
    #[test]
    fn sup1_task157_4_rejects_double_monitor_after_conflict_refresh() {
        let store = running_store(1);
        let mut s2 = attach(&store);
        // 先行する monitor が競合の隙に自 pid を記録した状況を再現する。
        {
            let mut g = store.rec.lock().unwrap();
            let cur = g.clone();
            *g = next_record(
                &cur,
                cur.status().clone(),
                SupervisionState::new(Some(pid(std::process::id())), cur.health(), 0),
            );
        }
        let p = FakeProc::alive();
        let e = monitor(&mut s2, &p, &MonitorConfig::default(), &StopToken::new()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(p.waits(), 0);
    }

    /// SUP-1・TASK-157.4: 別 supervisor が監視中なら開始を拒否し、記録を奪わない。
    #[test]
    fn sup1_task157_4_rejects_foreign_owner_at_start() {
        let store = store_with(
            ContainerStatus::running(cid(), Some(pid(42))),
            SupervisionState::new(Some(pid(999_999)), SupervisionState::default().health(), 0),
            0,
        );
        let mut s = attach(&store);
        let p = FakeProc::alive();
        let e = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(p.waits(), 0);
        let g = store.rec.lock().unwrap();
        assert_eq!(g.supervision().supervisor_pid(), Some(pid(999_999)));
    }

    /// SUP-1・TASK-157.4: 監視中に所有権が他 supervisor へ移ったら、終了記録でその pid を消さない。
    #[test]
    fn sup1_task157_4_does_not_clear_foreign_owner_on_exit() {
        struct Steal(Arc<FakeStore>);
        impl LaunchedProcess for Steal {
            fn pid(&self) -> NonZeroU32 {
                pid(42)
            }
            fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
                let mut g = self.0.rec.lock().unwrap();
                let s = SupervisionState::new(
                    Some(pid(999_999)),
                    SupervisionState::default().health(),
                    0,
                );
                *g = next_record(&g, g.status().clone(), s);
                Ok(Some(ProcessExit::Exited(0)))
            }
            fn terminate(&self, _: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }
        let store = running_store(0);
        let mut s = attach(&store);
        let p = Steal(store.clone());
        let out = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap();
        assert!(matches!(out, MonitorOutcome::ExitedUnrecorded { .. }));
        let g = store.rec.lock().unwrap();
        assert_eq!(g.supervision().supervisor_pid(), Some(pid(999_999)));
    }

    /// TASK-157.4: 停止要求で戻り、Running のまま supervisor_pid を外す（プロセスは kill しない）。
    #[test]
    fn sup1_task157_4_stop_requested() {
        let store = running_store(0);
        let mut s = attach(&store);
        let p = FakeProc::alive();
        let stop = StopToken::new();
        stop.request_stop();
        let out = monitor(&mut s, &p, &MonitorConfig::default(), &stop).unwrap();
        let MonitorOutcome::StopRequested { record } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(record.status().state(), ContainerState::Running);
        assert_eq!(record.status().pid(), Some(pid(42)));
        assert_eq!(record.supervisor_pid(), None);
        assert_eq!(p.waits(), 0);
    }

    /// TASK-157.4: Created / Stopped / pid 不一致は FailedPrecondition で wait は呼ばれない。
    #[test]
    fn sup1_task157_4_precondition() {
        let cases = [
            ContainerStatus::created(cid(), Some(pid(42))),
            ContainerStatus::stopped(cid(), Some(0)),
            ContainerStatus::running(cid(), Some(pid(43))),
            ContainerStatus::running(cid(), None),
        ];
        for st in cases {
            let store = store_with(st, SupervisionState::default(), 0);
            let mut s = attach(&store);
            let p = FakeProc::alive();
            let e = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap_err();
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(p.waits(), 0);
            assert_eq!(store.updates.load(Ordering::SeqCst), 0);
        }
    }

    /// REPAIR-5: wait の失敗は 1 回で返る。
    #[test]
    fn sup1_task157_4_wait_failure_is_returned() {
        let store = running_store(0);
        let mut s = attach(&store);
        let p = FakeProc::failing();
        let e = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
        assert_eq!(p.waits(), 1);
        // wait 失敗時は記録済みの supervisor_pid を解除している。
        assert_eq!(
            store.rec.lock().unwrap().supervision().supervisor_pid(),
            None
        );
    }

    /// 解除にも失敗したら WaitFailedUnreleased で両方の失敗を返す。
    #[test]
    fn sup1_task157_4_wait_failure_release_failure_is_identifiable() {
        let store = running_store(0);
        let mut s = attach(&store);
        struct FailRacy<'a>(&'a FakeStore);
        impl LaunchedProcess for FailRacy<'_> {
            fn pid(&self) -> NonZeroU32 {
                pid(42)
            }
            fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
                *self.0.conflicts.lock().unwrap() = 100;
                Err(TraitError::new(ErrorCode::Internal, "fake wait failure"))
            }
            fn terminate(&self, _: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }
        let p = FailRacy(&store);
        let out = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap();
        let MonitorOutcome::WaitFailedUnreleased {
            wait_error,
            release_error,
        } = out
        else {
            panic!("unexpected outcome")
        };
        assert_eq!(wait_error.code(), ErrorCode::Internal);
        assert_eq!(release_error.code(), ErrorCode::FailedPrecondition);
    }

    /// TASK-157.7: 捕捉開始（after_claim）の失敗と解除失敗の両方を StartFailedUnreleased で返す。
    #[test]
    fn sup1_task157_7_start_failure_release_failure_is_identifiable() {
        let store = running_store(0);
        let mut s = attach(&store);
        let p = FakeProc::alive();
        let out = monitor_after_claim(
            &mut s,
            &p,
            &MonitorConfig::default(),
            &StopToken::new(),
            &StderrLogObserver,
            &mut || {
                *store.conflicts.lock().unwrap() = 100;
                Err(TraitError::new(ErrorCode::Internal, "fake start failure"))
            },
        )
        .unwrap();
        let MonitorOutcome::StartFailedUnreleased {
            start_error,
            release_error,
        } = out
        else {
            panic!("unexpected outcome")
        };
        assert_eq!(start_error.code(), ErrorCode::Internal);
        assert_eq!(release_error.code(), ErrorCode::FailedPrecondition);
    }

    struct Rec(Mutex<Vec<(MonitorOperation, Option<ErrorCode>)>>);
    impl MonitorObserver for Rec {
        fn observe(&self, e: &MonitorEvent) {
            self.0.lock().unwrap().push((e.operation, e.error_code));
        }
    }

    /// REPAIR-4: 開始・wait・終了記録が通知され、開始失敗はエラーコード付きで通知される。
    #[test]
    fn sup1_task157_4_observer_reports_operations() {
        let store = running_store(0);
        let mut s = attach(&store);
        let p = FakeProc::exiting(2, ProcessExit::Exited(0));
        let rec = Rec(Mutex::new(Vec::new()));
        monitor_with_observer(
            &mut s,
            &p,
            &MonitorConfig::default(),
            &StopToken::new(),
            &rec,
        )
        .unwrap();
        assert_eq!(
            *rec.0.lock().unwrap(),
            vec![
                (MonitorOperation::Start, None),
                (MonitorOperation::Wait, None),
                (MonitorOperation::Wait, None),
                (MonitorOperation::RecordExit, None),
            ]
        );

        let store = running_store(100);
        let mut s = attach(&store);
        let p = FakeProc::alive();
        let rec = Rec(Mutex::new(Vec::new()));
        monitor_with_observer(
            &mut s,
            &p,
            &MonitorConfig::default(),
            &StopToken::new(),
            &rec,
        )
        .unwrap_err();
        assert_eq!(
            *rec.0.lock().unwrap(),
            vec![(MonitorOperation::Start, Some(ErrorCode::FailedPrecondition))]
        );
    }

    /// REPAIR-5: 競合 1 回は refresh 後に成功し、競合側の restart_count が保たれる。
    #[test]
    fn sup1_task157_4_retry_succeeds_and_keeps_foreign_update() {
        let store = running_store(1);
        let mut s = attach(&store);
        let p = FakeProc::exiting(1, ProcessExit::Exited(0));
        let out = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap();
        let MonitorOutcome::Exited { record, .. } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(record.restart_count(), 1);
        assert_eq!(record.status().state(), ContainerState::Stopped);
    }

    /// REPAIR-5: 競合が続けば MAX_WRITE_ATTEMPTS 回で打ち切る。
    #[test]
    fn sup1_task157_4_retry_is_bounded() {
        let store = running_store(100);
        let mut s = attach(&store);
        let p = FakeProc::alive();
        let e = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(store.updates.load(Ordering::SeqCst), MAX_WRITE_ATTEMPTS);
    }

    /// 設定検証: 0 と上限超過は拒否し、境界値は受理する。
    #[test]
    fn sup1_task157_4_config_validation() {
        for bad in [Duration::ZERO, MAX_POLL_INTERVAL + Duration::from_nanos(1)] {
            assert_eq!(
                MonitorConfig::new(bad).unwrap_err().code(),
                ErrorCode::InvalidArgument
            );
        }
        assert!(MonitorConfig::new(Duration::from_nanos(1)).is_ok());
        assert_eq!(
            MonitorConfig::new(MAX_POLL_INTERVAL)
                .unwrap()
                .poll_interval(),
            MAX_POLL_INTERVAL
        );
    }

    fn capture_streams(out: &[u8], err: &[u8]) -> (OutputStreams, Arc<crate::logs::MemoryLogSink>) {
        use std::io::Cursor;
        (
            OutputStreams::new(
                &ReaderBudget::with_max_limit(),
                Some(Box::new(Cursor::new(out.to_vec()))),
                Some(Box::new(Cursor::new(err.to_vec()))),
            ),
            Arc::new(crate::logs::MemoryLogSink::default()),
        )
    }

    /// SUP-1・TASK-157.7: 終了検知後に drain し、行数・バイト数が具体値で返る。
    #[test]
    fn sup1_task157_7_monitor_with_capture_drains_after_exit() {
        let store = running_store(0);
        let mut s = attach(&store);
        let p = FakeProc::exiting(1, ProcessExit::Exited(0));
        let (mut streams, sink) = capture_streams(b"a\nb\n", b"e\n");
        let r = monitor_with_capture(
            &mut s,
            &p,
            &mut streams,
            sink.clone(),
            &MonitorConfig::default(),
            &StopToken::new(),
            &StderrLogObserver,
        )
        .unwrap();
        assert!(matches!(r.outcome(), MonitorOutcome::Exited { .. }));
        assert!(r.capture_error().is_none());
        let c = r.capture().unwrap();
        assert_eq!(c.stdout().unwrap().lines(), 2);
        assert_eq!(c.stderr().unwrap().bytes(), 2);
        assert_eq!(sink.snapshot().unwrap().len(), 3);
    }

    /// REPAIR-5・TASK-157.7: 停止要求では drain を待たない（writer を開いたままでも戻る）。
    #[test]
    fn sup1_task157_7_stop_requested_does_not_wait_for_drain() {
        let store = running_store(0);
        let mut s = attach(&store);
        let p = FakeProc::alive();
        let (reader, writer) = std::io::pipe().unwrap();
        let mut streams = OutputStreams::new(
            &ReaderBudget::with_max_limit(),
            Some(Box::new(reader)),
            None,
        );
        let stop = StopToken::new();
        stop.request_stop();
        let r = monitor_with_capture(
            &mut s,
            &p,
            &mut streams,
            Arc::new(crate::logs::MemoryLogSink::default()),
            &MonitorConfig::default(),
            &stop,
            &StderrLogObserver,
        )
        .unwrap();
        assert!(matches!(r.outcome(), MonitorOutcome::StopRequested { .. }));
        assert!(r.capture().is_none());
        drop(writer);
    }

    /// TASK-157.7: 事前条件違反では捕捉を始めず sink は空のまま。
    #[test]
    fn sup1_task157_7_precondition_failure_starts_no_capture() {
        let store = store_with(
            ContainerStatus::stopped(cid(), Some(0)),
            SupervisionState::default(),
            0,
        );
        let mut s = attach(&store);
        let p = FakeProc::alive();
        let (mut streams, sink) = capture_streams(b"x\n", b"y\n");
        let e = monitor_with_capture(
            &mut s,
            &p,
            &mut streams,
            sink.clone(),
            &MonitorConfig::default(),
            &StopToken::new(),
            &StderrLogObserver,
        )
        .unwrap_err();
        assert_eq!(e.error().code(), ErrorCode::FailedPrecondition);
        // 捕捉を開始していないので、返す取っ手は無い。
        let (_, live) = e.into_parts();
        assert!(live.is_none());
        assert!(sink.snapshot().unwrap().is_empty());
    }

    /// TASK-157.7: 他の supervisor が監視中なら FailedPrecondition で、出力ストリームは 1 バイトも読まれない。
    #[test]
    fn sup1_task157_7_owned_by_other_supervisor_does_not_consume_streams() {
        struct Spy(Arc<AtomicBool>);
        impl std::io::Read for Spy {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                self.0.store(true, Ordering::SeqCst);
                Ok(0)
            }
        }
        let store = store_with(
            ContainerStatus::running(cid(), Some(pid(42))),
            SupervisionState::new(Some(pid(7)), None, 0),
            0,
        );
        let mut s = attach(&store);
        let read = Arc::new(AtomicBool::new(false));
        let sink = Arc::new(crate::logs::MemoryLogSink::default());
        let mut streams = OutputStreams::new(
            &ReaderBudget::with_max_limit(),
            Some(Box::new(Spy(read.clone()))),
            None,
        );
        let e = monitor_with_capture(
            &mut s,
            &FakeProc::alive(),
            &mut streams,
            sink.clone(),
            &MonitorConfig::default(),
            &StopToken::new(),
            &StderrLogObserver,
        )
        .unwrap_err();
        assert_eq!(e.error().code(), ErrorCode::FailedPrecondition);
        // 監視権を得られなかった場合、ストリームは呼び出し側に残る。
        assert!(!streams.is_empty());
        std::thread::sleep(Duration::from_millis(50));
        assert!(!read.load(Ordering::SeqCst));
        assert!(sink.snapshot().unwrap().is_empty());
    }

    /// TASK-157.7: drain が Timeout でも監視結果は失われない。
    #[test]
    fn sup1_task157_7_drain_timeout_keeps_outcome() {
        let store = running_store(0);
        let mut s = attach(&store);
        let p = FakeProc::exiting(1, ProcessExit::Exited(3));
        let (reader, writer) = std::io::pipe().unwrap();
        let mut streams = OutputStreams::new(
            &ReaderBudget::with_max_limit(),
            Some(Box::new(reader)),
            None,
        );
        let cfg = MonitorConfig::default()
            .with_drain_timeout(Duration::from_millis(50))
            .unwrap();
        let r = monitor_with_capture(
            &mut s,
            &p,
            &mut streams,
            Arc::new(crate::logs::MemoryLogSink::default()),
            &cfg,
            &StopToken::new(),
            &StderrLogObserver,
        )
        .unwrap();
        assert!(matches!(
            r.outcome(),
            MonitorOutcome::Exited {
                exit: ProcessExit::Exited(3),
                ..
            }
        ));
        assert_eq!(
            r.capture_error().map(|e| e.code()),
            Some(ErrorCode::Timeout)
        );
        drop(writer);
    }

    /// REPAIR-5・TASK-157.7: 終端待ちが期限切れになった監視の残存リーダーは、同じ予算を使う次の監視の捕捉開始でも
    /// 数えられる。上限 1・残存 1 本なら次の捕捉開始は Unavailable で失敗し、監視権は解放され、ストリームは未読で残る。
    #[test]
    fn sup1_task157_7_stuck_reader_blocks_next_capture_with_shared_budget() {
        let budget = ReaderBudget::new(1).unwrap();
        let cfg = MonitorConfig::default()
            .with_drain_timeout(Duration::from_millis(50))
            .unwrap();
        let sink = Arc::new(crate::logs::MemoryLogSink::default());

        // 1 回目: 子は終了したがパイプが開いたまま（孫プロセスが保持する状況）で、終端待ちが期限切れになる。
        let store = running_store(0);
        let mut s = attach(&store);
        let (reader, writer) = std::io::pipe().unwrap();
        let mut streams = OutputStreams::new(&budget, Some(Box::new(reader)), None);
        let r = monitor_with_capture(
            &mut s,
            &FakeProc::exiting(1, ProcessExit::Exited(0)),
            &mut streams,
            sink.clone(),
            &cfg,
            &StopToken::new(),
            &StderrLogObserver,
        )
        .unwrap();
        assert_eq!(
            r.capture_error().map(|e| e.code()),
            Some(ErrorCode::Timeout)
        );
        assert_eq!(budget.live(), 1);

        // 2 回目（再起動後を想定）: 新しい OutputStreams でも同じ予算で数えられ、開始が拒否される。
        let store = running_store(0);
        let mut s = attach(&store);
        let mut streams = OutputStreams::new(
            &budget,
            Some(Box::new(std::io::Cursor::new(b"x\n".to_vec()))),
            None,
        );
        let rec = Rec(Mutex::new(Vec::new()));
        let e = monitor_with_capture(
            &mut s,
            &FakeProc::alive(),
            &mut streams,
            sink.clone(),
            &cfg,
            &StopToken::new(),
            &rec,
        )
        .unwrap_err();
        let (e, live) = e.into_parts();
        assert_eq!(e.code(), ErrorCode::Unavailable);
        assert_eq!(e.message(), "too many log reader threads are still alive");
        assert!(live.is_none());
        assert_eq!(
            *rec.0.lock().unwrap(),
            vec![
                (MonitorOperation::Start, None),
                (MonitorOperation::CaptureStart, Some(ErrorCode::Unavailable)),
                (MonitorOperation::ReleaseAfterWaitError, None),
            ]
        );
        assert!(!streams.is_empty());
        assert_eq!(
            store.rec.lock().unwrap().supervision().supervisor_pid(),
            None
        );
        assert_eq!(budget.live(), 1);
        assert!(sink.snapshot().unwrap().is_empty());

        // 残存リーダーが終了すれば枠が戻る。
        drop(writer);
        let start = Instant::now();
        while budget.live() != 0 && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(budget.live(), 0);
    }

    /// REPAIR-5・TASK-157.7: 捕捉の開始後に wait が失敗して Err になっても、継続中の捕捉の取っ手が返る。
    /// 呼び出し側は cancel で止められ、以後に届いた行は追記されず、リーダーは終了して枠を返す。
    #[test]
    fn sup1_task157_7_wait_failure_returns_live_capture_handle() {
        let budget = ReaderBudget::new(1).unwrap();
        let store = running_store(0);
        let mut s = attach(&store);
        let (reader, mut writer) = std::io::pipe().unwrap();
        let mut streams = OutputStreams::new(&budget, Some(Box::new(reader)), None);
        let sink = Arc::new(crate::logs::MemoryLogSink::default());
        let mut e = monitor_with_capture(
            &mut s,
            &FakeProc::failing(),
            &mut streams,
            sink.clone(),
            &MonitorConfig::default(),
            &StopToken::new(),
            &StderrLogObserver,
        )
        .unwrap_err();
        assert_eq!(e.error().code(), ErrorCode::Internal);
        assert_eq!(e.error().message(), "fake wait failure");
        assert_eq!(e.to_string(), "INTERNAL: fake wait failure");
        // 監視権は解放済みで、ストリームはリーダーへ移っている（取っ手が捕捉の継続を表す）。
        assert_eq!(
            store.rec.lock().unwrap().supervision().supervisor_pid(),
            None
        );
        assert!(streams.is_empty());
        assert_eq!(budget.live(), 1);

        let live = e.take_live_capture().unwrap();
        assert!(e.take_live_capture().is_none());
        assert_eq!(live.cancel(), Ok(()));
        std::io::Write::write_all(&mut writer, b"late\n").unwrap();
        let start = Instant::now();
        while budget.live() != 0 && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(budget.live(), 0);
        assert!(sink.snapshot().unwrap().is_empty());
        drop(writer);
    }

    /// REPAIR-5・TASK-157.7: 停止要求では終端待ちをせず、継続中の捕捉の取っ手を返す。
    /// 取っ手を保持すれば捕捉は続き、後で drain して集計（1 行・2 バイト）を得られる。
    #[test]
    fn sup1_task157_7_stop_requested_returns_live_capture_handle() {
        let budget = ReaderBudget::new(1).unwrap();
        let store = running_store(0);
        let mut s = attach(&store);
        let (reader, mut writer) = std::io::pipe().unwrap();
        let mut streams = OutputStreams::new(&budget, Some(Box::new(reader)), None);
        let sink = Arc::new(crate::logs::MemoryLogSink::default());
        let stop = StopToken::new();
        stop.request_stop();
        let mut r = monitor_with_capture(
            &mut s,
            &FakeProc::alive(),
            &mut streams,
            sink.clone(),
            &MonitorConfig::default(),
            &stop,
            &StderrLogObserver,
        )
        .unwrap();
        assert!(matches!(r.outcome(), MonitorOutcome::StopRequested { .. }));
        assert!(r.capture().is_none());
        assert!(r.capture_error().is_none());
        let live = r.take_live_capture().unwrap();
        assert!(r.take_live_capture().is_none());

        std::io::Write::write_all(&mut writer, b"a\n").unwrap();
        drop(writer);
        let sum = live.drain(Duration::from_secs(10)).unwrap();
        assert_eq!(sum.stdout().unwrap().lines(), 1);
        assert_eq!(sum.stdout().unwrap().bytes(), 2);
        assert_eq!(sink.snapshot().unwrap().len(), 1);
    }

    /// TASK-157.7: 終了を検知して終端待ちをした結果では、返す取っ手は無い（drain が消費済み）。
    #[test]
    fn sup1_task157_7_exited_returns_no_live_capture_handle() {
        let store = running_store(0);
        let mut s = attach(&store);
        let (mut streams, sink) = capture_streams(b"a\n", b"");
        let mut r = monitor_with_capture(
            &mut s,
            &FakeProc::exiting(1, ProcessExit::Exited(0)),
            &mut streams,
            sink,
            &MonitorConfig::default(),
            &StopToken::new(),
            &StderrLogObserver,
        )
        .unwrap();
        assert_eq!(r.capture().unwrap().stdout().unwrap().lines(), 1);
        assert!(r.take_live_capture().is_none());
    }

    /// REPAIR-4・TASK-157.7: 捕捉操作が通知される。
    #[test]
    fn sup1_task157_7_observer_reports_capture_operations() {
        let store = running_store(0);
        let mut s = attach(&store);
        let p = FakeProc::exiting(1, ProcessExit::Exited(0));
        let (mut streams, sink) = capture_streams(b"", b"");
        let rec = Rec(Mutex::new(Vec::new()));
        monitor_with_capture(
            &mut s,
            &p,
            &mut streams,
            sink,
            &MonitorConfig::default(),
            &StopToken::new(),
            &rec,
        )
        .unwrap();
        assert_eq!(
            *rec.0.lock().unwrap(),
            vec![
                (MonitorOperation::Start, None),
                (MonitorOperation::CaptureStart, None),
                (MonitorOperation::Wait, None),
                (MonitorOperation::RecordExit, None),
                (MonitorOperation::CaptureDrain, None),
            ]
        );
        assert_eq!(MonitorOperation::CaptureStart.as_str(), "capture_start");
        assert_eq!(MonitorOperation::CaptureDrain.as_str(), "capture_drain");
    }

    /// REPAIR-4・TASK-157.7: sink 追記の失敗は CaptureDrain の観測イベントに失敗コードとして現れる。
    #[test]
    fn sup1_task157_7_sink_failure_is_reported_in_drain_event() {
        struct FailSink;
        impl LogSink for FailSink {
            fn append(&self, _: crate::logs::StreamKind, _: &[u8]) -> Result<(), TraitError> {
                Err(TraitError::new(ErrorCode::Internal, "fake sink failure"))
            }
        }
        let store = running_store(0);
        let mut s = attach(&store);
        let p = FakeProc::exiting(1, ProcessExit::Exited(0));
        let (mut streams, _) = capture_streams(b"a\n", b"");
        let rec = Rec(Mutex::new(Vec::new()));
        let r = monitor_with_capture(
            &mut s,
            &p,
            &mut streams,
            Arc::new(FailSink),
            &MonitorConfig::default(),
            &StopToken::new(),
            &rec,
        )
        .unwrap();
        assert_eq!(
            r.capture().unwrap().stdout().unwrap().error_code(),
            Some(ErrorCode::Internal)
        );
        assert_eq!(
            rec.0.lock().unwrap().last().copied(),
            Some((MonitorOperation::CaptureDrain, Some(ErrorCode::Internal)))
        );
    }

    /// TASK-157.7: drain_timeout の検証（0・上限超は拒否、境界は受理）。
    #[test]
    fn sup1_task157_7_drain_timeout_validation() {
        for bad in [Duration::ZERO, MAX_DRAIN_TIMEOUT + Duration::from_nanos(1)] {
            assert_eq!(
                MonitorConfig::default()
                    .with_drain_timeout(bad)
                    .unwrap_err()
                    .code(),
                ErrorCode::InvalidArgument
            );
        }
        assert_eq!(
            MonitorConfig::default()
                .with_drain_timeout(MAX_DRAIN_TIMEOUT)
                .unwrap()
                .drain_timeout(),
            MAX_DRAIN_TIMEOUT
        );
        assert_eq!(
            MonitorConfig::default().drain_timeout(),
            DEFAULT_DRAIN_TIMEOUT
        );
    }

    fn exit_with(init: SupervisionState, e: ProcessExit) -> (MonitorOutcome, Arc<FakeStore>) {
        let store = store_with(ContainerStatus::running(cid(), Some(pid(42))), init, 0);
        let mut s = attach(&store);
        let p = FakeProc::exiting(1, e);
        let out = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap();
        (out, store)
    }

    /// SUP-3・TASK-159.3: 非 0 終了でも monitor 単体は restart_count を進めず（2 のまま）、health は保たれる。
    /// 加算は再 launch 成功時（`restart.rs`）だけが行う。
    #[test]
    fn sup3_task159_3_abnormal_exit_keeps_restart_count() {
        let init = SupervisionState::new(None, Some(HealthStatus::Healthy), 2);
        let (out, store) = exit_with(init, ProcessExit::Exited(7));
        let MonitorOutcome::Exited { record, .. } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(record.restart_count(), 2);
        assert_eq!(record.health(), Some(HealthStatus::Healthy));
        assert_eq!(record.status().state(), ContainerState::Stopped);
        assert_eq!(record.status().exit_code(), Some(7));
        assert_eq!(record.supervisor_pid(), None);
        assert_eq!(store.rec.lock().unwrap().restart_count(), 2);
    }

    /// SUP-3・TASK-159.3: シグナル終了でも restart_count は 0 のまま、終了コードは 137。
    #[test]
    fn sup3_task159_3_signal_exit_keeps_restart_count() {
        let (out, _) = exit_with(SupervisionState::default(), ProcessExit::Signaled(9));
        let MonitorOutcome::Exited { record, .. } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(record.restart_count(), 0);
        assert_eq!(record.status().exit_code(), Some(137));
    }

    /// SUP-3・TASK-159.3: 正常終了でも restart_count は 2 のまま。
    #[test]
    fn sup3_task159_3_normal_exit_keeps_restart_count() {
        let init = SupervisionState::new(None, None, 2);
        let (out, _) = exit_with(init, ProcessExit::Exited(0));
        let MonitorOutcome::Exited { record, .. } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(record.restart_count(), 2);
    }

    /// SUP-3・TASK-159.3: 競合 1 回（外部が +1）の後も外部の更新が保たれる（0 -> 1。monitor は加算しない）。
    #[test]
    fn sup3_task159_3_exit_record_keeps_foreign_restart_count_update() {
        let store = running_store(1);
        let mut s = attach(&store);
        let p = FakeProc::exiting(1, ProcessExit::Exited(1));
        let out = monitor(&mut s, &p, &MonitorConfig::default(), &StopToken::new()).unwrap();
        let MonitorOutcome::Exited { record, .. } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(record.restart_count(), 1);
    }

    /// SUP-3・TASK-159.3: 終了記録が失敗した場合、外部加算 3 回ぶんのみが残り Running のまま。
    #[test]
    fn sup3_task159_3_unrecorded_exit_leaves_running() {
        let store = running_store(0);
        let mut s = attach(&store);
        struct Racy<'a>(&'a FakeStore);
        impl LaunchedProcess for Racy<'_> {
            fn pid(&self) -> NonZeroU32 {
                pid(42)
            }
            fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
                *self.0.conflicts.lock().unwrap() = 100;
                Ok(Some(ProcessExit::Exited(5)))
            }
            fn terminate(&self, _: Duration) -> Result<(), TraitError> {
                Ok(())
            }
        }
        let out = monitor(
            &mut s,
            &Racy(&store),
            &MonitorConfig::default(),
            &StopToken::new(),
        )
        .unwrap();
        assert!(matches!(out, MonitorOutcome::ExitedUnrecorded { .. }));
        let g = store.rec.lock().unwrap();
        assert_eq!(g.status().state(), ContainerState::Running);
        assert_eq!(g.restart_count(), MAX_WRITE_ATTEMPTS);
    }

    /// SUP-1・TASK-157.5: 停止要求・wait 失敗では restart_count を変えない。
    #[test]
    fn sup1_task157_5_stop_and_wait_failure_keep_restart_count() {
        let init = SupervisionState::new(None, None, 2);
        let store = store_with(ContainerStatus::running(cid(), Some(pid(42))), init, 0);
        let mut s = attach(&store);
        let stop = StopToken::new();
        stop.request_stop();
        let out = monitor(&mut s, &FakeProc::alive(), &MonitorConfig::default(), &stop).unwrap();
        let MonitorOutcome::StopRequested { record } = out else {
            panic!("unexpected outcome")
        };
        assert_eq!(record.restart_count(), 2);

        let store = store_with(ContainerStatus::running(cid(), Some(pid(42))), init, 0);
        let mut s = attach(&store);
        monitor(
            &mut s,
            &FakeProc::failing(),
            &MonitorConfig::default(),
            &StopToken::new(),
        )
        .unwrap_err();
        assert_eq!(store.rec.lock().unwrap().restart_count(), 2);
    }
}
