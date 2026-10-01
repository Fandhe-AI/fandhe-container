//! 1 コンテナ分の監視ループ（生存確認と終了検知）の基本実装（TASK-157.4・#238・SUP-1。関連: CORE-1・D-19・REPAIR-3・REPAIR-5・SEC-1）。
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
//! - restart 判定・`restart_count` 更新（#239・SUP-3）、health 更新（#240・SUP-4）、stdout / stderr 捕捉（#241）は未実装。
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
//! 4. 終了の記録: `Stopped` と終了コードを書き、`supervisor_pid` を `None` に戻す。回収後の書き込み失敗は
//!    `Err` にせず [`MonitorOutcome::ExitedUnrecorded`] で終了状態ごと返す（プロセスは回収済みで再 wait 不可。回復は #239）。本 issue ではループ終了 =
//!    監視なしのため。再起動で監視を続ける挙動は #239 が変更する。
//! 5. 停止要求（[`StopToken`]）: 監視をやめるだけで、プロセスは終了させない。状態は `Running` のまま
//!    `supervisor_pid` だけ `None` に戻す。起動ハンドルは参照渡しのため所有権は常に呼び出し側に残り、
//!    回収責任（終了・`wait` での回収、または別の監視への引き継ぎ）は呼び出し側が負う契約とする
//!    （[`MonitorOutcome::StopRequested`] の doc 参照）。
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

use crate::state::SupervisedState;

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
        Ok(Self { poll_interval })
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
    /// 終了を検知し、`Stopped` を記録した。
    Exited {
        /// 起動ハンドルが回収した終了状態。
        exit: ProcessExit,
        /// 書き込み後のレコード。
        record: StateRecord,
    },
    /// 終了を検知しプロセスは回収済みだが、`Stopped` の書き込みに失敗した（状態は `Running` のまま、
    /// `supervisor_pid` も自 pid のまま残り得る）。再 `wait` はできないため、終了状態を失わないよう
    /// `exit` と書き込み失敗の `error` を呼び出し側へ返す。回復（再書き込み・再起動判断）は #239（SUP-3）が扱う。
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
fn observed<T>(
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
/// 参照で受けるのは、後続（#239）が同じハンドル・状態で再起動処理を続けられるようにするため。
pub fn monitor_with_observer(
    state: &mut SupervisedState,
    process: &dyn LaunchedProcess,
    config: &MonitorConfig,
    stop: &StopToken,
    obs: &dyn MonitorObserver,
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
fn ensure_owner(rec: &StateRecord, self_pid: NonZeroU32) -> Result<(), TraitError> {
    if rec.supervision().supervisor_pid() == Some(self_pid) {
        Ok(())
    } else {
        Err(precondition(
            "supervisor ownership lost to another supervisor",
        ))
    }
}

fn precondition(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::FailedPrecondition, msg)
}

fn is_running_with_pid(rec: &StateRecord, pid: NonZeroU32) -> bool {
    rec.status().state() == ContainerState::Running && rec.status().pid() == Some(pid)
}

/// 終了状態を状態ファイルへ記録する終了コードへ写す（`Signaled(s)` は `128 + s`）。
fn exit_code_of(exit: ProcessExit) -> Option<i32> {
    match exit {
        ProcessExit::Exited(c) => Some(c),
        ProcessExit::Signaled(s) => 128i32.checked_add(s),
        _ => None,
    }
}

/// revision 不一致のときだけ `refresh` して再構築・再書き込みする（上限 [`MAX_WRITE_ATTEMPTS`]）。
fn write_with_retry<F>(
    state: &mut SupervisedState,
    pid: NonZeroU32,
    build: F,
) -> Result<StateRecord, TraitError>
where
    F: Fn(&StateRecord) -> Result<(ContainerStatus, SupervisionState), TraitError>,
{
    let mut last_err = precondition("state write attempts exhausted");
    for attempt in 0..MAX_WRITE_ATTEMPTS {
        if attempt > 0 {
            state.refresh()?;
            if !is_running_with_pid(state.record(), pid) {
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
}
