//! healthcheck の判定結果を `state.json` の `health` へ反映するフックの土台（TASK-157.6・#240・SUP-4。関連: SUP-1・SUP-6・STACK-2・REPAIR-3・REPAIR-4・REPAIR-5・SEC-1）。
//!
//! supervisor（コンテナごとの監視プロセス。CORE-1・D-19）が、`SupervisedState` 経由で core の `StateStore` へ
//! `health` を書く経路を提供する。`health` は stack の `depends_on`（healthy 条件。STACK-2・TASK-150）が読む。
//!
//! # 実装範囲の線引き（REPAIR-3）
//! - 提供するもの: 判定結果を書く [`record_health`]、判定処理の拡張点 [`HealthProbe`]、
//!   fail-closed のスタブ [`UnimplementedHealthProbe`]、1 回分の判定と記録をつなぐ [`probe_and_record`]。
//! - **未実装**: healthcheck コマンドの実行、周期実行、`monitor` ループからの呼び出し。
//!   将来は TASK-161（SUP-4）が exec と共通のコードパス（TASK-163・SUP-6）で [`HealthProbe`] を実装し、
//!   監視ループの生存確認の周回（`crate::run::monitor` の手順 3）から周期的に [`probe_and_record`] を呼ぶ。
//!   その際、healthcheck 引数の検証・シェル連結の禁止・コマンド出力のログ出力の扱いも TASK-161 で決める。
//! - スタブは `Healthy` を返さない。未検査のコンテナを healthy と公開すると `depends_on` の待ち合わせを
//!   誤って通すため、常に `Unimplemented` を返す（fail-closed）。
//! - probe の失敗（`Err`・期限超過）は元のエラーを返す。ただし記録済みの `Healthy` が残ると `depends_on` の
//!   healthy 条件を誤って満たすため、最新レコードを読み直して `Healthy` のときだけ `Unhealthy` へ落とす
//!   （古い成功を保持しない。revision 競合時は読み直して再判定する）。降格の成否は [`ProbeFailure::demotion`] で
//!   呼び出し側が識別できる（降格に失敗した場合は `Healthy` が残り得る。SUP-4）。
//!   未設定・`Starting`・`Unhealthy` の状態は書かない（未実装スタブが状態を書き換えない）。
//! - probe は別スレッドで実行し、`timeout` で待ちを打ち切る（REPAIR-5）。超過時は [`HealthProbe::cancel`] を
//!   別スレッドで呼び（これも `timeout` で打ち切る）、実装側に子プロセスの kill・回収を促し、結果は破棄する。
//!   打ち切り後に戻っていない probe / cancel スレッドは [`ProbeRunner`] が数え、残っている間は新しい判定を
//!   `Unavailable` で拒否する（スレッド・子プロセスの累積を防ぐ。同時に走る判定は最大 1 本）。
//! - 所有権の確認・判定・記録・失敗時の降格は、[`ProbeRunner`] ごとの 1 つの排他区間で行う（SUP-4・REPAIR-5）。
//!   区間の取得は待たない（取れなければ即 `Unavailable`）。先行する呼び出しが記録を終える前に次の判定を
//!   始めさせないので、古い判定の記録・降格が新しい判定の結果を後から上書きしない。拒否された呼び出しは
//!   probe も状態の書き込みもしない（状態の遷移は区間を持つ呼び出しだけが行う）。
//!   区間内の待ちはすべて有限（probe・cancel・回収は `timeout`、書き込みは [`MAX_WRITE_ATTEMPTS`] 回と
//!   core のロック待ち上限）で、ロックを持ったまま無期限に待つ経路はない。
//!   [`record_health`] を直接呼ぶ経路はこの排他の外にある。同じコンテナの `health` を書く呼び出し元は、
//!   1 つの [`ProbeRunner`]（clone は排他を共有する）を通して [`probe_and_record`] を使うこと。
//! - `Unhealthy` 等の記録に失敗した場合も、既存の `Healthy` を降格する（失敗は [`ProbeFailure::demotion`] で識別できる）。
//! - テスト用フェイクは `run.rs` と別に持つ。共有化は #242（TASK-157.8）で検討する。
//!
//! # 契約
//! 書けるのは「状態が `Running` で pid が起動ハンドルの pid と一致」かつ「記録上の `supervisor_pid` が自プロセス」
//! のときだけ（[`probe_and_record`] は probe の実行前にも同じ検証を行い、満たさなければ probe しない。SUP-1）。違えば `FailedPrecondition`（他 supervisor の記録を上書きしない。SUP-1）。pid は起動ハンドルから
//! 取り、状態に記録された pid を宛先に使わない（SEC-1）。revision 競合は `crate::run::MAX_WRITE_ATTEMPTS` 回までの
//! 有限リトライで、再試行のたびに `restart_count` 等を読み直す（並行する restart の更新を消さない。REPAIR-5）。

use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use fandhe_container_core::oci_runtime::LaunchedProcess;
use fandhe_container_core::traits::{
    ErrorCode, HealthStatus, StateRecord, SupervisionState, TraitError,
};

use crate::run::{
    MAX_POLL_INTERVAL, MAX_WRITE_ATTEMPTS, MonitorObserver, MonitorOperation, ensure_owner,
    is_running_with_pid, observed, precondition, write_with_retry,
};
use crate::state::SupervisedState;

/// 判定結果を `health` として状態へ書き、書き込み後のレコードを返す（`status`・`supervisor_pid`・`restart_count` は保つ）。
///
/// 将来の healthcheck 周期処理（TASK-161・SUP-4）から呼ばれる。可観測性は
/// [`MonitorOperation::RecordHealth`] で通知する（REPAIR-4）。
///
/// 本関数は呼び出し間の順序を保証しない（[`ProbeRunner`] の排他の外）。判定結果を書く経路は
/// [`probe_and_record`] を使い、判定から記録までを 1 つの排他区間に収める。
pub fn record_health(
    state: &mut SupervisedState,
    process: &dyn LaunchedProcess,
    health: HealthStatus,
    obs: &dyn MonitorObserver,
) -> Result<StateRecord, TraitError> {
    let pid = process.pid();
    let self_pid = NonZeroU32::new(std::process::id())
        .ok_or_else(|| TraitError::new(ErrorCode::Internal, "own pid is zero"))?;
    observed(obs, MonitorOperation::RecordHealth, || {
        if !is_running_with_pid(state.record(), pid) {
            return Err(precondition(
                "container is not running with the launched pid",
            ));
        }
        write_with_retry(state, pid, |rec| {
            ensure_owner(rec, self_pid)?;
            Ok((
                rec.status().clone(),
                SupervisionState::new(
                    rec.supervision().supervisor_pid(),
                    Some(health),
                    rec.restart_count(),
                ),
            ))
        })
    })
}

/// healthcheck 判定の拡張点（将来 TASK-161・SUP-4 が exec 共通関数〔SUP-6〕で実装する）。
///
/// [`probe_and_record`] が別スレッドで呼ぶため `Send + Sync` を要求する。
pub trait HealthProbe: Send + Sync {
    /// 判定を 1 回行う。
    ///
    /// 実装は `timeout` 内に戻ること（子プロセスの待機はタイムアウト付きで行い、超過時は kill して回収する。
    /// REPAIR-5）。ただし実装が守らなくても、呼び出し側は `timeout` で待ちを打ち切る（[`probe_and_record`]）。
    fn probe(&self, timeout: Duration) -> Result<HealthStatus, TraitError>;

    /// 期限超過で呼び出し側が待ちを打ち切ったときに呼ばれる。実装は実行中の子プロセスを kill して回収する
    /// （孤児・ゾンビを残さない。REPAIR-5）。既定は何もしない（子プロセスを持たない実装向け）。
    fn cancel(&self) {}
}

/// コマンド実行が未実装であることを示すスタブ。常に `Unimplemented` を返す（`Healthy` を装わない。REPAIR-3）。
///
/// 本実装は TASK-161（SUP-4）。
#[derive(Debug, Clone, Copy, Default)]
pub struct UnimplementedHealthProbe;

impl HealthProbe for UnimplementedHealthProbe {
    fn probe(&self, _timeout: Duration) -> Result<HealthStatus, TraitError> {
        Err(TraitError::new(
            ErrorCode::Unimplemented,
            "healthcheck command execution is not implemented",
        ))
    }
}

/// 降格（`Healthy` → `Unhealthy`）の結果（SUP-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Demotion {
    /// 降格は不要だった（最新レコードの `health` が `Healthy` でない、または probe 前の失敗・
    /// 別の呼び出しが判定〜記録の途中で拒否された）。
    NotNeeded,
    /// `Unhealthy` を書いた。
    Applied,
    /// 降格を試みたが書けなかった。`state.json` に `Healthy` が残り得るため呼び出し側が対処する。
    Failed(TraitError),
}

/// [`probe_and_record`] の失敗。判定側のエラーと降格の結果を両方返す（降格失敗を握りつぶさない。SUP-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeFailure {
    error: TraitError,
    demotion: Demotion,
}

impl ProbeFailure {
    fn new(error: TraitError, demotion: Demotion) -> Self {
        Self { error, demotion }
    }

    /// 失敗の原因（判定側のエラー・事前検証の失敗・記録の失敗）。
    pub fn error(&self) -> &TraitError {
        &self.error
    }

    /// 降格の結果。
    pub fn demotion(&self) -> &Demotion {
        &self.demotion
    }
}

/// 状態が `Running`・起動 pid 一致・自 supervisor 所有であることを最新レコードで確認する（SUP-1）。
fn verify_owned(
    state: &mut SupervisedState,
    pid: NonZeroU32,
    self_pid: NonZeroU32,
) -> Result<(), TraitError> {
    state.refresh()?;
    let rec = state.record();
    if !is_running_with_pid(rec, pid) {
        return Err(precondition(
            "container is not running with the launched pid",
        ));
    }
    ensure_owner(rec, self_pid)
}

/// 未終了（打ち切り後に残った probe / cancel）のスレッドを数える。生存中は新しい判定を始めさせない。
///
/// 判定ごとのスレッド・子プロセスが周期実行のたびに累積するのを防ぐ（REPAIR-5・リソース上限）。
/// 状態は [`ProbeRunner`] ごとに持ち、グローバル状態は使わない。
#[derive(Debug, Default)]
struct InFlight(AtomicUsize);

/// スレッドの生存期間だけ [`InFlight`] を保持する RAII ガード（panic でも解放される）。
struct InFlightGuard(Arc<InFlight>);

impl InFlightGuard {
    fn acquire(counter: &Arc<InFlight>) -> Self {
        counter.0.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(counter))
    }

    /// 未終了が 0 本のときに限り原子的に 1 本目を確保する（確認と取得を `compare_exchange` で不可分にする）。
    ///
    /// 同じ [`ProbeRunner`] への並行呼び出しでも、確保に成功するのは 1 呼び出しだけ（REPAIR-5）。
    fn try_acquire_exclusive(counter: &Arc<InFlight>) -> Option<Self> {
        counter
            .0
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .ok()?;
        Some(Self(Arc::clone(counter)))
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// [`HealthProbe`] と未終了スレッドの計数をまとめた実行単位（1 コンテナの 1 healthcheck につき 1 つ持つ）。
///
/// 期限超過で打ち切った probe スレッドが戻っていない間は、新しい判定を開始せず `Unavailable` を返す
/// （同時に走る判定は最大 1 本。REPAIR-5）。
///
/// [`probe_and_record`] は判定から記録・降格までを本型の排他区間（`busy`）の中で行う。区間は待たずに取得し、
/// 使用中なら `Unavailable` を返す（SUP-4・REPAIR-5）。`clone` は計数と排他区間を共有する。
#[derive(Clone)]
pub struct ProbeRunner {
    probe: Arc<dyn HealthProbe>,
    in_flight: Arc<InFlight>,
    /// [`probe_and_record`] の 1 呼び出しが判定〜記録の区間を保持している間 `true`。
    busy: Arc<AtomicBool>,
}

/// [`ProbeRunner`] の排他区間を保持する RAII ガード（判定・記録・降格の間ずっと保持する。panic でも解放される）。
///
/// 取得は [`ProbeRunner::try_begin`] の `compare_exchange` だけで、待たない（REPAIR-5）。
struct ProbeSession<'a> {
    runner: &'a ProbeRunner,
}

impl Drop for ProbeSession<'_> {
    fn drop(&mut self) {
        self.runner.busy.store(false, Ordering::SeqCst);
    }
}

impl ProbeRunner {
    /// `probe` を包む。
    pub fn new(probe: Arc<dyn HealthProbe>) -> Self {
        Self {
            probe,
            in_flight: Arc::new(InFlight::default()),
            busy: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 排他区間を待たずに取得する。別の呼び出しが保持中なら `None`（確認と取得は不可分。REPAIR-5）。
    fn try_begin(&self) -> Option<ProbeSession<'_>> {
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()?;
        Some(ProbeSession { runner: self })
    }

    /// 打ち切り後もまだ終了していない probe / cancel スレッドの数（診断用）。
    pub fn unfinished(&self) -> usize {
        self.in_flight.0.load(Ordering::SeqCst)
    }

    /// `cancel` を別スレッドで呼び、`timeout` までしか待たない。戻らない cancel も未終了として計数する。
    fn cancel_bounded(&self, timeout: Duration) {
        let (tx, rx) = mpsc::channel();
        let worker = Arc::clone(&self.probe);
        let guard = InFlightGuard::acquire(&self.in_flight);
        let spawned = std::thread::Builder::new()
            .name("healthcheck-cancel".to_owned())
            .spawn(move || {
                // probe スレッドと同じく、計数を戻してから完了を知らせる（panic 時も解放が先）。
                let tx = tx;
                let guard = guard;
                worker.cancel();
                drop(guard);
                let _ = tx.send(());
            });
        if spawned.is_ok() {
            // 期限内に戻らなくても待たない（Timeout / Disconnected はどちらも打ち切り）。
            let _ = rx.recv_timeout(timeout);
        }
    }
}

impl ProbeSession<'_> {
    /// `probe` を別スレッドで実行し、`timeout` で待ちを打ち切る（REPAIR-5）。
    ///
    /// 超過時は [`HealthProbe::cancel`] を別スレッドで呼び、これも `timeout` で待ちを打ち切る
    /// （cancel が戻らなくても呼び出し側は戻る）。cancel 後は probe スレッドの終了を `timeout` まで待って回収を
    /// 試みる。終了しなかったスレッドは [`ProbeRunner::unfinished`] に残り、戻るまで次の判定を拒否する。
    ///
    /// 排他区間（[`ProbeSession`]）の保持者だけが呼べる。戻った後も区間は呼び出し元が保持し続け、
    /// 記録・降格が終わるまで次の判定は始まらない（SUP-4）。
    fn run(&self, timeout: Duration) -> Result<HealthStatus, TraitError> {
        let runner = self.runner;
        let Some(guard) = InFlightGuard::try_acquire_exclusive(&runner.in_flight) else {
            return Err(TraitError::new(
                ErrorCode::Unavailable,
                "previous healthcheck probe has not terminated",
            ));
        };
        let (tx, rx) = mpsc::channel();
        let worker = Arc::clone(&runner.probe);
        std::thread::Builder::new()
            .name("healthcheck-probe".to_owned())
            .spawn(move || {
                // ローカル変数は宣言の逆順に破棄される。panic 時も計数の解放が送信側の切断より先になるよう、
                // `tx` を先に束縛する。
                let tx = tx;
                let guard = guard;
                let result = worker.probe(timeout);
                // 結果を渡す前に計数を戻す。受信した呼び出し側が戻った直後の次の判定を、終了処理中の
                // このスレッドが誤って `Unavailable` にしないため（次の判定は排他区間の解放後にしか始まらない）。
                drop(guard);
                // 受信側が打ち切り済みなら送信失敗になるが、結果は不要なので無視する。
                let _ = tx.send(result);
            })
            .map_err(|_| {
                TraitError::new(ErrorCode::Internal, "failed to spawn healthcheck probe")
            })?;
        match rx.recv_timeout(timeout) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => {
                runner.cancel_bounded(timeout);
                // 回収の確認: cancel の効果で probe が戻れば結果は破棄してスレッドを手放す。
                let _ = rx.recv_timeout(timeout);
                Err(TraitError::new(
                    ErrorCode::Timeout,
                    "healthcheck probe exceeded its timeout",
                ))
            }
            Err(RecvTimeoutError::Disconnected) => Err(TraitError::new(
                ErrorCode::Internal,
                "healthcheck probe terminated abnormally",
            )),
        }
    }
}

/// 最新レコードを読み直し、`Healthy` なら `Unhealthy` へ落とす。競合時は読み直して再判定する（上限
/// [`MAX_WRITE_ATTEMPTS`]。REPAIR-5）。書く前に所有権も再検証する（SUP-1）。
fn demote_if_healthy(
    state: &mut SupervisedState,
    pid: NonZeroU32,
    self_pid: NonZeroU32,
    obs: &dyn MonitorObserver,
) -> Demotion {
    let r = observed(obs, MonitorOperation::RecordHealth, || {
        let mut last_err = precondition("state write attempts exhausted");
        for _ in 0..MAX_WRITE_ATTEMPTS {
            verify_owned(state, pid, self_pid)?;
            let rec = state.record();
            if rec.health() != Some(HealthStatus::Healthy) {
                return Ok(false);
            }
            let supervision = SupervisionState::new(
                rec.supervision().supervisor_pid(),
                Some(HealthStatus::Unhealthy),
                rec.restart_count(),
            );
            let status = rec.status().clone();
            match state.write(status, supervision) {
                Ok(_) => return Ok(true),
                Err(e) if e.code() == ErrorCode::FailedPrecondition => last_err = e,
                Err(e) => return Err(e),
            }
        }
        Err(last_err)
    });
    match r {
        Ok(true) => Demotion::Applied,
        Ok(false) => Demotion::NotNeeded,
        Err(e) => Demotion::Failed(e),
    }
}

/// `probe` を 1 回実行し、結果を [`record_health`] で書く。
///
/// `timeout` が 0 または [`MAX_POLL_INTERVAL`] 超なら `InvalidArgument`。同じ [`ProbeRunner`] で別の呼び出しが
/// 判定〜記録の途中なら、probe も書き込みもせず `Unavailable`（降格は [`Demotion::NotNeeded`]。状態の遷移は
/// 先行する呼び出しが行う。待たずに戻る。SUP-4・REPAIR-5）。probe の前に最新レコードで `Running`・
/// 起動 pid・`supervisor_pid` の所有を確認し、満たさなければ probe せず `FailedPrecondition`（SUP-1）。
/// 判定は [`MonitorOperation::Probe`] として成否・レイテンシを通知する（REPAIR-4）。probe が `Err` を返すか
/// `timeout` を超えた（待ちを打ち切り `Timeout`）場合は、最新の `health` が `Healthy` のときに限り `Unhealthy`
/// へ落とし、判定側のエラーと降格の結果を [`ProbeFailure`] で返す。
pub fn probe_and_record(
    state: &mut SupervisedState,
    process: &dyn LaunchedProcess,
    probe: &ProbeRunner,
    timeout: Duration,
    obs: &dyn MonitorObserver,
) -> Result<StateRecord, ProbeFailure> {
    if timeout.is_zero() || timeout > MAX_POLL_INTERVAL {
        return Err(ProbeFailure::new(
            TraitError::new(ErrorCode::InvalidArgument, "probe timeout is out of range"),
            Demotion::NotNeeded,
        ));
    }
    let pid = process.pid();
    let self_pid = NonZeroU32::new(std::process::id()).ok_or_else(|| {
        ProbeFailure::new(
            TraitError::new(ErrorCode::Internal, "own pid is zero"),
            Demotion::NotNeeded,
        )
    })?;
    // 所有権の確認から記録・降格までを 1 つの排他区間に収める。`session` は関数の終わりまで保持する
    // （古い判定の記録・降格が、後から始まった判定の結果を上書きしないため。SUP-4）。
    let Some(session) = probe.try_begin() else {
        let busy = TraitError::new(ErrorCode::Unavailable, "another healthcheck is in progress");
        // 拒否も判定の失敗として観測できるようにする（REPAIR-4）。
        let _ = observed(obs, MonitorOperation::Probe, || {
            Err::<HealthStatus, _>(busy.clone())
        });
        return Err(ProbeFailure::new(busy, Demotion::NotNeeded));
    };
    verify_owned(state, pid, self_pid).map_err(|e| ProbeFailure::new(e, Demotion::NotNeeded))?;
    match observed(obs, MonitorOperation::Probe, || session.run(timeout)) {
        Ok(health) => match record_health(state, process, health, obs) {
            Ok(rec) => Ok(rec),
            // Unhealthy / Starting を書けないと既存の Healthy が残るため、降格を試みて結果を返す（SUP-4）。
            Err(e) if health != HealthStatus::Healthy => {
                let demotion = demote_if_healthy(state, pid, self_pid, obs);
                Err(ProbeFailure::new(e, demotion))
            }
            Err(e) => Err(ProbeFailure::new(e, Demotion::NotNeeded)),
        },
        Err(e) => {
            let demotion = demote_if_healthy(state, pid, self_pid, obs);
            Err(ProbeFailure::new(e, demotion))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use fandhe_container_core::oci_runtime::ProcessExit;
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
        GetStateRequest, ListStateRequest, StateList, StateRevision, StateStore,
        UpdateStateRequest,
    };

    use crate::run::{MAX_WRITE_ATTEMPTS, MonitorEvent};

    fn cid() -> ContainerId {
        ContainerId::new("c1").unwrap()
    }

    fn pid(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    fn me() -> NonZeroU32 {
        pid(std::process::id())
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

    /// 自 pid が監視所有者で restart_count = 3、health 未設定の Running（pid 42）。
    fn owned_store(conflicts: u32) -> Arc<FakeStore> {
        store_with(
            ContainerStatus::running(cid(), Some(pid(42))),
            SupervisionState::new(Some(me()), None, 3),
            conflicts,
        )
    }

    struct FakeProc;

    impl LaunchedProcess for FakeProc {
        fn pid(&self) -> NonZeroU32 {
            pid(42)
        }
        fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(None)
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecObs(Mutex<Vec<MonitorEvent>>);

    impl MonitorObserver for RecObs {
        fn observe(&self, e: &MonitorEvent) {
            self.0.lock().unwrap().push(e.clone());
        }
    }

    struct FixedProbe(HealthStatus);

    impl HealthProbe for FixedProbe {
        fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
            Ok(self.0)
        }
    }

    fn attach(store: &Arc<FakeStore>) -> SupervisedState {
        SupervisedState::attach(store.clone(), cid()).unwrap()
    }

    fn rec_health(s: &mut SupervisedState, h: HealthStatus) -> Result<StateRecord, TraitError> {
        record_health(s, &FakeProc, h, &RecObs::default())
    }

    /// SUP-4・TASK-157.6: health だけが変わり、他の項目は保たれる。
    #[test]
    fn sup4_task157_6_record_health_writes_only_health() {
        let store = owned_store(0);
        let mut s = attach(&store);
        let rec = rec_health(&mut s, HealthStatus::Healthy).unwrap();
        assert_eq!(rec.health(), Some(HealthStatus::Healthy));
        assert_eq!(rec.revision().value(), 2);
        assert_eq!(rec.supervisor_pid(), Some(me()));
        assert_eq!(rec.restart_count(), 3);
        assert_eq!(rec.status().pid(), Some(pid(42)));
    }

    /// SUP-4・TASK-157.6: 判定が変わるたびに値が追従する。
    #[test]
    fn sup4_task157_6_health_transitions() {
        let store = owned_store(0);
        let mut s = attach(&store);
        for h in [
            HealthStatus::Starting,
            HealthStatus::Healthy,
            HealthStatus::Unhealthy,
        ] {
            let rec = rec_health(&mut s, h).unwrap();
            assert_eq!(rec.health(), Some(h));
        }
        assert_eq!(s.record().revision().value(), 4);
    }

    /// SUP-1・TASK-157.6: 所有者でなければ書かない。
    #[test]
    fn sup1_task157_6_requires_ownership() {
        let other = pid(std::process::id().wrapping_add(1).max(1));
        for owner in [None, Some(other)] {
            let store = store_with(
                ContainerStatus::running(cid(), Some(pid(42))),
                SupervisionState::new(owner, None, 0),
                0,
            );
            let mut s = attach(&store);
            let e = rec_health(&mut s, HealthStatus::Healthy).unwrap_err();
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(store.updates.load(Ordering::SeqCst), 0);
            assert_eq!(s.record().health(), None);
        }
    }

    /// SUP-1・TASK-157.6: Stopped や pid 不一致では書かない。
    #[test]
    fn sup1_task157_6_requires_running_with_launched_pid() {
        let sup = SupervisionState::new(Some(me()), None, 0);
        for status in [
            ContainerStatus::stopped(cid(), Some(0)),
            ContainerStatus::running(cid(), Some(pid(43))),
        ] {
            let store = store_with(status, sup, 0);
            let mut s = attach(&store);
            let e = rec_health(&mut s, HealthStatus::Healthy).unwrap_err();
            assert_eq!(e.code(), ErrorCode::FailedPrecondition);
            assert_eq!(store.updates.load(Ordering::SeqCst), 0);
        }
    }

    /// REPAIR-5・TASK-157.6: 競合 1 回は再試行で成功し、競合側の restart_count を消さない。
    #[test]
    fn sup4_task157_6_retries_and_keeps_concurrent_restart_count() {
        let store = owned_store(1);
        let mut s = attach(&store);
        let rec = rec_health(&mut s, HealthStatus::Healthy).unwrap();
        assert_eq!(rec.health(), Some(HealthStatus::Healthy));
        assert_eq!(rec.restart_count(), 4);
        assert_eq!(store.updates.load(Ordering::SeqCst), 2);
    }

    /// REPAIR-5・TASK-157.6: 競合が続けば上限で打ち切る。
    #[test]
    fn sup4_task157_6_gives_up_after_max_attempts() {
        let store = owned_store(MAX_WRITE_ATTEMPTS);
        let mut s = attach(&store);
        let e = rec_health(&mut s, HealthStatus::Healthy).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(store.updates.load(Ordering::SeqCst), MAX_WRITE_ATTEMPTS);
    }

    /// REPAIR-3・TASK-157.6: スタブは Unimplemented で、状態を変えない。
    #[test]
    fn sup4_task157_6_stub_is_unimplemented_and_writes_nothing() {
        let t = Duration::from_secs(1);
        assert_eq!(
            UnimplementedHealthProbe.probe(t).unwrap_err().code(),
            ErrorCode::Unimplemented
        );
        let store = owned_store(0);
        let mut s = attach(&store);
        let e = probe_and_record(
            &mut s,
            &FakeProc,
            &ProbeRunner::new(Arc::new(UnimplementedHealthProbe)),
            t,
            &RecObs::default(),
        )
        .unwrap_err();
        assert_eq!(e.error().code(), ErrorCode::Unimplemented);
        assert_eq!(e.demotion(), &Demotion::NotNeeded);
        assert_eq!(s.record().revision().value(), 1);
        assert_eq!(s.record().health(), None);
        assert_eq!(store.updates.load(Ordering::SeqCst), 0);
    }

    /// TASK-157.6: probe 結果が反映され、timeout の範囲外は拒否する。
    #[test]
    fn sup4_task157_6_probe_and_record_applies_result_and_validates_timeout() {
        let store = owned_store(0);
        let mut s = attach(&store);
        let probe = ProbeRunner::new(Arc::new(FixedProbe(HealthStatus::Unhealthy)));
        let obs = RecObs::default();
        let rec =
            probe_and_record(&mut s, &FakeProc, &probe, Duration::from_secs(1), &obs).unwrap();
        assert_eq!(rec.health(), Some(HealthStatus::Unhealthy));
        for t in [Duration::ZERO, MAX_POLL_INTERVAL + Duration::from_millis(1)] {
            let e = probe_and_record(&mut s, &FakeProc, &probe, t, &obs).unwrap_err();
            assert_eq!(e.error().code(), ErrorCode::InvalidArgument);
        }
    }

    /// REPAIR-4・TASK-157.6: 成功・失敗が RecordHealth として 1 件ずつ通知される。
    #[test]
    fn sup4_task157_6_observer_receives_record_health() {
        let obs = RecObs::default();
        let store = owned_store(0);
        let mut s = attach(&store);
        record_health(&mut s, &FakeProc, HealthStatus::Healthy, &obs).unwrap();
        let bad = store_with(
            ContainerStatus::stopped(cid(), None),
            SupervisionState::default(),
            0,
        );
        let mut s2 = attach(&bad);
        record_health(&mut s2, &FakeProc, HealthStatus::Healthy, &obs).unwrap_err();
        let ev = obs.0.lock().unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].operation, MonitorOperation::RecordHealth);
        assert_eq!(ev[0].operation.as_str(), "record_health");
        assert_eq!(ev[0].error_code, None);
        assert_eq!(ev[1].error_code, Some(ErrorCode::FailedPrecondition));
    }

    struct FailingProbe;

    impl HealthProbe for FailingProbe {
        fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "boom"))
        }
    }

    /// `cancel` が呼ばれるまで戻らず、戻るときは Healthy を返す probe。
    ///
    /// 壁時計の sleep に依存すると、負荷の高い runner で呼び出し側の待ち開始が遅れ、期限内に結果が
    /// 届いてしまう。cancel（= 期限超過の確定）を待つことで判定を決定的にする（REPAIR-5）。
    struct SlowProbe(Arc<std::sync::atomic::AtomicBool>);

    impl SlowProbe {
        fn new() -> Self {
            Self(Arc::new(std::sync::atomic::AtomicBool::new(false)))
        }
    }

    impl HealthProbe for SlowProbe {
        fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
            // 安全弁: cancel が来なくてもテストがハングしないよう上限を設ける。
            let limit = std::time::Instant::now() + Duration::from_secs(10);
            while !self.0.load(Ordering::SeqCst) && std::time::Instant::now() < limit {
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(HealthStatus::Healthy)
        }
        fn cancel(&self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn healthy_store() -> Arc<FakeStore> {
        store_with(
            ContainerStatus::running(cid(), Some(pid(42))),
            SupervisionState::new(Some(me()), Some(HealthStatus::Healthy), 0),
            0,
        )
    }

    /// REPAIR-4・SUP-4: probe 失敗は Probe イベントで通知され、古い Healthy は Unhealthy へ落ちる。
    #[test]
    fn sup4_task157_6_probe_error_downgrades_stale_healthy_and_is_observed() {
        let store = healthy_store();
        let mut s = attach(&store);
        let obs = RecObs::default();
        let t = Duration::from_secs(1);
        let p = ProbeRunner::new(Arc::new(FailingProbe));
        let e = probe_and_record(&mut s, &FakeProc, &p, t, &obs).unwrap_err();
        assert_eq!(e.error().code(), ErrorCode::Internal);
        assert_eq!(e.demotion(), &Demotion::Applied);
        assert_eq!(s.record().health(), Some(HealthStatus::Unhealthy));
        let ev = obs.0.lock().unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].operation, MonitorOperation::Probe);
        assert_eq!(ev[0].error_code, Some(ErrorCode::Internal));
        assert_eq!(ev[1].operation, MonitorOperation::RecordHealth);
        assert_eq!(ev[1].error_code, None);
    }

    /// REPAIR-5: 期限超過の結果は破棄され、Timeout として失敗扱い（Healthy を残さない）。
    #[test]
    fn repair5_task157_6_overrun_probe_result_is_discarded() {
        let store = healthy_store();
        let mut s = attach(&store);
        let obs = RecObs::default();
        let e = probe_and_record(
            &mut s,
            &FakeProc,
            &ProbeRunner::new(Arc::new(SlowProbe::new())),
            Duration::from_millis(10),
            &obs,
        )
        .unwrap_err();
        assert_eq!(e.error().code(), ErrorCode::Timeout);
        assert_eq!(e.demotion(), &Demotion::Applied);
        assert_eq!(s.record().health(), Some(HealthStatus::Unhealthy));
        assert_eq!(
            obs.0.lock().unwrap()[0].error_code,
            Some(ErrorCode::Timeout)
        );
    }

    /// 成功時は Probe と RecordHealth が各 1 件通知される。
    #[test]
    fn sup4_task157_6_probe_success_is_observed() {
        let store = owned_store(0);
        let mut s = attach(&store);
        let obs = RecObs::default();
        probe_and_record(
            &mut s,
            &FakeProc,
            &ProbeRunner::new(Arc::new(FixedProbe(HealthStatus::Healthy))),
            Duration::from_secs(1),
            &obs,
        )
        .unwrap();
        let ev = obs.0.lock().unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].operation.as_str(), "probe");
        assert_eq!(ev[0].error_code, None);
    }

    /// 止まったまま戻らない probe。`cancel` が呼ばれたかを記録する。
    struct HangingProbe(Arc<AtomicU32>);

    impl HealthProbe for HangingProbe {
        fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
            std::thread::sleep(Duration::from_secs(2));
            Ok(HealthStatus::Healthy)
        }
        fn cancel(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// REPAIR-5: 応答しない probe でも呼び出しは timeout 付近で戻り、cancel が呼ばれる。
    #[test]
    fn repair5_task157_6_hanging_probe_is_cut_off_and_cancelled() {
        let store = healthy_store();
        let mut s = attach(&store);
        let cancels = Arc::new(AtomicU32::new(0));
        let p = ProbeRunner::new(Arc::new(HangingProbe(cancels.clone())));
        let started = std::time::Instant::now();
        let e = probe_and_record(
            &mut s,
            &FakeProc,
            &p,
            Duration::from_millis(50),
            &RecObs::default(),
        )
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_millis(1500));
        assert_eq!(e.error().code(), ErrorCode::Timeout);
        assert_eq!(cancels.load(Ordering::SeqCst), 1);
        assert_eq!(s.record().health(), Some(HealthStatus::Unhealthy));
    }

    /// SUP-1: 所有権がなければ probe を実行しない。
    #[test]
    fn sup1_task157_6_probe_not_run_without_ownership() {
        struct CountingProbe(Arc<AtomicU32>);
        impl HealthProbe for CountingProbe {
            fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(HealthStatus::Healthy)
            }
        }
        let other = pid(std::process::id().wrapping_add(1).max(1));
        let runs = Arc::new(AtomicU32::new(0));
        let p = ProbeRunner::new(Arc::new(CountingProbe(runs.clone())));
        for status in [
            ContainerStatus::running(cid(), Some(pid(42))),
            ContainerStatus::running(cid(), Some(pid(43))),
            ContainerStatus::stopped(cid(), Some(0)),
        ] {
            let owner = if status.pid() == Some(pid(42)) {
                Some(other)
            } else {
                Some(me())
            };
            let store = store_with(
                status,
                SupervisionState::new(owner, Some(HealthStatus::Healthy), 0),
                0,
            );
            let mut s = attach(&store);
            let e = probe_and_record(
                &mut s,
                &FakeProc,
                &p,
                Duration::from_secs(1),
                &RecObs::default(),
            )
            .unwrap_err();
            assert_eq!(e.error().code(), ErrorCode::FailedPrecondition);
            assert_eq!(store.updates.load(Ordering::SeqCst), 0);
        }
        assert_eq!(runs.load(Ordering::SeqCst), 0);
    }

    /// 書き込みが常に失敗するストア（get は成功）。
    struct FailingWriteStore(FakeStore);

    impl StateStore for FailingWriteStore {
        fn create(&self, r: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            self.0.create(r)
        }
        fn update(&self, _: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "disk full"))
        }
        fn get(&self, r: &GetStateRequest) -> Result<StateRecord, TraitError> {
            self.0.get(r)
        }
        fn list(&self, r: &ListStateRequest) -> Result<StateList, TraitError> {
            self.0.list(r)
        }
        fn delete(&self, r: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            self.0.delete(r)
        }
    }

    /// SUP-4: 降格の書き込みに失敗したら Demotion::Failed で呼び出し側へ伝える。
    #[test]
    fn sup4_task157_6_demotion_failure_is_reported() {
        let inner = healthy_store();
        let rec = inner.rec.lock().unwrap().clone();
        let store = Arc::new(FailingWriteStore(FakeStore {
            rec: Mutex::new(rec),
            conflicts: Mutex::new(0),
            updates: AtomicU32::new(0),
        }));
        let mut s = SupervisedState::attach(store, cid()).unwrap();
        let p = ProbeRunner::new(Arc::new(FailingProbe));
        let e = probe_and_record(
            &mut s,
            &FakeProc,
            &p,
            Duration::from_secs(1),
            &RecObs::default(),
        )
        .unwrap_err();
        assert_eq!(e.error().code(), ErrorCode::Internal);
        match e.demotion() {
            Demotion::Failed(d) => assert_eq!(d.code(), ErrorCode::Internal),
            other => panic!("unexpected demotion: {other:?}"),
        }
    }

    /// SUP-4: 古いキャッシュが Healthy でも最新が Unhealthy なら降格書き込みをしない（読み直して再判定）。
    #[test]
    fn sup4_task157_6_demotion_rereads_latest_record() {
        let store = healthy_store();
        let mut s = attach(&store);
        {
            let mut g = store.rec.lock().unwrap();
            let sup = SupervisionState::new(Some(me()), Some(HealthStatus::Unhealthy), 0);
            *g = next_record(&g, g.status().clone(), sup);
        }
        let p = ProbeRunner::new(Arc::new(FailingProbe));
        let e = probe_and_record(
            &mut s,
            &FakeProc,
            &p,
            Duration::from_secs(1),
            &RecObs::default(),
        )
        .unwrap_err();
        assert_eq!(e.demotion(), &Demotion::NotNeeded);
        assert_eq!(store.updates.load(Ordering::SeqCst), 0);
    }

    /// SUP-4・REPAIR-5: 降格の revision 競合は読み直して再試行し、成功すれば Applied。
    #[test]
    fn sup4_task157_6_demotion_retries_on_conflict() {
        let store = store_with(
            ContainerStatus::running(cid(), Some(pid(42))),
            SupervisionState::new(Some(me()), Some(HealthStatus::Healthy), 0),
            1,
        );
        let mut s = attach(&store);
        let p = ProbeRunner::new(Arc::new(FailingProbe));
        let e = probe_and_record(
            &mut s,
            &FakeProc,
            &p,
            Duration::from_secs(1),
            &RecObs::default(),
        )
        .unwrap_err();
        assert_eq!(e.demotion(), &Demotion::Applied);
        assert_eq!(s.record().health(), Some(HealthStatus::Unhealthy));
        assert_eq!(s.record().restart_count(), 1);
    }

    /// cancel が戻らない probe。
    struct StuckCancelProbe;

    impl HealthProbe for StuckCancelProbe {
        fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
            std::thread::sleep(Duration::from_millis(600));
            Ok(HealthStatus::Healthy)
        }
        fn cancel(&self) {
            std::thread::sleep(Duration::from_millis(600));
        }
    }

    /// REPAIR-5: cancel が戻らなくても呼び出しは期限内に戻り、未終了のスレッドが次の判定を拒否する。
    /// REPAIR-5: 同じ ProbeRunner への並行 run でも、確保に成功するのは 1 呼び出しだけ。
    #[test]
    fn repair5_task157_6_concurrent_acquire_admits_exactly_one() {
        let counter = Arc::new(InFlight::default());
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let c = Arc::clone(&counter);
                let b = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    b.wait();
                    let g = InFlightGuard::try_acquire_exclusive(&c);
                    // 全スレッドの競合が終わるまでガードを保持する。
                    std::thread::sleep(Duration::from_millis(100));
                    g.is_some()
                })
            })
            .collect();
        let admitted = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(admitted, 1);
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn repair5_task157_6_stuck_cancel_is_bounded_and_blocks_next_probe() {
        let store = healthy_store();
        let mut s = attach(&store);
        let runner = ProbeRunner::new(Arc::new(StuckCancelProbe));
        let started = std::time::Instant::now();
        let e = probe_and_record(
            &mut s,
            &FakeProc,
            &runner,
            Duration::from_millis(50),
            &RecObs::default(),
        )
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_millis(400));
        assert_eq!(e.error().code(), ErrorCode::Timeout);
        assert_eq!(e.demotion(), &Demotion::Applied);
        assert_eq!(runner.unfinished(), 2);
        let e2 = probe_and_record(
            &mut s,
            &FakeProc,
            &runner,
            Duration::from_millis(50),
            &RecObs::default(),
        )
        .unwrap_err();
        assert_eq!(e2.error().code(), ErrorCode::Unavailable);
        // スレッドが戻れば再び判定できる。
        std::thread::sleep(Duration::from_millis(1500));
        assert_eq!(runner.unfinished(), 0);
    }

    /// 書き込みは常に失敗するが、get は Healthy を返し続けるストア（Unhealthy を記録できない状況）。
    /// SUP-4: Unhealthy の記録に失敗したら降格を試み、失敗を Demotion::Failed で伝える。
    #[test]
    fn sup4_task157_6_unhealthy_record_failure_is_reported_as_demotion_failure() {
        let inner = healthy_store();
        let rec = inner.rec.lock().unwrap().clone();
        let store = Arc::new(FailingWriteStore(FakeStore {
            rec: Mutex::new(rec),
            conflicts: Mutex::new(0),
            updates: AtomicU32::new(0),
        }));
        let mut s = SupervisedState::attach(store, cid()).unwrap();
        let p = ProbeRunner::new(Arc::new(FixedProbe(HealthStatus::Unhealthy)));
        let e = probe_and_record(
            &mut s,
            &FakeProc,
            &p,
            Duration::from_secs(1),
            &RecObs::default(),
        )
        .unwrap_err();
        assert_eq!(e.error().code(), ErrorCode::Internal);
        match e.demotion() {
            Demotion::Failed(d) => assert_eq!(d.code(), ErrorCode::Internal),
            other => panic!("unexpected demotion: {other:?}"),
        }
    }
}
