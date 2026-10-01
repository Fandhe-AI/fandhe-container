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
//!   healthy 条件を誤って満たすため、現在値が `Healthy` のときだけ `Unhealthy` へ落とす（古い成功を保持しない）。
//!   未設定・`Starting`・`Unhealthy` の状態は書かない（未実装スタブが状態を書き換えない）。
//! - テスト用フェイクは `run.rs` と別に持つ。共有化は #242（TASK-157.8）で検討する。
//!
//! # 契約
//! 書けるのは「状態が `Running` で pid が起動ハンドルの pid と一致」かつ「記録上の `supervisor_pid` が自プロセス」
//! のときだけ。違えば `FailedPrecondition`（他 supervisor の記録を上書きしない。SUP-1）。pid は起動ハンドルから
//! 取り、状態に記録された pid を宛先に使わない（SEC-1）。revision 競合は `crate::run::MAX_WRITE_ATTEMPTS` 回までの
//! 有限リトライで、再試行のたびに `restart_count` 等を読み直す（並行する restart の更新を消さない。REPAIR-5）。

use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::LaunchedProcess;
use fandhe_container_core::traits::{
    ErrorCode, HealthStatus, StateRecord, SupervisionState, TraitError,
};

use crate::run::{
    MAX_POLL_INTERVAL, MonitorObserver, MonitorOperation, ensure_owner, is_running_with_pid,
    observed, precondition, write_with_retry,
};
use crate::state::SupervisedState;

/// 判定結果を `health` として状態へ書き、書き込み後のレコードを返す（`status`・`supervisor_pid`・`restart_count` は保つ）。
///
/// 将来の healthcheck 周期処理（TASK-161・SUP-4）から呼ばれる。可観測性は
/// [`MonitorOperation::RecordHealth`] で通知する（REPAIR-4）。
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
pub trait HealthProbe {
    /// 判定を 1 回行う。
    ///
    /// **実装は `timeout` 内に必ず戻ること**（子プロセスの待機はタイムアウト付きで行い、超過時は kill して回収する。
    /// REPAIR-5）。同期呼び出しのため呼び出し側は途中で打ち切れない。呼び出し側は戻りが `timeout` を超えた場合に
    /// その結果を破棄して失敗として扱う（[`probe_and_record`]）。
    fn probe(&self, timeout: Duration) -> Result<HealthStatus, TraitError>;
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

/// `probe` を 1 回実行し、結果を [`record_health`] で書く。
///
/// `timeout` が 0 または [`MAX_POLL_INTERVAL`] 超なら `InvalidArgument`。判定は [`MonitorOperation::Probe`] として
/// 成否・レイテンシを通知する（REPAIR-4）。probe が `Err` を返すか、戻りが `timeout` を超えた（`Timeout`
/// として結果を破棄）場合は、記録上の `health` が `Healthy` のときに限り `Unhealthy` へ落としたうえで
/// 判定側のエラーを返す。落とす書き込みの失敗は判定側のエラーを優先して握りつぶさない（両方を通知で観測できる）。
pub fn probe_and_record(
    state: &mut SupervisedState,
    process: &dyn LaunchedProcess,
    probe: &dyn HealthProbe,
    timeout: Duration,
    obs: &dyn MonitorObserver,
) -> Result<StateRecord, TraitError> {
    if timeout.is_zero() || timeout > MAX_POLL_INTERVAL {
        return Err(TraitError::new(
            ErrorCode::InvalidArgument,
            "probe timeout is out of range",
        ));
    }
    let probed = observed(obs, MonitorOperation::Probe, || {
        let started = Instant::now();
        let r = probe.probe(timeout);
        if started.elapsed() > timeout {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "healthcheck probe exceeded its timeout",
            ));
        }
        r
    });
    match probed {
        Ok(health) => record_health(state, process, health, obs),
        Err(e) => {
            if state.record().health() == Some(HealthStatus::Healthy) {
                // 書き込み失敗は判定側のエラーを優先する（失敗は RecordHealth として通知済み）。
                let _ = record_health(state, process, HealthStatus::Unhealthy, obs);
            }
            Err(e)
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
            &UnimplementedHealthProbe,
            t,
            &RecObs::default(),
        )
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert_eq!(s.record().revision().value(), 1);
        assert_eq!(s.record().health(), None);
        assert_eq!(store.updates.load(Ordering::SeqCst), 0);
    }

    /// TASK-157.6: probe 結果が反映され、timeout の範囲外は拒否する。
    #[test]
    fn sup4_task157_6_probe_and_record_applies_result_and_validates_timeout() {
        let store = owned_store(0);
        let mut s = attach(&store);
        let probe = FixedProbe(HealthStatus::Unhealthy);
        let obs = RecObs::default();
        let rec =
            probe_and_record(&mut s, &FakeProc, &probe, Duration::from_secs(1), &obs).unwrap();
        assert_eq!(rec.health(), Some(HealthStatus::Unhealthy));
        for t in [Duration::ZERO, MAX_POLL_INTERVAL + Duration::from_millis(1)] {
            let e = probe_and_record(&mut s, &FakeProc, &probe, t, &obs).unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument);
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

    struct SlowProbe;

    impl HealthProbe for SlowProbe {
        fn probe(&self, t: Duration) -> Result<HealthStatus, TraitError> {
            std::thread::sleep(t + Duration::from_millis(20));
            Ok(HealthStatus::Healthy)
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
        let e = probe_and_record(&mut s, &FakeProc, &FailingProbe, t, &obs).unwrap_err();
        assert_eq!(e.code(), ErrorCode::Internal);
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
            &SlowProbe,
            Duration::from_millis(10),
            &obs,
        )
        .unwrap_err();
        assert_eq!(e.code(), ErrorCode::Timeout);
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
            &FixedProbe(HealthStatus::Healthy),
            Duration::from_secs(1),
            &obs,
        )
        .unwrap();
        let ev = obs.0.lock().unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].operation.as_str(), "probe");
        assert_eq!(ev[0].error_code, None);
    }
}
