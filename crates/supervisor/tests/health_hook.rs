//! healthcheck フック土台の受け入れ照合テスト（TASK-157.6・#240・SUP-4・REPAIR-3・REPAIR-12）。
//!
//! 文字列照合であり構文解析ではない（tests/monitor_loop.rs と同じ手法）。

use std::time::Duration;

use fandhe_container_core::traits::ErrorCode;
use fandhe_container_supervisor::health::{
    HealthProbe, UnimplementedHealthProbe, probe_and_record, record_health,
};

/// AC1: 公開 API が外部 crate から参照でき、スタブは Unimplemented を返す。
#[test]
fn sup4_task157_6_public_api_and_stub() {
    let _record = record_health;
    let _both = probe_and_record;
    let err = UnimplementedHealthProbe
        .probe(Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unimplemented);
}

/// AC2: 未実装範囲と将来仕様の対応 ID が doc に書かれている。
#[test]
fn sup4_task157_6_doc_states_unimplemented_scope() {
    const SRC: &str = include_str!("../src/health.rs");
    let body = SRC.split("#[cfg(test)]").next().unwrap_or(SRC);
    for needle in ["SUP-4", "SUP-6", "TASK-161", "未実装"] {
        assert!(body.contains(needle), "health.rs must mention {needle}");
    }
}

/// コマンド実行・グローバル状態・unsafe・記録 pid への直接操作を持たない。
#[test]
fn sup4_task157_6_health_rs_has_no_exec_or_global_state() {
    const SRC: &str = include_str!("../src/health.rs");
    let body = SRC.split("#[cfg(test)]").next().unwrap_or(SRC);
    let code: String = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        "\nstatic ",
        "\npub static ",
        "thread_local",
        "OnceLock",
        "LazyLock",
        "unsafe",
        "kill(",
        "waitpid",
        "/proc",
        "cfg(target_os",
        "Command",
    ] {
        assert!(
            !code.contains(banned),
            "health.rs must not contain {banned}"
        );
    }
}
/// 公開 API だけで `record_health` / `probe_and_record` を駆動する結合試験（REPAIR-12・SUP-1・SUP-4）。
///
/// 外部 crate 側で実装したメモリ上の `StateStore` を使うため、3 OS・root 不要で既定のテスト集合で動く。
mod public_api {
    use std::num::NonZeroU32;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Duration;

    use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, DeleteStateRequest, DeleteStateResponse,
        ErrorCode, GetStateRequest, HealthStatus, ListStateRequest, StateList, StateRecord,
        StateRevision, StateStore, SupervisionState, TraitError, UpdateStateRequest,
    };
    use fandhe_container_supervisor::health::{
        Demotion, HealthProbe, ProbeRunner, probe_and_record, record_health,
    };
    use fandhe_container_supervisor::run::{MonitorEvent, MonitorObserver, MonitorOperation};
    use fandhe_container_supervisor::state::SupervisedState;

    /// 楽観ロック（expected_revision 一致）で更新する 1 レコードのメモリストア。
    struct MemStore(Mutex<StateRecord>);

    impl StateStore for MemStore {
        fn create(&self, _: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "mem"))
        }
        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            let mut g = self.0.lock().unwrap();
            if g.revision() != req.expected_revision() {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            let sup = req.supervision().unwrap_or_else(|| g.supervision());
            let next = StateRecord::new(
                req.status().clone(),
                g.bundle().to_path_buf(),
                StateRevision::from_raw(g.revision().value() + 1),
            )
            .unwrap()
            .with_supervision(sup);
            *g = next.clone();
            Ok(next)
        }
        fn get(&self, _: &GetStateRequest) -> Result<StateRecord, TraitError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn list(&self, _: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "mem"))
        }
        fn delete(&self, _: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "mem"))
        }
    }

    struct Proc;

    impl LaunchedProcess for Proc {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(42).unwrap()
        }
        fn wait(&self, _: Duration) -> Result<Option<ProcessExit>, TraitError> {
            Ok(None)
        }
        fn terminate(&self, _: Duration) -> Result<(), TraitError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct Obs(Mutex<Vec<MonitorEvent>>);

    impl MonitorObserver for Obs {
        fn observe(&self, e: &MonitorEvent) {
            self.0.lock().unwrap().push(e.clone());
        }
    }

    struct Fixed(HealthStatus);

    impl HealthProbe for Fixed {
        fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
            Ok(self.0)
        }
    }

    struct Failing;

    impl HealthProbe for Failing {
        fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "boom"))
        }
    }

    fn me() -> NonZeroU32 {
        NonZeroU32::new(std::process::id()).unwrap()
    }

    fn setup(owner: Option<NonZeroU32>, health: Option<HealthStatus>) -> SupervisedState {
        let id = ContainerId::new("c1").unwrap();
        let rec = StateRecord::new(
            ContainerStatus::running(id.clone(), NonZeroU32::new(42)),
            std::env::temp_dir().join("health-hook-it"),
            StateRevision::from_raw(1),
        )
        .unwrap()
        .with_supervision(SupervisionState::new(owner, health, 3));
        let store: Arc<dyn StateStore> = Arc::new(MemStore(Mutex::new(rec)));
        SupervisedState::attach(store, id).unwrap()
    }

    /// SUP-4: record_health が StateStore の health だけを更新し、revision を進める。
    #[test]
    fn sup4_task157_6_it_record_health_updates_store() {
        let mut s = setup(Some(me()), None);
        let rec = record_health(&mut s, &Proc, HealthStatus::Healthy, &Obs::default()).unwrap();
        assert_eq!(rec.health(), Some(HealthStatus::Healthy));
        assert_eq!(rec.revision().value(), 2);
        assert_eq!(rec.restart_count(), 3);
        assert_eq!(s.record().health(), Some(HealthStatus::Healthy));
    }

    /// SUP-1: 所有者でない supervisor は書けず、レコードは変わらない。
    #[test]
    fn sup1_task157_6_it_ownership_rejected() {
        let mut s = setup(None, None);
        let e = record_health(&mut s, &Proc, HealthStatus::Healthy, &Obs::default()).unwrap_err();
        assert_eq!(e.code(), ErrorCode::FailedPrecondition);
        assert_eq!(s.record().health(), None);
        assert_eq!(s.record().revision().value(), 1);
        let probe = ProbeRunner::new(Arc::new(Fixed(HealthStatus::Healthy)));
        let f = probe_and_record(
            &mut s,
            &Proc,
            &probe,
            Duration::from_secs(1),
            &Obs::default(),
        )
        .unwrap_err();
        assert_eq!(f.error().code(), ErrorCode::FailedPrecondition);
        assert_eq!(f.demotion(), &Demotion::NotNeeded);
    }

    /// SUP-4: probe 成功は結果が書かれ、Probe / RecordHealth が通知される。
    #[test]
    fn sup4_task157_6_it_probe_and_record_success() {
        let mut s = setup(Some(me()), None);
        let obs = Obs::default();
        let probe = ProbeRunner::new(Arc::new(Fixed(HealthStatus::Unhealthy)));
        let rec = probe_and_record(&mut s, &Proc, &probe, Duration::from_secs(1), &obs).unwrap();
        assert_eq!(rec.health(), Some(HealthStatus::Unhealthy));
        let ev = obs.0.lock().unwrap();
        assert_eq!(ev[0].operation, MonitorOperation::Probe);
        assert_eq!(ev[1].operation, MonitorOperation::RecordHealth);
    }

    /// SUP-4・REPAIR-5: probe 失敗で古い Healthy が Unhealthy へ降格される。
    #[test]
    fn sup4_task157_6_it_probe_failure_demotes_healthy() {
        let mut s = setup(Some(me()), Some(HealthStatus::Healthy));
        let probe = ProbeRunner::new(Arc::new(Failing));
        let f = probe_and_record(
            &mut s,
            &Proc,
            &probe,
            Duration::from_secs(1),
            &Obs::default(),
        )
        .unwrap_err();
        assert_eq!(f.error().code(), ErrorCode::Internal);
        assert_eq!(f.demotion(), &Demotion::Applied);
        assert_eq!(s.record().health(), Some(HealthStatus::Unhealthy));
    }

    /// 最初の `update` 1 回だけを、テストが解放するまで止めるストア（判定後・記録中の区間を作る）。
    struct GatedStore {
        inner: MemStore,
        armed: AtomicBool,
        entered: Mutex<mpsc::Sender<()>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    /// テストがハングしないための安全弁（通常は即座に受け渡される）。
    const GATE_LIMIT: Duration = Duration::from_secs(10);

    impl StateStore for GatedStore {
        fn create(&self, r: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            self.inner.create(r)
        }
        fn update(&self, r: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            if self.armed.swap(false, Ordering::SeqCst) {
                let _ = self.entered.lock().unwrap().send(());
                let _ = self.release.lock().unwrap().recv_timeout(GATE_LIMIT);
            }
            self.inner.update(r)
        }
        fn get(&self, r: &GetStateRequest) -> Result<StateRecord, TraitError> {
            self.inner.get(r)
        }
        fn list(&self, r: &ListStateRequest) -> Result<StateList, TraitError> {
            self.inner.list(r)
        }
        fn delete(&self, r: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            self.inner.delete(r)
        }
    }

    /// 1 回目は Healthy、2 回目以降は Unhealthy を返す probe（呼び出し回数を数える）。
    struct HealthyThenUnhealthy(AtomicU32);

    impl HealthProbe for HealthyThenUnhealthy {
        fn probe(&self, _: Duration) -> Result<HealthStatus, TraitError> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(HealthStatus::Healthy)
            } else {
                Ok(HealthStatus::Unhealthy)
            }
        }
    }

    /// SUP-4・REPAIR-5: 先行する判定が記録を終える前の並行呼び出しは、probe も書き込みもせず
    /// `Unavailable` で拒否される（古い Healthy が新しい Unhealthy を後から上書きしない）。
    /// 順序はチャネルの受け渡しで決まり、sleep に依存しない。
    #[test]
    fn sup4_repair5_task157_6_it_concurrent_call_cannot_overwrite_newer_result() {
        let id = ContainerId::new("c1").unwrap();
        let rec = StateRecord::new(
            ContainerStatus::running(id.clone(), NonZeroU32::new(42)),
            std::env::temp_dir().join("health-hook-it"),
            StateRevision::from_raw(1),
        )
        .unwrap()
        .with_supervision(SupervisionState::new(Some(me()), None, 3));
        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let store: Arc<dyn StateStore> = Arc::new(GatedStore {
            inner: MemStore(Mutex::new(rec)),
            armed: AtomicBool::new(true),
            entered: Mutex::new(entered_tx),
            release: Mutex::new(release_rx),
        });
        let probe = Arc::new(HealthyThenUnhealthy(AtomicU32::new(0)));
        let runner = ProbeRunner::new(probe.clone());
        let t = Duration::from_secs(1);

        let (a_store, a_id, a_runner) = (store.clone(), id.clone(), runner.clone());
        let a = std::thread::spawn(move || {
            let mut s = SupervisedState::attach(a_store, a_id).unwrap();
            probe_and_record(&mut s, &Proc, &a_runner, t, &Obs::default())
        });
        // A の probe は Healthy を返し終え、記録の書き込みで止まっている。
        entered.recv_timeout(GATE_LIMIT).unwrap();

        let mut s = SupervisedState::attach(store, id).unwrap();
        let f = probe_and_record(&mut s, &Proc, &runner, t, &Obs::default()).unwrap_err();
        assert_eq!(f.error().code(), ErrorCode::Unavailable);
        assert_eq!(f.demotion(), &Demotion::NotNeeded);
        assert_eq!(probe.0.load(Ordering::SeqCst), 1);
        assert_eq!(s.refresh().unwrap().revision().value(), 1);
        assert_eq!(s.record().health(), None);

        release.send(()).unwrap();
        let rec = a.join().unwrap().unwrap();
        assert_eq!(rec.health(), Some(HealthStatus::Healthy));
        assert_eq!(rec.revision().value(), 2);

        // A の終了後の判定（Unhealthy）が最後に残る。
        let rec = probe_and_record(&mut s, &Proc, &runner, t, &Obs::default()).unwrap();
        assert_eq!(rec.health(), Some(HealthStatus::Unhealthy));
        assert_eq!(rec.revision().value(), 3);
        assert_eq!(rec.restart_count(), 3);
        assert_eq!(probe.0.load(Ordering::SeqCst), 2);
    }
}
