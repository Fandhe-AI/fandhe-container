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
    use std::sync::{Arc, Mutex};
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
}
