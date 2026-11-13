//! `up` の `DependencyObserver` / `HealthSource` の本番アダプタと、launcher と共有する台帳（STACK-8・STACK-2・SUP-1・TASK-155・#4638）。
//!
//! # 役割
//! stack の `up()` は依存先の「起動した」「healthy になった」を待つ。その観測を、core の状態ストア（`state.json`）の
//! 読み取りで満たす。stack は core に依存しない（#4630）ため、読み取りは cli 側に置く。後続の `ps` の
//! `ServiceStatusSource` も [`read_status`] を ID の導出だけで再利用できる形にしてある。
//!
//! # 「今回の up が作ったものに限る」（`ServiceLauncher` の契約 (b)）
//! 状態ストアには前回の実行の記録が残りうる。そこで launcher が `create` に成功した時点で [`Ledger`] に
//! （サービス名 → コンテナ ID）を記録し、observer・health は台帳にあるサービスだけを読む。台帳に無ければ `Absent` / `None`
//! で、前回の残骸を満たし扱いしない。`up()` は 3 つのアダプタを別々の `&mut` で受けるため、台帳は単一スレッドの
//! `Rc<RefCell<..>>` で共有し、借用はメソッドの内側で短く取る（`try_borrow*` の失敗は panic せず観測エラーにする）。
//!
//! # 期限（REPAIR-5）
//! 状態ストアの読み取りは core のロック期限（`STATE_LOCK_TIMEOUT`）に従う。待ち全体の上限は stack の `UpPolicy`。

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, GetStateRequest, HealthStatus, StateStore,
};
use fandhe_container_stack::cli::up::ServiceContainerId;
use fandhe_container_stack::depends_on::wait::{
    DependencyObservation, DependencyObserver, ObserveError,
};
use fandhe_container_stack::depends_on::{HealthSource, HealthSourceError, ObservedHealth};

/// 今回の `up` が create したコンテナの台帳（サービス名 → コンテナ ID）。
#[derive(Debug, Default)]
pub(super) struct Ledger {
    created: BTreeMap<String, ServiceContainerId>,
}

impl Ledger {
    /// `create` に成功したサービスを記録する。
    pub(super) fn record(&mut self, service: &str, id: ServiceContainerId) {
        self.created.insert(service.to_owned(), id);
    }

    /// 記録済みのコンテナ ID。
    pub(super) fn get(&self, service: &str) -> Option<&ServiceContainerId> {
        self.created.get(service)
    }
}

/// 3 つのアダプタが共有する台帳。
pub(super) type SharedLedger = Rc<RefCell<Ledger>>;

/// 1 コンテナの観測値（状態と health）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Observed {
    pub(super) state: DependencyObservation,
    pub(super) health: Option<ObservedHealth>,
}

/// 状態の読み取りの失敗（固定文言。値は含めない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReadFailure;

/// `id` の記録を読み、状態と health を観測値へ写す。記録が無ければ `Absent`・health なし。
///
/// 記録が無い（`NotFound`）以外の読み取り失敗は [`ReadFailure`]。
pub(super) fn read_status(
    store: &dyn StateStore,
    id: &ServiceContainerId,
) -> Result<Observed, ReadFailure> {
    let cid = ContainerId::new(id.as_str()).map_err(|_| ReadFailure)?;
    match store.get(&GetStateRequest::new(cid)) {
        Ok(record) => {
            let state = match record.status().state() {
                ContainerState::Creating => DependencyObservation::Creating,
                ContainerState::Created => DependencyObservation::Created,
                ContainerState::Running => DependencyObservation::Running,
                ContainerState::Stopped => DependencyObservation::Stopped,
                _ => return Err(ReadFailure),
            };
            let health = match record.health() {
                None => None,
                Some(HealthStatus::Starting) => Some(ObservedHealth::Starting),
                Some(HealthStatus::Healthy) => Some(ObservedHealth::Healthy),
                Some(HealthStatus::Unhealthy) => Some(ObservedHealth::Unhealthy),
                Some(_) => return Err(ReadFailure),
            };
            Ok(Observed { state, health })
        }
        Err(e) if e.code() == ErrorCode::NotFound => Ok(Observed {
            state: DependencyObservation::Absent,
            health: None,
        }),
        Err(_) => Err(ReadFailure),
    }
}

/// 台帳にあるサービスの記録を読む（無ければ `Absent` 相当）。
fn observe_ledgered(
    store: &dyn StateStore,
    ledger: &SharedLedger,
    service: &str,
) -> Result<Observed, ReadFailure> {
    let id = {
        let l = ledger.try_borrow().map_err(|_| ReadFailure)?;
        l.get(service).cloned()
    };
    match id {
        None => Ok(Observed {
            state: DependencyObservation::Absent,
            health: None,
        }),
        Some(id) => read_status(store, &id),
    }
}

/// 本番の [`DependencyObserver`]。
pub(super) struct StateObserver<S: StateStore> {
    store: Rc<S>,
    ledger: SharedLedger,
}

impl<S: StateStore> StateObserver<S> {
    pub(super) fn new(store: Rc<S>, ledger: SharedLedger) -> Self {
        Self { store, ledger }
    }
}

impl<S: StateStore> DependencyObserver for StateObserver<S> {
    fn observe(&mut self, service: &str) -> Result<DependencyObservation, ObserveError> {
        observe_ledgered(self.store.as_ref(), &self.ledger, service)
            .map(|o| o.state)
            .map_err(|_| ObserveError::new("UNAVAILABLE", "container state could not be read"))
    }
}

/// 本番の [`HealthSource`]。
pub(super) struct StateHealth<S: StateStore> {
    store: Rc<S>,
    ledger: SharedLedger,
}

impl<S: StateStore> StateHealth<S> {
    pub(super) fn new(store: Rc<S>, ledger: SharedLedger) -> Self {
        Self { store, ledger }
    }
}

impl<S: StateStore> HealthSource for StateHealth<S> {
    fn observe(&mut self, service: &str) -> Result<Option<ObservedHealth>, HealthSourceError> {
        observe_ledgered(self.store.as_ref(), &self.ledger, service)
            .map(|o| o.health)
            .map_err(|_| HealthSourceError::new("UNAVAILABLE", "container state could not be read"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerStatus, CreateStateRequest, SupervisionState, UpdateStateRequest,
    };
    use fandhe_container_stack::cli::up::ProjectName;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let p = std::env::temp_dir().join(format!(
                "fc-up-observe-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).expect("mkdir");
            std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .expect("chmod");
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn open(s: &Scratch) -> FileStateStore {
        FileStateStore::open(StateRoot::from_override(s.0.join("state")).expect("root"))
            .expect("open")
    }

    fn status(id: &ServiceContainerId, state: ContainerState) -> ContainerStatus {
        let cid = ContainerId::new(id.as_str()).expect("id");
        match state {
            ContainerState::Created => ContainerStatus::created(cid, None),
            ContainerState::Running => ContainerStatus::running(cid, None),
            _ => ContainerStatus::creating(cid),
        }
    }

    fn id(service: &str) -> ServiceContainerId {
        ServiceContainerId::derive(&ProjectName::new("shop").expect("project"), service)
            .expect("id")
    }

    /// STACK-8・SUP-1・#4638: 台帳に無いサービスは、状態ストアに記録が残っていても `Absent`・health なし
    /// （前回の実行の残骸を満たし扱いしない）。
    #[test]
    fn stack8_4638_unledgered_service_is_absent_even_if_a_record_exists() {
        let s = Scratch::new("absent");
        let store = Rc::new(open(&s));
        let bundle = s.0.join("bundle");
        std::fs::create_dir_all(&bundle).expect("bundle");
        let db = id("db");
        store
            .create(
                &CreateStateRequest::new(status(&db, ContainerState::Running), bundle)
                    .expect("req"),
            )
            .expect("create");
        let ledger: SharedLedger = Rc::default();
        let mut obs = StateObserver::new(store.clone(), ledger.clone());
        let mut health = StateHealth::new(store, ledger);
        assert_eq!(obs.observe("db"), Ok(DependencyObservation::Absent));
        assert_eq!(health.observe("db"), Ok(None));
    }

    /// STACK-8・SUP-1・#4638: 台帳に記録した後は、状態ストアの状態と health を具体値で読む。
    #[test]
    fn stack8_4638_ledgered_service_reflects_state_and_health() {
        let s = Scratch::new("ledgered");
        let store = Rc::new(open(&s));
        let bundle = s.0.join("bundle");
        std::fs::create_dir_all(&bundle).expect("bundle");
        let db = id("db");
        let created = store
            .create(
                &CreateStateRequest::new(status(&db, ContainerState::Created), bundle)
                    .expect("req"),
            )
            .expect("create");
        let ledger: SharedLedger = Rc::default();
        ledger.borrow_mut().record("db", db.clone());
        let mut obs = StateObserver::new(store.clone(), ledger.clone());
        let mut health = StateHealth::new(store.clone(), ledger.clone());
        assert_eq!(obs.observe("db"), Ok(DependencyObservation::Created));
        assert_eq!(health.observe("db"), Ok(None));
        let sup = SupervisionState::new(None, Some(HealthStatus::Healthy), 0);
        store
            .update(
                &UpdateStateRequest::new(status(&db, ContainerState::Running), created.revision())
                    .with_supervision(sup),
            )
            .expect("update");
        assert_eq!(obs.observe("db"), Ok(DependencyObservation::Running));
        assert_eq!(health.observe("db"), Ok(Some(ObservedHealth::Healthy)));
    }

    /// REPAIR-5: 台帳が借用中でも panic せず観測エラーになる。
    #[test]
    fn stack8_4638_borrowed_ledger_is_an_observe_error_not_a_panic() {
        let s = Scratch::new("borrow");
        let store = Rc::new(open(&s));
        let ledger: SharedLedger = Rc::default();
        let mut obs = StateObserver::new(store, ledger.clone());
        let _held = ledger.borrow_mut();
        let e = obs.observe("db").expect_err("borrowed");
        assert_eq!(e.code(), "UNAVAILABLE");
    }
}
