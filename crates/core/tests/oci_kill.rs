//! `oci_runtime::kill` の結合試験（OCI-6・CORE-2・REPAIR-5・TASK-30.1）。
//!
//! 公開 API（`kill`・`ProcessSignaler`・`KillTimeout`・`StateStore`）だけを crate の外から呼び、
//! 不在 ID の `NotFound`・シグナルの転送・signaler が戻らないときの `Timeout` を具体値で確かめる。
//! 実プロセスは使わず（signaler は模擬）、3 OS の既定のテスト集合で root 不要で動く。

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{KillTimeout, ProcessSignaler, kill};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ContainerStatus, CreateStateRequest, DeleteStateRequest,
    DeleteStateResponse, ErrorCode, GetStateRequest, KillRequest, ListStateRequest, Signal,
    StateList, StateRecord, StateRevision, StateStore, TraitError, UpdateStateRequest,
};

/// テスト専用のインメモリ `StateStore`（kill は `get` だけを使う）。
#[derive(Default)]
struct MemStateStore(Mutex<HashMap<ContainerId, StateRecord>>);

impl StateStore for MemStateStore {
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        let record = StateRecord::new(
            req.status().clone(),
            req.bundle().to_path_buf(),
            StateRevision::from_raw(1),
        )?;
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(req.id().clone(), record.clone());
        Ok(record)
    }
    fn update(&self, _req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(req.id())
            .cloned()
            .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))
    }
    fn list(&self, _req: &ListStateRequest) -> Result<StateList, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn delete(&self, _req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
}

/// 受け取った (id, pid, signal) を記録し、`delay` だけ眠る偽の signaler。
struct FakeSignaler {
    calls: Mutex<Vec<(String, u32, u8)>>,
    delay: Duration,
}

impl ProcessSignaler for FakeSignaler {
    fn signal(
        &self,
        id: &ContainerId,
        pid: NonZeroU32,
        signal: Signal,
        _timeout: Duration,
    ) -> Result<(), TraitError> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).push((
            id.as_str().to_owned(),
            pid.get(),
            signal.as_u8(),
        ));
        std::thread::sleep(self.delay);
        Ok(())
    }
}

fn setup(delay: Duration) -> (MemStateStore, Arc<FakeSignaler>, ContainerId) {
    let id = ContainerId::new("c1").expect("id");
    let store = MemStateStore::default();
    let pid = NonZeroU32::new(4242).expect("pid");
    store
        .create(
            &CreateStateRequest::new(
                ContainerStatus::running(id.clone(), Some(pid)),
                std::env::temp_dir().join("bundle"),
            )
            .expect("req"),
        )
        .expect("create");
    let signaler = Arc::new(FakeSignaler {
        calls: Mutex::new(Vec::new()),
        delay,
    });
    (store, signaler, id)
}

/// OCI-6（受入基準 2）: 存在しない ID への kill は `NotFound` で、signaler は呼ばれない。
#[test]
fn oci6_kill_unknown_id_is_not_found() {
    let (store, signaler, _) = setup(Duration::ZERO);
    let dynamic: Arc<dyn ProcessSignaler> = signaler.clone();
    let req = KillRequest::new(ContainerId::new("missing").expect("id"), Signal::SIGKILL);
    let err = kill(
        &store,
        &OpRecorder::new(),
        &dynamic,
        &req,
        &KillTimeout::default(),
    )
    .expect_err("not found");
    assert_eq!(err.code(), ErrorCode::NotFound);
    assert!(signaler.calls.lock().unwrap().is_empty());
}

/// CORE-2・OCI-6: Running の ID への kill は (id, pid, signal) を signaler へ渡し、状態は Running のまま返す。
#[test]
fn core2_kill_forwards_signal_and_keeps_state() {
    let (store, signaler, id) = setup(Duration::ZERO);
    let dynamic: Arc<dyn ProcessSignaler> = signaler.clone();
    let status = kill(
        &store,
        &OpRecorder::new(),
        &dynamic,
        &KillRequest::new(id, Signal::SIGTERM),
        &KillTimeout::default(),
    )
    .expect("kill");
    assert_eq!(status.state(), ContainerState::Running);
    assert_eq!(status.pid(), NonZeroU32::new(4242));
    assert_eq!(
        signaler.calls.lock().unwrap().as_slice(),
        &[("c1".to_owned(), 4242, 15)]
    );
}

/// REPAIR-5: signaler が戻らなければ上限で `Timeout` を返す。
#[test]
fn repair5_kill_times_out_when_signaler_hangs() {
    let (store, signaler, id) = setup(Duration::from_secs(5));
    let dynamic: Arc<dyn ProcessSignaler> = signaler.clone();
    let err = kill(
        &store,
        &OpRecorder::new(),
        &dynamic,
        &KillRequest::new(id, Signal::SIGKILL),
        &KillTimeout::new(Duration::from_millis(50)).expect("timeout"),
    )
    .expect_err("timeout");
    assert_eq!(err.code(), ErrorCode::Timeout);
}
