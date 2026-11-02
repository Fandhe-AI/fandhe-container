//! shim v2 の State / Kill / Shutdown を UDS 越しに通す結合試験（CRI-5・ERR-3・TASK-62.7.2・MS-7・#873）。
//!
//! 偽ランタイムの上で Create → Start → State → Kill → 停止 → State / Kill → Delete → Shutdown を
//! v2 / v3 の両サービス名で通し、状態・pid・終了コード・NOT_FOUND・終了要求を具体値で照合する。
#![cfg(unix)]

#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest as RtDelete,
    DeleteResponse as RtDeleteResponse, ErrorCode, KillRequest as RtKill, StartRequest as RtStart,
    StateRequest as RtState, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::RuntimeAdapter;
use fandhe_container_cri::shim_v2::{
    CreateTaskRequest, DeleteRequest, FrameHeader, HEADER_LEN, KillRequest, MessageType,
    ServerConfig, ServiceRegistry, ShutdownRequest, ShutdownSignal, StartRequest, StateRequest,
    StateResponse, TaskApiVersion, TaskService, TaskStatus, TtrpcRequest, TtrpcResponse,
    TtrpcServer,
};
use prost::Message;

/// 状態つきの偽ランタイム。kill の記録と、停止の注入を持つ。
#[derive(Default)]
struct Fake {
    containers: Mutex<HashMap<String, ContainerStatus>>,
    kills: Mutex<Vec<(String, u8)>>,
    stopped_code: Mutex<Option<i32>>,
}

struct Shared(Arc<Fake>);

impl ContainerRuntime for Shared {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        let st = ContainerStatus::created(r.id().clone(), None);
        self.0
            .containers
            .lock()
            .unwrap()
            .insert(r.id().as_str().to_owned(), st.clone());
        Ok(st)
    }
    fn start(&self, r: &RtStart) -> Result<ContainerStatus, TraitError> {
        let st = ContainerStatus::running(r.id().clone(), NonZeroU32::new(777));
        self.0
            .containers
            .lock()
            .unwrap()
            .insert(r.id().as_str().to_owned(), st.clone());
        Ok(st)
    }
    fn kill(&self, r: &RtKill) -> Result<ContainerStatus, TraitError> {
        self.0
            .kills
            .lock()
            .unwrap()
            .push((r.id().as_str().to_owned(), r.signal().as_u8()));
        self.state(&RtState::new(r.id().clone()))
    }
    fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn delete(&self, r: &RtDelete) -> Result<RtDeleteResponse, TraitError> {
        let mut m = self.0.containers.lock().unwrap();
        if m.remove(r.id().as_str()).is_none() {
            return Err(TraitError::new(ErrorCode::NotFound, "none"));
        }
        Ok(RtDeleteResponse::new())
    }
    fn state(&self, r: &RtState) -> Result<ContainerStatus, TraitError> {
        let m = self.0.containers.lock().unwrap();
        let cur = m
            .get(r.id().as_str())
            .cloned()
            .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "none"))?;
        match *self.0.stopped_code.lock().unwrap() {
            Some(c) => Ok(ContainerStatus::stopped(r.id().clone(), Some(c))),
            None => Ok(cur),
        }
    }
}

fn call(s: &mut UnixStream, sid: u32, svc: &str, method: &str, payload: Vec<u8>) -> TtrpcResponse {
    let body = TtrpcRequest {
        service: svc.into(),
        method: method.into(),
        payload,
        ..Default::default()
    }
    .encode_to_vec();
    let h = FrameHeader::new(body.len() as u32, sid, MessageType::Request, 0).unwrap();
    s.write_all(&h.to_bytes()).unwrap();
    s.write_all(&body).unwrap();
    let mut hb = [0u8; HEADER_LEN];
    s.read_exact(&mut hb).unwrap();
    let h = FrameHeader::from_bytes(&hb).unwrap();
    let mut rb = vec![0u8; h.length() as usize];
    s.read_exact(&mut rb).unwrap();
    TtrpcResponse::decode(&rb[..]).unwrap()
}

fn state(s: &mut UnixStream, sid: u32, svc: &str) -> StateResponse {
    let req = StateRequest {
        id: "c1".into(),
        exec_id: String::new(),
    };
    let r = call(s, sid, svc, "State", req.encode_to_vec());
    assert!(r.status.is_none(), "{:?}", r.status);
    StateResponse::decode(&r.payload[..]).unwrap()
}

fn kill(id: &str, signal: u32) -> Vec<u8> {
    KillRequest {
        id: id.into(),
        exec_id: String::new(),
        signal,
        all: false,
    }
    .encode_to_vec()
}

/// CRI-5・TASK-62.7.2: State / Kill / Shutdown が v2 / v3 の両方で UDS 越しに通る。
#[test]
fn cri5_873_state_kill_shutdown_over_uds() {
    for (n, svc, tag) in [
        (TaskApiVersion::V2, "containerd.task.v2.Task", "v2"),
        (TaskApiVersion::V3, "containerd.task.v3.Task", "v3"),
    ] {
        let root = test_root::test_root("ttrpc", &format!("sk{tag}"));
        let path = root.join("s.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let fake = Arc::new(Fake::default());
        let signal = ShutdownSignal::new();
        let mut reg = ServiceRegistry::new();
        let adapter = RuntimeAdapter::from_runtime(Shared(fake.clone()));
        reg.register(Arc::new(
            TaskService::new(n, adapter).with_shutdown(signal.clone()),
        ))
        .unwrap();
        let handle = TtrpcServer::new(reg, ServerConfig::default())
            .serve(listener)
            .unwrap();
        let mut s = UnixStream::connect(&path).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let create = CreateTaskRequest {
            id: "c1".into(),
            bundle: "/run/bundle".into(),
            ..Default::default()
        }
        .encode_to_vec();
        assert!(call(&mut s, 1, svc, "Create", create).status.is_none());
        let r = state(&mut s, 3, svc);
        assert_eq!((r.pid, r.status), (0, TaskStatus::Created as i32));
        let start = StartRequest {
            id: "c1".into(),
            exec_id: String::new(),
        }
        .encode_to_vec();
        assert!(call(&mut s, 5, svc, "Start", start).status.is_none());
        let r = state(&mut s, 7, svc);
        assert_eq!(
            (r.id.as_str(), r.pid, r.status, r.exit_status),
            ("c1", 777, TaskStatus::Running as i32, 0)
        );

        // Kill(15) は偽ランタイムへ届く。範囲外は 3。
        assert!(
            call(&mut s, 9, svc, "Kill", kill("c1", 15))
                .status
                .is_none()
        );
        assert_eq!(*fake.kills.lock().unwrap(), [("c1".to_owned(), 15)]);
        let r = call(&mut s, 11, svc, "Kill", kill("c1", 0));
        assert_eq!(r.status.unwrap().code, 3);

        // 停止後: State は STOPPED と終了コード、Kill は NOT_FOUND で送らない。
        *fake.stopped_code.lock().unwrap() = Some(3);
        let r = state(&mut s, 13, svc);
        assert_eq!((r.status, r.exit_status), (TaskStatus::Stopped as i32, 3));
        let r = call(&mut s, 15, svc, "Kill", kill("c1", 9));
        let st = r.status.unwrap();
        assert_eq!(
            (st.code, st.message.as_str()),
            (5, "process already finished")
        );
        assert_eq!(fake.kills.lock().unwrap().len(), 1);

        // コンテナが残っている間の Shutdown は何もしない。Delete 後は終了を要求する。
        let sd = ShutdownRequest {
            id: "c1".into(),
            now: false,
        }
        .encode_to_vec();
        assert!(
            call(&mut s, 17, svc, "Shutdown", sd.clone())
                .status
                .is_none()
        );
        assert!(!signal.is_requested());
        let del = DeleteRequest {
            id: "c1".into(),
            exec_id: String::new(),
        }
        .encode_to_vec();
        assert!(call(&mut s, 19, svc, "Delete", del).status.is_none());
        let r = call(&mut s, 21, svc, "Shutdown", sd);
        assert!(r.status.is_none() && r.payload.is_empty());
        assert!(signal.is_requested());
        // 応答は書き込み済みで、処理中の要求は流れ切る。
        assert!(handle.wait_idle(Duration::from_secs(5)));

        drop(s);
        drop(handle);
    }
}
