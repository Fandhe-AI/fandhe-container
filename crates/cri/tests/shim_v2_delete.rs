//! shim v2 の Delete を UDS 越しに通す結合試験（CRI-5・ERR-3・TASK-62.3.1・MS-7）。
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
    DeleteResponse as RtDeleteResponse, ErrorCode, KillRequest, StartRequest as RtStart,
    StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::RuntimeAdapter;
use fandhe_container_cri::shim_v2::{
    CreateTaskRequest, DeleteRequest, DeleteResponse, FrameHeader, HEADER_LEN, MessageType,
    ServerConfig, ServiceRegistry, StartRequest, TaskApiVersion, TaskService, TtrpcRequest,
    TtrpcResponse, TtrpcServer,
};
use prost::Message;

/// 状態つきの偽ランタイム。`stopped_code` に値が入ると、そのコードで Stopped になる。
#[derive(Default)]
struct Fake {
    containers: Mutex<HashMap<String, ContainerStatus>>,
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
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn delete(&self, r: &RtDelete) -> Result<RtDeleteResponse, TraitError> {
        let mut m = self.0.containers.lock().unwrap();
        let id = r.id().as_str();
        let running = match m.get(id) {
            None => return Err(TraitError::new(ErrorCode::NotFound, "none")),
            Some(s) => s.pid().is_some(),
        };
        if running && self.0.stopped_code.lock().unwrap().is_none() {
            return Err(TraitError::new(ErrorCode::FailedPrecondition, "running"));
        }
        m.remove(id);
        Ok(RtDeleteResponse::new())
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
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

fn call(s: &mut UnixStream, sid: u32, method: &str, payload: Vec<u8>) -> TtrpcResponse {
    let body = TtrpcRequest {
        service: "containerd.task.v2.Task".into(),
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

fn del(id: &str, exec_id: &str) -> Vec<u8> {
    DeleteRequest {
        id: id.into(),
        exec_id: exec_id.into(),
    }
    .encode_to_vec()
}

/// CRI-5・ERR-3: 実行中は 9、停止後は成功して exit_status が返り、再度は NOT_FOUND（5）。
#[test]
fn cri5_delete_over_uds() {
    let root = test_root::test_root("ttrpc", "delete");
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let fake = Arc::new(Fake::default());
    let mut reg = ServiceRegistry::new();
    let adapter = RuntimeAdapter::from_runtime(Shared(fake.clone()));
    reg.register(Arc::new(TaskService::new(TaskApiVersion::V2, adapter)))
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
    assert!(call(&mut s, 1, "Create", create).status.is_none());
    let start = StartRequest {
        id: "c1".into(),
        exec_id: String::new(),
    }
    .encode_to_vec();
    assert!(call(&mut s, 3, "Start", start).status.is_none());

    // 実行中は拒否される。
    let r = call(&mut s, 5, "Delete", del("c1", ""));
    assert_eq!(r.status.unwrap().code, 9);

    // exec_id 付きは未対応。
    let r = call(&mut s, 7, "Delete", del("c1", "e"));
    assert_eq!(r.status.unwrap().code, 12);

    *fake.stopped_code.lock().unwrap() = Some(3);
    let r = call(&mut s, 9, "Delete", del("c1", ""));
    assert!(r.status.is_none());
    let d = DeleteResponse::decode(&r.payload[..]).unwrap();
    assert_eq!((d.pid, d.exit_status, d.exited_at), (0, 3, None));

    let r = call(&mut s, 11, "Delete", del("c1", ""));
    assert_eq!(r.status.unwrap().code, 5);

    drop(s);
    drop(handle);
}
