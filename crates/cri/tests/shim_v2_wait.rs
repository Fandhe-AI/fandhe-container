//! shim v2 の Wait を UDS 越しに通す結合試験（CRI-5・REPAIR-5・TASK-62.3.2・MS-7）。
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
    CreateTaskRequest, DeleteRequest, FrameHeader, HEADER_LEN, MessageType, ServerConfig,
    ServiceRegistry, StartRequest, TaskApiVersion, TaskService, TtrpcRequest, TtrpcResponse,
    TtrpcServer, WaitConfig, WaitRequest, WaitResponse,
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

fn wait_req(id: &str) -> Vec<u8> {
    WaitRequest {
        id: id.into(),
        exec_id: String::new(),
    }
    .encode_to_vec()
}

fn start_service(
    name: &str,
    cfg: WaitConfig,
) -> (
    Arc<Fake>,
    std::path::PathBuf,
    fandhe_container_cri::shim_v2::ServerHandle,
    test_root::TestRoot,
) {
    let root = test_root::test_root("ttrpc", name);
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let fake = Arc::new(Fake::default());
    let mut reg = ServiceRegistry::new();
    let adapter = RuntimeAdapter::from_runtime(Shared(fake.clone()));
    reg.register(Arc::new(
        TaskService::new(TaskApiVersion::V2, adapter).with_wait_config(cfg),
    ))
    .unwrap();
    let handle = TtrpcServer::new(reg, ServerConfig::default())
        .serve(listener)
        .unwrap();
    (fake, path, handle, root)
}

fn connect(path: &std::path::Path) -> UnixStream {
    let s = UnixStream::connect(path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn create_and_start(s: &mut UnixStream, first_sid: u32) {
    let create = CreateTaskRequest {
        id: "c1".into(),
        bundle: "/run/bundle".into(),
        ..Default::default()
    }
    .encode_to_vec();
    assert!(call(s, first_sid, "Create", create).status.is_none());
    let start = StartRequest {
        id: "c1".into(),
        exec_id: String::new(),
    }
    .encode_to_vec();
    assert!(call(s, first_sid + 2, "Start", start).status.is_none());
}

fn cfg(timeout_ms: u64) -> WaitConfig {
    WaitConfig::new(Duration::from_millis(timeout_ms), Duration::from_millis(10)).unwrap()
}

/// CRI-5: Wait は終了まで返らず、終了後に終了コードを返す。
#[test]
fn cri5_wait_over_uds_returns_exit_code() {
    let (fake, path, handle, _root) = start_service("wait-ok", cfg(10_000));
    let mut s = connect(&path);
    create_and_start(&mut s, 1);
    let t0 = std::time::Instant::now();
    let f2 = fake.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        *f2.stopped_code.lock().unwrap() = Some(42);
    });
    let r = call(&mut s, 5, "Wait", wait_req("c1"));
    t.join().unwrap();
    assert!(r.status.is_none());
    assert!(t0.elapsed() >= Duration::from_millis(150));
    let w = WaitResponse::decode(&r.payload[..]).unwrap();
    assert_eq!((w.exit_status, w.exited_at), (42, None));
    drop(s);
    drop(handle);
}

/// REPAIR-5: 終わらないコンテナの Wait は DEADLINE_EXCEEDED（4）で終わる。
#[test]
fn cri5_wait_over_uds_timeout() {
    let (_fake, path, handle, _root) = start_service("wait-timeout", cfg(100));
    let mut s = connect(&path);
    create_and_start(&mut s, 1);
    let t0 = std::time::Instant::now();
    let r = call(&mut s, 5, "Wait", wait_req("c1"));
    assert_eq!(r.status.unwrap().code, 4);
    assert!(t0.elapsed() >= Duration::from_millis(100));
    drop(s);
    drop(handle);
}

/// Wait の待ち中でも別の接続の要求は処理される（接続をまたいだ止まりが無い）。
#[test]
fn cri5_wait_does_not_block_other_connections() {
    let (fake, path, handle, _root) = start_service("wait-conn", cfg(10_000));
    let mut a = connect(&path);
    create_and_start(&mut a, 1);
    let waiter = std::thread::spawn(move || {
        let r = call(&mut a, 5, "Wait", wait_req("c1"));
        (r, a)
    });
    std::thread::sleep(Duration::from_millis(100));
    let mut b = connect(&path);
    let t0 = std::time::Instant::now();
    let r = call(
        &mut b,
        1,
        "Delete",
        DeleteRequest {
            id: "c1".into(),
            exec_id: String::new(),
        }
        .encode_to_vec(),
    );
    assert_eq!(r.status.unwrap().code, 9);
    assert!(t0.elapsed() < Duration::from_secs(5));
    *fake.stopped_code.lock().unwrap() = Some(0);
    let (r, a) = waiter.join().unwrap();
    assert!(r.status.is_none());
    assert_eq!(WaitResponse::decode(&r.payload[..]).unwrap().exit_status, 0);
    drop(a);
    drop(b);
    drop(handle);
}
