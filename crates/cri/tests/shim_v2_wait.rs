//! shim v2 の Wait を UDS 越しに通す結合試験（CRI-5・CRI-1・REPAIR-5・TASK-62.3.2・MS-7）。
//! `timeout_nano` の期限・停止時の取り消しと応答の到達・イベント駆動の `wait_exit` の上書きも照合する（#3666）。
#![cfg(unix)]

#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest as RtDelete,
    DeleteResponse as RtDeleteResponse, ErrorCode, KillRequest, StartRequest as RtStart,
    StateRequest, StopRequest, TraitError, WaitExitRequest,
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
    call_with(s, sid, method, payload, 0)
}

/// `timeout_nano` つきで呼ぶ。
fn call_with(
    s: &mut UnixStream,
    sid: u32,
    method: &str,
    payload: Vec<u8>,
    timeout_nano: i64,
) -> TtrpcResponse {
    send(s, sid, method, payload, timeout_nano);
    read_response(s)
}

fn send(s: &mut UnixStream, sid: u32, method: &str, payload: Vec<u8>, timeout_nano: i64) {
    let body = TtrpcRequest {
        service: "containerd.task.v2.Task".into(),
        method: method.into(),
        payload,
        timeout_nano,
        ..Default::default()
    }
    .encode_to_vec();
    let h = FrameHeader::new(body.len() as u32, sid, MessageType::Request, 0).unwrap();
    s.write_all(&h.to_bytes()).unwrap();
    s.write_all(&body).unwrap();
}

fn read_response(s: &mut UnixStream) -> TtrpcResponse {
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

type Started = (
    Arc<Fake>,
    std::path::PathBuf,
    fandhe_container_cri::shim_v2::ServerHandle,
    test_root::TestRoot,
);

fn start_service(name: &str, cfg: WaitConfig) -> Started {
    let fake = Arc::new(Fake::default());
    let adapter = RuntimeAdapter::from_runtime(Shared(fake.clone()));
    start_with(name, cfg, fake, adapter)
}

fn start_with(name: &str, cfg: WaitConfig, fake: Arc<Fake>, adapter: RuntimeAdapter) -> Started {
    let root = test_root::test_root("ttrpc", name);
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut reg = ServiceRegistry::new();
    reg.register(Arc::new(
        TaskService::new(TaskApiVersion::V2, adapter).with_wait_config(cfg),
    ))
    .unwrap();
    let handle = TtrpcServer::new(reg, ServerConfig::default())
        .serve(listener)
        .unwrap();
    (fake, path, handle, root)
}

type Gate = Arc<(Mutex<Option<i32>>, Condvar)>;

/// `wait_exit` を Condvar で上書きしたイベント駆動の偽ランタイム。通知されるまで `state` を呼ばずに待つ。
struct EventRt {
    inner: Shared,
    gate: Gate,
}

impl ContainerRuntime for EventRt {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        self.inner.create(r)
    }
    fn start(&self, r: &RtStart) -> Result<ContainerStatus, TraitError> {
        self.inner.start(r)
    }
    fn kill(&self, r: &KillRequest) -> Result<ContainerStatus, TraitError> {
        self.inner.kill(r)
    }
    fn stop(&self, r: &StopRequest) -> Result<ContainerStatus, TraitError> {
        self.inner.stop(r)
    }
    fn delete(&self, r: &RtDelete) -> Result<RtDeleteResponse, TraitError> {
        self.inner.delete(r)
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        self.inner.state(r)
    }
    fn wait_exit(&self, req: &WaitExitRequest<'_>) -> Result<ContainerStatus, TraitError> {
        let end = Instant::now() + req.timeout();
        let (m, cv) = &*self.gate;
        let mut g = m.lock().unwrap();
        loop {
            if let Some(code) = *g {
                return Ok(ContainerStatus::stopped(req.id().clone(), Some(code)));
            }
            if req.is_cancelled() {
                return Err(TraitError::new(ErrorCode::Unavailable, "wait cancelled"));
            }
            let now = Instant::now();
            if now >= end {
                return Err(TraitError::new(
                    ErrorCode::Timeout,
                    "wait exceeded its deadline",
                ));
            }
            g = cv
                .wait_timeout(g, (end - now).min(Duration::from_millis(10)))
                .unwrap()
                .0;
        }
    }
}

fn start_event(name: &str, cfg: WaitConfig) -> (Gate, Started) {
    let fake = Arc::new(Fake::default());
    let gate: Gate = Arc::new((Mutex::new(None), Condvar::new()));
    let adapter = RuntimeAdapter::from_runtime(EventRt {
        inner: Shared(fake.clone()),
        gate: gate.clone(),
    });
    (gate, start_with(name, cfg, fake, adapter))
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

fn cfg_poll(timeout_ms: u64, poll_ms: u64) -> WaitConfig {
    WaitConfig::new(
        Duration::from_millis(timeout_ms),
        Duration::from_millis(poll_ms),
    )
    .unwrap()
}

/// CRI-1・REPAIR-5: `timeout_nano` が WaitConfig（10 秒）より短ければ、その期限で DEADLINE_EXCEEDED（4）。
#[test]
fn cri1_wait_timeout_nano_bounds_wait() {
    let (_fake, path, handle, _root) = start_service("wait-tn", cfg(10_000));
    let mut s = connect(&path);
    create_and_start(&mut s, 1);
    let t0 = Instant::now();
    let r = call_with(&mut s, 5, "Wait", wait_req("c1"), 150_000_000);
    let st = r.status.unwrap();
    assert_eq!(
        (st.code, st.message.as_str()),
        (4, "wait exceeded its deadline")
    );
    assert!(t0.elapsed() >= Duration::from_millis(150));
    assert!(t0.elapsed() < Duration::from_secs(2));
    drop(s);
    drop(handle);
}

/// CRI-1・REPAIR-5: 負の `timeout_nano` は期限切れ済みとして runtime を待たずに 4。
#[test]
fn cri1_wait_negative_timeout_nano_expires_immediately() {
    let (_fake, path, handle, _root) = start_service("wait-neg", cfg(10_000));
    let mut s = connect(&path);
    create_and_start(&mut s, 1);
    let t0 = Instant::now();
    let r = call_with(&mut s, 5, "Wait", wait_req("c1"), -1);
    assert_eq!(r.status.unwrap().code, 4);
    assert!(t0.elapsed() < Duration::from_millis(500));
    drop(s);
    drop(handle);
}

/// REPAIR-5: `timeout_nano` が WaitConfig より長くても WaitConfig（100ms）が上限になる。
#[test]
fn repair5_wait_timeout_nano_cannot_exceed_config() {
    let (_fake, path, handle, _root) = start_service("wait-cap", cfg(100));
    let mut s = connect(&path);
    create_and_start(&mut s, 1);
    let t0 = Instant::now();
    let r = call_with(&mut s, 5, "Wait", wait_req("c1"), 3_600_000_000_000);
    assert_eq!(r.status.unwrap().code, 4);
    assert!(t0.elapsed() < Duration::from_secs(2));
    drop(s);
    drop(handle);
}

/// REPAIR-5・CRI-1: 停止で取り消された Wait の UNAVAILABLE（14）が、生きているクライアントへ届く。
#[test]
fn repair5_shutdown_cancels_inflight_wait() {
    let (_fake, path, handle, _root) = start_service("wait-stop", cfg(60_000));
    let mut s = connect(&path);
    create_and_start(&mut s, 1);
    send(&mut s, 5, "Wait", wait_req("c1"), 0);
    std::thread::sleep(Duration::from_millis(100));
    let t0 = Instant::now();
    handle.shutdown().unwrap();
    assert!(t0.elapsed() < Duration::from_secs(2));
    let r = read_response(&mut s);
    let st = r.status.unwrap();
    assert_eq!((st.code, st.message.as_str()), (14, "wait cancelled"));
    assert!(t0.elapsed() < Duration::from_secs(2));
}

/// CRI-1: 上書きされた `wait_exit` のイベント通知で、照会間隔（10 秒）を待たずに終了コードが返る。
#[test]
fn cri1_event_driven_wait_exit_returns_on_notify() {
    let (gate, (_fake, path, handle, _root)) = start_event("wait-ev", cfg_poll(60_000, 10_000));
    let mut s = connect(&path);
    create_and_start(&mut s, 1);
    send(&mut s, 5, "Wait", wait_req("c1"), 0);
    std::thread::sleep(Duration::from_millis(100));
    let t0 = Instant::now();
    {
        let (m, cv) = &*gate;
        *m.lock().unwrap() = Some(9);
        cv.notify_all();
    }
    let r = read_response(&mut s);
    assert!(r.status.is_none());
    assert_eq!(WaitResponse::decode(&r.payload[..]).unwrap().exit_status, 9);
    assert!(t0.elapsed() < Duration::from_secs(1));
    drop(s);
    drop(handle);
}

/// REPAIR-5: 上書きされた `wait_exit` の中で待っていても、停止で取り消され 14 が届く。
#[test]
fn repair5_shutdown_cancels_event_driven_wait() {
    let (_gate, (_fake, path, handle, _root)) =
        start_event("wait-ev-stop", cfg_poll(60_000, 10_000));
    let mut s = connect(&path);
    create_and_start(&mut s, 1);
    send(&mut s, 5, "Wait", wait_req("c1"), 0);
    std::thread::sleep(Duration::from_millis(100));
    let t0 = Instant::now();
    handle.shutdown().unwrap();
    let r = read_response(&mut s);
    let st = r.status.unwrap();
    assert_eq!((st.code, st.message.as_str()), (14, "wait cancelled"));
    assert!(t0.elapsed() < Duration::from_secs(2));
}
