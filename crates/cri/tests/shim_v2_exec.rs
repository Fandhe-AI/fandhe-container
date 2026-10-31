//! shim v2 の Exec を UDS 越しに通す結合試験（CRI-5・ERR-3・TASK-62.4・MS-7）。
#![cfg(unix)]

#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

use std::collections::HashSet;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fandhe_container_core::traits::{
    ContainerId, ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse,
    ErrorCode, KillRequest, StartRequest as RtStart, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::RuntimeAdapter;
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::shim_v2::{
    Any, CreateTaskRequest, ExecId, ExecProcessRequest, ExecProcessSpec, FrameHeader, HEADER_LEN,
    MessageType, ServerConfig, ServiceRegistry, StartRequest, StartResponse, TaskApiVersion,
    TaskExecLauncher, TaskService, TtrpcRequest, TtrpcResponse, TtrpcServer,
};
use prost::Message;

/// 作成済み ID を覚え、常に Running と答える偽ランタイム。
struct Fake(Mutex<HashSet<String>>);

impl ContainerRuntime for Fake {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        if !self.0.lock().unwrap().insert(r.id().as_str().to_owned()) {
            return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
        }
        Ok(ContainerStatus::created(r.id().clone(), None))
    }
    fn start(&self, r: &RtStart) -> Result<ContainerStatus, TraitError> {
        Ok(ContainerStatus::running(
            r.id().clone(),
            NonZeroU32::new(777),
        ))
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn delete(&self, _: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        Ok(ContainerStatus::running(
            r.id().clone(),
            NonZeroU32::new(777),
        ))
    }
}

/// 呼び出しを記録する偽の起動役。
struct Launcher(Mutex<Vec<(String, String, Vec<String>)>>);

impl TaskExecLauncher for Launcher {
    fn launch(
        &self,
        c: &ContainerId,
        e: &ExecId,
        s: &ExecProcessSpec,
    ) -> Result<Option<NonZeroU32>, CriError> {
        self.0
            .lock()
            .unwrap()
            .push((c.as_str().into(), e.as_str().into(), s.args().to_vec()));
        Ok(NonZeroU32::new(9001))
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

fn exec_req(json: &str) -> Vec<u8> {
    ExecProcessRequest {
        id: "c1".into(),
        exec_id: "e1".into(),
        spec: Some(Any {
            type_url: "types.containerd.io/opencontainers/runtime-spec/1/Process".into(),
            value: json.as_bytes().to_vec(),
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

/// CRI-5・ERR-3: 実ソケット越しに Create → Start → Exec → Start(exec_id) が通る。
#[test]
fn cri5_exec_over_uds() {
    let root = test_root::test_root("ttrpc", "exec");
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let launcher = Arc::new(Launcher(Mutex::new(Vec::new())));
    let mut reg = ServiceRegistry::new();
    let adapter = RuntimeAdapter::from_runtime(Fake(Mutex::new(HashSet::new())));
    reg.register(Arc::new(
        TaskService::new(TaskApiVersion::V2, adapter).with_exec_launcher(launcher.clone()),
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
    assert!(call(&mut s, 1, "Create", create).status.is_none());
    let start = StartRequest {
        id: "c1".into(),
        exec_id: String::new(),
    }
    .encode_to_vec();
    assert!(call(&mut s, 3, "Start", start).status.is_none());

    let r = call(
        &mut s,
        5,
        "Exec",
        exec_req(r#"{"cwd":"/","args":["/bin/true"]}"#),
    );
    assert!(r.status.is_none());
    assert!(r.payload.is_empty());

    let start_exec = StartRequest {
        id: "c1".into(),
        exec_id: "e1".into(),
    }
    .encode_to_vec();
    let r = call(&mut s, 7, "Start", start_exec);
    assert!(r.status.is_none());
    assert_eq!(StartResponse::decode(&r.payload[..]).unwrap().pid, 9001);
    assert_eq!(
        *launcher.0.lock().unwrap(),
        vec![(
            "c1".to_string(),
            "e1".to_string(),
            vec!["/bin/true".to_string()]
        )]
    );

    // 未対応の欄の Exec は UNIMPLEMENTED（12）。
    let r = call(
        &mut s,
        9,
        "Exec",
        exec_req(r#"{"cwd":"/","args":["a"],"capabilities":{}}"#),
    );
    assert_eq!(r.status.unwrap().code, 12);

    drop(s);
    drop(handle);
}
