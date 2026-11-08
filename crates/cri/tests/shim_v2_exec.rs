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
    ErrorCode, KillRequest, Signal, StartRequest as RtStart, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::RuntimeAdapter;
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::shim_v2::{
    Any, CreateTaskRequest, DeleteRequest as WireDelete, DeleteResponse as WireDeleteResponse,
    ExecId, ExecProcessRequest, ExecProcessSpec, ExecProcessStatus, FrameHeader, HEADER_LEN,
    KillRequest as WireKill, MessageType, ServerConfig, ServiceRegistry, StartRequest,
    StartResponse, StateRequest as WireState, StateResponse, TaskApiVersion, TaskExecLauncher,
    TaskExecProcess, TaskService, TtrpcRequest, TtrpcResponse, TtrpcServer, WaitRequest,
    WaitResponse,
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

/// 終了を外から注入でき、シグナルを記録する偽の exec プロセス。
struct Proc {
    exit: Mutex<Option<i32>>,
    signals: Mutex<Vec<u8>>,
}

impl TaskExecProcess for Proc {
    fn pid(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(9001)
    }
    fn status(&self) -> Result<ExecProcessStatus, CriError> {
        Ok(match *self.exit.lock().unwrap() {
            Some(code) => ExecProcessStatus::Exited { code: Some(code) },
            None => ExecProcessStatus::Running,
        })
    }
    fn signal(&self, signal: Signal) -> Result<(), CriError> {
        self.signals.lock().unwrap().push(signal.as_u8());
        Ok(())
    }
}

/// 呼び出しを記録する偽の起動役。起動したプロセスは `proc` に残す。
struct Launcher {
    calls: Mutex<Vec<(String, String, Vec<String>)>>,
    proc: Arc<Proc>,
}

impl Launcher {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            proc: Arc::new(Proc {
                exit: Mutex::new(None),
                signals: Mutex::new(Vec::new()),
            }),
        })
    }
}

impl TaskExecLauncher for Launcher {
    fn launch(
        &self,
        c: &ContainerId,
        e: &ExecId,
        s: &ExecProcessSpec,
    ) -> Result<Arc<dyn TaskExecProcess>, CriError> {
        self.calls
            .lock()
            .unwrap()
            .push((c.as_str().into(), e.as_str().into(), s.args().to_vec()));
        Ok(self.proc.clone())
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
    let launcher = Launcher::new();
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
        *launcher.calls.lock().unwrap(),
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

/// 1 回の呼び出しで使う接続に service 名を変えて通す。
fn call_svc(
    s: &mut UnixStream,
    sid: u32,
    service: &str,
    method: &str,
    payload: Vec<u8>,
) -> TtrpcResponse {
    let body = TtrpcRequest {
        service: service.into(),
        method: method.into(),
        payload,
        ..Default::default()
    }
    .encode_to_vec();
    let h = FrameHeader::new(body.len() as u32, sid, MessageType::Request, 0).unwrap();
    s.write_all(&h.to_bytes()).unwrap();
    s.write_all(&body).unwrap();
    read_response(s)
}

fn read_response(s: &mut UnixStream) -> TtrpcResponse {
    let mut hb = [0u8; HEADER_LEN];
    s.read_exact(&mut hb).unwrap();
    let h = FrameHeader::from_bytes(&hb).unwrap();
    let mut rb = vec![0u8; h.length() as usize];
    s.read_exact(&mut rb).unwrap();
    TtrpcResponse::decode(&rb[..]).unwrap()
}

/// CRI-5・CRI-1・REPAIR-5・#3681: Exec → 別接続の Wait → Start → State → Kill → 終了 → Wait の応答 →
/// State → Delete → State(NOT_FOUND) が UDS 越しに通る（v2 / v3 のサービス名）。
#[test]
fn cri5_3681_exec_lifecycle_over_uds() {
    for (version, service) in [
        (TaskApiVersion::V2, "containerd.task.v2.Task"),
        (TaskApiVersion::V3, "containerd.task.v3.Task"),
    ] {
        let root = test_root::test_root("ttrpc", "exec-lifecycle");
        let path = root.join("s.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let launcher = Launcher::new();
        let mut reg = ServiceRegistry::new();
        let adapter = RuntimeAdapter::from_runtime(Fake(Mutex::new(HashSet::new())));
        reg.register(Arc::new(
            TaskService::new(version, adapter).with_exec_launcher(launcher.clone()),
        ))
        .unwrap();
        let handle = TtrpcServer::new(reg, ServerConfig::default())
            .serve(listener)
            .unwrap();
        let mut s = UnixStream::connect(&path).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut sid = 1;
        let mut next = || {
            let v = sid;
            sid += 2;
            v
        };

        let create = CreateTaskRequest {
            id: "c1".into(),
            bundle: "/run/bundle".into(),
            ..Default::default()
        }
        .encode_to_vec();
        assert!(
            call_svc(&mut s, next(), service, "Create", create)
                .status
                .is_none()
        );
        let start = StartRequest {
            id: "c1".into(),
            exec_id: String::new(),
        }
        .encode_to_vec();
        assert!(
            call_svc(&mut s, next(), service, "Start", start)
                .status
                .is_none()
        );
        let r = call_svc(
            &mut s,
            next(),
            service,
            "Exec",
            exec_req(r#"{"cwd":"/","args":["/bin/true"]}"#),
        );
        assert!(r.status.is_none());

        // 別接続で Wait を始める（Start の前。ExecSync の順序）。
        let mut w = UnixStream::connect(&path).unwrap();
        w.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let wait = WaitRequest {
            id: "c1".into(),
            exec_id: "e1".into(),
        }
        .encode_to_vec();
        let body = TtrpcRequest {
            service: service.into(),
            method: "Wait".into(),
            payload: wait,
            ..Default::default()
        }
        .encode_to_vec();
        let h = FrameHeader::new(body.len() as u32, 1, MessageType::Request, 0).unwrap();
        w.write_all(&h.to_bytes()).unwrap();
        w.write_all(&body).unwrap();

        let st = |s: &mut UnixStream, id: u32| {
            let r = call_svc(
                s,
                id,
                service,
                "State",
                WireState {
                    id: "c1".into(),
                    exec_id: "e1".into(),
                }
                .encode_to_vec(),
            );
            (
                r.status.map(|x| x.code),
                StateResponse::decode(&r.payload[..]).unwrap(),
            )
        };
        let (code, r) = st(&mut s, next());
        assert_eq!(code, None);
        assert_eq!((r.id.as_str(), r.pid, r.status), ("e1", 0, 1));

        let start_exec = StartRequest {
            id: "c1".into(),
            exec_id: "e1".into(),
        }
        .encode_to_vec();
        let r = call_svc(&mut s, next(), service, "Start", start_exec);
        assert_eq!(StartResponse::decode(&r.payload[..]).unwrap().pid, 9001);
        let (_, r) = st(&mut s, next());
        assert_eq!((r.pid, r.status, r.exit_status), (9001, 2, 0));

        let kill = WireKill {
            id: "c1".into(),
            exec_id: "e1".into(),
            signal: 15,
            all: false,
        }
        .encode_to_vec();
        assert!(
            call_svc(&mut s, next(), service, "Kill", kill)
                .status
                .is_none()
        );
        assert_eq!(*launcher.proc.signals.lock().unwrap(), vec![15]);

        // 実行中の Delete は FAILED_PRECONDITION（9）。
        let del = WireDelete {
            id: "c1".into(),
            exec_id: "e1".into(),
        }
        .encode_to_vec();
        let r = call_svc(&mut s, next(), service, "Delete", del.clone());
        assert_eq!(r.status.unwrap().code, 9);

        *launcher.proc.exit.lock().unwrap() = Some(143);
        let wr = read_response(&mut w);
        assert!(wr.status.is_none());
        assert_eq!(
            WaitResponse::decode(&wr.payload[..]).unwrap().exit_status,
            143
        );
        let (_, r) = st(&mut s, next());
        assert_eq!((r.pid, r.status, r.exit_status), (9001, 3, 143));

        let r = call_svc(&mut s, next(), service, "Delete", del);
        assert!(r.status.is_none());
        let d = WireDeleteResponse::decode(&r.payload[..]).unwrap();
        assert_eq!((d.pid, d.exit_status), (9001, 143));
        let (code, _) = st(&mut s, next());
        assert_eq!(code, Some(5));

        drop(w);
        drop(s);
        drop(handle);
    }
}

/// REPAIR-5・#3681: `timeout_nano` つきの Wait(exec_id) は期限で DEADLINE_EXCEEDED（4）になる。
#[test]
fn cri5_3681_wait_exec_timeout_nano_over_uds() {
    let root = test_root::test_root("ttrpc", "exec-wait-timeout");
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let launcher = Launcher::new();
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
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let svc = "containerd.task.v2.Task";
    let create = CreateTaskRequest {
        id: "c1".into(),
        bundle: "/run/bundle".into(),
        ..Default::default()
    }
    .encode_to_vec();
    assert!(call_svc(&mut s, 1, svc, "Create", create).status.is_none());
    let start = StartRequest {
        id: "c1".into(),
        exec_id: String::new(),
    }
    .encode_to_vec();
    assert!(call_svc(&mut s, 3, svc, "Start", start).status.is_none());
    assert!(
        call_svc(
            &mut s,
            5,
            svc,
            "Exec",
            exec_req(r#"{"cwd":"/","args":["a"]}"#)
        )
        .status
        .is_none()
    );
    let start_exec = StartRequest {
        id: "c1".into(),
        exec_id: "e1".into(),
    }
    .encode_to_vec();
    assert!(
        call_svc(&mut s, 7, svc, "Start", start_exec)
            .status
            .is_none()
    );

    let wait = WaitRequest {
        id: "c1".into(),
        exec_id: "e1".into(),
    }
    .encode_to_vec();
    let body = TtrpcRequest {
        service: svc.into(),
        method: "Wait".into(),
        payload: wait,
        timeout_nano: 100_000_000,
        ..Default::default()
    }
    .encode_to_vec();
    let h = FrameHeader::new(body.len() as u32, 9, MessageType::Request, 0).unwrap();
    s.write_all(&h.to_bytes()).unwrap();
    s.write_all(&body).unwrap();
    let r = read_response(&mut s);
    let st = r.status.unwrap();
    assert_eq!(st.code, 4);

    drop(s);
    drop(handle);
}
/// 状態を外から差し替え・削除できる偽ランタイム。`None` の ID は state が NOT_FOUND になる。
struct Mutable(Arc<Mutex<std::collections::HashMap<String, Option<ContainerStatus>>>>);

impl ContainerRuntime for Mutable {
    fn create(&self, r: &CreateRequest) -> Result<ContainerStatus, TraitError> {
        let st = ContainerStatus::created(r.id().clone(), None);
        self.0
            .lock()
            .unwrap()
            .insert(r.id().as_str().to_owned(), Some(st.clone()));
        Ok(st)
    }
    fn start(&self, r: &RtStart) -> Result<ContainerStatus, TraitError> {
        let st = ContainerStatus::running(r.id().clone(), NonZeroU32::new(777));
        self.0
            .lock()
            .unwrap()
            .insert(r.id().as_str().to_owned(), Some(st.clone()));
        Ok(st)
    }
    fn kill(&self, _: &KillRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn stop(&self, _: &StopRequest) -> Result<ContainerStatus, TraitError> {
        Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
    }
    fn delete(&self, r: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        self.0.lock().unwrap().remove(r.id().as_str());
        Ok(DeleteResponse::new())
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        match self.0.lock().unwrap().get(r.id().as_str()) {
            Some(Some(st)) => Ok(st.clone()),
            _ => Err(TraitError::new(ErrorCode::NotFound, "gone")),
        }
    }
}

/// CRI-5・CRI-1・REPAIR-12・#4058: 実行層から外で消えたコンテナの exec 登録は NOT_FOUND の照会で回収され、
/// v2 と v3 が登録簿を共有し、どちらの Delete でも両方から消える（UDS 越し）。
#[test]
fn cri5_4058_exec_registry_reclaim_and_v2_v3_share_over_uds() {
    let root = test_root::test_root("ttrpc", "exec-reclaim");
    let path = root.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let launcher = Launcher::new();
    let table = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let v2 = TaskService::new(
        TaskApiVersion::V2,
        RuntimeAdapter::from_runtime(Mutable(table.clone())),
    )
    .with_exec_launcher(launcher.clone());
    let v3 = TaskService::new(
        TaskApiVersion::V3,
        RuntimeAdapter::from_runtime(Mutable(table.clone())),
    )
    .with_exec_launcher(launcher.clone())
    .with_shared_created(&v2);
    let mut reg = ServiceRegistry::new();
    reg.register(Arc::new(v2)).unwrap();
    reg.register(Arc::new(v3)).unwrap();
    let handle = TtrpcServer::new(reg, ServerConfig::default())
        .serve(listener)
        .unwrap();
    let mut s = UnixStream::connect(&path).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let (v2n, v3n) = ("containerd.task.v2.Task", "containerd.task.v3.Task");
    let mut sid = 1u32;
    let mut next = || {
        let v = sid;
        sid += 2;
        v
    };
    let create = || {
        CreateTaskRequest {
            id: "c1".into(),
            bundle: "/run/bundle".into(),
            ..Default::default()
        }
        .encode_to_vec()
    };
    let start = || {
        StartRequest {
            id: "c1".into(),
            exec_id: String::new(),
        }
        .encode_to_vec()
    };
    let state_e1 = || {
        WireState {
            id: "c1".into(),
            exec_id: "e1".into(),
        }
        .encode_to_vec()
    };
    let spec = r#"{"cwd":"/","args":["a"]}"#;

    assert!(
        call_svc(&mut s, next(), v2n, "Create", create())
            .status
            .is_none()
    );
    assert!(
        call_svc(&mut s, next(), v2n, "Start", start())
            .status
            .is_none()
    );
    assert!(
        call_svc(&mut s, next(), v2n, "Exec", exec_req(spec))
            .status
            .is_none()
    );

    // v2 で登録した exec が v3 から見える（TaskStatus::CREATED = 1）。
    let r = call_svc(&mut s, next(), v3n, "State", state_e1());
    assert!(r.status.is_none());
    assert_eq!(StateResponse::decode(&r.payload[..]).unwrap().status, 1);
    // 同じ exec_id の再登録は ALREADY_EXISTS（6）。
    let r = call_svc(&mut s, next(), v3n, "Exec", exec_req(spec));
    assert_eq!(r.status.unwrap().code, 6);

    // 実行層から外で消す。照会は NOT_FOUND（5）で、登録も回収される。
    table.lock().unwrap().insert("c1".into(), None);
    // v3 の Delete が NOT_FOUND を観測して登録を除去する。
    let del_gone = WireDelete {
        id: "c1".into(),
        exec_id: String::new(),
    }
    .encode_to_vec();
    let r = call_svc(&mut s, next(), v3n, "Delete", del_gone);
    assert_eq!(r.status.unwrap().code, 5);
    // v3 で回収された登録は v2 からも消えている。
    let r = call_svc(&mut s, next(), v2n, "State", state_e1());
    assert_eq!(r.status.unwrap().code, 5);
    // 作り直すと、同じ exec_id を再び登録できる（回収済みの証拠）。
    assert!(
        call_svc(&mut s, next(), v2n, "Create", create())
            .status
            .is_none()
    );
    assert!(
        call_svc(&mut s, next(), v2n, "Start", start())
            .status
            .is_none()
    );
    let r = call_svc(&mut s, next(), v2n, "State", state_e1());
    assert_eq!(r.status.unwrap().code, 5);
    assert!(
        call_svc(&mut s, next(), v2n, "Exec", exec_req(spec))
            .status
            .is_none()
    );

    // 停止させ、v3 の Delete で v2 側からも exec が消える。
    table.lock().unwrap().insert(
        "c1".into(),
        Some(ContainerStatus::stopped(
            ContainerId::new("c1").unwrap(),
            Some(0),
        )),
    );
    let del = WireDelete {
        id: "c1".into(),
        exec_id: String::new(),
    }
    .encode_to_vec();
    assert!(
        call_svc(&mut s, next(), v3n, "Delete", del)
            .status
            .is_none()
    );
    let r = call_svc(&mut s, next(), v2n, "State", state_e1());
    assert_eq!(r.status.unwrap().code, 5);

    drop(s);
    drop(handle);
}
