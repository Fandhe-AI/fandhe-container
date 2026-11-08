//! shim v2 の TaskCreate・TaskStart・TaskDelete・TaskExit の publish を、公開 API だけで本番の組み立て（`TaskService` + `exec_publisher_for_with` +
//! 検証済みの `PublishBinary`）を通して照合する結合試験（CRI-5・TASK-62.6・REPAIR-10・REPAIR-12・#4155・#4156）。
//!
//! 偽なのは実行層（`ContainerRuntime`）と publish バイナリ（`/bin/sh` の記録スクリプト）だけ。Start の後に終了を
//! 観測した watcher が、偽バイナリへ argv と `Any`（TaskExit）を渡し、イベントがちょうど 1 件であることを具体値で確かめる。
//! Delete 後に同じ ID で作り直した場合に、旧世代が旧 pid のイベントを送らないことも確かめる。
#![cfg(unix)]

#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{
    ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest as RtDelete,
    DeleteResponse as RtDeleteResponse, ErrorCode, ExitTime, KillRequest, StartRequest as RtStart,
    StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::RuntimeAdapter;
use fandhe_container_cri::shim_v2::bootstrap::{PublishBinary, ServeContext, ShimIdentifier};
use fandhe_container_cri::shim_v2::publish::{
    PublishConfig, PublishFailure, PublishLog, TaskCreate, TaskDelete, TaskExit, TaskIo, TaskStart,
    exec_publisher_for_with,
};
use fandhe_container_cri::shim_v2::{
    Any, CreateTaskRequest, DeleteRequest, ShutdownSignal, StartRequest, TaskApiVersion,
    TaskService, Timestamp, TtrpcService, WaitConfig,
};
use prost::Message;

#[derive(Default)]
struct Fake {
    containers: Mutex<HashMap<String, ContainerStatus>>,
    stopped: Mutex<Option<(i32, i64)>>,
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
        let st = ContainerStatus::running(r.id().clone(), NonZeroU32::new(4242));
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
        self.0.containers.lock().unwrap().remove(r.id().as_str());
        Ok(RtDeleteResponse::new())
    }
    fn state(&self, r: &StateRequest) -> Result<ContainerStatus, TraitError> {
        let cur = self
            .0
            .containers
            .lock()
            .unwrap()
            .get(r.id().as_str())
            .cloned()
            .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "none"))?;
        match *self.0.stopped.lock().unwrap() {
            Some((code, nanos)) => Ok(ContainerStatus::stopped_at(
                r.id().clone(),
                Some(code),
                ExitTime::from_unix_nanos(nanos),
            )),
            None => Ok(cur),
        }
    }
}

#[derive(Default)]
struct CaptureLog(Mutex<Vec<PublishFailure>>);

impl PublishLog for CaptureLog {
    fn record(&self, failure: &PublishFailure) {
        self.0.lock().unwrap().push(failure.clone());
    }
}

fn make_script(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("fake-publish");
    // ETXTBSY を避けるため、書き込みと chmod は子プロセスで行う。
    let st = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"printf '%s' "$1" > "$2" && chmod 755 "$2""#)
        .arg("sh")
        .arg(body)
        .arg(&path)
        .status()
        .expect("run sh");
    assert!(st.success());
    path
}

fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + limit;
    while !cond() {
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

fn create_req(id: &str, bundle: &str) -> Vec<u8> {
    CreateTaskRequest {
        id: id.into(),
        bundle: bundle.into(),
        ..Default::default()
    }
    .encode_to_vec()
}

fn start_req(id: &str) -> Vec<u8> {
    StartRequest {
        id: id.into(),
        exec_id: String::new(),
    }
    .encode_to_vec()
}

/// 偽バイナリの `n` 回目の呼び出し（`call<n>`）の完了を待ち、argv の topic と `Any` を返す。
fn wait_call(out: &std::path::Path, n: usize) -> (String, Any) {
    let dir = out.join(format!("call{n}"));
    assert!(wait_until(Duration::from_secs(10), || dir
        .join("stdin")
        .exists()));
    let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
    let lines: Vec<&str> = argv.lines().collect();
    assert_eq!(
        &lines[..5],
        [
            "--address",
            "/run/containerd/containerd.sock",
            "publish",
            "--namespace",
            "default"
        ]
    );
    assert_eq!(lines[5], "--topic");
    let any = Any::decode(std::fs::read(dir.join("stdin")).unwrap().as_slice()).unwrap();
    (lines[6].to_owned(), any)
}

fn count_calls(out: &std::path::Path) -> usize {
    std::fs::read_dir(out).unwrap().count()
}

/// CRI-5・#4155・#4156: Create → Start → 終了 → Delete → 作り直しの各段で、偽 publish バイナリが
/// topic（`/tasks/create`・`/tasks/start`・`/tasks/exit`・`/tasks/delete`）と `Any` の中身を、この順にちょうど 1 回ずつ受け取る。
/// 作り直しでは新しい世代の Create・Start・終了だけが追加される。
#[test]
fn cri5_4155_events_reach_fake_publish_binary_in_order() {
    let dir = test_root::test_root("pubit", "once");
    // 呼び出しごとに連番のディレクトリへ argv と stdin を記録する。連番は `$(( ))` で数値化する
    // （macOS の BSD `wc -l` は先頭へ空白を足し、そのまま連結すると `call       0` になって照合できない。#4218）。
    let out = dir.join("out");
    std::fs::create_dir(&out).unwrap();
    let body = format!(
        "#!/bin/sh\nn=$(( $(/bin/ls \"{o}\" | /usr/bin/wc -l) ))\nd=\"{o}/call$n\"\n/bin/mkdir \"$d\"\nprintf '%s\\n' \"$@\" > \"$d/argv\"\n/bin/cat > \"$d/stdin.tmp\"\n/bin/mv \"$d/stdin.tmp\" \"$d/stdin\"\n",
        o = out.display()
    );
    let bin = make_script(&dir, &body);
    let log = Arc::new(CaptureLog::default());
    let ctx = ServeContext::new(ShutdownSignal::new(), None)
        .with_origin(
            Some(ShimIdentifier::parse("default").unwrap()),
            Some("/run/containerd/containerd.sock".into()),
        )
        .with_publish_binary(Some(PublishBinary::verify(&bin).unwrap()));
    let publisher = exec_publisher_for_with(
        &ctx,
        PublishConfig::new(Duration::from_secs(5)).unwrap(),
        log.clone(),
    )
    .expect("publisher");

    let fake = Arc::new(Fake::default());
    let svc = TaskService::new(
        TaskApiVersion::V2,
        RuntimeAdapter::from_runtime(Shared(fake.clone())),
    )
    .with_wait_config(
        WaitConfig::new(Duration::from_millis(100), Duration::from_millis(10)).unwrap(),
    )
    .with_event_publisher(publisher);

    let bundle = dir.join("bundle");
    std::fs::create_dir(&bundle).unwrap();
    let bundle = bundle.to_str().unwrap().to_owned();
    svc.handle("Create", &create_req("c1", &bundle)).unwrap();
    svc.handle("Start", &start_req("c1")).unwrap();
    let (topic, any) = wait_call(&out, 0);
    assert_eq!(topic, "/tasks/create");
    assert_eq!(any.type_url, "containerd.events.TaskCreate");
    assert_eq!(
        TaskCreate::decode(any.value.as_slice()).unwrap(),
        TaskCreate {
            container_id: "c1".into(),
            bundle: bundle.clone(),
            rootfs: Vec::new(),
            io: Some(TaskIo::default()),
            checkpoint: String::new(),
            pid: 0,
        }
    );
    let (topic, any) = wait_call(&out, 1);
    assert_eq!(topic, "/tasks/start");
    assert_eq!(any.type_url, "containerd.events.TaskStart");
    assert_eq!(
        TaskStart::decode(any.value.as_slice()).unwrap(),
        TaskStart {
            container_id: "c1".into(),
            pid: 4242
        }
    );
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(count_calls(&out), 2, "running: Create and Start only");

    *fake.stopped.lock().unwrap() = Some((3, 1_700_000_000_000_000_005));
    let (topic, any) = wait_call(&out, 2);
    assert_eq!(topic, "/tasks/exit");
    assert_eq!(any.type_url, "containerd.events.TaskExit");
    assert_eq!(
        TaskExit::decode(any.value.as_slice()).unwrap(),
        TaskExit {
            container_id: "c1".into(),
            id: "c1".into(),
            pid: 4242,
            exit_status: 3,
            exited_at: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 5
            }),
        }
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(count_calls(&out), 3, "exit exactly once");

    // Delete は応答と同じ値の TaskDelete を 1 件送る。
    let out_bytes = svc
        .handle(
            "Delete",
            &DeleteRequest {
                id: "c1".into(),
                exec_id: String::new(),
            }
            .encode_to_vec(),
        )
        .unwrap();
    let resp = fandhe_container_cri::shim_v2::DeleteResponse::decode(&out_bytes[..]).unwrap();
    let (topic, any) = wait_call(&out, 3);
    assert_eq!(topic, "/tasks/delete");
    assert_eq!(any.type_url, "containerd.events.TaskDelete");
    assert_eq!(
        TaskDelete::decode(any.value.as_slice()).unwrap(),
        TaskDelete {
            container_id: "c1".into(),
            pid: resp.pid,
            exit_status: 3,
            exited_at: Some(Timestamp {
                seconds: 1_700_000_000,
                nanos: 5
            }),
            id: "c1".into(),
        }
    );
    assert_eq!(resp.exit_status, 3);

    // 作り直し: 新しい世代の Create・Start・終了だけが追加される。
    *fake.stopped.lock().unwrap() = None;
    svc.handle("Create", &create_req("c1", &bundle)).unwrap();
    svc.handle("Start", &start_req("c1")).unwrap();
    assert_eq!(wait_call(&out, 4).0, "/tasks/create");
    assert_eq!(wait_call(&out, 5).0, "/tasks/start");
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(count_calls(&out), 6, "still six");
    *fake.stopped.lock().unwrap() = Some((0, 1_700_000_001_000_000_000));
    let (topic, any) = wait_call(&out, 6);
    assert_eq!(topic, "/tasks/exit");
    let exit = TaskExit::decode(any.value.as_slice()).unwrap();
    assert_eq!((exit.pid, exit.exit_status), (4242, 0));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(count_calls(&out), 7);
    assert!(log.0.lock().unwrap().is_empty());
}
