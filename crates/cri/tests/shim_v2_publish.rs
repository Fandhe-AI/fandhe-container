//! shim v2 の TaskExit publish を、公開 API だけで本番の組み立て（`TaskService` + `exec_publisher_for_with` +
//! 検証済みの `PublishBinary`）を通して照合する結合試験（CRI-5・TASK-62.6・REPAIR-10・REPAIR-12・#4155）。
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
    PublishConfig, PublishFailure, PublishLog, TaskExit, exec_publisher_for_with,
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

/// CRI-5・#4155: Start 後の終了で、偽 publish バイナリが argv（`--address <a> publish --namespace default --topic /tasks/exit`）
/// と `Any`（TaskExit: pid 4242・exit_status 3・exited_at）をちょうど 1 回受け取る。
/// Delete 後の作り直しでは新しい終了だけが送られる。
#[test]
fn cri5_4155_task_exit_reaches_fake_publish_binary_once() {
    let dir = test_root::test_root("pubit", "once");
    // 呼び出しごとに連番のディレクトリへ argv と stdin を記録する。
    let out = dir.join("out");
    std::fs::create_dir(&out).unwrap();
    let body = format!(
        "#!/bin/sh\nn=$(/bin/ls \"{o}\" | /usr/bin/wc -l)\nd=\"{o}/call$n\"\n/bin/mkdir \"$d\"\nprintf '%s\\n' \"$@\" > \"$d/argv\"\n/bin/cat > \"$d/stdin.tmp\"\n/bin/mv \"$d/stdin.tmp\" \"$d/stdin\"\n",
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
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0, "running");

    *fake.stopped.lock().unwrap() = Some((3, 1_700_000_000_000_000_005));
    let stdin = out.join("call0").join("stdin");
    assert!(wait_until(Duration::from_secs(10), || stdin.exists()));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1, "exactly once");

    let argv = std::fs::read_to_string(out.join("call0").join("argv")).unwrap();
    assert_eq!(
        argv.lines().collect::<Vec<_>>(),
        vec![
            "--address",
            "/run/containerd/containerd.sock",
            "publish",
            "--namespace",
            "default",
            "--topic",
            "/tasks/exit"
        ]
    );
    let any = Any::decode(std::fs::read(&stdin).unwrap().as_slice()).unwrap();
    assert_eq!(any.type_url, "containerd.events.TaskExit");
    let exit = TaskExit::decode(any.value.as_slice()).unwrap();
    assert_eq!(
        exit,
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
    assert!(log.0.lock().unwrap().is_empty());

    // Delete して同じ ID で作り直し、再度 Start・終了すると、新しい終了が 1 件だけ追加される。
    svc.handle(
        "Delete",
        &DeleteRequest {
            id: "c1".into(),
            exec_id: String::new(),
        }
        .encode_to_vec(),
    )
    .unwrap();
    *fake.stopped.lock().unwrap() = None;
    svc.handle("Create", &create_req("c1", &bundle)).unwrap();
    svc.handle("Start", &start_req("c1")).unwrap();
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1, "still one");
    *fake.stopped.lock().unwrap() = Some((0, 1_700_000_001_000_000_000));
    let stdin1 = out.join("call1").join("stdin");
    assert!(wait_until(Duration::from_secs(10), || stdin1.exists()));
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 2);
    let any = Any::decode(std::fs::read(&stdin1).unwrap().as_slice()).unwrap();
    let exit = TaskExit::decode(any.value.as_slice()).unwrap();
    assert_eq!((exit.pid, exit.exit_status), (4242, 0));
    assert!(log.0.lock().unwrap().is_empty());
}
