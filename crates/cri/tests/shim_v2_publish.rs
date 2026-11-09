//! shim v2 の TaskCreate・TaskStart・TaskDelete・TaskExit の publish を、公開 API だけで本番の組み立て（`TaskService` + `exec_publisher_for_with` +
//! 検証済みの `PublishBinary`）を通して照合する結合試験（CRI-5・TASK-62.6・REPAIR-10・REPAIR-12・#4155・#4156）。
//!
//! exec は Exec → Start(exec_id) の TaskExecAdded・TaskExecStarted の順序と内容も照合する（#4281）。
//! 偽なのは実行層（`ContainerRuntime`）と publish バイナリ（`/bin/sh` の記録スクリプト）だけ。Start の後に終了を
//! 観測した watcher が、偽バイナリへ argv と `Any`（TaskExit）を渡し、イベントがちょうど 1 件であることを具体値で確かめる。
//! Delete 後に同じ ID で作り直した場合に、旧世代が旧 pid のイベントを送らないことも確かめる。
//! stdin 上の `Any` が 4096 バイトを超える TaskCreate（id 255 + bundle 4096 の最大値と、超える最小の組）の到達と、
//! 子が読まない場合の期限内の kill・回収も長い本文で照合する（#4291・#4223・REPAIR-12）。
#![cfg(unix)]

#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{
    ContainerId, ContainerRuntime, ContainerStatus, CreateRequest, DeleteRequest as RtDelete,
    DeleteResponse as RtDeleteResponse, ErrorCode, ExitTime, KillRequest, Signal,
    StartRequest as RtStart, StateRequest, StopRequest, TraitError,
};
use fandhe_container_cri::adapter::RuntimeAdapter;
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::shim_v2::bootstrap::{PublishBinary, ServeContext, ShimIdentifier};
use fandhe_container_cri::shim_v2::publish::{
    PublishConfig, PublishDrain, PublishFailure, PublishLog, TaskCreate, TaskDelete, TaskExecAdded,
    TaskExecStarted, TaskExit, TaskIo, TaskStart, exec_publisher_for_with,
};
use fandhe_container_cri::shim_v2::{
    Any, CreateTaskRequest, DeleteRequest, ExecId, ExecProcessRequest, ExecProcessSpec,
    ExecProcessStatus, ShutdownRequest, ShutdownSignal, StartRequest, TaskApiVersion,
    TaskExecLauncher, TaskExecProcess, TaskService, Timestamp, TtrpcService, WaitConfig,
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
struct CaptureLog(Mutex<Vec<PublishFailure>>, Mutex<Vec<PublishDrain>>);

impl PublishLog for CaptureLog {
    fn record(&self, failure: &PublishFailure) {
        self.0.lock().unwrap().push(failure.clone());
    }

    fn record_drain(&self, drain: &PublishDrain) {
        self.1.lock().unwrap().push(*drain);
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
            id: String::new(),
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

/// 排出の試験の共通の組み立て。偽バイナリは呼び出しごとに連番のディレクトリを作る（`first_sleep` が true なら 1 回目だけ 0.3 秒眠る。
/// `hang` が true なら pid を書いて 30 秒眠る）。返すのは (service, ctx, 記録先ディレクトリ, ログ, 偽バイナリが見る out)。
fn drain_setup(
    name: &str,
    first_sleep: bool,
    hang: bool,
    drain_timeout: Duration,
) -> (
    TaskService,
    ServeContext,
    ShutdownSignal,
    test_root::TestRoot,
    std::path::PathBuf,
    Arc<CaptureLog>,
) {
    let dir = test_root::test_root("pubit", name);
    let out = dir.join("out");
    std::fs::create_dir(&out).unwrap();
    let tail = if hang {
        "echo $$ > \"$d/pid\"\nexec /bin/sleep 30\n".to_owned()
    } else {
        format!(
            "{}printf '%s\\n' \"$@\" > \"$d/argv\"\n/bin/cat > \"$d/stdin.tmp\"\n/bin/mv \"$d/stdin.tmp\" \"$d/stdin\"\n",
            if first_sleep {
                "if [ \"$n\" = 0 ]; then /bin/sleep 0.3; fi\n"
            } else {
                ""
            }
        )
    };
    let body = format!(
        "#!/bin/sh\nn=$(( $(/bin/ls \"{o}\" | /usr/bin/wc -l) ))\nd=\"{o}/call$n\"\n/bin/mkdir \"$d\"\n{tail}",
        o = out.display()
    );
    let bin = make_script(&dir, &body);
    let log = Arc::new(CaptureLog::default());
    let signal = ShutdownSignal::new();
    let ctx = ServeContext::new(signal.clone(), None)
        .with_origin(
            Some(ShimIdentifier::parse("default").unwrap()),
            Some("/run/containerd/containerd.sock".into()),
        )
        .with_publish_binary(Some(PublishBinary::verify(&bin).unwrap()));
    let publisher = exec_publisher_for_with(
        &ctx,
        PublishConfig::new(Duration::from_secs(5))
            .unwrap()
            .with_drain_timeout(drain_timeout)
            .unwrap(),
        log.clone(),
    )
    .expect("publisher");
    let svc = TaskService::new(
        TaskApiVersion::V2,
        RuntimeAdapter::from_runtime(Shared(Arc::new(Fake::default()))),
    )
    .with_shutdown(signal.clone())
    .with_event_publisher(publisher);
    (svc, ctx, signal, dir, out, log)
}

/// Create → Delete の後に Shutdown を呼ぶ（最後の TaskDelete がキューに残る場面）。
fn create_delete_shutdown(svc: &TaskService, dir: &std::path::Path, signal: &ShutdownSignal) {
    let bundle = dir.join("bundle");
    std::fs::create_dir(&bundle).unwrap();
    let bundle = bundle.to_str().unwrap().to_owned();
    create_delete_shutdown_with(svc, "c1", &bundle, signal);
}

/// `create_delete_shutdown` の id・bundle 指定版。bundle は実在を確認されない（偽 runtime はパスに触れない）。
fn create_delete_shutdown_with(svc: &TaskService, id: &str, bundle: &str, signal: &ShutdownSignal) {
    svc.handle("Create", &create_req(id, bundle)).unwrap();
    svc.handle("Delete", &delete_req(id)).unwrap();
    svc.handle(
        "Shutdown",
        &ShutdownRequest {
            id: id.into(),
            now: false,
        }
        .encode_to_vec(),
    )
    .unwrap();
    assert!(signal.is_requested());
}

/// REPAIR-5・CRI-5・#4222: Shutdown の後の排出が、キューに残った TaskDelete を送り切ってから戻る。
/// 先行の TaskCreate が 0.3 秒眠るため、排出が無ければ TaskDelete は排出の呼び出しの時点で未送信。
/// TaskDelete の `id` は init では空（runc shim v2 と同じ）。
#[test]
fn repair5_4222_shutdown_drains_queued_task_delete() {
    let (svc, ctx, signal, dir, out, log) =
        drain_setup("drain-ok", true, false, Duration::from_secs(5));
    create_delete_shutdown(&svc, &dir, &signal);
    let drains = ctx.publisher_drains().drain_all();
    // wait_until を使わず、排出が戻った時点で 2 件とも届いていること。
    assert_eq!(count_calls(&out), 2);
    let any = Any::decode(std::fs::read(out.join("call1/stdin")).unwrap().as_slice()).unwrap();
    assert_eq!(any.type_url, "containerd.events.TaskDelete");
    assert_eq!(
        TaskDelete::decode(any.value.as_slice()).unwrap(),
        TaskDelete {
            container_id: "c1".into(),
            pid: 0,
            exit_status: 0,
            exited_at: None,
            id: String::new(),
        }
    );
    assert_eq!(drains.len(), 1);
    assert!(drains[0].queued >= 1, "{:?}", drains[0]);
    assert_eq!(drains[0].dropped, 0);
    assert!(!drains[0].deadline_hit && drains[0].worker_finished);
    assert_eq!(log.1.lock().unwrap().len(), 1);
    assert!(log.0.lock().unwrap().is_empty());
}

/// REPAIR-5・REPAIR-4・#4222: 子が止まったまま排出の期限を超えたら、実行中の子を kill して回収し、
/// 捨てた件数（実行中 1 + キュー 1）をログの 1 行に出す。期限を大きく超えて戻らない。
#[test]
fn repair5_4222_drain_deadline_drops_and_logs_exact_count() {
    let (svc, ctx, signal, dir, out, _log) =
        drain_setup("drain-deadline", false, true, Duration::from_millis(300));
    create_delete_shutdown(&svc, &dir, &signal);
    // 1 件目（TaskCreate）が子の起動で止まるのを待つ。
    assert!(wait_until(Duration::from_secs(10), || out
        .join("call0/pid")
        .exists()));
    let started = Instant::now();
    let drains = ctx.publisher_drains().drain_all();
    let took = started.elapsed();
    assert!(took < Duration::from_millis(2000), "{took:?}");
    assert_eq!(drains.len(), 1);
    let d = drains[0];
    assert!(d.deadline_hit, "{d:?}");
    assert!(d.worker_finished, "{d:?}");
    assert_eq!((d.queued, d.dropped), (2, 2), "{d:?}");
    let line = d.to_json_line();
    assert!(line.contains(r#""dropped":2"#), "{line}");
    assert!(line.contains(r#""outcome":"deadline""#), "{line}");
    for secret in ["/run/containerd", "default", "c1", "bundle"] {
        assert!(!line.contains(secret), "{line}");
    }
    assert_eq!(count_calls(&out), 1, "queued event must not start a child");
    #[cfg(target_os = "linux")]
    {
        let pid = std::fs::read_to_string(out.join("call0/pid")).unwrap();
        assert!(
            !std::path::Path::new(&format!("/proc/{}", pid.trim())).exists(),
            "child must be reaped"
        );
    }
}

/// 偽 publish バイナリ（`slow` の分だけ遅い）を通す本番の組み立てを作る。照会間隔は `poll`。
fn setup_4224(
    name: &str,
    slow: &str,
    poll: Duration,
) -> (
    TaskService,
    Arc<Fake>,
    std::path::PathBuf,
    String,
    Arc<CaptureLog>,
    test_root::TestRoot,
) {
    let dir = test_root::test_root("pubit", name);
    let out = dir.join("out");
    std::fs::create_dir(&out).unwrap();
    let body = format!(
        "#!/bin/sh\nn=$(( $(/bin/ls \"{o}\" | /usr/bin/wc -l) ))\nd=\"{o}/call$n\"\n/bin/mkdir \"$d\"\nprintf '%s\\n' \"$@\" > \"$d/argv\"\n/bin/cat > \"$d/stdin.tmp\"\n{slow}/bin/mv \"$d/stdin.tmp\" \"$d/stdin\"\n",
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
    .with_wait_config(WaitConfig::new(Duration::from_secs(30), poll).unwrap())
    .with_event_publisher(publisher);
    let bundle = dir.join("bundle");
    std::fs::create_dir(&bundle).unwrap();
    (
        svc,
        fake,
        out,
        bundle.to_str().unwrap().to_owned(),
        log,
        dir,
    )
}

fn wait_req(id: &str) -> Vec<u8> {
    fandhe_container_cri::shim_v2::WaitRequest {
        id: id.into(),
        exec_id: String::new(),
    }
    .encode_to_vec()
}

fn delete_req(id: &str) -> Vec<u8> {
    DeleteRequest {
        id: id.into(),
        exec_id: String::new(),
    }
    .encode_to_vec()
}

/// CRI-5・#4224: ctr 型（Wait の直後、watcher の照会間隔（5 秒）より短い間隔で Delete）でも、偽 publish バイナリが
/// TaskExit を TaskDelete より先にちょうど 1 件受け取る。
#[test]
fn cri5_4224_wait_then_delete_reaches_fake_binary_exit_then_delete() {
    let (svc, fake, out, bundle, log, _dir) = setup_4224("waitdel", "", Duration::from_secs(5));
    svc.handle("Create", &create_req("c1", &bundle)).unwrap();
    svc.handle("Start", &start_req("c1")).unwrap();
    assert_eq!(wait_call(&out, 0).0, "/tasks/create");
    assert_eq!(wait_call(&out, 1).0, "/tasks/start");
    // watcher の初回照会（running）を済ませる。次の照会は 5 秒後。
    std::thread::sleep(Duration::from_millis(300));
    *fake.stopped.lock().unwrap() = Some((3, 1_700_000_000_000_000_005));
    svc.handle("Wait", &wait_req("c1")).unwrap();
    svc.handle("Delete", &delete_req("c1")).unwrap();
    let (topic, any) = wait_call(&out, 2);
    assert_eq!(topic, "/tasks/exit");
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
    assert_eq!(wait_call(&out, 3).0, "/tasks/delete");
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(count_calls(&out), 4);
    assert!(log.0.lock().unwrap().is_empty());
}

/// CRI-5・#4224（残余 (3)）: watcher が TaskExit をキューへ入れた後（偽バイナリが遅く未送信）に Delete が走っても、
/// TaskExit は捨てられず TaskDelete より先に届く。
#[test]
fn cri5_4224_exit_queued_before_delete_is_not_dropped() {
    let (svc, fake, out, bundle, log, _dir) =
        setup_4224("queued", "/bin/sleep 0.4\n", Duration::from_millis(10));
    svc.handle("Create", &create_req("c1", &bundle)).unwrap();
    svc.handle("Start", &start_req("c1")).unwrap();
    // Create・Start の送信中（各 0.4 秒）に停止させ、watcher が Exit をキューへ入れるのを待ってから Delete する。
    *fake.stopped.lock().unwrap() = Some((3, 1_700_000_000_000_000_005));
    std::thread::sleep(Duration::from_millis(150));
    svc.handle("Delete", &delete_req("c1")).unwrap();
    let topics: Vec<String> = (0..4).map(|n| wait_call(&out, n).0).collect();
    assert_eq!(
        topics,
        [
            "/tasks/create",
            "/tasks/start",
            "/tasks/exit",
            "/tasks/delete"
        ]
    );
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(count_calls(&out), 4);
    assert!(log.0.lock().unwrap().is_empty());
}

/// 常に Running で pid 9001 の偽 exec プロセス。
struct ExecProc;

impl TaskExecProcess for ExecProc {
    fn pid(&self) -> Option<NonZeroU32> {
        NonZeroU32::new(9001)
    }
    fn status(&self) -> Result<ExecProcessStatus, CriError> {
        Ok(ExecProcessStatus::Running)
    }
    fn signal(&self, _: Signal) -> Result<(), CriError> {
        Ok(())
    }
}

/// 常に成功する偽の起動役。
struct ExecLauncher;

impl TaskExecLauncher for ExecLauncher {
    fn launch(
        &self,
        _: &ContainerId,
        _: &ExecId,
        _: &ExecProcessSpec,
    ) -> Result<Arc<dyn TaskExecProcess>, CriError> {
        Ok(Arc::new(ExecProc))
    }
}

/// CRI-5・#4281: 公開 API の Exec → Start(exec_id) が、偽 publish バイナリへ TaskExecAdded、TaskExecStarted の順に
/// ちょうど 1 件ずつ届く。Create・Start（init）の 2 件の後に続き、受信内容を具体値で照合する。
#[test]
fn cri5_4281_exec_events_reach_fake_binary_in_order() {
    let (svc, _fake, out, bundle, log, _dir) = setup_4224("execev", "", Duration::from_secs(5));
    let svc = svc.with_exec_launcher(Arc::new(ExecLauncher));
    svc.handle("Create", &create_req("c1", &bundle)).unwrap();
    svc.handle("Start", &start_req("c1")).unwrap();
    assert_eq!(wait_call(&out, 0).0, "/tasks/create");
    assert_eq!(wait_call(&out, 1).0, "/tasks/start");

    let exec = ExecProcessRequest {
        id: "c1".into(),
        exec_id: "e1".into(),
        spec: Some(Any {
            type_url: "types.containerd.io/opencontainers/runtime-spec/1/Process".into(),
            value: br#"{"cwd":"/","args":["/bin/true"]}"#.to_vec(),
        }),
        ..Default::default()
    }
    .encode_to_vec();
    svc.handle("Exec", &exec).unwrap();
    let (topic, any) = wait_call(&out, 2);
    assert_eq!(topic, "/tasks/exec-added");
    assert_eq!(any.type_url, "containerd.events.TaskExecAdded");
    assert_eq!(
        TaskExecAdded::decode(any.value.as_slice()).unwrap(),
        TaskExecAdded {
            container_id: "c1".into(),
            exec_id: "e1".into(),
        }
    );
    // Exec だけでは起動イベントは出ない。
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(count_calls(&out), 3);

    let start = StartRequest {
        id: "c1".into(),
        exec_id: "e1".into(),
    }
    .encode_to_vec();
    svc.handle("Start", &start).unwrap();
    let (topic, any) = wait_call(&out, 3);
    assert_eq!(topic, "/tasks/exec-started");
    assert_eq!(any.type_url, "containerd.events.TaskExecStarted");
    assert_eq!(
        TaskExecStarted::decode(any.value.as_slice()).unwrap(),
        TaskExecStarted {
            container_id: "c1".into(),
            exec_id: "e1".into(),
            pid: 9001,
        }
    );
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(count_calls(&out), 4, "exactly one event per step");
    assert!(log.0.lock().unwrap().is_empty());
}

/// 偽バイナリが受け取るはずの TaskCreate の `Any`（stdin 全体）。本体の定数とは独立に組み立てる。
fn expected_create_any(id: &str, bundle: &str) -> Vec<u8> {
    Any {
        type_url: "containerd.events.TaskCreate".into(),
        value: TaskCreate {
            container_id: id.into(),
            bundle: bundle.into(),
            rootfs: Vec::new(),
            io: Some(TaskIo::default()),
            checkpoint: String::new(),
            pid: 0,
        }
        .encode_to_vec(),
    }
    .encode_to_vec()
}

/// 長い bundle（`/` + `b` の繰り返し）。
fn long_bundle(len: usize) -> String {
    format!("/{}", "b".repeat(len - 1))
}

/// id `c1` で stdin 上の `Any` が 4096 バイトを超える最小の bundle 長を求める。
fn min_bundle_len_over_4096() -> usize {
    (1..=4096)
        .find(|&l| expected_create_any("c1", &long_bundle(l)).len() > 4096)
        .expect("4096 byte bundle exceeds 4096 byte Any")
}

/// CRI-5・REPAIR-12・#4291・#4223: stdin 上の `Any` が 4096 バイトを超える TaskCreate（id 255 + bundle 4096 の最大値と、
/// 4096 を超える最小の組）が、本番の組み立てを通って偽バイナリの stdin へ欠けずにバイト単位で一致して届く。
#[test]
fn cri5_4291_large_task_create_reaches_fake_binary_intact() {
    let min_len = min_bundle_len_over_4096();
    assert_eq!(min_len, 4055);
    assert!(expected_create_any("c1", &long_bundle(min_len - 1)).len() <= 4096);
    let (svc, _fake, out, _bundle, log, _dir) = setup_4224("long", "", Duration::from_secs(5));
    let max_id = "c".repeat(255);
    let max_bundle = long_bundle(4096);
    assert_eq!(max_bundle.len(), 4096);
    let min_bundle = long_bundle(min_len);
    let cases = [
        (max_id.as_str(), max_bundle.as_str(), 4392usize),
        ("c1", min_bundle.as_str(), 4097usize),
    ];
    for (id, bundle, _) in cases {
        svc.handle("Create", &create_req(id, bundle)).unwrap();
    }
    for (n, (id, bundle, want_len)) in cases.into_iter().enumerate() {
        assert_eq!(wait_call(&out, n).0, "/tasks/create");
        let raw = std::fs::read(out.join(format!("call{n}/stdin"))).unwrap();
        assert_eq!(raw.len(), want_len);
        assert!(raw.len() > 4096 && raw.len() <= 8192);
        assert_eq!(raw, expected_create_any(id, bundle));
        let any = Any::decode(raw.as_slice()).unwrap();
        let ev = TaskCreate::decode(any.value.as_slice()).unwrap();
        assert_eq!(ev.container_id, id);
        assert_eq!(ev.bundle, bundle);
        assert_eq!(ev.pid, 0);
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(count_calls(&out), 2);
    assert!(log.0.lock().unwrap().is_empty());
}

/// REPAIR-5・REPAIR-12・CRI-5・#4291・#4222: 子が読まないまま長い TaskCreate（id 255 + bundle 4096）を送っても、
/// 排出は期限内に戻り、子を kill して回収する。ログに id・bundle は出ない。
#[test]
fn repair5_4291_drain_deadline_reaps_non_reading_child_with_large_task_create() {
    let (svc, ctx, signal, _dir, out, _log) = drain_setup(
        "drain-deadline-long",
        false,
        true,
        Duration::from_millis(300),
    );
    let max_id = "c".repeat(255);
    create_delete_shutdown_with(&svc, &max_id, &long_bundle(4096), &signal);
    assert!(wait_until(Duration::from_secs(10), || out
        .join("call0/pid")
        .exists()));
    let started = Instant::now();
    let drains = ctx.publisher_drains().drain_all();
    let took = started.elapsed();
    assert!(took < Duration::from_millis(2000), "{took:?}");
    assert_eq!(drains.len(), 1);
    let d = drains[0];
    assert!(d.deadline_hit, "{d:?}");
    assert!(d.worker_finished, "{d:?}");
    assert_eq!((d.queued, d.dropped), (2, 2), "{d:?}");
    let line = d.to_json_line();
    assert!(line.contains(r#""dropped":2"#), "{line}");
    assert!(line.contains(r#""outcome":"deadline""#), "{line}");
    for secret in ["/run/containerd", "default", "ccccc", "bbbbb"] {
        assert!(!line.contains(secret), "{line}");
    }
    assert_eq!(count_calls(&out), 1, "queued event must not start a child");
    #[cfg(target_os = "linux")]
    {
        let pid = std::fs::read_to_string(out.join("call0/pid")).unwrap();
        assert!(
            !std::path::Path::new(&format!("/proc/{}", pid.trim())).exists(),
            "child must be reaped"
        );
    }
}
