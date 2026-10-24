//! `adapter`（TASK-114.2・#458・PLUG-1・CRI-2・CRI-7）の結合試験。3 OS で動く範囲だけを置く。
//!
//! 状態ストアを使う create → state → delete の流れは Linux・macOS で動く（macOS は main の
//! `platform-ci (macos-latest)` と `workflow_dispatch` で実行される。#2435）。

use std::sync::Arc;

#[cfg(target_os = "linux")]
use fandhe_container_core::traits::CleanupOutcome;
#[cfg(not(target_os = "linux"))]
use fandhe_container_core::traits::Signal;
use fandhe_container_core::traits::{
    AttachRequest, ContainerId, ContainerRuntime, ContainerStatus, CreateNetnsRequest,
    CreateNetworkRequest, DeleteNetworkRequest, DeleteRequest, DetachRequest, ErrorCode, IpCidr,
    KillRequest, NetworkName, NetworkPlugin, PublishPortRequest, StartRequest, StateRequest,
    StopRequest,
};
use fandhe_container_cri::adapter::{BundleProvider, BundleRequest};
use fandhe_container_cri::error::CriErrorCode;
use fandhe_container_cri::runtime::v1::{ContainerConfig, PodSandboxConfig};
#[cfg(not(target_os = "linux"))]
use fandhe_container_plugin_cri::adapter::MSG_LAUNCH_UNAVAILABLE;
use fandhe_container_plugin_cri::adapter::{
    CoreLifecycleRuntime, CriPluginBackends, MSG_BUNDLE_UNAVAILABLE, MSG_NETWORK_UNAVAILABLE,
    UnimplementedBundleProvider, UnimplementedNetwork,
};

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).expect("valid id")
}

/// 状態ストアに触れない runtime（注入の試験用）。state だけ固定値を返す。
struct Fake;

impl ContainerRuntime for Fake {
    fn create(
        &self,
        _r: &fandhe_container_core::traits::CreateRequest,
    ) -> Result<ContainerStatus, fandhe_container_core::traits::TraitError> {
        Ok(ContainerStatus::creating(cid("fake")))
    }
    fn start(
        &self,
        _r: &StartRequest,
    ) -> Result<ContainerStatus, fandhe_container_core::traits::TraitError> {
        Ok(ContainerStatus::creating(cid("fake")))
    }
    fn kill(
        &self,
        _r: &KillRequest,
    ) -> Result<ContainerStatus, fandhe_container_core::traits::TraitError> {
        Ok(ContainerStatus::creating(cid("fake")))
    }
    fn stop(
        &self,
        _r: &StopRequest,
    ) -> Result<ContainerStatus, fandhe_container_core::traits::TraitError> {
        Ok(ContainerStatus::creating(cid("fake")))
    }
    fn delete(
        &self,
        _r: &DeleteRequest,
    ) -> Result<
        fandhe_container_core::traits::DeleteResponse,
        fandhe_container_core::traits::TraitError,
    > {
        Ok(fandhe_container_core::traits::DeleteResponse::new())
    }
    fn state(
        &self,
        r: &StateRequest,
    ) -> Result<ContainerStatus, fandhe_container_core::traits::TraitError> {
        Ok(ContainerStatus::creating(r.id().clone()))
    }
}

/// 3 つのトレイトを注入して組め、注入した実装がそのまま呼ばれること（PLUG-1・CRI-7）。
#[test]
fn plug1_backends_hold_injected_trait_objects() {
    let state: Arc<dyn fandhe_container_core::traits::StateStore> = Arc::new(NoState);
    let backends = CriPluginBackends::new(Arc::new(Fake), state, Arc::new(UnimplementedNetwork));
    let got = backends
        .runtime()
        .state(&StateRequest::new(cid("c1")))
        .expect("fake state");
    assert_eq!(got.id().as_str(), "c1");
    let net = backends
        .network()
        .create_network(&CreateNetworkRequest::new(
            NetworkName::new("n1").expect("name"),
            IpCidr::new("10.0.0.0".parse().expect("ip"), 24).expect("cidr"),
        ))
        .expect_err("stub");
    assert_eq!(net.code(), ErrorCode::Unimplemented);
    // 組み立て（serve はしない）がパニックしないこと。
    let _svc = backends.runtime_service(Arc::new(UnimplementedBundleProvider));
}

/// 何も保持しない `StateStore`（全操作 Unimplemented）。
struct NoState;

impl fandhe_container_core::traits::StateStore for NoState {
    fn create(
        &self,
        _r: &fandhe_container_core::traits::CreateStateRequest,
    ) -> Result<fandhe_container_core::traits::StateRecord, fandhe_container_core::traits::TraitError>
    {
        Err(no_state())
    }
    fn get(
        &self,
        _r: &fandhe_container_core::traits::GetStateRequest,
    ) -> Result<fandhe_container_core::traits::StateRecord, fandhe_container_core::traits::TraitError>
    {
        Err(no_state())
    }
    fn update(
        &self,
        _r: &fandhe_container_core::traits::UpdateStateRequest,
    ) -> Result<fandhe_container_core::traits::StateRecord, fandhe_container_core::traits::TraitError>
    {
        Err(no_state())
    }
    fn delete(
        &self,
        _r: &fandhe_container_core::traits::DeleteStateRequest,
    ) -> Result<
        fandhe_container_core::traits::DeleteStateResponse,
        fandhe_container_core::traits::TraitError,
    > {
        Err(no_state())
    }
    fn list(
        &self,
        _r: &fandhe_container_core::traits::ListStateRequest,
    ) -> Result<fandhe_container_core::traits::StateList, fandhe_container_core::traits::TraitError>
    {
        Err(no_state())
    }
}

fn no_state() -> fandhe_container_core::traits::TraitError {
    fandhe_container_core::traits::TraitError::new(ErrorCode::Unimplemented, "unused")
}

/// start・kill・stop は固定文言の `Unimplemented`（REPAIR-3）。Linux は supervisor 経由で結線済みのため
/// 非 Linux だけで照合する（Linux 側は `tests/lifecycle_supervisor.rs`。#2434）。
#[cfg(not(target_os = "linux"))]
#[test]
fn cri2_start_kill_stop_unimplemented() {
    let rt = CoreLifecycleRuntime::new(Arc::new(NoState));
    let errs = [
        rt.start(&StartRequest::new(cid("c1"))).expect_err("start"),
        rt.kill(&KillRequest::new(cid("c1"), Signal::SIGTERM))
            .expect_err("kill"),
        rt.stop(&StopRequest::new(cid("c1"), std::time::Duration::from_secs(1)).expect("stop req"))
            .expect_err("stop"),
    ];
    for e in errs {
        assert_eq!(e.code(), ErrorCode::Unimplemented);
        assert_eq!(e.message(), MSG_LAUNCH_UNAVAILABLE);
    }
}

/// `UnimplementedNetwork` の全メソッドが固定文言の `Unimplemented`（CRI-7）。
#[test]
fn cri7_network_stub_unimplemented() {
    let n = UnimplementedNetwork;
    let name = NetworkName::new("n1").expect("name");
    let subnet = IpCidr::new("10.0.0.0".parse().expect("ip"), 24).expect("cidr");
    let errs = [
        n.create_network(&CreateNetworkRequest::new(name.clone(), subnet))
            .expect_err("create_network"),
        n.create_netns(&CreateNetnsRequest::new(name.clone(), cid("c1")))
            .expect_err("create_netns"),
        n.attach(&AttachRequest::new(name.clone(), cid("c1")))
            .expect_err("attach"),
        n.publish_port(&PublishPortRequest::new(
            name.clone(),
            cid("c1"),
            std::num::NonZeroU16::new(8080).expect("port"),
            std::num::NonZeroU16::new(80).expect("port"),
            fandhe_container_core::traits::Protocol::Tcp,
        ))
        .expect_err("publish_port"),
        n.detach(&DetachRequest::new(name.clone(), cid("c1")))
            .expect_err("detach"),
        n.delete_network(&DeleteNetworkRequest::new(name))
            .expect_err("delete_network"),
    ];
    for e in errs {
        let (code, msg) = (e.code(), e.message());
        assert_eq!(code, ErrorCode::Unimplemented);
        assert_eq!(msg, MSG_NETWORK_UNAVAILABLE);
    }
}

/// bundle 供給の stub: prepare は UNIMPLEMENTED、release は Ok（CRI-2）。
#[test]
fn cri2_bundle_provider_stub() {
    let p = UnimplementedBundleProvider;
    let (pod, ctr) = (PodSandboxConfig::default(), ContainerConfig::default());
    let e = p
        .prepare(&BundleRequest::new("c1", "s1", &pod, &ctr))
        .expect_err("prepare");
    assert_eq!(e.code(), CriErrorCode::Unimplemented);
    assert_eq!(e.message(), MSG_BUNDLE_UNAVAILABLE);
    p.release("c1").expect("release");
}

/// 非対応 OS では既定構成の組み立てが `Unimplemented` で fail-closed（CRI-2）。
#[cfg(not(target_os = "linux"))]
#[test]
fn cri2_production_unimplemented_off_linux() {
    let e = CriPluginBackends::production().expect_err("non-linux");
    assert_eq!(e.code(), ErrorCode::Unimplemented);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod store_backed {
    use std::path::PathBuf;

    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{ContainerState, CreateRequest};

    use super::*;

    fn tmp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fc-plugin-cri-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("tmp dir");
        // 状態ルートの祖先は group / other 書き込み不可でなければならない（umask に依存せず 0700 に固定）。
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        std::fs::canonicalize(&d).expect("canonicalize")
    }

    fn make_bundle(dir: &std::path::Path) -> PathBuf {
        let bundle = dir.join("bundle");
        std::fs::create_dir(&bundle).expect("bundle");
        std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
        std::fs::write(
            bundle.join("config.json"),
            r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
        )
        .expect("config");
        bundle
    }

    /// create → state → delete → state(NotFound) の流れ。重複 create は `AlreadyExists` で保たれる。
    #[test]
    fn cri2_core_runtime_create_state_delete() {
        let dir = tmp_dir("lifecycle");
        let bundle = make_bundle(&dir);
        let root = StateRoot::resolve(Some(dir.join("state"))).expect("root");
        let store: Arc<dyn fandhe_container_core::traits::StateStore> =
            Arc::new(FileStateStore::open(root).expect("open"));
        let rt = CoreLifecycleRuntime::new(store);

        let req = CreateRequest::new(cid("c1"), bundle.clone()).expect("req");
        let created = rt.create(&req).expect("create");
        assert_eq!(created.state(), ContainerState::Created);
        assert_eq!(created.pid(), None);

        let dup = rt.create(&req).expect_err("duplicate");
        assert_eq!(dup.code(), ErrorCode::AlreadyExists);

        let st = rt.state(&StateRequest::new(cid("c1"))).expect("state");
        assert_eq!(st.state(), ContainerState::Created);

        rt.delete(&DeleteRequest::new(cid("c1"))).expect("delete");
        let gone = rt.state(&StateRequest::new(cid("c1"))).expect_err("gone");
        assert_eq!(gone.code(), ErrorCode::NotFound);

        // 二重 delete も NotFound（core の契約）。
        let twice = rt
            .delete(&DeleteRequest::new(cid("c1")))
            .expect_err("second delete");
        assert_eq!(twice.code(), ErrorCode::NotFound);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- コンテナログの後始末（#2593・SUP-7・CRI-2・CLI-1）----
    // CLI の試験（crates/cli/tests/binary_entry.rs）の補助関数は別 crate から使えないため複製している。

    /// sink を開いて 1 行書き、flush する。再 open の競合は期限つきで再試行する（REPAIR-5）。
    #[cfg(target_os = "linux")]
    fn open_container_log_sink(
        root: &std::path::Path,
        name: &str,
    ) -> fandhe_container_supervisor::logs::RotatingFileSink {
        use fandhe_container_supervisor::logs::{
            LogSink as _, RotatingFileSink, StreamKind, container_log_dir,
            container_log_rotation_config,
        };
        use std::os::unix::fs::PermissionsExt as _;
        use std::time::{Duration, Instant};
        let dir = container_log_dir(root);
        std::fs::create_dir_all(&dir).expect("logdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let id = cid(name);
        let deadline = Instant::now() + Duration::from_secs(10);
        let sink = loop {
            match RotatingFileSink::open(&dir, &id, container_log_rotation_config()) {
                Ok(s) => break s,
                Err(e)
                    if e.code() == ErrorCode::FailedPrecondition && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("open sink: {e:?}"),
            }
        };
        sink.append(StreamKind::Stdout, format!("hello {name}").as_bytes())
            .expect("append");
        sink.flush().expect("flush");
        sink
    }

    #[cfg(target_os = "linux")]
    fn sorted_dir_names(dir: &std::path::Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .expect("dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[cfg(target_os = "linux")]
    fn log_runtime(
        dir: &std::path::Path,
    ) -> (
        CoreLifecycleRuntime,
        Arc<fandhe_container_core::observability::OpRecorder>,
        PathBuf,
    ) {
        use fandhe_container_core::observability::OpRecorder;
        let root = StateRoot::resolve(Some(dir.join("state"))).expect("root");
        let store: Arc<dyn fandhe_container_core::traits::StateStore> =
            Arc::new(FileStateStore::open(root).expect("open"));
        let state_root = store.host_state_root().expect("host root").to_path_buf();
        let recorder = Arc::new(OpRecorder::new());
        (
            CoreLifecycleRuntime::with_recorder(store, Arc::clone(&recorder)),
            recorder,
            state_root,
        )
    }

    /// 後始末の警告行を捕捉する出力先つきに差し替える（#2633）。
    #[cfg(target_os = "linux")]
    fn capture_cleanup_warnings(
        rt: CoreLifecycleRuntime,
    ) -> (CoreLifecycleRuntime, Arc<std::sync::Mutex<Vec<String>>>) {
        let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        let rt = rt.with_cleanup_warning_sink(Arc::new(move |line| {
            sink.lock().expect("lock").push(line);
        }));
        (rt, lines)
    }

    #[cfg(target_os = "linux")]
    fn log_remove_counts(
        recorder: &fandhe_container_core::observability::OpRecorder,
    ) -> Option<(u64, u64)> {
        use fandhe_container_core::observability::OpName;
        recorder
            .snapshot_op(&OpName::new("container_log_remove").expect("name"))
            .map(|s| (s.success(), s.failure()))
    }

    /// SUP-7・CRI-2・#2593: `delete` は対象 ID のコンテナログ（現在ログ・世代・ロック）だけを消し、他は残す。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup7_cri2_delete_removes_container_logs_only_for_target() {
        let dir = tmp_dir("ctrlog-target");
        let bundle = make_bundle(&dir);
        let (rt, recorder, root) = log_runtime(&dir);
        let (rt, warnings) = capture_cleanup_warnings(rt);
        for n in ["c1", "c2"] {
            rt.create(&CreateRequest::new(cid(n), bundle.clone()).expect("req"))
                .expect("create");
        }
        let logs = fandhe_container_supervisor::logs::container_log_dir(&root);
        drop(open_container_log_sink(&root, "c1"));
        drop(open_container_log_sink(&root, "c1"));
        drop(open_container_log_sink(&root, "c2"));
        assert_eq!(
            sorted_dir_names(&logs),
            ["c1.log", "c1.log.1", "c1.log.lock", "c2.log", "c2.log.lock"]
        );

        // 未 create の ID の delete は NotFound で、ログには触れない。
        let err = rt
            .delete(&DeleteRequest::new(cid("nope")))
            .expect_err("nope");
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(sorted_dir_names(&logs).len(), 5);

        let resp = rt.delete(&DeleteRequest::new(cid("c1"))).expect("delete");
        assert_eq!(resp.supervisor_log(), CleanupOutcome::Removed);
        assert_eq!(resp.container_log(), CleanupOutcome::Removed);
        assert_eq!(resp.image_rootfs(), CleanupOutcome::NotApplicable);
        assert!(warnings.lock().expect("lock").is_empty());
        assert_eq!(sorted_dir_names(&logs), ["c2.log", "c2.log.lock"]);
        assert_eq!(log_remove_counts(&recorder), Some((1, 0)));
        let st = rt.state(&StateRequest::new(cid("c2"))).expect("c2 state");
        assert_eq!(st.state(), ContainerState::Created);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SUP-7・CRI-2・#2593: sink が生きている間は `delete` は `Ok` のままログを残し、失敗を構造化エラーで観測できる。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup7_cri2_delete_keeps_logs_and_records_failure_when_sink_locked() {
        let dir = tmp_dir("ctrlog-locked");
        let bundle = make_bundle(&dir);
        let (rt, recorder, root) = log_runtime(&dir);
        let (rt, warnings) = capture_cleanup_warnings(rt);
        rt.create(&CreateRequest::new(cid("c1"), bundle).expect("req"))
            .expect("create");
        let logs = fandhe_container_supervisor::logs::container_log_dir(&root);
        let sink = open_container_log_sink(&root, "c1");

        let resp = rt.delete(&DeleteRequest::new(cid("c1"))).expect("delete");
        assert_eq!(
            resp.container_log(),
            CleanupOutcome::Kept {
                code: ErrorCode::FailedPrecondition
            }
        );
        let lines = warnings.lock().expect("lock").clone();
        assert_eq!(
            lines,
            vec![
                "{\"level\":\"warn\",\"event\":\"container_delete_cleanup\",\"id\":\"c1\",\"target\":\"container_log\",\"code\":\"FAILED_PRECONDITION\",\"message\":\"cleanup after delete left resources behind\"}"
                    .to_owned()
            ]
        );
        assert!(!lines[0].contains(dir.to_str().expect("utf8 path")));
        assert_eq!(sorted_dir_names(&logs), ["c1.log", "c1.log.lock"]);
        assert_eq!(log_remove_counts(&recorder), Some((0, 1)));
        let gone = rt.state(&StateRequest::new(cid("c1"))).expect_err("gone");
        assert_eq!(gone.code(), ErrorCode::NotFound);

        let err = rt.remove_container_log(&cid("c1")).expect_err("locked");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);

        drop(sink);
        rt.remove_container_log(&cid("c1")).expect("removed");
        assert!(sorted_dir_names(&logs).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SUP-7・CRI-2・#2593: 同じ ID が再作成されていたら（ガードが偽）ログを消さない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sup7_cri2_remove_container_log_skips_recreated_id() {
        let dir = tmp_dir("ctrlog-recreated");
        let bundle = make_bundle(&dir);
        let (rt, _recorder, root) = log_runtime(&dir);
        rt.create(&CreateRequest::new(cid("c1"), bundle.clone()).expect("req"))
            .expect("create");
        let logs = fandhe_container_supervisor::logs::container_log_dir(&root);
        drop(open_container_log_sink(&root, "c1"));

        // 状態が残っている（再作成された扱い）間は成功しても現在ログは残る（ロックだけは片付く）。
        rt.remove_container_log(&cid("c1")).expect("skipped");
        assert_eq!(sorted_dir_names(&logs), ["c1.log"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
