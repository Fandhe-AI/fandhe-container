//! `CreateContainer` の前の残りログ回収・起動オプション文書の掃除・plugin 起動時のログ走査の結合試験
//! （#2760・CRI-2・SUP-7・SUP-12・REPAIR-4）。
//!
//! 状態ルート（一時ディレクトリ）の実ファイルに対して `CoreLifecycleRuntime` を動かす。root 不要。Linux 限定
//! （起動オプション文書は Linux のみ。ログの sink は unix）。

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::{OpName, OpRecorder};
use fandhe_container_core::state_store::{FileStateStore, StateRoot};
use fandhe_container_core::traits::{
    ContainerId, ContainerRuntime, CreateRequest, DeleteRequest, ErrorCode, StateStore,
};
use fandhe_container_plugin_cri::adapter::{
    CoreLifecycleRuntime, sweep_leftover_container_logs, sweep_summary_line,
};
use fandhe_container_supervisor::container_options::document::ContainerOptionsDocument;
use fandhe_container_supervisor::container_options::store as options_store;
use fandhe_container_supervisor::logs::{
    LogSink as _, RotatingFileSink, StreamKind, container_log_dir, container_log_rotation_config,
};

fn cid(s: &str) -> ContainerId {
    ContainerId::new(s).expect("id")
}

fn tmp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("fc-cri-stale-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("tmp dir");
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    std::fs::canonicalize(&d).expect("canonicalize")
}

fn make_bundle(dir: &Path) -> PathBuf {
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

fn open_store(dir: &Path) -> (Arc<dyn StateStore>, PathBuf) {
    let root = StateRoot::resolve(Some(dir.join("state"))).expect("root");
    let store: Arc<dyn StateStore> = Arc::new(FileStateStore::open(root).expect("open"));
    let root = store.host_state_root().expect("host root").to_path_buf();
    (store, root)
}

fn runtime(store: &Arc<dyn StateStore>) -> (CoreLifecycleRuntime, Arc<OpRecorder>) {
    let recorder = Arc::new(OpRecorder::new());
    (
        CoreLifecycleRuntime::with_recorder(Arc::clone(store), Arc::clone(&recorder))
            .with_container_log_lock_wait(Duration::from_millis(200)),
        recorder,
    )
}

/// sink を開いて 1 行書く。再 open の競合は期限つきで再試行する（REPAIR-5）。
fn open_sink(root: &Path, name: &str) -> RotatingFileSink {
    let dir = container_log_dir(root);
    std::fs::create_dir_all(&dir).expect("logdir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    let deadline = Instant::now() + Duration::from_secs(10);
    let sink = loop {
        match RotatingFileSink::open(&dir, &cid(name), container_log_rotation_config()) {
            Ok(s) => break s,
            Err(e) if e.code() == ErrorCode::FailedPrecondition && Instant::now() < deadline => {
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

fn names(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn counts(recorder: &OpRecorder, name: &str) -> Option<(u64, u64)> {
    recorder
        .snapshot_op(&OpName::new(name).expect("name"))
        .map(|s| (s.success(), s.failure()))
}

/// 起動オプション文書（作成世代つき）を置き、置いた文書のバイト列を返す。
fn put_options_document(root: &Path, name: &str) -> Vec<u8> {
    let doc = ContainerOptionsDocument::new(
        vec!["nofile=1024:2048".into()],
        vec!["A=1".into()],
        None,
        None,
        vec![],
    )
    .expect("doc")
    .with_generation("g1".to_owned())
    .expect("gen");
    options_store::write_new(root, &cid(name), &doc).expect("write doc");
    std::fs::read(options_store::options_path(root, &cid(name))).expect("read doc")
}

/// CRI-2・SUP-7・#2760: `create` は core を呼ぶ前に、同じ ID の閉じた残りログだけを消し、他の ID は残す。
#[test]
fn sup7_cri2_create_reclaims_leftover_logs_before_core() {
    let dir = tmp_dir("create-reclaim");
    let bundle = make_bundle(&dir);
    let (store, root) = open_store(&dir);
    let (rt, recorder) = runtime(&store);
    let logs = container_log_dir(&root);
    drop(open_sink(&root, "c1"));
    drop(open_sink(&root, "c1"));
    drop(open_sink(&root, "c2"));
    assert_eq!(
        names(&logs),
        ["c1.log", "c1.log.1", "c1.log.lock", "c2.log", "c2.log.lock"]
    );
    rt.create(&CreateRequest::new(cid("c1"), bundle).expect("req"))
        .expect("create");
    assert_eq!(names(&logs), ["c2.log", "c2.log.lock"]);
    assert_eq!(counts(&recorder, "container_log_reclaim"), Some((1, 0)));
    let _ = std::fs::remove_dir_all(&dir);
}

/// CRI-2・SUP-7・#2760: 古い sink が生きている（ロック保持）間はログに触れず、失敗を 1 件計上して create は続ける。
#[test]
fn sup7_cri2_create_keeps_logs_of_live_sink() {
    let dir = tmp_dir("create-live");
    let bundle = make_bundle(&dir);
    let (store, root) = open_store(&dir);
    let (rt, recorder) = runtime(&store);
    let logs = container_log_dir(&root);
    let sink = open_sink(&root, "c1");
    rt.create(&CreateRequest::new(cid("c1"), bundle).expect("req"))
        .expect("create");
    assert_eq!(names(&logs), ["c1.log", "c1.log.lock"]);
    assert_eq!(counts(&recorder, "container_log_reclaim"), Some((0, 1)));
    drop(sink);
    let _ = std::fs::remove_dir_all(&dir);
}

/// SUP-7・CRI-2・#2760: 状態が既にある ID（重複 create）のログは消さない。create は `AlreadyExists` のまま。
#[test]
fn sup7_cri2_create_keeps_logs_when_state_present() {
    let dir = tmp_dir("create-present");
    let bundle = make_bundle(&dir);
    let (store, root) = open_store(&dir);
    let (rt, recorder) = runtime(&store);
    let req = CreateRequest::new(cid("c1"), bundle).expect("req");
    rt.create(&req).expect("create");
    drop(open_sink(&root, "c1"));
    let dup = rt.create(&req).expect_err("duplicate");
    assert_eq!(dup.code(), ErrorCode::AlreadyExists);
    assert_eq!(names(&container_log_dir(&root)), ["c1.log"]);
    assert_eq!(counts(&recorder, "container_log_reclaim"), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// SUP-12・CRI-2・#2760: 状態の記録が無い ID の起動オプション文書（残骸）は `create` の前に消え、ロックファイルも残らない。
#[test]
fn sup12_cri2_create_removes_stale_options_document() {
    let dir = tmp_dir("create-options");
    let bundle = make_bundle(&dir);
    let (store, root) = open_store(&dir);
    let (rt, recorder) = runtime(&store);
    put_options_document(&root, "c1");
    assert!(options_store::options_path(&root, &cid("c1")).exists());
    rt.create(&CreateRequest::new(cid("c1"), bundle).expect("req"))
        .expect("create");
    assert!(!options_store::options_path(&root, &cid("c1")).exists());
    assert!(
        !options_store::options_dir(&root)
            .join(options_store::LOCKS_DIR_NAME)
            .join("c1")
            .exists()
    );
    assert_eq!(counts(&recorder, "container_options_remove"), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// SUP-12・CRI-2・#2760: 状態の記録がある ID の文書は消さない（重複 create は `AlreadyExists` で、文書のバイト列は不変）。
#[test]
fn sup12_cri2_create_keeps_options_document_when_state_present() {
    let dir = tmp_dir("create-options-keep");
    let bundle = make_bundle(&dir);
    let (store, root) = open_store(&dir);
    let (rt, _recorder) = runtime(&store);
    let req = CreateRequest::new(cid("c1"), bundle).expect("req");
    rt.create(&req).expect("create");
    let before = put_options_document(&root, "c1");
    let dup = rt.create(&req).expect_err("duplicate");
    assert_eq!(dup.code(), ErrorCode::AlreadyExists);
    assert_eq!(
        std::fs::read(options_store::options_path(&root, &cid("c1"))).expect("kept"),
        before
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// SUP-12・CRI-2・#2760: core の `delete` が成功した後、記録の無くなった ID の文書を消す。他の ID の文書は残る。
#[test]
fn sup12_cri2_delete_removes_options_document_after_core_delete() {
    let dir = tmp_dir("delete-options");
    let bundle = make_bundle(&dir);
    let (store, root) = open_store(&dir);
    let warnings = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&warnings);
    let (rt, _recorder) = runtime(&store);
    let rt = rt.with_cleanup_warning_sink(Arc::new(move |line| {
        sink.lock().expect("lock").push(line);
    }));
    for n in ["c1", "c2"] {
        rt.create(&CreateRequest::new(cid(n), bundle.clone()).expect("req"))
            .expect("create");
    }
    put_options_document(&root, "c1");
    let other = put_options_document(&root, "c2");
    rt.delete(&DeleteRequest::new(cid("c1"))).expect("delete");
    assert!(!options_store::options_path(&root, &cid("c1")).exists());
    assert_eq!(
        std::fs::read(options_store::options_path(&root, &cid("c2"))).expect("c2 kept"),
        other
    );
    assert!(warnings.lock().expect("lock").is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// CRI-2・SUP-7・REPAIR-4・#2760: 起動時の走査は、閉じた残り・生きている sink・状態がある ID・帰属できない名前を区別し、
/// 消すのは閉じた残りだけ。要約の行も具体値で一致する（パス・ID を含まない）。
#[test]
fn sup7_cri2_startup_sweep_removes_only_closed_unrecorded_logs() {
    let dir = tmp_dir("startup-sweep");
    let bundle = make_bundle(&dir);
    let (store, root) = open_store(&dir);
    let (rt, _) = runtime(&store);
    rt.create(&CreateRequest::new(cid("present1"), bundle).expect("req"))
        .expect("create");
    drop(open_sink(&root, "present1"));
    drop(open_sink(&root, "closed1"));
    let _live = open_sink(&root, "live1");
    let logs = container_log_dir(&root);
    std::fs::write(logs.join("Foo.log"), b"x").expect("foo");

    let recorder = OpRecorder::new();
    let report =
        sweep_leftover_container_logs(&store, &recorder, Duration::from_secs(30)).expect("report");
    assert_eq!(report.reclaimed_ids, 1);
    assert_eq!(report.removed_files, 1);
    assert_eq!(report.skipped_live, 1);
    assert_eq!(report.skipped_present, 1);
    assert_eq!(report.skipped_undecodable, 1);
    assert_eq!(
        sweep_summary_line(&report),
        format!(
            "{{\"level\":\"info\",\"event\":\"container_log_sweep\",\"scanned\":{},\"reclaimed_ids\":1,\"removed_files\":1,\"skipped_live\":1,\"skipped_present\":1,\"skipped_undecodable\":1,\"failed\":0,\"timed_out\":false,\"workers_busy\":false}}",
            report.scanned
        )
    );
    assert_eq!(
        names(&logs),
        ["Foo.log", "live1.log", "live1.log.lock", "present1.log"]
    );
    assert_eq!(counts(&recorder, "container_log_reclaim"), Some((1, 0)));
    let _ = std::fs::remove_dir_all(&dir);
}
