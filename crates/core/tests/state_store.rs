//! ファイルベース `StateStore` を OCI ライフサイクル操作越しに使う結合試験（TASK-31.3・OCI-5・REPAIR-12）。
//!
//! 実 `FileStateStore` へ `oci_runtime::{create, start, delete}` を通し、各段階で `state.json` の
//! 内容（JSON 全体）・存在有無・権限・一時ファイル残骸の有無がどう変わるかをディスク上で照合する。
//!
//! 他の試験との分担: `state_store_integration.rs` は別プロセス共有・排他・再 open 後の永続性・破損回復
//! （トレイト直呼び）、`state_store_crash.rs` は書き込み途中のクラッシュ残骸、`oci_lifecycle.rs` は
//! インメモリ `StateStore` での一連フローを扱う。本ファイルはそのいずれも見ていない
//! 「ライフサイクル操作 × ファイル実体」を扱う。
//!
//! `FileStateStore` は Linux 限定で、他 OS の `open` が `Unimplemented` で fail-closed となることは
//! `state_store_integration.rs::oci5_open_is_unimplemented_outside_linux` が照合済みのため、本ファイルの
//! 試験は `linux` モジュールにのみ置く。launcher は模擬で実プロセスの exec は行わない（本番の
//! `ProcessLauncher` は後続タスクで提供される。実装済みを装わない。REPAIR-3）。Stopped への遷移は
//! supervisor（TASK-157）の責務のため `StateStore::update` で代替する。root 不要で既定のテスト集合で動く。

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::num::NonZeroU32;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::Duration;

    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, StartTimeouts, create, delete,
        start,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateRequest, DeleteRequest, DeleteResponse, ErrorCode,
        GetStateRequest, ListStateRequest, StartRequest, StateStore, TraitError,
        UpdateStateRequest,
    };
    use serde_json::{Value, json};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// テストごとに一意な作業ディレクトリ（0700。drop で削除）。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir()
                .join(format!("fandhe-state-lc-{tag}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("create tmp dir");
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
            Self(dir)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// `rootfs/` と `config.json` を持つ bundle（start の `BundleLock` はディレクトリ単位のため一意にする）。
    struct Bundle(PathBuf);

    impl Bundle {
        fn ready(tag: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let dir = std::env::temp_dir().join(format!(
                "fandhe-state-lc-bundle-{tag}-{}-{n}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("rootfs")).expect("create bundle");
            fs::write(
                dir.join("config.json"),
                serde_json::to_vec(&lifecycle_config()).expect("serialize"),
            )
            .expect("write config");
            Self(dir)
        }

        fn create_request(&self, id: &str) -> CreateRequest {
            CreateRequest::new(cid(id), self.0.clone()).expect("absolute bundle")
        }
    }

    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// start の fail-closed 検査に当たらない起動可能な最小 config。
    fn lifecycle_config() -> Value {
        json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "process": {
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/echo", "state-lifecycle"],
                "env": ["PATH=/usr/bin:/bin"],
                "cwd": "/"
            },
            "hostname": "state-lifecycle",
            "linux": {"namespaces": [
                {"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"}, {"type": "ipc"}
            ]}
        })
    }

    /// 固定 pid 101 を返す模擬プロセス（terminate 後の wait は SIGKILL 相当）。
    struct FakeProcess {
        terminated: AtomicBool,
    }

    impl LaunchedProcess for FakeProcess {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(101).expect("nonzero")
        }

        fn wait(&self, _timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
            if self.terminated.load(Ordering::SeqCst) {
                Ok(Some(ProcessExit::Signaled(9)))
            } else {
                Ok(None)
            }
        }

        fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
            self.terminated.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    /// 実 exec を行わない模擬 launcher。
    struct FakeLauncher;

    impl ProcessLauncher for FakeLauncher {
        fn launch(
            &self,
            _spec: &LaunchSpec,
            _timeout: Duration,
        ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            Ok(Box::new(FakeProcess {
                terminated: AtomicBool::new(false),
            }))
        }

        fn confirm_no_process(
            &self,
            _id: &ContainerId,
            _timeout: Duration,
        ) -> Result<(), TraitError> {
            Ok(())
        }
    }

    fn cid(id: &str) -> ContainerId {
        ContainerId::new(id).expect("container id")
    }

    fn state_json_path(root: &Path, id: &str) -> PathBuf {
        root.join(id).join("state.json")
    }

    fn read_state_json(root: &Path, id: &str) -> Value {
        let bytes = fs::read(state_json_path(root, id)).expect("read state.json");
        serde_json::from_slice(&bytes).expect("parse state.json")
    }

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// `<id>/` が `state.json` だけを持ち（一時ファイル残骸なし）、権限が 0700 / 0600 であること。
    fn assert_record_layout(root: &Path, id: &str) {
        assert_eq!(entries(&root.join(id)), ["state.json"]);
        assert_eq!(mode_of(&root.join(id)), 0o700);
        assert_eq!(mode_of(&state_json_path(root, id)), 0o600);
    }

    fn assert_gone(root: &Path, id: &str) {
        let err = fs::symlink_metadata(state_json_path(root, id)).expect_err("state.json gone");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        let err = fs::symlink_metadata(root.join(id)).expect_err("id dir gone");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    /// OCI-5・TASK-31.3: create → start → delete の各段階で `state.json` の内容・存在・権限が期待どおり。
    #[test]
    fn oci5_state_json_tracks_create_start_delete() {
        let tmp = TmpDir::new("full");
        let root = tmp.0.as_path();
        let bundle = Bundle::ready("full");
        let bundle_str = bundle.0.to_str().expect("utf-8 bundle path").to_string();
        let store =
            FileStateStore::open(StateRoot::from_override(root.to_path_buf()).expect("root"))
                .expect("open");
        let dyn_store: &dyn StateStore = &store;
        let rec = OpRecorder::new();
        let id = "lc-file";
        let launcher: Arc<dyn ProcessLauncher> = Arc::new(FakeLauncher);

        // 0. create 前は <id>/ が存在しない。
        assert_gone(root, id);

        // 1. create 直後: created・pid / exitCode なし・revision 0（FileStateStore の初回採番）。
        let created = create(dyn_store, &rec, &bundle.create_request(id)).expect("create");
        assert_eq!(created.revision().value(), 0);
        assert_eq!(
            read_state_json(root, id),
            json!({
                "ociVersion": "1.2.0",
                "id": id,
                "status": "created",
                "bundle": bundle_str,
                "revision": 0
            })
        );
        assert_record_layout(root, id);

        // 2. start 後: running・pid 101・revision 2（予約 update と Running 記録 update の 2 回）。
        let started = start(
            dyn_store,
            &rec,
            &launcher,
            &StartRequest::new(cid(id)),
            &StartTimeouts::default(),
        )
        .expect("start");
        let running_json = json!({
            "ociVersion": "1.2.0",
            "id": id,
            "status": "running",
            "pid": 101,
            "bundle": bundle_str,
            "revision": 2
        });
        assert_eq!(read_state_json(root, id), running_json);
        assert_record_layout(root, id);
        assert_eq!(started.record().revision().value(), 2);
        assert_eq!(
            &store.get(&GetStateRequest::new(cid(id))).expect("get"),
            started.record()
        );

        // 2a. Running 中の delete は拒否され、state.json のバイト列は変わらない。
        let before = fs::read(state_json_path(root, id)).expect("read");
        let err = delete(dyn_store, &rec, &DeleteRequest::new(cid(id)))
            .expect_err("delete while running");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "container is still running");
        assert_eq!(fs::read(state_json_path(root, id)).expect("read"), before);
        assert_record_layout(root, id);

        // ハンドルを回収する（CORE-1）。
        let (running, process) = started.into_parts();
        process
            .terminate(Duration::from_secs(1))
            .expect("terminate");

        // 3. Stopped 記録（supervisor の代わり）: exitCode 137・pid なし・revision 3。
        let stopped = store
            .update(&UpdateStateRequest::new(
                ContainerStatus::stopped(cid(id), Some(137)),
                running.revision(),
            ))
            .expect("stopped");
        assert_eq!(stopped.revision().value(), 3);
        assert_eq!(
            read_state_json(root, id),
            json!({
                "ociVersion": "1.2.0",
                "id": id,
                "status": "stopped",
                "bundle": bundle_str,
                "revision": 3,
                "exitCode": 137
            })
        );
        assert_record_layout(root, id);

        // 4. delete 後: state.json も <id>/ も消え、状態ルート直下はストア管理ファイルだけ。
        assert_eq!(
            delete(dyn_store, &rec, &DeleteRequest::new(cid(id))).expect("delete"),
            DeleteResponse::new()
        );
        assert_gone(root, id);
        assert_eq!(entries(root), ["@lock", "@revision"]);
        assert_eq!(
            store
                .get(&GetStateRequest::new(cid(id)))
                .expect_err("get after delete")
                .code(),
            ErrorCode::NotFound
        );
        let page =
            ListStateRequest::new(NonZeroU32::new(10).expect("nonzero")).expect("list request");
        assert_eq!(store.list(&page).expect("list").records().len(), 0);
        assert_eq!(
            delete(dyn_store, &rec, &DeleteRequest::new(cid(id)))
                .expect_err("second delete")
                .code(),
            ErrorCode::NotFound
        );

        // 5. 同 ID の再作成は削除済みの revision（0〜3）を再発行しない。
        let recreated = create(dyn_store, &rec, &bundle.create_request(id)).expect("recreate");
        assert_eq!(recreated.revision().value(), 4);
        assert_eq!(
            read_state_json(root, id),
            json!({
                "ociVersion": "1.2.0",
                "id": id,
                "status": "created",
                "bundle": bundle_str,
                "revision": 4
            })
        );
        assert_record_layout(root, id);
    }
}
