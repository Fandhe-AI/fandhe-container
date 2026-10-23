//! plugin-cri の `CoreLifecycleRuntime::create` の `mounts[].destination` 拒否が、中継 sink（`ControlAuditRelay`）を
//! 通って監査の記録先 `<状態ルート>/@audit.log` へ届くことの結合試験（SEC-4・OCI-4・CRI-7・REPAIR-12・#2594）。
//!
//! 背景: plugin-cri は `spawn_blocking` 等でプロセスが常に複数スレッドになり、`FileAuditSink` の fork 隔離が使えない。
//! 本番 `main.rs` は単一スレッドの間に fork した relay を `CriPluginBackends::production_with_audit_sink` で create の
//! 記録先に渡す。本試験は同じ順序（relay を fork → 別スレッドから `ContainerRuntime::create`）で、遡り・`/`・相対 `..` の
//! 3 つの destination が拒否され、`@audit.log` に mount 層・`path` なし・コンテナ ID つきで 1 件ずつ残ることを具体値で照合する。
//!
//! `ControlAuditRelay::spawn` は単一スレッドの呼び出し元を要求するため `harness = false` の単一スレッド `main` で動かす。
//! root 不要で既定のテスト集合で動く。待ちはすべて期限つき（REPAIR-5）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("create_destination_audit_relay: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{
        AuditSink, ControlAuditRelay, FileAuditSink, RECORD_WAIT_LIMIT,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerRuntime, CreateRequest, ErrorCode, GetStateRequest, StateStore,
    };
    use fandhe_container_plugin_cri::adapter::CoreLifecycleRuntime;

    /// 遡り・rootfs 全体・相対 `..`（core の `create_mount_audit_delivery` と同じ 3 ケース）。
    const DESTINATIONS: [&str; 3] = ["/../..", "/", "run/../../.."];
    const POLL_MARGIN: Duration = Duration::from_secs(5);

    fn config(dest: &str) -> String {
        format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs"}},
"process":{{"user":{{"uid":0,"gid":0}},"args":["/bin/echo","it"],"cwd":"/"}},
"mounts":[{{"destination":{dest:?},"type":"bind","source":"/srv/x","options":["rbind","rw"]}}]}}"#
        )
    }

    fn private_dir(path: &Path) {
        std::fs::create_dir_all(path).expect("create dir");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }

    /// `@audit.log` を期限つきでポーリングし、`want` 行そろったら（または期限で）返す。
    fn wait_for_audit_lines(root: &Path, want: usize) -> Vec<String> {
        let log = root.join("@audit.log");
        let deadline = Instant::now() + RECORD_WAIT_LIMIT + POLL_MARGIN;
        loop {
            let lines: Vec<String> = std::fs::read_to_string(&log)
                .map(|t| t.lines().map(str::to_owned).collect())
                .unwrap_or_default();
            if lines.len() >= want || Instant::now() >= deadline {
                return lines;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn run() {
        let base: PathBuf =
            std::env::temp_dir().join(format!("fandhe-cri-2594-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        private_dir(&base);
        let root = base.join("state");
        private_dir(&root);

        // 本番 main.rs と同じ順序: スレッドを作る前に relay を fork し、記録先を確かめる。
        let store = FileStateStore::open(StateRoot::resolve(Some(root.clone())).expect("root"))
            .expect("open the state store");
        let relay = ControlAuditRelay::spawn(FileAuditSink::in_state_store(&store))
            .unwrap_or_else(|e| panic!("spawn the audit relay: {e}"));
        relay
            .probe()
            .unwrap_or_else(|e| panic!("probe the audit log: {e}"));
        let relay: Arc<dyn AuditSink> = Arc::new(relay);
        let store: Arc<dyn StateStore> = Arc::new(store);
        let runtime = Arc::new(
            CoreLifecycleRuntime::new(Arc::clone(&store))
                .with_create_audit_sink(Arc::clone(&relay)),
        );

        for (i, dest) in DESTINATIONS.into_iter().enumerate() {
            let bundle = base.join(format!("bundle-{i}"));
            std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
            std::fs::write(bundle.join("config.json"), config(dest)).expect("config");
            let id = ContainerId::new(format!("c{i}")).expect("container id");
            let req = CreateRequest::new(id.clone(), bundle).expect("absolute bundle");
            // 本番と同じく別スレッド（複数スレッドのプロセス）から呼ぶ。
            let rt = Arc::clone(&runtime);
            let err = std::thread::spawn(move || rt.create(&req))
                .join()
                .expect("create thread")
                .expect_err("destination must be rejected");
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{dest}");
            assert_eq!(
                store.get(&GetStateRequest::new(id)).unwrap_err().code(),
                ErrorCode::NotFound,
                "no state may remain for {dest}"
            );
        }

        let lines = wait_for_audit_lines(&root, DESTINATIONS.len());
        assert_eq!(lines.len(), DESTINATIONS.len(), "audit lines: {lines:?}");
        let pid = format!(r#""pid":{}"#, std::process::id());
        for (i, line) in lines.iter().enumerate() {
            assert!(line.contains(r#""layer":"mount""#), "{line}");
            assert!(line.contains(r#""path":null"#), "{line}");
            assert!(
                line.contains(&format!(r#""container_id":"c{i}""#)),
                "{line}"
            );
            assert!(line.contains(&pid), "{line}");
            assert!(!line.contains(r#""reason""#), "{line}");
        }

        drop(runtime);
        drop(relay);
        let _ = std::fs::remove_dir_all(&base);
        println!(
            "create_destination_audit_relay: {} destination rejections reached @audit.log",
            DESTINATIONS.len()
        );
    }
}
