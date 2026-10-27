//! start の rootfs 固定（`RootfsDir::pin`）の検証後の差し替えの違反が、中継 sink（`ControlAuditRelay`）を通って
//! 監査の記録先 `<状態ルート>/@audit.log` へ届くことの結合試験（SEC-4・SEC-1・SUP-1・#2623・REPAIR-12）。
//!
//! 背景: `claim_start` は作業スレッド `supervisor-start` で走り、プロセスは複数スレッドになる。`FileAuditSink` は
//! 複数スレッドだと主経路を試せないため、本番の入口は単一スレッドの間に fork した relay を launcher の
//! `rejection_audit_sink` へ渡す。relay は理由つきの `Mount` を閉じた表（`MOUNT_REASONS`）の添字で運ぶ。
//! 本試験は同じ順序（relay を fork → 別スレッドで start の前半を実行）で、検証後に rootfs を symlink への差し替え・
//! 削除した 2 シナリオが、層 `mount`・パスなし・理由コードつきで 1 件ずつ `@audit.log` に残ることを照合する。
//!
//! `run_start` は差し替えの closure を通せないため、試験専用の入口 `claim_start_with_pin_swap_for_test`
//! （`exec-test-support`）を作業スレッドから直接呼ぶ。本番の結線（`with_rejection_audit_sink`）は
//! `start_entry` のソース構造の試験が固定する。
//!
//! `ControlAuditRelay::spawn` は単一スレッドの呼び出し元を要求するため、`harness = false` の単一スレッド `main`
//! で動かす（`start_bind_audit_relay` と同じ）。root 不要で既定のテスト集合で動く。待ちはすべて期限つき（REPAIR-5）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("start_rootfs_pin_audit_relay: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    linux::run();
}

// 一時領域の親を tmpfiles の flock 走査から守る共有部品（#3026・CORE-5・REPAIR-12）。
#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditSink, ControlAuditRelay};
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        LaunchMode, LaunchSpec, LaunchedProcess, ProcessLauncher,
        claim_start_with_pin_swap_for_test, create,
    };
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, ErrorCode, GetStateRequest, StartRequest,
        StateStore, TraitError,
    };
    use fandhe_container_supervisor::exec::default_audit_sink;
    use fandhe_container_supervisor::state::open_default_store;

    /// 作業スレッドの完了を待つ上限（REPAIR-5）。
    const THREAD_WAIT: Duration = Duration::from_secs(30);

    /// 拒否の記録先に relay を返し、`launch` に到達したら数える launcher。
    struct Launcher {
        relay: Arc<dyn AuditSink>,
        launches: AtomicUsize,
    }

    impl ProcessLauncher for Launcher {
        fn launch_mode(&self) -> LaunchMode {
            LaunchMode::CallerBounded
        }

        fn rejection_audit_sink(&self) -> Option<&dyn AuditSink> {
            Some(self.relay.as_ref())
        }

        fn launch(
            &self,
            _spec: &LaunchSpec,
            _timeout: Duration,
        ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            Err(TraitError::new(
                ErrorCode::Internal,
                "the test launcher never launches",
            ))
        }

        fn confirm_no_process(
            &self,
            _id: &ContainerId,
            _timeout: Duration,
        ) -> Result<(), TraitError> {
            Ok(())
        }
    }

    const CONFIG: &str = r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},
"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},
"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#;

    fn private_dir(path: &Path) {
        std::fs::create_dir_all(path).expect("create dir");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }

    pub fn run() {
        // tmpfiles の flock 走査から守る親（#3026）。bundle・状態ルートはその子に作り、関数の最後まで保持する。
        let scratch = super::scratch_root::ScratchDir::new(
            "fandhe-sup-2623",
            std::time::Duration::from_secs(10),
        );
        let base: PathBuf = scratch.path().join("b");
        private_dir(&base);
        let root = base.join("state");
        private_dir(&root);

        // 本番の入口と同じ順序: 単一スレッドの間に relay を fork し、記録先を確かめる。作業スレッドはまだ無い。
        let relay = default_audit_sink(Some(root.clone()))
            .and_then(ControlAuditRelay::spawn)
            .unwrap_or_else(|e| panic!("spawn the audit relay: {e}"));
        relay
            .probe()
            .unwrap_or_else(|e| panic!("probe the audit log: {e}"));
        let relay: Arc<dyn AuditSink> = Arc::new(relay);
        let store: Arc<dyn StateStore> =
            open_default_store(Some(root.clone())).expect("open the state store");
        let launcher = Arc::new(Launcher {
            relay: Arc::clone(&relay),
            launches: AtomicUsize::new(0),
        });

        // (コンテナ ID, 検証後の差し替え, 期待する理由コード)
        type Swap = fn(&Path);
        let scenarios: [(&str, Swap, &str); 2] = [
            (
                "c-2623-symlink",
                |rootfs| {
                    std::fs::remove_dir(rootfs).expect("remove rootfs");
                    std::os::unix::fs::symlink("/", rootfs).expect("symlink rootfs");
                },
                "path_symlink_or_not_directory",
            ),
            (
                "c-2623-missing",
                |rootfs| std::fs::remove_dir(rootfs).expect("remove rootfs"),
                "path_missing",
            ),
        ];

        for (name, swap, _) in &scenarios {
            let bundle = base.join(format!("bundle-{name}"));
            std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
            std::fs::write(bundle.join("config.json"), CONFIG).expect("write config");
            let id = ContainerId::new(*name).expect("container id");
            create(
                store.as_ref(),
                &OpRecorder::new(),
                &CreateRequest::new(id.clone(), bundle.clone()).expect("absolute bundle"),
            )
            .unwrap_or_else(|e| panic!("create: {e}"));

            // 本番と同じく作業スレッドで start の前半を実行する（プロセスが複数スレッドになる）。
            let (tx, rx) = std::sync::mpsc::channel();
            let worker = {
                let store = Arc::clone(&store);
                let launcher = Arc::clone(&launcher);
                let id = id.clone();
                let rootfs = bundle.join("rootfs");
                let swap = *swap;
                std::thread::Builder::new()
                    .name("supervisor-start-test".to_owned())
                    .spawn(move || {
                        let result = claim_start_with_pin_swap_for_test(
                            store.as_ref(),
                            launcher.as_ref(),
                            &StartRequest::new(id),
                            || swap(&rootfs),
                        );
                        let _ = tx.send(result.map(|_| ()).map_err(|e| e.to_string()));
                    })
                    .expect("spawn the worker thread")
            };
            let result = rx
                .recv_timeout(THREAD_WAIT)
                .unwrap_or_else(|e| panic!("the start worker did not finish: {e}"));
            worker.join().expect("join the worker thread");
            let message = result.expect_err("the swapped rootfs must be rejected");
            assert!(
                message.contains("rootfs changed after validation"),
                "{message}"
            );
            let state = store.get(&GetStateRequest::new(id)).expect("state");
            assert_eq!(state.status().state(), ContainerState::Created);
        }
        assert_eq!(launcher.launches.load(Ordering::SeqCst), 0);

        // 記録先: 要求ごとに 1 行（計 2 行）。層は mount、パスなし、理由コードつき、コンテナ ID つき。
        let log_path = root.join("@audit.log");
        let deadline = Instant::now() + Duration::from_secs(10);
        let log = loop {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            if log.lines().count() >= scenarios.len() || Instant::now() >= deadline {
                break log;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), scenarios.len(), "unexpected @audit.log: {log}");
        for ((name, _, reason), line) in scenarios.iter().zip(&lines) {
            assert!(line.contains(r#""layer":"mount""#), "{line}");
            assert!(line.contains(r#""path":null"#), "{line}");
            assert!(line.contains(&format!(r#""reason":"{reason}""#)), "{line}");
            assert!(
                line.contains(&format!(r#""container_id":"{name}""#)),
                "{line}"
            );
        }

        drop(launcher);
        drop(relay);
        let _ = std::fs::remove_dir_all(&base);
        println!("start_rootfs_pin_audit_relay: all scenarios passed");
    }
}
