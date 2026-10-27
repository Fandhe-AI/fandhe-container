//! supervisor の `start` の再検証（TOCTOU）で起きる `mounts[].destination` の拒否が、中継 sink
//! （`ControlAuditRelay`）を通って監査の記録先 `<状態ルート>/@audit.log` へ届くことの結合試験
//! （SEC-4・OCI-4・SUP-1・#2594・REPAIR-12）。
//!
//! 再検証の点は 2 つある。シナリオ A は手順 8（`claim_start` が呼ぶ `build_spec`）で launcher の拒否の記録先へ、
//! シナリオ B は手順 5（`prepare_cgroup` の `load_resource_limits_audited`）で supervisor の拒否の記録先へ、
//! どちらも relay 経由で記録する。B は手順 5 で拒否されれば手順 8 へ進まないので二重に記録しない（1 要求 1 行）。
//! create 後に `config.json` を書き換えて destination の遡り・`/`・相対 `..` を作る。
//! 本番の `ProductionStartDeps::prepare_cgroup` の結線は supervisor の単体試験（ソース構造）が固定する。
//!
//! `ControlAuditRelay::spawn` は単一スレッドの呼び出し元を要求するため、`harness = false` の単一スレッド `main`
//! で動かす。root 不要で既定のテスト集合で動く。待ちはすべて期限つき（REPAIR-5）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("start_destination_audit_relay: Linux only, not applicable on this OS");
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

    use fandhe_container_core::audit_log::{AuditSink, ControlAuditRelay, RECORD_WAIT_LIMIT};
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        LaunchMode, LaunchSpec, LaunchedProcess, ProcessLauncher, StartTimeouts, create,
        load_resource_limits_audited,
    };
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, ErrorCode, GetStateRequest, StartRequest,
        StateRecord, StateRevision, StateStore, TraitError,
    };
    use fandhe_container_supervisor::exec::default_audit_sink;
    use fandhe_container_supervisor::start_entry::{StartDeps, run_start};
    use fandhe_container_supervisor::state::open_default_store;

    const CONTAINER: &str = "c-2594";
    /// 遡り・rootfs 全体・相対 `..`（core の `create_mount_audit_delivery` と同じ 3 ケース）。
    const DESTINATIONS: [&str; 3] = ["/../..", "/", "run/../../.."];
    const POLL_MARGIN: Duration = Duration::from_secs(5);

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

    /// `step5` が真なら `prepare_cgroup` で本番と同じ `load_resource_limits_audited` を呼ぶ。
    struct Deps {
        launcher: Arc<Launcher>,
        step5: bool,
    }

    impl StartDeps for Deps {
        fn check_launcher_available(&self) -> Result<(), TraitError> {
            Ok(())
        }
        fn prepare_cgroup(
            &mut self,
            _store: &dyn StateStore,
            observed: &StateRecord,
        ) -> Result<Option<StateRevision>, TraitError> {
            if self.step5 {
                load_resource_limits_audited(
                    observed.bundle(),
                    observed.status().id(),
                    self.launcher.relay.as_ref(),
                )?;
            }
            Ok(None)
        }
        fn build_audit_sink(&mut self) -> Result<(), TraitError> {
            Ok(())
        }
        fn build_launcher(&mut self) -> Result<Arc<dyn ProcessLauncher>, TraitError> {
            Ok(Arc::clone(&self.launcher) as Arc<dyn ProcessLauncher>)
        }
        fn recover_interrupted(
            &mut self,
            _store: &dyn StateStore,
            _id: &ContainerId,
            _timeouts: &StartTimeouts,
        ) -> Result<(), TraitError> {
            Ok(())
        }
        fn release_cgroup(&mut self) -> Result<(), TraitError> {
            Ok(())
        }
    }

    fn config(mounts: &str) -> String {
        format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs"}},
"process":{{"user":{{"uid":0,"gid":0}},"args":["/bin/echo","it"],"cwd":"/"}},
"mounts":{mounts},
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"user"}},{{"type":"uts"}},{{"type":"ipc"}}]}}}}"#
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
        // tmpfiles の flock 走査から守る親（#3026）。bundle・状態ルートはその子に作り、関数の最後まで保持する。
        let scratch = super::scratch_root::ScratchDir::new(
            "fandhe-sup-2594",
            std::time::Duration::from_secs(10),
        );
        let base: PathBuf = scratch.path().join("b");
        private_dir(&base);
        let bundle = base.join("bundle");
        std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
        let root = base.join("state");
        private_dir(&root);

        // 本番の入口と同じ順序: 単一スレッドの間に relay を fork し、記録先を確かめる。
        let relay = default_audit_sink(Some(root.clone()))
            .and_then(ControlAuditRelay::spawn)
            .unwrap_or_else(|e| panic!("spawn the audit relay: {e}"));
        relay
            .probe()
            .unwrap_or_else(|e| panic!("probe the audit log: {e}"));
        let relay: Arc<dyn AuditSink> = Arc::new(relay);

        let store = open_default_store(Some(root.clone())).expect("open the state store");
        let id = ContainerId::new(CONTAINER).expect("container id");
        std::fs::write(bundle.join("config.json"), config("[]")).expect("write config");
        create(
            store.as_ref(),
            &OpRecorder::new(),
            &CreateRequest::new(id.clone(), bundle.clone()).expect("absolute bundle"),
        )
        .unwrap_or_else(|e| panic!("create: {e}"));

        let launcher = Arc::new(Launcher {
            relay: Arc::clone(&relay),
            launches: AtomicUsize::new(0),
        });
        let timeouts = StartTimeouts::new(
            Duration::from_millis(100),
            Duration::from_secs(1),
            Duration::from_millis(500),
        )
        .expect("timeouts");

        for step5 in [false, true] {
            for dest in DESTINATIONS {
                let mounts = format!(
                    r#"[{{"destination":{dest:?},"type":"bind","source":"/srv/x","options":["rbind","rw"]}}]"#
                );
                // create 後の書き換え（TOCTOU）。
                std::fs::write(bundle.join("config.json"), config(&mounts))
                    .expect("rewrite config");
                let mut out = Vec::new();
                // `run_start` は作業スレッドで手順を実行する（本番と同じ複数スレッドの状況）。
                let result = run_start(
                    Box::new(Deps {
                        launcher: Arc::clone(&launcher),
                        step5,
                    }),
                    &store,
                    &Arc::new(OpRecorder::new()),
                    &StartRequest::new(id.clone()),
                    &timeouts,
                    &mut out,
                );
                let report = String::from_utf8_lossy(&out);
                assert!(
                    result.is_err(),
                    "destination {dest:?} must be rejected (step5={step5}): {report}"
                );
            }
        }
        assert_eq!(launcher.launches.load(Ordering::SeqCst), 0);
        let state = store.get(&GetStateRequest::new(id)).expect("state");
        assert_eq!(state.status().state(), ContainerState::Created);

        // 記録先: 要求ごとに 1 行（A の 3 行 + B の 3 行）。層は mount、path なし、理由なし。
        let want = DESTINATIONS.len() * 2;
        let lines = wait_for_audit_lines(&root, want);
        assert_eq!(lines.len(), want, "unexpected @audit.log: {lines:?}");
        for line in &lines {
            assert!(line.contains(r#""layer":"mount""#), "{line}");
            assert!(line.contains(r#""path":null"#), "{line}");
            assert!(
                line.contains(&format!(r#""container_id":"{CONTAINER}""#)),
                "{line}"
            );
            assert!(!line.contains(r#""reason""#), "{line}");
        }

        drop(relay);
        let _ = std::fs::remove_dir_all(&base);
        println!("start_destination_audit_relay: all scenarios passed");
    }
}
