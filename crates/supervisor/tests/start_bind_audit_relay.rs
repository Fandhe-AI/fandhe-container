//! supervisor の `start` 経由の bind mount の元の拒否が、中継 sink（`ControlAuditRelay`）を通って監査の記録先
//! `<状態ルート>/@audit.log` へ届くことの結合試験（SEC-4・OCI-4・SUP-1・#2481・REPAIR-12）。
//!
//! 背景: `claim_start` の bind・sysfs の検証は作業スレッド `supervisor-start` で走り、入口スレッドが待つ間は
//! プロセスが複数スレッドになる。`FileAuditSink` は複数スレッドだと主経路を試せず、rootless では代替経路
//! （カーネル監査）も失敗して拒否が残らない。本番の入口は単一スレッドの間に fork した relay を launcher の
//! `rejection_audit_sink` へ渡す。本試験は同じ順序（relay を fork → `run_start` が作業スレッドを作る）で、
//! launcher の拒否の記録先に relay を返す偽の launcher を使い、公開の `run_start` から `@audit.log` まで照合する。
//! 本番の `ProductionStartDeps::build_launcher` の結線は core の単体試験とソース構造の試験が固定する。
//!
//! `ControlAuditRelay::spawn` は単一スレッドの呼び出し元を要求するため、`harness = false` の単一スレッド `main`
//! で動かす（`control_audit_delivery` と同じ）。root 不要で既定のテスト集合で動く。待ちはすべて期限つき（REPAIR-5）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("start_bind_audit_relay: Linux only, not applicable on this OS");
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
    use std::time::Duration;

    use fandhe_container_core::audit_log::{
        AuditEvent, AuditPath, AuditPid, AuditRecord, AuditSink, AuditTimestamp, ControlAuditRelay,
    };
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        LaunchMode, LaunchSpec, LaunchedProcess, ProcessLauncher, StartTimeouts, create,
    };
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, ErrorCode, GetStateRequest, StartRequest,
        StateRecord, StateRevision, StateStore, TraitError,
    };
    use fandhe_container_supervisor::exec::default_audit_sink;
    use fandhe_container_supervisor::start_entry::{StartDeps, run_start};
    use fandhe_container_supervisor::state::open_default_store;

    const CONTAINER: &str = "c-2481";
    const DESTINATION: &str = "/data";

    /// 拒否の記録先に relay を返し、`launch` に到達したら（＝拒否されなかったら）数えて失敗する launcher。
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

    struct Deps(Arc<Launcher>);

    impl StartDeps for Deps {
        fn check_launcher_available(&self) -> Result<(), TraitError> {
            Ok(())
        }
        fn prepare_cgroup(
            &mut self,
            _store: &dyn StateStore,
            _observed: &StateRecord,
        ) -> Result<Option<StateRevision>, TraitError> {
            Ok(None)
        }
        fn build_audit_sink(&mut self) -> Result<(), TraitError> {
            Ok(())
        }
        fn build_launcher(&mut self) -> Result<Arc<dyn ProcessLauncher>, TraitError> {
            Ok(Arc::clone(&self.0) as Arc<dyn ProcessLauncher>)
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

    pub fn run() {
        // tmpfiles の flock 走査から守る親（#3026）。bundle・状態ルートはその子に作り、関数の最後まで保持する。
        let scratch = super::scratch_root::ScratchDir::new(
            "fandhe-sup-2481",
            std::time::Duration::from_secs(10),
        );
        let base: PathBuf = scratch.path().join("b");
        private_dir(&base);
        let bundle = base.join("bundle");
        std::fs::create_dir_all(bundle.join("rootfs")).expect("rootfs");
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
        let host_state_root = store
            .host_state_root()
            .expect("the file store knows its root")
            .to_path_buf();
        // rootfs・bundle・状態ルートのいずれを元にした bind も `start` が拒否する（ESC-08 と同じ 3 ケース）。
        let sources = [bundle.join("rootfs"), bundle.clone(), host_state_root];
        let timeouts = StartTimeouts::new(
            Duration::from_millis(100),
            Duration::from_secs(1),
            Duration::from_millis(500),
        )
        .expect("timeouts");
        for source in &sources {
            let mounts = format!(
                r#"[{{"destination":"{DESTINATION}","type":"bind","source":{:?},"options":["rbind","rw"]}}]"#,
                source.to_str().expect("utf-8 path")
            );
            std::fs::write(bundle.join("config.json"), config(&mounts)).expect("rewrite config");
            let mut out = Vec::new();
            // `run_start` は作業スレッドで `claim_start` を実行する（本番と同じ複数スレッドの状況）。
            let result = run_start(
                Box::new(Deps(Arc::clone(&launcher))),
                &store,
                &Arc::new(OpRecorder::new()),
                &StartRequest::new(id.clone()),
                &timeouts,
                &mut out,
            );
            assert!(
                result.is_err(),
                "bind source {} must be rejected: {}",
                source.display(),
                String::from_utf8_lossy(&out)
            );
        }
        assert_eq!(launcher.launches.load(Ordering::SeqCst), 0);
        let state = store.get(&GetStateRequest::new(id)).expect("state");
        assert_eq!(state.status().state(), ContainerState::Created);

        // 記録先: 要求ごとに 1 行（計 3 行）。層は mount、宛先（ホスト側の元ではない）を載せ、理由は無い。
        let log = std::fs::read_to_string(root.join("@audit.log")).expect("read @audit.log");
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 3, "unexpected @audit.log: {log}");
        for line in &lines {
            assert!(line.contains(r#""layer":"mount""#), "{line}");
            assert!(
                line.contains(&format!(r#""path":"{DESTINATION}""#)),
                "{line}"
            );
            assert!(
                line.contains(&format!(r#""container_id":"{CONTAINER}""#)),
                "{line}"
            );
            assert!(line.contains(r#""path_truncated":false"#), "{line}");
            assert!(
                line.contains(&format!(r#""path_original_len":{}"#, DESTINATION.len())),
                "{line}"
            );
            assert!(!line.contains(r#""reason""#), "{line}");
        }

        // 運べない種類は黙って捨てず `InvalidArgument` で失敗が見え、中継は壊れない（続く記録は運べる）。
        let at = AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 0));
        let pid = AuditPid::new(1).expect("pid");
        let unsupported = AuditRecord::new(
            at,
            pid,
            AuditEvent::Landlock {
                path: AuditPath::new("/x"),
                syscall: None,
            },
        );
        let err = relay
            .record(&unsupported)
            .expect_err("landlock is not carried");
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        let after = std::fs::read_to_string(root.join("@audit.log")).expect("read @audit.log");
        assert_eq!(
            after.lines().count(),
            3,
            "an unsupported record must not be written"
        );
        let mount = AuditRecord::new(
            at,
            pid,
            AuditEvent::Mount {
                path: Some(AuditPath::new("/after")),
                reason: None,
            },
        );
        relay
            .record(&mount)
            .unwrap_or_else(|e| panic!("the relay stays usable: {e}"));
        let end = std::fs::read_to_string(root.join("@audit.log")).expect("read @audit.log");
        assert_eq!(end.lines().count(), 4, "{end}");

        drop(relay);
        let _ = std::fs::remove_dir_all(&base);
        println!("start_bind_audit_relay: all scenarios passed");
    }
}
