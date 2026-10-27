//! 別プロセスで起動した残存を、記録済みの cgroup から確かめて回復する結合試験
//! （`recover_interrupted_start` + `ProductionLauncher::confirm_no_process_recorded`。
//! CORE-2・SEC-1・OCI-6・REPAIR-12。#2011）。
//!
//! 台帳が空の新しい `ProductionLauncher`（= クラッシュした supervisor の後に起動した別プロセスの launcher）に、
//! 実 `FileStateStore` の Running・pid なしのレコード（cgroup の配置つき）を渡し、実 cgroup v2 上で次を具体値で照合する。
//! - シナリオ A: 記録のコンテナ cgroup に `sleep` が居る → `Ok`・状態が Created・`populated 0`・`sleep` が回収済み
//! - シナリオ B: 記録のコンテナ cgroup が空 → `Ok`・Created
//! - シナリオ C: 記録のスコープが既に無い → `Ok`・Created
//! - シナリオ D: 配置の記録が無いレコード → `FailedPrecondition`・Running のまま
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（と、child subreaper 化できるプロセス）が必要で、GitHub
//! ホステッド runner では保証できないため `#[ignore]` で既定のテスト集合から分離する（AGENTS.md「実機前提テスト」・
//! ci.md）。root 不要（root では所有者の検証が省かれるため非 root で実行する）:
//!
//! ```text
//! cargo test -p fandhe-container-core --test confirm_recorded_cgroup --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/confirm_recorded_cgroup-XXXX> --ignored
//! ```
//!
//! 作成時は未実行（ホストに cgroup を作るため Agent は実行しない）。

// 前提欠如を `PRECONDITION FAILED` の 1 行目で失敗させる共有部品（#2888・#2956・REPAIR-12）。
#[cfg(target_os = "linux")]
#[path = "support/precondition.rs"]
mod precondition;

#[cfg(target_os = "linux")]
mod linux {
    /// REPAIR-12・#2956: 前提欠如の分類（`precondition`）の自己照合。既定のテスト集合で常に走る。
    /// 純粋計算でプロセスを cgroup 間で移さないため、1 ファイル 1 テストの規約（自プロセスを移す
    /// 試験向け）の対象外。実機の実行は `--ignored` のため本番の試験と同時には走らない。
    #[test]
    fn repair12_precondition_self_check() {
        crate::precondition::self_check();
    }

    use fandhe_container_core::audit_log::{AuditRecord, AuditSink};
    use fandhe_container_core::cgroups::{CgroupName, DelegatedCgroup};
    use fandhe_container_core::exec::IsolationPrivilege;
    use fandhe_container_core::oci_runtime::{
        ProcessLauncher, ProductionLauncher, StartTimeouts, recover_interrupted_start,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        CgroupScope, ContainerId, ContainerState, ContainerStatus, CreateStateRequest, ErrorCode,
        GetStateRequest, StateStore, TraitError, UpdateStateRequest,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    struct NullSink;

    impl AuditSink for NullSink {
        fn record(&self, _record: &AuditRecord) -> Result<(), TraitError> {
            Ok(())
        }
    }

    fn launcher() -> Arc<dyn ProcessLauncher> {
        Arc::new(
            ProductionLauncher::builder()
                .privilege(IsolationPrivilege::RootlessSingleId)
                .audit_sink(Arc::new(NullSink))
                .build()
                .expect("build launcher (child subreaper)"),
        )
    }

    fn timeouts() -> StartTimeouts {
        StartTimeouts::new(
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .expect("timeouts")
    }

    /// 1 シナリオ分の状態ルートと記録。`recorded` のスコープ（なければ配置なし）で Running・pid なしにする。
    struct Case {
        id: ContainerId,
        root: PathBuf,
        store: FileStateStore,
        cgroup_dir: Option<PathBuf>,
    }

    impl Case {
        fn new(tag: &str, recorded: Option<&str>, scope_dir: &Path) -> Self {
            let id = ContainerId::new(format!("{tag}{}", std::process::id())).expect("id");
            let root = std::env::temp_dir().join(format!("fandhe-confirm-rec-{}", id.as_str()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(root.join("bundle")).expect("mkdir bundle");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("chmod");
            let store = FileStateStore::open(StateRoot::from_override(root.clone()).expect("root"))
                .expect("open store");
            let mut req = CreateStateRequest::new(
                ContainerStatus::created(id.clone(), None),
                root.join("bundle"),
            )
            .expect("req");
            if let Some(scope) = recorded {
                req = req.with_cgroup_scope(CgroupScope::new(scope).expect("scope"));
            }
            let record = store.create(&req).expect("create");
            let cgroup_dir = record.cgroup().map(|p| {
                let name = CgroupName::for_instance(&id, p.instance()).expect("name");
                scope_dir.join(name.as_str())
            });
            store
                .update(&UpdateStateRequest::new(
                    ContainerStatus::running(id.clone(), None),
                    record.revision(),
                ))
                .expect("reserve");
            Self {
                id,
                root,
                store,
                cgroup_dir,
            }
        }

        fn state(&self) -> ContainerState {
            self.store
                .get(&GetStateRequest::new(self.id.clone()))
                .expect("get")
                .status()
                .state()
        }
    }

    impl Drop for Case {
        fn drop(&mut self) {
            if let Some(d) = &self.cgroup_dir {
                let _ = fs::remove_dir(d);
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    struct ScopeDir(PathBuf);

    impl Drop for ScopeDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn delegated_scope() -> (DelegatedCgroup, String, PathBuf, ScopeDir) {
        let delegated = crate::precondition::delegated_cgroup();
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let name = format!("rec-{}", std::process::id());
        let dir = parent.join(&name);
        fs::create_dir(&dir).expect("create recorded scope dir");
        let recorded = format!("{}/{}", delegated.path().trim_end_matches('/'), name);
        (delegated, recorded, dir.clone(), ScopeDir(dir))
    }

    fn populated(dir: &Path) -> bool {
        fs::read_to_string(dir.join("cgroup.events"))
            .expect("cgroup.events")
            .lines()
            .any(|l| l == "populated 1")
    }

    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn core2_issue2011_recovers_from_recorded_cgroup_in_another_process() {
        let (_delegated, recorded, scope_dir, _guard) = delegated_scope();

        // A: 孤児の sleep が居る。
        let a = Case::new("ca", Some(&recorded), &scope_dir);
        let a_dir = a.cgroup_dir.clone().expect("placement");
        fs::create_dir(&a_dir).expect("mkdir container cgroup");
        let mut sleeper = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        fs::write(a_dir.join("cgroup.procs"), sleeper.id().to_string()).expect("move sleep");
        assert!(populated(&a_dir));
        recover_interrupted_start(&a.store, &launcher(), &a.id, &timeouts()).expect("recover A");
        assert_eq!(a.state(), ContainerState::Created);
        assert!(!populated(&a_dir));
        let deadline = Instant::now() + Duration::from_secs(10);
        while sleeper.try_wait().expect("try_wait").is_none() {
            assert!(Instant::now() < deadline, "sleep was not killed");
            std::thread::sleep(Duration::from_millis(20));
        }

        // B: 空のコンテナ cgroup。
        let b = Case::new("cb", Some(&recorded), &scope_dir);
        fs::create_dir(b.cgroup_dir.as_ref().expect("placement")).expect("mkdir");
        recover_interrupted_start(&b.store, &launcher(), &b.id, &timeouts()).expect("recover B");
        assert_eq!(b.state(), ContainerState::Created);

        // C: 記録のスコープが既に無い。
        let gone = format!(
            "{}/gone-{}",
            recorded.trim_end_matches('/'),
            std::process::id()
        );
        let c = Case::new("cc", Some(&gone), &scope_dir.join("gone"));
        recover_interrupted_start(&c.store, &launcher(), &c.id, &timeouts()).expect("recover C");
        assert_eq!(c.state(), ContainerState::Created);

        // D: 配置の記録が無い。
        let d = Case::new("cd", None, &scope_dir);
        let err = recover_interrupted_start(&d.store, &launcher(), &d.id, &timeouts())
            .expect_err("no placement");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(d.state(), ContainerState::Running);
    }
}
