//! start 時の cgroup 手順（記録 → mkdir → 制限 → 参加フック）の結合試験（CORE-3・OCI-6・SEC-1・TASK-32 追補・#1716）。
//!
//! 実 `DelegatedCgroup` と実 `FileStateStore` で `record_scope` → `create_cgroup` → `apply_limits` →
//! `into_join` を通し、`state.json` の `cgroupScope` / `cgroupInstance` と実 cgroup のディレクトリ
//! （`<委譲パス>/fc-<id>@<create の revision>`）を具体値で照合し、delete の後に両方が消えることを確かめる。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリーが必要で、GitHub ホステッド runner では保証できない
//! ため `#[ignore]` で既定のテスト集合から分離する（AGENTS.md「実機前提テスト」・ci.md）。root は不要
//! （rootless の適用経路 `NotApplied(Rootless)` を照合する）。自プロセスを cgroup 間で移動するため、
//! 1 ファイル 1 テストにする:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_start_chain --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_start_chain-XXXX> --ignored
//! ```

#[cfg(target_os = "linux")]
mod linux {
    use fandhe_container_core::cgroups::{
        CgroupLimitPlan, DelegatedCgroup, DevicePolicyMode, DevicePolicyNotApplied,
        DevicePolicyOutcome,
    };
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::delete;
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, DeleteRequest, ErrorCode, StateStore,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    /// CORE-3・OCI-6・SEC-1（#1716）: 連鎖の後、cgroup と記録が具体値で一致し、delete で両方消える。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn core3_oci6_task32_start_chain_records_then_creates_and_delete_cleans_up() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let id = ContainerId::new(format!("s{}", std::process::id())).expect("id");

        let root_dir = std::env::temp_dir().join(format!("fandhe-start-chain-{}", id.as_str()));
        let _ = fs::remove_dir_all(&root_dir);
        fs::create_dir_all(&root_dir).expect("create state root");
        fs::set_permissions(&root_dir, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
        let store = FileStateStore::open(StateRoot::from_override(root_dir.clone()).expect("root"))
            .expect("open store");
        // create ではスコープを記録しない（#1314・案 3-ii）。
        let created = store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(id.clone(), None),
                    root_dir.join("bundle"),
                )
                .expect("req"),
            )
            .expect("create record");
        assert_eq!(created.cgroup(), None);

        let rec = OpRecorder::new();
        let start = delegated
            .record_scope(&store, &created)
            .expect("record_scope")
            .create_cgroup()
            .expect("create_cgroup")
            .apply_limits(&rec, &CgroupLimitPlan::new(DevicePolicyMode::Rootless))
            .expect("apply_limits")
            .into_join()
            .expect("into_join");
        assert_eq!(
            start.limits().device_policy,
            DevicePolicyOutcome::NotApplied(DevicePolicyNotApplied::Rootless)
        );

        let name = format!("fc-{}@{}", id.as_str(), created.revision().value());
        assert_eq!(start.cgroup().name().as_str(), name);
        let cgroup_dir = parent.join(&name);
        assert!(cgroup_dir.is_dir());

        let state_json = root_dir.join(id.as_str()).join("state.json");
        let state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_json).expect("read state.json"))
                .expect("parse state.json");
        assert_eq!(state["cgroupScope"], delegated.path());
        assert_eq!(state["cgroupInstance"], created.revision().value());

        drop(start);
        delete(&store, &rec, &delegated, &DeleteRequest::new(id.clone())).expect("delete");
        assert!(
            !cgroup_dir.exists(),
            "cgroup {} remains",
            cgroup_dir.display()
        );
        assert!(!state_json.exists());
        let err = delete(&store, &rec, &delegated, &DeleteRequest::new(id.clone()))
            .expect_err("second delete");
        assert_eq!(err.code(), ErrorCode::NotFound);

        let _ = fs::remove_dir_all(&root_dir);
    }
}
