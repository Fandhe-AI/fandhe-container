//! 検出スコープと異なる記録済みスコープからの `delete` の結合試験（CORE-3・OCI-6・#2096）。
//!
//! 実 `DelegatedCgroup`（検出スコープ = 自プロセスの所属）を remover に、実 `FileStateStore` を状態ストアにして
//! `oci_runtime::delete` を呼ぶ。状態記録には検出スコープの子 `rec-<pid>` を記録し、その直下に
//! コンテナ cgroup `fc-<id>@<instance>` を作る。記録と検出のスコープは一致しないため、削除は
//! `ContainerCgroupRemover::remove_recorded` → `RecordedCgroupScope`（fd 起点の検証つき open）の本番経路を通る。
//! delete の後にコンテナ cgroup と `state.json` が実 FS から消え、2 回目が `NotFound` になることを具体値で照合する。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリーが必要で、GitHub ホステッド runner では保証できないため
//! `#[ignore]` で既定のテスト集合から分離する（AGENTS.md「実機前提テスト」・ci.md）。root 不要:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_delete_recorded --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_delete_recorded-XXXX> --ignored
//! ```

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

    use fandhe_container_core::cgroups::CgroupName;
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::delete;
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        CgroupScope, ContainerId, ContainerStatus, CreateStateRequest, DeleteRequest, ErrorCode,
        StateStore,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    /// CORE-3・OCI-6（#2096）: 検出スコープと別の記録スコープ配下のコンテナ cgroup と状態記録が消える。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn oci6_issue2096_delete_removes_cgroup_under_recorded_scope() {
        let delegated = crate::precondition::delegated_cgroup();
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));

        // 検出スコープの子を「記録されたスコープ」にする（検出スコープとは文字列が異なる）。
        let scope_name = format!("rec-{}", std::process::id());
        let scope_dir = parent.join(&scope_name);
        fs::create_dir(&scope_dir).expect("create recorded scope dir");
        let recorded_path = format!("{}/{}", delegated.path().trim_end_matches('/'), scope_name);
        assert_ne!(recorded_path, delegated.path());

        let id = ContainerId::new(format!("r{}", std::process::id())).expect("id");
        let root_dir = std::env::temp_dir().join(format!("fandhe-cgroup-rec-{}", id.as_str()));
        let _ = fs::remove_dir_all(&root_dir);
        fs::create_dir_all(&root_dir).expect("create state root");
        fs::set_permissions(&root_dir, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
        let store = FileStateStore::open(StateRoot::from_override(root_dir.clone()).expect("root"))
            .expect("open store");
        let record = store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::stopped(id.clone(), Some(0)),
                    root_dir.join("bundle"),
                )
                .expect("req")
                .with_cgroup_scope(CgroupScope::new(&recorded_path).expect("scope")),
            )
            .expect("create record");
        let instance = record.cgroup().expect("placement").instance();
        let name = CgroupName::for_instance(&id, instance).expect("name");
        let cgroup_dir = scope_dir.join(name.as_str());
        fs::create_dir(&cgroup_dir).expect("create container cgroup");
        assert!(cgroup_dir.is_dir());

        let state_json = root_dir.join(id.as_str()).join("state.json");
        let state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_json).expect("read state.json"))
                .expect("parse state.json");
        assert_eq!(state["cgroupScope"], recorded_path.as_str());

        let rec = OpRecorder::new();
        delete(&store, &rec, &delegated, &DeleteRequest::new(id.clone())).expect("delete");

        assert!(
            !cgroup_dir.exists(),
            "cgroup {} remains",
            cgroup_dir.display()
        );
        assert!(scope_dir.is_dir(), "recorded scope itself must remain");
        assert!(!state_json.exists());
        assert!(!root_dir.join(id.as_str()).exists());

        let err = delete(&store, &rec, &delegated, &DeleteRequest::new(id.clone()))
            .expect_err("second delete");
        assert_eq!(err.code(), ErrorCode::NotFound);

        let _ = fs::remove_dir(&scope_dir);
        let _ = fs::remove_dir_all(&root_dir);
    }
}
