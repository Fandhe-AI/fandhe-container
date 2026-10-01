//! `delete` による cgroup・状態ファイルの削除の結合試験（CORE-3・OCI-6・TASK-30.3）。
//!
//! 実 `DelegatedCgroup`（`ContainerCgroupRemover` の本番実装）と実 `FileStateStore` を `oci_runtime::delete`
//! へ渡し、delete の後にコンテナ用子 cgroup（`<委譲パス>/fc-<id>`）と `state.json` が実ファイルシステム上から
//! 消えていることを具体値で照合する（受入基準 1・2）。レコードには create 時の委譲スコープを記録し
//! （`CreateStateRequest::with_cgroup_scope`）、`state.json` の `cgroupScope` が検出した委譲パスと一致することも
//! 確かめる（delete はこの記録と削除側のスコープが一致するときだけ cgroup を削除・不存在確認する）。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリーが必要で、GitHub ホステッド runner では保証できない
//! ため `#[ignore]` で既定のテスト集合から分離する（AGENTS.md「実機前提テスト」・ci.md）。
//! 自プロセスを cgroup 間で移動するため、1 ファイル 1 テストにする。`cargo` を経由せず、
//! ビルド済みのテストバイナリを委譲スコープの中で直接実行する（root 不要）:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_delete --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_delete-XXXX> --ignored
//! ```

#[cfg(target_os = "linux")]
mod linux {
    use fandhe_container_core::cgroups::{CgroupName, DelegatedCgroup};
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{ContainerCgroupRemover, delete};
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, DeleteRequest, ErrorCode, StateStore,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    /// CORE-3・OCI-6（受入基準 1・2）: delete の後、`fc-<id>` と `state.json` が消え、2 回目は `NotFound`。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn oci6_task30_3_delete_removes_cgroup_and_state_file() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));

        let id = ContainerId::new(format!("d{}", std::process::id())).expect("id");
        let name = CgroupName::new(&id).expect("name");
        let (_child, _proof) = delegated.prepare(&name).expect("prepare");
        let cgroup_dir = parent.join(name.as_str());
        assert!(cgroup_dir.is_dir());

        let root_dir = std::env::temp_dir().join(format!("fandhe-cgroup-delete-{}", id.as_str()));
        let _ = fs::remove_dir_all(&root_dir);
        fs::create_dir_all(&root_dir).expect("create state root");
        fs::set_permissions(&root_dir, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
        let store = FileStateStore::open(StateRoot::from_override(root_dir.clone()).expect("root"))
            .expect("open store");
        store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::stopped(id.clone(), Some(0)),
                    root_dir.join("bundle"),
                )
                .expect("req")
                .with_cgroup_scope(delegated.scope().expect("scope")),
            )
            .expect("create record");
        let state_json = root_dir.join(id.as_str()).join("state.json");
        assert!(state_json.is_file());
        let state: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_json).expect("read state.json"))
                .expect("parse state.json");
        assert_eq!(state["cgroupScope"], delegated.path());

        let rec = OpRecorder::new();
        delete(&store, &rec, &delegated, &DeleteRequest::new(id.clone())).expect("delete");

        assert!(
            !cgroup_dir.exists(),
            "cgroup {} remains",
            cgroup_dir.display()
        );
        assert!(!state_json.exists());
        assert!(!root_dir.join(id.as_str()).exists());

        let err = delete(&store, &rec, &delegated, &DeleteRequest::new(id.clone()))
            .expect_err("second delete");
        assert_eq!(err.code(), ErrorCode::NotFound);

        let _ = fs::remove_dir_all(&root_dir);
    }
}
