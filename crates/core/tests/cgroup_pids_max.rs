//! `pids.max` 設定の結合試験（SUP-13・TASK-170.2・#533）。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（`pids` controller 付き）が必要で、GitHub ホステッド
//! runner では保証できないため `#[ignore]` で既定のテスト集合から分離する（AGENTS.md「実機前提テスト」・
//! ci.md）。自プロセスを cgroup 間で移動するため、1 ファイル 1 テストにし、`cargo` を経由せず
//! ビルド済みのテストバイナリを委譲スコープの中で直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_pids_max --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_pids_max-XXXX> --ignored
//! ```

#[cfg(target_os = "linux")]
mod linux {
    use fandhe_container_core::cgroups::{
        CgroupName, Controller, ControllerSet, DelegatedCgroup, PidsMax,
    };
    use fandhe_container_core::traits::{ContainerId, ErrorCode};
    use std::fs;
    use std::path::PathBuf;

    /// SUP-13・TASK-170.2: `pids.max` の書き込みを実 cgroup のファイル内容で具体値照合する。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn sup13_task170_2_set_pids_max_on_delegated_cgroup() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let id = ContainerId::new(format!("c{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        let (child, proof) = delegated.prepare(&name).expect("prepare");
        delegated
            .enable_controllers(&proof, &ControllerSet::of(&[Controller::Pids]))
            .expect("enable pids controller");
        let file = parent.join(name.as_str()).join("pids.max");
        let read = || fs::read_to_string(&file).expect("read pids.max");

        let limited = PidsMax::count(100).unwrap();
        assert_eq!(child.set_pids_max(&limited), Ok(limited));
        assert_eq!(read().trim_end(), "100");

        let unlimited = PidsMax::unlimited();
        assert_eq!(child.set_pids_max(&unlimited), Ok(unlimited));
        assert_eq!(read().trim_end(), "max");

        // 不正値は構築で拒否され、ファイルは変化しない。
        let err = PidsMax::count(0).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(read().trim_end(), "max");

        delegated.remove_child(&child).expect("remove child cgroup");
    }
}
