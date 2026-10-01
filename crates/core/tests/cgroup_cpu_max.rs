//! `cpu.max` 設定の結合試験（CORE-3・TASK-32.3・#160）。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（`cpu` controller 付き）が必要で、GitHub ホステッド
//! runner では保証できないため `#[ignore]` で既定のテスト集合から分離する（AGENTS.md「実機前提テスト」・
//! ci.md）。自プロセスを cgroup 間で移動するため、1 ファイル 1 テストにし、`cargo` を経由せず
//! ビルド済みのテストバイナリを委譲スコープの中で直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_cpu_max --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_cpu_max-XXXX> --ignored
//! ```

#[cfg(target_os = "linux")]
mod linux {
    use fandhe_container_core::cgroups::{
        CgroupName, Controller, ControllerSet, CpuMax, CpuQuota, DelegatedCgroup,
    };
    use fandhe_container_core::traits::{ContainerId, ErrorCode};
    use std::fs;
    use std::path::PathBuf;

    /// CORE-3・TASK-32.3: `cpu.max` の書き込みを実 cgroup のファイル内容で具体値照合する。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn core3_task32_3_set_cpu_max_on_delegated_cgroup() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let id = ContainerId::new(format!("c{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        let (child, proof) = delegated.prepare(&name).expect("prepare");
        delegated
            .enable_controllers(&proof, &ControllerSet::of(&[Controller::Cpu]))
            .expect("enable cpu controller");
        let file = parent.join(name.as_str()).join("cpu.max");
        let read = || fs::read_to_string(&file).expect("read cpu.max");

        let limited = CpuMax::new(CpuQuota::Micros(50_000), 100_000).unwrap();
        assert_eq!(child.set_cpu_max(&limited), Ok(limited));
        assert_eq!(read().trim_end(), "50000 100000");

        let unlimited = CpuMax::new(CpuQuota::Unlimited, 100_000).unwrap();
        assert_eq!(child.set_cpu_max(&unlimited), Ok(unlimited));
        assert_eq!(read().trim_end(), "max 100000");

        // 不正値は構築で拒否され、ファイルは変化しない。
        let err = CpuMax::new(CpuQuota::Micros(50_000), 0).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(read().trim_end(), "max 100000");

        delegated.remove_child(&child).expect("remove child cgroup");
    }
}
