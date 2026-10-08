//! `memory.max` / `memory.swap.max` 設定の結合試験（CORE-3・TASK-32.2・#159）。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（`memory` controller 委譲・swap accounting 有効）が
//! 必要で、GitHub ホステッド runner では保証できないため `#[ignore]` で既定のテスト集合から分離する
//! （AGENTS.md「実機前提テスト」・ci.md）。自プロセスを cgroup 間で移動するため 1 ファイル 1 テストにし、
//! `cargo` を経由せずビルド済みバイナリを委譲スコープ内で直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_memory --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_memory-XXXX> --ignored
//! ```

#[cfg(target_os = "linux")]
mod linux {
    use fandhe_container_core::cgroups::{
        CgroupName, Controller, ControllerSet, DelegatedCgroup, MemoryLimit, MemoryLimits,
    };
    use fandhe_container_core::traits::{ContainerId, ErrorCode};
    use std::fs;
    use std::path::PathBuf;

    fn read(p: &std::path::Path) -> String {
        fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    /// CORE-3: 64 MiB の `memory.max` と `memory.swap.max=0` が実 cgroup に書かれ、不正値は書き込み前に拒否される。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn core3_task32_2_set_memory_limits_on_delegated_cgroup() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let id = ContainerId::new(format!("m{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        let (child, proof) = delegated.prepare(&name).expect("prepare");
        let enabled = delegated
            .enable_controllers(&proof, &ControllerSet::of(&[Controller::Memory]))
            .expect("enable memory controller");

        let limits = MemoryLimits {
            memory_max: MemoryLimit::parse("64M").expect("parse 64M"),
            swap_max: Some(MemoryLimit::Bytes(0)),
        };
        let applied = child
            .set_memory_limits(
                &fandhe_container_core::observability::OpRecorder::new(),
                &enabled,
                &limits,
            )
            .expect("set memory limits");
        let dir = parent.join(name.as_str());
        assert_eq!(read(&dir.join("memory.max")).trim(), "67108864");
        assert_eq!(read(&dir.join("memory.swap.max")).trim(), "0");
        assert_eq!(applied.memory_max, MemoryLimit::Bytes(67_108_864));
        assert_eq!(applied.swap_max, Some(MemoryLimit::Bytes(0)));

        // 不正値は書き込み前に拒否され、ファイル内容は変わらない。`Bytes(u64)` は直接構築できるため、
        // 範囲外（i64::MAX 超）を設定 API へ渡して検証する。memory.max / memory.swap.max の
        // どちらに不正値があっても、両ファイルとも元の値のまま（部分書き込みなし）であること。
        let too_big = MemoryLimit::Bytes(i64::MAX as u64 + 1);
        let invalid_requests = [
            MemoryLimits {
                memory_max: too_big,
                swap_max: Some(MemoryLimit::Bytes(0)),
            },
            MemoryLimits {
                memory_max: MemoryLimit::Bytes(33_554_432),
                swap_max: Some(too_big),
            },
        ];
        for bad in &invalid_requests {
            let err = child
                .set_memory_limits(
                    &fandhe_container_core::observability::OpRecorder::new(),
                    &enabled,
                    bad,
                )
                .expect_err("out-of-range limit must be rejected");
            assert_eq!(err.code, ErrorCode::InvalidArgument);
            assert_eq!(read(&dir.join("memory.max")).trim(), "67108864");
            assert_eq!(read(&dir.join("memory.swap.max")).trim(), "0");
        }

        delegated.remove_child(&child).expect("remove child cgroup");
        assert!(!dir.exists());
    }
}
