//! `apply_default_device_policy` の rootless 経路の結合試験（SEC-1・SEC-5・TASK-32 追補・MS-2・#1680）。
//!
//! # 実機前提テストとしての分離
//! `ContainerCgroup` は委譲された cgroup v2 サブツリーでしか作れず、GitHub ホステッド runner では保証
//! できないため `#[ignore]` で既定のテスト集合から分離する（AGENTS.md「実機前提テスト」・ci.md）。
//! 自プロセスを cgroup 間で移動するため 1 ファイル 1 テストにし、`cargo` を経由せずビルド済みの
//! テストバイナリを**非 root ユーザー**の委譲スコープの中で直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_device_policy_rootless --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_device_policy_rootless-XXXX> --ignored
//! ```
//!
//! 公開入口を本番ビルド（`cfg(test)` の差し込みなし）で通す。rootless では `bpf(2)` を呼ばないため
//! 特権なしで結果型を具体値照合できる。root・`Rootful` の経路は `cgroup_device_policy_rootful.rs`。
//!
//! 「`bpf(2)` を呼ばない」ことの証拠として、同じ非 root のプロセスで `Rootful` を申告した対照を足す（#1681）。
//! 非 root ではどの `bpf(2)` も `EPERM` になり、`Rootful` の入口は最初の `BPF_PROG_QUERY` の `EPERM` を
//! `PermissionDenied`（段は `QueryDeviceProgram`）の `Err` に写す。したがって `Rootless` が `Ok` を返したことは、
//! `bpf(2)` を呼んでいない（呼んでいれば同じ `EPERM` が `Err` になる）ことを意味する。

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

    use fandhe_container_core::cgroups::{
        CgroupName, CgroupStep, DevicePolicyMode, DevicePolicyNotApplied, DevicePolicyOutcome,
    };
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::traits::{ContainerId, ErrorCode};

    /// `/proc/self/status` の実効 UID（`Uid:` 行の 3 番目の値）。
    fn euid() -> u32 {
        let status = std::fs::read_to_string("/proc/self/status").expect("read status");
        let line = status
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .expect("Uid line");
        line.split_whitespace()
            .nth(2)
            .expect("effective uid column")
            .parse()
            .expect("numeric uid")
    }

    /// SEC-1・SEC-5: rootless 申告では適用せず `NotApplied(Rootless)` を返す（失敗にしない）。
    #[test]
    #[ignore = "requires a non-root user with a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn sec1_task32_apply_default_device_policy_rootless_is_not_applied() {
        assert_ne!(euid(), 0, "this test must run as a non-root user");
        let delegated = crate::precondition::delegated_cgroup();
        let id = ContainerId::new(format!("dp{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        let (child, _proof) = delegated.prepare(&name).expect("prepare");

        let outcome = child
            .apply_default_device_policy(&OpRecorder::new(), DevicePolicyMode::Rootless)
            .expect("rootless apply returns Ok");
        assert_eq!(
            outcome,
            DevicePolicyOutcome::NotApplied(DevicePolicyNotApplied::Rootless)
        );

        // 対照: 同じ非 root で Rootful を申告すると bpf(2) の EPERM が Err になる。
        let err = child
            .apply_default_device_policy(&OpRecorder::new(), DevicePolicyMode::Rootful)
            .expect_err("rootful apply as non-root must fail with EPERM");
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(err.step, CgroupStep::QueryDeviceProgram);

        delegated.remove_child(&child).expect("remove child cgroup");
    }
}
