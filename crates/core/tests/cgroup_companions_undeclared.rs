//! 未宣言プロセスが親 cgroup にいる場合の拒否の結合試験（SUP-1・CORE-4・#2058）。
//!
//! # 実機前提テストとしての分離
//! 委譲された cgroup v2 サブツリーが必要で、GitHub ホステッド runner では保証できないため `#[ignore]` で
//! 既定のテスト集合から分離する。ビルド済みバイナリを委譲スコープの中で直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_companions_undeclared --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_companions_undeclared-XXXX> --ignored
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

    use fandhe_container_core::cgroups::{CgroupName, CgroupStep};
    use fandhe_container_core::traits::{ContainerId, ErrorCode};
    use std::path::PathBuf;
    use std::process::Command;

    /// SUP-1・CORE-4: 宣言していない他プロセスが親にいると拒否し、誰も動かさず何も作らない。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn sup1_core4_undeclared_process_is_refused_and_not_moved() {
        let mut other = Command::new("sleep")
            .arg("300")
            .spawn()
            .expect("spawn sleep");
        // 宣言する PID は別物（存在しない値）。other は未宣言のまま。
        let delegated = crate::precondition::delegated_cgroup().with_companions(&[u32::MAX - 1]);
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let id = ContainerId::new(format!("u{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();

        let Err(e) = delegated.prepare(&name) else {
            panic!("must refuse");
        };
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.step, CgroupStep::Evacuate);
        assert!(e.message.contains("other processes"), "{}", e.message);

        let procs = std::fs::read_to_string(parent.join("cgroup.procs")).unwrap();
        let pids: Vec<u32> = procs.lines().map(|l| l.trim().parse().unwrap()).collect();
        assert!(pids.contains(&other.id()), "{pids:?}");
        assert!(pids.contains(&std::process::id()), "{pids:?}");
        assert!(!parent.join(name.as_str()).exists());
        assert!(!parent.join("fc-runtime").exists());
        let _ = other.kill();
        let _ = other.wait();
    }
}
