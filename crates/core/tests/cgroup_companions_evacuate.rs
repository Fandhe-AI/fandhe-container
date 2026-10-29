//! 同伴プロセス（companions）を伴う委譲 cgroup の退避の結合試験（SUP-1・CORE-3・#2058）。
//!
//! # 実機前提テストとしての分離
//! 委譲された cgroup v2 サブツリーが必要で、GitHub ホステッド runner では保証できないため `#[ignore]` で
//! 既定のテスト集合から分離する。自プロセスを cgroup 間で移動するため 1 ファイル 1 テストにし、
//! ビルド済みバイナリを委譲スコープの中で直接実行する（`cgroup_delegation.rs` と同じ手順）:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_companions_evacuate --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_companions_evacuate-XXXX> --ignored
//! ```

#[path = "support/reap.rs"]
mod reap;

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
    use fandhe_container_core::traits::ContainerId;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn read(p: &Path) -> String {
        std::fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    /// SUP-1・CORE-3: 宣言した helper は自プロセスと一緒に退避リーフ fc-runtime へ移り、親は空になる。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn sup1_core3_declared_companion_is_evacuated_with_self() {
        let mut helper = Command::new("sleep")
            .arg("300")
            .spawn()
            .expect("spawn sleep");
        let delegated = crate::precondition::delegated_cgroup().with_companions(&[helper.id()]);
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let id = ContainerId::new(format!("c{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        let (child, _proof) = delegated.prepare(&name).expect("prepare with companion");

        let leaf = read(&parent.join("fc-runtime").join("cgroup.procs"));
        let pids: Vec<u32> = leaf.lines().map(|l| l.trim().parse().unwrap()).collect();
        assert!(pids.contains(&std::process::id()), "{pids:?}");
        assert!(pids.contains(&helper.id()), "{pids:?}");
        assert_eq!(read(&parent.join("cgroup.procs")).trim(), "");
        assert_eq!(
            read(
                &Path::new("/proc")
                    .join(helper.id().to_string())
                    .join("cgroup")
            )
            .trim_end(),
            format!("0::{}/fc-runtime", delegated.path())
        );

        delegated.remove_child(&child).expect("remove child");
        crate::reap::reap(&mut helper, crate::reap::reap_within()).expect("reap helper");
    }
}
