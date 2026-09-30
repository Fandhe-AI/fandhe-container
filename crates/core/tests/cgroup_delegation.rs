//! 委譲 cgroup 検出・子 cgroup 作成の結合試験（CORE-3・TASK-32.1・#158）。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリーが必要で、GitHub ホステッド runner では保証できない
//! ため `#[ignore]` で既定のテスト集合から分離する（AGENTS.md「実機前提テスト」・ci.md）。
//! 自プロセスを cgroup 間で移動するため、1 ファイル 1 テストにして同一バイナリ内の並行テストへ
//! 影響させない。親 cgroup に他のプロセスがいると `prepare` は他者を動かさず失敗するため、
//! `cargo` を経由せず、ビルド済みのテストバイナリを委譲スコープの中で直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_delegation --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_delegation-XXXX> --ignored
//! ```

#[cfg(target_os = "linux")]
mod linux {
    use fandhe_container_core::cgroups::{CgroupName, Controller, ControllerSet, DelegatedCgroup};
    use fandhe_container_core::traits::ContainerId;
    use std::fs;
    use std::path::PathBuf;

    fn read(p: &std::path::Path) -> String {
        fs::read_to_string(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    /// CORE-3: 検出 → 子作成 → 退避検証 → controller 有効化を、実 cgroup の状態で具体値照合する。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn core3_task32_1_detect_prepare_enable_on_delegated_cgroup() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        assert!(delegated.controllers().contains(Controller::Memory));
        assert!(delegated.controllers().contains(Controller::Cpu));

        let id = ContainerId::new(format!("t{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        let (child, proof) = delegated.prepare(&name).expect("prepare");

        // AC1: コンテナ用子 cgroup が作成されている。
        assert!(parent.join(name.as_str()).is_dir());
        // AC2: 自プロセスは退避リーフにいて、親とコンテナ用子 cgroup は空。
        let self_cgroup = read(std::path::Path::new("/proc/self/cgroup"));
        assert_eq!(
            self_cgroup.trim_end(),
            format!("0::{}/fc-runtime", delegated.path())
        );
        assert_eq!(read(&parent.join("cgroup.procs")).trim(), "");
        assert_eq!(
            read(&parent.join(name.as_str()).join("cgroup.procs")).trim(),
            ""
        );

        // 退避後に controller を有効化できる。
        let want = ControllerSet::of(&[Controller::Memory, Controller::Cpu]);
        let enabled = delegated
            .enable_controllers(&proof, &want)
            .expect("enable controllers");
        for c in want.iter() {
            assert!(enabled.contains(c), "{c:?} missing from {enabled:?}");
        }
        let subtree = read(&parent.join("cgroup.subtree_control"));
        assert!(
            subtree.contains("memory") && subtree.contains("cpu"),
            "{subtree}"
        );
        assert!(parent.join(name.as_str()).join("memory.max").exists());

        // 後始末。退避リーフは自プロセスが入っているため削除せず、スコープ終了時に回収される。
        // 削除は保持 fd 経由の `cgroup.events` が ENOENT（削除済み）のときだけ成功する。
        delegated.remove_child(&child).expect("remove child cgroup");
        assert!(!parent.join(name.as_str()).exists());
    }
}
