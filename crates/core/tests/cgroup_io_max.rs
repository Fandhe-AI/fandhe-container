//! `io.max` 設定の結合試験（SUP-13・TASK-170.2・#533）。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（`io` controller 付き）と、対象ブロックデバイス
//! （ディスク全体の `MAJ:MIN`。環境変数 `FANDHE_CONTAINER_TEST_BLOCK_DEVICE`）が必要で、GitHub ホステッド
//! runner では保証できないため `#[ignore]` で既定のテスト集合から分離する（AGENTS.md「実機前提テスト」・
//! ci.md）。環境変数が未設定なら検証せずに成功させず、明確なメッセージで失敗する。自プロセスを cgroup 間で
//! 移動するため、1 ファイル 1 テストにし、`cargo` を経由せずビルド済みのテストバイナリを委譲スコープの中で
//! 直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_io_max --no-run
//! FANDHE_CONTAINER_TEST_BLOCK_DEVICE=8:0 \
//!   systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_io_max-XXXX> --ignored
//! ```

#[cfg(target_os = "linux")]
mod linux {
    use fandhe_container_core::cgroups::{
        BlockDevice, CgroupName, Controller, ControllerSet, DelegatedCgroup, IoLimit, IoMax,
    };
    use fandhe_container_core::traits::{ContainerId, ErrorCode};
    use std::fs;
    use std::path::PathBuf;

    fn device_from_env() -> BlockDevice {
        let raw = std::env::var("FANDHE_CONTAINER_TEST_BLOCK_DEVICE")
            .expect("FANDHE_CONTAINER_TEST_BLOCK_DEVICE=<MAJ:MIN of a whole disk> is required");
        let (major, minor) = raw.split_once(':').expect("expected MAJ:MIN");
        BlockDevice::new(
            major.parse().expect("major must be a number"),
            minor.parse().expect("minor must be a number"),
        )
        .expect("device number in range")
    }

    /// SUP-13・TASK-170.2: `io.max` の書き込みを実 cgroup のファイル内容で具体値照合する。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree with io and FANDHE_CONTAINER_TEST_BLOCK_DEVICE"]
    fn sup13_task170_2_set_io_max_on_delegated_cgroup() {
        let device = device_from_env();
        let token = format!("{}:{}", device.major(), device.minor());
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let id = ContainerId::new(format!("c{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        let (child, proof) = delegated.prepare(&name).expect("prepare");
        delegated
            .enable_controllers(&proof, &ControllerSet::of(&[Controller::Io]))
            .expect("enable io controller");
        let file = parent.join(name.as_str()).join("io.max");
        let read = || fs::read_to_string(&file).expect("read io.max");

        let u = IoLimit::Unlimited;
        let limited = IoMax::new(device, IoLimit::Value(1_048_576), u, u, u).unwrap();
        assert_eq!(
            child.set_io_max(
                &fandhe_container_core::observability::OpRecorder::new(),
                &limited
            ),
            Ok(limited)
        );
        assert_eq!(
            read().trim_end(),
            format!("{token} rbps=1048576 wbps=max riops=max wiops=max")
        );

        // 全項目を既定へ戻すと、カーネルは該当デバイスの行を出力しない。
        let reset = IoMax::new(device, u, u, u, u).unwrap();
        assert_eq!(
            child.set_io_max(
                &fandhe_container_core::observability::OpRecorder::new(),
                &reset
            ),
            Ok(reset)
        );
        assert_eq!(read().trim_end(), "");

        // 不正値は構築で拒否され、ファイルは変化しない。
        let err = IoMax::new(device, IoLimit::Value(0), u, u, u).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(read().trim_end(), "");

        delegated.remove_child(&child).expect("remove child cgroup");
    }
}
