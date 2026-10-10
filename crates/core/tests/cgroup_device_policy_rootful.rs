//! `apply_default_device_policy` の rootful 経路の結合試験（SEC-1・CORE-4・TASK-32 追補・MS-2・#1680）。
//!
//! # 実機前提テストとしての分離
//! root（init user namespace の `CAP_BPF`+`CAP_NET_ADMIN` か `CAP_SYS_ADMIN`）・cgroup v2・`bpf(2)` の
//! `BPF_PROG_TYPE_CGROUP_DEVICE` 対応カーネルが必要で、GitHub ホステッド runner では保証できないため
//! `#[ignore]` で既定のテスト集合から分離する（AGENTS.md「実機前提テスト」・ci.md）。root 権限コマンドは
//! ユーザーの明示指示のもとで実機担当が実行する。自プロセスを cgroup 間で移動するため 1 ファイル
//! 1 テストにし、ビルド済みのテストバイナリを root の systemd scope 内で直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_device_policy_rootful --no-run
//! sudo systemd-run --scope -p Delegate=yes <target/debug/deps/cgroup_device_policy_rootful-XXXX> --ignored
//! ```
//!
//! 公開入口を本番ビルド（`cfg(test)` の差し込みなし）で通し、実際の `bpf(2)` で付いたこと
//! （プログラム ID・attach flags 0）と、二重適用の拒否を具体値照合する。

#[cfg(target_os = "linux")]
mod linux {
    use fandhe_container_core::cgroups::{
        CgroupName, DelegatedCgroup, DevicePolicyMode, DevicePolicyOutcome,
    };
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::traits::{ContainerId, ErrorCode};

    /// SEC-1: `Rootful` で既定のデバイス許可プログラムが付き、2 回目は置き換えず拒否される。
    /// euid 0 での `Rootless` 申告は何も呼ばず拒否される（整合ガード）。
    #[test]
    #[ignore = "requires root with CAP_BPF+CAP_NET_ADMIN (or CAP_SYS_ADMIN), cgroup v2 and bpf(2) cgroup-device support (sudo systemd-run --scope -p Delegate=yes)"]
    fn sec1_task32_apply_default_device_policy_rootful_attaches_once() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let id = ContainerId::new(format!("dp{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        let (child, _proof) = delegated.prepare(&name).expect("prepare");
        let recorder = OpRecorder::new();

        let outcome = child
            .apply_default_device_policy(&recorder, DevicePolicyMode::Rootful)
            .expect("rootful apply attaches the program");
        match outcome {
            DevicePolicyOutcome::Applied(applied) => {
                assert_eq!(applied.attach_flags(), 0);
                assert_ne!(applied.prog_id(), 0);
            }
            other => panic!("expected Applied, got {other:?}"),
        }

        // 既にプログラムがある cgroup への再適用は黙って置き換えず拒否する。
        let err = child
            .apply_default_device_policy(&recorder, DevicePolicyMode::Rootful)
            .expect_err("second apply is refused");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);

        // euid 0 での Rootless 申告は不整合として拒否する。
        let err = child
            .apply_default_device_policy(&recorder, DevicePolicyMode::Rootless)
            .expect_err("rootless declared as root is refused");
        assert_eq!(err.code, ErrorCode::FailedPrecondition);

        delegated.remove_child(&child).expect("remove child cgroup");
    }
}
