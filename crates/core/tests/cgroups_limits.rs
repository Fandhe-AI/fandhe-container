//! `--cpus` / `--pids-limit` / I/O 制限の相当値から cgroup ファイル内容までの通し結合試験
//! （SUP-13・TASK-170.3・#534・MS-9。REPAIR-12 の機械照合）。
//!
//! 個別機能は `cgroup_cpus_conversion`・`cgroup_cpu_max`・`cgroup_pids_max`・`cgroup_io_max` が担い、
//! 本試験は同一の子 cgroup 上で 4 制限（`cpu.max`・`pids.max`・`io.max`・`io.weight`。TASK-170.4・#1474）が併存し、後から書いた制限が先の制限を壊さないことだけを見る。
//!
//! `--blkio-weight` の書き込み先選択（`io.bfq.weight` があればそちら、無ければ変換して `io.weight`。#1534）も
//! 同じ子 cgroup で `set_blkio_weight` を呼び、通った分岐ごとの具体値を照合する。実機での実行結果
//! （どちらの分岐を通ったか）は #1477（TASK-170.h1・人間担当）に記録する。
//!
//! # 対象外（実装済みを装わない。REPAIR-3）
//! - CLI 引数パーサ・launcher への結線は未実装のため、本試験は公開 API を直接呼ぶ（結線は TASK-29 / TASK-157 系）。
//!
//! # 実機前提テストとしての分離
//! 実 cgroup 版は `cpu`・`pids`・`io` が委譲され `io.weight` を提供するカーネルの cgroup v2 サブツリーと、環境変数
//! `FANDHE_CONTAINER_TEST_BLOCK_DEVICE`（ディスク全体の `MAJ:MIN`）が必要で、GitHub ホステッド runner
//! では保証できないため `#[ignore]` で分離する（AGENTS.md「実機前提テスト」・ci.md）。条件が欠ける場合は
//! 成功扱いにせず、欠けた要素を名指しして失敗する。自プロセスを cgroup 間で移動するため、実機前提テストは
//! 1 件のみとし、ビルド済みバイナリを委譲スコープの中で直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroups_limits --no-run
//! FANDHE_CONTAINER_TEST_BLOCK_DEVICE=8:0 \
//!   systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroups_limits-XXXX> --ignored
//! ```

#[cfg(target_os = "linux")]
mod linux {
    use fandhe_container_core::cgroups::{
        BlkioWeight, BlkioWeightTarget, BlockDevice, CgroupName, Controller, ControllerSet, CpuMax,
        CpuQuota, DelegatedCgroup, IoLimit, IoMax, IoWeight, PidsMax,
    };
    use fandhe_container_core::traits::{ContainerId, ErrorCode};
    use std::fs;
    use std::path::PathBuf;

    /// SUP-13・TASK-170.3: オプション相当値が型つき制限値へ具体値で写ることを既定集合で常時検証する。
    #[test]
    fn sup13_task170_3_option_values_map_to_limits() {
        // --cpus 1.5
        let cpu = CpuMax::parse_cpus("1.5", CpuMax::DEFAULT_PERIOD_US).unwrap();
        assert_eq!(cpu.quota(), CpuQuota::Micros(150_000));
        assert_eq!(cpu.period_us(), 100_000);

        // --pids-limit 100 / -1
        assert_eq!(PidsMax::from_pids_limit(100).unwrap().limit(), Some(100));
        assert_eq!(PidsMax::from_pids_limit(-1).unwrap().limit(), None);
        assert_eq!(PidsMax::from_pids_limit(-1).unwrap(), PidsMax::unlimited());

        // I/O 読み取り 1 MiB/s（8:0 はダミー値でカーネルへは渡さない）
        let u = IoLimit::Unlimited;
        let dev = BlockDevice::new(8, 0).unwrap();
        let io = IoMax::new(dev, IoLimit::Value(1_048_576), u, u, u).unwrap();
        assert_eq!(io.rbps(), IoLimit::Value(1_048_576));
        assert_eq!(io.wbps(), IoLimit::Unlimited);
        assert_eq!(io.riops(), IoLimit::Unlimited);
        assert_eq!(io.wiops(), IoLimit::Unlimited);
        assert_eq!(io.device().major(), 8);
        assert_eq!(io.device().minor(), 0);

        // --blkio-weight 500 / 10 / 1000
        assert_eq!(IoWeight::from_blkio_weight(500).unwrap().weight(), 4950);
        assert_eq!(IoWeight::from_blkio_weight(10).unwrap().weight(), 1);
        assert_eq!(IoWeight::from_blkio_weight(1000).unwrap().weight(), 10_000);

        // --blkio-weight の型（io.bfq.weight があるときは無変換で書く。#1534）
        assert_eq!(BlkioWeight::new(500).unwrap().weight(), 500);
        assert_eq!(BlkioWeight::new(10).unwrap().weight(), 10);
        assert_eq!(BlkioWeight::new(1000).unwrap().weight(), 1000);

        // 不正値はいずれも InvalidArgument
        let errs = [
            CpuMax::parse_cpus("0", CpuMax::DEFAULT_PERIOD_US).unwrap_err(),
            PidsMax::from_pids_limit(0).unwrap_err(),
            PidsMax::from_pids_limit(-2).unwrap_err(),
            IoMax::new(dev, IoLimit::Value(0), u, u, u).unwrap_err(),
            IoWeight::from_blkio_weight(0).unwrap_err(),
            IoWeight::from_blkio_weight(1001).unwrap_err(),
            BlkioWeight::new(0).unwrap_err(),
            BlkioWeight::new(1001).unwrap_err(),
        ];
        for err in errs {
            assert_eq!(err.code, ErrorCode::InvalidArgument);
        }
    }

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

    /// SUP-13・TASK-170.3: 3 制限を同一の子 cgroup へ書き、実ファイルの内容を具体値で照合する。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree with cpu, pids, io and FANDHE_CONTAINER_TEST_BLOCK_DEVICE"]
    fn sup13_task170_3_all_limits_on_delegated_cgroup() {
        let device = device_from_env();
        let token = format!("{}:{}", device.major(), device.minor());
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let needed = [Controller::Cpu, Controller::Pids, Controller::Io];
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        // 名前に PID を含むため、アサーション失敗で子 cgroup が残っても次回実行とは衝突しない。
        let id = ContainerId::new(format!("c{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        let (child, proof) = delegated.prepare(&name).expect("prepare");
        // 未委譲の controller があればここで失敗する（成功扱いにしない）。
        delegated
            .enable_controllers(&proof, &ControllerSet::of(&needed))
            .expect("enable cpu, pids and io controllers (all must be delegated)");
        let dir = parent.join(name.as_str());
        let read = |f: &str| fs::read_to_string(dir.join(f)).expect("read cgroup file");

        let u = IoLimit::Unlimited;
        let cpu = CpuMax::parse_cpus("1.5", CpuMax::DEFAULT_PERIOD_US).unwrap();
        let pids = PidsMax::from_pids_limit(100).unwrap();
        let io = IoMax::new(device, IoLimit::Value(1_048_576), u, u, u).unwrap();
        assert_eq!(child.set_cpu_max(&cpu), Ok(cpu));
        assert_eq!(child.set_pids_max(&pids), Ok(pids));
        assert_eq!(child.set_io_max(&io), Ok(io));
        let weight = IoWeight::from_blkio_weight(500).unwrap();
        assert_eq!(
            child.set_io_weight(
                &fandhe_container_core::observability::OpRecorder::new(),
                &weight
            ),
            Ok(weight)
        );

        // 4 つすべてを書いた後に照合し、後続の書き込みが先の制限を壊していないことを確認する。
        let io_line = format!("{token} rbps=1048576 wbps=max riops=max wiops=max");
        assert_eq!(read("cpu.max").trim_end(), "150000 100000");
        assert_eq!(read("pids.max").trim_end(), "100");
        assert_eq!(read("io.max").trim_end(), io_line);
        assert_eq!(
            read("io.weight").lines().next().map(str::trim_end),
            Some("default 4950")
        );

        // --blkio-weight 500 の書き込み先選択（#1534）。通った分岐は #1477 の実行記録に残す。
        let recorder = fandhe_container_core::observability::OpRecorder::new();
        match child
            .set_blkio_weight(&recorder, &BlkioWeight::new(500).unwrap())
            .expect("set_blkio_weight")
        {
            BlkioWeightTarget::Bfq(w) => {
                eprintln!("set_blkio_weight: wrote io.bfq.weight");
                assert_eq!(w.weight(), 500);
                let first = read("io.bfq.weight")
                    .lines()
                    .next()
                    .map(|l| l.trim_end().to_string());
                assert!(
                    matches!(first.as_deref(), Some("default 500" | "500")),
                    "{first:?}"
                );
                // io.weight は直前の set_io_weight の値のまま
                assert_eq!(
                    read("io.weight").lines().next().map(str::trim_end),
                    Some("default 4950")
                );
            }
            BlkioWeightTarget::IoWeight(w) => {
                eprintln!("set_blkio_weight: wrote io.weight (no io.bfq.weight)");
                assert_eq!(w.weight(), 4950);
                assert!(!dir.join("io.bfq.weight").exists());
            }
            other => panic!("unexpected target: {other:?}"),
        }

        // 無制限側: pids と io を戻しても cpu.max は変化しない。
        let unlimited = PidsMax::from_pids_limit(-1).unwrap();
        let reset = IoMax::new(device, u, u, u, u).unwrap();
        assert_eq!(child.set_pids_max(&unlimited), Ok(unlimited));
        assert_eq!(child.set_io_max(&reset), Ok(reset));
        assert_eq!(read("cpu.max").trim_end(), "150000 100000");
        assert_eq!(read("pids.max").trim_end(), "max");
        assert_eq!(read("io.max").trim_end(), "");
        assert_eq!(
            read("io.weight").lines().next().map(str::trim_end),
            Some("default 4950")
        );
        let default_weight = IoWeight::default();
        assert_eq!(
            child.set_io_weight(
                &fandhe_container_core::observability::OpRecorder::new(),
                &default_weight
            ),
            Ok(default_weight)
        );
        assert_eq!(
            read("io.weight").lines().next().map(str::trim_end),
            Some("default 100")
        );

        // 不正値は構築で拒否され、ファイルは変化しない。
        let err = PidsMax::from_pids_limit(0).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        let err = IoMax::new(device, IoLimit::Value(0), u, u, u).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        let err = CpuMax::parse_cpus("0", CpuMax::DEFAULT_PERIOD_US).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        let err = IoWeight::from_blkio_weight(0).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(
            read("io.weight").lines().next().map(str::trim_end),
            Some("default 100")
        );
        assert_eq!(read("cpu.max").trim_end(), "150000 100000");
        assert_eq!(read("pids.max").trim_end(), "max");
        assert_eq!(read("io.max").trim_end(), "");

        delegated.remove_child(&child).expect("remove child cgroup");
    }
}
