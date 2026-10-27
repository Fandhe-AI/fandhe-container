//! OCI `linux.resources` が start の cgroup 連鎖で実 cgroup v2 の制限ファイルへ反映されることの結合試験
//! （CORE-3・CORE-4・SUP-13・SEC-1・TASK-29 追補・#2019）。
//!
//! `parse_config_bytes` で資源つきの config を作り、`ResourceLimitPlan` を載せた `CgroupLimitPlan` で
//! `record_scope` → `create_cgroup` → `apply_limits` → `into_join` を通して、`<委譲パス>/fc-<id>@<n>/` の
//! `memory.max`・`memory.swap.max`・`cpu.max`・`pids.max` を具体値で照合する。環境変数
//! `FANDHE_CONTAINER_TEST_BLOCK_DEVICE`（ディスク全体の `MAJ:MIN`）があれば、`blockIO` の weight と throttle の
//! `io.max` も照合する。最後に delete で cgroup と記録が消えることを確かめる。
//!
//! # 実機前提テストとしての分離
//! `memory`・`cpu`・`pids`（と、デバイス指定時は `io`）が委譲された cgroup v2 サブツリーと、swap accounting
//! （`memory.swap.max` の存在）が要り、GitHub ホステッド runner では保証できないため `#[ignore]` で既定の
//! テスト集合から分離する（AGENTS.md「実機前提テスト」・ci.md）。root は不要。条件が欠ける場合は成功扱いに
//! せず失敗する。自プロセスを cgroup 間で移動するため、1 ファイル 1 テストにする:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_resources_apply --no-run
//! FANDHE_CONTAINER_TEST_BLOCK_DEVICE=8:0 \
//!   systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_resources_apply-XXXX> --ignored
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

    use fandhe_container_core::cgroups::{CgroupLimitPlan, DevicePolicyMode, ResourceLimitPlan};
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{delete, parse_config_bytes};
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerStatus, CreateStateRequest, DeleteRequest, StateStore,
    };
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    /// CORE-3・CORE-4・SUP-13・SEC-1（#2019）: config の `linux.resources` が制限ファイルへ具体値で入り、
    /// delete で消える。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree with memory, cpu, pids (and io with FANDHE_CONTAINER_TEST_BLOCK_DEVICE) and swap accounting"]
    fn core3_core4_sup13_oci_resources_land_in_cgroup_files() {
        let device = std::env::var("FANDHE_CONTAINER_TEST_BLOCK_DEVICE").ok();
        let mut resources = json!({
            "memory": {"limit": 67108864, "swap": 67108864},
            "cpu": {"quota": 50000, "period": 100000},
            "pids": {"limit": 64}
        });
        if let Some(dev) = &device {
            let (major, minor) = dev.split_once(':').expect("MAJ:MIN");
            let major: u32 = major.parse().expect("major");
            let minor: u32 = minor.parse().expect("minor");
            resources["blockIO"] = json!({
                "weight": 500,
                "throttleReadBpsDevice": [{"major": major, "minor": minor, "rate": 1048576}]
            });
        }
        let config = json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs"},
            "process": {"args": ["/bin/true"], "cwd": "/", "user": {"uid": 0, "gid": 0}},
            "linux": {"resources": resources}
        });
        let config = parse_config_bytes(&serde_json::to_vec(&config).expect("serialize"))
            .expect("valid config");
        let limits = config.linux_resources().expect("resources");
        let plan = CgroupLimitPlan::new(DevicePolicyMode::Rootless)
            .with_resources(ResourceLimitPlan::try_from(limits).expect("plan"));

        let delegated = crate::precondition::delegated_cgroup();
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let id = ContainerId::new(format!("r{}", std::process::id())).expect("id");
        let root_dir = std::env::temp_dir().join(format!("fandhe-resources-{}", id.as_str()));
        let _ = fs::remove_dir_all(&root_dir);
        fs::create_dir_all(&root_dir).expect("create state root");
        fs::set_permissions(&root_dir, fs::Permissions::from_mode(0o700)).expect("chmod 0700");
        let store = FileStateStore::open(StateRoot::from_override(root_dir.clone()).expect("root"))
            .expect("open store");
        let created = store
            .create(
                &CreateStateRequest::new(
                    ContainerStatus::created(id.clone(), None),
                    root_dir.join("bundle"),
                )
                .expect("req"),
            )
            .expect("create record");

        let rec = OpRecorder::new();
        let start = delegated
            .record_scope(&store, &created)
            .expect("record_scope")
            .create_cgroup()
            .expect("create_cgroup")
            .apply_limits(&rec, &plan)
            .expect("apply_limits (memory, cpu, pids must be delegated)")
            .into_join()
            .expect("into_join");
        assert!(start.limits().resources.is_some());

        let dir = parent.join(start.cgroup().name().as_str());
        let read = |f: &str| {
            fs::read_to_string(dir.join(f))
                .unwrap_or_else(|e| panic!("read {f}: {e}"))
                .trim_end()
                .to_owned()
        };
        assert_eq!(read("memory.max"), "67108864");
        // OCI の swap は「メモリ + swap」の合計。メモリと同値なので swap 単体は 0。
        assert_eq!(read("memory.swap.max"), "0");
        assert_eq!(read("cpu.max"), "50000 100000");
        assert_eq!(read("pids.max"), "64");
        if let Some(dev) = &device {
            assert_eq!(
                read("io.max"),
                format!("{dev} rbps=1048576 wbps=max riops=max wiops=max")
            );
            // weight 500 の読み戻し。BFQ は数値のみ（500）か `default 500`、`io.weight` は変換後の `default 4950`。
            let (weight_file, expected): (&str, &[&str]) = if dir.join("io.bfq.weight").exists() {
                ("io.bfq.weight", &["500", "default 500"])
            } else {
                ("io.weight", &["default 4950"])
            };
            let first = read(weight_file);
            let line = first.lines().next().unwrap_or("");
            assert!(expected.contains(&line), "{first}");
        }

        drop(start);
        delete(&store, &rec, &delegated, &DeleteRequest::new(id.clone())).expect("delete");
        assert!(!dir.exists(), "cgroup {} remains", dir.display());
        let _ = fs::remove_dir_all(&root_dir);
    }
}
