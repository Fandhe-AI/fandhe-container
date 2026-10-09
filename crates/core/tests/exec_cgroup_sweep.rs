//! 残った exec 用の子 cgroup の掃除の結合試験（SUP-6・OCI-6・CORE-4・TASK-163 追補・TASK-30・#1596）。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（Linux 5.14 以降の `cgroup.kill`）と util-linux の `setpriv`
//! が必要で、GitHub ホステッド runner では保証できないため `#[ignore]` で既定のテスト集合から分離する
//! （AGENTS.md「実機前提テスト」・ci.md）。自プロセスを cgroup 間で移動するため、ビルド済みのテストバイナリを
//! 委譲スコープの中で直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test exec_cgroup_sweep --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/exec_cgroup_sweep-XXXX> --ignored
//! ```
//!
//! 照合するのは、(1) exec 開始時の掃除が空で持ち主の居ない `exec-*` だけを消し、持ち主が生きているもの・
//! プロセスの居るものを残す、(2) delete 前の掃除（`ContainerCgroupRemover::remove`）が空のものとプロセスの
//! 居るものを両方消し、コンテナ cgroup の削除が成功し、その件数が注入した記録器に載る、の 2 点。

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::{CgroupName, DelegatedCgroup};
    use fandhe_container_core::exec::{
        ExecCgroupName, ExecChildCgroup, sweep_stale_exec_child_cgroups_in,
    };
    use fandhe_container_core::observability::{OpName, OpRecorder};
    use fandhe_container_core::oci_runtime::{CgroupRemoval, ContainerCgroupRemover};
    use fandhe_container_core::traits::{ContainerId, StateRevision};

    fn pids_in(dir: &Path) -> Vec<u32> {
        fs::read_to_string(dir.join("cgroup.procs"))
            .map(|t| t.lines().filter_map(|l| l.trim().parse().ok()).collect())
            .unwrap_or_default()
    }

    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn pid_exists(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
            && fs::read_to_string(format!("/proc/{pid}/stat"))
                .map(|s| !s.contains(") Z "))
                .unwrap_or(false)
    }

    /// 子 cgroup へ入ってから、親死亡シグナルを解除したコマンドとして「直接の子 1 + 二重 fork して `setsid`
    /// した子孫 + バックグラウンドの子孫」を起動する（`exec_cgroup_kill` と同じ）。
    fn spawn_stubborn_command(exec_dir: &Path) -> Child {
        let script = concat!(
            "echo 0 > \"$1/cgroup.procs\" && ",
            "exec setpriv --pdeathsig clear sh -c '",
            "(setsid sleep 300 </dev/null >/dev/null 2>&1 &); ",
            "sleep 300 </dev/null >/dev/null 2>&1 & ",
            "exec sleep 300'"
        );
        Command::new("sh")
            .args(["-c", script, "sh"])
            .arg(exec_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the stubborn command")
    }

    /// SUP-6・OCI-6・#1596: exec 開始時の掃除と delete 前の掃除の通し。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree (systemd-run --user --scope -p Delegate=yes)"]
    fn sup6_stale_exec_child_cgroups_are_swept_on_exec_start_and_before_delete() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let delegated_path = delegated.path().to_owned();
        let base = PathBuf::from("/sys/fs/cgroup").join(delegated_path.trim_start_matches('/'));
        let id = ContainerId::new(format!("c{}", std::process::id())).unwrap();
        let instance = StateRevision::from_raw(7);
        let name = CgroupName::for_instance(&id, instance).unwrap();
        let (_container, _proof) = delegated.prepare(&name).expect("prepare");
        let container_dir = base.join(name.as_str());
        let container_path = format!("{}/{}", delegated_path.trim_end_matches('/'), name.as_str());

        let make = |exec_name: &str| {
            let exec_name = ExecCgroupName::new(exec_name).unwrap();
            let cg = ExecChildCgroup::create_in_path_for_test(&container_path, &exec_name)
                .expect("create exec child cgroup");
            (container_dir.join(exec_name.as_str()), cg)
        };
        // A: 空で自分の pid（過去の残骸）、B: 空で存在しない pid、C: 空で pid 1（持ち主が生きている）、
        // D: プロセスの居る残骸。
        let (a, _ka) = make(&format!("exec-{}-900", std::process::id()));
        let (b, _kb) = make("exec-2147483647-0");
        let (c, _kc) = make("exec-1-0");
        let (d, _kd) = make("exec-2147483646-0");
        let mut command = spawn_stubborn_command(&d);
        wait_until("three processes in D", || pids_in(&d).len() == 3);
        let members = pids_in(&d);

        // (1) exec 開始時の掃除: A・B だけが消え、C（持ち主が生きている）と D（プロセスが居る）は残る。
        let swept =
            sweep_stale_exec_child_cgroups_in(&container_path).expect("sweep on exec start");
        assert_eq!(swept.removed, 2);
        assert_eq!(swept.left_populated, 1);
        assert_eq!(swept.left_owner_alive, 1);
        assert_eq!(swept.failed, 0);
        assert!(!swept.truncated);
        assert!(!a.exists() && !b.exists());
        assert!(c.is_dir() && d.is_dir());
        assert!(members.iter().all(|p| pid_exists(*p)), "D must stay alive");

        // (2) delete 前の掃除: 空の C もプロセスの居る D も消え、コンテナ cgroup の削除が成功する。
        // 件数は delete が注入する記録器へ載る（REPAIR-4: removed 2・failed 0）。
        let recorder = OpRecorder::new();
        assert_eq!(
            delegated
                .remove_with_recorder(&id, instance, &recorder)
                .expect("remove"),
            CgroupRemoval::Removed
        );
        let counts = |n: &str| {
            let s = recorder
                .snapshot_op(&OpName::new(n).unwrap())
                .expect("recorded");
            (s.success(), s.failure())
        };
        assert_eq!(counts("exec_cgroup_sweep_kill_all"), (1, 0));
        assert_eq!(counts("exec_cgroup_sweep_kill_all_child"), (2, 0));
        assert!(!container_dir.exists());
        let _ = command.wait();
        wait_until("all processes of D to be gone", || {
            members.iter().all(|p| !pid_exists(*p))
        });
        assert_eq!(
            delegated.remove(&id, instance).expect("second remove"),
            CgroupRemoval::NotPresent
        );
    }
}
