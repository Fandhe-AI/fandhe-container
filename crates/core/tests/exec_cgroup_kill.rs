//! exec 用の子 cgroup と `cgroup.kill` の結合試験（SUP-6・SUP-4・REPAIR-5・CORE-4・TASK-163 追補・#1466）。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（`pids` controller 付き・Linux 5.14 以降の `cgroup.kill`）と
//! util-linux の `setpriv` が必要で、GitHub ホステッド runner では保証できないため `#[ignore]` で既定のテスト
//! 集合から分離する（AGENTS.md「実機前提テスト」・ci.md）。自プロセスを cgroup 間で移動するため、`cargo` を
//! 経由せずビルド済みのテストバイナリを委譲スコープの中で直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test exec_cgroup_kill --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/exec_cgroup_kill-XXXX> --ignored
//! ```
//!
//! 照合するのは、(1) 親死亡シグナルを解除したコマンドと二重 fork（`setsid`）した子孫が `cgroup.kill` で全て
//! 止まり子 cgroup が削除される、(2) 直接の子だけを `SIGKILL` しても子孫は残る（対照。テストが識別的であること）、
//! (3) 親 cgroup の `pids.max` が子 cgroup のプロセスにも掛かる、(4) 後始末が冪等、の 4 点。コマンドの子 cgroup への
//! 参加は fork した子が `cgroup.procs` へ `0` を書く操作で、ここではシェルが同じ書き込みを行って再現する
//! （`spawn_exec_command` の子での参加は、root を要する `fandhe-container-supervisor` の `tests/exec.rs` が通す）。

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::{
        CgroupName, Controller, ControllerSet, DelegatedCgroup, PidsMax,
    };
    use fandhe_container_core::exec::{
        ExecCgroupName, ExecCgroupRemoval, ExecChildCgroup, remove_exec_child_cgroup_in,
    };
    use fandhe_container_core::traits::ContainerId;

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

    /// 子 cgroup へ入ってから、親死亡シグナルを解除したコマンド（`setpriv --pdeathsig clear`）として
    /// 「直接の子 1 + 二重 fork して `setsid` した子孫 + バックグラウンドの子孫」を起動する。
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

    fn pid_exists(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
            && fs::read_to_string(format!("/proc/{pid}/stat"))
                .map(|s| !s.contains(") Z "))
                .unwrap_or(false)
    }

    /// SUP-6・SUP-4・REPAIR-5・CORE-4・TASK-163 追補・#1466: exec 用の子 cgroup と `cgroup.kill` の通し。
    #[test]
    #[ignore = "requires a delegated cgroup v2 subtree with pids controller (systemd-run --user --scope -p Delegate=yes)"]
    fn sup6_exec_child_cgroup_kills_descendants_and_is_removed() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup");
        let delegated_path = delegated.path();
        let base = PathBuf::from("/sys/fs/cgroup").join(delegated_path.trim_start_matches('/'));
        let id = ContainerId::new(format!("c{}", std::process::id())).unwrap();
        let name = CgroupName::new(&id).unwrap();
        let (container, proof) = delegated.prepare(&name).expect("prepare");
        delegated
            .enable_controllers(&proof, &ControllerSet::of(&[Controller::Pids]))
            .expect("enable pids controller");
        let container_dir = base.join(name.as_str());
        let container_path = format!("{}/{}", delegated_path.trim_end_matches('/'), name.as_str());

        // (1)(2) 作成 → 参加 → 対照（直接の子だけを kill しても子孫は残る）→ cgroup.kill → 削除。
        let exec_name = ExecCgroupName::unique();
        let exec = ExecChildCgroup::create_in_path_for_test(&container_path, &exec_name)
            .expect("create exec child cgroup");
        let exec_dir = container_dir.join(exec_name.as_str());
        assert!(exec_dir.is_dir());
        // 内部プロセス禁止規則: コンテナ cgroup・子 cgroup とも controller を有効化しない。
        for dir in [&container_dir, &exec_dir] {
            assert_eq!(
                fs::read_to_string(dir.join("cgroup.subtree_control")).unwrap(),
                "",
                "{dir:?}"
            );
        }
        let mut command = spawn_stubborn_command(&exec_dir);
        wait_until("three processes in the exec child cgroup", || {
            pids_in(&exec_dir).len() == 3
        });
        let members = pids_in(&exec_dir);
        assert!(members.contains(&command.id()));

        command.kill().expect("kill the direct child only");
        command.wait().expect("reap the direct child");
        wait_until("the direct child to leave the cgroup", || {
            !pids_in(&exec_dir).contains(&command.id())
        });
        assert_eq!(
            pids_in(&exec_dir).len(),
            2,
            "descendants must survive a kill of the direct child only"
        );

        exec.kill_all().expect("cgroup.kill");
        wait_until("the exec child cgroup to be empty", || {
            pids_in(&exec_dir).is_empty()
        });
        wait_until("all descendants to be gone", || {
            members.iter().all(|p| !pid_exists(*p))
        });
        assert_eq!(
            remove_exec_child_cgroup_in(&container_path, &exec_name, Duration::from_secs(5))
                .unwrap(),
            ExecCgroupRemoval::Removed
        );
        assert!(!exec_dir.exists());
        // (4) 冪等: 削除済みの後始末は成功扱い（Absent）。
        assert_eq!(
            remove_exec_child_cgroup_in(&container_path, &exec_name, Duration::from_secs(5))
                .unwrap(),
            ExecCgroupRemoval::Absent
        );

        // 同名は採用しない（作成は EEXIST で失敗する）。
        let again = ExecCgroupName::unique();
        let first = ExecChildCgroup::create_in_path_for_test(&container_path, &again).unwrap();
        assert!(
            ExecChildCgroup::create_in_path_for_test(&container_path, &again).is_err(),
            "an existing exec child cgroup must not be adopted"
        );
        drop(first);

        // 生きたプロセスが居る cgroup を、kill なしに名前から後始末しても子孫ごと止まって削除される。
        let mut command = spawn_stubborn_command(&container_dir.join(again.as_str()));
        wait_until("three processes before cleanup", || {
            pids_in(&container_dir.join(again.as_str())).len() == 3
        });
        assert_eq!(
            remove_exec_child_cgroup_in(&container_path, &again, Duration::from_secs(5)).unwrap(),
            ExecCgroupRemoval::Removed
        );
        let _ = command.wait();
        assert!(!container_dir.join(again.as_str()).exists());

        // (3) 親（コンテナ cgroup）の pids.max が子 cgroup のプロセスにも掛かり、親の pids.current に計上される。
        container
            .set_pids_max(
                &fandhe_container_core::observability::OpRecorder::new(),
                &PidsMax::count(3).unwrap(),
            )
            .expect("set pids.max on the container cgroup");
        let limited = ExecCgroupName::unique();
        let _limited_cg = ExecChildCgroup::create_in_path_for_test(&container_path, &limited)
            .expect("create exec child cgroup");
        let limited_dir = container_dir.join(limited.as_str());
        let script = concat!(
            "echo 0 > \"$1/cgroup.procs\" && ",
            "for i in 1 2 3 4 5 6; do sleep 300 </dev/null >/dev/null 2>&1 & done; sleep 300"
        );
        let mut forker = Command::new("sh")
            .args(["-c", script, "sh"])
            .arg(&limited_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the forking command");
        // 制限に達した fork は、コンテナ cgroup の `pids.events` の `max` に計上される（子 cgroup のプロセスが
        // 親の制限で拒否された証拠）。
        let max_events = || -> u64 {
            fs::read_to_string(container_dir.join("pids.events"))
                .unwrap()
                .lines()
                .find_map(|l| l.strip_prefix("max "))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0)
        };
        wait_until("a fork to be denied by the parent pids.max", || {
            max_events() > 0
        });
        let current: usize = fs::read_to_string(container_dir.join("pids.current"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let members = pids_in(&limited_dir).len();
        assert!(
            (1..=3).contains(&members),
            "pids.max=3 must cap the exec child cgroup: {members}"
        );
        // 親の `pids.current` は子 cgroup のプロセスを含む（未回収の終了済みプロセスの分だけ多くなり得る）。
        assert!(
            (members..=3).contains(&current),
            "the parent pids.current must count the child: {current} vs {members}"
        );
        assert_eq!(
            remove_exec_child_cgroup_in(&container_path, &limited, Duration::from_secs(5)).unwrap(),
            ExecCgroupRemoval::Removed
        );
        let _ = forker.wait();

        delegated
            .remove_child(&container)
            .expect("remove container cgroup");
    }
}
