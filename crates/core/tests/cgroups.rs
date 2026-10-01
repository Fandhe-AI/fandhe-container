//! cgroups 設定（資源制限＋起動フローへの参加）の通し結合試験（CORE-3・TASK-32.5・#162・MS-2。
//! REPAIR-12 の機械照合）。
//!
//! 同一の子 cgroup に `memory.max`・`memory.swap.max`・`cpu.max` を設定し、`ContainerCgroup::join_hook` を
//! `spawn_container_with_stages` の `CgroupJoin` 段へ登録して fork した実プロセスについて、親から次を
//! 具体値で照合する。個別機能の試験は `cgroup_memory`・`cgroup_cpu_max`・`cgroup_join` が担い、本試験は
//! 「制限を設定した cgroup へ起動フローで参加できる」組み合わせだけを見る。
//! 1. 子 cgroup の `memory.max` が `67108864`、`memory.swap.max` が `0`、`cpu.max` が `50000 100000`
//! 2. 起動したコンテナプロセスの PID が子 cgroup の `cgroup.procs` に含まれ、子の `/proc/self/cgroup` が
//!    `0::<委譲パス>/fc-<id>` を指す
//! 3. exec は制限証跡が無い間 `Exited(126)` で拒否される（SEC-1・CORE-5 の fail-closed の維持）
//!
//! # 観測点
//! 組み込み化されうる Landlock 段には依存せず、`CgroupJoin` 段へ「実 `CgroupJoin` を適用した直後に親と
//! 合図ファイルで同期するクロージャ」を登録して観測点にする。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（`memory`・`cpu` が委譲され swap accounting が有効）と、
//! root もしくは非特権 user namespace を許可するホストが必要で、GitHub ホステッド runner では保証できない
//! ため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。`prepare` が自プロセスを移動する
//! ため 1 ファイル 1 シナリオとし、`cargo` を経由せず委譲スコープの中でビルド済みバイナリを直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroups --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroups-XXXX> --ignored
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("cgroups: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    println!("cgroups: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
        println!("cgroups: CORE-3 cgroup limits and join verified");
    } else {
        println!("cgroups: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)");
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::{
        CgroupJoin, CgroupName, Controller, ControllerSet, CpuMax, CpuQuota, DelegatedCgroup,
        MemoryLimit, MemoryLimits,
    };
    use fandhe_container_core::exec::{
        ChildExit, Entrypoint, ExecError, Hostname, IsolationConfig, Namespace, NamespaceSet,
        StageHook, StageKind, StagePipeline, isolate, isolate_rootful_host_root, plan,
        plan_rootful_host_root, spawn_container_with_stages,
    };
    use fandhe_container_core::traits::ContainerId;

    /// 子が Landlock 段で書く `/proc/self/cgroup` の記録（親からは `<rootfs>/cg-ready`）。
    const READY: &str = "cgs-ready";
    /// 親が確認後に作る合図（親からは `<rootfs>/cg-go`）。
    const GO: &str = "cgs-go";
    /// 存在しないエントリポイント。exec は証跡が無いため拒否される。
    const ENTRY: &str = "/fandhe-cgs-probe";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn make_rootfs() -> Rootfs {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!("fandhe-cgroups-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&base).expect("exclusively create rootfs dir");
        let rootfs = Rootfs(base);
        std::fs::set_permissions(&rootfs.0, std::fs::Permissions::from_mode(0o755))
            .expect("chmod rootfs dir");
        std::fs::create_dir(rootfs.0.join("proc")).expect("create rootfs/proc");
        rootfs
    }

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .as_deref()
            == Some("0")
    }

    /// 子側の観測処理（`CgroupJoin` 段で参加直後に実行）: 自身の `/proc/self/cgroup` を記録して親の合図を待つ。
    fn handshake() -> Result<(), ExecError> {
        let record = std::fs::read_to_string("/proc/self/cgroup")
            .unwrap_or_else(|e| panic!("read /proc/self/cgroup in the child: {e}"));
        std::fs::write("/cgs-ready.tmp", record)
            .unwrap_or_else(|e| panic!("write record in the child: {e}"));
        std::fs::rename("/cgs-ready.tmp", format!("/{READY}"))
            .unwrap_or_else(|e| panic!("publish record in the child: {e}"));
        let deadline = Instant::now() + timeout();
        while !Path::new(&format!("/{GO}")).exists() {
            if Instant::now() >= deadline {
                // 親が現れない場合は setup 失敗（125）で終わる。
                return Hostname::new("").map(|_| ());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    /// 親が子 cgroup から読んだ値。
    struct Observed {
        procs: String,
        memory_max: String,
        swap_max: String,
        cpu_max: String,
    }

    pub fn run() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup v2");
        let id = ContainerId::new(format!("s{}", std::process::id())).expect("container id");
        let name = CgroupName::new(&id).expect("cgroup name");
        // detect / prepare / 制限設定 / join_hook は isolate より前（pivot 後はホストの cgroupfs が見えない）。
        let (container, proof) = delegated.prepare(&name).expect("prepare container cgroup");
        let enabled = delegated
            .enable_controllers(
                &proof,
                &ControllerSet::of(&[Controller::Memory, Controller::Cpu]),
            )
            .expect("enable memory and cpu controllers");
        let applied = container
            .set_memory_limits(
                &enabled,
                &MemoryLimits {
                    memory_max: MemoryLimit::parse("64M").expect("memory limit"),
                    swap_max: Some(MemoryLimit::Bytes(0)),
                },
            )
            .expect("set memory limits");
        let cpu = CpuMax::new(CpuQuota::Micros(50_000), 100_000).expect("cpu.max value");
        let applied_cpu = container.set_cpu_max(&cpu).expect("set cpu.max");
        let join = container.join_hook().expect("join hook");
        let dir = PathBuf::from("/sys/fs/cgroup")
            .join(delegated.path().trim_start_matches('/'))
            .join(name.as_str());
        let expected_cgroup = format!(
            "0::{}/{}\n",
            delegated.path().trim_end_matches('/'),
            name.as_str()
        );

        let rootfs = make_rootfs();
        // `launch` が panic しても（子は `ChildReaper` の drop で unwind 中に kill・回収済みなので）
        // 子 cgroup の削除まで到達できるよう、panic を捕捉して後始末後に再送出する。
        let verify = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            launch(&rootfs.0, join, &dir)
        }));
        // 後始末は成否に関わらず先に行う（子は回収済みで cgroup は空）。
        let removed = delegated.remove_child(&container);
        let gone = !dir.exists();
        let (observed, record, pid, exit) = match verify {
            Ok(v) => v,
            Err(payload) => {
                if let Err(e) = &removed {
                    eprintln!("cleanup: remove container cgroup failed after panic: {e}");
                }
                std::panic::resume_unwind(payload)
            }
        };
        removed.expect("remove container cgroup");
        assert!(gone, "child cgroup directory must be removed");

        // 設定時の戻り値（読み戻した実効値）。
        assert_eq!(applied.memory_max, MemoryLimit::Bytes(67_108_864));
        assert_eq!(applied.swap_max, Some(MemoryLimit::Bytes(0)));
        assert_eq!(applied_cpu, cpu);
        // 子が参加している間に親が読んだ cgroup ファイルの内容。
        assert_eq!(observed.memory_max.trim_end(), "67108864");
        assert_eq!(observed.swap_max.trim_end(), "0");
        assert_eq!(observed.cpu_max.trim_end(), "50000 100000");
        assert!(
            observed.procs.lines().any(|l| l.trim() == pid.to_string()),
            "pid {pid} must be listed in cgroup.procs; got {:?}",
            observed.procs
        );
        assert_eq!(record, expected_cgroup, "child cgroup at the join stage");
        // SEC-1・CORE-5: 制限証跡が無い間は exec が拒否される。
        assert_eq!(exit, ChildExit::Exited(126), "exec must still be refused");
    }

    /// drop（panic の unwind を含む）で子を kill して回収する後始末ガード（特権操作の後始末。CORE-3）。
    ///
    /// `ContainerChild` は Drop で kill・回収しないため、失敗経路で子が残り子 cgroup を削除できなく
    /// なるのを防ぐ。回収済みの子には `kill_and_reap` が kill を送らない（記録済みの終了状態を返す）。
    struct ChildReaper<'a>(&'a fandhe_container_core::exec::ContainerChild);

    impl Drop for ChildReaper<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill_and_reap(Duration::from_secs(5));
        }
    }

    /// 起動して観測値を採る。失敗（panic）経路でも子は `ChildReaper` が kill・回収する。
    fn launch(rootfs: &Path, join: CgroupJoin, dir: &Path) -> (Observed, String, u32, ChildExit) {
        let is_root = is_root();
        let mut namespaces = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        if !is_root {
            namespaces = namespaces.with(Namespace::User);
        }
        let config = IsolationConfig {
            namespaces,
            hostname: None,
        };
        let result = if is_root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        result.unwrap_or_else(|err| panic!("isolate failed: {err}"));

        let entry = Entrypoint::new(ENTRY, [ENTRY], [] as [&str; 0]).expect("entrypoint");
        let mut join = join;
        let stages = StagePipeline::new()
            .with_hook(StageKind::CgroupJoin, move || {
                StageHook::apply(&mut join)?;
                handshake()
            })
            .unwrap_or_else(|e| panic!("register hook: {e}"));
        let child = spawn_container_with_stages(rootfs, &entry, stages)
            .unwrap_or_else(|e| panic!("spawn: {e}"));
        let _reaper = ChildReaper(&child);

        let limit = timeout();
        let deadline = Instant::now() + limit;
        let ready = rootfs.join(READY);
        while !ready.exists() {
            if let Ok(Some(exit)) = child.wait_for_exit(Duration::from_millis(10)) {
                panic!("child exited early with {exit:?} before reaching the observation point");
            }
            if Instant::now() >= deadline {
                panic!("child did not reach the observation point within {limit:?}");
            }
        }
        // 親はホスト PID namespace に留まるため、`child.pid()` は cgroup.procs と同じ名前空間の値。
        let read = |f: &str| {
            std::fs::read_to_string(dir.join(f))
                .unwrap_or_else(|e| panic!("read {f} of the child cgroup: {e}"))
        };
        let observed = Observed {
            procs: read("cgroup.procs"),
            memory_max: read("memory.max"),
            swap_max: read("memory.swap.max"),
            cpu_max: read("cpu.max"),
        };
        let pid = child.pid();
        let record = std::fs::read_to_string(&ready).expect("read child record");
        std::fs::write(rootfs.join(GO), b"go").expect("create go signal");
        let exit = child
            .wait_timeout(limit)
            .unwrap_or_else(|e| panic!("wait: {e}"));
        (observed, record, pid, exit)
    }
}
