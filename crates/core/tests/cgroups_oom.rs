//! OOM Kill 確認の結合試験（CORE-3・TASK-33.1・#164・MS-2。REPAIR-12 の機械照合）。
//!
//! `memory.max` = 64 MiB・`memory.swap.max` = 0 を設定した子 cgroup へ `ContainerCgroup::join_hook` で
//! 参加したプロセスが 64 MiB を超えて確保しようとすると、カーネルの memcg OOM Killer に kill されることを
//! 親から具体値で照合する。設定そのものの照合は `cgroups`（TASK-32.5）が担い、本試験は「設定した上限が
//! 実際に効く」ことだけを見る。
//! 1. 子の終了状態が `ChildExit::Signaled(9)`（SIGKILL）で、シェル慣習の終了コードに直すと `137`（128 + 9）
//! 2. 子 cgroup の `memory.events` が起動前 `oom 0`・`oom_kill 0`、終了後 `oom 1`・`oom_kill 1`
//! 3. 設定の戻り値が `memory.max` = `67108864`・`memory.swap.max` = `0`
//!
//! # 観測点
//! 確保ループは `CgroupJoin` 段へ登録するクロージャ内（fork 後の単一スレッドの子で、参加直後・exec 前）に
//! 置くため、`unsafe` も `pre_exec` も不要。ループが上限まで完走した場合（制限が効いていない）は
//! `ExecError` を返し、子は setup 失敗の `Exited(125)` で終わるので親の照合が失敗する（ハングしない）。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（`memory` が委譲され swap accounting が有効）と、
//! root もしくは非特権 user namespace を許可するホストが必要で、`oom_score_adj` が -1000 でないこと。
//! GitHub ホステッド runner では保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。
//! `prepare` が自プロセスを移動するため 1 ファイル 1 シナリオとし、`cargo` を経由せず実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroups_oom --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroups_oom-XXXX> --ignored
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("cgroups_oom: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    println!("cgroups_oom: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
        println!("cgroups_oom: CORE-3 OOM kill verified");
    } else {
        println!(
            "cgroups_oom: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use fandhe_container_core::cgroups::{
        AppliedMemoryLimits, CgroupJoin, CgroupName, Controller, ControllerSet, DelegatedCgroup,
        MemoryLimit, MemoryLimits,
    };
    use fandhe_container_core::exec::{
        ChildExit, Entrypoint, ExecError, Hostname, IsolationConfig, Namespace, NamespaceSet,
        StageHook, StageKind, StagePipeline, isolate, isolate_rootful_host_root, plan,
        plan_rootful_host_root, spawn_container_with_stages,
    };
    use fandhe_container_core::traits::ContainerId;

    /// 存在しないエントリポイント。確保ループで kill されるため exec には到達しない。
    const ENTRY: &str = "/fandhe-oom-probe";
    /// 1 回の確保単位（1 MiB）。
    const CHUNK: usize = 1024 * 1024;
    /// 確保の上限（300 MiB）。制限が効かない場合にホストメモリを食い潰さないための安全弁。
    const ALLOC_CAP: usize = 300 * CHUNK;

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
            .join(format!("fandhe-cgroups-oom-{}-{nanos}", std::process::id()));
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

    /// 子側の確保ループ（`CgroupJoin` 段で参加直後に実行）: `memory.max` を超えるまで確保し続ける。
    ///
    /// 0 以外で埋めるのは、`vec![0; n]` が calloc 経由でページに触れず OOM が起きないため。
    /// 上限まで完走した場合は制限が効いていないので `ExecError` を返し、子を `Exited(125)` で終わらせる。
    fn allocate_until_killed() -> Result<(), ExecError> {
        let mut held: Vec<Vec<u8>> = Vec::new();
        let mut total = 0usize;
        while total < ALLOC_CAP {
            held.push(vec![0xA5u8; CHUNK]);
            std::hint::black_box(&held);
            total += CHUNK;
        }
        Hostname::new("").map(|_| ())
    }

    /// `memory.events` を `key value` 行の対応表にする。値が非数値なら panic する（fail-closed）。
    fn parse_events(text: &str) -> BTreeMap<String, u64> {
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let mut it = l.split_whitespace();
                let key = it.next().expect("memory.events key").to_string();
                let value = it
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or_else(|| panic!("non-numeric memory.events line: {l:?}"));
                (key, value)
            })
            .collect()
    }

    fn event(events: &BTreeMap<String, u64>, key: &str) -> u64 {
        *events
            .get(key)
            .unwrap_or_else(|| panic!("memory.events has no `{key}`: {events:?}"))
    }

    /// シェル慣習の終了コード（signal は 128 + n）。137 は本 issue が照合に使う値。
    fn shell_exit_code(exit: &ChildExit) -> i32 {
        match exit {
            ChildExit::Exited(c) => *c,
            ChildExit::Signaled(s) => 128i32.checked_add(*s).expect("shell exit code overflow"),
            other => panic!("unexpected child exit: {other:?}"),
        }
    }

    /// drop（panic の unwind を含む）で子を kill して回収する後始末ガード（特権操作の後始末。CORE-3）。
    struct ChildReaper<'a>(&'a fandhe_container_core::exec::ContainerChild);

    impl Drop for ChildReaper<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill_and_reap(Duration::from_secs(5));
        }
    }

    /// 親が採った観測値。
    struct Observed {
        applied: AppliedMemoryLimits,
        before: BTreeMap<String, u64>,
        after: BTreeMap<String, u64>,
        memory_max: String,
        swap_max: String,
        exit: ChildExit,
    }

    pub fn run() {
        let score =
            std::fs::read_to_string("/proc/self/oom_score_adj").expect("read oom_score_adj");
        assert_ne!(
            score.trim(),
            "-1000",
            "oom_score_adj is -1000 (unkillable): the memcg OOM killer cannot kill this test's child"
        );
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup v2");
        let id = ContainerId::new(format!("o{}", std::process::id())).expect("container id");
        let name = CgroupName::new(&id).expect("cgroup name");
        let (container, proof) = delegated.prepare(&name).expect("prepare container cgroup");
        let dir = PathBuf::from("/sys/fs/cgroup")
            .join(delegated.path().trim_start_matches('/'))
            .join(name.as_str());

        // rootfs 作成を含めどこで panic しても子 cgroup の削除まで到達できるよう捕捉し、
        // 後始末後に再送出する（rootfs は Drop で削除される）。
        let verify = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let rootfs = make_rootfs();
            let enabled = delegated
                .enable_controllers(&proof, &ControllerSet::of(&[Controller::Memory]))
                .expect("enable memory controller");
            let applied = container
                .set_memory_limits(
                    &enabled,
                    &MemoryLimits {
                        memory_max: MemoryLimit::parse("64M").expect("memory limit"),
                        swap_max: Some(MemoryLimit::Bytes(0)),
                    },
                )
                .expect("set memory limits");
            let read = |f: &str| {
                std::fs::read_to_string(dir.join(f))
                    .unwrap_or_else(|e| panic!("read {f} of the child cgroup: {e}"))
            };
            let before = parse_events(&read("memory.events"));
            let join = container.join_hook().expect("join hook");
            let exit = launch(&rootfs.0, join);
            // 子の回収後・cgroup 削除前に読む。
            Observed {
                applied,
                before,
                after: parse_events(&read("memory.events")),
                memory_max: read("memory.max"),
                swap_max: read("memory.swap.max"),
                exit,
            }
        }));
        let removed = delegated.remove_child(&container);
        let gone = !dir.exists();
        let r = match verify {
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

        assert_eq!(r.applied.memory_max, MemoryLimit::Bytes(67_108_864));
        assert_eq!(r.applied.swap_max, Some(MemoryLimit::Bytes(0)));
        assert_eq!(r.memory_max.trim_end(), "67108864");
        assert_eq!(r.swap_max.trim_end(), "0");
        assert_eq!(event(&r.before, "oom"), 0, "oom before start");
        assert_eq!(event(&r.before, "oom_kill"), 0, "oom_kill before start");
        assert_eq!(r.exit, ChildExit::Signaled(9), "child must be OOM-killed");
        assert_eq!(shell_exit_code(&r.exit), 137, "shell-style exit code");
        // `max` はリクレイム再試行回数に依存するため照合しない。
        assert_eq!(event(&r.after, "oom"), 1, "oom after exit: {:?}", r.after);
        assert_eq!(
            event(&r.after, "oom_kill"),
            1,
            "oom_kill after exit: {:?}",
            r.after
        );
    }

    /// 起動して子の終了状態を得る。失敗（panic）経路でも子は `ChildReaper` が kill・回収する。
    fn launch(rootfs: &Path, join: CgroupJoin) -> ChildExit {
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
                allocate_until_killed()
            })
            .unwrap_or_else(|e| panic!("register hook: {e}"));
        let child = spawn_container_with_stages(rootfs, &entry, stages)
            .unwrap_or_else(|e| panic!("spawn: {e}"));
        let _reaper = ChildReaper(&child);
        child
            .wait_timeout(timeout())
            .unwrap_or_else(|e| panic!("wait: {e}"))
    }
}
