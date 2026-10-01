//! cgroups v2 実効性の回帰テスト（CORE-3・TASK-36.1・#169・MS-2。REPAIR-12 の機械照合）。
//!
//! node4 の PoC（linux-real-machine）で実証済みの CORE-3 の確認手順を、fandhe-container 自身の実装
//! （TASK-32・#153 の `DelegatedCgroup`・`ContainerCgroup`）に対する回帰として固定する。
//! 1. 順序: 子 cgroup 作成 → 自プロセス退避（`prepare`）→ controller 有効化（`enable_controllers`）の
//!    各段階の状態を具体値で照合する。退避前に `+memory` を書くと EBUSY で失敗する負の対照も実カーネルで
//!    確認する（no-internal-process 制約。逆順のコードは `Evacuated` トークンにより型でコンパイルできない）
//! 2. OOM Kill: `memory.max=64M`・`memory.swap.max=0` の下で `CgroupJoin` 段の直後に 300 MiB を確保した
//!    プロセスが SIGKILL（`Signaled(9)`、シェル慣例の終了コード 137）され、`memory.events` の
//!    `oom_kill` が 1 以上になる
//!
//! # 観測点
//! 負荷は entrypoint ではなく `CgroupJoin` 段のフック内（参加直後）で実行する。exec は制限の証跡が無い間
//! `Exited(126)` で拒否されるため、entrypoint は到達しない（SEC-1・CORE-5 の fail-closed）。
//! `oom_kill` は子の回収後・子 cgroup の削除前に読む。`kill_and_reap` のタイムアウト kill も
//! `Signaled(9)` になるため、OOM による kill だと示す決め手は `oom_kill` の値である。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（`memory`・`cpu` が委譲され swap accounting が有効）と、
//! root もしくは非特権 user namespace を許可するホストが必要で、GitHub ホステッド runner では保証できない
//! ため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。`prepare` が自プロセスを移動する
//! ため 1 プロセス 1 シナリオとし、`cargo` を経由せず委譲スコープの中でビルド済みバイナリを直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroups_regression --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroups_regression-XXXX> --ignored
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("cgroups_regression: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    println!("cgroups_regression: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
        println!("cgroups_regression: CORE-3 cgroup ordering and OOM kill verified");
    } else {
        println!(
            "cgroups_regression: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use fandhe_container_core::cgroups::{
        CgroupJoin, CgroupName, Controller, ControllerSet, DelegatedCgroup, MemoryLimit,
        MemoryLimits,
    };
    use fandhe_container_core::exec::{
        ChildExit, ContainerChild, Entrypoint, ExecError, Hostname, IsolationConfig, Namespace,
        NamespaceSet, StageHook, StageKind, StagePipeline, isolate, isolate_rootful_host_root,
        plan, plan_rootful_host_root, spawn_container_with_stages,
    };
    use fandhe_container_core::traits::ContainerId;

    /// 存在しないエントリポイント。到達しない（exec は証跡が無いため拒否される）。
    const ENTRY: &str = "/fandhe-cgr-probe";
    /// 確保を試みる総量（MiB）。`memory.max`（64M）を十分に超える。
    const HOG_MIB: usize = 300;
    /// EBUSY。asm-generic の値で x86_64・aarch64 とも同じ。
    const EBUSY: i32 = 16;

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
            .join(format!(
                "fandhe-cgroups-regression-{}-{nanos}",
                std::process::id()
            ));
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

    /// `ChildExit` をシェル・Docker の慣例（`Exited(c)` は `c`、`Signaled(s)` は `128 + s`）の終了コードへ
    /// 写す。CORE-3 の「137」はこの慣例で、core に写像 API は追加しない（テスト内に局所化）。
    fn shell_exit_code(exit: ChildExit) -> i32 {
        match exit {
            ChildExit::Exited(c) => c,
            ChildExit::Signaled(s) => 128 + s,
            _ => -1,
        }
    }

    /// `memory.events` から `key` の値を取り出す（外部入力のため unwrap・添字を使わない）。
    fn event_count(events: &str, key: &str) -> Option<u64> {
        events.lines().find_map(|l| {
            let mut it = l.split_whitespace();
            (it.next() == Some(key))
                .then(|| it.next().and_then(|v| v.parse::<u64>().ok()))
                .flatten()
        })
    }

    /// 子側の負荷（`CgroupJoin` 段の参加直後に実行）。`HOG_MIB` を確保し終えても kill されなければ
    /// 制限が効いていないため `Err`（setup 失敗 125 でテストが失敗側に倒れる。fail-closed）。
    fn hog() -> Result<(), ExecError> {
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        for _ in 0..HOG_MIB {
            // 非ゼロで埋めて実ページを確定させる（遅延マッピングで実メモリを消費しない状況を避ける）。
            chunks.push(vec![0xA5u8; 1024 * 1024]);
            std::hint::black_box(&chunks);
        }
        std::hint::black_box(&chunks);
        Hostname::new("").map(|_| ())
    }

    /// drop（panic の unwind を含む）で子を kill して回収する後始末ガード（特権操作の後始末。CORE-3）。
    struct ChildReaper<'a>(&'a ContainerChild);

    impl Drop for ChildReaper<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill_and_reap(Duration::from_secs(5));
        }
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn self_cgroup() -> String {
        read(Path::new("/proc/self/cgroup"))
    }

    fn lists(subtree: &str, controller: &str) -> bool {
        subtree.split_whitespace().any(|c| c == controller)
    }

    pub fn run() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup v2");
        assert_ne!(
            delegated.path().trim_matches('/'),
            "",
            "the root cgroup is exempt from the no-internal-process rule; run inside a delegated scope"
        );
        assert!(delegated.controllers().contains(Controller::Memory));
        assert!(delegated.controllers().contains(Controller::Cpu));
        let parent = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let delegated_path = delegated.path().trim_end_matches('/').to_string();
        let id = ContainerId::new(format!("r{}", std::process::id())).expect("container id");
        let name = CgroupName::new(&id).expect("cgroup name");
        let dir = parent.join(name.as_str());
        let want = ControllerSet::of(&[Controller::Memory, Controller::Cpu]);
        let subtree = parent.join("cgroup.subtree_control");

        // --- AC1: prepare 前 ---
        assert_eq!(self_cgroup(), format!("0::{delegated_path}\n"));
        assert!(!dir.exists(), "child cgroup must not exist before prepare");
        let before = read(&subtree);
        assert!(
            !lists(&before, "memory") && !lists(&before, "cpu"),
            "controllers must not be enabled before prepare; got {before:?}"
        );
        // 負の対照: 退避前（自プロセスが親に居る間）の controller 有効化は no-internal-process 制約で
        // EBUSY になる。順序（子作成 → 退避 → 有効化）が必要な理由を実カーネルで確認する。
        let err = std::fs::write(&subtree, "+memory")
            .expect_err("enabling a controller before evacuation must fail");
        assert_eq!(err.raw_os_error(), Some(EBUSY), "expected EBUSY, got {err}");

        let (container, proof) = delegated.prepare(&name).expect("prepare container cgroup");
        // 子 cgroup の作成後は rootfs 作成を含めどこで panic しても remove_child まで到達できるよう、捕捉して後始末後に再送出する。
        let verify = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let rootfs = make_rootfs();
            // --- AC1: prepare 後 ---
            assert!(dir.is_dir(), "child cgroup must exist after prepare");
            assert_eq!(read(&dir.join("cgroup.procs")), "");
            assert_eq!(
                self_cgroup(),
                format!("0::{delegated_path}/fc-runtime\n"),
                "self must be evacuated into the leaf"
            );
            assert_eq!(read(&parent.join("cgroup.procs")), "");
            let mid = read(&subtree);
            assert!(
                !lists(&mid, "memory") && !lists(&mid, "cpu"),
                "prepare must not enable controllers; got {mid:?}"
            );

            // --- AC1: enable_controllers 後 ---
            let enabled = delegated
                .enable_controllers(&proof, &want)
                .expect("enable memory and cpu controllers");
            assert!(enabled.contains(Controller::Memory) && enabled.contains(Controller::Cpu));
            let after = read(&subtree);
            assert!(
                lists(&after, "memory") && lists(&after, "cpu"),
                "subtree_control must list memory and cpu; got {after:?}"
            );
            assert!(dir.join("memory.max").exists());

            // --- AC2: OOM Kill ---
            let applied = container
                .set_memory_limits(
                    &enabled,
                    &MemoryLimits {
                        memory_max: MemoryLimit::parse("64M").expect("memory limit"),
                        // swap が 0 でないと OOM ではなく swap に逃げる。
                        swap_max: Some(MemoryLimit::Bytes(0)),
                    },
                )
                .expect("set memory limits");
            assert_eq!(applied.memory_max, MemoryLimit::Bytes(67_108_864));
            assert_eq!(applied.swap_max, Some(MemoryLimit::Bytes(0)));
            let join = container.join_hook().expect("join hook");
            let exit = launch(&rootfs.0, join);
            // 回収後・remove_child 前に読む。oom_kill が OOM による kill の決め手。
            let events = read(&dir.join("memory.events"));
            (exit, events)
        }));
        // 後始末は成否に関わらず先に行う（子は回収済みで cgroup は空）。退避リーフは自プロセスが居るため
        // 削除しない（スコープ終了時に systemd が回収する）。
        let removed = delegated.remove_child(&container);
        let gone = !dir.exists();
        let (exit, events) = match verify {
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

        // pid ns の PID 1 でもカーネルが強制する SIGKILL は init の保護を受けない（Docker の OOMKilled と同じ）。
        assert_eq!(exit, ChildExit::Signaled(9), "must be OOM killed");
        assert_eq!(shell_exit_code(exit), 137);
        // 300 MiB 確保中に OOM 判定が複数回起き得るため、カウンタは 1 以上で照合する。
        for key in ["oom_kill", "oom"] {
            assert!(
                event_count(&events, key).is_some_and(|n| n >= 1),
                "{key} must be >= 1; events: {events:?}"
            );
        }
    }

    /// 起動して OOM Kill された子の終了状態を返す。失敗（panic）経路でも子は `ChildReaper` が回収する。
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
                hog()
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
