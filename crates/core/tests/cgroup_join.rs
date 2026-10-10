//! 起動フローへの cgroup 参加（`cgroups::CgroupJoin`・`StageKind::CgroupJoin`）の結合試験
//! （CORE-3・TASK-32.4・#161・MS-2。REPAIR-12 の機械照合）。
//!
//! 委譲 cgroup 上でコンテナ用子 cgroup を作り、`ContainerCgroup::join_hook` を
//! `spawn_container_with_stages` の `CgroupJoin` 段へ登録して fork した実プロセスが、次を満たすことを
//! 親から具体値で照合する。
//! 1. 起動したコンテナプロセスの PID（ホスト PID namespace 上の値）が子 cgroup の `cgroup.procs` に含まれる
//! 2. cgroup 参加が capability 削減・Landlock 等より前段で行われる（観測点の Landlock 段の時点で子の
//!    `/proc/self/cgroup` が既に子 cgroup を指す）
//!
//! # 観測点
//! `with_landlock` を載せないため `LaunchReady` が作られず exec が拒否される（fail-closed。#1714）ため、組み込みでない Landlock 段の
//! フックを観測点にして、親と合図ファイルで同期する。TASK-39.4 で Landlock が組み込み段になるとこの登録は
//! `InvalidArgument` で失敗する（意図した仕掛け。そのとき観測点を `CgroupJoin` 段の実フックを包む
//! ラッパーへ移し、`Exited(126)` の期待値も見直す）。
//!
//! # 実機前提テストとしての分離
//! 非特権ユーザーに委譲された cgroup v2 サブツリー（`detect` が成功すること）と、root もしくは非特権
//! user namespace を許可するホストが必要で、GitHub ホステッド runner では保証できないため
//! `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。実行された場合はあらゆる失敗を失敗として
//! 扱い、検証せずに成功する分岐は持たない。同一 cgroup に他プロセスがいると `prepare` が失敗するため、
//! `cargo` を経由せず委譲スコープの中でビルド済みバイナリを直接実行する:
//!
//! ```text
//! cargo test -p fandhe-container-core --test cgroup_join --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/cgroup_join-XXXX> --ignored
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("cgroup_join: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    println!("cgroup_join: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    if std::env::args().any(|a| a == "--ignored") {
        linux::run();
        println!("cgroup_join: CORE-3 cgroup join in the launch flow verified");
    } else {
        println!(
            "cgroup_join: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
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
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::{CgroupJoin, CgroupName, DelegatedCgroup};
    use fandhe_container_core::exec::{
        ChildExit, Entrypoint, ExecError, Hostname, IsolationConfig, Namespace, NamespaceSet,
        StageKind, StagePipeline, isolate, isolate_rootful_host_root, plan, plan_rootful_host_root,
        spawn_container_with_stages,
    };
    use fandhe_container_core::traits::ContainerId;

    /// 子が Landlock 段で書く `/proc/self/cgroup` の記録（親からは `<rootfs>/cg-ready`）。
    const READY: &str = "cg-ready";
    /// 親が確認後に作る合図（親からは `<rootfs>/cg-go`）。
    const GO: &str = "cg-go";
    /// 存在しないエントリポイント。exec は証跡が無いため拒否される。
    const ENTRY: &str = "/fandhe-cg-probe";

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
            .join(format!("fandhe-cgjoin-{}-{nanos}", std::process::id()));
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

    /// 子側の観測フック（Landlock 段）: 自身の `/proc/self/cgroup` を記録して親の合図を待つ。
    fn handshake_hook() -> Result<(), ExecError> {
        let record = std::fs::read_to_string("/proc/self/cgroup")
            .unwrap_or_else(|e| panic!("read /proc/self/cgroup in the child: {e}"));
        std::fs::write("/cg-ready.tmp", record)
            .unwrap_or_else(|e| panic!("write record in the child: {e}"));
        std::fs::rename("/cg-ready.tmp", format!("/{READY}"))
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

    pub fn run() {
        let delegated = DelegatedCgroup::detect().expect("detect delegated cgroup v2");
        let id = ContainerId::new(format!("j{}", std::process::id())).expect("container id");
        let name = CgroupName::new(&id).expect("cgroup name");
        // detect / prepare / join_hook は isolate より前（pivot 後はホストの cgroupfs が見えない）。
        let (container, _proof) = delegated.prepare(&name).expect("prepare container cgroup");
        let join = container.join_hook().expect("join hook");
        let procs_path = PathBuf::from("/sys/fs/cgroup")
            .join(delegated.path().trim_start_matches('/'))
            .join(name.as_str())
            .join("cgroup.procs");
        let expected_cgroup = format!(
            "0::{}/{}\n",
            delegated.path().trim_end_matches('/'),
            name.as_str()
        );

        let rootfs = make_rootfs();
        let verify = launch(&rootfs.0, join, &procs_path, expected_cgroup);
        // 後始末は成否に関わらず先に行う（子は回収済みで cgroup は空）。
        let removed = delegated.remove_child(&container);
        verify();
        removed.expect("remove container cgroup");
    }

    /// 起動して観測値を採る。検証は後始末の後に走らせるため、検証クロージャを返す。
    fn launch(
        rootfs: &Path,
        join: CgroupJoin,
        procs_path: &Path,
        expected_cgroup: String,
    ) -> Box<dyn FnOnce()> {
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
        let stages = StagePipeline::new()
            .with_hook(StageKind::CgroupJoin, join)
            .and_then(|p| p.with_hook(StageKind::Landlock, handshake_hook))
            .unwrap_or_else(|e| panic!("register hooks: {e}"));
        let child = spawn_container_with_stages(rootfs, &entry, stages)
            .unwrap_or_else(|e| panic!("spawn: {e}"));

        let limit = timeout();
        let deadline = Instant::now() + limit;
        let ready = rootfs.join(READY);
        while !ready.exists() {
            if let Ok(Some(exit)) = child.wait_for_exit(Duration::from_millis(10)) {
                panic!("child exited early with {exit:?} before reaching the observation point");
            }
            if Instant::now() >= deadline {
                let _ = child.kill_and_reap(Duration::from_secs(5));
                panic!("child did not reach the observation point within {limit:?}");
            }
        }
        // 親はホスト PID namespace に留まるため、`child.pid()` は cgroup.procs と同じ名前空間の値。
        let listed = std::fs::read_to_string(procs_path).expect("read cgroup.procs");
        let pid = child.pid();
        let record = std::fs::read_to_string(&ready).expect("read child record");
        std::fs::write(rootfs.join(GO), b"go").expect("create go signal");
        let exit = child.wait_timeout(limit).unwrap_or_else(|e| {
            let _ = child.kill_and_reap(Duration::from_secs(5));
            panic!("wait: {e}")
        });
        Box::new(move || {
            // AC1: 起動したコンテナプロセスの PID が対象 cgroup の cgroup.procs に含まれる。
            assert!(
                listed.lines().any(|l| l.trim() == pid.to_string()),
                "pid {pid} must be listed in cgroup.procs; got {listed:?}"
            );
            // AC2: 観測点（Landlock 段）の時点で既に子 cgroup に参加済み。
            assert_eq!(
                record, expected_cgroup,
                "child cgroup at the Landlock stage"
            );
            // SEC-1・CORE-5: 制限証跡が無い間は exec が拒否される。
            assert_eq!(exit, ChildExit::Exited(126), "exec must still be refused");
        })
    }
}
