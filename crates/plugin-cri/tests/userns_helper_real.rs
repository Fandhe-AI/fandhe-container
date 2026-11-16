//! userns helper（隠し引数 `__extract-in-userns`）を実バイナリで本番の参加経路（`--no-join` なし）で通す実機前提の結合試験
//! （SEC-5・OCI-1・CORE-6・REPAIR-5・REPAIR-12。#4795。親 issue #4777 の H1。設計は `docs/design/userns-extract-helper.md`）。
//!
//! 必要環境: 非 root・非特権 user namespace を許す環境（`kernel.apparmor_restrict_unprivileged_userns` の緩和など）・
//! `uidmap`（`newuidmap` / `newgidmap`）・自分の subuid / subgid の行・Linux 6.9 以降（範囲写像の helper の停止手段）。
//! `harness = false` で `-- --ignored` 指定時のみ動かす（AGENTS.md）。前提の欠落・root は終了コード 1（成功を装わない）。
//! 全体 watchdog は 120 秒で、超えたら `WATCHDOG EXPIRED` と終了コード 124。CI への組み込みは H7（本 issue の範囲外）。
//!
//! # シナリオ（各成功行は固定の文字列。`scripts/check-success-lines.sh` が本ファイルのリテラルから導出して照合する）
//! - Inspect: 参加後に joined・euid 0・egid 0・threads 1・dumpable 0・写像 2 行以上
//! - StatTarget: 自分が所有するディレクトリが、名前空間の中では uid 0 の所有に見える
//! - Remove（H3。#4800）: 範囲写像の user namespace の中で作った subuid 所有の木（最上位自身も subuid 所有・0700、
//!   0555 の子を含む）は、ホスト側の削除では消えず（陽性対照）、削除モードで消える。親ディレクトリは残る。木の作成は本試験
//!   バイナリを `--populate <dir>` で再実行した子（単一スレッド）が行う

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("userns_helper_real: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("userns_helper_real: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use std::fs::File;
    use std::os::fd::{AsFd as _, AsRawFd as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::time::Duration;

    use fandhe_container_plugin_cri::userns_helper::wire::{Mode, RemoveTarget, Report};
    use fandhe_container_plugin_cri::userns_helper::{
        USERNS_HELPER_ARG, UsernsHelperLauncher, WorkBudget,
    };

    const WATCHDOG: Duration = Duration::from_secs(120);
    const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-plugin-cri");

    pub fn main() -> ExitCode {
        let args: Vec<String> = std::env::args().collect();
        // 子の役（単一スレッドのまま user namespace に入る。watchdog スレッドを起動する前に処理する）。
        if let Some(i) = args.iter().position(|a| a == "--populate") {
            let dir = args
                .get(i + 1)
                .unwrap_or_else(|| fail("directory after --populate"));
            populate(dir);
            return ExitCode::SUCCESS;
        }
        match args.get(1).map(String::as_str) {
            Some("--ignored") => run_all(),
            _ => {
                println!(
                    "userns_helper_real: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
                );
                ExitCode::SUCCESS
            }
        }
    }

    fn fail(msg: &str) -> ! {
        println!("userns_helper_real: FAILED: {msg}");
        std::process::exit(1);
    }

    fn start_watchdog() {
        std::thread::spawn(|| {
            std::thread::sleep(WATCHDOG);
            println!("userns_helper_real: WATCHDOG EXPIRED after {WATCHDOG:?}");
            std::process::exit(124);
        });
    }

    fn run_all() -> ExitCode {
        let euid = std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid());
        if euid == 0 {
            println!("userns_helper_real: FAILED: must run as non-root (root=true)");
            return ExitCode::from(1);
        }
        for p in ["/usr/bin/newuidmap", "/usr/bin/newgidmap"] {
            if !Path::new(p).exists() {
                println!("userns_helper_real: PRECONDITION FAILED: {p} is required");
                return ExitCode::from(1);
            }
        }
        start_watchdog();

        let dir = scratch_dir();
        let target = File::open(&dir).unwrap_or_else(|e| fail(&format!("open scratch dir: {e}")));
        let launcher =
            UsernsHelperLauncher::with_fixed_command(BIN, vec![USERNS_HELPER_ARG.into()]);
        let budget =
            WorkBudget::new(Duration::from_secs(10)).unwrap_or_else(|e| fail(&e.to_string()));

        match launcher.run(Mode::Inspect, target.as_fd(), budget) {
            Ok(Report::Inspect(r)) => {
                if !(r.joined
                    && r.euid == 0
                    && r.egid == 0
                    && r.threads == 1
                    && r.dumpable == 0
                    && r.uid_map_rows >= 2
                    && r.gid_map_rows >= 2)
                {
                    fail(&format!("unexpected inspect report: {r:?}"));
                }
                println!(
                    "userns_helper_real: inspect joined ok (euid 0, egid 0, threads 1, dumpable 0, maps >= 2 rows)"
                );
            }
            Ok(other) => fail(&format!("unexpected report: {other:?}")),
            Err(e) => fail(&format!("inspect: {e} (helper={:?})", e.helper_code())),
        }

        match launcher.run(Mode::StatTarget, target.as_fd(), budget) {
            Ok(Report::StatTarget(r)) => {
                if r.uid != 0 || r.gid != 0 || r.mode != 0o700 {
                    fail(&format!("unexpected stat report: {r:?}"));
                }
                println!(
                    "userns_helper_real: stat target owner is namespace root ok (uid 0, gid 0, mode 0700)"
                );
            }
            Ok(other) => fail(&format!("unexpected report: {other:?}")),
            Err(e) => fail(&format!("stat: {e} (helper={:?})", e.helper_code())),
        }
        let _ = std::fs::remove_dir(&dir);
        remove_subordinate_owned_tree(&launcher, budget);
        ExitCode::SUCCESS
    }

    /// 子の役: user namespace の中で `dir` に subuid 所有の木を作る（最上位自身も subuid 所有・0700。0555 の子を含む）。
    fn populate(dir: &str) {
        // namespace に入る前にディレクトリを開く（入った後は `/proc/self/fd/N` で触る）。
        let root = File::open(dir).unwrap_or_else(|e| fail(&format!("open target dir: {e}")));
        enter_userns();
        let base = PathBuf::from(format!("/proc/self/fd/{}", root.as_raw_fd()));
        let sub = base.join("sub");
        let step = |what: &str, r: std::io::Result<()>| {
            if let Err(e) = r {
                fail(&format!("populate {what}: {e}"));
            }
        };
        step("mkdir", std::fs::create_dir(&sub));
        step(
            "write",
            std::fs::write(sub.join("f"), b"owned by a subordinate id"),
        );
        step(
            "chmod f",
            std::fs::set_permissions(sub.join("f"), std::fs::Permissions::from_mode(0o444)),
        );
        step(
            "chmod sub",
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o555)),
        );
        step(
            "chown f",
            std::os::unix::fs::chown(sub.join("f"), Some(1), Some(1)),
        );
        step(
            "chown sub",
            std::os::unix::fs::chown(&sub, Some(1), Some(1)),
        );
        step(
            "chmod root",
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)),
        );
        step(
            "chown root",
            std::os::unix::fs::chown(&base, Some(1), Some(1)),
        );
    }

    /// 本番の helper と同じ解決で範囲写像の user namespace に入る（単一スレッドで呼ぶこと）。
    fn enter_userns() {
        use fandhe_container_core::exec::{
            IsolationConfig, IsolationPrivilege, Namespace, NamespaceSet,
            isolate_rootless_subordinate, plan_rootless_subordinate,
        };
        use fandhe_container_core::rootless::{DEFAULT_HELPER_TIMEOUT, HelperPaths, IdMapWriter};

        let resolved = fandhe_container_supervisor::start_entry::resolve_self_launch_privilege()
            .unwrap_or_else(|e| fail(&format!("resolve privilege: {e}")));
        let (IsolationPrivilege::RootlessSubordinateIds, Some(source)) = resolved else {
            fail("a subordinate id range is required");
        };
        let meta = std::fs::metadata("/proc/self")
            .unwrap_or_else(|e| fail(&format!("stat /proc/self: {e}")));
        let maps = source
            .resolve_id_maps(meta.uid(), meta.gid())
            .unwrap_or_else(|e| fail(&format!("resolve id maps: {e}")));
        let helper = HelperPaths::system_default()
            .unwrap_or_else(|e| fail(&format!("newuidmap helper: {e}")));
        let config = IsolationConfig {
            namespaces: NamespaceSet::empty().with(Namespace::User),
            hostname: None,
        };
        let plan = plan_rootless_subordinate(
            &config,
            maps.uid().clone(),
            maps.gid().clone(),
            IdMapWriter::Helper(helper),
            DEFAULT_HELPER_TIMEOUT,
        )
        .unwrap_or_else(|e| fail(&format!("plan: {e}")));
        isolate_rootless_subordinate(&plan).unwrap_or_else(|e| fail(&format!("enter userns: {e}")));
    }

    /// Remove（H3。#4800）: subuid 所有の木はホスト側では消せず、削除モードで消える。親は残る。
    fn remove_subordinate_owned_tree(launcher: &UsernsHelperLauncher, budget: WorkBudget) {
        use std::os::unix::fs::DirBuilderExt as _;
        let base = std::env::temp_dir().join(format!("userns-helper-rm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let parent = base.join("bundle");
        for d in [&base, &parent, &parent.join("rootfs")] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(d)
                .unwrap_or_else(|e| fail(&format!("create {}: {e}", d.display())));
        }
        let rootfs = parent.join("rootfs");
        let status = std::process::Command::new(BIN)
            .arg("--populate")
            .arg(&rootfs)
            .status()
            .unwrap_or_else(|e| fail(&format!("spawn populate child: {e}")));
        if !status.success() {
            fail(&format!("populate child failed: {status}"));
        }
        // 陽性対照: 最上位が subuid 所有・0700 の木はホストの uid では消せず、木は残る。
        if std::fs::remove_dir_all(&rootfs).is_ok() || !rootfs.exists() {
            fail("host-side removal unexpectedly succeeded (positive control)");
        }
        let target = File::open(&parent).unwrap_or_else(|e| fail(&format!("open parent: {e}")));
        match launcher.run(
            Mode::Remove(RemoveTarget::BundleRootfs),
            target.as_fd(),
            budget,
        ) {
            Ok(Report::Removed) => {}
            Ok(other) => fail(&format!("unexpected report: {other:?}")),
            Err(e) => fail(&format!("remove: {e} (helper={:?})", e.helper_code())),
        }
        if std::fs::symlink_metadata(&rootfs).is_ok() || !parent.is_dir() {
            fail("rootfs must be gone and the parent kept");
        }
        let _ = std::fs::remove_dir_all(&base);
        println!(
            "userns_helper_real: remove subordinate-owned tree ok (rootfs absent, parent kept)"
        );
    }

    /// 自分が所有する 0700 のディレクトリ（名前空間の中では uid 0 の所有に見える）。
    fn scratch_dir() -> PathBuf {
        use std::os::unix::fs::DirBuilderExt as _;
        let dir = std::env::temp_dir().join(format!("userns-helper-real-{}", std::process::id()));
        let _ = std::fs::remove_dir(&dir);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .unwrap_or_else(|e| fail(&format!("create scratch dir: {e}")));
        dir
    }
}
