//! tmpfs マウント（`fandhe_container_core::exec::mount_tmpfs`）の結合試験（SUP-12・TASK-169.2・MS-9）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由・流れは `pivot_root_isolation.rs` と同じ
//! （`Cargo.toml` の `[[test]]`）。非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! 新マウント API（`fsopen`・`fsconfig`・`fsmount`・`move_mount`。Linux 5.2 以降）で載せたマウントを、実際の
//! mountinfo で照合する（SUP-12・TASK-169 追補・#1472）。
//!
//! # 流れ
//! - 親: `proc/`・`dev/`・`outside/` と symlink `link -> outside` を持つ rootfs を作る → 分離（root は
//!   rootful、非 root は rootless）→ 自身を `--child <rootfs>` で起動（新しい PID namespace の PID 1）
//!   → タイムアウト付きで終了コード 0 を待つ（REPAIR-5）→ 成功行を出力する
//! - 子: `establish` → `prepare_rootfs` の後、同じ分離の中で次を順に照合する
//!   1. **失敗時の後始末**: `/rb/one`（自動作成）→ `/link/x`（symlink で拒否）の 2 件を適用し、
//!      `path_symlink_or_not_directory` で失敗すること、1 件目の tmpfs が呼び出しスレッドの mountinfo から
//!      消えていること、自動作成した `rb` が rootfs に残らないこと、symlink の先に何も作られないこと
//!   2. **検査後の差し替え**: `exec-test-support` の入口 `mount_tmpfs_with_attach_hook` で、移動検査の後・
//!      付け替えの直前に `/swap` を改名して同名の新ディレクトリを作る。`failed_precondition` で失敗し、
//!      `swap`・`swapped` のどちらにもマウントが残らず（自分のマウントを fd で外す）、両方が空のまま残ること
//!   3. **順序の証跡**: `/dev` 配下の宛先（既定の `/dev/shm`）を含む集合を `create_default_devices` の結果なしで
//!      `mount_tmpfs` に渡すと、`failed_precondition` で拒否され `dev/shm` も作られないこと（#1669 事後監査 P2）
//!   4. **成功経路**: `/dev/shm`（未指定の既定 64 MiB。`ensure_default_dev_shm`・#1654）・`/scratch`（128 KiB）・`/roexec`（`ro,exec`・64 KiB）・
//!      `/nosize`（サイズ未指定）を適用 → `pivot_root` の後、rootfs の自己 bind の `/` に `nodev` が付いていること
//!      （`PivotReport::rootfs_nodev` と mountinfo。#1676 で rootful・rootless とも常に付与）、`/proc/self/mountinfo` で 4 件が fstype
//!      `tmpfs`・`nosuid,nodev` で存在し、`noexec` / `ro` が指定どおりであること、サイズ指定の 3 件が
//!      指定サイズであること、サイズ未指定の件に `size=` が出ないこと（カーネル既定のまま）、マウント先の
//!      `stat` のモードが 1777 であることを具体値で照合する
//!
//! カーネルは既定値と同じ `mode=1777`・既定サイズの `size=` を mountinfo に表示しないため
//! （`shmem_show_options`）、モードは `stat` で確かめる。サイズはページ単位へ切り上げて表示されるため、
//! 4K / 16K / 64K ページのいずれでも表示が変わらない 64 KiB の倍数を使う。rootless でも tmpfs は user
//! namespace 内で作れるため両経路とも成功を要求する（`create_default_devices` には依存しない）。
//! 本試験の rootfs の `dev` は素のディレクトリで、`create_default_devices`（#1653）の tmpfs の上には載らない
//! （本試験は rootless でも `create_default_devices` に依存しない構成のため。rootless の基本デバイスの供給は
//! #1660 で bind になった）。`/dev` の tmpfs の上に載る組み合わせは本番の起動順
//! （`create_default_devices` → `mount_tmpfs`）でのみ成り立ち、`mount_tmpfs` は `/dev` 配下の宛先に順序の証跡
//! （`DeviceReport`）を要求する。そのため成功経路は、順序の検査だけを省く `exec-test-support` の入口
//! `mount_tmpfs_over_bare_dev_for_test` で載せる（他の検証・後始末は `mount_tmpfs` と同一）。
//! 失敗後に同じ分離を使い続けるのは後始末の照合のためで、本番の契約（失敗時はプロセスを破棄）とは別。
//!
//! # 実機前提テストとしての分離
//! root もしくは非特権 user namespace を許可するホストが必要で、GitHub ホステッド runner では
//! 保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。CI では
//! `integration-test` ジョブ（ubuntu-latest）が AppArmor の制限を緩和した後に rootless 経路で実行し、
//! 成功行 `tmpfs_mount: mounts, flags and rollback verified (root=false)` を照合する。実行時は分離の
//! 拒否を含めあらゆる失敗を失敗として扱う。rootful 経路（root）の実行は root 権限コマンドのため
//! 明示指示のもとで行い、結果を PR に記録する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("tmpfs_mount: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    // `-- --ignored` を付けたときだけ実行する。子は `--child <rootfs>` で再入する。
    if std::env::args().any(|a| a == "--ignored" || a == "--child") {
        linux::run();
    } else {
        println!(
            "tmpfs_mount: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        IsolationConfig, IsolationStage, MountIsolation, Namespace, NamespaceSet, PreparedRootfs,
        ViolationReason, isolate, isolate_rootful_host_root, mount_tmpfs,
        mount_tmpfs_over_bare_dev_for_test, mount_tmpfs_with_attach_hook, pivot_root, plan,
        plan_rootful_host_root, prepare_rootfs,
    };
    use fandhe_container_core::tmpfs::{DevShmOrigin, TmpfsMountSet, TmpfsMountSpec, TmpfsSize};

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .as_deref()
            == Some("0")
    }

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        match args.iter().position(|a| a == "--child") {
            Some(i) => {
                let rootfs = args.get(i + 1).expect("rootfs path after --child");
                // user namespace 内では写像後の euid が 0 になり is_root() で判別できないため、
                // 親が決めた rootful / rootless を引数で受け取る。
                let rootful = args.iter().any(|a| a == "--rootful");
                child(Path::new(rootfs), rootful);
            }
            None => parent(),
        }
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn make_rootfs() -> Rootfs {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!("fandhe-tmpfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("proc")).expect("create rootfs/proc");
        std::fs::create_dir_all(base.join("dev")).expect("create rootfs/dev");
        // 失敗シナリオ用: rootfs 内の symlink（辿らずに拒否されること）とその先。
        std::fs::create_dir_all(base.join("outside")).expect("create rootfs/outside");
        // 差し替えシナリオ用: 検査後に改名される既存のマウント先。
        std::fs::create_dir_all(base.join("swap")).expect("create rootfs/swap");
        std::os::unix::fs::symlink("outside", base.join("link")).expect("create rootfs/link");
        Rootfs(base)
    }

    fn parent() {
        let rootfs = make_rootfs();
        let root = is_root();
        // euid 0 での自 ID 写像は SEC-5 で拒否されるため、root では User を除く rootful 構成にする。
        let mut namespaces = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        if !root {
            namespaces = namespaces.with(Namespace::User);
        }
        let config = IsolationConfig {
            namespaces,
            hostname: None,
        };
        let result = if root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        match result {
            Ok(_) => {
                run_child(&rootfs.0, root);
                println!("tmpfs_mount: mounts, flags and rollback verified (root={root})");
            }
            Err(err) => panic!("isolate failed: {err}"),
        }
    }

    /// 自身を `--child <rootfs>` で起動する。分離後の最初の子なので新しい PID namespace の PID 1 になる。
    fn run_child(rootfs: &Path, rootful: bool) {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .arg("--child")
            .arg(rootfs)
            .arg(if rootful { "--rootful" } else { "--rootless" })
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn child");
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    assert_eq!(status.code(), Some(0), "child must exit with 0");
                    return;
                }
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("child did not exit within {:?}", timeout());
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    /// `/proc/self/mountinfo` の 1 行から `(mount_point, mount_options, fstype, super_options)` を取り出す。
    fn parse_line(line: &str) -> Option<(String, String, String, String)> {
        let fields: Vec<&str> = line.split(' ').collect();
        let sep = fields.iter().position(|f| *f == "-")?;
        Some((
            (*fields.get(4)?).to_owned(),
            (*fields.get(5)?).to_owned(),
            (*fields.get(sep + 1)?).to_owned(),
            (*fields.get(sep + 3)?).to_owned(),
        ))
    }

    /// 失敗時の後始末（SUP-12・TASK-169.2）: 2 件目が symlink で拒否されたら、1 件目の tmpfs が
    /// mountinfo から消え、自動作成したディレクトリも rootfs に残らない。
    fn rollback_scenario(isolation: &MountIsolation, prepared: &PreparedRootfs, rootfs: &Path) {
        let mut set = TmpfsMountSet::new();
        set.push(TmpfsMountSpec::new("/rb/one", None).expect("rb spec"))
            .expect("push rb");
        set.push(TmpfsMountSpec::new("/link/x", None).expect("link spec"))
            .expect("push link");
        let err =
            mount_tmpfs(isolation, prepared, None, &set).expect_err("symlink must be rejected");
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(
            err.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::PathSymlinkOrNotDirectory)
        );
        // pivot 前なので、呼び出しスレッドの mount namespace を元の procfs 経由で読む。
        let info = std::fs::read_to_string("/proc/thread-self/mountinfo").expect("mountinfo");
        let leftover: Vec<String> = info
            .lines()
            .filter_map(parse_line)
            .map(|l| l.0)
            .filter(|point| point.ends_with("/rb/one") || point.ends_with("/rb"))
            .collect();
        assert_eq!(
            leftover,
            Vec::<String>::new(),
            "the first tmpfs must be unmounted"
        );
        assert_eq!(
            std::fs::symlink_metadata(rootfs.join("rb"))
                .map(|m| m.is_dir())
                .map_err(|e| e.kind()),
            Err(std::io::ErrorKind::NotFound),
            "auto-created directories must be removed"
        );
        assert_eq!(
            std::fs::read_dir(rootfs.join("outside"))
                .expect("read outside")
                .count(),
            0,
            "nothing must be created behind the symlink"
        );
    }

    /// 検査後の差し替え（SUP-12・TASK-169 追補・#1472）: 移動検査の後・付け替えの直前にマウント先を改名し
    /// 同名の新しいディレクトリを作っても、tmpfs は固定した実体（改名後の `swapped`）にしか載らず、名前の
    /// 位置（新しい `swap`）には載らない。事後検証が `failed_precondition` で拒否し、自分のマウントを fd で
    /// 外すため、どちらにもマウントは残らない。
    fn swap_scenario(isolation: &MountIsolation, prepared: &PreparedRootfs, rootfs: &Path) {
        let mut set = TmpfsMountSet::new();
        set.push(TmpfsMountSpec::new("/swap", None).expect("swap spec"))
            .expect("push swap");
        let (from, to) = (rootfs.join("swap"), rootfs.join("swapped"));
        let err = mount_tmpfs_with_attach_hook(isolation, prepared, None, &set, &|| {
            std::fs::rename(&from, &to).expect("rename swap");
            std::fs::create_dir(&from).expect("recreate swap");
        })
        .expect_err("swapped target must be rejected");
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(
            err.code,
            fandhe_container_core::traits::types::ErrorCode::FailedPrecondition
        );
        let info = std::fs::read_to_string("/proc/thread-self/mountinfo").expect("mountinfo");
        let leftover: Vec<String> = info
            .lines()
            .filter_map(parse_line)
            .map(|l| l.0)
            .filter(|point| point.ends_with("/swap") || point.ends_with("/swapped"))
            .collect();
        assert_eq!(
            leftover,
            Vec::<String>::new(),
            "our mount must be unmounted by fd"
        );
        for name in ["swap", "swapped"] {
            assert_eq!(
                std::fs::read_dir(rootfs.join(name))
                    .unwrap_or_else(|e| panic!("{name} must remain a directory: {e}"))
                    .count(),
                0,
                "{name} must stay empty"
            );
        }
    }

    fn child(rootfs: &Path, _rootful: bool) {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        rollback_scenario(&isolation, &prepared, rootfs);
        swap_scenario(&isolation, &prepared, rootfs);

        let mut set = TmpfsMountSet::new();
        let kib64 = TmpfsSize::from_bytes(64 * 1024).expect("64 KiB");
        let kib128 = TmpfsSize::from_bytes(128 * 1024).expect("128 KiB");
        set.push(TmpfsMountSpec::new("/scratch", Some(kib128)).expect("scratch spec"))
            .expect("push scratch");
        let mut roexec = TmpfsMountSpec::new("/roexec", Some(kib64)).expect("roexec spec");
        roexec.read_only = true;
        roexec.exec = true;
        set.push(roexec).expect("push roexec");
        set.push(TmpfsMountSpec::new("/nosize", None).expect("nosize spec"))
            .expect("push nosize");
        // `/dev/shm` は指定せず、既定 64 MiB が集合の先頭へ足されることを使う（#1654）。
        assert_eq!(
            set.ensure_default_dev_shm().expect("default shm"),
            DevShmOrigin::Default
        );
        // 順序の証跡（SUP-12・CORE-1・#1669 事後監査 P2）: `/dev` 配下の宛先を含む集合は、同じ rootfs に対する
        // `create_default_devices` の結果なしでは何も作らずに拒否される（`dev/shm` も作られない）。
        let err = mount_tmpfs(&isolation, &prepared, None, &set).expect_err("order evidence");
        assert_eq!(err.stage, IsolationStage::MountTmpfs);
        assert_eq!(
            err.code,
            fandhe_container_core::traits::types::ErrorCode::FailedPrecondition
        );
        assert_eq!(
            err.message,
            "tmpfs mounts under /dev require create_default_devices to run first on the same rootfs"
        );
        assert!(
            !rootfs.join("dev/shm").exists(),
            "no dev/shm before the order check"
        );
        // 本試験の `dev` は素のディレクトリ（`create_default_devices` に依存しない構成。#1660）のため、
        // 順序の検査だけを省く試験専用の入口でフラグ・サイズ・モードを照合する。
        let report =
            mount_tmpfs_over_bare_dev_for_test(&isolation, &prepared, &set).expect("mount tmpfs");
        let applied: Vec<(&str, Option<u64>, bool, bool)> = report
            .mounts
            .iter()
            .map(|m| (m.destination.as_str(), m.size, m.read_only, m.exec))
            .collect();
        assert_eq!(
            applied,
            vec![
                ("/dev/shm", Some(67_108_864), false, false),
                ("/scratch", Some(131_072), false, false),
                ("/roexec", Some(65_536), true, true),
                ("/nosize", None, false, false),
            ]
        );

        let report = pivot_root(&isolation, prepared).expect("pivot_root");

        let info = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        // `prepare_rootfs` は rootful・rootless とも rootfs の自己 bind に `nodev` を付ける（#1676。オーナー判断
        // 2026-10-10）。CI の integration-test は本試験を rootless で走らせるため、rootless で `mount_setattr(2)` が
        // 通り `nodev` が `/` に付くことの照合を兼ねる。
        assert!(report.rootfs_nodev, "rootfs self-bind must be nodev");
        let (_, root_opts, _, _) = info
            .lines()
            .filter_map(parse_line)
            .find(|l| l.0 == "/")
            .unwrap_or_else(|| panic!("/ must be mounted:\n{info}"));
        assert!(
            root_opts.split(',').any(|o| o == "nodev"),
            "/ must be nodev: {root_opts}"
        );
        // (マウント先, 表示サイズ, 読み取り専用か, noexec か)
        for (point, size, read_only, noexec) in [
            ("/dev/shm", Some("size=65536k"), false, true),
            ("/scratch", Some("size=128k"), false, true),
            ("/roexec", Some("size=64k"), true, false),
            ("/nosize", None, false, true),
        ] {
            let (_, opts, fstype, sup) = info
                .lines()
                .filter_map(parse_line)
                .find(|l| l.0 == point)
                .unwrap_or_else(|| panic!("{point} must be mounted:\n{info}"));
            assert_eq!(fstype, "tmpfs", "{point} fstype");
            let opts: Vec<&str> = opts.split(',').collect();
            for want in ["nosuid", "nodev"] {
                assert!(opts.contains(&want), "{point} must be {want}: {opts:?}");
            }
            assert_eq!(opts.contains(&"noexec"), noexec, "{point} noexec: {opts:?}");
            assert_eq!(opts.contains(&"ro"), read_only, "{point} ro: {opts:?}");
            assert_eq!(opts.contains(&"rw"), !read_only, "{point} rw: {opts:?}");
            let sup: Vec<&str> = sup.split(',').collect();
            // superblock 側も読み取り専用（旧 `MS_RDONLY` と同じく superblock とマウントの両方が ro）。
            assert_eq!(sup.contains(&"ro"), read_only, "{point} super ro: {sup:?}");
            assert_eq!(sup.contains(&"rw"), !read_only, "{point} super rw: {sup:?}");
            let shown: Vec<&str> = sup
                .iter()
                .copied()
                .filter(|o| o.starts_with("size="))
                .collect();
            // サイズ未指定はカーネル既定のままで、mountinfo に `size=` が出ない。
            assert_eq!(shown, size.into_iter().collect::<Vec<_>>(), "{point} size");
            // 既定値 1777 は mountinfo に出ないため、マウント先そのもののモードで照合する。
            let mode = std::fs::metadata(point)
                .unwrap_or_else(|e| panic!("stat {point}: {e}"))
                .permissions()
                .mode()
                & 0o7777;
            assert_eq!(mode, 0o1777, "{point} mode");
        }
    }
}
