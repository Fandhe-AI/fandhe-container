//! tmpfs マウント（`fandhe_container_core::exec::mount_tmpfs`）の結合試験（SUP-12・TASK-169.2・MS-9）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由・流れは `pivot_root_isolation.rs` と同じ
//! （`Cargo.toml` の `[[test]]`）。非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! - 親: `proc/`・`dev/`・`outside/` と symlink `link -> outside` を持つ rootfs を作る → 分離（root は
//!   rootful、非 root は rootless）→ 自身を `--child <rootfs>` で起動（新しい PID namespace の PID 1）
//!   → タイムアウト付きで終了コード 0 を待つ（REPAIR-5）→ 成功行を出力する
//! - 子: `establish` → `prepare_rootfs` の後、同じ分離の中で次を順に照合する
//!   1. **失敗時の後始末**: `/rb/one`（自動作成）→ `/link/x`（symlink で拒否）の 2 件を適用し、
//!      `path_symlink_or_not_directory` で失敗すること、1 件目の tmpfs が呼び出しスレッドの mountinfo から
//!      消えていること、自動作成した `rb` が rootfs に残らないこと、symlink の先に何も作られないこと
//!   2. **成功経路**: `/dev/shm`（64 KiB）・`/scratch`（128 KiB）・`/roexec`（`ro,exec`・64 KiB）・
//!      `/nosize`（サイズ未指定）を適用 → `pivot_root` の後、`/proc/self/mountinfo` で 4 件が fstype
//!      `tmpfs`・`nosuid,nodev` で存在し、`noexec` / `ro` が指定どおりであること、サイズ指定の 3 件が
//!      指定サイズであること、サイズ未指定の件に `size=` が出ないこと（カーネル既定のまま）、マウント先の
//!      `stat` のモードが 1777 であることを具体値で照合する
//!
//! カーネルは既定値と同じ `mode=1777`・既定サイズの `size=` を mountinfo に表示しないため
//! （`shmem_show_options`）、モードは `stat` で確かめる。サイズはページ単位へ切り上げて表示されるため、
//! 4K / 16K / 64K ページのいずれでも表示が変わらない 64 KiB の倍数を使う。rootless でも tmpfs は user
//! namespace 内で作れるため両経路とも成功を要求する（`create_default_devices` には依存しない）。
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
        ViolationReason, isolate, isolate_rootful_host_root, mount_tmpfs, pivot_root, plan,
        plan_rootful_host_root, prepare_rootfs,
    };
    use fandhe_container_core::tmpfs::{TmpfsMountSet, TmpfsMountSpec, TmpfsSize};

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
        let err = mount_tmpfs(isolation, prepared, &set).expect_err("symlink must be rejected");
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

    fn child(rootfs: &Path, _rootful: bool) {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        rollback_scenario(&isolation, &prepared, rootfs);

        let mut set = TmpfsMountSet::new();
        let kib64 = TmpfsSize::from_bytes(64 * 1024).expect("64 KiB");
        let kib128 = TmpfsSize::from_bytes(128 * 1024).expect("128 KiB");
        set.push(TmpfsMountSpec::dev_shm(kib64).expect("shm spec"))
            .expect("push shm");
        set.push(TmpfsMountSpec::new("/scratch", Some(kib128)).expect("scratch spec"))
            .expect("push scratch");
        let mut roexec = TmpfsMountSpec::new("/roexec", Some(kib64)).expect("roexec spec");
        roexec.read_only = true;
        roexec.exec = true;
        set.push(roexec).expect("push roexec");
        set.push(TmpfsMountSpec::new("/nosize", None).expect("nosize spec"))
            .expect("push nosize");
        let report = mount_tmpfs(&isolation, &prepared, &set).expect("mount tmpfs");
        let applied: Vec<(&str, Option<u64>, bool, bool)> = report
            .mounts
            .iter()
            .map(|m| (m.destination.as_str(), m.size, m.read_only, m.exec))
            .collect();
        assert_eq!(
            applied,
            vec![
                ("/dev/shm", Some(65_536), false, false),
                ("/scratch", Some(131_072), false, false),
                ("/roexec", Some(65_536), true, true),
                ("/nosize", None, false, false),
            ]
        );

        pivot_root(&isolation, prepared).expect("pivot_root");

        let info = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        // (マウント先, 表示サイズ, 読み取り専用か, noexec か)
        for (point, size, read_only, noexec) in [
            ("/dev/shm", Some("size=64k"), false, true),
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
