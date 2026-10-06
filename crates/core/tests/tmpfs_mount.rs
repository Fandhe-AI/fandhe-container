//! tmpfs マウント（`fandhe_container_core::exec::mount_tmpfs`）の結合試験（SUP-12・TASK-169.2・MS-9）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由・流れは `pivot_root_isolation.rs` と同じ
//! （`Cargo.toml` の `[[test]]`）。非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! - 親: `proc/` と `dev/` を持つ rootfs を作る → 分離（root は rootful、非 root は rootless）
//!   → 自身を `--child <rootfs>` で起動（新しい PID namespace の PID 1）→ タイムアウト付きで終了
//!   コード 0 を待つ（REPAIR-5）
//! - 子: `establish` → `prepare_rootfs` → `mount_tmpfs`（`/dev/shm` 64 KiB・`/scratch` 16 KiB 相当）
//!   → `pivot_root` の後、`/proc/self/mountinfo` で 2 件が fstype `tmpfs`・`nosuid,nodev,noexec`・
//!   指定サイズ・mode 1777 でマウントされていることを具体値で照合する。rootless でも tmpfs は
//!   user namespace 内で作れるため両経路とも成功を要求する（`create_default_devices` には依存しない）
//!
//! # 実機前提テストとしての分離
//! root もしくは非特権 user namespace を許可するホストが必要で、GitHub ホステッド runner では
//! 保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。実行時は分離の
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
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        IsolationConfig, MountIsolation, Namespace, NamespaceSet, isolate,
        isolate_rootful_host_root, mount_tmpfs, pivot_root, plan, plan_rootful_host_root,
        prepare_rootfs,
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
                println!("tmpfs_mount: tmpfs mounts verified (root={root})");
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

    fn child(rootfs: &Path, _rootful: bool) {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        let mut set = TmpfsMountSet::new();
        let shm = TmpfsSize::from_bytes(64 * 1024).expect("shm size");
        let scratch = TmpfsSize::from_bytes(16 * 1024).expect("scratch size");
        set.push(TmpfsMountSpec::dev_shm(shm).expect("shm spec"))
            .expect("push shm");
        set.push(TmpfsMountSpec::new("/scratch", Some(scratch)).expect("scratch spec"))
            .expect("push scratch");
        let report = mount_tmpfs(&isolation, &prepared, &set).expect("mount tmpfs");
        assert_eq!(report.mounts.len(), 2);
        assert_eq!(report.mounts[0].destination, "/dev/shm");
        assert_eq!(report.mounts[0].size, Some(65536));
        assert_eq!(report.mounts[1].destination, "/scratch");
        assert_eq!(report.mounts[1].size, Some(16384));

        pivot_root(&isolation, prepared).expect("pivot_root");

        let info = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        for (point, size) in [("/dev/shm", "size=64k"), ("/scratch", "size=16k")] {
            let (_, opts, fstype, sup) = info
                .lines()
                .filter_map(parse_line)
                .find(|l| l.0 == point)
                .unwrap_or_else(|| panic!("{point} must be mounted:\n{info}"));
            assert_eq!(fstype, "tmpfs", "{point} fstype");
            let opts: Vec<&str> = opts.split(',').collect();
            for want in ["nosuid", "nodev", "noexec"] {
                assert!(opts.contains(&want), "{point} must be {want}: {opts:?}");
            }
            let sup: Vec<&str> = sup.split(',').collect();
            assert!(sup.contains(&size), "{point} must have {size}: {sup:?}");
            assert!(sup.contains(&"mode=1777"), "{point} mode: {sup:?}");
        }
    }
}
