//! rootfs 切替（`fandhe_container_core::exec::prepare_rootfs` / `pivot_root`）の結合試験
//! （CORE-1・TASK-27.3・#135）。
//!
//! libtest はテストをスレッドで実行し、マルチスレッドからの `CLONE_NEWUSER` は `EINVAL` に
//! なるため、`harness = false` の単一スレッド `main` で動かす（`Cargo.toml` の `[[test]]`）。
//! 非 Linux では `exec` モジュール自体がビルド対象外（OS 非該当であり skip ではない）。
//!
//! # 流れ
//! - 親: 一時ディレクトリに rootfs（`proc/` と marker ファイル）を作る → 分離（`unshare_isolation` と
//!   同じ分岐: root は rootful、非 root は rootless）→ 自身を `--child <rootfs>` で起動
//!   （新しい PID namespace の PID 1 になる）→ タイムアウト付きで終了コード 0 を待つ（REPAIR-5）
//!   → 一時ディレクトリを削除
//! - 子: `MountIsolation::establish` → `prepare_rootfs` → `pivot_root` の後、具体値で照合する。
//!   `/` の内容が rootfs のみ・ホスト側パスが不可視・mountinfo に旧 root が無い・`/proc` に
//!   ホストのプロセスが見えない・cwd が `/`
//!
//! # 実機前提テストとしての分離
//! 実行には root もしくは非特権 user namespace を許可するホストが必要（AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1` 等の環境では `PermissionDenied` になる）。
//! GitHub ホステッド runner で保証できないため、`-- --ignored` 指定時のみ実行して既定のテスト集合
//! から分離している（ci.md「実機前提テスト」）。実行された場合は分離の拒否を含めあらゆる失敗を
//! 失敗として扱い、検証せずに成功終了する分岐は持たない。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("pivot_root_isolation: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    // `-- --ignored` を付けたときだけ実行する。子は `--child <rootfs>` で再入する。
    if std::env::args().any(|a| a == "--ignored" || a == "--child") {
        linux::run();
    } else {
        println!(
            "pivot_root_isolation: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        IsolationConfig, MountIsolation, Namespace, NamespaceSet, isolate,
        isolate_rootful_host_root, pivot_root, plan, plan_rootful_host_root, prepare_rootfs,
    };

    const MARKER: &str = "marker.txt";

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
                child(Path::new(rootfs));
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
            .join(format!("fandhe-pivot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("proc")).expect("create rootfs/proc");
        std::fs::write(base.join(MARKER), b"marker").expect("write marker");
        Rootfs(base)
    }

    fn parent() {
        let rootfs = make_rootfs();
        // euid 0 での自 ID 写像は SEC-5 で拒否されるため、root では User を除く rootful 構成にする。
        let is_root = std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .as_deref()
            == Some("0");
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
        match result {
            Ok(_) => {
                run_child(&rootfs.0);
                println!("pivot_root_isolation: rootfs switch verified (root={is_root})");
            }
            Err(err) => panic!("isolate failed: {err}"),
        }
    }

    /// 自身を `--child <rootfs>` で起動する。分離後の最初の子なので新しい PID namespace の PID 1 になる。
    fn run_child(rootfs: &Path) {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .arg("--child")
            .arg(rootfs)
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

    fn child(rootfs: &Path) {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        // pivot 後は元の実行ファイルのパスが見えなくなるため、先に取得しておく。
        let exe = std::env::current_exe().expect("current_exe");

        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");
        let report = pivot_root(&isolation, prepared).expect("pivot_root");
        assert!(report.old_root_detached);
        assert!(report.proc_mounted);

        // `/` の内容は作成した rootfs だけ。
        let names: BTreeSet<String> = std::fs::read_dir("/")
            .expect("read /")
            .map(|e| e.expect("dir entry").file_name().into_string().unwrap())
            .collect();
        let want: BTreeSet<String> = ["proc", MARKER].iter().map(|s| s.to_string()).collect();
        assert_eq!(names, want, "/ must contain only the container rootfs");
        assert_eq!(
            std::fs::read("/marker.txt").expect("read marker"),
            b"marker"
        );

        // ホスト側のパス（rootfs の元の場所・テストバイナリ）は見えない。
        for host_path in [rootfs, exe.as_path()] {
            let err = std::fs::metadata(host_path).unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::NotFound,
                "{host_path:?} must be invisible"
            );
        }

        // cwd は新しい `/`。
        assert_eq!(std::env::current_dir().expect("cwd"), Path::new("/"));

        // マウントは `/` と `/proc` のみで、旧 root は残っていない。
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        let mount_points: BTreeSet<String> = mountinfo
            .lines()
            .map(|l| l.split(' ').nth(4).expect("mount point field").to_string())
            .collect();
        let want: BTreeSet<String> = ["/", "/proc"].iter().map(|s| s.to_string()).collect();
        assert_eq!(mount_points, want, "only / and /proc must be mounted");

        // ホストのプロセスは不可視。
        let mut pids: Vec<String> = std::fs::read_dir("/proc")
            .expect("read /proc")
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .collect();
        pids.sort();
        assert_eq!(
            pids,
            vec!["1".to_string()],
            "host processes must be invisible"
        );
    }
}
