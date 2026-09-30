//! 基本デバイスノード作成（`fandhe_container_core::exec::create_default_devices`）の結合試験
//! （CORE-1・TASK-27.6・#834）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由・流れは `pivot_root_isolation.rs` と同じ
//! （`Cargo.toml` の `[[test]]`）。非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! - 親: `dev` を持たない rootfs（`proc/` のみ）を作る → 分離（root は rootful、非 root は rootless）
//!   → 自身を `--child <rootfs>` で起動（新しい PID namespace の PID 1）→ タイムアウト付きで終了
//!   コード 0 を待つ（REPAIR-5）
//! - 子（root）: `establish` → `prepare_rootfs` → `create_default_devices` → 再度
//!   `create_default_devices`（既存ノードは上書きせず `AlreadyPresent`）→ `pivot_root` の後、
//!   6 種の種別・`rdev`・モードを具体値で照合する
//! - 子（非 root）: 非特権 user namespace では文字デバイスの `mknod(2)` が `EPERM` になるため、
//!   `PermissionDenied`・段 `CreateDevices` で fail-closed することを照合する
//!
//! # 実機前提テストとしての分離
//! root もしくは非特権 user namespace を許可するホストが必要で、GitHub ホステッド runner では
//! 保証できないため `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。実行時は分離の
//! 拒否を含めあらゆる失敗を失敗として扱う。rootful 経路（root）の実行は root 権限コマンドのため
//! 明示指示のもとで行い、結果を PR に記録する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("default_devices: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    // `-- --ignored` を付けたときだけ実行する。子は `--child <rootfs>` で再入する。
    if std::env::args().any(|a| a == "--ignored" || a == "--child") {
        linux::run();
    } else {
        println!(
            "default_devices: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        DeviceNodeStatus, IsolationConfig, IsolationStage, MountIsolation, Namespace, NamespaceSet,
        create_default_devices, isolate, isolate_rootful_host_root, pivot_root, plan,
        plan_rootful_host_root, prepare_rootfs,
    };
    use fandhe_container_core::traits::types::ErrorCode;

    /// 期待する `(name, major, minor)`。OCI Runtime Spec の default devices（モードは全て 0666）。
    const EXPECTED: [(&str, u64, u64); 6] = [
        ("null", 1, 3),
        ("zero", 1, 5),
        ("full", 1, 7),
        ("random", 1, 8),
        ("urandom", 1, 9),
        ("tty", 5, 0),
    ];

    /// glibc の `gnu_dev_makedev` と同じ配置（下位 8 ビットの minor と 8..20 ビットの major）。
    fn makedev(major: u64, minor: u64) -> u64 {
        (major << 8) | minor
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
            .join(format!("fandhe-devices-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("proc")).expect("create rootfs/proc");
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
                if root {
                    println!("default_devices: basic device nodes verified (root=true)");
                } else {
                    println!("default_devices: rootless mknod rejected fail-closed (root=false)");
                }
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

    fn child(rootfs: &Path, rootful: bool) {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        let prepared = prepare_rootfs(&isolation, rootfs).expect("prepare rootfs");

        if !rootful {
            let err = create_default_devices(&isolation, &prepared)
                .expect_err("rootless mknod of character devices must be rejected");
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            assert_eq!(err.stage, IsolationStage::CreateDevices);
            assert!(err.violation.is_none());
            return;
        }

        // 1 回目: 6 種すべて新規作成。2 回目: 既存のため上書きせず AlreadyPresent。
        let first = create_default_devices(&isolation, &prepared).expect("create devices");
        assert_eq!(first.nodes.len(), 6);
        for (n, (name, major, minor)) in first.nodes.iter().zip(EXPECTED) {
            assert_eq!(
                (n.name, u64::from(n.major), u64::from(n.minor), n.mode),
                (name, major, minor, 0o666)
            );
            assert_eq!(n.status, DeviceNodeStatus::Created, "{name}");
        }
        let second = create_default_devices(&isolation, &prepared).expect("recreate devices");
        assert!(
            second
                .nodes
                .iter()
                .all(|n| n.status == DeviceNodeStatus::AlreadyPresent)
        );

        pivot_root(&isolation, prepared).expect("pivot_root");

        for (name, major, minor) in EXPECTED {
            let path = format!("/dev/{name}");
            let meta = std::fs::symlink_metadata(&path).expect("stat device node");
            assert!(
                meta.file_type().is_char_device(),
                "{path} must be a char device"
            );
            assert_eq!(meta.rdev(), makedev(major, minor), "{path} rdev");
            assert_eq!(meta.mode() & 0o7777, 0o666, "{path} mode");
        }
    }
}
