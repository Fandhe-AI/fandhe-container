//! 基本デバイスノード作成（`fandhe_container_core::exec::create_default_devices`）の結合試験
//! （CORE-1・TASK-27.6・#834）。
//!
//! `harness = false` の単一スレッド `main` で動かす理由・流れは `pivot_root_isolation.rs` と同じ
//! （`Cargo.toml` の `[[test]]`）。非 Linux では `exec` モジュール自体がビルド対象外。
//!
//! # 流れ
//! - 親（root）: `proc/` と、偽ノードとして通常ファイル `dev/null` を持つ rootfs を作る。親（非 root）: `dev` を
//!   持たない rootfs（`proc/` のみ）を作る。分離（root は rootful、非 root は rootless）→ 自身を
//!   `--child <rootfs>` で起動（新しい PID namespace の PID 1）→ タイムアウト付きで終了コード 0 を待つ
//!   （REPAIR-5）。子の終了後、ホスト側の rootfs を照合する
//! - 子（root）: `establish` → `prepare_rootfs` → `create_default_devices`（1 回。`dev` に専用の tmpfs を載せて
//!   から 6 種と symlink 4 本を作る。#1653）→ `pivot_root` の後、`/dev` の mountinfo（tmpfs・`nosuid` あり・
//!   `nodev` なし）、6 種の種別・`rdev`・モード、symlink 4 本の参照先を具体値で照合する。親は、ホスト側の
//!   偽ノードが内容ごと不変で、`dev` に新エントリが増えていないことを照合する
//! - 子（非 root）: 非特権 user namespace では tmpfs までは載るが文字デバイスの `mknod(2)` が `EPERM` に
//!   なるため、`PermissionDenied`・段 `CreateDevices` で fail-closed し、載せた tmpfs が外れていることを
//!   照合する。親は、この呼び出しが作った `dev` がホスト側から消えていることを照合する
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
        DeviceLinkStatus, DeviceNodeStatus, IsolationConfig, IsolationStage, MountIsolation,
        Namespace, NamespaceSet, create_default_devices, isolate, isolate_rootful_host_root,
        pivot_root, plan, plan_rootful_host_root, prepare_rootfs,
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

    /// ホスト側 rootfs の `dev/null` に置く偽ノード（通常ファイル）の内容。
    const FAKE_NULL: &[u8] = b"fake-null";

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
        if is_root() {
            // イメージ同梱の偽ノード。tmpfs に覆い隠され、コンテナからは見えずホスト側は不変であること。
            std::fs::create_dir_all(base.join("dev")).expect("create rootfs/dev");
            std::fs::write(base.join("dev/null"), FAKE_NULL).expect("write fake node");
        }
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
                    // 偽ノードは tmpfs に覆い隠されただけで、ホスト側は内容ごと不変・新エントリなし。
                    assert_eq!(
                        std::fs::read(rootfs.0.join("dev/null")).expect("read fake node"),
                        FAKE_NULL
                    );
                    let entries: Vec<_> = std::fs::read_dir(rootfs.0.join("dev"))
                        .expect("read host dev")
                        .map(|e| e.expect("entry").file_name())
                        .collect();
                    assert_eq!(entries, vec![std::ffi::OsString::from("null")]);
                    println!(
                        "default_devices: /dev tmpfs, basic device nodes and default links verified (root=true)"
                    );
                } else {
                    // この呼び出しが作った `dev` は後始末で消えている。
                    assert!(
                        !rootfs.0.join("dev").exists(),
                        "created dev must be removed on failure"
                    );
                    println!(
                        "default_devices: rootless mknod rejected fail-closed and /dev tmpfs rolled back (root=false)"
                    );
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
            // mknod まで到達した（tmpfs のマウントと事後検証は通った）ことと、後始末で外れたこと。
            assert!(err.message.contains("mknodat(null)"), "{}", err.message);
            let mountinfo =
                std::fs::read_to_string("/proc/thread-self/mountinfo").expect("read mountinfo");
            let dev_mount = rootfs.join("dev");
            assert!(
                !mountinfo
                    .lines()
                    .any(|l| l.split_whitespace().nth(4) == dev_mount.to_str()),
                "the /dev tmpfs must be unmounted after failure"
            );
            return;
        }

        // 1 回だけ呼ぶ（同じ PreparedRootfs への 2 回目は tmpfs が重なるため契約外）。
        let first = create_default_devices(&isolation, &prepared).expect("create devices");
        assert_eq!(first.nodes.len(), 6);
        for (n, (name, major, minor)) in first.nodes.iter().zip(EXPECTED) {
            assert_eq!(
                (n.name, u64::from(n.major), u64::from(n.minor), n.mode),
                (name, major, minor, 0o666)
            );
            assert_eq!(n.status, DeviceNodeStatus::Created, "{name}");
        }
        assert_eq!(first.links.len(), 4);
        assert!(
            first
                .links
                .iter()
                .all(|l| l.status == DeviceLinkStatus::Created)
        );

        pivot_root(&isolation, prepared).expect("pivot_root");

        // `/dev` は専用の tmpfs で、`nosuid` あり・`nodev` なし。
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo").expect("read mountinfo");
        let dev_lines: Vec<_> = mountinfo
            .lines()
            .filter(|l| l.split_whitespace().nth(4) == Some("/dev"))
            .collect();
        assert_eq!(dev_lines.len(), 1, "exactly one mount at /dev");
        let fields: Vec<_> = dev_lines[0].split_whitespace().collect();
        let options: Vec<_> = fields[5].split(',').collect();
        assert!(options.contains(&"nosuid"), "{}", dev_lines[0]);
        assert!(!options.contains(&"nodev"), "{}", dev_lines[0]);
        let sep = fields.iter().position(|f| *f == "-").expect("separator");
        assert_eq!(fields[sep + 1], "tmpfs", "{}", dev_lines[0]);

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
        for (name, target) in [
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
        ] {
            let path = format!("/dev/{name}");
            assert_eq!(
                std::fs::read_link(&path).expect("readlink"),
                std::path::PathBuf::from(target),
                "{path} target"
            );
        }
    }
}
