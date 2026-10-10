//! namespace 分離（`fandhe_container_core::exec::isolate`）の結合試験（CORE-1・SEC-5・
//! TASK-27.2・#134）。
//!
//! libtest はテストをスレッドで実行し、マルチスレッドからの `CLONE_NEWUSER` は `EINVAL` に
//! なるため、`harness = false` の単一スレッド `main` で動かす（`Cargo.toml` の `[[test]]`）。
//! 非 Linux では `exec` モジュール自体がビルド対象外（OS 非該当であり skip ではない）。
//!
//! # 流れ
//! - 親: 分離（hostname `fandhe-probe`）→ hostname を照合 → 自身を `--child` で起動
//!   （新しい PID namespace の PID 1 になる）→ タイムアウト付きで終了コード 0 を待つ（REPAIR-5）
//! - 子: PID が 1 → `/proc` をマウント → `/proc` の数値ディレクトリが `1` のみ
//!   （ホストのプロセスが不可視）→ hostname を照合
//!
//! # 実機前提テストとしての分離
//! 実行には root もしくは非特権 user namespace を許可するホストが必要（AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1` 等の環境では `PermissionDenied` になる）。
//! 既定のテスト集合（`--all-features` を含む）からは `#[ignore]` 相当（`-- --ignored` 指定時のみ実行）で
//! 分離している（ci.md「実機前提テスト」）。CI では `platform-ci`（ubuntu-latest）が AppArmor の
//! 制限を緩めた上で `--ignored` 付きで実行する（#1159）。実行された場合は分離の拒否を含め
//! あらゆる失敗を失敗として扱い、検証せずに成功終了する分岐は持たない。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("unshare_isolation: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    // `#[ignore]` 相当: `-- --ignored` を付けたときだけ実行する（`--all-features` を含む
    // 既定の `cargo test --workspace` では実行されない）。子は `--child` で再入する。
    if std::env::args().any(|a| a == "--ignored" || a == "--child") {
        linux::run();
    } else {
        println!(
            "unshare_isolation: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        Hostname, IsolationConfig, IsolationPrivilege, MountIsolation, Namespace, NamespaceSet,
        isolate, isolate_rootful_host_root, mount_proc, plan, plan_rootful_host_root,
    };

    const HOSTNAME: &str = "fandhe-probe";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn read_hostname() -> String {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .expect("read hostname")
            .trim()
            .to_string()
    }

    pub fn run() {
        if std::env::args().any(|a| a == "--child") {
            child();
        } else {
            parent();
        }
    }

    fn parent() {
        // euid 0 での自 ID 写像は SEC-5 で拒否されるため、root では User を除く rootful 構成
        // （CORE-7・CORE-9。`plan_rootful_host_root`）にする。
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
            hostname: Some(Hostname::new(HOSTNAME).expect("valid hostname")),
        };

        let host_before = read_hostname();
        // root は sudo 起動の rootful 経路（ホスト root のまま・User なし）、非 root は既定経路。
        let result = if is_root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        match result {
            Ok(report) => {
                assert_eq!(report.namespaces, namespaces);
                let want = if is_root {
                    IsolationPrivilege::RootfulHostRoot
                } else {
                    IsolationPrivilege::RootlessSingleId
                };
                assert_eq!(report.privilege, want);
                assert_eq!(read_hostname(), HOSTNAME);
                assert_ne!(
                    host_before, HOSTNAME,
                    "host hostname must not be the probe name"
                );
                run_child();
                println!("unshare_isolation: full isolation verified (root={is_root})");
            }
            Err(err) => panic!("isolate failed: {err}"),
        }
    }

    /// 自身を `--child` で起動する。分離後の最初の子なので新しい PID namespace の PID 1 になる。
    fn run_child() {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .arg("--child")
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

    fn child() {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        mount_proc(&isolation, Path::new("/"), Path::new("/proc")).expect("mount proc");
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
        assert_eq!(read_hostname(), HOSTNAME);
    }
}
