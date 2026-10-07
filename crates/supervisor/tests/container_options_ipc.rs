//! `--ipc=host` / `--ipc=shareable` の IPC namespace 共有・分離の結合試験
//! （SUP-12・TASK-169.3・#528・CORE-1）。
//!
//! `ContainerOptions` の `IpcMode` を `NamespaceSet` へ反映し、core の `exec::isolate` で分離した後の
//! `/proc/self/ns/ipc` の識別子を照合する。
//! - `host`: 分離後も親（ホスト側）と同じ IPC namespace（識別子が一致）
//! - `shareable`: 親と異なる専用 IPC namespace。分離済みの子が起動する孫とは同じ namespace を共有する
//!   （別コンテナからの join は未実装のため対象外。REPAIR-3）
//!
//! libtest はテストをスレッドで実行し、マルチスレッドからの `CLONE_NEWUSER` は `EINVAL` になるため
//! `harness = false` の単一スレッド `main` で動かす（`Cargo.toml` の `[[test]]`）。
//!
//! # 実機前提テストとしての分離
//! root もしくは非特権 user namespace を許可するホストが必要（AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1` 等では `PermissionDenied` になる）。`-- --ignored`
//! 指定時のみ実行し、CI では `integration-test`（ubuntu-latest）が実行する（AGENTS.md）。
//! 実行された場合は分離の拒否を含むあらゆる失敗を失敗として扱い、検証せず成功する分岐は持たない。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("container_options_ipc: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored" || a == "--child" || a == "--grandchild") {
        linux::run();
    } else {
        println!(
            "container_options_ipc: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        IsolationConfig, Namespace, NamespaceSet, isolate, isolate_rootful_host_root, plan,
        plan_rootful_host_root,
    };
    use fandhe_container_supervisor::container_options::{ContainerOptions, IpcMode};

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn ipc_id() -> String {
        std::fs::read_link("/proc/self/ns/ipc")
            .expect("read /proc/self/ns/ipc")
            .to_string_lossy()
            .into_owned()
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

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--grandchild") {
            grandchild(args.get(i + 1).expect("expected ipc id"));
        } else if let Some(i) = args.iter().position(|a| a == "--child") {
            child(
                args.get(i + 1).expect("expected mode"),
                args.get(i + 2).expect("expected parent ipc id"),
            );
        } else {
            parent();
        }
    }

    /// 子プロセスを終了コード 0 までタイムアウト付きで待つ（REPAIR-5）。
    fn wait_ok(mut child: Child, what: &str) {
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    assert_eq!(status.code(), Some(0), "{what} must exit with 0");
                    return;
                }
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{what} did not exit within {:?}", timeout());
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn spawn_self(args: &[&str]) -> Child {
        Command::new(std::env::current_exe().expect("current_exe"))
            .args(args)
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn self")
    }

    fn parent() {
        let host_id = ipc_id();
        for mode in ["host", "shareable"] {
            wait_ok(
                spawn_self(&["--child", mode, &host_id]),
                &format!("child({mode})"),
            );
        }
        println!(
            "container_options_ipc: host shared / shareable isolated verified (root={})",
            is_root()
        );
    }

    fn child(mode: &str, parent_id: &str) {
        let mode = IpcMode::parse(mode).expect("parse ipc mode");
        let options = ContainerOptions::new().with_ipc_mode(mode);
        let root = is_root();
        // Pid / Mount を含めず `/proc` の再マウントを不要にする。root では User を除く（SEC-5）。
        let mut base = NamespaceSet::empty().with(Namespace::Uts);
        if !root {
            base = base.with(Namespace::User);
        }
        let namespaces = options.ipc_mode().apply_to(base);
        let config = IsolationConfig {
            namespaces,
            hostname: None,
        };
        let result = if root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        let report = result.unwrap_or_else(|e| panic!("isolate failed: {e}"));
        let id = ipc_id();
        match mode {
            IpcMode::Host => {
                assert!(!report.namespaces.contains(Namespace::Ipc));
                assert_eq!(id, parent_id, "host mode must share the host IPC namespace");
            }
            IpcMode::Shareable => {
                assert!(report.namespaces.contains(Namespace::Ipc));
                assert_ne!(
                    id, parent_id,
                    "shareable mode must isolate the IPC namespace"
                );
                // 同じ IPC namespace を複数プロセスで共有できること（別コンテナからの join は未実装）。
                wait_ok(spawn_self(&["--grandchild", &id]), "grandchild");
            }
            _ => panic!("unexpected ipc mode in test"),
        }
    }

    fn grandchild(child_id: &str) {
        assert_eq!(
            ipc_id(),
            child_id,
            "descendants must share the IPC namespace"
        );
    }
}
