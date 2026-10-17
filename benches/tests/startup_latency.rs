//! 起動 p95 ベンチ（`startup_latency`）の入口契約の結合試験（TASK-190・#1900・REPAIR-8・REPAIR-10・REPAIR-12）。
//!
//! 実機（systemd・user namespace・supervisor の bin）を使わずに、公開入口（`parse_args` → `execute`）の
//! 引数解析・スモーク・fail-closed のエラー（機械可読な `code`）への接続を、実ファイルシステム上で照合する。
//! 実測そのもの（`Execution::Done`）は実機前提のため対象外（人間担当。AGENTS.md）。
//! Linux（x86_64 / aarch64）のみ。他 OS は `Execution::Unsupported` を返す契約を別に照合する。

use fandhe_container_benches::startup_latency::args::{Command, parse_args};
use fandhe_container_benches::startup_latency::{Execution, execute};

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_string()).collect()
}

/// 引数なし（`--bench` は無視）は何も起動しないスモークで、1 行を返す。
#[test]
fn no_args_runs_smoke_without_launching_anything() {
    let cmd = parse_args(&args(&["--bench"])).expect("smoke");
    assert_eq!(cmd, Command::Smoke);
    match execute(cmd).expect("smoke result") {
        Execution::Smoke(line) => {
            assert!(line.starts_with("startup_latency:"), "got {line}");
            assert!(!line.contains('\n'));
        }
        other => panic!("expected Smoke, got {other:?}"),
    }
}

#[test]
fn invalid_args_are_rejected_with_a_machine_readable_code() {
    for bad in [
        &["--trials", "19", "--supervisor-bin", "/x"][..],
        &["--unknown"],
        &["--supervisor-bin", "relative/path"],
        &["--trials", "20"],
    ] {
        let e = parse_args(&args(bad)).expect_err("must reject");
        assert_eq!(e.code, "invalid-args", "{bad:?}");
        assert_eq!(
            e.to_string().matches('\n').count(),
            0,
            "error is one JSON line"
        );
        assert!(
            e.to_string()
                .starts_with("{\"error\":{\"code\":\"invalid-args\"")
        );
    }
}

#[cfg(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    /// 0700 の専用ディレクトリ（テスト後に削除）。
    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("fc-sl-it-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir(&p).expect("mkdir");
            chmod(&p, 0o700);
            Self(p)
        }

        fn exe(&self, name: &str, mode: u32) -> PathBuf {
            let f = self.0.join(name);
            std::fs::write(&f, b"#!/bin/sh\n").expect("write");
            chmod(&f, mode);
            f
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn chmod(p: &Path, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Uid:").map(str::to_string))
            })
            .and_then(|u| u.split_whitespace().nth(1).map(|v| v == "0"))
            .unwrap_or(false)
    }

    fn measure_err(a: &[&str]) -> fandhe_container_benches::startup_latency::StartupLatencyError {
        let cmd = parse_args(&args(a)).expect("plan");
        execute(cmd).expect_err("must fail closed before launching anything")
    }

    /// 書き込み可能な supervisor bin は起動前に拒否される（root は別の理由で拒否される）。
    #[test]
    fn writable_supervisor_bin_is_rejected_before_launch() {
        let d = Dir::new("bin");
        let sup = d.exe("sup", 0o777);
        let sd = d.exe("sd", 0o755);
        let e = measure_err(&[
            "--supervisor-bin",
            sup.to_str().expect("utf8"),
            "--systemd-run",
            sd.to_str().expect("utf8"),
        ]);
        let want = if is_root() {
            "unsupported-environment"
        } else {
            "untrusted-binary"
        };
        assert_eq!(e.code, want);
    }

    /// 既存の出力先（FIFO・symlink 等を含む）は、計測を始める前に拒否される（開かない）。
    #[test]
    fn existing_output_target_is_rejected_before_launch() {
        if is_root() {
            return; // root は入口で unsupported-environment になる。
        }
        let d = Dir::new("out");
        let sup = d.exe("sup", 0o755);
        let sd = d.exe("sd", 0o755);
        let existing = d.exe("r.json", 0o600);
        let e = measure_err(&[
            "--supervisor-bin",
            sup.to_str().expect("utf8"),
            "--systemd-run",
            sd.to_str().expect("utf8"),
            "--output",
            existing.to_str().expect("utf8"),
        ]);
        assert_eq!(e.code, "untrusted-output");
        assert_eq!(e.message, "output path already exists");
    }

    /// 他者が書き込める作業ディレクトリの親は、作業ディレクトリを作る前に拒否される。
    #[test]
    fn world_writable_work_dir_parent_is_rejected_before_creating_anything() {
        if is_root() {
            return; // root は入口で unsupported-environment になる（上のテストが照合）。
        }
        let d = Dir::new("wd");
        let sup = d.exe("sup", 0o755);
        let sd = d.exe("sd", 0o755);
        let base = d.0.join("base");
        std::fs::create_dir(&base).expect("mkdir");
        chmod(&base, 0o777);
        let e = measure_err(&[
            "--supervisor-bin",
            sup.to_str().expect("utf8"),
            "--systemd-run",
            sd.to_str().expect("utf8"),
            "--work-dir",
            base.to_str().expect("utf8"),
        ]);
        chmod(&base, 0o700);
        assert_eq!(e.code, "untrusted-work-dir");
        assert_eq!(e.message, "ancestor directory is writable by others");
        let entries = std::fs::read_dir(&base).expect("read").count();
        assert_eq!(entries, 0, "nothing may be created under the rejected base");
    }

    /// 診断モード（`--scope-only`。CORE-10・TASK-190・#2124）は公開入口から `Command::ScopeOnly` として
    /// 本計測と別の経路へ届き、書き込み可能な `systemd-run` を起動前に拒否する（root は別の理由で拒否される）。
    #[test]
    fn scope_only_entry_rejects_writable_systemd_run_before_launch() {
        let d = Dir::new("so-sd");
        let sd = d.exe("sd", 0o777);
        let cmd = parse_args(&args(&[
            "--scope-only",
            "--systemd-run",
            sd.to_str().expect("utf8"),
        ]))
        .expect("plan");
        assert!(matches!(cmd, Command::ScopeOnly(_)), "got {cmd:?}");
        let e = execute(cmd).expect_err("must fail closed before launching anything");
        let want = if is_root() {
            "unsupported-environment"
        } else {
            "untrusted-binary"
        };
        assert_eq!(e.code, want);
    }

    /// 診断モード（CORE-10・TASK-190・#2124）: 既存の出力先は、scope を起動する前に拒否される。
    #[test]
    fn scope_only_entry_rejects_existing_output_before_launch() {
        if is_root() {
            return; // root は入口で unsupported-environment になる。
        }
        let d = Dir::new("so-out");
        let sd = d.exe("sd", 0o755);
        let existing = d.exe("r.json", 0o600);
        let cmd = parse_args(&args(&[
            "--scope-only",
            "--systemd-run",
            sd.to_str().expect("utf8"),
            "--output",
            existing.to_str().expect("utf8"),
        ]))
        .expect("plan");
        let e = execute(cmd).expect_err("must fail closed before launching anything");
        assert_eq!(e.code, "untrusted-output");
        assert_eq!(e.message, "output path already exists");
    }
}

#[cfg(not(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[cfg(unix)]
#[test]
fn measure_is_unsupported_off_linux() {
    let cmd = parse_args(&args(&["--supervisor-bin", "/x"])).expect("plan");
    assert!(matches!(execute(cmd), Ok(Execution::Unsupported)));
}

/// 診断モード（`--scope-only`。CORE-10・TASK-190・#2124）も、非対応 OS では計測したように見せず
/// `Execution::Unsupported` を返す。
#[cfg(not(all(
    target_os = "linux",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn scope_only_is_unsupported_off_linux() {
    let cmd = parse_args(&args(&["--scope-only"])).expect("plan");
    assert!(matches!(cmd, Command::ScopeOnly(_)), "got {cmd:?}");
    assert!(matches!(execute(cmd), Ok(Execution::Unsupported)));
}
