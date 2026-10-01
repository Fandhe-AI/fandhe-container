//! Landlock 適用後の遮断の結合試験（CORE-5・TASK-39.3・#183。REPAIR-12）。
//!
//! 本番の適用経路（`apply_landlock_ruleset`＝`landlock_create_ruleset` → `landlock_add_rule` →
//! `landlock_restrict_self`）を使い捨ての子プロセス（テストバイナリ自身を再実行）の中で適用し、
//! 次を具体値で照合する。適用は不可逆・単一スレッド前提のため、libtest ではなく `harness = false` の
//! 単一スレッド `main` で動かす。親は子をタイムアウト付きで待つ（REPAIR-5）。
//!
//! - `--child-nnp-unset`: `NO_NEW_PRIVS` 未設定で適用を呼ぶと `no_new_privs_not_set` で拒否される
//! - `--child-enforce`: ABI 6+ のカーネルでは `probe_dir` へのファイル作成が `EACCES`・既存ファイルの
//!   読み取りが成功する。ABI 6 未満のカーネルでは検出が拒否し、適用しない（fail-closed）
//!
//! root・KVM 等は不要で、カーネル版数に依存しない形で既定のテスト集合で動く。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("landlock_enforcement: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    println!("landlock_enforcement: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    use fandhe_container_core::landlock::{LandlockApplyErrorKind, observe_landlock_enforcement};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// Linux の `EACCES`（x86_64・aarch64 共通で 13）。
    const EACCES: i32 = 13;

    let args: Vec<String> = std::env::args().collect();
    let child_mode = args.iter().find(|a| a.starts_with("--child-")).cloned();
    if let Some(mode) = child_mode {
        let dir = args
            .iter()
            .position(|a| a == "--probe-dir")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .expect("--probe-dir");
        run_child(&mode, &dir);
        return;
    }

    fn run_child(mode: &str, dir: &Path) {
        match mode {
            "--child-nnp-unset" => {
                let o = observe_landlock_enforcement(dir, false).expect("observe");
                if o.no_new_privs_before {
                    // sandbox 等で NO_NEW_PRIVS を継承している環境では未設定の経路を作れない。
                    println!("landlock_enforcement child: nnp-inherited (unset path not testable)");
                    return;
                }
                let e = o.apply_error.expect("apply must be refused");
                assert_eq!(e.kind, LandlockApplyErrorKind::NoNewPrivsNotSet);
                assert_eq!(e.code.as_str(), "FAILED_PRECONDITION");
                assert!(!o.applied);
                // 何も制限していないので書き込みが成功する。
                assert_eq!(o.create_after, None, "no restriction was applied");
                assert!(o.read_after);
                println!("landlock_enforcement child: ok");
            }
            "--child-enforce" => {
                let o = observe_landlock_enforcement(dir, true).expect("observe");
                assert!(o.no_new_privs_before, "no_new_privs must be set");
                if let Some(reason) = o.detect_error {
                    // ABI 6 未満・Landlock 無効のカーネルでは検出が拒否し、適用しない（fail-closed）。
                    assert!(!o.applied);
                    assert!(o.apply_error.is_none());
                    println!("landlock_enforcement child: detect-refused ({reason})");
                    return;
                }
                assert_eq!(o.apply_error, None, "apply must succeed on ABI 6+");
                assert!(o.applied);
                assert_eq!(o.create_after, Some(EACCES), "create blocked by Landlock");
                assert!(o.read_after, "read of existing file is allowed");
                println!("landlock_enforcement child: ok");
            }
            other => panic!("unknown child mode {other}"),
        }
    }

    let exe = std::env::current_exe().expect("current_exe");
    for mode in ["--child-nnp-unset", "--child-enforce"] {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-landlock-enf-{}-{}",
            std::process::id(),
            mode.trim_start_matches('-')
        ));
        std::fs::create_dir_all(&dir).expect("create probe dir");
        let mut child = Command::new(&exe)
            .arg(mode)
            .arg("--probe-dir")
            .arg(&dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn child");
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(s) = child.try_wait().expect("try_wait") {
                break s;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_dir_all(&dir);
                panic!("landlock_enforcement child {mode} timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = child.wait_with_output().expect("wait_with_output");
        let _ = std::fs::remove_dir_all(&dir);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            status.success(),
            "child {mode} failed ({status}): {stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("landlock_enforcement child:"),
            "child {mode} printed no result: {stdout}"
        );
        println!("{mode}: {}", stdout.trim());
    }
    println!("landlock_enforcement: ok");
}
