//! Landlock による許可外パスの遮断の結合試験（CORE-5・TASK-39.5・#185・MS-2。REPAIR-12）。
//!
//! 1 つの ruleset（root は READ のみ・`allowed/` だけ `rw` mount）の下で、許可パスの操作は通り、
//! 許可外パス（`denied/`）の書き込み系操作は `EACCES` で拒否されることを具体値で照合する。
//! 適用は本番のステージ関数（`landlock_ruleset_from_config` → `apply_landlock_stage`）を
//! `observe_landlock_path_access` 経由で使い捨ての子（テストバイナリ自身の再実行）の中で行う。
//! 適用は不可逆・単一スレッド前提のため libtest ではなく `harness = false` の `main` で動かし、
//! 親は子をタイムアウト付きで待つ（REPAIR-5）。
//!
//! # 既存テストとの対応（TASK-39.5 の AC1。ABI 検出と fail-closed）
//!
//! 既定のテスト集合で次が走る（本ファイルでは再実装しない）。
//! - `src/landlock.rs` の単体テスト: 偽 probe による ABI 0/1/5/6/7/MAX・ENOSYS・EOPNOTSUPP 等の判定
//! - `tests/landlock_detect.rs`・`tests/landlock_path_rules.rs`: 公開 API の検出・ルール生成
//! - `tests/landlock_enforcement.rs`: `NO_NEW_PRIVS` 未設定の拒否と固定 ruleset の遮断
//!
//! `fork_exec_isolation` の `landlock-*` シナリオは起動経路と root 直下の書き込みのみを観測する。
//! 本ファイルは「許可パスと許可外パスの区別」を観測する点が異なる。
//!
//! # 実行モード（ci.md「実機前提テスト」）
//!
//! - 既定（`cargo test`）: 検出が `Ok` のカーネルならフル照合し、`Err` のカーネルでは
//!   fail-closed（ruleset 未生成・適用せず・プローブ未実行）を照合する。検証せず成功する分岐はない
//! - `-- --ignored`（実機前提。Linux 6.12+・Landlock ABI 6+・Landlock が LSM として有効・root 不要）:
//!   検出失敗を失敗として扱いフル照合を必須にする。GitHub ホステッド runner は ABI 6 を保証できない
//!   ため既定集合から分離している（CI 通過のための弱体化ではない）。実行:
//!   `cargo test -p fandhe-container-core --test landlock -- --ignored`

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("landlock: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    println!("landlock: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    use fandhe_container_core::exec::{
        IsolationStage, LandlockAccessKind as K, LandlockAccessObservation, LandlockAccessProbe,
        observe_landlock_path_access,
    };
    use fandhe_container_core::oci_runtime::{OciConfig, parse_config_bytes};
    use fandhe_container_core::traits::ErrorCode;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// Linux の `EACCES`（x86_64・aarch64 共通で 13）。
    const EACCES: i32 = 13;

    fn probe(kind: K, path: PathBuf) -> LandlockAccessProbe {
        let expected_content = (kind == K::ReadFile).then(|| b"probe".to_vec());
        LandlockAccessProbe {
            kind,
            path,
            expected_content,
        }
    }

    fn config_for(dir: &Path, extra_mount: Option<&str>) -> OciConfig {
        let allowed = dir.join("allowed");
        let allowed = allowed.to_str().expect("utf8 path");
        let extra = extra_mount
            .map(|m| format!(r#",{{"destination":"{m}","options":["rw"]}}"#))
            .unwrap_or_default();
        let json = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":true}},"mounts":[{{"destination":"{allowed}","options":["rw"]}}{extra}]}}"#
        );
        parse_config_bytes(json.as_bytes()).expect("valid config")
    }

    /// 検出が拒否したカーネルでの fail-closed を照合する。出力は `detect-refused`。
    fn check_fail_closed(o: &LandlockAccessObservation) {
        let e = o.ruleset_error.as_ref().expect("ruleset_error");
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert!(
            matches!(
                e.code,
                ErrorCode::FailedPrecondition | ErrorCode::Internal | ErrorCode::Unimplemented
            ),
            "unexpected code {:?}",
            e.code
        );
        assert!(e.message.starts_with("landlock_"), "{}", e.message);
        assert!(!o.applied);
        assert!(o.apply_error.is_none());
        assert!(o.results.is_empty(), "probes must not run");
        println!("landlock child: detect-refused ({})", e.message);
    }

    fn run_child(mode: &str, dir: &Path) {
        match mode {
            "--child-access" => {
                let allowed = dir.join("allowed");
                let denied = dir.join("denied");
                let probes = vec![
                    probe(K::CreateFile, denied.join("new")),
                    probe(K::MakeDir, denied.join("newdir")),
                    probe(K::WriteExisting, denied.join("existing")),
                    probe(K::TruncateOpen, denied.join("existing")),
                    probe(K::RemoveFile, denied.join("existing")),
                    probe(K::ReadFile, denied.join("readable")),
                    probe(K::ReadDir, denied.clone()),
                    probe(K::CreateFile, allowed.join("new")),
                    probe(K::MakeDir, allowed.join("newdir")),
                    probe(K::WriteExisting, allowed.join("existing")),
                    probe(K::TruncateOpen, allowed.join("existing")),
                    probe(K::ReadFile, allowed.join("readable")),
                    probe(K::RemoveFile, allowed.join("new")),
                ];
                let o =
                    observe_landlock_path_access(&config_for(dir, None), &probes).expect("observe");
                assert!(o.no_new_privs_before, "no_new_privs must be set");
                if o.ruleset_error.is_some() {
                    check_fail_closed(&o);
                    return;
                }
                assert!(o.apply_error.is_none(), "{:?}", o.apply_error);
                assert!(o.applied);
                let got: Vec<Option<i32>> = o.results.iter().map(|(_, r)| *r).collect();
                // 許可外（denied/）: 書き込み系は EACCES、読み取りは root の READ で成功。
                // allowed/: すべて成功。ReadFile は内容が確定した専用ファイル（readable）を読む。
                let expected = vec![
                    Some(EACCES),
                    Some(EACCES),
                    Some(EACCES),
                    Some(EACCES),
                    Some(EACCES),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ];
                assert_eq!(got, expected, "results: {:?}", o.results);
                assert!(!denied.join("new").exists(), "denied create left a file");
                assert!(!denied.join("newdir").exists(), "denied mkdir left a dir");
                assert!(
                    denied.join("existing").exists(),
                    "denied remove must not delete"
                );
                println!("landlock child: ok");
            }
            "--child-missing-rule" => {
                let missing = dir.join("no-such");
                let missing = missing.to_str().expect("utf8 path");
                let probes = vec![probe(K::CreateFile, dir.join("denied").join("new"))];
                let o = observe_landlock_path_access(&config_for(dir, Some(missing)), &probes)
                    .expect("observe");
                if o.ruleset_error.is_some() {
                    check_fail_closed(&o);
                    return;
                }
                let e = o
                    .apply_error
                    .as_ref()
                    .expect("apply must fail on missing path");
                assert_eq!(e.stage, IsolationStage::Landlock);
                assert!(
                    e.message.starts_with("landlock_open_path_failed"),
                    "{}",
                    e.message
                );
                assert!(!o.applied);
                assert!(
                    o.results.is_empty(),
                    "probes must not run after apply failure"
                );
                println!("landlock child: ok");
            }
            other => panic!("unknown child mode {other}"),
        }
    }

    let args: Vec<String> = std::env::args().collect();
    if let Some(mode) = args.iter().find(|a| a.starts_with("--child-")).cloned() {
        let dir = args
            .iter()
            .position(|a| a == "--probe-dir")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .expect("--probe-dir");
        run_child(&mode, &dir);
        return;
    }

    let require_full = args.iter().any(|a| a == "--ignored");
    let exe = std::env::current_exe().expect("current_exe");
    // RealKernel のルールパス解決は symlink を拒否するため canonicalize 済みの一時領域を使う。
    let base = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp dir");
    for mode in ["--child-access", "--child-missing-rule"] {
        let dir = base.join(format!(
            "fandhe-landlock-{}-{}",
            std::process::id(),
            mode.trim_start_matches('-')
        ));
        // 共有 /tmp の事前作成（symlink 等）を避けるため、既存なら失敗させる。
        std::fs::create_dir(&dir).expect("create probe dir (must not pre-exist)");
        for sub in ["allowed", "denied"] {
            std::fs::create_dir(dir.join(sub)).expect("create probe subdir");
            for f in ["existing", "readable"] {
                std::fs::write(dir.join(sub).join(f), b"probe").expect("create fixture");
            }
        }
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
                panic!("landlock child {mode} timed out");
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
        if require_full {
            assert!(
                stdout.contains("landlock child: ok"),
                "child {mode} did not fully verify on this host (needs Linux 6.12+/ABI 6+): {stdout}"
            );
        } else {
            assert!(
                stdout.contains("landlock child: ok")
                    || stdout.contains("landlock child: detect-refused"),
                "child {mode} printed no result: {stdout}"
            );
        }
        println!("{mode}: {}", stdout.trim());
    }
    println!("landlock: ok");
}
