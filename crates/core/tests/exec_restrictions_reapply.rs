//! exec プロセスへの seccomp / Landlock 再適用の結合試験（SUP-6・TASK-163.3・#502・CORE-5・MS-9。REPAIR-12）。
//!
//! 本番の `prepare_exec_restrictions` → `reapply_restrictions`（`observe_exec_restriction_reapply` 経由）を
//! 使い捨ての子（テストバイナリ自身の再実行）の中で通し、再適用の後に
//! 許可外 syscall（`unshare(0)` = `EPERM`）と許可外パス（`denied/` への書き込み系 = `EACCES`）が
//! 拒否され、許可パス（`allowed/`）と読み取りは通ることを具体値で照合する。
//! 適用は不可逆・単一スレッド前提のため libtest ではなく `harness = false` の `main` で動かし、
//! 親は子をタイムアウト付きで待つ（REPAIR-5）。
//!
//! このテストは `setns` を行わないため、「コンテナの rootfs」の代わりに自プロセスの `/` を照合の基準に渡し、
//! ルールのパスは自プロセスの `/` に対して解決される。加えて、基準を `/` 以外のディレクトリにした子
//! （`--child-root-mismatch`）で、参加後の `/` が rootfs でない場合の拒否（違反記録
//! `exec_root_not_container_rootfs`。`NoNewPrivs`・`Seccomp` とも変化なし = 何も適用していない）を、カーネル
//! 版数に依存せず具体値で照合する（SEC-1・SEC-4）。
//! 「`setns` の後に保持 fd 経由でスレッド数を読める」「実コンテナへ参加した後の `/` が rootfs と一致する」
//! ことの実機確認は #503（TASK-163.4）の統合テストで行う（REPAIR-3）。
//!
//! # 実行モード（ci.md「実機前提テスト」）
//!
//! - 既定（`cargo test`）: Landlock 検出が `Ok` のカーネルならフル照合し、`Err` のカーネルでは
//!   fail-closed（準備が `stage = Landlock` で失敗し、seccomp も載らない）を照合する
//! - `-- --ignored`（実機前提。Linux 6.12+・Landlock ABI 6+・Landlock が LSM として有効・root 不要）:
//!   検出失敗を失敗として扱いフル照合を必須にする。実行:
//!   `cargo test -p fandhe-container-core --test exec_restrictions_reapply -- --ignored`

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_restrictions_reapply: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    println!("exec_restrictions_reapply: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    use fandhe_container_core::exec::{
        IsolationStage, LandlockAccessKind as K, LandlockAccessProbe, UnappliedExecRestriction,
        observe_exec_restriction_reapply,
    };
    use fandhe_container_core::oci_runtime::parse_config_bytes;
    use fandhe_container_core::traits::ErrorCode;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// Linux の `EACCES` / `EPERM`（x86_64・aarch64 共通）。
    const EACCES: i32 = 13;
    const EPERM: i32 = 1;

    fn probe(kind: K, path: PathBuf) -> LandlockAccessProbe {
        let expected_content = (kind == K::ReadFile).then(|| b"probe".to_vec());
        LandlockAccessProbe {
            kind,
            path,
            expected_content,
        }
    }

    /// 文字列を JSON 文字列リテラル（引用符込み）へエスケープする。
    fn json_str(s: &str) -> String {
        let mut out = String::from("\"");
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    /// 予測困難な名前（`/dev/urandom` 由来）で 0700 の専用ディレクトリを新規作成する。
    fn create_unique_dir(base: &Path) -> PathBuf {
        use std::io::Read;
        use std::os::unix::fs::DirBuilderExt;
        for _ in 0..16 {
            let mut buf = [0u8; 8];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut buf))
                .expect("read /dev/urandom");
            let dir = base.join(format!(
                "fandhe-reapply-{}-{:016x}",
                std::process::id(),
                u64::from_le_bytes(buf)
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return dir,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create probe dir: {e}"),
            }
        }
        panic!("could not create a unique probe dir");
    }

    fn run_child(dir: &Path) {
        let allowed = dir.join("allowed");
        let denied = dir.join("denied");
        let json = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":true}},"mounts":[{{"destination":{},"options":["rw"]}}]}}"#,
            json_str(allowed.to_str().expect("utf8 path"))
        );
        let config = parse_config_bytes(json.as_bytes()).expect("valid config");
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
            probe(K::ReadFile, allowed.join("readable")),
            probe(K::RemoveFile, allowed.join("new")),
        ];
        let o =
            observe_exec_restriction_reapply(&config, Path::new("/"), &probes).expect("observe");
        assert_eq!(o.unshare_before, None, "control: unshare(0) must succeed");

        if let Some(e) = &o.prepare_error {
            // Landlock 未対応カーネルでの fail-closed: 準備が Landlock 段で拒否し、何も適用しない。
            assert_eq!(e.stage, IsolationStage::Landlock);
            assert!(
                matches!(
                    e.code,
                    ErrorCode::FailedPrecondition | ErrorCode::Internal | ErrorCode::Unimplemented
                ),
                "unexpected code {:?}",
                e.code
            );
            assert!(o.reapply_error.is_none());
            assert!(o.report.is_none());
            assert_eq!(
                o.seccomp_after, o.seccomp_before,
                "seccomp must not be applied"
            );
            assert_eq!(
                o.no_new_privs_after, o.no_new_privs_before,
                "no_new_privs must not be changed"
            );
            assert!(o.results.is_empty(), "probes must not run");
            println!(
                "exec_restrictions_reapply child: detect-refused ({})",
                e.message
            );
            return;
        }
        assert!(o.reapply_error.is_none(), "{:?}", o.reapply_error);
        let report = o.report.as_ref().expect("report");
        // root（`/`）と `allowed` の 2 ルール。
        assert_eq!(report.landlock_rules, 2, "{report:?}");
        assert!(report.seccomp_instructions > 0, "{report:?}");
        // SEC-1: 再適用の成功は exec してよい状態を意味しない（capability 削減・rlimit は未適用）。
        assert_eq!(
            report.unapplied,
            &[
                UnappliedExecRestriction::CapabilityDrop,
                UnappliedExecRestriction::Rlimits
            ]
        );
        assert!(!report.is_complete());
        assert_eq!(o.seccomp_before, "0");
        assert_eq!(o.seccomp_after, "2");
        assert_eq!(o.no_new_privs_after, "1");
        assert_eq!(o.unshare_after, Some(EPERM), "denied syscall must be EPERM");
        let got: Vec<Option<i32>> = o.results.iter().map(|(_, r)| *r).collect();
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
        ];
        assert_eq!(got, expected, "results: {:?}", o.results);
        assert!(!denied.join("new").exists(), "denied create left a file");
        assert!(!denied.join("newdir").exists(), "denied mkdir left a dir");
        assert!(
            denied.join("existing").exists(),
            "denied remove must not delete"
        );
        println!("exec_restrictions_reapply child: ok");
    }

    /// 照合の基準を `/` 以外（`dir`）にした再適用: 参加後の `/` が rootfs でない場合と同じ拒否になる。
    fn run_child_root_mismatch(dir: &Path) {
        let json = br#"{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":true}}"#;
        let config = parse_config_bytes(json).expect("valid config");
        let probes = vec![probe(K::ReadDir, dir.to_path_buf())];
        let o = observe_exec_restriction_reapply(&config, dir, &probes).expect("observe");
        if let Some(e) = &o.prepare_error {
            // Landlock 未対応カーネル: 準備の段階で拒否され、照合まで進まない（fail-closed）。
            assert_eq!(e.stage, IsolationStage::Landlock);
            assert_eq!(o.seccomp_after, o.seccomp_before);
            assert_eq!(o.no_new_privs_after, o.no_new_privs_before);
            println!(
                "exec_restrictions_reapply mismatch child: detect-refused ({})",
                e.message
            );
            return;
        }
        let e = o.reapply_error.as_ref().expect("reapply must be refused");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::SetNs);
        assert_eq!(
            e.message,
            "the root directory after joining is not the recorded container rootfs"
        );
        let v = e.violation.as_ref().expect("violation recorded");
        assert_eq!(v.kind.as_str(), "exec_target");
        assert_eq!(v.reason.as_str(), "exec_root_not_container_rootfs");
        assert_eq!(v.behavior_id, "SEC-1");
        assert!(o.report.is_none());
        // 何も適用していない: NO_NEW_PRIVS・seccomp とも変化なし（seccomp は無制限の `0` のまま）。
        assert_eq!(o.no_new_privs_after, o.no_new_privs_before);
        assert_eq!(o.seccomp_after, o.seccomp_before);
        assert_eq!(o.seccomp_after, "0");
        assert!(o.results.is_empty(), "probes must not run");
        println!("exec_restrictions_reapply mismatch child: ok");
    }

    /// 子（テストバイナリ自身の再実行）を `mode` で起動し、タイムアウト付きで待って標準出力を返す。
    fn spawn_and_wait(exe: &Path, mode: &str, dir: &Path) -> String {
        let mut child = Command::new(exe)
            .arg(mode)
            .arg("--probe-dir")
            .arg(dir)
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
                let _ = std::fs::remove_dir_all(dir);
                panic!("exec_restrictions_reapply child ({mode}) timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = child.wait_with_output().expect("wait_with_output");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if !status.success() {
            let _ = std::fs::remove_dir_all(dir);
            panic!(
                "child ({mode}) failed ({status}): {stdout}\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        stdout
    }

    let args: Vec<String> = std::env::args().collect();
    let probe_dir = || {
        args.iter()
            .position(|a| a == "--probe-dir")
            .and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .expect("--probe-dir")
    };
    if args.iter().any(|a| a == "--child-root-mismatch") {
        run_child_root_mismatch(&probe_dir());
        return;
    }
    if args.iter().any(|a| a == "--child") {
        run_child(&probe_dir());
        return;
    }

    let require_full = args.iter().any(|a| a == "--ignored");
    let exe = std::env::current_exe().expect("current_exe");
    // ルールパス解決は symlink を拒否するため canonicalize 済みの一時領域を使う。
    let base = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp dir");
    let dir = create_unique_dir(&base);
    for sub in ["allowed", "denied"] {
        std::fs::create_dir(dir.join(sub)).expect("create probe subdir");
        for f in ["existing", "readable"] {
            std::fs::write(dir.join(sub).join(f), b"probe").expect("create fixture");
        }
    }
    let stdout = spawn_and_wait(&exe, "--child", &dir);
    let mismatch = spawn_and_wait(&exe, "--child-root-mismatch", &dir);
    let _ = std::fs::remove_dir_all(&dir);
    let full = stdout.contains("exec_restrictions_reapply child: ok");
    let refused = stdout.contains("exec_restrictions_reapply child: detect-refused");
    let mismatch_full = mismatch.contains("exec_restrictions_reapply mismatch child: ok");
    let mismatch_refused =
        mismatch.contains("exec_restrictions_reapply mismatch child: detect-refused");
    if require_full {
        assert!(
            full,
            "child did not fully verify on this host (needs Linux 6.12+/ABI 6+): {stdout}"
        );
        assert!(
            mismatch_full,
            "mismatch child did not fully verify on this host: {mismatch}"
        );
    } else {
        assert!(full || refused, "child printed no result: {stdout}");
        assert!(
            mismatch_full || mismatch_refused,
            "mismatch child printed no result: {mismatch}"
        );
        // 2 つの子は同じカーネルで動くため、Landlock 検出の成否は一致する。
        assert_eq!(full, mismatch_full, "{stdout}\n{mismatch}");
    }
    println!("{}", stdout.trim());
    println!("{}", mismatch.trim());
    println!("exec_restrictions_reapply: ok");
}
