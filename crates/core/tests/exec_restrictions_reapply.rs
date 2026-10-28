//! exec プロセスへの seccomp / Landlock 再適用の結合試験（SUP-6・TASK-163.3・#502・CORE-5・MS-9。REPAIR-12）。
//!
//! 本番の `prepare_exec_restrictions` → `reapply_restrictions`（`observe_exec_restriction_reapply` 経由）を
//! 使い捨ての子（テストバイナリ自身の再実行）の中で通し、再適用の後に
//! 許可外 syscall（`kcmp(自 pid, 自 pid, KCMP_VM)` = `EPERM`。`unshare` は `KILL_PROCESS` で戻らない）と許可外パス（`denied/` への書き込み系 = `EACCES`）が
//! 拒否され、許可パス（`allowed/`）と読み取りは通ることを具体値で照合する。
//! 適用は不可逆・単一スレッド前提のため libtest ではなく `harness = false` の `main` で動かし、
//! 親は子をタイムアウト付きで待つ（REPAIR-5）。
//!
//! このテストは `setns` を行わないため、「コンテナの rootfs」の代わりに自プロセスの `/` を照合の基準に渡し、
//! ルールのパスは自プロセスの `/` に対して解決される。加えて、基準を `/` 以外のディレクトリにした子
//! （`--child-root-mismatch`）で、参加後の `/` が rootfs でない場合の拒否（違反記録
//! `exec_root_not_container_rootfs`。`NoNewPrivs`・`Seccomp` とも変化なし = 何も適用していない）を、カーネル
//! 版数に依存せず具体値で照合する（SEC-1・SEC-4）。
//! 加えて、launch が記録する Mount 由来のルールの識別子（`mnt_id`・`st_dev`・`st_ino`）を `MountCheck::Recorded` の経路へ渡し、
//! 一致する記録の受理と、`mnt_id` が変わった記録（overmount 相当）の `landlock_mount_identity_mismatch` での拒否・
//! 何も適用しないことを具体値で照合する（`--child-mount-identity-*`。SEC-1・SEC-4・CORE-5・#3201）。
//! `state.json` との往復は state_store の単体試験 `sec1_3201_state_mount_identity_roundtrip_and_legacy` が担う。
//! 「`setns` の後に保持 fd 経由でスレッド数を読める」「実コンテナへ参加した後の `/` が rootfs と一致する」
//! 「capability 削減・rlimit 適用」の実機確認は supervisor の `tests/exec.rs`（TASK-163.4・#503）で行う。
//! 本テストは非特権で動かすため、観測関数は capability 削減を省き、rlimit も変えない（空集合）。省いた 2 つは
//! 未適用に `Rlimits`・`CapabilityDrop` として残る（TASK-163 追補・#1460。本番の入口は rlimit の空集合を拒否する）。
//! 適用前の対照（`kcmp` の成功・`Seccomp: 0`）が外側の環境（`make docker-ci` の Docker 既定 seccomp 等）で
//! 満たせない場合は、skip せず失敗のまま、子がマーカー行（`precondition-failed ...`）と専用の終了コードで報告し、
//! 親が `PRECONDITION FAILED (test environment ...)` の 1 行目で判別できる panic にする（#2235・ESC-06）。
//! 観測関数は `exec-test-support` feature の下にあり、core の dev-dependency の自己参照で有効になる。
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
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("exec_restrictions_reapply: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    use fandhe_container_core::exec::{
        IsolationStage, LandlockAccessKind as K, LandlockAccessProbe, ObservedMountRecording,
        UnappliedExecRestriction, observe_exec_restriction_reapply,
        observe_exec_restriction_reapply_recorded,
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

    /// 前提欠如を報告する子の専用終了コード（panic の 101 と区別する）。
    const PRECONDITION_EXIT: i32 = 3;
    const MARKER: &str = "exec_restrictions_reapply child: precondition-failed ";

    /// 前提欠如をマーカー行で報告して専用の終了コードで終わる（#2235）。
    fn exit_precondition(kcmp_errno: Option<i32>, seccomp_before: &str) -> ! {
        let e = kcmp_errno.map_or("none".to_string(), |e| e.to_string());
        println!("{MARKER}kcmp_before_errno={e} seccomp_before={seccomp_before}");
        std::process::exit(PRECONDITION_EXIT);
    }

    /// 終了コードとマーカーが揃ったときだけ前提欠如のマーカー値部分を返す（解析不能は `None`＝汎用の失敗）。
    fn precondition_fields(code: Option<i32>, stdout: &str) -> Option<(i32, String)> {
        if code != Some(PRECONDITION_EXIT) {
            return None;
        }
        let rest = stdout.lines().find_map(|l| l.strip_prefix(MARKER))?;
        let mut errno = None;
        let mut mode = None;
        for kv in rest.split_whitespace() {
            if let Some(v) = kv.strip_prefix("kcmp_before_errno=") {
                // kcmp が成功していて errno が無い場合（`none`）は 0 とする。
                errno = if v == "none" {
                    Some(0)
                } else {
                    v.parse::<i32>().ok()
                };
            } else if let Some(v) = kv.strip_prefix("seccomp_before=") {
                mode = Some(v.to_string());
            }
        }
        Some((errno?, mode?))
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
        if o.kcmp_before.is_some() {
            exit_precondition(o.kcmp_before, &o.seccomp_before);
        }

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
        let report = o.report.expect("report");
        // root（`/`）・暗黙の `/dev`・`/dev/pts`・`/dev/shm`（#1657。ホストの同名パスを起点にする）・`allowed` の 5 ルール。
        assert_eq!(report.landlock_rules(), 5, "{report:?}");
        assert!(report.seccomp_instructions() > 0, "{report:?}");
        // SEC-1: 観測関数は `CAP_SETPCAP` を持たない非特権の子でも動くよう capability 削減を省き、rlimit も
        // 変えない（空集合）。省いた制限は launch の段の順で未適用に残り（TASK-163 追補・#1460。空集合の rlimit を
        // 適用済みと装わない）、exec へ進むための証跡（`ExecReady`）は作れない。本番の入口は rlimit・capability とも
        // 適用し、rlimit の空集合を拒否する。
        assert_eq!(report.rlimits_applied(), 0);
        assert_eq!(report.capability_bounding_dropped(), 0);
        assert_eq!(report.supplementary_groups(), None);
        assert_eq!(
            report.unapplied(),
            &[
                UnappliedExecRestriction::Rlimits,
                UnappliedExecRestriction::CapabilityDrop
            ]
        );
        assert!(!report.is_complete());
        let incomplete = report.into_complete().expect_err("not ready to exec");
        assert_eq!(incomplete.code, ErrorCode::FailedPrecondition);
        assert_eq!(incomplete.stage, IsolationStage::Exec);
        assert_eq!(
            incomplete.message,
            "exec restrictions are incomplete; not applied: rlimits, capability_drop"
        );
        if o.seccomp_before != "0" {
            exit_precondition(o.kcmp_before, &o.seccomp_before);
        }
        assert_eq!(o.seccomp_after, "2");
        assert_eq!(o.no_new_privs_after, "1");
        assert_eq!(o.kcmp_after, Some(EPERM), "denied syscall must be EPERM");
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

    /// マウントの識別子の照合（SEC-1・SEC-4・#3201）。launch が記録する識別子（適用の直前に開いた対象の実値）を
    /// 本番の `MountCheck::Recorded` の経路へ渡す。`faithful` は一致して受理され（暗黙の `/dev`・`/dev/pts`・
    /// `/dev/shm` の 3 件を照合）、`shifted` は `mnt_id` が変わった（overmount と同じ）として
    /// `landlock_mount_identity_mismatch` で拒否し、何も適用しない。
    fn run_child_mount_identity(dir: &Path, faithful: bool) {
        let json = br#"{"ociVersion":"1.2.0","root":{"path":"rootfs","readonly":true}}"#;
        let config = parse_config_bytes(json).expect("valid config");
        let probes = vec![probe(K::ReadDir, dir.to_path_buf())];
        let recording = if faithful {
            ObservedMountRecording::Faithful
        } else {
            ObservedMountRecording::MountIdShifted
        };
        let label = if faithful { "faithful" } else { "shifted" };
        let o =
            observe_exec_restriction_reapply_recorded(&config, Path::new("/"), &probes, recording)
                .expect("observe");
        if o.kcmp_before.is_some() {
            exit_precondition(o.kcmp_before, &o.seccomp_before);
        }
        if let Some(e) = &o.prepare_error {
            assert_eq!(e.stage, IsolationStage::Landlock);
            println!(
                "exec_restrictions_reapply mount-identity {label} child: detect-refused ({})",
                e.message
            );
            return;
        }
        if faithful {
            assert!(o.reapply_error.is_none(), "{:?}", o.reapply_error);
            let report = o.report.expect("report");
            // root・`/dev`・`/dev/pts`・`/dev/shm` の 4 ルールのうち、Mount 由来の 3 件の識別子が一致した。
            assert_eq!(report.landlock_rules(), 4, "{report:?}");
            assert_eq!(o.seccomp_after, "2");
            assert_eq!(o.no_new_privs_after, "1");
            println!("exec_restrictions_reapply mount-identity faithful child: ok");
        } else {
            let e = o.reapply_error.as_ref().expect("must be refused");
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(e.stage, IsolationStage::Landlock);
            let v = e.violation.as_ref().expect("violation recorded");
            assert_eq!(v.reason.as_str(), "landlock_mount_identity_mismatch");
            assert_eq!(v.behavior_id, "CORE-5");
            assert!(o.report.is_none());
            // 拒否は Landlock の適用前（restrict_self の前）: seccomp は載っていない。
            assert_eq!(o.seccomp_after, "0");
            assert!(o.results.is_empty(), "probes must not run");
            println!("exec_restrictions_reapply mount-identity shifted child: ok");
        }
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
            if let Some((errno, mode)) = precondition_fields(status.code(), &stdout) {
                let what = if errno == 0 {
                    "kcmp succeeded but an outer seccomp filter is already present".to_string()
                } else {
                    format!(
                        "kcmp(self, self, KCMP_VM) was denied with errno {errno} before reapply"
                    )
                };
                panic!(
                    "exec_restrictions_reapply: PRECONDITION FAILED (test environment, not a reapply regression): \
                     {what} (Seccomp: {mode} before reapply).\n\
                     hint: {}.\n\
                     By policy (#2235) the dev container keeps Docker's seccomp and this test stays failing there; \
                     run it on the host (cargo test -p fandhe-container-core --test exec_restrictions_reapply) \
                     or rely on CI. See AGENTS.md exec_restrictions_reapply.",
                    match (errno, mode.as_str()) {
                        (38, _) => "the kernel does not provide kcmp (CONFIG_KCMP)",
                        (_, "0") => "kcmp is denied by something other than seccomp (e.g. an LSM)",
                        _ =>
                            "an outer seccomp filter is present (e.g. Docker's default seccomp profile under make docker-ci)",
                    }
                );
            }
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
    if args.iter().any(|a| a == "--child-mount-identity-faithful") {
        run_child_mount_identity(&probe_dir(), true);
        return;
    }
    if args.iter().any(|a| a == "--child-mount-identity-shifted") {
        run_child_mount_identity(&probe_dir(), false);
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
    let faithful = spawn_and_wait(&exe, "--child-mount-identity-faithful", &dir);
    let shifted = spawn_and_wait(&exe, "--child-mount-identity-shifted", &dir);
    let _ = std::fs::remove_dir_all(&dir);
    let faithful_full =
        faithful.contains("exec_restrictions_reapply mount-identity faithful child: ok");
    let shifted_full =
        shifted.contains("exec_restrictions_reapply mount-identity shifted child: ok");
    let identity_refused = faithful
        .contains("exec_restrictions_reapply mount-identity faithful child: detect-refused")
        && shifted
            .contains("exec_restrictions_reapply mount-identity shifted child: detect-refused");
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
        assert!(
            faithful_full && shifted_full,
            "mount-identity children did not fully verify: {faithful}\n{shifted}"
        );
    } else {
        assert!(
            (faithful_full && shifted_full) || identity_refused,
            "mount-identity children printed no result: {faithful}\n{shifted}"
        );
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
    println!("{}", faithful.trim());
    println!("{}", shifted.trim());
    println!("exec_restrictions_reapply: ok");
}
