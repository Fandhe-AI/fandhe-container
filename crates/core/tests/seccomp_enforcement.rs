//! seccomp 適用後に禁止 syscall が実際に遮断されることの結合試験（CORE-5・TASK-38.3・#178。REPAIR-12）。
//!
//! 本番の適用経路（`apply_default_seccomp`＝既定 deny フィルタの構築と `prctl(PR_SET_SECCOMP)`）を、
//! 使い捨ての子プロセス（テストバイナリ自身を `--child` で再実行）の中で適用し、適用前の対照
//! （`kcmp` が成功）と適用後の遮断（`kcmp`・`mount`・`pivot_root`・`umount2` が `EPERM`）を
//! 具体値で照合する。`unshare`・`ptrace`・`kexec_load` は `SECCOMP_RET_KILL_PROCESS`（ESC-06・
//! SEC-2）で戻らないため、1 件ずつ別の子（`--child-kill <name>`）で発行し、親が終了シグナル
//! SIGSYS（31）を照合する。適用は不可逆・スレッド単位で単一スレッドを要するため、libtest ではなく
//! `harness = false` の単一スレッド `main` で動かす。親は子をタイムアウト付きで待つ（REPAIR-5）。
//! root・KVM 等は不要で、既定のテスト集合で動く。Landlock 証跡不足での exec 拒否は
//! `fork_exec_isolation` 側の責務で、本試験は seccomp の遮断そのものを検証する。
//!
//! 適用前の対照（`kcmp` の成功）が外側の環境（`make docker-ci` の Docker 既定 seccomp 等）で
//! 満たせない場合は、skip せず失敗のまま、子が固定書式のマーカー行（`precondition-failed ...`）と
//! 専用の終了コードで報告し、親が「試験環境の前提欠如でありリグレッションではない」と 1 行目で
//! 判別できる文言で panic する（#2235・ESC-06。方針は `AGENTS.md` の `seccomp_enforcement`）。
//! 終了コードとマーカーの両方が揃ったときだけ前提欠如として扱い、それ以外は汎用の失敗にする。

#[path = "support/reap.rs"]
mod reap;

#[cfg(target_os = "linux")]
#[path = "support/proc_status.rs"]
mod proc_status;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("seccomp_enforcement: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("seccomp_enforcement: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// Linux の `EPERM`（x86_64・aarch64 共通で 1）。
    const EPERM: i32 = 1;
    /// Linux の `SIGSYS`（x86_64・aarch64 共通で 31）。
    const SIGSYS: i32 = 31;

    use fandhe_container_core::exec::{KilledSyscall, observe_default_seccomp_kill};
    /// 強制終了の対象（ESC-06）。
    const KILLED: [(&str, KilledSyscall); 3] = [
        ("unshare", KilledSyscall::Unshare),
        ("ptrace", KilledSyscall::Ptrace),
        ("kexec_load", KilledSyscall::KexecLoad),
    ];

    /// 前提欠如を報告する子の専用終了コード（panic の 101・汎用失敗の 1 と区別する）。
    const PRECONDITION_EXIT: i32 = 3;
    const MARKER: &str = "seccomp_enforcement child: precondition-failed ";

    /// 子の結果の分類（REPAIR-12。純関数で自己照合する）。
    #[derive(Debug, PartialEq)]
    enum ChildOutcome {
        Ok,
        PreconditionFailed {
            kcmp_errno: i32,
            seccomp_before: String,
        },
        Failed,
    }

    /// 終了コードと標準出力から子の結果を分類する。解析に失敗したら `Failed`（fail-closed）。
    fn classify_child(code: Option<i32>, stdout: &str) -> ChildOutcome {
        if code == Some(0) {
            return ChildOutcome::Ok;
        }
        if code != Some(PRECONDITION_EXIT) {
            return ChildOutcome::Failed;
        }
        let Some(rest) = stdout.lines().find_map(|l| l.strip_prefix(MARKER)) else {
            return ChildOutcome::Failed;
        };
        let mut errno = None;
        let mut mode = None;
        for kv in rest.split_whitespace() {
            if let Some(v) = kv.strip_prefix("kcmp_before_errno=") {
                errno = v.parse::<i32>().ok();
            } else if let Some(v) = kv.strip_prefix("seccomp_before=") {
                mode = Some(v.to_string());
            }
        }
        match (errno, mode) {
            (Some(kcmp_errno), Some(seccomp_before)) => ChildOutcome::PreconditionFailed {
                kcmp_errno,
                seccomp_before,
            },
            _ => ChildOutcome::Failed,
        }
    }

    /// 前提欠如の panic メッセージ（1 行目で判別でき、値から決まるヒントだけを添える）。
    fn precondition_message(kcmp_errno: i32, seccomp_before: &str) -> String {
        let hint = match (kcmp_errno, seccomp_before) {
            (1, "0") => "kcmp is denied by something other than seccomp (e.g. an LSM)",
            (1, _) => {
                "an outer seccomp filter denies kcmp (e.g. Docker's default seccomp profile under make docker-ci)"
            }
            (38, _) => "the kernel does not provide kcmp (CONFIG_KCMP)",
            _ => "the environment denies kcmp",
        };
        format!(
            "seccomp_enforcement: PRECONDITION FAILED (test environment, not a seccomp filter regression): \
             kcmp(self, self, KCMP_VM) was denied with errno {kcmp_errno} before the runtime's filter was applied \
             (Seccomp: {seccomp_before} before apply).\n\
             hint: {hint}.\n\
             By policy (#2235) the dev container keeps Docker's seccomp and this test stays failing there; \
             run it on the host (cargo test -p fandhe-container-core --test seccomp_enforcement) or rely on CI. \
             See AGENTS.md seccomp_enforcement."
        )
    }

    let args: Vec<String> = std::env::args().collect();
    let is_child = args.iter().any(|a| a == "--child" || a == "--child-kill");
    if !is_child {
        // 分類の自己照合（常に走る。ESC-06・REPAIR-12）。
        let marker =
            |e: i32, m: &str| format!("noise\n{MARKER}kcmp_before_errno={e} seccomp_before={m}\n");
        assert_eq!(
            classify_child(Some(0), "seccomp_enforcement child: ok\n"),
            ChildOutcome::Ok
        );
        assert_eq!(
            classify_child(Some(PRECONDITION_EXIT), &marker(1, "2")),
            ChildOutcome::PreconditionFailed {
                kcmp_errno: 1,
                seccomp_before: "2".into()
            }
        );
        assert_eq!(
            classify_child(Some(PRECONDITION_EXIT), &marker(38, "0")),
            ChildOutcome::PreconditionFailed {
                kcmp_errno: 38,
                seccomp_before: "0".into()
            }
        );
        assert_eq!(
            classify_child(Some(PRECONDITION_EXIT), "no marker\n"),
            ChildOutcome::Failed
        );
        assert_eq!(
            classify_child(Some(101), &marker(1, "2")),
            ChildOutcome::Failed
        );
        assert_eq!(
            classify_child(
                Some(PRECONDITION_EXIT),
                &format!("{MARKER}kcmp_before_errno=x seccomp_before=2\n")
            ),
            ChildOutcome::Failed
        );
        assert_eq!(classify_child(None, &marker(1, "2")), ChildOutcome::Failed);
    }
    if let Some(i) = args.iter().position(|a| a == "--child-kill") {
        let name = args.get(i + 1).expect("syscall name after --child-kill");
        let (_, which) = KILLED
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("unknown syscall {name}"));
        // 正常ならここで SIGSYS により終了して戻らない。戻れば強制終了になっていない。
        let r = observe_default_seccomp_kill(*which);
        println!("seccomp_enforcement child-kill: returned {r:?}");
        std::process::exit(1);
    }

    if std::env::args().any(|a| a == "--child") {
        // 適用後は常に 2 になるため、適用前の `Seccomp:` を先に読んでおく（前提欠如の表示用）。
        let seccomp_before = std::fs::read_to_string("/proc/thread-self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("Seccomp:").map(|v| v.trim().to_string()))
            })
            .unwrap_or_else(|| "unknown".to_string());
        let o = fandhe_container_core::exec::observe_default_seccomp_enforcement()
            .expect("apply default seccomp in child");
        if let Some(errno) = o.kcmp_before {
            // 外側の環境が kcmp を拒否している: 対照が無意味なので親へ判別可能に報告して失敗する。
            println!("{MARKER}kcmp_before_errno={errno} seccomp_before={seccomp_before}");
            std::process::exit(PRECONDITION_EXIT);
        }
        assert!(o.instructions > 0, "filter has instructions");
        assert_eq!(o.seccomp_mode, "2", "SECCOMP_MODE_FILTER");
        assert_eq!(o.kcmp_after, Some(EPERM), "kcmp blocked");
        assert_eq!(o.mount_after, Some(EPERM), "mount blocked");
        assert_eq!(o.pivot_root_after, Some(EPERM), "pivot_root blocked");
        assert_eq!(o.umount_after, Some(EPERM), "umount2 blocked");
        println!("seccomp_enforcement child: ok");
        return;
    }

    // 診断ヘルパーの自己テスト（#2629・REPAIR-12）: 自プロセスの抜粋が State と CoreDumping の両行を持つ。
    let own = crate::proc_status::excerpt(std::process::id());
    assert!(own.contains("State:"), "State line missing: {own}");
    assert!(
        own.contains("CoreDumping:\t0"),
        "CoreDumping line missing: {own}"
    );

    let exe = std::env::current_exe().expect("current_exe");
    let run = |extra: &[&str]| {
        let mut child = Command::new(&exe)
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn child");
        let child_pid = child.id();
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(s) = child.try_wait().expect("try_wait") {
                break s;
            }
            if Instant::now() >= deadline {
                let diag = crate::proc_status::excerpt(child_pid);
                crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
                panic!("seccomp_enforcement child timed out ({diag})");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = child.wait_with_output().expect("wait_with_output");
        (status, out)
    };

    let (status, out) = run(&["--child"]);
    match classify_child(status.code(), &String::from_utf8_lossy(&out.stdout)) {
        ChildOutcome::Ok => {}
        ChildOutcome::PreconditionFailed {
            kcmp_errno,
            seccomp_before,
        } => panic!("{}", precondition_message(kcmp_errno, &seccomp_before)),
        ChildOutcome::Failed => panic!(
            "child failed ({status}): {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
    assert!(String::from_utf8_lossy(&out.stdout).contains("seccomp_enforcement child: ok"));

    for (name, _) in KILLED {
        let (status, out) = run(&["--child-kill", name]);
        assert_eq!(
            status.signal(),
            Some(SIGSYS),
            "{name} must be killed by SIGSYS (KILL_PROCESS); status {status}: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    println!("seccomp_enforcement: ok");
}
