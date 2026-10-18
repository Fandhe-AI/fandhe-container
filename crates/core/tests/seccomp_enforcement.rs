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

    let args: Vec<String> = std::env::args().collect();
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
        let o = fandhe_container_core::exec::observe_default_seccomp_enforcement()
            .expect("apply default seccomp in child");
        assert_eq!(
            o.kcmp_before, None,
            "precondition failed: kcmp(self, self, KCMP_VM) must succeed before our filter is applied \
             (errno {:?}); the outer environment already denies kcmp (e.g. Docker's default seccomp \
             profile in a dev container), so the control is meaningless. See AGENTS.md seccomp_enforcement",
            o.kcmp_before
        );
        assert!(o.instructions > 0, "filter has instructions");
        assert_eq!(o.seccomp_mode, "2", "SECCOMP_MODE_FILTER");
        assert_eq!(o.kcmp_after, Some(EPERM), "kcmp blocked");
        assert_eq!(o.mount_after, Some(EPERM), "mount blocked");
        assert_eq!(o.pivot_root_after, Some(EPERM), "pivot_root blocked");
        assert_eq!(o.umount_after, Some(EPERM), "umount2 blocked");
        println!("seccomp_enforcement child: ok");
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let run = |extra: &[&str]| {
        let mut child = Command::new(&exe)
            .args(extra)
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
                panic!("seccomp_enforcement child timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = child.wait_with_output().expect("wait_with_output");
        (status, out)
    };

    let (status, out) = run(&["--child"]);
    assert!(
        status.success(),
        "child failed ({status}): {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
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
