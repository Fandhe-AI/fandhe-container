//! seccomp 適用後に禁止 syscall が実際に遮断されることの結合試験（CORE-5・TASK-38.3・#178。REPAIR-12）。
//!
//! 本番の適用経路（`apply_default_seccomp`＝既定 deny フィルタの構築と `prctl(PR_SET_SECCOMP)`）を、
//! 使い捨ての子プロセス（テストバイナリ自身を `--child` で再実行）の中で適用し、適用前の対照
//! （`unshare(0)` が成功）と適用後の遮断（`unshare`・`mount`・`pivot_root`・`umount2` が `EPERM`）を
//! 具体値で照合する。適用は不可逆・スレッド単位で単一スレッドを要するため、libtest ではなく
//! `harness = false` の単一スレッド `main` で動かす。親は子をタイムアウト付きで待つ（REPAIR-5）。
//! root・KVM 等は不要で、既定のテスト集合で動く。Landlock 証跡不足での exec 拒否は
//! `fork_exec_isolation` 側の責務で、本試験は seccomp の遮断そのものを検証する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("seccomp_enforcement: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
fn main() {
    println!("seccomp_enforcement: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn main() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    /// Linux の `EPERM`（x86_64・aarch64 共通で 1）。
    const EPERM: i32 = 1;

    if std::env::args().any(|a| a == "--child") {
        let o = fandhe_container_core::exec::observe_default_seccomp_enforcement()
            .expect("apply default seccomp in child");
        assert_eq!(o.unshare_before, None, "control: unshare(0) before seccomp");
        assert!(o.instructions > 0, "filter has instructions");
        assert_eq!(o.seccomp_mode, "2", "SECCOMP_MODE_FILTER");
        assert_eq!(o.unshare_after, Some(EPERM), "unshare blocked");
        assert_eq!(o.mount_after, Some(EPERM), "mount blocked");
        assert_eq!(o.pivot_root_after, Some(EPERM), "pivot_root blocked");
        assert_eq!(o.umount_after, Some(EPERM), "umount2 blocked");
        println!("seccomp_enforcement child: ok");
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe)
        .arg("--child")
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
    assert!(
        status.success(),
        "child failed ({status}): {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("seccomp_enforcement child: ok"));
    println!("seccomp_enforcement: ok");
}
