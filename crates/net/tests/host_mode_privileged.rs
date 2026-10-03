//! host モード（ホスト netns 共有）の実機結合試験（NET-6・TASK-143.1・#326・MS-8）。
//!
//! root と util-linux の `unshare`、`sleep` が必要な実機前提テストのため `harness = false` の独自 `main` で
//! 動かし、`-- --ignored` を付けたときだけ実行する（未指定時は「ignored」を出力して成功終了する分離であり、
//! CI 通過のための弱体化ではない。`AGENTS.md`「実機前提テスト」節）。非 Linux では対象外。
//!
//! # 流れ
//! - ランチャ（host netns・root）: (1) `HostNetns::detect()` が成功し id が `/proc/1/ns/net` と一致、
//!   (2) 子 `sleep` が `verify_process` で `Member`、(3) その子の `/proc/<pid>/net/dev` の interface 名集合が
//!   ホストの `/proc/net/dev` と一致、(4) `unshare --net` で起こした子は `Other` になり、
//!   (5) `unshare --net -- <exe> --child` の子では `detect()` が `FAILED_PRECONDITION`（fail-closed）になる
//!
//! 待ちはすべて `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（既定 10 秒）で期限を切る（REPAIR-5）。前提を満たさない
//! 場合は skip せず失敗する。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("host_mode_privileged: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--child") {
        linux::child();
    } else if args.iter().any(|a| a == "--ignored") {
        linux::launcher();
    } else {
        println!(
            "host_mode_privileged: ignored (requires root and `unshare`; run the built executable with `--ignored` under `sudo`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::MetadataExt as _;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_net::error::NetErrorCode;
    use fandhe_container_net::network_mode::host::{HostNetns, HostNetnsMembership};

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn require_root() {
        let uid_root = fs::read_to_string("/proc/self/status")
            .expect("read /proc/self/status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_owned))
            .as_deref()
            == Some("0");
        assert!(uid_root, "this test requires root (euid 0); see AGENTS.md");
    }

    /// `/proc/.../net/dev` の interface 名集合（先頭 2 行はヘッダ）。
    fn ifaces(path: &str) -> BTreeSet<String> {
        fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"))
            .lines()
            .skip(2)
            .filter_map(|l| l.split(':').next().map(|n| n.trim().to_owned()))
            .collect()
    }

    /// 子を期限つきで待つ。超過したら kill して失敗する（REPAIR-5）。
    fn wait_exit(child: &mut Child) -> std::process::ExitStatus {
        let deadline = Instant::now() + timeout();
        loop {
            if let Some(st) = child.try_wait().expect("try_wait") {
                return st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not exit within the timeout");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// 子プロセスの所有ガード。成功・エラー・panic のいずれの経路でも Drop で kill と wait を実行し、
    /// root で起動した `sleep 60` や隔離 netns をテスト終了後に残さない（特権操作の後始末）。
    struct ChildGuard(Child);

    impl ChildGuard {
        fn id(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// `sleep` を起動する（`unshare_net` 時は `unshare --net` 経由）。起動完了の待機は `wait_comm_sleep` が担う。
    fn spawn_sleep(unshare_net: bool) -> ChildGuard {
        let mut cmd = if unshare_net {
            let mut c = Command::new("unshare");
            c.args(["--net", "--", "sleep", "60"]);
            c
        } else {
            let mut c = Command::new("sleep");
            c.arg("60");
            c
        };
        ChildGuard(
            cmd.stdin(Stdio::null())
                .spawn()
                .expect("spawn sleep (is util-linux unshare installed?)"),
        )
    }

    /// 子の exec と netns 切替の完了を、comm が `sleep` になるまで期限つきで待つ。
    fn wait_comm_sleep(pid: u32) {
        let deadline = Instant::now() + timeout();
        loop {
            let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            if comm.trim() == "sleep" {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "child did not exec sleep in time"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn launcher() {
        require_root();

        // (1) 呼び出しスレッドがホスト netns にいる。
        let host = HostNetns::detect().expect("detect host netns");
        let init = fs::metadata("/proc/1/ns/net").expect("stat /proc/1/ns/net");
        assert_eq!(
            (host.id().dev(), host.id().ino()),
            (init.dev(), init.ino()),
            "detect id must equal /proc/1/ns/net"
        );

        // (2)(3) host の子は Member で、interface 名集合がホストと一致する。
        let child = spawn_sleep(false);
        let pid = child.id();
        wait_comm_sleep(pid);
        let m = host.verify_process(pid).expect("verify host child");
        let host_ifaces = ifaces("/proc/net/dev");
        let child_ifaces = ifaces(&format!("/proc/{pid}/net/dev"));
        drop(child);
        assert_eq!(m, HostNetnsMembership::Member);
        assert_eq!(child_ifaces, host_ifaces);

        // (4) unshare --net の子は Other。
        let other = spawn_sleep(true);
        let opid = other.id();
        wait_comm_sleep(opid);
        let om = host.verify_process(opid);
        drop(other);
        match om.expect("verify unshared child") {
            HostNetnsMembership::Other { observed } => assert_ne!(observed, host.id()),
            m => panic!("unshared child must not be a member: {m:?}"),
        }

        // (5) 新しい netns の中では detect が FAILED_PRECONDITION。
        let exe = std::env::current_exe().expect("current_exe");
        let mut c = ChildGuard(
            Command::new("unshare")
                .args(["--net", "--"])
                .arg(exe)
                .arg("--child")
                .stdin(Stdio::null())
                .spawn()
                .expect("spawn unshare child"),
        );
        let st = wait_exit(&mut c.0);
        assert!(st.success(), "child detect check failed: {st:?}");

        println!(
            "host_mode_privileged: ok detect=host member=1 ifaces=equal other=detected fail_closed=1"
        );
    }

    pub fn child() {
        match HostNetns::detect() {
            Err(e) if e.code() == NetErrorCode::FailedPrecondition => {}
            other => {
                eprintln!("expected FAILED_PRECONDITION in unshared netns, got {other:?}");
                std::process::exit(1);
            }
        }
    }
}
