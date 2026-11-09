//! pod の保持役の namespace 確立 API(`oci_runtime::establish_pod_namespaces`)の結合試験
//! (CRI-2・CORE-3・SEC-5・NET-2・TASK-29 追補・#2870)。
//!
//! libtest はテストをスレッドで実行し、マルチスレッドからの `CLONE_NEWUSER` は `EINVAL` になるため、
//! `harness = false` の単一スレッド `main` で動かす(`Cargo.toml` の `[[test]]`)。確立は呼び出しプロセスの
//! namespace を変えるので、親は自身を `--child <case>` で再入させて期限つきで待つ(REPAIR-5)。
//!
//! # 子の照合(ケース `single`、`FANDHE_CONTAINER_TEST_ID_HELPER=1` のときは `subordinate` も)
//! - 呼び出し前に `PR_SET_DUMPABLE=0` にし、呼び出し後も non-dumpable であること
//! - 返った写像・実際の `/proc/self/{uid,gid}_map`・計画(`single` は `0 <euid> 1`)の 3 者が完全一致すること
//! - user / ipc / net の素性が呼び出し前と異なり、報告の `(dev, ino)` が `/proc/self/ns/*` と一致すること
//! - `lo` が up であること(自己宛ての UDP 送受信が通る。down なら `ENETUNREACH`)
//! - 子プロセスが残っていないこと
//! - root で実行した場合は確立を拒否すること(`single` の euid 0 は HostRootIdentityMapping)
//!
//! # 実機前提テストとしての分離
//! 非特権 user namespace を許可するホストが必要(AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1`
//! では失敗する)。`-- --ignored` 指定時のみ実行する(docs/verification/real-machine-tests.md)。範囲写像は
//! `uidmap`・subuid / subgid の自ユーザー行・Linux 6.9 以降が要り、前提が無ければ `PRECONDITION FAILED` で失敗する
//! (skip で成功にしない)。CI への組み込みは #2875。

#[cfg(target_os = "linux")]
#[path = "support/precondition.rs"]
mod precondition;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("pod_holder: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--child") {
        linux::child();
    } else if std::env::args().any(|a| a == "--ignored") {
        linux::parent();
    } else {
        precondition::self_check();
        println!(
            "pod_holder: ignored (real-machine test; run with `-- --ignored`, see docs/verification/real-machine-tests.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::precondition;
    use std::net::UdpSocket;
    use std::os::unix::fs::MetadataExt as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        IdMapping, IsolationPrivilege, is_non_dumpable_for_test, set_non_dumpable_for_test,
    };
    use fandhe_container_core::oci_runtime::{SubordinateIdSource, establish_pod_namespaces};
    use fandhe_container_core::traits::ErrorCode;

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        // 範囲写像は helper を 2 回呼ぶため、基本の期限に余裕を足す。
        Duration::from_secs(secs * 4)
    }

    fn helper_requested() -> bool {
        std::env::var("FANDHE_CONTAINER_TEST_ID_HELPER").as_deref() == Ok("1")
    }

    pub fn parent() {
        precondition::self_check();
        let mut cases = vec!["single"];
        if helper_requested() {
            cases.push("subordinate");
        } else {
            println!(
                "pod_holder: subordinate case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1)"
            );
        }
        for case in cases {
            run_child(case);
        }
    }

    fn run_child(case: &str) {
        let exe = std::env::current_exe().expect("current exe");
        let mut child = Command::new(exe)
            .args(["--child", case])
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn child");
        let deadline = Instant::now() + timeout();
        let status = loop {
            if let Some(s) = child.try_wait().expect("try_wait") {
                break s;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("pod_holder: child `{case}` exceeded the deadline (WATCHDOG EXPIRED)");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            status.success(),
            "pod_holder: child `{case}` failed: {status}"
        );
    }

    fn ids() -> (u32, u32) {
        let id = |key: &str| -> u32 {
            std::fs::read_to_string("/proc/self/status")
                .expect("read status")
                .lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(2))
                .and_then(|v| v.parse().ok())
                .expect("parse id")
        };
        (id("Uid:"), id("Gid:"))
    }

    fn ns_identity(name: &str) -> (u64, u64) {
        let m = std::fs::metadata(format!("/proc/self/ns/{name}")).expect("stat namespace");
        (m.dev(), m.ino())
    }

    fn read_map(name: &str) -> Vec<IdMapping> {
        std::fs::read_to_string(format!("/proc/self/{name}"))
            .expect("read id map")
            .lines()
            .map(|l| {
                let f: Vec<u32> = l
                    .split_whitespace()
                    .map(|v| v.parse().expect("number"))
                    .collect();
                assert_eq!(f.len(), 3, "map line");
                IdMapping {
                    container_id: f[0],
                    host_id: f[1],
                    count: f[2],
                }
            })
            .collect()
    }

    /// 自プロセスの子(PPid が自 pid)が無いこと。
    fn assert_no_children() {
        let me = std::process::id();
        for entry in std::fs::read_dir("/proc").expect("read /proc").flatten() {
            let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
                continue;
            };
            let ppid = status
                .lines()
                .find(|l| l.starts_with("PPid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<u32>().ok());
            assert_ne!(ppid, Some(me), "a child process remains");
        }
    }

    /// `lo` が up なら自己宛ての UDP が往復する(down なら送信が `ENETUNREACH`)。
    fn assert_loopback_up() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
        sock.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let addr = sock.local_addr().expect("addr");
        sock.send_to(b"p", addr).expect("send to loopback");
        let mut buf = [0u8; 1];
        let (n, _) = sock.recv_from(&mut buf).expect("recv from loopback");
        assert_eq!((n, buf[0]), (1, b'p'));
    }

    pub fn child() {
        let case = std::env::args()
            .skip_while(|a| a != "--child")
            .nth(1)
            .expect("case");
        let (euid, egid) = ids();
        let (privilege, source, success) = match case.as_str() {
            "single" => (
                IsolationPrivilege::RootlessSingleId,
                None,
                "pod_holder: single id namespaces established and verified (root=false)",
            ),
            "subordinate" => {
                if euid == 0 {
                    // 範囲写像は非 root のみ(root の分岐は CI 外)。
                    println!("pod_holder: subordinate case needs a non-root user");
                    std::process::exit(1);
                }
                precondition::require_subordinate_ids(euid);
                let name = std::env::var("USER").ok().filter(|n| !n.is_empty());
                (
                    IsolationPrivilege::RootlessSubordinateIds,
                    Some(SubordinateIdSource::system(name).expect("subordinate id source")),
                    "pod_holder: subordinate id namespaces established and verified",
                )
            }
            other => panic!("unknown case {other}"),
        };
        if euid == 0 {
            let err = establish_pod_namespaces(privilege, source).expect_err("root is rejected");
            assert!(
                matches!(
                    err.code(),
                    ErrorCode::PermissionDenied | ErrorCode::FailedPrecondition
                ),
                "unexpected code {:?}",
                err.code()
            );
            println!("pod_holder: root caller rejected (root=true)");
            return;
        }

        let before = [ns_identity("user"), ns_identity("ipc"), ns_identity("net")];
        set_non_dumpable_for_test().expect("set non-dumpable");
        let got = establish_pod_namespaces(privilege, source).expect("establish pod namespaces");

        // 写像: 報告・実際の /proc・計画の 3 者が完全一致する。
        let (uid_map, gid_map) = (read_map("uid_map"), read_map("gid_map"));
        assert_eq!(got.uid_map(), uid_map.as_slice());
        assert_eq!(got.gid_map(), gid_map.as_slice());
        let first = |host| IdMapping {
            container_id: 0,
            host_id: host,
            count: 1,
        };
        if case == "single" {
            assert_eq!(uid_map, vec![first(euid)]);
            assert_eq!(gid_map, vec![first(egid)]);
        } else {
            assert_eq!(uid_map.first().copied(), Some(first(euid)));
            assert_eq!(gid_map.first().copied(), Some(first(egid)));
            assert!(
                uid_map.len() > 1 && gid_map.len() > 1,
                "no subordinate range"
            );
        }

        // 素性: 呼び出し前と異なり、報告が実際の /proc/self/ns/* と一致する。
        let after = [ns_identity("user"), ns_identity("ipc"), ns_identity("net")];
        for (b, a) in before.iter().zip(after.iter()) {
            assert_ne!(b, a, "a namespace was not created");
        }
        let reported =
            |i: fandhe_container_core::oci_runtime::NamespaceIdentity| (i.dev(), i.ino());
        assert_eq!(reported(got.user()), after[0]);
        assert_eq!(reported(got.ipc()), after[1]);
        assert_eq!(reported(got.net()), after[2]);
        assert_eq!(got.privilege(), privilege);
        assert!(got.loopback_up());

        assert_loopback_up();
        assert_eq!(is_non_dumpable_for_test(), Some(true), "dumpable window");
        assert_no_children();
        println!("{success}");
    }
}
