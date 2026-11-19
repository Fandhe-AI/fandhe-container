//! pod の保持役の namespace 確立 API(`oci_runtime::establish_pod_namespaces`)の結合試験
//! (CRI-2・CORE-3・SEC-5・NET-2・TASK-29 追補・#2870)。
//!
//! libtest はテストをスレッドで実行し、マルチスレッドからの `CLONE_NEWUSER` は `EINVAL` になるため、
//! `harness = false` の単一スレッド `main` で動かす(`Cargo.toml` の `[[test]]`)。確立は呼び出しプロセスの
//! namespace を変えるので、親は自身を `--child <case>` で再入させて期限つきで待つ(REPAIR-5)。
//!
//! # 子の照合(ケース `single`、`FANDHE_CONTAINER_TEST_ID_HELPER=1` のときは `subordinate` も)
//! - (`subordinate` のみ)呼び出し前に `PR_SET_DUMPABLE=0` にし、呼び出し後も non-dumpable であること
//!   (`single` は自プロセスの `/proc/self` へ写像を書くため事前に non-dumpable にしない。#2875)
//! - 返った写像・実際の `/proc/self/{uid,gid}_map`・計画(`single` は `0 <euid> 1`)の 3 者が完全一致すること
//! - user / ipc / net / mnt の素性が呼び出し前と異なり、報告の `(dev, ino)` が `/proc/self/ns/*` と一致すること
//!   （mnt は #4808。所有者が pod の userns であることは確立が `NS_GET_USERNS` で照合済みで、成功値はその証跡）
//! - mount namespace の `/` が shared でない（`/proc/self/mountinfo` の `/` の行に `shared:` が無い。#4808）
//! - pod-init の空の root（`create_pod_root`）が `nosuid,nodev,noexec` で、エントリが 0 件であること（#4808）
//! - pod の `/dev/shm`（`mount_pod_shm`。#4821）が tmpfs で、mountinfo の `size=65536k`・`nosuid,nodev,noexec`、
//!   `st_mode` の 1777、報告の素性と `/dev/shm` の `stat` が一致すること
//! - pod-init（`spawn_pod_init`。#4815）が pod の pid ns の PID 1（`NSpid` の末尾 1）で、`CapEff`・`CapPrm` が 0、自己検査
//!   （non-dumpable）を通って生き続けること。SIGKILL で回収できる（root と pid ns の素性は `pod_holder_bin_real` のシナリオ G）
//! - `lo` が up であること(自己宛ての UDP 送受信が通る。down なら `ENETUNREACH`)
//! - 子プロセスが残っていないこと
//! - root で実行した場合は確立を拒否すること(`single` の euid 0 は HostRootIdentityMapping)
//!
//! # 実機前提テストとしての分離
//! 非特権 user namespace を許可するホストが必要(AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1`
//! では失敗する)。`-- --ignored` 指定時のみ実行する(docs/verification/real-machine-tests.md)。範囲写像は
//! `uidmap`・subuid / subgid の自ユーザー行・Linux 6.9 以降が要り、前提が無ければ `PRECONDITION FAILED` で失敗する
//! (skip で成功にしない)。CI の `platform-ci` の ubuntu で実行する（#2875）。

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
    use fandhe_container_core::oci_runtime::{
        SubordinateIdSource, create_pod_root, establish_pod_namespaces, mount_pod_shm,
        root_entry_count, spawn_pod_init,
    };
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
                let kill_result = child.kill();
                // kill 後も回収を無期限に待たない（D 状態の子で親が固まるのを防ぐ。REPAIR-5）。
                let reap_deadline = Instant::now() + Duration::from_secs(10);
                let reaped = loop {
                    match child.try_wait() {
                        Ok(Some(_)) => break true,
                        Ok(None) if Instant::now() < reap_deadline => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        _ => break false,
                    }
                };
                panic!(
                    "pod_holder: child `{case}` exceeded the deadline (WATCHDOG EXPIRED); \
                     kill={kill_result:?} reaped={reaped}"
                );
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

    /// pod-init が pid ns の PID 1 で、capability を持たず、自己検査（non-dumpable）を通って生き続けていること（#4815）。
    fn assert_pod_init(pid: u32) {
        // 自己検査に失敗すると数 ms で終わるため、少し待ってから見る。
        std::thread::sleep(Duration::from_millis(300));
        let status =
            std::fs::read_to_string(format!("/proc/{pid}/status")).expect("pod init status");
        let field = |name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .map(str::trim)
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(
            field("NSpid:").split_whitespace().last(),
            Some("1"),
            "pod init is PID 1"
        );
        assert_eq!(field("CapEff:"), "0000000000000000");
        assert_eq!(field("CapPrm:"), "0000000000000000");
        assert_eq!(
            field("State:").chars().next(),
            Some('S'),
            "pod init is alive"
        );
        // root と pid ns の素性は `/proc/<pid>/{root,ns}` の ptrace の検査を通らない（この子は exec の後に userns を作ったため
        // mm の userns が初期 userns のままで、non-dumpable の pod-init を開けない）。再 exec する保持役の実機試験
        // `pod_holder_bin_real` のシナリオ G で照合する。
    }

    /// pod の `/dev/shm`（#4821）が 64 MiB・mode 1777・`nosuid,nodev,noexec` の tmpfs で、報告の素性と一致すること。
    fn assert_pod_shm(dev: u64, ino: u64) {
        let md = std::fs::metadata("/dev/shm").expect("stat /dev/shm");
        assert_eq!(
            (md.dev(), md.ino()),
            (dev, ino),
            "reported /dev/shm identity"
        );
        assert_eq!(md.mode() & 0o7777, 0o1777, "/dev/shm mode");
        let info = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        // 同じ場所に重ねたマウントは後の行が上（ホストの `/dev/shm` の上に載せた）。
        let line = info
            .lines()
            .rfind(|l| l.split_whitespace().nth(4) == Some("/dev/shm"))
            .expect("/dev/shm mount line");
        let (head, tail) = line.split_once(" - ").expect("mountinfo separator");
        let opts: Vec<&str> = head
            .split_whitespace()
            .nth(5)
            .expect("mount options")
            .split(',')
            .collect();
        for want in ["rw", "nosuid", "nodev", "noexec"] {
            assert!(opts.contains(&want), "missing {want}: {line}");
        }
        let mut fs = tail.split_whitespace();
        assert_eq!(fs.next(), Some("tmpfs"), "{line}");
        let sb: Vec<&str> = fs.nth(1).expect("super options").split(',').collect();
        assert!(sb.contains(&"size=65536k"), "{line}");
        // mode は既定の 1777 のとき mountinfo に出ない（`mm/shmem.c` の `shmem_show_options`）ため、上の `st_mode` で照合する。
        assert!(!sb.iter().any(|o| o.starts_with("mode=")), "{line}");
    }

    /// `/` のマウントが shared でない（確立で再帰 private にした。#4808）。
    fn assert_root_not_shared() {
        let info = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        let root = info
            .lines()
            .find(|l| l.split_whitespace().nth(4) == Some("/"))
            .expect("root mount line");
        assert!(!root.contains("shared:"), "root mount is shared: {root}");
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

        let names = ["user", "ipc", "net", "mnt"];
        let before = names.map(ns_identity);
        // single は自プロセスの /proc/self/{setgroups,uid_map,gid_map} へ書く。non-dumpable のプロセスの /proc/self は
        // root（init user namespace の kuid 0）所有になり、unshare 後の namespace では写像が無く書き込みが拒否される
        // ため、single では事前に non-dumpable にしない（実機の CI で PermissionDenied になった。#2875）。範囲写像は
        // 別 holder が書くので、non-dumpable の維持の照合は subordinate だけで行う。
        let preset_non_dumpable = case == "subordinate";
        if preset_non_dumpable {
            set_non_dumpable_for_test().expect("set non-dumpable");
        }
        let got = establish_pod_namespaces(privilege, source).expect("establish pod namespaces");

        // 写像: 内側から読む /proc の host_id は開いた側基準で変わりうるため、報告(計画値)と
        // 実際の /proc は container_id・count の構造で照合し、host_id は計画値を具体値で固定する。
        let (uid_map, gid_map) = (read_map("uid_map"), read_map("gid_map"));
        let shape = |v: &[IdMapping]| -> Vec<(u32, u32)> {
            v.iter().map(|e| (e.container_id, e.count)).collect()
        };
        assert_eq!(shape(got.uid_map()), shape(&uid_map));
        assert_eq!(shape(got.gid_map()), shape(&gid_map));
        let (uid_map, gid_map) = (got.uid_map().to_vec(), got.gid_map().to_vec());
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
        let after = names.map(ns_identity);
        for (b, a) in before.iter().zip(after.iter()) {
            assert_ne!(b, a, "a namespace was not created");
        }
        let reported =
            |i: fandhe_container_core::oci_runtime::NamespaceIdentity| (i.dev(), i.ino());
        assert_eq!(reported(got.user()), after[0]);
        assert_eq!(reported(got.ipc()), after[1]);
        assert_eq!(reported(got.net()), after[2]);
        assert_eq!(reported(got.mnt()), after[3]);
        assert_root_not_shared();

        // pod-init の空の root（#4808）。属性は 3 つとも付き、中身は 0 件。
        let root = create_pod_root().expect("create the pod root");
        let attrs = root.attrs().expect("pod root attrs");
        assert_eq!(
            (attrs.nosuid, attrs.nodev, attrs.noexec),
            (true, true, true)
        );
        assert_eq!(root_entry_count(&root).expect("entries"), 0);
        // pod の `/dev/shm`（#4821）。確立した mount ns の `/dev/shm` に載せる。
        let shm = mount_pod_shm().expect("mount the pod /dev/shm");
        assert_pod_shm(shm.dev(), shm.ino());
        // pod の PID 1（pod-init。#4815）。確立と同じ単一スレッドの子から作る。pod-init は non-dumpable を自分で確かめる
        // ため、作る前に non-dumpable にする（single は確立の前にはできない。上のコメント）。
        if !preset_non_dumpable {
            set_non_dumpable_for_test().expect("set non-dumpable");
        }
        let init = spawn_pod_init(&root).expect("spawn the pod init");
        assert_pod_init(init.pid());
        assert!(!init.has_exited().expect("poll the pod init"));
        init.kill_and_reap(Duration::from_secs(5))
            .expect("stop the pod init");
        drop(root);
        assert_eq!(got.privilege(), privilege);
        assert!(got.loopback_up());

        assert_loopback_up();
        if preset_non_dumpable {
            assert_eq!(is_non_dumpable_for_test(), Some(true), "dumpable window");
        }
        assert_no_children();
        println!("{success}");
    }
}
