//! namespace 分離（`fandhe_container_core::exec::isolate`）の結合試験（CORE-1・SEC-5・
//! TASK-27.2・#134）。
//!
//! libtest はテストをスレッドで実行し、マルチスレッドからの `CLONE_NEWUSER` は `EINVAL` に
//! なるため、`harness = false` の単一スレッド `main` で動かす（`Cargo.toml` の `[[test]]`）。
//! 非 Linux では `exec` モジュール自体がビルド対象外（OS 非該当であり skip ではない）。
//!
//! # 流れ
//! - 親: 分離（hostname `fandhe-probe`）→ hostname を照合 → 自身を `--child` で起動
//!   （新しい PID namespace の PID 1 になる）→ タイムアウト付きで終了コード 0 を待つ（REPAIR-5）
//! - 子: PID が 1 → `/proc` をマウント → `/proc` の数値ディレクトリが `1` のみ
//!   （ホストのプロセスが不可視）→ hostname を照合
//!
//! # 範囲写像経路で呼び出しプロセスが dumpable にならないこと（CORE-6・SEC-5・SEC-1・#2374）
//! 非 root のとき、本体の分離より前に自身を `--subordinate-non-dumpable` で再起動する。子は
//! `PR_SET_DUMPABLE=0` にして `exec::isolate_rootless_subordinate`（`IdMapWriter::Direct`）を呼び、
//! user namespace 内の uid 0・`uid_map` / `gid_map` の読み戻し・namespace の変化・子プロセス 0 件・
//! 呼び出し後も non-dumpable であることを照合する。親（子の祖先）は、子の実行中に `/proc/<子>` の所有者 uid を
//! 繰り返し標本し、全件が 0（non-dumpable のプロセスは root 所有に見える）であることを照合する。
//! 窓があれば所有者が子の uid に変わり、標本で検出できる。
//!
//! # 実機前提テストとしての分離
//! 実行には root もしくは非特権 user namespace を許可するホストが必要（AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1` 等の環境では `PermissionDenied` になる）。
//! 既定のテスト集合（`--all-features` を含む）からは `#[ignore]` 相当（`-- --ignored` 指定時のみ実行）で
//! 分離している（ci.md「実機前提テスト」）。CI では `platform-ci`（ubuntu-latest）が AppArmor の
//! 制限を緩めた上で `--ignored` 付きで実行する（#1159）。実行された場合は分離の拒否を含め
//! あらゆる失敗を失敗として扱い、検証せずに成功終了する分岐は持たない。

#[path = "support/reap.rs"]
mod reap;

// 予測できる名前の作成を避けるための排他作成の一時領域（#3478・#3434・REPAIR-12）。
#[cfg(target_os = "linux")]
#[path = "support/scratch_root.rs"]
mod scratch_root;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("unshare_isolation: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    // `#[ignore]` 相当: `-- --ignored` を付けたときだけ実行する（`--all-features` を含む
    // 既定の `cargo test --workspace` では実行されない）。子は `--child` で再入する。
    if std::env::args()
        .any(|a| a == "--ignored" || a == "--child" || a == "--subordinate-non-dumpable")
    {
        linux::run();
    } else {
        println!(
            "unshare_isolation: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        Hostname, IsolationConfig, IsolationPrivilege, MountIsolation, Namespace, NamespaceSet,
        isolate, isolate_rootful_host_root, mount_proc, plan, plan_rootful_host_root,
    };

    const HOSTNAME: &str = "fandhe-probe";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn read_hostname() -> String {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .expect("read hostname")
            .trim()
            .to_string()
    }

    pub fn run() {
        if std::env::args().any(|a| a == "--child") {
            child();
        } else if std::env::args().any(|a| a == "--subordinate-non-dumpable") {
            subordinate_non_dumpable_child();
        } else {
            parent();
        }
    }

    fn parent() {
        // euid 0 での自 ID 写像は SEC-5 で拒否されるため、root では User を除く rootful 構成
        // （CORE-7・CORE-9。`plan_rootful_host_root`）にする。
        let is_root = std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(2).map(str::to_string))
            .as_deref()
            == Some("0");
        let mut namespaces = NamespaceSet::empty()
            .with(Namespace::Pid)
            .with(Namespace::Mount)
            .with(Namespace::Uts)
            .with(Namespace::Ipc);
        if !is_root {
            namespaces = namespaces.with(Namespace::User);
        }
        let config = IsolationConfig {
            namespaces,
            hostname: Some(Hostname::new(HOSTNAME).expect("valid hostname")),
        };

        if is_root {
            // root は範囲写像経路（ホスト ID 0 を含む写像）を SEC-5 で拒否する。
            assert!(
                fandhe_container_core::rootless::single_id_mapping(0).is_err(),
                "host root identity mapping must be rejected"
            );
        } else {
            subordinate_non_dumpable_dispatch();
        }

        let host_before = read_hostname();
        // root は sudo 起動の rootful 経路（ホスト root のまま・User なし）、非 root は既定経路。
        let result = if is_root {
            plan_rootful_host_root(&config).and_then(|p| isolate_rootful_host_root(&p))
        } else {
            plan(&config).and_then(|p| isolate(&p))
        };
        match result {
            Ok(report) => {
                assert_eq!(report.namespaces, namespaces);
                let want = if is_root {
                    IsolationPrivilege::RootfulHostRoot
                } else {
                    IsolationPrivilege::RootlessSingleId
                };
                assert_eq!(report.privilege, want);
                assert_eq!(read_hostname(), HOSTNAME);
                assert_ne!(
                    host_before, HOSTNAME,
                    "host hostname must not be the probe name"
                );
                run_child();
                println!("unshare_isolation: full isolation verified (root={is_root})");
            }
            Err(err) => panic!("isolate failed: {err}"),
        }
    }

    /// 自身を `--child` で起動する。分離後の最初の子なので新しい PID namespace の PID 1 になる。
    fn run_child() {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .arg("--child")
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn child");
        let deadline = Instant::now() + timeout();
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    assert_eq!(status.code(), Some(0), "child must exit with 0");
                    return;
                }
                None if Instant::now() >= deadline => {
                    crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
                    panic!("child did not exit within {:?}", timeout());
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn child() {
        assert_eq!(
            std::process::id(),
            1,
            "child must be PID 1 of the new PID namespace"
        );
        let isolation = MountIsolation::establish().expect("establish mount isolation");
        mount_proc(&isolation, Path::new("/"), Path::new("/proc")).expect("mount proc");
        let mut pids: Vec<String> = std::fs::read_dir("/proc")
            .expect("read /proc")
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .collect();
        pids.sort();
        assert_eq!(
            pids,
            vec!["1".to_string()],
            "host processes must be invisible"
        );
        assert_eq!(read_hostname(), HOSTNAME);
    }

    /// `/proc/<pid>` ディレクトリの所有者 uid（non-dumpable なら root 所有に見える）。
    fn proc_owner_uid(pid: u32) -> Option<u32> {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(format!("/proc/{pid}"))
            .ok()
            .map(|m| m.uid())
    }

    /// `/proc/self/status` の `Uid:` 行の実 uid。
    fn real_uid() -> u32 {
        std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1).map(str::to_string))
            .and_then(|v| v.parse().ok())
            .expect("parse uid")
    }

    fn user_ns_ino() -> u64 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self/ns/user")
            .expect("stat userns")
            .ino()
    }

    /// 親: 子を `--subordinate-non-dumpable` で起動し、実行中の `/proc/<子>` の所有者 uid を標本する。
    fn subordinate_non_dumpable_dispatch() {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        // 共有 /tmp の予測できる名前へ create せず、排他作成の ScratchDir の子へ create_new する。
        // 先置きの symlink は辿らず EEXIST で失敗し、panic の unwind でも drop で消える（#3478・REPAIR-12）。
        let scratch =
            crate::scratch_root::ScratchDir::new("fandhe-subordinate-non-dumpable", timeout());
        let log = scratch.path().join("child.log");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&log)
            .expect("create log");
        let mut child = Command::new(std::env::current_exe().expect("current_exe"))
            .arg("--subordinate-non-dumpable")
            .stdin(Stdio::piped())
            .stdout(file.try_clone().expect("clone log"))
            .stderr(file)
            .spawn()
            .expect("spawn subordinate child");
        let pid = child.id();
        let overall = Instant::now() + timeout() * 3;
        let fail = |child: &mut std::process::Child, msg: &str| -> ! {
            crate::reap::reap_or_report(child, crate::reap::reap_within());
            let out = std::fs::read_to_string(&log).unwrap_or_default();
            panic!("{msg}\n{out}");
        };
        // 子が non-dumpable にし終えるまで待つ(この前の標本は意味がない)。
        loop {
            let out = std::fs::read_to_string(&log).unwrap_or_default();
            if out.lines().any(|l| l == "subordinate child ready") {
                break;
            }
            if let Some(st) = child.try_wait().expect("try_wait") {
                panic!("subordinate child exited early: {st:?}\n{out}");
            }
            if Instant::now() >= overall {
                fail(&mut child, "subordinate child did not become ready in time");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // 開始の合図(stdin に 1 バイト)を送ってから、終了まで標本する。
        {
            let mut stdin = child.stdin.take().expect("child stdin");
            stdin.write_all(&[1]).expect("send go");
        }
        let mut samples = 0u64;
        let mut observed: Vec<u32> = Vec::new();
        let status = loop {
            if let Some(uid) = proc_owner_uid(pid) {
                samples += 1;
                if uid != 0 && !observed.contains(&uid) {
                    observed.push(uid);
                }
            }
            if let Some(st) = child.try_wait().expect("try_wait") {
                break st;
            }
            if Instant::now() >= overall {
                fail(&mut child, "subordinate child did not finish in time");
            }
            std::thread::sleep(Duration::from_micros(200));
        };
        let out = std::fs::read_to_string(&log).unwrap_or_default();
        assert_eq!(status.code(), Some(0), "subordinate child failed\n{out}");
        if !out.lines().any(|l| l == "owner sampling supported") {
            println!(
                "unshare_isolation: /proc owner does not reflect non-dumpable on this kernel; \
                 owner sampling skipped (the child still verified PR_GET_DUMPABLE)"
            );
        } else {
            assert!(samples >= 1, "no /proc/<child> owner sample was taken");
            assert!(
                observed.is_empty(),
                "the caller became dumpable while mapping (owner uids seen: {observed:?}, samples: {samples})"
            );
        }
        println!(
            "unshare_isolation: subordinate isolation kept the caller non-dumpable (samples={samples})"
        );
    }

    /// 子: non-dumpable のまま範囲写像経路（Direct）で分離し、結果を具体値で照合する。
    fn subordinate_non_dumpable_child() {
        use std::io::{Read as _, Write as _};

        use fandhe_container_core::exec::{
            is_non_dumpable_for_test, isolate_rootless_subordinate, plan_rootless_subordinate,
            set_non_dumpable_for_test,
        };
        use fandhe_container_core::rootless::{IdMapWriter, single_id_mapping};

        set_non_dumpable_for_test().expect("set non-dumpable");
        assert_eq!(is_non_dumpable_for_test(), Some(true));
        // non-dumpable のとき /proc/<pid> の所有者が root になるのは一部のカーネル・環境の挙動で、
        // 成り立たない環境では所有者の標本が窓の観測にならない。その場合は親が標本の判定を省き、
        // 子側の PR_GET_DUMPABLE の照合だけを残す(実装の不具合とは区別して明示する)。
        if proc_owner_uid(std::process::id()) == Some(0) {
            println!("owner sampling supported");
        } else {
            println!("owner sampling unsupported");
        }
        let uid = real_uid();
        let gid = std::fs::read_to_string("/proc/self/status")
            .expect("read status")
            .lines()
            .find(|l| l.starts_with("Gid:"))
            .and_then(|l| l.split_whitespace().nth(1).map(str::to_string))
            .and_then(|v| v.parse::<u32>().ok())
            .expect("parse gid");
        let ns_before = user_ns_ino();
        println!("subordinate child ready");
        let _ = std::io::stdout().flush();
        // 親が標本を始める合図を待つ(EOF でも進む)。
        let mut go = [0u8; 1];
        let _ = std::io::stdin().read(&mut go);

        let config = IsolationConfig {
            namespaces: NamespaceSet::empty().with(Namespace::User),
            hostname: None,
        };
        let plan = plan_rootless_subordinate(
            &config,
            single_id_mapping(uid).expect("uid mapping"),
            single_id_mapping(gid).expect("gid mapping"),
            IdMapWriter::Direct,
            timeout(),
        )
        .expect("plan");
        let report = isolate_rootless_subordinate(&plan).expect("isolate rootless subordinate");
        assert_eq!(
            report.isolation.privilege,
            IsolationPrivilege::RootlessSubordinateIds
        );

        assert_eq!(real_uid(), 0, "uid inside the user namespace");
        let map = |name: &str| {
            std::fs::read_to_string(format!("/proc/self/{name}"))
                .unwrap_or_else(|e| panic!("read {name}: {e}"))
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        // 内側から読む lower ID は読み手の user namespace 基準で表示され、ホストの uid / gid とは
        // 直接比較できない。ホスト ID との照合は親側(holder の外)の責務とし、ここでは内側の写像が
        // 「コンテナ 0 から 1 件」の形であることだけを照合する。
        for name in ["uid_map", "gid_map"] {
            let fields = map(name);
            assert_eq!(
                fields.len(),
                3,
                "{name} must have exactly one line: {fields:?}"
            );
            assert_eq!(fields[0], "0", "{name} container id");
            assert!(
                fields[1].parse::<u32>().is_ok(),
                "{name} lower id: {fields:?}"
            );
            assert_eq!(fields[2], "1", "{name} count");
        }
        assert_ne!(
            user_ns_ino(),
            ns_before,
            "must have joined a new user namespace"
        );
        assert_eq!(
            is_non_dumpable_for_test(),
            Some(true),
            "caller must stay non-dumpable"
        );

        // holder と mapper は回収済みで、子プロセスが残っていない。
        let me = std::process::id();
        let children: Vec<String> = std::fs::read_dir("/proc")
            .expect("read /proc")
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
            .filter(|n| {
                std::fs::read(format!("/proc/{n}/stat"))
                    .ok()
                    .is_some_and(|b| {
                        b.iter().rposition(|c| *c == b')').is_some_and(|i| {
                            String::from_utf8_lossy(&b[i + 1..])
                                .split_whitespace()
                                .nth(1)
                                .and_then(|v| v.parse::<u32>().ok())
                                == Some(me)
                        })
                    })
            })
            .collect();
        assert!(
            children.is_empty(),
            "leftover child processes: {children:?}"
        );
    }
}
