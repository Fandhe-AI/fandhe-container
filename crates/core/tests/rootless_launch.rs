//! rootless 起動フローへの統合（`exec::plan_rootless_subordinate` /
//! `isolate_rootless_subordinate` → `spawn_container`）の結合試験（CORE-6・SEC-5・TASK-40.2・#188）。
//!
//! libtest はマルチスレッドで、マルチスレッドからの `CLONE_NEWUSER`・fork は拒否されるため
//! `harness = false` の単一スレッド `main` で動かす（`rootless_id_map` と同じ理由）。非 Linux では
//! `exec` モジュール自体がビルド対象外（OS 非該当であり skip ではない）。
//!
//! # 受入基準の解釈（REPAIR-3）
//! 制限ステージ（capability 削減・seccomp・Landlock。TASK-37〜39）が未実装の間、`exec_entrypoint` は
//! rootless でも `PermissionDenied` で exec を拒否する。そのため「非 root で分離から exec 段まで
//! 到達できること」を、子が `Exited(126)` で終わり stderr に `PERMISSION_DENIED` が出る（setup 失敗の
//! 125 ではない）ことで照合する。user namespace の作成・写像の書き込み・`MS_PRIVATE`・自己 bind・
//! `/proc` マウント・`pivot_root` がホスト root なしで成功したことの証になる。
//!
//! # 流れ
//! - ディスパッチャ: 一時 rootfs を作り、自身を `--scenario <name> <rootfs>` で再起動して
//!   タイムアウト付きで終了コード 0 を待つ（REPAIR-5）。root で実行された場合は、plan が
//!   `HostRootIdentityMapping` で拒否されること（SEC-5）だけを照合する
//! - シナリオ `direct`: `single_id_mapping(euid)` と `IdMapWriter::Direct`。自プロセスの `uid_map` の
//!   読み戻しが `0 <euid> 1` であることと、Exec 段への到達を照合する
//! - シナリオ `helper`（`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ）: `/etc/subuid`・`/etc/subgid` の
//!   範囲写像を `newuidmap` / `newgidmap` 経由で書く。extent が 2 件以上で plan と一致することと、
//!   Exec 段への到達を照合する
//!
//! # 実機前提テストとしての分離
//! 非特権 user namespace を許可するホストが必要（AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1` 等では `PermissionDenied`）。`-- --ignored` 指定時のみ
//! 実行し、未指定時は「ignored」を出力して成功終了する（ci.md「実機前提テスト」）。CI の
//! `integration-test` への組み込みは別 PR（ci.yml は infra-builder 担当）。実行された場合は拒否を含む
//! あらゆる失敗を失敗として扱い、検証せずに成功する分岐は持たない。helper ケースは env の opt-in 時のみ
//! 実行し、opt-in 時に前提（uidmap・subuid/subgid 行）が無ければ失敗とする。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless_launch: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored" || a == "--scenario") {
        linux::run();
    } else {
        println!(
            "rootless_launch: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Read as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        ChildExit, Entrypoint, Hostname, IsolationConfig, IsolationPrivilege, Namespace,
        NamespaceSet, plan_rootless_subordinate, spawn_container,
    };
    use fandhe_container_core::rootless::{
        DEFAULT_HELPER_TIMEOUT, HelperPaths, IdKind, IdMapSet, IdMapWriter, SubIdOwner, TargetPid,
        WriterKind, load_subordinate_ids, read_id_map, rootless_mapping, single_id_mapping,
    };

    const ENTRY: &str = "entry";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    fn own_ids() -> (u32, u32) {
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

    fn helper_requested() -> bool {
        std::env::var("FANDHE_CONTAINER_TEST_ID_HELPER").as_deref() == Ok("1")
    }

    fn config() -> IsolationConfig {
        IsolationConfig {
            namespaces: NamespaceSet::empty()
                .with(Namespace::Pid)
                .with(Namespace::Mount)
                .with(Namespace::Uts)
                .with(Namespace::Ipc)
                .with(Namespace::User),
            hostname: Some(Hostname::new("fandhe-rootless").expect("hostname")),
        }
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        match args.iter().position(|a| a == "--scenario") {
            Some(i) => {
                let name = args.get(i + 1).expect("scenario name after --scenario");
                let rootfs = args
                    .get(i + 2)
                    .expect("rootfs path after the scenario name");
                scenario(name, Path::new(rootfs));
            }
            None => dispatcher(),
        }
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `proc/` と実行権限付きのエントリポイントを持つ rootfs を排他的に作る（共有 temp 配下の
    /// 予測可能な名前への事前配置を防ぐため、`mkdir` と `O_EXCL` で作る）。
    fn make_rootfs(label: &str) -> Rootfs {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!(
                "fandhe-rootless-{label}-{}-{nanos}",
                std::process::id()
            ));
        std::fs::create_dir(&base).expect("exclusively create rootfs dir");
        let rootfs = Rootfs(base);
        std::fs::set_permissions(&rootfs.0, std::fs::Permissions::from_mode(0o755))
            .expect("chmod rootfs dir");
        std::fs::create_dir(rootfs.0.join("proc")).expect("create rootfs/proc");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(rootfs.0.join(ENTRY))
            .expect("create entrypoint");
        // exec は制限の証跡が無く拒否されるため、中身は実行されない。
        f.write_all(b"#!/bin/true\n").expect("write entrypoint");
        f.set_permissions(std::fs::Permissions::from_mode(0o755))
            .expect("chmod entrypoint");
        rootfs
    }

    /// 子を期限付きで待つ。期限超過なら kill して回収し `None`（REPAIR-5）。
    fn wait_deadline(child: &mut std::process::Child, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => return Some(status),
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let reap_deadline = Instant::now() + Duration::from_secs(5);
                    while child.try_wait().expect("try_wait").is_none() {
                        assert!(
                            Instant::now() < reap_deadline,
                            "the child was not reaped after SIGKILL"
                        );
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    return None;
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn dispatcher() {
        let (euid, egid) = own_ids();
        if euid == 0 || egid == 0 {
            // SEC-5: root 起動＋自 ID 写像（コンテナ root = ホスト root）は計画の段階で拒否される。
            let uid = single_id_mapping(1000).expect("uid mapping");
            let gid = single_id_mapping(1000).expect("gid mapping");
            let err =
                plan_rootless_subordinate(&config(), uid, gid, IdMapWriter::Direct, timeout())
                    .expect_err("root launch must be rejected");
            let v = err.violation.expect("violation record");
            assert_eq!(v.reason.as_str(), "host_root_identity_mapping");
            println!("rootless_launch: host root launch rejected (SEC-5, root=true)");
            return;
        }
        let mut names = vec!["direct"];
        if helper_requested() {
            names.push("helper");
        } else {
            println!(
                "rootless_launch: helper case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1)"
            );
        }
        let exe = std::env::current_exe().expect("current_exe");
        for name in names {
            let rootfs = make_rootfs(name);
            let mut child = Command::new(&exe)
                .args(["--scenario", name])
                .arg(&rootfs.0)
                .stdin(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn scenario");
            let status = wait_deadline(&mut child, timeout() * 3)
                .unwrap_or_else(|| panic!("scenario {name} did not exit within the limit"));
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .expect("piped stderr")
                .read_to_string(&mut stderr)
                .expect("read scenario stderr");
            assert_eq!(
                status.code(),
                Some(0),
                "scenario {name} must exit with 0; stderr:\n{stderr}"
            );
            // Exec 段への到達（SEC-1・CORE-5: 制限証跡が無く exec だけが拒否される）。
            assert!(
                stderr.contains("PERMISSION_DENIED"),
                "stderr of scenario {name} must contain PERMISSION_DENIED; got:\n{stderr}"
            );
            println!("rootless_launch: scenario {name} verified (reached the exec stage)");
        }
    }

    fn helper_mappings(euid: u32, egid: u32) -> (IdMapSet, IdMapSet) {
        let name = std::env::var("USER").ok();
        let uowner = SubIdOwner::new(euid, name.clone()).expect("uid owner");
        let gowner = SubIdOwner::new(egid, name).expect("gid owner");
        let uranges =
            load_subordinate_ids(Path::new("/etc/subuid"), &uowner).expect("load /etc/subuid");
        let granges =
            load_subordinate_ids(Path::new("/etc/subgid"), &gowner).expect("load /etc/subgid");
        assert!(
            !uranges.is_empty() && !granges.is_empty(),
            "helper case requires subuid/subgid entries for the current user"
        );
        (
            rootless_mapping(euid, &uranges).expect("uid range mapping"),
            rootless_mapping(egid, &granges).expect("gid range mapping"),
        )
    }

    /// 分離 → 写像の読み戻し → fork/exec → 終了状態の照合。拒否を含むあらゆる失敗は panic（失敗）。
    fn scenario(name: &str, rootfs: &Path) {
        let (euid, egid) = own_ids();
        let (uid, gid, writer, want_kind) = match name {
            "direct" => (
                single_id_mapping(euid).expect("uid mapping"),
                single_id_mapping(egid).expect("gid mapping"),
                IdMapWriter::Direct,
                WriterKind::Direct,
            ),
            "helper" => {
                let (u, g) = helper_mappings(euid, egid);
                assert!(u.entries().len() >= 2 && g.entries().len() >= 2);
                let paths = HelperPaths::system_default().expect("newuidmap/newgidmap");
                (u, g, IdMapWriter::Helper(paths), WriterKind::Helper)
            }
            other => panic!("unknown scenario {other}"),
        };
        let plan = plan_rootless_subordinate(
            &config(),
            uid.clone(),
            gid.clone(),
            writer,
            DEFAULT_HELPER_TIMEOUT,
        )
        .unwrap_or_else(|e| panic!("plan failed: {e}"));
        let report = fandhe_container_core::exec::isolate_rootless_subordinate(&plan)
            .unwrap_or_else(|e| panic!("isolate failed: {e}"));
        assert_eq!(
            report.isolation.privilege,
            IsolationPrivilege::RootlessSubordinateIds
        );
        assert_eq!(report.id_maps.writer, want_kind);
        assert_eq!(report.id_maps.uid, uid);
        assert_eq!(report.id_maps.gid, gid);

        // 自プロセスの写像を読み戻して、計画どおりであることを具体値で照合する。
        let me = TargetPid::new(std::process::id()).expect("pid");
        assert_eq!(
            read_id_map(me, IdKind::Uid).expect("read uid_map"),
            uid.entries()
        );
        assert_eq!(
            read_id_map(me, IdKind::Gid).expect("read gid_map"),
            gid.entries()
        );
        if name == "direct" {
            let line = std::fs::read_to_string("/proc/self/uid_map").expect("uid_map");
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(fields, ["0", euid.to_string().as_str(), "1"]);
        }

        let path = format!("/{ENTRY}");
        let entry = Entrypoint::new(&path, [path.as_str()], [] as [&str; 0]).expect("entrypoint");
        let child =
            spawn_container(rootfs, &entry).unwrap_or_else(|e| panic!("spawn_container: {e}"));
        let exit = child
            .wait_timeout(timeout())
            .unwrap_or_else(|e| panic!("wait: {e}"));
        // 制限ステージ未実装の間は exec だけが拒否される（126）。setup 失敗（125）ではない。
        assert_eq!(exit, ChildExit::Exited(126), "scenario {name}");
    }
}
