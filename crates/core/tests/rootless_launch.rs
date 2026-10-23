//! rootless 起動フローへの統合（`exec::plan_rootless_subordinate` /
//! `isolate_rootless_subordinate` → `spawn_container`）の結合試験（CORE-6・SEC-5・TASK-40.2・#188）。
//!
//! libtest はマルチスレッドで、マルチスレッドからの `CLONE_NEWUSER`・fork は拒否されるため
//! `harness = false` の単一スレッド `main` で動かす（`rootless_id_map` と同じ理由）。非 Linux では
//! `exec` モジュール自体がビルド対象外（OS 非該当であり skip ではない）。
//!
//! # 受入基準の解釈（REPAIR-3）
//! 本試験の経路は `with_landlock` を載せず、制限適用の証跡 `LaunchReady` が作られない（fail-closed。#1714）ため、
//! `exec_entrypoint` は rootless でも `PermissionDenied` で exec を拒否する。そのため「非 root で分離から exec 段まで
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
//! `platform-ci`（ubuntu）では #2596 で helper ケースを有効にして実行し、成功行を照合する（root 分岐は CI で回さず #1621）。実行された場合は拒否を含む
//! あらゆる失敗を失敗として扱い、検証せずに成功する分岐は持たない。helper ケースは env の opt-in 時のみ
//! 実行し、opt-in 時に前提（uidmap・subuid/subgid 行）が無ければ失敗とする。
//!
//! # 寿命の上限と残った子の照合（#2436・CORE-1・REPAIR-5）
//! 本試験には exec される実エントリポイントが無い（`/entry` は `#!/bin/true` で、`LaunchReady` が無いため実行されない）。
//! そのため `rootless` 系と違い、env で渡す寿命の上限（`real_entry::arm_entry_lifetime`）は持たない。また scenario
//! プロセスは `isolate_rootless_subordinate`・`spawn_container` の前提として単一スレッドでなければならず、見張り
//! スレッドも置けない。代わりに、固まりうる待ちはすべて期限つきで、期限を過ぎたら kill する（helper の
//! `DEFAULT_HELPER_TIMEOUT`・`ContainerChild::wait_timeout`・ディスパッチャの `wait_deadline`）。さらにディスパッチャは
//! child subreaper になり、各 scenario の後に `leftover_children::assert_no_leftover_children` で、再親付けされた
//! holder・mapper・コンテナ PID 1 を含む子が残っていないことを fail-closed で照合する（残りは kill・回収して失敗にする）。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless_launch: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
#[path = "support/leftover_children.rs"]
mod leftover_children;

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

    use crate::leftover_children;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        ChildExit, ChildSubreaper, Entrypoint, Hostname, IsolationConfig, IsolationPrivilege,
        Namespace, NamespaceSet, plan_rootless_subordinate, spawn_container,
    };
    use fandhe_container_core::rootless::{
        DEFAULT_HELPER_TIMEOUT, HelperPaths, IdMapSet, IdMapWriter, SubIdOwner, WriterKind,
        load_subordinate_ids, rootless_mapping, single_id_mapping,
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

    /// シナリオ全体の期限。scenario 内の各段階の上限（UID・GID 各 1 回の
    /// helper 呼び出しに適用される `DEFAULT_HELPER_TIMEOUT` の 2 回分・子プロセス待ちの
    /// `timeout()`）の合計に、mapper 回収・起動・後始末の余裕として `timeout()` を加える（REPAIR-5）。
    /// `FANDHE_CONTAINER_TEST_TIMEOUT_SECS` が小さくても正常系が打ち切られない。
    fn scenario_deadline() -> Duration {
        DEFAULT_HELPER_TIMEOUT * 2 + timeout() * 2
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
        // exec は `LaunchReady` が作られず拒否されるため、中身は実行されない。
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
        // scenario が holder・mapper・コンテナ PID 1 を残して終わった（kill された）場合に、init ではなく
        // このプロセスへ再親付けさせ、後続の子の照合で見えるようにする（#2436）。
        let _subreaper = ChildSubreaper::enable().expect("enable child subreaper");
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
            let Some(status) = wait_deadline(&mut child, scenario_deadline()) else {
                // 期限超過で kill・回収済み。残った子も回収してから失敗にする。
                leftover_children::assert_no_leftover_children(
                    timeout(),
                    &format!("after scenario {name} was killed at its deadline"),
                );
                panic!("scenario {name} did not exit within the limit");
            };
            // 終了コードの照合や stderr の収集より前に、残存した子（holder・mapper・PID 1）を必ず回収する。
            // 残った子が stderr を継承していると EOF が来ないため、回収が先（#2436・REPAIR-5）。
            let leftover = leftover_children::reap_leftover_children(timeout());
            let mut pipe = child.stderr.take().expect("piped stderr");
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut buf = String::new();
                let r = pipe.read_to_string(&mut buf);
                let _ = tx.send((r, buf));
            });
            // stderr の収集にも期限を設ける。期限切れなら読み取りスレッドは放置して失敗にする。
            let stderr = match rx.recv_timeout(timeout()) {
                Ok((r, buf)) => {
                    r.expect("read scenario stderr");
                    buf
                }
                Err(_) => panic!("scenario {name} stderr did not reach EOF within the limit"),
            };
            assert_eq!(
                status.code(),
                Some(0),
                "scenario {name} must exit with 0; stderr:\n{stderr}"
            );
            if let Some((left, failed)) = leftover {
                panic!(
                    "no child may remain after scenario {name} finished: {left:?} (cleanup failures: {failed:?})"
                );
            }
            // Exec 段への到達（SEC-1・CORE-5: `LaunchReady` が作られず exec だけが拒否される）。
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
        // shadow は subgid の数値の行も gid ではなく uid で照合する（#2390）。
        let gowner = SubIdOwner::new(euid, name).expect("gid owner");
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

        // 写像の外側 ID との照合は mapper 側（`apply_id_maps_to`）が済ませている。分離先からの
        // 読み戻しは lower ID が読み手基準になり外側の ID と直接比較できないため、ここでは
        // namespace 内の ID（第 1 列）だけを具体値で確かめる。
        let map_firsts = |file: &str| -> Vec<String> {
            std::fs::read_to_string(file)
                .unwrap_or_else(|e| panic!("read {file}: {e}"))
                .lines()
                .filter_map(|l| l.split_whitespace().next().map(str::to_owned))
                .collect()
        };
        let want_uid: Vec<String> = uid
            .entries()
            .iter()
            .map(|e| e.container_id.to_string())
            .collect();
        let want_gid: Vec<String> = gid
            .entries()
            .iter()
            .map(|e| e.container_id.to_string())
            .collect();
        assert_eq!(map_firsts("/proc/self/uid_map"), want_uid);
        assert_eq!(map_firsts("/proc/self/gid_map"), want_gid);

        let path = format!("/{ENTRY}");
        let entry = Entrypoint::new(&path, [path.as_str()], [] as [&str; 0]).expect("entrypoint");
        let child =
            spawn_container(rootfs, &entry).unwrap_or_else(|e| panic!("spawn_container: {e}"));
        let exit = child
            .wait_timeout(timeout())
            .unwrap_or_else(|e| panic!("wait: {e}"));
        // `LaunchReady` が作られない経路のため exec だけが拒否される（126）。setup 失敗（125）ではない。
        assert_eq!(exit, ChildExit::Exited(126), "scenario {name}");
    }
}
