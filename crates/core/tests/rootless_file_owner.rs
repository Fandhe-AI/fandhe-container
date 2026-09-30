//! rootless 起動フローでコンテナ内 root が作るファイルの所有者写像の結合試験
//! （CORE-6・SEC-5・TASK-40.3・#189）。コンテナ内 uid 0 で作成したファイルが、ホスト側から見て
//! 写像先の非特権 UID（≠ 0）の所有になることを `stat` で照合する。
//!
//! libtest はマルチスレッドで、マルチスレッドからの `CLONE_NEWUSER`・fork は拒否されるため
//! `harness = false` の単一スレッド `main` で動かす（`rootless_launch` と同じ理由）。非 Linux では
//! `rootless` / `exec` モジュール自体がビルド対象外（OS 非該当であり skip ではない）。
//!
//! # 受入基準の解釈（REPAIR-3）
//! 制限ステージ（seccomp・Landlock 等。TASK-38・TASK-39）が未実装の間、`exec_entrypoint` は rootless でも
//! exec を拒否するため、エントリポイントにファイルを作らせることはできない（exec 到達は
//! `rootless_launch` が照合済み）。ファイル所有者はプロセスの user namespace 写像だけで決まるので、
//! `isolate_rootless_subordinate` 成功後のシナリオプロセス（コンテナの user namespace 内 uid 0）が
//! ファイルを作成し、分離されていない外側のディスパッチャ（ホスト視点）が `stat` で所有者を照合する。
//! exec が許可された後（TASK-38・TASK-39 以降）は、エントリポイント内での作成へ移せる。
//!
//! # 流れ
//! - ディスパッチャ: 作業ディレクトリを作り、自身を `--scenario <name> <dir>` で再起動して
//!   タイムアウト付きで終了コード 0 を待った後、作成されたファイルの所有者をホスト視点で具体値照合する
//!   （REPAIR-5）。root で実行された場合は、ホスト root への写像が `host_root_identity_mapping` で
//!   拒否されること（SEC-5）だけを照合する
//! - シナリオ `direct`: `single_id_mapping(euid)`。ns 内 uid 0 が作ったファイルはホスト側で euid・egid 所有
//! - シナリオ `helper`（`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ）: `/etc/subuid`・`/etc/subgid` の
//!   範囲写像。ns 内 0 → euid、ns 内 1 → subuid 範囲の先頭（いずれも ≠ 0）
//!
//! # 実機前提テストとしての分離
//! 非特権 user namespace を許可するホストが必要（AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1` 等では `PermissionDenied`）。`-- --ignored` 指定時のみ
//! 実行し、未指定時は「ignored」を出力して成功終了する（ci.md「実機前提テスト」）。CI の
//! `integration-test` への組み込みは別 PR。実行された場合は拒否を含むあらゆる失敗を失敗として扱い、
//! 検証せずに成功する分岐は持たない。helper ケースは env の opt-in 時のみ実行し、opt-in 時に前提
//! （uidmap・subuid/subgid 行）が無ければ失敗とする。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless_file_owner: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--ignored" || a == "--scenario") {
        linux::run();
    } else {
        println!(
            "rootless_file_owner: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::exec::{
        Hostname, IsolationConfig, IsolationPrivilege, Namespace, NamespaceSet,
        plan_rootless_subordinate,
    };
    use fandhe_container_core::rootless::{
        DEFAULT_HELPER_TIMEOUT, HelperPaths, IdMapSet, IdMapWriter, SubIdOwner, WriterKind,
        load_subordinate_ids, rootless_mapping, single_id_mapping,
    };

    const ROOT_FILE: &str = "root-created";
    const CHOWNED_FILE: &str = "chowned";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    /// シナリオ全体の期限（UID・GID 各 1 回の helper 呼び出し 2 回分に、起動・後始末の余裕を加える。REPAIR-5）。
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
                let dir = args.get(i + 2).expect("work dir after the scenario name");
                scenario(name, Path::new(dir));
            }
            None => dispatcher(),
        }
    }

    /// 一時作業ディレクトリ（drop で削除）。
    struct WorkDir(PathBuf);

    impl Drop for WorkDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// 共有 temp 配下の予測可能な名前への事前配置を防ぐため `mkdir`（排他）で作る。
    /// ファイルは各所で `create_new`（`O_EXCL`）で作る。
    fn make_workdir(label: &str) -> WorkDir {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!(
                "fandhe-rootless-owner-{label}-{}-{nanos}",
                std::process::id()
            ));
        std::fs::create_dir(&base).expect("exclusively create work dir");
        let dir = WorkDir(base);
        // 写像先 UID のコンテナ内 root が書けるよう、他者書き込み可にする。
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o777))
            .expect("chmod work dir");
        dir
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

    /// 期待するホスト側所有者。ディスパッチャ側で写像を独立に再計算して得る。
    struct Expected {
        root_uid: u32,
        root_gid: u32,
        /// helper のみ: ns 内 1 の写像先（subuid / subgid 範囲の先頭）。
        chowned: Option<(u32, u32)>,
    }

    fn expected(name: &str, euid: u32, egid: u32) -> Expected {
        match name {
            "direct" => {
                let u = single_id_mapping(euid).expect("uid mapping");
                let g = single_id_mapping(egid).expect("gid mapping");
                Expected {
                    root_uid: u.host_id_of(0).expect("uid 0 mapped"),
                    root_gid: g.host_id_of(0).expect("gid 0 mapped"),
                    chowned: None,
                }
            }
            "helper" => {
                let (u, g) = helper_mappings(euid, egid);
                Expected {
                    root_uid: u.host_id_of(0).expect("uid 0 mapped"),
                    root_gid: g.host_id_of(0).expect("gid 0 mapped"),
                    chowned: Some((
                        u.host_id_of(1).expect("uid 1 mapped"),
                        g.host_id_of(1).expect("gid 1 mapped"),
                    )),
                }
            }
            other => panic!("unknown scenario {other}"),
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
            println!("rootless_file_owner: host root launch rejected (SEC-5, root=true)");
            return;
        }
        let mut names = vec!["direct"];
        if helper_requested() {
            names.push("helper");
        } else {
            println!(
                "rootless_file_owner: helper case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1)"
            );
        }
        let exe = std::env::current_exe().expect("current_exe");
        for name in names {
            let dir = make_workdir(name);
            let mut child = Command::new(&exe)
                .args(["--scenario", name])
                .arg(&dir.0)
                .stdin(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn scenario");
            let status = wait_deadline(&mut child, scenario_deadline())
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

            // ホスト視点（分離されていないこのプロセス）での所有者照合（SEC-5）。
            let want = expected(name, euid, egid);
            let meta = std::fs::metadata(dir.0.join(ROOT_FILE)).expect("stat root-created");
            assert_eq!(meta.uid(), want.root_uid, "scenario {name}: host uid");
            assert_eq!(meta.gid(), want.root_gid, "scenario {name}: host gid");
            assert_eq!(meta.uid(), euid, "scenario {name}: root maps to the user");
            assert_eq!(meta.gid(), egid, "scenario {name}: root maps to the group");
            assert_ne!(meta.uid(), 0, "scenario {name}: not owned by host root");
            assert_ne!(
                meta.gid(),
                0,
                "scenario {name}: not group-owned by host root"
            );
            if let Some((cu, cg)) = want.chowned {
                let m = std::fs::metadata(dir.0.join(CHOWNED_FILE)).expect("stat chowned");
                assert_eq!(m.uid(), cu, "scenario {name}: host uid of ns uid 1");
                assert_eq!(m.gid(), cg, "scenario {name}: host gid of ns gid 1");
                assert_ne!(m.uid(), 0);
                assert_ne!(m.gid(), 0);
            }
            println!(
                "rootless_file_owner: scenario {name} verified (host uid={}, gid={})",
                meta.uid(),
                meta.gid()
            );
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

    /// 分離 → コンテナ内 root としてファイル作成。拒否を含むあらゆる失敗は panic（失敗）。
    /// 所有者のホスト視点での照合は外側のディスパッチャが行う。
    fn scenario(name: &str, dir: &Path) {
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

        // コンテナ内 root であること。
        assert_eq!(
            own_ids(),
            (0, 0),
            "scenario {name}: must be uid/gid 0 in the ns"
        );

        let root_path = dir.join(ROOT_FILE);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&root_path)
            .expect("create root-created");
        f.write_all(b"owner\n").expect("write root-created");
        // コンテナ視点では ns 内 0 所有に見える。
        let m = std::fs::metadata(&root_path).expect("stat root-created");
        assert_eq!(
            (m.uid(), m.gid()),
            (0, 0),
            "scenario {name}: container view"
        );

        if name == "helper" {
            let p = dir.join(CHOWNED_FILE);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&p)
                .expect("create chowned");
            std::os::unix::fs::chown(&p, Some(1), Some(1)).expect("chown to ns uid/gid 1");
            let m = std::fs::metadata(&p).expect("stat chowned");
            assert_eq!((m.uid(), m.gid()), (1, 1), "scenario {name}: ns 1 view");
        }
    }
}
