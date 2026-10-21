//! rootless コンテナ内 root が作るファイルのホスト側 UID 写像の結合試験（ESC-09 相当。
//! SEC-5・CORE-6・TASK-44・MS-2・#207）。非 root で分離した新 PID namespace の PID 1（コンテナ）が
//! `pivot_root` 後の rootfs 直下へコンテナ内 root としてファイルを作り、分離されていないホスト側
//! ディスパッチャが `stat` で所有者が非特権 UID / GID（写像先。≠ 0）であることを具体値で照合する。
//!
//! # 既存テストとの差別化
//! - `rootless_file_owner`（TASK-40.3）: 実エントリポイントの作成と `chown` の所有者写像を見る。本テストは
//!   加えて PID 1・pivot 済み rootfs であることの証跡（`/` の一覧）と ESC-09 の RESULT 行を見る
//! - `rootless`（TASK-40.4）: ファイルを作らずライフサイクルと `uid_map` を照合する。本テストは所有者（ESC-09）を見る
//! - `pivot_root_isolation`（TASK-27.3）: 所有者を照合しない。本テストは subuid 範囲経路も含む
//!
//! # 受入基準の解釈（REPAIR-3）
//! 起動経路は `StagePipeline::with_landlock` を載せたステージ列（`tests/support/real_entry.rs`。#2012）で、
//! `LaunchReady` がそろうため exec まで到達する。コンテナ PID 1 は実エントリポイント（試験バイナリ自身を
//! rootfs の `/entry` へコピーして `--entry <name>` で再入したもの）で、exec 後に pivot 済み rootfs 直下へ
//! コンテナ内 root としてファイルを作る。実エントリポイントの標準入出力は `/dev/null` へ置換されるため、
//! コンテナ視点の観測値は `/entry-report` へ書き、ホストが具体値で照合する。本番 launcher 経由の確認は
//! `production_launcher`（#1818）が担う。
//!
//! # 流れ（3 段）
//! 1. ディスパッチャ（分離なし）: rootfs（実エントリポイント入り）を作り、`--scenario <name> <rootfs> <LD_LIBRARY_PATH>`
//!    で自身を起動し、終了コード 0 を期限付きで待った後、ホスト視点で所有者を具体値照合する（REPAIR-5）。
//!    あわせて、実エントリポイントが報告した `/` 直下の一覧が、ホストから見た rootfs 直下の一覧（実エントリポイントが
//!    作ったファイルと報告ファイルを除く）と完全一致することを照合する（`/` が rootfs であることの証跡）。root で
//!    実行された場合は、ホスト root への写像が `host_root_identity_mapping` で拒否されること（SEC-5）だけを照合する
//! 2. シナリオ: `plan_rootless_subordinate` → `isolate_rootless_subordinate` の後、`with_landlock` を載せたステージ列で
//!    実エントリポイントを新 PID namespace の PID 1 として起動し、`Exited(0)` を待つ
//! 3. 実エントリポイント（exec 後の PID 1）: `/` 直下の一覧を報告し、`/` 直下にコンテナ内 root としてファイルを作る
//!
//! シナリオ `direct` は `single_id_mapping(euid)`、`helper`（`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ）
//! は `/etc/subuid`・`/etc/subgid` の範囲写像（ns 内 1 → subuid 範囲先頭も確認）。
//!
//! # 実機前提テストとしての分離（ci.md）
//! 必要環境: 非特権 user namespace を許可する Linux。AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1`（Ubuntu 24.04 既定）・`user.max_user_namespaces=0`・
//! Docker 既定 seccomp の開発コンテナ内では `PermissionDenied` 等で失敗する（緩和は root 権限が要り、
//! 人間が TASK-8 環境で行う。実機実行・レポートは #208）。実エントリポイントを exec まで通すため、Landlock ABI 6 以上
//! （Linux 6.12 以上）も必要（満たさないと失敗する）。`-- --ignored` 指定時のみ実行し、未指定時は
//! 「ignored」を出力して成功終了する。実行された場合は拒否を含むあらゆる失敗を失敗として扱い、
//! 検証せずに成功する分岐は持たない。
//! 実行: `cargo test -p fandhe-container-core --test rootless_uid_mapping -- --ignored`

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless_uid_mapping: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
#[path = "support/real_entry.rs"]
mod real_entry;

#[cfg(target_os = "linux")]
fn main() {
    if std::env::args().any(|a| a == "--entry") {
        linux::entry();
    } else if std::env::args().any(|a| a == "--ignored" || a == "--scenario") {
        linux::run();
    } else {
        println!(
            "rootless_uid_mapping: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use super::real_entry;
    use fandhe_container_core::exec::{
        ChildExit, Hostname, IsolationConfig, IsolationPrivilege, Namespace, NamespaceSet,
        isolate_rootless_subordinate, plan_rootless_subordinate,
    };
    use fandhe_container_core::rootless::{
        DEFAULT_HELPER_TIMEOUT, HelperPaths, IdMapSet, IdMapWriter, SubIdOwner, WriterKind,
        load_subordinate_ids, rootless_mapping, single_id_mapping,
    };

    const ROOT_FILE: &str = "esc09-root-created";
    const NS1_FILE: &str = "esc09-ns1-owned";
    const STDERR_LIMIT: u64 = 16 * 1024;

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    /// ディスパッチャがシナリオ全体を待つ期限（helper 呼び出し 2 回分＋起動・後始末の余裕。REPAIR-5）。
    fn scenario_deadline() -> Duration {
        DEFAULT_HELPER_TIMEOUT * 2 + timeout() * 3
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
        if let Some(i) = args.iter().position(|a| a == "--scenario") {
            let name = args.get(i + 1).expect("scenario name after --scenario");
            let rootfs = args.get(i + 2).expect("rootfs after the scenario name");
            let ld = args.get(i + 3).expect("LD_LIBRARY_PATH after the rootfs");
            scenario(name, Path::new(rootfs), ld);
        } else {
            dispatcher();
        }
    }

    /// 一時 rootfs（drop で削除）。
    struct Rootfs(PathBuf);

    impl Drop for Rootfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `proc/` と実エントリポイント（`/entry` とローダ・共有ライブラリ）を持つ rootfs を排他作成（事前配置の
    /// 差し替え防止）する。戻り値は rootfs と、実エントリポイントの `LD_LIBRARY_PATH`。
    fn make_rootfs(label: &str) -> (Rootfs, String) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!(
                "fandhe-rootless-uidmap-{label}-{}-{nanos}",
                std::process::id()
            ));
        std::fs::create_dir(&base).expect("exclusively create rootfs");
        let rootfs = Rootfs(base);
        let ld = real_entry::install_entry(&rootfs.0);
        // rootfs の所有者（= コンテナ内 root）だけが入れればよい。他ユーザーによる差し替えを防ぐ（SEC-5）。
        std::fs::set_permissions(&rootfs.0, std::fs::Permissions::from_mode(0o700))
            .expect("chmod rootfs");
        (rootfs, ld)
    }

    /// 子を期限付きで待つ。期限超過なら kill して回収し `None`（REPAIR-5）。
    fn wait_deadline(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
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

    /// 自身を指定引数で再起動し、期限付きで待って終了状態と stderr（上限付き）を返す。
    fn spawn_and_wait(
        args: &[&str],
        rootfs: &Path,
        ld: &str,
        limit: Duration,
    ) -> (Option<ExitStatus>, String) {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = Command::new(exe)
            .args(args)
            .arg(rootfs)
            .arg(ld)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn child");
        let status = wait_deadline(&mut child, limit);
        let mut stderr = String::new();
        let _ = child
            .stderr
            .take()
            .expect("piped stderr")
            .take(STDERR_LIMIT)
            .read_to_string(&mut stderr);
        (status, stderr)
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
            println!("rootless_uid_mapping: host root launch rejected (SEC-5, root=true)");
            return;
        }
        let mut names = vec!["direct"];
        if helper_requested() {
            names.push("helper");
        } else {
            println!(
                "rootless_uid_mapping: helper case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1)"
            );
        }
        for name in names {
            let (rootfs, ld) = make_rootfs(name);
            let (status, stderr) =
                spawn_and_wait(&["--scenario", name], &rootfs.0, &ld, scenario_deadline());
            let status =
                status.unwrap_or_else(|| panic!("scenario {name} did not exit within the limit"));
            assert_eq!(
                status.code(),
                Some(0),
                "scenario {name} must exit with 0; stderr:\n{stderr}"
            );

            // ホスト視点（分離されていないこのプロセス）での所有者照合。期待値は写像を独立に再計算する。
            let (want_uid, want_gid, ns1) = if name == "direct" {
                let u = single_id_mapping(euid).expect("uid mapping");
                let g = single_id_mapping(egid).expect("gid mapping");
                (
                    u.host_id_of(0).expect("uid 0 mapped"),
                    g.host_id_of(0).expect("gid 0 mapped"),
                    None,
                )
            } else {
                let (u, g) = helper_mappings(euid, egid);
                (
                    u.host_id_of(0).expect("uid 0 mapped"),
                    g.host_id_of(0).expect("gid 0 mapped"),
                    Some((
                        u.host_id_of(1).expect("uid 1 mapped"),
                        g.host_id_of(1).expect("gid 1 mapped"),
                    )),
                )
            };
            // 実エントリポイントの報告（exec 後のコンテナ視点）。
            let report =
                real_entry::read_report(&rootfs.0.join(real_entry::REPORT_FILE), timeout());
            let field = |k: &str| report.get(k).map(String::as_str).unwrap_or("missing");
            assert_eq!(
                field("pid"),
                "1",
                "scenario {name}: real entrypoint is PID 1"
            );
            assert_eq!(field("uid"), "0", "scenario {name}: container uid");
            assert_eq!(field("gid"), "0", "scenario {name}: container gid");
            assert_eq!(field("nonewprivs"), "1", "scenario {name}: NoNewPrivs");
            assert_eq!(
                field("seccomp"),
                "2",
                "scenario {name}: Seccomp filter mode"
            );
            assert_eq!(
                field("root_owner"),
                "0:0",
                "scenario {name}: container view"
            );
            if ns1.is_some() {
                assert_eq!(field("ns1_owner"), "1:1", "scenario {name}: ns 1 view");
            }
            // `/` が rootfs であることの証跡: 実エントリポイントが見た `/` 直下 = ホストから見た rootfs 直下
            // （実エントリポイントが後から作ったファイルと報告ファイルを除く）。
            let mut host_entries: Vec<String> = std::fs::read_dir(&rootfs.0)
                .expect("read rootfs")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .filter(|n| ![ROOT_FILE, NS1_FILE, real_entry::REPORT_FILE].contains(&n.as_str()))
                .collect();
            host_entries.sort();
            assert_eq!(
                field("root_entries"),
                host_entries.join(","),
                "scenario {name}: the entrypoint's / must be the rootfs"
            );
            let meta = std::fs::metadata(rootfs.0.join(ROOT_FILE)).expect("stat root-created");
            assert_eq!(meta.uid(), want_uid, "scenario {name}: host uid");
            assert_eq!(meta.gid(), want_gid, "scenario {name}: host gid");
            assert_eq!(meta.uid(), euid, "scenario {name}: root maps to the user");
            assert_eq!(meta.gid(), egid, "scenario {name}: root maps to the group");
            assert_ne!(meta.uid(), 0, "scenario {name}: not owned by host root");
            assert_ne!(
                meta.gid(),
                0,
                "scenario {name}: not group-owned by host root"
            );
            if let Some((cu, cg)) = ns1 {
                let m = std::fs::metadata(rootfs.0.join(NS1_FILE)).expect("stat ns1-owned");
                assert_eq!(m.uid(), cu, "scenario {name}: host uid of ns uid 1");
                assert_eq!(m.gid(), cg, "scenario {name}: host gid of ns gid 1");
                assert_ne!(m.uid(), 0, "scenario {name}: ns 1 not host root");
                assert_ne!(m.gid(), 0, "scenario {name}: ns 1 not host root group");
            }
            println!(
                "rootless_uid_mapping: scenario {name} verified (host uid={}, gid={})",
                meta.uid(),
                meta.gid()
            );
            println!(
                "rootless_uid_mapping: RESULT scenario={name} behavior=SEC-5,CORE-6,ESC-09 container_uid=0 \
                 expected_host_uid={want_uid} host_uid={} expected_host_gid={want_gid} host_gid={} verdict=pass",
                meta.uid(),
                meta.gid()
            );
        }
    }

    /// 分離 → `with_landlock` を載せて実エントリポイントを PID 1 として起動し、`Exited(0)` を待つ。
    /// 拒否を含むあらゆる失敗は panic（失敗）。
    fn scenario(name: &str, rootfs: &Path, ld: &str) {
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
        let report =
            isolate_rootless_subordinate(&plan).unwrap_or_else(|e| panic!("isolate failed: {e}"));
        assert_eq!(
            report.isolation.privilege,
            IsolationPrivilege::RootlessSubordinateIds
        );
        assert_eq!(report.id_maps.writer, want_kind);
        assert_eq!(report.id_maps.uid, uid);
        assert_eq!(report.id_maps.gid, gid);
        assert_eq!(
            own_ids(),
            (0, 0),
            "scenario {name}: must be uid/gid 0 in the ns"
        );

        let entry =
            real_entry::entrypoint_from(&real_entry::entry_args(name), &real_entry::entry_env(ld));
        let child = real_entry::spawn_real_entry(rootfs, &entry, &gid);
        let exit = child
            .wait_timeout(scenario_deadline())
            .unwrap_or_else(|e| panic!("wait: {e}"));
        assert_eq!(
            exit,
            ChildExit::Exited(0),
            "scenario {name}: the real entrypoint must create the files and exit 0"
        );
    }

    /// 実エントリポイント（exec 後のコンテナ PID 1。REPAIR-3）。`/` 直下の一覧を報告し、コンテナ内 root として
    /// `/` 直下へファイルを作る。失敗は値（`error:<kind>`）として記録し、終了コードは全操作が成功したときだけ 0 にする。
    pub fn entry() {
        let args: Vec<String> = std::env::args().collect();
        let name = args
            .iter()
            .position(|a| a == "--entry")
            .and_then(|i| args.get(i + 1))
            .expect("mode after --entry")
            .clone();
        let mut lines = real_entry::entry_observations();
        let mut ok = true;
        // 作成前の `/` 直下の一覧（報告ファイル・作成物を含まない）。
        let mut names: Vec<String> = match std::fs::read_dir("/") {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => {
                ok = false;
                Vec::new()
            }
        };
        names.sort();
        lines.push(("root_entries", names.join(",")));
        let mut create = |file: &str, key: &'static str, chown: bool| -> (&'static str, String) {
            let path = Path::new("/").join(file);
            let made = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .and_then(|mut f| f.write_all(b"owner\n"))
                .and_then(|()| {
                    if chown {
                        std::os::unix::fs::chown(&path, Some(1), Some(1))
                    } else {
                        Ok(())
                    }
                })
                .and_then(|()| std::fs::metadata(&path));
            match made {
                Ok(m) => (key, format!("{}:{}", m.uid(), m.gid())),
                Err(e) => {
                    ok = false;
                    (key, format!("error:{:?}", e.kind()))
                }
            }
        };
        let root = create(ROOT_FILE, "root_owner", false);
        let ns1 = (name == "helper").then(|| create(NS1_FILE, "ns1_owner", true));
        lines.push(root);
        lines.extend(ns1);
        real_entry::write_report(&lines);
        std::process::exit(if ok { 0 } else { 1 });
    }
}
