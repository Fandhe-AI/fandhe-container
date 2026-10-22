//! rootless コンテナ内 root が作るファイルのホスト側 UID 写像の結合試験（ESC-09 相当。
//! SEC-5・CORE-6・TASK-44・MS-2・#207・#2391）。非 root で分離した新 PID namespace の PID 1（コンテナ）が
//! `pivot_root` 後の rootfs 直下へコンテナ内 root としてファイルを作り、分離されていないホスト側
//! ディスパッチャが `stat` で所有者が非特権 UID / GID（写像先。≠ 0）であることを具体値で照合する。
//!
//! 起動は本番 `oci_runtime::ProductionLauncher` と `FileStateStore` の `create` → `start` で行う（#2391）。
//! `harness = false` の単一スレッド `main` で動かすのは、`ProductionLauncher` が単一スレッドのプロセスだけを
//! 受け付ける（マルチスレッドからの `CLONE_NEWUSER`・fork は拒否される）ためで、`rootless_file_owner` と同じ理由である。
//!
//! # 既存テストとの差別化
//! - `rootless_file_owner`（TASK-40.3）: 実エントリポイントの作成と `chown` の所有者写像を見る。本テストは
//!   加えて PID 1・pivot 済み rootfs であることの証跡（`/` の一覧）・`NoNewPrivs`・`Seccomp`・launch が記録した
//!   ID 写像（`launch_isolation().id_mapping()`）と ESC-09 の RESULT 行を見る
//! - `rootless`（TASK-40.4）: ファイルを作らずライフサイクルと `uid_map` を照合する。本テストは所有者（ESC-09）を見る
//! - `pivot_root_isolation`（TASK-27.3）: 所有者を照合しない。本テストは subuid 範囲経路も含む
//!
//! # 受入基準の解釈（REPAIR-3）
//! 起動経路は本番 launcher の `StagePipeline`（`with_landlock` 入り。`LaunchReady` がそろうため exec まで到達する）。
//! コンテナ PID 1 は実エントリポイント（試験バイナリ自身を rootfs の `/entry` へコピーして `--entry <name>` で
//! 再入したもの。`tests/support/real_entry.rs`）で、exec 後に pivot 済み rootfs 直下へコンテナ内 root として
//! ファイルを作る。実エントリポイントの標準入出力は `/dev/null` へ置換されるため、コンテナ視点の観測値は
//! `/entry-report` へ書き、ホストが具体値で照合する。範囲写像（`RootlessSubordinateIds`）は本番 launcher の
//! `SubordinateIdSource` 経路を通る（#2009）。cgroup の委譲は要らない（config に `linux.resources`・`cgroupsPath` を置かない）。
//!
//! # 流れ（2 段）
//! 1. ディスパッチャ（分離なし）: 一時 bundle（`config.json`・`rootfs/`〔実エントリポイント入り〕・状態ルート）を
//!    排他的に作り、本番 launcher で `create` → `start` し、起動記録が Running で、`launch_isolation` の `/` の
//!    `(dev, ino)` が rootfs と一致し、`id_mapping`（モデルと uid・gid の写像行）が写像を独立に計算し直した期待値と
//!    完全一致することを照合する。続けて `wait` の `Exited(0)`（期限つき。REPAIR-5）を待ち、実エントリポイントが報告した
//!    `/` 直下の一覧がホストから見た rootfs 直下の一覧（実エントリポイントが作ったファイルと報告ファイルを除く）と
//!    完全一致すること（`/` が rootfs である証跡）と、ホスト視点の所有者を具体値照合する。起動済みの PID 1 は成否に
//!    関わらず `terminate` で回収する。root で実行された場合は、ホスト root への写像が `host_root_identity_mapping` で
//!    拒否されることと、範囲写像の launcher の構築が `PermissionDenied` で拒否されること（SEC-5）だけを照合する
//! 2. 実エントリポイント（exec 後の PID 1）: `/` 直下の一覧を報告し、`/` 直下にコンテナ内 root としてファイルを作る
//!
//! ケース `direct`（`RootlessSingleId`）は `single_id_mapping(euid)`、`helper`（`FANDHE_CONTAINER_TEST_ID_HELPER=1`
//! の時だけ。`RootlessSubordinateIds`）は `/etc/subuid`・`/etc/subgid` の範囲写像（ns 内 1 → subuid 範囲先頭も確認）。
//!
//! # 実機前提テストとしての分離（ci.md）
//! 必要環境: 非特権 user namespace を許可する Linux。AppArmor の
//! `kernel.apparmor_restrict_unprivileged_userns=1`（Ubuntu 24.04 既定）・`user.max_user_namespaces=0`・
//! Docker 既定 seccomp の開発コンテナ内では `PermissionDenied` 等で失敗する（緩和は root 権限が要り、
//! 人間が TASK-8 環境で行う。実機実行・レポートは #208）。実エントリポイントを exec まで通すため、Landlock ABI 6 以上
//! （Linux 6.12 以上）も必要（満たさないと失敗する）。`-- --ignored` 指定時のみ実行し、未指定時は
//! 「ignored」を出力して成功終了する。実行された場合は拒否を含むあらゆる失敗を失敗として扱い、
//! 検証せずに成功する分岐は持たない。helper ケースは env の opt-in 時のみ実行し、opt-in 時に前提
//! （uidmap・subuid/subgid 行）が無ければ失敗とする。CI の `platform-ci` への組み込みは未実施（別 PR）。
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
    } else if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "rootless_uid_mapping: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::real_entry;
    use fandhe_container_core::exec::{
        Hostname, IsolationConfig, Namespace, NamespaceSet, plan_rootless_subordinate,
    };
    use fandhe_container_core::launch_isolation::{RecordedIdExtent, RecordedIdModel};
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        ProcessExit, START_TIMEOUT_MAX, StartTimeouts, create, start,
    };
    use fandhe_container_core::rootless::{
        DEFAULT_HELPER_TIMEOUT, IdMapSet, IdMapWriter, single_id_mapping,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, ErrorCode, StartRequest,
    };

    const ROOT_FILE: &str = "esc09-root-created";
    const NS1_FILE: &str = "esc09-ns1-owned";
    const HOSTNAME: &str = "fandhe-rootless";

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=600).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    /// 起動ハンドルの `wait` の期限（UID・GID 各 1 回の helper 呼び出し 2 回分に、起動・後始末の余裕を加える。REPAIR-5）。
    fn scenario_deadline() -> Duration {
        DEFAULT_HELPER_TIMEOUT * 2 + timeout() * 3
    }

    /// `start` 全体の上限。`scenario_deadline` と同じ式にし、`StartTimeouts` の上限（`START_TIMEOUT_MAX`）以下へ丸める。
    fn start_timeouts() -> StartTimeouts {
        let limit = scenario_deadline().min(START_TIMEOUT_MAX);
        StartTimeouts::new(limit, timeout(), timeout()).expect("start timeouts")
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

    /// root 実行時の拒否の照合に使う分離設定（`plan_rootless_subordinate` の入力）。
    fn config() -> IsolationConfig {
        IsolationConfig {
            namespaces: NamespaceSet::empty()
                .with(Namespace::Pid)
                .with(Namespace::Mount)
                .with(Namespace::Uts)
                .with(Namespace::Ipc)
                .with(Namespace::User),
            hostname: Some(Hostname::new(HOSTNAME).expect("hostname")),
        }
    }

    pub fn run() {
        dispatcher();
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
                "fandhe-rootless-uidmap-{label}-{}-{nanos}",
                std::process::id()
            ));
        std::fs::create_dir(&base).expect("exclusively create work dir");
        let dir = WorkDir(base);
        // bundle の所有者（= コンテナ内 root）だけが入れればよい。他ユーザーによる差し替えを防ぐ（SEC-5）。
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700))
            .expect("chmod work dir");
        dir
    }

    /// 期待するホスト側所有者と ID 写像。ディスパッチャ側で写像を独立に再計算して得る。
    struct Expected {
        root_uid: u32,
        root_gid: u32,
        /// helper のみ: ns 内 1 の写像先（subuid / subgid 範囲の先頭）。
        ns1: Option<(u32, u32)>,
        model: RecordedIdModel,
        uid_extents: Vec<RecordedIdExtent>,
        gid_extents: Vec<RecordedIdExtent>,
    }

    /// 写像行を launch の記録（`RecordedIdExtent`）と同じ形へ直す。
    fn extents(set: &IdMapSet) -> Vec<RecordedIdExtent> {
        set.entries()
            .iter()
            .map(|e| RecordedIdExtent {
                container_id: e.container_id,
                host_id: e.host_id,
                size: e.count,
            })
            .collect()
    }

    fn expected(name: &str, euid: u32, egid: u32) -> Expected {
        match name {
            "direct" => {
                let u = single_id_mapping(euid).expect("uid mapping");
                let g = single_id_mapping(egid).expect("gid mapping");
                Expected {
                    root_uid: u.host_id_of(0).expect("uid 0 mapped"),
                    root_gid: g.host_id_of(0).expect("gid 0 mapped"),
                    ns1: None,
                    model: RecordedIdModel::Single,
                    uid_extents: extents(&u),
                    gid_extents: extents(&g),
                }
            }
            "helper" => {
                let (u, g) = real_entry::helper_mappings(euid, egid);
                Expected {
                    root_uid: u.host_id_of(0).expect("uid 0 mapped"),
                    root_gid: g.host_id_of(0).expect("gid 0 mapped"),
                    ns1: Some((
                        u.host_id_of(1).expect("uid 1 mapped"),
                        g.host_id_of(1).expect("gid 1 mapped"),
                    )),
                    model: RecordedIdModel::Subordinate,
                    uid_extents: extents(&u),
                    gid_extents: extents(&g),
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
            // 本番経路でも、root での範囲写像の launcher の構築が拒否される（SEC-5・#2009）。
            let refused = real_entry::build_rootless_launcher(true)
                .expect_err("root must be refused for the subordinate-id launcher");
            assert_eq!(refused.code(), ErrorCode::PermissionDenied);
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
            run_case(name, euid, egid);
        }
    }

    /// 1 ケース分: bundle を作り、本番 launcher で `create` → `start` し、記録と `Exited(0)` と所有者を照合する。
    /// 起動済みのプロセスは成否に関わらず `terminate` して回収する（`LaunchedProcess` は Drop で終了・回収しないため、
    /// ここで回収しないと実機に PID 1 が残る）。
    fn run_case(name: &'static str, euid: u32, egid: u32) {
        let dir = make_workdir(name);
        let rootfs = dir.0.join("rootfs");
        let ld = real_entry::install_entry(&rootfs);
        real_entry::write_rootless_config(
            &dir.0,
            HOSTNAME,
            &real_entry::entry_args(name),
            &real_entry::entry_env(&ld),
        );
        let store = FileStateStore::open(
            StateRoot::from_override(dir.0.join("state")).expect("state root"),
        )
        .expect("open state store");
        let recorder = OpRecorder::new();
        let id = ContainerId::new(format!("rum{name}{}", std::process::id())).expect("id");
        create(
            &store,
            &recorder,
            &CreateRequest::new(id.clone(), dir.0.clone()).expect("absolute bundle"),
        )
        .expect("create");
        let launcher = real_entry::rootless_launcher(name == "helper");

        real_entry::wait_single_thread();
        let started = start(
            &store,
            &recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &start_timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));

        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(
                started.record().status().state(),
                ContainerState::Running,
                "scenario {name}: start must record Running"
            );
            // launch 時の分離の記録（SUP-6・SEC-1）。`/` の識別子は rootfs ディレクトリの (dev, ino) と一致する。
            let iso = started
                .record()
                .launch_isolation()
                .unwrap_or_else(|| panic!("scenario {name}: launch_isolation must be recorded"));
            let root_meta = std::fs::metadata(&rootfs).expect("stat rootfs");
            assert_eq!(iso.root().dev(), root_meta.dev(), "scenario {name}: dev");
            assert_eq!(iso.root().ino(), root_meta.ino(), "scenario {name}: ino");
            // launch が実際に使った ID 写像の記録（CORE-6・SEC-5・#2388）を、独立に計算し直した写像と照合する。
            let want = expected(name, euid, egid);
            let mapping = iso
                .id_mapping()
                .unwrap_or_else(|| panic!("scenario {name}: id_mapping must be recorded"));
            assert_eq!(mapping.model(), want.model, "scenario {name}: id model");
            assert_eq!(
                mapping.uid(),
                want.uid_extents.as_slice(),
                "scenario {name}: uid extents"
            );
            assert_eq!(
                mapping.gid(),
                want.gid_extents.as_slice(),
                "scenario {name}: gid extents"
            );

            let exit = started
                .process()
                .wait(scenario_deadline())
                .unwrap_or_else(|e| panic!("scenario {name}: wait: {e:?}"));
            assert_eq!(
                exit,
                Some(ProcessExit::Exited(0)),
                "scenario {name}: the real entrypoint must create the files and exit 0 within the limit"
            );
            verify(name, euid, egid, &rootfs, &want);
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            // 検証側の panic を優先する。terminate の失敗で元の panic を覆い隠さない。
            if let Err(e) = &terminated {
                eprintln!(
                    "rootless_uid_mapping: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
    }

    /// ホスト視点（分離されていないこのプロセス）での照合（SEC-5・ESC-09）。
    fn verify(name: &str, euid: u32, egid: u32, rootfs: &Path, want: &Expected) {
        let (want_uid, want_gid) = (want.root_uid, want.root_gid);
        // 実エントリポイントの報告（exec 後のコンテナ視点）。
        let report = real_entry::read_report(&rootfs.join(real_entry::REPORT_FILE), timeout());
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
        if want.ns1.is_some() {
            assert_eq!(field("ns1_owner"), "1:1", "scenario {name}: ns 1 view");
        }
        // `/` が rootfs であることの証跡: 実エントリポイントが見た `/` 直下 = ホストから見た rootfs 直下
        // （実エントリポイントが後から作ったファイルと報告ファイルを除く）。
        let mut host_entries: Vec<String> = std::fs::read_dir(rootfs)
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
        let meta = std::fs::metadata(rootfs.join(ROOT_FILE)).expect("stat root-created");
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
        if let Some((cu, cg)) = want.ns1 {
            let m = std::fs::metadata(rootfs.join(NS1_FILE)).expect("stat ns1-owned");
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
