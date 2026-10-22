//! rootless 起動フローでコンテナ内 root が作るファイルの所有者写像の結合試験
//! （CORE-6・SEC-5・TASK-40.3・#189・#2246）。コンテナ内 uid 0 で作成したファイルが、ホスト側から見て
//! 写像先の非特権 UID（≠ 0）の所有になることを `stat` で照合する。
//!
//! 起動は本番 `oci_runtime::ProductionLauncher`（`create` → `start`）で行う。`harness = false` の単一スレッド
//! `main` で動かすのは、`ProductionLauncher` が単一スレッドのプロセスだけを受け付ける（マルチスレッドからの
//! `CLONE_NEWUSER`・fork は拒否される）ためで、`rootless_launch` と同じ理由である。非 Linux では
//! `rootless` / `exec` モジュール自体がビルド対象外（OS 非該当であり skip ではない）。
//!
//! # 受入基準の解釈（REPAIR-3）
//! 起動経路は本番 launcher の `StagePipeline`（`with_landlock` 入り。`LaunchReady` がそろうため exec まで到達する）。
//! コンテナ PID 1 として exec された実エントリポイント（試験バイナリ自身を rootfs の `/entry` へコピーして
//! `--entry <name>` で再入したもの。`tests/support/real_entry.rs`）がコンテナ内 uid 0 でファイルを作り、
//! 分離されていない外側のディスパッチャ（ホスト視点）が `stat` で所有者を照合する。
//! 実エントリポイントの標準入出力は `/dev/null` へ置換されるため、コンテナ視点の観測値は `/entry-report` へ書く。
//! 範囲写像（`RootlessSubordinateIds`）は本番 launcher の `SubordinateIdSource` 経路を通る（#2009）。
//!
//! `rootless_uid_mapping`（ESC-09）との違い: 本試験は作成と `chown` の所有者写像を、ホスト上の bundle 配下の
//! rootfs で照合する。`rootless_uid_mapping` は PID 1・pivot 済み rootfs であることの証跡（`/` の一覧）・`id_mapping` の記録と RESULT 行を見る
//! （こちらも本番 launcher 経由。#2391）。
//!
//! # 流れ
//! - ディスパッチャ: 一時 bundle（`config.json`・`rootfs/`〔実エントリポイント入り〕・状態ルート）を排他的に作り、
//!   `FileStateStore` と本番 launcher で `create` → `start` を行い、起動ハンドルの `wait` が `Exited(0)`（REPAIR-5 の
//!   期限つき）になることと、`start` の返した記録が Running で `launch_isolation` を持ち `/` の `(dev, ino)` が rootfs と
//!   一致することを照合する。続けて `/entry-report` の `pid=1`・`uid=0`・`gid=0`・コンテナ視点の所有者と、作成された
//!   ファイルの所有者をホスト視点で具体値照合する。root で実行された場合は、ホスト root への写像が
//!   `host_root_identity_mapping` で拒否されること（SEC-5）と、本番経路の `RootlessSubordinateIds` の構築が
//!   `PermissionDenied` で拒否されることだけを照合する
//! - 実エントリポイント（`--entry <name>`）: `/root-created` を作る。helper では `/chowned` を作って `chown(1, 1)` する
//!   （exec 後も OCI 既定の `CAP_CHOWN` が残ることの実証を兼ねる）
//! - ケース `direct`（`RootlessSingleId`）: ns 内 uid 0 が作ったファイルはホスト側で euid・egid 所有
//! - ケース `helper`（`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ。`RootlessSubordinateIds`）: `/etc/subuid`・
//!   `/etc/subgid` の範囲写像。ns 内 0 → euid、ns 内 1 → subuid 範囲の先頭（いずれも ≠ 0）。期待値は launcher と
//!   同じく subuid・subgid の両方を euid（と `USER`）の所有者で引く
//!
//! # 実機前提テストとしての分離
//! 非特権 user namespace を許可するホスト（AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1` 等では
//! `PermissionDenied`）と、Landlock ABI 6 以上（Linux 6.12 以上。実エントリポイントを exec まで通すため）が必要。
//! cgroup の委譲は要らない（config に `linux.resources`・`cgroupsPath` を置かないため launcher は cgroup へ参加しない）。
//! `-- --ignored` 指定時のみ実行し、未指定時は「ignored」を出力して成功終了する（ci.md「実機前提テスト」）。CI の
//! `platform-ci` への組み込みは別 PR。実行された場合は拒否を含むあらゆる失敗を失敗として扱い、
//! 検証せずに成功する分岐は持たない。helper ケースは env の opt-in 時のみ実行し、opt-in 時に前提
//! （uidmap・subuid/subgid 行）が無ければ失敗とする。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless_file_owner: Linux only, not applicable on this OS");
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
            "rootless_file_owner: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
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
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        ProcessExit, START_TIMEOUT_MAX, StartTimeouts, create, start,
    };
    use fandhe_container_core::rootless::{DEFAULT_HELPER_TIMEOUT, IdMapWriter, single_id_mapping};
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, ErrorCode, StartRequest,
    };

    const ROOT_FILE: &str = "root-created";
    const CHOWNED_FILE: &str = "chowned";
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
        DEFAULT_HELPER_TIMEOUT * 2 + timeout() * 2
    }

    /// `start` 全体の上限。helper の写像では中間プロセスが `2 × helper_timeout + 1` 秒待つため
    /// `scenario_deadline` と同じ式にし、`StartTimeouts` の上限（`START_TIMEOUT_MAX`）以下へ丸める。
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
                "fandhe-rootless-owner-{label}-{}-{nanos}",
                std::process::id()
            ));
        std::fs::create_dir(&base).expect("exclusively create work dir");
        let dir = WorkDir(base);
        // ns 内 uid 0 は呼び出し元 euid に写像され、ディレクトリも同 euid の作成物なので
        // 所有者のみ（0o700）で足りる。他ユーザーによる検証対象の差し替えを防ぐ（SEC-5）。
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700))
            .expect("chmod work dir");
        dir
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
                let (u, g) = real_entry::helper_mappings(euid, egid);
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
            // 本番経路でも、root での範囲写像の launcher の構築が拒否される（SEC-5・#2009）。
            let refused = real_entry::build_rootless_launcher(true)
                .expect_err("root must be refused for the subordinate-id launcher");
            assert_eq!(refused.code(), ErrorCode::PermissionDenied);
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
        for name in names {
            run_case(name, euid, egid);
        }
    }

    /// 1 ケース分: bundle を作り、本番 launcher で `create` → `start` し、起動ハンドルの `Exited(0)` を待って
    /// 所有者を照合する。起動済みのプロセスは成否に関わらず `terminate` して回収する（`LaunchedProcess` は Drop で
    /// 終了・回収しないため、ここで回収しないと実機に PID 1 が残る）。
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
        let id = ContainerId::new(format!("rfo{name}{}", std::process::id())).expect("id");
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

            let exit = started
                .process()
                .wait(scenario_deadline())
                .unwrap_or_else(|e| panic!("scenario {name}: wait: {e:?}"));
            assert_eq!(
                exit,
                Some(ProcessExit::Exited(0)),
                "scenario {name}: the real entrypoint must create the files and exit 0 within the limit"
            );
            verify_owners(name, euid, egid, &rootfs);
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            // 検証側の panic を優先する。terminate の失敗で元の panic を覆い隠さない。
            if let Err(e) = &terminated {
                eprintln!(
                    "rootless_file_owner: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
    }

    /// ホスト視点（分離されていないこのプロセス）での所有者照合（SEC-5）。
    fn verify_owners(name: &str, euid: u32, egid: u32, rootfs: &Path) {
        let want = expected(name, euid, egid);
        let report = real_entry::read_report(&rootfs.join(real_entry::REPORT_FILE), timeout());
        let field = |k: &str| report.get(k).map(String::as_str).unwrap_or("missing");
        assert_eq!(
            field("pid"),
            "1",
            "scenario {name}: real entrypoint is PID 1"
        );
        assert_eq!(field("uid"), "0", "scenario {name}: container uid");
        assert_eq!(field("gid"), "0", "scenario {name}: container gid");
        assert_eq!(
            field("root_owner"),
            "0:0",
            "scenario {name}: container view of root-created"
        );
        if name == "helper" {
            assert_eq!(
                field("chowned_owner"),
                "1:1",
                "scenario {name}: container view of chowned"
            );
        }
        let meta = std::fs::metadata(rootfs.join(ROOT_FILE)).expect("stat root-created");
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
            let m = std::fs::metadata(rootfs.join(CHOWNED_FILE)).expect("stat chowned");
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
    /// 実エントリポイント（exec 後のコンテナ PID 1）。コンテナ内 root としてファイルを作り、観測値を報告する。
    /// 失敗は値（`error:<kind>`）として記録し、終了コードは全操作が成功したときだけ 0 にする。
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
        let chowned = (name == "helper").then(|| create(CHOWNED_FILE, "chowned_owner", true));
        lines.push(root);
        lines.extend(chowned);
        real_entry::write_report(&lines);
        std::process::exit(if ok { 0 } else { 1 });
    }
}
