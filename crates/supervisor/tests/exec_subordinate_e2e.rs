//! 範囲写像（subordinate ids）の rootless コンテナへ、本番の入口だけで create → start → exec を通す実機前提の結合試験
//! （SEC-5・CORE-6・SUP-6・CRI-2・SEC-1・SEC-4・REPAIR-12。#2835・#2811・#3291）。
//!
//! #2811（#2770）で、稼働中コンテナへの exec が範囲写像の対象に対して `config.json` の `process.user` の非 root と
//! `additionalGids` を受けるようになった。ただし試験は `exec_setns_join` の credential 段（実 syscall の照合）に絞られ、
//! 本番の経路を通しで確かめる試験が無かった。本試験は次の本番の入口だけを通す（`exec-test-support` の試験専用入口
//! `run_command`・`run_command_in`・`identify_pid1_in` は使わない）。
//! - core の `create` → `start`（本番 `ProductionLauncher`。`IsolationPrivilege::RootlessSubordinateIds`）。start の前に、
//!   supervisor の本番と同じ cgroup の連鎖（`record_scope` → `create_cgroup` → `apply_limits` → `into_join`。
//!   `ProductionStartDeps::prepare_cgroup` と同じ順序）で配置を状態記録へ書く。exec は配置・`launch_isolation`・`rlimits` の
//!   どれかが記録に無いと `FailedPrecondition` で拒否するため
//! - supervisor の本番 exec 入口 `run_command_with_pidfd`（起動時に保持した pidfd で pid1 を固定する）
//!
//! `harness = false` の単一スレッド独自 `main` で、同じ実行ファイルが 3 つの役を持つ。
//! - 親（既定）: `-- --ignored` のときだけ実機シナリオを動かす（それ以外は案内を出して成功。既定のテスト集合に実機前提を
//!   混ぜないため）
//! - コンテナ内の pid1（`--container-probe`）: `/data/ready` へ `READY` を書き、親が terminate するまで待つ
//!   （寿命の上限 60 秒を超えたら終了コード 8。取り残さない。REPAIR-5）
//! - exec されるコマンド（`--exec-probe <出力先名>`）: コンテナ内の `/proc/self/status` から `Uid:`・`Gid:`・`Groups:`・
//!   `NoNewPrivs:`・`Seccomp:`・`CapInh:`・`CapPrm:`・`CapEff:`・`CapBnd:`・`CapAmb:` の行を `/data/<出力先名>` へ書く（exec したコマンドの stdio は `/dev/null` で、
//!   `ExecOutcome` も出力を持たないため、観測値は bind mount したホストのディレクトリ経由で受ける）
//!
//! # 照合項目
//! - シナリオ C（重ねたマウントの拒否。SEC-1・SEC-4・CORE-5・#3201・#3291）: 実カーネルで bind 先 `/data` に tmpfs を
//!   重ね（`nsenter --user --mount --root=/ --wd=/proc/<pid>/root/data -- mount -t tmpfs ... .`。root は host のまま、
//!   cwd だけがコンテナの `/data` のマウント）、`/proc/<pid>/mountinfo` で重なり（マウント ID が launch の記録の `mnt_id`
//!   と異なる tmpfs が上に載ること）を確かめたうえで exec し、`FailedPrecondition`・
//!   `exec stage Landlock: landlock_mount_identity_mismatch ...`・監査 1 件（層 `mount`・理由
//!   `landlock_mount_identity_mismatch`・path なし・container_id 一致）・コマンド未起動を照合する
//! - シナリオ A（成功経路）: `config.json` の `process.user` が uid 1000・gid 1000・`additionalGids` [3000, 2000] の
//!   コンテナを start し、Running の記録に cgroup の配置・`launch_isolation`・`rlimits` が載ることを確かめる。そのうえで
//!   `run_command_with_pidfd` の `ExecOutcome` が、終了 `Command(Exited(0))`・補助グループ `Applied { count: 2 }`・seccomp
//!   listener の受け渡し `Verified`・監査 0 件であること、exec したコマンドの `/proc/self/status` が `Uid` 1000 1000 1000 1000・
//!   `Gid` 1000 1000 1000 1000・`Groups` 2000 3000（カーネルがソートする）・`NoNewPrivs` 1・`Seccomp` 2 であることを具体値で照合する。あわせて capability（SEC-1）として `CapInh`・`CapPrm`・
//!   `CapEff`・`CapAmb` が 0、`CapBnd` が OCI 既定の `00000000a80425fb` であることを照合する（根拠: exec は launch と同じ
//!   関数で bounding set を許可集合へ削り ambient・inheritable を空にし、非 root への uid 移行と execve で permitted・
//!   effective が空になる〔`crates/core/src/exec/reapply.rs`〕。`process.capabilities` は無いので許可集合は OCI 既定。
//!   core は空でない ambient の指定を拒否する〔#2666〕ため、ambient を与える場面は成り立たない）。期待値が core の定義と
//!   ずれないよう、マスクを `CapabilitySet::oci_default()` から再計算して突き合わせる
//! - シナリオ B（写像の外の拒否。fail-closed の対照）: 同じコンテナの bundle の `config.json` を、写像の外の uid へ書き換えて
//!   （exec は呼び出しごとに bundle を読み直す）exec し、`InvalidArgument` で拒否されること・コマンドが起動していないこと
//!   （出力ファイルが作られない）を照合する。照合後は config を元へ戻す
//!
//! # 必要環境
//! - 非特権ユーザー（root は範囲写像の launcher が `PermissionDenied`〔SEC-5〕で拒否することだけを照合し、成功行は
//!   `(root=true)` で終わる。CI では回さない。#1621）
//! - `FANDHE_CONTAINER_TEST_ID_HELPER=1`（範囲写像専用の試験。未設定で `--ignored` なら失敗する）
//! - `uidmap`（`/usr/bin/newuidmap`・`/usr/bin/newgidmap`。setuid）と `/etc/subuid`・`/etc/subgid` の自ユーザー行
//!   （uid 側 1000 件以上・gid 側 3000 件以上）
//! - 非特権ユーザーに委譲された cgroup v2（`systemd-run --user --scope -p Delegate=yes`）・Landlock ABI 6 以上（Linux 6.12 以上）・
//!   非特権 user namespace を許可するホスト
//! - util-linux の `nsenter`・`mount`（`/usr/bin`。シナリオ C。無ければ失敗にする）
//! - 動的リンクのためホストの共有ライブラリを rootfs へコピーする（ネットワークは不要）
//!
//! # 実機前提テストとしての分離
//! 上記の環境は既定のテスト集合では保証できないため、`-- --ignored` 指定時のみ実行する（`platform-ci` の ubuntu が実行し
//! 成功行を照合する。ci.md「実機前提テスト」）。前提が欠けた場合は 1 行目が
//! `exec_subordinate_e2e: PRECONDITION FAILED (test environment, not a <cgroup delegation|subordinate id mapping|landlock> regression): ...`
//! の失敗にし、検証せずに成功する分岐は持たない。分類は core の `tests/support/precondition.rs`（正本。#3144・REPAIR-12）。
//! setuid ビットと subuid / subgid の件数の閾値（uid 1000 件以上・gid 3000 件以上）は正本に無い試験固有の条件として残す。
//!
//! ```text
//! cargo test -p fandhe-container-supervisor --test exec_subordinate_e2e --no-run
//! FANDHE_CONTAINER_TEST_ID_HELPER=1 USER=$(id -un) systemd-run --user --scope -p Delegate=yes <target/debug/deps/exec_subordinate_e2e-XXXX> --ignored
//! ```
//!
//! 成功時の最終行: `exec_subordinate_e2e: create, start and exec under subordinate id mapping verified (root=false)`。
//!
//! # 既知の制約（REPAIR-3）
//! - exec 要求ごとの user の上書き（CLI の `--user` #2712・CRI の Exec #680）・名前形式の User の解決・同じ user namespace
//!   （`Shared`）での非 root と補助グループ（#2241 待ち）
//! - 実機（root）での実行と記録は #1621（人間担当）

#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_subordinate_e2e: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("exec_subordinate_e2e: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--container-probe") {
        linux::container_probe();
    } else if let Some(pos) = args.iter().position(|a| a == "--exec-probe") {
        linux::exec_probe(args.get(pos + 1).map(String::as_str));
    } else if args.iter().any(|a| a == "--ignored") {
        precondition::self_check();
        linux::run();
    } else {
        precondition::self_check();
        println!(
            "exec_subordinate_e2e: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
        );
    }
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "support/rootfs.rs"]
mod rootfs;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

/// 前提欠如（委譲 cgroup・範囲写像・Landlock）を `PRECONDITION FAILED` の 1 行目で報告する共有部品
/// （core の `tests/support/precondition.rs` の正本を取り込む。#3144・REPAIR-12）。
#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "../../core/tests/support/precondition.rs"]
mod precondition;

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditDelivery, AuditLayer, AuditRecord, AuditSink};
    use fandhe_container_core::cgroups::CgroupLimitPlan;
    use fandhe_container_core::exec::{
        ChildExit, ExecExit, IsolationPrivilege, SupplementaryGroups,
    };
    use fandhe_container_core::launch_isolation::RecordedTarget;
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        ProcessLauncher, ProductionLauncher, StartTimeouts, SubordinateIdSource, create, start,
    };
    use fandhe_container_core::rootless::{SubIdOwner, load_subordinate_ids};
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, ErrorCode, GetStateRequest, StartRequest,
        StateRecord, StateStore, TraitError,
    };
    use fandhe_container_supervisor::exec::{
        ExecListenerHandover, ExecRequest, run_command_with_pidfd,
    };

    use super::rootfs;

    /// コンテナ内の bind 先（ホストの `hostdata/` を `rw` で束ねる。pid1 の ready 通知と exec の観測値の受け渡し口）。
    const DATA_DEST: &str = "/data";
    /// pid1 が準備完了で書くファイル名と内容。
    const READY_FILE: &str = "ready";
    const READY_CONTENT: &str = "READY";
    /// exec したコマンドが観測値を書くファイル名（シナリオ A・B）。
    const STATUS_FILE_A: &str = "exec-status";
    const STATUS_FILE_B: &str = "exec-status-b";
    const STATUS_FILE_C: &str = "exec-status-c";
    /// 前提とする util-linux のコマンド（シナリオ C のマウントの重ね合わせに使う）。
    const NSENTER: &str = "/usr/bin/nsenter";
    const MOUNT: &str = "/usr/bin/mount";
    /// config の `process.user`（シナリオ A の成功経路）。
    const USER_UID: u32 = 1000;
    const USER_GID: u32 = 1000;
    /// config の `additionalGids`（順序はカーネルのソートと異なる並びで指定する）。
    const ADDITIONAL_GIDS: [u32; 2] = [3000, 2000];
    /// 範囲写像の前提: uid 側・gid 側の範囲の合計がこの件数以上であること（上の uid / gid を写せる件数）。
    const NEED_UIDS: u64 = 1000;
    const NEED_GIDS: u64 = 3000;
    /// pid1 の寿命の上限（取り残し防止。REPAIR-5）。超えたら終了コード 8。
    const PROBE_LIFETIME: Duration = Duration::from_secs(60);

    /// 1 件の待ちの上限。`FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（1..=295。未設定・不正値は 30 秒）。
    /// `StartTimeouts` が 600 秒以下を要求するため 295 秒に丸める。
    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| *s >= 1)
            .map_or(30, |s| s.min(295));
        Duration::from_secs(secs)
    }

    fn timeouts() -> StartTimeouts {
        let t = timeout();
        StartTimeouts::new(t, t, t).expect("start timeouts")
    }

    // ----- コンテナ内の役 ----------------------------------------------------------------------------------

    /// pid1 の役。`/data/ready` へ準備完了を書き、親が terminate するまで待つ（寿命の上限つき）。
    pub fn container_probe() {
        let path = format!("{DATA_DEST}/{READY_FILE}");
        if std::fs::write(&path, READY_CONTENT).is_err() {
            std::process::exit(9);
        }
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        let deadline = Instant::now() + PROBE_LIFETIME;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        std::process::exit(8);
    }

    /// exec されるコマンドの役。コンテナ内の `/proc/self/status` の資格情報の行を `/data/<name>` へ書く。
    pub fn exec_probe(name: Option<&str>) {
        let Some(name) = name.filter(|n| !n.is_empty() && !n.contains('/')) else {
            std::process::exit(2);
        };
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            std::process::exit(3);
        };
        let wanted = [
            "Uid:",
            "Gid:",
            "Groups:",
            "NoNewPrivs:",
            "Seccomp:",
            "CapInh:",
            "CapPrm:",
            "CapEff:",
            "CapBnd:",
            "CapAmb:",
        ];
        let mut out = String::new();
        for line in status.lines() {
            if wanted.iter().any(|k| line.starts_with(k)) {
                out.push_str(line);
                out.push('\n');
            }
        }
        let path = format!("{DATA_DEST}/{name}");
        if std::fs::write(&path, out).is_err() {
            std::process::exit(4);
        }
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        std::process::exit(0);
    }

    // ----- 親側の準備 --------------------------------------------------------------------------------------

    /// 一時ディレクトリ（0700。`create_dir` で排他的に作り、drop で削除）。
    struct TempDir {
        dir: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let dir = super::scratch_root::scratch_root("fandhe-exsub-scratch", timeout())
                .join(format!("fandhe-exsub-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir(&dir).expect("exclusively create the work dir");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod work dir");
            Self { dir }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// 監査レコードをメモリへ追記するだけの sink（件数と、シナリオ C では記録の中身を照合する）。
    struct MemSink(std::sync::Mutex<Vec<AuditRecord>>);

    impl MemSink {
        fn count(&self) -> usize {
            self.snapshot().len()
        }

        fn snapshot(&self) -> Vec<AuditRecord> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl AuditSink for MemSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(record.clone());
            Ok(())
        }
    }

    /// `/proc/<x>/status` 形式のファイルから、`key` で始まる行の値（key の後ろ）を返す。
    fn status_field(path: &str, key: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    }

    /// 実効 uid・gid（`/proc/self/status`）。
    fn own_ids() -> (u32, u32) {
        let id = |key: &str| -> u32 {
            status_field("/proc/self/status", key)
                .and_then(|v| v.split_whitespace().nth(1).map(str::to_string))
                .and_then(|v| v.parse().ok())
                .expect("parse id")
        };
        (id("Uid:"), id("Gid:"))
    }

    /// `cond` が真になるまで `timeout()` までポーリングする（固定 sleep に頼らない）。
    fn eventually(cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + timeout();
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    /// 呼び出しプロセスが単一スレッドに戻るのを待つ（fork の前提。`start` の期限つき呼び出しのスレッドが残り得る）。
    fn wait_single_thread() {
        assert!(
            eventually(|| status_field("/proc/self/status", "Threads:").as_deref() == Some("1")),
            "the test process must be single-threaded before a launch or an exec"
        );
    }

    /// 呼び出しプロセスの子（全スレッド分）の pid 一覧。
    fn children_of_self() -> Vec<String> {
        let mut out = Vec::new();
        let tasks = std::fs::read_dir("/proc/self/task").expect("read /proc/self/task");
        for t in tasks {
            let t = t.expect("task entry");
            if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
                out.extend(s.split_whitespace().map(str::to_string));
            }
        }
        out
    }

    /// 範囲の合計件数（uid・gid とも同じ読み方）。
    fn range_total(path: &str, owner: &SubIdOwner) -> u64 {
        match load_subordinate_ids(Path::new(path), owner) {
            Ok(ranges) => ranges.iter().map(|r| u64::from(r.count())).sum(),
            Err(_) => 0,
        }
    }

    /// `process.user` を差し替えた `config.json` の本文。`bind_src` は `/data` の bind の元（ホストのパス）。
    /// 書式は `production_launcher` の `write_config_groups` に揃える（`serde_json` は supervisor の依存に無いため手書き）。
    fn config_text(ld: &str, bind_src: &Path, uid: u32, gid: u32, gids: &[u32]) -> String {
        let gids = gids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let src = bind_src.to_str().expect("utf8 bind source");
        format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"hostname":"fandhe-exsub",
"process":{{"user":{{"uid":{uid},"gid":{gid},"additionalGids":[{gids}]}},"args":["/probe","--container-probe"],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"mounts":[{{"destination":"{DATA_DEST}","type":"bind","source":"{src}","options":["bind","rw"]}}],
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#
        )
    }

    /// 範囲写像の launcher を作る。所有者名は試験側が `USER` から渡す（ライブラリは読まない）。
    fn build_launcher(
        cgroup_join: Option<Arc<fandhe_container_core::cgroups::ContainerCgroup>>,
    ) -> Result<ProductionLauncher, TraitError> {
        let builder = ProductionLauncher::builder()
            .privilege(IsolationPrivilege::RootlessSubordinateIds)
            .subordinate_ids(SubordinateIdSource::system(std::env::var("USER").ok())?)
            .audit_sink(Arc::new(MemSink(std::sync::Mutex::new(Vec::new()))));
        match cgroup_join {
            Some(cgroup) => builder
                .cgroup_join_source(move || cgroup.join_hook())
                .build(),
            None => builder.build(),
        }
    }

    pub fn run() {
        // 前提の確認（副作用の前に fail-closed。#2788）。
        if std::env::var("FANDHE_CONTAINER_TEST_ID_HELPER").as_deref() != Ok("1") {
            println!(
                "exec_subordinate_e2e: subordinate id case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1), not verified"
            );
            std::process::exit(1);
        }
        if std::env::var("USER").map_or(true, |u| u.is_empty()) {
            crate::precondition::failed(
                crate::precondition::Kind::SubordinateIds,
                "USER is not set",
            );
        }
        let (euid, _) = own_ids();
        if euid == 0 {
            // root は範囲写像の launcher が拒否すること（SEC-5）だけを照合する。CI では回さない（#1621）。
            let refused = build_launcher(None).expect_err("root must be refused (SEC-5)");
            assert_eq!(refused.code(), ErrorCode::PermissionDenied);
            println!(
                "exec_subordinate_e2e: subordinate launcher refused for root (SEC-5) (root=true)"
            );
            return;
        }
        for helper in ["/usr/bin/newuidmap", "/usr/bin/newgidmap"] {
            match std::fs::metadata(helper) {
                Ok(m) if m.mode() & 0o4000 != 0 => {}
                _ => crate::precondition::failed(
                    crate::precondition::Kind::SubordinateIds,
                    "newuidmap / newgidmap is missing or not setuid",
                ),
            }
        }
        // 分類は正本（解析失敗は回帰側に残す）。setuid と件数の閾値は試験固有の条件として下に残す。
        crate::precondition::require_subordinate_ids(euid);
        let owner = SubIdOwner::new(euid, std::env::var("USER").ok()).expect("owner");
        let uid_total = range_total("/etc/subuid", &owner);
        let gid_total = range_total("/etc/subgid", &owner);
        if uid_total < NEED_UIDS || gid_total < NEED_GIDS {
            crate::precondition::failed(
                crate::precondition::Kind::SubordinateIds,
                "/etc/subuid or /etc/subgid has too few ids for the current user",
            );
        }
        let _landlock = crate::precondition::landlock_support();
        // シナリオ C が使う util-linux のコマンド。環境の欠落は検証せずに成功させず、副作用の前に失敗にする。
        for tool in [NSENTER, MOUNT] {
            assert!(
                std::fs::metadata(tool).is_ok_and(|m| m.is_file()),
                "exec_subordinate_e2e: util-linux nsenter and mount are required ({tool} is missing)"
            );
        }
        let delegated = crate::precondition::delegated_cgroup();

        // 一時領域の親ディレクトリ（tmpfiles の掃除と flock 競合の回避）を panic でも消す（#2887）。
        let _scratch_cleanup = super::scratch_root::ScratchRootCleanup;
        let tag = std::process::id();
        let work = TempDir::new("e2e");
        let store = FileStateStore::open(
            StateRoot::from_override(work.dir.join("state")).expect("state root"),
        )
        .expect("open state store");
        let id = ContainerId::new(format!("ese{tag}")).expect("container id");

        // bundle・bind 元・rootfs。bind 元は 0777（コンテナ内 uid 1000 はホストの subuid 先頭 + 999 で、所有者の
        // 試験ユーザーと異なるため）。親の作業ディレクトリが 0700 なので第三者からは辿れない。
        let bundle_dir = work.dir.join("bundle");
        let hostdata = work.dir.join("hostdata");
        std::fs::create_dir(&bundle_dir).expect("create bundle");
        std::fs::create_dir(&hostdata).expect("create hostdata");
        std::fs::set_permissions(&hostdata, std::fs::Permissions::from_mode(0o777))
            .expect("chmod hostdata");
        let ld = rootfs::make_rootfs(&bundle_dir.join("rootfs"), rootfs::ProcDir::Create);
        let config_path = bundle_dir.join("config.json");
        let config_a = config_text(&ld, &hostdata, USER_UID, USER_GID, &ADDITIONAL_GIDS);
        std::fs::write(&config_path, &config_a).expect("write config.json");

        let recorder = OpRecorder::new();
        let create_req =
            CreateRequest::new(id.clone(), bundle_dir.clone()).expect("absolute bundle");
        create(&store, &recorder, &create_req).expect("create");

        // 本番と同じ cgroup の連鎖（record_scope → create_cgroup → apply_limits → into_join）。配置が状態記録へ
        // 載らないと exec が拒否する。
        let observed = store
            .get(&GetStateRequest::new(id.clone()))
            .expect("get created state");
        let (container_cgroup, _first_join, _rec, _report) = delegated
            .record_scope(&store, &observed)
            .and_then(|r| r.create_cgroup())
            .and_then(|p| {
                p.apply_limits(
                    &recorder,
                    &CgroupLimitPlan::for_privilege(IsolationPrivilege::RootlessSubordinateIds),
                )
            })
            .and_then(|l| l.into_join())
            .unwrap_or_else(|e| panic!("cgroup start chain failed: {e:?}"))
            .into_parts();
        let container_cgroup = Arc::new(container_cgroup);

        // 後始末は成否に関わらず行う（panic でも cgroup と一時領域を残さない）。
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            scenarios(
                &store,
                &recorder,
                &id,
                &container_cgroup,
                &hostdata,
                &config_path,
                (&ld, &config_a),
            );
        }));
        let removed = delegated.remove_child(&container_cgroup);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        removed.expect("remove container cgroup");
        drop(work);

        println!(
            "exec_subordinate_e2e: create, start and exec under subordinate id mapping verified (root=false)"
        );
    }

    /// `/data` の準備完了通知（`hostdata/ready` が `READY` になる）を期限つきで待つ（スレッドを立てない）。
    fn wait_ready(hostdata: &Path) {
        let path = hostdata.join(READY_FILE);
        assert!(
            eventually(|| std::fs::read_to_string(&path).is_ok_and(|s| s == READY_CONTENT)),
            "the container probe must report READY"
        );
    }

    /// `/proc/<pid>/mountinfo` のうち、マウントポイントが `mountpoint` の行の `(マウント ID, 親 ID, fstype)`（出現順）。
    /// 空白区切りで読み、添字アクセスはしない。fstype は ` - ` の区切りの後ろから取る。
    fn mountinfo_entries(pid: u32, mountpoint: &str) -> Vec<(u64, u64, String)> {
        let text =
            std::fs::read_to_string(format!("/proc/{pid}/mountinfo")).expect("read mountinfo");
        text.lines()
            .filter_map(|line| {
                let (head, tail) = line.split_once(" - ")?;
                let mut f = head.split_whitespace();
                let id = f.next()?.parse::<u64>().ok()?;
                let parent = f.next()?.parse::<u64>().ok()?;
                let mp = f.nth(2)?;
                let fstype = tail.split_whitespace().next()?;
                (mp == mountpoint).then(|| (id, parent, fstype.to_string()))
            })
            .collect()
    }

    /// 期限つきで外部コマンドを実行して回収する（超えたら kill して回収し panic。REPAIR-5）。
    fn run_limited(mut cmd: std::process::Command) -> std::process::Output {
        use std::process::Stdio;
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn command");
        let deadline = Instant::now() + timeout();
        loop {
            if child.try_wait().expect("try_wait").is_some() {
                return child.wait_with_output().expect("collect output");
            }
            if Instant::now() >= deadline {
                crate::reap::reap_or_report(&mut child, crate::reap::REAP_WITHIN);
                panic!("command timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// OCI 既定の bounding set（moby の非 root コンテナの既定と同じ 14 個）の `/proc/<pid>/status` 表記。
    const OCI_DEFAULT_BOUNDING: &str = "00000000a80425fb";
    /// 空の capability 集合の表記。
    const NO_CAPS: &str = "0000000000000000";

    /// 期待値の定数が core の OCI 既定集合の定義とずれていないことを確かめる。
    fn assert_oci_default_mask_matches_core() {
        let mask = fandhe_container_core::capabilities::CapabilitySet::oci_default()
            .iter()
            .fold(0u64, |m, c| m | (1u64 << c.index()));
        assert_eq!(
            mask,
            u64::from_str_radix(OCI_DEFAULT_BOUNDING, 16).expect("hex"),
            "OCI_DEFAULT_BOUNDING must equal core's CapabilitySet::oci_default()"
        );
    }

    /// `Uid:` 等の行から値を空白区切りの数値列（`,` 連結）にして返す。
    fn status_value(text: &str, key: &str) -> String {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .unwrap_or_else(|| panic!("exec status line {key:?} missing in {text:?}"))
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(",")
    }

    // 理由: 試験の各シナリオが共有する固定の環境（状態ストア・記録器・ID・cgroup・ホスト側ディレクトリ・
    // config のパスと内容）を、1 回きりの試験専用の関数へそのまま渡す。まとめるだけの構造体は
    // 読み手に余計な間接を足すため、引数を並べたまま clippy の引数数の警告だけを抑止する。
    #[allow(clippy::too_many_arguments)]
    fn scenarios(
        store: &FileStateStore,
        recorder: &OpRecorder,
        id: &ContainerId,
        container_cgroup: &Arc<fandhe_container_core::cgroups::ContainerCgroup>,
        hostdata: &Path,
        config_path: &Path,
        (ld, config_a): (&str, &str),
    ) {
        let launcher: Arc<dyn ProcessLauncher> =
            Arc::new(build_launcher(Some(Arc::clone(container_cgroup))).expect("build launcher"));

        wait_single_thread();
        let started = start(
            store,
            recorder,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            wait_ready(hostdata);
            // exec の前に、Running の記録を入力として読み戻す（本番の supervisor と同じ）。exec が前提とする
            // 3 つ（cgroup の配置・launch_isolation・rlimits）が載っていることを明示的に確かめる。
            let record: StateRecord = store
                .get(&GetStateRequest::new(id.clone()))
                .expect("get running state");
            assert_eq!(record.status().state(), ContainerState::Running);
            assert_eq!(record.status().pid(), Some(pid));
            assert!(
                record.cgroup().is_some(),
                "cgroup placement must be recorded"
            );
            assert!(
                record.launch_isolation().is_some(),
                "launch_isolation must be recorded"
            );
            assert!(
                record.rlimits().is_some_and(|r| r.is_complete()),
                "complete rlimits must be recorded"
            );
            let pidfd = started
                .process()
                .launch_pidfd()
                .expect("the launch pidfd must be held");

            // シナリオ A: 成功経路。
            let sink = MemSink(std::sync::Mutex::new(Vec::new()));
            wait_single_thread();
            let request = ExecRequest::new("/probe", ["/probe", "--exec-probe", STATUS_FILE_A])
                .expect("exec request");
            let outcome = run_command_with_pidfd(&record, pidfd, &request, timeout(), &sink)
                .unwrap_or_else(|r| {
                    panic!("exec failed: {:?} {}", r.error.code(), r.error.message())
                });
            let outcome = outcome.outcome;
            assert_eq!(outcome.exit, ExecExit::Command(ChildExit::Exited(0)));
            assert_eq!(
                outcome.supplementary_groups,
                SupplementaryGroups::Applied { count: 2 }
            );
            assert_eq!(outcome.seccomp_listener, ExecListenerHandover::Verified);
            assert_eq!(
                sink.count(),
                0,
                "a successful exec must record no audit entry"
            );
            let text = std::fs::read_to_string(hostdata.join(STATUS_FILE_A))
                .expect("exec status written by the command");
            assert_eq!(
                status_value(&text, "Uid:"),
                "1000,1000,1000,1000",
                "{text:?}"
            );
            assert_eq!(
                status_value(&text, "Gid:"),
                "1000,1000,1000,1000",
                "{text:?}"
            );
            assert_eq!(status_value(&text, "Groups:"), "2000,3000", "{text:?}");
            assert_eq!(status_value(&text, "NoNewPrivs:"), "1", "{text:?}");
            assert_eq!(status_value(&text, "Seccomp:"), "2", "{text:?}");
            // capability（SEC-1・SEC-5・CORE-6）。非 root で exec すると permitted / effective は空になり、
            // bounding set だけが OCI 既定集合へ削られて残る。ambient は core が空でない指定を拒否する（#2666）ため常に空。
            assert_oci_default_mask_matches_core();
            for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
                assert_eq!(status_value(&text, key), NO_CAPS, "{key} in {text:?}");
            }
            assert_eq!(
                status_value(&text, "CapBnd:"),
                OCI_DEFAULT_BOUNDING,
                "{text:?}"
            );
            println!(
                "exec_subordinate_e2e: scenario=exec-user-capabilities CapInh=CapPrm=CapEff=CapAmb=0000000000000000 CapBnd=00000000a80425fb (non-root exec keeps only the OCI default bounding set)"
            );
            println!(
                "exec_subordinate_e2e: scenario=exec-user-applied uid=1000 gid=1000 groups=2000,3000 via ProductionLauncher create, start and run_command_with_pidfd"
            );

            // シナリオ B: 写像の外の uid は exec が拒否し、コマンドは起動しない。uid の範囲の合計 + 1 は写像の外。
            let owner = SubIdOwner::new(own_ids().0, std::env::var("USER").ok()).expect("owner");
            let outside = range_total("/etc/subuid", &owner) + 1;
            let outside_uid = u32::try_from(outside).expect("outside uid fits in u32");
            std::fs::write(
                config_path,
                config_text(ld, hostdata, outside_uid, USER_GID, &ADDITIONAL_GIDS),
            )
            .expect("rewrite config.json");
            let request_b = ExecRequest::new("/probe", ["/probe", "--exec-probe", STATUS_FILE_B])
                .expect("exec request b");
            let refused = run_command_with_pidfd(&record, pidfd, &request_b, timeout(), &sink);
            std::fs::write(config_path, config_a).expect("restore config.json");
            let refused = match refused {
                Ok(o) => panic!("a user outside the mapping must be refused, got {o:?}"),
                Err(r) => r,
            };
            assert_eq!(refused.error.code(), ErrorCode::InvalidArgument);
            assert!(
                !hostdata.join(STATUS_FILE_B).exists(),
                "the command must not start for a refused user"
            );
            println!(
                "exec_subordinate_e2e: scenario=exec-user-outside-mapping-refused code=InvalidArgument command_started=false"
            );

            // シナリオ C: bind 先 `/data` に別のマウント（tmpfs）を重ねた後の exec は、launch 時のマウント識別子との
            // 照合（`MountCheck::Recorded`）で拒否され、コマンドは起動しない（SEC-1・SEC-4・CORE-5・#3201・#3291）。
            // 重ねたマウントは pid1 の mount namespace に残り戻せないので最後に置く（terminate で namespace ごと消える）。
            let recorded_mnt_id = record
                .launch_isolation()
                .and_then(|l| {
                    assert_eq!(
                        l.landlock().mount_identities(),
                        fandhe_container_core::launch_isolation::RecordedMountIdentities::Complete
                    );
                    l.landlock().rules().iter().find_map(|r| match r.target() {
                        RecordedTarget::Mount { destination, .. }
                            if destination.as_str() == DATA_DEST =>
                        {
                            r.mount().map(|m| m.mnt_id())
                        }
                        _ => None,
                    })
                })
                .expect("the /data bind must have a recorded mount identity");
            let pid_u32 = pid.get();
            let before = mountinfo_entries(pid_u32, DATA_DEST);
            assert_eq!(before.len(), 1, "one mount at /data before: {before:?}");
            assert_eq!(
                before.first().map(|e| e.0),
                Some(recorded_mnt_id),
                "launch's recorded mnt_id must equal the kernel's mount id"
            );
            assert_eq!(
                std::fs::read_to_string(format!("/proc/{pid_u32}/root{DATA_DEST}/{READY_FILE}"))
                    .ok()
                    .as_deref(),
                Some(READY_CONTENT)
            );
            let mut overmount = std::process::Command::new(NSENTER);
            overmount
                .arg("--target")
                .arg(pid_u32.to_string())
                .args(["--user", "--mount", "--root=/"])
                .arg(format!("--wd=/proc/{pid_u32}/root{DATA_DEST}"))
                .args(["--", MOUNT, "--no-canonicalize", "-t", "tmpfs"])
                .args(["-o", "size=64k", "fandhe-overmount", "."]);
            let out = run_limited(overmount);
            assert!(
                out.status.success(),
                "overmount failed: {:?} stdout={:?} stderr={:?}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let after = mountinfo_entries(pid_u32, DATA_DEST);
            assert_eq!(after.len(), 2, "two mounts at /data after: {after:?}");
            let top = after.last().expect("top mount");
            assert_eq!(top.1, recorded_mnt_id, "{after:?}");
            assert_eq!(top.2, "tmpfs", "{after:?}");
            assert_ne!(top.0, recorded_mnt_id, "{after:?}");
            assert!(
                !Path::new(&format!("/proc/{pid_u32}/root{DATA_DEST}/{READY_FILE}")).exists(),
                "the overmounted tmpfs must hide the bind"
            );

            let sink_c = MemSink(std::sync::Mutex::new(Vec::new()));
            wait_single_thread();
            let request_c = ExecRequest::new("/probe", ["/probe", "--exec-probe", STATUS_FILE_C])
                .expect("exec request c");
            let rejected =
                match run_command_with_pidfd(&record, pidfd, &request_c, timeout(), &sink_c) {
                    Ok(o) => panic!("an overmounted bind must be refused, got {o:?}"),
                    Err(r) => r,
                };
            assert_eq!(rejected.error.code(), ErrorCode::FailedPrecondition);
            let message = rejected.error.message();
            assert!(
                message.starts_with("exec stage Landlock: landlock_mount_identity_mismatch")
                    && message.ends_with(
                        "(violation: mount_target/landlock_mount_identity_mismatch, CORE-5)"
                    ),
                "{message:?}"
            );
            assert_eq!(rejected.delivery, AuditDelivery::Recorded);
            let records = sink_c.snapshot();
            assert_eq!(records.len(), 1, "{records:?}");
            let rec = records.first().expect("one record");
            assert_eq!(rec.layer(), AuditLayer::Mount);
            assert_eq!(
                rec.reason().map(|r| r.as_str()),
                Some("landlock_mount_identity_mismatch")
            );
            assert_eq!(rec.path(), None, "no host path in the record (SEC-4)");
            assert_eq!(rec.container_id(), Some(id));
            assert_eq!(rec.pid().get(), std::process::id());
            assert!(
                !hostdata.join(STATUS_FILE_C).exists(),
                "the command must not start (host side)"
            );
            assert!(
                !Path::new(&format!("/proc/{pid_u32}/root{DATA_DEST}/{STATUS_FILE_C}")).exists(),
                "the command must not start (overmounted side)"
            );
            println!(
                "exec_subordinate_e2e: scenario=exec-overmounted-bind-refused code=FailedPrecondition reason=landlock_mount_identity_mismatch audit=mount records=1 command_started=false"
            );
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "exec_subordinate_e2e: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no child may remain after terminate"
        );
    }
}
