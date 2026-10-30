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
//! `harness = false` の単一スレッド独自 `main` で、同じ実行ファイルが 5 つの役を持つ。
//! - watchdog（`-- --ignored`）: 同じ実行ファイルを `--ignored-worker` で別プロセス（専用の pgid）として起動して全体の
//!   期限（`clamp(timeout × 16, 120, 480)` 秒）を見張る。試験は fork の前提で単一スレッドを要求するため、同一プロセスの
//!   スレッドでは見張れない。期限を過ぎたら診断（`ps --forest`・部分木の `wchan`・`syscall`）を stderr に出し、子孫を回収して
//!   `exec_subordinate_e2e: WATCHDOG EXPIRED ...` と終了コード 124 で終わる。worker が終わっても scope に自分以外の pid が
//!   残れば `LEFTOVER PROCESSES` で失敗にする。部分木の回収は、起動時に scope に自分だけが居たときに限る（端末から直接
//!   実行した利用者のセッションを撃たない）。watchdog 自身が kill された場合の回収（ステップ側）は #3486 の範囲で、
//!   worker は段の境界で親の消失を検出して止まるだけ（REPAIR-5・REPAIR-7。#3485）
//! - worker（`--ignored-worker`）: 実機シナリオを動かす。段ごとに `exec_subordinate_e2e: stage=<名前> begin` と
//!   `... end elapsed_ms=<n>` を出し、止まったときは最後の begin 行が場面を示す（成功行の照合の select には当たらない
//!   `stage=` の接頭辞）。親の watchdog を cgroup の同伴として宣言する（`with_companions`）。試験専用の注入
//!   `FANDHE_CONTAINER_ESE_TEST_HANG=<段名>` でその段の開始直後に止まり、watchdog の動作を実証できる
//! - 引数なし: 案内を出して成功（既定のテスト集合に実機前提を混ぜないため）。期限の計算の具体値だけ自己照合する
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
    } else if args.iter().any(|a| a == "--ignored-worker") {
        precondition::self_check();
        linux::run_worker();
    } else if let Some(pos) = args.iter().position(|a| a == "--exec-probe") {
        linux::exec_probe(args.get(pos + 1).map(String::as_str));
    } else if args.iter().any(|a| a == "--ignored") {
        precondition::self_check();
        linux::supervise();
    } else {
        precondition::self_check();
        linux::self_check_watchdog();
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

    // ----- 試験全体の watchdog（別プロセス。#3485・REPAIR-5・REPAIR-7）----------------------------------------

    /// worker が親（watchdog）の pid を確かめるための環境変数。watchdog 無しでは worker を走らせない（fail-closed）。
    const WATCHDOG_PID_ENV: &str = "FANDHE_CONTAINER_ESE_WATCHDOG_PID";
    /// 試験専用の停止の注入。値は `STAGES` の段名に限る。指定した段の開始行の直後で worker が止まり、watchdog の
    /// 期限切れ・回収・固定の失敗行を実証できる。未設定では何もしない。
    const HANG_ENV: &str = "FANDHE_CONTAINER_ESE_TEST_HANG";
    /// 段の名前の固定一覧（注入の許可リストを兼ねる）。
    const STAGES: [&str; 16] = [
        "preconditions",
        "scratch-and-bundle",
        "create",
        "cgroup-chain",
        "start",
        "wait-ready",
        "record-readback",
        "exec-a",
        "exec-b",
        "overmount",
        "exec-c",
        "terminate",
        "wait-proc-gone",
        "wait-no-children",
        "remove-cgroup",
        "cleanup",
    ];
    /// 期限切れで終わるときの終了コード（`timeout(1)` と同じ値）。
    const EXIT_WATCHDOG_EXPIRED: i32 = 124;
    /// 診断・走査の上限（無制限の確保を避ける。REPAIR-5）。
    const MAX_DIRS: usize = 256;
    const MAX_PIDS: usize = 4096;
    const MAX_DIAG_PIDS: usize = 256;
    const MAX_DIAG_TASKS: usize = 64;
    const KILL: &str = "/usr/bin/kill";
    const PS: &str = "/usr/bin/ps";

    /// 試験全体の期限。`timeout()` の 16 倍を 120..=480 秒に収める。CI のステップ上限 600 秒と繰り返しの
    /// `repeat-run-timeout`（600）より短く、期限後の診断と回収（最大約 60 秒）を足しても収まる。下限は
    /// timeout を小さく与えても rootfs の準備などの正常な所要時間で誤って発火しないため。
    pub fn deadline_for(timeout_secs: u64) -> Duration {
        Duration::from_secs(timeout_secs.saturating_mul(16).clamp(120, 480))
    }

    fn deadline() -> Duration {
        deadline_for(timeout().as_secs())
    }

    fn hang_is_valid(v: &str) -> bool {
        STAGES.contains(&v)
    }

    /// 既定の経路（引数なし）で回す、期限の計算と注入の許可リストの具体値の自己照合（REPAIR-12）。
    pub fn self_check_watchdog() {
        for (secs, want) in [
            (0, 120),
            (1, 120),
            (7, 120),
            (8, 128),
            (30, 480),
            (295, 480),
        ] {
            assert_eq!(deadline_for(secs), Duration::from_secs(want), "secs={secs}");
        }
        assert!(hang_is_valid("exec-a"));
        assert!(hang_is_valid("cleanup"));
        // 試験ソースが出す段名の全件が許可リストに入っていること（食い違うと注入が拒否される）。
        let src = include_str!("exec_subordinate_e2e.rs");
        let pat = concat!("begin", "(\"");
        let mut seen = 0;
        for part in src.split(pat).skip(1) {
            if let Some(name) = part.split('"').next()
                && !name.is_empty()
                && name.chars().all(|c| c.is_ascii_lowercase() || c == '-')
            {
                assert!(hang_is_valid(name), "stage {name} missing from STAGES");
                seen += 1;
            }
        }
        assert!(seen >= 16, "expected to find every stage, found {seen}");
        assert!(!hang_is_valid("bogus"));
        assert!(!hang_is_valid(""));
        assert!(
            STAGES.iter().all(|s| !s.is_empty() && !s.contains(' ')),
            "stage names must be single tokens"
        );
    }

    fn watchdog_pid() -> u32 {
        std::env::var(WATCHDOG_PID_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .expect("the watchdog pid must be passed by the watchdog")
    }

    static STAGE: std::sync::Mutex<Option<(&'static str, Instant)>> = std::sync::Mutex::new(None);
    static PARENT_LOST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// 段の開始行を出す（直前の段の終了行も出す）。止まったときは最後の `begin` 行が止まった段を示す。
    /// 親（watchdog）が消えていたら一度だけ panic して後始末の経路に乗せる（孤児のまま走り続けない）。
    /// 注入（`HANG_ENV`）が当たる段はここで止まる。
    fn begin(name: &'static str) {
        {
            let mut g = STAGE.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((prev, t0)) = g.take() {
                emit_stage_line(&format!(
                    "exec_subordinate_e2e: stage={prev} end elapsed_ms={}",
                    t0.elapsed().as_millis()
                ));
            }
            emit_stage_line(&format!("exec_subordinate_e2e: stage={name} begin"));
            *g = Some((name, Instant::now()));
        }
        if std::os::unix::process::parent_id() != watchdog_pid()
            && !PARENT_LOST.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            panic!("the watchdog parent process is gone");
        }
        if std::env::var(HANG_ENV).as_deref() == Ok(name) {
            eprintln!("exec_subordinate_e2e: injected hang at stage {name}");
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }

    /// 最後の段の終了行を出す。
    fn finish() {
        let mut g = STAGE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((prev, t0)) = g.take() {
            emit_stage_line(&format!(
                "exec_subordinate_e2e: stage={prev} end elapsed_ms={}",
                t0.elapsed().as_millis()
            ));
        }
    }

    /// 段の行を出して直ちに flush する。出力が `tee` へのパイプでブロックバッファされても、watchdog の SIGKILL で
    /// 最後の `begin` 行が失われず、止まった段を特定できる（REPAIR-5）。
    fn emit_stage_line(line: &str) {
        use std::io::Write;
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }

    /// worker の役。watchdog の子として起動された場合だけ実機シナリオを動かす。
    pub fn run_worker() {
        let parent = std::os::unix::process::parent_id();
        let ok = std::env::var(WATCHDOG_PID_ENV)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            == Some(parent);
        if !ok {
            println!(
                "exec_subordinate_e2e: the worker must be started by the watchdog (run with `-- --ignored`)"
            );
            std::process::exit(1);
        }
        run();
    }

    /// watchdog が見ている scope（自分の cgroup）。
    struct Scope {
        path: PathBuf,
        /// 起動時に自分だけが居て、子 cgroup が無く、euid 所有であるときだけ真。真のときに限り、期限切れ・残置で
        /// scope の部分木を回収する（端末から直接実行したときに利用者のセッションを撃たないため）。
        reapable: bool,
    }

    fn own_cgroup_dir() -> Option<PathBuf> {
        let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?;
        let rel = Path::new(rel.trim()).strip_prefix("/").ok()?;
        if rel
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return None;
        }
        Some(Path::new("/sys/fs/cgroup").join(rel))
    }

    fn read_procs(dir: &Path) -> Vec<u32> {
        std::fs::read_to_string(dir.join("cgroup.procs"))
            .map(|t| {
                t.lines()
                    .filter_map(|l| l.trim().parse().ok())
                    .take(MAX_PIDS)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn child_dirs(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .map(|e| e.path())
                    .take(MAX_DIRS)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `root` 配下の全 cgroup ディレクトリ（root を含む。深さと件数に上限）。
    fn subtree_dirs(root: &Path) -> Vec<PathBuf> {
        let mut out = vec![root.to_path_buf()];
        let mut i = 0;
        while let Some(d) = out.get(i).cloned() {
            i += 1;
            if d.strip_prefix(root).map_or(0, |r| r.components().count()) >= 6 {
                continue;
            }
            for c in child_dirs(&d) {
                if out.len() < MAX_DIRS {
                    out.push(c);
                }
            }
        }
        out
    }

    impl Scope {
        fn probe(me: u32) -> Option<Scope> {
            let path = own_cgroup_dir()?;
            let (euid, _) = own_ids();
            let owned = std::fs::metadata(&path).is_ok_and(|m| m.uid() == euid && m.is_dir());
            let alone = read_procs(&path) == [me];
            let reapable = owned && alone && child_dirs(&path).is_empty();
            Some(Scope { path, reapable })
        }

        /// 部分木にいる自分以外の pid（重複なし）。
        fn others(&self, me: u32) -> Vec<u32> {
            let mut pids: Vec<u32> = subtree_dirs(&self.path)
                .iter()
                .flat_map(|d| read_procs(d))
                .filter(|p| *p != me)
                .collect();
            pids.sort_unstable();
            pids.dedup();
            pids.truncate(MAX_PIDS);
            pids
        }

        fn wait_empty(&self, me: u32, within: Duration) -> Vec<u32> {
            let until = Instant::now() + within;
            loop {
                let left = self.others(me);
                if left.is_empty() || Instant::now() >= until {
                    return left;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        /// 自分の現在の cgroup（退避リーフ）の祖先でも自分自身でもない、部分木の cgroup。
        fn disposable_dirs(&self) -> Vec<PathBuf> {
            let mine = own_cgroup_dir();
            subtree_dirs(&self.path)
                .into_iter()
                .filter(|d| d != &self.path)
                .filter(|d| mine.as_ref().is_none_or(|m| !m.starts_with(d)))
                .collect()
        }

        /// 部分木を回収する（コンテナの cgroup は `cgroup.kill`、退避リーフ側の自分以外の pid は個別の kill）。
        fn reap_subtree(&self, me: u32) {
            for d in self.disposable_dirs() {
                if let Err(e) = std::fs::write(d.join("cgroup.kill"), "1") {
                    eprintln!(
                        "exec_subordinate_e2e: cgroup.kill on {} failed: {e}",
                        d.display()
                    );
                }
            }
            let mut targets: Vec<u32> = read_procs(&self.path);
            if let Some(m) = own_cgroup_dir() {
                targets.extend(read_procs(&m));
            }
            targets.retain(|p| *p != me);
            targets.sort_unstable();
            targets.dedup();
            kill_pids(&targets);
        }

        fn remove_disposable_dirs(&self) {
            let mut dirs = self.disposable_dirs();
            dirs.sort_by_key(|d| std::cmp::Reverse(d.as_os_str().len()));
            for d in dirs {
                let _ = std::fs::remove_dir(d);
            }
        }
    }

    fn run_kill(args: &[String]) {
        let mut cmd = std::process::Command::new(KILL);
        cmd.args(["-s", "KILL", "--"])
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if let Err(e) = crate::reap::run_within(&mut cmd, Duration::from_secs(10)) {
            eprintln!("exec_subordinate_e2e: {KILL} failed: {e}");
        }
    }

    fn kill_pids(pids: &[u32]) {
        // 数値だけを引数に渡す（pid 0・1 は撃たない）。
        let args: Vec<String> = pids
            .iter()
            .filter(|p| **p > 1)
            .map(u32::to_string)
            .collect();
        if !args.is_empty() {
            run_kill(&args);
        }
    }

    fn kill_group(pgid: u32) {
        if pgid > 1 {
            run_kill(&[format!("-{pgid}")]);
        }
    }

    /// 止まった場面の診断（stderr）。環境変数は読まない・出さない。
    fn dump_diag(scope: Option<&Scope>, me: u32) {
        let mut ps = std::process::Command::new(PS);
        ps.args([
            "-eo",
            "pid,ppid,pgid,sid,stat,wchan:32,etime,cmd",
            "--forest",
        ])
        .stdin(std::process::Stdio::null());
        match crate::reap::output_within(&mut ps, Duration::from_secs(10)) {
            Ok(o) => eprintln!(
                "exec_subordinate_e2e: ps --forest\n{}",
                // 全プロセスの木は大きいので行数に上限をつける。
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .take(400)
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            Err(e) => eprintln!("exec_subordinate_e2e: ps failed: {e}"),
        }
        let Some(scope) = scope else { return };
        for pid in scope.others(me).into_iter().take(MAX_DIAG_PIDS) {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
            let pick = |k: &str| {
                status
                    .lines()
                    .find_map(|l| l.strip_prefix(k))
                    .map(|v| v.trim().to_string())
                    .unwrap_or_default()
            };
            eprintln!(
                "exec_subordinate_e2e: diag pid={pid} name={} state={} threads={}",
                pick("Name:"),
                pick("State:"),
                pick("Threads:")
            );
            let tasks = std::fs::read_dir(format!("/proc/{pid}/task"))
                .map(|rd| {
                    rd.filter_map(Result::ok)
                        .take(MAX_DIAG_TASKS)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            for t in tasks {
                let base = t.path();
                let wchan = std::fs::read_to_string(base.join("wchan")).unwrap_or_default();
                let syscall = std::fs::read_to_string(base.join("syscall")).unwrap_or_default();
                eprintln!(
                    "exec_subordinate_e2e: diag task={} wchan={} syscall={}",
                    t.file_name().to_string_lossy(),
                    wchan.trim(),
                    syscall.trim()
                );
            }
        }
    }

    /// watchdog の役（`-- --ignored` の入口）。同じ実行ファイルを worker として別プロセスで起動し、試験全体の期限を
    /// 過ぎたら診断を出して子孫を回収し、固定の失敗行と終了コード 124 で終わる。worker が期限内に終わっても
    /// scope に自分以外の pid が残っていたら失敗にする（子孫が stdout を持ち続けて `tee` が止まる形を失敗として見せる）。
    pub fn supervise() {
        use std::os::unix::process::CommandExt as _;
        let me = std::process::id();
        println!(
            "exec_subordinate_e2e: stage=entry begin pid={me} ppid={}",
            std::os::unix::process::parent_id()
        );
        if let Ok(h) = std::env::var(HANG_ENV)
            && !hang_is_valid(&h)
        {
            println!("exec_subordinate_e2e: {HANG_ENV} must be one of the fixed stage names");
            std::process::exit(1);
        }
        let scope = Scope::probe(me);
        let reaping = scope.as_ref().filter(|s| s.reapable);
        let exe = std::env::current_exe().expect("current exe");
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("--ignored-worker")
            .process_group(0)
            .env(WATCHDOG_PID_ENV, me.to_string());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                println!("exec_subordinate_e2e: spawn worker failed: {e}");
                std::process::exit(1);
            }
        };
        let pgid = child.id();
        let limit = deadline();
        match crate::reap::wait_within(&mut child, limit) {
            Ok(status) => {
                if let Some(s) = reaping {
                    let left = s.wait_empty(me, crate::reap::reap_within());
                    if !left.is_empty() {
                        println!(
                            "exec_subordinate_e2e: LEFTOVER PROCESSES after the worker exited: pids={left:?}"
                        );
                        dump_diag(reaping, me);
                        kill_group(pgid);
                        s.reap_subtree(me);
                        let _ = s.wait_empty(me, crate::reap::reap_within());
                        s.remove_disposable_dirs();
                        std::process::exit(1);
                    }
                }
                match status.code() {
                    Some(c) => std::process::exit(c),
                    None => {
                        println!("exec_subordinate_e2e: worker terminated by a signal: {status}");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                println!(
                    "exec_subordinate_e2e: WATCHDOG EXPIRED (the test did not finish within the deadline; descendants were killed)"
                );
                println!(
                    "exec_subordinate_e2e: watchdog deadline_secs={} reason={e}",
                    limit.as_secs()
                );
                dump_diag(reaping, me);
                kill_group(pgid);
                if let Some(s) = reaping {
                    s.reap_subtree(me);
                }
                crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
                if let Some(s) = reaping {
                    let left = s.wait_empty(me, crate::reap::reap_within());
                    if !left.is_empty() {
                        eprintln!(
                            "exec_subordinate_e2e: processes remain after the kill: {left:?}"
                        );
                    }
                    s.remove_disposable_dirs();
                }
                std::process::exit(EXIT_WATCHDOG_EXPIRED);
            }
        }
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

    fn run() {
        begin("preconditions");
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
        // 親の watchdog を同伴として宣言する（`systemd-run --scope` では親と同じ cgroup にいて、退避の拒否〔他者の pid〕を
        // 避けるため。親も退避リーフへ一緒に移る）。
        let delegated = crate::precondition::delegated_cgroup().with_companions(&[watchdog_pid()]);

        begin("scratch-and-bundle");
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
        begin("create");
        create(&store, &recorder, &create_req).expect("create");
        begin("cgroup-chain");

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
        begin("remove-cgroup");
        let removed = delegated.remove_child(&container_cgroup);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        removed.expect("remove container cgroup");
        begin("cleanup");
        drop(work);
        finish();

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

    /// 期限つきで外部コマンドを実行して回収する（超えたら kill して回収し panic。REPAIR-5）。出力は一時ファイル経由で、
    /// 孫が pipe を持ち続けても戻る（#3409）。
    fn run_limited(mut cmd: std::process::Command) -> std::process::Output {
        crate::reap::output_within(&mut cmd, timeout())
            .unwrap_or_else(|e| panic!("run_limited: {e}"))
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

        begin("start");
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
            begin("wait-ready");
            wait_ready(hostdata);
            begin("record-readback");
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
            begin("exec-a");
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

            begin("exec-b");
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
            begin("overmount");
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

            begin("exec-c");
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
        begin("terminate");
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
        begin("wait-proc-gone");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid}")).exists()),
            "/proc/{pid} must disappear after terminate"
        );
        begin("wait-no-children");
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no child may remain after terminate"
        );
    }
}
