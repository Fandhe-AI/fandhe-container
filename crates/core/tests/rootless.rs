//! rootless 起動での OCI Runtime ライフサイクル（`create` → `start` → `kill`）の結合試験と、検証できない
//! 既知条件の記録（CORE-6・SEC-5・MS-2・TASK-40.4・#190・#2246）。
//!
//! 部品ごとの結合試験（`rootless_id_map`〔40.1〕・`rootless_launch`〔40.2〕・`rootless_file_owner`〔40.3〕）に
//! 対し、本ファイルは公開 API の `oci_runtime::{create, start, kill}` を **本番 `ProductionLauncher`** と
//! `FileStateStore` で非 root ユーザーから通し、起動されたコンテナプロセスを「ホスト視点」で検査する。
//! `oci_lifecycle.rs` の launcher は模擬で実プロセスも namespace 分離も使わないため、その不足を補う。
//!
//! libtest はマルチスレッドで、マルチスレッドからの `CLONE_NEWUSER`・fork は拒否されるため
//! `harness = false` の単一スレッド `main` で動かす（`rootless_launch` と同じ理由。`ProductionLauncher` も
//! 単一スレッドのプロセスだけを受け付ける）。非 Linux では OS 非該当（skip ではない）として成功終了する。
//!
//! # 受入基準の解釈（REPAIR-3）
//! - 「非 root で一連のライフサイクルが成功する」は、create → start → kill を実行し、各段の状態・revision・
//!   観測記録（REPAIR-4）と、起動したプロセスのホスト視点の写像（`/proc/<pid>/uid_map`・`gid_map`・
//!   `status`）で照合する。検証できるのは **create / start / kill と、kill 直後の delete の拒否まで**で、
//!   Running → Stopped の遷移と停止後の delete の成功は `crates/supervisor/tests/supervisor_bin_real.rs` のシナリオ D が照合する（下記「既知課題」）
//! - コンテナ PID 1 は実エントリポイント（#2012）。試験バイナリ自身を rootfs の `/entry` へコピーし、
//!   本番 launcher の `StagePipeline`（`with_landlock` 入り）で exec まで通して `--entry init` で再入させる
//!   （`tests/support/real_entry.rs`）。ホストの `/proc/<pid>` の pid は、この exec 後の PID 1（`NSpid` の末尾が 1、
//!   `cmdline` が `/entry --entry init`）で、`uid_map`・`gid_map`・`status` の照合もこの pid に対して行う。
//!   実エントリポイントの標準入出力は `/dev/null` へ置換されるため、コンテナ視点の観測値（pid・uid・gid・hostname・
//!   `NoNewPrivs`・`Seccomp`）は `/entry-report` へ書かせ、ホストが具体値で照合する
//! - 起動ハンドルの所有者は試験プロセス自身（`start` が返す `LaunchedProcess`。supervisor〔TASK-157〕の代わり）。
//!   本番 launcher の中間プロセスは PID 1 を作って終了し、PID 1 は child subreaper である試験プロセスへ再親付けされる
//!   ため、PID 1 の親（`PPid`）は試験プロセスになる。kill は保持したハンドルの `signal` へ委ねる `ProcessSignaler`
//!   （`HandleSignaler`）で行い、状態に記録された pid へ生の kill を送らない（SEC-1）
//! - 状態ストアは `FileStateStore`。start は本番 launcher が確定した分離の記録（`launch_isolation`）を Running の
//!   更新に載せるため、記録の存在と `/` の `(dev, ino)` が rootfs と一致することも照合する（SUP-6・SEC-1）
//! - 最終手段（#2250・CORE-1・REPAIR-5）: 試験専用の中間プロセスは #2368 で無くなり、本番の中間プロセスの固まりは
//!   `exec/launch_intermediate.rs` の単体テストが照合する。試験側では実エントリポイント（PID 1）に寿命の上限
//!   （`process.env` の `FANDHE_CONTAINER_TEST_ENTRY_LIFETIME_SECS`）を持たせ、上限が来たら固有の終了コードで
//!   自ら終わらせる（PID 1 が終われば PID namespace ごと落ちる）。試験プロセスが固まる・外から SIGKILL されても
//!   ホストに残るのは上限までになる。シナリオ `abandoned` は kill を送らない放置ハンドルでこれを照合し、
//!   各シナリオの終了後は `children_of_self()` が空であることも確かめる。親死亡時 SIGKILL（`PR_SET_PDEATHSIG`）の
//!   公開口は、PID 1 の親が設計上すぐ終わる中間プロセスのため成功した起動ごとに PID 1 を殺してしまうので足さない
//!
//! # 流れ
//! - ディスパッチャ: 一時 bundle（`config.json`・`rootfs/`・状態ルート）を排他的に作り、本番 launcher で
//!   `create` → `start` する
//! - モード `direct`: `RootlessSingleId`。`uid_map` は `0 <euid> 1`
//! - モード `helper`（`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ）: `RootlessSubordinateIds`
//!   （`SubordinateIdSource::system(USER)`）。`/etc/subuid`・`/etc/subgid` の範囲写像を `newuidmap` / `newgidmap`
//!   経由で書く。期待値は launcher と同じく subuid・subgid の両方を euid（と `USER`）の所有者で引く
//! - root で実行された場合は、plan が `host_root_identity_mapping` で拒否されること（SEC-5）と、本番経路で
//!   `RootlessSingleId` の start が拒否されて状態が Created のまま子が残らないこと・`RootlessSubordinateIds` の
//!   構築が `PermissionDenied` になることだけを照合する
//!
//! # 実機前提テストとしての分離
//! 非特権 user namespace を許可するホストと、Landlock ABI 6 以上（Linux 6.12 以上。実エントリポイントを exec まで
//! 通すため。満たさないと失敗する）が必要。cgroup の委譲は要らない（config に `linux.resources`・`cgroupsPath` を
//! 置かないため launcher は cgroup へ参加しない）。`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を
//! 出力して成功終了する（ci.md「実機前提テスト」。CI 通過のための弱体化ではない）。CI の
//! `platform-ci`（ubuntu）では #2596 で helper ケースを有効にして実行し、成功行を照合する（AppArmor 緩和の
//! `sudo sysctl` は CI が既に行う。root 分岐は CI で回さず #1621）。実行された場合は拒否を含むあらゆる失敗を失敗として扱い、検証せずに
//! 成功する分岐は持たない。
//!
//! # 既知課題・未検証の条件（ホスト設定などで本テストが検証できない、または未実装で検証しないもの）
//! - PID 1 の寿命の上限までの残り: 試験プロセスが外から SIGKILL された場合、PID 1 は上限（通常シナリオは
//!   `lifecycle_entry_lifetime`）の間ホストに残りうる。上限より短い間隔で繰り返し殺される場合は無力
//!   （外側の監視役 guard は導入しない。判断: 寿命の上限があるため残りは上限までに限られる。再親付けされた孫は
//!   subreaper と fail-closed の子の照合〔`leftover_children`〕で検出・回収できる。試験プロセスと無関係な別プロセスから
//!   PID 1 を止めるには、pid 指定の生の kill〔SEC-1 に反する〕か `sys` 外の新たな `unsafe`〔事前承認の範囲外〕が要り、
//!   guard 自身も CI のタイムアウトやプロセスグループ単位の kill で一緒に殺されうる。実機で人が実行する際の運用上の
//!   代替は `systemd-run --user --scope` の下で実行してスコープごと止めること。#2436）
//! - AppArmor の `kernel.apparmor_restrict_unprivileged_userns=1`（Ubuntu 23.10 以降・24.04 の既定）:
//!   非特権 user namespace での写像書き込みやマウントが拒否され、`PermissionDenied` で失敗する。緩和は
//!   sysctl を 0 にするか AppArmor プロファイルの付与（いずれも root 権限が必要）。CI が緩和しているのは
//!   `unshare_isolation` のみ
//! - `user.max_user_namespaces=0`・ディストリ固有の `kernel.unprivileged_userns_clone=0`:
//!   `CLONE_NEWUSER` が EPERM になる
//! - helper ケースの前提: `uidmap` パッケージ（setuid または file capability を持つ `newuidmap` /
//!   `newgidmap`）と、`/etc/subuid`・`/etc/subgid` の自ユーザー行。opt-in 時に無ければ失敗とする
//! - Docker コンテナ内（`make docker-ci` 等）: 既定の seccomp プロファイルが `CLONE_NEWUSER` を遮断し、
//!   マスクされた `/proc` で proc マウントも拒否されるため検証できない
//! - rootless の cgroup v2 委譲（systemd ユーザー slice の Delegate）: rootless 経路での cgroup 参加は
//!   未検証（TASK-32・CORE-3・CORE-4）
//! - SIGKILL 以外のシグナル（SIGTERM 等）の配送: 本試験は SIGKILL の kill の流れだけを範囲とする。常駐側の
//!   `ProcessSignaler`（制御チャネル）経由の SIGTERM の配送は `crates/supervisor/tests/supervisor_bin_real.rs` の
//!   シナリオ D が本番 launcher 経由で照合する（SUP-4・#2392）
//! - Running → Stopped の遷移と停止後の delete の成功: Stopped への遷移は起動ハンドルの所有者である
//!   supervisor（TASK-157）の責務。本試験は `kill` が状態を更新しない契約と、その結果 kill 直後の delete
//!   （TASK-30.2・#152）が `FailedPrecondition` で拒否され状態が残ることだけを照合し、状態の書き換えに
//!   よる代用はしない。遷移の記録と停止後の delete の成功（本番の remover）は `supervisor_bin_real` の
//!   シナリオ D が照合する（#2392）

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
#[path = "support/leftover_children.rs"]
mod leftover_children;

#[cfg(target_os = "linux")]
#[path = "support/real_entry.rs"]
mod real_entry;

#[cfg(target_os = "linux")]
#[path = "support/scratch_root.rs"]
mod scratch_root;

#[cfg(target_os = "linux")]
fn main() {
    // 前提欠如の分類の自己照合（既定のテスト集合でも常に走る。出力はしない。#2888）。
    real_entry::precondition::self_check();
    let args: Vec<String> = std::env::args().collect();
    if is_entry_mode(&args) {
        linux::entry_init();
    } else if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!("rootless: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)");
    }
}

/// 実エントリポイントへの再入か（CORE-6・REPAIR-12）。コンテナ PID 1 の argv は `/entry --entry init` で、
/// 第 1 引数（`args[1]`）だけを見る。ディスパッチャの argv（`<exe> --ignored`）は entry モードにならない。
#[cfg(target_os = "linux")]
fn is_entry_mode(args: &[String]) -> bool {
    args.get(1).is_some_and(|a| a == "--entry")
}

#[cfg(target_os = "linux")]
mod linux {
    use std::num::NonZeroU32;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::leftover_children::{assert_no_leftover_children, children_of_self};
    use super::real_entry;
    use fandhe_container_core::exec::{
        Hostname, IsolationConfig, Namespace, NamespaceSet, plan_rootless_subordinate,
    };
    use fandhe_container_core::observability::{OpName, OpRecorder};
    use fandhe_container_core::oci_runtime::{
        CgroupRemoval, ContainerCgroupRemover, KillTimeout, LaunchedProcess, ProcessExit,
        ProcessLauncher, ProcessSignaler, START_TIMEOUT_MAX, StartTimeouts, create, delete, kill,
        start,
    };
    use fandhe_container_core::rootless::{
        DEFAULT_HELPER_TIMEOUT, IdMapSet, IdMapWriter, single_id_mapping,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        CgroupScope, ContainerId, ContainerState, CreateRequest, DeleteRequest, ErrorCode,
        GetStateRequest, KillRequest, Signal, StartRequest, StateRevision, StateStore, TraitError,
    };

    const HOSTNAME: &str = "fandhe-rootless";

    /// 環境変数で受け付ける上限（秒）。start の全体上限 `DEFAULT_HELPER_TIMEOUT * 2 + t * 2` が
    /// `StartTimeouts::new` の 600 秒上限を超えないよう 295 秒で打ち切る。
    const MAX_TIMEOUT_SECS: u64 = 295;

    // 寿命の上限の定数・env の解析・見張りは `real_entry` に共有している（#2436・REPAIR-1）。
    use real_entry::{ENTRY_LIFETIME_MAX_SECS, EXIT_ENTRY_LIFETIME_EXPIRED};

    /// `abandoned` シナリオで使う短い寿命（秒）。
    const ABANDONED_LIFETIME_SECS: u64 = 3;

    /// 通常シナリオの PID 1 の寿命。1 シナリオの最悪の所要時間（start の全体上限 + 照合の各待ち + 後始末）より
    /// 長く取り、正常系では寿命に届く前に kill で終わる。試験プロセスが固まる・外から SIGKILL されても、
    /// PID 1 はこの時間で必ず消える（最終手段。下記 `entry_init`）。
    fn lifecycle_entry_lifetime() -> Duration {
        let t = start_timeouts();
        let start_total = t.launch() + t.terminate() + t.confirm();
        let secs =
            (start_total.as_secs() + timeout().as_secs() * 8 + 60).min(ENTRY_LIFETIME_MAX_SECS);
        Duration::from_secs(secs)
    }

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=MAX_TIMEOUT_SECS).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
    }

    /// `start` 全体の上限。helper ケースは 2 回の helper 呼び出し（中間プロセスは `2 × helper_timeout + 1` 秒待つ）が
    /// 要るため、既定の上限では足りない。`StartTimeouts` の上限（`START_TIMEOUT_MAX`）以下へ丸める。
    fn start_timeouts() -> StartTimeouts {
        let limit = (DEFAULT_HELPER_TIMEOUT * 2 + timeout() * 2).min(START_TIMEOUT_MAX);
        StartTimeouts::new(limit, timeout(), timeout()).expect("start timeouts")
    }

    fn own_ids() -> (u32, u32) {
        let id = |key: &str| -> u32 {
            std::fs::read_to_string("/proc/self/status")
                .expect("read status")
                .lines()
                .find(|l| l.starts_with(key))
                // 第 1 欄は real ID、第 2 欄が effective ID（兄弟テスト・plan_rootless_subordinate と同じ）。
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
        // 一時領域の親ディレクトリ（tmpfiles の掃除と flock 競合の回避）を panic でも消す（#2887）。
        let _scratch_cleanup = super::scratch_root::ScratchRootCleanup;
        // ディスパッチャの argv は entry モードと判定されず、PID 1 の argv は判定される（判定の回帰検出）。
        let dispatcher_argv: Vec<String> =
            ["x", "--ignored"].iter().map(|s| s.to_string()).collect();
        assert!(!super::is_entry_mode(&dispatcher_argv));
        let pid1: Vec<String> = ["/entry", "--entry", "init"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(super::is_entry_mode(&pid1));
        dispatcher();
    }

    // ---- 実エントリポイント（exec 後のコンテナ PID 1） ----

    /// 実エントリポイント `--entry init`（コンテナの PID 1。exec 後）。コンテナ視点の観測値を `/entry-report` へ
    /// 書いた後は、kill されるか寿命の上限が来るまで生きる（stdin は `/dev/null` のため EOF を待つ形にはしない）。
    ///
    /// 寿命の上限（`ENTRY_LIFETIME_ENV`。無い・不正なら `ENTRY_LIFETIME_MAX_SECS`）が来たら
    /// `EXIT_ENTRY_LIFETIME_EXPIRED` で自分から終わる。PID 1 が終わるとカーネルがその PID namespace の全プロセスを
    /// 終わらせるため、PID 1 の起動ハンドルを持つ試験プロセスが固まった場合や外から SIGKILL された場合（PID 1 が
    /// ホストの init へ再親付けされる）でも、ホストに残るのは寿命の上限までになる（#2250・CORE-1・REPAIR-5。
    /// `sys` の外に `unsafe` を置かずに済む試験側の最終手段）。
    pub fn entry_init() {
        let lifetime_secs = real_entry::arm_entry_lifetime();
        let mut lines = real_entry::entry_observations();
        lines.push(("lifetime_secs", lifetime_secs.to_string()));
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").map_or_else(
            |e| format!("error:{:?}", e.kind()),
            |s| s.trim().to_string(),
        );
        lines.push(("hostname", hostname));
        real_entry::write_report(&lines);
        loop {
            // 寿命の上限は見張りスレッドが担う。spurious wakeup はループで吸収する。
            std::thread::park();
        }
    }

    /// start が返した起動ハンドルを保持し、kill をそのハンドルへだけ委ねる signaler（テスト専用）。
    /// 状態に記録された pid へ生の kill は送らない（SEC-1）。常駐側は supervisor（TASK-157）が提供する。
    struct HandleSignaler {
        slot: Mutex<Option<(ContainerId, Box<dyn LaunchedProcess>)>>,
    }

    impl ProcessSignaler for HandleSignaler {
        fn signal(
            &self,
            id: &ContainerId,
            pid: NonZeroU32,
            signal: Signal,
            deadline: Instant,
        ) -> Result<(), TraitError> {
            let g = self.slot.lock().unwrap_or_else(|e| e.into_inner());
            match g.as_ref() {
                Some((hid, handle)) if hid == id && handle.pid() == pid => {
                    handle.signal(signal, deadline)
                }
                _ => Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "no matching launch handle",
                )),
            }
        }
    }

    /// テスト専用の `ContainerCgroupRemover`。cgroup は常に存在しない（`NotPresent`）として扱い、実 cgroup には
    /// 触れない（OS 非依存。cgroup 削除の結線は `oci_delete.rs`・`cgroup_delete.rs` が照合する。TASK-30.3）。
    /// `oci_runtime::create` は cgroup スコープを記録しないため、delete は本 fake を呼ばない。呼ばれた場合に
    /// 気付けるよう `scope` はエラーを返す（delete は照合できず失敗する）。
    struct NoCgroup;

    impl ContainerCgroupRemover for NoCgroup {
        fn scope(&self) -> Result<CgroupScope, TraitError> {
            Err(TraitError::new(
                ErrorCode::Internal,
                "no delegated cgroup in this test",
            ))
        }
        fn remove(
            &self,
            _id: &ContainerId,
            _instance: StateRevision,
        ) -> Result<CgroupRemoval, TraitError> {
            Ok(CgroupRemoval::NotPresent)
        }
    }

    // ---- bundle ----

    /// 一時 bundle（drop で削除）。
    struct Bundle(PathBuf);

    impl Drop for Bundle {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl Bundle {
        fn rootfs(&self) -> PathBuf {
            self.0.join("rootfs")
        }

        /// bundle 配下の状態ルート（`FileStateStore`）。bundle は 0700 で排他作成済み。
        fn open_store(&self) -> FileStateStore {
            FileStateStore::open(
                StateRoot::from_override(self.0.join("state")).expect("state root"),
            )
            .expect("open state store")
        }
    }

    /// `config.json` と `rootfs/`（`proc/`・実エントリポイント `/entry` とローダ・共有ライブラリ）を排他的に作る。
    /// `lifetime` は PID 1 の寿命の上限で、`process.env` へ秒で書く（`real_entry::lifetime_env`。`entry_init`）。
    /// `RootfsDir::pin` は symlink を含む祖先を拒否するため、temp は canonicalize する。
    fn make_bundle(label: &str, lifetime: Duration) -> Bundle {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base =
            super::scratch_root::scratch_root("fandhe-rootless-scratch", timeout()).join(format!(
                "fandhe-rootless-lifecycle-{label}-{}-{nanos}",
                std::process::id()
            ));
        std::fs::create_dir(&base).expect("exclusively create bundle dir");
        let bundle = Bundle(base);
        std::fs::set_permissions(&bundle.0, std::fs::Permissions::from_mode(0o700))
            .expect("chmod bundle");
        let ld = real_entry::install_entry(&bundle.rootfs());
        let mut env = real_entry::entry_env(&ld);
        env.push(real_entry::lifetime_env(lifetime));
        real_entry::write_rootless_config(
            &bundle.0,
            HOSTNAME,
            &real_entry::entry_args("init"),
            &env,
        );
        bundle
    }

    // ---- ディスパッチャ ----

    fn dispatcher() {
        let (euid, egid) = own_ids();
        if euid == 0 || egid == 0 {
            root_refused();
            return;
        }
        let mut modes: Vec<&'static str> = vec!["direct"];
        if helper_requested() {
            modes.push("helper");
        } else {
            println!("rootless: helper case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1)");
        }
        for mode in modes {
            lifecycle(mode, euid, egid);
        }
        abandoned(euid, egid);
    }

    /// 放置された起動ハンドル（#2250・CORE-1・REPAIR-5）: ハンドルの持ち主（試験プロセス）が kill を送らないまま
    /// 固まった状況を模す。PID 1 は寿命の上限で自分から終わり（`Exited(EXIT_ENTRY_LIFETIME_EXPIRED)`）、
    /// `/proc/<pid>` が消え、子が残らないことを照合する。寿命より早い終了・大きく遅れた終了はどちらも失敗にする。
    /// 本番の中間プロセスの固まりは `exec/launch_intermediate.rs` の単体テストが照合済み（試験側から注入する口は
    /// 本番コードに足さない）。
    fn abandoned(euid: u32, egid: u32) {
        let lifetime = Duration::from_secs(ABANDONED_LIFETIME_SECS);
        let bundle = make_bundle("abandoned", lifetime);
        let store = bundle.open_store();
        let rec = OpRecorder::new();
        let launcher = real_entry::rootless_launcher(false);
        let id = ContainerId::new("rootless-abandoned").expect("id");
        create(
            &store,
            &rec,
            &CreateRequest::new(id.clone(), bundle.0.clone()).expect("absolute bundle"),
        )
        .expect("create");
        real_entry::wait_single_thread();
        // PID 1 の寿命タイマーは entry_init の開始から数えるため、基準点は start() の前で採る
        // （start() の戻りが遅れても下限判定がフレークしない）。
        let began = Instant::now();
        let started = match start(
            &store,
            &rec,
            &launcher,
            &StartRequest::new(id.clone()),
            &start_timeouts(),
        ) {
            Ok(s) => s,
            Err(e) => panic!(
                "start failed: {:?} {} (may_have_left_process={}, children={:?})",
                e.code(),
                e.message(),
                launcher.last_launch_may_have_left_process(),
                children_of_self()
            ),
        };
        let (_record, handle) = started.into_parts();
        let pid = handle.pid().get();
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ready =
                real_entry::read_report(&bundle.rootfs().join(real_entry::REPORT_FILE), timeout());
            assert_eq!(ready.get("pid").map(String::as_str), Some("1"));
            assert_eq!(
                ready.get("lifetime_secs").map(String::as_str),
                Some(ABANDONED_LIFETIME_SECS.to_string().as_str())
            );
            // kill を送らずに待つ。寿命 + 余裕の間に PID 1 が自分で終わる。
            let exit = handle.wait(lifetime + timeout() * 2).expect("wait");
            assert_eq!(
                exit,
                Some(ProcessExit::Exited(EXIT_ENTRY_LIFETIME_EXPIRED)),
                "PID 1 must exit by its lifetime bound"
            );
            let elapsed = began.elapsed();
            assert!(
                elapsed + Duration::from_secs(1) >= lifetime,
                "PID 1 exited before its lifetime bound: {elapsed:?} < {lifetime:?}"
            );
            let gone = Instant::now() + timeout();
            while Path::new(&format!("/proc/{pid}")).exists() {
                assert!(
                    Instant::now() < gone,
                    "/proc/{pid} must disappear after the entrypoint is reaped"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_no_leftover_children(timeout(), "after the abandoned entrypoint exited");
        }));
        // 検証が途中で panic しても実機に PID 1 を残さない（回収済みなら terminate は何もしない）。
        let terminated = handle.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!("rootless: terminate after failed abandoned check also failed: {e:?}");
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        println!(
            "rootless: abandoned launch handle: PID 1 exited by its lifetime bound and left nothing behind (exit={EXIT_ENTRY_LIFETIME_EXPIRED}; host uid={euid}, gid={egid}; via ProductionLauncher)"
        );
    }

    /// root 実行（SEC-5）: コンテナ内 root をホスト root へ写す起動は試さず、拒否だけを照合する。
    /// plan の段階の拒否に加え、本番経路でも `RootlessSingleId` の start が拒否されて状態が Created のまま
    /// 子が残らないこと、`RootlessSubordinateIds` の構築が `PermissionDenied` になることを照合する。
    fn root_refused() {
        let uid = single_id_mapping(1000).expect("uid mapping");
        let gid = single_id_mapping(1000).expect("gid mapping");
        let err = plan_rootless_subordinate(&config(), uid, gid, IdMapWriter::Direct, timeout())
            .expect_err("root launch must be rejected");
        let v = err.violation.expect("violation record");
        assert_eq!(v.reason.as_str(), "host_root_identity_mapping");

        let refused = real_entry::build_rootless_launcher(true)
            .expect_err("root must be refused for the subordinate-id launcher");
        assert_eq!(refused.code(), ErrorCode::PermissionDenied);

        let bundle = make_bundle("root", lifecycle_entry_lifetime());
        let store = bundle.open_store();
        let rec = OpRecorder::new();
        let id = ContainerId::new("rootless-root-refused").expect("id");
        create(
            &store,
            &rec,
            &CreateRequest::new(id.clone(), bundle.0.clone()).expect("absolute bundle"),
        )
        .expect("create");
        let launcher = real_entry::rootless_launcher(false);
        real_entry::wait_single_thread();
        let err = match start(
            &store,
            &rec,
            &launcher,
            &StartRequest::new(id.clone()),
            &start_timeouts(),
        ) {
            Ok(_) => panic!("start must be refused for root (SEC-5)"),
            Err(e) => e,
        };
        assert_ne!(err.code(), ErrorCode::Timeout, "{}", err.message());
        assert_eq!(
            store
                .get(&GetStateRequest::new(id.clone()))
                .expect("stored")
                .status()
                .state(),
            ContainerState::Created
        );
        assert!(!launcher.last_launch_may_have_left_process());
        assert_no_leftover_children(timeout(), "after a refused root launch");
        println!("rootless: host root launch rejected (SEC-5, root=true)");
    }

    /// `/proc/<pid>/{uid_map,gid_map}` を (コンテナ内 ID, ホスト ID, 長さ) の列として読む。
    fn read_map(pid: u32, file: &str) -> Vec<(u32, u32, u32)> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/{file}"))
            .unwrap_or_else(|e| panic!("read {file}: {e}"));
        let mut rows: Vec<(u32, u32, u32)> = text
            .lines()
            .map(|l| {
                let mut it = l
                    .split_whitespace()
                    .map(|v| v.parse::<u32>().expect("number"));
                let row = (
                    it.next().expect("inside"),
                    it.next().expect("outside"),
                    it.next().expect("count"),
                );
                assert!(it.next().is_none(), "map line has 3 columns");
                row
            })
            .collect();
        rows.sort_unstable();
        rows
    }

    /// `/proc/<pid>/status` の `key` 行の値（key の後ろ。前後の空白を除く）。
    fn status_str(pid: u32, key: &str) -> String {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .expect("read status")
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
            .unwrap_or_else(|| panic!("status line {key} missing"))
    }

    fn expected_rows(set: &IdMapSet) -> Vec<(u32, u32, u32)> {
        let mut rows: Vec<_> = set
            .entries()
            .iter()
            .map(|e| (e.container_id, e.host_id, e.count))
            .collect();
        rows.sort_unstable();
        rows
    }

    /// `/proc/<pid>/status` の `Uid:` / `Gid:` 行の 4 つの ID（real・effective・saved・fs）。
    fn status_ids(pid: u32, key: &str) -> Vec<u32> {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .expect("read status")
            .lines()
            .find(|l| l.starts_with(key))
            .map(|l| {
                l.split_whitespace()
                    .skip(1)
                    .map(|v| v.parse().expect("id"))
                    .collect()
            })
            .expect("status line")
    }

    fn op_stats(rec: &OpRecorder, name: &str) -> (u64, u64) {
        let s = rec
            .snapshot_op(&OpName::new(name).expect("name"))
            .expect("recorded");
        (s.success(), s.failure())
    }

    /// 1 経路分の create → start → ホスト視点検証 → kill → 後始末の照合。拒否を含むあらゆる失敗は panic。
    /// 起動済みのハンドルは `HandleSignaler` の slot に預け、成否に関わらず最後に `terminate` して回収する
    /// （`LaunchedProcess` は Drop で終了・回収しないため、試験が失敗しても実機に PID 1 を残さない）。
    fn lifecycle(mode: &'static str, euid: u32, egid: u32) {
        let bundle = make_bundle(mode, lifecycle_entry_lifetime());
        let store = bundle.open_store();
        let rec = OpRecorder::new();
        let launcher: Arc<dyn ProcessLauncher> = real_entry::rootless_launcher(mode == "helper");
        let signaler_impl = Arc::new(HandleSignaler {
            slot: Mutex::new(None),
        });
        let signaler: Arc<dyn ProcessSignaler> = signaler_impl.clone();
        let id_str = format!("rootless-{mode}");
        let id = ContainerId::new(&id_str).expect("id");

        // create: Created・pid なし・revision 0（`FileStateStore` の最初の 1 件は `StateRevision::INITIAL`）。
        let created = create(
            &store,
            &rec,
            &CreateRequest::new(id.clone(), bundle.0.clone()).expect("absolute bundle"),
        )
        .expect("create");
        assert_eq!(created.status().state(), ContainerState::Created);
        assert_eq!(created.status().pid(), None);
        assert_eq!(created.revision(), StateRevision::INITIAL);
        assert_eq!(created.revision().value(), 0);

        // start（本番 launcher は単一スレッドのプロセスだけを受け付ける）。
        real_entry::wait_single_thread();
        let started = start(
            &store,
            &rec,
            &launcher,
            &StartRequest::new(id.clone()),
            &start_timeouts(),
        )
        .unwrap_or_else(|e| {
            panic!(
                "start failed: {:?} {} (may_have_left_process={}, children={:?})",
                e.code(),
                e.message(),
                launcher.last_launch_may_have_left_process(),
                children_of_self()
            )
        });
        let (record, handle) = started.into_parts();
        let pid = handle.pid();
        *signaler_impl.slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((id.clone(), handle));

        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_started_and_kill(
                mode,
                (euid, egid),
                &bundle,
                &store,
                &rec,
                &signaler,
                &signaler_impl,
                &id,
                &record,
                pid,
            );
        }));
        // 後始末: 回収済みなら何もしない。未回収（検証が途中で panic した）なら terminate で kill・回収する。
        let leftover = signaler_impl
            .slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let terminated = leftover.map(|(_, handle)| handle.terminate(timeout()));
        if let Err(p) = verified {
            // 検証側の panic を優先する。terminate の失敗で元の panic を覆い隠さない。
            if let Some(Err(e)) = &terminated {
                eprintln!("rootless: terminate after failed verification also failed: {e:?}");
            }
            std::panic::resume_unwind(p);
        }
        if let Some(t) = terminated {
            t.expect("terminate");
        }
        // 終了後に子が残っていない（PID 1 の取り残しがない）ことを fail-closed で確かめる（#2250）。
        assert_no_leftover_children(timeout(), "after the lifecycle scenario finished");

        println!(
            "rootless: scenario {mode} lifecycle verified with the real entrypoint as PID 1 (create/start/kill/delete-rejected; host uid={euid}; via ProductionLauncher)"
        );
    }

    /// `start` が返した記録とハンドルのホスト視点の照合（写像・実エントリポイント・コンテナ視点の観測値）と、
    /// kill 以降の流れの照合。
    // 照合対象（bundle・store・記録・ハンドル・期待値）は呼び出し元の試験が個別に持つ独立した値で、
    // 構造体へまとめても名前付けが増えるだけのため、この引数数のまま維持する。
    #[allow(clippy::too_many_arguments)]
    fn verify_started_and_kill(
        mode: &str,
        (euid, egid): (u32, u32),
        bundle: &Bundle,
        store: &FileStateStore,
        rec: &OpRecorder,
        signaler: &Arc<dyn ProcessSignaler>,
        signaler_impl: &HandleSignaler,
        id: &ContainerId,
        record: &fandhe_container_core::traits::StateRecord,
        pid: NonZeroU32,
    ) {
        assert_eq!(record.status().state(), ContainerState::Running);
        // 起動権の予約 update（0 → 1）と Running 記録の update（1 → 2）の 2 回。
        assert_eq!(record.revision().value(), 2);
        assert_eq!(record.status().pid(), Some(pid));
        assert_eq!(
            &store
                .get(&GetStateRequest::new(id.clone()))
                .expect("stored"),
            record
        );
        // 本番 launcher が確定した分離の記録（SUP-6・SEC-1）。`/` の識別子は rootfs ディレクトリの (dev, ino) と一致する。
        let iso = record
            .launch_isolation()
            .expect("launch_isolation must be recorded by the production launcher");
        let root_meta = std::fs::metadata(bundle.rootfs()).expect("stat rootfs");
        assert_eq!(iso.root().dev(), root_meta.dev());
        assert_eq!(iso.root().ino(), root_meta.ino());

        // ホスト視点の rootless 検証（SEC-5・CORE-6）。
        let p = pid.get();
        let (uid_set, gid_set) = match mode {
            "direct" => (
                single_id_mapping(euid).expect("uid"),
                single_id_mapping(egid).expect("gid"),
            ),
            _ => real_entry::helper_mappings(euid, egid),
        };
        assert_eq!(read_map(p, "uid_map"), expected_rows(&uid_set));
        assert_eq!(read_map(p, "gid_map"), expected_rows(&gid_set));
        if mode == "direct" {
            assert_eq!(read_map(p, "uid_map"), vec![(0, euid, 1)]);
            assert_eq!(read_map(p, "gid_map"), vec![(0, egid, 1)]);
        }
        assert_eq!(status_ids(p, "Uid:"), vec![euid; 4]);
        assert_eq!(status_ids(p, "Gid:"), vec![egid; 4]);
        assert_ne!(euid, 0);

        // 実エントリポイントであることの照合（#2012）: ホストの pid は exec 後の PID 1。
        let nspid = status_str(p, "NSpid:");
        let levels: Vec<&str> = nspid.split_whitespace().collect();
        assert_eq!(levels.len(), 2, "NSpid must have two levels: {nspid:?}");
        assert_eq!(levels.first().copied(), Some(p.to_string().as_str()));
        assert_eq!(levels.last().copied(), Some("1"));
        assert_eq!(
            std::fs::read(format!("/proc/{p}/cmdline")).expect("read cmdline"),
            b"/entry\0--entry\0init\0".to_vec(),
            "the host pid must be the exec'd real entrypoint"
        );
        // 本番 launcher の中間プロセスは PID 1 を作って終了し、PID 1 は child subreaper である試験プロセスへ
        // 再親付けされる（起動ハンドルの所有者は試験プロセス）。
        assert_eq!(
            status_str(p, "PPid:"),
            std::process::id().to_string(),
            "the parent of the entrypoint must be the test process (child subreaper)"
        );
        // コンテナ視点の観測値（`/entry-report`）。
        let ready =
            real_entry::read_report(&bundle.rootfs().join(real_entry::REPORT_FILE), timeout());
        let field = |k: &str| ready.get(k).map(String::as_str).unwrap_or("missing");
        assert_eq!(field("pid"), "1");
        assert_eq!(field("uid"), "0");
        assert_eq!(field("gid"), "0");
        assert_eq!(field("hostname"), HOSTNAME);
        // 見張り（寿命の上限）が期待どおりの値で張られたこと（#2436・REPAIR-12）。
        assert_eq!(
            field("lifetime_secs"),
            lifecycle_entry_lifetime().as_secs().to_string()
        );
        assert_eq!(field("nonewprivs"), "1");
        assert_eq!(field("seccomp"), "2");
        // 別の user namespace にいることは、初期 namespace の恒等写像ではない上の uid_map の完全一致で
        // 保証される（`/proc/<pid>/ns/user` の readlink は ptrace 権限検査を伴い環境差が大きいため使わない）。

        // kill: 戻り値は照合時点の状態（Running）で、状態は更新されない。
        let status = kill(
            store,
            rec,
            signaler,
            &KillRequest::new(id.clone(), Signal::SIGKILL),
            &KillTimeout::default(),
        )
        .expect("kill");
        assert_eq!(status.state(), ContainerState::Running);

        // 終了の確認（起動ハンドルで回収）。
        let exit = signaler_impl
            .slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .expect("handle")
            .1
            .wait(timeout())
            .expect("wait");
        // 寿命の上限が誤って短いと `Exited(EXIT_ENTRY_LIFETIME_EXPIRED)` になりここで失敗する。
        assert_eq!(exit, Some(ProcessExit::Signaled(9)));
        // 回収後は PID 1 のホスト側の /proc も消える。
        let gone_deadline = Instant::now() + timeout();
        while Path::new(&format!("/proc/{p}")).exists() {
            assert!(
                Instant::now() < gone_deadline,
                "/proc/{p} must disappear after the entrypoint is reaped"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        // kill 後も状態は Running のまま（Stopped への遷移は supervisor〔TASK-157〕の責務。書き換えない）。
        let after = store
            .get(&GetStateRequest::new(id.clone()))
            .expect("stored");
        assert_eq!(after.status().state(), ContainerState::Running);
        assert_eq!(after.status().pid(), Some(pid));

        // 2 回目の kill は回収済みのハンドルへ送らず FailedPrecondition（SEC-1）。
        let err = kill(
            store,
            rec,
            signaler,
            &KillRequest::new(id.clone(), Signal::SIGKILL),
            &KillTimeout::default(),
        )
        .expect_err("second kill");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);

        // kill 直後の delete は Running・pid ありとして拒否され、状態・revision は残る（CORE-2・TASK-30.2）。
        let err = delete(store, rec, &NoCgroup, &DeleteRequest::new(id.clone()))
            .expect_err("delete running");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);
        assert_eq!(err.message(), "container is still running");
        assert_eq!(
            store
                .get(&GetStateRequest::new(id.clone()))
                .expect("stored"),
            after
        );

        // 観測記録（REPAIR-4）。
        assert_eq!(op_stats(rec, "create"), (1, 0));
        assert_eq!(op_stats(rec, "start"), (1, 0));
        assert_eq!(op_stats(rec, "kill"), (1, 1));
        assert_eq!(op_stats(rec, "delete"), (0, 1));
    }
}
