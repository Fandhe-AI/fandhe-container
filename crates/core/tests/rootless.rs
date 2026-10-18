//! rootless 起動での OCI Runtime ライフサイクル（`create` → `start` → `kill`）の結合試験と、検証できない
//! 既知条件の記録（CORE-6・SEC-5・MS-2・TASK-40.4・#190）。
//!
//! 部品ごとの結合試験（`rootless_id_map`〔40.1〕・`rootless_launch`〔40.2〕・`rootless_file_owner`〔40.3〕）に
//! 対し、本ファイルは公開 API の `oci_runtime::{create, start, kill}` を非 root ユーザーから通し、
//! 起動されたコンテナプロセスを「ホスト視点」で検査する。`oci_lifecycle.rs` の launcher は模擬で実プロセスも
//! namespace 分離も使わないため、その不足を補う。
//!
//! libtest はマルチスレッドで、マルチスレッドからの `CLONE_NEWUSER`・fork は拒否されるため
//! `harness = false` の単一スレッド `main` で動かす（`rootless_launch` と同じ理由）。非 Linux では
//! OS 非該当（skip ではない）として成功終了する。
//!
//! # 受入基準の解釈（REPAIR-3）
//! - 「非 root で一連のライフサイクルが成功する」は、create → start → kill を実行し、各段の状態・revision・
//!   観測記録（REPAIR-4）と、起動したプロセスのホスト視点の写像（`/proc/<pid>/uid_map`・`gid_map`・
//!   `status`）で照合する。検証できるのは **create / start / kill と、kill 直後の delete の拒否まで**で、
//!   Running → Stopped の遷移と停止後の delete の成功は未検証（下記「既知課題」）
//! - コンテナ PID 1 は実エントリポイント（#2012）。試験バイナリ自身を rootfs の `/entry` へコピーし、
//!   `StagePipeline::with_landlock` を載せたステージ列（`tests/support/real_entry.rs`）で exec まで通して
//!   `--entry init` で再入させる。ホストの `/proc/<pid>` の pid は、この exec 後の PID 1（`NSpid` の末尾が 1、
//!   `cmdline` が `/entry --entry init`）で、`uid_map`・`gid_map`・`status` の照合もこの pid に対して行う。
//!   実エントリポイントの標準入出力は `/dev/null` へ置換されるため、コンテナ視点の観測値（pid・uid・gid・hostname・
//!   `NoNewPrivs`・`Seccomp`）は `/entry-report` へ書かせ、ホストが具体値で照合する
//! - 起動ハンドルの所有者は supervisor（TASK-157）を模した中間プロセス（`isolate_rootless_subordinate` を通り、
//!   実エントリポイントの親になる）。ホスト側のディスパッチャは PID 1 へ直接シグナルを送れない（子ではない）ため、
//!   kill は stdin の `KILL` 行で中間プロセスへ中継し、中間プロセスが `ContainerChild` で SIGKILL・回収して
//!   `EXIT` 行で終了状態を返す。stdin が EOF になれば（ディスパッチャが panic しても）PID 1 を kill・回収してから
//!   終わる（孤児が残らない）
//!
//! # 流れ
//! - ディスパッチャ: 一時 bundle（`config.json`・`rootfs/`）を排他的に作り、`start` へ渡す
//!   `ProcessLauncher` の実装（`RootlessLauncher`）が自身を `--scenario container ...` で再起動して
//!   中間プロセスとする。kill は保持している起動ハンドルへ送る `ProcessSignaler`（`HandleSignaler`）で行い、
//!   状態に記録された pid へ生の kill を送らない（SEC-1）
//! - モード `direct`: `single_id_mapping` と `IdMapWriter::Direct`。`uid_map` は `0 <euid> 1`
//! - モード `helper`（`FANDHE_CONTAINER_TEST_ID_HELPER=1` の時だけ）: `/etc/subuid`・`/etc/subgid` の
//!   範囲写像を `newuidmap` / `newgidmap` 経由で書く
//! - root で実行された場合は、plan が `host_root_identity_mapping` で拒否されること（SEC-5）だけを照合する
//!
//! # 実機前提テストとしての分離
//! 非特権 user namespace を許可するホストと、Landlock ABI 6 以上（Linux 6.12 以上。実エントリポイントを exec まで
//! 通すため。満たさないと失敗する）が必要。`-- --ignored` 指定時のみ実行し、未指定時は「ignored」を
//! 出力して成功終了する（ci.md「実機前提テスト」。CI 通過のための弱体化ではない）。CI の
//! `platform-ci` への組み込みは別 PR（ci.yml は infra-builder 担当・AppArmor 緩和の
//! `sudo sysctl` は root 権限コマンド）。実行された場合は拒否を含むあらゆる失敗を失敗として扱い、検証せずに
//! 成功する分岐は持たない。
//!
//! # 既知課題・未検証の条件（ホスト設定などで本テストが検証できない、または未実装で検証しないもの）
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
//!   未実装・未検証（TASK-32・CORE-3・CORE-4）
//! - SIGKILL 以外のシグナル（SIGTERM 等）の配送: 本テストの起動ハンドルが std のみで作られており送れない。
//!   本番の `ProcessSignaler` は supervisor（TASK-157）が提供する
//! - Running → Stopped の遷移と停止後の delete の成功: Stopped への遷移は起動ハンドルの所有者である
//!   supervisor（TASK-157）の責務。`kill` が状態を更新しない契約と、その結果 kill 直後の delete
//!   （TASK-30.2・#152）が `FailedPrecondition` で拒否され状態が残ることだけを照合し、状態の書き換えに
//!   よる代用はしない（停止後の delete の成功は `oci_lifecycle.rs`・`oci_delete.rs` が状態を直接作って
//!   照合する）。supervisor の実装後に本テストへ追加する
//! - SEC-1 契約からの逸脱（テスト専用）: 固定した rootfs の fd は CLOEXEC で閉じられ、std だけでは子へ
//!   継承できない。そのため子の側で `spec.rootfs()` を stat し、渡された (dev, ino) と一致することを
//!   確かめてから使う。本番 launcher（TASK-29・TASK-157 系）は fd を渡す

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("rootless: Linux only, not applicable on this OS");
}

#[cfg(target_os = "linux")]
#[path = "support/real_entry.rs"]
mod real_entry;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if is_entry_mode(&args) {
        linux::entry_init();
    } else if std::env::args().any(|a| a == "--ignored" || a == "--scenario") {
        linux::run();
    } else {
        println!("rootless: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)");
    }
}

/// 実エントリポイントへの再入か（CORE-6・REPAIR-12）。コンテナ PID 1 の argv は `/entry --entry init` で、
/// 第 1 引数（`args[1]`）だけを見る。中間プロセスは `--scenario container ... -- /entry --entry init` と
/// 同じ語を後方に持つため、引数全体の探索では誤って entry 側に入る。
#[cfg(target_os = "linux")]
fn is_entry_mode(args: &[String]) -> bool {
    args.get(1).is_some_and(|a| a == "--entry")
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::io::{BufRead as _, Read as _, Write as _};
    use std::num::NonZeroU32;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::real_entry;
    use fandhe_container_core::exec::{
        ChildExit, Hostname, IsolationConfig, IsolationPrivilege, Namespace, NamespaceSet,
        isolate_rootless_subordinate, plan_rootless_subordinate,
    };
    use fandhe_container_core::observability::{OpName, OpRecorder};
    use fandhe_container_core::oci_runtime::{
        CgroupRemoval, ContainerCgroupRemover, KillTimeout, LaunchSpec, LaunchedProcess,
        ProcessExit, ProcessLauncher, ProcessSignaler, StartTimeouts, create, delete, kill, start,
    };
    use fandhe_container_core::rootless::{
        DEFAULT_HELPER_TIMEOUT, HelperPaths, IdMapSet, IdMapWriter, SubIdOwner, WriterKind,
        load_subordinate_ids, rootless_mapping, single_id_mapping,
    };
    use fandhe_container_core::traits::{
        CgroupScope, ContainerId, ContainerState, CreateRequest, CreateStateRequest, DeleteRequest,
        DeleteStateRequest, DeleteStateResponse, ErrorCode, GetStateRequest, KillRequest,
        ListStateRequest, Signal, StartRequest, StateList, StateRecord, StateRevision, StateStore,
        TraitError, UpdateStateRequest,
    };

    const HOSTNAME: &str = "fandhe-rootless";
    /// 中間プロセスが PID 1 の `/entry-report` を確認した後に出す行の接頭辞（続けて PID 1 のホスト pid）。
    const READY_PREFIX: &str = "READY pid=";
    /// PID 1 が起動完了時に書く報告ファイル（コンテナ内では `/entry-report`）。
    const READY_FILE: &str = real_entry::REPORT_FILE;
    /// READY 行・stderr の読み取り上限（バイト）。無制限確保を避ける。
    const LINE_CAP: u64 = 256;
    const STDERR_CAP: u64 = 16 * 1024;

    /// 環境変数で受け付ける上限（秒）。start の全体上限 `DEFAULT_HELPER_TIMEOUT * 2 + t * 2` が
    /// `StartTimeouts::new` の 600 秒上限を超えないよう 295 秒で打ち切る。
    const MAX_TIMEOUT_SECS: u64 = 295;

    fn timeout() -> Duration {
        let secs = std::env::var("FANDHE_CONTAINER_TEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|s| (1..=MAX_TIMEOUT_SECS).contains(s))
            .unwrap_or(10);
        Duration::from_secs(secs)
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

    /// 経路（`direct` / `helper`）ごとの UID・GID 写像と書き込み経路。
    fn mappings_for(
        mode: &str,
        euid: u32,
        egid: u32,
    ) -> (IdMapSet, IdMapSet, IdMapWriter, WriterKind) {
        match mode {
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
            other => panic!("unknown mode {other}"),
        }
    }

    pub fn run() {
        let args: Vec<String> = std::env::args().collect();
        // 中間プロセスの argv は entry モードと判定されない（判定の回帰検出）。
        let intermediate: Vec<String> = [
            "x",
            "--scenario",
            "container",
            "--",
            "/entry",
            "--entry",
            "init",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert!(!super::is_entry_mode(&intermediate));
        let pid1: Vec<String> = ["/entry", "--entry", "init"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(super::is_entry_mode(&pid1));
        match args.iter().position(|a| a == "--scenario") {
            Some(i) => {
                let rest: Vec<&str> = args.iter().skip(i + 1).map(String::as_str).collect();
                container_scenario(&rest);
            }
            None => dispatcher(),
        }
    }

    // ---- 実エントリポイント（exec 後のコンテナ PID 1） ----

    /// 実エントリポイント `--entry init`（コンテナの PID 1。exec 後）。コンテナ視点の観測値を `/entry-report` へ
    /// 書いた後は、kill されるまで生き続ける（stdin は `/dev/null` のため EOF を待つ形にはしない）。
    pub fn entry_init() {
        let mut lines = real_entry::entry_observations();
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").map_or_else(
            |e| format!("error:{:?}", e.kind()),
            |s| s.trim().to_string(),
        );
        lines.push(("hostname", hostname));
        real_entry::write_report(&lines);
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // ---- 中間プロセス側（分離され、実エントリポイントの親になる） ----

    /// 引数: `container <rootfs> <hostname> <dev> <ino> <direct|helper> -- <args...> --env <env...>`。
    /// 失敗はすべて panic（非 0 終了。launcher 側は READY 未着として `Err` にする）。
    fn container_scenario(args: &[&str]) {
        let [name, rootfs, hostname, dev, ino, mode, "--", rest @ ..] = args else {
            panic!(
                "usage: container <rootfs> <hostname> <dev> <ino> <direct|helper> -- <args> --env <env>"
            );
        };
        assert_eq!(*name, "container");
        let env_at = rest
            .iter()
            .position(|a| *a == "--env")
            .expect("--env separator");
        let entry_args: Vec<String> = rest[..env_at].iter().map(|s| s.to_string()).collect();
        let entry_env: Vec<String> = rest[env_at + 1..].iter().map(|s| s.to_string()).collect();
        let rootfs = Path::new(rootfs);
        let want_dev: u64 = dev.parse().expect("dev");
        let want_ino: u64 = ino.parse().expect("ino");
        let (euid, egid) = own_ids();
        let (uid, gid, writer, want_kind) = mappings_for(mode, euid, egid);

        let cfg = IsolationConfig {
            hostname: Some(Hostname::new(*hostname).expect("hostname")),
            ..config()
        };
        let plan = plan_rootless_subordinate(
            &cfg,
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
        // namespace 内ではコンテナ root（uid 0・gid 0）に見える（SEC-5）。
        assert_eq!(own_ids(), (0, 0));

        // テスト専用の逸脱（冒頭の「既知課題」参照）: 固定 fd の代わりに (dev, ino) で同一性を確かめる。
        let meta = std::fs::metadata(rootfs).expect("stat rootfs");
        assert_eq!((meta.dev(), meta.ino()), (want_dev, want_ino));

        // launcher が `LaunchSpec` から渡した args / env で、実エントリポイントを PID 1 として exec まで通す。
        let entry = real_entry::entrypoint_from(&entry_args, &entry_env);
        let child = real_entry::spawn_real_entry(rootfs, &entry, &report.id_maps.gid);

        // PID 1 が `/entry-report` を書くまで待つ。早期の終了・期限切れは PID 1 を残さず失敗にする。
        let ready_path = rootfs.join(READY_FILE);
        let deadline = Instant::now() + timeout();
        loop {
            if real_entry::try_read_report(&ready_path).is_some() {
                break;
            }
            if let Some(exit) = child
                .wait_for_exit(Duration::ZERO)
                .expect("poll the entrypoint")
            {
                println!("FAILED exit={exit:?}");
                std::process::exit(1);
            }
            if Instant::now() >= deadline {
                let _ = child.kill_and_reap(timeout());
                println!("FAILED ready-timeout");
                std::process::exit(1);
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let mut out = std::io::stdout();
        writeln!(out, "{READY_PREFIX}{}", child.pid()).expect("write READY");
        out.flush().expect("flush READY");

        // kill の中継: stdin の `KILL` 行で PID 1 を SIGKILL・回収して結果を返す。stdin が EOF になった
        // （launcher・ディスパッチャが消えた）場合も PID 1 を kill・回収してから終わる（孤児を残さない）。
        let mut line = String::new();
        let mut stdin = std::io::BufReader::new(std::io::stdin().take(LINE_CAP));
        let requested = stdin.read_line(&mut line).map(|n| n > 0).unwrap_or(false);
        let exit = child
            .kill_and_reap(timeout())
            .unwrap_or_else(|e| panic!("kill and reap: {e}"));
        if requested && line.trim_end() == "KILL" {
            let text = match exit {
                ChildExit::Exited(n) => format!("EXIT Exited {n}"),
                ChildExit::Signaled(n) => format!("EXIT Signaled {n}"),
                other => panic!("unexpected exit state {other:?}"),
            };
            writeln!(out, "{text}").expect("write EXIT");
            out.flush().expect("flush EXIT");
        }
    }

    // ---- launcher 側（ディスパッチャ内で start が呼ぶ） ----

    /// PID 1 の起動ハンドル。実体は中間プロセス（`Child`）で、kill はその stdin へ中継する。回収済み（終了を記録済み）かを
    /// 自前で管理する（pid 再利用対策の判定は自前で行う。SEC-1）。
    struct RealInitProcess {
        /// PID 1 のホスト pid（中間プロセスの `ContainerChild::pid`）。
        pid: NonZeroU32,
        inner: Mutex<InitState>,
    }

    struct InitState {
        intermediary: Child,
        stdin: Option<ChildStdin>,
        lines: mpsc::Receiver<String>,
        exit: Option<ProcessExit>,
    }

    /// `EXIT Exited <n>` / `EXIT Signaled <n>` を `ProcessExit` へ解釈する。
    fn parse_exit(line: &str) -> Option<ProcessExit> {
        let mut it = line.split_whitespace();
        if it.next()? != "EXIT" {
            return None;
        }
        let kind = it.next()?;
        let n: i32 = it.next()?.parse().ok()?;
        match kind {
            "Exited" => Some(ProcessExit::Exited(n)),
            "Signaled" => Some(ProcessExit::Signaled(n)),
            _ => None,
        }
    }

    /// 中間プロセスの終了を期限つきで待つ。超過したら kill して回収する（PID 1 が孤児になり得る最終手段）。
    fn reap_intermediary(child: &mut Child, limit: Duration) {
        let deadline = Instant::now() + limit;
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    impl RealInitProcess {
        fn lock(&self) -> std::sync::MutexGuard<'_, InitState> {
            self.inner.lock().unwrap_or_else(|e| e.into_inner())
        }

        /// `KILL` を中継し、`deadline` までに返る `EXIT` 行を記録する。記録後は中間プロセスも回収する。
        fn relay_kill(st: &mut InitState, deadline: Instant) -> Result<ProcessExit, TraitError> {
            let internal = |msg: &'static str| TraitError::new(ErrorCode::Internal, msg);
            let stdin = st
                .stdin
                .as_mut()
                .ok_or_else(|| internal("the kill channel is closed"))?;
            writeln!(stdin, "KILL")
                .and_then(|()| stdin.flush())
                .map_err(|_| internal("failed to relay the kill request"))?;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match st.lines.recv_timeout(left) {
                    Ok(line) => {
                        if let Some(exit) = parse_exit(line.trim_end()) {
                            st.exit = Some(exit);
                            st.stdin = None;
                            reap_intermediary(&mut st.intermediary, timeout());
                            return Ok(exit);
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        return Err(TraitError::new(
                            ErrorCode::Timeout,
                            "the entrypoint was not reaped within the timeout",
                        ));
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(internal("the intermediary closed without reporting EXIT"));
                    }
                }
            }
        }
    }

    impl LaunchedProcess for RealInitProcess {
        fn pid(&self) -> NonZeroU32 {
            self.pid
        }

        fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
            let deadline = Instant::now() + timeout;
            loop {
                if let Some(exit) = self.lock().exit {
                    return Ok(Some(exit));
                }
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
            let mut st = self.lock();
            if st.exit.is_none() {
                Self::relay_kill(&mut st, Instant::now() + timeout)?;
            }
            Ok(())
        }

        fn signal(&self, signal: Signal, deadline: Instant) -> Result<(), TraitError> {
            let mut st = self.lock();
            if Instant::now() >= deadline {
                return Err(TraitError::new(
                    ErrorCode::Timeout,
                    "the signal deadline has passed",
                ));
            }
            if st.exit.is_some() {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "the container process has already exited",
                ));
            }
            if signal != Signal::SIGKILL {
                return Err(TraitError::new(
                    ErrorCode::Unimplemented,
                    "only SIGKILL can be relayed to the entrypoint",
                ));
            }
            Self::relay_kill(&mut st, deadline).map(|_| ())
        }
    }

    impl Drop for RealInitProcess {
        /// ディスパッチャが途中で panic しても PID 1 を残さない: stdin を閉じて中間プロセスに kill・回収させる。
        fn drop(&mut self) {
            let st = self.inner.get_mut().unwrap_or_else(|e| e.into_inner());
            st.stdin = None;
            reap_intermediary(&mut st.intermediary, timeout() * 2);
        }
    }

    /// 自身を `--scenario container ...` で再起動し、中間プロセス経由で実エントリポイントを起動する launcher（テスト専用）。
    ///
    /// SEC-1 契約からの逸脱と理由は冒頭の「既知課題」を参照（rootfs は (dev, ino) の照合で代替）。
    struct RootlessLauncher {
        mode: &'static str,
    }

    /// 失敗時の後始末。中間プロセスを直接 kill すると PID 1 が孤児になるため、まず stdin を閉じて中間プロセス自身に
    /// PID 1 を kill・回収させ、終わらないときだけ kill する。
    fn launch_failed(
        child: &mut Child,
        stdin: Option<ChildStdin>,
        code: ErrorCode,
        msg: &'static str,
    ) -> TraitError {
        drop(stdin);
        reap_intermediary(child, timeout() * 2 + Duration::from_secs(5));
        TraitError::new(code, msg)
    }

    impl ProcessLauncher for RootlessLauncher {
        fn launch(
            &self,
            spec: &LaunchSpec,
            timeout: Duration,
        ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            let pinned =
                std::fs::File::from(spec.rootfs_dir().as_fd().try_clone_to_owned().map_err(
                    |_| TraitError::new(ErrorCode::Internal, "pinned rootfs fd is invalid"),
                )?)
                .metadata()
                .map_err(|_| TraitError::new(ErrorCode::Internal, "pinned rootfs fstat failed"))?;
            let hostname = spec
                .hostname()
                .ok_or_else(|| TraitError::new(ErrorCode::Internal, "hostname is required"))?;
            let exe = std::env::current_exe()
                .map_err(|_| TraitError::new(ErrorCode::Internal, "current_exe failed"))?;
            // 引数は配列で渡し、シェルを介さない。
            let mut child = Command::new(exe)
                .args(["--scenario", "container"])
                .arg(spec.rootfs())
                .arg(hostname)
                .arg(pinned.dev().to_string())
                .arg(pinned.ino().to_string())
                .arg(self.mode)
                .arg("--")
                .args(spec.args())
                .arg("--env")
                .args(spec.env())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|_| {
                    TraitError::new(ErrorCode::Internal, "failed to spawn the scenario")
                })?;
            let stdin = child.stdin.take();
            let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
                return Err(launch_failed(
                    &mut child,
                    stdin,
                    ErrorCode::Internal,
                    "missing pipes",
                ));
            };
            // stderr は上限まで共有バッファへ蓄積し、以降は捨てる（パイプ詰まりで子が止まらないように）。
            // 蓄積分は起動失敗時の診断にだけ使う。
            let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
            let captured_writer = Arc::clone(&captured);
            std::thread::spawn(move || {
                let mut r = stderr;
                let mut chunk = [0u8; 1024];
                while let Ok(n) = r.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    if let Ok(mut buf) = captured_writer.lock() {
                        let room = STDERR_CAP as usize - buf.len().min(STDERR_CAP as usize);
                        let take = n.min(room);
                        if let Some(part) = chunk.get(..take) {
                            buf.extend_from_slice(part);
                        }
                    }
                }
            });
            // stdout は 1 行ずつ（上限つき）チャネルへ流す。READY の後の EXIT 行も同じチャネルで受ける。
            let (tx, rx) = mpsc::channel::<String>();
            std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(stdout);
                loop {
                    let mut line = String::new();
                    match (&mut reader).take(LINE_CAP).read_line(&mut line) {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {
                            if tx.send(line).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
            let ready = rx.recv_timeout(timeout);
            let pid = match ready {
                Ok(line) => line
                    .trim_end()
                    .strip_prefix(READY_PREFIX)
                    .and_then(|v| v.parse::<u32>().ok())
                    .and_then(NonZeroU32::new),
                Err(_) => {
                    if let Ok(b) = captured.lock() {
                        eprintln!("[scenario stderr] {}", String::from_utf8_lossy(&b));
                    }
                    return Err(launch_failed(
                        &mut child,
                        stdin,
                        ErrorCode::Timeout,
                        "the scenario did not report readiness within the timeout",
                    ));
                }
            };
            let Some(pid) = pid else {
                if let Ok(b) = captured.lock() {
                    eprintln!("[scenario stderr] {}", String::from_utf8_lossy(&b));
                }
                return Err(launch_failed(
                    &mut child,
                    stdin,
                    ErrorCode::Internal,
                    "the scenario did not report the entrypoint pid",
                ));
            };
            Ok(Box::new(RealInitProcess {
                pid,
                inner: Mutex::new(InitState {
                    intermediary: child,
                    stdin,
                    lines: rx,
                    exit: None,
                }),
            }))
        }
    }

    /// start が返した起動ハンドルを保持し、kill をそのハンドルへだけ委ねる signaler（テスト専用）。
    /// 状態に記録された pid へ生の kill は送らない（SEC-1）。本番は supervisor（TASK-157）が提供する。
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

    // ---- 最小のインメモリ StateStore（`StateStore::delete` は本テストの経路で呼ばれないため未実装のまま。
    // delete〔TASK-30.2〕は Running のレコードを状態判定で拒否し、ここへ到達しない） ----

    struct MemStateStore {
        records: Mutex<HashMap<ContainerId, StateRecord>>,
    }

    impl StateStore for MemStateStore {
        fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            if records.contains_key(req.id()) {
                return Err(TraitError::new(ErrorCode::AlreadyExists, "exists"));
            }
            let record = StateRecord::new(
                req.status().clone(),
                req.bundle().to_path_buf(),
                StateRevision::from_raw(1),
            )?;
            records.insert(req.id().clone(), record.clone());
            Ok(record)
        }

        fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
            let mut records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            let cur = records
                .get(req.status().id())
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))?;
            if cur.revision() != req.expected_revision() {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "stale"));
            }
            let next = StateRecord::new(
                req.status().clone(),
                cur.bundle().to_path_buf(),
                cur.revision().next()?,
            )?;
            records.insert(req.status().id().clone(), next.clone());
            Ok(next)
        }

        fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
            let records = self.records.lock().unwrap_or_else(|e| e.into_inner());
            records
                .get(req.id())
                .cloned()
                .ok_or_else(|| TraitError::new(ErrorCode::NotFound, "not found"))
        }

        fn list(&self, _req: &ListStateRequest) -> Result<StateList, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
        }

        fn delete(&self, _req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
            Err(TraitError::new(ErrorCode::Unimplemented, "unused"))
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

    /// `config.json` と `rootfs/`（`proc/`・実エントリポイント `/entry` とローダ・共有ライブラリ）を排他的に作る。
    /// `RootfsDir::pin` は symlink を含む祖先を拒否するため、temp は canonicalize する。
    fn make_bundle(label: &str) -> Bundle {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("canonicalize temp_dir")
            .join(format!(
                "fandhe-rootless-lifecycle-{label}-{}-{nanos}",
                std::process::id()
            ));
        std::fs::create_dir(&base).expect("exclusively create bundle dir");
        let bundle = Bundle(base);
        std::fs::set_permissions(&bundle.0, std::fs::Permissions::from_mode(0o700))
            .expect("chmod bundle");
        let rootfs = bundle.0.join("rootfs");
        let ld = real_entry::install_entry(&rootfs);
        // linux.uidMappings は書かない（start が拒否する。写像は launcher 側の責務）。
        let config = serde_json::json!({
            "ociVersion": "1.2.0",
            "root": {"path": "rootfs", "readonly": false},
            "process": {
                "user": {"uid": 0, "gid": 0},
                "args": real_entry::entry_args("init"),
                "env": real_entry::entry_env(&ld),
                "cwd": "/"
            },
            "hostname": HOSTNAME,
            "linux": {"namespaces": [
                {"type": "pid"}, {"type": "mount"}, {"type": "user"}, {"type": "uts"}, {"type": "ipc"}
            ]}
        });
        let mut cf = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(bundle.0.join("config.json"))
            .expect("create config.json");
        cf.write_all(&serde_json::to_vec(&config).expect("serialize"))
            .expect("write config.json");
        bundle
    }

    // ---- ディスパッチャ ----

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
            println!("rootless: host root launch rejected (SEC-5, root=true)");
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
    fn lifecycle(mode: &'static str, euid: u32, egid: u32) {
        let bundle = make_bundle(mode);
        let store = MemStateStore {
            records: Mutex::new(HashMap::new()),
        };
        let rec = OpRecorder::new();
        let launcher: Arc<dyn ProcessLauncher> = Arc::new(RootlessLauncher { mode });
        let signaler_impl = Arc::new(HandleSignaler {
            slot: Mutex::new(None),
        });
        let signaler: Arc<dyn ProcessSignaler> = signaler_impl.clone();
        let id_str = format!("rootless-{mode}");
        let id = ContainerId::new(&id_str).expect("id");

        // create: Created・pid なし・revision 1。
        let created = create(
            &store,
            &rec,
            &CreateRequest::new(id.clone(), bundle.0.clone()).expect("absolute bundle"),
        )
        .expect("create");
        assert_eq!(created.status().state(), ContainerState::Created);
        assert_eq!(created.status().pid(), None);
        assert_eq!(created.revision().value(), 1);

        // start: helper ケースは 2 回の helper 呼び出しが要るため、既定の上限では足りない。
        let limit = DEFAULT_HELPER_TIMEOUT * 2 + timeout() * 2;
        let timeouts = StartTimeouts::new(limit, timeout(), timeout()).expect("start timeouts");
        let started = start(
            &store,
            &rec,
            &launcher,
            &StartRequest::new(id.clone()),
            &timeouts,
        )
        .expect("start");
        let (record, handle) = started.into_parts();
        assert_eq!(record.status().state(), ContainerState::Running);
        assert_eq!(record.revision().value(), 3);
        let pid = handle.pid();
        assert_eq!(record.status().pid(), Some(pid));
        assert_eq!(
            store
                .get(&GetStateRequest::new(id.clone()))
                .expect("stored"),
            record
        );
        *signaler_impl.slot.lock().unwrap_or_else(|e| e.into_inner()) = Some((id.clone(), handle));

        // ホスト視点の rootless 検証（SEC-5・CORE-6）。
        let p = pid.get();
        let (uid_set, gid_set) = match mode {
            "direct" => (
                single_id_mapping(euid).expect("uid"),
                single_id_mapping(egid).expect("gid"),
            ),
            _ => helper_mappings(euid, egid),
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
        // 実エントリポイントの親は、起動ハンドルの所有者である中間プロセス（`--scenario container`）。
        let ppid = status_str(p, "PPid:");
        let parent_cmdline =
            std::fs::read(format!("/proc/{ppid}/cmdline")).expect("parent cmdline");
        let parent_args: Vec<&[u8]> = parent_cmdline.split(|b| *b == 0).collect();
        assert!(
            parent_args.contains(&b"--scenario".as_slice())
                && parent_args.contains(&b"container".as_slice()),
            "the parent of the entrypoint must be the intermediary process"
        );
        // コンテナ視点の観測値（`/entry-report`）。
        let ready = real_entry::read_report(&bundle.0.join("rootfs").join(READY_FILE), timeout());
        let field = |k: &str| ready.get(k).map(String::as_str).unwrap_or("missing");
        assert_eq!(field("pid"), "1");
        assert_eq!(field("uid"), "0");
        assert_eq!(field("gid"), "0");
        assert_eq!(field("hostname"), HOSTNAME);
        assert_eq!(field("nonewprivs"), "1");
        assert_eq!(field("seccomp"), "2");
        // 別の user namespace にいることは、初期 namespace の恒等写像ではない上の uid_map の完全一致で
        // 保証される（`/proc/<pid>/ns/user` の readlink は ptrace 権限検査を伴い環境差が大きいため使わない）。

        // kill: 戻り値は照合時点の状態（Running）で、状態は更新されない。
        let status = kill(
            &store,
            &rec,
            &signaler,
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
            &store,
            &rec,
            &signaler,
            &KillRequest::new(id.clone(), Signal::SIGKILL),
            &KillTimeout::default(),
        )
        .expect_err("second kill");
        assert_eq!(err.code(), ErrorCode::FailedPrecondition);

        // kill 直後の delete は Running・pid ありとして拒否され、状態・revision は残る（CORE-2・TASK-30.2）。
        let err = delete(&store, &rec, &NoCgroup, &DeleteRequest::new(id.clone()))
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
        assert_eq!(op_stats(&rec, "create"), (1, 0));
        assert_eq!(op_stats(&rec, "start"), (1, 0));
        assert_eq!(op_stats(&rec, "kill"), (1, 1));
        assert_eq!(op_stats(&rec, "delete"), (0, 1));

        println!(
            "rootless: scenario {mode} lifecycle verified with the real entrypoint as PID 1 (create/start/kill/delete-rejected; host uid={euid})"
        );
    }
}
