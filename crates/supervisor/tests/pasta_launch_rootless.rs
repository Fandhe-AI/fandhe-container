//! rootless の本番 launcher（`ProductionLauncher`）と実際の pasta を組み合わせた通し確認の実機前提試験
//! （NET-9・NET-3・CORE-1・CORE-7・SUP-2・REPAIR-5・REPAIR-12。#3331・#1940）。
//!
//! #1940 で、rootless のユーザー定義名の network（`LaunchNetworkMode::Attachable`）のとき supervisor が holder と pasta を
//! 起動してコンテナの寿命に連動させる結線（`pasta_attach` の `PastaWiring` / `PastaGuardedProcess`）が入ったが、本番の
//! launcher と実 pasta を通した確認が無かった。`exec_launch_netns_rootless` のフックは holder だけで pasta を起動せず、
//! net の `pasta_rootless` は net の API 単体でありここの launcher とつながっておらず、`pasta_attach/tests.rs` はフェイクの
//! backend を使う。本試験は本番の入口だけを通す。
//! - core の `create` → `start`（`ProductionLauncher`。start の前に本番と同じ cgroup の連鎖で配置を記録）
//! - supervisor の `PastaWiring::production`（`hook()` を launcher へ、`wrap()` で包む）と、その `PastaGuardedProcess`
//!
//! 試験プロセス（シナリオの子プロセス）が supervisor の役を担い、`LaunchedProcess::wait` を短い周期で呼んで監視ループを模す。
//! core は pasta を知らない（network-wiring.md D5。core から net への依存を足さない）ため、試験は supervisor 側に置く。
//!
//! # 照合項目（具体値）
//! 3 シナリオ（`stop-delete` / `supervisor-sigkill` / `holder-gone`）× 写像モデル 2（`single` / `subordinate`）で、起動後に次を照合する。
//! - 到達性（NET-3・NET-9）: ホストの `127.0.0.1:<公開ポート>` からコンテナ内のリスナーの固定トークンが届く。ホストの
//!   loopback 以外の IPv4 アドレスの同じポートは接続拒否になる（無ければ `observation non_loopback=absent`）。コンテナ内の
//!   既定経路は「あり」で、holder の netns は pid1 の netns と同じ inode
//! - cgroup（CORE-1・SUP-2）: pasta と holder の `/proc/<pid>/cgroup` は、supervisor の退避リーフ（試験プロセス自身）と一致し、
//!   コンテナの cgroup にも委譲親にも一致せず、コンテナの cgroup の配下でもない
//! - `stop-delete`: SIGKILL（本番の stop が猶予の後に上げる SIGKILL。PID 1 は SIG_DFL の SIGTERM を受けないため直接使う）の後、
//!   `wait` が終了を返した時点で pasta・holder が `(pid, starttime)` の照合つきで残らず、`@pasta/<id>` と子プロセスが無い。続けて
//!   CLI の delete と同じ `remove_pasta_leftovers` が `Ok` で、再確認しても残らない
//! - `supervisor-sigkill`: supervisor 役を SIGKILL すると pasta と holder が期限内に消え（PDEATHSIG）、孤児になった pid1 は
//!   稼働を続ける（SUP-5）。試験が pid1 を `cgroup.kill` で後始末し、`remove_pasta_leftovers` が残骸を消せることを照合する
//! - `holder-gone`: pid1 と holder を SIGKILL して `wait` を呼ばない間に、pasta が netns-quit で自分から終わる（NET-9。
//!   所要時間を `observation netns_quit_ms` に出す）。その後の `wait` が途中死を検出して終了を返し、後始末が残らない
//!
//! # 範囲外（REPAIR-3）
//! - 本番の CLI からの到達（`--network` の受け口と start での D10 の再照合・resolv.conf）は #3329。supervisor の bin を通す
//!   シナリオは #3329 の後に足す（本番の CLI が pasta を FCOPT1 に書けるまで、文書の手書きは壊れても CI で気づけないため採らない）。
//!   create から start までの pasta の記録の往復は、本試験内で `PastaRecord` の `to_body` → `parse_body` → `reverify` で代替する
//! - SEC-4 の監査は #3330、restart の再 launch は #2043、IPv6・常駐 PSS・rootful 比のスループット・実機での結果の記録は #341
//! - core の `delete` 本体（状態記録の Stopped が前提）は通さない。監視ループが Stopped を書く経路を持たないため、delete のうち
//!   pasta に関わる部分（`remove_pasta_leftovers`）と cgroup の削除だけを照合する
//!
//! # 必要環境
//! 非 root、非特権 user namespace（`kernel.apparmor_restrict_unprivileged_userns` の値は `observation` に出す。緩める
//! sysctl の変更は人間が行い、本試験は実行しない）、委譲 cgroup v2、`systemd-run --user`、Landlock ABI 6 以上、`passt`
//! （pasta。`FANDHE_CONTAINER_TEST_PASTA`、既定 `/usr/bin/pasta`。#340 で確認した版）、`$XDG_RUNTIME_DIR`（状態ルートをその下に
//! 一時作成する。AppArmor の pasta の許可の内側に置くため。許可外に置くと pasta が書けず `FailedPrecondition` になる）。
//! 範囲写像のシナリオは `FANDHE_CONTAINER_TEST_ID_HELPER=1`・uidmap・subuid / subgid も要る（未設定なら single だけを回し、
//! 成功を装わず終了コード 1 で終わる）。待ちの上限は `FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（1..=295。既定 30。REPAIR-5）。
//!
//! ```text
//! cargo test -p fandhe-container-supervisor --test pasta_launch_rootless --no-run
//! FANDHE_CONTAINER_TEST_ID_HELPER=1 USER=$(id -un) <target/debug/deps/pasta_launch_rootless-XXXX> --ignored
//! ```
//!
//! 各シナリオは `DelegatedCgroup::prepare` が自プロセスを退避リーフへ移すため、`systemd-run --user --scope -p Delegate=yes` の
//! 子プロセス（`--scenario`）で 1 つずつ実行する。`harness = false` で `-- --ignored` 指定時のみ動かす（実機前提の分離であり、
//! 既定のテスト集合の弱体化ではない）。platform-ci へは組み込まない（ランナー上の pasta と AppArmor の前提が未確認）。
//!
//! 成功時の最終行: `pasta_launch_rootless: production launcher with real pasta verified for stop, delete, supervisor SIGKILL and netns-quit (root=false)`。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("pasta_launch_rootless: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("pasta_launch_rootless: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os();
    let _exe = args.next();
    let first = args.next();
    // `spawn_netns_holder` は自身（この試験バイナリ）を `netns-holder` 付きで再実行する。ここで振り分けないと
    // holder の READY 待ちがタイムアウトする。
    if first.as_deref()
        == Some(std::ffi::OsStr::new(
            fandhe_container_net::netns_holder::NETNS_HOLDER_SUBCOMMAND,
        ))
    {
        return fandhe_container_net::netns_holder::run_netns_holder_main(args);
    }
    let first = first.and_then(|a| a.into_string().ok());
    match first.as_deref() {
        Some("--container-probe") => linux::container_probe(),
        Some("--scenario") => {
            precondition::self_check();
            let rest: Vec<String> = args.filter_map(|a| a.into_string().ok()).collect();
            return linux::scenario_main(&rest);
        }
        Some("--ignored") => {
            precondition::self_check();
            return linux::run();
        }
        _ => {
            precondition::self_check();
            println!(
                "pasta_launch_rootless: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
            );
        }
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[path = "../../core/tests/support/reap.rs"]
mod reap;

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
/// （core の `tests/support/precondition.rs` の正本。REPAIR-12）。
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
    use std::cell::Cell;
    use std::io::{BufRead as _, Read as _, Write as _};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Command, ExitCode, Stdio};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditRecord, AuditSink};
    use fandhe_container_core::cgroups::{CgroupLimitPlan, ContainerCgroup, DelegatedCgroup};
    use fandhe_container_core::exec::IsolationPrivilege;
    use fandhe_container_core::injected_files::InjectedFileSet;
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        LaunchIpcMode, LaunchNetworkMode, LaunchOptions, LaunchedProcess, ProcessExit,
        ProcessLauncher, ProductionLauncher, StartTimeouts, SubordinateIdSource, create, start,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::tmpfs::TmpfsMountSet;
    use fandhe_container_core::traits::{
        ContainerId, CreateRequest, GetStateRequest, Signal, StartRequest, StateRecord, StateStore,
        TraitError,
    };
    use fandhe_container_net::netns_holder::NETNS_HOLDER_SUBCOMMAND;
    use fandhe_container_net::pasta::binary::{PastaBinary, verify_pasta_binary};
    use fandhe_container_net::pasta::record::PastaRecord;
    use fandhe_container_net::pasta::{PastaPortForward, PastaPortForwards};
    use fandhe_container_supervisor::pasta_attach::{
        PastaAttachConfig, PastaLogBuffer, PastaWiring, READY_TIMEOUT_DEFAULT, TERM_GRACE,
        open_state_root, remove_pasta_leftovers,
    };

    use super::rootfs;

    /// コンテナ内の bind 先（ホストの `hostdata/` を `rw` で束ねる。pid1 の ready 通知と観測値の受け渡し口）。
    const DATA_DEST: &str = "/data";
    const READY_FILE: &str = "ready";
    const READY_CONTENT: &str = "READY";
    /// pid1 が自分の netns と既定経路の有無を書くファイル名。
    const INFO_FILE: &str = "info";
    /// コンテナ内のリスナーのポート（固定の内部ポート）。
    const CONTAINER_PORT: u16 = 18080;
    /// リスナーが接続ごとに返す固定トークン。
    const TOKEN: &str = "PLR-TOKEN";
    /// pid1 の寿命の上限（取り残し防止。REPAIR-5）。超えたら終了コード 8。
    const PROBE_LIFETIME: Duration = Duration::from_secs(60);
    /// シナリオ 1 件の上限（子プロセスの期限。REPAIR-5）。
    const SCENARIO_DEADLINE: Duration = Duration::from_secs(240);

    /// 1 件の待ちの上限。`FANDHE_CONTAINER_TEST_TIMEOUT_SECS`（1..=295。未設定・不正値は 30 秒）。
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

    /// 観測値の 1 行。成功行ではない（ホスト名・IP・ユーザー名・パスを含めない）。
    fn obs(key: &str, value: &str) {
        println!("pasta_launch_rootless: observation {key}={value}");
    }

    // ----- コンテナ内の役 ----------------------------------------------------------------------------------

    /// pid1 の役。`0.0.0.0:CONTAINER_PORT` で TCP を待ち、netns と既定経路の有無を `/data/info` へ、続けて `/data/ready` へ
    /// `READY` を書き、接続ごとに固定トークンを返して閉じる（寿命の上限つき）。IPv4 のみ（pasta の argv が `-4`）。
    pub fn container_probe() {
        let Ok(listener) = TcpListener::bind(("0.0.0.0", CONTAINER_PORT)) else {
            std::process::exit(7);
        };
        let Ok(net) = std::fs::read_link("/proc/self/ns/net") else {
            std::process::exit(7);
        };
        let default_route = std::fs::read_to_string("/proc/net/route").is_ok_and(|t| {
            t.lines()
                .skip(1)
                .any(|l| l.split_whitespace().nth(1) == Some("00000000"))
        });
        let info = format!(
            "{}\ndefault_route={}\n",
            net.display(),
            if default_route { "yes" } else { "no" }
        );
        for (name, content) in [(INFO_FILE, info.as_str()), (READY_FILE, READY_CONTENT)] {
            let path = format!("{DATA_DEST}/{name}");
            if std::fs::write(&path, content).is_err() {
                std::process::exit(9);
            }
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644));
        }
        if listener.set_nonblocking(true).is_err() {
            std::process::exit(7);
        }
        let deadline = Instant::now() + PROBE_LIFETIME;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut conn, _)) => {
                    let _ = conn.write_all(TOKEN.as_bytes());
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        std::process::exit(8);
    }

    // ----- 親側の部品 --------------------------------------------------------------------------------------

    fn nanos() -> u32 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    }

    /// 排他的に作る 0700 のディレクトリ（drop で削除）。
    struct TempDir {
        dir: PathBuf,
    }

    impl TempDir {
        /// 一時領域の親（tmpfiles の掃除と flock 競合の回避）の下に作る。bundle・rootfs・hostdata 用。
        fn in_scratch(tag: &str) -> Self {
            let dir = super::scratch_root::scratch_root("fandhe-plr-scratch", timeout()).join(
                format!("fandhe-plr-{tag}-{}-{}", std::process::id(), nanos()),
            );
            Self::create(dir)
        }

        /// `$XDG_RUNTIME_DIR` の下に作る。状態ルート（`@pasta/<id>`）を pasta の AppArmor の許可の内側に置くため。
        fn in_xdg(tag: &str) -> Self {
            let dir = xdg_runtime_dir().join(format!(
                "fandhe-plr-{tag}-{}-{}",
                std::process::id(),
                nanos()
            ));
            Self::create(dir)
        }

        fn create(dir: PathBuf) -> Self {
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

    fn xdg_runtime_dir() -> PathBuf {
        let xdg = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| fail_precondition("XDG_RUNTIME_DIR is not set"));
        if !xdg.is_absolute() {
            fail_precondition("XDG_RUNTIME_DIR is not absolute");
        }
        match std::fs::metadata(&xdg) {
            Ok(m) if m.is_dir() && m.uid() == own_euid() => xdg,
            _ => fail_precondition("XDG_RUNTIME_DIR is not a directory owned by the current user"),
        }
    }

    /// pasta・XDG_RUNTIME_DIR の前提欠如。成功へ分岐せず、試験環境起因であることが 1 行目で分かる形で失敗する。
    fn fail_precondition(what: &str) -> ! {
        panic!(
            "pasta_launch_rootless: PRECONDITION FAILED (test environment, not a launcher regression): {what}.\n\
             See AGENTS.md pasta_launch_rootless."
        )
    }

    /// 監査レコードを捨てる sink（本試験の照合対象ではない。SEC-4 は #3330）。
    struct MemSink(Mutex<Vec<AuditRecord>>);

    impl AuditSink for MemSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(record.clone());
            Ok(())
        }
    }

    fn status_field(path: &str, key: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    }

    fn own_euid() -> u32 {
        status_field("/proc/self/status", "Uid:")
            .and_then(|v| v.split_whitespace().nth(1).map(str::to_string))
            .and_then(|v| v.parse().ok())
            .expect("parse euid")
    }

    /// `cond` が真になるまで `limit` までポーリングする（固定 sleep に頼らない）。
    fn eventually_within(limit: Duration, cond: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    fn eventually(cond: impl Fn() -> bool) -> bool {
        eventually_within(timeout(), cond)
    }

    /// 呼び出しプロセスが単一スレッドに戻るのを待つ（fork・holder と pasta の起動の前提）。
    fn wait_single_thread() {
        assert!(
            eventually(|| status_field("/proc/self/status", "Threads:").as_deref() == Some("1")),
            "the test process must be single-threaded before a launch"
        );
    }

    /// 呼び出しプロセスの子（全スレッド分）の pid 一覧。
    fn children_of_self() -> Vec<u32> {
        let mut out = Vec::new();
        let tasks = std::fs::read_dir("/proc/self/task").expect("read /proc/self/task");
        for t in tasks {
            let t = t.expect("task entry");
            if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
                out.extend(s.split_whitespace().filter_map(|p| p.parse::<u32>().ok()));
            }
        }
        out
    }

    /// `/proc/<pid>/stat` の状態と starttime（最後の `)` の後ろを読む）。
    fn stat_fields(pid: u32) -> Option<(char, u64)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after = stat.get(stat.rfind(')')? + 1..)?;
        let mut it = after.split_whitespace();
        let state = it.next()?.chars().next()?;
        let start = it.nth(18)?.parse().ok()?;
        Some((state, start))
    }

    /// pid の再利用に備えて starttime と組で控えたプロセス。
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Proc {
        pid: u32,
        start: u64,
    }

    impl Proc {
        fn of(pid: u32) -> Self {
            let (_, start) = stat_fields(pid).unwrap_or_else(|| panic!("process {pid} vanished"));
            Self { pid, start }
        }

        /// 同じプロセスが生きている（zombie ではない）。
        fn alive(self) -> bool {
            matches!(stat_fields(self.pid), Some((s, st)) if st == self.start && s != 'Z')
        }

        /// 同じプロセスが存在しない（pid が消えたか、別のプロセスに再利用された）。
        fn gone(self) -> bool {
            !matches!(stat_fields(self.pid), Some((_, st)) if st == self.start)
        }

        /// 終わった（存在しないか zombie）。
        fn quit(self) -> bool {
            !self.alive()
        }

        fn label(self) -> String {
            format!("{}:{}", self.pid, self.start)
        }
    }

    fn parse_proc(s: &str) -> Proc {
        let (p, st) = s.split_once(':').expect("pid:start");
        Proc {
            pid: p.parse().expect("pid"),
            start: st.parse().expect("start"),
        }
    }

    /// `/proc/<pid>/cgroup` の cgroup v2 の行（`0::<path>`）のパス。
    fn cgroup_of(pid: u32) -> String {
        std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .unwrap_or_else(|e| panic!("read cgroup of {pid}: {e}"))
            .lines()
            .find_map(|l| l.strip_prefix("0::").map(str::to_string))
            .unwrap_or_else(|| panic!("no cgroup v2 line for {pid}"))
    }

    /// `kill -KILL <pid>`（外部コマンド。引数は固定の配列でシェルを経由しない。呼び出し側が starttime を照合済み）。
    fn kill_by_pid(p: Proc) {
        assert_eq!(
            Proc::of(p.pid),
            p,
            "refuse to signal a pid whose starttime changed"
        );
        let status = super::reap::run_within(
            Command::new("kill").arg("-KILL").arg(p.pid.to_string()),
            Duration::from_secs(5),
        )
        .unwrap_or_else(|e| panic!("kill: {e}"));
        assert!(status.success(), "kill -KILL failed: {status}");
    }

    // ----- シナリオ ----------------------------------------------------------------------------------------

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Kind {
        StopDelete,
        SupervisorSigkill,
        HolderGone,
    }

    impl Kind {
        fn label(self) -> &'static str {
            match self {
                Self::StopDelete => "stop-delete",
                Self::SupervisorSigkill => "supervisor-sigkill",
                Self::HolderGone => "holder-gone",
            }
        }

        fn parse(s: &str) -> Option<Self> {
            [Self::StopDelete, Self::SupervisorSigkill, Self::HolderGone]
                .into_iter()
                .find(|k| k.label() == s)
        }
    }

    fn privilege_label(subordinate: bool) -> &'static str {
        if subordinate { "subordinate" } else { "single" }
    }

    /// 成功行は固定文言（`{}` を含めない）にする。将来 CI の `check-success-lines.sh` が試験ソースの文字列リテラルから
    /// 期待行を導出して双方向に照合できるようにするため。
    fn success_line(kind: Kind, subordinate: bool) -> &'static str {
        match (kind, subordinate) {
            (Kind::StopDelete, false) => {
                "pasta_launch_rootless: scenario=stop-delete-single production launcher attached real pasta, published loopback only, and left no helper after stop and delete"
            }
            (Kind::StopDelete, true) => {
                "pasta_launch_rootless: scenario=stop-delete-subordinate production launcher attached real pasta, published loopback only, and left no helper after stop and delete"
            }
            (Kind::SupervisorSigkill, false) => {
                "pasta_launch_rootless: scenario=supervisor-sigkill-single pasta and holder died with the killed supervisor while pid1 kept running, and leftovers were removed"
            }
            (Kind::SupervisorSigkill, true) => {
                "pasta_launch_rootless: scenario=supervisor-sigkill-subordinate pasta and holder died with the killed supervisor while pid1 kept running, and leftovers were removed"
            }
            (Kind::HolderGone, false) => {
                "pasta_launch_rootless: scenario=holder-gone-single pasta quit by itself after the namespace holders were gone and the guarded process left no helper"
            }
            (Kind::HolderGone, true) => {
                "pasta_launch_rootless: scenario=holder-gone-subordinate pasta quit by itself after the namespace holders were gone and the guarded process left no helper"
            }
        }
    }

    /// 検証済みの pasta を、本番の create → start と同じく FCOPT1 の記録の往復（`to_body` → `parse_body` → `reverify`）を
    /// 通して得る。
    fn pasta_binary() -> PastaBinary {
        let path = std::env::var_os("FANDHE_CONTAINER_TEST_PASTA")
            .map_or_else(|| PathBuf::from("/usr/bin/pasta"), PathBuf::from);
        let verified = verify_pasta_binary(&path).unwrap_or_else(|e| {
            fail_precondition(&format!(
                "verify_pasta_binary failed: {} {} (install `passt` or set FANDHE_CONTAINER_TEST_PASTA)",
                e.code().as_str(),
                e.message()
            ))
        });
        let body = verified.record().to_body();
        PastaRecord::parse_body(&body)
            .and_then(|r| r.reverify())
            .unwrap_or_else(|e| {
                panic!(
                    "pasta record round trip: {} {}",
                    e.code().as_str(),
                    e.message()
                )
            })
    }

    /// ホストの空きポートを 1 つ決める（loopback と 0.0.0.0 の双方で bind できるもの）。
    fn free_port() -> u16 {
        let until = Instant::now() + timeout();
        loop {
            let l = TcpListener::bind("0.0.0.0:0").expect("bind probe");
            let p = l.local_addr().expect("local addr").port();
            drop(l);
            if TcpListener::bind(("127.0.0.1", p)).is_ok()
                && TcpListener::bind(("0.0.0.0", p)).is_ok()
            {
                return p;
            }
            assert!(Instant::now() < until, "could not find a free port in time");
        }
    }

    /// ホストの loopback 以外の IPv4 アドレス（経路を選ぶだけで送信しない）。無ければ `None`。
    fn non_loopback_addr() -> Option<Ipv4Addr> {
        let s = UdpSocket::bind("0.0.0.0:0").ok()?;
        s.connect("192.0.2.1:9").ok()?;
        match s.local_addr().ok()?.ip() {
            std::net::IpAddr::V4(a) if !a.is_loopback() && !a.is_unspecified() => Some(a),
            _ => None,
        }
    }

    /// シナリオ 1 件分の準備一式。後始末は drop とシナリオ末尾の `cleanup` が行う。
    struct Fixture<'a> {
        delegated: &'a DelegatedCgroup,
        /// bundle・rootfs・hostdata（一時領域の親の下）。
        work: TempDir,
        /// 状態ルートの親（`$XDG_RUNTIME_DIR` の下）。
        _xdg: TempDir,
        state_path: PathBuf,
        store: FileStateStore,
        recorder: OpRecorder,
        id: ContainerId,
        hostdata: PathBuf,
        host_port: u16,
        wiring: PastaWiring,
        launcher: Arc<dyn ProcessLauncher>,
        container_cgroup: Arc<ContainerCgroup>,
    }

    fn container_id(tag: u32, sequence: u32) -> ContainerId {
        ContainerId::new(format!("plr{tag}s{sequence}")).expect("container id")
    }

    /// `process.user` は uid 0・gid 0（どちらの写像モデルでも起動ユーザーに写る）。network の `linux.namespaces` エントリは
    /// 置かない（起動オプションの `Attachable` が新しい netns を要求する）。書式は `exec_launch_netns_rootless` に揃える。
    fn config_text(ld: &str, bind_src: &Path) -> String {
        let src = bind_src.to_str().expect("utf8 bind source");
        format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"hostname":"fandhe-plr",
"process":{{"user":{{"uid":0,"gid":0}},"args":["/probe","--container-probe"],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"mounts":[{{"destination":"{DATA_DEST}","type":"bind","source":"{src}","options":["bind","rw"]}}],
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#
        )
    }

    fn setup<'a>(
        delegated: &'a DelegatedCgroup,
        subordinate: bool,
        tag: u32,
        sequence: u32,
    ) -> Fixture<'a> {
        let privilege = if subordinate {
            IsolationPrivilege::RootlessSubordinateIds
        } else {
            IsolationPrivilege::RootlessSingleId
        };
        // 名前に親の tag を含める。親が失敗時に `reclaim_scenario` で前方一致により回収するため。
        let work = TempDir::in_scratch(&format!("t{tag}-s{sequence}"));
        let xdg = TempDir::in_xdg(&format!("t{tag}-s{sequence}"));
        let state_path = xdg.dir.join("state");
        let store =
            FileStateStore::open(StateRoot::from_override(state_path.clone()).expect("state root"))
                .expect("open state store");
        let id = container_id(tag, sequence);

        let bundle_dir = work.dir.join("bundle");
        let hostdata = work.dir.join("hostdata");
        std::fs::create_dir(&bundle_dir).expect("create bundle");
        std::fs::create_dir(&hostdata).expect("create hostdata");
        std::fs::set_permissions(&hostdata, std::fs::Permissions::from_mode(0o700))
            .expect("chmod hostdata");
        let ld = rootfs::make_rootfs(&bundle_dir.join("rootfs"), rootfs::ProcDir::Create);
        std::fs::write(bundle_dir.join("config.json"), config_text(&ld, &hostdata))
            .expect("write config.json");

        let recorder = OpRecorder::new();
        let create_req =
            CreateRequest::new(id.clone(), bundle_dir.clone()).expect("absolute bundle");
        create(&store, &recorder, &create_req).expect("create");

        // 本番と同じ cgroup の連鎖。
        let observed = store
            .get(&GetStateRequest::new(id.clone()))
            .expect("get created state");
        let (container_cgroup, _first_join, _rec, _report) = delegated
            .record_scope(&store, &observed)
            .and_then(|r| r.create_cgroup())
            .and_then(|p| p.apply_limits(&recorder, &CgroupLimitPlan::for_privilege(privilege)))
            .and_then(|l| l.into_join())
            .unwrap_or_else(|e| panic!("cgroup start chain failed: {e:?}"))
            .into_parts();
        let container_cgroup = Arc::new(container_cgroup);

        // pasta の構成（本番の `PastaWiring::production`）。公開は 127.0.0.1 のみ。
        let host_port = free_port();
        let forwards = PastaPortForwards::try_from_forwards([PastaPortForward::parse(&format!(
            "127.0.0.1:{host_port}:{CONTAINER_PORT}/tcp"
        ))
        .expect("port forward")])
        .expect("port forwards");
        let state_fd = open_state_root(&state_path).expect("open state root");
        let wiring = PastaWiring::production(
            PastaAttachConfig {
                binary: pasta_binary(),
                forwards,
                state_root: state_fd,
                state_root_path: state_path.clone(),
                container: id.clone(),
                ready_timeout: READY_TIMEOUT_DEFAULT,
            },
            Arc::new(PastaLogBuffer::new()),
        )
        .expect("pasta wiring");

        let launcher: Arc<dyn ProcessLauncher> = {
            let mut tmpfs = TmpfsMountSet::new();
            tmpfs.ensure_default_dev_shm().expect("default dev shm");
            let options = LaunchOptions::new(tmpfs, InjectedFileSet::new(), LaunchIpcMode::Private)
                .expect("launch options")
                .with_network(LaunchNetworkMode::Attachable);
            let mut builder = ProductionLauncher::builder().privilege(privilege);
            if subordinate {
                builder = builder.subordinate_ids(
                    SubordinateIdSource::system(std::env::var("USER").ok())
                        .expect("subordinate ids"),
                );
            }
            let cgroup = Arc::clone(&container_cgroup);
            let inner: Arc<dyn ProcessLauncher> = Arc::new(
                builder
                    .audit_sink(Arc::new(MemSink(Mutex::new(Vec::new()))))
                    .cgroup_join_source(move || cgroup.join_hook())
                    .launch_options(options)
                    .netns_attach_hook(wiring.hook())
                    .build()
                    .expect("build launcher"),
            );
            wiring.wrap(inner)
        };

        Fixture {
            delegated,
            work,
            _xdg: xdg,
            state_path,
            store,
            recorder,
            id,
            hostdata,
            host_port,
            wiring,
            launcher,
            container_cgroup,
        }
    }

    impl Fixture<'_> {
        fn pasta_dir(&self) -> PathBuf {
            self.state_path.join("@pasta").join(self.id.as_str())
        }

        /// 準備段階（`@pasta/<id>` の作成）→ start。失敗したら準備済みの置き場所を回収して panic する。
        fn start(&self) -> (StateRecord, Box<dyn LaunchedProcess>) {
            self.wiring
                .prepare(Instant::now() + timeout())
                .expect("prepare the pasta run directory");
            // holder・pasta の起動は main スレッド・単一スレッドを要求する。
            wait_single_thread();
            match start(
                &self.store,
                &self.recorder,
                &self.launcher,
                &StartRequest::new(self.id.clone()),
                &timeouts(),
            ) {
                Ok(started) => started.into_parts(),
                Err(e) => {
                    let _ = self.wiring.discard();
                    panic!("start failed: {:?} {}", e.code(), e.message());
                }
            }
        }

        /// `/data/ready` が `READY` になるのを期限つきで待つ。
        fn wait_ready(&self) {
            let path = self.hostdata.join(READY_FILE);
            assert!(
                eventually(|| std::fs::read_to_string(&path).is_ok_and(|s| s == READY_CONTENT)),
                "the container probe must report READY"
            );
        }
    }

    /// 起動後の pid1・pasta・holder。
    #[derive(Clone, Copy)]
    struct Helpers {
        pid1: Proc,
        pasta: Proc,
        holder: Proc,
    }

    fn cmdline_args(pid: u32) -> Vec<Vec<u8>> {
        std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| b.split(|c| *c == 0).map(<[u8]>::to_vec).collect())
            .unwrap_or_default()
    }

    /// 自分の子から pasta（argv[0] が `pasta`）と holder（argv[1] が `netns-holder`）を 1 つずつ特定する。
    fn find_helpers(pid1: u32) -> Helpers {
        let (mut pasta, mut holder) = (Vec::new(), Vec::new());
        for pid in children_of_self() {
            if pid == pid1 {
                continue;
            }
            let args = cmdline_args(pid);
            if args.first().is_some_and(|a| a.starts_with(b"pasta")) {
                pasta.push(pid);
            } else if args
                .get(1)
                .is_some_and(|a| a.as_slice() == NETNS_HOLDER_SUBCOMMAND.as_bytes())
            {
                holder.push(pid);
            }
        }
        assert_eq!(
            pasta.len(),
            1,
            "exactly one pasta child expected: {pasta:?}"
        );
        assert_eq!(
            holder.len(),
            1,
            "exactly one netns holder child expected: {holder:?}"
        );
        Helpers {
            pid1: Proc::of(pid1),
            pasta: Proc::of(pasta[0]),
            holder: Proc::of(holder[0]),
        }
    }

    /// 起動直後の照合: cgroup（CORE-1・SUP-2）・netns・到達性（NET-3・NET-9）。
    fn verify_started(fx: &Fixture<'_>, h: Helpers) {
        // cgroup: pasta と holder は supervisor の退避リーフ（試験プロセス自身）にいて、コンテナの cgroup にも委譲親にもいない。
        let own = cgroup_of(std::process::id());
        let container = cgroup_of(h.pid1.pid);
        let parent = fx.delegated.path();
        assert_ne!(
            own, container,
            "the supervisor leaf must differ from the container cgroup"
        );
        for (name, p) in [("pasta", h.pasta), ("holder", h.holder)] {
            let cg = cgroup_of(p.pid);
            assert_eq!(
                cg, own,
                "{name} must live in the supervisor evacuation leaf"
            );
            assert_ne!(cg, container, "{name} must not be in the container cgroup");
            assert!(
                !cg.starts_with(&format!("{container}/")),
                "{name} must not be below the container cgroup"
            );
            assert_ne!(cg, parent, "{name} must not be in the delegated parent");
            assert!(
                cg.starts_with(&format!("{parent}/")),
                "{name} must be below the delegated parent"
            );
        }
        assert_ne!(
            container, parent,
            "the container cgroup must be a child of the delegated parent"
        );

        // netns: holder は pid1 の netns を保持している。
        let net = |pid: u32| {
            std::fs::metadata(format!("/proc/{pid}/ns/net"))
                .unwrap_or_else(|e| panic!("stat ns of {pid}: {e}"))
                .ino()
        };
        let pid1_net = net(h.pid1.pid);
        assert_eq!(net(h.holder.pid), pid1_net, "holder netns vs pid1 netns");
        assert_ne!(
            net(std::process::id()),
            pid1_net,
            "the container netns must be new"
        );
        let info = std::fs::read_to_string(fx.hostdata.join(INFO_FILE)).expect("read info");
        assert!(
            info.lines().any(|l| l == "default_route=yes"),
            "the container must have a default route configured by pasta: {info:?}"
        );

        // AppArmor の観測（pasta の profile 名の部分だけ。読めなければ unreadable）。
        let attr = std::fs::read_to_string(format!("/proc/{}/attr/apparmor/current", h.pasta.pid))
            .or_else(|_| std::fs::read_to_string(format!("/proc/{}/attr/current", h.pasta.pid)));
        obs(
            "apparmor_profile",
            attr.as_deref()
                .ok()
                .and_then(|a| a.trim().split(" (").next().map(str::to_string))
                .as_deref()
                .unwrap_or("unreadable"),
        );

        // 到達性: ホストの 127.0.0.1:<公開ポート> からコンテナ内のトークンが届く。
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, fx.host_port));
        assert!(
            eventually(|| {
                let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
                    return false;
                };
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = String::new();
                s.read_to_string(&mut buf).is_ok() && buf == TOKEN
            }),
            "the published loopback port must reach the container listener"
        );
        // 陰性対照: loopback 以外のアドレスの同じポートへは接続できない。
        // ファイアウォールが DROP する環境では拒否でなく timeout になるため、それも不達として許容する。
        match non_loopback_addr() {
            Some(nl) => {
                let e = TcpStream::connect_timeout(
                    &SocketAddr::from((nl, fx.host_port)),
                    Duration::from_secs(2),
                );
                assert!(
                    matches!(
                        &e,
                        Err(e) if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::WouldBlock
                        )
                    ),
                    "non-loopback connect must not succeed (refused or dropped): {:?}",
                    e.as_ref()
                        .map(|_| "connected")
                        .map_err(std::io::Error::kind)
                );
            }
            None => obs("non_loopback", "absent"),
        }
    }

    /// `process.wait` を短い周期で呼び（監視ループの模倣）、終了を期限つきで受け取る。
    fn wait_exit(process: &dyn LaunchedProcess, limit: Duration) -> ProcessExit {
        let deadline = Instant::now() + limit;
        loop {
            match process.wait(Duration::from_millis(100)) {
                Ok(Some(exit)) => return exit,
                Ok(None) => {}
                Err(e) => panic!("wait failed: {:?} {}", e.code(), e.message()),
            }
            assert!(
                Instant::now() < deadline,
                "process did not exit within {limit:?}"
            );
        }
    }

    /// 終了後の「何も残らない」照合（pasta・holder・`@pasta/<id>`・子プロセス）。
    fn assert_nothing_left(fx: &Fixture<'_>, h: Helpers) {
        assert!(h.pasta.gone(), "pasta must not remain");
        assert!(h.holder.gone(), "holder must not remain");
        assert!(!fx.pasta_dir().exists(), "@pasta/<id> must be removed");
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no child may remain"
        );
    }

    // ----- 子プロセス（シナリオの本体） --------------------------------------------------------------------

    /// 子プロセス（`--scenario <kind> <0|1> <tag> <sequence>`）の入口。専用の委譲スコープ内で 1 シナリオだけ実行する。
    pub fn scenario_main(args: &[String]) -> ExitCode {
        let parsed = match args {
            [kind, sub, tag, seq] => match (
                Kind::parse(kind),
                sub.as_str(),
                tag.parse::<u32>(),
                seq.parse::<u32>(),
            ) {
                (Some(k), "0" | "1", Ok(t), Ok(q)) => Some((k, sub == "1", t, q)),
                _ => None,
            },
            _ => None,
        };
        let Some((kind, subordinate, tag, sequence)) = parsed else {
            println!("pasta_launch_rootless: FAILED: invalid --scenario arguments");
            return ExitCode::from(1);
        };
        // 子の scratch ルートは正常終了・失敗の両方で自分で消す（SIGKILL 時は親の `reclaim_scenario` が回収）。
        let _scratch_cleanup = super::scratch_root::ScratchRootCleanup;
        let _landlock = crate::precondition::landlock_support();
        let delegated = crate::precondition::delegated_cgroup();
        scenario(&delegated, kind, subordinate, tag, sequence);
        ExitCode::SUCCESS
    }

    fn scenario(
        delegated: &DelegatedCgroup,
        kind: Kind,
        subordinate: bool,
        tag: u32,
        sequence: u32,
    ) {
        let fx = setup(delegated, subordinate, tag, sequence);
        let (_record, process) = fx.start();
        let reaped = Cell::new(false);
        // 後始末は成否に関わらず行う（panic でも cgroup・pasta・holder・一時領域を残さない）。
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fx.wait_ready();
            let h = find_helpers(process.pid().get());
            verify_started(&fx, h);
            match kind {
                Kind::StopDelete => stop_delete(&fx, process.as_ref(), h, &reaped),
                Kind::SupervisorSigkill => supervisor_sigkill(&fx, h),
                Kind::HolderGone => holder_gone(&fx, process.as_ref(), h, &reaped),
            }
        }));
        if !reaped.get() {
            // 失敗時、または生きたままの経路。terminate は PID 1 の回収と pasta・holder の後始末を行う。
            if let Err(e) = process.terminate(timeout()) {
                eprintln!("pasta_launch_rootless: terminate during cleanup failed: {e:?}");
            }
        }
        drop(process);
        let removed = fx.delegated.remove_child(&fx.container_cgroup);
        let leftovers = remove_pasta_leftovers(&fx.state_path, &fx.id);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        removed.expect("remove container cgroup");
        leftovers.expect("remove pasta leftovers");
        println!("{}", success_line(kind, subordinate));
        drop(fx);
    }

    /// A: 停止（SIGKILL）→ `wait` が終了を返した時点で何も残らず、delete の pasta 側（`remove_pasta_leftovers`）も `Ok`。
    fn stop_delete(
        fx: &Fixture<'_>,
        process: &dyn LaunchedProcess,
        h: Helpers,
        reaped: &Cell<bool>,
    ) {
        process
            .signal(Signal::SIGKILL, Instant::now() + timeout())
            .expect("SIGKILL the container");
        let exit = wait_exit(process, timeout() + TERM_GRACE);
        reaped.set(true);
        assert!(
            matches!(exit, ProcessExit::Signaled(9)),
            "unexpected exit {exit:?}"
        );
        assert_nothing_left(fx, h);
        // CLI の delete と同じ入口。冪等で `Ok`、再確認しても残らない。
        remove_pasta_leftovers(&fx.state_path, &fx.id).expect("remove pasta leftovers");
        assert_nothing_left(fx, h);
    }

    /// B の子: helper の識別を 1 行出して、`wait` を呼ばずに SIGKILL を待つ（`fake_supervisor` と同じ形）。
    fn supervisor_sigkill(fx: &Fixture<'_>, h: Helpers) {
        println!(
            "PLR_HELPERS sup={} pid1={} pasta={} holder={} cg={} state={} work={}",
            Proc::of(std::process::id()).label(),
            h.pid1.label(),
            h.pasta.label(),
            h.holder.label(),
            cgroup_of(h.pid1.pid),
            fx.state_path.display(),
            fx.work.dir.display(),
        );
        let _ = std::io::stdout().flush();
        let until = Instant::now() + PROBE_LIFETIME;
        while Instant::now() < until {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// C: pid1 と holder を SIGKILL して `wait` を呼ばない間に、pasta が netns-quit で自分から終わる。その後の `wait` が
    /// 途中死を検出して終了を返し、何も残らない。
    fn holder_gone(
        fx: &Fixture<'_>,
        process: &dyn LaunchedProcess,
        h: Helpers,
        reaped: &Cell<bool>,
    ) {
        kill_by_pid(h.holder);
        process
            .signal(Signal::SIGKILL, Instant::now() + timeout())
            .expect("SIGKILL the container");
        let started = Instant::now();
        assert!(
            eventually(|| h.pasta.quit()),
            "pasta must quit by itself after the namespace holders were gone (12.10 step 3)"
        );
        obs("netns_quit_ms", &started.elapsed().as_millis().to_string());
        let exit = wait_exit(process, TERM_GRACE + timeout());
        reaped.set(true);
        assert!(
            matches!(exit, ProcessExit::Signaled(9)),
            "unexpected exit {exit:?}"
        );
        assert_nothing_left(fx, h);
    }

    // ----- 親（--ignored） ---------------------------------------------------------------------------------

    pub fn run() -> ExitCode {
        // 前提の確認（副作用の前に fail-closed）。
        let euid = own_euid();
        if euid == 0 {
            println!("pasta_launch_rootless: FAILED: must run as non-root (rootless test)");
            return ExitCode::from(1);
        }
        let _landlock = crate::precondition::landlock_support();
        let _ = xdg_runtime_dir();
        let _ = pasta_binary();
        let restrict =
            std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
                .map_or_else(|_| "absent".to_string(), |v| v.trim().to_string());
        obs("apparmor_restrict_unprivileged_userns", &restrict);
        let subordinate_requested =
            std::env::var("FANDHE_CONTAINER_TEST_ID_HELPER").as_deref() == Ok("1");
        if subordinate_requested {
            if std::env::var("USER").map_or(true, |u| u.is_empty()) {
                crate::precondition::failed(
                    crate::precondition::Kind::SubordinateIds,
                    "USER is not set",
                );
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
            crate::precondition::require_subordinate_ids(euid);
        }

        let _scratch_cleanup = super::scratch_root::ScratchRootCleanup;
        reclaim_child_scratch_selfcheck();
        let tag = std::process::id();
        let mut sequence = 0u32;
        let mut models = vec![false];
        if subordinate_requested {
            models.push(true);
        }
        // `DelegatedCgroup::prepare` は自プロセスを退避リーフへ移すため、1 プロセスで通せる起動は 1 回だけ。
        // シナリオごとに専用の委譲スコープ内の子プロセス（この試験バイナリの `--scenario`）で実行する。
        for kind in [Kind::StopDelete, Kind::SupervisorSigkill, Kind::HolderGone] {
            for &subordinate in &models {
                sequence += 1;
                if kind == Kind::SupervisorSigkill {
                    run_sigkill_scenario(subordinate, tag, sequence);
                } else {
                    run_scenario_in_scope(kind, subordinate, tag, sequence);
                }
            }
        }

        if !subordinate_requested {
            println!(
                "pasta_launch_rootless: subordinate id case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1), not verified"
            );
            return ExitCode::from(1);
        }
        println!(
            "pasta_launch_rootless: production launcher with real pasta verified for stop, delete, supervisor SIGKILL and netns-quit (root=false)"
        );
        ExitCode::SUCCESS
    }

    fn scope_command(kind: Kind, subordinate: bool, tag: u32, sequence: u32) -> Command {
        let exe = std::env::current_exe().expect("current exe");
        let mut cmd = Command::new("systemd-run");
        cmd.args(["--user", "--scope", "--quiet", "-p", "Delegate=yes"])
            .arg(format!("--unit={}", unit_name(tag, sequence)))
            .arg("--")
            .arg(&exe)
            .arg("--scenario")
            .arg(kind.label())
            .arg(if subordinate { "1" } else { "0" })
            .arg(tag.to_string())
            .arg(sequence.to_string());
        cmd
    }

    /// シナリオ専用の scope 名。期限超過・失敗時に scope 全体を止めるため名前を固定する。
    fn unit_name(tag: u32, sequence: u32) -> String {
        format!("fandhe-plr-{tag}-{sequence}.scope")
    }

    fn systemctl_user(args: &[&str]) -> Command {
        let mut cmd = Command::new("systemctl");
        cmd.arg("--user").args(args);
        cmd
    }

    /// 子プロセスが作った scratch ルート（`fandhe-plr-scratch-<子の pid>-*`）の下の `prefix` 前方一致の作業領域を
    /// 消し、空になったルートも消す。自プロセスのルートは対象外（親の別の作業領域を壊さない）。子が SIGKILL
    /// されると `ScratchRootCleanup` が走らないため、親が tag・sequence で特定して回収する（REPAIR-5・REPAIR-12）。
    fn reclaim_child_scratch(temp: &Path, prefix: &str) {
        let own = super::scratch_root::scratch_root("fandhe-plr-scratch", timeout()).to_path_buf();
        for root in std::fs::read_dir(temp).into_iter().flatten().flatten() {
            let path = root.path();
            if path == own
                || !root
                    .file_name()
                    .to_string_lossy()
                    .starts_with("fandhe-plr-scratch-")
            {
                continue;
            }
            let mut removed = false;
            for e in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                if e.file_name().to_string_lossy().starts_with(prefix) {
                    removed |= std::fs::remove_dir_all(e.path()).is_ok();
                }
            }
            if removed {
                // 空のときだけ消える（他のシナリオの領域が残っていれば消さない）。
                let _ = std::fs::remove_dir(&path);
            }
        }
    }

    /// `reclaim_child_scratch` の自己確認。子の pid 入りのルートを模した領域が、一致する作業領域だけ回収され、
    /// 一致しない領域は残ることを具体的なパスで確かめる。
    fn reclaim_child_scratch_selfcheck() {
        let guard = super::scratch_root::ScratchDir::new("fandhe-plr-selfcheck", timeout());
        let fake_root = guard.path().join("fandhe-plr-scratch-999999-1");
        let hit = fake_root.join("fandhe-plr-t1-s1-work");
        let keep = fake_root.join("fandhe-plr-t1-s2-work");
        std::fs::create_dir_all(&hit).expect("create hit dir");
        std::fs::create_dir_all(&keep).expect("create keep dir");
        reclaim_child_scratch(guard.path(), "fandhe-plr-t1-s1-");
        assert!(!hit.exists(), "matching child work dir must be reclaimed");
        assert!(keep.exists(), "non-matching work dir must stay");
        assert!(fake_root.exists(), "non-empty child root must stay");
        reclaim_child_scratch(guard.path(), "fandhe-plr-t1-s2-");
        assert!(!fake_root.exists(), "emptied child root must be removed");
    }

    /// 期限超過・失敗時の回収（REPAIR-5 と資源回収の両立）。直接の子だけでなく scope 全体（起動途中で止まった
    /// pid1・pasta・holder などの子孫）を SIGKILL して消滅を確認し、親側から一時領域も消す。scope が消えなければ
    /// panic する（消滅の確認を後始末の成否として表に出す）。
    fn reclaim_scenario(child: &mut std::process::Child, tag: u32, sequence: u32) {
        let unit = unit_name(tag, sequence);
        let gone = reclaim_scope(child, tag, sequence);
        assert!(gone, "scenario scope {unit} must disappear after SIGKILL");
    }

    /// `reclaim_scenario` の本体。scope 全体の SIGKILL と停止・消滅の確認（期限つき）・一時領域の回収を行い、
    /// scope が消えたかを返す。panic しないので、別の panic を再送出する前の後始末にも使える（元の panic を
    /// 後始末の panic で上書きしない）。
    fn reclaim_scope(child: &mut std::process::Child, tag: u32, sequence: u32) -> bool {
        let unit = unit_name(tag, sequence);
        let limit = crate::reap::reap_within();
        if let Err(e) = crate::reap::run_within(
            systemctl_user(&["kill", "--kill-whom=all", "--signal=SIGKILL", &unit])
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            limit,
        ) {
            eprintln!("scope kill failure: {e}");
        }
        let _ = crate::reap::run_within(
            systemctl_user(&["stop", &unit])
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            limit,
        );
        crate::reap::reap_or_report(child, limit);
        let gone = eventually_within(limit, || {
            let out = crate::reap::output_within(
                &mut systemctl_user(&["show", "-p", "ActiveState", "--value", &unit]),
                Duration::from_secs(10),
            );
            match out {
                Ok(o) => !matches!(
                    String::from_utf8_lossy(&o.stdout).trim(),
                    "active" | "activating" | "deactivating"
                ),
                Err(_) => false,
            }
        });
        if !gone {
            eprintln!("scope {unit} is still active after SIGKILL");
        }
        // 一時領域: 子の TempDir は Drop されないため、tag と sequence の前方一致で回収する。
        let prefix = format!("fandhe-plr-t{tag}-s{sequence}-");
        for e in std::fs::read_dir(xdg_runtime_dir())
            .into_iter()
            .flatten()
            .flatten()
        {
            if e.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
        // 子は再実行された別プロセスで、自分の pid 入りの scratch ルートを作る（親の `scratch_root()` とは別）。
        match std::fs::canonicalize(std::env::temp_dir()) {
            Ok(temp) => reclaim_child_scratch(&temp, &prefix),
            Err(e) => eprintln!("canonicalize temp_dir failed: {e}"),
        }
        gone
    }

    /// 1 シナリオを `systemd-run --user --scope -p Delegate=yes` の子プロセスで実行し、期限つきで成功を確認する。
    fn run_scenario_in_scope(kind: Kind, subordinate: bool, tag: u32, sequence: u32) {
        let mut child = scope_command(kind, subordinate, tag, sequence)
            .spawn()
            .expect("spawn systemd-run for scenario");
        let deadline = Instant::now() + SCENARIO_DEADLINE;
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait scenario") {
                break status;
            }
            if Instant::now() >= deadline {
                reclaim_scenario(&mut child, tag, sequence);
                panic!(
                    "scenario {}-{} exceeded {SCENARIO_DEADLINE:?}",
                    kind.label(),
                    privilege_label(subordinate)
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        if !status.success() {
            // 失敗した子が残した子孫・一時領域も回収する。
            reclaim_scenario(&mut child, tag, sequence);
        }
        assert!(
            status.success(),
            "scenario {}-{} failed: {status}",
            kind.label(),
            privilege_label(subordinate)
        );
    }

    /// `key=value` 形式のトークンから値を取り出す。
    fn field<'a>(line: &'a str, key: &str) -> &'a str {
        line.split_whitespace()
            .find_map(|t| t.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
            .unwrap_or_else(|| panic!("missing {key} in the helper line"))
    }

    /// B: supervisor 役の子を外から SIGKILL して、pasta と holder が消え pid1 が生き残ることを照合する。
    fn run_sigkill_scenario(subordinate: bool, tag: u32, sequence: u32) {
        let kind = Kind::SupervisorSigkill;
        let mut child = scope_command(kind, subordinate, tag, sequence)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn systemd-run for scenario");
        let out = child.stdout.take().expect("child stdout");
        let (tx, rx) = mpsc::channel::<String>();
        // 内部行（PLR_HELPERS）以外は、子の観測行としてそのまま流す。
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(out).lines() {
                match line {
                    Ok(l) if l.starts_with("PLR_HELPERS ") => {
                        let _ = tx.send(l);
                    }
                    Ok(l) => println!("{l}"),
                    Err(_) => break,
                }
            }
        });
        let line = match rx.recv_timeout(SCENARIO_DEADLINE) {
            Ok(l) => l,
            Err(_) => {
                reclaim_scenario(&mut child, tag, sequence);
                panic!("supervisor-sigkill scenario did not report its helpers in time");
            }
        };
        let sup = parse_proc(field(&line, "sup"));
        let h = (
            parse_proc(field(&line, "pid1")),
            parse_proc(field(&line, "pasta")),
            parse_proc(field(&line, "holder")),
        );
        let cg = field(&line, "cg").to_string();
        let state = PathBuf::from(field(&line, "state"));
        let work = PathBuf::from(field(&line, "work"));
        let id = container_id(tag, sequence);

        let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            kill_by_pid(sup);
            crate::reap::reap(&mut child, timeout()).expect("reap the killed supervisor scope");
            assert!(
                eventually(|| h.1.gone() && h.2.gone()),
                "pasta and holder must die with the killed supervisor (PDEATHSIG)"
            );
            assert!(
                h.0.alive(),
                "the orphaned container pid1 must keep running (SUP-5)"
            );
        }));

        // 検証に失敗したとき（PDEATHSIG の回帰で holder・pasta が生き残った等）は、コンテナの cgroup だけでなく
        // 退避リーフの holder・pasta を含む scope 全体を先に SIGKILL・停止し、消滅を確かめてから一時領域を消す。
        // holder が netns を保持し続けると pasta の netns-quit も働かず、helper・公開ポート・scope が後続の試験に
        // 残るため（REPAIR-5）。消えなければ stderr に出し、元の panic を優先して再送出する。
        if checked.is_err() {
            if !reclaim_scope(&mut child, tag, sequence) {
                eprintln!(
                    "scope {} was not reclaimed after the failed check",
                    unit_name(tag, sequence)
                );
            }
            if !eventually(|| h.1.gone() && h.2.gone()) {
                eprintln!(
                    "pasta {} or holder {} is still alive after the scope was reclaimed",
                    h.1.label(),
                    h.2.label()
                );
            }
        }

        // 後始末（成否に関わらず）: pid1 を cgroup.kill で止め、cgroup を消し、残骸を回収する。
        let cg_dir = PathBuf::from(format!("/sys/fs/cgroup{cg}"));
        let _ = std::fs::write(cg_dir.join("cgroup.kill"), "1");
        let pid1_gone = eventually(|| h.0.gone());
        let cg_removed = eventually(|| std::fs::remove_dir(&cg_dir).is_ok() || !cg_dir.exists());
        let leftovers = remove_pasta_leftovers(&state, &id);
        let pasta_dir_left = state.join("@pasta").join(id.as_str()).exists();
        // 子（SIGKILL された supervisor 役）が消せなかった一時領域の掃除。
        let _ = std::fs::remove_dir_all(&work);
        // 子は SIGKILL で `ScratchRootCleanup` が走らないため、work の親（子の pid 入りの scratch ルート
        // `fandhe-plr-scratch-<子の pid>-*`）が空で残る。空のときだけ消える `remove_dir` で回収する
        // （自プロセスのルートと他シナリオの領域は対象外）。
        if let Some(root) = work.parent() {
            let own =
                super::scratch_root::scratch_root("fandhe-plr-scratch", timeout()).to_path_buf();
            let is_child_root = root != own
                && root
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("fandhe-plr-scratch-"));
            if is_child_root {
                let _ = std::fs::remove_dir(root);
            }
        }
        if let Some(xdg) = state.parent() {
            let _ = std::fs::remove_dir_all(xdg);
        }
        // work を消しても子の scratch ルート（`fandhe-plr-scratch-<子の pid>-*`）自体は空で残る。子は SIGKILL で
        // `ScratchRootCleanup` が走らないため、親が tag・sequence の前方一致で作業領域と空のルートを回収する。
        let temp = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp_dir");
        reclaim_child_scratch(&temp, &format!("fandhe-plr-t{tag}-s{sequence}-"));
        if let Err(p) = checked {
            std::panic::resume_unwind(p);
        }
        assert!(pid1_gone, "pid1 must disappear after cgroup.kill");
        assert!(cg_removed, "the container cgroup must be removable");
        leftovers.expect("remove pasta leftovers");
        assert!(!pasta_dir_left, "@pasta/<id> must be removed");
        println!("{}", success_line(kind, subordinate));
    }
}
