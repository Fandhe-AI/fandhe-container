//! rootless の稼働中コンテナへの exec が、起動経路（本番 `ProductionLauncher`）で作った network namespace へ参加して
//! 通ることを照合する実機前提の結合試験（SUP-6・NET-9・CORE-6・SEC-5・REPAIR-12。#3349・#1939・#3198）。
//!
//! #1939 で core の rootless 起動経路に netns の作成と exec 直前の同期点（`LaunchNetworkMode::Loopback` /
//! `Attachable`）が入ったが、稼働中のコンテナへの exec がその netns に参加して動くことを起動経路そのままで確かめる試験が
//! 無かった。`exec.rs --ignored --rootless` はコンテナ役を `unshare(1)` で手組みするため起動経路の netns を通らず、
//! root が要る場面と同じファイルで CI でもビルドだけだった。本試験は次の本番の入口だけを通す
//! （`exec-test-support` の試験専用入口は使わない）。
//! - core の `create` → `start`（`ProductionLauncher`。start の前に本番と同じ cgroup の連鎖で配置を記録）
//! - supervisor の本番 exec 入口 `run_command_with_pidfd`
//! - Attachable では supervisor の本番の holder 起動 `netns_holder::spawn_netns_holder`（同期点の `NetnsAttachHook` から呼ぶ）
//!
//! # 照合項目（具体値）
//! 4 シナリオ（`loopback` / `attachable` × `single` / `subordinate`）のそれぞれで、次がすべて同じ inode であること。
//! - exec したコマンドが書いた `/proc/self/ns/net`
//! - ホストから見た pid1 の `/proc/<pid1>/ns/net` と、pid1 の自己申告
//! - （Attachable のみ）フックが受け取った net の fd・`HolderReady.identity.net_ino`・ホストから見た holder の
//!   `/proc/<holder>/ns/net`
//!
//! user namespace も同様に exec の値が pid1 のものと一致する（Attachable は holder の識別とも）。陰性対照として、これらは
//! 試験プロセス自身の netns / userns と異なる（継承ではなく参加した証拠）。Attachable は pid1 の消滅後も holder が同じ
//! netns を保持し、`stop()` が `Stopped`・終了コード 0 で終わる。
//!
//! # 範囲外（REPAIR-3）
//! - pasta を含めた起動からの通し確認（`PastaAttachHook`）は #3331。ホステッド runner に pasta が無いため、本試験の
//!   フックは holder の起動だけを行う試験用実装
//! - restart の再 launch は #2043 まで拒否される。rootful の Attachable は未実装（#3069）
//!
//! # 必要環境
//! 非 root・非特権 user namespace（AppArmor 緩和）・委譲 cgroup v2・Landlock ABI 6 以上。範囲写像の 2 シナリオは
//! `FANDHE_CONTAINER_TEST_ID_HELPER=1`・uidmap・subuid / subgid（自ユーザー行）も要る（未設定なら single の 2 シナリオだけを
//! 回し、成功を装わず終了コード 1 で終わる）。`harness = false` で `-- --ignored` 指定時のみ動かす。
//!
//! ```text
//! cargo test -p fandhe-container-supervisor --test exec_launch_netns_rootless --no-run
//! FANDHE_CONTAINER_TEST_ID_HELPER=1 USER=$(id -un) systemd-run --user --scope -p Delegate=yes <target/debug/deps/exec_launch_netns_rootless-XXXX> --ignored
//! ```
//!
//! 成功時の最終行: `exec_launch_netns_rootless: rootless exec joined the launch-path netns for loopback and attachable verified (root=false)`。

#[path = "../../core/tests/support/reap.rs"]
#[allow(dead_code)]
mod reap;

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("exec_launch_netns_rootless: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!(
        "exec_launch_netns_rootless: x86_64/aarch64 only, not applicable on this architecture"
    );
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
    // Attachable のフックは READY 待ちのタイムアウトで失敗する。
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
        Some("--exec-probe") => {
            let name = args.next().and_then(|a| a.into_string().ok());
            linux::exec_probe(name.as_deref());
        }
        Some("--ignored") => {
            precondition::self_check();
            return linux::run();
        }
        _ => {
            precondition::self_check();
            println!(
                "exec_launch_netns_rootless: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
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
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditRecord, AuditSink};
    use fandhe_container_core::cgroups::CgroupLimitPlan;
    use fandhe_container_core::exec::{ChildExit, ExecExit, IsolationPrivilege};
    use fandhe_container_core::injected_files::InjectedFileSet;
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        AttachableNamespaces, LaunchIpcMode, LaunchNetworkMode, LaunchOptions, NetnsAttachHook,
        ProcessLauncher, ProductionLauncher, StartTimeouts, SubordinateIdSource, create, start,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::tmpfs::TmpfsMountSet;
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, GetStateRequest, StartRequest, StateRecord,
        StateStore, TraitError,
    };
    use fandhe_container_net::netns_holder::NetnsHolderFds;
    use fandhe_container_supervisor::exec::{ExecRequest, run_command_with_pidfd};
    use fandhe_container_supervisor::netns_holder::{
        NetnsHolderProcess, StopPath, spawn_netns_holder,
    };

    use super::rootfs;

    /// コンテナ内の bind 先（ホストの `hostdata/` を `rw` で束ねる。pid1 の ready 通知と観測値の受け渡し口）。
    const DATA_DEST: &str = "/data";
    const READY_FILE: &str = "ready";
    const READY_CONTENT: &str = "READY";
    /// pid1 が自分の netns / userns を書くファイル名。
    const PID1_NS_FILE: &str = "pid1-ns";
    /// exec したコマンドが netns / userns を書くファイル名。
    const EXEC_NS_FILE: &str = "exec-ns";
    /// pid1 の寿命の上限（取り残し防止。REPAIR-5）。超えたら終了コード 8。
    const PROBE_LIFETIME: Duration = Duration::from_secs(60);

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

    // ----- コンテナ内の役 ----------------------------------------------------------------------------------

    fn ns_links() -> Option<String> {
        let net = std::fs::read_link("/proc/self/ns/net").ok()?;
        let user = std::fs::read_link("/proc/self/ns/user").ok()?;
        Some(format!("{}\n{}\n", net.display(), user.display()))
    }

    /// pid1 の役。自分の netns / userns を `/data/pid1-ns` へ、続けて `/data/ready` へ `READY` を書き、親が terminate
    /// するまで待つ（寿命の上限つき）。
    pub fn container_probe() {
        let Some(ns) = ns_links() else {
            std::process::exit(7);
        };
        let ns_path = format!("{DATA_DEST}/{PID1_NS_FILE}");
        if std::fs::write(&ns_path, ns).is_err() {
            std::process::exit(9);
        }
        let _ = std::fs::set_permissions(&ns_path, std::fs::Permissions::from_mode(0o644));
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

    /// exec されるコマンドの役。コンテナ内の `/proc/self/ns/{net,user}` を `/data/<name>` へ書く。
    pub fn exec_probe(name: Option<&str>) {
        let Some(name) = name.filter(|n| !n.is_empty() && !n.contains('/')) else {
            std::process::exit(2);
        };
        let Some(ns) = ns_links() else {
            std::process::exit(3);
        };
        let path = format!("{DATA_DEST}/{name}");
        if std::fs::write(&path, ns).is_err() {
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
            let dir = super::scratch_root::scratch_root("fandhe-elnr-scratch", timeout())
                .join(format!("fandhe-elnr-{tag}-{}-{nanos}", std::process::id()));
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

    /// 監査レコードを数えるだけの sink（成功経路は 0 件であること）。
    struct MemSink(Mutex<Vec<AuditRecord>>);

    impl MemSink {
        fn count(&self) -> usize {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len()
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

    /// 実効 uid（`/proc/self/status`）。
    fn own_euid() -> u32 {
        status_field("/proc/self/status", "Uid:")
            .and_then(|v| v.split_whitespace().nth(1).map(str::to_string))
            .and_then(|v| v.parse().ok())
            .expect("parse euid")
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

    /// 呼び出しプロセスが単一スレッドに戻るのを待つ（fork と holder 起動の前提）。
    fn wait_single_thread() {
        assert!(
            eventually(|| status_field("/proc/self/status", "Threads:").as_deref() == Some("1")),
            "the test process must be single-threaded before a launch, a holder spawn or an exec"
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

    /// ns の inode（`/proc/<x>/ns/<kind>` や `/proc/self/fd/N` を辿った先）。
    fn ns_ino(path: &str) -> u64 {
        std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("stat {path}: {e}"))
            .ino()
    }

    /// `readlink` 表記 `net:[N]` / `user:[M]` から inode を取り出す。
    fn parse_ns_link(line: &str, kind: &str) -> u64 {
        line.strip_prefix(kind)
            .and_then(|s| s.strip_prefix(":["))
            .and_then(|s| s.strip_suffix(']'))
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("unexpected ns link {line:?} for {kind}"))
    }

    /// `pid1-ns` / `exec-ns` の 2 行（net, user）を `(net_ino, user_ino)` にする。
    fn read_ns_file(path: &Path) -> (u64, u64) {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let mut lines = text.lines();
        let net = lines.next().expect("net line");
        let user = lines.next().expect("user line");
        (parse_ns_link(net, "net"), parse_ns_link(user, "user"))
    }

    /// `process.user` は uid 0・gid 0（どちらの写像モデルでも起動ユーザーに写る）。network の `linux.namespaces` エントリは
    /// 置かない（起動オプションの `Loopback` / `Attachable` が新しい netns を要求する）。
    /// 書式は `exec_subordinate_e2e` の `config_text` に揃える（`serde_json` は supervisor の依存に無いため手書き）。
    fn config_text(ld: &str, bind_src: &Path) -> String {
        let src = bind_src.to_str().expect("utf8 bind source");
        format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"hostname":"fandhe-elnr",
"process":{{"user":{{"uid":0,"gid":0}},"args":["/probe","--container-probe"],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"mounts":[{{"destination":"{DATA_DEST}","type":"bind","source":"{src}","options":["bind","rw"]}}],
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#
        )
    }

    // ----- Attachable の試験用フック -----------------------------------------------------------------------

    /// 同期点で受け取った netns / userns の fd の inode を記録し、本番の `spawn_netns_holder` で holder へ渡す試験用のフック
    /// （`PastaAttachHook` の holder 部分だけ。pasta は起動しない。#3331）。
    struct HolderAttachHook {
        /// フックが受け取った `(net_ino, user_ino)`。
        seen: Mutex<Option<(u64, u64)>>,
        /// 起動した holder（READY 済み）。
        holder: Mutex<Option<NetnsHolderProcess>>,
    }

    impl NetnsAttachHook for HolderAttachHook {
        fn attach(
            &self,
            namespaces: AttachableNamespaces,
            deadline: Instant,
        ) -> Result<(), TraitError> {
            let net_ino = ns_ino(&format!("/proc/self/fd/{}", namespaces.net().as_raw_fd()));
            let user_ino = ns_ino(&format!("/proc/self/fd/{}", namespaces.user().as_raw_fd()));
            *self
                .seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((net_ino, user_ino));
            // 戻りの順は `(user, net)`。holder の受け口 `NetnsHolderFds::new(user, net)` の引数の順に合わせてある。
            let (user, net) = namespaces.into_parts();
            let fds = NetnsHolderFds::new(user, net).map_err(|e| {
                TraitError::new(
                    fandhe_container_core::traits::ErrorCode::Internal,
                    e.to_string(),
                )
            })?;
            let holder = spawn_netns_holder(fds, deadline).map_err(|e| e.trait_error())?;
            *self
                .holder
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(holder);
            Ok(())
        }
    }

    // ----- シナリオ ----------------------------------------------------------------------------------------

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Loopback,
        Attachable,
    }

    impl Mode {
        fn label(self) -> &'static str {
            match self {
                Self::Loopback => "loopback",
                Self::Attachable => "attachable",
            }
        }
    }

    fn privilege_label(subordinate: bool) -> &'static str {
        if subordinate { "subordinate" } else { "single" }
    }

    pub fn run() -> ExitCode {
        // 前提の確認（副作用の前に fail-closed）。
        let euid = own_euid();
        if euid == 0 {
            println!("exec_launch_netns_rootless: FAILED: must run as non-root (rootless test)");
            return ExitCode::from(1);
        }
        let _landlock = crate::precondition::landlock_support();
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
        let delegated = crate::precondition::delegated_cgroup();

        // 一時領域の親ディレクトリ（tmpfiles の掃除と flock 競合の回避）を panic でも消す。
        let _scratch_cleanup = super::scratch_root::ScratchRootCleanup;
        let tag = std::process::id();
        let mut sequence = 0u32;
        let mut models = vec![false];
        if subordinate_requested {
            models.push(true);
        }
        for mode in [Mode::Loopback, Mode::Attachable] {
            for &subordinate in &models {
                sequence += 1;
                scenario(&delegated, mode, subordinate, tag, sequence);
            }
        }

        if !subordinate_requested {
            println!(
                "exec_launch_netns_rootless: subordinate id case not requested (set FANDHE_CONTAINER_TEST_ID_HELPER=1), not verified"
            );
            return ExitCode::from(1);
        }
        println!(
            "exec_launch_netns_rootless: rootless exec joined the launch-path netns for loopback and attachable verified (root=false)"
        );
        ExitCode::SUCCESS
    }

    /// `/data` の準備完了通知（`hostdata/ready` が `READY` になる）を期限つきで待つ。
    fn wait_ready(hostdata: &Path) {
        let path = hostdata.join(READY_FILE);
        assert!(
            eventually(|| std::fs::read_to_string(&path).is_ok_and(|s| s == READY_CONTENT)),
            "the container probe must report READY"
        );
    }

    fn scenario(
        delegated: &fandhe_container_core::cgroups::DelegatedCgroup,
        mode: Mode,
        subordinate: bool,
        tag: u32,
        sequence: u32,
    ) {
        let privilege = if subordinate {
            IsolationPrivilege::RootlessSubordinateIds
        } else {
            IsolationPrivilege::RootlessSingleId
        };
        let work = TempDir::new(&format!("s{sequence}"));
        let store = FileStateStore::open(
            StateRoot::from_override(work.dir.join("state")).expect("state root"),
        )
        .expect("open state store");
        let id = ContainerId::new(format!("elnr{tag}s{sequence}")).expect("container id");

        // bind 元は 0700 で足りる（コンテナ内の uid 0 は起動ユーザーに写るため）。
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

        // 本番と同じ cgroup の連鎖。配置が状態記録へ載らないと exec が拒否する。
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

        let hook = Arc::new(HolderAttachHook {
            seen: Mutex::new(None),
            holder: Mutex::new(None),
        });
        let launcher: Arc<dyn ProcessLauncher> = {
            let mut tmpfs = TmpfsMountSet::new();
            tmpfs.ensure_default_dev_shm().expect("default dev shm");
            let network = match mode {
                Mode::Loopback => LaunchNetworkMode::Loopback,
                Mode::Attachable => LaunchNetworkMode::Attachable,
            };
            let options = LaunchOptions::new(tmpfs, InjectedFileSet::new(), LaunchIpcMode::Private)
                .expect("launch options")
                .with_network(network);
            let mut builder = ProductionLauncher::builder().privilege(privilege);
            if subordinate {
                builder = builder.subordinate_ids(
                    SubordinateIdSource::system(std::env::var("USER").ok())
                        .expect("subordinate ids"),
                );
            }
            let cgroup = Arc::clone(&container_cgroup);
            let mut builder = builder
                .audit_sink(Arc::new(MemSink(Mutex::new(Vec::new()))))
                .cgroup_join_source(move || cgroup.join_hook())
                .launch_options(options);
            if mode == Mode::Attachable {
                let attach_hook: Arc<dyn NetnsAttachHook> = hook.clone();
                builder = builder.netns_attach_hook(attach_hook);
            }
            Arc::new(builder.build().expect("build launcher"))
        };

        // 後始末は成否に関わらず行う（panic でも cgroup・holder・一時領域を残さない）。
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify(
                &store,
                &recorder,
                &id,
                &launcher,
                &hostdata,
                &hook,
                mode,
                subordinate,
            );
        }));
        // 失敗時に holder が残っていれば drop で EOF と SIGKILL・回収される。
        drop(
            hook.holder
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
        let removed = delegated.remove_child(&container_cgroup);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        removed.expect("remove container cgroup");
        drop(work);
    }

    #[allow(clippy::too_many_arguments)]
    fn verify(
        store: &FileStateStore,
        recorder: &OpRecorder,
        id: &ContainerId,
        launcher: &Arc<dyn ProcessLauncher>,
        hostdata: &Path,
        hook: &Arc<HolderAttachHook>,
        mode: Mode,
        subordinate: bool,
    ) {
        let host_net = ns_ino("/proc/self/ns/net");
        let host_user = ns_ino("/proc/self/ns/user");

        // holder の起動は main スレッド・単一スレッドを要求する。start は launch を呼び出しスレッドで直接呼ぶ
        // （`ProductionLauncher::launch_mode` は `SelfBounded`）ので、ここは main のまま呼ぶ。
        wait_single_thread();
        let started = start(
            store,
            recorder,
            launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        let pid_u32 = pid.get();
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(started.record().status().state(), ContainerState::Running);
            wait_ready(hostdata);
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

            let sink = MemSink(Mutex::new(Vec::new()));
            wait_single_thread();
            let request = ExecRequest::new("/probe", ["/probe", "--exec-probe", EXEC_NS_FILE])
                .expect("exec request");
            let outcome = run_command_with_pidfd(&record, pidfd, &request, timeout(), &sink)
                .unwrap_or_else(|r| {
                    panic!("exec failed: {:?} {}", r.error.code(), r.error.message())
                });
            assert_eq!(
                outcome.outcome.exit,
                ExecExit::Command(ChildExit::Exited(0))
            );
            assert_eq!(
                sink.count(),
                0,
                "a successful exec must record no audit entry"
            );

            // netns / userns の一致（具体値）。
            let (exec_net, exec_user) = read_ns_file(&hostdata.join(EXEC_NS_FILE));
            let (self_net, self_user) = read_ns_file(&hostdata.join(PID1_NS_FILE));
            let pid1_net = ns_ino(&format!("/proc/{pid_u32}/ns/net"));
            let pid1_user = ns_ino(&format!("/proc/{pid_u32}/ns/user"));
            eprintln!(
                "exec_launch_netns_rootless: diag mode={} model={} host_net={host_net} pid1_net={pid1_net} exec_net={exec_net} host_user={host_user} pid1_user={pid1_user} exec_user={exec_user}",
                mode.label(),
                privilege_label(subordinate),
            );
            assert_eq!(self_net, pid1_net, "pid1 self-reported netns vs host view");
            assert_eq!(
                self_user, pid1_user,
                "pid1 self-reported userns vs host view"
            );
            assert_eq!(exec_net, pid1_net, "exec must join the launch-path netns");
            assert_eq!(exec_user, pid1_user, "exec must join the container userns");
            // 陰性対照: 継承ではなく参加した証拠。
            assert_ne!(exec_net, host_net, "the container netns must be new");
            assert_ne!(exec_user, host_user, "the container userns must be new");

            if mode == Mode::Attachable {
                let seen = hook
                    .seen
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .expect("the hook must have been called once before exec");
                assert_eq!(seen.0, exec_net, "hook netns fd vs exec netns");
                assert_eq!(seen.1, exec_user, "hook userns fd vs exec userns");
                let guard = hook
                    .holder
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let holder = guard.as_ref().expect("the holder must have been spawned");
                let ident = holder.ready().identity;
                assert_eq!(
                    ident.net_ino, exec_net,
                    "holder READY identity vs exec netns"
                );
                assert_eq!(
                    ident.user_ino, exec_user,
                    "holder READY identity vs exec userns"
                );
                assert_eq!(
                    ns_ino(&format!("/proc/{}/ns/net", holder.pid())),
                    exec_net,
                    "holder host view netns vs exec netns"
                );
            }
        }));
        let (_record, process) = started.into_parts();
        let terminated = process.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "exec_launch_netns_rootless: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{pid_u32}")).exists()),
            "/proc/{pid_u32} must disappear after terminate"
        );

        if mode == Mode::Attachable {
            // PID 1 が消えても holder が同じ netns を保持している。続けて holder を止めて回収する。
            let holder = hook
                .holder
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .expect("holder");
            let held = holder.ready().identity.net_ino;
            assert_eq!(
                ns_ino(&format!("/proc/{}/ns/net", holder.pid())),
                held,
                "holder must keep the netns after pid1 is gone"
            );
            let outcome = holder.stop();
            assert_eq!(outcome.path, StopPath::Stopped);
            assert_eq!(outcome.exit.as_ref().and_then(|e| e.code), Some(0));
        }
        assert!(
            eventually(|| children_of_self().is_empty()),
            "no child may remain after terminate and holder stop"
        );
        // 成功行は固定文言（`{}` を含めない）にする。CI の `check-success-lines.sh` が試験ソースの文字列リテラルから
        // 期待行を導出して双方向に照合するため。
        let line = match (mode, subordinate) {
            (Mode::Loopback, false) => {
                "exec_launch_netns_rootless: scenario=loopback-single exec joined the launch-path netns (net inode matched pid1, differed from host)"
            }
            (Mode::Loopback, true) => {
                "exec_launch_netns_rootless: scenario=loopback-subordinate exec joined the launch-path netns (net inode matched pid1, differed from host)"
            }
            (Mode::Attachable, false) => {
                "exec_launch_netns_rootless: scenario=attachable-single exec joined the launch-path netns held by the netns holder (net inode matched pid1, hook fd and holder, differed from host)"
            }
            (Mode::Attachable, true) => {
                "exec_launch_netns_rootless: scenario=attachable-subordinate exec joined the launch-path netns held by the netns holder (net inode matched pid1, hook fd and holder, differed from host)"
            }
        };
        println!("{line}");
    }
}
