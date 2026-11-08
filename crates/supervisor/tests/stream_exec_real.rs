//! stream-exec helper の本番の経路（制御チャネルの kind 6 / 7 → `run_command_with_pidfd_output_notify` → 実コマンド）を、
//! rootless の稼働中コンテナで通す実機前提の結合試験（SUP-6・SEC-1・REPAIR-5・REPAIR-12。#3760）。
//!
//! 試験プロセスが supervisor 役（`ControlServer` + `SignalSlot` + `ControlledProcess` + `StoreExecReclaimer`）と
//! plugin-cri 役（helper の起動・stdio の pipe・`send_stdio_handover`・`recv_from_helper`）を兼ねる。helper は
//! この試験バイナリ自身の再実行（第 1 引数 `stream-exec` を bin の `main` と同じ振り分けで受ける）。コンテナの起動は
//! core の `create` → `start`（`ProductionLauncher`）だけを通し、`exec-test-support` の試験専用入口は使わない。
//!
//! # 照合項目（具体値）
//! - `echo`: `Started` の後に `Result(Exited(0))`。stdout は `se-stdout-line\n`、stderr は `se-stderr-line\n` と別々に一致する。
//! - `exit3`: `Result(Exited(3))`。
//! - `stdin`: 渡した stdin のバイト列（`se-stdin-payload\n`）がコマンドの stdout に戻る。
//! - `disconnect`（接続断での停止。REPAIR-5）: `Started` の後に helper を SIGKILL すると、supervisor のガードが exec 子 cgroup
//!   を回収し、コマンドの心拍ファイルが増えなくなる。`Result` は届かず channel は EOF（`Closed`）になる。
//! - `requester_killed`（要求元の異常終了。SUP-6・SEC-1・REPAIR-5・#4167）: 終わらないコマンド（`ready-sleep`）を exec の期限 120 秒で
//!   実行し、要求元（channel の端を持つ偽の `/bin/sleep`）を SIGKILL してから helper が終わるまでを測る。2 秒以内（設計 doc の目標値）・
//!   終了コード 1（`Result` を送る相手が居ない）・fd 2 の診断行・コマンドが `/proc` に残らないことを具体値で照合する。
//!   期限（120 秒）や `hold_grace` による終了と区別するため、期限を大きく取る。
//! - `orphan`: supervisor（制御サーバー）が居ない状態では pidfd を受けられず `Failed(Unavailable)`。記録 pid からの縮退はしない。
//!
//! # 必要環境
//! 非 root・非特権 user namespace（AppArmor 緩和）・委譲 cgroup v2・Landlock ABI 6 以上（`healthcheck_exec_real` と同じ前提。
//! 範囲写像は使わない）。前提が欠けていれば `PRECONDITION FAILED` で終了コード 1（成功を装わない）。`harness = false` で
//! `-- --ignored` 指定時のみ動かす。
//!
//! ```text
//! cargo test -p fandhe-container-supervisor --test stream_exec_real --no-run
//! <target/debug/deps/stream_exec_real-XXXX> --ignored
//! ```
//!
//! 各シナリオは `DelegatedCgroup::prepare` が自プロセスを退避リーフへ移すため、試験自身が
//! `systemd-run --user --scope -p Delegate=yes` の子プロセス（`--scenario`）で実行する（外側を包まない）。
//!
//! 成功時の最終行: `stream_exec_real: real stream-exec helper ran commands in a rootless container and reported exit codes, separate stdio, stdin and the disconnect stop (root=false)`。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("stream_exec_real: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("stream_exec_real: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() -> std::process::ExitCode {
    use fandhe_container_supervisor::stream_exec::helper::{
        is_stream_exec_invocation, run_stream_exec_main,
    };
    let mut args = std::env::args_os();
    let _exe = args.next();
    let first = args.next();
    // helper はこの試験バイナリ自身の再実行として起動される。bin の main と同じ振り分け。
    if is_stream_exec_invocation(first.as_deref()) {
        return run_stream_exec_main(args);
    }
    let first = first.and_then(|a| a.into_string().ok());
    match first.as_deref() {
        Some("--container-probe") => linux::container_probe(),
        Some("--se-cmd") => {
            let mode = args.next().and_then(|a| a.into_string().ok());
            linux::se_cmd(mode.as_deref());
        }
        Some("--scenario") => {
            precondition::self_check();
            return linux::scenario_main();
        }
        Some("--ignored") => {
            precondition::self_check();
            return linux::run();
        }
        _ => {
            precondition::self_check();
            println!(
                "stream_exec_real: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
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

/// 前提欠如（委譲 cgroup・Landlock）を `PRECONDITION FAILED` の 1 行目で報告する共有部品（REPAIR-12）。
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
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::process::{Child, ExitCode, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditRecord, AuditSink};
    use fandhe_container_core::cgroups::CgroupLimitPlan;
    use fandhe_container_core::exec::{ChildSubreaper, ContainerChild, IsolationPrivilege};
    use fandhe_container_core::injected_files::InjectedFileSet;
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{
        LaunchIpcMode, LaunchNetworkMode, LaunchOptions, LaunchedProcess, ProcessLauncher,
        ProductionLauncher, StartTimeouts, create, start,
    };
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::tmpfs::TmpfsMountSet;
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, ErrorCode, GetStateRequest, StartRequest,
        StateStore, TraitError,
    };
    use fandhe_container_supervisor::control::listener::{ControlListener, effective_uid};
    use fandhe_container_supervisor::control::observe::ControlObserver;
    use fandhe_container_supervisor::control::server::{ControlServer, ServeConfig};
    use fandhe_container_supervisor::control::target::{ControlledProcess, SignalSlot};
    use fandhe_container_supervisor::control::{
        ExecCgroupReclaimer, ExecGuardLimits, ExecGuardPool, StoreExecReclaimer,
    };
    use fandhe_container_supervisor::stream_exec::channel::{
        ChannelError, HelperMessage, StdioSend, recv_from_helper, send_stdio_handover,
    };
    use fandhe_container_supervisor::stream_exec::helper::{StreamExecArgs, stream_exec_command};
    use fandhe_container_supervisor::stream_exec::wire::{StdioMask, StreamExecOutcome};

    use super::rootfs;

    /// コンテナ内の bind 先（ホストの `hostdata/` を `rw` で束ねる）。
    const DATA_DEST: &str = "/data";
    const READY_FILE: &str = "ready";
    const READY_CONTENT: &str = "READY";
    /// `beat` コマンドが追記する心拍ファイル名。
    const HEARTBEAT_FILE: &str = "se-heartbeat";
    /// `ready-sleep` コマンドが起動を知らせるファイル名（`requester_killed` 用）。
    const REQUESTER_READY_FILE: &str = "se-requester-ready";
    /// 要求元の消滅から helper の終了までの合格の上限（`docs/design/cri-streaming-server.md` の目標値。通知処理のない通常ケース）。
    const REQUESTER_KILL_BUDGET: Duration = Duration::from_secs(2);
    /// pid1 とコマンドの寿命の上限（取り残し防止。REPAIR-5）。
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

    /// pid1 の役。`/data/ready` へ `READY` を書き、親が terminate するまで待つ（寿命の上限つき）。
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

    /// exec されるコマンドの役（helper が exec する。コンテナ内で動く）。
    pub fn se_cmd(mode: Option<&str>) {
        match mode {
            Some("echo") => {
                let (mut out, mut err) = (std::io::stdout(), std::io::stderr());
                let _ = out.write_all(b"se-stdout-line\n");
                let _ = out.flush();
                let _ = err.write_all(b"se-stderr-line\n");
                let _ = err.flush();
                std::process::exit(0);
            }
            Some("exit3") => std::process::exit(3),
            Some("cat") => {
                let mut data = Vec::new();
                if std::io::stdin().read_to_end(&mut data).is_err() {
                    std::process::exit(4);
                }
                let mut out = std::io::stdout();
                let _ = out.write_all(&data);
                let _ = out.flush();
                std::process::exit(0);
            }
            Some("beat") => {
                // 終わらないコマンド。止められるまで心拍を追記する（上限つき）。
                let path = format!("{DATA_DEST}/{HEARTBEAT_FILE}");
                let deadline = Instant::now() + PROBE_LIFETIME;
                while Instant::now() < deadline {
                    if let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)
                    {
                        let _ = f.write_all(b".");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                std::process::exit(8);
            }
            Some("ready-sleep") => {
                // 終わらないコマンド（要求元の消滅の照合用）。最初に 1 回だけ READY を書き、あとは静かに待つ。
                // 書き続けない理由: 目標の 2 秒は「消滅の時点で seccomp の通知を処理中でない」ことが条件のため。
                let path = format!("{DATA_DEST}/{REQUESTER_READY_FILE}");
                if std::fs::write(&path, READY_CONTENT).is_err() {
                    std::process::exit(9);
                }
                let deadline = Instant::now() + PROBE_LIFETIME;
                while Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                }
                std::process::exit(8);
            }
            _ => std::process::exit(2),
        }
    }

    // ----- 親側の準備 --------------------------------------------------------------------------------------

    /// 一時ディレクトリ（0700。`create_dir` で排他的に作り、drop で削除）。
    struct TempDir {
        dir: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let dir = super::scratch_root::scratch_root("fandhe-sereal-scratch", timeout())
                .join(format!("fandhe-sereal-{}-{nanos}", std::process::id()));
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

    /// 監査レコードを捨てるだけの sink（launcher の構築に要る）。
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

    fn status_field(path: &str, key: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    }

    /// 呼び出しプロセスが単一スレッドに戻るのを待つ（fork の前提）。
    fn wait_single_thread() {
        assert!(
            eventually(|| status_field("/proc/self/status", "Threads:").as_deref() == Some("1")),
            "the test process must be single-threaded before a launch"
        );
    }

    fn own_euid() -> u32 {
        status_field("/proc/self/status", "Uid:")
            .and_then(|v| v.split_whitespace().nth(1).map(str::to_string))
            .and_then(|v| v.parse().ok())
            .expect("parse euid")
    }

    fn config_text(ld: &str, bind_src: &Path) -> String {
        let src = bind_src.to_str().expect("utf8 bind source");
        format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"hostname":"fandhe-sereal",
"process":{{"user":{{"uid":0,"gid":0}},"args":["/probe","--container-probe"],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"mounts":[{{"destination":"{DATA_DEST}","type":"bind","source":"{src}","options":["bind","rw"]}}],
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#
        )
    }

    // ----- シナリオ ----------------------------------------------------------------------------------------

    pub fn run() -> ExitCode {
        // 前提の確認（副作用の前に fail-closed）。
        if own_euid() == 0 {
            println!("stream_exec_real: FAILED: must run as non-root (rootless test)");
            return ExitCode::from(1);
        }
        let _landlock = crate::precondition::landlock_support();
        let _scratch_cleanup = super::scratch_root::ScratchRootCleanup;
        // `DelegatedCgroup::prepare` は自プロセスを退避リーフへ移すため、起動は専用の委譲スコープ内の子プロセスで行う。
        const SCENARIO_DEADLINE: Duration = Duration::from_secs(240);
        let exe = std::env::current_exe().expect("current exe");
        let mut child = std::process::Command::new("systemd-run")
            .args(["--user", "--scope", "--quiet", "-p", "Delegate=yes", "--"])
            .arg(&exe)
            .arg("--scenario")
            .spawn()
            .expect("spawn systemd-run for the scenario");
        let deadline = Instant::now() + SCENARIO_DEADLINE;
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait scenario") {
                break status;
            }
            if Instant::now() >= deadline {
                crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
                panic!("the scenario exceeded {SCENARIO_DEADLINE:?}");
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        assert!(status.success(), "the scenario failed: {status}");
        println!(
            "stream_exec_real: real stream-exec helper ran commands in a rootless container and reported exit codes, separate stdio, stdin and the disconnect stop (root=false)"
        );
        ExitCode::SUCCESS
    }

    /// 子プロセス（`--scenario`）の入口。専用の委譲スコープ内で実行する。
    pub fn scenario_main() -> ExitCode {
        let _landlock = crate::precondition::landlock_support();
        let delegated = crate::precondition::delegated_cgroup();
        scenario(&delegated);
        ExitCode::SUCCESS
    }

    fn scenario(delegated: &fandhe_container_core::cgroups::DelegatedCgroup) {
        let privilege = IsolationPrivilege::RootlessSingleId;
        let work = TempDir::new();
        let state_root = work.dir.join("state");
        let store = Arc::new(
            FileStateStore::open(StateRoot::from_override(state_root.clone()).expect("state root"))
                .expect("open state store"),
        );
        let id = ContainerId::new(format!("sereal{}", std::process::id())).expect("container id");

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
        create(&*store, &recorder, &create_req).expect("create");

        // 本番と同じ cgroup の連鎖。配置が状態記録へ載らないと exec が拒否する。
        let observed = store
            .get(&GetStateRequest::new(id.clone()))
            .expect("get created state");
        let (container_cgroup, _first_join, _rec, _report) = delegated
            .record_scope(&*store, &observed)
            .and_then(|r| r.create_cgroup())
            .and_then(|p| p.apply_limits(&recorder, &CgroupLimitPlan::for_privilege(privilege)))
            .and_then(|l| l.into_join())
            .unwrap_or_else(|e| panic!("cgroup start chain failed: {e:?}"))
            .into_parts();
        let container_cgroup = Arc::new(container_cgroup);

        let launcher: Arc<dyn ProcessLauncher> = {
            let mut tmpfs = TmpfsMountSet::new();
            tmpfs.ensure_default_dev_shm().expect("default dev shm");
            let options = LaunchOptions::new(tmpfs, InjectedFileSet::new(), LaunchIpcMode::Private)
                .expect("launch options")
                .with_network(LaunchNetworkMode::Loopback);
            let cgroup = Arc::clone(&container_cgroup);
            Arc::new(
                ProductionLauncher::builder()
                    .privilege(privilege)
                    .audit_sink(Arc::new(MemSink(Mutex::new(Vec::new()))))
                    .cgroup_join_source(move || cgroup.join_hook())
                    .launch_options(options)
                    .build()
                    .expect("build launcher"),
            )
        };

        // 後始末は成否に関わらず行う（panic でも cgroup・一時領域を残さない）。
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify(&store, &recorder, &id, &launcher, &hostdata, &state_root);
        }));
        let removed = delegated.remove_child(&container_cgroup);
        if let Err(p) = result {
            std::panic::resume_unwind(p);
        }
        removed.expect("remove container cgroup");
        drop(work);
    }

    /// helper を 1 回起動した結果（plugin-cri 役が持つ端）。
    struct Spawned {
        child: Child,
        plugin: UnixStream,
        stdout: File,
        stderr: File,
        /// helper 自身の fd 2（診断行）。`HelperStderr::Piped` のときだけ取り込む。
        helper_stderr: Option<File>,
    }

    /// helper 自身の fd 2 の扱い。
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum HelperStderr {
        Inherit,
        Piped,
    }

    /// 1 回の exec の結果。
    struct Finished {
        started: bool,
        outcome: StreamExecOutcome,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    /// 起動に必要な固定の文脈。
    struct Ctx {
        exe: PathBuf,
        state_root: PathBuf,
        id: ContainerId,
        pid: std::num::NonZeroU32,
    }

    /// helper を起動し、stdio の fd を渡す（`stdin` が `Some` なら、そのバイト列を書いて閉じた pipe の読み端を渡す）。
    fn spawn_exec(
        ctx: &Ctx,
        mode: &str,
        stdin: Option<&[u8]>,
        timeout_ms: u64,
        helper_stderr: HelperStderr,
    ) -> Spawned {
        let (stdout_r, stdout_w) = std::io::pipe().expect("stdout pipe");
        let (stderr_r, stderr_w) = std::io::pipe().expect("stderr pipe");
        let stdin_r = stdin.map(|data| {
            let (r, mut w) = std::io::pipe().expect("stdin pipe");
            w.write_all(data).expect("write stdin payload");
            drop(w);
            OwnedFd::from(r)
        });
        let (stdout_w, stderr_w) = (OwnedFd::from(stdout_w), OwnedFd::from(stderr_w));
        let mask = StdioMask::from_presence(stdin_r.is_some(), true, true);
        let args = StreamExecArgs::new(
            ctx.state_root.clone(),
            ctx.id.clone(),
            ctx.pid,
            Duration::from_millis(timeout_ms),
            mask,
            vec!["/probe".into(), "--se-cmd".into(), mode.into()],
        )
        .expect("stream-exec args");
        let (plugin, helper_end) = UnixStream::pair().expect("socketpair");
        let mut command = stream_exec_command(&ctx.exe, &args);
        command
            .stdin(Stdio::from(OwnedFd::from(helper_end)))
            .stdout(Stdio::null())
            .stderr(match helper_stderr {
                HelperStderr::Inherit => Stdio::inherit(),
                HelperStderr::Piped => Stdio::piped(),
            });
        let mut child = command.spawn().expect("spawn the stream-exec helper");
        let helper_stderr = child.stderr.take().map(|e| File::from(OwnedFd::from(e)));
        send_stdio_handover(
            &plugin,
            &StdioSend {
                stdin: stdin_r.as_ref().map(AsFd::as_fd),
                stdout: Some(stdout_w.as_fd()),
                stderr: Some(stderr_w.as_fd()),
            },
            Instant::now() + timeout(),
        )
        .expect("send the stdio handover");
        // 送り側の複製は閉じる（コマンドが持つ書き込み端だけが残り、終了で EOF になる）。
        drop((stdout_w, stderr_w, stdin_r));
        Spawned {
            child,
            plugin,
            stdout: File::from(OwnedFd::from(stdout_r)),
            stderr: File::from(OwnedFd::from(stderr_r)),
            helper_stderr,
        }
    }

    /// `Result` まで受け、helper の終了（コード 0）と出力を回収する。
    fn finish(mut sp: Spawned) -> Finished {
        let mut started = false;
        let outcome = loop {
            match recv_from_helper(&sp.plugin, Instant::now() + timeout()) {
                Ok(HelperMessage::Started) => started = true,
                Ok(HelperMessage::Result(o)) => break o,
                Ok(HelperMessage::PtyMaster(_)) => panic!("unexpected PtyMaster without a tty"),
                Err(e) => panic!("channel failed before the result: {e:?}"),
            }
        };
        let status = wait_child(&mut sp.child);
        assert_eq!(status, Some(0), "the helper must exit with 0");
        // 子孫が書き込み端を持ち続けても無期限に EOF を待たない（REPAIR-5・#3760）。
        let deadline = Instant::now() + timeout();
        let stdout = read_to_end_bounded(sp.stdout.try_clone().expect("clone stdout"), deadline);
        let stderr = read_to_end_bounded(sp.stderr.try_clone().expect("clone stderr"), deadline);
        Finished {
            started,
            outcome,
            stdout,
            stderr,
        }
    }

    /// pipe の読み取りを別スレッドで行い、絶対期限までに EOF が来なければ panic する（REPAIR-5）。
    fn read_to_end_bounded(mut f: File, deadline: Instant) -> Vec<u8> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let r = f.read_to_end(&mut buf).map(|_| buf);
            let _ = tx.send(r);
        });
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Ok(buf)) => buf,
            Ok(Err(e)) => panic!("read pipe failed: {e}"),
            Err(_) => panic!("pipe did not reach EOF before the deadline"),
        }
    }

    fn wait_child(child: &mut Child) -> Option<i32> {
        let deadline = Instant::now() + timeout();
        loop {
            if let Some(status) = child.try_wait().expect("wait helper") {
                return status.code();
            }
            if Instant::now() >= deadline {
                crate::reap::reap_or_report(child, crate::reap::reap_within());
                panic!("the helper did not exit in time");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn verify(
        store: &Arc<FileStateStore>,
        recorder: &OpRecorder,
        id: &ContainerId,
        launcher: &Arc<dyn ProcessLauncher>,
        hostdata: &Path,
        state_root: &Path,
    ) {
        wait_single_thread();
        let started = start(
            &**store,
            recorder,
            launcher,
            &StartRequest::new(id.clone()),
            &timeouts(),
        )
        .unwrap_or_else(|e| panic!("start failed: {:?} {}", e.code(), e.message()));
        let pid = started.process().pid();
        assert_eq!(started.record().status().state(), ContainerState::Running);
        let (_record, process) = started.into_parts();

        // supervisor 役: 制御チャネルのサーバーとガードを、起動後（単一スレッドの launch の後）に立てる。
        let slot = SignalSlot::new();
        let controlled = ControlledProcess::new(process, slot.clone());
        let listener = ControlListener::bind(state_root, id).expect("bind the control socket");
        let observer = Arc::new(ControlObserver::new(None, None));
        let dyn_store: Arc<dyn StateStore> = store.clone();
        let reclaimer: Arc<dyn ExecCgroupReclaimer> =
            Arc::new(StoreExecReclaimer::new(dyn_store, id.clone()));
        let pool = ExecGuardPool::new(reclaimer, Arc::clone(&observer), ExecGuardLimits::default());
        let server = ControlServer::spawn_with_exec_guard(
            listener.try_clone_listener().expect("clone the listener"),
            slot,
            effective_uid().expect("euid"),
            ServeConfig::default(),
            observer,
            Some(pool),
        )
        .expect("spawn the control server");

        let ctx = Ctx {
            exe: std::env::current_exe().expect("current exe"),
            state_root: state_root.to_path_buf(),
            id: id.clone(),
            pid,
        };
        let verified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let ready = hostdata.join(READY_FILE);
            assert!(
                eventually(|| std::fs::read_to_string(&ready).is_ok_and(|s| s == READY_CONTENT)),
                "the container probe must report READY"
            );
            scenarios(&ctx, hostdata, server, listener);
        }));
        // helper を SIGKILL した disconnect の後、孤児化した exec worker とコマンドのゾンビは、この試験プロセス
        // （launch が立てた child subreaper）へ再親付けされる。回収しないと pid namespace の teardown が完了せず
        // pid1 の terminate が期限切れになるので、pid1 以外の子を先に回収する。
        reap_reparented_orphans(pid.get());
        let terminated = controlled.terminate(timeout());
        if let Err(p) = verified {
            if let Err(e) = &terminated {
                eprintln!(
                    "stream_exec_real: terminate after failed verification also failed: {e:?}"
                );
            }
            std::panic::resume_unwind(p);
        }
        terminated.expect("terminate");
        assert!(
            eventually(|| !Path::new(&format!("/proc/{}", pid.get())).exists()),
            "/proc/{} must disappear after terminate",
            pid.get()
        );
    }

    /// `/proc/<pid>/stat` の (状態, 開始時刻)。comm に `)` が入りうるため最後の `)` 以降を読む。外部入力なので失敗は `None`。
    fn proc_state_and_start(pid: u32) -> Option<(char, u64)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = stat.get(stat.rfind(')')? + 1..)?;
        let mut fields = rest.split_whitespace();
        let state = fields.next()?.chars().next()?;
        // rest の先頭は 3 番目のフィールド（state）。開始時刻は 22 番目なので state の後 19 個目。
        let start = fields.nth(18)?.parse::<u64>().ok()?;
        Some((state, start))
    }

    /// cmdline（NUL 区切り）が `argv` に完全一致し、ゾンビ・死亡でない生きたプロセスの (pid, 開始時刻)。
    fn live_pids_with_argv(argv: &[&str]) -> Vec<(u32, u64)> {
        let mut want = Vec::new();
        for a in argv {
            want.extend_from_slice(a.as_bytes());
            want.push(0);
        }
        let mut found = Vec::new();
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return found;
        };
        for e in dir.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            if cmdline != want {
                continue;
            }
            if let Some((state, start)) = proc_state_and_start(pid)
                && state != 'Z'
                && state != 'X'
            {
                found.push((pid, start));
            }
        }
        found
    }

    /// 記録した (pid, 開始時刻) のプロセスが消えている（stat が無い・ゾンビ・死亡・開始時刻が違う＝pid の再利用）か。
    fn is_gone(pid: u32, starttime: u64) -> bool {
        match proc_state_and_start(pid) {
            None => true,
            Some((state, start)) => state == 'Z' || state == 'X' || start != starttime,
        }
    }

    /// 試験プロセス（child subreaper）へ再親付けされた pid1 以外の子（孤児化した exec worker・コマンド）を回収する。
    ///
    /// 本番では helper の孤児は plugin-cri 側（subreaper ではない）の外で init が回収するが、本試験は plugin-cri 役と
    /// supervisor 役を兼ねるため自分で回収する。pid 指定の `waitpid(WNOHANG)` だけを使い（core の `ContainerChild`）、
    /// 期限内に終わらない子は SIGKILL して回収する（REPAIR-5）。
    fn reap_reparented_orphans(pid1: u32) {
        let Ok(proof) = ChildSubreaper::enable() else {
            return;
        };
        let mut pids = Vec::new();
        if let Ok(tasks) = std::fs::read_dir("/proc/self/task") {
            for t in tasks.flatten() {
                if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
                    pids.extend(s.split_whitespace().filter_map(|v| v.parse::<u32>().ok()));
                }
            }
        }
        for pid in pids.into_iter().filter(|p| *p != pid1) {
            if let Some(nz) = std::num::NonZeroU32::new(pid) {
                let _ = ContainerChild::adopt_reparented(nz, &proof)
                    .wait_timeout(Duration::from_secs(5));
            }
        }
    }

    /// requester_killed: 要求元（channel の端を持つ偽のプロセス）を SIGKILL すると、helper が 2 秒以内に終わり
    /// コマンドも残らない（SUP-6・SEC-1・REPAIR-5・#4167）。exec の期限は 120 秒で、期限・`hold_grace` による終了とは区別される。
    fn requester_killed(ctx: &Ctx, hostdata: &Path) {
        const HELPER_TIMEOUT_MS: u64 = 120_000;
        let sp = spawn_exec(
            ctx,
            "ready-sleep",
            None,
            HELPER_TIMEOUT_MS,
            HelperStderr::Piped,
        );
        let first = recv_from_helper(&sp.plugin, Instant::now() + timeout()).expect("started");
        assert!(matches!(first, HelperMessage::Started), "{first:?}");
        let ready = hostdata.join(REQUESTER_READY_FILE);
        assert!(
            eventually(|| std::fs::read_to_string(&ready).is_ok_and(|s| s == READY_CONTENT)),
            "the ready-sleep command must have started"
        );
        // 偽の要求元は channel の端の複製を stdin に持つ。試験側の端を drop した後は、これが最後の端になる。
        // 試験側に端が 1 本でも残ると POLLHUP が立たず、期限（120 秒）の経路に落ちて検知を照合できない。
        let mut requester = {
            let held = sp.plugin.try_clone().expect("clone the channel end");
            let mut c = std::process::Command::new("/bin/sleep");
            c.arg("120")
                .stdin(Stdio::from(OwnedFd::from(held)))
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            c.spawn().expect("spawn the fake requester")
        };
        let Spawned {
            mut child,
            plugin,
            helper_stderr,
            ..
        } = sp;
        drop(plugin);
        // 誤検知しないこと: 要求元が生きている間は helper もコマンドも動き続ける。
        std::thread::sleep(Duration::from_millis(1000));
        assert!(
            child.try_wait().expect("poll helper").is_none(),
            "the helper must keep running while the requester is alive"
        );
        let argv = ["/probe", "--se-cmd", "ready-sleep"];
        let cmds = live_pids_with_argv(&argv);
        assert_eq!(
            cmds.len(),
            1,
            "exactly one live ready-sleep command: {cmds:?}"
        );
        let (cmd_pid, cmd_start) = cmds[0];

        let t0 = Instant::now();
        requester.kill().expect("kill the requester");
        let (elapsed, status) = loop {
            if let Some(status) = child.try_wait().expect("poll helper") {
                break (t0.elapsed(), status);
            }
            if t0.elapsed() >= Duration::from_secs(15) {
                crate::reap::reap_or_report(&mut child, crate::reap::reap_within());
                crate::reap::reap_or_report(&mut requester, crate::reap::reap_within());
                panic!("the helper did not exit within 15s after the requester was killed");
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        crate::reap::reap_or_report(&mut requester, crate::reap::reap_within());
        assert!(
            elapsed <= REQUESTER_KILL_BUDGET,
            "the helper took {elapsed:?} to exit after the requester was killed (budget {REQUESTER_KILL_BUDGET:?})"
        );
        assert_eq!(
            status.code(),
            Some(1),
            "the helper exits 1 when the requester is gone"
        );
        // 診断行（期限切れの経路と区別する）。
        let diag = read_to_end_bounded(
            helper_stderr.expect("helper stderr was piped"),
            Instant::now() + timeout(),
        );
        let diag = String::from_utf8_lossy(&diag);
        assert!(
            diag.contains(
                r#"{"code":"unavailable","message":"stream-exec requester went away; exec cancelled"}"#
            ),
            "the cancel diagnostic line is missing: {diag}"
        );
        // helper は cgroup の回収を終えてから終わるため、終了の直後に 1 回だけ厳密に確かめる。
        assert!(
            is_gone(cmd_pid, cmd_start),
            "the exec command (pid {cmd_pid}) must be gone once the helper has exited"
        );
        assert_eq!(
            live_pids_with_argv(&argv),
            Vec::<(u32, u64)>::new(),
            "no ready-sleep command may remain"
        );
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        println!(
            "stream_exec_real: info requester_kill_elapsed_ms={} budget_ms={} helper_timeout_ms={HELPER_TIMEOUT_MS} kernel={kernel}",
            elapsed.as_millis(),
            REQUESTER_KILL_BUDGET.as_millis()
        );
        println!(
            "stream_exec_real: scenario=requester_killed helper exited within 2s after the requester was killed and no exec process remained"
        );
    }

    fn scenarios(ctx: &Ctx, hostdata: &Path, server: ControlServer, listener: ControlListener) {
        // echo: stdout と stderr が別々の fd で返る。
        let sp = spawn_exec(ctx, "echo", None, 20_000, HelperStderr::Inherit);
        let f = finish(sp);
        assert!(f.started, "Started must precede the result");
        assert_eq!(f.outcome, StreamExecOutcome::Exited(0));
        assert_eq!(f.stdout, b"se-stdout-line\n".to_vec());
        assert_eq!(f.stderr, b"se-stderr-line\n".to_vec());
        println!("stream_exec_real: scenario=echo exit 0 with separate stdout and stderr");

        // exit3: 終了コード 3。
        let f = finish(spawn_exec(
            ctx,
            "exit3",
            None,
            20_000,
            HelperStderr::Inherit,
        ));
        assert!(f.started);
        assert_eq!(f.outcome, StreamExecOutcome::Exited(3));
        assert_eq!(f.stdout, Vec::<u8>::new());
        println!("stream_exec_real: scenario=exit3 exit code 3");

        // stdin: 渡したバイト列がコマンドの stdout に戻る。
        let f = finish(spawn_exec(
            ctx,
            "cat",
            Some(b"se-stdin-payload\n"),
            20_000,
            HelperStderr::Inherit,
        ));
        assert_eq!(f.outcome, StreamExecOutcome::Exited(0));
        assert_eq!(f.stdout, b"se-stdin-payload\n".to_vec());
        println!("stream_exec_real: scenario=stdin payload echoed back");

        // disconnect: Started の後に helper を SIGKILL すると、ガードが exec 子 cgroup を回収してコマンドが止まる。
        let mut sp = spawn_exec(ctx, "beat", None, 60_000, HelperStderr::Inherit);
        let first = recv_from_helper(&sp.plugin, Instant::now() + timeout()).expect("started");
        assert!(matches!(first, HelperMessage::Started), "{first:?}");
        let beat = hostdata.join(HEARTBEAT_FILE);
        assert!(
            eventually(|| std::fs::metadata(&beat).is_ok_and(|m| m.len() > 0)),
            "the beat command must have started"
        );
        sp.child.kill().expect("kill the helper");
        crate::reap::reap_or_report(&mut sp.child, crate::reap::reap_within());
        let err = recv_from_helper(&sp.plugin, Instant::now() + timeout()).unwrap_err();
        assert_eq!(err, ChannelError::Closed, "no result after the helper died");
        let stopped = eventually(|| {
            let a = std::fs::metadata(&beat).map_or(0, |m| m.len());
            std::thread::sleep(Duration::from_millis(400));
            let b = std::fs::metadata(&beat).map_or(0, |m| m.len());
            a == b
        });
        assert!(
            stopped,
            "the guard must stop the command after the helper died"
        );
        println!(
            "stream_exec_real: scenario=disconnect command stopped after the helper was killed"
        );

        requester_killed(ctx, hostdata);

        // orphan: supervisor が居ない（制御サーバーも listener も無い）なら pidfd を受けられず、縮退せず失敗する。
        drop(server);
        drop(listener);
        let f = finish(spawn_exec(ctx, "echo", None, 20_000, HelperStderr::Inherit));
        assert!(
            !f.started,
            "the command must not start without a supervisor"
        );
        assert_eq!(f.outcome, StreamExecOutcome::Failed(ErrorCode::Unavailable));
        println!("stream_exec_real: scenario=orphan no pidfd without a supervisor, failed closed");
    }
}
