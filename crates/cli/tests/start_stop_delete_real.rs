//! CLI の実バイナリだけで、本番の rootless の `start` から `stop`・`delete` までを通す実機前提の通し試験
//! （#2450・CORE-4・CORE-3・OCI-6・SUP-1・SUP-4・CLI-1・REPAIR-5・REPAIR-12。TASK-157 追補・TASK-79 追補。
//! 関連: #2062・#1621・`docs/verification/rootless-start-cgroup.md` のシナリオ 2）。
//!
//! `create` → `start`（CLI が `systemd-run --user --scope -p Delegate=yes` で supervisor を新 scope に包み、
//! supervisor が core の本番 launcher を in-process で呼ぶ）→ `list` → `logs` → `stop`（制御チャネル経由の SIGTERM）→
//! `list`（Stopped）→ `delete` → 2 回目の `delete` を、各段の終了コード・stdout・stderr・状態記録の具体値で照合し、
//! 最後に cgroup・状態ディレクトリ・`supervisor.sock`・ログ・プロセスの残骸が無いことを確かめる。
//!
//! # 既存の試験との分担（重複させない）
//! - `crates/supervisor/tests/supervisor_bin_real.rs`: supervisor の bin を直接起動し、stop は `ControlSignaler` を直接、
//!   delete は補助役が core を直接呼ぶ。seccomp 通知・ID 写像・NSpid・restart の fail-closed・起動失敗の後始末はそちらが担う。
//!   本試験はそれらを照合しない
//! - `start_scope_real.rs`（CLI が supervisor を新 scope で一人にすること）・`delete_cgroup_real.rs`（delete の cgroup 削除。
//!   状態は試験側で合成）・`start_recover_real.rs`（中断された予約の回復）とも範囲が異なる
//!
//! 同じ実行ファイルが 2 役を持つ。親（既定）は `--ignored` のときだけ実機シナリオを動かす。コンテナ内のプローブ
//! （`--container-probe`）は SIGTERM のハンドラ（`_exit(43)`）を登録して `READY_TERM` を出し、最大 60 秒待つ。
//! PID 1 は `SIG_DFL` のシグナルを受けないため、ハンドラ無しでは SIGTERM が捨てられ寿命切れを停止と取り違える（REPAIR-3）。
//!
//! # 必要環境
//! Linux 6.12 以上（Landlock ABI 6 以上）・cgroup v2・非 root・非特権 user namespace・`systemd-run --user`（user マネージャ）。
//! 試験全体を `systemd-run --user --scope -p Delegate=yes` で包んで実行する（CLI の `delete` は自分の cgroup から委譲を検出する）。
//! 事前に `cargo build -p fandhe-container-supervisor` を行う。CLI と supervisor は作業ディレクトリへ 0755 でコピーして使い、
//! 特権ランチャーは置かない（置くと CLI が rootful のインストールとみなす）。前提が欠けたら skip ではなく失敗する。
//!
//! # 実機前提テストとしての分離
//! `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。未指定は案内を出して成功する。
//!
//! ```text
//! cargo build -p fandhe-container-supervisor
//! cargo test -p fandhe-container-cli --test start_stop_delete_real --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/start_stop_delete_real-XXXX> --ignored
//! ```
//!
//! 成功時の最終行: `start_stop_delete_real: cli start ran the container under the production launcher; stop recorded Stopped(43); delete left no cgroup, state dir, control socket or logs`。
//! 使い捨ての CI runner（`platform-ci` の ubuntu）では #2596 で実行し、成功行を照合する。手元の実機での実行と結果の記録は人間担当（#2062・#1621）で、Agent はホストに transient scope と cgroup を作るため手元では実行しない。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("start_stop_delete_real: skipped (linux only)");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("start_stop_delete_real: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() -> std::process::ExitCode {
    if std::env::args().any(|a| a == "--container-probe") {
        linux::probe();
    }
    linux::main()
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod linux {
    use std::fs;
    use std::io::{Read, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::{CgroupName, DelegatedCgroup};
    use fandhe_container_core::exec::SIGTERM_HANDLER_EXIT_CODE_FOR_TEST;
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, GetStateRequest, StateRecord, StateStore,
    };

    /// `start` を待つ上限（CLI 自身の受信期限より長く取る。REPAIR-5）。
    const START_TIMEOUT: Duration = Duration::from_secs(90);
    /// `start` 以外の CLI を待つ上限（REPAIR-5）。
    const CLI_TIMEOUT: Duration = Duration::from_secs(30);
    /// kill 後の回収・出力収集の上限（REPAIR-5）。
    const REAP_TIMEOUT: Duration = Duration::from_secs(10);
    /// 状態・ハンドラ登録の待ちの上限（REPAIR-5）。
    const STATE_TIMEOUT: Duration = Duration::from_secs(30);
    const POLL: Duration = Duration::from_millis(20);
    /// プローブの寿命の上限。これを過ぎたら終了コード 8 で終わる（寿命切れを停止と取り違えないための目印）。
    const PROBE_LIFETIME: Duration = Duration::from_secs(60);
    /// `/proc/<pid>/status` の `SigCgt` で SIGTERM（15）に当たるビット（1 << 14）。
    const SIGTERM_CAUGHT_BIT: u64 = 1 << 14;

    /// コンテナ内で動くプローブ。SIGTERM のハンドラ（`_exit(43)` のみ）を登録してから `READY_TERM` を出して待つ。
    pub fn probe() -> ! {
        let mut out = std::io::stdout();
        if let Err(e) = fandhe_container_core::exec::exit_on_sigterm_for_test() {
            let _ = writeln!(out, "TERM_HANDLER_FAILED {e}");
            let _ = out.flush();
            std::process::exit(9);
        }
        let _ = writeln!(out, "READY_TERM");
        let _ = out.flush();
        let deadline = Instant::now() + PROBE_LIFETIME;
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
        }
        std::process::exit(8);
    }

    pub fn main() -> ExitCode {
        if !std::env::args().skip(1).any(|a| a == "--ignored") {
            println!(
                "start_stop_delete_real: skipped (real-host scenario; run with `-- --ignored` inside a delegated cgroup, e.g. `systemd-run --user --scope -p Delegate=yes`)"
            );
            return ExitCode::SUCCESS;
        }
        match scenario() {
            Ok(scope_present) => {
                println!(
                    "start_stop_delete_real: scenario ok scope_present_before_delete={scope_present}"
                );
                println!(
                    "start_stop_delete_real: cli start ran the container under the production launcher; stop recorded Stopped(43); delete left no cgroup, state dir, control socket or logs"
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("start_stop_delete_real: FAILED: {e}");
                ExitCode::FAILURE
            }
        }
    }

    fn expect(cond: bool, what: &str) -> Result<(), String> {
        if cond { Ok(()) } else { Err(what.to_string()) }
    }

    /// 子を kill し、`REAP_TIMEOUT` 内に `try_wait` で回収する（無期限の `wait` を避ける。REPAIR-5）。
    fn kill_and_reap(c: &mut Child) -> Result<(), String> {
        let kill_err = c.kill().err();
        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            match c.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() >= deadline => {
                    return Err(format!(
                        "child was not reaped within {REAP_TIMEOUT:?} (kill: {kill_err:?})"
                    ));
                }
                Ok(None) => thread::sleep(POLL),
                Err(e) => return Err(format!("reap child: {e}")),
            }
        }
    }

    /// 失敗時の後始末。CLI の `stop`・`delete` を期限つきで呼び、作業ディレクトリを消す。
    /// `state.json` の pid へ生の kill は送らない（PID 再利用で無関係なプロセスを止めない。SEC-1）。
    /// プローブは寿命 60 秒で自ら終わり、supervisor も続いて終わる。
    struct Cleanup {
        cli: PathBuf,
        work: PathBuf,
        root: String,
        id: String,
        armed: bool,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            if self.armed {
                if let Err(e) = run_cli(
                    &self.cli,
                    &["--root", &self.root, "stop", &self.id],
                    CLI_TIMEOUT,
                ) {
                    eprintln!("start_stop_delete_real: cleanup stop failed: {e}");
                }
                // stop は送達で戻り Stopped を待たないため、delete は成功（終了コード 0）まで期限内で再試行する。
                // 回収できなければ状態ルートを残して診断先を示す（回収に必要な記録を失わない）。
                let mut last = String::from("not attempted");
                let ok = wait_until(
                    STATE_TIMEOUT,
                    "cleanup delete to succeed",
                    || match run_cli(
                        &self.cli,
                        &["--root", &self.root, "delete", &self.id],
                        CLI_TIMEOUT,
                    ) {
                        Ok(o) if o.code == Some(0) => true,
                        Ok(o) => {
                            last = format!("exit {:?} stderr={:?}", o.code, o.stderr);
                            false
                        }
                        Err(e) => {
                            last = e;
                            false
                        }
                    },
                );
                if let Err(e) = ok {
                    eprintln!(
                        "start_stop_delete_real: cleanup delete failed ({e}; last: {last}); leaving {} for diagnosis",
                        self.work.display()
                    );
                    return;
                }
            }
            if let Err(e) = fs::remove_dir_all(&self.work) {
                eprintln!("start_stop_delete_real: cleanup remove work dir failed: {e}");
            }
        }
    }

    /// 前提の検査。欠けたら skip せず失敗にする。
    fn check_prerequisites() -> Result<(), String> {
        if effective_uid()? == 0 {
            return Err("must run as a non-root user: owner checks are skipped for root".into());
        }
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            return Err(
                "cgroup v2 is required (/sys/fs/cgroup/cgroup.controllers is missing)".into(),
            );
        }
        let hint = "run this test inside `systemd-run --user --scope -p Delegate=yes`";
        let delegated = DelegatedCgroup::detect()
            .map_err(|e| format!("no delegated cgroup ({e:?}); {hint}"))?;
        let own = fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| format!("read /proc/self/cgroup: {e}"))?;
        let own_path = own
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .ok_or("no cgroup v2 line in /proc/self/cgroup")?;
        if own_path.trim_end_matches('/') != delegated.path().trim_end_matches('/') {
            return Err(format!("detected cgroup differs from own cgroup; {hint}"));
        }
        let runtime = std::env::var_os("XDG_RUNTIME_DIR").ok_or("XDG_RUNTIME_DIR is not set")?;
        let private = Path::new(&runtime).join("systemd/private");
        let is_socket = fs::symlink_metadata(&private)
            .map(|m| std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()))
            .unwrap_or(false);
        expect(is_socket, "the systemd user manager socket is missing")?;
        fandhe_container_core::landlock::detect_landlock_abi()
            .map_err(|e| format!("Landlock ABI 6 or newer is required: {e:?}"))?;
        Ok(())
    }

    /// 戻り値は削除前に記録のスコープのディレクトリが存在したか。
    fn scenario() -> Result<bool, String> {
        check_prerequisites()?;
        let cli_src = PathBuf::from(env!("CARGO_BIN_EXE_fandhe-container"));
        let sup_src = cli_src
            .parent()
            .map(|d| d.join("fandhe-container-supervisor"))
            .ok_or("cli has no parent directory")?;
        if !sup_src.is_file() {
            return Err(format!(
                "{} is missing; run `cargo build -p fandhe-container-supervisor` first",
                sup_src.display()
            ));
        }

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let work = fs::canonicalize(std::env::temp_dir())
            .map_err(|e| format!("canonicalize temp_dir: {e}"))?
            .join(format!("fandhe-ssd-real-{}-{nanos}", std::process::id()));
        fs::create_dir(&work).map_err(|e| format!("create work dir: {e}"))?;
        set_mode(&work, 0o700)?;
        let id_s = format!("ssd{}", std::process::id());
        let root = work.join("state");
        let root_s = root.to_str().ok_or("work dir is not UTF-8")?.to_string();
        let mut cleanup = Cleanup {
            cli: PathBuf::new(),
            work: work.clone(),
            root: root_s.clone(),
            id: id_s.clone(),
            armed: false,
        };

        // CLI と supervisor を 0755 でコピーする。特権ランチャーは置かない（置くと rootful 経路に入る）。
        let bin = work.join("bin");
        fs::create_dir(&bin).map_err(|e| format!("mkdir bin: {e}"))?;
        set_mode(&bin, 0o755)?;
        let cli = bin.join("fandhe-container");
        fs::copy(&cli_src, &cli).map_err(|e| format!("copy cli: {e}"))?;
        set_mode(&cli, 0o755)?;
        let supervisor = bin.join("fandhe-container-supervisor");
        fs::copy(&sup_src, &supervisor).map_err(|e| format!("copy supervisor: {e}"))?;
        set_mode(&supervisor, 0o755)?;
        expect(
            !bin.join("fandhe-container-launcher").exists(),
            "a privileged launcher must not sit next to the cli",
        )?;
        cleanup.cli = cli.clone();

        fs::create_dir(&root).map_err(|e| format!("mkdir state root: {e}"))?;
        set_mode(&root, 0o700)?;
        let bundle = work.join("bundle");
        make_bundle(&bundle)?;
        let bundle_s = bundle.to_str().ok_or("bundle path is not UTF-8")?;

        let id = ContainerId::new(id_s.clone()).map_err(|e| format!("id: {e:?}"))?;

        // 1. create
        let out = run_cli(
            &cli,
            &["--root", &root_s, "create", "--bundle", bundle_s, &id_s],
            CLI_TIMEOUT,
        )?;
        expect_ok(&out, "create")?;
        cleanup.armed = true;

        // 2. start
        let out = run_cli(&cli, &["--root", &root_s, "start", &id_s], START_TIMEOUT)?;
        expect_ok(&out, "start")?;

        // 3. list（Running）と状態記録・cgroup 配置
        let out = run_cli(&cli, &["--root", &root_s, "list"], CLI_TIMEOUT)?;
        let pid = parse_running_list(&out, &id_s)?;
        let store = open_store(&root)?;
        let rec = get_record(&store, &id)?;
        expect(
            rec.status().state() == ContainerState::Running,
            "state record is not Running after start",
        )?;
        expect(
            rec.status().pid().map(|p| p.get()) == Some(pid),
            "state record pid differs from list pid",
        )?;
        let placement = rec.cgroup().ok_or("record has no cgroup placement")?;
        let scope = placement.scope().as_str().to_string();
        let name = CgroupName::for_instance(&id, placement.instance())
            .map_err(|e| format!("cgroup name: {e:?}"))?;
        let scope_dir = PathBuf::from("/sys/fs/cgroup").join(scope.trim_start_matches('/'));
        let container_cgroup = scope_dir.join(name.as_str());
        let expected_line = format!("{}/{}", scope.trim_end_matches('/'), name.as_str());
        let proc_cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .map_err(|e| format!("read /proc/{pid}/cgroup: {e}"))?;
        let got = proc_cgroup
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .unwrap_or("");
        if got != expected_line {
            return Err(format!(
                "container process cgroup: want {expected_line:?}, got {got:?}"
            ));
        }

        // 4. SIGTERM のハンドラ登録を待つ（登録前に stop すると PID 1 では捨てられる）
        wait_until(STATE_TIMEOUT, "SIGTERM handler registration", || {
            fs::read_to_string(format!("/proc/{pid}/status"))
                .ok()
                .and_then(|t| {
                    t.lines()
                        .find_map(|l| l.strip_prefix("SigCgt:"))
                        .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
                })
                .is_some_and(|m| m & SIGTERM_CAUGHT_BIT != 0)
        })?;

        // 5. logs
        // ハンドラ登録後でも supervisor の非同期ログ捕捉・flush は未完のことがあるため、期限内で再取得する（REPAIR-5）。
        let mut last_logs = String::new();
        let logs_ok =
            wait_until(
                STATE_TIMEOUT,
                "logs to contain `stdout READY_TERM`",
                || match run_cli(&cli, &["--root", &root_s, "logs", &id_s], CLI_TIMEOUT) {
                    Ok(o) if o.code == Some(0) => {
                        let found = o.stdout.lines().any(|l| l == "stdout READY_TERM");
                        last_logs = o.stdout;
                        found
                    }
                    Ok(o) => {
                        last_logs = format!("exit {:?} stderr={:?}", o.code, o.stderr);
                        false
                    }
                    Err(e) => {
                        last_logs = e;
                        false
                    }
                },
            );
        logs_ok.map_err(|e| format!("{e}; last logs: {last_logs:?}"))?;
        let container_log = root.join("@container-logs").join(format!("{id_s}.log"));
        let supervisor_log = root.join("@supervisor-logs").join(format!("{id_s}.log"));
        expect(
            container_log.is_file(),
            "container log file is missing before delete",
        )?;
        expect(
            supervisor_log.is_file(),
            "supervisor log file is missing before delete",
        )?;
        let control_socket = root.join(&id_s).join("supervisor.sock");

        // 6. stop（SIGTERM の送達で返る。Stopped は待たない）
        let out = run_cli(&cli, &["--root", &root_s, "stop", &id_s], CLI_TIMEOUT)?;
        expect_ok(&out, "stop")?;

        // 7. list（Stopped）と終了コード 43
        let want = format!("ID\tSTATUS\tPID\n{id_s}\tstopped\t-\n");
        wait_until(STATE_TIMEOUT, "list to report stopped", || {
            run_cli(&cli, &["--root", &root_s, "list"], CLI_TIMEOUT)
                .is_ok_and(|o| o.code == Some(0) && o.stdout == want)
        })?;
        let rec = get_record(&store, &id)?;
        if rec.status().exit_code() != Some(SIGTERM_HANDLER_EXIT_CODE_FOR_TEST) {
            return Err(format!(
                "exit code after stop: want {SIGTERM_HANDLER_EXIT_CODE_FOR_TEST}, got {:?}",
                rec.status().exit_code()
            ));
        }
        drop(store);

        // 8. プロセスの消滅とソケット
        wait_until(REAP_TIMEOUT, "the container process to vanish", || {
            !Path::new(&format!("/proc/{pid}")).exists()
        })?;
        // 今回の起動に属するプローブだけを見る（cgroup 一致。並行する別試験のプローブを巻き込まない）。
        let want_cgroup = format!("0::{expected_line}");
        wait_until(REAP_TIMEOUT, "probe processes to vanish", || {
            count_processes(|dir| {
                fs::read_to_string(dir.join("cgroup"))
                    .is_ok_and(|t| t.lines().any(|l| l == want_cgroup))
                    && fs::read(dir.join("cmdline"))
                        .is_ok_and(|c| c.windows(17).any(|w| w == b"--container-probe"))
            }) == 0
        })?;
        let sup_needle = supervisor.to_string_lossy().into_owned().into_bytes();
        let root_needle = root_s.clone().into_bytes();
        wait_until(REAP_TIMEOUT, "the supervisor to exit", || {
            count_processes(|dir| {
                fs::read(dir.join("cmdline")).is_ok_and(|c| {
                    c.starts_with(&sup_needle)
                        && c.windows(root_needle.len()).any(|w| w == root_needle)
                })
            }) == 0
        })?;
        expect(
            !control_socket.exists(),
            "supervisor.sock remains after the supervisor exited",
        )?;

        // 9. 削除前のスコープの有無（どちらの経路も正しいので固定しない）
        let scope_present = scope_dir.is_dir();

        // 10. delete
        let out = run_cli(&cli, &["--root", &root_s, "delete", &id_s], CLI_TIMEOUT)?;
        expect_ok(&out, "delete")?;

        // 11. 残骸の照合
        expect(!root.join(&id_s).exists(), "state dir remains after delete")?;
        expect(
            !container_cgroup.exists(),
            "container cgroup remains after delete",
        )?;
        if scope_dir.is_dir() {
            let prefix = format!("fc-{id_s}@");
            let leftovers = list_prefixed(&scope_dir, &prefix)?;
            expect(
                leftovers.is_empty(),
                &format!("container cgroups remain under the scope: {leftovers:?}"),
            )?;
            // 不存在（NotFound）だけを空として扱い、権限エラー等の観測失敗は伝播する
            let procs = match fs::read_to_string(scope_dir.join("cgroup.procs")) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(format!("read scope cgroup.procs: {e}")),
            };
            expect(
                procs.trim().is_empty(),
                &format!("scope cgroup.procs is not empty: {procs:?}"),
            )?;
        }
        let log_prefix = format!("{id_s}.log");
        for dir in ["@supervisor-logs", "@container-logs"] {
            let names = list_prefixed(&root.join(dir), &log_prefix)?;
            expect(
                names.is_empty(),
                &format!("{dir} entries remain: {names:?}"),
            )?;
        }
        let out = run_cli(&cli, &["--root", &root_s, "list"], CLI_TIMEOUT)?;
        expect(
            out.code == Some(0) && out.stdout == "ID\tSTATUS\tPID\n",
            &format!("list after delete: {:?} {:?}", out.code, out.stdout),
        )?;

        // 12. 2 回目の delete
        let out = run_cli(&cli, &["--root", &root_s, "delete", &id_s], CLI_TIMEOUT)?;
        if out.code != Some(3) || !out.stdout.is_empty() {
            return Err(format!(
                "second delete: want exit 3, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        let (op, code) = op_and_code(&out.stderr)?;
        if op != "delete" || code != "NOT_FOUND" {
            return Err(format!(
                "second delete: want op=delete code=NOT_FOUND, got op={op} code={code}"
            ));
        }
        cleanup.armed = false;
        Ok(scope_present)
    }

    /// `dir` 直下で `prefix` 始まりの名前を返す。ディレクトリ不存在（NotFound）だけを空とし、
    /// それ以外の読み取り失敗（PermissionDenied 等）とエントリ単位の失敗はエラーにする。
    fn list_prefixed(dir: &Path, prefix: &str) -> Result<Vec<String>, String> {
        let rd = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("read dir {}: {e}", dir.display())),
        };
        let mut names = Vec::new();
        for entry in rd {
            let entry = entry.map_err(|e| format!("read dir entry {}: {e}", dir.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(prefix) {
                names.push(name);
            }
        }
        Ok(names)
    }

    fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {}: {e}", path.display()))
    }

    fn wait_until(limit: Duration, what: &str, mut f: impl FnMut() -> bool) -> Result<(), String> {
        let deadline = Instant::now() + limit;
        loop {
            if f() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out after {limit:?} waiting for {what}"));
            }
            thread::sleep(POLL);
        }
    }

    fn open_store(root: &Path) -> Result<FileStateStore, String> {
        let root =
            StateRoot::from_override(root.to_path_buf()).map_err(|e| format!("root: {e:?}"))?;
        FileStateStore::open(root).map_err(|e| format!("open store: {e:?}"))
    }

    fn get_record(store: &FileStateStore, id: &ContainerId) -> Result<StateRecord, String> {
        store
            .get(&GetStateRequest::new(id.clone()))
            .map_err(|e| format!("get: {e:?}"))
    }

    /// `/proc` の全プロセスのうち、`/proc/<pid>` のディレクトリが条件に合うものの数。
    fn count_processes(pred: impl Fn(&Path) -> bool) -> usize {
        let Ok(dir) = fs::read_dir("/proc") else {
            return 0;
        };
        dir.flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
                    && pred(&e.path())
            })
            .count()
    }

    /// `list` の stdout が `ID\tSTATUS\tPID\n<id>\trunning\t<pid>\n` と完全一致することを確かめ、pid を返す。
    fn parse_running_list(out: &RunOut, id: &str) -> Result<u32, String> {
        expect_ok_code(out, "list")?;
        let body = out
            .stdout
            .strip_prefix("ID\tSTATUS\tPID\n")
            .ok_or_else(|| format!("list header: {:?}", out.stdout))?;
        let row = body
            .strip_prefix(&format!("{id}\trunning\t"))
            .and_then(|r| r.strip_suffix('\n'))
            .ok_or_else(|| format!("list row: {:?}", out.stdout))?;
        let pid: u32 = row.parse().map_err(|_| format!("list pid: {row:?}"))?;
        expect(pid > 0, "list pid must be positive")?;
        Ok(pid)
    }

    fn expect_ok_code(out: &RunOut, what: &str) -> Result<(), String> {
        if out.code != Some(0) {
            return Err(format!(
                "{what}: want exit 0, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        Ok(())
    }

    /// 終了コード 0・stdout と stderr が空。
    fn expect_ok(out: &RunOut, what: &str) -> Result<(), String> {
        if out.code != Some(0) || !out.stdout.is_empty() || !out.stderr.is_empty() {
            return Err(format!(
                "{what}: want exit 0 with empty output, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        Ok(())
    }

    fn op_and_code(stderr: &str) -> Result<(String, String), String> {
        if !stderr.ends_with('\n') || stderr.matches('\n').count() != 1 {
            return Err(format!("stderr is not exactly one line: {stderr:?}"));
        }
        let field = |key: &str| -> Result<String, String> {
            let pat = format!("\"{key}\":\"");
            let start = stderr
                .find(&pat)
                .ok_or_else(|| format!("no {key} in {stderr:?}"))?
                + pat.len();
            let rest = stderr.get(start..).ok_or("bad offset")?;
            let len = rest
                .find('"')
                .ok_or_else(|| format!("unterminated {key} in {stderr:?}"))?;
            Ok(rest.get(..len).ok_or("bad slice")?.to_string())
        };
        Ok((field("op")?, field("code")?))
    }

    /// 実効 UID を `/proc/self/status` から読む（`unsafe` の syscall を使わないため）。
    fn effective_uid() -> Result<u32, String> {
        let text = fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
        text.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| "no effective uid in /proc/self/status".to_string())
    }

    struct RunOut {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    }

    fn spawn_reader<R: Read + Send + 'static>(mut pipe: R) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
        rx
    }

    /// 実バイナリを有限期限内で実行する（REPAIR-5）。試験用の差し替え口は子の環境から外し、本番の解決経路を通す。
    fn run_cli(cli: &Path, args: &[&str], limit: Duration) -> Result<RunOut, String> {
        let mut child = Command::new(cli)
            .args(args)
            .env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
            .env_remove("FANDHE_CONTAINER_OP_LOG")
            .env_remove("FANDHE_CONTAINER_TEST_SYSTEMD_RUN")
            .env_remove("FANDHE_CONTAINER_TEST_LOGS_FOLLOW_DEADLINE_MS")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn cli: {e}"))?;
        let out_rx = spawn_reader(child.stdout.take().ok_or("stdout not piped")?);
        let err_rx = spawn_reader(child.stderr.take().ok_or("stderr not piped")?);
        let deadline = Instant::now() + limit;
        let status = loop {
            match child.try_wait().map_err(|e| format!("poll cli: {e}"))? {
                Some(s) => break s,
                None if Instant::now() >= deadline => {
                    return Err(match kill_and_reap(&mut child) {
                        Ok(()) => format!("cli did not exit within {limit:?}"),
                        Err(e) => format!("cli did not exit within {limit:?}; {e}"),
                    });
                }
                None => thread::sleep(POLL),
            }
        };
        let collect = Instant::now() + REAP_TIMEOUT;
        let remaining = || collect.saturating_duration_since(Instant::now());
        let stdout = out_rx
            .recv_timeout(remaining())
            .map_err(|_| "stdout was not collected in time".to_string())?;
        let stderr = err_rx
            .recv_timeout(remaining())
            .map_err(|_| "stderr was not collected in time".to_string())?;
        Ok(RunOut {
            code: status.code(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    }

    // ---- bundle の用意（supervisor_bin_real.rs の make_rootfs 等を写したもの。crate が違うため共有できない） ----

    fn mkdir(path: &Path) -> Result<(), String> {
        fs::create_dir_all(path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
        set_mode(path, 0o755)
    }

    /// `host` のファイルを rootfs 内の同じ絶対パスへコピーする。
    fn copy_into(rootfs: &Path, host: &Path) -> Result<(), String> {
        let rel = host
            .strip_prefix("/")
            .map_err(|_| format!("not absolute: {}", host.display()))?;
        let dest = rootfs.join(rel);
        mkdir(dest.parent().ok_or("no parent")?)?;
        let _ = fs::remove_file(&dest);
        fs::copy(host, &dest)
            .map_err(|e| format!("copy {} -> {}: {e}", host.display(), dest.display()))?;
        set_mode(&dest, 0o755)
    }

    /// ELF64（リトルエンディアン）の `PT_INTERP`（動的ローダのパス）を返す。範囲は `get()` で検査する。
    fn elf_interp(exe: &[u8]) -> Option<String> {
        let u16_at = |o: usize| Some(u16::from_le_bytes(exe.get(o..o + 2)?.try_into().ok()?));
        let u32_at = |o: usize| Some(u32::from_le_bytes(exe.get(o..o + 4)?.try_into().ok()?));
        let u64_at = |o: usize| Some(u64::from_le_bytes(exe.get(o..o + 8)?.try_into().ok()?));
        if exe.get(0..4)? != b"\x7fELF" {
            return None;
        }
        let phoff = usize::try_from(u64_at(0x20)?).ok()?;
        let phentsize = usize::from(u16_at(0x36)?);
        let phnum = usize::from(u16_at(0x38)?);
        for i in 0..phnum {
            let base = phoff.checked_add(i.checked_mul(phentsize)?)?;
            if u32_at(base)? == 3 {
                let off = usize::try_from(u64_at(base + 8)?).ok()?;
                let len = usize::try_from(u64_at(base + 32)?).ok()?;
                let raw = exe.get(off..off.checked_add(len)?)?;
                let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
                return String::from_utf8(raw.get(..end)?.to_vec()).ok();
            }
        }
        None
    }

    /// 自プロセスに読み込み済みの共有ライブラリの実パス（`/proc/self/maps` から。重複なし）。
    fn loaded_libraries(exe: &Path) -> Result<Vec<PathBuf>, String> {
        let maps = fs::read_to_string("/proc/self/maps").map_err(|e| format!("read maps: {e}"))?;
        let mut libs: Vec<PathBuf> = Vec::new();
        for line in maps.lines() {
            let Some(path) = line.split_whitespace().nth(5) else {
                continue;
            };
            let p = PathBuf::from(path);
            if !path.starts_with('/')
                || p == exe
                || ["/dev/", "/proc/", "/sys/", "/tmp/", "/memfd:"]
                    .iter()
                    .any(|pre| path.starts_with(pre))
                || libs.contains(&p)
            {
                continue;
            }
            if fs::metadata(&p).is_ok_and(|m| m.is_file()) {
                libs.push(p);
            }
        }
        Ok(libs)
    }

    /// bundle（`config.json` と最小 rootfs）を作る。`/probe` は本試験の実行ファイルのコピー。
    fn make_bundle(bundle: &Path) -> Result<(), String> {
        mkdir(bundle)?;
        let rootfs = bundle.join("rootfs");
        for d in ["", "proc", "dev", "tmp", "etc"] {
            mkdir(&rootfs.join(d))?;
        }
        let exe =
            fs::canonicalize(std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?)
                .map_err(|e| format!("canonicalize exe: {e}"))?;
        let probe = rootfs.join("probe");
        fs::copy(&exe, &probe).map_err(|e| format!("copy probe binary: {e}"))?;
        set_mode(&probe, 0o755)?;
        let bytes = fs::read(&exe).map_err(|e| format!("read exe: {e}"))?;
        let mut lib_dirs: Vec<String> = Vec::new();
        if let Some(interp) = elf_interp(&bytes) {
            copy_into(&rootfs, Path::new(&interp))?;
        }
        for lib in loaded_libraries(&exe)? {
            copy_into(&rootfs, &lib)?;
            if let Some(dir) = lib.parent().and_then(Path::to_str)
                && !lib_dirs.iter().any(|d| d == dir)
            {
                lib_dirs.push(dir.to_string());
            }
        }
        let ld = lib_dirs.join(":");
        // uidMappings / gidMappings・cgroupsPath は書かない（それぞれ UNIMPLEMENTED で拒否される）。
        let config = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"hostname":"fandhe-ssd",
"process":{{"user":{{"uid":0,"gid":0}},"args":["/probe","--container-probe"],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#
        );
        fs::write(bundle.join("config.json"), config).map_err(|e| format!("write config: {e}"))
    }
}
