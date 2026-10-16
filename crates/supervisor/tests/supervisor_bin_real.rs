//! supervisor の bin から core の本番 launcher を経て `monitor` まで通す実機シナリオ
//! （TASK-157 追補・#1819・SUP-1・SUP-3・SUP-7・CORE-1・CORE-2・CORE-3・CORE-5・SEC-1・REPAIR-3・REPAIR-12）。
//!
//! `harness = false` の単一 `main` で、同じ実行ファイルが 2 つの役を持つ。
//! - 親（既定）: `-- --ignored` のときだけ実機シナリオを動かす（それ以外は案内を出して成功。既定のテスト集合に
//!   実機前提を混ぜないため）。
//! - コンテナ内のプローブ（`--container-probe`）: `READY` を 1 行出し、約 2 秒待って終了コード 7 で終わる。
//!
//! # 照合項目
//! - シナリオ A（正常起動 → 監視 → 記録）: bin が `FCSUP1 OK <pid>` を報告し、状態が Running（pid 一致）で、ホストの
//!   `/proc/<pid>/status` の `NSpid` 末尾が 1。プローブの終了を `monitor` が回収して状態が Stopped（終了コード 7）に
//!   なり、bin が終了コード 0 で終わり、`/proc/<pid>` が消え、コンテナの出力（`READY`）がログ sink のファイルに残る
//! - シナリオ B（起動失敗で何も残らない。A6）: rootfs から `proc/` を除いて pre-pivot 段で失敗させ、報告が ERR・bin の
//!   終了コードが非 0・状態が Created（pid なし）・作った cgroup が消え・プローブのプロセスが残らないことを照合する
//! - シナリオ C（restart の fail-closed。SUP-3・#2043）: `--restart always` でプローブが終了した後、再 launch は
//!   単一スレッドの要求を満たせず本番 launcher が拒否する。新しい子は作られず、状態は Stopped で、bin の終了コードは
//!   FAILED_PRECONDITION の写像になる。再 launch が実機で成立する再構成（#2043）が入ったら、この項目を置き換える
//!
//! # 必要環境
//! - Linux 6.12 以上（Landlock ABI 6 以上。満たさないと launcher が起動を拒否する。CORE-5）
//! - 非特権ユーザーでの実行（root では rootful として拒否される。SEC-5）
//! - 非特権 user namespace を許可するホスト（`kernel.apparmor_restrict_unprivileged_userns=0` 等の緩和が要る場合がある）
//! - `systemd-run --user`（bin を非特権ユーザーに委譲された cgroup v2 の新しいスコープで起動するため。試験プロセスと同じ
//!   cgroup に他プロセスがいると `DelegatedCgroup::prepare` が失敗する）
//! - 動的リンクのためホストの共有ライブラリを rootfs へコピーする（ネットワークは不要）
//!
//! # 実機前提テストとしての分離
//! 上記の環境は GitHub ホステッド runner で保証できないため、`-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」。
//! 既定集合で動くはずの試験を移したものではない。既定集合では `supervisor_bin.rs` が fail-closed の不変条件を照合する）。
//! 実行された場合は、user namespace の拒否・Landlock ABI 不足・cgroup の委譲無しを含むあらゆる失敗を失敗として扱い、
//! 検証せずに成功する分岐は持たない。
//!
//! ```text
//! cargo test -p fandhe-container-supervisor --test supervisor_bin_real --no-run
//! <target/debug/deps/supervisor_bin_real-XXXX> --ignored
//! ```
//!
//! 成功時の最終行: `supervisor_bin_real: start reported OK, NSpid ends with 1, monitor recorded Stopped(7), logs
//! captured; failed start left no process; restart fails closed until #2043`。
//! 実行と結果の記録は人間担当（#499・#485・#491・#219 のうち該当するもの、または PR）。Linux 限定。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("supervisor_bin_real: Linux only, not applicable on this OS");
}

#[cfg(all(
    target_os = "linux",
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
fn main() {
    println!("supervisor_bin_real: x86_64/aarch64 only, not applicable on this architecture");
}

#[cfg(all(
    target_os = "linux",
    all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn main() {
    // 子（コンテナ内）は同じバイナリを `--container-probe` で再実行したもの。
    if std::env::args().any(|a| a == "--container-probe") {
        linux::probe();
    } else if std::env::args().any(|a| a == "--ignored") {
        linux::run();
    } else {
        println!(
            "supervisor_bin_real: ignored (real-machine test; run with `-- --ignored`, see AGENTS.md)"
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
mod linux {
    use std::io::{BufRead as _, Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::{create, exit_code_for};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, CreateRequest, ErrorCode, GetStateRequest, StateRecord,
        StateStore,
    };
    use fandhe_container_supervisor::start_contract::StartReport;
    use fandhe_container_supervisor::state::open_default_store;

    const BIN: &str = env!("CARGO_BIN_EXE_fandhe-container-supervisor");
    /// プローブの終了コード（状態の `Stopped` の終了コードと照合する）。
    const PROBE_EXIT: i32 = 7;
    /// プローブが `READY` を出してから終了するまでの時間。
    const PROBE_LIFETIME: Duration = Duration::from_secs(2);
    /// 報告 1 行を待つ上限と、bin の終了を待つ上限（REPAIR-5）。
    const REPORT_TIMEOUT: Duration = Duration::from_secs(60);
    const EXIT_TIMEOUT: Duration = Duration::from_secs(90);
    /// 報告 1 行の長さの上限（契約の最大長に十分な余裕。無制限確保を避ける）。
    const LINE_MAX: u64 = 1024;

    /// コンテナ内で動くプローブ。`READY` を出して一定時間待ち、`PROBE_EXIT` で終わる。
    pub fn probe() {
        let mut out = std::io::stdout();
        let _ = writeln!(out, "READY");
        let _ = out.flush();
        std::thread::sleep(PROBE_LIFETIME);
        std::process::exit(PROBE_EXIT);
    }

    fn require(ok: bool, msg: &str) {
        if !ok {
            eprintln!("supervisor_bin_real: precondition failed: {msg}");
            std::process::exit(1);
        }
    }

    fn status_field(path: &str, key: &str) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix(key).map(|v| v.trim().to_string()))
    }

    fn mkdir(path: &Path) {
        std::fs::create_dir_all(path).unwrap_or_else(|e| panic!("mkdir {}: {e}", path.display()));
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
    }

    /// `host` のファイルを rootfs 内の同じ絶対パスへコピーする。
    fn copy_into(rootfs: &Path, host: &Path, mode: u32) {
        let dest = rootfs.join(host.strip_prefix("/").expect("absolute path"));
        mkdir(dest.parent().expect("parent"));
        let _ = std::fs::remove_file(&dest);
        std::fs::copy(host, &dest)
            .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", host.display(), dest.display()));
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode))
            .unwrap_or_else(|e| panic!("chmod {}: {e}", dest.display()));
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
    fn loaded_libraries(exe: &Path) -> Vec<PathBuf> {
        let maps = std::fs::read_to_string("/proc/self/maps").expect("read /proc/self/maps");
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
            if std::fs::metadata(&p).is_ok_and(|m| m.is_file()) {
                libs.push(p);
            }
        }
        libs
    }

    /// 最小 rootfs を作る。`with_proc` が false なら `proc/` を作らない（シナリオ B の失敗注入）。
    /// 戻り値はプローブが使う `LD_LIBRARY_PATH` の値。
    fn make_rootfs(rootfs: &Path, with_proc: bool) -> String {
        mkdir(rootfs);
        let dirs: &[&str] = if with_proc {
            &["proc", "dev", "tmp", "etc"]
        } else {
            &["dev", "tmp", "etc"]
        };
        for d in dirs {
            mkdir(&rootfs.join(d));
        }
        let exe = std::env::current_exe().expect("current_exe");
        let exe = std::fs::canonicalize(exe).expect("canonicalize exe");
        let probe = rootfs.join("probe");
        std::fs::copy(&exe, &probe).expect("copy probe binary");
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755))
            .expect("chmod probe");
        let bytes = std::fs::read(&exe).expect("read exe");
        let mut lib_dirs: Vec<String> = Vec::new();
        if let Some(interp) = elf_interp(&bytes) {
            copy_into(rootfs, Path::new(&interp), 0o755);
        }
        for lib in loaded_libraries(&exe) {
            copy_into(rootfs, &lib, 0o755);
            if let Some(dir) = lib.parent().and_then(Path::to_str)
                && !lib_dirs.iter().any(|d| d == dir)
            {
                lib_dirs.push(dir.to_string());
            }
        }
        lib_dirs.join(":")
    }

    /// 一時ディレクトリ（bundle と状態ルート。drop で削除）。
    struct Env {
        dir: PathBuf,
        store: Arc<dyn StateStore>,
    }

    impl Env {
        fn new(tag: &str, with_proc: bool) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let dir = std::fs::canonicalize(std::env::temp_dir())
                .expect("canonicalize temp_dir")
                .join(format!(
                    "fandhe-supbinreal-{tag}-{}-{nanos}",
                    std::process::id()
                ));
            std::fs::create_dir(&dir).expect("exclusively create the work dir");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("chmod work dir");
            let bundle = dir.join("bundle");
            std::fs::create_dir(&bundle).expect("create bundle");
            let ld = make_rootfs(&bundle.join("rootfs"), with_proc);
            let config = format!(
                r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":false}},"hostname":"fandhe-supbin",
"process":{{"user":{{"uid":0,"gid":0}},"args":["/probe","--container-probe"],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#
            );
            std::fs::write(bundle.join("config.json"), config).expect("write config.json");
            let root = dir.join("state");
            std::fs::create_dir(&root).expect("create state root");
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .expect("chmod state root");
            let store = open_default_store(Some(root)).expect("open the state store");
            Self { dir, store }
        }

        fn root(&self) -> PathBuf {
            self.dir.join("state")
        }

        fn create(&self, id: &str) {
            let req = CreateRequest::new(cid(id), self.dir.join("bundle")).expect("create request");
            create(self.store.as_ref(), &OpRecorder::new(), &req).expect("create");
        }

        fn record(&self, id: &str) -> StateRecord {
            self.store
                .get(&GetStateRequest::new(cid(id)))
                .expect("get state")
        }
    }

    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn cid(id: &str) -> ContainerId {
        ContainerId::new(id).expect("container id")
    }

    /// 起動中の supervisor（`systemd-run --user --scope` 経由。stdout が結果チャネルの pipe）。
    struct Supervisor {
        child: Child,
        report: mpsc::Receiver<Vec<u8>>,
    }

    /// bin を非特権ユーザーに委譲された新しい cgroup スコープで起動する（CLI の契約と同じ argv・stdout は pipe）。
    fn spawn_supervisor(env: &Env, id: &str, restart: Option<&str>) -> Supervisor {
        let mut cmd = Command::new("systemd-run");
        cmd.args(["--user", "--scope", "--quiet", "-p", "Delegate=yes", "--"])
            .arg(BIN)
            .arg("start")
            .arg("--root")
            .arg(env.root());
        if let Some(policy) = restart {
            cmd.args(["--restart", policy]);
        }
        let mut child = cmd
            .arg(id)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn systemd-run (is `systemd-run --user` available?)");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, report) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = Vec::new();
            let mut reader = std::io::BufReader::new(stdout);
            let _ = (&mut reader).take(LINE_MAX).read_until(b'\n', &mut line);
            let _ = tx.send(line);
        });
        Supervisor { child, report }
    }

    impl Supervisor {
        /// 結果の 1 行を期限つきで待って復号する。
        fn report(&self) -> StartReport {
            let line = self
                .report
                .recv_timeout(REPORT_TIMEOUT)
                .expect("the supervisor must report within the deadline");
            StartReport::decode(&line)
                .unwrap_or_else(|e| panic!("invalid report {line:?}: {}", e.message()))
        }

        /// bin の終了を期限つきで待ち、終了コードを返す（超過したら kill して失敗させる）。
        fn exit_code(&mut self) -> i32 {
            let deadline = Instant::now() + EXIT_TIMEOUT;
            loop {
                if let Some(status) = self.child.try_wait().expect("try_wait") {
                    return status.code().expect("exit code (not a signal)");
                }
                if Instant::now() >= deadline {
                    let killed = self.child.kill();
                    // 回収も有限期限まで try_wait で確かめる（kill の失敗・終了しない子で無期限に止まらない。REPAIR-5）。
                    let reap_until = Instant::now() + Duration::from_secs(10);
                    let mut reaped = false;
                    while Instant::now() < reap_until {
                        if matches!(self.child.try_wait(), Ok(Some(_))) {
                            reaped = true;
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    panic!(
                        "the supervisor did not exit within the deadline (kill: {killed:?}, reaped: {reaped})"
                    );
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    /// `/proc` の全プロセスのうち、プローブ（`/probe --container-probe`）の数。
    fn probe_processes() -> usize {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return 0;
        };
        dir.flatten()
            .filter(|e| {
                std::fs::read(e.path().join("cmdline"))
                    .is_ok_and(|c| c.windows(17).any(|w| w == b"--container-probe"))
                    && e.file_name()
                        .to_str()
                        .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
            })
            // 自プロセス自体（`--container-probe` を引数に持たない）は除外される。
            .count()
    }

    /// プローブが消えるまで期限つきで待つ。
    fn no_probe_remains() -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if probe_processes() == 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        probe_processes() == 0
    }

    pub fn run() {
        let status = std::fs::read_to_string("/proc/self/status").expect("read status");
        let euid_is_root = status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|v| v.split_whitespace().nth(1).map(str::to_owned))
            .as_deref()
            == Some("0");
        require(
            !euid_is_root,
            "must run as a non-root user (rootful start is refused)",
        );
        scenario_a_start_monitor_record();
        scenario_b_failed_start_leaves_nothing();
        scenario_c_restart_fails_closed();
        println!(
            "supervisor_bin_real: start reported OK, NSpid ends with 1, monitor recorded Stopped({PROBE_EXIT}), logs captured; failed start left no process; restart fails closed until #2043"
        );
    }

    /// シナリオ A: 起動 → 報告 → 監視 → Stopped の記録。
    fn scenario_a_start_monitor_record() {
        let env = Env::new("a", true);
        let id = format!("sba{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, None);
        let pid = match sup.report() {
            StartReport::Started { pid } => pid,
            other => panic!("expected OK, got {other:?}"),
        };
        let running = env.record(&id);
        assert_eq!(running.status().state(), ContainerState::Running);
        assert_eq!(running.status().pid(), Some(pid));
        assert!(running.cgroup().is_some(), "the cgroup scope is recorded");
        let nspid = status_field(&format!("/proc/{pid}/status"), "NSpid:").expect("host NSpid");
        let parts: Vec<&str> = nspid.split_whitespace().collect();
        assert_eq!(parts.len(), 2, "NSpid must have two levels: {nspid:?}");
        assert_eq!(parts.first().copied(), Some(pid.to_string().as_str()));
        assert_eq!(parts.last().copied(), Some("1"));

        assert_eq!(sup.exit_code(), 0, "monitor must finish cleanly");
        let stopped = env.record(&id);
        assert_eq!(stopped.status().state(), ContainerState::Stopped);
        assert_eq!(stopped.status().exit_code(), Some(PROBE_EXIT));
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "the container process must be reaped"
        );
        assert!(no_probe_remains(), "no probe process may remain");
        // コンテナの出力が捕捉されてログ sink のファイルに残る（SUP-7）。
        let logs = env.root().join("logs");
        let captured = std::fs::read_dir(&logs)
            .expect("log directory")
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(&id))
            .any(|e| {
                std::fs::read_to_string(e.path())
                    .is_ok_and(|t| t.lines().any(|l| l.contains("READY")))
            });
        assert!(captured, "READY must be captured in the log sink");
        println!("supervisor_bin_real: scenario=A ok pid={pid} nspid={nspid:?}");
    }

    /// シナリオ B: pre-pivot 段の失敗で、子を残さず、Created のまま、作った cgroup を消す。
    fn scenario_b_failed_start_leaves_nothing() {
        let env = Env::new("b", false);
        let id = format!("sbb{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, None);
        let (code, exit_code) = match sup.report() {
            StartReport::Failed {
                code, exit_code, ..
            } => (code, exit_code),
            other => panic!("expected ERR, got {other:?}"),
        };
        let bin_exit = sup.exit_code();
        assert_ne!(bin_exit, 0);
        assert_eq!(bin_exit, i32::from(exit_code.get()));
        assert_ne!(code, ErrorCode::Unimplemented, "must reach the launcher");
        let rec = env.record(&id);
        assert_eq!(rec.status().state(), ContainerState::Created);
        assert!(rec.status().pid().is_none());
        assert!(no_probe_remains(), "no probe process may remain");
        // 作った cgroup は消えている（スコープの記録は残るが、`fc-<id>@...` のディレクトリは無い）。
        let placement = rec.cgroup().expect("the scope stays recorded");
        let scope_dir = PathBuf::from("/sys/fs/cgroup")
            .join(placement.scope().as_str().trim_start_matches('/'));
        let leftover = std::fs::read_dir(&scope_dir)
            .map(|d| {
                d.flatten()
                    .any(|e| e.file_name().to_string_lossy().contains(&id))
            })
            .unwrap_or(false);
        assert!(!leftover, "the container cgroup must be removed");
        println!("supervisor_bin_real: scenario=B ok code={}", code.as_str());
    }

    /// シナリオ C: restart の再 launch は fail-closed（#2043 まで）。
    fn scenario_c_restart_fails_closed() {
        let env = Env::new("c", true);
        let id = format!("sbc{}", std::process::id());
        env.create(&id);
        let mut sup = spawn_supervisor(&env, &id, Some("always"));
        let pid = match sup.report() {
            StartReport::Started { pid } => pid,
            other => panic!("expected OK, got {other:?}"),
        };
        let bin_exit = sup.exit_code();
        assert_eq!(
            bin_exit,
            i32::from(exit_code_for(ErrorCode::FailedPrecondition).get()),
            "the relaunch must be refused by the single-thread requirement"
        );
        let rec = env.record(&id);
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        assert!(no_probe_remains(), "no probe process may remain");
        println!("supervisor_bin_real: scenario=C ok first_pid={pid}");
    }
}
