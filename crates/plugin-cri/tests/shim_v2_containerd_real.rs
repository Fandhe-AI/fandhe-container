//! containerd 経由で実コンテナを配布する shim バイナリに通す実機前提の通し試験
//! （CRI-5・CRI-7・PLUG-1・SUP-1・CORE-3・REPAIR-5・REPAIR-12。TASK-62.6・#3684）。
//!
//! `crates/cri/tests/shim_v2.rs` の containerd シナリオ（#676）は試験バイナリ自身が偽ランタイムで shim 役を兼ねる
//! プロトコル水準の確認だった。本試験は配布する `containerd-shim-fandhe-container-v2`（本番の `TaskService` と
//! `CoreLifecycleRuntime` を登録する）を `ctr run --runtime <絶対パス>` で containerd に exec させ、本番の rootless の
//! `start`（supervisor を委譲 scope で起動）まで含めて実コンテナを動かす。
//!
//! # シナリオ
//! - A: `ctr run --rm --null-io --config <spec> <id>` で Create → Start、`ctr tasks ls` で RUNNING の pid（State。実在する pid）を確認、
//!   `ctr tasks kill --signal SIGKILL`（Kill）、`ctr run` の終了コードが 137（Wait。128 + SIGKILL）、`--rm` による Delete → Shutdown。
//! - B: `ctr run -d` で起動し、`ctr tasks kill --all --signal SIGKILL`（Kill の `all=true`。#3680）で STOPPED を待ち、
//!   `ctr tasks delete`・`ctr containers rm` で片付ける。
//! - 共通: 後始末の後に `ctr tasks ls -q`・`ctr containers ls -q` が空、shim のデーモンと supervisor が残らず、shim の socket が残らず、
//!   状態ルートの `<id>` が無いことを照合する。
//!
//! プローブ（`--container-probe`）は `READY` を出して最大 60 秒待つだけ。停止は SIGKILL で行う（PID 1 は `SIG_DFL` の SIGTERM を受けないため
//! ハンドラが要るが、ハンドラの登録は core の試験用 feature が要るので使わない）。
//!
//! # `exited_at` が未設定のときの containerd の扱い（#3682 の追記の依頼）
//! 本番の経路では supervisor の monitor が終了時刻を状態記録へ書き、State・Wait・Delete が同じ値を返す（`shim_exited_at.rs` で範囲照合済み）。
//! 未設定時の containerd の挙動の一次情報は `docs/design/shim-v2-production-binary.md` に記録する。
//!
//! # 必要環境
//! Linux 6.12 以上（Landlock ABI 6 以上）・cgroup v2・非 root・非特権 user namespace・`systemd-run --user`（user マネージャ）・
//! 非 root で動かせる containerd 2.0 以上と ctr（`FANDHE_CONTAINER_E2E_CONTAINERD`・`FANDHE_CONTAINER_E2E_CTR` で絶対パスを上書き可）。
//! 試験全体を `systemd-run --user --scope -p Delegate=yes` で包んで実行する（shim は containerd の環境と cgroup を継ぐ）。
//! 事前に `cargo build -p fandhe-container-supervisor -p fandhe-container-plugin-cri` を行う。shim と supervisor は作業ディレクトリの
//! `bin/` へ 0755 でコピーして使い、特権ランチャーは置かない（置くと rootful のインストールとみなされる）。
//! 前提が欠けたら skip ではなく 1 行目 `PRECONDITION FAILED` で失敗する。rootful の containerd では Create は通るが Start が
//! `UNIMPLEMENTED`（#2442・#2241）になるため対象外。
//!
//! # 実機前提テストとしての分離
//! `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。未指定は案内を出して成功する。実行と結果の記録は人間担当（#3685）。
//!
//! ```text
//! cargo build -p fandhe-container-supervisor -p fandhe-container-plugin-cri
//! cargo test -p fandhe-container-plugin-cri --test shim_v2_containerd_real --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/shim_v2_containerd_real-XXXX> --ignored
//! ```
//!
//! 成功行（固定）: `shim_v2_containerd_real: containerd drove Create -> Start -> State -> Kill -> Wait -> Delete -> Shutdown through the production shim (exit_status=137)`
//! と `shim_v2_containerd_real: containerd killed the whole container with Kill all=true through the production shim`。
//! 失敗は `shim_v2_containerd_real: FAILED: ...`、全体の期限切れは `WATCHDOG EXPIRED` と終了コード 124。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("shim_v2_containerd_real: skipped (linux only)");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    if std::env::args().any(|a| a == "--container-probe") {
        linux::probe();
    }
    linux::main()
}

#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/minimal_rootfs.rs"]
mod minimal_rootfs;
#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/reap.rs"]
mod reap;
#[cfg(target_os = "linux")]
#[path = "../../oci/tests/support/test_root.rs"]
mod test_root;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write as _;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::{minimal_rootfs, reap, test_root};

    /// 全体の期限（REPAIR-5）。超えたら子を回収して `WATCHDOG EXPIRED` と終了コード 124 で終わる。
    const WATCHDOG: Duration = Duration::from_secs(300);
    /// 個々の `ctr` 呼び出しの期限。
    const CTR_TIMEOUT: Duration = Duration::from_secs(20);
    /// コンテナの寿命の上限。SIGKILL が届かなければ終了コード 8 で終わる（寿命切れを停止と取り違えないための目印）。
    const PROBE_LIFETIME: Duration = Duration::from_secs(60);
    /// SIGKILL で止めたコンテナの `ctr run` の終了コード（128 + 9）。
    const EXIT_STATUS_KILLED: i32 = 137;
    const NAMESPACE: &str = "fandhe-e2e";
    const SHIM_NAME: &str = "containerd-shim-fandhe-container-v2";
    const SUPERVISOR_NAME: &str = "fandhe-container-supervisor";
    const LINE_A: &str = "shim_v2_containerd_real: containerd drove Create -> Start -> State -> Kill -> Wait -> Delete -> Shutdown through the production shim (exit_status=137)";
    const LINE_B: &str = "shim_v2_containerd_real: containerd killed the whole container with Kill all=true through the production shim";

    /// 期限切れの後始末で止める子の pid（containerd 本体と `ctr run` の子）。
    static CHILDREN: Mutex<Vec<u32>> = Mutex::new(Vec::new());

    /// コンテナ内で動くプローブ。`READY` を出して最大 60 秒待つ。
    pub fn probe() -> ! {
        let mut out = std::io::stdout();
        let _ = writeln!(out, "READY");
        let _ = out.flush();
        let deadline = Instant::now() + PROBE_LIFETIME;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        std::process::exit(8);
    }

    fn precondition_failed(reason: &str) -> ! {
        // 前提欠如は回帰と 1 行目で見分ける（skip にしない）。メッセージはホストのパス・ID を含めない。
        println!(
            "shim_v2_containerd_real: PRECONDITION FAILED (test environment, not a shim regression): {reason}"
        );
        std::process::exit(1);
    }

    fn kill_pid(sig: &str, pid: u32) {
        // `kill` の待ちにも期限を持つ（watchdog の中からも呼ばれる。止まっても exit(124) へ進めるため。REPAIR-5）。
        let _ = reap::run_within(
            Command::new("kill")
                .args([&format!("-{sig}"), &pid.to_string()])
                .stderr(Stdio::null()),
            Duration::from_secs(5),
        );
    }

    fn watchdog() {
        std::thread::spawn(|| {
            std::thread::sleep(WATCHDOG);
            eprintln!("shim_v2_containerd_real: WATCHDOG EXPIRED after {WATCHDOG:?}");
            if let Ok(pids) = CHILDREN.lock() {
                for pid in pids.iter() {
                    kill_pid("KILL", *pid);
                }
            }
            std::process::exit(124);
        });
    }

    fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
        let until = Instant::now() + limit;
        loop {
            if f() {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `containerd --version` の出力から (major, minor) を取り出す。
    fn containerd_version(text: &str) -> Option<(u32, u32)> {
        let v = text.split_whitespace().find(|w| {
            w.strip_prefix('v')
                .is_some_and(|r| r.chars().next().is_some_and(|c| c.is_ascii_digit()))
        })?;
        let mut it = v.trim_start_matches('v').split('.');
        Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
    }

    /// 私設 containerd の設定（v3 形式）。CRI・NRI・task monitor・tracing を無効にし、システムの containerd と何も共有しない。
    fn containerd_config(dir: &Path) -> String {
        let d = dir.display();
        format!(
            "version = 3\nroot = \"{d}/root\"\nstate = \"{d}/state\"\ntemp = \"{d}/tmp\"\n\
             disabled_plugins = [\"io.containerd.grpc.v1.cri\", \"io.containerd.cri.v1.runtime\", \
             \"io.containerd.cri.v1.images\", \"io.containerd.nri.v1.nri\", \
             \"io.containerd.monitor.task.v1.cgroups\", \"io.containerd.internal.v1.tracing\", \
             \"io.containerd.tracing.processor.v1.otlp\", \
             \"io.containerd.podsandbox.controller.v1.podsandbox\"]\n\
             [grpc]\n  address = \"{d}/c.sock\"\n[ttrpc]\n  address = \"{d}/t.sock\"\n[debug]\n  address = \"{d}/d.sock\"\n"
        )
    }

    /// 実体と全祖先が root 所有で group/other 書き込み不可の絶対パスだけを使う（検査後の差し替えを防ぐ）。
    fn tool(env: &str, name: &str) -> PathBuf {
        let cand: Vec<PathBuf> = match std::env::var_os(env) {
            Some(p) => vec![PathBuf::from(p)],
            None => ["/usr/bin", "/usr/local/bin"]
                .iter()
                .map(|d| Path::new(d).join(name))
                .collect(),
        };
        let Some(p) = cand.into_iter().find(|p| p.is_absolute() && p.is_file()) else {
            precondition_failed(&format!(
                "{name} is not installed (set {env} to an absolute path)"
            ));
        };
        let real = std::fs::canonicalize(&p)
            .unwrap_or_else(|_| precondition_failed("cannot resolve tool path"));
        for a in real.ancestors() {
            let m = std::fs::metadata(a)
                .unwrap_or_else(|_| precondition_failed("cannot stat tool or its ancestor"));
            if m.uid() != 0 || m.mode() & 0o022 != 0 {
                precondition_failed(&format!(
                    "{name} and all its ancestor directories must be owned by root and not group/other writable"
                ));
            }
        }
        real
    }

    /// 試験バイナリの隣（`target/<profile>/`）にある成果物を探す。
    fn sibling_artifact(name: &str) -> PathBuf {
        let exe = std::env::current_exe()
            .unwrap_or_else(|_| precondition_failed("cannot resolve the test executable path"));
        let found = exe
            .ancestors()
            .skip(1)
            .take(3)
            .map(|d| d.join(name))
            .find(|p| p.is_file());
        found.unwrap_or_else(|| {
            precondition_failed(&format!(
                "{name} is not built (run cargo build -p fandhe-container-supervisor -p fandhe-container-plugin-cri first)"
            ))
        })
    }

    fn install_exe(src: &Path, dest: &Path) -> Result<(), String> {
        minimal_rootfs::file_copy::replace_with_copy(src, dest)
            .map_err(|e| format!("copy {}: {e}", src.display()))?;
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("chmod {}: {e}", dest.display()))
    }

    /// 最小 rootfs と user namespace を含む spec（root.path は絶対パス）を書く。
    fn write_spec(dir: &Path) -> Result<PathBuf, String> {
        let rootfs = dir.join("rootfs");
        let ld =
            minimal_rootfs::install_binary_at(&rootfs, "probe", &["proc", "dev", "tmp", "etc"])?;
        let spec = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"{}","readonly":false}},"hostname":"fandhe-shim",
"process":{{"user":{{"uid":0,"gid":0}},"args":["/probe","--container-probe"],
"env":["PATH=/","TERM=dumb","LD_LIBRARY_PATH={ld}"],"cwd":"/"}},
"linux":{{"namespaces":[{{"type":"pid"}},{{"type":"mount"}},{{"type":"uts"}},{{"type":"ipc"}},{{"type":"user"}}]}}}}"#,
            rootfs.display()
        );
        let path = dir.join("spec.json");
        std::fs::write(&path, spec).map_err(|e| format!("write spec: {e}"))?;
        Ok(path)
    }

    /// 1 プロセスが「`bin_dir` から起動された `names` のどれかで、引数に `id` を持つ」かの判定（純関数）。
    /// 本番 supervisor は `PR_SET_DUMPABLE=0` のため同一 UID でも `/proc/<pid>/exe` の `read_link` が拒否される（`exe` が `None`）。
    /// その場合は拒否されない `cmdline` の argv[0] で帰属を判定し、確認不能を「不存在」にしない（fail-closed。REPAIR-12）。
    fn belongs(
        exe: Option<&Path>,
        cmdline: &[u8],
        id: &str,
        bin_dir: &Path,
        names: &[&str],
    ) -> bool {
        let argv0 = cmdline
            .split(|b| *b == 0)
            .next()
            .map(|a| PathBuf::from(String::from_utf8_lossy(a).into_owned()));
        let (dir_ok, file) = match (exe, argv0.as_deref()) {
            (Some(e), _) => (e.parent() == Some(bin_dir), e.file_name()),
            // 非 dumpable: 相対 argv[0] は親を確かめられないため名前だけで受ける（id の一致が別途必要）。
            (None, Some(a)) => (
                a.parent()
                    .is_none_or(|p| p.as_os_str().is_empty() || p == bin_dir),
                a.file_name(),
            ),
            (None, None) => return false,
        };
        if !dir_ok || !names.iter().any(|n| file.is_some_and(|f| f == *n)) {
            return false;
        }
        cmdline.split(|b| *b == 0).any(|arg| {
            let arg = String::from_utf8_lossy(arg);
            arg == id || arg.split('/').any(|part| part == id)
        })
    }

    /// 試験専用の `bin_dir` から起動された `names` のプロセスのうち、引数のどれかが `id` と完全一致（または `/` 区切りの
    /// 1 要素が一致）するものの pid。帰属は `/proc/<pid>/exe`、読めない（非 dumpable の本番 supervisor）ときは
    /// `cmdline` の argv[0] で確かめる。無関係なコンテナ（`id` を接頭辞に持つ別 ID など）には当たらない。
    fn processes_with(id: &str, bin_dir: &Path, names: &[&str]) -> Vec<u32> {
        let me = std::process::id();
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        rd.flatten()
            .filter_map(|e| {
                let pid: u32 = e.file_name().to_str()?.parse().ok()?;
                if pid == me {
                    return None;
                }
                let exe = std::fs::read_link(e.path().join("exe")).ok();
                let c = std::fs::read(e.path().join("cmdline")).ok()?;
                belongs(exe.as_deref(), &c, id, bin_dir, names).then_some(pid)
            })
            .collect()
    }

    /// `belongs` の具体値による自己照合（REPAIR-12）。非 dumpable（exe 不明）の supervisor が残存として検出されること、
    /// 別 ID・別ディレクトリが誤検出されないことを固定する。
    fn self_check_belongs() -> Result<(), String> {
        let bin = Path::new("/tmp/x/bin");
        let sup = Path::new("/tmp/x/bin/fandhe-container-supervisor");
        let names = [SHIM_NAME, SUPERVISOR_NAME];
        let cmd = b"/tmp/x/bin/fandhe-container-supervisor\0--id\0ctr1\0";
        let cases: [(&str, bool, bool); 5] = [
            (
                "dumpable",
                belongs(Some(sup), cmd, "ctr1", bin, &names),
                true,
            ),
            (
                "non-dumpable",
                belongs(None, cmd, "ctr1", bin, &names),
                true,
            ),
            ("other id", belongs(None, cmd, "ctr", bin, &names), false),
            (
                "other dir",
                belongs(
                    None,
                    b"/usr/bin/fandhe-container-supervisor\0ctr1\0",
                    "ctr1",
                    bin,
                    &names,
                ),
                false,
            ),
            ("no cmdline", belongs(None, b"", "ctr1", bin, &names), false),
        ];
        for (name, got, want) in cases {
            if got != want {
                return Err(format!(
                    "self-check belongs[{name}]: got {got}, want {want}"
                ));
            }
        }
        Ok(())
    }

    pub fn main() -> ExitCode {
        if let Err(e) = self_check_belongs() {
            eprintln!("shim_v2_containerd_real: FAILED: {e}");
            return ExitCode::from(1);
        }
        if !std::env::args().any(|a| a == "--ignored") {
            println!(
                "shim_v2_containerd_real: containerd scenario ignored (run the test binary with --ignored in a delegated scope; see crates/plugin-cri/tests/shim_v2_containerd_real.rs)"
            );
            return ExitCode::SUCCESS;
        }
        watchdog();
        match scenario() {
            Ok(()) => {
                println!("{LINE_A}");
                println!("{LINE_B}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("shim_v2_containerd_real: FAILED: {e}");
                ExitCode::from(1)
            }
        }
    }

    fn scenario() -> Result<(), String> {
        // 1. 前提確認（欠けたら skip せず PRECONDITION FAILED）。
        let uid = std::fs::metadata("/proc/self")
            .map(|m| m.uid())
            .unwrap_or(0);
        if uid == 0 {
            precondition_failed("must run as a non-root user (rootful start is UNIMPLEMENTED)");
        }
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            precondition_failed("cgroup v2 is required");
        }
        let containerd = tool("FANDHE_CONTAINER_E2E_CONTAINERD", "containerd");
        let ctr = tool("FANDHE_CONTAINER_E2E_CTR", "ctr");
        let mut v = Command::new(&containerd);
        v.arg("--version");
        let vout = reap::output_within(&mut v, Duration::from_secs(10))
            .unwrap_or_else(|_| precondition_failed("containerd --version did not finish"));
        match containerd_version(&String::from_utf8_lossy(&vout.stdout)) {
            Some((major, _)) if major >= 2 => {}
            _ => precondition_failed("containerd 2.0 or newer is required"),
        }
        let shim_src = sibling_artifact(SHIM_NAME);
        let sup_src = sibling_artifact(SUPERVISOR_NAME);

        // 2. 作業ディレクトリ（sun_path の制約のため短い /tmp 直下）。shim と supervisor は同じ bin/ に置く（ランチャーは置かない）。
        let work =
            test_root::test_root_at(PathBuf::from(format!("/tmp/fsr{}", std::process::id())));
        let dir: PathBuf = (*work).to_path_buf();
        let bin = dir.join("bin");
        std::fs::create_dir(&bin).map_err(|e| format!("mkdir bin: {e}"))?;
        let shim = bin.join(SHIM_NAME);
        install_exe(&shim_src, &shim)?;
        install_exe(&sup_src, &bin.join(SUPERVISOR_NAME))?;
        let spec = write_spec(&dir)?;
        let id = format!("shimreal{}", std::process::id());
        let id_b = format!("shimrealb{}", std::process::id());
        let cfg_path = dir.join("config.toml");
        std::fs::write(&cfg_path, containerd_config(&dir)).map_err(|e| format!("config: {e}"))?;
        for sub in ["root", "state", "tmp"] {
            std::fs::create_dir(dir.join(sub)).map_err(|e| format!("mkdir {sub}: {e}"))?;
        }

        // 3. 私設 containerd（非 root。shim の socket 置き場所は作業ディレクトリへ向ける）。
        let open_log = |n: &str| std::fs::File::create(dir.join(n));
        let mut d = Command::new(&containerd);
        d.arg("--config")
            .arg(&cfg_path)
            .env("FANDHE_CONTAINER_SHIM_SOCKET_DIR", dir.join("s"))
            .stdin(Stdio::null())
            .stdout(open_log("containerd.out").map_err(|e| e.to_string())?)
            .stderr(open_log("containerd.err").map_err(|e| e.to_string())?);
        let mut daemon = d
            .spawn()
            .unwrap_or_else(|_| precondition_failed("cannot start containerd"));
        if let Ok(mut c) = CHILDREN.lock() {
            c.push(daemon.id());
        }
        let sock = dir.join("c.sock");
        let ctr_cmd = |args: &[&str]| {
            let mut c = Command::new(&ctr);
            c.arg("--address")
                .arg(&sock)
                .args(["--namespace", NAMESPACE])
                .args(args)
                .stdin(Stdio::null());
            c
        };
        let ctr_out = |args: &[&str]| -> Result<String, String> {
            let o = reap::output_within(&mut ctr_cmd(args), CTR_TIMEOUT)
                .map_err(|e| format!("ctr {args:?}: {e}"))?;
            if !o.status.success() {
                return Err(format!(
                    "ctr {args:?} failed: {:?}; stderr: {}",
                    o.status.code(),
                    String::from_utf8_lossy(&o.stderr)
                ));
            }
            Ok(String::from_utf8_lossy(&o.stdout).into_owned())
        };
        let task_row = |id: &str| -> Option<(u32, String)> {
            let out = ctr_out(&["tasks", "ls"]).ok()?;
            out.lines().find_map(|l| {
                let mut f = l.split_whitespace();
                (f.next()? == id).then_some(())?;
                Some((f.next()?.parse().ok()?, f.next()?.to_string()))
            })
        };

        let shim_s = shim.to_string_lossy().into_owned();
        let spec_s = spec.to_string_lossy().into_owned();
        let outcome = (|| -> Result<(), String> {
            if !wait_until(Duration::from_secs(30), || {
                reap::output_within(&mut ctr_cmd(&["version"]), Duration::from_secs(5))
                    .is_ok_and(|o| o.status.success())
            }) {
                return Err("containerd did not become ready".into());
            }

            // シナリオ A: Create → Start → State → Kill → Wait → Delete → Shutdown。
            //   --runtime に絶対パスを渡すと containerd は PATH を探さずこの shim を exec する。
            //   --config を使うと位置引数は id だけになる。--null-io は stdio の FIFO を作らない。
            let mut run_cmd = ctr_cmd(&[
                "run",
                "--rm",
                "--null-io",
                "--runtime",
                &shim_s,
                "--config",
                &spec_s,
                &id,
            ]);
            let out_a =
                std::fs::File::create(dir.join("ctr-run-a.out")).map_err(|e| e.to_string())?;
            let err_a = out_a.try_clone().map_err(|e| e.to_string())?;
            let mut run_child: Child = run_cmd
                .stdout(out_a)
                .stderr(err_a)
                .spawn()
                .map_err(|e| format!("spawn ctr run: {e}"))?;
            if let Ok(mut c) = CHILDREN.lock() {
                c.push(run_child.id());
            }
            let mut running: Option<u32> = None;
            if !wait_until(Duration::from_secs(60), || match task_row(&id) {
                Some((pid, status)) if status == "RUNNING" => {
                    running = Some(pid);
                    true
                }
                _ => false,
            }) {
                let _ = reap::reap(&mut run_child, Duration::from_secs(10));
                return Err("task never reached RUNNING (State)".into());
            }
            let pid = running.unwrap_or(0);
            if pid == 0 || !Path::new(&format!("/proc/{pid}")).exists() {
                let _ = reap::reap(&mut run_child, Duration::from_secs(10));
                return Err(format!("State reported pid {pid}, which does not exist"));
            }
            ctr_out(&["tasks", "kill", "--signal", "SIGKILL", &id])?;
            let status = reap::wait_within(&mut run_child, Duration::from_secs(60))
                .map_err(|e| format!("ctr run did not exit: {e}"))?;
            if status.code() != Some(EXIT_STATUS_KILLED) {
                return Err(format!(
                    "ctr run exit code {:?} (want {EXIT_STATUS_KILLED}); output: {}",
                    status.code(),
                    std::fs::read_to_string(dir.join("ctr-run-a.out")).unwrap_or_default()
                ));
            }
            check_clean(&dir, &id, &ctr_out)?;

            // シナリオ B: Kill の all=true。
            ctr_out(&[
                "run",
                "-d",
                "--null-io",
                "--runtime",
                &shim_s,
                "--config",
                &spec_s,
                &id_b,
            ])?;
            if !wait_until(Duration::from_secs(30), || {
                task_row(&id_b).is_some_and(|(_, s)| s == "RUNNING")
            }) {
                return Err("detached task never reached RUNNING".into());
            }
            ctr_out(&["tasks", "kill", "--all", "--signal", "SIGKILL", &id_b])?;
            if !wait_until(Duration::from_secs(30), || {
                task_row(&id_b).is_some_and(|(_, s)| s == "STOPPED")
            }) {
                return Err("Kill all=true did not stop the task".into());
            }
            ctr_out(&["tasks", "delete", &id_b])?;
            ctr_out(&["containers", "rm", &id_b])?;
            check_clean(&dir, &id_b, &ctr_out)
        })();

        // 4. 後始末（成否に関わらず）。
        for target in [&id, &id_b] {
            let _ = reap::output_within(
                &mut ctr_cmd(&["tasks", "kill", "--signal", "SIGKILL", target]),
                Duration::from_secs(10),
            );
            let _ = reap::output_within(
                &mut ctr_cmd(&["tasks", "delete", target]),
                Duration::from_secs(10),
            );
            let _ = reap::output_within(
                &mut ctr_cmd(&["containers", "rm", target]),
                Duration::from_secs(10),
            );
        }
        kill_pid("TERM", daemon.id());
        if !wait_until(Duration::from_secs(15), || {
            daemon.try_wait().ok().flatten().is_some()
        }) {
            let _ = reap::reap(&mut daemon, Duration::from_secs(10));
        }
        for t in [&id, &id_b] {
            for pid in processes_with(t, &bin, &[SHIM_NAME, SUPERVISOR_NAME]) {
                kill_pid("KILL", pid);
            }
        }
        if let Err(e) = &outcome {
            for f in [
                "containerd.err",
                "containerd.out",
                "s/daemon.log",
                "ctr-run-a.out",
            ] {
                let t = std::fs::read_to_string(dir.join(f)).unwrap_or_default();
                let tail: Vec<&str> = t.lines().rev().take(40).collect();
                eprintln!(
                    "--- {f} (last lines) ---\n{}",
                    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                );
            }
            eprintln!("shim_v2_containerd_real: diagnostics end: {e}");
        }
        outcome
    }

    /// 1 つのコンテナが片付いたことの照合（tasks / containers が空・デーモンと supervisor が残らない・socket が残らない・状態ルートに無い）。
    fn check_clean(
        dir: &Path,
        id: &str,
        ctr_out: &dyn Fn(&[&str]) -> Result<String, String>,
    ) -> Result<(), String> {
        if !wait_until(Duration::from_secs(15), || {
            processes_with(id, &dir.join("bin"), &[SHIM_NAME, SUPERVISOR_NAME]).is_empty()
        }) {
            return Err(format!("shim daemon or supervisor for {id} still alive"));
        }
        for what in ["tasks", "containers"] {
            let out = ctr_out(&[what, "ls", "-q"])?;
            if out.lines().any(|l| l.trim() == id) {
                return Err(format!("{what} still lists {id}"));
            }
        }
        let socks = match std::fs::read_dir(dir.join("s")) {
            Ok(rd) => rd
                .flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_socket()))
                .count(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(format!("read socket dir: {e}")),
        };
        if socks != 0 {
            return Err(format!("{socks} shim socket(s) remain"));
        }
        let xdg = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or("XDG_RUNTIME_DIR is not set")?;
        // 実際の配置は `<XDG>/fandhe-container-shim-state/<address のハッシュ>/<namespace>/<id>`（`scoped_root`）。ハッシュは
        // containerd の ttrpc address 由来なので、全ハッシュ配下の当該 namespace を走査する。旧配置（`<XDG>/fandhe-container/<id>`）も見る。
        let mut remains = vec![xdg.join("fandhe-container").join(id)];
        match std::fs::read_dir(xdg.join("fandhe-container-shim-state")) {
            Ok(rd) => {
                for h in rd.flatten() {
                    remains.push(h.path().join(NAMESPACE).join(id));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("read shim state dir: {e}")),
        }
        if let Some(p) = remains.iter().find(|p| p.symlink_metadata().is_ok()) {
            return Err(format!("state directory for {id} remains: {}", p.display()));
        }
        Ok(())
    }
}
