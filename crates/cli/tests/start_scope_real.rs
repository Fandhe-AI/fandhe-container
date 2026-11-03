//! CLI の `start` が supervisor を委譲 scope で一人にして起動し、CLI が居残らないことの実機シナリオ
//! （#2081・CORE-3・CORE-4・SUP-1・CLI-1。関連: SEC-5・REPAIR-3・REPAIR-5・REPAIR-12）。
//!
//! `harness = false` の単一 `main` で、同じ実行ファイルが 2 つの役を持つ。
//! - 親（既定）: `-- --ignored` のときだけ実機シナリオを動かす（それ以外は案内を出して成功。既定のテスト集合に
//!   実機前提を混ぜないため）。
//! - プローブ（argv が `start --root <root> <id>`）: CLI の隣に `fandhe-container-supervisor` として置かれた
//!   この実行ファイル自身。自分の cgroup・親の cgroup・`cgroup.procs`・`DelegatedCgroup::detect` / `prepare` の結果を
//!   `<root の親>/probe.out` へ書いてから `FCSUP1 OK <pid>` を報告して終わる。
//!
//! # 照合項目
//! - シナリオ A（本番の経路）: 試験プロセスと同じ cgroup（端末のシェルと同居する形）から CLI の `create` と `start` を
//!   実行し、CLI が終了コード 0 で終わり、プローブが CLI と異なる `.scope` の cgroup にいて、`cgroup.procs` が自分だけで、
//!   親（CLI）の pid を直接の親に持ち（systemd-run が exec 方式であること）、`detect` と `prepare` が成功する
//! - シナリオ B（試験の感度）: プローブを CLI も systemd-run も通さず試験プロセスから直接起動し（同じ cgroup に同居）、
//!   `detect` か `prepare` が `FAILED_PRECONDITION` か `PERMISSION_DENIED` で失敗する
//!
//! # 必要環境
//! 非特権ユーザー・cgroup v2・`systemd-run --user`（user マネージャ。`XDG_RUNTIME_DIR` が有効）。差し替え口
//! （`FANDHE_CONTAINER_TEST_SYSTEMD_RUN`）は使わず、本番の解決経路（`/usr/bin/systemd-run` 等）を通す。
//!
//! # 実機前提テストとしての分離
//! `make docker-ci` には user マネージャが無いため、`-- --ignored` 指定時のみ実行する
//! （ci.md「実機前提テスト」。既定集合の試験を移したものではない。既定集合の包み込みの検証は偽の systemd-run を使う
//! `binary_entry.rs` が行う）。実行された場合は、前提が欠けていても失敗として扱い、検証せずに成功する分岐は持たない。
//!
//! ```text
//! cargo test -p fandhe-container-cli --test start_scope_real --no-run
//! <target/debug/deps/start_scope_real-XXXX> --ignored
//! ```
//!
//! 成功時の最終行: `start_scope_real: supervisor ran alone in a delegated user scope; cli did not linger; prepare accepted`。
//! CI では platform-ci の ubuntu が前提確認ステップの後に、委譲スコープで包まずに直接実行する（シナリオ B の感度は
//! 試験プロセスが非委譲 cgroup にいることに依存するため。#3105）。Agent は手元のホストに transient scope と cgroup を
//! 作るため実行しない。実機の OS・カーネル版での記録は #2062。Linux 限定。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("start_scope_real: skipped (linux only)");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

// kill 後の回収を期限つきにする共有補助（#3303・REPAIR-5）。
#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/reap.rs"]
mod reap;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::{CgroupName, DelegatedCgroup};
    use fandhe_container_core::traits::ContainerId;

    /// 子プロセスを待つ上限（REPAIR-5。CLI の受信期限 58.9 秒より長く、無期限にはしない）。
    const WAIT: Duration = Duration::from_secs(90);
    const POLL: Duration = Duration::from_millis(20);

    pub fn main() -> ExitCode {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.first().map(String::as_str) == Some("start")
            && args.get(1).map(String::as_str) == Some("--root")
        {
            return probe(&args);
        }
        if !args.iter().any(|a| a == "--ignored") {
            println!(
                "start_scope_real: skipped (real-host scenario; run with `-- --ignored` on a host with `systemd-run --user`)"
            );
            return ExitCode::SUCCESS;
        }
        match scenarios() {
            Ok(()) => {
                println!(
                    "start_scope_real: supervisor ran alone in a delegated user scope; cli did not linger; prepare accepted"
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("start_scope_real: FAILED: {e}");
                ExitCode::FAILURE
            }
        }
    }

    /// `/proc/self/cgroup`（cgroup v2 の `0::<path>`）の path 部分。
    fn cgroup_of(pid: &str) -> Result<String, String> {
        let text =
            std::fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|e| e.to_string())?;
        text.lines()
            .find_map(|l| l.strip_prefix("0::"))
            .map(str::to_string)
            .ok_or_else(|| format!("no cgroup v2 line for {pid}"))
    }

    fn ppid() -> String {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|t| {
                t.lines()
                    .find_map(|l| l.strip_prefix("PPid:").map(|v| v.trim().to_string()))
            })
            .unwrap_or_default()
    }

    /// プローブ役: 観測を書いてから OK を報告する（失敗しても報告は出す。照合は親が行う）。
    fn probe(args: &[String]) -> ExitCode {
        let (Some(root), Some(id)) = (args.get(2), args.get(3)) else {
            return ExitCode::FAILURE;
        };
        let out = Path::new(root).parent().map(|p| p.join("probe.out"));
        let me = std::process::id().to_string();
        let parent = ppid();
        let own = cgroup_of("self").unwrap_or_default();
        let procs = std::fs::read_to_string(format!("/sys/fs/cgroup{own}/cgroup.procs"))
            .map(|t| t.split_whitespace().collect::<Vec<_>>().join(" "))
            .unwrap_or_default();
        let result = |r: Result<(), fandhe_container_core::cgroups::CgroupError>| match r {
            Ok(()) => "ok".to_string(),
            Err(e) => e.code.as_str().to_string(),
        };
        let (detect, prepare) = match DelegatedCgroup::detect() {
            Err(e) => (result(Err(e)), "skipped".to_string()),
            Ok(d) => {
                let prepared = ContainerId::new(id)
                    .map_err(|_| ())
                    .and_then(|cid| CgroupName::new(&cid).map_err(|_| ()))
                    .map(|name| d.prepare(&name).map(|_| ()));
                (
                    "ok".to_string(),
                    prepared.map_or("bad-id".to_string(), result),
                )
            }
        };
        if let Some(out) = out {
            let body = format!(
                "pid={me}\nppid={parent}\ncgroup={own}\nppid_cgroup={}\nprocs={procs}\ndetect={detect}\nprepare={prepare}\n",
                cgroup_of(&parent).unwrap_or_default()
            );
            let _ = std::fs::write(out, body);
        }
        println!("FCSUP1 OK {me}");
        ExitCode::SUCCESS
    }

    struct Observed(Vec<(String, String)>);

    impl Observed {
        fn load(path: &Path) -> Result<Self, String> {
            let text = std::fs::read_to_string(path).map_err(|e| format!("probe.out: {e}"))?;
            Ok(Self(
                text.lines()
                    .filter_map(|l| {
                        l.split_once('=')
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                    })
                    .collect(),
            ))
        }
        fn get(&self, key: &str) -> &str {
            self.0
                .iter()
                .find(|(k, _)| k == key)
                .map_or("", |(_, v)| v.as_str())
        }
    }

    /// 期限付きで子を回収する（超過時は kill して失敗）。
    fn wait_child(mut c: Child, what: &str) -> Result<std::process::ExitStatus, String> {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(st) = c.try_wait().map_err(|e| e.to_string())? {
                return Ok(st);
            }
            if Instant::now() >= deadline {
                super::reap::reap_or_report(&mut c, super::reap::reap_within());
                return Err(format!("{what} timed out (REPAIR-5)"));
            }
            std::thread::sleep(POLL);
        }
    }

    fn work_dir(tag: &str) -> Result<PathBuf, String> {
        use std::os::unix::fs::PermissionsExt;
        let dir = super::scratch_root::scratch_root("fc-scope-real-scratch", WAIT)
            .join(format!("fc-scope-real-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        Ok(dir)
    }

    fn scenarios() -> Result<(), String> {
        // 一時領域の親ディレクトリ（tmpfiles の掃除と flock 競合の回避）を終了時に消す（#2887）。
        let _scratch_cleanup = super::scratch_root::ScratchRootCleanup;
        let me = std::env::current_exe().map_err(|e| e.to_string())?;
        let own_cgroup = cgroup_of("self")?;
        scenario_a(&me, &own_cgroup)?;
        scenario_b(&me)
    }

    fn scenario_a(me: &Path, own_cgroup: &str) -> Result<(), String> {
        let dir = work_dir("a")?;
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).map_err(|e| e.to_string())?;
        let cli = bin.join("fandhe-container");
        let src = env!("CARGO_BIN_EXE_fandhe-container");
        std::fs::hard_link(src, &cli)
            .or_else(|_| std::fs::copy(src, &cli).map(|_| ()))
            .map_err(|e| e.to_string())?;
        let sup = bin.join("fandhe-container-supervisor");
        std::fs::hard_link(me, &sup)
            .or_else(|_| std::fs::copy(me, &sup).map(|_| ()))
            .map_err(|e| e.to_string())?;

        let bundle = dir.join("bundle");
        std::fs::create_dir_all(bundle.join("rootfs")).map_err(|e| e.to_string())?;
        std::fs::write(
            bundle.join("config.json"),
            r#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
        )
        .map_err(|e| e.to_string())?;
        let root = dir.join("state");
        let run = |args: &[&str]| -> Result<Child, String> {
            Command::new(&cli)
                .arg("--root")
                .arg(&root)
                .args(args)
                .env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())
        };
        let create = run(&["create", "--bundle", bundle.to_str().ok_or("utf8")?, "c1"])?;
        if !wait_child(create, "create")?.success() {
            return Err("create failed".into());
        }
        let mut start = run(&["start", "c1"])?;
        let cli_pid = start.id().to_string();
        let mut stderr = start.stderr.take();
        let st = wait_child(start, "start")?;
        let mut err_text = String::new();
        if let Some(e) = stderr.as_mut() {
            let _ = e.take(4096).read_to_string(&mut err_text);
        }
        if st.code() != Some(0) {
            return Err(format!("start exit {:?}: {err_text}", st.code()));
        }
        let o = Observed::load(&dir.join("probe.out"))?;
        let probe_pid = o.get("pid").to_string();
        let checks: [(&str, bool); 7] = [
            (
                "probe cgroup is a .scope",
                o.get("cgroup").ends_with(".scope"),
            ),
            (
                "probe cgroup differs from the cli's",
                o.get("cgroup") != o.get("ppid_cgroup"),
            ),
            (
                "cli stayed in the test's cgroup",
                o.get("ppid_cgroup") == own_cgroup,
            ),
            (
                "cgroup.procs is only the probe",
                o.get("procs") == probe_pid,
            ),
            (
                "parent is the cli (exec, not fork)",
                o.get("ppid") == cli_pid,
            ),
            ("detect ok", o.get("detect") == "ok"),
            ("prepare ok", o.get("prepare") == "ok"),
        ];
        for (what, ok) in checks {
            if !ok {
                return Err(format!("scenario A: {what} (observed: {:?})", o.0));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    fn scenario_b(me: &Path) -> Result<(), String> {
        let dir = work_dir("b")?;
        let root = dir.join("state");
        let child = Command::new(me)
            .arg("start")
            .arg("--root")
            .arg(&root)
            .arg("c1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        wait_child(child, "direct probe")?;
        let o = Observed::load(&dir.join("probe.out"))?;
        let rejected = |v: &str| v == "FAILED_PRECONDITION" || v == "PERMISSION_DENIED";
        if !(rejected(o.get("detect")) || rejected(o.get("prepare"))) {
            return Err(format!(
                "scenario B: a probe sharing the test's cgroup must be rejected (observed: {:?})",
                o.0
            ));
        }
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
