//! CLI の実バイナリ `fandhe-container start` のやり直しで、別プロセスの supervisor が予約を回復する通し試験
//! （#2011・CORE-2・SEC-1・OCI-6・REPAIR-12。関連: #2060・#2096・#1817）。
//!
//! 「1 回目の supervisor が報告の前に落ちた」状態（Running・pid なし・cgroup 配置あり・コンテナ cgroup に孤児の
//! `sleep`）を、試験の側で決定的に用意する（生きた supervisor をちょうどよい瞬間に SIGKILL する方法は使わない）。
//! 2 回目の `fandhe-container start` は、新しい supervisor（CLI の隣の実バイナリ）が手順 3 で
//! `recover_interrupted` を呼び、記録済みの cgroup から孤児を止めて Created へ戻し、`FAILED_PRECONDITION`
//! （終了コード 5・`an interrupted start was recovered; delete and recreate the container`）を報告する。続く
//! `fandhe-container delete` は終了コード 0 で、cgroup と `state.json` が消える。CLI は状態を書かないため、
//! CLI 側に回復の処理は要らない（回復は supervisor の手順 3）。
//!
//! # 必要環境
//! Linux・cgroup v2・非特権ユーザー・`systemd-run --user`（user マネージャと有効な `XDG_RUNTIME_DIR`）。事前に
//! `cargo build -p fandhe-container-supervisor` で、CLI の隣（`target/debug`）に `fandhe-container-supervisor` を
//! 置く。無ければ skip ではなく失敗する。root では所有者の検証が省かれるため非 root で実行する。
//!
//! # 実機前提テストとしての分離
//! `-- --ignored` 指定時のみ実行する（ci.md「実機前提テスト」）。未指定は案内を出して成功する。
//!
//! ```text
//! cargo build -p fandhe-container-supervisor
//! cargo test -p fandhe-container-cli --test start_recover_real --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/start_recover_real-XXXX> --ignored
//! ```
//!
//! 成功時の最終行: `start_recover_real: a second cli start recovered the interrupted reservation from the recorded cgroup; delete then removed it`。
//! 実行と結果の記録は人間担当（#2062 等）。本試験は作成時に未実行で、Agent はホストに cgroup を作るため実行しない。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("start_recover_real: skipped (linux only)");
}

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitCode, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use fandhe_container_core::cgroups::{CgroupName, DelegatedCgroup};
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};
    use fandhe_container_core::traits::{
        CgroupScope, ContainerId, ContainerState, ContainerStatus, CreateStateRequest,
        GetStateRequest, StateStore, UpdateStateRequest,
    };

    /// CLI を待つ上限（REPAIR-5）。
    const CHILD_TIMEOUT: Duration = Duration::from_secs(60);
    /// kill 後の回収・出力収集の上限（REPAIR-5）。
    const REAP_TIMEOUT: Duration = Duration::from_secs(10);
    const POLL: Duration = Duration::from_millis(20);

    pub fn main() -> ExitCode {
        if !std::env::args().skip(1).any(|a| a == "--ignored") {
            println!(
                "start_recover_real: skipped (real-host scenario; run with `-- --ignored` inside a delegated cgroup, e.g. `systemd-run --user --scope -p Delegate=yes`)"
            );
            return ExitCode::SUCCESS;
        }
        match scenario() {
            Ok(()) => {
                println!(
                    "start_recover_real: a second cli start recovered the interrupted reservation from the recorded cgroup; delete then removed it"
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("start_recover_real: FAILED: {e}");
                ExitCode::FAILURE
            }
        }
    }

    /// 子を kill し、`REAP_TIMEOUT` 内に `try_wait` で回収する（無期限の `wait` を避ける。REPAIR-5）。
    /// 期限内に回収できなければエラーを返す。
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

    /// 後始末（孤児・cgroup・状態ルート）を Drop で保証する。
    struct Cleanup {
        sleeper: Option<Child>,
        dirs: Vec<PathBuf>,
        root: PathBuf,
    }

    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(mut c) = self.sleeper.take()
                && let Err(e) = kill_and_reap(&mut c)
            {
                eprintln!("start_recover_real: cleanup failed: {e}");
            }
            for d in self.dirs.iter().rev() {
                let _ = fs::remove_dir(d);
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn scenario() -> Result<(), String> {
        // 一時領域の親ディレクトリ（tmpfiles の掃除と flock 競合の回避）を終了時に消す（#2887）。
        let _scratch_cleanup = super::scratch_root::ScratchRootCleanup;
        if effective_uid()? == 0 {
            return Err("must run as a non-root user: owner checks are skipped for root".into());
        }
        let cli = PathBuf::from(env!("CARGO_BIN_EXE_fandhe-container"));
        let supervisor = cli
            .parent()
            .map(|d| d.join("fandhe-container-supervisor"))
            .ok_or("cli has no parent directory")?;
        if !supervisor.is_file() {
            return Err(format!(
                "{} is missing; run `cargo build -p fandhe-container-supervisor` first",
                supervisor.display()
            ));
        }
        let delegated = DelegatedCgroup::detect().map_err(|e| format!("detect: {e:?}"))?;
        let base = PathBuf::from("/sys/fs/cgroup").join(delegated.path().trim_start_matches('/'));
        let scope_name = format!("rec-{}", std::process::id());
        let scope_dir = base.join(&scope_name);
        fs::create_dir(&scope_dir).map_err(|e| format!("mkdir scope: {e}"))?;
        let recorded = format!("{}/{}", delegated.path().trim_end_matches('/'), scope_name);

        let id =
            ContainerId::new(format!("sr{}", std::process::id())).map_err(|e| format!("{e:?}"))?;
        let root = super::scratch_root::scratch_root("fandhe-start-recover-scratch", CHILD_TIMEOUT)
            .join(format!("fandhe-start-recover-{}", id.as_str()));
        let _ = fs::remove_dir_all(&root);
        let mut cleanup = Cleanup {
            sleeper: None,
            dirs: vec![scope_dir.clone()],
            root: root.clone(),
        };
        fs::create_dir_all(root.join("bundle")).map_err(|e| format!("mkdir: {e}"))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("chmod: {e}"))?;

        // 1 回目の supervisor が報告の前に落ちた状態を作る。
        let store = open_store(&root)?;
        let req = CreateStateRequest::new(
            ContainerStatus::created(id.clone(), None),
            root.join("bundle"),
        )
        .map_err(|e| format!("req: {e:?}"))?
        .with_cgroup_scope(CgroupScope::new(&recorded).map_err(|e| format!("scope: {e:?}"))?);
        let record = store.create(&req).map_err(|e| format!("create: {e:?}"))?;
        let placement = record.cgroup().ok_or("record has no placement")?;
        let name = CgroupName::for_instance(&id, placement.instance())
            .map_err(|e| format!("name: {e:?}"))?;
        let cgroup = scope_dir.join(name.as_str());
        fs::create_dir(&cgroup).map_err(|e| format!("mkdir cgroup: {e}"))?;
        cleanup.dirs.push(cgroup.clone());
        let sleeper = Command::new("/bin/sleep")
            .arg("120")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn sleep: {e}"))?;
        let spid = sleeper.id();
        cleanup.sleeper = Some(sleeper);
        fs::write(cgroup.join("cgroup.procs"), spid.to_string())
            .map_err(|e| format!("move sleep: {e}"))?;
        store
            .update(&UpdateStateRequest::new(
                ContainerStatus::running(id.clone(), None),
                record.revision(),
            ))
            .map_err(|e| format!("reserve: {e:?}"))?;
        drop(store);

        // 2 回目の start（別プロセスの新しい supervisor）。
        let root_s = root.to_string_lossy().into_owned();
        let out = run_cli(&cli, &["--root", &root_s, "start", id.as_str()])?;
        if out.code != Some(5) {
            return Err(format!(
                "start: want exit 5, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        let all = format!("{}{}", out.stdout, out.stderr);
        for want in [
            "FAILED_PRECONDITION",
            "an interrupted start was recovered; delete and recreate the container",
        ] {
            if !all.contains(want) {
                return Err(format!("start output lacks {want:?}: {all:?}"));
            }
        }
        let store = open_store(&root)?;
        let state = store
            .get(&GetStateRequest::new(id.clone()))
            .map_err(|e| format!("get: {e:?}"))?
            .status()
            .state();
        if state != ContainerState::Created {
            return Err(format!("state after recovery: want Created, got {state:?}"));
        }
        drop(store);
        let reaped = {
            let deadline = Instant::now() + REAP_TIMEOUT;
            let mut gone = false;
            while Instant::now() < deadline {
                let alive = cleanup
                    .sleeper
                    .as_mut()
                    .map(|c| matches!(c.try_wait(), Ok(None)))
                    .unwrap_or(false);
                if !alive {
                    gone = true;
                    break;
                }
                thread::sleep(POLL);
            }
            gone
        };
        if !reaped {
            return Err("the orphan sleep process was not stopped".into());
        }

        // 続く delete で cgroup と状態記録が消える。
        let out = run_cli(&cli, &["--root", &root_s, "delete", id.as_str()])?;
        if out.code != Some(0) || !out.stdout.is_empty() {
            return Err(format!(
                "delete: want exit 0, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        if cgroup.exists() {
            return Err("container cgroup remains after delete".into());
        }
        if root.join(id.as_str()).join("state.json").exists() {
            return Err("state.json remains after delete".into());
        }
        Ok(())
    }

    fn open_store(root: &Path) -> Result<FileStateStore, String> {
        let root =
            StateRoot::from_override(root.to_path_buf()).map_err(|e| format!("root: {e:?}"))?;
        FileStateStore::open(root).map_err(|e| format!("open store: {e:?}"))
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

    /// 実バイナリを有限期限内で実行する（REPAIR-5）。
    fn run_cli(cli: &Path, args: &[&str]) -> Result<RunOut, String> {
        let mut child = Command::new(cli)
            .args(args)
            .env_remove("FANDHE_CONTAINER_PLUGIN_PATH_SEARCH")
            .env_remove("FANDHE_CONTAINER_OP_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn cli: {e}"))?;
        let out_rx = spawn_reader(child.stdout.take().ok_or("stdout not piped")?);
        let err_rx = spawn_reader(child.stderr.take().ok_or("stderr not piped")?);
        let deadline = Instant::now() + CHILD_TIMEOUT;
        let status = loop {
            match child.try_wait().map_err(|e| format!("poll cli: {e}"))? {
                Some(s) => break s,
                None if Instant::now() >= deadline => {
                    return Err(match kill_and_reap(&mut child) {
                        Ok(()) => format!("cli did not exit within {CHILD_TIMEOUT:?}"),
                        Err(e) => format!("cli did not exit within {CHILD_TIMEOUT:?}; {e}"),
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
}
