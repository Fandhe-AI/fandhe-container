//! CLI の実バイナリ `fandhe-container delete` が、実際の委譲 cgroup 上でコンテナ cgroup と状態記録を消す
//! 通し試験（#2061・OCI-6・CORE-3・SEC-1・REPAIR-12。関連: TASK-79 追補・#2096・#2060・#1544・#1477・#1716）。
//!
//! 既存の試験が確かめていない経路を受け持つ。CLI の単体テスト（`stop_delete.rs`）はフェイクの remover と検出で、
//! core の実機試験（`cgroup_delete*.rs`）は `oci_runtime::delete` を直接呼んで照合している。本試験は実バイナリが
//! 自分の cgroup から `DelegatedCgroup::detect` で検出し（`DetectedCgroupRemover`）、記録のスコープと照合して
//! `fc-<id>@<n>` を消すまでを、子プロセスとして通しで確かめる。
//!
//! # 状態の準備
//! 本番の `start` は使わず、試験の側で状態記録（`FileStateStore`）と子 cgroup を用意する。理由は 3 つ。
//! (1) 本番の `start` は supervisor を新しい transient scope で起動し、CLI の隣に supervisor の bin を置く必要があり、
//! 本番の rootless `start` が委譲 cgroup の準備で拒否されないかは #2062（人間担当）の確認事項である。
//! (2) `start` 直後のレコードは Running で、Stopped への遷移は supervisor（TASK-157）の範囲であり、`delete` は
//! Running を `FAILED_PRECONDITION` で拒否する。(3) 本試験の対象は `delete` の経路に限る（`start` は `start_scope_real`）。
//!
//! # 照合項目（#2060 の決定と #2096 の検証を反映）
//! - シナリオ A（一致）: 記録のスコープが検出スコープと同じ。終了コード 0・出力なし。`fc-<id>@<n>` と `state.json` が
//!   消え、2 回目は終了コード 3 の `op=delete`・`code=NOT_FOUND`
//! - シナリオ B（空でない）: 子 cgroup の `cgroup.procs` に `sleep` がいる。何も kill せず終了コード 5・
//!   `code=FAILED_PRECONDITION`。`sleep` は生存、cgroup と状態記録は残る。`sleep` を止めた後の再試行は成功する
//! - シナリオ C（別スコープ）: 記録のスコープが検出スコープの子 `rec-<pid>`（文字列が異なる）。#2096 の検証
//!   （所有者 = euid・`cgroup.type`・instance の名前・子が空）を通り、`rec-<pid>` 配下の子 cgroup と状態記録が消え、
//!   `rec-<pid>` 自身は残る
//! - シナリオ D（スコープが既に無い）: 記録のスコープのディレクトリが無い（systemd が回収した後の状態）。
//!   `NotPresent` として閉じ、終了コード 0 で状態記録が消える
//!
//! # 必要環境
//! Linux・cgroup v2・非特権ユーザーに委譲された cgroup v2 サブツリー（`systemd-run --user`。user マネージャと有効な
//! `XDG_RUNTIME_DIR`）。root では所有者の検証が省かれ照合の意味が変わるため、非 root で実行する。
//!
//! # 実機前提テストとしての分離
//! GitHub ホステッド runner では委譲 cgroup を前提にできないため、`-- --ignored` 指定時のみ実行する（ci.md
//! 「実機前提テスト」。既定集合の試験を移したものではない。既定集合ではフェイクの remover を使う `stop_delete.rs` の
//! 単体テストが照合する）。実行された場合は、前提が欠けていても失敗として扱い、検証せずに成功する分岐は持たない。
//!
//! ```text
//! cargo test -p fandhe-container-cli --test delete_cgroup_real --no-run
//! systemd-run --user --scope -p Delegate=yes <target/debug/deps/delete_cgroup_real-XXXX> --ignored
//! ```
//!
//! 成功時の最終行: `delete_cgroup_real: cli delete removed the container cgroup and state for matching, recorded and vanished scopes; refused a non-empty cgroup without killing`。
//! 実行と結果の記録は人間担当（#2062）。本試験は作成時に未実行で、Agent はホストに cgroup を作るため実行しない。

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("delete_cgroup_real: skipped (linux only)");
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
        CgroupScope, ContainerId, ContainerStatus, CreateStateRequest, GetStateRequest, StateStore,
    };

    /// CLI を待つ上限（REPAIR-5）。
    const CHILD_TIMEOUT: Duration = Duration::from_secs(30);
    /// kill 後の回収・出力収集の上限（REPAIR-5）。
    const REAP_TIMEOUT: Duration = Duration::from_secs(10);
    /// `cgroup.procs` が空になるのを待つ上限（REPAIR-5）。
    const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
    const POLL: Duration = Duration::from_millis(20);

    pub fn main() -> ExitCode {
        if !std::env::args().skip(1).any(|a| a == "--ignored") {
            println!(
                "delete_cgroup_real: skipped (real-host scenario; run with `-- --ignored` inside a delegated cgroup, e.g. `systemd-run --user --scope -p Delegate=yes`)"
            );
            return ExitCode::SUCCESS;
        }
        // 一時領域の親ディレクトリ（tmpfiles の掃除と flock 競合の回避）を終了時に消す（#2887）。
        let _scratch_cleanup = super::scratch_root::ScratchRootCleanup;
        match scenarios() {
            Ok(()) => {
                println!(
                    "delete_cgroup_real: cli delete removed the container cgroup and state for matching, recorded and vanished scopes; refused a non-empty cgroup without killing"
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("delete_cgroup_real: FAILED: {e}");
                ExitCode::FAILURE
            }
        }
    }

    fn scenarios() -> Result<(), String> {
        // root では所有者検証が省かれ、非特権委譲の証跡にならない。cgroup や状態ルートを作る前に拒否する（REPAIR-12）。
        let euid = effective_uid()?;
        if euid == 0 {
            return Err(
                "must run as a non-root user: owner checks are skipped for root, so results would not prove unprivileged delegation"
                    .to_string(),
            );
        }
        let delegated = DelegatedCgroup::detect().map_err(|e| format!("detect: {e:?}"))?;
        let detected = delegated.path().to_string();
        let own = own_cgroup()?;
        if own != detected {
            return Err(format!(
                "detected path {detected:?} differs from /proc/self/cgroup {own:?}"
            ));
        }
        let base = PathBuf::from("/sys/fs/cgroup").join(detected.trim_start_matches('/'));
        scenario_a(&detected, &base)?;
        scenario_b(&detected, &base)?;
        scenario_c(&detected, &base)?;
        scenario_d(&detected)?;
        Ok(())
    }

    /// 1 シナリオの作業場。Drop で自分が作った cgroup・状態ルート・`sleep` を後始末する。
    struct Fixture {
        id: ContainerId,
        root: PathBuf,
        /// 自分が作った cgroup ディレクトリ（積んだ順の逆に消す）。
        dirs: Vec<PathBuf>,
        sleeper: Option<Child>,
    }

    impl Fixture {
        /// 状態ルート（0700）と Stopped の状態記録（`recorded` のスコープ・cgroup 配置つき）を作る。
        /// 返す `PathBuf` は子 cgroup `fc-<id>@<n>` のパス（作成は呼び出し側）。
        fn new(tag: &str, recorded: &str, scope_dir: &Path) -> Result<(Self, PathBuf), String> {
            let pid = std::process::id();
            let id = ContainerId::new(format!("{tag}{pid}")).map_err(|e| format!("id: {e:?}"))?;
            let root = super::scratch_root::scratch_root(
                "fandhe-delete-real-scratch",
                Duration::from_secs(10),
            )
            .join(format!("fandhe-delete-real-{}", id.as_str()));
            let _ = fs::remove_dir_all(&root);
            // 以降のどこで失敗しても Drop が状態ルートを片付けるよう、作成前に Fixture を組む。
            let fixture = Self {
                id: id.clone(),
                root: root.clone(),
                dirs: Vec::new(),
                sleeper: None,
            };
            fs::create_dir_all(&root).map_err(|e| format!("mkdir root: {e}"))?;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("chmod root: {e}"))?;
            let store = open_store(&root)?;
            let req = CreateStateRequest::new(
                ContainerStatus::stopped(id.clone(), Some(0)),
                root.join("bundle"),
            )
            .map_err(|e| format!("req: {e:?}"))?
            .with_cgroup_scope(CgroupScope::new(recorded).map_err(|e| format!("scope: {e:?}"))?);
            let record = store.create(&req).map_err(|e| format!("create: {e:?}"))?;
            let placement = record.cgroup().ok_or("record has no cgroup placement")?;
            let name = CgroupName::for_instance(&id, placement.instance())
                .map_err(|e| format!("name: {e:?}"))?;
            let cgroup = scope_dir.join(name.as_str());
            // CLI を起動する前にストアを閉じる。
            drop(store);
            Ok((fixture, cgroup))
        }

        fn state_json(&self) -> PathBuf {
            self.root.join(self.id.as_str()).join("state.json")
        }

        /// `fandhe-container --root <root> delete <id>` を実行する。
        fn delete(&self) -> Result<RunOut, String> {
            let root = self.root.to_string_lossy().into_owned();
            run_cli(&["--root", &root, "delete", self.id.as_str()])
        }

        /// 記録のスコープ・instance が変わっていないこと。
        fn check_record(&self, scope: &str, cgroup: &Path) -> Result<(), String> {
            let store = open_store(&self.root)?;
            let record = store
                .get(&GetStateRequest::new(self.id.clone()))
                .map_err(|e| format!("get: {e:?}"))?;
            let placement = record.cgroup().ok_or("record lost its placement")?;
            if placement.scope().as_str() != scope {
                return Err(format!(
                    "recorded scope changed: {:?}",
                    placement.scope().as_str()
                ));
            }
            let want = CgroupName::for_instance(&self.id, placement.instance())
                .map_err(|e| format!("name: {e:?}"))?;
            if cgroup.file_name().and_then(|n| n.to_str()) != Some(want.as_str()) {
                return Err(format!("instance changed: {:?}", want.as_str()));
            }
            Ok(())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(mut c) = self.sleeper.take()
                && let Err(e) = kill_and_reap(&mut c)
            {
                eprintln!("delete_cgroup_real: cleanup incomplete: {e}");
            }
            for d in self.dirs.iter().rev() {
                let _ = fs::remove_dir(d);
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    /// 子を kill し、`REAP_TIMEOUT` 内に回収する。回収できなければ待ち続けずエラーにする（REPAIR-5）。
    fn kill_and_reap(child: &mut Child) -> Result<(), String> {
        let _ = child.kill();
        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return Ok(()),
                Ok(None) if Instant::now() >= deadline => {
                    return Err(format!(
                        "child {} was not reaped within {REAP_TIMEOUT:?}; it may be left behind",
                        child.id()
                    ));
                }
                Ok(None) => thread::sleep(POLL),
                Err(e) => return Err(format!("reap child {}: {e}", child.id())),
            }
        }
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

    /// 記録スコープ用に作ったディレクトリを Drop で消す。`Fixture` より先に宣言し、後に Drop させる。
    struct ScopeGuard(PathBuf);

    impl Drop for ScopeGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn open_store(root: &Path) -> Result<FileStateStore, String> {
        let root =
            StateRoot::from_override(root.to_path_buf()).map_err(|e| format!("root: {e:?}"))?;
        FileStateStore::open(root).map_err(|e| format!("open store: {e:?}"))
    }

    fn own_cgroup() -> Result<String, String> {
        let text = fs::read_to_string("/proc/self/cgroup").map_err(|e| e.to_string())?;
        text.lines()
            .find_map(|l| l.strip_prefix("0::"))
            .map(str::to_string)
            .ok_or_else(|| "no cgroup v2 line in /proc/self/cgroup".to_string())
    }

    fn expect(cond: bool, what: &str) -> Result<(), String> {
        if cond { Ok(()) } else { Err(what.to_string()) }
    }

    fn expect_clean_success(out: &RunOut, what: &str) -> Result<(), String> {
        if out.code != Some(0) || !out.stdout.is_empty() || !out.stderr.is_empty() {
            return Err(format!(
                "{what}: want exit 0 with no output, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        Ok(())
    }

    /// 終了コードと、stderr の 1 行 JSON の `op`・`code` を照合する。
    fn expect_failure(out: &RunOut, exit: i32, code: &str, what: &str) -> Result<(), String> {
        if out.code != Some(exit) || !out.stdout.is_empty() {
            return Err(format!(
                "{what}: want exit {exit}, got {:?} stdout={:?} stderr={:?}",
                out.code, out.stdout, out.stderr
            ));
        }
        let (op, got) = op_and_code(&out.stderr)?;
        if op != "delete" || got != code {
            return Err(format!(
                "{what}: want op=delete code={code}, got op={op} code={got}"
            ));
        }
        Ok(())
    }

    fn scenario_a(detected: &str, base: &Path) -> Result<(), String> {
        let (mut fx, cgroup) = Fixture::new("dm", detected, base)?;
        fs::create_dir(&cgroup).map_err(|e| format!("A: mkdir cgroup: {e}"))?;
        fx.dirs.push(cgroup.clone());
        expect(
            fx.state_json().is_file(),
            "A: state.json must exist before delete",
        )?;

        expect_clean_success(&fx.delete()?, "A: delete")?;
        expect(!cgroup.exists(), "A: container cgroup remains")?;
        expect(!fx.state_json().exists(), "A: state.json remains")?;
        expect(
            !fx.root.join(fx.id.as_str()).exists(),
            "A: state dir remains",
        )?;
        expect_failure(&fx.delete()?, 3, "NOT_FOUND", "A: second delete")
    }

    fn scenario_b(detected: &str, base: &Path) -> Result<(), String> {
        let (mut fx, cgroup) = Fixture::new("db", detected, base)?;
        fs::create_dir(&cgroup).map_err(|e| format!("B: mkdir cgroup: {e}"))?;
        fx.dirs.push(cgroup.clone());
        let sleeper = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("B: spawn sleep: {e}"))?;
        let spid = sleeper.id();
        fx.sleeper = Some(sleeper);
        let procs = cgroup.join("cgroup.procs");
        fs::write(&procs, spid.to_string()).map_err(|e| format!("B: move sleep: {e}"))?;
        expect(
            read_procs(&procs)? == vec![spid],
            "B: sleep must be in the cgroup",
        )?;

        expect_failure(&fx.delete()?, 5, "FAILED_PRECONDITION", "B: delete")?;
        let alive = fx
            .sleeper
            .as_mut()
            .map(|c| matches!(c.try_wait(), Ok(None)))
            .unwrap_or(false);
        expect(alive, "B: delete must not kill the member process")?;
        expect(read_procs(&procs)? == vec![spid], "B: cgroup.procs changed")?;
        expect(cgroup.is_dir(), "B: container cgroup was removed")?;
        expect(fx.state_json().is_file(), "B: state.json was removed")?;
        fx.check_record(detected, &cgroup)?;

        // 後始末を兼ねた再試行: メンバーを止めて空になれば消せる。
        if let Some(mut c) = fx.sleeper.take() {
            kill_and_reap(&mut c).map_err(|e| format!("B: {e}"))?;
        }
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        while !read_procs(&procs)?.is_empty() {
            if Instant::now() >= deadline {
                return Err("B: cgroup.procs did not drain".to_string());
            }
            thread::sleep(POLL);
        }
        expect_clean_success(&fx.delete()?, "B: retry delete")?;
        expect(!cgroup.exists(), "B: cgroup remains after retry")?;
        expect(
            !fx.state_json().exists(),
            "B: state.json remains after retry",
        )
    }

    fn scenario_c(detected: &str, base: &Path) -> Result<(), String> {
        let scope_name = format!("rec-{}", std::process::id());
        let recorded = format!("{}/{}", detected.trim_end_matches('/'), scope_name);
        expect(
            recorded != detected,
            "C: recorded scope must differ from detected",
        )?;
        let scope_dir = base.join(&scope_name);
        fs::create_dir(&scope_dir).map_err(|e| format!("C: mkdir scope: {e}"))?;
        // 作成直後に後始末を保証する（`fx` より先に宣言するので後に Drop される）。
        let _scope_guard = ScopeGuard(scope_dir.clone());
        let (mut fx, cgroup) = Fixture::new("dr", &recorded, &scope_dir)?;
        fs::create_dir(&cgroup).map_err(|e| format!("C: mkdir cgroup: {e}"))?;
        fx.dirs.push(cgroup.clone());

        expect_clean_success(&fx.delete()?, "C: delete")?;
        expect(
            !cgroup.exists(),
            "C: container cgroup under recorded scope remains",
        )?;
        expect(scope_dir.is_dir(), "C: recorded scope itself must remain")?;
        expect(!fx.state_json().exists(), "C: state.json remains")?;
        expect_failure(&fx.delete()?, 3, "NOT_FOUND", "C: second delete")
    }

    fn scenario_d(detected: &str) -> Result<(), String> {
        let gone = format!(
            "{}/gone-{}",
            detected.trim_end_matches('/'),
            std::process::id()
        );
        let missing = PathBuf::from("/sys/fs/cgroup").join(gone.trim_start_matches('/'));
        expect(!missing.exists(), "D: vanished scope must not exist")?;
        let (fx, _cgroup) = Fixture::new("dg", &gone, &missing)?;
        expect(
            fx.state_json().is_file(),
            "D: state.json must exist before delete",
        )?;

        expect_clean_success(&fx.delete()?, "D: delete")?;
        expect(!fx.state_json().exists(), "D: state.json remains")?;
        expect(
            !fx.root.join(fx.id.as_str()).exists(),
            "D: state dir remains",
        )
    }

    fn read_procs(path: &Path) -> Result<Vec<u32>, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        Ok(text
            .split_whitespace()
            .filter_map(|t| t.parse().ok())
            .collect())
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

    /// 実バイナリを有限期限内で実行する（REPAIR-5）。子は試験プロセスと同じ cgroup に属する。
    fn run_cli(args: &[&str]) -> Result<RunOut, String> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_fandhe-container"))
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
                    let _ = child.kill();
                    let reap = Instant::now() + REAP_TIMEOUT;
                    while Instant::now() < reap {
                        if matches!(child.try_wait(), Ok(Some(_))) {
                            break;
                        }
                        thread::sleep(POLL);
                    }
                    return Err(format!("cli did not exit within {CHILD_TIMEOUT:?}"));
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

    /// stderr がちょうど 1 行の JSON であることを確かめ、`op` と `code` を取り出す。
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
            let len = stderr[start..]
                .find('"')
                .ok_or_else(|| format!("unterminated {key} in {stderr:?}"))?;
            Ok(stderr[start..start + len].to_string())
        };
        Ok((field("op")?, field("code")?))
    }
}
