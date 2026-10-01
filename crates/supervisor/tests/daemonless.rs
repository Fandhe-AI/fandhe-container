//! supervisor のデーモンレス確認テスト（TASK-28.2・#146・CORE-1・D-19・SUP-1・MS-2・REPAIR-12）。
//!
//! コンテナ 1 個の稼働中は監視プロセスがちょうど 1 個だけ存在し、コンテナ終了後はそれも含めて
//! fandhe-container 由来のプロセスが 0 個になることを、プロセス一覧（`/proc` の全走査）で照合する。
//! 既存の `run.rs`（TASK-157.8）は親が持つ `Child` ハンドルの回収で終了を確認するが、本ファイルは
//! ハンドルで追えない常駐プロセス（double fork・`setsid`）も検出できる点を補う。作成前の n=0 と
//! `created` 存在中の n=0 は `crates/core/tests/daemonless.rs` が担当する。
//!
//! 判定方法: nonce を環境変数 `FANDHE_SUP_DAEMONLESS_PROBE` として役割プロセスに与え（子孫へ継承される）、
//! `/proc/<pid>/environ` の完全一致で pid を集める。陰性対照は core 側テストが担うが、本ファイルでも
//! 稼働中に 2 件（supervisor 役・コンテナ役）を具体の pid で検出することで空振り合格を防ぐ（REPAIR-12）。
//!
//! 検証範囲と非範囲（REPAIR-3）: supervisor の本番バイナリ入口と core の本番 `ProcessLauncher` は未提供のため、
//! 役割プロセスはテストバイナリの再実行による代役である。SUP-1 の実機計測は TASK-45・47・49 の担当。
//! 走査補助は別 crate のテストと共有できないため core 側と同等のものを複製している。root 不要で
//! 既定のテスト集合で動く。

/// `environ`（NUL 区切りの `KEY=VALUE` 列）に `KEY=nonce` が完全一致で含まれるかを判定する。OS 非依存。
fn environ_has_marker(environ: &[u8], key: &str, nonce: &str) -> bool {
    let want = format!("{key}={nonce}");
    environ.split(|b| *b == 0).any(|e| e == want.as_bytes())
}

/// CORE-1・D-19: マーカー判定は完全一致のみ（前方一致・別キー・空入力は不一致）。
#[test]
fn sup1_task28_2_environ_marker_matching_is_exact() {
    let key = "FANDHE_SUP_DAEMONLESS_PROBE";
    assert!(environ_has_marker(
        b"A=1\0FANDHE_SUP_DAEMONLESS_PROBE=n1\0B=2\0",
        key,
        "n1"
    ));
    assert!(!environ_has_marker(
        b"FANDHE_SUP_DAEMONLESS_PROBE=n1x\0",
        key,
        "n1"
    ));
    assert!(!environ_has_marker(b"OTHER=n1\0", key, "n1"));
    assert!(!environ_has_marker(b"", key, "n1"));
}

#[cfg(target_os = "linux")]
mod linux {
    use super::environ_has_marker;

    use std::fs;
    use std::io::Read;
    use std::num::NonZeroU32;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, ContainerStatus, CreateStateRequest, ErrorCode, StateStore,
        SupervisionState, TraitError,
    };
    use fandhe_container_supervisor::run::{MonitorConfig, MonitorOutcome, StopToken, monitor};
    use fandhe_container_supervisor::state::{SupervisedState, open_default_store};

    const PROBE: &str = "FANDHE_SUP_DAEMONLESS_PROBE";
    const ENV_ROOT: &str = "FANDHE_SUP_DAEMONLESS_ROOT";
    const ENV_ID: &str = "FANDHE_SUP_DAEMONLESS_ID";
    const ENV_GO: &str = "FANDHE_SUP_DAEMONLESS_GO";
    const ENV_ROLE: &str = "FANDHE_SUP_DAEMONLESS_ROLE";

    /// コンテナ役が最終的に返す終了コード（具体値で照合する）。
    const CONTAINER_EXIT: i32 = 3;
    /// 期限つき待機の上限（REPAIR-5）。
    const DEADLINE: Duration = Duration::from_secs(10);
    const POLL: Duration = Duration::from_millis(10);
    /// コンテナ役がマーカー待ちを諦める上限。超過時は終了コード 99 で終わる。
    const CHILD_WAIT: Duration = Duration::from_secs(8);
    /// `environ` 1 件あたりの読み取り上限（無制限確保をしない）。
    const ENVIRON_LIMIT: u64 = 1 << 20;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique(tag: &str) -> String {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{tag}-{}-{n}-{t}", std::process::id())
    }

    /// `/proc` を全走査し、nonce つきの環境を持つ pid を昇順で返す。
    ///
    /// 消えたプロセス・他ユーザーのプロセスは読み飛ばし、それ以外の I/O エラーは panic する。
    /// 出力へ環境内容は含めない。
    fn scan_marked(nonce: &str) -> Vec<u32> {
        let mut pids = Vec::new();
        for ent in fs::read_dir("/proc").expect("read /proc") {
            let ent = ent.expect("read /proc entry");
            let Some(pid) = ent.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            let f = match fs::File::open(ent.path().join("environ")) {
                Ok(f) => f,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue;
                }
                Err(e) => panic!("open environ of pid {pid}: {e}"),
            };
            let mut buf = Vec::new();
            match f.take(ENVIRON_LIMIT).read_to_end(&mut buf) {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(3) => continue, // ESRCH
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => continue,
                Err(e) => panic!("read environ of pid {pid}: {e}"),
            }
            if environ_has_marker(&buf, PROBE, nonce) {
                pids.push(pid);
            }
        }
        pids.sort_unstable();
        pids
    }

    /// 期限つきで条件を待つ（無限待ちを作らない。REPAIR-5）。
    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let end = Instant::now() + DEADLINE;
        while !cond() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            std::thread::sleep(POLL);
        }
    }

    fn internal(msg: &'static str) -> TraitError {
        TraitError::new(ErrorCode::Internal, msg)
    }

    /// 実プロセスを [`LaunchedProcess`] として扱うアダプタ。`Drop` で kill + 回収する。
    struct ChildProcess {
        pid: NonZeroU32,
        child: Mutex<Child>,
    }

    impl ChildProcess {
        fn new(child: Child) -> Self {
            let pid = NonZeroU32::new(child.id()).expect("child pid must be non-zero");
            Self {
                pid,
                child: Mutex::new(child),
            }
        }
    }

    fn map_exit(status: std::process::ExitStatus) -> Result<ProcessExit, TraitError> {
        if let Some(code) = status.code() {
            return Ok(ProcessExit::Exited(code));
        }
        use std::os::unix::process::ExitStatusExt;
        status
            .signal()
            .map(ProcessExit::Signaled)
            .ok_or_else(|| internal("unrecognized exit status"))
    }

    impl LaunchedProcess for ChildProcess {
        fn pid(&self) -> NonZeroU32 {
            self.pid
        }

        fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
            let end = Instant::now() + timeout;
            loop {
                {
                    let mut c = self
                        .child
                        .lock()
                        .map_err(|_| internal("child lock poisoned"))?;
                    if let Some(s) = c.try_wait().map_err(|_| internal("try_wait failed"))? {
                        return map_exit(s).map(Some);
                    }
                }
                if Instant::now() >= end {
                    return Ok(None);
                }
                std::thread::sleep(POLL);
            }
        }

        fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
            {
                let mut c = self
                    .child
                    .lock()
                    .map_err(|_| internal("child lock poisoned"))?;
                let _ = c.kill();
            }
            match self.wait(timeout)? {
                Some(_) => Ok(()),
                None => Err(TraitError::new(ErrorCode::Timeout, "terminate timed out")),
            }
        }
    }

    impl Drop for ChildProcess {
        fn drop(&mut self) {
            if let Ok(c) = self.child.get_mut() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    /// テスト用一時ディレクトリ（0700。drop で削除）。状態ルートは `state/`、マーカーは `go`。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let p = std::env::temp_dir().join(format!("fandhe-sup-daemonless-{}", unique(tag)));
            fs::create_dir_all(p.join("state")).expect("mkdir");
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod");
            fs::set_permissions(p.join("state"), fs::Permissions::from_mode(0o700)).expect("chmod");
            Self(p)
        }
        fn root(&self) -> PathBuf {
            self.0.join("state")
        }
        fn go(&self) -> PathBuf {
            self.0.join("go")
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// drop 時にマーカーを作ってコンテナ役を終了させる（assert 失敗時も孤児を残さない。REPAIR-5）。
    struct Release(PathBuf);

    impl Release {
        fn fire(&self) {
            let _ = fs::write(&self.0, b"");
        }
    }

    impl Drop for Release {
        fn drop(&mut self) {
            self.fire();
        }
    }

    fn cid(s: &str) -> ContainerId {
        ContainerId::new(s).expect("container id")
    }

    fn open(root: &Path) -> Arc<dyn StateStore> {
        open_default_store(Some(root.to_path_buf())).expect("open store")
    }

    fn reread(root: &Path, id: &str) -> SupervisedState {
        SupervisedState::attach(open(root), cid(id)).expect("attach")
    }

    /// 役割プロセス（テストバイナリ自身の再実行）の起動コマンド。
    fn role_command(nonce: &str, test: &str) -> Command {
        let mut cmd = Command::new(std::env::current_exe().expect("current_exe"));
        cmd.args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env(PROBE, nonce)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }

    /// コンテナ役。環境変数が無ければ no-op。マーカーが現れるまで待ち、`CONTAINER_EXIT` で終了する。
    #[test]
    fn child_container_role() {
        let Ok(go) = std::env::var(ENV_GO) else {
            return;
        };
        if std::env::var(ENV_ROLE).as_deref() != Ok("container") {
            return;
        }
        let end = Instant::now() + CHILD_WAIT;
        while !Path::new(&go).exists() {
            if Instant::now() >= end {
                std::process::exit(99);
            }
            std::thread::sleep(POLL);
        }
        std::process::exit(CONTAINER_EXIT);
    }

    /// supervisor 役。環境変数が無ければ no-op。将来の入口と同じ順序で、コンテナ役（孫）を起動して
    /// `Running` へ更新し、`attach` して `monitor` を実行、`Exited` を確認して戻る（= プロセス終了）。
    #[test]
    fn child_supervisor_role() {
        let (Ok(root), Ok(id), Ok(go), Ok("supervisor")) = (
            std::env::var(ENV_ROOT),
            std::env::var(ENV_ID),
            std::env::var(ENV_GO),
            std::env::var(ENV_ROLE).as_deref(),
        ) else {
            return;
        };
        let nonce = std::env::var(PROBE).expect("probe env");
        let root = PathBuf::from(root);
        let mut cmd = role_command(&nonce, "linux::child_container_role");
        cmd.env(ENV_GO, &go).env(ENV_ROLE, "container");
        let child = ChildProcess::new(cmd.spawn().expect("spawn container role"));
        let mut state = SupervisedState::attach(open(&root), cid(&id)).expect("attach");
        state
            .write(
                ContainerStatus::running(cid(&id), Some(child.pid())),
                SupervisionState::new(None, None, 0),
            )
            .expect("mark running");
        let cfg = MonitorConfig::new(Duration::from_millis(20)).expect("config");
        match monitor(&mut state, &child, &cfg, &StopToken::new()).expect("monitor") {
            MonitorOutcome::Exited { exit, .. } => {
                assert_eq!(exit, ProcessExit::Exited(CONTAINER_EXIT));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    /// CORE-1・D-19・SUP-1: 稼働中は監視プロセスが 1 個（コンテナ役と合わせて 2 件）、終了後は 0 件。
    #[test]
    fn core1_task28_2_supervisor_disappears_from_process_list_after_container_exit() {
        let t = TmpDir::new("main");
        let nonce = unique("main");
        let root = t.root();
        let id = "c1";

        assert_eq!(scan_marked(&nonce), Vec::<u32>::new(), "before create");
        let req = CreateStateRequest::new(
            ContainerStatus::created(cid(id), None),
            std::env::temp_dir().join("fandhe-sup-daemonless-bundle"),
        )
        .expect("create request");
        open(&root).create(&req).expect("create record");
        assert_eq!(scan_marked(&nonce), Vec::<u32>::new(), "created only");

        let release = Release(t.go());
        let mut cmd = role_command(&nonce, "linux::child_supervisor_role");
        cmd.env(ENV_ROOT, &root)
            .env(ENV_ID, id)
            .env(ENV_GO, t.go())
            .env(ENV_ROLE, "supervisor");
        let sup = ChildProcess::new(cmd.spawn().expect("spawn supervisor role"));
        let sup_pid = sup.pid().get();

        // 稼働中: state.json に監視権とコンテナ pid が記録されるまで待つ。
        wait_until("supervisor_pid to be recorded", || {
            let s = reread(&root, id);
            s.record().status().state() == ContainerState::Running
                && s.record().supervisor_pid() == NonZeroU32::new(sup_pid)
        });
        let container_pid = reread(&root, id)
            .record()
            .status()
            .pid()
            .expect("container pid recorded")
            .get();
        let mut expected = vec![sup_pid, container_pid];
        expected.sort_unstable();
        wait_until("both roles to be visible in the process list", || {
            scan_marked(&nonce) == expected
        });

        // コンテナ終了 → 監視プロセスも消え、一覧が空になる。
        release.fire();
        wait_until("process list to become empty", || {
            scan_marked(&nonce).is_empty()
        });
        assert_eq!(
            sup.wait(DEADLINE).expect("wait supervisor"),
            Some(ProcessExit::Exited(0))
        );
        assert_eq!(scan_marked(&nonce), Vec::<u32>::new(), "after exit");

        let s = reread(&root, id);
        let rec = s.record();
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(rec.status().exit_code(), Some(CONTAINER_EXIT));
        assert_eq!(rec.supervisor_pid(), None);
    }
}
