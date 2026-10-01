//! 監視ループ（`run::monitor`）と実 `state.json` の結合テスト（TASK-157.8・#242・SUP-1・CORE-1・D-19・SUP-3・REPAIR-5・REPAIR-12）。
//!
//! 実プロセス（テストバイナリ自身の再実行）を `LaunchedProcess` として監視し、core の `FileStateStore`
//! が書く実 `state.json` が「監視開始 → プロセス終了 → 記録」まで更新されることを具体値で照合する。
//! 加えて、コンテナ 1 個の寿命が尽きたあとに supervisor 役プロセスが残らないこと（CORE-1・D-19）を
//! 別プロセスの終了で確認する。
//!
//! 検証範囲と非範囲（REPAIR-3）: supervisor の本番バイナリ入口と core の本番 `ProcessLauncher` は未提供のため、
//! 「supervisor 役」はテストバイナリの再実行で `open_default_store` → `attach` → `monitor` → 復帰という
//! 将来の入口と同じ呼び出し順を模したものである。SUP-1 の実機計測（50 コンテナの集約メモリの Docker 比・
//! n=0 の実プロセス数）は TASK-28・TASK-45・TASK-47・TASK-49 の担当で、本テストは保証しない。
//! root 不要で既定のテスト集合で動く。`FileStateStore` は Linux 限定のため、ストアを使う試験は
//! `linux` モジュールに置く（非 Linux の fail-closed は `state_store_wiring.rs` が照合済み）。

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{ErrorCode, TraitError};

/// 期限つき待機の上限（AGENTS.md の推奨（子プロセス応答待ちは 5〜10 秒）に収める。REPAIR-5）。
const DEADLINE: Duration = Duration::from_secs(10);
/// 子プロセスの終了確認ポーリング間隔。
const POLL: Duration = Duration::from_millis(10);
/// コンテナ役の子がマーカー待ちを諦める上限。超過時は終了コード 99 で終わる。
const CHILD_WAIT: Duration = Duration::from_secs(8);

const ENV_GO: &str = "FANDHE_SUP_RUN_IT_GO";
const ENV_EXIT: &str = "FANDHE_SUP_RUN_IT_EXIT";

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// 一意な一時パス（テスト間・並列実行間で衝突しない）。
fn unique_path(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "fandhe-sup-run-it-{tag}-{}-{n}",
        std::process::id()
    ))
}

fn internal(msg: &'static str) -> TraitError {
    TraitError::new(ErrorCode::Internal, msg)
}

/// 実プロセス（`std::process::Child`）を [`LaunchedProcess`] として扱うテスト用アダプタ。
///
/// 本番 launcher が未提供のため、監視ループ（`run::monitor`）へ注入する起動ハンドルの代役を務める。
/// `Drop` で kill + 回収し、テスト失敗時にもプロセスを残さない。
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

    /// 強制終了（SIGKILL 相当）を送る。シグナル終了の試験用（Linux のテストだけが使う）。
    #[cfg(target_os = "linux")]
    fn kill(&self) {
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
        }
    }
}

fn map_exit(status: std::process::ExitStatus) -> Result<ProcessExit, TraitError> {
    if let Some(code) = status.code() {
        return Ok(ProcessExit::Exited(code));
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Ok(ProcessExit::Signaled(sig));
        }
    }
    Err(internal("unrecognized exit status"))
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
                if let Some(status) = c.try_wait().map_err(|_| internal("try_wait failed"))? {
                    return map_exit(status).map(Some);
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

/// コンテナ役の子プロセス本体。通常のテスト実行では環境変数が無く即 return する（no-op）。
///
/// 親が [`spawn_container`] で再実行したときだけ、マーカーファイルが現れるまで待ち、
/// `FANDHE_SUP_RUN_IT_EXIT` の終了コードで終了する。ホストのコマンド（sh・sleep）に依存しない。
#[test]
fn child_container_role() {
    let Ok(go) = std::env::var(ENV_GO) else {
        return;
    };
    let code: i32 = std::env::var(ENV_EXIT)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let go = Path::new(&go);
    let end = Instant::now() + CHILD_WAIT;
    while !go.exists() {
        if Instant::now() >= end {
            std::process::exit(99);
        }
        std::thread::sleep(POLL);
    }
    std::process::exit(code);
}

/// コンテナ役の子（テストバイナリ自身の再実行）の起動コマンド。`go` が作られると `exit_code` で終了する。
fn container_command(go: &Path, exit_code: i32) -> Command {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.args([
        "--exact",
        "child_container_role",
        "--test-threads=1",
        "--nocapture",
    ])
    .env(ENV_GO, go)
    .env(ENV_EXIT, exit_code.to_string())
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    cmd
}

fn spawn_container(go: &Path, exit_code: i32) -> ChildProcess {
    let child = container_command(go, exit_code)
        .spawn()
        .expect("spawn container role");
    ChildProcess::new(child)
}

/// 起動ハンドルのアダプタ自体の検証（3 OS 共通）。生存中は `None`、終了後は具体の終了コードを返す。
#[test]
fn sup1_task157_8_process_handle_reports_alive_then_exit_code() {
    let go = unique_path("smoke-go");
    let p = spawn_container(&go, 3);
    assert_eq!(p.wait(Duration::from_millis(50)).unwrap(), None);
    std::fs::write(&go, b"").unwrap();
    let end = Instant::now() + DEADLINE;
    let exit = loop {
        if let Some(e) = p.wait(Duration::from_millis(100)).unwrap() {
            break e;
        }
        assert!(Instant::now() < end, "container role did not exit in time");
    };
    let _ = std::fs::remove_file(&go);
    assert_eq!(exit, ProcessExit::Exited(3));
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::sync::Arc;

    use fandhe_container_core::traits::{
        ContainerId, ContainerState, ContainerStatus, CreateStateRequest, HealthStatus, StateStore,
        SupervisionState,
    };
    use fandhe_container_supervisor::health::record_health;
    use fandhe_container_supervisor::run::{
        MonitorConfig, MonitorOutcome, StderrLogObserver, StopToken, monitor,
    };
    use fandhe_container_supervisor::state::{SupervisedState, open_default_store};

    const ENV_ROOT: &str = "FANDHE_SUP_RUN_IT_SUP_ROOT";
    const ENV_ID: &str = "FANDHE_SUP_RUN_IT_SUP_ID";
    const ENV_SUP_GO: &str = "FANDHE_SUP_RUN_IT_SUP_GO";

    /// テスト用一時ディレクトリ（0700。drop で削除）。状態ルートは `state/`、マーカーは `go` に置く。
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let p = unique_path(tag);
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(p.join("state")).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(p.join("state"), fs::Permissions::from_mode(0o700)).unwrap();
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

    /// drop 時にマーカーを作ってコンテナ役を終了させる（assert 失敗時も monitor スレッドが抜けられる。REPAIR-5）。
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
        ContainerId::new(s).unwrap()
    }

    fn open(root: &Path) -> Arc<dyn StateStore> {
        open_default_store(Some(root.to_path_buf())).unwrap()
    }

    fn cfg() -> MonitorConfig {
        MonitorConfig::new(Duration::from_millis(20)).unwrap()
    }

    /// CLI 役: `created` レコードを作る。
    fn create(root: &Path, id: &str) {
        let req = CreateStateRequest::new(
            ContainerStatus::created(cid(id), None),
            std::env::temp_dir().join("fandhe-sup-run-it-bundle"),
        )
        .unwrap();
        open(root).create(&req).unwrap();
    }

    /// CLI 役: `created` を `Running(pid)`（監視なし）へ進めたハンドルを返す。
    fn mark_running(root: &Path, id: &str, pid: NonZeroU32) -> SupervisedState {
        let mut s = SupervisedState::attach(open(root), cid(id)).unwrap();
        s.write(
            ContainerStatus::running(cid(id), Some(pid)),
            SupervisionState::new(None, None, 0),
        )
        .unwrap();
        s
    }

    /// ストアを開き直した新しいハンドルで最新レコードを読む。
    fn reread(root: &Path, id: &str) -> SupervisedState {
        SupervisedState::attach(open(root), cid(id)).unwrap()
    }

    /// 期限つきで条件を待つ（無限待ちを作らない。REPAIR-5）。
    fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
        let end = Instant::now() + DEADLINE;
        while !cond() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            std::thread::sleep(POLL);
        }
    }

    /// `supervisor_pid` に `owner` が記録され `Running` であることを待つ。
    fn wait_claimed(root: &Path, id: &str, owner: u32) {
        wait_until("supervisor_pid to be recorded", || {
            let s = reread(root, id);
            s.record().status().state() == ContainerState::Running
                && s.record().supervisor_pid() == NonZeroU32::new(owner)
        });
    }

    /// AC1: 監視開始 → 正常終了 → `state.json` 更新までを実プロセス・実ストアで通す。
    #[test]
    fn sup1_task157_8_monitor_records_normal_exit_to_state_json() {
        let t = TmpDir::new("normal");
        let root = t.root();
        create(&root, "c1");
        let child = spawn_container(&t.go(), 0);
        let mut state = mark_running(&root, "c1", child.pid());
        let before = state.record().revision().value();
        let stop = StopToken::new();

        let outcome = std::thread::scope(|sc| {
            let release = Release(t.go());
            let h = sc.spawn(|| monitor(&mut state, &child, &cfg(), &stop));
            wait_claimed(&root, "c1", std::process::id());
            release.fire();
            h.join().unwrap().unwrap()
        });

        match outcome {
            MonitorOutcome::Exited { exit, .. } => assert_eq!(exit, ProcessExit::Exited(0)),
            other => panic!("unexpected outcome: {other:?}"),
        }
        let s = reread(&root, "c1");
        let rec = s.record();
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(rec.status().exit_code(), Some(0));
        assert_eq!(rec.supervisor_pid(), None);
        assert_eq!(rec.restart_count(), 0);
        assert!(rec.revision().value() > before);
        assert!(root.join("c1").join("state.json").is_file());
    }

    /// 異常終了で `restart_count` が進み、監視中に別ハンドルが書いた `health` が保たれる（SUP-3・SUP-4 の土台）。
    #[test]
    fn sup1_task157_8_abnormal_exit_increments_restart_count_and_keeps_health() {
        let t = TmpDir::new("abnormal");
        let root = t.root();
        create(&root, "c1");
        let child = spawn_container(&t.go(), 3);
        let mut state = mark_running(&root, "c1", child.pid());
        // 初期値を 4 にして、加算が既存値の上に積まれることを確認する。
        state
            .write_supervision(SupervisionState::new(None, None, 4))
            .unwrap();
        let stop = StopToken::new();

        let outcome = std::thread::scope(|sc| {
            let release = Release(t.go());
            let h = sc.spawn(|| monitor(&mut state, &child, &cfg(), &stop));
            wait_claimed(&root, "c1", std::process::id());
            let mut other = reread(&root, "c1");
            record_health(
                &mut other,
                &child,
                HealthStatus::Healthy,
                &StderrLogObserver,
            )
            .unwrap();
            release.fire();
            h.join().unwrap().unwrap()
        });

        match outcome {
            MonitorOutcome::Exited { exit, .. } => assert_eq!(exit, ProcessExit::Exited(3)),
            other => panic!("unexpected outcome: {other:?}"),
        }
        let s = reread(&root, "c1");
        let rec = s.record();
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(rec.status().exit_code(), Some(3));
        assert_eq!(rec.restart_count(), 5);
        assert_eq!(rec.health(), Some(HealthStatus::Healthy));
        assert_eq!(rec.supervisor_pid(), None);
    }

    /// シグナル終了は 128 + シグナル番号で記録され、異常終了として `restart_count` が進む。
    #[test]
    fn sup1_task157_8_signal_exit_is_recorded_as_128_plus_signal() {
        let t = TmpDir::new("signal");
        let root = t.root();
        create(&root, "c1");
        let child = spawn_container(&t.go(), 0);
        let mut state = mark_running(&root, "c1", child.pid());
        let stop = StopToken::new();

        let outcome = std::thread::scope(|sc| {
            let _release = Release(t.go());
            let h = sc.spawn(|| monitor(&mut state, &child, &cfg(), &stop));
            wait_claimed(&root, "c1", std::process::id());
            child.kill();
            h.join().unwrap().unwrap()
        });

        match outcome {
            MonitorOutcome::Exited { exit, .. } => assert_eq!(exit, ProcessExit::Signaled(9)),
            other => panic!("unexpected outcome: {other:?}"),
        }
        let s = reread(&root, "c1");
        assert_eq!(s.record().status().exit_code(), Some(137));
        assert_eq!(s.record().restart_count(), 1);
        assert_eq!(s.record().supervisor_pid(), None);
    }

    /// 停止要求は監視権（`supervisor_pid`）だけを解放し、コンテナは `Running` のまま残る。
    #[test]
    fn sup1_task157_8_stop_request_releases_ownership_and_keeps_running() {
        let t = TmpDir::new("stop");
        let root = t.root();
        create(&root, "c1");
        let child = spawn_container(&t.go(), 0);
        let mut state = mark_running(&root, "c1", child.pid());
        let stop = StopToken::new();

        let outcome = std::thread::scope(|sc| {
            let _release = Release(t.go());
            let h = sc.spawn(|| monitor(&mut state, &child, &cfg(), &stop));
            wait_claimed(&root, "c1", std::process::id());
            stop.request_stop();
            h.join().unwrap().unwrap()
        });

        match outcome {
            MonitorOutcome::StopRequested { record } => {
                assert_eq!(record.status().state(), ContainerState::Running);
                assert_eq!(record.status().pid(), Some(child.pid()));
                assert_eq!(record.supervisor_pid(), None);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    /// 停止後に同じハンドルで再監視を始め、終了を記録できる（引き継ぎの往復）。
    #[test]
    fn sup1_task157_8_monitor_can_resume_after_stop_request() {
        let t = TmpDir::new("resume");
        let root = t.root();
        create(&root, "c1");
        let child = spawn_container(&t.go(), 0);
        let mut state = mark_running(&root, "c1", child.pid());

        // 停止要求済みなら、監視権を取ってすぐ解放して戻る。
        let stop = StopToken::new();
        stop.request_stop();
        let first = monitor(&mut state, &child, &cfg(), &stop).unwrap();
        assert!(matches!(first, MonitorOutcome::StopRequested { .. }));
        assert_eq!(reread(&root, "c1").record().supervisor_pid(), None);

        let stop2 = StopToken::new();
        let second = std::thread::scope(|sc| {
            let release = Release(t.go());
            let h = sc.spawn(|| monitor(&mut state, &child, &cfg(), &stop2));
            wait_claimed(&root, "c1", std::process::id());
            release.fire();
            h.join().unwrap().unwrap()
        });
        match second {
            MonitorOutcome::Exited { exit, .. } => assert_eq!(exit, ProcessExit::Exited(0)),
            other => panic!("unexpected outcome: {other:?}"),
        }
        let s = reread(&root, "c1");
        assert_eq!(s.record().status().state(), ContainerState::Stopped);
        assert_eq!(s.record().supervisor_pid(), None);
    }

    /// supervisor 役の子プロセス本体。環境変数が無ければ no-op（通常のテスト実行）。
    ///
    /// 将来の supervisor 入口と同じ順序で、ストアを開く → コンテナ役を起動 → `Running` へ更新 →
    /// `attach` → `monitor` を実行し、`Exited` を確認して戻る（= プロセス終了）。
    #[test]
    fn child_supervisor_role() {
        let (Ok(root), Ok(id), Ok(go)) = (
            std::env::var(ENV_ROOT),
            std::env::var(ENV_ID),
            std::env::var(ENV_SUP_GO),
        ) else {
            return;
        };
        let root = PathBuf::from(root);
        // 孫のコンテナ役へ supervisor 役の環境を引き継がない。
        let mut cmd = container_command(Path::new(&go), 3);
        cmd.env_remove(ENV_ROOT)
            .env_remove(ENV_ID)
            .env_remove(ENV_SUP_GO);
        let child = ChildProcess::new(cmd.spawn().expect("spawn grandchild"));
        let mut state = mark_running(&root, &id, child.pid());
        let outcome = monitor(&mut state, &child, &cfg(), &StopToken::new()).expect("monitor");
        match outcome {
            MonitorOutcome::Exited { exit, .. } => assert_eq!(exit, ProcessExit::Exited(3)),
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    /// CORE-1・D-19: コンテナ 0 個になった時点で supervisor 役プロセスが残らず、状態は終了で確定している。
    #[test]
    fn sup1_task157_8_supervisor_process_does_not_remain_after_container_exit() {
        let t = TmpDir::new("noresident");
        let root = t.root();
        create(&root, "c1");
        let exe = std::env::current_exe().unwrap();
        let child = Command::new(exe)
            .args([
                "--exact",
                "linux::child_supervisor_role",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(ENV_ROOT, &root)
            .env(ENV_ID, "c1")
            .env(ENV_SUP_GO, t.go())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn supervisor role");
        let sup = ChildProcess::new(child);

        let release = Release(t.go());
        // コンテナ 1 個の間は supervisor が 1 個生存し、状態に監視権が記録される。
        wait_claimed(&root, "c1", sup.pid().get());
        assert_eq!(sup.wait(Duration::from_millis(50)).unwrap(), None);

        release.fire();
        let end = Instant::now() + DEADLINE;
        let exit = loop {
            if let Some(e) = sup.wait(Duration::from_millis(100)).unwrap() {
                break e;
            }
            assert!(Instant::now() < end, "supervisor role did not exit in time");
        };
        // try_wait が終了を返した = 回収済みで、supervisor プロセスは残っていない。
        assert_eq!(exit, ProcessExit::Exited(0));
        let s = reread(&root, "c1");
        let rec = s.record();
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(rec.status().exit_code(), Some(3));
        assert_eq!(rec.supervisor_pid(), None);
        assert_eq!(rec.restart_count(), 1);
    }
}
