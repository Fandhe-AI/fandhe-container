//! 起動・再起動をまたぐコンテナ出力の捕捉の結合試験（TASK-164 追補・#1471・SUP-7・SUP-1・REPAIR-5・REPAIR-12）。
//!
//! 実プロセス（`sh -c`）の stdout / stderr を `LaunchedProcess::take_output` で受け取り、`run_start` →
//! `run_supervised`（再起動を含む）を通して `LogSink` に入る行を具体値で照合する。launcher はテスト用のフェイクで、
//! 「launcher がパイプを作って渡す」部分は本試験では照合しない（core 側は `exec::ChildStdio` の単体試験と
//! `tests/production_launcher.rs` が、bin → 本番 launcher の通しは実機前提の `supervisor_bin_real.rs`〔#1819〕が照合する）。
//! root 不要。
//! `FileStateStore` と rootfs の fd 固定は Linux 限定のため全体を Linux に置く。

#![cfg(target_os = "linux")]

// 一時領域の親を tmpfiles の flock 走査から守る共有部品（#3026・CORE-5・REPAIR-12）。
#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

use std::io::Read;
use std::num::{NonZeroU8, NonZeroU32};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    ContainerOutput, LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, StartTimeouts,
    create,
};
use fandhe_container_core::traits::{
    ContainerId, CreateRequest, ErrorCode, StartRequest, StateRecord, StateRevision, StateStore,
    TraitError,
};
use fandhe_container_supervisor::logs::{LogSink, MemoryLogSink, StreamKind};
use fandhe_container_supervisor::restart::RestartPolicy;
use fandhe_container_supervisor::run::StopToken;
use fandhe_container_supervisor::start_entry::{StartDeps, run_start, run_supervised};
use fandhe_container_supervisor::state::open_default_store;

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Env {
    id: String,
    base: PathBuf,
    store: Arc<dyn StateStore>,
    /// tmpfiles の flock 走査から守る親（#3026）。`base` はその子。最後のフィールドで、`Drop` の後に親が消える。
    _scratch: scratch_root::ScratchDir,
}

impl Env {
    fn new(tag: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let scratch =
            scratch_root::ScratchDir::new("fandhe-sup-logs", std::time::Duration::from_secs(10));
        let base = scratch.path().join(format!("{tag}-{n}"));
        std::fs::create_dir_all(base.join("bundle/rootfs")).unwrap();
        std::fs::write(
            base.join("bundle/config.json"),
            br#"{"ociVersion":"1.2.0","root":{"path":"rootfs"},
"process":{"user":{"uid":0,"gid":0},"args":["/bin/echo","it"],"cwd":"/"},
"linux":{"namespaces":[{"type":"pid"},{"type":"mount"},{"type":"user"},{"type":"uts"},{"type":"ipc"}]}}"#,
        )
        .unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = base.join("state");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = open_default_store(Some(root)).unwrap();
        let id = format!("c-{tag}-{n}");
        let req = CreateRequest::new(ContainerId::new(&id).unwrap(), base.join("bundle")).unwrap();
        create(store.as_ref(), &OpRecorder::new(), &req).unwrap();
        Self {
            id,
            base,
            store,
            _scratch: scratch,
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn timeouts() -> StartTimeouts {
    StartTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .unwrap()
}

/// 実プロセスを包み、stdout / stderr の読み取り側を `take_output` で 1 回だけ渡す。
struct ShProcess {
    pid: NonZeroU32,
    child: Mutex<Child>,
    output: Mutex<Option<ContainerOutput>>,
}

impl ShProcess {
    fn spawn(script: &str) -> Self {
        let mut child = Command::new("sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sh");
        let output = ContainerOutput {
            stdout: child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
            stderr: child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn Read + Send>),
        };
        Self {
            pid: NonZeroU32::new(child.id()).expect("pid"),
            child: Mutex::new(child),
            output: Mutex::new(Some(output)),
        }
    }
}

impl LaunchedProcess for ShProcess {
    fn pid(&self) -> NonZeroU32 {
        self.pid
    }

    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        let end = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.lock().unwrap().try_wait().expect("try_wait") {
                return Ok(Some(ProcessExit::Exited(status.code().unwrap_or(-1))));
            }
            if Instant::now() >= end {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
        let _ = self.child.lock().unwrap().kill();
        self.wait(timeout)?
            .map(drop)
            .ok_or_else(|| TraitError::new(ErrorCode::Timeout, "terminate timed out"))
    }

    fn take_output(&self) -> Option<ContainerOutput> {
        self.output.lock().unwrap().take()
    }
}

/// 起動のたびに `scripts` の次のスクリプトを実プロセスとして起動する launcher。
struct ScriptLauncher {
    scripts: Vec<&'static str>,
    launches: AtomicUsize,
}

impl ProcessLauncher for ScriptLauncher {
    fn launch(
        &self,
        _spec: &LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        let n = self.launches.fetch_add(1, Ordering::SeqCst);
        let script = self.scripts[n.min(self.scripts.len() - 1)];
        Ok(Box::new(ShProcess::spawn(script)))
    }

    fn confirm_no_process(&self, _id: &ContainerId, _timeout: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

struct Deps {
    launcher: Arc<ScriptLauncher>,
    sink: Option<Arc<dyn LogSink>>,
}

impl StartDeps for Deps {
    fn check_launcher_available(&self) -> Result<(), TraitError> {
        Ok(())
    }

    fn prepare_cgroup(
        &mut self,
        _store: &dyn StateStore,
        _observed: &StateRecord,
    ) -> Result<Option<StateRevision>, TraitError> {
        Ok(None)
    }

    fn build_audit_sink(&mut self) -> Result<(), TraitError> {
        Ok(())
    }

    fn build_launcher(&mut self) -> Result<Arc<dyn ProcessLauncher>, TraitError> {
        Ok(self.launcher.clone())
    }

    fn open_log_sink(&mut self, _id: &ContainerId) -> Result<Option<Arc<dyn LogSink>>, TraitError> {
        Ok(self.sink.clone())
    }

    fn release_cgroup(&mut self) -> Result<(), TraitError> {
        Ok(())
    }
}

/// `scripts` を順に起動して最後まで監視し、(終了コード, 起動回数) を返す。
fn supervise(
    env: &Env,
    scripts: Vec<&'static str>,
    sink: Option<Arc<dyn LogSink>>,
    policy: RestartPolicy,
) -> (u8, usize) {
    let launcher = Arc::new(ScriptLauncher {
        scripts,
        launches: AtomicUsize::new(0),
    });
    let running = run_start(
        Box::new(Deps {
            launcher: launcher.clone(),
            sink,
        }),
        &env.store,
        &Arc::new(OpRecorder::new()),
        &StartRequest::new(ContainerId::new(&env.id).unwrap()),
        &timeouts(),
        &mut Vec::new(),
    )
    .unwrap_or_else(|c: NonZeroU8| panic!("start failed: {c}"));
    let code = run_supervised(
        env.store.clone(),
        ContainerId::new(&env.id).unwrap(),
        running,
        policy,
        &timeouts(),
        &StopToken::new(),
    );
    (code, launcher.launches.load(Ordering::SeqCst))
}

fn lines(sink: &MemoryLogSink, kind: StreamKind) -> Vec<String> {
    let mut v: Vec<String> = sink
        .snapshot()
        .unwrap()
        .into_iter()
        .filter(|l| l.stream == kind)
        .map(|l| String::from_utf8(l.bytes).unwrap())
        .collect();
    v.sort();
    v
}

/// SUP-7・SUP-1: 初回の起動と再起動後の起動の stdout / stderr の行が、ストリーム別に欠落・重複なく sink に入る。
#[test]
fn sup7_1471_output_of_first_and_restarted_process_reaches_the_sink() {
    let env = Env::new("restart");
    let sink = Arc::new(MemoryLogSink::default());
    let (code, launches) = supervise(
        &env,
        vec![
            "echo first-out-1; echo first-out-2; echo first-err >&2; exit 1",
            "echo second-out; echo second-err-1 >&2; printf second-err-2 >&2",
        ],
        Some(sink.clone()),
        RestartPolicy::OnFailure {
            max_retries: NonZeroU32::new(1),
        },
    );
    assert_eq!((code, launches), (0, 2));
    assert_eq!(
        lines(&sink, StreamKind::Stdout),
        ["first-out-1", "first-out-2", "second-out"]
    );
    assert_eq!(
        lines(&sink, StreamKind::Stderr),
        ["first-err", "second-err-1", "second-err-2"]
    );
}

/// ハブを持たない（sink を開かない）構成では出力を捕捉せず、従来どおり監視が動く。
#[test]
fn sup7_1471_without_sink_supervision_still_runs() {
    let env = Env::new("nosink");
    let (code, launches) = supervise(&env, vec!["echo ignored"], None, RestartPolicy::No);
    assert_eq!((code, launches), (0, 1));
}

/// 常に失敗する sink でも読み取りは EOF まで続き、書き手（大量出力のプロセス）が詰まらずに終了する（REPAIR-5）。
#[test]
fn sup7_1471_failing_sink_does_not_block_the_writer() {
    struct FailingSink;
    impl LogSink for FailingSink {
        fn append(&self, _stream: StreamKind, _line: &[u8]) -> Result<(), TraitError> {
            Err(TraitError::new(ErrorCode::Internal, "sink is broken"))
        }
    }
    let env = Env::new("failing");
    let started = Instant::now();
    let (code, launches) = supervise(
        &env,
        vec!["yes line | head -n 300000; yes err | head -n 300000 >&2"],
        Some(Arc::new(FailingSink)),
        RestartPolicy::No,
    );
    assert_eq!((code, launches), (0, 1));
    assert!(started.elapsed() < Duration::from_secs(20));
}
