//! seccomp の通知への応答ハブの結線の結合試験（SEC-4・REPAIR-5・SUP-3・REPAIR-12・#2025）。
//!
//! 実カーネルの USER_NOTIF（使い捨てスレッドに載せた `UserNotif` 版の filter。core の `exec-test-support` の
//! `user_notif_probe_for_test`）を、起動と再起動の両方で `run_start` → `run_supervised` が受け取って応答ハブへ渡すこと、
//! listener が届かないときは起動したプロセスを回収して非 0 で終わること（fail-closed）を具体値で照合する。
//! launcher はテスト用のフェイク（本番 launcher が PID 1 から listener を渡す部分は core の `tests/production_launcher.rs`
//! が照合する。再 launch が本番で成り立つかは #2043）。root 不要。Linux 限定。

#![cfg(target_os = "linux")]

// 一時領域の親を tmpfiles の flock 走査から守る共有部品（#3026・CORE-5・REPAIR-12）。
#[cfg(target_os = "linux")]
#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

use std::num::{NonZeroU8, NonZeroU32};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_core::audit_log::{AuditRecord, AuditSink};
use fandhe_container_core::exec::{SeccompListener, UserNotifProbe, user_notif_probe_for_test};
use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{
    LaunchSpec, LaunchedProcess, ProcessExit, ProcessLauncher, StartTimeouts, create,
};
use fandhe_container_core::traits::{
    ContainerId, CreateRequest, ErrorCode, StartRequest, StateRecord, StateRevision, StateStore,
    TraitError,
};
use fandhe_container_supervisor::restart::RestartPolicy;
use fandhe_container_supervisor::run::StopToken;
use fandhe_container_supervisor::seccomp_notify::{NotifyConfig, SeccompNotifyHub};
use fandhe_container_supervisor::start_entry::{Running, StartDeps, run_start, run_supervised};
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
            scratch_root::ScratchDir::new("fandhe-sup-seccomp", std::time::Duration::from_secs(10));
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

/// 記録を集める sink。
#[derive(Default)]
struct VecSink(Mutex<Vec<AuditRecord>>);

impl AuditSink for VecSink {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        self.0.lock().unwrap().push(record.clone());
        Ok(())
    }
}

/// 使い捨てスレッドの filter（probe）を包む。listener は 1 回だけ取り出せる。
///
/// listener の取り出し（`&mut`）だけを mutex で守り、`call_kcmp`（USER_NOTIF の応答待ちでブロックする）は
/// mutex の外で呼ぶ。両方を同じ mutex の下で呼ぶと、`run_supervised` の `take_seccomp_listener` と
/// デッドロックする（Bugbot 指摘）。
struct SharedProbe {
    listener: Mutex<Option<SeccompListener>>,
    probe: UserNotifProbe,
}

/// 実プロセス（`sh -c`）を包み、probe があればその listener を `take_seccomp_listener` で 1 回だけ渡す。
struct ShProcess {
    pid: NonZeroU32,
    child: Mutex<Child>,
    probe: Option<Arc<SharedProbe>>,
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

    fn take_seccomp_listener(&self) -> Option<SeccompListener> {
        self.probe.as_ref()?.listener.lock().unwrap().take()
    }
}

/// 起動のたびに次のスクリプトを実プロセスとして起動し、`with_probe` なら新しい probe を付ける launcher。
struct ScriptLauncher {
    scripts: Vec<&'static str>,
    with_probe: bool,
    launches: AtomicUsize,
    probes: Mutex<Vec<Arc<SharedProbe>>>,
}

impl ProcessLauncher for ScriptLauncher {
    fn launch(
        &self,
        _spec: &LaunchSpec,
        _timeout: Duration,
    ) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        let n = self.launches.fetch_add(1, Ordering::SeqCst);
        let script = self.scripts[n.min(self.scripts.len() - 1)];
        let child = Command::new("sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sh");
        let probe = if self.with_probe {
            let mut probe = user_notif_probe_for_test().expect("probe");
            let p = Arc::new(SharedProbe {
                listener: Mutex::new(probe.take_listener()),
                probe,
            });
            self.probes.lock().unwrap().push(Arc::clone(&p));
            Some(p)
        } else {
            None
        };
        Ok(Box::new(ShProcess {
            pid: NonZeroU32::new(child.id()).expect("pid"),
            child: Mutex::new(child),
            probe,
        }))
    }

    fn confirm_no_process(&self, _id: &ContainerId, _timeout: Duration) -> Result<(), TraitError> {
        Ok(())
    }
}

struct Deps {
    launcher: Arc<ScriptLauncher>,
    hub: Arc<SeccompNotifyHub>,
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

    fn seccomp_hub(&self) -> Option<Arc<SeccompNotifyHub>> {
        Some(Arc::clone(&self.hub))
    }

    fn release_cgroup(&mut self) -> Result<(), TraitError> {
        Ok(())
    }
}

fn start(env: &Env, launcher: &Arc<ScriptLauncher>, hub: &Arc<SeccompNotifyHub>) -> Running {
    run_start(
        Box::new(Deps {
            launcher: launcher.clone(),
            hub: Arc::clone(hub),
        }),
        &env.store,
        &Arc::new(OpRecorder::new()),
        &StartRequest::new(ContainerId::new(&env.id).unwrap()),
        &timeouts(),
        &mut Vec::new(),
    )
    .unwrap_or_else(|c: NonZeroU8| panic!("start failed: {c}"))
}

fn new_hub(env: &Env, sink: Arc<dyn AuditSink>) -> Arc<SeccompNotifyHub> {
    Arc::new(SeccompNotifyHub::new(
        sink,
        ContainerId::new(&env.id).unwrap(),
        NotifyConfig::default(),
    ))
}

/// SEC-4・SUP-3・#2025: 初回の起動と再起動後の起動の listener が、それぞれ応答ハブに渡る。各プロセスの拒否対象の syscall
/// （`kcmp`）は `EPERM`(1) になり、記録がちょうど 1 件ずつ（pid は各プローブの TID、コンテナ ID つき）残る。
#[test]
fn sec4_2025_first_and_restarted_listeners_are_both_served() {
    let env = Env::new("restart");
    let sink = Arc::new(VecSink::default());
    let hub = new_hub(&env, sink.clone());
    let launcher = Arc::new(ScriptLauncher {
        scripts: vec!["sleep 1; exit 1", "sleep 1"],
        with_probe: true,
        launches: AtomicUsize::new(0),
        probes: Mutex::new(Vec::new()),
    });
    let running = start(&env, &launcher, &hub);
    let driver = {
        let launcher = Arc::clone(&launcher);
        std::thread::spawn(move || {
            let mut observed = Vec::new();
            for n in 1..=2usize {
                let started = Instant::now();
                let probe = loop {
                    if let Some(p) = launcher.probes.lock().unwrap().get(n - 1).cloned() {
                        break p;
                    }
                    assert!(started.elapsed() < Duration::from_secs(10), "launch {n}");
                    std::thread::sleep(Duration::from_millis(5));
                };
                let (errno, tid) = (probe.probe.call_kcmp(), probe.probe.tid());
                observed.push((errno, tid));
            }
            observed
        })
    };
    let code = run_supervised(
        env.store.clone(),
        ContainerId::new(&env.id).unwrap(),
        running,
        RestartPolicy::OnFailure {
            max_retries: NonZeroU32::new(1),
        },
        &timeouts(),
        &StopToken::new(),
    );
    let observed = driver.join().unwrap();
    assert_eq!(code, 0);
    assert_eq!(launcher.launches.load(Ordering::SeqCst), 2);
    assert_eq!(
        observed.iter().map(|o| o.0).collect::<Vec<_>>(),
        [Some(1), Some(1)]
    );
    let recs = sink.0.lock().unwrap();
    assert_eq!(
        recs.iter().map(|r| r.pid().get()).collect::<Vec<_>>(),
        observed.iter().map(|o| o.1).collect::<Vec<_>>()
    );
    assert!(
        recs.iter()
            .all(|r| r.container_id().map(ContainerId::as_str) == Some(env.id.as_str()))
    );
}

/// SEC-4・#2025（fail-closed）: ハブがあるのに listener が届かない（`take_seccomp_listener` が `None`）なら、
/// 起動したプロセスを回収して非 0 で終わる（応答者のいない USER_NOTIF を動かし続けない）。
#[test]
fn sec4_2025_missing_listener_disposes_the_process_and_fails() {
    let env = Env::new("nolistener");
    let hub = new_hub(&env, Arc::new(VecSink::default()));
    let launcher = Arc::new(ScriptLauncher {
        scripts: vec!["sleep 30"],
        with_probe: false,
        launches: AtomicUsize::new(0),
        probes: Mutex::new(Vec::new()),
    });
    let recorder = Arc::new(OpRecorder::new());
    let started = Instant::now();
    let mut out = Vec::new();
    let result = run_start(
        Box::new(Deps {
            launcher: launcher.clone(),
            hub: Arc::clone(&hub),
        }),
        &env.store,
        &recorder,
        &StartRequest::new(ContainerId::new(&env.id).unwrap()),
        &timeouts(),
        &mut out,
    );
    // REPAIR-4: 引き渡しの失敗は supervisor.start の失敗 1 件として数え、成功と二重計上しない。
    let stats = recorder
        .snapshot_op(
            &fandhe_container_core::observability::OpName::new("supervisor.start").unwrap(),
        )
        .expect("start must be recorded");
    assert_eq!((stats.success(), stats.failure()), (0, 1));
    assert!(result.is_err(), "start must fail without a listener");
    assert_ne!(result.err().map(NonZeroU8::get), Some(0));
    assert!(!out.is_empty(), "the ERR line must be reported");
    assert!(started.elapsed() < Duration::from_secs(10));
}
