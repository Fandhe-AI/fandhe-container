//! 再起動ループ（`restart::supervise_with_restart`）と実 `state.json` の結合テスト、およびバックオフ 0 の
//! 再起動レイテンシ計測（TASK-159.3・#489・SUP-3・SUP-1・REPAIR-4・REPAIR-5・REPAIR-12）。
//!
//! 実プロセス（テストバイナリ自身の再実行。即座に非 0 で終了する）をコンテナ役にし、core の `FileStateStore` が
//! 書く実 `state.json` で次を具体値で照合する。
//! - 再起動のたびに `restart_count` が 1 ずつ増え、`Running(新 pid)` が `state.json` に反映される（受け入れ条件 1）。
//! - バックオフ 0 の再起動レイテンシ（終了検知から `Running` 記録完了まで。`MonitorOperation::Restart` の `elapsed`）の
//!   中央値が 100ms 以下である（SUP-3。受け入れ条件 2）。
//!
//! 検証範囲と非範囲（REPAIR-3）: コンテナ役はテストバイナリの再実行であり、namespace 分離・cgroup・rootfs 準備を
//! 含まない。本番の `ProcessLauncher` による再 launch は未提供のため、`Relauncher` はテストバイナリの再 spawn で
//! 模している。したがって計測値は SUP-3 の実機での合否判定ではない（実機実測は #490・#491〔TASK-160・人間担当〕）。
//! root 不要で既定のテスト集合で動く。`FileStateStore` は Linux 限定のため、試験は `linux` モジュールに置く。

const ENV_EXIT: &str = "FANDHE_SUP_RLAT_EXIT";

/// コンテナ役の子プロセス本体。通常のテスト実行では環境変数が無く即 return する（no-op）。
/// 親が再実行したときだけ、`ENV_EXIT` の終了コードで即座に終了する。
#[test]
fn child_exit_role() {
    let Ok(code) = std::env::var(ENV_EXIT) else {
        return;
    };
    std::process::exit(code.parse().unwrap_or(99));
}

/// 非 Linux では `FileStateStore` が `Unimplemented`（fail-closed。CLI-1）のため、本結合試験は Linux のみで実行する。
/// 非 Linux の fail-closed は `state_store_wiring.rs` が照合済み。
#[cfg(not(target_os = "linux"))]
#[test]
fn sup3_task159_3_restart_latency_is_linux_only() {
    // 本体は `linux` モジュール。非 Linux は理由（上記 doc）を明示した no-op。
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// 一意な一時パス（テスト間・並列実行間で衝突しない）。
    fn unique_path(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!(
            "fandhe-sup-rlat-it-{tag}-{}-{n}",
            std::process::id()
        ))
    }

    use std::num::NonZeroU32;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use fandhe_container_core::oci_runtime::{LaunchedProcess, ProcessExit};
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, ContainerStatus, CreateStateRequest, ErrorCode, StateStore,
        SupervisionState, TraitError,
    };
    use fandhe_container_supervisor::restart::{
        NoRestartReason, Relauncher, RestartConfig, RestartPolicy, SuperviseOutcome,
        supervise_with_restart,
    };
    use fandhe_container_supervisor::run::{
        MonitorConfig, MonitorEvent, MonitorObserver, MonitorOperation, StopToken,
    };
    use fandhe_container_supervisor::state::{SupervisedState, open_default_store};

    /// 再起動回数（ポリシー `on-failure:N` の N）。中央値・p95 を意味のある標本数で出すため 11 以上にする。
    const RESTARTS: u32 = 20;
    /// ループ全体の期限（無限ループを作らない。REPAIR-5）。
    const OVERALL_DEADLINE: Duration = Duration::from_secs(60);
    /// 子プロセスの終了確認ポーリング間隔（レイテンシへの上乗せを小さくする）。
    const POLL: Duration = Duration::from_millis(2);
    /// SUP-3 のレイテンシ目標（中央値）。
    const TARGET_MEDIAN: Duration = Duration::from_millis(100);

    fn internal(msg: &'static str) -> TraitError {
        TraitError::new(ErrorCode::Internal, msg)
    }

    /// 実プロセス（`std::process::Child`）を [`LaunchedProcess`] として扱うテスト用アダプタ。`Drop` で kill + 回収する。
    struct ChildProcess {
        pid: NonZeroU32,
        child: Mutex<Child>,
    }

    impl ChildProcess {
        fn new(child: Child) -> Result<Self, TraitError> {
            let pid = NonZeroU32::new(child.id()).ok_or_else(|| internal("zero child pid"))?;
            Ok(Self {
                pid,
                child: Mutex::new(child),
            })
        }
    }

    impl LaunchedProcess for ChildProcess {
        fn pid(&self) -> NonZeroU32 {
            self.pid
        }

        fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
            use std::os::unix::process::ExitStatusExt;
            let end = Instant::now() + timeout;
            loop {
                {
                    let mut c = self
                        .child
                        .lock()
                        .map_err(|_| internal("child lock poisoned"))?;
                    if let Some(st) = c.try_wait().map_err(|_| internal("try_wait failed"))? {
                        return match (st.code(), st.signal()) {
                            (Some(code), _) => Ok(Some(ProcessExit::Exited(code))),
                            (None, Some(sig)) => Ok(Some(ProcessExit::Signaled(sig))),
                            _ => Err(internal("unrecognized exit status")),
                        };
                    }
                }
                if Instant::now() >= end {
                    return Ok(None);
                }
                std::thread::sleep(POLL);
            }
        }

        fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
            if let Ok(mut c) = self.child.lock() {
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

    /// 即座に終了コード 1 で終わるコンテナ役の子を起動する。
    fn spawn_failing_container() -> Result<ChildProcess, TraitError> {
        let exe = std::env::current_exe().map_err(|_| internal("current_exe failed"))?;
        let child = Command::new(exe)
            .args(["--exact", "child_exit_role", "--test-threads=1"])
            .env(ENV_EXIT, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| internal("spawn failed"))?;
        ChildProcess::new(child)
    }

    /// 本番 launcher の代役: 同じ子を再 spawn する。
    struct Respawn;

    impl Relauncher for Respawn {
        fn relaunch(&self, _: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
            Ok(Box::new(spawn_failing_container()?))
        }
    }

    /// 一時状態ルート（0700。drop で削除）。
    struct TmpRoot(PathBuf);

    impl TmpRoot {
        fn new(tag: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let p = unique_path(tag);
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
    }

    impl Drop for TmpRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// 再起動 1 回ごとに、実 `state.json` を開き直して読んだ値と `elapsed` を集める観測器。
    struct Probe {
        root: PathBuf,
        id: ContainerId,
        /// (restart_count, 状態, 記録された pid) を再起動成功ごとに記録する。
        seen: Mutex<Vec<(u32, ContainerState, Option<NonZeroU32>)>>,
        latencies: Mutex<Vec<Duration>>,
        failures: Mutex<Vec<ErrorCode>>,
    }

    impl MonitorObserver for Probe {
        fn observe(&self, e: &MonitorEvent) {
            if e.operation != MonitorOperation::Restart {
                return;
            }
            if let Some(code) = e.error_code {
                if let Ok(mut f) = self.failures.lock() {
                    f.push(code);
                }
                return;
            }
            // 観測器自身の読み取りは次周の計測に含まれない（elapsed はこの通知より前に確定している）。
            let Ok(store) = open_default_store(Some(self.root.clone())) else {
                return;
            };
            let Ok(s) = SupervisedState::attach(store, self.id.clone()) else {
                return;
            };
            let rec = s.record();
            if let Ok(mut v) = self.seen.lock() {
                v.push((
                    rec.restart_count(),
                    rec.status().state(),
                    rec.status().pid(),
                ));
            }
            if let Ok(mut l) = self.latencies.lock() {
                l.push(e.elapsed);
            }
        }
    }

    /// SUP-3・TASK-159.3: 実プロセス・実 state.json で `on-failure:20`・バックオフ 0 の再起動を通し、
    /// (1) `restart_count` が 1..=20 と増え `Running(新 pid)` が反映されること、
    /// (2) 再起動レイテンシの中央値が 100ms 以下であることを照合する。
    #[test]
    fn sup3_task159_3_restart_count_and_latency_with_real_state_json() {
        let tmp = TmpRoot::new("latency");
        let root = tmp.0.clone();
        let id = ContainerId::new("c1").unwrap();

        let store: Arc<dyn StateStore> = open_default_store(Some(root.clone())).unwrap();
        let req = CreateStateRequest::new(
            ContainerStatus::created(id.clone(), None),
            std::env::temp_dir().join("fandhe-sup-rlat-it-bundle"),
        )
        .unwrap();
        store.create(&req).unwrap();

        let first = spawn_failing_container().unwrap();
        let first_pid = first.pid();
        let mut state = SupervisedState::attach(store, id.clone()).unwrap();
        state
            .write(
                ContainerStatus::running(id.clone(), Some(first_pid)),
                SupervisionState::new(None, None, 0),
            )
            .unwrap();

        let policy: RestartPolicy = format!("on-failure:{RESTARTS}").parse().unwrap();
        let restart_cfg = RestartConfig::new(policy)
            .with_backoff(Duration::ZERO)
            .unwrap();
        let monitor_cfg = MonitorConfig::new(Duration::from_millis(20)).unwrap();
        let probe = Probe {
            root: root.clone(),
            id: id.clone(),
            seen: Mutex::new(Vec::new()),
            latencies: Mutex::new(Vec::new()),
            failures: Mutex::new(Vec::new()),
        };

        // 期限を過ぎたら停止を要求して、無限ループにならないようにする（REPAIR-5）。
        let stop = StopToken::new();
        let watchdog_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let outcome = std::thread::scope(|sc| {
            let (stop_w, done_w) = (stop.clone(), watchdog_done.clone());
            sc.spawn(move || {
                let end = Instant::now() + OVERALL_DEADLINE;
                while !done_w.load(Ordering::SeqCst) {
                    if Instant::now() >= end {
                        stop_w.request_stop();
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
            let r = supervise_with_restart(
                &mut state,
                Box::new(first),
                &(Arc::new(Respawn) as Arc<dyn Relauncher>),
                &monitor_cfg,
                &restart_cfg,
                &stop,
                &probe,
            );
            watchdog_done.store(true, Ordering::SeqCst);
            r
        })
        .unwrap();

        match outcome {
            SuperviseOutcome::Finished {
                reason, restarts, ..
            } => {
                assert_eq!(reason, NoRestartReason::RetriesExhausted);
                assert_eq!(restarts, RESTARTS);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert!(probe.failures.lock().unwrap().is_empty());

        // (1) state.json の restart_count の列と Running(新 pid) の反映。
        let seen = probe.seen.lock().unwrap().clone();
        let counts: Vec<u32> = seen.iter().map(|(c, _, _)| *c).collect();
        assert_eq!(counts, (1..=RESTARTS).collect::<Vec<u32>>());
        let mut prev = first_pid;
        for (_, st, pid) in &seen {
            assert_eq!(*st, ContainerState::Running);
            let pid = pid.expect("running state must record a pid");
            assert_ne!(pid, prev);
            prev = pid;
        }
        let store = open_default_store(Some(root.clone())).unwrap();
        let fin = SupervisedState::attach(store, id).unwrap();
        let rec = fin.record();
        assert_eq!(rec.restart_count(), RESTARTS);
        assert_eq!(rec.status().state(), ContainerState::Stopped);
        assert_eq!(rec.status().exit_code(), Some(1));
        assert_eq!(rec.supervisor_pid(), None);
        assert!(root.join("c1").join("state.json").is_file());

        // (2) 再起動レイテンシ（バックオフ 0）の中央値・p95。
        let mut lat = probe.latencies.lock().unwrap().clone();
        lat.sort();
        assert_eq!(lat.len(), RESTARTS as usize);
        let median = *lat.get(lat.len() / 2).expect("median");
        let p95_idx = (lat.len() * 95).div_ceil(100).saturating_sub(1);
        let p95 = *lat.get(p95_idx).expect("p95");
        eprintln!(
            "{{\"component\":\"supervisor.restart_latency\",\"behavior\":\"SUP-3\",\"trials\":{},\"median_us\":{},\"p95_us\":{}}}",
            lat.len(),
            median.as_micros(),
            p95.as_micros()
        );
        assert!(
            median <= TARGET_MEDIAN,
            "restart latency median {median:?} exceeds {TARGET_MEDIAN:?}"
        );
    }
}
