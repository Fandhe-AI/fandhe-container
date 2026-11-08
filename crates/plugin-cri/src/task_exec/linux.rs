//! `TaskExecLauncher` の Linux 実装（stream-exec helper 経由）。契約と残余は親モジュール `task_exec` の doc を参照
//! （CRI-5・CRI-1・SEC-1・REPAIR-3・REPAIR-5・#4148）。

use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Condvar, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, GetStateRequest, Signal, StateStore,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::shim_v2::{
    ExecId, ExecProcessSpec, ExecProcessStatus, TaskExecLauncher, TaskExecProcess,
};
use fandhe_container_supervisor::stream_exec::channel::{
    HelperMessage, StdioSend, recv_from_helper, send_stdio_handover,
};
use fandhe_container_supervisor::stream_exec::helper::StreamExecArgs;
use fandhe_container_supervisor::stream_exec::wire::{StdioMask, StreamExecOutcome};

use crate::streaming::exec_launcher::{
    HANDOVER_BUDGET, HelperGuard, HelperSpawner, ProductionHelperSpawner, RESULT_GRACE,
    SESSION_TIMEOUT, STARTED_BUDGET, Shared, SpawnedHelper, channel_error, cri_error, diagnostics,
    map_outcome,
};

/// 待ちの刻み。取り消しと期限をこの刻みで確かめる（REPAIR-5）。
const WAIT_SLICE: Duration = Duration::from_millis(10);

const UNCONFIRMED: &str = "exec termination is not confirmed";

/// 消滅の確認の結果（[`ExecExtinctionProbe::confirm`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtinctionOutcome {
    /// exec のプロセスと exec 子 cgroup の消滅を確認した。
    Confirmed,
    /// 回収に失敗したことを確認した。
    Failed,
    /// 確認の手段が無い、または未確定。
    Unknown,
}

/// kill・期限切れ・失敗の後に exec の消滅を確かめる差し込み口（CRI-5・SEC-1・REPAIR-3）。
///
/// `Confirmed` のときだけハンドルは `Exited` へ進む。それ以外は未確認のまま `Err` を保つ（fail-closed）。
pub trait ExecExtinctionProbe: Send + Sync + 'static {
    /// `container` の exec の消滅を確かめる。有界でブロッキングしてよい。
    fn confirm(&self, container: &ContainerId) -> ExtinctionOutcome;
}

/// 本番の probe。常に `Unknown`（REPAIR-3）。supervisor 側の wire 拡張（`Started` へ exec 子 cgroup の名前を載せる等）が
/// 入るまでの暫定で、plugin-cri からは `ExecGuardPool` の回収結果を観測できない。
#[derive(Debug, Default, Clone, Copy)]
pub struct UnconfirmedExtinctionProbe;

impl ExecExtinctionProbe for UnconfirmedExtinctionProbe {
    fn confirm(&self, _container: &ContainerId) -> ExtinctionOutcome {
        ExtinctionOutcome::Unknown
    }
}

/// 待ちの期限（本番は既定値。試験が短い値を差す）。
#[derive(Debug, Clone, Copy)]
pub struct ExecBudgets {
    /// stdio の fd を helper へ渡す期限。
    pub handover: Duration,
    /// `Started` を待つ上限。
    pub started: Duration,
    /// helper の `--timeout-ms`（exec の保持の最長）。
    pub session: Duration,
    /// `Result` を待つ余裕（session に足す）。
    pub result_grace: Duration,
}

impl Default for ExecBudgets {
    fn default() -> Self {
        Self {
            handover: HANDOVER_BUDGET,
            started: STARTED_BUDGET,
            session: SESSION_TIMEOUT,
            result_grace: RESULT_GRACE,
        }
    }
}

enum Phase {
    Running,
    Exited(Option<i32>),
    Unconfirmed(CriError),
}

struct Inner {
    phase: Mutex<Phase>,
    changed: Condvar,
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, Phase> {
        self.phase.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 実行中のときだけ遷移させる（終了済みを上書きしない）。
    fn settle_if_running(&self, next: Phase) {
        let mut p = self.lock();
        if matches!(*p, Phase::Running) {
            *p = next;
        }
        drop(p);
        self.changed.notify_all();
    }
}

/// 追跡中の helper（強参照）と停止の印。停止の印と登録を同じ lock で扱う。
#[derive(Default)]
struct Tracker {
    stopped: bool,
    guards: Vec<Arc<HelperGuard>>,
}

fn lock_tracker(t: &Mutex<Tracker>) -> std::sync::MutexGuard<'_, Tracker> {
    t.lock().unwrap_or_else(PoisonError::into_inner)
}

fn untrack(t: &Mutex<Tracker>, guard: &Arc<HelperGuard>) {
    lock_tracker(t).guards.retain(|g| !Arc::ptr_eq(g, guard));
}

/// 本番の `TaskExecLauncher`。
pub struct ShimExecLauncher {
    state_root: PathBuf,
    store: Arc<dyn StateStore>,
    spawner: Arc<dyn HelperSpawner>,
    probe: Arc<dyn ExecExtinctionProbe>,
    budgets: ExecBudgets,
    shared: Arc<Shared>,
    tracker: Arc<Mutex<Tracker>>,
}

impl ShimExecLauncher {
    /// 状態ルート（絶対パス）・状態ストア・helper の起動口・消滅確認の口から作る。
    pub fn new(
        state_root: PathBuf,
        store: Arc<dyn StateStore>,
        spawner: Arc<dyn HelperSpawner>,
        probe: Arc<dyn ExecExtinctionProbe>,
    ) -> Self {
        Self::with_budgets(state_root, store, spawner, probe, ExecBudgets::default())
    }

    /// 期限を指定して作る（試験用）。
    pub(crate) fn with_budgets(
        state_root: PathBuf,
        store: Arc<dyn StateStore>,
        spawner: Arc<dyn HelperSpawner>,
        probe: Arc<dyn ExecExtinctionProbe>,
        budgets: ExecBudgets,
    ) -> Self {
        Self {
            state_root,
            store,
            spawner,
            probe,
            budgets,
            shared: Arc::new(Shared::default()),
            tracker: Arc::new(Mutex::new(Tracker::default())),
        }
    }

    /// 本番の spawner と probe で作る。
    pub fn production(state_root: PathBuf, store: Arc<dyn StateStore>) -> Self {
        Self::new(
            state_root,
            store,
            Arc::new(ProductionHelperSpawner),
            Arc::new(UnconfirmedExtinctionProbe),
        )
    }

    /// 追跡中の helper の数（観測・試験用）。
    pub fn tracked_helpers(&self) -> usize {
        lock_tracker(&self.tracker).guards.len()
    }

    /// 追跡中の全 helper を kill し、以後の `launch` を拒否する（shim の停止時。REPAIR-5）。
    pub fn shutdown_all(&self) {
        let guards = {
            let mut t = lock_tracker(&self.tracker);
            t.stopped = true;
            std::mem::take(&mut t.guards)
        };
        for g in guards {
            g.kill();
        }
    }

    /// spec のうち helper が受けない欄を黙って捨てずに拒否する（cri の `parse_process_spec` との多重防御）。
    fn check_spec(spec: &ExecProcessSpec) -> Result<(), CriError> {
        if !spec.env().is_empty() {
            return Err(CriError::unimplemented("exec env is not supported"));
        }
        if spec.cwd() != "/" {
            return Err(CriError::unimplemented("exec cwd is not supported"));
        }
        if spec.user().is_some() {
            return Err(CriError::unimplemented("exec user is not supported"));
        }
        Ok(())
    }

    /// helper へ空の stdio を渡し `Started` まで進める。
    fn handshake(&self, channel: &std::os::unix::net::UnixStream) -> Result<(), CriError> {
        send_stdio_handover(
            channel,
            &StdioSend {
                stdin: None,
                stdout: None,
                stderr: None,
            },
            Instant::now() + self.budgets.handover,
        )
        .map_err(|e| channel_error(&e))?;
        match recv_from_helper(channel, Instant::now() + self.budgets.started) {
            Ok(HelperMessage::Started) => Ok(()),
            Ok(HelperMessage::Result(outcome)) => Err(match map_outcome(outcome) {
                Err(e) => e,
                Ok(_) => CriError::internal("exec ended before it started"),
            }),
            Ok(HelperMessage::PtyMaster(_)) => Err(CriError::internal("exec failed")),
            Err(e) => Err(channel_error(&e)),
        }
    }
}

impl TaskExecLauncher for ShimExecLauncher {
    fn launch(
        &self,
        container: &ContainerId,
        _exec_id: &ExecId,
        spec: &ExecProcessSpec,
    ) -> Result<Arc<dyn TaskExecProcess>, CriError> {
        Self::check_spec(spec)?;
        if lock_tracker(&self.tracker).stopped {
            return Err(CriError::unavailable("exec launcher is stopped"));
        }
        let slot = self.shared.acquire()?;

        let record = self
            .store
            .get(&GetStateRequest::new(container.clone()))
            .map_err(|e| {
                if e.code() == ErrorCode::NotFound {
                    CriError::not_found("container not found")
                } else {
                    CriError::unavailable("container state is unavailable")
                }
            })?;
        let status = record.status();
        let pid: NonZeroU32 = match (status.state(), status.pid()) {
            (ContainerState::Running, Some(pid)) => pid,
            _ => return Err(CriError::failed_precondition("container is not running")),
        };
        let args = StreamExecArgs::new(
            self.state_root.clone(),
            container.clone(),
            pid,
            self.budgets.session,
            StdioMask::from_presence(false, false, false),
            spec.args().to_vec(),
        )
        .map_err(|_| CriError::invalid_argument("exec request was rejected"))?;

        let SpawnedHelper {
            child,
            channel,
            diagnostics,
        } = self.spawner.spawn(&args)?;
        let diag_stop = Arc::new(AtomicBool::new(false));
        let guard = Arc::new(HelperGuard {
            child: Mutex::new(Some(child)),
            shared: Arc::clone(&self.shared),
            diag_stop: Arc::clone(&diag_stop),
            _slot: slot,
        });
        // helper の fd 2 は CRI の exec と同じく上限つきの読み手で固定語彙の構造化ログへ転送する（#4171）。
        // 作れなくても exec は失敗にしない（観測は最善努力）。
        if let Some(sock) = diagnostics {
            let reader_deadline = Instant::now()
                + self.budgets.started
                + self.budgets.session
                + self.budgets.result_grace;
            let sink = crate::telemetry::stderr_sink().clone();
            if diagnostics::spawn_reader(
                sock,
                diag_stop,
                reader_deadline,
                sink.clone(),
                &self.shared.diag,
            )
            .is_err()
            {
                let _ = sink.submit(diagnostics::reader_unavailable_line());
            }
        }
        {
            let mut t = lock_tracker(&self.tracker);
            if t.stopped {
                drop(t);
                guard.kill();
                return Err(CriError::unavailable("exec launcher is stopped"));
            }
            t.guards.push(Arc::clone(&guard));
        }

        let fail = |e: CriError| {
            untrack(&self.tracker, &guard);
            guard.kill();
            e
        };
        self.handshake(&channel).map_err(fail)?;

        let watch_channel = channel
            .try_clone()
            .map_err(|_| fail(CriError::unavailable("exec channel setup failed")))?;
        let inner = Arc::new(Inner {
            phase: Mutex::new(Phase::Running),
            changed: Condvar::new(),
        });
        let deadline = Instant::now() + self.budgets.session + self.budgets.result_grace;
        let thread_inner = Arc::clone(&inner);
        let thread_guard = Arc::clone(&guard);
        let thread_tracker = Arc::clone(&self.tracker);
        std::thread::Builder::new()
            .name("exec-result".to_string())
            .spawn(move || {
                watch_result(
                    &watch_channel,
                    deadline,
                    &thread_inner,
                    &thread_guard,
                    &thread_tracker,
                );
            })
            .map_err(|_| fail(CriError::unavailable("failed to start the exec watcher")))?;
        drop(channel);

        Ok(Arc::new(ShimExecProcess {
            inner,
            guard: Arc::downgrade(&guard),
            tracker: Arc::clone(&self.tracker),
            probe: Arc::clone(&self.probe),
            container: container.clone(),
        }))
    }
}

/// `Result` を待つ専用スレッドの本体。終了で `Exited`、失敗・期限切れ・切断で未確認にし、追跡から外す。
fn watch_result(
    channel: &std::os::unix::net::UnixStream,
    deadline: Instant,
    inner: &Inner,
    guard: &Arc<HelperGuard>,
    tracker: &Mutex<Tracker>,
) {
    let next = match recv_from_helper(channel, deadline) {
        Ok(HelperMessage::Result(StreamExecOutcome::Failed(code))) => {
            Phase::Unconfirmed(cri_error(code))
        }
        Ok(HelperMessage::Result(outcome)) => match map_outcome(outcome) {
            Ok(code) => Phase::Exited(Some(code)),
            Err(e) => Phase::Unconfirmed(e),
        },
        Ok(_) | Err(_) => {
            guard.kill();
            Phase::Unconfirmed(CriError::unavailable(UNCONFIRMED))
        }
    };
    inner.settle_if_running(next);
    untrack(tracker, guard);
}

/// 起動した exec のハンドル。helper の強参照は追跡一覧と監視スレッドが持ち、ここは弱参照だけ（drop で止めない）。
struct ShimExecProcess {
    inner: Arc<Inner>,
    guard: Weak<HelperGuard>,
    tracker: Arc<Mutex<Tracker>>,
    probe: Arc<dyn ExecExtinctionProbe>,
    container: ContainerId,
}

impl TaskExecProcess for ShimExecProcess {
    fn pid(&self) -> Option<NonZeroU32> {
        None
    }

    fn status(&self) -> Result<ExecProcessStatus, CriError> {
        let err = {
            let p = self.inner.lock();
            match &*p {
                Phase::Running => return Ok(ExecProcessStatus::Running),
                Phase::Exited(code) => return Ok(ExecProcessStatus::Exited { code: *code }),
                Phase::Unconfirmed(e) => e.clone(),
            }
        };
        // lock の外で probe を呼ぶ。確認できたときだけ終了へ進める。
        if self.probe.confirm(&self.container) == ExtinctionOutcome::Confirmed {
            let mut p = self.inner.lock();
            if matches!(*p, Phase::Unconfirmed(_)) {
                *p = Phase::Exited(None);
            }
            drop(p);
            self.inner.changed.notify_all();
            return Ok(ExecProcessStatus::Exited { code: None });
        }
        Err(err)
    }

    fn signal(&self, signal: Signal) -> Result<(), CriError> {
        if matches!(*self.inner.lock(), Phase::Exited(_)) {
            return Err(CriError::not_found("process already finished"));
        }
        if signal != Signal::SIGKILL {
            return Err(CriError::unimplemented("exec signal is not supported"));
        }
        // helper だけを kill する。init へは送らない（SEC-1）。helper が既に無ければ止まっている。
        if let Some(g) = self.guard.upgrade() {
            g.kill();
            untrack(&self.tracker, &g);
        }
        self.inner
            .settle_if_running(Phase::Unconfirmed(CriError::unavailable(UNCONFIRMED)));
        Ok(())
    }

    fn wait_exit(
        &self,
        timeout: Duration,
        _poll_interval: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<i32>, CriError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| CriError::internal("wait deadline overflow"))?;
        loop {
            if cancelled() {
                return Err(CriError::unavailable("wait cancelled"));
            }
            if let ExecProcessStatus::Exited { code } = self.status()? {
                return Ok(code);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(CriError::timeout("wait exceeded its deadline"));
            }
            let slice = WAIT_SLICE.min(deadline - now);
            let p = self.inner.lock();
            if matches!(*p, Phase::Running) {
                // 通知か刻みのどちらか早い方で起きる。
                let _ = self
                    .inner
                    .changed
                    .wait_timeout(p, slice)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        }
    }
}

#[cfg(test)]
mod tests;
