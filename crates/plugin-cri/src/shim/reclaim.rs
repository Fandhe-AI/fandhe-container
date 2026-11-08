//! delete action の停止・回収（CRI-5・CRI-7・PLUG-1・TASK-62.6・REPAIR-3・REPAIR-5・#4152）。
//!
//! 呼び出し元: `shim::delete_in`（記録の照合が `Recorded` のときだけ）。呼び出し先: 実行層（本番は
//! [`crate::adapter::CoreLifecycleRuntime`] の `stop`・`delete`。手順は複製しない）。
//!
//! 段の分解（`delete(force=true)` には寄せない。force は内部で停止しても終了状態を捨てるため、containerd へ返す終了コードが取れない）:
//!
//! | 記録の状態 | 呼び出し | 応答 |
//! | --- | --- | --- |
//! | Stopped | delete だけ | 記録の終了コード・`exited_at` |
//! | pid の無い Created | delete だけ | 終了コード 0（`TaskService` の Delete と同じ） |
//! | Running・pid つき Created | stop（猶予 0・SIGKILL）→ delete | 停止で得た Stopped の終了コード |
//! | Creating・未知の状態 | 呼ばない | `FAILED_PRECONDITION`（fail-closed。core の delete も拒否する） |
//!
//! 期限（REPAIR-5）: containerd は shim の delete を 5 秒（`io.containerd.timeout.shim.cleanup`）で kill するため、全体は
//! bootstrap の絶対期限（`SHIM_DELETE_DEADLINE`。`delete_recorded` が開始時刻から数え、照合・回収・socket 掃除・計測が共有する）に
//! 収める。各段の待ちは段の予算と残り時間の短い方で、照合の読み取り（状態ロックの待ち）も同じ期限で打ち切る。各段を作業スレッドで走らせて `recv_timeout` で待ち、切れたら `DEADLINE_EXCEEDED` を返す
//! （内側の `stop_within` の予算は段の最悪値で admit するため短い予算を一律に拒む。外側の待ちで有界にする）。毎回、照合からやり直すので、
//! 途中で期限切れ・kill されても記録の状態で続きの段から回収できる。回収は照合した記録の世代（bundle・revision）を stop・delete の直前に読み直して確かめ、再作成された別のコンテナに触れない
//! （SEC-1・CORE-1）。回収が触れるのは照合済みの id の記録だけで、`-bundle` は
//! 照合にだけ使い削除の対象にしない。状態記録の pid へ生のシグナルは送らない（PID 再利用対策。SEC-1・CORE-1）。

use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{
    ContainerId, ContainerState, ContainerStatus, CreateStateRequest, DeleteRequest,
    DeleteResponse, DeleteStateRequest, DeleteStateResponse, ErrorCode, GetStateRequest,
    ListStateRequest, Signal, StateList, StateRecord, StateRevision, StateStore, StopRequest,
    TraitError, UpdateStateRequest,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::shim_v2::bootstrap::ShimDeleteExit;

use super::DeleteTarget;

/// delete action 全体の上限（bootstrap の絶対期限と同じ値。段の予算の合計がこれに収まることを試験が照合する）。
#[cfg(test)]
pub(crate) use fandhe_container_cri::shim_v2::bootstrap::SHIM_DELETE_DEADLINE;

/// 照合した記録の世代（bundle と revision。SEC-1・CORE-1・#4152）。
///
/// 照合後に並行する回収が旧記録を消し、同じ id が別の bundle で再作成されたとき、id だけを渡した stop・delete が新しいコンテナに
/// 触れないよう、副作用の直前に記録を読み直して一致を確かめる（不一致は `FAILED_PRECONDITION`。次の delete が照合からやり直す）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Generation {
    bundle: PathBuf,
    revision: StateRevision,
}

impl Generation {
    pub(crate) fn of(rec: &StateRecord) -> Self {
        Self {
            bundle: rec.bundle().to_path_buf(),
            revision: rec.revision(),
        }
    }
}

/// 段ごとの予算。合計が [`SHIM_DELETE_DEADLINE`] 以下であること（試験で照合する）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReclaimBudget {
    /// 停止（SIGKILL の送信と Stopped の確認）の上限。
    pub(crate) stop: Duration,
    /// 削除（core の delete とログ・cgroup の後始末）の上限。
    pub(crate) remove: Duration,
}

impl ReclaimBudget {
    /// 本番の予算（停止 2.5 秒・削除 1.5 秒）。
    pub(crate) const PRODUCTION: Self = Self {
        stop: Duration::from_millis(2500),
        remove: Duration::from_millis(1500),
    };

    /// 内側（core の delete・ログの待ち）に渡す後始末の期限。外側の `remove` の待ちより短くし、内側が `Kept` の応答と
    /// 警告を組み立てる余裕を残す（外側が先に切れると記録だけ消えて `AlreadyReclaimed` になり、cgroup・ログを回収し直せない。
    /// CRI-5・REPAIR-5）。`remove` の 2/3。
    pub(crate) fn cleanup(&self) -> Duration {
        self.remove.saturating_mul(2) / 3
    }

    /// 段の予算の合計（試験が [`SHIM_DELETE_DEADLINE`] に収まることを照合する）。
    #[cfg(test)]
    pub(crate) fn total(&self) -> Duration {
        self.stop.saturating_add(self.remove)
    }
}

/// 回収が使う実行層の窓口（stop と delete だけ）。本番は [`GuardedCore`]、試験は偽の実装。
///
/// 実装は副作用の前に、記録が `generation` と一致することを確かめる（不一致は `FailedPrecondition`）。
/// `stop` は停止後の記録の世代を添えて返し、続く `delete` がそれを使う（停止で revision が進むため）。
pub(crate) trait ReclaimRuntime: Send + Sync + 'static {
    fn stop(
        &self,
        req: &StopRequest,
        generation: &Generation,
    ) -> Result<(ContainerStatus, Generation), TraitError>;
    fn delete(
        &self,
        req: &DeleteRequest,
        generation: &Generation,
    ) -> Result<DeleteResponse, TraitError>;
}

/// 本番の窓口: `CoreLifecycleRuntime` に、照合した bundle への固定（[`PinnedStore`]）を前置きする。
///
/// core が自身の読み取りで得る記録を、照合した bundle と、固定の revision 以上のものに限る（読み取りの結果を検証するので、検証と読み出しの間の窓が無い）。
/// core の stop・delete は読んだ記録の revision を基準に更新・削除するため、再作成された別 bundle のコンテナには届かない
/// （revision は再利用されない。SEC-1・CORE-1・#4152）。revision の変化（supervisor の `Stopped` 記録など同一コンテナの更新）は許す。
pub(crate) struct GuardedCore {
    core: crate::adapter::CoreLifecycleRuntime,
    store: Arc<dyn StateStore>,
    pin: Arc<Mutex<Option<Generation>>>,
}

impl GuardedCore {
    /// `build` へ固定つきの `StateStore` を渡して core を作る（core は渡された store だけを読む）。
    pub(crate) fn new(
        store: Arc<dyn StateStore>,
        build: impl FnOnce(Arc<dyn StateStore>) -> crate::adapter::CoreLifecycleRuntime,
    ) -> Self {
        let pin = Arc::new(Mutex::new(None));
        let pinned: Arc<dyn StateStore> = Arc::new(PinnedStore {
            inner: Arc::clone(&store),
            pin: Arc::clone(&pin),
        });
        Self {
            core: build(pinned),
            store,
            pin,
        }
    }

    fn set_pin(&self, generation: &Generation) {
        if let Ok(mut g) = self.pin.lock() {
            *g = Some(generation.clone());
        }
    }

    fn current(&self, id: &ContainerId, expected: &Generation) -> Result<StateRecord, TraitError> {
        let rec = self.store.get(&GetStateRequest::new(id.clone()))?;
        // bundle だけでなく revision も厳密に照合する。revision は再利用されず（同じ id・同じ bundle で再作成されても
        // 値が変わる）、旧世代の stop・delete が再作成後の記録を受け入れない（SEC-1・CORE-1・#4152）。
        if rec.bundle() != expected.bundle || rec.revision() != expected.revision {
            return Err(changed());
        }
        Ok(rec)
    }
}

fn changed() -> TraitError {
    TraitError::new(
        ErrorCode::FailedPrecondition,
        "container record changed since it was matched",
    )
}

/// 照合した bundle 以外の記録を core に見せない `StateStore`（`get` の結果が固定の bundle と違えば `FailedPrecondition`）。
struct PinnedStore {
    inner: Arc<dyn StateStore>,
    pin: Arc<Mutex<Option<Generation>>>,
}

impl StateStore for PinnedStore {
    fn create(&self, req: &CreateStateRequest) -> Result<StateRecord, TraitError> {
        self.inner.create(req)
    }

    fn update(&self, req: &UpdateStateRequest) -> Result<StateRecord, TraitError> {
        self.inner.update(req)
    }

    fn get(&self, req: &GetStateRequest) -> Result<StateRecord, TraitError> {
        let rec = self.inner.get(req)?;
        let pinned = self.pin.lock().ok().and_then(|g| g.clone());
        // revision は単調増加で再利用されない。固定の revision より小さい記録は別の世代なので拒む。同一コンテナの更新
        // （supervisor の `Stopped` 記録・core 自身の update）で進んだ値は許す（stop が Stopped の記録を待つため、完全一致にはできない。
        // 照合直後の再作成は `current` の完全一致が入口で拒む。残余: 入口の後に同じ bundle で再作成される窓）。
        match pinned {
            Some(p) if p.bundle != rec.bundle() || rec.revision() < p.revision => Err(changed()),
            _ => Ok(rec),
        }
    }

    fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError> {
        self.inner.list(req)
    }

    fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        self.inner.delete(req)
    }

    fn host_state_root(&self) -> Option<&std::path::Path> {
        self.inner.host_state_root()
    }
}

impl ReclaimRuntime for GuardedCore {
    fn stop(
        &self,
        req: &StopRequest,
        generation: &Generation,
    ) -> Result<(ContainerStatus, Generation), TraitError> {
        self.current(req.id(), generation)?;
        self.set_pin(generation);
        let status = fandhe_container_core::traits::ContainerRuntime::stop(&self.core, req)?;
        let after = self.store.get(&GetStateRequest::new(req.id().clone()))?;
        if after.bundle() != generation.bundle || after.status().state() != ContainerState::Stopped
        {
            return Err(changed());
        }
        Ok((status, Generation::of(&after)))
    }

    fn delete(
        &self,
        req: &DeleteRequest,
        generation: &Generation,
    ) -> Result<DeleteResponse, TraitError> {
        self.current(req.id(), generation)?;
        self.set_pin(generation);
        fandhe_container_core::traits::ContainerRuntime::delete(&self.core, req)
    }
}

/// 全体の絶対期限までの残り。尽きていれば固定文言の `DEADLINE_EXCEEDED`（REPAIR-5）。
pub(crate) fn remaining(deadline: Instant, stage: &'static str) -> Result<Duration, CriError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(CriError::timeout(format!(
            "shim delete deadline exhausted before {stage}"
        )));
    }
    Ok(left)
}

/// 段を作業スレッドで走らせ、`limit` で待ちを打ち切る。切れたら固定文言の `DEADLINE_EXCEEDED`。
///
/// 切れた後もスレッドは残るが、shim の delete プロセスは直後に終了するので有界のまま後始末される。
pub(crate) fn run_stage<T, F>(limit: Duration, stage: &'static str, f: F) -> Result<T, CriError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, CriError> + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .name(format!("shim-delete-{stage}"))
        .spawn(move || {
            let _ = tx.send(f());
        })
        .map_err(|_| CriError::internal("cannot start a shim delete stage"))?;
    match rx.recv_timeout(limit) {
        Ok(r) => r,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(CriError::timeout(format!(
            "shim delete {stage} did not finish within the deadline"
        ))),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(CriError::internal("shim delete stage ended unexpectedly"))
        }
    }
}

/// 記録のあるコンテナを止めて回収し、containerd へ返す終了状態を返す（上の表のとおり）。
pub(crate) fn reclaim_recorded(
    rt: Arc<dyn ReclaimRuntime>,
    target: &DeleteTarget,
    rec: &StateRecord,
    budget: &ReclaimBudget,
    deadline: Instant,
) -> Result<ShimDeleteExit, CriError> {
    let generation = Generation::of(rec);
    let id = target.id().clone();
    let before = rec.status();
    let before_pid = before.pid();
    let live = match before.state() {
        ContainerState::Stopped => false,
        ContainerState::Created if before.pid().is_none() => false,
        ContainerState::Running | ContainerState::Created => true,
        _ => {
            return Err(CriError::failed_precondition(
                "container is not in a reclaimable state",
            ));
        }
    };
    let (final_status, generation) = if live {
        let rt = Arc::clone(&rt);
        let id = id.clone();
        let limit = budget.stop.min(remaining(deadline, "stop")?);
        let stopped = run_stage(limit, "stop", move || {
            let req = StopRequest::new(id, Duration::ZERO)
                .map_err(|e| CriError::from(&e))?
                .with_signal(Signal::SIGKILL);
            match rt.stop(&req, &generation) {
                Ok(v) => Ok(Some(v)),
                // 並行する回収が先に消した。目的は達している（remove 段と同じく冪等）。
                Err(e) if e.code() == ErrorCode::NotFound => Ok(None),
                Err(e) => Err(CriError::from(&e)),
            }
        })?;
        match stopped {
            Some(v) => v,
            None => return Ok(ShimDeleteExit::from_core_status(before_pid, before)),
        }
    } else {
        (before.clone(), generation)
    };
    let limit = budget.remove.min(remaining(deadline, "remove")?);
    run_stage(limit, "remove", move || {
        match rt.delete(&DeleteRequest::new(id), &generation) {
            Ok(_) => Ok(()),
            // 並行する回収が先に消した。目的は達している（冪等）。
            Err(e) if e.code() == ErrorCode::NotFound => Ok(()),
            Err(e) => Err(CriError::from(&e)),
        }
    })?;
    Ok(ShimDeleteExit::from_core_status(before_pid, &final_status))
}
