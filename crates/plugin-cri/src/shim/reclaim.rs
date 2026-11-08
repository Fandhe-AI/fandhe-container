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
//! [`SHIM_DELETE_DEADLINE`] に収める。各段を作業スレッドで走らせて `recv_timeout` で待ち、切れたら `DEADLINE_EXCEEDED` を返す
//! （内側の `stop_within` の予算は段の最悪値で admit するため短い予算を一律に拒む。外側の待ちで有界にする）。毎回、照合からやり直すので、
//! 途中で期限切れ・kill されても記録の状態で続きの段から回収できる。回収が触れるのは照合済みの id の記録だけで、`-bundle` は
//! 照合にだけ使い削除の対象にしない。状態記録の pid へ生のシグナルは送らない（PID 再利用対策。SEC-1・CORE-1）。

use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use fandhe_container_core::traits::{
    ContainerState, ContainerStatus, DeleteRequest, DeleteResponse, ErrorCode, Signal, StateRecord,
    StopRequest, TraitError,
};
use fandhe_container_cri::error::CriError;
use fandhe_container_cri::shim_v2::bootstrap::ShimDeleteExit;

use super::DeleteTarget;

/// delete action 全体の上限（予算の根拠の定数。段の予算の合計がこれに収まることを試験が照合する）。containerd の cleanup の 5 秒から、プロセスの起動と応答の書き出しの余裕を引いた値。
#[cfg(test)]
pub(crate) const SHIM_DELETE_DEADLINE: Duration = Duration::from_secs(4);

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

    /// 段の予算の合計（試験が [`SHIM_DELETE_DEADLINE`] に収まることを照合する）。
    #[cfg(test)]
    pub(crate) fn total(&self) -> Duration {
        self.stop.saturating_add(self.remove)
    }
}

/// 回収が使う実行層の窓口（stop と delete だけ）。本番は `CoreLifecycleRuntime`、試験は偽の実装。
pub(crate) trait ReclaimRuntime: Send + Sync + 'static {
    fn stop(&self, req: &StopRequest) -> Result<ContainerStatus, TraitError>;
    fn delete(&self, req: &DeleteRequest) -> Result<DeleteResponse, TraitError>;
}

impl ReclaimRuntime for crate::adapter::CoreLifecycleRuntime {
    fn stop(&self, req: &StopRequest) -> Result<ContainerStatus, TraitError> {
        fandhe_container_core::traits::ContainerRuntime::stop(self, req)
    }

    fn delete(&self, req: &DeleteRequest) -> Result<DeleteResponse, TraitError> {
        fandhe_container_core::traits::ContainerRuntime::delete(self, req)
    }
}

/// 段を作業スレッドで走らせ、`limit` で待ちを打ち切る。切れたら固定文言の `DEADLINE_EXCEEDED`。
///
/// 切れた後もスレッドは残るが、shim の delete プロセスは直後に終了するので有界のまま後始末される。
fn run_stage<T, F>(limit: Duration, stage: &'static str, f: F) -> Result<T, CriError>
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
) -> Result<ShimDeleteExit, CriError> {
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
    let final_status = if live {
        let rt = Arc::clone(&rt);
        let id = id.clone();
        run_stage(budget.stop, "stop", move || {
            let req = StopRequest::new(id, Duration::ZERO)
                .map_err(|e| CriError::from(&e))?
                .with_signal(Signal::SIGKILL);
            rt.stop(&req).map_err(|e| CriError::from(&e))
        })?
    } else {
        before.clone()
    };
    run_stage(budget.remove, "remove", move || {
        match rt.delete(&DeleteRequest::new(id)) {
            Ok(_) => Ok(()),
            // 並行する回収が先に消した。目的は達している（冪等）。
            Err(e) if e.code() == ErrorCode::NotFound => Ok(()),
            Err(e) => Err(CriError::from(&e)),
        }
    })?;
    Ok(ShimDeleteExit::from_core_status(before_pid, &final_status))
}
