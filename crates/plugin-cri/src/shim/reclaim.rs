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

/// 照合した記録の世代（bundle・revision・cgroup の instance。SEC-1・CORE-1・#4152）。
///
/// 照合後に並行する回収が旧記録を消し、同じ id が別の bundle で再作成されたとき、id だけを渡した stop・delete が新しいコンテナに
/// 触れないよう、副作用の直前に記録を読み直して一致を確かめる（不一致は `FAILED_PRECONDITION`。次の delete が照合からやり直す）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Generation {
    bundle: PathBuf,
    revision: StateRevision,
    /// cgroup 配置の instance（create で割り当てた revision。ストア全体で再利用されず、同一コンテナの更新では変わらない）。
    /// 配置が未記録（`None`）の世代は instance で固定できない（revision の下限と bundle だけで見る。残余）。
    instance: Option<StateRevision>,
    /// 照合時の状態と PID。instance で固定できない世代の再作成を、状態の後退・PID の変化として検出する。
    state: ContainerState,
    pid: Option<u32>,
}

impl Generation {
    pub(crate) fn of(rec: &StateRecord) -> Self {
        Self {
            bundle: rec.bundle().to_path_buf(),
            revision: rec.revision(),
            instance: rec.cgroup().map(|c| c.instance()),
            state: rec.status().state(),
            pid: rec.status().pid().map(Into::into),
        }
    }

    fn rank(state: ContainerState) -> u8 {
        match state {
            ContainerState::Created => 0,
            ContainerState::Running => 1,
            _ => 2,
        }
    }

    /// `rec` が固定した世代の記録として受け入れられるか（`same_container` に加え、revision の下限と、instance 未記録の世代の
    /// 再作成の拒否）。instance が無い世代は、照合時が Created（PID なし）・Stopped なら revision の完全一致、稼働中なら
    /// 状態の後退（再作成後の Created）と PID の変化（再作成後の別プロセス）を拒む（SEC-1・CORE-1・#4152）。
    pub(crate) fn accepts(&self, rec: &StateRecord) -> bool {
        if !self.same_container(rec) || rec.revision() < self.revision {
            return false;
        }
        if self.instance.is_some() {
            return true;
        }
        let live = self.pid.is_some() && Self::rank(self.state) < 2;
        if !live {
            return rec.revision() == self.revision;
        }
        let st = rec.status();
        Self::rank(st.state()) >= Self::rank(self.state)
            && (st.state() == ContainerState::Stopped
                || st.pid().map(Into::<u32>::into) == self.pid)
    }

    /// `rec` が同じコンテナの記録か（bundle が同じで、固定の instance があれば一致する。revision は見ない）。
    fn same_container(&self, rec: &StateRecord) -> bool {
        self.bundle == rec.bundle()
            && self
                .instance
                .is_none_or(|i| rec.cgroup().map(|c| c.instance()) == Some(i))
    }
}

/// core の delete を始めてよい内側期限の下限。これ未満なら delete を始めず `DEADLINE_EXCEEDED` にする（record は残る）。
pub(crate) const MIN_CLEANUP: Duration = Duration::from_millis(1);

/// 段の残り `left` に収まる後始末の期限（`default` を上限に残りの 2/3）。`remove` 段の開始時と、実行層が世代確認（状態ロックの待ちを含む）の
/// 後に残りから決め直すときの両方が使う（REPAIR-5・#4152）。
pub(crate) fn cleanup_within_left(default: Duration, left: Duration) -> Duration {
    default.min(left.saturating_mul(2) / 3)
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

    /// 実際の残り `limit`（remove 段の待ち）に収まる内側の後始末期限。通常は `cleanup()`、残りが小さければ残りの 2/3
    /// （内側が `Kept` の応答を組み立てる余裕を残す）。下限は置かず、外側の `limit` を超えない。残りが
    /// [`MIN_CLEANUP`] に満たない（返り値がそれ未満）ときは、呼び出し側が core の delete を始めない（始めると外側が先に切れ、
    /// record が drop されて cgroup・ログが `AlreadyReclaimed` で回収できなくなる。REPAIR-5・CRI-5）。
    pub(crate) fn cleanup_within(&self, limit: Duration) -> Duration {
        cleanup_within_left(self.cleanup(), limit)
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
/// `delete` の `stage_end` は remove 段の絶対期限で、実装は世代確認の後の残りから後始末の予算と「始めてよいか」を決め直す
/// （足りなければ記録に触れず `Timeout`。REPAIR-5）。
/// `stop` は停止後の記録の世代を添えて返し、続く `delete` がそれを使う（停止で revision が進むため）。停止の後に記録が
/// 消えていたときは世代が `None` で、取得済みの終了状態だけを返す（削除は不要。CRI-5）。
pub(crate) trait ReclaimRuntime: Send + Sync + 'static {
    fn stop(
        &self,
        req: &StopRequest,
        generation: &Generation,
    ) -> Result<(ContainerStatus, Option<Generation>), TraitError>;
    fn delete(
        &self,
        req: &DeleteRequest,
        generation: &Generation,
        stage_end: Instant,
    ) -> Result<DeleteResponse, TraitError>;
}

/// 本番の窓口: `CoreLifecycleRuntime` に、照合した bundle への固定（[`PinnedStore`]）を前置きする。
///
/// core が自身の読み取りで得る記録を、照合した bundle と、固定の revision 以上のものに限る（読み取りの結果を検証するので、検証と読み出しの間の窓が無い）。
/// core の stop・delete は読んだ記録の revision を基準に更新・削除するため、再作成された別 bundle のコンテナには届かない
/// （revision は再利用されない。SEC-1・CORE-1・#4152）。revision の変化（supervisor の `Stopped` 記録など同一コンテナの更新）は許す。
pub(crate) struct GuardedCore {
    build: Box<
        dyn Fn(Arc<dyn StateStore>, Duration) -> crate::adapter::CoreLifecycleRuntime + Send + Sync,
    >,
    pinned: Arc<dyn StateStore>,
    default_cleanup: Duration,
    store: Arc<dyn StateStore>,
    pin: Arc<Mutex<Option<Generation>>>,
    delete_floor: Arc<Mutex<Option<Instant>>>,
}

impl GuardedCore {
    /// `build` へ固定つきの `StateStore` を渡して core を作る（core は渡された store だけを読む）。
    pub(crate) fn new(
        store: Arc<dyn StateStore>,
        default_cleanup: Duration,
        build: impl Fn(Arc<dyn StateStore>, Duration) -> crate::adapter::CoreLifecycleRuntime
        + Send
        + Sync
        + 'static,
    ) -> Self {
        let pin = Arc::new(Mutex::new(None));
        let delete_floor = Arc::new(Mutex::new(None));
        let pinned: Arc<dyn StateStore> = Arc::new(PinnedStore {
            inner: Arc::clone(&store),
            pin: Arc::clone(&pin),
            delete_floor: Arc::clone(&delete_floor),
        });
        Self {
            build: Box::new(build),
            pinned,
            default_cleanup,
            store,
            pin,
            delete_floor,
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
        if !expected.same_container(&rec) || rec.revision() != expected.revision {
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
    /// 記録の削除を始めてよい最後の時刻（core の後始末の期限の途中）。過ぎていれば削除せず `Timeout`（記録を残す。REPAIR-5）。
    delete_floor: Arc<Mutex<Option<Instant>>>,
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
            Some(p) if !p.accepts(&rec) => Err(changed()),
            _ => Ok(rec),
        }
    }

    fn list(&self, req: &ListStateRequest) -> Result<StateList, TraitError> {
        self.inner.list(req)
    }

    fn delete(&self, req: &DeleteStateRequest) -> Result<DeleteStateResponse, TraitError> {
        // 状態の読み取りの待ちで期限の半分を使い切った後に記録を消すと、後始末が全て飛んで外側の期限が先に切れ、
        // 次回は `AlreadyReclaimed` で残りを回収できない。記録を残して失敗にする（REPAIR-5・REPAIR-4・#4152）。
        let floor = self.delete_floor.lock().ok().and_then(|g| *g);
        if floor.is_some_and(|f| Instant::now() > f) {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "shim delete deadline exhausted before the record was removed",
            ));
        }
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
    ) -> Result<(ContainerStatus, Option<Generation>), TraitError> {
        self.current(req.id(), generation)?;
        self.set_pin(generation);
        let core = (self.build)(Arc::clone(&self.pinned), self.default_cleanup);
        let status = fandhe_container_core::traits::ContainerRuntime::stop(&core, req)?;
        let after = match self.store.get(&GetStateRequest::new(req.id().clone())) {
            Ok(after) => after,
            // 停止は成功し、その後に並行する回収が記録を消した。取得済みの終了状態を捨てない（CRI-5）。
            Err(e) if e.code() == ErrorCode::NotFound => return Ok((status, None)),
            Err(e) => return Err(e),
        };
        if !generation.accepts(&after) || after.status().state() != ContainerState::Stopped {
            return Err(changed());
        }
        Ok((status, Some(Generation::of(&after))))
    }

    fn delete(
        &self,
        req: &DeleteRequest,
        generation: &Generation,
        stage_end: Instant,
    ) -> Result<DeleteResponse, TraitError> {
        // 世代確認は状態ロックを待ちうるので、後始末の予算は確認の後の残りから決め直す（開始前に計算した値を使うと、待った分だけ
        // 段の期限を超える。REPAIR-5・#4152）。足りなければ記録に触れずに失敗にする。
        self.current(req.id(), generation)?;
        let left = stage_end.saturating_duration_since(Instant::now());
        let cleanup = cleanup_within_left(self.default_cleanup, left);
        if cleanup < MIN_CLEANUP {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "shim delete deadline exhausted before remove",
            ));
        }
        self.set_pin(generation);
        if let Ok(mut f) = self.delete_floor.lock() {
            *f = Some(Instant::now() + cleanup / 2);
        }
        let core = (self.build)(Arc::clone(&self.pinned), cleanup);
        fandhe_container_core::traits::ContainerRuntime::delete(&core, req)
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

/// 記録のあるコンテナを止めて回収し、containerd へ返す終了状態を返す（上の表のとおり）。停止の前に記録が消えていたとき
/// （終了状態が得られない）は `None`（固定の冪等な応答）。
pub(crate) fn reclaim_recorded(
    rt: Arc<dyn ReclaimRuntime>,
    target: &DeleteTarget,
    rec: &StateRecord,
    budget: &ReclaimBudget,
    deadline: Instant,
) -> Result<Option<ShimDeleteExit>, CriError> {
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
                // 停止の前に並行する回収が消した。終了状態は何も得られていないので、固定の冪等な応答にする
                // （停止前の状態から終了コードを作らない）。
                Err(e) if e.code() == ErrorCode::NotFound => Ok(None),
                Err(e) => Err(CriError::from(&e)),
            }
        })?;
        match stopped {
            Some(v) => v,
            None => return Ok(None),
        }
    } else {
        (before.clone(), Some(generation))
    };
    // 停止の後に記録が消えていた: 削除は済んでいる。取得済みの終了状態を応答に載せる。
    let Some(generation) = generation else {
        return Ok(Some(ShimDeleteExit::from_core_status(
            before_pid,
            &final_status,
        )));
    };
    let left = remaining(deadline, "remove")?;
    let limit = budget.remove.min(left);
    // 内側（core の delete・ログの待ち）の期限は、この段の実際の残りから余裕を引いた値にする。固定の `cleanup()` が残りを
    // 超えると外側が先に切れ、記録だけ消えてログが残る（次回 AlreadyReclaimed。REPAIR-5・CRI-5）。
    let inner = budget.cleanup_within(limit);
    if inner < MIN_CLEANUP {
        // 残りが小さすぎて内側が外側より先に終われない。始めずに記録を残し、次回の delete に回収を委ねる。
        return Err(CriError::timeout(
            "shim delete deadline exhausted before remove".to_string(),
        ));
    }
    let stage_end = Instant::now() + limit;
    run_stage(limit, "remove", move || {
        match rt.delete(&DeleteRequest::new(id), &generation, stage_end) {
            Ok(_) => Ok(()),
            // 並行する回収が先に消した。目的は達している（冪等）。
            Err(e) if e.code() == ErrorCode::NotFound => Ok(()),
            Err(e) => Err(CriError::from(&e)),
        }
    })?;
    Ok(Some(ShimDeleteExit::from_core_status(
        before_pid,
        &final_status,
    )))
}
