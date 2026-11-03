//! exec 子 cgroup の回収の見張り（ガード。Linux。SUP-6・REPAIR-5・REPAIR-4・SEC-1・#2626）。
//!
//! CLI の `exec` が pidfd を受け取った接続（ExecHandoverRequest。[`super::protocol`]）を、supervisor が **閉じずに**
//! 専用スレッドへ預かる。CLI は exec 子 cgroup の排他作成に成功した直後に ExecCgroupNotify（kind 7）でその名前を通知し、
//! ガードは ack を返した後、接続の切断（CLI の正常終了・異常終了・SIGKILL）か保持期限の到来を待って、
//! [`ExecCgroupReclaimer`] でその cgroup を `cgroup.kill` と削除で回収する。
//!
//! # なぜ supervisor 側に置くか
//!
//! `PR_SET_PDEATHSIG` は CLI → worker → 直接のコマンドの 1 段にしか効かず、コマンドが作った子孫へは継承されない。子孫は
//! 既にコンテナ側の cgroup へ移っており、cgroup を掃除する CLI 自身も SIGKILL され得るため、CLI 側では回収できない
//! （`--timeout` を超えた残留。codex の P1）。接続の相手が消えたことを検出して回収できるのは、生存する supervisor だけである。
//!
//! # 契約
//!
//! - 資源は固定: 同時のガード数は [`ExecGuardLimits::max_guards`] で上限を持ち、超えたら pidfd を渡す **前** に
//!   `ExecGuardExhausted` で断る（fail-closed）。ガードは 1 本ずつ専用スレッドで、accept ループ（Signal・Stop の処理）を止めない
//! - 待ちは有界: 通知の待ちは [`ExecGuardLimits::notify_wait`]、見張りは通知の保持期限 + [`ExecGuardLimits::hold_grace`]
//!   （保持期限の上限は [`super::protocol::MAX_EXEC_HOLD_SECS`]）。無期限に待たない（REPAIR-5）
//! - 通知が来ないまま接続が切れたら何もしない（cgroup の作成前に死んだ場合。残骸は exec 開始時の掃除・delete 前の掃除が回収する）
//! - 回収は冪等（通常終了では CLI が先に消していて `Absent`）。結果は [`ControlObserver`] が構造化ログへ出す（REPAIR-4）
//! - ガードのスレッドは再 launch の前に停止する（[`ExecGuardPool::shutdown_all`]。core の本番 launcher の `Threads: 1` 検査のため。SUP-3・#2043）。
//!   通知済みのガードは旧世代の exec 子 cgroup を回収してから終わり、resume の後に [`ExecGuardPool::reopen`] で新しいガードを受ける。
//!   プールは [`super::server::PausableServer`] が保持する
//!
//! # 残余
//!
//! - 通知の ack より前に CLI が消えた窓（作成から通知まで）は回収されない: 空なら既存の掃除に任せる
//! - supervisor 自身が消えた場合は回収されない（コンテナの cgroup ごと delete 前の `KillAll` が回収する）

use std::io::{self, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use fandhe_container_core::exec::{ExecCgroupName, ExecCgroupRemoval, remove_exec_child_cgroup};
use fandhe_container_core::traits::{ContainerId, ErrorCode, StateStore, TraitError};

use super::observe::ControlObserver;
use super::protocol::{
    ControlReason, ExecCgroupNotifyFrame, FrameHeader, HEADER_LEN, MAX_PAYLOAD, ResponseFrame,
};
use super::server::read_exact_until;

/// 同時のガード数の既定の上限。
pub const DEFAULT_MAX_EXEC_GUARDS: usize = 16;

/// 回収の結果（構造化ログの固定語彙。入力値は載せない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReclaimOutcome {
    /// `cgroup.kill` で子孫ごと停止して削除した。
    Removed,
    /// 既に存在しなかった（通常終了で CLI が先に消した）。
    Absent,
    /// 回収できなかった（期限切れ・記録を読めない・cgroup の失敗）。
    Failed,
}

impl ReclaimOutcome {
    /// 構造化ログ用の固定語彙。
    pub fn name(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::Absent => "absent",
            Self::Failed => "failed",
        }
    }
}

/// exec 子 cgroup を回収する役（supervisor が自分のコンテナ記録から導いて実行する。本番は [`StoreExecReclaimer`]、
/// 試験は偽の実装を差す）。実装は有界の時間で戻ること（REPAIR-5）。
pub trait ExecCgroupReclaimer: Send + Sync {
    /// `name` の exec 子 cgroup を子孫ごと停止して削除する。冪等で、存在しなければ [`ReclaimOutcome::Absent`]。
    fn reclaim(&self, name: &ExecCgroupName) -> ReclaimOutcome;
}

/// `cgroup.kill` と削除の待ちの上限（本番の回収役）。
const RECLAIM_TIMEOUT: Duration = Duration::from_secs(2);

/// 本番の回収役: 回収の時点で自分のコンテナの状態記録を読み、記録の cgroup 配置の直下の `exec-*` を
/// [`remove_exec_child_cgroup`] で止める（healthcheck の回収と同じ core の入口。SEC-1: 期待パスは記録の型から core が導く）。
pub struct StoreExecReclaimer {
    store: Arc<dyn StateStore>,
    id: ContainerId,
}

impl StoreExecReclaimer {
    /// 自分のコンテナの `id` と状態ストアから作る。
    pub fn new(store: Arc<dyn StateStore>, id: ContainerId) -> Self {
        Self { store, id }
    }
}

impl ExecCgroupReclaimer for StoreExecReclaimer {
    fn reclaim(&self, name: &ExecCgroupName) -> ReclaimOutcome {
        use fandhe_container_core::traits::GetStateRequest;
        let Ok(record) = self.store.get(&GetStateRequest::new(self.id.clone())) else {
            return ReclaimOutcome::Failed;
        };
        let Some(placement) = record.cgroup() else {
            return ReclaimOutcome::Failed;
        };
        match remove_exec_child_cgroup(&self.id, placement, name, RECLAIM_TIMEOUT) {
            Ok(ExecCgroupRemoval::Removed) => ReclaimOutcome::Removed,
            Ok(ExecCgroupRemoval::Absent) => ReclaimOutcome::Absent,
            Ok(_) | Err(_) => ReclaimOutcome::Failed,
        }
    }
}

/// ガードの期限類。本番の既定は [`Default`]。試験は短い値へ差し替える。
#[derive(Debug, Clone, Copy)]
pub struct ExecGuardLimits {
    /// 同時のガード数の上限。
    pub max_guards: usize,
    /// pidfd を渡した後、ExecCgroupNotify を待つ上限。
    pub notify_wait: Duration,
    /// 通知の保持期限の後ろに足す猶予（CLI の自前の期限切れ処理と後始末が先に終わるための余裕）。
    pub hold_grace: Duration,
    /// ack の書き込みの上限。
    pub write_timeout: Duration,
}

impl Default for ExecGuardLimits {
    fn default() -> Self {
        Self {
            max_guards: DEFAULT_MAX_EXEC_GUARDS,
            notify_wait: Duration::from_secs(10),
            hold_grace: Duration::from_secs(30),
            write_timeout: Duration::from_secs(1),
        }
    }
}

/// ガードの共有状態（回収役・観測・同時数の計数）。accept ループの作り直しをまたいで保持する。
pub struct ExecGuardPool {
    reclaimer: Arc<dyn ExecCgroupReclaimer>,
    observer: Arc<ControlObserver>,
    limits: ExecGuardLimits,
    active: AtomicUsize,
    next_id: AtomicU64,
    state: Mutex<PoolState>,
}

/// プールが追跡するガード（停止要求で起こして join するための控え）。
struct PoolState {
    /// 停止要求の後は新しいガードを受けない（[`ExecGuardPool::reopen`] まで）。
    stopping: bool,
    entries: Vec<GuardEntry>,
}

struct GuardEntry {
    id: u64,
    /// 接続の複製（close-on-exec）。停止要求で `shutdown(Both)` して、待機中の読み取りを EOF で起こす。
    stream: Option<UnixStream>,
    handle: JoinHandle<()>,
}

impl ExecGuardPool {
    /// 回収役・観測・期限類から作る。
    pub fn new(
        reclaimer: Arc<dyn ExecCgroupReclaimer>,
        observer: Arc<ControlObserver>,
        limits: ExecGuardLimits,
    ) -> Arc<Self> {
        Arc::new(Self {
            reclaimer,
            observer,
            limits,
            active: AtomicUsize::new(0),
            next_id: AtomicU64::new(0),
            state: Mutex::new(PoolState {
                stopping: false,
                entries: Vec::new(),
            }),
        })
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 全ガードに停止を要求し、`timeout` 内に全スレッドが終わる（join できる）のを待つ（SUP-3・SUP-6・REPAIR-5・#2043）。
    ///
    /// restart の再 launch は core の本番 launcher が単一スレッド（`Threads: 1`）を要求するため、
    /// [`super::server::PausableServer::pause`] が accept ループを止めた後にこれを呼ぶ。各ガードの接続を `shutdown` して
    /// 読み取りを起こし、通知済みのガードは旧世代の exec 子 cgroup を回収（`trigger=relaunch`）してから終わる
    /// （PID 1 が終わった旧世代の exec は意味を失う）。通知前のガードは何も回収せず終わる。停止要求の後は
    /// [`Self::reopen`] まで新しいガードを受けない。期限内に終わらなければ `Timeout`（呼び出し側は launch しない。
    /// fail-closed。単一スレッド検査を迂回しない）。
    pub fn shutdown_all(&self, timeout: Duration) -> Result<(), TraitError> {
        let mut handles: Vec<JoinHandle<()>> = {
            let mut st = self.lock_state();
            st.stopping = true;
            for e in &st.entries {
                if let Some(stream) = &e.stream {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            }
            std::mem::take(&mut st.entries)
                .into_iter()
                .map(|e| e.handle)
                .collect()
        };
        let until = Instant::now().checked_add(timeout);
        loop {
            let mut rest = Vec::new();
            for h in handles {
                if h.is_finished() {
                    let _ = h.join();
                } else {
                    rest.push(h);
                }
            }
            handles = rest;
            if handles.is_empty() {
                return Ok(());
            }
            if until.is_none_or(|u| Instant::now() >= u) {
                // 終わらなかったスレッドは追跡に戻す（次の停止要求・prune で回収する）。
                let mut st = self.lock_state();
                for handle in handles {
                    st.entries.push(GuardEntry {
                        id: u64::MAX,
                        stream: None,
                        handle,
                    });
                }
                return Err(TraitError::new(
                    ErrorCode::Timeout,
                    "exec guards did not stop in time",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// [`Self::shutdown_all`] の後、再 launch が済んで新しいガードを受けられるようにする。
    pub fn reopen(&self) {
        self.lock_state().stopping = false;
    }

    fn is_stopping(&self) -> bool {
        self.lock_state().stopping
    }

    /// 現在のガード数（試験と観測用）。
    pub fn active(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// 枠を 1 つ確保する。上限に達していれば `None`。枠は [`GuardPermit`] の `Drop` で必ず返る。
    fn try_acquire(self: &Arc<Self>) -> Option<GuardPermit> {
        let mut current = self.active.load(Ordering::SeqCst);
        loop {
            if current >= self.limits.max_guards {
                return None;
            }
            match self.active.compare_exchange(
                current,
                current.saturating_add(1),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Some(GuardPermit {
                        pool: Arc::clone(self),
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// pidfd を渡す **前** に呼ぶ: 枠を確保し、接続を受け取る待機中のガードのスレッドを起こす。
    /// 戻り値の [`GuardSlot`] へ、pidfd の送信に成功した後に接続を [`GuardSlot::start`] で渡す。
    /// 上限超過は `ExecGuardExhausted`、スレッドを作れなければ `ExecGuardExhausted`（fd は渡されない）。
    pub(super) fn reserve(self: &Arc<Self>) -> Result<GuardSlot, ControlReason> {
        let permit = self
            .try_acquire()
            .ok_or(ControlReason::ExecGuardExhausted)?;
        if self.is_stopping() {
            return Err(ControlReason::ExecGuardExhausted);
        }
        let (tx, rx) = channel::<UnixStream>();
        let pool = Arc::clone(self);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let handle = std::thread::Builder::new()
            .name("control-exec-guard".to_owned())
            .spawn(move || run_guard(&pool, id, permit, &rx))
            .map_err(|_| ControlReason::ExecGuardExhausted)?;
        {
            let mut st = self.lock_state();
            // 終わったスレッドは回収して追跡を軽く保つ。
            let (done, live): (Vec<_>, Vec<_>) = std::mem::take(&mut st.entries)
                .into_iter()
                .partition(|e| e.handle.is_finished());
            st.entries = live;
            for e in done {
                let _ = e.handle.join();
            }
            st.entries.push(GuardEntry {
                id,
                stream: None,
                handle,
            });
        }
        Ok(GuardSlot {
            tx,
            pool: Arc::clone(self),
            id,
        })
    }
}

/// ガードの枠（`Drop` で計数を戻す）。
struct GuardPermit {
    pool: Arc<ExecGuardPool>,
}

impl Drop for GuardPermit {
    fn drop(&mut self) {
        self.pool.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 確保済みのガード（スレッドは接続を待っている）。`start` で接続を渡して見張りを始める。
/// 渡さずに drop するとスレッドは終了し、枠が戻る。
pub(super) struct GuardSlot {
    tx: std::sync::mpsc::Sender<UnixStream>,
    pool: Arc<ExecGuardPool>,
    id: u64,
}

impl GuardSlot {
    /// pidfd を送り終えた接続をガードへ渡す。停止要求の後・複製できないときは渡さずに終える（ガードは接続を持たずに
    /// 終わり、クライアントの作成通知は失敗する。fail-closed）。
    pub(super) fn start(self, stream: UnixStream) {
        let Ok(copy) = stream.try_clone() else {
            return;
        };
        {
            let mut st = self.pool.lock_state();
            if st.stopping {
                return;
            }
            match st.entries.iter_mut().find(|e| e.id == self.id) {
                Some(e) => e.stream = Some(copy),
                None => return,
            }
        }
        let _ = self.tx.send(stream);
    }
}

/// ガードのスレッド本体: 通知 → ack → 切断か期限まで待つ → 回収。
fn run_guard(pool: &ExecGuardPool, id: u64, _permit: GuardPermit, rx: &Receiver<UnixStream>) {
    // 終わるとき（どの経路でも）停止用の接続の複製を手放す（複製が残ると fd が閉じない）。
    struct Release<'a>(&'a ExecGuardPool, u64);
    impl Drop for Release<'_> {
        fn drop(&mut self) {
            if let Some(e) = self
                .0
                .lock_state()
                .entries
                .iter_mut()
                .find(|e| e.id == self.1)
            {
                e.stream = None;
            }
        }
    }
    let _release = Release(pool, id);
    let Ok(mut stream) = rx.recv() else {
        return;
    };
    let Some(frame) = await_notify(&mut stream, &pool.limits) else {
        return;
    };
    let mut trigger = hold(&mut stream, &frame, &pool.limits);
    // 再 launch の停止要求で起こされたときは、切断と区別して記録する。
    if trigger == "disconnect" && pool.is_stopping() {
        trigger = "relaunch";
    }
    let outcome = pool.reclaimer.reclaim(&frame.name);
    pool.observer.record_exec_reclaim(trigger, outcome);
}

/// ExecCgroupNotify を期限内に読んで検証し、ack を返す。通知が来ない・壊れている場合は `None`（回収しない）。
/// ack を書けなくても、検証済みの名前は返す（相手が閉じたなら直後の待ちが切断として扱い回収する）。
fn await_notify(
    stream: &mut UnixStream,
    limits: &ExecGuardLimits,
) -> Option<ExecCgroupNotifyFrame> {
    let deadline = Instant::now().checked_add(limits.notify_wait)?;
    stream.set_write_timeout(Some(limits.write_timeout)).ok()?;
    let mut head = [0u8; HEADER_LEN];
    read_exact_until(stream, &mut head, deadline).ok()?;
    let len = match FrameHeader::decode(&head).and_then(FrameHeader::expect_exec_cgroup_notify) {
        Ok(len) => len,
        Err(reason) => return reject(stream, reason),
    };
    let mut payload = [0u8; MAX_PAYLOAD as usize];
    let Some(buf) = payload.get_mut(..len) else {
        return reject(stream, ControlReason::Malformed);
    };
    read_exact_until(stream, buf, deadline).ok()?;
    let frame = match ExecCgroupNotifyFrame::decode_payload(buf) {
        Ok(f) => f,
        Err(reason) => return reject(stream, reason),
    };
    // 保持期限の値域（過去・上限超）も ack の前に確かめる。
    let now_ns = crate::sys::monotonic_now_ns().ok()?;
    if let Err(reason) = frame.hold.remaining_from(now_ns) {
        return reject(stream, reason);
    }
    let ack = ResponseFrame {
        reason: ControlReason::Ok,
    };
    let _ = stream.write_all(&ack.encode());
    Some(frame)
}

/// 拒否の応答を返して `None`（回収しない。名前を信用できない）。
fn reject(stream: &mut UnixStream, reason: ControlReason) -> Option<ExecCgroupNotifyFrame> {
    super::log_control_event("control_request_rejected", Some(reason.name()));
    let _ = stream.write_all(&ResponseFrame { reason }.encode());
    None
}

/// 接続の切断・不正なデータ・保持期限の到来のいずれかまで待ち、その理由（固定語彙）を返す。
fn hold(
    stream: &mut UnixStream,
    frame: &ExecCgroupNotifyFrame,
    limits: &ExecGuardLimits,
) -> &'static str {
    let remaining = crate::sys::monotonic_now_ns()
        .ok()
        .and_then(|now| frame.hold.remaining_from(now).ok())
        .unwrap_or(Duration::ZERO);
    let until = Instant::now()
        .checked_add(remaining)
        .and_then(|t| t.checked_add(limits.hold_grace));
    let Some(until) = until else {
        return "deadline";
    };
    let mut byte = [0u8; 1];
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return "deadline";
        }
        if stream.set_read_timeout(Some(left)).is_err() {
            return "error";
        }
        match stream.read(&mut byte) {
            // クライアントの消滅または正常終了での close。
            Ok(0) => return "disconnect",
            // クライアントはこの後に何も送らない契約。違反は接続を信用せず後始末へ進む。
            Ok(_) => return "protocol",
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return "deadline";
            }
            Err(_) => return "disconnect",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::state_store::{FileStateStore, StateRoot};

    /// SUP-6・SEC-1・#2626: 本番の回収役は、状態記録を読めない（存在しないコンテナ）ときに何も止めず `Failed` を返す
    /// （cgroup 配置を記録から導けないなら、パスを推測しない）。
    #[test]
    fn sup6_sec1_store_reclaimer_fails_closed_without_record() {
        use std::os::unix::fs::DirBuilderExt as _;
        let dir = std::env::temp_dir().join(format!("fc-guard-ut-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let store = FileStateStore::open(StateRoot::from_override(dir.clone()).unwrap()).unwrap();
        let reclaimer =
            StoreExecReclaimer::new(Arc::new(store), ContainerId::new("nothere").unwrap());
        let name = ExecCgroupName::new("exec-1-0").unwrap();
        assert_eq!(reclaimer.reclaim(&name), ReclaimOutcome::Failed);
        assert_eq!(ReclaimOutcome::Failed.name(), "failed");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
