//! exec プロセスの終了 watcher と TaskExit（`id = exec_id`）の組み立て（CRI-5・TASK-62.6・REPAIR-3・REPAIR-5・#4317）。
//!
//! [`super::task_service::TaskService`] の `Start(exec_id)` が、起動に成功して TaskExecStarted を投入した直後に
//! [`ExecExitWatch`] を 1 本起こす。watcher は [`TaskExecProcess::wait_exit`] を期限つきで繰り返し、終了を観測したら
//! TaskExit を 1 回だけ publish する。init の終了 watcher（#4155）の exec 版だが、世代の登録表は持たない:
//! 送信権の印（`exit_claim`）と生存確認は [`super::exec::ExecRegistry`] のエントリが持つため、エントリの
//! 除去経路（`Delete(exec_id)`・コンテナの purge・作り直しの掃除）で自動的に watcher は黙る（REPAIR-1）。
//!
//! 契約:
//! - 送信権は `exit_claim` で取り合う。watcher・`Delete(exec_id)`・コンテナの Delete のうち先に取った 1 者だけが送る
//!   （ロック順は claim → 登録簿の内部ロック。watcher はコンテナのゲートを取らない）。
//! - 状態を確かめられないまま終了コードを作らない。照会の失敗が続けば `watch` を記録して止まる。
//! - `exited_at` は設定しない（exec の終了時刻の記録が無い。値を捏造しない。REPAIR-3）。`pid` は取れなければ 0。
//! - 同時に動かす watcher の数は [`MAX_EXEC_EXIT_WATCHERS`] が上限（REPAIR-5）。
//!
//! 残余は `docs/design/shim-v2-production-binary.md` の「exec の TaskExit の送信（#4317）」を参照。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::exec::{ExecId, ExecRegistry, MAX_EXECS_TOTAL, TaskExecProcess, sleep_until};
use super::publish::{
    EventPublisher, PublishFailure, PublishStage, TASK_EXIT_TOPIC, TaskEvent, TaskExit,
};
use super::shutdown::ShutdownSignal;
use super::task_service::exit_status_from_code;
use super::wait::WaitConfig;
use crate::error::CriErrorCode;
use fandhe_container_core::traits::ContainerId;

/// 同時に動かす exec 終了 watcher の上限。起動済みの exec は登録数以下なので、正常系では超えない（REPAIR-5）。
pub(super) const MAX_EXEC_EXIT_WATCHERS: usize = MAX_EXECS_TOTAL;
/// 照会の失敗が続いたときに諦めるまでの連続回数（init の watcher と同じ）。
const EXEC_WATCH_MAX_ERRORS: u32 = 3;

/// 生存数の RAII ガード。スレッドの終了・起動失敗のどちらでも 1 減らす。
pub(super) struct WatchSlot(Arc<AtomicUsize>);

impl WatchSlot {
    /// `limit` 未満のときだけ 1 増やして枠を取る。満杯なら `None`。
    pub(super) fn acquire(count: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < limit).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(count)))
    }
}

impl Drop for WatchSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// exec の TaskExit を組み立てる。watcher と Delete 系が共有する。
/// `id` は exec ID（containerd の CRI は `id != container_id` で exec の TaskExit を除外する）。
pub(super) fn exec_task_exit(
    container: &ContainerId,
    exec_id: &ExecId,
    process: &dyn TaskExecProcess,
    code: Option<i32>,
) -> TaskExit {
    TaskExit {
        container_id: container.as_str().to_owned(),
        id: exec_id.as_str().to_owned(),
        pid: process.pid().map_or(0, std::num::NonZeroU32::get),
        exit_status: exit_status_from_code(code),
        exited_at: None,
    }
}

/// 送信権を取り、未送信なら `exit` を投入する。取れたら `true`。ロックは投入の完了まで保持する。
pub(super) fn claim_and_publish(
    claim: &Mutex<bool>,
    publisher: &dyn EventPublisher,
    exit: impl FnOnce() -> TaskExit,
) -> bool {
    let mut claimed = claim.lock().unwrap_or_else(|p| p.into_inner());
    if *claimed {
        return false;
    }
    *claimed = true;
    publisher.publish(TaskEvent::Exit(exit()));
    true
}

/// exec 終了 watcher 1 本の持ち物。`TaskService::spawn_exec_exit_watcher` が起こすスレッドが所有する。
pub(super) struct ExecExitWatch {
    pub(super) process: Arc<dyn TaskExecProcess>,
    pub(super) execs: Arc<ExecRegistry>,
    pub(super) container: ContainerId,
    pub(super) exec_id: ExecId,
    pub(super) token: u64,
    pub(super) exit_claim: Arc<Mutex<bool>>,
    pub(super) publisher: Arc<dyn EventPublisher>,
    pub(super) wait: WaitConfig,
    pub(super) shutdown: Option<ShutdownSignal>,
    /// スレッドの寿命の間だけ枠を保持する。
    pub(super) _slot: WatchSlot,
}

impl ExecExitWatch {
    fn is_live(&self) -> bool {
        self.execs
            .is_live(&self.container, &self.exec_id, self.token)
    }

    /// 終了を観測して TaskExit を 1 回だけ publish する。`Timeout` は周回を続け、取り消し（Shutdown・登録の除去）は黙って終わる。
    /// その他の失敗は照会間隔だけ待って再試行し、連続 [`EXEC_WATCH_MAX_ERRORS`] 回で `watch` を 1 件記録して諦める。
    pub(super) fn run(&self) {
        let cancelled = || {
            self.shutdown
                .as_ref()
                .is_some_and(ShutdownSignal::is_requested)
                || !self.is_live()
        };
        let mut errors = 0;
        loop {
            if cancelled() {
                return;
            }
            match self
                .process
                .wait_exit(self.wait.timeout(), self.wait.poll_interval(), &cancelled)
            {
                Ok(code) => {
                    self.publish_exit(code);
                    return;
                }
                Err(e) if e.code() == CriErrorCode::Timeout => errors = 0,
                Err(_) => {
                    if cancelled() {
                        return;
                    }
                    errors += 1;
                    if errors >= EXEC_WATCH_MAX_ERRORS {
                        self.publisher.report(PublishFailure::new(
                            PublishStage::Watch,
                            Some(TASK_EXIT_TOPIC),
                        ));
                        return;
                    }
                    sleep_until(Instant::now() + self.wait.poll_interval(), &cancelled);
                }
            }
        }
    }

    /// 送信権を取った側だけが送る。登録が消えていれば（Delete・purge）送らない。
    /// 終了は既に起きた事実なので、世代の guard は付けない。
    fn publish_exit(&self, code: Option<i32>) {
        let mut claimed = self.exit_claim.lock().unwrap_or_else(|p| p.into_inner());
        if *claimed || !self.is_live() {
            return;
        }
        *claimed = true;
        self.publisher.publish(TaskEvent::Exit(exec_task_exit(
            &self.container,
            &self.exec_id,
            self.process.as_ref(),
            code,
        )));
    }
}
