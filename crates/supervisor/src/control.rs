//! supervisor の制御チャネル（コンテナごとの UDS。SUP-1・SEC-1・CORE-1・PLUG-12・REPAIR-2・REPAIR-5・
//! TASK-157 追補・#2058・SUP-9・#2162）。
//!
//! # なぜ存在するか
//!
//! `stop`・`kill` は `state.json` の pid へ生の `kill(2)` を送らない（pid 再利用で無関係なプロセスを止めない。
//! SEC-1・CORE-1）。送信できるのは、起動ハンドル（`LaunchedProcess`）を持つ supervisor だけで、CLI から
//! supervisor へ依頼を届ける経路が要る。常駐デーモンは持たない（CORE-1）ので、コンテナごとの supervisor が
//! 自分の UDS を開き、CLI が接続して依頼する。
//!
//! # 構成
//!
//! | モジュール | 役割 |
//! | ---------- | ---- |
//! | `protocol` | 固定長 frame（Hello・SignalRequest・StopRequest・CancelRestartRequest・ExecHandoverRequest・ExitWatchRequest・AttachRequest・Response）と理由コード。全 OS |
//! | `target` | 起動ハンドルの包み（`ControlledProcess`）と共有状態（`SignalSlot`。exec 用に起動時 pidfd の複製も保持する）。全 OS |
//! | `listener` | 置き場所の検証・bind・削除（Linux） |
//! | `server` | accept ループ・接続元の検証・期限（Linux） |
//! | `exec_guard` | exec 子 cgroup の回収の見張り（pidfd を渡した接続を預かり、切断か期限で回収役を呼ぶ。Linux。#2626） |
//! | `client` | 終了の購読の入口 `ControlExitWatcher`（plugin-cri の `wait_exit` 用。下の「終了の購読」）と、CLI が使う入口 `ControlSignaler`（core の `ProcessSignaler` を実装）と `ControlRestartCanceller`（非 Linux は `Unimplemented`）、Linux のみ `ControlExecHandover`（CLI の `exec` 用に起動時 pidfd の複製を `SCM_RIGHTS` で受け取る。#2626） |
//!
//! # exec 用 pidfd の受け渡し（SUP-6・SEC-1・#2626）
//!
//! CLI の `exec` は `run_command_with_pidfd` に起動時の pidfd を要する（記録 pid からの `pidfd_open` は pid 再利用に弱く、
//! 本番では使わない）。pidfd を持つのは supervisor の監視スレッドだけなので、ExecHandoverRequest（kind 6）で複製を
//! `SCM_RIGHTS` の fd 1 本として返す。`Active` で記録 pid が一致するときだけ渡し（拒否には fd を添えない）、複製は
//! `Exited`・`Empty` へ遷移したら落とす。受け取った CLI は fd を信用せず、`identify_pid1_with_pidfd` が記録 pid との
//! 一致を確かめる。信頼境界は他の要求と同じ（同じ uid・コンテナごとの 0600 のソケット・`SO_PEERCRED` の照合）。
//! 判断記録は `docs/design/exec-pidfd-handover.md`。
//!
//! pidfd を渡した接続は閉じずに専用の「ガード」スレッドが預かる（`exec_guard`）。CLI は exec 子 cgroup の排他作成の直後に
//! ExecCgroupNotify（kind 7）でその名前を通知し、ガードは ack の後、接続の切断（CLI の消滅を含む）か保持期限で、
//! その cgroup を `cgroup.kill` と削除で回収する。PDEATHSIG の届かない子孫（`--timeout` を超えた残留）を、生存する
//! supervisor が回収する（SUP-6・REPAIR-5）。回収役が結線されていない構成は pidfd を渡さない（fail-closed）。
//!
//! # 終了の購読（SUP-1・CRI-1・REPAIR-5・#3683）
//!
//! plugin-cri の `wait_exit` が、コンテナの終了を状態の照会（既定 100ms 間隔）ではなく通知で待つための口。ExitWatchRequest
//! （kind 8）で購読すると、supervisor は `Response(Ok)` の後、コンテナの終了（init の回収）・世代交代・保持期限（最大 60 秒）の
//! いずれかで接続を閉じ、購読者はそれを起床の合図にして状態ストアを読み直す。通知はヒントに過ぎず、返す状態は常に状態
//! ストアの記録である。クライアント入口は [`ExitNotifier`]（本番は [`production_exit_notifier`] の [`ControlExitWatcher`]、
//! 試験は差し替え）。通知が使えない（supervisor 不在・古い版・非 Linux）ときは [`ExitWatchOutcome::NoSupervisor`] を返し、
//! 呼び出し側は照会へ退避する。新しいスレッドは作らない（サーバは接続の複製をスロットに預け、クライアントは 10ms 刻みの
//! 読み取りで取り消しと期限を見る）。
//!
//! # Attach 用 fd の受け渡し（SUP-4・SUP-7・REPAIR-2・SEC-1・CRI-6・#4075）
//!
//! plugin-cri の Attach が、init の stdin の書き込み端（tty では pty master の複製）と出力の tap の端を受け取る口。
//! AttachRequest（kind 9）は固定長の 1 往復で、`Response(Ok)` と同じ `sendmsg` に fd を最大 3 本添えて返し、接続は
//! 保持しない。非 tty の `stdin_once` では元の端そのものを渡し（所有の移転。受け手が唯一の書き込み端を持つので、
//! 受け手が閉じるとコンテナの stdin が EOF になる）、送れなかったときは同じ世代にだけ戻す。tty の `stdin_once` は
//! master を複製して渡し、閉じない。クライアント入口は `AttachIoSource`（本番は `production_attach_io_source` の
//! `ControlAttach`）。古い supervisor は kind 9 を `Malformed` で断り、クライアントは `Unavailable` を返す
//! （別の手段へ切り替えない）。結線は plugin-cri の C9（#4077）。設計は `docs/design/cri-streaming-server.md`。
//!
//! # 寿命
//!
//! 作成は supervisor の入口（`start_entry`）が `Running` を受け取った直後、`run_supervised` の前。単一スレッドを
//! 要する launch（手順 8）より後なので制約に触れない。削除は `run_supervised` が返った後（RAII）。作成に
//! 失敗したら、停止できないコンテナを残さないよう停止を要求する（fail-closed）。
//!
//! # 未実装・残余（REPAIR-3）
//!
//! - CLI の `kill` は結線済み（#1902。`ControlSignaler::new`〔stop の意図を立てない kind 2〕。`stop` は
//!   `stop_delete::production_stop_signaler`。#2059・#2162）。残余: moby の `kill` は SIGKILL か StopSignal と一致するとき再起動を
//!   止めるが、本実装は意図を立てないため `kill <id> KILL` の後に再起動されうる（Docker 互換にするかはオーナー判断待ち）
//! - 明示 stop の意図は StopRequest（kind 4。稼働中）か CancelRestartRequest（kind 5。バックオフ・再 launch 中。#2440）が
//!   `StopToken::mark_explicit_stop` で立て、restart の判定が読む（SUP-9・#2162）。supervisor の寿命の中では `always`・
//!   `unless-stopped` を含む全ポリシーで、stop 後は再起動しない。明示 stop は `restart` ループが state.json の `Stopped` の記録へ
//!   「明示 stop 済み」（トレイト契約 14）として残す。記録に失敗したら再起動せず非 0 で終わる（fail-closed）。取り消しの `Ok` は
//!   「この supervisor は再起動しない」の意味で、記録の成否は応答に含まれない（失敗は supervisor のログと終了コードで見える）。
//!   終了から記録までの間に supervisor が死んだ場合も記録は残らず、その後の re-adopt では `unless-stopped` が起こし得る。
//!   re-adopt 本体（`restart::evaluate_resume` を呼ぶ側）は未実装（#514・SUP-8）
//! - restart の再 launch を単一スレッドで行う再構成（#2043）では、制御チャネルのスレッドも止める対象になる
//!   （再 launch の間は `PausableServer::pause` / `resume` で止めて作り直す。#2043）
//! - 異常終了で残った `supervisor.sock` は、core の `StateStore::delete`（`FileStateStore`）が `<id>/` を開いた fd を
//!   起点に種別（ソケット）と所有者（実効 UID）を検証してから消す（#2174・OCI-6・SUP-1）。ソケット以外・他 UID 所有の
//!   同名は消さず `<id>/` を残す。`purge_corrupted` は触れない
//! - `start` の OK 報告は制御チャネルの作成より前に送信済みのため、作成に失敗した場合は報告を取り消せない。
//!   停止を要求し、supervisor の終了コードを非 0 にして `Stopped` を記録する（報告の順序の再構成は別 issue）

pub mod client;
pub mod protocol;
pub mod target;

#[cfg(target_os = "linux")]
pub mod exec_guard;
#[cfg(target_os = "linux")]
pub mod listener;
#[cfg(target_os = "linux")]
pub mod observe;
#[cfg(target_os = "linux")]
pub(crate) mod os_errno;
#[cfg(target_os = "linux")]
pub mod server;

pub use client::{CancelOutcome, ControlExitWatcher, ControlRestartCanceller, ControlSignaler};
#[cfg(target_os = "linux")]
pub use client::{ControlAttach, ControlExecHandover};
#[cfg(target_os = "linux")]
pub use exec_guard::{
    ExecCgroupReclaimer, ExecGuardLimits, ExecGuardPool, ReclaimOutcome, StoreExecReclaimer,
};

/// 状態ルートを公開しないストア用の fail-closed の signaler。常に `Unimplemented` で失敗する（REPAIR-3）。
///
/// [`production_signaler`]・[`production_stop_signaler`] が `host_state_root()` の無いストアに対してだけ返す。
/// 送らないことで `state.json` の pid への縮退を防ぐ（SEC-1・CORE-1）。
pub struct UnavailableSignaler;

impl fandhe_container_core::oci_runtime::ProcessSignaler for UnavailableSignaler {
    fn signal(
        &self,
        _id: &fandhe_container_core::traits::ContainerId,
        _pid: std::num::NonZeroU32,
        _signal: fandhe_container_core::traits::Signal,
        _deadline: std::time::Instant,
    ) -> Result<(), fandhe_container_core::traits::TraitError> {
        Err(fandhe_container_core::traits::TraitError::new(
            fandhe_container_core::traits::ErrorCode::Unimplemented,
            "process signaler is not available yet",
        ))
    }
}

/// 本番の signaler（stop の意図を記録させない版。`kill` 用。#2059・#1902。CLI-1・SEC-1・CORE-1）。
///
/// CLI の `kill` 系の注入点と plugin-cri の `kill` が呼ぶ。`<host_state_root>/<id>/supervisor.sock` の supervisor へ依頼する
/// [`ControlSignaler`] を返し、到達できなければ構造化エラーで失敗する。`state.json` の pid へ `kill(2)` する縮退は持たない。
/// ルートに `host_state_root()` を使うのは、supervisor のログルートと揃い、cfg を呼び出し側に持ち込まないため。
/// supervisor の bind 側（`args.root`）との違いは親の symlink の解決だけで、`<root>/<id>` は同じディレクトリを指す。
pub fn production_signaler(
    store: &dyn fandhe_container_core::traits::StateStore,
) -> std::sync::Arc<dyn fandhe_container_core::oci_runtime::ProcessSignaler> {
    match store.host_state_root() {
        Some(root) => std::sync::Arc::new(ControlSignaler::new(root.to_path_buf())),
        None => std::sync::Arc::new(UnavailableSignaler),
    }
}

/// 本番の `stop` 用 signaler（SUP-9・#2162）。[`production_signaler`] と同じ到達先・縮退なしの規則だが、
/// `ControlSignaler::for_stop` で StopRequest を送り、supervisor に明示 stop の意図を記録させてから SIGTERM を渡す。
/// 意図を記録できない supervisor（書き先なし・古い版）には送らず、構造化エラーで失敗する（fail-closed）。
pub fn production_stop_signaler(
    store: &dyn fandhe_container_core::traits::StateStore,
) -> std::sync::Arc<dyn fandhe_container_core::oci_runtime::ProcessSignaler> {
    match store.host_state_root() {
        Some(root) => std::sync::Arc::new(ControlSignaler::for_stop(root.to_path_buf())),
        None => std::sync::Arc::new(UnavailableSignaler),
    }
}

/// バックオフ中・再 launch 中の stop で、supervisor の保留中の再起動を取り消す注入点（SUP-9・SUP-3・#2440）。
///
/// CLI の `stop`（`Stopped` の記録に対する分岐）が呼ぶ。本番は [`ControlRestartCanceller`]、CLI の試験は差し替える。
pub trait PendingRestartCanceller: Send + Sync {
    /// `deadline` までに取り消しを依頼し、結果を返す。シグナルは送らない。
    fn cancel(
        &self,
        id: &fandhe_container_core::traits::ContainerId,
        deadline: std::time::Instant,
    ) -> Result<CancelOutcome, fandhe_container_core::traits::TraitError>;
}

/// 状態ルートを公開しないストア用の fail-closed の canceller。常に `Unimplemented` で失敗する（REPAIR-3）。
pub struct UnavailableRestartCanceller;

impl PendingRestartCanceller for UnavailableRestartCanceller {
    fn cancel(
        &self,
        _id: &fandhe_container_core::traits::ContainerId,
        _deadline: std::time::Instant,
    ) -> Result<CancelOutcome, fandhe_container_core::traits::TraitError> {
        Err(fandhe_container_core::traits::TraitError::new(
            fandhe_container_core::traits::ErrorCode::Unimplemented,
            "restart canceller is not available yet",
        ))
    }
}

/// 本番の canceller（`stop` が `Stopped` の記録に当たったとき用。SUP-9・SUP-3・#2440）。
/// [`production_stop_signaler`] と同じ到達先の規則で、`host_state_root()` の無いストアには fail-closed の実装を返す。
pub fn production_restart_canceller(
    store: &dyn fandhe_container_core::traits::StateStore,
) -> std::sync::Arc<dyn PendingRestartCanceller> {
    match store.host_state_root() {
        Some(root) => std::sync::Arc::new(ControlRestartCanceller::new(root.to_path_buf())),
        None => std::sync::Arc::new(UnavailableRestartCanceller),
    }
}

/// [`ExitNotifier::watch`] の結果（SUP-1・CRI-1・REPAIR-5・#3683）。いずれも「状態ストアを読み直す」か「通知を諦める」の
/// 合図で、コンテナが終了したという主張ではない（正しさは状態ストアに置く）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitWatchOutcome {
    /// 終了の通知（または既に終了済みの応答）を受けた。状態を読み直す。
    Woken,
    /// 要求の pid と supervisor が保持する pid が違う（再起動などで入れ替わった）。状態を読み直す。
    PidChanged,
    /// 購読の期限（`until`）まで何も起きなかった。状態を読み直して、必要なら購読し直す。
    Expired,
    /// 呼び出し側の取り消し（`cancel` が真）で中断した。
    Cancelled,
    /// 届く supervisor が無い・通知を知らない古い版・信頼できない相手・非 Linux。以後この呼び出しでは通知を使わない。
    NoSupervisor,
    /// 一時的な失敗（枠が満杯・ハンドシェイクの期限・I/O の失敗）。1 回分は照会で待ち、次の周回で購読をやり直す。
    Transient,
}

/// コンテナの終了を通知で待つ注入点（plugin-cri の `wait_exit` 用。SUP-1・CRI-1・REPAIR-5・#3683）。
///
/// 本番は [`ControlExitWatcher`]（supervisor の制御チャネルの ExitWatchRequest）、試験は差し替える。
pub trait ExitNotifier: Send + Sync {
    /// `pid`（記録上の pid1）のコンテナの終了を `until` まで購読する。`cancel` は 10ms 程度の刻みで確かめ、真なら
    /// [`ExitWatchOutcome::Cancelled`] で戻る。`until` を超えて待たない。シグナルは送らず、fd も受け取らない。
    fn watch(
        &self,
        id: &fandhe_container_core::traits::ContainerId,
        pid: std::num::NonZeroU32,
        until: std::time::Instant,
        cancel: &dyn Fn() -> bool,
    ) -> ExitWatchOutcome;
}

/// 本番の終了購読の入口（#3683）。`host_state_root()` の無いストアには `None`（通知は使わず、呼び出し側は照会だけで待つ。
/// `state.json` の pid に頼る縮退は持たない）。
pub fn production_exit_notifier(
    store: &dyn fandhe_container_core::traits::StateStore,
) -> Option<std::sync::Arc<dyn ExitNotifier>> {
    store.host_state_root().map(|root| {
        std::sync::Arc::new(ControlExitWatcher::new(root.to_path_buf()))
            as std::sync::Arc<dyn ExitNotifier>
    })
}

/// 稼働中コンテナの起動時 pidfd の複製を取得する注入点（CLI の `exec` 用。SUP-6・SEC-1・CLI-1・#2626）。Linux のみ。
///
/// 本番は [`ControlExecHandover`]（supervisor の制御チャネルの ExecHandoverRequest）、CLI の試験は差し替える。
/// 取得した fd を信用しない: 呼び出し側が `exec::identify_pid1_with_pidfd`（`run_command_with_pidfd`）で記録 pid との一致を
/// 確かめる。`state.json` の pid からの `pidfd_open` への縮退は持たない（pid 再利用。SEC-1）。
#[cfg(target_os = "linux")]
pub trait ExecPidfdSource: Send + Sync {
    /// `deadline` までに、`pid`（記録上の pid1）の起動時 pidfd の複製を受け取る。supervisor に届かない・保持していない・
    /// pid 不一致・古い版の supervisor・回収役の無い supervisor・ガードの上限などは構造化エラー（fd は渡らない）。
    /// 返す [`ExecHandover`] は supervisor との接続を保持する。呼び出し側は exec が終わり後始末を済ませるまで
    /// 生かし、その後に drop する（drop が切断で、supervisor の回収の合図になる）。
    fn obtain(
        &self,
        id: &fandhe_container_core::traits::ContainerId,
        pid: std::num::NonZeroU32,
        deadline: std::time::Instant,
    ) -> Result<ExecHandover, fandhe_container_core::traits::TraitError>;

    /// [`Self::obtain`] と同じだが、失敗に OS の errno を添えて返す（stream-exec helper の診断行用。SUP-6・REPAIR-4・#4284）。
    /// 既定は errno なしで [`Self::obtain`] を包む（errno を運べない実装は従来どおり）。
    fn obtain_with_errno(
        &self,
        id: &fandhe_container_core::traits::ContainerId,
        pid: std::num::NonZeroU32,
        deadline: std::time::Instant,
    ) -> Result<ExecHandover, ExecControlFailure> {
        self.obtain(id, pid, deadline)
            .map_err(ExecControlFailure::from)
    }
}

/// 制御チャネルの失敗と、その原因の OS の errno（分かるときだけ）。stream-exec helper の診断行が段名と一緒に出す
/// （SUP-6・REPAIR-4・#4284）。core の `TraitError` は errno を持たないため、supervisor 内でだけ添えて運ぶ。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecControlFailure {
    error: fandhe_container_core::traits::TraitError,
    errno: Option<i32>,
}

#[cfg(target_os = "linux")]
impl ExecControlFailure {
    /// 失敗と errno から作る。
    pub fn new(error: fandhe_container_core::traits::TraitError, errno: Option<i32>) -> Self {
        Self { error, errno }
    }

    /// 構造化エラー。
    pub fn error(&self) -> &fandhe_container_core::traits::TraitError {
        &self.error
    }

    /// OS の errno（OS 由来でない失敗は `None`）。
    pub fn errno(&self) -> Option<i32> {
        self.errno
    }

    /// 構造化エラーだけを取り出す。
    pub fn into_error(self) -> fandhe_container_core::traits::TraitError {
        self.error
    }
}

#[cfg(target_os = "linux")]
impl From<fandhe_container_core::traits::TraitError> for ExecControlFailure {
    fn from(error: fandhe_container_core::traits::TraitError) -> Self {
        Self { error, errno: None }
    }
}

/// exec 子 cgroup の作成を、pidfd を渡した supervisor へ通知する口（SUP-6・REPAIR-5・#2626）。
///
/// 本番は制御チャネルの接続（ExecCgroupNotify）、CLI の試験は記録する偽の実装に差し替える。
#[cfg(target_os = "linux")]
pub trait ExecCreatedNotifier: Send {
    /// 排他作成に成功した exec 子 cgroup `name` を通知し、supervisor の ack を待つ。`hold_until` は exec 全体の期限
    /// （supervisor はこの期限 + 猶予まで接続を見張る）。失敗したら呼び出し側は worker を fork せず exec を中止する。
    fn notify_created(
        &self,
        name: &fandhe_container_core::exec::ExecCgroupName,
        hold_until: std::time::Instant,
    ) -> Result<(), fandhe_container_core::traits::TraitError>;

    /// [`Self::notify_created`] と同じだが、失敗に OS の errno を添える（#4284）。既定は errno なしで包む。
    fn notify_created_with_errno(
        &self,
        name: &fandhe_container_core::exec::ExecCgroupName,
        hold_until: std::time::Instant,
    ) -> Result<(), ExecControlFailure> {
        self.notify_created(name, hold_until)
            .map_err(ExecControlFailure::from)
    }
}

/// [`ExecPidfdSource::obtain`] の結果: 起動時 pidfd の複製と、supervisor との接続（作成通知の口）。
///
/// drop でこの接続が閉じる。supervisor は通知済みの cgroup を、接続が閉じた時点で回収する（通常終了では CLI が先に
/// 消していて何も起きない）。
#[cfg(target_os = "linux")]
pub struct ExecHandover {
    pidfd: std::os::fd::OwnedFd,
    notifier: Box<dyn ExecCreatedNotifier>,
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for ExecHandover {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecHandover").finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
impl ExecHandover {
    /// pidfd と通知の口から作る。
    pub fn new(pidfd: std::os::fd::OwnedFd, notifier: Box<dyn ExecCreatedNotifier>) -> Self {
        Self { pidfd, notifier }
    }

    /// 受け取った pidfd（信用せず、呼び出し側が記録 pid との一致を確かめる）。
    pub fn pidfd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self.pidfd)
    }

    /// exec 子 cgroup の作成を supervisor へ通知する（[`ExecCreatedNotifier::notify_created`]）。
    pub fn notify_created(
        &self,
        name: &fandhe_container_core::exec::ExecCgroupName,
        hold_until: std::time::Instant,
    ) -> Result<(), fandhe_container_core::traits::TraitError> {
        self.notifier.notify_created(name, hold_until)
    }

    /// [`Self::notify_created`] の errno つき版（#4284）。
    pub fn notify_created_with_errno(
        &self,
        name: &fandhe_container_core::exec::ExecCgroupName,
        hold_until: std::time::Instant,
    ) -> Result<(), ExecControlFailure> {
        self.notifier.notify_created_with_errno(name, hold_until)
    }
}

/// 状態ルートを公開しないストア用の fail-closed の取得元。常に `Unimplemented` で失敗する（REPAIR-3）。
#[cfg(target_os = "linux")]
pub struct UnavailableExecPidfdSource;

#[cfg(target_os = "linux")]
impl ExecPidfdSource for UnavailableExecPidfdSource {
    fn obtain(
        &self,
        _id: &fandhe_container_core::traits::ContainerId,
        _pid: std::num::NonZeroU32,
        _deadline: std::time::Instant,
    ) -> Result<ExecHandover, fandhe_container_core::traits::TraitError> {
        Err(fandhe_container_core::traits::TraitError::new(
            fandhe_container_core::traits::ErrorCode::Unimplemented,
            "exec pidfd source is not available yet",
        ))
    }
}

/// 本番の exec 用 pidfd 取得元。[`production_stop_signaler`] と同じ到達先の規則で、`host_state_root()` の無いストアには
/// fail-closed の実装を返す（縮退しない。SEC-1・CORE-1）。
#[cfg(target_os = "linux")]
pub fn production_exec_pidfd_source(
    store: &dyn fandhe_container_core::traits::StateStore,
) -> std::sync::Arc<dyn ExecPidfdSource> {
    match store.host_state_root() {
        Some(root) => std::sync::Arc::new(ControlExecHandover::new(root.to_path_buf())),
        None => std::sync::Arc::new(UnavailableExecPidfdSource),
    }
}

/// [`AttachIoSource::obtain`] の要求（SUP-4・SUP-7・CRI-6・#4075）。受け取りたい fd の指定と、想定する入出力の構成。
/// tty と stderr の併用は `InvalidArgument`（tty は stdout と stderr が混ざる）。
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachIoRequest {
    /// 入力（stdin の書き込み端。tty では pty master の複製）を受け取る。
    pub stdin: bool,
    /// stdout の tap を受け取る。
    pub stdout: bool,
    /// stderr の tap を受け取る（tty とは併用できない）。
    pub stderr: bool,
    /// 想定する構成が pty か（コンテナの構成と合わなければ `FailedPrecondition`）。
    pub tty: bool,
}

/// Attach の入力 fd（検証済み。SEC-1）。
#[cfg(target_os = "linux")]
pub enum AttachInput {
    /// 非 tty の stdin の書き込み端（pipe。`stdin_once` では唯一の書き込み端 = 所有の移転を受けたもの）。
    Pipe(std::os::fd::OwnedFd),
    /// tty の pty master の複製（`5:2` と `TIOCGPTN` を確認済み）。書き込みと `TIOCSWINSZ` 専用で、読むと
    /// ログの捕捉から出力を奪うので読まない（出力は tap の端で受ける）。
    Pty(fandhe_container_core::exec::PtyMaster),
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for AttachInput {
    /// fd の番号や内容は出さない。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pipe(_) => "AttachInput::Pipe",
            Self::Pty(_) => "AttachInput::Pty",
        })
    }
}

/// [`AttachIoSource::obtain`] の結果: 入力の fd と出力の tap の端。要求しなかったものは `None`。drop で閉じる。
#[cfg(target_os = "linux")]
pub struct AttachIo {
    /// 入力（stdin の書き込み端、または tty の master の複製）。
    pub input: Option<AttachInput>,
    /// stdout の tap の端（ブロッキング）。
    pub stdout: Option<std::os::unix::net::UnixStream>,
    /// stderr の tap の端（ブロッキング。tty では常に `None`）。
    pub stderr: Option<std::os::unix::net::UnixStream>,
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for AttachIo {
    /// 有無だけを出す（fd の番号や内容は出さない）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachIo")
            .field("input", &self.input)
            .field("stdout", &self.stdout.is_some())
            .field("stderr", &self.stderr.is_some())
            .finish()
    }
}

/// 稼働中コンテナの Attach 用の入力 fd と出力の tap を取得する注入点（plugin-cri の Attach 用。
/// SUP-4・SUP-7・REPAIR-2・SEC-1・CRI-6・#4075）。Linux のみ。
///
/// 本番は [`ControlAttach`]（supervisor の制御チャネルの AttachRequest）、plugin-cri の試験は差し替える。
/// 結線は plugin-cri の C9（#4077）。
#[cfg(target_os = "linux")]
pub trait AttachIoSource: Send + Sync {
    /// `deadline`（実際の期限は 5 秒以内に抑えられる）までに、`pid`（記録上の pid1）の入出力を受け取る。
    /// supervisor に届かない・古い版（`Unavailable`）・pid 不一致・tty の不一致・`stdin_once` の消費済みなどは
    /// 構造化エラーで、fd は渡らない（受け取った fd は閉じる）。
    fn obtain(
        &self,
        id: &fandhe_container_core::traits::ContainerId,
        pid: std::num::NonZeroU32,
        request: AttachIoRequest,
        deadline: std::time::Instant,
    ) -> Result<AttachIo, fandhe_container_core::traits::TraitError>;
}

/// 状態ルートを公開しないストア用の fail-closed の取得元。常に `Unimplemented` で失敗する（REPAIR-3）。
#[cfg(target_os = "linux")]
pub struct UnavailableAttachIoSource;

#[cfg(target_os = "linux")]
impl AttachIoSource for UnavailableAttachIoSource {
    fn obtain(
        &self,
        _id: &fandhe_container_core::traits::ContainerId,
        _pid: std::num::NonZeroU32,
        _request: AttachIoRequest,
        _deadline: std::time::Instant,
    ) -> Result<AttachIo, fandhe_container_core::traits::TraitError> {
        Err(fandhe_container_core::traits::TraitError::new(
            fandhe_container_core::traits::ErrorCode::Unimplemented,
            "attach io source is not available yet",
        ))
    }
}

/// 本番の Attach 用 fd 取得元。[`production_exec_pidfd_source`] と同じ到達先の規則で、`host_state_root()` の無い
/// ストアには fail-closed の実装を返す（縮退しない。SEC-1・CORE-1）。
#[cfg(target_os = "linux")]
pub fn production_attach_io_source(
    store: &dyn fandhe_container_core::traits::StateStore,
) -> std::sync::Arc<dyn AttachIoSource> {
    match store.host_state_root() {
        Some(root) => std::sync::Arc::new(ControlAttach::new(root.to_path_buf())),
        None => std::sync::Arc::new(UnavailableAttachIoSource),
    }
}

/// 構造化ログを stderr に 1 行出す（値は固定語彙だけ。入力値・uid・パス・errno は載せない。REPAIR-4）。
///
/// 待たない出力経路（`stderr_sink`）へ渡すだけで、キューが満杯なら捨てる（REPAIR-5）。
#[cfg(target_os = "linux")]
pub(crate) fn log_control_event(event: &'static str, reason: Option<&'static str>) {
    let reason = reason.unwrap_or("");
    let line =
        format!("{{\"component\":\"supervisor\",\"event\":\"{event}\",\"reason\":\"{reason}\"}}\n");
    let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
}

#[cfg(target_os = "linux")]
pub use install::{ControlHandle, install, install_with_exec_reclaimer};

#[cfg(target_os = "linux")]
mod install {
    use std::path::Path;
    use std::sync::Arc;

    use fandhe_container_core::audit_log::AuditSink;
    use fandhe_container_core::oci_runtime::exit_code_for;
    use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

    use super::exec_guard::{ExecCgroupReclaimer, ExecGuardLimits, ExecGuardPool};
    use super::listener::{ControlListener, effective_uid};
    use super::observe::ControlObserver;
    use super::server::{PausableServer, ServeConfig};
    use super::target::{ControlledProcess, ControlledRelauncher, SignalSlot};
    use crate::run::StopToken;
    use crate::start_entry::Running;

    /// 制御チャネルの後始末（`Drop` でサーバスレッドを止め、その後にソケットを消す）。
    ///
    /// フィールドの宣言順がそのまま drop 順で、サーバを先に止めてから listener の `Drop` が最終名を消す。
    /// 作成に失敗していたら [`Self::failure`] が構造化エラーを返す。
    #[must_use = "dropping the handle stops the control channel"]
    pub struct ControlHandle {
        server: Option<Arc<PausableServer>>,
        _listener: Option<ControlListener>,
        failure: Option<TraitError>,
    }

    impl Drop for ControlHandle {
        /// サーバスレッドを先に止め、その後にフィールドの drop が listener を閉じてソケットを消す。
        /// relauncher が `Arc` を保持していても、ここで確実に止める（#2043）。
        fn drop(&mut self) {
            if let Some(server) = self.server.take() {
                server.shutdown();
            }
        }
    }

    impl ControlHandle {
        /// 作成の失敗（機械可読な code と message。入力値を含まない）。成功なら `None`。
        pub fn failure(&self) -> Option<&TraitError> {
            self.failure.as_ref()
        }

        /// `run_supervised` の終了コードへ作成の失敗を反映する（失敗していて `code` が 0 なら非 0 にする）。
        ///
        /// 失敗時は停止を要求済みで、回収に成功すると `run_supervised` は 0 を返す。それを正常終了として
        /// 報告しない（SUP-1・REPAIR-4）。
        pub fn exit_code(&self, code: u8) -> u8 {
            match (&self.failure, code) {
                (Some(e), 0) => exit_code_for(e.code()).get(),
                _ => code,
            }
        }
    }

    fn failed_handle(error: TraitError) -> ControlHandle {
        // 機械可読な固定語彙の 1 行（code は列挙名。message は固定文言）。
        let line = format!(
            "{{\"component\":\"supervisor\",\"event\":\"control_channel_failed\",\"code\":\"{}\",\"message\":\"{}\"}}\n",
            error.code().as_str(),
            error.message()
        );
        let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
        ControlHandle {
            server: None,
            _listener: None,
            failure: Some(error),
        }
    }

    /// `running` の起動ハンドルと relauncher を制御チャネルに結線し、サーバを起動する。
    ///
    /// bind・サーバスレッドの生成に失敗したら、構造化エラーを [`ControlHandle::failure`] に載せ、`stop` に
    /// 停止を要求する（停止できないコンテナを残さない。fail-closed）。呼び出し元は `run_supervised` の前に呼び、
    /// 返った [`ControlHandle`] を `run_supervised` が返るまで保持し、終了コードを [`ControlHandle::exit_code`]
    /// に通す。`audit` は認証境界の拒否（別 uid 等）の記録先（SEC-4）。
    pub fn install(
        state_root: &Path,
        id: &ContainerId,
        running: Running,
        stop: &StopToken,
        audit: Option<Arc<dyn AuditSink>>,
    ) -> (Running, ControlHandle) {
        install_with_exec_reclaimer(state_root, id, running, stop, audit, None, None)
    }

    /// [`install`] に、exec 子 cgroup の回収役を足した版（SUP-6・REPAIR-5・#2626）。本番の入口
    /// （`start_entry`）はこちらを使う。`reclaimer` が `None` なら、制御チャネルは ExecHandoverRequest を断る
    /// （子孫を回収できない exec に pidfd を渡さない。fail-closed）。
    ///
    /// `stdin` は argv の `--stdin`（SUP-7・CRI-6・#4074）で、スロットへ設定して世代交代をまたいで保つ。
    // 理由: 入口が束ねる値（状態ルート・ID・Running・停止トークン・監査・回収役・stdin の指定）はいずれも独立で、
    // 束ねる型を作ると呼び出し側の分解コードが増えるだけのため引数のまま渡す。
    #[allow(clippy::too_many_arguments)]
    pub fn install_with_exec_reclaimer(
        state_root: &Path,
        id: &ContainerId,
        running: Running,
        stop: &StopToken,
        audit: Option<Arc<dyn AuditSink>>,
        reclaimer: Option<Arc<dyn ExecCgroupReclaimer>>,
        stdin: Option<crate::start_contract::StdinOption>,
    ) -> (Running, ControlHandle) {
        let bound = effective_uid()
            .and_then(|uid| ControlListener::bind_as(state_root, id, uid).map(|l| (uid, l)));
        let (uid, listener) = match bound {
            Ok(v) => v,
            Err(e) => {
                stop.request_stop();
                return (running, failed_handle(e));
            }
        };
        // kind 9 の tap の購読先（捕捉ハブ）もスロットへ渡す。サーバの引数に通すより変更が小さい（#4075）。
        let slot = SignalSlot::with_stop_intent(stop.clone())
            .with_stdin_option(stdin)
            .with_output_capture(running.logs.clone());
        let Running {
            process,
            relauncher,
            instance,
            logs,
            seccomp,
        } = running;
        let observer = Arc::new(ControlObserver::new(audit, Some(id.clone())));
        let guards = reclaimer
            .map(|r| ExecGuardPool::new(r, Arc::clone(&observer), ExecGuardLimits::default()));
        let server = listener.try_clone_listener().and_then(|l| {
            PausableServer::spawn_with_exec_guard(
                l,
                slot.clone(),
                uid,
                ServeConfig::default(),
                observer,
                guards,
            )
        });
        match server {
            Ok(s) => {
                let s = Arc::new(s);
                // 再 launch の間だけ accept スレッドを止める（単一スレッドを要求する本番 launcher のため。#2043）。
                let controlled =
                    ControlledRelauncher::new(relauncher, slot.clone()).with_pause(s.clone());
                let running = Running {
                    process: Box::new(ControlledProcess::new(process, slot)),
                    relauncher: Arc::new(controlled),
                    instance,
                    logs,
                    seccomp,
                };
                (
                    running,
                    ControlHandle {
                        server: Some(s),
                        _listener: Some(listener),
                        failure: None,
                    },
                )
            }
            Err(_) => {
                let running = Running {
                    process: Box::new(ControlledProcess::new(process, slot.clone())),
                    relauncher: Arc::new(ControlledRelauncher::new(relauncher, slot)),
                    instance,
                    logs,
                    seccomp,
                };
                stop.request_stop();
                let mut handle = failed_handle(TraitError::new(
                    ErrorCode::Internal,
                    "failed to start the control channel server",
                ));
                handle._listener = Some(listener);
                (running, handle)
            }
        }
    }
}
