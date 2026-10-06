//! `VZVirtualMachine` の start / stop ライフサイクルと状態イベント（MAC-1・TASK-64.4・MS-5）。
//!
//! 構成:
//! - OS 非依存層: `VmState`・`VmEvent`・`VmError` と、状態遷移を決める純粋な `Lifecycle`・イベント配送
//!   `EventSink`・操作の受付 / 放棄を直列化する `Core`。FFI 層は遷移を `Core` に委ねるだけにし、遷移ロジックを
//!   Linux 上の `make test` で検証できるようにする（REPAIR-12）。
//! - macOS 限定層: `Vm`。`config::VzVmConfiguration` から VM を生成し、`start` / `stop` を同期 API
//!   （タイムアウト付き。REPAIR-5）として公開する。
//!
//! run loop 統合: `initWithConfiguration:`（キュー指定なし）はメインキューを使うため呼び出し側が run loop を
//! 回し続ける必要があるが、本モジュールは VM ごとに専用のシリアル `DispatchQueue` を作って生成する。
//! completion handler・delegate は GCD のワーカースレッドで届くので、呼び出し元（TASK-115 の plugin
//! プロセス）はメイン run loop を回さずに済む。VM に関わる unsafe はすべて `sys` に閉じ込めている。
//!
//! タイムアウト後の回復（REPAIR-5）: 待機期限を過ぎた操作は放棄（世代を無効化）し、後続の start / stop を
//! 受け付ける。受付時には VZ の実状態を読んで状態機械を追従させる。放棄後に届いた完了通知は、別の操作や停止
//! 通知に追い越されていなければ状態機械にだけ適用する（呼び出し元へは返らない）。
//!
//! 破棄時の停止: `Vm` の `Drop` は実行中の VM に停止を要求する（ブロックしない）。失敗したら間隔を空けて
//! 最大 `DROP_STOP_MAX_ATTEMPTS` 回まで要求し直し、それでも止まらなければ `VmEvent::StopOnDropFailed` で
//! 記録したうえで VM オブジェクトの解放（VZ 側の後始末）に委ねる。
//!
//! 注意: `start` / `stop` / `state` を VM キュー上（イベント処理の中など）から呼ぶとデッドロックする。
//! 最後の防壁としてタイムアウトが `VmError::Timeout` を返す。
//!
//! タイムアウト既定値（TASK-64.5・REPAIR-5）: start / stop / 状態照会ごとの既定値と許容範囲を
//! [`OpTimeouts`] で表す。待機ロジックは OS 非依存の `await_op_result` に切り出し、期限超過で
//! `VmError::Timeout` を返すことを Linux 上のテストで検証する。
//!
//! ゲスト内 virtiofs mount の待機（TASK-65.3）: `Vm::launch` は `start` 成功後、mount 指定つき共有の報告を
//! `guest_mount` モジュールの契約で `OpTimeouts::guest_mount`（既定 60 秒）を上限に待つ。ゲスト init が未実装の
//! 間（REPAIR-3）は、mount 指定つきの `launch` は報告が届かず `guest_mount.timeout` になる。
//!
//! 起動失敗時のクリーンアップ（TASK-64.5）: 失敗した完了通知の直後に `Core::complete_and_settle` が
//! VZ の実状態へ追従し、状態機械が `Error` のまま残らない。`Vm::launch`（macOS）は設定の構築・VM 生成・
//! 起動のどこで失敗しても、所有する設定と VM を Rust の drop 順（VM → 設定）で解放する。解放後は VM の
//! `Drop` が停止を要求し（起動途中なら完了後に再要求）、コンソールログの排他 lock も書き出しスレッドの
//! 終了とともに解放される。本 crate は一時ファイルを作らず、コンソールログも診断材料として削除しない。
//!
//! エラー型は `crate::error` に移動し、本モジュールから `VmError`・`VmOp` を再エクスポートする（ERR-1）。
//!
//! 未実装（REPAIR-3）: 協調停止（`requestStop`）・pause / resume / save / restore は範囲外。
//! plugin 境界のエラー写像は TASK-115。

use std::io::Write;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::time::Duration;

/// NSError の要約（domain, code）。
type ErrInfo = (String, isize);

/// イベントチャネルの容量。溢れた分は `VmEvent::EventsDropped` で通知する。
pub const EVENT_CHANNEL_CAPACITY: usize = 64;

/// `Vm` の破棄時に停止を要求する最大回数（初回を含む）。失敗し続ける VM への要求を有界に保つ。
pub const DROP_STOP_MAX_ATTEMPTS: u32 = 3;

pub use crate::error::{VmError, VmOp};

/// `start` の完了待ちの既定タイムアウト。VZ の start 完了はゲストのブートではなく VM 開始を指すため、
/// 30 秒あれば最小構成でも十分な余裕がある（MAC-1・REPAIR-5・TASK-64.5。実測に基づく見直しは別途）。
pub const DEFAULT_START_TIMEOUT: Duration = Duration::from_secs(30);

/// `stop`（破壊的停止）の完了待ちの既定タイムアウト（REPAIR-5・TASK-64.5）。
pub const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(15);

/// `Vm::state` が VM キューの応答を待つ既定タイムアウト（REPAIR-5・TASK-64.5）。
pub const DEFAULT_STATE_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// `Vm::launch` がゲスト内 virtiofs mount の報告を待つ既定タイムアウト（MAC-1・REPAIR-5・TASK-65.3）。
pub const DEFAULT_GUEST_MOUNT_TIMEOUT: Duration = Duration::from_secs(60);

/// 指定できるタイムアウトの下限。0 や極小値で常時失敗させる設定を拒否する。
pub const MIN_OP_TIMEOUT: Duration = Duration::from_millis(100);

/// 指定できるタイムアウトの上限。巨大値による無期限に近い待機を拒否する。
pub const MAX_OP_TIMEOUT: Duration = Duration::from_secs(600);

/// 操作ごとの待機タイムアウト。範囲外の値を表現できない検証済み型（REPAIR-2・REPAIR-5・TASK-64.5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpTimeouts {
    start: Duration,
    stop: Duration,
    state_query: Duration,
    guest_mount: Duration,
    /// `Vm::launch` が構成構築時に行う共有配下の走査の期限。`None` は期限なし（件数上限のみ）。
    share_scan: Option<Duration>,
}

impl OpTimeouts {
    /// 3 つの値を `MIN_OP_TIMEOUT..=MAX_OP_TIMEOUT` で検証して作る。範囲外は `VmError::InvalidTimeout`。
    pub fn try_new(
        start: Duration,
        stop: Duration,
        state_query: Duration,
    ) -> Result<OpTimeouts, VmError> {
        for (field, value) in [
            ("start", start),
            ("stop", stop),
            ("state_query", state_query),
        ] {
            if !(MIN_OP_TIMEOUT..=MAX_OP_TIMEOUT).contains(&value) {
                return Err(VmError::InvalidTimeout {
                    field,
                    requested: value,
                    min: MIN_OP_TIMEOUT,
                    max: MAX_OP_TIMEOUT,
                });
            }
        }
        Ok(OpTimeouts {
            start,
            stop,
            state_query,
            guest_mount: DEFAULT_GUEST_MOUNT_TIMEOUT,
            share_scan: None,
        })
    }

    /// `Vm::launch` が構成構築時に行う共有配下の走査（`VmConfigSpec::check_share_conflicts_within`）の
    /// 期限を指定する（`MIN_OP_TIMEOUT..=MAX_OP_TIMEOUT`。REPAIR-5・MAC-1・TASK-115.3）。
    ///
    /// 未指定（既定）は従来どおり期限なしで、件数上限だけで止まる。相手の応答期限を持つ呼び出し元
    /// （plugin の RPC 経路）が指定する。超過は `ConfigError::SharedDirScanTimeout`。
    pub fn with_share_scan(mut self, share_scan: Duration) -> Result<OpTimeouts, VmError> {
        if !(MIN_OP_TIMEOUT..=MAX_OP_TIMEOUT).contains(&share_scan) {
            return Err(VmError::InvalidTimeout {
                field: "share_scan",
                requested: share_scan,
                min: MIN_OP_TIMEOUT,
                max: MAX_OP_TIMEOUT,
            });
        }
        self.share_scan = Some(share_scan);
        Ok(self)
    }

    /// 共有配下の走査の期限（未指定は `None`）。
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn share_scan(&self) -> Option<Duration> {
        self.share_scan
    }

    /// ゲスト mount 報告の待機時間を差し替える（`MIN_OP_TIMEOUT..=MAX_OP_TIMEOUT`。TASK-65.3）。
    pub fn with_guest_mount(mut self, guest_mount: Duration) -> Result<OpTimeouts, VmError> {
        if !(MIN_OP_TIMEOUT..=MAX_OP_TIMEOUT).contains(&guest_mount) {
            return Err(VmError::InvalidTimeout {
                field: "guest_mount",
                requested: guest_mount,
                min: MIN_OP_TIMEOUT,
                max: MAX_OP_TIMEOUT,
            });
        }
        self.guest_mount = guest_mount;
        Ok(self)
    }

    /// ゲスト mount 報告の待機時間。
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn guest_mount(&self) -> Duration {
        self.guest_mount
    }

    /// `start` の完了待ち。
    pub fn start(&self) -> Duration {
        self.start
    }

    /// `stop` の完了待ち。
    pub fn stop(&self) -> Duration {
        self.stop
    }

    /// 状態照会の応答待ち。
    pub fn state_query(&self) -> Duration {
        self.state_query
    }

    /// 操作種別に対応する完了待ち。
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn for_op(&self, op: VmOp) -> Duration {
        match op {
            VmOp::Start => self.start,
            VmOp::Stop => self.stop,
        }
    }
}

impl Default for OpTimeouts {
    fn default() -> Self {
        OpTimeouts {
            start: DEFAULT_START_TIMEOUT,
            stop: DEFAULT_STOP_TIMEOUT,
            state_query: DEFAULT_STATE_QUERY_TIMEOUT,
            guest_mount: DEFAULT_GUEST_MOUNT_TIMEOUT,
            share_scan: None,
        }
    }
}

/// 操作の結果を期限付きで待つ。呼び出し元の `Vm::run_op`（macOS）が使う OS 非依存の待機部分。
///
/// 期限内に結果が届けばそのまま返す。期限切れなら `VmError::Timeout`、送信側が失われたら
/// `VmError::CallbackLost` を `give_up` に渡し、その戻り値（直前に確定した結果があればそれ）を返す。
/// `give_up` は操作の取り消し・放棄の後始末を担う（REPAIR-5・TASK-64.5）。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn await_op_result(
    rx: &Receiver<Result<(), VmError>>,
    op: VmOp,
    timeout: Duration,
    give_up: impl FnOnce(VmError) -> Result<(), VmError>,
) -> Result<(), VmError> {
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => give_up(VmError::Timeout { op, after: timeout }),
        Err(RecvTimeoutError::Disconnected) => give_up(VmError::CallbackLost { op }),
    }
}

/// VM の状態（`VZVirtualMachineState` に対応）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VmState {
    Stopped,
    Running,
    Paused,
    Error,
    Starting,
    Pausing,
    Resuming,
    Stopping,
    Saving,
    Restoring,
    /// 未知の値（フレームワーク由来の外部入力のため、そのまま保持する）。
    Unknown(isize),
}

impl VmState {
    /// `VZVirtualMachineState` の生値から変換する。範囲外でも panic しない。
    pub fn from_raw(raw: isize) -> VmState {
        match raw {
            0 => VmState::Stopped,
            1 => VmState::Running,
            2 => VmState::Paused,
            3 => VmState::Error,
            4 => VmState::Starting,
            5 => VmState::Pausing,
            6 => VmState::Resuming,
            7 => VmState::Stopping,
            8 => VmState::Saving,
            9 => VmState::Restoring,
            other => VmState::Unknown(other),
        }
    }
}

/// VM の状態遷移・停止通知イベント。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VmEvent {
    /// 状態が遷移した。
    StateChanged { from: VmState, to: VmState },
    /// ゲスト側から停止された。
    GuestStopped,
    /// エラーで停止した。
    StoppedWithError { domain: String, code: isize },
    /// チャネルが溢れて `count` 件のイベントを落とした（送れるようになった時点で 1 回通知する）。
    EventsDropped { count: u64 },
    /// `Vm` の破棄時に要求した停止が `attempts` 回とも失敗した（最後の失敗の要約。VM は動作を続けている
    /// 可能性がある）。
    StopOnDropFailed {
        domain: String,
        code: isize,
        attempts: u32,
    },
}

/// 状態機械への入力。
#[derive(Debug, Clone, PartialEq, Eq)]
// macOS 限定の `Vm` だけが使う内部項目。他 OS ではテストからのみ参照されるため、この項目に限り dead_code を許容する。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum LifecycleInput {
    StartRequested,
    /// 第 1 要素は `Core::try_begin` が返した操作世代。現行の世代と一致しない完了通知は無視される。
    StartCompleted(u64, Result<(), ErrInfo>),
    StopRequested,
    /// 第 1 要素は `Core::try_begin` が返した操作世代。現行の世代と一致しない完了通知は無視される。
    StopCompleted(u64, Result<(), ErrInfo>),
    GuestStopped,
    StoppedWithError(ErrInfo),
}

/// 状態遷移を決める純粋な状態機械。FFI を持たない。
///
/// 完了入力（`StartCompleted(Err)` → `Error`、`StopCompleted(Err)` → `Running`）は仮の遷移で、VZ の実状態
/// （例: 起動失敗後に `Stopped`）と食い違い得る。実状態は `Vm::state()` が正。次の要求の受付時・タイムアウト後に
/// `reconcile` で実状態へ追従する。失敗した完了通知の直後は `Core::complete_and_settle` が追従する（TASK-64.5）。
///
/// 操作世代: 要求ごとに世代を進め、完了通知は要求時の世代と一致する間だけ適用する。ゲスト停止・エラー停止の
/// 通知は進行中の操作を無効化するため、停止済みの VM を遅れて届いた `StartCompleted(Ok)` が `Running` へ
/// 逆行させない。
///
/// 放棄（REPAIR-5）: 呼び出し元が待機期限で諦めた操作は `abandon` で進行中から外し、後続の要求を受け付ける。
/// 放棄した操作の完了通知は、その後に新しい要求も停止通知もなければ遅れて適用する（放棄後も VZ 側の操作は
/// 続いており、その結果が実状態を表すため）。停止通知・新しい要求のどちらかが先に来たら古い通知として捨てる。
#[derive(Debug)]
pub(crate) struct Lifecycle {
    state: VmState,
    generation: u64,
    in_flight: Option<u64>,
    /// 待機期限切れで放棄した操作の世代（完了通知を遅れて受理するための目印）。
    abandoned: Option<u64>,
}

// macOS 限定の `Vm` だけが使う内部項目。他 OS ではテストからのみ参照されるため、この項目に限り dead_code を許容する。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl Lifecycle {
    pub(crate) fn new() -> Lifecycle {
        Lifecycle {
            state: VmState::Stopped,
            generation: 0,
            in_flight: None,
            abandoned: None,
        }
    }

    /// 現在の状態機械上の状態。
    pub(crate) fn state(&self) -> VmState {
        self.state
    }

    /// 指定世代の完了通知を受理するか。現行の進行中操作、または進行中の操作がない間の放棄済み操作なら true
    /// （ゲスト停止・後続の要求で無効化されていれば false）。
    pub(crate) fn accepts(&self, generation: u64) -> bool {
        match self.in_flight {
            Some(current) => current == generation,
            None => self.abandoned == Some(generation),
        }
    }

    /// 進行中の操作を放棄する（呼び出し元の待機期限切れ。REPAIR-5）。現行の進行中操作だったら true。
    pub(crate) fn abandon(&mut self, generation: u64) -> bool {
        if self.in_flight != Some(generation) {
            return false;
        }
        self.in_flight = None;
        self.abandoned = Some(generation);
        true
    }

    /// 要求できなかった操作を取り消す（完了通知は来ないため放棄の目印も残さない）。
    pub(crate) fn cancel(&mut self, generation: u64) {
        if self.in_flight == Some(generation) {
            self.in_flight = None;
        }
        if self.abandoned == Some(generation) {
            self.abandoned = None;
        }
    }

    /// 進行中の操作がなければ、状態を VZ の実状態 `actual` に合わせる（食い違っていれば `StateChanged`）。
    /// 進行中の操作がある間は、その完了通知が状態を決めるため何もしない。
    pub(crate) fn reconcile(&mut self, actual: VmState) -> Vec<VmEvent> {
        if self.in_flight.is_some() || actual == self.state {
            return Vec::new();
        }
        let from = self.state;
        self.state = actual;
        vec![VmEvent::StateChanged { from, to: actual }]
    }

    /// 完了待ちの操作があるか。
    pub(crate) fn has_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    /// 直近の要求に割り当てた操作世代。
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// 入力を適用し、発行すべきイベント列を返す。
    pub(crate) fn step(&mut self, input: LifecycleInput) -> Vec<VmEvent> {
        let mut events = Vec::new();
        let mut extra = None;
        let next = match input {
            LifecycleInput::StartRequested => {
                self.begin_op();
                VmState::Starting
            }
            LifecycleInput::StopRequested => {
                self.begin_op();
                VmState::Stopping
            }
            LifecycleInput::StartCompleted(generation, res) => {
                if !self.finish_op(generation) {
                    return events;
                }
                if res.is_ok() {
                    VmState::Running
                } else {
                    VmState::Error
                }
            }
            LifecycleInput::StopCompleted(generation, res) => {
                if !self.finish_op(generation) {
                    return events;
                }
                // 停止に失敗した VM は動作を続けているとみなす。
                if res.is_ok() {
                    VmState::Stopped
                } else {
                    VmState::Running
                }
            }
            LifecycleInput::GuestStopped => {
                self.in_flight = None;
                self.abandoned = None;
                extra = Some(VmEvent::GuestStopped);
                VmState::Stopped
            }
            LifecycleInput::StoppedWithError((domain, code)) => {
                self.in_flight = None;
                self.abandoned = None;
                extra = Some(VmEvent::StoppedWithError { domain, code });
                VmState::Error
            }
        };
        if next != self.state {
            events.push(VmEvent::StateChanged {
                from: self.state,
                to: next,
            });
            self.state = next;
        }
        events.extend(extra);
        events
    }

    fn begin_op(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.in_flight = Some(self.generation);
        // 新しい要求が来たら、放棄済み操作の遅れた完了通知は古い通知として捨てる。
        self.abandoned = None;
    }

    /// 完了通知を受理できる（`accepts`）なら受理して true。古い通知は false。
    fn finish_op(&mut self, generation: u64) -> bool {
        if !self.accepts(generation) {
            return false;
        }
        self.in_flight = None;
        self.abandoned = None;
        true
    }
}

/// イベント送信側。VM キュー上のコールバックから呼ばれるため、決して block しない（`try_send` のみ）。
#[derive(Debug)]
pub(crate) struct EventSink {
    tx: SyncSender<VmEvent>,
    dropped: u64,
}

/// 容量付きのイベントチャネルを作る。
// macOS 限定の `Vm` だけが使う内部項目。他 OS ではテストからのみ参照されるため、この項目に限り dead_code を許容する。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn event_channel(capacity: usize) -> (EventSink, Receiver<VmEvent>) {
    let (tx, rx) = sync_channel(capacity);
    (EventSink { tx, dropped: 0 }, rx)
}

impl EventSink {
    /// イベントを送る。満杯なら落とした件数を数え、次に送れた時に `EventsDropped` を先に送る。
    /// 受信側が drop 済みなら捨てる（panic しない）。
    ///
    /// 戻り値は `event` をチャネルへ積めたか（満杯で落とした・受信側がない場合は false）。
    pub(crate) fn send(&mut self, event: VmEvent) -> bool {
        if self.dropped > 0 {
            let notice = VmEvent::EventsDropped {
                count: self.dropped,
            };
            match self.tx.try_send(notice) {
                Ok(()) => self.dropped = 0,
                Err(TrySendError::Full(_)) => {
                    self.dropped = self.dropped.saturating_add(1);
                    return false;
                }
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.dropped = self.dropped.saturating_add(1);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

/// `start` / `stop` 1 回分の受付状況。呼び出し元スレッドと VM キューで共有し、必ず `Core` のロックを
/// 取った後に触る（ロック順は `Core` → チケット）。キュー上の受付と呼び出し元の放棄を直列化するため（REPAIR-5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// macOS 限定の `Vm` だけが使う内部項目。他 OS ではテストからのみ参照されるため、この項目に限り dead_code を許容する。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum OpTicket {
    /// キューへ投入済みで未着手。
    Pending,
    /// 受け付けて VZ へ要求した（値は操作世代）。
    Begun(u64),
    /// 受け付けずに結果を返した（`canStart` / `canStop` が false、または重複要求）。
    Settled,
    /// 着手前に呼び出し元が待機期限で取り消した。キュー上では何もしない。
    Cancelled,
}

/// `Core::begin` の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// macOS 限定の `Vm` だけが使う内部項目。他 OS ではテストからのみ参照されるため、この項目に限り dead_code を許容する。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum BeginOutcome {
    /// 取り消し済みのため何もしない（結果は呼び出し元へ返さない）。
    Cancelled,
    /// 受け付けなかった。その時点の状態を `InvalidState` として返す。
    Rejected(VmState),
    /// 受け付けた。値は完了通知に持ち回る操作世代。
    Begun(u64),
}

/// `Core::abandon` の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// macOS 限定の `Vm` だけが使う内部項目。他 OS ではテストからのみ参照されるため、この項目に限り dead_code を許容する。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum AbandonOutcome {
    /// 未着手だったので取り消した（VZ へは要求しない）。
    NotStarted,
    /// VZ へ要求済みの操作を放棄した。後続の要求を受け付け、実状態への追従を要する。
    Abandoned(u64),
    /// 既に結果が確定していた（結果チャネルに値がある）。
    Settled,
}

/// 状態機械とイベント配送をまとめたもの。コールバックと操作側で `Arc<Mutex<_>>` 共有する。
#[derive(Debug)]
pub(crate) struct Core {
    lifecycle: Lifecycle,
    sink: EventSink,
    /// `Vm` が破棄され、停止を要求すべき状態か（破棄時に停止できなかった場合も、後の完了通知で再試行する）。
    drop_requested: bool,
    /// 破棄時の停止を要求した回数（`DROP_STOP_MAX_ATTEMPTS` で打ち切る）。
    drop_stop_attempts: u32,
}

// macOS 限定の `Vm` だけが使う内部項目。他 OS ではテストからのみ参照されるため、この項目に限り dead_code を許容する。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl Core {
    pub(crate) fn new(sink: EventSink) -> Core {
        Core {
            lifecycle: Lifecycle::new(),
            sink,
            drop_requested: false,
            drop_stop_attempts: 0,
        }
    }

    /// VM キュー上で要求を受け付ける。`allowed` は `canStart` / `canStop`、`actual` は VZ の実状態。
    ///
    /// 取り消し済みなら何もしない。受け付けられない（`allowed` が false・進行中の操作がある）なら
    /// チケットを確定させて `Rejected` を返す。重複要求を拒否するのは、先行操作の世代を潰して完了通知を
    /// 破棄させ、状態とイベントが食い違うのを防ぐため。受け付ける前に状態機械を実状態へ追従させる
    /// （タイムアウトで放棄した操作の後でも、実状態から次の操作を始められるようにする。REPAIR-5）。
    pub(crate) fn begin(
        &mut self,
        ticket: &mut OpTicket,
        input: LifecycleInput,
        allowed: bool,
        actual: VmState,
    ) -> BeginOutcome {
        if *ticket != OpTicket::Pending {
            return BeginOutcome::Cancelled;
        }
        if !allowed {
            *ticket = OpTicket::Settled;
            // 拒否する場合も、進行中の操作がなければ状態機械を実状態へ追従させる（放棄後の回復を早める）。
            self.reconcile(actual);
            return BeginOutcome::Rejected(actual);
        }
        if self.lifecycle.has_in_flight() {
            *ticket = OpTicket::Settled;
            return BeginOutcome::Rejected(self.lifecycle.state());
        }
        self.reconcile(actual);
        self.apply(input);
        let generation = self.lifecycle.generation();
        *ticket = OpTicket::Begun(generation);
        BeginOutcome::Begun(generation)
    }

    /// 呼び出し元の待機期限切れで操作を手放す（REPAIR-5）。未着手なら取り消し、要求済みで完了待ちなら
    /// 世代を放棄して後続の要求を受け付けられるようにする。
    pub(crate) fn abandon(&mut self, ticket: &mut OpTicket) -> AbandonOutcome {
        match *ticket {
            OpTicket::Pending => {
                *ticket = OpTicket::Cancelled;
                AbandonOutcome::NotStarted
            }
            OpTicket::Begun(generation) if self.lifecycle.abandon(generation) => {
                AbandonOutcome::Abandoned(generation)
            }
            _ => AbandonOutcome::Settled,
        }
    }

    /// 受け付けた操作 `generation` を VZ へ要求できなかった（要求直前の `canStart` / `canStop` が false）
    /// ときに取り消し、状態機械を実状態 `actual` へ戻す。取り消し後の状態を返す（`InvalidState` 用）。
    pub(crate) fn cancel_begun(&mut self, generation: u64, actual: VmState) -> VmState {
        self.lifecycle.cancel(generation);
        self.reconcile(actual);
        self.lifecycle.state()
    }

    /// 進行中の操作がなければ状態機械を VZ の実状態へ合わせ、差分を `StateChanged` で配送する。
    pub(crate) fn reconcile(&mut self, actual: VmState) {
        for event in self.lifecycle.reconcile(actual) {
            self.sink.send(event);
        }
    }

    #[cfg(test)]
    pub(crate) fn begin_unchecked(&mut self, input: LifecycleInput) -> u64 {
        self.apply(input);
        self.lifecycle.generation()
    }

    /// 完了入力を適用する。受理されれば `Ok`、停止通知・後続の要求で無効化済みなら適用せず
    /// その時点の状態を `Err` で返す（呼び出し元へ成功を返さないため。TASK-64.4）。
    pub(crate) fn complete(
        &mut self,
        generation: u64,
        input: LifecycleInput,
    ) -> Result<(), VmState> {
        if !self.lifecycle.accepts(generation) {
            let state = self.lifecycle.state();
            // 停止要求中にゲスト停止通知が先着して世代が無効化された場合でも、停止自体は成功しており
            // VM は Stopped なので、通知と完了の到着順に依存せず正常な停止として扱う。
            if matches!(input, LifecycleInput::StopCompleted(_, Ok(())))
                && state == VmState::Stopped
            {
                return Ok(());
            }
            return Err(state);
        }
        self.apply(input);
        Ok(())
    }

    /// `complete` に加え、失敗した完了（`StartCompleted(Err)` / `StopCompleted(Err)`）や無効化された完了の
    /// 直後に VZ の実状態 `actual` へ状態機械を追従させる。起動失敗後に仮の `Error` が残り、VZ の `Stopped`
    /// と食い違うのを防ぐ（MAC-1・TASK-64.5）。VM キュー上の completion handler から呼ぶ。
    pub(crate) fn complete_and_settle(
        &mut self,
        generation: u64,
        input: LifecycleInput,
        actual: VmState,
    ) -> Result<(), VmState> {
        let failed = matches!(
            input,
            LifecycleInput::StartCompleted(_, Err(_)) | LifecycleInput::StopCompleted(_, Err(_))
        );
        let result = self.complete(generation, input);
        if failed || result.is_err() {
            self.reconcile(actual);
        }
        result
    }

    pub(crate) fn apply(&mut self, input: LifecycleInput) {
        for event in self.lifecycle.step(input) {
            self.sink.send(event);
        }
    }

    /// `Vm` の破棄に伴う停止を VM キュー上で受け付ける。停止要求を出すべきならその操作世代を返す。
    ///
    /// 破棄済みの印は常に付ける。`can_stop` が false（起動途中等）または完了待ちの操作がある間は要求せず、
    /// 後でその操作の完了通知が `drop_stop_due` を見て再試行する（起動完了後に動き続けるのを防ぐ）。
    /// 要求回数が `DROP_STOP_MAX_ATTEMPTS` に達したら以後は要求しない。
    pub(crate) fn request_drop_stop(&mut self, can_stop: bool, actual: VmState) -> Option<u64> {
        self.drop_requested = true;
        if !can_stop
            || self.lifecycle.has_in_flight()
            || self.drop_stop_attempts >= DROP_STOP_MAX_ATTEMPTS
        {
            return None;
        }
        self.drop_stop_attempts = self.drop_stop_attempts.saturating_add(1);
        self.reconcile(actual);
        self.apply(LifecycleInput::StopRequested);
        Some(self.lifecycle.generation())
    }

    /// 破棄済みで、完了待ちの操作がない（破棄時の停止を要求し直すべき）か。
    pub(crate) fn drop_stop_due(&self) -> bool {
        self.drop_requested && !self.lifecycle.has_in_flight()
    }

    /// 破棄時の停止の完了を適用する。受理された失敗で要求回数が残っていれば `true`（呼び出し元が間隔を
    /// 空けて `request_drop_stop` からやり直す）。
    ///
    /// 回数を使い切った失敗は `StopOnDropFailed` として記録する（呼び出し元はもういないため）。受信側が
    /// `Vm` とともに破棄されている・満杯でイベントが届かない場合は、失敗を見失わないよう構造化ログ
    /// （1 行 1 JSON）を stderr へ出す（REPAIR-4）。
    ///
    /// VM キュー上の completion block 内で呼ばれるため panic しないこと（ロックは毒化を許容し、出力の
    /// 失敗は無視する）。
    pub(crate) fn finish_drop_stop(&mut self, generation: u64, res: Result<(), ErrInfo>) -> bool {
        let failure = res.clone().err();
        let accepted = self
            .complete(generation, LifecycleInput::StopCompleted(generation, res))
            .is_ok();
        let Some((domain, code)) = failure else {
            return false;
        };
        // ゲスト停止・エラー停止の通知が先着して無効化された結果なら、VM は既に止まっている（状態機械と
        // 通知で表されている）ため、失敗として記録もやり直しもしない。
        if !accepted {
            return false;
        }
        if self.drop_stop_attempts < DROP_STOP_MAX_ATTEMPTS {
            return true;
        }
        let attempts = self.drop_stop_attempts;
        let line = stop_on_drop_failure_log(&domain, code, attempts);
        if !self.sink.send(VmEvent::StopOnDropFailed {
            domain,
            code,
            attempts,
        }) {
            // VM キュー上の completion block 内から呼ばれる。`eprintln!` は stderr への書き込み失敗（EPIPE 等）で
            // panic し、VZ / libdispatch のフレームへ巻き戻り得るため、失敗を無視する `writeln!` を使う。
            let _ = writeln!(std::io::stderr().lock(), "{line}");
        }
        false
    }
}

/// 破棄時の停止の失敗を表す構造化ログ 1 行（JSON）。`domain` は VZ 由来の外部入力のため JSON 文字列として
/// エスケープする（`sys` 側で 128 文字に切り詰め済み）。
// macOS 限定の `Vm` だけが使う内部項目。他 OS ではテストからのみ参照されるため、この項目に限り dead_code を許容する。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn stop_on_drop_failure_log(domain: &str, code: isize, attempts: u32) -> String {
    let mut escaped = String::with_capacity(domain.len());
    for c in domain.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            // 制御文字（C0・DEL・NEL）と、JSON は許すが JavaScript 等で行区切りとして扱われる U+2028 / U+2029 も
            // `\uXXXX` にして、1 行 1 JSON を崩さない。
            c if u32::from(c) < 0x20
                || matches!(c, '\u{7f}' | '\u{85}' | '\u{2028}' | '\u{2029}') =>
            {
                escaped.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => escaped.push(c),
        }
    }
    format!(
        "{{\"component\":\"platform-macos.vm\",\"operation\":\"stop_on_drop\",\"result\":\"error\",\"code\":\"vm.stop_failed\",\"domain\":\"{escaped}\",\"vz_code\":{code},\"attempts\":{attempts}}}"
    )
}

#[cfg(target_os = "macos")]
pub use mac::Vm;

#[cfg(target_os = "macos")]
mod mac {
    use std::sync::mpsc::Receiver;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::Duration;

    use super::{
        AbandonOutcome, BeginOutcome, Core, EVENT_CHANNEL_CAPACITY, ErrInfo, LifecycleInput,
        OpTicket, OpTimeouts, VmError, VmEvent, VmOp, VmState, await_op_result, event_channel,
    };
    use crate::config::{
        VmConfigSpec, VzVmConfiguration, build_vz_configuration, build_vz_configuration_within,
    };
    use crate::error::PlatformError;
    use crate::sys::{self, DelegateEvent, HostInitError, VmRef};

    /// 破棄時の停止が失敗した後、要求し直すまでの間隔（失敗直後は同じ理由で失敗しやすいため）。
    const DROP_STOP_RETRY_DELAY: Duration = Duration::from_secs(1);

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        // 毒化しても状態機械・チケットは壊れないため、中身をそのまま使う（コールバック内で panic させない）。
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn actual_state(vm: &VmRef<'_>) -> VmState {
        VmState::from_raw(vm.state_raw())
    }

    /// 起動可能な `VZVirtualMachine` のハンドル。
    ///
    /// 呼び出し元: `fandhe-container-plugin-macos`（TASK-115）。実機での起動確認は TASK-64.6。
    /// `Drop` は実行中の VM に停止を要求してから、VM を専用キュー上で解放する（ブロックしない。失敗時は
    /// 有界回数やり直す。停止の完了・失敗はイベントで届く。完了まで待ちたい呼び出し元は先に `stop` を呼ぶ）。
    pub struct Vm {
        host: sys::VmHost,
        core: Arc<Mutex<Core>>,
        events: Option<Receiver<VmEvent>>,
        timeouts: OpTimeouts,
    }

    impl Vm {
        /// 構築済み設定から既定のタイムアウト（`OpTimeouts::default`）で VM を生成する（起動はしない）。
        pub fn create(config: &VzVmConfiguration) -> Result<Vm, VmError> {
            Vm::create_with_timeouts(config, OpTimeouts::default())
        }

        /// 構築済み設定から、タイムアウトを指定して VM を生成する（起動はしない）。
        pub fn create_with_timeouts(
            config: &VzVmConfiguration,
            timeouts: OpTimeouts,
        ) -> Result<Vm, VmError> {
            let (sink, rx) = event_channel(EVENT_CHANNEL_CAPACITY);
            let core = Arc::new(Mutex::new(Core::new(sink)));
            let cb_core = Arc::clone(&core);
            let handler = Box::new(move |ev: DelegateEvent| {
                let input = match ev {
                    DelegateEvent::GuestStopped => LifecycleInput::GuestStopped,
                    DelegateEvent::StoppedWithError(info) => LifecycleInput::StoppedWithError(info),
                };
                lock(&cb_core).apply(input);
            });
            let host = sys::VmHost::new(config.inner(), handler).map_err(|e| match e {
                HostInitError::Unsupported => VmError::VirtualizationUnsupported,
                HostInitError::InvalidConfiguration((domain, code)) => {
                    VmError::InvalidConfiguration { domain, code }
                }
            })?;
            Ok(Vm {
                host,
                core,
                events: Some(rx),
                timeouts,
            })
        }

        /// 設定の構築・VM 生成・起動を一括で行い、起動済みの VM を返す（MAC-1・REPAIR-5・TASK-64.5）。
        ///
        /// 呼び出し元: `fandhe-container-plugin-macos`（TASK-115）。どの段で失敗しても（`?` による早期 return と
        /// 起動のタイムアウトを含む）、所有する VM と設定を drop 順（VM → 設定）で解放する。VM の `Drop` が
        /// 停止を要求し（起動途中なら完了通知の後に再要求）、設定が保持していた serial の書き込み端が閉じて
        /// コンソールログの書き出しスレッドが終了し、排他 lock も解放される。
        ///
        /// `spec` にゲスト mount 指定の共有があれば、`start` の成功後に全共有の mount 報告を
        /// `OpTimeouts::guest_mount` を上限に待ち、失敗・期限切れ・VM 停止は `PlatformError::GuestMount`
        /// （`guest_mount.*`）で返す。`Vm::create` を直接使う呼び出し元は mount の結果を検証されない。
        ///
        /// コンソールログは失敗の診断材料として削除しない。本 crate は一時ファイルを作らず（kernel・initrd・
        /// ディスクイメージは呼び出し側の所有物）、追記先として検証したパスを削除対象にする経路も作らない。
        pub fn launch(spec: &VmConfigSpec, timeouts: OpTimeouts) -> Result<Vm, PlatformError> {
            // 宣言順の逆に drop される: `vm`（先）→ `config`（後）。
            // 共有配下の走査は、期限の指定があればその範囲で打ち切る（REPAIR-5・TASK-115.3）。
            let mut config = match timeouts.share_scan() {
                Some(budget) => build_vz_configuration_within(spec, budget)?,
                None => build_vz_configuration(spec)?,
            };
            let vm = Vm::create_with_timeouts(&config, timeouts)?;
            if let Err(e) = vm.start() {
                drop(vm);
                drop(config);
                return Err(e.into());
            }
            // ゲスト内 virtiofs mount の完了を待つ（mount 指定がある場合のみ。MAC-1・TASK-65.3）。
            if let Some(watch) = config.take_guest_mount_watch() {
                // 照会が期限内に決着しない（キュー詰まり）場合は `Unknown(-1)` を返す。待機中は一過性として
                // 継続し、成功確定時は再照会しても確認できなければ失敗にする（fail-closed）。
                let alive = |remaining: Duration| match vm.state_within(remaining) {
                    None => Err(VmState::Unknown(-1)),
                    Some(VmState::Running | VmState::Starting) => Ok(()),
                    Some(other) => Err(other),
                };
                if let Err(e) = watch.wait(timeouts.guest_mount(), alive) {
                    drop(vm);
                    drop(config);
                    return Err(e.into());
                }
            }
            Ok(vm)
        }

        /// VM を起動し、完了（または失敗・タイムアウト）まで待つ。
        pub fn start(&self) -> Result<(), VmError> {
            self.run_op(VmOp::Start)
        }

        /// VM を破壊的に停止し、完了まで待つ（協調停止は範囲外）。
        pub fn stop(&self) -> Result<(), VmError> {
            self.run_op(VmOp::Stop)
        }

        /// フレームワークが報告する現在の状態。`state_query` タイムアウト内に取得できなければ
        /// `Unknown(-1)`（REPAIR-5）。
        pub fn state(&self) -> VmState {
            self.host
                .run_timeout(self.timeouts.state_query(), actual_state)
                .unwrap_or(VmState::Unknown(-1))
        }

        /// `state` の照会時間を `budget` でも制限する版。決着しなければ `None`（REPAIR-5）。
        fn state_within(&self, budget: Duration) -> Option<VmState> {
            let limit = self
                .timeouts
                .state_query()
                .min(budget.max(Duration::from_millis(1)));
            self.host.run_timeout(limit, actual_state)
        }

        /// イベントを 1 件受け取る。`take_events` 後、または期限切れなら `None`。
        pub fn recv_event(&self, timeout: Duration) -> Option<VmEvent> {
            self.events.as_ref()?.recv_timeout(timeout).ok()
        }

        /// イベント受信側を取り出す（別スレッドへ渡したい呼び出し元向け。1 回だけ取り出せる）。
        pub fn take_events(&mut self) -> Option<Receiver<VmEvent>> {
            self.events.take()
        }

        fn run_op(&self, op: VmOp) -> Result<(), VmError> {
            let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(), VmError>>(1);
            let core = Arc::clone(&self.core);
            let ticket = Arc::new(Mutex::new(OpTicket::Pending));
            let queue_ticket = Arc::clone(&ticket);
            self.host.run_async(move |vm| {
                let actual = actual_state(vm);
                let allowed = match op {
                    VmOp::Start => vm.can_start(),
                    VmOp::Stop => vm.can_stop(),
                };
                let request = match op {
                    VmOp::Start => LifecycleInput::StartRequested,
                    VmOp::Stop => LifecycleInput::StopRequested,
                };
                // 受付は Core → チケットの順にロックして行い、呼び出し元の放棄（`abandon`）と直列化する。
                // VZ への要求（FFI）はロックを外してから行う。
                let generation = {
                    let mut c = lock(&core);
                    let mut t = lock(&queue_ticket);
                    match c.begin(&mut t, request, allowed, actual) {
                        BeginOutcome::Cancelled => return,
                        BeginOutcome::Rejected(state) => {
                            let _ = tx.try_send(Err(VmError::InvalidState { op, state }));
                            return;
                        }
                        BeginOutcome::Begun(generation) => generation,
                    }
                };
                let handler_core = Arc::clone(&core);
                let reject_tx = tx.clone();
                let handler = move |vm: &VmRef<'_>, res: Result<(), ErrInfo>| {
                    let outcome = res.clone().map_err(|(domain, code)| match op {
                        VmOp::Start => VmError::StartFailed { domain, code },
                        VmOp::Stop => VmError::StopFailed { domain, code },
                    });
                    let input = match op {
                        VmOp::Start => LifecycleInput::StartCompleted(generation, res),
                        VmOp::Stop => LifecycleInput::StopCompleted(generation, res),
                    };
                    let retry_drop_stop = {
                        let mut c = lock(&handler_core);
                        // 停止通知で無効化済みの操作は成功を返さず、その時点の状態に応じた InvalidState を返す。
                        let outcome =
                            match c.complete_and_settle(generation, input, actual_state(vm)) {
                                Ok(()) => outcome,
                                Err(state) => Err(VmError::InvalidState { op, state }),
                            };
                        // 呼び出し元の放棄と直列化するため、Core のロック内で結果を送る（block しない）。
                        let _ = tx.try_send(outcome);
                        c.drop_stop_due()
                    };
                    // 破棄時に停止できなかった（起動途中等）VM は、この完了を機に停止を要求し直す。
                    if retry_drop_stop {
                        issue_drop_stop(vm, &handler_core);
                    }
                };
                let requested = match op {
                    VmOp::Start => vm.start(handler),
                    VmOp::Stop => vm.stop(handler),
                };
                // 受付後に要求直前の確認で拒否された（シリアルキュー上のため通常は起きない）。操作を取り消し、
                // 呼び出し元の放棄と直列化するため Core のロック内で InvalidState を返す。
                if let Err(rejected) = requested {
                    let actual = VmState::from_raw(rejected.state_raw);
                    let mut c = lock(&core);
                    let state = c.cancel_begun(generation, actual);
                    let _ = reject_tx.try_send(Err(VmError::InvalidState { op, state }));
                }
            });
            await_op_result(&rx, op, self.timeouts.for_op(op), |error| {
                self.give_up(&ticket, &rx, error)
            })
        }

        /// 待機期限切れ・通知経路の喪失の後始末（REPAIR-5）。操作を取り消すか放棄して後続の start / stop を
        /// 受け付けられるようにし、放棄した場合は VM キュー上で実状態へ追従させる。直前に結果が確定していれば
        /// それを、なければ `error` を返す。
        fn give_up(
            &self,
            ticket: &Mutex<OpTicket>,
            rx: &Receiver<Result<(), VmError>>,
            error: VmError,
        ) -> Result<(), VmError> {
            let abandoned = {
                let mut c = lock(&self.core);
                let mut t = lock(ticket);
                let outcome = c.abandon(&mut t);
                // 結果はロック内で送られるため、ここで空なら以後この操作の結果は呼び出し元へ届かない。
                if let Ok(result) = rx.try_recv() {
                    return result;
                }
                matches!(outcome, AbandonOutcome::Abandoned(_))
            };
            if abandoned {
                // キュー自体が詰まっていれば追従は後回しになるが、次の操作の受付時にも実状態へ追従する。
                let core = Arc::clone(&self.core);
                self.host
                    .run_async(move |vm| lock(&core).reconcile(actual_state(vm)));
            }
            Err(error)
        }
    }

    /// 破棄時の停止を VM キュー上で要求する（`Vm::drop` と、破棄後に届いた操作の完了通知から呼ばれる）。
    ///
    /// 停止の完了・失敗は `Core::finish_drop_stop` が状態機械とイベントへ記録する。失敗して要求回数が残って
    /// いれば `DROP_STOP_RETRY_DELAY` 後に VM キュー上でやり直す（VM はそれまで保持される）。停止できない
    /// 状態なら何もせず、破棄済みの印だけを残す。
    fn issue_drop_stop(vm: &VmRef<'_>, core: &Arc<Mutex<Core>>) {
        let actual = actual_state(vm);
        let can_stop = vm.can_stop();
        let Some(generation) = lock(core).request_drop_stop(can_stop, actual) else {
            return;
        };
        let handler_core = Arc::clone(core);
        let requested = vm.stop(move |vm: &VmRef<'_>, res: Result<(), ErrInfo>| {
            let retry = lock(&handler_core).finish_drop_stop(generation, res);
            if retry {
                let core = Arc::clone(&handler_core);
                vm.run_after(DROP_STOP_RETRY_DELAY, move |vm| issue_drop_stop(vm, &core));
            }
        });
        // 要求直前の確認で停止できなかった（既に止まった等）。完了通知は来ないので取り消す。
        if let Err(rejected) = requested {
            lock(core).cancel_begun(generation, VmState::from_raw(rejected.state_raw));
        }
    }

    impl Drop for Vm {
        fn drop(&mut self) {
            // ブロックしない: 停止要求を VM キューへ投入するだけ。キューはシリアルのため、この後に
            // `VmHost::drop` が投入する解放より先に実行され、停止の完了までは completion handler が VM を保持する。
            let core = Arc::clone(&self.core);
            self.host.run_async(move |vm| issue_drop_stop(vm, &core));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::Receiver;

    fn changed(from: VmState, to: VmState) -> VmEvent {
        VmEvent::StateChanged { from, to }
    }

    /// MAC-1・TASK-64.4: 生値 0..=9 が各状態に写り、範囲外は Unknown になる。
    #[test]
    fn from_raw_maps_known_and_unknown_values() {
        let expected = [
            VmState::Stopped,
            VmState::Running,
            VmState::Paused,
            VmState::Error,
            VmState::Starting,
            VmState::Pausing,
            VmState::Resuming,
            VmState::Stopping,
            VmState::Saving,
            VmState::Restoring,
        ];
        for (raw, state) in expected.into_iter().enumerate() {
            assert_eq!(VmState::from_raw(raw as isize), state);
        }
        assert_eq!(VmState::from_raw(-1), VmState::Unknown(-1));
        assert_eq!(VmState::from_raw(10), VmState::Unknown(10));
        assert_eq!(VmState::from_raw(isize::MAX), VmState::Unknown(isize::MAX));
    }

    /// MAC-1・TASK-64.4: VZVirtualMachineState の定数と生値の対応がずれていない。
    #[cfg(target_os = "macos")]
    #[test]
    fn from_raw_matches_framework_constants() {
        use objc2_virtualization::VZVirtualMachineState as S;
        assert_eq!(VmState::from_raw(S::Stopped.0), VmState::Stopped);
        assert_eq!(VmState::from_raw(S::Running.0), VmState::Running);
        assert_eq!(VmState::from_raw(S::Paused.0), VmState::Paused);
        assert_eq!(VmState::from_raw(S::Error.0), VmState::Error);
        assert_eq!(VmState::from_raw(S::Starting.0), VmState::Starting);
        assert_eq!(VmState::from_raw(S::Pausing.0), VmState::Pausing);
        assert_eq!(VmState::from_raw(S::Resuming.0), VmState::Resuming);
        assert_eq!(VmState::from_raw(S::Stopping.0), VmState::Stopping);
        assert_eq!(VmState::from_raw(S::Saving.0), VmState::Saving);
        assert_eq!(VmState::from_raw(S::Restoring.0), VmState::Restoring);
    }

    /// MAC-1・TASK-64.4: 正常な起動と停止の遷移。
    #[test]
    fn lifecycle_start_then_stop() {
        let mut lc = Lifecycle::new();
        assert_eq!(
            lc.step(LifecycleInput::StartRequested),
            vec![changed(VmState::Stopped, VmState::Starting)]
        );
        assert_eq!(
            lc.step(LifecycleInput::StartCompleted(1, Ok(()))),
            vec![changed(VmState::Starting, VmState::Running)]
        );
        assert_eq!(
            lc.step(LifecycleInput::StopRequested),
            vec![changed(VmState::Running, VmState::Stopping)]
        );
        assert_eq!(
            lc.step(LifecycleInput::StopCompleted(2, Ok(()))),
            vec![changed(VmState::Stopping, VmState::Stopped)]
        );
    }

    /// MAC-1・TASK-64.4: 起動失敗は Error へ遷移する。停止失敗は Running に戻る。
    #[test]
    fn lifecycle_failures() {
        let err = ("VZErrorDomain".to_string(), 2);
        let mut lc = Lifecycle::new();
        lc.step(LifecycleInput::StartRequested);
        assert_eq!(
            lc.step(LifecycleInput::StartCompleted(1, Err(err.clone()))),
            vec![changed(VmState::Starting, VmState::Error)]
        );
        let mut lc = Lifecycle::new();
        lc.step(LifecycleInput::StartRequested);
        lc.step(LifecycleInput::StartCompleted(1, Ok(())));
        lc.step(LifecycleInput::StopRequested);
        assert_eq!(
            lc.step(LifecycleInput::StopCompleted(2, Err(err))),
            vec![changed(VmState::Stopping, VmState::Running)]
        );
    }

    /// MAC-1・TASK-64.4: ゲスト停止・エラー停止の通知。
    #[test]
    fn lifecycle_delegate_notifications() {
        let mut lc = Lifecycle::new();
        lc.step(LifecycleInput::StartRequested);
        lc.step(LifecycleInput::StartCompleted(1, Ok(())));
        assert_eq!(
            lc.step(LifecycleInput::GuestStopped),
            vec![
                changed(VmState::Running, VmState::Stopped),
                VmEvent::GuestStopped
            ]
        );
        let mut lc = Lifecycle::new();
        lc.step(LifecycleInput::StartRequested);
        lc.step(LifecycleInput::StartCompleted(1, Ok(())));
        assert_eq!(
            lc.step(LifecycleInput::StoppedWithError(("D".to_string(), 7))),
            vec![
                changed(VmState::Running, VmState::Error),
                VmEvent::StoppedWithError {
                    domain: "D".to_string(),
                    code: 7
                }
            ]
        );
    }

    /// MAC-1・TASK-64.4: ゲスト停止後に遅れて届いた起動完了で Running へ逆行しない。
    #[test]
    fn stale_start_completion_after_guest_stop_is_ignored() {
        let mut lc = Lifecycle::new();
        lc.step(LifecycleInput::StartRequested);
        lc.step(LifecycleInput::GuestStopped);
        assert_eq!(
            lc.step(LifecycleInput::StartCompleted(1, Ok(()))),
            Vec::<VmEvent>::new()
        );
    }

    /// MAC-1・TASK-64.4: エラー停止後に届いた停止完了・古い世代の完了は無視される。
    /// TASK-64.4: 停止通知で無効化された操作の完了は受理されず、その時点の状態が返る。
    #[test]
    fn core_complete_rejects_invalidated_operation() {
        let (sink, _rx) = event_channel(8);
        let mut core = Core::new(sink);
        let generation = core.begin_unchecked(LifecycleInput::StartRequested);
        core.apply(LifecycleInput::GuestStopped);
        assert_eq!(
            core.complete(
                generation,
                LifecycleInput::StartCompleted(generation, Ok(()))
            ),
            Err(VmState::Stopped)
        );
        let generation = core.begin_unchecked(LifecycleInput::StartRequested);
        assert_eq!(
            core.complete(
                generation,
                LifecycleInput::StartCompleted(generation, Ok(()))
            ),
            Ok(())
        );
    }

    /// テスト用: チケットを新規に作って受け付け、操作世代を返す（受け付けられなければ panic）。
    fn begin_ok(core: &mut Core, input: LifecycleInput, actual: VmState) -> (OpTicket, u64) {
        let mut ticket = OpTicket::Pending;
        match core.begin(&mut ticket, input, true, actual) {
            BeginOutcome::Begun(generation) => (ticket, generation),
            other => panic!("unexpected begin outcome: {other:?}"),
        }
    }

    fn drain(rx: &Receiver<VmEvent>) -> Vec<VmEvent> {
        rx.try_iter().collect()
    }

    /// MAC-1・TASK-64.4: 進行中の操作がある間の重複要求は拒否し、先行操作の完了通知を潰さない。
    #[test]
    fn core_begin_rejects_overlapping_operation() {
        let (sink, _rx) = event_channel(8);
        let mut core = Core::new(sink);
        let (ticket, start) = begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        assert_eq!(ticket, OpTicket::Begun(1));
        let mut overlapping = OpTicket::Pending;
        assert_eq!(
            core.begin(
                &mut overlapping,
                LifecycleInput::StopRequested,
                true,
                VmState::Starting
            ),
            BeginOutcome::Rejected(VmState::Starting)
        );
        assert_eq!(overlapping, OpTicket::Settled);
        assert_eq!(core.lifecycle.state(), VmState::Starting);
        assert_eq!(
            core.complete(start, LifecycleInput::StartCompleted(start, Ok(()))),
            Ok(())
        );
        assert_eq!(core.lifecycle.state(), VmState::Running);
        let (_, stop) = begin_ok(&mut core, LifecycleInput::StopRequested, VmState::Running);
        assert_eq!(stop, 2);
    }

    /// MAC-1・TASK-64.4: `canStart` / `canStop` が false なら実状態を返して拒否し、取り消し済みなら何もしない。
    #[test]
    fn core_begin_rejects_disallowed_and_skips_cancelled() {
        let (sink, rx) = event_channel(8);
        let mut core = Core::new(sink);
        let mut ticket = OpTicket::Pending;
        assert_eq!(
            core.begin(
                &mut ticket,
                LifecycleInput::StopRequested,
                false,
                VmState::Stopped
            ),
            BeginOutcome::Rejected(VmState::Stopped)
        );
        assert_eq!(ticket, OpTicket::Settled);
        let mut cancelled = OpTicket::Cancelled;
        assert_eq!(
            core.begin(
                &mut cancelled,
                LifecycleInput::StartRequested,
                true,
                VmState::Stopped
            ),
            BeginOutcome::Cancelled
        );
        assert_eq!(core.lifecycle.state(), VmState::Stopped);
        assert_eq!(drain(&rx), Vec::<VmEvent>::new());
    }

    /// REPAIR-5・TASK-64.4: 未着手の操作は待機期限切れで取り消され、キュー上では実行されない。
    #[test]
    fn core_abandon_cancels_pending_operation() {
        let (sink, _rx) = event_channel(8);
        let mut core = Core::new(sink);
        let mut ticket = OpTicket::Pending;
        assert_eq!(core.abandon(&mut ticket), AbandonOutcome::NotStarted);
        assert_eq!(ticket, OpTicket::Cancelled);
        assert_eq!(
            core.begin(
                &mut ticket,
                LifecycleInput::StartRequested,
                true,
                VmState::Stopped
            ),
            BeginOutcome::Cancelled
        );
        assert!(!core.lifecycle.has_in_flight());
    }

    /// REPAIR-5・TASK-64.4: 完了通知が来ないまま放棄した操作は後続の要求を妨げず、実状態から停止できる。
    #[test]
    fn core_abandon_unblocks_following_operation() {
        let (sink, rx) = event_channel(16);
        let mut core = Core::new(sink);
        let (mut ticket, start) =
            begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        assert_eq!(core.abandon(&mut ticket), AbandonOutcome::Abandoned(start));
        assert!(!core.lifecycle.has_in_flight());
        drain(&rx);
        // VZ 上では起動が済んでいた（Running）。停止要求の受付時に実状態へ追従してから Stopping へ進む。
        let (_, stop) = begin_ok(&mut core, LifecycleInput::StopRequested, VmState::Running);
        assert_eq!(stop, 2);
        assert_eq!(
            drain(&rx),
            vec![
                changed(VmState::Starting, VmState::Running),
                changed(VmState::Running, VmState::Stopping)
            ]
        );
        // 新しい要求の後に届いた放棄済み操作の完了は古い通知として捨てる。
        assert_eq!(
            core.complete(start, LifecycleInput::StartCompleted(start, Ok(()))),
            Err(VmState::Stopping)
        );
        assert_eq!(
            core.complete(stop, LifecycleInput::StopCompleted(stop, Ok(()))),
            Ok(())
        );
        assert_eq!(core.lifecycle.state(), VmState::Stopped);
    }

    /// REPAIR-5・TASK-64.4: 放棄後に遅れて届いた完了は、他の操作・停止通知がなければ状態機械に適用する。
    #[test]
    fn core_applies_late_completion_of_abandoned_operation() {
        let (sink, rx) = event_channel(16);
        let mut core = Core::new(sink);
        let (mut ticket, start) =
            begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        core.abandon(&mut ticket);
        // 放棄直後の追従で、実状態がまだ Starting なら変化なし。
        core.reconcile(VmState::Starting);
        drain(&rx);
        assert_eq!(
            core.complete(start, LifecycleInput::StartCompleted(start, Ok(()))),
            Ok(())
        );
        assert_eq!(
            drain(&rx),
            vec![changed(VmState::Starting, VmState::Running)]
        );
        // 受理は 1 回限り。
        assert_eq!(
            core.complete(start, LifecycleInput::StartCompleted(start, Ok(()))),
            Err(VmState::Running)
        );
    }

    /// REPAIR-5・TASK-64.4: 放棄後に停止通知が先着したら、遅れた起動完了で Running へ逆行しない。
    #[test]
    fn core_ignores_late_completion_after_abandon_and_guest_stop() {
        let (sink, rx) = event_channel(16);
        let mut core = Core::new(sink);
        let (mut ticket, start) =
            begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        core.abandon(&mut ticket);
        core.apply(LifecycleInput::GuestStopped);
        drain(&rx);
        assert_eq!(
            core.complete(start, LifecycleInput::StartCompleted(start, Ok(()))),
            Err(VmState::Stopped)
        );
        assert_eq!(drain(&rx), Vec::<VmEvent>::new());
        assert_eq!(core.lifecycle.state(), VmState::Stopped);
    }

    /// REPAIR-5・TASK-64.4: 放棄後の要求が `canStart` で拒否されても、状態機械は実状態へ追従する。
    #[test]
    fn core_rejected_request_after_abandon_follows_actual_state() {
        let (sink, rx) = event_channel(16);
        let mut core = Core::new(sink);
        let (mut ticket, _start) =
            begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        core.abandon(&mut ticket);
        drain(&rx);
        let mut again = OpTicket::Pending;
        assert_eq!(
            core.begin(
                &mut again,
                LifecycleInput::StartRequested,
                false,
                VmState::Running
            ),
            BeginOutcome::Rejected(VmState::Running)
        );
        assert_eq!(
            drain(&rx),
            vec![changed(VmState::Starting, VmState::Running)]
        );
        assert_eq!(core.lifecycle.state(), VmState::Running);
    }

    /// REPAIR-5・TASK-64.4: 完了済みの操作の放棄は何もしない（結果は確定済み）。
    #[test]
    fn core_abandon_after_completion_is_settled() {
        let (sink, _rx) = event_channel(8);
        let mut core = Core::new(sink);
        let (mut ticket, start) =
            begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        core.complete(start, LifecycleInput::StartCompleted(start, Ok(())))
            .unwrap();
        assert_eq!(core.abandon(&mut ticket), AbandonOutcome::Settled);
        assert_eq!(core.lifecycle.state(), VmState::Running);
        let mut rejected = OpTicket::Settled;
        assert_eq!(core.abandon(&mut rejected), AbandonOutcome::Settled);
    }

    /// TASK-64.4: 進行中の操作がある間は実状態へ追従せず、ない間は差分を StateChanged で出す。
    #[test]
    fn core_reconcile_follows_actual_state_only_when_idle() {
        let (sink, rx) = event_channel(8);
        let mut core = Core::new(sink);
        let (_, _start) = begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        drain(&rx);
        core.reconcile(VmState::Running);
        assert_eq!(core.lifecycle.state(), VmState::Starting);
        assert_eq!(drain(&rx), Vec::<VmEvent>::new());
        let (sink, rx) = event_channel(8);
        let mut idle = Core::new(sink);
        idle.reconcile(VmState::Running);
        assert_eq!(
            drain(&rx),
            vec![changed(VmState::Stopped, VmState::Running)]
        );
    }

    /// TASK-64.4: 破棄時に実行中なら停止を要求し、成功すれば Stopped で終わる。
    #[test]
    fn core_drop_stop_stops_running_vm() {
        let (sink, rx) = event_channel(16);
        let mut core = Core::new(sink);
        let (_, start) = begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        core.complete(start, LifecycleInput::StartCompleted(start, Ok(())))
            .unwrap();
        drain(&rx);
        let stop = core.request_drop_stop(true, VmState::Running);
        assert_eq!(stop, Some(2));
        assert!(!core.finish_drop_stop(2, Ok(())));
        assert_eq!(
            drain(&rx),
            vec![
                changed(VmState::Running, VmState::Stopping),
                changed(VmState::Stopping, VmState::Stopped)
            ]
        );
        assert!(core.drop_stop_due());
    }

    /// TASK-64.4: 破棄時の停止は失敗しても DROP_STOP_MAX_ATTEMPTS 回までやり直し、使い切った失敗だけを
    /// StopOnDropFailed として記録する。以後は要求しない。
    #[test]
    fn core_drop_stop_retries_then_records_failure() {
        let (sink, rx) = event_channel(32);
        let mut core = Core::new(sink);
        let err = || Err(("VZErrorDomain".to_string(), 3));
        assert_eq!(core.request_drop_stop(true, VmState::Running), Some(1));
        assert!(core.finish_drop_stop(1, err()));
        assert_eq!(core.request_drop_stop(true, VmState::Running), Some(2));
        assert!(core.finish_drop_stop(2, err()));
        drain(&rx);
        assert_eq!(core.request_drop_stop(true, VmState::Running), Some(3));
        assert!(!core.finish_drop_stop(3, err()));
        assert_eq!(
            drain(&rx),
            vec![
                changed(VmState::Running, VmState::Stopping),
                changed(VmState::Stopping, VmState::Running),
                VmEvent::StopOnDropFailed {
                    domain: "VZErrorDomain".to_string(),
                    code: 3,
                    attempts: DROP_STOP_MAX_ATTEMPTS
                }
            ]
        );
        assert_eq!(core.request_drop_stop(true, VmState::Running), None);
        assert_eq!(core.lifecycle.state(), VmState::Running);
    }

    /// TASK-64.4: 破棄時の停止が 1 回目に失敗しても、やり直しが成功すれば Stopped で終わり失敗は記録しない。
    #[test]
    fn core_drop_stop_retry_succeeds_on_second_attempt() {
        let (sink, rx) = event_channel(32);
        let mut core = Core::new(sink);
        assert_eq!(core.request_drop_stop(true, VmState::Running), Some(1));
        assert!(core.finish_drop_stop(1, Err(("VZErrorDomain".to_string(), 3))));
        assert_eq!(core.request_drop_stop(true, VmState::Running), Some(2));
        assert!(!core.finish_drop_stop(2, Ok(())));
        assert_eq!(
            drain(&rx),
            vec![
                changed(VmState::Stopped, VmState::Running),
                changed(VmState::Running, VmState::Stopping),
                changed(VmState::Stopping, VmState::Running),
                changed(VmState::Running, VmState::Stopping),
                changed(VmState::Stopping, VmState::Stopped)
            ]
        );
    }

    /// TASK-64.4: 停止通知が先着して無効化された破棄時停止の失敗は、記録もやり直しもしない。
    #[test]
    fn core_drop_stop_failure_after_stop_notification_is_ignored() {
        let (sink, rx) = event_channel(32);
        let mut core = Core::new(sink);
        let err = || Err(("VZErrorDomain".to_string(), 3));
        // 最後の 1 回で停止通知が先着する場合も含めて確認する。
        for attempt in 1..u64::from(DROP_STOP_MAX_ATTEMPTS) {
            assert_eq!(
                core.request_drop_stop(true, VmState::Running),
                Some(attempt)
            );
            assert!(core.finish_drop_stop(attempt, err()));
        }
        let last = u64::from(DROP_STOP_MAX_ATTEMPTS);
        assert_eq!(core.request_drop_stop(true, VmState::Running), Some(last));
        drain(&rx);
        core.apply(LifecycleInput::GuestStopped);
        assert!(!core.finish_drop_stop(last, err()));
        assert_eq!(
            drain(&rx),
            vec![
                changed(VmState::Stopping, VmState::Stopped),
                VmEvent::GuestStopped
            ]
        );
        assert_eq!(core.lifecycle.state(), VmState::Stopped);
        // 1 回目で停止通知が先着した場合もやり直さない。
        let (sink, rx) = event_channel(8);
        let mut core = Core::new(sink);
        assert_eq!(core.request_drop_stop(true, VmState::Running), Some(1));
        core.apply(LifecycleInput::StoppedWithError(("D".to_string(), 7)));
        drain(&rx);
        assert!(!core.finish_drop_stop(1, err()));
        assert_eq!(drain(&rx), Vec::<VmEvent>::new());
    }

    /// TASK-64.4: 停止できない間（起動途中・完了待ち）の破棄は印だけ残し、完了後に停止を要求し直す。
    #[test]
    fn core_drop_stop_is_deferred_until_operation_completes() {
        let (sink, _rx) = event_channel(16);
        let mut core = Core::new(sink);
        let (mut ticket, start) =
            begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        core.abandon(&mut ticket);
        // 起動途中で canStop が false。
        assert_eq!(core.request_drop_stop(false, VmState::Starting), None);
        assert!(core.drop_stop_due());
        core.complete(start, LifecycleInput::StartCompleted(start, Ok(())))
            .unwrap();
        assert!(core.drop_stop_due());
        assert_eq!(core.request_drop_stop(true, VmState::Running), Some(2));
        assert!(!core.drop_stop_due());
        assert_eq!(core.lifecycle.state(), VmState::Stopping);
    }

    /// TASK-64.4: 完了待ちの操作がある間は破棄時の停止を要求しない（その完了を待って再試行する）。
    #[test]
    fn core_drop_stop_waits_for_in_flight_operation() {
        let (sink, _rx) = event_channel(16);
        let mut core = Core::new(sink);
        let (_, start) = begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        assert_eq!(core.request_drop_stop(true, VmState::Starting), None);
        assert!(!core.drop_stop_due());
        core.complete(start, LifecycleInput::StartCompleted(start, Ok(())))
            .unwrap();
        assert!(core.drop_stop_due());
    }

    /// MAC-1・TASK-64.4: 停止通知が停止完了より先着しても、停止要求は正常終了として扱う。
    #[test]
    fn core_complete_accepts_stop_after_guest_stopped_notification() {
        let (sink, _rx) = event_channel(8);
        let mut core = Core::new(sink);
        let start = core.begin_unchecked(LifecycleInput::StartRequested);
        core.complete(start, LifecycleInput::StartCompleted(start, Ok(())))
            .unwrap();
        let stop = core.begin_unchecked(LifecycleInput::StopRequested);
        core.apply(LifecycleInput::GuestStopped);
        assert_eq!(
            core.complete(stop, LifecycleInput::StopCompleted(stop, Ok(()))),
            Ok(())
        );
        assert_eq!(core.lifecycle.state(), VmState::Stopped);
    }

    #[test]
    fn stale_completions_are_ignored() {
        let mut lc = Lifecycle::new();
        lc.step(LifecycleInput::StartRequested);
        lc.step(LifecycleInput::StartCompleted(1, Ok(())));
        lc.step(LifecycleInput::StopRequested);
        lc.step(LifecycleInput::StoppedWithError(("D".to_string(), 7)));
        assert_eq!(
            lc.step(LifecycleInput::StopCompleted(2, Ok(()))),
            Vec::<VmEvent>::new()
        );
        // 停止後の再起動に対し、前回の世代の完了は適用されない。
        lc.step(LifecycleInput::StartRequested);
        assert_eq!(
            lc.step(LifecycleInput::StartCompleted(1, Ok(()))),
            Vec::<VmEvent>::new()
        );
        assert_eq!(
            lc.step(LifecycleInput::StartCompleted(3, Ok(()))),
            vec![changed(VmState::Starting, VmState::Running)]
        );
    }

    /// MAC-1・TASK-64.4: 溢れた件数は次に送れた時に EventsDropped で先に通知される。
    #[test]
    fn event_sink_reports_dropped_events() {
        let (mut sink, rx) = event_channel(1);
        sink.send(VmEvent::GuestStopped);
        sink.send(VmEvent::GuestStopped);
        sink.send(VmEvent::GuestStopped);
        assert_eq!(rx.try_recv(), Ok(VmEvent::GuestStopped));
        sink.send(VmEvent::GuestStopped);
        assert_eq!(rx.try_recv(), Ok(VmEvent::EventsDropped { count: 2 }));
        assert!(rx.try_recv().is_err());
    }

    /// REPAIR-4・TASK-64.4: 積めたかを返す（満杯・受信側なしは false）。
    #[test]
    fn event_sink_send_reports_delivery() {
        let (mut sink, rx) = event_channel(1);
        assert!(sink.send(VmEvent::GuestStopped));
        assert!(!sink.send(VmEvent::GuestStopped));
        assert_eq!(rx.try_recv(), Ok(VmEvent::GuestStopped));
        drop(rx);
        assert!(!sink.send(VmEvent::GuestStopped));
    }

    /// REPAIR-4・TASK-64.4: 破棄時停止の失敗ログは 1 行の JSON で、domain の引用符・制御文字をエスケープする。
    #[test]
    fn stop_on_drop_failure_log_escapes_domain() {
        assert_eq!(
            stop_on_drop_failure_log("VZErrorDomain", 3, 3),
            r#"{"component":"platform-macos.vm","operation":"stop_on_drop","result":"error","code":"vm.stop_failed","domain":"VZErrorDomain","vz_code":3,"attempts":3}"#
        );
        assert_eq!(
            stop_on_drop_failure_log("a\"b\\c\nd", -1, 1),
            r#"{"component":"platform-macos.vm","operation":"stop_on_drop","result":"error","code":"vm.stop_failed","domain":"a\"b\\c\u000ad","vz_code":-1,"attempts":1}"#
        );
    }

    /// REPAIR-4・TASK-64.4: DEL・NEL・U+2028 / U+2029 も \uXXXX にエスケープし、1 行に収める。
    #[test]
    fn stop_on_drop_failure_log_escapes_line_separators() {
        let line = stop_on_drop_failure_log("a\u{7f}b\u{85}c\u{2028}d\u{2029}e", 1, 3);
        assert_eq!(
            line,
            r#"{"component":"platform-macos.vm","operation":"stop_on_drop","result":"error","code":"vm.stop_failed","domain":"a\u007fb\u0085c\u2028d\u2029e","vz_code":1,"attempts":3}"#
        );
        assert_eq!(line.lines().count(), 1);
    }

    /// TASK-64.4: 要求直前の確認で拒否された操作は取り消され、実状態へ戻って後続の要求を受け付ける。
    #[test]
    fn core_cancel_begun_restores_actual_state() {
        let (sink, rx) = event_channel(16);
        let mut core = Core::new(sink);
        let (_, start) = begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        drain(&rx);
        assert_eq!(core.cancel_begun(start, VmState::Stopped), VmState::Stopped);
        assert_eq!(
            drain(&rx),
            vec![changed(VmState::Starting, VmState::Stopped)]
        );
        assert!(!core.lifecycle.has_in_flight());
        // 取り消した世代の完了は受理しない。
        assert_eq!(
            core.complete(start, LifecycleInput::StartCompleted(start, Ok(()))),
            Err(VmState::Stopped)
        );
        let (_, again) = begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        assert_eq!(again, 2);
    }

    /// TASK-64.4: 放棄済みの操作を取り消すと、遅れた完了の受理の目印も消える。
    #[test]
    fn core_cancel_begun_clears_abandoned_marker() {
        let (sink, _rx) = event_channel(16);
        let mut core = Core::new(sink);
        let (mut ticket, start) =
            begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        core.abandon(&mut ticket);
        assert!(core.lifecycle.accepts(start));
        core.cancel_begun(start, VmState::Stopped);
        assert!(!core.lifecycle.accepts(start));
        assert_eq!(core.lifecycle.state(), VmState::Stopped);
    }

    /// TASK-64.4: 受信側が破棄済みでも破棄時停止の失敗の記録は panic せず、状態機械は Running に戻る。
    #[test]
    fn core_drop_stop_failure_without_receiver_does_not_panic() {
        let (sink, rx) = event_channel(4);
        let mut core = Core::new(sink);
        drop(rx);
        for attempt in 1..=u64::from(DROP_STOP_MAX_ATTEMPTS) {
            assert_eq!(
                core.request_drop_stop(true, VmState::Running),
                Some(attempt)
            );
            let retry = core.finish_drop_stop(attempt, Err(("VZErrorDomain".to_string(), 3)));
            assert_eq!(retry, attempt < u64::from(DROP_STOP_MAX_ATTEMPTS));
        }
        assert_eq!(core.lifecycle.state(), VmState::Running);
    }

    /// MAC-1・TASK-64.4: 受信側が drop 済みでも送信は panic しない。
    #[test]
    fn event_sink_tolerates_disconnected_receiver() {
        let (mut sink, rx) = event_channel(1);
        drop(rx);
        sink.send(VmEvent::GuestStopped);
        sink.send(VmEvent::GuestStopped);
    }

    /// MAC-1・TASK-64.4: エラーコードは一意で `vm.` で始まり、Display は `<code>: <message>`。
    #[test]
    fn error_codes_are_unique_and_prefixed() {
        let errors = [
            VmError::VirtualizationUnsupported,
            VmError::InvalidConfiguration {
                domain: "d".into(),
                code: 1,
            },
            VmError::InvalidState {
                op: VmOp::Start,
                state: VmState::Running,
            },
            VmError::StartFailed {
                domain: "d".into(),
                code: 1,
            },
            VmError::StopFailed {
                domain: "d".into(),
                code: 1,
            },
            VmError::Timeout {
                op: VmOp::Stop,
                after: Duration::from_secs(3),
            },
            VmError::CallbackLost { op: VmOp::Start },
        ];
        let mut codes: Vec<&str> = errors.iter().map(VmError::code).collect();
        assert!(codes.iter().all(|c| c.starts_with("vm.")));
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
        assert_eq!(
            errors[2].to_string(),
            "vm.invalid_state: cannot start the virtual machine in state Running"
        );
        assert_eq!(
            errors[5].to_string(),
            "vm.timeout: stop did not complete within 3s"
        );
    }

    /// REPAIR-5・TASK-64.5: 結果が届かないまま期限を過ぎたら `Timeout` を返し、放棄処理に渡る。
    #[test]
    fn await_op_result_times_out_with_concrete_error() {
        let (_tx, rx) = std::sync::mpsc::sync_channel::<Result<(), VmError>>(1);
        let started = std::time::Instant::now();
        let res = await_op_result(&rx, VmOp::Start, Duration::from_millis(50), Err);
        assert_eq!(
            res,
            Err(VmError::Timeout {
                op: VmOp::Start,
                after: Duration::from_millis(50)
            })
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// REPAIR-5・TASK-64.5: 送信側が失われたら `CallbackLost`。
    #[test]
    fn await_op_result_reports_callback_lost() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(), VmError>>(1);
        drop(tx);
        let res = await_op_result(&rx, VmOp::Stop, Duration::from_secs(5), Err);
        assert_eq!(res, Err(VmError::CallbackLost { op: VmOp::Stop }));
    }

    /// REPAIR-5・TASK-64.5: 期限内に届いた結果はそのまま返り、放棄処理は呼ばれない。
    #[test]
    fn await_op_result_returns_delivered_result_without_give_up() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(), VmError>>(1);
        let failure = VmError::StartFailed {
            domain: "D".into(),
            code: 5,
        };
        tx.send(Err(failure.clone())).expect("send");
        let res = await_op_result(&rx, VmOp::Start, Duration::from_secs(5), |_| {
            panic!("give_up must not run")
        });
        assert_eq!(res, Err(failure));
    }

    /// REPAIR-5・TASK-64.5: 放棄の直前に確定した結果は期限切れより優先される。
    #[test]
    fn await_op_result_prefers_late_settled_result() {
        let (_tx, rx) = std::sync::mpsc::sync_channel::<Result<(), VmError>>(1);
        let res = await_op_result(&rx, VmOp::Start, Duration::from_millis(20), |_| Ok(()));
        assert_eq!(res, Ok(()));
    }

    /// REPAIR-5・TASK-64.5: 既定値は具体値で固定し、境界値の内側だけ受理する。
    #[test]
    fn op_timeouts_defaults_and_bounds() {
        let d = OpTimeouts::default();
        assert_eq!(d.start(), Duration::from_secs(30));
        assert_eq!(d.stop(), Duration::from_secs(15));
        assert_eq!(d.state_query(), Duration::from_secs(5));
        assert_eq!(d.for_op(VmOp::Stop), Duration::from_secs(15));

        let ok = OpTimeouts::try_new(MIN_OP_TIMEOUT, MAX_OP_TIMEOUT, MIN_OP_TIMEOUT);
        assert_eq!(ok.map(|t| t.stop()), Ok(MAX_OP_TIMEOUT));

        let one_ns = Duration::from_nanos(1);
        for (bad, field) in [
            (MIN_OP_TIMEOUT - one_ns, "start"),
            (MAX_OP_TIMEOUT + one_ns, "stop"),
            (Duration::ZERO, "state_query"),
        ] {
            let ok = Duration::from_secs(1);
            let res = match field {
                "start" => OpTimeouts::try_new(bad, ok, ok),
                "stop" => OpTimeouts::try_new(ok, bad, ok),
                _ => OpTimeouts::try_new(ok, ok, bad),
            };
            assert_eq!(
                res,
                Err(VmError::InvalidTimeout {
                    field,
                    requested: bad,
                    min: MIN_OP_TIMEOUT,
                    max: MAX_OP_TIMEOUT
                })
            );
        }
    }

    /// MAC-1・TASK-64.5: 起動失敗の完了直後に実状態 Stopped へ追従し、Error のまま残らない。
    #[test]
    fn failed_start_settles_to_actual_state() {
        let (sink, rx) = event_channel(8);
        let mut core = Core::new(sink);
        let (_, generation) = begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        let res = core.complete_and_settle(
            generation,
            LifecycleInput::StartCompleted(generation, Err(("VZErrorDomain".to_string(), 1))),
            VmState::Stopped,
        );
        assert_eq!(res, Ok(()));
        assert_eq!(core.lifecycle.state(), VmState::Stopped);
        assert_eq!(
            drain(&rx),
            vec![
                changed(VmState::Stopped, VmState::Starting),
                changed(VmState::Starting, VmState::Error),
                changed(VmState::Error, VmState::Stopped),
            ]
        );
    }

    /// MAC-1・TASK-64.5: 成功した完了では追加の追従イベントを出さない。
    #[test]
    fn successful_start_does_not_reconcile_extra() {
        let (sink, rx) = event_channel(8);
        let mut core = Core::new(sink);
        let (_, generation) = begin_ok(&mut core, LifecycleInput::StartRequested, VmState::Stopped);
        let res = core.complete_and_settle(
            generation,
            LifecycleInput::StartCompleted(generation, Ok(())),
            VmState::Running,
        );
        assert_eq!(res, Ok(()));
        assert_eq!(
            drain(&rx),
            vec![
                changed(VmState::Stopped, VmState::Starting),
                changed(VmState::Starting, VmState::Running),
            ]
        );
    }

    /// MAC-1・REPAIR-5・TASK-64.5: `Vm::launch` が失敗しても、コンソールログの排他 lock は有界時間内に解放される。
    ///
    /// 実機起動は要さない。GitHub の macOS ランナーでは `VirtualizationUnsupported`、entitlement がない環境では
    /// `InvalidConfiguration`、ダミー kernel では `StartFailed` で失敗する。いずれも許容し、lock の解放だけを確認する。
    #[cfg(target_os = "macos")]
    #[test]
    fn launch_failure_releases_console_log_lock() {
        use crate::config::{ConsoleLogPath, DeviceConfigSpec, SerialConsoleSink, VmConfigSpec};
        use std::os::unix::fs::PermissionsExt;

        // 既存ディレクトリを再利用・削除しないよう、`create_dir`（既存なら失敗）で新規作成できた名前だけを使う。
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temp dir");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = (0..100u32)
            .find_map(|n| {
                let candidate = base.join(format!(
                    "fandhe-macos-launch-{}-{nanos}-{n}",
                    std::process::id()
                ));
                std::fs::create_dir(&candidate).ok().map(|()| candidate)
            })
            .expect("create a fresh unique temp dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let kernel = dir.join("vmlinux");
        std::fs::write(&kernel, b"dummy").expect("write kernel");
        std::fs::set_permissions(&kernel, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let log = dir.join("console.log");

        let devices = DeviceConfigSpec::try_new(
            vec![],
            Some(SerialConsoleSink::LogFile(
                ConsoleLogPath::try_new(&log).expect("log path"),
            )),
        )
        .expect("devices");
        let spec = VmConfigSpec::from_parts(&kernel, None, "console=hvc0")
            .and_then(|s| s.with_devices(devices))
            .expect("spec");

        let timeouts = OpTimeouts::try_new(
            Duration::from_secs(10),
            Duration::from_secs(10),
            Duration::from_secs(5),
        )
        .expect("timeouts");
        match Vm::launch(&spec, timeouts) {
            Ok(vm) => drop(vm),
            Err(e) => assert!(
                [
                    "vm.virtualization_unsupported",
                    "vm.invalid_configuration",
                    "vm.start_failed",
                    "vm.timeout",
                ]
                .contains(&e.code()),
                "unexpected launch error: {e}"
            ),
        }

        // lock の解放は VM キュー上で非同期に起きるため、有界ポーリングで確認する（REPAIR-5）。
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let sink = loop {
            match spec.open_serial_console() {
                Ok(Some(sink)) => break sink,
                Ok(None) => panic!("console sink is configured"),
                Err(e) if e.code() == "config.console_log_in_use" => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "console log lock was not released"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("unexpected error: {e}"),
            }
        };
        sink.finish(Duration::from_secs(5));
        // このテストが新規作成したディレクトリ配下の既知ファイルだけを消す（再帰削除はしない）。
        let _ = std::fs::remove_file(&log);
        let _ = std::fs::remove_file(&kernel);
        let _ = std::fs::remove_dir(&dir);
    }

    /// MAC-1・REPAIR-5・TASK-65.3: ゲスト mount の待機時間は既定 60 秒で、範囲外は `vm.invalid_timeout`。
    #[test]
    fn guest_mount_timeout_default_and_bounds() {
        assert_eq!(OpTimeouts::default().guest_mount(), Duration::from_secs(60));
        let ok = OpTimeouts::default()
            .with_guest_mount(MAX_OP_TIMEOUT)
            .unwrap();
        assert_eq!(ok.guest_mount(), MAX_OP_TIMEOUT);
        assert_eq!(ok.start(), DEFAULT_START_TIMEOUT);
        let one_ns = Duration::from_nanos(1);
        for bad in [MIN_OP_TIMEOUT - one_ns, MAX_OP_TIMEOUT + one_ns] {
            assert_eq!(
                OpTimeouts::default().with_guest_mount(bad),
                Err(VmError::InvalidTimeout {
                    field: "guest_mount",
                    requested: bad,
                    min: MIN_OP_TIMEOUT,
                    max: MAX_OP_TIMEOUT
                })
            );
        }
    }

    /// REPAIR-5・MAC-1・TASK-115.3: 共有走査の期限は既定で未指定（従来どおり）で、指定は範囲内のみ受け付ける。
    #[test]
    fn share_scan_timeout_default_and_bounds() {
        assert_eq!(OpTimeouts::default().share_scan(), None);
        let base = OpTimeouts::try_new(MIN_OP_TIMEOUT, MIN_OP_TIMEOUT, MIN_OP_TIMEOUT).unwrap();
        assert_eq!(base.share_scan(), None);
        let ok = base.with_share_scan(Duration::from_secs(2)).unwrap();
        assert_eq!(ok.share_scan(), Some(Duration::from_secs(2)));
        assert_eq!(ok.guest_mount(), DEFAULT_GUEST_MOUNT_TIMEOUT);
        let one_ns = Duration::from_nanos(1);
        for bad in [MIN_OP_TIMEOUT - one_ns, MAX_OP_TIMEOUT + one_ns] {
            assert_eq!(
                OpTimeouts::default().with_share_scan(bad),
                Err(VmError::InvalidTimeout {
                    field: "share_scan",
                    requested: bad,
                    min: MIN_OP_TIMEOUT,
                    max: MAX_OP_TIMEOUT
                })
            );
        }
    }
}
