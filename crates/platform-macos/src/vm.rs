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
//! 注意: `start` / `stop` / `state` を VM キュー上（イベント処理の中など）から呼ぶとデッドロックする。
//! 最後の防壁としてタイムアウトが `VmError::Timeout` を返す。
//!
//! 未実装（REPAIR-3）: 待機タイムアウトの既定値の確定、起動失敗時のクリーンアップ、実行中 VM の `Drop` 時
//! 停止、`VmError` の `error.rs` への移動と `ConfigError` との統合は TASK-64.5。協調停止（`requestStop`）・
//! pause / resume / save / restore は範囲外。

use std::fmt;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::time::Duration;

/// NSError の要約（domain, code）。
type ErrInfo = (String, isize);

/// イベントチャネルの容量。溢れた分は `VmEvent::EventsDropped` で通知する。
pub const EVENT_CHANNEL_CAPACITY: usize = 64;

/// start / stop の待機タイムアウトの暫定値。既定値の確定とクリーンアップは TASK-64.5。
pub const PROVISIONAL_OP_TIMEOUT: Duration = Duration::from_secs(30);

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
}

/// 失敗した操作の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmOp {
    Start,
    Stop,
}

impl VmOp {
    fn as_str(self) -> &'static str {
        match self {
            VmOp::Start => "start",
            VmOp::Stop => "stop",
        }
    }
}

/// VM ライフサイクルのエラー（ERR 系・REPAIR-4。message は英語）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VmError {
    /// Virtualization.framework がこの環境で使えない。
    VirtualizationUnsupported,
    /// 設定が `validateWithError` に拒否された（entitlement 欠如を含む）。
    InvalidConfiguration {
        domain: String,
        code: isize,
    },
    /// 現在の状態では操作できない（`canStart` / `canStop` が false）。
    InvalidState {
        op: VmOp,
        state: VmState,
    },
    StartFailed {
        domain: String,
        code: isize,
    },
    StopFailed {
        domain: String,
        code: isize,
    },
    /// 完了通知が期限内に届かなかった。
    Timeout {
        op: VmOp,
        after: Duration,
    },
    /// 完了通知が届く前に通知経路が失われた。
    CallbackLost {
        op: VmOp,
    },
}

impl VmError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            VmError::VirtualizationUnsupported => "vm.virtualization_unsupported",
            VmError::InvalidConfiguration { .. } => "vm.invalid_configuration",
            VmError::InvalidState { .. } => "vm.invalid_state",
            VmError::StartFailed { .. } => "vm.start_failed",
            VmError::StopFailed { .. } => "vm.stop_failed",
            VmError::Timeout { .. } => "vm.timeout",
            VmError::CallbackLost { .. } => "vm.callback_lost",
        }
    }

    /// 人間可読なメッセージ（英語）。
    pub fn message(&self) -> String {
        match self {
            VmError::VirtualizationUnsupported => {
                "Virtualization.framework is not supported on this host".to_string()
            }
            VmError::InvalidConfiguration { domain, code } => {
                format!("virtual machine configuration was rejected ({domain}, code {code})")
            }
            VmError::InvalidState { op, state } => {
                format!(
                    "cannot {} the virtual machine in state {state:?}",
                    op.as_str()
                )
            }
            VmError::StartFailed { domain, code } => {
                format!("virtual machine failed to start ({domain}, code {code})")
            }
            VmError::StopFailed { domain, code } => {
                format!("virtual machine failed to stop ({domain}, code {code})")
            }
            VmError::Timeout { op, after } => {
                format!("{} did not complete within {after:?}", op.as_str())
            }
            VmError::CallbackLost { op } => {
                format!(
                    "completion of {} was lost before it was delivered",
                    op.as_str()
                )
            }
        }
    }
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for VmError {}

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
/// `reconcile` で実状態へ追従する。完了直後の常時追従は TASK-64.5 で扱う。
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
    /// 受信側が drop 済みなら黙って捨てる。
    pub(crate) fn send(&mut self, event: VmEvent) {
        if self.dropped > 0 {
            let notice = VmEvent::EventsDropped {
                count: self.dropped,
            };
            match self.tx.try_send(notice) {
                Ok(()) => self.dropped = 0,
                Err(TrySendError::Full(_)) => {
                    self.dropped = self.dropped.saturating_add(1);
                    return;
                }
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
        if let Err(TrySendError::Full(_)) = self.tx.try_send(event) {
            self.dropped = self.dropped.saturating_add(1);
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
}

// macOS 限定の `Vm` だけが使う内部項目。他 OS ではテストからのみ参照されるため、この項目に限り dead_code を許容する。
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl Core {
    pub(crate) fn new(sink: EventSink) -> Core {
        Core {
            lifecycle: Lifecycle::new(),
            sink,
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

    pub(crate) fn apply(&mut self, input: LifecycleInput) {
        for event in self.lifecycle.step(input) {
            self.sink.send(event);
        }
    }
}

#[cfg(target_os = "macos")]
pub use mac::Vm;

#[cfg(target_os = "macos")]
mod mac {
    use std::sync::mpsc::{Receiver, RecvTimeoutError};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::Duration;

    use super::{
        AbandonOutcome, BeginOutcome, Core, EVENT_CHANNEL_CAPACITY, ErrInfo, LifecycleInput,
        OpTicket, PROVISIONAL_OP_TIMEOUT, VmError, VmEvent, VmOp, VmState, event_channel,
    };
    use crate::config::VzVmConfiguration;
    use crate::sys::{self, DelegateEvent, HostInitError, VmRef};

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
    /// `Drop` は VM を専用キュー上で解放するだけで、実行中 VM の停止はしない（TASK-64.5）。
    pub struct Vm {
        host: sys::VmHost,
        core: Arc<Mutex<Core>>,
        events: Option<Receiver<VmEvent>>,
        op_timeout: Duration,
    }

    impl Vm {
        /// 構築済み設定から VM を生成する（起動はしない）。
        pub fn create(config: &VzVmConfiguration) -> Result<Vm, VmError> {
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
                op_timeout: PROVISIONAL_OP_TIMEOUT,
            })
        }

        /// VM を起動し、完了（または失敗・タイムアウト）まで待つ。
        pub fn start(&self) -> Result<(), VmError> {
            self.run_op(VmOp::Start)
        }

        /// VM を破壊的に停止し、完了まで待つ（協調停止は範囲外）。
        pub fn stop(&self) -> Result<(), VmError> {
            self.run_op(VmOp::Stop)
        }

        /// フレームワークが報告する現在の状態。`op_timeout` 内に取得できなければ `Unknown(-1)`（REPAIR-5）。
        pub fn state(&self) -> VmState {
            self.host
                .run_timeout(self.op_timeout, actual_state)
                .unwrap_or(VmState::Unknown(-1))
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
                let handler = move |res: Result<(), ErrInfo>| {
                    let outcome = res.clone().map_err(|(domain, code)| match op {
                        VmOp::Start => VmError::StartFailed { domain, code },
                        VmOp::Stop => VmError::StopFailed { domain, code },
                    });
                    let input = match op {
                        VmOp::Start => LifecycleInput::StartCompleted(generation, res),
                        VmOp::Stop => LifecycleInput::StopCompleted(generation, res),
                    };
                    {
                        let mut c = lock(&handler_core);
                        // 停止通知で無効化済みの操作は成功を返さず、その時点の状態に応じた InvalidState を返す。
                        let outcome = match c.complete(generation, input) {
                            Ok(()) => outcome,
                            Err(state) => Err(VmError::InvalidState { op, state }),
                        };
                        // 呼び出し元の放棄と直列化するため、Core のロック内で結果を送る（block しない）。
                        let _ = tx.try_send(outcome);
                    }
                };
                match op {
                    VmOp::Start => vm.start(handler),
                    VmOp::Stop => vm.stop(handler),
                }
            });
            match rx.recv_timeout(self.op_timeout) {
                Ok(result) => result,
                Err(RecvTimeoutError::Timeout) => self.give_up(op, &ticket, &rx),
                Err(RecvTimeoutError::Disconnected) => Err(VmError::CallbackLost { op }),
            }
        }

        /// 待機期限切れの後始末（REPAIR-5）。操作を取り消すか放棄して後続の start / stop を受け付けられる
        /// ようにし、放棄した場合は VM キュー上で実状態へ追従させる。期限直後に結果が確定していればそれを返す。
        fn give_up(
            &self,
            op: VmOp,
            ticket: &Mutex<OpTicket>,
            rx: &Receiver<Result<(), VmError>>,
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
            Err(VmError::Timeout {
                op,
                after: self.op_timeout,
            })
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
}
