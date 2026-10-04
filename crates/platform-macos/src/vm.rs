//! `VZVirtualMachine` の start / stop ライフサイクルと状態イベント（MAC-1・TASK-64.4・MS-5）。
//!
//! 構成:
//! - OS 非依存層: `VmState`・`VmEvent`・`VmError` と、状態遷移を決める純粋な `Lifecycle`・イベント配送
//!   `EventSink`。FFI 層は遷移を `Lifecycle` に委ねるだけにし、遷移ロジックを Linux 上の `make test` で
//!   検証できるようにする（REPAIR-12）。
//! - macOS 限定層: `Vm`。`config::VzVmConfiguration` から VM を生成し、`start` / `stop` を同期 API
//!   （タイムアウト付き。REPAIR-5）として公開する。
//!
//! run loop 統合: `initWithConfiguration:`（キュー指定なし）はメインキューを使うため呼び出し側が run loop を
//! 回し続ける必要があるが、本モジュールは VM ごとに専用のシリアル `DispatchQueue` を作って生成する。
//! completion handler・delegate は GCD のワーカースレッドで届くので、呼び出し元（TASK-115 の plugin
//! プロセス）はメイン run loop を回さずに済む。VM に関わる unsafe はすべて `sys` に閉じ込めている。
//!
//! 注意: `start` / `stop` / `state` を VM キュー上（イベント処理の中など）から呼ぶとデッドロックする。
//! 最後の防壁としてタイムアウトが `VmError::Timeout` を返す。
//!
//! 未実装（REPAIR-3）: 待機タイムアウトの既定値の確定、タイムアウト・起動失敗時のクリーンアップ、
//! 実行中 VM の `Drop` 時停止、`VmError` の `error.rs` への移動と `ConfigError` との統合は TASK-64.5。
//! 協調停止（`requestStop`）・pause / resume / save / restore は範囲外。

// macOS 限定の `Vm` だけが使う内部型は、他 OS ではテストからのみ参照されるため dead_code を許容する。
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

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
pub(crate) enum LifecycleInput {
    StartRequested,
    StartCompleted(Result<(), ErrInfo>),
    StopRequested,
    StopCompleted(Result<(), ErrInfo>),
    GuestStopped,
    StoppedWithError(ErrInfo),
}

/// 状態遷移を決める純粋な状態機械。FFI を持たない。
#[derive(Debug)]
pub(crate) struct Lifecycle {
    state: VmState,
}

impl Lifecycle {
    pub(crate) fn new() -> Lifecycle {
        Lifecycle {
            state: VmState::Stopped,
        }
    }

    /// 入力を適用し、発行すべきイベント列を返す。
    pub(crate) fn step(&mut self, input: LifecycleInput) -> Vec<VmEvent> {
        let mut events = Vec::new();
        let mut extra = None;
        let next = match input {
            LifecycleInput::StartRequested => VmState::Starting,
            LifecycleInput::StartCompleted(Ok(())) => VmState::Running,
            LifecycleInput::StartCompleted(Err(_)) => VmState::Error,
            LifecycleInput::StopRequested => VmState::Stopping,
            LifecycleInput::StopCompleted(Ok(())) => VmState::Stopped,
            // 停止に失敗した VM は動作を続けているとみなす。
            LifecycleInput::StopCompleted(Err(_)) => VmState::Running,
            LifecycleInput::GuestStopped => {
                extra = Some(VmEvent::GuestStopped);
                VmState::Stopped
            }
            LifecycleInput::StoppedWithError((domain, code)) => {
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
}

/// イベント送信側。VM キュー上のコールバックから呼ばれるため、決して block しない（`try_send` のみ）。
#[derive(Debug)]
pub(crate) struct EventSink {
    tx: SyncSender<VmEvent>,
    dropped: u64,
}

/// 容量付きのイベントチャネルを作る。
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

/// 状態機械とイベント配送をまとめたもの。コールバックと操作側で `Arc<Mutex<_>>` 共有する。
#[derive(Debug)]
pub(crate) struct Core {
    lifecycle: Lifecycle,
    sink: EventSink,
}

impl Core {
    pub(crate) fn new(sink: EventSink) -> Core {
        Core {
            lifecycle: Lifecycle::new(),
            sink,
        }
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
        Core, EVENT_CHANNEL_CAPACITY, ErrInfo, LifecycleInput, PROVISIONAL_OP_TIMEOUT, VmError,
        VmEvent, VmOp, VmState, event_channel,
    };
    use crate::config::VzVmConfiguration;
    use crate::sys::{self, DelegateEvent, HostInitError};

    fn lock(core: &Mutex<Core>) -> MutexGuard<'_, Core> {
        // 毒化しても状態機械は壊れないため、中身をそのまま使う（コールバック内で panic させない）。
        core.lock().unwrap_or_else(|e| e.into_inner())
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

        /// フレームワークが報告する現在の状態。取得できなければ `Unknown(-1)`。
        pub fn state(&self) -> VmState {
            self.host
                .run_sync(|vm| VmState::from_raw(vm.state_raw()))
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
            self.host.run_async(move |vm| {
                let allowed = match op {
                    VmOp::Start => vm.can_start(),
                    VmOp::Stop => vm.can_stop(),
                };
                if !allowed {
                    let state = VmState::from_raw(vm.state_raw());
                    let _ = tx.try_send(Err(VmError::InvalidState { op, state }));
                    return;
                }
                lock(&core).apply(match op {
                    VmOp::Start => LifecycleInput::StartRequested,
                    VmOp::Stop => LifecycleInput::StopRequested,
                });
                let handler = move |res: Result<(), ErrInfo>| {
                    let outcome = res.clone().map_err(|(domain, code)| match op {
                        VmOp::Start => VmError::StartFailed { domain, code },
                        VmOp::Stop => VmError::StopFailed { domain, code },
                    });
                    lock(&core).apply(match op {
                        VmOp::Start => LifecycleInput::StartCompleted(res),
                        VmOp::Stop => LifecycleInput::StopCompleted(res),
                    });
                    let _ = tx.try_send(outcome);
                };
                match op {
                    VmOp::Start => vm.start(handler),
                    VmOp::Stop => vm.stop(handler),
                }
            });
            match rx.recv_timeout(self.op_timeout) {
                Ok(result) => result,
                Err(RecvTimeoutError::Timeout) => Err(VmError::Timeout {
                    op,
                    after: self.op_timeout,
                }),
                Err(RecvTimeoutError::Disconnected) => Err(VmError::CallbackLost { op }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            lc.step(LifecycleInput::StartCompleted(Ok(()))),
            vec![changed(VmState::Starting, VmState::Running)]
        );
        assert_eq!(
            lc.step(LifecycleInput::StopRequested),
            vec![changed(VmState::Running, VmState::Stopping)]
        );
        assert_eq!(
            lc.step(LifecycleInput::StopCompleted(Ok(()))),
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
            lc.step(LifecycleInput::StartCompleted(Err(err.clone()))),
            vec![changed(VmState::Starting, VmState::Error)]
        );
        let mut lc = Lifecycle::new();
        lc.step(LifecycleInput::StartRequested);
        lc.step(LifecycleInput::StartCompleted(Ok(())));
        lc.step(LifecycleInput::StopRequested);
        assert_eq!(
            lc.step(LifecycleInput::StopCompleted(Err(err))),
            vec![changed(VmState::Stopping, VmState::Running)]
        );
    }

    /// MAC-1・TASK-64.4: ゲスト停止・エラー停止の通知。
    #[test]
    fn lifecycle_delegate_notifications() {
        let mut lc = Lifecycle::new();
        lc.step(LifecycleInput::StartRequested);
        lc.step(LifecycleInput::StartCompleted(Ok(())));
        assert_eq!(
            lc.step(LifecycleInput::GuestStopped),
            vec![
                changed(VmState::Running, VmState::Stopped),
                VmEvent::GuestStopped
            ]
        );
        let mut lc = Lifecycle::new();
        lc.step(LifecycleInput::StartRequested);
        lc.step(LifecycleInput::StartCompleted(Ok(())));
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
