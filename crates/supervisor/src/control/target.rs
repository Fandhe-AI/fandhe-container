//! 制御チャネルのサーバと、起動ハンドルを持つ監視スレッドの橋渡し（SUP-1・SEC-1・CORE-1・REPAIR-5・#2058）。
//!
//! `LaunchedProcess` は `Send` だけで `Sync` ではなく、別スレッドから同じハンドルを触れない（core のトレイトを
//! `Sync` に広げるとすべてのフェイクへ波及し、core と supervisor の境界も変わる）。そこで次の形にする。
//!
//! - [`ControlledProcess`]: 起動ハンドルを包む `LaunchedProcess`。監視ループが `wait` を呼ぶたびに、先に
//!   受け箱（有界チャネル）の要求を処理してから内側の `wait` を呼ぶ。シグナルの送信は常にハンドルを持つ
//!   スレッドの上で行われ、回収状態のロックの下で送られる（pid 再利用で無関係なプロセスへ送らない）。
//! - [`SignalSlot`]: サーバが見る共有の状態（`Empty` / `Active` / `Exited`）。ハンドルなし・終了済み・pid 不一致を
//!   監視スレッドを待たずに即答するために使う。世代番号で、再起動後の新しいハンドルを古いハンドルの `Drop` から守る。
//! - [`ControlledRelauncher`]: restart の再 launch で得た新しいハンドルを、新しい世代の [`ControlledProcess`] として
//!   登録する（古い世代の受け箱の要求は新しいプロセスへ届かない）。
//!
//! 応答の遅れは最大で監視ループの poll 間隔（`start_entry::POLL_INTERVAL`、100ms）。`run.rs`・`restart.rs` の
//! 公開関数のシグネチャは変えない（REPAIR-1）。全 OS でコンパイル・テストする（std のみ）。

use std::num::NonZeroU32;
use std::sync::mpsc::{
    Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError, sync_channel,
};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fandhe_container_core::oci_runtime::{ContainerOutput, LaunchedProcess, ProcessExit};
use fandhe_container_core::traits::{ErrorCode, Signal, TraitError};

use super::protocol::ControlReason;
use crate::restart::{LateOrphan, Relauncher};

/// 受け箱の容量（超えたら `Busy`。資源の使用量を固定に抑える）。
pub const INBOX_CAPACITY: usize = 4;

/// 監視スレッドへ渡す 1 件のシグナル送信要求。
struct PendingSignal {
    pid: NonZeroU32,
    signal: Signal,
    /// この時刻以降は送らない（`Timeout` を返す）。
    deadline: Instant,
    /// 結果の返信先（容量 1。受け手が居なくても送信は詰まらない）。
    reply: SyncSender<ControlReason>,
}

enum SlotState {
    Empty,
    Active {
        generation: u64,
        pid: NonZeroU32,
        inbox: SyncSender<PendingSignal>,
    },
    Exited {
        generation: u64,
        pid: NonZeroU32,
    },
}

struct SlotInner {
    next_generation: u64,
    state: SlotState,
}

/// サーバと監視スレッドが共有する、起動ハンドルの有無・世代の状態。
#[derive(Clone)]
pub struct SignalSlot(Arc<Mutex<SlotInner>>);

impl Default for SignalSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalSlot {
    /// ハンドルなし（`Empty`）の状態で作る。
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(SlotInner {
            next_generation: 1,
            state: SlotState::Empty,
        })))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SlotInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 新しいハンドルを登録し、世代と受け箱を返す（直前の状態は上書きする）。
    fn register(&self, pid: NonZeroU32) -> (u64, Receiver<PendingSignal>) {
        let (tx, rx) = sync_channel(INBOX_CAPACITY);
        let mut inner = self.lock();
        let generation = inner.next_generation;
        inner.next_generation = inner.next_generation.wrapping_add(1);
        inner.state = SlotState::Active {
            generation,
            pid,
            inbox: tx,
        };
        (generation, rx)
    }

    /// `generation` の `Active` を `Exited` にする（別世代なら何もしない）。
    fn mark_exited(&self, generation: u64) {
        let mut inner = self.lock();
        if let SlotState::Active {
            generation: g, pid, ..
        } = &inner.state
            && *g == generation
        {
            let pid = *pid;
            inner.state = SlotState::Exited { generation, pid };
        }
    }

    /// `generation` の状態を `Empty` に戻す（別世代なら何もしない）。
    fn clear(&self, generation: u64) {
        let mut inner = self.lock();
        let matches = match &inner.state {
            SlotState::Active { generation: g, .. } | SlotState::Exited { generation: g, .. } => {
                *g == generation
            }
            SlotState::Empty => false,
        };
        if matches {
            inner.state = SlotState::Empty;
        }
    }

    /// サーバから要求を預ける。受け付けたら返信用の受け口を返し、その場で断れるものは理由コードを返す。
    pub fn submit(
        &self,
        pid: NonZeroU32,
        signal: Signal,
        deadline: Instant,
    ) -> Result<Receiver<ControlReason>, ControlReason> {
        let inner = self.lock();
        match &inner.state {
            SlotState::Empty => Err(ControlReason::NoHandle),
            SlotState::Exited { pid: held, .. } => {
                if *held != pid {
                    Err(ControlReason::PidMismatch)
                } else {
                    Err(ControlReason::ContainerExited)
                }
            }
            SlotState::Active {
                pid: held, inbox, ..
            } => {
                if *held != pid {
                    return Err(ControlReason::PidMismatch);
                }
                let (reply, rx) = sync_channel(1);
                match inbox.try_send(PendingSignal {
                    pid,
                    signal,
                    deadline,
                    reply,
                }) {
                    Ok(()) => Ok(rx),
                    Err(TrySendError::Full(_)) => Err(ControlReason::Busy),
                    Err(TrySendError::Disconnected(_)) => Err(ControlReason::NoHandle),
                }
            }
        }
    }
}

/// 起動ハンドルを包み、制御チャネルからの送信要求を監視ループの `wait` で処理する `LaunchedProcess`。
///
/// 呼び出し元は `supervise_with_restart`（監視ループ）。`pid`・`terminate`・`signal`・`take_output`・
/// `launch_pidfd` は内側へ転送する（`take_output` はログ捕捉〔#1471〕、`launch_pidfd` は exec の pidfd 固定
/// 〔#1461〕に必須）。
pub struct ControlledProcess {
    inner: Box<dyn LaunchedProcess>,
    slot: SignalSlot,
    generation: u64,
    inbox: Receiver<PendingSignal>,
}

impl ControlledProcess {
    /// `inner` を包み、`slot` へ新しい世代として登録する。
    pub fn new(inner: Box<dyn LaunchedProcess>, slot: SignalSlot) -> Self {
        let (generation, inbox) = slot.register(inner.pid());
        Self {
            inner,
            slot,
            generation,
            inbox,
        }
    }

    /// 受け箱が空になるまで処理する。`fixed` があれば送信せずその理由で返信する。
    fn drain(&self, fixed: Option<ControlReason>) {
        loop {
            match self.inbox.try_recv() {
                Ok(req) => {
                    let reason = match fixed {
                        Some(r) => r,
                        None => self.handle(&req),
                    };
                    // 受け手（サーバ）が期限で諦めていても詰まらない（容量 1・送信は 1 回）。
                    let _ = req.reply.try_send(reason);
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => return,
            }
        }
    }

    fn handle(&self, req: &PendingSignal) -> ControlReason {
        // 期限後には送らない（REPAIR-5）。core の `signal` も送信直前に再確認する。
        if Instant::now() >= req.deadline {
            return ControlReason::Timeout;
        }
        if req.pid != self.inner.pid() {
            return ControlReason::PidMismatch;
        }
        match self.inner.signal(req.signal, req.deadline) {
            Ok(()) => ControlReason::Ok,
            Err(e) => match e.code() {
                ErrorCode::FailedPrecondition => ControlReason::ContainerExited,
                ErrorCode::Timeout => ControlReason::Timeout,
                _ => ControlReason::SignalFailed,
            },
        }
    }
}

impl LaunchedProcess for ControlledProcess {
    fn pid(&self) -> NonZeroU32 {
        self.inner.pid()
    }

    /// 内側の launch 時の分離の記録へ転送する(転送しないと restart の記録の置き換えが落ち、restart 後の exec が
    /// `/` の照合で拒否される。SUP-6・#2007)。
    fn launch_isolation(
        &self,
    ) -> Option<&fandhe_container_core::launch_isolation::LaunchIsolationRecord> {
        self.inner.launch_isolation()
    }

    fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
        self.drain(None);
        let result = self.inner.wait(timeout);
        if matches!(result, Ok(Some(_))) {
            self.slot.mark_exited(self.generation);
            self.drain(Some(ControlReason::ContainerExited));
        }
        result
    }

    fn terminate(&self, timeout: Duration) -> Result<(), TraitError> {
        let result = self.inner.terminate(timeout);
        if result.is_ok() {
            self.slot.mark_exited(self.generation);
            self.drain(Some(ControlReason::ContainerExited));
        }
        result
    }

    fn signal(&self, signal: Signal, deadline: Instant) -> Result<(), TraitError> {
        self.inner.signal(signal, deadline)
    }

    #[cfg(target_os = "linux")]
    fn launch_pidfd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.inner.launch_pidfd()
    }

    fn take_output(&self) -> Option<ContainerOutput> {
        self.inner.take_output()
    }

    /// seccomp の listener を内側へ転送する(転送しないと、包み直した後は取り出せず #2025 の応答ループが
    /// listener を得られない。`take_output` と同じ注意。SEC-4・#2024)。
    #[cfg(target_os = "linux")]
    fn take_seccomp_listener(&self) -> Option<fandhe_container_core::exec::SeccompListener> {
        self.inner.take_seccomp_listener()
    }
}

impl Drop for ControlledProcess {
    fn drop(&mut self) {
        // 自分の世代のときだけ空に戻す（再起動後の新しい世代を消さない）。
        self.slot.clear(self.generation);
        self.drain(Some(ControlReason::NoHandle));
    }
}

/// restart の再 launch で得た新しいハンドルを、新しい世代の [`ControlledProcess`] として登録する。
pub struct ControlledRelauncher {
    inner: Arc<dyn Relauncher>,
    slot: SignalSlot,
}

impl ControlledRelauncher {
    /// `inner` の再 launch の結果を `slot` に登録して返す relauncher を作る。
    pub fn new(inner: Arc<dyn Relauncher>, slot: SignalSlot) -> Self {
        Self { inner, slot }
    }
}

impl Relauncher for ControlledRelauncher {
    fn relaunch(&self, timeout: Duration) -> Result<Box<dyn LaunchedProcess>, TraitError> {
        let process = self.inner.relaunch(timeout)?;
        Ok(Box::new(ControlledProcess::new(process, self.slot.clone())))
    }

    fn take_stranded(&self) -> Vec<LateOrphan> {
        self.inner.take_stranded()
    }
}

/// 返信を期限つきで待つ（サーバ側の補助。送信期限 + 猶予まで）。
pub fn wait_reply(
    rx: &Receiver<ControlReason>,
    deadline: Instant,
    grace: Duration,
) -> ControlReason {
    let limit = deadline.checked_add(grace).unwrap_or(deadline);
    let remaining = limit.saturating_duration_since(Instant::now());
    match rx.recv_timeout(remaining) {
        Ok(reason) => reason,
        Err(RecvTimeoutError::Timeout) => ControlReason::Timeout,
        Err(RecvTimeoutError::Disconnected) => ControlReason::Internal,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// 送られたシグナル番号を記録する模擬プロセス。
    struct Fake {
        pid: u32,
        signals: Arc<Mutex<Vec<u8>>>,
        exited: Arc<AtomicBool>,
        output_taken: Arc<AtomicBool>,
        isolation: Option<fandhe_container_core::launch_isolation::LaunchIsolationRecord>,
    }

    impl Fake {
        fn new(pid: u32) -> (Self, Arc<Mutex<Vec<u8>>>, Arc<AtomicBool>) {
            let signals = Arc::new(Mutex::new(Vec::new()));
            let exited = Arc::new(AtomicBool::new(false));
            (
                Self {
                    pid,
                    signals: Arc::clone(&signals),
                    exited: Arc::clone(&exited),
                    output_taken: Arc::new(AtomicBool::new(false)),
                    isolation: None,
                },
                signals,
                exited,
            )
        }
    }

    impl LaunchedProcess for Fake {
        fn pid(&self) -> NonZeroU32 {
            NonZeroU32::new(self.pid).unwrap()
        }
        fn wait(&self, timeout: Duration) -> Result<Option<ProcessExit>, TraitError> {
            if self.exited.load(Ordering::SeqCst) {
                return Ok(Some(ProcessExit::Exited(0)));
            }
            std::thread::sleep(timeout.min(Duration::from_millis(5)));
            Ok(None)
        }
        fn terminate(&self, _timeout: Duration) -> Result<(), TraitError> {
            self.exited.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn signal(&self, signal: Signal, _deadline: Instant) -> Result<(), TraitError> {
            if self.exited.load(Ordering::SeqCst) {
                return Err(TraitError::new(ErrorCode::FailedPrecondition, "reaped"));
            }
            self.signals.lock().unwrap().push(signal.as_u8());
            Ok(())
        }
        fn launch_isolation(
            &self,
        ) -> Option<&fandhe_container_core::launch_isolation::LaunchIsolationRecord> {
            self.isolation.as_ref()
        }
        fn take_output(&self) -> Option<ContainerOutput> {
            self.output_taken.store(true, Ordering::SeqCst);
            Some(ContainerOutput::default())
        }
        #[cfg(target_os = "linux")]
        fn take_seccomp_listener(&self) -> Option<fandhe_container_core::exec::SeccompListener> {
            self.output_taken.store(true, Ordering::SeqCst);
            None
        }
    }

    fn pid(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    /// 要求を預けて、監視役のつもりで 1 回 `wait` を回し、結果を受け取る。
    fn roundtrip(
        slot: &SignalSlot,
        process: &ControlledProcess,
        p: u32,
        sig: u8,
        deadline: Instant,
    ) -> ControlReason {
        let rx = match slot.submit(pid(p), Signal::new(sig).unwrap(), deadline) {
            Ok(rx) => rx,
            Err(r) => return r,
        };
        let _ = process.wait(Duration::from_millis(1));
        rx.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    /// SUP-6(#2007): 包み直しは内側の分離の記録をそのまま返す(記録なしの内側では `None`)。
    #[test]
    fn sup6_controlled_process_forwards_launch_isolation() {
        use fandhe_container_core::launch_isolation::{
            LaunchIsolationRecord, RecordedLandlock, RecordedRule, RecordedTarget, RootIdentity,
        };
        let landlock =
            RecordedLandlock::new(0x3f, vec![RecordedRule::new(RecordedTarget::Root, 0x0f)])
                .unwrap();
        let record = LaunchIsolationRecord::from_parts(RootIdentity::new(5, 6), landlock);
        let (mut fake, _, _) = Fake::new(100);
        fake.isolation = Some(record.clone());
        let cp = ControlledProcess::new(Box::new(fake), SignalSlot::new());
        assert!(cp.launch_isolation() == Some(&record));
        let (plain, _, _) = Fake::new(101);
        let cp = ControlledProcess::new(Box::new(plain), SignalSlot::new());
        assert!(cp.launch_isolation().is_none());
    }

    /// SUP-1・SEC-1: 一致する pid の要求だけがシグナル番号つきで内側へ届く。
    #[test]
    fn sup1_sec1_matching_pid_delivers_signal_15() {
        let slot = SignalSlot::new();
        let (fake, signals, _) = Fake::new(100);
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        assert_eq!(roundtrip(&slot, &cp, 100, 15, far()), ControlReason::Ok);
        assert_eq!(*signals.lock().unwrap(), vec![15]);
    }

    /// SUP-1・SEC-1: pid 不一致は送らずに `PidMismatch`。
    #[test]
    fn sup1_sec1_pid_mismatch_does_not_signal() {
        let slot = SignalSlot::new();
        let (fake, signals, _) = Fake::new(100);
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        assert_eq!(
            roundtrip(&slot, &cp, 101, 15, far()),
            ControlReason::PidMismatch
        );
        assert!(signals.lock().unwrap().is_empty());
    }

    /// REPAIR-5・SEC-1: 期限切れの要求は後から処理しても送らない。
    #[test]
    fn repair5_sec1_expired_request_is_not_delivered() {
        let slot = SignalSlot::new();
        let (fake, signals, _) = Fake::new(100);
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        let deadline = Instant::now() + Duration::from_millis(20);
        let rx = slot.submit(pid(100), Signal::SIGTERM, deadline).unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let _ = cp.wait(Duration::from_millis(1));
        assert_eq!(rx.recv().unwrap(), ControlReason::Timeout);
        assert!(signals.lock().unwrap().is_empty());
    }

    /// SUP-1: 終了後は `ContainerExited`、`Drop` の後は `NoHandle`、ハンドル登録前も `NoHandle`。
    #[test]
    fn sup1_exited_then_dropped_then_empty() {
        let slot = SignalSlot::new();
        assert_eq!(
            slot.submit(pid(100), Signal::SIGTERM, far()).unwrap_err(),
            ControlReason::NoHandle
        );
        let (fake, signals, exited) = Fake::new(100);
        let cp = ControlledProcess::new(Box::new(fake), slot.clone());
        // 受け箱に要求が残ったまま終了を検知したら、送らずに ContainerExited を返す。
        let rx = slot.submit(pid(100), Signal::SIGTERM, far()).unwrap();
        exited.store(true, Ordering::SeqCst);
        assert!(cp.wait(Duration::from_millis(1)).unwrap().is_some());
        // drain(None) が先に走るが、模擬は終了済みなら FailedPrecondition を返すので同じ結果になる。
        assert_eq!(rx.recv().unwrap(), ControlReason::ContainerExited);
        assert!(signals.lock().unwrap().is_empty());
        assert_eq!(
            slot.submit(pid(100), Signal::SIGTERM, far()).unwrap_err(),
            ControlReason::ContainerExited
        );
        drop(cp);
        assert_eq!(
            slot.submit(pid(100), Signal::SIGTERM, far()).unwrap_err(),
            ControlReason::NoHandle
        );
    }

    /// SEC-1: 古い世代の `Drop` は、再起動後の新しい世代を空に戻さない。
    #[test]
    fn sec1_old_generation_drop_keeps_new_generation() {
        let slot = SignalSlot::new();
        let (old, _, _) = Fake::new(100);
        let old_cp = ControlledProcess::new(Box::new(old), slot.clone());
        let (new, signals, _) = Fake::new(200);
        let new_cp = ControlledProcess::new(Box::new(new), slot.clone());
        drop(old_cp);
        assert_eq!(roundtrip(&slot, &new_cp, 200, 2, far()), ControlReason::Ok);
        assert_eq!(*signals.lock().unwrap(), vec![2]);
        // 古い pid へは届かない。
        assert_eq!(
            slot.submit(pid(100), Signal::SIGTERM, far()).unwrap_err(),
            ControlReason::PidMismatch
        );
    }

    /// 受け箱が満杯なら `Busy`。
    #[test]
    fn sup1_full_inbox_is_busy() {
        let slot = SignalSlot::new();
        let (fake, _, _) = Fake::new(100);
        let _cp = ControlledProcess::new(Box::new(fake), slot.clone());
        let mut held = Vec::new();
        for _ in 0..INBOX_CAPACITY {
            held.push(slot.submit(pid(100), Signal::SIGTERM, far()).unwrap());
        }
        assert_eq!(
            slot.submit(pid(100), Signal::SIGTERM, far()).unwrap_err(),
            ControlReason::Busy
        );
    }

    /// SEC-4・#2024: `take_seccomp_listener` が内側へ転送される(転送を忘れると包み直した後に listener を取れない)。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_2024_take_seccomp_listener_is_forwarded() {
        let slot = SignalSlot::new();
        let (fake, _, _) = Fake::new(100);
        let called = Arc::clone(&fake.output_taken);
        let cp = ControlledProcess::new(Box::new(fake), slot);
        assert!(cp.take_seccomp_listener().is_none());
        assert!(
            called.load(Ordering::SeqCst),
            "the inner process was not asked"
        );
    }

    /// `take_output` が内側へ転送される（ログ捕捉に必須。#1471）。
    #[test]
    fn sup1_take_output_is_forwarded() {
        let slot = SignalSlot::new();
        let (fake, _, _) = Fake::new(100);
        let taken = Arc::clone(&fake.output_taken);
        let cp = ControlledProcess::new(Box::new(fake), slot);
        assert!(cp.take_output().is_some());
        assert!(taken.load(Ordering::SeqCst));
    }
}
