//! HVF の AP（vCPU 1..N）を PSCI CPU_ON で起動し、CPU_OFF で parked へ戻す OS 非依存コア（#3891・MVM-5・MVM-1・REPAIR-3・REPAIR-5）。`unsafe` なし。
//!
//! 役割: `crate::psci` の電源状態機械（#3883）と、`hvf::vcpu` の parked の AP スレッド（#3884）を結ぶ。`hv_*` を呼ばないため、
//! 偽の実行体（[`VcpuExec`]）で Linux の PR CI でも単体試験が走る（macOS の PR CI は型検査のみ）。
//!
//! # 構成
//! - [`ApMailbox`]: AP 1 台ごとの起動要求の置き場（容量 1）。呼び出し元 vCPU のスレッドが [`ApMailbox::post`] し、AP の owning thread が
//!   [`ApMailbox::wait`] で受ける。レジスタは owning thread でしか書かない（HVF の vCPU はスレッドに束縛される）。
//! - [`HvfPowerControl`]: `CpuPowerControl` の実装。BSP と全 AP のハンドラが `Arc` で共有する。`power_on` は entry を検査して
//!   メールボックスへ積むだけで戻る（長く待たない。`CpuPowerControl` の契約）。
//! - [`run_parked_ap`]: AP スレッドの実行サイクル（park → 起動要求 → レジスタ設定 → ON 確定 → 実行 → CPU_OFF なら park へ）。
//!
//! # 順序の契約（試験で照合する）
//! メールボックスへ積む → owning thread がレジスタを書く → `PsciCpus::confirm_on`（ON_PENDING→ON）→ 実行ループ。
//! ON を名乗るのは、レジスタを書き終えて実行に入る直前。
//!
//! # CPU_OFF の窓
//! CPU_OFF は `psci` が OFF を書いてから [`ExitAction::Park`] を返し、AP スレッドが実行ループを抜けて park に戻る。その間に別の vCPU が
//! CPU_ON すると、要求はメールボックスに残り、park に戻った時点で処理される（AP はその間ゲストの命令を実行しない。取りこぼさない）。
//!
//! # 未実装・逸脱（REPAIR-3）
//! - BSP の CPU_OFF は `power_off(0)` が DENIED を返す。DENIED は CPU_OFF が返しうる唯一の失敗値（DEN0022 §5.1.3）で、BSP を
//!   「VM が生きていることの錨」として保つ判断であり、仕様の強制ではない。
//! - ビッグエンディアンのゲストは対象外（`SCTLR_EL1.EE` を 0 にして起動する。`boot_arm64::sctlr_for_cpu_on`）。
//! - `hvf_wake::WfiWaker` は単一の待ち手のため、複数 vCPU が WFI すると通知を取り合う。即時性は保証されず、WFI の待ちの上限が
//!   安全網になるだけ。
//! - VM の終了（SYSTEM_OFF・SYSTEM_RESET・fail-closed の停止・異常終了。CPU_OFF の Park とは別）は、終わった vCPU のスレッドが
//!   [`VmShutdown::trigger`] を呼び、全 vCPU の停止フラグを立てて kick する（BSP の実行・AP の parked 待ちを即解除）。
//!   呼び出し側の `stop` を待たずに他の vCPU が止まる。`VcpuSet::is_finished` は従来どおり状態を調べるだけ。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use crate::boot_arm64::{ApBootRegs, ap_boot_registers, check_cpu_on_entry};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_loop::{ExitAction, HvExit, LoopExit, VcpuExec, VcpuExitObserver, run_loop_exit};
use crate::psci::{CpuPowerControl, PowerControlError, PsciCpus};
use crate::stop::StopReason;

/// parked の AP が停止フラグを見直す間隔（通知の取りこぼし対策。待ちの上限ではない）。
pub const AP_PARK_POLL: Duration = Duration::from_millis(100);

/// CPU_ON の起動要求（ゲスト由来の untrusted な値。entry は RAM 範囲と整列を検査済み、context_id は不透明な値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApBootRequest {
    /// 起動アドレス。
    pub entry: u64,
    /// CPU_ON の context_id（X0 へ書く）。
    pub context_id: u64,
}

/// [`ApMailbox::wait`] の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApWake {
    /// 起動要求を受け取った（メールボックスは空に戻る）。
    Start(ApBootRequest),
    /// 停止要求、またはメールボックスが閉じられた。
    Stopped,
}

#[derive(Debug)]
enum MailboxState {
    Empty,
    Pending(ApBootRequest),
    Closed,
}

/// AP 1 台ぶんの起動要求の置き場（容量 1。ゲストが CPU_ON を連打しても増えない）。poison は状態が 1 語のため `into_inner` で受ける。
#[derive(Debug)]
pub struct ApMailbox {
    state: Mutex<MailboxState>,
    cv: Condvar,
}

impl Default for ApMailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl ApMailbox {
    /// 空のメールボックスを作る。
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MailboxState::Empty),
            cv: Condvar::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MailboxState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 起動要求を積む。空でなければ（`psci` の CAS が二重の積みを防ぐので来ない）`Internal`、閉じていれば `FailedPrecondition`。
    pub fn post(&self, req: ApBootRequest) -> Result<(), PowerControlError> {
        let mut g = self.lock();
        match *g {
            MailboxState::Empty => {
                *g = MailboxState::Pending(req);
                drop(g);
                self.cv.notify_all();
                Ok(())
            }
            MailboxState::Pending(_) => Err(PowerControlError::Failed(MicrovmErrorCode::Internal)),
            MailboxState::Closed => Err(PowerControlError::Failed(
                MicrovmErrorCode::FailedPrecondition,
            )),
        }
    }

    /// 起動要求か停止要求まで待つ。壁時計の上限は持たない（ゲストが AP を起動しないのは正常な構成で、待ちを解くのは期限つきの
    /// 停止要求だけ。`poll` は取りこぼし対策の見直し間隔で上限ではない）。停止フラグを先に見る。
    pub fn wait(&self, stop: &AtomicBool, poll: Duration) -> ApWake {
        let mut g = self.lock();
        loop {
            if stop.load(Ordering::Acquire) {
                return ApWake::Stopped;
            }
            match *g {
                MailboxState::Pending(req) => {
                    *g = MailboxState::Empty;
                    return ApWake::Start(req);
                }
                MailboxState::Closed => return ApWake::Stopped,
                MailboxState::Empty => {}
            }
            g = self
                .cv
                .wait_timeout(g, poll)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// 待っている AP を起こす（停止の kick から呼ぶ。ロックを取ってから通知し、待ちに入る直前の取りこぼしを避ける）。
    pub fn notify(&self) {
        drop(self.lock());
        self.cv.notify_all();
    }

    /// 閉じる（AP スレッドが終わるとき）。以後の [`Self::post`] は失敗する。
    pub fn close(&self) {
        *self.lock() = MailboxState::Closed;
        self.cv.notify_all();
    }
}

/// 他の vCPU を起こす手段（canceller の kick・メールボックスの notify・WFI の waker をまとめた閉包）。
pub type PeerKick = Box<dyn Fn() + Send + Sync>;

struct ShutdownPeer {
    stop: Arc<AtomicBool>,
    kick: PeerKick,
}

/// VM 全体の終了通知（全 vCPU で共有。VM の終了と CPU_OFF の Park を区別する。MVM-5・MVM-1・REPAIR-5）。
///
/// vCPU スレッドは実行体の準備ができたら [`Self::register`] で自分の停止フラグと kick を登録し、停止理由が `Requested`
/// 以外で終わるとき（SYSTEM_OFF・SYSTEM_RESET・失敗・BSP の終了）に [`Self::on_vcpu_end`] 経由で [`Self::trigger`] を呼ぶ。
/// `trigger` は登録済みの全 vCPU の停止フラグを立てて kick し、以後の `register` は即座に停止状態で受ける
/// （登録が `trigger` と競合しても取りこぼさない）。冪等。poison は状態が単純なため `into_inner` で受ける。
#[derive(Default)]
pub struct VmShutdown {
    state: Mutex<ShutdownState>,
}

#[derive(Default)]
struct ShutdownState {
    triggered: bool,
    peers: Vec<ShutdownPeer>,
}

impl std::fmt::Debug for VmShutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmShutdown")
            .field("triggered", &self.is_triggered())
            .finish()
    }
}

impl VmShutdown {
    /// 未通知の状態で作る。
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ShutdownState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 既に VM の終了が通知されたか。
    pub fn is_triggered(&self) -> bool {
        self.lock().triggered
    }

    /// vCPU の停止フラグと kick を登録する。既に通知済みなら、登録せずその場で停止フラグを立てて kick する。
    pub fn register(&self, stop: Arc<AtomicBool>, kick: PeerKick) {
        let mut g = self.lock();
        if g.triggered {
            drop(g);
            stop.store(true, Ordering::Release);
            kick();
            return;
        }
        g.peers.push(ShutdownPeer { stop, kick });
    }

    /// VM の終了を通知する。登録済みの全 vCPU の停止フラグを立ててから kick する（フラグが先。kick で起きた側が必ず見える）。
    pub fn trigger(&self) {
        let peers = {
            let mut g = self.lock();
            g.triggered = true;
            std::mem::take(&mut g.peers)
        };
        for p in &peers {
            p.stop.store(true, Ordering::Release);
        }
        for p in &peers {
            (p.kick)();
        }
    }

    /// vCPU スレッドの終了時に呼ぶ。`Requested` 以外（ゲスト起因の終了・失敗）なら VM の終了を通知する。
    pub fn on_vcpu_end(&self, reason: StopReason) {
        if reason != StopReason::Requested {
            self.trigger();
        }
    }
}

/// `CpuPowerControl` の HVF 実装。BSP と全 AP のハンドラが共有する。
#[derive(Debug)]
pub struct HvfPowerControl {
    ram_base: u64,
    ram_size: u64,
    /// index 1..N のメールボックス（`[0]` は BSP で使わない）。AP の spawn 後に埋める。
    slots: Vec<OnceLock<Arc<ApMailbox>>>,
}

impl HvfPowerControl {
    /// `vcpus` 台構成（ゲスト RAM は `[ram_base, ram_base + ram_size)`）。メールボックスは [`Self::attach`] で後から結ぶ。
    pub fn new(vcpus: u32, ram_base: u64, ram_size: u64) -> Self {
        Self {
            ram_base,
            ram_size,
            slots: (0..vcpus).map(|_| OnceLock::new()).collect(),
        }
    }

    /// AP `index`（1 以上）のメールボックスを結ぶ。範囲外・二重の設定は `Internal`。
    pub fn attach(&self, index: u32, mailbox: Arc<ApMailbox>) -> Result<(), MicrovmError> {
        let slot = match index {
            0 => None,
            i => self.slots.get(i as usize),
        };
        slot.ok_or_else(|| MicrovmError::new(MicrovmErrorCode::Internal, "ap index out of range"))?
            .set(mailbox)
            .map_err(|_| MicrovmError::new(MicrovmErrorCode::Internal, "ap mailbox attached twice"))
    }
}

impl CpuPowerControl for HvfPowerControl {
    fn power_on(&self, index: u32, entry: u64, context_id: u64) -> Result<(), PowerControlError> {
        if check_cpu_on_entry(self.ram_base, self.ram_size, entry).is_err() {
            return Err(PowerControlError::InvalidAddress);
        }
        let slot = match index {
            0 => None,
            i => self.slots.get(i as usize).and_then(OnceLock::get),
        };
        let mailbox = slot.ok_or(PowerControlError::Failed(MicrovmErrorCode::Internal))?;
        mailbox.post(ApBootRequest { entry, context_id })
    }

    fn power_off(&self, index: u32) -> Result<(), PowerControlError> {
        if index == 0 {
            return Err(PowerControlError::Denied);
        }
        Ok(())
    }
}

/// AP の実行サイクル。park → 起動要求 → `boot` でレジスタを書く → ON を確定 → 実行 → CPU_OFF（`Park`）なら park に戻る、を繰り返す。
/// 停止要求・ゲスト起因の終了・失敗で終わり、終了理由を返す（戻る前にメールボックスを閉じる）。
///
/// `boot` は owning thread で呼ばれ、失敗は `Failed(code)` で終える（推測で走らせない）。`confirm_on` は `boot` の成功後、実行ループに入る直前。
#[allow(clippy::too_many_arguments)]
pub fn run_parked_ap<E, B, D>(
    mailbox: &ApMailbox,
    stop: &AtomicBool,
    cpus: &PsciCpus,
    index: u32,
    exec: &mut E,
    slice: Duration,
    observer: Option<&dyn VcpuExitObserver>,
    mut boot: B,
    mut dispatch: D,
) -> StopReason
where
    E: VcpuExec,
    B: FnMut(&mut E, &ApBootRegs) -> Result<(), MicrovmError>,
    D: FnMut(&mut E, &HvExit) -> Result<ExitAction, MicrovmError>,
{
    let reason = loop {
        let req = match mailbox.wait(stop, AP_PARK_POLL) {
            ApWake::Stopped => break StopReason::Requested,
            ApWake::Start(req) => req,
        };
        let prepared = ap_boot_registers(index, req.entry, req.context_id)
            .and_then(|regs| boot(exec, &regs))
            .and_then(|()| cpus.confirm_on(index));
        if let Err(e) = prepared {
            break StopReason::Failed(e.code());
        }
        match run_loop_exit(exec, stop, slice, observer, &mut dispatch) {
            LoopExit::Stopped(r) => break r,
            LoopExit::Parked => {}
        }
    };
    mailbox.close();
    reason
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hvf_abi::{HvRunStats, HvVcpuExit, HvVcpuExitException};
    use crate::psci::{
        self, CpuPowerState, PSCI_FN_AFFINITY_INFO_64, PSCI_FN_CPU_OFF, PSCI_FN_CPU_ON_64,
        PsciAction, PsciArgs,
    };

    const RAM_BASE: u64 = 0x4000_0000;
    const RAM_SIZE: u64 = 0x100_0000;
    const ENTRY: u64 = 0x4010_0000;
    const CTX: u64 = 0x0123_4567_89ab_cdef;
    const LONG: Duration = Duration::from_secs(5);
    const HVC0: u64 = 0x5A00_0000;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Boot { pc: u64, x0: u64, mpidr: u64 },
        Run { state: Option<CpuPowerState> },
    }

    /// 台本の exit を返す偽の実行体。`exits` が尽きたら停止フラグを立てて `Canceled` を返す。
    struct FakeExec {
        log: Arc<Mutex<Vec<Event>>>,
        cpus: Arc<PsciCpus>,
        index: u32,
        stop: Arc<AtomicBool>,
        exits: Vec<HvVcpuExit>,
    }

    impl VcpuExec for FakeExec {
        fn run(&mut self, _slice: Duration) -> Result<HvVcpuExit, MicrovmError> {
            self.log.lock().unwrap().push(Event::Run {
                state: self.cpus.state(self.index),
            });
            if self.exits.is_empty() {
                self.stop.store(true, Ordering::Release);
                return Ok(HvVcpuExit::Canceled);
            }
            Ok(self.exits.remove(0))
        }
        fn stats(&self) -> HvRunStats {
            HvRunStats::default()
        }
    }

    fn hvc_exit() -> HvVcpuExit {
        HvVcpuExit::Exception(HvVcpuExitException {
            syndrome: HVC0,
            virtual_address: 0,
            physical_address: 0,
        })
    }

    fn args(x0: u32, x1: u64, x2: u64, x3: u64) -> PsciArgs {
        PsciArgs {
            imm16: 0,
            x0: u64::from(x0),
            x1,
            x2,
            x3,
        }
    }

    fn code(a: PsciAction) -> u64 {
        match a {
            PsciAction::Return(r) => r.to_x0(),
            other => panic!("unexpected action {other:?}"),
        }
    }

    struct Rig {
        cpus: Arc<PsciCpus>,
        power: Arc<HvfPowerControl>,
        mailbox: Arc<ApMailbox>,
        stop: Arc<AtomicBool>,
        log: Arc<Mutex<Vec<Event>>>,
    }

    fn rig() -> Rig {
        let cpus = Arc::new(PsciCpus::new(2).unwrap());
        let power = Arc::new(HvfPowerControl::new(2, RAM_BASE, RAM_SIZE));
        let mailbox = Arc::new(ApMailbox::new());
        power.attach(1, Arc::clone(&mailbox)).unwrap();
        Rig {
            cpus,
            power,
            mailbox,
            stop: Arc::new(AtomicBool::new(false)),
            log: Arc::default(),
        }
    }

    /// AP スレッドを起こす。`exits` を台本にし、CPU_OFF の HVC は本物の `psci::handle_call` を通す。
    fn spawn_ap(r: &Rig, exits: Vec<HvVcpuExit>) -> std::thread::JoinHandle<StopReason> {
        let (cpus, power, mailbox, stop, log) = (
            Arc::clone(&r.cpus),
            Arc::clone(&r.power),
            Arc::clone(&r.mailbox),
            Arc::clone(&r.stop),
            Arc::clone(&r.log),
        );
        std::thread::spawn(move || {
            let mut exec = FakeExec {
                log: Arc::clone(&log),
                cpus: Arc::clone(&cpus),
                index: 1,
                stop: Arc::clone(&stop),
                exits,
            };
            let blog = Arc::clone(&log);
            let bcpus = Arc::clone(&cpus);
            let dcpus = Arc::clone(&cpus);
            run_parked_ap(
                &mailbox,
                &stop,
                &cpus,
                1,
                &mut exec,
                Duration::from_millis(1),
                None,
                move |_, regs| {
                    // boot の時点ではまだ ON_PENDING（ON の確定は実行ループに入る直前）。
                    assert_eq!(bcpus.state(1), Some(CpuPowerState::OnPending));
                    blog.lock().unwrap().push(Event::Boot {
                        pc: regs.pc,
                        x0: regs.x0,
                        mpidr: regs.mpidr,
                    });
                    Ok(())
                },
                move |_, _| {
                    let a = psci::handle_call(
                        &dcpus,
                        power.as_ref(),
                        1,
                        args(PSCI_FN_CPU_OFF, 0, 0, 0),
                    )?;
                    match a {
                        PsciAction::CpuOff { index: 1 } => Ok(ExitAction::Park),
                        _ => Err(MicrovmError::new(MicrovmErrorCode::Internal, "unexpected")),
                    }
                },
            )
        })
    }

    fn wait_state(cpus: &PsciCpus, want: CpuPowerState) {
        let t = std::time::Instant::now();
        while cpus.state(1) != Some(want) {
            assert!(t.elapsed() < LONG, "state did not reach {want:?}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// MVM-5・MVM-1・#3891: 要求 → レジスタ → ON 確定 → 実行の順。`power_on` はレジスタを書かずに戻り、ctx は 64 bit のまま届く。
    #[test]
    fn mvm5_3891_boot_order_request_then_regs_then_confirm_then_run() {
        let r = rig();
        let h = spawn_ap(&r, Vec::new());
        // AP は park で待っている間、何も実行しない。
        std::thread::sleep(Duration::from_millis(30));
        assert!(r.log.lock().unwrap().is_empty());
        let a = psci::handle_call(
            &r.cpus,
            r.power.as_ref(),
            0,
            args(PSCI_FN_CPU_ON_64, 1, ENTRY, CTX),
        )
        .unwrap();
        assert_eq!(code(a), 0);
        assert_eq!(h.join().unwrap(), StopReason::Requested);
        assert_eq!(
            *r.log.lock().unwrap(),
            vec![
                Event::Boot {
                    pc: ENTRY,
                    x0: CTX,
                    mpidr: 1
                },
                Event::Run {
                    state: Some(CpuPowerState::On)
                },
            ]
        );
        // 終了したのでメールボックスは閉じている。
        let e = r
            .mailbox
            .post(ApBootRequest {
                entry: ENTRY,
                context_id: 0,
            })
            .unwrap_err();
        assert_eq!(
            e,
            PowerControlError::Failed(MicrovmErrorCode::FailedPrecondition)
        );
    }

    /// MVM-5・MVM-1・#3891: CPU_OFF で park に戻り（AFFINITY_INFO は OFF）、再度の CPU_ON が新しい entry・ctx で起動する。
    #[test]
    fn mvm5_3891_cpu_off_parks_and_cpu_on_rearms() {
        let r = rig();
        let h = spawn_ap(&r, vec![hvc_exit()]);
        let on = |entry: u64, ctx: u64| {
            code(
                psci::handle_call(
                    &r.cpus,
                    r.power.as_ref(),
                    0,
                    args(PSCI_FN_CPU_ON_64, 1, entry, ctx),
                )
                .unwrap(),
            )
        };
        assert_eq!(on(ENTRY, CTX), 0);
        wait_state(&r.cpus, CpuPowerState::Off);
        let info = psci::handle_call(
            &r.cpus,
            r.power.as_ref(),
            0,
            args(PSCI_FN_AFFINITY_INFO_64, 1, 0, 0),
        )
        .unwrap();
        assert_eq!(code(info), 1);
        assert_eq!(on(ENTRY + 0x100, 7), 0);
        assert_eq!(h.join().unwrap(), StopReason::Requested);
        let log = r.log.lock().unwrap().clone();
        let boots: Vec<_> = log
            .iter()
            .filter_map(|e| match e {
                Event::Boot { pc, x0, .. } => Some((*pc, *x0)),
                _ => None,
            })
            .collect();
        assert_eq!(boots, vec![(ENTRY, CTX), (ENTRY + 0x100, 7)]);
    }

    /// MVM-5・#3891: 起動の途中は ON_PENDING（-5）、確定後は ALREADY_ON（-4）。
    #[test]
    fn mvm5_3891_already_on_and_on_pending() {
        let r = rig();
        let on = || {
            code(
                psci::handle_call(
                    &r.cpus,
                    r.power.as_ref(),
                    0,
                    args(PSCI_FN_CPU_ON_64, 1, ENTRY, 0),
                )
                .unwrap(),
            )
        };
        // AP スレッド無し: メールボックスに積まれたまま ON_PENDING。
        assert_eq!(on(), 0);
        assert_eq!(on() as i64, -5);
        r.cpus.confirm_on(1).unwrap();
        assert_eq!(on() as i64, -4);
    }

    /// SEC-1・#3891: RAM 外・非整列の entry は INVALID_ADDRESS（-9）で OFF へ戻り、未接続のスロットは INTERNAL_FAILURE（-6）。
    #[test]
    fn mvm5_3891_power_on_rejects_invalid_entry_and_unattached() {
        let r = rig();
        for bad in [RAM_BASE + RAM_SIZE, RAM_BASE - 4, ENTRY + 2, 0] {
            let a = psci::handle_call(
                &r.cpus,
                r.power.as_ref(),
                0,
                args(PSCI_FN_CPU_ON_64, 1, bad, 0),
            )
            .unwrap();
            assert_eq!(code(a) as i64, -9);
            assert_eq!(r.cpus.state(1), Some(CpuPowerState::Off));
        }
        let cpus = PsciCpus::new(2).unwrap();
        let power = HvfPowerControl::new(2, RAM_BASE, RAM_SIZE);
        let a = psci::handle_call(&cpus, &power, 0, args(PSCI_FN_CPU_ON_64, 1, ENTRY, 0)).unwrap();
        assert_eq!(code(a) as i64, -6);
        assert_eq!(cpus.state(1), Some(CpuPowerState::Off));
    }

    /// MVM-5・#3891: BSP の CPU_OFF は DENIED（-3）。
    #[test]
    fn mvm5_3891_bsp_cpu_off_is_denied() {
        let r = rig();
        let a = psci::handle_call(&r.cpus, r.power.as_ref(), 0, args(PSCI_FN_CPU_OFF, 0, 0, 0))
            .unwrap();
        assert_eq!(code(a) as i64, -3);
        assert_eq!(r.cpus.state(0), Some(CpuPowerState::On));
    }

    /// 二重の post は不変条件違反（Internal）、attach は 0・範囲外・二重を拒否する。
    #[test]
    fn mvm5_3891_double_post_and_attach_errors() {
        let m = ApMailbox::new();
        let req = ApBootRequest {
            entry: ENTRY,
            context_id: 0,
        };
        m.post(req).unwrap();
        assert_eq!(
            m.post(req).unwrap_err(),
            PowerControlError::Failed(MicrovmErrorCode::Internal)
        );
        let p = HvfPowerControl::new(2, RAM_BASE, RAM_SIZE);
        for i in [0u32, 2, 9] {
            assert!(p.attach(i, Arc::default()).is_err());
        }
        p.attach(1, Arc::default()).unwrap();
        assert!(p.attach(1, Arc::default()).is_err());
    }

    /// REPAIR-5・#3891: メールボックスの待ちは見直し間隔を何倍過ぎても終わらず、停止フラグ + `notify` で即 `Stopped`。
    #[test]
    fn repair5_mvm5_3891_mailbox_wait_has_no_wall_clock_limit_and_stops() {
        let m = Arc::new(ApMailbox::new());
        let stop = Arc::new(AtomicBool::new(false));
        let (m2, s2) = (Arc::clone(&m), Arc::clone(&stop));
        let t = std::thread::spawn(move || m2.wait(&s2, Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(300));
        assert!(!t.is_finished());
        stop.store(true, Ordering::Release);
        m.notify();
        assert_eq!(t.join().unwrap(), ApWake::Stopped);
    }

    /// 実行中の BSP 役と parked の AP を VM の共有通知に結び、AP の SYSTEM_OFF 相当の終了が BSP を止める。
    /// MVM-5・MVM-1・REPAIR-5・#3891。
    #[test]
    fn mvm5_3891_ap_vm_end_stops_running_bsp() {
        struct Spin;
        impl VcpuExec for Spin {
            fn run(&mut self, _slice: Duration) -> Result<HvVcpuExit, MicrovmError> {
                std::thread::sleep(Duration::from_millis(1));
                Err(MicrovmError::new(
                    MicrovmErrorCode::DeadlineExceeded,
                    "slice",
                ))
            }
            fn stats(&self) -> HvRunStats {
                HvRunStats::default()
            }
        }
        let r = rig();
        let sd = Arc::new(VmShutdown::new());
        let bsp_stop = Arc::new(AtomicBool::new(false));
        sd.register(Arc::clone(&bsp_stop), Box::new(|| {}));
        let m = Arc::clone(&r.mailbox);
        sd.register(Arc::clone(&r.stop), Box::new(move || m.notify()));
        let (b2, sd2) = (Arc::clone(&bsp_stop), Arc::clone(&sd));
        let bsp = std::thread::spawn(move || {
            let reason = crate::hvf_loop::run_loop(
                &mut Spin,
                &b2,
                Duration::from_millis(1),
                None,
                |_, _| Ok(ExitAction::Continue),
            );
            sd2.on_vcpu_end(reason);
            reason
        });
        // AP は SYSTEM_OFF 相当（dispatch が GuestShutdown で停止）で終わる。
        let sd3 = Arc::clone(&sd);
        let (cpus, mailbox, stop) = (
            Arc::clone(&r.cpus),
            Arc::clone(&r.mailbox),
            Arc::clone(&r.stop),
        );
        let ap = std::thread::spawn(move || {
            let mut exec = FakeExec {
                log: Arc::default(),
                cpus: Arc::clone(&cpus),
                index: 1,
                stop: Arc::clone(&stop),
                exits: vec![hvc_exit()],
            };
            let reason = run_parked_ap(
                &mailbox,
                &stop,
                &cpus,
                1,
                &mut exec,
                Duration::from_millis(1),
                None,
                |_, _| Ok(()),
                |_, _| Ok(ExitAction::Stop(StopReason::GuestShutdown)),
            );
            sd3.on_vcpu_end(reason);
            reason
        });
        psci::handle_call(
            &r.cpus,
            r.power.as_ref(),
            0,
            args(PSCI_FN_CPU_ON_64, 1, ENTRY, 0),
        )
        .unwrap();
        assert_eq!(ap.join().unwrap(), StopReason::GuestShutdown);
        // BSP は呼び出し側の stop 無しで止まる。
        let t = std::time::Instant::now();
        while !bsp.is_finished() {
            assert!(t.elapsed() < LONG, "bsp kept running after the vm ended");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(bsp.join().unwrap(), StopReason::Requested);
        assert!(sd.is_triggered());
    }

    /// BSP の失敗終了が parked の AP を解く。Requested の終了は通知しない。通知後の登録は即停止状態。
    #[test]
    fn mvm5_3891_bsp_end_wakes_parked_ap_and_late_register_is_stopped() {
        let r = rig();
        let sd = Arc::new(VmShutdown::new());
        let m = Arc::clone(&r.mailbox);
        sd.register(Arc::clone(&r.stop), Box::new(move || m.notify()));
        sd.on_vcpu_end(StopReason::Requested);
        assert!(!sd.is_triggered());
        let h = spawn_ap(&r, Vec::new());
        std::thread::sleep(Duration::from_millis(30));
        assert!(!h.is_finished());
        sd.on_vcpu_end(StopReason::Failed(MicrovmErrorCode::Internal));
        assert_eq!(h.join().unwrap(), StopReason::Requested);
        let late = Arc::new(AtomicBool::new(false));
        let kicked = Arc::new(AtomicBool::new(false));
        let k2 = Arc::clone(&kicked);
        sd.register(
            Arc::clone(&late),
            Box::new(move || k2.store(true, Ordering::Release)),
        );
        assert!(late.load(Ordering::Acquire));
        assert!(kicked.load(Ordering::Acquire));
    }
}
