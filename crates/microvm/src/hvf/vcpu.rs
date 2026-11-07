//! macOS の vCPU 専用スレッドと実行ループの外殻（TASK-192.9・#3791・MVM-5・MVM-1・REPAIR-5）。`unsafe` なし。
//!
//! 役割: Hypervisor.framework の vCPU は作ったスレッドに束縛される（`hv_vcpu_run`・レジスタ操作・destroy は作成スレッドから
//! 呼ぶ）。専用スレッドで `HvVcpu` を作って所有し、レジスタ初期化（`setup`）の後に実行ループを回す。ループ・停止・期限・観測の
//! 論理は OS 非依存の `crate::hvf_loop` にあり（`hv_*` を呼ばない偽の実行体で単体試験できる）、本ファイルは次だけを持つ。
//! - `HvVcpu` への [`VcpuExec`]（`pc` は未対応 exit の診断ログ用に `HvReg::PC` を読む。#4035・REPAIR-4）と `VcpuCanceller` への [`VcpuKick`] の実装（kick は `WakingKick` で包み、WFI の待ちも起こす。#3887）
//! - [`VcpuThread::spawn`] と、分類した exit を `hvf::{mmio, hvc, timer}` のハンドラへ振り分ける関数
//!
//! 呼び出し元は #3797（構成体の組み立て。`setup` に PC・CPSR・X0（FDT のアドレス）等の初期化を渡し、ハンドラ状態を持たせる）。
//! `mmio`・`hvc`・`timer` の関数シグネチャは担当 issue（#3793・#3794・#3796。いずれも実装済み）との契約で、変えるときは振り分ける関数と揃える。
//!
//! # 寿命の契約
//! スレッドは `Arc<VmWithGic>` の複製を持ち、vCPU が生きている間は VM が破棄されない。呼び出し元は自分の `Arc` とゲスト RAM
//! （`GuestMapping` は `&HvVm` を借用する）を、[`VcpuHandle::stop`] が戻るまで保つこと。`stop` が期限切れになったら、
//! スレッドが自力で終わるまで VM とゲスト RAM は残る（無期限の `join` はしない）。終わった時点で、スレッドが vCPU の破棄 →
//! デバイスの参照 → RAM のスロットの clone（[`ExitHandlers::guest_memory`]）→ VM の順に落とし、最後の `Arc` として unmap・munmap・
//! `hv_vm_destroy` を行う（#4032。vCPU スレッドからの `hv_vm_unmap`・`hv_vm_destroy` は実機未確認、#4034）。
//!
//! # 開始の制御と破棄の順序（TASK-192.16・#3798）
//! [`VcpuThread::spawn_gated`] は vCPU を作って `setup` を済ませた後、[`VcpuHandle::open_start`] が呼ばれるまでゲストを走らせない
//! （microVM の組み立てと `start` を分ける。[`VcpuThread::spawn`] は直後に開く従来の形）。ゲートの待ちは上限つきで、開く前の
//! stop / drop は走らせずに終わる。`spawn_gated` のスレッドは終了時、`VmWithGic::mark_teardown`（以後の vCPU 作成を拒否）→
//! owning thread での vCPU の破棄 → `Arc<VmWithGic>` の解放、の順で戻る（`hvf::microvm` の解放順序）。`spawn`（従来の形）は
//! 印を立てない（同じ VM に vCPU を作り直す既存の結合試験があるため）。
//!
//! # AP（vCPU 1..N）の parked スレッド（#3884・MVM-5・MVM-1・REPAIR-5）
//! [`VcpuThread::spawn_parked_ap`] は index 1 以上の vCPU を専用スレッド `hvf-vcpu-{index}` で作り、`MPIDR_EL1` に
//! `arm64_vcpu_mpidr_affinity(index)`（FDT の `cpu@index` の `reg`）を書いて読み戻し、起動要求（PSCI CPU_ON）まで止めておく。
//! parked の間は `hv_vcpu_run` を呼ばず、待ちに壁時計の上限は持たない（`hvf_smp::ApMailbox::wait`）。CPU_ON は
//! `hvf_smp::HvfPowerControl` がメールボックスへ積み、owning thread がレジスタ（X0〜X3・PC・CPSR・SCTLR_EL1）を書いて ON を確定し
//! （`PsciCpus::confirm_on`）実行ループに入る。CPU_OFF は `ExitAction::Park` で実行ループを抜けて park に戻る（#3891）。vCPU の破棄は
//! 停止要求（kick がメールボックスも起こす）で待ちが解けたときだけ、owning thread が `mark_teardown` の後に行う。
//! N 台の停止は [`VcpuSet`] が `hvf_loop::stop_all` で集約し、どれか 1 台が終われば [`VcpuSet::is_finished`] が真になる。
//!
//! # 未実装（REPAIR-3）
//! exit ごとの処理は mmio・hvc・timer・sysreg（OS Lock の write のみ。#4037）とも実装済み。それ以外の SysReg trap・ISV=0 の data abort・未知の EC は `hvf_loop::run_loop` が `Failed(Unimplemented)` で VM を止める（fail-closed）。各ハンドラに残る制限は `hvf::timer` の「未実装・簡易実装」と `hvf::{mmio, hvc}` の「未実装」節を参照。

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::arm64_layout::arm64_vcpu_mpidr_affinity;
use crate::boot_arm64::{
    ApBootRegs, SCTLR_EL1_C, SCTLR_EL1_EE, SCTLR_EL1_I, SCTLR_EL1_M, check_vcpu_mpidr_readback,
    sctlr_for_cpu_on,
};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::EsrClass;
use crate::guest_memory_slot::GuestMemorySlot;
use crate::hvf::VmWithGic;
use crate::hvf::memory::RegisteredHvfRam;
use crate::hvf::{hvc, mmio, sysreg, timer};
use crate::hvf_abi::{HVF_MAX_VCPUS, HvReg, HvRunStats, HvSysReg, HvVcpuExit, check_run_deadline};
use crate::hvf_lifecycle::{VcpuStopper, drop_vcpu_thread_state};
use crate::hvf_loop::{
    ExitAction, HvExit, LoopHandle, LoopStart, VCPU_CREATE_DEADLINE_DEFAULT, VCPU_RUN_SLICE,
    VcpuExec, VcpuExitObserver, VcpuKick, VcpuSetStopReport, VcpuStopReport, run_loop, spawn_loop,
    stop_all,
};
use crate::hvf_smp::{ApMailbox, run_parked_ap};
use crate::hvf_wake::{WakingKick, WfiWakeSet};
use crate::psci::PsciCpus;
use crate::stop::StopReason;
use crate::sys::{HvVcpu, VcpuCanceller};

// `Arc<VmWithGic>` を vCPU スレッドへ渡す前提（1 プロセス 1 VM の VM を Arc で共有する）。
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<VmWithGic>();
};

/// exit の種別ごとのハンドラ状態。スレッドへ move するため各状態は `Send` であること。
///
/// `Default` は実装しない（各ハンドラが自分の型の `Default` を変えても `vcpu.rs` を触らずに済むように、呼び出し側が組み立てる）。
#[derive(Debug)]
pub struct ExitHandlers {
    /// MMIO（data abort）。#3793。
    pub mmio: mmio::MmioHandler,
    /// HVC / SMC（PSCI）。#3794。
    pub hvc: hvc::HvcHandler,
    /// WFI / vtimer。#3796。
    pub timer: timer::TimerHandler,
    /// ゲスト RAM のスロットの clone（#4032・MVM-5・REPAIR-5）。親の `stop` が期限切れで切り離したスレッドが、終了時に最後の
    /// `Arc` を落として unmap → munmap → `hv_vm_destroy` の回収を担うための保持。`hvf::microvm::assemble` は全 vCPU に `Some` を渡す
    /// （block が 0 台でも保持する。route 経由の clone だけでは、block が無い構成でゲストの走行中に RAM が解放されうるため）。
    ///
    /// 契約: vCPU の破棄より後、`mmio` などデバイス側の参照より後、`Arc<VmWithGic>` より前に落とす（`hvf_lifecycle::drop_vcpu_thread_state`）。
    /// 試験などで保持が要らない呼び出し側は `None`。
    pub guest_memory: Option<GuestMemorySlot<RegisteredHvfRam<'static>>>,
}

/// [`VcpuThread::spawn`] の設定。
#[derive(Debug, Clone)]
pub struct VcpuThreadConfig {
    /// `run` 1 回あたりの期限。0 超 `HV_RUN_DEADLINE_MAX` 以下（`InvalidArgument`）。
    pub run_slice: Duration,
    /// vCPU の作成と `setup` を待つ期限。0 超 60 秒以下（`InvalidArgument`）。
    pub create_deadline: Duration,
    /// exit の種別と回数の観測器（REPAIR-4）。
    pub observer: Option<Arc<dyn VcpuExitObserver>>,
}

impl Default for VcpuThreadConfig {
    fn default() -> Self {
        Self {
            run_slice: VCPU_RUN_SLICE,
            create_deadline: VCPU_CREATE_DEADLINE_DEFAULT,
            observer: None,
        }
    }
}

/// `HvVcpu` を [`VcpuExec`] として扱う薄い包み（スレッド内でだけ作る。`!Send`）。
/// vtimer の mask 同期を `hv_vcpu_run` の再入直前に行うため `TimerHandler` もここで持つ（MVM-5・#3796）。
struct HvfExec<'a>(HvVcpu<'a>, timer::TimerHandler);

impl VcpuExec for HvfExec<'_> {
    fn run(&mut self, slice: Duration) -> Result<HvVcpuExit, MicrovmError> {
        timer::sync_before_run(&mut self.0, &mut self.1)?;
        self.0.run_once(slice)
    }

    fn stats(&self) -> HvRunStats {
        self.0.stats()
    }

    fn pc(&self) -> Option<u64> {
        self.0.get_reg(HvReg::PC).ok()
    }
}

/// vCPU スレッドの kick。`hv_vcpus_exit` に加え、AP ではメールボックスの待ちも起こす（parked の AP が停止要求に即応する。#3891）。
/// BSP は `mailbox = None`。
#[derive(Debug)]
pub struct HvfKick {
    canceller: VcpuCanceller,
    mailbox: Option<Arc<ApMailbox>>,
}

impl VcpuKick for HvfKick {
    fn kick(&self) -> Result<(), MicrovmError> {
        let r = self.canceller.cancel();
        if let Some(m) = &self.mailbox {
            m.notify();
        }
        r
    }
}

/// 起動済みの vCPU スレッドの操作口。
#[derive(Debug)]
pub struct VcpuHandle(LoopHandle<WakingKick<HvfKick, WfiWakeSet>>);

impl VcpuHandle {
    /// スレッドが既に終わったか（ゲスト起因の終了を含む）。
    pub fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    /// 停止を要求し、`deadline`（0 超 60 秒以下）まで終了報告を待つ。`Ok` で戻った時点で vCPU は破棄済み。
    /// ゲスト起因で既に終わっていたときはその理由を返す。期限切れは `TIMEOUT`（`DeadlineExceeded`）でスレッドを切り離す。
    pub fn stop(self, deadline: Duration) -> Result<VcpuStopReport, MicrovmError> {
        self.0.stop(deadline)
    }

    /// 実行開始の合図を出す（[`VcpuThread::spawn_gated`] で作ったスレッドがゲストを走らせ始める。TASK-192.16・#3798）。
    pub fn open_start(&self) {
        self.0.open_start();
    }
}

impl VcpuStopper for VcpuHandle {
    fn stop(self, deadline: Duration) -> Result<VcpuSetStopReport, MicrovmError> {
        VcpuHandle::stop(self, deadline).map(VcpuSetStopReport::single)
    }
}

/// N 台の vCPU スレッドの集合（index 0 = BSP、1.. = parked の AP。#3884）。停止は全台をまとめて期限つきで回収する。
#[derive(Debug)]
pub struct VcpuSet(Vec<VcpuHandle>);

impl VcpuSet {
    /// BSP だけの集合を作る。
    pub fn new(bsp: VcpuHandle) -> Self {
        Self(vec![bsp])
    }

    /// AP を末尾へ足す（index 順に呼ぶこと）。
    pub fn push_ap(&mut self, ap: VcpuHandle) {
        self.0.push(ap);
    }

    /// どれか 1 台のスレッドが終わったか（空なら真）。parked の AP は停止要求か、ゲスト起因の終了（SYSTEM_OFF・fail-closed の停止）でしか
    /// 終わらないため、AP の終了も VM 全体の終了として呼び出し元に伝わる（#3891）。理由は停止時の集約（`VcpuSetStopReport`）に出る。
    pub fn is_finished(&self) -> bool {
        self.0.is_empty() || self.0.iter().any(VcpuHandle::is_finished)
    }

    /// 実行開始の合図を BSP にだけ出す。AP は gate を使わず、CPU_ON のメールボックスで起きる（#3891）。
    pub fn open_start(&self) {
        if let Some(bsp) = self.0.first() {
            bsp.open_start();
        }
    }
}

impl VcpuStopper for VcpuSet {
    /// 全台へ先に停止を要求し、共有の期限で回収する（`hvf_loop::stop_all`）。`Ok` は N 台すべてが破棄済みのとき。
    fn stop(self, deadline: Duration) -> Result<VcpuSetStopReport, MicrovmError> {
        stop_all(self.0.into_iter().map(|h| h.0).collect(), deadline)
    }
}

/// vCPU 専用スレッドの起動口。
#[derive(Debug)]
pub struct VcpuThread;

fn internal(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, msg)
}

/// 分類済みの exit を担当のハンドラへ振り分ける。[`run_loop`] が処理済みの exit（停止・未知・未対応）はここへ来ない。
fn dispatch(
    exec: &mut HvfExec<'_>,
    handlers: &mut ExitHandlers,
    exit: &HvExit,
) -> Result<ExitAction, MicrovmError> {
    let vcpu = &mut exec.0;
    let timer_handler = &mut exec.1;
    match exit {
        HvExit::Exception { class, exception } => match class {
            EsrClass::DataAbort(da) => {
                mmio::handle_data_abort(vcpu, &mut handlers.mmio, da, exception)
            }
            EsrClass::Hvc { imm16 } => hvc::handle_hvc(vcpu, &mut handlers.hvc, *imm16, exception),
            EsrClass::Smc { imm16 } => hvc::handle_smc(vcpu, &mut handlers.hvc, *imm16, exception),
            EsrClass::Wfx(kind) => timer::handle_wfx(vcpu, timer_handler, *kind, exception),
            EsrClass::SysReg(access) => sysreg::handle_sysreg(vcpu, access, exception),
            _ => Err(internal(
                "unexpected exception class reached the dispatcher",
            )),
        },
        HvExit::VtimerActivated => timer::handle_vtimer(vcpu, timer_handler),
        _ => Err(internal("unexpected exit reached the dispatcher")),
    }
}

fn gpr_reg(n: u8) -> Result<HvReg, MicrovmError> {
    HvReg::x(n).ok_or_else(|| internal("invalid general register"))
}

/// CPU_ON で起動する AP のレジスタを owning thread で書き、読み戻して照合する（#3891・MVM-5）。
///
/// X0〜X3・PC・CPSR は `regs` の値。`SCTLR_EL1` は CPU_OFF の前にゲストが有効にした MMU・D-cache・I-cache・EE が残りうるため、
/// 毎回 `sctlr_for_cpu_on` で M・C・I・EE を落とした値にする（変わらないときは書かない）。照合の不一致は fail-closed
/// （`Internal` / `FailedPrecondition`）で、走らせない。MPIDR は spawn 時に書いて照合済みのため書き直さない。
fn boot_ap(vcpu: &mut HvVcpu<'_>, regs: &ApBootRegs) -> Result<(), MicrovmError> {
    for (n, value) in [(0u8, regs.x0), (1, regs.x1), (2, regs.x2), (3, regs.x3)] {
        vcpu.set_reg(gpr_reg(n)?, value)?;
    }
    vcpu.set_reg(HvReg::PC, regs.pc)?;
    vcpu.set_reg(HvReg::CPSR, regs.cpsr)?;
    let prev = vcpu.get_sys_reg(HvSysReg::SCTLR_EL1)?;
    let want = sctlr_for_cpu_on(prev);
    if want != prev {
        vcpu.set_sys_reg(HvSysReg::SCTLR_EL1, want)?;
    }
    if vcpu.get_reg(gpr_reg(0)?)? != regs.x0
        || vcpu.get_reg(HvReg::PC)? != regs.pc
        || vcpu.get_reg(HvReg::CPSR)? != regs.cpsr
    {
        return Err(internal("ap boot register readback does not match"));
    }
    if vcpu.get_sys_reg(HvSysReg::SCTLR_EL1)?
        & (SCTLR_EL1_M | SCTLR_EL1_C | SCTLR_EL1_I | SCTLR_EL1_EE)
        != 0
    {
        return Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "sctlr_el1 has mmu, d-cache, i-cache or big-endian enabled at ap boot",
        ));
    }
    Ok(())
}

impl VcpuThread {
    /// 専用スレッド `hvf-vcpu-0` で vCPU を作り、`setup` を実行してから実行ループを回す。
    ///
    /// vCPU は `VmWithGic::create_vcpu` で作る（GIC を vCPU より先に作る契約を迂回しない。MVM-5・TASK-192.12）。
    ///
    /// 作成と `setup` の成否は `config.create_deadline` まで待って返す（失敗は `setup` のエラーのまま）。`setup` は PC・CPSR・
    /// 引数レジスタ等の初期化で、#3797 が渡す。ゲストが未対応の exit（OS Lock の write 以外の SysReg trap・ISV=0 の data abort・未知の EC。`hvf_loop::run_loop` の表）に達するとループは `Failed(Unimplemented)` で
    /// 終わり、[`VcpuHandle::is_finished`] で観測できる。寿命の契約はモジュールの doc を参照。
    pub fn spawn<S>(
        vm: Arc<VmWithGic>,
        setup: S,
        handlers: ExitHandlers,
        config: VcpuThreadConfig,
    ) -> Result<VcpuHandle, MicrovmError>
    where
        S: FnOnce(&mut HvVcpu<'_>) -> Result<(), MicrovmError> + Send + 'static,
    {
        let handle = Self::spawn_inner(vm, setup, handlers, config, false)?;
        handle.open_start();
        Ok(handle)
    }

    /// [`Self::spawn`] と同じだが、[`VcpuHandle::open_start`] が呼ばれるまでゲストを走らせない（TASK-192.16・#3798・MVM-5）。
    ///
    /// microVM の `assemble`（組み立て）が使い、`start` が開く。終了時は `VmWithGic::mark_teardown` を立ててから vCPU を破棄する。
    pub fn spawn_gated<S>(
        vm: Arc<VmWithGic>,
        setup: S,
        handlers: ExitHandlers,
        config: VcpuThreadConfig,
    ) -> Result<VcpuHandle, MicrovmError>
    where
        S: FnOnce(&mut HvVcpu<'_>) -> Result<(), MicrovmError> + Send + 'static,
    {
        Self::spawn_inner(vm, setup, handlers, config, true)
    }

    /// AP（vCPU `index`。1 以上 [`HVF_MAX_VCPUS`] 未満）の専用スレッド `hvf-vcpu-{index}` を作り、CPU_ON まで parked で待たせる
    /// （#3884・#3891・MVM-5・MVM-1・REPAIR-5）。戻り値の `u64` は読み戻した `MPIDR_EL1` の生の値（観測用。記録は #3803）。
    ///
    /// スレッド内で `VmWithGic::create_vcpu` → `MPIDR_EL1` の書き込み → 読み戻し → `check_vcpu_mpidr_readback` で照合し、成功したら
    /// `hvf_smp::run_parked_ap` に入る。`mailbox` は呼び出し元が `HvfPowerControl::attach` で結ぶものと同じ実体で、`cpus` は BSP のハンドラと
    /// 共有する電源状態の表。`handlers` は AP 専用の exit ハンドラ（`hvc` は `HvcHandler::with_cpus(.., index)`）。作成・照合の失敗は
    /// 呼び出し元へ返す（`mark_teardown` は立てない。BSP の作成失敗と同じ）。停止要求で待ちが解けたら `mark_teardown` → owning thread での
    /// vCPU の破棄 → 戻る。残余: `Err` の直後は、失敗したスレッドの終了処理中に VM の `Arc` が一瞬残りうる（BSP と同じ）。
    pub fn spawn_parked_ap(
        vm: Arc<VmWithGic>,
        index: u32,
        handlers: ExitHandlers,
        mailbox: Arc<ApMailbox>,
        cpus: Arc<PsciCpus>,
        config: &VcpuThreadConfig,
    ) -> Result<(VcpuHandle, u64), MicrovmError> {
        if index == 0 || index >= HVF_MAX_VCPUS {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "ap vcpu index out of range",
            ));
        }
        check_run_deadline(config.run_slice)?;
        let slice = config.run_slice;
        let observer = config.observer.clone();
        let affinity = u64::from(arm64_vcpu_mpidr_affinity(index)?);
        let slot: Arc<OnceLock<u64>> = Arc::new(OnceLock::new());
        let slot_in = Arc::clone(&slot);
        let name = format!("hvf-vcpu-{index}");
        // WFI の待ちは vCPU 専用のスロットに結び（SPI は宛先のスロットだけを起こす。#3948）、停止要求は全台を起こす。
        let mut handlers = handlers;
        handlers.timer.set_waker(vm.wfi_waker_for_vcpu(index)?);
        let wake = vm.wake_set();
        let kick_mailbox = Arc::clone(&mailbox);
        let shutdown = vm.shutdown();
        let handle = spawn_loop(
            &name,
            config.create_deadline,
            move |start: LoopStart<WakingKick<HvfKick, WfiWakeSet>>| {
                // vCPU は `vm_run`（`vm` の `Arc` の clone）を借用する。`vm` 自身は借用させず、終了時に
                // `drop_vcpu_thread_state` へ move して、vCPU・デバイス参照・スロットの後に落とす（#4032）。
                // `vm_run` はこの closure のローカルで、関数のスコープの終わりに落ちる。`drop_vcpu_thread_state` が
                // `vm` を落とした時点で `vm_run` が最後の `Arc` を持っていれば、VM の解放はここ（`vm_run` の drop）になる。
                // 順序の根拠は `vm_run` の drop 位置ではなく、vCPU を先に破棄してから `vm` を渡すことにある。
                let vm_run = Arc::clone(&vm);
                let mut vcpu = match vm_run.create_vcpu() {
                    Ok(v) => v,
                    Err(e) => {
                        let code = e.code();
                        start.fail(e);
                        let ExitHandlers {
                            mmio,
                            hvc,
                            timer,
                            guest_memory,
                        } = handlers;
                        drop(timer);
                        drop_vcpu_thread_state((mmio, hvc), guest_memory, vm);
                        return (StopReason::Failed(code), HvRunStats::default());
                    }
                };
                let prepared = vcpu
                    .set_sys_reg(HvSysReg::MPIDR_EL1, affinity)
                    .and_then(|()| vcpu.get_sys_reg(HvSysReg::MPIDR_EL1))
                    .and_then(|raw| check_vcpu_mpidr_readback(index, raw).map(|()| raw))
                    .and_then(|raw| {
                        slot_in
                            .set(raw)
                            .map_err(|_| internal("mpidr readback was recorded twice"))
                    });
                if let Err(e) = prepared {
                    let code = e.code();
                    start.fail(e);
                    drop(vcpu);
                    let ExitHandlers {
                        mmio,
                        hvc,
                        timer,
                        guest_memory,
                    } = handlers;
                    drop(timer);
                    drop_vcpu_thread_state((mmio, hvc), guest_memory, vm);
                    return (StopReason::Failed(code), HvRunStats::default());
                }
                let kick = HvfKick {
                    canceller: vcpu.canceller(),
                    mailbox: Some(kick_mailbox),
                };
                let peer = (vcpu.canceller(), Arc::clone(&mailbox), wake.clone());
                let stop = start.ready(WakingKick::new(kick, wake));
                shutdown.register(
                    Arc::clone(&stop),
                    Box::new(move || {
                        let _ = peer.0.cancel();
                        peer.1.notify();
                        peer.2.notify_all();
                    }),
                );
                let mut exec = HvfExec(vcpu, std::mem::take(&mut handlers.timer));
                let reason = run_parked_ap(
                    &mailbox,
                    &stop,
                    &cpus,
                    index,
                    &mut exec,
                    slice,
                    observer.as_deref(),
                    |e, regs| boot_ap(&mut e.0, regs),
                    |e, x| dispatch(e, &mut handlers, x),
                );
                // VM の終了（SYSTEM_OFF・失敗。CPU_OFF の Park ではない）を他の vCPU へ伝える。
                shutdown.on_vcpu_end(reason);
                let stats = exec.stats();
                // 破棄は teardown のときだけ（以後の vCPU 作成を拒否してから owning thread で破棄する）。
                vm.mark_teardown();
                drop(exec);
                let ExitHandlers {
                    mmio,
                    hvc,
                    timer,
                    guest_memory,
                } = handlers;
                drop(timer);
                drop_vcpu_thread_state((mmio, hvc), guest_memory, vm);
                (reason, stats)
            },
        )?;
        match slot.get() {
            Some(raw) => Ok((VcpuHandle(handle), *raw)),
            None => {
                let _ = handle.stop(crate::hvf_lifecycle::DROP_STOP_DEADLINE);
                Err(internal("mpidr readback was not recorded"))
            }
        }
    }

    fn spawn_inner<S>(
        vm: Arc<VmWithGic>,
        setup: S,
        handlers: ExitHandlers,
        config: VcpuThreadConfig,
        gated: bool,
    ) -> Result<VcpuHandle, MicrovmError>
    where
        S: FnOnce(&mut HvVcpu<'_>) -> Result<(), MicrovmError> + Send + 'static,
    {
        check_run_deadline(config.run_slice)?;
        let slice = config.run_slice;
        let observer = config.observer;
        let mut handlers = handlers;
        // WFI の待ちを vCPU 0 専用のスロットに結ぶ（SPI は宛先のスロットだけ、停止要求の kick は全台を起こす。#3887・#3948）。
        // 呼び出し側がどの `TimerHandler` を渡しても同じ。
        handlers.timer.set_waker(vm.wfi_waker_for_vcpu(0)?);
        let wake = vm.wake_set();
        let shutdown = vm.shutdown();
        let handle = spawn_loop(
            "hvf-vcpu-0",
            config.create_deadline,
            move |start: LoopStart<WakingKick<HvfKick, WfiWakeSet>>| {
                // vCPU は `vm_run`（`vm` の `Arc` の clone）を借用する。`vm` 自身は借用させず、終了時に
                // `drop_vcpu_thread_state` へ move して、vCPU・デバイス参照・スロットの後に落とす（#4032）。
                // `vm_run` はこの closure のローカルで、関数のスコープの終わりに落ちる。`drop_vcpu_thread_state` が
                // `vm` を落とした時点で `vm_run` が最後の `Arc` を持っていれば、VM の解放はここ（`vm_run` の drop）になる。
                // 順序の根拠は `vm_run` の drop 位置ではなく、vCPU を先に破棄してから `vm` を渡すことにある。
                let vm_run = Arc::clone(&vm);
                let mut vcpu = match vm_run.create_vcpu() {
                    Ok(v) => v,
                    Err(e) => {
                        let code = e.code();
                        start.fail(e);
                        let ExitHandlers {
                            mmio,
                            hvc,
                            timer,
                            guest_memory,
                        } = handlers;
                        drop(timer);
                        drop_vcpu_thread_state((mmio, hvc), guest_memory, vm);
                        return (StopReason::Failed(code), HvRunStats::default());
                    }
                };
                if let Err(e) = setup(&mut vcpu) {
                    let code = e.code();
                    start.fail(e);
                    drop(vcpu);
                    let ExitHandlers {
                        mmio,
                        hvc,
                        timer,
                        guest_memory,
                    } = handlers;
                    drop(timer);
                    drop_vcpu_thread_state((mmio, hvc), guest_memory, vm);
                    return (StopReason::Failed(code), HvRunStats::default());
                }
                let peer = (vcpu.canceller(), wake.clone());
                let kick = WakingKick::new(
                    HvfKick {
                        canceller: vcpu.canceller(),
                        mailbox: None,
                    },
                    wake,
                );
                let stop = if gated {
                    match start.ready_gated(kick) {
                        Ok(stop) => stop,
                        Err(reason) => {
                            // 走らせずに終わる（開く前の stop / drop、またはゲートの待ちの期限切れ）。
                            vm.mark_teardown();
                            drop(vcpu);
                            let ExitHandlers {
                                mmio,
                                hvc,
                                timer,
                                guest_memory,
                            } = handlers;
                            drop(timer);
                            drop_vcpu_thread_state((mmio, hvc), guest_memory, vm);
                            return (reason, HvRunStats::default());
                        }
                    }
                } else {
                    start.ready(kick)
                };
                shutdown.register(
                    Arc::clone(&stop),
                    Box::new(move || {
                        let _ = peer.0.cancel();
                        peer.1.notify_all();
                    }),
                );
                let mut exec = HvfExec(vcpu, std::mem::take(&mut handlers.timer));
                let reason = run_loop(&mut exec, &stop, slice, observer.as_deref(), |e, x| {
                    dispatch(e, &mut handlers, x)
                });
                // BSP の終了（SYSTEM_OFF・失敗）も VM の終了として AP へ伝える。
                shutdown.on_vcpu_end(reason);
                let stats = exec.stats();
                if gated {
                    // これ以後の vCPU 作成を拒否する。vCPU の破棄は teardown の一部としてだけ起きる。
                    vm.mark_teardown();
                }
                // vCPU → デバイス参照 → スロット → VM の順に破棄してから戻る（AP と同じ。#4032）。
                drop(exec);
                let ExitHandlers {
                    mmio,
                    hvc,
                    timer,
                    guest_memory,
                } = handlers;
                drop(timer);
                drop_vcpu_thread_state((mmio, hvc), guest_memory, vm);
                (reason, stats)
            },
        )?;
        Ok(VcpuHandle(handle))
    }
}
