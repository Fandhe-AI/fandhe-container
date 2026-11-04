//! macOS の vCPU 専用スレッドと実行ループの外殻（TASK-192.9・#3791・MVM-5・MVM-1・REPAIR-5）。`unsafe` なし。
//!
//! 役割: Hypervisor.framework の vCPU は作ったスレッドに束縛される（`hv_vcpu_run`・レジスタ操作・destroy は作成スレッドから
//! 呼ぶ）。専用スレッドで `HvVcpu` を作って所有し、レジスタ初期化（`setup`）の後に実行ループを回す。ループ・停止・期限・観測の
//! 論理は OS 非依存の `crate::hvf_loop` にあり（`hv_*` を呼ばない偽の実行体で単体試験できる）、本ファイルは次だけを持つ。
//! - `HvVcpu` への [`VcpuExec`] と `VcpuCanceller` への [`VcpuKick`] の実装
//! - [`VcpuThread::spawn`] と、分類した exit を `hvf::{mmio, hvc, timer}` のハンドラへ振り分ける関数
//!
//! 呼び出し元は #3797（構成体の組み立て。`setup` に PC・CPSR・X0（FDT のアドレス）等の初期化を渡し、ハンドラ状態を持たせる）。
//! `mmio`・`hvc`・`timer` の関数シグネチャは担当 issue（#3793・#3794・#3796。いずれも実装済み）との契約で、変えるときは振り分ける関数と揃える。
//!
//! # 寿命の契約
//! スレッドは `Arc<VmWithGic>` の複製を持ち、vCPU が生きている間は VM が破棄されない。呼び出し元は自分の `Arc` とゲスト RAM
//! （`GuestMapping` は `&HvVm` を借用する）を、[`VcpuHandle::stop`] が戻るまで保つこと。`stop` が期限切れになったら、
//! スレッドが自力で終わるまで VM は残る（無期限の `join` はしない）。
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
//! `arm64_vcpu_mpidr_affinity(index)`（FDT の `cpu@index` の `reg`）を書いて読み戻し、起動要求（CPU_ON。#3891）まで止めておく。
//! parked の間は `hv_vcpu_run` を呼ばず、待ちに壁時計の上限は持たない（`LoopStart::ready_parked`）。vCPU の破棄は停止要求で
//! 待ちが解けたときだけ、owning thread が `mark_teardown` の後に行う。N 台の停止は [`VcpuSet`] が `hvf_loop::stop_all` で集約する。
//!
//! # 未実装（REPAIR-3）
//! AP の起動（CPU_ON。AP ごとの `ExitHandlers`〔`MmioHandler::with_shared_dispatcher`・`TimerHandler`・`HvcHandler::with_cpus(.., index)`〕の
//! 用意を含む）と CPU_OFF 後の parked への戻しは #3891。exit ごとの処理は mmio・hvc・timer とも実装済み。SysReg trap・ISV=0 の data abort・未知の EC は `hvf_loop::run_loop` が `Failed(Unimplemented)` で VM を止める（fail-closed）。各ハンドラに残る制限は `hvf::timer` の「未実装・簡易実装」と `hvf::{mmio, hvc}` の「未実装」節を参照。

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::arm64_layout::arm64_vcpu_mpidr_affinity;
use crate::boot_arm64::check_vcpu_mpidr_readback;
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::EsrClass;
use crate::hvf::VmWithGic;
use crate::hvf::{hvc, mmio, timer};
use crate::hvf_abi::{HVF_MAX_VCPUS, HvRunStats, HvSysReg, HvVcpuExit, check_run_deadline};
use crate::hvf_lifecycle::VcpuStopper;
use crate::hvf_loop::{
    ExitAction, HvExit, LoopHandle, LoopStart, ParkOutcome, VCPU_CREATE_DEADLINE_DEFAULT,
    VCPU_RUN_SLICE, VcpuExec, VcpuExitObserver, VcpuKick, VcpuSetStopReport, VcpuStopReport,
    run_loop, spawn_loop, stop_all,
};
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
}

impl VcpuKick for VcpuCanceller {
    fn kick(&self) -> Result<(), MicrovmError> {
        self.cancel()
    }
}

/// 起動済みの vCPU スレッドの操作口。
#[derive(Debug)]
pub struct VcpuHandle(LoopHandle<VcpuCanceller>);

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

    /// vCPU 0（BSP）のスレッドが終わったか。ゲスト起因の終了は今は BSP でだけ起きる（AP の exit をきっかけにした全台の停止は #3891）。
    pub fn is_finished(&self) -> bool {
        self.0.first().is_none_or(VcpuHandle::is_finished)
    }

    /// 実行開始の合図を BSP にだけ出す。AP の gate は開けない（CPU_ON は #3891）。
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
            _ => Err(internal(
                "unexpected exception class reached the dispatcher",
            )),
        },
        HvExit::VtimerActivated => timer::handle_vtimer(vcpu, timer_handler),
        _ => Err(internal("unexpected exit reached the dispatcher")),
    }
}

impl VcpuThread {
    /// 専用スレッド `hvf-vcpu-0` で vCPU を作り、`setup` を実行してから実行ループを回す。
    ///
    /// vCPU は `VmWithGic::create_vcpu` で作る（GIC を vCPU より先に作る契約を迂回しない。MVM-5・TASK-192.12）。
    ///
    /// 作成と `setup` の成否は `config.create_deadline` まで待って返す（失敗は `setup` のエラーのまま）。`setup` は PC・CPSR・
    /// 引数レジスタ等の初期化で、#3797 が渡す。ゲストが未対応の exit（SysReg trap・ISV=0 の data abort・未知の EC。`hvf_loop::run_loop` の表）に達するとループは `Failed(Unimplemented)` で
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

    /// AP（vCPU `index`。1 以上 [`HVF_MAX_VCPUS`] 未満）の専用スレッド `hvf-vcpu-{index}` を作り、起動要求まで parked で待たせる
    /// （#3884・MVM-5・MVM-1・REPAIR-5）。戻り値の `u64` は読み戻した `MPIDR_EL1` の生の値（観測用。記録は #3803）。
    ///
    /// スレッド内で `VmWithGic::create_vcpu` → `MPIDR_EL1` の書き込み → 読み戻し → `check_vcpu_mpidr_readback` で照合し、成功したら
    /// `ready_parked` で待つ。作成・照合の失敗は呼び出し元へ返す（`mark_teardown` は立てない。BSP の作成失敗と同じ）。停止要求で
    /// 待ちが解けたら `mark_teardown` → owning thread での vCPU の破棄 → 戻る（`hv_vcpu_run` は呼ばないので exit は 0 件）。
    /// 残余: `Err` の直後は、失敗したスレッドの終了処理中に VM の `Arc` が一瞬残りうる（BSP と同じ）。
    pub fn spawn_parked_ap(
        vm: Arc<VmWithGic>,
        index: u32,
        config: &VcpuThreadConfig,
    ) -> Result<(VcpuHandle, u64), MicrovmError> {
        if index == 0 || index >= HVF_MAX_VCPUS {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "ap vcpu index out of range",
            ));
        }
        let affinity = u64::from(arm64_vcpu_mpidr_affinity(index)?);
        let slot: Arc<OnceLock<u64>> = Arc::new(OnceLock::new());
        let slot_in = Arc::clone(&slot);
        let name = format!("hvf-vcpu-{index}");
        let handle = spawn_loop(
            &name,
            config.create_deadline,
            move |start: LoopStart<VcpuCanceller>| {
                let mut vcpu = match vm.create_vcpu() {
                    Ok(v) => v,
                    Err(e) => {
                        let code = e.code();
                        start.fail(e);
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
                    return (StopReason::Failed(code), HvRunStats::default());
                }
                let reason = match start.ready_parked(vcpu.canceller()) {
                    ParkOutcome::Stopped => StopReason::Requested,
                    // #3884 では AP の gate を誰も開けない。想定外の起動要求は推測で走らせず fail-closed で終える。
                    _ => StopReason::Failed(MicrovmErrorCode::Unimplemented),
                };
                // 破棄は teardown のときだけ（以後の vCPU 作成を拒否してから owning thread で破棄する）。
                vm.mark_teardown();
                drop(vcpu);
                (reason, HvRunStats::default())
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
        let handle = spawn_loop(
            "hvf-vcpu-0",
            config.create_deadline,
            move |start: LoopStart<VcpuCanceller>| {
                let mut vcpu = match vm.create_vcpu() {
                    Ok(v) => v,
                    Err(e) => {
                        let code = e.code();
                        start.fail(e);
                        return (StopReason::Failed(code), HvRunStats::default());
                    }
                };
                if let Err(e) = setup(&mut vcpu) {
                    let code = e.code();
                    start.fail(e);
                    return (StopReason::Failed(code), HvRunStats::default());
                }
                let stop = if gated {
                    match start.ready_gated(vcpu.canceller()) {
                        Ok(stop) => stop,
                        Err(reason) => {
                            // 走らせずに終わる（開く前の stop / drop、またはゲートの待ちの期限切れ）。
                            vm.mark_teardown();
                            drop(vcpu);
                            return (reason, HvRunStats::default());
                        }
                    }
                } else {
                    start.ready(vcpu.canceller())
                };
                let mut exec = HvfExec(vcpu, std::mem::take(&mut handlers.timer));
                let reason = run_loop(&mut exec, &stop, slice, observer.as_deref(), |e, x| {
                    dispatch(e, &mut handlers, x)
                });
                let stats = exec.stats();
                if gated {
                    // これ以後の vCPU 作成を拒否する。vCPU の破棄は teardown の一部としてだけ起きる。
                    vm.mark_teardown();
                }
                // vCPU を `vm`（この closure の捕捉値）より先に破棄してから戻る。
                drop(exec);
                (reason, stats)
            },
        )?;
        Ok(VcpuHandle(handle))
    }
}
