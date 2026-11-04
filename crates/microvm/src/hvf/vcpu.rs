//! macOS の vCPU 専用スレッドと実行ループの外殻（TASK-192.9・#3791・MVM-5・MVM-1・REPAIR-5）。`unsafe` なし。
//!
//! 役割: Hypervisor.framework の vCPU は作ったスレッドに束縛される（`hv_vcpu_run`・レジスタ操作・destroy は作成スレッドから
//! 呼ぶ）。専用スレッドで `HvVcpu` を作って所有し、レジスタ初期化（`setup`）の後に実行ループを回す。ループ・停止・期限・観測の
//! 論理は OS 非依存の `crate::hvf_loop` にあり（`hv_*` を呼ばない偽の実行体で単体試験できる）、本ファイルは次だけを持つ。
//! - `HvVcpu` への [`VcpuExec`] と `VcpuCanceller` への [`VcpuKick`] の実装
//! - [`VcpuThread::spawn`] と、分類した exit を `hvf::{mmio, hvc, timer}` のスタブへ振り分ける関数
//!
//! 呼び出し元は #3797（構成体の組み立て。`setup` に PC・CPSR・X0（FDT のアドレス）等の初期化を渡し、ハンドラ状態を持たせる）。
//! `mmio`・`hvc`・`timer` の関数シグネチャは担当 issue（#3793・#3794・#3796）との契約で、各自が自分のファイルだけを差し替える。
//!
//! # 寿命の契約
//! スレッドは `Arc<VmWithGic>` の複製を持ち、vCPU が生きている間は VM が破棄されない。呼び出し元は自分の `Arc` とゲスト RAM
//! （`GuestMapping` は `&HvVm` を借用する）を、[`VcpuHandle::stop`] が戻るまで保つこと。`stop` が期限切れになったら、
//! スレッドが自力で終わるまで VM は残る（無期限の `join` はしない）。
//!
//! # 未実装（REPAIR-3）
//! 複数 vCPU（スレッド名は `hvf-vcpu-0` 固定）・AP の起動。exit ごとの実処理は hvc 以外スタブ（`Unimplemented` で VM を止める）。

use std::sync::Arc;
use std::time::Duration;

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::EsrClass;
use crate::hvf::VmWithGic;
use crate::hvf::{hvc, mmio, timer};
use crate::hvf_abi::{HvRunStats, HvVcpuExit, check_run_deadline};
use crate::hvf_loop::{
    ExitAction, HvExit, LoopHandle, LoopStart, VCPU_CREATE_DEADLINE_DEFAULT, VCPU_RUN_SLICE,
    VcpuExec, VcpuExitObserver, VcpuKick, VcpuStopReport, run_loop, spawn_loop,
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
struct HvfExec<'a>(HvVcpu<'a>);

impl VcpuExec for HvfExec<'_> {
    fn run(&mut self, slice: Duration) -> Result<HvVcpuExit, MicrovmError> {
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
    match exit {
        HvExit::Exception { class, exception } => match class {
            EsrClass::DataAbort(da) => {
                mmio::handle_data_abort(vcpu, &mut handlers.mmio, da, exception)
            }
            EsrClass::Hvc { imm16 } => hvc::handle_hvc(vcpu, &mut handlers.hvc, *imm16, exception),
            EsrClass::Smc { imm16 } => hvc::handle_smc(vcpu, &mut handlers.hvc, *imm16, exception),
            EsrClass::Wfx(kind) => timer::handle_wfx(vcpu, &mut handlers.timer, *kind, exception),
            _ => Err(internal(
                "unexpected exception class reached the dispatcher",
            )),
        },
        HvExit::VtimerActivated => timer::handle_vtimer(vcpu, &mut handlers.timer),
        _ => Err(internal("unexpected exit reached the dispatcher")),
    }
}

impl VcpuThread {
    /// 専用スレッド `hvf-vcpu-0` で vCPU を作り、`setup` を実行してから実行ループを回す。
    ///
    /// vCPU は `VmWithGic::create_vcpu` で作る（GIC を vCPU より先に作る契約を迂回しない。MVM-5・TASK-192.12）。
    ///
    /// 作成と `setup` の成否は `config.create_deadline` まで待って返す（失敗は `setup` のエラーのまま）。`setup` は PC・CPSR・
    /// 引数レジスタ等の初期化で、#3797 が渡す。ゲストが `Unimplemented` の exit（スタブ）に達するとループは `Failed(Unimplemented)` で
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
                let stop = start.ready(vcpu.canceller());
                let mut exec = HvfExec(vcpu);
                let reason = run_loop(&mut exec, &stop, slice, observer.as_deref(), |e, x| {
                    dispatch(e, &mut handlers, x)
                });
                let stats = exec.stats();
                // vCPU を `vm`（この closure の捕捉値）より先に破棄してから戻る。
                drop(exec);
                (reason, stats)
            },
        )?;
        Ok(VcpuHandle(handle))
    }
}
