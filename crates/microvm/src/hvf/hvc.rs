//! HVC / SMC の exit 処理（PSCI の最小実装。TASK-192.11・#3794・MVM-5・MVM-1・REPAIR-3）。
//!
//! 役割: `hvf::vcpu` の実行ループが分類した HVC / SMC を受け、X0（関数 ID）・X1 を読んで OS 非依存の `crate::psci` に
//! 応答を決めさせ、X0 へ書いて再開するか VM を止める。シグネチャは `hvf::vcpu::dispatch` との契約で変えない。
//!
//! # 契約
//! - SYSTEM_OFF / SYSTEM_RESET は `ExitAction::Stop(StopReason::GuestShutdown)`。再起動は対象外のため RESET も同じ停止に写す
//!   （`psci` の層には区別が残る。区別が要る時は `StopReason` へ足し plugin-microvm の固定名と揃える）。
//! - それ以外は PSCI の戻り値（未知の関数 ID は NOT_SUPPORTED）を X0 に書いて `Continue`。推測で成功にしない。
//! - レジスタの読み書きの失敗は `Err` で返し、ループは `Failed` で VM を止める（fail-closed）。
//!
//! # PC の扱い
//! HVC の preferred return address は次の命令なので、HVF の exit 時点の PC は既に HVC の次を指しているとみなし、
//! HVC では PC を進めない（`handle_hvc` の 1 箇所に閉じ込めた）。この仮定は `tests/hvf_device.rs` の `hvf_device_psci_version_then_system_off` が
//! 実機で観測し、外れていればその試験が落ちる（結果記録は #3803）。trap した SMC は SMC 自身を指すので命令長だけ進める。
//!
//! # 未実装（REPAIR-3）
//! FDT は `method = "hvc"` のため SMC はゲストの誤りで NOT_SUPPORTED を返す。HVF が SMC で exit するか（HCR_EL2.TSC の扱い）は
//! 未確認で #3803 で記録する。CPU_ON 等の電源管理と SMP は対象外（`crate::psci` の doc 参照）。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_abi::{HvReg, HvVcpuExitException};
use crate::hvf_loop::ExitAction;
use crate::psci::{self, PsciAction};
use crate::stop::StopReason;
use crate::sys::HvVcpu;

/// HVC / SMC ハンドラの状態。現状は状態を持たない（将来 SMP の電源状態を持たせる）。
#[derive(Debug, Default)]
pub struct HvcHandler {
    _private: (),
}

impl HvcHandler {
    /// 空のハンドラを作る。
    pub fn new() -> Self {
        Self::default()
    }
}

fn gpr(n: u8) -> Result<HvReg, MicrovmError> {
    HvReg::x(n).ok_or_else(|| MicrovmError::new(MicrovmErrorCode::Internal, "invalid gpr index"))
}

/// HVC（PSCI）を処理する。`vcpu.rs` の dispatch から呼ばれる。
pub fn handle_hvc(
    vcpu: &mut HvVcpu<'_>,
    _handler: &mut HvcHandler,
    imm16: u16,
    _exception: &HvVcpuExitException,
) -> Result<ExitAction, MicrovmError> {
    let x0_reg = gpr(0)?;
    let x0 = vcpu.get_reg(x0_reg)?;
    let x1 = vcpu.get_reg(gpr(1)?)?;
    match psci::handle_call(imm16, x0, x1) {
        PsciAction::Return(r) => {
            vcpu.set_reg(x0_reg, r.to_x0())?;
            // PC は進めない（モジュール doc「PC の扱い」。仮定を変えるときはこの 1 箇所だけを直す）。
            Ok(ExitAction::Continue)
        }
        PsciAction::SystemOff | PsciAction::SystemReset => {
            Ok(ExitAction::Stop(StopReason::GuestShutdown))
        }
    }
}

/// trap した SMC を処理する。NOT_SUPPORTED を X0 に書き、PC を SMC の次へ進める。
pub fn handle_smc(
    vcpu: &mut HvVcpu<'_>,
    _handler: &mut HvcHandler,
    _imm16: u16,
    exception: &HvVcpuExitException,
) -> Result<ExitAction, MicrovmError> {
    vcpu.set_reg(gpr(0)?, psci::smc_return().to_x0())?;
    let pc = vcpu.get_reg(HvReg::PC)?;
    let next = psci::pc_after_trapped_smc(pc, exception.syndrome)
        .ok_or_else(|| MicrovmError::new(MicrovmErrorCode::Internal, "pc overflow after smc"))?;
    vcpu.set_reg(HvReg::PC, next)?;
    Ok(ExitAction::Continue)
}
