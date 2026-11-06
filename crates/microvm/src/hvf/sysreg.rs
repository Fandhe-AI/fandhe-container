//! SysReg trap（EC 0x18）の exit 処理（#4037・MVM-5・MVM-1）。
//!
//! 役割: `hvf::vcpu` の `dispatch` から呼ばれ、`hvf_loop::run_loop_exit` が受けると判断した OS Lock レジスタ
//! （`OSDLR_EL1`・`OSLAR_EL1`）の write だけを処理する。`rt` の値を読み（rt=31 は 0）、判定と次の PC の計算は
//! OS 非依存の `crate::sysreg_os_lock` に任せ、PC を進めて続行する。0 以外の write は `Unimplemented` で止める。
//!
//! # 未実装（REPAIR-3）
//! - OS Lock の状態は持たない（ロックを掛ける write は止める）。read・他のレジスタは `run_loop_exit` が止める。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::SysRegAccess;
use crate::hvf_abi::{HvReg, HvVcpuExitException};
use crate::hvf_loop::ExitAction;
use crate::sys::HvVcpu;
use crate::sysreg_os_lock::os_lock_write_next_pc;

fn internal(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, msg)
}

/// OS Lock の write を処理する。値が 0 なら PC を命令長だけ進めて続行し、0 以外は `Unimplemented`。
pub fn handle_sysreg(
    vcpu: &mut HvVcpu<'_>,
    access: &SysRegAccess,
    exception: &HvVcpuExitException,
) -> Result<ExitAction, MicrovmError> {
    let value = if access.rt.is_zero_register() {
        0
    } else {
        let reg = HvReg::x(access.rt.get()).ok_or_else(|| internal("invalid Rt"))?;
        vcpu.get_reg(reg)?
    };
    let pc = vcpu.get_reg(HvReg::PC)?;
    let next = os_lock_write_next_pc(access, value, pc, exception.syndrome)?;
    vcpu.set_reg(HvReg::PC, next)?;
    Ok(ExitAction::Continue)
}
