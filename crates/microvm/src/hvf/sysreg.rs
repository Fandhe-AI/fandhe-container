//! SysReg trap（EC 0x18）の exit 処理（#4037・MVM-5・MVM-1）。
//!
//! 役割: `hvf::vcpu` の `dispatch` から呼ばれ、`hvf_loop::run_loop_exit` が受けると判断した OS Lock レジスタ
//! （`OSDLR_EL1`・`OSLAR_EL1`）の write だけを処理する。`rt` の読み出し・判定・PC の書き戻しの手順は
//! OS 非依存の `crate::sysreg_os_lock::apply_os_lock_write`（Linux で偽のレジスタ口により単体試験する）に任せ、
//! ここは `HvVcpu` をそのレジスタ口として渡すだけの薄い層にする。0 以外の write は `Unimplemented` で止める。
//!
//! # 未実装（REPAIR-3）
//! - OS Lock の状態は持たない（ロックを掛ける write は止める）。read・他のレジスタは `run_loop_exit` が止める。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::SysRegAccess;
use crate::hvf_abi::{HvReg, HvVcpuExitException};
use crate::hvf_loop::ExitAction;
use crate::sys::HvVcpu;
use crate::sysreg_os_lock::{SysRegRegs, apply_os_lock_write};

impl SysRegRegs for HvVcpu<'_> {
    fn read_gpr(&mut self, n: u8) -> Result<u64, MicrovmError> {
        let reg = HvReg::x(n)
            .ok_or_else(|| MicrovmError::new(MicrovmErrorCode::Internal, "invalid Rt"))?;
        self.get_reg(reg)
    }

    fn read_pc(&mut self) -> Result<u64, MicrovmError> {
        self.get_reg(HvReg::PC)
    }

    fn write_pc(&mut self, pc: u64) -> Result<(), MicrovmError> {
        self.set_reg(HvReg::PC, pc)
    }
}

/// OS Lock の write を処理する。値が 0 なら PC を命令長だけ進めて続行し、0 以外は `Unimplemented`。
pub fn handle_sysreg(
    vcpu: &mut HvVcpu<'_>,
    access: &SysRegAccess,
    exception: &HvVcpuExitException,
) -> Result<ExitAction, MicrovmError> {
    apply_os_lock_write(vcpu, access, exception.syndrome)?;
    Ok(ExitAction::Continue)
}
