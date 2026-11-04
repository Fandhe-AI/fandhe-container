//! HVC / SMC の exit 処理（スタブ。TASK-192.9・#3791・MVM-5・MVM-1・REPAIR-3）。
//!
//! 役割: `hvf::vcpu` の実行ループが分類した HVC / SMC を、PSCI 等の処理へ振り分ける入口。シグネチャは `hvf::vcpu` との契約で、
//! 担当 issue（#3794）が `vcpu.rs` に触れず本ファイルだけを差し替える。現状は `Unimplemented` を返し、ループは VM を止める。
//!
//! # 将来仕様（#3794）
//! PSCI（VERSION・CPU_ON・SYSTEM_OFF 等）を処理する。SYSTEM_OFF は `ExitAction::Stop(StopReason::GuestShutdown)` を返す。
//! PC を進める責務はここにある（HVC の優先戻り先は次の命令、HCR_EL2.TSC で trap した SMC は SMC 命令自身。esr.rs の要確認事項を
//! Arm ARM で再確認する）。未知の関数 ID は PSCI の NOT_SUPPORTED を返し、推測で成功にしない。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_abi::HvVcpuExitException;
use crate::hvf_loop::ExitAction;
use crate::sys::HvVcpu;

/// HVC / SMC ハンドラの状態（PSCI の電源状態等。#3794 が持たせる）。
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

fn unimplemented(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Unimplemented, msg)
}

/// HVC を処理する（スタブ）。常に `Unimplemented`。
pub fn handle_hvc(
    _vcpu: &mut HvVcpu<'_>,
    _handler: &mut HvcHandler,
    _imm16: u16,
    _exception: &HvVcpuExitException,
) -> Result<ExitAction, MicrovmError> {
    Err(unimplemented("hvc exit handling is not implemented"))
}

/// SMC を処理する（スタブ）。常に `Unimplemented`。
pub fn handle_smc(
    _vcpu: &mut HvVcpu<'_>,
    _handler: &mut HvcHandler,
    _imm16: u16,
    _exception: &HvVcpuExitException,
) -> Result<ExitAction, MicrovmError> {
    Err(unimplemented("smc exit handling is not implemented"))
}
