//! WFI / WFE と vtimer の exit 処理（スタブ。TASK-192.9・#3791・MVM-5・MVM-1・REPAIR-3）。
//!
//! 役割: `hvf::vcpu` の実行ループが分類した WF* と vtimer の発火を処理する入口。シグネチャは `hvf::vcpu` との契約で、担当 issue
//! （#3796）が `vcpu.rs` に触れず本ファイルだけを差し替える。現状は `Unimplemented` を返し、ループは VM を止める。
//!
//! # 将来仕様（#3796）
//! WFI は次の割り込み・vtimer 期限・停止要求のいずれかまで待つ。待ちは必ず期限つき（REPAIR-5）で、停止要求（kick）で戻る。
//! vtimer の発火はマスクを解除して GIC へ割り込みを注入する。PC を進める責務はここにある（WF* は命令自身を指すため
//! `esr::instruction_length` の分だけ進める）。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::WfxKind;
use crate::hvf_abi::HvVcpuExitException;
use crate::hvf_loop::ExitAction;
use crate::sys::HvVcpu;

/// WFI / vtimer ハンドラの状態（タイマー期限・割り込みコントローラ等。#3796 が持たせる）。
#[derive(Debug, Default)]
pub struct TimerHandler {
    _private: (),
}

impl TimerHandler {
    /// 空のハンドラを作る。
    pub fn new() -> Self {
        Self::default()
    }
}

fn unimplemented(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Unimplemented, msg)
}

/// WFI / WFE 系を処理する（スタブ）。常に `Unimplemented`。
pub fn handle_wfx(
    _vcpu: &mut HvVcpu<'_>,
    _handler: &mut TimerHandler,
    _kind: WfxKind,
    _exception: &HvVcpuExitException,
) -> Result<ExitAction, MicrovmError> {
    Err(unimplemented("wfx exit handling is not implemented"))
}

/// vtimer の発火を処理する（スタブ）。常に `Unimplemented`。
pub fn handle_vtimer(
    _vcpu: &mut HvVcpu<'_>,
    _handler: &mut TimerHandler,
) -> Result<ExitAction, MicrovmError> {
    Err(unimplemented("vtimer exit handling is not implemented"))
}
