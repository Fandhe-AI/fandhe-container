//! MMIO（ISV=1 の data abort）の exit 処理（TASK-192.10・#3793・MVM-5・MVM-1・MVM-4）。
//!
//! 役割: `hvf::vcpu` の実行ループが分類した data abort を、Linux 版と共有する `ExitDispatcher`（virtio-mmio の
//! デバイスモデル）へ渡す入口。復号済みの [`DataAbort`] と IPA から `VcpuExit::Mmio` を作り（変換規則は OS 非依存の
//! `crate::mmio_abort`）、読み出しの応答を `SRT` の汎用レジスタへ書き戻し、PC を進める。
//! シグネチャは `hvf::vcpu` との契約で変えない。
//!
//! # 契約
//! - PC を進める責務はここにある（data abort は faulting 命令自身を指すため、ESR の IL の分だけ進める）。
//! - どのデバイスにも当たらないアクセスは Linux 版と同じく続行する（読み出しは全バイト 0xFF、書き込みは捨てる）。
//!   旧スタブの doc の「窓の外は `Failed` で止める」は #3793 の要件で上書きした。回数は [`MmioHandler::unhandled_count`] で観測する。
//! - stage 1 のページテーブル引き中の fault（`s1ptw`）と translation fault 以外（permission fault 等）は MMIO として扱わず
//!   fail-closed で止める（`mmio_abort::ensure_mmio_fault`）。
//! - ゲスト由来のアドレス・値は信頼しない。長さは SAS で 1..=8 に限られ、dispatcher も再検査する。
//!
//! # 要確認（実機で未観測。結果の記録は #3803）
//! - Hypervisor.framework は例外 exit で PC を自動では進めない、という前提を置いている（第三者実装からの読み）。
//! - `HvVcpuExitException.physical_address` は下位ビットを含む完全な IPA である、という前提を置いている。
//!
//! # 未実装（REPAIR-3）
//! - virtqueue の処理と割り込みへの結線（`QueueNotify` の後続）は #3797（macOS の構成体の組み立て）の担当。
//!   ここでは通知を捨てず [`MmioHandler::last_queue_notify`] に残すだけで、実際のキュー処理は行わない。
//! - ゲストが big-endian（`SCTLR_EL1.EE` / `E0E`）の場合は扱わない（little-endian 固定）。

use crate::dispatch::{DeviceId, DispatchOutcome, ExitDispatcher, MmioAccess};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::{AccessDirection, DataAbort};
use crate::hvf_abi::{HvReg, HvVcpuExitException};
use crate::hvf_loop::ExitAction;
use crate::mmio_abort;
use crate::sys::HvVcpu;
use crate::virtio_mmio::MmioWriteOutcome;

/// MMIO ハンドラの状態（デバイスバスと観測用の計数）。
#[derive(Debug, Default)]
pub struct MmioHandler {
    dispatcher: ExitDispatcher,
    unhandled: u64,
    queue_notifies: u64,
    last_queue_notify: Option<(DeviceId, u16)>,
}

impl MmioHandler {
    /// デバイス未登録のハンドラを作る（全アクセスが未登録として扱われる）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 登録済みの dispatcher を持つハンドラを作る。
    pub fn with_dispatcher(dispatcher: ExitDispatcher) -> Self {
        Self {
            dispatcher,
            ..Self::default()
        }
    }

    /// デバイスの登録用に dispatcher を借りる。
    pub fn dispatcher_mut(&mut self) -> &mut ExitDispatcher {
        &mut self.dispatcher
    }

    /// どのデバイスにも当たらなかったアクセスの回数（REPAIR-4）。
    pub fn unhandled_count(&self) -> u64 {
        self.unhandled
    }

    /// `QueueNotify` を受けた回数（処理は #3797 の担当。REPAIR-3）。
    pub fn queue_notify_count(&self) -> u64 {
        self.queue_notifies
    }

    /// 最後に受けた `QueueNotify`（デバイスとキュー番号）。
    pub fn last_queue_notify(&self) -> Option<(DeviceId, u16)> {
        self.last_queue_notify
    }
}

fn internal(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, msg)
}

/// data abort を処理する。MMIO を dispatcher へ渡し、読み出しなら応答を `SRT` へ書き、PC を進めて続行する。
pub fn handle_data_abort(
    vcpu: &mut HvVcpu<'_>,
    handler: &mut MmioHandler,
    abort: &DataAbort,
    exception: &HvVcpuExitException,
) -> Result<ExitAction, MicrovmError> {
    mmio_abort::ensure_mmio_fault(abort)?;

    let write_value = if abort.direction == AccessDirection::Write {
        if abort.register.is_zero_register() {
            mmio_abort::write_source_value(abort, None)
        } else {
            let reg = HvReg::x(abort.register.get()).ok_or_else(|| internal("invalid SRT"))?;
            mmio_abort::write_source_value(abort, Some(vcpu.get_reg(reg)?))
        }
    } else {
        0
    };

    let exit = mmio_abort::mmio_exit_from_abort(abort, exception.physical_address, write_value);
    let outcome = handler.dispatcher.dispatch(&exit)?;
    match &outcome {
        DispatchOutcome::Mmio {
            device,
            access: MmioAccess::Write(MmioWriteOutcome::QueueNotify(q)),
        } => {
            handler.queue_notifies = handler.queue_notifies.saturating_add(1);
            handler.last_queue_notify = Some((*device, *q));
        }
        DispatchOutcome::Unhandled { .. } => {
            handler.unhandled = handler.unhandled.saturating_add(1);
        }
        _ => {}
    }

    if abort.direction == AccessDirection::Read {
        let resp = outcome
            .read_response()
            .ok_or_else(|| internal("mmio read produced no response"))?;
        if let Some(v) = mmio_abort::read_register_value(abort, resp)? {
            let reg = HvReg::x(abort.register.get()).ok_or_else(|| internal("invalid SRT"))?;
            vcpu.set_reg(reg, v)?;
        }
    }

    let pc = vcpu.get_reg(HvReg::PC)?;
    vcpu.set_reg(HvReg::PC, mmio_abort::next_pc(pc, exception.syndrome)?)?;
    Ok(ExitAction::Continue)
}
