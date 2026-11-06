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
//!   実装前（#3791 時点）の doc の「窓の外は `Failed` で止める」は #3793 の要件で上書きした。回数は [`MmioHandler::unhandled_count`] で観測する。
//! - stage 1 のページテーブル引き中の fault（`s1ptw`）と translation fault 以外（permission fault 等）は MMIO として扱わず
//!   fail-closed で止める（`mmio_abort::ensure_mmio_fault`）。
//! - ゲスト由来のアドレス・値は信頼しない。長さは SAS で 1..=8 に限られ、dispatcher も再検査する。
//!
//! # 実機で確かめた前提（#3803）
//! - Hypervisor.framework は例外 exit で PC を自動では進めない。data abort の exit 時点の PC は faulting 命令を指していた。
//! - `HvVcpuExitException.physical_address` は下位ビットを含む完全な IPA である。窓 + 4 への書き込みの exit で確かめた
//!   （`hvf_device_spi_reaches_guest` の準備完了の書き込み）。
//!
//! # 未実装（REPAIR-3）
//! - `InterruptACK` の後処理（level 扱いの SPI の deassert / resample。#3863）は [`MmioHandler::with_ack_routes`] で結ぶ。
//!   route の無いデバイスは回数（[`MmioHandler::interrupt_ack_count`]）だけ数えて続行する。
//! - `InterruptACK` を処理した vCPU はその線の SPI の宛先として [`MmioHandler::with_ack_learner`] で記録し、WFI の待ちを
//!   宛先の vCPU だけ起こすのに使う（#3948・MVM-5・REPAIR-5。方式と残余は `crate::hvf_wake`）。
//! - virtqueue の処理と割り込みへの結線（`QueueNotify` の後続）は #3908 の担当。
//!   ここでは通知を捨てず [`MmioHandler::last_queue_notify`] に残すだけで、実際のキュー処理は行わない。
//! - ゲストが big-endian（`SCTLR_EL1.EE` / `E0E`）の場合は扱わない（little-endian 固定）。

use crate::dispatch::{DeviceId, DispatchOutcome, ExitDispatcher, MmioAccess};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::{AccessDirection, DataAbort};
use crate::hvf_abi::{HvReg, HvVcpuExitException};
use crate::hvf_loop::ExitAction;
use crate::hvf_wake::AckRouteLearner;
use crate::interrupt::InterruptAckRoute;
use crate::mmio_abort;
use crate::sys::HvVcpu;
use crate::virtio_mmio::MmioWriteOutcome;
use std::sync::{Arc, Mutex};

/// MMIO ハンドラの状態（デバイスバスと観測用の計数）。
#[derive(Debug, Default)]
pub struct MmioHandler {
    dispatcher: Arc<Mutex<ExitDispatcher>>,
    unhandled: u64,
    queue_notifies: u64,
    last_queue_notify: Option<(DeviceId, u16)>,
    /// `InterruptACK` の後処理（level 扱いの線の deassert / resample。#3863）。route の無いデバイスは計数だけ。
    ack_routes: Vec<(DeviceId, Arc<dyn InterruptAckRoute>)>,
    interrupt_acks: u64,
    /// `InterruptACK` を処理したこの vCPU を、その線の SPI の宛先として記録する（WFI の宛先指定の起床。#3948）。無ければ学習しない。
    learner: Option<AckRouteLearner<DeviceId>>,
}

impl MmioHandler {
    /// デバイス未登録のハンドラを作る（全アクセスが未登録として扱われる）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 登録済みの dispatcher を持つハンドラを作る。
    pub fn with_dispatcher(dispatcher: ExitDispatcher) -> Self {
        Self::with_shared_dispatcher(Arc::new(Mutex::new(dispatcher)))
    }

    /// 組み立て済み VM が持つ共有 dispatcher（`HvfMicroVm::dispatcher`）を使うハンドラを作る（#3793）。
    pub fn with_shared_dispatcher(dispatcher: Arc<Mutex<ExitDispatcher>>) -> Self {
        Self {
            dispatcher,
            ..Self::default()
        }
    }

    /// デバイスごとの `InterruptACK` の後処理を足す（#3863・MVM-5）。
    pub fn with_ack_routes(mut self, routes: Vec<(DeviceId, Arc<dyn InterruptAckRoute>)>) -> Self {
        self.ack_routes = routes;
        self
    }

    /// `InterruptACK` を処理した vCPU を宛先として学習する部品を足す（#3948・MVM-5・REPAIR-5）。
    /// 学習は `InterruptAcknowledged` だけで、`DeviceReset` では行わない。
    pub fn with_ack_learner(mut self, learner: AckRouteLearner<DeviceId>) -> Self {
        self.learner = Some(learner);
        self
    }

    /// `InterruptACK` を受けた回数（#3863）。
    pub fn interrupt_ack_count(&self) -> u64 {
        self.interrupt_acks
    }

    /// 共有 dispatcher のハンドル（デバイスの追加登録用）。
    pub fn dispatcher(&self) -> &Arc<Mutex<ExitDispatcher>> {
        &self.dispatcher
    }

    /// どのデバイスにも当たらなかったアクセスの回数（REPAIR-4）。
    pub fn unhandled_count(&self) -> u64 {
        self.unhandled
    }

    /// `QueueNotify` を受けた回数（処理は #3908 の担当。REPAIR-3）。
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
    // dispatcher の lock はこの式の終わりで解放する（ACK の後処理でトランスポートの lock を取るため、同時保持しない）。
    let outcome = handler
        .dispatcher
        .lock()
        .map_err(|_| internal("mmio dispatcher lock poisoned"))?
        .dispatch(&exit)?;
    match &outcome {
        DispatchOutcome::Mmio {
            device,
            access: MmioAccess::Write(MmioWriteOutcome::InterruptAcknowledged),
        } => {
            handler.interrupt_acks = handler.interrupt_acks.saturating_add(1);
            // この vCPU がその線の割り込みを処理した = 宛先のヒント（#3948）。後処理の失敗とは独立に記録する。
            if let Some(l) = &handler.learner {
                l.on_interrupt_ack(device);
            }
            // 失敗は VM を止める（fail-closed。trigger の失敗と同じ扱い）。
            if let Some((_, route)) = handler.ack_routes.iter().find(|(id, _)| id == device) {
                route.on_interrupt_ack()?;
            }
        }
        // Status=0 のリセットは `interrupt_status` を 0 にするため、level 線が上がったままにならないよう
        // ACK と同じ後処理（resample）を呼ぶ（MVM-5。ACK 数の計数には含めない）。
        DispatchOutcome::Mmio {
            device,
            access: MmioAccess::Write(MmioWriteOutcome::DeviceReset),
        } => {
            if let Some((_, route)) = handler.ack_routes.iter().find(|(id, _)| id == device) {
                route.on_interrupt_ack()?;
            }
        }
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

#[cfg(test)]
mod tests {
    //! macOS かつ aarch64 のネイティブでだけ走る（`hv_*` は呼ばない）。MVM-5・MVM-1・REPAIR-3・REPAIR-12。
    use super::*;
    use crate::virtio_block::{MemoryBlockBackend, VirtioBlock};
    use crate::virtio_mmio::VirtioMmioTransport;

    /// ACK の route はデバイスの識別子で引かれ、保持される（#3863）。`hv_*` を呼ばないため vCPU の経路は別途実機で確かめる（#4015）。
    #[test]
    fn mvm5_3863_ack_routes_are_kept() {
        use crate::interrupt::{InterruptAckReport, LineResample};
        #[derive(Debug)]
        struct Fake;
        impl InterruptAckRoute for Fake {
            fn on_interrupt_ack(&self) -> Result<InterruptAckReport, MicrovmError> {
                Ok(InterruptAckReport {
                    remaining: 0,
                    resample: LineResample::Deasserted,
                })
            }
        }
        let mut d = ExitDispatcher::new();
        let block = VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap();
        let id = d
            .register_mmio(0x0a00_0000, 0x200, Box::new(block))
            .unwrap();
        let h = MmioHandler::with_dispatcher(d).with_ack_routes(vec![(id, Arc::new(Fake))]);
        assert_eq!(h.interrupt_ack_count(), 0);
        assert_eq!(h.ack_routes.len(), 1);
    }

    /// 共有の dispatcher へ後から登録したデバイスが、ハンドラ側から見える（同じ実体を指す）。
    #[test]
    fn mvm5_shared_dispatcher_is_same_instance() {
        let shared = Arc::new(Mutex::new(ExitDispatcher::new()));
        let handler = MmioHandler::with_shared_dispatcher(Arc::clone(&shared));
        assert!(Arc::ptr_eq(handler.dispatcher(), &shared));
        assert_eq!(Arc::strong_count(&shared), 2);
        let block = VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap();
        shared
            .lock()
            .unwrap()
            .register_mmio(0x0a00_0000, 0x200, Box::new(block))
            .unwrap();
        // MagicValue（offset 0）がハンドラ経由の dispatcher から 0x7472_6976 で読める。
        let exit = crate::exit::VcpuExit::Mmio {
            phys_addr: 0x0a00_0000,
            data: [0; 8],
            len: 4,
            is_write: false,
        };
        let out = handler
            .dispatcher()
            .lock()
            .unwrap()
            .dispatch(&exit)
            .unwrap();
        assert_eq!(out.read_response(), Some(&0x7472_6976u32.to_le_bytes()[..]));
    }
}
