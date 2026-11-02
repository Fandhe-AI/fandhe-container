//! virtio デバイスの割り込み通知の OS 非依存部分（TASK-74.2.3・MVM-1。`unsafe` なし・全 OS でビルドする）。
//!
//! 呼び出し文脈: ゲストの `QueueNotify` を受けた側（Linux では `crate::irq` の ioeventfd、それ以外では
//! `crate::dispatch` の MMIO exit）が [`complete_block_notify`] を呼び、virtqueue の処理結果に応じて
//! [`InterruptLine::trigger`] でゲストへ割り込みを 1 回注入する。Linux の [`InterruptLine`] 実装は
//! `crate::irq::IrqFd`（`KVM_IRQFD`）、試験では回数を数える偽物を使う。virtio-net（TASK-74.3.2）も
//! [`InterruptLine`] と [`IoEventSpec`] を使い回す。
//!
//! 待ち（ブロック）は持たない同期処理のため REPAIR-5 のタイムアウトは不要。割り込みは edge 扱いで、
//! resamplefd による level の再注入は未実装（TASK-75 で再検討。REPAIR-3）。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestMemory, GuestMemoryBacking};
use crate::virtio_block::{BlockBackend, BlockQueueStats, VirtioBlock};
use crate::virtio_mmio::{InterruptReason, VirtioMmioTransport, reg};

/// ゲストへの割り込み 1 回分の注入口。
pub trait InterruptLine {
    /// 割り込みを 1 回注入する。失敗はホスト側の問題（ゲストの入力では起きない）。
    fn trigger(&self) -> Result<(), MicrovmError>;
}

/// ioeventfd で監視するゲストの書き込み先。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoEventAddress {
    /// MMIO のゲスト物理アドレス。
    Mmio(u64),
    /// PIO のポート。
    Pio(u16),
}

/// ioeventfd の監視条件（検証済み）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoEventSpec {
    address: IoEventAddress,
    len: u32,
    datamatch: Option<u64>,
}

impl IoEventSpec {
    /// 条件を検証して作る。`len` は 1 / 2 / 4 / 8、`datamatch` は `len` のビット幅に収まること。
    pub fn new(
        address: IoEventAddress,
        len: u32,
        datamatch: Option<u64>,
    ) -> Result<Self, MicrovmError> {
        if !matches!(len, 1 | 2 | 4 | 8) {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "ioeventfd length must be 1, 2, 4 or 8",
            ));
        }
        if let Some(v) = datamatch {
            let fits = len == 8 || v >> (len * 8) == 0;
            if !fits {
                return Err(MicrovmError::new(
                    MicrovmErrorCode::InvalidArgument,
                    "ioeventfd datamatch does not fit the length",
                ));
            }
        }
        if let IoEventAddress::Pio(_) = address
            && len == 8
        {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "ioeventfd PIO length must be 1, 2 or 4",
            ));
        }
        Ok(Self {
            address,
            len,
            datamatch,
        })
    }

    /// virtio-mmio の `QueueNotify`（`base + 0x050`）へ `queue` が 4 バイトで書かれたときだけ発火する条件。
    pub fn virtio_mmio_queue_notify(base: u64, queue: u16) -> Result<Self, MicrovmError> {
        let addr = base.checked_add(reg::QUEUE_NOTIFY).ok_or_else(|| {
            MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "virtio-mmio base address overflows",
            )
        })?;
        Self::new(IoEventAddress::Mmio(addr), 4, Some(u64::from(queue)))
    }

    /// 監視するアドレス。
    pub fn address(&self) -> IoEventAddress {
        self.address
    }

    /// 書き込みの幅（バイト）。
    pub fn len(&self) -> u32 {
        self.len
    }

    /// 幅が 0 か（検証で 0 は拒否されるため常に `false`）。
    pub fn is_empty(&self) -> bool {
        false
    }

    /// 発火する値（`None` は任意の値）。
    pub fn datamatch(&self) -> Option<u64> {
        self.datamatch
    }
}

/// 割り込みを注入したか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptDelivery {
    /// 1 回以上の完了があり、割り込みを注入した。
    Triggered,
    /// 完了が 0 件で、注入しなかった。
    NotNeeded,
}

/// [`complete_block_notify`] の結果（REPAIR-4: 真偽値にしない）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockNotifyReport {
    /// 今回の処理内訳（エラー終了でもそれまでの分）。
    pub stats: BlockQueueStats,
    /// 割り込みを注入したか。
    pub delivery: InterruptDelivery,
    /// リング破損など virtqueue 処理の失敗（ゲスト起因）。割り込み線の失敗は外側の `Err` で返す。
    pub queue_error: Option<MicrovmError>,
}

/// `QueueNotify(0)` を受けた後の処理。requestq を処理し、完了が 1 件以上なら `UsedBuffer` を立てて
/// 割り込みを注入する。
///
/// `process_queue` が `Err` でも、それまでに used へ返した分（`stats_before_error`）があれば割り込みを上げる
/// （virtio_block.rs の契約）。停止・リセットの判断は呼び出し元に残す。外側の `Err` は割り込み線の失敗だけ。
pub fn complete_block_notify<B: BlockBackend, M: GuestMemoryBacking>(
    transport: &mut VirtioMmioTransport<VirtioBlock<B>>,
    mem: &mut GuestMemory<M>,
    line: &dyn InterruptLine,
) -> Result<BlockNotifyReport, MicrovmError> {
    let (stats, queue_error) = match transport.device_mut().process_queue(mem) {
        Ok(stats) => (stats, None),
        Err(e) => (transport.device().stats_before_error(), Some(e)),
    };
    let delivery = if stats.completed >= 1 {
        transport.raise_interrupt(InterruptReason::UsedBuffer);
        line.trigger()?;
        InterruptDelivery::Triggered
    } else {
        InterruptDelivery::NotNeeded
    };
    Ok(BlockNotifyReport {
        stats,
        delivery,
        queue_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mvm1_879_io_event_spec_table() {
        let mmio = IoEventAddress::Mmio(0x2050);
        for len in [0, 3, 16] {
            let e = IoEventSpec::new(mmio, len, None).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        }
        let e = IoEventSpec::new(mmio, 2, Some(0x1_0000)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert!(IoEventSpec::new(mmio, 2, Some(0xFFFF)).is_ok());
        assert!(IoEventSpec::new(mmio, 8, Some(u64::MAX)).is_ok());
        assert!(IoEventSpec::new(IoEventAddress::Pio(0x10), 8, None).is_err());
        let s = IoEventSpec::virtio_mmio_queue_notify(0x2000, 0).unwrap();
        assert_eq!(s.address(), IoEventAddress::Mmio(0x2050));
        assert_eq!((s.len(), s.datamatch()), (4, Some(0)));
        let e = IoEventSpec::virtio_mmio_queue_notify(u64::MAX, 0).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    }
}
