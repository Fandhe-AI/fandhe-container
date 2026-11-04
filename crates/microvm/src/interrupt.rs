//! virtio デバイスの割り込み通知の OS 非依存部分（TASK-74.2.3・MVM-1。`unsafe` なし・全 OS でビルドする）。
//!
//! 呼び出し文脈: ゲストの `QueueNotify` を受けた側（Linux では `crate::irq` の ioeventfd、それ以外では
//! `crate::dispatch` の MMIO exit）が [`complete_block_notify`]（virtio-net は [`complete_net_notify`]）を呼び、virtqueue の処理結果に応じて
//! [`InterruptLine::trigger`] でゲストへ割り込みを 1 回注入する。Linux の [`InterruptLine`] 実装は
//! `crate::irq::IrqFd`（`KVM_IRQFD`）、macOS は `crate::hvf::gic::GicSpiLine`（`hv_gic_set_spi`。#3795）、試験では回数を数える偽物を使う。virtio-net（TASK-74.3.2・#881）も
//! [`InterruptLine`] と [`IoEventSpec`] を使い回し、`QueueNotify` のキュー番号で振り分ける [`complete_net_notify`] を持つ。
//!
//! 待ち（ブロック）は持たない同期処理のため REPAIR-5 のタイムアウトは不要。割り込みの既定は edge 扱い。
//!
//! # level 扱いの SPI（#3863・MVM-5・MVM-1）
//! macOS の `hv_gic_set_spi(intid, level)` は level 形の API のため、FDT の trigger を level-high にする構成では
//! ゲストの `InterruptACK` の書き込み（virtio-mmio の `InterruptStatus` は読み取りで消えない。VIRTIO 1.2 4.2.2）の後に
//! 線を下げる（deassert）か、要因が残っていれば上げ直す（resample）必要がある。その判断を [`InterruptLine::resample`] と
//! [`complete_interrupt_ack`] に置く。ACK 後の線の値は、トランスポートの lock の下で読んだ `interrupt_status != 0` で決める
//! （線ごとの状態は持たない）。Linux の KVM の resamplefd（`KVM_IRQFD_FLAG_RESAMPLE`）による level の再注入は未実装
//! （`IrqFd` は edge のまま。REPAIR-3）。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestMemory, GuestMemoryBacking};
use crate::virtio_block::{BlockBackend, BlockQueueStats, VirtioBlock};
use crate::virtio_mmio::{DeviceStatus, InterruptReason, VirtioMmioTransport, reg};
use crate::virtio_net::{NetBackend, NetRxStats, NetTxStats, VirtioNet};

/// 割り込み線の注入方式（FDT の `interrupts` の trigger 種別と一致させる。照合は `arm64_layout` の `check_virtio_spi_injection`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IrqTrigger {
    /// edge-rising。`trigger` で 1 回起こすだけで、ACK 後の操作は要らない。
    EdgeRising,
    /// level-high。`trigger` で線を上げ、ACK 後に [`InterruptLine::resample`] で下げる（要因が残れば上げ直す）。
    LevelHigh,
}

/// [`InterruptLine::resample`] が線に対して行ったこと（REPAIR-4: 真偽値にしない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LineResample {
    /// edge 扱いの線、または resample を持たない線。何もしていない。
    NotApplicable,
    /// 要因が無くなったため線を下げた（deassert）。
    Deasserted,
    /// 要因が残っているため線を上げたままにした（上げ直した）。
    Reasserted,
}

/// ゲストへの割り込み 1 回分の注入口。
pub trait InterruptLine {
    /// 割り込みを 1 回注入する（level 扱いでは線を上げる）。失敗はホスト側の問題（ゲストの入力では起きない）。
    fn trigger(&self) -> Result<(), MicrovmError>;

    /// この線の注入方式。既定は edge（Linux の `IrqFd` と試験の偽物）。
    fn injection(&self) -> IrqTrigger {
        IrqTrigger::EdgeRising
    }

    /// `InterruptACK` の後に線の値を要因の残りに合わせる。`pending` は ACK 後に `interrupt_status != 0` か。
    /// 既定は何もしない（edge）。level 扱いの実装は `pending == false` で下げ、`true` で上げ直す。
    fn resample(&self, _pending: bool) -> Result<LineResample, MicrovmError> {
        Ok(LineResample::NotApplicable)
    }
}

/// [`complete_interrupt_ack`] の結果（REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptAckReport {
    /// ACK 後に残っている `interrupt_status`。
    pub remaining: u32,
    /// 線に対して行ったこと。
    pub resample: LineResample,
}

/// ゲストの `InterruptACK` を処理した後に、線の値を `interrupt_status` に合わせる（#3863・MVM-5・MVM-1）。
///
/// 呼び出し元は MMIO exit が `MmioWriteOutcome::InterruptAcknowledged` を返したとき（macOS では `hvf::mmio`）で、
/// `transport` の lock を持った状態で呼ぶ（デバイスの完了通知と ACK の競合で割り込みを取りこぼさないため）。
/// [`complete_block_notify`] と対になる。待ちは持たない（REPAIR-5 不要）。失敗は線の失敗だけ。
pub fn complete_interrupt_ack<D: crate::virtio_mmio::VirtioDevice>(
    transport: &VirtioMmioTransport<D>,
    line: &dyn InterruptLine,
) -> Result<InterruptAckReport, MicrovmError> {
    let remaining = transport.interrupt_status();
    let resample = line.resample(remaining != 0)?;
    Ok(InterruptAckReport {
        remaining,
        resample,
    })
}

/// `InterruptACK` の後処理の口（MMIO exit 側が dispatcher の lock を解放した後に呼ぶ）。
pub trait InterruptAckRoute: Send + Sync + std::fmt::Debug {
    /// トランスポートの lock を取って [`complete_interrupt_ack`] を呼ぶ。
    fn on_interrupt_ack(&self) -> Result<InterruptAckReport, MicrovmError>;
}

/// 共有トランスポートと割り込み線を束ねた [`InterruptAckRoute`]（macOS の `HvfDeviceBus` が 1 台ごとに作る）。
#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
// Linux の本番経路（edge の `IrqFd`）は ACK の後処理を持たず、使うのは macOS と試験だけ。
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(crate) struct BoundAckRoute<D: crate::virtio_mmio::VirtioDevice, L> {
    pub(crate) transport: std::sync::Arc<std::sync::Mutex<VirtioMmioTransport<D>>>,
    pub(crate) line: L,
}

#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
impl<D: crate::virtio_mmio::VirtioDevice, L> std::fmt::Debug for BoundAckRoute<D, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundAckRoute").finish_non_exhaustive()
    }
}

#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
impl<D, L> InterruptAckRoute for BoundAckRoute<D, L>
where
    D: crate::virtio_mmio::VirtioDevice + Send,
    L: InterruptLine + Send + Sync,
{
    fn on_interrupt_ack(&self) -> Result<InterruptAckReport, MicrovmError> {
        let t = self.transport.lock().map_err(|_| {
            MicrovmError::new(MicrovmErrorCode::Internal, "virtio transport lock poisoned")
        })?;
        complete_interrupt_ack(&t, &self.line)
    }
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
///
/// 残余: `trigger` が失敗すると外側の `Err` だけを返し、処理済みの `stats` は呼び出し元へ渡らない。
/// その時点で `interrupt_status` の `UsedBuffer` は立ったままだが、ゲストへの再通知は行われない
/// （次の `QueueNotify` か `InterruptACK` の読み取りで回復しうる）。`IrqFd::trigger` は eventfd 書き込みで
/// 失敗は稀なため、現状はエラーに `stats` を含めない（MVM-1）。
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

/// virtio-net の 1 キュー分の処理内訳（キュー番号で受信 / 送信を区別する。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetQueueStats {
    /// receiveq（キュー 0）の `process_rx` の内訳。
    Rx(NetRxStats),
    /// transmitq（キュー 1）の `process_tx` の内訳。
    Tx(NetTxStats),
    /// 範囲外のキュー番号（ゲストの入力）。何も処理していない。
    Unknown {
        /// ゲストが指定したキュー番号。
        queue: u16,
    },
}

impl NetQueueStats {
    /// used へ返した数（`Unknown` は 0）。
    pub fn completed(&self) -> u32 {
        match self {
            Self::Rx(s) => s.completed,
            Self::Tx(s) => s.completed,
            Self::Unknown { .. } => 0,
        }
    }
}

/// [`complete_net_notify`] の結果（REPAIR-4: 真偽値にしない。意味は [`BlockNotifyReport`] と同じ）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetNotifyReport {
    /// 今回の処理内訳（エラー終了でもそれまでの分）。
    pub stats: NetQueueStats,
    /// 割り込みを注入したか。
    pub delivery: InterruptDelivery,
    /// リング破損・範囲外のキュー番号など（ゲスト起因）。割り込み線の失敗は外側の `Err` で返す。
    pub queue_error: Option<MicrovmError>,
}

/// virtio-net で `QueueNotify(queue)` を受けた後の処理（TASK-74.3.2・#881・MVM-1）。
///
/// 呼び出し文脈: ioeventfd か MMIO exit が返す `MmioWriteOutcome::QueueNotify(i)` の `i` を `queue` に渡す。
/// backend にフレームが届いたとき（ゲストの kick なし）は呼び出し元が `queue = 0` で呼ぶ。
/// 0 は `process_rx`、1 は `process_tx`、それ以外はゲストの入力として `queue_error`（`InvalidArgument`）で返し、
/// トランスポートにも割り込み線にも触れない。完了が 1 件以上なら `UsedBuffer` を立てて割り込みを 1 回注入する。
/// virtio-mmio の割り込み線はデバイスに 1 本で、2 つのキューは同じ `line`（同じ GSI）を共有する。
///
/// `process_*` が `Err` でも、それまでに used へ返した分（`*_stats_before_error`）があれば割り込みを上げる。
/// 停止・リセットの判断は呼び出し元に残す。外側の `Err` は割り込み線の失敗だけ。待ちは持たない（REPAIR-5 不要）。
///
/// 残余（[`complete_block_notify`] と同じ。REPAIR-3）: `trigger` が失敗すると外側の `Err` だけを返し、
/// 処理済みの `stats` は呼び出し元へ渡らない。`interrupt_status` の `UsedBuffer` は立ったまま残る。
pub fn complete_net_notify<B: NetBackend, M: GuestMemoryBacking>(
    transport: &mut VirtioMmioTransport<VirtioNet<B>>,
    mem: &mut GuestMemory<M>,
    queue: u16,
    line: &dyn InterruptLine,
) -> Result<NetNotifyReport, MicrovmError> {
    let (stats, queue_error) = match queue {
        0 => match transport.device_mut().process_rx(mem) {
            Ok(s) => (NetQueueStats::Rx(s), None),
            Err(e) => (
                NetQueueStats::Rx(transport.device().rx_stats_before_error()),
                Some(e),
            ),
        },
        1 => match transport.device_mut().process_tx(mem) {
            Ok(s) => (NetQueueStats::Tx(s), None),
            Err(e) => (
                NetQueueStats::Tx(transport.device().tx_stats_before_error()),
                Some(e),
            ),
        },
        other => (
            NetQueueStats::Unknown { queue: other },
            Some(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "net queue index out of range",
            )),
        ),
    };
    let delivery = if stats.completed() >= 1 {
        transport.raise_interrupt(InterruptReason::UsedBuffer);
        line.trigger()?;
        InterruptDelivery::Triggered
    } else {
        InterruptDelivery::NotNeeded
    };
    Ok(NetNotifyReport {
        stats,
        delivery,
        queue_error,
    })
}

/// [`poll_net_rx`] が `process_rx` を呼ばなかった理由（REPAIR-4: 真偽値にしない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetRxPollSkip {
    /// `DRIVER_OK` が立っていない（ゲストのドライバが未初期化。activate 前）。
    NotActive,
    /// `FAILED` か `DEVICE_NEEDS_RESET` が立っている。異常状態のデバイスへは書き込まない。
    DeviceFailed,
    /// receiveq（キュー 0）が無いか、`ready` でない（ゲストが止めた）。
    QueueNotReady,
}

/// [`poll_net_rx`] の結果（REPAIR-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetRxPollOutcome {
    /// 処理しなかった。ゲストの状態が整うまで backend のフレームは backend 側に残る。
    Skipped(NetRxPollSkip),
    /// `process_rx` を呼んだ。内訳は [`complete_net_notify`] と同じ。
    Polled(NetNotifyReport),
}

/// ゲストの kick なしで virtio-net の受信を 1 回処理する（#3742・MVM-1・REPAIR-5）。
///
/// 呼び出し元は受信ポーラー（Linux では `microvm` の `NetRxPoller`。期限ごとに呼ぶ）。kick 経路と同じ lock の下で直列に呼ぶ前提。
/// 先にトランスポートの状態を確かめ、ドライバ未初期化（`DRIVER_OK` なし）・`FAILED` / `DEVICE_NEEDS_RESET`・receiveq が
/// ready でないときは `process_rx` を呼ばず [`NetRxPollOutcome::Skipped`] を返す。activate 前の `process_rx` は
/// `FailedPrecondition` を返し、ポーラーがそれを異常として拾うとゲストが virtio_net を読み込む前に VM が止まるため。
/// 有効なら [`complete_net_notify`] を `queue = 0` で呼ぶ（完了が 1 件以上のときだけ割り込みを 1 回注入する）。
/// リング破損は内訳の `queue_error`、割り込み線の失敗は外側の `Err` に入る。待ちは持たない。
pub fn poll_net_rx<B: NetBackend, M: GuestMemoryBacking>(
    transport: &mut VirtioMmioTransport<VirtioNet<B>>,
    mem: &mut GuestMemory<M>,
    line: &dyn InterruptLine,
) -> Result<NetRxPollOutcome, MicrovmError> {
    let status = transport.status();
    if status.contains(DeviceStatus::FAILED) || status.contains(DeviceStatus::DEVICE_NEEDS_RESET) {
        return Ok(NetRxPollOutcome::Skipped(NetRxPollSkip::DeviceFailed));
    }
    if !status.contains(DeviceStatus::DRIVER_OK) {
        return Ok(NetRxPollOutcome::Skipped(NetRxPollSkip::NotActive));
    }
    if !transport.queue(0).is_some_and(|q| q.ready()) {
        return Ok(NetRxPollOutcome::Skipped(NetRxPollSkip::QueueNotReady));
    }
    complete_net_notify(transport, mem, 0, line).map(NetRxPollOutcome::Polled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spi::SpiLine;
    use crate::spi::tests::RecordingGic;
    use crate::virtio_block::{MemoryBlockBackend, VirtioBlock};
    use crate::virtio_mmio::MmioWriteOutcome;

    fn block_transport() -> VirtioMmioTransport<VirtioBlock<MemoryBlockBackend>> {
        VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap()
    }

    /// MVM-5・MVM-1（#3863）: assert → ACK → deassert の呼び出し列が `(intid, level)` で具体値になる。
    #[test]
    fn mvm5_3863_transport_ack_drives_level_deassert() {
        let gic = RecordingGic::default();
        let line = SpiLine::new(gic.clone(), 48, IrqTrigger::LevelHigh);
        let mut t = block_transport();
        t.raise_interrupt(InterruptReason::UsedBuffer);
        line.trigger().unwrap();
        let out = t.write(reg::INTERRUPT_ACK, &1u32.to_le_bytes());
        assert_eq!(out, MmioWriteOutcome::InterruptAcknowledged);
        let r = complete_interrupt_ack(&t, &line).unwrap();
        assert_eq!(
            r,
            InterruptAckReport {
                remaining: 0,
                resample: LineResample::Deasserted
            }
        );
        assert_eq!(gic.calls(), vec![(48, true), (48, false)]);
    }

    /// 部分 ACK で要因が残れば線を上げ直す。
    #[test]
    fn mvm5_3863_transport_partial_ack_reasserts() {
        let gic = RecordingGic::default();
        let line = SpiLine::new(gic.clone(), 48, IrqTrigger::LevelHigh);
        let mut t = block_transport();
        t.raise_interrupt(InterruptReason::UsedBuffer);
        t.raise_interrupt(InterruptReason::ConfigChange);
        line.trigger().unwrap();
        t.write(reg::INTERRUPT_ACK, &1u32.to_le_bytes());
        let r = complete_interrupt_ack(&t, &line).unwrap();
        assert_eq!(r.remaining, 2);
        assert_eq!(r.resample, LineResample::Reasserted);
        assert_eq!(gic.calls(), vec![(48, true), (48, true)]);
    }

    /// edge の線は ACK で何も呼ばない。
    #[test]
    fn mvm5_3863_edge_line_ack_is_noop() {
        let gic = RecordingGic::default();
        let line = SpiLine::new(gic.clone(), 48, IrqTrigger::EdgeRising);
        let mut t = block_transport();
        t.raise_interrupt(InterruptReason::UsedBuffer);
        line.trigger().unwrap();
        t.write(reg::INTERRUPT_ACK, &1u32.to_le_bytes());
        let r = complete_interrupt_ack(&t, &line).unwrap();
        assert_eq!(r.resample, LineResample::NotApplicable);
        assert_eq!(gic.calls(), vec![(48, true)]);
    }

    /// dispatcher 経由の ACK exit が `InterruptAcknowledged` を返し、`BoundAckRoute` で deassert される。
    #[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
    #[test]
    fn mvm5_3863_bound_ack_route_deasserts() {
        use crate::dispatch::{DispatchOutcome, ExitDispatcher, MmioAccess};
        use crate::exit::VcpuExit;
        use crate::virtio_mmio::SharedTransport;
        use std::sync::{Arc, Mutex};

        let gic = RecordingGic::default();
        let line = SpiLine::new(gic.clone(), 48, IrqTrigger::LevelHigh);
        let transport = Arc::new(Mutex::new(block_transport()));
        let mut d = ExitDispatcher::new();
        d.register_mmio(
            0x0a00_0000,
            0x200,
            Box::new(SharedTransport(Arc::clone(&transport))),
        )
        .unwrap();
        transport
            .lock()
            .unwrap()
            .raise_interrupt(InterruptReason::UsedBuffer);
        line.trigger().unwrap();
        let mut data = [0u8; 8];
        data[..4].copy_from_slice(&1u32.to_le_bytes());
        let out = d
            .dispatch(&VcpuExit::Mmio {
                phys_addr: 0x0a00_0000 + reg::INTERRUPT_ACK,
                data,
                len: 4,
                is_write: true,
            })
            .unwrap();
        assert!(matches!(
            out,
            DispatchOutcome::Mmio {
                access: MmioAccess::Write(MmioWriteOutcome::InterruptAcknowledged),
                ..
            }
        ));
        let route = BoundAckRoute { transport, line };
        let r = route.on_interrupt_ack().unwrap();
        assert_eq!(r.resample, LineResample::Deasserted);
        assert_eq!(gic.calls(), vec![(48, true), (48, false)]);
    }

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
