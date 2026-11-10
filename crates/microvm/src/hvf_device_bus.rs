//! macOS（HVF）microvm のデバイスバスの OS 非依存コア（MVM-5・MVM-1・REPAIR-1・#4293）。
//!
//! virtio-mmio のデバイス群とシリアル、それを引く `ExitDispatcher` を束ねる。割り込み線は
//! HVF の GIC から直接作らず、呼び出し側が渡す生成関数で作る。本番（`hvf::microvm` の
//! `HvfMicroVm::assemble`）は `VmWithGic::spi_line` / `serial_line` を渡し、試験は偽の GIC
//! （`spi::tests::RecordingGic`）の線を渡す。これで HVF なしでも（Linux の既定のテスト集合でも）
//! 本番と同じ登録順・注入方式の照合・route の組み立てを通せる。
//!
//! 線の生成関数の契約:
//!
//! - virtio の生成関数の引数 `index` は virtio の通し番号（block → net の順に 0 から）。
//!   窓（`layout.virtio_mmio_window(index)`）と同じ番号である。
//! - シリアルの生成関数は `layout.serial` が `Some` のときだけ、virtio の登録の後に 1 回呼ばれる。
//!
//! Linux では本番がこのバスを使わず、使うのは試験だけである（macOS aarch64 では本番と試験が使う）。
//! 公開 API は増やさない（`pub(crate)`）。`unsafe` は持たない。

use std::sync::{Arc, Mutex};

use crate::arm64_layout::{Arm64Layout, MmioRegion};
use crate::dispatch::{DeviceId, ExitDispatcher};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::GuestMemoryBacking;
use crate::guest_memory_slot::GuestMemorySlot;
use crate::hvf_lifecycle::ReleaseDevices;
use crate::interrupt::{
    BlockQueueNotifyRoute, BoundAckRoute, InterruptAckRoute, InterruptAckTally, InterruptLine,
    LevelInterruptLine, NetQueueNotifyRoute, NetRxPollRoute, QueueNotifyRoute,
};
use crate::uart::SerialConsole;
use crate::virtio_block::{BlockBackend, VirtioBlock};
use crate::virtio_mmio::{QueueNotifyTally, SharedTransport, VirtioDevice, VirtioMmioTransport};
use crate::virtio_net::{NetBackend, VirtioNet};

fn internal(m: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, m)
}

/// 登録済みのデバイス 1 台（トランスポート・識別子・窓・割り込み線）。
pub(crate) struct HvfBoundDevice<D: VirtioDevice, L> {
    /// QueueNotify の route（#4028）と ACK の route（#3863）が型つきで触る。dispatcher と共有する。
    transport: Arc<Mutex<VirtioMmioTransport<D>>>,
    id: DeviceId,
    window: MmioRegion,
    line: L,
    /// 注入する SPI の INTID（`layout.virtio_spi(index)` の値。診断用）。
    spi_intid: u32,
    /// ACK の後処理の結果の累計（観測専用。全 vCPU のハンドラと共有する。#4014）。
    ack_tally: Arc<InterruptAckTally>,
}

/// 登録済みデバイス 1 台の診断用の写し（`hvf::microvm` の `infos()` が公開型へ詰め替える）。
#[cfg_attr(target_os = "linux", allow(dead_code))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct BoundDeviceSummary {
    /// virtio-net なら真、virtio-block なら偽。
    pub(crate) is_net: bool,
    pub(crate) id: DeviceId,
    pub(crate) window: MmioRegion,
    pub(crate) spi_intid: u32,
}

/// 登録済みのシリアル（ホストが出力を取り出すハンドル・識別子・窓・SPI の INTID）。
pub(crate) struct HvfSerial {
    console: SerialConsole,
    /// 登録の識別子（観測・将来の登録解除用）。
    #[allow(dead_code)]
    id: DeviceId,
    #[allow(dead_code)]
    window: MmioRegion,
    /// THRE 割り込みの INTID（level の SPI。#3892）。診断用に保持する。
    #[allow(dead_code)]
    spi_intid: u32,
}

/// virtio-mmio のデバイス群とシリアル、それを引く `ExitDispatcher`。`L` は virtio 1 台ごとの割り込み線。
pub(crate) struct HvfDeviceBus<B: BlockBackend, N: NetBackend, L> {
    dispatcher: Arc<Mutex<ExitDispatcher>>,
    serial: Option<HvfSerial>,
    block: Vec<HvfBoundDevice<VirtioBlock<B>, L>>,
    net: Vec<HvfBoundDevice<VirtioNet<N>, L>>,
    /// 全 virtio デバイスのトランスポートが共有する、MMIO exit 経路で捨てた QUEUE_NOTIFY の件数（VM ごと。HVF は常にこの経路。#4459）。
    queue_notify: Arc<QueueNotifyTally>,
}

impl<B: BlockBackend, N: NetBackend, L> Drop for HvfDeviceBus<B, N, L> {
    /// dispatcher の `Arc` は vCPU の `MmioHandler` や `HvfVmParts` も持ち、バスを drop してもデバイス（と backend）は
    /// dispatcher の範囲表に残る。RAM と VM の解放より前にデバイスを手放すため、ここで範囲表を空にする（MVM-5・REPAIR-5）。
    /// vCPU スレッドがロックを持ったまま止まっている（期限切れ）場合に待たないよう `try_lock` を使い、
    /// 取れなければ空にしない（そのときは RAM もリークされ、解放順序の違反は起きない）。
    fn drop(&mut self) {
        match self.dispatcher.try_lock() {
            Ok(mut d) => d.clear(),
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner().clear(),
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
    }
}

impl<B: BlockBackend, N: NetBackend, L> ReleaseDevices for HvfDeviceBus<B, N, L> {
    /// dispatcher の範囲表を空にする。`dispatcher()` の clone 保持者がロック中なら `deadline` まで 1ms 刻みで再試行し、
    /// それでも取れなければ `DeadlineExceeded`（成功扱いにしない。呼び出し側が RAM・VM を解放しない。MVM-5・REPAIR-5）。
    fn release_devices(&mut self, deadline: std::time::Duration) -> Result<(), MicrovmError> {
        let limit = std::time::Instant::now() + deadline;
        loop {
            match self.dispatcher.try_lock() {
                Ok(mut d) => {
                    d.clear();
                    return Ok(());
                }
                Err(std::sync::TryLockError::Poisoned(e)) => {
                    e.into_inner().clear();
                    return Ok(());
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    if std::time::Instant::now() >= limit {
                        return Err(MicrovmError::new(
                            MicrovmErrorCode::DeadlineExceeded,
                            "device dispatcher is locked; devices not released",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
    }
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
impl<B, N, L> HvfDeviceBus<B, N, L>
where
    B: BlockBackend + Send + 'static,
    N: NetBackend + Send + 'static,
    L: InterruptLine + Clone + Send + Sync + 'static,
{
    /// block → net → シリアルの順に窓（`layout.virtio_mmio_window(i)`）と割り込み線（`virtio_line(i)`）を割り当てて登録する。
    ///
    /// `serial_line` は `layout.serial` が `Some` のときだけ呼ばれ、線と INTID（診断用）を返す。
    pub(crate) fn new<S>(
        layout: &Arm64Layout,
        block: Vec<B>,
        net: Vec<(N, [u8; 6])>,
        mut virtio_line: impl FnMut(u32) -> Result<L, MicrovmError>,
        serial_line: impl FnOnce() -> Result<(S, u32), MicrovmError>,
    ) -> Result<Self, MicrovmError>
    where
        S: LevelInterruptLine + 'static,
    {
        let mut bus = HvfDeviceBus {
            dispatcher: Arc::new(Mutex::new(ExitDispatcher::new())),
            block: Vec::with_capacity(block.len()),
            net: Vec::with_capacity(net.len()),
            serial: None,
            queue_notify: Arc::default(),
        };
        let mut index: u32 = 0;
        for backend in block {
            let transport = Arc::new(Mutex::new(
                VirtioMmioTransport::new(VirtioBlock::new(backend))?
                    .with_queue_notify_tally(Arc::clone(&bus.queue_notify)),
            ));
            let dev = bus.bind(layout, &mut virtio_line, index, transport)?;
            bus.block.push(dev);
            index += 1;
        }
        for (backend, mac) in net {
            let transport = Arc::new(Mutex::new(
                VirtioMmioTransport::new(VirtioNet::new(backend, mac))?
                    .with_queue_notify_tally(Arc::clone(&bus.queue_notify)),
            ));
            let dev = bus.bind(layout, &mut virtio_line, index, transport)?;
            bus.net.push(dev);
            index += 1;
        }
        // シリアルは virtio の後に登録する（virtio の DeviceId を変えない）。THRE 割り込みは level の SPI で結ぶ（#3892）。
        if let Some(window) = layout.serial {
            let console = SerialConsole::new();
            let (line, spi_intid) = serial_line()?;
            let id = bus
                .dispatcher
                .lock()
                .map_err(|_| internal("device dispatcher lock poisoned"))?
                .register_mmio(
                    window.base.raw(),
                    window.size,
                    console.mmio_device_with_irq(Arc::new(line)),
                )?;
            bus.serial = Some(HvfSerial {
                console,
                id,
                window,
                spi_intid,
            });
        }
        Ok(bus)
    }

    /// `index` 番目の窓に `transport` を登録し、割り込み線を結ぶ。評価順は 窓 → 線の生成 → 注入方式の照合 → 登録。
    fn bind<D: VirtioDevice + Send + 'static>(
        &self,
        layout: &Arm64Layout,
        virtio_line: &mut impl FnMut(u32) -> Result<L, MicrovmError>,
        index: u32,
        transport: Arc<Mutex<VirtioMmioTransport<D>>>,
    ) -> Result<HvfBoundDevice<D, L>, MicrovmError> {
        let window = layout.virtio_mmio_window(index)?;
        let line = virtio_line(index)?;
        layout.check_virtio_injection(line.injection())?;
        let spi_intid = layout
            .virtio_spi(index)?
            .intid()
            .ok_or_else(|| internal("virtio spi intid overflows"))?;
        let id = self
            .dispatcher
            .lock()
            .map_err(|_| internal("device dispatcher lock poisoned"))?
            .register_mmio(
                window.base.raw(),
                window.size,
                Box::new(SharedTransport(Arc::clone(&transport))),
            )?;
        Ok(HvfBoundDevice {
            transport,
            id,
            window,
            line,
            spi_intid,
            ack_tally: Arc::new(InterruptAckTally::default()),
        })
    }

    /// MMIO exit 経路で捨てた QUEUE_NOTIFY の共有の計数（`HvfVmParts` が停止の報告の集約先として持つ。#4459）。
    pub(crate) fn queue_notify_tally(&self) -> Arc<QueueNotifyTally> {
        Arc::clone(&self.queue_notify)
    }

    /// dispatcher（vCPU の `MmioHandler` と共有する）。
    pub(crate) fn dispatcher(&self) -> &Arc<Mutex<ExitDispatcher>> {
        &self.dispatcher
    }

    /// シリアルの出力を取り出すハンドル（clone）。
    pub(crate) fn serial_console(&self) -> Option<SerialConsole> {
        self.serial.as_ref().map(|s| s.console.clone())
    }

    /// 登録済みの virtio デバイスの診断用の写し（block → net の順）。
    pub(crate) fn summaries(&self) -> Vec<BoundDeviceSummary> {
        let b = self
            .block
            .iter()
            .map(|d| (false, d.id, d.window, d.spi_intid));
        let n = self.net.iter().map(|d| (true, d.id, d.window, d.spi_intid));
        b.chain(n)
            .map(|(is_net, id, window, spi_intid)| BoundDeviceSummary {
                is_net,
                id,
                window,
                spi_intid,
            })
            .collect()
    }

    /// 全デバイスの `InterruptACK` の後処理（#3863）。
    pub(crate) fn ack_routes(&self) -> Vec<(DeviceId, Arc<dyn InterruptAckRoute>)> {
        fn route<
            D: VirtioDevice + Send + 'static,
            L: InterruptLine + Clone + Send + Sync + 'static,
        >(
            d: &HvfBoundDevice<D, L>,
        ) -> (DeviceId, Arc<dyn InterruptAckRoute>) {
            (
                d.id,
                Arc::new(BoundAckRoute {
                    transport: Arc::clone(&d.transport),
                    line: d.line.clone(),
                }),
            )
        }
        let b = self.block.iter().map(route);
        let n = self.net.iter().map(route);
        b.chain(n).collect()
    }

    /// 全デバイスの `InterruptACK` の後処理の結果の計数（観測専用。#4014）。`Arc` の clone を全 vCPU が共有する。
    pub(crate) fn ack_tallies(&self) -> Vec<(DeviceId, Arc<InterruptAckTally>)> {
        let b = self.block.iter().map(|d| (d.id, Arc::clone(&d.ack_tally)));
        let n = self.net.iter().map(|d| (d.id, Arc::clone(&d.ack_tally)));
        b.chain(n).collect()
    }

    /// virtio-block の `QueueNotify` の処理（virtqueue の処理と完了の割り込み。#4028・MVM-5・MVM-1）。
    ///
    /// 台ごとに 1 回だけ作り、全 vCPU の `MmioHandler` が同じ実体（`Arc`）を共有する。ゲスト RAM は `memory` スロットの
    /// clone で受け渡す（解放後の通知は `Internal` で fail-closed）。virtio-net の台にも同じ形で route を作る（#4029）。
    pub(crate) fn queue_notify_routes<M: GuestMemoryBacking + Send + 'static>(
        &self,
        memory: &GuestMemorySlot<M>,
    ) -> Vec<(DeviceId, Arc<dyn QueueNotifyRoute>)> {
        let b = self.block.iter().map(|d| {
            let route: Arc<dyn QueueNotifyRoute> = Arc::new(BlockQueueNotifyRoute::new(
                Arc::clone(&d.transport),
                memory.clone(),
                d.line.clone(),
            ));
            (d.id, route)
        });
        let n = self.net.iter().map(|d| {
            let route: Arc<dyn QueueNotifyRoute> = Arc::new(NetQueueNotifyRoute::new(
                Arc::clone(&d.transport),
                memory.clone(),
                d.line.clone(),
            ));
            (d.id, route)
        });
        b.chain(n).collect()
    }

    /// virtio-net の台ごとの受信ポーラー用の route（ホスト側の到着を契機にした受信。#4030・MVM-5・MVM-1）。net が無ければ空。
    pub(crate) fn net_rx_poll_routes<M: GuestMemoryBacking + Send + 'static>(
        &self,
        memory: &GuestMemorySlot<M>,
    ) -> Vec<Arc<dyn NetRxPollRoute>> {
        self.net
            .iter()
            .map(|d| {
                let route: Arc<dyn NetRxPollRoute> = Arc::new(NetQueueNotifyRoute::new(
                    Arc::clone(&d.transport),
                    memory.clone(),
                    d.line.clone(),
                ));
                route
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    //! 偽の GIC による試験（Linux・macOS の既定の集合。HVF 不要。#4293・MVM-5・MVM-1・REPAIR-12）。
    use super::*;
    use crate::dispatch::{DispatchOutcome, MmioAccess};
    use crate::exit::VcpuExit;
    use crate::interrupt::IrqTrigger;
    use crate::spi::tests::RecordingGic;
    use crate::spi::{SpiLevelLine, SpiLine};
    use crate::virtio_block::MemoryBlockBackend;
    use crate::virtio_mmio::{IgnoredAccess, MmioWriteOutcome, reg};
    use crate::virtio_net::MemoryNetBackend;

    type Line = SpiLine<RecordingGic>;
    type Bus = HvfDeviceBus<MemoryBlockBackend, MemoryNetBackend, Line>;

    fn write(d: &mut ExitDispatcher, addr: u64, value: u32) -> MmioWriteOutcome {
        let mut data = [0u8; 8];
        data[..4].copy_from_slice(&value.to_le_bytes());
        let exit = VcpuExit::Mmio {
            phys_addr: addr,
            data,
            len: 4,
            is_write: true,
        };
        match d.dispatch(&exit).unwrap() {
            DispatchOutcome::Mmio {
                access: MmioAccess::Write(o),
                ..
            } => o,
            other => panic!("expected mmio write, got {other:?}"),
        }
    }

    fn read(d: &mut ExitDispatcher, addr: u64) -> u32 {
        let exit = VcpuExit::Mmio {
            phys_addr: addr,
            data: [0; 8],
            len: 4,
            is_write: false,
        };
        let out = d.dispatch(&exit).unwrap();
        let r = out.read_response().expect("read response");
        u32::from_le_bytes([r[0], r[1], r[2], r[3]])
    }

    /// 交渉 → 指定キューの設定 → DRIVER_OK。
    fn bring_up(d: &mut ExitDispatcher, base: u64, queues: &[u32]) {
        write(d, base + reg::STATUS, 1);
        write(d, base + reg::STATUS, 3);
        write(d, base + reg::DEVICE_FEATURES_SEL, 0);
        let low = read(d, base + reg::DEVICE_FEATURES);
        write(d, base + reg::DRIVER_FEATURES_SEL, 0);
        write(d, base + reg::DRIVER_FEATURES, low);
        write(d, base + reg::DRIVER_FEATURES_SEL, 1);
        write(d, base + reg::DRIVER_FEATURES, 1);
        assert_eq!(
            write(d, base + reg::STATUS, 11),
            MmioWriteOutcome::FeaturesAccepted
        );
        for &q in queues {
            let off = 0x1000 * (u64::from(q) + 1);
            write(d, base + reg::QUEUE_SEL, q);
            write(d, base + reg::QUEUE_NUM, 16);
            write(d, base + reg::QUEUE_DESC_LOW, off as u32);
            write(d, base + reg::QUEUE_DRIVER_LOW, (off + 0x400) as u32);
            write(d, base + reg::QUEUE_DEVICE_LOW, (off + 0x800) as u32);
            write(d, base + reg::QUEUE_READY, 1);
        }
        assert_eq!(
            write(d, base + reg::STATUS, 15),
            MmioWriteOutcome::DeviceActivated
        );
    }

    fn block() -> Vec<MemoryBlockBackend> {
        vec![MemoryBlockBackend::new(16 * 512, false).unwrap()]
    }

    fn net() -> Vec<(MemoryNetBackend, [u8; 6])> {
        vec![(MemoryNetBackend::new(), [2, 0, 0, 0, 0, 1])]
    }

    /// 偽の GIC の線を作る生成関数（`index` を `seen` に記録する）。
    fn factory<'a>(
        layout: &'a Arm64Layout,
        gic: &'a RecordingGic,
        seen: &'a mut Vec<u32>,
        trigger: IrqTrigger,
    ) -> impl FnMut(u32) -> Result<Line, MicrovmError> + 'a {
        move |i| {
            seen.push(i);
            let intid = layout.virtio_spi(i)?.intid().unwrap();
            Ok(SpiLine::new(gic.clone(), intid, trigger))
        }
    }

    type SerialLine = SpiLevelLine<RecordingGic>;

    fn no_serial() -> Result<(SerialLine, u32), MicrovmError> {
        panic!("serial line factory must not be called without layout.serial");
    }

    /// MVM-5・MVM-1・REPAIR-4・#4459: HVF は常に MMIO exit 経路のため、DRIVER_OK 前の QUEUE_NOTIFY は VM ごとの計数に数えられ、
    /// QUEUE_NOTIFY 以外の無視は数えられない。block と net の合算で、受理された通知も数えない。
    #[test]
    fn mvm5_4459_hvf_bus_counts_mmio_ignored_queue_notify() {
        let layout = Arm64Layout::new(64 << 20, 1, 2).unwrap();
        let gic = RecordingGic::default();
        let mut seen = Vec::new();
        let bus: Bus = HvfDeviceBus::new(
            &layout,
            block(),
            net(),
            factory(&layout, &gic, &mut seen, layout.virtio_spi_trigger),
            no_serial,
        )
        .unwrap();
        let tally = bus.queue_notify_tally();
        let infos = bus.summaries();
        let (blk, nt) = (infos[0].window.base.raw(), infos[1].window.base.raw());
        let mut d = bus.dispatcher().lock().unwrap();
        for base in [blk, blk, nt] {
            assert_eq!(
                write(&mut d, base + reg::QUEUE_NOTIFY, 0),
                MmioWriteOutcome::Ignored(IgnoredAccess::WrongDeviceState)
            );
        }
        assert_eq!(tally.mmio_ignored(), 3);
        // 対照: QUEUE_NOTIFY 以外の Ignored（FEATURES_OK 前の QUEUE_NUM・読み取り専用の MAGIC）は増えない。
        for off in [reg::QUEUE_NUM, reg::MAGIC] {
            assert!(matches!(
                write(&mut d, blk + off, 16),
                MmioWriteOutcome::Ignored(_)
            ));
        }
        assert_eq!(tally.mmio_ignored(), 3);
        // 対照: 受理された通知（DRIVER_OK 後のキュー 0）は数えない。
        bring_up(&mut d, blk, &[0]);
        assert_eq!(
            write(&mut d, blk + reg::QUEUE_NOTIFY, 0),
            MmioWriteOutcome::QueueNotify(0)
        );
        assert_eq!(tally.mmio_ignored(), 3);
    }

    #[test]
    fn mvm5_4293_queue_ready_zero_stops_once_via_bus_without_hvf() {
        let layout = Arm64Layout::new(64 << 20, 1, 2).unwrap();
        let gic = RecordingGic::default();
        let mut seen = Vec::new();
        let bus: Bus = HvfDeviceBus::new(
            &layout,
            block(),
            net(),
            factory(&layout, &gic, &mut seen, layout.virtio_spi_trigger),
            no_serial,
        )
        .unwrap();
        assert_eq!(seen, vec![0, 1]);
        let infos = bus.summaries();
        assert_eq!(infos.len(), 2);
        let (blk, nt) = (infos[0].window.base.raw(), infos[1].window.base.raw());
        let mut d = bus.dispatcher().lock().unwrap();

        // block: 1 回目の QueueReady=0 で QueueStopped(0)、2 回目は何も起きない。
        bring_up(&mut d, blk, &[0]);
        write(&mut d, blk + reg::QUEUE_SEL, 0);
        assert_eq!(read(&mut d, blk + reg::QUEUE_READY), 1);
        assert_eq!(
            write(&mut d, blk + reg::QUEUE_READY, 0),
            MmioWriteOutcome::QueueStopped(0)
        );
        assert_eq!(read(&mut d, blk + reg::QUEUE_READY), 0);
        assert_eq!(
            write(&mut d, blk + reg::QUEUE_READY, 0),
            MmioWriteOutcome::Handled
        );

        // net: キュー 1 だけが止まり、キュー 0 は有効なまま。
        bring_up(&mut d, nt, &[0, 1]);
        write(&mut d, nt + reg::QUEUE_SEL, 1);
        assert_eq!(
            write(&mut d, nt + reg::QUEUE_READY, 0),
            MmioWriteOutcome::QueueStopped(1)
        );
        assert_eq!(
            write(&mut d, nt + reg::QUEUE_READY, 0),
            MmioWriteOutcome::Handled
        );
        write(&mut d, nt + reg::QUEUE_SEL, 0);
        assert_eq!(read(&mut d, nt + reg::QUEUE_READY), 1);
        // queue_stopped は割り込みを注入しない。
        assert_eq!(gic.calls(), Vec::<(u32, bool)>::new());
    }

    #[test]
    fn mvm5_4293_bus_registers_block_net_serial_in_order() {
        let layout = Arm64Layout::new(64 << 20, 1, 2)
            .unwrap()
            .with_default_serial()
            .unwrap();
        let gic = RecordingGic::default();
        let mut seen = Vec::new();
        let mut serial_calls = 0;
        let bus: Bus = HvfDeviceBus::new(
            &layout,
            block(),
            net(),
            factory(&layout, &gic, &mut seen, layout.virtio_spi_trigger),
            || {
                serial_calls += 1;
                Ok((SpiLevelLine::new(gic.clone(), 33), 33))
            },
        )
        .unwrap();
        assert_eq!(serial_calls, 1);
        assert_eq!(seen, vec![0, 1]);
        assert!(bus.serial_console().is_some());
        let s = bus.summaries();
        assert_eq!((s[0].is_net, s[1].is_net), (false, true));
        let acks = bus.ack_routes();
        let tallies = bus.ack_tallies();
        assert_eq!(acks.len(), 2);
        assert_eq!(tallies.len(), 2);
        assert_eq!((acks[0].0, acks[1].0), (s[0].id, s[1].id));
        assert_eq!((tallies[0].0, tallies[1].0), (s[0].id, s[1].id));
        // シリアルは virtio の後（DeviceId が大きい）。
        assert!(bus.serial.as_ref().unwrap().id != s[0].id);
        assert_eq!(bus.serial.as_ref().unwrap().spi_intid, 33);
    }

    #[test]
    fn mvm5_4293_line_factory_error_and_injection_mismatch_are_rejected() {
        let layout = Arm64Layout::new(64 << 20, 1, 2).unwrap();
        let gic = RecordingGic::default();

        // 生成関数が index 1 で失敗すれば、そのコードで new が失敗する。
        let failing = |i: u32| -> Result<Line, MicrovmError> {
            if i == 1 {
                return Err(MicrovmError::new(
                    MicrovmErrorCode::InvalidArgument,
                    "factory failure",
                ));
            }
            let intid = layout.virtio_spi(i)?.intid().unwrap();
            Ok(SpiLine::new(gic.clone(), intid, layout.virtio_spi_trigger))
        };
        let e = Bus::new(&layout, block(), net(), failing, no_serial)
            .err()
            .expect("factory error must propagate");
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);

        // FDT の trigger（edge）と食い違う注入方式（level）の線は拒否する。
        let mut seen = Vec::new();
        let e = Bus::new(
            &layout,
            block(),
            net(),
            factory(&layout, &gic, &mut seen, IrqTrigger::LevelHigh),
            no_serial,
        )
        .err()
        .expect("injection mismatch must be rejected");
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    }
}
