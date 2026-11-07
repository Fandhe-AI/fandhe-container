//! virtio-net の受信ポーラー（`net_rx_poll`）の結合試験（#4030・MVM-5・MVM-1・REPAIR-5）。
//!
//! 公開 API だけで `NetQueueNotifyRoute` を `spawn_net_rx_poller` に渡し、ゲストの kick なしにホスト側 backend へ届いた
//! フレームが受信キューへ配送され割り込みが 1 回上がること、未 activate のデバイスには配送しないこと、停止後に
//! routes が解放されていることを具体値で照合する。KVM・Hypervisor.framework は不要。
#![cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_microvm::error::MicrovmError;
use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
use fandhe_container_microvm::guest_memory_slot::GuestMemorySlot;
use fandhe_container_microvm::hvf_smp::VmShutdown;
use fandhe_container_microvm::interrupt::{InterruptLine, NetQueueNotifyRoute, NetRxPollRoute};
use fandhe_container_microvm::net_rx_poll::spawn_net_rx_poller;
use fandhe_container_microvm::stop::StopReason;
use fandhe_container_microvm::virtio_mmio::{MmioWriteOutcome, VirtioMmioTransport, reg};
use fandhe_container_microvm::virtio_net::{MemoryNetBackend, VirtioNet};

type T = VirtioMmioTransport<VirtioNet<MemoryNetBackend>>;
type Mem = GuestMemory<HeapBacking>;

const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const RX_DESC: u64 = 0x1000;
const RX_AVAIL: u64 = 0x2000;
const RX_USED: u64 = 0x3000;
const TX_DESC: u64 = 0x4000;
const TX_AVAIL: u64 = 0x5000;
const TX_USED: u64 = 0x6000;
const RX_BUF: u64 = 0x11000;

#[derive(Clone, Default)]
struct CountLine(Arc<AtomicU32>);

impl InterruptLine for CountLine {
    fn trigger(&self) -> Result<(), MicrovmError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn ga(a: u64) -> GuestAddress {
    GuestAddress::new(a)
}

fn wr(t: &mut T, off: u64, v: u32) -> MmioWriteOutcome {
    t.write(off, &v.to_le_bytes())
}

fn init(t: &mut T) {
    wr(t, reg::STATUS, 1);
    wr(t, reg::STATUS, 3);
    let mut b = [0u8; 4];
    wr(t, reg::DEVICE_FEATURES_SEL, 0);
    t.read(reg::DEVICE_FEATURES, &mut b);
    wr(t, reg::DRIVER_FEATURES_SEL, 0);
    wr(t, reg::DRIVER_FEATURES, u32::from_le_bytes(b));
    wr(t, reg::DRIVER_FEATURES_SEL, 1);
    wr(t, reg::DRIVER_FEATURES, 1);
    assert_eq!(wr(t, reg::STATUS, 11), MmioWriteOutcome::FeaturesAccepted);
    for (q, d, a, u) in [
        (0, RX_DESC, RX_AVAIL, RX_USED),
        (1, TX_DESC, TX_AVAIL, TX_USED),
    ] {
        wr(t, reg::QUEUE_SEL, q);
        wr(t, reg::QUEUE_NUM, 16);
        wr(t, reg::QUEUE_DESC_LOW, d as u32);
        wr(t, reg::QUEUE_DRIVER_LOW, a as u32);
        wr(t, reg::QUEUE_DEVICE_LOW, u as u32);
        wr(t, reg::QUEUE_READY, 1);
    }
    assert_eq!(wr(t, reg::STATUS, 15), MmioWriteOutcome::DeviceActivated);
}

/// receiveq の 0 番へ 2048 バイトの書き込み用バッファを積む。
fn submit_rx(m: &mut Mem) {
    let at = RX_DESC;
    m.write_at(ga(at), &RX_BUF.to_le_bytes()).unwrap();
    m.write_u32_le(ga(at + 8), 2048).unwrap();
    m.write_u16_le(ga(at + 12), 2).unwrap();
    m.write_u16_le(ga(at + 14), 0).unwrap();
    m.write_u16_le(ga(RX_AVAIL + 4), 0).unwrap();
    m.write_u16_le(ga(RX_AVAIL + 2), 1).unwrap();
}

struct Fixture {
    transport: Arc<Mutex<T>>,
    slot: GuestMemorySlot<HeapBacking>,
    line: CountLine,
    route: Arc<dyn NetRxPollRoute>,
}

fn fixture(activate: bool) -> Fixture {
    let mut t = VirtioMmioTransport::new(VirtioNet::new(MemoryNetBackend::new(), MAC)).unwrap();
    let mut mem =
        GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
    if activate {
        init(&mut t);
        submit_rx(&mut mem);
    }
    let transport = Arc::new(Mutex::new(t));
    let slot = GuestMemorySlot::new(mem);
    let line = CountLine::default();
    let route: Arc<dyn NetRxPollRoute> = Arc::new(NetQueueNotifyRoute::new(
        Arc::clone(&transport),
        slot.clone(),
        line.clone(),
    ));
    Fixture {
        transport,
        slot,
        line,
        route,
    }
}

fn push(f: &Fixture, frame: &[u8]) {
    f.transport
        .lock()
        .unwrap()
        .device_mut()
        .backend_mut()
        .push_inbound(frame)
        .unwrap();
}

fn inbound_len(f: &Fixture) -> usize {
    f.transport.lock().unwrap().device().backend().inbound_len()
}

/// フレームが届くと kick なしで完了し、割り込みが 1 回上がる。stop で routes が解放される。
#[test]
fn mvm5_4030_arrival_completes_and_raises_interrupt_without_kick() {
    let f = fixture(true);
    let h = spawn_net_rx_poller(
        vec![Arc::clone(&f.route)],
        Duration::from_millis(5),
        Arc::new(VmShutdown::new()),
    )
    .unwrap();
    let frame: Vec<u8> = (0..60u32).map(|i| (i % 241) as u8).collect();
    push(&f, &frame);
    let end = Instant::now() + Duration::from_secs(5);
    while f.line.0.load(Ordering::SeqCst) == 0 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(f.line.0.load(Ordering::SeqCst), 1);
    assert_eq!(inbound_len(&f), 0);
    let (idx, len) = f
        .slot
        .with_memory(|m| {
            Ok((
                m.read_u16_le(ga(RX_USED + 2))?,
                m.read_u32_le(ga(RX_USED + 8))?,
            ))
        })
        .unwrap();
    assert_eq!((idx, len), (1, 12 + 60));
    let mut got = vec![0u8; 72];
    f.slot
        .with_memory(|m| m.read_at(ga(RX_BUF), &mut got))
        .unwrap();
    assert_eq!(&got[12..], &frame[..]);
    assert_eq!(
        h.stop(Duration::from_secs(2)).unwrap(),
        StopReason::Requested
    );
    // ポーラーが持っていた route の clone は解放済み。残るのは f.route だけ。
    drop(f.route);
    assert_eq!(Arc::strong_count(&f.transport), 1);
}

/// DRIVER_OK 前は配送せず、フレームは backend に残り、ポーラーも失敗しない。
#[test]
fn mvm5_4030_not_active_device_keeps_frame_and_poller_runs() {
    let f = fixture(false);
    let h = spawn_net_rx_poller(
        vec![Arc::clone(&f.route)],
        Duration::from_millis(2),
        Arc::new(VmShutdown::new()),
    )
    .unwrap();
    push(&f, &[1u8; 60]);
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(inbound_len(&f), 1);
    assert_eq!(f.line.0.load(Ordering::SeqCst), 0);
    assert!(!h.is_finished());
    assert_eq!(
        h.stop(Duration::from_secs(2)).unwrap(),
        StopReason::Requested
    );
}
