//! virtio-net の受信ポーラー（`net_rx_poll`）の結合試験（#4030・MVM-5・MVM-1・REPAIR-5）。
//!
//! 公開 API だけで `NetQueueNotifyRoute` を `spawn_net_rx_poller` に渡し、ゲストの kick なしにホスト側 backend へ届いた
//! フレームが受信キューへ配送され割り込みが 1 回上がること、未 activate のデバイスには配送しないこと、停止後に
//! routes が解放されていることを具体値で照合する。KVM・Hypervisor.framework は不要。
#![cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
use fandhe_container_microvm::guest_memory_slot::GuestMemorySlot;
use fandhe_container_microvm::hvf_smp::VmShutdown;
use fandhe_container_microvm::interrupt::{NetQueueNotifyRoute, NetRxPollRoute};
use fandhe_container_microvm::net_rx_poll::spawn_net_rx_poller;
use fandhe_container_microvm::stop::StopReason;
use fandhe_container_microvm::virtio_mmio::VirtioMmioTransport;
use fandhe_container_microvm::virtio_net::{MemoryNetBackend, VirtioNet};

type T = VirtioMmioTransport<VirtioNet<MemoryNetBackend>>;

/// virtqueue の試験補助の正本（`tests/support/virtqueue_driver.rs`。複製しない・#4113）。
#[path = "support/virtqueue_driver.rs"]
mod virtqueue_driver;
use virtqueue_driver::net::{MAC, RX_BUF, RX_USED, init, submit_rx};
use virtqueue_driver::{CountLine, ga};

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
    while f.line.count() == 0 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(f.line.count(), 1);
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
    assert_eq!(f.line.count(), 0);
    assert!(!h.is_finished());
    assert_eq!(
        h.stop(Duration::from_secs(2)).unwrap(),
        StopReason::Requested
    );
}
