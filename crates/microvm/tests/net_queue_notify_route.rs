//! virtio-net の QueueNotify route の結合試験（#4029・MVM-1・MVM-5）。
//!
//! 公開 API だけで `NetQueueNotifyRoute`（トランスポート・ゲスト RAM のスロット・割り込み線の束ね）を作り、
//! 送信（キュー 1）と、ゲストの kick による受信（キュー 0）の完了・`trigger` の回数・範囲外のキュー番号・
//! リング破損の返し方・固定の `Err` を具体値で照合する。KVM は不要。
//! ホスト側の到着を契機にした受信（受信ポーラー）は `tests/net_rx_poller.rs`（#4030）で扱い、ここでは扱わない。
#![cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
use fandhe_container_microvm::guest_memory_slot::GuestMemorySlot;
use fandhe_container_microvm::interrupt::{
    InterruptDelivery, InterruptLine, NetNotifyReport, NetQueueNotifyRoute, NetQueueStats,
    QueueNotifyReport, QueueNotifyRoute,
};
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
const TX_BUF: u64 = 0x10000;
const RX_BUF: u64 = 0x11000;

/// 回数を数える `Send + Sync` の偽の割り込み線。
#[derive(Clone, Default)]
struct CountLine(Arc<AtomicU32>);

impl CountLine {
    fn count(&self) -> u32 {
        self.0.load(Ordering::SeqCst)
    }
}

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

fn desc(m: &mut Mem, base: u64, i: u64, addr: u64, len: u32, flags: u16) {
    let at = base + i * 16;
    m.write_at(ga(at), &addr.to_le_bytes()).unwrap();
    m.write_u32_le(ga(at + 8), len).unwrap();
    m.write_u16_le(ga(at + 12), flags).unwrap();
    m.write_u16_le(ga(at + 14), 0).unwrap();
}

fn publish(m: &mut Mem, avail: u64, slot: u16) {
    m.write_u16_le(ga(avail + 4 + 2 * u64::from(slot)), slot)
        .unwrap();
    m.write_u16_le(ga(avail + 2), slot + 1).unwrap();
}

/// transmitq の `slot` へ（ヘッダ 12 バイト + 64 バイトのフレーム）を積み、フレームを返す。
fn submit_tx(m: &mut Mem, slot: u16) -> Vec<u8> {
    let frame: Vec<u8> = (0..64u32)
        .map(|i| ((i + u32::from(slot)) % 251) as u8)
        .collect();
    let mut data = vec![0u8; 12];
    data.extend_from_slice(&frame);
    let buf = TX_BUF + u64::from(slot) * 0x1000;
    m.write_at(ga(buf), &data).unwrap();
    desc(m, TX_DESC, u64::from(slot), buf, data.len() as u32, 0);
    publish(m, TX_AVAIL, slot);
    frame
}

/// receiveq の 0 番へ 2048 バイトの書き込み用バッファを積む。
fn submit_rx(m: &mut Mem) {
    desc(m, RX_DESC, 0, RX_BUF, 2048, 2);
    publish(m, RX_AVAIL, 0);
}

struct Fixture {
    transport: Arc<Mutex<T>>,
    slot: GuestMemorySlot<HeapBacking>,
    line: CountLine,
    route: Arc<NetQueueNotifyRoute<MemoryNetBackend, HeapBacking, CountLine>>,
}

fn fixture() -> Fixture {
    let mut t = VirtioMmioTransport::new(VirtioNet::new(MemoryNetBackend::new(), MAC)).unwrap();
    init(&mut t);
    let mem = GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
    let transport = Arc::new(Mutex::new(t));
    let slot = GuestMemorySlot::new(mem);
    let line = CountLine::default();
    let route = Arc::new(NetQueueNotifyRoute::new(
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

fn with_mem<R>(f: &Fixture, op: impl FnOnce(&mut Mem) -> R) -> R {
    f.slot
        .with_memory_mut(|m| Ok(op(m)))
        .expect("memory present")
}

fn used_idx(f: &Fixture, used: u64) -> u16 {
    f.slot.with_memory(|m| m.read_u16_le(ga(used + 2))).unwrap()
}

fn net(r: QueueNotifyReport) -> NetNotifyReport {
    match r {
        QueueNotifyReport::Net(n) => n,
        other => panic!("unexpected report: {other:?}"),
    }
}

/// 送信の完了: フレームが backend へ渡り、used 更新・trigger 1 回・interrupt_status が立つ。
#[test]
fn mvm1_4029_net_route_completes_tx() {
    let f = fixture();
    let frame = with_mem(&f, |m| submit_tx(m, 0));
    let r = net(f.route.on_queue_notify(1).unwrap());
    let NetQueueStats::Tx(s) = r.stats else {
        panic!("expected Tx stats: {:?}", r.stats);
    };
    assert_eq!((s.completed, s.sent), (1, 1));
    assert_eq!(r.delivery, InterruptDelivery::Triggered);
    assert_eq!(r.queue_error, None);
    assert_eq!(f.line.count(), 1);
    assert_eq!(used_idx(&f, TX_USED), 1);
    let t = f.transport.lock().unwrap();
    assert_eq!(t.interrupt_status(), 1);
    assert_eq!(t.device().backend().sent(), std::slice::from_ref(&frame));
}

/// ゲストの kick による受信の完了: ヘッダ + フレームが書かれ、trigger 1 回。
#[test]
fn mvm1_4029_net_route_completes_rx_on_guest_notify() {
    let f = fixture();
    let inbound: Vec<u8> = (0..100u32).map(|i| (i % 241) as u8).collect();
    f.transport
        .lock()
        .unwrap()
        .device_mut()
        .backend_mut()
        .push_inbound(&inbound)
        .unwrap();
    with_mem(&f, submit_rx);
    let r = net(f.route.on_queue_notify(0).unwrap());
    let NetQueueStats::Rx(s) = r.stats else {
        panic!("expected Rx stats: {:?}", r.stats);
    };
    assert_eq!((s.completed, s.delivered), (1, 1));
    assert_eq!(r.delivery, InterruptDelivery::Triggered);
    assert_eq!(r.queue_error, None);
    assert_eq!(f.line.count(), 1);
    assert_eq!(used_idx(&f, RX_USED), 1);
    let (len, got) = with_mem(&f, |m| {
        let len = m.read_u32_le(ga(RX_USED + 8)).unwrap();
        let mut got = vec![0u8; 112];
        m.read_at(ga(RX_BUF), &mut got).unwrap();
        (len, got)
    });
    assert_eq!(len, 112);
    assert_eq!(&got[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    assert_eq!(&got[12..], &inbound[..]);
    assert_eq!(f.transport.lock().unwrap().interrupt_status(), 1);
}

/// 届いたフレームが無いなら kick だけでは割り込みを入れない。
#[test]
fn mvm1_4029_net_route_rx_without_inbound_does_not_trigger() {
    let f = fixture();
    with_mem(&f, submit_rx);
    let r = net(f.route.on_queue_notify(0).unwrap());
    assert_eq!(r.stats.completed(), 0);
    assert_eq!(r.delivery, InterruptDelivery::NotNeeded);
    assert_eq!(r.queue_error, None);
    assert_eq!(f.line.count(), 0);
    assert_eq!(f.transport.lock().unwrap().interrupt_status(), 0);
}

/// 送信と受信を続けて通すと trigger はちょうど 2 回。
#[test]
fn mvm1_4029_net_route_tx_then_rx_counts_triggers() {
    let f = fixture();
    with_mem(&f, |m| {
        submit_tx(m, 0);
        submit_rx(m);
    });
    f.transport
        .lock()
        .unwrap()
        .device_mut()
        .backend_mut()
        .push_inbound(&[7u8; 60])
        .unwrap();
    let tx = net(f.route.on_queue_notify(1).unwrap());
    assert_eq!(tx.delivery, InterruptDelivery::Triggered);
    assert_eq!(f.line.count(), 1);
    let rx = net(f.route.on_queue_notify(0).unwrap());
    assert_eq!(rx.delivery, InterruptDelivery::Triggered);
    assert_eq!(f.line.count(), 2);
}

/// 範囲外のキュー番号は lock の前に `Ok` の `queue_error` で拒否する（メモリが取り出し済みでも同じ）。
#[test]
fn mvm1_4029_net_route_rejects_out_of_range_queue() {
    let f = fixture();
    with_mem(&f, |m| {
        submit_tx(m, 0);
    });
    for q in [2u16, u16::MAX] {
        let r = net(f.route.on_queue_notify(q).unwrap());
        assert_eq!(r.stats, NetQueueStats::Unknown { queue: q });
        assert_eq!(r.delivery, InterruptDelivery::NotNeeded);
        let e = r.queue_error.expect("queue_error");
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "net queue index out of range");
    }
    assert_eq!(f.line.count(), 0);
    assert_eq!(f.transport.lock().unwrap().interrupt_status(), 0);
    assert_eq!(used_idx(&f, RX_USED), 0);
    assert_eq!(used_idx(&f, TX_USED), 0);

    assert!(f.slot.take().unwrap().is_some());
    let r = net(f.route.on_queue_notify(2).unwrap());
    assert_eq!(r.stats, NetQueueStats::Unknown { queue: 2 });
    assert_eq!(
        r.queue_error.map(|e| e.code()),
        Some(MicrovmErrorCode::InvalidArgument)
    );
}

/// リング破損は `Ok` の `queue_error` で返る。完了 0 件なら割り込みは入らない。
#[test]
fn mvm1_4029_net_route_returns_ring_corruption_in_report() {
    let f = fixture();
    with_mem(&f, |m| {
        submit_tx(m, 0);
        // head を範囲外にする。
        m.write_u16_le(ga(TX_AVAIL + 4), 99).unwrap();
    });
    let r = net(f.route.on_queue_notify(1).unwrap());
    assert_eq!(
        r.queue_error.as_ref().map(MicrovmError::code),
        Some(MicrovmErrorCode::InvalidArgument)
    );
    assert_eq!(r.stats.completed(), 0);
    assert_eq!(r.delivery, InterruptDelivery::NotNeeded);
    assert_eq!(f.line.count(), 0);
}

/// メモリの取り出し済みは固定の `Err`。
#[test]
fn mvm5_4029_net_route_after_memory_taken_is_fixed_error() {
    let f = fixture();
    assert!(f.slot.take().unwrap().is_some());
    let e = f.route.on_queue_notify(1).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::Internal);
    assert_eq!(e.message(), "guest memory is already released");
    assert_eq!(f.line.count(), 0);
}

/// トランスポートの lock が毒化していたら固定の `Err`。
#[test]
fn mvm5_4029_net_route_with_poisoned_transport_is_fixed_error() {
    let f = fixture();
    let t = Arc::clone(&f.transport);
    let _ = std::thread::spawn(move || {
        let _g = t.lock().unwrap();
        panic!("poison the transport lock");
    })
    .join();
    let e = f.route.on_queue_notify(1).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::Internal);
    assert_eq!(e.message(), "virtio transport lock poisoned");
}

/// `Debug` は lock を取らない（transport の lock を持ち、メモリを取り出した状態でも返る）。
#[test]
fn mvm1_4029_net_route_debug_does_not_lock() {
    let f = fixture();
    let _g = f.transport.lock().unwrap();
    assert!(f.slot.take().unwrap().is_some());
    assert_eq!(format!("{:?}", f.route), "NetQueueNotifyRoute { .. }");
}
