//! virtio-block の QueueNotify route の結合試験（#4026・MVM-1・MVM-5）。
//!
//! 公開 API だけで `BlockQueueNotifyRoute`（トランスポート・ゲスト RAM のスロット・割り込み線の束ね）を作り、
//! 要求の完了・リング破損の返し方・固定の `Err`・同時 notify の排他を具体値で照合する。KVM は不要。
#![cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]

use std::sync::{Arc, Barrier, Mutex};

use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
use fandhe_container_microvm::guest_memory_slot::GuestMemorySlot;
use fandhe_container_microvm::interrupt::{
    BlockQueueNotifyRoute, InterruptDelivery, QueueNotifyReport, QueueNotifyRoute,
};
use fandhe_container_microvm::virtio_block::{MemoryBlockBackend, VirtioBlock};
use fandhe_container_microvm::virtio_mmio::VirtioMmioTransport;

type Dev = VirtioBlock<MemoryBlockBackend>;
type T = VirtioMmioTransport<Dev>;
type Mem = GuestMemory<HeapBacking>;

/// virtqueue の試験補助の正本（`tests/support/virtqueue_driver.rs`。複製しない・#4113）。
#[path = "support/virtqueue_driver.rs"]
mod virtqueue_driver;
use virtqueue_driver::CountLine;
use virtqueue_driver::block::{AVAIL, DATA, STATUS, USED, init, submit};

struct Fixture {
    transport: Arc<Mutex<T>>,
    slot: GuestMemorySlot<HeapBacking>,
    line: CountLine,
    route: Arc<BlockQueueNotifyRoute<MemoryBlockBackend, HeapBacking, CountLine>>,
}

fn fixture() -> Fixture {
    let mut t = VirtioMmioTransport::new(VirtioBlock::new(
        MemoryBlockBackend::new(16 * 512, false).unwrap(),
    ))
    .unwrap();
    init(&mut t);
    let mem = GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
    let transport = Arc::new(Mutex::new(t));
    let slot = GuestMemorySlot::new(mem);
    let line = CountLine::default();
    let route = Arc::new(BlockQueueNotifyRoute::new(
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

fn used_idx(f: &Fixture) -> u16 {
    f.slot
        .with_memory(|m| m.read_u16_le(GuestAddress::new(USED + 2)))
        .unwrap()
}

fn block(r: QueueNotifyReport) -> fandhe_container_microvm::interrupt::BlockNotifyReport {
    match r {
        QueueNotifyReport::Block(b) => b,
        other => panic!("unexpected report: {other:?}"),
    }
}

/// 読み要求の完了: used 更新・status・trigger 1 回・interrupt_status（MVM-1・MVM-5）。
#[test]
fn mvm1_4026_route_completes_write_then_read() {
    let f = fixture();
    let payload: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();

    with_mem(&f, |m| {
        m.write_at(GuestAddress::new(DATA), &payload).unwrap();
        submit(m, 0, 1, 2, 1024, 0);
    });
    let r = block(f.route.on_queue_notify(0).unwrap());
    assert_eq!((r.stats.completed, r.stats.ok), (1, 1));
    assert_eq!(r.delivery, InterruptDelivery::Triggered);
    assert_eq!(r.queue_error, None);
    assert_eq!(f.line.count(), 1);
    assert_eq!(used_idx(&f), 1);

    with_mem(&f, |m| {
        m.write_at(GuestAddress::new(DATA), &[0u8; 1024]).unwrap();
        submit(m, 1, 0, 2, 1024, 2);
    });
    let r = block(f.route.on_queue_notify(0).unwrap());
    assert_eq!((r.stats.completed, r.stats.ok), (1, 1));
    assert_eq!(r.delivery, InterruptDelivery::Triggered);
    assert_eq!(r.queue_error, None);
    assert_eq!(f.line.count(), 2);
    assert_eq!(used_idx(&f), 2);
    assert_eq!(f.transport.lock().unwrap().interrupt_status(), 1);

    let (len, status, got) = with_mem(&f, |m| {
        let len = m.read_u32_le(GuestAddress::new(USED + 16)).unwrap();
        let mut st = [0xffu8; 1];
        m.read_at(GuestAddress::new(STATUS), &mut st).unwrap();
        let mut got = vec![0u8; 1024];
        m.read_at(GuestAddress::new(DATA), &mut got).unwrap();
        (len, st[0], got)
    });
    assert_eq!(len, 1025);
    assert_eq!(status, 0);
    assert_eq!(got, payload);
}

/// リング破損は `Ok` の `queue_error` で返る。完了 0 件なら割り込みは入らない。
#[test]
fn mvm1_4026_route_returns_ring_corruption_in_report() {
    let f = fixture();
    with_mem(&f, |m| {
        submit(m, 0, 1, 2, 512, 0);
        // head を範囲外にする。
        m.write_u16_le(GuestAddress::new(AVAIL + 4), 99).unwrap();
    });
    let r = block(f.route.on_queue_notify(0).unwrap());
    assert_eq!(
        r.queue_error.as_ref().map(MicrovmError::code),
        Some(MicrovmErrorCode::InvalidArgument)
    );
    assert_eq!(r.stats.completed, 0);
    assert_eq!(r.delivery, InterruptDelivery::NotNeeded);
    assert_eq!(f.line.count(), 0);
}

/// 1 件目が正常で 2 件目が破損: 処理済みの分と割り込みは呼び出し元へ届く。
#[test]
fn mvm1_4026_route_reports_partial_progress_before_corruption() {
    let f = fixture();
    with_mem(&f, |m| {
        submit(m, 0, 1, 2, 512, 0);
        // 2 件目の avail が範囲外の head を指す。
        m.write_u16_le(GuestAddress::new(AVAIL + 4 + 2), 99)
            .unwrap();
        m.write_u16_le(GuestAddress::new(AVAIL + 2), 2).unwrap();
    });
    let r = block(f.route.on_queue_notify(0).unwrap());
    assert_eq!(r.stats.completed, 1);
    assert_eq!(r.delivery, InterruptDelivery::Triggered);
    assert_eq!(
        r.queue_error.as_ref().map(MicrovmError::code),
        Some(MicrovmErrorCode::InvalidArgument)
    );
    assert_eq!(f.line.count(), 1);
    assert_eq!(f.transport.lock().unwrap().interrupt_status(), 1);
}

/// メモリの取り出し済みは固定の `Err`。
#[test]
fn mvm5_4026_route_after_memory_taken_is_fixed_error() {
    let f = fixture();
    assert!(f.slot.take().unwrap().is_some());
    let e = f.route.on_queue_notify(0).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::Internal);
    assert_eq!(e.message(), "guest memory is already released");
    assert_eq!(f.line.count(), 0);
}

/// 範囲外のキュー番号は lock を取る前に拒否する（メモリが取り出し済みでも InvalidArgument が先）。
#[test]
fn mvm1_4026_route_rejects_out_of_range_queue_before_locking() {
    let f = fixture();
    with_mem(&f, |m| submit(m, 0, 1, 2, 512, 0));
    let e = f.route.on_queue_notify(1).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    assert_eq!(e.message(), "block queue index out of range");
    assert_eq!(used_idx(&f), 0);
    assert_eq!(f.line.count(), 0);
    assert_eq!(f.transport.lock().unwrap().interrupt_status(), 0);

    assert!(f.slot.take().unwrap().is_some());
    let e = f.route.on_queue_notify(1).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    assert_eq!(e.message(), "block queue index out of range");
}

/// トランスポートの lock が毒化していたら固定の `Err`。
#[test]
fn mvm5_4026_route_with_poisoned_transport_is_fixed_error() {
    let f = fixture();
    let t = Arc::clone(&f.transport);
    let _ = std::thread::spawn(move || {
        let _g = t.lock().unwrap();
        panic!("poison the transport lock");
    })
    .join();
    let e = f.route.on_queue_notify(0).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::Internal);
    assert_eq!(e.message(), "virtio transport lock poisoned");
}

/// 同じデバイスへ 2 スレッドから同時に notify しても二重に処理しない。
#[test]
fn mvm1_4026_concurrent_notify_processes_once() {
    let f = fixture();
    with_mem(&f, |m| submit(m, 0, 1, 2, 512, 0));
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let route: Arc<dyn QueueNotifyRoute> = f.route.clone();
            let b = Arc::clone(&barrier);
            std::thread::spawn(move || {
                b.wait();
                route.on_queue_notify(0).unwrap()
            })
        })
        .collect();
    let reports: Vec<_> = handles
        .into_iter()
        .map(|h| block(h.join().unwrap()))
        .collect();
    let completed: u32 = reports.iter().map(|r| r.stats.completed).sum();
    let triggered = reports
        .iter()
        .filter(|r| r.delivery == InterruptDelivery::Triggered)
        .count();
    let not_needed = reports
        .iter()
        .filter(|r| r.delivery == InterruptDelivery::NotNeeded)
        .count();
    assert_eq!((completed, triggered, not_needed), (1, 1, 1));
    assert_eq!(f.line.count(), 1);
    assert_eq!(used_idx(&f), 1);
    assert_eq!(f.transport.lock().unwrap().interrupt_status(), 1);
}

/// `Debug` は lock を取らない（transport の lock を持ったままでも返る）。
#[test]
fn mvm1_4026_route_debug_does_not_lock() {
    let f = fixture();
    let _g = f.transport.lock().unwrap();
    let _m = f.slot.take();
    assert_eq!(format!("{:?}", f.route), "BlockQueueNotifyRoute { .. }");
}
