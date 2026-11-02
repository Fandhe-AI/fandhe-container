//! virtio-block の結合試験（MVM-1・TASK-74.2.2・#878）。
//!
//! 公開 API だけを使い、MMIO レジスタ経由の初期化（トランスポート）から、virtqueue に積んだ
//! write / read 要求の処理、status・used リングの書き戻しまでを具体値で照合する。
//! KVM は不要で、既定のテスト集合で走る。

use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
use fandhe_container_microvm::interrupt::{
    InterruptDelivery, InterruptLine, complete_block_notify,
};
use fandhe_container_microvm::virtio_block::{MemoryBlockBackend, VirtioBlock};
use fandhe_container_microvm::virtio_mmio::{
    InterruptReason, MmioReadOutcome, MmioWriteOutcome, VirtioMmioTransport, reg,
};

type T = VirtioMmioTransport<VirtioBlock<MemoryBlockBackend>>;
type Mem = GuestMemory<HeapBacking>;

const DESC: u64 = 0x1000;
const AVAIL: u64 = 0x2000;
const USED: u64 = 0x3000;
const HDR: u64 = 0x10000;
const DATA: u64 = 0x11000;
const STATUS: u64 = 0x12000;

fn wr(t: &mut T, off: u64, v: u32) -> MmioWriteOutcome {
    t.write(off, &v.to_le_bytes())
}

fn init(t: &mut T) {
    wr(t, reg::STATUS, 1);
    wr(t, reg::STATUS, 3);
    // 提示された feature をそのまま受ける（下位 32 bit と VERSION_1）。
    let mut b = [0u8; 4];
    wr(t, reg::DEVICE_FEATURES_SEL, 0);
    assert_eq!(
        t.read(reg::DEVICE_FEATURES, &mut b),
        MmioReadOutcome::Handled
    );
    wr(t, reg::DRIVER_FEATURES_SEL, 0);
    wr(t, reg::DRIVER_FEATURES, u32::from_le_bytes(b));
    wr(t, reg::DRIVER_FEATURES_SEL, 1);
    wr(t, reg::DRIVER_FEATURES, 1);
    assert_eq!(wr(t, reg::STATUS, 11), MmioWriteOutcome::FeaturesAccepted);
    wr(t, reg::QUEUE_SEL, 0);
    wr(t, reg::QUEUE_NUM, 16);
    wr(t, reg::QUEUE_DESC_LOW, DESC as u32);
    wr(t, reg::QUEUE_DRIVER_LOW, AVAIL as u32);
    wr(t, reg::QUEUE_DEVICE_LOW, USED as u32);
    wr(t, reg::QUEUE_READY, 1);
    assert_eq!(wr(t, reg::STATUS, 15), MmioWriteOutcome::DeviceActivated);
}

fn desc(m: &mut Mem, i: u64, addr: u64, len: u32, flags: u16, next: u16) {
    let at = DESC + i * 16;
    m.write_at(GuestAddress::new(at), &addr.to_le_bytes())
        .unwrap();
    m.write_u32_le(GuestAddress::new(at + 8), len).unwrap();
    m.write_u16_le(GuestAddress::new(at + 12), flags).unwrap();
    m.write_u16_le(GuestAddress::new(at + 14), next).unwrap();
}

/// head=0 の [header R][data][status W] を avail の `slot` に積む。
fn submit(m: &mut Mem, slot: u16, ty: u32, sector: u64, len: u32, data_flags: u16) {
    m.write_u32_le(GuestAddress::new(HDR), ty).unwrap();
    m.write_at(GuestAddress::new(HDR + 8), &sector.to_le_bytes())
        .unwrap();
    desc(m, 0, HDR, 16, 1, 1);
    desc(m, 1, DATA, len, data_flags | 1, 2);
    desc(m, 2, STATUS, 1, 2, 0);
    m.write_at(GuestAddress::new(STATUS), &[0xff]).unwrap();
    let a = AVAIL + 4 + 2 * u64::from(slot);
    m.write_u16_le(GuestAddress::new(a), 0).unwrap();
    m.write_u16_le(GuestAddress::new(AVAIL + 2), slot + 1)
        .unwrap();
}

/// 受け入れ条件: virtio-block のキューを経由して read/write を処理できる。
#[test]
fn mvm1_878_block_queue_write_then_read() {
    let mut t = VirtioMmioTransport::new(VirtioBlock::new(
        MemoryBlockBackend::new(16 * 512, false).unwrap(),
    ))
    .unwrap();
    init(&mut t);
    let mut mem =
        GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();

    // write: sector 2 へ 1024 バイト。
    let payload: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    mem.write_at(GuestAddress::new(DATA), &payload).unwrap();
    submit(&mut mem, 0, 1, 2, 1024, 0);
    assert_eq!(
        wr(&mut t, reg::QUEUE_NOTIFY, 0),
        MmioWriteOutcome::QueueNotify(0)
    );
    let stats = t.device_mut().process_queue(&mut mem).unwrap();
    assert_eq!((stats.completed, stats.ok, stats.ioerr), (1, 1, 0));
    t.raise_interrupt(InterruptReason::UsedBuffer);
    assert_eq!(t.interrupt_status(), 1);

    assert_eq!(mem.read_u16_le(GuestAddress::new(USED + 2)).unwrap(), 1);
    assert_eq!(mem.read_u32_le(GuestAddress::new(USED + 4)).unwrap(), 0);
    assert_eq!(mem.read_u32_le(GuestAddress::new(USED + 8)).unwrap(), 1);
    let mut st = [0u8; 1];
    mem.read_at(GuestAddress::new(STATUS), &mut st).unwrap();
    assert_eq!(st, [0]);
    assert_eq!(&t.device().backend().contents()[1024..2048], &payload[..]);

    // read: 同じ sector を読み戻す。
    mem.write_at(GuestAddress::new(DATA), &[0u8; 1024]).unwrap();
    submit(&mut mem, 1, 0, 2, 1024, 2);
    assert_eq!(
        wr(&mut t, reg::QUEUE_NOTIFY, 0),
        MmioWriteOutcome::QueueNotify(0)
    );
    let stats = t.device_mut().process_queue(&mut mem).unwrap();
    assert_eq!((stats.completed, stats.ok), (1, 1));
    let mut got = vec![0u8; 1024];
    mem.read_at(GuestAddress::new(DATA), &mut got).unwrap();
    assert_eq!(got, payload);
    assert_eq!(mem.read_u16_le(GuestAddress::new(USED + 2)).unwrap(), 2);
    assert_eq!(mem.read_u32_le(GuestAddress::new(USED + 16)).unwrap(), 1025);

    // キュー停止後は処理しない。
    assert_eq!(
        wr(&mut t, reg::QUEUE_READY, 0),
        MmioWriteOutcome::QueueStopped(0)
    );
    t.device_mut().stop_queue();
    assert!(t.device_mut().process_queue(&mut mem).is_err());
}
/// 割り込みを数える偽の割り込み線。
struct CountLine {
    count: std::cell::Cell<u32>,
    fail: bool,
}

impl CountLine {
    fn new(fail: bool) -> Self {
        Self {
            count: std::cell::Cell::new(0),
            fail,
        }
    }
}

impl InterruptLine for CountLine {
    fn trigger(&self) -> Result<(), MicrovmError> {
        if self.fail {
            return Err(MicrovmError::new(MicrovmErrorCode::Internal, "line down"));
        }
        self.count.set(self.count.get() + 1);
        Ok(())
    }
}

fn fresh() -> (T, Mem) {
    let mut t = VirtioMmioTransport::new(VirtioBlock::new(
        MemoryBlockBackend::new(16 * 512, false).unwrap(),
    ))
    .unwrap();
    init(&mut t);
    let mem = GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
    (t, mem)
}

/// 受け入れ条件（TASK-74.2.3）: 完了があれば InterruptStatus を立てて割り込みを 1 回注入する。
#[test]
fn mvm1_879_notify_with_one_request_triggers_once() {
    let (mut t, mut mem) = fresh();
    submit(&mut mem, 0, 1, 2, 512, 0);
    let line = CountLine::new(false);
    let r = complete_block_notify(&mut t, &mut mem, &line).unwrap();
    assert_eq!((r.stats.completed, r.stats.ok), (1, 1));
    assert_eq!(r.delivery, InterruptDelivery::Triggered);
    assert_eq!(r.queue_error, None);
    assert_eq!(line.count.get(), 1);
    assert_eq!(t.interrupt_status(), 1);
}

/// 空のキューでは割り込みを入れない。
#[test]
fn mvm1_879_notify_with_empty_queue_does_not_trigger() {
    let (mut t, mut mem) = fresh();
    let line = CountLine::new(false);
    let r = complete_block_notify(&mut t, &mut mem, &line).unwrap();
    assert_eq!(r.stats.completed, 0);
    assert_eq!(r.delivery, InterruptDelivery::NotNeeded);
    assert_eq!(line.count.get(), 0);
    assert_eq!(t.interrupt_status(), 0);
}

/// リング破損でも、それまでに返した分があれば割り込みを入れ、破損は `queue_error` で返す。
#[test]
fn mvm1_879_notify_after_partial_progress_still_triggers() {
    let (mut t, mut mem) = fresh();
    submit(&mut mem, 0, 1, 2, 512, 0);
    // 2 件目の avail が範囲外の head を指す。
    mem.write_u16_le(GuestAddress::new(AVAIL + 4 + 2), 99)
        .unwrap();
    mem.write_u16_le(GuestAddress::new(AVAIL + 2), 2).unwrap();
    let line = CountLine::new(false);
    let r = complete_block_notify(&mut t, &mut mem, &line).unwrap();
    assert_eq!(r.stats.completed, 1);
    assert_eq!(r.delivery, InterruptDelivery::Triggered);
    assert_eq!(
        r.queue_error.map(|e| e.code()),
        Some(MicrovmErrorCode::InvalidArgument)
    );
    assert_eq!(line.count.get(), 1);
    assert_eq!(t.interrupt_status(), 1);
}

/// 1 件目から壊れていれば割り込みを入れない。
#[test]
fn mvm1_879_notify_with_broken_first_request_does_not_trigger() {
    let (mut t, mut mem) = fresh();
    mem.write_u16_le(GuestAddress::new(AVAIL + 4), 99).unwrap();
    mem.write_u16_le(GuestAddress::new(AVAIL + 2), 1).unwrap();
    let line = CountLine::new(false);
    let r = complete_block_notify(&mut t, &mut mem, &line).unwrap();
    assert_eq!(r.stats.completed, 0);
    assert_eq!(r.delivery, InterruptDelivery::NotNeeded);
    assert_eq!(
        r.queue_error.map(|e| e.code()),
        Some(MicrovmErrorCode::InvalidArgument)
    );
    assert_eq!(line.count.get(), 0);
    assert_eq!(t.interrupt_status(), 0);
}

/// 割り込み線の失敗はホスト側の失敗として外側の `Err` で返る。
#[test]
fn mvm1_879_notify_line_failure_is_outer_error() {
    let (mut t, mut mem) = fresh();
    submit(&mut mem, 0, 1, 2, 512, 0);
    let line = CountLine::new(true);
    let e = complete_block_notify(&mut t, &mut mem, &line).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::Internal);
}

/// activate 前は `FailedPrecondition` を `queue_error` で返し、割り込みを入れない。
#[test]
fn mvm1_879_notify_before_activation_reports_queue_error() {
    let mut t = VirtioMmioTransport::new(VirtioBlock::new(
        MemoryBlockBackend::new(16 * 512, false).unwrap(),
    ))
    .unwrap();
    let mut mem =
        GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
    let line = CountLine::new(false);
    let r = complete_block_notify(&mut t, &mut mem, &line).unwrap();
    assert_eq!(r.delivery, InterruptDelivery::NotNeeded);
    assert_eq!(
        r.queue_error.map(|e| e.code()),
        Some(MicrovmErrorCode::FailedPrecondition)
    );
    assert_eq!(line.count.get(), 0);
}
