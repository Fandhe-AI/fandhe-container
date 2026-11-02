//! virtio-net の結合試験（MVM-1・TASK-74.3.1・#880）。
//!
//! 公開 API だけを使い、MMIO レジスタ経由の初期化（receiveq / transmitq の 2 キュー）から、
//! 送信（ゲスト→ホスト）と受信（ホスト→ゲスト）、used リングの書き戻し、キュー停止までを具体値で照合する。
//! TASK-74.3.2・#881 の割り込み通知（`complete_net_notify`）も偽の割り込み線で具体値を照合する。
//! KVM は不要で、既定のテスト集合で走る。

use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
use fandhe_container_microvm::interrupt::{
    InterruptDelivery, InterruptLine, NetQueueStats, complete_net_notify,
};
use fandhe_container_microvm::virtio_mmio::{
    InterruptReason, MmioReadOutcome, MmioWriteOutcome, VirtioMmioTransport, reg,
};
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

fn ga(a: u64) -> GuestAddress {
    GuestAddress::new(a)
}

fn wr(t: &mut T, off: u64, v: u32) -> MmioWriteOutcome {
    t.write(off, &v.to_le_bytes())
}

fn init(t: &mut T) {
    wr(t, reg::STATUS, 1);
    wr(t, reg::STATUS, 3);
    // 提示された feature をそのまま受ける。
    let mut b = [0u8; 4];
    wr(t, reg::DEVICE_FEATURES_SEL, 0);
    assert_eq!(
        t.read(reg::DEVICE_FEATURES, &mut b),
        MmioReadOutcome::Handled
    );
    assert_eq!(u32::from_le_bytes(b), 1 << 5);
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

/// 受け入れ条件: virtio-net のキューを経由して、送信と受信を処理できる。
#[test]
fn mvm1_880_net_queues_transmit_and_receive() {
    let mut t = VirtioMmioTransport::new(VirtioNet::new(MemoryNetBackend::new(), MAC)).unwrap();
    init(&mut t);
    let mut mem =
        GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();

    // 設定空間（MMIO の 0x100 以降）から MAC が読める。
    let mut cfg = [0u8; 6];
    for (i, b) in cfg.iter_mut().enumerate() {
        let mut one = [0u8; 1];
        t.read(0x100 + i as u64, &mut one);
        *b = one[0];
    }
    assert_eq!(cfg, MAC);

    // 送信: ヘッダ 12 バイト（全 0）+ フレーム 64 バイトを transmitq（キュー 1）へ。
    let out: Vec<u8> = (0..64u32).map(|i| (i % 251) as u8).collect();
    let mut data = vec![0u8; 12];
    data.extend_from_slice(&out);
    mem.write_at(ga(TX_BUF), &data).unwrap();
    desc(&mut mem, TX_DESC, 0, TX_BUF, data.len() as u32, 0);
    publish(&mut mem, TX_AVAIL, 0);
    assert_eq!(
        wr(&mut t, reg::QUEUE_NOTIFY, 1),
        MmioWriteOutcome::QueueNotify(1)
    );
    let s = t.device_mut().process_tx(&mut mem).unwrap();
    assert_eq!((s.completed, s.sent), (1, 1));
    t.raise_interrupt(InterruptReason::UsedBuffer);
    assert_eq!(t.interrupt_status() & 1, 1);
    assert_eq!(t.device().backend().sent(), std::slice::from_ref(&out));
    assert_eq!(mem.read_u16_le(ga(TX_USED + 2)).unwrap(), 1);
    assert_eq!(mem.read_u32_le(ga(TX_USED + 4)).unwrap(), 0);
    assert_eq!(mem.read_u32_le(ga(TX_USED + 8)).unwrap(), 0);

    // 受信: backend に 100 バイトのフレームを入れ、receiveq（キュー 0）にバッファを積む。
    let inbound: Vec<u8> = (0..100u32).map(|i| (i % 241) as u8).collect();
    t.device_mut().backend_mut().push_inbound(&inbound).unwrap();
    desc(&mut mem, RX_DESC, 0, RX_BUF, 2048, 2);
    publish(&mut mem, RX_AVAIL, 0);
    assert_eq!(
        wr(&mut t, reg::QUEUE_NOTIFY, 0),
        MmioWriteOutcome::QueueNotify(0)
    );
    let s = t.device_mut().process_rx(&mut mem).unwrap();
    assert_eq!((s.completed, s.delivered), (1, 1));
    assert!(!s.waiting_for_buffer);
    let mut got = vec![0u8; 112];
    mem.read_at(ga(RX_BUF), &mut got).unwrap();
    assert_eq!(&got[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    assert_eq!(&got[12..], &inbound[..]);
    assert_eq!(mem.read_u16_le(ga(RX_USED + 2)).unwrap(), 1);
    assert_eq!(mem.read_u32_le(ga(RX_USED + 8)).unwrap(), 112);

    // transmitq だけを止めても receiveq は動き続ける。
    assert_eq!(wr(&mut t, reg::QUEUE_SEL, 1), MmioWriteOutcome::Handled);
    assert_eq!(
        wr(&mut t, reg::QUEUE_READY, 0),
        MmioWriteOutcome::QueueStopped(1)
    );
    t.device_mut().stop_queue(1);
    assert_eq!(
        t.device_mut().process_tx(&mut mem).unwrap_err().code(),
        MicrovmErrorCode::FailedPrecondition
    );
    assert!(t.device_mut().process_rx(&mut mem).is_ok());
}

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
    let mut t = VirtioMmioTransport::new(VirtioNet::new(MemoryNetBackend::new(), MAC)).unwrap();
    init(&mut t);
    let mem = GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
    (t, mem)
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

/// 受け入れ条件（TASK-74.3.2）: 送信の QueueNotify(1) の完了で割り込みを 1 回注入する。
#[test]
fn mvm1_881_tx_notify_with_one_frame_triggers_once() {
    let (mut t, mut mem) = fresh();
    let frame = submit_tx(&mut mem, 0);
    let line = CountLine::new(false);
    let r = complete_net_notify(&mut t, &mut mem, 1, &line).unwrap();
    let NetQueueStats::Tx(s) = r.stats else {
        panic!("expected Tx stats: {:?}", r.stats);
    };
    assert_eq!((s.completed, s.sent), (1, 1));
    assert_eq!(r.delivery, InterruptDelivery::Triggered);
    assert_eq!(r.queue_error, None);
    assert_eq!(line.count.get(), 1);
    assert_eq!(t.interrupt_status(), 1);
    assert_eq!(t.device().backend().sent(), std::slice::from_ref(&frame));
}

/// 受信の QueueNotify(0)（またはホスト側のフレーム到着）で配送し、割り込みを 1 回注入する。
#[test]
fn mvm1_881_rx_notify_delivers_and_triggers_once() {
    let (mut t, mut mem) = fresh();
    let inbound: Vec<u8> = (0..100u32).map(|i| (i % 241) as u8).collect();
    t.device_mut().backend_mut().push_inbound(&inbound).unwrap();
    desc(&mut mem, RX_DESC, 0, RX_BUF, 2048, 2);
    publish(&mut mem, RX_AVAIL, 0);
    let line = CountLine::new(false);
    let r = complete_net_notify(&mut t, &mut mem, 0, &line).unwrap();
    let NetQueueStats::Rx(s) = r.stats else {
        panic!("expected Rx stats: {:?}", r.stats);
    };
    assert_eq!((s.completed, s.delivered), (1, 1));
    assert_eq!(r.delivery, InterruptDelivery::Triggered);
    assert_eq!(r.queue_error, None);
    assert_eq!(line.count.get(), 1);
    assert_eq!(t.interrupt_status(), 1);
    let mut got = vec![0u8; 112];
    mem.read_at(ga(RX_BUF), &mut got).unwrap();
    assert_eq!(&got[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    assert_eq!(&got[12..], &inbound[..]);
}

/// 完了が 0 件なら両キューとも割り込みを入れない。
#[test]
fn mvm1_881_notify_with_empty_queues_does_not_trigger() {
    let (mut t, mut mem) = fresh();
    let line = CountLine::new(false);
    for q in [0u16, 1] {
        let r = complete_net_notify(&mut t, &mut mem, q, &line).unwrap();
        assert_eq!(r.stats.completed(), 0);
        assert_eq!(r.delivery, InterruptDelivery::NotNeeded);
        assert_eq!(r.queue_error, None);
    }
    assert_eq!(line.count.get(), 0);
    assert_eq!(t.interrupt_status(), 0);
}

/// フレームがあっても受信バッファが無ければ完了 0 件で、割り込みを入れず次の kick を待つ。
#[test]
fn mvm1_881_rx_waiting_for_buffer_does_not_trigger() {
    let (mut t, mut mem) = fresh();
    t.device_mut()
        .backend_mut()
        .push_inbound(&[7u8; 60])
        .unwrap();
    let line = CountLine::new(false);
    let r = complete_net_notify(&mut t, &mut mem, 0, &line).unwrap();
    let NetQueueStats::Rx(s) = r.stats else {
        panic!("expected Rx stats: {:?}", r.stats);
    };
    assert_eq!(s.completed, 0);
    assert!(s.waiting_for_buffer);
    assert_eq!(r.delivery, InterruptDelivery::NotNeeded);
    assert_eq!(line.count.get(), 0);
}

/// 途中で壊れても、それまでに返した分があれば割り込みを入れる。
#[test]
fn mvm1_881_notify_after_partial_progress_still_triggers() {
    let (mut t, mut mem) = fresh();
    submit_tx(&mut mem, 0);
    // 2 件目の avail が範囲外の head を指す。
    mem.write_u16_le(ga(TX_AVAIL + 4 + 2), 99).unwrap();
    mem.write_u16_le(ga(TX_AVAIL + 2), 2).unwrap();
    let line = CountLine::new(false);
    let r = complete_net_notify(&mut t, &mut mem, 1, &line).unwrap();
    assert_eq!(r.stats.completed(), 1);
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
fn mvm1_881_notify_with_broken_first_chain_does_not_trigger() {
    let (mut t, mut mem) = fresh();
    mem.write_u16_le(ga(TX_AVAIL + 4), 99).unwrap();
    mem.write_u16_le(ga(TX_AVAIL + 2), 1).unwrap();
    let line = CountLine::new(false);
    let r = complete_net_notify(&mut t, &mut mem, 1, &line).unwrap();
    assert_eq!(r.stats.completed(), 0);
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
fn mvm1_881_notify_line_failure_is_outer_error() {
    let (mut t, mut mem) = fresh();
    submit_tx(&mut mem, 0);
    let line = CountLine::new(true);
    let e = complete_net_notify(&mut t, &mut mem, 1, &line).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::Internal);
}

/// activate 前と範囲外のキュー番号は `queue_error` で返し、割り込みを入れない。
#[test]
fn mvm1_881_notify_before_activation_and_unknown_queue() {
    let mut t = VirtioMmioTransport::new(VirtioNet::new(MemoryNetBackend::new(), MAC)).unwrap();
    let mut mem =
        GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
    let line = CountLine::new(false);
    let r = complete_net_notify(&mut t, &mut mem, 0, &line).unwrap();
    assert_eq!(r.delivery, InterruptDelivery::NotNeeded);
    assert_eq!(
        r.queue_error.map(|e| e.code()),
        Some(MicrovmErrorCode::FailedPrecondition)
    );
    let (mut t, mut mem) = fresh();
    let r = complete_net_notify(&mut t, &mut mem, 2, &line).unwrap();
    assert_eq!(r.stats, NetQueueStats::Unknown { queue: 2 });
    assert_eq!(r.delivery, InterruptDelivery::NotNeeded);
    assert_eq!(
        r.queue_error.map(|e| e.code()),
        Some(MicrovmErrorCode::InvalidArgument)
    );
    assert_eq!(line.count.get(), 0);
    assert_eq!(t.interrupt_status(), 0);
}
