//! `VIRTIO_F_RING_RESET`（ビット 40）を提示・受理しないことと、動作開始後の `QueueReady=1`
//! （止めたキューの再有効化）を受けないことを、実デバイス（block・net）と公開 API で固定する
//! （MVM-1・MVM-5・#4169。親 #4115、停止側の実装は #4031）。
//!
//! KVM は不要で、既定のテスト集合で走る。OS 限定のモジュールは使わない（3 OS の型検査を通すため）。
//! 判断の記録は `docs/design/microvm-virtio-ring-reset.md`。

use fandhe_container_microvm::error::MicrovmErrorCode;
use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
use fandhe_container_microvm::virtio_block::{MemoryBlockBackend, VirtioBlock};
use fandhe_container_microvm::virtio_mmio::{
    IgnoredAccess, MmioReadOutcome, MmioWriteOutcome, VirtioDevice, VirtioMmioTransport, reg,
};
use fandhe_container_microvm::virtio_net::{MemoryNetBackend, VirtioNet};

/// VIRTIO 1.2 の 6 章 Reserved Feature Bits の `VIRTIO_F_RING_RESET`（Linux の `virtio_config.h` も 40）。
/// lib へ公開定数を足すと「対応済み」に見えるため、試験の中だけに置く（REPAIR-3）。
const VIRTIO_F_RING_RESET_BIT: u32 = 40;
/// VIRTIO 1.2 の 4.2.2 の `QueueReset`（RW）。`RING_RESET` を交渉したときだけ意味を持つ。
const QUEUE_RESET: u64 = 0x0c0;

const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
const DESC: u64 = 0x1000;
const AVAIL: u64 = 0x2000;
const USED: u64 = 0x3000;

type Blk = VirtioMmioTransport<VirtioBlock<MemoryBlockBackend>>;
type Net = VirtioMmioTransport<VirtioNet<MemoryNetBackend>>;

fn blk(read_only: bool) -> Blk {
    let b = MemoryBlockBackend::new(8192, read_only).unwrap();
    VirtioMmioTransport::new(VirtioBlock::new(b)).unwrap()
}

fn net() -> Net {
    VirtioMmioTransport::new(VirtioNet::new(MemoryNetBackend::new(), MAC)).unwrap()
}

fn mem() -> GuestMemory<HeapBacking> {
    GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap()
}

fn wr<D: VirtioDevice>(t: &mut VirtioMmioTransport<D>, off: u64, v: u32) -> MmioWriteOutcome {
    t.write(off, &v.to_le_bytes())
}

fn rd<D: VirtioDevice>(t: &VirtioMmioTransport<D>, off: u64) -> u32 {
    let mut b = [0u8; 4];
    assert_eq!(t.read(off, &mut b), MmioReadOutcome::Handled);
    u32::from_le_bytes(b)
}

fn features_page<D: VirtioDevice>(t: &mut VirtioMmioTransport<D>, sel: u32) -> u32 {
    wr(t, reg::DEVICE_FEATURES_SEL, sel);
    rd(t, reg::DEVICE_FEATURES)
}

/// ドライバが要求する feature を書き、`STATUS=11` の結果を返す（ACKNOWLEDGE|DRIVER の後）。
fn negotiate<D: VirtioDevice>(
    t: &mut VirtioMmioTransport<D>,
    lo: u32,
    hi: u32,
) -> MmioWriteOutcome {
    wr(t, reg::STATUS, 1);
    wr(t, reg::STATUS, 3);
    wr(t, reg::DRIVER_FEATURES_SEL, 0);
    wr(t, reg::DRIVER_FEATURES, lo);
    wr(t, reg::DRIVER_FEATURES_SEL, 1);
    wr(t, reg::DRIVER_FEATURES, hi);
    wr(t, reg::STATUS, 11)
}

fn setup_queue<D: VirtioDevice>(t: &mut VirtioMmioTransport<D>, index: u32, base: u64) {
    wr(t, reg::QUEUE_SEL, index);
    wr(t, reg::QUEUE_NUM, 16);
    wr(t, reg::QUEUE_DESC_LOW, (DESC + base) as u32);
    wr(t, reg::QUEUE_DRIVER_LOW, (AVAIL + base) as u32);
    wr(t, reg::QUEUE_DEVICE_LOW, (USED + base) as u32);
    wr(t, reg::QUEUE_READY, 1);
}

/// 提示値どおりに交渉し、`queues` 本のキューを設定して DRIVER_OK まで進める。
fn init_to_driver_ok<D: VirtioDevice>(t: &mut VirtioMmioTransport<D>, queues: u32) {
    let lo = features_page(t, 0);
    assert_eq!(negotiate(t, lo, 1), MmioWriteOutcome::FeaturesAccepted);
    for i in 0..queues {
        setup_queue(t, i, u64::from(i) * 0x4000);
    }
    assert_eq!(wr(t, reg::STATUS, 15), MmioWriteOutcome::DeviceActivated);
}

fn ring_reset_bit_in_hi(hi: u32) -> u32 {
    (hi >> (VIRTIO_F_RING_RESET_BIT - 32)) & 1
}

/// MVM-1・MVM-5: block は上位ページに VERSION_1 だけを出し、RING_RESET を提示しない。
#[test]
fn mvm1_4169_block_does_not_offer_ring_reset() {
    for (read_only, lo) in [(false, 0x206u32), (true, 0x226u32)] {
        let mut t = blk(read_only);
        assert_eq!(features_page(&mut t, 0), lo);
        let hi = features_page(&mut t, 1);
        assert_eq!(hi, 0x0000_0001);
        assert_eq!(ring_reset_bit_in_hi(hi), 0);
    }
}

/// MVM-1・MVM-5: net も RING_RESET を提示しない。
#[test]
fn mvm1_4169_net_does_not_offer_ring_reset() {
    let mut t = net();
    assert_eq!(features_page(&mut t, 0), 0x20);
    let hi = features_page(&mut t, 1);
    assert_eq!(hi, 0x0000_0001);
    assert_eq!(ring_reset_bit_in_hi(hi), 0);
}

fn assert_ring_reset_rejected<D: VirtioDevice>(mut t: VirtioMmioTransport<D>) {
    let lo = features_page(&mut t, 0);
    let want_hi = 1 | (1 << (VIRTIO_F_RING_RESET_BIT - 32));
    assert_eq!(want_hi, 0x0000_0101);
    assert_eq!(
        negotiate(&mut t, lo, want_hi),
        MmioWriteOutcome::FeaturesRejected
    );
    // FEATURES_OK(8) が立たず ACKNOWLEDGE|DRIVER の 3 のまま。
    assert_eq!(rd(&t, reg::STATUS), 3);
    assert_eq!(t.negotiated_features(), None);
}

/// MVM-1・MVM-5: ドライバが RING_RESET を要求しても交渉は通らない（fail-closed）。
/// 対照として、上位を VERSION_1 だけにした同じ手順は通る（拒否の理由がビット 40 だけであることを示す）。
#[test]
fn mvm1_4169_driver_requesting_ring_reset_is_rejected() {
    assert_ring_reset_rejected(blk(false));
    assert_ring_reset_rejected(net());

    let mut b = blk(false);
    let lo = features_page(&mut b, 0);
    assert_eq!(negotiate(&mut b, lo, 1), MmioWriteOutcome::FeaturesAccepted);
    let mut n = net();
    let lo = features_page(&mut n, 0);
    assert_eq!(negotiate(&mut n, lo, 1), MmioWriteOutcome::FeaturesAccepted);
}

/// MVM-1・MVM-5: `QueueReset`（0x0c0）は未知のレジスタ。読み書きとも無視し、キューの状態を変えない。
#[test]
fn mvm1_4169_queue_reset_register_is_not_implemented() {
    let mut t = blk(false);
    init_to_driver_ok(&mut t, 1);
    wr(&mut t, reg::QUEUE_SEL, 0);
    assert_eq!(
        wr(&mut t, QUEUE_RESET, 1),
        MmioWriteOutcome::Ignored(IgnoredAccess::UnknownRegister)
    );
    let mut b = [0xffu8; 4];
    assert_eq!(
        t.read(QUEUE_RESET, &mut b),
        MmioReadOutcome::Ignored(IgnoredAccess::UnknownRegister)
    );
    assert_eq!(u32::from_le_bytes(b), 0);
    assert!(t.queue(0).unwrap().ready());
    assert_eq!(rd(&t, reg::QUEUE_READY), 1);
}

/// MVM-1・MVM-5: block で DRIVER_OK 後に止めたキューは QueueReady=1 で再開しない。復帰は Status=0 から。
#[test]
fn mvm1_4169_block_reenable_after_driver_ok_is_ignored() {
    let mut t = blk(false);
    let mut m = mem();
    init_to_driver_ok(&mut t, 1);
    wr(&mut t, reg::QUEUE_SEL, 0);

    // ready のままの 1 も動作開始後は受けない。
    assert_eq!(
        wr(&mut t, reg::QUEUE_READY, 1),
        MmioWriteOutcome::Ignored(IgnoredAccess::WrongDeviceState)
    );
    assert_eq!(
        wr(&mut t, reg::QUEUE_READY, 0),
        MmioWriteOutcome::QueueStopped(0)
    );
    assert_eq!(
        wr(&mut t, reg::QUEUE_READY, 1),
        MmioWriteOutcome::Ignored(IgnoredAccess::WrongDeviceState)
    );
    assert_eq!(rd(&t, reg::QUEUE_READY), 0);
    assert!(!t.queue(0).unwrap().ready());
    assert_eq!(
        wr(&mut t, reg::QUEUE_DESC_LOW, 0x1000),
        MmioWriteOutcome::Ignored(IgnoredAccess::WrongDeviceState)
    );
    let err = t.device_mut().process_queue(&mut m).unwrap_err();
    assert_eq!(err.code(), MicrovmErrorCode::FailedPrecondition);

    // 復帰経路は Status=0 の reset と再初期化だけ。
    assert_eq!(wr(&mut t, reg::STATUS, 0), MmioWriteOutcome::DeviceReset);
    init_to_driver_ok(&mut t, 1);
    assert!(t.queue(0).unwrap().ready());
}

/// MVM-1・MVM-5: net で tx だけ止めた場合も再有効化されず、止めていない rx は動く。
#[test]
fn mvm1_4169_net_reenable_after_driver_ok_is_ignored() {
    let mut t = net();
    let mut m = mem();
    init_to_driver_ok(&mut t, 2);
    wr(&mut t, reg::QUEUE_SEL, 1);
    assert_eq!(
        wr(&mut t, reg::QUEUE_READY, 0),
        MmioWriteOutcome::QueueStopped(1)
    );
    assert_eq!(
        wr(&mut t, reg::QUEUE_READY, 1),
        MmioWriteOutcome::Ignored(IgnoredAccess::WrongDeviceState)
    );
    assert_eq!(rd(&t, reg::QUEUE_READY), 0);
    let err = t.device_mut().process_tx(&mut m).unwrap_err();
    assert_eq!(err.code(), MicrovmErrorCode::FailedPrecondition);
    t.device_mut().process_rx(&mut m).unwrap();

    assert_eq!(wr(&mut t, reg::STATUS, 0), MmioWriteOutcome::DeviceReset);
    init_to_driver_ok(&mut t, 2);
    assert!(t.queue(1).unwrap().ready());
}
