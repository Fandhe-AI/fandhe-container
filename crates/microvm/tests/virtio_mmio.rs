//! virtio-mmio トランスポートの結合試験（MVM-1・TASK-74.2.1・#877）。
//!
//! 公開 API だけを使い、外部の `VirtioDevice` 実装に対するトランスポートの契約（識別レジスタ・
//! feature negotiation・activate への設定の伝達・通知・停止・reset）を具体値で確認する。
//! KVM は不要で、既定のテスト集合で走る。

use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
use fandhe_container_microvm::virtio_mmio::{
    FeatureBits, MmioReadOutcome, MmioWriteOutcome, QueueConfig, VirtioDevice, VirtioDeviceType,
    VirtioMmioTransport, reg,
};

#[derive(Default)]
struct Probe {
    activated: Option<(FeatureBits, Vec<QueueConfig>)>,
    resets: u32,
}

impl VirtioDevice for Probe {
    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::Block
    }
    fn device_features(&self) -> FeatureBits {
        FeatureBits::from_bits(0x1234)
    }
    fn queue_max_sizes(&self) -> &[u16] {
        &[256, 128]
    }
    fn read_config(&self, _offset: u64, data: &mut [u8]) {
        data.fill(0xab);
    }
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}
    fn activate(&mut self, f: FeatureBits, q: &[QueueConfig]) -> Result<(), MicrovmError> {
        self.activated = Some((f, q.to_vec()));
        Ok(())
    }
    fn reset(&mut self) {
        self.resets += 1;
    }
}

type T = VirtioMmioTransport<Probe>;

fn rd(t: &T, off: u64) -> u32 {
    let mut b = [0u8; 4];
    assert_eq!(t.read(off, &mut b), MmioReadOutcome::Handled);
    u32::from_le_bytes(b)
}

fn wr(t: &mut T, off: u64, v: u32) -> MmioWriteOutcome {
    t.write(off, &v.to_le_bytes())
}

fn setup_queue(t: &mut T, i: u32, size: u32) {
    wr(t, reg::QUEUE_SEL, i);
    assert_eq!(wr(t, reg::QUEUE_NUM, size), MmioWriteOutcome::Handled);
    wr(t, reg::QUEUE_DESC_LOW, 0x1000);
    wr(t, reg::QUEUE_DESC_HIGH, 0x1);
    wr(t, reg::QUEUE_DRIVER_LOW, 0x2002);
    wr(t, reg::QUEUE_DEVICE_LOW, 0x3004);
    assert_eq!(wr(t, reg::QUEUE_READY, 1), MmioWriteOutcome::Handled);
}

/// 識別レジスタと feature の提示（VERSION_1 を常に加える）。
#[test]
fn mvm1_877_identification_and_offered_features() {
    let t = VirtioMmioTransport::new(Probe::default()).unwrap();
    assert_eq!(rd(&t, reg::MAGIC), 0x7472_6976);
    assert_eq!(rd(&t, reg::VERSION), 2);
    assert_eq!(rd(&t, reg::DEVICE_ID), 2);
    assert_eq!(rd(&t, reg::VENDOR_ID), 0);
    let mut t = t;
    wr(&mut t, reg::DEVICE_FEATURES_SEL, 0);
    assert_eq!(rd(&t, reg::DEVICE_FEATURES), 0x1234);
    wr(&mut t, reg::DEVICE_FEATURES_SEL, 1);
    assert_eq!(rd(&t, reg::DEVICE_FEATURES), 1);
}

/// 初期化から DRIVER_OK までで activate に feature とキュー設定が渡り、通知・停止・reset が働く。
#[test]
fn mvm1_877_activate_notify_stop_reset() {
    let mut t = VirtioMmioTransport::new(Probe::default()).unwrap();
    assert_eq!(wr(&mut t, reg::STATUS, 1), MmioWriteOutcome::Handled);
    assert_eq!(wr(&mut t, reg::STATUS, 3), MmioWriteOutcome::Handled);
    wr(&mut t, reg::DRIVER_FEATURES_SEL, 0);
    wr(&mut t, reg::DRIVER_FEATURES, 0x1234);
    wr(&mut t, reg::DRIVER_FEATURES_SEL, 1);
    wr(&mut t, reg::DRIVER_FEATURES, 1);
    assert_eq!(
        wr(&mut t, reg::STATUS, 11),
        MmioWriteOutcome::FeaturesAccepted
    );
    setup_queue(&mut t, 0, 64);
    setup_queue(&mut t, 1, 32);
    assert_eq!(
        wr(&mut t, reg::STATUS, 15),
        MmioWriteOutcome::DeviceActivated
    );

    let (feat, queues) = t.device().activated.clone().unwrap();
    assert_eq!(feat, FeatureBits::from_bits(0x1234 | (1 << 32)));
    assert_eq!(queues.len(), 2);
    assert_eq!(queues[0].size(), 64);
    assert_eq!(queues[0].max_size(), 256);
    assert!(queues[0].ready());
    assert_eq!(queues[0].desc_table(), 0x1_0000_1000);
    assert_eq!(queues[0].driver_area(), 0x2002);
    assert_eq!(queues[0].device_area(), 0x3004);
    assert_eq!(queues[1].size(), 32);

    assert_eq!(
        wr(&mut t, reg::QUEUE_NOTIFY, 1),
        MmioWriteOutcome::QueueNotify(1)
    );

    wr(&mut t, reg::QUEUE_SEL, 0);
    assert_eq!(
        wr(&mut t, reg::QUEUE_READY, 0),
        MmioWriteOutcome::QueueStopped(0)
    );

    assert_eq!(wr(&mut t, reg::STATUS, 0), MmioWriteOutcome::DeviceReset);
    assert_eq!(t.device().resets, 1);
    assert_eq!(rd(&t, reg::STATUS), 0);
    assert!(!t.queue(1).unwrap().ready());
}

/// 提示外の feature を要求すると FEATURES_OK が立たない。
#[test]
fn mvm1_877_unoffered_feature_rejected() {
    let mut t = VirtioMmioTransport::new(Probe::default()).unwrap();
    wr(&mut t, reg::STATUS, 1);
    wr(&mut t, reg::STATUS, 3);
    wr(&mut t, reg::DRIVER_FEATURES_SEL, 0);
    wr(&mut t, reg::DRIVER_FEATURES, 0x8000_0000);
    assert_eq!(
        wr(&mut t, reg::STATUS, 11),
        MmioWriteOutcome::FeaturesRejected
    );
    assert_eq!(rd(&t, reg::STATUS) & 8, 0);
    assert!(t.device().activated.is_none());
}

/// キュー数が範囲外のデバイスは `new` で拒否される。
#[test]
fn mvm1_877_new_rejects_bad_queue_count() {
    #[derive(Debug)]
    struct NoQueue;
    impl VirtioDevice for NoQueue {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Net
        }
        fn device_features(&self) -> FeatureBits {
            FeatureBits::EMPTY
        }
        fn queue_max_sizes(&self) -> &[u16] {
            &[0u16; 9]
        }
        fn read_config(&self, _: u64, _: &mut [u8]) {}
        fn write_config(&mut self, _: u64, _: &[u8]) {}
        fn activate(&mut self, _: FeatureBits, _: &[QueueConfig]) -> Result<(), MicrovmError> {
            Ok(())
        }
        fn reset(&mut self) {}
    }
    let e = VirtioMmioTransport::new(NoQueue).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
}
