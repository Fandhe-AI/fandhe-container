//! virtqueue を使う結合試験の「ゲストのドライバ役」補助（MMIO 経由の初期化・記述子・avail への積み込み・割り込み線）の正本。
//!
//! 役割: ホスト側の試験が virtio デバイスモデルへ向けてゲストの手順（レジスタ列での初期化、記述子テーブルと avail リング
//! への書き込み）を演じる部分を 1 か所に置き、試験ごとの複製が食い違うのを防ぐ（REPAIR-1）。次の試験が `#[path]` で共有する:
//! `tests/virtio_block.rs`・`tests/queue_notify_route.rs`・`tests/virtio_net.rs`・`tests/net_queue_notify_route.rs`・
//! `tests/net_rx_poller.rs`・`tests/device.rs`・`tests/hvf_microvm.rs`（記述子のバイト列 `desc_bytes` のみ）。
//! OS 非依存にするため `guest_memory_slot`（Linux・macOS arm64 限定）には依存しない。`Fixture` 等は各試験に残す。
//! 対応: MVM-1・MVM-5・#4113（元の複製は #4026・#4028・#4029・#4030）。

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
use fandhe_container_microvm::interrupt::InterruptLine;
use fandhe_container_microvm::virtio_mmio::{
    MmioReadOutcome, MmioWriteOutcome, VirtioDevice, VirtioMmioTransport, reg,
};

type Mem = GuestMemory<HeapBacking>;

/// 記述子 1 件（16 バイト）のワイヤー配置: addr u64 LE @0・len u32 @8・flags u16 @12・next u16 @14。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn desc_bytes(addr: u64, len: u32, flags: u16, next: u16) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&addr.to_le_bytes());
    b[8..12].copy_from_slice(&len.to_le_bytes());
    b[12..14].copy_from_slice(&flags.to_le_bytes());
    b[14..16].copy_from_slice(&next.to_le_bytes());
    b
}

#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn ga(a: u64) -> GuestAddress {
    GuestAddress::new(a)
}

/// 32 bit のレジスタ書き込み。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn wr<D: VirtioDevice>(t: &mut VirtioMmioTransport<D>, off: u64, v: u32) -> MmioWriteOutcome {
    t.write(off, &v.to_le_bytes())
}

/// `table` の `i` 番の記述子を書く。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn write_desc(m: &mut Mem, table: u64, i: u64, addr: u64, len: u32, flags: u16, next: u16) {
    m.write_at(ga(table + i * 16), &desc_bytes(addr, len, flags, next))
        .unwrap();
}

/// avail の ring[`slot`] = `slot`、idx = `slot` + 1 とする。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
pub fn publish(m: &mut Mem, avail: u64, slot: u16) {
    m.write_u16_le(ga(avail + 4 + 2 * u64::from(slot)), slot)
        .unwrap();
    m.write_u16_le(ga(avail + 2), slot + 1).unwrap();
}

/// 割り込みを数える偽の割り込み線（`Send + Sync`。`fail` なら `trigger` が失敗する）。
#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
#[derive(Clone, Default)]
pub struct CountLine {
    hits: Arc<AtomicU32>,
    fail: bool,
}

#[allow(dead_code, reason = "取り込み元の試験によっては使わない共有補助")]
impl CountLine {
    pub fn new(fail: bool) -> Self {
        Self {
            hits: Arc::new(AtomicU32::new(0)),
            fail,
        }
    }

    pub fn count(&self) -> u32 {
        self.hits.load(Ordering::SeqCst)
    }
}

impl InterruptLine for CountLine {
    fn trigger(&self) -> Result<(), MicrovmError> {
        if self.fail {
            return Err(MicrovmError::new(MicrovmErrorCode::Internal, "line down"));
        }
        self.hits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// virtio-block（queue 0）のゲスト側の配置と手順。
pub mod block {
    use super::*;
    use fandhe_container_microvm::virtio_block::{MemoryBlockBackend, VirtioBlock};

    #[allow(
        dead_code,
        reason = "virtio-block を使わない取り込み元の試験では参照されない"
    )]
    pub const DESC: u64 = 0x1000;
    #[allow(
        dead_code,
        reason = "virtio-block を使わない取り込み元の試験では参照されない"
    )]
    pub const AVAIL: u64 = 0x2000;
    #[allow(
        dead_code,
        reason = "virtio-block を使わない取り込み元の試験では参照されない"
    )]
    pub const USED: u64 = 0x3000;
    #[allow(
        dead_code,
        reason = "virtio-block を使わない取り込み元の試験では参照されない"
    )]
    pub const HDR: u64 = 0x10000;
    #[allow(
        dead_code,
        reason = "virtio-block を使わない取り込み元の試験では参照されない"
    )]
    pub const DATA: u64 = 0x11000;
    #[allow(
        dead_code,
        reason = "virtio-block を使わない取り込み元の試験では参照されない"
    )]
    pub const STATUS: u64 = 0x12000;

    /// MMIO レジスタ経由でデバイスを activate する（提示された feature をそのまま受け、queue 0 を設定する）。
    #[allow(
        dead_code,
        reason = "virtio-block を使わない取り込み元の試験では参照されない"
    )]
    pub fn init(t: &mut VirtioMmioTransport<VirtioBlock<MemoryBlockBackend>>) {
        wr(t, reg::STATUS, 1);
        wr(t, reg::STATUS, 3);
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

    #[allow(
        dead_code,
        reason = "virtio-block を使わない取り込み元の試験では参照されない"
    )]
    pub fn desc(m: &mut Mem, i: u64, addr: u64, len: u32, flags: u16, next: u16) {
        write_desc(m, DESC, i, addr, len, flags, next);
    }

    /// head=0 の [header R][data][status W] を avail の `slot` に積む。
    #[allow(
        dead_code,
        reason = "virtio-block を使わない取り込み元の試験では参照されない"
    )]
    pub fn submit(m: &mut Mem, slot: u16, ty: u32, sector: u64, len: u32, data_flags: u16) {
        m.write_u32_le(ga(HDR), ty).unwrap();
        m.write_at(ga(HDR + 8), &sector.to_le_bytes()).unwrap();
        desc(m, 0, HDR, 16, 1, 1);
        desc(m, 1, DATA, len, data_flags | 1, 2);
        desc(m, 2, STATUS, 1, 2, 0);
        m.write_at(ga(STATUS), &[0xff]).unwrap();
        let a = AVAIL + 4 + 2 * u64::from(slot);
        m.write_u16_le(ga(a), 0).unwrap();
        m.write_u16_le(ga(AVAIL + 2), slot + 1).unwrap();
    }
}

/// virtio-net（queue 0 = receiveq・queue 1 = transmitq）のゲスト側の配置と手順。
pub mod net {
    use super::*;
    use fandhe_container_microvm::virtio_net::{MemoryNetBackend, VirtioNet};

    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub const RX_DESC: u64 = 0x1000;
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub const RX_AVAIL: u64 = 0x2000;
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub const RX_USED: u64 = 0x3000;
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub const TX_DESC: u64 = 0x4000;
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub const TX_AVAIL: u64 = 0x5000;
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub const TX_USED: u64 = 0x6000;
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub const TX_BUF: u64 = 0x10000;
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub const RX_BUF: u64 = 0x11000;

    /// MMIO レジスタ経由でデバイスを activate する（VIRTIO_NET_F_MAC を受け、2 キューを設定する）。
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub fn init(t: &mut VirtioMmioTransport<VirtioNet<MemoryNetBackend>>) {
        wr(t, reg::STATUS, 1);
        wr(t, reg::STATUS, 3);
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

    /// `base` の記述子テーブルの `i` 番を書く（next = 0）。
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub fn desc(m: &mut Mem, base: u64, i: u64, addr: u64, len: u32, flags: u16) {
        write_desc(m, base, i, addr, len, flags, 0);
    }

    pub use super::publish;

    /// transmitq の `slot` へ（ヘッダ 12 バイト + 64 バイトのフレーム）を積み、フレームを返す。
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub fn submit_tx(m: &mut Mem, slot: u16) -> Vec<u8> {
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
    #[allow(
        dead_code,
        reason = "virtio-net を使わない取り込み元の試験では参照されない"
    )]
    pub fn submit_rx(m: &mut Mem) {
        desc(m, RX_DESC, 0, RX_BUF, 2048, 2);
        publish(m, RX_AVAIL, 0);
    }
}
