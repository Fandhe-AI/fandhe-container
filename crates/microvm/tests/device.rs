//! VM exit 振り分け経由の virtio デバイスモデル結合試験（MVM-1・TASK-74.5・#693）。
//!
//! `tests/virtio_block.rs`・`tests/virtio_net.rs` はトランスポートのメソッドを直接呼ぶ。本ファイルは
//! vCPU が返す `VcpuExit::Mmio` を `ExitDispatcher::dispatch` へ渡し、本物の `VirtioMmioTransport`
//! （virtio-block / virtio-net）まで届く合成経路を具体値で照合する。`device::VcpuFd::handle_exit` が
//! 実機でたどる経路のうち KVM を除いた部分に当たる。KVM 不要で、既定のテスト集合で 3 OS とも走る
//! （`device` / `irq` モジュールは Linux 限定のため使わない）。

use std::sync::{Arc, Mutex};

use fandhe_container_microvm::dispatch::{
    DeviceId, DispatchOutcome, ExitDispatcher, MmioAccess, MmioDevice, UnhandledAccess,
};
use fandhe_container_microvm::error::{MicrovmError, MicrovmErrorCode};
use fandhe_container_microvm::exit::{IoDirection, VcpuExit};
use fandhe_container_microvm::guest_memory::{GuestAddress, GuestMemory, HeapBacking};
use fandhe_container_microvm::interrupt::{
    InterruptDelivery, InterruptLine, NetQueueStats, complete_block_notify, complete_net_notify,
};
use fandhe_container_microvm::virtio_block::{MemoryBlockBackend, VirtioBlock};
use fandhe_container_microvm::virtio_mmio::{
    MAGIC_VALUE, MmioReadOutcome, MmioWriteOutcome, VirtioMmioTransport, reg,
};
use fandhe_container_microvm::virtio_net::{MemoryNetBackend, VirtioNet};

type Mem = GuestMemory<HeapBacking>;
type Blk = VirtioMmioTransport<VirtioBlock<MemoryBlockBackend>>;
type Net = VirtioMmioTransport<VirtioNet<MemoryNetBackend>>;

const BLK_BASE: u64 = 0x0a00_0000;
const NET_BASE: u64 = 0x0a00_0200;
const WINDOW: u64 = 0x200;
const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

const DESC: u64 = 0x1000;
const AVAIL: u64 = 0x2000;
const USED: u64 = 0x3000;
const HDR: u64 = 0x10000;
const DATA: u64 = 0x11000;
const STATUS: u64 = 0x12000;

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

/// ディスパッチャーへ所有を渡しつつ、試験側も同じトランスポートを触るための共有ラッパー。
struct Shared<D>(Arc<Mutex<D>>);

impl MmioDevice for Shared<Blk> {
    fn read(&self, offset: u64, data: &mut [u8]) -> MmioReadOutcome {
        self.0.lock().expect("lock").read(offset, data)
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
        self.0.lock().expect("lock").write(offset, data)
    }
}

impl MmioDevice for Shared<Net> {
    fn read(&self, offset: u64, data: &mut [u8]) -> MmioReadOutcome {
        self.0.lock().expect("lock").read(offset, data)
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
        self.0.lock().expect("lock").write(offset, data)
    }
}

/// 割り込み注入の回数を数える偽の割り込み線。
#[derive(Default)]
struct CountLine(std::cell::Cell<u32>);

impl InterruptLine for CountLine {
    fn trigger(&self) -> Result<(), MicrovmError> {
        self.0.set(self.0.get() + 1);
        Ok(())
    }
}

struct Bench {
    disp: ExitDispatcher,
    blk: Arc<Mutex<Blk>>,
    net: Arc<Mutex<Net>>,
    blk_id: DeviceId,
    net_id: DeviceId,
    mem: Mem,
}

fn bench() -> Bench {
    let blk = Arc::new(Mutex::new(
        VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap(),
    ));
    let net = Arc::new(Mutex::new(
        VirtioMmioTransport::new(VirtioNet::new(MemoryNetBackend::new(), MAC)).unwrap(),
    ));
    let mut disp = ExitDispatcher::new();
    let blk_id = disp
        .register_mmio(BLK_BASE, WINDOW, Box::new(Shared(blk.clone())))
        .unwrap();
    let net_id = disp
        .register_mmio(NET_BASE, WINDOW, Box::new(Shared(net.clone())))
        .unwrap();
    let mem = GuestMemory::new(ga(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
    Bench {
        disp,
        blk,
        net,
        blk_id,
        net_id,
        mem,
    }
}

fn mmio_exit(addr: u64, value: u32, is_write: bool) -> VcpuExit {
    let mut data = [0u8; 8];
    data[..4].copy_from_slice(&value.to_le_bytes());
    VcpuExit::Mmio {
        phys_addr: addr,
        data,
        len: 4,
        is_write,
    }
}

fn wr(d: &mut ExitDispatcher, addr: u64, v: u32) -> MmioWriteOutcome {
    match d.dispatch(&mmio_exit(addr, v, true)).unwrap() {
        DispatchOutcome::Mmio {
            access: MmioAccess::Write(o),
            ..
        } => o,
        other => panic!("expected mmio write, got {other:?}"),
    }
}

fn rd(d: &mut ExitDispatcher, addr: u64) -> u32 {
    let out = d.dispatch(&mmio_exit(addr, 0, false)).unwrap();
    let r = out.read_response().expect("read response");
    assert_eq!(r.len(), 4);
    u32::from_le_bytes([r[0], r[1], r[2], r[3]])
}

fn negotiate(d: &mut ExitDispatcher, base: u64, expect_low: Option<u32>) {
    wr(d, base + reg::STATUS, 1);
    wr(d, base + reg::STATUS, 3);
    wr(d, base + reg::DEVICE_FEATURES_SEL, 0);
    let low = rd(d, base + reg::DEVICE_FEATURES);
    if let Some(e) = expect_low {
        assert_eq!(low, e);
    }
    wr(d, base + reg::DRIVER_FEATURES_SEL, 0);
    wr(d, base + reg::DRIVER_FEATURES, low);
    wr(d, base + reg::DRIVER_FEATURES_SEL, 1);
    wr(d, base + reg::DRIVER_FEATURES, 1);
    assert_eq!(
        wr(d, base + reg::STATUS, 11),
        MmioWriteOutcome::FeaturesAccepted
    );
}

fn setup_queue(d: &mut ExitDispatcher, base: u64, q: u32, desc: u64, avail: u64, used: u64) {
    wr(d, base + reg::QUEUE_SEL, q);
    wr(d, base + reg::QUEUE_NUM, 16);
    wr(d, base + reg::QUEUE_DESC_LOW, desc as u32);
    wr(d, base + reg::QUEUE_DRIVER_LOW, avail as u32);
    wr(d, base + reg::QUEUE_DEVICE_LOW, used as u32);
    wr(d, base + reg::QUEUE_READY, 1);
}

fn init_block(d: &mut ExitDispatcher) {
    negotiate(d, BLK_BASE, None);
    setup_queue(d, BLK_BASE, 0, DESC, AVAIL, USED);
    assert_eq!(
        wr(d, BLK_BASE + reg::STATUS, 15),
        MmioWriteOutcome::DeviceActivated
    );
}

fn init_net(d: &mut ExitDispatcher) {
    negotiate(d, NET_BASE, Some(1 << 5));
    setup_queue(d, NET_BASE, 0, RX_DESC, RX_AVAIL, RX_USED);
    setup_queue(d, NET_BASE, 1, TX_DESC, TX_AVAIL, TX_USED);
    assert_eq!(
        wr(d, NET_BASE + reg::STATUS, 15),
        MmioWriteOutcome::DeviceActivated
    );
}

fn blk_desc(m: &mut Mem, i: u64, addr: u64, len: u32, flags: u16, next: u16) {
    let at = DESC + i * 16;
    m.write_at(ga(at), &addr.to_le_bytes()).unwrap();
    m.write_u32_le(ga(at + 8), len).unwrap();
    m.write_u16_le(ga(at + 12), flags).unwrap();
    m.write_u16_le(ga(at + 14), next).unwrap();
}

/// [header R][data][status W] を avail の `slot` に積む（`tests/virtio_block.rs` と同じ配置）。
fn blk_submit(m: &mut Mem, slot: u16, ty: u32, sector: u64, len: u32, data_flags: u16) {
    m.write_u32_le(ga(HDR), ty).unwrap();
    m.write_at(ga(HDR + 8), &sector.to_le_bytes()).unwrap();
    blk_desc(m, 0, HDR, 16, 1, 1);
    blk_desc(m, 1, DATA, len, data_flags | 1, 2);
    blk_desc(m, 2, STATUS, 1, 2, 0);
    m.write_at(ga(STATUS), &[0xff]).unwrap();
    m.write_u16_le(ga(AVAIL + 4 + 2 * u64::from(slot)), 0)
        .unwrap();
    m.write_u16_le(ga(AVAIL + 2), slot + 1).unwrap();
}

fn net_desc(m: &mut Mem, base: u64, i: u64, addr: u64, len: u32, flags: u16) {
    let at = base + i * 16;
    m.write_at(ga(at), &addr.to_le_bytes()).unwrap();
    m.write_u32_le(ga(at + 8), len).unwrap();
    m.write_u16_le(ga(at + 12), flags).unwrap();
    m.write_u16_le(ga(at + 14), 0).unwrap();
}

fn net_publish(m: &mut Mem, avail: u64, slot: u16) {
    m.write_u16_le(ga(avail + 4 + 2 * u64::from(slot)), slot)
        .unwrap();
    m.write_u16_le(ga(avail + 2), slot + 1).unwrap();
}

/// 受け入れ条件 1: 2 デバイスの識別レジスタが exit 経由で具体値のまま読める。
#[test]
fn mvm1_693_identification_via_dispatch() {
    let mut b = bench();
    assert_eq!((b.blk_id.index(), b.net_id.index()), (0, 1));
    for (base, id, dev_id) in [(BLK_BASE, b.blk_id, 2u32), (NET_BASE, b.net_id, 1u32)] {
        assert_eq!(rd(&mut b.disp, base + reg::MAGIC), MAGIC_VALUE);
        assert_eq!(rd(&mut b.disp, base + reg::VERSION), 2);
        assert_eq!(rd(&mut b.disp, base + reg::DEVICE_ID), dev_id);
        match b.disp.dispatch(&mmio_exit(base, 0, false)).unwrap() {
            DispatchOutcome::Mmio { device, .. } => assert_eq!(device, id),
            other => panic!("unexpected {other:?}"),
        }
    }
}

/// 範囲外・境界またぎは開いたバス（0xFF）で、ホスト側の誤用は `InvalidArgument`。
#[test]
fn mvm1_693_unhandled_access_is_open_bus() {
    let mut b = bench();
    let out = b.disp.dispatch(&mmio_exit(0x0900_0000, 0, false)).unwrap();
    assert!(matches!(
        out,
        DispatchOutcome::Unhandled {
            access: UnhandledAccess::Mmio {
                phys_addr: 0x0900_0000,
                len: 4,
                is_write: false
            },
            ..
        }
    ));
    assert_eq!(out.read_response(), Some(&[0xFF; 4][..]));

    // 2 範囲の境界をまたぐアクセスはどちらにも当たらない。
    let out = b.disp.dispatch(&mmio_exit(NET_BASE - 2, 0, false)).unwrap();
    assert!(matches!(out, DispatchOutcome::Unhandled { .. }));
    assert_eq!(out.read_response(), Some(&[0xFF; 4][..]));

    let out = b.disp.dispatch(&mmio_exit(0x0900_0000, 7, true)).unwrap();
    assert!(matches!(out, DispatchOutcome::Unhandled { .. }));
    assert_eq!(out.read_response(), None);

    let io = VcpuExit::Io {
        direction: IoDirection::In,
        port: 0x3f8,
        size: 1,
        count: 2,
        data: vec![],
    };
    assert_eq!(
        b.disp.dispatch(&io).unwrap().read_response(),
        Some(&[0xFF, 0xFF][..])
    );

    let e = b.disp.dispatch(&VcpuExit::Hlt).unwrap_err();
    assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
}

/// 受け入れ条件 1: virtio-block の write → read が exit 経由の kick で通り、割り込みも具体値で数えられる。
#[test]
fn mvm1_693_block_write_then_read_via_dispatch() {
    let mut b = bench();
    init_block(&mut b.disp);
    let line = CountLine::default();

    let payload: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    b.mem.write_at(ga(DATA), &payload).unwrap();
    blk_submit(&mut b.mem, 0, 1, 2, 1024, 0);
    assert_eq!(
        wr(&mut b.disp, BLK_BASE + reg::QUEUE_NOTIFY, 0),
        MmioWriteOutcome::QueueNotify(0)
    );
    let r = {
        let mut t = b.blk.lock().unwrap();
        complete_block_notify(&mut t, &mut b.mem, &line).unwrap()
    };
    assert_eq!((r.stats.completed, r.stats.ok), (1, 1));
    assert_eq!(r.delivery, InterruptDelivery::Triggered);
    assert_eq!(line.0.get(), 1);
    let mut st = [0u8; 1];
    b.mem.read_at(ga(STATUS), &mut st).unwrap();
    assert_eq!(st, [0]);
    assert_eq!(b.mem.read_u16_le(ga(USED + 2)).unwrap(), 1);
    assert_eq!(
        &b.blk.lock().unwrap().device().backend().contents()[1024..2048],
        &payload[..]
    );

    // 割り込み状態は exit 経由の読みで 1（UsedBuffer）、ACK で 0。
    assert_eq!(rd(&mut b.disp, BLK_BASE + reg::INTERRUPT_STATUS), 1);
    wr(&mut b.disp, BLK_BASE + reg::INTERRUPT_ACK, 1);
    assert_eq!(rd(&mut b.disp, BLK_BASE + reg::INTERRUPT_STATUS), 0);

    // 同じ sector を読み戻す。
    b.mem.write_at(ga(DATA), &[0u8; 1024]).unwrap();
    blk_submit(&mut b.mem, 1, 0, 2, 1024, 2);
    assert_eq!(
        wr(&mut b.disp, BLK_BASE + reg::QUEUE_NOTIFY, 0),
        MmioWriteOutcome::QueueNotify(0)
    );
    {
        let mut t = b.blk.lock().unwrap();
        let r = complete_block_notify(&mut t, &mut b.mem, &line).unwrap();
        assert_eq!((r.stats.completed, r.stats.ok), (1, 1));
    }
    let mut got = vec![0u8; 1024];
    b.mem.read_at(ga(DATA), &mut got).unwrap();
    assert_eq!(got, payload);
    assert_eq!(b.mem.read_u16_le(ga(USED + 2)).unwrap(), 2);
    assert_eq!(line.0.get(), 2);
}

/// 受け入れ条件 1: virtio-net の送信（tx）と受信（rx）が exit 経由の kick で通る。
#[test]
fn mvm1_693_net_tx_and_rx_via_dispatch() {
    let mut b = bench();
    init_net(&mut b.disp);
    let line = CountLine::default();

    // 設定空間から MAC が exit 経由で読める。
    for (i, want) in MAC.iter().enumerate() {
        let out = b
            .disp
            .dispatch(&VcpuExit::Mmio {
                phys_addr: NET_BASE + 0x100 + i as u64,
                data: [0; 8],
                len: 1,
                is_write: false,
            })
            .unwrap();
        assert_eq!(out.read_response(), Some(&[*want][..]));
    }

    // 送信: ヘッダ 12 バイト + 64 バイトのフレーム。
    let out: Vec<u8> = (0..64u32).map(|i| (i % 251) as u8).collect();
    let mut data = vec![0u8; 12];
    data.extend_from_slice(&out);
    b.mem.write_at(ga(TX_BUF), &data).unwrap();
    net_desc(&mut b.mem, TX_DESC, 0, TX_BUF, data.len() as u32, 0);
    net_publish(&mut b.mem, TX_AVAIL, 0);
    assert_eq!(
        wr(&mut b.disp, NET_BASE + reg::QUEUE_NOTIFY, 1),
        MmioWriteOutcome::QueueNotify(1)
    );
    let r = {
        let mut t = b.net.lock().unwrap();
        complete_net_notify(&mut t, &mut b.mem, 1, &line).unwrap()
    };
    match r.stats {
        NetQueueStats::Tx(s) => assert_eq!((s.completed, s.sent), (1, 1)),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(r.delivery, InterruptDelivery::Triggered);
    assert_eq!(line.0.get(), 1);
    assert_eq!(
        b.net.lock().unwrap().device().backend().sent(),
        std::slice::from_ref(&out)
    );
    assert_eq!(b.mem.read_u16_le(ga(TX_USED + 2)).unwrap(), 1);

    // 受信: backend に 100 バイトのフレームを入れ、receiveq にバッファを積む。
    let inbound: Vec<u8> = (0..100u32).map(|i| (i % 241) as u8).collect();
    b.net
        .lock()
        .unwrap()
        .device_mut()
        .backend_mut()
        .push_inbound(&inbound)
        .unwrap();
    net_desc(&mut b.mem, RX_DESC, 0, RX_BUF, 2048, 2);
    net_publish(&mut b.mem, RX_AVAIL, 0);
    assert_eq!(
        wr(&mut b.disp, NET_BASE + reg::QUEUE_NOTIFY, 0),
        MmioWriteOutcome::QueueNotify(0)
    );
    let r = {
        let mut t = b.net.lock().unwrap();
        complete_net_notify(&mut t, &mut b.mem, 0, &line).unwrap()
    };
    match r.stats {
        NetQueueStats::Rx(s) => assert_eq!((s.completed, s.delivered), (1, 1)),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(line.0.get(), 2);
    let mut got = vec![0u8; 112];
    b.mem.read_at(ga(RX_BUF), &mut got).unwrap();
    assert_eq!(&got[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
    assert_eq!(&got[12..], &inbound[..]);
    assert_eq!(b.mem.read_u32_le(ga(RX_USED + 8)).unwrap(), 112);
}
