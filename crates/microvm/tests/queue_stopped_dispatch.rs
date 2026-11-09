//! VM exit 振り分け経由の `VirtioDevice::queue_stopped` 受け入れ試験（#4168・#4031・MVM-1・MVM-5）。
//!
//! `DeviceBus` が組む経路（`ExitDispatcher` + 共有トランスポート）へ `VcpuExit::Mmio` で
//! QueueReady=0 / Status=0 を書き、`queue_stopped` / `reset` の呼び出しを数える。`DeviceBus`・
//! `SharedTransport` は crate 内限定のため、`tests/device.rs` と同じ組み立てを試験側の `Shared<D>` で
//! 再現する（device.rs の補助と重複するのは、dispatcher 越しの初期化が共有の対象外のため。REPAIR-1）。
//! KVM 不要で既定のテスト集合（3 OS）で走る。本番の組み立て（`DeviceBus` の `dispatch_exit` と macOS の `HvfDeviceBus`）を通る経路は、`HvfDeviceBus` については `hvf_device_bus` の `mvm5_4293_*`（偽の GIC の線。HVF 不要）も既定の集合で照合する。実 GIC の線を通す経路は
//! #4231 の試験（`microvm.rs` の `mvm1_4231_*`・`hvf/mmio.rs` の `mvm5_4231_*`・`tests/hvf_device.rs`）が担う。停止後のリング処理への効果はトランスポート層の試験
//! （#4093）が担う。

use std::sync::{Arc, Mutex};

use fandhe_container_microvm::dispatch::{DispatchOutcome, ExitDispatcher, MmioAccess, MmioDevice};
use fandhe_container_microvm::error::MicrovmError;
use fandhe_container_microvm::exit::VcpuExit;
use fandhe_container_microvm::virtio_block::{MemoryBlockBackend, VirtioBlock};
use fandhe_container_microvm::virtio_mmio::{
    FeatureBits, IgnoredAccess, MmioReadOutcome, MmioWriteOutcome, QueueConfig, VirtioDevice,
    VirtioDeviceType, VirtioMmioTransport, reg,
};
use fandhe_container_microvm::virtio_net::{MemoryNetBackend, VirtioNet};

const BLK_BASE: u64 = 0x0a00_0000;
const NET_BASE: u64 = 0x0a00_0200;
const WINDOW: u64 = 0x200;
const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// 本物のデバイスへ委譲し、`queue_stopped` / `reset` の呼び出しだけを記録するアダプタ。
struct Recording<D: VirtioDevice> {
    inner: D,
    stopped: Vec<u16>,
    resets: u32,
}

impl<D: VirtioDevice> Recording<D> {
    fn new(inner: D) -> Self {
        Self {
            inner,
            stopped: Vec::new(),
            resets: 0,
        }
    }
}

impl<D: VirtioDevice> VirtioDevice for Recording<D> {
    fn device_type(&self) -> VirtioDeviceType {
        self.inner.device_type()
    }
    fn device_features(&self) -> FeatureBits {
        self.inner.device_features()
    }
    fn queue_max_sizes(&self) -> &[u16] {
        self.inner.queue_max_sizes()
    }
    fn read_config(&self, offset: u64, data: &mut [u8]) {
        self.inner.read_config(offset, data)
    }
    fn write_config(&mut self, offset: u64, data: &[u8]) {
        self.inner.write_config(offset, data)
    }
    fn accepts_features(&self, features: FeatureBits) -> bool {
        self.inner.accepts_features(features)
    }
    fn activate(&mut self, f: FeatureBits, q: &[QueueConfig]) -> Result<(), MicrovmError> {
        self.inner.activate(f, q)
    }
    fn queue_stopped(&mut self, index: u16) {
        self.stopped.push(index);
        self.inner.queue_stopped(index);
    }
    fn reset(&mut self) {
        self.resets += 1;
        self.inner.reset();
    }
}

type Blk = VirtioMmioTransport<Recording<VirtioBlock<MemoryBlockBackend>>>;
type Net = VirtioMmioTransport<Recording<VirtioNet<MemoryNetBackend>>>;

/// ディスパッチャーへ所有を渡しつつ、試験側も同じトランスポートを触るための共有ラッパー。
struct Shared<D: VirtioDevice>(Arc<Mutex<VirtioMmioTransport<D>>>);

impl<D: VirtioDevice + Send> MmioDevice for Shared<D> {
    fn read(&self, offset: u64, data: &mut [u8]) -> MmioReadOutcome {
        self.0.lock().expect("lock").read(offset, data)
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
        self.0.lock().expect("lock").write(offset, data)
    }
}

struct Bench {
    disp: ExitDispatcher,
    blk: Arc<Mutex<Blk>>,
    net: Arc<Mutex<Net>>,
}

fn bench() -> Bench {
    let blk = Arc::new(Mutex::new(
        VirtioMmioTransport::new(Recording::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        )))
        .unwrap(),
    ));
    let net = Arc::new(Mutex::new(
        VirtioMmioTransport::new(Recording::new(VirtioNet::new(MemoryNetBackend::new(), MAC)))
            .unwrap(),
    ));
    let mut disp = ExitDispatcher::new();
    disp.register_mmio(BLK_BASE, WINDOW, Box::new(Shared(blk.clone())))
        .unwrap();
    disp.register_mmio(NET_BASE, WINDOW, Box::new(Shared(net.clone())))
        .unwrap();
    Bench { disp, blk, net }
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

fn blk_rec(b: &Bench) -> (Vec<u16>, u32) {
    let t = b.blk.lock().unwrap();
    (t.device().stopped.clone(), t.device().resets)
}

fn net_rec(b: &Bench) -> (Vec<u16>, u32) {
    let t = b.net.lock().unwrap();
    (t.device().stopped.clone(), t.device().resets)
}

fn init_block(b: &mut Bench) {
    negotiate(&mut b.disp, BLK_BASE, None);
    setup_queue(&mut b.disp, BLK_BASE, 0, 0x1000, 0x2000, 0x3000);
    assert_eq!(
        wr(&mut b.disp, BLK_BASE + reg::STATUS, 15),
        MmioWriteOutcome::DeviceActivated
    );
    assert_eq!(blk_rec(b), (vec![], 0));
}

fn init_net(b: &mut Bench) {
    negotiate(&mut b.disp, NET_BASE, Some(1 << 5));
    setup_queue(&mut b.disp, NET_BASE, 0, 0x1000, 0x2000, 0x3000);
    setup_queue(&mut b.disp, NET_BASE, 1, 0x4000, 0x5000, 0x6000);
    assert_eq!(
        wr(&mut b.disp, NET_BASE + reg::STATUS, 15),
        MmioWriteOutcome::DeviceActivated
    );
    assert_eq!(net_rec(b), (vec![], 0));
}

/// block: DRIVER_OK 後の QueueReady=0 は dispatcher 越しにちょうど 1 回 `queue_stopped(0)`。
/// 同じ書き込みの繰り返しでは回数が増えない。
#[test]
fn mvm1_4168_block_queue_ready_zero_stops_once_via_dispatch() {
    let mut b = bench();
    init_block(&mut b);
    wr(&mut b.disp, BLK_BASE + reg::QUEUE_SEL, 0);
    assert_eq!(rd(&mut b.disp, BLK_BASE + reg::QUEUE_READY), 1);

    assert_eq!(
        wr(&mut b.disp, BLK_BASE + reg::QUEUE_READY, 0),
        MmioWriteOutcome::QueueStopped(0)
    );
    assert_eq!(blk_rec(&b), (vec![0], 0));
    assert_eq!(rd(&mut b.disp, BLK_BASE + reg::QUEUE_READY), 0);

    assert_eq!(
        wr(&mut b.disp, BLK_BASE + reg::QUEUE_READY, 0),
        MmioWriteOutcome::Handled
    );
    assert_eq!(blk_rec(&b), (vec![0], 0));
}

/// net: 対象のキューだけが止まり、他のキューは有効なまま。2 回目の書き込みは何も増やさない。
#[test]
fn mvm1_4168_net_queue_ready_zero_stops_only_target_queue_via_dispatch() {
    let mut b = bench();
    init_net(&mut b);

    wr(&mut b.disp, NET_BASE + reg::QUEUE_SEL, 1);
    assert_eq!(
        wr(&mut b.disp, NET_BASE + reg::QUEUE_READY, 0),
        MmioWriteOutcome::QueueStopped(1)
    );
    assert_eq!(net_rec(&b), (vec![1], 0));
    assert_eq!(rd(&mut b.disp, NET_BASE + reg::QUEUE_READY), 0);
    wr(&mut b.disp, NET_BASE + reg::QUEUE_SEL, 0);
    assert_eq!(rd(&mut b.disp, NET_BASE + reg::QUEUE_READY), 1);

    // queue 1 への 2 回目: 増えない。queue 0 は有効のまま。
    wr(&mut b.disp, NET_BASE + reg::QUEUE_SEL, 1);
    assert_eq!(
        wr(&mut b.disp, NET_BASE + reg::QUEUE_READY, 0),
        MmioWriteOutcome::Handled
    );
    assert_eq!(net_rec(&b), (vec![1], 0));
    wr(&mut b.disp, NET_BASE + reg::QUEUE_SEL, 0);
    assert_eq!(rd(&mut b.disp, NET_BASE + reg::QUEUE_READY), 1);

    // queue 0 を止める。
    assert_eq!(
        wr(&mut b.disp, NET_BASE + reg::QUEUE_READY, 0),
        MmioWriteOutcome::QueueStopped(0)
    );
    assert_eq!(net_rec(&b), (vec![1, 0], 0));
    assert_eq!(
        wr(&mut b.disp, NET_BASE + reg::QUEUE_READY, 0),
        MmioWriteOutcome::Handled
    );
    assert_eq!(net_rec(&b), (vec![1, 0], 0));
}

/// Status=0 の reset は `reset` を 1 回呼ぶだけで `queue_stopped` は呼ばない（block・net とも）。
/// reset 後の QueueReady=0 は FEATURES_OK が無いため無視され、呼び出しは増えない。
#[test]
fn mvm1_4168_status_reset_does_not_call_queue_stopped_via_dispatch() {
    let mut b = bench();
    init_block(&mut b);
    init_net(&mut b);

    assert_eq!(
        wr(&mut b.disp, BLK_BASE + reg::STATUS, 0),
        MmioWriteOutcome::DeviceReset
    );
    assert_eq!(
        wr(&mut b.disp, NET_BASE + reg::STATUS, 0),
        MmioWriteOutcome::DeviceReset
    );
    assert_eq!(blk_rec(&b), (vec![], 1));
    assert_eq!(net_rec(&b), (vec![], 1));
    assert_eq!(rd(&mut b.disp, BLK_BASE + reg::STATUS), 0);
    assert_eq!(rd(&mut b.disp, NET_BASE + reg::STATUS), 0);

    for base in [BLK_BASE, NET_BASE] {
        wr(&mut b.disp, base + reg::QUEUE_SEL, 0);
        assert_eq!(
            wr(&mut b.disp, base + reg::QUEUE_READY, 0),
            MmioWriteOutcome::Ignored(IgnoredAccess::WrongDeviceState)
        );
    }
    assert_eq!(blk_rec(&b), (vec![], 1));
    assert_eq!(net_rec(&b), (vec![], 1));
}
