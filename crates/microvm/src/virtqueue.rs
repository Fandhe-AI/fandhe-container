//! split virtqueue の走査と used リングへの書き戻し（TASK-74.2.2・MVM-1・MVM-4・MS-7。OS 非依存・unsafe なし）。
//!
//! virtio-block（`virtio_block`）と virtio-net（TASK-74.3.1）が共有する。トランスポート
//! （`virtio_mmio`）が整列を検査済みの [`QueueConfig`] とゲストメモリ（`guest_memory`）から
//! [`SplitQueue`] を組み立て、[`SplitQueue::pop`] で avail リングの記述子チェーンを 1 本取り出し、
//! デバイスが処理した後に [`SplitQueue::add_used`] で used リングへ返す。割り込みの配送は呼び出し元の責務
//! （TASK-74.2.3）。待ちを持たない同期処理なので REPAIR-5 のタイムアウトは不要。
//!
//! # 準拠先
//! OASIS "Virtual I/O Device (VIRTIO) Version 1.2" の 2.7（Split Virtqueues）。`EVENT_IDX`・`INDIRECT`・
//! packed は広告しないので扱わない（REPAIR-3）。順序（avail.idx を読んでから ring を読む・used 要素を書いてから
//! used.idx を書く）は fence で表す。コピー API は非アトミックなので、実機のバリアになることに依存する。
//!
//! # 外部入力の扱い
//! avail の idx・ring・記述子の内容はすべてゲストが書く非信頼入力。共有メモリから 1 回だけコピーし、検査と使用を
//! 同じ値で行う（TOCTOU 防止）。チェーン長・合計バイト数に上限を置く。失敗した `pop` は `last_avail` を進めず、
//! 壊れた要求を黙って捨てない。呼び出し元はリング破損のとき、デバイスの扱い（停止・リセット要求）を決める。

use std::fmt;
use std::sync::atomic::{Ordering, fence};

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestAddress, GuestMemory, GuestMemoryBacking};
use crate::virtio_mmio::QueueConfig;

/// 記述子の `flags`: 次の記述子へ続く。
pub const VRING_DESC_F_NEXT: u16 = 1;
/// 記述子の `flags`: デバイスが書き込む（書き込み可能）。
pub const VRING_DESC_F_WRITE: u16 = 2;
/// 記述子の `flags`: 間接記述子テーブル（非対応）。
pub const VRING_DESC_F_INDIRECT: u16 = 4;

/// 1 チェーンに含められる記述子数の上限（キュー長でも頭打ちにする）。
pub const MAX_CHAIN_LEN: usize = 128;
/// 1 チェーンの合計バイト数の上限（readable / writable それぞれ）。
pub const MAX_CHAIN_BYTES: u64 = 16 << 20;

const DESC_SIZE: u64 = 16;

/// virtqueue 処理の失敗の分類（固定語彙。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VirtqueueErrorCode {
    /// キューが ready でない・size が 0。
    InvalidQueueState,
    /// desc / avail / used のいずれかがゲストメモリの範囲外。
    RingOutOfRange,
    /// `avail.idx` が未処理数としてあり得ない値（キュー長を超えて進んでいる）。
    InvalidAvailIdx,
    /// head または next がキュー長以上。
    DescIndexOutOfRange,
    /// チェーンが同じ記述子を二度辿った。
    ChainLoop,
    /// 記述子数が上限を超えた。
    ChainTooLong,
    /// 合計バイト数が上限を超えた（現行の `pop` は `Err` にせず `oversized` で伝える。語彙は互換のため残す）。
    ChainTooLarge,
    /// INDIRECT が立っている（非対応）。
    IndirectUnsupported,
    /// 未定義の flags が立っている。
    InvalidDescFlags,
    /// 書き込み可能な記述子の後に読み取り専用が来た（仕様 2.7.4.2 違反）。
    ReadableAfterWritable,
    /// used に書く len が書き込み可能な合計を超えた。
    UsedLenExceedsWritable,
    /// 記述子のバッファがゲストメモリの範囲外・メモリアクセス失敗。
    GuestMemory,
}

impl VirtqueueErrorCode {
    /// ログ・ワイヤー用の固定文字列。
    pub const fn as_str(self) -> &'static str {
        match self {
            VirtqueueErrorCode::InvalidQueueState => "INVALID_QUEUE_STATE",
            VirtqueueErrorCode::RingOutOfRange => "RING_OUT_OF_RANGE",
            VirtqueueErrorCode::InvalidAvailIdx => "INVALID_AVAIL_IDX",
            VirtqueueErrorCode::DescIndexOutOfRange => "DESC_INDEX_OUT_OF_RANGE",
            VirtqueueErrorCode::ChainLoop => "CHAIN_LOOP",
            VirtqueueErrorCode::ChainTooLong => "CHAIN_TOO_LONG",
            VirtqueueErrorCode::ChainTooLarge => "CHAIN_TOO_LARGE",
            VirtqueueErrorCode::IndirectUnsupported => "INDIRECT_UNSUPPORTED",
            VirtqueueErrorCode::InvalidDescFlags => "INVALID_DESC_FLAGS",
            VirtqueueErrorCode::ReadableAfterWritable => "READABLE_AFTER_WRITABLE",
            VirtqueueErrorCode::UsedLenExceedsWritable => "USED_LEN_EXCEEDS_WRITABLE",
            VirtqueueErrorCode::GuestMemory => "GUEST_MEMORY",
        }
    }
}

/// virtqueue 処理の失敗。`message` は英語の固定文で、ゲスト由来の値は載せない（ERR-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtqueueError {
    code: VirtqueueErrorCode,
}

impl VirtqueueError {
    const fn new(code: VirtqueueErrorCode) -> Self {
        Self { code }
    }
    /// 分類。
    pub const fn code(&self) -> VirtqueueErrorCode {
        self.code
    }
}

impl fmt::Display for VirtqueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "virtqueue error: {}", self.code.as_str())
    }
}

impl std::error::Error for VirtqueueError {}

impl From<VirtqueueError> for MicrovmError {
    fn from(e: VirtqueueError) -> Self {
        MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            format!("virtqueue error: {}", e.code.as_str()),
        )
    }
}

fn mem_err(_: MicrovmError) -> VirtqueueError {
    VirtqueueError::new(VirtqueueErrorCode::GuestMemory)
}

/// チェーンの記述子 1 つ（検査済み）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor {
    /// バッファのゲスト物理アドレス。
    pub addr: GuestAddress,
    /// バッファの長さ。
    pub len: u32,
    /// デバイスが書き込むバッファか。
    pub writable: bool,
}

/// avail から取り出した記述子チェーン（readable が先、writable が後）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorChain {
    head: u16,
    descriptors: Vec<Descriptor>,
    readable_len: u64,
    writable_len: u64,
    oversized: bool,
}

impl DescriptorChain {
    /// 先頭の記述子の index（used の `id`）。
    pub fn head(&self) -> u16 {
        self.head
    }
    /// 記述子の列（チェーン順）。
    pub fn descriptors(&self) -> &[Descriptor] {
        &self.descriptors
    }
    /// 読み取り専用バッファの合計バイト数。
    pub fn readable_len(&self) -> u64 {
        self.readable_len
    }
    /// 書き込み可能バッファの合計バイト数。
    pub fn writable_len(&self) -> u64 {
        self.writable_len
    }
    /// readable / writable いずれかの合計が [`MAX_CHAIN_BYTES`] を超えたか。
    ///
    /// 構造は検査済みで消費できるチェーンだが、デバイスは処理せずエラー status で完了させる（MVM-1）。
    pub fn oversized(&self) -> bool {
        self.oversized
    }
}

/// split virtqueue（デバイス側の状態）。
#[derive(Debug, Clone)]
pub struct SplitQueue {
    size: u16,
    desc: GuestAddress,
    avail: GuestAddress,
    used: GuestAddress,
    last_avail: u16,
    next_used: u16,
}

impl SplitQueue {
    /// 設定済み・ready のキューから作る。desc / avail / used の各範囲がメモリに収まることを確かめる。
    pub fn new<B: GuestMemoryBacking>(
        cfg: &QueueConfig,
        mem: &GuestMemory<B>,
    ) -> Result<Self, VirtqueueError> {
        let size = cfg.size();
        if !cfg.ready() || size == 0 {
            return Err(VirtqueueError::new(VirtqueueErrorCode::InvalidQueueState));
        }
        let n = u64::from(size);
        let desc = GuestAddress::new(cfg.desc_table());
        let avail = GuestAddress::new(cfg.driver_area());
        let used = GuestAddress::new(cfg.device_area());
        let fits = |a: GuestAddress, len: u64| mem.check_range(a, len).is_ok();
        if !(fits(desc, n * DESC_SIZE) && fits(avail, 4 + 2 * n) && fits(used, 4 + 8 * n)) {
            return Err(VirtqueueError::new(VirtqueueErrorCode::RingOutOfRange));
        }
        Ok(Self {
            size,
            desc,
            avail,
            used,
            last_avail: 0,
            next_used: 0,
        })
    }

    /// キュー長。
    pub fn size(&self) -> u16 {
        self.size
    }

    fn at(base: GuestAddress, off: u64) -> Result<GuestAddress, VirtqueueError> {
        base.checked_add(off)
            .ok_or(VirtqueueError::new(VirtqueueErrorCode::RingOutOfRange))
    }

    /// avail リングから未処理のチェーンを 1 本取り出す。無ければ `Ok(None)`。
    ///
    /// 失敗したときは `last_avail` を進めない。
    pub fn pop<B: GuestMemoryBacking>(
        &mut self,
        mem: &GuestMemory<B>,
    ) -> Result<Option<DescriptorChain>, VirtqueueError> {
        let avail_idx = mem.read_u16_le(Self::at(self.avail, 2)?).map_err(mem_err)?;
        // avail.idx を読んだ後でなければ ring の要素を読んではならない（仕様 2.7.13）。
        fence(Ordering::Acquire);
        let pending = avail_idx.wrapping_sub(self.last_avail);
        if pending == 0 {
            return Ok(None);
        }
        if pending > self.size {
            return Err(VirtqueueError::new(VirtqueueErrorCode::InvalidAvailIdx));
        }
        let slot = u64::from(self.last_avail % self.size);
        let head = mem
            .read_u16_le(Self::at(self.avail, 4 + 2 * slot)?)
            .map_err(mem_err)?;
        let chain = self.walk(mem, head)?;
        self.last_avail = self.last_avail.wrapping_add(1);
        Ok(Some(chain))
    }

    fn walk<B: GuestMemoryBacking>(
        &self,
        mem: &GuestMemory<B>,
        head: u16,
    ) -> Result<DescriptorChain, VirtqueueError> {
        let limit = MAX_CHAIN_LEN.min(usize::from(self.size));
        let mut index = head;
        let mut visited: Vec<u16> = Vec::new();
        let mut descriptors = Vec::new();
        let (mut readable_len, mut writable_len) = (0u64, 0u64);
        let mut oversized = false;
        loop {
            if index >= self.size {
                return Err(VirtqueueError::new(VirtqueueErrorCode::DescIndexOutOfRange));
            }
            if visited.contains(&index) {
                return Err(VirtqueueError::new(VirtqueueErrorCode::ChainLoop));
            }
            if visited.len() >= limit {
                return Err(VirtqueueError::new(VirtqueueErrorCode::ChainTooLong));
            }
            visited.push(index);
            // 16 バイトを 1 回だけコピーし、以降の検査と使用は同じコピーで行う。
            let mut raw = [0u8; DESC_SIZE as usize];
            let at = Self::at(self.desc, u64::from(index) * DESC_SIZE)?;
            mem.read_at(at, &mut raw).map_err(mem_err)?;
            let addr = u64::from_le_bytes(sub8(&raw, 0));
            let len = u32::from_le_bytes(sub4(&raw, 8));
            let flags = u16::from_le_bytes(sub2(&raw, 12));
            let next = u16::from_le_bytes(sub2(&raw, 14));

            if flags & VRING_DESC_F_INDIRECT != 0 {
                return Err(VirtqueueError::new(VirtqueueErrorCode::IndirectUnsupported));
            }
            if flags & !(VRING_DESC_F_NEXT | VRING_DESC_F_WRITE) != 0 {
                return Err(VirtqueueError::new(VirtqueueErrorCode::InvalidDescFlags));
            }
            let writable = flags & VRING_DESC_F_WRITE != 0;
            if !writable && descriptors_have_writable(&descriptors) {
                return Err(VirtqueueError::new(
                    VirtqueueErrorCode::ReadableAfterWritable,
                ));
            }
            mem.check_range(GuestAddress::new(addr), u64::from(len))
                .map_err(mem_err)?;
            let total = if writable {
                &mut writable_len
            } else {
                &mut readable_len
            };
            // 合計の超過はリング破損ではない（仕様準拠のドライバも広告値の範囲で起こしうる）ため
            // `Err` にせず `oversized` を立てて最後まで辿る。`Err` だと `last_avail` が進まず、
            // 以後の pop が同じ要求で失敗し続けてデバイスが恒久的に止まる（MVM-1）。
            *total = total.saturating_add(u64::from(len));
            if *total > MAX_CHAIN_BYTES {
                oversized = true;
            }
            descriptors.push(Descriptor {
                addr: GuestAddress::new(addr),
                len,
                writable,
            });
            if flags & VRING_DESC_F_NEXT == 0 {
                break;
            }
            index = next;
        }
        Ok(DescriptorChain {
            head,
            descriptors,
            readable_len,
            writable_len,
            oversized,
        })
    }

    /// 処理済みのチェーンを used リングへ返す。`len` はデバイスが書き込んだバイト数。
    pub fn add_used<B: GuestMemoryBacking>(
        &mut self,
        mem: &mut GuestMemory<B>,
        chain: &DescriptorChain,
        len: u32,
    ) -> Result<(), VirtqueueError> {
        if u64::from(len) > chain.writable_len {
            return Err(VirtqueueError::new(
                VirtqueueErrorCode::UsedLenExceedsWritable,
            ));
        }
        let slot = u64::from(self.next_used % self.size);
        let elem = Self::at(self.used, 4 + 8 * slot)?;
        mem.write_u32_le(elem, u32::from(chain.head))
            .map_err(mem_err)?;
        mem.write_u32_le(Self::at(elem, 4)?, len).map_err(mem_err)?;
        // 要素を書いた後でなければ used.idx を進めてはならない（仕様 2.7.13）。
        fence(Ordering::Release);
        self.next_used = self.next_used.wrapping_add(1);
        mem.write_u16_le(Self::at(self.used, 2)?, self.next_used)
            .map_err(mem_err)?;
        Ok(())
    }
}

fn descriptors_have_writable(d: &[Descriptor]) -> bool {
    d.iter().any(|x| x.writable)
}

fn sub2(raw: &[u8; 16], at: usize) -> [u8; 2] {
    let mut o = [0u8; 2];
    if let Some(s) = raw.get(at..at + 2) {
        o.copy_from_slice(s);
    }
    o
}
fn sub4(raw: &[u8; 16], at: usize) -> [u8; 4] {
    let mut o = [0u8; 4];
    if let Some(s) = raw.get(at..at + 4) {
        o.copy_from_slice(s);
    }
    o
}
fn sub8(raw: &[u8; 16], at: usize) -> [u8; 8] {
    let mut o = [0u8; 8];
    if let Some(s) = raw.get(at..at + 8) {
        o.copy_from_slice(s);
    }
    o
}

/// 試験用: heap のゲストメモリ上にリングを組む補助（virtio_block の単体試験も使う）。
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::guest_memory::HeapBacking;
    use crate::virtio_mmio::{
        FeatureBits, VirtioDevice, VirtioDeviceType, VirtioMmioTransport, reg,
    };

    pub const DESC: u64 = 0x1000;
    pub const AVAIL: u64 = 0x2000;
    pub const USED: u64 = 0x3000;
    pub const BUF: u64 = 0x10000;

    pub type Mem = GuestMemory<HeapBacking>;

    pub fn new_mem() -> Mem {
        GuestMemory::new(GuestAddress::new(0), HeapBacking::new(4 << 20).unwrap()).unwrap()
    }

    /// 最小のデバイス（QueueConfig を作るためだけ）。
    struct Nop;
    impl VirtioDevice for Nop {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Block
        }
        fn device_features(&self) -> FeatureBits {
            FeatureBits::EMPTY
        }
        fn queue_max_sizes(&self) -> &[u16] {
            &[16]
        }
        fn read_config(&self, _: u64, _: &mut [u8]) {}
        fn write_config(&mut self, _: u64, _: &[u8]) {}
        fn activate(&mut self, _: FeatureBits, _: &[QueueConfig]) -> Result<(), MicrovmError> {
            Ok(())
        }
        fn reset(&mut self) {}
    }

    /// トランスポート経由で ready なサイズ 16 のキュー設定を得る。
    pub fn queue_cfg(desc: u64, avail: u64, used: u64) -> QueueConfig {
        let mut t = VirtioMmioTransport::new(Nop).unwrap();
        let w = |t: &mut VirtioMmioTransport<Nop>, off: u64, v: u32| {
            t.write(off, &v.to_le_bytes());
        };
        w(&mut t, reg::STATUS, 1);
        w(&mut t, reg::STATUS, 3);
        w(&mut t, reg::DRIVER_FEATURES_SEL, 1);
        w(&mut t, reg::DRIVER_FEATURES, 1);
        w(&mut t, reg::STATUS, 11);
        w(&mut t, reg::QUEUE_SEL, 0);
        w(&mut t, reg::QUEUE_NUM, 16);
        w(&mut t, reg::QUEUE_DESC_LOW, desc as u32);
        w(&mut t, reg::QUEUE_DESC_HIGH, (desc >> 32) as u32);
        w(&mut t, reg::QUEUE_DRIVER_LOW, avail as u32);
        w(&mut t, reg::QUEUE_DRIVER_HIGH, (avail >> 32) as u32);
        w(&mut t, reg::QUEUE_DEVICE_LOW, used as u32);
        w(&mut t, reg::QUEUE_DEVICE_HIGH, (used >> 32) as u32);
        w(&mut t, reg::QUEUE_READY, 1);
        *t.queue(0).unwrap()
    }

    pub fn put_desc(m: &mut Mem, i: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let at = GuestAddress::new(DESC + u64::from(i) * 16);
        m.write_at(at, &addr.to_le_bytes()).unwrap();
        m.write_u32_le(GuestAddress::new(DESC + u64::from(i) * 16 + 8), len)
            .unwrap();
        m.write_u16_le(GuestAddress::new(DESC + u64::from(i) * 16 + 12), flags)
            .unwrap();
        m.write_u16_le(GuestAddress::new(DESC + u64::from(i) * 16 + 14), next)
            .unwrap();
    }

    /// avail の `slot` 番目に head を置き、`idx` を設定する。
    pub fn publish(m: &mut Mem, slot: u16, head: u16, idx: u16) {
        m.write_u16_le(GuestAddress::new(AVAIL + 4 + 2 * u64::from(slot)), head)
            .unwrap();
        m.write_u16_le(GuestAddress::new(AVAIL + 2), idx).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn queue(m: &Mem) -> SplitQueue {
        SplitQueue::new(&queue_cfg(DESC, AVAIL, USED), m).unwrap()
    }

    /// MVM-1: 3 記述子のチェーンを取り出し、used へ返すと idx と要素が具体値で書かれる。
    #[test]
    fn mvm1_pop_chain_and_add_used() {
        let mut m = new_mem();
        put_desc(&mut m, 0, BUF, 16, VRING_DESC_F_NEXT, 5);
        put_desc(
            &mut m,
            5,
            BUF + 0x100,
            512,
            VRING_DESC_F_NEXT | VRING_DESC_F_WRITE,
            9,
        );
        put_desc(&mut m, 9, BUF + 0x400, 1, VRING_DESC_F_WRITE, 0);
        publish(&mut m, 0, 0, 1);
        let mut q = queue(&m);
        let c = q.pop(&m).unwrap().unwrap();
        assert_eq!(c.head(), 0);
        assert_eq!(c.descriptors().len(), 3);
        assert_eq!(c.readable_len(), 16);
        assert_eq!(c.writable_len(), 513);
        assert!(c.descriptors()[1].writable);
        assert_eq!(c.descriptors()[1].addr, GuestAddress::new(BUF + 0x100));
        assert!(q.pop(&m).unwrap().is_none());

        q.add_used(&mut m, &c, 513).unwrap();
        assert_eq!(m.read_u16_le(GuestAddress::new(USED + 2)).unwrap(), 1);
        assert_eq!(m.read_u32_le(GuestAddress::new(USED + 4)).unwrap(), 0);
        assert_eq!(m.read_u32_le(GuestAddress::new(USED + 8)).unwrap(), 513);
        let e = q.add_used(&mut m, &c, 514).unwrap_err();
        assert_eq!(e.code(), VirtqueueErrorCode::UsedLenExceedsWritable);
    }

    /// MVM-1: avail.idx が 65535 から 0 へ折り返しても取り出せる。
    #[test]
    fn mvm1_avail_idx_wraps() {
        let mut m = new_mem();
        put_desc(&mut m, 1, BUF, 8, 0, 0);
        let mut q = queue(&m);
        q.last_avail = 65535;
        // slot = 65535 % 16 = 15。
        publish(&mut m, 15, 1, 0);
        let c = q.pop(&m).unwrap().unwrap();
        assert_eq!(c.head(), 1);
        assert_eq!(q.last_avail, 0);
        assert!(q.pop(&m).unwrap().is_none());
    }

    fn expect_err(m: &Mem, code: VirtqueueErrorCode) {
        let mut q = queue(m);
        assert_eq!(q.pop(m).unwrap_err().code(), code);
        // 失敗では last_avail を進めない。
        assert_eq!(q.last_avail, 0);
    }

    /// MVM-1: ゲストが作る壊れたチェーンを分類つきで拒否する。
    #[test]
    fn mvm1_malformed_chains_are_rejected() {
        let n = VRING_DESC_F_NEXT;
        let w = VRING_DESC_F_WRITE;
        // ループ。
        let mut m = new_mem();
        put_desc(&mut m, 0, BUF, 8, n, 1);
        put_desc(&mut m, 1, BUF, 8, n, 0);
        publish(&mut m, 0, 0, 1);
        expect_err(&m, VirtqueueErrorCode::ChainLoop);
        // next が範囲外。
        let mut m = new_mem();
        put_desc(&mut m, 0, BUF, 8, n, 16);
        publish(&mut m, 0, 0, 1);
        expect_err(&m, VirtqueueErrorCode::DescIndexOutOfRange);
        // head が範囲外。
        let mut m = new_mem();
        publish(&mut m, 0, 16, 1);
        expect_err(&m, VirtqueueErrorCode::DescIndexOutOfRange);
        // INDIRECT。
        let mut m = new_mem();
        put_desc(&mut m, 0, BUF, 8, VRING_DESC_F_INDIRECT, 0);
        publish(&mut m, 0, 0, 1);
        expect_err(&m, VirtqueueErrorCode::IndirectUnsupported);
        // 未定義 flags。
        let mut m = new_mem();
        put_desc(&mut m, 0, BUF, 8, 0x8, 0);
        publish(&mut m, 0, 0, 1);
        expect_err(&m, VirtqueueErrorCode::InvalidDescFlags);
        // writable の後の readable。
        let mut m = new_mem();
        put_desc(&mut m, 0, BUF, 8, n | w, 1);
        put_desc(&mut m, 1, BUF, 8, 0, 0);
        publish(&mut m, 0, 0, 1);
        expect_err(&m, VirtqueueErrorCode::ReadableAfterWritable);
        // バッファが範囲外。
        let mut m = new_mem();
        put_desc(&mut m, 0, (4 << 20) - 4, 8, 0, 0);
        publish(&mut m, 0, 0, 1);
        expect_err(&m, VirtqueueErrorCode::GuestMemory);
        // 未処理数がキュー長を超える。
        let mut m = new_mem();
        publish(&mut m, 0, 0, 17);
        expect_err(&m, VirtqueueErrorCode::InvalidAvailIdx);
    }

    /// MVM-1: 合計バイト数の超過は Err にせず oversized で消費でき、キューが進む。
    #[test]
    fn mvm1_oversized_chain_is_consumed() {
        let n = VRING_DESC_F_NEXT;
        let mut m = new_mem();
        put_desc(&mut m, 0, 0, 2 << 20, n, 1);
        for i in 1..16u16 {
            put_desc(&mut m, i, 0, 2 << 20, if i == 15 { 0 } else { n }, i + 1);
        }
        publish(&mut m, 0, 0, 1);
        let mut q = queue(&m);
        let chain = q.pop(&m).unwrap().unwrap();
        assert!(chain.oversized());
        assert_eq!(chain.readable_len(), 32 << 20);
        assert_eq!(q.last_avail, 1);
        assert!(q.pop(&m).unwrap().is_none());
    }

    /// MVM-1: ring がメモリの外にあるキューと ready でないキューは作れない。
    #[test]
    fn mvm1_queue_construction_checks_rings() {
        let m = new_mem();
        let cfg = queue_cfg(DESC, AVAIL, (4 << 20) - 8);
        assert_eq!(
            SplitQueue::new(&cfg, &m).unwrap_err().code(),
            VirtqueueErrorCode::RingOutOfRange
        );
        assert_eq!(
            SplitQueue::new(&QueueConfig::default(), &m)
                .unwrap_err()
                .code(),
            VirtqueueErrorCode::InvalidQueueState
        );
        let e: MicrovmError = VirtqueueError::new(VirtqueueErrorCode::ChainLoop).into();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "virtqueue error: CHAIN_LOOP");
    }
}
