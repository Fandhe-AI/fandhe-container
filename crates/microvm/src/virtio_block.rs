//! virtio-block デバイス（TASK-74.2.2・MVM-1・MVM-4・MS-7。OS 非依存・unsafe なし）。
//!
//! `virtio_mmio` の [`VirtioMmioTransport`](crate::virtio_mmio::VirtioMmioTransport) に包んで使う
//! [`VirtioDevice`] 実装。requestq（キュー 0）の split virtqueue（`virtqueue`）から要求を取り出し、
//! read（`VIRTIO_BLK_T_IN`）・write（`VIRTIO_BLK_T_OUT`）・flush を [`BlockBackend`] へ流して、
//! status バイトと used リングを書き戻す。
//!
//! # 呼び出し契約
//! `KVM_RUN` の MMIO exit を振り分ける側（TASK-74.4.2）が `QueueNotify(0)` を受けたら
//! `device_mut().process_queue(&mem)` を呼び、[`BlockQueueStats::completed`] が 1 以上なら
//! `raise_interrupt(InterruptReason::UsedBuffer)` を呼ぶ（割り込みの実配送は TASK-74.2.3）。
//! `QueueStopped(0)` では [`VirtioBlock::stop_queue`] を呼ぶ。リングの破損は `process_queue` が `Err` で返し、
//! 停止・リセット要求の判断は呼び出し元が行う（デバイスからトランスポートへ DEVICE_NEEDS_RESET は立てない）。
//!
//! # 範囲外（REPAIR-3。将来仕様）
//! `GET_ID`（UNSUPP を返す）・DISCARD / WRITE_ZEROES・マルチキュー・`EVENT_IDX`・`INDIRECT`・packed・
//! ファイルを backing にする [`BlockBackend`]（起動フローの TASK-75 / TASK-117 で決める）。
//!
//! # 準拠先
//! OASIS "Virtual I/O Device (VIRTIO) Version 1.2" の 5.2（Block Device）。待ちを持たない同期処理なので
//! REPAIR-5 のタイムアウトは不要。データは固定長の bounce buffer を通すため、ゲストが指定した長さで確保しない。
//!
//! # 外部入力の扱い
//! ヘッダの type・sector と記述子の内容はゲストが決める非信頼入力。算術は checked 演算で行い、
//! panic・添字アクセスを使わない。status 記述子が無い要求は status を書かずに used len 0 で消費する。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestMemory, GuestMemoryBacking};
use crate::virtio_mmio::{FeatureBits, QueueConfig, VirtioDevice, VirtioDeviceType};
use crate::virtqueue::{Descriptor, DescriptorChain, MAX_CHAIN_LEN, SplitQueue};

/// セクタ長。
pub const SECTOR_SIZE: u64 = 512;
/// feature: 1 記述子の最大長（`size_max`）。
pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
/// feature: 1 要求のデータ記述子の最大数（`seg_max`）。
pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
/// feature: 読み取り専用。
pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
/// feature: flush 要求。
pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
/// 要求種別: read。
pub const VIRTIO_BLK_T_IN: u32 = 0;
/// 要求種別: write。
pub const VIRTIO_BLK_T_OUT: u32 = 1;
/// 要求種別: flush。
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
/// status: 成功。
pub const VIRTIO_BLK_S_OK: u8 = 0;
/// status: I/O エラー。
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
/// status: 非対応の要求。
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;
/// 設定空間で広告する `size_max`。
pub const SIZE_MAX: u32 = 1 << 20;
/// 設定空間で広告する `seg_max`（ヘッダと status を除いたデータ記述子の最大数）。
pub const SEG_MAX: u32 = (MAX_CHAIN_LEN - 2) as u32;
/// requestq の最大キュー長。
pub const QUEUE_MAX_SIZE: u16 = 256;
/// [`MemoryBlockBackend`] の容量上限。
pub const MAX_MEMORY_BACKEND: u64 = 1 << 30;

const HEADER_LEN: u32 = 16;
const BOUNCE_LEN: usize = 64 << 10;

fn invalid(message: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, message)
}

/// ブロックデバイスの実体。範囲検査は [`VirtioBlock`] が済ませてから呼ぶ。
pub trait BlockBackend {
    /// 容量（バイト。512 の倍数）。
    fn capacity_bytes(&self) -> u64;
    /// 読み取り専用か。
    fn read_only(&self) -> bool;
    /// `offset` から `buf.len()` バイトを読む。
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError>;
    /// `offset` へ書く。
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError>;
    /// 書き込みを永続化する。
    fn flush(&mut self) -> Result<(), MicrovmError>;
}

/// `Vec<u8>` の backend（試験と KVM を使わない用途）。
#[derive(Debug, Clone)]
pub struct MemoryBlockBackend {
    bytes: Vec<u8>,
    read_only: bool,
}

impl MemoryBlockBackend {
    /// 0 埋めで作る。容量は 512 の倍数で [`MAX_MEMORY_BACKEND`] 以下。
    pub fn new(capacity_bytes: u64, read_only: bool) -> Result<Self, MicrovmError> {
        if !capacity_bytes.is_multiple_of(SECTOR_SIZE) || capacity_bytes > MAX_MEMORY_BACKEND {
            return Err(invalid("invalid block backend capacity"));
        }
        let len = usize::try_from(capacity_bytes).map_err(|_| invalid("invalid capacity"))?;
        Ok(Self {
            bytes: vec![0; len],
            read_only,
        })
    }

    /// 内容の読み取り（試験用）。
    pub fn contents(&self) -> &[u8] {
        &self.bytes
    }

    fn span(&self, offset: u64, len: usize) -> Result<std::ops::Range<usize>, MicrovmError> {
        let start = usize::try_from(offset).map_err(|_| invalid("block range"))?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| invalid("block range"))?;
        if end > self.bytes.len() {
            return Err(invalid("block range"));
        }
        Ok(start..end)
    }
}

impl BlockBackend for MemoryBlockBackend {
    fn capacity_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_only(&self) -> bool {
        self.read_only
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        let r = self.span(offset, buf.len())?;
        buf.copy_from_slice(self.bytes.get(r).ok_or_else(|| invalid("block range"))?);
        Ok(())
    }
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
        if self.read_only {
            return Err(invalid("block backend is read-only"));
        }
        let r = self.span(offset, data.len())?;
        self.bytes
            .get_mut(r)
            .ok_or_else(|| invalid("block range"))?
            .copy_from_slice(data);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), MicrovmError> {
        Ok(())
    }
}

/// `process_queue` 1 回分の処理内訳（REPAIR-4: 真偽値にしない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlockQueueStats {
    /// used へ返した要求の数（malformed を含む）。
    pub completed: u32,
    /// status が OK の数。
    pub ok: u32,
    /// status が IOERR の数。
    pub ioerr: u32,
    /// status が UNSUPP の数。
    pub unsupp: u32,
    /// status を書けず used len 0 で消費した数。
    pub malformed: u32,
}

/// virtio-block デバイス。
#[derive(Debug)]
pub struct VirtioBlock<B: BlockBackend> {
    backend: B,
    queue_cfg: Option<QueueConfig>,
    queue: Option<SplitQueue>,
    bounce: Vec<u8>,
}

impl<B: BlockBackend> VirtioBlock<B> {
    /// backend から作る。
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            queue_cfg: None,
            queue: None,
            bounce: vec![0; BOUNCE_LEN],
        }
    }

    /// backend への参照。
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// requestq の処理を止める（トランスポートの `QueueStopped(0)` で呼ぶ）。
    pub fn stop_queue(&mut self) {
        self.queue_cfg = None;
        self.queue = None;
    }

    /// avail に積まれた要求を処理して used へ返す（1 回に最大キュー長の本数）。
    ///
    /// activate 前・停止後は `FailedPrecondition`。リング破損は `Err`（`InvalidArgument`）。
    pub fn process_queue<M: GuestMemoryBacking>(
        &mut self,
        mem: &mut GuestMemory<M>,
    ) -> Result<BlockQueueStats, MicrovmError> {
        if self.queue.is_none() {
            let cfg = self.queue_cfg.ok_or_else(|| {
                MicrovmError::new(
                    MicrovmErrorCode::FailedPrecondition,
                    "block queue is not active",
                )
            })?;
            self.queue = Some(SplitQueue::new(&cfg, mem)?);
        }
        let mut stats = BlockQueueStats::default();
        let Some(mut queue) = self.queue.take() else {
            return Ok(stats);
        };
        let result = self.drain(&mut queue, mem, &mut stats);
        self.queue = Some(queue);
        result.map(|()| stats)
    }

    fn drain<M: GuestMemoryBacking>(
        &mut self,
        queue: &mut SplitQueue,
        mem: &mut GuestMemory<M>,
        stats: &mut BlockQueueStats,
    ) -> Result<(), MicrovmError> {
        for _ in 0..queue.size() {
            let Some(chain) = queue.pop(mem)? else {
                break;
            };
            let (outcome, written) = self.handle(&chain, mem);
            let used_len = match outcome {
                Some(status) => {
                    // 最後の記述子の最終バイトが status（handle が存在と書き込み可を確認済み）。
                    if let Some(last) = chain.descriptors().last() {
                        let at = last
                            .addr
                            .checked_add(u64::from(last.len) - 1)
                            .ok_or_else(|| invalid("status address"))?;
                        mem.write_at(at, &[status])?;
                    }
                    match status {
                        VIRTIO_BLK_S_OK => stats.ok += 1,
                        VIRTIO_BLK_S_UNSUPP => stats.unsupp += 1,
                        _ => stats.ioerr += 1,
                    }
                    // データのバイト数 + status 1 バイト。
                    written.saturating_add(1)
                }
                None => {
                    stats.malformed += 1;
                    0
                }
            };
            queue.add_used(mem, &chain, used_len)?;
            stats.completed += 1;
        }
        Ok(())
    }

    /// 1 要求を処理する。`None` は status を書けない（malformed）。`Some` は (status, 書いたデータのバイト数)。
    fn handle<M: GuestMemoryBacking>(
        &mut self,
        chain: &DescriptorChain,
        mem: &mut GuestMemory<M>,
    ) -> (Option<u8>, u32) {
        let descs = chain.descriptors();
        let (Some(first), Some(last)) = (descs.first(), descs.last()) else {
            return (None, 0);
        };
        if descs.len() < 2 || !last.writable || last.len == 0 {
            return (None, 0);
        }
        if first.writable || first.len < HEADER_LEN {
            return (Some(VIRTIO_BLK_S_IOERR), 0);
        }
        let mut header = [0u8; HEADER_LEN as usize];
        if mem.read_at(first.addr, &mut header).is_err() {
            return (Some(VIRTIO_BLK_S_IOERR), 0);
        }
        let ty = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let sector = u64::from_le_bytes([
            header[8], header[9], header[10], header[11], header[12], header[13], header[14],
            header[15],
        ]);
        // 最後の記述子の本体以外（最終バイトが status）。status 記述子が複数バイトのとき、
        // 先頭側はデータとして扱わない（IN の writable データは中間の記述子だけ）。
        let data = descs.get(1..descs.len() - 1).unwrap_or(&[]);
        match ty {
            VIRTIO_BLK_T_IN => self.transfer(data, sector, mem, true),
            VIRTIO_BLK_T_OUT => self.transfer(data, sector, mem, false),
            VIRTIO_BLK_T_FLUSH => match self.backend.flush() {
                Ok(()) => (Some(VIRTIO_BLK_S_OK), 0),
                Err(_) => (Some(VIRTIO_BLK_S_IOERR), 0),
            },
            _ => (Some(VIRTIO_BLK_S_UNSUPP), 0),
        }
    }

    fn transfer<M: GuestMemoryBacking>(
        &mut self,
        data: &[Descriptor],
        sector: u64,
        mem: &mut GuestMemory<M>,
        read: bool,
    ) -> (Option<u8>, u32) {
        let ioerr = (Some(VIRTIO_BLK_S_IOERR), 0);
        if data.len() > SEG_MAX as usize
            || data.iter().any(|d| d.writable != read || d.len > SIZE_MAX)
            || (!read && self.backend.read_only())
        {
            return ioerr;
        }
        let total: u64 = data.iter().map(|d| u64::from(d.len)).sum();
        if total == 0 || !total.is_multiple_of(SECTOR_SIZE) {
            return ioerr;
        }
        let Some(start) = sector.checked_mul(SECTOR_SIZE) else {
            return ioerr;
        };
        match start.checked_add(total) {
            Some(end) if end <= self.backend.capacity_bytes() => {}
            _ => return ioerr,
        }
        let mut offset = start;
        let mut written = 0u32;
        for d in data {
            let mut addr = d.addr;
            let mut remaining = u64::from(d.len);
            while remaining > 0 {
                let n = remaining.min(BOUNCE_LEN as u64) as usize;
                let Some(buf) = self.bounce.get_mut(..n) else {
                    return (Some(VIRTIO_BLK_S_IOERR), written);
                };
                let ok = if read {
                    self.backend.read_at(offset, buf).is_ok() && mem.write_at(addr, buf).is_ok()
                } else {
                    mem.read_at(addr, buf).is_ok() && self.backend.write_at(offset, buf).is_ok()
                };
                if !ok {
                    return (Some(VIRTIO_BLK_S_IOERR), written);
                }
                if read {
                    written = written.saturating_add(n as u32);
                }
                offset += n as u64;
                remaining -= n as u64;
                addr = match addr.checked_add(n as u64) {
                    Some(a) => a,
                    None => return (Some(VIRTIO_BLK_S_IOERR), written),
                };
            }
        }
        (Some(VIRTIO_BLK_S_OK), written)
    }
}

impl<B: BlockBackend> VirtioDevice for VirtioBlock<B> {
    fn device_type(&self) -> VirtioDeviceType {
        VirtioDeviceType::Block
    }

    fn device_features(&self) -> FeatureBits {
        let mut bits = VIRTIO_BLK_F_SEG_MAX | VIRTIO_BLK_F_SIZE_MAX | VIRTIO_BLK_F_FLUSH;
        if self.backend.read_only() {
            bits |= VIRTIO_BLK_F_RO;
        }
        FeatureBits::from_bits(bits)
    }

    fn queue_max_sizes(&self) -> &[u16] {
        &[QUEUE_MAX_SIZE]
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // capacity(le64 @0)・size_max(le32 @8)・seg_max(le32 @12)。
        let mut cfg = [0u8; 16];
        cfg[..8].copy_from_slice(&(self.backend.capacity_bytes() / SECTOR_SIZE).to_le_bytes());
        cfg[8..12].copy_from_slice(&SIZE_MAX.to_le_bytes());
        cfg[12..16].copy_from_slice(&SEG_MAX.to_le_bytes());
        data.fill(0);
        let Ok(start) = usize::try_from(offset) else {
            return;
        };
        for (i, b) in data.iter_mut().enumerate() {
            if let Some(v) = start.checked_add(i).and_then(|p| cfg.get(p)) {
                *b = *v;
            }
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn activate(
        &mut self,
        _features: FeatureBits,
        queues: &[QueueConfig],
    ) -> Result<(), MicrovmError> {
        match queues.first() {
            Some(q) if q.ready() => {
                self.queue_cfg = Some(*q);
                self.queue = None;
                Ok(())
            }
            _ => Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "block request queue is not ready",
            )),
        }
    }

    fn reset(&mut self) {
        self.stop_queue();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_memory::GuestAddress;
    use crate::virtqueue::test_support::*;
    use crate::virtqueue::{VRING_DESC_F_NEXT, VRING_DESC_F_WRITE};

    const N: u16 = VRING_DESC_F_NEXT;
    const W: u16 = VRING_DESC_F_WRITE;

    fn block(ro: bool) -> VirtioBlock<MemoryBlockBackend> {
        let mut b = VirtioBlock::new(MemoryBlockBackend::new(8192, ro).unwrap());
        b.activate(FeatureBits::EMPTY, &[queue_cfg(DESC, AVAIL, USED)])
            .unwrap();
        b
    }

    fn header(m: &mut Mem, at: u64, ty: u32, sector: u64) {
        m.write_u32_le(GuestAddress::new(at), ty).unwrap();
        m.write_at(GuestAddress::new(at + 8), &sector.to_le_bytes())
            .unwrap();
    }

    /// head=0: [header R][data][status W]。status は BUF+0x2000 の 1 バイト。
    fn request(m: &mut Mem, ty: u32, sector: u64, data_len: u32, data_flags: u16) {
        header(m, BUF, ty, sector);
        put_desc(m, 0, BUF, 16, N, 1);
        put_desc(m, 1, BUF + 0x1000, data_len, data_flags | N, 2);
        put_desc(m, 2, BUF + 0x2000, 1, W, 0);
        m.write_at(GuestAddress::new(BUF + 0x2000), &[0xff])
            .unwrap();
        publish(m, 0, 0, 1);
    }

    fn status(m: &Mem) -> u8 {
        let mut b = [0u8; 1];
        m.read_at(GuestAddress::new(BUF + 0x2000), &mut b).unwrap();
        b[0]
    }

    /// MVM-1: 設定空間と feature の具体値。
    #[test]
    fn mvm1_config_space_and_features() {
        let b = block(false);
        let mut d = [0u8; 8];
        b.read_config(0, &mut d);
        assert_eq!(u64::from_le_bytes(d), 16);
        let mut d = [0u8; 4];
        b.read_config(8, &mut d);
        assert_eq!(u32::from_le_bytes(d), SIZE_MAX);
        b.read_config(12, &mut d);
        assert_eq!(u32::from_le_bytes(d), 126);
        b.read_config(0x20, &mut d);
        assert_eq!(d, [0; 4]);
        assert_eq!(b.device_features().bits(), (1 << 1) | (1 << 2) | (1 << 9));
        assert_eq!(
            block(true).device_features().bits(),
            (1 << 1) | (1 << 2) | (1 << 5) | (1 << 9)
        );
    }

    /// MVM-1: OUT で書いた内容を IN で読み戻せ、used len が具体値になる。
    #[test]
    fn mvm1_write_then_read_roundtrip() {
        let mut m = new_mem();
        let mut b = block(false);
        request(&mut m, VIRTIO_BLK_T_OUT, 1, 512, 0);
        m.write_at(GuestAddress::new(BUF + 0x1000), &[0x5a; 512])
            .unwrap();
        let s = b.process_queue(&mut m).unwrap();
        assert_eq!(
            s,
            BlockQueueStats {
                completed: 1,
                ok: 1,
                ..Default::default()
            }
        );
        assert_eq!(status(&m), 0);
        assert_eq!(m.read_u32_le(GuestAddress::new(USED + 8)).unwrap(), 1);
        assert_eq!(&b.backend().contents()[512..1024], &[0x5a; 512][..]);

        request(&mut m, VIRTIO_BLK_T_IN, 1, 512, W);
        m.write_u16_le(GuestAddress::new(AVAIL + 2), 2).unwrap();
        m.write_u16_le(GuestAddress::new(AVAIL + 6), 0).unwrap();
        let s = b.process_queue(&mut m).unwrap();
        assert_eq!(s.ok, 1);
        let mut got = [0u8; 512];
        m.read_at(GuestAddress::new(BUF + 0x1000), &mut got)
            .unwrap();
        assert_eq!(got, [0x5a; 512]);
        assert_eq!(m.read_u32_le(GuestAddress::new(USED + 16)).unwrap(), 513);
        assert_eq!(m.read_u16_le(GuestAddress::new(USED + 2)).unwrap(), 2);
    }

    /// MVM-1: 範囲外・不揃い・RO への書き込み・未知 type・flush の status。
    #[test]
    fn mvm1_error_statuses() {
        let cases: [(u32, u64, u32, u16, bool, u8); 6] = [
            (VIRTIO_BLK_T_IN, 16, 512, W, false, VIRTIO_BLK_S_IOERR),
            (VIRTIO_BLK_T_IN, 15, 1024, W, false, VIRTIO_BLK_S_IOERR),
            (VIRTIO_BLK_T_IN, u64::MAX, 512, W, false, VIRTIO_BLK_S_IOERR),
            (VIRTIO_BLK_T_IN, 0, 100, W, false, VIRTIO_BLK_S_IOERR),
            (VIRTIO_BLK_T_OUT, 0, 512, 0, true, VIRTIO_BLK_S_IOERR),
            (VIRTIO_BLK_T_IN, 0, 512, 0, false, VIRTIO_BLK_S_IOERR),
        ];
        for (ty, sector, len, flags, ro, want) in cases {
            let mut m = new_mem();
            let mut b = block(ro);
            request(&mut m, ty, sector, len, flags);
            let s = b.process_queue(&mut m).unwrap();
            assert_eq!(status(&m), want, "ty={ty} sector={sector} len={len}");
            assert_eq!(s.ioerr, 1);
            assert_eq!(m.read_u32_le(GuestAddress::new(USED + 8)).unwrap(), 1);
        }
        let mut m = new_mem();
        let mut b = block(false);
        request(&mut m, 8, 0, 20, W);
        assert_eq!(b.process_queue(&mut m).unwrap().unsupp, 1);
        assert_eq!(status(&m), VIRTIO_BLK_S_UNSUPP);
        let mut m = new_mem();
        let mut b = block(false);
        request(&mut m, VIRTIO_BLK_T_FLUSH, 0, 0, 0);
        assert_eq!(b.process_queue(&mut m).unwrap().ok, 1);
        assert_eq!(status(&m), 0);
    }

    /// MVM-1: status 記述子が無い要求は status を書かず used len 0 で消費する。
    #[test]
    fn mvm1_missing_status_descriptor_is_malformed() {
        let mut m = new_mem();
        let mut b = block(false);
        header(&mut m, BUF, VIRTIO_BLK_T_IN, 0);
        put_desc(&mut m, 0, BUF, 16, N, 1);
        put_desc(&mut m, 1, BUF + 0x1000, 512, 0, 0);
        publish(&mut m, 0, 0, 1);
        let s = b.process_queue(&mut m).unwrap();
        assert_eq!(
            s,
            BlockQueueStats {
                completed: 1,
                malformed: 1,
                ..Default::default()
            }
        );
        assert_eq!(m.read_u32_le(GuestAddress::new(USED + 8)).unwrap(), 0);
        assert_eq!(m.read_u16_le(GuestAddress::new(USED + 2)).unwrap(), 1);
    }

    /// MVM-1: activate 前・停止後は FailedPrecondition、壊れたリングは Err。
    #[test]
    fn mvm1_inactive_and_broken_ring() {
        let mut m = new_mem();
        let mut b = VirtioBlock::new(MemoryBlockBackend::new(512, false).unwrap());
        let e = b.process_queue(&mut m).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        assert!(b.activate(FeatureBits::EMPTY, &[]).is_err());
        let mut b = block(false);
        publish(&mut m, 0, 0, 17);
        assert_eq!(
            b.process_queue(&mut m).unwrap_err().message(),
            "virtqueue error: INVALID_AVAIL_IDX"
        );
        b.reset();
        assert_eq!(
            b.process_queue(&mut m).unwrap_err().code(),
            MicrovmErrorCode::FailedPrecondition
        );
    }

    #[test]
    fn mvm1_backend_validation() {
        assert!(MemoryBlockBackend::new(100, false).is_err());
        assert!(MemoryBlockBackend::new(MAX_MEMORY_BACKEND + 512, false).is_err());
    }
}
