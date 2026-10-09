//! split virtqueue の走査と used への書き戻し（GPU-6・MVM-4・REPAIR-2・TASK-172 F1.3・#1518）。
//!
//! 役割: vhost-user の `SET_VRING_NUM` / `SET_VRING_ADDR` / `SET_VRING_BASE` で受けた値を検証して [`QueueConfig`] にし、
//! avail リングから要求の記述子チェーンを取り出し（[`SplitQueue::pop`]）、処理後に used リングへ書き戻す
//! （[`SplitQueue::add_used`]）。呼び出し元は `crate::session`（セッションと応答ループ。F1.4・#1519。Linux 限定）。
//! メモリへのアクセスは [`QueueMemory`] だけを通す。Linux では `vhost_user::guest_memory::GuestMemory`
//! （境界検査つきのコピー）が実装し、合成リングのテストは OS を問わず動く。トランスポートに依存しないので `vhost_user` の外に置く。
//!
//! # 出典（確認日 2026-10-09。値だけを転記し、rust-vmm の `virtio-queue` 等のコードや構造体は参照も流用もしない。MVM-4）
//! - OASIS VIRTIO 1.2 の「2.7 Split Virtqueues」: 2.7 のレイアウト（desc 16 バイトアラインメント・avail 2・used 4・
//!   Queue Size は 2 の冪で最大 32768）、2.7.5 の記述子の `flags`（NEXT=1・WRITE=2・INDIRECT=4）、
//!   2.7.6 の avail ring（`flags`・`idx`・`ring[]`・`used_event`）、2.7.8 の used ring（`flags`・`idx`・`ring[]`＝`id` le32 と `len` le32・
//!   `avail_event`）、2.7.13 の Supplying / Receiving Used Buffers（要素を書いてから `idx` を更新する順序）、
//!   2.7.4 の driver 要件（device-readable の記述子を device-writable より前に置く）
//! - Linux `include/uapi/linux/virtio_ring.h`（`VIRTIO_RING_F_INDIRECT_DESC`=28・`VIRTIO_RING_F_EVENT_IDX`=29）
//! - QEMU `docs/interop/vhost-user.rst`（`SET_VRING_ADDR` の flags の bit 0 が log 有効化、アドレスは frontend の user アドレス）
//!
//! 節番号と値は仕様の記憶と既存の `vhost_user` の出典に基づく転記で、仕様本文の再取得による照合は未実施。
//! F1.4 の結合か実機（F3）で食い違いが出たらここを直す。
//!
//! # 入力の扱い（fail-closed・TOCTOU）
//! リングと記述子はすべてゲスト由来の untrusted。avail の `idx`・`ring[]` の要素・記述子 16 バイトは、共有メモリから
//! 1 回だけローカルへコピーし、検査と使用を同じコピーに対して行う（同じ値を二度読まない。`vhost_user::guest_memory` の
//! 「残っている前提」の規則）。走査は有限回（`min(MAX_CHAIN_LEN, num)`）で終わり、待機は持たない。
//! エラーは固定語彙の code だけを持ち、ゲスト由来の値（アドレス・インデックス）をエコーしない。失敗した `pop` は
//! `last_avail` を進めない（壊れた要求を黙って捨てない。以降の扱いは F1.4 が決める）。
//!
//! # 順序の前提
//! `pop` は `avail.idx` を読んだ後に Acquire の fence、`add_used` は `used.ring` の要素を書いた後に Release の fence を置いてから
//! `used.idx` を書く。`QueueMemory` の読み書きは非アトミックなコピーなので、これは Rust の抽象機械上の保証ではなく、
//! fence が実機のバリア命令（x86_64 は TSO、aarch64 は dmb）になることに頼る前提として残る。
//!
//! # 扱わない範囲（実装済みを装わない。REPAIR-3）
//! - `INDIRECT`（`VIRTIO_RING_F_INDIRECT_DESC`）と `EVENT_IDX`: `device::FEATURES` はどちらも広告しないので届かない前提で、
//!   `INDIRECT` の記述子は拒否し、avail の `used_event`・used の `avail_event`（リング末尾の 2 バイト）は読み書きしない
//! - packed virtqueue
//! - kick / call の eventfd、`SET_VRING_ENABLE` の状態、`GET_VRING_BASE` の応答、ctrl / cursor キューとの対応づけ、
//!   avail の `NO_INTERRUPT` と used の `flags`、観測カウンタ（いずれも F1.4）

use std::fmt;
use std::sync::atomic::{Ordering, fence};

use crate::vhost_user::VringAddr;

/// Queue Size の上限（仕様 2.7）。
pub const MAX_QUEUE_SIZE: u32 = 32768;
/// 1 チェーンの記述子数の上限。治具独自の値（ctrl の要求と応答は数個の記述子で足りる）。実際の上限は `num` との小さい方。
pub const MAX_CHAIN_LEN: usize = 64;
/// 1 チェーンの総バイト長の上限。治具独自の値（1 MiB。ctrl の要求・応答より十分大きく、巨大確保を避ける）。
pub const MAX_CHAIN_BYTES: u64 = 1 << 20;

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;
const DESC_F_INDIRECT: u16 = 4;
const DESC_SIZE: u64 = 16;

/// 機械可読なエラー種別。`as_str` の大文字スネーク表記が外部に出す code。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtqueueErrorCode {
    /// `num` が 0・2 の冪でない・[`MAX_QUEUE_SIZE`] 超。
    InvalidQueueSize,
    /// desc が 16、avail が 2、used が 4 バイトにそろっていない。
    MisalignedRing,
    /// `VringAddr.flags` が 0 でない（log ビット等。ログは未ネゴシエーション）。
    LogNotSupported,
    /// リング全体が 1 領域に収まらない、または user アドレスが未登録。
    RingOutOfRegion,
    /// 未処理数が `num` を超える（キュー破損）。
    InvalidAvailIdx,
    /// head または next が `num` 以上。
    DescIndexOutOfRange,
    /// 同じ記述子を二度辿った。
    ChainLoop,
    /// チェーンが上限を超えた。
    ChainTooLong,
    /// `INDIRECT` が立っている。
    IndirectUnsupported,
    /// NEXT・WRITE・INDIRECT 以外のビットが立っている。
    InvalidDescFlags,
    /// device-writable の後に device-readable の記述子がある。
    ReadableAfterWritable,
    /// 総バイト長が溢れた、または [`MAX_CHAIN_BYTES`] 超。
    ChainTooLarge,
    /// `add_used` の len が writable の容量を超える。
    UsedLenExceedsWritable,
    /// 下位のメモリアクセスが失敗した（境界外・アドレスの加算の溢れなど）。
    GuestMemory,
}

impl VirtqueueErrorCode {
    /// 外部に出す code 文字列。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidQueueSize => "INVALID_QUEUE_SIZE",
            Self::MisalignedRing => "MISALIGNED_RING",
            Self::LogNotSupported => "LOG_NOT_SUPPORTED",
            Self::RingOutOfRegion => "RING_OUT_OF_REGION",
            Self::InvalidAvailIdx => "INVALID_AVAIL_IDX",
            Self::DescIndexOutOfRange => "DESC_INDEX_OUT_OF_RANGE",
            Self::ChainLoop => "CHAIN_LOOP",
            Self::ChainTooLong => "CHAIN_TOO_LONG",
            Self::IndirectUnsupported => "INDIRECT_UNSUPPORTED",
            Self::InvalidDescFlags => "INVALID_DESC_FLAGS",
            Self::ReadableAfterWritable => "READABLE_AFTER_WRITABLE",
            Self::ChainTooLarge => "CHAIN_TOO_LARGE",
            Self::UsedLenExceedsWritable => "USED_LEN_EXCEEDS_WRITABLE",
            Self::GuestMemory => "GUEST_MEMORY",
        }
    }

    /// 英語の固定文（ゲスト由来の値を含めない）。
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidQueueSize => "queue size must be a power of two in 1..=32768",
            Self::MisalignedRing => "ring address is not aligned",
            Self::LogNotSupported => "vring log is not supported",
            Self::RingOutOfRegion => "ring is not contained in one memory region",
            Self::InvalidAvailIdx => "available index is ahead of the queue size",
            Self::DescIndexOutOfRange => "descriptor index is out of range",
            Self::ChainLoop => "descriptor chain has a loop",
            Self::ChainTooLong => "descriptor chain is too long",
            Self::IndirectUnsupported => "indirect descriptors are not supported",
            Self::InvalidDescFlags => "descriptor has unknown flags",
            Self::ReadableAfterWritable => "readable descriptor follows a writable one",
            Self::ChainTooLarge => "descriptor chain has too many bytes",
            Self::UsedLenExceedsWritable => "used length exceeds the writable capacity",
            Self::GuestMemory => "guest memory access failed",
        }
    }
}

/// virtqueue のエラー（固定語彙の code だけを持つ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtqueueError {
    /// 種別。
    pub code: VirtqueueErrorCode,
}

impl VirtqueueError {
    /// code から作る。
    pub fn new(code: VirtqueueErrorCode) -> Self {
        Self { code }
    }
}

impl fmt::Display for VirtqueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.code.message())
    }
}

impl std::error::Error for VirtqueueError {}

fn err(code: VirtqueueErrorCode) -> VirtqueueError {
    VirtqueueError::new(code)
}

/// virtqueue が使うゲストメモリの抽象。Linux では `GuestMemory` が実装し、テストでは合成メモリが実装する。
pub trait QueueMemory {
    /// GPA から `dst.len()` バイトをコピーする。
    fn read_at(&self, gpa: u64, dst: &mut [u8]) -> Result<(), VirtqueueError>;
    /// GPA へ `src` をコピーする。
    fn write_at(&self, gpa: u64, src: &[u8]) -> Result<(), VirtqueueError>;
    /// frontend の user アドレス（`SET_VRING_ADDR` の値）を GPA に変換する。`[uva, uva+len)` が 1 領域に収まる場合だけ成功する。
    fn translate_uva(&self, uva: u64, len: u64) -> Result<u64, VirtqueueError>;
}

/// 領域の列 `(userspace_addr, gpa, size)` から user アドレスを GPA に変換する純関数（checked 演算。領域をまたぐ範囲は拒否）。
pub fn translate_uva_in(
    regions: impl IntoIterator<Item = (u64, u64, u64)>,
    uva: u64,
    len: u64,
) -> Result<u64, VirtqueueError> {
    let bad = || err(VirtqueueErrorCode::RingOutOfRegion);
    let end = uva.checked_add(len).ok_or_else(bad)?;
    for (r_uva, r_gpa, r_size) in regions {
        let Some(r_end) = r_uva.checked_add(r_size) else {
            continue;
        };
        if uva >= r_uva && end <= r_end {
            return r_gpa.checked_add(uva - r_uva).ok_or_else(bad);
        }
    }
    Err(bad())
}

#[cfg(target_os = "linux")]
impl QueueMemory for crate::vhost_user::guest_memory::GuestMemory {
    fn read_at(&self, gpa: u64, dst: &mut [u8]) -> Result<(), VirtqueueError> {
        crate::vhost_user::guest_memory::GuestMemory::read_at(self, gpa, dst)
            .map_err(|_| err(VirtqueueErrorCode::GuestMemory))
    }

    fn write_at(&self, gpa: u64, src: &[u8]) -> Result<(), VirtqueueError> {
        crate::vhost_user::guest_memory::GuestMemory::write_at(self, gpa, src)
            .map_err(|_| err(VirtqueueErrorCode::GuestMemory))
    }

    fn translate_uva(&self, uva: u64, len: u64) -> Result<u64, VirtqueueError> {
        translate_uva_in(
            self.regions()
                .iter()
                .map(|r| (r.userspace_addr(), r.gpa(), r.size())),
            uva,
            len,
        )
    }
}

/// 検証済みのキュー設定。フィールドは非公開で、[`QueueConfig::new`] を通った値だけを持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueConfig {
    num: u16,
    desc_gpa: u64,
    avail_gpa: u64,
    used_gpa: u64,
}

impl QueueConfig {
    /// `SET_VRING_NUM` の `num` と `SET_VRING_ADDR` の値を検証して作る。
    ///
    /// 検査: `num`（2 の冪・1〜32768）、`flags == 0`、3 つのリングそれぞれの全長が 1 領域に収まること、
    /// user アドレスと GPA の両方のアラインメント（desc 16・avail 2・used 4）。
    pub fn new(num: u32, addr: &VringAddr, mem: &impl QueueMemory) -> Result<Self, VirtqueueError> {
        if num == 0 || num > MAX_QUEUE_SIZE || !num.is_power_of_two() {
            return Err(err(VirtqueueErrorCode::InvalidQueueSize));
        }
        if addr.flags != 0 {
            return Err(err(VirtqueueErrorCode::LogNotSupported));
        }
        let n = u64::from(num);
        let desc_gpa = Self::place(mem, addr.descriptor, DESC_SIZE * n, 16)?;
        let avail_gpa = Self::place(mem, addr.available, 4 + 2 * n, 2)?;
        let used_gpa = Self::place(mem, addr.used, 4 + 8 * n, 4)?;
        Ok(Self {
            // num <= 32768 なので u16 に収まる。
            num: u16::try_from(num).map_err(|_| err(VirtqueueErrorCode::InvalidQueueSize))?,
            desc_gpa,
            avail_gpa,
            used_gpa,
        })
    }

    fn place(
        mem: &impl QueueMemory,
        uva: u64,
        len: u64,
        align: u64,
    ) -> Result<u64, VirtqueueError> {
        let gpa = mem.translate_uva(uva, len)?;
        if !uva.is_multiple_of(align) || !gpa.is_multiple_of(align) {
            return Err(err(VirtqueueErrorCode::MisalignedRing));
        }
        // リング全体の GPA 範囲が溢れないことも確認する。
        gpa.checked_add(len)
            .ok_or_else(|| err(VirtqueueErrorCode::RingOutOfRegion))?;
        Ok(gpa)
    }

    /// キューサイズ。
    pub fn num(&self) -> u16 {
        self.num
    }
}

/// `pop` が返す記述子チェーン。`pop` 以外では作れず、[`SplitQueue::add_used`] で消費する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescChain {
    head: u16,
    readable: Vec<(u64, u32)>,
    writable: Vec<(u64, u32)>,
    readable_len: u64,
    writable_len: u64,
}

impl DescChain {
    /// 先頭の記述子の番号（used の `id` になる）。
    pub fn head(&self) -> u16 {
        self.head
    }
    /// device-readable 部分の `(gpa, len)` 列。
    pub fn readable(&self) -> &[(u64, u32)] {
        &self.readable
    }
    /// device-writable 部分の `(gpa, len)` 列。
    pub fn writable(&self) -> &[(u64, u32)] {
        &self.writable
    }
    /// readable の総バイト長。
    pub fn readable_len(&self) -> u64 {
        self.readable_len
    }
    /// writable の総バイト長。
    pub fn writable_len(&self) -> u64 {
        self.writable_len
    }

    /// readable 部分を先頭から `dst` へ詰めてコピーし、コピーしたバイト数を返す（上限は `dst.len()` と readable の総長）。
    pub fn read_readable(
        &self,
        mem: &impl QueueMemory,
        dst: &mut [u8],
    ) -> Result<usize, VirtqueueError> {
        let mut done = 0usize;
        for &(gpa, len) in &self.readable {
            // 長さ 0 の記述子は読むものが無いだけなので飛ばし、後続を読み続ける。
            // 打ち切るのは dst が満杯のときだけ。
            if done >= dst.len() {
                break;
            }
            let want = (len as usize).min(dst.len() - done);
            if want == 0 {
                continue;
            }
            let slot = dst
                .get_mut(done..done + want)
                .ok_or_else(|| err(VirtqueueErrorCode::GuestMemory))?;
            mem.read_at(gpa, slot)?;
            done += want;
        }
        Ok(done)
    }

    /// `src` を writable 部分へ先頭から順に書き、書いたバイト数（`add_used` の len に使える）を返す。
    /// 容量を超える場合は何も書かずに `USED_LEN_EXCEEDS_WRITABLE`。
    pub fn write_writable(
        &self,
        mem: &impl QueueMemory,
        src: &[u8],
    ) -> Result<u32, VirtqueueError> {
        if src.len() as u64 > self.writable_len {
            return Err(err(VirtqueueErrorCode::UsedLenExceedsWritable));
        }
        let mut rest = src;
        for &(gpa, len) in &self.writable {
            if rest.is_empty() {
                break;
            }
            let n = (len as usize).min(rest.len());
            // 長さ 0 の記述子は書くものが無く、GPA が未登録でもメモリへ触れない。
            if n == 0 {
                continue;
            }
            let (now, later) = rest.split_at(n);
            mem.write_at(gpa, now)?;
            rest = later;
        }
        u32::try_from(src.len()).map_err(|_| err(VirtqueueErrorCode::ChainTooLarge))
    }
}

/// split virtqueue 1 本の状態（デバイス側）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitQueue {
    config: QueueConfig,
    last_avail: u16,
    used_idx: u16,
}

impl SplitQueue {
    /// `last_avail` は `SET_VRING_BASE` の値、`used_idx` は used ring の現在の idx。
    pub fn new(config: QueueConfig, last_avail: u16, used_idx: u16) -> Self {
        Self {
            config,
            last_avail,
            used_idx,
        }
    }

    /// 次に取り出す avail ring の位置（`GET_VRING_BASE` の応答に使う）。
    pub fn last_avail(&self) -> u16 {
        self.last_avail
    }
    /// 次に書く used ring の位置。
    pub fn used_idx(&self) -> u16 {
        self.used_idx
    }

    fn read_u16(mem: &impl QueueMemory, gpa: u64) -> Result<u16, VirtqueueError> {
        let mut b = [0u8; 2];
        mem.read_at(gpa, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    fn addr_of(base: u64, off: u64) -> Result<u64, VirtqueueError> {
        base.checked_add(off)
            .ok_or_else(|| err(VirtqueueErrorCode::GuestMemory))
    }

    /// avail ring から 1 チェーンを取り出す。未処理が無ければ `None`。失敗時は `last_avail` を進めない。
    pub fn pop(&mut self, mem: &impl QueueMemory) -> Result<Option<DescChain>, VirtqueueError> {
        let cfg = self.config;
        let num = cfg.num;
        // avail.idx は 1 回だけ読む。以降の ring[] の読み出しより前に Acquire を置く。
        let avail_idx = Self::read_u16(mem, Self::addr_of(cfg.avail_gpa, 2)?)?;
        fence(Ordering::Acquire);
        let pending = avail_idx.wrapping_sub(self.last_avail);
        if pending == 0 {
            return Ok(None);
        }
        if pending > num {
            return Err(err(VirtqueueErrorCode::InvalidAvailIdx));
        }
        let slot = u64::from(self.last_avail % num);
        let head = Self::read_u16(mem, Self::addr_of(cfg.avail_gpa, 4 + 2 * slot)?)?;
        let chain = Self::walk(&cfg, mem, head)?;
        self.last_avail = self.last_avail.wrapping_add(1);
        Ok(Some(chain))
    }

    fn walk(
        cfg: &QueueConfig,
        mem: &impl QueueMemory,
        head: u16,
    ) -> Result<DescChain, VirtqueueError> {
        let num = cfg.num;
        // 訪問済みの集合。num の検証後に確保し、最大 512 個の u64（4 KiB）。
        let mut visited = vec![0u64; usize::from(num).div_ceil(64)];
        let limit = MAX_CHAIN_LEN.min(usize::from(num));
        let mut chain = DescChain {
            head,
            readable: Vec::new(),
            writable: Vec::new(),
            readable_len: 0,
            writable_len: 0,
        };
        let mut idx = head;
        let mut count = 0usize;
        loop {
            if idx >= num {
                return Err(err(VirtqueueErrorCode::DescIndexOutOfRange));
            }
            let word = visited
                .get_mut(usize::from(idx) / 64)
                .ok_or_else(|| err(VirtqueueErrorCode::DescIndexOutOfRange))?;
            let bit = 1u64 << (idx % 64);
            if *word & bit != 0 {
                return Err(err(VirtqueueErrorCode::ChainLoop));
            }
            if count >= limit {
                return Err(err(VirtqueueErrorCode::ChainTooLong));
            }
            *word |= bit;
            count += 1;

            // 記述子 16 バイトを 1 回だけコピーし、以降はそのコピーだけを使う。
            let mut raw = [0u8; 16];
            let at = Self::addr_of(cfg.desc_gpa, DESC_SIZE * u64::from(idx))?;
            mem.read_at(at, &mut raw)?;
            let (addr_b, rest) = raw.split_at(8);
            let (len_b, rest) = rest.split_at(4);
            let (flags_b, next_b) = rest.split_at(2);
            let conv = |_| err(VirtqueueErrorCode::GuestMemory);
            let addr = u64::from_le_bytes(addr_b.try_into().map_err(conv)?);
            let len = u32::from_le_bytes(len_b.try_into().map_err(conv)?);
            let flags = u16::from_le_bytes(flags_b.try_into().map_err(conv)?);
            let next = u16::from_le_bytes(next_b.try_into().map_err(conv)?);

            if flags & !(DESC_F_NEXT | DESC_F_WRITE | DESC_F_INDIRECT) != 0 {
                return Err(err(VirtqueueErrorCode::InvalidDescFlags));
            }
            if flags & DESC_F_INDIRECT != 0 {
                return Err(err(VirtqueueErrorCode::IndirectUnsupported));
            }
            addr.checked_add(u64::from(len))
                .ok_or_else(|| err(VirtqueueErrorCode::GuestMemory))?;
            chain
                .readable_len
                .checked_add(chain.writable_len)
                .and_then(|t| t.checked_add(u64::from(len)))
                .filter(|t| *t <= MAX_CHAIN_BYTES)
                .ok_or_else(|| err(VirtqueueErrorCode::ChainTooLarge))?;
            if flags & DESC_F_WRITE != 0 {
                chain.writable.push((addr, len));
                chain.writable_len += u64::from(len);
            } else {
                if !chain.writable.is_empty() {
                    return Err(err(VirtqueueErrorCode::ReadableAfterWritable));
                }
                chain.readable.push((addr, len));
                chain.readable_len += u64::from(len);
            }
            if flags & DESC_F_NEXT == 0 {
                return Ok(chain);
            }
            idx = next;
        }
    }

    /// 処理済みのチェーンを used ring へ返す。`len` は device が書いたバイト数（writable の総長以下）。
    /// 順序は要素の書き込み、Release の fence、`used.idx` の更新。
    pub fn add_used(
        &mut self,
        mem: &impl QueueMemory,
        chain: DescChain,
        len: u32,
    ) -> Result<(), VirtqueueError> {
        if u64::from(len) > chain.writable_len {
            return Err(err(VirtqueueErrorCode::UsedLenExceedsWritable));
        }
        let cfg = self.config;
        let slot = u64::from(self.used_idx % cfg.num);
        let mut elem = [0u8; 8];
        elem[..4].copy_from_slice(&u32::from(chain.head).to_le_bytes());
        elem[4..].copy_from_slice(&len.to_le_bytes());
        mem.write_at(Self::addr_of(cfg.used_gpa, 4 + 8 * slot)?, &elem)?;
        fence(Ordering::Release);
        let next = self.used_idx.wrapping_add(1);
        mem.write_at(Self::addr_of(cfg.used_gpa, 2)?, &next.to_le_bytes())?;
        self.used_idx = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
