//! ゲスト物理メモリのアクセス型（TASK-74.2.2・MVM-1・MVM-4・MS-7。OS 非依存・unsafe なし）。
//!
//! virtqueue（`virtqueue`）と virtio デバイス（`virtio_block` ほか）が、ゲストが書いた descriptor・データを
//! 読み書きする唯一の入口。docs/design/microvm-memory-ownership.md の決め事に従い、(1) アドレスは
//! [`GuestAddress`] の newtype、(2) 外へ参照を渡さず常にコピーで読み書きする（vCPU が並行して書き換えるため）、
//! (3) backing は [`GuestMemoryBacking`] で差し替える。実機の mmap backing と KVM への登録は `crate::microvm`（TASK-75.1。Linux のみ）が持つ。
//!
//! # 範囲外（REPAIR-3）
//! 領域は 1 つだけ（MMIO hole などを含む複数領域は未対応。判断記録の再評価条件）。
//! 本モジュールが提供する backing は [`HeapBacking`]（`Vec<u8>`。試験と KVM を使わない用途）だけで、mmap の backing は `crate::microvm`（Linux）と `crate::hvf::memory`（macOS。TASK-192.4）が提供する。
//!
//! # 外部入力の扱い
//! アドレス・長さはゲストが決める非信頼入力。範囲検査はすべて checked 演算で行い、panic しない。
//! エラーの `message` に値は載せない（ERR-1）。

use crate::error::{MicrovmError, MicrovmErrorCode};

/// [`HeapBacking`] の確保上限（無制限確保の防止）。
pub const MAX_HEAP_BACKING: u64 = 1 << 30;

fn out_of_range() -> MicrovmError {
    MicrovmError::new(
        MicrovmErrorCode::InvalidArgument,
        "guest memory access out of range",
    )
}

fn unaligned() -> MicrovmError {
    MicrovmError::new(
        MicrovmErrorCode::InvalidArgument,
        "unaligned guest memory access",
    )
}

/// ゲスト物理アドレス。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuestAddress(u64);

impl GuestAddress {
    /// 素の値から作る。
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }
    /// 素の値。
    pub const fn raw(self) -> u64 {
        self.0
    }
    /// 桁あふれしない加算。
    pub const fn checked_add(self, n: u64) -> Option<GuestAddress> {
        match self.0.checked_add(n) {
            Some(v) => Some(GuestAddress(v)),
            None => None,
        }
    }
}

/// ゲストメモリの実体（領域先頭からのオフセットで読み書きする）。
///
/// 範囲検査は [`GuestMemory`] が済ませてから呼ぶ。実装は並行する書き換えを前提にコピーで返す。
pub trait GuestMemoryBacking {
    /// 実体のバイト数。
    fn len(&self) -> u64;
    /// `offset` から `buf.len()` バイトを読む。
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError>;
    /// `offset` へ `data` を書く。
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError>;
    /// `offset` の 2 バイトを、整列した単一命令の volatile アクセスで読み、リトルエンディアンの u16 として返す。
    ///
    /// virtqueue の共有 index（`avail.idx`）専用（MVM-1・MVM-5・REPAIR-3・#3862）。`read` は 1 バイトずつのコピーなので、
    /// ゲストが同時に書くと tear した値が見える。この関数は tear しない読みを 1 回で行う。`offset` が奇数、または
    /// 範囲外なら `InvalidArgument`。意図的に既定実装を置かない（バイトコピーへ黙って退化して tear する実装を継承させないため）。
    fn read_u16_le_aligned(&self, offset: u64) -> Result<u16, MicrovmError>;
    /// `offset` へ u16 をリトルエンディアンで、整列した単一命令の volatile アクセスで書く（`used.idx` 専用。契約は読みと同じ）。
    fn write_u16_le_aligned(&mut self, offset: u64, v: u16) -> Result<(), MicrovmError>;
    /// 空か。
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// `Vec<u8>` の backing（試験と KVM を使わない用途）。
#[derive(Debug, Clone)]
pub struct HeapBacking {
    bytes: Vec<u8>,
}

impl HeapBacking {
    /// 0 埋めで確保する。`len` が [`MAX_HEAP_BACKING`] を超えるものは拒否する。
    pub fn new(len: u64) -> Result<Self, MicrovmError> {
        if len > MAX_HEAP_BACKING {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "heap backing too large",
            ));
        }
        let len = usize::try_from(len).map_err(|_| out_of_range())?;
        Ok(Self {
            bytes: vec![0; len],
        })
    }

    fn span(&self, offset: u64, len: usize) -> Result<std::ops::Range<usize>, MicrovmError> {
        let start = usize::try_from(offset).map_err(|_| out_of_range())?;
        let end = start.checked_add(len).ok_or_else(out_of_range)?;
        if end > self.bytes.len() {
            return Err(out_of_range());
        }
        Ok(start..end)
    }
}

impl GuestMemoryBacking for HeapBacking {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        let r = self.span(offset, buf.len())?;
        buf.copy_from_slice(self.bytes.get(r).ok_or_else(out_of_range)?);
        Ok(())
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
        let r = self.span(offset, data.len())?;
        self.bytes
            .get_mut(r)
            .ok_or_else(out_of_range)?
            .copy_from_slice(data);
        Ok(())
    }
    // 並行する書き手がいないので、バイト列の変換で足りる（tear しうる並行アクセスが無い）。奇数 offset は
    // 実機の backing と同じく拒否し、試験で整列の契約を確かめられるようにする。
    fn read_u16_le_aligned(&self, offset: u64) -> Result<u16, MicrovmError> {
        if !offset.is_multiple_of(2) {
            return Err(unaligned());
        }
        let mut b = [0u8; 2];
        self.read(offset, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }
    fn write_u16_le_aligned(&mut self, offset: u64, v: u16) -> Result<(), MicrovmError> {
        if !offset.is_multiple_of(2) {
            return Err(unaligned());
        }
        self.write(offset, &v.to_le_bytes())
    }
}

/// 単一領域のゲスト物理メモリ。
#[derive(Debug)]
pub struct GuestMemory<B: GuestMemoryBacking> {
    base: GuestAddress,
    backing: B,
}

impl<B: GuestMemoryBacking> GuestMemory<B> {
    /// 領域の先頭アドレスと実体から作る。`base + len` が桁あふれするものは拒否する。
    pub fn new(base: GuestAddress, backing: B) -> Result<Self, MicrovmError> {
        base.checked_add(backing.len()).ok_or_else(out_of_range)?;
        Ok(Self { base, backing })
    }

    /// 領域の先頭アドレス。
    pub fn base(&self) -> GuestAddress {
        self.base
    }

    /// 領域のバイト数。
    pub fn len(&self) -> u64 {
        self.backing.len()
    }

    /// 領域が空か。
    pub fn is_empty(&self) -> bool {
        self.backing.is_empty()
    }

    /// `[addr, addr + len)` が領域に収まるか確かめ、領域先頭からのオフセットを返す。
    pub fn check_range(&self, addr: GuestAddress, len: u64) -> Result<u64, MicrovmError> {
        let off = addr
            .raw()
            .checked_sub(self.base.raw())
            .ok_or_else(out_of_range)?;
        let end = off.checked_add(len).ok_or_else(out_of_range)?;
        if end > self.backing.len() {
            return Err(out_of_range());
        }
        Ok(off)
    }

    /// `buf.len()` バイトをコピーで読む。
    pub fn read_at(&self, addr: GuestAddress, buf: &mut [u8]) -> Result<(), MicrovmError> {
        let off = self.check_range(addr, buf.len() as u64)?;
        self.backing.read(off, buf)
    }

    /// `data` をコピーで書く。
    pub fn write_at(&mut self, addr: GuestAddress, data: &[u8]) -> Result<(), MicrovmError> {
        let off = self.check_range(addr, data.len() as u64)?;
        self.backing.write(off, data)
    }

    /// リトルエンディアンの u16 を読む。
    pub fn read_u16_le(&self, addr: GuestAddress) -> Result<u16, MicrovmError> {
        let mut b = [0u8; 2];
        self.read_at(addr, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    /// リトルエンディアンの u32 を読む。
    pub fn read_u32_le(&self, addr: GuestAddress) -> Result<u32, MicrovmError> {
        let mut b = [0u8; 4];
        self.read_at(addr, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    /// リトルエンディアンの u64 を読む。
    pub fn read_u64_le(&self, addr: GuestAddress) -> Result<u64, MicrovmError> {
        let mut b = [0u8; 8];
        self.read_at(addr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    /// リトルエンディアンの u16 を書く。
    pub fn write_u16_le(&mut self, addr: GuestAddress, v: u16) -> Result<(), MicrovmError> {
        self.write_at(addr, &v.to_le_bytes())
    }

    /// 共有 index 用: 2 バイト整列した u16 を単一命令の volatile で読む（MVM-1・MVM-5・REPAIR-3・#3862）。
    ///
    /// virtqueue の `avail.idx` 専用。`addr` が奇数なら `InvalidArgument`（"unaligned guest memory access"）。
    /// 範囲外は `read_u16_le` と同じ。ring の要素・記述子はこの関数を使わない（理由は `virtqueue` のモジュール doc）。
    pub fn read_u16_le_aligned(&self, addr: GuestAddress) -> Result<u16, MicrovmError> {
        if !addr.raw().is_multiple_of(2) {
            return Err(unaligned());
        }
        let off = self.check_range(addr, 2)?;
        self.backing.read_u16_le_aligned(off)
    }

    /// 共有 index 用: 2 バイト整列した u16 を単一命令の volatile で書く（`used.idx` 専用。契約は読みと同じ）。
    pub fn write_u16_le_aligned(&mut self, addr: GuestAddress, v: u16) -> Result<(), MicrovmError> {
        if !addr.raw().is_multiple_of(2) {
            return Err(unaligned());
        }
        let off = self.check_range(addr, 2)?;
        self.backing.write_u16_le_aligned(off, v)
    }

    /// リトルエンディアンの u32 を書く。
    pub fn write_u32_le(&mut self, addr: GuestAddress, v: u32) -> Result<(), MicrovmError> {
        self.write_at(addr, &v.to_le_bytes())
    }

    /// リトルエンディアンの u64 を書く。
    pub fn write_u64_le(&mut self, addr: GuestAddress, v: u64) -> Result<(), MicrovmError> {
        self.write_at(addr, &v.to_le_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem(base: u64, len: u64) -> GuestMemory<HeapBacking> {
        GuestMemory::new(GuestAddress::new(base), HeapBacking::new(len).unwrap()).unwrap()
    }

    /// MVM-1: 範囲内の読み書きがバイト列どおりに往復する。
    #[test]
    fn mvm1_roundtrip_bytes_and_integers() {
        let mut m = mem(0x1000, 0x100);
        m.write_at(GuestAddress::new(0x1010), &[1, 2, 3, 4])
            .unwrap();
        let mut b = [0u8; 4];
        m.read_at(GuestAddress::new(0x1010), &mut b).unwrap();
        assert_eq!(b, [1, 2, 3, 4]);
        assert_eq!(m.read_u16_le(GuestAddress::new(0x1010)).unwrap(), 0x0201);
        assert_eq!(
            m.read_u32_le(GuestAddress::new(0x1010)).unwrap(),
            0x0403_0201
        );
        m.write_u32_le(GuestAddress::new(0x1020), 0xdead_beef)
            .unwrap();
        assert_eq!(
            m.read_u64_le(GuestAddress::new(0x1020)).unwrap(),
            0xdead_beef
        );
        m.write_u16_le(GuestAddress::new(0x10fe), 0xabcd).unwrap();
        assert_eq!(m.read_u16_le(GuestAddress::new(0x10fe)).unwrap(), 0xabcd);
    }

    /// MVM-1・TASK-75.3.1: u64 の書き込みがバイト列と `read_u64_le` の両方で往復する。
    #[test]
    fn mvm1_write_u64_le_roundtrip() {
        let mut m = mem(0x1000, 0x100);
        m.write_u64_le(GuestAddress::new(0x1008), 0x0102_0304_0506_0708)
            .unwrap();
        let mut b = [0u8; 8];
        m.read_at(GuestAddress::new(0x1008), &mut b).unwrap();
        assert_eq!(b, [8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(
            m.read_u64_le(GuestAddress::new(0x1008)).unwrap(),
            0x0102_0304_0506_0708
        );
        assert!(m.write_u64_le(GuestAddress::new(0x10f9), 1).is_err());
    }

    /// MVM-1: 領域の外・桁あふれ・base より下はすべて InvalidArgument。
    #[test]
    fn mvm1_out_of_range_is_rejected() {
        let mut m = mem(0x1000, 0x100);
        let mut b = [0u8; 2];
        assert!(m.read_at(GuestAddress::new(0x10fe), &mut b).is_ok());
        for addr in [0x10ff, 0x1100, 0xfff, 0, u64::MAX, u64::MAX - 1] {
            let e = m.read_at(GuestAddress::new(addr), &mut b).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "guest memory access out of range");
        }
        assert!(m.write_at(GuestAddress::new(0x10ff), &[0, 0]).is_err());
        assert!(m.check_range(GuestAddress::new(0x1000), u64::MAX).is_err());
        assert_eq!(m.check_range(GuestAddress::new(0x1000), 0x100).unwrap(), 0);
    }

    /// MVM-1・MVM-5・#3862: 整列 u16 の往復（バイト列と一致）、奇数アドレス・範囲外の拒否。
    #[test]
    fn mvm1_aligned_u16_roundtrip_and_rejects_unaligned() {
        let mut m = mem(0x1000, 0x100);
        m.write_u16_le_aligned(GuestAddress::new(0x1002), 0xBEEF)
            .unwrap();
        let mut b = [0u8; 2];
        m.read_at(GuestAddress::new(0x1002), &mut b).unwrap();
        assert_eq!(b, [0xEF, 0xBE]);
        m.write_at(GuestAddress::new(0x1004), &[0x34, 0x12])
            .unwrap();
        assert_eq!(
            m.read_u16_le_aligned(GuestAddress::new(0x1004)).unwrap(),
            0x1234
        );
        // 末尾の 2 バイトは可。
        assert!(m.read_u16_le_aligned(GuestAddress::new(0x10fe)).is_ok());
        let e = m
            .read_u16_le_aligned(GuestAddress::new(0x1003))
            .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "unaligned guest memory access");
        let e = m
            .write_u16_le_aligned(GuestAddress::new(0x1003), 1)
            .unwrap_err();
        assert_eq!(e.message(), "unaligned guest memory access");
        for addr in [0x1100u64, 0x1102, 0xffe, 0, u64::MAX - 1] {
            let e = m.read_u16_le_aligned(GuestAddress::new(addr)).unwrap_err();
            assert_eq!(e.message(), "guest memory access out of range");
            let e = m
                .write_u16_le_aligned(GuestAddress::new(addr), 1)
                .unwrap_err();
            assert_eq!(e.message(), "guest memory access out of range");
        }
    }

    /// MVM-1・#3862: base が奇数で、アドレスは偶数でも backing の offset が奇数になる場合は backing が拒否する。
    #[test]
    fn mvm1_aligned_u16_rejects_odd_backing_offset() {
        let m = mem(0x1001, 0x100);
        let e = m
            .read_u16_le_aligned(GuestAddress::new(0x1002))
            .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "unaligned guest memory access");
    }

    /// MVM-1: 上限超えの確保と、末尾が桁あふれする base を拒否する。
    #[test]
    fn mvm1_rejects_oversized_backing_and_wrapping_base() {
        assert!(HeapBacking::new(MAX_HEAP_BACKING + 1).is_err());
        let r = GuestMemory::new(GuestAddress::new(u64::MAX), HeapBacking::new(16).unwrap());
        assert_eq!(r.unwrap_err().code(), MicrovmErrorCode::InvalidArgument);
    }
}
