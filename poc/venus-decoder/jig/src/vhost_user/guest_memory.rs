//! ゲストメモリ領域の mmap と境界検査つきアクセス（GPU-6・MVM-4・TASK-172 F1.2・#1517）。
//!
//! 役割: `SET_MEM_TABLE` の領域（[`MemRegion`]）と受け取った fd を検証して `MAP_SHARED` で map し、ゲスト物理アドレス
//! （GPA）からの読み書きを境界検査つきのコピーだけで提供する。解放は `Drop`。呼び出し元は F1.3（virtqueue の走査。#1518）と
//! F1.4（セッション。#1519）。生ポインタ・スライス参照は公開しない（共有メモリへの参照は frontend / ゲストの同時書き込みで
//! エイリアシング規則に反するため）。syscall は `crate::sys`（unsafe の承認範囲）に閉じる。
//!
//! # map 方式
//! 領域ごとに fd の先頭（file offset 0）から `mmap_offset + memory_size` バイトを map し、領域の先頭をマップ内の
//! `mmap_offset` の位置として扱う。ページ境界にそろっていない `mmap_offset` でも `EINVAL` にならず、ページサイズの
//! 問い合わせも要らない。上限（[`MAX_REGION_SIZE`]・[`MAX_TOTAL_MAP_LEN`]）は mmap より前に検証する。
//!
//! # 残余リスク（PoC の割り切り）
//! map 前にファイル長を検査するが、frontend が後から `ftruncate` で縮めると EOF を超えたアクセスは `SIGBUS` になる。
//! frontend はローカルの VMM で、backend 側に seal を強制する手段は無い。製品版は TASK-173 系で扱う。
//! 領域をまたぐアクセスは `OUT_OF_BOUNDS` で拒否する（PoC の割り切り）。`userspace_addr` は vring アドレスの変換
//! （F1.3 / F1.4）で使うので [`GuestMemoryRegion::userspace_addr`] で保持だけし、ここでは使わない。

use std::fs::File;
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, OwnedFd};

use super::MemRegion;
use super::MemTable;
use super::transport_error::{TransportError, TransportErrorCode};
use crate::sys::{self, MmapRegion};

/// 1 領域の map 長（`mmap_offset + memory_size`）の上限。仮想アドレス空間の浪費（DoS）を防ぐ治具独自の値で、64 GiB。
pub const MAX_REGION_SIZE: u64 = 64 << 30;
/// 全領域の map 長の合計の上限。治具独自の値で、128 GiB。
pub const MAX_TOTAL_MAP_LEN: u64 = 128 << 30;

fn err(code: TransportErrorCode) -> TransportError {
    TransportError::new(code)
}

fn map_sys_oob(_: sys::SysError) -> TransportError {
    // sys 側の再検査（多層防御）に掛かった場合。上位の検査をすり抜けたことを意味するので範囲外として拒否する。
    err(TransportErrorCode::OutOfBounds)
}

/// map 済みのゲストメモリ領域 1 個。
#[derive(Debug)]
pub struct GuestMemoryRegion {
    map: MmapRegion,
    gpa: u64,
    size: u64,
    map_offset: usize,
    userspace_addr: u64,
}

impl GuestMemoryRegion {
    /// `region` の記述に従って `file` を map する。mmap より前に値とファイル長を検証する。
    ///
    /// - `memory_size` は 0 より大きく、`mmap_offset + memory_size`（map 長）は [`MAX_REGION_SIZE`] 以下（`INVALID_REGION`）
    /// - `guest_phys_addr + memory_size` と `mmap_offset + memory_size` が overflow しない（`INVALID_REGION`）
    /// - ファイル長が map 長以上（`FILE_TOO_SHORT`）
    pub fn map(file: &File, region: &MemRegion) -> Result<Self, TransportError> {
        let bad = || err(TransportErrorCode::InvalidRegion);
        if region.memory_size == 0 {
            return Err(bad());
        }
        region
            .guest_phys_addr
            .checked_add(region.memory_size)
            .ok_or_else(bad)?;
        let map_len = region
            .mmap_offset
            .checked_add(region.memory_size)
            .filter(|n| *n <= MAX_REGION_SIZE)
            .ok_or_else(bad)?;
        let map_len_usize = usize::try_from(map_len).map_err(|_| bad())?;
        let map_offset = usize::try_from(region.mmap_offset).map_err(|_| bad())?;
        let file_len = file
            .metadata()
            .map_err(|e| TransportError::from_io(&e))?
            .len();
        if file_len < map_len {
            return Err(err(TransportErrorCode::FileTooShort));
        }
        let non_zero = NonZeroUsize::new(map_len_usize).ok_or_else(bad)?;
        let map =
            MmapRegion::map_shared(file.as_fd(), non_zero).map_err(TransportError::from_sys)?;
        Ok(Self {
            map,
            gpa: region.guest_phys_addr,
            size: region.memory_size,
            map_offset,
            userspace_addr: region.userspace_addr,
        })
    }

    /// 領域の先頭のゲスト物理アドレス。
    pub fn gpa(&self) -> u64 {
        self.gpa
    }

    /// 領域のサイズ（バイト）。
    pub fn size(&self) -> u64 {
        self.size
    }

    /// frontend プロセス側の user アドレス（vring アドレスの変換用。F1.3 / F1.4）。
    pub fn userspace_addr(&self) -> u64 {
        self.userspace_addr
    }

    /// map 長（`mmap_offset + memory_size`）。
    pub fn mapped_len(&self) -> usize {
        self.map.len()
    }

    /// `gpa` から `len` バイトのアクセスが領域内に収まるなら、map 内のオフセットを返す。
    fn locate(&self, gpa: u64, len: usize) -> Result<usize, TransportError> {
        let oob = || err(TransportErrorCode::OutOfBounds);
        let off = gpa.checked_sub(self.gpa).ok_or_else(oob)?;
        let len64 = u64::try_from(len).map_err(|_| oob())?;
        let end = off.checked_add(len64).ok_or_else(oob)?;
        if end > self.size {
            return Err(oob());
        }
        let off = usize::try_from(off).map_err(|_| oob())?;
        self.map_offset.checked_add(off).ok_or_else(oob)
    }

    /// `gpa` から `dst.len()` バイトを `dst` へコピーする。範囲外は `OUT_OF_BOUNDS`（長さ 0 は領域内に限り成功）。
    pub fn read_at(&self, gpa: u64, dst: &mut [u8]) -> Result<(), TransportError> {
        let at = self.locate(gpa, dst.len())?;
        self.map.copy_out(at, dst).map_err(map_sys_oob)
    }

    /// `src` を `gpa` へコピーする。範囲外は `OUT_OF_BOUNDS`（長さ 0 は領域内に限り成功）。
    pub fn write_at(&self, gpa: u64, src: &[u8]) -> Result<(), TransportError> {
        let at = self.locate(gpa, src.len())?;
        self.map.copy_in(at, src).map_err(map_sys_oob)
    }

    fn contains(&self, gpa: u64) -> bool {
        // gpa + size の overflow は map 時に検証済み。
        gpa >= self.gpa && gpa - self.gpa < self.size
    }
}

/// `SET_MEM_TABLE` 全体のゲストメモリ。GPA から領域を引いてアクセスする。
#[derive(Debug)]
pub struct GuestMemory {
    regions: Vec<GuestMemoryRegion>,
}

impl GuestMemory {
    /// `table` の各領域を、同じ順序の `fds` と対応させて map する。
    ///
    /// 領域数と fd 数が違えば `FD_COUNT_MISMATCH`、GPA の範囲が重なれば `OVERLAPPING_REGIONS`、map 長の合計が
    /// [`MAX_TOTAL_MAP_LEN`] を超えれば `INVALID_REGION`。途中で失敗しても map 済みの領域は `Drop` で解放される。
    pub fn from_table(table: &MemTable, fds: Vec<OwnedFd>) -> Result<Self, TransportError> {
        let specs = table.regions();
        if specs.len() != fds.len() {
            return Err(err(TransportErrorCode::FdCountMismatch));
        }
        let mut regions: Vec<GuestMemoryRegion> = Vec::with_capacity(specs.len());
        let mut total: u64 = 0;
        for (spec, fd) in specs.iter().zip(fds) {
            let file = File::from(fd);
            let region = GuestMemoryRegion::map(&file, spec)?;
            // map 長は MAX_REGION_SIZE 以下で、領域数は 32 以下なので u64 の加算は溢れない。
            total += u64::try_from(region.mapped_len()).unwrap_or(u64::MAX);
            if total > MAX_TOTAL_MAP_LEN {
                return Err(err(TransportErrorCode::InvalidRegion));
            }
            // gpa + size の overflow は map 時に検証済み。
            let (start, end) = (region.gpa, region.gpa + region.size);
            if regions
                .iter()
                .any(|r| start < r.gpa + r.size && r.gpa < end)
            {
                return Err(err(TransportErrorCode::OverlappingRegions));
            }
            regions.push(region);
        }
        Ok(Self { regions })
    }

    /// 領域の一覧（`SET_MEM_TABLE` の順序）。
    pub fn regions(&self) -> &[GuestMemoryRegion] {
        &self.regions
    }

    fn find(&self, gpa: u64) -> Result<&GuestMemoryRegion, TransportError> {
        self.regions
            .iter()
            .find(|r| r.contains(gpa))
            .ok_or_else(|| err(TransportErrorCode::OutOfBounds))
    }

    /// `gpa` を含む 1 領域の中に収まるアクセスだけ許す。領域をまたぐと `OUT_OF_BOUNDS`。
    pub fn read_at(&self, gpa: u64, dst: &mut [u8]) -> Result<(), TransportError> {
        self.find(gpa)?.read_at(gpa, dst)
    }

    /// [`Self::read_at`] の書き込み版。
    pub fn write_at(&self, gpa: u64, src: &[u8]) -> Result<(), TransportError> {
        self.find(gpa)?.write_at(gpa, src)
    }
}
