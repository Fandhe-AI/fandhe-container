//! ゲストメモリ領域の mmap と境界検査つきアクセス（GPU-6・MVM-4・TASK-172 F1.2・#1517）。
//!
//! 役割: `SET_MEM_TABLE` の領域（[`MemRegion`]）と受け取った fd を検証して `MAP_SHARED` で map し、ゲスト物理アドレス
//! （GPA）からの読み書きを境界検査つきのコピーだけで提供する。解放は `Drop`。呼び出し元は F1.3（`crate::virtqueue`。#1518。`QueueMemory` を実装して使う）と
//! F1.4（セッション。#1519）。生ポインタ・スライス参照は公開しない（共有メモリへの参照は frontend / ゲストの同時書き込みで
//! エイリアシング規則に反するため）。syscall は `crate::sys`（unsafe の承認範囲）に閉じる。
//!
//! # map 方式
//! 領域ごとに fd の先頭（file offset 0）から `mmap_offset + memory_size` バイトを map し、領域の先頭をマップ内の
//! `mmap_offset` の位置として扱う。ページ境界にそろっていない `mmap_offset` でも `EINVAL` にならず、ページサイズの
//! 問い合わせも要らない。上限（[`MAX_REGION_SIZE`]・[`MAX_TOTAL_MAP_LEN`]）は mmap より前に検証する。
//!
//! # 縮小の封じ込め（SIGBUS 対策）
//! map 前のファイル長検査だけでは、frontend が後から `ftruncate` で縮めると EOF を超えたアクセスが `SIGBUS` になり
//! backend 全体が落ちる。このため `fcntl(F_GET_SEALS)` で `F_SEAL_SHRINK` を確認し、縮まないと確認できない fd
//! （seal なしの memfd 等）は `SHRINK_NOT_SEALED` で map せず拒否する（fail-closed）。
//! seal は取り消せないので、確認後に縮むことは無い。長さの検査は seal の確認後に行う。
//! それより前に、backing file が治具自身の作る memfd と同じ shmem のファイルシステム（`st_dev`）にあることを確かめ、
//! 違う fd（hugetlb の memfd・通常ファイル等）は `UNSUPPORTED_BACKING` で拒否する。hugetlb の memfd は hole punch の後に
//! SIGBUS になり得て、huge page に揃わない長さの munmap が失敗してマッピングが残るため。
//! 領域をまたぐアクセスは `OUT_OF_BOUNDS` で拒否する（PoC の割り切り）。`userspace_addr` は vring アドレスの変換
//! （F1.3 / F1.4）で使うので [`GuestMemoryRegion::userspace_addr`] で保持だけし、ここでは使わない。
//!
//! # 排他性（プロセス内の並行アクセスの封じ込め）
//! 読み書きは `copy_nonoverlapping`（非アトミック）なので、プロセス内で同じ backing memory へ並行にアクセスできると
//! データ競合になる。これを safe API だけでは起こせないよう、次の 2 つを保証する。
//! - 領域の型は `!Send` / `!Sync`（1 領域は 1 スレッドからしか使えない）
//! - backing file（`st_dev`・`st_ino`）のアクセス範囲（ファイル上の `[mmap_offset, mmap_offset + memory_size)`）ごとに、
//!   生きている領域は 1 個だけ。重なる範囲を別の領域で map しようとすると mmap より前に `BACKING_IN_USE` で拒否する
//!   （占有一覧は `sys::MmapRegion` が持ち、seal・ファイル長の検査とあわせて map と不可分に行う）。
//!   fd を複製（`dup`・`try_clone`・`/proc/self/fd` の再オープン）しても同じ inode なので同じ判定になる。
//!   同じ memfd の重ならない範囲を別領域にする frontend（4 GiB 境界の上下で分ける等）は受け付ける
//!
//!
//! # 残っている前提
//! - frontend プロセスによる同時書き込みは、Rust の抽象機械の外にある非アトミックなコピー（`copy_nonoverlapping`）として
//!   扱う（コピーした値が不定になるだけで、マッピング外は触らない）。アトミックなコピーへの置き換えは
//!   `copy_nonoverlapping`（U8）と別の unsafe になり U1〜U10 の承認範囲外のため、承認を得るまで行わない
//! - 後続の F1.3（virtqueue。#1518）は、[`GuestMemory::read_at`] でコピーした後のバッファだけを解析する。共有メモリから
//!   同じ値を二度読むと、その間に frontend が書き換えて検査済みの値と使う値が食い違い得る（二度読み・TOCTOU）
//! - `SET_MEM_TABLE` の送り直し（F1.4・#1519）では、古い [`GuestMemory`] を drop してから新しい表を map する
//!   （生かしたままだと同じ memfd の重なる範囲が `BACKING_IN_USE` になる）。合計上限は `GuestMemory` 1 個の中だけで、
//!   セッション単位の上限は F1.4 で決める

use std::fs::File;
use std::num::NonZeroUsize;
use std::os::fd::OwnedFd;

use super::MemRegion;
use super::MemTable;
use super::observe::{self, Op};
use super::transport_error::{TransportError, TransportErrorCode};
use crate::sys::MmapRegion;

/// 1 領域の map 長（`mmap_offset + memory_size`）の上限。仮想アドレス空間の浪費（DoS）を防ぐ治具独自の値で、64 GiB。
pub const MAX_REGION_SIZE: u64 = 64 << 30;
/// 全領域の map 長の合計の上限。治具独自の値で、128 GiB。
pub const MAX_TOTAL_MAP_LEN: u64 = 128 << 30;

fn err(code: TransportErrorCode) -> TransportError {
    TransportError::new(code)
}

/// map 済みのゲストメモリ領域 1 個。
///
/// `!Send` / `!Sync`（内部の `sys::MmapRegion` が生ポインタの marker を持つため）。同じ backing file の重なる範囲を
/// 別の領域で同時に map できない（モジュール doc の「排他性」）。
#[derive(Debug)]
pub struct GuestMemoryRegion {
    map: MmapRegion,
    gpa: u64,
    /// 領域の末尾（`gpa + size`。map 時に checked 演算で求めて保持し、以降の判定で加減算しない）。
    gpa_end: u64,
    size: u64,
    map_offset: usize,
    userspace_addr: u64,
}

impl GuestMemoryRegion {
    /// `region` の記述に従って `file` を map する。mmap より前に値とファイル長を検証する。
    ///
    /// - `memory_size` は 0 より大きく、`mmap_offset + memory_size`（map 長）は [`MAX_REGION_SIZE`] 以下（`INVALID_REGION`）
    /// - `guest_phys_addr + memory_size` と `mmap_offset + memory_size` が overflow しない（`INVALID_REGION`）
    /// - fd が治具自身の作る memfd と同じ `st_dev`（shmem）にある（`UNSUPPORTED_BACKING`。hugetlb の memfd・通常ファイル等）
    /// - fd が `F_SEAL_SHRINK` つきで縮まない（`SHRINK_NOT_SEALED`。seal 非対応の fd の `EINVAL` もこれに含める）
    /// - ファイル長が map 長以上（`FILE_TOO_SHORT`。seal の確認後に検査する）
    /// - 同じ backing file の重なる範囲を map している領域が生きていない（`BACKING_IN_USE`。mmap の直前に占有する）
    ///
    /// 結果と所要時間は観測カウンタに計上する（REPAIR-4。検証の拒否も失敗として数える）。
    pub fn map(file: &File, region: &MemRegion) -> Result<Self, TransportError> {
        observe::global().observe(Op::MemMap, || Self::map_raw(file, region))
    }

    fn map_raw(file: &File, region: &MemRegion) -> Result<Self, TransportError> {
        let bad = || err(TransportErrorCode::InvalidRegion);
        if region.memory_size == 0 {
            return Err(bad());
        }
        let gpa_end = region
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
        let non_zero = NonZeroUsize::new(map_len_usize).ok_or_else(bad)?;
        // seal・ファイル長・アクセス範囲の占有の検証は、map と不可分に `sys::MmapRegion::map_shared` が行う。
        let map = MmapRegion::map_shared(file, region.mmap_offset, non_zero)
            .map_err(TransportError::from_sys)?;
        Ok(Self {
            map,
            gpa: region.guest_phys_addr,
            gpa_end,
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
    /// 結果と所要時間は観測カウンタに計上する（REPAIR-4）。
    pub fn read_at(&self, gpa: u64, dst: &mut [u8]) -> Result<(), TransportError> {
        observe::global().observe(Op::MemRead, || self.read_raw(gpa, dst))
    }

    /// `src` を `gpa` へコピーする。範囲外は `OUT_OF_BOUNDS`（長さ 0 は領域内に限り成功）。
    /// 結果と所要時間は観測カウンタに計上する（REPAIR-4）。
    pub fn write_at(&self, gpa: u64, src: &[u8]) -> Result<(), TransportError> {
        observe::global().observe(Op::MemWrite, || self.write_raw(gpa, src))
    }

    /// 計上なしの読み出し（`GuestMemory` が領域の検索失敗も含めて 1 回として計上するために使う）。
    fn read_raw(&self, gpa: u64, dst: &mut [u8]) -> Result<(), TransportError> {
        let at = self.locate(gpa, dst.len())?;
        self.map.copy_out(at, dst).map_err(TransportError::from_sys)
    }

    fn write_raw(&self, gpa: u64, src: &[u8]) -> Result<(), TransportError> {
        let at = self.locate(gpa, src.len())?;
        self.map.copy_in(at, src).map_err(TransportError::from_sys)
    }

    fn contains(&self, gpa: u64) -> bool {
        self.gpa <= gpa && gpa < self.gpa_end
    }
}

/// `SET_MEM_TABLE` 全体のゲストメモリ。GPA から領域を引いてアクセスする。
///
/// `!Send` / `!Sync`（内部の `sys::MmapRegion` が生ポインタの marker を持つため）。`read_at` / `write_at` は `&self` から非アトミックに
/// コピーするので、スレッド間で共有・移動できないことをコンパイル時に保証する（GPU-6）。
///
/// ```compile_fail,E0277
/// fn need_sync<T: Sync>() {}
/// need_sync::<fandhe_container_poc_venus_jig::vhost_user::guest_memory::GuestMemory>();
/// ```
///
/// ```compile_fail,E0277
/// fn need_send<T: Send>() {}
/// need_send::<fandhe_container_poc_venus_jig::vhost_user::guest_memory::GuestMemoryRegion>();
/// ```
#[derive(Debug)]
pub struct GuestMemory {
    regions: Vec<GuestMemoryRegion>,
}

impl GuestMemory {
    /// `table` の各領域を、同じ順序の `fds` と対応させて map する。
    ///
    /// 領域数と fd 数が違えば `FD_COUNT_MISMATCH`、GPA の範囲が重なれば `OVERLAPPING_REGIONS`、map 長の合計が
    /// [`MAX_TOTAL_MAP_LEN`] を超えれば（mmap より前に判定して）`INVALID_REGION`。途中で失敗しても map 済みの領域は `Drop` で解放される。
    /// 結果と所要時間は観測カウンタに計上する（REPAIR-4。入口の検証失敗も含む。領域ごとの map は別に `MemMap` として計上する）。
    pub fn from_table(table: &MemTable, fds: Vec<OwnedFd>) -> Result<Self, TransportError> {
        observe::global().observe(Op::MemTable, || Self::from_table_raw(table, fds))
    }

    fn from_table_raw(table: &MemTable, fds: Vec<OwnedFd>) -> Result<Self, TransportError> {
        let specs = table.regions();
        if specs.len() != fds.len() {
            return Err(err(TransportErrorCode::FdCountMismatch));
        }
        // 合計の上限は mmap より前に checked 演算で検証する（超過入力でアドレス空間を確保しない）。
        // 1 領域ごとの値検証は `GuestMemoryRegion::map` が行うので、ここでは map 長の合計だけを見る。
        let mut total: u64 = 0;
        for spec in specs {
            total = spec
                .mmap_offset
                .checked_add(spec.memory_size)
                .filter(|len| *len <= MAX_REGION_SIZE)
                .and_then(|len| total.checked_add(len))
                .filter(|t| *t <= MAX_TOTAL_MAP_LEN)
                .ok_or_else(|| err(TransportErrorCode::InvalidRegion))?;
        }
        let mut regions: Vec<GuestMemoryRegion> = Vec::with_capacity(specs.len());
        for (spec, fd) in specs.iter().zip(fds) {
            let file = File::from(fd);
            let region = GuestMemoryRegion::map(&file, spec)?;
            let (start, end) = (region.gpa, region.gpa_end);
            if regions.iter().any(|r| start < r.gpa_end && r.gpa < end) {
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
    /// 領域が見つからない失敗も含めて 1 回の操作として観測カウンタに計上する（REPAIR-4）。
    pub fn read_at(&self, gpa: u64, dst: &mut [u8]) -> Result<(), TransportError> {
        observe::global().observe(Op::MemRead, || self.find(gpa)?.read_raw(gpa, dst))
    }

    /// [`Self::read_at`] の書き込み版。
    pub fn write_at(&self, gpa: u64, src: &[u8]) -> Result<(), TransportError> {
        observe::global().observe(Op::MemWrite, || self.find(gpa)?.write_raw(gpa, src))
    }
}

// 実際の syscall を使うので、定数を定義している x86_64 / aarch64 でだけ走らせる（他アーキは `UNSUPPORTED` を返す）。
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::*;
    use crate::vhost_user::fd_passing::create_memfd;
    use std::os::unix::fs::FileExt;

    fn region(gpa: u64, size: u64, off: u64) -> MemRegion {
        MemRegion {
            guest_phys_addr: gpa,
            memory_size: size,
            userspace_addr: 0x7000_0000,
            mmap_offset: off,
        }
    }

    /// gpa=0x1000・size=0x2000・mmap_offset=0 の領域。
    fn basic() -> (File, GuestMemoryRegion) {
        let f = create_memfd(c"jig-gm-basic", 0x2000).expect("memfd");
        let r = GuestMemoryRegion::map(&f, &region(0x1000, 0x2000, 0)).expect("map");
        (f, r)
    }

    /// GPU-6・REPAIR-12: `locate` の境界。領域内の先頭・末尾ちょうどは成功、1 バイト超過は `OUT_OF_BOUNDS`。
    #[test]
    fn gpu6_locate_boundaries() {
        let (_f, r) = basic();
        assert_eq!(r.locate(0x1000, 0x2000).expect("whole"), 0);
        assert_eq!(r.locate(0x2fff, 1).expect("last byte"), 0x1fff);
        for (gpa, len) in [(0x1000, 0x2001), (0x2fff, 2), (0x3000, 1)] {
            let e = r.locate(gpa, len).expect_err("oob");
            assert_eq!(e.code, TransportErrorCode::OutOfBounds, "gpa={gpa:#x}");
        }
    }

    /// GPU-6・REPAIR-12: `gpa - 領域先頭` の減算 underflow と `off + len` の加算 overflow は `OUT_OF_BOUNDS`（panic しない）。
    #[test]
    fn gpu6_locate_arithmetic_overflow_is_rejected() {
        let (_f, r) = basic();
        // 領域より前の GPA（減算 underflow）。
        for gpa in [0, 0xfff] {
            let e = r.locate(gpa, 1).expect_err("below region");
            assert_eq!(e.code, TransportErrorCode::OutOfBounds);
        }
        // off = 0x10 に usize::MAX を足すと u64 で overflow する。
        let e = r.locate(0x1010, usize::MAX).expect_err("add overflow");
        assert_eq!(e.code, TransportErrorCode::OutOfBounds);
        let mut dst = [0u8; 1];
        let e = r.read_at(u64::MAX, &mut dst).expect_err("max gpa");
        assert_eq!(e.code, TransportErrorCode::OutOfBounds);
    }

    /// GPU-6・REPAIR-12: 長さ 0 は領域末尾ちょうど（gpa+size）まで成功し、それを超えると失敗する。
    /// 領域単体では末尾の 1 つ先も長さ 0 なら成功、`GuestMemory` は領域に含まれない GPA として拒否する。
    #[test]
    fn gpu6_zero_length_at_region_end() {
        let (_f, r) = basic();
        assert_eq!(r.locate(0x1000, 0).expect("start"), 0);
        assert_eq!(r.locate(0x3000, 0).expect("end"), 0x2000);
        let e = r.locate(0x3001, 0).expect_err("past end");
        assert_eq!(e.code, TransportErrorCode::OutOfBounds);
        r.read_at(0x3000, &mut []).expect("empty read at end");
        r.write_at(0x1000, &[]).expect("empty write at start");

        let f = create_memfd(c"jig-gm-zero", 0x2000).expect("memfd");
        let table = MemTable::new(&[region(0x1000, 0x2000, 0)]).expect("table");
        let gm = GuestMemory::from_table(&table, vec![OwnedFd::from(f)]).expect("gm");
        gm.read_at(0x1000, &mut []).expect("empty read in region");
        let e = gm
            .read_at(0x3000, &mut [])
            .expect_err("end is not in region");
        assert_eq!(e.code, TransportErrorCode::OutOfBounds);
    }

    /// GPU-6・REPAIR-12: ページ境界にそろっていない `mmap_offset`（0x123）でも map でき、領域の先頭は
    /// ファイルの 0x123 バイト目に対応する。`locate` の結果にもオフセットが足される。
    #[test]
    fn gpu6_unaligned_mmap_offset() {
        let f = create_memfd(c"jig-gm-unaligned", 0x123 + 0x100).expect("memfd");
        let r = GuestMemoryRegion::map(&f, &region(0x4000, 0x100, 0x123)).expect("map");
        assert_eq!(r.mapped_len(), 0x223);
        assert_eq!(r.locate(0x4000, 4).expect("head"), 0x123);
        assert_eq!(r.locate(0x40fc, 4).expect("tail"), 0x123 + 0xfc);
        r.write_at(0x4000, b"ABCD").expect("write");
        let mut got = [0u8; 4];
        f.read_exact_at(&mut got, 0x123).expect("file read");
        assert_eq!(&got, b"ABCD");
        let mut back = [0u8; 4];
        r.read_at(0x4000, &mut back).expect("read");
        assert_eq!(&back, b"ABCD");
        // 領域末尾を 1 バイト超えると拒否される（ファイル側の余りではなく領域サイズで判定）。
        let e = r.write_at(0x40fd, b"ABCD").expect_err("oob");
        assert_eq!(e.code, TransportErrorCode::OutOfBounds);
    }

    /// GPU-6: 同じ memfd の重なる範囲は、先の領域が生きている間 `BACKING_IN_USE` で拒否し、drop 後は map できる。
    /// fd を複製しても同じ inode として判定する。
    #[test]
    fn gpu6_overlapping_backing_range_is_exclusive() {
        let f = create_memfd(c"jig-gm-lease", 0x3000).expect("memfd");
        let dup = f.try_clone().expect("dup");
        let first = GuestMemoryRegion::map(&f, &region(0x1000, 0x2000, 0)).expect("first");
        // ファイル上 [0x1000, 0x3000) は [0, 0x2000) と 0x1000 バイト重なる。
        let e = GuestMemoryRegion::map(&dup, &region(0x8000, 0x2000, 0x1000)).expect_err("overlap");
        assert_eq!(e.code, TransportErrorCode::BackingInUse);
        assert_eq!(e.code.as_str(), "BACKING_IN_USE");
        // 重ならない範囲 [0x2000, 0x3000) は受け付ける。
        let tail = GuestMemoryRegion::map(&dup, &region(0x8000, 0x1000, 0x2000)).expect("disjoint");
        assert_eq!(tail.mapped_len(), 0x3000);
        drop(first);
        let again = GuestMemoryRegion::map(&dup, &region(0x1000, 0x2000, 0)).expect("after drop");
        assert_eq!(again.mapped_len(), 0x2000);
    }

    /// GPU-6・REPAIR-12: 領域の末尾は map 時の値を使う。GPA 空間の末尾（`u64::MAX`）に接する領域でも加減算で
    /// overflow せず、末尾ちょうどは領域外、接するだけの 2 領域は重ならない。
    #[test]
    fn gpu6_region_end_is_kept_without_arithmetic() {
        let f = create_memfd(c"jig-gm-end", 0x1000).expect("memfd");
        let top = u64::MAX - 0x1000;
        let r = GuestMemoryRegion::map(&f, &region(top, 0x1000, 0)).expect("map");
        assert_eq!(r.gpa_end, u64::MAX);
        assert!(r.contains(u64::MAX - 1));
        assert!(!r.contains(u64::MAX));
        assert!(!r.contains(top - 1));
        drop(r);
        let (a, b) = (
            create_memfd(c"jig-gm-adj-a", 0x1000).expect("memfd"),
            create_memfd(c"jig-gm-adj-b", 0x1000).expect("memfd"),
        );
        let table = MemTable::new(&[region(top - 0x1000, 0x1000, 0), region(top, 0x1000, 0)])
            .expect("table");
        let gm = GuestMemory::from_table(&table, vec![OwnedFd::from(a), OwnedFd::from(b)])
            .expect("adjacent regions do not overlap");
        assert_eq!(gm.regions().len(), 2);
    }

    /// GPU-6・REPAIR-4: 境界検査の拒否が観測カウンタに失敗として計上される（増分で照合する）。
    #[test]
    fn gpu6_memory_ops_are_observed() {
        let (_f, r) = basic();
        let m = observe::global();
        let (rd, wr) = (m.snapshot(Op::MemRead), m.snapshot(Op::MemWrite));
        let mut b = [0u8; 1];
        r.read_at(0x1000, &mut b).expect("read");
        r.read_at(0x3000, &mut b).expect_err("oob read");
        r.write_at(0x1000, &[1]).expect("write");
        let (rd2, wr2) = (m.snapshot(Op::MemRead), m.snapshot(Op::MemWrite));
        let oob = TransportErrorCode::OutOfBounds as usize;
        assert!(rd2.ok > rd.ok);
        assert!(rd2.err > rd.err);
        assert!(rd2.by_code[oob] > rd.by_code[oob]);
        assert!(wr2.ok > wr.ok);
    }
}
