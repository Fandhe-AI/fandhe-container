//! `LOG_DIRTY_PAGES` つき memslot の dirty bitmap の取得（`KVM_GET_DIRTY_LOG`。#4225・MVM-1。Linux 限定・`unsafe` なし）。
//!
//! 役割: bitmap の長さの決定・上限の検証・ビットの解釈（[`DirtyBitmap`]）と、ioctl の継ぎ目 `DirtyLogFetcher` を持つ。
//! 呼び出し文脈: [`crate::microvm::RegisteredGuestRam::dirty_log`]（`GuestMemory<RegisteredGuestRam>::dirty_log` 経由）が
//! VM fd の借用を継ぎ目として渡し、`fetch_dirty_log_checked` が「フラグ・サイズの検査 → 確保 → ioctl 1 回」を行う。
//! ioctl 本体と `unsafe` は `crate::sys::kvm_get_dirty_log` に閉じる（sys 側でもバッファ長を再検査する）。
//!
//! 契約:
//! - 読み取りと同時にカーネル側の dirty 状態はクリアされる（`KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2` は有効にしない）。
//! - 追跡されるのはゲストの書き込みだけで、ホストからの mapping への書き込みは立たない。
//! - ビット順はページ `i` がバイト `i / 8` の bit `i % 8`（`set_bit_le`）。ページはホストの `PAGE_SIZE` 単位。
//!
//! 未実装（REPAIR-3）: `KVM_CLEAR_DIRTY_LOG`・manual protect・dirty ring・稼働中 VM（`MicroVm`）や plugin-microvm への結線は範囲外。

use std::os::fd::BorrowedFd;

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::memslot_flags::MemslotFlags;
use crate::microvm::{GUEST_RAM_ALIGN, MAX_GUEST_RAM_BYTES};
use crate::sys::{self, SysError};

/// 取得する bitmap の上限バイト数（[`MAX_GUEST_RAM_BYTES`] を最小ページ [`GUEST_RAM_ALIGN`] で数えたページ数を
/// 64 ページ単位に切り上げ、8 バイトにしたもの。16 GiB / 4 KiB なら 524288）。
pub const MAX_DIRTY_BITMAP_BYTES: usize =
    ((MAX_GUEST_RAM_BYTES / GUEST_RAM_ALIGN).div_ceil(64) * 8) as usize;
const _: () = assert!(MAX_DIRTY_BITMAP_BYTES == 524_288);

/// 1 回の取得で得た dirty bitmap。フィールドは非公開で、ビットは [`DirtyBitmap::is_dirty`] 等で読む。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirtyBitmap {
    bytes: Vec<u8>,
    pages: u64,
    page_size: u64,
}

impl DirtyBitmap {
    /// 1 ページのバイト数（ホストのページサイズ）。
    #[must_use]
    pub fn page_size(&self) -> u64 {
        self.page_size
    }

    /// memslot のページ数。
    #[must_use]
    pub fn page_count(&self) -> u64 {
        self.pages
    }

    /// ページ `page` が dirty か。範囲外は `None`。
    #[must_use]
    pub fn is_dirty(&self, page: u64) -> Option<bool> {
        if page >= self.pages {
            return None;
        }
        let byte = self.bytes.get(usize::try_from(page / 8).ok()?)?;
        Some((byte >> (page % 8)) & 1 == 1)
    }

    /// dirty なページ番号（昇順）。
    pub fn dirty_pages(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.pages).filter(|p| self.is_dirty(*p) == Some(true))
    }

    /// カーネルが返した生の bitmap（ビット順は LE。長さは 64 ページ単位に切り上げた 8 の倍数）。
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// `KVM_GET_DIRTY_LOG` の継ぎ目。本番は VM fd の借用（[`VmFdDirtyLog`]）、単体試験は ioctl を呼ばず記録する偽実装。
pub(crate) trait DirtyLogFetcher {
    /// `slot`（登録時のサイズ `memory_size`）の bitmap を `bitmap` へ読む。
    fn get_dirty_log(&self, slot: u32, memory_size: u64, bitmap: &mut [u8])
    -> Result<(), SysError>;
}

/// VM fd の借用で [`DirtyLogFetcher`] を満たす本番の実装。
pub(crate) struct VmFdDirtyLog<'a>(pub(crate) BorrowedFd<'a>);

impl DirtyLogFetcher for VmFdDirtyLog<'_> {
    fn get_dirty_log(
        &self,
        slot: u32,
        memory_size: u64,
        bitmap: &mut [u8],
    ) -> Result<(), SysError> {
        sys::kvm_get_dirty_log(self.0, slot, memory_size, bitmap)
    }
}

/// [`fetch_dirty_log_checked`] の失敗。事前検査の拒否と ioctl の失敗で errno の分類が異なるため分ける。
#[derive(Debug)]
pub(crate) enum FetchDirtyLogError {
    /// 事前検査で拒否した（ioctl は呼ばれていない）。
    Precheck(MicrovmError),
    /// ioctl が失敗した。
    Ioctl(SysError),
}

/// フラグとサイズを検査してから bitmap を取得する。`LOG_DIRTY_PAGES` なし・不正なサイズ・上限超過は ioctl を呼ばず拒否する（fail-closed）。
pub(crate) fn fetch_dirty_log_checked(
    f: &impl DirtyLogFetcher,
    slot: u32,
    flags: MemslotFlags,
    memory_size: u64,
    page_size: u64,
) -> Result<DirtyBitmap, FetchDirtyLogError> {
    let pre = |code, msg: &'static str| FetchDirtyLogError::Precheck(MicrovmError::new(code, msg));
    if !flags.contains(MemslotFlags::LOG_DIRTY_PAGES) {
        return Err(pre(
            MicrovmErrorCode::FailedPrecondition,
            "memslot was not registered with LOG_DIRTY_PAGES",
        ));
    }
    let bytes = sys::dirty_bitmap_bytes(memory_size, page_size).ok_or_else(|| {
        pre(
            MicrovmErrorCode::InvalidArgument,
            "invalid memslot size for dirty log",
        )
    })?;
    let len = usize::try_from(bytes)
        .ok()
        .filter(|n| *n <= MAX_DIRTY_BITMAP_BYTES)
        .ok_or_else(|| pre(MicrovmErrorCode::InvalidArgument, "dirty bitmap too large"))?;
    let mut buf = vec![0u8; len];
    f.get_dirty_log(slot, memory_size, &mut buf)
        .map_err(FetchDirtyLogError::Ioctl)?;
    Ok(DirtyBitmap {
        bytes: buf,
        pages: memory_size / page_size,
        page_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<(u32, u64, usize)>>,
        fill: Vec<u8>,
        result: Option<SysError>,
    }

    impl DirtyLogFetcher for Fake {
        fn get_dirty_log(
            &self,
            slot: u32,
            memory_size: u64,
            bitmap: &mut [u8],
        ) -> Result<(), SysError> {
            self.calls
                .borrow_mut()
                .push((slot, memory_size, bitmap.len()));
            for (d, s) in bitmap.iter_mut().zip(self.fill.iter()) {
                *d = *s;
            }
            self.result.map_or(Ok(()), Err)
        }
    }

    const LOG: MemslotFlags = MemslotFlags::LOG_DIRTY_PAGES;

    fn precheck(e: FetchDirtyLogError) -> MicrovmError {
        match e {
            FetchDirtyLogError::Precheck(e) => e,
            FetchDirtyLogError::Ioctl(e) => panic!("unexpected ioctl error {e:?}"),
        }
    }

    /// MVM-1・#4225: ioctl へ渡る slot・サイズ・bitmap の長さ。
    #[test]
    fn mvm1_4225_fetch_passes_slot_and_length() {
        let cases: [(u32, u64, u64, usize); 4] = [
            (3, 0x10_0000, 4096, 32),
            (0, 0x1_0000, 4096, 8),
            (5, 260 * 1024, 4096, 16),
            (1, 0x10_0000, 65536, 8),
        ];
        for (slot, size, page, len) in cases {
            let f = Fake::default();
            let b = fetch_dirty_log_checked(&f, slot, LOG, size, page)
                .ok()
                .unwrap();
            assert_eq!(*f.calls.borrow(), vec![(slot, size, len)]);
            assert_eq!(b.as_bytes().len(), len);
            assert_eq!(b.page_count(), size / page);
        }
    }

    /// MVM-1・#4225: ビットの解釈（LE）。
    #[test]
    fn mvm1_4225_fetch_decodes_bits() {
        let f = Fake {
            fill: vec![0b0000_0101, 0x80],
            ..Fake::default()
        };
        let b = fetch_dirty_log_checked(&f, 0, LOG, 16 * 4096, 4096)
            .ok()
            .unwrap();
        assert_eq!(b.dirty_pages().collect::<Vec<_>>(), vec![0, 2, 15]);
        assert_eq!(b.is_dirty(1), Some(false));
        assert_eq!(b.is_dirty(16), None);
        assert_eq!(b.page_size(), 4096);
    }

    /// MVM-1・#4225: `LOG_DIRTY_PAGES` なしは ioctl を呼ばない。
    #[test]
    fn mvm1_4225_without_log_dirty_does_not_call_ioctl() {
        for flags in [MemslotFlags::NONE, MemslotFlags::READONLY] {
            let f = Fake::default();
            let e = precheck(
                fetch_dirty_log_checked(&f, 0, flags, 4096, 4096)
                    .err()
                    .unwrap(),
            );
            assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
            assert_eq!(
                e.message(),
                "memslot was not registered with LOG_DIRTY_PAGES"
            );
            assert!(f.calls.borrow().is_empty());
        }
    }

    /// MVM-1・#4225: 上限超過は確保も ioctl もしない。ちょうど上限は通る。
    #[test]
    fn mvm1_4225_oversized_does_not_call_ioctl() {
        let f = Fake::default();
        let e = precheck(
            fetch_dirty_log_checked(&f, 0, LOG, MAX_GUEST_RAM_BYTES + 64 * 4096, 4096)
                .err()
                .unwrap(),
        );
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "dirty bitmap too large");
        assert!(f.calls.borrow().is_empty());
        let b = fetch_dirty_log_checked(&f, 0, LOG, MAX_GUEST_RAM_BYTES, 4096)
            .ok()
            .unwrap();
        assert_eq!(b.as_bytes().len(), 524_288);
        assert_eq!(f.calls.borrow().len(), 1);
    }

    /// MVM-1・#4225: 不正なページサイズ・非倍数のサイズは ioctl を呼ばない。
    #[test]
    fn mvm1_4225_invalid_size_does_not_call_ioctl() {
        for (size, page) in [(4096u64, 0u64), (4097, 4096), (4096, 3)] {
            let f = Fake::default();
            let e = precheck(
                fetch_dirty_log_checked(&f, 0, LOG, size, page)
                    .err()
                    .unwrap(),
            );
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "invalid memslot size for dirty log");
            assert!(f.calls.borrow().is_empty());
        }
    }

    /// MVM-1・#4225: ioctl の失敗はそのまま返る。
    #[test]
    fn mvm1_4225_ioctl_error_propagates() {
        let f = Fake {
            result: Some(SysError::Os(2)),
            ..Fake::default()
        };
        match fetch_dirty_log_checked(&f, 0, LOG, 4096, 4096) {
            Err(FetchDirtyLogError::Ioctl(SysError::Os(2))) => {}
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(f.calls.borrow().len(), 1);
    }
}
