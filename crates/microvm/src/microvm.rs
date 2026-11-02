//! ゲストメモリの初期化（mmap backing と KVM への登録。TASK-75.1・MVM-1・MS-7。Linux のみ・unsafe なし）。
//!
//! TASK-75（microVM の起動フロー）の起点。`crate::guest_memory` のアクセス型 [`GuestMemory`] に、実機の backing を
//! 与える。[`GuestRam::new`] が匿名 mmap（私有・ゼロ埋め・`MAP_NORESERVE`・`MADV_DONTFORK`）でゲスト RAM を確保し、
//! [`GuestRam::register`] が `KVM_SET_USER_MEMORY_REGION` で VM の memslot に登録して
//! `GuestMemory<RegisteredGuestRam>` を返す。`unsafe` は `crate::sys` に閉じ、本モジュールは入力の検証・errno の
//! 分類・寿命の管理だけを持つ。所有先の判断は docs/design/microvm-memory-ownership.md。
//!
//! # 呼び出し元の想定
//! 後続の VM 構成体（TASK-75.2・#697）と plugin-microvm（TASK-117）が、非信頼の VM 構成（サイズ・GPA）から呼ぶ。
//! そのため size・GPA は ioctl の前にすべて検証し、slot は `u16` で受ける（KVM は上位 16 bit を address space id に使う）。
//!
//! # 範囲外（REPAIR-3）
//! 複数領域（MMIO hole・4 GiB をまたぐ x86_64 の配置）・`KVM_CAP_NR_MEMSLOTS` による slot 上限の照会・
//! hugepage・`KVM_MEM_READONLY` / `KVM_MEM_LOG_DIRTY_PAGES`・VM 構成体（TASK-75.2）・カーネルのロード（TASK-75.3）は未実装。
//!
//! # 寿命
//! [`RegisteredGuestRam`] は VM fd を dup して持つ（`'vm` の借用を持たないので、VM 構成体が VM fd と一緒に保持できる）。
//! drop では slot を削除してから munmap する。削除に失敗したら mapping を解放せず漏らす（ゲストがまだ書けるメモリを
//! 別の用途に再利用させない fail-closed）。

#![cfg(target_os = "linux")]

use std::os::fd::{AsFd as _, OwnedFd};

use crate::device::VmFd;
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestAddress, GuestMemory, GuestMemoryBacking};
use crate::sys::{self, GuestRamMap, SysError};

/// ゲスト RAM の確保上限（16 GiB。無制限確保による DoS を防ぐ。`MAP_NORESERVE` でも上限で抑える）。
pub const MAX_GUEST_RAM_BYTES: u64 = 1 << 34;

/// ゲスト RAM のサイズ・GPA の整列単位の下限（4 KiB）。実際の単位は `max(これ, ホストのページサイズ)`
/// （KVM の memslot はホストの `PAGE_SIZE` の倍数を要求する。16 / 64 KiB ページの aarch64 Linux 対応）。
pub const GUEST_RAM_ALIGN: u64 = sys::GUEST_PAGE_SIZE as u64;

const EPERM: i32 = 1;
const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENFILE: i32 = 23;
const EMFILE: i32 = 24;
const ENOTTY: i32 = 25;

/// RAM の整列単位 `max(GUEST_RAM_ALIGN, ホストのページサイズ)`。取得失敗は分類して返す。
fn ram_align() -> Result<u64, MicrovmError> {
    let host = sys::host_page_size().map_err(|e| classify_ram_error(RamStage::Mmap, e))?;
    Ok(host.max(GUEST_RAM_ALIGN))
}

fn invalid(message: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, message)
}

fn out_of_range() -> MicrovmError {
    invalid("guest memory access out of range")
}

/// 失敗した段（errno 分類のメッセージ切り替え用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RamStage {
    Mmap,
    DupVmFd,
    Register,
}

fn classify_ram_error(stage: RamStage, e: SysError) -> MicrovmError {
    let name = match stage {
        RamStage::Mmap => "mmap of guest memory",
        RamStage::DupVmFd => "duplicating VM fd",
        RamStage::Register => "KVM_SET_USER_MEMORY_REGION",
    };
    match e {
        SysError::Unsupported => MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        ),
        SysError::Os(n) if n == ENOMEM || n == EMFILE || n == ENFILE => MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            format!("resource exhausted in {name} (os error {n})"),
        ),
        SysError::Os(EEXIST) if stage == RamStage::Register => MicrovmError::new(
            MicrovmErrorCode::AlreadyExists,
            "guest memory slot or address range already registered",
        ),
        SysError::Os(EINVAL) if stage == RamStage::Register => MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "KVM rejected the guest memory region",
        ),
        SysError::Os(ENOTTY) if stage == RamStage::Register => {
            MicrovmError::new(MicrovmErrorCode::FailedPrecondition, "not a KVM VM fd")
        }
        SysError::Os(n) if n == EACCES || n == EPERM => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            format!("permission denied in {name}"),
        ),
        SysError::NullMapping => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("{name} returned a null address"),
        ),
        SysError::Os(n) => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("{name} failed (os error {n})"),
        ),
    }
}

fn read_map(map: &GuestRamMap, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
    let off = usize::try_from(offset).map_err(|_| out_of_range())?;
    map.read_into(off, buf).map_err(|()| out_of_range())
}

fn write_map(map: &mut GuestRamMap, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
    let off = usize::try_from(offset).map_err(|_| out_of_range())?;
    map.write_from(off, data).map_err(|()| out_of_range())
}

/// まだ KVM に登録していない、mmap 済みのゲスト RAM。
///
/// [`GuestMemoryBacking`] を実装するので、登録前のゲストメモリ（カーネル・initrd の書き込み）にも使える。
#[derive(Debug)]
pub struct GuestRam {
    map: GuestRamMap,
}

impl GuestRam {
    /// `size` バイトのゼロ埋めのゲスト RAM を確保する。
    ///
    /// `size` は 0 でなく、`max(4096, ホストのページサイズ)` の倍数で、[`MAX_GUEST_RAM_BYTES`] 以下であること（違反は `InvalidArgument`）。
    pub fn new(size: u64) -> Result<GuestRam, MicrovmError> {
        let align = ram_align()?;
        Self::new_aligned(size, align)
    }

    /// 整列単位 `align`（`max(4096, ホストのページサイズ)`）を指定して確保する（試験で 16 / 64 KiB を再現するため分離）。
    fn new_aligned(size: u64, align: u64) -> Result<GuestRam, MicrovmError> {
        if size == 0 {
            return Err(invalid("guest memory size must not be zero"));
        }
        if !size.is_multiple_of(align) {
            return Err(invalid(
                "guest memory size must be a multiple of the host page size (at least 4096)",
            ));
        }
        if size > MAX_GUEST_RAM_BYTES {
            return Err(invalid("guest memory size too large"));
        }
        let len = usize::try_from(size).map_err(|_| invalid("guest memory size too large"))?;
        let map = GuestRamMap::map(len).map_err(|e| classify_ram_error(RamStage::Mmap, e))?;
        Ok(GuestRam { map })
    }

    /// `vm` の memslot `slot` に、ゲスト物理アドレス `base` から登録する。
    ///
    /// `base` は `max(4096, ホストのページサイズ)` 境界で、`base + size` が桁あふれしないこと。登録に失敗したときは mapping を解放して返す
    /// （未登録なので解放してよい）。範囲が重なる既存の slot があれば `AlreadyExists`。
    pub fn register(
        self,
        vm: &VmFd,
        slot: u16,
        base: GuestAddress,
    ) -> Result<GuestMemory<RegisteredGuestRam>, MicrovmError> {
        if !base.raw().is_multiple_of(ram_align()?) {
            return Err(invalid(
                "guest address must be a multiple of the host page size (at least 4096)",
            ));
        }
        let size = self.map.len() as u64;
        base.checked_add(size)
            .ok_or_else(|| invalid("guest address range overflows"))?;
        let vm_fd = vm.as_fd().try_clone_to_owned().map_err(|e| {
            classify_ram_error(
                RamStage::DupVmFd,
                SysError::Os(e.raw_os_error().unwrap_or(0)),
            )
        })?;
        sys::register_guest_ram(vm_fd.as_fd(), u32::from(slot), base.raw(), &self.map)
            .map_err(|e| classify_ram_error(RamStage::Register, e))?;
        let registered = RegisteredGuestRam {
            vm: vm_fd,
            slot,
            map: Some(self.map),
        };
        GuestMemory::new(base, registered)
    }
}

impl GuestMemoryBacking for GuestRam {
    fn len(&self) -> u64 {
        self.map.len() as u64
    }
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        read_map(&self.map, offset, buf)
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
        write_map(&mut self.map, offset, data)
    }
}

/// KVM の memslot に登録済みのゲスト RAM。
///
/// 登録後はゲスト（vCPU）がいつでも書き換えるため、読み書きは常にコピーで行う。drop で slot を削除してから
/// munmap する（削除に失敗したら mapping を漏らす）。
#[derive(Debug)]
pub struct RegisteredGuestRam {
    vm: OwnedFd,
    slot: u16,
    map: Option<GuestRamMap>,
}

impl GuestMemoryBacking for RegisteredGuestRam {
    fn len(&self) -> u64 {
        self.map.as_ref().map_or(0, |m| m.len() as u64)
    }
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        let map = self.map.as_ref().ok_or_else(out_of_range)?;
        read_map(map, offset, buf)
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
        let map = self.map.as_mut().ok_or_else(out_of_range)?;
        write_map(map, offset, data)
    }
}

impl Drop for RegisteredGuestRam {
    fn drop(&mut self) {
        let removed = sys::unregister_guest_ram(self.vm.as_fd(), u32::from(self.slot)).is_ok();
        if let Some(map) = self.map.take() {
            if removed {
                drop(map);
            } else {
                // 削除に失敗した領域は解放しない（ゲストがまだ書けるメモリを別の用途に再利用させない fail-closed）。
                std::mem::forget(map);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_invalid(r: Result<GuestRam, MicrovmError>, msg: &str) {
        let e = r.unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), msg);
    }

    /// MVM-1・TASK-75.1: 登録前の mmap backing が `GuestMemory` 経由で往復する。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn unregistered_ram_roundtrips_through_guest_memory() {
        let ram = GuestRam::new(8192).unwrap();
        let mut mem = GuestMemory::new(GuestAddress::new(0x10000), ram).unwrap();
        assert_eq!(mem.len(), 8192);
        mem.write_at(GuestAddress::new(0x10FFE), &[0x78, 0x56, 0x34, 0x12])
            .unwrap();
        assert_eq!(
            mem.read_u32_le(GuestAddress::new(0x10FFE)).unwrap(),
            0x1234_5678
        );
        assert_eq!(mem.read_u16_le(GuestAddress::new(0x11000)).unwrap(), 0x1234);
        assert_eq!(mem.read_u32_le(GuestAddress::new(0x10000)).unwrap(), 0);
        assert!(mem.read_u32_le(GuestAddress::new(0x11FFE)).is_err());
    }

    /// MVM-1・TASK-75.1: size の検証は mmap の前に `InvalidArgument` で弾く。
    #[test]
    fn guest_ram_size_is_validated() {
        assert_invalid(GuestRam::new(0), "guest memory size must not be zero");
        assert_invalid(
            GuestRam::new(4097),
            "guest memory size must be a multiple of the host page size (at least 4096)",
        );
        assert_invalid(
            GuestRam::new(MAX_GUEST_RAM_BYTES + 4096),
            "guest memory size too large",
        );
        assert_invalid(
            GuestRam::new(u64::MAX - 4095),
            "guest memory size too large",
        );
        assert_eq!(MAX_GUEST_RAM_BYTES, 17_179_869_184);
    }

    /// MVM-1・TASK-75.1: ホストのページサイズが 4096 を超える場合、4096 だけのサイズは確保前に拒否し、倍数は通す。
    #[test]
    fn guest_ram_size_follows_host_page_size() {
        let msg = "guest memory size must be a multiple of the host page size (at least 4096)";
        assert_invalid(GuestRam::new_aligned(4096, 16384), msg);
        assert_invalid(GuestRam::new_aligned(16384 + 4096, 16384), msg);
        assert_invalid(GuestRam::new_aligned(32768, 65536), msg);
        assert!(GuestRam::new_aligned(16384, 16384).is_ok());
        assert!(GuestRam::new_aligned(65536, 65536).is_ok());
        assert!(GuestRam::new_aligned(4096, 4096).is_ok());
    }

    /// MVM-1・TASK-75.1: ホストのページサイズは 2 の冪で 4096 以上（x86_64 は 4096 の具体値）。
    #[test]
    fn host_page_size_is_sane() {
        let p = sys::host_page_size().unwrap();
        assert!(p.is_power_of_two() && p >= 4096);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(p, 4096);
        assert_eq!(ram_align().unwrap(), p.max(GUEST_RAM_ALIGN));
    }

    /// MVM-1・TASK-75.1: errno の分類の具体値。
    #[test]
    fn errno_classification_table() {
        let c = |s, e| classify_ram_error(s, e).code();
        assert_eq!(
            c(RamStage::Mmap, SysError::Unsupported),
            MicrovmErrorCode::Unimplemented
        );
        assert_eq!(
            c(RamStage::Mmap, SysError::Os(ENOMEM)),
            MicrovmErrorCode::ResourceExhausted
        );
        assert_eq!(
            c(RamStage::Register, SysError::Os(EEXIST)),
            MicrovmErrorCode::AlreadyExists
        );
        assert_eq!(
            c(RamStage::Register, SysError::Os(EINVAL)),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            c(RamStage::Register, SysError::Os(ENOTTY)),
            MicrovmErrorCode::FailedPrecondition
        );
        assert_eq!(
            c(RamStage::Register, SysError::Os(EACCES)),
            MicrovmErrorCode::PermissionDenied
        );
        assert_eq!(
            c(RamStage::Mmap, SysError::NullMapping),
            MicrovmErrorCode::Internal
        );
        let e = classify_ram_error(RamStage::Mmap, SysError::Os(99));
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        assert_eq!(e.message(), "mmap of guest memory failed (os error 99)");
    }
}
