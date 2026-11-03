//! Hypervisor.framework（macOS・Apple Silicon）の ABI 値と純粋な検査（TASK-192.1・#3783・MVM-5・MVM-4）。
//!
//! 呼び出し文脈: macOS バックエンドの `sys`（`src/sys/hvf.rs`）の安全なラッパーが、`hv_*` を呼ぶ前の
//! 引数検査（[`check_map_range`]）と、呼んだ後の戻り値の写像（[`classify_hv_return`]）にここを使う。
//! `hv_*` を呼ばず `unsafe` も持たないため OS 非依存で、Linux の PR CI の単体テストでも走る。
//!
//! # `hv_return_t` の写像（`message` には数値を載せない。ERR-1）
//! | 値 | `MicrovmErrorCode` |
//! | --- | --- |
//! | `HV_SUCCESS` | `Ok(())` |
//! | `HV_ERROR` | `Internal` |
//! | `HV_BUSY` | `FailedPrecondition` |
//! | `HV_BAD_ARGUMENT` | `InvalidArgument` |
//! | `HV_ILLEGAL_GUEST_STATE` | `FailedPrecondition` |
//! | `HV_NO_RESOURCES` | `ResourceExhausted` |
//! | `HV_NO_DEVICE` | `Unimplemented`（hypervisor を使えない環境） |
//! | `HV_DENIED` | `PermissionDenied` |
//! | `HV_FAULT` | `Internal` |
//! | `HV_UNSUPPORTED` | `Unimplemented` |
//! | 未知の値 | `Internal`（fail-closed） |
//!
//! # 出典
//! 数値の一部と 3 つの名前は第三者バインディング由来で、SDK ヘッダ（`Hypervisor/hv_error.h`）との
//! 最終照合は人間担当の #3803 で行う。それまでは暫定値として扱う。

use crate::error::{MicrovmError, MicrovmErrorCode};
use std::ops::BitOr;

/// ゲスト RAM のマップ確保上限（16 GiB）。Linux 側の `MAX_GUEST_RAM_BYTES` と同値で、
/// mmap の前に超過を拒否して無制限確保を防ぐ（リソース上限・MVM-5・MVM-4）。
pub const MAX_MAP_BYTES: u64 = 1 << 34;

/// `HV_SUCCESS`。
pub const HV_SUCCESS: i32 = 0;
/// `HV_ERROR`（0xfae94001）。
pub const HV_ERROR: i32 = 0xfae9_4001_u32 as i32;
/// `HV_BUSY`（0xfae94002）。
pub const HV_BUSY: i32 = 0xfae9_4002_u32 as i32;
/// `HV_BAD_ARGUMENT`（0xfae94003）。
pub const HV_BAD_ARGUMENT: i32 = 0xfae9_4003_u32 as i32;
/// `HV_ILLEGAL_GUEST_STATE`（0xfae94004）。
pub const HV_ILLEGAL_GUEST_STATE: i32 = 0xfae9_4004_u32 as i32;
/// `HV_NO_RESOURCES`（0xfae94005）。
pub const HV_NO_RESOURCES: i32 = 0xfae9_4005_u32 as i32;
/// `HV_NO_DEVICE`（0xfae94006）。
pub const HV_NO_DEVICE: i32 = 0xfae9_4006_u32 as i32;
/// `HV_DENIED`（0xfae94007）。
pub const HV_DENIED: i32 = 0xfae9_4007_u32 as i32;
/// `HV_FAULT`（0xfae94008）。
pub const HV_FAULT: i32 = 0xfae9_4008_u32 as i32;
/// `HV_UNSUPPORTED`（0xfae9400f）。
pub const HV_UNSUPPORTED: i32 = 0xfae9_400f_u32 as i32;

/// どの `hv_*` 呼び出しの結果かを示す（`message` の操作名になる）。後続の子 issue が variant を足す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HvOp {
    /// `hv_vm_create`。
    VmCreate,
    /// `hv_vm_destroy`。
    VmDestroy,
    /// `hv_vm_map`。
    VmMap,
    /// `hv_vm_unmap`。
    VmUnmap,
    /// `hv_vm_protect`。
    VmProtect,
}

impl HvOp {
    const fn name(self) -> &'static str {
        match self {
            HvOp::VmCreate => "hv_vm_create",
            HvOp::VmDestroy => "hv_vm_destroy",
            HvOp::VmMap => "hv_vm_map",
            HvOp::VmUnmap => "hv_vm_unmap",
            HvOp::VmProtect => "hv_vm_protect",
        }
    }
}

/// `hv_return_t` を `Result` に写す（モジュール doc の表。`hv_*` は呼ばない純関数）。
///
/// `message` は英語の固定文で、操作名と既知の値のシンボル名だけを載せる。
pub fn classify_hv_return(op: HvOp, code: i32) -> Result<(), MicrovmError> {
    let (class, sym) = match code {
        HV_SUCCESS => return Ok(()),
        HV_ERROR => (MicrovmErrorCode::Internal, "HV_ERROR"),
        HV_BUSY => (MicrovmErrorCode::FailedPrecondition, "HV_BUSY"),
        HV_BAD_ARGUMENT => (MicrovmErrorCode::InvalidArgument, "HV_BAD_ARGUMENT"),
        HV_ILLEGAL_GUEST_STATE => (
            MicrovmErrorCode::FailedPrecondition,
            "HV_ILLEGAL_GUEST_STATE",
        ),
        HV_NO_RESOURCES => (MicrovmErrorCode::ResourceExhausted, "HV_NO_RESOURCES"),
        HV_NO_DEVICE => (MicrovmErrorCode::Unimplemented, "HV_NO_DEVICE"),
        HV_DENIED => (MicrovmErrorCode::PermissionDenied, "HV_DENIED"),
        HV_FAULT => (MicrovmErrorCode::Internal, "HV_FAULT"),
        HV_UNSUPPORTED => (MicrovmErrorCode::Unimplemented, "HV_UNSUPPORTED"),
        _ => {
            return Err(MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{} returned an unknown hv_return_t", op.name()),
            ));
        }
    };
    Err(MicrovmError::new(
        class,
        format!("{} returned {}", op.name(), sym),
    ))
}

/// `hv_memory_flags_t`（u64）の newtype。生の数値を渡し回さない（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFlags(u64);

impl MemoryFlags {
    /// `HV_MEMORY_READ`。
    pub const READ: MemoryFlags = MemoryFlags(1);
    /// `HV_MEMORY_WRITE`。
    pub const WRITE: MemoryFlags = MemoryFlags(2);
    /// `HV_MEMORY_EXEC`。
    pub const EXEC: MemoryFlags = MemoryFlags(4);
    /// READ | WRITE | EXEC。
    pub const RWX: MemoryFlags = MemoryFlags(7);

    /// FFI に渡す生のビット値。
    pub const fn bits(self) -> u64 {
        self.0
    }
}

impl BitOr for MemoryFlags {
    type Output = MemoryFlags;
    fn bitor(self, rhs: MemoryFlags) -> MemoryFlags {
        MemoryFlags(self.0 | rhs.0)
    }
}

fn invalid(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, msg)
}

/// `hv_vm_map` / `hv_vm_protect` に渡す範囲の検査（FFI の前に必ず通す）。
///
/// `page_size` が 0 か 2 の冪でない、`size` が 0 か [`MAX_MAP_BYTES`] 超かページ倍数でない、`addr`・`ipa` がページ境界でない、
/// `addr + size`・`ipa + size` が桁あふれする、のいずれかを `InvalidArgument` にする。
pub fn check_map_range(addr: u64, ipa: u64, size: u64, page_size: u64) -> Result<(), MicrovmError> {
    if !page_size.is_power_of_two() {
        return Err(invalid("page size is not a power of two"));
    }
    if size == 0 {
        return Err(invalid("size is zero"));
    }
    if size > MAX_MAP_BYTES {
        return Err(invalid("size exceeds the maximum mapping size"));
    }
    if !size.is_multiple_of(page_size) {
        return Err(invalid("size is not a multiple of the page size"));
    }
    if !addr.is_multiple_of(page_size) {
        return Err(invalid("host address is not page aligned"));
    }
    if !ipa.is_multiple_of(page_size) {
        return Err(invalid("guest address is not page aligned"));
    }
    if addr.checked_add(size).is_none() || ipa.checked_add(size).is_none() {
        return Err(invalid("range overflows the address space"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mvm5_3783_constants_have_expected_values() {
        assert_eq!(HV_SUCCESS, 0);
        assert_eq!(HV_ERROR as u32, 0xfae9_4001);
        assert_eq!(HV_BUSY as u32, 0xfae9_4002);
        assert_eq!(HV_BAD_ARGUMENT as u32, 0xfae9_4003);
        assert_eq!(HV_ILLEGAL_GUEST_STATE as u32, 0xfae9_4004);
        assert_eq!(HV_NO_RESOURCES as u32, 0xfae9_4005);
        assert_eq!(HV_NO_DEVICE as u32, 0xfae9_4006);
        assert_eq!(HV_DENIED as u32, 0xfae9_4007);
        assert_eq!(HV_FAULT as u32, 0xfae9_4008);
        assert_eq!(HV_UNSUPPORTED as u32, 0xfae9_400f);
    }

    #[test]
    fn mvm5_3783_classify_maps_every_known_value() {
        assert!(classify_hv_return(HvOp::VmCreate, HV_SUCCESS).is_ok());
        let cases = [
            (HV_ERROR, MicrovmErrorCode::Internal, "HV_ERROR"),
            (HV_BUSY, MicrovmErrorCode::FailedPrecondition, "HV_BUSY"),
            (
                HV_BAD_ARGUMENT,
                MicrovmErrorCode::InvalidArgument,
                "HV_BAD_ARGUMENT",
            ),
            (
                HV_ILLEGAL_GUEST_STATE,
                MicrovmErrorCode::FailedPrecondition,
                "HV_ILLEGAL_GUEST_STATE",
            ),
            (
                HV_NO_RESOURCES,
                MicrovmErrorCode::ResourceExhausted,
                "HV_NO_RESOURCES",
            ),
            (
                HV_NO_DEVICE,
                MicrovmErrorCode::Unimplemented,
                "HV_NO_DEVICE",
            ),
            (HV_DENIED, MicrovmErrorCode::PermissionDenied, "HV_DENIED"),
            (HV_FAULT, MicrovmErrorCode::Internal, "HV_FAULT"),
            (
                HV_UNSUPPORTED,
                MicrovmErrorCode::Unimplemented,
                "HV_UNSUPPORTED",
            ),
        ];
        for (code, class, sym) in cases {
            let e = classify_hv_return(HvOp::VmMap, code).unwrap_err();
            assert_eq!(e.code(), class, "{sym}");
            assert_eq!(e.message(), format!("hv_vm_map returned {sym}"));
        }
    }

    #[test]
    fn mvm5_3783_classify_unknown_is_internal_without_number() {
        let e = classify_hv_return(HvOp::VmCreate, 0xfae9_4099_u32 as i32).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        assert_eq!(e.message(), "hv_vm_create returned an unknown hv_return_t");
        let e = classify_hv_return(HvOp::VmDestroy, 1).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
    }

    #[test]
    fn mvm5_3783_memory_flags_bits() {
        assert_eq!(MemoryFlags::READ.bits(), 1);
        assert_eq!(MemoryFlags::WRITE.bits(), 2);
        assert_eq!(MemoryFlags::EXEC.bits(), 4);
        assert_eq!(MemoryFlags::RWX.bits(), 7);
        assert_eq!(
            MemoryFlags::READ | MemoryFlags::WRITE | MemoryFlags::EXEC,
            MemoryFlags::RWX
        );
    }

    #[test]
    fn mvm5_3783_check_map_range_rejects_violations_for_both_page_sizes() {
        for page in [4096_u64, 16384] {
            let base = page * 8;
            assert!(check_map_range(base, 0x4000_0000, page, page).is_ok());
            let bad = [
                check_map_range(base + 0x800, 0x4000_0000, page, page),
                check_map_range(base, 0x4000_0000 + 0x800, page, page),
                check_map_range(base, 0x4000_0000, 0, page),
                check_map_range(base, 0x4000_0000, page / 2, page),
                check_map_range(base, 0x4000_0000, page + 0x800, page),
                check_map_range(u64::MAX - page + 1, 0x4000_0000, page * 2, page),
                check_map_range(base, u64::MAX - page + 1, page * 2, page),
            ];
            for r in bad {
                assert_eq!(r.unwrap_err().code(), MicrovmErrorCode::InvalidArgument);
            }
        }
    }

    #[test]
    fn mvm5_3783_check_map_range_0x1000_offset_on_16k_pages() {
        // 16 KiB ページでは 0x1000 のずれがページ境界違反になる。
        let e = check_map_range(0x1000, 0x4000_0000, 16384, 16384).unwrap_err();
        assert_eq!(e.message(), "host address is not page aligned");
        let e = check_map_range(0x4000, 0x4000_1000, 16384, 16384).unwrap_err();
        assert_eq!(e.message(), "guest address is not page aligned");
        // 4 KiB ページではページ未満の size を拒否する。
        let e = check_map_range(0x1000, 0x4000_0000, 0x800, 4096).unwrap_err();
        assert_eq!(e.message(), "size is not a multiple of the page size");
    }

    #[test]
    fn mvm5_3783_check_map_range_rejects_bad_page_size() {
        for page in [0_u64, 3] {
            let e = check_map_range(0, 0, 4096, page).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "page size is not a power of two");
        }
    }

    #[test]
    fn mvm5_3783_check_map_range_rejects_size_over_limit() {
        for page in [4096_u64, 16384] {
            assert_eq!(MAX_MAP_BYTES, 17_179_869_184);
            assert!(check_map_range(0, 0, MAX_MAP_BYTES, page).is_ok());
            let e = check_map_range(0, 0, MAX_MAP_BYTES + page, page).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "size exceeds the maximum mapping size");
        }
    }
}
