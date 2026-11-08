//! memslot のフラグ（`KVM_SET_USER_MEMORY_REGION` の `flags`）を型で表し、`KVM_CHECK_EXTENSION` で対応を判定する（#4157・MVM-1・#4105）。
//!
//! 役割: 未知のビットを持つ値を作れない [`MemslotFlags`] と、カーネルの対応を照会する継ぎ目
//! `MemslotCapabilityQuery`、その判定の純関数 `check_memslot_flags_supported` を提供する。
//! 呼び出し文脈: [`crate::device::VmFd::check_memslot_flags`] が VM fd を継ぎ目として渡す。
//! 未実装（REPAIR-3）: 登録 API（`set_user_memory_region` は `flags: 0` 固定のまま）への結線は #4158、hugepage は #4159。
//!
//! 一次情報（Linux v6.12）: `KVM_MEM_READONLY` は `Documentation/virt/kvm/api.rst` のとおり `KVM_CAP_READONLY_MEM` が許すときだけ
//! 設定できる。`KVM_MEM_LOG_DIRTY_PAGES` は cap の照会を要さない（`check_memory_region_flags` の既定の有効フラグ）。
//! `KVM_MEM_GUEST_MEMFD`（bit 2）は `KVM_SET_USER_MEMORY_REGION2` 専用で本 crate は扱わず、[`MemslotFlags::try_from_raw`] が拒否する。
//! 照会先を VM fd にするのは、`KVM_CHECK_EXTENSION` が VM ごとに答えを変えうる（x86）ため（アーキ別の返し方の個別確認は未実施）。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::sys::{self, KvmCap};

/// memslot のフラグ。フィールドは非公開で、既知のビット（`LOG_DIRTY_PAGES`・`READONLY`）だけを持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemslotFlags(u32);

impl MemslotFlags {
    /// フラグなし（既存の登録の `flags = 0` と一致）。
    pub const NONE: Self = Self(0);
    /// dirty page の追跡（`KVM_MEM_LOG_DIRTY_PAGES`）。
    pub const LOG_DIRTY_PAGES: Self = Self(sys::consts::KVM_MEM_LOG_DIRTY_PAGES);
    /// 読み取り専用（`KVM_MEM_READONLY`。`KVM_CAP_READONLY_MEM` が要る）。
    pub const READONLY: Self = Self(sys::consts::KVM_MEM_READONLY);

    const VALID_MASK: u32 = sys::consts::KVM_MEM_LOG_DIRTY_PAGES | sys::consts::KVM_MEM_READONLY;

    /// 2 つのフラグの和。
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `other` の全ビットを含むか。
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// カーネルへ渡す生値（`KvmUserspaceMemoryRegion.flags` の型）。
    #[must_use]
    pub const fn to_raw(self) -> u32 {
        self.0
    }

    /// 外部由来の生値から作る。未知のビットを含めば `InvalidArgument`（fail-closed）。
    pub fn try_from_raw(raw: u32) -> Result<Self, MicrovmError> {
        if raw & !Self::VALID_MASK != 0 {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "memslot flags contain unsupported bits",
            ));
        }
        Ok(Self(raw))
    }
}

/// `KVM_CHECK_EXTENSION` の継ぎ目。本番は VM fd（[`crate::device::VmFd`]）、単体試験は偽実装。
pub(crate) trait MemslotCapabilityQuery {
    /// `cap` を照会し、カーネルの戻り値（0 は非対応）を返す。
    fn check_extension(&self, cap: KvmCap) -> Result<i32, MicrovmError>;
}

/// `flags` がカーネルで使えるかを確かめる。`READONLY` を含むときだけ `KVM_CAP_READONLY_MEM` を照会し、
/// 0 以下は `FailedPrecondition`。照会の失敗はそのまま返す。
pub(crate) fn check_memslot_flags_supported(
    flags: MemslotFlags,
    q: &impl MemslotCapabilityQuery,
) -> Result<(), MicrovmError> {
    if flags.contains(MemslotFlags::READONLY)
        && q.check_extension(sys::consts::KVM_CAP_READONLY_MEM)? <= 0
    {
        return Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "KVM_CAP_READONLY_MEM is not supported by this kernel",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fake {
        answer: Result<i32, MicrovmErrorCode>,
        calls: RefCell<Vec<KvmCap>>,
    }

    impl Fake {
        fn new(answer: Result<i32, MicrovmErrorCode>) -> Self {
            Self {
                answer,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl MemslotCapabilityQuery for Fake {
        fn check_extension(&self, cap: KvmCap) -> Result<i32, MicrovmError> {
            self.calls.borrow_mut().push(cap);
            self.answer
                .map_err(|c| MicrovmError::new(c, "fake query failure"))
        }
    }

    #[test]
    fn mvm1_4157_flags_to_raw() {
        assert_eq!(MemslotFlags::NONE.to_raw(), 0);
        assert_eq!(MemslotFlags::LOG_DIRTY_PAGES.to_raw(), 1);
        assert_eq!(MemslotFlags::READONLY.to_raw(), 2);
        let both = MemslotFlags::LOG_DIRTY_PAGES.union(MemslotFlags::READONLY);
        assert_eq!(both.to_raw(), 3);
        assert!(both.contains(MemslotFlags::READONLY));
        assert!(!MemslotFlags::LOG_DIRTY_PAGES.contains(MemslotFlags::READONLY));
        assert_eq!(MemslotFlags::default(), MemslotFlags::NONE);
    }

    #[test]
    fn mvm1_4157_try_from_raw_accepts_known() {
        for raw in 0..=3u32 {
            let f = MemslotFlags::try_from_raw(raw).expect("known bits");
            assert_eq!(f.to_raw(), raw);
        }
    }

    #[test]
    fn mvm1_4157_try_from_raw_rejects_unknown() {
        for raw in [1u32 << 2, 3 | 4, 0x8000_0000, 0xFFFF_FFFF] {
            let e = MemslotFlags::try_from_raw(raw).expect_err("unknown bits");
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "memslot flags contain unsupported bits");
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4157_readonly_supported_ok() {
        let q = Fake::new(Ok(1));
        assert!(check_memslot_flags_supported(MemslotFlags::READONLY, &q).is_ok());
        assert_eq!(*q.calls.borrow(), vec![sys::consts::KVM_CAP_READONLY_MEM]);
    }

    #[test]
    fn mvm1_4157_readonly_unsupported_failed_precondition() {
        for n in [0, -1] {
            let q = Fake::new(Ok(n));
            let e =
                check_memslot_flags_supported(MemslotFlags::READONLY, &q).expect_err("unsupported");
            assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
            assert_eq!(
                e.message(),
                "KVM_CAP_READONLY_MEM is not supported by this kernel"
            );
        }
        let q = Fake::new(Ok(0));
        let both = MemslotFlags::LOG_DIRTY_PAGES.union(MemslotFlags::READONLY);
        let e = check_memslot_flags_supported(both, &q).expect_err("unsupported");
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
    }

    #[test]
    fn mvm1_4157_none_and_log_dirty_do_not_query() {
        let q = Fake::new(Ok(0));
        assert!(check_memslot_flags_supported(MemslotFlags::NONE, &q).is_ok());
        assert!(check_memslot_flags_supported(MemslotFlags::LOG_DIRTY_PAGES, &q).is_ok());
        assert!(q.calls.borrow().is_empty());
    }

    #[test]
    fn mvm1_4157_query_failure_propagates() {
        let q = Fake::new(Err(MicrovmErrorCode::Internal));
        let e =
            check_memslot_flags_supported(MemslotFlags::READONLY, &q).expect_err("query failed");
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
    }
}
