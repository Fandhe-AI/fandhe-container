//! memslot のフラグ（`KVM_SET_USER_MEMORY_REGION` の `flags`）を型で表し、`KVM_CHECK_EXTENSION` で対応を判定する（#4157・MVM-1・#4105）。
//!
//! 役割: 未知のビットを持つ値を作れない [`MemslotFlags`] と、カーネルの対応を照会する継ぎ目
//! `MemslotCapabilityQuery`、その判定の純関数 `check_memslot_flags_supported` を提供する。
//! 呼び出し文脈: [`crate::device::VmFd::check_memslot_flags`] が VM fd を継ぎ目として渡す。
//! 結線（#4158）: `register_memslot_checked` が「対応の照会 → 登録 ioctl」を行い、`GuestRam::register_with_flags`（Linux）が呼ぶ。
//! 未実装（REPAIR-3）: dirty log の取得（`KVM_GET_DIRTY_LOG`）は範囲外。hugepage は採らない判断を記録済み（#4159。docs/design/microvm-memory-ownership.md）。
//!
//! 一次情報（Linux v6.12）: `KVM_MEM_READONLY` は `Documentation/virt/kvm/api.rst` のとおり `KVM_CAP_READONLY_MEM` が許すときだけ
//! 設定できる。`KVM_MEM_LOG_DIRTY_PAGES` は cap の照会を要さない（`check_memory_region_flags` の既定の有効フラグ）。
//! `KVM_MEM_GUEST_MEMFD`（bit 2）は `KVM_SET_USER_MEMORY_REGION2` 専用で本 crate は扱わず、[`MemslotFlags::try_from_raw`] が拒否する。
//! `KVM_CAP_READONLY_MEM` の返し方（v6.12 の原文で確認済み。#4226）: system fd は x86・arm64 とも常に 1。VM fd は
//! x86 が `!kvm->arch.has_protected_state`（SEV-ES・SNP の VM でだけ 0）、arm64 が pKVM の保護 VM でだけ 0（`arm.c` の
//! `kvm_vm_is_protected` と `pkvm_ext_allowed`）で、それ以外は 1。本 crate の VM（machine type 0）はどちらも 1 になる。
//! 照会先を VM fd にするのは、将来ほかの VM type を作ったときにも正しく判定するため。
//! `READONLY | LOG_DIRTY_PAGES` の同時指定は、`check_memory_region_flags`（`virt/kvm/kvm_main.c`）が cap と同じ述語
//! `kvm_arch_has_readonly_mem` で `READONLY` を有効フラグに足すだけで組み合わせを禁じないため、cap が 1 なら受理される。
//! 出典の行範囲・確認していない範囲は docs/design/microvm-memory-ownership.md の #4226 の節を参照。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::sys::{self, KvmCap, SysError};

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

/// memslot の登録 ioctl の継ぎ目（#4158）。本番は VM fd（[`crate::device::VmFd`]）、単体試験は ioctl を呼ばず記録する偽実装。
pub(crate) trait MemslotRegistrar: MemslotCapabilityQuery {
    /// `KVM_SET_USER_MEMORY_REGION` を 1 回呼ぶ。
    fn set_user_memory_region(
        &self,
        slot: u32,
        flags: u32,
        gpa: u64,
        size: u64,
        userspace_addr: u64,
    ) -> Result<(), SysError>;
}

/// [`register_memslot_checked`] の失敗。照会側と ioctl 側で errno の分類が異なるため呼び出し側が区別できるようにする。
#[derive(Debug)]
pub(crate) enum RegisterMemslotError {
    /// 対応の確認で拒否・失敗した（登録 ioctl は呼ばれていない）。
    Capability(MicrovmError),
    /// 登録 ioctl が失敗した。
    Ioctl(SysError),
}

/// `flags` の対応を確かめてから memslot を登録する。非対応・照会失敗なら ioctl を呼ばない（fail-closed）。
///
/// `crate::microvm::GuestRam::register_with_flags` から呼ばれる。`NONE` と `LOG_DIRTY_PAGES` は照会を伴わず ioctl だけを 1 回行う。
pub(crate) fn register_memslot_checked(
    reg: &impl MemslotRegistrar,
    slot: u32,
    flags: MemslotFlags,
    gpa: u64,
    size: u64,
    userspace_addr: u64,
) -> Result<(), RegisterMemslotError> {
    check_memslot_flags_supported(flags, reg).map_err(RegisterMemslotError::Capability)?;
    reg.set_user_memory_region(slot, flags.to_raw(), gpa, size, userspace_addr)
        .map_err(RegisterMemslotError::Ioctl)
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

    /// 登録 ioctl の引数（slot, flags, gpa, size, uaddr）。
    type RegCall = (u32, u32, u64, u64, u64);

    /// 偽の登録層。ioctl に渡る引数を記録する（MVM-1・#4158）。
    struct FakeReg {
        q: Fake,
        calls: RefCell<Vec<RegCall>>,
        result: Result<(), SysError>,
    }

    impl FakeReg {
        fn new(answer: Result<i32, MicrovmErrorCode>) -> Self {
            Self {
                q: Fake::new(answer),
                calls: RefCell::new(Vec::new()),
                result: Ok(()),
            }
        }
    }

    impl MemslotCapabilityQuery for FakeReg {
        fn check_extension(&self, cap: KvmCap) -> Result<i32, MicrovmError> {
            self.q.check_extension(cap)
        }
    }

    impl MemslotRegistrar for FakeReg {
        fn set_user_memory_region(
            &self,
            slot: u32,
            flags: u32,
            gpa: u64,
            size: u64,
            uaddr: u64,
        ) -> Result<(), SysError> {
            self.calls
                .borrow_mut()
                .push((slot, flags, gpa, size, uaddr));
            self.result
        }
    }

    #[test]
    fn mvm1_4158_none_and_log_dirty_register_without_query() {
        for (f, raw) in [
            (MemslotFlags::NONE, 0u32),
            (MemslotFlags::LOG_DIRTY_PAGES, 1),
        ] {
            let r = FakeReg::new(Ok(0));
            register_memslot_checked(&r, 3, f, 0x1000, 0x2000, 0x7000).expect("ok");
            assert_eq!(*r.calls.borrow(), vec![(3, raw, 0x1000, 0x2000, 0x7000)]);
            assert!(r.q.calls.borrow().is_empty());
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4158_readonly_registers_after_query() {
        let both = MemslotFlags::LOG_DIRTY_PAGES.union(MemslotFlags::READONLY);
        for (f, raw) in [(MemslotFlags::READONLY, 2u32), (both, 3)] {
            let r = FakeReg::new(Ok(1));
            register_memslot_checked(&r, 0, f, 0, 4096, 0x9000).expect("ok");
            assert_eq!(*r.calls.borrow(), vec![(0, raw, 0, 4096, 0x9000)]);
            assert_eq!(*r.q.calls.borrow(), vec![sys::consts::KVM_CAP_READONLY_MEM]);
        }
    }

    #[test]
    fn mvm1_4158_unsupported_does_not_call_ioctl() {
        let both = MemslotFlags::LOG_DIRTY_PAGES.union(MemslotFlags::READONLY);
        for f in [MemslotFlags::READONLY, both] {
            for n in [0, -1] {
                let r = FakeReg::new(Ok(n));
                let Err(RegisterMemslotError::Capability(e)) =
                    register_memslot_checked(&r, 0, f, 0, 4096, 0x9000)
                else {
                    panic!("expected capability error");
                };
                assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
                assert_eq!(
                    e.message(),
                    "KVM_CAP_READONLY_MEM is not supported by this kernel"
                );
                assert!(r.calls.borrow().is_empty());
            }
        }
    }

    #[test]
    fn mvm1_4158_query_failure_does_not_call_ioctl() {
        let r = FakeReg::new(Err(MicrovmErrorCode::Internal));
        let Err(RegisterMemslotError::Capability(e)) =
            register_memslot_checked(&r, 0, MemslotFlags::READONLY, 0, 4096, 0x9000)
        else {
            panic!("expected capability error");
        };
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        assert!(r.calls.borrow().is_empty());
    }

    #[test]
    fn mvm1_4158_ioctl_error_propagates() {
        let mut r = FakeReg::new(Ok(1));
        r.result = Err(SysError::Os(22));
        let e = register_memslot_checked(&r, 0, MemslotFlags::LOG_DIRTY_PAGES, 0, 4096, 0x9000);
        assert!(matches!(
            e,
            Err(RegisterMemslotError::Ioctl(SysError::Os(22)))
        ));
        assert_eq!(r.calls.borrow().len(), 1);
    }
}
