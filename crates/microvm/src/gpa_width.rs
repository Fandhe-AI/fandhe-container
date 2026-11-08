//! ゲスト物理アドレス（GPA / IPA）の幅と最上位 GPA の照合（MVM-1・MVM-5・ERR-1。#4106・#4227）。
//!
//! 役割: 「VM が実際に使えるアドレス幅」と「レイアウトの最上位 GPA（終端・排他）」を、VM 資源を作る前に突き合わせる
//! OS 非依存の純関数群。KVM・HVF のどちらも呼ばないので、既定のテスト集合（Linux x86_64 の PR CI）で境界値を照合できる。
//!
//! 呼び出し元（いずれも VM fd / `hv_vm_create` より前。失敗しても後始末は要らない）:
//! - x86_64（KVM）: `microvm::MicroVm::assemble` が CPUID leaf 0x8000_0008 の EAX\[7:0\] で [`check_gpa_fits`]（#4106）
//! - aarch64（KVM）: 同 `assemble` が `KVM_CAP_ARM_VM_IPA_SIZE` の応答を [`kvm_arm64_type0_ipa_bits`] で幅に直し、
//!   [`check_gpa_fits`] で `Arm64Layout::max_region_end` と照合する（#4227）
//! - macOS（HVF）: `HvfMicroVm::assemble` が `hv_vm_config_get_default_ipa_size` の応答を [`hvf_ipa_bits`] で検査し、
//!   [`check_gpa_fits`] で `Arm64Layout::max_region_end` と照合する（#4227）
//!
//! # 方針
//! - 超過はホストの能力に依存する失敗で、構成の誤り（`InvalidArgument`）ではなく `FailedPrecondition`。
//! - カーネル・フレームワークの応答は外部入力として扱う。非対応・負・異常値は幅として使わず拒否する（fail-closed。
//!   「36 bit とみなす」ような縮退はしない）。
//! - エラーの message は固定文で、幅・アドレス・シンボル名は載せない（ERR-1）。
//!
//! # 一次情報（Linux v6.12。2026-11 に原文で確認）
//! - `include/uapi/linux/kvm.h`: `KVM_CAP_ARM_VM_IPA_SIZE` は 165。
//! - `arch/arm64/kvm/arm.c` の `kvm_vm_ioctl_check_extension`: 応答は `get_kvm_ipa_limit()`（ホストの IPA 上限のビット数）。
//! - `arch/arm64/include/asm/kvm_mmu.h`: `KVM_PHYS_SHIFT` は 40（machine type 0 の既定幅）。
//! - `arch/arm64/kvm/mmu.c` の `kvm_init_stage2_mmu`: type 0 では `KVM_PHYS_SHIFT > kvm_ipa_limit` のとき `-EINVAL`
//!   （切り詰めない）。pKVM（`is_protected_kvm_enabled`）では `kvm_ipa_limit` 全体を使うが、ここでは 40 未満を一律に拒否する
//!   安全側に倒す。明示指定（`KVM_VM_TYPE_ARM_IPA_SIZE(n)`）は `ARM64_MIN_PARANGE_BITS`（32）以上・上限以下。
//! - Apple: `hv_vm_config_get_default_ipa_size(uint32_t *)` は macOS 13.0 以降。
//!   <https://developer.apple.com/documentation/hypervisor/hv_vm_config_get_default_ipa_size(_:)>
//!
//! 判断記録は docs/design/microvm-memory-ownership.md の #4227 の節。

use crate::error::{MicrovmError, MicrovmErrorCode};

/// KVM の arm64 で machine type 0 のときの既定の IPA 幅（Linux の `KVM_PHYS_SHIFT`）。
pub const KVM_ARM64_DEFAULT_IPA_BITS: u32 = 40;

/// arm64 の IPA 幅の下限（Linux の `ARM64_MIN_PARANGE_BITS`。明示指定の下限）。
pub const ARM64_MIN_IPA_BITS: u32 = 32;

/// arm64 の IPA 幅の上限（Armv8 の PARange の最大。応答の異常値の検査用）。
pub const ARM64_MAX_IPA_BITS: u32 = 52;

/// 照合の失敗文を選ぶための照会元（message に数値を載せないため、固定文だけを持つ）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpaWidthSource {
    /// x86_64 の CPUID leaf 0x8000_0008 の物理アドレス幅。
    X86Cpuid,
    /// aarch64（KVM）の machine type 0 の IPA 幅。
    KvmArm64Ipa,
    /// macOS（HVF）の既定の IPA 幅。
    HvfDefaultIpa,
}

impl GpaWidthSource {
    const fn message(self) -> &'static str {
        match self {
            GpaWidthSource::X86Cpuid => {
                "guest physical address space exceeds the CPUID physical address width"
            }
            GpaWidthSource::KvmArm64Ipa => "guest physical address space exceeds the KVM IPA size",
            GpaWidthSource::HvfDefaultIpa => {
                "guest physical address space exceeds the hypervisor default IPA size"
            }
        }
    }
}

/// 最上位 GPA の終端 `top_end`（排他）が幅 `bits` で表せる範囲 `[0, 2^bits)` に収まるか確かめる。
///
/// 超過は `FailedPrecondition`。シフトは `checked_shl` で、64 bit 以上は表せないものとして拒否する（fail-closed）。
pub fn check_gpa_fits(bits: u32, top_end: u64, source: GpaWidthSource) -> Result<(), MicrovmError> {
    match 1u64.checked_shl(bits) {
        Some(limit) if top_end <= limit => Ok(()),
        _ => Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            source.message(),
        )),
    }
}

/// `KVM_CHECK_EXTENSION(KVM_CAP_ARM_VM_IPA_SIZE)` の応答 `cap`（ホストの IPA 上限ビット数）から、machine type 0 で
/// 作る VM の実際の IPA 幅を決める。
///
/// - `cap <= 0`（非対応・照会不能）と `cap > 52`（異常値）は `FailedPrecondition`。
/// - `cap < 40` は `FailedPrecondition`（v6.12 の `kvm_init_stage2_mmu` が type 0 を `-EINVAL` で拒否するため）。
/// - それ以外は 40（`KVM_PHYS_SHIFT`）。
pub fn kvm_arm64_type0_ipa_bits(cap: i32) -> Result<u32, MicrovmError> {
    let cap = u32::try_from(cap)
        .ok()
        .filter(|c| (1..=ARM64_MAX_IPA_BITS).contains(c))
        .ok_or_else(|| {
            MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "KVM_CAP_ARM_VM_IPA_SIZE is not supported or reported an invalid size",
            )
        })?;
    if cap < KVM_ARM64_DEFAULT_IPA_BITS {
        return Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "host IPA size limit is below the KVM default for machine type 0",
        ));
    }
    Ok(KVM_ARM64_DEFAULT_IPA_BITS)
}

/// `hv_vm_config_get_default_ipa_size` の出力 `raw`（ビット数）を検査する。0 と 52 超は `FailedPrecondition`。
pub fn hvf_ipa_bits(raw: u32) -> Result<u32, MicrovmError> {
    if (1..=ARM64_MAX_IPA_BITS).contains(&raw) {
        Ok(raw)
    } else {
        Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "hypervisor reported an invalid default IPA size",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MVM-1・#4227: 幅と最上位 GPA の境界（収まる / 収まらない）。
    #[test]
    fn mvm1_4227_check_gpa_fits_boundaries() {
        use GpaWidthSource::*;
        assert!(check_gpa_fits(36, 1 << 36, HvfDefaultIpa).is_ok());
        assert!(check_gpa_fits(36, (1 << 36) + 1, HvfDefaultIpa).is_err());
        assert!(check_gpa_fits(40, 1 << 40, KvmArm64Ipa).is_ok());
        let e = check_gpa_fits(40, (1 << 40) + 1, KvmArm64Ipa).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        assert!(check_gpa_fits(52, 1 << 52, KvmArm64Ipa).is_ok());
        assert!(check_gpa_fits(64, 1, X86Cpuid).is_err());
        assert!(check_gpa_fits(63, 1 << 63, X86Cpuid).is_ok());
    }

    /// ERR-1: message は固定文で数値を含まない。x86 の文は #4106 と同じ。
    #[test]
    fn mvm1_4227_messages_are_fixed() {
        use GpaWidthSource::*;
        let x = check_gpa_fits(34, u64::MAX, X86Cpuid).unwrap_err();
        assert_eq!(
            x.message(),
            "guest physical address space exceeds the CPUID physical address width"
        );
        for s in [X86Cpuid, KvmArm64Ipa, HvfDefaultIpa] {
            let e = check_gpa_fits(36, u64::MAX, s).unwrap_err();
            assert!(!e.message().chars().any(|c| c.is_ascii_digit()));
        }
    }

    /// MVM-1・#4227: `KVM_CAP_ARM_VM_IPA_SIZE` の応答から type 0 の幅を決める（v6.12 の挙動。40 未満は EINVAL 相当）。
    #[test]
    fn mvm1_4227_kvm_arm64_type0_ipa_bits() {
        for bad in [0, -1, i32::MIN, 53, 64, i32::MAX] {
            assert_eq!(
                kvm_arm64_type0_ipa_bits(bad).unwrap_err().code(),
                MicrovmErrorCode::FailedPrecondition,
                "cap={bad}"
            );
        }
        for low in [1, 32, 36, 39] {
            assert_eq!(
                kvm_arm64_type0_ipa_bits(low).unwrap_err().code(),
                MicrovmErrorCode::FailedPrecondition,
                "cap={low}"
            );
        }
        for ok in [40, 44, 48, 52] {
            assert_eq!(kvm_arm64_type0_ipa_bits(ok).unwrap(), 40, "cap={ok}");
        }
    }

    /// MVM-5・#4227: HVF の既定幅の範囲検査。
    #[test]
    fn mvm1_4227_hvf_ipa_bits() {
        assert!(hvf_ipa_bits(0).is_err());
        assert_eq!(hvf_ipa_bits(36).unwrap(), 36);
        assert_eq!(hvf_ipa_bits(40).unwrap(), 40);
        assert_eq!(hvf_ipa_bits(52).unwrap(), 52);
        assert!(hvf_ipa_bits(53).is_err());
    }
}
