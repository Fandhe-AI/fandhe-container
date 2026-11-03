//! x86_64 ゲストへ渡す CPUID 表の型と、vCPU ごとの調整（#3733・TASK-75.3.2・MVM-1・REPAIR-3）。
//!
//! OS 非依存・`unsafe` なし。`device::KvmDevice::supported_cpuid` が `KVM_GET_SUPPORTED_CPUID` の結果をこの型へ変換し、
//! `microvm::MicroVm::assemble` が vCPU を作るたびに [`CpuidTable::for_vcpu`] で調整した表を作って
//! `device::VcpuFd::set_cpuid`（`KVM_SET_CPUID2`）へ渡す（#3720 の AP も同じ経路を通る）。`KVM_SET_CPUID2` は
//! 最初の `KVM_RUN` より前でなければならない（新しいカーネルは実行後の変更を拒否する）。
//!
//! # 調整の方針
//! - APIC ID は vCPU id と同じにする（in-kernel LAPIC は APIC ID を vCPU id から決めるため、表の値がずれるとゲストが
//!   自分の LAPIC を見失う）。書き換えるのは leaf 1 の EBX\[31:24\] と、leaf 0xB・0x1F の全 subleaf の EDX（x2APIC ID）だけ。
//! - leaf 1 の ECX bit 31（hypervisor present）を立てる。ゲストが仮想化環境と判断して paravirt を使えるようにする。
//!   ホストの機能は新たに露出しない（機能ビットは KVM の supported の範囲を超えない）。
//! - 上記以外の leaf は触らない。
//!
//! # 範囲外（REPAIR-3）
//! トポロジーの leaf（leaf 4 EAX\[31:26\]・leaf 1 EBX\[23:16\]・leaf 0xB の EAX / EBX / ECX の段数・0x8000_001E）の整合、
//! KVM 署名の leaf 0x4000_000x（KVM が返した値のまま渡す）、機能ビットの絞り込みは未実装。
//!
//! 一次情報は Intel SDM の CPUID の章と、カーネルの `Documentation/virt/kvm/api.rst`
//! （`KVM_GET_SUPPORTED_CPUID`・`KVM_SET_CPUID2`）。rust-vmm・Firecracker のコードは参照しない（MVM-4）。
//! エラーの `message` に表の値は載せない（ERR-1）。

use crate::error::{MicrovmError, MicrovmErrorCode};

/// CPUID 表の最大件数（カーネルの `KVM_MAX_CPUID_ENTRIES` と同じ 256。`sys` の値と `device` 側で照合する）。
pub const MAX_CPUID_ENTRIES: usize = 256;

const LEAF_VENDOR: u32 = 0;
const LEAF_FEATURES: u32 = 1;
const LEAF_TOPOLOGY_V1: u32 = 0xB;
const LEAF_TOPOLOGY_V2: u32 = 0x1F;
/// leaf 1 ECX bit 31（hypervisor present）。
const HYPERVISOR_BIT: u32 = 1 << 31;

/// CPUID の 1 エントリ（`struct kvm_cpuid_entry2` の padding を除いたもの）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuidEntry {
    /// leaf（EAX 入力）。
    pub function: u32,
    /// subleaf（ECX 入力）。
    pub index: u32,
    /// `KVM_CPUID_FLAG_*`。
    pub flags: u32,
    /// EAX 出力。
    pub eax: u32,
    /// EBX 出力。
    pub ebx: u32,
    /// ECX 出力。
    pub ecx: u32,
    /// EDX 出力。
    pub edx: u32,
}

/// 件数を検証済みの CPUID 表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuidTable {
    entries: Vec<CpuidEntry>,
}

impl CpuidTable {
    /// 表を作る。0 件と [`MAX_CPUID_ENTRIES`] 超は `InvalidArgument`。
    pub fn new(entries: Vec<CpuidEntry>) -> Result<Self, MicrovmError> {
        if entries.is_empty() || entries.len() > MAX_CPUID_ENTRIES {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "CPUID table must have 1..=256 entries",
            ));
        }
        Ok(CpuidTable { entries })
    }

    /// 全エントリ。
    pub fn entries(&self) -> &[CpuidEntry] {
        &self.entries
    }

    /// `function` / `index` に一致する最初のエントリ。
    pub fn get(&self, function: u32, index: u32) -> Option<&CpuidEntry> {
        self.entries
            .iter()
            .find(|e| e.function == function && e.index == index)
    }

    /// leaf 0 の vendor 文字列（EBX・EDX・ECX を little endian で並べた 12 バイト）。
    pub fn vendor(&self) -> Option<[u8; 12]> {
        let e = self.get(LEAF_VENDOR, 0)?;
        let (b, d, c) = (
            e.ebx.to_le_bytes(),
            e.edx.to_le_bytes(),
            e.ecx.to_le_bytes(),
        );
        Some([
            b[0], b[1], b[2], b[3], d[0], d[1], d[2], d[3], c[0], c[1], c[2], c[3],
        ])
    }

    /// vCPU `apic_id` 用に調整した複製を返す（方針はモジュール doc）。
    ///
    /// `apic_id` が 255 超なら `InvalidArgument`、leaf 1 が無ければ `FailedPrecondition`（fail-closed）。
    pub fn for_vcpu(&self, apic_id: u32) -> Result<CpuidTable, MicrovmError> {
        let id8 = u8::try_from(apic_id).map_err(|_| {
            MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "APIC ID does not fit in 8 bits",
            )
        })?;
        let mut out = self.clone();
        let mut found = false;
        for e in out.entries.iter_mut() {
            if e.function == LEAF_FEATURES && e.index == 0 {
                e.ebx = (e.ebx & 0x00FF_FFFF) | (u32::from(id8) << 24);
                e.ecx |= HYPERVISOR_BIT;
                found = true;
            } else if e.function == LEAF_TOPOLOGY_V1 || e.function == LEAF_TOPOLOGY_V2 {
                e.edx = apic_id;
            }
        }
        if !found {
            return Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "CPUID table has no leaf 1",
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(function: u32, index: u32, eax: u32, ebx: u32, ecx: u32, edx: u32) -> CpuidEntry {
        CpuidEntry {
            function,
            index,
            flags: u32::from(function == 0xB || function == 0x1F),
            eax,
            ebx,
            ecx,
            edx,
        }
    }

    fn sample() -> CpuidTable {
        CpuidTable::new(vec![
            e(0, 0, 0x16, 0x756E_6547, 0x6C65_746E, 0x4965_6E69),
            e(1, 0, 0x000A_0653, 0x0A10_0800, 0x0000_0001, 0xBFEB_FBFF),
            e(7, 0, 0, 0x1234, 0x5678, 0x9ABC),
            e(0xB, 0, 1, 2, 0x100, 0xDEAD),
            e(0xB, 1, 4, 8, 0x201, 0xBEEF),
            e(0x1F, 0, 1, 2, 0x100, 0xCAFE),
            e(0x4000_0000, 0, 0x4000_0001, 0x4B4D_564B, 0x564B_4D56, 0x4D),
        ])
        .unwrap()
    }

    #[test]
    fn mvm1_3733_leaf1_apic_id_and_hypervisor_bit() {
        let t = sample().for_vcpu(5).unwrap();
        let l1 = t.get(1, 0).unwrap();
        assert_eq!(l1.ebx, 0x0510_0800);
        assert_eq!(l1.ecx, 0x8000_0001);
        assert_eq!(l1.eax, 0x000A_0653);
        assert_eq!(l1.edx, 0xBFEB_FBFF);
    }

    #[test]
    fn mvm1_3733_apic_id_boundaries_and_idempotent_hypervisor_bit() {
        assert_eq!(
            sample().for_vcpu(0).unwrap().get(1, 0).unwrap().ebx,
            0x0010_0800
        );
        assert_eq!(
            sample().for_vcpu(31).unwrap().get(1, 0).unwrap().ebx,
            0x1F10_0800
        );
        let mut v = sample().entries().to_vec();
        v[1].ecx = 0x8000_0001;
        let t = CpuidTable::new(v).unwrap().for_vcpu(1).unwrap();
        assert_eq!(t.get(1, 0).unwrap().ecx, 0x8000_0001);
    }

    #[test]
    fn mvm1_3733_x2apic_leaves_get_edx_only() {
        let t = sample().for_vcpu(7).unwrap();
        let a = t.get(0xB, 0).unwrap();
        assert_eq!((a.eax, a.ebx, a.ecx, a.edx, a.flags), (1, 2, 0x100, 7, 1));
        let b = t.get(0xB, 1).unwrap();
        assert_eq!((b.eax, b.ebx, b.ecx, b.edx), (4, 8, 0x201, 7));
        let c = t.get(0x1F, 0).unwrap();
        assert_eq!((c.eax, c.ebx, c.ecx, c.edx), (1, 2, 0x100, 7));
    }

    #[test]
    fn mvm1_3733_other_leaves_unchanged() {
        let base = sample();
        let t = base.for_vcpu(3).unwrap();
        for f in [0u32, 7, 0x4000_0000] {
            assert_eq!(t.get(f, 0), base.get(f, 0));
        }
    }

    #[test]
    fn mvm1_3733_rejects_bad_apic_id_and_missing_leaf1() {
        assert_eq!(
            sample().for_vcpu(256).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        let t = CpuidTable::new(vec![e(0, 0, 0, 0, 0, 0)]).unwrap();
        assert_eq!(
            t.for_vcpu(0).unwrap_err().code(),
            MicrovmErrorCode::FailedPrecondition
        );
    }

    #[test]
    fn mvm1_3733_new_enforces_entry_count() {
        let one = e(0, 0, 0, 0, 0, 0);
        assert!(CpuidTable::new(vec![]).is_err());
        assert!(CpuidTable::new(vec![one; 257]).is_err());
        assert_eq!(
            CpuidTable::new(vec![one; 256]).unwrap().entries().len(),
            256
        );
    }

    #[test]
    fn mvm1_3733_vendor_string() {
        assert_eq!(sample().vendor(), Some(*b"GenuineIntel"));
        let amd = CpuidTable::new(vec![e(0, 0, 0, 0x6874_7541, 0x444D_4163, 0x6974_6E65)]).unwrap();
        assert_eq!(amd.vendor(), Some(*b"AuthenticAMD"));
        let none = CpuidTable::new(vec![e(1, 0, 0, 0, 0, 0)]).unwrap();
        assert_eq!(none.vendor(), None);
    }
}
