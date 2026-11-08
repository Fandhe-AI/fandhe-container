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
//! - 上記以外の leaf は触らない。leaf 0x8000_0008（物理アドレス幅）も書き換えず、[`CpuidTable::physical_address_bits`] で
//!   ゲストが見る幅を読み、登録する最上位 GPA の照合に使う（#4106・MVM-1。照合は `microvm::check_physical_address_width`）。
//!
//! # 範囲外（REPAIR-3）
//! トポロジーの leaf（leaf 4 EAX\[31:26\]・leaf 1 EBX\[23:16\]・leaf 0xB の EAX / EBX / ECX の段数・0x8000_001E）の整合、
//! KVM 署名の leaf 0x4000_000x（KVM が返した値のまま渡す）、機能ビットの絞り込みは未実装。
//! leaf 0x8000_0008 は EAX\[7:0\] だけを参照する。EAX\[23:16\]（AMD の GuestPhysAddrSize）は未考慮（#4106）。
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
/// leaf 0x8000_0008（アドレス幅。EAX\[7:0\] が MAXPHYADDR）。
const LEAF_ADDR_SIZES: u32 = 0x8000_0008;
/// 物理アドレス幅として受け入れる上限（x86-64 のアーキテクチャ上限 52 bit）。超える値は壊れた入力として拒否する。
const MAX_PHYS_ADDR_BITS: u8 = 52;
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

    /// ゲストが見る物理アドレス幅（leaf 0x8000_0008・subleaf 0 の EAX\[7:0\]。ビット数）を返す。#4106・MVM-1。
    ///
    /// leaf が無い・値が 0・`MAX_PHYS_ADDR_BITS`（52）超は `FailedPrecondition`（fail-closed）。SDM の「leaf が無ければ
    /// 36 bit とみなす」フォールバックは使わない。`microvm::MicroVm::assemble` が VM 資源を作る前に最上位 GPA と照合する。
    pub fn physical_address_bits(&self) -> Result<u8, MicrovmError> {
        let bits = self
            .get(LEAF_ADDR_SIZES, 0)
            .map(|e| (e.eax & 0xFF) as u8)
            .filter(|b| (1..=MAX_PHYS_ADDR_BITS).contains(b));
        bits.ok_or_else(|| {
            MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "CPUID physical address width is missing or out of range",
            )
        })
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

    fn with_addr_sizes(eax: u32) -> CpuidTable {
        let mut v = sample().entries().to_vec();
        v.push(e(0x8000_0008, 0, eax, 0, 0, 0));
        CpuidTable::new(v).unwrap()
    }

    /// MVM-1・#4106: EAX[7:0] だけを読む（上位ビットは無視）。
    #[test]
    fn mvm1_4106_physical_address_bits_values() {
        assert_eq!(with_addr_sizes(39).physical_address_bits().unwrap(), 39);
        assert_eq!(with_addr_sizes(34).physical_address_bits().unwrap(), 34);
        assert_eq!(with_addr_sizes(52).physical_address_bits().unwrap(), 52);
        assert_eq!(
            with_addr_sizes(0x0030_2E2F)
                .physical_address_bits()
                .unwrap(),
            0x2F
        );
    }

    /// MVM-1・#4106: leaf 欠如・0・53 以上は fail-closed。
    #[test]
    fn mvm1_4106_physical_address_bits_rejects_bad_values() {
        for t in [
            sample(),
            with_addr_sizes(0),
            with_addr_sizes(53),
            with_addr_sizes(255),
        ] {
            assert_eq!(
                t.physical_address_bits().unwrap_err().code(),
                MicrovmErrorCode::FailedPrecondition
            );
        }
    }

    /// MVM-1・#4106: `for_vcpu` は leaf 0x8000_0008 を書き換えない（ベースの表の照合がゲストの見る値と一致する根拠）。
    #[test]
    fn mvm1_4106_for_vcpu_keeps_address_width_leaf() {
        let base = with_addr_sizes(39);
        let t = base.for_vcpu(3).unwrap();
        assert_eq!(t.get(0x8000_0008, 0), base.get(0x8000_0008, 0));
        assert_eq!(t.physical_address_bits().unwrap(), 39);
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
