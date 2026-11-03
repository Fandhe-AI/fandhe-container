//! x86_64 の BSP の LAPIC の LVT LINT0 / LINT1 を virtual wire mode 用に組み立てる純粋な論理（#3735・MVM-1・MS-7。
//! OS・arch 非依存・`unsafe` なし）。
//!
//! 呼び出し元は `device::VcpuFd::set_boot_lints`（`MicroVm::setup_boot_vcpu` から全 vCPU に呼ばれる）。`KVM_GET_LAPIC` で読んだ
//! 1024 バイトのレジスタ面（xAPIC の MMIO レイアウトで、各レジスタは little-endian の u32）を受け取り、LINT0 を ExtINT
//! （マスク解除）、LINT1 を NMI にして返す。ioctl 自体は `device` / `sys` 側にあり、本モジュールは KVM なしで具体値を試験できる。
//!
//! # 一次情報
//! - Intel SDM Vol. 3A の Local Vector Table（LVT）の図: delivery mode は bit 10:8（`0b100` = NMI、`0b111` = ExtINT）、
//!   mask は bit 16、LINT0 / LINT1 の MMIO オフセットは 0x350 / 0x360。
//! - MP 仕様 1.4 の Virtual Wire Mode: PIC の出力を BSP の LINT0 に ExtINT で接続し、NMI を LINT1 に接続する。
//! - kernel.org の KVM API（`KVM_GET_LAPIC` / `KVM_SET_LAPIC`。`regs[1024]` は xAPIC のレジスタページ）。
//! - Linux の `arch/x86/kernel/apic/apic.c` の `setup_local_APIC` は、BSP の LINT0 がマスク解除の ExtINT のときに virtual wire を
//!   保つ。そのため delivery mode だけでなくマスクビットも 0 にする（`KVM_X86_QUIRK_LINT0_REENABLED` が無効のホスト対策）。
//!
//! Firecracker・rust-vmm のコードは参照も流用もしない（MVM-4）。AP（vCPU 1 以上）にも同じ値を書く（#3737）が、INIT で LVT がマスクへ戻るため設定が残るのは INIT までで、AP の LINT はゲストのカーネルが設定し直す。

use crate::error::{MicrovmError, MicrovmErrorCode};

/// `struct kvm_lapic_state` のレジスタ面のバイト数（`KVM_APIC_REG_SIZE`）。
pub const LAPIC_REG_SIZE: usize = 0x400;
/// LVT LINT0 のオフセット。
pub const LVT_LINT0_OFFSET: usize = 0x350;
/// LVT LINT1 のオフセット。
pub const LVT_LINT1_OFFSET: usize = 0x360;
/// LVT の delivery mode（bit 10:8）のマスク。
pub const LVT_DELIVERY_MODE_MASK: u32 = 0x700;
/// LVT のマスクビット（bit 16）。
pub const LVT_MASKED: u32 = 1 << 16;
/// delivery mode: NMI。
pub const DELIVERY_MODE_NMI: u8 = 0b100;
/// delivery mode: ExtINT。
pub const DELIVERY_MODE_EXTINT: u8 = 0b111;

/// LVT の delivery mode。生の数値を手で組まないための型（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LvtDeliveryMode {
    Fixed,
    Smi,
    Nmi,
    Init,
    ExtInt,
    /// 上記以外の値（予約。読み取りの観測用）。
    Reserved(u8),
}

impl LvtDeliveryMode {
    /// LVT の値から delivery mode を取り出す。
    pub fn from_lvt(lvt: u32) -> Self {
        match ((lvt & LVT_DELIVERY_MODE_MASK) >> 8) as u8 {
            0b000 => Self::Fixed,
            0b010 => Self::Smi,
            0b100 => Self::Nmi,
            0b101 => Self::Init,
            0b111 => Self::ExtInt,
            n => Self::Reserved(n),
        }
    }

    /// bit 10:8 に置く 3 ビットの値。
    pub fn bits(self) -> u8 {
        match self {
            Self::Fixed => 0b000,
            Self::Smi => 0b010,
            Self::Nmi => DELIVERY_MODE_NMI,
            Self::Init => 0b101,
            Self::ExtInt => DELIVERY_MODE_EXTINT,
            Self::Reserved(n) => n & 0b111,
        }
    }
}

/// `current` の delivery mode を `mode` に置き換え、マスクを解除した LVT の値を返す（vector など他のビットは保つ）。
pub fn virtual_wire_lvt(current: u32, mode: LvtDeliveryMode) -> u32 {
    (current & !(LVT_DELIVERY_MODE_MASK | LVT_MASKED)) | (u32::from(mode.bits()) << 8)
}

/// レジスタ面の `offset` の u32（little-endian）を読む。範囲外は `None`。
pub fn read_lapic_reg(regs: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = regs.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// レジスタ面の `offset` へ u32（little-endian）を書く。範囲外は `None`（面は変えない）。
pub fn write_lapic_reg(regs: &mut [u8], offset: usize, value: u32) -> Option<()> {
    let end = offset.checked_add(4)?;
    regs.get_mut(offset..end)?
        .copy_from_slice(&value.to_le_bytes());
    Some(())
}

/// LINT0 / LINT1 の LVT の値の観測結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LapicLints {
    pub lint0: u32,
    pub lint1: u32,
}

impl LapicLints {
    /// レジスタ面から読む。面が短ければ `None`。
    pub fn from_regs(regs: &[u8]) -> Option<Self> {
        Some(Self {
            lint0: read_lapic_reg(regs, LVT_LINT0_OFFSET)?,
            lint1: read_lapic_reg(regs, LVT_LINT1_OFFSET)?,
        })
    }

    pub fn lint0_mode(&self) -> LvtDeliveryMode {
        LvtDeliveryMode::from_lvt(self.lint0)
    }

    pub fn lint1_mode(&self) -> LvtDeliveryMode {
        LvtDeliveryMode::from_lvt(self.lint1)
    }

    pub fn lint0_masked(&self) -> bool {
        self.lint0 & LVT_MASKED != 0
    }

    pub fn lint1_masked(&self) -> bool {
        self.lint1 & LVT_MASKED != 0
    }
}

fn short_page() -> MicrovmError {
    MicrovmError::new(
        MicrovmErrorCode::Internal,
        "LAPIC register page is too short for LVT LINT0/LINT1",
    )
}

/// レジスタ面の LINT0 を ExtINT、LINT1 を NMI（ともにマスク解除）にし、設定後の値を返す。他のバイトは変えない。
/// 面が短ければ fail-closed でエラー（面は変えない）。
pub fn apply_boot_lints(regs: &mut [u8]) -> Result<LapicLints, MicrovmError> {
    let cur = LapicLints::from_regs(regs).ok_or_else(short_page)?;
    let new = LapicLints {
        lint0: virtual_wire_lvt(cur.lint0, LvtDeliveryMode::ExtInt),
        lint1: virtual_wire_lvt(cur.lint1, LvtDeliveryMode::Nmi),
    };
    write_lapic_reg(regs, LVT_LINT0_OFFSET, new.lint0).ok_or_else(short_page)?;
    write_lapic_reg(regs, LVT_LINT1_OFFSET, new.lint1).ok_or_else(short_page)?;
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MVM-1・#3735: KVM のリセット値（マスク済み 0x10000）から ExtINT / NMI を組み立てる。
    #[test]
    fn mvm1_3735_builds_from_reset_value() {
        assert_eq!(
            virtual_wire_lvt(0x0001_0000, LvtDeliveryMode::ExtInt),
            0x0000_0700
        );
        assert_eq!(
            virtual_wire_lvt(0x0001_0000, LvtDeliveryMode::Nmi),
            0x0000_0400
        );
    }

    /// vector は保ち、delivery mode の置換とマスク解除だけを行い、冪等である。
    #[test]
    fn mvm1_3735_keeps_vector_and_is_idempotent() {
        assert_eq!(
            virtual_wire_lvt(0x0001_00FF, LvtDeliveryMode::ExtInt),
            0x0000_07FF
        );
        assert_eq!(
            virtual_wire_lvt(0x0000_0030, LvtDeliveryMode::Nmi),
            0x0000_0430
        );
        assert_eq!(
            virtual_wire_lvt(0x0000_0700, LvtDeliveryMode::ExtInt),
            0x0000_0700
        );
    }

    #[test]
    fn mvm1_3735_delivery_mode_round_trip() {
        assert_eq!(LvtDeliveryMode::from_lvt(0x700), LvtDeliveryMode::ExtInt);
        assert_eq!(LvtDeliveryMode::from_lvt(0x400), LvtDeliveryMode::Nmi);
        assert_eq!(LvtDeliveryMode::from_lvt(0x030), LvtDeliveryMode::Fixed);
        assert_eq!(
            LvtDeliveryMode::from_lvt(0x300),
            LvtDeliveryMode::Reserved(3)
        );
        assert_eq!(LvtDeliveryMode::Reserved(3).bits(), 3);
    }

    #[test]
    fn mvm1_3735_reg_access_le_and_bounds() {
        let mut regs = [0u8; LAPIC_REG_SIZE];
        write_lapic_reg(&mut regs, 0x350, 0x0102_0304).unwrap();
        assert_eq!(&regs[0x350..0x354], &[4, 3, 2, 1]);
        assert_eq!(read_lapic_reg(&regs, 0x350), Some(0x0102_0304));
        assert_eq!(read_lapic_reg(&regs, 0x3FC), Some(0));
        assert_eq!(read_lapic_reg(&regs, 0x3FD), None);
        assert_eq!(read_lapic_reg(&regs, 0x400), None);
        assert_eq!(read_lapic_reg(&regs, usize::MAX), None);
        assert_eq!(write_lapic_reg(&mut regs, 0x3FD, 1), None);
    }

    /// 0x350 / 0x360 の 8 バイトだけが変わり、他は変わらない。
    #[test]
    fn mvm1_3735_apply_changes_only_lint_bytes() {
        let mut regs = [0xA5u8; LAPIC_REG_SIZE];
        write_lapic_reg(&mut regs, LVT_LINT0_OFFSET, 0x0001_0000).unwrap();
        write_lapic_reg(&mut regs, LVT_LINT1_OFFSET, 0x0001_0000).unwrap();
        let before = regs;
        let got = apply_boot_lints(&mut regs).unwrap();
        assert_eq!(
            got,
            LapicLints {
                lint0: 0x0000_0700,
                lint1: 0x0000_0400
            }
        );
        assert_eq!(LapicLints::from_regs(&regs), Some(got));
        assert_eq!(got.lint0_mode(), LvtDeliveryMode::ExtInt);
        assert_eq!(got.lint1_mode(), LvtDeliveryMode::Nmi);
        assert!(!got.lint0_masked() && !got.lint1_masked());
        for (i, (a, b)) in before.iter().zip(regs.iter()).enumerate() {
            let in_lint = (0x350..0x354).contains(&i) || (0x360..0x364).contains(&i);
            if !in_lint {
                assert_eq!(a, b, "byte {i:#x}");
            }
        }
    }

    #[test]
    fn mvm1_3735_short_page_fails_closed() {
        let mut regs = [0u8; 0x363];
        let err = apply_boot_lints(&mut regs).unwrap_err();
        assert_eq!(err.code(), MicrovmErrorCode::Internal);
        assert!(regs.iter().all(|b| *b == 0));
    }
}
