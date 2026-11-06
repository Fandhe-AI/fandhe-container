//! arm64 の ESR（例外 syndrome）の復号（TASK-192.8・#3785・MVM-5・MVM-1）。OS 非依存・`unsafe` なし。
//!
//! 役割: ゲストの例外 exit で得る syndrome（`hv_vcpu_exit_exception_t.syndrome`。ESR_EL2 相当の u64）を、
//! EC（Exception Class）と ISS で分類した型へ写す純関数群。`hv_*` や KVM を呼ばないため、Linux の PR CI で
//! 単体試験が走る（macOS の PR CI は型検査のみ）。呼び出し元は macOS バックエンドの実行ループ（#3791 の exit 分類。
//! MMIO は #3793、PSCI / HVC は #3794、WFI は #3796）で、KVM の aarch64 でも再利用できる。
//!
//! # 一次情報（ビット位置の出典）
//! Arm Architecture Reference Manual for A-profile（DDI 0487）の「ESR_EL2, Exception Syndrome Register (EL2)」と、
//! ISS 符号化の各節（Data Abort / WF* / HVC・SVC / SMC / MSR・MRS・System instruction。いずれも AArch64 state）。
//! 要確認: 本実装時点で Arm 公式ページの版 ID までは機械的に確認できていない（二次資料の hafnium・barebox・zephyr の
//! 定義と一致を確認）。Linux の `esr.h`（GPL）は参照も流用もしない（MVM-4・licensing）。
//!
//! # 契約
//! - bit 63:37 は RES0、36:32 は ISS2。分類には使わず無視する。
//! - [`EsrClass::Other`]（未知の EC）と [`EsrClass::DataAbortUnsupported`]（ISV=0）は fail-closed の入口で、
//!   呼び出し側は推測で続行せず VM を止めること。
//! - PC の進め方は呼び出し側の責務。HVC の優先戻り先は次の命令、HCR_EL2.TSC で trap した SMC の優先戻り先は
//!   SMC 命令自身、data abort も faulting 命令を指す（HVC と data abort は #3803、SMC は #3997 で実機の exit を確かめた）。
//!   進める量は [`instruction_length`] で得る。
//!
//! # 未実装（REPAIR-3）
//! ISV=0 の命令の自前デコード（ゲストメモリから命令を読んで解釈する攻撃面を作らないため行わない）・AArch32 の EC・
//! ISS2 と FEAT_LS64 等の拡張の復号。

/// EC（bit 31:26）の位置。
const EC_SHIFT: u32 = 26;
/// IL（bit 25）。1 なら 32 bit 命令。
const IL_BIT: u32 = 25;
/// ISS（bit 24:0）のマスク。
const ISS_MASK: u64 = 0x01FF_FFFF;

const EC_WFX: u8 = 0x01;
const EC_HVC64: u8 = 0x16;
const EC_SMC64: u8 = 0x17;
const EC_SYSREG: u8 = 0x18;
const EC_DABT_LOWER: u8 = 0x24;

/// 命令長（IL）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionLength {
    /// 16 bit 命令（IL=0）。
    Two,
    /// 32 bit 命令（IL=1）。
    Four,
}

impl InstructionLength {
    /// バイト数（2 または 4）。
    pub fn bytes(self) -> u64 {
        match self {
            Self::Two => 2,
            Self::Four => 4,
        }
    }
}

/// 汎用レジスタ番号（0..=31）。31 は XZR / WZR で SP ではない（誤って SP へ書かないこと）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GprIndex(u8);

impl GprIndex {
    fn from_bits(v: u64) -> Self {
        Self((v & 0x1F) as u8)
    }

    /// 番号（0..=31）。
    pub fn get(self) -> u8 {
        self.0
    }

    /// XZR / WZR（番号 31）なら true。読みは 0、書きは捨てる。
    pub fn is_zero_register(self) -> bool {
        self.0 == 31
    }
}

/// WF* の種別（ISS の TI = bit 1:0）。WFIT / WFET は FEAT_WFxT。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfxKind {
    /// WFI。
    Wfi,
    /// WFE。
    Wfe,
    /// WFIT。
    Wfit,
    /// WFET。
    Wfet,
}

/// アクセスの向き（data abort の WnR）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessDirection {
    /// 読み（WnR=0）。
    Read,
    /// 書き（WnR=1）。
    Write,
}

/// システムレジスタ trap の向き（ISS の Direction = bit 0）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysRegDirection {
    /// MSR（書き。bit 0 = 0）。
    Write,
    /// MRS（読み。bit 0 = 1）。
    Read,
}

/// data abort のアクセス幅（SAS = bit 23:22）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSize {
    /// 1 バイト。
    Byte,
    /// 2 バイト。
    Halfword,
    /// 4 バイト。
    Word,
    /// 8 バイト。
    Doubleword,
}

impl AccessSize {
    /// バイト数（1 / 2 / 4 / 8）。
    pub fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Halfword => 2,
            Self::Word => 4,
            Self::Doubleword => 8,
        }
    }
}

/// 命令の復号情報あり（ISV=1）の data abort。MMIO のデバイスモデルへ渡す材料（#3793）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataAbort {
    /// SAS: アクセス幅。
    pub access_size: AccessSize,
    /// SSE: 読みの符号拡張。
    pub sign_extend: bool,
    /// SRT: 転送レジスタ。31 は XZR。
    pub register: GprIndex,
    /// SF: 64 bit レジスタ幅。
    pub sixty_four_bit: bool,
    /// AR: acquire / release。
    pub acquire_release: bool,
    /// WnR: 読みか書きか。
    pub direction: AccessDirection,
    /// S1PTW: stage 1 の表引き中の fault。MMIO として扱うかは呼び出し側が判断する。
    pub s1ptw: bool,
    /// DFSC（bit 5:0）。観測用。
    pub dfsc: u8,
    /// ISS 全体（bit 24:0）。EA・CM・FnV 等を呼び出し側が見るために残す。
    pub iss: u32,
}

/// MSR / MRS / システム命令 trap の ISS（EC 0x18）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysRegAccess {
    /// Op0（bit 21:20）。
    pub op0: u8,
    /// Op2（bit 19:17）。
    pub op2: u8,
    /// Op1（bit 16:14）。
    pub op1: u8,
    /// CRn（bit 13:10）。
    pub crn: u8,
    /// Rt（bit 9:5）。31 は XZR。
    pub rt: GprIndex,
    /// CRm（bit 4:1）。
    pub crm: u8,
    /// 向き（bit 0）。
    pub direction: SysRegDirection,
}

/// syndrome の分類結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EsrClass {
    /// EC 0x01: WFI / WFE 系。
    Wfx(WfxKind),
    /// EC 0x16: AArch64 の HVC。
    Hvc {
        /// 命令の immediate（ISS bit 15:0）。
        imm16: u16,
    },
    /// EC 0x17: AArch64 の SMC。
    Smc {
        /// 命令の immediate（ISS bit 15:0）。
        imm16: u16,
    },
    /// EC 0x18: MSR / MRS / システム命令の trap。
    SysReg(SysRegAccess),
    /// EC 0x24 かつ ISV=1: lower EL からの data abort。
    DataAbort(DataAbort),
    /// EC 0x24 かつ ISV=0: 命令の復号情報なし。命令の自前デコードはしない（REPAIR-3）。呼び出し側は VM を止める。
    DataAbortUnsupported {
        /// ISS 全体（bit 24:0）。
        iss: u32,
    },
    /// 上記以外。fail-closed: 呼び出し側は VM を止める。
    Other {
        /// EC の値（0..=63）。
        ec: u8,
    },
}

/// EC（bit 31:26）を返す。
pub fn exception_class(syndrome: u64) -> u8 {
    ((syndrome >> EC_SHIFT) & 0x3F) as u8
}

/// IL（bit 25）から命令長を得る。
pub fn instruction_length(syndrome: u64) -> InstructionLength {
    if (syndrome >> IL_BIT) & 1 == 1 {
        InstructionLength::Four
    } else {
        InstructionLength::Two
    }
}

/// syndrome を分類する。全 64 bit の入力を何らかの variant に写す（panic しない。ゲスト由来の untrusted な値）。
pub fn decode_esr(syndrome: u64) -> EsrClass {
    let ec = exception_class(syndrome);
    let iss = (syndrome & ISS_MASK) as u32;
    let bits = u64::from(iss);
    match ec {
        EC_WFX => EsrClass::Wfx(match bits & 0b11 {
            0 => WfxKind::Wfi,
            1 => WfxKind::Wfe,
            2 => WfxKind::Wfit,
            _ => WfxKind::Wfet,
        }),
        EC_HVC64 => EsrClass::Hvc {
            imm16: (bits & 0xFFFF) as u16,
        },
        EC_SMC64 => EsrClass::Smc {
            imm16: (bits & 0xFFFF) as u16,
        },
        EC_SYSREG => EsrClass::SysReg(SysRegAccess {
            op0: ((bits >> 20) & 0b11) as u8,
            op2: ((bits >> 17) & 0b111) as u8,
            op1: ((bits >> 14) & 0b111) as u8,
            crn: ((bits >> 10) & 0xF) as u8,
            rt: GprIndex::from_bits(bits >> 5),
            crm: ((bits >> 1) & 0xF) as u8,
            direction: if bits & 1 == 1 {
                SysRegDirection::Read
            } else {
                SysRegDirection::Write
            },
        }),
        EC_DABT_LOWER => {
            if (bits >> 24) & 1 == 0 {
                return EsrClass::DataAbortUnsupported { iss };
            }
            EsrClass::DataAbort(DataAbort {
                access_size: match (bits >> 22) & 0b11 {
                    0 => AccessSize::Byte,
                    1 => AccessSize::Halfword,
                    2 => AccessSize::Word,
                    _ => AccessSize::Doubleword,
                },
                sign_extend: (bits >> 21) & 1 == 1,
                register: GprIndex::from_bits(bits >> 16),
                sixty_four_bit: (bits >> 15) & 1 == 1,
                acquire_release: (bits >> 14) & 1 == 1,
                direction: if (bits >> 6) & 1 == 1 {
                    AccessDirection::Write
                } else {
                    AccessDirection::Read
                },
                s1ptw: (bits >> 7) & 1 == 1,
                dfsc: (bits & 0x3F) as u8,
                iss,
            })
        }
        _ => EsrClass::Other { ec },
    }
}

#[cfg(test)]
mod tests {
    //! 期待値は Arm ARM のビット位置から手で組んだリテラル（実装の定数は流用しない）。MVM-5・MVM-1。
    use super::*;

    fn dabt(s: u64) -> DataAbort {
        match decode_esr(s) {
            EsrClass::DataAbort(d) => d,
            other => panic!("expected DataAbort, got {other:?}"),
        }
    }

    #[test]
    fn mvm5_esr_data_abort_word_write() {
        let d = dabt(0x9380_0046);
        assert_eq!(d.access_size, AccessSize::Word);
        assert_eq!(d.access_size.bytes(), 4);
        assert!(!d.sign_extend && !d.sixty_four_bit && !d.acquire_release && !d.s1ptw);
        assert_eq!(d.register.get(), 0);
        assert_eq!(d.direction, AccessDirection::Write);
        assert_eq!(d.dfsc, 0x06);
        assert_eq!(d.iss, 0x0180_0046);
        assert_eq!(instruction_length(0x9380_0046), InstructionLength::Four);
        assert_eq!(instruction_length(0x9380_0046).bytes(), 4);
    }

    #[test]
    fn mvm5_esr_data_abort_fields() {
        let b = dabt(0x9300_0006);
        assert_eq!(b.access_size.bytes(), 1);
        assert_eq!(b.direction, AccessDirection::Read);

        let h = dabt(0x9365_0006);
        assert_eq!(h.access_size.bytes(), 2);
        assert!(h.sign_extend);
        assert_eq!(h.register.get(), 5);
        assert!(!h.sixty_four_bit);
        assert_eq!(h.direction, AccessDirection::Read);

        let q = dabt(0x93DE_8046);
        assert_eq!(q.access_size.bytes(), 8);
        assert_eq!(q.register.get(), 30);
        assert!(q.sixty_four_bit);
        assert_eq!(q.direction, AccessDirection::Write);

        let z = dabt(0x939F_0046);
        assert_eq!(z.register.get(), 31);
        assert!(z.register.is_zero_register());
        assert_eq!(z.access_size.bytes(), 4);

        assert!(dabt(0x9300_4006).acquire_release);
        let s = dabt(0x9300_0086);
        assert!(s.s1ptw);
        assert_eq!(s.direction, AccessDirection::Read);
    }

    #[test]
    fn mvm5_esr_data_abort_isv0_is_unsupported() {
        assert_eq!(
            decode_esr(0x9200_0046),
            EsrClass::DataAbortUnsupported { iss: 0x46 }
        );
        assert_eq!(instruction_length(0x9200_0046), InstructionLength::Four);
        assert_eq!(instruction_length(0x9000_0046), InstructionLength::Two);
        assert_eq!(instruction_length(0x9000_0046).bytes(), 2);
    }

    #[test]
    fn mvm5_esr_hvc_smc_wfx() {
        assert_eq!(decode_esr(0x5a00_0000), EsrClass::Hvc { imm16: 0 });
        assert_eq!(decode_esr(0x5a00_1234), EsrClass::Hvc { imm16: 0x1234 });
        assert_eq!(decode_esr(0x5e00_0000), EsrClass::Smc { imm16: 0 });
        assert_eq!(decode_esr(0x0600_0000), EsrClass::Wfx(WfxKind::Wfi));
        assert_eq!(decode_esr(0x0600_0001), EsrClass::Wfx(WfxKind::Wfe));
        assert_eq!(decode_esr(0x0600_0002), EsrClass::Wfx(WfxKind::Wfit));
        assert_eq!(decode_esr(0x0600_0003), EsrClass::Wfx(WfxKind::Wfet));
    }

    #[test]
    fn mvm5_esr_sysreg() {
        let expect = |direction| {
            EsrClass::SysReg(SysRegAccess {
                op0: 3,
                op2: 1,
                op1: 3,
                crn: 14,
                rt: GprIndex(3),
                crm: 0,
                direction,
            })
        };
        assert_eq!(decode_esr(0x6232_F861), expect(SysRegDirection::Read));
        assert_eq!(decode_esr(0x6232_F860), expect(SysRegDirection::Write));
    }

    #[test]
    fn mvm5_esr_other_is_fail_closed() {
        assert_eq!(decode_esr(0x5600_0000), EsrClass::Other { ec: 0x15 });
        assert_eq!(decode_esr(0x9600_0046), EsrClass::Other { ec: 0x25 });
        assert_eq!(decode_esr(0x0000_0000), EsrClass::Other { ec: 0x00 });
        assert_eq!(decode_esr(0x4800_0000), EsrClass::Other { ec: 0x12 });
    }

    #[test]
    fn mvm5_esr_upper_bits_ignored() {
        assert_eq!(
            decode_esr(0x0000_001F_5A00_1234),
            EsrClass::Hvc { imm16: 0x1234 }
        );
        assert_eq!(decode_esr(u64::MAX), decode_esr(0x0000_0000_FFFF_FFFF));
    }

    #[test]
    fn mvm5_esr_every_ec_value() {
        for ec in 0u64..64 {
            let s = ec << 26;
            assert_eq!(u64::from(exception_class(s)), ec);
            let known = matches!(ec, 0x01 | 0x16 | 0x17 | 0x18 | 0x24);
            assert_eq!(
                matches!(decode_esr(s), EsrClass::Other { .. }),
                !known,
                "ec={ec:#x}"
            );
        }
    }
}
