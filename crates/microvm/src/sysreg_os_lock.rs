//! OS Lock レジスタ（`OSDLR_EL1`・`OSLAR_EL1`）への write trap の分類と判定（OS 非依存の純粋関数。MVM-5・MVM-1）。
//!
//! 役割: 実 Linux ゲストは起動時に `clear_os_lock`（`msr OSDLR_EL1, x8`）で OS Double Lock を解除し、Hypervisor.framework は
//! この SysReg を trap する（#4037）。ホスト側は何も実装しないため、値が 0（ロック解除）の write だけ「何もせず PC を進める」。
//! `hvf_loop::run_loop_exit` が [`is_accepted_sysreg`] で受ける trap だけを `dispatch` へ回し、`hvf::vcpu` の
//! `dispatch` が `hvf::sysreg` のハンドラ経由で [`os_lock_write_next_pc`] を使う。分類は符号化と向きだけで決まり、値は
//! ハンドラが vCPU から読む。
//!
//! # 契約
//! - 受けるのは `OSDLR_EL1`（op0=2 op1=0 crn=1 crm=3 op2=4）と `OSLAR_EL1`（op0=2 op1=0 crn=1 crm=0 op2=4）の write だけ。
//!   read・他のレジスタ（近い符号化を含む）は受けず、`run_loop_exit` が従来どおり `Failed(Unimplemented)` で止める。
//! - 値が 0 以外の write は `Unimplemented` で止める（ロックを実際に掛ける挙動はモデル化しない。fail-closed）。
//! - 状態は持たない。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::{SysRegAccess, SysRegDirection};
use crate::mmio_abort::next_pc;

/// 受ける OS Lock レジスタ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsLockReg {
    /// `OSDLR_EL1`（OS Double Lock Register）。
    Osdlr,
    /// `OSLAR_EL1`（OS Lock Access Register）。
    Oslar,
}

/// SysReg trap が OS Lock レジスタの write なら、その種別を返す（符号化と向きのみで決まる）。
pub fn classify_os_lock_write(a: &SysRegAccess) -> Option<OsLockReg> {
    if a.direction != SysRegDirection::Write || (a.op0, a.op1, a.crn, a.op2) != (2, 0, 1, 4) {
        return None;
    }
    match a.crm {
        3 => Some(OsLockReg::Osdlr),
        0 => Some(OsLockReg::Oslar),
        _ => None,
    }
}

/// `run_loop_exit` が `dispatch` へ回してよい SysReg trap か（受けるのは OS Lock の write だけ）。
pub fn is_accepted_sysreg(a: &SysRegAccess) -> bool {
    classify_os_lock_write(a).is_some()
}

/// OS Lock の write を受理し、続行する PC（命令長だけ進めた値）を返す。
///
/// `value` は書かれた値（rt=31 は 0）。0 以外、または OS Lock の write でない場合は `Unimplemented`。
/// PC の桁あふれは `Internal`（`next_pc` の契約）。
pub fn os_lock_write_next_pc(
    a: &SysRegAccess,
    value: u64,
    pc: u64,
    syndrome: u64,
) -> Result<u64, MicrovmError> {
    if classify_os_lock_write(a).is_none() {
        return Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "sysreg access is not an os lock register write",
        ));
    }
    if value != 0 {
        return Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "os lock register write with a non-zero value is not supported",
        ));
    }
    next_pc(pc, syndrome)
}

#[cfg(test)]
mod tests {
    //! ESR は Arm ARM の ISS の配置（op0=21:20・op2=19:17・op1=16:14・crn=13:10・rt=9:5・crm=4:1・dir=0）から組んだ値。
    //! 0x6228_0506 = EC 0x18・IL・OSDLR_EL1 の write・rt=8（実機で観測した値）。OSLAR_EL1 は crn=1・crm=0 で
    //! rt=0 のとき 0x6228_0400（crn の bit 10 が立つ）。MVM-5・MVM-1。
    use super::*;
    use crate::esr::{EsrClass, decode_esr};

    const OSDLR_X8: u64 = 0x6228_0506;
    const OSDLR_XZR: u64 = 0x6228_05E6;
    const OSLAR_X0: u64 = 0x6228_0400;
    const OSLAR_XZR: u64 = 0x6228_04E0;

    fn access(esr: u64) -> SysRegAccess {
        match decode_esr(esr) {
            EsrClass::SysReg(a) => a,
            other => panic!("not a sysreg: {other:?}"),
        }
    }

    #[test]
    fn mvm5_4037_classify_accepts_only_the_two_writes() {
        assert_eq!(
            classify_os_lock_write(&access(OSDLR_X8)),
            Some(OsLockReg::Osdlr)
        );
        assert_eq!(
            classify_os_lock_write(&access(OSDLR_XZR)),
            Some(OsLockReg::Osdlr)
        );
        assert_eq!(
            classify_os_lock_write(&access(OSLAR_X0)),
            Some(OsLockReg::Oslar)
        );
        assert_eq!(
            classify_os_lock_write(&access(OSLAR_XZR)),
            Some(OsLockReg::Oslar)
        );
    }

    #[test]
    fn mvm5_4037_classify_rejects_reads_and_neighbours() {
        // 同じ符号化の read（dir bit = 1）。
        assert!(!is_accepted_sysreg(&access(OSDLR_X8 | 1)));
        assert!(!is_accepted_sysreg(&access(OSLAR_X0 | 1)));
        for esr in [
            OSLAR_X0 + (1 << 1),  // crm=1
            OSLAR_X0 + (2 << 1),  // crm=2
            OSDLR_X8 - (1 << 17), // op2=3
            OSDLR_X8 + (1 << 10), // crn=2
            OSDLR_X8 + (1 << 14), // op1=1
            OSDLR_X8 - (1 << 20), // op0=1
            OSDLR_X8 + (1 << 20), // op0=3
            0x623A_38F2,          // crn=14 のタイマ系の write
            0x6200_0000,          // op0=0 の write
        ] {
            assert!(!is_accepted_sysreg(&access(esr)), "esr={esr:#x}");
        }
    }

    #[test]
    fn mvm5_4037_zero_write_advances_pc_by_four() {
        for esr in [OSDLR_X8, OSDLR_XZR, OSLAR_X0, OSLAR_XZR] {
            assert_eq!(
                os_lock_write_next_pc(&access(esr), 0, 0x8008_1000, esr).unwrap(),
                0x8008_1004
            );
        }
    }

    #[test]
    fn mvm5_4037_nonzero_write_and_other_registers_stay_unimplemented() {
        for (esr, v) in [(OSDLR_X8, 1), (OSLAR_X0, u64::MAX)] {
            let e = os_lock_write_next_pc(&access(esr), v, 0x1000, esr).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::Unimplemented);
        }
        let read = OSDLR_X8 | 1;
        let e = os_lock_write_next_pc(&access(read), 0, 0x1000, read).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Unimplemented);
    }

    #[test]
    fn mvm5_4037_pc_overflow_is_internal() {
        let e = os_lock_write_next_pc(&access(OSDLR_X8), 0, u64::MAX - 1, OSDLR_X8).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
    }
}
