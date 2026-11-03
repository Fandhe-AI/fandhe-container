//! 公開 ESR API（`esr::decode_esr` ほか）だけを使う結合試験（TASK-192.8・#3785・MVM-5・MVM-1）。
//! KVM・macOS 実機に依存しない。期待値は Arm ARM のビット位置から手で組んだリテラル。

use fandhe_container_microvm::esr::{
    AccessDirection, AccessSize, EsrClass, InstructionLength, SysRegDirection, WfxKind, decode_esr,
    exception_class, instruction_length,
};

#[test]
fn mvm5_esr_public_api_data_abort_word_write() {
    let s = 0x9380_0046;
    assert_eq!(exception_class(s), 0x24);
    assert_eq!(instruction_length(s), InstructionLength::Four);
    match decode_esr(s) {
        EsrClass::DataAbort(d) => {
            assert_eq!(d.access_size, AccessSize::Word);
            assert_eq!(d.direction, AccessDirection::Write);
            assert_eq!(d.register.get(), 0);
            assert_eq!(d.dfsc, 0x06);
            assert_eq!(d.iss, 0x0180_0046);
        }
        other => panic!("expected DataAbort, got {other:?}"),
    }
}

#[test]
fn mvm5_esr_public_api_hvc_wfx_sysreg() {
    assert_eq!(decode_esr(0x5A00_1234), EsrClass::Hvc { imm16: 0x1234 });
    // 上位 32 bit（RES0 / ISS2）は分類に影響しない。
    assert_eq!(
        decode_esr(0xFFFF_FFFF_5A00_1234),
        EsrClass::Hvc { imm16: 0x1234 }
    );
    assert_eq!(decode_esr(0x0600_0000), EsrClass::Wfx(WfxKind::Wfi));
    assert_eq!(decode_esr(0x0600_0001), EsrClass::Wfx(WfxKind::Wfe));
    match decode_esr(0x6230_0441) {
        EsrClass::SysReg(a) => {
            assert_eq!((a.op0, a.op1, a.op2), (3, 0, 0));
            assert_eq!((a.crn, a.crm), (1, 0));
            assert_eq!(a.rt.get(), 2);
            assert_eq!(a.direction, SysRegDirection::Read);
        }
        other => panic!("expected SysReg, got {other:?}"),
    }
}

#[test]
fn mvm5_esr_public_api_unsupported_is_fail_closed() {
    // EC 0x24 で ISV=0: 自前デコードせず DataAbortUnsupported。
    assert_eq!(
        decode_esr(0x9200_0006),
        EsrClass::DataAbortUnsupported { iss: 0x06 }
    );
    // 未知の EC 0x20 は Other。
    assert_eq!(decode_esr(0x8200_0000), EsrClass::Other { ec: 0x20 });
    assert_eq!(decode_esr(0), EsrClass::Other { ec: 0 });
}
