//! macOS の MMIO（ISV=1 の data abort）を `VcpuExit::Mmio` へ写す純関数群
//! （TASK-192.10・#3793・MVM-5・MVM-1。OS 非依存・`unsafe` なし）。
//!
//! 役割: `hvf::mmio::handle_data_abort`（macOS かつ aarch64 のみ）から呼ばれ、復号済みの [`DataAbort`] と IPA を
//! Linux 版と共有する `ExitDispatcher::dispatch`（`dispatch` モジュール）の入力 `VcpuExit::Mmio` へ変換し、
//! 応答を転送レジスタ（SRT）へ書く値と PC の更新値へ戻す。`hv_*` を呼ばないため Linux の PR CI でも単体試験が走る（REPAIR-12）。
//!
//! # 契約
//! - KVM の aarch64 は MMIO の符号拡張をカーネルが行うが、Hypervisor.framework は行わない。本モジュールの
//!   符号拡張（SSE）・32 bit への切り詰め（SF=0）は macOS 専用の規則である。
//! - SRT=31 は XZR（SP ではない）。書き込みの値は 0、読み出しはレジスタを書かない。
//! - 外部（ゲスト）由来の値は信頼しない。幅は SAS で 1 / 2 / 4 / 8 に限られ、応答長が幅と食い違えば fail-closed。
//!
//! # 未実装（REPAIR-3）
//! ゲストが big-endian（`SCTLR_EL1.EE` / `E0E`）の場合は扱わず、little-endian 固定とする。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::{self, AccessDirection, DataAbort};
use crate::exit::VcpuExit;

fn internal(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, msg)
}

/// 書き込みで SRT から読んだレジスタ値を、データへ入れる値にする。XZR は常に 0（`reg_value` は無視）。
pub fn write_source_value(abort: &DataAbort, reg_value: Option<u64>) -> u64 {
    if abort.register.is_zero_register() {
        0
    } else {
        reg_value.unwrap_or(0)
    }
}

/// 復号済みの data abort から `VcpuExit::Mmio` を作る。
///
/// `write_value` は書き込みの値（読み出しでは無視）。幅より上位のバイトは捨てる。
pub fn mmio_exit_from_abort(abort: &DataAbort, ipa: u64, write_value: u64) -> VcpuExit {
    let len = abort.access_size.bytes();
    let is_write = abort.direction == AccessDirection::Write;
    let mut data = [0u8; 8];
    if is_write {
        let bytes = write_value.to_le_bytes();
        for (dst, src) in data.iter_mut().zip(bytes.iter()).take(len) {
            *dst = *src;
        }
    }
    VcpuExit::Mmio {
        phys_addr: ipa,
        data,
        // `len` は 1..=8（AccessSize の網羅）なので変換は失敗しない。
        len: u32::try_from(len).unwrap_or(8),
        is_write,
    }
}

/// 読み出しの応答を SRT へ書く値にする。XZR なら `Ok(None)`（書かない）。
///
/// 応答長が幅と違えば `Internal`。符号拡張（SSE）の後、SF=0（W レジスタ）なら下位 32 bit に切る。
pub fn read_register_value(
    abort: &DataAbort,
    response: &[u8],
) -> Result<Option<u64>, MicrovmError> {
    let len = abort.access_size.bytes();
    if response.len() != len {
        return Err(internal("mmio response length differs from access width"));
    }
    if abort.register.is_zero_register() {
        return Ok(None);
    }
    let mut raw: u64 = 0;
    for (i, b) in response.iter().enumerate() {
        let shift = u32::try_from(i)
            .ok()
            .and_then(|i| i.checked_mul(8))
            .ok_or_else(|| internal("mmio response shift overflow"))?;
        raw |= u64::from(*b) << shift;
    }
    let bits = u32::try_from(len)
        .ok()
        .and_then(|l| l.checked_mul(8))
        .ok_or_else(|| internal("mmio width overflow"))?;
    let mut value = raw;
    if abort.sign_extend && bits < 64 {
        let sign = 1u64 << (bits - 1);
        if raw & sign != 0 {
            value = raw | (u64::MAX << bits);
        }
    }
    if !abort.sixty_four_bit {
        value &= 0xffff_ffff;
    }
    Ok(Some(value))
}

/// data abort を MMIO として扱ってよいか検査する（MVM-5・MVM-1・fail-closed）。
///
/// MMIO 窓は stage-2 に未マップなので、正当な MMIO の abort は translation fault（DFSC 0b0001LL、
/// level 0..=3）だけである。S1PTW 付き、および permission fault・access flag fault 等
/// （例: 読み取り専用で登録した RAM への書き込み）は MMIO として握りつぶさず `FailedPrecondition` で止める。
pub fn ensure_mmio_fault(abort: &DataAbort) -> Result<(), MicrovmError> {
    if abort.s1ptw {
        return Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "data abort during stage-1 page table walk is not emulated",
        ));
    }
    if !(0x04..=0x07).contains(&abort.dfsc) {
        return Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            format!(
                "data abort is not a stage-2 translation fault (dfsc=0x{:02x}); not emulated as mmio",
                abort.dfsc
            ),
        ));
    }
    Ok(())
}

/// faulting 命令の次の PC。命令長は ESR の IL。桁あふれは `Internal`（wrap しない）。
pub fn next_pc(pc: u64, syndrome: u64) -> Result<u64, MicrovmError> {
    pc.checked_add(esr::instruction_length(syndrome).bytes())
        .ok_or_else(|| internal("pc overflows when skipping the faulting instruction"))
}

#[cfg(test)]
mod tests {
    //! syndrome は Arm ARM のビット位置から手で組んだリテラル。
    //! 0x9300_0006 = EC 0x24(31:26)・IL(25)・ISV(24)・DFSC 0x06。SAS=bit23:22、SSE=bit21、SRT=bit20:16、SF=bit15、WnR=bit6。
    //! MVM-5・MVM-1。
    use super::*;
    use crate::dispatch::ExitDispatcher;
    use crate::esr::{EsrClass, decode_esr};
    use crate::virtio_block::{MemoryBlockBackend, VirtioBlock};
    use crate::virtio_mmio::VirtioMmioTransport;

    fn dabt(s: u64) -> DataAbort {
        match decode_esr(s) {
            EsrClass::DataAbort(d) => d,
            other => panic!("expected DataAbort, got {other:?}"),
        }
    }

    #[test]
    fn mvm5_mmio_fault_allows_translation_faults_only() {
        // DFSC 0x04..=0x07（translation fault level 0..=3）は MMIO として許可する。
        for dfsc in 0x04..=0x07u64 {
            assert!(ensure_mmio_fault(&dabt(0x9300_0000 | dfsc)).is_ok());
        }
        // permission fault（level 3 = 0x0f。READ のみ登録の RAM への書き込み）は拒否する。
        let e = ensure_mmio_fault(&dabt(0x9300_004f)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        // access flag fault（0x09）・alignment（0x21）・synchronous external abort（0x10）も拒否する。
        for dfsc in [0x09u64, 0x10, 0x21, 0x00, 0x08, 0x0c] {
            let e = ensure_mmio_fault(&dabt(0x9300_0000 | dfsc)).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        }
        // S1PTW（bit 7）付きは translation fault でも拒否する。
        let e = ensure_mmio_fault(&dabt(0x9300_0086)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
    }

    #[test]
    fn mvm5_mmio_abort_byte_sign_extension() {
        // SAS=0・SSE=1・SRT=1・SF=1。
        let a = dabt(0x9321_8006);
        assert_eq!(
            read_register_value(&a, &[0x80]).unwrap(),
            Some(0xffff_ffff_ffff_ff80)
        );
        // SSE=1・SF=0: W レジスタなので上位 32 bit は 0。
        let b = dabt(0x9321_0006);
        assert_eq!(
            read_register_value(&b, &[0x80]).unwrap(),
            Some(0x0000_0000_ffff_ff80)
        );
        // SSE=0・SF=1。
        let c = dabt(0x9301_8006);
        assert_eq!(read_register_value(&c, &[0x80]).unwrap(), Some(0x80));
        // 正の値は符号拡張しても変わらない。
        assert_eq!(read_register_value(&a, &[0x7f]).unwrap(), Some(0x7f));
    }

    #[test]
    fn mvm5_mmio_abort_halfword_and_doubleword() {
        // SAS=1・SSE=1・SRT=1・SF=1。
        let h = dabt(0x9361_8006);
        assert_eq!(
            read_register_value(&h, &[0x00, 0x80]).unwrap(),
            Some(0xffff_ffff_ffff_8000)
        );
        // SAS=3・SSE=1: 8 バイトは拡張の余地がない。
        let d = dabt(0x93E1_8006);
        let resp = 0x8000_0000_0000_0001u64.to_le_bytes();
        assert_eq!(
            read_register_value(&d, &resp).unwrap(),
            Some(0x8000_0000_0000_0001)
        );
        // SAS=2・SSE=0・SF=0 の 4 バイト。
        let w = dabt(0x9381_0006);
        assert_eq!(
            read_register_value(&w, &0xdead_beefu32.to_le_bytes()).unwrap(),
            Some(0xdead_beef)
        );
    }

    #[test]
    fn mvm5_mmio_abort_xzr() {
        // 読み出し（SAS=2・SRT=31・WnR=0）はレジスタを書かない。
        let r = dabt(0x939F_0006);
        assert_eq!(read_register_value(&r, &[0, 0, 0, 0]).unwrap(), None);
        // 書き込み（SAS=2・SRT=31・WnR=1）は値 0。
        let w = dabt(0x939F_0046);
        let v = write_source_value(&w, Some(0xffff_ffff_ffff_ffff));
        assert_eq!(v, 0);
        let VcpuExit::Mmio {
            data,
            len,
            is_write,
            ..
        } = mmio_exit_from_abort(&w, 0x0a00_0000, v)
        else {
            panic!("expected Mmio");
        };
        assert_eq!((data, len, is_write), ([0u8; 8], 4, true));
        // XZR 以外は値をそのまま使う。
        let n = dabt(0x9381_8046);
        assert_eq!(write_source_value(&n, Some(7)), 7);
    }

    #[test]
    fn mvm5_mmio_abort_write_truncates_to_width() {
        // SAS=1・SRT=1・WnR=1。
        let a = dabt(0x9341_8046);
        let VcpuExit::Mmio {
            phys_addr,
            data,
            len,
            is_write,
        } = mmio_exit_from_abort(&a, 0x0a00_0050, 0x1122_3344_5566_7788)
        else {
            panic!("expected Mmio");
        };
        assert_eq!(phys_addr, 0x0a00_0050);
        assert_eq!(data, [0x88, 0x77, 0, 0, 0, 0, 0, 0]);
        assert_eq!(len, 2);
        assert!(is_write);
        // 読み出しは data が全 0。
        let r = dabt(0x9381_0006);
        let VcpuExit::Mmio {
            data,
            len,
            is_write,
            ..
        } = mmio_exit_from_abort(&r, 0, 0xffff)
        else {
            panic!("expected Mmio");
        };
        assert_eq!((data, len, is_write), ([0u8; 8], 4, false));
    }

    #[test]
    fn mvm5_mmio_abort_rejects_response_length_mismatch() {
        let w = dabt(0x9381_0006);
        let e = read_register_value(&w, &[1, 2]).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        assert!(read_register_value(&w, &[]).is_err());
    }

    #[test]
    fn mvm5_mmio_abort_next_pc() {
        // IL=1 は +4。
        assert_eq!(next_pc(0x4000_0000, 0x9300_0006).unwrap(), 0x4000_0004);
        // IL=0（bit 25 = 0）は +2。
        assert_eq!(next_pc(0x4000_0000, 0x0400_0000).unwrap(), 0x4000_0002);
        let e = next_pc(u64::MAX - 1, 0x9300_0006).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
    }

    #[test]
    fn mvm5_mmio_abort_reaches_virtio_mmio_and_unhandled() {
        let mut d = ExitDispatcher::new();
        let dev = VirtioMmioTransport::new(VirtioBlock::new(
            MemoryBlockBackend::new(16 * 512, false).unwrap(),
        ))
        .unwrap();
        d.register_mmio(0x0a00_0000, 0x200, Box::new(dev)).unwrap();
        // 4 バイトの読み出し（SF=0・SRT=1）で MagicValue。
        let a = dabt(0x9381_0006);
        let exit = mmio_exit_from_abort(&a, 0x0a00_0000, 0);
        let out = d.dispatch(&exit).unwrap();
        let resp = out.read_response().unwrap();
        assert_eq!(read_register_value(&a, resp).unwrap(), Some(0x7472_6976));
        // 未登録のアドレスは全バイト 0xFF。
        let exit = mmio_exit_from_abort(&a, 0x0b00_0000, 0);
        let out = d.dispatch(&exit).unwrap();
        let resp = out.read_response().unwrap();
        assert_eq!(read_register_value(&a, resp).unwrap(), Some(0xffff_ffff));
    }
}
