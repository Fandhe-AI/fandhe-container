//! SMCCC / PSCI の応答決定（OS 非依存・`unsafe` なし。TASK-192.11・#3794・MVM-5・MVM-1・REPAIR-3）。
//!
//! 役割: arm64 ゲストが HVC（FDT の `psci` ノードは `method = "hvc"`。`arm64_layout.rs`）で呼ぶ PSCI の関数 ID を復号し、
//! X0 へ返す値か VM の停止かを純関数で決める。呼び出し元は macOS の `hvf::hvc`（レジスタの読み書きと PC の扱いはそちらの責務）。
//! KVM の aarch64 でも再利用できるよう OS 依存を持たない。
//!
//! # 契約
//! - 関数 ID は SMCCC（Arm DEN0028）に従い W0 にある。X0 の上位 32 bit は無視する（[`function_id_from_x0`]）。
//!   PSCI_FEATURES の引数（照会する関数 ID）も W1 として同様に切り詰める。
//! - 戻り値は符号つき 32 bit（SUCCESS 0・NOT_SUPPORTED -1・INVALID_PARAMETERS -2・DENIED -3）。X0 へは i64 へ符号拡張した値を書く
//!   （-1 は `0xFFFF_FFFF_FFFF_FFFF`。[`PsciReturn::to_x0`]）。
//! - 32 bit / 64 bit の ID は別物として完全一致で引く。存在しない組み合わせ（例: `0xC400_0008`）は NOT_SUPPORTED で、停止しない。
//! - SMCCC は `HVC #0` だけを使う。imm16 が 0 でない呼び出しは関数 ID を見ず NOT_SUPPORTED で再開する（推測で成功にしない）。
//! - [`PsciAction::SystemOff`] と [`PsciAction::SystemReset`] は区別して返す。ただし `hvf::hvc` はどちらも
//!   `StopReason::GuestShutdown` に写す（再起動は対象外。区別が要る時は `StopReason` へ足し、plugin-microvm の固定名と揃える）。
//! - PSCI_FEATURES は [`is_implemented`] の単一の表から導くため、実処理との不一致は起きない（試験で機械照合する）。
//! - CPU_ON（32 / 64 bit）は NOT_SUPPORTED。HVF のバックエンドは vCPU 1 つだけ（FDT は `cpu@N` を複数出せる。#3864）で、FEATURES も NOT_SUPPORTED を返し一致させる。
//!   vCPU 1..N のスレッドと CPU_ON の実装は後続（REPAIR-3）。
//!   DEN0022 の CPU_ON の戻り値は SUCCESS・INVALID_PARAMETERS・INVALID_ADDRESS・ALREADY_ON・ON_PENDING・INTERNAL_FAILURE・DENIED の認識で、
//!   NOT_SUPPORTED は列挙に無い。これは DEN0022 からの逸脱で、SMP を入れるときに見直す（一次情報での再確認は #3803 の実機記録と合わせて行う）。
//!
//! # 未実装（REPAIR-3）
//! CPU_SUSPEND・CPU_OFF・AFFINITY_INFO・SYSTEM_SUSPEND・SYSTEM_RESET2・SMCCC_VERSION（FDT に `arm,smccc` を出さない）・再起動。
//! PSCI 1.0 の mandatory 関数（CPU_SUSPEND・CPU_OFF・CPU_ON・AFFINITY_INFO 等）を返さないのは逸脱で、将来 SMP・電源管理を入れるときに見直す。

use crate::esr::instruction_length;

/// PSCI_VERSION。
pub const PSCI_FN_VERSION: u32 = 0x8400_0000;
/// CPU_ON（SMC32 の呼び出し規約）。
pub const PSCI_FN_CPU_ON_32: u32 = 0x8400_0003;
/// CPU_ON（SMC64 の呼び出し規約）。
pub const PSCI_FN_CPU_ON_64: u32 = 0xC400_0003;
/// MIGRATE_INFO_TYPE。
pub const PSCI_FN_MIGRATE_INFO_TYPE: u32 = 0x8400_0006;
/// SYSTEM_OFF。
pub const PSCI_FN_SYSTEM_OFF: u32 = 0x8400_0008;
/// SYSTEM_RESET。
pub const PSCI_FN_SYSTEM_RESET: u32 = 0x8400_0009;
/// PSCI_FEATURES。
pub const PSCI_FN_FEATURES: u32 = 0x8400_000A;
/// SMCCC_VERSION（SMCCC 1.1 以降。応答しない）。
pub const SMCCC_FN_VERSION: u32 = 0x8000_0000;

/// SUCCESS。
pub const PSCI_RET_SUCCESS: i32 = 0;
/// NOT_SUPPORTED。
pub const PSCI_RET_NOT_SUPPORTED: i32 = -1;
/// PSCI 1.0（上位 16 bit がメジャー、下位 16 bit がマイナー）。
pub const PSCI_VERSION_1_0: u32 = 0x0001_0000;
/// MIGRATE_INFO_TYPE の「Trusted OS なし（マイグレーション不要）」。
pub const MIGRATE_INFO_TYPE_NOT_PRESENT: u32 = 2;

/// 実装した（NOT_SUPPORTED 以外を返す）関数 ID の唯一の表。PSCI_FEATURES はここから導く。
const IMPLEMENTED: [u32; 5] = [
    PSCI_FN_VERSION,
    PSCI_FN_FEATURES,
    PSCI_FN_MIGRATE_INFO_TYPE,
    PSCI_FN_SYSTEM_OFF,
    PSCI_FN_SYSTEM_RESET,
];

/// 復号した PSCI の関数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PsciFunction {
    /// PSCI_VERSION。
    Version,
    /// PSCI_FEATURES。
    Features,
    /// MIGRATE_INFO_TYPE。
    MigrateInfoType,
    /// SYSTEM_OFF。
    SystemOff,
    /// SYSTEM_RESET。
    SystemReset,
    /// CPU_ON（32 bit）。
    CpuOn32,
    /// CPU_ON（64 bit）。
    CpuOn64,
    /// SMCCC_VERSION。
    SmcccVersion,
    /// 上記以外（NOT_SUPPORTED になる）。
    Other(u32),
}

/// 関数 ID を完全一致で復号する。
pub fn decode_function(id: u32) -> PsciFunction {
    match id {
        PSCI_FN_VERSION => PsciFunction::Version,
        PSCI_FN_FEATURES => PsciFunction::Features,
        PSCI_FN_MIGRATE_INFO_TYPE => PsciFunction::MigrateInfoType,
        PSCI_FN_SYSTEM_OFF => PsciFunction::SystemOff,
        PSCI_FN_SYSTEM_RESET => PsciFunction::SystemReset,
        PSCI_FN_CPU_ON_32 => PsciFunction::CpuOn32,
        PSCI_FN_CPU_ON_64 => PsciFunction::CpuOn64,
        SMCCC_FN_VERSION => PsciFunction::SmcccVersion,
        other => PsciFunction::Other(other),
    }
}

/// X0 から関数 ID（W0）を取り出す。上位 32 bit は捨てる。
pub fn function_id_from_x0(x0: u64) -> u32 {
    (x0 & 0xFFFF_FFFF) as u32
}

/// 関数 ID が NOT_SUPPORTED 以外を返す実装済みか（PSCI_FEATURES の根拠）。
pub fn is_implemented(id: u32) -> bool {
    IMPLEMENTED.contains(&id)
}

/// X0 へ返す値（符号つき 32 bit を i64 に符号拡張して保持する）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsciReturn(i64);

impl PsciReturn {
    /// 符号つきの PSCI 戻りコード（0・-1 等）から作る。
    pub fn from_code(code: i32) -> Self {
        Self(i64::from(code))
    }

    /// 符号なしの値（VERSION・MIGRATE_INFO_TYPE 等の正の値）から作る。
    pub fn from_value(value: u32) -> Self {
        Self(i64::from(value))
    }

    /// X0 へ書く 64 bit 値（負数は符号拡張）。
    pub fn to_x0(self) -> u64 {
        self.0 as u64
    }
}

/// 呼び出しへの応答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PsciAction {
    /// X0 へ値を書いて再開する。
    Return(PsciReturn),
    /// SYSTEM_OFF。VM を止める。
    SystemOff,
    /// SYSTEM_RESET。再起動は対象外のため呼び出し側が停止に写す。
    SystemReset,
}

/// NOT_SUPPORTED。
pub fn not_supported() -> PsciReturn {
    PsciReturn::from_code(PSCI_RET_NOT_SUPPORTED)
}

/// SMC の trap への応答（FDT は HVC 方式のため常に NOT_SUPPORTED）。
pub fn smc_return() -> PsciReturn {
    not_supported()
}

/// HVC の呼び出し（imm16・X0・X1）への応答を決める。ゲスト由来の untrusted な値を表引きするだけで、アドレスとしては解釈しない。
pub fn handle_call(imm16: u16, x0: u64, x1: u64) -> PsciAction {
    if imm16 != 0 {
        return PsciAction::Return(not_supported());
    }
    match decode_function(function_id_from_x0(x0)) {
        PsciFunction::Version => PsciAction::Return(PsciReturn::from_value(PSCI_VERSION_1_0)),
        PsciFunction::Features => {
            let code = if is_implemented(function_id_from_x0(x1)) {
                PSCI_RET_SUCCESS
            } else {
                PSCI_RET_NOT_SUPPORTED
            };
            PsciAction::Return(PsciReturn::from_code(code))
        }
        PsciFunction::MigrateInfoType => {
            PsciAction::Return(PsciReturn::from_value(MIGRATE_INFO_TYPE_NOT_PRESENT))
        }
        PsciFunction::SystemOff => PsciAction::SystemOff,
        PsciFunction::SystemReset => PsciAction::SystemReset,
        PsciFunction::CpuOn32
        | PsciFunction::CpuOn64
        | PsciFunction::SmcccVersion
        | PsciFunction::Other(_) => PsciAction::Return(not_supported()),
    }
}

/// trap した SMC の戻り先 PC（SMC 自身の次の命令）。溢れたら `None`。
///
/// SMC は preferred return address が SMC 自身のため、命令長（IL）だけ進める。HVC は進めない（`hvf::hvc` の doc 参照）。
pub fn pc_after_trapped_smc(pc: u64, syndrome: u64) -> Option<u64> {
    pc.checked_add(instruction_length(syndrome).bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: u64 = 0xFFFF_FFFF_FFFF_FFFF;

    fn call(id: u64) -> PsciAction {
        handle_call(0, id, 0)
    }

    fn ret(v: u64) -> PsciAction {
        PsciAction::Return(PsciReturn(v as i64))
    }

    /// MVM-5・MVM-1・TASK-192.11: VERSION は 1.0。
    #[test]
    fn mvm5_3794_version_is_1_0() {
        assert_eq!(call(0x8400_0000), ret(0x0001_0000));
    }

    #[test]
    fn mvm5_3794_features_implemented_are_zero() {
        for id in [
            0x8400_0000u64,
            0x8400_000A,
            0x8400_0008,
            0x8400_0009,
            0x8400_0006,
        ] {
            assert_eq!(handle_call(0, 0x8400_000A, id), ret(0), "{id:#x}");
        }
    }

    #[test]
    fn mvm5_3794_features_unimplemented_are_not_supported() {
        for id in [
            0x8400_0003u64,
            0xC400_0003,
            0x8000_0000,
            0x8400_00ff,
            0xC400_0001,
            0x8400_0002,
            0xC400_0008,
        ] {
            assert_eq!(handle_call(0, 0x8400_000A, id), ret(NS), "{id:#x}");
        }
    }

    /// FEATURES と実処理の一致（REPAIR-12）。
    #[test]
    fn mvm5_3794_features_agree_with_handle_call() {
        for id in IMPLEMENTED {
            assert!(is_implemented(id));
            assert_ne!(
                handle_call(0, u64::from(id), u64::from(PSCI_FN_VERSION)),
                ret(NS),
                "{id:#x}"
            );
        }
        for id in [
            0x8400_0001u32,
            0xC400_0001,
            0x8400_0002,
            0x8400_0003,
            0xC400_0003,
            0x8400_0004,
            0xC400_0004,
            0x8000_0000,
            0x8400_00ff,
            0xC400_0000,
            0xC400_0008,
            0xC400_0009,
        ] {
            assert!(!is_implemented(id), "{id:#x}");
            assert_eq!(call(u64::from(id)), ret(NS), "{id:#x}");
            assert_eq!(handle_call(0, 0x8400_000A, u64::from(id)), ret(NS));
        }
    }

    #[test]
    fn mvm5_3794_system_off_and_reset_are_distinguished() {
        assert_eq!(call(0x8400_0008), PsciAction::SystemOff);
        assert_eq!(call(0x8400_0009), PsciAction::SystemReset);
    }

    #[test]
    fn mvm5_3794_migrate_info_type_is_2() {
        assert_eq!(call(0x8400_0006), ret(2));
    }

    #[test]
    fn mvm5_3794_width_variants_do_not_alias() {
        assert_eq!(call(0xC400_0000), ret(NS));
        assert_eq!(call(0xC400_0008), ret(NS));
        assert_eq!(call(0xC400_0009), ret(NS));
    }

    #[test]
    fn mvm5_3794_upper_bits_of_x0_are_ignored() {
        assert_eq!(call(0xFFFF_FFFF_8400_0000), ret(0x0001_0000));
        assert_eq!(call(0x0000_0001_8400_0008), PsciAction::SystemOff);
    }

    #[test]
    fn mvm5_3794_nonzero_imm16_is_not_supported() {
        assert_eq!(handle_call(1, 0x8400_0008, 0), ret(NS));
        assert_eq!(handle_call(0xffff, 0x8400_0000, 0), ret(NS));
    }

    #[test]
    fn mvm5_3794_return_sign_extends() {
        assert_eq!(PsciReturn::from_code(-1).to_x0(), u64::MAX);
        assert_eq!(PsciReturn::from_code(-2).to_x0(), 0xFFFF_FFFF_FFFF_FFFE);
        assert_eq!(PsciReturn::from_value(0x0001_0000).to_x0(), 0x0001_0000);
        assert_eq!(smc_return().to_x0(), u64::MAX);
    }

    #[test]
    fn mvm5_3794_pc_after_trapped_smc() {
        let il4 = 0x5e00_0000u64;
        assert_eq!(pc_after_trapped_smc(0x4000_0100, il4), Some(0x4000_0104));
        assert_eq!(
            pc_after_trapped_smc(0x4000_0100, 0x5c00_0000),
            Some(0x4000_0102)
        );
        assert_eq!(pc_after_trapped_smc(u64::MAX - 1, il4), None);
    }
}
