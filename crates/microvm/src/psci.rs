//! SMCCC / PSCI の応答決定と vCPU 電源状態機械（OS 非依存・`unsafe` なし。TASK-192.11・#3794・#3883・MVM-5・MVM-1・REPAIR-3）。
//!
//! 役割: arm64 ゲストが HVC（FDT の `psci` ノードは `method = "hvc"`。`arm64_layout.rs`）で呼ぶ PSCI の関数 ID を復号し、
//! X0 へ返す値か VM の停止かを決める。vCPU ごとの電源状態（[`PsciCpus`]）と、実際の起動・停止の境界（[`CpuPowerControl`]）を持つ。
//! 呼び出し元は macOS の `hvf::hvc`（レジスタの読み書きと PC の扱いはそちらの責務）。KVM の aarch64 でも再利用できるよう OS 依存を持たない。
//!
//! # 契約
//! - 関数 ID は SMCCC（Arm DEN0028）に従い W0 にある。X0 の上位 32 bit は無視する（[`function_id_from_x0`]）。
//!   PSCI_FEATURES の引数（照会する関数 ID）も W1 として同様に切り詰める。SMC32 の関数の引数（CPU_ON の W1〜W3 等）も下位 32 bit に切り詰める。
//! - 戻り値は符号つき 32 bit（SUCCESS 0・NOT_SUPPORTED -1・INVALID_PARAMETERS -2・DENIED -3・ALREADY_ON -4・ON_PENDING -5・
//!   INTERNAL_FAILURE -6・INVALID_ADDRESS -9）。X0 へは i64 へ符号拡張した値を書く（-1 は `0xFFFF_FFFF_FFFF_FFFF`。[`PsciReturn::to_x0`]）。
//! - 32 bit / 64 bit の ID は別物として完全一致で引く。存在しない組み合わせ（例: `0xC400_0008`、CPU_OFF の SMC64 版）は NOT_SUPPORTED で、停止しない。
//! - SMCCC は `HVC #0` だけを使う。imm16 が 0 でない呼び出しは関数 ID を見ず NOT_SUPPORTED で再開する（推測で成功にしない）。
//! - [`PsciAction::SystemOff`] と [`PsciAction::SystemReset`] は区別して返す。ただし `hvf::hvc` はどちらも
//!   `StopReason::GuestShutdown` に写す（再起動は対象外。区別が要る時は `StopReason` へ足し、plugin-microvm の固定名と揃える）。
//! - PSCI_FEATURES は [`is_implemented`] の単一の表から導くため、実処理との不一致は起きない（試験で機械照合する）。
//! - `Err` は VMM 側の不変条件違反（caller の範囲外・状態の符号の破損）だけに使う。ゲスト由来の値の誤りは常に PSCI の戻り値で返す。
//!
//! # 電源状態機械（#3883）
//! vCPU 0 は ON、他は OFF で始まる。CPU_ON は compare_exchange で OFF→ON_PENDING に進めた呼び出しだけが [`CpuPowerControl::power_on`] を呼ぶ
//! （同じ対象への二重起動を防ぐ）。起動が失敗したら OFF へ戻す。ON_PENDING→ON は対象 vCPU が実行を始めた時点で
//! 後続 #3891 の AP スレッドが [`PsciCpus::confirm_on`] で刻む。CPU_OFF は呼び出し元自身にしか効かず、成功したら OFF にして
//! [`PsciAction::CpuOff`] を返す。OFF にしてから実際に parked になるまでの窓の扱いは #3891 の責務。
//! 対象の指定（target_cpu）は MPIDR の affinity 形式（Aff3 は bit 39:32、Aff2..0 は bit 23:0、他は MBZ）で、
//! MBZ ビットが立つ値と存在しない vCPU は INVALID_PARAMETERS。entry の妥当性（ゲスト RAM 内か）は純粋層が知らないため
//! [`CpuPowerControl`] 側が [`PowerControlError::InvalidAddress`] で返す。
//!
//! # 一次情報の確認状況（REPAIR-3）
//! 数値の戻り値は Linux の `include/uapi/linux/psci.h`（二次情報）と突き合わせた。DEN0022 / DEN0028 の本文（版・節・表の番号）は
//! 実装時に一次情報へ到達できなかった（Arm の文書ページは本文を取得できない）ため、**版・節・表の番号は未確認**で、
//! 上記の target_cpu の MBZ と AFFINITY_INFO の `lowest_affinity_level != 0` を INVALID_PARAMETERS とする扱いも一次情報で未照合。
//! 一次情報で確認したら、ここへ版・節・表の番号を書き、食い違えば直す（#3883 の受け入れ条件 1 の残り）。
//!
//! # 未実装（REPAIR-3）
//! CPU_SUSPEND・SYSTEM_SUSPEND・SYSTEM_RESET2・SMCCC_VERSION（FDT に `arm,smccc` を出さない）・再起動。
//! PSCI 1.0 の mandatory 関数のうち CPU_SUSPEND を返さないのは DEN0022 からの逸脱（表番号は未確認）で、電源管理を入れるときに見直す。
//! HVF での AP の実起動と CPU_OFF 後の parked への戻しは #3891。

use std::sync::atomic::{AtomicU8, Ordering};

use crate::arm64_layout::{ARM64_MAX_VCPUS, arm64_vcpu_mpidr_affinity};
use crate::boot_arm64::ARM64_MPIDR_AFFINITY_MASK;
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::instruction_length;

/// PSCI_VERSION。
pub const PSCI_FN_VERSION: u32 = 0x8400_0000;
/// CPU_OFF（SMC32 のみ。SMC64 版は無い）。
pub const PSCI_FN_CPU_OFF: u32 = 0x8400_0002;
/// CPU_ON（SMC32 の呼び出し規約）。
pub const PSCI_FN_CPU_ON_32: u32 = 0x8400_0003;
/// CPU_ON（SMC64 の呼び出し規約）。
pub const PSCI_FN_CPU_ON_64: u32 = 0xC400_0003;
/// AFFINITY_INFO（SMC32）。
pub const PSCI_FN_AFFINITY_INFO_32: u32 = 0x8400_0004;
/// AFFINITY_INFO（SMC64）。
pub const PSCI_FN_AFFINITY_INFO_64: u32 = 0xC400_0004;
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
/// INVALID_PARAMETERS。
pub const PSCI_RET_INVALID_PARAMETERS: i32 = -2;
/// DENIED。
pub const PSCI_RET_DENIED: i32 = -3;
/// ALREADY_ON。
pub const PSCI_RET_ALREADY_ON: i32 = -4;
/// ON_PENDING。
pub const PSCI_RET_ON_PENDING: i32 = -5;
/// INTERNAL_FAILURE。
pub const PSCI_RET_INTERNAL_FAILURE: i32 = -6;
/// INVALID_ADDRESS。
pub const PSCI_RET_INVALID_ADDRESS: i32 = -9;
/// AFFINITY_INFO の ON。
pub const AFFINITY_INFO_ON: u32 = 0;
/// AFFINITY_INFO の OFF。
pub const AFFINITY_INFO_OFF: u32 = 1;
/// AFFINITY_INFO の ON_PENDING。
pub const AFFINITY_INFO_ON_PENDING: u32 = 2;
/// PSCI 1.0（上位 16 bit がメジャー、下位 16 bit がマイナー）。
pub const PSCI_VERSION_1_0: u32 = 0x0001_0000;
/// MIGRATE_INFO_TYPE の「Trusted OS なし（マイグレーション不要）」。
pub const MIGRATE_INFO_TYPE_NOT_PRESENT: u32 = 2;

/// 実装した（NOT_SUPPORTED 以外を返す）関数 ID の唯一の表。PSCI_FEATURES はここから導く。
const IMPLEMENTED: [u32; 10] = [
    PSCI_FN_VERSION,
    PSCI_FN_FEATURES,
    PSCI_FN_MIGRATE_INFO_TYPE,
    PSCI_FN_SYSTEM_OFF,
    PSCI_FN_SYSTEM_RESET,
    PSCI_FN_CPU_ON_32,
    PSCI_FN_CPU_ON_64,
    PSCI_FN_CPU_OFF,
    PSCI_FN_AFFINITY_INFO_32,
    PSCI_FN_AFFINITY_INFO_64,
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
    /// CPU_OFF。
    CpuOff,
    /// AFFINITY_INFO（32 bit）。
    AffinityInfo32,
    /// AFFINITY_INFO（64 bit）。
    AffinityInfo64,
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
        PSCI_FN_CPU_OFF => PsciFunction::CpuOff,
        PSCI_FN_AFFINITY_INFO_32 => PsciFunction::AffinityInfo32,
        PSCI_FN_AFFINITY_INFO_64 => PsciFunction::AffinityInfo64,
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
    /// CPU_OFF が成功した。呼び出し元には戻らないので、呼び出し側は vCPU `index` を parked へ戻す（#3891）。
    CpuOff {
        /// 停止する vCPU の index。
        index: u32,
    },
}

/// NOT_SUPPORTED。
pub fn not_supported() -> PsciReturn {
    PsciReturn::from_code(PSCI_RET_NOT_SUPPORTED)
}

/// SMC の trap への応答（FDT は HVC 方式のため常に NOT_SUPPORTED）。
pub fn smc_return() -> PsciReturn {
    not_supported()
}

/// vCPU の電源状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuPowerState {
    /// 停止中（parked）。
    Off,
    /// CPU_ON を受理し、起動の完了待ち。
    OnPending,
    /// 実行中。
    On,
}

impl CpuPowerState {
    fn to_raw(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::OnPending => 1,
            Self::On => 2,
        }
    }

    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Off),
            1 => Some(Self::OnPending),
            2 => Some(Self::On),
            _ => None,
        }
    }

    /// AFFINITY_INFO が返す値（ON 0・OFF 1・ON_PENDING 2）。
    pub fn affinity_info(self) -> u32 {
        match self {
            Self::On => AFFINITY_INFO_ON,
            Self::Off => AFFINITY_INFO_OFF,
            Self::OnPending => AFFINITY_INFO_ON_PENDING,
        }
    }
}

/// 起動・停止の実処理が返す失敗。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PowerControlError {
    /// entry がゲストのアドレスとして不正（INVALID_ADDRESS）。
    InvalidAddress,
    /// 許可されない（DENIED）。
    Denied,
    /// その他の失敗（INTERNAL_FAILURE）。
    Failed(MicrovmErrorCode),
}

/// vCPU の実際の起動・停止の境界。純粋層はゲストのアドレスを知らないため、entry の妥当性もここで判断する。
///
/// 契約: 呼び出し元 vCPU のスレッドから呼ばれる。実装は他の vCPU への通知だけを行い、長く待たない。
/// 呼び出し側（[`handle_call`]）はロックを握らずに呼ぶ。HVF の実装は #3891。
pub trait CpuPowerControl: Send + Sync {
    /// vCPU `index` を `entry` から `context_id` を X0 に入れて起動する。
    fn power_on(&self, index: u32, entry: u64, context_id: u64) -> Result<(), PowerControlError>;
    /// 呼び出し元の vCPU `index` を停止する。
    fn power_off(&self, index: u32) -> Result<(), PowerControlError>;
}

/// 1 vCPU 構成の既定の実装。1 台では CPU_ON は対象が自分（ALREADY_ON）か存在しない（INVALID_PARAMETERS）ので
/// `power_on` に到達しない。CPU_OFF は parked へ戻す機構が無いので DENIED にする。
#[derive(Debug, Default, Clone, Copy)]
pub struct BootCpuOnly;

impl CpuPowerControl for BootCpuOnly {
    fn power_on(
        &self,
        _index: u32,
        _entry: u64,
        _context_id: u64,
    ) -> Result<(), PowerControlError> {
        Err(PowerControlError::Failed(MicrovmErrorCode::Unimplemented))
    }

    fn power_off(&self, _index: u32) -> Result<(), PowerControlError> {
        Err(PowerControlError::Denied)
    }
}

/// vCPU ごとの電源状態の表。vCPU スレッド間で `Arc` で共有する（ロックを使わず poison が無い）。
#[derive(Debug)]
pub struct PsciCpus {
    affinities: Vec<u64>,
    states: Vec<AtomicU8>,
}

fn invariant(message: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, message)
}

impl PsciCpus {
    /// `vcpus` 台（1..=`ARM64_MAX_VCPUS`）の表を作る。vCPU 0 が ON、残りは OFF。範囲外は `InvalidArgument`。
    pub fn new(vcpus: u32) -> Result<Self, MicrovmError> {
        if vcpus == 0 || vcpus > ARM64_MAX_VCPUS {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "vcpu count out of range",
            ));
        }
        let mut affinities = Vec::with_capacity(vcpus as usize);
        let mut states = Vec::with_capacity(vcpus as usize);
        for i in 0..vcpus {
            affinities.push(u64::from(arm64_vcpu_mpidr_affinity(i)?));
            let s = if i == 0 {
                CpuPowerState::On
            } else {
                CpuPowerState::Off
            };
            states.push(AtomicU8::new(s.to_raw()));
        }
        Ok(Self { affinities, states })
    }

    /// 1 vCPU 構成（失敗しない）。
    pub fn single() -> Self {
        Self {
            affinities: vec![0],
            states: vec![AtomicU8::new(CpuPowerState::On.to_raw())],
        }
    }

    /// vCPU 数。
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// 空か（`new` / `single` では常に偽）。
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// 電源状態。範囲外や破損した符号は `None`。
    pub fn state(&self, index: u32) -> Option<CpuPowerState> {
        let s = self.states.get(index as usize)?;
        CpuPowerState::from_raw(s.load(Ordering::SeqCst))
    }

    /// ON_PENDING→ON を刻む。対象 vCPU が実行を始めた時点で #3891 の AP スレッドが呼ぶ。他の状態は `FailedPrecondition`。
    pub fn confirm_on(&self, index: u32) -> Result<(), MicrovmError> {
        let s = self.slot(index)?;
        s.compare_exchange(
            CpuPowerState::OnPending.to_raw(),
            CpuPowerState::On.to_raw(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .map(|_| ())
        .map_err(|_| {
            MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "vcpu is not on_pending",
            )
        })
    }

    /// target_cpu（MPIDR の affinity 形式）から vCPU の index を引く。MBZ ビットが立つ値は `None`。
    pub fn index_of_target(&self, target: u64) -> Option<u32> {
        if target & !ARM64_MPIDR_AFFINITY_MASK != 0 {
            return None;
        }
        let pos = self.affinities.iter().position(|a| *a == target)?;
        u32::try_from(pos).ok()
    }

    fn slot(&self, index: u32) -> Result<&AtomicU8, MicrovmError> {
        self.states
            .get(index as usize)
            .ok_or_else(|| invariant("vcpu index out of range"))
    }

    fn load(&self, index: u32) -> Result<CpuPowerState, MicrovmError> {
        CpuPowerState::from_raw(self.slot(index)?.load(Ordering::SeqCst))
            .ok_or_else(|| invariant("corrupt cpu power state"))
    }

    fn store(&self, index: u32, s: CpuPowerState) -> Result<(), MicrovmError> {
        self.slot(index)?.store(s.to_raw(), Ordering::SeqCst);
        Ok(())
    }
}

/// HVC の呼び出しのレジスタ（imm16・X0〜X3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PsciArgs {
    /// HVC の即値。
    pub imm16: u16,
    /// X0（関数 ID）。
    pub x0: u64,
    /// X1。
    pub x1: u64,
    /// X2。
    pub x2: u64,
    /// X3。
    pub x3: u64,
}

fn ret(code: i32) -> PsciAction {
    PsciAction::Return(PsciReturn::from_code(code))
}

fn trunc32(v: u64, wide: bool) -> u64 {
    if wide { v } else { v & 0xFFFF_FFFF }
}

fn cpu_on(
    cpus: &PsciCpus,
    power: &dyn CpuPowerControl,
    args: &PsciArgs,
    wide: bool,
) -> Result<PsciAction, MicrovmError> {
    let target = trunc32(args.x1, wide);
    let entry = trunc32(args.x2, wide);
    let ctx = trunc32(args.x3, wide);
    let Some(index) = cpus.index_of_target(target) else {
        return Ok(ret(PSCI_RET_INVALID_PARAMETERS));
    };
    let slot = cpus.slot(index)?;
    if let Err(cur) = slot.compare_exchange(
        CpuPowerState::Off.to_raw(),
        CpuPowerState::OnPending.to_raw(),
        Ordering::SeqCst,
        Ordering::SeqCst,
    ) {
        return match CpuPowerState::from_raw(cur) {
            Some(CpuPowerState::On) => Ok(ret(PSCI_RET_ALREADY_ON)),
            Some(CpuPowerState::OnPending) => Ok(ret(PSCI_RET_ON_PENDING)),
            _ => Err(invariant("corrupt cpu power state")),
        };
    }
    match power.power_on(index, entry, ctx) {
        Ok(()) => Ok(ret(PSCI_RET_SUCCESS)),
        Err(e) => {
            cpus.store(index, CpuPowerState::Off)?;
            Ok(ret(match e {
                PowerControlError::InvalidAddress => PSCI_RET_INVALID_ADDRESS,
                PowerControlError::Denied => PSCI_RET_DENIED,
                PowerControlError::Failed(_) => PSCI_RET_INTERNAL_FAILURE,
            }))
        }
    }
}

fn cpu_off(
    cpus: &PsciCpus,
    power: &dyn CpuPowerControl,
    caller: u32,
) -> Result<PsciAction, MicrovmError> {
    if cpus.load(caller)? != CpuPowerState::On {
        return Err(invariant("cpu_off from a vcpu that is not on"));
    }
    match power.power_off(caller) {
        Ok(()) => {
            cpus.store(caller, CpuPowerState::Off)?;
            Ok(PsciAction::CpuOff { index: caller })
        }
        Err(_) => Ok(ret(PSCI_RET_DENIED)),
    }
}

fn affinity_info(cpus: &PsciCpus, args: &PsciArgs, wide: bool) -> Result<PsciAction, MicrovmError> {
    let target = trunc32(args.x1, wide);
    // lowest_affinity_level は W2。0 以外（クラスタ集約）は扱わない（一次情報で未照合。モジュール doc 参照）。
    if args.x2 & 0xFFFF_FFFF != 0 {
        return Ok(ret(PSCI_RET_INVALID_PARAMETERS));
    }
    let Some(index) = cpus.index_of_target(target) else {
        return Ok(ret(PSCI_RET_INVALID_PARAMETERS));
    };
    let state = cpus.load(index)?;
    Ok(PsciAction::Return(PsciReturn::from_value(
        state.affinity_info(),
    )))
}

/// HVC の呼び出しへの応答を決める。ゲスト由来の untrusted な値を表引きするだけで、アドレスとしては解釈しない。
///
/// `caller` は呼び出し元 vCPU の index。`Err` は VMM 側の不変条件違反のみ（モジュール doc 参照）。
pub fn handle_call(
    cpus: &PsciCpus,
    power: &dyn CpuPowerControl,
    caller: u32,
    args: PsciArgs,
) -> Result<PsciAction, MicrovmError> {
    if cpus.slot(caller).is_err() {
        return Err(invariant("caller vcpu index out of range"));
    }
    if args.imm16 != 0 {
        return Ok(PsciAction::Return(not_supported()));
    }
    match decode_function(function_id_from_x0(args.x0)) {
        PsciFunction::Version => Ok(PsciAction::Return(PsciReturn::from_value(PSCI_VERSION_1_0))),
        PsciFunction::Features => {
            let code = if is_implemented(function_id_from_x0(args.x1)) {
                PSCI_RET_SUCCESS
            } else {
                PSCI_RET_NOT_SUPPORTED
            };
            Ok(ret(code))
        }
        PsciFunction::MigrateInfoType => Ok(PsciAction::Return(PsciReturn::from_value(
            MIGRATE_INFO_TYPE_NOT_PRESENT,
        ))),
        PsciFunction::SystemOff => Ok(PsciAction::SystemOff),
        PsciFunction::SystemReset => Ok(PsciAction::SystemReset),
        PsciFunction::CpuOn32 => cpu_on(cpus, power, &args, false),
        PsciFunction::CpuOn64 => cpu_on(cpus, power, &args, true),
        PsciFunction::CpuOff => cpu_off(cpus, power, caller),
        PsciFunction::AffinityInfo32 => affinity_info(cpus, &args, false),
        PsciFunction::AffinityInfo64 => affinity_info(cpus, &args, true),
        PsciFunction::SmcccVersion | PsciFunction::Other(_) => {
            Ok(PsciAction::Return(not_supported()))
        }
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
    use std::sync::{Barrier, Mutex};

    const NS: u64 = 0xFFFF_FFFF_FFFF_FFFF;

    /// 呼び出しを記録し、結果を差し替えられる偽の電源制御。
    #[derive(Default)]
    struct Fake {
        ons: Mutex<Vec<(u32, u64, u64)>>,
        offs: Mutex<Vec<u32>>,
        on_result: Mutex<Option<PowerControlError>>,
        off_result: Mutex<Option<PowerControlError>>,
    }

    impl CpuPowerControl for Fake {
        fn power_on(&self, i: u32, e: u64, c: u64) -> Result<(), PowerControlError> {
            self.ons.lock().unwrap().push((i, e, c));
            match self.on_result.lock().unwrap().clone() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
        fn power_off(&self, i: u32) -> Result<(), PowerControlError> {
            self.offs.lock().unwrap().push(i);
            match self.off_result.lock().unwrap().clone() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }

    fn args(x0: u64, x1: u64, x2: u64, x3: u64) -> PsciArgs {
        PsciArgs {
            imm16: 0,
            x0,
            x1,
            x2,
            x3,
        }
    }

    fn run(c: &PsciCpus, p: &dyn CpuPowerControl, caller: u32, a: PsciArgs) -> PsciAction {
        handle_call(c, p, caller, a).unwrap()
    }

    fn call(id: u64) -> PsciAction {
        run(&PsciCpus::single(), &BootCpuOnly, 0, args(id, 0, 0, 0))
    }

    fn r(v: u64) -> PsciAction {
        PsciAction::Return(PsciReturn(v as i64))
    }

    fn neg(n: i64) -> PsciAction {
        r(n as u64)
    }

    fn cpu_on64(c: &PsciCpus, p: &Fake, target: u64) -> PsciAction {
        run(c, p, 0, args(0xC400_0003, target, 0x4008_0000, 0xdead_beef))
    }

    fn info(c: &PsciCpus, p: &Fake, target: u64) -> PsciAction {
        run(c, p, 0, args(0xC400_0004, target, 0, 0))
    }

    /// MVM-5・MVM-1・TASK-192.11: VERSION は 1.0。
    #[test]
    fn mvm5_3794_version_is_1_0() {
        assert_eq!(call(0x8400_0000), r(0x0001_0000));
    }

    /// MVM-5・#3883: 実装した 10 件の FEATURES は 0。
    #[test]
    fn mvm5_3794_features_implemented_are_zero() {
        let c = PsciCpus::single();
        for id in IMPLEMENTED {
            assert_eq!(
                run(&c, &BootCpuOnly, 0, args(0x8400_000A, u64::from(id), 0, 0)),
                r(0),
                "{id:#x}"
            );
        }
        assert_eq!(IMPLEMENTED.len(), 10);
    }

    /// FEATURES と実処理の一致（REPAIR-12）。
    #[test]
    fn mvm5_3794_features_agree_with_handle_call() {
        let c = PsciCpus::single();
        for id in IMPLEMENTED {
            assert!(is_implemented(id));
            // FEATURES は X1 に実装済みの ID（VERSION）が要る。
            let a = args(u64::from(id), u64::from(PSCI_FN_VERSION), 0, 0);
            assert_ne!(run(&c, &BootCpuOnly, 0, a), r(NS), "{id:#x}");
        }
        for id in [
            0x8400_0001u32,
            0xC400_0001,
            0xC400_0002,
            0x8000_0000,
            0x8400_00ff,
            0xC400_0000,
            0xC400_0008,
            0xC400_0009,
        ] {
            assert!(!is_implemented(id), "{id:#x}");
            assert_eq!(call(u64::from(id)), r(NS), "{id:#x}");
            assert_eq!(
                run(&c, &BootCpuOnly, 0, args(0x8400_000A, u64::from(id), 0, 0)),
                r(NS)
            );
        }
    }

    #[test]
    fn mvm5_3794_system_off_and_reset_are_distinguished() {
        assert_eq!(call(0x8400_0008), PsciAction::SystemOff);
        assert_eq!(call(0x8400_0009), PsciAction::SystemReset);
    }

    #[test]
    fn mvm5_3794_migrate_info_type_is_2() {
        assert_eq!(call(0x8400_0006), r(2));
    }

    #[test]
    fn mvm5_3794_upper_bits_of_x0_are_ignored() {
        assert_eq!(call(0xFFFF_FFFF_8400_0000), r(0x0001_0000));
        assert_eq!(call(0x0000_0001_8400_0008), PsciAction::SystemOff);
    }

    #[test]
    fn mvm5_3794_nonzero_imm16_is_not_supported() {
        let c = PsciCpus::single();
        let mut a = args(0x8400_0008, 0, 0, 0);
        a.imm16 = 1;
        assert_eq!(run(&c, &BootCpuOnly, 0, a), r(NS));
        a.imm16 = 0xffff;
        a.x0 = 0x8400_0000;
        assert_eq!(run(&c, &BootCpuOnly, 0, a), r(NS));
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

    /// 1 台構成（HvcHandler の既定）の応答（#3883 受け入れ条件 4 の論理面）。
    #[test]
    fn mvm5_3883_single_vcpu_defaults() {
        let c = PsciCpus::single();
        let p = BootCpuOnly;
        assert_eq!(
            run(&c, &p, 0, args(0xC400_0003, 0, 0x4000_0000, 0)),
            neg(-4)
        );
        assert_eq!(
            run(&c, &p, 0, args(0xC400_0003, 1, 0x4000_0000, 0)),
            neg(-2)
        );
        assert_eq!(run(&c, &p, 0, args(0x8400_0002, 0, 0, 0)), neg(-3));
        assert_eq!(run(&c, &p, 0, args(0xC400_0004, 0, 0, 0)), r(0));
        assert_eq!(c.state(0), Some(CpuPowerState::On));
        assert_eq!(call(0x8400_00ff), r(NS));
    }

    #[test]
    fn mvm5_3883_cpu_on_success_pending_then_already_on() {
        let c = PsciCpus::new(2).unwrap();
        let p = Fake::default();
        assert_eq!(cpu_on64(&c, &p, 1), r(0));
        assert_eq!(*p.ons.lock().unwrap(), vec![(1, 0x4008_0000, 0xdead_beef)]);
        assert_eq!(info(&c, &p, 1), r(2));
        // ON_PENDING 中の CPU_ON は ON_PENDING (-5) で power_on は増えない。
        assert_eq!(cpu_on64(&c, &p, 1), neg(-5));
        assert_eq!(p.ons.lock().unwrap().len(), 1);
        c.confirm_on(1).unwrap();
        assert_eq!(info(&c, &p, 1), r(0));
        assert_eq!(cpu_on64(&c, &p, 1), neg(-4));
        // 自分宛て。
        assert_eq!(cpu_on64(&c, &p, 0), neg(-4));
    }

    #[test]
    fn mvm5_3883_invalid_targets() {
        let c = PsciCpus::new(2).unwrap();
        let p = Fake::default();
        assert_eq!(cpu_on64(&c, &p, 2), neg(-2));
        assert_eq!(cpu_on64(&c, &p, 0x100), neg(-2));
        // MBZ ビット（bit 31 / bit 40）。
        assert_eq!(cpu_on64(&c, &p, 0x8000_0001), neg(-2));
        assert_eq!(cpu_on64(&c, &p, 0x100_0000_0001), neg(-2));
        assert_eq!(info(&c, &p, 2), neg(-2));
        assert_eq!(run(&c, &p, 0, args(0xC400_0004, 0, 1, 0)), neg(-2));
        assert!(p.ons.lock().unwrap().is_empty());
    }

    #[test]
    fn mvm5_3883_cpu_on_32_truncates() {
        let c = PsciCpus::new(2).unwrap();
        let p = Fake::default();
        let a = args(
            0x8400_0003,
            0xAAAA_AAAA_0000_0001,
            0xBBBB_BBBB_4008_0000,
            0xCCCC_CCCC_0000_0007,
        );
        assert_eq!(run(&c, &p, 0, a), r(0));
        assert_eq!(*p.ons.lock().unwrap(), vec![(1, 0x4008_0000, 7)]);
    }

    #[test]
    fn mvm5_3883_cpu_off_then_affinity_info_and_reboot() {
        let c = PsciCpus::new(2).unwrap();
        let p = Fake::default();
        assert_eq!(cpu_on64(&c, &p, 1), r(0));
        c.confirm_on(1).unwrap();
        assert_eq!(
            run(&c, &p, 1, args(0x8400_0002, 0, 0, 0)),
            PsciAction::CpuOff { index: 1 }
        );
        assert_eq!(*p.offs.lock().unwrap(), vec![1]);
        assert_eq!(info(&c, &p, 1), r(1));
        assert_eq!(cpu_on64(&c, &p, 1), r(0));
        assert_eq!(p.ons.lock().unwrap().len(), 2);
    }

    #[test]
    fn mvm5_3883_power_failures_roll_back() {
        let c = PsciCpus::new(2).unwrap();
        let p = Fake::default();
        *p.on_result.lock().unwrap() = Some(PowerControlError::Failed(MicrovmErrorCode::Internal));
        assert_eq!(cpu_on64(&c, &p, 1), neg(-6));
        assert_eq!(info(&c, &p, 1), r(1));
        *p.on_result.lock().unwrap() = Some(PowerControlError::InvalidAddress);
        assert_eq!(cpu_on64(&c, &p, 1), neg(-9));
        assert_eq!(info(&c, &p, 1), r(1));
        // power_off の失敗は DENIED で ON のまま。
        *p.off_result.lock().unwrap() = Some(PowerControlError::Denied);
        assert_eq!(run(&c, &p, 0, args(0x8400_0002, 0, 0, 0)), neg(-3));
        assert_eq!(info(&c, &p, 0), r(0));
    }

    #[test]
    fn mvm5_3883_invariant_violations_are_errors() {
        let c = PsciCpus::new(2).unwrap();
        let p = Fake::default();
        let e = handle_call(&c, &p, 5, args(0x8400_0000, 0, 0, 0)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        // OFF の vCPU からの CPU_OFF。
        let e = handle_call(&c, &p, 1, args(0x8400_0002, 0, 0, 0)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        assert_eq!(
            PsciCpus::new(0).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            PsciCpus::new(65).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            c.confirm_on(1).unwrap_err().code(),
            MicrovmErrorCode::FailedPrecondition
        );
        assert_eq!(
            c.confirm_on(0).unwrap_err().code(),
            MicrovmErrorCode::FailedPrecondition
        );
    }

    #[test]
    fn mvm5_3883_concurrent_cpu_on_has_one_winner() {
        let c = PsciCpus::new(2).unwrap();
        let p = Fake::default();
        let barrier = Barrier::new(2);
        let results: Vec<PsciAction> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..2)
                .map(|_| {
                    s.spawn(|| {
                        barrier.wait();
                        cpu_on64(&c, &p, 1)
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(results.contains(&r(0)), "{results:?}");
        assert!(results.contains(&neg(-5)), "{results:?}");
        assert_eq!(p.ons.lock().unwrap().len(), 1);
    }
}
