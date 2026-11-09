//! Hypervisor.framework（macOS・Apple Silicon）の ABI 値と純粋な検査（TASK-192.1・#3783・MVM-5・MVM-4）。
//!
//! 呼び出し文脈: macOS バックエンドの `sys`（`src/sys/hvf.rs`）の安全なラッパーが、`hv_*` を呼ぶ前の
//! 引数検査（[`check_map_range`]・[`check_vm_map`]）と、呼んだ後の戻り値の写像（[`classify_hv_return`]）にここを使う。
//! `hv_*` を呼ばず `unsafe` も持たないため OS 非依存で、Linux の PR CI の単体テストでも走る。
//!
//! # `hv_return_t` の写像（`message` には数値を載せない。ERR-1）
//! | 値 | `MicrovmErrorCode` |
//! | --- | --- |
//! | `HV_SUCCESS` | `Ok(())` |
//! | `HV_ERROR` | `Internal` |
//! | `HV_BUSY` | `FailedPrecondition` |
//! | `HV_BAD_ARGUMENT` | `InvalidArgument` |
//! | `HV_ILLEGAL_GUEST_STATE` | `FailedPrecondition` |
//! | `HV_NO_RESOURCES` | `ResourceExhausted` |
//! | `HV_NO_DEVICE` | `Unimplemented`（hypervisor を使えない環境） |
//! | `HV_DENIED` | `PermissionDenied` |
//! | `HV_EXISTS` | `AlreadyExists` |
//! | `HV_UNSUPPORTED` | `Unimplemented` |
//! | 未知の値 | `Internal`（fail-closed） |
//!
//! # vCPU 側の値（TASK-192.2・#3786）
//! [`HvReg`]・[`HvSysReg`]・[`HvInterruptType`] は FFI へ渡す値の newtype / enum、[`HvVcpuExitRaw`] は
//! `hv_vcpu_exit_t` のレイアウト、[`decode_exit`] は exit reason の復号（未知の値は `Unknown` で fail-closed）。
//! syndrome の解釈は #3785 の担当で、ここでは生値のまま運ぶ。
//!
//! # GICv3 の版判定（TASK-192.3・#3789）
//! [`parse_macos_product_version`]・[`check_gic_supported`] は `kern.osproductversion` の分解と macOS 15 未満の拒否。
//! [`HvGicIntid`] の値は SDK ヘッダ（`hv_gic_types.h`）の列挙値で、実機でも確かめた（#3803）。
//!
//! # 出典
//! 数値の一部と 3 つの名前は第三者バインディング由来で、SDK 27.2 のヘッダと照合した（#3803。食い違いは #3989 で直した）。
//! vCPU 側の値（`hv_reg_t` の連番、exit reason 0〜3、`HV_INTERRUPT_TYPE_*` の 0 / 1、`hv_reg_t` /
//! `hv_exit_reason_t` / `hv_interrupt_type_t` の幅 u32、`hv_sys_reg_t` の幅 u16、`hv_vcpu_exit_t` の
//! レイアウト）は Apple の公開ドキュメントに基づき、同じヘッダ（`hv_vcpu_types.h` ほか）と一致した（#3803）。
//! macOS 15 の SDK の時点の値は未確認である。`hv_sys_reg_t` の値は Arm ARM の (op0, op1, CRn, CRm, op2) から導出した
//! （第三者リポジトリの一覧は写していない）。

use crate::error::{MicrovmError, MicrovmErrorCode};
use std::ops::BitOr;

/// ゲスト RAM のマップ確保上限（16 GiB）。Linux 側の `MAX_GUEST_RAM_BYTES` と同値で、
/// mmap の前に超過を拒否して無制限確保を防ぐ（リソース上限・MVM-5・MVM-4）。
pub const MAX_MAP_BYTES: u64 = 1 << 34;

/// `HV_SUCCESS`。
pub const HV_SUCCESS: i32 = 0;
/// `HV_ERROR`（0xfae94001）。
pub const HV_ERROR: i32 = 0xfae9_4001_u32 as i32;
/// `HV_BUSY`（0xfae94002）。
pub const HV_BUSY: i32 = 0xfae9_4002_u32 as i32;
/// `HV_BAD_ARGUMENT`（0xfae94003）。
pub const HV_BAD_ARGUMENT: i32 = 0xfae9_4003_u32 as i32;
/// `HV_ILLEGAL_GUEST_STATE`（0xfae94004）。
pub const HV_ILLEGAL_GUEST_STATE: i32 = 0xfae9_4004_u32 as i32;
/// `HV_NO_RESOURCES`（0xfae94005）。
pub const HV_NO_RESOURCES: i32 = 0xfae9_4005_u32 as i32;
/// `HV_NO_DEVICE`（0xfae94006）。
pub const HV_NO_DEVICE: i32 = 0xfae9_4006_u32 as i32;
/// `HV_DENIED`（0xfae94007）。
pub const HV_DENIED: i32 = 0xfae9_4007_u32 as i32;
/// `HV_EXISTS`（0xfae94008）。arm64 のヘッダ（`hv_kern_types.h`）の名前で、`HV_FAULT` は x86_64 のヘッダにだけある（#3803）。
pub const HV_EXISTS: i32 = 0xfae9_4008_u32 as i32;
/// `HV_UNSUPPORTED`（0xfae9400f）。
pub const HV_UNSUPPORTED: i32 = 0xfae9_400f_u32 as i32;

/// どの `hv_*` 呼び出しの結果かを示す（`message` の操作名になる）。後続の子 issue が variant を足す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HvOp {
    /// `hv_vm_create`。
    VmCreate,
    /// `hv_vm_destroy`。
    VmDestroy,
    /// `hv_vm_map`。
    VmMap,
    /// `hv_vm_unmap`。
    VmUnmap,
    /// `hv_vm_protect`。
    VmProtect,
    /// `hv_vcpu_create`。
    VcpuCreate,
    /// `hv_vcpu_destroy`。
    VcpuDestroy,
    /// `hv_vcpu_run`。
    VcpuRun,
    /// `hv_vcpus_exit`。
    VcpusExit,
    /// `hv_vcpu_get_reg`。
    VcpuGetReg,
    /// `hv_vcpu_set_reg`。
    VcpuSetReg,
    /// `hv_vcpu_get_sys_reg`。
    VcpuGetSysReg,
    /// `hv_vcpu_set_sys_reg`。
    VcpuSetSysReg,
    /// `hv_vcpu_set_pending_interrupt`。
    VcpuSetPendingInterrupt,
    /// `hv_gic_config_set_distributor_base`（macOS 15 以降。TASK-192.3・#3789）。
    GicConfigSetDistributorBase,
    /// `hv_gic_config_set_redistributor_base`（macOS 15 以降。TASK-192.3・#3789）。
    GicConfigSetRedistributorBase,
    /// `hv_gic_create`（macOS 15 以降。TASK-192.3・#3789）。
    GicCreate,
    /// `hv_gic_set_spi`（macOS 15 以降。TASK-192.3・#3789）。
    GicSetSpi,
    /// `hv_gic_get_distributor_size`（macOS 15 以降。TASK-192.3・#3789）。
    GicGetDistributorSize,
    /// `hv_gic_get_distributor_base_alignment`（macOS 15 以降。TASK-192.3・#3789）。
    GicGetDistributorBaseAlignment,
    /// `hv_gic_get_redistributor_size`（macOS 15 以降。TASK-192.3・#3789）。
    GicGetRedistributorSize,
    /// `hv_gic_get_redistributor_base_alignment`（macOS 15 以降。TASK-192.3・#3789）。
    GicGetRedistributorBaseAlignment,
    /// `hv_gic_get_spi_interrupt_range`（macOS 15 以降。TASK-192.3・#3789）。
    GicGetSpiInterruptRange,
    /// `hv_gic_get_intid`（macOS 15 以降。TASK-192.3・#3789）。
    GicGetIntid,
    /// `hv_gic_get_distributor_reg`（macOS 15 以降。任意のシンボル。#3960・MVM-5）。
    GicGetDistributorReg,
    /// `hv_vm_config_get_default_ipa_size`（macOS 13 以降。`dlsym` で解決。#4227・MVM-5）。
    VmConfigGetDefaultIpaSize,
}

impl HvOp {
    const fn name(self) -> &'static str {
        match self {
            HvOp::VmCreate => "hv_vm_create",
            HvOp::VmDestroy => "hv_vm_destroy",
            HvOp::VmMap => "hv_vm_map",
            HvOp::VmUnmap => "hv_vm_unmap",
            HvOp::VmProtect => "hv_vm_protect",
            HvOp::VcpuCreate => "hv_vcpu_create",
            HvOp::VcpuDestroy => "hv_vcpu_destroy",
            HvOp::VcpuRun => "hv_vcpu_run",
            HvOp::VcpusExit => "hv_vcpus_exit",
            HvOp::VcpuGetReg => "hv_vcpu_get_reg",
            HvOp::VcpuSetReg => "hv_vcpu_set_reg",
            HvOp::VcpuGetSysReg => "hv_vcpu_get_sys_reg",
            HvOp::VcpuSetSysReg => "hv_vcpu_set_sys_reg",
            HvOp::VcpuSetPendingInterrupt => "hv_vcpu_set_pending_interrupt",
            HvOp::GicConfigSetDistributorBase => "hv_gic_config_set_distributor_base",
            HvOp::GicConfigSetRedistributorBase => "hv_gic_config_set_redistributor_base",
            HvOp::GicCreate => "hv_gic_create",
            HvOp::GicSetSpi => "hv_gic_set_spi",
            HvOp::GicGetDistributorSize => "hv_gic_get_distributor_size",
            HvOp::GicGetDistributorBaseAlignment => "hv_gic_get_distributor_base_alignment",
            HvOp::GicGetRedistributorSize => "hv_gic_get_redistributor_size",
            HvOp::GicGetRedistributorBaseAlignment => "hv_gic_get_redistributor_base_alignment",
            HvOp::GicGetSpiInterruptRange => "hv_gic_get_spi_interrupt_range",
            HvOp::GicGetIntid => "hv_gic_get_intid",
            HvOp::GicGetDistributorReg => "hv_gic_get_distributor_reg",
            HvOp::VmConfigGetDefaultIpaSize => "hv_vm_config_get_default_ipa_size",
        }
    }
}

/// `hv_return_t` を `Result` に写す（モジュール doc の表。`hv_*` は呼ばない純関数）。
///
/// `message` は英語の固定文で、操作名と既知の値のシンボル名だけを載せる。
pub fn classify_hv_return(op: HvOp, code: i32) -> Result<(), MicrovmError> {
    let (class, sym) = match code {
        HV_SUCCESS => return Ok(()),
        HV_ERROR => (MicrovmErrorCode::Internal, "HV_ERROR"),
        HV_BUSY => (MicrovmErrorCode::FailedPrecondition, "HV_BUSY"),
        HV_BAD_ARGUMENT => (MicrovmErrorCode::InvalidArgument, "HV_BAD_ARGUMENT"),
        HV_ILLEGAL_GUEST_STATE => (
            MicrovmErrorCode::FailedPrecondition,
            "HV_ILLEGAL_GUEST_STATE",
        ),
        HV_NO_RESOURCES => (MicrovmErrorCode::ResourceExhausted, "HV_NO_RESOURCES"),
        HV_NO_DEVICE => (MicrovmErrorCode::Unimplemented, "HV_NO_DEVICE"),
        HV_DENIED => (MicrovmErrorCode::PermissionDenied, "HV_DENIED"),
        HV_EXISTS => (MicrovmErrorCode::AlreadyExists, "HV_EXISTS"),
        HV_UNSUPPORTED => (MicrovmErrorCode::Unimplemented, "HV_UNSUPPORTED"),
        _ => {
            return Err(MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{} returned an unknown hv_return_t", op.name()),
            ));
        }
    };
    Err(MicrovmError::new(
        class,
        format!("{} returned {}", op.name(), sym),
    ))
}

/// `hv_memory_flags_t`（u64）の newtype。生の数値を渡し回さない（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryFlags(u64);

impl MemoryFlags {
    /// `HV_MEMORY_READ`。
    pub const READ: MemoryFlags = MemoryFlags(1);
    /// `HV_MEMORY_WRITE`。
    pub const WRITE: MemoryFlags = MemoryFlags(2);
    /// `HV_MEMORY_EXEC`。
    pub const EXEC: MemoryFlags = MemoryFlags(4);
    /// READ | WRITE | EXEC。
    pub const RWX: MemoryFlags = MemoryFlags(7);

    /// FFI に渡す生のビット値。
    pub const fn bits(self) -> u64 {
        self.0
    }
}

impl BitOr for MemoryFlags {
    type Output = MemoryFlags;
    fn bitor(self, rhs: MemoryFlags) -> MemoryFlags {
        MemoryFlags(self.0 | rhs.0)
    }
}

/// `hv_reg_t`（u32）の newtype。X0〜X30 は [`HvReg::x`] で作り、範囲外は作れない（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvReg(u32);

impl HvReg {
    /// `HV_REG_PC`。
    pub const PC: HvReg = HvReg(31);
    /// `HV_REG_FPCR`。
    pub const FPCR: HvReg = HvReg(32);
    /// `HV_REG_FPSR`。
    pub const FPSR: HvReg = HvReg(33);
    /// `HV_REG_CPSR`。
    pub const CPSR: HvReg = HvReg(34);

    /// 汎用レジスタ `Xn`（0..=30）。31 以上は `None`。
    pub const fn x(n: u8) -> Option<HvReg> {
        if n <= 30 { Some(HvReg(n as u32)) } else { None }
    }

    /// FFI に渡す生の値。
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// `hv_sys_reg_t`（u16）の newtype。本ツリーで使う 4 つに限る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvSysReg(u16);

impl HvSysReg {
    /// MRS / MSR のオペランドの符号化（op0:op1:CRn:CRm:op2 = 2:3:4:4:3 ビット）。
    const fn encode(op0: u16, op1: u16, crn: u16, crm: u16, op2: u16) -> u16 {
        (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
    }

    /// `HV_SYS_REG_MPIDR_EL1`。
    pub const MPIDR_EL1: HvSysReg = HvSysReg(Self::encode(3, 0, 0, 0, 5));
    /// `HV_SYS_REG_SCTLR_EL1`。
    pub const SCTLR_EL1: HvSysReg = HvSysReg(Self::encode(3, 0, 1, 0, 0));
    /// `HV_SYS_REG_CNTV_CTL_EL0`。
    pub const CNTV_CTL_EL0: HvSysReg = HvSysReg(Self::encode(3, 3, 14, 3, 1));
    /// `HV_SYS_REG_CNTV_CVAL_EL0`。
    pub const CNTV_CVAL_EL0: HvSysReg = HvSysReg(Self::encode(3, 3, 14, 3, 2));

    /// FFI に渡す生の値。
    pub const fn bits(self) -> u16 {
        self.0
    }
}

/// `hv_interrupt_type_t`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvInterruptType {
    /// `HV_INTERRUPT_TYPE_IRQ`。
    Irq,
    /// `HV_INTERRUPT_TYPE_FIQ`。
    Fiq,
}

impl HvInterruptType {
    /// FFI に渡す生の値。
    pub const fn bits(self) -> u32 {
        match self {
            HvInterruptType::Irq => 0,
            HvInterruptType::Fiq => 1,
        }
    }
}

/// `HV_EXIT_REASON_CANCELED`。
pub const HV_EXIT_REASON_CANCELED: u32 = 0;
/// `HV_EXIT_REASON_EXCEPTION`。
pub const HV_EXIT_REASON_EXCEPTION: u32 = 1;
/// `HV_EXIT_REASON_VTIMER_ACTIVATED`。
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: u32 = 2;
/// `HV_EXIT_REASON_UNKNOWN`。
pub const HV_EXIT_REASON_UNKNOWN: u32 = 3;

/// `hv_vcpu_exit_exception_t`（syndrome・仮想アドレス・物理アドレス）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvVcpuExitException {
    /// ESR_EL2 相当の syndrome（解釈は #3785）。
    pub syndrome: u64,
    /// フォールトした仮想アドレス。
    pub virtual_address: u64,
    /// フォールトしたゲスト物理アドレス（IPA）。
    pub physical_address: u64,
}

/// `hv_vcpu_exit_t`（reason の後ろに 4 バイトのパディング）。フレームワークが vCPU ごとに持つ領域のレイアウト。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HvVcpuExitRaw {
    /// `hv_exit_reason_t`。
    pub reason: u32,
    /// reason が EXCEPTION のときだけ意味を持つ。
    pub exception: HvVcpuExitException,
}

// レイアウトの固定（LP64 の全ターゲットで成り立つ。SDK 27.2 のヘッダと一致した。#3803）。
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<HvVcpuExitException>() == 24);
    assert!(offset_of!(HvVcpuExitException, syndrome) == 0);
    assert!(offset_of!(HvVcpuExitException, virtual_address) == 8);
    assert!(offset_of!(HvVcpuExitException, physical_address) == 16);
    assert!(size_of::<HvVcpuExitRaw>() == 32);
    assert!(offset_of!(HvVcpuExitRaw, reason) == 0);
    assert!(offset_of!(HvVcpuExitRaw, exception) == 8);
    assert!(align_of::<HvVcpuExitRaw>() == 8);
};

/// `hv_vcpu_run` が戻った理由。未知の値は `Unknown`（呼び出し側は VM を止める。fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvVcpuExit {
    /// `hv_vcpus_exit` による停止要求。
    Canceled,
    /// ゲストの例外（syndrome は生値）。
    Exception(HvVcpuExitException),
    /// vtimer の発火（マスクされて戻った）。
    VtimerActivated,
    /// `HV_EXIT_REASON_UNKNOWN` と未定義の値（生値を保持）。
    Unknown(u32),
}

/// exit 領域の写しを復号する（純関数）。
pub fn decode_exit(raw: &HvVcpuExitRaw) -> HvVcpuExit {
    match raw.reason {
        HV_EXIT_REASON_CANCELED => HvVcpuExit::Canceled,
        HV_EXIT_REASON_EXCEPTION => HvVcpuExit::Exception(raw.exception),
        HV_EXIT_REASON_VTIMER_ACTIVATED => HvVcpuExit::VtimerActivated,
        other => HvVcpuExit::Unknown(other),
    }
}

fn invalid(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, msg)
}

/// macOS バックエンドが受ける vCPU 数の上限（#3884・MVM-5・MVM-1・REPAIR-5）。
///
/// 固定値 32。根拠: (1) Linux（KVM）バックエンドの `microvm::MAX_VCPUS`（32）と揃え、plugin-microvm から見た上限を 2 つの
/// バックエンドで同じにする。(2) GICR の窓と FDT の `cpu@N` が受ける `ARM64_MAX_VCPUS`（64）以内（下の const assert で固定）。
/// フレームワーク側の実際の上限（`hv_vm_get_max_vcpu_count`）は照会しない。macOS 27.2・Apple M4 Max の値は 64 で（#3997）、
/// 照会しても受ける上限は 32 のままなのに、新しい FFI 宣言と macOS 14 での dyld の解決の確認が要るため。32 台を受けない機種では
/// `hv_vcpu_create` が失敗し、`assemble` 全体が作成済みの資源を回収して失敗する（fail-closed）。64 は照会した値で、実機前提試験は
/// 32 台を作っていない。
pub const HVF_MAX_VCPUS: u32 = 32;
const _: () = assert!(HVF_MAX_VCPUS <= crate::arm64_layout::ARM64_MAX_VCPUS);
/// macOS バックエンドが受けるゲスト RAM の上限（[`MAX_MAP_BYTES`] と同値。mmap の前に超過を拒否する）。
pub const HVF_MAX_GUEST_RAM_BYTES: u64 = MAX_MAP_BYTES;

/// `HvfMicroVm::assemble` が資源（VM・GIC・mmap）を作る前に検査する構成値（#3797）。
///
/// 循環依存を避けるためプリミティブだけで受ける。呼び出し元は plugin-microvm 側から来る非信頼の VM 構成。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvfAssembleInput {
    /// 構成（`HvfMicroVmConfig::vcpus`）の vCPU 数。
    pub vcpus: u32,
    /// レイアウトの vCPU 数（`layout.vcpus`。FDT の `cpu@N` の個数。`vcpus` と一致すること。#3884）。
    pub layout_vcpus: u32,
    /// ゲスト RAM の大きさ（バイト）。
    pub ram_size: u64,
    /// レイアウトの virtio-mmio の個数。
    pub layout_virtio_count: u32,
    /// 実際に登録するデバイス数（block + net。シリアルは含まない）。
    pub device_count: usize,
    /// シリアル（ns16550a の MMIO）を MMIO 表へ登録するか（`HvfMicroVmConfig::serial`。#3882・MVM-5・MVM-1）。
    pub serial: bool,
    /// レイアウトにシリアルの窓があるか（`layout.serial.is_some()`。#3882）。
    pub layout_serial: bool,
    /// カーネル Image の長さ。
    pub image_len: u64,
    /// initrd の長さ（無ければ `None`）。
    pub initrd_len: Option<u64>,
    /// カーネル cmdline の長さ。
    pub cmdline_len: usize,
}

/// 構成値の上限検査（資源を作る前。ERR-1: メッセージは固定で入力値をエコーしない）。
///
/// 順序: vcpus（0 と [`HVF_MAX_VCPUS`] 超は `InvalidArgument`。他の不正に隠れないよう最初）→ レイアウトの vcpus との一致 →
/// RAM → virtio の台数
/// （[`crate::arm64_layout::ARM64_VIRTIO_MMIO_MAX`]）→ レイアウトの個数の一致 → シリアルの有無の一致 → MMIO 表の合計 →
/// Image・initrd・cmdline の長さ。Image ヘッダの中身はここでは見ない（RAM 登録後の `load_arm64` が検証する）。
///
/// MMIO 表の合計（#3882）: macOS ではシリアルも virtio と同じ MMIO 表（1 表 [`crate::dispatch::MAX_BUS_DEVICES`] 件）に載るため、
/// virtio + シリアル（有効なら 1）がその上限を超える構成は、VM・GIC・RAM を作る前に `InvalidArgument` で拒否する
/// （作った後の段 5 で `ResourceExhausted` になるのを避ける）。virtio は単独なら 32 台まで受けるが、シリアルありでは 31 台まで。
/// Linux の x86_64 `MicroVm` は UART が PIO 表（COM1）にあり別勘定。KVM aarch64 は同じ MMIO 表に載せ、同じ検査を共有する（#3898）。
pub fn check_assemble_input(input: &HvfAssembleInput) -> Result<(), MicrovmError> {
    use crate::arm64_layout::{ARM64_MAX_BOOTARGS, ARM64_VIRTIO_MMIO_MAX};
    use crate::boot_x86::{MAX_INITRD_BYTES, MAX_KERNEL_IMAGE_BYTES};

    if input.vcpus == 0 {
        return Err(invalid("vcpus is zero"));
    }
    if input.vcpus > HVF_MAX_VCPUS {
        return Err(invalid("too many vcpus for the hvf backend"));
    }
    if input.layout_vcpus != input.vcpus {
        return Err(invalid("vcpu layout does not match the configuration"));
    }
    if input.ram_size == 0 || input.ram_size > HVF_MAX_GUEST_RAM_BYTES {
        return Err(invalid("guest ram size is out of range"));
    }
    if input.device_count > ARM64_VIRTIO_MMIO_MAX as usize {
        return Err(invalid("too many virtio devices"));
    }
    if u32::try_from(input.device_count).ok() != Some(input.layout_virtio_count) {
        return Err(invalid("device layout does not match the configuration"));
    }
    if input.layout_serial != input.serial {
        return Err(invalid("serial layout does not match the configuration"));
    }
    crate::dispatch::check_mmio_bus_capacity(input.device_count, input.serial)?;
    if input.image_len == 0 || input.image_len > MAX_KERNEL_IMAGE_BYTES {
        return Err(invalid("kernel image length is out of range"));
    }
    if input.initrd_len.is_some_and(|n| n > MAX_INITRD_BYTES) {
        return Err(invalid("initrd length is out of range"));
    }
    if input.cmdline_len > ARM64_MAX_BOOTARGS {
        return Err(invalid("kernel cmdline is too long"));
    }
    Ok(())
}

/// `hv_vm_map` / `hv_vm_protect` に渡す範囲の検査（FFI の前に必ず通す）。
///
/// `page_size` が 0 か 2 の冪でない、`size` が 0 か [`MAX_MAP_BYTES`] 超かページ倍数でない、`addr`・`ipa` がページ境界でない、
/// `addr + size`・`ipa + size` が桁あふれする、のいずれかを `InvalidArgument` にする。
pub fn check_map_range(addr: u64, ipa: u64, size: u64, page_size: u64) -> Result<(), MicrovmError> {
    if !page_size.is_power_of_two() {
        return Err(invalid("page size is not a power of two"));
    }
    if size == 0 {
        return Err(invalid("size is zero"));
    }
    if size > MAX_MAP_BYTES {
        return Err(invalid("size exceeds the maximum mapping size"));
    }
    if !size.is_multiple_of(page_size) {
        return Err(invalid("size is not a multiple of the page size"));
    }
    if !addr.is_multiple_of(page_size) {
        return Err(invalid("host address is not page aligned"));
    }
    if !ipa.is_multiple_of(page_size) {
        return Err(invalid("guest address is not page aligned"));
    }
    if addr.checked_add(size).is_none() || ipa.checked_add(size).is_none() {
        return Err(invalid("range overflows the address space"));
    }
    Ok(())
}

/// 既定の IPA 幅（36 ビット = 64 GiB）に基づくゲスト物理アドレスの上限（TASK-192.4・#3787・MVM-5）。
///
/// macOS 27.2・Apple M4 Max の実機の既定は 36 ビット、最大は 40 ビットだった（#3997。他の機種・版は未確認）。`config = NULL` の
/// VM でこの上限の直前のページは map でき、直後のページは `HV_BAD_ARGUMENT` だった。広げるには VM の作成時に IPA 幅を指定する変更が要る。
/// この定数は FFI 引数の天井として残す。実行時の既定幅（`hv_vm_config_get_default_ipa_size`）との照合は `assemble` が
/// `crate::gpa_width` で行う（#4227）。
pub const HVF_DEFAULT_IPA_LIMIT: u64 = 1 << 36;

/// ゲスト RAM を `[ipa, ipa + size)` に置けるか、IPA の上限に対して検査する（`hv_vm_map` の前に通す）。
///
/// `ipa_limit` が 0 か [`HVF_DEFAULT_IPA_LIMIT`] 超、`ipa + size` の桁あふれ、`ipa_limit` 超過を `InvalidArgument` にする。
pub fn check_ipa_limit(ipa: u64, size: u64, ipa_limit: u64) -> Result<(), MicrovmError> {
    if ipa_limit == 0 || ipa_limit > HVF_DEFAULT_IPA_LIMIT {
        return Err(invalid("ipa limit is out of range"));
    }
    let end = ipa
        .checked_add(size)
        .ok_or_else(|| invalid("guest range overflows the address space"))?;
    if end > ipa_limit {
        return Err(invalid("guest range exceeds the ipa limit"));
    }
    Ok(())
}

/// `HvVm::map`（`sys/hvf.rs`）が `hv_vm_map` の前に通す検査（#3844・MVM-5）。
///
/// [`check_map_range`] の後に、[`HVF_DEFAULT_IPA_LIMIT`] に対する [`check_ipa_limit`] を行う（この順序）。
/// `config = NULL` で作る VM の IPA 幅は既定値なので、既定の上限が FFI に渡せる範囲の天井になる。
/// 上限の前後のページの挙動は実機で確かめた（#3997）。レイアウトごとの、より厳しい上限は `HvfGuestRam::register` が検査する。
pub fn check_vm_map(addr: u64, ipa: u64, size: u64, page_size: u64) -> Result<(), MicrovmError> {
    check_map_range(addr, ipa, size, page_size)?;
    check_ipa_limit(ipa, size, HVF_DEFAULT_IPA_LIMIT)
}

/// `HvVcpu::run_once` の期限の上限（異常な値で実質無期限になるのを防ぐ。REPAIR-5・KVM 側の `RUN_DEADLINE_MAX` と同値）。
pub const HV_RUN_DEADLINE_MAX: std::time::Duration = std::time::Duration::from_secs(3600);

/// `run_once` の期限の検査（FFI の前に必ず通す）。0 と上限超過は `InvalidArgument`。
pub fn check_run_deadline(timeout: std::time::Duration) -> Result<(), MicrovmError> {
    if timeout.is_zero() {
        return Err(invalid("run deadline must be non-zero"));
    }
    if timeout > HV_RUN_DEADLINE_MAX {
        return Err(invalid("run deadline exceeds the maximum"));
    }
    Ok(())
}

/// `hv_vcpu_run` 1 回の結果の分類（計装用。REPAIR-4。KVM 側の `RunOutcome` に対応）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvRunOutcome {
    /// VM exit で戻った。値は exit の種別名（`exception` / `vtimer` / `canceled` / `unknown`）。
    Exit(&'static str),
    /// 期限を超えて `hv_vcpus_exit` で中断した（REPAIR-5）。
    DeadlineExceeded,
    /// FFI または復号の失敗。
    Error(MicrovmErrorCode),
}

/// `run_once` 1 回の記録（結果と所要時間。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvRunRecord {
    /// 結果。
    pub outcome: HvRunOutcome,
    /// `hv_vcpu_run` の発行から戻るまでの時間。
    pub elapsed: std::time::Duration,
}

/// 実行結果の記録器。呼び出し側が構造化ログやメトリクスへ接続する。`record` は vCPU スレッドから同期で
/// 呼ばれるため、ブロックしないこと。
pub trait HvRunObserver: Send + Sync + std::fmt::Debug {
    /// 1 回の `run_once` の記録を受け取る。
    fn record(&self, record: &HvRunRecord);
}

/// vCPU ごとの累積の実行統計（観測器が無くても取れる。REPAIR-4）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HvRunStats {
    /// 発行回数。
    pub runs: u64,
    /// VM exit で戻った回数。
    pub exits: u64,
    /// 期限超過の回数。
    pub deadline_exceeded: u64,
    /// 失敗の回数。
    pub errors: u64,
    /// 所要時間の合計。
    pub total_elapsed: std::time::Duration,
}

impl HvRunStats {
    /// 記録 1 件を累積へ加える。
    pub fn add(&mut self, record: &HvRunRecord) {
        self.runs = self.runs.saturating_add(1);
        self.total_elapsed = self.total_elapsed.saturating_add(record.elapsed);
        match record.outcome {
            HvRunOutcome::Exit(_) => self.exits = self.exits.saturating_add(1),
            HvRunOutcome::DeadlineExceeded => {
                self.deadline_exceeded = self.deadline_exceeded.saturating_add(1);
            }
            HvRunOutcome::Error(_) => self.errors = self.errors.saturating_add(1),
        }
    }
}

fn exit_kind(e: &HvVcpuExit) -> &'static str {
    match e {
        HvVcpuExit::Canceled => "canceled",
        HvVcpuExit::Exception(_) => "exception",
        HvVcpuExit::VtimerActivated => "vtimer",
        HvVcpuExit::Unknown(_) => "unknown",
    }
}

/// `hv_vcpu_run` の戻りを期限の発火の有無と合わせて確定する（純関数）。
///
/// 期限が発火して `Canceled` で戻ったときだけ `DeadlineExceeded`（外部からの `cancel` による `Canceled` は
/// そのまま `Ok(Canceled)`）。分類した記録も返す。
pub fn finish_run(
    result: Result<HvVcpuExit, MicrovmError>,
    deadline_fired: bool,
    elapsed: std::time::Duration,
) -> (Result<HvVcpuExit, MicrovmError>, HvRunRecord) {
    let result = match result {
        Ok(HvVcpuExit::Canceled) if deadline_fired => Err(MicrovmError::new(
            MicrovmErrorCode::DeadlineExceeded,
            "vcpu run exceeded its deadline",
        )),
        other => other,
    };
    let outcome = match &result {
        Ok(e) => HvRunOutcome::Exit(exit_kind(e)),
        Err(e) if e.code() == MicrovmErrorCode::DeadlineExceeded => HvRunOutcome::DeadlineExceeded,
        Err(e) => HvRunOutcome::Error(e.code()),
    };
    (result, HvRunRecord { outcome, elapsed })
}

// ---- GICv3（TASK-192.3・#3789・MVM-5・MVM-4） ----

/// `kern.osproductversion` を受ける上限（NUL を除く）。これを超える応答は分解の前に拒否する。
pub const MACOS_PRODUCT_VERSION_MAX_LEN: usize = 32;

/// `hv_gic_*` が入った macOS のメジャー版（15.0）。
pub const GIC_MIN_MACOS_MAJOR: u32 = 15;

/// macOS の版（`kern.osproductversion`。`major.minor[.patch]`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacosVersion {
    /// メジャー版。
    pub major: u32,
    /// マイナー版（無ければ 0）。
    pub minor: u32,
    /// パッチ版（無ければ 0）。
    pub patch: u32,
}

fn bad_version() -> MicrovmError {
    MicrovmError::new(
        MicrovmErrorCode::Internal,
        "unexpected kern.osproductversion format",
    )
}

/// `kern.osproductversion` の生バイト列を分解する（sysctl 由来の外部入力。末尾の NUL は 1 個まで許す）。
///
/// 長さの上限と文字種を検査し、不正なら `Internal`（固定文・fail-closed）。`hv_*` は呼ばない純関数。
pub fn parse_macos_product_version(raw: &[u8]) -> Result<MacosVersion, MicrovmError> {
    let body = raw.strip_suffix(&[0]).unwrap_or(raw);
    if body.is_empty() || body.len() > MACOS_PRODUCT_VERSION_MAX_LEN {
        return Err(bad_version());
    }
    let mut parts = [0u32; 3];
    for (count, piece) in body.split(|b| *b == b'.').enumerate() {
        let slot = parts.get_mut(count).ok_or_else(bad_version)?;
        if piece.is_empty() {
            return Err(bad_version());
        }
        let mut value = 0u32;
        for b in piece {
            if !b.is_ascii_digit() {
                return Err(bad_version());
            }
            value = value
                .checked_mul(10)
                .and_then(|v| v.checked_add(u32::from(b - b'0')))
                .ok_or_else(bad_version)?;
        }
        *slot = value;
    }
    let [major, minor, patch] = parts;
    Ok(MacosVersion {
        major,
        minor,
        patch,
    })
}

/// GICv3 の API を使える版か。15 より前は `Unimplemented`（構造化エラーで起動を拒否する。TASK-192）。
pub fn check_gic_supported(v: MacosVersion) -> Result<(), MicrovmError> {
    if v.major < GIC_MIN_MACOS_MAJOR {
        return Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "hypervisor GIC requires macOS 15 or later",
        ));
    }
    Ok(())
}

/// `hv_gic_intid_t`（`uint16_t` の列挙）の識別値。`hv_gic_get_intid` へ渡す「割り込みの種類」の選択子。
///
/// ゲストに見せる INTID は [`GicIntid`] として戻り値から得る。`EL1_VIRTUAL_TIMER` は SDK（27.2）の列挙値が 27 で、
/// 実機の戻り値も 27 だった（#3803）が、選択子と戻り値は意味が違うので型を分けたままにする。
/// 呼び出し側は数値を直接書かず定数だけを使う（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvGicIntid(u16);

impl HvGicIntid {
    /// `HV_GIC_INT_EL1_VIRTUAL_TIMER` の列挙識別値（SDK ヘッダと実機で確認。#3803）。
    pub const EL1_VIRTUAL_TIMER: HvGicIntid = HvGicIntid(27);

    /// FFI へ渡す列挙識別値。
    pub const fn bits(self) -> u16 {
        self.0
    }
}

/// `hv_gic_get_intid` が返すゲスト側の割り込み番号（INTID）。列挙識別値 [`HvGicIntid`] とは別の型にして
/// 取り違えを防ぐ。FDT の割り込み指定などはこの値から組み立て、ハードコードしない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GicIntid(u32);

impl GicIntid {
    /// FFI の戻り値から作る。
    pub const fn new(raw: u32) -> Self {
        GicIntid(raw)
    }

    /// 生の INTID。
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// `hv_gic_distributor_reg_t` の列挙値（`GICD_CTLR` と `GICD_IROUTER<n>` のみ。#3960・#3974・MVM-5・REPAIR-2）。
///
/// Apple の文書は、列挙値が ARM GICv3 仕様の distributor のレジスタオフセットに等しいと述べる
/// （`hv_gic_get_distributor_reg`。macOS 15.0）。型の幅は `uint16_t`（`hv_gic_distributor_reg_t` の `rawValue` は `UInt16`）。
/// 構築口は [`Self::ctlr`] と [`Self::irouter`] だけで、SPI の範囲外の INTID は作れない（壊れた値を表現できない）。
/// 出典: <https://developer.apple.com/documentation/hypervisor/hv_gic_get_distributor_reg(_:_:)>・
/// <https://developer.apple.com/documentation/hypervisor/hv_gic_distributor_reg_t>・
/// <https://developer.apple.com/documentation/hypervisor/hv_gic_distributor_reg_gicd_irouter32>・
/// <https://developer.apple.com/documentation/hypervisor/hv_gic_distributor_reg_gicd_ctlr>（確認日 2026-11-05）。
/// SDK ヘッダと一致した（幅は `uint16_t`、`GICD_IROUTER32` は 0x6100。#3803）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GicDistributorReg(u16);

/// `GICD_IROUTER<n>` の先頭オフセット（Arm IHI 0069。IROUTER32 は 0x6100 = 0x6000 + 8 × 32）。
const GICD_IROUTER_BASE: u32 = 0x6000;
/// SPI の INTID の最小値（INTID 32 以降）。
const GIC_SPI_MIN_INTID: u32 = 32;
/// SPI の INTID の最大値（1019。1020 以降は特殊・LPI 等）。
const GIC_SPI_MAX_INTID: u32 = 1019;

impl GicDistributorReg {
    /// `GICD_CTLR`（オフセット 0x0000。Arm IHI 0069）。観測用の getter が読む（#3974・#4041・MVM-5）。
    pub const fn ctlr() -> Self {
        Self(0)
    }

    /// `GICD_IROUTER<intid>` のレジスタ。SPI の範囲（32..=1019）の外は `InvalidArgument`。
    pub fn irouter(intid: u32) -> Result<Self, MicrovmError> {
        if !(GIC_SPI_MIN_INTID..=GIC_SPI_MAX_INTID).contains(&intid) {
            return Err(invalid("irouter intid is outside the spi range"));
        }
        let off = intid
            .checked_mul(8)
            .and_then(|v| v.checked_add(GICD_IROUTER_BASE))
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| invalid("irouter offset out of range"))?;
        Ok(Self(off))
    }

    /// FFI へ渡す列挙値（distributor のレジスタオフセット）。
    pub const fn bits(self) -> u16 {
        self.0
    }
}

/// `GICD_IROUTER<n>` の復号結果（#3960・MVM-5）。値はゲストが書くので非信頼として扱う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrouterRoute {
    /// IRM = 0 で、宛先は 1 つの PE。値は Aff3:Aff2:Aff1:Aff0 を下位から 8 ビットずつ詰めた 32 ビット値
    /// （`arm64_vcpu_mpidr_affinity` の形式に Aff3 を bit 24 以降へ足したもの）。
    Affinity(u32),
    /// IRM = 1（1-of-N。参加する任意の PE。宛先を 1 台に決められない）。
    AnyParticipating,
    /// RES0 が立っている（書式違反）。
    Malformed,
}

/// `GICD_IROUTER<n>` の生値を復号する。Aff0 = bit 7:0・Aff1 = 15:8・Aff2 = 23:16・IRM = 31・Aff3 = 39:32（Arm IHI 0069）。
/// 残りのビットは RES0。IRM = 1 のときの affinity フィールドは無視される（読み出しは 0 とは限らないため見ない）。
pub fn decode_irouter(raw: u64) -> IrouterRoute {
    const IRM: u64 = 1 << 31;
    // 使うのは bit 23:0（Aff2:1:0）・bit 31（IRM）・bit 39:32（Aff3）だけ。
    const RES0: u64 = !(0x00FF_FFFFu64 | IRM | (0xFFu64 << 32));
    if raw & RES0 != 0 {
        return IrouterRoute::Malformed;
    }
    if raw & IRM != 0 {
        return IrouterRoute::AnyParticipating;
    }
    let aff012 = (raw & 0x00FF_FFFF) as u32;
    let aff3 = ((raw >> 32) & 0xFF) as u32;
    IrouterRoute::Affinity(aff012 | (aff3 << 24))
}

/// `HostMapping` の drop で `munmap` が失敗したときに出す固定の 1 行（MVM-5・REPAIR-4・#4292）。
/// 既存の `op=hvf.vm_unmap` / `op=hvf.vm_destroy` の文法（`level=.. op=.. outcome=error leaked=..`）に揃える。
/// errno・アドレス・長さ・スレッド名は出さない（ホストのアドレス配置を漏らさず、行を完全な定数にする）。
pub const HOST_UNMAP_FAILED_LINE: &str =
    "level=error op=hvf.host_unmap outcome=error leaked=host_mapping";

/// `munmap` の戻り値から観測用の行を決める純関数。`sys::hvf` の `HostMapping` の drop から呼ばれる。
/// 0 以外はすべて失敗とみなす（fail-closed。munmap は成功 0・失敗 -1 だが戻り値の細部に依らない）。
pub fn host_unmap_failure_line(rc: i32) -> Option<&'static str> {
    if rc == 0 {
        None
    } else {
        Some(HOST_UNMAP_FAILED_LINE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// munmap の戻り値と行の対応を具体値で固定する（MVM-5・REPAIR-4・#4292）。
    #[test]
    fn mvm5_4292_host_unmap_failure_line_maps_rc() {
        assert_eq!(host_unmap_failure_line(0), None);
        let want = "level=error op=hvf.host_unmap outcome=error leaked=host_mapping";
        assert_eq!(host_unmap_failure_line(-1), Some(want));
        assert_eq!(host_unmap_failure_line(1), Some(want));
    }

    #[test]
    fn mvm5_3783_constants_have_expected_values() {
        assert_eq!(HV_SUCCESS, 0);
        assert_eq!(HV_ERROR as u32, 0xfae9_4001);
        assert_eq!(HV_BUSY as u32, 0xfae9_4002);
        assert_eq!(HV_BAD_ARGUMENT as u32, 0xfae9_4003);
        assert_eq!(HV_ILLEGAL_GUEST_STATE as u32, 0xfae9_4004);
        assert_eq!(HV_NO_RESOURCES as u32, 0xfae9_4005);
        assert_eq!(HV_NO_DEVICE as u32, 0xfae9_4006);
        assert_eq!(HV_DENIED as u32, 0xfae9_4007);
        assert_eq!(HV_EXISTS as u32, 0xfae9_4008);
        assert_eq!(HV_UNSUPPORTED as u32, 0xfae9_400f);
    }

    #[test]
    fn mvm5_3783_classify_maps_every_known_value() {
        assert!(classify_hv_return(HvOp::VmCreate, HV_SUCCESS).is_ok());
        let cases = [
            (HV_ERROR, MicrovmErrorCode::Internal, "HV_ERROR"),
            (HV_BUSY, MicrovmErrorCode::FailedPrecondition, "HV_BUSY"),
            (
                HV_BAD_ARGUMENT,
                MicrovmErrorCode::InvalidArgument,
                "HV_BAD_ARGUMENT",
            ),
            (
                HV_ILLEGAL_GUEST_STATE,
                MicrovmErrorCode::FailedPrecondition,
                "HV_ILLEGAL_GUEST_STATE",
            ),
            (
                HV_NO_RESOURCES,
                MicrovmErrorCode::ResourceExhausted,
                "HV_NO_RESOURCES",
            ),
            (
                HV_NO_DEVICE,
                MicrovmErrorCode::Unimplemented,
                "HV_NO_DEVICE",
            ),
            (HV_DENIED, MicrovmErrorCode::PermissionDenied, "HV_DENIED"),
            (HV_EXISTS, MicrovmErrorCode::AlreadyExists, "HV_EXISTS"),
            (
                HV_UNSUPPORTED,
                MicrovmErrorCode::Unimplemented,
                "HV_UNSUPPORTED",
            ),
        ];
        for (code, class, sym) in cases {
            let e = classify_hv_return(HvOp::VmMap, code).unwrap_err();
            assert_eq!(e.code(), class, "{sym}");
            assert_eq!(e.message(), format!("hv_vm_map returned {sym}"));
        }
    }

    #[test]
    fn mvm5_3783_classify_unknown_is_internal_without_number() {
        let e = classify_hv_return(HvOp::VmCreate, 0xfae9_4099_u32 as i32).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        assert_eq!(e.message(), "hv_vm_create returned an unknown hv_return_t");
        let e = classify_hv_return(HvOp::VmDestroy, 1).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
    }

    #[test]
    fn mvm5_3783_memory_flags_bits() {
        assert_eq!(MemoryFlags::READ.bits(), 1);
        assert_eq!(MemoryFlags::WRITE.bits(), 2);
        assert_eq!(MemoryFlags::EXEC.bits(), 4);
        assert_eq!(MemoryFlags::RWX.bits(), 7);
        assert_eq!(
            MemoryFlags::READ | MemoryFlags::WRITE | MemoryFlags::EXEC,
            MemoryFlags::RWX
        );
    }

    #[test]
    fn mvm5_3783_check_map_range_rejects_violations_for_both_page_sizes() {
        for page in [4096_u64, 16384] {
            let base = page * 8;
            assert!(check_map_range(base, 0x4000_0000, page, page).is_ok());
            let bad = [
                check_map_range(base + 0x800, 0x4000_0000, page, page),
                check_map_range(base, 0x4000_0000 + 0x800, page, page),
                check_map_range(base, 0x4000_0000, 0, page),
                check_map_range(base, 0x4000_0000, page / 2, page),
                check_map_range(base, 0x4000_0000, page + 0x800, page),
                check_map_range(u64::MAX - page + 1, 0x4000_0000, page * 2, page),
                check_map_range(base, u64::MAX - page + 1, page * 2, page),
            ];
            for r in bad {
                assert_eq!(r.unwrap_err().code(), MicrovmErrorCode::InvalidArgument);
            }
        }
    }

    #[test]
    fn mvm5_3783_check_map_range_0x1000_offset_on_16k_pages() {
        // 16 KiB ページでは 0x1000 のずれがページ境界違反になる。
        let e = check_map_range(0x1000, 0x4000_0000, 16384, 16384).unwrap_err();
        assert_eq!(e.message(), "host address is not page aligned");
        let e = check_map_range(0x4000, 0x4000_1000, 16384, 16384).unwrap_err();
        assert_eq!(e.message(), "guest address is not page aligned");
        // 4 KiB ページではページ未満の size を拒否する。
        let e = check_map_range(0x1000, 0x4000_0000, 0x800, 4096).unwrap_err();
        assert_eq!(e.message(), "size is not a multiple of the page size");
    }

    #[test]
    fn mvm5_3783_check_map_range_rejects_bad_page_size() {
        for page in [0_u64, 3] {
            let e = check_map_range(0, 0, 4096, page).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "page size is not a power of two");
        }
    }

    #[test]
    fn mvm5_3783_check_map_range_rejects_size_over_limit() {
        for page in [4096_u64, 16384] {
            assert_eq!(MAX_MAP_BYTES, 17_179_869_184);
            assert!(check_map_range(0, 0, MAX_MAP_BYTES, page).is_ok());
            let e = check_map_range(0, 0, MAX_MAP_BYTES + page, page).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "size exceeds the maximum mapping size");
        }
    }

    /// MVM-5・#3844: `HvVm::map` の検査は既定の IPA 上限を超える範囲を拒否する。
    #[test]
    fn mvm5_3844_check_vm_map_enforces_default_ipa_limit() {
        let exceeds = "guest range exceeds the ipa limit";
        for page in [4096_u64, 16384] {
            assert!(check_vm_map(0, 0x4000_0000, 4 << 20, page).is_ok());
            assert!(check_vm_map(0, HVF_DEFAULT_IPA_LIMIT - page, page, page).is_ok());
            for (ipa, size) in [
                (HVF_DEFAULT_IPA_LIMIT, page),
                (HVF_DEFAULT_IPA_LIMIT - page, 2 * page),
                (1_u64 << 40, page),
            ] {
                let e = check_vm_map(0, ipa, size, page).unwrap_err();
                assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
                assert_eq!(e.message(), exceeds);
            }
            // 範囲検査が IPA 上限より先に効く。
            let e = check_vm_map(0, HVF_DEFAULT_IPA_LIMIT + 1, page, page).unwrap_err();
            assert_eq!(e.message(), "guest address is not page aligned");
            let e = check_vm_map(0, 0, 0, page).unwrap_err();
            assert_eq!(e.message(), "size is zero");
        }
    }

    #[test]
    fn mvm5_3787_check_ipa_limit_boundaries() {
        assert_eq!(HVF_DEFAULT_IPA_LIMIT, 68_719_476_736);
        let lim = HVF_DEFAULT_IPA_LIMIT;
        assert!(check_ipa_limit(0x4000_0000, 4 << 20, lim).is_ok());
        assert!(check_ipa_limit(lim - 4096, 4096, lim).is_ok());
        let e = check_ipa_limit(lim - 4096, 4097, lim).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "guest range exceeds the ipa limit");
        let e = check_ipa_limit(u64::MAX - 4096, 8192, lim).unwrap_err();
        assert_eq!(e.message(), "guest range overflows the address space");
        for bad in [0, lim + 1] {
            let e = check_ipa_limit(0, 4096, bad).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "ipa limit is out of range");
        }
    }

    fn raw_exit(reason: u32) -> HvVcpuExitRaw {
        HvVcpuExitRaw {
            reason,
            exception: HvVcpuExitException {
                syndrome: 0x9200_0046,
                virtual_address: 0x1000,
                physical_address: 0x0900_0000,
            },
        }
    }

    #[test]
    fn mvm5_3786_decode_exit_known_reasons() {
        assert_eq!(decode_exit(&raw_exit(0)), HvVcpuExit::Canceled);
        assert_eq!(
            decode_exit(&raw_exit(1)),
            HvVcpuExit::Exception(HvVcpuExitException {
                syndrome: 0x9200_0046,
                virtual_address: 0x1000,
                physical_address: 0x0900_0000,
            })
        );
        assert_eq!(decode_exit(&raw_exit(2)), HvVcpuExit::VtimerActivated);
        assert_eq!(decode_exit(&raw_exit(3)), HvVcpuExit::Unknown(3));
    }

    #[test]
    fn mvm5_3786_decode_exit_unrecognized_values_are_kept() {
        for v in [4_u32, 0xdead_beef, u32::MAX] {
            assert_eq!(decode_exit(&raw_exit(v)), HvVcpuExit::Unknown(v));
        }
    }

    #[test]
    fn mvm5_3786_reg_values() {
        assert_eq!(HvReg::x(0).map(HvReg::bits), Some(0));
        assert_eq!(HvReg::x(30).map(HvReg::bits), Some(30));
        assert_eq!(HvReg::x(31), None);
        assert_eq!(HvReg::x(255), None);
        assert_eq!(HvReg::PC.bits(), 31);
        assert_eq!(HvReg::FPCR.bits(), 32);
        assert_eq!(HvReg::FPSR.bits(), 33);
        assert_eq!(HvReg::CPSR.bits(), 34);
    }

    #[test]
    fn mvm5_3786_sys_reg_encoding() {
        assert_eq!(HvSysReg::MPIDR_EL1.bits(), 0xc005);
        assert_eq!(HvSysReg::SCTLR_EL1.bits(), 0xc080);
        assert_eq!(HvSysReg::CNTV_CTL_EL0.bits(), 0xdf19);
        assert_eq!(HvSysReg::CNTV_CVAL_EL0.bits(), 0xdf1a);
    }

    #[test]
    fn mvm5_3786_interrupt_type_and_op_names() {
        assert_eq!(HvInterruptType::Irq.bits(), 0);
        assert_eq!(HvInterruptType::Fiq.bits(), 1);
        let e = classify_hv_return(HvOp::VcpuRun, HV_BAD_ARGUMENT).unwrap_err();
        assert_eq!(e.message(), "hv_vcpu_run returned HV_BAD_ARGUMENT");
        let e = classify_hv_return(HvOp::VcpusExit, HV_BUSY).unwrap_err();
        assert_eq!(e.message(), "hv_vcpus_exit returned HV_BUSY");
        let e = classify_hv_return(HvOp::VcpuSetPendingInterrupt, HV_BUSY).unwrap_err();
        assert_eq!(
            e.message(),
            "hv_vcpu_set_pending_interrupt returned HV_BUSY"
        );
    }

    #[test]
    fn mvm5_3786_check_run_deadline_bounds() {
        use std::time::Duration;
        assert!(check_run_deadline(Duration::from_millis(1)).is_ok());
        assert!(check_run_deadline(HV_RUN_DEADLINE_MAX).is_ok());
        for t in [
            Duration::ZERO,
            HV_RUN_DEADLINE_MAX + Duration::from_nanos(1),
        ] {
            assert_eq!(
                check_run_deadline(t).unwrap_err().code(),
                MicrovmErrorCode::InvalidArgument
            );
        }
    }

    #[test]
    fn mvm5_3786_finish_run_classifies_and_accumulates() {
        use std::time::Duration;
        let d = Duration::from_millis(5);
        let (r, rec1) = finish_run(Ok(HvVcpuExit::Canceled), true, d);
        assert_eq!(r.unwrap_err().code(), MicrovmErrorCode::DeadlineExceeded);
        assert_eq!(rec1.outcome, HvRunOutcome::DeadlineExceeded);
        let (r, rec2) = finish_run(Ok(HvVcpuExit::Canceled), false, d);
        assert_eq!(r.unwrap(), HvVcpuExit::Canceled);
        assert_eq!(rec2.outcome, HvRunOutcome::Exit("canceled"));
        let (_, rec3) = finish_run(Ok(HvVcpuExit::VtimerActivated), true, d);
        assert_eq!(rec3.outcome, HvRunOutcome::Exit("vtimer"));
        let (r, rec4) = finish_run(
            Err(MicrovmError::new(MicrovmErrorCode::Internal, "x")),
            false,
            d,
        );
        assert!(r.is_err());
        assert_eq!(
            rec4.outcome,
            HvRunOutcome::Error(MicrovmErrorCode::Internal)
        );
        let mut st = HvRunStats::default();
        for rec in [rec1, rec2, rec3, rec4] {
            st.add(&rec);
        }
        assert_eq!(
            st,
            HvRunStats {
                runs: 4,
                exits: 2,
                deadline_exceeded: 1,
                errors: 1,
                total_elapsed: Duration::from_millis(20),
            }
        );
    }

    #[test]
    fn mvm5_3789_parse_version_accepts_valid() {
        let v = |major, minor, patch| MacosVersion {
            major,
            minor,
            patch,
        };
        assert_eq!(parse_macos_product_version(b"15.0").unwrap(), v(15, 0, 0));
        assert_eq!(parse_macos_product_version(b"15.1.1").unwrap(), v(15, 1, 1));
        assert_eq!(parse_macos_product_version(b"26.0").unwrap(), v(26, 0, 0));
        assert_eq!(parse_macos_product_version(b"15.0\0").unwrap(), v(15, 0, 0));
        assert_eq!(parse_macos_product_version(b"14").unwrap(), v(14, 0, 0));
    }

    #[test]
    fn mvm5_3789_parse_version_rejects_malformed() {
        let mut long_ok = b"15.".to_vec();
        long_ok.extend(std::iter::repeat_n(b'0', 29));
        assert_eq!(long_ok.len(), MACOS_PRODUCT_VERSION_MAX_LEN);
        // 32 バイトちょうどは長さの検査を通って受理される（minor は 0）。
        assert_eq!(
            parse_macos_product_version(&long_ok).unwrap(),
            MacosVersion {
                major: 15,
                minor: 0,
                patch: 0
            }
        );
        let mut long_ng = long_ok.clone();
        long_ng.push(b'0');
        let cases: [&[u8]; 9] = [
            b"",
            b"\0",
            b"x.y",
            b"15.",
            b".1",
            b"1.2.3.4",
            b"99999999999.0",
            b"15.0\0\0",
            &long_ng,
        ];
        for raw in cases {
            let e = parse_macos_product_version(raw).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::Internal, "{raw:?}");
            assert_eq!(e.message(), "unexpected kern.osproductversion format");
        }
    }

    #[test]
    fn mvm5_3789_gic_requires_macos_15() {
        let v14 = parse_macos_product_version(b"14.7").unwrap();
        let e = check_gic_supported(v14).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Unimplemented);
        assert_eq!(e.message(), "hypervisor GIC requires macOS 15 or later");
        for raw in [&b"15.0"[..], b"15.1.1", b"26.0"] {
            assert!(check_gic_supported(parse_macos_product_version(raw).unwrap()).is_ok());
        }
    }

    #[test]
    fn mvm5_3974_ctlr_offset_value() {
        assert_eq!(GicDistributorReg::ctlr().bits(), 0);
    }

    #[test]
    fn mvm5_3960_irouter_offset_values() {
        assert_eq!(GicDistributorReg::irouter(32).unwrap().bits(), 0x6100);
        assert_eq!(GicDistributorReg::irouter(48).unwrap().bits(), 0x6180);
        assert_eq!(GicDistributorReg::irouter(1019).unwrap().bits(), 0x7FD8);
        for bad in [0, 31, 1020, u32::MAX] {
            let e = GicDistributorReg::irouter(bad).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "irouter intid is outside the spi range");
        }
    }

    #[test]
    fn mvm5_3960_decode_irouter_values() {
        assert_eq!(decode_irouter(0), IrouterRoute::Affinity(0));
        assert_eq!(decode_irouter(0x103), IrouterRoute::Affinity(0x103));
        assert_eq!(decode_irouter(0x8000_0000), IrouterRoute::AnyParticipating);
        assert_eq!(
            decode_irouter(0x0000_0001_0000_0002),
            IrouterRoute::Affinity(0x0100_0002)
        );
        assert_eq!(decode_irouter(0x0100_0000), IrouterRoute::Malformed);
        assert_eq!(decode_irouter(0x4000_0000), IrouterRoute::Malformed);
        assert_eq!(decode_irouter(1 << 40), IrouterRoute::Malformed);
        assert_eq!(decode_irouter(u64::MAX), IrouterRoute::Malformed);
    }

    #[test]
    fn mvm5_3789_gic_op_names_match_c_symbols() {
        let e = classify_hv_return(HvOp::GicCreate, HV_NO_RESOURCES).unwrap_err();
        assert_eq!(e.message(), "hv_gic_create returned HV_NO_RESOURCES");
        let e = classify_hv_return(HvOp::GicGetSpiInterruptRange, HV_UNSUPPORTED).unwrap_err();
        assert_eq!(
            e.message(),
            "hv_gic_get_spi_interrupt_range returned HV_UNSUPPORTED"
        );
        assert_eq!(GicIntid::new(27).get(), 27);
    }

    /// `HV_GIC_INT_EL1_VIRTUAL_TIMER` は SDK で 27。3 を渡すと実機で `HV_BAD_ARGUMENT` になる（#3803・#3989・MVM-5）。
    #[test]
    fn mvm5_3989_virtual_timer_selector_matches_sdk() {
        assert_eq!(HvGicIntid::EL1_VIRTUAL_TIMER.bits(), 27);
    }

    /// entitlements は XML コメントを持たず、キーは hypervisor の 1 つだけ（#3803・#3989・MVM-5）。
    ///
    /// コメント内の `--` は `codesign` が `AMFIUnserializeXML: syntax error` で拒否し、`plutil -lint` は通すため、
    /// 内容をここで照合する。実機で署名できたのはコメントなしの形なので、説明はコメントで足さない。
    #[test]
    fn mvm5_3989_entitlements_have_no_xml_comment() {
        let plist = include_str!("../tests/hvf.entitlements");
        assert!(
            !plist.contains("<!--"),
            "entitlements must not have an XML comment"
        );
        assert!(
            !plist.contains("--"),
            "entitlements must not contain a double hyphen"
        );
        assert_eq!(plist.matches("<key>").count(), 1);
        assert!(plist.contains("<key>com.apple.security.hypervisor</key>"));
    }

    // ---- check_assemble_input（TASK-192.15・#3797・MVM-5） ----

    fn ok_input() -> HvfAssembleInput {
        HvfAssembleInput {
            vcpus: 1,
            layout_vcpus: 1,
            ram_size: 64 << 20,
            layout_virtio_count: 1,
            device_count: 1,
            serial: false,
            layout_serial: false,
            image_len: 4096,
            initrd_len: None,
            cmdline_len: 0,
        }
    }

    fn assemble_err(i: HvfAssembleInput) -> (MicrovmErrorCode, &'static str) {
        let e = check_assemble_input(&i).unwrap_err();
        // 試験用に寿命を延ばす（リークは試験プロセスの終了で回収される）。
        (
            e.code(),
            Box::leak(e.message().to_string().into_boxed_str()),
        )
    }

    #[test]
    fn mvm5_3797_assemble_input_accepts_baseline() {
        assert!(check_assemble_input(&ok_input()).is_ok());
    }

    /// MVM-5・MVM-1・#3884: 上限ちょうどは受理、上限 + 1 と 0 は `InvalidArgument`。他の不正に隠れず最初に検査される。
    #[test]
    fn mvm5_3884_assemble_vcpus_bounds() {
        assert_eq!(HVF_MAX_VCPUS, 32);
        let mut i = ok_input();
        i.vcpus = HVF_MAX_VCPUS;
        i.layout_vcpus = HVF_MAX_VCPUS;
        assert!(check_assemble_input(&i).is_ok());
        i.vcpus = HVF_MAX_VCPUS + 1;
        i.layout_vcpus = HVF_MAX_VCPUS + 1;
        assert_eq!(
            assemble_err(i),
            (
                MicrovmErrorCode::InvalidArgument,
                "too many vcpus for the hvf backend"
            )
        );
        i.vcpus = 0;
        i.layout_vcpus = 0;
        assert_eq!(
            assemble_err(i),
            (MicrovmErrorCode::InvalidArgument, "vcpus is zero")
        );
        // 他の値も不正でも vcpus の拒否が優先される。
        i.vcpus = HVF_MAX_VCPUS + 1;
        i.ram_size = 0;
        i.image_len = 0;
        assert_eq!(
            assemble_err(i),
            (
                MicrovmErrorCode::InvalidArgument,
                "too many vcpus for the hvf backend"
            )
        );
    }

    /// MVM-5・MVM-1・#3884: 構成の vcpus と layout の vcpus が違えば、どちら向きでも `InvalidArgument`。
    #[test]
    fn mvm5_3884_assemble_vcpus_layout_mismatch() {
        let expected = (
            MicrovmErrorCode::InvalidArgument,
            "vcpu layout does not match the configuration",
        );
        let mut i = ok_input();
        i.vcpus = 2;
        i.layout_vcpus = 1;
        assert_eq!(assemble_err(i), expected);
        i.vcpus = 1;
        i.layout_vcpus = 2;
        assert_eq!(assemble_err(i), expected);
        i.vcpus = 2;
        i.layout_vcpus = 2;
        assert!(check_assemble_input(&i).is_ok());
    }

    #[test]
    fn mvm5_3797_assemble_ram_bounds() {
        let mut i = ok_input();
        i.ram_size = 0;
        assert_eq!(
            assemble_err(i),
            (
                MicrovmErrorCode::InvalidArgument,
                "guest ram size is out of range"
            )
        );
        i.ram_size = HVF_MAX_GUEST_RAM_BYTES;
        assert!(check_assemble_input(&i).is_ok());
        i.ram_size = HVF_MAX_GUEST_RAM_BYTES + 64 * 1024;
        assert_eq!(assemble_err(i).0, MicrovmErrorCode::InvalidArgument);
    }

    #[test]
    fn mvm5_3797_assemble_device_counts() {
        let mut i = ok_input();
        i.device_count = 33;
        i.layout_virtio_count = 33;
        assert_eq!(
            assemble_err(i),
            (MicrovmErrorCode::InvalidArgument, "too many virtio devices")
        );
        i.device_count = 32;
        i.layout_virtio_count = 32;
        assert!(check_assemble_input(&i).is_ok());
        i.layout_virtio_count = 1;
        assert_eq!(
            assemble_err(i),
            (
                MicrovmErrorCode::InvalidArgument,
                "device layout does not match the configuration"
            )
        );
    }

    /// MVM-5・MVM-1・#3882: シリアルは virtio と同じ MMIO 表を 1 枠使う。32 台 + シリアルは資源を作る前に拒否する。
    #[test]
    fn mvm5_3882_assemble_bus_limit_with_serial() {
        let mut i = ok_input();
        i.device_count = 32;
        i.layout_virtio_count = 32;
        i.serial = true;
        i.layout_serial = true;
        assert_eq!(
            assemble_err(i),
            (
                MicrovmErrorCode::InvalidArgument,
                "too many mmio bus devices"
            )
        );
        i.device_count = 31;
        i.layout_virtio_count = 31;
        assert!(check_assemble_input(&i).is_ok());
        i.device_count = 32;
        i.layout_virtio_count = 32;
        i.serial = false;
        i.layout_serial = false;
        assert!(check_assemble_input(&i).is_ok());
    }

    /// MVM-5・MVM-1・#3882: 設定とレイアウトのシリアルの有無の不一致は fail-closed。
    #[test]
    fn mvm5_3882_assemble_serial_layout_mismatch() {
        let msg = "serial layout does not match the configuration";
        let mut i = ok_input();
        i.serial = false;
        i.layout_serial = true;
        assert_eq!(assemble_err(i), (MicrovmErrorCode::InvalidArgument, msg));
        i.serial = true;
        i.layout_serial = false;
        assert_eq!(assemble_err(i), (MicrovmErrorCode::InvalidArgument, msg));
        i.layout_serial = true;
        assert!(check_assemble_input(&i).is_ok());
    }

    /// MVM-5・MVM-1・#3882: virtio の上限と MMIO 表の上限が食い違うと新しい検査が死ぬか前提が崩れるため、値を固定する。
    #[test]
    fn mvm5_3882_bus_limit_matches_virtio_max() {
        use crate::arm64_layout::ARM64_VIRTIO_MMIO_MAX;
        use crate::dispatch::MAX_BUS_DEVICES;
        assert_eq!(ARM64_VIRTIO_MMIO_MAX as usize, MAX_BUS_DEVICES);
        assert_eq!(MAX_BUS_DEVICES, 32);
    }

    #[test]
    fn mvm5_3797_assemble_image_initrd_cmdline_bounds() {
        use crate::boot_x86::{MAX_INITRD_BYTES, MAX_KERNEL_IMAGE_BYTES};
        let mut i = ok_input();
        i.image_len = 0;
        assert_eq!(
            assemble_err(i),
            (
                MicrovmErrorCode::InvalidArgument,
                "kernel image length is out of range"
            )
        );
        i.image_len = MAX_KERNEL_IMAGE_BYTES + 1;
        assert_eq!(assemble_err(i).0, MicrovmErrorCode::InvalidArgument);
        i.image_len = MAX_KERNEL_IMAGE_BYTES;
        assert!(check_assemble_input(&i).is_ok());
        i.initrd_len = Some(MAX_INITRD_BYTES + 1);
        assert_eq!(
            assemble_err(i),
            (
                MicrovmErrorCode::InvalidArgument,
                "initrd length is out of range"
            )
        );
        i.initrd_len = Some(MAX_INITRD_BYTES);
        assert!(check_assemble_input(&i).is_ok());
        i.cmdline_len = 2047;
        assert!(check_assemble_input(&i).is_ok());
        i.cmdline_len = 2048;
        assert_eq!(
            assemble_err(i),
            (
                MicrovmErrorCode::InvalidArgument,
                "kernel cmdline is too long"
            )
        );
    }
}
