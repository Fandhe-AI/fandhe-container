//! arm64 ゲストの物理アドレス配置と、その配置から作る FDT のノード生成（OS 非依存・`unsafe` なし）。
//!
//! 役割: RAM・GICv3（distributor / redistributor）・virtio-mmio の窓と SPI 番号を 1 か所で定め、
//! 同じ値から [`crate::fdt::FdtBuilder`] で arm64 ゲスト向けの FDT を組み立てる。
//! GIC 作成（#3792）・ゲスト RAM 登録（#3787）・Image/initrd/FDT 配置（#3790）・VM 組み立て（#3797）が
//! 同じ [`Arm64Layout`] を共有する前提で、macOS の Hypervisor.framework（TASK-192・MVM-5）と
//! 将来の KVM aarch64（#3696・MVM-1）の両方から使える。
//!
//! 契約（TASK-192.6・#3788・MVM-5・MVM-1・REPAIR-2）:
//! - 消費側は [`Arm64Layout::validate`] を先に呼ぶ。[`build_guest_fdt`] も内部で再実行する（fail-closed）。
//! - 違反は `InvalidArgument`。メッセージは固定の英語で入力をエコーしない。演算はすべて checked。
//! - GICD / GICR の基底は候補値である。アライン・大きさは [`Arm64Layout::check_gic_geometry`] が
//!   `hv_gic_get_distributor_base_alignment` 等の実値（[`GicGeometry`]）に対して検証する（#3792）。
//!   virtual timer の PPI は [`check_virtual_timer_intid`] が API の INTID と照合する。FDT を API の値から
//!   組み直さず照合で fail-closed にするのは、`build_guest_fdt` の署名変更を #3790・#3797 へ波及させないため。
//!
//! SMP とシリアル（#3864・MVM-5・MVM-1）:
//! - `cpus` には vCPU 数ぶんの `cpu@N` を出す。`reg` は [`arm64_vcpu_mpidr_affinity`]（Aff0 = n % 16、Aff1 = n / 16）。
//!   将来 HVF で SMP を作るときは、vCPU n の `MPIDR_EL1` にこの値を書く（GICv3 は redistributor を `GICR_TYPER` の
//!   affinity で引くため、FDT の値と一致している必要がある）。上限は [`ARM64_MAX_VCPUS`]。
//! - シリアルは `layout.serial` が `Some` のときだけ、8250 互換（`ns16550a`・`reg-shift = 0`・`reg-io-width = 1`）の
//!   MMIO ノードと `/chosen/stdout-path` を出す（実体の無いデバイスを FDT に載せない）。モデルは
//!   [`crate::uart::SerialConsole::mmio_device`]。PL011 は clock ノードと phandle が要り、既存モデルを流用できないため採らない。
//! - `interrupts` は level-high の SPI（[`ARM64_SERIAL_SPI`]）で出す（#3892・MVM-5・MVM-1）。線は `crate::uart` の
//!   THRE 状態から [`crate::interrupt::LevelInterruptLine`] で駆動する（macOS は `hv_gic_set_spi`）。トリガは
//!   `virtio_spi_trigger` と独立で常に level。SPI 番号は virtio の基点（既定 16）より下で重ならない
//!   （[`Arm64Layout::validate`] が重なりを拒否）。実ゲストでの確認は #3803。
//!
//! 未実装（REPAIR-3）: HVF の SMP（vCPU 1..N のスレッド・PSCI CPU_ON・`HVF_MAX_VCPUS` の引き上げ。バックエンドは 1 vCPU のまま。
//! N 個の cpu を持つ FDT が実ゲストに届くと Linux は「failed to boot CPUn」を出して 1 CPU で動き続ける）・
//! PCI・IPA 上限の確定（#3803）。
//!
//! virtio の通知方式（#3795・#3863）: 既定の FDT は edge-rising で、macOS の `hv_gic_set_spi(intid, true)` を 1 回呼べば
//! edge が 1 回立つ（edge の `false` は無視されるため deassert は不要）。`Arm64Layout::virtio_spi_trigger` を
//! `LevelHigh` にすると FDT が level-high になり、InterruptACK の後に線を下げる / 上げ直す必要がある
//! （`crate::interrupt::complete_interrupt_ack`）。FDT の trigger と線の注入方式の食い違いは
//! [`check_virtio_spi_injection`] が組み立て時に拒否する。SPI 番号が API の範囲内かは [`check_spi_intid`] が照合する。
//!
//! # 出典（Linux `Documentation/devicetree/bindings`）
//! `arm/psci.yaml`・`serial/8250.yaml`・`interrupt-controller/arm,gic-v3.yaml`・`timer/arm,arch_timer.yaml`・`virtio/mmio.yaml`・`arm/cpus.yaml`。
//! 割り込みセルの値は `include/dt-bindings/interrupt-controller/{arm-gic.h,irq.h}`。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::fdt::FdtBuilder;
use crate::guest_memory::GuestAddress;
use crate::hvf_abi::HVF_DEFAULT_IPA_LIMIT;
use crate::interrupt::IrqTrigger;
use crate::virtio_mmio::CONFIG_SPACE_SIZE;

/// RAM の基底（2 MiB 境界。arm64 の booting.rst のカーネル配置が依存する。配置は #3790）。
pub const ARM64_RAM_BASE: u64 = 0x4000_0000;
/// GICv3 distributor の基底（候補値）。
pub const ARM64_GIC_DIST_BASE: u64 = 0x0800_0000;
/// GICv3 distributor の大きさ（64 KiB）。
pub const ARM64_GIC_DIST_SIZE: u64 = 0x1_0000;
/// GICv3 redistributor の基底（候補値。2 MiB 境界に置き実機のアライン要件に通りやすくする）。
pub const ARM64_GIC_REDIST_BASE: u64 = 0x0820_0000;
/// vCPU ごとの redistributor の大きさ（RD_base + SGI_base の 2 × 64 KiB）。
pub const ARM64_GIC_REDIST_SIZE_PER_CPU: u64 = 0x2_0000;
/// virtio-mmio の窓の先頭。
pub const ARM64_VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
/// 8250 互換シリアルの MMIO 基底（GICR の最大終端の後ろ、virtio の窓の前。#3864）。
pub const ARM64_SERIAL_BASE: u64 = 0x0900_0000;
/// シリアルの窓の大きさ。
pub const ARM64_SERIAL_SIZE: u64 = 0x1000;
/// FDT の `clock-frequency`（標準の 8250 の 1.8432 MHz。ボーレートの除数計算用で、出力には影響しない）。
pub const ARM64_SERIAL_CLOCK_HZ: u32 = 1_843_200;
/// vCPU 数の上限。redistributor の窓が [`ARM64_SERIAL_BASE`] に収まる範囲で決める。
pub const ARM64_MAX_VCPUS: u32 = 64;
/// virtio-mmio の窓の刻み（設定空間 0x100 とレジスタ 0x100 を収める）。
pub const ARM64_VIRTIO_MMIO_STRIDE: u64 = 0x200;
/// virtio-mmio の個数の上限。macOS バックエンドでシリアルを有効にすると MMIO 表（`dispatch::MAX_BUS_DEVICES` = 32）を
/// 1 枠使うため、そのときの実効上限は 31（#3882・MVM-5。32 台はシリアルなしのときだけ）。
pub const ARM64_VIRTIO_MMIO_MAX: u32 = 32;
/// virtio-mmio の最初の SPI 番号（DT のセル値。GIC の INTID は 32 + n）。
pub const ARM64_VIRTIO_SPI_BASE: u32 = 16;
/// シリアルの SPI 番号（DT のセル値。INTID は 33）。virtio の基点（既定 16）より下で重ならない
/// （QEMU の virt の VIRT_UART と同じ慣行。#3892・MVM-5）。
pub const ARM64_SERIAL_SPI: u32 = 1;
/// 既定の IPA 上限（暫定。確定は #3803。KVM 経路は自分の値を `ipa_limit` に渡せる）。
pub const ARM64_DEFAULT_IPA_LIMIT: u64 = HVF_DEFAULT_IPA_LIMIT;
/// `cpu@0` の `reg`。#3797 が `MPIDR_EL1` の affinity をこの値から設定する。
pub const ARM64_BOOT_CPU_MPIDR: u32 = 0;
/// `intc` の phandle（`fdt` は採番しないため固定。0 と 0xffffffff は使わない）。
pub const ARM64_INTC_PHANDLE: u32 = 1;
/// bootargs 本文の最大バイト数。arm64 Linux の `COMMAND_LINE_SIZE`（2048）は NUL 終端を含む
/// バッファの大きさのため、保持できる本文は 2047 バイトまで（超えると末尾が切り捨てられる）。
pub const ARM64_MAX_BOOTARGS: usize = 2047;

const GIC_SPI: u32 = 0;
const GIC_PPI: u32 = 1;
const IRQ_TYPE_EDGE_RISING: u32 = 1;
/// GICv3 ドライバーが受理するのは LEVEL_HIGH か EDGE_RISING のみ（LEVEL_LOW は拒否される）。
const IRQ_TYPE_LEVEL_HIGH: u32 = 4;
/// PPI 番号を GIC の INTID へ直す加算値（INTID = 16 + PPI 番号）。
pub const ARM64_PPI_INTID_BASE: u32 = 16;
/// secure physical timer の PPI 番号（DT の `interrupts` 第 2 セル）。
pub const ARM64_TIMER_SEC_PHYS_PPI: u32 = 13;
/// non-secure physical timer の PPI 番号。
pub const ARM64_TIMER_PHYS_PPI: u32 = 14;
/// virtual timer の PPI 番号（INTID は 27）。`hv_gic_get_intid(EL1_VIRTUAL_TIMER)` と一致させる。
pub const ARM64_TIMER_VIRT_PPI: u32 = 11;
/// hypervisor timer の PPI 番号。
pub const ARM64_TIMER_HYP_PPI: u32 = 10;
/// timer の PPI 番号（arm,arch_timer の並び順。値と順序は変えない）。
/// virtual timer の一致は [`check_virtual_timer_intid`] が照合する（#3792）。
const TIMER_PPIS: [u32; 4] = [
    ARM64_TIMER_SEC_PHYS_PPI,
    ARM64_TIMER_PHYS_PPI,
    ARM64_TIMER_VIRT_PPI,
    ARM64_TIMER_HYP_PPI,
];
/// 注入方式を FDT の `interrupts` 第 3 セルへ写す（#3795・#3863）。既定は edge-rising で、macOS の
/// `hv_gic_set_spi(intid, level)` は edge なら `true` を 1 回渡せば発生する。level-high は opt-in
/// （[`Arm64Layout::virtio_spi_trigger`]）で、ACK 後の deassert / resample が要る（`crate::interrupt::complete_interrupt_ack`）。
const fn dt_irq_type(t: IrqTrigger) -> u32 {
    match t {
        IrqTrigger::EdgeRising => IRQ_TYPE_EDGE_RISING,
        IrqTrigger::LevelHigh => IRQ_TYPE_LEVEL_HIGH,
    }
}

/// FDT の trigger と線の注入方式が一致するか照合する（#3863・MVM-5）。不一致はゲストが ICFGR で選ぶ方式と
/// ホストの注入が食い違い、割り込みが失われる / 張り付くため、組み立て時に `InvalidArgument` で拒否する。
pub fn check_virtio_spi_injection(
    fdt: IrqTrigger,
    injection: IrqTrigger,
) -> Result<(), MicrovmError> {
    if fdt == injection {
        Ok(())
    } else {
        Err(invalid(
            "virtio spi injection does not match the guest fdt trigger",
        ))
    }
}
/// GICv3 の SPI 番号の上限（INTID 1019 - 32）。
const GIC_MAX_SPI_N: u32 = 987;
/// SPI の最小 INTID（INTID 0..=15 が SGI、16..=31 が PPI）。
const ARM64_SPI_INTID_BASE: u32 = 32;
const RAM_BASE_ALIGN: u64 = 2 * 1024 * 1024;
const RAM_SIZE_ALIGN: u64 = 64 * 1024;

const _: () = {
    assert!(ARM64_RAM_BASE.is_multiple_of(RAM_BASE_ALIGN));
    assert!(ARM64_GIC_DIST_BASE + ARM64_GIC_DIST_SIZE <= ARM64_GIC_REDIST_BASE);
    assert!(ARM64_GIC_REDIST_BASE < ARM64_VIRTIO_MMIO_BASE);
    assert!(
        ARM64_VIRTIO_MMIO_BASE + ARM64_VIRTIO_MMIO_STRIDE * ARM64_VIRTIO_MMIO_MAX as u64
            <= ARM64_RAM_BASE
    );
    assert!(ARM64_VIRTIO_MMIO_STRIDE >= CONFIG_SPACE_SIZE + 0x100);
    assert!(
        ARM64_GIC_REDIST_BASE + ARM64_GIC_REDIST_SIZE_PER_CPU * ARM64_MAX_VCPUS as u64
            <= ARM64_SERIAL_BASE
    );
    assert!(ARM64_SERIAL_BASE + ARM64_SERIAL_SIZE <= ARM64_VIRTIO_MMIO_BASE);
    assert!(ARM64_BOOT_CPU_MPIDR == 0);
    assert!(ARM64_SERIAL_SPI < ARM64_VIRTIO_SPI_BASE);
};

fn invalid(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, msg)
}

/// ゲスト物理アドレス空間の半開区間 `[base, base + size)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioRegion {
    /// 先頭。
    pub base: GuestAddress,
    /// 大きさ（バイト）。
    pub size: u64,
}

impl MmioRegion {
    /// 作る。
    pub const fn new(base: u64, size: u64) -> Self {
        Self {
            base: GuestAddress::new(base),
            size,
        }
    }
    /// 排他的終端。桁あふれは `None`。
    pub fn end(&self) -> Option<u64> {
        self.base.raw().checked_add(self.size)
    }
    fn overlaps(&self, other: &MmioRegion) -> bool {
        match (self.end(), other.end()) {
            (Some(ae), Some(be)) => self.base.raw() < be && other.base.raw() < ae,
            _ => true,
        }
    }
}

/// GIC の SPI 番号（DT の `interrupts` の第 2 セル）。INTID は 32 を足した値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestSpi(u32);

impl GuestSpi {
    /// DT のセル値（SPI 番号 n）。
    pub const fn dt_cell(self) -> u32 {
        self.0
    }
    /// GIC の INTID（32 + n）。`hv_gic_set_spi` に渡す値（#3795）。
    pub fn intid(self) -> Option<u32> {
        self.0.checked_add(ARM64_SPI_INTID_BASE)
    }
}

/// arm64 ゲストの物理アドレス配置。フィールドは異常系の試験のため pub。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm64Layout {
    /// ゲスト RAM。
    pub ram: MmioRegion,
    /// GICv3 distributor。
    pub gic_dist: MmioRegion,
    /// GICv3 redistributor（全 vCPU 分）。
    pub gic_redist: MmioRegion,
    /// virtio-mmio の窓の先頭。
    pub virtio_mmio_base: GuestAddress,
    /// 窓の刻み。
    pub virtio_mmio_stride: u64,
    /// virtio-mmio の個数。
    pub virtio_mmio_count: u32,
    /// 最初の SPI 番号。
    pub virtio_spi_base: u32,
    /// virtio の割り込みの trigger（FDT に書く値。既定は edge-rising。level は opt-in。#3863）。
    pub virtio_spi_trigger: IrqTrigger,
    /// vCPU 数。
    pub vcpus: u32,
    /// IPA 上限（排他的）。
    pub ipa_limit: u64,
    /// 8250 互換シリアルの MMIO 窓。`Some` のときだけ FDT に載せる（#3864）。
    pub serial: Option<MmioRegion>,
}

impl Arm64Layout {
    /// 既定の定数で組み、[`Self::validate`] を通して返す。
    pub fn new(ram_size: u64, vcpus: u32, virtio_mmio_count: u32) -> Result<Self, MicrovmError> {
        let redist = ARM64_GIC_REDIST_SIZE_PER_CPU
            .checked_mul(u64::from(vcpus))
            .ok_or_else(|| invalid("guest layout size overflow"))?;
        let layout = Self {
            ram: MmioRegion::new(ARM64_RAM_BASE, ram_size),
            gic_dist: MmioRegion::new(ARM64_GIC_DIST_BASE, ARM64_GIC_DIST_SIZE),
            gic_redist: MmioRegion::new(ARM64_GIC_REDIST_BASE, redist),
            virtio_mmio_base: GuestAddress::new(ARM64_VIRTIO_MMIO_BASE),
            virtio_mmio_stride: ARM64_VIRTIO_MMIO_STRIDE,
            virtio_mmio_count,
            virtio_spi_base: ARM64_VIRTIO_SPI_BASE,
            virtio_spi_trigger: IrqTrigger::EdgeRising,
            vcpus,
            ipa_limit: ARM64_DEFAULT_IPA_LIMIT,
            serial: None,
        };
        layout.validate()?;
        Ok(layout)
    }

    /// 既定の窓（[`ARM64_SERIAL_BASE`]・[`ARM64_SERIAL_SIZE`]）でシリアルを有効にし、[`Self::validate`] を通して返す。
    pub fn with_default_serial(mut self) -> Result<Self, MicrovmError> {
        self.serial = Some(MmioRegion::new(ARM64_SERIAL_BASE, ARM64_SERIAL_SIZE));
        self.validate()?;
        Ok(self)
    }

    fn virtio_window_all(&self) -> Result<MmioRegion, MicrovmError> {
        let size = self
            .virtio_mmio_stride
            .checked_mul(u64::from(self.virtio_mmio_count))
            .ok_or_else(|| invalid("guest layout size overflow"))?;
        Ok(MmioRegion {
            base: self.virtio_mmio_base,
            size,
        })
    }

    /// シリアルの SPI（`serial` が `Some` のときだけ。#3892）。
    pub fn serial_spi(&self) -> Option<GuestSpi> {
        self.serial.map(|_| GuestSpi(ARM64_SERIAL_SPI))
    }

    /// シリアルの SPI が API の範囲に収まるか検査する（VM 作成の前に呼ぶ。`serial` 無しは常に `Ok`。#3892）。
    pub fn check_serial_spi_range(
        &self,
        range_base: u32,
        range_count: u32,
    ) -> Result<(), MicrovmError> {
        let Some(spi) = self.serial_spi() else {
            return Ok(());
        };
        check_spi_intid(spi, range_base, range_count).map_err(|e| {
            if e.code() == MicrovmErrorCode::InvalidArgument {
                invalid("serial spi intid is outside the gic spi range")
            } else {
                e
            }
        })?;
        Ok(())
    }

    /// 配置の整合を検査する（0 長・桁あふれ・アライン・IPA 上限・個数・SPI 範囲・領域の重なり）。
    pub fn validate(&self) -> Result<(), MicrovmError> {
        if self.ram.size == 0 {
            return Err(invalid("guest ram size must be non-zero"));
        }
        if self.gic_dist.size == 0 || self.gic_redist.size == 0 {
            return Err(invalid("gic region size must be non-zero"));
        }
        if !self.ram.base.raw().is_multiple_of(RAM_BASE_ALIGN) {
            return Err(invalid("guest ram base must be 2 MiB aligned"));
        }
        if !self.ram.size.is_multiple_of(RAM_SIZE_ALIGN) {
            return Err(invalid("guest ram size must be a multiple of 64 KiB"));
        }
        if self.vcpus == 0 {
            return Err(invalid("vcpu count must be non-zero"));
        }
        if self.vcpus > ARM64_MAX_VCPUS {
            return Err(invalid("too many vcpus"));
        }
        if matches!(self.serial, Some(r) if r.size == 0) {
            return Err(invalid("serial region size must be non-zero"));
        }
        // UART モデルは offset 0..UART_PORT_LEN を使う。窓が短いと LSR 等が広告領域の外になる（MVM-5・REPAIR-2）。
        if matches!(self.serial, Some(r) if r.size < u64::from(crate::uart::UART_PORT_LEN)) {
            return Err(invalid(
                "serial region is smaller than the uart register window",
            ));
        }
        let need = ARM64_GIC_REDIST_SIZE_PER_CPU
            .checked_mul(u64::from(self.vcpus))
            .ok_or_else(|| invalid("guest layout size overflow"))?;
        if self.gic_redist.size < need {
            return Err(invalid("gic redistributor region is too small"));
        }
        if self.virtio_mmio_count > ARM64_VIRTIO_MMIO_MAX {
            return Err(invalid("too many virtio-mmio devices"));
        }
        if self.virtio_mmio_stride < CONFIG_SPACE_SIZE + 0x100 {
            return Err(invalid("virtio-mmio stride is too small"));
        }
        let last_spi = self
            .virtio_spi_base
            .checked_add(self.virtio_mmio_count)
            .ok_or_else(|| invalid("guest layout size overflow"))?;
        if last_spi > GIC_MAX_SPI_N + 1 {
            return Err(invalid("virtio spi number exceeds the gic range"));
        }
        // シリアルの SPI が virtio の範囲と重なると同じ INTID を共有する（#3892）。
        if self.serial.is_some()
            && ARM64_SERIAL_SPI >= self.virtio_spi_base
            && ARM64_SERIAL_SPI < last_spi
        {
            return Err(invalid("serial spi overlaps the virtio spi range"));
        }
        if self.ipa_limit == 0 {
            return Err(invalid("ipa limit must be non-zero"));
        }
        let virtio = self.virtio_window_all()?;
        let mut regions = vec![self.ram, self.gic_dist, self.gic_redist];
        if self.virtio_mmio_count > 0 {
            regions.push(virtio);
        }
        if let Some(serial) = self.serial {
            regions.push(serial);
        }
        for r in &regions {
            match r.end() {
                None => return Err(invalid("guest layout size overflow")),
                Some(e) if e > self.ipa_limit => {
                    return Err(invalid("guest layout exceeds the ipa limit"));
                }
                Some(_) => {}
            }
        }
        for (i, a) in regions.iter().enumerate() {
            for b in regions.iter().skip(i + 1) {
                if a.overlaps(b) {
                    return Err(invalid("guest layout regions overlap"));
                }
            }
        }
        Ok(())
    }
}

/// フレームワークが返す GIC の大きさとアライン（`hv_gic_get_*` の値。usize から u64 へ直したもの）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GicGeometry {
    /// distributor の大きさ。
    pub dist_size: u64,
    /// distributor の base のアライン。
    pub dist_align: u64,
    /// vCPU 1 台分の redistributor の大きさ（Apple のドキュメントからの読み。全体の値でも現状は vCPU = 1 で判定が同じ。確定は #3803）。
    pub redist_size_per_cpu: u64,
    /// redistributor の base のアライン。
    pub redist_align: u64,
}

/// [`check_gic_region`] が出すメッセージの出し分け。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicRegionKind {
    /// distributor。
    Distributor,
    /// redistributor。
    Redistributor,
}

/// 窓 `region` が、API の要求（`required` バイト・`align` アライン）を満たすか検査する（純関数）。
///
/// アライン 0・2 の冪でない・要求 0 はフレームワークの異常値として `Internal`。
/// base のずれ・窓の不足・桁あふれは配置の違反として `InvalidArgument`。メッセージは固定で入力をエコーしない。
pub fn check_gic_region(
    region: MmioRegion,
    required: u64,
    align: u64,
    kind: GicRegionKind,
) -> Result<(), MicrovmError> {
    let internal = |m: &'static str| MicrovmError::new(MicrovmErrorCode::Internal, m);
    if align == 0 || !align.is_power_of_two() {
        return Err(internal(
            "gic alignment reported by the hypervisor is invalid",
        ));
    }
    if required == 0 {
        return Err(internal("gic size reported by the hypervisor is zero"));
    }
    if region.end().is_none() {
        return Err(invalid("guest layout size overflow"));
    }
    if !region.base.raw().is_multiple_of(align) {
        return Err(invalid(match kind {
            GicRegionKind::Distributor => "gic distributor base is not aligned",
            GicRegionKind::Redistributor => "gic redistributor base is not aligned",
        }));
    }
    if required > region.size {
        return Err(invalid(match kind {
            GicRegionKind::Distributor => "gic distributor region is too small",
            GicRegionKind::Redistributor => "gic redistributor region is too small",
        }));
    }
    Ok(())
}

/// `intid`（`hv_gic_get_intid(EL1_VIRTUAL_TIMER)` の値）が FDT の virtual timer の PPI と一致するか照合する。
/// 不一致は `Internal`（ゲストを起動させない）。
pub fn check_virtual_timer_intid(intid: u32) -> Result<(), MicrovmError> {
    if intid != ARM64_PPI_INTID_BASE + ARM64_TIMER_VIRT_PPI {
        return Err(MicrovmError::new(
            MicrovmErrorCode::Internal,
            "virtual timer intid does not match the guest fdt",
        ));
    }
    Ok(())
}

/// `spi` の INTID が `hv_gic_get_spi_interrupt_range` の範囲 `[range_base, range_base + range_count)` に
/// 収まるか検査し、INTID を返す（純関数。#3795・MVM-5）。
///
/// 範囲そのものの異常（0 件・INTID 32 未満・桁あふれ）はフレームワークの異常値として `Internal`、
/// INTID の桁あふれと範囲外は `InvalidArgument`。メッセージは固定の英語で入力をエコーしない。
pub fn check_spi_intid(
    spi: GuestSpi,
    range_base: u32,
    range_count: u32,
) -> Result<u32, MicrovmError> {
    let internal = |m: &'static str| MicrovmError::new(MicrovmErrorCode::Internal, m);
    let range_end = range_base
        .checked_add(range_count)
        .filter(|_| range_count != 0 && range_base >= ARM64_SPI_INTID_BASE)
        .ok_or_else(|| internal("gic spi range reported by the hypervisor is invalid"))?;
    let intid = spi
        .intid()
        .ok_or_else(|| invalid("virtio spi intid overflows"))?;
    if intid < range_base || intid >= range_end {
        return Err(invalid("virtio spi intid is outside the gic spi range"));
    }
    Ok(intid)
}

impl Arm64Layout {
    /// 線の注入方式が FDT の trigger（[`Self::virtio_spi_trigger`]）と一致するか照合する（#3863）。
    pub fn check_virtio_injection(&self, injection: IrqTrigger) -> Result<(), MicrovmError> {
        check_virtio_spi_injection(self.virtio_spi_trigger, injection)
    }

    /// 全 virtio-mmio の SPI が API の範囲に収まるか検査する（VM 作成の前に呼ぶ。#3795・MVM-5）。
    pub fn check_virtio_spi_range(
        &self,
        range_base: u32,
        range_count: u32,
    ) -> Result<(), MicrovmError> {
        for index in 0..self.virtio_mmio_count {
            check_spi_intid(self.virtio_spi(index)?, range_base, range_count)?;
        }
        Ok(())
    }

    /// 配置が GIC の実値 `g` を満たすか検査する（VM 作成の前に呼ぶ。#3792・MVM-5）。
    ///
    /// 先に [`Self::validate`] を通す。窓の重なりと IPA 上限は `validate` が窓の大きさで検査済みで、
    /// ここで「API の要求 <= 窓」を確かめるため、要求範囲も窓の内側に収まる。
    pub fn check_gic_geometry(&self, g: &GicGeometry) -> Result<(), MicrovmError> {
        self.validate()?;
        check_gic_region(
            self.gic_dist,
            g.dist_size,
            g.dist_align,
            GicRegionKind::Distributor,
        )?;
        let required = g
            .redist_size_per_cpu
            .checked_mul(u64::from(self.vcpus))
            .ok_or_else(|| invalid("guest layout size overflow"))?;
        check_gic_region(
            self.gic_redist,
            required,
            g.redist_align,
            GicRegionKind::Redistributor,
        )
    }
}

impl Arm64Layout {
    /// `index` 番目の virtio-mmio の窓（#3797 のディスパッチャ登録が同じ値を使う）。
    pub fn virtio_mmio_window(&self, index: u32) -> Result<MmioRegion, MicrovmError> {
        if index >= self.virtio_mmio_count {
            return Err(invalid("virtio-mmio index out of range"));
        }
        let off = self
            .virtio_mmio_stride
            .checked_mul(u64::from(index))
            .ok_or_else(|| invalid("guest layout size overflow"))?;
        let base = self
            .virtio_mmio_base
            .checked_add(off)
            .ok_or_else(|| invalid("guest layout size overflow"))?;
        Ok(MmioRegion {
            base,
            size: self.virtio_mmio_stride,
        })
    }

    /// `index` 番目の virtio-mmio の SPI。
    pub fn virtio_spi(&self, index: u32) -> Result<GuestSpi, MicrovmError> {
        if index >= self.virtio_mmio_count {
            return Err(invalid("virtio-mmio index out of range"));
        }
        self.virtio_spi_base
            .checked_add(index)
            .map(GuestSpi)
            .ok_or_else(|| invalid("guest layout size overflow"))
    }
}

/// [`build_guest_fdt`] の入力。
#[derive(Debug, Clone, Copy)]
pub struct GuestFdtConfig<'a> {
    /// 配置。
    pub layout: &'a Arm64Layout,
    /// カーネルのコマンドライン。
    pub bootargs: &'a str,
    /// initrd の範囲 `[start, start + size)`（`linux,initrd-end` は排他的終端）。
    /// カーネル / FDT との重なりは #3790 の配置の責務。
    pub initrd: Option<MmioRegion>,
}

/// vCPU `index` の MPIDR affinity（`MPIDR` の下位 24 ビット。Aff0 = index % 16、Aff1 = index / 16）。
///
/// GICv3 の SGI の TargetList は 16 ビットで、1 クラスタの Aff0 は 0..15 に限る（KVM の既定の割り当てと同形）。
/// FDT の `cpu@N` の `reg` と、将来の vCPU の `MPIDR_EL1` はこの値で一致させる（#3864・MVM-5）。
/// `index >= ARM64_MAX_VCPUS` は `InvalidArgument`。
pub fn arm64_vcpu_mpidr_affinity(index: u32) -> Result<u32, MicrovmError> {
    if index >= ARM64_MAX_VCPUS {
        return Err(invalid("vcpu index out of range"));
    }
    Ok(((index / 16) << 8) | (index % 16))
}

/// シリアルのノード名（`serial@<base>`）。`stdout-path` と同じ値から作り、食い違わせない。
fn serial_node_name(r: &MmioRegion) -> String {
    format!("serial@{:x}", r.base.raw())
}

fn hi_lo(v: u64) -> [u32; 2] {
    [(v >> 32) as u32, v as u32]
}

fn reg_cells(regions: &[(u64, u64)]) -> Vec<u32> {
    let mut cells = Vec::with_capacity(regions.len() * 4);
    for (b, s) in regions {
        cells.extend_from_slice(&hi_lo(*b));
        cells.extend_from_slice(&hi_lo(*s));
    }
    cells
}

/// arm64 ゲスト向けの FDT を組み立てる（ルート・chosen・memory・cpus・psci・GICv3・timer・シリアル・virtio-mmio）。
///
/// `InvalidArgument`: 配置の違反（vCPU 数の上限超過を含む）・bootargs 超過・initrd が RAM の外。
/// `cpu@N` は vCPU 数ぶん出す（HVF のバックエンドは 1 vCPU のまま。REPAIR-3）。
/// `layout.serial` が `Some` のときだけ、シリアルのノードと `/chosen/stdout-path` を出す（`None` は従来と同じ出力）。
pub fn build_guest_fdt(config: &GuestFdtConfig<'_>) -> Result<Vec<u8>, MicrovmError> {
    let l = config.layout;
    l.validate()?;
    if config.bootargs.len() > ARM64_MAX_BOOTARGS {
        return Err(invalid("bootargs too long"));
    }
    let initrd = match config.initrd {
        None => None,
        Some(r) => {
            let end = r.end().ok_or_else(|| invalid("initrd range overflow"))?;
            let ram_end = l
                .ram
                .end()
                .ok_or_else(|| invalid("guest layout size overflow"))?;
            if r.size == 0 || r.base.raw() < l.ram.base.raw() || end > ram_end {
                return Err(invalid("initrd must be non-empty and inside guest ram"));
            }
            Some((r.base.raw(), end))
        }
    };

    let mut b = FdtBuilder::new();
    b.begin_node("")?;
    b.property_u32("#address-cells", 2)?;
    b.property_u32("#size-cells", 2)?;
    b.property_string("compatible", "linux,dummy-virt")?;
    b.property_u32("interrupt-parent", ARM64_INTC_PHANDLE)?;

    b.begin_node("chosen")?;
    b.property_string("bootargs", config.bootargs)?;
    if let Some((start, end)) = initrd {
        b.property_u64("linux,initrd-start", start)?;
        b.property_u64("linux,initrd-end", end)?;
    }
    if let Some(serial) = &l.serial {
        // aliases は作らない。of_console_check は 8250 の最初の line（ttyS0）で照合が成り立つ。
        b.property_string("stdout-path", &format!("/{}", serial_node_name(serial)))?;
    }
    b.end_node()?;

    b.begin_node(&format!("memory@{:x}", l.ram.base.raw()))?;
    b.property_string("device_type", "memory")?;
    b.property_cells("reg", &reg_cells(&[(l.ram.base.raw(), l.ram.size)]))?;
    b.end_node()?;

    // arm/cpus.yaml: #address-cells = 1・#size-cells = 0 が無いと cpu@0 の reg を読めない。
    b.begin_node("cpus")?;
    b.property_u32("#address-cells", 1)?;
    b.property_u32("#size-cells", 0)?;
    for n in 0..l.vcpus {
        let mpidr = arm64_vcpu_mpidr_affinity(n)?;
        b.begin_node(&format!("cpu@{mpidr:x}"))?;
        b.property_string("device_type", "cpu")?;
        b.property_string("compatible", "arm,arm-v8")?;
        b.property_string("enable-method", "psci")?;
        b.property_cells("reg", &[mpidr])?;
        b.end_node()?;
    }
    b.end_node()?;

    // arm/psci.yaml: method = "hvc"。HVC の exit は VMM（vCPU ループ）が処理する。
    b.begin_node("psci")?;
    b.property_string_list("compatible", &["arm,psci-1.0", "arm,psci-0.2"])?;
    b.property_string("method", "hvc")?;
    b.end_node()?;

    // interrupt-controller/arm,gic-v3.yaml。unit address は最初の reg（GICD）。
    b.begin_node(&format!("intc@{:x}", l.gic_dist.base.raw()))?;
    b.property_string("compatible", "arm,gic-v3")?;
    b.property_u32("#interrupt-cells", 3)?;
    b.property_empty("interrupt-controller")?;
    b.property_cells(
        "reg",
        &reg_cells(&[
            (l.gic_dist.base.raw(), l.gic_dist.size),
            (l.gic_redist.base.raw(), l.gic_redist.size),
        ]),
    )?;
    b.property_u32("phandle", ARM64_INTC_PHANDLE)?;
    b.end_node()?;

    // timer/arm,arch_timer.yaml。GICv3 は CPU マスクのビットを持たない。
    let mut irq = Vec::with_capacity(12);
    for ppi in TIMER_PPIS {
        irq.extend_from_slice(&[GIC_PPI, ppi, IRQ_TYPE_LEVEL_HIGH]);
    }
    b.begin_node("timer")?;
    b.property_string("compatible", "arm,armv8-timer")?;
    b.property_cells("interrupts", &irq)?;
    b.end_node()?;

    // serial/8250.yaml。interrupts は level-high の SPI（モジュール doc 参照）。
    if let Some(serial) = &l.serial {
        b.begin_node(&serial_node_name(serial))?;
        b.property_string("compatible", "ns16550a")?;
        b.property_cells("reg", &reg_cells(&[(serial.base.raw(), serial.size)]))?;
        b.property_u32("reg-shift", 0)?;
        b.property_u32("reg-io-width", 1)?;
        b.property_u32("clock-frequency", ARM64_SERIAL_CLOCK_HZ)?;
        b.property_cells(
            "interrupts",
            &[GIC_SPI, ARM64_SERIAL_SPI, IRQ_TYPE_LEVEL_HIGH],
        )?;
        b.end_node()?;
    }

    // virtio/mmio.yaml。
    for i in 0..l.virtio_mmio_count {
        let w = l.virtio_mmio_window(i)?;
        let spi = l.virtio_spi(i)?;
        b.begin_node(&format!("virtio_mmio@{:x}", w.base.raw()))?;
        b.property_string("compatible", "virtio,mmio")?;
        b.property_cells("reg", &reg_cells(&[(w.base.raw(), w.size)]))?;
        b.property_cells(
            "interrupts",
            &[GIC_SPI, spi.dt_cell(), dt_irq_type(l.virtio_spi_trigger)],
        )?;
        b.property_empty("dma-coherent")?;
        b.end_node()?;
    }

    b.end_node()?;
    b.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    /// MVM-5・MVM-1: FDT の trigger と注入方式が食い違うと `InvalidArgument`、一致なら通る（#3863）。
    #[test]
    fn mvm5_3863_injection_mismatch_rejected() {
        use IrqTrigger::{EdgeRising, LevelHigh};
        for (fdt, inj) in [(LevelHigh, EdgeRising), (EdgeRising, LevelHigh)] {
            let e = check_virtio_spi_injection(fdt, inj).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        }
        assert!(check_virtio_spi_injection(EdgeRising, EdgeRising).is_ok());
        assert!(check_virtio_spi_injection(LevelHigh, LevelHigh).is_ok());
        let mut l = Arm64Layout::new(4 * MIB, 1, 1).unwrap();
        assert!(l.check_virtio_injection(EdgeRising).is_ok());
        assert!(l.check_virtio_injection(LevelHigh).is_err());
        l.virtio_spi_trigger = LevelHigh;
        assert!(l.check_virtio_injection(LevelHigh).is_ok());
    }

    /// MVM-5・MVM-1: SPI の INTID が範囲の境界で具体的に判定される（#3795）。
    #[test]
    fn mvm5_3795_spi_intid_range_boundaries() {
        let l = Arm64Layout::new(4 * MIB, 1, 20).unwrap();
        let spi = |i: u32| l.virtio_spi(i).unwrap();
        // 既定の SPI 基点 16（INTID 48）。範囲 [48, 52)。
        assert_eq!(check_spi_intid(spi(0), 48, 4).unwrap(), 48);
        assert_eq!(check_spi_intid(spi(3), 48, 4).unwrap(), 51);
        assert_eq!(
            check_spi_intid(spi(4), 48, 4).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        // 範囲の下側（base=49 のとき INTID 48 は外）。
        assert_eq!(
            check_spi_intid(spi(0), 49, 4).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        // 典型の範囲 [32, 1020)。
        let mut m = l.clone();
        m.virtio_spi_base = 987 - 1;
        assert_eq!(
            check_spi_intid(m.virtio_spi(0).unwrap(), 32, 988).unwrap(),
            1018
        );
        assert_eq!(
            check_spi_intid(m.virtio_spi(1).unwrap(), 32, 988).unwrap(),
            1019
        );
        assert_eq!(
            check_spi_intid(m.virtio_spi(2).unwrap(), 32, 988)
                .unwrap_err()
                .code(),
            MicrovmErrorCode::InvalidArgument
        );
    }

    /// MVM-5: フレームワークの範囲の異常は `Internal`、INTID の桁あふれは `InvalidArgument`（#3795）。
    #[test]
    fn mvm5_3795_spi_intid_rejects_abnormal_range_and_overflow() {
        let l = Arm64Layout::new(4 * MIB, 1, 1).unwrap();
        let spi = l.virtio_spi(0).unwrap();
        for (base, count) in [(48, 0), (31, 10), (u32::MAX, 2)] {
            assert_eq!(
                check_spi_intid(spi, base, count).unwrap_err().code(),
                MicrovmErrorCode::Internal,
                "base={base} count={count}"
            );
        }
        let mut m = l.clone();
        m.virtio_spi_base = u32::MAX - 31;
        let huge = m.virtio_spi(0).unwrap();
        assert_eq!(huge.intid(), None);
        assert_eq!(
            check_spi_intid(huge, 32, 988).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
    }

    /// MVM-5: 既定配置の最初の virtio は INTID 48 で、範囲外の配置は事前検査で拒否される（#3795）。
    #[test]
    fn mvm5_3795_default_layout_virtio_intid_is_48() {
        let l = Arm64Layout::new(4 * MIB, 1, 4).unwrap();
        assert_eq!(l.virtio_spi(0).unwrap().intid(), Some(48));
        assert!(l.check_virtio_spi_range(32, 988).is_ok());
        assert!(l.check_virtio_spi_range(48, 4).is_ok());
        assert_eq!(
            l.check_virtio_spi_range(48, 3).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        // virtio が 0 台なら範囲の照合は対象が無く成功する。
        let none = Arm64Layout::new(4 * MIB, 1, 0).unwrap();
        assert!(none.check_virtio_spi_range(1000, 4).is_ok());
    }

    /// MVM-5: 既定配置の値。
    #[test]
    fn mvm5_3788_default_layout_values() {
        let l = Arm64Layout::new(256 * MIB, 1, 2).unwrap();
        assert_eq!(l.ram.base.raw(), 0x4000_0000);
        assert_eq!(l.ram.end(), Some(0x5000_0000));
        assert_eq!(l.gic_redist.size, 0x2_0000);
        assert_eq!(l.virtio_mmio_window(1).unwrap().base.raw(), 0x0a00_0200);
        assert_eq!(l.virtio_spi(1).unwrap().dt_cell(), 17);
        assert_eq!(l.virtio_spi(0).unwrap().intid(), Some(48));
        assert_eq!(l.virtio_spi(1).unwrap().intid(), Some(49));
        assert!(l.virtio_spi(2).is_err());
        assert_eq!(ARM64_DEFAULT_IPA_LIMIT, 1 << 36);
    }

    fn expect_invalid(l: &Arm64Layout, msg: &str) {
        let e = l.validate().unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), msg);
    }

    /// MVM-5: validate の各分岐。
    #[test]
    fn mvm5_3788_validate_rejects() {
        let base = Arm64Layout::new(256 * MIB, 1, 2).unwrap();
        let mut l = base.clone();
        l.ram.size = 0;
        expect_invalid(&l, "guest ram size must be non-zero");
        let mut l = base.clone();
        l.ram.base = GuestAddress::new(0x4000_1000);
        expect_invalid(&l, "guest ram base must be 2 MiB aligned");
        let mut l = base.clone();
        l.ram.size = 0x1_0001;
        expect_invalid(&l, "guest ram size must be a multiple of 64 KiB");
        // RAM と GICD の重なり。
        let mut l = base.clone();
        l.ram.base = GuestAddress::new(0x0800_0000);
        expect_invalid(&l, "guest layout regions overlap");
        // virtio 窓と GICR の重なり。
        let mut l = base.clone();
        l.virtio_mmio_base = GuestAddress::new(0x0820_0000);
        expect_invalid(&l, "guest layout regions overlap");
        // IPA 上限: ちょうどは成功、1 バイト超は失敗。
        let mut l = base.clone();
        l.ipa_limit = 0x5000_0000;
        assert!(l.validate().is_ok());
        l.ipa_limit = 0x4fff_ffff;
        expect_invalid(&l, "guest layout exceeds the ipa limit");
        l.ipa_limit = 0;
        expect_invalid(&l, "ipa limit must be non-zero");
        let mut l = base.clone();
        l.virtio_mmio_count = 33;
        expect_invalid(&l, "too many virtio-mmio devices");
        let mut l = base.clone();
        l.virtio_spi_base = 987;
        expect_invalid(&l, "virtio spi number exceeds the gic range");
        let mut l = base.clone();
        l.virtio_spi_base = u32::MAX;
        expect_invalid(&l, "guest layout size overflow");
        let mut l = base.clone();
        l.vcpus = 0;
        expect_invalid(&l, "vcpu count must be non-zero");
        let mut l = base;
        l.virtio_mmio_stride = 0x100;
        expect_invalid(&l, "virtio-mmio stride is too small");
    }

    /// MVM-5: SMP（2 vCPU は受理）と bootargs・initrd の検査。
    #[test]
    fn mvm5_3788_fdt_input_checks() {
        let two = Arm64Layout::new(256 * MIB, 2, 0).unwrap();
        let cfg = GuestFdtConfig {
            layout: &two,
            bootargs: "",
            initrd: None,
        };
        assert!(build_guest_fdt(&cfg).is_ok());
        let one = Arm64Layout::new(256 * MIB, 1, 0).unwrap();
        // 境界値: 2047 バイトは受理し、2048 バイト（NUL 終端を含めると 2049）は拒否する。
        assert_eq!(ARM64_MAX_BOOTARGS, 2047);
        let ok = "a".repeat(2047);
        let cfg = GuestFdtConfig {
            layout: &one,
            bootargs: &ok,
            initrd: None,
        };
        assert!(build_guest_fdt(&cfg).is_ok());
        let long = "a".repeat(2048);
        let cfg = GuestFdtConfig {
            layout: &one,
            bootargs: &long,
            initrd: None,
        };
        assert_eq!(
            build_guest_fdt(&cfg).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        for initrd in [
            MmioRegion::new(0x4800_0000, 0),
            MmioRegion::new(0x5000_0000 - 0x10, 0x20),
            MmioRegion::new(0x3000_0000, 0x1000),
        ] {
            let cfg = GuestFdtConfig {
                layout: &one,
                bootargs: "",
                initrd: Some(initrd),
            };
            assert_eq!(
                build_guest_fdt(&cfg).unwrap_err().code(),
                MicrovmErrorCode::InvalidArgument
            );
        }
    }

    fn geom() -> GicGeometry {
        GicGeometry {
            dist_size: 0x1_0000,
            dist_align: 0x1_0000,
            redist_size_per_cpu: 0x2_0000,
            redist_align: 0x2_0000,
        }
    }

    /// MVM-5: 既定配置と想定の実値の組は通る。
    #[test]
    fn mvm5_3792_default_layout_accepts_expected_geometry() {
        let l = Arm64Layout::new(256 * MIB, 1, 2).unwrap();
        assert!(l.check_gic_geometry(&geom()).is_ok());
    }

    fn region(base: u64, size: u64) -> MmioRegion {
        MmioRegion::new(base, size)
    }

    /// MVM-5: アラインの境界（base ±1）。
    #[test]
    fn mvm5_3792_region_alignment_boundaries() {
        use GicRegionKind::Distributor as D;
        assert!(check_gic_region(region(0x0800_0000, 0x1_0000), 0x1_0000, 0x1_0000, D).is_ok());
        for base in [0x0800_0001, 0x07ff_ffff] {
            let e = check_gic_region(region(base, 0x1_0000), 0x1_0000, 0x1_0000, D).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "gic distributor base is not aligned");
        }
        let e = check_gic_region(
            region(0x0820_0001, 0x2_0000),
            0x2_0000,
            0x2_0000,
            GicRegionKind::Redistributor,
        )
        .unwrap_err();
        assert_eq!(e.message(), "gic redistributor base is not aligned");
    }

    /// MVM-5: 大きさの境界（窓の末尾ちょうど・1 バイト超）。
    #[test]
    fn mvm5_3792_region_size_boundaries() {
        use GicRegionKind::Distributor as D;
        let r = region(0x0800_0000, 0x1_0000);
        assert!(check_gic_region(r, 0x1_0000, 0x1_0000, D).is_ok());
        let e = check_gic_region(r, 0x1_0001, 0x1_0000, D).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "gic distributor region is too small");
        let e = check_gic_region(region(u64::MAX - 0xf, 0x20), 0x10, 1, D).unwrap_err();
        assert_eq!(e.message(), "guest layout size overflow");
    }

    /// MVM-5: フレームワークの異常値は Internal。
    #[test]
    fn mvm5_3792_region_rejects_abnormal_reports_as_internal() {
        use GicRegionKind::Distributor as D;
        let r = region(0x0800_0000, 0x1_0000);
        for (req, align) in [(0x1_0000, 0), (0x1_0000, 3), (0, 0x1_0000)] {
            let e = check_gic_region(r, req, align, D).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::Internal);
        }
    }

    /// MVM-5: redistributor は vCPU 数を掛けた要求で検査し、桁あふれは拒否する。
    #[test]
    fn mvm5_3792_redistributor_per_cpu_requirement() {
        let l = Arm64Layout::new(256 * MIB, 1, 0).unwrap();
        let mut g = geom();
        g.redist_size_per_cpu = 0x2_0001;
        let e = l.check_gic_geometry(&g).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "gic redistributor region is too small");
        let two = Arm64Layout::new(256 * MIB, 2, 0).unwrap();
        g.redist_size_per_cpu = u64::MAX;
        let e = two.check_gic_geometry(&g).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "guest layout size overflow");
    }

    /// MVM-5: virtual timer の intid は 27 だけが通り、FDT の timer の 3 組目と同じ PPI を指す。
    #[test]
    fn mvm5_3792_virtual_timer_intid_matches_fdt() {
        assert!(check_virtual_timer_intid(27).is_ok());
        for bad in [26, 28] {
            let e = check_virtual_timer_intid(bad).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::Internal);
            assert_eq!(
                e.message(),
                "virtual timer intid does not match the guest fdt"
            );
        }
        assert_eq!(TIMER_PPIS, [13, 14, 11, 10]);
        assert_eq!(TIMER_PPIS[2], ARM64_TIMER_VIRT_PPI);
        assert_eq!(ARM64_PPI_INTID_BASE + ARM64_TIMER_VIRT_PPI, 27);
    }

    /// MVM-5・MVM-1・#3864: MPIDR affinity の具体値。
    #[test]
    fn mvm5_3864_vcpu_mpidr_affinity_values() {
        for (idx, want) in [
            (0, 0),
            (1, 1),
            (15, 0xf),
            (16, 0x100),
            (17, 0x101),
            (63, 0x30f),
        ] {
            assert_eq!(arm64_vcpu_mpidr_affinity(idx).unwrap(), want, "idx={idx}");
        }
        assert_eq!(
            arm64_vcpu_mpidr_affinity(64).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
    }

    /// MVM-5・#3864: vCPU 数の上限。
    #[test]
    fn mvm5_3864_validate_vcpu_cap() {
        assert!(Arm64Layout::new(4 * MIB, ARM64_MAX_VCPUS, 0).is_ok());
        let e = Arm64Layout::new(4 * MIB, ARM64_MAX_VCPUS + 1, 0).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "too many vcpus");
        assert!(
            ARM64_GIC_REDIST_BASE + ARM64_GIC_REDIST_SIZE_PER_CPU * u64::from(ARM64_MAX_VCPUS)
                <= ARM64_SERIAL_BASE
        );
    }

    /// MVM-5・#3864: シリアル窓の検査。
    #[test]
    fn mvm5_3864_validate_serial_region() {
        let base = Arm64Layout::new(256 * MIB, 1, 2).unwrap();
        let l = base.clone().with_default_serial().unwrap();
        assert_eq!(l.serial, Some(MmioRegion::new(0x0900_0000, 0x1000)));
        let mut z = l.clone();
        z.serial = Some(MmioRegion::new(ARM64_SERIAL_BASE, 0));
        expect_invalid(&z, "serial region size must be non-zero");
        let len = u64::from(crate::uart::UART_PORT_LEN);
        for size in [1, len - 1] {
            let mut s = l.clone();
            s.serial = Some(MmioRegion::new(ARM64_SERIAL_BASE, size));
            expect_invalid(&s, "serial region is smaller than the uart register window");
        }
        let mut ok = l.clone();
        ok.serial = Some(MmioRegion::new(ARM64_SERIAL_BASE, len));
        assert!(ok.validate().is_ok());
        for b in [0x0800_0000u64, 0x0820_0000, 0x0a00_0000, 0x4000_0000] {
            let mut o = l.clone();
            o.serial = Some(MmioRegion::new(b, ARM64_SERIAL_SIZE));
            expect_invalid(&o, "guest layout regions overlap");
        }
        let mut hi = l.clone();
        hi.serial = Some(MmioRegion::new(hi.ipa_limit, ARM64_SERIAL_SIZE));
        expect_invalid(&hi, "guest layout exceeds the ipa limit");
    }

    /// MVM-5・#3892: シリアルの SPI 番号と INTID。シリアルが無い配置は `None`。
    #[test]
    fn mvm5_3892_serial_spi_values() {
        assert_eq!(ARM64_SERIAL_SPI, 1);
        let base = Arm64Layout::new(256 * MIB, 1, 2).unwrap();
        assert_eq!(base.serial_spi(), None);
        let l = base.with_default_serial().unwrap();
        let spi = l.serial_spi().unwrap();
        assert_eq!(spi.dt_cell(), 1);
        assert_eq!(spi.intid(), Some(33));
    }

    /// MVM-5・#3892: virtio の SPI 範囲との重なりは拒否する（シリアル無しなら通る）。
    #[test]
    fn mvm5_3892_serial_spi_overlap_rejected() {
        let mut l = Arm64Layout::new(256 * MIB, 1, 2)
            .unwrap()
            .with_default_serial()
            .unwrap();
        l.virtio_spi_base = 0;
        expect_invalid(&l, "serial spi overlaps the virtio spi range");
        l.virtio_spi_base = 2;
        assert!(l.validate().is_ok());
        let mut none = Arm64Layout::new(256 * MIB, 1, 2).unwrap();
        none.virtio_spi_base = 0;
        assert!(none.validate().is_ok());
    }

    /// MVM-5・#3892: シリアルの SPI は API の範囲で照合する。
    #[test]
    fn mvm5_3892_serial_spi_range_check() {
        let l = Arm64Layout::new(256 * MIB, 1, 2)
            .unwrap()
            .with_default_serial()
            .unwrap();
        assert!(l.check_serial_spi_range(33, 1).is_ok());
        let e = l.check_serial_spi_range(34, 10).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "serial spi intid is outside the gic spi range");
        let e = l.check_serial_spi_range(48, 0).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        let none = Arm64Layout::new(256 * MIB, 1, 2).unwrap();
        assert!(none.check_serial_spi_range(48, 0).is_ok());
    }
}
