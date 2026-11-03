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
//! - GICD / GICR の基底は候補値である。アライン・大きさは #3792 が
//!   `hv_gic_get_distributor_base_alignment` 等で実行時に検証する。
//!
//! 未実装（REPAIR-3）: SMP（vCPU 2 以上は `Unimplemented`。#3797）・シリアルと `stdout-path`（chosen に付けない）・
//! PCI・`hv_gic_*` による実値の取得（#3792）・virtio の通知方式と trigger の整合（#3795）・IPA 上限の確定（#3803）。
//!
//! # 出典（Linux `Documentation/devicetree/bindings`）
//! `arm/psci.yaml`・`interrupt-controller/arm,gic-v3.yaml`・`timer/arm,arch_timer.yaml`・`virtio/mmio.yaml`・`arm/cpus.yaml`。
//! 割り込みセルの値は `include/dt-bindings/interrupt-controller/{arm-gic.h,irq.h}`。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::fdt::FdtBuilder;
use crate::guest_memory::GuestAddress;
use crate::hvf_abi::HVF_DEFAULT_IPA_LIMIT;
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
/// virtio-mmio の窓の刻み（設定空間 0x100 とレジスタ 0x100 を収める）。
pub const ARM64_VIRTIO_MMIO_STRIDE: u64 = 0x200;
/// virtio-mmio の個数の上限。
pub const ARM64_VIRTIO_MMIO_MAX: u32 = 32;
/// virtio-mmio の最初の SPI 番号（DT のセル値。GIC の INTID は 32 + n）。
pub const ARM64_VIRTIO_SPI_BASE: u32 = 16;
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
const IRQ_TYPE_LEVEL_LOW: u32 = 8;
/// timer の PPI 番号（arm,arch_timer の並び順。INTID = 16 + PPI で virt は 27）。
/// `hv_gic_get_intid(EL1_VIRTUAL_TIMER)` との一致は #3792 の実機試験で照合する。
const TIMER_PPIS: [u32; 4] = [13, 14, 11, 10];
/// virtio の trigger。`hv_gic_set_spi(intid, level)` は level 形の API のため、
/// #3795 の通知方式（パルスか保持か）とこの定数を一致させる必要がある（未決・#3795 で確定）。
const VIRTIO_IRQ_TRIGGER: u32 = IRQ_TYPE_EDGE_RISING;
/// GICv3 の SPI 番号の上限（INTID 1019 - 32）。
const GIC_MAX_SPI_N: u32 = 987;
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
        self.0.checked_add(32)
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
    /// vCPU 数。
    pub vcpus: u32,
    /// IPA 上限（排他的）。
    pub ipa_limit: u64,
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
            vcpus,
            ipa_limit: ARM64_DEFAULT_IPA_LIMIT,
        };
        layout.validate()?;
        Ok(layout)
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
        if self.ipa_limit == 0 {
            return Err(invalid("ipa limit must be non-zero"));
        }
        let virtio = self.virtio_window_all()?;
        let mut regions = vec![self.ram, self.gic_dist, self.gic_redist];
        if self.virtio_mmio_count > 0 {
            regions.push(virtio);
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

/// arm64 ゲスト向けの FDT を組み立てる（ルート・chosen・memory・cpus・psci・GICv3・timer・virtio-mmio）。
///
/// `Unimplemented`: vCPU が 1 以外（#3797）。`InvalidArgument`: 配置の違反・bootargs 超過・initrd が RAM の外。
/// `stdout-path` は付けない（シリアル未実装。REPAIR-3）。
pub fn build_guest_fdt(config: &GuestFdtConfig<'_>) -> Result<Vec<u8>, MicrovmError> {
    let l = config.layout;
    l.validate()?;
    if l.vcpus != 1 {
        return Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "only one vcpu is supported",
        ));
    }
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
    b.end_node()?;

    b.begin_node(&format!("memory@{:x}", l.ram.base.raw()))?;
    b.property_string("device_type", "memory")?;
    b.property_cells("reg", &reg_cells(&[(l.ram.base.raw(), l.ram.size)]))?;
    b.end_node()?;

    // arm/cpus.yaml: #address-cells = 1・#size-cells = 0 が無いと cpu@0 の reg を読めない。
    b.begin_node("cpus")?;
    b.property_u32("#address-cells", 1)?;
    b.property_u32("#size-cells", 0)?;
    b.begin_node("cpu@0")?;
    b.property_string("device_type", "cpu")?;
    b.property_string("compatible", "arm,arm-v8")?;
    b.property_string("enable-method", "psci")?;
    b.property_cells("reg", &[ARM64_BOOT_CPU_MPIDR])?;
    b.end_node()?;
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
        irq.extend_from_slice(&[GIC_PPI, ppi, IRQ_TYPE_LEVEL_LOW]);
    }
    b.begin_node("timer")?;
    b.property_string("compatible", "arm,armv8-timer")?;
    b.property_cells("interrupts", &irq)?;
    b.end_node()?;

    // virtio/mmio.yaml。
    for i in 0..l.virtio_mmio_count {
        let w = l.virtio_mmio_window(i)?;
        let spi = l.virtio_spi(i)?;
        b.begin_node(&format!("virtio_mmio@{:x}", w.base.raw()))?;
        b.property_string("compatible", "virtio,mmio")?;
        b.property_cells("reg", &reg_cells(&[(w.base.raw(), w.size)]))?;
        b.property_cells("interrupts", &[GIC_SPI, spi.dt_cell(), VIRTIO_IRQ_TRIGGER])?;
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

    /// MVM-5: SMP と bootargs・initrd の検査。
    #[test]
    fn mvm5_3788_fdt_input_checks() {
        let two = Arm64Layout::new(256 * MIB, 2, 0).unwrap();
        let cfg = GuestFdtConfig {
            layout: &two,
            bootargs: "",
            initrd: None,
        };
        assert_eq!(
            build_guest_fdt(&cfg).unwrap_err().code(),
            MicrovmErrorCode::Unimplemented
        );
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
}
