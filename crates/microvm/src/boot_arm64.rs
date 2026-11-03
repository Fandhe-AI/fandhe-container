//! arm64 Linux の Image・initrd・FDT のゲストメモリへの配置と、起動時のレジスタの値（OS 非依存・`unsafe` なし）。
//!
//! 役割: x86_64 の [`crate::boot_x86::load_linux`] に相当する arm64 側の入口。Image ヘッダを検証し、
//! カーネル・initrd・FDT の置き場所を決めて [`GuestMemory`] へ書き、起動時に vCPU へ入れる値を
//! [`ArmBootState`] で返す。呼び出し元は macOS の VM 組み立て（#3797・TASK-192.15）と、
//! 将来の KVM aarch64（#3696）。レジスタへの実書き込み（`hv_vcpu_set_reg`）と `SCTLR_EL1`・キャッシュの保守・
//! MPIDR は呼び出し側の責務で、本層は「どこに何を置き、各レジスタに何を入れるか」だけを返す
//! （TASK-192.7・#3790・MVM-5・MVM-1・MVM-4）。
//!
//! 一次情報: Linux の `Documentation/arch/arm64/booting.rst`（Image ヘッダ・配置・起動時のレジスタ）。
//! Firecracker・rust-vmm（`linux-loader` 等）のコードは参照も流用もしない（MVM-4）。
//!
//! # 配置（RAM 基底から上へ。2 MiB 区画）
//! ```text
//! ram.base + text_offset  : カーネル（ファイル長。確保域は max(image_size, ファイル長)）
//!   ... 空き（BSS・カーネル直後を空ける。booting.rst の求め）...
//! initrd                  : 2 MiB 境界に切り下げ（FDT の直下）
//! FDT                     : 天井 - 64 KiB を 2 MiB 境界に切り下げ（8 バイト境界・2 MiB 以下）
//! 天井                    : min(RAM 終端, カーネルを覆う 1 GiB 境界 + 32 GiB)
//! ```
//! initrd と FDT を「上から詰める」1 方式に統一する理由: `image_size = 0` の旧形式ではカーネルの BSS の大きさが
//! 分からず、booting.rst はカーネル直後のメモリを空けておくことを求める。`image_size` が有っても同じ方式で
//! 安全に置ける。initrd は 1 GiB 境界・最大 32 GiB の窓に収める（booting.rst）。
//!
//! # 外部入力の扱い（ERR-1・REPAIR-2）
//! Image・initrd・cmdline は非信頼入力。長さの上限（plugin-microvm の読み込み上限と同じ
//! [`crate::boot_x86::MAX_KERNEL_IMAGE_BYTES`]・[`crate::boot_x86::MAX_INITRD_BYTES`]）をバイトを読む前に検査し、
//! 演算はすべて checked。計画がすべて通るまでゲストメモリへ書かない。
//! エラーは `InvalidArgument` で、メッセージは固定の英語（入力値をエコーしない）。
//! イメージの署名・digest の検証は本層の責務ではない（plugin-microvm 側の経路）。
//!
//! # 範囲外（REPAIR-3）
//! 圧縮 Image（`Image.gz`）・EFI stub 起動・BE カーネル・SMP（`build_guest_fdt` が vCPU 2 以上を `Unimplemented` にする）・
//! `stdout-path`・複数の RAM 領域・ファイルからの読み込み（呼び出し側が上限つきで読む）・キャッシュの保守（#3797）。
//! 新しいゲスト RAM はゼロなので BSS のゼロ化はカーネル自身の起動処理に任せる。
//!
//! ビヘイビア: MVM-5・MVM-1・MVM-4・ERR-1・REPAIR-2・REPAIR-3。

use crate::arm64_layout::{
    ARM64_RAM_BASE, Arm64Layout, GuestFdtConfig, MmioRegion, build_guest_fdt,
};
use crate::boot_x86::{MAX_INITRD_BYTES, MAX_KERNEL_IMAGE_BYTES};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::fdt::MAX_FDT_BYTES;
use crate::guest_memory::{GuestAddress, GuestMemory, GuestMemoryBacking};

/// Image ヘッダの長さ（64 バイト）。
pub const ARM64_IMAGE_HEADER_LEN: usize = 64;
/// Image ヘッダ offset 56 の magic（"ARM\x64" の LE）。
pub const ARM64_IMAGE_MAGIC: u32 = 0x644d_5241;
/// `image_size = 0` の旧形式（v3.17 より前）で仮定する `text_offset`。
pub const ARM64_LEGACY_TEXT_OFFSET: u64 = 0x8_0000;
/// カーネル・initrd・FDT の配置の刻み（2 MiB）。
pub const ARM64_KERNEL_ALIGN: u64 = 2 * 1024 * 1024;
/// initrd を収める窓の境界（1 GiB）。
pub const ARM64_INITRD_WINDOW_ALIGN: u64 = 1 << 30;
/// initrd を収める窓の大きさ（32 GiB）。
pub const ARM64_INITRD_WINDOW_MAX: u64 = 32 << 30;
/// 起動時の `CPSR`（`PSTATE`）。`M[3:0]` = 0b0101（EL1h）と D(9)・A(8)・I(7)・F(6) = 1 で `0x3c0 | 0x5`。
/// MMU off・D-cache off（`SCTLR_EL1` の M = 0・C = 0）は #3797 の責務。
pub const ARM64_BOOT_CPSR: u64 = 0x3c5;
/// 配置を 48 ビット物理アドレスに制限する境界（flags bit 3 = 1 のとき）。
const PHYS_48BIT: u64 = 1 << 48;

const _: () = {
    assert!(ARM64_RAM_BASE.is_multiple_of(ARM64_KERNEL_ALIGN));
    assert!(MAX_FDT_BYTES as u64 <= ARM64_KERNEL_ALIGN);
};

fn invalid(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, msg)
}

fn rd_u32_le(img: &[u8], off: usize) -> Result<u32, MicrovmError> {
    let end = off
        .checked_add(4)
        .ok_or_else(|| invalid("kernel image offset overflow"))?;
    let b: [u8; 4] = img
        .get(off..end)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| invalid("kernel image is shorter than the arm64 header"))?;
    Ok(u32::from_le_bytes(b))
}

fn rd_u64_le(img: &[u8], off: usize) -> Result<u64, MicrovmError> {
    let end = off
        .checked_add(8)
        .ok_or_else(|| invalid("kernel image offset overflow"))?;
    let b: [u8; 8] = img
        .get(off..end)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| invalid("kernel image is shorter than the arm64 header"))?;
    Ok(u64::from_le_bytes(b))
}

fn align_down(v: u64, a: u64) -> u64 {
    v - (v % a)
}

/// 半開区間 `[a, a + alen)` と `[b, b + blen)` の重なり。桁あふれは重なり扱い（fail-closed）。
fn ranges_overlap(a: u64, alen: u64, b: u64, blen: u64) -> bool {
    match (a.checked_add(alen), b.checked_add(blen)) {
        (Some(ae), Some(be)) => a < be && b < ae,
        _ => true,
    }
}

/// Image ヘッダ flags bit 1-2 のカーネルのページサイズ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm64PageSize {
    /// 0: 未指定。
    Unspecified,
    /// 1: 4 KiB。
    K4,
    /// 2: 16 KiB。
    K16,
    /// 3: 64 KiB。
    K64,
}

/// 検証済みの arm64 Image ヘッダ。
///
/// ゲストのページサイズが実機で使えるか（例: 64 KiB の Apple Silicon での可否）は本層では判断せず、
/// backend（#3797）が `page_size` を見て決める。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Arm64ImageHeader {
    /// 実効の `text_offset`（旧形式では [`ARM64_LEGACY_TEXT_OFFSET`]）。
    pub text_offset: u64,
    /// ヘッダの生の `image_size`（0 は旧形式）。
    pub image_size: u64,
    /// ヘッダの生の flags。
    pub flags: u64,
    /// flags bit 1-2。
    pub page_size: Arm64PageSize,
    /// flags bit 3。1 ならカーネルを物理メモリの任意の位置に置ける（ただし 48 ビット以内）。
    pub placement_anywhere: bool,
    /// `image_size = 0` の旧形式か。
    pub legacy: bool,
}

impl Arm64ImageHeader {
    /// Image の先頭 64 バイトを検証して解析する。
    ///
    /// `image_size = 0`（v3.17 より前の旧形式）: ヘッダの `text_offset` は無視して 0x80000 を仮定し、
    /// flags も未定義なのでページサイズ未指定・配置 false とする。必要な領域の大きさは不明（BSS が分からない）
    /// なのでファイル長を最低限の確保域とし、BSS が大きい旧カーネルは保証しない（REPAIR-3）。
    /// flags bit 4-63 は予約で、無視する（生値は `flags` に残す）。
    pub fn parse(image: &[u8]) -> Result<Self, MicrovmError> {
        if image.len() as u64 > MAX_KERNEL_IMAGE_BYTES {
            return Err(invalid("kernel image too large"));
        }
        if image.len() < ARM64_IMAGE_HEADER_LEN {
            return Err(invalid("kernel image is shorter than the arm64 header"));
        }
        if rd_u32_le(image, 56)? != ARM64_IMAGE_MAGIC {
            return Err(invalid("kernel image is not an arm64 Image"));
        }
        let hdr_text_offset = rd_u64_le(image, 8)?;
        let image_size = rd_u64_le(image, 16)?;
        let flags = rd_u64_le(image, 24)?;
        let legacy = image_size == 0;
        if !legacy {
            if flags & 1 == 1 {
                return Err(invalid("big-endian arm64 kernels are not supported"));
            }
            if image_size < image.len() as u64 {
                return Err(invalid("kernel image_size is smaller than the image"));
            }
        }
        let (text_offset, page_size, placement_anywhere) = if legacy {
            (ARM64_LEGACY_TEXT_OFFSET, Arm64PageSize::Unspecified, false)
        } else {
            let ps = match (flags >> 1) & 3 {
                1 => Arm64PageSize::K4,
                2 => Arm64PageSize::K16,
                3 => Arm64PageSize::K64,
                _ => Arm64PageSize::Unspecified,
            };
            (hdr_text_offset, ps, (flags >> 3) & 1 == 1)
        };
        if text_offset >= ARM64_KERNEL_ALIGN {
            return Err(invalid("kernel text_offset is out of range"));
        }
        Ok(Self {
            text_offset,
            image_size,
            flags,
            page_size,
            placement_anywhere,
            legacy,
        })
    }
}

/// [`plan_arm64`] の結果（メモリへはまだ書かない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Arm64BootPlan {
    /// カーネルの置き場所（大きさはファイル長）。
    pub kernel: MmioRegion,
    /// カーネルの確保域の排他的終端（`max(image_size, ファイル長)` 分）。
    pub reserved_end: u64,
    /// initrd の置き場所。
    pub initrd: Option<MmioRegion>,
    /// FDT の先頭（枠は 64 KiB）。
    pub fdt_addr: GuestAddress,
    /// FDT が収まる上限（排他的）。
    pub ceiling: u64,
}

/// カーネル・initrd・FDT の置き場所を決める純関数（メモリ不要。違反は `InvalidArgument`）。
pub fn plan_arm64(
    header: &Arm64ImageHeader,
    image_len: u64,
    initrd_len: Option<u64>,
    layout: &Arm64Layout,
) -> Result<Arm64BootPlan, MicrovmError> {
    layout.validate()?;
    let overflow = || invalid("guest layout size overflow");
    let too_small = || invalid("guest ram too small for kernel, initrd and fdt");
    let ram_base = layout.ram.base.raw();
    let ram_end = layout.ram.end().ok_or_else(overflow)?;
    let kernel_addr = ram_base
        .checked_add(header.text_offset)
        .ok_or_else(overflow)?;
    let reserved_end = kernel_addr
        .checked_add(header.image_size.max(image_len))
        .ok_or_else(overflow)?;
    if reserved_end > ram_end {
        return Err(too_small());
    }
    if header.placement_anywhere && reserved_end > PHYS_48BIT {
        return Err(invalid("kernel is outside the 48-bit physical range"));
    }
    let window_end = align_down(kernel_addr, ARM64_INITRD_WINDOW_ALIGN)
        .checked_add(ARM64_INITRD_WINDOW_MAX)
        .ok_or_else(overflow)?;
    let ceiling = ram_end.min(window_end);
    let fdt_top = ceiling
        .checked_sub(MAX_FDT_BYTES as u64)
        .ok_or_else(too_small)?;
    let fdt_addr = align_down(fdt_top, ARM64_KERNEL_ALIGN);
    let initrd = match initrd_len {
        None => {
            if fdt_addr < reserved_end {
                return Err(too_small());
            }
            None
        }
        Some(len) => {
            if len == 0 {
                return Err(invalid("initrd must be non-empty"));
            }
            if len > MAX_INITRD_BYTES {
                return Err(invalid("initrd too large"));
            }
            let top = fdt_addr.checked_sub(len).ok_or_else(too_small)?;
            let addr = align_down(top, ARM64_KERNEL_ALIGN);
            if addr < reserved_end {
                return Err(too_small());
            }
            Some(MmioRegion::new(addr, len))
        }
    };
    // 多重の安全網: 3 区間が重ならないこと。
    let fdt_len = MAX_FDT_BYTES as u64;
    if ranges_overlap(kernel_addr, image_len, fdt_addr, fdt_len) {
        return Err(too_small());
    }
    if let Some(i) = initrd
        && (ranges_overlap(kernel_addr, image_len, i.base.raw(), i.size)
            || ranges_overlap(i.base.raw(), i.size, fdt_addr, fdt_len))
    {
        return Err(too_small());
    }
    Ok(Arm64BootPlan {
        kernel: MmioRegion::new(kernel_addr, image_len),
        reserved_end,
        initrd,
        fdt_addr: GuestAddress::new(fdt_addr),
        ceiling,
    })
}

/// [`load_arm64`] が配置した結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LoadedArm64 {
    /// カーネル（大きさはファイル長）。
    pub kernel: MmioRegion,
    /// カーネルの確保域の排他的終端。
    pub reserved_end: u64,
    /// initrd。
    pub initrd: Option<MmioRegion>,
    /// FDT（実際の長さ）。
    pub fdt: MmioRegion,
    /// 検証済みの Image ヘッダ。
    pub header: Arm64ImageHeader,
}

/// 起動時に vCPU へ入れるレジスタの値（実書き込みは #3797。macOS では `HvReg` に対応する）。
///
/// 対応: `pc` -> [`crate::hvf_abi::HvReg::PC`]、`cpsr` -> [`crate::hvf_abi::HvReg::CPSR`]、
/// `x0`〜`x3` -> `HvReg::x(n)`。呼び出し側の責務: `SCTLR_EL1` の M = 0・C = 0（MMU・D-cache off）、
/// 書いた範囲の PoC までの clean と I-cache の無効化の要否の判断、MPIDR、他の vCPU の PSCI 起動。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmBootState {
    /// カーネル先頭。
    pub pc: u64,
    /// FDT の GPA。
    pub x0: u64,
    /// 0（予約）。
    pub x1: u64,
    /// 0（予約）。
    pub x2: u64,
    /// 0（予約）。
    pub x3: u64,
    /// [`ARM64_BOOT_CPSR`]。
    pub cpsr: u64,
}

impl ArmBootState {
    /// 配置結果から作る。
    pub fn for_loaded(loaded: &LoadedArm64) -> Self {
        Self {
            pc: loaded.kernel.base.raw(),
            x0: loaded.fdt.base.raw(),
            x1: 0,
            x2: 0,
            x3: 0,
            cpsr: ARM64_BOOT_CPSR,
        }
    }
}

/// Image・initrd・FDT をゲストメモリへ配置し、起動レジスタの値を返す。
///
/// 検証と計画がすべて通るまで何も書かない。`build_guest_fdt` の挙動を引き継ぐ:
/// vCPU が 1 以外なら `Unimplemented`、cmdline の超過・NUL は `InvalidArgument`。
pub fn load_arm64<B: GuestMemoryBacking>(
    memory: &mut GuestMemory<B>,
    image: &[u8],
    initrd: Option<&[u8]>,
    cmdline: &str,
    layout: &Arm64Layout,
) -> Result<(LoadedArm64, ArmBootState), MicrovmError> {
    if memory.base() != layout.ram.base || memory.len() != layout.ram.size {
        return Err(invalid("guest memory does not match the layout ram"));
    }
    let header = Arm64ImageHeader::parse(image)?;
    let plan = plan_arm64(
        &header,
        image.len() as u64,
        initrd.map(|i| i.len() as u64),
        layout,
    )?;
    let fdt = build_guest_fdt(&GuestFdtConfig {
        layout,
        bootargs: cmdline,
        initrd: plan.initrd,
    })?;
    let fdt_len = fdt.len() as u64;
    let fdt_end = plan
        .fdt_addr
        .raw()
        .checked_add(fdt_len)
        .ok_or_else(|| invalid("guest layout size overflow"))?;
    if fdt.len() > MAX_FDT_BYTES || fdt_end > plan.ceiling {
        return Err(invalid("fdt too large"));
    }
    memory.write_at(plan.kernel.base, image)?;
    if let (Some(region), Some(data)) = (plan.initrd, initrd) {
        memory.write_at(region.base, data)?;
    }
    memory.write_at(plan.fdt_addr, &fdt)?;
    let loaded = LoadedArm64 {
        kernel: plan.kernel,
        reserved_end: plan.reserved_end,
        initrd: plan.initrd,
        fdt: MmioRegion {
            base: plan.fdt_addr,
            size: fdt_len,
        },
        header,
    };
    let state = ArmBootState::for_loaded(&loaded);
    Ok((loaded, state))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(len: usize, text_offset: u64, image_size: u64, flags: u64) -> Vec<u8> {
        let mut v: Vec<u8> = (0..len).map(|i| i as u8).collect();
        v[8..16].copy_from_slice(&text_offset.to_le_bytes());
        v[16..24].copy_from_slice(&image_size.to_le_bytes());
        v[24..32].copy_from_slice(&flags.to_le_bytes());
        v[56..60].copy_from_slice(&ARM64_IMAGE_MAGIC.to_le_bytes());
        v
    }

    #[test]
    fn mvm5_legacy_image_assumes_text_offset_0x80000() {
        let img = image(4096, 0, 0, 0);
        let h = Arm64ImageHeader::parse(&img).unwrap();
        assert!(h.legacy);
        assert_eq!(h.text_offset, 0x8_0000);
        assert_eq!(h.page_size, Arm64PageSize::Unspecified);
        let l = Arm64Layout::new(16 << 20, 1, 1).unwrap();
        let p = plan_arm64(&h, 4096, None, &l).unwrap();
        assert_eq!(p.kernel.base.raw(), 0x4008_0000);
        assert_eq!(p.reserved_end, 0x4008_1000);
    }

    #[test]
    fn mvm5_image_size_smaller_than_image_is_rejected() {
        let img = image(4096, 0, 2048, 0);
        assert_eq!(
            Arm64ImageHeader::parse(&img).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
    }

    #[test]
    fn mvm5_text_offset_boundary() {
        let ok = image(4096, 0x1f_f000, 0x20_0000, 0);
        assert_eq!(Arm64ImageHeader::parse(&ok).unwrap().text_offset, 0x1f_f000);
        let ng = image(4096, 0x20_0000, 0x20_0000, 0);
        assert!(Arm64ImageHeader::parse(&ng).is_err());
    }

    #[test]
    fn mvm5_page_size_and_reserved_bits() {
        for (bits, want) in [
            (0u64, Arm64PageSize::Unspecified),
            (1, Arm64PageSize::K4),
            (2, Arm64PageSize::K16),
            (3, Arm64PageSize::K64),
        ] {
            let img = image(4096, 0, 0x20_0000, bits << 1);
            assert_eq!(Arm64ImageHeader::parse(&img).unwrap().page_size, want);
        }
        let img = image(4096, 0, 0x20_0000, 1 << 4);
        assert!(Arm64ImageHeader::parse(&img).is_ok());
    }

    #[test]
    fn mvm5_window_is_32gib_above_the_1gib_boundary() {
        let mut l = Arm64Layout::new(16 << 20, 1, 1).unwrap();
        l.ram = MmioRegion::new(0x4000_0000, 64 << 30);
        l.ipa_limit = 1 << 40;
        let h = Arm64ImageHeader::parse(&image(4096, 0, 0x20_0000, 0)).unwrap();
        let p = plan_arm64(&h, 4096, None, &l).unwrap();
        assert_eq!(p.ceiling, 0x4000_0000 + (32 << 30));
        assert_eq!(p.fdt_addr.raw(), 0x8_3fe0_0000);
    }

    #[test]
    fn mvm5_initrd_length_bounds() {
        let l = Arm64Layout::new(16 << 20, 1, 1).unwrap();
        let h = Arm64ImageHeader::parse(&image(4096, 0, 0x20_0000, 0)).unwrap();
        assert!(plan_arm64(&h, 4096, Some(0), &l).is_err());
        assert!(plan_arm64(&h, 4096, Some(MAX_INITRD_BYTES + 1), &l).is_err());
    }

    #[test]
    fn mvm5_boot_cpsr_is_el1h_with_daif_masked() {
        assert_eq!(ARM64_BOOT_CPSR, 0x3c5);
        assert_eq!(ARM64_BOOT_CPSR & 0xf, 0b0101);
        assert_eq!((ARM64_BOOT_CPSR >> 6) & 0xf, 0xf);
    }
}
