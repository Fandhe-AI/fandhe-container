//! x86_64 ゲストへ渡す Intel MultiProcessor Specification 1.4 の MP テーブルの生成器（#3888・MVM-1。OS・arch 非依存・unsafe なし）。
//!
//! 呼び出し元は `microvm::MicroVm::load_kernel`（Linux のみ。`boot_x86::load_linux` の前に [`build_mp_table`] で組み、後に
//! [`write_mp_table`] で書く）。MP テーブルが無いと Linux は AP（vCPU 1 以上）の LAPIC を知らず、INIT/SIPI（`smp_x86`）で起こしても
//! オンラインにならない。ACPI の MADT は RSDP・RSDT/XSDT・FADT 等が要り範囲が大きいため採らない（ACPI は範囲外）。
//!
//! # 一次情報（MVM-4: Firecracker・rust-vmm のコードは参照しない）
//! MP 仕様 1.4 の第 4 章（floating pointer と configuration table の形式・checksum）と、Linux v6.12 の
//! `arch/x86/include/asm/mpspec_def.h`（項の配置）・`arch/x86/kernel/mpparse.c`（`smp_scan_config` は `_MP_` を 16 バイト境界で
//! 探し、length が 1・spec が 1 か 4・16 バイトの総和が 0 であることを検査する）。走査範囲のひとつ `[639 KiB, 640 KiB)` に置く
//! （`boot_x86::MP_TABLE_START`..`MP_TABLE_END`。e820 では予約）。
//!
//! # 表の中身
//! processor は vCPU 数ぶん（LAPIC ID = vCPU 番号・BSP の印は vCPU 0 だけ）、bus は ISA 1 本、IOAPIC は 1 つ
//! （[`IOAPIC_MMIO_BASE`]）、interrupt source は呼び出し側が渡す ISA IRQ と IOAPIC pin の対応、local interrupt は
//! LINT0 = ExtINT・LINT1 = NMI（`lapic_x86` の BSP の設定と同じ）。floating pointer の feature2 の IMCRP は 0（virtual wire）。
//! irqflag は 0（bus の既定 = ISA の edge・active high）で、irqfd の edge 注入と整合する。cpufeature・featureflag は 0 とし、
//! ホストの CPUID を写さない。
//!
//! # 範囲外（REPAIR-3）
//! ACPI・PCI bus の項・MP の拡張表・PIT のモデル（IOAPIC モードでは Linux の `check_timer` が走る。切り分けは `AGENTS.md`）。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestAddress, GuestMemory, GuestMemoryBacking};

/// in-kernel IOAPIC の MMIO の窓の先頭（既定の物理アドレス）。
pub const IOAPIC_MMIO_BASE: u64 = 0xfec0_0000;
/// LAPIC の MMIO の窓の先頭（既定の物理アドレス）。
pub const LAPIC_MMIO_BASE: u64 = 0xfee0_0000;
/// KVM の in-kernel IOAPIC のピン数。Linux v6.12 の `arch/x86/include/uapi/asm/kvm.h` の `KVM_IOAPIC_NUM_PINS`（24）と同じ値。
/// libc に KVM の uapi 定数が無く本 crate に libc の照合も未導入のため、照合は出典の記載と const 評価に限る（#4162・MVM-1）。
pub const IOAPIC_PINS: u8 = 24;
/// ISA bus の IRQ 数。
pub const ISA_IRQS: u8 = 16;
const _: () = assert!(ISA_IRQS <= IOAPIC_PINS);

const FLOATING_LEN: usize = 16;
const HEADER_LEN: usize = 44;
const CPU_LEN: usize = 20;
const SMALL_LEN: usize = 8;
/// MP 仕様の版（1.4）。
const SPEC_REV: u8 = 4;
const CPU_ENABLED: u8 = 1;
const CPU_BSP: u8 = 2;
const IOAPIC_ENABLED: u8 = 1;
const APIC_VERSION_LAPIC: u8 = 0x14;
const APIC_VERSION_IOAPIC: u8 = 0x11;
const ENTRY_CPU: u8 = 0;
const ENTRY_BUS: u8 = 1;
const ENTRY_IOAPIC: u8 = 2;
const ENTRY_INTSRC: u8 = 3;
const ENTRY_LINTSRC: u8 = 4;
const DEST_ALL_APICS: u8 = 0xFF;
const OEM_ID: &[u8; 8] = b"FANDHE  ";
const PRODUCT_ID: &[u8; 12] = b"MICROVM     ";
const BUS_ISA: &[u8; 6] = b"ISA   ";

/// 割り込み種別（MP 仕様の interrupt type）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MpIrqType {
    Int = 0,
    Nmi = 1,
    ExtInt = 3,
}

fn invalid(message: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, message)
}

/// 総和が 0（mod 256）になるための checksum バイトを返す。
fn mp_checksum(bytes: &[u8]) -> u8 {
    bytes
        .iter()
        .fold(0u8, |acc, b| acc.wrapping_add(*b))
        .wrapping_neg()
}

/// ISA IRQ と IOAPIC pin の対応 1 組。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsaIrqRoute {
    /// ISA bus 上の IRQ（0..16）。
    pub source_irq: u8,
    /// 接続先の IOAPIC の pin（0..24）。
    pub ioapic_pin: u8,
}

/// MP テーブルの入力。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpTableConfig<'a> {
    /// vCPU 数（LAPIC ID は 0..vcpu_count。xAPIC の 8 bit に収まること）。
    pub vcpu_count: u32,
    /// IOAPIC の ID（LAPIC ID と衝突しない値）。
    pub ioapic_id: u8,
    /// IOAPIC の MMIO アドレス。
    pub ioapic_addr: u32,
    /// LAPIC の MMIO アドレス。
    pub lapic_addr: u32,
    /// interrupt source の対応。
    pub isa_irqs: &'a [IsaIrqRoute],
}

/// 組み上がった MP テーブル（floating pointer の直後に configuration table が続く連続バイト列）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MpTable {
    bytes: Vec<u8>,
}

impl MpTable {
    /// ゲストへ書くバイト列。
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// 全長。
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    /// 空か（生成器は空を返さない）。
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

fn cpu_entry(apic_id: u8, bsp: bool) -> [u8; CPU_LEN] {
    let mut e = [0u8; CPU_LEN];
    e[0] = ENTRY_CPU;
    e[1] = apic_id;
    e[2] = APIC_VERSION_LAPIC;
    e[3] = CPU_ENABLED | if bsp { CPU_BSP } else { 0 };
    e
}

fn bus_entry() -> [u8; SMALL_LEN] {
    let mut e = [0u8; SMALL_LEN];
    e[0] = ENTRY_BUS;
    e[1] = 0;
    e[2..8].copy_from_slice(BUS_ISA);
    e
}

fn ioapic_entry(id: u8, addr: u32) -> [u8; SMALL_LEN] {
    let mut e = [0u8; SMALL_LEN];
    e[0] = ENTRY_IOAPIC;
    e[1] = id;
    e[2] = APIC_VERSION_IOAPIC;
    e[3] = IOAPIC_ENABLED;
    e[4..8].copy_from_slice(&addr.to_le_bytes());
    e
}

fn intsrc_entry(route: IsaIrqRoute, ioapic_id: u8) -> [u8; SMALL_LEN] {
    // type, irqtype, irqflag(u16), srcbus, srcbusirq, dstapic, dstirq。irqflag 0 は bus の既定（ISA: edge・active high）。
    [
        ENTRY_INTSRC,
        MpIrqType::Int as u8,
        0,
        0,
        0,
        route.source_irq,
        ioapic_id,
        route.ioapic_pin,
    ]
}

fn lintsrc_entry(kind: MpIrqType, lint: u8) -> [u8; SMALL_LEN] {
    [ENTRY_LINTSRC, kind as u8, 0, 0, 0, 0, DEST_ALL_APICS, lint]
}

/// 構成を検証し vCPU 数を `u8` で返す（fail-closed。値は message に載せない。ERR-1）。
fn validate(cfg: &MpTableConfig<'_>) -> Result<u8, MicrovmError> {
    let count = u8::try_from(cfg.vcpu_count)
        .ok()
        .filter(|n| *n >= 1 && *n < DEST_ALL_APICS)
        .ok_or_else(|| invalid("MP table vCPU count must be 1..=254"))?;
    if cfg.ioapic_id < count || cfg.ioapic_id == DEST_ALL_APICS {
        return Err(invalid("MP table IOAPIC id collides with a LAPIC id"));
    }
    for (i, r) in cfg.isa_irqs.iter().enumerate() {
        if r.source_irq >= ISA_IRQS {
            return Err(invalid("MP table ISA IRQ is out of range"));
        }
        if r.ioapic_pin >= IOAPIC_PINS {
            return Err(invalid("MP table IOAPIC pin is out of range"));
        }
        let dup = cfg
            .isa_irqs
            .iter()
            .take(i)
            .any(|p| p.source_irq == r.source_irq || p.ioapic_pin == r.ioapic_pin);
        if dup {
            return Err(invalid("MP table has a duplicate IRQ or IOAPIC pin"));
        }
    }
    Ok(count)
}

/// MP テーブルを組む。`base` は floating pointer を置く GPA（configuration table は `base + 16`）。
///
/// 全長が `boot_x86::MP_TABLE_END - MP_TABLE_START` を超える構成は拒否する。
pub fn build_mp_table(cfg: &MpTableConfig<'_>, base: u64) -> Result<MpTable, MicrovmError> {
    let count = validate(cfg)?;
    let n = usize::from(count);
    // processor + bus + IOAPIC + intsrc + lintsrc 2 本。isa_irqs は validate で 16 件以下（重複なし）。
    let small = 1 + 1 + cfg.isa_irqs.len() + 2;
    let entries = n + small;
    let body_len = HEADER_LEN + n * CPU_LEN + SMALL_LEN * small;
    let total = FLOATING_LEN + body_len;
    let capacity = crate::boot_x86::MP_TABLE_END - crate::boot_x86::MP_TABLE_START;
    if total as u64 > capacity {
        return Err(invalid("MP table does not fit in its reserved area"));
    }
    if base != crate::boot_x86::MP_TABLE_START {
        // write_mp_table は常に固定の置き場所へ書くため、別の base では floating pointer が誤った設定表を指す。
        return Err(invalid("MP table base must be MP_TABLE_START"));
    }
    let physptr = base
        .checked_add(FLOATING_LEN as u64)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| invalid("MP table address must fit in 32 bits"))?;

    let mut body = Vec::with_capacity(body_len);
    body.extend_from_slice(b"PCMP");
    body.extend_from_slice(&(body_len as u16).to_le_bytes());
    body.push(SPEC_REV);
    body.push(0); // checksum（後で埋める）
    body.extend_from_slice(OEM_ID);
    body.extend_from_slice(PRODUCT_ID);
    body.extend_from_slice(&0u32.to_le_bytes()); // oemptr
    body.extend_from_slice(&0u16.to_le_bytes()); // oemsize
    body.extend_from_slice(&(entries as u16).to_le_bytes());
    body.extend_from_slice(&cfg.lapic_addr.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // 拡張表なし
    for id in 0..count {
        body.extend_from_slice(&cpu_entry(id, id == 0));
    }
    body.extend_from_slice(&bus_entry());
    body.extend_from_slice(&ioapic_entry(cfg.ioapic_id, cfg.ioapic_addr));
    for r in cfg.isa_irqs {
        body.extend_from_slice(&intsrc_entry(*r, cfg.ioapic_id));
    }
    body.extend_from_slice(&lintsrc_entry(MpIrqType::ExtInt, 0));
    body.extend_from_slice(&lintsrc_entry(MpIrqType::Nmi, 1));
    debug_assert_eq!(body.len(), body_len);
    let sum = mp_checksum(&body);
    if let Some(b) = body.get_mut(7) {
        *b = sum;
    }

    let mut fp = [0u8; FLOATING_LEN];
    fp[0..4].copy_from_slice(b"_MP_");
    fp[4..8].copy_from_slice(&physptr.to_le_bytes());
    fp[8] = 1; // length（16 バイト単位）
    fp[9] = SPEC_REV;
    // fp[11] feature1 = 0（設定表あり）・fp[12] feature2 = 0（IMCRP = 0: virtual wire）
    fp[10] = mp_checksum(&fp);

    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&fp);
    bytes.extend_from_slice(&body);
    Ok(MpTable { bytes })
}

/// `table` を `boot_x86::MP_TABLE_START` へ書く。範囲外は `write_at` のエラー。
pub fn write_mp_table<B: GuestMemoryBacking>(
    mem: &mut GuestMemory<B>,
    table: &MpTable,
) -> Result<GuestAddress, MicrovmError> {
    let at = GuestAddress::new(crate::boot_x86::MP_TABLE_START);
    mem.write_at(at, table.as_bytes())?;
    Ok(at)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_x86::{MP_TABLE_END, MP_TABLE_START};
    use crate::guest_memory::HeapBacking;

    const fn route(source_irq: u8, ioapic_pin: u8) -> IsaIrqRoute {
        IsaIrqRoute {
            source_irq,
            ioapic_pin,
        }
    }

    const IRQS: [IsaIrqRoute; 5] = [
        route(0, 2),
        route(4, 4),
        route(5, 5),
        route(6, 6),
        route(7, 7),
    ];

    fn cfg(vcpus: u32, irqs: &[IsaIrqRoute]) -> MpTableConfig<'_> {
        MpTableConfig {
            vcpu_count: vcpus,
            ioapic_id: 32,
            ioapic_addr: IOAPIC_MMIO_BASE as u32,
            lapic_addr: LAPIC_MMIO_BASE as u32,
            isa_irqs: irqs,
        }
    }

    fn sum(b: &[u8]) -> u8 {
        b.iter().fold(0u8, |a, x| a.wrapping_add(*x))
    }

    fn u16le(b: &[u8], o: usize) -> u16 {
        u16::from_le_bytes([b[o], b[o + 1]])
    }

    fn u32le(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
    }

    /// MVM-1・#3888: floating pointer の signature・length・spec・physptr・checksum。
    /// MVM-1・#3888: 固定の置き場所以外の base は拒否する（floating pointer が別の設定表を指すのを防ぐ）。
    #[test]
    fn mvm1_3888_rejects_foreign_base() {
        let e = build_mp_table(&cfg(2, &IRQS), 0xF_0000).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    }

    #[test]
    fn mvm1_3888_floating_pointer_fields() {
        let t = build_mp_table(&cfg(2, &IRQS), MP_TABLE_START).unwrap();
        let b = t.as_bytes();
        assert_eq!(&b[0..4], b"_MP_");
        assert_eq!(u32le(b, 4), (MP_TABLE_START + 16) as u32);
        assert_eq!(b[8], 1);
        assert_eq!(b[9], 4);
        assert_eq!(b[11], 0);
        assert_eq!(b[12], 0);
        assert_eq!(sum(&b[0..16]), 0);
    }

    /// MVM-1・#3888: configuration table の署名・長さ・checksum・LAPIC アドレス・項数。
    #[test]
    fn mvm1_3888_config_header_fields() {
        let t = build_mp_table(&cfg(2, &IRQS), MP_TABLE_START).unwrap();
        let c = &t.as_bytes()[16..];
        assert_eq!(&c[0..4], b"PCMP");
        assert_eq!(usize::from(u16le(c, 4)), c.len());
        assert_eq!(c[6], 4);
        assert_eq!(sum(c), 0);
        assert_eq!(&c[8..16], b"FANDHE  ");
        assert_eq!(u32le(c, 36), 0xFEE0_0000);
        // processor 2 + bus 1 + IOAPIC 1 + intsrc 5 + lintsrc 2
        assert_eq!(usize::from(u16le(c, 34)), 11);
        assert_eq!(c.len(), 44 + 2 * 20 + 8 * 9);
    }

    /// 設定表の項を種別ごとに分解する。
    fn entries(t: &MpTable) -> (Vec<[u8; 20]>, Vec<[u8; 8]>) {
        let c = &t.as_bytes()[16 + 44..];
        let (mut cpus, mut smalls, mut o) = (vec![], vec![], 0);
        while o < c.len() {
            if c[o] == 0 {
                cpus.push(<[u8; 20]>::try_from(&c[o..o + 20]).unwrap());
                o += 20;
            } else {
                smalls.push(<[u8; 8]>::try_from(&c[o..o + 8]).unwrap());
                o += 8;
            }
        }
        (cpus, smalls)
    }

    /// MVM-1・#3888: processor は N 件・LAPIC ID は 0..N-1・BSP は vCPU 0 だけ。
    #[test]
    fn mvm1_3888_processors() {
        for n in [1u32, 2, 4, 32] {
            let t = build_mp_table(&cfg(n, &IRQS), MP_TABLE_START).unwrap();
            let (cpus, _) = entries(&t);
            assert_eq!(cpus.len(), n as usize);
            for (i, e) in cpus.iter().enumerate() {
                assert_eq!(usize::from(e[1]), i);
                assert_eq!(e[2], 0x14);
                assert_eq!(e[3], if i == 0 { 3 } else { 1 });
                assert_eq!(&e[4..12], &[0u8; 8]);
            }
        }
    }

    /// MVM-1・#3888: bus・IOAPIC・interrupt source・local interrupt の具体値。
    #[test]
    fn mvm1_3888_bus_ioapic_and_interrupts() {
        let t = build_mp_table(&cfg(2, &IRQS), MP_TABLE_START).unwrap();
        let (_, s) = entries(&t);
        assert_eq!(s[0], [1, 0, b'I', b'S', b'A', b' ', b' ', b' ']);
        assert_eq!(s[1][0..4], [2, 32, 0x11, 1]);
        assert_eq!(u32le(&s[1], 4), IOAPIC_MMIO_BASE as u32);
        let src: Vec<(u8, u8)> = s[2..7].iter().map(|e| (e[5], e[7])).collect();
        assert_eq!(src, vec![(0, 2), (4, 4), (5, 5), (6, 6), (7, 7)]);
        for e in &s[2..7] {
            assert_eq!([e[0], e[1], e[2], e[3], e[4], e[6]], [3, 0, 0, 0, 0, 32]);
        }
        assert_eq!(s[7], [4, 3, 0, 0, 0, 0, 0xFF, 0]);
        assert_eq!(s[8], [4, 1, 0, 0, 0, 0, 0xFF, 1]);
    }

    /// MVM-1・#3888: Linux の走査（16 バイト刻み）で見つかる `_MP_` はちょうど 1 つで先頭。
    #[test]
    fn mvm1_3888_linux_style_scan_finds_one() {
        let mut mem =
            GuestMemory::new(GuestAddress::new(0), HeapBacking::new(2 << 20).unwrap()).unwrap();
        let t = build_mp_table(&cfg(4, &IRQS), MP_TABLE_START).unwrap();
        write_mp_table(&mut mem, &t).unwrap();
        let mut area = vec![0u8; (MP_TABLE_END - MP_TABLE_START) as usize];
        mem.read_at(GuestAddress::new(MP_TABLE_START), &mut area)
            .unwrap();
        let hits: Vec<usize> = (0..area.len())
            .step_by(16)
            .filter(|o| {
                &area[*o..*o + 4] == b"_MP_" && area[*o + 8] == 1 && sum(&area[*o..*o + 16]) == 0
            })
            .collect();
        assert_eq!(hits, vec![0]);
        assert_eq!(&area[..t.len()], t.as_bytes());
    }

    /// MVM-1・#3888・ERR-1: 不正な構成は INVALID_ARGUMENT で拒否する。
    #[test]
    fn mvm1_3888_rejects_invalid_configs() {
        let bad = |c: MpTableConfig<'_>| {
            let e = build_mp_table(&c, MP_TABLE_START).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        };
        bad(cfg(0, &IRQS));
        bad(cfg(255, &IRQS));
        bad(cfg(256, &IRQS));
        bad(MpTableConfig {
            ioapic_id: 1,
            ..cfg(2, &IRQS)
        });
        bad(cfg(2, &[route(16, 3)]));
        bad(cfg(2, &[route(3, 24)]));
        bad(cfg(2, &[route(3, 3), route(3, 4)]));
        bad(cfg(2, &[route(3, 3), route(4, 3)]));
        // 100 台は置き場所（1 KiB）に収まらない。
        bad(MpTableConfig {
            ioapic_id: 200,
            ..cfg(100, &IRQS)
        });
    }

    /// MVM-1・#3888: 最大構成（32 vCPU・IRQ 0・COM1・virtio 8 台）も置き場所に収まる。
    #[test]
    fn mvm1_3888_max_config_fits() {
        let mut irqs = vec![route(0, 2), route(4, 4)];
        irqs.extend((5..13).map(|g| route(g, g)));
        let t = build_mp_table(&cfg(32, &irqs), MP_TABLE_START).unwrap();
        assert_eq!(t.len(), 16 + 44 + 32 * 20 + 8 * (2 + 10 + 2));
        assert!(t.len() as u64 <= MP_TABLE_END - MP_TABLE_START);
    }

    /// MVM-1・#3888: SIPI で使えるどのベクタの起動コードも MP テーブルと重ならない。
    #[test]
    fn mvm1_3888_ap_startup_pages_never_overlap_table() {
        use crate::smp_x86::{SipiVector, sipi_startup_range};
        let mut ok = 0;
        for v in 0..=0xFFu8 {
            if let Ok(vec) = SipiVector::new(v)
                && let Ok((_, end)) = sipi_startup_range(vec, 16, 256 << 20)
            {
                assert!(end <= MP_TABLE_START, "vector {v:#x}");
                ok += 1;
            }
        }
        assert!(ok > 0);
    }

    /// MVM-1・#3888: 書き込みは RAM の外なら拒否される。
    #[test]
    fn mvm1_3888_write_outside_ram_is_rejected() {
        let mut mem =
            GuestMemory::new(GuestAddress::new(0), HeapBacking::new(0x8_0000).unwrap()).unwrap();
        let t = build_mp_table(&cfg(1, &IRQS), MP_TABLE_START).unwrap();
        assert!(write_mp_table(&mut mem, &t).is_err());
    }
}
