//! x86_64 の Linux カーネル（bzImage）・initrd・cmdline のゲストメモリへのロード（TASK-75.3.1・MVM-1・MS-7。OS 非依存・unsafe なし）。
//!
//! 呼び出し元は `MicroVm::load_kernel`（Linux のみ）と、将来の plugin-microvm（TASK-117）。
//! 戻り値の [`LoadedKernel`] を #885（TASK-75.3.2）の [`BootCpuState::for_kernel`] が受け取り、`entry` を RIP、`boot_params` を RSI に設定する。
//! `MicroVm::setup_boot_vcpu` が [`write_boot_tables`] で GDT・IDT・ページテーブルを書き、vCPU 0 へ [`BootCpuState`] を設定する。
//!
//! # 準拠するブートプロトコル（一次情報）
//! kernel.org の v6.12 の `Documentation/arch/x86/boot.rst`（setup header・64-bit Boot Protocol）と
//! `Documentation/arch/x86/zero-page.rst`（boot_params の配置）。定数と配置はこの 2 つの文書から自前で導いた。
//! Firecracker・rust-vmm（`linux-loader` 等）のコードは参照も流用もしない（MVM-4）。
//!
//! - bzImage の setup header（イメージの 0x1F1 から、`0x202 + (0x201 の値)` まで）を boot_params の同じオフセットへ写し、
//!   loader が書くフィールド（`type_of_loader`・`ramdisk_image` / `ramdisk_size`・`cmd_line_ptr`）と e820 を埋める。
//! - protected-mode 部（イメージのオフセット `(setup_sects + 1) * 512` から末尾）を `load_addr` へ置く。
//!   64-bit のエントリは `load_addr + 0x200`（`XLF_KERNEL_64`）。
//! - 実行時の展開先の開始は relocatable なら `max(align_up(load_addr, kernel_alignment), pref_address)`、
//!   でなければ `pref_address`（`arch/x86/boot/compressed/head_64.S` が `LOAD_PHYSICAL_ADDR` と比べて大きい方を使う）。
//!   `[runtime_start, runtime_start + init_size)` が RAM に収まらない配置は拒否する（`init_size`）。
//! - initrd は `initrd_addr_max` 以下かつカーネルの確保域より上、4 KiB 境界の先頭に置く。
//!
//! # 低位メモリの配置
//! [`ZERO_PAGE_ADDR`]・[`CMDLINE_ADDR`] と、#885 が使う GDT（[`BOOT_GDT_START`]）・IDT（[`BOOT_IDT_START`]）・起動スタック
//! （[`BOOT_STACK_TOP`]）・ページテーブル（[`BOOT_PML4_ADDR`]..[`BOOT_TABLES_END`]。`[BOOT_SCRATCH_START, BOOT_SCRATCH_END)` の内側）
//! を 1 か所で定義し、重ならないことを `const` の assert で担保する。
//!
//! # vCPU の初期状態（TASK-75.3.2）
//! 64-bit Boot Protocol（boot.rst）の条件に従う: long mode（CR0.PE|PG・CR4.PAE・EFER.LME|LMA）・`__BOOT_CS`（0x10）/ `__BOOT_DS`（0x18）・
//! RSI = boot_params・割り込み禁止（IF=0）・GPA 0..4 GiB の 2 MiB ページによる恒等写像（カーネルの確保域・zero page・cmdline を覆う）。
//! GDT のバイト列と `kvm_segment` の値は同じ記述子から導き、食い違いを型と試験で防ぐ（REPAIR-2）。
//!
//! # MSR・FPU の初期値（#3734・MVM-1）
//! [`boot_msrs`] が vCPU 0 の `KVM_SET_MSRS` に渡す表、[`X86FpuState::boot`] が `KVM_SET_FPU` に渡す値を KVM から切り離して組み立てる
//! （既定のテスト集合で具体値を照合するため。適用は `device::VcpuFd::{set_msrs, set_fpu}`、呼び出しは `MicroVm::setup_boot_vcpu`）。
//!
//! | MSR | index | 値 | 根拠 |
//! | --- | ----- | -- | ---- |
//! | IA32_TSC | 0x10 | 0 | 起動時の TSC を 0 にそろえる |
//! | IA32_SYSENTER_CS / ESP / EIP | 0x174 / 0x175 / 0x176 | 0 | カーネルが `syscall_init`（`arch/x86/kernel/cpu/common.c`）で自分で書く。起動時は既知の 0 |
//! | IA32_MISC_ENABLE | 0x1A0 | 0x1801 | bit0 FAST_STRING を立てる。落ちていると `early_init_intel`（`arch/x86/kernel/cpu/intel.c`）が REP_GOOD / ERMS を落とす。bit11 BTS_UNAVAIL・bit12 PEBS_UNAVAIL は KVM の vCPU 作成時の既定を保つ |
//! | STAR / LSTAR / CSTAR / SFMASK | 0xC000_0081..0084 | 0 | `syscall_init` が書く。0 は canonical 検査に通る |
//! | KERNEL_GS_BASE | 0xC000_0102 | 0 | 同上（`swapgs` 用。カーネルが設定） |
//!
//! 外したもの: MTRRdefType（0x2FF）など CPUID の機能ビットに依存する MSR は、CPUID の設定（#3733）に依存するため今回は入れない。
//! 一次情報は Linux v6.12 の `arch/x86/include/asm/msr-index.h`・`arch/x86/kvm/x86.c`、`Documentation/virt/kvm/api.rst`
//! （KVM_SET_MSRS / KVM_SET_FPU）、Intel SDM Vol.1（FNINIT 後の FCW = 0x37F・MXCSR = 0x1F80）・Vol.4（MSR 番号）。実機での受理と
//! 読み戻しは `tests/kvm_device.rs` で照合する（MXCSR は Linux 7.0.0-34 の `KVM_GET_FPU` が常に 0 を返し照合できない。観測は後続。REPAIR-3）。Firecracker・rust-vmm のコードは参照しない（MVM-4）。
//!
//! FPU は `KVM_SET_FPU`（レガシー領域）だけを設定し、XSAVE / XCRS は設定しない。KVM の vCPU リセットで XCR0 は x87 のみ・xsave ヘッダは
//! 既知の状態になり、ゲストカーネルは CPUID（#3733）を見て自分で XSETBV する。`KVM_SET_XSAVE` / `KVM_SET_XCRS` が要るのは
//! スナップショットと復元の用途で、その用途は未実装（REPAIR-3）。
//!
//! # 範囲外（REPAIR-3）
//! ELF vmlinux・PVH エントリ・aarch64 の FDT / Image・`setup_data`・ACPI（MP テーブルは `mptable_x86`・#3888）・EFI・4 GiB 超への配置（`ext_*`）・
//! 複数の RAM 領域・`min_alignment`・MSR / FPU / LAPIC の設定（CPUID は `cpuid_x86`・#3733。実カーネルの起動完走に必要。#886 以降の追跡事項）・start / stop（#886）・
//! ファイルからの読み込み（呼び出し元が上限つきで読んで渡す）は未実装。
//!
//! # 外部入力の扱い
//! カーネルイメージ・initrd・cmdline は非信頼入力。長さは上限定数で書き込みの前に拒否し、オフセット計算は checked 演算と
//! `try_from` だけで行い、計画がすべて通るまでゲストメモリへ書かない。エラーの `message` に値は載せない（ERR-1）。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestAddress, GuestMemory, GuestMemoryBacking, GuestMemoryRegion};

/// カーネルイメージの長さの上限。
pub const MAX_KERNEL_IMAGE_BYTES: u64 = 128 << 20;
/// initrd の長さの上限。
pub const MAX_INITRD_BYTES: u64 = 1 << 30;

/// boot_params（zero page）の GPA。
pub const ZERO_PAGE_ADDR: u64 = 0x7000;
/// zero page の大きさ。
pub const ZERO_PAGE_SIZE: usize = 4096;
/// 起動用 GDT（4 エントリ・32 バイト）の GPA（TASK-75.3.2）。
pub const BOOT_GDT_START: u64 = 0x500;
/// 起動用 IDT（空の 8 バイト）の GPA。GDT の直後（TASK-75.3.2）。
pub const BOOT_IDT_START: u64 = 0x520;
/// 起動スタックと起動用ページテーブルに使う領域の先頭。
pub const BOOT_SCRATCH_START: u64 = 0x8000;
/// 起動スタックの初期 RSP（16 バイト整列。`BOOT_SCRATCH_START` へ向けて下へ伸びる 4 KiB 弱）。
pub const BOOT_STACK_TOP: u64 = 0x8FF0;
/// PML4 の GPA（CR3）。
pub const BOOT_PML4_ADDR: u64 = 0x9000;
/// PDPT の GPA。
pub const BOOT_PDPT_ADDR: u64 = 0xA000;
/// PD（4 ページ = 4 GiB 分）の先頭の GPA。
pub const BOOT_PD_ADDR: u64 = 0xB000;
/// 起動用ページテーブルの終端（排他）。
pub const BOOT_TABLES_END: u64 = 0xF000;
/// 恒等写像する GPA の上限（排他。4 GiB）。
pub const IDENTITY_MAP_LIMIT: u64 = 4 << 30;
/// 同領域の終端（排他）。起動用ページテーブルは [`BOOT_TABLES_END`] までで、以降は将来の拡張用。
pub const BOOT_SCRATCH_END: u64 = 0x2_0000;
/// cmdline の GPA。
pub const CMDLINE_ADDR: u64 = 0x2_0000;
/// cmdline の領域の大きさ（終端 NUL を含む）。
pub const CMDLINE_CAPACITY: u64 = 4096;
/// 低位 RAM の終端（排他。e820 の 1 本目の終わり）。
pub const LOW_RAM_END: u64 = 0x9_FC00;
/// MP テーブル（#3888・MVM-1）の置き場所の先頭。基本メモリの最後の 1 KiB（`[LOW_RAM_END, MP_TABLE_END)`）で、
/// Linux v6.12 の `smp_scan_config` が `_MP_` を探す 4 範囲のひとつ（639 KiB から 640 KiB）。e820 では予約にする。
pub const MP_TABLE_START: u64 = LOW_RAM_END;
/// MP テーブルの置き場所の終端（排他。640 KiB）。
pub const MP_TABLE_END: u64 = 0xA_0000;
/// カーネルのロード先の下限（1 MiB）。
pub const HIMEM_START: u64 = 0x10_0000;

const _: () = assert!(BOOT_GDT_START + BOOT_GDT_BYTES as u64 <= BOOT_IDT_START);
const _: () = assert!(BOOT_IDT_START + BOOT_IDT_BYTES as u64 <= ZERO_PAGE_ADDR);
const _: () = assert!(BOOT_SCRATCH_START < BOOT_STACK_TOP);
const _: () = assert!(BOOT_STACK_TOP.is_multiple_of(16));
const _: () = assert!(BOOT_STACK_TOP < BOOT_PML4_ADDR);
const _: () = assert!(BOOT_PML4_ADDR + 0x1000 <= BOOT_PDPT_ADDR);
const _: () = assert!(BOOT_PDPT_ADDR + 0x1000 <= BOOT_PD_ADDR);
const _: () = assert!(BOOT_PD_ADDR + (IDENTITY_MAP_LIMIT >> 30) * 0x1000 == BOOT_TABLES_END);
const _: () = assert!(BOOT_TABLES_END <= BOOT_SCRATCH_END);
const _: () = assert!(ZERO_PAGE_ADDR + ZERO_PAGE_SIZE as u64 <= BOOT_SCRATCH_START);
const _: () = assert!(BOOT_SCRATCH_START < BOOT_SCRATCH_END);
const _: () = assert!(BOOT_SCRATCH_END <= CMDLINE_ADDR);
const _: () = assert!(CMDLINE_ADDR + CMDLINE_CAPACITY <= LOW_RAM_END);
const _: () = assert!(LOW_RAM_END <= HIMEM_START);
const _: () = assert!(CMDLINE_ADDR + CMDLINE_CAPACITY <= MP_TABLE_START);
const _: () = assert!(MP_TABLE_START < MP_TABLE_END);
const _: () = assert!(MP_TABLE_END <= HIMEM_START);
const _: () = assert!(MP_TABLE_START.is_multiple_of(16));

const BOOT_GDT_BYTES: usize = 32;
const BOOT_IDT_BYTES: usize = 8;

// --- setup header のオフセット（boot.rst の表と 1 対 1） ---
const OFF_SETUP_SECTS: usize = 0x1F1;
const OFF_BOOT_FLAG: usize = 0x1FE;
const OFF_HEADER_END_LEN: usize = 0x201;
const OFF_HEADER_MAGIC: usize = 0x202;
const OFF_VERSION: usize = 0x206;
const OFF_TYPE_OF_LOADER: usize = 0x210;
const OFF_LOADFLAGS: usize = 0x211;
const OFF_RAMDISK_IMAGE: usize = 0x218;
const OFF_RAMDISK_SIZE: usize = 0x21C;
const OFF_CMD_LINE_PTR: usize = 0x228;
const OFF_INITRD_ADDR_MAX: usize = 0x22C;
const OFF_KERNEL_ALIGNMENT: usize = 0x230;
const OFF_RELOCATABLE: usize = 0x234;
const OFF_XLOADFLAGS: usize = 0x236;
const OFF_CMDLINE_SIZE: usize = 0x238;
const OFF_PREF_ADDRESS: usize = 0x258;
const OFF_INIT_SIZE: usize = 0x260;
/// `init_size` の終端。setup header がここまで届かないイメージは拒否する。
const SETUP_HEADER_MIN_END: usize = OFF_INIT_SIZE + 4;

// --- boot_params のオフセット ---
const OFF_E820_ENTRIES: usize = 0x1E8;
const OFF_E820_TABLE: usize = 0x2D0;
const E820_ENTRY_SIZE: usize = 20;
const E820_MAX: usize = 128;

const BOOT_FLAG: u16 = 0xAA55;
/// "HdrS" のリトルエンディアン。
const HEADER_MAGIC: u32 = 0x5372_6448;
/// 2.12（`XLF_KERNEL_64`・`init_size` を確かめられる最小版）。
const MIN_PROTOCOL_VERSION: u16 = 0x020C;
const LOADED_HIGH: u8 = 1;
const XLF_KERNEL_64: u16 = 1;
/// ID を持たないローダーの `type_of_loader`。
const LOADER_TYPE_UNDEFINED: u8 = 0xFF;
/// 64-bit エントリのカーネル先頭からのオフセット。
const ENTRY_64_OFFSET: u64 = 0x200;
const E820_RAM: u32 = 1;
/// e820 の予約（type 2）。MP テーブルの範囲に使う。
const E820_RESERVED: u32 = 2;
const INITRD_ALIGN: u64 = 4096;
const MAX_KERNEL_ALIGNMENT: u64 = 1 << 30;

fn err(code: MicrovmErrorCode, message: &'static str) -> MicrovmError {
    MicrovmError::new(code, message)
}

fn invalid(message: &'static str) -> MicrovmError {
    err(MicrovmErrorCode::InvalidArgument, message)
}

fn rd<const N: usize>(img: &[u8], off: usize) -> Result<[u8; N], MicrovmError> {
    off.checked_add(N)
        .and_then(|end| img.get(off..end))
        .and_then(|s| <[u8; N]>::try_from(s).ok())
        .ok_or_else(|| invalid("kernel image is truncated"))
}

fn rd_u8(img: &[u8], off: usize) -> Result<u8, MicrovmError> {
    let [b] = rd::<1>(img, off)?;
    Ok(b)
}
fn rd_u16(img: &[u8], off: usize) -> Result<u16, MicrovmError> {
    Ok(u16::from_le_bytes(rd(img, off)?))
}
fn rd_u32(img: &[u8], off: usize) -> Result<u32, MicrovmError> {
    Ok(u32::from_le_bytes(rd(img, off)?))
}
fn rd_u64(img: &[u8], off: usize) -> Result<u64, MicrovmError> {
    Ok(u64::from_le_bytes(rd(img, off)?))
}

fn align_up(v: u64, align: u64) -> Option<u64> {
    let m = align.checked_sub(1)?;
    v.checked_add(m).map(|x| x & !m)
}

/// bzImage から検証つきで読んだ setup header。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupHeader {
    /// プロトコルの版（2.12 以上）。
    pub version: u16,
    /// protected-mode 部のイメージ内のオフセット（`(setup_sects + 1) * 512`）。
    pub payload_offset: usize,
    /// `initrd_addr_max`（initrd が占めてよい最上位のバイトのアドレス）。
    pub initrd_addr_max: u32,
    /// `kernel_alignment`。
    pub kernel_alignment: u32,
    /// `relocatable_kernel` が非 0 か。
    pub relocatable: bool,
    /// `cmdline_size`（終端 NUL を含まない最大長）。
    pub cmdline_size: u32,
    /// `pref_address`。
    pub pref_address: u64,
    /// `init_size`。
    pub init_size: u32,
    /// boot_params へ写す setup header のバイト列（イメージの 0x1F1 から header の終端まで）。
    header_bytes: Vec<u8>,
}

impl SetupHeader {
    /// イメージを検証して解析する。ELF・magic の欠落・古い版・`XLF_KERNEL_64` / `LOADED_HIGH` の欠落・header の不足は拒否する。
    pub fn parse(image: &[u8]) -> Result<SetupHeader, MicrovmError> {
        if image.len() as u64 > MAX_KERNEL_IMAGE_BYTES {
            return Err(invalid("kernel image too large"));
        }
        if image.starts_with(b"\x7fELF") {
            return Err(err(
                MicrovmErrorCode::Unimplemented,
                "ELF vmlinux kernel images are not supported",
            ));
        }
        if rd_u16(image, OFF_BOOT_FLAG)? != BOOT_FLAG {
            return Err(invalid("kernel image has no boot flag"));
        }
        if rd_u32(image, OFF_HEADER_MAGIC)? != HEADER_MAGIC {
            return Err(invalid("kernel image has no setup header magic"));
        }
        let version = rd_u16(image, OFF_VERSION)?;
        if version < MIN_PROTOCOL_VERSION {
            return Err(invalid("boot protocol version is older than 2.12"));
        }
        if rd_u8(image, OFF_LOADFLAGS)? & LOADED_HIGH == 0 {
            return Err(invalid("kernel image is not a bzImage (LOADED_HIGH unset)"));
        }
        if rd_u16(image, OFF_XLOADFLAGS)? & XLF_KERNEL_64 == 0 {
            return Err(invalid(
                "kernel image has no 64-bit entry (XLF_KERNEL_64 unset)",
            ));
        }
        let setup_sects = match rd_u8(image, OFF_SETUP_SECTS)? {
            0 => 4usize,
            n => usize::from(n),
        };
        let payload_offset = setup_sects
            .checked_add(1)
            .and_then(|n| n.checked_mul(512))
            .ok_or_else(|| invalid("kernel setup size overflows"))?;
        if payload_offset >= image.len() {
            return Err(invalid("kernel image has no protected-mode part"));
        }
        let header_end = OFF_HEADER_MAGIC
            .checked_add(usize::from(rd_u8(image, OFF_HEADER_END_LEN)?))
            .ok_or_else(|| invalid("setup header end overflows"))?;
        if header_end < SETUP_HEADER_MIN_END || header_end > payload_offset {
            return Err(invalid("setup header length is invalid"));
        }
        let header_bytes = image
            .get(OFF_SETUP_SECTS..header_end)
            .ok_or_else(|| invalid("kernel image is truncated"))?
            .to_vec();
        Ok(SetupHeader {
            version,
            payload_offset,
            initrd_addr_max: rd_u32(image, OFF_INITRD_ADDR_MAX)?,
            kernel_alignment: rd_u32(image, OFF_KERNEL_ALIGNMENT)?,
            relocatable: rd_u8(image, OFF_RELOCATABLE)? != 0,
            cmdline_size: rd_u32(image, OFF_CMDLINE_SIZE)?,
            pref_address: rd_u64(image, OFF_PREF_ADDRESS)?,
            init_size: rd_u32(image, OFF_INIT_SIZE)?,
            header_bytes,
        })
    }
}

/// カーネル cmdline に足す virtio-mmio デバイス 1 台（`virtio_mmio.device=<size>@<base>:<irq>`）。
///
/// 一次情報: v6.12 の `drivers/virtio/virtio_mmio.c` 先頭のコメント。size・base は 16 進、irq は 10 進で書く。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioMmioParam {
    /// MMIO の窓の先頭（GPA）。
    pub base: u64,
    /// MMIO の窓の大きさ。
    pub len: u64,
    /// 割り込みの GSI。
    pub gsi: u32,
}

/// `user` を引用符の外の単独の `--` で `(前半, 後半)` に分ける（後半は `--` を含む。`--` が無ければ後半は空）。
/// 閉じていない引用符は `InvalidArgument`。前半の末尾の空白は落とす。
fn split_at_init_args(user: &str) -> Result<(&str, &str), MicrovmError> {
    let bytes = user.as_bytes();
    let mut in_quote = false;
    let mut split: Option<usize> = None;
    let mut start = 0usize;
    let mut i = 0usize;
    while i <= bytes.len() {
        let c = bytes.get(i).copied();
        if c == Some(b'"') {
            in_quote = !in_quote;
        } else if !in_quote && (c.is_none() || c == Some(b' ')) {
            if split.is_none()
                && let Some(tok) = bytes.get(start..i)
            {
                if tok == b"--".as_slice() {
                    split = Some(start);
                } else if tok.contains(&b'"') && tok.iter().filter(|&&b| b != b'"').eq(b"--".iter())
                {
                    // Linux は引用符を除去してからトークン化するため、`"--"` も init 引数の区切りになる。
                    // 区切り位置を誤ると後ろに足す virtio_mmio.device が init の引数になるため拒否する。
                    return Err(invalid(
                        "quoted \"--\" in kernel command line is not supported",
                    ));
                }
            }
            start = i + 1;
        }
        i += 1;
    }
    if in_quote {
        return Err(invalid("kernel command line has an unclosed quote"));
    }
    match split {
        Some(off) => {
            let head = user
                .get(..off)
                .ok_or_else(|| invalid("kernel command line split failed"))?;
            let tail = user
                .get(off..)
                .ok_or_else(|| invalid("kernel command line split failed"))?;
            Ok((head.trim_end_matches(' '), tail))
        }
        None => Ok((user, "")),
    }
}

/// 利用者の cmdline に、この VM が PIT を持たないために必要な `no_timer_check` を足す（MVM-1・#3888）。
///
/// MP テーブルでゲストが IOAPIC モードになると Linux は IRQ 0 の `check_timer` を走らせるが、この VM には PIT も
/// タイマー割り込みの注入経路も無く検査に失敗して起動できない。そのため `microvm.rs` の `load_kernel` が
/// 常に付ける（Linux x86_64 以外では呼び出し元が無いため、試験を除き `cfg` で除外する）。init 引数の区切り `--` より前（head の末尾）へ入れ、利用者が既に指定していれば足さない。
#[cfg(any(all(target_os = "linux", target_arch = "x86_64"), test))]
pub(crate) fn with_no_timer_check(user: &str) -> Result<String, MicrovmError> {
    // 公開 API の直接呼び出しでも、複製の前に上限を超える入力を拒否する（確保の無制限化を防ぐ）。
    if user.len() as u64 >= CMDLINE_CAPACITY {
        return Err(invalid("kernel command line too long"));
    }
    let (head, tail) = split_at_init_args(user)?;
    let mut text = head.to_owned();
    if !has_standalone_token(head, "no_timer_check") {
        if !text.is_empty() {
            text.push(' ');
        }
        text.push_str("no_timer_check");
    }
    if !tail.is_empty() {
        text.push(' ');
        text.push_str(tail);
    }
    if text.len() as u64 >= CMDLINE_CAPACITY {
        return Err(invalid("kernel command line too long"));
    }
    Ok(text)
}

/// 引用符の外の空白で区切った独立トークンに `name` が完全一致で含まれるか。
/// `foo="x no_timer_check y"` のように引用符内にある文字列は独立した引数とみなさない。
#[cfg(any(all(target_os = "linux", target_arch = "x86_64"), test))]
fn has_standalone_token(text: &str, name: &str) -> bool {
    let mut in_quote = false;
    let mut start = 0usize;
    let bytes = text.as_bytes();
    for i in 0..=bytes.len() {
        let c = bytes.get(i).copied();
        if c == Some(b'"') {
            in_quote = !in_quote;
        } else if !in_quote && (c.is_none() || c == Some(b' ')) {
            if text.get(start..i) == Some(name) {
                return true;
            }
            start = i + 1;
        }
    }
    false
}

/// 検証済みの cmdline（印字可能な ASCII のみ。virtio-mmio の項目はコードが型つきの値から生成して足す）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelCmdline {
    text: String,
}

impl KernelCmdline {
    /// 利用者の部分 `user` を検証し、`devices` の項目を末尾に足す。NUL・改行・制御文字・非 ASCII・長さ超過は `InvalidArgument`。
    pub fn new(user: &str, devices: &[VirtioMmioParam]) -> Result<KernelCmdline, MicrovmError> {
        if user.len() as u64 >= CMDLINE_CAPACITY {
            return Err(invalid("kernel command line too long"));
        }
        if !user.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
            return Err(invalid(
                "kernel command line must be printable ASCII without control characters",
            ));
        }
        // カーネルは引用符の外の単独の `--` 以降を init の引数として扱うため、自動生成項目はその前に挿入する。
        let (head, tail) = split_at_init_args(user)?;
        let mut text = head.to_owned();
        // 追加前に残り容量（終端 NUL 分を含む）を確認し、拒否する入力のために確保を膨らませない。
        let limit = usize::try_from(CMDLINE_CAPACITY - 1).unwrap_or(0);
        let mut total = text.len()
            + if tail.is_empty() {
                0
            } else {
                tail.len() + usize::from(!text.is_empty())
            };
        for d in devices {
            let item = format!("virtio_mmio.device=0x{:x}@0x{:x}:{}", d.len, d.base, d.gsi);
            let add = item.len() + usize::from(!text.is_empty());
            // head が空で tail だけのとき、tail の前の区切りは head 側の空白としては数えない。
            total = total.saturating_add(add);
            if total > limit {
                return Err(invalid("kernel command line too long"));
            }
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(&item);
        }
        if !tail.is_empty() {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(tail);
        }
        if text.len() as u64 >= CMDLINE_CAPACITY {
            return Err(invalid("kernel command line too long"));
        }
        Ok(KernelCmdline { text })
    }

    /// 終端 NUL を含まない文字列。
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

/// e820 の 1 エントリ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E820Entry {
    /// 先頭アドレス。
    pub addr: u64,
    /// 長さ。
    pub size: u64,
    /// 種別（1 = RAM・2 = 予約）。
    pub kind: u32,
}

/// ロード先の計画（純粋な計算の結果。書き込みはこれがすべて通ってから行う）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootPlan {
    /// protected-mode 部のロード先。
    pub load_addr: u64,
    /// カーネルが確保する範囲の終端（排他）。
    pub kernel_end: u64,
    /// initrd の GPA と長さ。
    pub initrd: Option<(u64, u64)>,
    /// e820 の表。
    pub e820: Vec<E820Entry>,
}

/// ロード先・initrd の位置・e820 を決める。`ram` は登録済みの RAM 領域（base の昇順。#3697）。
///
/// 先頭の領域は GPA 0 から始まること。カーネル・initrd・boot_params は先頭の領域（low RAM）の中に置き、
/// e820 は領域の一覧から機械的に作る（先頭の領域は従来の 3 本、2 番目以降は RAM 1 本ずつ）ので、KVM に登録した memslot と一致する。
pub fn plan_boot(
    header: &SetupHeader,
    payload_len: u64,
    initrd_len: Option<u64>,
    ram: &[GuestMemoryRegion],
) -> Result<BootPlan, MicrovmError> {
    let (first, rest) = ram
        .split_first()
        .ok_or_else(|| invalid("guest memory has no region"))?;
    if first.base != GuestAddress::new(0) {
        return Err(invalid("guest memory must start at GPA 0"));
    }
    let mem_len = first.len;
    if mem_len <= HIMEM_START {
        return Err(invalid("guest memory is too small for a kernel"));
    }
    let align = u64::from(header.kernel_alignment);
    let align_ok = align.is_power_of_two() && align <= MAX_KERNEL_ALIGNMENT;
    let pref = header.pref_address;
    let pref_usable =
        pref >= HIMEM_START && (!header.relocatable || (align_ok && pref.is_multiple_of(align)));
    // 実際の展開先の開始。relocatable は head_64.S と同じく max(align_up(load_addr, kernel_alignment), pref_address)
    // （pref_address は LOAD_PHYSICAL_ADDR 相当）、非 relocatable は pref_address 固定。
    // 確保域は protected-mode 部の置き場所と、展開先の `[run_start, run_start + init_size)` の和の終端まで。
    let range_end = |load_addr: u64| -> Result<u64, MicrovmError> {
        let run_start = if header.relocatable {
            align_up(load_addr, align)
                .ok_or_else(|| invalid("kernel load range overflows"))?
                .max(pref)
        } else {
            pref
        };
        load_addr
            .checked_add(payload_len)
            .zip(run_start.checked_add(u64::from(header.init_size)))
            .map(|(a, b)| a.max(b))
            .ok_or_else(|| invalid("kernel load range overflows"))
    };
    let relocated = || -> Result<u64, MicrovmError> {
        align_up(HIMEM_START, align).ok_or_else(|| invalid("kernel load address overflows"))
    };
    // 配置の候補を優先順に並べ、カーネルと initrd の両方が収まる最初の候補を採る。
    // relocatable は pref_address で収まらない場合（カーネル単体・initrd のどちらでも）再配置先
    // （1 MiB を alignment で切り上げた位置）を試す。非 relocatable は pref_address 固定。
    let mut candidates: [Option<u64>; 2] = [None, None];
    if pref_usable {
        candidates[0] = Some(pref);
        if header.relocatable && align_ok {
            candidates[1] = Some(relocated()?);
        }
    } else if header.relocatable && align_ok {
        candidates[0] = Some(relocated()?);
    } else {
        return Err(invalid(
            "kernel cannot be placed (alignment or preferred address)",
        ));
    }
    let place = |load_addr: u64| -> Result<(u64, Option<(u64, u64)>), MicrovmError> {
        let kernel_end = range_end(load_addr)?;
        if kernel_end > mem_len {
            return Err(err(
                MicrovmErrorCode::ResourceExhausted,
                "kernel does not fit in guest memory",
            ));
        }
        let floor = kernel_end;
        let initrd = match initrd_len {
            None => None,
            Some(0) => return Err(invalid("initrd must not be empty")),
            Some(len) => {
                let top = mem_len.min(u64::from(header.initrd_addr_max) + 1);
                let start = top
                    .checked_sub(len)
                    .map(|s| s & !(INITRD_ALIGN - 1))
                    .filter(|s| *s >= floor)
                    .ok_or_else(|| {
                        err(
                            MicrovmErrorCode::ResourceExhausted,
                            "initrd does not fit in guest memory",
                        )
                    })?;
                Some((start, len))
            }
        };
        Ok((kernel_end, initrd))
    };
    let mut chosen = None;
    let mut first_err: Option<MicrovmError> = None;
    for load_addr in candidates.into_iter().flatten() {
        match place(load_addr) {
            Ok((end, initrd)) => {
                chosen = Some((load_addr, end, initrd));
                break;
            }
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    let (load_addr, kernel_end, initrd) = match chosen {
        Some(c) => c,
        None => {
            return Err(first_err.unwrap_or_else(|| invalid("kernel cannot be placed")));
        }
    };
    let mut e820 = vec![
        E820Entry {
            addr: 0,
            size: LOW_RAM_END,
            kind: E820_RAM,
        },
        E820Entry {
            addr: MP_TABLE_START,
            size: MP_TABLE_END - MP_TABLE_START,
            kind: E820_RESERVED,
        },
        E820Entry {
            addr: HIMEM_START,
            size: mem_len - HIMEM_START,
            kind: E820_RAM,
        },
    ];
    for r in rest {
        e820.push(E820Entry {
            addr: r.base.raw(),
            size: r.len,
            kind: E820_RAM,
        });
    }
    Ok(BootPlan {
        load_addr,
        kernel_end,
        initrd,
        e820,
    })
}

/// boot_params（zero page）。名前つきのオフセットと型つきの setter だけで組み立てる。
struct ZeroPage([u8; ZERO_PAGE_SIZE]);

impl ZeroPage {
    fn new(header: &SetupHeader) -> Result<ZeroPage, MicrovmError> {
        let mut page = ZeroPage([0u8; ZERO_PAGE_SIZE]);
        page.put(OFF_SETUP_SECTS, &header.header_bytes)?;
        page.put(OFF_TYPE_OF_LOADER, &[LOADER_TYPE_UNDEFINED])?;
        Ok(page)
    }

    fn put(&mut self, off: usize, data: &[u8]) -> Result<(), MicrovmError> {
        off.checked_add(data.len())
            .and_then(|end| self.0.get_mut(off..end))
            .ok_or_else(|| invalid("boot params field out of range"))?
            .copy_from_slice(data);
        Ok(())
    }

    fn set_ramdisk(&mut self, image: u32, size: u32) -> Result<(), MicrovmError> {
        self.put(OFF_RAMDISK_IMAGE, &image.to_le_bytes())?;
        self.put(OFF_RAMDISK_SIZE, &size.to_le_bytes())
    }

    fn set_cmd_line_ptr(&mut self, ptr: u32) -> Result<(), MicrovmError> {
        self.put(OFF_CMD_LINE_PTR, &ptr.to_le_bytes())
    }

    fn set_e820(&mut self, entries: &[E820Entry]) -> Result<(), MicrovmError> {
        if entries.len() > E820_MAX {
            return Err(invalid("too many e820 entries"));
        }
        for (i, e) in entries.iter().enumerate() {
            let base = OFF_E820_TABLE + i * E820_ENTRY_SIZE;
            self.put(base, &e.addr.to_le_bytes())?;
            self.put(base + 8, &e.size.to_le_bytes())?;
            self.put(base + 16, &e.kind.to_le_bytes())?;
        }
        self.put(OFF_E820_ENTRIES, &[entries.len() as u8])
    }
}

/// ロード結果（[`BootCpuState::for_kernel`] がレジスタ初期化に使う）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LoadedKernel {
    /// 64-bit エントリ（RIP の初期値。`load_addr + 0x200`）。
    pub entry: GuestAddress,
    /// boot_params の GPA（RSI の初期値）。
    pub boot_params: GuestAddress,
    /// protected-mode 部の GPA。
    pub kernel_addr: GuestAddress,
    /// protected-mode 部の長さ。
    pub kernel_len: u64,
    /// カーネルが確保する範囲の終端（排他。[`write_boot_tables`] の恒等写像（4 GiB まで）の対象）。
    pub runtime_end: u64,
    /// cmdline の GPA。
    pub cmdline: GuestAddress,
    /// cmdline の長さ（終端 NUL を含まない）。
    pub cmdline_len: u64,
    /// initrd の GPA と長さ。
    pub initrd: Option<(GuestAddress, u64)>,
    /// プロトコルの版。
    pub protocol_version: u16,
}

/// カーネル・initrd・cmdline・boot_params をゲストメモリへ書く。検証と計画が全部通ってから書き込む。
pub fn load_linux<B: GuestMemoryBacking>(
    mem: &mut GuestMemory<B>,
    kernel: &[u8],
    initrd: Option<&[u8]>,
    cmdline: &KernelCmdline,
) -> Result<LoadedKernel, MicrovmError> {
    if mem.base() != GuestAddress::new(0) {
        return Err(invalid("guest memory must start at GPA 0"));
    }
    let header = SetupHeader::parse(kernel)?;
    if initrd.is_some_and(|i| i.len() as u64 > MAX_INITRD_BYTES) {
        return Err(invalid("initrd too large"));
    }
    let payload = kernel
        .get(header.payload_offset..)
        .ok_or_else(|| invalid("kernel image has no protected-mode part"))?;
    let payload_len = payload.len() as u64;
    // 返す entry（load_addr + ENTRY_64_OFFSET）が書き込む payload の内側であることを書き込み前に保証する。
    if payload_len <= ENTRY_64_OFFSET {
        return Err(invalid(
            "kernel protected-mode part does not contain the 64-bit entry point",
        ));
    }
    let plan = plan_boot(
        &header,
        payload_len,
        initrd.map(|i| i.len() as u64),
        &mem.regions(),
    )?;

    let cmd_bytes = cmdline.as_str().as_bytes();
    let cmd_len = cmd_bytes.len() as u64;
    if cmd_len > u64::from(header.cmdline_size).min(CMDLINE_CAPACITY - 1) {
        return Err(invalid("kernel command line exceeds the kernel's limit"));
    }

    let mut page = ZeroPage::new(&header)?;
    if let Some((addr, len)) = plan.initrd {
        let image = u32::try_from(addr).map_err(|_| invalid("initrd address exceeds 4 GiB"))?;
        let size = u32::try_from(len).map_err(|_| invalid("initrd size exceeds 4 GiB"))?;
        page.set_ramdisk(image, size)?;
    } else {
        // 入力イメージの header に非ゼロの値があっても、置いていない initrd をゲストに渡さない。
        page.set_ramdisk(0, 0)?;
    }
    page.set_cmd_line_ptr(CMDLINE_ADDR as u32)?;
    page.set_e820(&plan.e820)?;

    mem.write_at(GuestAddress::new(plan.load_addr), payload)?;
    if let (Some((addr, _)), Some(data)) = (plan.initrd, initrd) {
        mem.write_at(GuestAddress::new(addr), data)?;
    }
    let mut cmd_with_nul = Vec::with_capacity(cmd_bytes.len() + 1);
    cmd_with_nul.extend_from_slice(cmd_bytes);
    cmd_with_nul.push(0);
    mem.write_at(GuestAddress::new(CMDLINE_ADDR), &cmd_with_nul)?;
    mem.write_at(GuestAddress::new(ZERO_PAGE_ADDR), &page.0)?;

    Ok(LoadedKernel {
        entry: GuestAddress::new(plan.load_addr + ENTRY_64_OFFSET),
        boot_params: GuestAddress::new(ZERO_PAGE_ADDR),
        kernel_addr: GuestAddress::new(plan.load_addr),
        kernel_len: payload_len,
        runtime_end: plan.kernel_end,
        cmdline: GuestAddress::new(CMDLINE_ADDR),
        cmdline_len: cmd_len,
        initrd: plan.initrd.map(|(a, l)| (GuestAddress::new(a), l)),
        protocol_version: header.version,
    })
}

// ---------------------------------------------------------------------------
// vCPU の初期状態（TASK-75.3.2・MVM-1。64-bit Boot Protocol）
// ---------------------------------------------------------------------------

/// `__BOOT_CS`（GDT の 2 番目の有効エントリ。boot.rst の 64-bit Boot Protocol）。
pub const BOOT_CS_SELECTOR: u16 = 0x10;
/// `__BOOT_DS`。
pub const BOOT_DS_SELECTOR: u16 = 0x18;
/// 64-bit コードセグメント（P=1・DPL=0・S=1・type=0xB・G=1・L=1・D=0・limit 0xFFFFF）。Intel SDM Vol.3 の記述子形式。
const GDT_CODE64: u64 = 0x00AF_9B00_0000_FFFF;
/// データセグメント（P=1・DPL=0・S=1・type=3・G=1・D=1・limit 0xFFFFF）。
const GDT_DATA: u64 = 0x00CF_9300_0000_FFFF;
/// GDT の内容。0・1 番はヌル（`__BOOT_CS` = 0x10 を 2 番に合わせるため 1 番も空ける）。
const GDT_ENTRIES: [u64; 4] = [0, 0, GDT_CODE64, GDT_DATA];
const _: () = assert!(GDT_ENTRIES.len() * 8 == BOOT_GDT_BYTES);

const CR0_PE: u64 = 1 << 0;
const CR0_ET: u64 = 1 << 4;
const CR0_PG: u64 = 1 << 31;
const CR4_PAE: u64 = 1 << 5;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
/// RFLAGS の予約ビット 1（常に 1。IF=0 で割り込み禁止）。
const RFLAGS_RESERVED: u64 = 0x2;
const PTE_PRESENT_RW: u64 = 0x3;
const PTE_PAGE_SIZE: u64 = 1 << 7;
const PAGE_2MIB: u64 = 2 << 20;
const TABLE_PAGE: usize = 0x1000;

/// KVM に設定するセグメントレジスタの値（`kvm_segment` と同じ内容。OS 非依存）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SegmentDescriptor {
    /// セグメントの基底。
    pub base: u64,
    /// 実効的な limit（G=1 なら 4 KiB 単位へ展開済み）。
    pub limit: u32,
    /// セレクタ。
    pub selector: u16,
    /// type（4 bit）。
    pub type_: u8,
    /// P。
    pub present: bool,
    /// DPL（2 bit）。
    pub dpl: u8,
    /// D/B。
    pub db: bool,
    /// S（コード / データ）。
    pub s: bool,
    /// L（64-bit コード）。
    pub l: bool,
    /// G（limit の単位）。
    pub g: bool,
    /// AVL。
    pub avl: bool,
}

impl SegmentDescriptor {
    /// GDT のエントリ（8 バイト）と selector から、KVM に渡す値を導く。GDT に書くバイト列と同じ値から作るため食い違わない。
    pub const fn from_gdt_entry(selector: u16, entry: u64) -> SegmentDescriptor {
        let limit_raw = (entry & 0xFFFF) | (((entry >> 48) & 0xF) << 16);
        let base = ((entry >> 16) & 0xFF_FFFF) | (((entry >> 56) & 0xFF) << 24);
        let g = (entry >> 55) & 1 == 1;
        let limit = if g {
            ((limit_raw << 12) | 0xFFF) as u32
        } else {
            limit_raw as u32
        };
        SegmentDescriptor {
            base,
            limit,
            selector,
            type_: ((entry >> 40) & 0xF) as u8,
            present: (entry >> 47) & 1 == 1,
            dpl: ((entry >> 45) & 3) as u8,
            db: (entry >> 54) & 1 == 1,
            s: (entry >> 44) & 1 == 1,
            l: (entry >> 53) & 1 == 1,
            g,
            avl: (entry >> 52) & 1 == 1,
        }
    }
}

/// GDT / IDT レジスタの値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorTable {
    /// 先頭の GPA（恒等写像のため線形アドレスと同じ）。
    pub base: u64,
    /// limit（バイト数 - 1）。
    pub limit: u16,
}

/// x86_64 の汎用レジスタ（`kvm_regs` と同じ 18 本）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct X86Regs {
    /// RAX レジスタ。
    pub rax: u64,
    /// RBX レジスタ。
    pub rbx: u64,
    /// RCX レジスタ。
    pub rcx: u64,
    /// RDX レジスタ。
    pub rdx: u64,
    /// RSI レジスタ。
    pub rsi: u64,
    /// RDI レジスタ。
    pub rdi: u64,
    /// RSP レジスタ。
    pub rsp: u64,
    /// RBP レジスタ。
    pub rbp: u64,
    /// R8 レジスタ。
    pub r8: u64,
    /// R9 レジスタ。
    pub r9: u64,
    /// R10 レジスタ。
    pub r10: u64,
    /// R11 レジスタ。
    pub r11: u64,
    /// R12 レジスタ。
    pub r12: u64,
    /// R13 レジスタ。
    pub r13: u64,
    /// R14 レジスタ。
    pub r14: u64,
    /// R15 レジスタ。
    pub r15: u64,
    /// RIP レジスタ。
    pub rip: u64,
    /// RFLAGS レジスタ。
    pub rflags: u64,
}

/// ロード済みカーネルのエントリへ入るための BSP の初期状態（TASK-75.3.2・MVM-1）。
///
/// [`BootCpuState::for_kernel`] が純粋な計算で作り、`device::VcpuFd::set_boot_state` が KVM へ設定する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BootCpuState {
    /// 汎用レジスタ（RIP = entry・RSI = boot_params・RSP = RBP = [`BOOT_STACK_TOP`]・RFLAGS = 0x2）。
    pub regs: X86Regs,
    /// CS（`__BOOT_CS`。64-bit コード）。
    pub code_segment: SegmentDescriptor,
    /// DS / ES / FS / GS / SS（`__BOOT_DS`）。
    pub data_segment: SegmentDescriptor,
    /// GDTR。
    pub gdt: DescriptorTable,
    /// IDTR。
    pub idt: DescriptorTable,
    /// CR0（PE|ET|PG）。
    pub cr0: u64,
    /// CR3（PML4 の GPA）。
    pub cr3: u64,
    /// CR4（PAE）。
    pub cr4: u64,
    /// EFER（LME|LMA）。
    pub efer: u64,
}

impl BootCpuState {
    /// `loaded` のエントリへ入る初期状態を作る。`entry`・`boot_params`・`cmdline` が恒等写像の範囲（4 GiB 未満）に無い、
    /// または `runtime_end` が範囲を超える入力は `InvalidArgument`（別 VM の値の取り違え・不正な値の拒否）。
    pub fn for_kernel(loaded: &LoadedKernel) -> Result<BootCpuState, MicrovmError> {
        let inside = |a: GuestAddress| a.raw() < IDENTITY_MAP_LIMIT;
        if !inside(loaded.entry) || !inside(loaded.boot_params) || !inside(loaded.cmdline) {
            return Err(invalid("boot address is outside the identity mapping"));
        }
        if loaded.runtime_end > IDENTITY_MAP_LIMIT {
            return Err(invalid("kernel range exceeds the 4 GiB identity mapping"));
        }
        let regs = X86Regs {
            rsi: loaded.boot_params.raw(),
            rsp: BOOT_STACK_TOP,
            rbp: BOOT_STACK_TOP,
            rip: loaded.entry.raw(),
            rflags: RFLAGS_RESERVED,
            ..X86Regs::default()
        };
        Ok(BootCpuState {
            regs,
            code_segment: SegmentDescriptor::from_gdt_entry(BOOT_CS_SELECTOR, GDT_CODE64),
            data_segment: SegmentDescriptor::from_gdt_entry(BOOT_DS_SELECTOR, GDT_DATA),
            gdt: DescriptorTable {
                base: BOOT_GDT_START,
                limit: (BOOT_GDT_BYTES - 1) as u16,
            },
            idt: DescriptorTable {
                base: BOOT_IDT_START,
                limit: (BOOT_IDT_BYTES - 1) as u16,
            },
            cr0: CR0_PE | CR0_ET | CR0_PG,
            cr3: BOOT_PML4_ADDR,
            cr4: CR4_PAE,
            efer: EFER_LME | EFER_LMA,
        })
    }
}

/// 起動用の GDT・IDT・ページテーブル（GPA 0..4 GiB の 2 MiB ページによる恒等写像）をゲストメモリへ書く（TASK-75.3.2）。
///
/// 書く範囲は固定の低位領域 `[BOOT_GDT_START, BOOT_TABLES_END)` の内側だけで、zero page・cmdline とは重ならない（const assert）。
/// 領域が GPA 0 から始まらない、または [`BOOT_TABLES_END`] に届かないときは書く前に `InvalidArgument`。
/// 恒等写像は 4 GiB 全域を覆い、RAM の外（MMIO 窓）へのアクセスは従来どおり VM exit になる。
pub fn write_boot_tables<B: GuestMemoryBacking>(
    mem: &mut GuestMemory<B>,
) -> Result<(), MicrovmError> {
    if mem.base() != GuestAddress::new(0) {
        return Err(invalid("guest memory must start at GPA 0"));
    }
    // 総バイト数ではなく先頭の領域の長さで見る（hole を挟む構成で緩めない。#3697）。
    if mem.regions().first().map_or(0, |r| r.len) < BOOT_TABLES_END {
        return Err(invalid("guest memory is too small for the boot tables"));
    }
    let overflow = || invalid("page table size overflows");
    let mut gdt = Vec::with_capacity(BOOT_GDT_BYTES);
    for e in GDT_ENTRIES {
        gdt.extend_from_slice(&e.to_le_bytes());
    }
    let idt = [0u8; BOOT_IDT_BYTES];

    let mut pml4 = vec![0u8; TABLE_PAGE];
    put_u64(&mut pml4, 0, BOOT_PDPT_ADDR | PTE_PRESENT_RW)?;
    let mut pdpt = vec![0u8; TABLE_PAGE];
    let pd_pages = IDENTITY_MAP_LIMIT >> 30;
    let pd_len = usize::try_from(pd_pages)
        .ok()
        .and_then(|n| n.checked_mul(TABLE_PAGE))
        .ok_or_else(overflow)?;
    let mut pd = vec![0u8; pd_len];
    for gb in 0..pd_pages {
        let off = usize::try_from(gb * 8).map_err(|_| overflow())?;
        put_u64(
            &mut pdpt,
            off,
            (BOOT_PD_ADDR + gb * 0x1000) | PTE_PRESENT_RW,
        )?;
    }
    for i in 0..(pd_pages * 512) {
        let phys = i.checked_mul(PAGE_2MIB).ok_or_else(overflow)?;
        let off = usize::try_from(i * 8).map_err(|_| overflow())?;
        put_u64(&mut pd, off, phys | PTE_PRESENT_RW | PTE_PAGE_SIZE)?;
    }

    mem.write_at(GuestAddress::new(BOOT_GDT_START), &gdt)?;
    mem.write_at(GuestAddress::new(BOOT_IDT_START), &idt)?;
    mem.write_at(GuestAddress::new(BOOT_PML4_ADDR), &pml4)?;
    mem.write_at(GuestAddress::new(BOOT_PDPT_ADDR), &pdpt)?;
    mem.write_at(GuestAddress::new(BOOT_PD_ADDR), &pd)?;
    Ok(())
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) -> Result<(), MicrovmError> {
    off.checked_add(8)
        .and_then(|end| buf.get_mut(off..end))
        .ok_or_else(|| invalid("page table entry out of range"))?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}
// ---- vCPU の MSR・FPU の初期値（#3734・MVM-1） ----

/// IA32_TSC。
pub const MSR_IA32_TSC: u32 = 0x10;
/// IA32_SYSENTER_CS。
pub const MSR_IA32_SYSENTER_CS: u32 = 0x174;
/// IA32_SYSENTER_ESP。
pub const MSR_IA32_SYSENTER_ESP: u32 = 0x175;
/// IA32_SYSENTER_EIP。
pub const MSR_IA32_SYSENTER_EIP: u32 = 0x176;
/// IA32_MISC_ENABLE。
pub const MSR_IA32_MISC_ENABLE: u32 = 0x1A0;
/// IA32_STAR。
pub const MSR_STAR: u32 = 0xC000_0081;
/// IA32_LSTAR。
pub const MSR_LSTAR: u32 = 0xC000_0082;
/// IA32_CSTAR。
pub const MSR_CSTAR: u32 = 0xC000_0083;
/// IA32_FMASK（SFMASK）。
pub const MSR_SYSCALL_MASK: u32 = 0xC000_0084;
/// IA32_KERNEL_GS_BASE。
pub const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// IA32_MISC_ENABLE の bit0（Fast-Strings）。
pub const MISC_ENABLE_FAST_STRING: u64 = 1 << 0;
/// IA32_MISC_ENABLE の bit11（BTS unavailable）。
pub const MISC_ENABLE_BTS_UNAVAIL: u64 = 1 << 11;
/// IA32_MISC_ENABLE の bit12（PEBS unavailable）。
pub const MISC_ENABLE_PEBS_UNAVAIL: u64 = 1 << 12;

/// 起動時の FCW（FNINIT 後の値。Intel SDM Vol.1）。
pub const BOOT_FPU_FCW: u16 = 0x37F;
/// 起動時の MXCSR（リセット値。Intel SDM Vol.1）。
pub const BOOT_FPU_MXCSR: u32 = 0x1F80;

/// `KVM_SET_MSRS` に渡す 1 件（MSR 番号と値。`kvm_msr_entry` の予約領域は公開しない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct X86MsrEntry {
    /// MSR 番号。
    pub index: u32,
    /// 値。
    pub data: u64,
}

impl X86MsrEntry {
    /// 番号と値から作る。
    pub const fn new(index: u32, data: u64) -> Self {
        Self { index, data }
    }
}

/// [`boot_msrs`] の件数。
pub const BOOT_MSR_COUNT: usize = 10;

// KVM の 1 回の ioctl の上限（sys の MAX_MSR_ENTRIES = 255）を超えない。
const _: () = assert!(BOOT_MSR_COUNT <= 255);

/// vCPU 0 の起動用 MSR 表（根拠はモジュール doc「MSR・FPU の初期値」）。index は重複しない。
pub const fn boot_msrs() -> [X86MsrEntry; BOOT_MSR_COUNT] {
    [
        X86MsrEntry::new(MSR_IA32_TSC, 0),
        X86MsrEntry::new(MSR_IA32_SYSENTER_CS, 0),
        X86MsrEntry::new(MSR_IA32_SYSENTER_ESP, 0),
        X86MsrEntry::new(MSR_IA32_SYSENTER_EIP, 0),
        X86MsrEntry::new(
            MSR_IA32_MISC_ENABLE,
            MISC_ENABLE_FAST_STRING | MISC_ENABLE_BTS_UNAVAIL | MISC_ENABLE_PEBS_UNAVAIL,
        ),
        X86MsrEntry::new(MSR_STAR, 0),
        X86MsrEntry::new(MSR_LSTAR, 0),
        X86MsrEntry::new(MSR_CSTAR, 0),
        X86MsrEntry::new(MSR_SYSCALL_MASK, 0),
        X86MsrEntry::new(MSR_KERNEL_GS_BASE, 0),
    ]
}

/// vCPU の FPU 状態のうち公開する部分（`kvm_fpu` の x87 制御系と MXCSR）。
///
/// `fpr`（x87 レジスタ）と `xmm` は公開しない。設定時は 0 を書き、読み戻しでは捨てる。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct X86FpuState {
    /// x87 コントロールワード。
    pub fcw: u16,
    /// x87 ステータスワード。
    pub fsw: u16,
    /// 抽象タグワード（FXSAVE 形式の 8 ビット）。
    pub ftwx: u8,
    /// 最後の x87 命令のオペコード。
    pub last_opcode: u16,
    /// 最後の x87 命令の IP。
    pub last_ip: u64,
    /// 最後の x87 オペランドのアドレス。
    pub last_dp: u64,
    /// MXCSR。
    pub mxcsr: u32,
}

impl X86FpuState {
    /// 起動時の値（fcw = 0x37F・mxcsr = 0x1F80・他は 0）。
    pub const fn boot() -> Self {
        Self {
            fcw: BOOT_FPU_FCW,
            fsw: 0,
            ftwx: 0,
            last_opcode: 0,
            last_ip: 0,
            last_dp: 0,
            mxcsr: BOOT_FPU_MXCSR,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_memory::HeapBacking;

    const MIB: u64 = 1 << 20;

    /// 合成 bzImage のパラメータ。
    #[derive(Clone)]
    struct Img {
        setup_sects: u8,
        boot_flag: u16,
        magic: u32,
        version: u16,
        loadflags: u8,
        xloadflags: u16,
        header_len: u8,
        initrd_addr_max: u32,
        alignment: u32,
        relocatable: u8,
        cmdline_size: u32,
        pref: u64,
        init_size: u32,
        payload_len: usize,
    }

    impl Default for Img {
        fn default() -> Self {
            Img {
                setup_sects: 4,
                boot_flag: 0xAA55,
                magic: HEADER_MAGIC,
                version: 0x020F,
                loadflags: 1,
                xloadflags: 1,
                header_len: 0x62,
                initrd_addr_max: 0x3FF_FFFF,
                alignment: 0x20_0000,
                relocatable: 1,
                cmdline_size: 2047,
                pref: 0x100_0000,
                init_size: 0x40_0000,
                payload_len: 0x1000,
            }
        }
    }

    impl Img {
        fn build(&self) -> Vec<u8> {
            let setup = (usize::from(self.setup_sects).max(1) + 1) * 512;
            let setup = if self.setup_sects == 0 {
                5 * 512
            } else {
                setup
            };
            let mut v = vec![0u8; setup + self.payload_len];
            let put =
                |v: &mut Vec<u8>, off: usize, d: &[u8]| v[off..off + d.len()].copy_from_slice(d);
            put(&mut v, OFF_SETUP_SECTS, &[self.setup_sects]);
            put(&mut v, OFF_BOOT_FLAG, &self.boot_flag.to_le_bytes());
            put(&mut v, OFF_HEADER_END_LEN, &[self.header_len]);
            put(&mut v, OFF_HEADER_MAGIC, &self.magic.to_le_bytes());
            put(&mut v, OFF_VERSION, &self.version.to_le_bytes());
            put(&mut v, OFF_LOADFLAGS, &[self.loadflags]);
            put(
                &mut v,
                OFF_INITRD_ADDR_MAX,
                &self.initrd_addr_max.to_le_bytes(),
            );
            put(&mut v, OFF_KERNEL_ALIGNMENT, &self.alignment.to_le_bytes());
            put(&mut v, OFF_RELOCATABLE, &[self.relocatable]);
            put(&mut v, OFF_XLOADFLAGS, &self.xloadflags.to_le_bytes());
            put(&mut v, OFF_CMDLINE_SIZE, &self.cmdline_size.to_le_bytes());
            put(&mut v, OFF_PREF_ADDRESS, &self.pref.to_le_bytes());
            put(&mut v, OFF_INIT_SIZE, &self.init_size.to_le_bytes());
            for (i, b) in v[setup..].iter_mut().enumerate() {
                *b = (i % 251) as u8 | 1;
            }
            v
        }
    }

    fn mem(len: u64) -> GuestMemory<HeapBacking> {
        GuestMemory::new(GuestAddress::new(0), HeapBacking::new(len).unwrap()).unwrap()
    }

    fn cmd(user: &str) -> KernelCmdline {
        KernelCmdline::new(user, &[]).unwrap()
    }

    fn read(m: &GuestMemory<HeapBacking>, addr: u64, n: usize) -> Vec<u8> {
        let mut b = vec![0u8; n];
        m.read_at(GuestAddress::new(addr), &mut b).unwrap();
        b
    }

    fn expect_err(r: Result<LoadedKernel, MicrovmError>, code: MicrovmErrorCode, msg: &str) {
        let e = r.unwrap_err();
        assert_eq!(e.code(), code);
        assert_eq!(e.message(), msg);
    }

    /// MVM-1・TASK-75.3.1: bzImage が boot.rst のオフセットどおり（payload は pref_address、zero page は 0x7000）に置かれる。
    #[test]
    fn mvm1_884_loads_bzimage_at_protocol_offsets() {
        let img = Img::default().build();
        let mut m = mem(64 * MIB);
        let l = load_linux(&mut m, &img, None, &cmd("console=ttyS0")).unwrap();
        assert_eq!(l.kernel_addr, GuestAddress::new(0x100_0000));
        assert_eq!(l.entry, GuestAddress::new(0x100_0200));
        assert_eq!(l.boot_params, GuestAddress::new(0x7000));
        assert_eq!(l.kernel_len, 0x1000);
        assert_eq!(l.runtime_end, 0x100_0000 + 0x40_0000);
        assert_eq!(l.protocol_version, 0x020F);
        assert_eq!(l.initrd, None);
        assert_eq!(read(&m, 0x100_0000, 0x1000), img[5 * 512..].to_vec());
        assert_eq!(read(&m, 0x7000 + 0x202, 4), b"HdrS".to_vec());
        assert_eq!(read(&m, 0x7000 + 0x210, 1), vec![0xFF]);
        assert_eq!(
            m.read_u32_le(GuestAddress::new(0x7000 + 0x228)).unwrap(),
            0x2_0000
        );
        // e820 は RAM・MP テーブルの予約（#3888）・RAM の 3 本。
        assert_eq!(read(&m, 0x7000 + 0x1E8, 1), vec![3]);
        let t = 0x7000 + 0x2D0;
        assert_eq!(m.read_u64_le(GuestAddress::new(t)).unwrap(), 0);
        assert_eq!(m.read_u64_le(GuestAddress::new(t + 8)).unwrap(), 0x9_FC00);
        assert_eq!(m.read_u32_le(GuestAddress::new(t + 16)).unwrap(), 1);
        assert_eq!(m.read_u64_le(GuestAddress::new(t + 20)).unwrap(), 0x9_FC00);
        assert_eq!(m.read_u64_le(GuestAddress::new(t + 28)).unwrap(), 0x400);
        assert_eq!(m.read_u32_le(GuestAddress::new(t + 36)).unwrap(), 2);
        assert_eq!(m.read_u64_le(GuestAddress::new(t + 40)).unwrap(), 0x10_0000);
        assert_eq!(m.read_u64_le(GuestAddress::new(t + 48)).unwrap(), 63 * MIB);
        assert_eq!(m.read_u32_le(GuestAddress::new(t + 56)).unwrap(), 1);
        assert_eq!(read(&m, 0x2_0000, 14), b"console=ttyS0\0".to_vec());
        assert_eq!(l.cmdline_len, 13);
    }

    /// MVM-1・#3888: MP テーブルの領域はカーネル・initrd・cmdline と重ならず、書いても zero page と cmdline を壊さない。
    #[test]
    fn mvm1_3888_mp_table_area_is_disjoint_and_writable() {
        use crate::mptable_x86::{IsaIrqRoute, MpTableConfig, build_mp_table, write_mp_table};
        let data = vec![0xA5u8; 0x1801];
        let img = Img::default().build();
        let mut m = mem(64 * MIB);
        let l = load_linux(&mut m, &img, Some(&data), &cmd("console=ttyS0")).unwrap();
        assert!(l.kernel_addr.raw() >= MP_TABLE_END);
        let (ird, _) = l.initrd.unwrap();
        assert!(ird.raw() >= MP_TABLE_END);
        let routes = [IsaIrqRoute {
            source_irq: 4,
            ioapic_pin: 4,
        }];
        let cfg = MpTableConfig {
            vcpu_count: 2,
            ioapic_id: 32,
            ioapic_addr: 0xfec0_0000,
            lapic_addr: 0xfee0_0000,
            isa_irqs: &routes,
        };
        let t = build_mp_table(&cfg, MP_TABLE_START).unwrap();
        write_mp_table(&mut m, &t).unwrap();
        assert_eq!(read(&m, MP_TABLE_START, 4), b"_MP_".to_vec());
        assert_eq!(read(&m, 0x7000 + 0x202, 4), b"HdrS".to_vec());
        assert_eq!(read(&m, CMDLINE_ADDR, 14), b"console=ttyS0\0".to_vec());
    }

    fn region(base: u64, len: u64) -> GuestMemoryRegion {
        GuestMemoryRegion {
            base: GuestAddress::new(base),
            len,
        }
    }

    /// MVM-1・#3697: 2 番目以降の領域が RAM として e820 に並ぶ。先頭が GPA 0 でなければ拒否する。
    #[test]
    fn mvm1_3697_plan_e820_includes_high_region() {
        let h = SetupHeader::parse(&Img::default().build()).unwrap();
        let ram = [region(0, 0xd000_0000), region(0x1_0000_0000, 0x7000_0000)];
        let p = plan_boot(&h, 0x1000, None, &ram).unwrap();
        assert_eq!(
            p.e820,
            vec![
                E820Entry {
                    addr: 0,
                    size: 0x9_FC00,
                    kind: 1
                },
                E820Entry {
                    addr: 0x9_FC00,
                    size: 0x400,
                    kind: 2
                },
                E820Entry {
                    addr: 0x10_0000,
                    size: 0xd000_0000 - 0x10_0000,
                    kind: 1
                },
                E820Entry {
                    addr: 0x1_0000_0000,
                    size: 0x7000_0000,
                    kind: 1
                },
            ]
        );
        let e = plan_boot(&h, 0x1000, None, &[region(0x1000, 64 * MIB)]).unwrap_err();
        assert_eq!(e.message(), "guest memory must start at GPA 0");
    }

    /// MVM-1・#3697: load_linux は領域ごとの e820 を zero page に書く（4 本目の addr・size・type をバイト列で照合）。
    #[test]
    fn mvm1_3697_load_linux_writes_e820_for_each_region() {
        let mut m = GuestMemory::from_regions(vec![
            (GuestAddress::new(0), HeapBacking::new(64 * MIB).unwrap()),
            (
                GuestAddress::new(0x1_0000_0000),
                HeapBacking::new(MIB).unwrap(),
            ),
        ])
        .unwrap();
        load_linux(&mut m, &Img::default().build(), None, &cmd("console=ttyS0")).unwrap();
        let zp = read(&m, ZERO_PAGE_ADDR, ZERO_PAGE_SIZE);
        assert_eq!(zp[OFF_E820_ENTRIES], 4);
        let base = OFF_E820_TABLE + 3 * E820_ENTRY_SIZE;
        assert_eq!(&zp[base..base + 8], &0x1_0000_0000u64.to_le_bytes());
        assert_eq!(&zp[base + 8..base + 16], &(MIB).to_le_bytes());
        assert_eq!(&zp[base + 16..base + 20], &1u32.to_le_bytes());
    }

    /// MVM-1・#3888: plan_boot の e820 は RAM・予約（MP テーブル）・RAM の具体値。
    #[test]
    fn mvm1_3888_plan_e820_values() {
        let h = SetupHeader::parse(&Img::default().build()).unwrap();
        let p = plan_boot(&h, 0x1000, None, &[region(0, 64 * MIB)]).unwrap();
        assert_eq!(
            p.e820,
            vec![
                E820Entry {
                    addr: 0,
                    size: 0x9_FC00,
                    kind: 1
                },
                E820Entry {
                    addr: 0x9_FC00,
                    size: 0x400,
                    kind: 2
                },
                E820Entry {
                    addr: 0x10_0000,
                    size: 63 * MIB,
                    kind: 1
                },
            ]
        );
    }

    /// MVM-1・TASK-75.3.1: initrd は initrd_addr_max と RAM 終端の低いほうの下、4 KiB 境界に置かれ、ramdisk_* に反映される。
    #[test]
    fn mvm1_884_initrd_placed_below_initrd_addr_max() {
        let data: Vec<u8> = (0..0x1801u32).map(|i| (i % 253) as u8).collect();
        // RAM 終端のほうが低い（addr_max が RAM の上）。
        let img = Img {
            initrd_addr_max: 0x7FF_FFFF,
            ..Img::default()
        }
        .build();
        let mut m = mem(64 * MIB);
        let l = load_linux(&mut m, &img, Some(&data), &cmd("")).unwrap();
        assert_eq!(l.initrd, Some((GuestAddress::new(0x3FF_E000), 0x1801)));
        assert_eq!(
            m.read_u32_le(GuestAddress::new(0x7000 + 0x218)).unwrap(),
            0x3FF_E000
        );
        assert_eq!(
            m.read_u32_le(GuestAddress::new(0x7000 + 0x21C)).unwrap(),
            0x1801
        );
        assert_eq!(read(&m, 0x3FF_E000, 0x1801), data);
        // initrd_addr_max のほうが低い。
        let img = Img {
            initrd_addr_max: 0x1FF_FFFF,
            ..Img::default()
        }
        .build();
        let mut m = mem(64 * MIB);
        let l = load_linux(&mut m, &img, Some(&data), &cmd("")).unwrap();
        assert_eq!(l.initrd, Some((GuestAddress::new(0x1FF_E000), 0x1801)));
        assert_eq!(
            m.read_u32_le(GuestAddress::new(0x7000 + 0x218)).unwrap(),
            0x1FF_E000
        );
        assert_eq!(read(&m, 0x1FF_E000, 0x1801), data);
        // 空の initrd と、カーネルの確保域に食い込む initrd。
        let mut m = mem(64 * MIB);
        assert_eq!(
            load_linux(&mut m, &img, Some(&[]), &cmd(""))
                .unwrap_err()
                .code(),
            MicrovmErrorCode::InvalidArgument
        );
        let big = vec![1u8; 0x1FF_0000];
        expect_err(
            load_linux(&mut m, &img, Some(&big), &cmd("")),
            MicrovmErrorCode::ResourceExhausted,
            "initrd does not fit in guest memory",
        );
    }

    /// MVM-1・#3888: 既定の cmdline に `no_timer_check` が `--` の前へ 1 回だけ入る（PIT が無い VM で check_timer を避ける）。
    #[test]
    fn mvm1_3888_with_no_timer_check() {
        assert_eq!(
            with_no_timer_check("console=ttyS0 reboot=t").unwrap(),
            "console=ttyS0 reboot=t no_timer_check"
        );
        assert_eq!(with_no_timer_check("").unwrap(), "no_timer_check");
        // 引用符内の no_timer_check は独立した引数ではないので、別途足す。
        assert_eq!(
            with_no_timer_check("foo=\"x no_timer_check y\"").unwrap(),
            "foo=\"x no_timer_check y\" no_timer_check"
        );
        // 上限超過は複製前に拒否する。
        let big = "a".repeat(CMDLINE_CAPACITY as usize);
        assert!(with_no_timer_check(&big).is_err());
        assert_eq!(
            with_no_timer_check("console=ttyS0 no_timer_check").unwrap(),
            "console=ttyS0 no_timer_check"
        );
        assert_eq!(
            with_no_timer_check("console=ttyS0 -- rescue").unwrap(),
            "console=ttyS0 no_timer_check -- rescue"
        );
    }

    /// MVM-1・TASK-75.3.1: cmdline に virtio-mmio の項目が block → net の順で付き、NUL 終端で 0x2_0000 に書かれる。
    #[test]
    fn mvm1_884_cmdline_appends_virtio_mmio_devices() {
        let devs = [
            VirtioMmioParam {
                base: 0xd000_0000,
                len: 0x1000,
                gsi: 5,
            },
            VirtioMmioParam {
                base: 0xd000_1000,
                len: 0x1000,
                gsi: 6,
            },
        ];
        let c = KernelCmdline::new("console=ttyS0", &devs).unwrap();
        let expect = "console=ttyS0 virtio_mmio.device=0x1000@0xd0000000:5 virtio_mmio.device=0x1000@0xd0001000:6";
        assert_eq!(c.as_str(), expect);
        let mut m = mem(64 * MIB);
        let l = load_linux(&mut m, &Img::default().build(), None, &c).unwrap();
        let mut want = expect.as_bytes().to_vec();
        want.push(0);
        assert_eq!(read(&m, 0x2_0000, want.len()), want);
        assert_eq!(l.cmdline, GuestAddress::new(0x2_0000));
        assert_eq!(l.cmdline_len, expect.len() as u64);
        assert_eq!(
            KernelCmdline::new("", &devs[..1]).unwrap().as_str(),
            "virtio_mmio.device=0x1000@0xd0000000:5"
        );
    }

    /// MVM-1・TASK-75.3.1: user の `--` より前に virtio 項目を入れ、`--` 以降は init 引数のまま保つ。
    #[test]
    fn mvm1_884_cmdline_inserts_devices_before_double_dash() {
        let d = [VirtioMmioParam {
            base: 0xd000_0000,
            len: 0x1000,
            gsi: 5,
        }];
        assert_eq!(
            KernelCmdline::new("console=ttyS0 -- rescue", &d)
                .unwrap()
                .as_str(),
            "console=ttyS0 virtio_mmio.device=0x1000@0xd0000000:5 -- rescue"
        );
        assert_eq!(
            KernelCmdline::new("-- rescue", &d).unwrap().as_str(),
            "virtio_mmio.device=0x1000@0xd0000000:5 -- rescue"
        );
    }

    /// MVM-1・TASK-75.3.1: 引用符内の `--` は区切りにせず、閉じていない引用符は拒否し、user が最大長でも先頭に空白を入れない。
    #[test]
    fn mvm1_884_cmdline_quote_aware_split() {
        let d = [VirtioMmioParam {
            base: 0xd000_0000,
            len: 0x1000,
            gsi: 5,
        }];
        assert_eq!(
            KernelCmdline::new("foo=\"x -- y\" -- init", &d)
                .unwrap()
                .as_str(),
            "foo=\"x -- y\" virtio_mmio.device=0x1000@0xd0000000:5 -- init"
        );
        assert_eq!(
            KernelCmdline::new("foo=\"x -- y\"", &d).unwrap().as_str(),
            "foo=\"x -- y\" virtio_mmio.device=0x1000@0xd0000000:5"
        );
        assert!(KernelCmdline::new("foo=\"x -- y", &d).is_err());
        assert!(KernelCmdline::new("a \"--\" b", &d).is_err());
        assert!(KernelCmdline::new("a -\"-\" b", &d).is_err());
        assert_eq!(KernelCmdline::new("-- a", &[]).unwrap().as_str(), "-- a");
        let long = format!("--{}", "a".repeat(CMDLINE_CAPACITY as usize - 3));
        assert_eq!(KernelCmdline::new(&long, &[]).unwrap().as_str(), long);
    }

    /// MVM-1・TASK-75.3.1: 件数が多く容量を超える devices は途中で拒否する。
    #[test]
    fn mvm1_884_cmdline_rejects_oversized_devices() {
        let d = vec![
            VirtioMmioParam {
                base: 0xd000_0000,
                len: 0x1000,
                gsi: 5,
            };
            1_000
        ];
        assert!(KernelCmdline::new("", &d).is_err());
    }

    /// MVM-1・TASK-75.3.1: 非 relocatable は pref_address、pref_address の無い relocatable は alignment で切り上げた 1 MiB に置く。
    #[test]
    fn mvm1_884_non_relocatable_loads_at_pref_address() {
        let img = Img {
            relocatable: 0,
            pref: 0x200_0000,
            ..Img::default()
        }
        .build();
        let mut m = mem(64 * MIB);
        let l = load_linux(&mut m, &img, None, &cmd("")).unwrap();
        assert_eq!(l.kernel_addr, GuestAddress::new(0x200_0000));
        assert_eq!(l.entry, GuestAddress::new(0x200_0200));
        let img = Img {
            relocatable: 0,
            pref: 0,
            ..Img::default()
        }
        .build();
        expect_err(
            load_linux(&mut m, &img, None, &cmd("")),
            MicrovmErrorCode::InvalidArgument,
            "kernel cannot be placed (alignment or preferred address)",
        );
    }

    #[test]
    fn mvm1_884_relocatable_without_pref_address_aligns_himem() {
        let img = Img {
            pref: 0,
            ..Img::default()
        }
        .build();
        let mut m = mem(64 * MIB);
        let l = load_linux(&mut m, &img, None, &cmd("")).unwrap();
        assert_eq!(l.kernel_addr, GuestAddress::new(0x20_0000));
        assert_eq!(l.entry, GuestAddress::new(0x20_0200));
        let img = Img {
            pref: 0,
            alignment: 0x1000,
            ..Img::default()
        }
        .build();
        let l = load_linux(&mut m, &img, None, &cmd("")).unwrap();
        assert_eq!(l.kernel_addr, GuestAddress::new(0x10_0000));
        let img = Img {
            pref: 0,
            alignment: 0x3000,
            ..Img::default()
        }
        .build();
        assert_eq!(
            load_linux(&mut m, &img, None, &cmd("")).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
    }

    /// MVM-1・TASK-75.3.1: relocatable でも展開先 max(align_up(load, alignment), pref_address) から init_size が RAM に収まらなければ拒否する
    /// （pref=16 MiB・init_size=4 MiB・RAM=8 MiB で 2 MiB へ再配置しても展開先 16〜20 MiB は RAM 外。Codex 指摘の再現）。
    #[test]
    fn mvm1_884_relocatable_rejects_when_decompress_window_outside_ram() {
        let img = Img {
            pref: 16 * MIB,
            init_size: 4 * MIB as u32,
            ..Img::default()
        }
        .build();
        let mut m = mem(8 * MIB);
        expect_err(
            load_linux(&mut m, &img, None, &cmd("")),
            MicrovmErrorCode::ResourceExhausted,
            "kernel does not fit in guest memory",
        );
        // 窓がちょうど収まる RAM（20 MiB）では、再配置先の 2 MiB を使わず pref_address に置かれる。
        let mut m = mem(20 * MIB);
        let l = load_linux(&mut m, &img, None, &cmd("")).unwrap();
        assert_eq!(l.kernel_addr, GuestAddress::new(16 * MIB));
        // pref_address が無い relocatable は従来どおり 2 MiB。
        let img = Img {
            pref: 0,
            init_size: 4 * MIB as u32,
            ..Img::default()
        }
        .build();
        let l = load_linux(&mut mem(8 * MIB), &img, None, &cmd("")).unwrap();
        assert_eq!(l.kernel_addr, GuestAddress::new(0x20_0000));
        let img = Img {
            relocatable: 0,
            pref: 0x100_0000,
            ..Img::default()
        }
        .build();
        assert_eq!(
            load_linux(&mut mem(8 * MIB), &img, None, &cmd(""))
                .unwrap_err()
                .code(),
            MicrovmErrorCode::ResourceExhausted
        );
    }

    /// MVM-1・TASK-75.3.1: 不正・非対応のイメージは書き込みの前に具体的な code と message で拒否される。
    /// MVM-1・TASK-75.3.1: initrd が優先配置に収まらず再配置しても、pref_address の展開窓 [16 MiB, 20 MiB) と重ならない位置にだけ置く。
    #[test]
    fn mvm1_884_initrd_avoids_pref_address_window_after_relocation() {
        let img = Img {
            pref: 16 * MIB,
            ..Img::default()
        }
        .build();
        // 窓の上（20 MiB 以降）に収まらない 48 MiB の initrd は、再配置しても拒否される。
        let initrd = vec![0xAB; (48 * MIB) as usize];
        let mut m = mem(64 * MIB);
        assert_eq!(
            load_linux(&mut m, &img, Some(&initrd), &cmd(""))
                .unwrap_err()
                .code(),
            MicrovmErrorCode::ResourceExhausted
        );
        // 窓の上に収まる 40 MiB の initrd は 24 MiB に置かれ、窓と重ならない。
        let initrd = vec![0xAB; (40 * MIB) as usize];
        let l = load_linux(&mut m, &img, Some(&initrd), &cmd("")).unwrap();
        assert_eq!(l.initrd.unwrap().0, GuestAddress::new(24 * MIB));
    }

    /// MVM-1・TASK-75.3.1: 64-bit エントリ位置を含まない payload は書き込み前に InvalidArgument で拒否する。
    #[test]
    fn mvm1_884_rejects_payload_without_entry_point() {
        let mut img = Img::default().build();
        // payload を 1 バイトだけ残して切り詰める。
        let setup = (usize::from(Img::default().setup_sects) + 1) * 512;
        img.truncate(setup + 1);
        let mut m = mem(64 * MIB);
        let e = load_linux(&mut m, &img, None, &cmd("")).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    }

    #[test]
    fn mvm1_884_rejects_invalid_images() {
        let inv = MicrovmErrorCode::InvalidArgument;
        let mut m = mem(64 * MIB);
        let mut try_img = |img: &[u8]| load_linux(&mut m, img, None, &cmd(""));
        let mut elf = Img::default().build();
        elf[..4].copy_from_slice(b"\x7fELF");
        expect_err(
            try_img(&elf),
            MicrovmErrorCode::Unimplemented,
            "ELF vmlinux kernel images are not supported",
        );
        expect_err(
            try_img(
                &Img {
                    boot_flag: 0,
                    ..Img::default()
                }
                .build(),
            ),
            inv,
            "kernel image has no boot flag",
        );
        expect_err(
            try_img(
                &Img {
                    magic: 0,
                    ..Img::default()
                }
                .build(),
            ),
            inv,
            "kernel image has no setup header magic",
        );
        expect_err(
            try_img(
                &Img {
                    version: 0x020B,
                    ..Img::default()
                }
                .build(),
            ),
            inv,
            "boot protocol version is older than 2.12",
        );
        expect_err(
            try_img(
                &Img {
                    xloadflags: 0,
                    ..Img::default()
                }
                .build(),
            ),
            inv,
            "kernel image has no 64-bit entry (XLF_KERNEL_64 unset)",
        );
        expect_err(
            try_img(
                &Img {
                    loadflags: 0,
                    ..Img::default()
                }
                .build(),
            ),
            inv,
            "kernel image is not a bzImage (LOADED_HIGH unset)",
        );
        expect_err(
            try_img(
                &Img {
                    header_len: 0x61,
                    ..Img::default()
                }
                .build(),
            ),
            inv,
            "setup header length is invalid",
        );
        expect_err(
            try_img(
                &Img {
                    payload_len: 0,
                    ..Img::default()
                }
                .build(),
            ),
            inv,
            "kernel image has no protected-mode part",
        );
        expect_err(try_img(&[0u8; 100]), inv, "kernel image is truncated");
        // setup_sects = 0 は 4 とみなす（payload は 2560 バイト目から）。
        let l = try_img(
            &Img {
                setup_sects: 0,
                ..Img::default()
            }
            .build(),
        )
        .unwrap();
        assert_eq!(l.kernel_len, 0x1000);
    }

    /// MVM-1・TASK-75.3.1: RAM に収まらないカーネル・小さすぎる RAM・GPA 0 でない RAM を拒否する。
    #[test]
    fn mvm1_884_rejects_memory_misfit() {
        let img = Img::default().build();
        // 非 relocatable は pref_address 固定のため、収まらなければ拒否される（relocatable は再配置先へ落ちる）。
        let fixed = Img {
            relocatable: 0,
            ..Img::default()
        }
        .build();
        expect_err(
            load_linux(&mut mem(16 * MIB), &fixed, None, &cmd("")),
            MicrovmErrorCode::ResourceExhausted,
            "kernel does not fit in guest memory",
        );
        expect_err(
            load_linux(&mut mem(MIB), &img, None, &cmd("")),
            MicrovmErrorCode::InvalidArgument,
            "guest memory is too small for a kernel",
        );
        let mut off = GuestMemory::new(
            GuestAddress::new(0x1000),
            HeapBacking::new(64 * MIB).unwrap(),
        )
        .unwrap();
        expect_err(
            load_linux(&mut off, &img, None, &cmd("")),
            MicrovmErrorCode::InvalidArgument,
            "guest memory must start at GPA 0",
        );
    }

    /// MVM-1・TASK-75.3.1: cmdline の不正文字と長さの境界（cmdline_size ちょうどは通る）。
    #[test]
    fn mvm1_884_cmdline_validation() {
        let inv = MicrovmErrorCode::InvalidArgument;
        for bad in ["a\0b", "a\nb", "a\tb", "caf\u{e9}", "a\x7fb"] {
            assert_eq!(
                KernelCmdline::new(bad, &[]).unwrap_err().code(),
                inv,
                "{bad:?}"
            );
        }
        assert!(KernelCmdline::new(&"a".repeat(4095), &[]).is_ok());
        assert_eq!(
            KernelCmdline::new(&"a".repeat(4096), &[])
                .unwrap_err()
                .message(),
            "kernel command line too long"
        );
        let c = cmd(&"a".repeat(100));
        let ok = Img {
            cmdline_size: 100,
            ..Img::default()
        }
        .build();
        assert_eq!(
            load_linux(&mut mem(64 * MIB), &ok, None, &c)
                .unwrap()
                .cmdline_len,
            100
        );
        let ng = Img {
            cmdline_size: 99,
            ..Img::default()
        }
        .build();
        expect_err(
            load_linux(&mut mem(64 * MIB), &ng, None, &c),
            inv,
            "kernel command line exceeds the kernel's limit",
        );
    }

    /// MVM-1・TASK-75.3.1: 上限定数の具体値と、上限超過の拒否。
    #[test]
    fn mvm1_884_size_limits() {
        assert_eq!(MAX_KERNEL_IMAGE_BYTES, 134_217_728);
        assert_eq!(MAX_INITRD_BYTES, 1_073_741_824);
        let big = vec![0u8; MAX_KERNEL_IMAGE_BYTES as usize + 1];
        assert_eq!(
            SetupHeader::parse(&big).unwrap_err().message(),
            "kernel image too large"
        );
    }

    /// MVM-1・TASK-75.3.1: 低位メモリの配置の具体値（const assert と同じ関係を値で固定する）。
    #[test]
    fn mvm1_884_layout_constants() {
        assert_eq!(BOOT_GDT_START, 0x500);
        assert_eq!(BOOT_IDT_START, 0x520);
        assert_eq!(BOOT_STACK_TOP, 0x8FF0);
        assert_eq!(BOOT_TABLES_END, 0xF000);
        assert_eq!(ZERO_PAGE_ADDR, 0x7000);
        assert_eq!(CMDLINE_ADDR, 0x2_0000);
        assert_eq!(BOOT_SCRATCH_START, 0x8000);
        assert_eq!(BOOT_SCRATCH_END, 0x2_0000);
        assert_eq!(LOW_RAM_END, 0x9_FC00);
        assert_eq!(HIMEM_START, 0x10_0000);
    }

    fn heap_mem(len: u64) -> GuestMemory<HeapBacking> {
        GuestMemory::new(GuestAddress::new(0), HeapBacking::new(len).unwrap()).unwrap()
    }

    fn loaded(entry: u64, boot_params: u64, runtime_end: u64) -> LoadedKernel {
        LoadedKernel {
            entry: GuestAddress::new(entry),
            boot_params: GuestAddress::new(boot_params),
            kernel_addr: GuestAddress::new(0x100_0000),
            kernel_len: 0x1000,
            runtime_end,
            cmdline: GuestAddress::new(CMDLINE_ADDR),
            cmdline_len: 0,
            initrd: None,
            protocol_version: 0x020F,
        }
    }

    /// MVM-1・TASK-75.3.2: GDT のエントリと、そこから導いたセグメント値の具体値。
    #[test]
    fn mvm1_885_gdt_entries_concrete() {
        assert_eq!(GDT_CODE64, 0x00AF_9B00_0000_FFFF);
        assert_eq!(GDT_DATA, 0x00CF_9300_0000_FFFF);
        let c = SegmentDescriptor::from_gdt_entry(BOOT_CS_SELECTOR, GDT_CODE64);
        assert_eq!(
            (c.base, c.limit, c.selector, c.type_, c.dpl),
            (0, 0xFFFF_FFFF, 0x10, 0xB, 0)
        );
        assert!(c.present && c.s && c.l && c.g && !c.db && !c.avl);
        let d = SegmentDescriptor::from_gdt_entry(BOOT_DS_SELECTOR, GDT_DATA);
        assert_eq!(
            (d.base, d.limit, d.selector, d.type_, d.dpl),
            (0, 0xFFFF_FFFF, 0x18, 0x3, 0)
        );
        assert!(d.present && d.s && d.db && d.g && !d.l && !d.avl);
        // 非 G の limit・base の復号（別の記述子）。
        let x = SegmentDescriptor::from_gdt_entry(0x8, 0x0040_8912_3456_00FF);
        assert_eq!(
            (x.base, x.limit, x.type_, x.g, x.db, x.s),
            (0x12_3456, 0xFF, 0x9, false, true, false)
        );
        // バイト列側: selector 0x10 / 0x18 の位置に同じ記述子がある。
        let mut mem = heap_mem(0x1_0000);
        write_boot_tables(&mut mem).unwrap();
        let q = |a: u64| mem.read_u64_le(GuestAddress::new(a)).unwrap();
        assert_eq!(q(BOOT_GDT_START), 0);
        assert_eq!(q(BOOT_GDT_START + 0x8), 0);
        assert_eq!(q(BOOT_GDT_START + 0x10), 0x00AF_9B00_0000_FFFF);
        assert_eq!(q(BOOT_GDT_START + 0x18), 0x00CF_9300_0000_FFFF);
    }

    /// MVM-1・TASK-75.3.2: 4 GiB の恒等写像（2 MiB ページ）を具体値で照合し、終端より先へ書かない。
    #[test]
    fn mvm1_885_page_tables_identity_map_4gib() {
        let mut mem = heap_mem(0x2_0000);
        write_boot_tables(&mut mem).unwrap();
        let q = |a: u64| mem.read_u64_le(GuestAddress::new(a)).unwrap();
        assert_eq!(q(0x9000), 0xA003);
        assert_eq!(q(0x9008), 0);
        assert_eq!(q(0xA000), 0xB003);
        assert_eq!(q(0xA008), 0xC003);
        assert_eq!(q(0xA010), 0xD003);
        assert_eq!(q(0xA018), 0xE003);
        assert_eq!(q(0xA020), 0);
        assert_eq!(q(0xB000), 0x83);
        assert_eq!(q(0xB008), 0x20_0083);
        assert_eq!(q(0xB000 + 511 * 8), 0x3FE0_0083);
        assert_eq!(q(0xE000 + 511 * 8), 0xFFE0_0083);
        // 終端以降・IDT・zero page は書き込まれない。
        assert_eq!(q(0xF000), 0);
        assert_eq!(q(BOOT_IDT_START), 0);
        assert_eq!(q(ZERO_PAGE_ADDR), 0);
    }

    /// MVM-1・TASK-75.3.2: ロード結果から BSP の初期状態を具体値で導く。
    #[test]
    fn mvm1_885_boot_cpu_state_for_kernel() {
        let s = BootCpuState::for_kernel(&loaded(0x100_0200, 0x7000, 0x500_0000)).unwrap();
        assert_eq!(s.regs.rip, 0x100_0200);
        assert_eq!(s.regs.rsi, 0x7000);
        assert_eq!(s.regs.rsp, 0x8FF0);
        assert_eq!(s.regs.rbp, 0x8FF0);
        assert_eq!(s.regs.rflags, 0x2);
        assert_eq!(
            (s.regs.rax, s.regs.rbx, s.regs.rdi, s.regs.r15),
            (0, 0, 0, 0)
        );
        assert_eq!(s.cr0, 0x8000_0011);
        assert_eq!(s.cr3, 0x9000);
        assert_eq!(s.cr4, 0x20);
        assert_eq!(s.efer, 0x500);
        assert_eq!(
            s.gdt,
            DescriptorTable {
                base: 0x500,
                limit: 31
            }
        );
        assert_eq!(
            s.idt,
            DescriptorTable {
                base: 0x520,
                limit: 7
            }
        );
        assert_eq!(s.code_segment.selector, 0x10);
        assert_eq!(s.data_segment.selector, 0x18);
        // 4 GiB ちょうどまでは受理する。
        BootCpuState::for_kernel(&loaded(0x100_0200, 0x7000, IDENTITY_MAP_LIMIT)).unwrap();
    }

    /// MVM-1・TASK-75.3.2: 恒等写像の外・メモリ不足・GPA 0 以外の入力を書く前に拒否する。
    #[test]
    fn mvm1_885_rejects_out_of_range() {
        let e = BootCpuState::for_kernel(&loaded(0x100_0200, 0x7000, IDENTITY_MAP_LIMIT + 1))
            .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(
            e.message(),
            "kernel range exceeds the 4 GiB identity mapping"
        );
        let e =
            BootCpuState::for_kernel(&loaded(IDENTITY_MAP_LIMIT, 0x7000, 0x100_0000)).unwrap_err();
        assert_eq!(e.message(), "boot address is outside the identity mapping");
        let e = BootCpuState::for_kernel(&loaded(0x100_0200, u64::MAX, 0x100_0000)).unwrap_err();
        assert_eq!(e.message(), "boot address is outside the identity mapping");

        let mut small = heap_mem(0xE000);
        let e = write_boot_tables(&mut small).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "guest memory is too small for the boot tables");
        // 小さい領域には 1 バイトも書かない。
        assert_eq!(
            small
                .read_u64_le(GuestAddress::new(BOOT_GDT_START + 0x10))
                .unwrap(),
            0
        );
        let mut shifted = GuestMemory::new(
            GuestAddress::new(0x1000),
            HeapBacking::new(0x2_0000).unwrap(),
        )
        .unwrap();
        let e = write_boot_tables(&mut shifted).unwrap_err();
        assert_eq!(e.message(), "guest memory must start at GPA 0");
    }

    /// MVM-1・#3734: 起動用 MSR 表を具体値で照合する。
    #[test]
    fn mvm1_3734_boot_msrs_table() {
        let expect: [(u32, u64); 10] = [
            (0x10, 0),
            (0x174, 0),
            (0x175, 0),
            (0x176, 0),
            (0x1A0, 0x1801),
            (0xC000_0081, 0),
            (0xC000_0082, 0),
            (0xC000_0083, 0),
            (0xC000_0084, 0),
            (0xC000_0102, 0),
        ];
        let got: Vec<(u32, u64)> = boot_msrs().iter().map(|e| (e.index, e.data)).collect();
        assert_eq!(got, expect.to_vec());
    }

    /// MVM-1・#3734: index は重複せず、件数は ioctl の上限以下。
    #[test]
    fn mvm1_3734_boot_msrs_unique_and_bounded() {
        let t = boot_msrs();
        assert_eq!(t.len(), BOOT_MSR_COUNT);
        assert!(t.len() <= 255);
        let mut idx: Vec<u32> = t.iter().map(|e| e.index).collect();
        idx.sort_unstable();
        idx.dedup();
        assert_eq!(idx.len(), t.len());
    }

    /// MVM-1・#3734: 起動時の FPU の値。
    #[test]
    fn mvm1_3734_boot_fpu_values() {
        let f = X86FpuState::boot();
        assert_eq!(
            (
                f.fcw,
                f.fsw,
                f.ftwx,
                f.last_opcode,
                f.last_ip,
                f.last_dp,
                f.mxcsr
            ),
            (0x37F, 0, 0, 0, 0, 0, 0x1F80)
        );
    }
}
