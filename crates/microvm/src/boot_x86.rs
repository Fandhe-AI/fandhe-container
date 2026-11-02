//! x86_64 の Linux カーネル（bzImage）・initrd・cmdline のゲストメモリへのロード（TASK-75.3.1・MVM-1・MS-7。OS 非依存・unsafe なし）。
//!
//! 呼び出し元は `MicroVm::load_kernel`（Linux のみ）と、将来の plugin-microvm（TASK-117）。
//! 戻り値の [`LoadedKernel`] を #885（TASK-75.3.2。vCPU のレジスタ初期化）が受け取り、`entry` を RIP、`boot_params` を RSI に設定する。
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
//! - 実行時の開始は relocatable なら `align_up(load_addr, kernel_alignment)`、でなければ `pref_address`。
//!   `[runtime_start, runtime_start + init_size)` を確保する（`init_size`）。
//! - initrd は `initrd_addr_max` 以下かつカーネルの確保域より上、4 KiB 境界の先頭に置く。
//!
//! # 低位メモリの配置
//! [`ZERO_PAGE_ADDR`]・[`CMDLINE_ADDR`] と、#885 が GDT・ページテーブル・スタックに使う [`BOOT_SCRATCH_START`]..[`BOOT_SCRATCH_END`]
//! を 1 か所で定義し、重ならないことを `const` の assert で担保する。
//!
//! # 範囲外（REPAIR-3）
//! ELF vmlinux・PVH エントリ・aarch64 の FDT / Image・`setup_data`・ACPI / MP テーブル・EFI・4 GiB 超への配置（`ext_*`）・
//! 複数の RAM 領域・`min_alignment`・レジスタ / GDT / ページテーブル（#885）・start / stop（#886）・
//! 失敗時の網羅的な後始末（#887）・ファイルからの読み込み（呼び出し元が上限つきで読んで渡す）は未実装。
//!
//! # 外部入力の扱い
//! カーネルイメージ・initrd・cmdline は非信頼入力。長さは上限定数で書き込みの前に拒否し、オフセット計算は checked 演算と
//! `try_from` だけで行い、計画がすべて通るまでゲストメモリへ書かない。エラーの `message` に値は載せない（ERR-1）。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestAddress, GuestMemory, GuestMemoryBacking};

/// カーネルイメージの長さの上限。
pub const MAX_KERNEL_IMAGE_BYTES: u64 = 128 << 20;
/// initrd の長さの上限。
pub const MAX_INITRD_BYTES: u64 = 1 << 30;

/// boot_params（zero page）の GPA。
pub const ZERO_PAGE_ADDR: u64 = 0x7000;
/// zero page の大きさ。
pub const ZERO_PAGE_SIZE: usize = 4096;
/// #885 が GDT・IDT に使う領域の先頭（本 issue では使わない）。
pub const BOOT_GDT_START: u64 = 0x500;
/// #885 が起動スタック・ページテーブルに使う領域の先頭（本 issue では使わない）。
pub const BOOT_SCRATCH_START: u64 = 0x8000;
/// 同領域の終端（排他）。
pub const BOOT_SCRATCH_END: u64 = 0x2_0000;
/// cmdline の GPA。
pub const CMDLINE_ADDR: u64 = 0x2_0000;
/// cmdline の領域の大きさ（終端 NUL を含む）。
pub const CMDLINE_CAPACITY: u64 = 4096;
/// 低位 RAM の終端（排他。e820 の 1 本目の終わり）。
pub const LOW_RAM_END: u64 = 0x9_FC00;
/// カーネルのロード先の下限（1 MiB）。
pub const HIMEM_START: u64 = 0x10_0000;

const _: () = assert!(BOOT_GDT_START < ZERO_PAGE_ADDR);
const _: () = assert!(ZERO_PAGE_ADDR + ZERO_PAGE_SIZE as u64 <= BOOT_SCRATCH_START);
const _: () = assert!(BOOT_SCRATCH_START < BOOT_SCRATCH_END);
const _: () = assert!(BOOT_SCRATCH_END <= CMDLINE_ADDR);
const _: () = assert!(CMDLINE_ADDR + CMDLINE_CAPACITY <= LOW_RAM_END);
const _: () = assert!(LOW_RAM_END <= HIMEM_START);

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
    Ok(rd::<1>(img, off)?[0])
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
        // カーネルは単独の `--` 以降を init の引数として扱うため、自動生成項目はその前に挿入する。
        let (head, tail) = match user.split(' ').position(|t| t == "--") {
            Some(i) => {
                let off: usize = user.split(' ').take(i).map(|t| t.len() + 1).sum();
                (user[..off].trim_end_matches(' '), &user[off..])
            }
            None => (user, ""),
        };
        let mut text = head.to_owned();
        // 追加前に残り容量（終端 NUL 分を含む）を確認し、拒否する入力のために確保を膨らませない。
        let limit = usize::try_from(CMDLINE_CAPACITY - 1).unwrap_or(0);
        let mut total = text.len() + if tail.is_empty() { 0 } else { 1 + tail.len() };
        for d in devices {
            let item = format!("virtio_mmio.device=0x{:x}@0x{:x}:{}", d.len, d.base, d.gsi);
            let add = item.len() + usize::from(!text.is_empty());
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
            text.push(' ');
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
    /// 種別（1 = RAM）。
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
    pub e820: [E820Entry; 2],
}

/// ロード先・initrd の位置・e820 を決める。ゲストメモリは GPA 0 から `mem_len` バイトの単一領域。
pub fn plan_boot(
    header: &SetupHeader,
    payload_len: u64,
    initrd_len: Option<u64>,
    mem_len: u64,
) -> Result<BootPlan, MicrovmError> {
    if mem_len <= HIMEM_START {
        return Err(invalid("guest memory is too small for a kernel"));
    }
    let align = u64::from(header.kernel_alignment);
    let align_ok = align.is_power_of_two() && align <= MAX_KERNEL_ALIGNMENT;
    let pref = header.pref_address;
    let pref_usable =
        pref >= HIMEM_START && (!header.relocatable || (align_ok && pref.is_multiple_of(align)));
    let range_end = |load_addr: u64| -> Result<u64, MicrovmError> {
        load_addr
            .checked_add(payload_len)
            .zip(load_addr.checked_add(u64::from(header.init_size)))
            .map(|(a, b)| a.max(b))
            .ok_or_else(|| invalid("kernel load range overflows"))
    };
    let relocated = || -> Result<u64, MicrovmError> {
        align_up(HIMEM_START, align).ok_or_else(|| invalid("kernel load address overflows"))
    };
    // relocatable で pref_address 配置が RAM に収まらないときは再配置先（1 MiB を alignment で切り上げた位置）へ
    // フォールバックする。非 relocatable は pref_address 固定のため収まらなければ下で拒否する。
    let (load_addr, kernel_end) = if pref_usable {
        let end = range_end(pref)?;
        if header.relocatable && align_ok && end > mem_len {
            let alt = relocated()?;
            (alt, range_end(alt)?)
        } else {
            (pref, end)
        }
    } else if header.relocatable && align_ok {
        let alt = relocated()?;
        (alt, range_end(alt)?)
    } else {
        return Err(invalid(
            "kernel cannot be placed (alignment or preferred address)",
        ));
    };
    if kernel_end > mem_len {
        return Err(err(
            MicrovmErrorCode::ResourceExhausted,
            "kernel does not fit in guest memory",
        ));
    }
    let initrd = match initrd_len {
        None => None,
        Some(0) => return Err(invalid("initrd must not be empty")),
        Some(len) => {
            let top = mem_len.min(u64::from(header.initrd_addr_max) + 1);
            let start = top
                .checked_sub(len)
                .map(|s| s & !(INITRD_ALIGN - 1))
                .filter(|s| *s >= kernel_end)
                .ok_or_else(|| {
                    err(
                        MicrovmErrorCode::ResourceExhausted,
                        "initrd does not fit in guest memory",
                    )
                })?;
            Some((start, len))
        }
    };
    Ok(BootPlan {
        load_addr,
        kernel_end,
        initrd,
        e820: [
            E820Entry {
                addr: 0,
                size: LOW_RAM_END,
                kind: E820_RAM,
            },
            E820Entry {
                addr: HIMEM_START,
                size: mem_len - HIMEM_START,
                kind: E820_RAM,
            },
        ],
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

/// ロード結果（#885 がレジスタ初期化に使う）。
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
    /// カーネルが確保する範囲の終端（排他。#885 の恒等写像の対象）。
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
    let plan = plan_boot(
        &header,
        payload_len,
        initrd.map(|i| i.len() as u64),
        mem.len(),
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
        assert_eq!(read(&m, 0x7000 + 0x1E8, 1), vec![2]);
        let t = 0x7000 + 0x2D0;
        assert_eq!(m.read_u64_le(GuestAddress::new(t)).unwrap(), 0);
        assert_eq!(m.read_u64_le(GuestAddress::new(t + 8)).unwrap(), 0x9_FC00);
        assert_eq!(m.read_u32_le(GuestAddress::new(t + 16)).unwrap(), 1);
        assert_eq!(m.read_u64_le(GuestAddress::new(t + 20)).unwrap(), 0x10_0000);
        assert_eq!(m.read_u64_le(GuestAddress::new(t + 28)).unwrap(), 63 * MIB);
        assert_eq!(m.read_u32_le(GuestAddress::new(t + 36)).unwrap(), 1);
        assert_eq!(read(&m, 0x2_0000, 14), b"console=ttyS0\0".to_vec());
        assert_eq!(l.cmdline_len, 13);
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

    /// MVM-1・TASK-75.3.1: relocatable は pref_address 配置が RAM に収まらなければ再配置先（2 MiB）へ、非 relocatable は拒否する。
    #[test]
    fn mvm1_884_relocatable_falls_back_when_pref_does_not_fit() {
        let img = Img {
            pref: 0x100_0000,
            ..Img::default()
        }
        .build();
        let mut m = mem(8 * MIB);
        let l = load_linux(&mut m, &img, None, &cmd("")).unwrap();
        assert_eq!(l.kernel_addr, GuestAddress::new(0x20_0000));
        let img = Img {
            relocatable: 0,
            pref: 0x100_0000,
            ..Img::default()
        }
        .build();
        assert_eq!(
            load_linux(&mut m, &img, None, &cmd("")).unwrap_err().code(),
            MicrovmErrorCode::ResourceExhausted
        );
    }

    /// MVM-1・TASK-75.3.1: 不正・非対応のイメージは書き込みの前に具体的な code と message で拒否される。
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
        assert_eq!(ZERO_PAGE_ADDR, 0x7000);
        assert_eq!(CMDLINE_ADDR, 0x2_0000);
        assert_eq!(BOOT_SCRATCH_START, 0x8000);
        assert_eq!(BOOT_SCRATCH_END, 0x2_0000);
        assert_eq!(LOW_RAM_END, 0x9_FC00);
        assert_eq!(HIMEM_START, 0x10_0000);
    }
}
