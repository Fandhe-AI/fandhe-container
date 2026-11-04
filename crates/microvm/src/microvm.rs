//! ゲストメモリの初期化（TASK-75.1）と VM 構成体の組み立て（TASK-75.2）（MVM-1・MS-7。Linux のみ・unsafe なし）。
//!
//! # VM 構成体（TASK-75.2）
//! [`MicroVm::assemble`] が検証済みの [`MicroVmConfig`] から、VM fd・in-kernel irqchip・登録済みゲストメモリ・
//! virtio デバイス群（MMIO の窓と GSI 割り込み線つき）・vCPU 群を 1 つの [`MicroVm`] に束ねる。配置は
//! [`VIRTIO_MMIO_BASE`] から [`VIRTIO_MMIO_WINDOW`] 刻みで block → net の順、GSI は [`VIRTIO_GSI_BASE`] から連番。
//! カーネルのロードと `virtio_mmio.device=<size>@<base>:<irq>` の cmdline 生成は [`MicroVm::load_kernel`]
//! （TASK-75.3.1・#884。実体は `crate::boot_x86`）。vCPU 0 のレジスタ初期化（long mode・エントリへの RIP）は [`MicroVm::setup_boot_vcpu`]（TASK-75.3.2・#885）。
//! 呼び出し元は `fandhe-container-plugin-microvm`（TASK-117）。構成は非信頼の入力として、ioctl の前に上限を検証する。
//!
//! KVM 内部領域（#3732）: identity map（[`IDENTITY_MAP_ADDR`]）と TSS（[`TSS_ADDR`]）は vCPU の作成前に置き、RAM・MMIO の窓と
//! 重ならないことを `plan_layout` が検証する。e820 への予約領域としての記載は範囲外（REPAIR-3。現状の e820 は RAM のみ）。
//!
//! 範囲外（REPAIR-3）: ioeventfd の結線（QueueNotify は MMIO exit → dispatcher の経路で受ける）・
//! MSR / FPU の設定（CPUID は #3733 で vCPU ごとに設定済み。実カーネルの起動完走に必要。#886 以降の追跡事項）・一時停止（pause）・
//! aarch64（vGIC 未実装のため組み立ての入口で `Unimplemented`）・複数のメモリ領域（RAM は GPA 0 からの単一領域で
//! [`VIRTIO_MMIO_BASE`] 未満に制限）。複数 vCPU の exit 処理は 1 つの Mutex で直列にする簡易実装で、デバイス単位の並行は範囲外。
//!
//! # 起動と停止（TASK-75.4.1・#886）
//! [`MicroVm::start`] が vCPU 0 を初期化し、vCPU ごとの専用スレッド（`microvm-vcpu-<n>`）で実行ループを始め、
//! [`RunningMicroVm`] を返す（#3738）。AP は `KVM_MP_STATE_UNINITIALIZED` のまま `KVM_RUN` に入り、BSP の INIT/SIPI で起動する（#3737）。
//! 数は ioctl・スレッド生成の前に `1..=`[`MAX_VCPUS`] で検証する。全スレッドが 1 つの停止信号を共有し、停止は
//! [`RunningMicroVm::stop`]（期限つき。`Ok` で戻った時点で全スレッド join 済み・fd・mmap・irqfd 解放済み）で、
//! 呼び忘れても drop が回収する。1 台が `Requested` 以外（ゲストのシャットダウン・失敗・panic）で終わると全台を止める。
//! 終了は [`StopReason`] で 1 つの [`StopReport`]（全台の統計の合計・きっかけの vCPU 番号）に集約し、同じ後始末を通る。
//! 停止要求は `immediate_exit` と kick（`SIGUSR2`）で実行中の `KVM_RUN` を即時に中断する（#3736・REPAIR-5。`VCPU_POLL_INTERVAL` を待たない）。
//!
//! # virtio-net の受信ポーラー（#3742・MVM-1・REPAIR-5）
//! ゲストの kick なしで backend のフレームを受信キューへ配送するため、virtio-net を含む VM には専用スレッド `microvm-net-rx`
//! （`NetRxPoller`。1 VM に 1 本で全 net デバイスを担当）を足す。[`NET_RX_POLL_INTERVAL`] ごとに `interrupt::poll_net_rx` を呼ぶ。
//! 選択の理由: vCPU ループ内のポーリングは、in-kernel irqchip で HLT が `KVM_RUN` の中で待たれるため受信遅延が最大
//! `VCPU_POLL_INTERVAL` になる。別スレッドなら irqfd の注入で vCPU を起こせ、`StopAggregate` の参加者にすれば停止・panic・drop・
//! spawn 失敗の後始末と「`stop` が `Ok` で戻れば解放済み」の契約を vCPU と共有できる。却下: backend の到着通知（`NetBackend` に
//! API が無く実 backend も未定。TASK-75・TASK-117 で TAP を導入したら置き換えを検討する。REPAIR-3）。ロックは共有部 →
//! トランスポートの順で vCPU の `dispatch_exit` と揃える。待ちは停止要求で即座に起き、リング破損・lock の poison は fail-closed で全台を止める。
//! `start` は virtio-net を含む構成でもこのポーラーつきで起動する（#3743）。実機での確認は `tests/kvm_device.rs` の
//! `kvm_device_net_rx_reaches_guest_without_kick`。
//!
//! # シリアル（TASK-75.5・#3740・MVM-1）
//! `DeviceBus` が 8250 / 16550 互換の UART を COM1（0x3f8〜0x3ff）の PIO へ常に登録する。ホストは
//! [`MicroVm::serial_console`] / [`RunningMicroVm::serial_console`] の [`SerialConsole`]（clone。fd を持たない）から
//! THR 出力を上限つきバッファで取り出す。ハンドルは vCPU スレッドの `MicroVm` の drop 後も生きる。lock が poison したら
//! ホスト API は `Internal`、ゲスト側は応答しない（fail-closed）。未実装（REPAIR-3）: IRQ 4・ゲスト入力。
//! aarch64 には PIO が無く、組み立ての入口が `Unimplemented`。
//!
//! # 失敗時の解放（TASK-75.4.2・#887・ERR-1・REPAIR-4）
//! 失敗はすべて `Result` の [`MicrovmError`]（機械可読な `code` と英語の `message`）で返し、panic しない。
//! 解放は RAII で成り立つ: `assemble` の `Err` は戻る前に VM fd・irqchip・memslot と mmap・irqfd・vCPU fd と
//! kvm_run の mmap をすべて解放する。`start` の `Err` は `self` を消費して解放する（やり直しは `assemble` から）。
//! `load_kernel` / `setup_boot_vcpu` の `Err` では `MicroVm` が残り、drop すれば同じ順序で解放される。
//! スレッドの生成に失敗しても `body`（`MicroVm`）はクロージャごと drop される。段ごとの確認は
//! `mvm1_887_*`（KVM 不要）と `tests/kvm_device.rs` の `kvm_device_start_failure_releases_resources`（実機前提）。
//!
//! drop の順序は宣言順で固定する: vCPU → デバイス（dispatcher・irqfd の解除）→ メモリ（memslot の削除と munmap）→ VM fd。
//! [`IrqFd`] と [`RegisteredGuestRam`] は VM fd の dup を持つので、順序に依らず解除が効く。
//!
//! # ゲストメモリ（TASK-75.1）
//! TASK-75（microVM の起動フロー）の起点。`crate::guest_memory` のアクセス型 [`GuestMemory`] に、実機の backing を
//! 与える。[`GuestRam::new`] が匿名 mmap（私有・ゼロ埋め・`MAP_NORESERVE`・`MADV_DONTFORK`）でゲスト RAM を確保し、
//! [`GuestRam::register`] が `KVM_SET_USER_MEMORY_REGION` で VM の memslot に登録して
//! `GuestMemory<RegisteredGuestRam>` を返す。`unsafe` は `crate::sys` に閉じ、本モジュールは入力の検証・errno の
//! 分類・寿命の管理だけを持つ。所有先の判断は docs/design/microvm-memory-ownership.md。
//!
//! # 呼び出し元の想定
//! 後続の VM 構成体（TASK-75.2・#697）と plugin-microvm（TASK-117）が、非信頼の VM 構成（サイズ・GPA）から呼ぶ。
//! そのため size・GPA は ioctl の前にすべて検証し、slot は `u16` で受ける（KVM は上位 16 bit を address space id に使う）。
//!
//! # 範囲外（REPAIR-3）
//! 複数領域（MMIO hole・4 GiB をまたぐ x86_64 の配置）・`KVM_CAP_NR_MEMSLOTS` による slot 上限の照会・
//! hugepage・`KVM_MEM_READONLY` / `KVM_MEM_LOG_DIRTY_PAGES`・カーネルのロード（TASK-75.3）は未実装。
//!
//! # 寿命
//! [`RegisteredGuestRam`] は VM fd を dup して持つ（`'vm` の借用を持たないので、VM 構成体が VM fd と一緒に保持できる）。
//! drop では slot を削除してから munmap する。削除に失敗したら mapping を解放せず漏らす（ゲストがまだ書けるメモリを
//! 別の用途に再利用させない fail-closed）。

#![cfg(target_os = "linux")]

use std::os::fd::{AsFd as _, OwnedFd};
use std::sync::{Arc, Condvar, Mutex, PoisonError, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::boot_x86::LoadedKernel;
#[cfg(target_arch = "x86_64")]
use crate::boot_x86::{
    BootCpuState, KernelCmdline, VirtioMmioParam, X86FpuState, boot_msrs, load_linux,
    write_boot_tables,
};
use crate::device::{KvmDevice, RunStats, StopSignal, VcpuFd, VmFd};
use crate::dispatch::{DeviceId, DispatchOutcome, ExitDispatcher, MmioAccess, MmioDevice};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::exit::VcpuExit;
use crate::guest_memory::{GuestAddress, GuestMemory, GuestMemoryBacking};
use crate::interrupt::{
    BlockNotifyReport, InterruptLine, NetNotifyReport, NetRxPollOutcome, complete_block_notify,
    complete_net_notify, poll_net_rx,
};
use crate::irq::IrqFd;
use crate::smp_x86::SipiVector;
#[cfg(target_arch = "x86_64")]
use crate::smp_x86::{MpState, plan_vcpus, sipi_startup_range};
use crate::sys::{self, GuestRamMap, SysError};
use crate::uart::{COM1_BASE, SerialConsole, UART_PORT_LEN};
use crate::virtio_block::{BlockBackend, VirtioBlock};
use crate::virtio_mmio::{
    CONFIG_SPACE_SIZE, IgnoredAccess, MmioReadOutcome, MmioWriteOutcome, VirtioDevice,
    VirtioMmioTransport,
};
use crate::virtio_net::{NetBackend, VirtioNet};

/// virtio-mmio の窓の先頭（GPA）。ゲスト RAM（GPA 0 からの単一領域）はこれより下に収まる。
/// cmdline の `virtio_mmio.device=<size>@<base>:<irq>`（[`MicroVm::load_kernel`]。#884）が使う。
pub const VIRTIO_MMIO_BASE: u64 = 0xd000_0000;
/// 1 デバイスの MMIO 窓の大きさ（ページ境界。レジスタ 0x100 と設定空間 [`CONFIG_SPACE_SIZE`] の和以上）。
pub const VIRTIO_MMIO_WINDOW: u64 = 0x1000;
/// 最初のデバイスの GSI。以降は 1 ずつ増やす（既存の `probe_queue_interrupt` も GSI 5 を使う）。
pub const VIRTIO_GSI_BASE: u32 = 5;
/// block と net の合計台数の上限。GSI は 5..=12 に収まり、x86_64 の IOAPIC（24 ピン）の範囲内。
pub const MAX_VIRTIO_DEVICES: usize = 8;
/// 構成の検証上限としての vCPU 数（これより上の実際の上限はカーネルの EINVAL に任せる）。
pub const MAX_VCPUS: u32 = 32;
// xAPIC の APIC ID（8 bit）に収まること（#3737。`smp_x86::plan_vcpus` の上限）。
const _: () = assert!(MAX_VCPUS <= crate::smp_x86::MAX_XAPIC_VCPUS);

const _: () = assert!(VIRTIO_MMIO_WINDOW.is_multiple_of(4096));
const _: () = assert!(VIRTIO_MMIO_WINDOW >= 0x100 + CONFIG_SPACE_SIZE);

/// KVM の identity map ページ（EPT 用。`KVM_SET_IDENTITY_MAP_ADDR`）の置き場（GPA。1 ページ）。KVM の既定値と同じで、
/// TSS の直前に置く。ゲストのページテーブルが作る恒等写像の範囲（`boot_x86::IDENTITY_MAP_LIMIT`）とは別物。
/// KVM API 文書は、この領域と [`TSS_ADDR`] を最初の 4 GiB に置き、どの memslot・MMIO とも衝突させないことを要求する。
/// RAM は GPA 0 から [`VIRTIO_MMIO_BASE`] 以下、virtio-mmio の窓は最大 `0xd000_8000` まで、IOAPIC / LAPIC は
/// `0xfec0_0000` 以降なので、この位置はどれとも重ならない（`assemble` が `check_reserved_regions` で検証する。MVM-1・#3732）。
pub const IDENTITY_MAP_ADDR: u64 = 0xfffb_c000;
/// [`IDENTITY_MAP_ADDR`] の大きさ（1 ページ）。
pub const IDENTITY_MAP_LEN: u64 = 0x1000;
/// TSS 用の置き場（GPA。3 ページ）。identity map の直後。`KVM_SET_TSS_ADDR` は先頭から 3 ページを使い、
/// カーネルは `addr` が `(unsigned int)(-3 * PAGE_SIZE)` を超えると拒否する（上限は下の const assert で固定）。
pub const TSS_ADDR: u64 = 0xfffb_d000;
/// [`TSS_ADDR`] の大きさ（3 ページ）。
pub const TSS_LEN: u64 = 0x3000;
/// in-kernel IOAPIC の MMIO の窓（既定の物理アドレス。実体は 0x20 バイトだがページ単位で確保する）。
const IOAPIC_MMIO_BASE: u64 = 0xfec0_0000;
const IOAPIC_MMIO_LEN: u64 = 0x1000;
/// LAPIC の MMIO の窓（既定の物理アドレス）。
const LAPIC_MMIO_BASE: u64 = 0xfee0_0000;
const LAPIC_MMIO_LEN: u64 = 0x1000;
/// 4 GiB（TSS・identity map はここまでに収める）。
const GPA_4GIB: u64 = 1 << 32;

const _: () = assert!(TSS_ADDR.is_multiple_of(4096) && IDENTITY_MAP_ADDR.is_multiple_of(4096));
const _: () = assert!(TSS_LEN == 3 * 4096 && IDENTITY_MAP_LEN == 4096);
const _: () = assert!(IDENTITY_MAP_ADDR + IDENTITY_MAP_LEN <= TSS_ADDR);
const _: () = assert!(TSS_ADDR + TSS_LEN <= GPA_4GIB);
// カーネルの上限 `addr <= (unsigned int)(-3 * PAGE_SIZE)` = 0xffff_d000。
const _: () = assert!(TSS_ADDR <= 0xffff_d000);
const _: () =
    assert!(VIRTIO_MMIO_BASE + MAX_VIRTIO_DEVICES as u64 * VIRTIO_MMIO_WINDOW <= IOAPIC_MMIO_BASE);
const _: () = assert!(IOAPIC_MMIO_BASE + IOAPIC_MMIO_LEN <= LAPIC_MMIO_BASE);
const _: () = assert!(LAPIC_MMIO_BASE + LAPIC_MMIO_LEN <= IDENTITY_MAP_ADDR);

/// ゲスト RAM の確保上限（16 GiB。無制限確保による DoS を防ぐ。`MAP_NORESERVE` でも上限で抑える）。
pub const MAX_GUEST_RAM_BYTES: u64 = 1 << 34;

/// ゲスト RAM のサイズ・GPA の整列単位の下限（4 KiB）。実際の単位は `max(これ, ホストのページサイズ)`
/// （KVM の memslot はホストの `PAGE_SIZE` の倍数を要求する。16 / 64 KiB ページの aarch64 Linux 対応）。
pub const GUEST_RAM_ALIGN: u64 = sys::GUEST_PAGE_SIZE as u64;

const EPERM: i32 = 1;
const EAGAIN: i32 = 11;
const ENOMEM: i32 = 12;
const EACCES: i32 = 13;
const EEXIST: i32 = 17;
const EINVAL: i32 = 22;
const ENFILE: i32 = 23;
const EMFILE: i32 = 24;
const ENOTTY: i32 = 25;

/// RAM の整列単位 `max(GUEST_RAM_ALIGN, ホストのページサイズ)`。取得失敗は分類して返す。
fn ram_align() -> Result<u64, MicrovmError> {
    let host = sys::host_page_size().map_err(|e| classify_ram_error(RamStage::Mmap, e))?;
    Ok(host.max(GUEST_RAM_ALIGN))
}

/// RAM サイズの検証（副作用なし）。`GuestRam::new` と `MicroVm::assemble` の ioctl 前検証が共有する。
fn validate_ram_size(size: u64, align: u64) -> Result<(), MicrovmError> {
    if size == 0 {
        return Err(invalid("guest memory size must not be zero"));
    }
    if !size.is_multiple_of(align) {
        return Err(invalid(
            "guest memory size must be a multiple of the host page size (at least 4096)",
        ));
    }
    if size > MAX_GUEST_RAM_BYTES {
        return Err(invalid("guest memory size too large"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, message)
}

fn out_of_range() -> MicrovmError {
    invalid("guest memory access out of range")
}

/// 失敗した段（errno 分類のメッセージ切り替え用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RamStage {
    Mmap,
    DupVmFd,
    Register,
}

fn classify_ram_error(stage: RamStage, e: SysError) -> MicrovmError {
    let name = match stage {
        RamStage::Mmap => "mmap of guest memory",
        RamStage::DupVmFd => "duplicating VM fd",
        RamStage::Register => "KVM_SET_USER_MEMORY_REGION",
    };
    match e {
        SysError::Unsupported => MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        ),
        SysError::Os(n) if n == ENOMEM || n == EMFILE || n == ENFILE => MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            format!("resource exhausted in {name} (os error {n})"),
        ),
        SysError::Os(EEXIST) if stage == RamStage::Register => MicrovmError::new(
            MicrovmErrorCode::AlreadyExists,
            "guest memory slot or address range already registered",
        ),
        SysError::Os(EINVAL) if stage == RamStage::Register => MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "KVM rejected the guest memory region",
        ),
        SysError::Os(ENOTTY) if stage == RamStage::Register => {
            MicrovmError::new(MicrovmErrorCode::FailedPrecondition, "not a KVM VM fd")
        }
        SysError::Os(n) if n == EACCES || n == EPERM => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            format!("permission denied in {name}"),
        ),
        SysError::NullMapping => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("{name} returned a null address"),
        ),
        SysError::Os(n) => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("{name} failed (os error {n})"),
        ),
    }
}

fn read_map(map: &GuestRamMap, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
    let off = usize::try_from(offset).map_err(|_| out_of_range())?;
    map.read_into(off, buf).map_err(|()| out_of_range())
}

fn write_map(map: &mut GuestRamMap, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
    let off = usize::try_from(offset).map_err(|_| out_of_range())?;
    map.write_from(off, data).map_err(|()| out_of_range())
}

/// まだ KVM に登録していない、mmap 済みのゲスト RAM。
///
/// [`GuestMemoryBacking`] を実装するので、登録前のゲストメモリ（カーネル・initrd の書き込み）にも使える。
#[derive(Debug)]
pub struct GuestRam {
    map: GuestRamMap,
}

impl GuestRam {
    /// `size` バイトのゼロ埋めのゲスト RAM を確保する。
    ///
    /// `size` は 0 でなく、`max(4096, ホストのページサイズ)` の倍数で、[`MAX_GUEST_RAM_BYTES`] 以下であること（違反は `InvalidArgument`）。
    pub fn new(size: u64) -> Result<GuestRam, MicrovmError> {
        let align = ram_align()?;
        Self::new_aligned(size, align)
    }

    /// 整列単位 `align`（`max(4096, ホストのページサイズ)`）を指定して確保する（試験で 16 / 64 KiB を再現するため分離）。
    fn new_aligned(size: u64, align: u64) -> Result<GuestRam, MicrovmError> {
        validate_ram_size(size, align)?;
        let len = usize::try_from(size).map_err(|_| invalid("guest memory size too large"))?;
        let map = GuestRamMap::map(len).map_err(|e| classify_ram_error(RamStage::Mmap, e))?;
        Ok(GuestRam { map })
    }

    /// `vm` の memslot `slot` に、ゲスト物理アドレス `base` から登録する。
    ///
    /// `base` は `max(4096, ホストのページサイズ)` 境界で、`base + size` が桁あふれしないこと。登録に失敗したときは mapping を解放して返す
    /// （未登録なので解放してよい）。範囲が重なる既存の slot があれば `AlreadyExists`。
    pub fn register(
        self,
        vm: &VmFd,
        slot: u16,
        base: GuestAddress,
    ) -> Result<GuestMemory<RegisteredGuestRam>, MicrovmError> {
        if !base.raw().is_multiple_of(ram_align()?) {
            return Err(invalid(
                "guest address must be a multiple of the host page size (at least 4096)",
            ));
        }
        let size = self.map.len() as u64;
        base.checked_add(size)
            .ok_or_else(|| invalid("guest address range overflows"))?;
        let vm_fd = vm.as_fd().try_clone_to_owned().map_err(|e| {
            classify_ram_error(
                RamStage::DupVmFd,
                SysError::Os(e.raw_os_error().unwrap_or(0)),
            )
        })?;
        sys::register_guest_ram(vm_fd.as_fd(), u32::from(slot), base.raw(), &self.map)
            .map_err(|e| classify_ram_error(RamStage::Register, e))?;
        let registered = RegisteredGuestRam {
            vm: vm_fd,
            slot,
            map: Some(self.map),
        };
        GuestMemory::new(base, registered)
    }
}

impl GuestMemoryBacking for GuestRam {
    fn len(&self) -> u64 {
        self.map.len() as u64
    }
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        read_map(&self.map, offset, buf)
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
        write_map(&mut self.map, offset, data)
    }
}

/// KVM の memslot に登録済みのゲスト RAM。
///
/// 登録後はゲスト（vCPU）がいつでも書き換えるため、読み書きは常にコピーで行う。drop で slot を削除してから
/// munmap する（削除に失敗したら mapping を漏らす）。
#[derive(Debug)]
pub struct RegisteredGuestRam {
    vm: OwnedFd,
    slot: u16,
    map: Option<GuestRamMap>,
}

impl GuestMemoryBacking for RegisteredGuestRam {
    fn len(&self) -> u64 {
        self.map.as_ref().map_or(0, |m| m.len() as u64)
    }
    fn read(&self, offset: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        let map = self.map.as_ref().ok_or_else(out_of_range)?;
        read_map(map, offset, buf)
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> Result<(), MicrovmError> {
        let map = self.map.as_mut().ok_or_else(out_of_range)?;
        write_map(map, offset, data)
    }
}

impl Drop for RegisteredGuestRam {
    fn drop(&mut self) {
        let removed = sys::unregister_guest_ram(self.vm.as_fd(), u32::from(self.slot)).is_ok();
        if let Some(map) = self.map.take() {
            if removed {
                drop(map);
            } else {
                // 削除に失敗した領域は解放しない（ゲストがまだ書けるメモリを別の用途に再利用させない fail-closed）。
                log_line(format_args!(
                    "level=error op=microvm.guest_ram_unregister outcome=error code=INTERNAL leaked_bytes={}",
                    map.len()
                ));
                std::mem::forget(map);
            }
        }
    }
}

/// virtio デバイスの種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VirtioDeviceKind {
    /// virtio-block。
    Block,
    /// virtio-net。
    Net,
}

/// virtio-net 1 台分の構成。
#[derive(Debug)]
pub struct NetDeviceConfig<N> {
    /// フレームの送受信先。
    pub backend: N,
    /// ゲストに見せる MAC アドレス。
    pub mac: [u8; 6],
}

/// microVM の構成（非信頼の入力。[`MicroVm::assemble`] が ioctl の前に検証する）。
#[derive(Debug)]
pub struct MicroVmConfig<B, N> {
    /// vCPU 数（1..=[`MAX_VCPUS`]）。
    pub vcpu_count: u32,
    /// ゲスト RAM のサイズ（GPA 0 から。[`VIRTIO_MMIO_BASE`] 以下）。
    pub mem_size: u64,
    /// virtio-block の backend（先に配置される）。
    pub block: Vec<B>,
    /// virtio-net の構成（block の後に配置される）。
    pub net: Vec<NetDeviceConfig<N>>,
}

/// デバイス 1 台の MMIO の窓と割り込み線の配置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceSlot {
    /// 種別。
    pub kind: VirtioDeviceKind,
    /// 同じ種別の中での番号。
    pub index: usize,
    /// MMIO の窓の先頭（GPA）。
    pub mmio_base: u64,
    /// MMIO の窓の大きさ。
    pub mmio_len: u64,
    /// 割り込みの GSI。
    pub gsi: u32,
}

/// 配置と dispatcher 上の識別子。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceInfo {
    /// 配置。
    pub slot: DeviceSlot,
    /// MMIO dispatcher 上の識別子（`complete_queue_notify` に渡す）。
    pub id: DeviceId,
}

/// 構成を検証してデバイスの配置を計算する（ioctl 前の純粋な処理）。
fn plan_layout(
    vcpu_count: u32,
    mem_size: u64,
    block_count: usize,
    net_count: usize,
) -> Result<Vec<DeviceSlot>, MicrovmError> {
    if cfg!(not(target_arch = "x86_64")) {
        return Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "microvm assembly is only implemented for x86_64 (aarch64 vGIC is not implemented)",
        ));
    }
    if vcpu_count == 0 || vcpu_count > MAX_VCPUS {
        return Err(invalid("vcpu count out of range"));
    }
    validate_ram_size(mem_size, ram_align()?)?;
    if mem_size > VIRTIO_MMIO_BASE {
        return Err(invalid("guest memory overlaps the virtio-mmio window"));
    }
    let slots = layout_slots(block_count, net_count)?;
    let (reserved, occupied) = system_regions(mem_size, &slots)?;
    check_reserved_regions(&reserved, &occupied)?;
    Ok(slots)
}

/// GPA の半開区間 `[start, end)`（重なり検証用。`end` の溢れと空区間は作れない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuestRange {
    start: u64,
    end: u64,
}

impl GuestRange {
    /// `[start, start + len)`。`len == 0` と加算の溢れは `InvalidArgument`（panic しない）。
    fn new(start: u64, len: u64) -> Result<Self, MicrovmError> {
        let end = start
            .checked_add(len)
            .filter(|_| len != 0)
            .ok_or_else(|| invalid("guest range is empty or overflows"))?;
        Ok(Self { start, end })
    }

    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// 重なり検証の領域の種別（エラー文言用。値・アドレスは載せない。ERR-1・REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegionKind {
    GuestMemory,
    VirtioMmio,
    Ioapic,
    Lapic,
    Tss,
    IdentityMap,
}

impl RegionKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::GuestMemory => "guest memory",
            Self::VirtioMmio => "a virtio-mmio window",
            Self::Ioapic => "the IOAPIC window",
            Self::Lapic => "the LAPIC window",
            Self::Tss => "the TSS region",
            Self::IdentityMap => "the identity map page",
        }
    }
}

type Region = (RegionKind, GuestRange);

/// KVM 内部領域（`reserved`: TSS・identity map）が 4 GiB 以内に収まり、互いに、また使用中の領域（`occupied`:
/// RAM・MMIO の窓）と重ならないことを確かめる（KVM 不要の純粋関数。`plan_layout` が ioctl の前に呼ぶ。MVM-1・#3732）。
/// 違反は `InvalidArgument`（fail-closed）。範囲を引数で受けるのは、定数の組では境界の 1 バイトを試験できないため。
fn check_reserved_regions(reserved: &[Region], occupied: &[Region]) -> Result<(), MicrovmError> {
    for (i, (kind, range)) in reserved.iter().enumerate() {
        if range.end > GPA_4GIB {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                format!("{} must lie below 4 GiB", kind.as_str()),
            ));
        }
        for (other_kind, other) in reserved.iter().take(i).chain(occupied.iter()) {
            if range.overlaps(*other) {
                return Err(MicrovmError::new(
                    MicrovmErrorCode::InvalidArgument,
                    format!("{} overlaps {}", kind.as_str(), other_kind.as_str()),
                ));
            }
        }
    }
    Ok(())
}

/// 実際の構成から `check_reserved_regions` へ渡す `(reserved, occupied)` を組む。
fn system_regions(
    mem_size: u64,
    slots: &[DeviceSlot],
) -> Result<(Vec<Region>, Vec<Region>), MicrovmError> {
    let mut occupied = vec![(RegionKind::GuestMemory, GuestRange::new(0, mem_size)?)];
    for s in slots {
        occupied.push((
            RegionKind::VirtioMmio,
            GuestRange::new(s.mmio_base, s.mmio_len)?,
        ));
    }
    occupied.push((
        RegionKind::Ioapic,
        GuestRange::new(IOAPIC_MMIO_BASE, IOAPIC_MMIO_LEN)?,
    ));
    occupied.push((
        RegionKind::Lapic,
        GuestRange::new(LAPIC_MMIO_BASE, LAPIC_MMIO_LEN)?,
    ));
    let reserved = vec![
        (
            RegionKind::IdentityMap,
            GuestRange::new(IDENTITY_MAP_ADDR, IDENTITY_MAP_LEN)?,
        ),
        (RegionKind::Tss, GuestRange::new(TSS_ADDR, TSS_LEN)?),
    ];
    Ok((reserved, occupied))
}

/// デバイス数からの配置計算（arch・KVM 非依存の純粋な処理。`plan_layout` が検証後に呼ぶ）。
fn layout_slots(block_count: usize, net_count: usize) -> Result<Vec<DeviceSlot>, MicrovmError> {
    let total = block_count
        .checked_add(net_count)
        .filter(|n| *n <= MAX_VIRTIO_DEVICES)
        .ok_or_else(|| invalid("too many virtio devices"))?;
    let mut slots = Vec::with_capacity(total);
    for i in 0..total {
        let (kind, index) = if i < block_count {
            (VirtioDeviceKind::Block, i)
        } else {
            (VirtioDeviceKind::Net, i - block_count)
        };
        let off = u64::try_from(i)
            .ok()
            .and_then(|n| n.checked_mul(VIRTIO_MMIO_WINDOW))
            .and_then(|n| VIRTIO_MMIO_BASE.checked_add(n))
            .ok_or_else(|| invalid("device range overflows"))?;
        let gsi = u32::try_from(i)
            .ok()
            .and_then(|n| VIRTIO_GSI_BASE.checked_add(n))
            .ok_or_else(|| invalid("device range overflows"))?;
        slots.push(DeviceSlot {
            kind,
            index,
            mmio_base: off,
            mmio_len: VIRTIO_MMIO_WINDOW,
            gsi,
        });
    }
    Ok(slots)
}

fn poisoned() -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, "virtio device lock poisoned")
}

/// dispatcher（所有を要求する）と VM 構成体（型つきで触る）がトランスポートを共有するためのラッパー。
///
/// lock が poison していたらデバイスは応答をやめる（fail-closed。`MmioDevice` は `Result` を返せない）。
struct SharedTransport<D: VirtioDevice>(Arc<Mutex<VirtioMmioTransport<D>>>);

impl<D: VirtioDevice + Send> MmioDevice for SharedTransport<D> {
    fn read(&self, offset: u64, data: &mut [u8]) -> MmioReadOutcome {
        match self.0.lock() {
            Ok(t) => t.read(offset, data),
            Err(_) => {
                data.fill(0);
                MmioReadOutcome::Ignored(IgnoredAccess::WrongDeviceState)
            }
        }
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> MmioWriteOutcome {
        match self.0.lock() {
            Ok(mut t) => t.write(offset, data),
            Err(_) => MmioWriteOutcome::Ignored(IgnoredAccess::WrongDeviceState),
        }
    }
}

/// 登録済みのデバイス 1 台（トランスポート・識別子・配置・割り込み線）。
struct BoundDevice<D: VirtioDevice, L> {
    transport: Arc<Mutex<VirtioMmioTransport<D>>>,
    id: DeviceId,
    slot: DeviceSlot,
    line: L,
}

/// `QueueNotify` の処理結果（デバイス種別ごと。REPAIR-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueueNotifyReport {
    /// virtio-block。
    Block(BlockNotifyReport),
    /// virtio-net。
    Net(NetNotifyReport),
}

impl QueueNotifyReport {
    /// virtqueue 処理の失敗（リング破損など、ゲスト起因）。無ければ `None`。
    pub fn queue_error(&self) -> Option<&MicrovmError> {
        match self {
            QueueNotifyReport::Block(r) => r.queue_error.as_ref(),
            QueueNotifyReport::Net(r) => r.queue_error.as_ref(),
        }
    }
}

/// MMIO / PIO dispatcher と block / net デバイス群と COM1 の UART。KVM に依存しない（`L` は割り込み線で、本番は [`IrqFd`]）。
///
/// UART（#3740・MVM-1）は常に COM1 へ登録し、`serial` はホストへ出力を渡す共有ハンドル。
struct DeviceBus<B: BlockBackend, N: NetBackend, L> {
    dispatcher: ExitDispatcher,
    block: Vec<BoundDevice<VirtioBlock<B>, L>>,
    net: Vec<BoundDevice<VirtioNet<N>, L>>,
    serial: SerialConsole,
}

impl<B: BlockBackend, N: NetBackend, L> DeviceBus<B, N, L> {
    fn infos(&self) -> Vec<DeviceInfo> {
        let b = self.block.iter().map(|d| DeviceInfo {
            slot: d.slot,
            id: d.id,
        });
        let n = self.net.iter().map(|d| DeviceInfo {
            slot: d.slot,
            id: d.id,
        });
        b.chain(n).collect()
    }
}

impl<B: BlockBackend + Send + 'static, N: NetBackend + Send + 'static, L> DeviceBus<B, N, L> {
    /// `slots`（block → net の順）に従ってデバイスを作り、dispatcher に登録し、`make_line` で割り込み線を得る。
    fn new(
        slots: &[DeviceSlot],
        block: Vec<B>,
        net: Vec<NetDeviceConfig<N>>,
        mut make_line: impl FnMut(&DeviceSlot) -> Result<L, MicrovmError>,
    ) -> Result<Self, MicrovmError> {
        if slots.len() != block.len() + net.len() {
            return Err(invalid("device layout does not match the configuration"));
        }
        let mut bus = DeviceBus {
            dispatcher: ExitDispatcher::new(),
            block: Vec::with_capacity(block.len()),
            net: Vec::with_capacity(net.len()),
            serial: SerialConsole::new(),
        };
        // PIO と MMIO は別の表なので virtio の窓とは衝突しない。
        bus.dispatcher
            .register_pio(COM1_BASE, UART_PORT_LEN, bus.serial.port_device())?;
        let mut slots_iter = slots.iter();
        for backend in block {
            let slot = *slots_iter
                .next()
                .ok_or_else(|| invalid("device layout does not match the configuration"))?;
            let transport = Arc::new(Mutex::new(VirtioMmioTransport::new(VirtioBlock::new(
                backend,
            ))?));
            let id = bus.dispatcher.register_mmio(
                slot.mmio_base,
                slot.mmio_len,
                Box::new(SharedTransport(Arc::clone(&transport))),
            )?;
            let line = make_line(&slot)?;
            bus.block.push(BoundDevice {
                transport,
                id,
                slot,
                line,
            });
        }
        for cfg in net {
            let slot = *slots_iter
                .next()
                .ok_or_else(|| invalid("device layout does not match the configuration"))?;
            let transport = Arc::new(Mutex::new(VirtioMmioTransport::new(VirtioNet::new(
                cfg.backend,
                cfg.mac,
            ))?));
            let id = bus.dispatcher.register_mmio(
                slot.mmio_base,
                slot.mmio_len,
                Box::new(SharedTransport(Arc::clone(&transport))),
            )?;
            let line = make_line(&slot)?;
            bus.net.push(BoundDevice {
                transport,
                id,
                slot,
                line,
            });
        }
        Ok(bus)
    }

    /// `id` のデバイスの `QueueNotify(queue)` を処理する（割り込み線はデバイス自身のもの）。
    fn complete_queue_notify<M: GuestMemoryBacking>(
        &mut self,
        id: DeviceId,
        queue: u16,
        mem: &mut GuestMemory<M>,
    ) -> Result<QueueNotifyReport, MicrovmError>
    where
        L: InterruptLine,
    {
        if let Some(dev) = self.block.iter().find(|d| d.id == id) {
            if queue != 0 {
                return Err(invalid("block queue index out of range"));
            }
            let mut t = dev.transport.lock().map_err(|_| poisoned())?;
            return complete_block_notify(&mut t, mem, &dev.line).map(QueueNotifyReport::Block);
        }
        if let Some(dev) = self.net.iter().find(|d| d.id == id) {
            let mut t = dev.transport.lock().map_err(|_| poisoned())?;
            return complete_net_notify(&mut t, mem, queue, &dev.line).map(QueueNotifyReport::Net);
        }
        Err(invalid("unknown virtio device"))
    }

    /// 全 virtio-net の受信をゲストの kick なしで 1 回ずつ処理する（#3742・MVM-1・REPAIR-5）。
    ///
    /// 受信ポーラーが期限ごとに呼ぶ。各トランスポートの lock を順に取り（呼び出し元が共有部の lock を持つ前提で、
    /// vCPU の `dispatch_exit` と同じ「共有部 → トランスポート」の順）、[`poll_net_rx`] を呼ぶ。リング破損は最初の 1 件を
    /// `queue_error` に保持してそこで打ち切る（fail-closed。呼び出し元が VM を止める）。lock の poison と割り込み線の失敗は `Err`。
    fn poll_net_rx<M: GuestMemoryBacking>(
        &mut self,
        mem: &mut GuestMemory<M>,
    ) -> Result<NetRxPollReport, MicrovmError>
    where
        L: InterruptLine,
    {
        let mut report = NetRxPollReport::default();
        for dev in &self.net {
            let mut t = dev.transport.lock().map_err(|_| poisoned())?;
            match poll_net_rx(&mut t, mem, &dev.line)? {
                NetRxPollOutcome::Skipped(_) => report.skipped += 1,
                NetRxPollOutcome::Polled(r) => {
                    report.polled += 1;
                    if let crate::interrupt::NetQueueStats::Rx(s) = r.stats {
                        report.delivered = report.delivered.saturating_add(s.delivered);
                    }
                    report.completed = report.completed.saturating_add(r.stats.completed());
                    if r.delivery == crate::interrupt::InterruptDelivery::Triggered {
                        report.interrupts += 1;
                    }
                    if let Some(e) = r.queue_error {
                        report.queue_error = Some(e);
                        break;
                    }
                }
            }
        }
        Ok(report)
    }
}

/// [`DeviceBus::poll_net_rx`] の集計（crate 内。REPAIR-4）。
#[derive(Debug, Default)]
struct NetRxPollReport {
    /// `process_rx` を呼んだデバイス数。
    polled: u32,
    /// 状態（未 activate・FAILED・キュー停止）で飛ばしたデバイス数。
    skipped: u32,
    /// used へ返した数の合計。
    completed: u32,
    /// ゲストのバッファへ配送したフレーム数の合計。
    delivered: u32,
    /// 注入した割り込みの回数。
    interrupts: u32,
    /// 最初に見つかったリング破損など（ゲスト起因）。
    queue_error: Option<MicrovmError>,
}

/// 組み立て済みの microVM（VM fd・vCPU 群・登録済みゲストメモリ・virtio デバイス群）。
///
/// フィールドの宣言順が drop 順（vCPU → デバイス → メモリ → VM fd）。モジュール doc 参照。
pub struct MicroVm<B: BlockBackend, N: NetBackend> {
    vcpus: Vec<VcpuFd>,
    devices: DeviceBus<B, N, IrqFd>,
    memory: GuestMemory<RegisteredGuestRam>,
    vm: VmFd,
}

impl<B: BlockBackend, N: NetBackend> std::fmt::Debug for MicroVm<B, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MicroVm")
            .field("vcpus", &self.vcpus.len())
            .field("memory_len", &self.memory.len())
            .field("devices", &self.devices.infos())
            .finish()
    }
}

impl<B: BlockBackend + Send + 'static, N: NetBackend + Send + 'static> MicroVm<B, N> {
    /// 構成を検証し、VM → irqchip → identity map / TSS（x86_64）→ ゲストメモリ → デバイス → vCPU の順に組み立てる。
    ///
    /// irqchip は vCPU より前に作る必要がある。途中で失敗したときはローカル変数の drop が逆順に後始末する
    /// （段ごとの確認は `mvm1_887_*`・#887）。aarch64 は最初の ioctl より前に `Unimplemented`。
    ///
    /// vCPU ごとに `KVM_SET_CPUID2`（APIC ID = vCPU id。`cpuid_x86`・#3733）も設定する。
    ///
    /// `Err` のとき、それまでに取った fd・mmap・irqfd はすべて戻る前に解放済み。構成値・パスはログに載せない（REPAIR-4）。
    pub fn assemble(
        kvm: &KvmDevice,
        config: MicroVmConfig<B, N>,
    ) -> Result<MicroVm<B, N>, MicrovmError> {
        let started = Instant::now();
        let result = Self::assemble_inner(kvm, config);
        let elapsed_us = started.elapsed().as_micros();
        match &result {
            Ok(_) => log_line(format_args!(
                "level=info op=microvm.assemble outcome=ok elapsed_us={elapsed_us}"
            )),
            Err(e) => log_line(format_args!(
                "level=error op=microvm.assemble outcome=error code={} elapsed_us={elapsed_us}",
                e.code().as_str()
            )),
        }
        result
    }

    fn assemble_inner(
        kvm: &KvmDevice,
        config: MicroVmConfig<B, N>,
    ) -> Result<MicroVm<B, N>, MicrovmError> {
        let slots = plan_layout(
            config.vcpu_count,
            config.mem_size,
            config.block.len(),
            config.net.len(),
        )?;
        let vm = kvm.create_vm()?;
        vm.create_irqchip()?;
        // KVM 内部領域（identity map・TSS）は vCPU の作成前に置く。位置の重なりは plan_layout で検証済み（#3732）。
        #[cfg(target_arch = "x86_64")]
        {
            vm.set_identity_map_addr(IDENTITY_MAP_ADDR)?;
            vm.set_tss_addr(TSS_ADDR)?;
        }
        let memory = GuestRam::new(config.mem_size)?.register(&vm, 0, GuestAddress::new(0))?;
        let devices = DeviceBus::new(&slots, config.block, config.net, |s| {
            vm.register_irqfd(s.gsi)
        })?;
        // CPUID は最初の KVM_RUN と KVM_SET_SREGS より前に vCPU ごとに設定する（APIC ID = vCPU id。#3733）。
        let cpuid = kvm.supported_cpuid()?;
        let mut vcpus = Vec::with_capacity(config.vcpu_count as usize);
        #[cfg(target_arch = "x86_64")]
        for plan in plan_vcpus(config.vcpu_count)? {
            let mut v = vm.create_vcpu(plan.index)?;
            v.set_cpuid(&cpuid.for_vcpu(plan.apic_id)?)?;
            // AP は INIT/SIPI を待つ状態へ、カーネルの既定に頼らず明示的に置く（#3737）。
            if plan.initial_mp_state == MpState::Uninitialized {
                v.set_mp_state(MpState::Uninitialized)?;
            }
            vcpus.push(v);
        }
        #[cfg(not(target_arch = "x86_64"))]
        for i in 0..config.vcpu_count {
            let mut v = vm.create_vcpu(i)?;
            v.set_cpuid(&cpuid.for_vcpu(i)?)?;
            vcpus.push(v);
        }
        Ok(MicroVm {
            vcpus,
            devices,
            memory,
            vm,
        })
    }

    /// VM fd。
    pub fn vm(&self) -> &VmFd {
        &self.vm
    }

    /// vCPU 群（id 順）。
    pub fn vcpus(&self) -> &[VcpuFd] {
        &self.vcpus
    }

    /// `index` 番の vCPU。範囲外は `None`。
    pub fn vcpu_mut(&mut self, index: usize) -> Option<&mut VcpuFd> {
        self.vcpus.get_mut(index)
    }

    /// 登録済みゲストメモリ。
    pub fn memory(&self) -> &GuestMemory<RegisteredGuestRam> {
        &self.memory
    }

    /// 登録済みゲストメモリ（書き込み用。カーネルのロードは [`MicroVm::load_kernel`]）。
    pub fn memory_mut(&mut self) -> &mut GuestMemory<RegisteredGuestRam> {
        &mut self.memory
    }

    /// bzImage・initrd・cmdline をゲストメモリへロードする（TASK-75.3.1・MVM-1。x86_64 のみ、他 arch は `Unimplemented`）。
    ///
    /// cmdline は `user_cmdline` の後ろに、組み立て済みの各デバイスの `virtio_mmio.device=<size>@<base>:<irq>` を
    /// block → net の順で足す。戻り値の [`LoadedKernel`] を [`MicroVm::setup_boot_vcpu`]（#885）に渡す。
    /// 検証と配置の詳細は `crate::boot_x86`。
    pub fn load_kernel(
        &mut self,
        kernel: &[u8],
        initrd: Option<&[u8]>,
        user_cmdline: &str,
    ) -> Result<LoadedKernel, MicrovmError> {
        // REPAIR-4: 成功・失敗と所要時間を固定の操作名とエラーコードだけで 1 行出す。
        // 非信頼の cmdline・イメージ内容・エラー文言は記録しない（サイズは長さのみ）。
        let started = std::time::Instant::now();
        let result = self.load_kernel_inner(kernel, initrd, user_cmdline);
        let elapsed_us = started.elapsed().as_micros();
        // ログ出力の失敗（stderr が閉じている等）でロードの結果を失わないよう、書き込みエラーは捨てる。
        use std::io::Write as _;
        match &result {
            Ok(_) => drop(writeln!(
                std::io::stderr(),
                "level=info op=microvm.load_kernel outcome=ok elapsed_us={elapsed_us} kernel_len={} initrd_len={}",
                kernel.len(),
                initrd.map_or(0, <[u8]>::len)
            )),
            Err(e) => drop(writeln!(
                std::io::stderr(),
                "level=error op=microvm.load_kernel outcome=error code={} elapsed_us={elapsed_us} kernel_len={} initrd_len={}",
                e.code().as_str(),
                kernel.len(),
                initrd.map_or(0, <[u8]>::len)
            )),
        }
        result
    }

    /// [`MicroVm::load_kernel`] の本体（計装を含まない）。
    fn load_kernel_inner(
        &mut self,
        kernel: &[u8],
        initrd: Option<&[u8]>,
        user_cmdline: &str,
    ) -> Result<LoadedKernel, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            let params: Vec<VirtioMmioParam> = self
                .devices
                .infos()
                .iter()
                .map(|i| VirtioMmioParam {
                    base: i.slot.mmio_base,
                    len: i.slot.mmio_len,
                    gsi: i.slot.gsi,
                })
                .collect();
            let cmdline = KernelCmdline::new(user_cmdline, &params)?;
            load_linux(&mut self.memory, kernel, initrd, &cmdline)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (kernel, initrd, user_cmdline);
            Err(MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "kernel loading is only implemented for x86_64 (aarch64 FDT is not implemented)",
            ))
        }
    }

    /// vCPU 0（BSP）を、ロード済みカーネルのエントリから long mode で実行を始める状態に初期化する（TASK-75.3.2・MVM-1。
    /// x86_64 のみ、他 arch は `Unimplemented`）。
    ///
    /// 手順: `loaded` の各アドレスがこの VM のゲストメモリ内かを検証（別 VM の値の取り違えを拒否）→ [`BootCpuState::for_kernel`] →
    /// GDT・IDT・ページテーブル（GPA 0..4 GiB の恒等写像）の書き込み → `VcpuFd::set_boot_state` → 起動用 MSR（`set_msrs`）→ FPU（`set_fpu`。#3734）。最初の `VcpuFd::run_once` より前に、
    /// [`MicroVm::load_kernel`] の後で 1 回呼ぶ。in-kernel irqchip のある VM の AP（vCPU 1 以上）はレジスタを触らず（INIT/SIPI で起動する。#3737）、
    /// LAPIC の LINT だけを BSP と同じ経路で設定する。
    /// 実行ループは [`MicroVm::start`]（TASK-75.4.1・#886）。失敗時の解放はモジュール doc（#887）、MSR・FPU は本メソッドが設定し（CPUID は assemble が設定済み）、BSP の LAPIC の LINT は `VcpuFd::set_boot_lints`（#3735）。成功・失敗と所要時間は 1 行の構造化ログへ出す（REPAIR-4。入力値は載せない）。
    pub fn setup_boot_vcpu(&mut self, loaded: &LoadedKernel) -> Result<(), MicrovmError> {
        let started = std::time::Instant::now();
        let result = self.setup_boot_vcpu_inner(loaded);
        let elapsed_us = started.elapsed().as_micros();
        // ログ出力の失敗でセットアップの結果を失わないよう、書き込みエラーは捨てる。
        use std::io::Write as _;
        match &result {
            Ok(()) => drop(writeln!(
                std::io::stderr(),
                "level=info op=microvm.setup_boot_vcpu outcome=ok elapsed_us={elapsed_us}"
            )),
            Err(e) => drop(writeln!(
                std::io::stderr(),
                "level=error op=microvm.setup_boot_vcpu outcome=error code={} elapsed_us={elapsed_us}",
                e.code().as_str()
            )),
        }
        result
    }

    /// [`MicroVm::setup_boot_vcpu`] の本体（計装を含まない）。
    fn setup_boot_vcpu_inner(&mut self, loaded: &LoadedKernel) -> Result<(), MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            check_loaded_within(loaded, self.memory.len())?;
            let state = BootCpuState::for_kernel(loaded)?;
            let vcpu = self.vcpus.first_mut().ok_or_else(|| {
                MicrovmError::new(
                    MicrovmErrorCode::FailedPrecondition,
                    "microVM has no boot vCPU",
                )
            })?;
            write_boot_tables(&mut self.memory)?;
            vcpu.set_boot_state(&state)?;
            // CPUID（#3733）はこの MSR の設定より前に入れる（CPUID の機能ビットで受理される MSR が変わるため）。
            vcpu.set_msrs(&boot_msrs())?;
            vcpu.set_fpu(&X86FpuState::boot())?;
            vcpu.set_boot_lints()?;
            // AP は BSP と同じ経路で LINT を設定する。INIT が LVT をマスクへ戻すので、この設定が残るのは INIT までで、
            // LINT はゲストのカーネルが AP ごとに設定し直す（レジスタは INIT/SIPI で決まるため触らない。#3737）。
            for ap in self.vcpus.iter_mut().skip(1) {
                ap.set_boot_lints()?;
            }
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = loaded;
            Err(MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "boot register setup is only implemented for x86_64",
            ))
        }
    }

    /// AP の起動コードを SIPI のベクタが指すページへ書く（#3737・MVM-1・TASK-75.4。x86_64 のみ、他 arch は `Unimplemented`）。
    ///
    /// BSP のゲストコードが送る STARTUP IPI のベクタと同じ `vector` を渡す。置き場所は [`sipi_startup_range`] で検証してから書く
    /// （ブート用領域・RAM の外との重なりは書く前に `InvalidArgument`）。戻り値は書いた先頭の GPA。Linux ゲストは自分で
    /// trampoline を置くため、本メソッドはファームウェアの無い起動コードと試験のためのもの（e820 への予約は範囲外。REPAIR-3）。
    pub fn write_ap_startup_code(
        &mut self,
        vector: SipiVector,
        code: &[u8],
    ) -> Result<GuestAddress, MicrovmError> {
        // REPAIR-4: 成功・失敗と所要時間を固定の操作名とエラーコードだけで 1 行出す。コードの内容は記録しない。
        let started = std::time::Instant::now();
        let result = self.write_ap_startup_code_inner(vector, code);
        let elapsed_us = started.elapsed().as_micros();
        use std::io::Write as _;
        match &result {
            Ok(_) => drop(writeln!(
                std::io::stderr(),
                "level=info op=microvm.write_ap_startup_code outcome=ok elapsed_us={elapsed_us} code_len={}",
                code.len()
            )),
            Err(e) => drop(writeln!(
                std::io::stderr(),
                "level=error op=microvm.write_ap_startup_code outcome=error code={} elapsed_us={elapsed_us} code_len={}",
                e.code().as_str(),
                code.len()
            )),
        }
        result
    }

    /// [`MicroVm::write_ap_startup_code`] の本体（計装を含まない）。
    fn write_ap_startup_code_inner(
        &mut self,
        vector: SipiVector,
        code: &[u8],
    ) -> Result<GuestAddress, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            let (start, _end) = sipi_startup_range(vector, code.len(), self.memory.len())?;
            let addr = GuestAddress::new(start);
            self.memory.write_at(addr, code)?;
            Ok(addr)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (vector, code);
            Err(MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "AP startup is only implemented for x86_64",
            ))
        }
    }

    /// デバイスの配置と識別子（block → net の順）。
    pub fn devices(&self) -> Vec<DeviceInfo> {
        self.devices.infos()
    }

    /// `index` 番の virtio-block のトランスポートに `f` を適用する。範囲外は `InvalidArgument`、lock の poison は `Internal`。
    pub fn with_block<R>(
        &self,
        index: usize,
        f: impl FnOnce(&mut VirtioMmioTransport<VirtioBlock<B>>) -> R,
    ) -> Result<R, MicrovmError> {
        let dev = self
            .devices
            .block
            .get(index)
            .ok_or_else(|| invalid("block device index out of range"))?;
        let mut t = dev.transport.lock().map_err(|_| poisoned())?;
        Ok(f(&mut t))
    }

    /// `index` 番の virtio-net のトランスポートに `f` を適用する（エラーは [`MicroVm::with_block`] と同じ）。
    pub fn with_net<R>(
        &self,
        index: usize,
        f: impl FnOnce(&mut VirtioMmioTransport<VirtioNet<N>>) -> R,
    ) -> Result<R, MicrovmError> {
        let dev = self
            .devices
            .net
            .get(index)
            .ok_or_else(|| invalid("net device index out of range"))?;
        let mut t = dev.transport.lock().map_err(|_| poisoned())?;
        Ok(f(&mut t))
    }

    /// COM1 の UART の出力をホストが取り出すハンドル（clone）。ゲストの THR 出力（`console=ttyS0`）が溜まる。
    ///
    /// 上限つき（[`crate::uart::MAX_OUTPUT_BYTES`]）。中身は非信頼のゲスト出力なので、表示・記録時はエスケープすること。
    /// 未実装（REPAIR-3）: IRQ 4 とゲスト入力。
    pub fn serial_console(&self) -> SerialConsole {
        self.devices.serial.clone()
    }

    /// `vcpu_index` の vCPU が返した `Io` / `Mmio` exit を MMIO / PIO dispatcher（COM1 の UART を含む）へ振り分ける。範囲外の index は `InvalidArgument`。
    pub fn handle_exit(
        &mut self,
        vcpu_index: usize,
        exit: &VcpuExit,
    ) -> Result<DispatchOutcome, MicrovmError> {
        let vcpu = self
            .vcpus
            .get_mut(vcpu_index)
            .ok_or_else(|| invalid("vcpu index out of range"))?;
        vcpu.handle_exit(exit, &mut self.devices.dispatcher)
    }

    /// `id` のデバイスの `QueueNotify(queue)` を、この VM のゲストメモリと割り込み線で処理する。
    pub fn complete_queue_notify(
        &mut self,
        id: DeviceId,
        queue: u16,
    ) -> Result<QueueNotifyReport, MicrovmError> {
        self.devices
            .complete_queue_notify(id, queue, &mut self.memory)
    }
}

// ---- 起動と停止（TASK-75.4.1・#886・MVM-1） ----

/// vCPU スレッドが `VcpuFd::run_once` に渡す 1 回あたりの期限。停止要求は kick で即時に届くため、この間隔には依らない。
/// 期限切れは正常系（in-kernel irqchip の VM は HLT をユーザー空間へ出さず `KVM_RUN` の中で待つ）として継続する。
pub const VCPU_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// 受信ポーラー（`NetRxPoller`）が backend のフレームを確かめる周期（#3742・MVM-1・REPAIR-5）。値は暫定。
///
/// `NetBackend::recv` は待たない API で到着通知を持たないため、周期で取り出す。受信遅延の上限になるので
/// [`VCPU_POLL_INTERVAL`] より短くし、busy loop にしないため下限は 1ms（`NET_RX_POLL_INTERVAL_MIN`）。待ちは停止要求で即座に起きる。
pub const NET_RX_POLL_INTERVAL: Duration = Duration::from_millis(10);
/// 受信ポーラーの周期の下限（0 による busy loop を防ぐ）。
const NET_RX_POLL_INTERVAL_MIN: Duration = Duration::from_millis(1);
/// 受信ポーラーの周期の上限（無期限に近い周期で受信が止まるのを防ぐ）。
const NET_RX_POLL_INTERVAL_MAX: Duration = Duration::from_secs(1);
/// [`RunningMicroVm::stop`] の期限の上限（異常な値で実質無期限になるのを防ぐ。REPAIR-5）。
pub const STOP_DEADLINE_MAX: Duration = Duration::from_secs(60);
/// [`RunningMicroVm`] が `stop` を経ずに drop されたときに、vCPU スレッドの終了を待つ上限。
const DROP_STOP_WAIT: Duration = Duration::from_secs(5);

pub use crate::stop::StopReason;

/// 全 vCPU ループの終了報告。最後の vCPU スレッドが `MicroVm` の部品（fd・mmap・irqfd）を解放し終えた後に送られる（#3738）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StopReport {
    /// VM 全体の終了理由。最初に `Requested` 以外で終わった vCPU の理由で、無ければ `Requested`。
    pub reason: StopReason,
    /// 全 vCPU の累積の実行統計の合計。
    pub stats: RunStats,
    /// `start` からループ終了までの時間。
    pub elapsed: Duration,
    /// 動かした vCPU スレッドの数。
    pub vcpu_count: u32,
    /// 終了のきっかけになった vCPU の番号（`Requested` なら `None`）。`None` で理由が `Requested` 以外なら、vCPU 以外（virtio-net の受信ポーラー。#3742）がきっかけ。
    pub origin_vcpu: Option<u32>,
}

/// 1 回の `run_once` の結果の分類（純粋関数 [`classify_run`] の戻り値）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunClass {
    /// 続けて次の `run_once` へ。
    Continue,
    /// `Io` / `Mmio`。dispatcher へ渡す。
    Dispatch,
    /// ループを終える。
    Finish(StopReason),
}

/// `run_once` の結果をループの次の動作に分類する。期限切れ・中断は正常系。ゲスト由来の異常は fail-closed で終える。
fn classify_run(r: &Result<VcpuExit, MicrovmError>) -> RunClass {
    match r {
        Ok(VcpuExit::Interrupted) => RunClass::Continue,
        Ok(VcpuExit::Io { .. } | VcpuExit::Mmio { .. }) => RunClass::Dispatch,
        Ok(VcpuExit::Shutdown) => RunClass::Finish(StopReason::GuestShutdown),
        Ok(VcpuExit::Hlt) => RunClass::Finish(StopReason::GuestHalted),
        Ok(VcpuExit::FailEntry { .. } | VcpuExit::InternalError { .. }) => {
            RunClass::Finish(StopReason::Failed(MicrovmErrorCode::Internal))
        }
        Ok(VcpuExit::Other { .. }) => {
            RunClass::Finish(StopReason::Failed(MicrovmErrorCode::Unimplemented))
        }
        Err(e) if e.code() == MicrovmErrorCode::DeadlineExceeded => RunClass::Continue,
        Err(e) => RunClass::Finish(StopReason::Failed(e.code())),
    }
}

/// dispatcher の結果が virtqueue の通知なら `(デバイス, キュー)` を返す（呼び出し元が `complete_queue_notify` へつなぐ）。
fn queue_notify_of(outcome: &DispatchOutcome) -> Option<(DeviceId, u16)> {
    match outcome {
        DispatchOutcome::Mmio {
            device,
            access: MmioAccess::Write(MmioWriteOutcome::QueueNotify(q)),
        } => Some((*device, *q)),
        _ => None,
    }
}

/// vCPU ループの 1 歩の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopStep {
    Continue,
    Finish(StopReason),
}

/// vCPU スレッドが駆動する対象。実体は [`VcpuWorker`]（1 台の vCPU と共有部）。KVM なしでループの契約（停止・後始末の順序）を試験するための継ぎ目。
trait VcpuLoopBody: Send + 'static {
    /// 最大 `slice` だけ実行し、exit を処理して次の動作を返す。
    /// `stop` は `RunningMicroVm` からの停止信号で、実行中の `KVM_RUN` を中断するために `run_once_with_stop` へ渡す。
    fn step(&mut self, slice: Duration, stop: &StopSignal) -> LoopStep;
    /// この vCPU の累積統計。
    fn stats(&self) -> RunStats;
}

/// `start` 後に全 vCPU スレッドが共有する VM の部品（#3738・MVM-1）。`Arc<Mutex<_>>` で持ち、exit 処理（デバイスの dispatch と
/// 通知の完了）を 1 つの lock で直列にする。デバイス単位の並行は範囲外（REPAIR-3）。
///
/// フィールドの宣言順が drop 順（デバイス → メモリ → VM fd）。最後のスレッド（vCPU か受信ポーラー）が `Arc` を落としたときに、
/// 全 `VcpuFd` が解放済みの状態でこの順に解放される（モジュール doc の「vCPU → デバイス → メモリ → VM fd」を保つ）。
struct VmShared<B: BlockBackend, N: NetBackend> {
    devices: DeviceBus<B, N, IrqFd>,
    memory: GuestMemory<RegisteredGuestRam>,
    /// 読まない。memslot・irqfd より後に VM fd を閉じる drop 順を保つために持つ。
    _vm: VmFd,
}

/// 1 台の vCPU とその共有部への参照。vCPU スレッドが所有する（`VcpuFd` が先、共有部の参照が後に drop される）。
struct VcpuWorker<B: BlockBackend, N: NetBackend> {
    vcpu: VcpuFd,
    shared: Arc<Mutex<VmShared<B, N>>>,
}

/// `Io` / `Mmio` exit を共有部のデバイスへ振り分け、virtqueue の通知なら完了まで処理する。
/// 失敗は fail-closed で `Finish` にする（lock の poison を含む）。
fn dispatch_exit<B: BlockBackend + Send + 'static, N: NetBackend + Send + 'static>(
    vcpu: &mut VcpuFd,
    shared: &Mutex<VmShared<B, N>>,
    exit: &VcpuExit,
) -> LoopStep {
    let Ok(mut guard) = shared.lock() else {
        return LoopStep::Finish(StopReason::Failed(poisoned().code()));
    };
    let g = &mut *guard;
    let outcome = match vcpu.handle_exit(exit, &mut g.devices.dispatcher) {
        Ok(o) => o,
        Err(e) => return LoopStep::Finish(StopReason::Failed(e.code())),
    };
    // 通知の完了に失敗したまま続けると、通知の届かないゲストがハングするため止める（fail-closed）。
    // リング破損などは外側の `Err` ではなく report.queue_error に入り last_avail も進まないため、
    // 続行するとゲストが完了しない要求を待ち続ける。呼び出し元（ここ）が停止を判断する。
    if let Some((id, queue)) = queue_notify_of(&outcome) {
        match g.devices.complete_queue_notify(id, queue, &mut g.memory) {
            Err(e) => return LoopStep::Finish(StopReason::Failed(e.code())),
            Ok(report) => {
                if let Some(e) = report.queue_error() {
                    return LoopStep::Finish(StopReason::Failed(e.code()));
                }
            }
        }
    }
    LoopStep::Continue
}

impl<B: BlockBackend + Send + 'static, N: NetBackend + Send + 'static> VcpuLoopBody
    for VcpuWorker<B, N>
{
    fn step(&mut self, slice: Duration, stop: &StopSignal) -> LoopStep {
        let result = self.vcpu.run_once_with_stop(slice, stop);
        match classify_run(&result) {
            RunClass::Continue => LoopStep::Continue,
            RunClass::Finish(reason) => LoopStep::Finish(reason),
            RunClass::Dispatch => {
                let Ok(exit) = result else {
                    return LoopStep::Finish(StopReason::Failed(MicrovmErrorCode::Internal));
                };
                dispatch_exit(&mut self.vcpu, &self.shared, &exit)
            }
        }
    }

    fn stats(&self) -> RunStats {
        self.vcpu.stats()
    }
}

/// 受信ポーラーの対象（継ぎ目）。実体は [`VmShared`]。KVM なしでポーラーの契約を試験するためのトレイト。
trait NetRxPollTarget: Send + 'static {
    /// 全 virtio-net の受信を 1 回処理する（[`DeviceBus::poll_net_rx`]）。
    fn poll_net_rx(&mut self) -> Result<NetRxPollReport, MicrovmError>;
}

impl<B: BlockBackend + Send + 'static, N: NetBackend + Send + 'static> NetRxPollTarget
    for VmShared<B, N>
{
    fn poll_net_rx(&mut self) -> Result<NetRxPollReport, MicrovmError> {
        self.devices.poll_net_rx(&mut self.memory)
    }
}

/// ゲストの kick なしで virtio-net の受信を処理する専用スレッド `microvm-net-rx` の本体（#3742・MVM-1・REPAIR-5）。
///
/// # 経路の選択と理由
/// vCPU ループの中ではなく**専用スレッド**にした。
/// - in-kernel irqchip ではゲストの HLT が `KVM_RUN` の中で待たれ [`VCPU_POLL_INTERVAL`] まで戻らない。vCPU ループ内でポーリングすると
///   受信遅延が最大でその間隔になり、vCPU 0 のスケジューリングにも縛られる。別スレッドなら irqfd の注入で HLT 中の vCPU を起こせる。
/// - 「`stop` が `Ok` で戻った時点で fd・mmap・irqfd 解放済み」の契約は、共有部の最後の `Arc` を持つスレッドが [`StopAggregate`] に
///   数えられていることに依る。ポーラーも同じ機構（`spawn_loops_gated` の補助スレッド）の参加者にして、停止・panic・drop・spawn 失敗の
///   後始末を共有する。
/// - 却下: backend の到着通知（fd の poll）。`NetBackend` にその API が無く実 backend（TAP）も未定のため将来仕様（TASK-75・TASK-117。
///   REPAIR-3）。TAP を導入したら通知へ置き換えを検討する。
///
/// # 契約
/// 1 周期ごとに [`StopSignal::wait_requested`] で期限つきに待ち（停止要求で即起きる。REPAIR-5）、共有部の lock → トランスポートの
/// lock の順（vCPU の `dispatch_exit` と同じ）で [`NetRxPollTarget::poll_net_rx`] を呼ぶ。1 回の処理量はデバイス数 × キュー長で頭打ち。
/// リング破損・lock の poison・割り込み線の失敗は fail-closed で `Finish(Failed)` にし、全スレッドを止める。
struct NetRxPoller<S: NetRxPollTarget> {
    shared: Arc<Mutex<S>>,
    interval: Duration,
}

impl<S: NetRxPollTarget> NetRxPoller<S> {
    /// `interval` を `[NET_RX_POLL_INTERVAL_MIN, NET_RX_POLL_INTERVAL_MAX]` に検証して作る（範囲外は `InvalidArgument`）。
    fn new(shared: Arc<Mutex<S>>, interval: Duration) -> Result<Self, MicrovmError> {
        if !(NET_RX_POLL_INTERVAL_MIN..=NET_RX_POLL_INTERVAL_MAX).contains(&interval) {
            return Err(invalid("net rx poll interval out of range"));
        }
        Ok(Self { shared, interval })
    }
}

impl<S: NetRxPollTarget> VcpuLoopBody for NetRxPoller<S> {
    fn step(&mut self, _slice: Duration, stop: &StopSignal) -> LoopStep {
        if stop.wait_requested(self.interval) {
            return LoopStep::Continue;
        }
        let result = match self.shared.lock() {
            Ok(mut g) => g.poll_net_rx(),
            Err(_) => Err(poisoned()),
        };
        let err = match result {
            Ok(report) => match report.queue_error {
                None => return LoopStep::Continue,
                Some(e) => e,
            },
            Err(e) => e,
        };
        log_line(format_args!(
            "level=error op=microvm.net_rx_poll outcome=error code={}",
            err.code().as_str()
        ));
        LoopStep::Finish(StopReason::Failed(err.code()))
    }

    fn stats(&self) -> RunStats {
        RunStats::default()
    }
}

impl VcpuLoopBody for Box<dyn VcpuLoopBody> {
    fn step(&mut self, slice: Duration, stop: &StopSignal) -> LoopStep {
        (**self).step(slice, stop)
    }

    fn stats(&self) -> RunStats {
        (**self).stats()
    }
}

/// vCPU 以外の補助スレッド（受信ポーラー）。集約（[`StopAggregate`]）の参加者として vCPU と同じ機構で起動・停止・回収する。
struct AuxThread {
    name: &'static str,
    body: Box<dyn VcpuLoopBody>,
}

/// 構造化ログを 1 行 stderr へ出す（書き込みの失敗は捨てる。REPAIR-4）。
fn log_line(args: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    drop(writeln!(std::io::stderr(), "{args}"));
}

/// 全 vCPU スレッドの終了の集約状態。
#[derive(Debug)]
struct AggState {
    /// まだ終わっていないスレッド数。0 になったスレッドが確定処理をする。
    remaining: usize,
    /// 最初に記録された `Requested` 以外の終了理由と、そのきっかけの vCPU 番号。
    reason: Option<(StopReason, Option<u32>)>,
    /// 終わったスレッドの統計の合計。
    stats: RunStats,
    /// panic の unwind などで正常に終われなかったスレッドがあった。
    abnormal: bool,
    /// 確定時に 1 回だけ報告を送る送信側（異常終了では送らずに閉じる）。
    sender: Option<mpsc::Sender<StopReport>>,
}

/// 全 vCPU スレッドの終了を 1 つの [`StopReport`] に集約する（#3738・MVM-1・REPAIR-5）。
///
/// 全スレッドが同じ `Arc<StopSignal>` を共有するので、1 台が `Requested` 以外で終わったら `stop.request()` で全台を止める
/// （1 台だけ走り続ける状態を作らない。fail-closed）。確定は最後のスレッドが、自分の body（最後なら共有部）を解放した後に行う。
struct StopAggregate {
    state: Mutex<AggState>,
    exit: Arc<ExitCell>,
    stop: Arc<StopSignal>,
    started: Instant,
    vcpu_count: u32,
}

fn add_stats(a: &mut RunStats, b: &RunStats) {
    a.runs = a.runs.saturating_add(b.runs);
    a.exits = a.exits.saturating_add(b.exits);
    a.interrupted = a.interrupted.saturating_add(b.interrupted);
    a.deadline_exceeded = a.deadline_exceeded.saturating_add(b.deadline_exceeded);
    a.errors = a.errors.saturating_add(b.errors);
    a.total_elapsed = a.total_elapsed.saturating_add(b.total_elapsed);
}

impl StopAggregate {
    /// 状態は単純な値で、panic 中に壊れる不変条件が無い。poison でも中身を使う。
    fn lock(&self) -> std::sync::MutexGuard<'_, AggState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `Requested` 以外の終了を記録し（先勝ち）、全台へ停止を要求する。body の解放より前に呼ぶ。
    fn note_finish(&self, reason: StopReason, index: Option<u32>) {
        if reason == StopReason::Requested {
            return;
        }
        {
            let mut st = self.lock();
            if st.reason.is_none() {
                st.reason = Some((reason, index));
            }
        }
        self.stop.request();
    }

    /// 1 スレッドの終了を計上する。最後の 1 本なら集約した報告を確定して記録・送信する（解放の後に記録する順序を保つ）。
    fn complete_one(&self, stats: RunStats, abnormal: bool) {
        let fin = {
            let mut st = self.lock();
            add_stats(&mut st.stats, &stats);
            st.abnormal |= abnormal;
            st.remaining = st.remaining.saturating_sub(1);
            if st.remaining == 0 {
                Some((st.reason, st.stats, st.abnormal, st.sender.take()))
            } else {
                None
            }
        };
        let Some((reason, mut stats, abnormal, sender)) = fin else {
            return;
        };
        if abnormal {
            log_line(format_args!(
                "level=error op=microvm.vcpus_stopped outcome=error code={} vcpus={}",
                MicrovmErrorCode::Internal.as_str(),
                self.vcpu_count
            ));
            self.exit.mark_abnormal_if_running();
            drop(sender);
            return;
        }
        let (stop_reason, origin_vcpu) = match reason {
            Some((r, i)) => (r, i),
            None => (StopReason::Requested, None),
        };
        // dispatch・通知完了・割り込み配送の失敗は vCPU の統計に載らないため、失敗終了なら最低 1 件を計上する。
        if matches!(stop_reason, StopReason::Failed(_)) && stats.errors == 0 {
            stats.errors = 1;
        }
        let elapsed = self.started.elapsed();
        let (level, outcome, code) = match stop_reason {
            StopReason::Failed(c) => ("error", "error", format!(" code={}", c.as_str())),
            _ => ("info", "ok", String::new()),
        };
        log_line(format_args!(
            "level={level} op=microvm.vcpus_stopped outcome={outcome} reason={}{code} vcpus={} runs={} exits={} errors={} elapsed_us={}",
            stop_reason.as_str(),
            self.vcpu_count,
            stats.runs,
            stats.exits,
            stats.errors,
            elapsed.as_micros()
        ));
        let report = StopReport {
            reason: stop_reason,
            stats,
            elapsed,
            vcpu_count: self.vcpu_count,
            origin_vcpu,
        };
        self.exit.complete(report);
        // 受け手（RunningMicroVm）が既に無ければ送信は失敗するが、解放は済んでいるので捨てる。
        if let Some(tx) = sender {
            let _ = tx.send(report);
        }
    }
}

/// vCPU スレッドのクロージャが持つ guard。正常に `finish` せず drop された（panic の unwind）ら、全台を止めて異常終了として計上する。
struct VcpuThreadGuard {
    agg: Arc<StopAggregate>,
    /// vCPU 番号。補助スレッド（受信ポーラー）は `None`。
    index: Option<u32>,
    done: std::cell::Cell<bool>,
}

impl VcpuThreadGuard {
    fn new(agg: Arc<StopAggregate>, index: Option<u32>) -> Self {
        VcpuThreadGuard {
            agg,
            index,
            done: std::cell::Cell::new(false),
        }
    }

    /// body の解放後に呼ぶ。統計を渡して自分の終了を計上する。
    fn finish(&self, stats: RunStats) {
        self.done.set(true);
        self.agg.complete_one(stats, false);
    }
}

impl Drop for VcpuThreadGuard {
    fn drop(&mut self) {
        if !self.done.get() {
            self.agg.stop.request();
            self.agg.complete_one(RunStats::default(), true);
        }
    }
}

/// vCPU スレッドの本体。停止要求・ゲスト起因の終了のどちらでも、`body`（`VcpuWorker`。最後の 1 台なら共有部も）を drop して
/// fd・mmap・irqfd を解放してから終了を計上する。この順序が「`stop` が `Ok` で戻った時点で解放済み」という契約の根拠。
/// `Requested` 以外で抜けたときは、解放より先に全台へ停止を要求する（1 台の終了で全台を止める。#3738）。
fn vcpu_loop<T: VcpuLoopBody>(mut body: T, guard: &VcpuThreadGuard) {
    let stop = Arc::clone(&guard.agg.stop);
    let reason = loop {
        if stop.is_requested() {
            break StopReason::Requested;
        }
        match body.step(VCPU_POLL_INTERVAL, &stop) {
            LoopStep::Continue => {}
            LoopStep::Finish(r) => break r,
        }
    };
    guard.agg.note_finish(reason, guard.index);
    let stats = body.stats();
    // 後始末（vCPU → デバイス → メモリ → VM fd の順）を、計上より先に済ませる。
    drop(body);
    let (level, outcome, code) = match reason {
        StopReason::Failed(c) => ("error", "error", format!(" code={}", c.as_str())),
        _ => ("info", "ok", String::new()),
    };
    let who = match guard.index {
        Some(i) => format!("op=microvm.vcpu_loop outcome={outcome} vcpu={i}"),
        None => format!("op=microvm.net_rx_loop outcome={outcome}"),
    };
    log_line(format_args!(
        "level={level} {who} reason={}{code} runs={} exits={} deadline_exceeded={} errors={} elapsed_us={}",
        reason.as_str(),
        stats.runs,
        stats.exits,
        stats.deadline_exceeded,
        stats.errors,
        guard.agg.started.elapsed().as_micros()
    ));
    guard.finish(stats);
}

/// スレッド生成の失敗を分類する（EAGAIN・ENOMEM は資源枯渇、それ以外は内部エラー。メッセージは固定文言と errno だけ）。
///
/// 生成に失敗したとき `body`（`MicroVm`）は std がクロージャごと drop するので、fd・mmap は解放される（#887）。
fn classify_spawn_error(e: &std::io::Error) -> MicrovmError {
    match e.raw_os_error() {
        Some(errno @ (EAGAIN | ENOMEM)) => MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            format!("cannot spawn vCPU thread (errno {errno})"),
        ),
        Some(errno) => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("cannot spawn vCPU thread (errno {errno})"),
        ),
        None => MicrovmError::new(MicrovmErrorCode::Internal, "cannot spawn vCPU thread"),
    }
}

/// vCPU スレッド数を検証する（確保・生成の前に呼ぶ。`1..=MAX_VCPUS`。#3738・REPAIR-5。非信頼の構成による無制限確保を防ぐ）。
fn validate_vcpu_threads(n: usize) -> Result<u32, MicrovmError> {
    match u32::try_from(n) {
        Ok(v) if (1..=MAX_VCPUS).contains(&v) => Ok(v),
        _ => Err(invalid("vcpu count out of range")),
    }
}

/// 全 vCPU スレッドの生成が終わるまでゲスト実行を始めさせない起動ゲート（#3738・REPAIR-4・REPAIR-5）。
///
/// 生成途中の失敗でも、生成済みスレッドは一度もゲストを実行していないので、停止要求を立ててゲートを開ければ
/// `step` を呼ばずに body を drop して確実に回収できる（回収未完了の資源を `Err` の外へ残さない）。
struct StartGate {
    open: Mutex<bool>,
    cv: Condvar,
    /// 待ちの上限（本番は [`START_GATE_WAIT`]。試験で短くする）。
    wait_limit: Duration,
}

/// ゲート待ちの上限（呼び出し側が必ず開けるので通常は到達しない。到達したスレッドは全台へ停止を要求し、
/// ゲスト実行へ進まず body を drop して異常終了として計上する。無限待ちも未生成のままの実行も作らない）。
const START_GATE_WAIT: Duration = Duration::from_secs(30);

impl StartGate {
    fn new(wait_limit: Duration) -> Self {
        StartGate {
            open: Mutex::new(false),
            cv: Condvar::new(),
            wait_limit,
        }
    }

    fn release(&self) {
        *self.open.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.cv.notify_all();
    }

    /// ゲートが開いたら `true`、期限切れなら `false`（期限切れのスレッドはゲスト実行へ進んではならない）。
    fn wait(&self) -> bool {
        let limit = Instant::now() + self.wait_limit;
        let mut g = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        while !*g {
            let left = limit.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            g = self
                .cv
                .wait_timeout(g, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }
}

/// drop で必ずゲートを開ける。生成済みの `handles` もここが持ち、spawn ループ中の panic（unwind）では
/// ゲートを開く前に停止を要求し、生成済みスレッドが 1 step も実行せず終わるのを期限つきで回収する
/// （detach して誰も止めないゲスト実行を残さない。REPAIR-5・MVM-1・#3738）。
struct GateRelease {
    gate: Arc<StartGate>,
    stop: Arc<StopSignal>,
    handles: Vec<JoinHandle<()>>,
}

impl Drop for GateRelease {
    fn drop(&mut self) {
        let unwinding = thread::panicking();
        if unwinding {
            // 停止要求を先に立ててからゲートを開ける（Err 経路と同じ順序）。
            self.stop.request();
        }
        self.gate.release();
        if unwinding {
            let limit = Instant::now() + DROP_STOP_WAIT;
            if join_all(std::mem::take(&mut self.handles), limit).timed_out {
                log_line(format_args!(
                    "level=error op=microvm.spawn_unwind outcome=error code={}",
                    MicrovmErrorCode::DeadlineExceeded.as_str()
                ));
            }
        }
    }
}

/// 生成するスレッドの本体（試験で生成を差し替えるための型）。
type VcpuJob = Box<dyn FnOnce() + Send + 'static>;

/// 各 `body` を専用スレッド（`microvm-vcpu-<index>`）で駆動して [`RunningMicroVm`] を返す。
fn spawn_loops<T: VcpuLoopBody>(
    bodies: Vec<T>,
    aux: Vec<AuxThread>,
    started: Instant,
    serial: SerialConsole,
) -> Result<RunningMicroVm, MicrovmError> {
    spawn_loops_gated(
        bodies,
        aux,
        started,
        serial,
        START_GATE_WAIT,
        |name, job| thread::Builder::new().name(name).spawn(job),
    )
}

/// [`spawn_loops_gated`] を本番のゲート待ち上限で呼ぶ（試験で生成を差し替える入口）。
#[cfg(test)]
fn spawn_loops_with<T, S>(
    bodies: Vec<T>,
    started: Instant,
    serial: SerialConsole,
    spawn: S,
) -> Result<RunningMicroVm, MicrovmError>
where
    T: VcpuLoopBody,
    S: FnMut(String, VcpuJob) -> std::io::Result<JoinHandle<()>>,
{
    spawn_loops_gated(bodies, Vec::new(), started, serial, START_GATE_WAIT, spawn)
}

/// [`spawn_loops_with`] の補助スレッドつき版（受信ポーラーの試験用）。
#[cfg(test)]
fn spawn_loops_with_aux<T, S>(
    bodies: Vec<T>,
    aux: Vec<AuxThread>,
    started: Instant,
    serial: SerialConsole,
    spawn: S,
) -> Result<RunningMicroVm, MicrovmError>
where
    T: VcpuLoopBody,
    S: FnMut(String, VcpuJob) -> std::io::Result<JoinHandle<()>>,
{
    spawn_loops_gated(bodies, aux, started, serial, START_GATE_WAIT, spawn)
}

/// [`spawn_loops`] の本体。`spawn` はスレッド生成（試験でだけ失敗を注入する）。`gate_wait` は起動ゲートの待ち上限。
///
/// `aux`（受信ポーラー等）は vCPU の後に生成し、vCPU と同じ集約・起動ゲート・ロールバックに参加する。台数の検証と
/// [`StopReport::vcpu_count`] は vCPU 数だけを数える（#3742）。
///
/// 数を検証してから確保する。k 本目の生成が失敗したら、全台へ停止を要求し、生成済みを 1 つの期限（[`DROP_STOP_WAIT`]）で
/// 回収してから失敗を返す。未生成の `body` と失敗した job は drop される（fd・mmap は解放される。#887）。
fn spawn_loops_gated<T, S>(
    bodies: Vec<T>,
    aux: Vec<AuxThread>,
    started: Instant,
    serial: SerialConsole,
    gate_wait: Duration,
    mut spawn: S,
) -> Result<RunningMicroVm, MicrovmError>
where
    T: VcpuLoopBody,
    S: FnMut(String, VcpuJob) -> std::io::Result<JoinHandle<()>>,
{
    let count = validate_vcpu_threads(bodies.len())?;
    let stop = Arc::new(StopSignal::new());
    let exit = Arc::new(ExitCell::new());
    let (tx, rx) = mpsc::channel();
    let agg = Arc::new(StopAggregate {
        state: Mutex::new(AggState {
            remaining: bodies.len() + aux.len(),
            reason: None,
            stats: RunStats::default(),
            abnormal: false,
            sender: Some(tx),
        }),
        exit: Arc::clone(&exit),
        stop: Arc::clone(&stop),
        started,
        vcpu_count: count,
    });
    let gate = Arc::new(StartGate::new(gate_wait));
    let mut release = GateRelease {
        gate: Arc::clone(&gate),
        stop: Arc::clone(&stop),
        handles: Vec::with_capacity(bodies.len() + aux.len()),
    };
    // vCPU → 補助の順に、(スレッド名, vCPU 番号, body) を遅延して作る（未生成の body は失敗時にまとめて drop される）。
    let vcpu_entries = bodies.into_iter().enumerate().map(|(i, body)| {
        let index = u32::try_from(i).unwrap_or(u32::MAX);
        let boxed: Box<dyn VcpuLoopBody> = Box::new(body);
        (format!("microvm-vcpu-{index}"), Some(index), boxed)
    });
    let aux_entries = aux.into_iter().map(|a| (a.name.to_string(), None, a.body));
    for (name, index, body) in vcpu_entries.chain(aux_entries) {
        let thread_gate = Arc::clone(&gate);
        let guard = VcpuThreadGuard::new(Arc::clone(&agg), index);
        // panic の unwind でも計上を残す。`body` は `vcpu_loop` のフレームが所有するため、unwind では
        // `body` の drop がこの guard の drop より先に走り、「解放後に計上」の順序が正常・panic の両経路で成り立つ。
        let job: VcpuJob = Box::new(move || {
            let guard = guard;
            if thread_gate.wait() {
                vcpu_loop(body, &guard);
            } else {
                // 期限切れ: 全台の生成完了前にゲストを実行しない。全台へ停止を要求し、body を先に解放してから
                // guard の drop が異常終了として計上する（REPAIR-4・REPAIR-5）。
                guard.agg.stop.request();
                drop(body);
                log_line(format_args!(
                    "level=error op=microvm.start_gate outcome=error code={}",
                    MicrovmErrorCode::DeadlineExceeded.as_str()
                ));
            }
        });
        match spawn(name, job) {
            Ok(h) => release.handles.push(h),
            Err(e) => {
                // 停止要求を先に立ててからゲートを開ける。生成済みスレッドは 1 step も実行せず body を drop して終わる。
                stop.request();
                let handles = std::mem::take(&mut release.handles);
                drop(release);
                let limit = Instant::now() + DROP_STOP_WAIT;
                if join_all(handles, limit).timed_out {
                    log_line(format_args!(
                        "level=error op=microvm.spawn_rollback outcome=error code={}",
                        MicrovmErrorCode::DeadlineExceeded.as_str()
                    ));
                }
                return Err(classify_spawn_error(&e));
            }
        }
    }
    let handles = std::mem::take(&mut release.handles);
    drop(release);
    Ok(RunningMicroVm {
        exit,
        stop,
        done_rx: rx,
        handles,
        serial,
    })
}

/// 起動中の microVM（vCPU ごとのスレッドを持つ）。[`MicroVm::start`] が返す。
///
/// 停止は [`RunningMicroVm::stop`]。呼び忘れても drop が期限つきで停止を要求して回収する（fd のリークを防ぐ）。
/// 停止要求は `StopSignal` を立て、実行中の `KVM_RUN` の監視スレッドが `immediate_exit` と kick で即時に中断する
/// （#3736・MVM-1・REPAIR-5）。停止の遅延の上限は exit 処理 1 回分で、[`VCPU_POLL_INTERVAL`] には依らない。
/// 所有関係: 本型が持つのは `Arc<StopSignal>` だけでスレッド識別子は持たず、kick を出すのは `KVM_RUN` 1 回分の間だけ
/// 生きる監視スレッドのみ。vCPU スレッドが終わった後の停止要求はシグナルを送らない。
///
/// 全 vCPU スレッドが 1 つの `StopSignal` を共有するので、停止要求は全台へ届く。1 台が `Requested` 以外（ゲストのシャットダウン・
/// exit 処理の失敗・panic）で終わったときも全台を止める（fail-closed。#3738）。`stop`・drop の待ちは全スレッドへ 1 つの期限を当てる。
///
/// 範囲外（REPAIR-3）: 一時停止（pause）。
#[derive(Debug)]
pub struct RunningMicroVm {
    exit: Arc<ExitCell>,
    stop: Arc<StopSignal>,
    done_rx: mpsc::Receiver<StopReport>,
    handles: Vec<JoinHandle<()>>,
    serial: SerialConsole,
}

impl RunningMicroVm {
    /// COM1 の UART の出力を取り出すハンドル（clone）。
    ///
    /// vCPU スレッドが `MicroVm` を drop した後も clone がバッファを保持する。[`RunningMicroVm::stop`] は自身を
    /// 消費するので、停止後に取り出したい呼び出し元は事前にこのハンドルを取っておくこと。停止の報告は vCPU スレッドの
    /// 送信完了後なので、`stop` が `Ok` で戻れば停止までの出力は欠けない。中身は非信頼のゲスト出力（表示・記録時はエスケープ）。
    pub fn serial_console(&self) -> SerialConsole {
        self.serial.clone()
    }

    /// 停止を要求し、`deadline` 以内に vCPU スレッドが終わって資源（VM fd・vCPU fd・memslot・mmap・irqfd）が解放されるのを待つ。
    ///
    /// `Ok` で戻った時点で、スレッドは join 済みで `MicroVm` は drop 済み。ゲスト起因で既に終わっていた場合は
    /// その理由（[`StopReason::GuestShutdown`] 等）を返す。`deadline` が 0 または [`STOP_DEADLINE_MAX`] 超なら `InvalidArgument`
    /// （この場合も drop が回収する）。期限切れは `DeadlineExceeded`（停止フラグは立ったままで、スレッドは後で自力で終わる）。
    pub fn stop(mut self, deadline: Duration) -> Result<StopReport, MicrovmError> {
        let started = Instant::now();
        let result = self.stop_inner(deadline);
        let elapsed_us = started.elapsed().as_micros();
        match &result {
            Ok(r) => log_line(format_args!(
                "level=info op=microvm.stop outcome=ok reason={} elapsed_us={elapsed_us}",
                r.reason.as_str()
            )),
            Err(e) => log_line(format_args!(
                "level=error op=microvm.stop outcome=error code={} elapsed_us={elapsed_us}",
                e.code().as_str()
            )),
        }
        result
    }

    fn stop_inner(&mut self, deadline: Duration) -> Result<StopReport, MicrovmError> {
        if deadline.is_zero() || deadline > STOP_DEADLINE_MAX {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "stop deadline out of range",
            ));
        }
        let limit = Instant::now() + deadline;
        self.stop.request();
        match self.done_rx.recv_timeout(deadline) {
            Ok(report) => {
                // 報告後もスレッドローカルの destructor が未完了でありうるため、全スレッドの join に同じ期限を適用する。
                let joined = join_all(std::mem::take(&mut self.handles), limit);
                if joined.timed_out {
                    Err(MicrovmError::new(
                        MicrovmErrorCode::DeadlineExceeded,
                        "vCPU thread did not finish within deadline",
                    ))
                } else if joined.panicked {
                    Err(MicrovmError::new(
                        MicrovmErrorCode::Internal,
                        "vCPU thread terminated abnormally",
                    ))
                } else {
                    Ok(report)
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // 期限の無い join はしない（REPAIR-5）。全スレッドを detach し、スレッドは停止フラグで自力で終わる。
                self.handles.clear();
                Err(MicrovmError::new(
                    MicrovmErrorCode::DeadlineExceeded,
                    "vCPU thread did not stop within deadline",
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // 報告を送る前にチャネルが切れた（panic の unwind）。切断はスレッド終了を保証しない
                // （引数の drop 順で done が先に落ち、残りの Drop が続く）ため、join には期限を適用する。
                let timed_out = join_all(std::mem::take(&mut self.handles), limit).timed_out;
                if timed_out {
                    return Err(MicrovmError::new(
                        MicrovmErrorCode::DeadlineExceeded,
                        "vCPU thread did not finish within deadline",
                    ));
                }
                Err(MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    "vCPU thread terminated abnormally",
                ))
            }
        }
    }

    /// vCPU ループが既に終わったか（ゲスト起因の終了の観測用）。終わっていても資源の確定は [`RunningMicroVm::stop`] で報告を受ける。
    pub fn is_finished(&self) -> bool {
        self.handles.iter().all(JoinHandle::is_finished)
    }

    /// vCPU スレッドの終了を観測するハンドルの複製を返す（#3744・MVM-1・REPAIR-5）。
    ///
    /// [`RunningMicroVm::stop`] は `self` を消費し、期限切れ（`DeadlineExceeded`）ではスレッドを切り離すため、
    /// 期限切れの後に終了を知る手段は無い。`stop` や drop の**前**に取得しておけば、ハンドルはそれらの後も有効で、
    /// plugin-microvm の adapter が切り離した VM の計数枠を返してよいかの判定に使う（#3745）。
    pub fn exit_watch(&self) -> VcpuExitWatch {
        VcpuExitWatch {
            cell: Arc::clone(&self.exit),
        }
    }
}

impl Drop for RunningMicroVm {
    fn drop(&mut self) {
        if self.handles.is_empty() {
            return;
        }
        let handles = std::mem::take(&mut self.handles);
        self.stop.request();
        let limit = Instant::now() + DROP_STOP_WAIT;
        let expired = match self.done_rx.recv_timeout(DROP_STOP_WAIT) {
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => join_all(handles, limit).timed_out,
            Err(mpsc::RecvTimeoutError::Timeout) => true,
        };
        if expired {
            log_line(format_args!(
                "level=error op=microvm.drop_running outcome=error code={}",
                MicrovmErrorCode::DeadlineExceeded.as_str()
            ));
        }
    }
}

/// [`VcpuExitWatch`] が返す vCPU ループの終了状態（真偽値で返さない。拡張できる）。
///
/// 呼び出し側は `Running` 以外を「資源を解放済み」とみなしてよい（例外は [`VcpuExitWatch`] の doc を参照）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VcpuExitState {
    /// vCPU ループはまだ `MicroVm` を解放していない（未終了）。
    Running,
    /// 最後の vCPU スレッドが `MicroVm` の部品の解放（vCPU fd → デバイスの dispatcher・irqfd → メモリの memslot 削除と munmap → VM fd）を終えた。
    Exited(StopReport),
    /// vCPU スレッドが panic で unwind した。`MicroVm` は unwind で解放済みで、終了済みとして扱える。
    ExitedAbnormally,
}

/// 終了状態の共有セル。vCPU スレッドが書き、[`VcpuExitWatch`] が期限つきで待つ。
#[derive(Debug)]
struct ExitCell {
    state: Mutex<VcpuExitState>,
    changed: Condvar,
}

impl ExitCell {
    fn new() -> Self {
        ExitCell {
            state: Mutex::new(VcpuExitState::Running),
            changed: Condvar::new(),
        }
    }

    /// 状態は単純な値で、panic 中に壊れる不変条件が無い。poison でも中身を読む（`Running` 扱いで枠を返さないより正確）。
    fn lock(&self) -> std::sync::MutexGuard<'_, VcpuExitState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set_if_running(&self, next: VcpuExitState) {
        let mut st = self.lock();
        if *st == VcpuExitState::Running {
            *st = next;
            self.changed.notify_all();
        }
    }

    /// 正常経路の記録。既に記録済みなら上書きしない。
    fn complete(&self, report: StopReport) {
        self.set_if_running(VcpuExitState::Exited(report));
    }

    /// 未記録なら異常終了として記録する（`Exited` は上書きしない）。
    fn mark_abnormal_if_running(&self) {
        self.set_if_running(VcpuExitState::ExitedAbnormally);
    }

    fn state(&self) -> VcpuExitState {
        *self.lock()
    }

    /// `limit` まで状態の変化を待つ（spurious wakeup は残り時間を再計算して吸収する）。期限切れは `Running`。
    fn wait_until(&self, limit: Instant) -> VcpuExitState {
        let mut st = self.lock();
        while *st == VcpuExitState::Running {
            let now = Instant::now();
            if now >= limit {
                break;
            }
            st = self
                .changed
                .wait_timeout(st, limit - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        *st
    }
}

/// 切り離した vCPU スレッドの終了を期限つきで観測するハンドル（#3744・MVM-1・REPAIR-5。[`RunningMicroVm::exit_watch`]）。
///
/// `Arc` の複製で、[`RunningMicroVm`] の `stop`・drop の後も独立に生きる。`stop` が `DeadlineExceeded` で戻ったあと
/// スレッドが後で終わったかを [`VcpuExitWatch::wait`] で知る。plugin-microvm の adapter が期限切れ VM の計数枠を返す判定に使う（#3745）。
///
/// # 観測できる範囲（REPAIR-3）
/// - `Exited` は `MicroVm` の解放完了（vCPU fd と kvm_run の mmap、dispatcher と irqfd の解除、memslot の削除と munmap、VM fd の close）
///   の直後に記録される。スレッドローカルの destructor の完了や OS スレッドの回収より前。
/// - `stop` が報告を受けた後の join だけが期限切れになった `DeadlineExceeded` では、資源は解放済みで `Exited` を返す。
/// - 例外（fail-closed の既存仕様）: memslot の削除に失敗した場合ゲスト RAM の mapping は意図的に残され、`Exited` でも残りうる。
///
/// # 観測できないもの
/// - `KVM_RUN` や ioctl の中で D 状態のまま戻らないスレッドは `Running` のまま。期限で `Running` を返すだけで、強制回収する手段は無い。
/// - カーネルが実際にページを解放したか。
#[derive(Debug, Clone)]
pub struct VcpuExitWatch {
    cell: Arc<ExitCell>,
}

impl VcpuExitWatch {
    /// 待たずに現在の状態を返す。
    pub fn state(&self) -> VcpuExitState {
        self.cell.state()
    }

    /// `deadline` まで終了を待つ。期限内に終わらなければ `Ok(Running)`。`deadline` が 0 または [`STOP_DEADLINE_MAX`] 超なら
    /// `InvalidArgument`（待たない照会は [`VcpuExitWatch::state`]）。
    pub fn wait(&self, deadline: Duration) -> Result<VcpuExitState, MicrovmError> {
        if deadline.is_zero() || deadline > STOP_DEADLINE_MAX {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "exit wait deadline out of range",
            ));
        }
        Ok(self.cell.wait_until(Instant::now() + deadline))
    }
}

/// 期限つき join の結果（REPAIR-5）。
enum JoinOutcome {
    Joined(thread::Result<()>),
    TimedOut,
}

/// `limit` まで `is_finished` を短い間隔で確認し、終わっていれば join する。期限切れなら join せず detach する
/// （無期限の join をしない。REPAIR-5）。
fn join_by(handle: JoinHandle<()>, limit: Instant) -> JoinOutcome {
    loop {
        if handle.is_finished() {
            return JoinOutcome::Joined(handle.join());
        }
        let now = Instant::now();
        if now >= limit {
            return JoinOutcome::TimedOut;
        }
        thread::sleep((limit - now).min(Duration::from_millis(1)));
    }
}

/// [`join_all`] の結果。
struct JoinAll {
    /// 期限までに終わらず切り離したスレッドがあった。
    timed_out: bool,
    /// join が panic を返したスレッドがあった。
    panicked: bool,
}

/// 全スレッドを 1 つの `limit` で回収する（スレッドごとに期限を足さない。REPAIR-5）。期限後も、終わっているものは join する。
fn join_all(handles: Vec<JoinHandle<()>>, limit: Instant) -> JoinAll {
    let mut out = JoinAll {
        timed_out: false,
        panicked: false,
    };
    for h in handles {
        match join_by(h, limit) {
            JoinOutcome::Joined(Ok(())) => {}
            JoinOutcome::Joined(Err(_)) => out.panicked = true,
            JoinOutcome::TimedOut => out.timed_out = true,
        }
    }
    out
}

impl<B: BlockBackend + Send + 'static, N: NetBackend + Send + 'static> MicroVm<B, N> {
    /// カーネルのエントリへ vCPU 0 を初期化し（[`MicroVm::setup_boot_vcpu`]）、vCPU ごとの専用スレッドで実行ループを始める（TASK-75.4.1・MVM-1）。
    ///
    /// `self` はスレッドが所有し、停止時に解放される。[`MicroVm::load_kernel`] の後に呼ぶ。vCPU は 1 台につき 1 スレッドで、
    /// 台数は確保の前に `1..=`[`MAX_VCPUS`] を検証する（範囲外は `InvalidArgument`。#3738）。virtio-net を含む構成では、ゲストの kick なしで受信を処理する専用スレッド `microvm-net-rx`（`NetRxPoller`。期限ごとの
    /// `process_rx`。#3742）を vCPU スレッドと一緒に起動し、停止・失敗・drop の後始末を共有する（#3743）。backend の到着通知は将来仕様（MVM-1・TASK-117・REPAIR-3）。非 x86_64 は `Unimplemented`。`run_once` の初回に SIGUSR2 の
    /// handler が入る注意事項は [`VcpuFd::run_once`] を参照。失敗時の網羅的な後始末の検証は #887。
    pub fn start(self, loaded: &LoadedKernel) -> Result<RunningMicroVm, MicrovmError> {
        let started = Instant::now();
        let result = self.start_inner(loaded, started);
        let elapsed_us = started.elapsed().as_micros();
        match &result {
            Ok(_) => log_line(format_args!(
                "level=info op=microvm.start outcome=ok elapsed_us={elapsed_us}"
            )),
            Err(e) => log_line(format_args!(
                "level=error op=microvm.start outcome=error code={} elapsed_us={elapsed_us}",
                e.code().as_str()
            )),
        }
        result
    }

    fn start_inner(
        mut self,
        loaded: &LoadedKernel,
        started: Instant,
    ) -> Result<RunningMicroVm, MicrovmError> {
        // スレッドと管理領域を確保する前に台数を検証する（#3738・REPAIR-5）。
        validate_vcpu_threads(self.vcpus.len())?;
        self.setup_boot_vcpu(loaded)?;
        let serial = self.devices.serial.clone();
        // 共有部（デバイス・メモリ・VM fd）を 1 つの Arc に移し、vCPU ごとに worker を作る。呼び出し元が持つ参照は
        // 残さない（最後の worker が落ちたときに共有部が解放されることが、stop の「解放済み」の契約の根拠）。
        let MicroVm {
            vcpus,
            devices,
            memory,
            vm,
        } = self;
        let has_net = !devices.net.is_empty();
        let shared = Arc::new(Mutex::new(VmShared {
            devices,
            memory,
            _vm: vm,
        }));
        let workers: Vec<VcpuWorker<B, N>> = vcpus
            .into_iter()
            .map(|vcpu| VcpuWorker {
                vcpu,
                shared: Arc::clone(&shared),
            })
            .collect();
        // virtio-net があるときだけ、ゲストの kick なしで受信を処理する専用スレッドを足す（#3742）。
        let mut aux = Vec::new();
        if has_net {
            let poller = NetRxPoller::new(Arc::clone(&shared), NET_RX_POLL_INTERVAL)?;
            aux.push(AuxThread {
                name: "microvm-net-rx",
                body: Box::new(poller),
            });
        }
        drop(shared);
        spawn_loops(workers, aux, started, serial)
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// 1 台の body を `spawn_loops` で動かす（既存の単独 vCPU の試験用）。
    fn spawn_one<T: VcpuLoopBody>(
        body: T,
        started: Instant,
        serial: SerialConsole,
    ) -> Result<RunningMicroVm, MicrovmError> {
        spawn_loops(vec![body], Vec::new(), started, serial)
    }

    /// 偽の body。step ごとに短く眠り、`finish_after` 回目で `Finish(GuestShutdown)` を返す。drop で `dropped` を立てる。
    struct FakeBody {
        dropped: Arc<AtomicBool>,
        steps: u32,
        finish_after: Option<u32>,
        gate: Option<Arc<(Mutex<bool>, std::sync::Condvar)>>,
        entered: Arc<AtomicBool>,
        panic_after_gate: bool,
    }

    impl FakeBody {
        fn new(dropped: &Arc<AtomicBool>) -> Self {
            FakeBody {
                dropped: Arc::clone(dropped),
                steps: 0,
                finish_after: None,
                gate: None,
                entered: Arc::new(AtomicBool::new(false)),
                panic_after_gate: false,
            }
        }
    }

    impl Drop for FakeBody {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl VcpuLoopBody for FakeBody {
        fn step(&mut self, _slice: Duration, _stop: &StopSignal) -> LoopStep {
            self.entered.store(true, Ordering::SeqCst);
            if let Some(gate) = &self.gate {
                let (m, cv) = &**gate;
                let mut open = m.lock().unwrap();
                let start = Instant::now();
                while !*open {
                    // 解放されない回帰でも無期限に待たない（REPAIR-5）。
                    assert!(
                        start.elapsed() < Duration::from_secs(30),
                        "gate was not opened within 30s"
                    );
                    open = cv.wait_timeout(open, Duration::from_millis(100)).unwrap().0;
                }
            }
            assert!(!self.panic_after_gate, "fake body panic");
            std::thread::sleep(Duration::from_millis(2));
            self.steps += 1;
            match self.finish_after {
                Some(n) if self.steps >= n => LoopStep::Finish(StopReason::GuestShutdown),
                _ => LoopStep::Continue,
            }
        }

        fn stats(&self) -> RunStats {
            RunStats {
                runs: u64::from(self.steps),
                ..RunStats::default()
            }
        }
    }

    /// MVM-1・REPAIR-5: join は期限を超えて待たない。終わらないスレッドは `TimedOut`、終わるスレッドは `Joined`。
    #[test]
    fn mvm1_join_by_respects_deadline() {
        let (tx, rx) = mpsc::channel::<()>();
        let h = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        let t = Instant::now();
        let out = join_by(h, Instant::now() + Duration::from_millis(50));
        assert!(matches!(out, JoinOutcome::TimedOut));
        assert!(t.elapsed() < Duration::from_secs(5));
        drop(tx);
        let h2 = std::thread::spawn(|| {});
        let out = join_by(h2, Instant::now() + Duration::from_secs(5));
        assert!(matches!(out, JoinOutcome::Joined(Ok(()))));
    }

    fn wait_until(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        cond()
    }

    /// MVM-1・REPAIR-3: `run_once` の結果の分類。
    #[test]
    fn mvm1_886_classify_run_table() {
        let io = VcpuExit::Io {
            direction: crate::exit::IoDirection::Out,
            port: 0x10,
            size: 1,
            count: 1,
            data: vec![0],
        };
        let mmio = VcpuExit::Mmio {
            phys_addr: 0,
            data: [0; 8],
            len: 1,
            is_write: true,
        };
        let err = |c| Err(MicrovmError::new(c, "x"));
        assert_eq!(classify_run(&Ok(VcpuExit::Interrupted)), RunClass::Continue);
        assert_eq!(
            classify_run(&err(MicrovmErrorCode::DeadlineExceeded)),
            RunClass::Continue
        );
        assert_eq!(classify_run(&Ok(io)), RunClass::Dispatch);
        assert_eq!(classify_run(&Ok(mmio)), RunClass::Dispatch);
        assert_eq!(
            classify_run(&Ok(VcpuExit::Shutdown)),
            RunClass::Finish(StopReason::GuestShutdown)
        );
        assert_eq!(
            classify_run(&Ok(VcpuExit::Hlt)),
            RunClass::Finish(StopReason::GuestHalted)
        );
        let internal = RunClass::Finish(StopReason::Failed(MicrovmErrorCode::Internal));
        assert_eq!(
            classify_run(&Ok(VcpuExit::FailEntry {
                hardware_entry_failure_reason: 1,
                cpu: 0
            })),
            internal
        );
        assert_eq!(
            classify_run(&Ok(VcpuExit::InternalError { suberror: 1 })),
            internal
        );
        assert_eq!(
            classify_run(&Ok(VcpuExit::Other { exit_reason: 999 })),
            RunClass::Finish(StopReason::Failed(MicrovmErrorCode::Unimplemented))
        );
        assert_eq!(
            classify_run(&err(MicrovmErrorCode::PermissionDenied)),
            RunClass::Finish(StopReason::Failed(MicrovmErrorCode::PermissionDenied))
        );
    }

    /// MVM-1: QueueNotify の MMIO 書き込みだけが通知として取り出される。
    #[test]
    fn mvm1_886_queue_notify_of() {
        struct Nop;
        impl MmioDevice for Nop {
            fn read(&self, _offset: u64, _data: &mut [u8]) -> crate::virtio_mmio::MmioReadOutcome {
                crate::virtio_mmio::MmioReadOutcome::Handled
            }
            fn write(&mut self, _offset: u64, _data: &[u8]) -> MmioWriteOutcome {
                MmioWriteOutcome::Handled
            }
        }
        let id = ExitDispatcher::new()
            .register_mmio(0x1000, 0x100, Box::new(Nop))
            .unwrap();
        let notify = DispatchOutcome::Mmio {
            device: id,
            access: MmioAccess::Write(MmioWriteOutcome::QueueNotify(1)),
        };
        assert_eq!(queue_notify_of(&notify), Some((id, 1)));
        let other_write = DispatchOutcome::Mmio {
            device: id,
            access: MmioAccess::Write(MmioWriteOutcome::Handled),
        };
        assert_eq!(queue_notify_of(&other_write), None);
    }

    /// MVM-1・#3740: `RunningMicroVm::serial_console` は spawn_loop に渡したハンドルと同じバッファを指す。
    #[test]
    fn mvm1_3740_running_serial_console_shares_buffer() {
        let dropped = Arc::new(AtomicBool::new(false));
        let console = SerialConsole::new();
        let running = spawn_one(FakeBody::new(&dropped), Instant::now(), console.clone()).unwrap();
        let mut dev = running.serial_console().port_device();
        assert_eq!(dev.write(0, b"z"), crate::dispatch::PortIoOutcome::Handled);
        assert_eq!(console.take_output().unwrap(), b"z");
    }

    /// MVM-1・TASK-75.4.1: 停止要求で body が drop されてから報告が届く。
    #[test]
    fn mvm1_886_stop_requested_drops_body_before_return() {
        let dropped = Arc::new(AtomicBool::new(false));
        let running = spawn_one(
            FakeBody::new(&dropped),
            Instant::now(),
            SerialConsole::new(),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(30));
        let report = running.stop(Duration::from_secs(5)).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert!(report.stats.runs >= 1);
        assert!(dropped.load(Ordering::SeqCst));
    }

    /// MVM-1・REPAIR-5（#3736）: 停止要求は `VCPU_POLL_INTERVAL` のポーリングに依らず、信号で body まで即時に届く。
    #[test]
    fn mvm1_3736_stop_wakes_body_waiting_on_signal() {
        struct Waiter(Arc<AtomicBool>);
        impl VcpuLoopBody for Waiter {
            fn step(&mut self, _slice: Duration, stop: &StopSignal) -> LoopStep {
                self.0.store(true, Ordering::SeqCst);
                let start = Instant::now();
                while !stop.is_requested() && start.elapsed() < Duration::from_secs(30) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                LoopStep::Continue
            }
            fn stats(&self) -> RunStats {
                RunStats::default()
            }
        }
        let entered = Arc::new(AtomicBool::new(false));
        let running = spawn_one(
            Waiter(Arc::clone(&entered)),
            Instant::now(),
            SerialConsole::new(),
        )
        .unwrap();
        assert!(
            wait_until(Duration::from_secs(10), || entered.load(Ordering::SeqCst)),
            "body did not enter step within 10s"
        );
        let t = Instant::now();
        let report = running.stop(Duration::from_secs(5)).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    }

    /// MVM-1・REPAIR-5（#3736）: ゲスト起因で終わったスレッドへの停止要求は安全に戻り、その理由を返す。
    #[test]
    fn mvm1_3736_stop_after_loop_finished_is_harmless() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut body = FakeBody::new(&dropped);
        body.finish_after = Some(1);
        let running = spawn_one(body, Instant::now(), SerialConsole::new()).unwrap();
        assert!(
            wait_until(Duration::from_secs(5), || dropped.load(Ordering::SeqCst)),
            "loop thread did not exit within the deadline"
        );
        let report = running.stop(Duration::from_secs(5)).unwrap();
        assert_eq!(report.reason, StopReason::GuestShutdown);
    }

    /// MVM-1: ゲスト起因の終了は stop より前に観測でき、stop がその理由を返す。
    #[test]
    fn mvm1_886_guest_finish_reported_before_stop() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut body = FakeBody::new(&dropped);
        body.finish_after = Some(3);
        let running = spawn_one(body, Instant::now(), SerialConsole::new()).unwrap();
        assert!(wait_until(Duration::from_secs(5), || running.is_finished()));
        let report = running.stop(Duration::from_secs(5)).unwrap();
        assert_eq!(report.reason, StopReason::GuestShutdown);
        assert_eq!(report.stats.runs, 3);
        assert!(dropped.load(Ordering::SeqCst));
    }

    /// REPAIR-5: stop の期限は 0 と上限超を拒否し、拒否時も drop が回収する。
    #[test]
    fn mvm1_886_stop_deadline_validated() {
        for bad in [Duration::ZERO, STOP_DEADLINE_MAX + Duration::from_nanos(1)] {
            let dropped = Arc::new(AtomicBool::new(false));
            let running = spawn_one(
                FakeBody::new(&dropped),
                Instant::now(),
                SerialConsole::new(),
            )
            .unwrap();
            let e = running.stop(bad).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "stop deadline out of range");
            assert!(dropped.load(Ordering::SeqCst));
        }
    }

    /// REPAIR-5: body が止まっていても stop は期限で戻る。解放後はスレッドが自力で終わる。
    #[test]
    fn mvm1_886_stop_times_out_when_body_blocks() {
        let dropped = Arc::new(AtomicBool::new(false));
        let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let mut body = FakeBody::new(&dropped);
        body.gate = Some(Arc::clone(&gate));
        let entered = Arc::clone(&body.entered);
        let running = spawn_one(body, Instant::now(), SerialConsole::new()).unwrap();
        // body が step の中（gate 待ち）に入ってから停止を要求する。
        assert!(wait_until(Duration::from_secs(5), || entered.load(Ordering::SeqCst)));
        let e = running.stop(Duration::from_millis(50)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert!(!dropped.load(Ordering::SeqCst));
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(wait_until(Duration::from_secs(5), || dropped.load(Ordering::SeqCst)));
    }

    /// MVM-1: stop を呼ばずに drop しても回収される。
    #[test]
    fn mvm1_886_drop_without_stop_joins() {
        let dropped = Arc::new(AtomicBool::new(false));
        let running = spawn_one(
            FakeBody::new(&dropped),
            Instant::now(),
            SerialConsole::new(),
        )
        .unwrap();
        drop(running);
        assert!(dropped.load(Ordering::SeqCst));
    }

    fn gated_body(dropped: &Arc<AtomicBool>) -> (FakeBody, Arc<(Mutex<bool>, Condvar)>) {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let mut body = FakeBody::new(dropped);
        body.gate = Some(Arc::clone(&gate));
        (body, gate)
    }

    fn open(gate: &Arc<(Mutex<bool>, Condvar)>) {
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
    }

    /// MVM-1・REPAIR-5・#3744: 期限切れの stop の後、未終了なら期限で `Running`、終了後は `Exited`（解放後に記録）。
    #[test]
    fn mvm1_3744_watch_reports_exit_after_stop_timeout() {
        let dropped = Arc::new(AtomicBool::new(false));
        let (body, gate) = gated_body(&dropped);
        let entered = Arc::clone(&body.entered);
        let running = spawn_one(body, Instant::now(), SerialConsole::new()).unwrap();
        assert!(wait_until(Duration::from_secs(5), || entered.load(Ordering::SeqCst)));
        let watch = running.exit_watch();
        let e = running.stop(Duration::from_millis(50)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert_eq!(watch.state(), VcpuExitState::Running);
        let t = Instant::now();
        assert_eq!(
            watch.wait(Duration::from_millis(50)).unwrap(),
            VcpuExitState::Running
        );
        assert!(t.elapsed() >= Duration::from_millis(50));
        assert!(t.elapsed() < Duration::from_secs(1));
        open(&gate);
        let t = Instant::now();
        let VcpuExitState::Exited(r) = watch.wait(Duration::from_secs(5)).unwrap() else {
            panic!("expected Exited");
        };
        assert_eq!(r.reason, StopReason::Requested);
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(dropped.load(Ordering::SeqCst));
    }

    /// MVM-1・#3744: 正常な stop の後は、事前に取った watch が stop の戻り値と同じ報告を返す。
    #[test]
    fn mvm1_3744_watch_exited_after_successful_stop() {
        let dropped = Arc::new(AtomicBool::new(false));
        let running = spawn_one(
            FakeBody::new(&dropped),
            Instant::now(),
            SerialConsole::new(),
        )
        .unwrap();
        let watch = running.exit_watch();
        let report = running.stop(Duration::from_secs(5)).unwrap();
        assert_eq!(watch.state(), VcpuExitState::Exited(report));
    }

    /// MVM-1・#3744: ゲスト起因の終了も `Exited` で報告される。
    #[test]
    fn mvm1_3744_watch_reports_guest_shutdown() {
        let dropped = Arc::new(AtomicBool::new(false));
        let mut body = FakeBody::new(&dropped);
        body.finish_after = Some(3);
        let running = spawn_one(body, Instant::now(), SerialConsole::new()).unwrap();
        let watch = running.exit_watch();
        let VcpuExitState::Exited(r) = watch.wait(Duration::from_secs(5)).unwrap() else {
            panic!("expected Exited");
        };
        assert_eq!(r.reason, StopReason::GuestShutdown);
        assert_eq!(r.stats.runs, 3);
        drop(running);
    }

    /// MVM-1・#3744: `RunningMicroVm` を drop した後も watch は生きて終了を報告する。
    #[test]
    fn mvm1_3744_watch_survives_drop_of_running() {
        let dropped = Arc::new(AtomicBool::new(false));
        let (body, gate) = gated_body(&dropped);
        let entered = Arc::clone(&body.entered);
        let running = spawn_one(body, Instant::now(), SerialConsole::new()).unwrap();
        assert!(wait_until(Duration::from_secs(5), || entered.load(Ordering::SeqCst)));
        let watch = running.exit_watch();
        let opener = std::thread::spawn({
            let gate = Arc::clone(&gate);
            move || {
                std::thread::sleep(Duration::from_millis(100));
                open(&gate);
            }
        });
        drop(running);
        assert!(matches!(
            watch.wait(Duration::from_secs(5)).unwrap(),
            VcpuExitState::Exited(_)
        ));
        opener.join().unwrap();
    }

    /// MVM-1・REPAIR-5・#3744: panic で unwind しても、解放後に `ExitedAbnormally` が記録される。
    #[test]
    fn mvm1_3744_watch_reports_abnormal_exit_on_panic() {
        let dropped = Arc::new(AtomicBool::new(false));
        let (mut body, gate) = gated_body(&dropped);
        body.panic_after_gate = true;
        let entered = Arc::clone(&body.entered);
        let running = spawn_one(body, Instant::now(), SerialConsole::new()).unwrap();
        assert!(wait_until(Duration::from_secs(5), || entered.load(Ordering::SeqCst)));
        let watch = running.exit_watch();
        assert!(running.stop(Duration::from_millis(50)).is_err());
        open(&gate);
        assert_eq!(
            watch.wait(Duration::from_secs(5)).unwrap(),
            VcpuExitState::ExitedAbnormally
        );
        assert!(dropped.load(Ordering::SeqCst));
    }

    /// REPAIR-5・#3744: 待ちの期限は 0 と上限超を即時に拒否する。
    #[test]
    fn mvm1_3744_watch_wait_deadline_validated() {
        let dropped = Arc::new(AtomicBool::new(false));
        let running = spawn_one(
            FakeBody::new(&dropped),
            Instant::now(),
            SerialConsole::new(),
        )
        .unwrap();
        let watch = running.exit_watch();
        for bad in [Duration::ZERO, STOP_DEADLINE_MAX + Duration::from_nanos(1)] {
            let t = Instant::now();
            let e = watch.wait(bad).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "exit wait deadline out of range");
            assert!(t.elapsed() < Duration::from_secs(1));
        }
    }

    /// #3744: `ExitCell` の記録は先勝ちで、異常終了の記録は `Exited` を上書きしない。
    #[test]
    fn mvm1_3744_exit_cell_first_write_wins() {
        let cell = ExitCell::new();
        assert_eq!(cell.state(), VcpuExitState::Running);
        let report = StopReport {
            reason: StopReason::Requested,
            stats: RunStats::default(),
            elapsed: Duration::from_millis(1),
            vcpu_count: 1,
            origin_vcpu: None,
        };
        cell.complete(report);
        cell.mark_abnormal_if_running();
        let other = StopReport {
            reason: StopReason::GuestShutdown,
            ..report
        };
        cell.complete(other);
        assert_eq!(cell.state(), VcpuExitState::Exited(report));
    }

    /// #3744: 観測ハンドルはスレッド間で共有できる。
    #[test]
    fn mvm1_3744_exit_watch_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VcpuExitWatch>();
    }

    /// MVM-1: 起動中ハンドルはスレッド間で移動できる。
    #[test]
    fn mvm1_886_running_microvm_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<RunningMicroVm>();
    }
    // ---- vCPU ごとのスレッド（#3738・MVM-1・REPAIR-5） ----

    use std::sync::atomic::AtomicUsize;

    /// 1 台の vCPU の代役。step ごとに 1ms 眠り、`finish_at` / `panic_at` 回目の step でそれぞれ終了・panic する。
    /// drop で `drops` を増やし、`total_steps` に自分の step 数を足す。`hold` は生存を `Arc` の参照数で観測するため。
    struct TBody {
        drops: Arc<AtomicUsize>,
        total_steps: Arc<std::sync::atomic::AtomicU64>,
        _hold: Arc<()>,
        steps: u32,
        finish_at: Option<(u32, StopReason)>,
        panic_at: Option<u32>,
        gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    }

    impl Drop for TBody {
        fn drop(&mut self) {
            self.total_steps
                .fetch_add(u64::from(self.steps), Ordering::SeqCst);
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl VcpuLoopBody for TBody {
        fn step(&mut self, _slice: Duration, _stop: &StopSignal) -> LoopStep {
            if let Some(gate) = &self.gate {
                let (m, cv) = &**gate;
                let mut open = m.lock().unwrap();
                let start = Instant::now();
                while !*open {
                    // 解放されない回帰でも無期限に待たない（REPAIR-5）。
                    assert!(
                        start.elapsed() < Duration::from_secs(30),
                        "gate was not opened within 30s"
                    );
                    open = cv.wait_timeout(open, Duration::from_millis(50)).unwrap().0;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
            self.steps += 1;
            assert!(self.panic_at != Some(self.steps), "test body panic");
            match self.finish_at {
                Some((n, r)) if self.steps >= n => LoopStep::Finish(r),
                _ => LoopStep::Continue,
            }
        }

        fn stats(&self) -> RunStats {
            RunStats {
                runs: u64::from(self.steps),
                ..RunStats::default()
            }
        }
    }

    struct Probe {
        drops: Arc<AtomicUsize>,
        total_steps: Arc<std::sync::atomic::AtomicU64>,
        hold: Arc<()>,
    }

    impl Probe {
        fn new() -> Self {
            Probe {
                drops: Arc::new(AtomicUsize::new(0)),
                total_steps: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                hold: Arc::new(()),
            }
        }

        fn bodies(&self, n: usize) -> Vec<TBody> {
            (0..n)
                .map(|_| TBody {
                    drops: Arc::clone(&self.drops),
                    total_steps: Arc::clone(&self.total_steps),
                    _hold: Arc::clone(&self.hold),
                    steps: 0,
                    finish_at: None,
                    panic_at: None,
                    gate: None,
                })
                .collect()
        }

        fn drops(&self) -> usize {
            self.drops.load(Ordering::SeqCst)
        }
    }

    /// MVM-1・REPAIR-5・#3738: 台数は `1..=MAX_VCPUS` で、境界の外は確保・生成の前に拒否される。
    #[test]
    fn mvm1_3738_vcpu_count_limit_rejected_before_spawn() {
        for (n, ok) in [
            (0usize, false),
            (1, true),
            (MAX_VCPUS as usize, true),
            (MAX_VCPUS as usize + 1, false),
            (usize::MAX, false),
        ] {
            let r = validate_vcpu_threads(n);
            assert_eq!(r.is_ok(), ok, "n={n}");
            if let Ok(v) = r {
                assert_eq!(v as usize, n);
            } else {
                let e = r.unwrap_err();
                assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
                assert_eq!(e.message(), "vcpu count out of range");
            }
        }
        // 上限超過: スレッドを 1 本も生成せず、body はすべて drop される。
        let p = Probe::new();
        let mut spawned = 0usize;
        let e = spawn_loops_with(
            p.bodies(MAX_VCPUS as usize + 1),
            Instant::now(),
            SerialConsole::new(),
            |_name, _job| {
                spawned += 1;
                Err(std::io::Error::from_raw_os_error(EAGAIN))
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(spawned, 0);
        assert_eq!(p.drops(), MAX_VCPUS as usize + 1);
        let e = spawn_loops(
            p.bodies(0),
            Vec::new(),
            Instant::now(),
            SerialConsole::new(),
        )
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    }

    /// MVM-1・REPAIR-5・#3738: `stop` は全スレッドを回収し、報告は全台の合計になる。
    #[test]
    fn mvm1_3738_stop_joins_all_vcpu_threads() {
        let p = Probe::new();
        let running = spawn_loops(
            p.bodies(3),
            Vec::new(),
            Instant::now(),
            SerialConsole::new(),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(30));
        let report = running.stop(Duration::from_secs(5)).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert_eq!(report.vcpu_count, 3);
        assert_eq!(report.origin_vcpu, None);
        assert_eq!(p.drops(), 3);
        assert_eq!(report.stats.runs, p.total_steps.load(Ordering::SeqCst));
        assert!(report.stats.runs >= 3);
    }

    /// MVM-1・#3738: 1 台が `Requested` 以外で終わると全台が止まり、きっかけの vCPU 番号が報告される。
    #[test]
    fn mvm1_3738_one_vcpu_finish_stops_all() {
        for reason in [
            StopReason::GuestShutdown,
            StopReason::Failed(MicrovmErrorCode::Internal),
        ] {
            let p = Probe::new();
            let mut bodies = p.bodies(3);
            bodies[1].finish_at = Some((3, reason));
            let running =
                spawn_loops(bodies, Vec::new(), Instant::now(), SerialConsole::new()).unwrap();
            let watch = running.exit_watch();
            let VcpuExitState::Exited(r) = watch.wait(Duration::from_secs(10)).unwrap() else {
                panic!("expected Exited");
            };
            assert_eq!(r.reason, reason);
            assert_eq!(r.origin_vcpu, Some(1));
            assert_eq!(r.vcpu_count, 3);
            assert_eq!(p.drops(), 3);
            if matches!(reason, StopReason::Failed(_)) {
                assert!(r.stats.errors >= 1);
            }
            let report = running.stop(Duration::from_secs(5)).unwrap();
            assert_eq!(report, r);
        }
    }

    /// MVM-1・REPAIR-5・#3738: 1 台が panic すると残りも止まり、異常終了として報告される。
    #[test]
    fn mvm1_3738_panic_in_one_vcpu_stops_all() {
        let p = Probe::new();
        let mut bodies = p.bodies(3);
        bodies[2].panic_at = Some(2);
        let running =
            spawn_loops(bodies, Vec::new(), Instant::now(), SerialConsole::new()).unwrap();
        let watch = running.exit_watch();
        assert_eq!(
            watch.wait(Duration::from_secs(10)).unwrap(),
            VcpuExitState::ExitedAbnormally
        );
        assert_eq!(p.drops(), 3);
        let e = running.stop(Duration::from_secs(5)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
    }

    /// MVM-1・#3738: `stop` が `Ok` で戻った時点で、全 body（共有部の参照）は解放済み。
    #[test]
    fn mvm1_3738_shared_released_after_last_vcpu() {
        let p = Probe::new();
        let running = spawn_loops(
            p.bodies(4),
            Vec::new(),
            Instant::now(),
            SerialConsole::new(),
        )
        .unwrap();
        assert_eq!(Arc::strong_count(&p.hold), 5);
        running.stop(Duration::from_secs(5)).unwrap();
        assert_eq!(Arc::strong_count(&p.hold), 1);
    }

    /// REPAIR-5・#3738: 期限は全スレッドへ 1 つ。止まったスレッドが 1 本でも期限で `DeadlineExceeded`、後で終われば `Exited`。
    #[test]
    fn mvm1_3738_stop_deadline_applies_to_all_threads() {
        let p = Probe::new();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let mut bodies = p.bodies(3);
        bodies[1].gate = Some(Arc::clone(&gate));
        let running =
            spawn_loops(bodies, Vec::new(), Instant::now(), SerialConsole::new()).unwrap();
        let watch = running.exit_watch();
        std::thread::sleep(Duration::from_millis(30));
        let t = Instant::now();
        let e = running.stop(Duration::from_millis(100)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        assert_eq!(watch.state(), VcpuExitState::Running);
        open(&gate);
        assert!(matches!(
            watch.wait(Duration::from_secs(10)).unwrap(),
            VcpuExitState::Exited(_)
        ));
        assert_eq!(p.drops(), 3);
    }

    /// MVM-1・#3738: `stop` を呼ばずに drop しても全スレッドが回収される。
    #[test]
    fn mvm1_3738_drop_without_stop_joins_all() {
        let p = Probe::new();
        let running = spawn_loops(
            p.bodies(3),
            Vec::new(),
            Instant::now(),
            SerialConsole::new(),
        )
        .unwrap();
        drop(running);
        assert_eq!(p.drops(), 3);
    }

    /// REPAIR-5・#887・#3738: k 本目の生成に失敗したら、生成済みを回収して `ResourceExhausted` を返し、body はすべて解放される。
    #[test]
    fn mvm1_3738_spawn_failure_rolls_back_started_threads() {
        let p = Probe::new();
        let mut names = Vec::new();
        let e = spawn_loops_with(
            p.bodies(3),
            Instant::now(),
            SerialConsole::new(),
            |name: String, job: VcpuJob| {
                names.push(name.clone());
                if name == "microvm-vcpu-1" {
                    drop(job);
                    return Err(std::io::Error::from_raw_os_error(EAGAIN));
                }
                thread::Builder::new().name(name).spawn(job)
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(names, ["microvm-vcpu-0", "microvm-vcpu-1"]);
        assert_eq!(p.drops(), 3);
        assert_eq!(Arc::strong_count(&p.hold), 1);
        // 起動ゲートにより、生成済みスレッドもゲストを一度も実行していない（回収が 5 秒を超える窓が無い）。
        assert_eq!(p.total_steps.load(Ordering::SeqCst), 0);
    }

    /// REPAIR-5・MVM-1・#3738: spawn ループ中の panic でも、生成済みスレッドは 1 step も実行せず回収され、body が解放される。
    #[test]
    fn mvm1_3738_spawn_panic_stops_and_joins_started_threads() {
        let p = Probe::new();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = spawn_loops_with(
                p.bodies(3),
                Instant::now(),
                SerialConsole::new(),
                |name: String, job: VcpuJob| {
                    assert!(name != "microvm-vcpu-2", "injected spawn panic");
                    thread::Builder::new().name(name).spawn(job)
                },
            );
        }));
        assert!(r.is_err());
        // unwind が戻った時点で、生成済み 2 台は join 済みで、3 台とも解放されている。
        assert_eq!(p.drops(), 3);
        assert_eq!(p.total_steps.load(Ordering::SeqCst), 0);
        assert_eq!(Arc::strong_count(&p.hold), 1);
    }

    /// REPAIR-4・REPAIR-5・#3738: ゲートが期限切れになったスレッドはゲスト実行へ進まず、全台が停止して body が解放される。
    #[test]
    fn mvm1_3738_gate_expiry_does_not_run_guest() {
        let p = Probe::new();
        let running = spawn_loops_gated(
            p.bodies(2),
            Vec::new(),
            Instant::now(),
            SerialConsole::new(),
            Duration::from_millis(100),
            |name: String, job: VcpuJob| {
                if name == "microvm-vcpu-1" {
                    // 後続の生成が遅延し、先に生成した vCPU 0 のゲート待ちが期限切れになる。
                    std::thread::sleep(Duration::from_millis(500));
                }
                thread::Builder::new().name(name).spawn(job)
            },
        )
        .unwrap();
        let watch = running.exit_watch();
        // 期限切れの vCPU は異常終了として計上され、全台が止まる。
        assert_eq!(
            watch.wait(Duration::from_secs(10)).unwrap(),
            VcpuExitState::ExitedAbnormally
        );
        let _ = running.stop(Duration::from_secs(5));
        assert_eq!(p.total_steps.load(Ordering::SeqCst), 0);
        assert_eq!(p.drops(), 2);
        assert_eq!(Arc::strong_count(&p.hold), 1);
    }
}
#[cfg(test)]
mod assemble_tests {
    use std::cell::Cell;

    use super::*;
    use crate::guest_memory::HeapBacking;
    use crate::interrupt::InterruptDelivery;
    use crate::virtio_block::MemoryBlockBackend;
    use crate::virtio_mmio::{MAGIC_VALUE, reg};
    use crate::virtio_net::MemoryNetBackend;

    type Bus = DeviceBus<MemoryBlockBackend, MemoryNetBackend, CountLine>;

    #[derive(Default)]
    struct CountLine(Cell<u32>);

    impl InterruptLine for CountLine {
        fn trigger(&self) -> Result<(), MicrovmError> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn slot(kind: VirtioDeviceKind, index: usize, base: u64, gsi: u32) -> DeviceSlot {
        DeviceSlot {
            kind,
            index,
            mmio_base: base,
            mmio_len: 0x1000,
            gsi,
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn assert_plan_err(r: Result<Vec<DeviceSlot>, MicrovmError>, msg: &str) {
        let e = r.unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), msg);
    }

    fn bus(block: usize, net: usize) -> (Bus, Mem) {
        let slots = layout_slots(block, net).unwrap();
        let blocks = (0..block)
            .map(|_| MemoryBlockBackend::new(16 * 512, false).unwrap())
            .collect();
        let nets = (0..net)
            .map(|_| NetDeviceConfig {
                backend: MemoryNetBackend::new(),
                mac: [2, 0, 0, 0, 0, 1],
            })
            .collect();
        let bus = DeviceBus::new(&slots, blocks, nets, |_| Ok(CountLine::default())).unwrap();
        let mem =
            GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
        (bus, mem)
    }

    type Mem = GuestMemory<HeapBacking>;

    /// MVM-1・#3740: COM1 の PIO exit が UART に届き、範囲外は 0xFF のまま。
    #[test]
    fn mvm1_3740_device_bus_routes_com1_to_serial() {
        use crate::exit::IoDirection;
        let (mut b, _mem) = bus(1, 0);
        let out = VcpuExit::Io {
            direction: IoDirection::Out,
            port: COM1_BASE,
            size: 1,
            count: 3,
            data: b"abc".to_vec(),
        };
        assert!(matches!(
            b.dispatcher.dispatch(&out).unwrap(),
            DispatchOutcome::Pio { .. }
        ));
        assert_eq!(b.serial.take_output().unwrap(), b"abc");
        let far = VcpuExit::Io {
            direction: IoDirection::In,
            port: 0x400,
            size: 1,
            count: 1,
            data: vec![],
        };
        match b.dispatcher.dispatch(&far).unwrap() {
            DispatchOutcome::Unhandled { response, .. } => assert_eq!(response, vec![0xFF]),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn read32(b: &mut Bus, addr: u64) -> DispatchOutcome {
        let exit = VcpuExit::Mmio {
            phys_addr: addr,
            data: [0; 8],
            len: 4,
            is_write: false,
        };
        b.dispatcher.dispatch(&exit).unwrap()
    }

    /// MVM-1・TASK-75.2: block 2 台 + net 1 台の配置を具体値で照合する。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mvm1_697_plan_layout_concrete_addresses() {
        let k = VirtioDeviceKind::Block;
        let n = VirtioDeviceKind::Net;
        assert_eq!(
            plan_layout(2, 1 << 20, 2, 1).unwrap(),
            vec![
                slot(k, 0, 0xd000_0000, 5),
                slot(k, 1, 0xd000_1000, 6),
                slot(n, 0, 0xd000_2000, 7),
            ]
        );
    }

    /// MVM-1・TASK-75.2: 不正な構成は ioctl の前に `InvalidArgument`、境界は通る。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mvm1_697_plan_layout_rejects_invalid_config() {
        assert_plan_err(plan_layout(0, 4096, 0, 0), "vcpu count out of range");
        assert_plan_err(plan_layout(33, 4096, 0, 0), "vcpu count out of range");
        assert_plan_err(
            plan_layout(1, VIRTIO_MMIO_BASE + 4096, 0, 0),
            "guest memory overlaps the virtio-mmio window",
        );
        assert_plan_err(plan_layout(1, 4096, 5, 4), "too many virtio devices");
        assert_plan_err(
            plan_layout(1, 4096, usize::MAX, 1),
            "too many virtio devices",
        );
        assert!(plan_layout(32, VIRTIO_MMIO_BASE, 8, 0).is_ok());
        assert_eq!(plan_layout(1, 4096, 4, 4).unwrap().len(), 8);
        assert!(plan_layout(1, 4096, 0, 0).unwrap().is_empty());
        assert_plan_err(
            plan_layout(1, 0, 0, 0),
            "guest memory size must not be zero",
        );
        assert_plan_err(
            plan_layout(1, 4096 + 1, 0, 0),
            "guest memory size must be a multiple of the host page size (at least 4096)",
        );
    }

    fn gr(start: u64, len: u64) -> GuestRange {
        GuestRange::new(start, len).unwrap()
    }

    fn tss_at(start: u64) -> Vec<Region> {
        vec![(RegionKind::Tss, gr(start, 0x3000))]
    }

    fn overlap_msg(r: Result<(), MicrovmError>) -> String {
        let e = r.unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        e.message().to_string()
    }

    /// MVM-1・#3732: RAM との境界（1 バイト手前は通り、1 バイト食い込むと拒否）。
    #[test]
    fn mvm1_3732_reserved_region_ram_boundary() {
        let res = tss_at(0x10_0000);
        let ram = |len| vec![(RegionKind::GuestMemory, gr(0, len))];
        assert!(check_reserved_regions(&res, &ram(0x10_0000)).is_ok());
        assert_eq!(
            overlap_msg(check_reserved_regions(&res, &ram(0x10_0001))),
            "the TSS region overlaps guest memory"
        );
    }

    /// MVM-1・#3732: MMIO の窓の直前・直後は通り、1 バイトでも食い込むと拒否。内包も拒否。
    #[test]
    fn mvm1_3732_reserved_region_mmio_window_before_and_after() {
        let base = 0x20_0000;
        let res = tss_at(base);
        let end = base + 0x3000;
        let win = |s, l| vec![(RegionKind::VirtioMmio, gr(s, l))];
        assert!(check_reserved_regions(&res, &win(base - 0x1000, 0x1000)).is_ok());
        assert!(check_reserved_regions(&res, &win(end, 0x1000)).is_ok());
        let msg = "the TSS region overlaps a virtio-mmio window";
        for (s, l) in [
            (base - 0xfff, 0x1000),
            (end - 1, 0x1000),
            (base + 0x1000, 0x100),
        ] {
            assert_eq!(overlap_msg(check_reserved_regions(&res, &win(s, l))), msg);
        }
    }

    /// MVM-1・#3732: IOAPIC / LAPIC の窓との重なりは種別ごとの文言で拒否。
    #[test]
    fn mvm1_3732_reserved_region_ioapic_lapic() {
        let res = vec![(RegionKind::IdentityMap, gr(IOAPIC_MMIO_BASE, 0x1000))];
        let io = vec![(RegionKind::Ioapic, gr(IOAPIC_MMIO_BASE, IOAPIC_MMIO_LEN))];
        assert_eq!(
            overlap_msg(check_reserved_regions(&res, &io)),
            "the identity map page overlaps the IOAPIC window"
        );
        let res = tss_at(LAPIC_MMIO_BASE - 0x1000);
        let lapic = vec![(RegionKind::Lapic, gr(LAPIC_MMIO_BASE, LAPIC_MMIO_LEN))];
        assert_eq!(
            overlap_msg(check_reserved_regions(&res, &lapic)),
            "the TSS region overlaps the LAPIC window"
        );
    }

    /// MVM-1・#3732: TSS と identity map が 1 バイトでも重なると拒否、隣接は通る。
    #[test]
    fn mvm1_3732_reserved_regions_must_not_overlap_each_other() {
        let mk = |tss| {
            vec![
                (RegionKind::IdentityMap, gr(0x10_0000, 0x1000)),
                (RegionKind::Tss, gr(tss, 0x3000)),
            ]
        };
        assert!(check_reserved_regions(&mk(0x10_1000), &[]).is_ok());
        assert_eq!(
            overlap_msg(check_reserved_regions(&mk(0x10_0fff), &[])),
            "the TSS region overlaps the identity map page"
        );
    }

    /// MVM-1・#3732: 終端がちょうど 4 GiB は通り、1 バイト超えると拒否。
    #[test]
    fn mvm1_3732_reserved_region_below_4gib() {
        assert!(check_reserved_regions(&tss_at((1 << 32) - 0x3000), &[]).is_ok());
        assert_eq!(
            overlap_msg(check_reserved_regions(&tss_at((1 << 32) - 0x3000 + 1), &[])),
            "the TSS region must lie below 4 GiB"
        );
    }

    /// MVM-1・#3732: 空区間と加算の溢れは panic せず `InvalidArgument`。
    #[test]
    fn mvm1_3732_guest_range_rejects_overflow_and_empty() {
        for (s, l) in [(u64::MAX, 2), (0x1000, 0)] {
            let e = GuestRange::new(s, l).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        }
        assert_eq!(GuestRange::new(u64::MAX - 1, 1).unwrap().end, u64::MAX);
    }

    /// MVM-1・#3732: 既定・最大構成は通り、渡される予約領域は `assemble` が設定する定数と一致する。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mvm1_3732_default_layout_passes() {
        assert!(plan_layout(32, VIRTIO_MMIO_BASE, 8, 0).is_ok());
        assert!(plan_layout(1, 1 << 28, 1, 1).is_ok());
        let (reserved, _) = system_regions(4096, &[]).unwrap();
        assert_eq!(
            reserved,
            vec![
                (RegionKind::IdentityMap, gr(0xfffb_c000, 0x1000)),
                (RegionKind::Tss, gr(0xfffb_d000, 0x3000)),
            ]
        );
        assert_eq!(IDENTITY_MAP_ADDR, 0xfffb_c000);
        assert_eq!(TSS_ADDR, 0xfffb_d000);
    }

    /// MVM-1・TASK-75.2: x86_64 以外は最初の ioctl の前に `Unimplemented`。
    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn mvm1_697_plan_layout_unimplemented_off_x86_64() {
        let e = plan_layout(1, 4096, 0, 0).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Unimplemented);
    }

    /// MVM-1・TASK-75.2: MMIO exit が共有トランスポートまで届き、窓の外は `Unhandled`。
    #[test]
    fn mvm1_697_device_bus_routes_mmio_to_shared_transport() {
        let (mut b, _mem) = bus(1, 1);
        let magic = read32(&mut b, 0xd000_0000 + reg::MAGIC);
        assert_eq!(
            magic.read_response().unwrap(),
            MAGIC_VALUE.to_le_bytes().as_slice()
        );
        let dev_id = read32(&mut b, 0xd000_1000 + reg::DEVICE_ID);
        assert_eq!(
            dev_id.read_response().unwrap(),
            1u32.to_le_bytes().as_slice()
        );
        assert!(matches!(
            read32(&mut b, 0xd000_2000),
            DispatchOutcome::Unhandled { .. }
        ));
    }

    /// MVM-1・TASK-75.2: 未 activate への notify は割り込み 0 回、不明な ID・block の queue 1 は拒否。
    #[test]
    fn mvm1_697_device_bus_complete_queue_notify() {
        let (mut b, mut mem) = bus(1, 1);
        let infos = b.infos();
        let (blk, net) = (infos[0].id, infos[1].id);
        match b.complete_queue_notify(blk, 0, &mut mem) {
            Ok(QueueNotifyReport::Block(r)) => assert_eq!(r.delivery, InterruptDelivery::NotNeeded),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(b.block[0].line.0.get(), 0);
        let e = b.complete_queue_notify(blk, 1, &mut mem).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), "block queue index out of range");
        assert!(b.complete_queue_notify(net, 0, &mut mem).is_ok());
        assert_eq!(b.net[0].line.0.get(), 0);
        // 登録順の別バスの ID（このバスに無い番号）は不明なデバイス。
        let (mut other, _m) = bus(0, 0);
        let e = other.complete_queue_notify(blk, 0, &mut mem).unwrap_err();
        assert_eq!(e.message(), "unknown virtio device");
    }

    /// MVM-1・TASK-75.2: lock が poison したデバイスは応答をやめる（fail-closed）。
    #[test]
    fn mvm1_697_shared_transport_poison_is_fail_closed() {
        let t = Arc::new(Mutex::new(
            VirtioMmioTransport::new(VirtioBlock::new(
                MemoryBlockBackend::new(16 * 512, false).unwrap(),
            ))
            .unwrap(),
        ));
        let t2 = Arc::clone(&t);
        let _ = std::thread::spawn(move || {
            let _g = t2.lock().unwrap();
            panic!("poison the lock");
        })
        .join();
        let mut dev = SharedTransport(Arc::clone(&t));
        let mut data = [0xAAu8; 4];
        assert_eq!(
            dev.read(reg::MAGIC, &mut data),
            MmioReadOutcome::Ignored(IgnoredAccess::WrongDeviceState)
        );
        assert_eq!(data, [0; 4]);
        assert_eq!(
            dev.write(reg::QUEUE_SEL, &[0; 4]),
            MmioWriteOutcome::Ignored(IgnoredAccess::WrongDeviceState)
        );
    }

    /// MVM-1・TASK-75.2: VM 構成体はスレッド間で移動できる。
    #[test]
    fn mvm1_697_microvm_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<MicroVm<MemoryBlockBackend, MemoryNetBackend>>();
    }
}

/// `loaded` のアドレスがゲストメモリ（GPA 0 から `mem_len` バイト）に収まるか確かめる。別の VM（より小さい RAM）で
/// 作られた [`LoadedKernel`] の取り違えや、改変された値を、レジスタへ設定する前に拒否する（SEC-1。値は message に載せない）。
#[cfg(target_arch = "x86_64")]
fn check_loaded_within(loaded: &LoadedKernel, mem_len: u64) -> Result<(), MicrovmError> {
    let inside = |a: GuestAddress| a.raw() < mem_len;
    if !(inside(loaded.entry) && inside(loaded.boot_params) && inside(loaded.cmdline))
        || loaded.runtime_end > mem_len
    {
        return Err(invalid(
            "loaded kernel does not fit in this microVM's memory",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_invalid(r: Result<GuestRam, MicrovmError>, msg: &str) {
        let e = r.unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(e.message(), msg);
    }

    /// MVM-1・TASK-75.1: 登録前の mmap backing が `GuestMemory` 経由で往復する。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn unregistered_ram_roundtrips_through_guest_memory() {
        // 16 / 64 KiB ページのホストでは整列単位の倍数にする（8192 は整列検査で拒否される）。
        let size = ram_align().unwrap().max(8192);
        let ram = GuestRam::new(size).unwrap();
        let mut mem = GuestMemory::new(GuestAddress::new(0x10000), ram).unwrap();
        assert_eq!(mem.len(), size);
        mem.write_at(GuestAddress::new(0x10FFE), &[0x78, 0x56, 0x34, 0x12])
            .unwrap();
        assert_eq!(
            mem.read_u32_le(GuestAddress::new(0x10FFE)).unwrap(),
            0x1234_5678
        );
        assert_eq!(mem.read_u16_le(GuestAddress::new(0x11000)).unwrap(), 0x1234);
        assert_eq!(mem.read_u32_le(GuestAddress::new(0x10000)).unwrap(), 0);
        assert!(
            mem.read_u32_le(GuestAddress::new(0x10000 + size - 2))
                .is_err()
        );
    }

    /// MVM-1・TASK-75.1: size の検証は mmap の前に `InvalidArgument` で弾く。
    #[test]
    fn guest_ram_size_is_validated() {
        assert_invalid(GuestRam::new(0), "guest memory size must not be zero");
        assert_invalid(
            GuestRam::new(4097),
            "guest memory size must be a multiple of the host page size (at least 4096)",
        );
        let align = ram_align().unwrap();
        assert_invalid(
            GuestRam::new(MAX_GUEST_RAM_BYTES + align),
            "guest memory size too large",
        );
        assert_invalid(
            GuestRam::new(u64::MAX - (align - 1)),
            "guest memory size too large",
        );
        assert_eq!(MAX_GUEST_RAM_BYTES, 17_179_869_184);
    }

    /// MVM-1・TASK-75.1: ホストのページサイズが 4096 を超える場合、4096 だけのサイズは確保前に拒否し、倍数は通す。
    #[test]
    fn guest_ram_size_follows_host_page_size() {
        let msg = "guest memory size must be a multiple of the host page size (at least 4096)";
        assert_invalid(GuestRam::new_aligned(4096, 16384), msg);
        assert_invalid(GuestRam::new_aligned(16384 + 4096, 16384), msg);
        assert_invalid(GuestRam::new_aligned(32768, 65536), msg);
        assert!(GuestRam::new_aligned(16384, 16384).is_ok());
        assert!(GuestRam::new_aligned(65536, 65536).is_ok());
        assert!(GuestRam::new_aligned(4096, 4096).is_ok());
    }

    /// MVM-1・TASK-75.1: ホストのページサイズは 2 の冪で 4096 以上（x86_64 は 4096 の具体値）。
    #[test]
    fn host_page_size_is_sane() {
        let p = sys::host_page_size().unwrap();
        assert!(p.is_power_of_two() && p >= 4096);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(p, 4096);
        assert_eq!(ram_align().unwrap(), p.max(GUEST_RAM_ALIGN));
    }

    /// MVM-1・TASK-75.1: errno の分類の具体値。
    #[test]
    fn errno_classification_table() {
        let c = |s, e| classify_ram_error(s, e).code();
        assert_eq!(
            c(RamStage::Mmap, SysError::Unsupported),
            MicrovmErrorCode::Unimplemented
        );
        assert_eq!(
            c(RamStage::Mmap, SysError::Os(ENOMEM)),
            MicrovmErrorCode::ResourceExhausted
        );
        assert_eq!(
            c(RamStage::Register, SysError::Os(EEXIST)),
            MicrovmErrorCode::AlreadyExists
        );
        assert_eq!(
            c(RamStage::Register, SysError::Os(EINVAL)),
            MicrovmErrorCode::InvalidArgument
        );
        assert_eq!(
            c(RamStage::Register, SysError::Os(ENOTTY)),
            MicrovmErrorCode::FailedPrecondition
        );
        assert_eq!(
            c(RamStage::Register, SysError::Os(EACCES)),
            MicrovmErrorCode::PermissionDenied
        );
        assert_eq!(
            c(RamStage::Mmap, SysError::NullMapping),
            MicrovmErrorCode::Internal
        );
        let e = classify_ram_error(RamStage::Mmap, SysError::Os(99));
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        assert_eq!(e.message(), "mmap of guest memory failed (os error 99)");
    }

    /// MVM-1・TASK-75.3.2: 別 VM 由来・改変された `LoadedKernel` をメモリ長で拒否する。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mvm1_885_check_loaded_within_memory() {
        let mk = |entry: u64, bp: u64, cmd: u64, end: u64| LoadedKernel {
            entry: GuestAddress::new(entry),
            boot_params: GuestAddress::new(bp),
            kernel_addr: GuestAddress::new(0x100_0000),
            kernel_len: 0x1000,
            runtime_end: end,
            cmdline: GuestAddress::new(cmd),
            cmdline_len: 0,
            initrd: None,
            protocol_version: 0x020F,
        };
        let mem = 64 << 20;
        check_loaded_within(&mk(0x100_0200, 0x7000, 0x2_0000, 0x300_0000), mem).unwrap();
        for bad in [
            mk(mem, 0x7000, 0x2_0000, 0x300_0000),
            mk(0x100_0200, mem, 0x2_0000, 0x300_0000),
            mk(0x100_0200, 0x7000, mem, 0x300_0000),
            mk(0x100_0200, 0x7000, 0x2_0000, mem + 1),
        ] {
            let e = check_loaded_within(&bad, mem).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(
                e.message(),
                "loaded kernel does not fit in this microVM's memory"
            );
        }
    }
}
/// 起動途中の失敗で取得済みの資源が解放されること（TASK-75.4.2・#887・MVM-1・ERR-1）。KVM は使わない。
/// 受信ポーラー（#3742・MVM-1・REPAIR-5）の試験。KVM 不要（`HeapBacking` のゲストメモリと `MemoryNetBackend`）。
#[cfg(test)]
mod net_rx_tests {
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    use super::*;
    use crate::guest_memory::{GuestAddress, HeapBacking};
    use crate::virtio_block::MemoryBlockBackend;
    use crate::virtio_mmio::{DeviceStatus, VirtioMmioTransport, reg};
    use crate::virtio_net::MemoryNetBackend;

    const RX_DESC: u64 = 0x1000;
    const RX_AVAIL: u64 = 0x2000;
    const RX_USED: u64 = 0x3000;
    const TX_DESC: u64 = 0x4000;
    const TX_AVAIL: u64 = 0x5000;
    const TX_USED: u64 = 0x6000;
    const RX_BUF: u64 = 0x11000;

    /// 回数を数える割り込み線（スレッド間で共有できるよう atomic）。
    struct AtomicLine(Arc<AtomicU32>);

    impl InterruptLine for AtomicLine {
        fn trigger(&self) -> Result<(), MicrovmError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    type Bus = DeviceBus<MemoryBlockBackend, MemoryNetBackend, AtomicLine>;

    /// virtio-net 1 台のバスとゲストメモリを束ねた試験用の対象。
    struct Target {
        bus: Bus,
        mem: GuestMemory<HeapBacking>,
    }

    impl NetRxPollTarget for Target {
        fn poll_net_rx(&mut self) -> Result<NetRxPollReport, MicrovmError> {
            self.bus.poll_net_rx(&mut self.mem)
        }
    }

    fn ga(a: u64) -> GuestAddress {
        GuestAddress::new(a)
    }

    fn target() -> (Target, Arc<AtomicU32>) {
        let slots = layout_slots(0, 1).unwrap();
        let nets = vec![NetDeviceConfig {
            backend: MemoryNetBackend::new(),
            mac: [2, 0, 0, 0, 0, 1],
        }];
        let irqs = Arc::new(AtomicU32::new(0));
        let line_irqs = Arc::clone(&irqs);
        let bus = DeviceBus::new(&slots, Vec::new(), nets, move |_| {
            Ok(AtomicLine(Arc::clone(&line_irqs)))
        })
        .unwrap();
        let mem =
            GuestMemory::new(GuestAddress::new(0), HeapBacking::new(1 << 20).unwrap()).unwrap();
        (Target { bus, mem }, irqs)
    }

    fn wr(t: &mut VirtioMmioTransport<VirtioNet<MemoryNetBackend>>, off: u64, v: u32) {
        t.write(off, &v.to_le_bytes());
    }

    /// ゲストのドライバ相当の初期化（STATUS 1→3→feature→11→キュー 0/1 の設定→15）。
    fn activate(t: &mut Target) {
        let mut tr = t.bus.net[0].transport.lock().unwrap();
        let tr = &mut *tr;
        wr(tr, reg::STATUS, 1);
        wr(tr, reg::STATUS, 3);
        wr(tr, reg::DRIVER_FEATURES_SEL, 0);
        wr(tr, reg::DRIVER_FEATURES, 1 << 5);
        wr(tr, reg::DRIVER_FEATURES_SEL, 1);
        wr(tr, reg::DRIVER_FEATURES, 1);
        wr(tr, reg::STATUS, 11);
        for (q, d, a, u) in [
            (0, RX_DESC, RX_AVAIL, RX_USED),
            (1, TX_DESC, TX_AVAIL, TX_USED),
        ] {
            wr(tr, reg::QUEUE_SEL, q);
            wr(tr, reg::QUEUE_NUM, 16);
            wr(tr, reg::QUEUE_DESC_LOW, d as u32);
            wr(tr, reg::QUEUE_DRIVER_LOW, a as u32);
            wr(tr, reg::QUEUE_DEVICE_LOW, u as u32);
            wr(tr, reg::QUEUE_READY, 1);
        }
        wr(tr, reg::STATUS, 15);
        assert!(tr.status().contains(DeviceStatus::DRIVER_OK));
    }

    /// receiveq の `slot` へ 2048 バイトの writable バッファ（0xee で埋める）を積む。
    fn post_rx_buffer(mem: &mut GuestMemory<HeapBacking>, slot: u16) {
        let buf = RX_BUF + u64::from(slot) * 0x1000;
        mem.write_at(ga(buf), &[0xee; 2048]).unwrap();
        let at = RX_DESC + u64::from(slot) * 16;
        mem.write_at(ga(at), &buf.to_le_bytes()).unwrap();
        mem.write_u32_le(ga(at + 8), 2048).unwrap();
        mem.write_u16_le(ga(at + 12), 2).unwrap();
        mem.write_u16_le(ga(at + 14), 0).unwrap();
        mem.write_u16_le(ga(RX_AVAIL + 4 + 2 * u64::from(slot)), slot)
            .unwrap();
        mem.write_u16_le(ga(RX_AVAIL + 2), slot + 1).unwrap();
    }

    fn frame(len: usize, seed: usize) -> Vec<u8> {
        (0..len).map(|i| ((i + seed) % 241) as u8).collect()
    }

    fn push(t: &mut Target, f: &[u8]) {
        t.bus.net[0]
            .transport
            .lock()
            .unwrap()
            .device_mut()
            .backend_mut()
            .push_inbound(f)
            .unwrap();
    }

    fn inbound_len(t: &Target) -> usize {
        t.bus.net[0]
            .transport
            .lock()
            .unwrap()
            .device()
            .backend()
            .inbound_len()
    }

    fn used_idx(t: &Target) -> u16 {
        t.mem.read_u16_le(ga(RX_USED + 2)).unwrap()
    }

    /// MVM-1・REPAIR-5・#3742: ゲストの kick なしの 1 回のポーリングで、backend のフレームが used ring へ届く。
    #[test]
    fn mvm1_3742_poll_delivers_frame_without_kick() {
        let (mut t, irqs) = target();
        activate(&mut t);
        post_rx_buffer(&mut t.mem, 0);
        let f = frame(60, 7);
        push(&mut t, &f);
        let r = t.poll_net_rx().unwrap();
        assert_eq!(
            (r.polled, r.skipped, r.completed, r.delivered),
            (1, 0, 1, 1)
        );
        assert_eq!(r.interrupts, 1);
        assert!(r.queue_error.is_none());
        assert_eq!(used_idx(&t), 1);
        assert_eq!(t.mem.read_u32_le(ga(RX_USED + 4)).unwrap(), 0);
        assert_eq!(t.mem.read_u32_le(ga(RX_USED + 8)).unwrap(), 12 + 60);
        let mut got = vec![0u8; 72];
        t.mem.read_at(ga(RX_BUF), &mut got).unwrap();
        assert_eq!(&got[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
        assert_eq!(&got[12..], &f[..]);
        assert_eq!(irqs.load(Ordering::SeqCst), 1);
        assert_eq!(inbound_len(&t), 0);
        // 続けて呼んでも、フレームが無ければ何も増えない。
        let r = t.poll_net_rx().unwrap();
        assert_eq!((r.completed, r.interrupts), (0, 0));
        assert_eq!(used_idx(&t), 1);
        assert_eq!(irqs.load(Ordering::SeqCst), 1);
    }

    /// MVM-1・#3742: activate 前と FAILED のデバイスは処理せず、フレームは backend に残る（異常として扱わない）。
    #[test]
    fn mvm1_3742_poll_skips_inactive_and_failed_device() {
        let (mut t, irqs) = target();
        push(&mut t, &frame(40, 1));
        let r = t.poll_net_rx().unwrap();
        assert_eq!((r.polled, r.skipped, r.interrupts), (0, 1, 0));
        assert!(r.queue_error.is_none());
        assert_eq!(inbound_len(&t), 1);
        activate(&mut t);
        post_rx_buffer(&mut t.mem, 0);
        {
            let mut tr = t.bus.net[0].transport.lock().unwrap();
            wr(&mut tr, reg::STATUS, 15 | 128);
        }
        let r = t.poll_net_rx().unwrap();
        assert_eq!((r.polled, r.skipped), (0, 1));
        assert_eq!(inbound_len(&t), 1);
        assert_eq!(used_idx(&t), 0);
        assert_eq!(irqs.load(Ordering::SeqCst), 0);
    }

    /// MVM-1・#3742: 受信バッファが無い間は何も配送せず、バッファが積まれた次のポーリング（kick なし）で届く。
    #[test]
    fn mvm1_3742_poll_waits_for_buffer_then_delivers() {
        let (mut t, irqs) = target();
        activate(&mut t);
        let f = frame(100, 3);
        push(&mut t, &f);
        let r = t.poll_net_rx().unwrap();
        assert_eq!((r.completed, r.interrupts), (0, 0));
        assert_eq!(used_idx(&t), 0);
        assert_eq!(irqs.load(Ordering::SeqCst), 0);
        post_rx_buffer(&mut t.mem, 0);
        let r = t.poll_net_rx().unwrap();
        assert_eq!((r.completed, r.delivered, r.interrupts), (1, 1, 1));
        assert_eq!(used_idx(&t), 1);
        let mut got = vec![0u8; 112];
        t.mem.read_at(ga(RX_BUF), &mut got).unwrap();
        assert_eq!(&got[12..], &f[..]);
        assert_eq!(irqs.load(Ordering::SeqCst), 1);
    }

    /// MVM-1・#3742: リング破損は `queue_error`（`InvalidArgument`）で報告される。
    #[test]
    fn mvm1_3742_poll_ring_corruption_is_reported() {
        let (mut t, _irqs) = target();
        activate(&mut t);
        push(&mut t, &frame(60, 0));
        // avail ring の先頭が範囲外の記述子番号（キュー長 16）を指す。
        t.mem.write_u16_le(ga(RX_AVAIL + 4), 99).unwrap();
        t.mem.write_u16_le(ga(RX_AVAIL + 2), 1).unwrap();
        let r = t.poll_net_rx().unwrap();
        let e = r.queue_error.expect("corruption must be reported");
        assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
    }

    /// 停止要求を待つだけの vCPU の代役。drop を数える。
    struct IdleBody(Arc<AtomicUsize>);

    impl Drop for IdleBody {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl VcpuLoopBody for IdleBody {
        fn step(&mut self, _slice: Duration, stop: &StopSignal) -> LoopStep {
            stop.wait_requested(Duration::from_millis(20));
            LoopStep::Continue
        }

        fn stats(&self) -> RunStats {
            RunStats::default()
        }
    }

    fn poller_aux<S: NetRxPollTarget>(
        shared: &Arc<Mutex<S>>,
        interval: Duration,
    ) -> Vec<AuxThread> {
        let p = NetRxPoller::new(Arc::clone(shared), interval).unwrap();
        vec![AuxThread {
            name: "microvm-net-rx",
            body: Box::new(p),
        }]
    }

    fn wait_for(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
        let end = Instant::now() + limit;
        while Instant::now() < end {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        cond()
    }

    /// MVM-1・REPAIR-5・#3742: ポーラーのスレッドが kick なしにフレームを配送し、`stop` で共有部ごと回収される。
    #[test]
    fn mvm1_3742_rx_poller_thread_delivers_frame() {
        let (mut t, irqs) = target();
        activate(&mut t);
        post_rx_buffer(&mut t.mem, 0);
        let shared = Arc::new(Mutex::new(t));
        let drops = Arc::new(AtomicUsize::new(0));
        let running = spawn_loops_with_aux(
            vec![IdleBody(Arc::clone(&drops))],
            poller_aux(&shared, Duration::from_millis(5)),
            Instant::now(),
            SerialConsole::new(),
            |name, job| thread::Builder::new().name(name).spawn(job),
        )
        .unwrap();
        let f = frame(60, 9);
        push(&mut shared.lock().unwrap(), &f);
        assert!(wait_for(Duration::from_secs(5), || used_idx(
            &shared.lock().unwrap()
        ) == 1));
        {
            let g = shared.lock().unwrap();
            assert_eq!(g.mem.read_u32_le(ga(RX_USED + 8)).unwrap(), 72);
            let mut got = vec![0u8; 72];
            g.mem.read_at(ga(RX_BUF), &mut got).unwrap();
            assert_eq!(&got[12..], &f[..]);
        }
        assert_eq!(irqs.load(Ordering::SeqCst), 1);
        let report = running.stop(Duration::from_secs(2)).unwrap();
        assert_eq!(report.reason, StopReason::Requested);
        assert_eq!(report.vcpu_count, 1);
        assert_eq!(report.origin_vcpu, None);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(Arc::strong_count(&shared), 1);
    }

    /// MVM-1・REPAIR-5・#3742: 周期が長くても、停止要求で待ちが起き、期限内に止まる。
    #[test]
    fn mvm1_3742_rx_poller_stops_within_deadline() {
        let (t, _irqs) = target();
        let shared = Arc::new(Mutex::new(t));
        let drops = Arc::new(AtomicUsize::new(0));
        let running = spawn_loops_with_aux(
            vec![IdleBody(Arc::clone(&drops))],
            poller_aux(&shared, NET_RX_POLL_INTERVAL_MAX),
            Instant::now(),
            SerialConsole::new(),
            |name, job| thread::Builder::new().name(name).spawn(job),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let t0 = Instant::now();
        let report = running.stop(Duration::from_millis(500)).unwrap();
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "{:?}",
            t0.elapsed()
        );
        assert_eq!(report.reason, StopReason::Requested);
        assert_eq!(Arc::strong_count(&shared), 1);
    }

    /// 周期の検証。範囲外は `InvalidArgument`。
    #[test]
    fn mvm1_3742_rx_poller_interval_is_validated() {
        let (t, _irqs) = target();
        let shared = Arc::new(Mutex::new(t));
        for bad in [
            Duration::ZERO,
            NET_RX_POLL_INTERVAL_MIN - Duration::from_nanos(1),
            NET_RX_POLL_INTERVAL_MAX + Duration::from_nanos(1),
        ] {
            let e = NetRxPoller::new(Arc::clone(&shared), bad).err().unwrap();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        }
        assert!(NetRxPoller::new(Arc::clone(&shared), NET_RX_POLL_INTERVAL).is_ok());
    }

    /// 常に `queue_error` を返す対象。
    struct FailTarget;

    impl NetRxPollTarget for FailTarget {
        fn poll_net_rx(&mut self) -> Result<NetRxPollReport, MicrovmError> {
            Ok(NetRxPollReport {
                queue_error: Some(MicrovmError::new(
                    MicrovmErrorCode::InvalidArgument,
                    "corrupt",
                )),
                ..NetRxPollReport::default()
            })
        }
    }

    /// MVM-1・REPAIR-5・#3742: ポーラーの失敗は全スレッドを止め、きっかけは vCPU 以外（`origin_vcpu == None`）で報告される。
    #[test]
    fn mvm1_3742_rx_poller_failure_stops_all() {
        let shared = Arc::new(Mutex::new(FailTarget));
        let drops = Arc::new(AtomicUsize::new(0));
        let running = spawn_loops_with_aux(
            vec![IdleBody(Arc::clone(&drops))],
            poller_aux(&shared, Duration::from_millis(2)),
            Instant::now(),
            SerialConsole::new(),
            |name, job| thread::Builder::new().name(name).spawn(job),
        )
        .unwrap();
        // ポーラーが先に失敗して全台が止まるのを待ってから stop する（stop が先だと Requested になる）。
        let state = running.exit_watch().wait(Duration::from_secs(5)).unwrap();
        assert!(matches!(state, VcpuExitState::Exited(_)), "{state:?}");
        let report = running.stop(Duration::from_secs(5)).unwrap();
        assert_eq!(
            report.reason,
            StopReason::Failed(MicrovmErrorCode::InvalidArgument)
        );
        assert_eq!(report.origin_vcpu, None);
        assert_eq!(report.vcpu_count, 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(Arc::strong_count(&shared), 1);
    }

    /// REPAIR-5・#887・#3742: 補助スレッドの生成に失敗したら、生成済みの vCPU スレッドを回収して `ResourceExhausted` を返す。
    #[test]
    fn mvm1_3742_aux_spawn_failure_rolls_back() {
        let shared = Arc::new(Mutex::new(FailTarget));
        let drops = Arc::new(AtomicUsize::new(0));
        let e = spawn_loops_with_aux(
            vec![IdleBody(Arc::clone(&drops))],
            poller_aux(&shared, Duration::from_millis(2)),
            Instant::now(),
            SerialConsole::new(),
            |name: String, job: VcpuJob| {
                if name == "microvm-net-rx" {
                    drop(job);
                    return Err(std::io::Error::from_raw_os_error(EAGAIN));
                }
                thread::Builder::new().name(name).spawn(job)
            },
        )
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(Arc::strong_count(&shared), 1);
    }
}

#[cfg(test)]
mod failure_tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::virtio_block::MemoryBlockBackend;
    use crate::virtio_net::MemoryNetBackend;

    /// drop の回数を数える割り込み線（irqfd の代役）。
    struct DropLine(Rc<Cell<u32>>);

    impl InterruptLine for DropLine {
        fn trigger(&self) -> Result<(), MicrovmError> {
            Ok(())
        }
    }

    impl Drop for DropLine {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    /// block 2 台・net 1 台の構成で 3 台目の割り込み線の取得が失敗しても、作成済みの 2 台分は解放される。
    #[test]
    fn mvm1_887_device_bus_partial_failure_drops_acquired_lines() {
        let slots = layout_slots(2, 1).unwrap();
        let blocks = (0..2)
            .map(|_| MemoryBlockBackend::new(16 * 512, false).unwrap())
            .collect();
        let nets = vec![NetDeviceConfig {
            backend: MemoryNetBackend::new(),
            mac: [2, 0, 0, 0, 0, 1],
        }];
        let dropped = Rc::new(Cell::new(0u32));
        let made = Cell::new(0u32);
        let r = DeviceBus::<_, _, DropLine>::new(&slots, blocks, nets, |_| {
            if made.get() == 2 {
                return Err(MicrovmError::new(
                    MicrovmErrorCode::ResourceExhausted,
                    "no irqfd",
                ));
            }
            made.set(made.get() + 1);
            Ok(DropLine(Rc::clone(&dropped)))
        });
        let Err(e) = r else { panic!("must fail") };
        assert_eq!(e.code(), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(e.to_string(), "RESOURCE_EXHAUSTED: no irqfd");
        assert_eq!(made.get(), 2);
        assert_eq!(dropped.get(), 2);
        assert_eq!(Rc::strong_count(&dropped), 1);
    }

    /// 窓が重なって dispatcher への登録が失敗しても、作成済みの割り込み線は解放される。
    #[test]
    fn mvm1_887_device_bus_dispatcher_failure_drops_acquired_lines() {
        let mut slots = layout_slots(2, 0).unwrap();
        slots[1].mmio_base = slots[0].mmio_base;
        let blocks = (0..2)
            .map(|_| MemoryBlockBackend::new(16 * 512, false).unwrap())
            .collect();
        let dropped = Rc::new(Cell::new(0u32));
        let r = DeviceBus::<_, MemoryNetBackend, DropLine>::new(&slots, blocks, vec![], |_| {
            Ok(DropLine(Rc::clone(&dropped)))
        });
        assert!(r.is_err());
        assert_eq!(dropped.get(), 1);
        assert_eq!(Rc::strong_count(&dropped), 1);
    }

    #[test]
    fn mvm1_887_classify_spawn_error_table() {
        use std::io::Error;
        let c = |e: Error| classify_spawn_error(&e);
        assert_eq!(
            c(Error::from_raw_os_error(EAGAIN)).to_string(),
            "RESOURCE_EXHAUSTED: cannot spawn vCPU thread (errno 11)"
        );
        assert_eq!(
            c(Error::from_raw_os_error(ENOMEM)).code(),
            MicrovmErrorCode::ResourceExhausted
        );
        assert_eq!(
            c(Error::from_raw_os_error(EINVAL)).to_string(),
            "INTERNAL: cannot spawn vCPU thread (errno 22)"
        );
        assert_eq!(
            c(Error::other("x")).to_string(),
            "INTERNAL: cannot spawn vCPU thread"
        );
    }
}
