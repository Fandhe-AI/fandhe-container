//! ゲストメモリの初期化（TASK-75.1）と VM 構成体の組み立て（TASK-75.2）（MVM-1・MS-7。Linux のみ・unsafe なし）。
//!
//! # VM 構成体（TASK-75.2）
//! [`MicroVm::assemble`] が検証済みの [`MicroVmConfig`] から、VM fd・in-kernel irqchip・登録済みゲストメモリ・
//! virtio デバイス群（MMIO の窓と GSI 割り込み線つき）・vCPU 群を 1 つの [`MicroVm`] に束ねる。配置は
//! [`VIRTIO_MMIO_BASE`] から [`VIRTIO_MMIO_WINDOW`] 刻みで block → net の順、GSI は [`VIRTIO_GSI_BASE`] から連番。
//! 呼び出し元は #884（TASK-75.3.1。カーネルのロードと `virtio_mmio.device=<size>@<base>:<irq>` の cmdline 生成）・
//! #885（TASK-75.3.2。vCPU のレジスタ）・#886（TASK-75.4.1。start / stop と実行ループ）と、
//! `fandhe-container-plugin-microvm`（TASK-117）。構成は非信頼の入力として、ioctl の前に上限を検証する。
//!
//! 範囲外（REPAIR-3）: ioeventfd の結線（QueueNotify は MMIO exit → dispatcher の経路で受ける）・カーネルのロード（#884）・
//! レジスタ設定（#885）・start / stop（#886）・起動失敗の網羅的な後始末（#887。ここでは RAII の drop 順の固定まで）・
//! aarch64（vGIC 未実装のため組み立ての入口で `Unimplemented`）・複数のメモリ領域（RAM は GPA 0 からの単一領域で
//! [`VIRTIO_MMIO_BASE`] 未満に制限）。デバイスの lock は vCPU 0 だけの現状では競合しない（複数 vCPU の並行は #886 以降）。
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
use std::sync::{Arc, Mutex};

use crate::device::{KvmDevice, VcpuFd, VmFd};
use crate::dispatch::{DeviceId, DispatchOutcome, ExitDispatcher, MmioDevice};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::exit::VcpuExit;
use crate::guest_memory::{GuestAddress, GuestMemory, GuestMemoryBacking};
use crate::interrupt::{
    BlockNotifyReport, InterruptLine, NetNotifyReport, complete_block_notify, complete_net_notify,
};
use crate::irq::IrqFd;
use crate::sys::{self, GuestRamMap, SysError};
use crate::virtio_block::{BlockBackend, VirtioBlock};
use crate::virtio_mmio::{
    CONFIG_SPACE_SIZE, IgnoredAccess, MmioReadOutcome, MmioWriteOutcome, VirtioDevice,
    VirtioMmioTransport,
};
use crate::virtio_net::{NetBackend, VirtioNet};

/// virtio-mmio の窓の先頭（GPA）。ゲスト RAM（GPA 0 からの単一領域）はこれより下に収まる。
/// cmdline の `virtio_mmio.device=<size>@<base>:<irq>`（#884）が使う。
pub const VIRTIO_MMIO_BASE: u64 = 0xd000_0000;
/// 1 デバイスの MMIO 窓の大きさ（ページ境界。レジスタ 0x100 と設定空間 [`CONFIG_SPACE_SIZE`] の和以上）。
pub const VIRTIO_MMIO_WINDOW: u64 = 0x1000;
/// 最初のデバイスの GSI。以降は 1 ずつ増やす（既存の `probe_queue_interrupt` も GSI 5 を使う）。
pub const VIRTIO_GSI_BASE: u32 = 5;
/// block と net の合計台数の上限。GSI は 5..=12 に収まり、x86_64 の IOAPIC（24 ピン）の範囲内。
pub const MAX_VIRTIO_DEVICES: usize = 8;
/// 構成の検証上限としての vCPU 数（これより上の実際の上限はカーネルの EINVAL に任せる）。
pub const MAX_VCPUS: u32 = 32;

const _: () = assert!(VIRTIO_MMIO_WINDOW.is_multiple_of(4096));
const _: () = assert!(VIRTIO_MMIO_WINDOW >= 0x100 + CONFIG_SPACE_SIZE);

/// ゲスト RAM の確保上限（16 GiB。無制限確保による DoS を防ぐ。`MAP_NORESERVE` でも上限で抑える）。
pub const MAX_GUEST_RAM_BYTES: u64 = 1 << 34;

/// ゲスト RAM のサイズ・GPA の整列単位の下限（4 KiB）。実際の単位は `max(これ, ホストのページサイズ)`
/// （KVM の memslot はホストの `PAGE_SIZE` の倍数を要求する。16 / 64 KiB ページの aarch64 Linux 対応）。
pub const GUEST_RAM_ALIGN: u64 = sys::GUEST_PAGE_SIZE as u64;

const EPERM: i32 = 1;
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
    layout_slots(block_count, net_count)
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

/// MMIO dispatcher と block / net デバイス群。KVM に依存しない（`L` は割り込み線で、本番は [`IrqFd`]）。
struct DeviceBus<B: BlockBackend, N: NetBackend, L> {
    dispatcher: ExitDispatcher,
    block: Vec<BoundDevice<VirtioBlock<B>, L>>,
    net: Vec<BoundDevice<VirtioNet<N>, L>>,
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
        };
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
    /// 構成を検証し、VM → irqchip → ゲストメモリ → デバイス → vCPU の順に組み立てる。
    ///
    /// irqchip は vCPU より前に作る必要がある。途中で失敗したときはローカル変数の drop が逆順に後始末する
    /// （網羅的な失敗経路の検証は #887）。aarch64 は最初の ioctl より前に `Unimplemented`。
    pub fn assemble(
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
        let memory = GuestRam::new(config.mem_size)?.register(&vm, 0, GuestAddress::new(0))?;
        let devices = DeviceBus::new(&slots, config.block, config.net, |s| {
            vm.register_irqfd(s.gsi)
        })?;
        let mut vcpus = Vec::with_capacity(config.vcpu_count as usize);
        for i in 0..config.vcpu_count {
            vcpus.push(vm.create_vcpu(i)?);
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

    /// 登録済みゲストメモリ（カーネルの書き込み用。#884）。
    pub fn memory_mut(&mut self) -> &mut GuestMemory<RegisteredGuestRam> {
        &mut self.memory
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

    /// `vcpu_index` の vCPU が返した `Io` / `Mmio` exit を MMIO dispatcher へ振り分ける。範囲外の index は `InvalidArgument`。
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
}
