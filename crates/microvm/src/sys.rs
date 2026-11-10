//! KVM の ioctl の薄いラッパー（`crates/microvm` の `sys` モジュール。TASK-74.1.1・MVM-1。
//! `unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::device` の `KvmDevice` が、`/dev/kvm` を開いた fd に対して `KVM_GET_API_VERSION` と
//! `KVM_CREATE_VM` を発行する。open は std（`O_CLOEXEC` 付き）で行うため open の FFI は持たない。
//! VM fd に対する `KVM_CREATE_VCPU`（TASK-74.1.2）と、aarch64 のみ `KVM_ARM_PREFERRED_TARGET` /
//! `KVM_ARM_VCPU_INIT` も発行する。TASK-74.4.1 で vCPU fd の `kvm_run` 領域の mmap（`KvmRunMap`）・
//! `KVM_RUN`・`KVM_SET_USER_MEMORY_REGION`（自己診断用の 1 ページ。`GuestPage`・`RegisteredPage`）を足した。
//! TASK-74.4.2 で `kvm_run` 領域への応答の書き戻し（`KvmRunMap::write_from`。`device::VcpuFd::handle_exit` が呼ぶ）を足した。
//! TASK-75.3.2 で vCPU のレジスタ初期化用に `KVM_GET_REGS` / `KVM_SET_REGS` / `KVM_GET_SREGS` / `KVM_SET_SREGS`
//! （x86_64 のみ。`KvmRegs`・`KvmSregs` ほか。`device::VcpuFd::set_boot_state` / `regs` が呼ぶ）を足した。
//! #3731（TASK-75.3.2・MVM-1・MVM-4）で x86_64 の `KVM_GET_SUPPORTED_CPUID`・`KVM_SET_CPUID2`・`KVM_{GET,SET}_MSRS`・
//! `KVM_{GET,SET}_FPU`・`KVM_{GET,SET}_LAPIC`・`KVM_SET_TSS_ADDR`・`KVM_SET_IDENTITY_MAP_ADDR` を足した
//! （CPUID は #3733 で `device` が呼ぶ。他は呼び出し側を #3732・#3734・#3735 で足す。それまでは試験からだけ呼ぶ）。
//! #4225 で `KVM_GET_DIRTY_LOG`（VM fd。`kvm_get_dirty_log`）を足した（`crate::microvm` の `RegisteredGuestRam` が `crate::dirty_log` の継ぎ目を通して呼ぶ）。
//! TASK-74.2.3 で `KVM_CHECK_EXTENSION`・`KVM_CREATE_IRQCHIP`（x86_64 のみ）・`KVM_IRQFD`・`KVM_IOEVENTFD` と
//! `eventfd` を足した（`crate::irq` の `EventFd`・`IrqFd`・`IoEventFd` と `device::VmFd` のメソッドが呼ぶ）。
//! eventfd の読み書きは std の `File` で行い、ここには読み書きの `unsafe` を持たない。
//! #3698 で ioeventfd の通知スレッドが eventfd を期限つきで待つための `poll(2)` のラッパー（`poll_readable`）を足した。
//! `KVM_RUN` 以外の ioctl はブロックしない同期呼び出しで、`KVM_RUN` はゲストが exit しない限り戻らない
//! （期限は `crate::device` が `KvmRunMap::set_immediate_exit` と `KickCell::kick`（`SIGUSR2`。`KickCell::armed` の中の間だけ送る）で中断する。REPAIR-5）。停止要求（`RunningMicroVm::stop` / drop）も同じ監視スレッド経由でこれを使う（#3736）。監視スレッドは vCPU ごとの常駐 1 本で、`KickCell` が kick の宛先の生存を保つ（#4288）。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と維持すべき不変条件を明記する
//! - 定数は `cfg(target_arch = ...)` ごとに個別に定義し（値が同じでも流用しない）、対応外では
//!   [`SysError::Unsupported`] を返す（fail-closed）。対応は glibc（`target_env = "gnu"`）の LP64 の x86_64・aarch64 だけ。musl は `ioctl` の `request` の型が異なるため対象外
//! - 戻り値が `-1` のときは直後に `std::io::Error::last_os_error()` で errno を確保する
//!
//! # `libc` との機械照合について
//! TASK-75.1 で匿名 mmap のゲスト RAM（`GuestRamMap`）・`madvise(MADV_DONTFORK)`（#3679 で `MADV_DONTDUMP` も）・登録 / 削除のラッパーを足した
//! （`crate::microvm` の `GuestRam`・`RegisteredGuestRam` が呼ぶ。`madvise` も `libc` 導入後は照合の対象）。
//! 本 crate は dev-dependency に `libc` を持たず照合は未導入（追加は crate ごとの承認事項。
//! `docs/design/ffi-libc-check.md`「適用状況」）。なお `KVM_*` の ioctl 番号は `linux/kvm.h` のカーネル ABI で
//! `libc` に対応物が無く、導入後も `ioctl` 関数の型の照合だけが対象になる（`mmap` / `munmap` も導入後は照合の対象）。
//! `eventfd` は `libc` に対応物があり、導入後は照合の対象になる（照合の追跡は #3664。`MADV_DONTDUMP` も同じ）。#3698 の `poll` / `struct pollfd` / `POLL*` も `libc` に対応物があり、導入後は照合の対象（#3664）。`kvm_irqfd`・`kvm_ioeventfd` もカーネル ABI で
//! 対応物が無く、サイズ・オフセットを const assert で固定する。`KVM_MEM_*`（memslot のフラグ）と `KVM_CAP_READONLY_MEM` もカーネル ABI で `libc` に対応物が無く、値を const assert で固定する（#4157）。
//! `kvm_regs`・`kvm_sregs`（`kvm_segment`・`kvm_dtable` を含む）も `libc` に対応物が無く、サイズ・オフセットを const assert で固定する（照合の追跡は #3664）。
//! `kvm_cpuid2` / `kvm_cpuid_entry2`・`kvm_msrs` / `kvm_msr_entry`・`kvm_fpu`・`kvm_lapic_state` も `asm/kvm.h` のカーネル ABI で
//! `libc` に対応物が無く、サイズ・オフセットを const assert で固定する（照合の追跡は #3664）。#3737 で足した `kvm_mp_state`
//! （`linux/kvm.h` v6.12。`KVM_{GET,SET}_MP_STATE`）も同様に対応物が無く、サイズ・アラインを const assert で固定する。上限の `KVM_MAX_CPUID_ENTRIES`・
//! `MAX_IO_MSRS` はカーネル内部の値で uapi にも無い。
//! `kvm_dirty_log`・`KVM_GET_DIRTY_LOG`（#4225）もカーネル ABI で `libc` に対応物が無く、サイズ・オフセット・ioctl 番号を const assert で固定する（導入後も照合の対象は `ioctl` の型だけ。追跡は #3664）。
//! `kvm_userspace_memory_region` と `kvm_run` もカーネル ABI で `libc` に対応物が無く、サイズ・オフセットを const assert で固定する。aarch64 の `kvm_vcpu_init`
//! （`asm/kvm.h` のカーネル ABI 構造体）も `libc` に対応物が無く、サイズ・アラインを const assert で固定する。

#![cfg(target_os = "linux")]

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ffi::c_void;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::exit::{RunArea, RunAreaMut};

/// ioctl 失敗の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysError {
    /// 対応外のアーキテクチャ（定数が未定義）。
    Unsupported,
    /// カーネルが返した errno。
    Os(i32),
    /// `mmap` が NULL を返した（マッピングは `munmap` 済み。原因の errno は無い）。
    NullMapping,
}

/// `_IO(type, nr)` の符号化（方向・サイズが 0 のため `(type << 8) | nr`）。
pub(crate) const fn io(ty: u64, nr: u64) -> u64 {
    (ty << 8) | nr
}

/// ioctl 方向ビット（asm-generic の `_IOC_WRITE` / `_IOC_READ`）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
const IOC_WRITE: u64 = 1;
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
const IOC_READ: u64 = 2;

/// asm-generic の `_IOC(dir, type, nr, size)` の符号化（nr: bit0-7、type: bit8-15、size: bit16-29、dir: bit30-31）。
/// x86_64・aarch64 はどちらもこの符号化。size は 14 bit に収まること（超えたらコンパイル時 / 実行時に panic）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const fn ioc(dir: u64, ty: u64, nr: u64, size: u64) -> u64 {
    assert!(size <= 0x3FFF);
    (dir << 30) | (size << 16) | (ty << 8) | nr
}

/// `_IOR(type, nr, size)`（カーネルからユーザーへ書く）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const fn ior(ty: u64, nr: u64, size: u64) -> u64 {
    ioc(IOC_READ, ty, nr, size)
}

/// `_IOW(type, nr, size)`（ユーザーからカーネルへ読ませる）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const fn iow(ty: u64, nr: u64, size: u64) -> u64 {
    ioc(IOC_WRITE, ty, nr, size)
}

/// `_IOWR(type, nr, size)`（読み書き両方向。#3731・x86_64 の `KVM_GET_SUPPORTED_CPUID` / `KVM_GET_MSRS`）。
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) const fn iowr(ty: u64, nr: u64, size: u64) -> u64 {
    ioc(IOC_READ | IOC_WRITE, ty, nr, size)
}

/// `linux/kvm.h` の `KVMIO`。
const KVMIO: u64 = 0xAE;

/// 定数（x86_64）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) mod consts {
    /// glibc の LP64 のみ対応（musl は `ioctl` の `request` が `int` で宣言が合わないため fail-closed）。
    pub const SUPPORTED: bool = cfg!(target_env = "gnu");
    pub const KVM_API_VERSION: i32 = 12;
    pub const KVM_GET_API_VERSION: u64 = super::io(super::KVMIO, 0x00);
    pub const KVM_CREATE_VM: u64 = super::io(super::KVMIO, 0x01);
    pub const KVM_CREATE_VCPU: u64 = super::io(super::KVMIO, 0x41);
    pub const KVM_GET_VCPU_MMAP_SIZE: u64 = super::io(super::KVMIO, 0x04);
    pub const KVM_RUN: u64 = super::io(super::KVMIO, 0x80);
    /// `_IOW(KVMIO, 0x46, struct kvm_userspace_memory_region)`（32 バイト）。
    pub const KVM_SET_USER_MEMORY_REGION: u64 = super::iow(super::KVMIO, 0x46, 32);
    /// `_IOW(KVMIO, 0x42, struct kvm_dirty_log)`（16 バイト。#4225）。`_IOW` だがカーネルは `dirty_bitmap` の指す先へ書き込む
    /// （`KVM_GET_DEVICE_ATTR` / `KVM_GET_ONE_REG` と同じ流儀）。
    pub const KVM_GET_DIRTY_LOG: u64 = super::iow(super::KVMIO, 0x42, 16);
    pub const PROT_READ: i32 = 1;
    pub const PROT_WRITE: i32 = 2;
    pub const MAP_SHARED: i32 = 1;
    /// `MAP_PRIVATE`（`asm-generic/mman-common.h`）。
    pub const MAP_PRIVATE: i32 = 0x02;
    /// `MAP_ANONYMOUS`（`asm-generic/mman.h`）。
    pub const MAP_ANONYMOUS: i32 = 0x20;
    /// `MAP_NORESERVE`（`asm-generic/mman.h`）。
    pub const MAP_NORESERVE: i32 = 0x4000;
    /// `MADV_DONTFORK`（`asm-generic/mman-common.h`）。
    pub const MADV_DONTFORK: i32 = 10;
    /// `MADV_DONTDUMP`（`asm-generic/mman-common.h`。コアダンプからゲスト RAM を外す。#3679）。
    pub const MADV_DONTDUMP: i32 = 16;
    /// `_IO(KVMIO, 0x03)`（`/dev/kvm` と VM fd のどちらにも発行できる）。
    pub const KVM_CHECK_EXTENSION: u64 = super::io(super::KVMIO, 0x03);
    /// `_IO(KVMIO, 0x60)`（x86_64 のみ定義。vCPU を作る前に発行する）。
    pub const KVM_CREATE_IRQCHIP: u64 = super::io(super::KVMIO, 0x60);
    /// `_IOW(KVMIO, 0x61, struct kvm_irq_level)`（8 バイト。x86_64 と aarch64。in-kernel irqchip の線を駆動する。#3918・#3943）。
    /// x86_64 は GSI、aarch64 は vGIC の SPI / PPI（`irq` の配置は [`arm64_spi_irq_field`]）。
    pub const KVM_IRQ_LINE: u64 = super::iow(super::KVMIO, 0x61, 8);
    /// `_IOW(KVMIO, 0x76, struct kvm_irqfd)`（32 バイト）。
    pub const KVM_IRQFD: u64 = super::iow(super::KVMIO, 0x76, 32);
    /// `_IOW(KVMIO, 0x79, struct kvm_ioeventfd)`（64 バイト）。
    pub const KVM_IOEVENTFD: u64 = super::iow(super::KVMIO, 0x79, 64);
    /// `_IOR(KVMIO, 0x81, struct kvm_regs)`（144 バイト。TASK-75.3.2）。
    pub const KVM_GET_REGS: u64 = super::ior(super::KVMIO, 0x81, 144);
    /// `_IOW(KVMIO, 0x82, struct kvm_regs)`（144 バイト）。
    pub const KVM_SET_REGS: u64 = super::iow(super::KVMIO, 0x82, 144);
    /// `_IOR(KVMIO, 0x83, struct kvm_sregs)`（312 バイト）。
    pub const KVM_GET_SREGS: u64 = super::ior(super::KVMIO, 0x83, 312);
    /// `_IOW(KVMIO, 0x84, struct kvm_sregs)`（312 バイト）。
    pub const KVM_SET_SREGS: u64 = super::iow(super::KVMIO, 0x84, 312);
    // ---- #3731（TASK-75.3.2・MVM-1・MVM-4）: x86_64 起動用の ioctl 番号 ----
    // 出典: Linux の `include/uapi/linux/kvm.h`（ioctl 番号）と `arch/x86/include/uapi/asm/kvm.h`（構造体）。
    // linux-libc-dev 7.0.0 のヘッダと照合済み。
    /// `_IOWR(KVMIO, 0x05, struct kvm_cpuid2)`（ヘッダ 8 バイト。system fd に発行する）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub const KVM_GET_SUPPORTED_CPUID: u64 = super::iowr(super::KVMIO, 0x05, 8);
    /// `_IOW(KVMIO, 0x90, struct kvm_cpuid2)`。
    #[cfg_attr(not(test), allow(dead_code))]
    pub const KVM_SET_CPUID2: u64 = super::iow(super::KVMIO, 0x90, 8);
    /// `_IOWR(KVMIO, 0x88, struct kvm_msrs)`（ヘッダ 8 バイト）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub const KVM_GET_MSRS: u64 = super::iowr(super::KVMIO, 0x88, 8);
    /// `_IOW(KVMIO, 0x89, struct kvm_msrs)`。
    #[cfg_attr(not(test), allow(dead_code))]
    pub const KVM_SET_MSRS: u64 = super::iow(super::KVMIO, 0x89, 8);
    /// `_IOR(KVMIO, 0x8c, struct kvm_fpu)`（416 バイト）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub const KVM_GET_FPU: u64 = super::ior(super::KVMIO, 0x8c, 416);
    /// `_IOW(KVMIO, 0x8d, struct kvm_fpu)`。
    #[cfg_attr(not(test), allow(dead_code))]
    pub const KVM_SET_FPU: u64 = super::iow(super::KVMIO, 0x8d, 416);
    /// `_IOR(KVMIO, 0x98, struct kvm_mp_state)`（4 バイト。vCPU fd。#3737）。
    pub const KVM_GET_MP_STATE: u64 = super::ior(super::KVMIO, 0x98, 4);
    /// `_IOW(KVMIO, 0x99, struct kvm_mp_state)`。
    pub const KVM_SET_MP_STATE: u64 = super::iow(super::KVMIO, 0x99, 4);
    /// `_IOR(KVMIO, 0x8e, struct kvm_lapic_state)`（1024 バイト）。
    pub const KVM_GET_LAPIC: u64 = super::ior(super::KVMIO, 0x8e, 1024);
    /// `_IOW(KVMIO, 0x8f, struct kvm_lapic_state)`。
    pub const KVM_SET_LAPIC: u64 = super::iow(super::KVMIO, 0x8f, 1024);
    /// `_IO(KVMIO, 0x47)`（引数は `unsigned long` の値渡し。VM fd）。
    pub const KVM_SET_TSS_ADDR: u64 = super::io(super::KVMIO, 0x47);
    /// `_IOW(KVMIO, 0x48, __u64)`（引数は `u64` へのポインタ。VM fd）。
    pub const KVM_SET_IDENTITY_MAP_ADDR: u64 = super::iow(super::KVMIO, 0x48, 8);
    /// `KVM_MAX_CPUID_ENTRIES`（`arch/x86/include/asm/kvm_host.h`。カーネル内部の値で uapi に無い）。
    /// `KVM_SET_CPUID2` は `nent` がこれを超えると E2BIG、`KVM_GET_SUPPORTED_CPUID` はこの件数に丸める。
    #[cfg_attr(not(test), allow(dead_code))]
    pub const MAX_CPUID_ENTRIES: usize = 256;
    /// `MAX_IO_MSRS = 256`（`arch/x86/kvm/x86.c`。`nmsrs >= 256` が E2BIG のため上限は 255）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub const MAX_MSR_ENTRIES: usize = 255;
    pub const KVM_CAP_IRQCHIP: super::KvmCap = super::KvmCap(0);
    pub const KVM_CAP_IRQFD: super::KvmCap = super::KvmCap(32);
    pub const KVM_CAP_IOEVENTFD: super::KvmCap = super::KvmCap(36);
    /// `KVM_CAP_NR_MEMSLOTS`（Linux v6.12 `include/uapi/linux/kvm.h` で 10。VM が使える memslot の上限数を返す。#3697）。
    /// `libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_CAP_NR_MEMSLOTS: super::KvmCap = super::KvmCap(10);
    /// `KVM_MEM_LOG_DIRTY_PAGES`（Linux v6.12 `include/uapi/linux/kvm.h` で `1UL << 0`。memslot の dirty page 追跡。#4157）。
    /// `libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_MEM_LOG_DIRTY_PAGES: u32 = 1;
    /// `KVM_MEM_READONLY`（v6.12 `kvm.h` で `1UL << 1`。`KVM_CAP_READONLY_MEM` が要る。#4157）。`libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_MEM_READONLY: u32 = 2;
    /// `KVM_CAP_READONLY_MEM`（v6.12 `kvm.h` で 81。#4157）。`libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_CAP_READONLY_MEM: super::KvmCap = super::KvmCap(81);
    pub const KVM_IRQFD_FLAG_DEASSIGN: u32 = 1 << 0;
    pub const KVM_IOEVENTFD_FLAG_DATAMATCH: u32 = 1 << 0;
    pub const KVM_IOEVENTFD_FLAG_PIO: u32 = 1 << 1;
    pub const KVM_IOEVENTFD_FLAG_DEASSIGN: u32 = 1 << 2;
    /// glibc の `EFD_CLOEXEC`（`O_CLOEXEC` = 0o2000000）。
    pub const EFD_CLOEXEC: i32 = 0o2000000;
    /// glibc の `EFD_NONBLOCK`（`O_NONBLOCK` = 0o4000）。
    pub const EFD_NONBLOCK: i32 = 0o4000;
    /// `POLLIN`（`asm-generic/poll.h`。#3698 の ioeventfd 通知スレッドの待ち）。
    pub const POLLIN: i16 = 0x0001;
    /// `POLLERR`（同上）。
    pub const POLLERR: i16 = 0x0008;
    /// `POLLHUP`（同上）。
    pub const POLLHUP: i16 = 0x0010;
    /// `POLLNVAL`（同上）。
    pub const POLLNVAL: i16 = 0x0020;
}

/// 定数（aarch64）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) mod consts {
    /// glibc の LP64 のみ対応（musl は `ioctl` の `request` が `int` で宣言が合わないため fail-closed）。
    pub const SUPPORTED: bool = cfg!(target_env = "gnu");
    pub const KVM_API_VERSION: i32 = 12;
    pub const KVM_GET_API_VERSION: u64 = super::io(super::KVMIO, 0x00);
    pub const KVM_CREATE_VM: u64 = super::io(super::KVMIO, 0x01);
    pub const KVM_CREATE_VCPU: u64 = super::io(super::KVMIO, 0x41);
    pub const KVM_GET_VCPU_MMAP_SIZE: u64 = super::io(super::KVMIO, 0x04);
    pub const KVM_RUN: u64 = super::io(super::KVMIO, 0x80);
    /// `_IOW(KVMIO, 0x46, struct kvm_userspace_memory_region)`（32 バイト）。
    pub const KVM_SET_USER_MEMORY_REGION: u64 = super::iow(super::KVMIO, 0x46, 32);
    /// `_IOW(KVMIO, 0x42, struct kvm_dirty_log)`（16 バイト。#4225）。`_IOW` だがカーネルは `dirty_bitmap` の指す先へ書き込む
    /// （`KVM_GET_DEVICE_ATTR` / `KVM_GET_ONE_REG` と同じ流儀）。
    pub const KVM_GET_DIRTY_LOG: u64 = super::iow(super::KVMIO, 0x42, 16);
    pub const PROT_READ: i32 = 1;
    pub const PROT_WRITE: i32 = 2;
    pub const MAP_SHARED: i32 = 1;
    /// `MAP_PRIVATE`（`asm-generic/mman-common.h`）。
    pub const MAP_PRIVATE: i32 = 0x02;
    /// `MAP_ANONYMOUS`（`asm-generic/mman.h`）。
    pub const MAP_ANONYMOUS: i32 = 0x20;
    /// `MAP_NORESERVE`（`asm-generic/mman.h`）。
    pub const MAP_NORESERVE: i32 = 0x4000;
    /// `MADV_DONTFORK`（`asm-generic/mman-common.h`）。
    pub const MADV_DONTFORK: i32 = 10;
    /// `MADV_DONTDUMP`（`asm-generic/mman-common.h`。コアダンプからゲスト RAM を外す。#3679）。
    pub const MADV_DONTDUMP: i32 = 16;
    /// `_IOW(KVMIO, 0xae, struct kvm_vcpu_init)`（32 バイト）。
    pub const KVM_ARM_VCPU_INIT: u64 = super::iow(super::KVMIO, 0xAE, 32);
    /// `_IOR(KVMIO, 0xaf, struct kvm_vcpu_init)`（32 バイト）。
    pub const KVM_ARM_PREFERRED_TARGET: u64 = super::ior(super::KVMIO, 0xAF, 32);
    /// `KVM_CAP_ARM_PSCI_0_2`（v6.12 `linux/kvm.h`。#3896）。`libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_CAP_ARM_PSCI_0_2: super::KvmCap = super::KvmCap(102);
    /// `KVM_CAP_ARM_VM_IPA_SIZE`（v6.12 `linux/kvm.h` で 165。応答はホストの IPA 上限ビット数。#4227）。
    /// `libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_CAP_ARM_VM_IPA_SIZE: super::KvmCap = super::KvmCap(165);
    /// `KVM_ARM_VCPU_PSCI_0_2`（v6.12 `asm/kvm.h`）。features の**ビット番号**でマスクではない（`1 << 値` で立てる）。
    pub const KVM_ARM_VCPU_PSCI_0_2: u32 = 2;
    /// `KVM_ARM_VCPU_POWER_OFF`（v6.12 `asm/kvm.h`。#3899）。features の**ビット番号**。立てた vCPU は `KVM_RUN` が
    /// PSCI CPU_ON を受けるまで眠る（`kvm_arm_vcpu_power_off`）。vCPU 0 に立ててはならない。
    pub const KVM_ARM_VCPU_POWER_OFF: u32 = 0;
    // 以下は #3696（vGIC・起動レジスタ）。値は Linux v6.12 の `include/uapi/linux/kvm.h` /
    // `arch/arm64/include/uapi/asm/kvm.h` で照合した（`libc` に対応物が無いカーネル ABI のため、機械照合は適用外）。
    /// `_IOWR(KVMIO, 0xe0, struct kvm_create_device)`（12 バイト）。
    pub const KVM_CREATE_DEVICE: u64 = super::iowr(super::KVMIO, 0xE0, 12);
    /// `_IOW(KVMIO, 0xe1, struct kvm_device_attr)`（24 バイト）。
    pub const KVM_SET_DEVICE_ATTR: u64 = super::iow(super::KVMIO, 0xE1, 24);
    /// `_IOW(KVMIO, 0xe2, struct kvm_device_attr)`（24 バイト。`_IOW` だがカーネルは `addr` の先へ書く）。
    pub const KVM_GET_DEVICE_ATTR: u64 = super::iow(super::KVMIO, 0xE2, 24);
    /// `_IOW(KVMIO, 0xab, struct kvm_one_reg)`（16 バイト。`_IOW` だがカーネルは `addr` の先へ書く）。
    pub const KVM_GET_ONE_REG: u64 = super::iow(super::KVMIO, 0xAB, 16);
    /// `_IOW(KVMIO, 0xac, struct kvm_one_reg)`（16 バイト）。
    pub const KVM_SET_ONE_REG: u64 = super::iow(super::KVMIO, 0xAC, 16);
    pub const KVM_CAP_DEVICE_CTRL: super::KvmCap = super::KvmCap(89);
    /// `enum kvm_device_type` の `KVM_DEV_TYPE_ARM_VGIC_V3`（FSL_MPIC_20 = 1 から数えて 7）。
    pub const KVM_DEV_TYPE_ARM_VGIC_V3: u32 = 7;
    pub const KVM_DEV_ARM_VGIC_GRP_ADDR: u32 = 0;
    pub const KVM_DEV_ARM_VGIC_GRP_DIST_REGS: u32 = 1;
    pub const KVM_DEV_ARM_VGIC_GRP_CTRL: u32 = 4;
    pub const KVM_DEV_ARM_VGIC_CTRL_INIT: u64 = 0;
    pub const KVM_VGIC_V3_ADDR_TYPE_DIST: u64 = 2;
    pub const KVM_VGIC_V3_ADDR_TYPE_REDIST: u64 = 3;
    /// `_IO(KVMIO, 0x03)`（`/dev/kvm` と VM fd のどちらにも発行できる）。
    pub const KVM_CHECK_EXTENSION: u64 = super::io(super::KVMIO, 0x03);
    /// `_IOW(KVMIO, 0x61, struct kvm_irq_level)`（8 バイト。vGIC の SPI / PPI を駆動する。#3943）。
    pub const KVM_IRQ_LINE: u64 = super::iow(super::KVMIO, 0x61, 8);
    /// `_IOW(KVMIO, 0x76, struct kvm_irqfd)`（32 バイト）。
    pub const KVM_IRQFD: u64 = super::iow(super::KVMIO, 0x76, 32);
    /// `_IOW(KVMIO, 0x79, struct kvm_ioeventfd)`（64 バイト）。
    pub const KVM_IOEVENTFD: u64 = super::iow(super::KVMIO, 0x79, 64);
    /// `KVM_CAP_IRQCHIP`（0。arm64 のカーネルは in-kernel vGIC を持てるとき 1 を返す。#3943）。
    pub const KVM_CAP_IRQCHIP: super::KvmCap = super::KvmCap(0);
    pub const KVM_CAP_IRQFD: super::KvmCap = super::KvmCap(32);
    pub const KVM_CAP_IOEVENTFD: super::KvmCap = super::KvmCap(36);
    /// `KVM_CAP_NR_MEMSLOTS`（Linux v6.12 `include/uapi/linux/kvm.h` で 10。VM が使える memslot の上限数を返す。#3697）。
    /// `libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_CAP_NR_MEMSLOTS: super::KvmCap = super::KvmCap(10);
    /// `KVM_MEM_LOG_DIRTY_PAGES`（Linux v6.12 `include/uapi/linux/kvm.h` で `1UL << 0`。memslot の dirty page 追跡。#4157）。
    /// `libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_MEM_LOG_DIRTY_PAGES: u32 = 1;
    /// `KVM_MEM_READONLY`（v6.12 `kvm.h` で `1UL << 1`。`KVM_CAP_READONLY_MEM` が要る。#4157）。`libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_MEM_READONLY: u32 = 2;
    /// `KVM_CAP_READONLY_MEM`（v6.12 `kvm.h` で 81。#4157）。`libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_CAP_READONLY_MEM: super::KvmCap = super::KvmCap(81);
    pub const KVM_IRQFD_FLAG_DEASSIGN: u32 = 1 << 0;
    pub const KVM_IOEVENTFD_FLAG_DATAMATCH: u32 = 1 << 0;
    pub const KVM_IOEVENTFD_FLAG_PIO: u32 = 1 << 1;
    pub const KVM_IOEVENTFD_FLAG_DEASSIGN: u32 = 1 << 2;
    /// glibc の `EFD_CLOEXEC`（`O_CLOEXEC` = 0o2000000）。
    pub const EFD_CLOEXEC: i32 = 0o2000000;
    /// glibc の `EFD_NONBLOCK`（`O_NONBLOCK` = 0o4000）。
    pub const EFD_NONBLOCK: i32 = 0o4000;
    /// `POLLIN`（`asm-generic/poll.h`。#3698 の ioeventfd 通知スレッドの待ち）。
    pub const POLLIN: i16 = 0x0001;
    /// `POLLERR`（同上）。
    pub const POLLERR: i16 = 0x0008;
    /// `POLLHUP`（同上）。
    pub const POLLHUP: i16 = 0x0010;
    /// `POLLNVAL`（同上）。
    pub const POLLNVAL: i16 = 0x0020;
}

/// 対応外アーキテクチャ。値は使われない（各ラッパーが `Unsupported` を返す）。
#[cfg(not(any(
    all(target_arch = "x86_64", target_pointer_width = "64"),
    all(target_arch = "aarch64", target_pointer_width = "64")
)))]
pub(crate) mod consts {
    pub const SUPPORTED: bool = false;
    pub const KVM_API_VERSION: i32 = 0;
    pub const KVM_GET_API_VERSION: u64 = 0;
    pub const KVM_CREATE_VM: u64 = 0;
    pub const KVM_CREATE_VCPU: u64 = 0;
    pub const KVM_GET_VCPU_MMAP_SIZE: u64 = 0;
    pub const KVM_RUN: u64 = 0;
    pub const KVM_SET_USER_MEMORY_REGION: u64 = 0;
    pub const KVM_GET_DIRTY_LOG: u64 = 0;
    pub const PROT_READ: i32 = 0;
    pub const PROT_WRITE: i32 = 0;
    pub const MAP_SHARED: i32 = 0;
    pub const MAP_PRIVATE: i32 = 0;
    pub const MAP_ANONYMOUS: i32 = 0;
    pub const MAP_NORESERVE: i32 = 0;
    pub const MADV_DONTFORK: i32 = 0;
    pub const MADV_DONTDUMP: i32 = 0;
    pub const KVM_CHECK_EXTENSION: u64 = 0;
    pub const KVM_IRQFD: u64 = 0;
    pub const KVM_IOEVENTFD: u64 = 0;
    pub const KVM_CAP_IRQFD: super::KvmCap = super::KvmCap(0);
    pub const KVM_CAP_IOEVENTFD: super::KvmCap = super::KvmCap(0);
    /// `KVM_CAP_NR_MEMSLOTS`（Linux v6.12 `include/uapi/linux/kvm.h` で 10。VM が使える memslot の上限数を返す。#3697）。
    /// `libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_CAP_NR_MEMSLOTS: super::KvmCap = super::KvmCap(0);
    /// `KVM_MEM_LOG_DIRTY_PAGES`（Linux v6.12 `include/uapi/linux/kvm.h` で `1UL << 0`。memslot の dirty page 追跡。#4157）。
    /// `libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_MEM_LOG_DIRTY_PAGES: u32 = 0;
    /// `KVM_MEM_READONLY`（v6.12 `kvm.h` で `1UL << 1`。`KVM_CAP_READONLY_MEM` が要る。#4157）。`libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_MEM_READONLY: u32 = 0;
    /// `KVM_CAP_READONLY_MEM`（v6.12 `kvm.h` で 81。#4157）。`libc` に対応物が無く、具体値の試験で固定する（#3664）。
    pub const KVM_CAP_READONLY_MEM: super::KvmCap = super::KvmCap(0);
    pub const KVM_IRQFD_FLAG_DEASSIGN: u32 = 0;
    pub const KVM_IOEVENTFD_FLAG_DATAMATCH: u32 = 0;
    pub const KVM_IOEVENTFD_FLAG_PIO: u32 = 0;
    pub const KVM_IOEVENTFD_FLAG_DEASSIGN: u32 = 0;
    pub const EFD_CLOEXEC: i32 = 0;
    pub const EFD_NONBLOCK: i32 = 0;
    pub const POLLIN: i16 = 0;
    pub const POLLERR: i16 = 0;
    pub const POLLHUP: i16 = 0;
    pub const POLLNVAL: i16 = 0;
}

/// aarch64 の `struct kvm_vcpu_init`（`asm/kvm.h`。`target` と features ビットマップ 7 語の 32 バイト）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct KvmVcpuInit {
    pub target: u32,
    pub features: [u32; 7],
}

#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
const _: () = {
    assert!(std::mem::size_of::<KvmVcpuInit>() == 32);
    assert!(std::mem::align_of::<KvmVcpuInit>() == 4);
    assert!(consts::KVM_ARM_VCPU_INIT == 0x4020_AEAE);
    assert!(consts::KVM_ARM_PREFERRED_TARGET == 0x8020_AEAF);
    assert!(consts::KVM_CAP_ARM_PSCI_0_2.0 == 102);
    assert!(consts::KVM_CAP_ARM_VM_IPA_SIZE.0 == 165);
    assert!(consts::KVM_MEM_LOG_DIRTY_PAGES == 1);
    assert!(consts::KVM_MEM_READONLY == 2);
    assert!(consts::KVM_CAP_READONLY_MEM.0 == 81);
    assert!(consts::KVM_ARM_VCPU_PSCI_0_2 == 2);
    assert!(consts::KVM_ARM_VCPU_POWER_OFF == 0);
};

/// features[0] に `KVM_ARM_VCPU_POWER_OFF` のビットを立てる（AP 用。他の語・ビットは不変。#3899）。
/// `device::VmFd::create_arm64_vcpu` が `PoweredOff` のときだけ呼ぶ。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) fn with_power_off(mut init: KvmVcpuInit) -> KvmVcpuInit {
    init.features[0] |= 1u32 << consts::KVM_ARM_VCPU_POWER_OFF;
    init
}

/// features[0] に `KVM_ARM_VCPU_PSCI_0_2` のビットを立てる（他の語・ビットは不変。#3896）。
/// `device::VmFd::create_vcpu` が `KVM_ARM_VCPU_INIT` の前に呼ぶ。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) fn with_psci_0_2(mut init: KvmVcpuInit) -> KvmVcpuInit {
    init.features[0] |= 1u32 << consts::KVM_ARM_VCPU_PSCI_0_2;
    init
}

/// aarch64 の `struct kvm_create_device`（`linux/kvm.h`。`type`・`fd`・`flags` の 12 バイト。#3696）。
/// `fd` はカーネルが書く出力で、入力時は 0 にしておく。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct KvmCreateDevice {
    type_: u32,
    fd: u32,
    flags: u32,
}

/// aarch64 の `struct kvm_device_attr`（`linux/kvm.h`。24 バイト。#3696）。`addr` はユーザー空間の値のアドレス。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct KvmDeviceAttr {
    flags: u32,
    group: u32,
    attr: u64,
    addr: u64,
}

/// aarch64 の `struct kvm_one_reg`（`linux/kvm.h`。16 バイト。#3696）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct KvmOneReg {
    id: u64,
    addr: u64,
}

#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<KvmCreateDevice>() == 12);
    assert!(align_of::<KvmCreateDevice>() == 4);
    assert!(offset_of!(KvmCreateDevice, fd) == 4);
    assert!(offset_of!(KvmCreateDevice, flags) == 8);
    assert!(size_of::<KvmDeviceAttr>() == 24);
    assert!(align_of::<KvmDeviceAttr>() == 8);
    assert!(offset_of!(KvmDeviceAttr, group) == 4);
    assert!(offset_of!(KvmDeviceAttr, attr) == 8);
    assert!(offset_of!(KvmDeviceAttr, addr) == 16);
    assert!(size_of::<KvmOneReg>() == 16);
    assert!(align_of::<KvmOneReg>() == 8);
    assert!(offset_of!(KvmOneReg, addr) == 8);
    assert!(consts::KVM_CREATE_DEVICE == 0xC00C_AEE0);
    assert!(consts::KVM_SET_DEVICE_ATTR == 0x4018_AEE1);
    assert!(consts::KVM_GET_DEVICE_ATTR == 0x4018_AEE2);
    assert!(consts::KVM_GET_ONE_REG == 0x4010_AEAB);
    assert!(consts::KVM_SET_ONE_REG == 0x4010_AEAC);
};

/// `KVM_REG_ARM64`（`linux/kvm.h`）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
/// `KVM_REG_SIZE_U64`（`linux/kvm.h`）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
/// `KVM_REG_SIZE_MASK`（`linux/kvm.h`）。ONE_REG の id のうちレジスタのサイズ種別を表すビット。
/// カーネル ABI の定数で `libc` に対応物が無いため、具体値の試験（`mvm1_3949_*`）で固定する。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
const KVM_REG_SIZE_MASK: u64 = 0x00f0_0000_0000_0000;

/// ONE_REG の id のサイズ種別が `KVM_REG_SIZE_U64` であることを確かめる（#3949・MVM-1・純関数）。
///
/// `kvm_get_one_reg_u64` / `kvm_set_one_reg_u64` が ioctl の前に呼ぶ。8 バイトのバッファで足りることを保証し、
/// U128 以上の id でカーネルがバッファを超えて書く（get）・読む（set）経路を閉じる。不一致は `Os(EINVAL)`。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const fn check_one_reg_id_u64(id: u64) -> Result<(), SysError> {
    if id & KVM_REG_SIZE_MASK == KVM_REG_SIZE_U64 {
        Ok(())
    } else {
        Err(SysError::Os(22))
    }
}
/// `KVM_REG_ARM_CORE`（`0x0010 << KVM_REG_ARM_COPROC_SHIFT(16)`。`asm/kvm.h`）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
const KVM_REG_ARM_CORE: u64 = 0x0010 << 16;

/// aarch64 の core レジスタ（`struct kvm_regs` の先頭の `user_pt_regs`）の ONE_REG id を組む（#3696・純関数）。
///
/// `word_index` は `KVM_REG_ARM_CORE_REG(name)` = `offsetof(struct kvm_regs, name) / sizeof(__u32)`
/// （`user_pt_regs` は `regs[31]`・`sp`・`pc`・`pstate` の u64 を並べたものなので、u64 の番号 × 2）。
/// すべて 64 bit レジスタ（`KVM_REG_SIZE_U64`）として扱う。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const fn arm64_core_reg_id(word_index: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | word_index
}

/// 汎用レジスタ `x<n>`（`n <= 30`）の ONE_REG id。範囲外は `None`。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const fn arm64_reg_x(n: u64) -> Option<u64> {
    if n > 30 {
        return None;
    }
    Some(arm64_core_reg_id(n * 2))
}

/// `pc` の ONE_REG id（`regs[31]`・`sp` の次の u64 = 32 番目 → u32 換算で 64）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const ARM64_REG_PC: u64 = arm64_core_reg_id(64);
/// `pstate` の ONE_REG id（u64 の 33 番目 → u32 換算で 66）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const ARM64_REG_PSTATE: u64 = arm64_core_reg_id(66);

/// `KVM_REG_ARM64_SYSREG`（`0x0013 << KVM_REG_ARM_COPROC_SHIFT(16)`。`asm/kvm.h`。#3899）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
const KVM_REG_ARM64_SYSREG: u64 = 0x0013 << 16;

/// システムレジスタの ONE_REG id を組む（`ARM64_SYS_REG(op0, op1, crn, crm, op2)`。純関数。#3899）。
/// 各フィールドの位置は op0=14・op1=11・crn=7・crm=3・op2=0（`KVM_REG_ARM64_SYSREG_*_SHIFT`）で、64 bit として扱う。
/// `libc` に対応物が無いカーネル ABI のため機械照合は適用外で、具体値の試験で固定する。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const fn arm64_sys_reg_id(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | KVM_REG_ARM64_SYSREG
        | ((op0 & 0x3) << 14)
        | ((op1 & 0x7) << 11)
        | ((crn & 0xf) << 7)
        | ((crm & 0xf) << 3)
        | (op2 & 0x7)
}

/// `MPIDR_EL1`（op0=3・op1=0・crn=0・crm=0・op2=5）の ONE_REG id。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const ARM64_REG_MPIDR_EL1: u64 = arm64_sys_reg_id(3, 0, 0, 0, 5);

/// x86_64 の `struct kvm_regs`（`asm/kvm.h`。汎用レジスタ 16 本・rip・rflags の 144 バイト。TASK-75.3.2）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// x86_64 の `struct kvm_segment`（`asm/kvm.h`。24 バイト）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmSegment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

/// x86_64 の `struct kvm_dtable`（`asm/kvm.h`。GDT / IDT の base・limit の 16 バイト）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmDtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

/// x86_64 の `struct kvm_sregs`（`asm/kvm.h`。312 バイト。`interrupt_bitmap` は `KVM_NR_INTERRUPTS` = 256 bit）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmSregs {
    pub cs: KvmSegment,
    pub ds: KvmSegment,
    pub es: KvmSegment,
    pub fs: KvmSegment,
    pub gs: KvmSegment,
    pub ss: KvmSegment,
    pub tr: KvmSegment,
    pub ldt: KvmSegment,
    pub gdt: KvmDtable,
    pub idt: KvmDtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

// `asm/kvm.h` のレイアウトと ioctl 番号のサイズ符号を固定する。`libc` に対応物の無いカーネル ABI の構造体（照合の追跡は #3664）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<KvmRegs>() == 144);
    assert!(align_of::<KvmRegs>() == 8);
    assert!(offset_of!(KvmRegs, rsi) == 32);
    assert!(offset_of!(KvmRegs, rsp) == 48);
    assert!(offset_of!(KvmRegs, r8) == 64);
    assert!(offset_of!(KvmRegs, rip) == 128);
    assert!(offset_of!(KvmRegs, rflags) == 136);
    assert!(size_of::<KvmSegment>() == 24);
    assert!(align_of::<KvmSegment>() == 8);
    assert!(offset_of!(KvmSegment, limit) == 8);
    assert!(offset_of!(KvmSegment, selector) == 12);
    assert!(offset_of!(KvmSegment, type_) == 14);
    assert!(offset_of!(KvmSegment, present) == 15);
    assert!(offset_of!(KvmSegment, avl) == 21);
    assert!(offset_of!(KvmSegment, unusable) == 22);
    assert!(size_of::<KvmDtable>() == 16);
    assert!(offset_of!(KvmDtable, limit) == 8);
    assert!(size_of::<KvmSregs>() == 312);
    assert!(align_of::<KvmSregs>() == 8);
    assert!(offset_of!(KvmSregs, tr) == 144);
    assert!(offset_of!(KvmSregs, gdt) == 192);
    assert!(offset_of!(KvmSregs, idt) == 208);
    assert!(offset_of!(KvmSregs, cr0) == 224);
    assert!(offset_of!(KvmSregs, cr3) == 240);
    assert!(offset_of!(KvmSregs, cr4) == 248);
    assert!(offset_of!(KvmSregs, efer) == 264);
    assert!(offset_of!(KvmSregs, apic_base) == 272);
    assert!(offset_of!(KvmSregs, interrupt_bitmap) == 280);
    assert!(consts::KVM_GET_REGS == 0x8090_AE81);
    assert!(consts::KVM_SET_REGS == 0x4090_AE82);
    assert!(consts::KVM_GET_SREGS == 0x8138_AE83);
    assert!(consts::KVM_SET_SREGS == 0x4138_AE84);
};

// ---- #3731（TASK-75.3.2・MVM-1・MVM-4）: x86_64 起動用の構造体 ----
// CPUID 系は #3733 で `device` が呼ぶ。他の呼び出し側（`device` / `microvm`）は #3732・#3734・#3735 で足す。それまでは
// 試験からだけ使うため `dead_code` を許可し、呼び出しが入ったら外す。

/// x86_64 の `struct kvm_cpuid_entry2`（`asm/kvm.h`。40 バイト）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmCpuidEntry2 {
    pub function: u32,
    pub index: u32,
    pub flags: u32,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub padding: [u32; 3],
}

/// x86_64 の `struct kvm_msr_entry`（`asm/kvm.h`。16 バイト）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmMsrEntry {
    pub index: u32,
    pub reserved: u32,
    pub data: u64,
}

/// `struct kvm_mp_state`（`linux/kvm.h`。4 バイト。x86_64 の AP の INIT/SIPI 待ち状態の読み書き。#3737・MVM-1）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmMpState {
    pub mp_state: u32,
}

/// x86_64 の `struct kvm_fpu`（`asm/kvm.h`。416 バイト）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KvmFpu {
    pub fpr: [[u8; 16]; 8],
    pub fcw: u16,
    pub fsw: u16,
    pub ftwx: u8,
    pub pad1: u8,
    pub last_opcode: u16,
    pub last_ip: u64,
    pub last_dp: u64,
    pub xmm: [[u8; 16]; 16],
    pub mxcsr: u32,
    pub pad2: u32,
}

/// x86_64 の `struct kvm_lapic_state`（`asm/kvm.h`。`char regs[KVM_APIC_REG_SIZE = 0x400]`）。
/// C の `char` は x86_64 で符号付きだがレイアウトは `u8` と同一。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KvmLapicState {
    pub regs: [u8; 1024],
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
impl Default for KvmLapicState {
    fn default() -> Self {
        KvmLapicState { regs: [0; 1024] }
    }
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
mod sealed {
    /// `FlexEntry` を sys の外から実装させないための封印（#3840）。この module も private のため名前を書けない。
    pub trait Sealed {}
}

/// `FlexBuf` の要素型（#3840・MVM-1・MVM-4・REPAIR-2）。sys 内でだけ実装できる（`sealed::Sealed` が private）。
///
/// # Safety
///
/// 実装する型は次をすべて満たすこと。
/// - `#[repr(C)]` で、フィールドは整数（と整数の配列）だけ。どのビットパターンも有効な値になる
///   （`bool`・enum・`char`・参照・ポインタ・`NonZero*` を含まない）。ゼロ埋めの領域やカーネルが書き戻した
///   任意のバイト列をこの型として読んでも UB にならない
/// - `align_of::<Self>() <= 8`（ヘッダ 8 バイトの直後に置くため。各型の const assert で固定する）
/// - レイアウトが uapi の対応する C 構造体と一致する（const assert で固定する）
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
unsafe trait FlexEntry: sealed::Sealed + Copy {}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
impl sealed::Sealed for KvmCpuidEntry2 {}
// SAFETY: repr(C) で u32 のフィールドと [u32; 3] だけ（どのビットパターンも有効）。align 4（<= 8）とサイズ 40 は
// 下の const assert で固定済み。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
unsafe impl FlexEntry for KvmCpuidEntry2 {}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
impl sealed::Sealed for KvmMsrEntry {}
// SAFETY: repr(C) で u32・u32・u64 だけ（どのビットパターンも有効）。align 8（<= 8）とサイズ 16 は
// 下の const assert で固定済み。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
unsafe impl FlexEntry for KvmMsrEntry {}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<KvmCpuidEntry2>() == 40);
    assert!(align_of::<KvmCpuidEntry2>() == 4);
    assert!(offset_of!(KvmCpuidEntry2, flags) == 8);
    assert!(offset_of!(KvmCpuidEntry2, eax) == 12);
    assert!(offset_of!(KvmCpuidEntry2, edx) == 24);
    assert!(offset_of!(KvmCpuidEntry2, padding) == 28);
    assert!(size_of::<KvmMsrEntry>() == 16);
    assert!(align_of::<KvmMsrEntry>() == 8);
    assert!(offset_of!(KvmMsrEntry, data) == 8);
    assert!(size_of::<KvmFpu>() == 416);
    assert!(align_of::<KvmFpu>() == 8);
    assert!(offset_of!(KvmFpu, fcw) == 128);
    assert!(offset_of!(KvmFpu, ftwx) == 132);
    assert!(offset_of!(KvmFpu, last_opcode) == 134);
    assert!(offset_of!(KvmFpu, last_ip) == 136);
    assert!(offset_of!(KvmFpu, last_dp) == 144);
    assert!(offset_of!(KvmFpu, xmm) == 152);
    assert!(offset_of!(KvmFpu, mxcsr) == 408);
    assert!(offset_of!(KvmFpu, pad2) == 412);
    assert!(size_of::<KvmLapicState>() == 1024);
    assert!(align_of::<KvmLapicState>() == 1);
    assert!(size_of::<KvmMpState>() == 4);
    assert!(align_of::<KvmMpState>() == 4);
    assert!(consts::KVM_GET_MP_STATE == 0x8004_AE98);
    assert!(consts::KVM_SET_MP_STATE == 0x4004_AE99);
    assert!(consts::KVM_GET_SUPPORTED_CPUID == 0xC008_AE05);
    assert!(consts::KVM_SET_CPUID2 == 0x4008_AE90);
    assert!(consts::KVM_GET_MSRS == 0xC008_AE88);
    assert!(consts::KVM_SET_MSRS == 0x4008_AE89);
    assert!(consts::KVM_GET_FPU == 0x81A0_AE8C);
    assert!(consts::KVM_SET_FPU == 0x41A0_AE8D);
    assert!(consts::KVM_GET_LAPIC == 0x8400_AE8E);
    assert!(consts::KVM_SET_LAPIC == 0x4400_AE8F);
    assert!(consts::KVM_SET_TSS_ADDR == 0xAE47);
    assert!(consts::KVM_SET_IDENTITY_MAP_ADDR == 0x4008_AE48);
};

/// `struct kvm_userspace_memory_region`（`linux/kvm.h`。32 バイト）。対応外 arch では使われない。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct KvmUserspaceMemoryRegion {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
}

const _: () = {
    assert!(std::mem::size_of::<KvmUserspaceMemoryRegion>() == 32);
    assert!(std::mem::align_of::<KvmUserspaceMemoryRegion>() == 8);
};

/// `struct kvm_dirty_log`（`linux/kvm.h`。16 バイト。#4225・MVM-1）。末尾の union（`void __user *dirty_bitmap` / `__u64 padding2`）は、
/// 対応する LP64 ではポインタと `u64` が同じ大きさ・配置なので `u64` 1 本に平らにする。`libc` に対応物が無いカーネル ABI のため、
/// サイズ・オフセットを const assert で固定する。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KvmDirtyLog {
    slot: u32,
    padding1: u32,
    dirty_bitmap: u64,
}

const _: () = {
    assert!(std::mem::size_of::<KvmDirtyLog>() == 16);
    assert!(std::mem::align_of::<KvmDirtyLog>() == 8);
    assert!(std::mem::offset_of!(KvmDirtyLog, dirty_bitmap) == 8);
};

/// `struct kvm_irqfd`（`linux/kvm.h`。32 バイト。TASK-74.2.3・MVM-1）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct KvmIrqfd {
    fd: u32,
    gsi: u32,
    flags: u32,
    resamplefd: u32,
    pad: [u8; 16],
}

/// `struct kvm_ioeventfd`（`linux/kvm.h`。64 バイト。TASK-74.2.3・MVM-1）。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct KvmIoeventfd {
    datamatch: u64,
    addr: u64,
    len: u32,
    fd: i32,
    flags: u32,
    pad: [u8; 36],
}

/// `struct kvm_irq_level`（`linux/kvm.h`。8 バイト。#3918・MVM-1）。`irq` は共用体 `{ __u32 irq; __s32 status; }`
/// の `irq` 側（`KVM_IRQ_LINE` では入力のみ。結果の書き戻しは `KVM_IRQ_LINE_STATUS`〔番号 0x67〕だけ）。
#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_pointer_width = "64"
))]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct KvmIrqLevel {
    irq: u32,
    level: u32,
}

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_pointer_width = "64"
))]
const _: () = {
    assert!(std::mem::size_of::<KvmIrqLevel>() == 8);
    assert!(std::mem::align_of::<KvmIrqLevel>() == 4);
    assert!(std::mem::offset_of!(KvmIrqLevel, irq) == 0);
    assert!(std::mem::offset_of!(KvmIrqLevel, level) == 4);
};

const _: () = {
    assert!(std::mem::size_of::<KvmIrqfd>() == 32);
    assert!(std::mem::align_of::<KvmIrqfd>() == 4);
    assert!(std::mem::offset_of!(KvmIrqfd, gsi) == 4);
    assert!(std::mem::offset_of!(KvmIrqfd, flags) == 8);
    assert!(std::mem::size_of::<KvmIoeventfd>() == 64);
    assert!(std::mem::align_of::<KvmIoeventfd>() == 8);
    assert!(std::mem::offset_of!(KvmIoeventfd, addr) == 8);
    assert!(std::mem::offset_of!(KvmIoeventfd, len) == 16);
    assert!(std::mem::offset_of!(KvmIoeventfd, fd) == 20);
    assert!(std::mem::offset_of!(KvmIoeventfd, flags) == 24);
};

#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const _: () = {
    assert!(consts::KVM_SET_USER_MEMORY_REGION == 0x4020_AE46);
    assert!(consts::KVM_GET_DIRTY_LOG == 0x4010_AE42);
    assert!(consts::KVM_MEM_LOG_DIRTY_PAGES == 1);
    assert!(consts::KVM_MEM_READONLY == 2);
    assert!(consts::KVM_CAP_READONLY_MEM.0 == 81);
    assert!(consts::KVM_GET_VCPU_MMAP_SIZE == 0xAE04);
    assert!(consts::KVM_RUN == 0xAE80);
    assert!(consts::KVM_CHECK_EXTENSION == 0xAE03);
    assert!(consts::KVM_IRQFD == 0x4020_AE76);
    assert!(consts::KVM_IOEVENTFD == 0x4040_AE79);
};

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const _: () = assert!(consts::KVM_CREATE_IRQCHIP == 0xAE60);

#[cfg(all(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_pointer_width = "64"
))]
const _: () = assert!(consts::KVM_IRQ_LINE == 0x4008_AE61);

/// arm64 の `KVM_IRQ_LINE` の `irq` フィールドの配置（`arch/arm64/include/uapi/asm/kvm.h`。Linux v6.12）。
/// `KVM_ARM_IRQ_TYPE_SHIFT`(24) に種別（SPI = 1）、`KVM_ARM_IRQ_NUM_SHIFT`(0) に INTID（16 ビット）を置く。
/// SPI では vcpu_index は無視されるので 0。`libc` に対応物が無い（カーネルの uapi 定数のみ）ため、機械照合ではなく
/// 値の const assert で固定する（#3943）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
const _: () = {
    assert!(KVM_ARM_IRQ_TYPE_SHIFT == 24);
    assert!(KVM_ARM_IRQ_TYPE_SPI == 1);
    assert!(KVM_ARM_IRQ_NUM_MASK == 0xffff);
    assert!(match arm64_spi_irq_field(33) {
        Some(v) => v == 0x0100_0021,
        None => false,
    });
};

/// `kvm_run.immediate_exit` のオフセット（`linux/kvm.h`）。
const IMMEDIATE_EXIT_OFFSET: usize = 1;

/// ゲストページ 1 枚の大きさとアライン（KVM の memslot は 4 KiB 単位）。
pub(crate) const GUEST_PAGE_SIZE: usize = 4096;

/// Linux の `sigset_t`（glibc・musl とも 1024 bit = 128 バイト。`SIGUSR2` は第 0 語の bit 11）。
#[repr(C)]
#[derive(Clone, Copy)]
struct SigSet([u64; 16]);

/// Linux の `struct sigaction` の共通レイアウト（handler・mask・flags・restorer の順。x86_64・aarch64 の glibc・musl）。
#[repr(C)]
struct SigAction {
    handler: usize,
    mask: SigSet,
    flags: i32,
    restorer: usize,
}

#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const _: () = {
    assert!(std::mem::size_of::<SigSet>() == 128);
    assert!(std::mem::size_of::<SigAction>() == 152);
    assert!(std::mem::align_of::<SigAction>() == 8);
    assert!(std::mem::offset_of!(SigAction, mask) == 8);
    assert!(std::mem::offset_of!(SigAction, flags) == 136);
    assert!(std::mem::offset_of!(SigAction, restorer) == 144);
};

/// `struct pollfd`（`poll.h`。8 バイト。#3698・MVM-1・REPAIR-5）。`revents` はカーネルが書く。
#[repr(C)]
#[derive(Clone, Copy)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

const _: () = {
    assert!(std::mem::size_of::<PollFd>() == 8);
    assert!(std::mem::align_of::<PollFd>() == 4);
    assert!(std::mem::offset_of!(PollFd, events) == 4);
    assert!(std::mem::offset_of!(PollFd, revents) == 6);
};

// SAFETY: 宣言の根拠をここに集約する（対応は glibc の LP64 の x86_64・aarch64 だけで、`consts::SUPPORTED` が
// それ以外では各ラッパーの冒頭で弾くため、型の合わない宣言は呼ばれない。宣言しただけでは未定義動作にならない）。
// - `ioctl`: `int ioctl(int fd, unsigned long request, ...)`（glibc。musl は `request` が `int`）。可変長引数として
//   宣言する（非可変長で宣言して呼ぶと、可変長引数の渡し方が異なる ABI で未定義動作になる）。LP64 で
//   `unsigned long` は u64。可変長部は呼び出し側が u64 かポインタで渡す。
// - `mmap` / `munmap`: LP64 で `size_t` は usize、`off_t` は i64。可変長ではない。
// - `madvise`: `int madvise(void *addr, size_t length, int advice)`（TASK-75.1）。LP64 で `size_t` は usize。可変長ではない。
// - `sysconf`: `long sysconf(int name)`（LP64 で `long` は i64。可変長ではない。副作用なし）。
// - `sigaction`: `SigAction` は上の const assert（152 バイト・mask がオフセット 8・flags が 136・restorer が 144）で
//   固定した x86_64・aarch64 の `struct sigaction` のレイアウト。第 2・3 引数は NULL 可。
// - `pthread_sigmask`: `SigSet` は 128 バイトの `sigset_t`（上の const assert）。第 2・3 引数は NULL 可。
// - `eventfd`: `int eventfd(unsigned int initval, int flags)`（glibc。TASK-74.2.3）。値渡しだけでポインタを取らない。
// - `poll`: `int poll(struct pollfd *fds, nfds_t nfds, int timeout)`（glibc。#3698）。LP64 で `nfds_t` は `unsigned long` = u64。
//   `PollFd` は下の const assert（8 バイト・アライン 4）で固定した `struct pollfd`。可変長ではない。
// - `pthread_self` / `pthread_kill`: `pthread_t` は glibc の LP64 で `unsigned long` = u64。`pthread_kill` は
//   errno を戻り値で返す（errno 変数は触らない）。
unsafe extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64)
    -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    fn madvise(addr: *mut c_void, len: usize, advice: i32) -> i32;
    fn sysconf(name: i32) -> i64;
    fn sigaction(signum: i32, act: *const SigAction, old: *mut SigAction) -> i32;
    fn pthread_sigmask(how: i32, set: *const SigSet, old: *mut SigSet) -> i32;
    fn pthread_self() -> u64;
    fn pthread_kill(thread: u64, sig: i32) -> i32;
    fn eventfd(initval: u32, flags: i32) -> i32;
    fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32;
}

/// `_SC_PAGESIZE`（x86_64・aarch64 Linux とも 30）。
const SC_PAGESIZE: i32 = 30;

/// ホストのページサイズ（バイト）を返す。`KVM_SET_USER_MEMORY_REGION` はサイズと GPA にこれの倍数を要求する
/// （16 KiB / 64 KiB ページの aarch64 Linux では 4096 より大きい。MVM-1・TASK-75.1）。
/// 取得に失敗した・2 の冪でない値は fail-closed に `SysError::Os(22)`（EINVAL）で返す。
pub(crate) fn host_page_size() -> Result<u64, SysError> {
    // 非対応環境（32 bit・非 glibc 等）では FFI 宣言（LP64 の `long` = i64）が成り立たないため呼ばずに拒否する。
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `sysconf` は整数 1 つを取り値を返すだけで、ポインタもメモリも触らない。`consts::SUPPORTED` で
    // LP64 の glibc に限っているため、戻り値の `long` は宣言の i64 と一致する。
    let n = unsafe { sysconf(SC_PAGESIZE) };
    match u64::try_from(n) {
        Ok(v) if v.is_power_of_two() => Ok(v),
        _ => Err(SysError::Os(22)),
    }
}

/// `EBUSY`（x86_64・aarch64 Linux とも 16）。
const EBUSY: i32 = 16;
/// vCPU 中断用のシグナル（`SIGUSR2`。x86_64・aarch64 Linux とも 12）。
const SIG_VCPU_KICK: i32 = 12;
/// `SIG_DFL`。
const SIG_DFL: usize = 0;
/// `pthread_sigmask` の how（Linux 共通: SIG_UNBLOCK = 1、SIG_SETMASK = 2）。
#[cfg(target_arch = "x86_64")]
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;
const SIG_SETMASK: i32 = 2;

extern "C" fn kick_handler(_sig: i32) {}

/// vCPU スレッドへの kick（`pthread_kill`）の宛先セル。常駐の期限監視スレッドと vCPU スレッドが共有する（#4288・MVM-1・REPAIR-5）。
///
/// vCPU スレッドが [`KickCell::armed`] の閉包の中で `KVM_RUN` を発行している間だけ、自分の `pthread_t` がセルに入る。
/// 監視スレッド（`crate::device` の `RunWatchdog`）は [`KickCell::kick`] で、武装中のときだけ送る。
///
/// # 健全性（終了したスレッドへの `pthread_kill` は glibc で未定義動作になりうる）
/// - `armed` は対象スレッド自身の上で閉包を同期実行し、閉包が戻る（panic の巻き戻しを含む。drop guard）前にセルを空へ戻す。
///   閉包の実行中、対象スレッドは終了しないので `pthread_t` は生存し再利用されない
/// - 解除と送信は同じ mutex の下で直列になる。`kick` は mutex を保持したまま `pthread_kill` を発行するため、
///   `armed` が戻った（解除された）後に送信が残ることも、解除途中のスレッドへ送ることも無い
/// - 生存の証明をスレッド結合（scoped thread）に頼らないので、監視スレッドは `'static` の常駐スレッドにできる。
///   `mem::forget` できる guard を外へ出さず、閉包の形だけを公開するため、旧 `KickTarget` の doc にあった却下案
///   （`!Send` guard の借用・`&Scope` 由来のライフタイム）の穴にも当たらない
/// - 二重武装（別スレッドが武装中）は閉包を実行せず `Err` にする（fail-closed。1 つのセルは 1 つの vCPU スレッド専用）
///
/// 対応外の対象（`consts::SUPPORTED` が偽）では `pthread_self` を呼ばず、`armed` が `Unsupported` を返す。
#[derive(Debug, Default)]
pub(crate) struct KickCell {
    target: std::sync::Mutex<Option<u64>>,
}

/// [`KickCell::armed`] の解除 guard（戻り・panic のどちらでもセルを空へ戻す）。
struct Disarm<'a>(&'a KickCell);

impl Drop for Disarm<'_> {
    fn drop(&mut self) {
        *self.0.target.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

impl KickCell {
    /// 呼び出しスレッドを宛先として武装して `f` を同期実行し、戻る前に解除する。`crate::device` の `run_bounded` が
    /// `KVM_RUN` の発行を包むために使う。別スレッドが武装中なら `f` を実行せず `Err(SysError::Os(EBUSY))` を返す。
    pub(crate) fn armed<R>(&self, f: impl FnOnce() -> R) -> Result<R, SysError> {
        if !consts::SUPPORTED {
            return Err(SysError::Unsupported);
        }
        {
            let mut g = self.target.lock().unwrap_or_else(|p| p.into_inner());
            if g.is_some() {
                return Err(SysError::Os(EBUSY));
            }
            // SAFETY: 引数なしで呼び出しスレッドの `pthread_t` を返すだけ。副作用・失敗は無い。
            *g = Some(unsafe { pthread_self() });
        }
        let _disarm = Disarm(self);
        Ok(f())
    }

    /// 武装中なら宛先スレッドへ vCPU 中断シグナルを送って `Ok(true)`、未武装なら何もせず `Ok(false)`。
    pub(crate) fn kick(&self) -> Result<bool, SysError> {
        if !consts::SUPPORTED {
            return Err(SysError::Unsupported);
        }
        let g = self.target.lock().unwrap_or_else(|p| p.into_inner());
        let Some(thread) = *g else {
            return Ok(false);
        };
        // SAFETY: `thread` は `armed` が武装中に `pthread_self` で入れた値で、`armed` の閉包（対象スレッドの上で
        // 同期実行）が戻るまで対象スレッドは生存する。解除は同じ mutex の下で行われ、この `g` を保持している間は
        // 解除されないので、終了したスレッドへは送らない（`Disarm::drop` も同じ `target` の mutex を取る。#4329）。シグナル番号は固定の SIGUSR2。ポインタ引数は無い。
        // 戻り値は errno そのもの。
        let r = unsafe { pthread_kill(thread, SIG_VCPU_KICK) };
        drop(g);
        if r == 0 {
            Ok(true)
        } else {
            Err(SysError::Os(r))
        }
    }
}

/// 呼び出しスレッドで vCPU 中断シグナルのブロックを解除し、drop で元のマスクへ戻す guard。
///
/// スレッドが `SIGUSR2` をブロックしていると `pthread_kill` が配送されず `KVM_RUN` の期限（REPAIR-5）を
/// 保証できないため、実行中だけ解除する。guard を作ったスレッドで drop すること（`!Send`）。
pub(crate) struct KickUnblocked {
    old: SigSet,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl KickUnblocked {
    pub(crate) fn new() -> Result<KickUnblocked, SysError> {
        Self::change(SIG_UNBLOCK)
    }

    /// 自己診断用: `SIGUSR2` をブロックし、drop で元へ戻す（期限の中断がブロック下でも届くことの確認用）。
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn blocked_for_probe() -> Result<KickUnblocked, SysError> {
        Self::change(SIG_BLOCK)
    }

    /// 呼び出しスレッドで `SIGUSR2` がブロックされているか。
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn kick_is_blocked() -> Result<bool, SysError> {
        if !consts::SUPPORTED {
            return Err(SysError::Unsupported);
        }
        let mut cur = SigSet([0; 16]);
        // SAFETY: set は NULL（マスクは変えない）、old は有効な書き込み可能なローカルの `sigset_t` 互換。
        let r = unsafe { pthread_sigmask(SIG_BLOCK, std::ptr::null(), &mut cur) };
        if r != 0 {
            return Err(SysError::Os(r));
        }
        Ok(cur.0[0] & (1u64 << (SIG_VCPU_KICK - 1)) != 0)
    }

    fn change(how: i32) -> Result<KickUnblocked, SysError> {
        if !consts::SUPPORTED {
            return Err(SysError::Unsupported);
        }
        let mut set = SigSet([0; 16]);
        set.0[0] = 1u64 << (SIG_VCPU_KICK - 1);
        let mut old = SigSet([0; 16]);
        // SAFETY: `set` と `old` は 128 バイトの有効な `sigset_t` 互換のローカル変数で、呼び出しの間だけ借りる。
        // how は SIG_BLOCK か SIG_UNBLOCK で呼び出しスレッドのマスクだけを変え、`old` に直前のマスクを書く。戻り値は errno そのもの。
        let r = unsafe { pthread_sigmask(how, &set, &mut old) };
        if r != 0 {
            return Err(SysError::Os(r));
        }
        Ok(KickUnblocked {
            old,
            _not_send: std::marker::PhantomData,
        })
    }
}

impl Drop for KickUnblocked {
    fn drop(&mut self) {
        // SAFETY: `self.old` は `new` が `pthread_sigmask` から受け取った有効なマスク。同じスレッドで元へ戻す
        // （`!Send`）。`old` 出力は NULL（不要）。
        let _ = unsafe { pthread_sigmask(SIG_SETMASK, &self.old, std::ptr::null_mut()) };
    }
}

/// `install_kick_handler` の同期用。照会から導入までを 1 つの臨界区間にして並行呼び出しの競合を防ぐ。
static INSTALL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// vCPU 中断シグナルの何もしない handler を入れる（冪等）。
///
/// `sigaction` で現在の設定を **書き換えずに照会** し、未設定（SIG_DFL）か本 crate の handler のときだけ導入する。
/// 別の handler・SIG_IGN があれば何も変更せず `Err`（他の用途を壊さない）。SA_RESTART は付けない。
///
/// # プロセス全体への影響
/// `SIGUSR2` の handler はプロセス全体の設定で、導入後に元へ戻さない。本 crate を組み込むプロセスは `SIGUSR2` を
/// 他の用途に使わないこと。既に別の handler・SIG_IGN があるときは上書きせず `SysError::Os(EBUSY)` で失敗する。
pub(crate) fn install_kick_handler() -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let ours = kick_handler as extern "C" fn(i32) as usize;
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut cur = SigAction {
        handler: 0,
        mask: SigSet([0; 16]),
        flags: 0,
        restorer: 0,
    };
    // SAFETY: act は NULL（設定は変えない）、old は有効な書き込み可能なローカルの `struct sigaction` 互換。
    let r = unsafe { sigaction(SIG_VCPU_KICK, std::ptr::null(), &mut cur) };
    if r != 0 {
        return Err(last_error());
    }
    if cur.handler == ours {
        return Ok(());
    }
    if cur.handler != SIG_DFL {
        return Err(SysError::Os(EBUSY));
    }
    let new = SigAction {
        handler: ours,
        mask: SigSet([0; 16]),
        flags: 0,
        restorer: 0,
    };
    // SAFETY: `new` は有効な `struct sigaction` 互換で handler は引数 1 つの `extern "C"` 関数（本体は空で
    // async-signal-safe）。old は NULL。固定のシグナル番号。
    let r = unsafe { sigaction(SIG_VCPU_KICK, &new, std::ptr::null_mut()) };
    if r != 0 {
        return Err(last_error());
    }
    Ok(())
}

fn last_error() -> SysError {
    // `last_os_error` は常に OS 由来で `raw_os_error` は `Some` を返すため、`unwrap_or(0)` へは到達しない。
    SysError::Os(io::Error::last_os_error().raw_os_error().unwrap_or(0))
}

/// `KVM_GET_API_VERSION` を発行して API 版数を返す。
pub(crate) fn kvm_get_api_version(fd: BorrowedFd<'_>) -> Result<i32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `fd` は借用中の生存 fd。カーネルは `KVM_GET_API_VERSION` で引数が非 0 だと EINVAL を返すため、
    // 可変長部に 0 を明示して渡す（省略するとレジスタの残値が引数になり間欠的に失敗する）。ポインタではなく
    // 値渡しなので、カーネルはユーザー空間のメモリを読み書きしない（戻り値が版数）。
    let r = unsafe { ioctl(fd.as_raw_fd(), consts::KVM_GET_API_VERSION, 0u64) };
    if r < 0 { Err(last_error()) } else { Ok(r) }
}

/// `KVM_CREATE_VM` を発行して VM fd を返す。`machine_type` は x86_64・aarch64 とも 0 が既定。
pub(crate) fn kvm_create_vm(fd: BorrowedFd<'_>, machine_type: u64) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `fd` は借用中の生存 fd。`machine_type` は値渡しの `unsigned long` でポインタを含まず、
    // カーネルはユーザー空間のメモリを読み書きしない。
    let r = unsafe { ioctl(fd.as_raw_fd(), consts::KVM_CREATE_VM, machine_type) };
    if r < 0 {
        return Err(last_error());
    }
    // SAFETY: `r` は直前の ioctl が返した非負の新規 fd（KVM が `O_CLOEXEC` 付きで作る）で、他に所有者が
    // おらず `OwnedFd` が唯一の所有者になる。
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

/// `KVM_CREATE_VCPU` を VM fd に発行して vCPU fd を返す（x86_64 はこれだけで使用可能。aarch64 は別途初期化が要る）。
pub(crate) fn kvm_create_vcpu(vm: BorrowedFd<'_>, id: u64) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `vm` は借用中の生存 fd。`id` は値渡しの `unsigned long` でポインタを含まず、カーネルは
    // ユーザー空間のメモリを読み書きしない。
    let r = unsafe { ioctl(vm.as_raw_fd(), consts::KVM_CREATE_VCPU, id) };
    if r < 0 {
        return Err(last_error());
    }
    // SAFETY: `r` は直前の ioctl が返した非負の新規 fd（KVM が `O_CLOEXEC` 付きで作る）で、他に所有者が
    // おらず `OwnedFd` が唯一の所有者になる。
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}
/// `KVM_GET_VCPU_MMAP_SIZE`（KVM デバイス fd）で vCPU fd の `kvm_run` 領域の mmap サイズを得る。
pub(crate) fn kvm_get_vcpu_mmap_size(kvm: BorrowedFd<'_>) -> Result<usize, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `kvm` は借用中の生存 fd。引数は値渡しの 0（`KVM_GET_API_VERSION` と同様、非 0 を避けるため明示）で
    // ポインタを含まず、カーネルはユーザー空間のメモリを読み書きしない（戻り値がサイズ）。
    let r = unsafe { ioctl(kvm.as_raw_fd(), consts::KVM_GET_VCPU_MMAP_SIZE, 0u64) };
    if r < 0 {
        return Err(last_error());
    }
    // `r >= 0` の i32 は LP64 の usize に必ず収まるため、`Os(0)` の分岐へは到達しない。
    usize::try_from(r).map_err(|_| SysError::Os(0))
}

/// `KVM_RUN`（vCPU fd）を 1 回発行する。ゲストが exit するかシグナルを受けるまで戻らない（期限は持たない）。
///
/// 戻った後の exit 内容は `KvmRunMap` の `kvm_run` 領域に書かれる。呼び出し側は `&mut VcpuFd` 経由でだけ
/// 発行し、同じ領域への読み取りと重ならないようにする。
pub(crate) fn kvm_run(vcpu: BorrowedFd<'_>) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `vcpu` は借用中の生存 fd。引数は値渡しの 0 でポインタを含まない。カーネルは vCPU fd に mmap 済みの
    // `kvm_run` 領域と登録済みの memslot にだけ書く。両者の寿命は呼び出し元の所有型（`KvmRunMap`・
    // `RegisteredPage`）が呼び出し中に維持する。呼び出しはブロックしうるが同期で完了し、戻り後にポインタを保持しない。
    let r = unsafe { ioctl(vcpu.as_raw_fd(), consts::KVM_RUN, 0u64) };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// 非ブロック・close-on-exec・初期値 0 の eventfd を作る（ioeventfd / irqfd の通知先。TASK-74.2.3・MVM-1）。
pub(crate) fn eventfd_new() -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: 値渡しの 2 引数だけでポインタを取らず、ユーザー空間のメモリを読み書きしない。
    // 戻り値が負なら失敗（errno は直後に確保する）。
    let r = unsafe { eventfd(0, consts::EFD_CLOEXEC | consts::EFD_NONBLOCK) };
    if r < 0 {
        return Err(last_error());
    }
    // SAFETY: `r` は直前の `eventfd` が返した非負の新規 fd で、他に所有者がおらず `OwnedFd` が唯一の所有者になる。
    Ok(unsafe { OwnedFd::from_raw_fd(r) })
}

/// [`poll_readable`] が一度に待てる fd の最大数（無制限の確保・引数を防ぐ。REPAIR-5）。
pub(crate) const MAX_POLL_FDS: usize = 32;
/// [`poll_readable`] の 1 回の待ちの上限（呼び出し側の誤りで実質無期限にしない。REPAIR-5）。
pub(crate) const MAX_POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// `fds` のどれかが読めるようになるか `timeout` が尽きるまで待つ（`poll(2)`。#3698・MVM-1・REPAIR-5）。
///
/// 呼び出し元は ioeventfd の通知スレッド（`microvm::IoEventPoller`）。`ready[i]` に `fds[i]` の結果（[`PollReadiness`]）を書き、
/// `Idle` 以外の件数を返す。読める（`POLLIN` のみ）は `Readable`、異常（`POLLERR` / `POLLHUP` / `POLLNVAL`）は `POLLIN` が
/// 同時に立っていても `Abnormal`（#4101・REPAIR-5。異常を読める扱いにすると `take` が 0 を返して即時に戻り続け空回りする）。
/// `ready` は先に全て `Idle` に戻す。
/// `fds` と `ready` の長さが違う・`MAX_POLL_FDS` 超過は `Os(EINVAL)`。`timeout` は ms に切り上げ [`MAX_POLL_TIMEOUT`] で頭打ち
/// （無期限・負値は渡さない）。`EINTR` は 0 件の成功として返す（呼び出し側が次の周回で再度待つ）。
pub(crate) fn poll_readable(
    fds: &[BorrowedFd<'_>],
    timeout: std::time::Duration,
    ready: &mut [PollReadiness],
) -> Result<usize, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    if fds.len() != ready.len() || fds.len() > MAX_POLL_FDS {
        return Err(SysError::Os(22));
    }
    ready.fill(PollReadiness::Idle);
    let mut pfds = [PollFd {
        fd: -1,
        events: 0,
        revents: 0,
    }; MAX_POLL_FDS];
    for (slot, fd) in pfds.iter_mut().zip(fds) {
        *slot = PollFd {
            fd: fd.as_raw_fd(),
            events: consts::POLLIN,
            revents: 0,
        };
    }
    let capped = timeout.min(MAX_POLL_TIMEOUT);
    let ms = capped
        .as_millis()
        .saturating_add(u128::from(!capped.subsec_nanos().is_multiple_of(1_000_000)));
    let ms = i32::try_from(ms).unwrap_or(i32::MAX);
    // SAFETY: `pfds` は長さ `MAX_POLL_FDS` のローカル配列で、`nfds` は `fds.len()`（<= `MAX_POLL_FDS`）なので
    // カーネルが触る範囲は配列内に収まる。各 fd は `fds` の借用で呼び出しの間生きている。カーネルが書くのは各要素の
    // `revents` だけで、呼び出しは同期的に戻り、戻った後にポインタは保持されない。`timeout` は 0 以上の有限値。
    let r = unsafe { poll(pfds.as_mut_ptr(), fds.len() as u64, ms) };
    if r < 0 {
        return match last_error() {
            SysError::Os(4) => Ok(0),
            e => Err(e),
        };
    }
    let mut n = 0;
    for (slot, p) in ready.iter_mut().zip(&pfds) {
        *slot = classify_revents(p.revents);
        if *slot != PollReadiness::Idle {
            n += 1;
        }
    }
    Ok(n)
}

/// [`poll_readable`] が fd ごとに返す結果（#4101・MVM-1・REPAIR-5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PollReadiness {
    /// 何も起きていない。
    Idle,
    /// `POLLIN` だけが立った（読んで処理する）。
    Readable,
    /// `POLLERR` / `POLLHUP` / `POLLNVAL` のどれかが立った（`POLLIN` の有無によらない）。`revents` はカーネルが返した値。
    Abnormal { revents: i16 },
}

/// `poll(2)` の `revents` を分類する。異常ビットは `POLLIN` より優先する。
pub(crate) fn classify_revents(revents: i16) -> PollReadiness {
    let abnormal = consts::POLLERR | consts::POLLHUP | consts::POLLNVAL;
    if revents & abnormal != 0 {
        PollReadiness::Abnormal { revents }
    } else if revents & consts::POLLIN != 0 {
        PollReadiness::Readable
    } else {
        PollReadiness::Idle
    }
}

/// `KVM_CHECK_EXTENSION` に渡せる `KVM_CAP_*` の番号（#3679・P3-6）。フィールドは `sys` の外から見えず、
/// 任意の `u64` は作れない。値は `consts::KVM_CAP_*` だけが持つ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KvmCap(u64);

/// `KVM_CHECK_EXTENSION`（KVM デバイス fd または VM fd）。戻り値は拡張の対応状況（0 は非対応）。
pub(crate) fn kvm_check_extension(fd: BorrowedFd<'_>, cap: KvmCap) -> Result<i32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `fd` は借用中の生存 fd。`cap.0` は `KvmCap`（`KVM_CAP_*` の定数だけが作れる）の値渡しの
    // `unsigned long` でポインタを含まず、カーネルはユーザー空間のメモリを読み書きしない（戻り値が結果）。
    let r = unsafe { ioctl(fd.as_raw_fd(), consts::KVM_CHECK_EXTENSION, cap.0) };
    if r < 0 { Err(last_error()) } else { Ok(r) }
}

/// `KVM_CREATE_IRQCHIP`（VM fd。x86_64 のみ。vCPU を作る前に発行する）。他 arch は `Unsupported`
/// （aarch64 の vGIC は `KVM_CREATE_DEVICE` で別方式。`kvm_create_device`・#3696）。
pub(crate) fn kvm_create_irqchip(vm: BorrowedFd<'_>) -> Result<(), SysError> {
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    {
        if !consts::SUPPORTED {
            return Err(SysError::Unsupported);
        }
        // SAFETY: `vm` は借用中の生存 fd。引数は値渡しの 0 でポインタを含まず、カーネルは
        // ユーザー空間のメモリを読み書きしない。
        let r = unsafe { ioctl(vm.as_raw_fd(), consts::KVM_CREATE_IRQCHIP, 0u64) };
        if r < 0 { Err(last_error()) } else { Ok(()) }
    }
    #[cfg(not(all(target_arch = "x86_64", target_pointer_width = "64")))]
    {
        let _ = vm;
        Err(SysError::Unsupported)
    }
}

/// arm64 の `KVM_IRQ_LINE` の `irq` フィールドの種別の位置（`KVM_ARM_IRQ_TYPE_SHIFT`。#3943）。
pub(crate) const KVM_ARM_IRQ_TYPE_SHIFT: u32 = 24;
/// arm64 の種別 SPI（`KVM_ARM_IRQ_TYPE_SPI`。#3943）。
pub(crate) const KVM_ARM_IRQ_TYPE_SPI: u32 = 1;
/// arm64 の `irq` フィールドの INTID 部のマスク（`KVM_ARM_IRQ_NUM_MASK`。#3943）。
pub(crate) const KVM_ARM_IRQ_NUM_MASK: u32 = 0xffff;

/// arm64 の `KVM_IRQ_LINE` の `irq` フィールドを SPI の INTID から作る（#3943・MVM-1）。
/// `(KVM_ARM_IRQ_TYPE_SPI << 24) | intid`。INTID が 16 ビットに収まらないときは `None`（呼び出し側が範囲を先に検査する）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) const fn arm64_spi_irq_field(intid: u32) -> Option<u32> {
    if intid > KVM_ARM_IRQ_NUM_MASK {
        return None;
    }
    Some((KVM_ARM_IRQ_TYPE_SPI << KVM_ARM_IRQ_TYPE_SHIFT) | intid)
}

/// `KVM_IRQ_LINE`（VM fd。x86_64 と aarch64。in-kernel irqchip が前提）。`irq` の線を `level` に駆動する。
/// `irq` は `kvm_irq_level.irq` にそのまま入る値で、x86_64 は GSI、aarch64 は `arm64_spi_irq_field` のエンコード済みの値。
/// edge 注入の `KVM_IRQFD` と違い、線の値そのものを持つので level 線（`LevelInterruptLine`）に使える（#3918・#3943・MVM-1）。
/// irqchip が無い VM fd では `ENXIO`。他 arch は `Unsupported`。
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    allow(dead_code)
)]
pub(crate) fn kvm_irq_line(vm: BorrowedFd<'_>, irq: u32, level: bool) -> Result<(), SysError> {
    #[cfg(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_pointer_width = "64"
    ))]
    {
        if !consts::SUPPORTED {
            return Err(SysError::Unsupported);
        }
        let arg = KvmIrqLevel {
            irq,
            level: u32::from(level),
        };
        // SAFETY: `vm` は借用中の生存 fd。`arg` は `repr(C)` で 8 バイト（const assert 済み・ioctl 番号のサイズ符号と一致）の
        // ローカルの借用で、カーネルはこの 8 バイトを読むだけで書かず（結果の書き戻しは `KVM_IRQ_LINE_STATUS` だけ）、
        // 呼び出しは同期で完了して戻り後にポインタを保持しない。
        let r = unsafe {
            ioctl(
                vm.as_raw_fd(),
                consts::KVM_IRQ_LINE,
                &arg as *const KvmIrqLevel,
            )
        };
        if r < 0 { Err(last_error()) } else { Ok(()) }
    }
    #[cfg(not(all(
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_pointer_width = "64"
    )))]
    {
        let _ = (vm, irq, level);
        Err(SysError::Unsupported)
    }
}

/// `KVM_IRQFD`（VM fd）。`event` への書き込みで GSI `gsi` の割り込みを注入する。`deassign` で登録を解く
/// （解除は登録時と同じ `event` と `gsi` で行う）。
pub(crate) fn kvm_irqfd(
    vm: BorrowedFd<'_>,
    event: BorrowedFd<'_>,
    gsi: u32,
    deassign: bool,
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let arg = KvmIrqfd {
        fd: u32::try_from(event.as_raw_fd()).map_err(|_| SysError::Os(9))?,
        gsi,
        flags: if deassign {
            consts::KVM_IRQFD_FLAG_DEASSIGN
        } else {
            0
        },
        resamplefd: 0,
        pad: [0; 16],
    };
    // SAFETY: `vm` は借用中の生存 fd。`arg` は `repr(C)` で 32 バイト（const assert 済み・ioctl 番号のサイズ符号と一致）の
    // ローカルの借用で、カーネルはこの 32 バイトを読むだけで書かず、呼び出しは同期で完了して戻り後にポインタを保持しない。
    // `arg.fd` は借用中の生存 fd の番号。
    let r = unsafe { ioctl(vm.as_raw_fd(), consts::KVM_IRQFD, &arg as *const KvmIrqfd) };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `KVM_IOEVENTFD`（VM fd）。ゲストが `addr`（`pio` ならポート）へ `len` バイト書くと `event` が発火し、VM exit は起きない。
/// `datamatch` が `Some` のときは書かれた値が一致したときだけ発火する。引数の組み合わせの検証は上位の型で済ませる。
pub(crate) fn kvm_ioeventfd(
    vm: BorrowedFd<'_>,
    event: BorrowedFd<'_>,
    addr: u64,
    len: u32,
    datamatch: Option<u64>,
    pio: bool,
    deassign: bool,
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut flags = 0;
    if datamatch.is_some() {
        flags |= consts::KVM_IOEVENTFD_FLAG_DATAMATCH;
    }
    if pio {
        flags |= consts::KVM_IOEVENTFD_FLAG_PIO;
    }
    if deassign {
        flags |= consts::KVM_IOEVENTFD_FLAG_DEASSIGN;
    }
    let arg = KvmIoeventfd {
        datamatch: datamatch.unwrap_or(0),
        addr,
        len,
        fd: event.as_raw_fd(),
        flags,
        pad: [0; 36],
    };
    // SAFETY: `vm` は借用中の生存 fd。`arg` は `repr(C)` で 64 バイト（const assert 済み・ioctl 番号のサイズ符号と一致）の
    // ローカルの借用で、カーネルはこの 64 バイトを読むだけで書かず、呼び出しは同期で完了して戻り後にポインタを保持しない。
    // `arg.fd` は借用中の生存 fd の番号。
    let r = unsafe {
        ioctl(
            vm.as_raw_fd(),
            consts::KVM_IOEVENTFD,
            &arg as *const KvmIoeventfd,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// vCPU fd に mmap した `kvm_run` 領域の所有型。drop で munmap する。
///
/// 領域はカーネルが `KVM_RUN` 中に書き換える共有メモリのため、`&[u8]` / `&mut [u8]` は作らず、
/// 範囲検査つきの volatile コピーだけで読む（Rust のエイリアシング規則に反する参照を残さない）。
#[derive(Debug)]
pub(crate) struct KvmRunMap {
    ptr: NonNull<u8>,
    len: usize,
    /// drop の munmap 失敗を数える VM ごとの集約先（観測専用。#4382）。
    unmap_tally: Option<Arc<UnmapTally>>,
}

// SAFETY: 領域への書き込みはカーネルが `KVM_RUN` の実行中にだけ行い、`KVM_RUN` は `&mut VcpuFd` 経由でしか
// 発行されないため、`&self` からの読み取りと重ならない。ポインタはマッピングの生存中（drop まで）有効で、
// スレッドに固有ではない。
unsafe impl Send for KvmRunMap {}
// SAFETY: 上と同じ。共有参照から行うのは volatile の読み取りと、`immediate_exit`（オフセット 1）の
// `AtomicU8` による読み書きだけで、後者は期限監視スレッドと同時でもデータ競合にならない。カーネルによる書き込みは
// `&mut VcpuFd` 経由の `KVM_RUN` の間だけ。`write_from` は `&mut self` で排他的で、オフセット 1 には触らない。
// 型では強制できない前提: `KVM_RUN` の実行中に `read_into` を呼ばない（カーネルの書き込みと volatile の読み取りが
// 重なる）。実行中に `&KvmRunMap` へ触ってよいのは `run_bounded` の監視スレッドの `set_immediate_exit` だけ。
unsafe impl Sync for KvmRunMap {}

impl KvmRunMap {
    /// vCPU fd の先頭から `len` バイトを読み書き可能・共有で mmap する。`len` は呼び出し側が検証済み
    /// （非 0・上限内・ページ倍数）のものだけを渡す。
    ///
    /// `tally` は drop の munmap 失敗の件数を VM ごとに集約する先（停止・解放の集約行の `unmap_failures=`。#4382）。
    pub(crate) fn map(
        vcpu: BorrowedFd<'_>,
        len: usize,
        tally: Option<Arc<UnmapTally>>,
    ) -> Result<KvmRunMap, SysError> {
        if !consts::SUPPORTED {
            return Err(SysError::Unsupported);
        }
        // SAFETY: addr に NULL を渡すためカーネルが配置を選び、既存のマッピングを上書きしない。`vcpu` は借用中の
        // 生存 fd、オフセット 0 は KVM が `kvm_run` を割り当てる位置。戻り値は `MAP_FAILED` を比較してから使う。
        let p = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                consts::PROT_READ | consts::PROT_WRITE,
                consts::MAP_SHARED,
                vcpu.as_raw_fd(),
                0,
            )
        };
        if p as usize == usize::MAX {
            return Err(last_error());
        }
        match NonNull::new(p.cast::<u8>()) {
            Some(ptr) => Ok(KvmRunMap {
                ptr,
                len,
                unmap_tally: tally,
            }),
            None => {
                // SAFETY: 直前の mmap が返した長さ `len` の領域そのもので、他に所有者がいない。
                // 戻った後は `p` を使わない。
                Err(unsafe {
                    rollback_failed_map(p, len, KVM_RUN_UNMAP_FAILED_LINE, SysError::NullMapping)
                })
            }
        }
    }

    /// `off..off+buf.len()` を `buf` へ volatile でコピーする。範囲外・桁あふれは `Err`（添字アクセスをしない）。
    ///
    /// `KVM_RUN` の実行中は呼んではならない（カーネルの書き込みと重なる。型では強制できない前提。`Sync` の SAFETY を参照）。
    pub(crate) fn read_into(&self, off: usize, buf: &mut [u8]) -> Result<(), ()> {
        let end = off.checked_add(buf.len()).ok_or(())?;
        if end > self.len {
            return Err(());
        }
        for (i, b) in buf.iter_mut().enumerate() {
            // SAFETY: `off + i < end <= len` を上で検査済みで、`ptr` は `len` バイトのマッピングの先頭。
            // マッピングは `self` の生存中有効。呼び出しは `KVM_RUN` の外に限る（上の doc）ため、カーネルの書き込みと重ならない。
            // 参照を作らず volatile で 1 バイト読む。
            // `immediate_exit` のバイトだけは期限監視スレッドが `AtomicU8` で書くため、atomic load で読む
            // （atomic と非 atomic のアクセスを混ぜない。u8 のためアラインは自明）。
            *b = unsafe {
                let p = self.ptr.as_ptr().add(off + i);
                if off + i == IMMEDIATE_EXIT_OFFSET {
                    AtomicU8::from_ptr(p).load(Ordering::SeqCst)
                } else {
                    p.read_volatile()
                }
            };
        }
        Ok(())
    }

    /// `buf` を `off..off+buf.len()` へ volatile でコピーする（IN・MMIO read の応答の書き戻し。TASK-74.4.2）。
    /// 範囲外・桁あふれは `Err`。`&mut self` を要求するのは、`KVM_RUN` が `&mut VcpuFd` 経由でしか発行されず、
    /// 書き戻しとカーネルの `kvm_run` への書き込みが重ならないことを型で保つため。
    ///
    /// `immediate_exit`（オフセット 1）に重なる範囲は 1 バイトも書かずに `Err`（多重防御。#3679・P3-3）。
    /// このバイトは `AtomicU8` で触る約束で、volatile の非 atomic 書き込みを混ぜない。空の範囲は何も書かず `Ok`。
    pub(crate) fn write_from(&mut self, off: usize, buf: &[u8]) -> Result<(), ()> {
        let end = off.checked_add(buf.len()).ok_or(())?;
        if end > self.len {
            return Err(());
        }
        if off <= IMMEDIATE_EXIT_OFFSET && IMMEDIATE_EXIT_OFFSET < end {
            return Err(());
        }
        for (i, b) in buf.iter().enumerate() {
            // SAFETY: `off + i < end <= len` を上で検査済みで、`ptr` は `len` バイトのマッピングの先頭。
            // マッピングは `self` の生存中有効で、PROT_WRITE で mmap 済み。`&mut self` のため `KVM_RUN` の実行中
            // （カーネルが領域を書く間）には呼ばれない。`immediate_exit` のバイトは上で除外済みで、参照を作らず volatile で
            // 1 バイトだけ書く。
            unsafe { self.ptr.as_ptr().add(off + i).write_volatile(*b) };
        }
        Ok(())
    }

    /// `kvm_run.immediate_exit`（オフセット 1 の u8）を立てる / 下ろす。立てると次の（または実行中の）
    /// `KVM_RUN` がゲストを実行せず EINTR で戻る。別スレッドの期限監視が呼ぶ。
    pub(crate) fn set_immediate_exit(&self, on: bool) -> Result<(), ()> {
        if self.len <= IMMEDIATE_EXIT_OFFSET {
            return Err(());
        }
        // SAFETY: `IMMEDIATE_EXIT_OFFSET < len` を上で検査済みで、`ptr` は `len` バイトのマッピングの先頭。
        // マッピングは `self` の生存中有効で、u8 のためアラインは自明。このバイトは KVM がユーザー空間の書き込みを
        // 前提に読む ABI。Rust 側でこのバイトに触るのは、この atomic store と `read_into` の atomic load だけ
        // （`write_from` は範囲検査でこのバイトを拒否する）。SeqCst は呼び出し側の
        // `timed_out` の store と順序を揃え、その後の `KickCell::kick` より前に見えることを保証する。
        // カーネル側の読み取り（READ_ONCE）は Rust のメモリモデルの外にある。
        unsafe {
            AtomicU8::from_ptr(self.ptr.as_ptr().add(IMMEDIATE_EXIT_OFFSET))
                .store(u8::from(on), Ordering::SeqCst);
        }
        Ok(())
    }
}

impl RunArea for KvmRunMap {
    fn len(&self) -> usize {
        self.len
    }
    fn copy_out(&self, off: usize, buf: &mut [u8]) -> Result<(), ()> {
        self.read_into(off, buf)
    }
}

impl RunAreaMut for KvmRunMap {
    fn copy_in(&mut self, off: usize, buf: &[u8]) -> Result<(), ()> {
        self.write_from(off, buf)
    }
}

impl Drop for KvmRunMap {
    fn drop(&mut self) {
        // SAFETY: `ptr` / `len` は `map` が成功した mmap の戻り値と長さそのもので、drop は 1 度だけ呼ばれる。
        // 失敗しても再試行・panic はせずリークを受け入れ、固定の 1 行で観測するだけにする（#4330・REPAIR-4）。
        // 試験は ptr をずらして EINVAL を起こすが、munmap は引数を参照外ししない。
        let rc = unsafe { munmap(self.ptr.as_ptr().cast::<c_void>(), self.len) };
        if let Some(line) = unmap_failure_line(rc, KVM_RUN_UNMAP_FAILED_LINE) {
            crate::hvf_loop::log_line(format_args!("{line}"));
            if let Some(t) = &self.unmap_tally {
                t.record_failure();
            }
        }
    }
}

/// 自己診断用の 4 KiB のゲストページ（`alloc_zeroed` したヒープ）。登録前だけ書き込める。
///
/// `Box` を使わないのは、登録後にカーネル（ゲスト）が書く領域へ Rust の一意参照を残さないため。
/// 汎用のゲストメモリ backing は #696（TASK-75.1）の担当で、これは #882 の自己診断専用
/// （docs/design/microvm-memory-ownership.md「#882 の例外」）。
#[derive(Debug)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) struct GuestPage {
    ptr: NonNull<u8>,
}

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
impl GuestPage {
    fn layout() -> Layout {
        // サイズとアラインは定数（4096・2 冪）で、`from_size_align` は失敗しない。
        match Layout::from_size_align(GUEST_PAGE_SIZE, GUEST_PAGE_SIZE) {
            Ok(l) => l,
            Err(_) => unreachable!("4096/4096 is a valid layout"),
        }
    }

    /// ゼロ埋めの 1 ページを確保する。確保失敗は `ENOMEM`。
    pub(crate) fn new() -> Result<GuestPage, SysError> {
        // SAFETY: レイアウトのサイズは非 0。戻り値の null は直後に検査する。
        let p = unsafe { alloc_zeroed(Self::layout()) };
        NonNull::new(p)
            .map(|ptr| GuestPage { ptr })
            .ok_or(SysError::Os(12))
    }

    /// `off` から `data` を書く。範囲外・桁あふれは `Err`。登録前（`RegisteredPage` に渡す前）だけ呼べる。
    pub(crate) fn write_at(&mut self, off: usize, data: &[u8]) -> Result<(), ()> {
        let end = off.checked_add(data.len()).ok_or(())?;
        if end > GUEST_PAGE_SIZE {
            return Err(());
        }
        // SAFETY: `off + data.len() <= 4096` を検査済みで、`ptr` は 4096 バイトの確保の先頭。`&mut self` で
        // 排他的（未登録のためカーネルも触らない）。`data` は別の確保で重ならない。
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.as_ptr().add(off), data.len());
        }
        Ok(())
    }
}

impl Drop for GuestPage {
    fn drop(&mut self) {
        // SAFETY: `ptr` は `new` が同じレイアウトで確保したもので、drop は 1 度だけ。登録中のページは
        // `RegisteredPage` が所有し、slot の削除に成功した後にだけここへ来る（失敗時は `forget` で漏らす）。
        unsafe { dealloc(self.ptr.as_ptr(), Self::layout()) };
    }
}

/// `KVM_SET_USER_MEMORY_REGION` で VM に登録済みの 1 ページ。
///
/// 生存中は VM fd を借用し（`'vm`）、VM fd より先に drop されることを型で保証する。ページの中身へ触る口は持たない。
#[derive(Debug)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) struct RegisteredPage<'vm> {
    vm: BorrowedFd<'vm>,
    slot: u32,
    page: Option<GuestPage>,
}

/// `KVM_SET_USER_MEMORY_REGION` に渡す構造体を組む純関数（flags の値を単体試験で照合するため分離。#4158・MVM-1）。
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn memory_region(
    slot: u32,
    flags: u32,
    gpa: u64,
    size: u64,
    userspace_addr: u64,
) -> KvmUserspaceMemoryRegion {
    KvmUserspaceMemoryRegion {
        slot,
        flags,
        guest_phys_addr: gpa,
        memory_size: size,
        userspace_addr,
    }
}

/// `flags` は呼び出し側（`crate::memslot_flags`）が既知ビットと対応の確認を済ませた値。削除（`size = 0`）は 0 を渡す。
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) fn set_user_memory_region(
    vm: BorrowedFd<'_>,
    slot: u32,
    flags: u32,
    gpa: u64,
    size: u64,
    userspace_addr: u64,
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let region = memory_region(slot, flags, gpa, size, userspace_addr);
    // SAFETY: `vm` は借用中の生存 fd（`flags` の値は 32 バイトの読み取りという不変条件に影響しない）。`region` は `repr(C)` で 32 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）のローカルの借用で、カーネルはこの 32 バイトを読むだけで書かず、呼び出しは同期で完了して
    // 戻り後にポインタを保持しない。`userspace_addr` の指す領域の寿命は `RegisteredPage` と `RegisteredGuestRam`（`crate::microvm`）が維持する。
    let r = unsafe {
        ioctl(
            vm.as_raw_fd(),
            consts::KVM_SET_USER_MEMORY_REGION,
            &region as *const KvmUserspaceMemoryRegion,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `KVM_GET_DIRTY_LOG` がカーネルへ書き込むバイト数（`kvm_dirty_bitmap_bytes`。Linux v6.12 `include/linux/kvm_host.h`）。
///
/// `ALIGN(npages, BITS_PER_LONG) / 8` で、`npages = memory_size / page_size`（ホストのページ単位）。BITS_PER_LONG は
/// 対応する LP64 の 2 アーキとも 64 なので 64 ページ単位で切り上げた 8 の倍数になる（`ceil(npages / 8)` ではない）。
/// `page_size` が 0・2 の冪でない、`memory_size` が `page_size` の倍数でない、桁あふれは `None`（#4225・MVM-1）。
pub(crate) const fn dirty_bitmap_bytes(memory_size: u64, page_size: u64) -> Option<u64> {
    if page_size == 0 || !page_size.is_power_of_two() || !memory_size.is_multiple_of(page_size) {
        return None;
    }
    (memory_size / page_size).div_ceil(64).checked_mul(8)
}

/// `KVM_GET_DIRTY_LOG` に渡す構造体を組む純関数（単体試験で値を照合するため分離。#4225）。
fn dirty_log_request(slot: u32, bitmap_addr: u64) -> KvmDirtyLog {
    KvmDirtyLog {
        slot,
        padding1: 0,
        dirty_bitmap: bitmap_addr,
    }
}

/// `KVM_GET_DIRTY_LOG`（VM fd）で `slot` の dirty bitmap を `bitmap` へ読む（#4225・MVM-1）。
///
/// `memory_size` は `slot` に登録した memslot のサイズ。カーネルが書く長さ（[`dirty_bitmap_bytes`]）はこれとホストの
/// ページサイズで決まるため、本関数が ioctl の前に `bitmap.len()` がそれ以上であることを確かめる（不足・不正なサイズは
/// `SysError::Os(22)`〔EINVAL〕で、ioctl は呼ばない）。読み取りと同時にカーネル側の dirty 状態はクリアされる。
/// 呼び出し元は `crate::microvm` の `RegisteredGuestRam` に限る（slot と `memory_size` の対応はそこが登録時に固定する）。
pub(crate) fn kvm_get_dirty_log(
    vm: BorrowedFd<'_>,
    slot: u32,
    memory_size: u64,
    bitmap: &mut [u8],
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let page_size = host_page_size()?;
    let need = dirty_bitmap_bytes(memory_size, page_size).ok_or(SysError::Os(22))?;
    // カーネルは `memory_size` ではなく slot に現在登録されている領域の長さを書くため、差し替えに備えて
    // 登録しうる最大の領域の bitmap 長（`MAX_DIRTY_BITMAP_BYTES`）以上も要求する。
    let required = need.max(crate::dirty_log::MAX_DIRTY_BITMAP_BYTES as u64);
    if u64::try_from(bitmap.len()).map_or(true, |have| have < required) {
        return Err(SysError::Os(22));
    }
    let arg = dirty_log_request(slot, bitmap.as_mut_ptr() as usize as u64);
    // SAFETY: `vm` は借用中の生存 fd。`arg` は `repr(C)` で 16 バイト（const assert 済み・ioctl 番号のサイズ符号と一致）の
    // ローカルの借用。ioctl 番号は `_IOW` だが、カーネルは `arg.dirty_bitmap` の先へ `kvm_dirty_bitmap_bytes(memslot)` バイトを
    // 書く（`arg` 自体は読むだけ）。その長さは登録時の `memory_size` とホストの `PAGE_SIZE` から決まり、直前の検査で
    // `bitmap`（排他借用のバッファ）が `MAX_DIRTY_BITMAP_BYTES`（登録しうる最大の領域の bitmap 長）以上だと確かめ済み。
    // slot が呼び出し後に差し替わっても、登録できる領域は `MAX_GUEST_RAM_BYTES` 以下なので書き込みは `bitmap` の範囲に収まる。
    // 呼び出しは同期で完了し、戻り後にカーネルはポインタを保持しない。
    let r = unsafe {
        ioctl(
            vm.as_raw_fd(),
            consts::KVM_GET_DIRTY_LOG,
            &arg as *const KvmDirtyLog,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `page` を `slot` / `gpa` で VM に登録する。失敗時は `page` を返す（呼び出し側が解放できる）。
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub(crate) fn register_single_page<'vm>(
    vm: BorrowedFd<'vm>,
    slot: u32,
    gpa: u64,
    page: GuestPage,
) -> Result<RegisteredPage<'vm>, (SysError, GuestPage)> {
    match set_user_memory_region(
        vm,
        slot,
        0,
        gpa,
        GUEST_PAGE_SIZE as u64,
        page.ptr.as_ptr() as usize as u64,
    ) {
        Ok(()) => Ok(RegisteredPage {
            vm,
            slot,
            page: Some(page),
        }),
        Err(e) => Err((e, page)),
    }
}

impl Drop for RegisteredPage<'_> {
    fn drop(&mut self) {
        // `memory_size = 0` の再登録で slot を削除する（gpa・userspace_addr は無視される）。
        let removed = set_user_memory_region(self.vm, self.slot, 0, 0, 0, 0).is_ok();
        if let Some(page) = self.page.take() {
            if removed {
                drop(page);
            } else {
                // 削除に失敗したページは解放しない（解放後のメモリをゲストに書かせないための fail-closed）。
                std::mem::forget(page);
            }
        }
    }
}

/// 匿名 mmap で確保したゲスト RAM の所有型（TASK-75.1・MVM-1）。drop で munmap する。
///
/// `MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE` のゼロ埋め私有メモリで、`MADV_DONTFORK` により fork 先へ
/// 引き継がず（ゲストメモリの内容を子プロセスへ漏らさない）、`MADV_DONTDUMP` によりホストのコアダンプへ含めない
/// （最大 16 GiB のゲスト内容をダンプへ漏らさない。#3679・SEC-4 周辺）。どちらかが失敗したら munmap して `Err`（fail-closed）。KVM へ登録した後はゲスト（vCPU）がいつでも
/// 書き換えるため、`&[u8]` / `&mut [u8]` は作らず、範囲検査つきのバイト単位の volatile 読み書きだけで触る。
/// 例外は virtqueue の共有 index（`avail.idx`・`used.idx`）用の整列した u16 の単一命令 volatile アクセス
/// （`read_u16_le_aligned` / `write_u16_le_aligned`。#3862・MVM-1・MVM-5。tear を避けるため）。
#[derive(Debug)]
pub(crate) struct GuestRamMap {
    ptr: NonNull<u8>,
    len: usize,
    /// drop の munmap 失敗を数える VM ごとの集約先。VM が決まる登録時に `set_unmap_tally` で付ける（#4382）。
    unmap_tally: Option<Arc<UnmapTally>>,
}

// SAFETY: ポインタはマッピングの生存中（drop まで）有効で、スレッドに固有ではない。Rust 側は参照を一切作らず
// すべて volatile で触り、書き込みは `&mut self` で排他的。ゲスト / カーネルによる書き込みは Rust のメモリモデルの
// 外にあり、Rust 側の参照のエイリアシングを生まない（`KvmRunMap` とは異なり、KVM_RUN の外でもゲストが書きうる）。
unsafe impl Send for GuestRamMap {}
// SAFETY: 上と同じ。共有参照から行うのは volatile の読み取りだけで、Rust 側の書き込みは `&mut self` に限る。
unsafe impl Sync for GuestRamMap {}

impl GuestRamMap {
    /// mapping の先頭アドレス（`KVM_SET_USER_MEMORY_REGION` の `userspace_addr`）。ポインタは外へ渡さず数値だけを返す。
    pub(crate) fn user_addr(&self) -> u64 {
        self.ptr.as_ptr() as usize as u64
    }

    /// `len` バイトのゼロ埋めの私有メモリを確保する。`len` は呼び出し側が検証済み（非 0・ページ倍数・上限内）。
    pub(crate) fn map(len: usize) -> Result<GuestRamMap, SysError> {
        if !consts::SUPPORTED {
            return Err(SysError::Unsupported);
        }
        if len == 0 {
            // mmap は長さ 0 を EINVAL で拒否する。呼ばずに同じ errno を返す。
            return Err(SysError::Os(22));
        }
        // SAFETY: addr に NULL を渡すためカーネルが配置を選び、既存のマッピングを上書きしない。fd は -1 / オフセット 0 で
        // 匿名マッピングの規約どおり。戻り値は `MAP_FAILED` を比較してから使う。
        let p = unsafe {
            mmap(
                std::ptr::null_mut(),
                len,
                consts::PROT_READ | consts::PROT_WRITE,
                consts::MAP_PRIVATE | consts::MAP_ANONYMOUS | consts::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if p as usize == usize::MAX {
            return Err(last_error());
        }
        let advise = |ptr: NonNull<u8>, len: usize, advice: i32| {
            // SAFETY: `ptr` / `len` は下の `finish_guest_ram_map` へ渡す mmap の領域そのもの。`MADV_DONTFORK` は fork 先に
            // マッピングを作らず、`MADV_DONTDUMP` はコアダンプに含めない指示だけを行い、どちらも領域の内容・対応付けを変更しない。
            let r = unsafe { madvise(ptr.as_ptr().cast::<c_void>(), len, advice) };
            if r < 0 { Err(last_error()) } else { Ok(()) }
        };
        // SAFETY: `p` / `len` は直前の mmap が成功して返した領域そのもので、他に所有者がいない。
        unsafe { finish_guest_ram_map(p, len, advise) }
    }

    /// drop の munmap 失敗を数える VM ごとの集約先を付ける（`register_backing` が登録成功後に呼ぶ。#4382）。
    pub(crate) fn set_unmap_tally(&mut self, tally: Arc<UnmapTally>) {
        self.unmap_tally = Some(tally);
    }

    /// マッピングのバイト数。
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// `off..off+buf.len()` を `buf` へ volatile でコピーする。範囲外・桁あふれは `Err`。
    pub(crate) fn read_into(&self, off: usize, buf: &mut [u8]) -> Result<(), ()> {
        let end = off.checked_add(buf.len()).ok_or(())?;
        if end > self.len {
            return Err(());
        }
        for (i, b) in buf.iter_mut().enumerate() {
            // SAFETY: `off + i < end <= len` を上で検査済みで、`ptr` は `len` バイトのマッピングの先頭。マッピングは
            // `self` の生存中有効。ゲストが並行して書き換えうるため、参照を作らず volatile で 1 バイトだけ読む。
            *b = unsafe { self.ptr.as_ptr().add(off + i).read_volatile() };
        }
        Ok(())
    }

    /// `data` を `off..off+data.len()` へ volatile でコピーする。範囲外・桁あふれは `Err`。
    pub(crate) fn write_from(&mut self, off: usize, data: &[u8]) -> Result<(), ()> {
        let end = off.checked_add(data.len()).ok_or(())?;
        if end > self.len {
            return Err(());
        }
        for (i, b) in data.iter().enumerate() {
            // SAFETY: `off + i < end <= len` を上で検査済みで、`ptr` は `len` バイトのマッピングの先頭。マッピングは
            // `self` の生存中有効で PROT_WRITE。ゲストが並行して読み書きしうるため、参照を作らず volatile で 1 バイトだけ書く。
            unsafe { self.ptr.as_ptr().add(off + i).write_volatile(*b) };
        }
        Ok(())
    }

    /// `off` の 2 バイトを整列した単一の volatile 読みで取り、LE の u16 として返す（`avail.idx` 用。#3862）。
    ///
    /// 範囲外・桁あふれ・ホストポインタが 2 バイト整列でない場合は `Err`（unsafe の前に検査する）。
    /// 「単一命令」は Rust の言語仕様の保証ではなく、自然整列した 2 バイトの volatile が x86_64（`mov`）・
    /// aarch64（`ldrh`）で 1 命令に下りることに依る（Linux の `READ_ONCE` と同じ前提。対象アーキテクチャは `SUPPORTED` の範囲）。
    pub(crate) fn read_u16_le_aligned(&self, off: usize) -> Result<u16, ()> {
        let end = off.checked_add(2).ok_or(())?;
        if end > self.len {
            return Err(());
        }
        let p = self.ptr.as_ptr().wrapping_add(off);
        if !(p as usize).is_multiple_of(core::mem::align_of::<u16>()) {
            return Err(());
        }
        // SAFETY: `off + 2 <= len` を上で検査済みで、`p` は `u16` に整列している（未整列の volatile 読みは UB のため
        // 検査した）。マッピングは `self` の生存中有効。ゲストが並行して書きうるため参照（`&u16`）を作らず volatile で読む。
        let raw = unsafe { p.cast::<u16>().read_volatile() };
        Ok(u16::from_le(raw))
    }

    /// `v` を LE で `off` の 2 バイトへ整列した単一の volatile 書きで置く（`used.idx` 用。契約は読みと同じ。#3862）。
    pub(crate) fn write_u16_le_aligned(&mut self, off: usize, v: u16) -> Result<(), ()> {
        let end = off.checked_add(2).ok_or(())?;
        if end > self.len {
            return Err(());
        }
        let p = self.ptr.as_ptr().wrapping_add(off);
        if !(p as usize).is_multiple_of(core::mem::align_of::<u16>()) {
            return Err(());
        }
        // SAFETY: `off + 2 <= len` を上で検査済みで、`p` は `u16` に整列している。マッピングは `self` の生存中有効で
        // PROT_WRITE、`&mut self` で Rust 側は排他的。ゲストが並行して読みうるため参照を作らず volatile で書く。
        unsafe { p.cast::<u16>().write_volatile(v.to_le()) };
        Ok(())
    }
}

impl Drop for GuestRamMap {
    fn drop(&mut self) {
        // SAFETY: `ptr` / `len` は `map` が成功した mmap の戻り値と長さそのもので、drop は 1 度だけ呼ばれる。
        // KVM への登録中は `RegisteredGuestRam` が所有し、slot の削除に成功した後にだけここへ来る（失敗時は
        // `forget` で漏らす）。失敗しても再試行・panic はせずリークを受け入れ、固定の 1 行で観測するだけにする
        // （#4330・REPAIR-4）。試験は ptr をずらして EINVAL を起こすが、munmap は引数を参照外ししない。
        let rc = unsafe { munmap(self.ptr.as_ptr().cast::<c_void>(), self.len) };
        if let Some(line) = unmap_failure_line(rc, GUEST_RAM_UNMAP_FAILED_LINE) {
            crate::hvf_loop::log_line(format_args!("{line}"));
            if let Some(t) = &self.unmap_tally {
                t.record_failure();
            }
        }
    }
}

/// `GuestRamMap::map` の mmap 成功後の段（NULL 検査と `madvise` 2 回）。失敗時は munmap して `Err` を返す。
///
/// `advise` を引数にするのは、`madvise` の失敗を試験で注入するため（本番は syscall を包む閉包）。
/// 失敗経路の munmap も失敗したら固定の 1 行を出し、返すエラーは元のまま変えない（#4382・MVM-1・REPAIR-4）。
///
/// # Safety
///
/// `p` / `len` は直前の mmap が成功して返した領域そのもので、他に所有者がいないこと。
unsafe fn finish_guest_ram_map(
    p: *mut c_void,
    len: usize,
    mut advise: impl FnMut(NonNull<u8>, usize, i32) -> Result<(), SysError>,
) -> Result<GuestRamMap, SysError> {
    let Some(ptr) = NonNull::new(p.cast::<u8>()) else {
        // SAFETY: 呼び出し側の契約により `p` / `len` は直前の mmap の領域そのもの。戻った後は使わない。
        return Err(unsafe {
            rollback_failed_map(p, len, GUEST_RAM_UNMAP_FAILED_LINE, SysError::NullMapping)
        });
    };
    for advice in [consts::MADV_DONTFORK, consts::MADV_DONTDUMP] {
        // errno は munmap より前に取る（munmap の errno で上書きさせない）。`advise` の閉包が取得済み。
        if let Err(e) = advise(ptr, len, advice) {
            // SAFETY: 呼び出し側の契約により mmap の領域そのもので、まだ誰にも渡しておらず他に所有者がいない。
            return Err(unsafe { rollback_failed_map(p, len, GUEST_RAM_UNMAP_FAILED_LINE, e) });
        }
    }
    Ok(GuestRamMap {
        ptr,
        len,
        unmap_tally: None,
    })
}

/// map の失敗経路で mmap した領域を munmap して `err` を返す。munmap も失敗したら `line` を 1 行出す。
///
/// 失敗経路の時点では VM ごとの集約先が無いため、件数には数えず行だけで観測する（#4382）。
/// `GuestRamMap::map` / `KvmRunMap::map` から呼ばれる。
///
/// # Safety
///
/// `addr` / `len` は直前の mmap が返した領域そのもので、他に所有者がいないこと。呼び出し後は `addr` を使わない。
/// （試験は ptr をずらして EINVAL を起こすが、munmap は引数を参照外ししない。）
unsafe fn rollback_failed_map(
    addr: *mut c_void,
    len: usize,
    line: &'static str,
    err: SysError,
) -> SysError {
    // SAFETY: 上の契約どおり。失敗しても再試行・panic はせずリークを受け入れて観測するだけにする。
    let rc = unsafe { munmap(addr, len) };
    if let Some(l) = unmap_failure_line(rc, line) {
        crate::hvf_loop::log_line(format_args!("{l}"));
    }
    err
}

pub(crate) use crate::stop::UnmapTally;

/// `GuestRamMap` の munmap 失敗時に出す固定の 1 行（MVM-1・REPAIR-4・#4330）。HVF の `op=hvf.host_unmap`
/// （#4292）と同じ文法。errno・アドレス・長さは出さず（ホストのアドレス配置を漏らさない）完全な定数にする。
const GUEST_RAM_UNMAP_FAILED_LINE: &str =
    "level=error op=kvm.guest_ram_unmap outcome=error leaked=guest_ram";

/// `KvmRunMap` の munmap 失敗時に出す固定の 1 行（MVM-1・REPAIR-4・#4330）。出さない情報は上と同じ。
const KVM_RUN_UNMAP_FAILED_LINE: &str = "level=error op=kvm.run_unmap outcome=error leaked=kvm_run";

/// munmap の戻り値から出す行を決める純関数。0 以外はすべて失敗として `line` を返す（fail-closed）。
/// `GuestRamMap` / `KvmRunMap` の drop から呼ばれる。
fn unmap_failure_line(rc: i32, line: &'static str) -> Option<&'static str> {
    if rc == 0 { None } else { Some(line) }
}

/// `slot` の memslot を削除する（`memory_size = 0` の再登録）。
pub(crate) fn unregister_guest_ram(vm: BorrowedFd<'_>, slot: u32) -> Result<(), SysError> {
    set_user_memory_region(vm, slot, 0, 0, 0, 0)
}

/// `KVM_ARM_PREFERRED_TARGET`（VM fd）で推奨 target を得る（aarch64 のみ）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) fn kvm_arm_preferred_target(vm: BorrowedFd<'_>) -> Result<KvmVcpuInit, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut init = KvmVcpuInit::default();
    // SAFETY: `vm` は借用中の生存 fd。`init` は `repr(C)` で 32 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）のゼロ初期化済みローカルで、呼び出し中は排他的に生存する。カーネルはこの 32 バイトだけを
    // 書き、呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vm.as_raw_fd(),
            consts::KVM_ARM_PREFERRED_TARGET,
            &mut init as *mut KvmVcpuInit,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(init) }
}

/// `KVM_ARM_VCPU_INIT`（vCPU fd）で vCPU を初期化する（aarch64 のみ。未実施だと `KVM_RUN` は ENOEXEC）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) fn kvm_arm_vcpu_init(vcpu: BorrowedFd<'_>, init: &KvmVcpuInit) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `vcpu` は借用中の生存 fd。`init` は `repr(C)` で 32 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）の借用で、呼び出し中は生存する。カーネルはこの 32 バイトを読むだけで書かず、
    // 呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_ARM_VCPU_INIT,
            init as *const KvmVcpuInit,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `KVM_CREATE_DEVICE`（VM fd）で in-kernel デバイス（`ty` は `KVM_DEV_TYPE_*`）を作り、そのデバイス fd を返す（aarch64 のみ。#3696）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) fn kvm_create_device(vm: BorrowedFd<'_>, ty: u32) -> Result<OwnedFd, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut arg = KvmCreateDevice {
        type_: ty,
        fd: 0,
        flags: 0,
    };
    // SAFETY: `vm` は借用中の生存 fd。`arg` は `repr(C)` で 12 バイト（const assert 済み・ioctl 番号のサイズ符号と
    // 一致）のローカルで、呼び出し中は排他的に生存する。カーネルはこの 12 バイトを読み、`fd` だけを書く。
    // 呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vm.as_raw_fd(),
            consts::KVM_CREATE_DEVICE,
            &mut arg as *mut KvmCreateDevice,
        )
    };
    if r < 0 {
        return Err(last_error());
    }
    let raw = i32::try_from(arg.fd).map_err(|_| SysError::Os(9))?;
    // SAFETY: ioctl が成功したので `arg.fd` はカーネルが返した新規のデバイス fd（`O_CLOEXEC` 付き）で、他に所有者が
    // おらず `OwnedFd` が唯一の所有者になる。`i32::try_from` で負値にならないことを確かめた。
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// `KVM_SET_DEVICE_ATTR`（デバイス fd）で、値 `value`（u64）を属性 `(group, attr)` へ書く（aarch64 のみ。#3696）。
/// vGIC の `GRP_ADDR`（8 バイトのアドレス）・`GRP_NR_IRQS`（先頭 4 バイトだけ読まれる）・`GRP_CTRL`（`addr` は読まれない）に使う。
///
/// 前提（#3949）: 呼べる `(group, attr)` は、カーネルが `addr` の先から読む値が 8 バイト以下のものに限る。
/// 8 バイトを超える属性は専用のラッパーを足すこと（組ごとのサイズはカーネル実装依存で、実行時検査の表は持たない）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) fn kvm_set_device_attr_u64(
    dev: BorrowedFd<'_>,
    group: u32,
    attr: u64,
    value: u64,
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let arg = KvmDeviceAttr {
        flags: 0,
        group,
        attr,
        addr: &value as *const u64 as u64,
    };
    // SAFETY: `dev` は借用中の生存 fd。`arg` は `repr(C)` で 24 バイト（const assert 済み・ioctl 番号のサイズ符号と
    // 一致）のローカルの借用。`arg.addr` はこの関数の引数 `value`（u64・8 バイト）のアドレスで、呼び出し中は生存し、
    // カーネルはそこから最大 8 バイトを読むだけで書かない（`GRP_CTRL` は読まない）。呼び出しは同期で完了し、
    // 戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            dev.as_raw_fd(),
            consts::KVM_SET_DEVICE_ATTR,
            &arg as *const KvmDeviceAttr,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `KVM_GET_DEVICE_ATTR`（デバイス fd）で属性 `(group, attr)` を u64 として読む（aarch64 のみ。#3696）。
/// `GRP_ADDR` は 8 バイトの値を返す。`GRP_DIST_REGS` は 4 バイト（上位は 0 のまま）を返す。
///
/// 前提（#3949）: 呼べる `(group, attr)` は、カーネルが `addr` の先へ書く値が 8 バイト以下のものに限る
/// （現状の呼び出し元は `GRP_ADDR`・`GRP_DIST_REGS` だけ）。8 バイトを超える属性は本関数を使わず専用のラッパーを足すこと。
/// 組ごとのサイズはカーネル実装依存のため実行時検査はしない。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) fn kvm_get_device_attr_u64(
    dev: BorrowedFd<'_>,
    group: u32,
    attr: u64,
) -> Result<u64, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut value: u64 = 0;
    let arg = KvmDeviceAttr {
        flags: 0,
        group,
        attr,
        addr: &mut value as *mut u64 as u64,
    };
    // SAFETY: `dev` は借用中の生存 fd。`arg` は `repr(C)` で 24 バイト（const assert 済み）のローカルの借用。
    // `arg.addr` はゼロ初期化済みのローカル `value`（u64・8 バイト）のアドレスで、呼び出し中は生存し、他から
    // 参照されない。カーネルはそこへ最大 8 バイトを書く（上記 doc の前提どおり、呼び出し元が 8 バイト以下の属性に限る）。
    // 呼び出しは同期で完了し、戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            dev.as_raw_fd(),
            consts::KVM_GET_DEVICE_ATTR,
            &arg as *const KvmDeviceAttr,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(value) }
}

/// `KVM_SET_ONE_REG`（vCPU fd）で 64 bit レジスタ `id` に `value` を書く（aarch64 のみ。#3696）。
/// `id` のサイズ種別が U64 でなければ ioctl を呼ばず `SysError::Os(EINVAL)`（#3949・MVM-1）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) fn kvm_set_one_reg_u64(
    vcpu: BorrowedFd<'_>,
    id: u64,
    value: u64,
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    check_one_reg_id_u64(id)?;
    let arg = KvmOneReg {
        id,
        addr: &value as *const u64 as u64,
    };
    // SAFETY: `vcpu` は借用中の生存 fd。`arg` は `repr(C)` で 16 バイト（const assert 済み・ioctl 番号のサイズ符号と
    // 一致）のローカルの借用。`arg.addr` は引数 `value`（u64・8 バイト）のアドレスで、`id` は 64 bit レジスタ
    // （直前の `check_one_reg_id_u64` でサイズ種別が `KVM_REG_SIZE_U64` と確かめ済み）なのでカーネルが読むのは 8 バイトだけ。呼び出しは同期で完了し、戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_SET_ONE_REG,
            &arg as *const KvmOneReg,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `KVM_GET_ONE_REG`（vCPU fd）で 64 bit レジスタ `id` を読む（aarch64 のみ。#3696）。
/// `id` のサイズ種別が U64 でなければ ioctl を呼ばず `SysError::Os(EINVAL)`（#3949・MVM-1）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) fn kvm_get_one_reg_u64(vcpu: BorrowedFd<'_>, id: u64) -> Result<u64, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    check_one_reg_id_u64(id)?;
    let mut value: u64 = 0;
    let arg = KvmOneReg {
        id,
        addr: &mut value as *mut u64 as u64,
    };
    // SAFETY: `vcpu` は借用中の生存 fd。`arg` は `repr(C)` で 16 バイト（const assert 済み）のローカルの借用。
    // `arg.addr` はゼロ初期化済みのローカル `value`（u64・8 バイト）のアドレスで、呼び出し中は生存し他から参照されない。
    // `id` は直前の `check_one_reg_id_u64` でサイズ種別が `KVM_REG_SIZE_U64` と確かめ済みなのでカーネルが書くのは 8 バイトだけ。呼び出しは同期で完了し、戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_GET_ONE_REG,
            &arg as *const KvmOneReg,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(value) }
}
/// `KVM_GET_REGS`（vCPU fd）で汎用レジスタを読む（x86_64 のみ。TASK-75.3.2）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_get_regs(vcpu: BorrowedFd<'_>) -> Result<KvmRegs, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut regs = KvmRegs::default();
    // SAFETY: `vcpu` は借用中の生存 fd。`regs` は `repr(C)` で 144 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）のゼロ初期化済みローカルで、呼び出し中は排他的に生存する。カーネルはこの 144 バイトだけを
    // 書き、呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_GET_REGS,
            &mut regs as *mut KvmRegs,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(regs) }
}

/// `KVM_SET_REGS`（vCPU fd）で汎用レジスタを書く（x86_64 のみ。TASK-75.3.2）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_set_regs(vcpu: BorrowedFd<'_>, regs: &KvmRegs) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `vcpu` は借用中の生存 fd。`regs` は `repr(C)` で 144 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）の借用で、呼び出し中は生存する。カーネルはこの 144 バイトを読むだけで書かず、
    // 呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_SET_REGS,
            regs as *const KvmRegs,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `KVM_GET_SREGS`（vCPU fd）でセグメント・制御レジスタを読む（x86_64 のみ。TASK-75.3.2）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_get_sregs(vcpu: BorrowedFd<'_>) -> Result<KvmSregs, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut sregs = KvmSregs::default();
    // SAFETY: `vcpu` は借用中の生存 fd。`sregs` は `repr(C)` で 312 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）のゼロ初期化済みローカルで、呼び出し中は排他的に生存する。カーネルはこの 312 バイトだけを
    // 書き、呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_GET_SREGS,
            &mut sregs as *mut KvmSregs,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(sregs) }
}

/// `KVM_SET_SREGS`（vCPU fd）でセグメント・制御レジスタを書く（x86_64 のみ。TASK-75.3.2）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_set_sregs(vcpu: BorrowedFd<'_>, sregs: &KvmSregs) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `vcpu` は借用中の生存 fd。`sregs` は `repr(C)` で 312 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）の借用で、呼び出し中は生存する。カーネルはこの 312 バイトを読むだけで書かず、
    // 呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_SET_SREGS,
            sregs as *const KvmSregs,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// 可変長ヘッダ付きバッファ（`struct kvm_cpuid2` / `struct kvm_msrs` 用。#3731・MVM-1・MVM-4）。
///
/// 先頭 8 バイトのヘッダ（先頭 4 バイトが件数 `u32`、残りは padding）の直後に `E` が `cap` 件続く 1 つの連続領域を
/// ちょうどの大きさで確保する。不変条件: 作成時にヘッダの件数へ `cap` を書く（ioctl 後はカーネルが書き戻した
/// 非信頼の値になるため、読むときは `entries` が容量以下を検証する）。
/// `E` は [`FlexEntry`] を実装する型（`KvmCpuidEntry2`・`KvmMsrEntry`）に限る。不変条件は trait の `# Safety` にある。
/// 呼び出し元は下の `kvm_get_supported_cpuid` などの安全なラッパーだけ。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[cfg_attr(not(test), allow(dead_code))]
struct FlexBuf<E: FlexEntry> {
    ptr: NonNull<u8>,
    layout: Layout,
    cap: usize,
    _entry: std::marker::PhantomData<E>,
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[cfg_attr(not(test), allow(dead_code))]
impl<E: FlexEntry> FlexBuf<E> {
    const HEADER: usize = 8;

    /// `n` 件分を確保する。`n > max` は確保より前に E2BIG（7）で拒否する。
    fn with_capacity(n: usize, max: usize) -> Result<Self, SysError> {
        if n > max {
            return Err(SysError::Os(7));
        }
        let count = u32::try_from(n).map_err(|_| SysError::Os(7))?;
        let size = std::mem::size_of::<E>()
            .checked_mul(n)
            .and_then(|b| b.checked_add(Self::HEADER))
            .ok_or(SysError::Os(22))?;
        let align = std::mem::align_of::<E>().max(4);
        let layout = Layout::from_size_align(size, align).map_err(|_| SysError::Os(22))?;
        // SAFETY: `size >= 8` で非 0。戻り値の null は直後に検査する。
        let p = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(p).ok_or(SysError::Os(12))?;
        let buf = FlexBuf {
            ptr,
            layout,
            cap: n,
            _entry: std::marker::PhantomData,
        };
        buf.set_count(count);
        Ok(buf)
    }

    /// ヘッダの件数を書く。
    fn set_count(&self, count: u32) {
        // SAFETY: `ptr` は 8 バイト以上でアライン 4 以上の確保の先頭。先頭 4 バイトへの書き込みで範囲内。
        unsafe { self.ptr.as_ptr().cast::<u32>().write(count) };
    }

    /// ヘッダの件数（ioctl 後はカーネルが書き戻した値で、非信頼）。
    fn count(&self) -> u32 {
        // SAFETY: `ptr` は 8 バイト以上でアライン 4 以上の確保の先頭で、ゼロ埋め済み（初期化済み）。
        unsafe { self.ptr.as_ptr().cast::<u32>().read() }
    }

    fn as_ioctl_ptr(&mut self) -> *mut c_void {
        self.ptr.as_ptr().cast::<c_void>()
    }

    /// 先頭 `count` 件を読む。`count > cap` は不整合として EINVAL（22）。
    fn entries(&self, count: usize) -> Result<&[E], SysError> {
        if count > self.cap {
            return Err(SysError::Os(22));
        }
        // SAFETY: entries は先頭から 8 バイト後で、確保のアラインは `max(4, align_of::<E>())` で、
        // `E: FlexEntry` の契約により `align_of::<E>() <= 8` のため `E` のアラインに合う。同じ契約によりどのビット
        // パターンも有効（ゼロ埋め以後・カーネルの書き戻しを含む）。`count <= cap` で範囲内、
        // `&self` の間は他に書き手がいない。
        Ok(unsafe {
            std::slice::from_raw_parts(self.ptr.as_ptr().add(Self::HEADER).cast::<E>(), count)
        })
    }

    /// 先頭 `src.len()` 件へ書く。`src.len() > cap` は EINVAL（22）。
    fn fill(&mut self, src: &[E]) -> Result<(), SysError> {
        if src.len() > self.cap {
            return Err(SysError::Os(22));
        }
        // SAFETY: 範囲は `src.len() <= cap` を検査済みで、アラインは `entries` と同じ（`E: FlexEntry` の契約）。`&mut self` で排他的、
        // `src` は別の確保で重ならない。
        unsafe {
            std::ptr::copy_nonoverlapping(
                src.as_ptr(),
                self.ptr.as_ptr().add(Self::HEADER).cast::<E>(),
                src.len(),
            );
        }
        Ok(())
    }
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[cfg_attr(not(test), allow(dead_code))]
impl<E: FlexEntry> Drop for FlexBuf<E> {
    fn drop(&mut self) {
        // SAFETY: `ptr` は `with_capacity` が同じ `layout` で確保したもので、drop は 1 度だけ。
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
    }
}

/// `KVM_GET_SUPPORTED_CPUID`（system fd = `/dev/kvm`）でホストの CPUID 候補を最大 `max_entries` 件読む（x86_64 のみ）。
///
/// `max_entries` が 0 または 256 超なら確保前に E2BIG。容量不足でカーネルが E2BIG を返したときもそのまま返す
/// （呼び出し側 `device::KvmDevice::supported_cpuid` は 256 件で 1 回だけ要求し、E2BIG でも再試行しない。#3733）。書き戻された件数は非信頼として容量以下を検証する。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_get_supported_cpuid(
    kvm: BorrowedFd<'_>,
    max_entries: usize,
) -> Result<Vec<KvmCpuidEntry2>, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    if max_entries == 0 {
        return Err(SysError::Os(7));
    }
    let mut buf = FlexBuf::<KvmCpuidEntry2>::with_capacity(max_entries, consts::MAX_CPUID_ENTRIES)?;
    // SAFETY: `kvm` は借用中の生存 fd。`buf` は `8 + 40 * max_entries` バイトの確保で、ヘッダの件数が確保した
    // 容量と一致する（カーネルはこの件数の範囲内だけを書く）。呼び出し中は `&mut` で排他的に生存し、
    // 同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            kvm.as_raw_fd(),
            consts::KVM_GET_SUPPORTED_CPUID,
            buf.as_ioctl_ptr(),
        )
    };
    if r < 0 {
        return Err(last_error());
    }
    Ok(buf.entries(buf.count() as usize)?.to_vec())
}

/// `KVM_SET_CPUID2`（vCPU fd）で CPUID を設定する（x86_64 のみ）。256 件超は確保前に E2BIG。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_set_cpuid2(
    vcpu: BorrowedFd<'_>,
    entries: &[KvmCpuidEntry2],
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut buf =
        FlexBuf::<KvmCpuidEntry2>::with_capacity(entries.len(), consts::MAX_CPUID_ENTRIES)?;
    buf.fill(entries)?;
    // SAFETY: `vcpu` は借用中の生存 fd。`buf` は `8 + 40 * len` バイトでヘッダの件数 = 容量。カーネルは
    // その範囲を読むだけで書かず、呼び出し中は生存し、同期で完了して戻り後にポインタを保持しない。
    let r = unsafe { ioctl(vcpu.as_raw_fd(), consts::KVM_SET_CPUID2, buf.as_ioctl_ptr()) };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `KVM_GET_MSRS`（vCPU fd）で MSR を読む（x86_64 のみ）。`entries[i].index` に読む MSR 番号を入れて渡す。
///
/// 戻り値は処理できた MSR の件数（0 でも成功。途中の MSR で止まると `len` 未満の非負値が返り errno は無い）。
/// 呼び出し側が `== entries.len()` を確かめること。先頭の戻り値件数だけを `entries` へ書き戻す。
/// 255 件超は確保前に E2BIG。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_get_msrs(
    vcpu: BorrowedFd<'_>,
    entries: &mut [KvmMsrEntry],
) -> Result<usize, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut buf = FlexBuf::<KvmMsrEntry>::with_capacity(entries.len(), consts::MAX_MSR_ENTRIES)?;
    buf.fill(entries)?;
    // SAFETY: `vcpu` は借用中の生存 fd。`buf` は `8 + 16 * len` バイトでヘッダの件数 = 容量（カーネルは
    // その範囲内だけを読み書きする）。呼び出し中は `&mut` で排他的に生存し、同期で完了して戻り後にポインタを保持しない。
    let r = unsafe { ioctl(vcpu.as_raw_fd(), consts::KVM_GET_MSRS, buf.as_ioctl_ptr()) };
    let n = msr_result(r, entries.len())?;
    let got = buf.entries(n)?;
    let dst = entries.get_mut(..n).ok_or(SysError::Os(22))?;
    dst.copy_from_slice(got);
    Ok(n)
}

/// `KVM_SET_MSRS`（vCPU fd）で MSR を書く（x86_64 のみ）。戻り値の意味は [`kvm_get_msrs`] と同じ
/// （設定できた件数。呼び出し側が `== entries.len()` を確かめる）。255 件超は確保前に E2BIG。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_set_msrs(
    vcpu: BorrowedFd<'_>,
    entries: &[KvmMsrEntry],
) -> Result<usize, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut buf = FlexBuf::<KvmMsrEntry>::with_capacity(entries.len(), consts::MAX_MSR_ENTRIES)?;
    buf.fill(entries)?;
    // SAFETY: `vcpu` は借用中の生存 fd。`buf` は `8 + 16 * len` バイトでヘッダの件数 = 容量。カーネルは
    // その範囲を読むだけで書かず、呼び出し中は生存し、同期で完了して戻り後にポインタを保持しない。
    let r = unsafe { ioctl(vcpu.as_raw_fd(), consts::KVM_SET_MSRS, buf.as_ioctl_ptr()) };
    msr_result(r, entries.len())
}

/// MSR 系 ioctl の戻り値を検証する。負は errno、要求件数超はカーネル応答の不整合として EINVAL（22）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
fn msr_result(r: i32, requested: usize) -> Result<usize, SysError> {
    if r < 0 {
        return Err(last_error());
    }
    let n = usize::try_from(r).map_err(|_| SysError::Os(22))?;
    if n > requested {
        return Err(SysError::Os(22));
    }
    Ok(n)
}

/// `KVM_GET_FPU`（vCPU fd）で FPU 状態を読む（x86_64 のみ）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_get_fpu(vcpu: BorrowedFd<'_>) -> Result<KvmFpu, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut fpu = KvmFpu::default();
    // SAFETY: `vcpu` は借用中の生存 fd。`fpu` は `repr(C)` で 416 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）のゼロ初期化済みローカルで、呼び出し中は排他的に生存する。カーネルはこの 416 バイトだけを
    // 書き、呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_GET_FPU,
            &mut fpu as *mut KvmFpu,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(fpu) }
}

/// `KVM_SET_FPU`（vCPU fd）で FPU 状態を書く（x86_64 のみ）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_set_fpu(vcpu: BorrowedFd<'_>, fpu: &KvmFpu) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `vcpu` は借用中の生存 fd。`fpu` は `repr(C)` で 416 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）の借用で、呼び出し中は生存する。カーネルはこの 416 バイトを読むだけで書かず、
    // 呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe { ioctl(vcpu.as_raw_fd(), consts::KVM_SET_FPU, fpu as *const KvmFpu) };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `KVM_GET_MP_STATE`（vCPU fd）で MP 状態を読む（x86_64 のみ。#3737）。in-kernel LAPIC では保留中の
/// INIT/SIPI をカーネルが先に処理してから返す。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_get_mp_state(vcpu: BorrowedFd<'_>) -> Result<KvmMpState, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut st = KvmMpState::default();
    // SAFETY: `vcpu` は借用中の生存 fd。`st` は `repr(C)` で 4 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）のゼロ初期化済みローカルで、呼び出し中は排他的に生存する。カーネルはこの 4 バイトだけを
    // 書き、呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_GET_MP_STATE,
            &mut st as *mut KvmMpState,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(st) }
}

/// `KVM_SET_MP_STATE`（vCPU fd）で MP 状態を書く（x86_64 のみ。#3737）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_set_mp_state(vcpu: BorrowedFd<'_>, st: &KvmMpState) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `vcpu` は借用中の生存 fd。`st` は `repr(C)` で 4 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）の借用で、呼び出し中は生存する。カーネルはこの 4 バイトを読むだけで書かず、
    // 呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_SET_MP_STATE,
            st as *const KvmMpState,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `KVM_GET_LAPIC`（vCPU fd）で LAPIC レジスタ面を読む（x86_64 のみ）。in-kernel irqchip
/// （`KVM_CREATE_IRQCHIP`）が無いと EINVAL になる。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_get_lapic(vcpu: BorrowedFd<'_>) -> Result<KvmLapicState, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let mut lapic = KvmLapicState::default();
    // SAFETY: `vcpu` は借用中の生存 fd。`lapic` は `repr(C)` で 1024 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）のゼロ初期化済みローカルで、呼び出し中は排他的に生存する。カーネルはこの 1024 バイトだけを
    // 書き、呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_GET_LAPIC,
            &mut lapic as *mut KvmLapicState,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(lapic) }
}

/// `KVM_SET_LAPIC`（vCPU fd）で LAPIC レジスタ面を書く（x86_64 のみ。in-kernel irqchip が前提）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_set_lapic(vcpu: BorrowedFd<'_>, lapic: &KvmLapicState) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `vcpu` は借用中の生存 fd。`lapic` は `repr(C)` で 1024 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）の借用で、呼び出し中は生存する。カーネルはこの 1024 バイトを読むだけで書かず、
    // 呼び出しは同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vcpu.as_raw_fd(),
            consts::KVM_SET_LAPIC,
            lapic as *const KvmLapicState,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `KVM_SET_TSS_ADDR`（VM fd）で TSS 用の 3 ページ（12 KiB）の置き場を指定する（x86_64 のみ）。
/// vCPU 作成前に発行する。引数は `unsigned long` の値渡し。呼び出しは `VmFd::set_tss_addr` 経由の `MicroVm::assemble` のみ（値の選定と他領域との重なり検証は `microvm.rs`。#3732）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_set_tss_addr(vm: BorrowedFd<'_>, addr: u64) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `vm` は借用中の生存 fd。引数は値渡し（ポインタではない）で、カーネルはユーザー空間のメモリを読み書きしない。
    let r = unsafe { ioctl(vm.as_raw_fd(), consts::KVM_SET_TSS_ADDR, addr) };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

/// `KVM_SET_IDENTITY_MAP_ADDR`（VM fd）で identity map 用の 1 ページの置き場を指定する（x86_64 のみ）。
/// vCPU 作成前に発行する。引数は `u64` へのポインタ（`KVM_SET_TSS_ADDR` の値渡しとは形が違う）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) fn kvm_set_identity_map_addr(vm: BorrowedFd<'_>, addr: u64) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `vm` は借用中の生存 fd。`addr` は 8 バイト（ioctl 番号のサイズ符号と一致）のローカルの借用で、
    // 呼び出し中は生存する。カーネルは 8 バイトを読むだけで書かず、同期で完了して戻り後にポインタを保持しない。
    let r = unsafe {
        ioctl(
            vm.as_raw_fd(),
            consts::KVM_SET_IDENTITY_MAP_ADDR,
            &addr as *const u64,
        )
    };
    if r < 0 { Err(last_error()) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MVM-1: `linux/kvm.h` の `_IO(0xAE, 0x00/0x01)` と版数の具体値。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn kvm_constants_match_kernel_abi() {
        assert_eq!(io(0xAE, 0x00), 0xAE00);
        assert_eq!(consts::KVM_GET_API_VERSION, 0xAE00);
        assert_eq!(consts::KVM_CREATE_VM, 0xAE01);
        assert_eq!(consts::KVM_API_VERSION, 12);
    }

    /// MVM-1: `_IOC` の符号化の具体値（arch 非依存）。
    #[test]
    fn ioc_encoding_matches_kernel_abi() {
        assert_eq!(ior(0xAE, 0xAF, 32), 0x8020_AEAF);
        assert_eq!(iow(0xAE, 0xAE, 32), 0x4020_AEAE);
        assert_eq!(ioc(0, 0xAE, 0x41, 0), 0xAE41);
        assert_eq!(iowr(0xAE, 0x05, 8), 0xC008_AE05);
    }

    /// MVM-1: `KVM_CREATE_VCPU = _IO(KVMIO, 0x41)`。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn create_vcpu_constant_matches_kernel_abi() {
        assert_eq!(consts::KVM_CREATE_VCPU, 0xAE41);
    }

    /// REPAIR-5: handler 導入後は武装中の自スレッドへ中断シグナルを送ってもプロセスが終了しない（冪等な再導入も可）。
    #[cfg(all(
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn kick_self_after_handler_install_survives() {
        install_kick_handler().unwrap();
        install_kick_handler().unwrap();
        let cell = KickCell::default();
        let v = cell.armed(|| cell.kick().unwrap()).unwrap();
        assert!(v);
    }

    /// REPAIR-5・MVM-1・#4288: 別スレッドから武装中の所有スレッドへ送れて `Ok(true)`、解除後と未武装は `Ok(false)`。
    /// `armed` の戻り値はそのまま返る。
    #[cfg(all(
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn kick_cell_sends_only_while_armed() {
        install_kick_handler().unwrap();
        let cell = std::sync::Arc::new(KickCell::default());
        assert!(!cell.kick().unwrap());
        let c2 = std::sync::Arc::clone(&cell);
        let v = cell
            .armed(|| {
                std::thread::spawn(move || c2.kick())
                    .join()
                    .unwrap()
                    .unwrap()
            })
            .unwrap();
        assert!(v);
        assert!(!cell.kick().unwrap());
    }

    /// #4288: 二重武装は閉包を実行せず `Err`（fail-closed）。内側が戻ると外側の武装も解除済みになる。
    #[cfg(all(
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn kick_cell_rejects_double_arm() {
        let cell = KickCell::default();
        let mut ran = false;
        let r = cell.armed(|| cell.armed(|| ran = true)).unwrap();
        assert!(matches!(r, Err(SysError::Os(EBUSY))));
        assert!(!ran);
        assert!(!cell.kick().unwrap());
    }

    /// #4288: 閉包が panic しても解除される。
    #[cfg(all(
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn kick_cell_disarms_on_panic() {
        let cell = KickCell::default();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = cell.armed(|| panic!("boom"));
        }));
        assert!(r.is_err());
        assert!(!cell.kick().unwrap());
    }

    /// MVM-1: sigaction / sigset_t のレイアウトの具体値。
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn signal_struct_layout_matches_kernel_abi() {
        assert_eq!(std::mem::size_of::<SigSet>(), 128);
        assert_eq!(std::mem::size_of::<SigAction>(), 152);
        assert_eq!(std::mem::offset_of!(SigAction, flags), 136);
    }

    /// MVM-1: `KVM_RUN` 系の ioctl 番号と構造体サイズの具体値（`linux/kvm.h`）。
    #[test]
    fn run_constants_match_kernel_abi() {
        assert_eq!(consts::KVM_GET_VCPU_MMAP_SIZE, 0xAE04);
        assert_eq!(consts::KVM_RUN, 0xAE80);
        assert_eq!(consts::KVM_SET_USER_MEMORY_REGION, 0x4020_AE46);
        assert_eq!(std::mem::size_of::<KvmUserspaceMemoryRegion>(), 32);
    }

    /// MVM-1・#3949: ONE_REG の id は U64 のサイズ種別だけを受ける（ioctl の前の検査の具体値）。
    #[test]
    fn mvm1_3949_one_reg_id_size_must_be_u64() {
        assert_eq!(KVM_REG_SIZE_MASK, 0x00f0_0000_0000_0000);
        for id in [
            0x6030_0000_0010_0040_u64,
            0x6030_0000_0013_C005,
            0x6030_0000_0010_0000,
            0x6030_0000_0010_003C,
        ] {
            assert_eq!(check_one_reg_id_u64(id), Ok(()), "id={id:#x}");
        }
        for id in [
            0x6000_0000_0010_0040_u64, // U8
            0x6010_0000_0010_0040,     // U16
            0x6020_0000_0010_0040,     // U32
            0x6040_0000_0010_0040,     // U128
            0x6050_0000_0010_0040,     // U256
            0x6080_0000_0010_0040,     // U2048
            0x60f0_0000_0010_0040,     // マスク全ビット
        ] {
            assert_eq!(
                check_one_reg_id_u64(id),
                Err(SysError::Os(22)),
                "id={id:#x}"
            );
        }
    }

    /// MVM-1・#3949: U64 以外の id は ioctl を呼ばずに EINVAL（届けば /dev/null は ENOTTY=25）。
    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    #[test]
    fn mvm1_3949_one_reg_rejects_non_u64_before_ioctl() {
        use std::os::fd::AsFd as _;
        let f = dev_null();
        let u128_id = 0x6040_0000_0010_0040_u64;
        assert_eq!(
            kvm_get_one_reg_u64(f.as_fd(), u128_id),
            Err(SysError::Os(22))
        );
        assert_eq!(
            kvm_set_one_reg_u64(f.as_fd(), u128_id, 0),
            Err(SysError::Os(22))
        );
        assert_eq!(
            kvm_get_one_reg_u64(f.as_fd(), ARM64_REG_PC),
            Err(SysError::Os(25))
        );
        assert_eq!(
            kvm_set_one_reg_u64(f.as_fd(), ARM64_REG_PC, 0),
            Err(SysError::Os(25))
        );
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn dev_null() -> std::fs::File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap()
    }

    /// MVM-1: KVM でない fd への ioctl は ENOTTY（unsafe 経路を KVM 無しで通す）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn run_ioctls_on_non_kvm_fd_are_enotty() {
        use std::os::fd::AsFd as _;
        let f = dev_null();
        assert_eq!(kvm_run(f.as_fd()), Err(SysError::Os(25)));
        assert_eq!(kvm_get_vcpu_mmap_size(f.as_fd()), Err(SysError::Os(25)));
        let page = GuestPage::new().unwrap();
        let (e, _page) = register_single_page(f.as_fd(), 0, 0x1000, page).unwrap_err();
        assert_eq!(e, SysError::Os(25));
    }

    /// MVM-1・TASK-75.3.2: レジスタ ioctl は KVM でない fd に対して ENOTTY（x86_64）。
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn regs_ioctls_on_non_kvm_fd_are_enotty() {
        use std::os::fd::AsFd as _;
        let f = dev_null();
        assert_eq!(kvm_get_regs(f.as_fd()), Err(SysError::Os(25)));
        assert_eq!(
            kvm_set_regs(f.as_fd(), &KvmRegs::default()),
            Err(SysError::Os(25))
        );
        assert_eq!(kvm_get_sregs(f.as_fd()), Err(SysError::Os(25)));
        assert_eq!(
            kvm_set_sregs(f.as_fd(), &KvmSregs::default()),
            Err(SysError::Os(25))
        );
    }

    /// MVM-1: `/dev/null` は mmap できない（ENODEV）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn map_non_mappable_fd_is_enodev() {
        use std::os::fd::AsFd as _;
        let f = dev_null();
        assert_eq!(
            KvmRunMap::map(f.as_fd(), 4096, None).unwrap_err(),
            SysError::Os(19)
        );
    }

    /// MVM-1・#3679: `write_from` は `immediate_exit`（オフセット 1）に重なる範囲を、1 バイトも書かずに拒否する。
    /// `/dev/zero` の `MAP_SHARED` は共有ゼロページで、KVM なしで `KvmRunMap` の経路を試せる。
    #[cfg(all(
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn mvm1_3679_write_from_rejects_immediate_exit_overlap() {
        use std::os::fd::AsFd as _;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/zero")
            .unwrap();
        let mut m = KvmRunMap::map(f.as_fd(), 4096, None).unwrap();
        assert!(m.write_from(0, &[7, 8]).is_err());
        assert!(m.write_from(1, &[9]).is_err());
        let mut head = [0xFFu8; 3];
        m.read_into(0, &mut head).unwrap();
        assert_eq!(head, [0, 0, 0]);
        assert!(m.write_from(0, &[5]).is_ok());
        assert!(m.write_from(2, &[6]).is_ok());
        assert!(m.write_from(1, &[]).is_ok());
        m.read_into(0, &mut head).unwrap();
        assert_eq!(head, [5, 0, 6]);
        m.set_immediate_exit(true).unwrap();
        assert!(m.write_from(1, &[0]).is_err());
        m.read_into(0, &mut head).unwrap();
        assert_eq!(head, [5, 1, 6]);
    }

    /// MVM-1・#3679: ゲスト RAM は fork 先へ引き継がれず（`dc`）、コアダンプにも含まれない（`dd`）。
    #[cfg(all(
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn mvm1_3679_guest_ram_excluded_from_fork_and_core_dump() {
        let m = GuestRamMap::map(8192).unwrap();
        let addr = m.ptr.as_ptr() as usize;
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut in_range = false;
        let mut flags: Option<&str> = None;
        for line in smaps.lines() {
            let head = line.split_whitespace().next().unwrap_or("");
            if let Some((lo, hi)) = head.split_once('-')
                && let (Ok(lo), Ok(hi)) =
                    (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
            {
                in_range = lo <= addr && addr < hi;
                continue;
            }
            if in_range && line.starts_with("VmFlags:") {
                flags = Some(line);
                break;
            }
        }
        let flags = flags.expect("VmFlags of the guest ram mapping");
        let names: Vec<&str> = flags.split_whitespace().skip(1).collect();
        assert!(names.contains(&"dc"), "{flags}");
        assert!(names.contains(&"dd"), "{flags}");
    }

    /// MVM-1: ゲストページへの書き込みの境界検査。
    #[test]
    fn guest_page_write_bounds() {
        let mut p = GuestPage::new().unwrap();
        assert!(p.write_at(0xFF0, &[1, 2, 3, 4, 5]).is_ok());
        assert!(p.write_at(4092, &[0; 4]).is_ok());
        assert!(p.write_at(4093, &[0; 4]).is_err());
        assert!(p.write_at(usize::MAX, &[0; 4]).is_err());
        assert!(p.write_at(4096, &[]).is_ok());
    }

    /// MVM-1・TASK-74.2.3: 割り込み通知系の ioctl 番号と構造体レイアウトの具体値（`linux/kvm.h`）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn irq_constants_match_kernel_abi() {
        assert_eq!(consts::KVM_CHECK_EXTENSION, 0xAE03);
        assert_eq!(consts::KVM_IRQFD, 0x4020_AE76);
        assert_eq!(consts::KVM_IOEVENTFD, 0x4040_AE79);
        assert_eq!(std::mem::size_of::<KvmIrqfd>(), 32);
        assert_eq!(std::mem::size_of::<KvmIoeventfd>(), 64);
        assert_eq!(std::mem::offset_of!(KvmIoeventfd, len), 16);
        assert_eq!(consts::KVM_CAP_IRQFD.0, 32);
        assert_eq!(consts::KVM_CAP_IOEVENTFD.0, 36);
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        assert_eq!(consts::KVM_CAP_NR_MEMSLOTS.0, 10);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn create_irqchip_constant_matches_kernel_abi() {
        assert_eq!(consts::KVM_CREATE_IRQCHIP, 0xAE60);
    }

    /// MVM-1・#3918: `KVM_IRQ_LINE` の番号と `kvm_irq_level` のレイアウトの具体値（`linux/kvm.h`）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn kvm_irq_line_constant_matches_kernel_abi() {
        assert_eq!(consts::KVM_IRQ_LINE, 0x4008_AE61);
        assert_eq!(std::mem::size_of::<KvmIrqLevel>(), 8);
        assert_eq!(std::mem::offset_of!(KvmIrqLevel, irq), 0);
        assert_eq!(std::mem::offset_of!(KvmIrqLevel, level), 4);
    }

    /// MVM-1・#3943: arm64 の `irq` フィールドの合成（INTID 33 は `0x0100_0021`、16 ビット超は `None`）。全 arch で走る。
    #[test]
    fn mvm1_3943_arm64_spi_irq_field_values() {
        assert_eq!(arm64_spi_irq_field(33), Some(0x0100_0021));
        assert_eq!(arm64_spi_irq_field(32), Some(0x0100_0020));
        assert_eq!(arm64_spi_irq_field(0xffff), Some(0x0100_ffff));
        assert_eq!(arm64_spi_irq_field(0x1_0000), None);
    }

    /// MVM-1・TASK-74.2.3: KVM でない fd への ioctl は ENOTTY（unsafe 経路を KVM 無しで通す）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn irq_ioctls_on_non_kvm_fd_are_enotty() {
        use std::os::fd::AsFd as _;
        let f = dev_null();
        let ev = eventfd_new().unwrap();
        assert_eq!(
            kvm_check_extension(f.as_fd(), consts::KVM_CAP_IRQFD),
            Err(SysError::Os(25))
        );
        assert_eq!(
            kvm_irqfd(f.as_fd(), ev.as_fd(), 5, false),
            Err(SysError::Os(25))
        );
        assert_eq!(
            kvm_ioeventfd(f.as_fd(), ev.as_fd(), 0x2050, 4, Some(0), false, false),
            Err(SysError::Os(25))
        );
        #[cfg(target_arch = "x86_64")]
        assert_eq!(kvm_create_irqchip(f.as_fd()), Err(SysError::Os(25)));
        #[cfg(target_arch = "x86_64")]
        assert_eq!(kvm_irq_line(f.as_fd(), 4, true), Err(SysError::Os(25)));
        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            kvm_irq_line(f.as_fd(), 0x0100_0021, true),
            Err(SysError::Os(25))
        );
        #[cfg(target_arch = "aarch64")]
        assert_eq!(kvm_create_irqchip(f.as_fd()), Err(SysError::Unsupported));
    }

    /// MVM-1・REPAIR-5・#3698: `poll_readable` は発火した fd だけを true にし、未発火は期限で 0 件を返し、長さの不一致・上限超過は EINVAL。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_3698_poll_readable_reports_only_signaled_fds() {
        use std::io::Write as _;
        use std::os::fd::AsFd as _;
        use std::time::{Duration, Instant};
        let a = std::fs::File::from(eventfd_new().unwrap());
        let b = std::fs::File::from(eventfd_new().unwrap());
        let fds = [a.as_fd(), b.as_fd()];
        let mut ready = [PollReadiness::Readable; 2];
        // 未発火: 0 件。期限（20 ms）で戻り、全て false に戻される。
        let t0 = Instant::now();
        assert_eq!(
            poll_readable(&fds, Duration::from_millis(20), &mut ready),
            Ok(0)
        );
        assert_eq!(ready, [PollReadiness::Idle; 2]);
        assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
        // b だけ発火。
        (&b).write_all(&1u64.to_ne_bytes()).unwrap();
        assert_eq!(poll_readable(&fds, Duration::ZERO, &mut ready), Ok(1));
        assert_eq!(ready, [PollReadiness::Idle, PollReadiness::Readable]);
        // 長さの不一致と上限超過。
        let mut one = [PollReadiness::Idle];
        assert_eq!(
            poll_readable(&fds, Duration::ZERO, &mut one),
            Err(SysError::Os(22))
        );
        let many = vec![a.as_fd(); MAX_POLL_FDS + 1];
        let mut flags = vec![PollReadiness::Idle; MAX_POLL_FDS + 1];
        assert_eq!(
            poll_readable(&many, Duration::ZERO, &mut flags),
            Err(SysError::Os(22))
        );
    }

    /// MVM-1・REPAIR-5・#4101: 異常ビットは `POLLIN` と同時でも `Abnormal`、`POLLIN` だけが `Readable`。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4101_classify_revents_prefers_abnormal() {
        use consts::{POLLERR, POLLHUP, POLLIN, POLLNVAL};
        assert_eq!(classify_revents(0), PollReadiness::Idle);
        assert_eq!(classify_revents(POLLIN), PollReadiness::Readable);
        for bit in [POLLERR, POLLHUP, POLLNVAL] {
            assert_eq!(
                classify_revents(bit),
                PollReadiness::Abnormal { revents: bit }
            );
            assert_eq!(
                classify_revents(bit | POLLIN),
                PollReadiness::Abnormal {
                    revents: bit | POLLIN
                }
            );
        }
    }

    /// MVM-1・REPAIR-5・#4101: 実カーネルで、書き込み端が閉じたパイプの読み出し端は `Abnormal`（POLLHUP）になる。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4101_poll_readable_classifies_hup_as_abnormal() {
        use std::os::fd::AsFd as _;
        use std::time::Duration;
        let (reader, writer) = std::io::pipe().unwrap();
        drop(writer);
        let fds = [reader.as_fd()];
        let mut ready = [PollReadiness::Idle];
        assert_eq!(poll_readable(&fds, Duration::ZERO, &mut ready), Ok(1));
        assert!(
            matches!(ready[0], PollReadiness::Abnormal { revents } if revents & consts::POLLHUP != 0),
            "{:?}",
            ready[0]
        );
    }

    /// MVM-1・TASK-74.2.3: eventfd は非ブロック・close-on-exec で、書いた値の合計を 1 回で読み出す。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn eventfd_roundtrip_and_flags() {
        use std::io::{Read as _, Write as _};
        let fd = eventfd_new().unwrap();
        let raw = fd.as_raw_fd();
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{raw}")).unwrap();
        let flags = info
            .lines()
            .find_map(|l| l.strip_prefix("flags:"))
            .map(str::trim)
            .and_then(|v| u32::from_str_radix(v, 8).ok())
            .unwrap();
        assert_eq!(flags & 0o2000000, 0o2000000, "O_CLOEXEC");
        assert_eq!(flags & 0o4000, 0o4000, "O_NONBLOCK");
        let mut f = std::fs::File::from(fd);
        f.write_all(&1u64.to_ne_bytes()).unwrap();
        f.write_all(&1u64.to_ne_bytes()).unwrap();
        let mut b = [0u8; 8];
        f.read_exact(&mut b).unwrap();
        assert_eq!(u64::from_ne_bytes(b), 2);
        assert_eq!(
            f.read(&mut b).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    /// MVM-1・TASK-75.1: ゲスト RAM の mmap フラグ・madvise の定数の具体値（`asm-generic/mman*.h`）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn guest_ram_constants_match_kernel_abi() {
        assert_eq!(consts::MAP_PRIVATE, 0x02);
        assert_eq!(consts::MAP_ANONYMOUS, 0x20);
        assert_eq!(consts::MAP_NORESERVE, 0x4000);
        assert_eq!(consts::MADV_DONTFORK, 10);
        assert_eq!(consts::MADV_DONTDUMP, 16);
    }

    /// MVM-1・TASK-75.1: ゲスト RAM はゼロ埋めで、読み書きが往復し、範囲外・桁あふれは拒否される。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn guest_ram_map_roundtrip_and_bounds() {
        let mut m = GuestRamMap::map(8192).unwrap();
        assert_eq!(m.len(), 8192);
        let mut b = [0xFFu8; 8];
        m.read_into(8184, &mut b).unwrap();
        assert_eq!(b, [0; 8]);
        m.write_from(4094, &[1, 2, 3, 4]).unwrap();
        let mut r = [0u8; 4];
        m.read_into(4094, &mut r).unwrap();
        assert_eq!(r, [1, 2, 3, 4]);
        assert!(m.write_from(8189, &[0; 4]).is_err());
        assert!(m.read_into(usize::MAX, &mut [0; 4]).is_err());
        assert!(m.write_from(8192, &[]).is_ok());
        assert_eq!(GuestRamMap::map(0).unwrap_err(), SysError::Os(22));
    }

    /// MVM-1・MVM-5・#3862: 整列 u16 の単一命令アクセスは幅 2 で LE、奇数オフセットと範囲外を拒否する。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn guest_ram_map_aligned_u16_width_and_alignment() {
        let mut m = GuestRamMap::map(8192).unwrap();
        m.write_from(2, &[0x34, 0x12]).unwrap();
        assert_eq!(m.read_u16_le_aligned(2), Ok(0x1234));
        m.write_u16_le_aligned(4, 0xBEEF).unwrap();
        let mut r = [0u8; 2];
        m.read_into(4, &mut r).unwrap();
        assert_eq!(r, [0xEF, 0xBE]);
        // 隣接バイトは書き換わっていない（幅 2）。
        let mut n = [0xFFu8; 1];
        m.read_into(3, &mut n).unwrap();
        assert_eq!(n, [0x12]);
        m.read_into(6, &mut n).unwrap();
        assert_eq!(n, [0]);
        assert_eq!(m.read_u16_le_aligned(1), Err(()));
        assert_eq!(m.write_u16_le_aligned(8191, 1), Err(()));
        assert_eq!(m.read_u16_le_aligned(8191), Err(()));
        assert_eq!(m.read_u16_le_aligned(8190), Ok(0));
        assert!(m.write_u16_le_aligned(8190, 7).is_ok());
        for off in [8192, usize::MAX - 1, usize::MAX] {
            assert_eq!(m.read_u16_le_aligned(off), Err(()));
            assert_eq!(m.write_u16_le_aligned(off, 1), Err(()));
        }
    }

    /// MVM-1・TASK-75.1: drop で munmap され、`/proc/self/maps` から範囲が消える。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn guest_ram_map_is_unmapped_on_drop() {
        let m = GuestRamMap::map(1 << 20).unwrap();
        let start = m.ptr.as_ptr() as usize;
        let needle = format!("{start:x}-");
        let present = |needle: &str| {
            std::fs::read_to_string("/proc/self/maps")
                .unwrap()
                .lines()
                .any(|l| l.starts_with(needle))
        };
        assert!(present(&needle));
        drop(m);
        assert!(!present(&needle));
    }

    /// MVM-1・REPAIR-4・#4330: munmap の戻り値と固定行の対応。0 は行なし、それ以外はすべて行あり。
    #[test]
    fn mvm1_4330_unmap_failure_line_maps_rc() {
        assert_eq!(unmap_failure_line(0, GUEST_RAM_UNMAP_FAILED_LINE), None);
        for rc in [-1, 1] {
            assert_eq!(
                unmap_failure_line(rc, GUEST_RAM_UNMAP_FAILED_LINE),
                Some("level=error op=kvm.guest_ram_unmap outcome=error leaked=guest_ram")
            );
            assert_eq!(
                unmap_failure_line(rc, KVM_RUN_UNMAP_FAILED_LINE),
                Some("level=error op=kvm.run_unmap outcome=error leaked=kvm_run")
            );
        }
    }

    /// MVM-1・REPAIR-4・#4330: ゲスト RAM の munmap が失敗（ptr をずらして EINVAL）したら固定の 1 行が出る。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4330_guest_ram_unmap_failure_emits_one_line() {
        let m = GuestRamMap::map(8192).unwrap();
        let fake = GuestRamMap {
            ptr: NonNull::new(m.ptr.as_ptr().wrapping_byte_add(1)).unwrap(),
            len: m.len,
            unmap_tally: None,
        };
        let ((), lines) = crate::hvf_loop::capture_log_lines(|| drop(fake));
        assert_eq!(
            lines,
            vec!["level=error op=kvm.guest_ram_unmap outcome=error leaked=guest_ram".to_string()]
        );
        drop(m);
    }

    /// MVM-1・REPAIR-4・#4330: `kvm_run` 領域の munmap 失敗でも固定の 1 行が出る（KVM 不要）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4330_kvm_run_unmap_failure_emits_one_line() {
        let m = GuestRamMap::map(8192).unwrap();
        let fake = KvmRunMap {
            ptr: NonNull::new(m.ptr.as_ptr().wrapping_byte_add(1)).unwrap(),
            len: m.len,
            unmap_tally: None,
        };
        let ((), lines) = crate::hvf_loop::capture_log_lines(|| drop(fake));
        assert_eq!(
            lines,
            vec!["level=error op=kvm.run_unmap outcome=error leaked=kvm_run".to_string()]
        );
        drop(m);
    }

    /// MVM-1・REPAIR-4・#4382: NULL 検査の失敗経路の munmap が失敗したら、元のエラーを保ったまま固定の 1 行が出る。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4382_null_mapping_rollback_failure_emits_one_line_and_keeps_error() {
        for (line, expected) in [
            (
                GUEST_RAM_UNMAP_FAILED_LINE,
                "level=error op=kvm.guest_ram_unmap outcome=error leaked=guest_ram",
            ),
            (
                KVM_RUN_UNMAP_FAILED_LINE,
                "level=error op=kvm.run_unmap outcome=error leaked=kvm_run",
            ),
        ] {
            let m = GuestRamMap::map(8192).unwrap();
            let shifted = m.ptr.as_ptr().wrapping_byte_add(1).cast::<c_void>();
            let len = m.len;
            // SAFETY: munmap は引数を参照外ししない。ずらした ptr で EINVAL を起こすだけ（#4330 と同じ）。
            let (err, lines) = crate::hvf_loop::capture_log_lines(|| unsafe {
                rollback_failed_map(shifted, len, line, SysError::NullMapping)
            });
            assert!(matches!(err, SysError::NullMapping));
            assert_eq!(lines, vec![expected.to_string()]);
            drop(m);
        }
    }

    /// MVM-1・REPAIR-4・#4382: `madvise` の失敗経路の munmap も失敗したら、errno を保ったまま 1 行だけ出る。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4382_madvise_failure_rollback_failure_emits_one_line_and_keeps_errno() {
        let m = GuestRamMap::map(8192).unwrap();
        let shifted = m.ptr.as_ptr().wrapping_byte_add(1).cast::<c_void>();
        let len = m.len;
        // SAFETY: 閉包はメモリに触れない。munmap は引数を参照外ししない。
        let (res, lines) = crate::hvf_loop::capture_log_lines(|| unsafe {
            finish_guest_ram_map(shifted, len, |_, _, _| Err(SysError::Os(99)))
        });
        assert!(matches!(res, Err(SysError::Os(99))));
        assert_eq!(
            lines,
            vec!["level=error op=kvm.guest_ram_unmap outcome=error leaked=guest_ram".to_string()]
        );
        drop(m);
    }

    /// MVM-1・REPAIR-4・#4382: `madvise` が失敗し munmap が成功したら行は出ず、領域は実際に解放される。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4382_madvise_failure_rollback_success_emits_no_line() {
        // `/proc/self/maps` のアドレス照合は、並列の別試験が解放直後の同じアドレスへ mmap すると誤る（#4412・REPAIR-12）。
        // そこで PROT_NONE の予約の中へ MAP_FIXED で置き、巻き戻しの後に同じアドレスへ MAP_FIXED_NOREPLACE で
        // 置き直せること（解放済み）で確かめる。解放した穴は他スレッドの mmap が拾いうるため、
        // (1) 後始末で munmap するのは自分の予約の両端だけで、穴は置き直せた時だけ解除する（他スレッドの領域を巻き込まない）、
        // (2) 穴を他スレッドに取られて置き直せなかった場合に備え、新しい予約で最大 ATTEMPTS 回やり直す。
        //     本当に解放されない不具合なら毎回失敗するので、1 回も成功しなければ失敗にする。
        // libc との機械照合は microvm に未導入（#3664・#3290）。定数は Linux の x86_64・aarch64 共通の ABI 値。
        const PROT_NONE: i32 = 0;
        const MAP_FIXED: i32 = 0x10;
        const MAP_FIXED_NOREPLACE: i32 = 0x0010_0000;
        const ATTEMPTS: usize = 16;
        // ホストのページサイズ（4 KiB・16 KiB・64 KiB）に合わせて、オフセット・長さ・予約をページ単位で計算する。
        let page = usize::try_from(host_page_size().unwrap()).unwrap();
        let len = 2 * page;
        let reserve = 64 * page;
        let anon = consts::MAP_PRIVATE | consts::MAP_ANONYMOUS | consts::MAP_NORESERVE;
        let mut released = false;
        for _ in 0..ATTEMPTS {
            // SAFETY: 新規の匿名マッピングで既存領域に触れない。戻り値は失敗値（-1）と比較してから使う。
            let base = unsafe { mmap(std::ptr::null_mut(), reserve, PROT_NONE, anon, -1, 0) };
            assert_ne!(base as isize, -1, "reserve failed");
            let p = base.wrapping_byte_add(page);
            // SAFETY: `p..p+len` は上の予約の内側で、MAP_FIXED が置き換えるのは自分の予約だけ。
            let got = unsafe {
                mmap(
                    p,
                    len,
                    consts::PROT_READ | consts::PROT_WRITE,
                    anon | MAP_FIXED,
                    -1,
                    0,
                )
            };
            assert_eq!(got, p);
            // 陽性対照: 使用中の範囲への NOREPLACE は置けない。
            // SAFETY: NOREPLACE は既存の領域を置き換えず失敗するだけ。
            let busy = unsafe { mmap(p, len, PROT_NONE, anon | MAP_FIXED_NOREPLACE, -1, 0) };
            assert_eq!(busy as isize, -1);
            // SAFETY: `p` / `len` は上の mmap の領域で、この試験の他に所有者がいない。
            let (res, lines) = crate::hvf_loop::capture_log_lines(|| unsafe {
                finish_guest_ram_map(p, len, |_, _, _| Err(SysError::Os(99)))
            });
            assert!(matches!(res, Err(SysError::Os(99))));
            assert_eq!(lines, Vec::<String>::new());
            // SAFETY: 解放済みなら同じアドレスへ置き直せる。置けなければ何も変わらない。
            let again = unsafe { mmap(p, len, PROT_NONE, anon | MAP_FIXED_NOREPLACE, -1, 0) };
            // SAFETY: 前後の予約 `base..p` と `p+len..base+reserve` は PROT_NONE の自分の予約で、他に所有者がいない。
            let (head, tail) = unsafe {
                (
                    munmap(base, page),
                    munmap(p.wrapping_byte_add(len), reserve - page - len),
                )
            };
            assert_eq!((head, tail), (0, 0));
            if again == p {
                // SAFETY: NOREPLACE で自分が置いた領域。
                assert_eq!(unsafe { munmap(p, len) }, 0);
                released = true;
                break;
            }
            // 穴は他スレッドに取られた可能性があるため、解除せずやり直す（他の領域を壊さない）。
        }
        assert!(released, "region was not released by the rollback");
    }

    /// MVM-1・REPAIR-4・#4382: drop の munmap 失敗は VM ごとの tally に 1 件数える。成功の drop は数えない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4382_drop_failure_records_tally() {
        let t = Arc::new(UnmapTally::default());
        let m = GuestRamMap::map(8192).unwrap();
        let ram = GuestRamMap {
            ptr: NonNull::new(m.ptr.as_ptr().wrapping_byte_add(1)).unwrap(),
            len: m.len,
            unmap_tally: Some(Arc::clone(&t)),
        };
        let ((), lines) = crate::hvf_loop::capture_log_lines(|| drop(ram));
        assert_eq!(lines.len(), 1);
        assert_eq!(t.count(), 1);
        let run = KvmRunMap {
            ptr: NonNull::new(m.ptr.as_ptr().wrapping_byte_add(1)).unwrap(),
            len: m.len,
            unmap_tally: Some(Arc::clone(&t)),
        };
        let ((), lines) = crate::hvf_loop::capture_log_lines(|| drop(run));
        assert_eq!(lines.len(), 1);
        assert_eq!(t.count(), 2);
        drop(m);

        let t2 = Arc::new(UnmapTally::default());
        let mut ok = GuestRamMap::map(8192).unwrap();
        ok.set_unmap_tally(Arc::clone(&t2));
        let ((), lines) = crate::hvf_loop::capture_log_lines(|| drop(ok));
        assert_eq!(lines, Vec::<String>::new());
        assert_eq!(t2.count(), 0);
    }

    /// MVM-1・REPAIR-4・#4330: munmap が成功したら行は出ない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4330_guest_ram_unmap_success_emits_no_line() {
        let m = GuestRamMap::map(8192).unwrap();
        let ((), lines) = crate::hvf_loop::capture_log_lines(|| drop(m));
        assert_eq!(lines, Vec::<String>::new());
    }

    /// MVM-1・#4158: 登録に渡る構造体の `flags` は指定値（0・1・2・3）のまま、他のフィールドも具体値どおり。
    #[test]
    fn mvm1_4158_memory_region_carries_flags() {
        for flags in 0..=3u32 {
            let r = memory_region(7, flags, 0x1000, 0x2000, 0x7000_0000);
            assert_eq!(r.slot, 7);
            assert_eq!(r.flags, flags);
            assert_eq!(r.guest_phys_addr, 0x1000);
            assert_eq!(r.memory_size, 0x2000);
            assert_eq!(r.userspace_addr, 0x7000_0000);
        }
    }

    /// MVM-1・TASK-75.1: KVM でない fd への登録は ENOTTY で、mapping は呼び出し側に残る。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn register_guest_ram_on_non_kvm_fd_is_enotty() {
        use std::os::fd::AsFd as _;
        let f = dev_null();
        let m = GuestRamMap::map(4096).unwrap();
        for flags in [0u32, 2] {
            assert_eq!(
                set_user_memory_region(f.as_fd(), 0, flags, 0, m.len() as u64, m.user_addr()),
                Err(SysError::Os(25))
            );
        }
        assert_eq!(unregister_guest_ram(f.as_fd(), 0), Err(SysError::Os(25)));
    }

    /// MVM-1・#4225: kvm_dirty_bitmap_bytes 相当の長さ（64 ページ単位の切り上げ × 8）。
    #[test]
    fn mvm1_4225_dirty_bitmap_bytes_values() {
        assert_eq!(dirty_bitmap_bytes(64 * 1024, 4096), Some(8));
        assert_eq!(dirty_bitmap_bytes(256 * 1024, 4096), Some(8));
        assert_eq!(dirty_bitmap_bytes(260 * 1024, 4096), Some(16));
        assert_eq!(dirty_bitmap_bytes(1 << 34, 4096), Some(524_288));
        assert_eq!(dirty_bitmap_bytes(1 << 20, 65536), Some(8));
        assert_eq!(dirty_bitmap_bytes(4096, 0), None);
        assert_eq!(dirty_bitmap_bytes(4096, 3), None);
        assert_eq!(dirty_bitmap_bytes(4097, 4096), None);
        assert_eq!(
            dirty_bitmap_bytes(u64::MAX - 63, 1),
            Some(((u64::MAX - 63) / 64) * 8)
        );
    }

    /// MVM-1・#4225: `KVM_GET_DIRTY_LOG` に渡す構造体の各フィールド。
    #[test]
    fn mvm1_4225_dirty_log_request_fields() {
        let r = dirty_log_request(7, 0x7000_0000);
        assert_eq!(r.slot, 7);
        assert_eq!(r.padding1, 0);
        assert_eq!(r.dirty_bitmap, 0x7000_0000);
    }

    /// MVM-1・#4225: バッファ長の検査は ioctl の前に効く（短いと EINVAL、十分なら ioctl まで届き非 KVM fd の ENOTTY）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_4225_get_dirty_log_short_buffer_is_einval_before_ioctl() {
        use std::os::fd::AsFd as _;
        let f = dev_null();
        for len in [0usize, 7, 8, crate::dirty_log::MAX_DIRTY_BITMAP_BYTES - 1] {
            let mut buf = vec![0u8; len];
            assert_eq!(
                kvm_get_dirty_log(f.as_fd(), 0, 64 * 1024, &mut buf),
                Err(SysError::Os(22))
            );
        }
        let mut ok = vec![0u8; crate::dirty_log::MAX_DIRTY_BITMAP_BYTES];
        assert_eq!(
            kvm_get_dirty_log(f.as_fd(), 0, 64 * 1024, &mut ok),
            Err(SysError::Os(25))
        );
    }

    /// MVM-1: aarch64 の vCPU 初期化 ioctl 番号。
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn arm_vcpu_constants_match_kernel_abi() {
        assert_eq!(consts::KVM_ARM_VCPU_INIT, 0x4020_AEAE);
        assert_eq!(consts::KVM_ARM_PREFERRED_TARGET, 0x8020_AEAF);
    }

    /// MVM-1・#3896: PSCI 0.2 の capability・feature ビット番号と、ビットを立てる純関数。
    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    #[test]
    fn mvm1_3896_psci_0_2_constants_and_features() {
        assert_eq!(consts::KVM_CAP_ARM_PSCI_0_2.0, 102);
        assert_eq!(consts::KVM_CAP_ARM_VM_IPA_SIZE.0, 165);
        assert_eq!(consts::KVM_ARM_VCPU_PSCI_0_2, 2);
        let init = with_psci_0_2(KvmVcpuInit {
            target: 5,
            features: [0, 1, 2, 3, 4, 5, 6],
        });
        assert_eq!(init.target, 5);
        assert_eq!(init.features, [0b100, 1, 2, 3, 4, 5, 6]);
    }

    /// MVM-1・#3899: POWER_OFF のビット番号と、ビットを立てる純関数（PSCI_0_2 と合成すると 0b101）。
    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    #[test]
    fn mvm1_3899_power_off_constants_and_features() {
        assert_eq!(consts::KVM_ARM_VCPU_POWER_OFF, 0);
        let init = with_power_off(KvmVcpuInit {
            target: 5,
            features: [0, 1, 2, 3, 4, 5, 6],
        });
        assert_eq!(init.features, [0b1, 1, 2, 3, 4, 5, 6]);
        let both = with_psci_0_2(with_power_off(KvmVcpuInit::default()));
        assert_eq!(both.features[0], 0b101);
    }

    /// MVM-1・#3899: `MPIDR_EL1` の ONE_REG id（arch に依らず計算式を固定する）。
    #[test]
    fn mvm1_3899_mpidr_el1_reg_id() {
        assert_eq!(ARM64_REG_MPIDR_EL1, 0x6030_0000_0013_C005);
    }

    /// MVM-1・#3696: aarch64 の core レジスタ id（`KVM_REG_ARM_CORE_REG` の u32 換算）。arch に依らず計算式を固定する。
    #[test]
    fn mvm1_3696_arm64_core_reg_ids() {
        assert_eq!(ARM64_REG_PC, 0x6030_0000_0010_0040);
        assert_eq!(ARM64_REG_PSTATE, 0x6030_0000_0010_0042);
        assert_eq!(arm64_reg_x(0), Some(0x6030_0000_0010_0000));
        assert_eq!(arm64_reg_x(1), Some(0x6030_0000_0010_0002));
        assert_eq!(arm64_reg_x(3), Some(0x6030_0000_0010_0006));
        assert_eq!(arm64_reg_x(30), Some(0x6030_0000_0010_003C));
        assert_eq!(arm64_reg_x(31), None);
    }

    /// MVM-1・#3696: aarch64 の vGIC・ONE_REG の ioctl 番号と定数。
    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
    #[test]
    fn mvm1_3696_arm_vgic_constants_match_kernel_abi() {
        assert_eq!(consts::KVM_CREATE_DEVICE, 0xC00C_AEE0);
        assert_eq!(consts::KVM_SET_DEVICE_ATTR, 0x4018_AEE1);
        assert_eq!(consts::KVM_GET_DEVICE_ATTR, 0x4018_AEE2);
        assert_eq!(consts::KVM_GET_ONE_REG, 0x4010_AEAB);
        assert_eq!(consts::KVM_SET_ONE_REG, 0x4010_AEAC);
        assert_eq!(consts::KVM_DEV_TYPE_ARM_VGIC_V3, 7);
        assert_eq!(consts::KVM_CAP_DEVICE_CTRL.0, 89);
    }

    /// MVM-1・MVM-4・#3731: x86_64 起動用の ioctl 番号と上限の具体値。
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn x86_boot_ioctl_constants_match_kernel_abi() {
        assert_eq!(iowr(0xAE, 0x05, 8), 0xC008_AE05);
        assert_eq!(consts::KVM_GET_SUPPORTED_CPUID, 0xC008_AE05);
        assert_eq!(consts::KVM_SET_CPUID2, 0x4008_AE90);
        assert_eq!(consts::KVM_GET_MSRS, 0xC008_AE88);
        assert_eq!(consts::KVM_SET_MSRS, 0x4008_AE89);
        assert_eq!(consts::KVM_GET_FPU, 0x81A0_AE8C);
        assert_eq!(consts::KVM_SET_FPU, 0x41A0_AE8D);
        assert_eq!(consts::KVM_GET_MP_STATE, 0x8004_AE98);
        assert_eq!(consts::KVM_SET_MP_STATE, 0x4004_AE99);
        assert_eq!(consts::KVM_GET_LAPIC, 0x8400_AE8E);
        assert_eq!(consts::KVM_SET_LAPIC, 0x4400_AE8F);
        assert_eq!(consts::KVM_SET_TSS_ADDR, 0xAE47);
        assert_eq!(consts::KVM_SET_IDENTITY_MAP_ADDR, 0x4008_AE48);
        assert_eq!(consts::MAX_CPUID_ENTRIES, 256);
        assert_eq!(consts::MAX_MSR_ENTRIES, 255);
    }

    /// MVM-1・MVM-4・#3731: 構造体のサイズと主要オフセットの具体値。
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn x86_boot_struct_layout_matches_kernel_abi() {
        use std::mem::{offset_of, size_of};
        assert_eq!(size_of::<KvmCpuidEntry2>(), 40);
        assert_eq!(offset_of!(KvmCpuidEntry2, padding), 28);
        assert_eq!(size_of::<KvmMsrEntry>(), 16);
        assert_eq!(offset_of!(KvmMsrEntry, data), 8);
        assert_eq!(size_of::<KvmFpu>(), 416);
        assert_eq!(offset_of!(KvmFpu, xmm), 152);
        assert_eq!(offset_of!(KvmFpu, mxcsr), 408);
        assert_eq!(size_of::<KvmLapicState>(), 1024);
    }

    /// MVM-1・#3731: 起動用 ioctl は KVM でない fd に対して ENOTTY（unsafe 経路を KVM 無しで通す）。
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn x86_boot_ioctls_on_non_kvm_fd_are_enotty() {
        use std::os::fd::AsFd as _;
        let f = dev_null();
        let fd = f.as_fd();
        let enotty = SysError::Os(25);
        assert_eq!(kvm_get_supported_cpuid(fd, 8), Err(enotty));
        assert_eq!(
            kvm_set_cpuid2(fd, &[KvmCpuidEntry2::default(); 2]),
            Err(enotty)
        );
        let mut m = [KvmMsrEntry {
            index: 0x10,
            ..Default::default()
        }];
        assert_eq!(kvm_get_msrs(fd, &mut m), Err(enotty));
        assert_eq!(kvm_set_msrs(fd, &m), Err(enotty));
        assert_eq!(kvm_get_fpu(fd), Err(enotty));
        assert_eq!(kvm_set_fpu(fd, &KvmFpu::default()), Err(enotty));
        assert_eq!(kvm_get_mp_state(fd), Err(enotty));
        assert_eq!(kvm_set_mp_state(fd, &KvmMpState::default()), Err(enotty));
        assert_eq!(kvm_get_lapic(fd), Err(enotty));
        assert_eq!(kvm_set_lapic(fd, &KvmLapicState::default()), Err(enotty));
        assert_eq!(kvm_set_tss_addr(fd, 0xFFFB_D000), Err(enotty));
        assert_eq!(kvm_set_identity_map_addr(fd, 0xFFFB_C000), Err(enotty));
    }

    /// MVM-4・REPAIR-5・#3731: 件数の上限超過は確保・ioctl より前に E2BIG（ENOTTY でないので ioctl 未到達）。
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn x86_boot_entry_limits_are_rejected_before_allocation() {
        use std::os::fd::AsFd as _;
        let f = dev_null();
        let fd = f.as_fd();
        let e2big = SysError::Os(7);
        assert_eq!(kvm_get_supported_cpuid(fd, 257), Err(e2big));
        assert_eq!(kvm_get_supported_cpuid(fd, usize::MAX), Err(e2big));
        assert_eq!(kvm_get_supported_cpuid(fd, 0), Err(e2big));
        assert_eq!(
            kvm_set_cpuid2(fd, &vec![KvmCpuidEntry2::default(); 257]),
            Err(e2big)
        );
        let mut m = vec![KvmMsrEntry::default(); 256];
        assert_eq!(kvm_get_msrs(fd, &mut m), Err(e2big));
        assert_eq!(kvm_set_msrs(fd, &m), Err(e2big));
        // 境界は ioctl まで届く。
        assert_eq!(
            kvm_set_cpuid2(fd, &vec![KvmCpuidEntry2::default(); 256]),
            Err(SysError::Os(25))
        );
        let mut m = vec![KvmMsrEntry::default(); 255];
        assert_eq!(kvm_get_msrs(fd, &mut m), Err(SysError::Os(25)));
    }

    /// MVM-4・#3731: 可変長バッファの往復と、カーネル応答（件数・戻り値）の検証。
    #[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
    #[test]
    fn flex_buffer_roundtrip_and_untrusted_count() {
        fn assert_flex_entry<E: FlexEntry>() {}
        assert_flex_entry::<KvmCpuidEntry2>();
        assert_flex_entry::<KvmMsrEntry>();
        let mut b = FlexBuf::<KvmCpuidEntry2>::with_capacity(3, 256).unwrap();
        assert_eq!(b.count(), 3);
        let src = [
            KvmCpuidEntry2 {
                function: 1,
                eax: 7,
                ..Default::default()
            },
            KvmCpuidEntry2 {
                function: 0xB,
                edx: 9,
                ..Default::default()
            },
        ];
        b.fill(&src).unwrap();
        assert_eq!(b.entries(2).unwrap(), &src);
        assert_eq!(b.entries(4), Err(SysError::Os(22)));
        assert_eq!(
            b.fill(&[KvmCpuidEntry2::default(); 4]),
            Err(SysError::Os(22))
        );
        // カーネルが容量超の件数を書き戻した場合を模擬する。
        b.set_count(4);
        assert_eq!(b.entries(b.count() as usize), Err(SysError::Os(22)));

        let m = FlexBuf::<KvmMsrEntry>::with_capacity(2, 255).unwrap();
        assert_eq!(m.count(), 2);
        assert_eq!(m.ptr.as_ptr() as usize % 8, 0);
        assert_eq!(
            FlexBuf::<KvmMsrEntry>::with_capacity(256, 255).err(),
            Some(SysError::Os(7))
        );
        assert_eq!(msr_result(2, 2), Ok(2));
        assert_eq!(msr_result(0, 2), Ok(0));
        assert_eq!(msr_result(3, 2), Err(SysError::Os(22)));
    }
}
