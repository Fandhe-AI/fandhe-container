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
//! TASK-74.2.3 で `KVM_CHECK_EXTENSION`・`KVM_CREATE_IRQCHIP`（x86_64 のみ）・`KVM_IRQFD`・`KVM_IOEVENTFD` と
//! `eventfd` を足した（`crate::irq` の `EventFd`・`IrqFd`・`IoEventFd` と `device::VmFd` のメソッドが呼ぶ）。
//! eventfd の読み書きは std の `File` で行い、ここには読み書きの `unsafe` を持たない。
//! `KVM_RUN` 以外の ioctl はブロックしない同期呼び出しで、`KVM_RUN` はゲストが exit しない限り戻らない
//! （期限は `crate::device` が `KvmRunMap::set_immediate_exit` と `KickTarget::kick`（`SIGUSR2`。`with_current_thread` の中だけで使える）で中断する。REPAIR-5）。停止要求（`RunningMicroVm::stop` / drop）も同じ監視スレッド経由でこれを使い、`sys` に unsafe は足していない（#3736）。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と維持すべき不変条件を明記する
//! - 定数は `cfg(target_arch = ...)` ごとに個別に定義し（値が同じでも流用しない）、対応外では
//!   [`SysError::Unsupported`] を返す（fail-closed）。対応は glibc（`target_env = "gnu"`）の LP64 の x86_64・aarch64 だけ。musl は `ioctl` の `request` の型が異なるため対象外
//! - 戻り値が `-1` のときは直後に `std::io::Error::last_os_error()` で errno を確保する
//!
//! # `libc` との機械照合について
//! TASK-75.1 で匿名 mmap のゲスト RAM（`GuestRamMap`）・`madvise(MADV_DONTFORK)`・登録 / 削除のラッパーを足した
//! （`crate::microvm` の `GuestRam`・`RegisteredGuestRam` が呼ぶ。`madvise` も `libc` 導入後は照合の対象）。
//! 本 crate は dev-dependency に `libc` を持たず照合は未導入（追加は crate ごとの承認事項。
//! `docs/design/ffi-libc-check.md`「適用状況」）。なお `KVM_*` の ioctl 番号は `linux/kvm.h` のカーネル ABI で
//! `libc` に対応物が無く、導入後も `ioctl` 関数の型の照合だけが対象になる（`mmap` / `munmap` も導入後は照合の対象）。
//! `eventfd` は `libc` に対応物があり、導入後は照合の対象になる。`kvm_irqfd`・`kvm_ioeventfd` もカーネル ABI で
//! 対応物が無く、サイズ・オフセットを const assert で固定する。
//! `kvm_regs`・`kvm_sregs`（`kvm_segment`・`kvm_dtable` を含む）も `libc` に対応物が無く、サイズ・オフセットを const assert で固定する（照合の追跡は #3664）。
//! `kvm_cpuid2` / `kvm_cpuid_entry2`・`kvm_msrs` / `kvm_msr_entry`・`kvm_fpu`・`kvm_lapic_state` も `asm/kvm.h` のカーネル ABI で
//! `libc` に対応物が無く、サイズ・オフセットを const assert で固定する（照合の追跡は #3664）。上限の `KVM_MAX_CPUID_ENTRIES`・
//! `MAX_IO_MSRS` はカーネル内部の値で uapi にも無い。
//! `kvm_userspace_memory_region` と `kvm_run` もカーネル ABI で `libc` に対応物が無く、サイズ・オフセットを const assert で固定する。aarch64 の `kvm_vcpu_init`
//! （`asm/kvm.h` のカーネル ABI 構造体）も `libc` に対応物が無く、サイズ・アラインを const assert で固定する。

#![cfg(target_os = "linux")]

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ffi::c_void;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::ptr::NonNull;
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
    /// `_IO(KVMIO, 0x03)`（`/dev/kvm` と VM fd のどちらにも発行できる）。
    pub const KVM_CHECK_EXTENSION: u64 = super::io(super::KVMIO, 0x03);
    /// `_IO(KVMIO, 0x60)`（x86_64 のみ定義。vCPU を作る前に発行する）。
    pub const KVM_CREATE_IRQCHIP: u64 = super::io(super::KVMIO, 0x60);
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
    /// `_IOR(KVMIO, 0x8e, struct kvm_lapic_state)`（1024 バイト）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub const KVM_GET_LAPIC: u64 = super::ior(super::KVMIO, 0x8e, 1024);
    /// `_IOW(KVMIO, 0x8f, struct kvm_lapic_state)`。
    #[cfg_attr(not(test), allow(dead_code))]
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
    pub const KVM_CAP_IRQCHIP: u64 = 0;
    pub const KVM_CAP_IRQFD: u64 = 32;
    pub const KVM_CAP_IOEVENTFD: u64 = 36;
    pub const KVM_IRQFD_FLAG_DEASSIGN: u32 = 1 << 0;
    pub const KVM_IOEVENTFD_FLAG_DATAMATCH: u32 = 1 << 0;
    pub const KVM_IOEVENTFD_FLAG_PIO: u32 = 1 << 1;
    pub const KVM_IOEVENTFD_FLAG_DEASSIGN: u32 = 1 << 2;
    /// glibc の `EFD_CLOEXEC`（`O_CLOEXEC` = 0o2000000）。
    pub const EFD_CLOEXEC: i32 = 0o2000000;
    /// glibc の `EFD_NONBLOCK`（`O_NONBLOCK` = 0o4000）。
    pub const EFD_NONBLOCK: i32 = 0o4000;
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
    /// `_IOW(KVMIO, 0xae, struct kvm_vcpu_init)`（32 バイト）。
    pub const KVM_ARM_VCPU_INIT: u64 = super::iow(super::KVMIO, 0xAE, 32);
    /// `_IOR(KVMIO, 0xaf, struct kvm_vcpu_init)`（32 バイト）。
    pub const KVM_ARM_PREFERRED_TARGET: u64 = super::ior(super::KVMIO, 0xAF, 32);
    /// `_IO(KVMIO, 0x03)`（`/dev/kvm` と VM fd のどちらにも発行できる）。
    pub const KVM_CHECK_EXTENSION: u64 = super::io(super::KVMIO, 0x03);
    /// `_IOW(KVMIO, 0x76, struct kvm_irqfd)`（32 バイト）。
    pub const KVM_IRQFD: u64 = super::iow(super::KVMIO, 0x76, 32);
    /// `_IOW(KVMIO, 0x79, struct kvm_ioeventfd)`（64 バイト）。
    pub const KVM_IOEVENTFD: u64 = super::iow(super::KVMIO, 0x79, 64);
    pub const KVM_CAP_IRQFD: u64 = 32;
    pub const KVM_CAP_IOEVENTFD: u64 = 36;
    pub const KVM_IRQFD_FLAG_DEASSIGN: u32 = 1 << 0;
    pub const KVM_IOEVENTFD_FLAG_DATAMATCH: u32 = 1 << 0;
    pub const KVM_IOEVENTFD_FLAG_PIO: u32 = 1 << 1;
    pub const KVM_IOEVENTFD_FLAG_DEASSIGN: u32 = 1 << 2;
    /// glibc の `EFD_CLOEXEC`（`O_CLOEXEC` = 0o2000000）。
    pub const EFD_CLOEXEC: i32 = 0o2000000;
    /// glibc の `EFD_NONBLOCK`（`O_NONBLOCK` = 0o4000）。
    pub const EFD_NONBLOCK: i32 = 0o4000;
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
    pub const PROT_READ: i32 = 0;
    pub const PROT_WRITE: i32 = 0;
    pub const MAP_SHARED: i32 = 0;
    pub const MAP_PRIVATE: i32 = 0;
    pub const MAP_ANONYMOUS: i32 = 0;
    pub const MAP_NORESERVE: i32 = 0;
    pub const MADV_DONTFORK: i32 = 0;
    pub const KVM_CHECK_EXTENSION: u64 = 0;
    pub const KVM_IRQFD: u64 = 0;
    pub const KVM_IOEVENTFD: u64 = 0;
    pub const KVM_CAP_IRQFD: u64 = 0;
    pub const KVM_CAP_IOEVENTFD: u64 = 0;
    pub const KVM_IRQFD_FLAG_DEASSIGN: u32 = 0;
    pub const KVM_IOEVENTFD_FLAG_DATAMATCH: u32 = 0;
    pub const KVM_IOEVENTFD_FLAG_PIO: u32 = 0;
    pub const KVM_IOEVENTFD_FLAG_DEASSIGN: u32 = 0;
    pub const EFD_CLOEXEC: i32 = 0;
    pub const EFD_NONBLOCK: i32 = 0;
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
};

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
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct KvmLapicState {
    pub regs: [u8; 1024],
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[cfg_attr(not(test), allow(dead_code))]
impl Default for KvmLapicState {
    fn default() -> Self {
        KvmLapicState { regs: [0; 1024] }
    }
}

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
    assert!(consts::KVM_GET_VCPU_MMAP_SIZE == 0xAE04);
    assert!(consts::KVM_RUN == 0xAE80);
    assert!(consts::KVM_CHECK_EXTENSION == 0xAE03);
    assert!(consts::KVM_IRQFD == 0x4020_AE76);
    assert!(consts::KVM_IOEVENTFD == 0x4040_AE79);
};

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
const _: () = assert!(consts::KVM_CREATE_IRQCHIP == 0xAE60);

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

/// `pthread_kill` の宛先スレッド。生存中のスレッドを指すことを型で保証する（`with_current_thread` が唯一の入口）。
///
/// # 健全性（終了したスレッドへの `pthread_kill` は glibc で未定義動作になりうる）
/// `'a` は [`with_current_thread`] の高階クロージャが決めるため、呼び出し側は次のどれもできない:
/// 戻り値への混入・外側の変数への保存・`'static` を要求する `std::thread::spawn` への受け渡し・クロージャより
/// 外側の scope への `spawn`。渡せるのはクロージャの中で作る `thread::scope` の scoped thread だけで、それは
/// scope が戻る前（panic の巻き戻しを含む）に必ず join される。クロージャは対象スレッド自身の上で同期実行される
/// ため、`KickTarget` が使われうる間、対象スレッドは終了も join もしておらず、`pthread_t` も再利用されない。
///
/// 退けた案: `!Send` の guard 借用で生存を表す案は `Box::leak` で `'static` にでき、`&Scope` 由来のライフタイム案は
/// scoped thread が自分を途中で join できるため、どちらも健全にならない。外へ持ち出せないことの compile-fail
/// 試験は置かない（trybuild は依存の追加で、doctest は private な `sys` に届かない）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct KickTarget<'a> {
    thread: u64,
    _alive: std::marker::PhantomData<&'a ()>,
}

/// 呼び出しスレッドを宛先とする [`KickTarget`] を作って `f` を同期実行する。`f` が戻るまで対象スレッドは生存する。
///
/// `crate::device` の `run_bounded` が、vCPU スレッド上で期限監視の scoped thread へ `KickTarget` を渡すために使う。
pub(crate) fn with_current_thread<R>(f: impl for<'a> FnOnce(KickTarget<'a>) -> R) -> R {
    // SAFETY: 引数なしで呼び出しスレッドの `pthread_t` を返すだけ。副作用・失敗は無い。
    let thread = unsafe { pthread_self() };
    f(KickTarget {
        thread,
        _alive: std::marker::PhantomData,
    })
}

impl KickTarget<'_> {
    /// このスレッドへ vCPU 中断シグナルを送る。
    pub(crate) fn kick(self) -> Result<(), SysError> {
        if !consts::SUPPORTED {
            return Err(SysError::Unsupported);
        }
        // SAFETY: `self.thread` は `with_current_thread` の中で `pthread_self` が返した値で、`'a` が高階のため
        // `with_current_thread` が戻る前（対象スレッドが生存中）にしか使えない。シグナル番号は固定の SIGUSR2。
        // ポインタ引数は無い。戻り値は errno そのもの。
        let r = unsafe { pthread_kill(self.thread, SIG_VCPU_KICK) };
        if r == 0 { Ok(()) } else { Err(SysError::Os(r)) }
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

/// `KVM_CHECK_EXTENSION`（KVM デバイス fd または VM fd）。戻り値は拡張の対応状況（0 は非対応）。
pub(crate) fn kvm_check_extension(fd: BorrowedFd<'_>, cap: u64) -> Result<i32, SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    // SAFETY: `fd` は借用中の生存 fd。`cap` は値渡しの `unsigned long` でポインタを含まず、
    // カーネルはユーザー空間のメモリを読み書きしない（戻り値が結果）。
    let r = unsafe { ioctl(fd.as_raw_fd(), consts::KVM_CHECK_EXTENSION, cap) };
    if r < 0 { Err(last_error()) } else { Ok(r) }
}

/// `KVM_CREATE_IRQCHIP`（VM fd。x86_64 のみ。vCPU を作る前に発行する）。他 arch は `Unsupported`
/// （aarch64 の vGIC は `KVM_CREATE_DEVICE` で別方式。TASK-75）。
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
}

// SAFETY: 領域への書き込みはカーネルが `KVM_RUN` の実行中にだけ行い、`KVM_RUN` は `&mut VcpuFd` 経由でしか
// 発行されないため、`&self` からの読み取りと重ならない。ポインタはマッピングの生存中（drop まで）有効で、
// スレッドに固有ではない。
unsafe impl Send for KvmRunMap {}
// SAFETY: 上と同じ。共有参照から行うのは volatile の読み取りと、`immediate_exit`（オフセット 1）の
// `AtomicU8` による読み書きだけで、後者は期限監視スレッドと同時でもデータ競合にならない。カーネルによる書き込みは
// `&mut VcpuFd` 経由の `KVM_RUN` の間だけ。`write_from` は `&mut self` で排他的。
unsafe impl Sync for KvmRunMap {}

impl KvmRunMap {
    /// vCPU fd の先頭から `len` バイトを読み書き可能・共有で mmap する。`len` は呼び出し側が検証済み
    /// （非 0・上限内・ページ倍数）のものだけを渡す。
    pub(crate) fn map(vcpu: BorrowedFd<'_>, len: usize) -> Result<KvmRunMap, SysError> {
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
            Some(ptr) => Ok(KvmRunMap { ptr, len }),
            None => {
                // SAFETY: 直前の mmap が返した長さ `len` の領域そのもので、他に所有者がいない。
                let _ = unsafe { munmap(p, len) };
                Err(SysError::NullMapping)
            }
        }
    }

    /// `off..off+buf.len()` を `buf` へ volatile でコピーする。範囲外・桁あふれは `Err`（添字アクセスをしない）。
    pub(crate) fn read_into(&self, off: usize, buf: &mut [u8]) -> Result<(), ()> {
        let end = off.checked_add(buf.len()).ok_or(())?;
        if end > self.len {
            return Err(());
        }
        for (i, b) in buf.iter_mut().enumerate() {
            // SAFETY: `off + i < end <= len` を上で検査済みで、`ptr` は `len` バイトのマッピングの先頭。
            // マッピングは `self` の生存中有効。カーネルが並行して書き換えうるため参照を作らず volatile で 1 バイト読む。
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
    pub(crate) fn write_from(&mut self, off: usize, buf: &[u8]) -> Result<(), ()> {
        let end = off.checked_add(buf.len()).ok_or(())?;
        if end > self.len {
            return Err(());
        }
        for (i, b) in buf.iter().enumerate() {
            // SAFETY: `off + i < end <= len` を上で検査済みで、`ptr` は `len` バイトのマッピングの先頭。
            // マッピングは `self` の生存中有効で、PROT_WRITE で mmap 済み。`&mut self` のため `KVM_RUN` の実行中
            // （カーネルが領域を書く間）には呼ばれず、参照を作らず volatile で 1 バイトだけ書く。
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
        // 前提に読む ABI。Rust 側でこのバイトに触るのは、この atomic store と `read_into` の atomic load と、
        // `&mut self` で排他的な `write_from` だけ（`&self` のこの関数とは重ならない）。SeqCst は呼び出し側の
        // `timed_out` の store と順序を揃え、その後の `KickTarget::kick` より前に見えることを保証する。
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
        // 失敗しても何もできず、drop で panic しないため戻り値は無視する。
        let _ = unsafe { munmap(self.ptr.as_ptr().cast::<c_void>(), self.len) };
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

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn set_user_memory_region(
    vm: BorrowedFd<'_>,
    slot: u32,
    gpa: u64,
    size: u64,
    userspace_addr: u64,
) -> Result<(), SysError> {
    if !consts::SUPPORTED {
        return Err(SysError::Unsupported);
    }
    let region = KvmUserspaceMemoryRegion {
        slot,
        flags: 0,
        guest_phys_addr: gpa,
        memory_size: size,
        userspace_addr,
    };
    // SAFETY: `vm` は借用中の生存 fd。`region` は `repr(C)` で 32 バイト（const assert 済み・ioctl 番号の
    // サイズ符号と一致）のローカルの借用で、カーネルはこの 32 バイトを読むだけで書かず、呼び出しは同期で完了して
    // 戻り後にポインタを保持しない。`userspace_addr` の指す領域の寿命は `RegisteredPage` が維持する。
    let r = unsafe {
        ioctl(
            vm.as_raw_fd(),
            consts::KVM_SET_USER_MEMORY_REGION,
            &region as *const KvmUserspaceMemoryRegion,
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
        let removed = set_user_memory_region(self.vm, self.slot, 0, 0, 0).is_ok();
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
/// 引き継がない（ゲストメモリの内容を子プロセスへ漏らさない）。KVM へ登録した後はゲスト（vCPU）がいつでも
/// 書き換えるため、`&[u8]` / `&mut [u8]` は作らず、範囲検査つきのバイト単位の volatile 読み書きだけで触る。
#[derive(Debug)]
pub(crate) struct GuestRamMap {
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: ポインタはマッピングの生存中（drop まで）有効で、スレッドに固有ではない。Rust 側は参照を一切作らず
// すべて volatile で触り、書き込みは `&mut self` で排他的。ゲスト / カーネルによる書き込みは Rust のメモリモデルの
// 外にあり、Rust 側の参照のエイリアシングを生まない（`KvmRunMap` とは異なり、KVM_RUN の外でもゲストが書きうる）。
unsafe impl Send for GuestRamMap {}
// SAFETY: 上と同じ。共有参照から行うのは volatile の読み取りだけで、Rust 側の書き込みは `&mut self` に限る。
unsafe impl Sync for GuestRamMap {}

impl GuestRamMap {
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
        let Some(ptr) = NonNull::new(p.cast::<u8>()) else {
            // SAFETY: 直前の mmap が返した長さ `len` の領域そのもので、他に所有者がいない。
            let _ = unsafe { munmap(p, len) };
            return Err(SysError::NullMapping);
        };
        // SAFETY: `ptr` / `len` は直前の mmap が返した領域そのもの。`MADV_DONTFORK` は領域を変更せず、fork 先に
        // マッピングを作らない指示だけを行う。
        let r = unsafe { madvise(ptr.as_ptr().cast::<c_void>(), len, consts::MADV_DONTFORK) };
        if r < 0 {
            let e = last_error();
            // SAFETY: 上の mmap が返した領域そのもので、まだ誰にも渡しておらず他に所有者がいない。
            let _ = unsafe { munmap(ptr.as_ptr().cast::<c_void>(), len) };
            return Err(e);
        }
        Ok(GuestRamMap { ptr, len })
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
}

impl Drop for GuestRamMap {
    fn drop(&mut self) {
        // SAFETY: `ptr` / `len` は `map` が成功した mmap の戻り値と長さそのもので、drop は 1 度だけ呼ばれる。
        // KVM への登録中は `RegisteredGuestRam` が所有し、slot の削除に成功した後にだけここへ来る（失敗時は
        // `forget` で漏らす）。失敗しても何もできず、drop で panic しないため戻り値は無視する。
        let _ = unsafe { munmap(self.ptr.as_ptr().cast::<c_void>(), self.len) };
    }
}

/// `ram` を `slot` / `gpa` の memslot として VM に登録する（`KVM_SET_USER_MEMORY_REGION`。flags は 0）。
///
/// 呼び出し側（`crate::microvm`）は、登録が成功している間 `ram` を drop せず、slot を削除してから解放する。
pub(crate) fn register_guest_ram(
    vm: BorrowedFd<'_>,
    slot: u32,
    gpa: u64,
    ram: &GuestRamMap,
) -> Result<(), SysError> {
    set_user_memory_region(
        vm,
        slot,
        gpa,
        ram.len as u64,
        ram.ptr.as_ptr() as usize as u64,
    )
}

/// `slot` の memslot を削除する（`memory_size = 0` の再登録）。
pub(crate) fn unregister_guest_ram(vm: BorrowedFd<'_>, slot: u32) -> Result<(), SysError> {
    set_user_memory_region(vm, slot, 0, 0, 0)
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
/// `E` はどのビットパターンも有効な整数だけの `repr(C)` 型（`KvmCpuidEntry2`・`KvmMsrEntry`）に限る。
/// 呼び出し元は下の `kvm_get_supported_cpuid` などの安全なラッパーだけ。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[cfg_attr(not(test), allow(dead_code))]
struct FlexBuf<E: Copy> {
    ptr: NonNull<u8>,
    layout: Layout,
    cap: usize,
    _entry: std::marker::PhantomData<E>,
}

#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[cfg_attr(not(test), allow(dead_code))]
impl<E: Copy> FlexBuf<E> {
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
        // SAFETY: entries は先頭から 8 バイト後で、確保のアラインは `max(4, align_of::<E>())`（<= 8）のため
        // `E` のアラインに合う。`count <= cap` で範囲内、ゼロ埋め以後は整数だけで有効なビットパターン、
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
        // SAFETY: 範囲は `src.len() <= cap` を検査済みで、アラインは `entries` と同じ。`&mut self` で排他的、
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
impl<E: Copy> Drop for FlexBuf<E> {
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

/// `KVM_GET_LAPIC`（vCPU fd）で LAPIC レジスタ面を読む（x86_64 のみ）。in-kernel irqchip
/// （`KVM_CREATE_IRQCHIP`）が無いと EINVAL になる。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
#[cfg_attr(not(test), allow(dead_code))]
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
#[cfg_attr(not(test), allow(dead_code))]
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

    /// REPAIR-5: handler 導入後は自スレッドへ中断シグナルを送ってもプロセスが終了しない（冪等な再導入も可）。
    #[test]
    fn kick_self_after_handler_install_survives() {
        install_kick_handler().unwrap();
        install_kick_handler().unwrap();
        with_current_thread(|t| t.kick()).unwrap();
    }

    /// REPAIR-5・MVM-1: scoped thread から `KickTarget` で所有スレッドへ送れ、戻り値がそのまま返る。
    #[cfg(all(
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn kick_from_scoped_thread_reaches_owner() {
        install_kick_handler().unwrap();
        let v = with_current_thread(|t| {
            std::thread::scope(|s| {
                s.spawn(move || t.kick()).join().unwrap().unwrap();
            });
            42
        });
        assert_eq!(v, 42);
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
            KvmRunMap::map(f.as_fd(), 4096).unwrap_err(),
            SysError::Os(19)
        );
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
        assert_eq!(consts::KVM_CAP_IRQFD, 32);
        assert_eq!(consts::KVM_CAP_IOEVENTFD, 36);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn create_irqchip_constant_matches_kernel_abi() {
        assert_eq!(consts::KVM_CREATE_IRQCHIP, 0xAE60);
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
        #[cfg(target_arch = "aarch64")]
        assert_eq!(kvm_create_irqchip(f.as_fd()), Err(SysError::Unsupported));
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

    /// MVM-1・TASK-75.1: KVM でない fd への登録は ENOTTY で、mapping は呼び出し側に残る。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn register_guest_ram_on_non_kvm_fd_is_enotty() {
        use std::os::fd::AsFd as _;
        let f = dev_null();
        let m = GuestRamMap::map(4096).unwrap();
        assert_eq!(
            register_guest_ram(f.as_fd(), 0, 0, &m),
            Err(SysError::Os(25))
        );
        assert_eq!(unregister_guest_ram(f.as_fd(), 0), Err(SysError::Os(25)));
    }

    /// MVM-1: aarch64 の vCPU 初期化 ioctl 番号。
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn arm_vcpu_constants_match_kernel_abi() {
        assert_eq!(consts::KVM_ARM_VCPU_INIT, 0x4020_AEAE);
        assert_eq!(consts::KVM_ARM_PREFERRED_TARGET, 0x8020_AEAF);
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
