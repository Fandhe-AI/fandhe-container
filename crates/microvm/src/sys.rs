//! KVM の ioctl の薄いラッパー（`crates/microvm` の `sys` モジュール。TASK-74.1.1・MVM-1。
//! `unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::device` の `KvmDevice` が、`/dev/kvm` を開いた fd に対して `KVM_GET_API_VERSION` と
//! `KVM_CREATE_VM` を発行する。open は std（`O_CLOEXEC` 付き）で行うため open の FFI は持たない。
//! VM fd に対する `KVM_CREATE_VCPU`（TASK-74.1.2）と、aarch64 のみ `KVM_ARM_PREFERRED_TARGET` /
//! `KVM_ARM_VCPU_INIT` も発行する。いずれの ioctl もブロックしない同期呼び出しのため、REPAIR-5 の
//! タイムアウトは持たない。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と維持すべき不変条件を明記する
//! - 定数は `cfg(target_arch = ...)` ごとに個別に定義し（値が同じでも流用しない）、対応外では
//!   [`SysError::Unsupported`] を返す（fail-closed）。対応 arch は LP64 の x86_64・aarch64 だけ
//! - 戻り値が `-1` のときは直後に `std::io::Error::last_os_error()` で errno を確保する
//!
//! # `libc` との機械照合について
//! 本 crate は dev-dependency に `libc` を持たず照合は未導入（追加は crate ごとの承認事項。
//! `docs/design/ffi-libc-check.md`「適用状況」）。なお `KVM_*` の ioctl 番号は `linux/kvm.h` のカーネル ABI で
//! `libc` に対応物が無く、導入後も `ioctl` 関数の型の照合だけが対象になる。aarch64 の `kvm_vcpu_init`
//! （`asm/kvm.h` のカーネル ABI 構造体）も `libc` に対応物が無く、サイズ・アラインを const assert で固定する。

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};

/// ioctl 失敗の分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SysError {
    /// 対応外のアーキテクチャ（定数が未定義）。
    Unsupported,
    /// カーネルが返した errno。
    Os(i32),
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

/// `linux/kvm.h` の `KVMIO`。
const KVMIO: u64 = 0xAE;

/// 定数（x86_64）。
#[cfg(all(target_arch = "x86_64", target_pointer_width = "64"))]
pub(crate) mod consts {
    pub const SUPPORTED: bool = true;
    pub const KVM_API_VERSION: i32 = 12;
    pub const KVM_GET_API_VERSION: u64 = super::io(super::KVMIO, 0x00);
    pub const KVM_CREATE_VM: u64 = super::io(super::KVMIO, 0x01);
    pub const KVM_CREATE_VCPU: u64 = super::io(super::KVMIO, 0x41);
}

/// 定数（aarch64）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) mod consts {
    pub const SUPPORTED: bool = true;
    pub const KVM_API_VERSION: i32 = 12;
    pub const KVM_GET_API_VERSION: u64 = super::io(super::KVMIO, 0x00);
    pub const KVM_CREATE_VM: u64 = super::io(super::KVMIO, 0x01);
    pub const KVM_CREATE_VCPU: u64 = super::io(super::KVMIO, 0x41);
    /// `_IOW(KVMIO, 0xae, struct kvm_vcpu_init)`（32 バイト）。
    pub const KVM_ARM_VCPU_INIT: u64 = super::iow(super::KVMIO, 0xAE, 32);
    /// `_IOR(KVMIO, 0xaf, struct kvm_vcpu_init)`（32 バイト）。
    pub const KVM_ARM_PREFERRED_TARGET: u64 = super::ior(super::KVMIO, 0xAF, 32);
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

// SAFETY: `int ioctl(int fd, unsigned long request, ...)`（glibc。musl は `request` が `int` で対象外）。
// 可変長引数として宣言する（非可変長で宣言して呼ぶと、可変長引数の渡し方が異なる ABI で未定義動作になる）。
// LP64 で `unsigned long` は u64。可変長部は `KVM_CREATE_VM` の machine type（`unsigned long`）のみで、
// 呼び出し側は u64 で渡す。
unsafe extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
}

fn last_error() -> SysError {
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

/// `KVM_ARM_PREFERRED_TARGET`（VM fd）で推奨 target を得る（aarch64 のみ）。
#[cfg(all(target_arch = "aarch64", target_pointer_width = "64"))]
pub(crate) fn kvm_arm_preferred_target(vm: BorrowedFd<'_>) -> Result<KvmVcpuInit, SysError> {
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
    }

    /// MVM-1: `KVM_CREATE_VCPU = _IO(KVMIO, 0x41)`。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn create_vcpu_constant_matches_kernel_abi() {
        assert_eq!(consts::KVM_CREATE_VCPU, 0xAE41);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn arm_vcpu_constants_match_kernel_abi() {
        assert_eq!(consts::KVM_ARM_VCPU_INIT, 0x4020_AEAE);
        assert_eq!(consts::KVM_ARM_PREFERRED_TARGET, 0x8020_AEAF);
    }
}
