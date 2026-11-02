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
//! `KVM_RUN` 以外の ioctl はブロックしない同期呼び出しで、`KVM_RUN` はゲストが exit しない限り戻らない
//! （期限は `crate::device` が `KvmRunMap::set_immediate_exit` と `KickTarget::kick`（`SIGUSR2`。`with_current_thread` の中だけで使える）で中断する。REPAIR-5）。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と維持すべき不変条件を明記する
//! - 定数は `cfg(target_arch = ...)` ごとに個別に定義し（値が同じでも流用しない）、対応外では
//!   [`SysError::Unsupported`] を返す（fail-closed）。対応は glibc（`target_env = "gnu"`）の LP64 の x86_64・aarch64 だけ。musl は `ioctl` の `request` の型が異なるため対象外
//! - 戻り値が `-1` のときは直後に `std::io::Error::last_os_error()` で errno を確保する
//!
//! # `libc` との機械照合について
//! 本 crate は dev-dependency に `libc` を持たず照合は未導入（追加は crate ごとの承認事項。
//! `docs/design/ffi-libc-check.md`「適用状況」）。なお `KVM_*` の ioctl 番号は `linux/kvm.h` のカーネル ABI で
//! `libc` に対応物が無く、導入後も `ioctl` 関数の型の照合だけが対象になる（`mmap` / `munmap` も導入後は照合の対象）。
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
    pub const KVM_GET_VCPU_MMAP_SIZE: u64 = 0;
    pub const KVM_RUN: u64 = 0;
    pub const KVM_SET_USER_MEMORY_REGION: u64 = 0;
    pub const PROT_READ: i32 = 0;
    pub const PROT_WRITE: i32 = 0;
    pub const MAP_SHARED: i32 = 0;
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

#[cfg(all(
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const _: () = {
    assert!(consts::KVM_SET_USER_MEMORY_REGION == 0x4020_AE46);
    assert!(consts::KVM_GET_VCPU_MMAP_SIZE == 0xAE04);
    assert!(consts::KVM_RUN == 0xAE80);
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

// SAFETY: 宣言の根拠をここに集約する（対応は glibc の LP64 の x86_64・aarch64 だけで、`consts::SUPPORTED` が
// それ以外では各ラッパーの冒頭で弾くため、型の合わない宣言は呼ばれない。宣言しただけでは未定義動作にならない）。
// - `ioctl`: `int ioctl(int fd, unsigned long request, ...)`（glibc。musl は `request` が `int`）。可変長引数として
//   宣言する（非可変長で宣言して呼ぶと、可変長引数の渡し方が異なる ABI で未定義動作になる）。LP64 で
//   `unsigned long` は u64。可変長部は呼び出し側が u64 かポインタで渡す。
// - `mmap` / `munmap`: LP64 で `size_t` は usize、`off_t` は i64。可変長ではない。
// - `sigaction`: `SigAction` は上の const assert（152 バイト・mask がオフセット 8・flags が 136・restorer が 144）で
//   固定した x86_64・aarch64 の `struct sigaction` のレイアウト。第 2・3 引数は NULL 可。
// - `pthread_sigmask`: `SigSet` は 128 バイトの `sigset_t`（上の const assert）。第 2・3 引数は NULL 可。
// - `pthread_self` / `pthread_kill`: `pthread_t` は glibc の LP64 で `unsigned long` = u64。`pthread_kill` は
//   errno を戻り値で返す（errno 変数は触らない）。
unsafe extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn mmap(addr: *mut c_void, len: usize, prot: i32, flags: i32, fd: i32, off: i64)
    -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> i32;
    fn sigaction(signum: i32, act: *const SigAction, old: *mut SigAction) -> i32;
    fn pthread_sigmask(how: i32, set: *const SigSet, old: *mut SigSet) -> i32;
    fn pthread_self() -> u64;
    fn pthread_kill(thread: u64, sig: i32) -> i32;
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

    /// MVM-1: aarch64 の vCPU 初期化 ioctl 番号。
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn arm_vcpu_constants_match_kernel_abi() {
        assert_eq!(consts::KVM_ARM_VCPU_INIT, 0x4020_AEAE);
        assert_eq!(consts::KVM_ARM_PREFERRED_TARGET, 0x8020_AEAF);
    }
}
