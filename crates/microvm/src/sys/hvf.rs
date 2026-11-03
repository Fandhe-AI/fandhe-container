//! Hypervisor.framework の VM・ゲストメモリの薄いラッパー（`crates/microvm` の `sys` モジュールの macOS 版。
//! TASK-192.1・#3783・MVM-5・MVM-4。`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::hvf` が `HvVm`・`HostMapping`・`GuestMapping` を再公開し、macOS バックエンド（TASK-192 配下の
//! vCPU・GIC・ゲスト RAM の各子 issue）がここへ追記する。`hv_*` は同期呼び出しでゲストを走らせない。
//! 引数の検査と戻り値の写像は OS 非依存の純関数 `crate::hvf_abi` が受け持ち、ここは FFI と RAII だけを持つ。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と維持すべき不変条件を明記する
//! - ホストメモリは `mmap` で確保する（Apple の制約。`malloc` は不可）。`GuestMapping` が `HvVm` と
//!   `HostMapping` を借用するため、対応付けが生きている間は munmap も `hv_vm_destroy` も起きない
//! - 1 プロセス 1 VM。2 個目の `HvVm::create` は `hv_vm_create` を呼ばず `FailedPrecondition`
//! - `hv_vm_destroy` が失敗したら VM はプロセス内に残るため、排他のフラグは戻さない（fail-closed）
//!
//! # `libc` との機械照合について
//! `hv_*` は Hypervisor.framework の宣言で `libc` の範囲外。`mmap`・`munmap`・`sysconf` と下の定数は
//! `libc` に対応物があり、本 crate は dev-dependency に `libc` を持たず照合は未導入（#3664 の導入後に
//! 照合の対象）。定数は macOS の値で、Linux の値を流用しない。構造体は宣言しない（`hv_vm_config_t` は
//! 不透明なポインタで NULL を渡す）。
//!
//! # 出典
//! 関数名・引数の型・`hv_memory_flags_t` の値は Apple の Hypervisor.framework の公開ドキュメント由来。
//! SDK ヘッダとの最終照合は人間担当の #3803 で行う。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_abi::{HvOp, MemoryFlags, check_map_range, classify_hv_return};
use std::ffi::{c_int, c_long, c_void};
use std::marker::PhantomData;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

#[link(name = "Hypervisor", kind = "framework")]
// SAFETY: 宣言は Hypervisor.framework（macOS 11 以降・Apple Silicon）の C ABI に一致させている
// （`hv_return_t` = int、`hv_ipa_t` = u64、`hv_memory_flags_t` = u64、`size_t` = usize）。
// 呼び出しはすべて下の安全なラッパー経由で、引数は検査済みのものだけを渡す。
unsafe extern "C" {
    fn hv_vm_create(config: *mut c_void) -> c_int;
    fn hv_vm_destroy() -> c_int;
    fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> c_int;
    fn hv_vm_unmap(ipa: u64, size: usize) -> c_int;
    fn hv_vm_protect(ipa: u64, size: usize, flags: u64) -> c_int;
}

// SAFETY: 宣言は macOS（LP64）の libSystem の C ABI に一致させている
// （`off_t` = i64、`size_t` = usize、`sysconf` は long を返す）。
unsafe extern "C" {
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
    fn sysconf(name: c_int) -> c_long;
}

// macOS の値（libc 0.2.189 の bsd/apple に一致）。Linux の値を流用しない。
const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const MAP_PRIVATE: c_int = 0x0002;
const MAP_ANON: c_int = 0x1000;
const SC_PAGESIZE: c_int = 29;
const ENOMEM: i32 = 12;

/// プロセス内に `HvVm` が存在するか（1 プロセス 1 VM の排他）。
static VM_EXISTS: AtomicBool = AtomicBool::new(false);

fn internal(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, msg)
}

/// ホストのページサイズ（実行時の `sysconf` の値）。2 の冪でなければ fail-closed で `Internal`。
fn host_page_size() -> Result<usize, MicrovmError> {
    // SAFETY: `sysconf` は引数が整数のみで、ポインタを取らず副作用もない。
    let v = unsafe { sysconf(SC_PAGESIZE) };
    let size = usize::try_from(v).map_err(|_| internal("sysconf(_SC_PAGESIZE) failed"))?;
    if !size.is_power_of_two() {
        return Err(internal("host page size is not a power of two"));
    }
    Ok(size)
}

/// Hypervisor.framework の VM（`hv_vm_create` ～ drop での `hv_vm_destroy`）。1 プロセス 1 VM。
#[derive(Debug)]
pub struct HvVm {
    _private: (),
}

impl HvVm {
    /// VM を作る。既にプロセス内に VM があれば `hv_vm_create` を呼ばず `FailedPrecondition`。
    pub fn create() -> Result<HvVm, MicrovmError> {
        if VM_EXISTS
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "a Hypervisor.framework VM already exists in this process",
            ));
        }
        // SAFETY: config に NULL（既定の構成）を渡す。他に引数はなく、ポインタは参照されない。
        // 排他のフラグを取得済みのため、同時に 2 回呼ばれない。
        let rc = unsafe { hv_vm_create(ptr::null_mut()) };
        if let Err(e) = classify_hv_return(HvOp::VmCreate, rc) {
            VM_EXISTS.store(false, Ordering::Release);
            return Err(e);
        }
        Ok(HvVm { _private: () })
    }

    /// `host` の `offset` から `size` バイトを、ゲスト物理アドレス `ipa` に `flags` で対応付ける。
    ///
    /// `hv_vm_map` の前に、範囲（`offset + size <= host.len()`）・ページ境界・桁あふれを検査する。
    /// 戻り値の `GuestMapping` が `self` と `host` を借用するため、対応付けの間は munmap も destroy も起きない。
    pub fn map<'a>(
        &'a self,
        host: &'a HostMapping,
        offset: usize,
        ipa: u64,
        size: usize,
        flags: MemoryFlags,
    ) -> Result<GuestMapping<'a>, MicrovmError> {
        let end = offset
            .checked_add(size)
            .ok_or_else(|| invalid_arg("range overflows the host mapping"))?;
        if end > host.len {
            return Err(invalid_arg("range exceeds the host mapping"));
        }
        let addr = (host.ptr as usize)
            .checked_add(offset)
            .ok_or_else(|| invalid_arg("range overflows the address space"))?;
        check_map_range(addr as u64, ipa, size as u64, host.page_size as u64)?;
        // SAFETY: addr は `host`（生存中の mmap 領域）の内側で、offset + size <= host.len を検査済み。
        // ipa・size はページ境界・倍数を検査済み。`GuestMapping` が `host` を借用するため、
        // unmap されるまで領域は munmap されない。
        let rc = unsafe { hv_vm_map(addr as *mut c_void, ipa, size, flags.bits()) };
        classify_hv_return(HvOp::VmMap, rc)?;
        Ok(GuestMapping {
            _vm: self,
            ipa,
            size,
            page_size: host.page_size,
            active: true,
            _host: PhantomData,
        })
    }
}

fn invalid_arg(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::InvalidArgument, msg)
}

impl Drop for HvVm {
    fn drop(&mut self) {
        // SAFETY: 引数なし。`GuestMapping` が `&HvVm` を借用しているため、対応付けが残った状態では到達しない。
        let rc = unsafe { hv_vm_destroy() };
        // 失敗（例: HV_BUSY）ではプロセス内に VM が残るので、排他のフラグは true のままにする（fail-closed）。
        if rc == crate::hvf_abi::HV_SUCCESS {
            VM_EXISTS.store(false, Ordering::Release);
        }
    }
}

/// ゲストへ見せるホスト側メモリ（匿名 mmap。drop で munmap）。
///
/// 生ポインタを持つため `Send` / `Sync` ではない（必要になった子 issue が判断する）。
#[derive(Debug)]
pub struct HostMapping {
    ptr: *mut c_void,
    len: usize,
    page_size: usize,
}

impl HostMapping {
    /// ホストのページサイズ（`sysconf(_SC_PAGESIZE)`）。
    pub fn page_size() -> Result<usize, MicrovmError> {
        host_page_size()
    }

    /// `len` バイト（ページサイズの倍数・0 不可）の匿名メモリを確保する。
    pub fn new(len: usize) -> Result<HostMapping, MicrovmError> {
        let page_size = host_page_size()?;
        check_map_range(0, 0, len as u64, page_size as u64)?;
        // SAFETY: addr = NULL（カーネルが選ぶ）、fd = -1・offset = 0 の匿名・private 領域。
        // len は検査済み（0 でなくページ倍数）。戻り値は MAP_FAILED を判定してから使う。
        let p = unsafe {
            mmap(
                ptr::null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                MAP_ANON | MAP_PRIVATE,
                -1,
                0,
            )
        };
        if p as usize == usize::MAX || p.is_null() {
            let errno = std::io::Error::last_os_error().raw_os_error();
            return Err(if errno == Some(ENOMEM) {
                MicrovmError::new(
                    MicrovmErrorCode::ResourceExhausted,
                    "mmap failed: out of memory",
                )
            } else {
                internal("mmap failed")
            });
        }
        Ok(HostMapping {
            ptr: p,
            len,
            page_size,
        })
    }

    /// 確保したバイト数。
    pub fn len(&self) -> usize {
        self.len
    }

    /// 長さが 0 か（`new` は 0 を拒否するため常に false）。
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for HostMapping {
    fn drop(&mut self) {
        // SAFETY: ptr・len は `new` で得た mmap 領域そのもの。`GuestMapping` が借用している間は到達しない。
        // 二重 munmap は起きない（drop は 1 回）。失敗は後始末のため無視する。
        let _ = unsafe { munmap(self.ptr, self.len) };
    }
}

/// `hv_vm_map` の対応付け（drop で `hv_vm_unmap`）。`HvVm` と `HostMapping` を借用して寿命を縛る。
#[derive(Debug)]
pub struct GuestMapping<'a> {
    _vm: &'a HvVm,
    ipa: u64,
    size: usize,
    page_size: usize,
    active: bool,
    _host: PhantomData<&'a HostMapping>,
}

impl GuestMapping<'_> {
    /// 明示的に unmap し、結果を観測する（二重 unmap はしない）。
    pub fn unmap(mut self) -> Result<(), MicrovmError> {
        self.active = false;
        // SAFETY: ipa・size は `map` で検査・対応付け済みの範囲。`active` を下ろしたので drop は再度呼ばない。
        let rc = unsafe { hv_vm_unmap(self.ipa, self.size) };
        classify_hv_return(HvOp::VmUnmap, rc)
    }

    /// 対応付けの保護を `flags` に変える。
    pub fn protect(&self, flags: MemoryFlags) -> Result<(), MicrovmError> {
        check_map_range(0, self.ipa, self.size as u64, self.page_size as u64)?;
        // SAFETY: ipa・size は `map` で対応付け済みで、ページ境界・倍数を再検査した。ポインタは渡さない。
        let rc = unsafe { hv_vm_protect(self.ipa, self.size, flags.bits()) };
        classify_hv_return(HvOp::VmProtect, rc)
    }
}

impl Drop for GuestMapping<'_> {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: `unmap` 済みでない対応付けの範囲。失敗は後始末のため無視する。
            let _ = unsafe { hv_vm_unmap(self.ipa, self.size) };
        }
    }
}
