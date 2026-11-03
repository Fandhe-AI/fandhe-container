//! Hypervisor.framework の VM・ゲストメモリの薄いラッパー（`crates/microvm` の `sys` モジュールの macOS 版。
//! TASK-192.1・#3783・MVM-5・MVM-4。`unsafe` 事前承認の範囲。coding-rust.md「unsafe・FFI・syscall」節・
//! オーナー決定 2026-09-27〔[#4](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856057084)・
//! [範囲限定](https://github.com/Fandhe-AI/fandhe-container/issues/4#issuecomment-5856167174)〕）。
//!
//! # 呼び出し文脈
//! `crate::hvf` が `HvVm`・`HostMapping`・`GuestMapping`・`HvVcpu`・`VcpuCanceller` を再公開し、macOS バックエンド（TASK-192 配下の
//! vCPU・GIC・ゲスト RAM の各子 issue）がここへ追記する。`hv_*` は同期呼び出しでゲストを走らせない。
//! 引数の検査と戻り値の写像は OS 非依存の純関数 `crate::hvf_abi` が受け持ち、ここは FFI と RAII だけを持つ。
//!
//! # 契約（事前承認の条件を満たす設計）
//! - `unsafe fn` はこのモジュールの外へ公開しない
//! - すべての `unsafe` ブロック・`unsafe extern "C"` 宣言に `// SAFETY:` で理由と維持すべき不変条件を明記する
//! - ホストメモリは `mmap` で確保する（Apple の制約。`malloc` は不可）。`HvVm::map` は
//!   `HostMapping` を値で受け取り `GuestMapping` が所有する。ゲストへの対応付けの解除（`hv_vm_unmap`）が成功
//!   するまで munmap しない。解除に失敗したら backing は解放せず意図的にリークする（fail-closed）。
//!   `mem::forget` で `GuestMapping` を捨てても backing はリークするだけで、解放されない（安全）。
//!   `GuestMapping` は `&HvVm` を借用するため、対応付けが生きている間は `hv_vm_destroy` も起きない
//! - 1 プロセス 1 VM。2 個目の `HvVm::create` は `hv_vm_create` を呼ばず `FailedPrecondition`
//! - `hv_vm_destroy` が失敗したら VM はプロセス内に残るため、排他のフラグは戻さない（fail-closed）
//!
//! # vCPU の契約（TASK-192.2・#3786）
//! - `HvVcpu` は作ったスレッドに束縛される（`hv_vcpu_run`・レジスタ操作・destroy は owning thread から呼ぶ）。
//!   生ポインタ入りの `PhantomData` で `!Send`・`!Sync` にして型で強制する。
//! - 他スレッドからの停止は `VcpuCanceller`（id と排他ロックだけを持つ `Send + Sync`）が `hv_vcpus_exit` で行う。
//!   destroy は同じロックを持って id を `None` にしてから呼ぶため、破棄済み（番号が再利用されうる）の id へ
//!   `hv_vcpus_exit` を送らない。他スレッドからの `hv_vcpus_exit` は `HV_EXIT_REASON_CANCELED` の説明からの
//!   読みで、実機前提の試験で観測する。
//! - `run_once` は期限つき（監視スレッドが `hv_vcpus_exit` で中断し `DeadlineExceeded`。REPAIR-5）で、結果と所要時間を
//!   `HvRunStats`・`HvRunObserver` へ残す（REPAIR-4）。期限なしの `hv_vcpu_run` は公開しない。
//! - exit 領域は `HvVcpu` の寿命内だけ有効で、`run` の戻りの時点でコピーして値を返す（参照を外へ出さない）。
//! - `HvVcpu` は `&HvVm` を借用し、vCPU が残ったまま `hv_vm_destroy` が走らない。vCPU スレッドで使うときは
//!   `HvVm` を `Arc` で共有するか `std::thread::scope` を使う（#3791 の担当）。
//! - `hv_vcpu_set_pending_interrupt` は GIC（#3789）を使う本ツリーの既定経路では使わない（GIC 無しとの比較用）。
//!
//! # `libc` との機械照合について
//! `hv_*` は Hypervisor.framework の宣言で `libc` の範囲外。`mmap`・`munmap`・`sysconf` と下の定数は
//! `libc` に対応物があり、本 crate は dev-dependency に `libc` を持たず照合は未導入（#3664 の導入後に
//! 照合の対象）。定数は macOS の値で、Linux の値を流用しない。`hv_vm_config_t`・`hv_vcpu_config_t` は
//! 不透明なポインタで NULL を渡す。`hv_*` と `HvVcpuExitRaw`（Hypervisor.framework の構造体）は `libc` に
//! 対応物が無く、レイアウトは `hvf_abi` の const assert で固定する。
//!
//! # 出典
//! 関数名・引数の型・`hv_memory_flags_t` の値は Apple の Hypervisor.framework の公開ドキュメント由来。
//! SDK ヘッダとの最終照合は人間担当の #3803 で行う。vCPU 側のうち `hv_vcpu_set_reg`・`hv_vcpu_get_sys_reg` /
//! `set_sys_reg`・`hv_vcpu_get_vtimer_mask`・`hv_vcpu_set_vtimer_offset` は対の形からの推定で、#3803 で照合する。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_abi::{
    HvInterruptType, HvOp, HvReg, HvRunObserver, HvRunStats, HvSysReg, HvVcpuExit, HvVcpuExitRaw,
    MemoryFlags, check_map_range, check_run_deadline, classify_hv_return, decode_exit, finish_run,
};
use std::ffi::{c_int, c_long, c_void};
use std::marker::PhantomData;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

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

#[link(name = "Hypervisor", kind = "framework")]
// SAFETY: 宣言は Hypervisor.framework（macOS 11 以降・Apple Silicon）の C ABI に一致させている
// （`hv_vcpu_t` = u64、`hv_reg_t` = u32、`hv_sys_reg_t` = u16、`hv_interrupt_type_t` = u32、
// bool = C の `_Bool`、`hv_vcpu_config_t` は不透明ポインタで NULL を渡す）。
// `hv_vcpu_set_reg`・`hv_vcpu_get_sys_reg` / `set_sys_reg`・`hv_vcpu_get_vtimer_mask`・
// `hv_vcpu_set_vtimer_offset` は対の形からの推定で、#3803 で SDK ヘッダと照合する。
// 呼び出しはすべて下の安全なラッパー（`HvVcpu`・`VcpuCanceller`）経由で、出力引数はローカル変数だけを渡す。
unsafe extern "C" {
    fn hv_vcpu_create(
        vcpu: *mut u64,
        exit: *mut *const HvVcpuExitRaw,
        config: *mut c_void,
    ) -> c_int;
    fn hv_vcpu_destroy(vcpu: u64) -> c_int;
    fn hv_vcpu_run(vcpu: u64) -> c_int;
    fn hv_vcpus_exit(vcpus: *mut u64, vcpu_count: u32) -> c_int;
    fn hv_vcpu_get_reg(vcpu: u64, reg: u32, value: *mut u64) -> c_int;
    fn hv_vcpu_set_reg(vcpu: u64, reg: u32, value: u64) -> c_int;
    fn hv_vcpu_get_sys_reg(vcpu: u64, reg: u16, value: *mut u64) -> c_int;
    fn hv_vcpu_set_sys_reg(vcpu: u64, reg: u16, value: u64) -> c_int;
    fn hv_vcpu_get_vtimer_mask(vcpu: u64, masked: *mut bool) -> c_int;
    fn hv_vcpu_set_vtimer_mask(vcpu: u64, masked: bool) -> c_int;
    fn hv_vcpu_get_vtimer_offset(vcpu: u64, offset: *mut u64) -> c_int;
    fn hv_vcpu_set_vtimer_offset(vcpu: u64, offset: u64) -> c_int;
    fn hv_vcpu_set_pending_interrupt(vcpu: u64, kind: u32, pending: bool) -> c_int;
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
    /// `host` は値で受け取り、戻り値の `GuestMapping` が所有する（解除成功まで munmap しない）。
    /// 失敗時は対応付けが作られていないため `host` を drop して安全。
    pub fn map<'a>(
        &'a self,
        host: HostMapping,
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
        // ipa・size はページ境界・倍数を検査済み。`GuestMapping` が `host` を所有し、
        // unmap の成功まで munmap しない（失敗時はリーク）。
        let rc = unsafe { hv_vm_map(addr as *mut c_void, ipa, size, flags.bits()) };
        classify_hv_return(HvOp::VmMap, rc)?;
        Ok(GuestMapping {
            _vm: self,
            ipa,
            size,
            page_size: host.page_size,
            active: true,
            host_offset: offset,
            host: Some(host),
        })
    }
}

impl HvVm {
    /// 呼び出しスレッドに束縛された vCPU を作る（config は NULL）。
    ///
    /// 同じスレッドで 2 個目を作ったときの挙動は未確認（#3803 で観測）。
    pub fn create_vcpu(&self) -> Result<HvVcpu<'_>, MicrovmError> {
        let mut id: u64 = 0;
        let mut exit: *const HvVcpuExitRaw = ptr::null();
        // SAFETY: id・exit はこのスタック上の有効なローカル変数への書き込み先。config は NULL（既定）。
        // `&self` により VM は生存している。
        let rc = unsafe { hv_vcpu_create(&mut id, &mut exit, ptr::null_mut()) };
        classify_hv_return(HvOp::VcpuCreate, rc)?;
        if exit.is_null() {
            // SAFETY: 直前の create で得た id を 1 回だけ破棄する（exit 領域が無い vCPU は使えない）。
            let _ = unsafe { hv_vcpu_destroy(id) };
            return Err(internal("hv_vcpu_create returned a null exit area"));
        }
        Ok(HvVcpu {
            _vm: self,
            id,
            exit,
            cancel: Arc::new(Mutex::new(Some(id))),
            stats: HvRunStats::default(),
            observer: None,
            _thread: PhantomData,
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

    /// `offset` から `bytes` を書く（`map` の前にゲストの初期内容を置くための最小 API。TASK-192.2）。
    ///
    /// 範囲外（桁あふれを含む）は `InvalidArgument`。対応付け後のゲスト RAM のアクセスは #3787 の担当。
    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<(), MicrovmError> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or_else(|| invalid_arg("write range overflows"))?;
        if end > self.len {
            return Err(invalid_arg("write range exceeds the host mapping"));
        }
        // SAFETY: [offset, end) は生存中の mmap 領域（長さ self.len）の内側で検査済み。bytes は別の Rust の
        // 借用で mmap 領域と重ならず、&mut self により同時アクセスもない。
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (self.ptr as *mut u8).add(offset),
                bytes.len(),
            );
        }
        Ok(())
    }

    /// `[offset, offset + len)` が領域に収まるか検査する（桁あふれは範囲外）。
    fn check_span(&self, offset: usize, len: usize) -> Result<(), MicrovmError> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| invalid_arg("guest memory access out of range"))?;
        if end > self.len {
            return Err(invalid_arg("guest memory access out of range"));
        }
        Ok(())
    }

    /// `offset` から `buf.len()` バイトを 1 バイトずつ volatile で読む（TASK-192.4・#3787・MVM-5・MVM-1）。
    ///
    /// 登録後はゲストが並行して書き換えうるため、参照（`&[u8]`）を作らない。範囲外は `InvalidArgument`。
    pub fn read_into(&self, offset: usize, buf: &mut [u8]) -> Result<(), MicrovmError> {
        self.check_span(offset, buf.len())?;
        for (i, b) in buf.iter_mut().enumerate() {
            // SAFETY: `check_span` で offset + buf.len() <= self.len を検査済みで、i < buf.len()。
            // 領域は self の生存中有効。ゲストが並行して書き換えうるため参照を作らず volatile で 1 バイトだけ読む。
            *b = unsafe { ((self.ptr as *const u8).add(offset + i)).read_volatile() };
        }
        Ok(())
    }

    /// `offset` へ `data` を 1 バイトずつ volatile で書く（TASK-192.4・#3787・MVM-5・MVM-1）。範囲外は `InvalidArgument`。
    pub fn write_from(&mut self, offset: usize, data: &[u8]) -> Result<(), MicrovmError> {
        self.check_span(offset, data.len())?;
        for (i, b) in data.iter().enumerate() {
            // SAFETY: `check_span` で offset + data.len() <= self.len を検査済みで、i < data.len()。
            // 領域は self の生存中有効で、&mut self により Rust 側の同時アクセスはない。参照を作らず volatile で書く。
            unsafe { ((self.ptr as *mut u8).add(offset + i)).write_volatile(*b) };
        }
        Ok(())
    }
}

impl Drop for HostMapping {
    fn drop(&mut self) {
        // SAFETY: ptr・len は `new` で得た mmap 領域そのもの。`GuestMapping` が借用している間は到達しない。
        // 二重 munmap は起きない（drop は 1 回）。失敗は後始末のため無視する。
        let _ = unsafe { munmap(self.ptr, self.len) };
    }
}

/// `hv_vm_map` の対応付け（drop で `hv_vm_unmap`）。`HvVm` を借用し、`HostMapping` を所有する。
///
/// 解除（`hv_vm_unmap`）が成功するまで backing を munmap しない。失敗時は backing をリークする（fail-closed）。
#[derive(Debug)]
pub struct GuestMapping<'a> {
    _vm: &'a HvVm,
    ipa: u64,
    size: usize,
    page_size: usize,
    active: bool,
    /// backing 内で対応付けを始めた位置（`HvVm::map` の `offset`）。
    host_offset: usize,
    /// 登録済みの backing。解除成功時のみ drop し、失敗時は `leak_host` でリークする。
    host: Option<HostMapping>,
}

impl GuestMapping<'_> {
    /// 明示的に unmap し、結果を観測する（二重 unmap はしない）。
    ///
    /// 失敗時はゲストへの対応付けが残りうるため backing を解放せずリークする（fail-closed）。
    pub fn unmap(mut self) -> Result<(), MicrovmError> {
        let r = self.release();
        self.active = false;
        r
    }

    /// `hv_vm_unmap` を呼び、成功なら backing を drop、失敗ならリークする。
    fn release(&mut self) -> Result<(), MicrovmError> {
        if !self.active {
            return Ok(());
        }
        // SAFETY: ipa・size は `map` で検査・対応付け済みの範囲。成功しない限り backing は解放しない。
        let rc = unsafe { hv_vm_unmap(self.ipa, self.size) };
        let r = classify_hv_return(HvOp::VmUnmap, rc);
        match (&r, self.host.take()) {
            (Ok(()), host) => drop(host),
            (Err(_), host) => std::mem::forget(host),
        }
        r
    }

    /// 対応付けたゲスト物理アドレスの先頭。
    pub fn ipa(&self) -> u64 {
        self.ipa
    }

    /// 対応付けたバイト数。
    pub fn size(&self) -> usize {
        self.size
    }

    /// `[offset, offset + len)` が対応付けの範囲に収まるか検査し、backing 内の位置を返す。
    fn host_span(&self, offset: usize, len: usize) -> Result<usize, MicrovmError> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| invalid_arg("guest memory access out of range"))?;
        if end > self.size {
            return Err(invalid_arg("guest memory access out of range"));
        }
        self.host_offset
            .checked_add(offset)
            .ok_or_else(|| invalid_arg("guest memory access out of range"))
    }

    /// 対応付けの先頭から `offset` の位置を `buf.len()` バイト読む（volatile のコピー。TASK-192.4・#3787）。
    pub fn read_into(&self, offset: usize, buf: &mut [u8]) -> Result<(), MicrovmError> {
        let pos = self.host_span(offset, buf.len())?;
        self.host
            .as_ref()
            .ok_or_else(|| invalid_arg("guest memory access out of range"))?
            .read_into(pos, buf)
    }

    /// 対応付けの先頭から `offset` の位置へ `data` を書く（volatile のコピー。TASK-192.4・#3787）。
    pub fn write_from(&mut self, offset: usize, data: &[u8]) -> Result<(), MicrovmError> {
        let pos = self.host_span(offset, data.len())?;
        self.host
            .as_mut()
            .ok_or_else(|| invalid_arg("guest memory access out of range"))?
            .write_from(pos, data)
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
        // 失敗時は backing をリークし、munmap しない（対応付けが残りうるため）。エラーは後始末のため捨てる。
        let _ = self.release();
        self.active = false;
    }
}

/// 他スレッドから vCPU の実行を止める手段。id と排他ロックだけを持つため `Send + Sync`。
///
/// `HvVcpu` の破棄と同じロックを共有し、破棄済みの id（再利用されうる）へ `hv_vcpus_exit` を送らない。
#[derive(Debug, Clone)]
pub struct VcpuCanceller {
    id: Arc<Mutex<Option<u64>>>,
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<VcpuCanceller>();
};

impl VcpuCanceller {
    /// `hv_vcpus_exit` で実行中の `hv_vcpu_run` を `Canceled` で戻させる。vCPU 破棄後は `FailedPrecondition`。
    ///
    /// `run` の前に呼んだときに次の `run` が即戻るかは未確認（#3803）。
    pub fn cancel(&self) -> Result<(), MicrovmError> {
        let guard = self.id.lock().unwrap_or_else(|e| e.into_inner());
        let Some(id) = *guard else {
            return Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "vcpu already destroyed",
            ));
        };
        let mut ids = [id];
        // SAFETY: ids はローカル配列で件数 1。ロックを持っている間は vCPU が破棄されないため、id は生存中。
        let rc = unsafe { hv_vcpus_exit(ids.as_mut_ptr(), 1) };
        classify_hv_return(HvOp::VcpusExit, rc)
    }
}

/// 作成スレッドに束縛された vCPU（drop で `hv_vcpu_destroy`）。`!Send`・`!Sync`。
///
/// `HvVm` を借用するため、vCPU が残ったまま VM は破棄されない。
///
/// ```no_run
/// use fandhe_container_microvm::hvf::{HvVcpu, VcpuCanceller};
/// fn assert_sized<T: Sized>() {}
/// fn assert_send<T: Send>() {}
/// assert_sized::<HvVcpu<'static>>();
/// assert_send::<VcpuCanceller>();
/// ```
///
/// `Send` でないこと（スレッド間の移動を型で禁じる）:
///
/// ```compile_fail
/// use fandhe_container_microvm::hvf::HvVcpu;
/// fn assert_send<T: Send>() {}
/// assert_send::<HvVcpu<'static>>();
/// ```
///
/// `Sync` でないこと:
///
/// ```compile_fail
/// use fandhe_container_microvm::hvf::HvVcpu;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<HvVcpu<'static>>();
/// ```
#[derive(Debug)]
pub struct HvVcpu<'a> {
    _vm: &'a HvVm,
    id: u64,
    /// フレームワークが返す exit 領域。vCPU の寿命内だけ有効。
    exit: *const HvVcpuExitRaw,
    cancel: Arc<Mutex<Option<u64>>>,
    stats: HvRunStats,
    observer: Option<Arc<dyn HvRunObserver>>,
    _thread: PhantomData<*const ()>,
}

/// 期限監視スレッドが超過後に `hv_vcpus_exit` を繰り返す間隔（`cancel` が `run` より先に届いたときの取りこぼし対策）。
const KICK_INTERVAL: Duration = Duration::from_millis(10);

/// 監視スレッドへ「実行が戻った」ことを知らせる。drop でも立てるため、panic でも監視が残らない。
struct DoneGuard<'a>(&'a (Mutex<bool>, Condvar));

impl Drop for DoneGuard<'_> {
    fn drop(&mut self) {
        *self.0.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.0.1.notify_all();
    }
}

impl HvVcpu<'_> {
    /// 他スレッドから停止するための `VcpuCanceller`。
    pub fn canceller(&self) -> VcpuCanceller {
        VcpuCanceller {
            id: Arc::clone(&self.cancel),
        }
    }

    /// ゲストを走らせ、戻った理由を返す。`timeout` を超えると監視スレッドが `hv_vcpus_exit` を送り
    /// `DeadlineExceeded` で戻る（REPAIR-5）。`timeout` は 0 不可・上限 `HV_RUN_DEADLINE_MAX`（`InvalidArgument`）。
    ///
    /// 外部の `VcpuCanceller::cancel` による停止は `Ok(Canceled)`。未知の理由は `Unknown` で、呼び出し側は
    /// VM を止める（fail-closed）。結果と所要時間は `stats` と観測器（`set_observer`）へ、エラー経路も含めて残す
    /// （REPAIR-4）。期限の入力検査の失敗は発行前のため記録しない。
    pub fn run_once(&mut self, timeout: Duration) -> Result<HvVcpuExit, MicrovmError> {
        check_run_deadline(timeout)?;
        let canceller = self.canceller();
        let done = (Mutex::new(false), Condvar::new());
        let fired = AtomicBool::new(false);
        let start = Instant::now();
        let result = std::thread::scope(|scope| {
            let watchdog = std::thread::Builder::new()
                .name("hvf-run-deadline".to_string())
                .spawn_scoped(scope, || {
                    let (lock, cv) = &done;
                    let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                    let (guard, res) = cv
                        .wait_timeout_while(guard, timeout, |d| !*d)
                        .unwrap_or_else(|e| e.into_inner());
                    if !res.timed_out() || *guard {
                        return;
                    }
                    drop(guard);
                    fired.store(true, Ordering::SeqCst);
                    loop {
                        // 失敗（vCPU 破棄済み等）は戻りの側が結果を持つため無視する。
                        let _ = canceller.cancel();
                        let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
                        let (guard, _) = cv
                            .wait_timeout_while(guard, KICK_INTERVAL, |d| !*d)
                            .unwrap_or_else(|e| e.into_inner());
                        if *guard {
                            return;
                        }
                    }
                })
                .map_err(|_| internal("failed to spawn the run deadline thread"))?;
            let run_result = {
                let _guard = DoneGuard(&done);
                self.run_unbounded()
            };
            let _ = watchdog.join();
            run_result
        });
        let (result, record) = finish_run(result, fired.load(Ordering::SeqCst), start.elapsed());
        self.stats.add(&record);
        if let Some(o) = &self.observer {
            o.record(&record);
        }
        result
    }

    /// 累積の実行統計（REPAIR-4）。
    pub fn stats(&self) -> HvRunStats {
        self.stats
    }

    /// 実行結果の観測器を設定する（構造化ログ・メトリクスへの接続口。REPAIR-4）。
    pub fn set_observer(&mut self, observer: Arc<dyn HvRunObserver>) {
        self.observer = Some(observer);
    }

    /// 期限なしの `hv_vcpu_run`。公開しない（`run_once` の監視下でだけ呼ぶ。REPAIR-5）。
    fn run_unbounded(&mut self) -> Result<HvVcpuExit, MicrovmError> {
        // SAFETY: id は生存中の vCPU で、呼び出しは作成スレッド（!Send）。
        let rc = unsafe { hv_vcpu_run(self.id) };
        classify_hv_return(HvOp::VcpuRun, rc)?;
        // SAFETY: exit は作成時にフレームワークが返した非 NULL の領域で vCPU の寿命内は有効。
        // run の戻りの直後に値をコピーし、参照は外へ出さない。
        let raw = unsafe { ptr::read(self.exit) };
        Ok(decode_exit(&raw))
    }

    /// 汎用・特殊レジスタを読む。
    pub fn get_reg(&self, reg: HvReg) -> Result<u64, MicrovmError> {
        let mut v: u64 = 0;
        // SAFETY: v はローカル変数への書き込み先。id は生存中、呼び出しは作成スレッド。
        let rc = unsafe { hv_vcpu_get_reg(self.id, reg.bits(), &mut v) };
        classify_hv_return(HvOp::VcpuGetReg, rc)?;
        Ok(v)
    }

    /// 汎用・特殊レジスタを書く。
    pub fn set_reg(&mut self, reg: HvReg, value: u64) -> Result<(), MicrovmError> {
        // SAFETY: ポインタは渡さない。id は生存中、呼び出しは作成スレッド。
        let rc = unsafe { hv_vcpu_set_reg(self.id, reg.bits(), value) };
        classify_hv_return(HvOp::VcpuSetReg, rc)
    }

    /// システムレジスタを読む。
    pub fn get_sys_reg(&self, reg: HvSysReg) -> Result<u64, MicrovmError> {
        let mut v: u64 = 0;
        // SAFETY: v はローカル変数への書き込み先。id は生存中、呼び出しは作成スレッド。
        let rc = unsafe { hv_vcpu_get_sys_reg(self.id, reg.bits(), &mut v) };
        classify_hv_return(HvOp::VcpuGetSysReg, rc)?;
        Ok(v)
    }

    /// システムレジスタを書く。
    pub fn set_sys_reg(&mut self, reg: HvSysReg, value: u64) -> Result<(), MicrovmError> {
        // SAFETY: ポインタは渡さない。id は生存中、呼び出しは作成スレッド。
        let rc = unsafe { hv_vcpu_set_sys_reg(self.id, reg.bits(), value) };
        classify_hv_return(HvOp::VcpuSetSysReg, rc)
    }

    /// vtimer のマスク状態を読む。
    pub fn vtimer_mask(&self) -> Result<bool, MicrovmError> {
        let mut m = false;
        // SAFETY: m はローカル変数への書き込み先。id は生存中、呼び出しは作成スレッド。
        let rc = unsafe { hv_vcpu_get_vtimer_mask(self.id, &mut m) };
        classify_hv_return(HvOp::VcpuGetVtimerMask, rc)?;
        Ok(m)
    }

    /// vtimer のマスクを設定する（`VtimerActivated` の後に解除する用途）。
    pub fn set_vtimer_mask(&mut self, masked: bool) -> Result<(), MicrovmError> {
        // SAFETY: ポインタは渡さない。id は生存中、呼び出しは作成スレッド。
        let rc = unsafe { hv_vcpu_set_vtimer_mask(self.id, masked) };
        classify_hv_return(HvOp::VcpuSetVtimerMask, rc)
    }

    /// vtimer のオフセットを読む。
    pub fn vtimer_offset(&self) -> Result<u64, MicrovmError> {
        let mut o: u64 = 0;
        // SAFETY: o はローカル変数への書き込み先。id は生存中、呼び出しは作成スレッド。
        let rc = unsafe { hv_vcpu_get_vtimer_offset(self.id, &mut o) };
        classify_hv_return(HvOp::VcpuGetVtimerOffset, rc)?;
        Ok(o)
    }

    /// vtimer のオフセットを設定する。
    pub fn set_vtimer_offset(&mut self, offset: u64) -> Result<(), MicrovmError> {
        // SAFETY: ポインタは渡さない。id は生存中、呼び出しは作成スレッド。
        let rc = unsafe { hv_vcpu_set_vtimer_offset(self.id, offset) };
        classify_hv_return(HvOp::VcpuSetVtimerOffset, rc)
    }

    /// 保留中の割り込みを設定する。GIC（#3789）を使う既定経路では使わない（GIC 無しとの比較用）。
    pub fn set_pending_interrupt(
        &mut self,
        kind: HvInterruptType,
        pending: bool,
    ) -> Result<(), MicrovmError> {
        // SAFETY: ポインタは渡さない。id は生存中、呼び出しは作成スレッド。
        let rc = unsafe { hv_vcpu_set_pending_interrupt(self.id, kind.bits(), pending) };
        classify_hv_return(HvOp::VcpuSetPendingInterrupt, rc)
    }
}

impl Drop for HvVcpu<'_> {
    fn drop(&mut self) {
        // canceller と同じロックを持ったまま id を無効化して破棄する（破棄済み id への cancel を防ぐ）。
        let mut guard = self.cancel.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(id) = guard.take() {
            // SAFETY: id は生存中の vCPU で、drop は作成スレッド（!Send）。結果は後始末のため捨てる。
            let _ = unsafe { hv_vcpu_destroy(id) };
        }
    }
}
