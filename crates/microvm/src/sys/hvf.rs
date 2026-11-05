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
//!   `GuestMapping` は `&HvVm` を借用するか（`map`）`Arc<HvVm>` を保持する（`map_shared`、#3797）ため、対応付けが生きている間は `hv_vm_destroy` も起きない
//! - `HvVm::map` は範囲・ページ境界に加えて既定の IPA 上限（`HVF_DEFAULT_IPA_LIMIT`）も FFI の前に検査する（#3844）
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
//! - run していない vCPU への `hv_vcpus_exit` は保留され、次の `hv_vcpu_run` がゲストへ入らず `Canceled` で戻る。保留はその
//!   1 回で消える（SDK ヘッダと実機のプローブ。#3803）。`hv_vcpu_run` の戻りから監視スレッドが止まるまでの窓に届いた
//!   監視スレッドの `cancel` も保留になるため、`run_once` は期限が発火した run の後に保留を捨てる（#3845）。
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
//! # GICv3 の契約（TASK-192.3・#3789・MVM-5・MVM-4）
//! - `hv_gic_*` は macOS 15.0 で入った。Rust の既定の deployment target（11.0）で `extern` に直接宣言すると、
//!   macOS 14 では dyld がシンボルを解決できずプロセスが起動しない。そこで **どの `extern` ブロックにも宣言せず**、
//!   `dlsym(RTLD_DEFAULT, ..)` で実行時に探す。deployment target を 15 に上げる案は 14 で起動できなくなるため採らない。
//! - `dlopen` は使わない。探すのは起動時に `#[link]` で読み込み済みの image（Hypervisor.framework と libSystem）だけで、
//!   新しいライブラリを実行時に読み込まない（security.md「動的ライブラリの実行時ロードを行わない」）。`dlclose` もしない
//!   ため、解決した関数ポインタはプロセスの寿命の間有効。
//! - 手順は「`kern.osproductversion` の版判定（15 未満は `Unimplemented`）→ 11 個のシンボル解決」の順。1 つでも見つから
//!   なければ GIC の関数を何も返さない。12 個目の `hv_gic_get_distributor_reg`（#3960。macOS 15.0 で導入。
//!   <https://developer.apple.com/documentation/hypervisor/hv_gic_get_distributor_reg(_:_:)>）だけは任意で、無ければ
//!   `GicApi::distributor_reg` が `Unimplemented` を返し、呼び出し側が縮退する（読むのは `GICD_CTLR` と `GICD_IROUTER<n>`。#3974）。結果（エラーを含む）は `OnceLock` にプロセスで 1 回だけ作る。
//! - 関数ポインタは `GicApi` の private フィールドに閉じ、`sys` の外へ出さない。`hv_gic_*` は `libc` に対応物が無いため
//!   機械照合の対象外。`hv_gic_config_t` は OS オブジェクトで、`os_release`（libSystem・macOS 10.10 以降なので直接リンクしてよい）
//!   で解放する。作成順序（VM の後・vCPU の前）を型で強制するのは #3792 の担当。
//! - 出典: 関数名・シグネチャは Apple の Hypervisor ドキュメント（各 `hv_gic_*` のページ）。SDK ヘッダとの照合は #3803。
//!
//! # ホストの時刻（TASK-192.14・#3796）
//! WFI の待ち時間の計算用に `mach_absolute_time` と `mach_timebase_info`（libSystem）を宣言し、安全なラッパー
//! `host_absolute_time`・`host_timebase` だけを公開する。`hvf::timer` が呼ぶ。SDK ヘッダとの照合は #3803。
//! 2 関数は本ファイル末尾の単体試験（#3885）で直接確かめる（entitlement 不要のため既定の試験集合で走る）。
//!
//! # 出典
//! 関数名・引数の型・`hv_memory_flags_t` の値は Apple の Hypervisor.framework の公開ドキュメント由来。
//! SDK ヘッダとの最終照合は人間担当の #3803 で行う。vCPU 側のうち `hv_vcpu_set_reg`・`hv_vcpu_get_sys_reg` /
//! `set_sys_reg`・`hv_vcpu_get_vtimer_mask`・`hv_vcpu_set_vtimer_offset` は対の形からの推定で、#3803 で照合する。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_abi::{
    GicDistributorReg, GicIntid, HostTimebase, HvGicIntid, HvInterruptType, HvOp, HvReg,
    HvRunObserver, HvRunStats, HvSysReg, HvVcpuExit, HvVcpuExitRaw, MACOS_PRODUCT_VERSION_MAX_LEN,
    MacosVersion, MemoryFlags, check_gic_supported, check_map_range, check_run_deadline,
    check_vm_map, classify_hv_return, decode_exit, finish_run, parse_macos_product_version,
};
use std::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::marker::PhantomData;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
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

// SAFETY: 宣言は macOS（LP64）の libSystem の C ABI に一致させている（`dlsym` は `<dlfcn.h>`、
// `sysctlbyname` は `<sys/sysctl.h>`、`os_release` は `<os/object.h>` の宣言。`size_t` = usize）。
// `dlsym`・`sysctlbyname` は libc に対応物があり #3664 で照合する。`os_release` は libc に無い。
unsafe extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *mut c_void,
        newlen: usize,
    ) -> c_int;
    fn os_release(object: *mut c_void);
}

// macOS の `RTLD_DEFAULT`（`(void *)-2`。libc 0.2.189 の bsd に一致）。Linux の値（0）を流用しない。
const RTLD_DEFAULT: *mut c_void = -2isize as *mut c_void;

// macOS の値（libc 0.2.189 の bsd/apple に一致）。Linux の値を流用しない。
const PROT_READ: c_int = 1;
const PROT_WRITE: c_int = 2;
const MAP_PRIVATE: c_int = 0x0002;
const MAP_ANON: c_int = 0x1000;
const SC_PAGESIZE: c_int = 29;
const ENOMEM: i32 = 12;

// SAFETY: 宣言は macOS（LP64）の libSystem（`<mach/mach_time.h>`）の C ABI に一致させている
// （`mach_absolute_time` は `uint64_t` を返し引数なし、`mach_timebase_info` は `kern_return_t` = int を返し
// `struct mach_timebase_info { uint32_t numer; uint32_t denom; }` へのポインタを取る）。
// 両関数は libc に対応物があり #3664 で照合する（本 crate は dev-dependency に libc を持たない）。
// 呼び出しは下の安全なラッパー（`host_absolute_time`・`host_timebase`）経由だけ。
unsafe extern "C" {
    fn mach_absolute_time() -> u64;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> c_int;
}

/// `struct mach_timebase_info`（`<mach/mach_time.h>`）。`sys` の外へ出さない。
#[repr(C)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

const _: () = {
    assert!(std::mem::size_of::<MachTimebaseInfo>() == 8);
    assert!(std::mem::align_of::<MachTimebaseInfo>() == 4);
};

/// ホストの絶対時間カウンタを読む（`mach_absolute_time`）。引数なし・常に成功する。
/// `hvf::timer` が WFI の待ち時間の計算の直前に呼ぶ（TASK-192.14・#3796）。
pub(crate) fn host_absolute_time() -> u64 {
    // SAFETY: 引数もポインタも取らず、メモリを触らない。常に成功する libSystem の関数。
    unsafe { mach_absolute_time() }
}

static HOST_TIMEBASE: OnceLock<Result<HostTimebase, MicrovmError>> = OnceLock::new();

/// ホストの絶対時間カウンタの ns への換算比を返す（プロセスで 1 回だけ取得して保つ）。
/// 失敗や 0 の値は `Internal`（推測の値で続けない。fail-closed）。
pub(crate) fn host_timebase() -> Result<HostTimebase, MicrovmError> {
    HOST_TIMEBASE
        .get_or_init(|| {
            let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
            // SAFETY: `info` は初期化済みのローカル変数で、呼び出しの間は有効な書き込み先（8 バイト・4 アライン）。
            let rc = unsafe { mach_timebase_info(&mut info) };
            if rc != 0 {
                return Err(internal("mach_timebase_info failed"));
            }
            HostTimebase::new(info.numer, info.denom)
        })
        .clone()
}

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
    /// `hv_vm_map` の前に、範囲（`offset + size <= host.len()`）・ページ境界・桁あふれと、ゲスト範囲
    /// `[ipa, ipa + size)` が既定の IPA 上限（`HVF_DEFAULT_IPA_LIMIT`）の内側であることを検査し、
    /// 違反は `hv_vm_map` を呼ばずに `InvalidArgument` にする（#3844）。
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
        self.map_with(VmRef::Borrowed(self), host, offset, ipa, size, flags)
    }

    /// [`HvVm::map`] の `Arc` 版。戻り値の対応付けが `Arc<HvVm>` を保持するため `'static` で、`VmWithGic` を `Arc` で
    /// 共有する構成体（#3797）が自己参照なしにゲスト RAM を持てる。
    ///
    /// 対応付けが生きている間は `Arc` の参照が残るので `hv_vm_destroy`（`HvVm::drop`）は必ず `hv_vm_unmap` の後になる
    /// （unmap を VM 破棄の後に回さない。破棄後に作り直した別 VM の IPA を誤って unmap する危険を型で断つ）。
    /// 検査と失敗時の扱いは [`HvVm::map`] と同じ。
    pub fn map_shared(
        self: &Arc<Self>,
        host: HostMapping,
        offset: usize,
        ipa: u64,
        size: usize,
        flags: MemoryFlags,
    ) -> Result<GuestMapping<'static>, MicrovmError> {
        self.map_with(
            VmRef::Shared(Arc::clone(self)),
            host,
            offset,
            ipa,
            size,
            flags,
        )
    }

    /// `map`・`map_shared` の共通本体。`keep` は戻り値の対応付けが保持する VM への参照（借用か `Arc`）。
    fn map_with<'a>(
        &self,
        keep: VmRef<'a>,
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
        check_vm_map(addr as u64, ipa, size as u64, host.page_size as u64)?;
        // SAFETY: addr は `host`（生存中の mmap 領域）の内側で、offset + size <= host.len を検査済み。
        // ipa・size はページ境界・倍数と、ipa + size が既定 IPA 上限の内側であること（`check_vm_map`）を検査済み。`GuestMapping` が `host` を所有し、
        // unmap の成功まで munmap しない（失敗時はリーク）。
        let rc = unsafe { hv_vm_map(addr as *mut c_void, ipa, size, flags.bits()) };
        classify_hv_return(HvOp::VmMap, rc)?;
        Ok(GuestMapping {
            _vm: keep,
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
    /// GIC は vCPU より前に作る必要があるため、外部には `crate::hvf::gic::VmWithGic::create_vcpu` だけが公開される（#3792）。
    pub(crate) fn create_vcpu(&self) -> Result<HvVcpu<'_>, MicrovmError> {
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
        // SAFETY: 引数なし。`GuestMapping` が `&HvVm` を借用するか `Arc<HvVm>` を保持するため、対応付けが残った状態では到達しない。
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

    /// 範囲と、実際のホストポインタの 2 バイト整列を検査してポインタを返す（整列 u16 アクセスの共通部。#3862）。
    fn aligned_u16_ptr(&self, offset: usize) -> Result<*mut u16, MicrovmError> {
        self.check_span(offset, 2)?;
        let p = (self.ptr as *mut u8).wrapping_add(offset);
        if !(p as usize).is_multiple_of(core::mem::align_of::<u16>()) {
            return Err(invalid_arg("unaligned guest memory access"));
        }
        Ok(p.cast::<u16>())
    }

    /// `offset` の 2 バイトを整列した単一の volatile 読みで取り LE の u16 として返す（`avail.idx` 用。#3862・MVM-5・MVM-1）。
    ///
    /// 範囲外・未整列は `InvalidArgument`（unsafe の前に検査）。「単一命令」は aarch64 の `ldrh` に下りる前提で、
    /// Rust の言語仕様の保証ではない（Linux の `READ_ONCE` と同じ前提）。
    pub fn read_u16_le_aligned(&self, offset: usize) -> Result<u16, MicrovmError> {
        let p = self.aligned_u16_ptr(offset)?;
        // SAFETY: `aligned_u16_ptr` が範囲（offset + 2 <= len）と u16 の整列を検査済み。領域は self の生存中有効。
        // ゲストが並行して書きうるため参照（`&u16`）を作らず volatile で読む。
        Ok(u16::from_le(unsafe { p.read_volatile() }))
    }

    /// `v` を LE で `offset` へ整列した単一の volatile 書きで置く（`used.idx` 用。契約は読みと同じ。#3862）。
    pub fn write_u16_le_aligned(&mut self, offset: usize, v: u16) -> Result<(), MicrovmError> {
        let p = self.aligned_u16_ptr(offset)?;
        // SAFETY: `aligned_u16_ptr` が範囲と整列を検査済み。領域は self の生存中有効で、&mut self により Rust 側の
        // 同時アクセスはない。ゲストが並行して読みうるため参照を作らず volatile で書く。
        unsafe { p.write_volatile(v.to_le()) };
        Ok(())
    }
}

impl Drop for HostMapping {
    fn drop(&mut self) {
        // SAFETY: ptr・len は `new` で得た mmap 領域そのもの。二重 munmap は起きない（drop は 1 回）。
        // ゲストへ対応付けた `HostMapping` は `GuestMapping` が `Option` で所有し、`release()` が `take()` して
        // `hv_vm_unmap` が成功したときだけここへ来る（失敗時は `mem::forget` でリークし、ここへは来ない）。
        // それ以外にここへ来るのは対応付けていない backing（`map` の前、または検査か `hv_vm_map` の失敗で
        // 対応付けができなかったとき）だけなので、ゲストから見えている領域は munmap しない。失敗は後始末のため無視する。
        let _ = unsafe { munmap(self.ptr, self.len) };
    }
}

/// 対応付けが VM を生かしておくための参照。借用（`HvVm::map`）か `Arc`（`HvVm::map_shared`、#3797）。
/// どちらも対応付けが残る間 `hv_vm_destroy` が走らないことを保証する。
// 中身は読まない（保持して寿命を延ばすだけ）ため dead_code を許す。
#[allow(dead_code)]
#[derive(Debug)]
enum VmRef<'a> {
    Borrowed(&'a HvVm),
    Shared(Arc<HvVm>),
}

/// `hv_vm_map` の対応付け（drop で `hv_vm_unmap`）。`HvVm` を借用するか `Arc<HvVm>` を保持し、`HostMapping` を所有する。
///
/// 解除（`hv_vm_unmap`）が成功するまで backing を munmap しない。失敗時は backing をリークする（fail-closed）。
#[derive(Debug)]
pub struct GuestMapping<'a> {
    _vm: VmRef<'a>,
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

    /// 対応付けの先頭から `offset` の位置の整列した u16 を単一命令の volatile で読む（#3862）。
    ///
    /// `host_offset` がページ境界でも、backing 側がホストポインタで整列を再検査する。
    pub fn read_u16_le_aligned(&self, offset: usize) -> Result<u16, MicrovmError> {
        let pos = self.host_span(offset, 2)?;
        self.host
            .as_ref()
            .ok_or_else(|| invalid_arg("guest memory access out of range"))?
            .read_u16_le_aligned(pos)
    }

    /// 対応付けの先頭から `offset` の位置へ整列した u16 を単一命令の volatile で書く（#3862）。
    pub fn write_u16_le_aligned(&mut self, offset: usize, v: u16) -> Result<(), MicrovmError> {
        let pos = self.host_span(offset, 2)?;
        self.host
            .as_mut()
            .ok_or_else(|| invalid_arg("guest memory access out of range"))?
            .write_u16_le_aligned(pos, v)
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

// `HvVcpu` が `Send` でも `Sync` でもないことをコンパイル時に固定する（#3844）。実装すると 2 つの impl が
// 両方当てはまって型推論が曖昧になり（E0283）、cross-target-check の `cargo check` で落ちる。
// 下の doctest は stable の rustdoc がエラー番号を照合しないため、stable の CI ではこちらが担う。
const _: fn() = || {
    trait AmbiguousIfSend<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
    let _ = <HvVcpu<'static> as AmbiguousIfSend<_>>::some_item;
    trait AmbiguousIfSync<A> {
        fn some_item() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
    let _ = <HvVcpu<'static> as AmbiguousIfSync<_>>::some_item;
};

impl VcpuCanceller {
    /// `hv_vcpus_exit` で実行中の `hv_vcpu_run` を `Canceled` で戻させる。vCPU 破棄後は `FailedPrecondition`。
    ///
    /// `run` の前に呼ぶと保留され、次の `run` がゲストへ入らず `Canceled` で戻る（#3803）。
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
/// `Send` でないこと（スレッド間の移動を型で禁じる。エラー番号 E0277 を照合するのは nightly の rustdoc だけで、
/// stable では上の const の判定が担う。#3844）:
///
/// ```compile_fail,E0277
/// use fandhe_container_microvm::hvf::HvVcpu;
/// fn assert_send<T: Send>() {}
/// assert_send::<HvVcpu<'static>>();
/// ```
///
/// `Sync` でないこと:
///
/// ```compile_fail,E0277
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

/// 期限監視スレッドが超過後に `hv_vcpus_exit` を繰り返す間隔。`run` の前の `cancel` は保留されるので取りこぼさないが、
/// 止まらないと `run_once` が戻らないため、再送を歯止めとして残す（REPAIR-5）。
const KICK_INTERVAL: Duration = Duration::from_millis(10);

/// 保留の `cancel` を捨てる run の期限。ゲストへ入らず即戻るはずの run で、超えたら異常として扱う。
const DISCARD_CANCEL_DEADLINE: Duration = Duration::from_secs(1);

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
    /// 外部の `VcpuCanceller::cancel` による停止は `Ok(Canceled)`。run の間に届いた外部の `cancel` も次の run を
    /// `Ok(Canceled)` で戻すため、呼び出し側は自分の停止条件を確かめる（`hvf_loop` は停止フラグが無ければ続行する）。
    /// 期限の発火で送った `cancel` は `discard_pending_cancel` で捨て、次の run へ漏らさない（#3845）。
    /// 未知の理由は `Unknown` で、呼び出し側は VM を止める（fail-closed）。結果と所要時間は `stats` と観測器
    /// （`set_observer`）へ、エラー経路も含めて残す（REPAIR-4）。期限の入力検査の失敗は発行前のため記録しない。
    pub fn run_once(&mut self, timeout: Duration) -> Result<HvVcpuExit, MicrovmError> {
        check_run_deadline(timeout)?;
        let start = Instant::now();
        let (result, fired) = self.run_watched(timeout);
        let result = if fired {
            self.discard_pending_cancel().and(result)
        } else {
            result
        };
        let (result, record) = finish_run(result, fired, start.elapsed());
        self.stats.add(&record);
        if let Some(o) = &self.observer {
            o.record(&record);
        }
        result
    }

    /// 期限の発火で残りうる保留の `cancel` を捨てる（#3845）。
    ///
    /// 保留の有無は照会できない。そこで `cancel` を足して保留を確定させ、ゲストへ入らず `Canceled` で戻る run で消費する。
    /// 同じ理由の `hv_vcpu_run` は PC を動かさない（#3803）。`Canceled` 以外はゲストが走って exit を失ったことになるため
    /// `Internal` で失敗にする（fail-closed）。呼び出しの前に監視スレッドは止まっており、後から `cancel` は届かない。
    /// ここで外部の `cancel` を消費しても、`hvf_loop` は期限切れの後に停止フラグを見直し、stop は kick を再送するので、
    /// 停止は失われない。
    fn discard_pending_cancel(&mut self) -> Result<(), MicrovmError> {
        self.canceller().cancel()?;
        match self.run_watched(DISCARD_CANCEL_DEADLINE) {
            (Ok(HvVcpuExit::Canceled), false) => Ok(()),
            (Err(e), _) => Err(e),
            (Ok(_), _) => Err(internal("vcpu entered the guest while discarding a cancel")),
        }
    }

    /// 期限の監視つきで `hv_vcpu_run` を 1 回呼び、結果と期限が発火したかを返す。戻った時点で監視スレッドは止まっている。
    fn run_watched(&mut self, timeout: Duration) -> (Result<HvVcpuExit, MicrovmError>, bool) {
        let canceller = self.canceller();
        let done = (Mutex::new(false), Condvar::new());
        let fired = AtomicBool::new(false);
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
        (result, fired.load(Ordering::SeqCst))
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
// ---- GICv3（TASK-192.3・#3789）。`hv_gic_*` は直接リンクせず `dlsym` で解決する（モジュール doc） ----

// `hv_gic_*` の関数ポインタ型。`hv_gic_config_t` は OS オブジェクト（不透明ポインタ）、`hv_gic_intid_t` は
// `uint16_t`、`bool` は C の `_Bool`、`size_t` = usize。
type GicConfigCreateFn = unsafe extern "C" fn() -> *mut c_void;
type GicConfigSetBaseFn = unsafe extern "C" fn(*mut c_void, u64) -> c_int;
type GicCreateFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type GicSetSpiFn = unsafe extern "C" fn(u32, bool) -> c_int;
type GicGetSizeFn = unsafe extern "C" fn(*mut usize) -> c_int;
type GicGetRangeFn = unsafe extern "C" fn(*mut u32, *mut u32) -> c_int;
type GicGetIntidFn = unsafe extern "C" fn(u16, *mut u32) -> c_int;
// `hv_gic_get_distributor_reg(hv_gic_distributor_reg_t reg, uint64_t *value)`。`hv_gic_distributor_reg_t` は `uint16_t`（#3960）。
type GicGetDistributorRegFn = unsafe extern "C" fn(u16, *mut u64) -> c_int;

/// シンボル解決の失敗の固定文（シンボル名は載せない。ERR-1）。
fn gic_symbol_missing() -> MicrovmError {
    MicrovmError::new(
        MicrovmErrorCode::Unimplemented,
        "hypervisor GIC symbol is not available",
    )
}

/// `kern.osproductversion` を読んで分解する。応答は上限つきのスタックバッファで受け、切り詰めは拒否する。
fn macos_version() -> Result<MacosVersion, MicrovmError> {
    let mut buf = [0u8; MACOS_PRODUCT_VERSION_MAX_LEN + 1];
    let mut len = buf.len();
    // SAFETY: 名前は NUL 終端の `c""` 定数。`oldp` は `buf`（`len` バイト）を指し、`oldlenp` は `len` を指す
    // ローカル変数で、どちらも呼び出しの間生きている。`newp` は NULL・`newlen` は 0（読み取りのみ）。
    let rc = unsafe {
        sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            buf.as_mut_ptr().cast::<c_void>(),
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len > buf.len() {
        return Err(internal("sysctl kern.osproductversion failed"));
    }
    parse_macos_product_version(buf.get(..len).ok_or_else(|| internal("sysctl length"))?)
}

/// 読み込み済みの image から `name` を探す。見つからなければ `None`（NULL）。
fn lookup(name: &CStr) -> Option<*mut c_void> {
    // SAFETY: `RTLD_DEFAULT` は読み込み済み image の検索を表す疑似ハンドル。`name` は NUL 終端で呼び出しの間生きている。
    // `dlsym` は新しい image を読み込まない。`hv_gic_*` が見つかるのは Hypervisor.framework が読み込み済みのときだけで、
    // その前提はこのファイルの `hv_vm_*`・`hv_vcpu_*` の `extern` ブロックが `#[link(name = "Hypervisor", kind = "framework")]`
    // で直接リンクしている（load-time の依存。起動時に dyld が読み込み、プロセスの終わりまで unload しない）ことに依る。
    // 直接リンクが無くなれば `dlsym` は NULL を返し、呼び出し側は `Unimplemented` で fail-closed する（UB にはならない）。
    // 退行は実機前提試験 `hvf_device_gic_symbols_resolve` が検出する。
    let p = unsafe { dlsym(RTLD_DEFAULT, name.as_ptr()) };
    (!p.is_null()).then_some(p)
}

/// シンボルを関数ポインタ型 `$ty` として解決する（NULL 検査の後でだけ変換する）。
macro_rules! resolve {
    ($name:expr, $ty:ty) => {{
        let p = lookup($name).ok_or_else(gic_symbol_missing)?;
        // SAFETY: `p` は NULL でない `dlsym` の戻り値で、`$ty` は Apple のドキュメントのシグネチャに一致させた
        // `extern "C"` の関数ポインタ（データポインタと同じ幅）。`p` を返した image は Hypervisor.framework（`lookup` の SAFETY の前提）で、
        // load-time の依存のため unload されず `dlclose` もしないので、関数ポインタの寿命はプロセスと同じ。
        unsafe { std::mem::transmute::<*mut c_void, $ty>(p) }
    }};
}

/// 実行時に解決した `hv_gic_*` の関数表（macOS 15 以降）。関数ポインタは private で `sys` の外へ出さない。
/// `Copy` な関数ポインタだけを持つので `Send + Sync`。取得は [`GicApi::get`]。
///
/// 公開範囲（#3867・MVM-5・MVM-4）: 構造体・`get`・照会 6 種（`distributor_size`・`distributor_base_alignment`・
/// `redistributor_size`・`redistributor_base_alignment`・`spi_interrupt_range`・`intid`）は `pub` のまま残す。
/// 照会は VM・GIC の作成前に呼ぶ前提（`HvfGic::probe` が VM 作成前に呼ぶ）で、副作用が無く失敗は戻り値で返る。
/// 外部の実機前提試験 `hvf_device_gic_symbols_resolve` が配置検証と切り離してシンボル解決と生の値を観測するのにも使う。
/// 状態を変える操作（`config_create`・`create`・`set_spi` と `GicConfig`）は `pub(crate)` で、外部からは順序と生存を
/// 型で強制した `HvfGic::create`・`VmWithGic`・`GicSpiLine` の経路でしか行えない。
pub struct GicApi {
    config_create: GicConfigCreateFn,
    config_set_distributor_base: GicConfigSetBaseFn,
    config_set_redistributor_base: GicConfigSetBaseFn,
    create: GicCreateFn,
    set_spi: GicSetSpiFn,
    get_distributor_size: GicGetSizeFn,
    get_distributor_base_alignment: GicGetSizeFn,
    get_redistributor_size: GicGetSizeFn,
    get_redistributor_base_alignment: GicGetSizeFn,
    get_spi_interrupt_range: GicGetRangeFn,
    get_intid: GicGetIntidFn,
    /// 任意のシンボル（#3960）。見つからなければ `None` で、GIC 自体は使える（11 個の必須の規則には含めない）。
    get_distributor_reg: Option<GicGetDistributorRegFn>,
}

impl std::fmt::Debug for GicApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GicApi").finish_non_exhaustive()
    }
}

static GIC_API: OnceLock<Result<GicApi, MicrovmError>> = OnceLock::new();

impl GicApi {
    /// 版判定（15 未満は `Unimplemented`）の後に 11 シンボルを解決する。結果（エラーを含む）はプロセスで 1 回だけ作る。
    pub fn get() -> Result<&'static GicApi, MicrovmError> {
        GIC_API
            .get_or_init(|| {
                check_gic_supported(macos_version()?)?;
                GicApi::resolve_all()
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    fn resolve_all() -> Result<GicApi, MicrovmError> {
        Ok(GicApi {
            config_create: resolve!(c"hv_gic_config_create", GicConfigCreateFn),
            config_set_distributor_base: resolve!(
                c"hv_gic_config_set_distributor_base",
                GicConfigSetBaseFn
            ),
            config_set_redistributor_base: resolve!(
                c"hv_gic_config_set_redistributor_base",
                GicConfigSetBaseFn
            ),
            create: resolve!(c"hv_gic_create", GicCreateFn),
            set_spi: resolve!(c"hv_gic_set_spi", GicSetSpiFn),
            get_distributor_size: resolve!(c"hv_gic_get_distributor_size", GicGetSizeFn),
            get_distributor_base_alignment: resolve!(
                c"hv_gic_get_distributor_base_alignment",
                GicGetSizeFn
            ),
            get_redistributor_size: resolve!(c"hv_gic_get_redistributor_size", GicGetSizeFn),
            get_redistributor_base_alignment: resolve!(
                c"hv_gic_get_redistributor_base_alignment",
                GicGetSizeFn
            ),
            get_spi_interrupt_range: resolve!(c"hv_gic_get_spi_interrupt_range", GicGetRangeFn),
            get_intid: resolve!(c"hv_gic_get_intid", GicGetIntidFn),
            get_distributor_reg: lookup(c"hv_gic_get_distributor_reg").map(|p| {
                // SAFETY: `p` は NULL でない `dlsym` の戻り値（`lookup`）。型は Apple の文書のシグネチャ
                // （`hv_gic_distributor_reg_t` は `uint16_t`・出力は `uint64_t *`・戻りは `hv_return_t`）に一致させた
                // `extern "C"` の関数ポインタ（データポインタと同じ幅）。image は unload されず `dlclose` もしない（`resolve!` と同じ論拠）。
                unsafe { std::mem::transmute::<*mut c_void, GicGetDistributorRegFn>(p) }
            }),
        })
    }

    fn query_size(f: GicGetSizeFn, op: HvOp) -> Result<usize, MicrovmError> {
        let mut out = 0usize;
        // SAFETY: 解決元の Hypervisor.framework は読み込み済みで unload されない（`lookup` の SAFETY）。
        // `f` は `get` の版判定を通った後に解決した関数で、出力先はローカル変数 `out` だけ（呼び出しの間生きている）。
        let rc = unsafe { f(&mut out) };
        classify_hv_return(op, rc)?;
        Ok(out)
    }

    /// distributor の大きさ（バイト）。
    pub fn distributor_size(&self) -> Result<usize, MicrovmError> {
        Self::query_size(self.get_distributor_size, HvOp::GicGetDistributorSize)
    }

    /// distributor の base に要求されるアラインメント（バイト）。
    pub fn distributor_base_alignment(&self) -> Result<usize, MicrovmError> {
        Self::query_size(
            self.get_distributor_base_alignment,
            HvOp::GicGetDistributorBaseAlignment,
        )
    }

    /// redistributor 領域の大きさ（バイト）。
    pub fn redistributor_size(&self) -> Result<usize, MicrovmError> {
        Self::query_size(self.get_redistributor_size, HvOp::GicGetRedistributorSize)
    }

    /// redistributor の base に要求されるアラインメント（バイト）。
    pub fn redistributor_base_alignment(&self) -> Result<usize, MicrovmError> {
        Self::query_size(
            self.get_redistributor_base_alignment,
            HvOp::GicGetRedistributorBaseAlignment,
        )
    }

    /// SPI の割り込み番号の範囲 `(base, count)`。
    pub fn spi_interrupt_range(&self) -> Result<(u32, u32), MicrovmError> {
        let (mut base, mut count) = (0u32, 0u32);
        // SAFETY: 解決元の Hypervisor.framework は読み込み済みで unload されない（`lookup` の SAFETY）。出力先はローカル変数 2 つで、呼び出しの間生きている。
        let rc = unsafe { (self.get_spi_interrupt_range)(&mut base, &mut count) };
        classify_hv_return(HvOp::GicGetSpiInterruptRange, rc)?;
        Ok((base, count))
    }

    /// 予約済みの割り込み `id` の割り込み番号（INTID）。
    pub fn intid(&self, id: HvGicIntid) -> Result<GicIntid, MicrovmError> {
        let mut out = 0u32;
        // SAFETY: 解決元の Hypervisor.framework は読み込み済みで unload されない（`lookup` の SAFETY）。出力先はローカル変数 `out` だけ。`id.bits()` は `uint16_t` の値。
        let rc = unsafe { (self.get_intid)(id.bits(), &mut out) };
        classify_hv_return(HvOp::GicGetIntid, rc)?;
        Ok(GicIntid::new(out))
    }

    /// distributor のレジスタ `reg` を読む（`hv_gic_get_distributor_reg`。macOS 15.0 以降の任意のシンボル。#3960・MVM-5）。
    ///
    /// シンボルが無ければ `Unimplemented`。戻りは [`classify_hv_return`] で写す。`reg` は検証済みの newtype からしか作れない。
    /// 呼び出し元（`hvf::gic` の SPI sink）は縮退先（学習したヒント）を持つので、失敗は無視してよい。
    /// 出典: <https://developer.apple.com/documentation/hypervisor/hv_gic_get_distributor_reg(_:_:)>（distributor 版には
    /// redistributor 版にある「owning thread で呼ぶ」注記が無い。非 vCPU スレッドからの呼び出しの観測は #3803）。
    pub(crate) fn distributor_reg(&self, reg: GicDistributorReg) -> Result<u64, MicrovmError> {
        let f = self.get_distributor_reg.ok_or_else(|| {
            MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "hypervisor GIC distributor register read is not available",
            )
        })?;
        let mut out = 0u64;
        // SAFETY: 解決元の Hypervisor.framework は読み込み済みで unload されない（`lookup` の SAFETY）。出力先はローカル変数
        // `out` だけで呼び出しの間生きている。`reg.bits()` は検証済みの distributor のレジスタオフセット（`GICD_CTLR` か `GICD_IROUTER<n>`。#3974）（`uint16_t`）。
        let rc = unsafe { f(reg.bits(), &mut out) };
        classify_hv_return(HvOp::GicGetDistributorReg, rc)?;
        Ok(out)
    }

    /// SPI の入力レベルを設定する。
    pub(crate) fn set_spi(&self, intid: u32, level: bool) -> Result<(), MicrovmError> {
        // SAFETY: 解決元の Hypervisor.framework は読み込み済みで unload されない（`lookup` の SAFETY）。引数は整数と bool だけで、ポインタを取らない。
        let rc = unsafe { (self.set_spi)(intid, level) };
        classify_hv_return(HvOp::GicSetSpi, rc)
    }

    /// GIC の設定オブジェクトを作る（NULL は `ResourceExhausted`）。
    pub(crate) fn config_create(&'static self) -> Result<GicConfig, MicrovmError> {
        // SAFETY: 解決元の Hypervisor.framework は読み込み済みで unload されない（`lookup` の SAFETY）。引数なしで OS オブジェクトを返す。戻り値は NULL 検査の後で `GicConfig` が所有する。
        let raw = unsafe { (self.config_create)() };
        if raw.is_null() {
            return Err(MicrovmError::new(
                MicrovmErrorCode::ResourceExhausted,
                "hv_gic_config_create returned NULL",
            ));
        }
        Ok(GicConfig { raw, api: self })
    }

    /// VM に GIC を作る。VM が存在する間（`&HvVm`）だけ呼べ、`config` は消費する。
    /// 作成順序（vCPU より前・VM につき 1 回）は `crate::hvf::gic::HvfGic::create` が型で強制する（#3792）ため、
    /// crate の外へは公開しない。
    pub(crate) fn create(&self, _vm: &HvVm, config: GicConfig) -> Result<(), MicrovmError> {
        // SAFETY: 解決元の Hypervisor.framework は読み込み済みで unload されない（`lookup` の SAFETY）。`config.raw` は `GicConfig` が所有する有効な OS オブジェクトで、呼び出しの間生きている
        // （解放は `GicConfig` の drop で 1 回だけ）。VM は `_vm` の借用で存在が保証される。
        let rc = unsafe { (self.create)(config.raw) };
        classify_hv_return(HvOp::GicCreate, rc)
    }
}

/// `hv_gic_config_t`（OS オブジェクト）の所有者。drop で `os_release` を 1 回だけ呼ぶ。生ポインタ入りで `!Send`・`!Sync`。
#[derive(Debug)]
pub(crate) struct GicConfig {
    raw: *mut c_void,
    api: &'static GicApi,
}

impl GicConfig {
    /// distributor の base の IPA を設定する。
    pub(crate) fn set_distributor_base(&mut self, ipa: u64) -> Result<(), MicrovmError> {
        // SAFETY: 解決元の Hypervisor.framework は読み込み済みで unload されない（`lookup` の SAFETY）。`raw` は有効な OS オブジェクトで、`&mut self` により排他。
        let rc = unsafe { (self.api.config_set_distributor_base)(self.raw, ipa) };
        classify_hv_return(HvOp::GicConfigSetDistributorBase, rc)
    }

    /// redistributor の base の IPA を設定する。
    pub(crate) fn set_redistributor_base(&mut self, ipa: u64) -> Result<(), MicrovmError> {
        // SAFETY: 解決元の Hypervisor.framework は読み込み済みで unload されない（`lookup` の SAFETY）。`raw` は有効な OS オブジェクトで、`&mut self` により排他。
        let rc = unsafe { (self.api.config_set_redistributor_base)(self.raw, ipa) };
        classify_hv_return(HvOp::GicConfigSetRedistributorBase, rc)
    }
}

impl Drop for GicConfig {
    fn drop(&mut self) {
        // SAFETY: `raw` は `config_create` が返した NULL でない OS オブジェクトで、ここ以外で解放されない
        // （`create` は config を消費するが解放しない）。`hv_gic_create` は retain しないが、`create` の後に解放しても
        // 以後の `hv_gic_*`・`hv_vcpu_create`・`hv_vm_destroy` は成功した（実機のプローブ。#3803）。
        unsafe { os_release(self.raw) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 換算比の numer・denom が 0 以外で、`OnceLock` のキャッシュにより毎回同じ値を返す。
    /// entitlement 不要で既定の試験集合で走る（MVM-5・#3796・#3885）。
    #[test]
    fn mvm5_3796_host_timebase_is_nonzero_and_cached() {
        let first = host_timebase().expect("mach_timebase_info must succeed");
        assert_ne!(first.numer(), 0);
        assert_ne!(first.denom(), 0);
        let second = host_timebase().expect("cached timebase must be Ok");
        assert_eq!(first, second);
    }

    /// 連続 2 回は減らず、1 ms の sleep を挟むと厳密に増える。Apple Silicon のカウンタは 24 MHz 程度で
    /// 1 ms は数万 tick のため厳密増加が成り立つ（MVM-5・#3796・#3885）。
    #[test]
    fn mvm5_3796_host_absolute_time_is_monotonic() {
        let a = host_absolute_time();
        let b = host_absolute_time();
        assert!(b >= a, "counter went backwards: a={a} b={b}");
        std::thread::sleep(Duration::from_millis(1));
        let c = host_absolute_time();
        assert!(
            c > b,
            "counter did not advance across 1ms sleep: b={b} c={c}"
        );
    }
}
