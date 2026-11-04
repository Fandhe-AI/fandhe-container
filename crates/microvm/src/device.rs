//! `/dev/kvm` のオープンと VM fd の作成（TASK-74.1.1・MVM-1・MVM-4。Linux のみ）。
//!
//! 将来の起動フロー（TASK-75）・`fandhe-container-plugin-microvm`（TASK-117）から呼ばれる入口。
//! [`KvmDevice`] が `/dev/kvm` を `O_RDWR | O_CLOEXEC` で開き、API 版数 12 を確認してから
//! [`KvmDevice::create_vm`] で [`VmFd`] を返し、[`VmFd::create_vcpu`] で [`VcpuFd`] を返す（TASK-74.1.2）。
//! TASK-74.4.1 で [`VcpuFd::run_once`]（`KVM_RUN` を 1 回発行して VM exit を [`VcpuExit`] で返す）と、
//! 実機で実行を示す自己診断 [`KvmDevice::probe_guest_execution`] を足した。
//! TASK-74.4.2（#883）で exit のデバイスへの振り分けと IN・MMIO read の応答の書き戻し（[`VcpuFd::handle_exit`]。
//! 振り分け先は `crate::dispatch`）と、実機で確かめる自己診断 [`KvmDevice::probe_exit_dispatch`] を足した。
//! ゲストメモリ（アクセス型は TASK-74.1 配下の後続 sub-issue、mmap と KVM 登録は TASK-75.1。docs/design/microvm-memory-ownership.md）・
//! 停止は `microvm::RunningMicroVm::stop` が `StopSignal` を立て、実行中の `KVM_RUN` を `immediate_exit` と kick で即時に中断する（TASK-75.4.1・#886・#3736）。
//! 一時停止は未実装で、後続が [`VmFd`]・[`VcpuFd`]（いずれも `AsFd`）を使って足す（REPAIR-3）。
//! `run_once` は期限つき（`immediate_exit` とシグナルで中断し `DeadlineExceeded`。REPAIR-5）で、結果と所要時間を
//! [`RunStats`]・[`RunObserver`] へ残す（REPAIR-4）。
//! TASK-74.2.3（#879）で割り込み通知を足した: [`VmFd::create_irqchip`]（x86_64。vCPU より前に作る）・
//! [`VmFd::register_irqfd`]（`KVM_IRQFD`。eventfd への書き込みで GSI の割り込みを注入）・
//! [`VmFd::register_ioeventfd`]（`KVM_IOEVENTFD`。ゲストの `QueueNotify` を VM exit なしで eventfd へ）と、
//! 実機で確かめる自己診断 [`KvmDevice::probe_queue_interrupt`]。in-kernel irqchip を作った VM では x86_64 の HLT が
//! userspace へ exit せず `KVM_RUN` の中で待つ（割り込みが無ければ `run_once` の期限で `DeadlineExceeded`）。
//! #3918（MVM-1）で x86_64 の COM1（IRQ 4）の level 線 `VmFd::register_irq_line`（`KVM_IRQ_LINE`）を足した。
//! #3696（MVM-1）で aarch64 の vGICv3（`KVM_CREATE_DEVICE`。`VgicV3`）と起動レジスタ（`KVM_SET_ONE_REG`。`VcpuFd::set_arm64_boot_state`）を足した。
//! resamplefd による level の再注入・eventfd を待つ常駐ループは未実装（TASK-75。REPAIR-3）。
//! TASK-75.3.2（#885）で x86_64 の起動時のレジスタ初期化 [`VcpuFd::set_boot_state`]（long mode・RIP = カーネルのエントリ・RSI = boot_params）と
//! 観測用の [`VcpuFd::regs`] を足した（CPUID は #3733 の [`VcpuFd::set_cpuid`]。LAPIC の LINT は #3735。REPAIR-3）。#3734 で起動用の [`VcpuFd::set_msrs`]・[`VcpuFd::set_fpu`] と観測用の [`VcpuFd::msrs`]・[`VcpuFd::fpu`] を足した。
//! #3735（MVM-1）で BSP の LAPIC の LVT LINT0 = ExtINT・LINT1 = NMI を設定する [`VcpuFd::set_boot_lints`] と観測用の [`VcpuFd::lapic_lints`] を足した。
//! 失敗は panic せず [`MicrovmError`]（ERR-1）で返す。`unsafe` は `crate::sys` に閉じる。
//!
//! # アーキテクチャ別の vCPU 作成
//! - x86_64: `KVM_CREATE_VCPU` だけで vCPU fd が使える。レジスタ設定は TASK-75.3.2 の `VcpuFd::set_boot_state`
//! - aarch64: `KVM_CREATE_VCPU` の後に VM fd へ `KVM_ARM_PREFERRED_TARGET`、vCPU fd へ `KVM_ARM_VCPU_INIT`
//!   （features は `KVM_ARM_VCPU_PSCI_0_2` のみ。先に `KVM_CAP_ARM_PSCI_0_2` を確かめ、無ければ `FailedPrecondition`。
//!   #3896）を発行して初期化済みの vCPU を返す。未初期化だと `KVM_RUN` が ENOEXEC で失敗する。aarch64 はネイティブ CI が無く（#2274）型検査のみで実行は未検証
//!
//! # aarch64 の割り込みコントローラー（#3696）
//! x86_64 の `KVM_CREATE_IRQCHIP` は無く、vGICv3 を `KVM_CREATE_DEVICE`（`KVM_DEV_TYPE_ARM_VGIC_V3`）で作る。順序は
//! 「vCPU を全部作る → vGIC を作ってアドレス（distributor・redistributor）を設定 → `KVM_DEV_ARM_VGIC_CTRL_INIT` → irqfd」。
//! 根拠（Linux v6.12）: `Documentation/virt/kvm/devices/arm-vgic-v3.rst` は CTRL_INIT を「全 vCPU の作成後」と定め、
//! `virt/kvm/eventfd.c` の `kvm_irqfd_assign` は `kvm_arch_intc_initialized()` が偽なら `-EAGAIN` を返す（初期化前の irqfd は拒否される）。
//! irqfd の GSI は SPI 番号に等しい（`arch/arm64/kvm/vgic/vgic-irqfd.c` の既定 routing は pin = GSI で、注入は INTID = pin + 32）。
//!
//! aarch64 の machine type（IPA サイズ）は既定の 0 を使う。指定は TASK-75 で再検討する。
//! [`KvmDevice`]・[`VmFd`]・[`VcpuFd`] は `OwnedFd` を持つため `Send` / `Sync`。

#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[cfg(target_arch = "aarch64")]
use crate::boot_arm64::ArmBootState;
use crate::boot_x86::BootCpuState;
#[cfg(target_arch = "x86_64")]
use crate::boot_x86::{SegmentDescriptor, X86FpuState, X86MsrEntry, X86Regs};
use crate::cpuid_x86::CpuidTable;
#[cfg(target_arch = "x86_64")]
use crate::cpuid_x86::{CpuidEntry, MAX_CPUID_ENTRIES};
use crate::dispatch::{DispatchOutcome, ExitDispatcher};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::exit::{self, ExitValue, VcpuExit};
use crate::interrupt::{InterruptLine, IoEventSpec};
#[cfg(target_arch = "x86_64")]
use crate::irq::IrqLevelLine;
use crate::irq::{self, EventFd, IoEventFd, IrqFd};
use crate::sys::{self, SysError};

/// 本番で開くデバイスパス（固定リテラル。外部入力は届かない）。
const KVM_PATH: &str = "/dev/kvm";

// errno（Linux 共通。x86_64・aarch64 で同値）。`io::ErrorKind` で分類できないものだけ使う。
const EPERM: i32 = 1;
const ENOMEM: i32 = 12;
const EEXIST: i32 = 17;
const ENOEXEC: i32 = 8;
const EAGAIN: i32 = 11;
const EINTR: i32 = 4;
const EINVAL: i32 = 22;
const E2BIG: i32 = 7;
const EACCES: i32 = 13;
const ENFILE: i32 = 23;
const EMFILE: i32 = 24;
const ENOTTY: i32 = 25;
const EBUSY: i32 = 16;
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    allow(dead_code)
)]
const ENXIO: i32 = 6;
/// `ENODEV`（ホストが要求したデバイス種別を持たない。vGICv3 の作成で使う）。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
const ENODEV: i32 = 19;
const ENOSPC: i32 = 28;

/// 開いた `/dev/kvm`。
#[derive(Debug)]
pub struct KvmDevice {
    fd: OwnedFd,
}

/// `KVM_CREATE_VM` で得た VM fd。drop で close される。
#[derive(Debug)]
pub struct VmFd {
    fd: OwnedFd,
    /// `KVM_GET_VCPU_MMAP_SIZE` の検証済みの値（`create_vcpu` の `kvm_run` の mmap に使う）。
    vcpu_mmap_size: usize,
}

/// `KVM_CREATE_DEVICE` で得た aarch64 の vGICv3 の device fd（MVM-1・#3696）。drop で close され、KVM がデバイスを破棄する。
///
/// `MicroVm` が保持し、drop 順は「vCPU → デバイス（irqfd の解除）→ vGIC → メモリ → VM fd」。観測用の
/// `dist_base`・`redist_base`・`spi_pending` だけを公開し、設定系は `pub(crate)`（検証を経ない値を外へ出さない）。
#[cfg(target_arch = "aarch64")]
#[derive(Debug)]
pub struct VgicV3 {
    fd: OwnedFd,
}

#[cfg(target_arch = "aarch64")]
impl VgicV3 {
    /// vGIC を初期化する（`KVM_DEV_ARM_VGIC_GRP_CTRL` の `CTRL_INIT`）。全 vCPU の作成後、irqfd の登録前に 1 回だけ呼ぶ。
    ///
    /// vCPU が実行済みなどでカーネルが拒否したときは `FailedPrecondition`（EBUSY）、アドレスの重なり・redistributor の不足は
    /// `InvalidArgument`（EINVAL）。二重に呼んだ場合の挙動はカーネルに任せる（本層は 1 回だけ呼ぶ）。
    pub(crate) fn init(&self) -> Result<(), MicrovmError> {
        sys::kvm_set_device_attr_u64(
            self.fd.as_fd(),
            sys::consts::KVM_DEV_ARM_VGIC_GRP_CTRL,
            sys::consts::KVM_DEV_ARM_VGIC_CTRL_INIT,
            0,
        )
        .map_err(|e| classify_irq_error(IrqStage::SetDeviceAttr, e))
    }

    /// distributor の GPA を読み戻す（観測用）。
    pub fn dist_base(&self) -> Result<u64, MicrovmError> {
        sys::kvm_get_device_attr_u64(
            self.fd.as_fd(),
            sys::consts::KVM_DEV_ARM_VGIC_GRP_ADDR,
            sys::consts::KVM_VGIC_V3_ADDR_TYPE_DIST,
        )
        .map_err(|e| classify_irq_error(IrqStage::GetDeviceAttr, e))
    }

    /// redistributor の GPA を読み戻す（観測用）。
    pub fn redist_base(&self) -> Result<u64, MicrovmError> {
        sys::kvm_get_device_attr_u64(
            self.fd.as_fd(),
            sys::consts::KVM_DEV_ARM_VGIC_GRP_ADDR,
            sys::consts::KVM_VGIC_V3_ADDR_TYPE_REDIST,
        )
        .map_err(|e| classify_irq_error(IrqStage::GetDeviceAttr, e))
    }

    /// SPI `intid`（32..1020）が pending か、distributor の `GICD_ISPENDR<n>` を読んで返す（観測用。試験・診断向け）。
    ///
    /// `KVM_DEV_ARM_VGIC_GRP_DIST_REGS`（vCPU 0 の MPIDR = 0 を attr の上位に、レジスタの offset を下位に置く）で読む。
    /// カーネルは全 vCPU をロックして読むため、**vCPU が `KVM_RUN` 中は `EBUSY`**（`FailedPrecondition`）。vGIC の初期化前も同じ。
    /// 範囲外の `intid` は `InvalidArgument`。
    pub fn spi_pending(&self, intid: u32) -> Result<bool, MicrovmError> {
        let offset = spi_ispendr_offset(intid)?;
        let v = sys::kvm_get_device_attr_u64(
            self.fd.as_fd(),
            sys::consts::KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
            offset,
        )
        .map_err(|e| classify_irq_error(IrqStage::GetDeviceAttr, e))?;
        Ok(v & (1u64 << (intid % 32)) != 0)
    }
}

/// SPI の INTID から `GICD_ISPENDR<n>` の distributor 内 offset（`0x200 + 4 * (intid / 32)`）を返す（純関数。#3696）。
/// SPI は INTID 32..=1019。範囲外は `InvalidArgument`。
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
fn spi_ispendr_offset(intid: u32) -> Result<u64, MicrovmError> {
    const GICD_ISPENDR: u64 = 0x200;
    if !(32..1020).contains(&intid) {
        return Err(MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "SPI intid out of range",
        ));
    }
    Ok(GICD_ISPENDR + 4 * u64::from(intid / 32))
}

/// `KVM_CREATE_VCPU` で得た vCPU fd と、その `kvm_run` 領域の mmap。drop で munmap・close される。
#[derive(Debug)]
pub struct VcpuFd {
    // フィールドの宣言順 = drop 順。mmap（run）を fd より先に解く。
    run: sys::KvmRunMap,
    fd: OwnedFd,
    id: u32,
    stats: RunStats,
    observer: Option<Arc<dyn RunObserver>>,
}

/// `KVM_RUN` 1 回の結果の分類（計装用。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// VM exit で戻った。値は exit の種別名（`io` / `mmio` / `hlt` 等）。
    Exit(&'static str),
    /// シグナル等で中断された（EINTR / EAGAIN）。
    Interrupted,
    /// 期限を超えて `immediate_exit` とシグナルで中断した（REPAIR-5）。
    DeadlineExceeded,
    /// ioctl または復号の失敗。
    Error(MicrovmErrorCode),
}

/// `KVM_RUN` 1 回の記録（結果と所要時間。REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunRecord {
    /// 実行した vCPU の id。
    pub vcpu_id: u32,
    /// 結果。
    pub outcome: RunOutcome,
    /// `KVM_RUN` の発行から戻るまでの時間。
    pub elapsed: Duration,
    /// exit の値（PIO・MMIO）。観測器が [`RunObserver::wants_values`] で求めたときだけ `Some`。
    /// ゲストが制御する値で untrusted（#3769・MVM-1・REPAIR-12）。
    pub value: Option<ExitValue>,
}

/// 実行結果の記録器。呼び出し側（将来の plugin-microvm・TASK-117 等）が構造化ログやメトリクスへ接続する。
/// `record` は `KVM_RUN` が戻った直後に vCPU スレッドから同期で呼ばれるため、ブロックしないこと。
pub trait RunObserver: Send + Sync + std::fmt::Debug {
    /// 1 回の `KVM_RUN` の記録を受け取る。
    fn record(&self, record: &RunRecord);

    /// `RunRecord::value` を求めるか。既定は false（opt-in）。値はゲスト由来の秘密を含みうるため、
    /// 製品の構造化ログ・メトリクスへ接続する観測器は true にしない（試験・診断用。#3769）。
    fn wants_values(&self) -> bool {
        false
    }
}

/// [`BoundedRunLog`] の記録件数の上限（割り当て上限の検証用。#3769）。
pub const RUN_LOG_CAPACITY_MAX: usize = 4096;

/// [`BoundedRunLog`] が exit の値を記録するか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueCapture {
    /// 値を記録しない（種別と時間のみ）。
    Omit,
    /// PIO・MMIO の値を記録する（データ長は `EXIT_VALUE_DATA_MAX` で上限）。
    Record,
}

/// 件数上限つきの観測器（試験・診断用。#3769・MVM-1・REPAIR-12）。
///
/// 上限を超えたレコードは捨てて [`BoundedRunLog::dropped`] に数える。`record` は割り当てしない（`new` で確保済み）。
/// 読み取り側（`records` 等）はロックを短時間（複製の間だけ）しか持たないため、`record` は競合しても
/// 短い待ちで必ず記録する（競合で exit を捨てると並びの照合が不安定になる。REPAIR-12）。`Debug` は記録した値を出さない。
pub struct BoundedRunLog {
    capacity: usize,
    capture: ValueCapture,
    inner: std::sync::Mutex<BoundedRunLogInner>,
}

struct BoundedRunLogInner {
    records: Vec<RunRecord>,
    dropped: u64,
}

impl BoundedRunLog {
    /// `capacity` は 1 以上 [`RUN_LOG_CAPACITY_MAX`] 以下。範囲外は `InvalidArgument`。
    pub fn new(capacity: usize, capture: ValueCapture) -> Result<BoundedRunLog, MicrovmError> {
        if capacity == 0 || capacity > RUN_LOG_CAPACITY_MAX {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "run log capacity must be in 1..=4096",
            ));
        }
        Ok(BoundedRunLog {
            capacity,
            capture,
            inner: std::sync::Mutex::new(BoundedRunLogInner {
                records: Vec::with_capacity(capacity),
                dropped: 0,
            }),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BoundedRunLogInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 記録済みのレコード（起きた順）。
    pub fn records(&self) -> Vec<RunRecord> {
        self.lock().records.clone()
    }

    /// 件数上限で捨てたレコード数。
    pub fn dropped(&self) -> u64 {
        self.lock().dropped
    }
}

impl std::fmt::Debug for BoundedRunLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 出力先が詰まってもロックを持ち続けないよう、値を複製して解放してから出す。
        let (len, dropped) = {
            let g = self.lock();
            (g.records.len(), g.dropped)
        };
        f.debug_struct("BoundedRunLog")
            .field("capacity", &self.capacity)
            .field("capture", &self.capture)
            .field("len", &len)
            .field("dropped", &dropped)
            .finish()
    }
}

impl RunObserver for BoundedRunLog {
    fn record(&self, record: &RunRecord) {
        // 読み取り側の保持は複製の間だけで有界。競合しても待って必ず記録する。
        let mut g = self.lock();
        if g.records.len() < self.capacity {
            g.records.push(*record);
        } else {
            g.dropped = g.dropped.saturating_add(1);
        }
    }

    fn wants_values(&self) -> bool {
        self.capture == ValueCapture::Record
    }
}

/// `run_once` の結果から記録を作る。`capture` のときだけ exit の値を載せる。
fn build_record(
    vcpu_id: u32,
    result: &Result<VcpuExit, MicrovmError>,
    elapsed: Duration,
    capture: bool,
) -> RunRecord {
    let outcome = match result {
        Ok(VcpuExit::Interrupted) => RunOutcome::Interrupted,
        Ok(e) => RunOutcome::Exit(exit_kind(e)),
        Err(e) if e.code() == MicrovmErrorCode::DeadlineExceeded => RunOutcome::DeadlineExceeded,
        Err(e) => RunOutcome::Error(e.code()),
    };
    let value = match result {
        Ok(e) if capture => ExitValue::from_exit(e),
        _ => None,
    };
    RunRecord {
        vcpu_id,
        outcome,
        elapsed,
        value,
    }
}

/// [`VcpuFd`] ごとの累積の実行統計（観測器が無くても取れる。REPAIR-4）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunStats {
    /// 発行回数。
    pub runs: u64,
    /// VM exit で戻った回数。
    pub exits: u64,
    /// 中断（EINTR / EAGAIN）の回数。
    pub interrupted: u64,
    /// 期限超過の回数。
    pub deadline_exceeded: u64,
    /// 失敗の回数。
    pub errors: u64,
    /// 所要時間の合計。
    pub total_elapsed: Duration,
}

fn exit_kind(e: &VcpuExit) -> &'static str {
    match e {
        VcpuExit::Io { .. } => "io",
        VcpuExit::Mmio { .. } => "mmio",
        VcpuExit::Hlt => "hlt",
        VcpuExit::Shutdown => "shutdown",
        VcpuExit::FailEntry { .. } => "fail_entry",
        VcpuExit::InternalError { .. } => "internal_error",
        VcpuExit::SystemEvent { .. } => "system_event",
        VcpuExit::Interrupted => "interrupted",
        VcpuExit::Other { .. } => "other",
    }
}

/// 期限監視スレッドが超過後に `kick`（シグナル）を繰り返す間隔。
const KICK_INTERVAL: Duration = Duration::from_millis(10);
/// `run_once` の期限の上限（異常な値で実質無期限になるのを防ぐ）。
pub const RUN_DEADLINE_MAX: Duration = Duration::from_secs(3600);

/// [`KvmDevice::probe_irqfd_vgic_order`] の結果（MVM-1・#3696）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrqfdVgicOrderProbe {
    /// vGIC の初期化前の irqfd 登録の失敗（コードとメッセージ）。成功してしまった場合は `None`。
    pub before_init: Option<(MicrovmErrorCode, String)>,
    /// vGIC の初期化後の irqfd 登録が成功したか。
    pub after_init_ok: bool,
}

/// [`KvmDevice::probe_guest_execution`] の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestExecutionProbe {
    /// 観測した VM exit（`Interrupted` を除く、起きた順）。期待は `[Io{Out, 0x10, 1, 1, [0x42]}, Hlt]`。
    pub exits: Vec<VcpuExit>,
    /// `KVM_RUN` が中断（EINTR / EAGAIN）で戻って再実行した回数。
    pub interrupted: u32,
}

/// [`KvmDevice::probe_exit_dispatch`] の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitDispatchProbe {
    /// 観測した VM exit（`Interrupted` を除く、起きた順）。
    pub exits: Vec<VcpuExit>,
    /// 記録用ポートデバイス（ポート 0x11 から）へ書かれた `(基底からのオフセット, 値)`。IN・MMIO read の
    /// 応答がゲストへ届いた証拠（ゲストが受け取った値をそのまま OUT する）。
    pub port_writes: Vec<(u16, u8)>,
}

/// [`KvmDevice::probe_queue_interrupt`] の結果（TASK-74.2.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueInterruptProbe {
    /// ゲストが準備完了を知らせた exit。期待は `Io{Out, 0x10, [0x42]}`（`QueueNotify` の書き込みは exit にならない）。
    pub ready_exit: VcpuExit,
    /// ioeventfd が数えた `QueueNotify` の回数。期待は 1。
    pub notify_count: u64,
    /// 割り込みを入れる前に `run_once` した結果（ゲストは HLT で待つため期待は `DeadlineExceeded`）。
    pub idle_outcome: MicrovmErrorCode,
    /// 割り込みを入れた後にゲストの ISR が知らせた exit。期待は `Io{Out, 0x13, [0xA5]}`。
    pub interrupt_exit: VcpuExit,
}

/// [`KvmDevice::probe_deadline_interrupt`] の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadlineProbe {
    /// vCPU の累積統計。
    pub stats: RunStats,
    /// 各 `run_once` の記録（起きた順）。
    pub records: Vec<RunRecord>,
    /// 診断中は呼び出しスレッドで `SIGUSR2` をブロックしており、戻った後にブロック状態が復元されていたか。
    pub kick_mask_restored: bool,
}

#[cfg(target_arch = "x86_64")]
#[derive(Debug, Default)]
struct CollectingObserver(std::sync::Mutex<Vec<RunRecord>>);

#[cfg(target_arch = "x86_64")]
impl RunObserver for CollectingObserver {
    fn record(&self, record: &RunRecord) {
        if let Ok(mut v) = self.0.lock() {
            v.push(*record);
        }
    }
}

/// 自己診断の `KVM_RUN` の最大発行回数（`Interrupted` の再実行を含む）。
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const PROBE_MAX_RUNS: usize = 8;

/// 自己診断の `KVM_RUN` 1 回の期限（超過は `DeadlineExceeded` で失敗。REPAIR-5）。
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
const PROBE_RUN_DEADLINE: Duration = Duration::from_secs(5);

/// `KVM_GET_VCPU_MMAP_SIZE` の上限（外部入力として検証する。実機は 12 KiB 程度）。
const VCPU_MMAP_MAX: usize = 1 << 20;

fn validate_mmap_size(n: usize) -> Result<usize, MicrovmError> {
    if !(exit::RUN_MIN_LEN..=VCPU_MMAP_MAX).contains(&n) || !n.is_multiple_of(sys::GUEST_PAGE_SIZE)
    {
        return Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            format!("unexpected KVM vCPU mmap size {n}"),
        ));
    }
    Ok(n)
}

/// `KVM_RUN` の errno の分類。EINTR / EAGAIN は正常系の [`VcpuExit::Interrupted`]。
fn classify_run_error(e: SysError) -> Result<VcpuExit, MicrovmError> {
    match e {
        SysError::Unsupported => Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        )),
        SysError::Os(EINTR) | SysError::Os(EAGAIN) => Ok(VcpuExit::Interrupted),
        SysError::Os(ENOTTY) => Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "not a KVM vCPU fd",
        )),
        SysError::Os(ENOEXEC) => Err(MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "vCPU not initialized",
        )),
        SysError::Os(ENOMEM) => Err(MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            "resource exhausted running vCPU",
        )),
        SysError::NullMapping => Err(MicrovmError::new(
            MicrovmErrorCode::Internal,
            "KVM_RUN failed (unexpected null mapping)",
        )),
        SysError::Os(n) => Err(MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("KVM_RUN failed (os error {n})"),
        )),
    }
}

impl VcpuFd {
    /// 作成時に指定した vCPU id。
    pub fn id(&self) -> u32 {
        self.id
    }

    /// ロード済みカーネルのエントリへ入る初期状態を設定する（TASK-75.3.2・MVM-1。x86_64 のみ。他 arch は `Unimplemented`）。
    ///
    /// `KVM_GET_SREGS` で現在値を読み、セグメント（CS = `__BOOT_CS`・DS/ES/FS/GS/SS = `__BOOT_DS`）・GDT・IDT・CR0/CR3/CR4/EFER
    /// だけを `state` で上書きして `KVM_SET_SREGS`、続けて `KVM_SET_REGS` で汎用レジスタを設定する。`tr`・`ldt`・`cr2`・`cr8`・
    /// `apic_base`・`interrupt_bitmap` は読んだ値のまま保つ。最初の [`VcpuFd::run_once`] より前に、BSP（vCPU 0）にだけ呼ぶ。
    /// GDT・ページテーブルなど `state` が指すゲストメモリの内容は呼び出し側が先に書く（`boot_x86::write_boot_tables`）。
    /// in-kernel irqchip のある VM の AP（vCPU 1 以上）は INIT/SIPI を待つため触らない。CPUID は [`VcpuFd::set_cpuid`]、MSR・FPU は [`VcpuFd::set_msrs`]・[`VcpuFd::set_fpu`]
    /// （`MicroVm::setup_boot_vcpu` が続けて呼ぶ）で別に設定する。LAPIC の LINT は [`VcpuFd::set_boot_lints`]（#3735）。
    #[cfg(target_arch = "x86_64")]
    pub fn set_boot_state(&mut self, state: &BootCpuState) -> Result<(), MicrovmError> {
        let fd = self.fd.as_fd();
        let mut sregs =
            sys::kvm_get_sregs(fd).map_err(|e| classify_vcpu_error(VcpuStage::GetSregs, e))?;
        let seg = |d: &SegmentDescriptor| sys::KvmSegment {
            base: d.base,
            limit: d.limit,
            selector: d.selector,
            type_: d.type_,
            present: u8::from(d.present),
            dpl: d.dpl,
            db: u8::from(d.db),
            s: u8::from(d.s),
            l: u8::from(d.l),
            g: u8::from(d.g),
            avl: u8::from(d.avl),
            unusable: 0,
            padding: 0,
        };
        sregs.cs = seg(&state.code_segment);
        sregs.ds = seg(&state.data_segment);
        sregs.es = seg(&state.data_segment);
        sregs.fs = seg(&state.data_segment);
        sregs.gs = seg(&state.data_segment);
        sregs.ss = seg(&state.data_segment);
        sregs.gdt = sys::KvmDtable {
            base: state.gdt.base,
            limit: state.gdt.limit,
            padding: [0; 3],
        };
        sregs.idt = sys::KvmDtable {
            base: state.idt.base,
            limit: state.idt.limit,
            padding: [0; 3],
        };
        sregs.cr0 = state.cr0;
        sregs.cr3 = state.cr3;
        sregs.cr4 = state.cr4;
        sregs.efer = state.efer;
        sys::kvm_set_sregs(fd, &sregs).map_err(|e| classify_vcpu_error(VcpuStage::SetSregs, e))?;
        let r = &state.regs;
        let regs = sys::KvmRegs {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rsp: r.rsp,
            rbp: r.rbp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
            rflags: r.rflags,
        };
        sys::kvm_set_regs(fd, &regs).map_err(|e| classify_vcpu_error(VcpuStage::SetRegs, e))
    }

    /// MSR を `KVM_SET_MSRS` で書く（#3734・MVM-1。x86_64 のみ）。`MicroVm::setup_boot_vcpu` が [`crate::boot_x86::boot_msrs`] を渡す。
    ///
    /// 255 件超は確保の前に `InvalidArgument`。カーネルは途中の MSR で止まると処理できた件数だけを返し errno を出さないため、
    /// 件数が要求と食い違えば `FailedPrecondition` にする（一部だけ設定された状態を成功にしない）。message に MSR の値は載せない（ERR-1）。
    #[cfg(target_arch = "x86_64")]
    pub fn set_msrs(&mut self, entries: &[X86MsrEntry]) -> Result<(), MicrovmError> {
        check_msr_count(entries.len())?;
        let raw: Vec<sys::KvmMsrEntry> = entries
            .iter()
            .map(|e| sys::KvmMsrEntry {
                index: e.index,
                reserved: 0,
                data: e.data,
            })
            .collect();
        let n = sys::kvm_set_msrs(self.fd.as_fd(), &raw)
            .map_err(|e| classify_vcpu_error(VcpuStage::SetMsrs, e))?;
        check_msr_done("KVM_SET_MSRS", n, raw.len())
    }

    /// `indices` の MSR を `KVM_GET_MSRS` で読む（観測用。#3734・MVM-1。x86_64 のみ）。件数の扱いは [`VcpuFd::set_msrs`] と同じ。
    #[cfg(target_arch = "x86_64")]
    pub fn msrs(&self, indices: &[u32]) -> Result<Vec<X86MsrEntry>, MicrovmError> {
        check_msr_count(indices.len())?;
        let mut raw: Vec<sys::KvmMsrEntry> = indices
            .iter()
            .map(|&index| sys::KvmMsrEntry {
                index,
                reserved: 0,
                data: 0,
            })
            .collect();
        let n = sys::kvm_get_msrs(self.fd.as_fd(), &mut raw)
            .map_err(|e| classify_vcpu_error(VcpuStage::GetMsrs, e))?;
        check_msr_done("KVM_GET_MSRS", n, raw.len())?;
        Ok(raw
            .iter()
            .map(|e| X86MsrEntry::new(e.index, e.data))
            .collect())
    }

    /// FPU 状態を `KVM_SET_FPU` で書く（#3734・MVM-1。x86_64 のみ）。`fpr`・`xmm` は 0。
    #[cfg(target_arch = "x86_64")]
    pub fn set_fpu(&mut self, fpu: &X86FpuState) -> Result<(), MicrovmError> {
        let raw = sys::KvmFpu {
            fcw: fpu.fcw,
            fsw: fpu.fsw,
            ftwx: fpu.ftwx,
            last_opcode: fpu.last_opcode,
            last_ip: fpu.last_ip,
            last_dp: fpu.last_dp,
            mxcsr: fpu.mxcsr,
            ..sys::KvmFpu::default()
        };
        sys::kvm_set_fpu(self.fd.as_fd(), &raw)
            .map_err(|e| classify_vcpu_error(VcpuStage::SetFpu, e))
    }

    /// FPU 状態を `KVM_GET_FPU` で読む（観測用。#3734・MVM-1。x86_64 のみ）。`fpr`・`xmm` は捨てる。
    #[cfg(target_arch = "x86_64")]
    pub fn fpu(&self) -> Result<X86FpuState, MicrovmError> {
        let r = sys::kvm_get_fpu(self.fd.as_fd())
            .map_err(|e| classify_vcpu_error(VcpuStage::GetFpu, e))?;
        Ok(X86FpuState {
            fcw: r.fcw,
            fsw: r.fsw,
            ftwx: r.ftwx,
            last_opcode: r.last_opcode,
            last_ip: r.last_ip,
            last_dp: r.last_dp,
            mxcsr: r.mxcsr,
        })
    }

    /// vCPU の CPUID を設定する（`KVM_SET_CPUID2`。#3733・MVM-1。x86_64 のみ。他 arch は `Unimplemented`）。
    ///
    /// 最初の [`VcpuFd::run_once`] と `set_boot_state` より前に呼ぶ（`microvm::MicroVm::assemble` が vCPU 作成直後に呼ぶ）。
    /// 表は `CpuidTable::for_vcpu` で vCPU ごとに調整したものを渡す。
    #[cfg(target_arch = "x86_64")]
    pub fn set_cpuid(&mut self, table: &CpuidTable) -> Result<(), MicrovmError> {
        let entries: Vec<sys::KvmCpuidEntry2> = table
            .entries()
            .iter()
            .map(|e| sys::KvmCpuidEntry2 {
                function: e.function,
                index: e.index,
                flags: e.flags,
                eax: e.eax,
                ebx: e.ebx,
                ecx: e.ecx,
                edx: e.edx,
                padding: [0; 3],
            })
            .collect();
        sys::kvm_set_cpuid2(self.fd.as_fd(), &entries)
            .map_err(|e| classify_vcpu_error(VcpuStage::SetCpuid, e))
    }

    /// x86_64 以外では CPUID の設定は未実装（REPAIR-3）。
    #[cfg(not(target_arch = "x86_64"))]
    pub fn set_cpuid(&mut self, _table: &CpuidTable) -> Result<(), MicrovmError> {
        Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "CPUID setup is only implemented for x86_64",
        ))
    }

    /// aarch64 の起動レジスタ（X0〜X3・PSTATE・PC）を `KVM_SET_ONE_REG` で設定する（MVM-1・#3696。aarch64 のみ）。
    ///
    /// 値は `boot_arm64::ArmBootState`（Image のエントリ・FDT の GPA・EL1h で DAIF マスク）。最初の `run_once` より前に
    /// vCPU 0 にだけ呼ぶ。`SCTLR_EL1`（MMU・D-cache off）は `KVM_ARM_VCPU_INIT` のリセット値に依存し、本メソッドは書かない
    /// （確認は範囲外。REPAIR-3）。AP の起動（PSCI CPU_ON・`KVM_ARM_VCPU_POWER_OFF`）は #3899。
    #[cfg(target_arch = "aarch64")]
    pub fn set_arm64_boot_state(&mut self, s: &ArmBootState) -> Result<(), MicrovmError> {
        let fd = self.fd.as_fd();
        let set = |id: u64, v: u64| {
            sys::kvm_set_one_reg_u64(fd, id, v)
                .map_err(|e| classify_vcpu_error(VcpuStage::SetOneReg, e))
        };
        for (n, v) in [(0u64, s.x0), (1, s.x1), (2, s.x2), (3, s.x3)] {
            let id = sys::arm64_reg_x(n).ok_or_else(|| {
                MicrovmError::new(MicrovmErrorCode::Internal, "register index out of range")
            })?;
            set(id, v)?;
        }
        set(sys::ARM64_REG_PSTATE, s.cpsr)?;
        set(sys::ARM64_REG_PC, s.pc)
    }

    /// aarch64 の起動レジスタ（X0〜X3・PSTATE・PC）を `KVM_GET_ONE_REG` で読み戻す（観測・照合用。aarch64 のみ）。
    #[cfg(target_arch = "aarch64")]
    pub fn arm64_boot_regs(&self) -> Result<ArmBootState, MicrovmError> {
        let fd = self.fd.as_fd();
        let get = |id: u64| {
            sys::kvm_get_one_reg_u64(fd, id)
                .map_err(|e| classify_vcpu_error(VcpuStage::GetOneReg, e))
        };
        let x = |n: u64| {
            sys::arm64_reg_x(n).ok_or_else(|| {
                MicrovmError::new(MicrovmErrorCode::Internal, "register index out of range")
            })
        };
        Ok(ArmBootState {
            pc: get(sys::ARM64_REG_PC)?,
            x0: get(x(0)?)?,
            x1: get(x(1)?)?,
            x2: get(x(2)?)?,
            x3: get(x(3)?)?,
            cpsr: get(sys::ARM64_REG_PSTATE)?,
        })
    }

    /// x86_64 以外では x86 の起動レジスタ初期化（`BootCpuState`）は使えない。aarch64 は `set_arm64_boot_state`（#3696）。
    #[cfg(not(target_arch = "x86_64"))]
    pub fn set_boot_state(&mut self, _state: &BootCpuState) -> Result<(), MicrovmError> {
        Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "boot register setup is only implemented for x86_64",
        ))
    }

    /// 汎用レジスタの現在値を読む（観測用。TASK-75.3.2。x86_64 のみ）。
    ///
    /// `KVM_RUN` の実行中には呼べない: 実行は `&mut self` の [`VcpuFd::run_once`] だけが行い、本メソッドは `&self` のため
    /// 借用規則で排他される。VM exit の直後の値を読む用途（試験・診断）を想定する。
    #[cfg(target_arch = "x86_64")]
    pub fn regs(&self) -> Result<X86Regs, MicrovmError> {
        let r = sys::kvm_get_regs(self.fd.as_fd())
            .map_err(|e| classify_vcpu_error(VcpuStage::GetRegs, e))?;
        Ok(X86Regs {
            rax: r.rax,
            rbx: r.rbx,
            rcx: r.rcx,
            rdx: r.rdx,
            rsi: r.rsi,
            rdi: r.rdi,
            rsp: r.rsp,
            rbp: r.rbp,
            r8: r.r8,
            r9: r.r9,
            r10: r.r10,
            r11: r.r11,
            r12: r.r12,
            r13: r.r13,
            r14: r.r14,
            r15: r.r15,
            rip: r.rip,
            rflags: r.rflags,
        })
    }

    /// BSP の LAPIC の LVT LINT0 を ExtINT、LINT1 を NMI（ともにマスク解除）にして `KVM_SET_LAPIC` で書き戻す（#3735・MVM-1。
    /// x86_64 のみ）。設定後の LINT の値を返す。
    ///
    /// `MicroVm::setup_boot_vcpu` が全 vCPU に呼ぶ（BSP と同じ経路。#3737）。PIC 経由の virtual wire mode（MP 仕様 1.4）でカーネルを起動する前提で、
    /// マスクも解除する理由は `lapic_x86` モジュールを参照。in-kernel irqchip が前提で、無い VM では `FailedPrecondition`。
    /// AP にも同じ値を書けるが、INIT で LVT がマスクへ戻るため設定が残るのは INIT までである（#3737）。
    /// エラー message にレジスタ値は載せない（ERR-1）。
    #[cfg(target_arch = "x86_64")]
    pub fn set_boot_lints(&mut self) -> Result<crate::lapic_x86::LapicLints, MicrovmError> {
        let fd = self.fd.as_fd();
        let mut state =
            sys::kvm_get_lapic(fd).map_err(|e| classify_vcpu_error(VcpuStage::GetLapic, e))?;
        let lints = crate::lapic_x86::apply_boot_lints(&mut state.regs)?;
        sys::kvm_set_lapic(fd, &state).map_err(|e| classify_vcpu_error(VcpuStage::SetLapic, e))?;
        Ok(lints)
    }

    /// LAPIC の LVT LINT0 / LINT1 の現在値を読む（観測用。#3735。x86_64 のみ）。
    ///
    /// [`VcpuFd::regs`] と同じく `&self` で、`run_once`（`&mut self`）とは借用規則で排他される。
    #[cfg(target_arch = "x86_64")]
    pub fn lapic_lints(&self) -> Result<crate::lapic_x86::LapicLints, MicrovmError> {
        let state = sys::kvm_get_lapic(self.fd.as_fd())
            .map_err(|e| classify_vcpu_error(VcpuStage::GetLapic, e))?;
        crate::lapic_x86::LapicLints::from_regs(&state.regs).ok_or_else(|| {
            MicrovmError::new(
                MicrovmErrorCode::Internal,
                "LAPIC register page is too short for LVT LINT0/LINT1",
            )
        })
    }

    /// vCPU の MP 状態を読む（`KVM_GET_MP_STATE`。#3737・MVM-1。x86_64 のみ）。AP は作成直後 `Uninitialized`。
    ///
    /// `&self` のため `run_once`（`&mut self`）とは借用規則で排他される。in-kernel LAPIC では保留中の INIT/SIPI を先に処理する。
    #[cfg(target_arch = "x86_64")]
    pub fn mp_state(&self) -> Result<crate::smp_x86::MpState, MicrovmError> {
        let st = sys::kvm_get_mp_state(self.fd.as_fd())
            .map_err(|e| classify_vcpu_error(VcpuStage::GetMpState, e))?;
        Ok(crate::smp_x86::MpState::from_raw(st.mp_state))
    }

    /// vCPU の MP 状態を設定する（`KVM_SET_MP_STATE`。#3737。x86_64 のみ）。`MicroVm::assemble` が AP を明示的に
    /// `Uninitialized` にするために呼ぶ。
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn set_mp_state(
        &mut self,
        state: crate::smp_x86::MpState,
    ) -> Result<(), MicrovmError> {
        let st = sys::KvmMpState {
            mp_state: state.as_raw(),
        };
        sys::kvm_set_mp_state(self.fd.as_fd(), &st)
            .map_err(|e| classify_vcpu_error(VcpuStage::SetMpState, e))
    }

    /// x86_64 以外では MP 状態の読み取りは未実装（REPAIR-3）。
    #[cfg(not(target_arch = "x86_64"))]
    pub fn mp_state(&self) -> Result<crate::smp_x86::MpState, MicrovmError> {
        Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "MP state is only implemented for x86_64",
        ))
    }

    /// 累積の実行統計。
    pub fn stats(&self) -> RunStats {
        self.stats
    }

    /// 実行結果の記録器を接続する（以後の `run_once` ごとに呼ばれる。REPAIR-4）。
    pub fn set_observer(&mut self, observer: Arc<dyn RunObserver>) {
        self.observer = Some(observer);
    }

    /// `KVM_RUN` を 1 回発行し、戻った理由（VM exit）を返す。ループは呼び出し側が組む。
    ///
    /// # プロセス全体への影響（SIGUSR2）
    /// 初回の呼び出しで `SIGUSR2` に何もしない handler を入れ、プロセス全体の設定として元へ戻さない。
    /// 本 crate を組み込むプロセスは `SIGUSR2` を他の用途に使わないこと（既存の別 handler・SIG_IGN があれば
    /// 上書きせず `FailedPrecondition` で失敗する。crate doc 参照）。
    ///
    /// `timeout` を超えてもゲストが exit しないときは、別スレッドが `kvm_run.immediate_exit` を立てて
    /// 呼び出しスレッドへ `SIGUSR2` を送り（何もしない handler を `sigaction` で入れる。既存の別 handler があれば
    /// 失敗にする）、`KVM_RUN` を中断して `DeadlineExceeded` を返す（REPAIR-5）。監視スレッドは戻る前に
    /// 必ず join し、`immediate_exit` は下ろす。`timeout` は 0 より大きく [`RUN_DEADLINE_MAX`] 以下。
    /// EINTR / EAGAIN は [`VcpuExit::Interrupted`]（再実行できる）。exit のデバイスへの振り分けと
    /// IN・MMIO 読み出しの応答の書き戻しは [`VcpuFd::handle_exit`] が担う（次の `run_once` の前に呼ぶ）。結果と所要時間は統計と記録器へ残す（REPAIR-4）。
    pub fn run_once(&mut self, timeout: Duration) -> Result<VcpuExit, MicrovmError> {
        // 公開 API には停止要求の経路が無い（要求されることのないローカルの信号を渡す）。
        self.run_once_inner(timeout, &StopSignal::new())
    }

    /// [`VcpuFd::run_once`] に外部からの停止要求（[`StopSignal`]）を加えたもの。`RunningMicroVm` の vCPU ループが使う
    /// （#3736・MVM-1・REPAIR-5）。要求されると `KVM_RUN` を中断して `Interrupted` で戻る（呼び出し側が信号を確認する）。
    pub(crate) fn run_once_with_stop(
        &mut self,
        timeout: Duration,
        signal: &StopSignal,
    ) -> Result<VcpuExit, MicrovmError> {
        self.run_once_inner(timeout, signal)
    }

    fn run_once_inner(
        &mut self,
        timeout: Duration,
        signal: &StopSignal,
    ) -> Result<VcpuExit, MicrovmError> {
        let start = Instant::now();
        let result = self.run_bounded(timeout, signal);
        let elapsed = start.elapsed();
        let capture = self.observer.as_ref().is_some_and(|o| o.wants_values());
        let rec = build_record(self.id, &result, elapsed, capture);
        self.stats.runs += 1;
        self.stats.total_elapsed = self.stats.total_elapsed.saturating_add(elapsed);
        match rec.outcome {
            RunOutcome::Exit(_) => self.stats.exits += 1,
            RunOutcome::Interrupted => self.stats.interrupted += 1,
            RunOutcome::DeadlineExceeded => self.stats.deadline_exceeded += 1,
            RunOutcome::Error(_) => self.stats.errors += 1,
        }
        if let Some(o) = &self.observer {
            o.record(&rec);
        }
        result
    }

    /// `run_once` が返した `exit`（`Io` / `Mmio`）を `dispatcher` の該当デバイスへ振り分け、ゲストの読み出し
    /// （IN・MMIO read）の応答があれば `kvm_run` 領域へ書き戻す（TASK-74.4.2・MVM-1）。
    ///
    /// 読み出しは書き戻さないと次の `KVM_RUN` で命令が完了しないため、ループは
    /// `run_once` → `handle_exit` → `run_once` の順で組む。`exit` は直前の `run_once` の戻り値でなければならず、
    /// dispatch の前に領域の現在の exit（アドレス / ポート・幅・回数・向き・書き込みデータ）と照合し、食い違えばデバイスにも領域にも触れず `Internal`（fail-closed）。`Io` / `Mmio` 以外の exit は `InvalidArgument`。
    /// どのデバイスにも当たらないアクセスはエラーにせず `DispatchOutcome::Unhandled`（読み出しは 0xFF 埋め）で返す。
    pub fn handle_exit(
        &mut self,
        exit: &VcpuExit,
        dispatcher: &mut ExitDispatcher,
    ) -> Result<DispatchOutcome, MicrovmError> {
        exit::ensure_exit_matches_area(&self.run, exit)?;
        let outcome = dispatcher.dispatch(exit)?;
        if let Some(response) = outcome.read_response() {
            match exit {
                VcpuExit::Io { .. } => exit::complete_io_in(&mut self.run, response)?,
                VcpuExit::Mmio { .. } => exit::complete_mmio_read(&mut self.run, response)?,
                _ => {}
            }
        }
        Ok(outcome)
    }

    fn run_bounded(
        &mut self,
        timeout: Duration,
        signal: &StopSignal,
    ) -> Result<VcpuExit, MicrovmError> {
        if timeout.is_zero() || timeout > RUN_DEADLINE_MAX {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "KVM_RUN deadline out of range",
            ));
        }
        sys::install_kick_handler().map_err(|e| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::NullMapping => MicrovmError::new(
                MicrovmErrorCode::Internal,
                "cannot install vCPU kick handler (unexpected null mapping)",
            ),
            SysError::Os(n) => MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                format!("cannot install vCPU kick handler (os error {n})"),
            ),
        })?;
        // 呼び出しスレッドが SIGUSR2 をブロックしていても中断が届くよう、実行中だけ解除する（drop で復元）。
        let _unblocked = sys::KickUnblocked::new().map_err(|e| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::NullMapping => MicrovmError::new(
                MicrovmErrorCode::Internal,
                "cannot unblock vCPU kick signal (unexpected null mapping)",
            ),
            SysError::Os(n) => MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                format!("cannot unblock vCPU kick signal (os error {n})"),
            ),
        })?;
        // 要求済みなら `KVM_RUN` を発行せず戻る（ループ先頭の確認と run の開始の間に来た要求を即時に処理する）。
        if signal.is_requested() {
            return Ok(VcpuExit::Interrupted);
        }
        // `target` は closure の中でだけ使え、vCPU スレッドが生存中であることを型が保証する（sys::KickTarget）。
        // kick を出すのはこの scope の監視スレッドだけで、`KVM_RUN` 1 回分の間しか生きない。
        let timed_out = AtomicBool::new(false);
        let fired = AtomicBool::new(false);
        let run_done = AtomicBool::new(false);
        let run = &self.run;
        let fd = self.fd.as_fd();
        let timed_out_ref = &timed_out;
        let fired_ref = &fired;
        let run_done_ref = &run_done;
        let outcome = sys::with_current_thread(|target| {
            std::thread::scope(|scope| {
                let watchdog = std::thread::Builder::new()
                    .name("kvm-run-deadline".into())
                    .spawn_scoped(scope, move || {
                        let o = watch_run(
                            signal,
                            run_done_ref,
                            timeout,
                            |on| {
                                let _ = run.set_immediate_exit(on);
                            },
                            || {
                                let _ = target.kick();
                            },
                        );
                        match o {
                            WatchOutcome::Finished => {}
                            WatchOutcome::TimedOut => {
                                timed_out_ref.store(true, Ordering::SeqCst);
                                fired_ref.store(true, Ordering::SeqCst);
                            }
                            WatchOutcome::Stopped => fired_ref.store(true, Ordering::SeqCst),
                        }
                    })
                    .map_err(|_| {
                        MicrovmError::new(
                            MicrovmErrorCode::ResourceExhausted,
                            "cannot spawn KVM_RUN deadline thread",
                        )
                    })?;
                let r = sys::kvm_run(fd);
                run_done.store(true, Ordering::SeqCst);
                signal.notify();
                let _ = watchdog.join();
                Ok::<_, MicrovmError>(r)
            })
        })?;
        let expired = timed_out.load(Ordering::SeqCst);
        if fired.load(Ordering::SeqCst) {
            // 監視スレッドは join 済み。次回の実行を妨げないよう下ろす（期限切れ・停止要求のどちらでも）。
            let _ = self.run.set_immediate_exit(false);
        }
        match outcome {
            Ok(()) => exit::decode_exit(&self.run),
            Err(e) => match classify_run_error(e) {
                Ok(VcpuExit::Interrupted) if expired => Err(MicrovmError::new(
                    MicrovmErrorCode::DeadlineExceeded,
                    "KVM_RUN deadline exceeded",
                )),
                other => other,
            },
        }
    }
}

/// 外部（`RunningMicroVm::stop` / drop）から vCPU の `KVM_RUN` へ停止を伝える信号（#3736・MVM-1・REPAIR-5）。
///
/// 所有関係: `RunningMicroVm` と vCPU ループが持つのはこの `Arc<StopSignal>` だけで、スレッド識別子は持たない。
/// [`StopSignal::request`] は状態の更新と condvar の通知だけを行い、シグナルは送らない。kick（`SIGUSR2`）を出すのは
/// `run_bounded` の `with_current_thread` の中で生きている監視スレッドだけで、そのスレッドは `KVM_RUN` 1 回分の間だけ生き、
/// join されてから `with_current_thread` が戻る。したがって vCPU スレッドが終わった後に `request` が呼ばれても
/// `pthread_kill` は発行されず、終了したスレッドへの送信も tid の再利用も構造上起きない。
/// 全 vCPU スレッドが同じ信号を共有する（#3738。run ごとの完了状態は共有せず、`run_bounded` のローカルに置く）。
#[derive(Debug, Default)]
pub(crate) struct StopSignal {
    requested: Mutex<bool>,
    cv: Condvar,
}

impl StopSignal {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 停止を要求して待ち手をすべて起こす。何度呼んでもよい。
    pub(crate) fn request(&self) {
        *self.requested.lock().unwrap_or_else(|p| p.into_inner()) = true;
        self.cv.notify_all();
    }

    pub(crate) fn is_requested(&self) -> bool {
        *self.requested.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// 停止が要求されるか `timeout` が経つまで待つ。要求済み（待ちの途中での要求を含む）なら `true`、期限切れなら `false`。
    /// 受信ポーラーの周期待ちが使う（#3742・REPAIR-5）。spurious wakeup は残り時間を計算し直して吸収する。
    pub(crate) fn wait_requested(&self, timeout: Duration) -> bool {
        let limit = Instant::now() + timeout;
        let mut g = self.requested.lock().unwrap_or_else(|p| p.into_inner());
        while !*g {
            let left = limit.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            g = self
                .cv
                .wait_timeout(g, left)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        true
    }

    /// run の完了を待ち手へ知らせる。ロックを一度取って放すことで、待ち手の条件確認と待ち入りの間の通知の取りこぼしを防ぐ。
    fn notify(&self) {
        drop(self.requested.lock().unwrap_or_else(|p| p.into_inner()));
        self.cv.notify_all();
    }
}

/// 監視スレッドの結末。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchOutcome {
    /// run が先に終わった（kick も `immediate_exit` も使っていない）。
    Finished,
    /// 期限に達した。
    TimedOut,
    /// 外部から停止が要求された。
    Stopped,
}

/// `run_bounded` の監視スレッドの本体。KVM なしで試験できるよう、副作用（`immediate_exit` の設定と kick）は
/// クロージャで受ける。run の完了（`run_done`）を観測した後は一度も kick しない（#3736・REPAIR-5）。
fn watch_run(
    signal: &StopSignal,
    run_done: &AtomicBool,
    timeout: Duration,
    set_exit: impl Fn(bool),
    mut kick: impl FnMut(),
) -> WatchOutcome {
    let deadline = Instant::now() + timeout;
    let mut guard = signal.requested.lock().unwrap_or_else(|p| p.into_inner());
    let outcome = loop {
        if run_done.load(Ordering::SeqCst) {
            return WatchOutcome::Finished;
        }
        if *guard {
            break WatchOutcome::Stopped;
        }
        let now = Instant::now();
        if now >= deadline {
            break WatchOutcome::TimedOut;
        }
        guard = signal
            .cv
            .wait_timeout(guard, deadline - now)
            .unwrap_or_else(|p| p.into_inner())
            .0;
    };
    drop(guard);
    set_exit(true);
    // シグナルが ioctl 突入前に届いても immediate_exit が効くが、取りこぼしに備えて run の完了まで繰り返す。
    while !run_done.load(Ordering::SeqCst) {
        kick();
        let mut g = signal.requested.lock().unwrap_or_else(|p| p.into_inner());
        if run_done.load(Ordering::SeqCst) {
            break;
        }
        g = signal
            .cv
            .wait_timeout(g, KICK_INTERVAL)
            .unwrap_or_else(|p| p.into_inner())
            .0;
        drop(g);
    }
    outcome
}

impl AsFd for VcpuFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// MSR の件数を確保の前に検証する（`sys::consts::MAX_MSR_ENTRIES` と同じ 255 件が上限）。
#[cfg(target_arch = "x86_64")]
fn check_msr_count(len: usize) -> Result<(), MicrovmError> {
    if len > sys::consts::MAX_MSR_ENTRIES {
        return Err(MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "too many MSR entries",
        ));
    }
    Ok(())
}

/// カーネルが処理できた MSR の件数が要求と一致するかを確かめる（一部だけ受理された場合は失敗）。
#[cfg(target_arch = "x86_64")]
fn check_msr_done(name: &str, done: usize, requested: usize) -> Result<(), MicrovmError> {
    if done == requested {
        return Ok(());
    }
    Err(MicrovmError::new(
        MicrovmErrorCode::FailedPrecondition,
        format!("{name} accepted {done} of {requested} entries"),
    ))
}

/// vCPU 作成の段（errno 分類のメッセージ切り替え用）。`PreferredTarget`・`VcpuInit` は aarch64 だけが使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
enum VcpuStage {
    Create,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    GetRegs,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    SetRegs,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    GetSregs,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    SetSregs,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    GetMsrs,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    SetMsrs,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    GetFpu,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    SetFpu,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    GetLapic,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    SetLapic,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    SetCpuid,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    GetMpState,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    SetMpState,
    PreferredTarget,
    VcpuInit,
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    GetOneReg,
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    SetOneReg,
    Mmap,
}

fn classify_vcpu_error(stage: VcpuStage, e: SysError) -> MicrovmError {
    let name = match stage {
        VcpuStage::Create => "KVM_CREATE_VCPU",
        VcpuStage::PreferredTarget => "KVM_ARM_PREFERRED_TARGET",
        VcpuStage::VcpuInit => "KVM_ARM_VCPU_INIT",
        VcpuStage::GetOneReg => "KVM_GET_ONE_REG",
        VcpuStage::SetOneReg => "KVM_SET_ONE_REG",
        VcpuStage::Mmap => "mmap of kvm_run",
        VcpuStage::GetRegs => "KVM_GET_REGS",
        VcpuStage::SetRegs => "KVM_SET_REGS",
        VcpuStage::GetSregs => "KVM_GET_SREGS",
        VcpuStage::SetSregs => "KVM_SET_SREGS",
        VcpuStage::GetMsrs => "KVM_GET_MSRS",
        VcpuStage::SetMsrs => "KVM_SET_MSRS",
        VcpuStage::GetFpu => "KVM_GET_FPU",
        VcpuStage::SetFpu => "KVM_SET_FPU",
        VcpuStage::GetLapic => "KVM_GET_LAPIC",
        VcpuStage::SetLapic => "KVM_SET_LAPIC",
        VcpuStage::SetCpuid => "KVM_SET_CPUID2",
        VcpuStage::GetMpState => "KVM_GET_MP_STATE",
        VcpuStage::SetMpState => "KVM_SET_MP_STATE",
    };
    let registers = matches!(
        stage,
        VcpuStage::GetRegs
            | VcpuStage::SetRegs
            | VcpuStage::GetSregs
            | VcpuStage::SetSregs
            | VcpuStage::GetMsrs
            | VcpuStage::SetMsrs
            | VcpuStage::GetFpu
            | VcpuStage::SetFpu
            | VcpuStage::SetLapic
            | VcpuStage::GetOneReg
            | VcpuStage::SetOneReg
    );
    let msrs = matches!(stage, VcpuStage::GetMsrs | VcpuStage::SetMsrs);
    match e {
        SysError::Unsupported => MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        ),
        SysError::Os(EINVAL) if stage == VcpuStage::Create => {
            MicrovmError::new(MicrovmErrorCode::InvalidArgument, "invalid vCPU id")
        }
        // in-kernel irqchip が無い VM の LAPIC 読み取り（BSP の LINT 設定の前提違反）。
        SysError::Os(EINVAL) if stage == VcpuStage::GetLapic => MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "KVM_GET_LAPIC requires an in-kernel irqchip",
        ),
        // レジスタ値の拒否。値・アドレスは message に載せない（ERR-1）。
        SysError::Os(EINVAL) if registers => MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "KVM rejected the vCPU registers",
        ),
        SysError::Os(E2BIG) if msrs => {
            MicrovmError::new(MicrovmErrorCode::InvalidArgument, "too many MSR entries")
        }
        // CPUID の拒否（実行開始後の変更を含む）。値は message に載せない（ERR-1）。
        SysError::Os(EINVAL) if stage == VcpuStage::SetCpuid => MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "KVM rejected the CPUID table (it must be set before the vCPU runs)",
        ),
        SysError::Os(E2BIG) if stage == VcpuStage::SetCpuid => {
            MicrovmError::new(MicrovmErrorCode::InvalidArgument, "too many CPUID entries")
        }
        SysError::Os(EEXIST) => {
            MicrovmError::new(MicrovmErrorCode::AlreadyExists, "vCPU id already exists")
        }
        SysError::Os(ENOTTY) => {
            MicrovmError::new(MicrovmErrorCode::FailedPrecondition, "not a KVM VM fd")
        }
        SysError::Os(n) if n == EACCES || n == EPERM => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            "permission denied creating vCPU",
        ),
        SysError::Os(n) if n == ENOMEM || n == EMFILE || n == ENFILE => MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            format!("resource exhausted creating vCPU (os error {n})"),
        ),
        // mmap が NULL を返した（`VcpuStage::Mmap` だけで起きる。マッピングは sys 側で munmap 済み）。
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

/// 割り込み通知の設定の段（errno 分類のメッセージ切り替え用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IrqStage {
    CheckExtension,
    CreateIrqchip,
    /// `KVM_CREATE_DEVICE`（aarch64 の vGICv3。#3696）。
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    CreateDevice,
    /// `KVM_SET_DEVICE_ATTR`（vGIC のアドレス・初期化。#3696）。
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    SetDeviceAttr,
    /// `KVM_GET_DEVICE_ATTR`（vGIC の観測。#3696）。
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    GetDeviceAttr,
    Irqfd,
    Ioeventfd,
    /// `KVM_IRQ_LINE`（#3918）。x86_64 の COM1 の level 線。
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    IrqLine,
}

fn classify_irq_error(stage: IrqStage, e: SysError) -> MicrovmError {
    let name = match stage {
        IrqStage::CheckExtension => "KVM_CHECK_EXTENSION",
        IrqStage::CreateIrqchip => "KVM_CREATE_IRQCHIP",
        IrqStage::CreateDevice => "KVM_CREATE_DEVICE",
        IrqStage::SetDeviceAttr => "KVM_SET_DEVICE_ATTR",
        IrqStage::GetDeviceAttr => "KVM_GET_DEVICE_ATTR",
        IrqStage::Irqfd => "KVM_IRQFD",
        IrqStage::Ioeventfd => "KVM_IOEVENTFD",
        IrqStage::IrqLine => "KVM_IRQ_LINE",
    };
    match e {
        SysError::Unsupported => MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        ),
        SysError::Os(ENOTTY) => {
            MicrovmError::new(MicrovmErrorCode::FailedPrecondition, "not a KVM VM fd")
        }
        // vGIC（#3696）。ホストが GICv3 を持たない場合は ENODEV（GICv2 のみのホスト等）。
        SysError::Os(ENODEV) if stage == IrqStage::CreateDevice => MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "the host does not provide an in-kernel GICv3",
        ),
        // 初期化済み・vCPU が実行済みの vGIC へのアドレス設定や、実行中の vCPU がある状態の観測は EBUSY。
        SysError::Os(EBUSY)
            if matches!(stage, IrqStage::SetDeviceAttr | IrqStage::GetDeviceAttr) =>
        {
            MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "the vGIC is busy (already initialized, or a vCPU has run)",
            )
        }
        // アドレスの重複設定は EEXIST。
        SysError::Os(EEXIST) if stage == IrqStage::SetDeviceAttr => MicrovmError::new(
            MicrovmErrorCode::AlreadyExists,
            "KVM_SET_DEVICE_ATTR: address already set",
        ),
        // アドレス・サイズ・vCPU 数の不整合（重なり・整列違反・redistributor が vCPU 数に足りない等）。
        SysError::Os(EINVAL) if stage == IrqStage::SetDeviceAttr => MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "KVM rejected the vGIC address or state",
        ),
        // 未対応の属性（ENXIO）・観測の引数不整合。
        SysError::Os(n) if (n == ENXIO || n == EINVAL) && stage == IrqStage::GetDeviceAttr => {
            MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "KVM_GET_DEVICE_ATTR rejected the attribute (vGIC not ready or unsupported)",
            )
        }
        SysError::Os(EEXIST) | SysError::Os(EBUSY) => MicrovmError::new(
            MicrovmErrorCode::AlreadyExists,
            format!("{name}: already registered"),
        ),
        // irqchip の作成は vCPU より前でなければならず、irqfd は irqchip が無いと EINVAL になる。
        SysError::Os(EINVAL) if stage == IrqStage::CreateIrqchip => MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "KVM_CREATE_IRQCHIP must run before any vCPU is created",
        ),
        // irqchip が無い VM fd への KVM_IRQ_LINE は ENXIO（`kvm_vm_ioctl_irq_line` 前の `irqchip_in_kernel` 検査）。
        SysError::Os(ENXIO) if stage == IrqStage::IrqLine => MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "KVM_IRQ_LINE requires an in-kernel irqchip",
        ),
        SysError::Os(EINVAL) if stage == IrqStage::Irqfd => MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "KVM_IRQFD rejected (no irqchip or invalid GSI)",
        ),
        // aarch64 は vGIC の初期化前の irqfd が EAGAIN（`kvm_arch_intc_initialized()` が偽。#3696）。
        SysError::Os(EAGAIN) if stage == IrqStage::Irqfd => MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "KVM_IRQFD requires an initialized interrupt controller (vGIC)",
        ),
        SysError::Os(EINVAL) if stage == IrqStage::Ioeventfd => MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "KVM_IOEVENTFD rejected the address, length or datamatch",
        ),
        SysError::Os(n) if n == EACCES || n == EPERM => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            format!("permission denied ({name})"),
        ),
        SysError::Os(n) if n == ENOSPC || n == ENOMEM || n == EMFILE || n == ENFILE => {
            MicrovmError::new(
                MicrovmErrorCode::ResourceExhausted,
                format!("resource exhausted ({name}, os error {n})"),
            )
        }
        SysError::NullMapping => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("{name} failed (unexpected null mapping)"),
        ),
        SysError::Os(n) => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("{name} failed (os error {n})"),
        ),
    }
}

/// VM 設定（TSS・identity map）の段（errno 分類のメッセージ切り替え用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
enum VmSetupStage {
    SetTssAddr,
    SetIdentityMapAddr,
}

#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
fn classify_vm_setup_error(stage: VmSetupStage, e: SysError) -> MicrovmError {
    let name = match stage {
        VmSetupStage::SetTssAddr => "KVM_SET_TSS_ADDR",
        VmSetupStage::SetIdentityMapAddr => "KVM_SET_IDENTITY_MAP_ADDR",
    };
    match e {
        SysError::Unsupported => MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        ),
        SysError::Os(ENOTTY) => {
            MicrovmError::new(MicrovmErrorCode::FailedPrecondition, "not a KVM VM fd")
        }
        // identity map は vCPU の作成後に設定できない。
        SysError::Os(EINVAL) if stage == VmSetupStage::SetIdentityMapAddr => MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            "KVM_SET_IDENTITY_MAP_ADDR must run before any vCPU is created",
        ),
        SysError::Os(EINVAL) => MicrovmError::new(
            MicrovmErrorCode::InvalidArgument,
            "KVM_SET_TSS_ADDR rejected the address",
        ),
        SysError::Os(EEXIST) => MicrovmError::new(
            MicrovmErrorCode::FailedPrecondition,
            format!("{name}: already set or overlaps an existing memory slot"),
        ),
        SysError::Os(n) if n == EACCES || n == EPERM => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            format!("permission denied ({name})"),
        ),
        SysError::Os(n) if n == ENOSPC || n == ENOMEM || n == EMFILE || n == ENFILE => {
            MicrovmError::new(
                MicrovmErrorCode::ResourceExhausted,
                format!("resource exhausted ({name}, os error {n})"),
            )
        }
        SysError::NullMapping => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("{name} failed (unexpected null mapping)"),
        ),
        SysError::Os(n) => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("{name} failed (os error {n})"),
        ),
    }
}

impl VmFd {
    /// 拡張 `cap` に対応しているかを確かめ、非対応なら `FailedPrecondition`。
    fn require_extension(&self, cap: u64, what: &'static str) -> Result<(), MicrovmError> {
        let n = sys::kvm_check_extension(self.fd.as_fd(), cap)
            .map_err(|e| classify_irq_error(IrqStage::CheckExtension, e))?;
        if n == 0 {
            return Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                format!("{what} is not supported by this kernel"),
            ));
        }
        Ok(())
    }

    /// in-kernel irqchip（PIC・IOAPIC・LAPIC）を作る（TASK-74.2.3・MVM-1。x86_64 のみ）。
    ///
    /// vCPU を作る前に呼ぶ（作った後はカーネルが EINVAL を返し `FailedPrecondition`）。二重作成は `AlreadyExists`。
    /// aarch64 は vGIC が別方式（`KVM_CREATE_DEVICE`。`create_vgic_v3`・#3696）のため本メソッドは `Unimplemented`。
    pub fn create_irqchip(&self) -> Result<(), MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        self.require_extension(sys::consts::KVM_CAP_IRQCHIP, "KVM_CAP_IRQCHIP")?;
        sys::kvm_create_irqchip(self.fd.as_fd())
            .map_err(|e| classify_irq_error(IrqStage::CreateIrqchip, e))
    }

    /// vGICv3 を作り、distributor・redistributor の GPA を設定する（aarch64 のみ。MVM-1・#3696）。
    ///
    /// `KVM_CAP_DEVICE_CTRL` を確かめてから `KVM_CREATE_DEVICE`（`KVM_DEV_TYPE_ARM_VGIC_V3`）→
    /// `KVM_DEV_ARM_VGIC_GRP_ADDR` の DIST・REDIST。**初期化（`VgicV3::init`）は含まない**: 初期化は全 vCPU の作成後で、
    /// irqfd の登録前に呼ぶ（モジュール doc）。redistributor の領域は vCPU 数 × 128 KiB が必要で、不足は初期化時に拒否される。
    /// 検証を経ない任意アドレスを crate の外へ公開しないため `pub(crate)`（呼び出しは `assemble` のみ。アドレスは `Arm64Layout` の検証済みの値）。
    /// ホストが GICv3 を持たなければ `FailedPrecondition`。失敗時は作成済みの device fd を drop で閉じる。
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn create_vgic_v3(
        &self,
        dist_base: u64,
        redist_base: u64,
    ) -> Result<VgicV3, MicrovmError> {
        self.require_extension(sys::consts::KVM_CAP_DEVICE_CTRL, "KVM_CAP_DEVICE_CTRL")?;
        let fd = sys::kvm_create_device(self.fd.as_fd(), sys::consts::KVM_DEV_TYPE_ARM_VGIC_V3)
            .map_err(|e| classify_irq_error(IrqStage::CreateDevice, e))?;
        sys::kvm_set_device_attr_u64(
            fd.as_fd(),
            sys::consts::KVM_DEV_ARM_VGIC_GRP_ADDR,
            sys::consts::KVM_VGIC_V3_ADDR_TYPE_DIST,
            dist_base,
        )
        .map_err(|e| classify_irq_error(IrqStage::SetDeviceAttr, e))?;
        sys::kvm_set_device_attr_u64(
            fd.as_fd(),
            sys::consts::KVM_DEV_ARM_VGIC_GRP_ADDR,
            sys::consts::KVM_VGIC_V3_ADDR_TYPE_REDIST,
            redist_base,
        )
        .map_err(|e| classify_irq_error(IrqStage::SetDeviceAttr, e))?;
        Ok(VgicV3 { fd })
    }

    /// KVM の identity map ページ（1 ページ）の置き場を設定する（x86_64 のみ。MVM-1・#3732）。
    /// vCPU の作成前に呼ぶ。検証を経ない任意アドレスを crate の外へ公開しないため `pub(crate)`（呼び出しは `assemble` のみ）。
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn set_identity_map_addr(&self, addr: u64) -> Result<(), MicrovmError> {
        sys::kvm_set_identity_map_addr(self.fd.as_fd(), addr)
            .map_err(|e| classify_vm_setup_error(VmSetupStage::SetIdentityMapAddr, e))
    }

    /// KVM の TSS 用 3 ページの置き場を設定する（x86_64 のみ。MVM-1・#3732）。vCPU の作成前に呼ぶ。`pub(crate)` の理由は上と同じ。
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn set_tss_addr(&self, addr: u64) -> Result<(), MicrovmError> {
        sys::kvm_set_tss_addr(self.fd.as_fd(), addr)
            .map_err(|e| classify_vm_setup_error(VmSetupStage::SetTssAddr, e))
    }

    /// eventfd を GSI `gsi` に結ぶ（`KVM_IRQFD`）。返った [`IrqFd`] の `trigger` でゲストへ割り込みが入る。
    ///
    /// irqchip を先に作ること（無いと `FailedPrecondition`）。aarch64 は vGIC の**初期化後**に呼ぶ（前は `EAGAIN` で
    /// `FailedPrecondition`。順序の根拠はモジュール doc）。aarch64 の GSI は SPI 番号に等しい（INTID = GSI + 32）。GSI の範囲はカーネルの検証に任せる。
    /// 同じ組の二重登録は `AlreadyExists`。割り込みは edge 扱い（level の再注入は未実装）。
    pub fn register_irqfd(&self, gsi: u32) -> Result<IrqFd, MicrovmError> {
        self.require_extension(sys::consts::KVM_CAP_IRQFD, "KVM_CAP_IRQFD")?;
        // 順序は dup → eventfd 作成 → KVM_IRQFD（dup に失敗しても何も漏らさない。TASK-75.2）。
        let vm_fd = self.fd.as_fd().try_clone_to_owned().map_err(|e| {
            let n = e.raw_os_error().unwrap_or(0);
            if n == EMFILE || n == ENFILE {
                MicrovmError::new(
                    MicrovmErrorCode::ResourceExhausted,
                    format!("resource exhausted duplicating VM fd for irqfd (os error {n})"),
                )
            } else {
                MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    format!("duplicating VM fd for irqfd failed (os error {n})"),
                )
            }
        })?;
        let event = EventFd::new()?;
        sys::kvm_irqfd(self.fd.as_fd(), event.as_fd(), gsi, false)
            .map_err(|e| classify_irq_error(IrqStage::Irqfd, e))?;
        Ok(IrqFd::registered(vm_fd, event, gsi))
    }

    /// GSI `irq` を `KVM_IRQ_LINE` で駆動する level 線を作る（x86_64 のみ。#3918・MVM-1）。
    ///
    /// UART の割り込み（`crate::interrupt::LevelInterruptLine`）の結線に使う。`KVM_IRQFD` は edge 注入で線の値を持てないため
    /// 別に持つ。irqchip を先に作ること。作成時に `level = 0` を 1 回発行して irqchip の有無をここで検証する
    /// （無ければ `FailedPrecondition`。fail-closed）。VM fd の dup を所有するので借用を持たない。
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn register_irq_line(&self, irq: u32) -> Result<IrqLevelLine, MicrovmError> {
        self.require_extension(sys::consts::KVM_CAP_IRQCHIP, "KVM_CAP_IRQCHIP")?;
        let vm_fd = self.fd.as_fd().try_clone_to_owned().map_err(|e| {
            let n = e.raw_os_error().unwrap_or(0);
            if n == EMFILE || n == ENFILE {
                MicrovmError::new(
                    MicrovmErrorCode::ResourceExhausted,
                    format!("resource exhausted duplicating VM fd for irq line (os error {n})"),
                )
            } else {
                MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    format!("duplicating VM fd for irq line failed (os error {n})"),
                )
            }
        })?;
        sys::kvm_irq_line(self.fd.as_fd(), irq, false)
            .map_err(|e| classify_irq_error(IrqStage::IrqLine, e))?;
        Ok(IrqLevelLine::new(vm_fd, irq))
    }

    /// ゲストの `spec` への書き込みを VM exit なしで eventfd へ通す（`KVM_IOEVENTFD`）。
    ///
    /// 条件に合わない書き込みは従来どおり MMIO / PIO exit で `dispatch` に届く。同じ組の二重登録は `AlreadyExists`。
    pub fn register_ioeventfd(&self, spec: IoEventSpec) -> Result<IoEventFd<'_>, MicrovmError> {
        self.require_extension(sys::consts::KVM_CAP_IOEVENTFD, "KVM_CAP_IOEVENTFD")?;
        let event = EventFd::new()?;
        let (addr, pio) = irq::ioevent_args(&spec);
        sys::kvm_ioeventfd(
            self.fd.as_fd(),
            event.as_fd(),
            addr,
            spec.len(),
            spec.datamatch(),
            pio,
            false,
        )
        .map_err(|e| classify_irq_error(IrqStage::Ioeventfd, e))?;
        Ok(IoEventFd::registered(self.fd.as_fd(), event, spec))
    }

    /// `KVM_CREATE_VCPU` で vCPU を作る（aarch64 は続けて初期化する。モジュール doc 参照）。
    /// id の上限は検証せずカーネルの EINVAL（`InvalidArgument`）に任せる。重複は `AlreadyExists`。
    /// 初期化に失敗したときは作成済みの fd を drop で close する。
    pub fn create_vcpu(&self, id: u32) -> Result<VcpuFd, MicrovmError> {
        // aarch64 は PSCI 0.2 を有効にするため、vCPU を作る前に capability を確かめる（無ければ fd を作らない）。
        #[cfg(target_arch = "aarch64")]
        self.require_extension(sys::consts::KVM_CAP_ARM_PSCI_0_2, "KVM_CAP_ARM_PSCI_0_2")?;
        let fd = sys::kvm_create_vcpu(self.fd.as_fd(), u64::from(id))
            .map_err(|e| classify_vcpu_error(VcpuStage::Create, e))?;
        #[cfg(target_arch = "aarch64")]
        {
            let init = sys::kvm_arm_preferred_target(self.fd.as_fd())
                .map_err(|e| classify_vcpu_error(VcpuStage::PreferredTarget, e))?;
            let init = sys::with_psci_0_2(init);
            sys::kvm_arm_vcpu_init(fd.as_fd(), &init)
                .map_err(|e| classify_vcpu_error(VcpuStage::VcpuInit, e))?;
        }
        let run = sys::KvmRunMap::map(fd.as_fd(), self.vcpu_mmap_size)
            .map_err(|e| classify_vcpu_error(VcpuStage::Mmap, e))?;
        Ok(VcpuFd {
            run,
            fd,
            id,
            stats: RunStats::default(),
            observer: None,
        })
    }
}

impl AsFd for VmFd {
    /// `KVM_CREATE_VCPU` が借用する。
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn classify_open_error(e: &io::Error) -> MicrovmError {
    match e.kind() {
        io::ErrorKind::NotFound => {
            MicrovmError::new(MicrovmErrorCode::NotFound, "KVM device not found")
        }
        io::ErrorKind::PermissionDenied => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            "permission denied opening KVM device",
        ),
        _ => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!(
                "failed to open KVM device (os error {})",
                e.raw_os_error().unwrap_or(0)
            ),
        ),
    }
}

fn classify_create_vm_error(e: SysError) -> MicrovmError {
    match e {
        SysError::Unsupported => MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "KVM is not supported on this architecture",
        ),
        SysError::Os(n) if n == EACCES || n == EPERM => MicrovmError::new(
            MicrovmErrorCode::PermissionDenied,
            "permission denied creating VM",
        ),
        SysError::Os(n) if n == ENOMEM || n == EMFILE || n == ENFILE => MicrovmError::new(
            MicrovmErrorCode::ResourceExhausted,
            format!("resource exhausted creating VM (os error {n})"),
        ),
        SysError::NullMapping => MicrovmError::new(
            MicrovmErrorCode::Internal,
            "KVM_CREATE_VM failed (unexpected null mapping)",
        ),
        SysError::Os(n) => MicrovmError::new(
            MicrovmErrorCode::Internal,
            format!("KVM_CREATE_VM failed (os error {n})"),
        ),
    }
}

impl KvmDevice {
    /// ホストが提供できる CPUID の表を読む（`KVM_GET_SUPPORTED_CPUID`。#3733・MVM-1。x86_64 のみ。他 arch は `Unimplemented`）。
    ///
    /// 件数の上限は `KVM_MAX_CPUID_ENTRIES`（256）で 1 回だけ要求し、E2BIG でも広げて再試行しない（fail-closed。
    /// バッファは約 10 KB でカーネル側の上限も同じ 256 のため、ループを持たない）。
    #[cfg(target_arch = "x86_64")]
    pub fn supported_cpuid(&self) -> Result<CpuidTable, MicrovmError> {
        const _: () = assert!(MAX_CPUID_ENTRIES == sys::consts::MAX_CPUID_ENTRIES);
        let raw = sys::kvm_get_supported_cpuid(self.fd.as_fd(), MAX_CPUID_ENTRIES).map_err(
            |e| match e {
                SysError::Unsupported => MicrovmError::new(
                    MicrovmErrorCode::Unimplemented,
                    "KVM is not supported on this architecture",
                ),
                SysError::Os(ENOTTY) => {
                    MicrovmError::new(MicrovmErrorCode::FailedPrecondition, "not a KVM system fd")
                }
                SysError::Os(E2BIG) => MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    "KVM_GET_SUPPORTED_CPUID exceeds the 256 entry limit",
                ),
                SysError::Os(ENOMEM) => MicrovmError::new(
                    MicrovmErrorCode::ResourceExhausted,
                    "resource exhausted reading supported CPUID",
                ),
                SysError::NullMapping => MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    "KVM_GET_SUPPORTED_CPUID failed (unexpected null mapping)",
                ),
                SysError::Os(n) => MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    format!("KVM_GET_SUPPORTED_CPUID failed (os error {n})"),
                ),
            },
        )?;
        CpuidTable::new(
            raw.iter()
                .map(|e| CpuidEntry {
                    function: e.function,
                    index: e.index,
                    flags: e.flags,
                    eax: e.eax,
                    ebx: e.ebx,
                    ecx: e.ecx,
                    edx: e.edx,
                })
                .collect(),
        )
    }

    /// x86_64 以外では CPUID の取得は未実装（REPAIR-3）。
    #[cfg(not(target_arch = "x86_64"))]
    pub fn supported_cpuid(&self) -> Result<CpuidTable, MicrovmError> {
        Err(MicrovmError::new(
            MicrovmErrorCode::Unimplemented,
            "CPUID setup is only implemented for x86_64",
        ))
    }

    /// `/dev/kvm` を開き、KVM API 版数が 12 であることを確かめる。
    pub fn open() -> Result<KvmDevice, MicrovmError> {
        Self::open_at(Path::new(KVM_PATH))
    }

    /// 任意のパスを KVM デバイスとして開く（試験・将来の差し替え用）。エラーの `message` にパスは載せない。
    pub fn open_at(path: &Path) -> Result<KvmDevice, MicrovmError> {
        // std は Linux で O_CLOEXEC を付ける。KVM は O_RDWR が必要。
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| classify_open_error(&e))?;
        let dev = KvmDevice {
            fd: OwnedFd::from(file),
        };
        let v = dev.api_version()?;
        if v != sys::consts::KVM_API_VERSION {
            return Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                format!(
                    "unsupported KVM API version {v} (expected {})",
                    sys::consts::KVM_API_VERSION
                ),
            ));
        }
        Ok(dev)
    }

    /// `KVM_GET_API_VERSION` の値。KVM デバイスでない fd（ENOTTY 等）は `FailedPrecondition`。
    pub fn api_version(&self) -> Result<i32, MicrovmError> {
        sys::kvm_get_api_version(self.fd.as_fd()).map_err(|e| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::Os(_) | SysError::NullMapping => {
                MicrovmError::new(MicrovmErrorCode::FailedPrecondition, "not a KVM device")
            }
        })
    }

    /// `KVM_CREATE_VM`（machine type 0）で VM fd を作る。
    pub fn create_vm(&self) -> Result<VmFd, MicrovmError> {
        sys::kvm_create_vm(self.fd.as_fd(), 0)
            .map_err(classify_create_vm_error)
            .and_then(|fd| {
                let n = sys::kvm_get_vcpu_mmap_size(self.fd.as_fd()).map_err(|e| match e {
                    SysError::Unsupported => MicrovmError::new(
                        MicrovmErrorCode::Unimplemented,
                        "KVM is not supported on this architecture",
                    ),
                    SysError::NullMapping => MicrovmError::new(
                        MicrovmErrorCode::Internal,
                        "KVM_GET_VCPU_MMAP_SIZE failed (unexpected null mapping)",
                    ),
                    SysError::Os(n) => MicrovmError::new(
                        MicrovmErrorCode::Internal,
                        format!("KVM_GET_VCPU_MMAP_SIZE failed (os error {n})"),
                    ),
                })?;
                Ok(VmFd {
                    fd,
                    vcpu_mmap_size: validate_mmap_size(n)?,
                })
            })
    }

    /// 自己診断: 固定の 5 バイトのゲストコード（`mov al,0x42; out 0x10,al; hlt`）を 1 ページに置いて
    /// 自己診断: vGICv3 の初期化前の irqfd 登録が `FailedPrecondition` で拒否され、初期化後は通ることを確かめる
    /// （MVM-1・#3696。aarch64 のみ。他 arch は `Unimplemented`）。VM・vCPU・vGIC の寿命は関数内で完結する。
    /// `tests/` の結合試験から呼ぶための口で、vGIC の構成 API（`create_vgic_v3`・`init`）は公開しない。
    /// 順序の根拠はモジュール doc。ホストが GICv3 を持たない場合は `create_vgic_v3` の `FailedPrecondition` を返す。
    pub fn probe_irqfd_vgic_order(&self) -> Result<IrqfdVgicOrderProbe, MicrovmError> {
        #[cfg(target_arch = "aarch64")]
        {
            let vm = self.create_vm()?;
            let _vcpu = vm.create_vcpu(0)?;
            let vgic = vm.create_vgic_v3(
                crate::arm64_layout::ARM64_GIC_DIST_BASE,
                crate::arm64_layout::ARM64_GIC_REDIST_BASE,
            )?;
            let before_init = match vm.register_irqfd(16) {
                Ok(_) => None,
                Err(e) => Some((e.code(), e.message().to_string())),
            };
            vgic.init()?;
            let after_init_ok = vm.register_irqfd(16).is_ok();
            Ok(IrqfdVgicOrderProbe {
                before_init,
                after_init_ok,
            })
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            Err(MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "irqfd vGIC order probe is only implemented for aarch64",
            ))
        }
    }

    /// 実際に `KVM_RUN` し、観測した VM exit を返す（TASK-74.4.1・MVM-1。x86_64 のみ）。
    ///
    /// x86_64 のリセット状態（CS:IP = F000:FFF0、線形 0xFFFFFFF0）のまま GPA `0xFFFFF000` に置いた 1 ページから
    /// 実行され、レジスタ設定は不要。ゲストのコードは固定のリテラルで外部入力は届かない。VM・ページ・vCPU の
    /// 寿命はこの関数の中で完結する（戻る前に vCPU、登録ページ、VM の順に解放する）。
    /// 将来 `fandhe-container-plugin-microvm`（TASK-117）の利用可否の確認にも使える。汎用のゲストメモリは
    /// #696（TASK-75.1）の担当でこれは別物。ゲストが想定どおり終わらないときは 1 回 5 秒の期限で中断して失敗にする
    /// （最大 8 回でも打ち切る）。他 arch は `Unimplemented`。
    pub fn probe_guest_execution(&self) -> Result<GuestExecutionProbe, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            self.probe_guest_execution_x86_64()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "guest execution probe is only implemented for x86_64",
            ))
        }
    }

    /// 自己診断: ゲストコード（`in al,0x10; out 0x11,al; mov al,[0x2000]; out 0x12,al; hlt`）を実際に `KVM_RUN` し、
    /// PIO の IN と MMIO read の応答が `handle_exit` でゲストへ書き戻されることを確かめる（TASK-74.4.2・MVM-1。
    /// x86_64 のみ）。ポート 0x10 は固定値 `0x5A`、GPA `0x2000` の MMIO は固定値 `0xA5` を返し、ポート 0x11・0x12
    /// への OUT が記録される。ページ・vCPU の扱いと期限は [`KvmDevice::probe_guest_execution`] と同じ。
    /// 他 arch は `Unimplemented`。
    pub fn probe_exit_dispatch(&self) -> Result<ExitDispatchProbe, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            self.probe_exit_dispatch_x86_64()
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "exit dispatch probe is only implemented for x86_64",
            ))
        }
    }

    /// 自己診断: virtio-mmio の `QueueNotify` の ioeventfd と、irqfd による割り込み注入を実機で確かめる
    /// （TASK-74.2.3・MVM-1・MVM-4。x86_64 のみ。他 arch は `Unimplemented`）。
    ///
    /// VM に in-kernel irqchip を作り、virtio-mmio（基底 GPA `0x2000`）の `QueueNotify`（キュー 0）を ioeventfd、
    /// GSI 5 を irqfd に結んだうえで、real mode のゲストを走らせる。ゲストは 8259 を初期化して IRQ5 だけを許可し、
    /// `QueueNotify` へキュー 0 を書き（exit にならない）、準備完了を OUT `0x10` で知らせ、`sti; hlt` で待つ。
    /// ホストは ioeventfd の発火 1 回を確かめ、割り込みが無い間は `DeadlineExceeded`（HLT のまま）になることを確かめてから
    /// `on_notify` に [`InterruptLine`] を渡す（呼び出し側がここで virtqueue を処理して `trigger` する）。
    /// ゲストの ISR は OUT `0x13` で到着を知らせる。到着しなければ無限に待たず `Internal` で失敗する（REPAIR-5）。
    ///
    /// 前提: `KVM_X86_QUIRK_LINT0_REENABLED`（既定で有効）により BSP の LAPIC LINT0 が ExtINT になり、PIC の出力が
    /// vCPU 0 へ届く。満たされない環境では割り込みが届かず `Internal` で fail-closed する。ゲストコードは固定の
    /// リテラルで外部入力は届かない。ゲストが使うのは QueueNotify への書き込みだけで、virtqueue の中身はホストの
    /// heap 上にある（ゲストメモリの KVM 登録は TASK-75.1）。
    pub fn probe_queue_interrupt(
        &self,
        on_notify: &mut dyn FnMut(&dyn InterruptLine) -> Result<(), MicrovmError>,
    ) -> Result<QueueInterruptProbe, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            self.probe_queue_interrupt_x86_64(on_notify)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = on_notify;
            Err(MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "queue interrupt probe is only implemented for x86_64",
            ))
        }
    }

    /// 無限ループ（`jmp $`）のゲストを `runs` 回 `deadline` で中断させ、統計と記録を返す（REPAIR-5・REPAIR-4・MVM-1。
    /// x86_64 のみ。他 arch は `Unimplemented`）。呼び出しスレッドの `SIGUSR2` を診断中ブロックして最悪条件で確かめる。各回は必ず `DeadlineExceeded` で戻ることを期待し、
    /// 想定外の結果は `Internal` で失敗にする。`runs` は 1〜8、`deadline` は `run_once` と同じ範囲。
    pub fn probe_deadline_interrupt(
        &self,
        deadline: Duration,
        runs: u32,
    ) -> Result<DeadlineProbe, MicrovmError> {
        #[cfg(target_arch = "x86_64")]
        {
            self.probe_deadline_interrupt_x86_64(deadline, runs)
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (deadline, runs);
            Err(MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "deadline probe is only implemented for x86_64",
            ))
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn probe_queue_interrupt_x86_64(
        &self,
        on_notify: &mut dyn FnMut(&dyn InterruptLine) -> Result<(), MicrovmError>,
    ) -> Result<QueueInterruptProbe, MicrovmError> {
        use crate::exit::IoDirection;

        const VIRTIO_BASE: u64 = 0x2000;
        const IRQ_GSI: u32 = 5;
        // slot 0（GPA 0）: IVT・ISR・本体。slot 1（GPA 0xFFFFF000）: リセットベクタ。
        const LOW_GPA: u64 = 0;
        const RESET_GPA: u64 = 0xFFFF_F000;
        // リセットベクタ: jmp far 0000:0600
        const RESET_CODE: &[u8] = &[0xEA, 0x00, 0x06, 0x00, 0x00];
        // IVT のベクタ 0x25（8259 の IRQ5）: 0000:0500
        const IVT_OFFSET: usize = 0x25 * 4;
        const IVT_ENTRY: &[u8] = &[0x00, 0x05, 0x00, 0x00];
        // ISR（0000:0500）: mov al,0xA5; out 0x13,al; mov al,0x20; out 0x20,al (EOI); hlt; jmp hlt
        const ISR_OFFSET: usize = 0x500;
        const ISR_CODE: &[u8] = &[
            0xB0, 0xA5, 0xE6, 0x13, 0xB0, 0x20, 0xE6, 0x20, 0xF4, 0xEB, 0xFD,
        ];
        // 本体（0000:0600）: cli; ss/ds/sp 設定; 8259 を初期化（ICW1〜4・IRQ5 だけ許可）;
        // mov dword [0x2050],0 (QueueNotify); mov al,0x42; out 0x10,al; sti; hlt; jmp hlt
        const BODY_OFFSET: usize = 0x600;
        const BODY_CODE: &[u8] = &[
            // cli; xor ax,ax; mov ss,ax; mov sp,0xF00; mov ds,ax
            0xFA, 0x31, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x0F, 0x8E, 0xD8, //
            0xB0, 0x11, 0xE6, 0x20, // ICW1
            0xB0, 0x20, 0xE6, 0x21, // ICW2: ベクタ base 0x20
            0xB0, 0x04, 0xE6, 0x21, // ICW3
            0xB0, 0x01, 0xE6, 0x21, // ICW4
            0xB0, 0xDF, 0xE6, 0x21, // OCW1: IRQ5 だけ許可
            0x66, 0xC7, 0x06, 0x50, 0x20, 0x00, 0x00, 0x00, 0x00, // mov dword [0x2050],0
            0xB0, 0x42, 0xE6, 0x10, // mov al,0x42; out 0x10,al
            0xFB, 0xF4, 0xEB, 0xFD, // sti; hlt; jmp hlt
        ];
        const IDLE_DEADLINE: Duration = Duration::from_millis(200);

        let internal = |what: &str, e: SysError| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::NullMapping => MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{what} failed (unexpected null mapping)"),
            ),
            SysError::Os(n) => MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{what} failed (os error {n})"),
            ),
        };
        let too_big = |()| {
            MicrovmError::new(
                MicrovmErrorCode::Internal,
                "guest code does not fit the page",
            )
        };
        let io_out = |port: u16, byte: u8| VcpuExit::Io {
            direction: IoDirection::Out,
            port,
            size: 1,
            count: 1,
            data: vec![byte],
        };

        // 最後に明示 drop して順序を固定する: vcpu → ioevent → irqfd → 登録ページ 2 枚 → vm。
        let vm = self.create_vm()?;
        vm.create_irqchip()?;
        let mut low = sys::GuestPage::new().map_err(|e| internal("guest page allocation", e))?;
        low.write_at(IVT_OFFSET, IVT_ENTRY).map_err(too_big)?;
        low.write_at(ISR_OFFSET, ISR_CODE).map_err(too_big)?;
        low.write_at(BODY_OFFSET, BODY_CODE).map_err(too_big)?;
        let mut reset = sys::GuestPage::new().map_err(|e| internal("guest page allocation", e))?;
        reset.write_at(0xFF0, RESET_CODE).map_err(too_big)?;
        let reg_low = sys::register_single_page(vm.fd.as_fd(), 0, LOW_GPA, low)
            .map_err(|(e, _page)| internal("KVM_SET_USER_MEMORY_REGION", e))?;
        let reg_reset = sys::register_single_page(vm.fd.as_fd(), 1, RESET_GPA, reset)
            .map_err(|(e, _page)| internal("KVM_SET_USER_MEMORY_REGION", e))?;
        let ioevent =
            vm.register_ioeventfd(IoEventSpec::virtio_mmio_queue_notify(VIRTIO_BASE, 0)?)?;
        let irqfd = vm.register_irqfd(IRQ_GSI)?;
        let mut vcpu = vm.create_vcpu(0)?;

        let result = (|| {
            let ready_exit = run_skipping_interrupted(|| vcpu.run_once(PROBE_RUN_DEADLINE))?;
            if ready_exit != io_out(0x10, 0x42) {
                return Err(MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    "guest did not reach the ready point (QueueNotify must not exit)",
                ));
            }
            let notify_count = ioevent.consume()?;
            let idle_outcome = match run_skipping_interrupted(|| vcpu.run_once(IDLE_DEADLINE)) {
                Err(e) => e.code(),
                Ok(_) => {
                    return Err(MicrovmError::new(
                        MicrovmErrorCode::Internal,
                        "guest left HLT without an interrupt",
                    ));
                }
            };
            on_notify(&irqfd)?;
            let interrupt_exit = run_skipping_interrupted(|| vcpu.run_once(PROBE_RUN_DEADLINE))
                .map_err(|e| {
                    if e.code() == MicrovmErrorCode::DeadlineExceeded {
                        MicrovmError::new(
                            MicrovmErrorCode::Internal,
                            "interrupt did not reach the guest",
                        )
                    } else {
                        e
                    }
                })?;
            Ok(QueueInterruptProbe {
                ready_exit,
                notify_count,
                idle_outcome,
                interrupt_exit,
            })
        })();
        drop(vcpu);
        drop(ioevent);
        drop(irqfd);
        drop(reg_reset);
        drop(reg_low);
        drop(vm);
        result
    }

    #[cfg(target_arch = "x86_64")]
    fn probe_deadline_interrupt_x86_64(
        &self,
        deadline: Duration,
        runs: u32,
    ) -> Result<DeadlineProbe, MicrovmError> {
        const GPA: u64 = 0xFFFF_F000;
        if runs == 0 || runs > 8 {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "probe run count out of range",
            ));
        }
        let internal = |what: &str, e: SysError| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::NullMapping => MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{what} failed (unexpected null mapping)"),
            ),
            SysError::Os(n) => MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{what} failed (os error {n})"),
            ),
        };
        // 最も厳しい条件（SIGUSR2 をブロックしたスレッド）で期限が効くことを確かめる。
        let blocked = sys::KickUnblocked::blocked_for_probe()
            .map_err(|e| internal("signal mask change", e))?;
        let vm = self.create_vm()?;
        let mut page = sys::GuestPage::new().map_err(|e| internal("guest page allocation", e))?;
        // jmp $
        page.write_at(0xFF0, &[0xEB, 0xFE]).map_err(|()| {
            MicrovmError::new(
                MicrovmErrorCode::Internal,
                "guest code does not fit the page",
            )
        })?;
        let registered = sys::register_single_page(vm.fd.as_fd(), 0, GPA, page)
            .map_err(|(e, _page)| internal("KVM_SET_USER_MEMORY_REGION", e))?;
        let mut vcpu = vm.create_vcpu(0)?;
        let obs = Arc::new(CollectingObserver::default());
        vcpu.set_observer(obs.clone());
        let mut result = Ok(());
        for _ in 0..runs {
            match vcpu.run_once(deadline) {
                Err(e) if e.code() == MicrovmErrorCode::DeadlineExceeded => {}
                Err(e) => {
                    result = Err(e);
                    break;
                }
                Ok(_) => {
                    result = Err(MicrovmError::new(
                        MicrovmErrorCode::Internal,
                        "spinning guest exited before the deadline",
                    ));
                    break;
                }
            }
        }
        let stats = vcpu.stats();
        drop(vcpu);
        drop(registered);
        drop(vm);
        let restored =
            sys::KickUnblocked::kick_is_blocked().map_err(|e| internal("signal mask query", e))?;
        drop(blocked);
        result?;
        let records = obs.0.lock().map(|v| v.clone()).unwrap_or_default();
        Ok(DeadlineProbe {
            stats,
            records,
            kick_mask_restored: restored,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn probe_exit_dispatch_x86_64(&self) -> Result<ExitDispatchProbe, MicrovmError> {
        use crate::dispatch::{MmioDevice, PortIoDevice, PortIoOutcome};
        use crate::virtio_mmio::{MmioReadOutcome, MmioWriteOutcome};
        use std::sync::Mutex;

        // in al,0x10 / out 0x11,al / mov al,[0x2000] (16 ビット moffs) / out 0x12,al / hlt
        const CODE: [u8; 10] = [0xE4, 0x10, 0xE6, 0x11, 0xA0, 0x00, 0x20, 0xE6, 0x12, 0xF4];
        const GPA: u64 = 0xFFFF_F000;
        const CODE_OFFSET: usize = 0xFF0;
        const IN_VALUE: u8 = 0x5A;
        const MMIO_VALUE: u8 = 0xA5;

        /// 読み出しで固定値を返すポートデバイス。
        struct ConstPort(u8);
        impl PortIoDevice for ConstPort {
            fn read(&mut self, _offset: u16, data: &mut [u8]) -> PortIoOutcome {
                data.fill(self.0);
                PortIoOutcome::Handled
            }
            fn write(&mut self, _offset: u16, _data: &[u8]) -> PortIoOutcome {
                PortIoOutcome::Ignored
            }
        }
        /// 書き込みを記録するポートデバイス。
        struct RecordPort(Arc<Mutex<Vec<(u16, u8)>>>);
        impl PortIoDevice for RecordPort {
            fn read(&mut self, _offset: u16, data: &mut [u8]) -> PortIoOutcome {
                data.fill(0);
                PortIoOutcome::Ignored
            }
            fn write(&mut self, offset: u16, data: &[u8]) -> PortIoOutcome {
                if let (Ok(mut log), Some(b)) = (self.0.lock(), data.first()) {
                    log.push((offset, *b));
                }
                PortIoOutcome::Handled
            }
        }
        /// 読み出しで固定値を返す MMIO デバイス。
        struct ConstMmio(u8);
        impl MmioDevice for ConstMmio {
            fn read(&self, _offset: u64, data: &mut [u8]) -> MmioReadOutcome {
                data.fill(self.0);
                MmioReadOutcome::Handled
            }
            fn write(&mut self, _offset: u64, _data: &[u8]) -> MmioWriteOutcome {
                MmioWriteOutcome::Handled
            }
        }

        let internal = |what: &str, e: SysError| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::NullMapping => MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{what} failed (unexpected null mapping)"),
            ),
            SysError::Os(n) => MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{what} failed (os error {n})"),
            ),
        };
        let writes = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = ExitDispatcher::new();
        dispatcher.register_pio(0x10, 1, Box::new(ConstPort(IN_VALUE)))?;
        dispatcher.register_pio(0x11, 2, Box::new(RecordPort(Arc::clone(&writes))))?;
        dispatcher.register_mmio(0x2000, 0x10, Box::new(ConstMmio(MMIO_VALUE)))?;
        // 宣言順の逆が drop 順: vcpu → registered → vm。明示 drop で順序を固定する。
        let vm = self.create_vm()?;
        let mut page = sys::GuestPage::new().map_err(|e| internal("guest page allocation", e))?;
        page.write_at(CODE_OFFSET, &CODE).map_err(|()| {
            MicrovmError::new(
                MicrovmErrorCode::Internal,
                "guest code does not fit the page",
            )
        })?;
        let registered = sys::register_single_page(vm.fd.as_fd(), 0, GPA, page)
            .map_err(|(e, _page)| internal("KVM_SET_USER_MEMORY_REGION", e))?;
        let mut vcpu = vm.create_vcpu(0)?;
        let outcome = run_probe_loop(|| {
            let exit = vcpu.run_once(PROBE_RUN_DEADLINE)?;
            if matches!(exit, VcpuExit::Io { .. } | VcpuExit::Mmio { .. }) {
                vcpu.handle_exit(&exit, &mut dispatcher)?;
            }
            Ok(exit)
        });
        drop(vcpu);
        drop(registered);
        drop(vm);
        let (exits, _interrupted) = outcome?;
        let port_writes = writes.lock().map(|v| v.clone()).unwrap_or_default();
        Ok(ExitDispatchProbe { exits, port_writes })
    }

    #[cfg(target_arch = "x86_64")]
    fn probe_guest_execution_x86_64(&self) -> Result<GuestExecutionProbe, MicrovmError> {
        const CODE: [u8; 5] = [0xB0, 0x42, 0xE6, 0x10, 0xF4];
        const GPA: u64 = 0xFFFF_F000;
        const CODE_OFFSET: usize = 0xFF0;
        let internal = |what: &str, e: SysError| match e {
            SysError::Unsupported => MicrovmError::new(
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
            SysError::NullMapping => MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{what} failed (unexpected null mapping)"),
            ),
            SysError::Os(n) => MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("{what} failed (os error {n})"),
            ),
        };
        // 宣言順の逆が drop 順: vcpu → registered → vm。明示 drop で順序を固定する。
        let vm = self.create_vm()?;
        let mut page = sys::GuestPage::new().map_err(|e| internal("guest page allocation", e))?;
        page.write_at(CODE_OFFSET, &CODE).map_err(|()| {
            MicrovmError::new(
                MicrovmErrorCode::Internal,
                "guest code does not fit the page",
            )
        })?;
        let registered = sys::register_single_page(vm.fd.as_fd(), 0, GPA, page)
            .map_err(|(e, _page)| internal("KVM_SET_USER_MEMORY_REGION", e))?;
        let mut vcpu = vm.create_vcpu(0)?;
        let outcome = run_probe_loop(|| vcpu.run_once(PROBE_RUN_DEADLINE));
        drop(vcpu);
        drop(registered);
        drop(vm);
        let (exits, interrupted) = outcome?;
        Ok(GuestExecutionProbe { exits, interrupted })
    }
}

/// `Interrupted`（ホスト側の EINTR / EAGAIN。ゲストの exit ではない）を読み飛ばして再実行し、
/// 最初の実 exit かエラーを返す。回数上限（[`PROBE_MAX_RUNS`]）まで `Interrupted` が続けば
/// `Internal` で失敗にする（fail-closed。MVM-1・REPAIR-5）。
#[cfg(target_arch = "x86_64")]
fn run_skipping_interrupted(
    mut run: impl FnMut() -> Result<VcpuExit, MicrovmError>,
) -> Result<VcpuExit, MicrovmError> {
    for _ in 0..PROBE_MAX_RUNS {
        match run()? {
            VcpuExit::Interrupted => {}
            other => return Ok(other),
        }
    }
    Err(MicrovmError::new(
        MicrovmErrorCode::Internal,
        "vcpu run was interrupted up to the probe run limit",
    ))
}

/// 自己診断のループ本体。`Hlt` で完了したときだけ `Ok`、回数上限（[`PROBE_MAX_RUNS`]）に達しても
/// `Hlt` に至らなければ `Internal` で失敗にする（fail-closed。TASK-74.4.1・MVM-1・REPAIR-5）。
#[cfg(target_arch = "x86_64")]
fn run_probe_loop(
    mut run: impl FnMut() -> Result<VcpuExit, MicrovmError>,
) -> Result<(Vec<VcpuExit>, u32), MicrovmError> {
    let mut exits = Vec::new();
    let mut interrupted = 0u32;
    for _ in 0..PROBE_MAX_RUNS {
        match run()? {
            VcpuExit::Interrupted => interrupted += 1,
            VcpuExit::Hlt => {
                exits.push(VcpuExit::Hlt);
                return Ok((exits, interrupted));
            }
            other => exits.push(other),
        }
    }
    Err(MicrovmError::new(
        MicrovmErrorCode::Internal,
        "guest did not halt within the probe run limit",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::{ExitData, IoDirection};

    fn io_out(b: u8) -> VcpuExit {
        VcpuExit::Io {
            direction: IoDirection::Out,
            port: 0x10,
            size: 1,
            count: 1,
            data: vec![b],
        }
    }

    fn rec(id: u32, b: u8) -> RunRecord {
        build_record(id, &Ok(io_out(b)), Duration::ZERO, true)
    }

    /// #3769・MVM-1: 値は求められたときだけ載り、非アクセス exit・エラーには載らない。
    #[test]
    fn mvm1_3769_build_record_captures_value_only_when_requested() {
        let on = build_record(0, &Ok(io_out(b'O')), Duration::ZERO, true);
        assert_eq!(on.outcome, RunOutcome::Exit("io"));
        assert_eq!(
            on.value,
            Some(ExitValue::Pio {
                direction: IoDirection::Out,
                port: 0x10,
                size: 1,
                count: 1,
                data: ExitData::from_slice(b"O"),
            })
        );
        let off = build_record(0, &Ok(io_out(b'O')), Duration::ZERO, false);
        assert_eq!(off.value, None);
        let int = build_record(0, &Ok(VcpuExit::Interrupted), Duration::ZERO, true);
        assert_eq!((int.outcome, int.value), (RunOutcome::Interrupted, None));
        let err = Err(MicrovmError::new(
            MicrovmErrorCode::DeadlineExceeded,
            "deadline",
        ));
        let d = build_record(0, &err, Duration::ZERO, true);
        assert_eq!((d.outcome, d.value), (RunOutcome::DeadlineExceeded, None));
    }

    /// #3769・MVM-1: 件数上限を超えたレコードは捨てて数える。
    #[test]
    fn mvm1_3769_bounded_run_log_drops_and_counts_overflow() {
        let log = BoundedRunLog::new(2, ValueCapture::Record).unwrap();
        for i in 0..5u8 {
            log.record(&rec(u32::from(i), b'a' + i));
        }
        assert_eq!(log.records(), vec![rec(0, b'a'), rec(1, b'b')]);
        assert_eq!(log.dropped(), 3);
    }

    /// #3769・MVM-1・REPAIR-12: 読み取りと `record` が重なっても記録を捨てない。
    #[test]
    fn mvm1_3769_bounded_run_log_record_survives_concurrent_reads() {
        let log = std::sync::Arc::new(BoundedRunLog::new(256, ValueCapture::Record).unwrap());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let (log, stop) = (log.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = log.records();
                }
            })
        };
        for i in 0..200u32 {
            log.record(&rec(i, 1));
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        reader.join().unwrap();
        assert_eq!(log.records().len(), 200);
        assert_eq!(log.dropped(), 0);
    }

    /// #3769・MVM-1: 容量の範囲外は `InvalidArgument`。
    #[test]
    fn mvm1_3769_bounded_run_log_rejects_out_of_range_capacity() {
        for c in [0, RUN_LOG_CAPACITY_MAX + 1] {
            let e = BoundedRunLog::new(c, ValueCapture::Omit).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
        }
        assert!(BoundedRunLog::new(RUN_LOG_CAPACITY_MAX, ValueCapture::Omit).is_ok());
    }

    /// #3769・MVM-1: `wants_values` は既定 false で、`Record` のときだけ true。
    #[test]
    fn mvm1_3769_wants_values_defaults_to_false() {
        #[derive(Debug)]
        struct Plain;
        impl RunObserver for Plain {
            fn record(&self, _: &RunRecord) {}
        }
        assert!(!Plain.wants_values());
        assert!(
            !BoundedRunLog::new(1, ValueCapture::Omit)
                .unwrap()
                .wants_values()
        );
        assert!(
            BoundedRunLog::new(1, ValueCapture::Record)
                .unwrap()
                .wants_values()
        );
    }

    /// #3769・MVM-1: `Debug` は記録した値を出さず、件数だけ出す。
    #[test]
    fn mvm1_3769_bounded_run_log_debug_omits_values() {
        let log = BoundedRunLog::new(1, ValueCapture::Record).unwrap();
        log.record(&rec(0, 0xAB));
        log.record(&rec(0, 0xCD));
        let s = format!("{log:?}");
        assert!(
            !s.contains("171") && !s.to_lowercase().contains("0xab"),
            "{s}"
        );
        assert!(s.contains("dropped: 1") && s.contains("len: 1"), "{s}");
    }

    use std::sync::atomic::AtomicU32;

    fn watch_in_thread(
        signal: &StopSignal,
        run_done: &AtomicBool,
        timeout: Duration,
        exits: &Mutex<Vec<bool>>,
        kicks: &AtomicU32,
        body: impl FnOnce() + Send,
    ) -> WatchOutcome {
        std::thread::scope(|s| {
            let h = s.spawn(|| {
                watch_run(
                    signal,
                    run_done,
                    timeout,
                    |on| exits.lock().unwrap().push(on),
                    || {
                        kicks.fetch_add(1, Ordering::SeqCst);
                    },
                )
            });
            // body が panic / assert 失敗しても run_done を立てて通知し、scope の暗黙 join で停止しないようにする。
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
            run_done.store(true, Ordering::SeqCst);
            signal.notify();
            let o = h.join().unwrap();
            if let Err(e) = r {
                std::panic::resume_unwind(e);
            }
            o
        })
    }

    /// 条件成立を期限つき（10 秒）で待つ。超えたら panic で失敗させ、無期限に待たない（REPAIR-5）。
    fn wait_kicked(kicks: &AtomicU32) {
        let start = Instant::now();
        while kicks.load(Ordering::SeqCst) == 0 {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "kick was not observed within 10s"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// REPAIR-5・MVM-1（#3736）: 停止要求なしで run が完了すれば kick も immediate_exit も使わない。
    #[test]
    fn mvm1_3736_watch_finished_run_never_kicks() {
        let (sig, done) = (StopSignal::new(), AtomicBool::new(false));
        let (exits, kicks) = (Mutex::new(vec![]), AtomicU32::new(0));
        let o = watch_in_thread(&sig, &done, Duration::from_secs(10), &exits, &kicks, || {
            std::thread::sleep(Duration::from_millis(20));
            done.store(true, Ordering::SeqCst);
            sig.notify();
        });
        assert_eq!(o, WatchOutcome::Finished);
        assert_eq!(kicks.load(Ordering::SeqCst), 0);
        assert!(exits.lock().unwrap().is_empty());
    }

    /// MVM-1・REPAIR-5（#3736）: 停止要求で immediate_exit を立てて kick し、run の完了後は kick を止める。
    #[test]
    fn mvm1_3736_watch_stop_request_sets_exit_then_kicks_until_run_done() {
        let (sig, done) = (StopSignal::new(), AtomicBool::new(false));
        let (exits, kicks) = (Mutex::new(vec![]), AtomicU32::new(0));
        let o = watch_in_thread(&sig, &done, Duration::from_secs(10), &exits, &kicks, || {
            std::thread::sleep(Duration::from_millis(10));
            sig.request();
            wait_kicked(&kicks);
            done.store(true, Ordering::SeqCst);
            sig.notify();
        });
        assert_eq!(o, WatchOutcome::Stopped);
        assert_eq!(*exits.lock().unwrap(), vec![true]);
        let after = kicks.load(Ordering::SeqCst);
        assert!(after >= 1);
        std::thread::sleep(KICK_INTERVAL * 3);
        assert_eq!(kicks.load(Ordering::SeqCst), after);
    }

    /// REPAIR-5・MVM-1（#3736）: run の完了後に停止が要求されても kick を出さない（停止済みスレッドへ送らない）。
    #[test]
    fn mvm1_3736_watch_no_kick_after_run_done_even_if_stop_requested() {
        let (sig, done) = (StopSignal::new(), AtomicBool::new(true));
        let (exits, kicks) = (Mutex::new(vec![]), AtomicU32::new(0));
        sig.request();
        let o = watch_in_thread(&sig, &done, Duration::from_secs(10), &exits, &kicks, || {});
        assert_eq!(o, WatchOutcome::Finished);
        assert_eq!(kicks.load(Ordering::SeqCst), 0);
        assert!(exits.lock().unwrap().is_empty());
    }

    /// MVM-1・REPAIR-5（#3736）: 監視の開始前に要求済みなら、期限を待たず即座に Stopped になる。
    #[test]
    fn mvm1_3736_watch_stop_requested_before_start_fires_immediately() {
        let (sig, done) = (StopSignal::new(), AtomicBool::new(false));
        let (exits, kicks) = (Mutex::new(vec![]), AtomicU32::new(0));
        sig.request();
        let t = Instant::now();
        let o = watch_in_thread(&sig, &done, Duration::from_secs(10), &exits, &kicks, || {
            wait_kicked(&kicks);
            done.store(true, Ordering::SeqCst);
            sig.notify();
        });
        assert_eq!(o, WatchOutcome::Stopped);
        assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    }

    /// REPAIR-5（#3736）: 期限に達したら TimedOut で immediate_exit を立てる。
    #[test]
    fn mvm1_3736_watch_deadline_reports_timed_out() {
        let (sig, done) = (StopSignal::new(), AtomicBool::new(false));
        let (exits, kicks) = (Mutex::new(vec![]), AtomicU32::new(0));
        let o = watch_in_thread(
            &sig,
            &done,
            Duration::from_millis(20),
            &exits,
            &kicks,
            || {
                wait_kicked(&kicks);
                done.store(true, Ordering::SeqCst);
                sig.notify();
            },
        );
        assert_eq!(o, WatchOutcome::TimedOut);
        assert_eq!(*exits.lock().unwrap(), vec![true]);
    }

    /// MVM-1（#3736）: request は冪等で、後から見える。
    #[test]
    fn mvm1_3736_stop_signal_request_is_idempotent_and_visible() {
        let sig = StopSignal::new();
        assert!(!sig.is_requested());
        sig.request();
        sig.request();
        assert!(sig.is_requested());
    }

    /// MVM-1: 上限まで `Interrupted` だけ、または `Hlt` 以外だけなら完了扱いにせず `Internal` で失敗する。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn probe_loop_fails_when_run_limit_reached_without_hlt() {
        let mut calls = 0usize;
        let e = run_probe_loop(|| {
            calls += 1;
            Ok(VcpuExit::Interrupted)
        })
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        assert_eq!(e.message(), "guest did not halt within the probe run limit");
        assert_eq!(calls, 8);
        let e = run_probe_loop(|| Ok(VcpuExit::Shutdown)).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
    }

    /// MVM-1: `Interrupted` はホスト側の中断で、読み飛ばして次の実 exit を返す。上限まで続けば `Internal`。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn run_skipping_interrupted_returns_first_real_exit() {
        let mut seq = vec![VcpuExit::Hlt, VcpuExit::Interrupted, VcpuExit::Interrupted];
        let exit = run_skipping_interrupted(|| Ok(seq.pop().unwrap())).unwrap();
        assert_eq!(exit, VcpuExit::Hlt);
        assert!(seq.is_empty());
        let mut calls = 0usize;
        let e = run_skipping_interrupted(|| {
            calls += 1;
            Ok(VcpuExit::Interrupted)
        })
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::Internal);
        assert_eq!(calls, 8);
        let e = run_skipping_interrupted(|| {
            Err(MicrovmError::new(MicrovmErrorCode::DeadlineExceeded, "x"))
        })
        .unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::DeadlineExceeded);
    }

    /// MVM-1: `Interrupted` を挟んでも `Hlt` で完了すれば `Ok`。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn probe_loop_completes_on_hlt_after_interrupts() {
        let mut seq = vec![VcpuExit::Hlt, VcpuExit::Interrupted, VcpuExit::Interrupted];
        let (exits, interrupted) = run_probe_loop(|| Ok(seq.pop().unwrap())).unwrap();
        assert_eq!(exits, vec![VcpuExit::Hlt]);
        assert_eq!(interrupted, 2);
    }

    #[test]
    fn open_missing_path_is_not_found() {
        let p = std::env::temp_dir().join(format!(
            "fandhe-microvm-missing-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        let e = KvmDevice::open_at(&p).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::NotFound);
        assert_eq!(e.message(), "KVM device not found");
    }

    /// MVM-1: KVM でないデバイスは ioctl が ENOTTY で失敗し FailedPrecondition（unsafe 経路を KVM 無しで通す）。
    #[test]
    fn open_dev_null_is_failed_precondition() {
        let e = KvmDevice::open_at(Path::new("/dev/null")).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "not a KVM device");
    }

    #[test]
    fn classify_open_error_table() {
        let c = |e: io::Error| classify_open_error(&e).code();
        assert_eq!(
            c(io::Error::from(io::ErrorKind::NotFound)),
            MicrovmErrorCode::NotFound
        );
        assert_eq!(
            c(io::Error::from_raw_os_error(EACCES)),
            MicrovmErrorCode::PermissionDenied
        );
        assert_eq!(
            c(io::Error::from_raw_os_error(EPERM)),
            MicrovmErrorCode::PermissionDenied
        );
        assert_eq!(
            c(io::Error::from_raw_os_error(5)),
            MicrovmErrorCode::Internal
        );
        let m = classify_open_error(&io::Error::from_raw_os_error(5));
        assert_eq!(m.message(), "failed to open KVM device (os error 5)");
    }

    #[test]
    fn classify_create_vm_error_table() {
        let c = |e| classify_create_vm_error(e).code();
        assert_eq!(c(SysError::Os(EACCES)), MicrovmErrorCode::PermissionDenied);
        assert_eq!(c(SysError::Os(EPERM)), MicrovmErrorCode::PermissionDenied);
        assert_eq!(c(SysError::Os(ENOMEM)), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(c(SysError::Os(EMFILE)), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(c(SysError::Os(ENFILE)), MicrovmErrorCode::ResourceExhausted);
        assert_eq!(c(SysError::Unsupported), MicrovmErrorCode::Unimplemented);
        let m = classify_vcpu_error(VcpuStage::Mmap, SysError::NullMapping);
        assert_eq!(m.code(), MicrovmErrorCode::Internal);
        assert_eq!(m.message(), "mmap of kvm_run returned a null address");
        let m = classify_create_vm_error(SysError::Os(22));
        assert_eq!(m.code(), MicrovmErrorCode::Internal);
        assert_eq!(m.message(), "KVM_CREATE_VM failed (os error 22)");
    }

    /// 権限なしファイルは非 root で PermissionDenied。root では対照も成功するので期待値を対照に合わせる。
    #[test]
    fn open_unreadable_file_matches_std_behavior() {
        use std::os::unix::fs::PermissionsExt as _;
        let p = std::env::temp_dir().join(format!("fandhe-microvm-perm-{}", std::process::id()));
        std::fs::write(&p, b"").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        let std_denied = OpenOptions::new().read(true).write(true).open(&p).is_err();
        let r = KvmDevice::open_at(&p);
        std::fs::remove_file(&p).unwrap();
        let e = r.unwrap_err();
        if std_denied {
            assert_eq!(e.code(), MicrovmErrorCode::PermissionDenied);
        } else {
            assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        }
    }

    /// MVM-1: KVM の VM fd でない fd への `KVM_CREATE_VCPU` は ENOTTY で FailedPrecondition（KVM 無しで unsafe 経路を通す）。
    #[test]
    fn create_vcpu_on_non_vm_fd_is_failed_precondition() {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        let vm = VmFd {
            fd: OwnedFd::from(f),
            vcpu_mmap_size: 4096 * 3,
        };
        let e = vm.create_vcpu(0).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "not a KVM VM fd");
    }

    /// MVM-1: vCPU mmap サイズの検証表。
    #[test]
    fn validate_mmap_size_table() {
        assert_eq!(validate_mmap_size(12288).unwrap(), 12288);
        for n in [0, 4095, 4097, 2 << 20, 12289] {
            let e = validate_mmap_size(n).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
            assert_eq!(e.message(), format!("unexpected KVM vCPU mmap size {n}"));
        }
    }

    /// MVM-1: KVM_RUN のエラー分類表。
    #[test]
    fn classify_run_error_table() {
        assert_eq!(
            classify_run_error(SysError::Os(EINTR)).unwrap(),
            VcpuExit::Interrupted
        );
        assert_eq!(
            classify_run_error(SysError::Os(EAGAIN)).unwrap(),
            VcpuExit::Interrupted
        );
        let cases = [
            (
                SysError::Os(ENOTTY),
                MicrovmErrorCode::FailedPrecondition,
                "not a KVM vCPU fd",
            ),
            (
                SysError::Os(ENOEXEC),
                MicrovmErrorCode::FailedPrecondition,
                "vCPU not initialized",
            ),
            (
                SysError::Os(ENOMEM),
                MicrovmErrorCode::ResourceExhausted,
                "resource exhausted running vCPU",
            ),
            (
                SysError::Os(14),
                MicrovmErrorCode::Internal,
                "KVM_RUN failed (os error 14)",
            ),
            (
                SysError::Unsupported,
                MicrovmErrorCode::Unimplemented,
                "KVM is not supported on this architecture",
            ),
        ];
        for (e, code, msg) in cases {
            let err = classify_run_error(e).unwrap_err();
            assert_eq!(err.code(), code);
            assert_eq!(err.message(), msg);
        }
    }

    /// MVM-1・TASK-74.2.3: 割り込み通知の ioctl のエラー分類表。
    #[test]
    fn mvm1_879_classify_irq_error_table() {
        use MicrovmErrorCode as C;
        let cases = [
            (
                IrqStage::CreateIrqchip,
                SysError::Os(EEXIST),
                C::AlreadyExists,
            ),
            (IrqStage::Irqfd, SysError::Os(EBUSY), C::AlreadyExists),
            (
                IrqStage::IrqLine,
                SysError::Os(ENXIO),
                C::FailedPrecondition,
            ),
            (IrqStage::IrqLine, SysError::Os(5), C::Internal),
            (IrqStage::Ioeventfd, SysError::Os(EEXIST), C::AlreadyExists),
            (
                IrqStage::CreateIrqchip,
                SysError::Os(EINVAL),
                C::FailedPrecondition,
            ),
            (IrqStage::Irqfd, SysError::Os(EINVAL), C::FailedPrecondition),
            (
                IrqStage::Ioeventfd,
                SysError::Os(EINVAL),
                C::InvalidArgument,
            ),
            (IrqStage::CheckExtension, SysError::Os(EINVAL), C::Internal),
            (
                IrqStage::Ioeventfd,
                SysError::Os(ENOSPC),
                C::ResourceExhausted,
            ),
            (IrqStage::Irqfd, SysError::Os(ENOMEM), C::ResourceExhausted),
            (IrqStage::Irqfd, SysError::Os(EMFILE), C::ResourceExhausted),
            (IrqStage::Irqfd, SysError::Os(ENOTTY), C::FailedPrecondition),
            (IrqStage::Irqfd, SysError::Os(EACCES), C::PermissionDenied),
            (IrqStage::Irqfd, SysError::Os(5), C::Internal),
            (IrqStage::Irqfd, SysError::NullMapping, C::Internal),
            (IrqStage::Irqfd, SysError::Unsupported, C::Unimplemented),
        ];
        for (stage, e, code) in cases {
            assert_eq!(classify_irq_error(stage, e).code(), code, "{stage:?} {e:?}");
        }
        let m = classify_irq_error(IrqStage::Irqfd, SysError::Os(5));
        assert_eq!(m.message(), "KVM_IRQFD failed (os error 5)");
    }

    /// MVM-1・#3696: aarch64 の vGIC（`KVM_CREATE_DEVICE` / `KVM_SET_DEVICE_ATTR` / `KVM_GET_DEVICE_ATTR`）と
    /// 初期化前の irqfd（EAGAIN）のエラー分類表。メッセージは固定の英語で errno 値を載せない（ERR-1）。
    #[test]
    fn mvm1_3696_classify_vgic_error_table() {
        use MicrovmErrorCode as C;
        let cases = [
            // ホストが GICv3 を持たない（GICv2 のみ等）。
            (
                IrqStage::CreateDevice,
                SysError::Os(ENODEV),
                C::FailedPrecondition,
            ),
            (
                IrqStage::CreateDevice,
                SysError::Os(EEXIST),
                C::AlreadyExists,
            ),
            (
                IrqStage::CreateDevice,
                SysError::Os(ENOMEM),
                C::ResourceExhausted,
            ),
            (
                IrqStage::CreateDevice,
                SysError::Os(EACCES),
                C::PermissionDenied,
            ),
            (
                IrqStage::CreateDevice,
                SysError::Unsupported,
                C::Unimplemented,
            ),
            // 初期化済み・vCPU が実行済みの vGIC は EBUSY。
            (
                IrqStage::SetDeviceAttr,
                SysError::Os(EBUSY),
                C::FailedPrecondition,
            ),
            (
                IrqStage::SetDeviceAttr,
                SysError::Os(EEXIST),
                C::AlreadyExists,
            ),
            (
                IrqStage::SetDeviceAttr,
                SysError::Os(EINVAL),
                C::InvalidArgument,
            ),
            (
                IrqStage::GetDeviceAttr,
                SysError::Os(EBUSY),
                C::FailedPrecondition,
            ),
            (
                IrqStage::GetDeviceAttr,
                SysError::Os(ENXIO),
                C::FailedPrecondition,
            ),
            (
                IrqStage::GetDeviceAttr,
                SysError::Os(EINVAL),
                C::FailedPrecondition,
            ),
            (IrqStage::GetDeviceAttr, SysError::Os(5), C::Internal),
            // vGIC の初期化前の irqfd。
            (IrqStage::Irqfd, SysError::Os(EAGAIN), C::FailedPrecondition),
        ];
        for (stage, e, want) in cases {
            let m = classify_irq_error(stage, e);
            assert_eq!(m.code(), want, "{stage:?} {e:?}");
            assert!(!m.message().contains("os error 19"), "errno must not leak");
        }
        assert_eq!(
            classify_irq_error(IrqStage::Irqfd, SysError::Os(EAGAIN)).message(),
            "KVM_IRQFD requires an initialized interrupt controller (vGIC)"
        );
        assert_eq!(
            classify_irq_error(IrqStage::CreateDevice, SysError::Os(ENODEV)).message(),
            "the host does not provide an in-kernel GICv3"
        );
    }

    /// MVM-1・#3696: SPI の pending 読み出しの offset（`GICD_ISPENDR<n>` = `0x200 + 4 * (intid / 32)`）と範囲検査。
    #[test]
    fn mvm1_3696_spi_ispendr_offset() {
        assert_eq!(spi_ispendr_offset(32).unwrap(), 0x204);
        assert_eq!(spi_ispendr_offset(48).unwrap(), 0x204);
        assert_eq!(spi_ispendr_offset(63).unwrap(), 0x204);
        assert_eq!(spi_ispendr_offset(64).unwrap(), 0x208);
        assert_eq!(spi_ispendr_offset(1019).unwrap(), 0x200 + 4 * 31);
        for bad in [0, 31, 1020, u32::MAX] {
            let e = spi_ispendr_offset(bad).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(e.message(), "SPI intid out of range");
        }
    }

    /// MVM-1・#3732: TSS / identity map の ioctl のエラー分類表。
    #[test]
    fn classify_vm_setup_error_table() {
        use MicrovmErrorCode as C;
        use VmSetupStage::{SetIdentityMapAddr as I, SetTssAddr as T};
        let cases = [
            (T, SysError::Unsupported, C::Unimplemented),
            (T, SysError::Os(ENOTTY), C::FailedPrecondition),
            (I, SysError::Os(EINVAL), C::FailedPrecondition),
            (T, SysError::Os(EINVAL), C::InvalidArgument),
            (T, SysError::Os(EEXIST), C::FailedPrecondition),
            (I, SysError::Os(EEXIST), C::FailedPrecondition),
            (T, SysError::Os(EACCES), C::PermissionDenied),
            (I, SysError::Os(EPERM), C::PermissionDenied),
            (T, SysError::Os(ENOMEM), C::ResourceExhausted),
            (I, SysError::Os(ENOSPC), C::ResourceExhausted),
            (T, SysError::Os(EMFILE), C::ResourceExhausted),
            (I, SysError::Os(ENFILE), C::ResourceExhausted),
            (T, SysError::NullMapping, C::Internal),
            (I, SysError::Os(5), C::Internal),
        ];
        for (stage, e, code) in cases {
            assert_eq!(
                classify_vm_setup_error(stage, e).code(),
                code,
                "{stage:?} {e:?}"
            );
        }
        assert_eq!(
            classify_vm_setup_error(T, SysError::Os(5)).message(),
            "KVM_SET_TSS_ADDR failed (os error 5)"
        );
    }

    /// MVM-1・TASK-74.2.3: KVM の VM fd でない fd への登録は FailedPrecondition（KVM 無しで unsafe 経路を通す）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn mvm1_879_irq_registration_on_non_vm_fd_is_failed_precondition() {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        let vm = VmFd {
            fd: OwnedFd::from(f),
            vcpu_mmap_size: 4096 * 3,
        };
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            vm.create_irqchip().unwrap_err().code(),
            MicrovmErrorCode::FailedPrecondition
        );
        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            vm.create_irqchip().unwrap_err().code(),
            MicrovmErrorCode::Unimplemented
        );
        assert_eq!(
            vm.register_irqfd(5).unwrap_err().code(),
            MicrovmErrorCode::FailedPrecondition
        );
        let spec = IoEventSpec::virtio_mmio_queue_notify(0x2000, 0).unwrap();
        assert_eq!(
            vm.register_ioeventfd(spec).unwrap_err().code(),
            MicrovmErrorCode::FailedPrecondition
        );
    }

    /// MVM-1・TASK-75.3.2: レジスタ ioctl の errno 分類（値を message に載せない）。
    #[test]
    fn mvm1_885_classify_regs_error_table() {
        let c = classify_vcpu_error;
        for st in [
            VcpuStage::GetRegs,
            VcpuStage::SetRegs,
            VcpuStage::GetSregs,
            VcpuStage::SetSregs,
        ] {
            let m = c(st, SysError::Os(EINVAL));
            assert_eq!(m.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(m.message(), "KVM rejected the vCPU registers");
            assert_eq!(
                c(st, SysError::Os(ENOTTY)).code(),
                MicrovmErrorCode::FailedPrecondition
            );
            assert_eq!(
                c(st, SysError::Unsupported).code(),
                MicrovmErrorCode::Unimplemented
            );
        }
        let m = c(VcpuStage::SetSregs, SysError::Os(5));
        assert_eq!(m.code(), MicrovmErrorCode::Internal);
        assert_eq!(m.message(), "KVM_SET_SREGS failed (os error 5)");
        let m = c(VcpuStage::GetRegs, SysError::Os(5));
        assert_eq!(m.message(), "KVM_GET_REGS failed (os error 5)");
    }

    #[test]
    fn classify_vcpu_error_table() {
        let c = classify_vcpu_error;
        let m = c(VcpuStage::Create, SysError::Os(EINVAL));
        assert_eq!(m.code(), MicrovmErrorCode::InvalidArgument);
        assert_eq!(m.message(), "invalid vCPU id");
        let m = c(VcpuStage::Create, SysError::Os(EEXIST));
        assert_eq!(m.code(), MicrovmErrorCode::AlreadyExists);
        assert_eq!(m.message(), "vCPU id already exists");
        let m = c(VcpuStage::VcpuInit, SysError::Os(ENOTTY));
        assert_eq!(m.code(), MicrovmErrorCode::FailedPrecondition);
        assert_eq!(m.message(), "not a KVM VM fd");
        for n in [EACCES, EPERM] {
            let m = c(VcpuStage::Create, SysError::Os(n));
            assert_eq!(m.code(), MicrovmErrorCode::PermissionDenied);
        }
        for n in [ENOMEM, EMFILE, ENFILE] {
            let m = c(VcpuStage::Create, SysError::Os(n));
            assert_eq!(m.code(), MicrovmErrorCode::ResourceExhausted);
        }
        let m = c(VcpuStage::Create, SysError::Unsupported);
        assert_eq!(m.code(), MicrovmErrorCode::Unimplemented);
        // aarch64 の初期化段の EINVAL は id の誤りではなく Internal。
        let m = c(VcpuStage::PreferredTarget, SysError::Os(EINVAL));
        assert_eq!(m.code(), MicrovmErrorCode::Internal);
        assert_eq!(m.message(), "KVM_ARM_PREFERRED_TARGET failed (os error 22)");
        let m = c(VcpuStage::VcpuInit, SysError::Os(5));
        assert_eq!(m.message(), "KVM_ARM_VCPU_INIT failed (os error 5)");
        let m = c(VcpuStage::Create, SysError::Os(5));
        assert_eq!(m.message(), "KVM_CREATE_VCPU failed (os error 5)");
    }

    /// MVM-1・#3734: MSR・FPU 系の errno 分類と件数照合。
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn mvm1_3734_msr_fpu_classify_and_count() {
        let c = classify_vcpu_error;
        for st in [VcpuStage::GetMsrs, VcpuStage::SetMsrs] {
            let m = c(st, SysError::Os(E2BIG));
            assert_eq!(m.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(m.message(), "too many MSR entries");
        }
        for st in [
            VcpuStage::GetMsrs,
            VcpuStage::SetMsrs,
            VcpuStage::GetFpu,
            VcpuStage::SetFpu,
        ] {
            let m = c(st, SysError::Os(EINVAL));
            assert_eq!(m.code(), MicrovmErrorCode::InvalidArgument);
            assert_eq!(m.message(), "KVM rejected the vCPU registers");
        }
        assert_eq!(
            c(VcpuStage::SetFpu, SysError::Os(5)).message(),
            "KVM_SET_FPU failed (os error 5)"
        );
        assert!(check_msr_count(255).is_ok());
        assert_eq!(
            check_msr_count(256).unwrap_err().code(),
            MicrovmErrorCode::InvalidArgument
        );
        assert!(check_msr_done("KVM_SET_MSRS", 3, 3).is_ok());
        let e = check_msr_done("KVM_SET_MSRS", 2, 3).unwrap_err();
        assert_eq!(e.code(), MicrovmErrorCode::FailedPrecondition);
        assert_eq!(e.message(), "KVM_SET_MSRS accepted 2 of 3 entries");
    }

    /// MVM-1・REPAIR-5・#3742: `wait_requested` は要求済みなら即 `true`、要求が無ければ期限後に `false`、待ちの途中の要求で期限前に `true`。
    #[test]
    fn mvm1_3742_stop_signal_wait_requested() {
        let sig = Arc::new(StopSignal::new());
        let t = Instant::now();
        assert!(!sig.wait_requested(Duration::from_millis(20)));
        assert!(t.elapsed() >= Duration::from_millis(20));
        let s2 = Arc::clone(&sig);
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            s2.request();
        });
        let t = Instant::now();
        assert!(sig.wait_requested(Duration::from_secs(10)));
        assert!(t.elapsed() < Duration::from_secs(5));
        h.join().unwrap();
        let t = Instant::now();
        assert!(sig.wait_requested(Duration::from_secs(10)));
        assert!(t.elapsed() < Duration::from_secs(1));
    }
}
