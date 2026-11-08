//! KVM の ioeventfd / irqfd と eventfd の所有型（TASK-74.2.3・MVM-1・MVM-4。Linux のみ・`unsafe` なし）。
//!
//! 呼び出し文脈: `crate::device::VmFd::register_irqfd` / `register_ioeventfd` が `crate::sys` の
//! `KVM_IRQFD` / `KVM_IOEVENTFD` を発行して [`IrqFd`] / [`IoEventFd`] を返す。[`IrqFd`] は
//! `crate::interrupt::InterruptLine` を実装し、`signal` で書いた eventfd を KVM が GSI の割り込みに変える。
//! [`IoEventFd`] はゲストの `QueueNotify` 書き込み（VM exit なし）で発火する eventfd を持ち、
//! [`IoEventFd::consume`] で回数を読む。[`IrqFd`]・[`IoEventFd`] はどちらも VM fd を dup して所有する（VM 構成体が VM fd と
//! 一緒に保持できる。TASK-75.2・#3698）。どちらも drop で登録を解く。
//! #3918 で x86_64 の COM1 用に `KVM_IRQ_LINE` の level 線 `IrqLevelLine`（x86_64 のみ）を足した（`VmFd::register_irq_line` が返す）。
//! #3943 で aarch64 のシリアルの SPI（INTID 33）にも同じ線を広げた（`VmFd::register_spi_line`。`irq` は `Arm64SpiIrqLine` のエンコード）。
//!
//! # 待ちを持たない設計（REPAIR-5）
//! eventfd は非ブロックで、読み取りは [`EventFd::consume`] のみ（`WouldBlock` は 0 件）。この module 自体は待たない。
//! `assemble` が結んだ ioeventfd を期限つきの `poll(2)` で待つ通知スレッドは `crate::microvm` の `IoEventPoller`（#3698。
//! 待ちは `crate::sys::poll_readable`）が持つ。
//!
//! # 残余（REPAIR-3・REPAIR-4）
//! drop 時の `KVM_IRQFD` / `KVM_IOEVENTFD` の解除が失敗しても panic せず待たない。失敗は種別ごとの件数
//! （[`deassign_failures`]）と構造化ログ 1 行（`op=kvm.irqfd.deassign` / `op=kvm.ioeventfd.deassign`。`level=error`・
//! `released=false`）で観測できる（#3679・REPAIR-4）。その場合、カーネルは eventfd の file を VM の破棄まで保持するだけで、
//! VM fd を close すれば解放される。ただし登録が残った組は、同じ VM で次の ASSIGN が `EBUSY` / `EEXIST` で失敗しうる。
//! VM ごとの解除失敗の件数は `IoEventTally`（`IoEventFd::with_tally`）が数え、`StopReport::ioevent` と
//! `fandhe-container-plugin-microvm` の stop の結果行（`unbind_failed=`）へ出る（#4161）。irqfd の件数の露出は未実装（REPAIR-3）。

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::interrupt::{InterruptLine, IoEventAddress, IoEventSpec, IoEventTally};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::interrupt::{IrqLevel, LevelInterruptLine};
use crate::sys::{self, SysError};

fn io_error(what: &str, e: &io::Error) -> MicrovmError {
    MicrovmError::new(
        MicrovmErrorCode::Internal,
        format!(
            "eventfd {what} failed (os error {})",
            e.raw_os_error().unwrap_or(0)
        ),
    )
}

/// ある種別の解除失敗の累計（プロセス全体）。`last_os_error` の 0 は errno の記録なし（#3679・REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeassignFailureStat {
    /// 解除（`KVM_IRQFD` / `KVM_IOEVENTFD` の DEASSIGN）が失敗した回数。
    pub count: u64,
    /// 直近の失敗の errno（0 は記録なし）。
    pub last_os_error: i32,
}

/// [`IrqFd`] / [`IoEventFd`] の drop での解除失敗の累計（#3679・REPAIR-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeassignFailures {
    /// [`IrqFd`] の解除失敗。
    pub irqfd: DeassignFailureStat,
    /// [`IoEventFd`] の解除失敗。
    pub ioeventfd: DeassignFailureStat,
}

static IRQFD_DEASSIGN_COUNT: AtomicU64 = AtomicU64::new(0);
static IRQFD_DEASSIGN_ERRNO: AtomicI32 = AtomicI32::new(0);
static IOEVENTFD_DEASSIGN_COUNT: AtomicU64 = AtomicU64::new(0);
static IOEVENTFD_DEASSIGN_ERRNO: AtomicI32 = AtomicI32::new(0);

/// drop での解除失敗の累計を返す。プロセス全体の値で、`Relaxed`（観測用で他のデータを公開しない）。
///
/// 呼び出し元は診断・試験。登録が残った組は VM fd の close まで残る（モジュール doc の残余）。
pub fn deassign_failures() -> DeassignFailures {
    DeassignFailures {
        irqfd: DeassignFailureStat {
            count: IRQFD_DEASSIGN_COUNT.load(Ordering::Relaxed),
            last_os_error: IRQFD_DEASSIGN_ERRNO.load(Ordering::Relaxed),
        },
        ioeventfd: DeassignFailureStat {
            count: IOEVENTFD_DEASSIGN_COUNT.load(Ordering::Relaxed),
            last_os_error: IOEVENTFD_DEASSIGN_ERRNO.load(Ordering::Relaxed),
        },
    }
}

/// 失敗の errno（`Os` のときだけ）。
fn os_error_of(e: &SysError) -> Option<i32> {
    match e {
        SysError::Os(n) => Some(*n),
        _ => None,
    }
}

/// `code=` の固定語彙と、`os_error=` の付記（errno があるときだけ）。値は数値と固定語彙のみ。
fn deassign_code_fields(e: &SysError) -> (&'static str, String) {
    match e {
        SysError::Unsupported => ("UNIMPLEMENTED", String::new()),
        SysError::NullMapping => ("INTERNAL", String::new()),
        SysError::Os(n) => ("INTERNAL", format!(" os_error={n}")),
    }
}

/// irqfd の解除失敗の構造化ログ 1 行（REPAIR-4）。
pub(crate) fn irqfd_deassign_log_line(gsi: u32, e: &SysError) -> String {
    let (code, os) = deassign_code_fields(e);
    format!(
        "level=error op=kvm.irqfd.deassign outcome=error code={code} gsi={gsi}{os} released=false"
    )
}

/// ioeventfd の解除失敗の構造化ログ 1 行（REPAIR-4）。
pub(crate) fn ioeventfd_deassign_log_line(
    addr: u64,
    pio: bool,
    len: u32,
    datamatch: Option<u64>,
    e: &SysError,
) -> String {
    let (code, os) = deassign_code_fields(e);
    let dm = datamatch.map_or_else(|| "none".to_string(), |d| format!("{d:#x}"));
    format!(
        "level=error op=kvm.ioeventfd.deassign outcome=error code={code} addr={addr:#x} pio={pio} len={len} datamatch={dm}{os} released=false"
    )
}

/// 非ブロック・close-on-exec の eventfd。
#[derive(Debug)]
pub struct EventFd(File);

impl EventFd {
    /// 初期値 0 の eventfd を作る。
    pub fn new() -> Result<Self, MicrovmError> {
        sys::eventfd_new()
            .map(|fd| EventFd(File::from(fd)))
            .map_err(|e| match e {
                SysError::Unsupported => MicrovmError::new(
                    MicrovmErrorCode::Unimplemented,
                    "KVM is not supported on this architecture",
                ),
                SysError::NullMapping => MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    "eventfd failed (unexpected null mapping)",
                ),
                SysError::Os(n) if n == 24 || n == 23 => MicrovmError::new(
                    MicrovmErrorCode::ResourceExhausted,
                    format!("resource exhausted creating eventfd (os error {n})"),
                ),
                SysError::Os(n) => MicrovmError::new(
                    MicrovmErrorCode::Internal,
                    format!("eventfd failed (os error {n})"),
                ),
            })
    }

    /// カウンタに 1 を加える（読み手が `consume` するか、KVM が割り込みへ変える）。
    pub fn signal(&self) -> Result<(), MicrovmError> {
        (&self.0)
            .write_all(&1u64.to_ne_bytes())
            .map_err(|e| io_error("write", &e))
    }

    /// カウンタを読んで 0 に戻す。0 のときは待たずに 0 を返す。
    pub fn consume(&self) -> Result<u64, MicrovmError> {
        let mut buf = [0u8; 8];
        match (&self.0).read_exact(&mut buf) {
            Ok(()) => Ok(u64::from_ne_bytes(buf)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(io_error("read", &e)),
        }
    }
}

impl AsFd for EventFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// `KVM_IRQFD` で GSI に結んだ eventfd。[`InterruptLine`] として割り込みを注入する。
///
/// VM fd の dup を所有するので借用を持たず、VM 構成体（TASK-75.2）が VM fd と同じ構造体に保持できる。
/// drop の解除は dup した fd で発行するため、VM fd 本体より後に drop されても効く。
#[derive(Debug)]
pub struct IrqFd {
    vm: OwnedFd,
    event: EventFd,
    gsi: u32,
}

impl IrqFd {
    pub(crate) fn registered(vm: OwnedFd, event: EventFd, gsi: u32) -> Self {
        Self { vm, event, gsi }
    }

    /// 結んだ GSI。
    pub fn gsi(&self) -> u32 {
        self.gsi
    }
}

impl InterruptLine for IrqFd {
    fn trigger(&self) -> Result<(), MicrovmError> {
        self.event.signal()
    }
}

impl Drop for IrqFd {
    fn drop(&mut self) {
        if let Err(e) = sys::kvm_irqfd(self.vm.as_fd(), self.event.as_fd(), self.gsi, true) {
            IRQFD_DEASSIGN_ERRNO.store(os_error_of(&e).unwrap_or(0), Ordering::Relaxed);
            IRQFD_DEASSIGN_COUNT.fetch_add(1, Ordering::Relaxed);
            // 上限つき try_send で待たず、満杯なら捨てる（件数は残る。REPAIR-5）。
            crate::hvf_loop::log_line(format_args!("{}", irqfd_deassign_log_line(self.gsi, &e)));
        }
    }
}

/// `KVM_IRQ_LINE` で割り込み線を駆動する level 線（x86_64 は GSI、aarch64 は vGIC の SPI。#3918・#3943・MVM-1・REPAIR-3）。
///
/// 呼び出し元は `SerialConsole::port_device_with_irq`（UART のモデルが線の値を決めて `set_level` で伝える。
/// `crate::microvm::assemble` が COM1 = IRQ 4 に結ぶ）。edge 注入の [`IrqFd`] と違い線の値を持つので level 線に使える。
///
/// # 設計
/// resamplefd（`KVM_IRQFD_FLAG_RESAMPLE`）は level に設定された pin の EOI でだけ働く。Linux は MP テーブル
/// （ISA の既定 = edge・active high）に従い IRQ 4 を edge に設定するため使えない。`KVM_IRQ_LINE` は pin が edge でも level でも
/// 働く同期・非ブロックの ioctl 1 回で済み、スレッドも要らない（待ちを持たないので REPAIR-5 のタイムアウトは不要）。
/// edge の pin では 0 から 1 の遷移でだけ配送されるが、モデルは要因が消えたときに線を下げ変化時だけ伝えるので、
/// 新しい要因ごとに立ち上がりが 1 回起きる。ISR が最後の IIR 読み出しの後 `iret` の前に入力が届くと余分な配送が 1 回起きるが、
/// そのときの IIR は 0x01（`IRQ_NONE`）で無害。
///
/// # aarch64（#3943）
/// `irq` フィールドは `Arm64SpiIrqLine` のエンコード（種別 SPI = 1 を 24 ビット目、INTID を下位 16 ビット。INTID 33 で `0x0100_0021`）。
/// irqfd の GSI は SPI 番号（`GuestSpi::dt_cell()` = 1）だが、`KVM_IRQ_LINE` は INTID（`GuestSpi::intid()` = 33）を取る。
/// 取り違えるとカーネルは `EINVAL`（INTID < 32）か別の SPI を駆動する。vGIC が level の SPI の `line_level` を保持するので
/// resamplefd は要らない（`reject_level_spi` が irqfd / virtio の level を拒否するのとは別の話で、ここは「直さない」こと）。
///
/// VM fd の dup を所有する。drop では何もしない（VM fd が全部 close されると irqchip ごと破棄され、線の deassert は不要）。
/// カーネルの一次情報は v6.12 の `include/uapi/linux/kvm.h`（`struct kvm_irq_level`・`KVM_IRQ_LINE`）と `arch/x86/kvm/x86.c` の
/// `kvm_vm_ioctl_irq_line`（irqchip が無いと `-ENXIO`。結果の書き戻しは `KVM_IRQ_LINE_STATUS` だけ）。
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[derive(Debug)]
pub struct IrqLevelLine {
    vm: OwnedFd,
    irq: u32,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl IrqLevelLine {
    pub(crate) fn new(vm: OwnedFd, irq: u32) -> Self {
        Self { vm, irq }
    }

    /// `kvm_irq_level.irq` に入れる値（x86_64 は GSI、aarch64 は SPI のエンコード済みの値）。
    pub fn irq(&self) -> u32 {
        self.irq
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl LevelInterruptLine for IrqLevelLine {
    fn set_level(&self, level: IrqLevel) -> Result<(), MicrovmError> {
        sys::kvm_irq_line(self.vm.as_fd(), self.irq, level == IrqLevel::High).map_err(|e| {
            MicrovmError::new(
                MicrovmErrorCode::Internal,
                format!("KVM_IRQ_LINE failed ({e:?})"),
            )
        })
    }
}

/// aarch64 の `KVM_IRQ_LINE` に渡す SPI の `irq` フィールド（種別 SPI + INTID）。壊れた値を表せない型（#3943・REPAIR-2）。
///
/// INTID は SPI の範囲 32..=1019 に限る（範囲外は `InvalidArgument`。1020 以上は特殊 INTID、31 以下は SGI / PPI で
/// カーネルも `EINVAL`）。`crate::arm64_layout::GuestSpi::intid` の値から作る。x86_64 でも単体試験が走るよう arch で外さない。
/// 一次情報は Linux v6.12 の `arch/arm64/include/uapi/asm/kvm.h`（`KVM_ARM_IRQ_*`）と `arch/arm64/kvm/arm.c` の `kvm_vm_ioctl_irq_line`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub(crate) struct Arm64SpiIrqLine(u32);

#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
impl Arm64SpiIrqLine {
    /// SPI の INTID（32..=1019）から作る。
    pub(crate) fn from_intid(intid: u32) -> Result<Self, MicrovmError> {
        if !(32..=1019).contains(&intid) {
            return Err(MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "spi intid is outside 32..=1019",
            ));
        }
        sys::arm64_spi_irq_field(intid).map(Self).ok_or_else(|| {
            MicrovmError::new(MicrovmErrorCode::InvalidArgument, "spi intid does not fit")
        })
    }

    /// `kvm_irq_level.irq` にそのまま入れる値。
    pub(crate) fn raw(self) -> u32 {
        self.0
    }
}

/// `KVM_IOEVENTFD` で結んだ eventfd。ゲストの対象アドレスへの書き込みで発火する（VM exit なし）。
///
/// [`IrqFd`] と同じく VM fd の dup を所有するので借用を持たず、VM 構成体（`crate::microvm::MicroVm`）が VM fd と同じ構造体に
/// 保持できる（#3698）。drop の解除は dup した fd で発行するため、VM fd 本体より後に drop されても効く。
#[derive(Debug)]
pub struct IoEventFd {
    vm: OwnedFd,
    event: EventFd,
    spec: IoEventSpec,
    /// 解除失敗を VM ごとに数える先（#4161）。無ければ全体の static だけを更新する。
    tally: Option<Arc<IoEventTally>>,
}

impl IoEventFd {
    pub(crate) fn registered(vm: OwnedFd, event: EventFd, spec: IoEventSpec) -> Self {
        Self {
            vm,
            event,
            spec,
            tally: None,
        }
    }

    /// drop での解除失敗を `tally` にも数える（`MicroVm` の組み立てが VM ごとの 1 つを渡す。#4161・REPAIR-4）。
    pub(crate) fn with_tally(mut self, tally: Arc<IoEventTally>) -> Self {
        self.tally = Some(tally);
        self
    }

    /// 監視条件。
    pub fn spec(&self) -> IoEventSpec {
        self.spec
    }

    /// 発火回数を読んで 0 に戻す（待たない）。
    pub fn consume(&self) -> Result<u64, MicrovmError> {
        self.event.consume()
    }
}

impl AsFd for IoEventFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.event.as_fd()
    }
}

/// `spec` を `sys::kvm_ioeventfd` の引数（アドレス・PIO か）へ展開する。
pub(crate) fn ioevent_args(spec: &IoEventSpec) -> (u64, bool) {
    match spec.address() {
        IoEventAddress::Mmio(a) => (a, false),
        IoEventAddress::Pio(p) => (u64::from(p), true),
    }
}

impl Drop for IoEventFd {
    fn drop(&mut self) {
        let (addr, pio) = ioevent_args(&self.spec);
        if let Err(e) = sys::kvm_ioeventfd(
            self.vm.as_fd(),
            self.event.as_fd(),
            addr,
            self.spec.len(),
            self.spec.datamatch(),
            pio,
            true,
        ) {
            IOEVENTFD_DEASSIGN_ERRNO.store(os_error_of(&e).unwrap_or(0), Ordering::Relaxed);
            IOEVENTFD_DEASSIGN_COUNT.fetch_add(1, Ordering::Relaxed);
            if let Some(t) = &self.tally {
                t.record_unbind_failed();
            }
            crate::hvf_loop::log_line(format_args!(
                "{}",
                ioeventfd_deassign_log_line(addr, pio, self.spec.len(), self.spec.datamatch(), &e)
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MVM-1・#3943: SPI の `irq` フィールドは INTID 33 で `0x0100_0021`、範囲外は `InvalidArgument`（全 arch で走る）。
    #[test]
    fn mvm1_3943_arm64_spi_irq_line_encoding() {
        assert_eq!(Arm64SpiIrqLine::from_intid(33).unwrap().raw(), 0x0100_0021);
        assert_eq!(Arm64SpiIrqLine::from_intid(32).unwrap().raw(), 0x0100_0020);
        assert_eq!(
            Arm64SpiIrqLine::from_intid(1019).unwrap().raw(),
            0x0100_03fb
        );
        for bad in [0, 1, 31, 1020, 0x1_0000, u32::MAX] {
            let e = Arm64SpiIrqLine::from_intid(bad).unwrap_err();
            assert_eq!(e.code(), MicrovmErrorCode::InvalidArgument, "intid {bad}");
        }
    }

    /// MVM-1・TASK-74.2.3: eventfd の signal / consume は回数を合算し、空なら待たずに 0。
    #[test]
    fn mvm1_879_event_fd_counts_without_blocking() {
        let e = EventFd::new().unwrap();
        assert_eq!(e.consume().unwrap(), 0);
        e.signal().unwrap();
        e.signal().unwrap();
        e.signal().unwrap();
        assert_eq!(e.consume().unwrap(), 3);
        assert_eq!(e.consume().unwrap(), 0);
    }

    #[test]
    fn mvm1_879_ioevent_args_mapping() {
        let mmio = IoEventSpec::virtio_mmio_queue_notify(0x2000, 0).unwrap();
        assert_eq!(ioevent_args(&mmio), (0x2050, false));
        let pio = IoEventSpec::new(IoEventAddress::Pio(0x10), 1, None).unwrap();
        assert_eq!(ioevent_args(&pio), (0x10, true));
    }

    /// REPAIR-4・#3679: irqfd の解除失敗（`/dev/null` は ioctl に ENOTTY を返す）が件数と errno で観測できる。
    /// 件数はプロセス全体の値なので、この種別を失敗させる試験はこれ 1 件だけにして差分で照合する。
    #[cfg(all(
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn repair4_3679_irqfd_deassign_failure_is_observable() {
        let before = deassign_failures().irqfd.count;
        let vm = OwnedFd::from(File::open("/dev/null").unwrap());
        drop(IrqFd::registered(vm, EventFd::new().unwrap(), 5));
        let after = deassign_failures().irqfd;
        assert_eq!(after.count, before + 1);
        assert_eq!(after.last_os_error, 25);
    }

    /// REPAIR-4・#3679: ioeventfd の解除失敗の観測（件数の差分と errno）。この種別を失敗させる試験はこれ 1 件だけ。
    #[cfg(all(
        target_env = "gnu",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn repair4_3679_ioeventfd_deassign_failure_is_observable() {
        let before = deassign_failures().ioeventfd.count;
        let null = OwnedFd::from(File::open("/dev/null").unwrap());
        let spec = IoEventSpec::virtio_mmio_queue_notify(0x2000, 0).unwrap();
        let tally = Arc::new(IoEventTally::default());
        drop(
            IoEventFd::registered(null, EventFd::new().unwrap(), spec)
                .with_tally(Arc::clone(&tally)),
        );
        let after = deassign_failures().ioeventfd;
        assert_eq!(after.count, before + 1);
        assert_eq!(after.last_os_error, 25);
        // #4161: VM ごとの件数にも載る（具体値）。
        assert_eq!(tally.snapshot(), crate::interrupt::IoEventCounts::new(0, 1));
    }

    /// REPAIR-4・#3679: ログ行は数値と固定語彙のみ（完全一致）。
    #[test]
    fn repair4_3679_deassign_log_line_values() {
        assert_eq!(
            irqfd_deassign_log_line(5, &SysError::Os(25)),
            "level=error op=kvm.irqfd.deassign outcome=error code=INTERNAL gsi=5 os_error=25 released=false"
        );
        assert_eq!(
            irqfd_deassign_log_line(5, &SysError::Unsupported),
            "level=error op=kvm.irqfd.deassign outcome=error code=UNIMPLEMENTED gsi=5 released=false"
        );
        assert_eq!(
            ioeventfd_deassign_log_line(0x2050, false, 4, None, &SysError::Os(25)),
            "level=error op=kvm.ioeventfd.deassign outcome=error code=INTERNAL addr=0x2050 pio=false len=4 datamatch=none os_error=25 released=false"
        );
        assert_eq!(
            ioeventfd_deassign_log_line(0x10, true, 1, Some(0), &SysError::NullMapping),
            "level=error op=kvm.ioeventfd.deassign outcome=error code=INTERNAL addr=0x10 pio=true len=1 datamatch=0x0 released=false"
        );
    }
}
