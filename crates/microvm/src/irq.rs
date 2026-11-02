//! KVM の ioeventfd / irqfd と eventfd の所有型（TASK-74.2.3・MVM-1・MVM-4。Linux のみ・`unsafe` なし）。
//!
//! 呼び出し文脈: `crate::device::VmFd::register_irqfd` / `register_ioeventfd` が `crate::sys` の
//! `KVM_IRQFD` / `KVM_IOEVENTFD` を発行して [`IrqFd`] / [`IoEventFd`] を返す。[`IrqFd`] は
//! `crate::interrupt::InterruptLine` を実装し、`signal` で書いた eventfd を KVM が GSI の割り込みに変える。
//! [`IoEventFd`] はゲストの `QueueNotify` 書き込み（VM exit なし）で発火する eventfd を持ち、
//! [`IoEventFd::consume`] で回数を読む。[`IrqFd`] は VM fd を dup して所有する（VM 構成体が VM fd と一緒に保持できる。TASK-75.2）。
//! [`IoEventFd`] は `'vm` の借用。どちらも drop で登録を解く。
//!
//! # 待ちを持たない設計（REPAIR-5）
//! eventfd は非ブロックで、読み取りは [`EventFd::consume`] のみ（`WouldBlock` は 0 件）。`poll` / `epoll` で
//! 待つ常駐のイベントループは起動フロー（TASK-75）・`fandhe-container-plugin-microvm`（TASK-117）の範囲で未実装。
//!
//! # 残余（REPAIR-3）
//! drop 時の `KVM_IRQFD` / `KVM_IOEVENTFD` の解除が失敗しても戻り値は無視する（panic しない）。その場合、カーネルは
//! eventfd の file を VM の破棄まで保持するだけで、VM fd を close すれば解放される。

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::interrupt::{InterruptLine, IoEventAddress, IoEventSpec};
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
        let _ = sys::kvm_irqfd(self.vm.as_fd(), self.event.as_fd(), self.gsi, true);
    }
}

/// `KVM_IOEVENTFD` で結んだ eventfd。ゲストの対象アドレスへの書き込みで発火する（VM exit なし）。
#[derive(Debug)]
pub struct IoEventFd<'vm> {
    vm: BorrowedFd<'vm>,
    event: EventFd,
    spec: IoEventSpec,
}

impl<'vm> IoEventFd<'vm> {
    pub(crate) fn registered(vm: BorrowedFd<'vm>, event: EventFd, spec: IoEventSpec) -> Self {
        Self { vm, event, spec }
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

impl AsFd for IoEventFd<'_> {
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

impl Drop for IoEventFd<'_> {
    fn drop(&mut self) {
        let (addr, pio) = ioevent_args(&self.spec);
        let _ = sys::kvm_ioeventfd(
            self.vm,
            self.event.as_fd(),
            addr,
            self.spec.len(),
            self.spec.datamatch(),
            pio,
            true,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
