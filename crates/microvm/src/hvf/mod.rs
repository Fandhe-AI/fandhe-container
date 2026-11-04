//! macOS（Apple Silicon）の Hypervisor.framework バックエンドの入口（TASK-192.1・#3783・MVM-5・MVM-4）。
//!
//! `sys`（`src/sys/hvf.rs`）の安全な型を再公開するだけで、`unsafe` を持たない。結合試験
//! （`tests/hvf_device.rs`）と、後続の子 issue（#3786 vCPU・#3789 GIC・#3787 ゲスト RAM = `memory`・#3792 GIC の作成順序 = `gic`・#3795 SPI の注入 = `gic::GicSpiLine`）が
//! ここへ追記する。引数の検査と戻り値の写像は OS 非依存の `crate::hvf_abi`。
//! TASK-192.16・#3798: microVM の start / stop と解放順序（`microvm::{HvfMicroVm, RunningHvfMicroVm}`）。
//! TASK-192.9・#3791: vCPU 専用スレッド（`vcpu`）と exit ごとのスタブ（`mmio`・`hvc`・`timer`）。ループ本体は OS 非依存の `crate::hvf_loop`。

pub use crate::sys::{GicApi, GuestMapping, HostMapping, HvVcpu, HvVm, VcpuCanceller};

pub mod memory;
pub use memory::{HvfGuestRam, RegisteredHvfRam};

// TASK-192.9・#3791: vCPU 専用スレッドと実行ループの外殻（論理は OS 非依存の `crate::hvf_loop`）。
// exit ごとの処理は `mmio`（#3793 で実装済み）・`hvc`（#3794 で実装済み。`crate::psci`）・`timer`（#3796）で、`timer` はスタブのまま担当 issue がファイルだけを差し替える。
pub mod hvc;
pub mod mmio;
pub mod timer;
pub mod vcpu;
pub use vcpu::{ExitHandlers, VcpuHandle, VcpuThread, VcpuThreadConfig};
pub mod gic;
pub use gic::{GicSpiLine, HvfGic, VmWithGic};

// TASK-192.15・#3797: microVM 構成体（VM・GIC・ゲスト RAM・virtio-mmio・vCPU 0 の起動レジスタの組み立て）。
pub mod microvm;
pub use microvm::{
    HvfDeviceInfo, HvfDeviceKind, HvfMicroVm, HvfMicroVmConfig, HvfNetDeviceConfig,
    RunningHvfMicroVm,
};
// TASK-192.16・#3798: start / stop と解放順序（OS 非依存コアは `crate::hvf_lifecycle`）。
pub use crate::hvf_lifecycle::HvfStopReport;
