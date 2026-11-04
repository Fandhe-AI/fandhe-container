//! macOS（Apple Silicon）の Hypervisor.framework バックエンドの入口（TASK-192.1・#3783・MVM-5・MVM-4）。
//!
//! `sys`（`src/sys/hvf.rs`）の安全な型を再公開するだけで、`unsafe` を持たない。結合試験
//! （`tests/hvf_device.rs`）と、後続の子 issue（#3786 vCPU・#3789 GIC・#3787 ゲスト RAM = `memory`・#3792 GIC の作成順序 = `gic`・#3795 SPI の注入 = `gic::GicSpiLine`）が
//! ここへ追記する。引数の検査と戻り値の写像は OS 非依存の `crate::hvf_abi`。

pub use crate::sys::{GicApi, GicConfig, GuestMapping, HostMapping, HvVcpu, HvVm, VcpuCanceller};

pub mod memory;
pub use memory::{HvfGuestRam, RegisteredHvfRam};

pub mod gic;
pub use gic::{GicSpiLine, HvfGic, VmWithGic};
