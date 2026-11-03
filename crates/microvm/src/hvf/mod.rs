//! macOS（Apple Silicon）の Hypervisor.framework バックエンドの入口（TASK-192.1・#3783・MVM-5・MVM-4）。
//!
//! `sys`（`src/sys/hvf.rs`）の安全な型を再公開するだけで、`unsafe` を持たない。結合試験
//! （`tests/hvf_device.rs`）と、後続の子 issue（#3786 vCPU・#3789 GIC・#3787 ゲスト RAM = `memory`）が
//! ここへ追記する。引数の検査と戻り値の写像は OS 非依存の `crate::hvf_abi`。
//! TASK-192.9・#3791: vCPU 専用スレッド（`vcpu`）と exit ごとのスタブ（`mmio`・`hvc`・`timer`）。ループ本体は OS 非依存の `crate::hvf_loop`。

pub use crate::sys::{GuestMapping, HostMapping, HvVcpu, HvVm, VcpuCanceller};

pub mod memory;
pub use memory::{HvfGuestRam, RegisteredHvfRam};

// TASK-192.9・#3791: vCPU 専用スレッドと実行ループの外殻（論理は OS 非依存の `crate::hvf_loop`）。
// exit ごとの処理 `mmio`（#3793）・`hvc`（#3794）・`timer`（#3796）はスタブで、担当 issue が各ファイルだけを差し替える。
pub mod hvc;
pub mod mmio;
pub mod timer;
pub mod vcpu;
pub use vcpu::{ExitHandlers, VcpuHandle, VcpuThread, VcpuThreadConfig};
