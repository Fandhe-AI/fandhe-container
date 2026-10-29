//! macOS 実機の VM 起動試験が共有する、ゲスト資産の環境変数解決と spec の組み立て（MAC-1・MAC-2・REPAIR-1・#3351）。
//!
//! `vm_boot.rs`（MAC-1・TASK-64.6）と `vm_cold_start.rs`（MAC-2・TASK-70 準備）の実機試験が、同じ環境変数
//! （kernel・initrd・disk・cmdline）の読み取りと同じ `VmConfigSpec` の組み立てを複製していたため 1 本にまとめる。
//! `Vm::launch` の呼び出し・待ちループ・期限は各試験に残す（計測の意味が違うため共通化しない）。
//!
//! 取り込み側は `vm_boot.rs`・`vm_cold_start.rs` に加え、`virtiofs_io.rs`・`virtiofs_link.rs`（#3456）。
//! kernel 未設定時の panic 文言は呼び出し側が渡す。`virtiofs_link.rs` は disk を使わない（読むだけで無視する）。
//!
//! 取り込み側は macOS 限定にし、`#[path = "support/common.rs"] mod common;` を先にトップレベルで宣言すること
//! （本ファイルは `super::common` を参照する）。

use std::path::{Path, PathBuf};

use fandhe_container_platform_macos::config::{
    BlockDeviceSpec, ConsoleLogPath, DeviceConfigSpec, DiskImagePath, SerialConsoleSink,
    VmConfigSpec,
};

use super::common::env_path;

/// 環境変数で渡されるゲスト資産（呼び出し側が用意したものを信頼する前提）。
pub struct GuestAssets {
    pub kernel: PathBuf,
    pub initrd: Option<PathBuf>,
    #[allow(
        dead_code,
        reason = "取り込み側の試験 target によっては使わない（各 tests/*.rs は別 crate）"
    )]
    pub disk: Option<PathBuf>,
    pub cmdline: String,
}

impl GuestAssets {
    /// kernel（必須）・initrd・disk・cmdline（既定 `console=hvc0`）を読む。kernel が無ければ
    /// `missing_kernel_help` を載せて panic する（黙って成功させない）。
    pub fn from_env(missing_kernel_help: &str) -> Self {
        let kernel = env_path("FANDHE_CONTAINER_MACOS_VM_KERNEL")
            .unwrap_or_else(|| panic!("{missing_kernel_help}"));
        Self {
            kernel,
            initrd: env_path("FANDHE_CONTAINER_MACOS_VM_INITRD"),
            disk: env_path("FANDHE_CONTAINER_MACOS_VM_DISK_IMAGE"),
            cmdline: std::env::var("FANDHE_CONTAINER_MACOS_VM_CMDLINE")
                .unwrap_or_else(|_| "console=hvc0".to_string()),
        }
    }
}

/// ゲスト資産とコンソールログから `VmConfigSpec` を組み立てる。VM を持つ前なので設定誤りは panic でよい。
#[allow(
    dead_code,
    reason = "取り込み側の試験 target によっては使わない（各 tests/*.rs は別 crate）"
)]
pub fn console_boot_spec(g: &GuestAssets, log: &Path) -> VmConfigSpec {
    let blocks = g
        .disk
        .iter()
        .map(|p| BlockDeviceSpec::root(DiskImagePath::try_new(p).expect("disk image path")))
        .collect();
    let devices = DeviceConfigSpec::try_new(
        blocks,
        Some(SerialConsoleSink::LogFile(
            ConsoleLogPath::try_new(log).expect("console log path"),
        )),
    )
    .expect("device spec");
    VmConfigSpec::from_parts(&g.kernel, g.initrd.as_deref(), &g.cmdline)
        .expect("spec")
        .with_devices(devices)
        .expect("with_devices")
}
