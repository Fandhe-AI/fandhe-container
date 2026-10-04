#![cfg(target_os = "macos")]
//! objc2 / Virtualization.framework の FFI 呼び出しを包む薄いラッパーの置き場（MAC-1・TASK-64.1/64.2）。
//!
//! 上位モジュール（`config`）へは安全な API だけを公開し、`unsafe fn` を本モジュールの外へ公開しない。
//! 各 `unsafe` は `// SAFETY:` で不変条件を明記し、`.claude/rules/coding-rust.md` の事前承認（#4）の
//! 条件（security-auditor 観点のレビュー・PR 本文の unsafe 一覧）を満たす。
//!
//! 共通の不変条件: 引数は `Retained` / 参照で生存期間が保証された有効な Objective-C オブジェクトで、
//! セレクタと型シグネチャは objc2-virtualization 0.3.2 の生成バインディングと一致する。ここで呼ぶ
//! setter / getter は ObjC 例外を投げない（objc2 の `exception` feature は無効のため、例外は abort になる。
//! CPU 数・メモリ量は呼び出し側 `config` が VZ の許容範囲を検証済みであること）。設定オブジェクトは
//! VM 生成前で `VZVirtualMachine` のキュー制約は受けない（キュー制約は TASK-64.4 で扱う）。

use std::path::PathBuf;

use objc2::AnyThread;
use objc2::rc::Retained;
use objc2_foundation::{NSString, NSURL};
use objc2_virtualization::{VZLinuxBootLoader, VZVirtualMachineConfiguration};

/// 読み戻したブートローダ設定（kernel パス・initrd パス・コマンドライン）。
pub(crate) struct BootReadBack {
    pub(crate) kernel: Option<PathBuf>,
    pub(crate) initrd: Option<PathBuf>,
    pub(crate) command_line: String,
}

/// kernel / initrd / コマンドラインを持つ `VZLinuxBootLoader` を生成する。
pub(crate) fn new_linux_boot_loader(
    kernel: &NSURL,
    initrd: Option<&NSURL>,
    cmdline: &NSString,
) -> Retained<VZLinuxBootLoader> {
    // SAFETY: `kernel` / `cmdline` / `initrd` は有効な NSURL / NSString への参照で、呼び出し中は生存する。
    // `alloc` した未初期化オブジェクトを `initWithKernelURL:`（init ファミリー）で初期化し、所有権は
    // 戻り値の `Retained` が引き継ぐ。setter は例外を投げず、VZ はこれらの値を copy / retain する。
    unsafe {
        let loader = VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), kernel);
        loader.setCommandLine(cmdline);
        loader.setInitialRamdiskURL(initrd);
        loader
    }
}

/// ブートローダ・CPU 数・メモリ量を設定した `VZVirtualMachineConfiguration` を生成する。
///
/// `cpus` / `memory` は呼び出し側が `allowed_*_range` の範囲内であることを検証済みであること。
pub(crate) fn new_vm_configuration(
    boot: &VZLinuxBootLoader,
    cpus: usize,
    memory: u64,
) -> Retained<VZVirtualMachineConfiguration> {
    // SAFETY: `new`（new ファミリー）の戻りは +1 所有で `Retained` が管理する。`boot` は有効な
    // VZLinuxBootLoader（VZBootLoader のサブクラス）で、設定側が retain する。`cpus` / `memory` は
    // 呼び出し側で VZ の許容範囲内に検証済みのため、setter は例外を投げない。
    unsafe {
        let config = VZVirtualMachineConfiguration::new();
        config.setBootLoader(Some(boot));
        config.setCPUCount(cpus);
        config.setMemorySize(memory);
        config
    }
}

/// VZ が許容する CPU 数の範囲 `(min, max)`。
pub(crate) fn allowed_cpu_range() -> (usize, usize) {
    // SAFETY: 引数なしのクラスメソッドで、副作用なく整数を返す。
    unsafe {
        (
            VZVirtualMachineConfiguration::minimumAllowedCPUCount(),
            VZVirtualMachineConfiguration::maximumAllowedCPUCount(),
        )
    }
}

/// VZ が許容するメモリ量（バイト）の範囲 `(min, max)`。
pub(crate) fn allowed_memory_range() -> (u64, u64) {
    // SAFETY: 引数なしのクラスメソッドで、副作用なく整数を返す。
    unsafe {
        (
            VZVirtualMachineConfiguration::minimumAllowedMemorySize(),
            VZVirtualMachineConfiguration::maximumAllowedMemorySize(),
        )
    }
}

/// 設定済みの CPU 数を読み戻す（テスト・診断用）。
pub(crate) fn cpu_count(config: &VZVirtualMachineConfiguration) -> usize {
    // SAFETY: `config` は有効なインスタンスで、getter は副作用のない整数読み出し。
    unsafe { config.CPUCount() }
}

/// 設定済みのメモリ量（バイト）を読み戻す（テスト・診断用）。
pub(crate) fn memory_size(config: &VZVirtualMachineConfiguration) -> u64 {
    // SAFETY: `config` は有効なインスタンスで、getter は副作用のない整数読み出し。
    unsafe { config.memorySize() }
}

/// 設定済みブートローダを `VZLinuxBootLoader` として読み戻す（テスト・診断用）。
///
/// ブートローダ未設定・別種のブートローダなら `None`。
pub(crate) fn read_back_boot(config: &VZVirtualMachineConfiguration) -> Option<BootReadBack> {
    // SAFETY: `config` は有効なインスタンス。`bootLoader` は nullable の getter で、戻りは `Retained` が管理する。
    let boot = unsafe { config.bootLoader() }?;
    let linux = boot.downcast::<VZLinuxBootLoader>().ok()?;
    // SAFETY: `linux` は有効な VZLinuxBootLoader で、各 getter は副作用のない読み出し。
    // kernelURL / commandLine は非 null、initialRamdiskURL は nullable として生成バインディングが表す。
    unsafe {
        Some(BootReadBack {
            kernel: linux.kernelURL().to_file_path(),
            initrd: linux.initialRamdiskURL().and_then(|u| u.to_file_path()),
            command_line: linux.commandLine().to_string(),
        })
    }
}
