#![cfg(target_os = "macos")]
//! objc2 / Virtualization.framework の FFI 呼び出しを包む薄いラッパーの置き場（MAC-1・TASK-64.1/64.2/64.3）。
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

use std::os::fd::{IntoRawFd, OwnedFd};
use std::path::PathBuf;

use objc2::AnyThread;
use objc2::rc::Retained;
use objc2_foundation::{NSArray, NSError, NSFileHandle, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageStorageDeviceAttachment, VZFileHandleSerialPortAttachment, VZLinuxBootLoader,
    VZSerialPortConfiguration, VZStorageDeviceConfiguration, VZVirtioBlockDeviceConfiguration,
    VZVirtioConsoleDeviceSerialPortConfiguration, VZVirtualMachineConfiguration,
};

/// NSError の domain と code（VZ が返すエラーの機械可読な要約）。domain は長さを制限して保持する。
pub(crate) type VzErrorInfo = (String, isize);

/// 読み戻したストレージデバイス設定（診断用）。
pub(crate) struct StorageReadBack {
    pub(crate) path: Option<PathBuf>,
    pub(crate) read_only: bool,
    pub(crate) id: String,
}

/// NSError を (domain, code) に要約する。domain は 128 文字までに切り詰める（無制限保持の防止）。
fn summarize_error(err: &NSError) -> VzErrorInfo {
    (
        err.domain().to_string().chars().take(128).collect(),
        err.code(),
    )
}

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

/// ディスクイメージ（RAW）用の `VZDiskImageStorageDeviceAttachment` を生成する（TASK-64.3）。
///
/// 失敗（ファイル不正・VZ の拒否）は NSError の要約で返し、panic しない。
pub(crate) fn new_disk_image_attachment(
    url: &NSURL,
    read_only: bool,
) -> Result<Retained<VZDiskImageStorageDeviceAttachment>, VzErrorInfo> {
    // SAFETY: `url` は有効な NSURL への参照で呼び出し中は生存する。`alloc` した未初期化オブジェクトを
    // init ファミリーの `initWithURL:readOnly:error:` で初期化し、成功時の所有権は `Retained` が引き継ぐ。
    // 失敗時は nil と NSError が返り、objc2 が `Err` に変換する。
    unsafe {
        VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_error(
            VZDiskImageStorageDeviceAttachment::alloc(),
            url,
            read_only,
        )
    }
    .map_err(|e| summarize_error(&e))
}

/// virtio-blk のデバイス識別子を VZ 側でも検証する（ASCII・20 バイト以下）。
pub(crate) fn validate_block_device_id(id: &NSString) -> Result<(), VzErrorInfo> {
    // SAFETY: `id` は有効な NSString への参照。クラスメソッドで副作用はなく、不正値は例外ではなく
    // NSError として返る。
    unsafe { VZVirtioBlockDeviceConfiguration::validateBlockDeviceIdentifier_error(id) }
        .map_err(|e| summarize_error(&e))
}

/// ディスク attachment から virtio-blk デバイス設定を生成する。`id` は検証済みであること。
pub(crate) fn new_virtio_block_device(
    attachment: &VZDiskImageStorageDeviceAttachment,
    id: Option<&NSString>,
) -> Retained<VZStorageDeviceConfiguration> {
    // SAFETY: `attachment` は有効な VZDiskImageStorageDeviceAttachment（VZStorageDeviceAttachment の
    // サブクラス）で、デバイス設定側が retain する。init ファミリーの戻りは +1 所有で `Retained` が管理する。
    // `id` は呼び出し側が `validate_block_device_id` 済みのため setter は例外を投げない。
    unsafe {
        let dev = VZVirtioBlockDeviceConfiguration::initWithAttachment(
            VZVirtioBlockDeviceConfiguration::alloc(),
            attachment,
        );
        if let Some(id) = id {
            dev.setBlockDeviceIdentifier(id);
        }
        dev.into_super()
    }
}

/// 所有 fd を `NSFileHandle` に移す。
///
/// `into_raw_fd` で Rust 側の所有を手放し、以後は `closeOnDealloc: true` により `NSFileHandle` が
/// dealloc 時に close する。以降の処理がどこで失敗しても、`Retained` が drop されれば fd は閉じられる。
pub(crate) fn new_file_handle(fd: OwnedFd) -> Retained<NSFileHandle> {
    NSFileHandle::initWithFileDescriptor_closeOnDealloc(
        NSFileHandle::alloc(),
        fd.into_raw_fd(),
        true,
    )
}

/// 出力専用（ゲストへの入力なし）の virtio-console シリアルポート設定を生成する。
pub(crate) fn new_console_serial_port(write: &NSFileHandle) -> Retained<VZSerialPortConfiguration> {
    // SAFETY: `write` は有効な fd を持つ NSFileHandle で、attachment が retain する。reading は nil
    // （VZ は nil を許容する）。init / new ファミリーの戻りは `Retained` が管理し、`setAttachment` は
    // attachment を retain する。
    unsafe {
        let att =
            VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
                VZFileHandleSerialPortAttachment::alloc(),
                None,
                Some(write),
            );
        let port = VZVirtioConsoleDeviceSerialPortConfiguration::new();
        port.setAttachment(Some(&att));
        port.into_super()
    }
}

/// ストレージデバイスとシリアルポートを設定に組み込む。
pub(crate) fn set_devices(
    config: &VZVirtualMachineConfiguration,
    storage: &[Retained<VZStorageDeviceConfiguration>],
    serial: &[Retained<VZSerialPortConfiguration>],
) {
    let storage = NSArray::from_retained_slice(storage);
    let serial = NSArray::from_retained_slice(serial);
    // SAFETY: 配列は有効で、VZ 側が copy する（呼び出し中のみ生存すればよい）。要素は有効なデバイス設定。
    unsafe {
        config.setStorageDevices(&storage);
        config.setSerialPorts(&serial);
    }
}

/// 設定済みの virtio-blk デバイスを読み戻す（テスト・診断用）。
pub(crate) fn read_back_storage(config: &VZVirtualMachineConfiguration) -> Vec<StorageReadBack> {
    // SAFETY: `config` は有効なインスタンスで、getter は副作用のない読み出し。
    let devices = unsafe { config.storageDevices() };
    devices
        .to_vec()
        .into_iter()
        .filter_map(|dev| {
            // SAFETY: `dev` は有効なデバイス設定。getter は副作用のない読み出しで、戻りは `Retained` が管理する。
            let att = unsafe { dev.attachment() };
            let blk = dev.downcast::<VZVirtioBlockDeviceConfiguration>().ok()?;
            let disk = att.downcast::<VZDiskImageStorageDeviceAttachment>().ok()?;
            // SAFETY: `blk` / `disk` は有効なインスタンスで、getter は副作用のない読み出し。
            unsafe {
                Some(StorageReadBack {
                    path: disk.URL().to_file_path(),
                    read_only: disk.isReadOnly(),
                    id: blk.blockDeviceIdentifier().to_string(),
                })
            }
        })
        .collect()
}

/// 設定済みのシリアルポート数を読み戻す（テスト・診断用）。
pub(crate) fn serial_port_count(config: &VZVirtualMachineConfiguration) -> usize {
    // SAFETY: `config` は有効なインスタンスで、getter は副作用のない読み出し。
    unsafe { config.serialPorts() }.len()
}
