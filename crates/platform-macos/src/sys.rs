#![cfg(target_os = "macos")]
//! objc2 / Virtualization.framework の FFI 呼び出しを包む薄いラッパーの置き場（MAC-1・TASK-64.1/64.2/64.3・65.1）。
//!
//! 上位モジュール（`config`）へは安全な API だけを公開し、`unsafe fn` を本モジュールの外へ公開しない。
//! 各 `unsafe` は `// SAFETY:` で不変条件を明記し、`.claude/rules/coding-rust.md` の事前承認（#4）の
//! 条件（security-auditor 観点のレビュー・PR 本文の unsafe 一覧）を満たす。
//!
//! 共通の不変条件: 引数は `Retained` / 参照で生存期間が保証された有効な Objective-C オブジェクトで、
//! セレクタと型シグネチャは objc2-virtualization 0.3.2 の生成バインディングと一致する。ここで呼ぶ
//! setter / getter は ObjC 例外を投げない（objc2 の `exception` feature は無効のため、ObjC 例外は Rust の
//! フレームをアンワインドで通り抜け、dispatch の extern "C" 境界等で abort する。捕捉はできないので、例外を
//! 投げ得る呼び出しは事前条件を確認してから行う。CPU 数・メモリ量は呼び出し側 `config` が VZ の許容範囲を
//! 検証済みであること）。設定オブジェクトは
//! VM 生成前で `VZVirtualMachine` のキュー制約は受けない。
//!
//! キュー制約（TASK-64.4）: `VZVirtualMachine` の操作・completion handler・delegate は、その VM 専用の
//! シリアル `DispatchQueue` 上でのみ行う。`VmHost` が VM と delegate を `QueueBound` に包んで保持し、
//! 操作は `VmHost::run_async` / `run_timeout` のクロージャと completion handler（いずれもキュー上で実行される）
//! にだけ `VmRef` として渡す。`VmRef` は本モジュール外で生成できないため、キュー外から VM を触る経路は型として
//! 存在しない。VM への強参照は `QueueOwned` が持ち、最後の解放を必ずキュー上へ回す。
//!
//! unix 共通の POSIX ラッパー（`geteuid` 等）は子モジュール `posix`（`src/sys/posix.rs`）に置く。macOS 以外の
//! unix では `lib.rs` が `posix` だけを持つ `sys` を定義し、同じ `crate::sys::effective_uid` で呼べるようにする。

use std::cell::Cell;
use std::marker::PhantomData;
use std::os::fd::{IntoRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::Duration;

use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchQueueAttr, DispatchRetained, DispatchTime};
use objc2::rc::Retained;
use objc2::runtime::{NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{AnyThread, DefinedClass, define_class, msg_send};
use objc2_foundation::{NSArray, NSError, NSFileHandle, NSString, NSURL};
use objc2_virtualization::{
    VZDirectorySharingDeviceConfiguration, VZDiskImageStorageDeviceAttachment,
    VZFileHandleSerialPortAttachment, VZLinuxBootLoader, VZSerialPortConfiguration,
    VZSharedDirectory, VZSingleDirectoryShare, VZStorageDeviceConfiguration,
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceSerialPortConfiguration,
    VZVirtioFileSystemDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
    VZVirtualMachineDelegate,
};
use std::sync::Arc;

mod posix;
pub(crate) use posix::effective_uid;

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

/// 読み戻した virtiofs 共有設定（診断用）。
pub(crate) struct ShareReadBack {
    pub(crate) tag: String,
    pub(crate) path: Option<PathBuf>,
    pub(crate) read_only: bool,
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

/// virtiofs の共有タグを VZ 側でも検証する（35 バイト以下・UTF-8 等）。
pub(crate) fn validate_virtiofs_tag(tag: &NSString) -> Result<(), VzErrorInfo> {
    // SAFETY: `tag` は有効な NSString への参照。クラスメソッドで副作用はなく、不正値は例外ではなく
    // NSError として返る。
    unsafe { VZVirtioFileSystemDeviceConfiguration::validateTag_error(tag) }
        .map_err(|e| summarize_error(&e))
}

/// 単一ディレクトリ共有の virtiofs デバイス設定を生成する。
///
/// `tag` は呼び出し側が `validate_virtiofs_tag` 済み、`url` は検証済みのホストディレクトリの file URL であること
/// （`initWithTag:` は不正タグで ObjC 例外を投げ、捕捉できず abort するため）。
pub(crate) fn new_virtiofs_device(
    tag: &NSString,
    url: &NSURL,
    read_only: bool,
) -> Retained<VZDirectorySharingDeviceConfiguration> {
    // SAFETY: `tag` / `url` は有効な参照で呼び出し中は生存する。`tag` は事前に VZ の検証を通している。
    // alloc した未初期化オブジェクトを init ファミリーで初期化し、所有権は `Retained` が引き継ぐ。
    // `VZSharedDirectory` は `url` を保持し、`VZSingleDirectoryShare` は directory を、デバイス設定は
    // share を retain する（setter は例外を投げない）。
    unsafe {
        let dir =
            VZSharedDirectory::initWithURL_readOnly(VZSharedDirectory::alloc(), url, read_only);
        let share =
            VZSingleDirectoryShare::initWithDirectory(VZSingleDirectoryShare::alloc(), &dir);
        let dev = VZVirtioFileSystemDeviceConfiguration::initWithTag(
            VZVirtioFileSystemDeviceConfiguration::alloc(),
            tag,
        );
        dev.setShare(Some(&share.into_super()));
        dev.into_super()
    }
}

/// virtiofs デバイス群を設定に組み込む。
pub(crate) fn set_directory_sharing_devices(
    config: &VZVirtualMachineConfiguration,
    devices: &[Retained<VZDirectorySharingDeviceConfiguration>],
) {
    let devices = NSArray::from_retained_slice(devices);
    // SAFETY: 配列は有効で、VZ 側が copy する（呼び出し中のみ生存すればよい）。要素は有効なデバイス設定。
    unsafe { config.setDirectorySharingDevices(&devices) }
}

/// 設定済みの virtiofs 共有を読み戻す（テスト・診断用）。
pub(crate) fn read_back_shares(config: &VZVirtualMachineConfiguration) -> Vec<ShareReadBack> {
    // SAFETY: `config` は有効なインスタンスで、getter は副作用のない読み出し。
    let devices = unsafe { config.directorySharingDevices() };
    devices
        .to_vec()
        .into_iter()
        .filter_map(|dev| {
            let fs = dev
                .downcast::<VZVirtioFileSystemDeviceConfiguration>()
                .ok()?;
            // SAFETY: `fs` は有効なインスタンスで、getter は副作用のない読み出し。戻りは `Retained` が管理する。
            let share = unsafe { fs.share() }?;
            let single = share.downcast::<VZSingleDirectoryShare>().ok()?;
            // SAFETY: `single` / その directory は有効なインスタンスで、getter は副作用のない読み出し。
            unsafe {
                let dir = single.directory();
                Some(ShareReadBack {
                    tag: fs.tag().to_string(),
                    path: dir.URL().to_file_path(),
                    read_only: dir.isReadOnly(),
                })
            }
        })
        .collect()
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

/// `VmRef::start` / `stop` が事前条件（`canStart` / `canStop`）を満たさず要求しなかったこと。
///
/// handler は呼ばれずに破棄される。`state_raw` はその時点の `VZVirtualMachineState` の生値。
pub(crate) struct OpRejected {
    pub(crate) state_raw: isize,
}

/// VM 専用キューのラベル（固定文字列。入力から組み立てない）。
const VM_QUEUE_LABEL: &str = "ai.fandhe.container.platform-macos.vm";

/// `VmHost::new` の失敗要因。呼び出し側 `vm` が `VmError` へ写す。
pub(crate) enum HostInitError {
    /// この環境で Virtualization.framework が使えない（`isSupported` が false）。
    Unsupported,
    /// `validateWithError` が設定を拒否した（entitlement 欠如もここに来る）。
    InvalidConfiguration(VzErrorInfo),
}

/// delegate が受け取る VM 停止通知。`vm` の状態機械へ中継される。
pub(crate) enum DelegateEvent {
    /// ゲスト側から停止された（`guestDidStopVirtualMachine:`）。
    GuestStopped,
    /// エラーで停止した（`virtualMachine:didStopWithError:`）。NSError は要約済み。
    StoppedWithError(VzErrorInfo),
}

/// delegate の ivar。通知は VM キュー上で呼ばれる（どのスレッドかは GCD 次第のため handler は `Send`）。
struct DelegateIvars {
    handler: Box<dyn Fn(DelegateEvent) + Send>,
}

define_class!(
    /// `VZVirtualMachineDelegate` を実装し、停止通知を Rust のクロージャへ中継するクラス。
    ///
    /// `VZVirtualMachine.delegate` は weak プロパティのため、`VmObjects` が強参照を VM と同じ寿命で保持する。
    // SAFETY: NSObject にはサブクラス化の追加要件がなく、ivars の `DelegateIvars` は Drop で特別な処理をしない。
    #[unsafe(super(NSObject))]
    #[name = "FandheContainerVmDelegate"]
    #[ivars = DelegateIvars]
    struct VmDelegate;

    // SAFETY: NSObject が NSObjectProtocol を実装するため、サブクラスも準拠する。
    unsafe impl NSObjectProtocol for VmDelegate {}

    // SAFETY: セレクタと引数型は objc2-virtualization 0.3.2 の生成バインディングと一致させている。
    // 引数は呼び出し中のみ有効なため、NSError はその場で要約して保持しない。panic しない処理だけを行う。
    unsafe impl VZVirtualMachineDelegate for VmDelegate {
        #[unsafe(method(guestDidStopVirtualMachine:))]
        fn guest_did_stop(&self, _vm: &VZVirtualMachine) {
            (self.ivars().handler)(DelegateEvent::GuestStopped);
        }

        #[unsafe(method(virtualMachine:didStopWithError:))]
        fn did_stop_with_error(&self, _vm: &VZVirtualMachine, error: &NSError) {
            (self.ivars().handler)(DelegateEvent::StoppedWithError(summarize_error(error)));
        }
    }
);

impl VmDelegate {
    fn new(handler: Box<dyn Fn(DelegateEvent) + Send>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(DelegateIvars { handler });
        // SAFETY: ivars を設定済みの未初期化オブジェクトに NSObject の `init` を送る標準手順。
        unsafe { msg_send![super(this), init] }
    }
}

/// VM と delegate の組。VM キュー上でのみ触る。
struct VmObjects {
    // フィールド順: VM を先に解放し、その後に delegate を解放する。
    vm: Retained<VZVirtualMachine>,
    delegate: Retained<VmDelegate>,
}

/// 専用シリアルキューに束縛された値の包み。キュー上のクロージャ内でだけ中身を触る。
struct QueueBound<T>(T);

// SAFETY: 中身（VZVirtualMachine・delegate）は ObjC オブジェクトで `Send` ではないが、本モジュールは
// 中身を参照・解放するコードを VM の専用シリアルキュー上のクロージャ（`run_async` / `run_after` /
// `run_timeout` / completion handler / `QueueOwned::drop` が投入する解放）にだけ置く。包みを別スレッドへ
// 動かしても、中身を触る・最後の参照を解放するのは常にそのキューのスレッドである。中身へ到達する唯一の窓口
// `VmRef` は `!Send` / `!Sync` のため、キュー上のクロージャから別スレッドへ持ち出せない。対象は
// `VmObjects` に限る（任意の型へ広げない）。
unsafe impl Send for QueueBound<VmObjects> {}
// SAFETY: 上記と同じ不変条件。共有参照越しに中身へ到達できるのもキュー上のクロージャ（`VmRef`）だけ。
unsafe impl Sync for QueueBound<VmObjects> {}

/// VM への強参照を、最後の解放が必ず VM キュー上で起きるように包む。
///
/// `VmHost` と、完了待ちの completion handler（VZ が任意のスレッドで block を解放し得る）が持つ。
/// drop されると参照を VM キューへ送ってそこで解放するため、どのスレッドで drop してもよい。
struct QueueOwned {
    objs: Option<Arc<QueueBound<VmObjects>>>,
    queue: DispatchRetained<DispatchQueue>,
}

impl Drop for QueueOwned {
    fn drop(&mut self) {
        if let Some(objs) = self.objs.take() {
            // 任意のスレッドから VZVirtualMachine を release しないため、VM キュー上で解放する。
            self.queue.exec_async(move || drop(objs));
        }
    }
}

/// VM キュー上のクロージャ・completion handler にだけ渡される VM 操作の窓口（本モジュール外では生成できない）。
///
/// `!Send` / `!Sync`（`PhantomData<*const ()>`）のため、キュー上のクロージャ内から `thread::scope` 等で
/// キュー外のスレッドへ渡せない。下の各 `unsafe` の「VM キュー上でのみ存在する」前提を型で保証する。
pub(crate) struct VmRef<'a> {
    objs: &'a Arc<QueueBound<VmObjects>>,
    queue: &'a DispatchRetained<DispatchQueue>,
    _not_send: PhantomData<*const ()>,
}

/// `VmRef` が `Send` / `Sync` でないことのコンパイル時検査（依存なしの曖昧性トリック）。
///
/// `T: Send`（`Sync`）なら 2 つの impl が両方当てはまり、型推論が曖昧になってコンパイルエラーになる。
mod vm_ref_is_not_send_or_sync {
    use super::VmRef;

    trait AmbiguousIfSend<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

    trait AmbiguousIfSync<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

    const _: fn() = || {
        <VmRef<'static> as AmbiguousIfSend<_>>::check();
        <VmRef<'static> as AmbiguousIfSync<_>>::check();
    };
}

impl<'a> VmRef<'a> {
    /// VM キュー上で実行中のクロージャ・completion handler の中でだけ呼ぶ（本モジュール内に限る）。
    fn on_queue(
        objs: &'a Arc<QueueBound<VmObjects>>,
        queue: &'a DispatchRetained<DispatchQueue>,
    ) -> VmRef<'a> {
        VmRef {
            objs,
            queue,
            _not_send: PhantomData,
        }
    }
}

impl VmRef<'_> {
    /// 現在の状態の生値（`VZVirtualMachineState`）。
    pub(crate) fn state_raw(&self) -> isize {
        // SAFETY: `VmRef` は VM キュー上でのみ存在し、getter は副作用のない読み出し。
        unsafe { self.objs.0.vm.state().0 }
    }

    /// 起動可能か（不正状態での `startWithCompletionHandler:` は ObjC 例外 = abort になるため、`start` も内部で確認する）。
    pub(crate) fn can_start(&self) -> bool {
        // SAFETY: 同上。
        unsafe { self.objs.0.vm.canStart() }
    }

    /// 停止可能か（`stop` も内部で確認する）。
    pub(crate) fn can_stop(&self) -> bool {
        // SAFETY: 同上。
        unsafe { self.objs.0.vm.canStop() }
    }

    /// `canStart` を確認してから `startWithCompletionHandler:` を呼ぶ。起動できない状態なら要求せず
    /// `OpRejected` を返す（handler は呼ばれない）。
    ///
    /// `handler` は VM キュー上で 1 回だけ、その時点の `VmRef` とともに呼ばれる（続けて停止を要求できる）。
    pub(crate) fn start(
        &self,
        handler: impl Fn(&VmRef<'_>, Result<(), VzErrorInfo>) + Send + 'static,
    ) -> Result<(), OpRejected> {
        if !self.can_start() {
            return Err(OpRejected {
                state_raw: self.state_raw(),
            });
        }
        let block = self.completion_block(handler);
        // SAFETY: VM キュー上で呼ばれ（`VmRef` は !Send でキュー上にしか存在しない）、直前に `canStart` を
        // 確認済み。シリアルキュー上のため確認と呼び出しの間に他の操作は入らない。block は VZ が copy して
        // 保持し、キュー上で呼ぶ。
        unsafe { self.objs.0.vm.startWithCompletionHandler(&block) };
        Ok(())
    }

    /// `canStop` を確認してから `stopWithCompletionHandler:` を呼ぶ。戻り値と `handler` は `start` と同じ。
    pub(crate) fn stop(
        &self,
        handler: impl Fn(&VmRef<'_>, Result<(), VzErrorInfo>) + Send + 'static,
    ) -> Result<(), OpRejected> {
        if !self.can_stop() {
            return Err(OpRejected {
                state_raw: self.state_raw(),
            });
        }
        let block = self.completion_block(handler);
        // SAFETY: VM キュー上で呼ばれ、直前に `canStop` を確認済み。block の扱いは `start` と同じ。
        unsafe { self.objs.0.vm.stopWithCompletionHandler(&block) };
        Ok(())
    }

    /// `delay` 後に VM キュー上で `f` を実行する（それまで VM を保持し、解放はキュー上で行う）。
    ///
    /// `delay` を `DispatchTime` で表せない（桁あふれ）場合は直ちに投入する。
    pub(crate) fn run_after(&self, delay: Duration, f: impl FnOnce(&VmRef<'_>) + Send + 'static) {
        let objs = Arc::clone(self.objs);
        let queue = self.queue.clone();
        let work = move || {
            f(&VmRef::on_queue(&objs, &queue));
            // この clone が最後の参照でも、解放は VM キューのスレッド上で行われる。
            drop(objs);
        };
        match DispatchTime::try_from(delay) {
            // dispatch2 0.3.1 の `after` は `dispatch_after_f` で投入し、常に `Ok` を返す。
            Ok(when) => {
                let _ = self.queue.after(when, work);
            }
            Err(()) => self.queue.exec_async(work),
        }
    }

    /// completion handler 用の block を作る。
    ///
    /// block は完了まで VM への強参照（`QueueOwned`）を持ち、`Vm` が先に破棄されても操作中の VM を解放しない。
    /// 呼ばれた時点で参照を手放す（解放はキュー上）。2 回目以降の呼び出しでは何もしない。VZ が block を
    /// 一度も呼ばずに保持し続けた場合、VM は解放されない（use-after-free より安全側に倒す）。
    fn completion_block(
        &self,
        handler: impl Fn(&VmRef<'_>, Result<(), VzErrorInfo>) + Send + 'static,
    ) -> RcBlock<dyn Fn(*mut NSError)> {
        let keep = Cell::new(Some(QueueOwned {
            objs: Some(Arc::clone(self.objs)),
            queue: self.queue.clone(),
        }));
        RcBlock::new(move |err: *mut NSError| {
            let res = completion_result(err);
            let Some(owned) = keep.take() else {
                return;
            };
            if let Some(objs) = owned.objs.as_ref() {
                // completion handler は VM キュー上で呼ばれるため、ここで `VmRef` を渡してよい。
                handler(&VmRef::on_queue(objs, &owned.queue), res);
            }
        })
    }
}

/// completion handler の `NSError*`（成功時 nil）を要約結果へ変換する。要約は呼び出し中にコピーする。
fn completion_result(err: *mut NSError) -> Result<(), VzErrorInfo> {
    // SAFETY: VZ は nil か、handler 呼び出し中に有効な NSError を渡す。借用は本関数内で完結する。
    match unsafe { err.as_ref() } {
        None => Ok(()),
        Some(e) => Err(summarize_error(e)),
    }
}

/// 専用シリアルキューと、そこに束縛された `VZVirtualMachine` の持ち主。
///
/// `initWithConfiguration:` のメインキュー依存（呼び出し側が run loop を回し続ける必要がある）を避けるため、
/// VM ごとに専用キューを持つ。コールバックは GCD のワーカースレッドで届く（TASK-64.4 の run loop 統合）。
pub(crate) struct VmHost {
    owned: QueueOwned,
}

impl VmHost {
    /// 対応確認・設定検証の後に、専用キュー上で動く VM を生成する。
    pub(crate) fn new(
        config: &VZVirtualMachineConfiguration,
        handler: Box<dyn Fn(DelegateEvent) + Send>,
    ) -> Result<VmHost, HostInitError> {
        // SAFETY: 引数なしのクラスメソッドで副作用はない。
        if !unsafe { VZVirtualMachine::isSupported() } {
            return Err(HostInitError::Unsupported);
        }
        // SAFETY: 有効な設定への参照。不正は例外ではなく NSError で返る。ObjC 例外は abort になるため、
        // 例外を投げ得る init の前に必ず検証する。
        unsafe { config.validateWithError() }
            .map_err(|e| HostInitError::InvalidConfiguration(summarize_error(&e)))?;
        // `None`（DispatchQueueAttr::SERIAL）は `dispatch_queue_create(label, NULL)` = シリアルキュー。
        let queue = DispatchQueue::new(VM_QUEUE_LABEL, DispatchQueueAttr::SERIAL);
        let delegate = VmDelegate::new(handler);
        // SAFETY: 設定は検証済みで VZ が copy する。キューはシリアル。init ファミリーの戻りは +1 所有で
        // `Retained` が管理する。生成後の操作はすべて `queue` 上で行う。
        let vm = unsafe {
            VZVirtualMachine::initWithConfiguration_queue(VZVirtualMachine::alloc(), config, &queue)
        };
        let host = VmHost {
            owned: QueueOwned {
                objs: Some(Arc::new(QueueBound(VmObjects { vm, delegate }))),
                queue,
            },
        };
        // 専用キューはシリアルのため、後続の操作より先に実行される。完了待ちはしない（無期限 block の回避。REPAIR-5）。
        host.run_async(|vm| {
            let objs = &vm.objs.0;
            let proto = ProtocolObject::from_ref(&*objs.delegate);
            // SAFETY: delegate は weak 参照のため、`VmObjects` が VM と同じ寿命で強参照を保持する。VM キュー上で呼ぶ。
            unsafe { objs.vm.setDelegate(Some(proto)) };
        });
        Ok(host)
    }

    /// VM キュー上でクロージャを非同期に実行する。完了は待たない。
    ///
    /// `VmHost` の生存中は VM への参照を必ず持つため、クロージャは常に実行される。
    pub(crate) fn run_async(&self, f: impl FnOnce(&VmRef<'_>) + Send + 'static) {
        let Some(objs) = self.owned.objs.as_ref().map(Arc::clone) else {
            return;
        };
        let queue = self.owned.queue.clone();
        self.owned.queue.exec_async(move || {
            f(&VmRef::on_queue(&objs, &queue));
            // この clone が最後の参照でも、解放は VM キューのスレッド上で行われる。
            drop(objs);
        });
    }

    /// VM キュー上でクロージャを実行し、結果を `timeout` まで待つ（`run_async` ＋ チャネル。REPAIR-5）。
    ///
    /// キューが詰まった場合や VM キュー上から呼んだ場合も期限で戻る。期限切れ・実行されなかった場合は `None`
    /// （クロージャは後からキュー上で実行され得る）。
    pub(crate) fn run_timeout<R: Send + 'static>(
        &self,
        timeout: Duration,
        f: impl FnOnce(&VmRef<'_>) -> R + Send + 'static,
    ) -> Option<R> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<R>(1);
        self.run_async(move |vm| {
            let _ = tx.try_send(f(vm));
        });
        rx.recv_timeout(timeout).ok()
    }
}
