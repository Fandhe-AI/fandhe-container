//! macOS（Hypervisor.framework）の microVM 構成体 `HvfMicroVm`（TASK-192.15・#3797・MVM-5・MVM-1・MVM-4）。
//!
//! 役割: 既にある部品（GIC つきの VM = `VmWithGic`〔#3792〕、ゲスト RAM = `HvfGuestRam`〔#3787〕、Image・initrd・FDT の配置 =
//! `boot_arm64::load_arm64`〔#3790〕、virtio-mmio のデバイスモデルと SPI 注入 = `GicSpiLine`〔#3795〕、vCPU スレッド =
//! `VcpuThread`〔#3791〕）を 1 つにまとめ、vCPU 0 を起動レジスタ込みで走らせる。Linux の `microvm::MicroVm::assemble` の対応物。
//! 呼び出し元は plugin-microvm（#3800）。start / stop の API は #3798（モジュール doc の「start / stop と解放順序」）。
//!
//! # 組み立ての順序（[`HvfMicroVm::assemble`]）
//! 1. 構成値の検査（資源を作る前。`hvf_abi::check_assemble_input` と `Arm64Layout::validate`）。`config.serial` と `layout.serial` を突き合わせ（#3882）、virtio + シリアルが MMIO 表の上限（`MAX_BUS_DEVICES`）を超える構成もここで拒否する。vcpus 2 以上は `Unimplemented`（FDT 側は N 個を出せる。backend は 1。#3864）。
//! 2. VM + GIC（`VmWithGic::create`。GIC の配置違反は VM を作る前に拒否される）。
//! 3. ゲスト RAM の登録（`HvfGuestRam::register_shared`。対応付けが `Arc<HvVm>` を保持する）。
//! 4. Image・initrd・FDT の配置（`load_arm64`。Image ヘッダの検証はここ）。
//! 5. virtio-mmio のデバイス群を `ExitDispatcher` に登録し、各デバイスの割り込みを `GicSpiLine` に結ぶ（block → net → シリアルの順。シリアルは `layout.serial` があるときだけ。THRE 割り込みは level の SPI で結ぶ。#3882・#3892）。
//!    線の注入方式が FDT の trigger と一致するかをここで照合し（不一致は `InvalidArgument`）、`InterruptACK` の後処理
//!    （level 扱いの deassert / resample。#3863）の route を `MmioHandler` へ結ぶ。
//! 6. vCPU スレッドの作成。vCPU 0 の `setup` で X0 = FDT の GPA・X1〜X3 = 0・PC = カーネルのエントリ・CPSR = `0x3c5`・
//!    MPIDR_EL1 = FDT の `cpu@0` の `reg` を書き、読み戻して照合する。`SCTLR_EL1` は書かず、既定値で MMU・D-cache が off
//!    （M = 0・C = 0）であることだけを確かめる（違反は `FailedPrecondition`）。
//!
//! # 失敗時の解放
//! 途中で失敗したら、作成済みの資源をローカル変数の逆順 drop で解放する（RAM の unmap → munmap → VM の destroy）。
//! 対応付けが `Arc<HvVm>` を保持するため、VM の破棄は必ず unmap の後になる。同じプロセスで再び `assemble` できる。
//! 残余: `setup` の失敗で `spawn` が `Err` になった直後は、vCPU スレッドの終了処理中に VM の `Arc` が一瞬残りうる。その間の
//! 再 assemble は `FailedPrecondition` になりうる（`spawn` より前の失敗では起きない）。
//!
//! # start / stop と解放順序（TASK-192.16・#3798・MVM-5・MVM-1・REPAIR-5）
//! `assemble` は vCPU 0 を作って起動レジスタを書くところまで行い、ゲストは走らせない（start gate。`VcpuThread::spawn_gated`）。
//! [`HvfMicroVm::start`] がゲートを開いて [`RunningHvfMicroVm`] を返し、[`RunningHvfMicroVm::stop`] が期限（0 超 60 秒以下。
//! Linux の `STOP_DEADLINE_MAX` と同じ）つきで止める。start しないまま drop すると、ゲストは一度も走らずに終わる。
//! 終了理由は Linux と共有の `StopReason`（`stop` の `Requested`、PSCI の SYSTEM_OFF・SYSTEM_RESET は `GuestShutdown`、未対応・未知の
//! exit は fail-closed の `Failed(Unimplemented / Internal)`）で、[`HvfStopReport`] に載せる。
//! exit ごとの処理は `hvf::{mmio, hvc, timer}`（#3793・#3794・#3796）が担い、WFI の待ちの上限など残る制限は `hvf::timer` の「未実装・簡易実装」を参照。
//!
//! ## 解放順序（`hvf_lifecycle::stop_and_release`。stop と drop が同じ手順を通る。drop の期限は 5 秒）
//! 1. 停止要求 → kick（`hv_vcpus_exit`。待つ間も 10 ms ごとに打ち直す）→ vCPU スレッドが実行ループを抜ける。
//! 2. owning thread が自分の vCPU を `hv_vcpu_destroy` し（vCPU はスレッドに束縛され、他スレッドからは破棄できない）、捕捉していた
//!    `Arc<VmWithGic>` を落として報告を送る。報告を受けた時点で vCPU の破棄は済んでいる。
//! 3. 報告が `Ok` のときだけ、デバイス → ゲスト RAM（`hv_vm_unmap` に成功したら munmap。失敗ならリーク）→ VM（最後の `Arc` の drop が
//!    `hv_vm_destroy`）の順で解放する。ゲスト RAM の対応付けは `Arc<HvVm>` を握るため、unmap が `hv_vm_destroy` より後になることは型で
//!    起きない。munmap が `hv_vm_destroy` より前でよいのは、unmap の成功後はゲストからその backing へ到達できないため。
//!
//! ## Apple の記述との関係
//! `hv_gic_create` のドキュメント（<https://developer.apple.com/documentation/hypervisor/hv_gic_create(_:)> の Discussion。2026-11-04 に
//! JSON 版で確認）は、vCPU が走り出すとトポロジーは確定するとみなされること、vCPU を破棄するのは VM を teardown するときだけにする
//! こと、の 2 点を述べる。VM の破棄順序や、走行中の vCPU の破棄時の挙動には触れていない。本 crate は 1 プロセス 1 VM で pause・
//! vCPU の再作成・hot-unplug を持たないため、停止は常に VM の teardown そのもので、「owning thread が vCPU を破棄し、同じ teardown の
//! 中で unmap → `hv_vm_destroy` まで進める」ことは「teardown のときだけ破棄する」と矛盾しない。`VmWithGic::mark_teardown` が破棄の直前に
//! 立つ印で、以後の vCPU 作成は `FailedPrecondition`。
//! - 採らない案 1「`hv_vcpu_destroy` を呼ばず `hv_vm_destroy` に任せる」: vCPU が残ったままの `hv_vm_destroy` の成功が文書に無い。
//!   失敗（`HV_BUSY` 等）すると `VM_EXISTS` が立ったままになり、同じプロセスで二度と VM を作れない。
//! - 採らない案 2「vCPU スレッドで `hv_vm_destroy` まで行う」: `HostMapping` が `!Send` のため RAM を移すのに `sys` へ新しい
//!   `unsafe impl Send` が要る（事前承認の範囲外）。
//! - 実機での戻り値・所要時間の観測は #3803（人間担当）。
//!
//! ## 期限切れ（`TIMEOUT`）のとき
//! 解放はデバイスと VM の手放しに留め、ゲスト RAM の対応付けは `mem::forget` でリークする（ゲストがまだ書けうるメモリを再利用させない
//! fail-closed）。残る資源は vCPU スレッド・vCPU・VM（GIC を含む）・ゲスト RAM の mmap と map。リークした対応付けが `Arc<HvVm>` を
//! 握るため、スレッドが後で自力で終わっても `hv_vm_destroy` は走らず、同じプロセスでの再 assemble は `FailedPrecondition` になる。
//! 回収の方法はプロセスの終了だけ（plugin-microvm による再起動。#3800）。後から終わったスレッドの資源を回収する案は、`HostMapping`
//! を `Send` にして回収スレッドへ渡す必要があり、`sys` に新しい `unsafe` が要るため本 issue の範囲外（追跡は #3908）。
//!
//! # 範囲外（REPAIR-3。担当 issue）
//! - virtqueue の処理と QueueNotify の配線、ゲスト RAM のデバイスへの受け渡し（`HostMapping` の `Send` を含む）は未実装で、担当は
//!   #3908（`HvfBoundDevice::transport` が将来使う）。
//! - SMP（vCPU 1..N・CPU_ON・`MPIDR_EL1` は `arm64_vcpu_mpidr_affinity`。vCPU 1..N の停止の集約を含む。#3864 の後続）、シリアルの入力（RX）、`NetDeviceConfig`（Linux 限定）との共通化、構造化ログ（crate にログ基盤が無い）。
//! - 書いた範囲の PoC までの clean と I-cache 無効化の要否、MPIDR / SCTLR の生の値の記録（#3803）。
//! - Image の署名・digest の検証は本層の責務ではない（plugin-microvm 側。PLUG-11）。構成値・パスはエラーに載せない（ERR-1）。
//!
//! `unsafe` は持たない（crate の `#![deny(unsafe_code)]` で担保）。

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::arm64_layout::{
    ARM64_BOOT_CPU_MPIDR, ARM64_SERIAL_BASE, ARM64_SERIAL_SIZE, Arm64Layout, MmioRegion,
};
use crate::boot_arm64::{ArmBootReadback, LoadedArm64, check_boot_readback, load_arm64};
use crate::dispatch::{DeviceId, ExitDispatcher};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::guest_memory::{GuestAddress, GuestMemory};
use crate::hvf::gic::{GicSpiLine, VmWithGic};
use crate::hvf::hvc::HvcHandler;
use crate::hvf::memory::{HvfGuestRam, RegisteredHvfRam};
use crate::hvf::mmio::MmioHandler;
use crate::hvf::timer::TimerHandler;
use crate::hvf::vcpu::{ExitHandlers, VcpuHandle, VcpuThread, VcpuThreadConfig};
use crate::hvf_abi::{HvReg, HvSysReg, HvfAssembleInput, check_assemble_input};
use crate::hvf_lifecycle::{
    DROP_STOP_DEADLINE, HvfStopReport, ReleaseDevices, Resources, stop_and_release,
};
use crate::hvf_loop::log_line;
use crate::interrupt::{BoundAckRoute, InterruptAckRoute, InterruptLine};
use crate::uart::SerialConsole;
use crate::virtio_block::{BlockBackend, VirtioBlock};
use crate::virtio_mmio::{SharedTransport, VirtioMmioTransport};
use crate::virtio_net::{NetBackend, VirtioNet};

fn internal(msg: &'static str) -> MicrovmError {
    MicrovmError::new(MicrovmErrorCode::Internal, msg)
}

/// virtio-net 1 台分の構成（`microvm::NetDeviceConfig` は Linux 限定のため macOS 側に持つ。共通化は REPAIR-3）。
#[derive(Debug)]
pub struct HvfNetDeviceConfig<N> {
    /// ホスト側の backend。
    pub backend: N,
    /// ゲストへ見せる MAC アドレス。
    pub mac: [u8; 6],
}

/// [`HvfMicroVm::assemble`] の構成。値は非信頼入力として `assemble` が上限を検査する。
#[derive(Debug)]
pub struct HvfMicroVmConfig<B, N> {
    /// ゲストの物理アドレス配置（vCPU 数・RAM の大きさ・virtio-mmio の個数）。
    pub layout: Arm64Layout,
    /// カーネル Image（arm64 Linux Image 形式）。
    pub kernel: Vec<u8>,
    /// initrd。
    pub initrd: Option<Vec<u8>>,
    /// カーネル cmdline（FDT の `chosen/bootargs`）。
    pub cmdline: String,
    /// virtio-block の backend（先に窓を割り当てる）。
    pub block: Vec<B>,
    /// virtio-net（block の後）。
    pub net: Vec<HvfNetDeviceConfig<N>>,
    /// vCPU スレッドの設定。
    pub vcpu: VcpuThreadConfig,
    /// シリアル（ns16550a の MMIO。`HvfMicroVm::serial_console` で出力を得る）を有効にするか（#3882・MVM-5・MVM-1）。
    ///
    /// - `true` で `layout.serial` が `None`: 既定の窓（`ARM64_SERIAL_BASE`・`ARM64_SERIAL_SIZE`）を設定する。
    /// - `true` で `layout.serial` が `Some`: 呼び出し元の窓を使う（大きさ・重なりは `Arm64Layout::validate` が検査）。
    /// - `false` で `layout.serial` が `Some`: `InvalidArgument`（実体の無いデバイスを FDT に載せない）。
    ///
    /// シリアルは virtio と同じ MMIO 表を 1 枠使うため、有効なら virtio は 31 台まで（資源を作る前に検査する）。
    pub serial: bool,
}

/// デバイスの種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HvfDeviceKind {
    /// virtio-block。
    Block,
    /// virtio-net。
    Net,
}

/// 登録済みデバイス 1 台の配置（観測用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HvfDeviceInfo {
    /// 種別。
    pub kind: HvfDeviceKind,
    /// 同じ種別の中での番号。
    pub index: usize,
    /// MMIO の窓。
    pub window: MmioRegion,
    /// 注入する SPI の INTID（GIC の番号空間。SPI 番号 + 32）。
    pub spi_intid: u32,
    /// dispatcher 上の識別子。
    pub id: DeviceId,
}

/// 登録済みのデバイス 1 台（トランスポート・識別子・窓・割り込み線）。
struct HvfBoundDevice<D: crate::virtio_mmio::VirtioDevice> {
    /// QueueNotify の処理（#3798）と ACK の route（#3863）が型つきで触る。dispatcher と共有する。
    #[allow(dead_code)]
    transport: Arc<Mutex<VirtioMmioTransport<D>>>,
    id: DeviceId,
    window: MmioRegion,
    line: GicSpiLine,
}

/// 登録済みのシリアル（ホストが出力を取り出すハンドル・識別子・窓・SPI の INTID）。
struct HvfSerial {
    console: SerialConsole,
    /// 登録の識別子（観測・将来の登録解除用）。
    #[allow(dead_code)]
    id: DeviceId,
    #[allow(dead_code)]
    window: MmioRegion,
    /// THRE 割り込みの INTID（level の SPI。#3892）。結線は `SpiLevelLine` が持つため今は読まず、
    /// 診断用に保持する（将来 `devices()` 相当の一覧へ載せる想定）。
    #[allow(dead_code)]
    spi_intid: u32,
}

/// virtio-mmio のデバイス群とシリアル、それを引く `ExitDispatcher`。macOS には PIO は無い（arm64）。
struct HvfDeviceBus<B: BlockBackend, N: NetBackend> {
    dispatcher: Arc<Mutex<ExitDispatcher>>,
    serial: Option<HvfSerial>,
    block: Vec<HvfBoundDevice<VirtioBlock<B>>>,
    net: Vec<HvfBoundDevice<VirtioNet<N>>>,
}

impl<B: BlockBackend, N: NetBackend> Drop for HvfDeviceBus<B, N> {
    /// dispatcher の `Arc` は vCPU の `MmioHandler` や `HvfVmParts` も持ち、バスを drop してもデバイス（と backend）は
    /// dispatcher の範囲表に残る。RAM と VM の解放より前にデバイスを手放すため、ここで範囲表を空にする（MVM-5・REPAIR-5）。
    /// vCPU スレッドがロックを持ったまま止まっている（期限切れ）場合に待たないよう `try_lock` を使い、
    /// 取れなければ空にしない（そのときは RAM もリークされ、解放順序の違反は起きない）。
    fn drop(&mut self) {
        match self.dispatcher.try_lock() {
            Ok(mut d) => d.clear(),
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner().clear(),
            Err(std::sync::TryLockError::WouldBlock) => {}
        }
    }
}

impl<B: BlockBackend, N: NetBackend> ReleaseDevices for HvfDeviceBus<B, N> {
    /// dispatcher の範囲表を空にする。`dispatcher()` の clone 保持者がロック中なら `deadline` まで 1ms 刻みで再試行し、
    /// それでも取れなければ `DeadlineExceeded`（成功扱いにしない。呼び出し側が RAM・VM を解放しない。MVM-5・REPAIR-5）。
    fn release_devices(&mut self, deadline: std::time::Duration) -> Result<(), MicrovmError> {
        let limit = std::time::Instant::now() + deadline;
        loop {
            match self.dispatcher.try_lock() {
                Ok(mut d) => {
                    d.clear();
                    return Ok(());
                }
                Err(std::sync::TryLockError::Poisoned(e)) => {
                    e.into_inner().clear();
                    return Ok(());
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    if std::time::Instant::now() >= limit {
                        return Err(MicrovmError::new(
                            MicrovmErrorCode::DeadlineExceeded,
                            "device dispatcher is locked; devices not released",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        }
    }
}

impl<B: BlockBackend + Send + 'static, N: NetBackend + Send + 'static> HvfDeviceBus<B, N> {
    /// block → net → シリアルの順に窓（`layout.virtio_mmio_window(i)`）と SPI（`vm.spi_line(layout, i)`）を割り当てて登録する。
    fn new(
        layout: &Arm64Layout,
        vm: &VmWithGic,
        block: Vec<B>,
        net: Vec<HvfNetDeviceConfig<N>>,
    ) -> Result<Self, MicrovmError> {
        let mut bus = HvfDeviceBus {
            dispatcher: Arc::new(Mutex::new(ExitDispatcher::new())),
            block: Vec::with_capacity(block.len()),
            net: Vec::with_capacity(net.len()),
            serial: None,
        };
        let mut index: u32 = 0;
        for backend in block {
            let transport = Arc::new(Mutex::new(VirtioMmioTransport::new(VirtioBlock::new(
                backend,
            ))?));
            let dev = bus.bind(layout, vm, index, transport)?;
            bus.block.push(dev);
            index += 1;
        }
        for cfg in net {
            let transport = Arc::new(Mutex::new(VirtioMmioTransport::new(VirtioNet::new(
                cfg.backend,
                cfg.mac,
            ))?));
            let dev = bus.bind(layout, vm, index, transport)?;
            bus.net.push(dev);
            index += 1;
        }
        // シリアルは virtio の後に登録する（virtio の DeviceId を変えない）。THRE 割り込みは level の SPI で結ぶ（#3892）。
        if let Some(window) = layout.serial {
            let console = SerialConsole::new();
            let line = vm.serial_line(layout)?;
            let spi_intid = line.intid();
            let id = bus
                .dispatcher
                .lock()
                .map_err(|_| internal("device dispatcher lock poisoned"))?
                .register_mmio(
                    window.base.raw(),
                    window.size,
                    console.mmio_device_with_irq(Arc::new(line)),
                )?;
            bus.serial = Some(HvfSerial {
                console,
                id,
                window,
                spi_intid,
            });
        }
        Ok(bus)
    }

    /// `index` 番目の窓に `transport` を登録し、割り込み線を結ぶ。
    fn bind<D: crate::virtio_mmio::VirtioDevice + Send + 'static>(
        &self,
        layout: &Arm64Layout,
        vm: &VmWithGic,
        index: u32,
        transport: Arc<Mutex<VirtioMmioTransport<D>>>,
    ) -> Result<HvfBoundDevice<D>, MicrovmError> {
        let window = layout.virtio_mmio_window(index)?;
        let line = vm.spi_line(layout, index)?;
        layout.check_virtio_injection(line.injection())?;
        let id = self
            .dispatcher
            .lock()
            .map_err(|_| internal("device dispatcher lock poisoned"))?
            .register_mmio(
                window.base.raw(),
                window.size,
                Box::new(SharedTransport(Arc::clone(&transport))),
            )?;
        Ok(HvfBoundDevice {
            transport,
            id,
            window,
            line,
        })
    }
}

impl<B: BlockBackend + Send + 'static, N: NetBackend + Send + 'static> HvfDeviceBus<B, N> {
    /// 全デバイスの `InterruptACK` の後処理（#3863）。
    fn ack_routes(&self) -> Vec<(DeviceId, Arc<dyn InterruptAckRoute>)> {
        fn route<D: crate::virtio_mmio::VirtioDevice + Send + 'static>(
            d: &HvfBoundDevice<D>,
        ) -> (DeviceId, Arc<dyn InterruptAckRoute>) {
            (
                d.id,
                Arc::new(BoundAckRoute {
                    transport: Arc::clone(&d.transport),
                    line: d.line.clone(),
                }),
            )
        }
        let b = self.block.iter().map(route);
        let n = self.net.iter().map(route);
        b.chain(n).collect()
    }
}

impl<B: BlockBackend, N: NetBackend> HvfDeviceBus<B, N> {
    fn infos(&self) -> Vec<HvfDeviceInfo> {
        let b = self
            .block
            .iter()
            .enumerate()
            .map(|(i, d)| (HvfDeviceKind::Block, i, d.id, d.window, d.line.intid()));
        let n = self
            .net
            .iter()
            .enumerate()
            .map(|(i, d)| (HvfDeviceKind::Net, i, d.id, d.window, d.line.intid()));
        b.chain(n)
            .map(|(kind, index, id, window, spi_intid)| HvfDeviceInfo {
                kind,
                index,
                window,
                spi_intid,
                id,
            })
            .collect()
    }
}

/// 組み立て済みの microVM が持つ資源と観測用の値。`Drop` が [`stop_and_release`] を drop 用の期限で呼ぶ（`HvfMicroVm` と
/// `RunningHvfMicroVm` が共有する。モジュール doc の「解放順序」）。資源は `Option` で、`release` が 1 回だけ取り出す。
struct HvfVmParts<B: BlockBackend, N: NetBackend> {
    vcpu: Option<VcpuHandle>,
    devices: Option<HvfDeviceBus<B, N>>,
    memory: Option<GuestMemory<RegisteredHvfRam<'static>>>,
    vm: Option<Arc<VmWithGic>>,
    dispatcher: Arc<Mutex<ExitDispatcher>>,
    infos: Vec<HvfDeviceInfo>,
    /// シリアルの出力ハンドル（`SerialConsole` の clone。fd を持たず、解放順序に影響しない）。
    serial: Option<SerialConsole>,
    layout: Arm64Layout,
    loaded: LoadedArm64,
    boot: ArmBootReadback,
}

impl<B: BlockBackend, N: NetBackend> HvfVmParts<B, N> {
    /// 資源を取り出し、停止と解放を行う。2 回目以降は `FailedPrecondition`。
    fn release(
        &mut self,
        op: &'static str,
        deadline: Duration,
    ) -> Result<HvfStopReport, MicrovmError> {
        let (Some(vcpu), Some(devices), Some(memory), Some(vm)) = (
            self.vcpu.take(),
            self.devices.take(),
            self.memory.take(),
            self.vm.take(),
        ) else {
            return Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "microvm resources are already released",
            ));
        };
        stop_and_release(
            op,
            vcpu,
            deadline,
            Resources {
                devices,
                memory,
                vm,
            },
        )
    }

    fn read_guest(&self, addr: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        let mem = self
            .memory
            .as_ref()
            .ok_or_else(|| internal("guest memory is already released"))?;
        mem.read_at(GuestAddress::new(addr), buf)
    }

    fn is_finished(&self) -> bool {
        self.vcpu.as_ref().is_none_or(VcpuHandle::is_finished)
    }
}

impl<B: BlockBackend, N: NetBackend> Drop for HvfVmParts<B, N> {
    /// stop を経ない drop も同じ手順を期限つき（[`DROP_STOP_DEADLINE`]）で行う。期限切れは `level=error` で記録される。
    fn drop(&mut self) {
        if self.vcpu.is_some() {
            let _ = self.release("hvf.microvm.drop", DROP_STOP_DEADLINE);
        }
    }
}

impl<B: BlockBackend, N: NetBackend> std::fmt::Debug for HvfVmParts<B, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HvfVmParts")
            .field("layout", &self.layout)
            .field("loaded", &self.loaded)
            .field("boot", &self.boot)
            .finish_non_exhaustive()
    }
}

/// 組み立て済みで、まだ start していない macOS microVM（ゲストは走っていない）。
/// [`Self::start`] で [`RunningHvfMicroVm`] になる。start しないまま drop してもゲストは走らず、資源を解放する。
pub struct HvfMicroVm<B: BlockBackend, N: NetBackend> {
    parts: HvfVmParts<B, N>,
}

impl<B: BlockBackend, N: NetBackend> std::fmt::Debug for HvfMicroVm<B, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HvfMicroVm")
            .field("parts", &self.parts)
            .finish_non_exhaustive()
    }
}

impl<B: BlockBackend + Send + 'static, N: NetBackend + Send + 'static> HvfMicroVm<B, N> {
    /// 構成を検証し、VM・GIC・RAM・カーネル・デバイス・vCPU 0 を組み立てる（順序と失敗時の解放はモジュール doc）。
    ///
    /// 戻った時点で vCPU 0 は起動レジスタを書かれて待機中で、ゲストはまだ走らない（[`Self::start`] が走らせる）。
    pub fn assemble(config: HvfMicroVmConfig<B, N>) -> Result<Self, MicrovmError> {
        let HvfMicroVmConfig {
            layout,
            kernel,
            initrd,
            cmdline,
            block,
            net,
            vcpu,
            serial,
        } = config;
        // serial = true で窓が無ければ既定の窓を入れる。検査順序を崩さないよう validate() は呼ばず直接代入する。
        let mut layout = layout;
        if serial && layout.serial.is_none() {
            layout.serial = Some(MmioRegion::new(ARM64_SERIAL_BASE, ARM64_SERIAL_SIZE));
        }
        check_assemble_input(&HvfAssembleInput {
            vcpus: layout.vcpus,
            ram_size: layout.ram.size,
            layout_virtio_count: layout.virtio_mmio_count,
            device_count: block.len().saturating_add(net.len()),
            serial,
            layout_serial: layout.serial.is_some(),
            image_len: kernel.len() as u64,
            initrd_len: initrd.as_ref().map(|i| i.len() as u64),
            cmdline_len: cmdline.len(),
        })?;
        layout.validate()?;

        // 以降はローカル変数の逆順 drop が解放順になる（宣言順: vm → memory → bus。drop は bus → memory → vm）。
        let vm = Arc::new(VmWithGic::create(&layout)?);
        let mut memory = HvfGuestRam::new(layout.ram.size)?.register_shared(
            &vm,
            layout.ram.base,
            layout.ipa_limit,
        )?;
        let (loaded, state) =
            load_arm64(&mut memory, &kernel, initrd.as_deref(), &cmdline, &layout)?;
        let devices = HvfDeviceBus::new(&layout, &vm, block, net)?;

        let readback: Arc<OnceLock<ArmBootReadback>> = Arc::new(OnceLock::new());
        let slot = Arc::clone(&readback);
        let handle = VcpuThread::spawn_gated(
            Arc::clone(&vm),
            move |v| {
                let regs = [(0u8, state.x0), (1, state.x1), (2, state.x2), (3, state.x3)];
                for (n, value) in regs {
                    let reg = HvReg::x(n).ok_or_else(|| internal("invalid general register"))?;
                    v.set_reg(reg, value)?;
                }
                v.set_reg(HvReg::PC, state.pc)?;
                v.set_reg(HvReg::CPSR, state.cpsr)?;
                v.set_sys_reg(HvSysReg::MPIDR_EL1, u64::from(ARM64_BOOT_CPU_MPIDR))?;
                let got = ArmBootReadback {
                    x0: v.get_reg(
                        HvReg::x(0).ok_or_else(|| internal("invalid general register"))?,
                    )?,
                    pc: v.get_reg(HvReg::PC)?,
                    cpsr: v.get_reg(HvReg::CPSR)?,
                    mpidr: v.get_sys_reg(HvSysReg::MPIDR_EL1)?,
                    // SCTLR_EL1 は書かない（既定値で M = 0・C = 0 を満たすかを確かめるだけ）。
                    sctlr: v.get_sys_reg(HvSysReg::SCTLR_EL1)?,
                };
                check_boot_readback(&state, &got)?;
                slot.set(got)
                    .map_err(|_| internal("boot readback was recorded twice"))
            },
            ExitHandlers {
                mmio: MmioHandler::with_shared_dispatcher(Arc::clone(&devices.dispatcher))
                    .with_ack_routes(devices.ack_routes()),
                hvc: HvcHandler::new(),
                timer: TimerHandler::new(),
            },
            vcpu,
        )?;
        let boot = match readback.get() {
            Some(b) => *b,
            None => {
                // 想定外（setup は成功で戻った）。ゲートを開けずに止める（ゲストは走らない）。
                let _ = handle.stop(DROP_STOP_DEADLINE);
                return Err(internal("boot readback was not recorded"));
            }
        };
        let dispatcher = Arc::clone(&devices.dispatcher);
        let infos = devices.infos();
        let serial = devices.serial.as_ref().map(|s| s.console.clone());
        Ok(HvfMicroVm {
            parts: HvfVmParts {
                vcpu: Some(handle),
                devices: Some(devices),
                memory: Some(memory),
                vm: Some(vm),
                dispatcher,
                infos,
                serial,
                layout,
                loaded,
                boot,
            },
        })
    }
}

impl<B: BlockBackend, N: NetBackend> HvfMicroVm<B, N> {
    /// ゲストを走らせ始める（start gate を開く）。以後の停止は [`RunningHvfMicroVm::stop`] か drop。
    ///
    /// ゲートの待ちは上限つき（`hvf_loop::START_GATE_WAIT`）で、`assemble` から長く放置されたスレッドは走らせずに終わっていることが
    /// ある。その場合も `start` は成功し、終了理由（`Failed(DeadlineExceeded)`）は `stop` の報告に出る。
    pub fn start(self) -> Result<RunningHvfMicroVm<B, N>, MicrovmError> {
        let started = Instant::now();
        match &self.parts.vcpu {
            Some(v) => v.open_start(),
            None => {
                return Err(MicrovmError::new(
                    MicrovmErrorCode::FailedPrecondition,
                    "microvm resources are already released",
                ));
            }
        }
        log_line(format_args!("level=info op=hvf.microvm.start outcome=ok"));
        Ok(RunningHvfMicroVm {
            parts: self.parts,
            started,
        })
    }

    /// 組み立てに使った配置。
    pub fn layout(&self) -> &Arm64Layout {
        &self.parts.layout
    }

    /// Image・initrd・FDT の配置結果。
    pub fn loaded(&self) -> &LoadedArm64 {
        &self.parts.loaded
    }

    /// vCPU 0 の `setup` で書いて読み戻した起動レジスタ（MPIDR_EL1・SCTLR_EL1 は生の値。記録は #3803）。
    pub fn boot_registers(&self) -> &ArmBootReadback {
        &self.parts.boot
    }

    /// 登録済みの virtio デバイスの配置（block → net の順）。シリアルは含まない（`serial_console` を参照）。
    pub fn devices(&self) -> Vec<HvfDeviceInfo> {
        self.parts.infos.clone()
    }

    /// シリアルの出力を取り出すハンドル（clone）。`config.serial` が `false` なら `None`（#3882・MVM-5・MVM-1）。
    ///
    /// Linux の `MicroVm::serial_console` と同じ語彙だが、こちらは任意なので `Option`。fd を持たず drop 順序に影響しない。
    /// 中身は非信頼のゲスト出力で、上限は `uart::MAX_OUTPUT_BYTES`。
    pub fn serial_console(&self) -> Option<SerialConsole> {
        self.parts.serial.clone()
    }

    /// MMIO dispatcher の共有ハンドル（vCPU の `MmioHandler` と同じ実体。#3793）。
    pub fn dispatcher(&self) -> &Arc<Mutex<ExitDispatcher>> {
        &self.parts.dispatcher
    }

    /// ゲスト RAM を読む（試験・観測用。参照は外へ出さずコピーして返す）。
    pub fn read_guest(&self, addr: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        self.parts.read_guest(addr, buf)
    }

    /// vCPU スレッドが既に終わったか（start 前に終わるのはゲートの期限切れだけ）。
    pub fn is_vcpu_finished(&self) -> bool {
        self.parts.is_finished()
    }
}

/// start 済みの macOS microVM。[`Self::stop`] か drop で止まる（モジュール doc の「解放順序」）。
pub struct RunningHvfMicroVm<B: BlockBackend, N: NetBackend> {
    parts: HvfVmParts<B, N>,
    started: Instant,
}

impl<B: BlockBackend, N: NetBackend> std::fmt::Debug for RunningHvfMicroVm<B, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunningHvfMicroVm")
            .field("parts", &self.parts)
            .field("finished", &self.parts.is_finished())
            .finish_non_exhaustive()
    }
}

impl<B: BlockBackend, N: NetBackend> RunningHvfMicroVm<B, N> {
    /// 停止を要求し、`deadline`（0 超 60 秒以下。範囲外は `InvalidArgument`）まで待って資源を解放する。
    ///
    /// ゲスト起因で既に終わっていたときはその理由（`GuestShutdown`・`Failed(..)`）を返す。期限切れは `TIMEOUT`
    /// （`DeadlineExceeded`）で、ゲスト RAM を解放せずリークする（残る資源と回収の方法はモジュール doc）。
    pub fn stop(mut self, deadline: Duration) -> Result<HvfStopReport, MicrovmError> {
        let result = self.parts.release("hvf.microvm.stop", deadline);
        log_line(format_args!(
            "level=info op=hvf.microvm.lifetime elapsed_us={}",
            self.started.elapsed().as_micros()
        ));
        result
    }

    /// vCPU スレッドが既に終わったか（ゲスト起因の終了を含む）。
    pub fn is_finished(&self) -> bool {
        self.parts.is_finished()
    }

    /// 組み立てに使った配置。
    pub fn layout(&self) -> &Arm64Layout {
        &self.parts.layout
    }

    /// Image・initrd・FDT の配置結果。
    pub fn loaded(&self) -> &LoadedArm64 {
        &self.parts.loaded
    }

    /// vCPU 0 の起動レジスタの読み戻し値。
    pub fn boot_registers(&self) -> &ArmBootReadback {
        &self.parts.boot
    }

    /// 登録済みデバイスの配置（block → net の順）。
    pub fn devices(&self) -> Vec<HvfDeviceInfo> {
        self.parts.infos.clone()
    }

    /// シリアルの出力を取り出すハンドル（clone）。`config.serial` が `false` なら `None`（#3882）。
    pub fn serial_console(&self) -> Option<SerialConsole> {
        self.parts.serial.clone()
    }

    /// MMIO dispatcher の共有ハンドル。
    pub fn dispatcher(&self) -> &Arc<Mutex<ExitDispatcher>> {
        &self.parts.dispatcher
    }

    /// ゲスト RAM を読む（試験・観測用。コピーして返す）。
    pub fn read_guest(&self, addr: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        self.parts.read_guest(addr, buf)
    }
}
