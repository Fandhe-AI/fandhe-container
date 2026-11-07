//! macOS（Hypervisor.framework）の microVM 構成体 `HvfMicroVm`（TASK-192.15・#3797・MVM-5・MVM-1・MVM-4）。
//!
//! 役割: 既にある部品（GIC つきの VM = `VmWithGic`〔#3792〕、ゲスト RAM = `HvfGuestRam`〔#3787〕、Image・initrd・FDT の配置 =
//! `boot_arm64::load_arm64`〔#3790〕、virtio-mmio のデバイスモデルと SPI 注入 = `GicSpiLine`〔#3795〕、vCPU スレッド =
//! `VcpuThread`〔#3791〕）を 1 つにまとめ、vCPU 0 を起動レジスタ込みで走らせる。Linux の `microvm::MicroVm::assemble` の対応物。
//! 呼び出し元は plugin-microvm（#3800）。start / stop の API は #3798（モジュール doc の「start / stop と解放順序」）。
//!
//! # 組み立ての順序（[`HvfMicroVm::assemble`]）
//! 1. 構成値の検査（資源を作る前。`hvf_abi::check_assemble_input` と `Arm64Layout::validate`）。`config.serial` と `layout.serial` を突き合わせ（#3882）、virtio + シリアルが MMIO 表の上限（`MAX_BUS_DEVICES`）を超える構成もここで拒否する。vcpus は 1 以上 `HVF_MAX_VCPUS`（32）以下で、構成の `vcpus` と `layout.vcpus` の一致も検査する（#3884）。
//! 2. VM + GIC（`VmWithGic::create`。GIC の配置違反は VM を作る前に拒否される）。
//! 3. ゲスト RAM の登録（`HvfGuestRam::register_shared`。対応付けが `Arc<HvVm>` を保持する）。
//! 4. Image・initrd・FDT の配置（`load_arm64`。Image ヘッダの検証はここ）。
//! 5. virtio-mmio のデバイス群を `ExitDispatcher` に登録し、各デバイスの割り込みを `GicSpiLine` に結ぶ（block → net → シリアルの順。シリアルは `layout.serial` があるときだけ。THRE 割り込みは level の SPI で結ぶ。#3882・#3892）。
//!    線の注入方式が FDT の trigger と一致するかをここで照合し（不一致は `InvalidArgument`）、`InterruptACK` の後処理
//!    （level 扱いの deassert / resample。#3863）の route を `MmioHandler` へ結ぶ。
//! 6. vCPU スレッドの作成（#3884）。まず vCPU 0 を `spawn_gated` で作り、続けて vCPU 1..N（AP）を `spawn_parked_ap` で順に作る。
//!    全 vCPU の作成は start より前に終わる（vCPU が走り出すとトポロジーは確定する、に反しない）。途中の失敗は、作成済みの全台を
//!    `stop_all` で回収してから返す。AP は `MPIDR_EL1` に `arm64_vcpu_mpidr_affinity(n)` を書いて照合し、起動要求まで parked で待つ
//!    （CPU_ON は `hvf_smp::HvfPowerControl` が entry を検査して AP のメールボックスへ積み、AP の owning thread がレジスタを書いて起動する。#3891。
//!    `HvfPowerControl` は BSP を先に spawn する順序を保つため空のスロットで作り、AP の spawn ごとに `attach` で結ぶ。全スロットは start より前に埋まる）。
//!    vCPU 0 の `setup` で X0 = FDT の GPA・X1〜X3 = 0・PC = カーネルのエントリ・CPSR = `0x3c5`・
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
//! 1. 停止要求 → kick（`hv_vcpus_exit` と、WFI の待ちを全台起こす `WfiWakeSet` の通知。#3887・#3948。待つ間も 10 ms ごとに打ち直す）→ vCPU スレッドが実行ループを抜ける。
//! 2. owning thread が自分の vCPU を `hv_vcpu_destroy` し（vCPU はスレッドに束縛され、他スレッドからは破棄できない）、捕捉していた
//!    `Arc<VmWithGic>` を落として報告を送る。報告を受けた時点で vCPU の破棄は済んでいる。
//!    vCPU は N 台あり、parked の AP も同じく owning thread が破棄する。報告は「N 台すべてが破棄済み」のときだけ `Ok`（`stop_all`）。
//! 3. 報告が `Ok` のときだけ、デバイス → ゲスト RAM（`hv_vm_unmap` に成功したら munmap。失敗ならリーク）→ VM（最後の `Arc` の drop が
//!    `hv_vm_destroy`）の順で解放する。ゲスト RAM の対応付けは `Arc<HvVm>` を握るため、unmap が `hv_vm_destroy` より後になることは型で
//!    起きない。munmap が `hv_vm_destroy` より前でよいのは、unmap の成功後はゲストからその backing へ到達できないため。
//!    ゲスト RAM は `GuestMemorySlot` が持ち、`release` がスロットの clone を `stop_and_release` へ渡し、
//!    vCPU の停止を確かめた後に `take_within` で期限つきに取り出す（#4027・#4092）。vCPU スレッドは virtio-block の
//!    route 越しにスロットの clone を持つ（#4028 で結線済み）。停止の途中でブロック I/O を処理していた vCPU の `with_memory_mut` は
//!    固定の RELEASED エラー（`Internal`）になり、その vCPU は `Failed(Internal)` で終わる（fail-closed。`Requested` にはならない）。
//!    backing の unmap は停止の報告の後だけになる。route 内でメモリの lock を持つ vCPU がバックエンド I/O で応答しなくても、
//!    stop は vCPU の停止待ちの期限で戻り（停止を確かめられなければ RAM をリーク）、RAM の取得も期限つきなので無期限には待たない
//!    （REPAIR-5・#4092）。残余: route はバックエンド I/O の間 RAM の lock を持つ（I/O 中に lock を外す構造は、ファイルを
//!    backing にするバックエンドを入れる TASK-75 / TASK-117 で見直す。REPAIR-3）。lock の毒化時は中身を解放せずリークする。
//!    `assemble` が vCPU スレッドを作った後に失敗した場合は、全台を止めた後に assemble のスレッドでスロットを取り出して手放す（ゲートを
//!    開けていないので安全。unmap と `hv_vm_destroy` を vCPU スレッドに担わせない）。
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
//! - 採らない案 2「vCPU スレッドで `hv_vm_destroy` まで行う」: RAM の `Send` は #4024（#4022 の個別承認）で入ったが、
//!   `hv_vm_destroy` まで別スレッドで行う案の採否は #3908 で評価する。
//! - 実機では破棄の後に同じプロセスで作り直せて、`stop` の所要は合成ゲストで 103〜241 µs だった（#3803）。
//!
//! ## 期限切れ（`TIMEOUT`）のとき
//! 解放はデバイスと VM の手放しに留め、ゲスト RAM の対応付けは `mem::forget` でリークする（ゲストがまだ書けうるメモリを再利用させない
//! fail-closed）。残る資源は vCPU スレッド・vCPU・VM（GIC を含む）・ゲスト RAM の mmap と map。リークした対応付けが `Arc<HvVm>` を
//! 握るため、スレッドが後で自力で終わっても `hv_vm_destroy` は走らず、同じプロセスでの再 assemble は `FailedPrecondition` になる。
//! 回収の方法はプロセスの終了だけ（plugin-microvm による再起動。#3800）。後から終わったスレッドの資源を回収する案は、`HostMapping`
//! の `Send`（#4024 で導入済み）を使って回収スレッドへ渡す実装そのものが本 issue の範囲外（追跡は #3908）。
//!
//! # 範囲外（REPAIR-3。担当 issue）
//! - virtio-block の QueueNotify の処理は #4028 で結線済み（`HvfDeviceBus::queue_notify_routes`。失敗は VM を止める）。virtio-net の
//!   route は #4029、`QueueStopped` の `stop_queue` への接続は #4031、期限切れ後の最後の `Arc` での RAM の回収は #4032、
//!   実カーネルでの block-read（edge と LevelHigh の割り込みの配送）は #4014。全体の追跡は #3908。
//! - PSCI は #3794、WFI / vtimer は #3796 で実装済み。SMP は AP のスレッドと `MPIDR_EL1`・N 台の停止の集約まで #3884 で実装済みで、
//!   CPU_ON による AP の実起動・AP ごとの `ExitHandlers`・CPU_OFF 後の parked への戻し・AP の exit による全台の停止の検知（`VcpuSet::is_finished`）は #3891 で実装済み（残余は `hvf_smp` の「未実装・逸脱」）。シリアルの入力（RX）、`NetDeviceConfig`（Linux 限定）との共通化、構造化ログ（crate にログ基盤が無い）。
//! - 書いた範囲の PoC までの clean と I-cache 無効化の要否（合成 Image は無しで起動した。#3803。実カーネルは #3988）。
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
use crate::guest_memory::GuestAddress;
use crate::guest_memory_slot::GuestMemorySlot;
use crate::hvf::gic::{GicSpiLine, VmWithGic};
use crate::hvf::hvc::HvcHandler;
use crate::hvf::memory::{HvfGuestRam, RegisteredHvfRam};
use crate::hvf::mmio::MmioHandler;
use crate::hvf::timer::TimerHandler;
use crate::hvf::vcpu::{ExitHandlers, VcpuSet, VcpuThread, VcpuThreadConfig};
use crate::hvf_abi::{HvReg, HvSysReg, HvfAssembleInput, check_assemble_input};
use crate::hvf_lifecycle::{
    DROP_STOP_DEADLINE, HvfStopReport, ReleaseDevices, Resources, VcpuStopper, stop_and_release,
};
use crate::hvf_loop::log_line;
use crate::hvf_smp::{ApMailbox, HvfPowerControl};
use crate::hvf_wake::{AckRouteLearner, SpiRouteHint};
use crate::interrupt::{
    BlockQueueNotifyRoute, BoundAckRoute, InterruptAckRoute, InterruptLine, QueueNotifyRoute,
};
use crate::psci::PsciCpus;
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
    /// vCPU 数（1 以上 `HVF_MAX_VCPUS` 以下）。`layout.vcpus`（FDT の `cpu@N` の個数）と一致すること（#3884）。
    pub vcpus: u32,
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
    /// QueueNotify の route（#4028）と ACK の route（#3863）が型つきで触る。dispatcher と共有する。
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

    /// virtio-block の `QueueNotify` の処理（virtqueue の処理と完了の割り込み。#4028・MVM-5・MVM-1）。
    ///
    /// 台ごとに 1 回だけ作り、全 vCPU の `MmioHandler` が同じ実体（`Arc`）を共有する。ゲスト RAM は `memory` スロットの
    /// clone で受け渡す（`HvfVmParts::release` が停止確認後に取り出すため、解放後の通知は `Internal` で fail-closed）。
    /// virtio-net の route は #4029 の担当で、それまで net は計数だけで続行する（REPAIR-3）。
    fn queue_notify_routes(
        &self,
        memory: &GuestMemorySlot<RegisteredHvfRam<'static>>,
    ) -> Vec<(DeviceId, Arc<dyn QueueNotifyRoute>)> {
        self.block
            .iter()
            .map(|d| {
                let route: Arc<dyn QueueNotifyRoute> = Arc::new(BlockQueueNotifyRoute::new(
                    Arc::clone(&d.transport),
                    memory.clone(),
                    d.line.clone(),
                ));
                (d.id, route)
            })
            .collect()
    }

    /// 全デバイスの SPI の宛先のヒント（vCPU ごとの `AckRouteLearner` が ACK を処理した vCPU を書く。#3948）。
    fn route_hints(&self) -> Vec<(DeviceId, SpiRouteHint)> {
        let b = self.block.iter().map(|d| (d.id, d.line.route_hint()));
        let n = self.net.iter().map(|d| (d.id, d.line.route_hint()));
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
/// `RunningHvfMicroVm` が共有する。モジュール doc の「解放順序」）。資源は `Option`（ゲスト RAM だけは `GuestMemorySlot`）で、`release` が 1 回だけ取り出す。
struct HvfVmParts<B: BlockBackend, N: NetBackend> {
    /// vCPU 0（BSP）と parked の AP（#3884）。
    vcpus: Option<VcpuSet>,
    /// 各 vCPU の `MPIDR_EL1` の読み戻し（生の値。index 順）。
    mpidrs: Vec<u64>,
    devices: Option<HvfDeviceBus<B, N>>,
    /// ゲスト RAM の所有。`release` がスロットの clone を渡し、停止確認後に期限つきで取り出す（#4027・#4092）。
    memory: GuestMemorySlot<RegisteredHvfRam<'static>>,
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
        // RAM は stop より前に取り出さない（vCPU がバックエンド I/O 中に lock を持つと期限なしで待つため。REPAIR-5・#4092）。
        // スロットの clone を渡し、`stop_and_release` が vCPU の停止を確かめた後に期限つきで取り出す。
        // 停止・取得が失敗したら clone を `forget` してリークする（fail-closed）ので、この構造体の drop では解放されない。
        let (Some(vcpus), Some(devices), Some(vm)) =
            (self.vcpus.take(), self.devices.take(), self.vm.take())
        else {
            return Err(MicrovmError::new(
                MicrovmErrorCode::FailedPrecondition,
                "microvm resources are already released",
            ));
        };
        stop_and_release(
            op,
            vcpus,
            deadline,
            Resources {
                devices,
                memory: self.memory.clone(),
                vm,
            },
        )
    }

    fn read_guest(&self, addr: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        self.memory
            .with_memory(|m| m.read_at(GuestAddress::new(addr), buf))
    }

    fn is_finished(&self) -> bool {
        self.vcpus.as_ref().is_none_or(VcpuSet::is_finished)
    }
}

impl<B: BlockBackend, N: NetBackend> Drop for HvfVmParts<B, N> {
    /// stop を経ない drop も同じ手順を期限つき（[`DROP_STOP_DEADLINE`]）で行う。期限切れは `level=error` で記録される。
    fn drop(&mut self) {
        if self.vcpus.is_some() {
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
            vcpus,
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
            vcpus,
            layout_vcpus: layout.vcpus,
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
        // 以降の失敗経路は、スロットを取り出してから返す（`abort_after_spawn`）。vCPU スレッドが route 越しに最後の `Arc` を
        // 持って unmap と `hv_vm_destroy` を担う形（採らない案 2）にしないため。
        let memory = GuestMemorySlot::new(memory);
        let devices = HvfDeviceBus::new(&layout, &vm, block, net)?;
        let queue_routes = devices.queue_notify_routes(&memory);

        let psci = Arc::new(PsciCpus::new(layout.vcpus)?);
        let power = Arc::new(HvfPowerControl::new(
            layout.vcpus,
            layout.ram.base.raw(),
            layout.ram.size,
        ));
        let ap_config = vcpu.clone();
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
                    .with_ack_routes(devices.ack_routes())
                    .with_queue_notify_routes(queue_routes.clone())
                    .with_ack_learner(AckRouteLearner::new(0, devices.route_hints())),
                hvc: HvcHandler::with_cpus(Arc::clone(&psci), power.clone(), 0)?,
                timer: TimerHandler::new(),
            },
            vcpu,
        )?;
        let mut vcpu_set = VcpuSet::new(handle);
        let boot = match readback.get() {
            Some(b) => *b,
            None => {
                // 想定外（setup は成功で戻った）。ゲートを開けずに止める（ゲストは走らない）。
                abort_after_spawn(vcpu_set, &memory);
                return Err(internal("boot readback was not recorded"));
            }
        };
        // AP（vCPU 1..N）を parked で作る。途中で失敗したら、作成済みの全台を回収してから返す（残りの資源は逆順 drop）。
        let mut mpidrs = vec![boot.mpidr];
        for index in 1..layout.vcpus {
            let mailbox = Arc::new(ApMailbox::new());
            let spawned =
                HvcHandler::with_cpus(Arc::clone(&psci), power.clone(), index).and_then(|hvc| {
                    let handlers = ExitHandlers {
                        mmio: MmioHandler::with_shared_dispatcher(Arc::clone(&devices.dispatcher))
                            .with_ack_routes(devices.ack_routes())
                            .with_queue_notify_routes(queue_routes.clone())
                            .with_ack_learner(AckRouteLearner::new(index, devices.route_hints())),
                        hvc,
                        timer: TimerHandler::new(),
                    };
                    VcpuThread::spawn_parked_ap(
                        Arc::clone(&vm),
                        index,
                        handlers,
                        Arc::clone(&mailbox),
                        Arc::clone(&psci),
                        &ap_config,
                    )
                });
            match spawned {
                Ok((ap, raw)) => {
                    vcpu_set.push_ap(ap);
                    mpidrs.push(raw);
                    // AP が起きてから結ぶ。結べなければ（不変条件違反）全台を回収して返す。
                    if let Err(e) = power.attach(index, mailbox) {
                        abort_after_spawn(vcpu_set, &memory);
                        return Err(e);
                    }
                }
                Err(e) => {
                    abort_after_spawn(vcpu_set, &memory);
                    return Err(e);
                }
            }
        }
        let dispatcher = Arc::clone(&devices.dispatcher);
        let infos = devices.infos();
        let serial = devices.serial.as_ref().map(|s| s.console.clone());
        Ok(HvfMicroVm {
            parts: HvfVmParts {
                vcpus: Some(vcpu_set),
                mpidrs,
                devices: Some(devices),
                memory,
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

/// vCPU スレッドを作った後の失敗経路の後始末（`assemble` 専用）。全台を止めてから、ゲスト RAM を assemble のスレッドで取り出して
/// drop する。ゲートを開けていないのでゲストは 1 命令も走っておらず、drop は安全。`stop` が期限切れでも RAM は取り出して
/// ここで手放す（vCPU スレッドが route 越しに最後の `Arc` を持って unmap を行う形にしない。#4028）。
fn abort_after_spawn(vcpu_set: VcpuSet, memory: &GuestMemorySlot<RegisteredHvfRam<'static>>) {
    let _ = vcpu_set.stop(DROP_STOP_DEADLINE);
    // 全台停止済みなので lock は空いている。取得は期限つきで、失敗時は中身をリークする（fail-closed）。
    let _ = memory.take_within(DROP_STOP_DEADLINE);
}

impl<B: BlockBackend, N: NetBackend> HvfMicroVm<B, N> {
    /// ゲストを走らせ始める（start gate を開く）。以後の停止は [`RunningHvfMicroVm::stop`] か drop。
    ///
    /// ゲートの待ちは上限つき（`hvf_loop::START_GATE_WAIT`）で、`assemble` から長く放置されたスレッドは走らせずに終わっていることが
    /// ある。その場合も `start` は成功し、終了理由（`Failed(DeadlineExceeded)`）は `stop` の報告に出る。
    pub fn start(self) -> Result<RunningHvfMicroVm<B, N>, MicrovmError> {
        let started = Instant::now();
        // 開けるのは vCPU 0 の gate だけ。AP は CPU_ON（#3891。メールボックス）まで parked のまま。
        match &self.parts.vcpus {
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

    /// 各 vCPU の `MPIDR_EL1` の読み戻し（生の値。index 順。`[0]` は `boot_registers().mpidr` と同じ。記録は #3803）。
    pub fn vcpu_mpidrs(&self) -> &[u64] {
        &self.parts.mpidrs
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

    /// 各 vCPU の `MPIDR_EL1` の読み戻し（生の値。index 順）。
    pub fn vcpu_mpidrs(&self) -> &[u64] {
        &self.parts.mpidrs
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
