//! macOS（Hypervisor.framework）の microVM 構成体 `HvfMicroVm`（TASK-192.15・#3797・MVM-5・MVM-1・MVM-4）。
//!
//! 役割: 既にある部品（GIC つきの VM = `VmWithGic`〔#3792〕、ゲスト RAM = `HvfGuestRam`〔#3787〕、Image・initrd・FDT の配置 =
//! `boot_arm64::load_arm64`〔#3790〕、virtio-mmio のデバイスモデルと SPI 注入 = `GicSpiLine`〔#3795〕、vCPU スレッド =
//! `VcpuThread`〔#3791〕）を 1 つにまとめ、vCPU 0 を起動レジスタ込みで走らせる。Linux の `microvm::MicroVm::assemble` の対応物。
//! 呼び出し元は start / stop の API（#3798）と plugin-microvm（#3800）。
//!
//! # 組み立ての順序（[`HvfMicroVm::assemble`]）
//! 1. 構成値の検査（資源を作る前。`hvf_abi::check_assemble_input` と `Arm64Layout::validate`）。vcpus 2 以上は `Unimplemented`。
//! 2. VM + GIC（`VmWithGic::create`。GIC の配置違反は VM を作る前に拒否される）。
//! 3. ゲスト RAM の登録（`HvfGuestRam::register_shared`。対応付けが `Arc<HvVm>` を保持する）。
//! 4. Image・initrd・FDT の配置（`load_arm64`。Image ヘッダの検証はここ）。
//! 5. virtio-mmio のデバイス群を `ExitDispatcher` に登録し、各デバイスの割り込みを `GicSpiLine` に結ぶ（block → net の順）。
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
//! # drop
//! 宣言順が drop 順（vCPU → デバイス → RAM → VM）。`Drop` はまず vCPU スレッドを期限つき（5 秒）で止める。停止が期限切れ等で
//! 失敗した（スレッドが VM を持ったまま残る）ときは、RAM の対応付けを `mem::forget` でリークする（ゲストがまだ書けうる
//! メモリを解放しない fail-closed。VM も残り、後続の `HvVm::create` は `FailedPrecondition` になる）。start / stop の API と
//! 解放順序の詰めは #3798。この `Drop` は最小の後始末。
//!
//! # 範囲外（REPAIR-3。担当 issue）
//! - 実行開始の制御（start gate）: `spawn` は ready の後すぐ実行ループに入るため、assemble の時点でゲストは走り始める。現状は
//!   exit のスタブ（#3793・#3794・#3796）が `Unimplemented` を返すので、実カーネルは最初の exit で `Failed(Unimplemented)` になる（#3798）。
//! - `MmioHandler` への dispatcher とゲスト RAM の受け渡し（[`HvfMicroVm::dispatcher`] を渡す）と `HostMapping` の `Send`（#3793・#3798）。
//! - PSCI・WFI / vtimer（#3794・#3796）、SMP、`NetDeviceConfig`（Linux 限定）との共通化、構造化ログ（crate にログ基盤が無い）。
//! - 書いた範囲の PoC までの clean と I-cache 無効化の要否、MPIDR / SCTLR の生の値の記録（#3803）。
//! - Image の署名・digest の検証は本層の責務ではない（plugin-microvm 側。PLUG-11）。構成値・パスはエラーに載せない（ERR-1）。
//!
//! `unsafe` は持たない（crate の `#![deny(unsafe_code)]` で担保）。

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::arm64_layout::{ARM64_BOOT_CPU_MPIDR, Arm64Layout, MmioRegion};
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
use crate::virtio_block::{BlockBackend, VirtioBlock};
use crate::virtio_mmio::{SharedTransport, VirtioMmioTransport};
use crate::virtio_net::{NetBackend, VirtioNet};

/// drop 時に vCPU スレッドの停止を待つ期限（REPAIR-5）。
const DROP_STOP_DEADLINE: Duration = Duration::from_secs(5);

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
    /// QueueNotify の処理（#3798）が型つきで触る。dispatcher と共有する。
    #[allow(dead_code)]
    transport: Arc<Mutex<VirtioMmioTransport<D>>>,
    id: DeviceId,
    window: MmioRegion,
    line: GicSpiLine,
}

/// virtio-mmio のデバイス群と、それを引く `ExitDispatcher`。macOS には PIO・UART は無い（arm64）。
struct HvfDeviceBus<B: BlockBackend, N: NetBackend> {
    dispatcher: Arc<Mutex<ExitDispatcher>>,
    block: Vec<HvfBoundDevice<VirtioBlock<B>>>,
    net: Vec<HvfBoundDevice<VirtioNet<N>>>,
}

impl<B: BlockBackend + Send + 'static, N: NetBackend + Send + 'static> HvfDeviceBus<B, N> {
    /// block → net の順に窓（`layout.virtio_mmio_window(i)`）と SPI（`vm.spi_line(layout, i)`）を割り当てて登録する。
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

/// 組み立て済みの macOS microVM。宣言順が drop 順（モジュール doc の「drop」）。
pub struct HvfMicroVm<B: BlockBackend, N: NetBackend> {
    vcpu: Option<VcpuHandle>,
    devices: HvfDeviceBus<B, N>,
    memory: Option<GuestMemory<RegisteredHvfRam<'static>>>,
    vm: Arc<VmWithGic>,
    layout: Arm64Layout,
    loaded: LoadedArm64,
    boot: ArmBootReadback,
}

impl<B: BlockBackend, N: NetBackend> std::fmt::Debug for HvfMicroVm<B, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HvfMicroVm")
            .field("layout", &self.layout)
            .field("loaded", &self.loaded)
            .field("boot", &self.boot)
            .finish_non_exhaustive()
    }
}

impl<B: BlockBackend + Send + 'static, N: NetBackend + Send + 'static> HvfMicroVm<B, N> {
    /// 構成を検証し、VM・GIC・RAM・カーネル・デバイス・vCPU 0 を組み立てる（順序と失敗時の解放はモジュール doc）。
    ///
    /// 戻った時点で vCPU 0 は実行中（start gate は #3798）。
    pub fn assemble(config: HvfMicroVmConfig<B, N>) -> Result<Self, MicrovmError> {
        let HvfMicroVmConfig {
            layout,
            kernel,
            initrd,
            cmdline,
            block,
            net,
            vcpu,
        } = config;
        check_assemble_input(&HvfAssembleInput {
            vcpus: layout.vcpus,
            ram_size: layout.ram.size,
            layout_virtio_count: layout.virtio_mmio_count,
            device_count: block.len().saturating_add(net.len()),
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
        let handle = VcpuThread::spawn(
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
                mmio: MmioHandler::new(),
                hvc: HvcHandler::new(),
                timer: TimerHandler::new(),
            },
            vcpu,
        )?;
        let boot = match readback.get() {
            Some(b) => *b,
            None => {
                // 想定外（setup は成功で戻った）。スレッドを止めて失敗にする。
                let _ = handle.stop(DROP_STOP_DEADLINE);
                return Err(internal("boot readback was not recorded"));
            }
        };
        Ok(HvfMicroVm {
            vcpu: Some(handle),
            devices,
            memory: Some(memory),
            vm,
            layout,
            loaded,
            boot,
        })
    }
}

impl<B: BlockBackend, N: NetBackend> HvfMicroVm<B, N> {
    /// 組み立てに使った配置。
    pub fn layout(&self) -> &Arm64Layout {
        &self.layout
    }

    /// Image・initrd・FDT の配置結果。
    pub fn loaded(&self) -> &LoadedArm64 {
        &self.loaded
    }

    /// vCPU 0 の `setup` で書いて読み戻した起動レジスタ（MPIDR_EL1・SCTLR_EL1 は生の値。記録は #3803）。
    pub fn boot_registers(&self) -> &ArmBootReadback {
        &self.boot
    }

    /// 登録済みデバイスの配置（block → net の順）。
    pub fn devices(&self) -> Vec<HvfDeviceInfo> {
        self.devices.infos()
    }

    /// MMIO dispatcher の共有ハンドル。`MmioHandler` への受け渡しは #3793。
    pub fn dispatcher(&self) -> &Arc<Mutex<ExitDispatcher>> {
        &self.devices.dispatcher
    }

    /// ゲスト RAM を読む（試験・観測用。参照は外へ出さずコピーして返す）。
    pub fn read_guest(&self, addr: u64, buf: &mut [u8]) -> Result<(), MicrovmError> {
        let mem = self
            .memory
            .as_ref()
            .ok_or_else(|| internal("guest memory is already released"))?;
        mem.read_at(GuestAddress::new(addr), buf)
    }

    /// vCPU スレッドが既に終わったか（ゲスト起因の終了を含む）。
    pub fn is_vcpu_finished(&self) -> bool {
        self.vcpu.as_ref().is_none_or(VcpuHandle::is_finished)
    }

    /// GIC つきの VM（`Arc`）。
    pub fn vm(&self) -> &Arc<VmWithGic> {
        &self.vm
    }
}

impl<B: BlockBackend, N: NetBackend> Drop for HvfMicroVm<B, N> {
    fn drop(&mut self) {
        let Some(handle) = self.vcpu.take() else {
            return;
        };
        if handle.stop(DROP_STOP_DEADLINE).is_err() {
            // vCPU スレッドが VM を持ったまま残る。対応付けを解放せずリークして、ゲストが書けうるメモリを再利用させない。
            if let Some(mem) = self.memory.take() {
                std::mem::forget(mem);
            }
        }
    }
}
