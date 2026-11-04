//! macOS の GICv3 の作成順序の強制と、配置・timer の照合（TASK-192.12・#3792・MVM-5・MVM-1）。
//!
//! 役割: Hypervisor.framework の `hv_gic_create` は「VM 作成後・vCPU 作成前・VM につき 1 回」しか呼べない。
//! この順序を型で強制する。流れは `HvVm` → [`VmWithGic`]（GIC 作成済み）→ `HvVcpu` で、vCPU は
//! [`VmWithGic::create_vcpu`] からだけ作れる（`HvVm::create_vcpu`・`GicApi::create`・`GicApi::config_create`・`GicApi::set_spi`・`GicConfig` は crate 外へ公開しない）。
//! 後続の VM 構成体（#3797）が [`VmWithGic`] / [`HvfGic`] を使い、virtio の完了通知は [`GicSpiLine`]（#3795）が担う。
//!
//! # 順序の契約
//! - [`HvfGic::create`] は `HvVm` を値で消費する。生きている vCPU は `&HvVm` を借用するため、vCPU が残る間は
//!   `HvVm` を move できず「vCPU 作成後の GIC 作成」は借用検査で書けない。GIC 作成済みの VM は [`VmWithGic`] に
//!   包まれて裸の `HvVm` へ戻れないため、2 個目の GIC も書けない（Issue の例示は `&HvVm` だが、それでは
//!   vCPU と共存できて順序を強制できない）。
//! - 起動手順は VM → GIC → ゲスト RAM の登録（`register(vgic.vm(), ..)`）→ vCPU の順になる。
//! - 検証は VM 作成より前に行える（[`HvfGic::probe`]）。[`VmWithGic::create`] は probe が失敗すれば VM を作らない。
//!   [`HvfGic::create`] も内部で再検証し（fail-closed）、失敗時は受け取った `HvVm` をその場で drop（destroy）する。
//! - macOS 15 未満・シンボル未解決は `GicApi::get` の `Unimplemented` をそのまま返す。
//! - `GicConfig` は `!Send` のため、config 作成から `hv_gic_create` までを呼び出しスレッドで同期に終える。
//!
//! # 検証の内容
//! 配置の違反（アライン・窓の不足）は `InvalidArgument`、フレームワークの異常値と virtual timer の INTID の不一致は
//! `Internal`（純関数は `crate::arm64_layout`。FDT を API の値から組み直さず照合で fail-closed にする）。
//! `hv_gic_get_redistributor_size` は vCPU 1 台分と読む（確定は #3803）。
//!
//! # SPI の注入（TASK-192.13・#3795・MVM-5・MVM-1）
//! [`GicSpiLine`] は `crate::interrupt::InterruptLine` の macOS 実装で、virtio-mmio 1 台分の SPI に対応する。
//! 呼び出し元は virtio デバイスの完了通知（`complete_block_notify` 等。Linux の `IrqFd` と同じ位置）。
//! - 通知方式は FDT の trigger と一致させる（#3863）。既定は edge-rising で、`trigger` は `hv_gic_set_spi(intid, true)` を
//!   1 回呼ぶだけ（edge の `false` は framework が無視するため呼ばない）。`Arm64Layout::virtio_spi_trigger` を `LevelHigh`
//!   にした構成では、InterruptACK の後に `crate::interrupt::complete_interrupt_ack` が `resample` を呼び、要因が無ければ
//!   `set_spi(intid, false)`（deassert）、残っていれば `set_spi(intid, true)`（上げ直し）にする。線の作成
//!   （[`VmWithGic::spi_line_with_injection`]）で FDT の trigger と注入方式の食い違いを `InvalidArgument` で拒否する。
//!   呼び出しは data abort の exit 1 回につき高々 1 回で増幅せず、待ちも持たない（REPAIR-5 不要）。
//! - INTID は `Arm64Layout` の SPI 番号 + 32 で、作成時に `hv_gic_get_spi_interrupt_range` の範囲内か検証する
//!   （範囲外は `InvalidArgument`。[`HvfGic::probe`] が全 virtio の SPI を VM 作成前に先に検査する）。
//! - スレッド: `hv_gic_set_spi` を vCPU の owning thread 以外から呼べるかは Apple のドキュメントに記述が無い。
//!   引数が整数と bool だけで失敗は戻り値で返るため [`GicSpiLine`] は `Send + Sync` とし、
//!   `hvf_device_spi_reaches_guest` が非 vCPU スレッドから呼んで観測する（結果の記録は #3803。未観測）。
//! - 寿命: `hv_gic_set_spi` は VM を取らないため、古い line が後から作った別の VM へ注入しうる。
//!   [`VmWithGic`] が持つ生存フラグ（`RwLock<bool>`）を各 line が共有し、`Drop` で書き込みロックを取って false にする。
//!   `trigger` と `resample` は読み取りロックを `set_spi` の間保持するので、破棄と注入は競合せず、破棄後は `Internal` で拒否する。
//! - 残余: MSI の範囲は GIC の config に MSI を設定しないため対象外。
//!
//! # 範囲外（REPAIR-3）
//! SMP（AP の起動。`MPIDR_EL1` の実設定は #3797 の `HvfMicroVm::assemble` が vCPU 0 の `setup` で行う）・MSI・
//! `hv_gic_get_redistributor_base` の照合・`HvGicIntid` の virtual timer 以外の照合・SDK ヘッダとの値の照合（#3803）・
//! vCPU の個別 drop と「破棄は VM 破棄時のみ」の整合（#3798・#3791）。`unsafe` は持たない。
//!
//! # 所有（#3797）
//! [`VmWithGic`] は内部の VM を `Arc<HvVm>` で持つ。ゲスト RAM の対応付け（`HvVm::map_shared`）が VM への参照を保持し、
//! 「unmap → `hv_vm_destroy`」の順を参照数で保証するため。`HvfGic::create` が `HvVm` を値で消費する点は変わらない。

use std::sync::{Arc, RwLock};

use crate::arm64_layout::{Arm64Layout, GicGeometry, check_spi_intid, check_virtual_timer_intid};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_abi::HvGicIntid;
use crate::interrupt::{InterruptLine, IrqLevel, IrqTrigger, LevelInterruptLine, LineResample};
use crate::spi::{SpiLevelLine, SpiLine, SpiSink};
use crate::sys::{GicApi, HvVcpu, HvVm};

fn to_u64(v: usize) -> Result<u64, MicrovmError> {
    u64::try_from(v).map_err(|_| {
        MicrovmError::new(
            MicrovmErrorCode::Internal,
            "gic value reported by the hypervisor is out of range",
        )
    })
}

/// 検証済みの GIC の配置の記録（値型）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HvfGic {
    geometry: GicGeometry,
    virtual_timer_intid: u32,
    spi_base: u32,
    spi_count: u32,
}

impl HvfGic {
    /// `hv_gic_get_spi_interrupt_range` の `(base, count)`（全 virtio の SPI を照合済み）。
    pub fn spi_range(&self) -> (u32, u32) {
        (self.spi_base, self.spi_count)
    }

    /// フレームワークの実値。
    pub fn geometry(&self) -> GicGeometry {
        self.geometry
    }

    /// `hv_gic_get_intid(EL1_VIRTUAL_TIMER)` の値（FDT の virtual timer と照合済み）。
    pub fn virtual_timer_intid(&self) -> u32 {
        self.virtual_timer_intid
    }

    /// VM を作らない前検査。API の解決、配置の整合、アラインと大きさ、virtual timer の INTID を検査する。
    ///
    /// 照会に VM が要らない前提（`hvf_device_gic_symbols_resolve` が VM なしで照会している）。
    pub fn probe(layout: &Arm64Layout) -> Result<HvfGic, MicrovmError> {
        let api = GicApi::get()?;
        layout.validate()?;
        let geometry = GicGeometry {
            dist_size: to_u64(api.distributor_size()?)?,
            dist_align: to_u64(api.distributor_base_alignment()?)?,
            redist_size_per_cpu: to_u64(api.redistributor_size()?)?,
            redist_align: to_u64(api.redistributor_base_alignment()?)?,
        };
        layout.check_gic_geometry(&geometry)?;
        let virtual_timer_intid = api.intid(HvGicIntid::EL1_VIRTUAL_TIMER)?.get();
        check_virtual_timer_intid(virtual_timer_intid)?;
        let (spi_base, spi_count) = api.spi_interrupt_range()?;
        layout.check_virtio_spi_range(spi_base, spi_count)?;
        layout.check_serial_spi_range(spi_base, spi_count)?;
        Ok(HvfGic {
            geometry,
            virtual_timer_intid,
            spi_base,
            spi_count,
        })
    }

    /// `vm` に GIC を作り、[`VmWithGic`] を返す。`vm` は消費する（順序の強制は doc の「順序の契約」）。
    ///
    /// 検証（[`Self::probe`]）が失敗すると `vm` はここで drop される。
    pub fn create(vm: HvVm, layout: &Arm64Layout) -> Result<VmWithGic, MicrovmError> {
        let gic = Self::probe(layout)?;
        let api = GicApi::get()?;
        let mut config = api.config_create()?;
        config.set_distributor_base(layout.gic_dist.base.raw())?;
        config.set_redistributor_base(layout.gic_redist.base.raw())?;
        api.create(&vm, config)?;
        Ok(VmWithGic {
            gic,
            vm: Arc::new(vm),
            alive: Arc::new(RwLock::new(true)),
        })
    }
}

/// GIC 作成済みの VM。vCPU はここからだけ作れる。drop は `HvVm` の drop（GIC は VM と一緒に消える）。
#[derive(Debug)]
pub struct VmWithGic {
    gic: HvfGic,
    /// `Arc` なのは、ゲスト RAM の対応付け（`HvVm::map_shared`）が VM を生かしておくため（#3797）。crate の外へは出さない。
    vm: Arc<HvVm>,
    /// 生存フラグ。[`GicSpiLine`] と共有し、`Drop` で false にする。
    alive: Arc<RwLock<bool>>,
}

impl Drop for VmWithGic {
    fn drop(&mut self) {
        // `vm` はこの後に drop される。進行中の `trigger`（読み取りロック）を待ってから閉じる。
        let mut g = self.alive.write().unwrap_or_else(|e| e.into_inner());
        *g = false;
    }
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<VmWithGic>();
};

impl VmWithGic {
    /// 推奨経路。[`HvfGic::probe`] → `HvVm::create` → [`HvfGic::create`] の順に呼び、検証が失敗したら VM を作らない。
    pub fn create(layout: &Arm64Layout) -> Result<VmWithGic, MicrovmError> {
        HvfGic::probe(layout)?;
        HvfGic::create(HvVm::create()?, layout)
    }

    /// VM への参照（`HvVm::map`・`HvfGuestRam::register` 用）。`Deref` にしないのは `create_vcpu` の見え方を取り違えないため。
    pub fn vm(&self) -> &HvVm {
        &self.vm
    }

    /// `Arc<HvVm>`（`HvfGuestRam::register_shared` 用。crate の外へは公開しない。#3797）。
    pub(crate) fn shared_vm(&self) -> &Arc<HvVm> {
        &self.vm
    }

    /// GIC の配置の記録。
    pub fn gic(&self) -> &HvfGic {
        &self.gic
    }

    /// 呼び出しスレッドに束縛された vCPU を作る（GIC 作成後なので順序の条件を満たす）。
    ///
    /// 呼び出し側（#3797）の手順: 最初の `run_once` の前に `set_sys_reg(HvSysReg::MPIDR_EL1, ..)` で
    /// affinity を FDT の `cpu@0` の `reg`（`ARM64_BOOT_CPU_MPIDR`。Aff0..Aff2 = 0）に合わせ、読み戻して確かめる
    /// （フレームワークによる加工の有無は #3803 で観測）。vCPU の実行開始後はトポロジが確定する。
    /// 試験の `0x8000_0001` はレジスタ往復の確認で、起動の契約ではない。
    ///
    /// ```compile_fail
    /// // 外部からは GIC を経ない vCPU 作成を書けない。
    /// let vm = fandhe_container_microvm::hvf::HvVm::create().unwrap();
    /// let _ = vm.create_vcpu();
    /// ```
    pub fn create_vcpu(&self) -> Result<HvVcpu<'_>, MicrovmError> {
        self.vm.create_vcpu()
    }

    /// `index` 番目の virtio-mmio の SPI を注入する [`GicSpiLine`] を作る（#3795）。注入方式は `layout.virtio_spi_trigger`。
    ///
    /// 借用は返さない（デバイスのスレッドへ move できる）。代わりに生存フラグを共有し、VM の破棄後の注入は拒否する。
    /// INTID は GIC 作成時に照会した範囲で検証する。`index` が配置の台数以上なら `InvalidArgument`。
    pub fn spi_line(&self, layout: &Arm64Layout, index: u32) -> Result<GicSpiLine, MicrovmError> {
        self.spi_line_with_injection(layout, index, layout.virtio_spi_trigger)
    }

    /// [`Self::spi_line`] の注入方式を明示する版（#3863）。FDT の trigger と食い違えば線を作らず `InvalidArgument`。
    pub fn spi_line_with_injection(
        &self,
        layout: &Arm64Layout,
        index: u32,
        injection: IrqTrigger,
    ) -> Result<GicSpiLine, MicrovmError> {
        layout.check_virtio_injection(injection)?;
        let (base, count) = self.gic.spi_range();
        let intid = check_spi_intid(layout.virtio_spi(index)?, base, count)?;
        let sink = HvfGicSink {
            api: GicApi::get()?,
            alive: Arc::clone(&self.alive),
        };
        Ok(GicSpiLine(SpiLine::new(sink, intid, injection)))
    }

    /// シリアルの SPI を level 形で駆動する [`GicSerialLine`] を作る（#3892・MVM-5・MVM-1）。
    ///
    /// `layout.serial` が無ければ `InvalidArgument`。INTID は GIC 作成時に照会した範囲で検証する。
    /// 生存フラグを共有するので、ホスト側の `SerialConsole` の clone が VM より長生きしても、VM の破棄後の注入は
    /// `Internal` で拒否される。呼び出しは MMIO exit を処理する vCPU スレッドから UART の lock の下で行い、待ちは持たない
    /// （REPAIR-5 不要）。ロック順は dispatcher → UART → 生存フラグ（読み取り）で、`Drop` の書き込みロックは vCPU 停止後に取られる。
    /// ホストスレッドの `SerialConsole::push_input`（#3893）も UART の lock の下で呼ぶ（ロック順は同じ）。`hv_gic_set_spi` を
    /// vCPU 以外のスレッドから呼べるかは未確認（#3803）。
    pub fn serial_line(&self, layout: &Arm64Layout) -> Result<GicSerialLine, MicrovmError> {
        let spi = layout.serial_spi().ok_or_else(|| {
            MicrovmError::new(
                MicrovmErrorCode::InvalidArgument,
                "serial is not configured",
            )
        })?;
        let (base, count) = self.gic.spi_range();
        let intid = check_spi_intid(spi, base, count).map_err(|e| {
            if e.code() == MicrovmErrorCode::InvalidArgument {
                MicrovmError::new(
                    MicrovmErrorCode::InvalidArgument,
                    "serial spi intid is outside the gic spi range",
                )
            } else {
                e
            }
        })?;
        let sink = HvfGicSink {
            api: GicApi::get()?,
            alive: Arc::clone(&self.alive),
        };
        Ok(GicSerialLine(SpiLevelLine::new(sink, intid)))
    }
}

/// `hv_gic_set_spi` を呼ぶ [`SpiSink`]。VM の生存フラグの読み取りロックを呼び出しの間保持する。
#[derive(Debug, Clone)]
pub(crate) struct HvfGicSink {
    api: &'static GicApi,
    alive: Arc<RwLock<bool>>,
}

impl SpiSink for HvfGicSink {
    fn set_spi(&self, intid: u32, level: bool) -> Result<(), MicrovmError> {
        let guard = self.alive.read().map_err(|_| {
            MicrovmError::new(MicrovmErrorCode::Internal, "gic liveness lock is poisoned")
        })?;
        if !*guard {
            return Err(MicrovmError::new(
                MicrovmErrorCode::Internal,
                "spi line outlived its vm; refusing to inject",
            ));
        }
        self.api.set_spi(intid, level)
    }
}

/// virtio-mmio 1 台分の SPI を `hv_gic_set_spi` で注入する [`InterruptLine`]（#3795・#3863）。
/// 契約はモジュール doc の「SPI の注入」。
#[derive(Debug, Clone)]
pub struct GicSpiLine(SpiLine<HvfGicSink>);

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GicSpiLine>();
};

impl GicSpiLine {
    /// 注入する INTID（検証済み）。
    pub fn intid(&self) -> u32 {
        self.0.intid()
    }
}

impl InterruptLine for GicSpiLine {
    /// `set_spi(intid, true)` を 1 回呼ぶ（edge は立ち上がり、level は線を上げる）。
    fn trigger(&self) -> Result<(), MicrovmError> {
        self.0.trigger()
    }

    fn injection(&self) -> IrqTrigger {
        self.0.injection()
    }

    fn resample(&self, pending: bool) -> Result<LineResample, MicrovmError> {
        self.0.resample(pending)
    }
}

/// シリアル（UART）の SPI を `hv_gic_set_spi` で level 駆動する [`LevelInterruptLine`]（#3892・MVM-5・MVM-1）。
/// 呼び出し元は `crate::uart` の MMIO ラッパー（`SerialConsole::mmio_device_with_irq`）。
#[derive(Debug, Clone)]
pub struct GicSerialLine(SpiLevelLine<HvfGicSink>);

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GicSerialLine>();
};

impl GicSerialLine {
    /// 駆動する INTID（検証済み）。
    pub fn intid(&self) -> u32 {
        self.0.intid()
    }
}

impl LevelInterruptLine for GicSerialLine {
    fn set_level(&self, level: IrqLevel) -> Result<(), MicrovmError> {
        self.0.set_level(level)
    }
}
