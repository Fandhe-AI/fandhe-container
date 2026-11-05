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
//!   引数が整数と bool だけで失敗は戻り値で返るため [`GicSpiLine`] は `Send + Sync` とする。実機では非 vCPU スレッドから
//!   呼べて、`wfi` で待つゲストへ 1 ms 以内に届いた（macOS 27.2・#3803）。`hvf_device_spi_reaches_guest` が照合する。
//! - 寿命: `hv_gic_set_spi` は VM を取らないため、古い line が後から作った別の VM へ注入しうる。
//!   [`VmWithGic`] が持つ生存フラグ（`RwLock<bool>`）を各 line が共有し、`Drop` で書き込みロックを取って false にする。
//!   `trigger` と `resample` は読み取りロックを `set_spi` の間保持するので、破棄と注入は競合せず、破棄後は `Internal` で拒否する。
//! - WFI の起床（#3887・#3948）: `set_spi(intid, true)` が成功したら `WfiWakeSet::notify_spi` で WFI の待ちを起こす
//!   （edge の trigger・level の上げ直し・シリアル入力の `High` を覆う。deassert では通知しない）。virtio の線は
//!   `InterruptACK` を処理した vCPU を学習した宛先の 1 台だけを起こし、未学習の線とシリアルは全台を起こす（#3948。
//!   学習の方式と残余は `crate::hvf_wake`）。ロック順は UART → 生存フラグ（読み取り。通知の前に外す）→ waker のスロットの
//!   mutex で、スロットの mutex は 1 個ずつ取り持つ間は他の lock を取らない。宛先のヒントは atomic で lock ではない。
//!   GIC つきの実機では WFI は exit しないため、この通知で起きる待ちは無く、ゲストを起こすのは `set_spi` 自身である
//!   （macOS 27.2・#3803・#3994。通知の要否の判断は #3995）。
//! - 宛先の決定（#3960・MVM-5）: `hv_gic_get_distributor_reg` は **ある**（macOS 15.0 で導入。`hv_gic_distributor_reg_t` の列挙値は
//!   ARM GICv3 の distributor のレジスタオフセットに等しく、`HV_GIC_DISTRIBUTOR_REG_GICD_IROUTER32` が存在する。一次資料:
//!   <https://developer.apple.com/documentation/hypervisor/hv_gic_get_distributor_reg(_:_:)>・
//!   <https://developer.apple.com/documentation/hypervisor/hv_gic_distributor_reg_t>・
//!   <https://developer.apple.com/documentation/hypervisor/hv_gic_distributor_reg_gicd_irouter32>。確認日 2026-11-05。
//!   SDK ヘッダとの照合は #3803）。assert の成功後に `GICD_IROUTER<intid>` を読み、IRM = 0 で affinity が割り当て済みの vCPU
//!   に当たればその 1 台を起こす（シリアルの線も同じ。決定規則は `crate::hvf_wake::spi_wake_target`）。読めない・IRM = 1・書式違反
//!   のときは学習したヒントへ、それも無ければ全台へ縮退する。縮退は理由別に数え（[`VmWithGic::spi_routing_stats`]）、理由ごとの初回だけ
//!   ログに出す。`GICD_CTLR.ARE` = 0 か読めないときは IROUTER を使わない（#3974・REPAIR-4。詳細は `crate::hvf_wake`）。観測用に [`VmWithGic::spi_routing`] を公開する。
//!   distributor 版の getter に owning thread の注記は無い（redistributor 版にはある）が、非 vCPU スレッドからの読み出しは未観測
//!   （#3803）。
//! - 残余: MSI の範囲は GIC の config に MSI を設定しないため対象外。
//!
//! # 範囲外（REPAIR-3）
//! MSI・
//! `hv_gic_get_redistributor_base` の照合・`HvGicIntid` の virtual timer 以外の照合・SDK ヘッダとの値の照合（#3803）・
//! vCPU の個別 drop（本 crate では持たない。破棄は teardown の一部としてだけ起き、`mark_teardown` の後の再作成を拒否する。#3798）。`unsafe` は持たない。
//!
//! # 所有（#3797）
//! [`VmWithGic`] は内部の VM を `Arc<HvVm>` で持つ。ゲスト RAM の対応付け（`HvVm::map_shared`）が VM への参照を保持し、
//! 「unmap → `hv_vm_destroy`」の順を参照数で保証するため。`HvfGic::create` が `HvVm` を値で消費する点は変わらない。

use std::sync::{Arc, RwLock};

use crate::hvf_smp::VmShutdown;
use crate::hvf_wake::{
    GicdRegisterRead, SpiRouteHint, SpiRouteStatsSnapshot, SpiRouting, WfiWakeSet, WfiWaker,
    spi_route_fallback_log_line,
};

use crate::arm64_layout::{Arm64Layout, GicGeometry, check_spi_intid, check_virtual_timer_intid};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_abi::{GicDistributorReg, HvGicIntid};
use crate::hvf_lifecycle::TeardownMark;
use crate::hvf_loop::log_line;
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
            wake: WfiWakeSet::new(layout.vcpus)?,
            routing: SpiRouting::default(),
            shutdown: Arc::new(VmShutdown::new()),
            teardown: TeardownMark::new(),
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
    /// vCPU ごとの WFI の待ちを起こす通知口の束。SPI の sink と vCPU スレッドが共有する（#3887・#3948）。
    wake: WfiWakeSet,
    /// SPI ルーティングの縮退の理由別件数と ARE のラッチ。SPI の sink と共有する（#3974）。
    routing: SpiRouting,
    /// VM 全体の終了通知（SYSTEM_OFF・失敗・BSP の終了で全 vCPU を止める。MVM-5・MVM-1・REPAIR-5）。
    shutdown: Arc<VmShutdown>,
    /// teardown の開始印（TASK-192.16・#3798）。立った後の vCPU 作成を拒否する。
    teardown: TeardownMark,
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

    /// vCPU `index` 専用の WFI の待ち手（#3887・#3948）。`hvf::vcpu` が `TimerHandler` へ結ぶ。範囲外は `InvalidArgument`。
    pub fn wfi_waker_for_vcpu(&self, index: u32) -> Result<WfiWaker, MicrovmError> {
        self.wake.handle(index)
    }

    /// 全 vCPU の通知口の束の clone。停止要求の kick と VM の終了通知が全台を起こすのに使う（#3948）。
    pub fn wake_set(&self) -> WfiWakeSet {
        self.wake.clone()
    }

    /// SPI `intid` の `GICD_IROUTER<intid>` の生値を読む（実機の観測用。#3960・MVM-5）。
    ///
    /// `&self` で VM の生存を保証する。`intid` が SPI の範囲（32..=1019）外なら `InvalidArgument`、`hv_gic_get_distributor_reg`
    /// が使えなければ `Unimplemented`。宛先の決定は `crate::hvf_wake::spi_wake_target`（この値を `decode_irouter` で復号する）。
    pub fn spi_routing(&self, intid: u32) -> Result<u64, MicrovmError> {
        GicApi::get()?.distributor_reg(GicDistributorReg::irouter(intid)?)
    }

    /// SPI の宛先決定の縮退の理由別件数（実機の観測用。#3974・MVM-5・REPAIR-4）。
    pub fn spi_routing_stats(&self) -> SpiRouteStatsSnapshot {
        self.routing.snapshot()
    }

    /// `GICD_CTLR` の生値を読む（実機の観測用。ARE の確認は #3803。#3974）。
    pub fn distributor_ctlr(&self) -> Result<u64, MicrovmError> {
        GicApi::get()?.distributor_reg(GicDistributorReg::ctlr())
    }

    /// VM 全体の終了通知（全 vCPU スレッドが共有する）。
    pub fn shutdown(&self) -> Arc<VmShutdown> {
        Arc::clone(&self.shutdown)
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
        self.teardown.check_can_create_vcpu()?;
        self.vm.create_vcpu()
    }

    /// teardown の開始を記録する（vCPU スレッドが、自分の vCPU を `hv_vcpu_destroy` する直前に呼ぶ。TASK-192.16・#3798）。
    ///
    /// Apple の `hv_gic_create` の記述（vCPU が走り出すとトポロジーは確定する／vCPU を破棄するのは VM を teardown するときだけ）に
    /// 従い、以後の [`Self::create_vcpu`] は `FailedPrecondition` で拒否する。本 crate は pause・vCPU の再作成を持たないため、
    /// vCPU の破棄は常に teardown の一部である。
    pub(crate) fn mark_teardown(&self) {
        self.teardown.begin();
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
        // 宛先は `InterruptACK` を処理した vCPU から学習する（#3948）。学習するまでは全台を起こす。
        let route = SpiRouteHint::unknown();
        let sink = HvfGicSink {
            api: GicApi::get()?,
            alive: Arc::clone(&self.alive),
            wake: self.wake.clone(),
            routing: self.routing.clone(),
            route: route.clone(),
        };
        Ok(GicSpiLine(SpiLine::new(sink, intid, injection), route))
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
            wake: self.wake.clone(),
            routing: self.routing.clone(),
            // UART の ACK は IIR の読み出しで経路が違うため学習せず、常に全台を起こす（#3948 の残余）。
            route: SpiRouteHint::unknown(),
        };
        Ok(GicSerialLine(SpiLevelLine::new(sink, intid)))
    }
}

/// `hv_gic_set_spi` を呼ぶ [`SpiSink`]。VM の生存フラグの読み取りロックを呼び出しの間保持する。
#[derive(Debug, Clone)]
pub(crate) struct HvfGicSink {
    api: &'static GicApi,
    alive: Arc<RwLock<bool>>,
    wake: WfiWakeSet,
    /// VM 共有の縮退の件数・ARE のラッチ（#3974）。
    routing: SpiRouting,
    /// この線の宛先 vCPU のヒント（#3948）。未学習なら全台を起こす。
    route: SpiRouteHint,
}

impl GicdRegisterRead for HvfGicSink {
    fn read(&self, reg: GicDistributorReg) -> Result<u64, MicrovmError> {
        self.api.distributor_reg(reg)
    }
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
        let r = self.api.set_spi(intid, level);
        // assert が成功したら、読み取りロックの中で宛先を決める（VM が生きている間だけ framework を呼ぶ。同期呼び出しで lock ではない）。
        // ARE = 0・読めない・書式違反などはヒント（無ければ全台）へ縮退し、理由別に数える（#3960・#3974）。
        let decision = if r.is_ok() && level {
            Some(
                self.routing
                    .resolve(self, intid, self.route.get(), self.wake.vcpus()),
            )
        } else {
            None
        };
        // 読み取りロックを外してから、初回の縮退をログに出し（非ブロッキング）、assert が成功したときだけ WFI の待ちを起こす
        // （waker の mutex を持つ間は他の lock を取らない）。
        drop(guard);
        if let Some(d) = decision {
            if d.first
                && let Some(reason) = d.fallback
            {
                log_line(format_args!(
                    "{}",
                    spi_route_fallback_log_line(reason, d.code)
                ));
            }
            self.wake.notify_target(d.target);
        }
        r
    }
}

/// virtio-mmio 1 台分の SPI を `hv_gic_set_spi` で注入する [`InterruptLine`]（#3795・#3863）。
/// 契約はモジュール doc の「SPI の注入」。
#[derive(Debug, Clone)]
pub struct GicSpiLine(SpiLine<HvfGicSink>, SpiRouteHint);

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GicSpiLine>();
};

impl GicSpiLine {
    /// 注入する INTID（検証済み）。
    pub fn intid(&self) -> u32 {
        self.0.intid()
    }

    /// この線の宛先 vCPU のヒント（`hvf::mmio` の `InterruptACK` の学習が書く。#3948）。
    pub(crate) fn route_hint(&self) -> SpiRouteHint {
        self.1.clone()
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
