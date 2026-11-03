//! macOS の GICv3 の作成順序の強制と、配置・timer の照合（TASK-192.12・#3792・MVM-5・MVM-1）。
//!
//! 役割: Hypervisor.framework の `hv_gic_create` は「VM 作成後・vCPU 作成前・VM につき 1 回」しか呼べない。
//! この順序を型で強制する。流れは `HvVm` → [`VmWithGic`]（GIC 作成済み）→ `HvVcpu` で、vCPU は
//! [`VmWithGic::create_vcpu`] からだけ作れる（`HvVm::create_vcpu`・`GicApi::create` は crate 外へ公開しない）。
//! 後続の VM 構成体（#3797）・virtio の SPI 通知（#3795）が [`VmWithGic`] / [`HvfGic`] を使う。
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
//! # 範囲外（REPAIR-3）
//! `MPIDR_EL1` の実際の設定と SMP（#3797）・virtio の SPI 範囲と通知方式の照合（#3795）・MSI・
//! `hv_gic_get_redistributor_base` の照合・`HvGicIntid` の virtual timer 以外の照合・SDK ヘッダとの値の照合（#3803）・
//! vCPU の個別 drop と「破棄は VM 破棄時のみ」の整合（#3797・#3791）。`unsafe` は持たない。

use crate::arm64_layout::{Arm64Layout, GicGeometry, check_virtual_timer_intid};
use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::hvf_abi::HvGicIntid;
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
}

impl HvfGic {
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
        Ok(HvfGic {
            geometry,
            virtual_timer_intid,
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
        Ok(VmWithGic { gic, vm })
    }
}

/// GIC 作成済みの VM。vCPU はここからだけ作れる。drop は `HvVm` の drop（GIC は VM と一緒に消える）。
#[derive(Debug)]
pub struct VmWithGic {
    gic: HvfGic,
    vm: HvVm,
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
}
