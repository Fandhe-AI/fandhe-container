//! WFI / WFE と vtimer の exit 処理（TASK-192.14・#3796・MVM-5・MVM-1・REPAIR-5・REPAIR-3）。
//!
//! 役割: `hvf::vcpu` の実行ループが分類した WF* と vtimer の発火（`VTIMER_ACTIVATED`）を処理する入口。
//! シグネチャは `hvf::vcpu` との契約で、本ファイルだけを差し替えて実装している。待ち時間の計算は
//! `hv_*` を呼ばない純関数（`hvf_abi::wfi_wait_plan`）に置き、ここは vCPU のレジスタ読み書きと sleep だけを持つ。
//!
//! # 契約
//! - WFI: ゲストの次のタイマー期限（`CNTV_CVAL_EL0`・vtimer offset・ホストのカウンタから計算）まで
//!   ホスト側で待つ。1 回の待ちは `WFI_WAIT_MAX`（10 ms）で頭打ちで、**これが停止要求の応答時間を決める唯一の値**
//!   （本ハンドラは停止フラグにも kick にも触れられず、kick はホストの sleep を起こさない。REPAIR-5）。
//! - WFE / WFIT / WFET: 待たずに戻る。WFIT は期限レジスタ（Rt）を読まず CNTV の状態だけで待つと、
//!   CNTV 無効かつ期限超過でも sleep して契約を破るため、期限の取得に対応するまで即時再開する
//!   （WFIT の spurious な早期再開はアーキテクチャ上許される）。
//! - PC: WF* の trap の優先戻り先は命令自身のため、常に `esr::instruction_length` の分だけ進める
//!   （進めないと、割り込みを mask したまま `wfi` する Linux の idle が WFI の trap を繰り返して起きられない）。
//! - vtimer: `hv_vcpu_run` が `VTIMER_ACTIVATED` で戻ると vtimer は自動で mask され、mask を外すまで再 exit しない。
//!   ゲストが割り込みを処理して CVAL を進める、またはタイマーを止める、または mask すると線が下がる
//!   （`CNTV_CTL_EL0` の ISTATUS=0・IMASK=1・ENABLE=0）。その検出時に限り `set_vtimer_mask(false)` で外す
//!   （QEMU の hvf の `hvf_sync_vtimer` と同じ考え方。確定は #3803）。
//! - GIC あり（#3792）の構成で vtimer の PPI（INTID 27）を pending にするのは framework 側という仮説に立つ。
//!   根拠は `GicApi` に PPI を操作する API が無いことと `hv_gic_get_intid(EL1_VIRTUAL_TIMER)` が存在すること。
//!
//! # 未実装・簡易実装（REPAIR-3）
//! (a) 待っている最中の SPI の注入（`GicSpiLine::trigger`）では起きず、最大で `WFI_WAIT_MAX` 遅れる。
//! (b) 停止要求でも直接は起きず、上限で戻ってから実行ループの先頭で `Requested` になる。
//! (c) mask の解除は `hv_vcpu_run` の再入直前（`sync_before_run`）にも確認する。ただし線が立っている間は外せず、
//!     ゲストが CVAL を進める等で線が下がった後の次の再入（exit か実行期限）で外れる。
//! (d) #3803 で確定させる観測事項: GIC あり構成で PPI が自動で pending になるか、`VTIMER_ACTIVATED` が起きるか、
//!     WFI の exit 時点の PC、mach の 2 関数の SDK ヘッダとの照合。

use crate::error::{MicrovmError, MicrovmErrorCode};
use crate::esr::{WfxKind, instruction_length};
use crate::hvf_abi::{
    HvReg, HvSysReg, HvVcpuExitException, WFI_WAIT_MAX, guest_virtual_count, vtimer_level,
    wfi_wait_plan,
};
use crate::hvf_loop::ExitAction;
use crate::sys::HvVcpu;
use crate::sys::{host_absolute_time, host_timebase};

/// 観測用の計数（REPAIR-4）。加算は `saturating_add`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimerStats {
    /// WFI で実際に sleep した回数。
    pub wfi_waits: u64,
    /// WFI で待たずに戻った回数。
    pub wfi_immediate: u64,
    /// `VTIMER_ACTIVATED` の回数。
    pub vtimer_activations: u64,
    /// vtimer の mask を外した回数。
    pub vtimer_unmasks: u64,
}

/// WFI / vtimer ハンドラの状態。vCPU スレッドへ move される（`Send`）。
#[derive(Debug, Default)]
pub struct TimerHandler {
    vtimer_masked: bool,
    stats: TimerStats,
}

const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<TimerHandler>();
};

impl TimerHandler {
    /// 空のハンドラを作る（失敗しない）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 観測用の計数。
    pub fn stats(&self) -> TimerStats {
        self.stats
    }

    /// `VTIMER_ACTIVATED` の後で mask を外していない状態か。
    pub fn vtimer_masked(&self) -> bool {
        self.vtimer_masked
    }
}

/// mask 中で、かつ割り込み線が下がっているとき mask を外すべきか（`hv_*` を呼ばない純関数）。
fn should_unmask(masked: bool, ctl: u64) -> bool {
    masked && !vtimer_level(ctl)
}

/// `hv_vcpu_run` へ入る直前の同期口。`hvf::vcpu` の `HvfExec::run` が再入のたびに呼ぶ。
///
/// WF* を出さずに計算を続けるゲストでも mask が残らないようにする（実行期限・kick による復帰後の再入を含む。MVM-5）。
/// mask 中でなければ `hv_*` を呼ばない。
pub fn sync_before_run(
    vcpu: &mut HvVcpu<'_>,
    handler: &mut TimerHandler,
) -> Result<(), MicrovmError> {
    sync_vtimer_mask(vcpu, handler)
}

/// mask 中なら `CNTV_CTL_EL0` を読み、割り込み線が下がっていれば mask を外す。
fn sync_vtimer_mask(vcpu: &mut HvVcpu<'_>, handler: &mut TimerHandler) -> Result<(), MicrovmError> {
    if !handler.vtimer_masked {
        return Ok(());
    }
    let ctl = vcpu.get_sys_reg(HvSysReg::CNTV_CTL_EL0)?;
    if should_unmask(handler.vtimer_masked, ctl) {
        vcpu.set_vtimer_mask(false)?;
        handler.vtimer_masked = false;
        handler.stats.vtimer_unmasks = handler.stats.vtimer_unmasks.saturating_add(1);
    }
    Ok(())
}

/// WFI / WFE 系を処理する。WFI は期限つきで待ち（WFIT は期限未対応のため即時再開）、PC を命令長だけ進めて `Continue` を返す。
pub fn handle_wfx(
    vcpu: &mut HvVcpu<'_>,
    handler: &mut TimerHandler,
    kind: WfxKind,
    exception: &HvVcpuExitException,
) -> Result<ExitAction, MicrovmError> {
    sync_vtimer_mask(vcpu, handler)?;
    if matches!(kind, WfxKind::Wfi) {
        let ctl = vcpu.get_sys_reg(HvSysReg::CNTV_CTL_EL0)?;
        let cval = vcpu.get_sys_reg(HvSysReg::CNTV_CVAL_EL0)?;
        let offset = vcpu.vtimer_offset()?;
        let timebase = host_timebase()?;
        let now = guest_virtual_count(host_absolute_time(), offset);
        let plan = wfi_wait_plan(ctl, cval, now, timebase, WFI_WAIT_MAX)?;
        if plan.wait.is_zero() {
            handler.stats.wfi_immediate = handler.stats.wfi_immediate.saturating_add(1);
        } else {
            handler.stats.wfi_waits = handler.stats.wfi_waits.saturating_add(1);
            std::thread::sleep(plan.wait);
        }
    }
    let pc = vcpu.get_reg(HvReg::PC)?;
    let next = pc
        .checked_add(instruction_length(exception.syndrome).bytes())
        .ok_or_else(|| MicrovmError::new(MicrovmErrorCode::Internal, "pc overflow at wfx exit"))?;
    vcpu.set_reg(HvReg::PC, next)?;
    Ok(ExitAction::Continue)
}

/// vtimer の発火（`VTIMER_ACTIVATED`）を処理する。exception ではないため PC は進めない。
pub fn handle_vtimer(
    vcpu: &mut HvVcpu<'_>,
    handler: &mut TimerHandler,
) -> Result<ExitAction, MicrovmError> {
    handler.vtimer_masked = true;
    handler.stats.vtimer_activations = handler.stats.vtimer_activations.saturating_add(1);
    sync_vtimer_mask(vcpu, handler)?;
    Ok(ExitAction::Continue)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hvf_abi::{CNTV_CTL_ENABLE, CNTV_CTL_ISTATUS};

    /// MVM-5・#3796: 線が立っている間は外さず、CVAL 更新で ISTATUS が落ちたら外す（WF* を経由しない再入前の同期）。
    #[test]
    fn mvm5_3796_should_unmask_follows_line_level() {
        let asserted = CNTV_CTL_ENABLE | CNTV_CTL_ISTATUS;
        assert!(!should_unmask(true, asserted));
        assert!(should_unmask(true, CNTV_CTL_ENABLE));
        assert!(should_unmask(true, 0));
        assert!(!should_unmask(false, CNTV_CTL_ENABLE));
    }
}
