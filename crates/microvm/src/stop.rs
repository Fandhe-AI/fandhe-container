//! vCPU ループの終了理由 [`StopReason`]（OS 非依存・`unsafe` なし。MVM-1・MVM-5・REPAIR-5）。
//!
//! Linux の KVM バックエンド（`microvm`）と macOS の Hypervisor.framework バックエンド（`hvf_loop`・`hvf::vcpu`。
//! TASK-192.9・#3791）が同じ語彙で終了理由を報告するため、`microvm` から移した（#3791）。`microvm` は互換のため
//! `microvm::StopReason` として再公開する。variant と [`StopReason::as_str`] の固定名は移動前と同一で、変えない。

use crate::error::MicrovmErrorCode;

/// vCPU ループが終わった理由（真偽値・文字列で返さない。拡張できる）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StopReason {
    /// `stop` または drop による停止要求。
    Requested,
    /// ゲストのシャットダウン（トリプルフォールト・PSCI SYSTEM_OFF 等）。
    GuestShutdown,
    /// ユーザー空間へ出た `HLT`（KVM の in-kernel irqchip のある現構成では起きない想定。busy loop を避けるため終了として扱う）。
    GuestHalted,
    /// 実行・exit の処理・通知の完了が失敗した（fail-closed で VM を止める）。
    Failed(MicrovmErrorCode),
}

impl StopReason {
    /// 構造化ログ用の固定名。
    pub const fn as_str(self) -> &'static str {
        match self {
            StopReason::Requested => "requested",
            StopReason::GuestShutdown => "guest_shutdown",
            StopReason::GuestHalted => "guest_halted",
            StopReason::Failed(_) => "failed",
        }
    }
}

/// VM ごとの unmap 系の失敗件数（drop の経路のみ。停止・解放の集約行に出す。#4382・#4411・#4439・MVM-1・MVM-5・REPAIR-4）。
/// OS 非依存（`unsafe` なし）。munmap 用（`unmap_failures=`）と HVF の `hv_vm_unmap` 用（`vm_unmap_failures=`）を
/// 別インスタンスで持ち、混ぜない。
///
/// KVM では `VmFd` が持ち、`GuestRamMap` / `KvmRunMap` が drop で加算し、最後の停止スレッドが集約行を出す時に読む。
/// HVF では `HvVm` が持ち、ゲストへ対応付けた `HostMapping` が drop で加算し、`stop_and_release` が資源を落とした後に読む。
/// 観測専用で、停止の合否には使わない。
#[derive(Debug, Default)]
pub struct UnmapTally {
    failures: std::sync::atomic::AtomicU64,
}

impl UnmapTally {
    /// munmap の失敗を 1 件数える。製品コードの呼び出し元は Linux の `sys` と macOS aarch64 の `sys::hvf` だけ。
    #[cfg_attr(
        not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))),
        allow(dead_code)
    )]
    pub(crate) fn record_failure(&self) {
        self.failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// これまでの失敗件数。
    pub(crate) fn count(&self) -> u64 {
        self.failures.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MVM-1: 構造化ログの固定名は移動前と変わらない。
    #[test]
    fn mvm5_3791_stop_reason_names_unchanged() {
        assert_eq!(StopReason::Requested.as_str(), "requested");
        assert_eq!(StopReason::GuestShutdown.as_str(), "guest_shutdown");
        assert_eq!(StopReason::GuestHalted.as_str(), "guest_halted");
        assert_eq!(
            StopReason::Failed(MicrovmErrorCode::Internal).as_str(),
            "failed"
        );
    }

    /// MVM-5・REPAIR-4: 失敗件数は 0 から数える（#4411）。
    #[test]
    fn mvm5_4411_unmap_tally_counts() {
        let t = UnmapTally::default();
        assert_eq!(t.count(), 0);
        t.record_failure();
        t.record_failure();
        assert_eq!(t.count(), 2);
    }
}
