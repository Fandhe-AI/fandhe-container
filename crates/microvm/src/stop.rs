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
}
