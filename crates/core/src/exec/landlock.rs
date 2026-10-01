//! Landlock 適用ステージの入口とエラー写像（CORE-5・TASK-39.4・#184・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! ステージ列（`exec/stages.rs`）第 4 段「Landlock」の実体への入口。`crate::landlock`
//! （TASK-39.1〜39.3）が持つ ABI 検出・ルール生成・適用を、起動フローの `ExecError`
//! （`stage = Landlock`）へ写像して繋ぐ。呼び出し元は `StagePipeline::with_landlock` が登録する
//! クロージャで、`run_then` が fork 後の単一スレッドの子（pivot 後・capability 削減と
//! `NO_NEW_PRIVS` の後・seccomp の前）で呼ぶ。実行順は `StageKind::ORDER` が固定する。
//!
//! seccomp・capability 削減と違い Landlock はコンテナごとの入力（`OciConfig` 由来の ruleset）を
//! 要するため、引数なしの組み込み段にはせず、ruleset を持つフックとして Landlock 枠へ差し込む。
//!
//! # 契約
//!
//! - ruleset は fork 前に親で [`landlock_ruleset_from_config`] で作る（検出済みの
//!   `LandlockSupport` を要する型経路のため、ABI 未確認の ruleset は作れない。fail-closed）
//! - 適用は不可逆で呼び出しスレッドにしか効かない。`NO_NEW_PRIVS`・単一スレッドの検証は
//!   `crate::landlock::apply_landlock_ruleset` が ruleset 作成前に行う
//! - 写像は `code` を保ち、`stage` を `Landlock` にし、message に機械可読な理由コードを含める。
//!   ホスト側パスは含めない。`violation` は `None`（ABI 不足・適用失敗は分離違反の試行ではない。
//!   監査ログは TASK-41・SEC-4）
//!
//! # 未実装範囲（REPAIR-3）
//!
//! - 制限適用の証跡型の確定と `require_restriction_evidence` への配線（exec の許可）は未実装の
//!   後続作業で、適用結果 [`LandlockApplyReport`] は証跡ではなく捨てる
//! - Landlock の組み込み固定段への昇格（`with_hook(Landlock)` の拒否）は後続作業
//! - 本番 launcher（`oci_runtime`）からの本関数の呼び出しは後続

use super::{ExecError, IsolationStage};
use crate::landlock::{
    LandlockApplyError, LandlockApplyReport, LandlockError, LandlockRuleError, LandlockRuleset,
    detect_landlock_abi, path_rules_from_config,
};
use crate::oci_runtime::OciConfig;

/// 生成済みの ruleset を呼び出しスレッドへ適用する（CORE-5・TASK-39.4）。
///
/// `StagePipeline::with_landlock` のクロージャから、fork 後の子でのみ呼ぶ（不可逆）。
// テストでは `stages.rs` が偽物（`testing`）へ差し替えるため、本物は未使用になる。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn apply_landlock_stage(
    ruleset: &LandlockRuleset,
) -> Result<LandlockApplyReport, ExecError> {
    crate::landlock::apply_landlock_ruleset(ruleset).map_err(from_landlock_apply)
}

/// `OciConfig` から Landlock ruleset を作る（ABI 検出 → ルール生成。CORE-5・TASK-39.4）。
///
/// fork 前に親で呼び、得た ruleset を `StagePipeline::with_landlock` へ渡す。
/// ABI 不足・生成失敗は `stage = Landlock` の `ExecError` になる（起動拒否。fail-closed）。
///
/// # 将来仕様（記録のみ）
///
/// 本番 launcher（`oci_runtime`）からの呼び出しは後続作業（REPAIR-3）。
// 本番 launcher からの呼び出しが未配線のため、結合試験・テスト以外では未使用になりうる。
#[allow(dead_code)]
pub(crate) fn landlock_ruleset_from_config(
    config: &OciConfig,
) -> Result<LandlockRuleset, ExecError> {
    let support = detect_landlock_abi().map_err(from_landlock_unavailable)?;
    path_rules_from_config(&support, config).map_err(from_landlock_rule)
}

fn from_landlock_apply(e: LandlockApplyError) -> ExecError {
    ExecError::new(
        e.code,
        IsolationStage::Landlock,
        format!("{}: {}", e.kind.as_str(), e.message),
    )
}

fn from_landlock_unavailable(e: LandlockError) -> ExecError {
    ExecError::new(
        e.code,
        IsolationStage::Landlock,
        format!("{}: {}", e.reason.as_str(), e.message),
    )
}

fn from_landlock_rule(e: LandlockRuleError) -> ExecError {
    ExecError::new(
        e.code,
        IsolationStage::Landlock,
        format!("{}: {}", e.kind.as_str(), e.message),
    )
}

/// `stages.rs` が `cfg(test)` で差し替える偽物（`seccomp::testing` と同型）。
#[cfg(test)]
pub(super) mod testing {
    use std::cell::Cell;

    use super::{ExecError, LandlockApplyReport, LandlockRuleset};

    thread_local! {
        static LANDLOCK_ERR: Cell<Option<ExecError>> = const { Cell::new(None) };
    }

    /// 次の 1 回だけ、`apply_landlock_stage` の偽物を失敗させる（使うと既定へ戻る）。
    pub(in crate::exec) fn fake_landlock_err(e: ExecError) {
        LANDLOCK_ERR.with(|c| c.set(Some(e)));
    }

    /// `stages.rs` の `with_landlock` が `cfg(test)` で呼ぶ偽物。
    pub(in crate::exec) fn apply_landlock_stage(
        ruleset: &LandlockRuleset,
    ) -> Result<LandlockApplyReport, ExecError> {
        crate::exec::no_new_privs::testing::rec("landlock");
        match LANDLOCK_ERR.with(Cell::take) {
            Some(e) => Err(e),
            None => Ok(LandlockApplyReport {
                rules_added: ruleset.rules().len(),
                file_rules: 0,
                skipped_empty: 0,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::landlock::{LandlockApplyErrorKind, LandlockRuleErrorKind, LandlockUnavailable};
    use crate::traits::types::ErrorCode;

    /// CORE-5・TASK-39.4: 適用失敗は code を保ち stage を Landlock にする。
    #[test]
    fn core5_apply_error_maps_to_landlock_stage() {
        let e = from_landlock_apply(LandlockApplyError {
            code: ErrorCode::FailedPrecondition,
            kind: LandlockApplyErrorKind::NoNewPrivsNotSet,
            message: "no_new_privs is not set".to_string(),
        });
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert!(e.violation.is_none());
        assert!(e.message.contains("no_new_privs_not_set"), "{}", e.message);
    }

    /// CORE-5・TASK-39.4: ABI 不足は FailedPrecondition・理由コード付き。
    #[test]
    fn core5_abi_too_old_maps_to_failed_precondition() {
        let err = LandlockError {
            code: ErrorCode::FailedPrecondition,
            reason: LandlockUnavailable::AbiTooOld {
                detected: 5,
                required: 6,
            },
            message: "too old".to_string(),
        };
        let e = from_landlock_unavailable(err);
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert!(e.message.contains("landlock_abi_too_old"), "{}", e.message);
    }

    /// CORE-5・TASK-39.4: ルール生成失敗は InvalidArgument のまま Landlock 段へ。
    #[test]
    fn core5_rule_error_maps_to_invalid_argument() {
        let err = LandlockRuleError {
            code: ErrorCode::InvalidArgument,
            kind: LandlockRuleErrorKind::TooManyRules { count: 9, max: 8 },
            message: "too many".to_string(),
        };
        let e = from_landlock_rule(err);
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert!(e.message.starts_with("too_many_rules: "), "{}", e.message);
    }
}
