//! 順序固定の制限ステージ列（CORE-1・TASK-27.4.2・#832・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! `crate::exec` の最小実行フロー第 4 段の「枠」。`process.rs::run_child` が pivot_root の後・
//! `exec_entrypoint` の前に [`StagePipeline::run_then`] を呼び、次の順序で各段のフックを実行する。
//!
//! ```text
//! cgroup 参加 -> capability 削減 -> PR_SET_NO_NEW_PRIVS -> Landlock -> seccomp -> exec
//! ```
//!
//! 各段の実体は後続の TASK が [`StageHook`] として差し込む（cgroup 参加: TASK-32、capability 削減:
//! TASK-37、`NO_NEW_PRIVS`: #833・TASK-27.4.3、Landlock: TASK-39、seccomp: TASK-38、rootless: TASK-40）。
//! `NO_NEW_PRIVS` を Landlock / seccomp より前に固定する順序は fail-closed の前提である。
//!
//! # 契約
//!
//! - **順序は [`StageKind::ORDER`] だけが決める**: 登録順・呼び出し側の指定では変えられない。
//!   exec は [`StagePipeline::run_then`] の終端クロージャからしか呼べず、全段成功後に限り最後に走る
//! - **最初の失敗で打ち切る**: 後続段と exec は呼ばない。エラーの `stage` はパイプライン側で
//!   その段に付け替える（フックが自分の段を偽れない。ERR-1）
//! - **同じ段への二重登録は拒否する**: 既存の制限フックを no-op で上書きする経路を作らない
//! - **[`StageReport`] と `Applied` は制限適用の証跡ではない**: 「フックが `Ok` を返した」事実の
//!   記録にすぎない。`process.rs::require_restriction_evidence` の判定には使わず、フック無し・
//!   ダミーフックのどちらでも exec は `PermissionDenied` のまま拒否される（SEC-1・CORE-5）。
//!   将来の証跡は、各ビルトインのステージが返す型付きトークンで表す（REPAIR-3: 実装済みを装わない）
//! - **フックは fork 前に親で構築し、fork で子へコピーされて子で実行される**。シングルスレッドの
//!   まま実行するため `Send` は要求しない。panic は `sys::fork_single_threaded` の
//!   `catch_unwind` により `EXIT_SETUP_FAILED` で `_exit` する（fail-closed）
//! - **フックの実装者は core crate 内のモジュール**を想定する（`ExecError::new` は非公開）
//!
//! # 将来仕様（記録のみ）
//!
//! pivot 後はホストの `/sys/fs/cgroup` が見えないため、TASK-32 の cgroup 参加フックは fork 前に
//! cgroup ディレクトリの `OwnedFd` を確保し、fd 経由で `cgroup.procs` へ書く設計にする。

use std::fmt;

use super::{ExecError, IsolationStage};
use crate::traits::types::ErrorCode;

/// ステージの種別。`ORDER` の順が実行順（固定）。
///
/// `#[non_exhaustive]` にしない: 順序表とスロット添字が全要素を網羅することを、`match` の
/// 網羅性検査でコンパイル時に保証するため。段の追加はこのモジュール内の変更に限る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageKind {
    /// cgroup 参加（TASK-32）。
    CgroupJoin,
    /// capability 削減（TASK-37）。
    CapabilityDrop,
    /// `PR_SET_NO_NEW_PRIVS`（#833・TASK-27.4.3）。
    NoNewPrivs,
    /// Landlock（TASK-39）。
    Landlock,
    /// seccomp（TASK-38）。
    Seccomp,
}

impl StageKind {
    /// 実行順（唯一の定義元）。
    pub const ORDER: [StageKind; 5] = [
        StageKind::CgroupJoin,
        StageKind::CapabilityDrop,
        StageKind::NoNewPrivs,
        StageKind::Landlock,
        StageKind::Seccomp,
    ];

    fn index(self) -> usize {
        match self {
            StageKind::CgroupJoin => 0,
            StageKind::CapabilityDrop => 1,
            StageKind::NoNewPrivs => 2,
            StageKind::Landlock => 3,
            StageKind::Seccomp => 4,
        }
    }

    /// 機械可読な英語識別子。
    pub fn as_str(self) -> &'static str {
        match self {
            StageKind::CgroupJoin => "cgroup_join",
            StageKind::CapabilityDrop => "capability_drop",
            StageKind::NoNewPrivs => "no_new_privs",
            StageKind::Landlock => "landlock",
            StageKind::Seccomp => "seccomp",
        }
    }

    fn isolation_stage(self) -> IsolationStage {
        match self {
            StageKind::CgroupJoin => IsolationStage::CgroupJoin,
            StageKind::CapabilityDrop => IsolationStage::CapabilityDrop,
            StageKind::NoNewPrivs => IsolationStage::NoNewPrivs,
            StageKind::Landlock => IsolationStage::Landlock,
            StageKind::Seccomp => IsolationStage::Seccomp,
        }
    }
}

/// 1 段ぶんの制限適用フック。
///
/// 子プロセス（pivot 後）で 1 回だけ呼ばれる。状態を持てるよう `&mut self`。失敗は
/// [`ExecError`] で返す（段はパイプラインが付け替える）。`FnMut() -> Result<(), ExecError>` の
/// クロージャもそのままフックとして使える。
pub trait StageHook {
    /// 制限を適用する。
    fn apply(&mut self) -> Result<(), ExecError>;
}

impl<F: FnMut() -> Result<(), ExecError>> StageHook for F {
    fn apply(&mut self) -> Result<(), ExecError> {
        self()
    }
}

/// 段の実行結果。制限適用の証跡ではない（モジュール doc 参照）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StageStatus {
    /// フックが `Ok` を返した。
    Applied,
    /// フック未登録で何もしなかった。
    Skipped,
}

/// 段ごとの結果（`ORDER` 順）。`Applied` は証跡ではない（モジュール doc 参照）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StageReport {
    statuses: [StageStatus; 5],
}

impl StageReport {
    /// 指定した段の結果。
    pub fn status(&self, kind: StageKind) -> StageStatus {
        self.statuses
            .get(kind.index())
            .copied()
            .unwrap_or(StageStatus::Skipped)
    }

    /// `ORDER` 順に `(段, 結果)` を返す。
    pub fn iter(&self) -> impl Iterator<Item = (StageKind, StageStatus)> + '_ {
        StageKind::ORDER.iter().map(|&k| (k, self.status(k)))
    }
}

/// 順序固定のステージ列。空のままでも既定動作は「何も差し込まず exec へ進む」だけで、
/// exec の fail-closed（証跡要求）は変わらない。
pub struct StagePipeline {
    hooks: [Option<Box<dyn StageHook>>; 5],
}

impl Default for StagePipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for StagePipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("StagePipeline");
        for kind in StageKind::ORDER {
            let registered = self.hooks.get(kind.index()).is_some_and(Option::is_some);
            d.field(kind.as_str(), &registered);
        }
        d.finish()
    }
}

impl StagePipeline {
    /// 全段が未登録の列を作る。
    pub fn new() -> Self {
        Self {
            hooks: [None, None, None, None, None],
        }
    }

    /// 段にフックを登録する。同じ段への二重登録は `InvalidArgument`（`Validate` 段）で拒否する。
    pub fn with_hook(
        mut self,
        kind: StageKind,
        hook: impl StageHook + 'static,
    ) -> Result<Self, ExecError> {
        let slot = self.hooks.get_mut(kind.index()).ok_or_else(|| {
            ExecError::new(
                ErrorCode::Internal,
                IsolationStage::Validate,
                "stage slot out of range",
            )
        })?;
        if slot.is_some() {
            return Err(ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::Validate,
                format!("stage hook already registered: {}", kind.as_str()),
            ));
        }
        *slot = Some(Box::new(hook));
        Ok(self)
    }

    /// `ORDER` の順に各段のフックを実行し、全段成功したときだけ最後に `exec` を呼ぶ。
    ///
    /// 最初の `Err` で打ち切る（後続段と `exec` は呼ばない）。フックの `Err` は `stage` を
    /// その段へ付け替えて返す。`exec` へは [`StageReport`] を渡す（証跡ではない）。
    pub fn run_then<T>(
        mut self,
        exec: impl FnOnce(&StageReport) -> Result<T, ExecError>,
    ) -> Result<T, ExecError> {
        let mut statuses = [StageStatus::Skipped; 5];
        for kind in StageKind::ORDER {
            let idx = kind.index();
            let Some(Some(hook)) = self.hooks.get_mut(idx) else {
                continue;
            };
            hook.apply()
                .map_err(|e| e.at_stage(kind.isolation_stage()))?;
            if let Some(s) = statuses.get_mut(idx) {
                *s = StageStatus::Applied;
            }
        }
        exec(&StageReport { statuses })
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    thread_local! {
        static CALLS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    }

    fn rec(name: &'static str) {
        CALLS.with(|c| c.borrow_mut().push(name));
    }

    fn take() -> Vec<&'static str> {
        CALLS.with(|c| std::mem::take(&mut *c.borrow_mut()))
    }

    fn ok_hook(kind: StageKind) -> impl StageHook + 'static {
        move || {
            rec(kind.as_str());
            Ok(())
        }
    }

    fn exec_ok(_: &StageReport) -> Result<(), ExecError> {
        rec("exec");
        Ok(())
    }

    /// CORE-1・TASK-27.4.2: 順序表の機械照合。
    #[test]
    fn core1_stage_order_is_fixed() {
        assert_eq!(
            StageKind::ORDER,
            [
                StageKind::CgroupJoin,
                StageKind::CapabilityDrop,
                StageKind::NoNewPrivs,
                StageKind::Landlock,
                StageKind::Seccomp,
            ]
        );
        for (i, k) in StageKind::ORDER.iter().enumerate() {
            assert_eq!(k.index(), i);
        }
    }

    /// CORE-1・TASK-27.4.2: 逆順に登録しても固定順で呼ばれ、exec が最後。
    #[test]
    fn core1_dummy_hooks_run_in_fixed_order() {
        take();
        let mut p = StagePipeline::new();
        for kind in StageKind::ORDER.iter().rev() {
            p = p.with_hook(*kind, ok_hook(*kind)).unwrap();
        }
        let report = p
            .run_then(|r| {
                rec("exec");
                Ok(r.clone())
            })
            .unwrap();
        assert_eq!(
            take(),
            [
                "cgroup_join",
                "capability_drop",
                "no_new_privs",
                "landlock",
                "seccomp",
                "exec"
            ]
        );
        assert!(report.iter().all(|(_, s)| s == StageStatus::Applied));
    }

    /// CORE-1・TASK-27.4.2: 一部登録でも順序を保ち、未登録は Skipped。
    #[test]
    fn core1_partial_hooks_keep_order_and_report_skipped() {
        take();
        let p = StagePipeline::new()
            .with_hook(StageKind::Seccomp, ok_hook(StageKind::Seccomp))
            .unwrap()
            .with_hook(StageKind::NoNewPrivs, ok_hook(StageKind::NoNewPrivs))
            .unwrap();
        let report = p
            .run_then(|r| {
                rec("exec");
                Ok(r.clone())
            })
            .unwrap();
        assert_eq!(take(), ["no_new_privs", "seccomp", "exec"]);
        let got: Vec<_> = report.iter().map(|(_, s)| s).collect();
        assert_eq!(
            got,
            [
                StageStatus::Skipped,
                StageStatus::Skipped,
                StageStatus::Applied,
                StageStatus::Skipped,
                StageStatus::Applied
            ]
        );
    }

    /// CORE-1・TASK-27.4.2: フック無しでも exec は 1 回呼ばれ、全段 Skipped。
    #[test]
    fn core1_empty_pipeline_reaches_exec_with_all_skipped() {
        take();
        let report = StagePipeline::new()
            .run_then(|r| {
                rec("exec");
                Ok(r.clone())
            })
            .unwrap();
        assert_eq!(take(), ["exec"]);
        assert!(report.iter().all(|(_, s)| s == StageStatus::Skipped));
    }

    /// CORE-1・TASK-27.4.2: k 段目の失敗で打ち切り、段は付け替わり code は保持される。
    #[test]
    fn core1_hook_failure_stops_pipeline() {
        for (k, failing) in StageKind::ORDER.iter().enumerate() {
            take();
            let mut p = StagePipeline::new();
            for kind in StageKind::ORDER {
                if kind == *failing {
                    p = p
                        .with_hook(kind, || {
                            rec("fail");
                            Err(ExecError::new(
                                ErrorCode::PermissionDenied,
                                IsolationStage::Validate,
                                "boom",
                            ))
                        })
                        .unwrap();
                } else {
                    p = p.with_hook(kind, ok_hook(kind)).unwrap();
                }
            }
            let err = p.run_then(exec_ok).unwrap_err();
            assert_eq!(err.stage, failing.isolation_stage());
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            let calls = take();
            assert_eq!(calls.len(), k + 1, "stopped after {}", failing.as_str());
            assert_eq!(calls.last().copied(), Some("fail"));
            assert!(!calls.contains(&"exec"));
        }
    }

    /// CORE-1・TASK-27.4.2: 同じ段への二重登録は拒否される。
    #[test]
    fn core1_duplicate_hook_is_rejected() {
        let p = StagePipeline::new()
            .with_hook(StageKind::Landlock, ok_hook(StageKind::Landlock))
            .unwrap();
        let err = p
            .with_hook(StageKind::Landlock, ok_hook(StageKind::Landlock))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert_eq!(err.violation, None);
    }
}
