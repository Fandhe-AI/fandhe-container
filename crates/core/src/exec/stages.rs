//! 順序固定の制限ステージ列（CORE-1・TASK-27.4.2・#832・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! `crate::exec` の最小実行フロー第 4 段の「枠」。`process.rs::run_child` が pivot_root の後・
//! `exec_entrypoint` の前に `StagePipeline::run_then` を呼び、次の順序で各段のフックを実行する。
//!
//! ```text
//! cgroup 参加 -> capability 削減 -> PR_SET_NO_NEW_PRIVS -> Landlock -> seccomp -> exec
//! ```
//!
//! 各段の実体は後続の TASK が [`StageHook`] として差し込む（cgroup 参加: TASK-32、capability 削減:
//! TASK-37、Landlock: TASK-39、seccomp: TASK-38、rootless: TASK-40）。`NO_NEW_PRIVS` だけは
//! 組み込みの固定ステージ（`exec/no_new_privs.rs`。#833・TASK-27.4.3）で、フックを登録しなくても
//! 必ず実行され、[`StagePipeline::with_hook`] による差し替えは拒否する。
//! `NO_NEW_PRIVS` を Landlock / seccomp より前に固定する順序は fail-closed の前提である。
//!
//! # 契約
//!
//! - **順序は [`StageKind::ORDER`] だけが決める**: 登録順・呼び出し側の指定では変えられない。
//!   exec は `StagePipeline::run_then` の終端クロージャからしか呼べず、全段成功後に限り最後に走る
//! - **最初の失敗で打ち切る**: 後続段と exec は呼ばない。エラーの `stage` はパイプライン側で
//!   その段に付け替える（フックが自分の段を偽れない。ERR-1）
//! - **同じ段への二重登録は拒否する**: 既存の制限フックを no-op で上書きする経路を作らない
//! - **組み込みの固定ステージは差し替えられない**: [`StageKind::is_builtin`] の段
//!   （`NoNewPrivs`）は `with_hook` で `InvalidArgument` になり、`run_then` はフック配列を読まず
//!   組み込み処理へ直接振り分ける
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

use super::{ExecError, IsolationStage, no_new_privs};
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
    /// `PR_SET_NO_NEW_PRIVS`（#833・TASK-27.4.3）。組み込みの固定ステージ（差し替え不可）。
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

    /// 組み込みの固定ステージか（`with_hook` で差し替えを拒否する唯一の判定元）。
    pub fn is_builtin(self) -> bool {
        match self {
            StageKind::NoNewPrivs => true,
            StageKind::CgroupJoin
            | StageKind::CapabilityDrop
            | StageKind::Landlock
            | StageKind::Seccomp => false,
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

/// 順序固定のステージ列。空のままでも組み込みの `NO_NEW_PRIVS` だけを適用して exec へ進み、
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
            if kind.is_builtin() {
                d.field(kind.as_str(), &"builtin");
                continue;
            }
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

    /// 段にフックを登録する。同じ段への二重登録と、組み込みの固定ステージ
    /// （[`StageKind::is_builtin`]）への登録は `InvalidArgument`（`Validate` 段）で拒否する。
    pub fn with_hook(
        mut self,
        kind: StageKind,
        hook: impl StageHook + 'static,
    ) -> Result<Self, ExecError> {
        if kind.is_builtin() {
            return Err(ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::Validate,
                format!(
                    "stage is built-in and cannot be replaced: {}",
                    kind.as_str()
                ),
            ));
        }
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
    ///
    /// # 呼び出し契約
    ///
    /// 可視性は `pub(crate)` に限る（破壊的変更: 従来の `pub` から縮小。外部 crate からは呼べない。
    /// 呼び出し元は `process.rs::run_child`（fork 後の子）だけで、親から誤用できない API 境界にする）。
    /// 新たな呼び出し元を crate 内に増やす場合も fork 後の子でのみ呼ぶこと。組み込みの `NoNewPrivs` 段（TASK-27.4.3）が
    /// 呼び出しスレッドへ `PR_SET_NO_NEW_PRIVS` を立て、これは不可逆で解除できない。
    /// 親プロセス（supervisor 等）から呼ぶと、そのスレッドが恒久的に強化される
    /// （setuid 実行などが以後効かなくなる）。
    ///
    /// # 破壊的変更と移行方法（#833・TASK-27.4.3）
    ///
    /// - 変更内容: `pub fn run_then` から `pub(crate) fn run_then` へ縮小した。crate 外から
    ///   `StagePipeline::run_then` を直接呼ぶことはできなくなった。
    /// - 理由: 組み込みの `NO_NEW_PRIVS` 段が不可逆のため、親プロセスからの誤呼び出しを型で防ぐ。
    /// - 移行方法: 外部 crate は `StagePipeline` を `spawn_container_with_stages` に渡す。
    ///   `run_then` は fork 後の子（`process.rs::run_child`）内で core が呼ぶ。`run_then` を
    ///   単体で呼んでいた利用者は、ステージ列の順序・失敗時の挙動の確認を
    ///   `spawn_container_with_stages` 経由の結合試験（`fork_exec_isolation` の `stages-order`）へ移す。
    pub(crate) fn run_then<T>(
        mut self,
        exec: impl FnOnce(&StageReport) -> Result<T, ExecError>,
    ) -> Result<T, ExecError> {
        let mut statuses = [StageStatus::Skipped; 5];
        for kind in StageKind::ORDER {
            let idx = kind.index();
            if kind == StageKind::NoNewPrivs {
                // 組み込み: フック配列のスロットは読まない（差し替えも無効化もできない）。
                no_new_privs::apply_no_new_privs()
                    .map_err(|e| e.at_stage(kind.isolation_stage()))?;
            } else {
                let Some(Some(hook)) = self.hooks.get_mut(idx) else {
                    continue;
                };
                hook.apply()
                    .map_err(|e| e.at_stage(kind.isolation_stage()))?;
            }
            if let Some(s) = statuses.get_mut(idx) {
                *s = StageStatus::Applied;
            }
        }
        exec(&StageReport { statuses })
    }
}

#[cfg(test)]
mod tests {
    use super::super::no_new_privs::testing::{fake, rec, take};
    use super::*;
    use crate::sys::{self, SysError};

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

    /// 組み込み段を除く全段にダミーフックを登録する（逆順）。
    fn all_hooks_reversed() -> StagePipeline {
        let mut p = StagePipeline::new();
        for kind in StageKind::ORDER.iter().rev().filter(|k| !k.is_builtin()) {
            p = p.with_hook(*kind, ok_hook(*kind)).unwrap();
        }
        p
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
        let report = all_hooks_reversed()
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

    /// CORE-1・TASK-27.4.3: NO_NEW_PRIVS は capability 削減の後・Landlock の前に実行される
    /// （受け入れ基準の機械照合。Landlock -> CapabilityDrop の逆順で登録しても崩れない）。
    #[test]
    fn core1_no_new_privs_runs_after_capability_drop_and_before_landlock() {
        take();
        let p = StagePipeline::new()
            .with_hook(StageKind::Landlock, ok_hook(StageKind::Landlock))
            .unwrap()
            .with_hook(
                StageKind::CapabilityDrop,
                ok_hook(StageKind::CapabilityDrop),
            )
            .unwrap();
        p.run_then(exec_ok).unwrap();
        assert_eq!(
            take(),
            ["capability_drop", "no_new_privs", "landlock", "exec"]
        );
    }

    /// CORE-1・TASK-27.4.2/27.4.3: 一部登録でも順序を保ち、未登録は Skipped（組み込みは常に Applied）。
    #[test]
    fn core1_partial_hooks_keep_order_and_report_skipped() {
        take();
        let p = StagePipeline::new()
            .with_hook(StageKind::Seccomp, ok_hook(StageKind::Seccomp))
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

    /// CORE-1・TASK-27.4.3: フック無しでも組み込みの NO_NEW_PRIVS だけは適用され、その後 exec。
    #[test]
    fn core1_empty_pipeline_applies_builtin_no_new_privs() {
        take();
        let report = StagePipeline::new()
            .run_then(|r| {
                rec("exec");
                Ok(r.clone())
            })
            .unwrap();
        assert_eq!(take(), ["no_new_privs", "exec"]);
        for (kind, status) in report.iter() {
            let expected = if kind == StageKind::NoNewPrivs {
                StageStatus::Applied
            } else {
                StageStatus::Skipped
            };
            assert_eq!(status, expected, "{}", kind.as_str());
        }
    }

    /// CORE-1・TASK-27.4.2/27.4.3: k 段目の失敗で打ち切り、段は付け替わり code は保持される。
    #[test]
    fn core1_hook_failure_stops_pipeline() {
        for (k, failing) in StageKind::ORDER.iter().enumerate() {
            take();
            let mut p = StagePipeline::new();
            for kind in StageKind::ORDER {
                if kind.is_builtin() {
                    continue;
                }
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
            if failing.is_builtin() {
                fake(Err(SysError::Os(sys::EPERM)), Ok(true));
            }
            let err = p.run_then(exec_ok).unwrap_err();
            assert_eq!(err.stage, failing.isolation_stage());
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            let calls = take();
            assert_eq!(calls.len(), k + 1, "stopped after {}", failing.as_str());
            let last = if failing.is_builtin() {
                "no_new_privs"
            } else {
                "fail"
            };
            assert_eq!(calls.last().copied(), Some(last));
            assert!(!calls.contains(&"exec"));
        }
    }

    /// CORE-1・TASK-27.4.3: capability 削減が失敗したら NO_NEW_PRIVS には進まない。
    #[test]
    fn core1_capability_drop_failure_skips_no_new_privs() {
        take();
        let p = StagePipeline::new()
            .with_hook(StageKind::CapabilityDrop, || {
                Err(ExecError::new(
                    ErrorCode::Internal,
                    IsolationStage::Validate,
                    "boom",
                ))
            })
            .unwrap();
        let err = p.run_then(exec_ok).unwrap_err();
        assert_eq!(err.stage, IsolationStage::CapabilityDrop);
        assert_eq!(take(), Vec::<&str>::new());
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

    /// CORE-1・TASK-27.4.3: 組み込みの NO_NEW_PRIVS 段はフックで差し替えられない。
    #[test]
    fn core1_builtin_no_new_privs_cannot_be_replaced() {
        let err = StagePipeline::new()
            .with_hook(StageKind::NoNewPrivs, || Ok(()))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert_eq!(err.violation, None);
        assert!(err.message.contains("built-in"), "{}", err.message);
    }
}
