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
//! cgroup 参加の実体は `crate::cgroups::CgroupJoin`（TASK-32.4・#161。[`StageHook`] 実装済みで、
//! `ContainerCgroup::join_hook` が返すものを呼び出し側が `with_hook(StageKind::CgroupJoin, ..)` で登録する）。
//! 残りの段の実体は後続の TASK が [`StageHook`] として差し込む（rootless: TASK-40。Landlock は [`StagePipeline::with_landlock`]（TASK-39.4・#184）で core の適用処理を差し込む）。`CapabilityDrop`（`exec/capabilities.rs`。
//! #173・TASK-37.2・SEC-1）・`NoNewPrivs`（`exec/no_new_privs.rs`。#833・TASK-27.4.3）・
//! `Seccomp`（`exec/seccomp.rs`。#178・TASK-38.3・CORE-5。exec 直前の最終段）は
//! 組み込みの固定ステージで、フックを登録しなくても必ず実行され、[`StagePipeline::with_hook`] による
//! 差し替えは拒否する（呼び出し側の登録漏れで capability が残る経路を作らない）。
//! capability 削減と `NO_NEW_PRIVS` を Landlock / seccomp より前に固定する順序は fail-closed の前提で、
//! seccomp は失敗すると exec に進まない。
//!
//! # 契約
//!
//! - **順序は [`StageKind::ORDER`] だけが決める**: 登録順・呼び出し側の指定では変えられない。
//!   exec は `StagePipeline::run_then` の終端クロージャからしか呼べず、全段成功後に限り最後に走る
//! - **最初の失敗で打ち切る**: 後続段と exec は呼ばない。エラーの `stage` はパイプライン側で
//!   その段に付け替える（フックが自分の段を偽れない。ERR-1）
//! - **同じ段への二重登録は拒否する**: 既存の制限フックを no-op で上書きする経路を作らない
//! - **組み込みの固定ステージは差し替えられない**: [`StageKind::is_builtin`] の段
//!   （`CapabilityDrop`・`NoNewPrivs`・`Seccomp`）は `with_hook` で `InvalidArgument` になり、`run_then` はフック配列を読まず
//!   組み込み処理へ直接振り分ける
//! - **[`StageReport`] と `Applied` は制限適用の証跡ではない**: 「フックが `Ok` を返した」事実の
//!   記録にすぎない。`process.rs::require_restriction_evidence` の判定には使わず、フック無し・
//!   ダミーフックのどちらでも exec は `PermissionDenied` のまま拒否される（SEC-1・CORE-5）。
//!   将来の証跡は、各ビルトインのステージが返す型付きトークンで表す（REPAIR-3: 実装済みを装わない）。
//!   capability 削減の [`CapabilityReport`] は終端クロージャへ渡すが、最終的な証跡型は
//!   TASK-38・TASK-39 で決めるため、現時点では exec の許可には使われない
//! - **フックは fork 前に親で構築し、fork で子へコピーされて子で実行される**。シングルスレッドの
//!   まま実行するため `Send` は要求しない。panic は `sys::fork_single_threaded` の
//!   `catch_unwind` により `EXIT_SETUP_FAILED` で `_exit` する（fail-closed）
//! - **フックの実装者は core crate 内のモジュール**を想定する（`ExecError::new` は非公開）
//!
//! # cgroup 参加（TASK-32.4）
//!
//! pivot 後はホストの `/sys/fs/cgroup` が見えないため、参加フックは fork 前に確保した cgroup
//! ディレクトリの `OwnedFd` 経由で `cgroup.procs` へ書く。本番 launcher からの結線は未実装（REPAIR-3）。

use std::fmt;

#[cfg(not(test))]
use super::capabilities::apply_default_capabilities;
#[cfg(not(test))]
use super::landlock::apply_landlock_stage;
#[cfg(not(test))]
use super::seccomp::apply_default_seccomp;
use super::{CapabilityReport, ExecError, IsolationStage, no_new_privs};
// テストでは本物（`Threads: 1` を要求）の代わりに偽カーネルで走る関数へ差し替える。
#[cfg(test)]
use super::capabilities::testing::apply_default_capabilities;
#[cfg(test)]
use super::landlock::testing::apply_landlock_stage;
#[cfg(test)]
use super::seccomp::testing::apply_default_seccomp;
use crate::landlock::LandlockRuleset;
use crate::traits::types::ErrorCode;

/// ステージの種別。`ORDER` の順が実行順（固定）。
///
/// `#[non_exhaustive]` にしない: 順序表とスロット添字が全要素を網羅することを、`match` の
/// 網羅性検査でコンパイル時に保証するため。段の追加はこのモジュール内の変更に限る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageKind {
    /// cgroup 参加（TASK-32）。
    CgroupJoin,
    /// capability 削減（#173・TASK-37.2）。組み込みの固定ステージ（差し替え不可）。
    CapabilityDrop,
    /// `PR_SET_NO_NEW_PRIVS`（#833・TASK-27.4.3）。組み込みの固定ステージ（差し替え不可）。
    NoNewPrivs,
    /// Landlock（TASK-39）。
    Landlock,
    /// seccomp（#178・TASK-38.3）。組み込みの固定ステージ（差し替え不可）。
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
            StageKind::CapabilityDrop | StageKind::NoNewPrivs | StageKind::Seccomp => true,
            StageKind::CgroupJoin | StageKind::Landlock => false,
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

/// cgroup 参加（TASK-32.4）。fork 後の子（pivot 後・capability 削減前）でのみ呼ばれる契約。
impl StageHook for crate::cgroups::CgroupJoin {
    fn apply(&mut self) -> Result<(), ExecError> {
        self.join_current_process().map_err(ExecError::from_cgroup)
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

/// 順序固定のステージ列。空のままでも組み込みの capability 削減・`NO_NEW_PRIVS`・seccomp だけを適用して exec へ進み、
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

    /// core の Landlock 適用処理（TASK-39.4・#184・CORE-5）を Landlock 段へ登録する。
    ///
    /// `ruleset` は fork 前に親で `landlock_ruleset_from_config` 等で作り、クロージャへ move する
    /// （fork で子へコピーされる）。実行位置は [`StageKind::ORDER`] により capability 削減・
    /// `NO_NEW_PRIVS` の後、seccomp の前で固定される。適用失敗は `stage = Landlock` のエラーで
    /// 以降の段と exec に進まない（fail-closed）。Landlock スロットを占有するため、独自の Landlock
    /// フックとは排他で、どちらが先でも 2 回目は `InvalidArgument`（`Validate` 段）になる。
    ///
    /// 適用結果は制限適用の証跡ではなく捨てる（証跡型の確定は後続作業。REPAIR-3）。
    pub fn with_landlock(self, ruleset: LandlockRuleset) -> Result<Self, ExecError> {
        self.with_hook(StageKind::Landlock, move || {
            apply_landlock_stage(&ruleset).map(|_report| ())
        })
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
    /// # 破壊的変更と移行方法（#173・TASK-37.2）
    ///
    /// - 変更内容: `CapabilityDrop` が組み込みの固定ステージになった。`with_hook(StageKind::CapabilityDrop, …)`
    ///   は `InvalidArgument`（`Validate` 段）で拒否される。
    /// - 理由: フック登録に頼ると登録漏れで capability が残る。組み込みにして SEC-1 を fail-closed にする。
    /// - 移行方法: capability 削減は core が常に適用するため登録は不要。独自の制限は他の段
    ///   （`CgroupJoin`・`Landlock`）のフックで行う。
    ///
    /// # 破壊的変更と移行方法（#178・TASK-38.3）
    ///
    /// - 変更内容: `Seccomp` が組み込みの固定ステージになった。`with_hook(StageKind::Seccomp, …)` は
    ///   `InvalidArgument`（`Validate` 段）で拒否される。
    /// - 理由: 登録漏れ・no-op フックで seccomp が外れる経路をなくす（CORE-5・fail-closed）。
    /// - 移行方法: seccomp は core が常に適用するため登録は不要。exec 直前の観測点・独自処理は、
    ///   組み込みでない最後の段 `Landlock` を使う（#184 では Landlock を組み込みにせず `with_landlock` を提供した。組み込み化は後続作業）。
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
        exec: impl FnOnce(&StageReport, Option<&CapabilityReport>) -> Result<T, ExecError>,
    ) -> Result<T, ExecError> {
        let mut statuses = [StageStatus::Skipped; 5];
        let mut capability_report = None;
        for kind in StageKind::ORDER {
            let idx = kind.index();
            match kind {
                // 組み込み: フック配列のスロットは読まない（差し替えも無効化もできない）。
                StageKind::CapabilityDrop => {
                    let r = apply_default_capabilities()
                        .map_err(|e| e.at_stage(kind.isolation_stage()))?;
                    capability_report = Some(r);
                }
                StageKind::NoNewPrivs => {
                    no_new_privs::apply_no_new_privs()
                        .map_err(|e| e.at_stage(kind.isolation_stage()))?;
                }
                StageKind::Seccomp => {
                    // 証跡型の確定と配線は後続作業（スコープ外）のため、終端へは渡さない（REPAIR-3）。
                    let _report =
                        apply_default_seccomp().map_err(|e| e.at_stage(kind.isolation_stage()))?;
                }
                StageKind::CgroupJoin | StageKind::Landlock => {
                    let Some(Some(hook)) = self.hooks.get_mut(idx) else {
                        continue;
                    };
                    hook.apply()
                        .map_err(|e| e.at_stage(kind.isolation_stage()))?;
                }
            }
            if let Some(s) = statuses.get_mut(idx) {
                *s = StageStatus::Applied;
            }
        }
        exec(&StageReport { statuses }, capability_report.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::super::capabilities::testing::fake_capability_drop_err;
    use super::super::no_new_privs::testing::{fake, rec, take};
    use super::super::seccomp::testing::fake_seccomp_err;
    use super::*;
    use crate::sys::{self, SysError};

    fn ok_hook(kind: StageKind) -> impl StageHook + 'static {
        move || {
            rec(kind.as_str());
            Ok(())
        }
    }

    fn exec_ok(_: &StageReport, _: Option<&CapabilityReport>) -> Result<(), ExecError> {
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
            .run_then(|r, _| {
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
            .unwrap();
        p.run_then(exec_ok).unwrap();
        assert_eq!(
            take(),
            [
                "capability_drop",
                "no_new_privs",
                "landlock",
                "seccomp",
                "exec"
            ]
        );
    }

    /// CORE-1・TASK-27.4.2/27.4.3: 一部登録でも順序を保ち、未登録は Skipped（組み込みは常に Applied）。
    #[test]
    fn core1_partial_hooks_keep_order_and_report_skipped() {
        take();
        let p = StagePipeline::new()
            .with_hook(StageKind::Landlock, ok_hook(StageKind::Landlock))
            .unwrap();
        let report = p
            .run_then(|r, _| {
                rec("exec");
                Ok(r.clone())
            })
            .unwrap();
        assert_eq!(
            take(),
            [
                "capability_drop",
                "no_new_privs",
                "landlock",
                "seccomp",
                "exec"
            ]
        );
        let got: Vec<_> = report.iter().map(|(_, s)| s).collect();
        assert_eq!(
            got,
            [
                StageStatus::Skipped,
                StageStatus::Applied,
                StageStatus::Applied,
                StageStatus::Applied,
                StageStatus::Applied
            ]
        );
    }

    /// CORE-1・TASK-27.4.3・TASK-37.2: フック無しでも組み込みの capability 削減と NO_NEW_PRIVS は適用され、その後 exec。
    #[test]
    fn core1_empty_pipeline_applies_builtin_stages() {
        take();
        let report = StagePipeline::new()
            .run_then(|r, _| {
                rec("exec");
                Ok(r.clone())
            })
            .unwrap();
        assert_eq!(
            take(),
            ["capability_drop", "no_new_privs", "seccomp", "exec"]
        );
        assert_eq!(report.status(StageKind::Seccomp), StageStatus::Applied);
        for (kind, status) in report.iter() {
            let expected = if kind.is_builtin() {
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
            match failing {
                StageKind::CapabilityDrop => fake_capability_drop_err(SysError::Os(sys::EPERM)),
                StageKind::NoNewPrivs => fake(Err(SysError::Os(sys::EPERM)), Ok(true)),
                StageKind::Seccomp => fake_seccomp_err(ExecError::new(
                    ErrorCode::PermissionDenied,
                    IsolationStage::Validate,
                    "boom",
                )),
                _ => {}
            }
            let err = p.run_then(exec_ok).unwrap_err();
            assert_eq!(err.stage, failing.isolation_stage());
            assert_eq!(err.code, ErrorCode::PermissionDenied);
            let calls = take();
            assert_eq!(calls.len(), k + 1, "stopped after {}", failing.as_str());
            let last = match failing {
                StageKind::CapabilityDrop => "capability_drop",
                StageKind::NoNewPrivs => "no_new_privs",
                StageKind::Seccomp => "seccomp",
                _ => "fail",
            };
            assert_eq!(calls.last().copied(), Some(last));
            assert!(!calls.contains(&"exec"));
        }
    }

    /// CORE-1・TASK-27.4.3・TASK-37.2: capability 削減が失敗したら NO_NEW_PRIVS には進まない。
    #[test]
    fn core1_capability_drop_failure_skips_no_new_privs() {
        take();
        fake_capability_drop_err(SysError::Os(sys::EPERM));
        let err = StagePipeline::new().run_then(exec_ok).unwrap_err();
        assert_eq!(err.stage, IsolationStage::CapabilityDrop);
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(take(), ["capability_drop"]);
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

    /// SEC-1・TASK-37.2: capability 削減は組み込みで、フックでは差し替えられない。
    #[test]
    fn core1_builtin_capability_drop_cannot_be_replaced() {
        let err = StagePipeline::new()
            .with_hook(StageKind::CapabilityDrop, || Ok(()))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert!(err.message.contains("built-in"), "{}", err.message);
    }

    /// SEC-1・MS-2・TASK-37.2（受け入れ条件）: cgroup 参加 -> capability 削減 -> NO_NEW_PRIVS ->
    /// Landlock -> seccomp の順に走る（逆順で登録しても崩れない）。
    #[test]
    fn sec1_capability_drop_runs_after_cgroup_join_and_before_landlock_and_seccomp() {
        take();
        let mut p = StagePipeline::new();
        for kind in [StageKind::Landlock, StageKind::CgroupJoin] {
            p = p.with_hook(kind, ok_hook(kind)).unwrap();
        }
        p.run_then(exec_ok).unwrap();
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
    }

    /// CORE-3・TASK-32.4（受け入れ条件）: 実 `CgroupJoin` は capability 削減・Landlock・seccomp・exec の
    /// いずれより前に走る。Landlock 時点で既に `cgroup.procs` へ PID が書かれていることで機械照合する。
    #[test]
    fn core3_task32_4_cgroup_join_runs_before_other_stages() {
        use crate::cgroups::{CgroupJoin, CgroupName};
        use crate::traits::ContainerId;
        use std::os::fd::OwnedFd;

        take();
        let dir = std::env::temp_dir().join(format!("fandhe-stages-cgjoin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let procs = dir.join("cgroup.procs");
        std::fs::write(&procs, "").unwrap();
        let fd = OwnedFd::from(std::fs::File::open(&dir).unwrap());
        let name = CgroupName::new(&ContainerId::new("t").unwrap()).unwrap();
        let mut real = CgroupJoin::from_dir_for_test(name, fd);
        let join = move || {
            real.apply()?;
            rec("cgroup_join");
            Ok(())
        };
        let procs_for_landlock = procs.clone();
        let landlock = move || {
            let seen = std::fs::read_to_string(&procs_for_landlock).unwrap();
            // Landlock 時点で自 PID が書かれていれば "landlock"、そうでなければ別名で記録する。
            rec(if seen == std::process::id().to_string() {
                "landlock"
            } else {
                "landlock:not_joined"
            });
            Ok(())
        };
        StagePipeline::new()
            .with_hook(StageKind::Landlock, landlock)
            .unwrap()
            .with_hook(StageKind::CgroupJoin, join)
            .unwrap()
            .run_then(exec_ok)
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
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CORE-5・TASK-38.3・MS-2（受け入れ条件）: seccomp は Landlock の直後・exec の直前に走る。
    #[test]
    fn core5_seccomp_runs_after_landlock_and_immediately_before_exec() {
        take();
        let p = StagePipeline::new()
            .with_hook(StageKind::Landlock, ok_hook(StageKind::Landlock))
            .unwrap();
        p.run_then(exec_ok).unwrap();
        assert_eq!(
            take(),
            [
                "capability_drop",
                "no_new_privs",
                "landlock",
                "seccomp",
                "exec"
            ]
        );
    }

    fn landlock_fixture() -> LandlockRuleset {
        use crate::landlock::{AccessFs, PathRule, RuleOrigin, RulePath};
        LandlockRuleset::for_observation(
            6,
            vec![PathRule {
                path: RulePath::Root,
                allowed: AccessFs::READ,
                origin: RuleOrigin::Root,
            }],
        )
    }

    /// CORE-5・TASK-39.4・MS-2（受け入れ条件）: Landlock は capability 削減の後・seccomp の前に走る。
    #[test]
    fn core5_landlock_runs_after_capability_drop_and_before_seccomp() {
        take();
        let p = StagePipeline::new()
            .with_landlock(landlock_fixture())
            .unwrap();
        p.run_then(exec_ok).unwrap();
        assert_eq!(
            take(),
            [
                "capability_drop",
                "no_new_privs",
                "landlock",
                "seccomp",
                "exec"
            ]
        );
    }

    /// CORE-5・TASK-39.4: 他段のフックを後から登録しても固定順。
    #[test]
    fn core5_landlock_with_cgroup_hook_keeps_fixed_order() {
        take();
        let p = StagePipeline::new()
            .with_landlock(landlock_fixture())
            .unwrap()
            .with_hook(StageKind::CgroupJoin, ok_hook(StageKind::CgroupJoin))
            .unwrap();
        p.run_then(exec_ok).unwrap();
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
    }

    /// CORE-5・TASK-39.4: Landlock 適用が失敗したら seccomp・exec に進まない（fail-closed）。
    #[test]
    fn core5_landlock_failure_blocks_seccomp_and_exec() {
        take();
        super::super::landlock::testing::fake_landlock_err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Validate,
            "boom",
        ));
        let err = StagePipeline::new()
            .with_landlock(landlock_fixture())
            .unwrap()
            .run_then(exec_ok)
            .unwrap_err();
        assert_eq!(err.stage, IsolationStage::Landlock);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(take(), ["capability_drop", "no_new_privs", "landlock"]);
    }

    /// CORE-5・TASK-39.4: capability 削減が失敗したら Landlock は走らない。
    #[test]
    fn core5_capability_drop_failure_skips_landlock() {
        take();
        fake_capability_drop_err(SysError::Os(sys::EPERM));
        let err = StagePipeline::new()
            .with_landlock(landlock_fixture())
            .unwrap()
            .run_then(exec_ok)
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(take(), ["capability_drop"]);
    }

    /// CORE-5・TASK-39.4: `with_landlock` と独自 Landlock フックは排他（どちらの順でも拒否）。
    #[test]
    fn core5_with_landlock_conflicts_with_custom_landlock_hook() {
        let a = StagePipeline::new()
            .with_hook(StageKind::Landlock, || Ok(()))
            .unwrap()
            .with_landlock(landlock_fixture())
            .unwrap_err();
        let b = StagePipeline::new()
            .with_landlock(landlock_fixture())
            .unwrap()
            .with_hook(StageKind::Landlock, || Ok(()))
            .unwrap_err();
        for err in [a, b] {
            assert_eq!(err.code, ErrorCode::InvalidArgument);
            assert_eq!(err.stage, IsolationStage::Validate);
            assert!(
                err.message.contains("already registered"),
                "{}",
                err.message
            );
        }
    }

    /// CORE-5・TASK-38.3: seccomp は組み込みで、フックでは差し替えられない。
    #[test]
    fn core5_builtin_seccomp_cannot_be_replaced() {
        let err = StagePipeline::new()
            .with_hook(StageKind::Seccomp, || Ok(()))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert!(err.message.contains("built-in"), "{}", err.message);
    }

    /// CORE-5・TASK-38.3: seccomp 適用が失敗したら exec に進まない（fail-closed）。
    #[test]
    fn core5_seccomp_failure_blocks_exec() {
        take();
        fake_seccomp_err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Validate,
            "boom",
        ));
        let err = StagePipeline::new().run_then(exec_ok).unwrap_err();
        assert_eq!(err.stage, IsolationStage::Seccomp);
        assert_eq!(err.code, ErrorCode::FailedPrecondition);
        assert_eq!(take(), ["capability_drop", "no_new_privs", "seccomp"]);
    }

    /// SEC-1・TASK-37.2: 終端へ capability 削減の結果（OCI 既定集合）が渡る。
    #[test]
    fn sec1_terminal_receives_capability_report() {
        take();
        let granted = StagePipeline::new()
            .run_then(|_, caps| Ok(caps.map(|c| c.granted)))
            .unwrap();
        assert_eq!(
            granted,
            Some(crate::capabilities::CapabilitySet::oci_default())
        );
        take();
    }
}
