//! 順序固定の制限ステージ列（CORE-1・TASK-27.4.2・#832・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! `crate::exec` の最小実行フロー第 4 段の「枠」。`process.rs::run_child` が pivot_root の後・
//! `exec_entrypoint` の前に `StagePipeline::run_then` を呼び、次の順序で各段のフックを実行する。
//!
//! ```text
//! cgroup 参加 -> rlimit 適用 -> capability 削減 -> PR_SET_NO_NEW_PRIVS -> Landlock -> seccomp -> exec
//! ```
//!
//! cgroup 参加の実体は `crate::cgroups::CgroupJoin`（TASK-32.4・#161。[`StageHook`] 実装済みで、
//! `ContainerCgroup::join_hook` が返すものを呼び出し側が `with_hook(StageKind::CgroupJoin, ..)` で登録する）。
//! 残りの段の実体は後続の TASK が [`StageHook`] として差し込む（rootless: TASK-40。Landlock は [`StagePipeline::with_landlock`]（TASK-39.4・#184）で core の適用処理を差し込む）。`Rlimits`（`exec/rlimits.rs`。SUP-12・TASK-169.1・#526。`with_rlimits` で渡した集合を適用し、未設定なら何もしない）・`CapabilityDrop`（`exec/capabilities.rs`。
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
//!   （`Rlimits`・`CapabilityDrop`・`NoNewPrivs`・`Seccomp`）は `with_hook` で `InvalidArgument` になり、`run_then` はフック配列を読まず
//!   組み込み処理へ直接振り分ける
//! - **[`StageReport`] と `Applied` は制限適用の証跡ではない**: 「フックが `Ok` を返した」事実の
//!   記録にすぎない。exec の許可には使わない（SEC-1・CORE-5）
//! - **制限適用の証跡は型付きトークン `LaunchReady`**（#1714・TASK-29 追補・#1314 の決定）: 組み込みの
//!   各段（`Rlimits`・`CapabilityDrop`・`NoNewPrivs`・`Seccomp`）と、`with_landlock` で登録した core の
//!   Landlock 適用が `Ok` を返した直後に、このモジュール内だけで作れる段ごとの証跡（`exec/reapply.rs` の
//!   `ExecReady` と同じ流儀）を、`run_then` が束ねて終端クロージャへ値で渡す。`process.rs` の
//!   `require_restriction_evidence` が `LaunchReady` を受け取ったときだけ exec を許す。
//!   - **Landlock は必須**: `with_landlock` を通らない（独自フックだけ・未登録）パイプラインでは作られない
//!   - **`CgroupJoin` は条件に入れない**: cgroup を使う設定なのに join していない場合の拒否は
//!     本番 launcher 側の責務（#1715）
//!   - **`/proc/self/status` の読み戻しは証跡にしない**: 親から継承した制限と区別できないため
//!   - 段が 1 つでも失敗したら打ち切るので `LaunchReady` は作られず、終端も呼ばれない（fail-closed）
//!   - capability 削減の [`CapabilityReport`] は終端クロージャへ別途渡すが、exec の許可には使わない
//! - **フックは fork 前に親で構築し、fork で子へコピーされて子で実行される**。シングルスレッドの
//!   まま実行するため `Send` は要求しない。panic は `sys::fork_single_threaded` の
//!   `catch_unwind` により `EXIT_SETUP_FAILED` で `_exit` する（fail-closed）
//! - **フックの実装者は core crate 内のモジュール**を想定する（`ExecError::new` は非公開）
//!
//! # cgroup 参加（TASK-32.4）
//!
//! pivot 後はホストの `/sys/fs/cgroup` が見えないため、参加フックは fork 前に確保した cgroup
//! ディレクトリの `OwnedFd` 経由で `cgroup.procs` へ書く。本番 launcher からの結線は未実装（#1715。REPAIR-3）。

use std::fmt;

#[cfg(not(test))]
use super::capabilities::apply_default_capabilities;
#[cfg(not(test))]
use super::landlock::apply_landlock_stage;
#[cfg(not(test))]
use super::seccomp::apply_default_seccomp;
use super::{CapabilityReport, ExecError, IsolationStage, no_new_privs, rlimits};
// テストでは本物（`Threads: 1` を要求）の代わりに偽カーネルで走る関数へ差し替える。
#[cfg(test)]
use super::capabilities::testing::apply_default_capabilities;
#[cfg(test)]
use super::landlock::testing::apply_landlock_stage;
#[cfg(test)]
use super::seccomp::testing::apply_default_seccomp;
use crate::landlock::LandlockRuleset;
use crate::rlimits::Rlimits;
use crate::traits::types::ErrorCode;

/// 段ごとの適用証跡（#1714・SEC-1・CORE-5）。
///
/// どれもこのモジュールの外では作れない（型自体が非公開）。`run_then` が各段の関数の `Ok` を受けた
/// 直後にだけ作る。`Clone`・`Copy`・`Default` は持たせず、複製・既定値での偽造経路を作らない。
/// 段の関数の戻り値は変えない（`exec/reapply.rs` も同系統の関数を使い、戻り値を広げると証跡を作る手段が
/// exec の再適用の経路へ漏れるため）。
///
/// `Rlimits` は「呼び出し側が指定した集合（未指定・空を含む）を組み込み段が処理し終えた」ことを表す
/// （SUP-12。launch では OCI の `process.rlimits` が空でもよい。必須にするかは spec の判断）。
struct RlimitsApplied {
    _private: (),
}
/// capability 削減が `Ok` を返した証跡。
struct CapabilitiesDropped {
    _private: (),
}
/// `PR_SET_NO_NEW_PRIVS` の設定が `Ok` を返した証跡。
struct NoNewPrivsSet {
    _private: (),
}
/// core の Landlock 適用（`with_landlock` 経由の `apply_landlock_stage`）が `Ok` を返した証跡。
/// 独自の Landlock フックでは作られない。
struct LandlockApplied {
    _private: (),
}
/// 組み込み seccomp が `Ok` を返した証跡。
struct SeccompApplied {
    _private: (),
}

/// 制限ステージの適用証跡（#1714・TASK-29 追補・SEC-1・CORE-5）。
///
/// `exec/reapply.rs` の `ExecReady` と同じ流儀の型付きトークン。作るのは `StagePipeline::run_then` が
/// 呼ぶ `bundle_launch_evidence` だけで、`for_test` のようなテスト用コンストラクタ・`Clone`・`Default` は
/// 持たない。`process.rs` の `require_restriction_evidence` が値で受け取ったときだけ exec を許す。
/// フィールドは「どの段が通ったか」を型で保持するだけで読み出さない。
#[must_use]
pub(crate) struct LaunchReady {
    _rlimits: RlimitsApplied,
    _capabilities: CapabilitiesDropped,
    _no_new_privs: NoNewPrivsSet,
    _landlock: LandlockApplied,
    _seccomp: SeccompApplied,
}

/// 証跡がそろわなかったこと。欠けた段を `StageKind::ORDER` の順で持つ（最大 5 件）。
///
/// `require_restriction_evidence` が exec を拒否する理由（`PermissionDenied`・段 `Exec`）に変換する。
#[derive(Debug)]
pub(crate) struct LaunchNotReady {
    missing: Vec<StageKind>,
}

impl LaunchNotReady {
    /// 欠けた段（`ORDER` 順）。
    pub(crate) fn missing(&self) -> &[StageKind] {
        &self.missing
    }

    /// ステージ列を通していない入口（`exec_entrypoint`）用。証跡を持つ 5 段をすべて欠落として返す。
    pub(super) fn pipeline_not_run() -> Self {
        Self {
            missing: StageKind::ORDER
                .iter()
                .copied()
                .filter(|k| *k != StageKind::CgroupJoin)
                .collect(),
        }
    }

    /// exec 拒否のエラーへ変換する。段を `Exec` に保つのは、終了コード 126 を変えないため。
    pub(super) fn into_exec_error(self) -> ExecError {
        let names: Vec<&str> = self.missing().iter().map(|k| k.as_str()).collect();
        ExecError::new(
            ErrorCode::PermissionDenied,
            IsolationStage::Exec,
            format!(
                "refusing to exec: no evidence that the isolation restrictions were applied; missing: {}",
                names.join(",")
            ),
        )
    }
}

/// 5 つの段ごとの証跡を `LaunchReady` に束ねる。1 つでも欠ければ欠けた段を列挙して `Err`。
///
/// 呼び出し元は `StagePipeline::run_then` だけ。関数に切り出してあるのは、パイプラインでは起こせない
/// 欠落（例: seccomp だけ無い）も表で試験するため（`CgroupJoin` は条件に入れない）。
fn bundle_launch_evidence(
    rlimits: Option<RlimitsApplied>,
    capabilities: Option<CapabilitiesDropped>,
    no_new_privs: Option<NoNewPrivsSet>,
    landlock: Option<LandlockApplied>,
    seccomp: Option<SeccompApplied>,
) -> Result<LaunchReady, LaunchNotReady> {
    match (rlimits, capabilities, no_new_privs, landlock, seccomp) {
        (Some(r), Some(c), Some(n), Some(l), Some(s)) => Ok(LaunchReady {
            _rlimits: r,
            _capabilities: c,
            _no_new_privs: n,
            _landlock: l,
            _seccomp: s,
        }),
        (r, c, n, l, s) => {
            let mut missing = Vec::new();
            if r.is_none() {
                missing.push(StageKind::Rlimits);
            }
            if c.is_none() {
                missing.push(StageKind::CapabilityDrop);
            }
            if n.is_none() {
                missing.push(StageKind::NoNewPrivs);
            }
            if l.is_none() {
                missing.push(StageKind::Landlock);
            }
            if s.is_none() {
                missing.push(StageKind::Seccomp);
            }
            Err(LaunchNotReady { missing })
        }
    }
}

/// ステージの種別。`ORDER` の順が実行順（固定）。
///
/// `#[non_exhaustive]` にしない: 順序表とスロット添字が全要素を網羅することを、`match` の
/// 網羅性検査でコンパイル時に保証するため。段の追加はこのモジュール内の変更に限る。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageKind {
    /// cgroup 参加（TASK-32）。
    CgroupJoin,
    /// rlimit 適用（SUP-12・TASK-169.1・#526）。組み込みの固定ステージ（差し替え不可）。
    /// capability 削減より前に置くのは、削減後は `CAP_SYS_RESOURCE` が無く hard の引き上げが常に失敗するため。
    Rlimits,
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
    pub const ORDER: [StageKind; 6] = [
        StageKind::CgroupJoin,
        StageKind::Rlimits,
        StageKind::CapabilityDrop,
        StageKind::NoNewPrivs,
        StageKind::Landlock,
        StageKind::Seccomp,
    ];

    fn index(self) -> usize {
        match self {
            StageKind::CgroupJoin => 0,
            StageKind::Rlimits => 1,
            StageKind::CapabilityDrop => 2,
            StageKind::NoNewPrivs => 3,
            StageKind::Landlock => 4,
            StageKind::Seccomp => 5,
        }
    }

    /// 組み込みの固定ステージか（`with_hook` で差し替えを拒否する唯一の判定元）。
    pub fn is_builtin(self) -> bool {
        match self {
            StageKind::Rlimits
            | StageKind::CapabilityDrop
            | StageKind::NoNewPrivs
            | StageKind::Seccomp => true,
            StageKind::CgroupJoin | StageKind::Landlock => false,
        }
    }

    /// 機械可読な英語識別子。
    pub fn as_str(self) -> &'static str {
        match self {
            StageKind::CgroupJoin => "cgroup_join",
            StageKind::Rlimits => "rlimits",
            StageKind::CapabilityDrop => "capability_drop",
            StageKind::NoNewPrivs => "no_new_privs",
            StageKind::Landlock => "landlock",
            StageKind::Seccomp => "seccomp",
        }
    }

    fn isolation_stage(self) -> IsolationStage {
        match self {
            StageKind::CgroupJoin => IsolationStage::CgroupJoin,
            StageKind::Rlimits => IsolationStage::Rlimits,
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
    statuses: [StageStatus; 6],
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
    hooks: [Option<Box<dyn StageHook>>; 6],
    rlimits: Option<Rlimits>,
    /// core の Landlock 適用（`with_landlock`）。これだけが `LandlockApplied` 証跡を作れる。
    landlock: Option<LandlockRuleset>,
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
            if kind == StageKind::Landlock {
                let state = if self.landlock.is_some() {
                    "ruleset"
                } else if registered {
                    "custom_hook"
                } else {
                    "none"
                };
                d.field(kind.as_str(), &state);
                continue;
            }
            d.field(kind.as_str(), &registered);
        }
        d.finish()
    }
}

impl StagePipeline {
    /// 全段が未登録の列を作る。
    pub fn new() -> Self {
        Self {
            hooks: [None, None, None, None, None, None],
            rlimits: None,
            landlock: None,
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
    /// 適用が `Ok` なら、この段の証跡（`LandlockApplied`）を `run_then` が作る。独自の Landlock フックでは
    /// 証跡は作られず、`LaunchReady` もそろわない（Landlock は必須。#1714・CORE-5）。適用結果
    /// `LandlockApplyReport` 自体は証跡ではなく捨てる。
    ///
    /// `ruleset` は検出済みの Landlock ABI（`MIN_LANDLOCK_ABI` 以上）からしか作れないため、ABI 不足の
    /// カーネルでは本関数へ到達する前に `landlock_ruleset_from_config` が起動を拒否する。
    pub fn with_landlock(mut self, ruleset: LandlockRuleset) -> Result<Self, ExecError> {
        let hook_set = self
            .hooks
            .get(StageKind::Landlock.index())
            .is_some_and(Option::is_some);
        if self.landlock.is_some() || hook_set {
            return Err(Self::already_registered(StageKind::Landlock));
        }
        self.landlock = Some(ruleset);
        Ok(self)
    }

    fn already_registered(kind: StageKind) -> ExecError {
        ExecError::new(
            ErrorCode::InvalidArgument,
            IsolationStage::Validate,
            format!("stage hook already registered: {}", kind.as_str()),
        )
    }

    /// rlimit 集合（SUP-12・TASK-169.1・#526）を `Rlimits` 段へ設定する。
    ///
    /// 集合は fork 前に親で検証済みの型（`crate::rlimits::Rlimits`）として作り、fork で子へコピーされて
    /// 子で適用される。実行位置は [`StageKind::ORDER`] により cgroup 参加の後・capability 削減の前で固定。
    /// 2 回目の呼び出しは `InvalidArgument`（`Validate` 段。Landlock の二重登録と同じ扱い）。
    /// 適用失敗は `stage = Rlimits` のエラーで後続段と exec に進まない（fail-closed）。
    pub fn with_rlimits(mut self, set: Rlimits) -> Result<Self, ExecError> {
        if self.rlimits.is_some() {
            return Err(ExecError::new(
                ErrorCode::InvalidArgument,
                IsolationStage::Validate,
                "rlimits already set",
            ));
        }
        self.rlimits = Some(set);
        Ok(self)
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
        if kind == StageKind::Landlock && self.landlock.is_some() {
            return Err(Self::already_registered(kind));
        }
        let slot = self.hooks.get_mut(kind.index()).ok_or_else(|| {
            ExecError::new(
                ErrorCode::Internal,
                IsolationStage::Validate,
                "stage slot out of range",
            )
        })?;
        if slot.is_some() {
            return Err(Self::already_registered(kind));
        }
        *slot = Some(Box::new(hook));
        Ok(self)
    }

    /// `ORDER` の順に各段のフックを実行し、全段成功したときだけ最後に `exec` を呼ぶ。
    ///
    /// 最初の `Err` で打ち切る（後続段と `exec` は呼ばない）。フックの `Err` は `stage` を
    /// その段へ付け替えて返す。`exec` へは [`StageReport`]（証跡ではない）・capability 削減の結果・
    /// 制限適用の証跡 `Result<LaunchReady, LaunchNotReady>`（#1714）を渡す。全段が成功しても Landlock が
    /// `with_landlock` 経由でなければ `Err`（欠けた段つき）で、終端は exec を拒否する。
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
    /// # 破壊的変更と移行方法（SUP-12・TASK-169.1・#526）
    ///
    /// - 変更内容: 公開 enum `StageKind` に variant `Rlimits` が増え、`ORDER` の長さが 5 から 6 になった
    ///   （`StageReport` の段数も同様）。`with_hook(StageKind::Rlimits, …)` は組み込み段のため拒否される。
    /// - 理由: rlimit は capability 削減の前に適用する必要があり（削減後は hard を引き上げられない）、
    ///   no-op フックによる無効化経路も作らない。
    /// - 移行方法: `StageKind` を網羅 match している利用者は `Rlimits` の腕を足す。`ORDER` の長さを
    ///   定数で持っている場合は 6 に更新する。rlimit の指定は `StagePipeline::with_rlimits` を使う。
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
        exec: impl FnOnce(
            &StageReport,
            Option<&CapabilityReport>,
            Result<LaunchReady, LaunchNotReady>,
        ) -> Result<T, ExecError>,
    ) -> Result<T, ExecError> {
        let mut statuses = [StageStatus::Skipped; 6];
        let mut capability_report = None;
        // 証跡は各段の `Ok` の直後（`?` を越えた後）にここでだけ作る。
        let mut rlimits_ev = None;
        let mut capabilities_ev = None;
        let mut no_new_privs_ev = None;
        let mut landlock_ev = None;
        let mut seccomp_ev = None;
        for kind in StageKind::ORDER {
            let idx = kind.index();
            match kind {
                // 組み込み: フック配列のスロットは読まない（差し替えも無効化もできない）。
                StageKind::Rlimits => {
                    // 未設定・空集合なら syscall を呼ばず `Skipped` のまま次の段へ進む。
                    // 組み込み段の処理は完了しているので、証跡は両方の分岐で作る。
                    match self.rlimits.as_ref() {
                        Some(set) if !set.is_empty() => {
                            rlimits::apply_rlimits(set)
                                .map_err(|e| e.at_stage(kind.isolation_stage()))?;
                            rlimits_ev = Some(RlimitsApplied { _private: () });
                        }
                        _ => {
                            rlimits_ev = Some(RlimitsApplied { _private: () });
                            continue;
                        }
                    }
                }
                StageKind::CapabilityDrop => {
                    let r = apply_default_capabilities()
                        .map_err(|e| e.at_stage(kind.isolation_stage()))?;
                    capability_report = Some(r);
                    capabilities_ev = Some(CapabilitiesDropped { _private: () });
                }
                StageKind::NoNewPrivs => {
                    no_new_privs::apply_no_new_privs()
                        .map_err(|e| e.at_stage(kind.isolation_stage()))?;
                    no_new_privs_ev = Some(NoNewPrivsSet { _private: () });
                }
                StageKind::Seccomp => {
                    let _report =
                        apply_default_seccomp().map_err(|e| e.at_stage(kind.isolation_stage()))?;
                    seccomp_ev = Some(SeccompApplied { _private: () });
                }
                StageKind::Landlock => {
                    if let Some(ruleset) = self.landlock.as_ref() {
                        apply_landlock_stage(ruleset)
                            .map_err(|e| e.at_stage(kind.isolation_stage()))?;
                        landlock_ev = Some(LandlockApplied { _private: () });
                    } else if let Some(Some(hook)) = self.hooks.get_mut(idx) {
                        // 独自フックは `Applied` になるが証跡は作らない。
                        hook.apply()
                            .map_err(|e| e.at_stage(kind.isolation_stage()))?;
                    } else {
                        continue;
                    }
                }
                StageKind::CgroupJoin => {
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
        let evidence = bundle_launch_evidence(
            rlimits_ev,
            capabilities_ev,
            no_new_privs_ev,
            landlock_ev,
            seccomp_ev,
        );
        exec(
            &StageReport { statuses },
            capability_report.as_ref(),
            evidence,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::capabilities::testing::fake_capability_drop_err;
    use super::super::no_new_privs::testing::{fake, rec, take};
    use super::super::rlimits::testing::{fake as fake_rlimits, take_sets};
    use super::super::seccomp::testing::fake_seccomp_err;
    use super::*;
    use crate::sys::{self, SysError};

    fn ok_hook(kind: StageKind) -> impl StageHook + 'static {
        move || {
            rec(kind.as_str());
            Ok(())
        }
    }

    fn rlimit_fixture() -> Rlimits {
        use crate::rlimits::{Rlimit, RlimitKind};
        Rlimits::new(vec![Rlimit::new(RlimitKind::Nofile, 256, 512).unwrap()]).unwrap()
    }

    fn exec_ok(
        _: &StageReport,
        _: Option<&CapabilityReport>,
        _: Result<LaunchReady, LaunchNotReady>,
    ) -> Result<(), ExecError> {
        rec("exec");
        Ok(())
    }

    /// 組み込み段を除く全段にダミーフックを登録する（逆順）。
    fn all_hooks_reversed() -> StagePipeline {
        let mut p = StagePipeline::new().with_rlimits(rlimit_fixture()).unwrap();
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
                StageKind::Rlimits,
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
        take_sets();
        let report = all_hooks_reversed()
            .run_then(|r, _, _| {
                rec("exec");
                Ok(r.clone())
            })
            .unwrap();
        assert_eq!(
            take(),
            [
                "cgroup_join",
                "rlimits",
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
            .run_then(|r, _, _| {
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
            .run_then(|r, _, _| {
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
            // Rlimits は組み込みだが、集合が未設定なら何もせず Skipped のまま。
            let expected = if kind.is_builtin() && kind != StageKind::Rlimits {
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
            take_sets();
            // Rlimits 段も走らせるため、非空の集合を常に設定する（記録は "rlimits"）。
            let mut p = StagePipeline::new().with_rlimits(rlimit_fixture()).unwrap();
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
                StageKind::Rlimits => fake_rlimits(Err(SysError::Os(sys::EPERM)), None),
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
                StageKind::Rlimits => "rlimits",
                StageKind::CapabilityDrop => "capability_drop",
                StageKind::NoNewPrivs => "no_new_privs",
                StageKind::Seccomp => "seccomp",
                _ => "fail",
            };
            assert_eq!(calls.last().copied(), Some(last));
            assert!(!calls.contains(&"exec"));
            take_sets();
        }
    }

    /// SUP-12・TASK-169.1: Rlimits は cgroup 参加の後・capability 削減の前に走り、指定値で適用される。
    #[test]
    fn sup12_rlimits_run_after_cgroup_join_and_before_capability_drop() {
        use crate::rlimits::RlimitKind;
        take();
        take_sets();
        let report = StagePipeline::new()
            .with_hook(StageKind::CgroupJoin, ok_hook(StageKind::CgroupJoin))
            .unwrap()
            .with_rlimits(rlimit_fixture())
            .unwrap()
            .run_then(|r, _, _| {
                rec("exec");
                Ok(r.clone())
            })
            .unwrap();
        assert_eq!(
            take(),
            [
                "cgroup_join",
                "rlimits",
                "capability_drop",
                "no_new_privs",
                "seccomp",
                "exec"
            ]
        );
        assert_eq!(take_sets(), [(RlimitKind::Nofile, 256, 512)]);
        assert_eq!(report.status(StageKind::Rlimits), StageStatus::Applied);
    }

    /// SUP-12・TASK-169.1: 未設定・空集合では rlimit の syscall を呼ばず Skipped。
    #[test]
    fn sup12_rlimits_unset_or_empty_is_skipped() {
        take();
        take_sets();
        for p in [
            StagePipeline::new(),
            StagePipeline::new()
                .with_rlimits(Rlimits::new(Vec::new()).unwrap())
                .unwrap(),
        ] {
            let report = p
                .run_then(|r, _, _| {
                    rec("exec");
                    Ok(r.clone())
                })
                .unwrap();
            assert_eq!(report.status(StageKind::Rlimits), StageStatus::Skipped);
            assert_eq!(
                take(),
                ["capability_drop", "no_new_privs", "seccomp", "exec"]
            );
            assert!(take_sets().is_empty());
        }
    }

    /// SUP-12・TASK-169.1: Rlimits は組み込みで、フックでは差し替えられない。二重の `with_rlimits` も拒否。
    #[test]
    fn sup12_rlimits_builtin_and_single_registration() {
        let err = StagePipeline::new()
            .with_hook(StageKind::Rlimits, || Ok(()))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
        assert!(err.message.contains("built-in"), "{}", err.message);
        let err = StagePipeline::new()
            .with_rlimits(rlimit_fixture())
            .unwrap()
            .with_rlimits(rlimit_fixture())
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
        assert_eq!(err.stage, IsolationStage::Validate);
    }

    /// SUP-12・TASK-169.1: rlimit 適用が失敗したら capability 削減以降と exec に進まない（fail-closed）。
    #[test]
    fn sup12_rlimits_failure_blocks_later_stages_and_exec() {
        take();
        take_sets();
        fake_rlimits(Err(SysError::Os(sys::EPERM)), None);
        let err = StagePipeline::new()
            .with_rlimits(rlimit_fixture())
            .unwrap()
            .run_then(exec_ok)
            .unwrap_err();
        assert_eq!(err.stage, IsolationStage::Rlimits);
        assert_eq!(err.code, ErrorCode::PermissionDenied);
        assert_eq!(take(), ["rlimits"]);
        take_sets();
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
            .run_then(|_, caps, _| Ok(caps.map(|c| c.granted)))
            .unwrap();
        assert_eq!(
            granted,
            Some(crate::capabilities::CapabilitySet::oci_default())
        );
        take();
    }

    use super::super::landlock::testing::fake_landlock_err;

    fn ev_of(stages: StagePipeline) -> Result<(Vec<StageKind>, bool), ExecError> {
        stages.run_then(|_, _, ev| match ev {
            Ok(_ready) => Ok((Vec::new(), true)),
            Err(n) => Ok((n.missing().to_vec(), false)),
        })
    }

    /// SEC-1・CORE-5・#1714: 5 つの証跡のうち 1 つでも欠ければ `LaunchReady` は作られず、欠けた段が
    /// `ORDER` 順で具体値として報告される（Landlock 無し・Seccomp 無しを含む）。
    #[test]
    fn sec1_core5_bundle_requires_every_evidence() {
        let r = || Some(RlimitsApplied { _private: () });
        let c = || Some(CapabilitiesDropped { _private: () });
        let n = || Some(NoNewPrivsSet { _private: () });
        let l = || Some(LandlockApplied { _private: () });
        let s = || Some(SeccompApplied { _private: () });
        assert!(bundle_launch_evidence(r(), c(), n(), l(), s()).is_ok());
        let cases = [
            (
                bundle_launch_evidence(None, c(), n(), l(), s()),
                StageKind::Rlimits,
            ),
            (
                bundle_launch_evidence(r(), None, n(), l(), s()),
                StageKind::CapabilityDrop,
            ),
            (
                bundle_launch_evidence(r(), c(), None, l(), s()),
                StageKind::NoNewPrivs,
            ),
            (
                bundle_launch_evidence(r(), c(), n(), None, s()),
                StageKind::Landlock,
            ),
            (
                bundle_launch_evidence(r(), c(), n(), l(), None),
                StageKind::Seccomp,
            ),
        ];
        for (got, missing) in cases {
            let err = got.err().expect("must be not ready");
            assert_eq!(err.missing(), [missing]);
        }
        let all = bundle_launch_evidence(None, None, None, None, None)
            .err()
            .expect("must be not ready");
        assert_eq!(all.missing(), &StageKind::ORDER[1..]);
    }

    /// CORE-5・#1714: Landlock の段を通らないパイプライン（`with_landlock` 無し）では `LaunchReady` が作られない。
    #[test]
    fn core5_pipeline_without_landlock_yields_no_launch_ready() {
        take();
        let (missing, ready) = ev_of(
            StagePipeline::new()
                .with_hook(StageKind::CgroupJoin, ok_hook(StageKind::CgroupJoin))
                .unwrap(),
        )
        .unwrap();
        assert!(!ready);
        assert_eq!(missing, [StageKind::Landlock]);
        take();
        let (missing, ready) = ev_of(StagePipeline::new()).unwrap();
        assert!(!ready);
        assert_eq!(missing, [StageKind::Landlock]);
        assert_eq!(take(), ["capability_drop", "no_new_privs", "seccomp"]);
    }

    /// SEC-1・#1714: 独自の Landlock フックは `Applied` になっても証跡ではない。
    #[test]
    fn sec1_custom_landlock_hook_is_not_evidence() {
        take();
        let p = StagePipeline::new()
            .with_hook(StageKind::Landlock, ok_hook(StageKind::Landlock))
            .unwrap();
        let (missing, ready, status) = p
            .run_then(|r, _, ev| {
                Ok((
                    ev.as_ref().err().map(|n| n.missing().to_vec()),
                    ev.is_ok(),
                    r.status(StageKind::Landlock),
                ))
            })
            .map(|(m, r, st)| (m.unwrap_or_default(), r, st))
            .unwrap();
        assert!(!ready);
        assert_eq!(missing, [StageKind::Landlock]);
        assert_eq!(status, StageStatus::Applied);
        take();
    }

    /// SEC-1・CORE-5・#1714・SUP-12: `with_landlock` を含む全段の成功でだけ `LaunchReady` が作られる。
    /// CgroupJoin の有無・rlimit の有無（未指定は `Skipped` のまま）は条件に入らない。
    #[test]
    fn sec1_core5_full_pipeline_yields_launch_ready() {
        for (with_cgroup, with_rlimit) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            take();
            take_sets();
            let mut p = StagePipeline::new()
                .with_landlock(landlock_fixture())
                .unwrap();
            let mut expected = Vec::new();
            if with_cgroup {
                p = p
                    .with_hook(StageKind::CgroupJoin, ok_hook(StageKind::CgroupJoin))
                    .unwrap();
                expected.push("cgroup_join");
            }
            if with_rlimit {
                p = p.with_rlimits(rlimit_fixture()).unwrap();
                expected.push("rlimits");
            }
            expected.extend([
                "capability_drop",
                "no_new_privs",
                "landlock",
                "seccomp",
                "exec",
            ]);
            let rlimits_status = p
                .run_then(|r, _, ev| {
                    rec("exec");
                    assert!(ev.is_ok());
                    Ok(r.status(StageKind::Rlimits))
                })
                .unwrap();
            assert_eq!(take(), expected);
            assert_eq!(
                rlimits_status,
                if with_rlimit {
                    StageStatus::Applied
                } else {
                    StageStatus::Skipped
                }
            );
            take_sets();
        }
    }

    /// SEC-1・CORE-5・#1714（fail-closed）: どの組み込み段・Landlock が失敗しても終端は呼ばれず、
    /// `LaunchReady` は作られない。エラーの段と code は失敗した段のまま。
    #[test]
    fn sec1_stage_failure_never_reaches_launch_ready() {
        let boom = |code| ExecError::new(code, IsolationStage::Validate, "boom");
        for failing in [
            StageKind::Rlimits,
            StageKind::CapabilityDrop,
            StageKind::NoNewPrivs,
            StageKind::Landlock,
            StageKind::Seccomp,
        ] {
            take();
            take_sets();
            let code = match failing {
                StageKind::Landlock | StageKind::Seccomp => ErrorCode::FailedPrecondition,
                _ => ErrorCode::PermissionDenied,
            };
            match failing {
                StageKind::Rlimits => fake_rlimits(Err(SysError::Os(sys::EPERM)), None),
                StageKind::CapabilityDrop => fake_capability_drop_err(SysError::Os(sys::EPERM)),
                StageKind::NoNewPrivs => fake(Err(SysError::Os(sys::EPERM)), Ok(true)),
                StageKind::Landlock => fake_landlock_err(boom(code)),
                _ => fake_seccomp_err(boom(code)),
            }
            let err = StagePipeline::new()
                .with_rlimits(rlimit_fixture())
                .unwrap()
                .with_landlock(landlock_fixture())
                .unwrap()
                .run_then(exec_ok)
                .unwrap_err();
            assert_eq!(err.stage, failing.isolation_stage(), "{}", failing.as_str());
            assert_eq!(err.code, code, "{}", failing.as_str());
            assert!(!take().contains(&"exec"), "{}", failing.as_str());
            take_sets();
        }
    }
}
