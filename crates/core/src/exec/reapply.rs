//! exec プロセスへの seccomp / Landlock 再適用（SUP-6・TASK-163.3・#502・CORE-5・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! SUP-6 の exec は「pid1 の namespace へ `setns` → cgroup join → seccomp / Landlock 再適用 → コマンド実行」。
//! `setns` と cgroup join だけを済ませたプロセスは、コンテナ本体（launch 経路のステージ列
//! `NoNewPrivs → Landlock → Seccomp`。`exec/stages.rs`）より弱い制限で動いてしまう。本モジュールは
//! 3 段目の再適用を担い、`fandhe-container-supervisor` の `exec`（`prepare_restrictions` /
//! `reapply_restrictions`）が薄く配線する。#503（TASK-163.4）の exec 専用プロセスが呼ぶ想定。
//!
//! # 契約
//!
//! - 二段階 API（`exec/cgroup_join.rs` の `prepare_cgroup_join` / `join_cgroup` と同型）:
//!   [`prepare_exec_restrictions`] は **`join_namespaces` の前**、[`reapply_restrictions`] は
//!   `join_namespaces` と `join_cgroup` の **後** に呼ぶ。seccomp の既定フィルタは `setns` を拒否するため、
//!   再適用を `setns` の前に置くと namespace 参加が失敗する（cgroup join を seccomp の前に置く既存の順序と一致）。
//!   [`reapply_restrictions`] の内部は「準備したプロセスの確認 → 参加後の `/` の照合 → 適用」の順で、
//!   確認・照合で拒否したときは何も適用していない
//! - 全体の順序（#503 が守る。exec 専用プロセス内）: `identify_pid1` → `prepare_cgroup_join` →
//!   [`prepare_exec_restrictions`] → `join_namespaces` → `join_cgroup` → [`reapply_restrictions`] →
//!   （#503: fork → `close_range` → execve）。制限（`NO_NEW_PRIVS`・Landlock・seccomp）は fork / execve を
//!   越えて継承されるため、#503 は「適用 → fork → execve」の順にする
//! - 内部の適用順は `PR_SET_NO_NEW_PRIVS` → Landlock → seccomp で固定（`StageKind::ORDER` の相対順と同じ）。
//!   最初の失敗で打ち切り、後続は呼ばない。エラーの `stage` は `NoNewPrivs` / `Landlock` / `Seccomp`
//!   （適用前の拒否は、準備したプロセスの不一致が `Validate`、参加後の `/` の不一致が `SetNs`）
//! - **準備したプロセス自身が適用する**: 保持する `/proc/self/status` の fd は開いたプロセスの情報を返す。
//!   `setns(CLONE_NEWNS)` の後は `/proc` がコンテナ側の procfs になり自プロセスを `/proc/self` で解決できない
//!   ため、事前に開いた fd で適用前後の `Threads: 1` 検査（seccomp・Landlock の既存検査）を行う。fork した
//!   子から使うと親のスレッド数を読むため、準備時の pid を記録し、不一致なら何も適用せず
//!   `FailedPrecondition` にする（best-effort の誤用検知。PID namespace をまたぐ数値衝突は検知できない）
//! - **単一スレッド専用・不可逆**: logs 捕捉スレッドを持つ supervisor 本体からは呼ばない。失敗時は制限が
//!   部分的に載った不定状態のため、呼び出し側は続行せず終了する（巻き戻し不可。`join_cgroup` と同じ）
//! - **fail-closed**: Landlock 未対応カーネル・ルール生成失敗は準備段階で `stage = Landlock` として拒否し、
//!   Landlock 無しで続行する経路を作らない（CORE-5）。値を消費するため二重適用・fd の残留を型で防ぐ
//! - **参加後の `/` をコンテナの rootfs と照合してから適用する（SEC-1）**: `setns(CLONE_NEWNS)` は呼び出し
//!   プロセスの root と cwd を **参加先 mount namespace のルート**（`mnt_ns->root` に積まれた最上位のマウント）へ
//!   付け替える（カーネルの `fs/namespace.c` `mntns_install` が `set_fs_root` / `set_fs_pwd` を呼ぶ。pidfd で複数
//!   namespace を一括指定した場合も `kernel/nsproxy.c` の `commit_nsset` が同じ root / cwd を反映する。`setns(2)` の
//!   man page には記載が無いカーネルの挙動）。したがって参加後の `/` はホストの `/` ではないが、それが
//!   「コンテナの rootfs」であることは launcher が `pivot_root` 済み（`exec/rootfs.rs`）で、以後 `/` へ別の
//!   マウントが重ねられていないという前提に依存する。この前提を仮定で済ませず、[`prepare_exec_restrictions`] が
//!   `setns` の前に固定した rootfs（start と同じ検査・固定を通した `RootfsDir`。ホスト側の記録が起点で、
//!   コンテナからは変えられない）と、[`reapply_restrictions`] が参加後に開いた `/` が **同じディレクトリ
//!   （`st_dev`・`st_ino` の一致）** であることを、何も適用する前に確かめる。不一致は違反記録
//!   `exec_root_not_container_rootfs` つきの `FailedPrecondition` で拒否する（pivot していない対象・`/` へ
//!   マウントを重ねた対象では、ルールが別の木に付くうえコマンドも rootfs の外で動くため）。固定した fd は
//!   適用が終わるまで保持する（inode 番号の再利用で一致が偽にならないようにする）
//! - **照合の基準に pid1 の root（`/proc/<pid>/root`）を使わない**: pid1 の root はコンテナ側が変えられる
//!   （OCI 既定の capability には `CAP_SYS_CHROOT` が含まれ、pid1 は自分を `chroot` できる）。基準はホスト側で
//!   固定した rootfs にする。pid1 が自分を `chroot` していても、exec は mount namespace のルート = rootfs へ入る
//! - **ルールパスは照合済みの `/` の fd を起点に、`setns` の後に解決する**: 準備段階の ruleset が持つのは
//!   config の mount destination（コンテナ内パス。`RulePath`。`..` を含まない正規化済み）の文字列だけで、
//!   準備ではルールのパスを開かない（`setns` 前に開くとホスト側の木を指すため）。`landlock_add_rule` 用の
//!   `O_PATH` fd は [`reapply_restrictions`] の中で、照合に使ったのと同じ `/` の fd から 1 要素ずつ
//!   `O_NOFOLLOW` で開く。symlink はまたがず、解決できないパスは拒否し、ルールを黙って落とさない。launch 経路
//!   （`StagePipeline::with_landlock`。pivot 後の `/` 起点）と同じ関数・同じ規則で辿る
//! - ルールは launcher が実際にマウントした結果ではなく `config.json` から再導出する（launch 時の ruleset は
//!   保存されていない）。Landlock の適用は存在しない・開けないルールパスを拒否するため、config の mount
//!   destination が稼働中の rootfs に無ければ [`reapply_restrictions`] は失敗し exec は拒否される
//!   （fail-closed として正しい挙動）。bundle は supervisor と同じ信頼境界（コンテナから書けない）にある前提
//! - **再適用だけでは exec してよい状態にならない**: 本モジュールが載せるのは `NO_NEW_PRIVS`・Landlock・
//!   seccomp の 3 つだけで、launch 経路が同じ位置で行う rlimit 適用と capability 削減（`StageKind::ORDER` の
//!   `Rlimits`・`CapabilityDrop`）は行わない。`setns` は資格情報を変えないため、rootful の exec では成功後も
//!   全 capability を持つ。[`ExecRestrictionReport::unapplied`] が未適用の制限を列挙し、
//!   [`ExecRestrictionReport::is_complete`] は未適用が残る間 `false` を返す。呼び出し側（#503）は成功を
//!   「制限の再適用が完了した」と扱わず、未適用が空になるまで `execve` しないこと
//! - エラーメッセージ・`Debug` 出力にホスト側パス・ルール内容を載せない
//!
//! # 未実装（REPAIR-3）
//!
//! - fork・execve・`close_range`・`setns` を伴う通し試験は #503（TASK-163.4）。**`setns` の後に保持 fd から
//!   スレッド数が実際に読めること** の実機確認もそこで行う（本モジュールのテストは `setns` をしない）
//! - user namespace への参加、exec プロセスの capability 削減・rlimit 適用は未実装（後 2 つは
//!   [`UnappliedExecRestriction`] として成功結果に載る。TASK-163 の内容は seccomp / Landlock のみで、exec での
//!   扱いは spec〔SUP-6〕の確認事項）
//! - 本番 launcher（`oci_runtime` の `ProcessLauncher` 実装）は未結線で、launch 経路の Landlock も本番では
//!   まだ適用されない（`exec/landlock.rs`）。exec と launch の一致は「同じ `config.json` から同じ関数で導いた
//!   ルールを、同じ rootfs のディレクトリを起点に同じ規則で辿る」ことで担保し、実コンテナでの突き合わせは #503
//! - 拒否の監査ログ保存の配線（#839・SEC-4）

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use super::landlock::{LandlockAccessProbe, landlock_ruleset_from_config, run_probe};
use super::{ExecError, IsolationStage, ThreadCountSource, ViolationReason, no_new_privs};
use crate::landlock::LandlockRuleset;
use crate::oci_runtime::{OciConfig, RootfsDir};
use crate::sys;
use crate::traits::types::ErrorCode;

// テストでは本物（`Threads: 1` と実 syscall を要する）の代わりに偽物へ差し替える（`stages.rs` と同じ）。
#[cfg(not(test))]
use super::landlock::apply_landlock_stage_with;
#[cfg(test)]
use super::landlock::testing::apply_landlock_stage_with;
#[cfg(not(test))]
use super::seccomp::apply_default_seccomp_with;
#[cfg(test)]
use super::seccomp::testing::apply_default_seccomp_with;

/// [`prepare_exec_restrictions`] が `setns` の前に確保した再適用の材料一式。[`reapply_restrictions`] が消費する。
#[must_use = "prepared restrictions do nothing until passed to reapply_restrictions"]
pub struct ExecRestrictions {
    landlock: LandlockRuleset,
    threads: ThreadCountSource,
    owner_pid: u32,
    /// `setns` の前にホスト側で固定したコンテナの rootfs（`O_PATH`）。参加後の `/` と照合する基準。
    /// 適用が終わるまで保持し、inode 番号が再利用されないようにする。
    rootfs: OwnedFd,
}

impl std::fmt::Debug for ExecRestrictions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // fd・ルール内容は出さない。
        f.debug_struct("ExecRestrictions")
            .field("owner_pid", &self.owner_pid)
            .finish_non_exhaustive()
    }
}

/// launch 経路は適用するが、exec の再適用（本モジュール）は **適用しない** 制限（SUP-6・SEC-1・REPAIR-3）。
///
/// [`ExecRestrictionReport::unapplied`] に載る。実装されたものから列挙を外す。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnappliedExecRestriction {
    /// capability 削減（launch 経路の `StageKind::CapabilityDrop`。SEC-1）。`setns` は資格情報を変えないため、
    /// rootful の exec プロセスは再適用の後も全 capability を持つ。
    CapabilityDrop,
    /// rlimit 適用（launch 経路の `StageKind::Rlimits`。SUP-12）。
    Rlimits,
}

/// [`reapply_restrictions`] の成功結果（将来拡張できる構造。制限適用の証跡ではない。REPAIR-3）。
///
/// 成功は「`NO_NEW_PRIVS`・Landlock・seccomp を載せた」ことだけを表す。**exec してよい状態になったことは
/// 表さない**: [`unapplied`](Self::unapplied) に未適用の制限が残る間（[`is_complete`](Self::is_complete) が
/// `false` の間）は、呼び出し側は `execve` へ進まないこと。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use = "a successful reapply does not make the process ready to exec; check `unapplied`"]
pub struct ExecRestrictionReport {
    /// 追加した Landlock ルール数。
    pub landlock_rules: usize,
    /// 適用した seccomp の BPF 命令数。
    pub seccomp_instructions: usize,
    /// launch 経路は適用するが、この再適用では適用していない制限（[`ExecRestrictionReport::UNAPPLIED`]）。
    pub unapplied: &'static [UnappliedExecRestriction],
}

impl ExecRestrictionReport {
    /// 現在の実装が適用しない制限の一覧（唯一の定義元）。
    pub const UNAPPLIED: &'static [UnappliedExecRestriction] = &[
        UnappliedExecRestriction::CapabilityDrop,
        UnappliedExecRestriction::Rlimits,
    ];

    /// launch 経路と同じ制限がすべて載ったか（未適用が残る間は `false`。現在の実装では常に `false`）。
    pub fn is_complete(&self) -> bool {
        self.unapplied.is_empty()
    }
}

/// `config`（コンテナの `config.json`）から Landlock ruleset を作り、参加後の `/` と照合する rootfs と
/// 自プロセスの status fd を確保する。
///
/// `join_namespaces` の **前** に、再適用を行うプロセス自身が呼ぶ。`rootfs` は稼働中コンテナの bundle から
/// `oci_runtime::pin_bundle_rootfs` で固定したもの（`config` と同じ bundle のもの）を渡す。ABI 検出・ルール
/// 生成の失敗（Landlock 未対応カーネルを含む）は `stage = Landlock` で拒否する（fail-closed。CORE-5）。
/// `rootfs` が呼び出しプロセス自身の `/` と同じディレクトリなら、参加後の照合が意味を持たないため
/// 違反記録 `rootfs_is_host_root` つきで拒否する（SEC-1）。
pub fn prepare_exec_restrictions(
    config: &OciConfig,
    rootfs: &RootfsDir,
) -> Result<ExecRestrictions, ExecError> {
    let rootfs = rootfs.as_fd().try_clone_to_owned().map_err(|e| {
        ExecError::from_io(&e, IsolationStage::Validate, "duplicate the rootfs handle")
    })?;
    prepare_distinct_from_own_root(config, rootfs)
}

/// `rootfs` が呼び出しプロセス自身の `/` と別のディレクトリであることを確かめてから準備する
/// （[`prepare_exec_restrictions`] の本体。Landlock の検出より先に判定する）。
fn prepare_distinct_from_own_root(
    config: &OciConfig,
    rootfs: OwnedFd,
) -> Result<ExecRestrictions, ExecError> {
    let own_root = sys::open_dir_path_nofollow(None, c"/")
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Validate, "open own root"))?;
    let is_own_root = same_directory(rootfs.as_fd(), own_root.as_fd())
        .map_err(|e| e.at_stage(IsolationStage::Validate))?;
    if is_own_root {
        return Err(ExecError::from_violation_at(
            ViolationReason::RootfsIsHostRoot,
            None,
            IsolationStage::Validate,
        ));
    }
    prepare_with_rootfs(config, rootfs)
}

/// [`prepare_exec_restrictions`] の本体（`rootfs` が自分の `/` でないことの検査を除く）。
/// 結合試験用の観測関数は `setns` をしないため、自分の `/` を基準にしてここから入る。
fn prepare_with_rootfs(config: &OciConfig, rootfs: OwnedFd) -> Result<ExecRestrictions, ExecError> {
    let landlock = landlock_ruleset_from_config(config)?;
    let status_error =
        |what: &'static str| ExecError::new(ErrorCode::Internal, IsolationStage::Landlock, what);
    let file = std::fs::File::open("/proc/self/status")
        .map_err(|_| status_error("failed to open /proc/self/status"))?;
    // スレッド数の取得元が本物の procfs であることを確かめる（`/proc` に別の FS が載った環境で、
    // 固定の内容を読んで単一スレッドと誤認しない。fail-closed）。
    if sys::fs_type(file.as_fd()) != Ok(sys::PROC_MAGIC) {
        return Err(status_error("/proc/self/status is not on procfs"));
    }
    Ok(ExecRestrictions {
        landlock,
        threads: ThreadCountSource::PreOpened(file),
        owner_pid: std::process::id(),
        rootfs,
    })
}

/// 2 つの fd が同じディレクトリ（`st_dev`・`st_ino` が一致）を指すか。どちらかがディレクトリでない・
/// 調べられない場合はエラー（段 `SetNs`。一致とも不一致とも扱わない）。
fn same_directory(a: BorrowedFd<'_>, b: BorrowedFd<'_>) -> Result<bool, ExecError> {
    let identity = |fd: BorrowedFd<'_>| -> Option<(u64, u64)> {
        // `O_PATH` の fd への fstat（パスを再解決しない）。複製は同じ open file description を指す。
        let meta = std::fs::File::from(fd.try_clone_to_owned().ok()?)
            .metadata()
            .ok()?;
        meta.is_dir().then(|| (meta.dev(), meta.ino()))
    };
    match (identity(a), identity(b)) {
        (Some(a), Some(b)) => Ok(a == b),
        _ => Err(ExecError::new(
            ErrorCode::Internal,
            IsolationStage::SetNs,
            "failed to inspect the root directory",
        )),
    }
}

/// 参加後の呼び出しプロセスの `/` を開き、`rootfs`（`setns` の前に固定したコンテナの rootfs）と同じ
/// ディレクトリであることを確かめて返す（SEC-1）。不一致は違反記録 `exec_root_not_container_rootfs`。
///
/// 返す fd は Landlock のルールパスを辿る起点に使う（照合した実体と起点を同じ fd にする）。
fn open_verified_root(rootfs: BorrowedFd<'_>) -> Result<OwnedFd, ExecError> {
    let root = sys::open_dir_path_nofollow(None, c"/")
        .map_err(|e| ExecError::from_sys(e, IsolationStage::SetNs, "open / after joining"))?;
    if !same_directory(rootfs, root.as_fd())? {
        return Err(ExecError::from_violation(
            ViolationReason::ExecRootNotContainerRootfs,
            None,
        ));
    }
    Ok(root)
}

/// `NO_NEW_PRIVS` → Landlock → seccomp を呼び出しプロセスへ不可逆に適用する。
///
/// `join_namespaces` と `join_cgroup` の **後**、準備したプロセス自身から単一スレッドで呼ぶ。
/// 適用の前に、参加後の `/` が準備時に固定したコンテナの rootfs であることを照合し、不一致なら何も適用せず
/// 拒否する（違反記録つき。SEC-1）。Landlock のルールパスは照合済みの `/` を起点に辿る。
/// 最初の失敗で打ち切る。失敗後の制限は部分的に載った不定状態のため、呼び出し側は続行せず終了すること。
///
/// 成功しても capability 削減と rlimit 適用は行われていない（[`ExecRestrictionReport::unapplied`]）。
/// 戻り値を確認せずに `execve` へ進まないこと。
pub fn reapply_restrictions(
    restrictions: ExecRestrictions,
) -> Result<ExecRestrictionReport, ExecError> {
    let ExecRestrictions {
        landlock,
        mut threads,
        owner_pid,
        rootfs,
    } = restrictions;
    if owner_pid != std::process::id() {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::Validate,
            "restrictions must be reapplied by the process that prepared them",
        ));
    }
    let root = open_verified_root(rootfs.as_fd())?;
    no_new_privs::apply_no_new_privs()?;
    let landlock = apply_landlock_stage_with(&landlock, &mut threads, root.as_fd())
        .map_err(|e| e.at_stage(IsolationStage::Landlock))?;
    let seccomp = apply_default_seccomp_with(&mut threads)
        .map_err(|e| e.at_stage(IsolationStage::Seccomp))?;
    Ok(ExecRestrictionReport {
        landlock_rules: landlock.rules_added,
        seccomp_instructions: seccomp.instructions,
        unapplied: ExecRestrictionReport::UNAPPLIED,
    })
}

/// [`observe_exec_restriction_reapply`] の観測結果。errno は成功を `None`、失敗を `Some(errno)`（不明は `-1`）。
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecReapplyObservation {
    /// 準備（ABI 検出・ルール生成）の失敗。`Some` なら適用もプローブもしていない（fail-closed）。
    pub prepare_error: Option<ExecError>,
    /// 再適用の失敗。`Some` ならプローブはしていない（exec 拒否に相当）。
    pub reapply_error: Option<ExecError>,
    /// 再適用の成功結果。
    pub report: Option<ExecRestrictionReport>,
    /// 適用前の `/proc/thread-self/status` の `Seccomp:` 値（無制限は `0`）。
    pub seccomp_before: String,
    /// 適用前の `NoNewPrivs:` 値（準備失敗時に「変わっていない」ことを照合する基準）。
    pub no_new_privs_before: String,
    /// 試行後の `Seccomp:` 値（適用に成功すれば filter モードの `2`）。
    pub seccomp_after: String,
    /// 試行後の `NoNewPrivs:` 値（適用に成功すれば `1`）。
    pub no_new_privs_after: String,
    /// 適用前の `unshare(0)`（対照。フラグなしのため通常は成功し `None`）。
    pub unshare_before: Option<i32>,
    /// 適用後の `unshare(0)`（禁止 syscall のため `EPERM`）。適用に失敗した場合は `None`。
    pub unshare_after: Option<i32>,
    /// Landlock プローブ結果（入力順）。再適用に成功した場合のみ入る。
    pub results: Vec<(LandlockAccessProbe, Option<i32>)>,
}

/// 観測 1 回で試せるプローブ数の上限（`exec/landlock.rs` と同じ固定リスト前提の防御）。
const MAX_REAPPLY_PROBES: usize = 32;

/// 本番の準備・再適用の経路をそのまま通し、seccomp と Landlock の遮断を観測する
/// （SUP-6・TASK-163.3・#502・CORE-5。結合試験専用）。
///
/// 結合試験 `tests/exec_restrictions_reapply.rs` の使い捨て子プロセス（単一スレッドの `main`）専用で、
/// 通常の利用者は呼ばない。`setns` は行わないため、「コンテナの rootfs」の代わりに呼び出し側が渡す
/// `expected_root`（ディレクトリ）を照合の基準にする: `/` を渡せば照合が通り、Landlock のルールパスは
/// 呼び出しプロセスの `/` に対して解決される。`/` 以外を渡せば、参加後の `/` が rootfs でない場合と同じ
/// 拒否（違反記録 `exec_root_not_container_rootfs`。何も適用しない）を観測できる。本番の入口
/// [`prepare_exec_restrictions`] が行う「rootfs が自分の `/` でないこと」の検査だけは通さない。
/// 準備・再適用のいずれかが失敗したらプローブは実行しない。`unsafe` は追加せず、syscall は既存の
/// `crate::sys` ラッパーに限る。
///
/// # 将来仕様（記録のみ）
///
/// `setns` を伴う通し確認は #503（TASK-163.4）の統合テストで行う（REPAIR-3）。
#[doc(hidden)]
pub fn observe_exec_restriction_reapply(
    config: &OciConfig,
    expected_root: &Path,
    probes: &[LandlockAccessProbe],
) -> Result<ExecReapplyObservation, ExecError> {
    let internal = |m: &str| ExecError::new(ErrorCode::Internal, IsolationStage::Validate, m);
    if probes.len() > MAX_REAPPLY_PROBES {
        return Err(ExecError::new(
            ErrorCode::InvalidArgument,
            IsolationStage::Landlock,
            "too many access probes",
        ));
    }
    let seccomp_before = status_field("Seccomp:").ok_or_else(|| internal("Seccomp missing"))?;
    let no_new_privs_before =
        status_field("NoNewPrivs:").ok_or_else(|| internal("NoNewPrivs missing"))?;
    let unshare_before = errno_of(sys::unshare_namespaces(&[]));
    let mut obs = ExecReapplyObservation {
        prepare_error: None,
        reapply_error: None,
        report: None,
        seccomp_before,
        no_new_privs_before,
        seccomp_after: String::new(),
        no_new_privs_after: String::new(),
        unshare_before,
        unshare_after: None,
        results: Vec::new(),
    };
    let expected = OwnedFd::from(
        std::fs::File::open(expected_root).map_err(|_| internal("cannot open expected root"))?,
    );
    match prepare_with_rootfs(config, expected) {
        Err(e) => obs.prepare_error = Some(e),
        Ok(prepared) => match reapply_restrictions(prepared) {
            Ok(report) => obs.report = Some(report),
            Err(e) => obs.reapply_error = Some(e),
        },
    }
    obs.seccomp_after = status_field("Seccomp:").ok_or_else(|| internal("Seccomp missing"))?;
    obs.no_new_privs_after =
        status_field("NoNewPrivs:").ok_or_else(|| internal("NoNewPrivs missing"))?;
    if obs.report.is_some() {
        obs.unshare_after = errno_of(sys::unshare_namespaces(&[]));
        for p in probes {
            obs.results.push((p.clone(), run_probe(p)));
        }
    }
    Ok(obs)
}

fn errno_of(r: Result<(), sys::SysError>) -> Option<i32> {
    match r {
        Ok(()) => None,
        Err(sys::SysError::Os(n)) => Some(n),
        Err(_) => Some(-1),
    }
}

/// `/proc/thread-self/status` の指定フィールド値（前後の空白は除く）。
fn status_field(name: &str) -> Option<String> {
    let status = std::fs::read_to_string("/proc/thread-self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix(name))
        .map(|v| v.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::no_new_privs::testing::{fake, take};
    use crate::sys::SysError;

    fn dir_fd(path: &Path) -> OwnedFd {
        OwnedFd::from(std::fs::File::open(path).expect("open dir"))
    }

    /// 照合の基準を自プロセスの `/` にした材料（単体テストは `setns` をしないため照合が通る）。
    fn restrictions(owner_pid: u32) -> ExecRestrictions {
        restrictions_rooted_at(owner_pid, Path::new("/"))
    }

    fn restrictions_rooted_at(owner_pid: u32, rootfs: &Path) -> ExecRestrictions {
        ExecRestrictions {
            landlock: LandlockRuleset::for_observation(6, Vec::new()),
            threads: ThreadCountSource::ProcSelf,
            owner_pid,
            rootfs: dir_fd(rootfs),
        }
    }

    /// 使い捨ての空ディレクトリ（`/` とは別の inode）。
    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fandhe-reapply-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn err(code: ErrorCode, stage: IsolationStage) -> ExecError {
        ExecError::new(code, stage, "fake")
    }

    /// SUP-6・TASK-163.3: 適用順は NO_NEW_PRIVS → Landlock → seccomp で固定。
    #[test]
    fn sup6_task163_3_reapply_order_is_nnp_landlock_seccomp() {
        let _ = take();
        let report = reapply_restrictions(restrictions(std::process::id())).expect("ok");
        assert_eq!(take(), vec!["no_new_privs", "landlock", "seccomp"]);
        assert_eq!(
            report,
            ExecRestrictionReport {
                landlock_rules: 0,
                seccomp_instructions: 0,
                unapplied: &[
                    UnappliedExecRestriction::CapabilityDrop,
                    UnappliedExecRestriction::Rlimits,
                ],
            }
        );
        // SEC-1: 再適用の成功は「exec してよい」を意味しない（capability 削減・rlimit が未適用）。
        assert!(!report.is_complete());
    }

    /// SUP-6・SEC-1・SEC-4・TASK-163.3: 参加後の `/` が準備時に固定した rootfs と別のディレクトリなら、
    /// 何も適用せず違反記録つきの `FailedPrecondition`（理由 `exec_root_not_container_rootfs`・段 `SetNs`）。
    #[test]
    fn sup6_task163_3_root_mismatch_applies_nothing_and_records_violation() {
        let _ = take();
        let dir = temp_dir("mismatch");
        let e = reapply_restrictions(restrictions_rooted_at(std::process::id(), &dir))
            .expect_err("root mismatch");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.stage, IsolationStage::SetNs);
        assert_eq!(
            e.message,
            "the root directory after joining is not the recorded container rootfs"
        );
        let v = e.violation.expect("violation recorded");
        assert_eq!(v.reason, ViolationReason::ExecRootNotContainerRootfs);
        assert_eq!(v.reason.as_str(), "exec_root_not_container_rootfs");
        assert_eq!(v.kind.as_str(), "exec_target");
        assert_eq!(v.behavior_id, "SEC-1");
        assert_eq!(take(), Vec::<&str>::new());
    }

    /// SUP-6・SEC-1・TASK-163.3: 準備したプロセスの確認は root の照合より先（別プロセスからは root が
    /// 一致しなくても違反記録を付けず `Validate` 段で拒否する）。
    #[test]
    fn sup6_task163_3_owner_check_precedes_root_check() {
        let _ = take();
        let dir = temp_dir("owner-first");
        let other = std::process::id().wrapping_add(1);
        let e = reapply_restrictions(restrictions_rooted_at(other, &dir)).expect_err("mismatch");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(e.stage, IsolationStage::Validate);
        assert!(e.violation.is_none());
        assert_eq!(take(), Vec::<&str>::new());
    }

    /// SUP-6・SEC-1・TASK-163.3: ディレクトリの同一性は `st_dev`・`st_ino` で決まる。同じディレクトリを別々に
    /// 開いた fd は一致し、別のディレクトリ・親子は一致しない。ディレクトリでない fd は判定せずエラー。
    #[test]
    fn sup6_task163_3_same_directory_compares_dev_and_ino() {
        let dir = temp_dir("same");
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).expect("sub");
        std::fs::write(dir.join("file"), b"x").expect("file");
        let (a, b, c) = (dir_fd(&dir), dir_fd(&dir), dir_fd(&sub));
        let file = dir_fd(&dir.join("file"));
        assert_eq!(same_directory(a.as_fd(), b.as_fd()).ok(), Some(true));
        assert_eq!(same_directory(a.as_fd(), c.as_fd()).ok(), Some(false));
        assert_eq!(same_directory(c.as_fd(), a.as_fd()).ok(), Some(false));
        let e = same_directory(a.as_fd(), file.as_fd()).expect_err("not a directory");
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::SetNs);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SUP-6・SEC-1・SEC-4・TASK-163.3: 固定した rootfs が自プロセスの `/` と同じディレクトリなら、準備が
    /// 違反記録 `rootfs_is_host_root` つきの `InvalidArgument`（段 `Validate`）で拒否する（参加後の照合が
    /// 意味を持たないため）。Landlock の検出より先に判定するので、カーネル版数に依存しない。
    #[test]
    fn sup6_task163_3_prepare_rejects_rootfs_equal_to_own_root() {
        let c = config(true, "[]");
        let e = prepare_distinct_from_own_root(&c, dir_fd(Path::new("/"))).expect_err("own root");
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.stage, IsolationStage::Validate);
        assert_eq!(e.message, "rootfs must not be the host root '/'");
        let v = e.violation.expect("violation recorded");
        assert_eq!(v.reason.as_str(), "rootfs_is_host_root");
    }

    /// SUP-6・TASK-163.3: NO_NEW_PRIVS の失敗で Landlock・seccomp を呼ばない（段は NoNewPrivs）。
    #[test]
    fn sup6_task163_3_nnp_failure_stops_before_landlock() {
        let _ = take();
        fake(Err(SysError::Os(1)), Ok(true));
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("nnp fails");
        assert_eq!(e.stage, IsolationStage::NoNewPrivs);
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(take(), vec!["no_new_privs"]);
    }

    /// SUP-6・TASK-163.3: Landlock の失敗で seccomp を呼ばない（段と code を保つ）。
    #[test]
    fn sup6_task163_3_landlock_failure_stops_before_seccomp() {
        let _ = take();
        crate::exec::landlock::testing::fake_landlock_err(err(
            ErrorCode::FailedPrecondition,
            IsolationStage::Seccomp,
        ));
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("landlock");
        assert_eq!(e.stage, IsolationStage::Landlock);
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(take(), vec!["no_new_privs", "landlock"]);
    }

    /// SUP-6・TASK-163.3: seccomp の失敗は段 Seccomp・code を保って返る（Landlock までは適用済み）。
    #[test]
    fn sup6_task163_3_seccomp_failure_reports_seccomp_stage() {
        let _ = take();
        crate::exec::seccomp::testing::fake_seccomp_err(err(
            ErrorCode::Internal,
            IsolationStage::Landlock,
        ));
        let e = reapply_restrictions(restrictions(std::process::id())).expect_err("seccomp");
        assert_eq!(e.stage, IsolationStage::Seccomp);
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(take(), vec!["no_new_privs", "landlock", "seccomp"]);
    }

    /// SUP-6・TASK-163.3: 準備したのと別のプロセスからは何も適用せず FailedPrecondition。
    #[test]
    fn sup6_task163_3_owner_pid_mismatch_applies_nothing() {
        let _ = take();
        let other = std::process::id().wrapping_add(1);
        let e = reapply_restrictions(restrictions(other)).expect_err("mismatch");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            e.message,
            "restrictions must be reapplied by the process that prepared them"
        );
        assert_eq!(take(), Vec::<&str>::new());
    }

    /// SUP-6・TASK-163.3: `Debug` は fd・ルール内容を出さず、pid だけを示す。
    #[test]
    fn sup6_task163_3_debug_hides_internals() {
        let text = format!("{:?}", restrictions(42));
        assert_eq!(text, "ExecRestrictions { owner_pid: 42, .. }");
    }

    /// `config` の `root.path`（`rootfs`）を持つ使い捨ての bundle を作り、start と同じ経路で rootfs を固定する。
    fn pinned_rootfs(label: &str, config: &OciConfig) -> (std::path::PathBuf, RootfsDir) {
        let base = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp dir");
        let bundle = base.join(
            temp_dir(label)
                .file_name()
                .expect("temp dir has a file name"),
        );
        std::fs::create_dir(bundle.join("rootfs")).expect("rootfs");
        let rootfs = crate::oci_runtime::pin_bundle_rootfs(&bundle, config).expect("pin rootfs");
        (bundle, rootfs)
    }

    fn config(readonly: bool, mounts: &str) -> OciConfig {
        let json = format!(
            r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs","readonly":{readonly}}},"mounts":{mounts}}}"#
        );
        crate::oci_runtime::parse_config_bytes(json.as_bytes()).expect("config")
    }

    /// SUP-6・TASK-163.3・CORE-5: 書き込み制限が祖先ルールで無効になる構成は、準備が `stage = Landlock` で
    /// 拒否する。ABI 検出が通らない環境では検出失敗で拒否される（どちらも fail-closed で成功しない）。
    #[test]
    fn sup6_task163_3_prepare_rejects_shadowed_write_restriction() {
        let c = config(false, r#"[{"destination":"/etc","options":["ro"]}]"#);
        let (bundle, rootfs) = pinned_rootfs("shadowed", &c);
        let e = prepare_exec_restrictions(&c, &rootfs).expect_err("must be rejected");
        let _ = std::fs::remove_dir_all(&bundle);
        assert_eq!(e.stage, IsolationStage::Landlock);
        const DETECT: [&str; 6] = [
            "kernel_lacks_landlock",
            "landlock_disabled_at_boot",
            "landlock_abi_too_old",
            "invalid_kernel_response",
            "unsupported_architecture",
            "landlock_probe_failed",
        ];
        if e.message.starts_with("write_restriction_shadowed:") {
            assert_eq!(e.code, ErrorCode::InvalidArgument);
        } else {
            assert!(
                DETECT.iter().any(|r| e.message.starts_with(r)),
                "{}",
                e.message
            );
        }
    }

    /// SUP-6・TASK-163.3: 準備が通れば自 pid を記録し、status fd からスレッド数を読める。
    #[test]
    fn sup6_task163_3_prepare_records_pid_and_reads_threads() {
        let c = config(true, "[]");
        let (bundle, rootfs) = pinned_rootfs("records", &c);
        let prepared = prepare_exec_restrictions(&c, &rootfs);
        let _ = std::fs::remove_dir_all(&bundle);
        match prepared {
            Ok(mut r) => {
                assert_eq!(r.owner_pid, std::process::id());
                let n = r.threads.count().expect("threads readable");
                assert!(n >= 1, "{n}");
            }
            // Landlock 未対応のカーネルでは検出で拒否される（fail-closed）。
            Err(e) => assert_eq!(e.stage, IsolationStage::Landlock),
        }
    }

    /// SUP-6・TASK-163.3・CORE-5: 準備はルールパスを開かず解決もしない。実在しないパスを destination に
    /// 持つ config でも準備は成功し、ruleset はコンテナ内パスの文字列をそのまま保持する
    /// （開く処理は `setns` 後の `reapply_restrictions` 側。fail-closed の拒否もそこで起きる）。
    #[test]
    fn sup6_task163_3_prepare_keeps_container_paths_unresolved() {
        let dest = "/fandhe-nonexistent-reapply-dest/data";
        let c = config(
            true,
            &format!(r#"[{{"destination":"{dest}","options":["ro"]}}]"#),
        );
        let (bundle, rootfs) = pinned_rootfs("unresolved", &c);
        let prepared = prepare_exec_restrictions(&c, &rootfs);
        let _ = std::fs::remove_dir_all(&bundle);
        match prepared {
            Ok(r) => {
                let paths: Vec<&str> = r
                    .landlock
                    .rules()
                    .iter()
                    .map(|rule| rule.path.as_str())
                    .collect();
                assert_eq!(paths, vec!["/", dest]);
                // 準備（`join_namespaces` 前）でホストへ解決されていないこと: destination は実在しない。
                assert!(!std::path::Path::new(dest).exists());
            }
            // Landlock 未対応のカーネルでは検出で拒否される（fail-closed）。
            Err(e) => assert_eq!(e.stage, IsolationStage::Landlock),
        }
    }

    fn tmp_file(content: &[u8]) -> std::fs::File {
        use std::io::{Seek as _, Write as _};
        let mut f = tempfile_in_target();
        f.write_all(content).expect("write");
        f.seek(std::io::SeekFrom::Start(0)).expect("seek");
        f
    }

    /// 使い捨ての無名ファイル（名前を残さない）。`O_TMPFILE` 相当を std だけで作れないため、
    /// 一意名で作成して直ちに unlink する。
    fn tempfile_in_target() -> std::fs::File {
        use std::io::Read as _;
        let mut buf = [0u8; 8];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .expect("urandom");
        let path = std::env::temp_dir().join(format!(
            "fandhe-reapply-{}-{:016x}",
            std::process::id(),
            u64::from_le_bytes(buf)
        ));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create");
        std::fs::remove_file(&path).expect("unlink");
        f
    }

    /// SUP-6・TASK-163.3: 事前に開いた fd から `Threads:` を読め、同じ fd を再読込しても同じ値になる。
    #[test]
    fn sup6_task163_3_pre_opened_source_parses_and_rereads() {
        let mut src =
            ThreadCountSource::PreOpened(tmp_file(b"Name:\tx\nThreads:\t1\nVmRSS:\t5 kB\n"));
        assert_eq!(src.count(), Some(1));
        assert_eq!(src.count(), Some(1));
    }

    /// SUP-6・TASK-163.3: `Threads:` 行が無い・空の fd は `None`（適用は拒否される。fail-closed）。
    #[test]
    fn sup6_task163_3_pre_opened_source_rejects_unreadable_status() {
        let mut no_line = ThreadCountSource::PreOpened(tmp_file(b"Name:\tx\n"));
        assert_eq!(no_line.count(), None);
        let mut empty = ThreadCountSource::PreOpened(tmp_file(b""));
        assert_eq!(empty.count(), None);
        let mut multi = ThreadCountSource::PreOpened(tmp_file(b"Threads:\t3\n"));
        assert_eq!(multi.count(), Some(3));
    }
}
