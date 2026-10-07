//! capability の絞り込み（SEC-1・TASK-37.1・#172・MS-2）。
//!
//! # 役割と呼び出し文脈
//!
//! ステージ列（`exec/stages.rs`）の第 2 段「capability 削減」の実体。呼び出したスレッドの
//! capability を OCI 既定集合（[`CapabilitySet::oci_default`]。SEC-1）へ絞り込み、結果を読み戻して
//! 検証する。ステージ列（`StagePipeline`）へは #173（TASK-37.2）で組み込み済みで、`StagePipeline::run_then`
//! が差し替え不可の組み込み段として呼ぶ（返す [`CapabilityReport`] は終端クロージャへ渡る）。
//! 最終的な制限適用の証跡型は TASK-38・TASK-39 で決めるため、`process.rs::require_restriction_evidence`
//! は本関数の成否によらず exec を拒否し続ける（REPAIR-3）。実プロセスでの `/proc/<pid>/status` 検証は
//! #174（TASK-37.3）が担う。
//!
//! # 契約
//!
//! - `fork_single_threaded` による単一スレッドの子で、pivot 後・`NO_NEW_PRIVS` の前に呼ぶ。
//!   bounding set・`capset(2)` はスレッド単位で、呼んだスレッドにしか効かない。この条件は
//!   呼び出し側に任せず、[`apply_default_capabilities`] が `/proc/self/status` の `Threads:` が 1 で
//!   あることを適用の前後で実行時に確認し、事前に満たさない・読めないときは何も変更せず
//!   `FailedPrecondition`、適用中に増えたときは `Internal` で失敗する（fail-closed。他スレッドに強い
//!   capability が残ったまま `Ok` を返さない）。関数自体も `pub(crate)` で、外部 crate から呼べない
//! - 許可集合は OCI 既定集合に固定し、任意の集合を渡せる公開経路は持たない（設定から危険な
//!   capability を足せない）
//! - bounding set は `execve` 後の uid 0 プロセスの permitted の上限を決めるため、最初に縮める。
//!   カーネルが知る全番号を `PR_CAPBSET_READ` で調べ、許可集合に無いものはすべて drop する。
//!   本 crate の `Capability` が知らない新しい capability も drop される（fail-closed）
//! - inheritable は空にする（CVE-2022-29162 の教訓。ambient は inheritable ⊆ で空に保たれる）
//! - `retained_after_exec` は `execve` 後の権限の**上限**（適用後の permitted ∪ bounding set）で、
//!   exec 時の資格情報に依存しない。uid 0 の `execve` では permitted に無い capability も bounding
//!   set から再取得でき（`P'(permitted) = inheritable ∪ bounding ∪ ambient`）、`NO_NEW_PRIVS` は
//!   その獲得を「適用前の permitted」へ丸めるにすぎないため、後段の `NO_NEW_PRIVS` に期待しない。
//!   実プロセスでの exec 後の読み戻しによる証跡化は #174（TASK-37.3）が担う
//! - 途中で失敗したら打ち切ってエラーを返し、部分的に成功した状態のまま `Ok` を返さない。
//!   設定後に capget と bounding set を読み戻し、不一致なら `Internal` で失敗する
//!
//! 本物の syscall は [`RealKernel`]（`sys` のラッパー）だけが呼ぶ。テストは偽の `CapKernel` を差し込んで
//! 呼び出し順・エラー写像・読み戻し不一致を再現し、本物の syscall は `sys.rs` のテストと、使い捨て
//! スレッドを使う `sec1_apply_default_capabilities_real_thread` で確認する。

use std::os::fd::{AsFd as _, BorrowedFd};

use super::setns::read_bounded_from;
use super::{ExecError, IsolationStage, ThreadCountSource};
use crate::capabilities::CapabilitySet;
use crate::sys::{self, EINVAL, EPERM, SysError, ThreadCaps};
use crate::traits::types::ErrorCode;

/// カーネルへの capability 操作の境界。本番は [`RealKernel`]（`sys` の薄いラッパー）、
/// テストは偽物を差し込んで呼び出し順・エラー写像・読み戻し不一致を再現する。
trait CapKernel {
    fn bounding_contains(&mut self, cap: u8) -> Result<bool, SysError>;
    fn bounding_drop(&mut self, cap: u8) -> Result<(), SysError>;
    fn ambient_clear_all(&mut self) -> Result<(), SysError>;
    fn get(&mut self) -> Result<ThreadCaps, SysError>;
    fn set(&mut self, caps: ThreadCaps) -> Result<(), SysError>;
    /// 呼び出したプロセスのスレッド数（`/proc/self/status` の `Threads:`）。読めない・解釈できない場合は `None`。
    fn thread_count(&mut self) -> Option<u64>;
    /// 補助グループの件数（`getgroups(0, NULL)`）。
    fn supplementary_group_count(&mut self) -> Result<usize, SysError>;
    /// 補助グループをすべて消去する（`setgroups(0, NULL)`）。
    fn clear_supplementary_groups(&mut self) -> Result<(), SysError>;
    /// 呼び出しプロセスの user namespace が `setgroups` を禁じているか（procfs の `setgroups` が `deny`）。
    /// 確認できない（procfs でない・読めない・`allow` / `deny` 以外の内容）場合は `None`。
    fn setgroups_denied(&mut self) -> Option<bool>;
}

/// 本物の syscall を呼ぶ実装。スレッド数の取得元（`/proc/self/status` か、`setns` 前に開いた fd）を持つ。
struct RealKernel<'a> {
    threads: &'a mut ThreadCountSource,
    /// 呼び出しプロセス自身の procfs ディレクトリ（`/proc/<pid>`。procfs と確認済みの fd）。exec 専用プロセスは
    /// `setns` の後に `/proc/self` を解決できないため、`setns` の前に開いた fd を渡す。`None` なら `/proc` を
    /// procfs と確認したうえで `self` を引く（launch 経路。pivot 後の `/proc` は `prepare_rootfs` がマウント済み）。
    own_proc_dir: Option<BorrowedFd<'a>>,
}

/// procfs の `setgroups` の読み取り上限（本物は `allow\n` / `deny\n` の 5〜6 バイト）。
const SETGROUPS_READ_LIMIT: u64 = 16;

/// 呼び出しプロセスの user namespace が `setgroups` を禁じているかを、信頼できる procfs から読む。
///
/// `own_proc_dir` があればその `setgroups`、無ければ `fstatfs` で procfs と確認した `/proc` の `self/setgroups`。
/// `deny` なら `Some(true)`、`allow` なら `Some(false)`、それ以外・確認できない場合は `None`。
fn read_setgroups_denied(own_proc_dir: Option<BorrowedFd<'_>>) -> Option<bool> {
    let file = match own_proc_dir {
        Some(dir) => sys::open_read_at(dir, c"setgroups").ok()?,
        None => {
            let proc_dir = sys::open_dir_path_nofollow(None, c"/proc").ok()?;
            if sys::fs_type(proc_dir.as_fd()) != Ok(sys::PROC_MAGIC) {
                return None;
            }
            sys::open_read_at(proc_dir.as_fd(), c"self/setgroups").ok()?
        }
    };
    // 開いたファイル自体も procfs 上にあること（別のファイルシステムの同名ファイルを信用しない）。
    if sys::fs_type(file.as_fd()) != Ok(sys::PROC_MAGIC) {
        return None;
    }
    let text = read_bounded_from(std::fs::File::from(file), SETGROUPS_READ_LIMIT).ok()?;
    match text.trim_end_matches('\n') {
        "deny" => Some(true),
        "allow" => Some(false),
        _ => None,
    }
}

impl CapKernel for RealKernel<'_> {
    fn bounding_contains(&mut self, cap: u8) -> Result<bool, SysError> {
        sys::cap_bounding_contains(cap)
    }
    fn bounding_drop(&mut self, cap: u8) -> Result<(), SysError> {
        sys::cap_bounding_drop(cap)
    }
    fn ambient_clear_all(&mut self) -> Result<(), SysError> {
        sys::cap_ambient_clear_all()
    }
    fn get(&mut self) -> Result<ThreadCaps, SysError> {
        sys::cap_get_thread()
    }
    fn set(&mut self, caps: ThreadCaps) -> Result<(), SysError> {
        sys::cap_set_thread(caps)
    }
    fn thread_count(&mut self) -> Option<u64> {
        self.threads.count()
    }
    fn supplementary_group_count(&mut self) -> Result<usize, SysError> {
        sys::supplementary_group_count()
    }
    fn clear_supplementary_groups(&mut self) -> Result<(), SysError> {
        sys::clear_supplementary_groups()
    }
    fn setgroups_denied(&mut self) -> Option<bool> {
        read_setgroups_denied(self.own_proc_dir)
    }
}

/// 補助グループの扱いの結果（SUP-6・SEC-1・SEC-5・TASK-163 追補・#1457）。
///
/// launch 経路（組み込みの capability 削減段）と稼働中コンテナへの exec（`reapply_restrictions`）が同じ関数で
/// 同じ扱いをする: コンテナのプロセスは補助グループを **持たない**（`config.json` の
/// `process.user.additionalGids` は launch が非空を拒否するため、空が唯一の指定）。起動したプロセス（supervisor・
/// exec を起動した CLI。`sudo` 経由なら呼び出しユーザーのもの）のホスト側の補助グループを持ち越さない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SupplementaryGroups {
    /// 元から空だった（syscall を呼んでいない）。
    AlreadyEmpty,
    /// `setgroups(0)` で消去し、読み戻して空であることを確かめた（`cleared` は消去前の件数）。
    Cleared {
        /// 消去前の件数。
        cleared: usize,
    },
    /// 消去できず、**現状のまま残した**（`kept` 件）。`setgroups` が `EPERM` になり、かつ procfs の
    /// `/proc/<pid>/setgroups` で user namespace が `setgroups` を `deny` にしている（非特権で作った user
    /// namespace = rootless）と確認できた場合に限る。カーネルが意図して禁じている操作
    /// （グループを落として「グループによる拒否」の ACL を回避させない）。
    ///
    /// **残るのは「このプロセスが持ち込んだ」補助グループ**（user namespace の中からは写像されず overflow gid に
    /// 見える）で、誰のものかは経路で違う。launch の子は supervisor から fork されるため、user namespace を作った
    /// 非特権ユーザー自身のグループであり、そのユーザーが元から持つ権限を超えない。稼働中コンテナへの exec では
    /// **exec を起動したプロセスのグループ** で、user namespace の作成者と同じとは限らない（照合していない）。
    /// そのため exec は、`setns` で user namespace へ入る **前**（初期 user namespace で `CAP_SETGID` を持つ間）に
    /// [`clear_supplementary_groups_before_join`] で消去を試み、root・`sudo` 経由の起動者のグループを持ち込まない。
    /// exec でこの値になるのは、起動者自身が既に `setgroups` を禁じた user namespace の中にいる場合だけである。
    KeptSetgroupsDenied {
        /// 残した件数。
        kept: usize,
    },
}

impl SupplementaryGroups {
    /// 機械可読な名前（ログ・worker の結果行用）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AlreadyEmpty => "already_empty",
            Self::Cleared { .. } => "cleared",
            Self::KeptSetgroupsDenied { .. } => "kept_setgroups_denied",
        }
    }

    /// 適用後に残っている補助グループの件数（消去済み・元から空は 0）。
    pub fn remaining(self) -> usize {
        match self {
            Self::AlreadyEmpty | Self::Cleared { .. } => 0,
            Self::KeptSetgroupsDenied { kept } => kept,
        }
    }
}

/// capability の適用結果。将来の拡張（最終的な証跡型。TASK-38・TASK-39）に備えて `non_exhaustive` にする。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CapabilityReport {
    /// bounding set から drop した capability 番号（本 crate が知らない番号も表せるよう番号で持つ）。
    pub bounding_dropped: Vec<u8>,
    /// 呼び出したスレッドの現在の effective / permitted の集合（`execve` 後に保持される集合では
    /// ない。`execve` 後に保持できるのは `retained_after_exec`）。
    pub granted: CapabilitySet,
    /// 適用後の bounding set（許可集合の部分集合であることを読み戻して検証済み）。
    pub bounding: CapabilitySet,
    /// `execve` 後に保持し得る権限の上限（`granted` ∪ `bounding`。exec 時の資格情報によらない）。
    /// uid 0 の `execve` は permitted に無い capability も bounding set から再取得するため、
    /// `granted` ∩ bounding では過小評価になる。証跡にはこちらを使う（型の確定は TASK-38・TASK-39）。
    pub retained_after_exec: CapabilitySet,
    /// 許可集合に含まれるが、適用前の permitted に無く付与できなかったもの。
    pub unavailable: CapabilitySet,
    /// 調べて分かったカーネルの最後の capability 番号。
    pub last_cap: u8,
    /// 補助グループの扱いの結果（capability の削減より前に行う。TASK-163 追補・#1457）。
    pub supplementary_groups: SupplementaryGroups,
}

/// 呼び出したスレッドの capability を OCI 既定集合（SEC-1）へ絞り込む。
///
/// **crate 内限定**（`pub(crate)`）。外部 crate から単一スレッドでない文脈で呼べないようにし、
/// 呼び出し経路を `sys::fork_single_threaded` の子（`StagePipeline::run_then` の組み込み段。#173）に
/// 閉じる。pivot 後・`NO_NEW_PRIVS` の前に呼ぶ。
///
/// bounding set・capset はスレッド単位で他スレッドには効かないため、適用の前後で `Threads:` が 1
/// であることを確認し、満たさない（または確認できない）場合は失敗する（SEC-1・fail-closed）。
/// - 事前確認: 副作用の前に行い、満たさなければ何も変更せず `FailedPrecondition` で失敗する。
///   `Threads: 1` のプロセスに新しいスレッドを作れるのは呼び出しスレッド自身だけで、本関数は
///   スレッドを作らないため、確認から適用までの間に他スレッドが増えることはない
///   （`sys::fork_single_threaded` と同じ論拠）
/// - 事後確認: 適用後にもう一度 `Threads: 1` を確認する。万一増えていれば（呼び出し側の
///   別経路の不具合等）`Ok` を返さず `Internal` で失敗し、権限が残った可能性を呼び出し側へ伝える
pub(crate) fn apply_default_capabilities() -> Result<CapabilityReport, ExecError> {
    apply_default_capabilities_with(&mut ThreadCountSource::ProcSelf, None)
}

/// [`apply_default_capabilities`] の、スレッド数の取得元を差し替えられる版（SUP-6・TASK-163.4・#503）。
///
/// exec 専用プロセスは `setns` の後に自プロセスを `/proc/self` で解決できないため、`setns` の前に開いた
/// status fd（`ThreadCountSource::PreOpened`）で `Threads: 1` を適用の前後に確認する。検査自体は弱めない。
///
/// `own_proc_dir` は呼び出しプロセス自身の procfs ディレクトリ（`setns` の前に開き、procfs と確認した fd）で、
/// 補助グループを消去できなかったときに user namespace の `setgroups` の設定を読むために使う（#1457）。
pub(crate) fn apply_default_capabilities_with(
    threads: &mut ThreadCountSource,
    own_proc_dir: Option<BorrowedFd<'_>>,
) -> Result<CapabilityReport, ExecError> {
    apply_capabilities_single_threaded(
        CapabilitySet::oci_default(),
        &mut RealKernel {
            threads,
            own_proc_dir,
        },
    )
}

/// 単一スレッド条件を適用の前後で検査して [`apply_capabilities`] を呼ぶ。事前検査は副作用の前に行う。
fn apply_capabilities_single_threaded(
    allowed: CapabilitySet,
    kernel: &mut impl CapKernel,
) -> Result<CapabilityReport, ExecError> {
    if kernel.thread_count() != Some(1) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            IsolationStage::CapabilityDrop,
            "capability drop requires a single-threaded process (Threads: 1)",
        ));
    }
    let report = apply_capabilities(allowed, kernel)?;
    if kernel.thread_count() != Some(1) {
        return Err(ExecError::new(
            ErrorCode::Internal,
            IsolationStage::CapabilityDrop,
            "process became multi-threaded while dropping capabilities",
        ));
    }
    Ok(report)
}

/// カーネルの capability 番号の上限（2 語 = 64 bit）。
const CAP_INDEX_LIMIT: u8 = 64;

fn apply_capabilities(
    allowed: CapabilitySet,
    kernel: &mut impl CapKernel,
) -> Result<CapabilityReport, ExecError> {
    let stage = IsolationStage::CapabilityDrop;
    let fail = |e: SysError, what: &str| ExecError::from_sys(e, stage, what);

    // 0. 補助グループの消去（`CAP_SETGID` を落とす前に行う。失敗したら何も削減しないまま拒否する）。
    let supplementary_groups = drop_supplementary_groups(kernel)?;

    // 1. bounding set の削減（許可集合に無い番号を、カーネルが知る最後の番号まですべて drop する）。
    let mut dropped = Vec::new();
    let mut last_cap = None;
    for n in 0..CAP_INDEX_LIMIT {
        match kernel.bounding_contains(n) {
            Ok(true) if !allowed.contains_index(n) => {
                kernel
                    .bounding_drop(n)
                    .map_err(|e| fail(e, "prctl(PR_CAPBSET_DROP)"))?;
                dropped.push(n);
            }
            Ok(_) => {}
            // カーネルの最後の capability を超えると EINVAL になる。
            Err(SysError::Os(e)) if e == EINVAL && n > 0 => {
                last_cap = Some(n - 1);
                break;
            }
            // 番号 0 で EINVAL は「capability を 1 つも知らない」ことになり、カーネルの応答として異常。
            Err(SysError::Os(e)) if e == EINVAL => {
                return Err(ExecError::new(
                    ErrorCode::Internal,
                    stage,
                    "prctl(PR_CAPBSET_READ) rejected capability 0",
                ));
            }
            Err(e) => return Err(fail(e, "prctl(PR_CAPBSET_READ)")),
        }
    }
    let last_cap = match last_cap {
        Some(n) => n,
        // 0..64 がすべて既知だった場合、番号 64 が EINVAL であること（= 63 が最後）を確認する。
        // 認識されるなら本実装の 2 語 ABI では扱えない未知 capability が残り得るため、
        // 対応 ABI を実装するまで fail-closed で拒否する（SEC-1）。
        None => match kernel.bounding_contains(CAP_INDEX_LIMIT) {
            Err(SysError::Os(e)) if e == EINVAL => CAP_INDEX_LIMIT - 1,
            Ok(_) => {
                return Err(ExecError::new(
                    ErrorCode::Unimplemented,
                    stage,
                    "kernel recognises capability numbers beyond 63, which this implementation cannot drop",
                ));
            }
            Err(e) => return Err(fail(e, "prctl(PR_CAPBSET_READ)")),
        },
    };

    // 2. ambient のクリア。
    kernel
        .ambient_clear_all()
        .map_err(|e| fail(e, "prctl(PR_CAP_AMBIENT_CLEAR_ALL)"))?;

    // 3. effective = permitted = 許可集合 ∩ 現在の permitted、inheritable = 空。
    let current = kernel.get().map_err(|e| fail(e, "capget"))?;
    let granted = allowed.intersect(CapabilitySet::from_cap_words(current.permitted));
    let unavailable = without(allowed, granted);
    let target = ThreadCaps {
        effective: granted.to_cap_words(),
        permitted: granted.to_cap_words(),
        inheritable: [0, 0],
    };
    kernel.set(target).map_err(|e| fail(e, "capset"))?;

    // 4. 読み戻し検証（fail-closed）。
    let after = kernel.get().map_err(|e| fail(e, "capget"))?;
    if after != target {
        return Err(ExecError::new(
            ErrorCode::Internal,
            stage,
            "capabilities differ from the target after capset",
        ));
    }
    let mut bounding_held = [false; CAP_INDEX_LIMIT as usize];
    for n in 0..=last_cap {
        let present = kernel
            .bounding_contains(n)
            .map_err(|e| fail(e, "prctl(PR_CAPBSET_READ)"))?;
        if let Some(slot) = bounding_held.get_mut(usize::from(n)) {
            *slot = present;
        }
        if present && !allowed.contains_index(n) {
            return Err(ExecError::new(
                ErrorCode::Internal,
                stage,
                "bounding set still holds a capability outside the allowed set",
            ));
        }
    }

    // 検証済みなので bounding ⊆ allowed。許可集合の各 capability について保持の有無を集める。
    let bounding = allowed
        .iter()
        .filter(|c| {
            bounding_held
                .get(usize::from(c.index()))
                .copied()
                .unwrap_or(false)
        })
        .fold(CapabilitySet::empty(), |acc, c| acc.with(c));
    let retained_after_exec = bounding.iter().fold(granted, |acc, c| acc.with(c));

    Ok(CapabilityReport {
        bounding_dropped: dropped,
        granted,
        bounding,
        retained_after_exec,
        unavailable,
        last_cap,
        supplementary_groups,
    })
}

/// 稼働中コンテナへの exec が、namespace へ参加する **前** に補助グループを空にする
/// （SUP-6・SEC-1・SEC-5・TASK-163 追補・#1457）。本番ビルドの実装。
///
/// `reapply::prepare_exec_restrictions` が準備の最後に呼ぶ。exec 専用プロセスは、対象の user namespace へ
/// `setns` した後では（その user namespace が `setgroups` を `deny` にしていれば）補助グループを消せず、exec を
/// 起動したプロセス（root・`sudo` 経由・別のグループ集合のセッション）のホスト側の補助グループを持ち込んだまま
/// コンテナ内でコマンドを動かすことになる。参加の前、まだ自分の user namespace で `CAP_SETGID` を持つ間に
/// 消去しておけば、参加後の capability 削減は「元から空」になる。
///
/// 契約は [`drop_supplementary_groups`] と同じ（消去できず `deny` も確認できなければ拒否 = 準備の失敗で、
/// 参加しない）。スレッド単位の syscall のため、前後で `Threads: 1` を確かめる。capability は変更しない。
#[cfg(not(test))]
pub(super) fn clear_supplementary_groups_before_join(
    threads: &mut ThreadCountSource,
    own_proc_dir: BorrowedFd<'_>,
) -> Result<SupplementaryGroups, ExecError> {
    clear_groups_single_threaded(&mut RealKernel {
        threads,
        own_proc_dir: Some(own_proc_dir),
    })
}

/// 単一スレッド条件を前後で検査して [`drop_supplementary_groups`] を呼ぶ（事前検査は副作用の前）。
fn clear_groups_single_threaded(
    kernel: &mut impl CapKernel,
) -> Result<SupplementaryGroups, ExecError> {
    let stage = IsolationStage::CapabilityDrop;
    if kernel.thread_count() != Some(1) {
        return Err(ExecError::new(
            ErrorCode::FailedPrecondition,
            stage,
            "clearing the supplementary groups requires a single-threaded process (Threads: 1)",
        ));
    }
    let outcome = drop_supplementary_groups(kernel)?;
    if kernel.thread_count() != Some(1) {
        return Err(ExecError::new(
            ErrorCode::Internal,
            stage,
            "process became multi-threaded while clearing the supplementary groups",
        ));
    }
    Ok(outcome)
}

/// 結合試験専用: 呼び出したスレッドの補助グループを、本番と同じ関数・本物の syscall で空にする
/// （SUP-6・SEC-1・SEC-5・TASK-163 追補・#1457）。
///
/// 呼び出し文脈は core の `tests/exec_child_setup.rs` と supervisor の `tests/exec_setns_join.rs` の **使い捨ての
/// 子プロセス**（単一スレッドの `main`。呼び出しプロセス自身の資格情報を不可逆に変えるため）。capability は
/// 削減しない。非特権のプロセス（`CAP_SETGID` なし）での拒否と、`setgroups` が `deny` の user namespace での
/// 「現状維持の記録」を実 syscall で照合するために使う。権限を増やす操作ではない。`exec-test-support` feature を
/// 付けたビルドにだけ存在し、既定のビルドの公開 API には含まれない。
#[cfg(all(feature = "exec-test-support", not(test)))]
#[doc(hidden)]
pub fn clear_supplementary_groups_for_test() -> Result<SupplementaryGroups, ExecError> {
    drop_supplementary_groups(&mut RealKernel {
        threads: &mut ThreadCountSource::ProcSelf,
        own_proc_dir: None,
    })
}

/// 呼び出したスレッドの補助グループを空にする（SUP-6・SEC-1・SEC-5・TASK-163 追補・#1457）。
///
/// launch・exec の両経路で、capability の削減より前に呼ぶ。契約:
///
/// - 元から空なら何も呼ばない（[`SupplementaryGroups::AlreadyEmpty`]）
/// - `setgroups(0)` が成功したら、読み戻して空であることを確かめる（[`SupplementaryGroups::Cleared`]。空で
///   なければ `Internal`）
/// - `EPERM` で、かつ **procfs の `setgroups` が `deny` と確認できた** 場合だけ、現状のまま残して結果に記録する
///   （[`SupplementaryGroups::KeptSetgroupsDenied`]）。`EPERM` は `CAP_SETGID` の不足・継承した seccomp フィルタ・
///   LSM でも返るため、errno と capability からは理由を特定しない。読むのは呼び出しプロセス自身の procfs の
///   `setgroups`（user namespace ごとの設定。初期 user namespace は常に `allow`）で、exec 専用プロセスは `setns` の
///   後に `/proc/self` を解決できないため `setns` の前に開いた自分の procfs ディレクトリの fd から、launch の子は
///   `fstatfs` で procfs と確認した `/proc` から読む。開いたファイルが procfs 上に無い・内容が `allow` / `deny` で
///   ない場合は確認できなかったものとして扱う
/// - それ以外（`deny` と確認できない `EPERM`・その他の errno）は、ホスト側の補助グループを持ち越したまま
///   進めないため拒否する（fail-closed）
fn drop_supplementary_groups(
    kernel: &mut impl CapKernel,
) -> Result<SupplementaryGroups, ExecError> {
    let stage = IsolationStage::CapabilityDrop;
    let fail = |e: SysError, what: &str| ExecError::from_sys(e, stage, what);
    let before = kernel
        .supplementary_group_count()
        .map_err(|e| fail(e, "getgroups"))?;
    if before == 0 {
        return Ok(SupplementaryGroups::AlreadyEmpty);
    }
    match kernel.clear_supplementary_groups() {
        Ok(()) => {
            let after = kernel
                .supplementary_group_count()
                .map_err(|e| fail(e, "getgroups"))?;
            if after != 0 {
                return Err(ExecError::new(
                    ErrorCode::Internal,
                    stage,
                    "supplementary groups remain after setgroups(0)",
                ));
            }
            Ok(SupplementaryGroups::Cleared { cleared: before })
        }
        // `EPERM` だけでは理由を特定できない（`CAP_SETGID` が無い・継承した seccomp フィルタ・LSM でも `EPERM` に
        // なる）。信頼できる procfs で user namespace の `setgroups` が `deny` と確認できた場合だけ残す。
        Err(SysError::Os(e)) if e == EPERM => match kernel.setgroups_denied() {
            Some(true) => Ok(SupplementaryGroups::KeptSetgroupsDenied { kept: before }),
            _ => Err(ExecError::new(
                ErrorCode::PermissionDenied,
                stage,
                "cannot clear the supplementary groups: setgroups(0) was refused and the user namespace is not confirmed to deny setgroups",
            )),
        },
        Err(e) => Err(fail(e, "setgroups(0)")),
    }
}

/// `set` から `minus` の要素を除いた集合。
fn without(set: CapabilitySet, minus: CapabilitySet) -> CapabilitySet {
    set.iter()
        .filter(|c| !minus.contains(*c))
        .fold(CapabilitySet::empty(), |acc, c| acc.with(c))
}

/// テスト用の偽 syscall。
#[cfg(test)]
pub(super) mod testing {
    use std::cell::Cell;

    use super::{CapabilityReport, CapabilitySet, ExecError, apply_capabilities_single_threaded};
    use crate::sys::{EINVAL, SysError, ThreadCaps};

    thread_local! {
        static DROP_ERR: Cell<Option<SysError>> = const { Cell::new(None) };
    }

    /// 次の 1 回だけ、`apply_default_capabilities` の偽物の bounding drop を失敗させる
    /// （使うと既定へ戻り、後続テストへ漏れない）。
    pub(in crate::exec) fn fake_capability_drop_err(e: SysError) {
        DROP_ERR.with(|c| c.set(Some(e)));
    }

    /// `stages.rs` の組み込み段が `cfg(test)` で呼ぶ偽物。本物の絞り込みロジックを偽カーネルで走らせる
    /// （本物は `Threads: 1` を要求し、マルチスレッドの libtest では動かないため）。
    pub(in crate::exec) fn apply_default_capabilities() -> Result<CapabilityReport, ExecError> {
        crate::exec::no_new_privs::testing::rec("capability_drop");
        let mut k = Fake::new();
        k.drop_err = DROP_ERR.with(Cell::take);
        apply_capabilities_single_threaded(CapabilitySet::oci_default(), &mut k)
    }

    thread_local! {
        static GROUPS_BEFORE_JOIN: Cell<usize> = const { Cell::new(0) };
    }

    /// 次の 1 回だけ、参加前の補助グループの偽物が持つ件数を設定する（使うと 0 へ戻る）。
    pub(in crate::exec) fn fake_groups_before_join(count: usize) {
        GROUPS_BEFORE_JOIN.with(|c| c.set(count));
    }

    /// `reapply.rs` が `cfg(test)` で呼ぶ偽物（libtest のプロセスの資格情報は変えない）。本物の判定ロジックを
    /// 偽カーネルで走らせ、呼ばれたことを記録する。
    pub(in crate::exec) fn clear_supplementary_groups_before_join(
        _threads: &mut super::ThreadCountSource,
        _own_proc_dir: std::os::fd::BorrowedFd<'_>,
    ) -> Result<super::SupplementaryGroups, ExecError> {
        crate::exec::no_new_privs::testing::rec("setgroups_before_join");
        let mut k = Fake::new();
        k.groups = GROUPS_BEFORE_JOIN.with(Cell::take);
        super::clear_groups_single_threaded(&mut k)
    }

    /// `reapply.rs` が `cfg(test)` で呼ぶ偽物（スレッド数の取得元は偽カーネルが持つため無視する）。
    pub(in crate::exec) fn apply_default_capabilities_with(
        _threads: &mut super::ThreadCountSource,
        _own_proc_dir: Option<std::os::fd::BorrowedFd<'_>>,
    ) -> Result<CapabilityReport, ExecError> {
        apply_default_capabilities()
    }

    /// 偽カーネルの状態と、呼び出し記録・注入するエラー。
    pub(super) struct Fake {
        pub(super) bounding: u64,
        pub(super) last_cap: u8,
        pub(super) caps: ThreadCaps,
        pub(super) calls: Vec<&'static str>,
        pub(super) drop_err: Option<SysError>,
        pub(super) read_err: Option<SysError>,
        pub(super) capset_err: Option<SysError>,
        /// capset が成功を返すが値を反映しない（読み戻し検証の不一致を作る）。
        pub(super) capset_noop: bool,
        pub(super) capset_arg: Option<ThreadCaps>,
        /// `thread_count` の戻り値。
        pub(super) threads: Option<u64>,
        /// 2 回目以降の `thread_count` の戻り値（適用中にスレッドが増えた状況を作る）。`None` なら `threads` のまま。
        pub(super) threads_later: Option<Option<u64>>,
        pub(super) thread_queries: u32,
        /// 補助グループの件数（既定は 0 = 元から空）。
        pub(super) groups: usize,
        /// `setgroups(0)` に返させるエラー。
        pub(super) setgroups_err: Option<SysError>,
        /// `setgroups(0)` が成功を返すが消去しない（読み戻し検証の不一致を作る）。
        pub(super) setgroups_noop: bool,
        /// procfs の `setgroups` の確認結果（既定は `allow` = `Some(false)`）。
        pub(super) setgroups_denied: Option<bool>,
    }

    impl Fake {
        pub(super) fn new() -> Self {
            Self {
                bounding: (1u64 << 41) - 1,
                last_cap: 40,
                caps: ThreadCaps {
                    effective: [u32::MAX, 0x1FF],
                    permitted: [u32::MAX, 0x1FF],
                    inheritable: [0x10, 0],
                },
                calls: Vec::new(),
                drop_err: None,
                read_err: None,
                capset_err: None,
                capset_noop: false,
                capset_arg: None,
                threads: Some(1),
                threads_later: None,
                thread_queries: 0,
                groups: 0,
                setgroups_err: None,
                setgroups_noop: false,
                setgroups_denied: Some(false),
            }
        }
    }

    impl super::CapKernel for Fake {
        fn bounding_contains(&mut self, cap: u8) -> Result<bool, SysError> {
            if cap == 0
                && let Some(e) = self.read_err
            {
                return Err(e);
            }
            if cap > self.last_cap {
                return Err(SysError::Os(EINVAL));
            }
            // 64 以上は bounding（u64）の範囲外。認識されるが保持していない扱いにする。
            Ok(cap < 64 && self.bounding & (1u64 << cap) != 0)
        }

        fn bounding_drop(&mut self, cap: u8) -> Result<(), SysError> {
            self.calls.push("drop");
            if let Some(e) = self.drop_err {
                return Err(e);
            }
            self.bounding &= !(1u64 << cap);
            Ok(())
        }

        fn ambient_clear_all(&mut self) -> Result<(), SysError> {
            self.calls.push("ambient");
            Ok(())
        }

        fn get(&mut self) -> Result<ThreadCaps, SysError> {
            self.calls.push("capget");
            Ok(self.caps)
        }

        fn thread_count(&mut self) -> Option<u64> {
            self.thread_queries += 1;
            match self.threads_later {
                Some(later) if self.thread_queries > 1 => later,
                _ => self.threads,
            }
        }

        fn supplementary_group_count(&mut self) -> Result<usize, SysError> {
            Ok(self.groups)
        }

        fn setgroups_denied(&mut self) -> Option<bool> {
            self.calls.push("read_setgroups");
            self.setgroups_denied
        }

        fn clear_supplementary_groups(&mut self) -> Result<(), SysError> {
            self.calls.push("setgroups");
            if let Some(e) = self.setgroups_err {
                return Err(e);
            }
            if !self.setgroups_noop {
                self.groups = 0;
            }
            Ok(())
        }

        fn set(&mut self, caps: ThreadCaps) -> Result<(), SysError> {
            self.calls.push("capset");
            self.capset_arg = Some(caps);
            if let Some(e) = self.capset_err {
                return Err(e);
            }
            if !self.capset_noop {
                self.caps = caps;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Fake;
    use super::*;
    use crate::capabilities::Capability;

    const DEFAULT_MASK: u64 = 0xA804_25FB;

    /// 偽カーネルへ既定集合を適用する。
    fn run(fake: &mut Fake) -> Result<CapabilityReport, ExecError> {
        apply_capabilities(CapabilitySet::oci_default(), fake)
    }

    /// SEC-1: 既定集合以外（41 - 14 = 27 個）をすべて drop し、bounding が既定集合になる。
    #[test]
    fn sec1_drops_all_non_default_caps_from_bounding() {
        let mut k = Fake::new();
        let report = run(&mut k).unwrap();
        let expected: Vec<u8> = (0..41u8)
            .filter(|n| DEFAULT_MASK & (1u64 << n) == 0)
            .collect();
        assert_eq!(expected.len(), 27);
        assert_eq!(report.bounding_dropped, expected);
        assert_eq!(report.last_cap, 40);
        assert_eq!(k.bounding, DEFAULT_MASK);
        assert_eq!(report.granted, CapabilitySet::oci_default());
        assert_eq!(report.retained_after_exec, CapabilitySet::oci_default());
        assert_eq!(report.bounding, CapabilitySet::oci_default());
        assert!(report.unavailable.is_empty());
    }

    /// SEC-1: 本 crate が知らない新しい capability（41〜45）も drop される。
    #[test]
    fn sec1_unknown_newer_cap_is_dropped() {
        let mut k = Fake::new();
        k.last_cap = 45;
        k.bounding = (1u64 << 46) - 1;
        let report = run(&mut k).unwrap();
        for n in 41..=45u8 {
            assert!(report.bounding_dropped.contains(&n), "{n}");
        }
        assert_eq!(report.last_cap, 45);
        assert_eq!(k.bounding, DEFAULT_MASK);
    }

    /// SEC-1: カーネルが番号 64 以上を認識する場合は fail-closed で拒否する。
    #[test]
    fn sec1_cap_number_64_recognised_is_rejected() {
        let mut k = Fake::new();
        k.last_cap = 64;
        k.bounding = u64::MAX;
        let e = run(&mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unimplemented);
        assert_eq!(e.stage, IsolationStage::CapabilityDrop);
        // 拒否は ambient・capset より前（以降の呼び出しは行わない）。
        assert!(!k.calls.contains(&"capset"));
    }

    /// SEC-1: 番号 63 まで既知で 64 が EINVAL なら last_cap = 63 で成功する。
    #[test]
    fn sec1_cap_number_63_is_last_succeeds() {
        let mut k = Fake::new();
        k.last_cap = 63;
        k.bounding = u64::MAX;
        let report = run(&mut k).unwrap();
        assert_eq!(report.last_cap, 63);
        assert_eq!(k.bounding, DEFAULT_MASK);
    }

    /// SEC-1: 呼び出し順は bounding drop → ambient → capget → capset → capget（検証）。
    #[test]
    fn sec1_call_order_is_bounding_ambient_capset_verify() {
        let mut k = Fake::new();
        k.bounding = 0xFF; // 既定外の番号 2 が drop 対象になる
        run(&mut k).unwrap();
        assert_eq!(k.calls, ["drop", "ambient", "capget", "capset", "capget"]);
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1457）: 補助グループが元から空なら `setgroups` を呼ばず、結果に
    /// `AlreadyEmpty` を記録する（既存の呼び出し順は変わらない）。
    #[test]
    fn sup6_sec1_task163_empty_supplementary_groups_need_no_syscall() {
        let mut k = Fake::new();
        let report = run(&mut k).unwrap();
        assert_eq!(
            report.supplementary_groups,
            SupplementaryGroups::AlreadyEmpty
        );
        assert_eq!(report.supplementary_groups.as_str(), "already_empty");
        assert_eq!(report.supplementary_groups.remaining(), 0);
        assert!(!k.calls.contains(&"setgroups"));
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1457）: 補助グループは capability の削減より前に `setgroups(0)` で消去し、
    /// 読み戻して空であることを確かめる（launch・exec が同じ関数を通る）。
    #[test]
    fn sup6_sec1_task163_supplementary_groups_are_cleared_before_capability_drop() {
        let mut k = Fake::new();
        k.bounding = 0xFF;
        k.groups = 3;
        let report = run(&mut k).unwrap();
        assert_eq!(
            report.supplementary_groups,
            SupplementaryGroups::Cleared { cleared: 3 }
        );
        assert_eq!(report.supplementary_groups.as_str(), "cleared");
        assert_eq!(report.supplementary_groups.remaining(), 0);
        assert_eq!(k.groups, 0);
        assert_eq!(
            k.calls,
            ["setgroups", "drop", "ambient", "capget", "capset", "capget"]
        );
    }

    /// SUP-6・SEC-5・TASK-163 追補（#1457）: `setgroups` が `EPERM` で、procfs で user namespace の `deny` を確認
    /// できた場合（rootless）は、現状のまま残して結果に記録し、capability の削減は続ける（rootless の launch を
    /// 壊さない）。`CAP_SETGID` の有無は判定に使わない。
    #[test]
    fn sup6_sec5_task163_setgroups_denied_in_user_namespace_is_recorded() {
        for effective in [[u32::MAX, 0x1FF], [!(1 << 6), 0x1FF]] {
            let mut k = Fake::new();
            k.groups = 4;
            k.setgroups_err = Some(SysError::Os(EPERM));
            k.setgroups_denied = Some(true);
            k.caps.effective = effective;
            let report = run(&mut k).unwrap();
            assert_eq!(
                report.supplementary_groups,
                SupplementaryGroups::KeptSetgroupsDenied { kept: 4 }
            );
            assert_eq!(
                report.supplementary_groups.as_str(),
                "kept_setgroups_denied"
            );
            assert_eq!(report.supplementary_groups.remaining(), 4);
            assert_eq!(k.groups, 4);
            assert_eq!(report.bounding, CapabilitySet::oci_default());
            assert_eq!(k.calls.first().copied(), Some("setgroups"));
            assert_eq!(k.calls.get(1).copied(), Some("read_setgroups"));
        }
    }

    /// SUP-6・SEC-1・TASK-163 追補（#1457）: 補助グループを消去できず、user namespace の `deny` を確認できない
    /// 場合は、何も削減せずに拒否する（fail-closed。ホスト側の補助グループを持ち越したまま進めない）。
    /// `CAP_SETGID` を持っていても、`EPERM` だけでは `deny` とみなさない（継承した seccomp フィルタ等でも
    /// `EPERM` になるため）。
    #[test]
    fn sup6_sec1_task163_uncleared_supplementary_groups_fail_closed() {
        // `setgroups` は `allow`（初期 user namespace 等）・確認できない、のどちらでも拒否する。
        for denied in [Some(false), None] {
            let mut k = Fake::new();
            k.groups = 2;
            k.setgroups_err = Some(SysError::Os(EPERM));
            k.setgroups_denied = denied;
            let e = run(&mut k).unwrap_err();
            assert_eq!(
                (e.code, e.stage),
                (ErrorCode::PermissionDenied, IsolationStage::CapabilityDrop)
            );
            assert_eq!(
                e.message,
                "cannot clear the supplementary groups: setgroups(0) was refused and the user \
                 namespace is not confirmed to deny setgroups"
            );
            assert_eq!(k.calls, ["setgroups", "read_setgroups"]);
            assert_eq!(k.groups, 2);
        }

        // その他の errno は、`deny` であっても残す理由にしない。
        let mut k = Fake::new();
        k.groups = 2;
        k.setgroups_err = Some(SysError::Os(EINVAL));
        k.setgroups_denied = Some(true);
        let e = run(&mut k).unwrap_err();
        assert_eq!(e.stage, IsolationStage::CapabilityDrop);
        assert_eq!(k.calls, ["setgroups"]);

        // 成功を返したのに残っている（読み戻しの不一致）。
        let mut k = Fake::new();
        k.groups = 2;
        k.setgroups_noop = true;
        let e = run(&mut k).unwrap_err();
        assert_eq!(
            (e.code, e.stage),
            (ErrorCode::Internal, IsolationStage::CapabilityDrop)
        );
        assert_eq!(e.message, "supplementary groups remain after setgroups(0)");
        assert_eq!(k.calls, ["setgroups"]);
    }

    /// SUP-6・SEC-5・TASK-163 追補（#1457）: `setgroups` の設定は procfs からだけ読む。テストプロセス自身の値は
    /// `/proc/self/setgroups` と一致し、自分の procfs ディレクトリの fd からも同じ値が得られる。procfs でない
    /// ディレクトリの同名ファイルは信用しない。
    #[test]
    fn sup6_sec5_task163_setgroups_policy_is_read_from_procfs_only() {
        let expected = match std::fs::read_to_string("/proc/self/setgroups")
            .unwrap()
            .as_str()
        {
            "deny\n" => Some(true),
            "allow\n" => Some(false),
            other => panic!("unexpected setgroups content: {other:?}"),
        };
        assert_eq!(read_setgroups_denied(None), expected);
        let own = std::ffi::CString::new(format!("/proc/{}", std::process::id())).unwrap();
        let own = sys::open_dir_path_nofollow(None, &own).unwrap();
        assert_eq!(read_setgroups_denied(Some(own.as_fd())), expected);

        let dir = std::env::temp_dir().join(format!(
            "fandhe-setgroups-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos())
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("setgroups"), "deny\n").unwrap();
        let fake = std::os::fd::OwnedFd::from(std::fs::File::open(&dir).unwrap());
        assert_eq!(read_setgroups_denied(Some(fake.as_fd())), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// SUP-6・SEC-1・SEC-5・TASK-163 追補（#1457）: 参加前の消去は単一スレッドでだけ行い、capability には触れない。
    /// 初期 user namespace の root 相当（`setgroups` が通る）は消去され、非特権で消せず `deny` も確認できなければ
    /// 準備の時点で拒否する（exec を起動した側のグループをコンテナへ持ち込まない）。
    #[test]
    fn sup6_sec1_task163_groups_are_cleared_before_joining_namespaces() {
        let mut k = Fake::new();
        k.groups = 5;
        assert_eq!(
            clear_groups_single_threaded(&mut k).unwrap(),
            SupplementaryGroups::Cleared { cleared: 5 }
        );
        assert_eq!(k.calls, ["setgroups"]);
        assert_eq!(k.bounding, (1u64 << 41) - 1);

        // 起動者が既に `deny` の user namespace の中にいる場合だけ、残して記録する。
        let mut k = Fake::new();
        k.groups = 5;
        k.setgroups_err = Some(SysError::Os(EPERM));
        k.setgroups_denied = Some(true);
        assert_eq!(
            clear_groups_single_threaded(&mut k).unwrap(),
            SupplementaryGroups::KeptSetgroupsDenied { kept: 5 }
        );

        let mut k = Fake::new();
        k.groups = 5;
        k.setgroups_err = Some(SysError::Os(EPERM));
        let e = clear_groups_single_threaded(&mut k).unwrap_err();
        assert_eq!(
            (e.code, e.stage),
            (ErrorCode::PermissionDenied, IsolationStage::CapabilityDrop)
        );

        // 単一スレッドでなければ何も呼ばない。
        let mut k = Fake::new();
        k.groups = 5;
        k.threads = Some(2);
        let e = clear_groups_single_threaded(&mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(k.calls, Vec::<&str>::new());
        assert_eq!(k.groups, 5);
    }

    /// SEC-1: capset に渡る値は effective = permitted = 既定集合、inheritable = 空。
    #[test]
    fn sec1_inheritable_is_cleared_and_effective_equals_permitted() {
        let mut k = Fake::new();
        run(&mut k).unwrap();
        let arg = k.capset_arg.unwrap();
        assert_eq!(arg.effective, [0xA804_25FB, 0]);
        assert_eq!(arg.permitted, [0xA804_25FB, 0]);
        assert_eq!(arg.inheritable, [0, 0]);
    }

    /// SEC-1: 適用前の permitted に無い capability は付与せず、`unavailable` に報告する。
    #[test]
    fn sec1_unavailable_caps_are_reported() {
        let mut k = Fake::new();
        // CAP_MKNOD（27）を permitted から外す。
        k.caps.permitted = [!(1u32 << 27), 0x1FF];
        let report = run(&mut k).unwrap();
        assert_eq!(
            report.unavailable,
            CapabilitySet::empty().with(Capability::Mknod)
        );
        assert!(!report.granted.contains(Capability::Mknod));
        assert_eq!(report.granted.len(), 13);
        // uid 0 の execve は bounding set から MKNOD を再取得し得るため、上限には残る。
        assert!(report.bounding.contains(Capability::Mknod));
        assert!(report.retained_after_exec.contains(Capability::Mknod));
        assert_eq!(report.retained_after_exec.len(), 14);
        let arg = k.capset_arg.unwrap();
        assert_eq!(arg.effective, [0xA804_25FB & !(1 << 27), 0]);
    }

    /// SEC-1: `granted` に無くても bounding set に残る権限は `retained_after_exec` に含める
    /// （uid 0 の execve は bounding set から再取得する）。
    #[test]
    fn sec1_retained_after_exec_includes_bounding_caps_missing_from_permitted() {
        let mut k = Fake::new();
        // CAP_MKNOD（27）は permitted に無いが bounding set には残っている。
        k.caps.permitted = [!(1u32 << 27), 0x1FF];
        let report = run(&mut k).unwrap();
        assert!(!report.granted.contains(Capability::Mknod));
        assert!(report.bounding.contains(Capability::Mknod));
        assert!(report.retained_after_exec.contains(Capability::Mknod));
        assert_eq!(report.retained_after_exec, CapabilitySet::oci_default());
    }

    /// SEC-1: bounding set にも permitted にも無い権限は `retained_after_exec` に含めない。
    #[test]
    fn sec1_retained_after_exec_excludes_caps_missing_from_both() {
        let mut k = Fake::new();
        k.caps.permitted = [!(1u32 << 27), 0x1FF];
        k.bounding &= !(1u64 << 27);
        let report = run(&mut k).unwrap();
        assert!(!report.retained_after_exec.contains(Capability::Mknod));
        assert_eq!(report.retained_after_exec.len(), 13);
    }

    /// SEC-1: 単一スレッドでなければ何も変更せず FailedPrecondition（fail-closed）。
    #[test]
    fn sec1_multithreaded_or_unknown_thread_count_is_rejected_without_side_effects() {
        for threads in [Some(2), Some(0), None] {
            let mut k = Fake::new();
            k.threads = threads;
            let e = apply_capabilities_single_threaded(CapabilitySet::oci_default(), &mut k)
                .unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition, "{threads:?}");
            assert_eq!(e.stage, IsolationStage::CapabilityDrop);
            assert!(k.calls.is_empty());
            assert_eq!(k.bounding, (1u64 << 41) - 1);
        }
    }

    /// SEC-1: 適用中にスレッドが増えた場合は `Ok` を返さず Internal で失敗する（fail-closed）。
    #[test]
    fn sec1_thread_appearing_during_apply_is_internal() {
        for later in [Some(2), None] {
            let mut k = Fake::new();
            k.threads_later = Some(later);
            let e = apply_capabilities_single_threaded(CapabilitySet::oci_default(), &mut k)
                .unwrap_err();
            assert_eq!(e.code, ErrorCode::Internal, "{later:?}");
            assert_eq!(e.stage, IsolationStage::CapabilityDrop);
        }
    }

    /// SEC-1: 内部関数はマルチスレッドの本物のプロセスで拒否し、何も変更しない。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sec1_public_api_rejects_multithreaded_process() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let helper = std::thread::spawn(move || {
            let _ = rx.recv();
        });
        let before = status_value("CapBnd:");
        let e = apply_default_capabilities().unwrap_err();
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(status_value("CapBnd:"), before);
        drop(tx);
        helper.join().unwrap();
    }

    /// SUP-6・SEC-1・TASK-163.4: スレッド数の取得元を `setns` 前に開いた status fd に替えても、`Threads:` が 1 で
    /// なければ何も変更せず `FailedPrecondition`（検査は弱まらない）。読めない取得元も同じ（fail-closed）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sup6_task163_4_pre_opened_thread_source_is_enforced() {
        use std::io::{Seek as _, Write as _};
        let before = status_value("CapBnd:");
        let path = std::env::temp_dir().join(format!("fandhe-cap-threads-{}", std::process::id()));
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("create");
        std::fs::remove_file(&path).expect("unlink");
        writeln!(f, "Threads:\t2").expect("write");
        f.seek(std::io::SeekFrom::Start(0)).expect("seek");
        let mut sources = [
            ThreadCountSource::PreOpened(f),
            ThreadCountSource::PreOpened(std::fs::File::open("/dev/null").expect("null")),
        ];
        for source in &mut sources {
            let e = apply_default_capabilities_with(source, None).unwrap_err();
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(e.stage, IsolationStage::CapabilityDrop);
            assert_eq!(
                e.message,
                "capability drop requires a single-threaded process (Threads: 1)"
            );
        }
        assert_eq!(status_value("CapBnd:"), before);
    }

    /// SEC-1: drop の EPERM は PermissionDenied・段は CapabilityDrop・後続を呼ばない。
    #[test]
    fn sec1_drop_eperm_maps_permission_denied_and_stops() {
        let mut k = Fake::new();
        k.drop_err = Some(SysError::Os(sys::EPERM));
        let e = run(&mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(e.stage, IsolationStage::CapabilityDrop);
        assert_eq!(e.violation, None);
        assert_eq!(k.calls, ["drop"]);
    }

    /// SEC-1: capset が成功を返しても読み戻しが違えば Internal（fail-closed）。
    #[test]
    fn sec1_verify_mismatch_is_internal() {
        let mut k = Fake::new();
        k.capset_noop = true;
        let e = run(&mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::CapabilityDrop);
    }

    /// SEC-1: capset の EPERM は PermissionDenied。
    #[test]
    fn sec1_capset_eperm_maps_permission_denied() {
        let mut k = Fake::new();
        k.capset_err = Some(SysError::Os(sys::EPERM));
        assert_eq!(run(&mut k).unwrap_err().code, ErrorCode::PermissionDenied);
    }

    /// SEC-1: 番号 0 で EINVAL なら Internal、Unsupported は Unimplemented。
    #[test]
    fn sec1_bounding_read_errors_are_mapped() {
        let mut k = Fake::new();
        k.read_err = Some(SysError::Os(EINVAL));
        let e = run(&mut k).unwrap_err();
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(e.stage, IsolationStage::CapabilityDrop);
        let mut k = Fake::new();
        k.read_err = Some(SysError::Unsupported);
        assert_eq!(run(&mut k).unwrap_err().code, ErrorCode::Unimplemented);
    }

    /// `/proc/thread-self/status` の `field:` 行（16 進 64 bit）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn status_value(field: &str) -> u64 {
        let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
        let v = status
            .lines()
            .find_map(|l| l.strip_prefix(field))
            .unwrap_or_else(|| panic!("{field} missing"));
        u64::from_str_radix(v.trim(), 16).unwrap()
    }

    /// SEC-1: 本物の syscall（使い捨てスレッド。スレッド単位なので libtest の他スレッドに影響しない）。
    /// `CAP_SETPCAP` が effective にあれば適用が成功して /proc の値が既定集合に絞られ、無ければ
    /// `PR_CAPBSET_DROP` が EPERM で PermissionDenied になる（root 権限は要求しない）。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn sec1_apply_default_capabilities_real_thread() {
        std::thread::spawn(|| {
            let bnd = status_value("CapBnd:");
            let prm = status_value("CapPrm:");
            let eff = status_value("CapEff:");
            let bnd_has_extra = bnd & !DEFAULT_MASK & ((1u64 << 41) - 1) != 0;
            // TASK-163 追補（#1457）: 補助グループの消去が先に走る。`CAP_SETGID` を持たず補助グループが残る
            // 非特権のスレッドは、bounding set に触れる前にそこで拒否される（どちらの拒否かを文言で区別する）。
            let groups = sys::supplementary_group_count().unwrap();
            // `CAP_SETGID`（番号 6）が無ければ `setgroups` は `EPERM`。`deny` の user namespace の中なら残して進む。
            let groups_refused = groups > 0
                && eff & (1 << 6) == 0
                && read_setgroups_denied(None) != Some(true);
            if eff & (1 << 8) == 0 {
                if groups_refused || bnd_has_extra {
                    let mut threads = ThreadCountSource::ProcSelf;
                    let e = apply_capabilities(
                        CapabilitySet::oci_default(),
                        &mut RealKernel {
                            threads: &mut threads,
                            own_proc_dir: None,
                        },
                    )
                    .unwrap_err();
                    assert_eq!(e.code, ErrorCode::PermissionDenied);
                    assert_eq!(e.stage, IsolationStage::CapabilityDrop);
                    if groups_refused {
                        assert_eq!(
                            e.message,
                            "cannot clear the supplementary groups: setgroups(0) was refused and the \
                             user namespace is not confirmed to deny setgroups"
                        );
                        // 何も変わっていない（補助グループも bounding set も元のまま）。
                        assert_eq!(sys::supplementary_group_count(), Ok(groups));
                        assert_eq!(status_value("CapBnd:"), bnd);
                    } else {
                        assert!(
                            e.message.starts_with("prctl(PR_CAPBSET_DROP) failed"),
                            "{}",
                            e.message
                        );
                    }
                }
            } else {
                let mut threads = ThreadCountSource::ProcSelf;
                let report = apply_capabilities(
                    CapabilitySet::oci_default(),
                    &mut RealKernel {
                        threads: &mut threads,
                        own_proc_dir: None,
                    },
                )
                .unwrap();
                assert_eq!(status_value("CapBnd:"), bnd & DEFAULT_MASK);
                assert_eq!(status_value("CapEff:"), prm & DEFAULT_MASK);
                assert_eq!(status_value("CapPrm:"), prm & DEFAULT_MASK);
                assert_eq!(status_value("CapInh:"), 0);
                assert_eq!(status_value("CapAmb:"), 0);
                assert_eq!(
                    report.granted.len() as u32,
                    (prm & DEFAULT_MASK).count_ones()
                );
            }
        })
        .join()
        .unwrap();
    }
}
