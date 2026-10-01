//! Landlock ruleset のカーネルへの適用（CORE-5・TASK-39.3・#183。Linux 限定）。
//!
//! # 役割
//!
//! `build_path_rules`（#182・`rules` 子モジュール）が作った [`LandlockRuleset`] を、
//! `landlock_create_ruleset` → `landlock_add_rule(PATH_BENEATH)` → `landlock_restrict_self` の順で
//! 呼び出しスレッドへ適用する。前提（`NO_NEW_PRIVS`・単一スレッド）が満たされなければ、
//! ruleset を作る前に [`LandlockApplyError`] で拒否する（fail-closed。「Landlock 無しで続行」しない）。
//!
//! # 呼び出し文脈・契約
//!
//! - 将来、ステージ列の Landlock 段（#184・TASK-39.4）が pivot_root 後・exec 直前の単一スレッドの子
//!   プロセスから [`apply_landlock_ruleset`] を呼ぶ。`ExecError` / `IsolationStage` への写像は #184 で
//!   行い、本モジュールは `ErrorCode` までを決める
//! - `PR_SET_NO_NEW_PRIVS` は固定ステージ `no_new_privs`（TASK-27.4.3・#833）が先に立てる。本関数は
//!   それを再度設定せず、立っていることを自前で検証する。カーネルは呼び出し元が user namespace 内で
//!   `CAP_SYS_ADMIN` を持つと NNP 無しでも `landlock_restrict_self` を許すため、この検証が実際の防御になる
//!   （seccomp の適用と同じ根拠）
//! - 適用は呼び出したスレッドにしか効かず不可逆。そのため `Threads: 1` を適用の前後で確認する
//! - ルールのパスは pivot 後の `/` 起点で 1 要素ずつ `O_NOFOLLOW` の fd で辿って固定する（TOCTOU・
//!   symlink 対策）。symlink・不在・開けないパスはスキップせず拒否する
//! - syscall は `crate::sys` の安全なラッパーのみを使い、`unsafe` を持たない。実カーネルは
//!   [`LandlockKernel`] の差し込み点で隔離し、単体テストは偽カーネルで呼び出し順を照合する
//! - 分離違反の試行の監査ログ記録（SEC-4）は TASK-41 の範囲で、本モジュールは記録しない
//!
//! # 未実装範囲（REPAIR-3）
//!
//! ステージ列への組み込み（#184・TASK-39.4）は未実装。[`LandlockApplyReport`] は制限適用の証跡では
//! なく、`require_restriction_evidence` の判定には使えない（証跡型は TASK-38・TASK-39 の後続）。

use std::ffi::CString;
use std::fmt;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::Path;

use super::rules::{AccessFs, LandlockRuleset, PathRule, RuleOrigin, RulePath};
use crate::sys::{self, SysError};
use crate::traits::ErrorCode;

/// 適用失敗の分類。`index` は [`LandlockRuleset::rules`] 内の位置（パス文字列は含めない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LandlockApplyErrorKind {
    /// `NO_NEW_PRIVS` が立っていない（適用前に拒否。何も変更していない）。
    NoNewPrivsNotSet,
    /// `NO_NEW_PRIVS` の問い合わせ自体に失敗した。
    NoNewPrivsQueryFailed {
        /// errno（errno を伴わない失敗は 0）。
        errno: i32,
    },
    /// 呼び出しプロセスが単一スレッドでない、または判定できない（適用は呼び出しスレッドにしか効かない）。
    NotSingleThreaded,
    /// `landlock_create_ruleset` が失敗した。
    CreateRulesetFailed {
        /// errno（errno を伴わない失敗は 0）。
        errno: i32,
    },
    /// ルール対象パスを開けなかった（不在を含む。スキップしない）。
    OpenPathFailed {
        /// ルールの位置。
        index: usize,
        /// errno（errno を伴わない失敗は 0）。
        errno: i32,
    },
    /// ルール対象パスの実体が symlink だった（追従せず拒否する）。
    SymlinkRejected {
        /// ルールの位置。
        index: usize,
    },
    /// `landlock_add_rule` が失敗した。
    AddRuleFailed {
        /// ルールの位置。
        index: usize,
        /// errno（errno を伴わない失敗は 0）。
        errno: i32,
    },
    /// `landlock_restrict_self` が失敗した。
    RestrictSelfFailed {
        /// errno（errno を伴わない失敗は 0）。
        errno: i32,
    },
    /// 適用後にスレッドが増えている、または数えられない（不変条件の破れ）。
    BecameMultiThreaded,
    /// 対応外アーキテクチャ。
    UnsupportedArchitecture,
    /// 内部不整合（パスに NUL が含まれる等。型により通常は起こらない）。
    Internal,
}

impl LandlockApplyErrorKind {
    /// 機械可読な理由コード。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoNewPrivsNotSet => "no_new_privs_not_set",
            Self::NoNewPrivsQueryFailed { .. } => "no_new_privs_query_failed",
            Self::NotSingleThreaded => "not_single_threaded",
            Self::CreateRulesetFailed { .. } => "landlock_create_ruleset_failed",
            Self::OpenPathFailed { .. } => "landlock_open_path_failed",
            Self::SymlinkRejected { .. } => "landlock_symlink_rejected",
            Self::AddRuleFailed { .. } => "landlock_add_rule_failed",
            Self::RestrictSelfFailed { .. } => "landlock_restrict_self_failed",
            Self::BecameMultiThreaded => "became_multi_threaded",
            Self::UnsupportedArchitecture => "unsupported_architecture",
            Self::Internal => "internal",
        }
    }
}

/// 適用に失敗した明示エラー（機械可読な `code` / `kind` と英語 `message`。パスは含めない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LandlockApplyError {
    /// 構造化エラーコード（ERR 系）。
    pub code: ErrorCode,
    /// 失敗の分類。
    pub kind: LandlockApplyErrorKind,
    /// 人間向け説明（英語）。
    pub message: String,
}

impl LandlockApplyError {
    fn new(code: ErrorCode, kind: LandlockApplyErrorKind, message: &str) -> Self {
        Self {
            code,
            kind,
            message: message.to_string(),
        }
    }

    /// syscall の失敗を `exec::errno_to_code` と同じ規則で写して作る
    /// （`EPERM` / `EACCES` は権限不足、`EINVAL` は前提違反、`Unsupported` は未実装、他は内部エラー）。
    fn from_sys(
        err: SysError,
        make: impl FnOnce(i32) -> LandlockApplyErrorKind,
        msg: &str,
    ) -> Self {
        let (code, errno) = match err {
            SysError::Unsupported => {
                return Self::new(
                    ErrorCode::Unimplemented,
                    LandlockApplyErrorKind::UnsupportedArchitecture,
                    "Landlock is not supported on this architecture",
                );
            }
            SysError::Os(e) if e == sys::EPERM || e == sys::EACCES => {
                (ErrorCode::PermissionDenied, e)
            }
            SysError::Os(e) if e == sys::EINVAL => (ErrorCode::FailedPrecondition, e),
            SysError::Os(e) => (ErrorCode::Internal, e),
            _ => (ErrorCode::Internal, 0),
        };
        Self::new(code, make(errno), msg)
    }
}

impl fmt::Display for LandlockApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ({})",
            self.code.as_str(),
            self.message,
            self.kind.as_str()
        )
    }
}

impl std::error::Error for LandlockApplyError {}

/// 適用結果の件数（制限適用の証跡ではない。REPAIR-3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LandlockApplyReport {
    /// `landlock_add_rule` に成功したルール数。
    pub rules_added: usize,
    /// うち非ディレクトリ（ファイル）へのルール数（権利を `FILE_COMPATIBLE` に絞った）。
    pub file_rules: usize,
    /// 絞った結果が空になり追加しなかったルール数（「配下を全拒否」と同じ意味）。
    pub skipped_empty: usize,
}

/// ルール対象の実体の種別。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathKind {
    Dir,
    File,
}

/// パスを開く処理の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenError {
    Sys(SysError),
    Symlink,
    Invalid,
}

/// カーネルとの境界（差し込み点。本番は [`RealKernel`]、単体テストは偽実装。`SeccompKernel` と同型）。
pub(crate) trait LandlockKernel {
    /// ruleset fd の表現。
    type Ruleset;
    /// ルール対象パスの fd の表現。
    type PathFd;

    fn thread_count(&self) -> Option<u64>;
    fn no_new_privs_enabled(&self) -> Result<bool, SysError>;
    fn create_ruleset(&self, handled: u64) -> Result<Self::Ruleset, SysError>;
    fn open_rule_path(&self, path: &RulePath) -> Result<(Self::PathFd, PathKind), OpenError>;
    fn add_rule(
        &self,
        ruleset: &Self::Ruleset,
        allowed: u64,
        path: &Self::PathFd,
    ) -> Result<(), SysError>;
    fn restrict_self(&self, ruleset: &Self::Ruleset) -> Result<(), SysError>;
}

/// 実カーネルへの適用（`crate::sys` の安全なラッパーを呼ぶだけ）。
struct RealKernel;

impl LandlockKernel for RealKernel {
    type Ruleset = OwnedFd;
    type PathFd = OwnedFd;

    fn thread_count(&self) -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        crate::exec::status_threads(&status)
    }

    fn no_new_privs_enabled(&self) -> Result<bool, SysError> {
        sys::no_new_privs_enabled()
    }

    fn create_ruleset(&self, handled: u64) -> Result<OwnedFd, SysError> {
        sys::landlock_create_ruleset_fs(handled)
    }

    fn open_rule_path(&self, path: &RulePath) -> Result<(OwnedFd, PathKind), OpenError> {
        let root = sys::open_dir_path_nofollow(None, c"/").map_err(OpenError::Sys)?;
        let comps: Vec<&str> = match path {
            RulePath::Root => Vec::new(),
            other => other
                .as_str()
                .split('/')
                .filter(|c| !c.is_empty())
                .collect(),
        };
        let mut cur = root;
        let last_index = comps.len().checked_sub(1);
        for (i, comp) in comps.iter().enumerate() {
            let name = CString::new(*comp).map_err(|_| OpenError::Invalid)?;
            if Some(i) != last_index {
                // 中間要素は symlink・非ディレクトリを ENOTDIR で拒否する。
                cur = sys::open_dir_path_nofollow(Some(cur.as_fd()), &name)
                    .map_err(OpenError::Sys)?;
                continue;
            }
            return match sys::open_dir_path_nofollow(Some(cur.as_fd()), &name) {
                Ok(fd) => Ok((fd, PathKind::Dir)),
                Err(SysError::Os(e)) if e == sys::ENOTDIR => {
                    let fd = sys::open_path_nofollow(cur.as_fd(), &name).map_err(OpenError::Sys)?;
                    // O_PATH fd への fstat（追従しない）で実体の種別を固定して判定する。
                    let file = std::fs::File::from(fd);
                    let ft = file.metadata().map_err(|_| OpenError::Invalid)?.file_type();
                    let fd = OwnedFd::from(file);
                    if ft.is_symlink() {
                        Err(OpenError::Symlink)
                    } else if ft.is_dir() {
                        Ok((fd, PathKind::Dir))
                    } else {
                        Ok((fd, PathKind::File))
                    }
                }
                Err(e) => Err(OpenError::Sys(e)),
            };
        }
        // `/`（Root、または空要素のみ）。
        Ok((cur, PathKind::Dir))
    }

    fn add_rule(&self, ruleset: &OwnedFd, allowed: u64, path: &OwnedFd) -> Result<(), SysError> {
        sys::landlock_add_path_beneath(ruleset.as_fd(), allowed, path.as_fd())
    }

    fn restrict_self(&self, ruleset: &OwnedFd) -> Result<(), SysError> {
        sys::landlock_restrict_self(ruleset.as_fd())
    }
}

/// 生成済みの ruleset を呼び出しスレッドへ適用する（CORE-5・TASK-39.3・#183。不可逆）。
///
/// 前提検査（NNP・単一スレッド）は ruleset を作る前に行い、違反なら何も変えず、fd も作らない。
/// 呼び出しは #184 のステージから単一スレッドの子プロセスで行う。
// 組み込み（#184）までは結合試験用の観測関数だけが呼ぶため、テストビルドでは dead_code を許可する。
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn apply_landlock_ruleset(
    ruleset: &LandlockRuleset,
) -> Result<LandlockApplyReport, LandlockApplyError> {
    apply_with(&RealKernel, ruleset)
}

fn apply_with<K: LandlockKernel>(
    kernel: &K,
    ruleset: &LandlockRuleset,
) -> Result<LandlockApplyReport, LandlockApplyError> {
    use LandlockApplyErrorKind as Kind;

    match kernel.no_new_privs_enabled() {
        Ok(true) => {}
        Ok(false) => {
            return Err(LandlockApplyError::new(
                ErrorCode::FailedPrecondition,
                Kind::NoNewPrivsNotSet,
                "no_new_privs is not set; refusing to apply Landlock",
            ));
        }
        Err(e) => {
            return Err(LandlockApplyError::from_sys(
                e,
                |errno| Kind::NoNewPrivsQueryFailed { errno },
                "failed to query no_new_privs",
            ));
        }
    }
    if kernel.thread_count() != Some(1) {
        return Err(LandlockApplyError::new(
            ErrorCode::FailedPrecondition,
            Kind::NotSingleThreaded,
            "Landlock must be applied from a single-threaded process",
        ));
    }

    let rs = kernel
        .create_ruleset(ruleset.handled_access_fs().bits())
        .map_err(|e| {
            LandlockApplyError::from_sys(
                e,
                |errno| Kind::CreateRulesetFailed { errno },
                "landlock_create_ruleset failed",
            )
        })?;

    let mut report = LandlockApplyReport {
        rules_added: 0,
        file_rules: 0,
        skipped_empty: 0,
    };
    for (index, rule) in ruleset.rules().iter().enumerate() {
        let (fd, kind) = kernel.open_rule_path(&rule.path).map_err(|e| match e {
            OpenError::Symlink => LandlockApplyError::new(
                ErrorCode::FailedPrecondition,
                Kind::SymlinkRejected { index },
                "rule path resolves to a symlink",
            ),
            OpenError::Invalid => LandlockApplyError::new(
                ErrorCode::Internal,
                Kind::Internal,
                "rule path could not be opened safely",
            ),
            OpenError::Sys(s) => LandlockApplyError::from_sys(
                s,
                |errno| Kind::OpenPathFailed { index, errno },
                "failed to open rule path",
            ),
        })?;
        let allowed = effective_allowed(rule, kind);
        if kind == PathKind::File {
            report.file_rules += 1;
        }
        if allowed.is_empty() {
            // 空の権利は ENOMSG になる。何も許可しない（配下を全拒否）のと同じ意味なので追加しない。
            report.skipped_empty += 1;
            continue;
        }
        kernel.add_rule(&rs, allowed.bits(), &fd).map_err(|e| {
            LandlockApplyError::from_sys(
                e,
                |errno| Kind::AddRuleFailed { index, errno },
                "landlock_add_rule failed",
            )
        })?;
        report.rules_added += 1;
    }

    kernel.restrict_self(&rs).map_err(|e| {
        LandlockApplyError::from_sys(
            e,
            |errno| Kind::RestrictSelfFailed { errno },
            "landlock_restrict_self failed",
        )
    })?;
    if kernel.thread_count() != Some(1) {
        return Err(LandlockApplyError::new(
            ErrorCode::Internal,
            Kind::BecameMultiThreaded,
            "thread count changed while applying Landlock",
        ));
    }
    Ok(report)
}

/// 非ディレクトリにはディレクトリ専用の権利を付けない（付けると `landlock_add_rule` が `EINVAL`）。
fn effective_allowed(rule: &PathRule, kind: PathKind) -> AccessFs {
    match kind {
        PathKind::Dir => rule.allowed,
        PathKind::File => rule.allowed.intersection(AccessFs::FILE_COMPATIBLE),
    }
}

/// [`observe_landlock_enforcement`] の観測結果。errno は成功なら `None`。
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LandlockEnforcementObservation {
    /// 適用を呼ぶ直前の `NO_NEW_PRIVS`（継承で既に立っている環境もある）。
    pub no_new_privs_before: bool,
    /// ABI 検出が拒否した理由コード（`set_nnp = true` のとき。拒否なら適用は呼ばない）。
    pub detect_error: Option<&'static str>,
    /// 適用の失敗（成功なら `None`。検出拒否で適用しなかった場合も `None`）。
    pub apply_error: Option<LandlockApplyError>,
    /// 適用に成功したか。
    pub applied: bool,
    /// 適用後に `probe_dir` へファイルを作成した errno（成功なら `None`）。
    pub create_after: Option<i32>,
    /// 適用後に `probe_dir` の既存ファイルを読めたか。
    pub read_after: bool,
}

/// 本番の適用経路（[`apply_landlock_ruleset`]）を呼び出しスレッドへ適用し、遮断を観測する
/// （CORE-5・TASK-39.3・#183。結合試験専用）。
///
/// 適用は不可逆・単一スレッド前提のため、`tests/landlock_enforcement.rs`（`harness = false`）から
/// 使い捨ての子プロセスの中で呼ぶ。`unsafe` を `sys` の外へ出さないため syscall はここで肩代わりする。
/// - `set_nnp = false`: `NO_NEW_PRIVS` を立てずに適用を試み、前提検証で拒否されることを観測する
///   （カーネル版数に依存しない）
/// - `set_nnp = true`: NNP を立て、ABI 検出に成功すれば「`/` に読み取りのみ」の ruleset を適用し、
///   `probe_dir` への作成が `EACCES`・既存ファイルの読み取りが成功することを観測する。検出が拒否したら
///   その理由を返し、適用しない（fail-closed）
///
/// 通常の利用者は呼ばない。`probe_dir` は呼び出し側が用意した書き込み可能なディレクトリ。
#[doc(hidden)]
pub fn observe_landlock_enforcement(
    probe_dir: &Path,
    set_nnp: bool,
) -> Result<LandlockEnforcementObservation, LandlockApplyError> {
    let fail =
        |m: &str| LandlockApplyError::new(ErrorCode::Internal, LandlockApplyErrorKind::Internal, m);
    if set_nnp {
        sys::set_no_new_privs().map_err(|_| fail("failed to set no_new_privs"))?;
    }
    let no_new_privs_before = sys::no_new_privs_enabled().unwrap_or(false);
    let existing = probe_dir.join("existing");
    std::fs::write(&existing, b"probe").map_err(|_| fail("failed to create probe file"))?;

    let abi = if set_nnp {
        match super::detect_landlock_abi() {
            Ok(support) => support.abi.get(),
            Err(e) => {
                return Ok(LandlockEnforcementObservation {
                    no_new_privs_before,
                    detect_error: Some(e.reason.as_str()),
                    apply_error: None,
                    applied: false,
                    create_after: None,
                    read_after: false,
                });
            }
        }
    } else {
        super::MIN_LANDLOCK_ABI
    };
    let ruleset = LandlockRuleset::for_observation(
        abi,
        vec![PathRule {
            path: RulePath::Root,
            allowed: AccessFs::READ,
            origin: RuleOrigin::Root,
        }],
    );
    let result = apply_landlock_ruleset(&ruleset);
    let applied = result.is_ok();
    let apply_error = result.err();
    let create_after = match std::fs::File::create(probe_dir.join("after")) {
        Ok(_) => None,
        Err(e) => Some(e.raw_os_error().unwrap_or(-1)),
    };
    let read_after = std::fs::read(&existing).is_ok_and(|b| b == b"probe");
    Ok(LandlockEnforcementObservation {
        no_new_privs_before,
        detect_error: None,
        apply_error,
        applied,
        create_after,
        read_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::landlock::rules::LandlockRuleset;
    use std::cell::RefCell;

    /// 呼び出し記録つきの偽カーネル。
    struct Fake {
        calls: RefCell<Vec<String>>,
        nnp: Result<bool, SysError>,
        /// `thread_count` の応答を呼び出し順に返す（尽きたら最後の値）。
        threads: RefCell<Vec<Option<u64>>>,
        create: Result<(), SysError>,
        open: Vec<Result<PathKind, OpenError>>,
        add: Result<(), SysError>,
        restrict: Result<(), SysError>,
    }

    impl Fake {
        fn ok(n_paths: usize) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                nnp: Ok(true),
                threads: RefCell::new(vec![Some(1)]),
                create: Ok(()),
                open: vec![Ok(PathKind::Dir); n_paths],
                add: Ok(()),
                restrict: Ok(()),
            }
        }
        fn log(&self, s: impl Into<String>) {
            self.calls.borrow_mut().push(s.into());
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl LandlockKernel for Fake {
        type Ruleset = ();
        type PathFd = usize;
        fn thread_count(&self) -> Option<u64> {
            self.log("threads");
            let mut t = self.threads.borrow_mut();
            if t.len() > 1 { t.remove(0) } else { t[0] }
        }
        fn no_new_privs_enabled(&self) -> Result<bool, SysError> {
            self.log("nnp");
            self.nnp
        }
        fn create_ruleset(&self, handled: u64) -> Result<(), SysError> {
            self.log(format!("create:{handled:#x}"));
            self.create
        }
        fn open_rule_path(&self, path: &RulePath) -> Result<(usize, PathKind), OpenError> {
            let idx = self
                .calls
                .borrow()
                .iter()
                .filter(|c| c.starts_with("open"))
                .count();
            self.log(format!("open:{}", path.as_str()));
            self.open[idx].map(|k| (idx, k))
        }
        fn add_rule(&self, _: &(), allowed: u64, path: &usize) -> Result<(), SysError> {
            self.log(format!("add:{path}:{allowed:#x}"));
            self.add
        }
        fn restrict_self(&self, _: &()) -> Result<(), SysError> {
            self.log("restrict");
            self.restrict
        }
    }

    /// 実体の解決は偽カーネルが決めるため、パスはすべて `RulePath::Root` で足りる（権利だけを変える）。
    fn rs(rights: &[AccessFs]) -> LandlockRuleset {
        let rules = rights
            .iter()
            .enumerate()
            .map(|(i, a)| PathRule {
                path: RulePath::Root,
                allowed: *a,
                origin: if i == 0 {
                    RuleOrigin::Root
                } else {
                    RuleOrigin::Mount { index: i - 1 }
                },
            })
            .collect();
        LandlockRuleset::for_observation(6, rules)
    }

    /// CORE-5・TASK-39.3: NNP 未設定は何も呼ばずに `FailedPrecondition`（受入条件）。
    #[test]
    fn core5_apply_refuses_without_no_new_privs_before_any_syscall() {
        let mut k = Fake::ok(1);
        k.nnp = Ok(false);
        let e = apply_with(&k, &rs(&[AccessFs::READ])).expect_err("must refuse");
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.kind, LandlockApplyErrorKind::NoNewPrivsNotSet);
        assert_eq!(k.calls(), vec!["nnp"]);
    }

    /// CORE-5・TASK-39.3: NNP 問い合わせの失敗・マルチスレッドも ruleset 作成前に拒否する。
    #[test]
    fn core5_apply_refuses_on_query_failure_and_multithread() {
        let mut k = Fake::ok(1);
        k.nnp = Err(SysError::Os(sys::EPERM));
        let e = apply_with(&k, &rs(&[AccessFs::READ])).expect_err("refuse");
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert_eq!(
            e.kind,
            LandlockApplyErrorKind::NoNewPrivsQueryFailed { errno: sys::EPERM }
        );
        assert_eq!(k.calls(), vec!["nnp"]);

        for threads in [Some(2), None] {
            let k = Fake {
                threads: RefCell::new(vec![threads]),
                ..Fake::ok(1)
            };
            let e = apply_with(&k, &rs(&[AccessFs::READ])).expect_err("refuse");
            assert_eq!(e.kind, LandlockApplyErrorKind::NotSingleThreaded);
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(k.calls(), vec!["nnp", "threads"]);
        }
    }

    /// CORE-5・TASK-39.3: 正常系の呼び出し順は nnp → threads → create → (open → add) × n → restrict → threads。
    #[test]
    fn core5_apply_calls_kernel_in_order() {
        let k = Fake::ok(2);
        let set = rs(&[AccessFs::READ, AccessFs::ALL]);
        let r = apply_with(&k, &set).expect("applied");
        assert_eq!((r.rules_added, r.file_rules, r.skipped_empty), (2, 0, 0));
        assert_eq!(
            k.calls(),
            vec![
                "nnp".to_string(),
                "threads".into(),
                "create:0xffff".into(),
                "open:/".into(),
                "add:0:0xd".into(),
                "open:/".into(),
                "add:1:0xffff".into(),
                "restrict".into(),
                "threads".into(),
            ]
        );
    }

    /// CORE-5・TASK-39.3: ファイルでは権利を `FILE_COMPATIBLE` に絞り、空になれば追加しない。
    #[test]
    fn core5_apply_narrows_rights_for_files() {
        let mut k = Fake::ok(2);
        k.open = vec![Ok(PathKind::File), Ok(PathKind::File)];
        let set = rs(&[AccessFs::ALL, AccessFs::READ_DIR]);
        let r = apply_with(&k, &set).expect("applied");
        assert_eq!((r.rules_added, r.file_rules, r.skipped_empty), (1, 2, 1));
        let want = AccessFs::FILE_COMPATIBLE.bits();
        assert!(k.calls().contains(&format!("add:0:{want:#x}")));
        assert!(!k.calls().iter().any(|c| c.starts_with("add:1")));
    }

    /// CORE-5・TASK-39.3: symlink は拒否、不在は `OpenPathFailed`（スキップしない）。
    #[test]
    fn core5_apply_rejects_symlink_and_missing_paths() {
        let mut k = Fake::ok(2);
        k.open = vec![Ok(PathKind::Dir), Err(OpenError::Symlink)];
        let e = apply_with(&k, &rs(&[AccessFs::READ, AccessFs::READ])).expect_err("symlink");
        assert_eq!(e.kind, LandlockApplyErrorKind::SymlinkRejected { index: 1 });
        assert!(!k.calls().contains(&"restrict".to_string()));

        let mut k = Fake::ok(1);
        k.open = vec![Err(OpenError::Sys(SysError::Os(sys::ENOENT)))];
        let e = apply_with(&k, &rs(&[AccessFs::READ])).expect_err("missing");
        assert_eq!(
            e.kind,
            LandlockApplyErrorKind::OpenPathFailed {
                index: 0,
                errno: sys::ENOENT
            }
        );
        assert_eq!(e.code, ErrorCode::Internal);
    }

    /// CORE-5・TASK-39.3: add / restrict / create の errno がコードへ写る。
    #[test]
    fn core5_apply_maps_errno_to_codes() {
        let set = rs(&[AccessFs::READ]);
        let cases = [
            (SysError::Os(sys::EPERM), ErrorCode::PermissionDenied),
            (SysError::Os(sys::EINVAL), ErrorCode::FailedPrecondition),
            (SysError::Os(sys::ENOENT), ErrorCode::Internal),
            (SysError::Unsupported, ErrorCode::Unimplemented),
        ];
        for (err, code) in cases {
            let mut k = Fake::ok(1);
            k.add = Err(err);
            let e = apply_with(&k, &set).expect_err("add");
            assert_eq!(e.code, code);
            assert!(matches!(
                e.kind,
                LandlockApplyErrorKind::AddRuleFailed { index: 0, .. }
                    | LandlockApplyErrorKind::UnsupportedArchitecture
            ));

            let mut k = Fake::ok(1);
            k.restrict = Err(err);
            assert_eq!(apply_with(&k, &set).expect_err("restrict").code, code);

            let mut k = Fake::ok(1);
            k.create = Err(err);
            let e = apply_with(&k, &set).expect_err("create");
            assert_eq!(e.code, code);
            assert!(!k.calls().iter().any(|c| c.starts_with("open")));
        }
    }

    /// CORE-5・TASK-39.3: 適用後にスレッドが増えていたら `Internal`。
    #[test]
    fn core5_apply_detects_thread_growth() {
        let k = Fake {
            threads: RefCell::new(vec![Some(1), Some(2)]),
            ..Fake::ok(1)
        };
        let e = apply_with(&k, &rs(&[AccessFs::READ])).expect_err("grew");
        assert_eq!(e.kind, LandlockApplyErrorKind::BecameMultiThreaded);
        assert_eq!(e.code, ErrorCode::Internal);
    }

    /// CORE-5・TASK-39.3: `Display` と `as_str` の具体値。
    #[test]
    fn core5_apply_error_display_and_reason_codes() {
        let e = LandlockApplyError::new(
            ErrorCode::FailedPrecondition,
            LandlockApplyErrorKind::NoNewPrivsNotSet,
            "no_new_privs is not set; refusing to apply Landlock",
        );
        assert_eq!(
            e.to_string(),
            "FAILED_PRECONDITION: no_new_privs is not set; refusing to apply Landlock (no_new_privs_not_set)"
        );
        assert_eq!(
            LandlockApplyErrorKind::AddRuleFailed { index: 3, errno: 1 }.as_str(),
            "landlock_add_rule_failed"
        );
        assert_eq!(
            LandlockApplyErrorKind::RestrictSelfFailed { errno: 1 }.as_str(),
            "landlock_restrict_self_failed"
        );
    }
}
