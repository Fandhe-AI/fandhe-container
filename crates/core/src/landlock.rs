//! Landlock ABI 検出と fail-closed 判定（CORE-5・TASK-39.1・#181。Linux 限定）。
//!
//! # 役割
//!
//! CORE-5 は Landlock（Linux 6.12+・ABI 6+）によるパス単位のアクセス制御を要求する。
//! 本モジュールは実行中カーネルの Landlock ABI を問い合わせ、ABI 6 未満・Landlock 無効・
//! 応答不正のいずれでも起動を拒否する明示エラー（[`LandlockError`]）を返す。
//! 「Landlock 無しで黙って続行」する経路を作らない（fail-closed）。
//!
//! # 呼び出し文脈・契約
//!
//! - ステージ列の Landlock 段（`exec/landlock.rs`・#184・TASK-39.4。適用は #183 の `apply` が担う）や
//!   CLI / supervisor の事前チェックから呼ぶ。`ExecError` / `IsolationStage` への写像は `exec/landlock.rs`
//!   が行い、本モジュールは `ErrorCode` までを決める
//! - 検出した ABI は #182（TASK-39.2。`rules` 子モジュール）が handled access のマスク選択に使う
//! - syscall は `crate::sys::landlock_abi_version` のみ（読み取り専用の問い合わせ。権限を変えない）
//! - ABI 不足は環境の前提条件違反であり、分離違反の試行ではないため SEC-4 の監査ログ対象にしない
//!
//! # 未実装範囲（REPAIR-3）
//!
//! ステージ列への組み込み口（`StagePipeline::with_landlock`・#184）は実装済みだが、本番 launcher からの呼び出しと
//! 制限適用の証跡（`LaunchReady`）は #1714 で配線済み。本モジュールは検出と拒否判定、純粋関数によるルール生成
//! （`rules` 子モジュール・#182）、ruleset の適用（`apply` 子モジュール・#183。`landlock_create_ruleset` →
//! `landlock_add_rule` → `landlock_restrict_self`）を提供する。適用関数 `apply_landlock_ruleset` は #184 の
//! `exec/landlock.rs` が呼ぶ前提で crate 内公開に留める。

use std::fmt;
use std::num::NonZeroU32;

mod apply;
mod rules;
pub use apply::{
    LandlockApplyError, LandlockApplyErrorKind, LandlockApplyReport,
    LandlockEnforcementObservation, observe_landlock_enforcement,
};
pub(crate) use apply::{apply_landlock_ruleset, apply_landlock_ruleset_with};
pub use rules::{
    AccessFs, LandlockRuleError, LandlockRuleErrorKind, LandlockRuleset, MAX_LANDLOCK_RULES,
    PathRule, RuleOrigin, RulePath, ShadowedRestriction, build_path_rules,
    build_path_rules_with_dev, path_rules_from_config,
};

use crate::sys::{self, SysError};
use crate::traits::ErrorCode;

/// 必須の最小 Landlock ABI（CORE-5: Linux 6.12+・ABI 6+）。
pub const MIN_LANDLOCK_ABI: u32 = 6;

/// Landlock ABI バージョン。0 を表現できない（壊れた値を作れない）newtype。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockAbi(NonZeroU32);

impl LandlockAbi {
    /// ABI 番号を返す（常に 1 以上）。
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

/// 検出結果。ABI が要件（[`MIN_LANDLOCK_ABI`]）を満たす場合のみ得られる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LandlockSupport {
    /// カーネルが報告した ABI。#182 が handled access のマスク選択に使う。
    pub abi: LandlockAbi,
    /// 要求した最小 ABI。
    pub required: LandlockAbi,
}

/// 起動を拒否する理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LandlockUnavailable {
    /// カーネルに syscall が無い（`ENOSYS`）。
    KernelLacksLandlock,
    /// ビルド済みだが起動時に無効化されている（`EOPNOTSUPP`）。
    DisabledAtBoot,
    /// ABI が要件未満（1 以上）。
    AbiTooOld {
        /// 検出した ABI。
        detected: u32,
        /// 要求 ABI。
        required: u32,
    },
    /// カーネルが 0 を返した（仕様上ありえない応答）。
    InvalidKernelResponse {
        /// 生の戻り値。
        raw: u32,
    },
    /// 対応外アーキテクチャ。
    UnsupportedArchitecture,
    /// 上記以外の errno。
    ProbeFailed {
        /// errno 値。
        errno: i32,
    },
}

impl LandlockUnavailable {
    /// 機械可読な理由コード。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KernelLacksLandlock => "kernel_lacks_landlock",
            Self::DisabledAtBoot => "landlock_disabled_at_boot",
            Self::AbiTooOld { .. } => "landlock_abi_too_old",
            Self::InvalidKernelResponse { .. } => "invalid_kernel_response",
            Self::UnsupportedArchitecture => "unsupported_architecture",
            Self::ProbeFailed { .. } => "landlock_probe_failed",
        }
    }
}

/// Landlock 要件を満たせず起動を拒否する明示エラー（機械可読な `code` / `reason` と英語 `message`）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LandlockError {
    /// 構造化エラーコード（ERR 系）。
    pub code: ErrorCode,
    /// 拒否理由。
    pub reason: LandlockUnavailable,
    /// 人間向け説明（英語）。
    pub message: String,
}

impl fmt::Display for LandlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ({})",
            self.code.as_str(),
            self.message,
            self.reason.as_str()
        )
    }
}

impl std::error::Error for LandlockError {}

impl LandlockError {
    fn new(reason: LandlockUnavailable) -> Self {
        let (code, message) = match reason {
            LandlockUnavailable::KernelLacksLandlock => (
                ErrorCode::FailedPrecondition,
                "kernel does not provide Landlock (ENOSYS); refusing to start".to_string(),
            ),
            LandlockUnavailable::DisabledAtBoot => (
                ErrorCode::FailedPrecondition,
                "Landlock is disabled at boot (EOPNOTSUPP); refusing to start".to_string(),
            ),
            LandlockUnavailable::AbiTooOld { detected, required } => (
                ErrorCode::FailedPrecondition,
                format!(
                    "Landlock ABI {detected} is older than required ABI {required}; refusing to start"
                ),
            ),
            LandlockUnavailable::InvalidKernelResponse { raw } => (
                ErrorCode::Internal,
                format!("kernel returned invalid Landlock ABI value {raw}"),
            ),
            LandlockUnavailable::UnsupportedArchitecture => (
                ErrorCode::Unimplemented,
                "Landlock probe is not supported on this architecture".to_string(),
            ),
            LandlockUnavailable::ProbeFailed { errno } => (
                ErrorCode::Internal,
                format!("Landlock ABI probe failed with errno {errno}"),
            ),
        };
        Self {
            code,
            reason,
            message,
        }
    }
}

/// ABI 問い合わせの差し込み点（テストで戻り値をモックする。`exec/capabilities.rs` の `CapKernel` と同型）。
trait AbiProbe {
    fn abi_version(&mut self) -> Result<u32, SysError>;
}

/// 本番実装。`crate::sys` のラッパーを呼ぶだけ。
struct RealProbe;

impl AbiProbe for RealProbe {
    fn abi_version(&mut self) -> Result<u32, SysError> {
        sys::landlock_abi_version()
    }
}

/// 生の ABI 値を評価する（純粋関数）。[`MIN_LANDLOCK_ABI`] 以上のみ `Ok`。
pub(crate) fn evaluate_abi(raw: u32) -> Result<LandlockSupport, LandlockError> {
    let (Some(abi), Some(required)) = (NonZeroU32::new(raw), NonZeroU32::new(MIN_LANDLOCK_ABI))
    else {
        return Err(LandlockError::new(
            LandlockUnavailable::InvalidKernelResponse { raw },
        ));
    };
    if raw < MIN_LANDLOCK_ABI {
        return Err(LandlockError::new(LandlockUnavailable::AbiTooOld {
            detected: raw,
            required: MIN_LANDLOCK_ABI,
        }));
    }
    Ok(LandlockSupport {
        abi: LandlockAbi(abi),
        required: LandlockAbi(required),
    })
}

fn detect_with(probe: &mut impl AbiProbe) -> Result<LandlockSupport, LandlockError> {
    match probe.abi_version() {
        Ok(raw) => evaluate_abi(raw),
        Err(SysError::Unsupported) => Err(LandlockError::new(
            LandlockUnavailable::UnsupportedArchitecture,
        )),
        Err(SysError::Os(e)) if e == sys::ENOSYS => {
            Err(LandlockError::new(LandlockUnavailable::KernelLacksLandlock))
        }
        Err(SysError::Os(e)) if e == sys::EOPNOTSUPP => {
            Err(LandlockError::new(LandlockUnavailable::DisabledAtBoot))
        }
        Err(SysError::Os(errno)) => Err(LandlockError::new(LandlockUnavailable::ProbeFailed {
            errno,
        })),
        // 本問い合わせでは発生しない分類。未知の失敗も必ず拒否側へ倒す。
        Err(SysError::MultiThreaded) => Err(LandlockError::new(LandlockUnavailable::ProbeFailed {
            errno: 0,
        })),
    }
}

/// 実行中カーネルの Landlock ABI を検出する。ABI 6 以上以外はすべて `Err`（fail-closed。CORE-5）。
///
/// 読み取り専用の問い合わせで副作用は無い。
pub fn detect_landlock_abi() -> Result<LandlockSupport, LandlockError> {
    detect_with(&mut RealProbe)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(Result<u32, SysError>);
    impl AbiProbe for Fake {
        fn abi_version(&mut self) -> Result<u32, SysError> {
            self.0
        }
    }

    fn run(r: Result<u32, SysError>) -> Result<LandlockSupport, LandlockError> {
        detect_with(&mut Fake(r))
    }

    fn err(r: Result<u32, SysError>) -> LandlockError {
        run(r).expect_err("must be rejected")
    }

    #[test]
    fn core5_abi6_is_accepted() {
        let s = run(Ok(6)).expect("abi 6 accepted");
        assert_eq!(s.abi.get(), 6);
        assert_eq!(s.required.get(), 6);
    }

    #[test]
    fn core5_abi7_and_max_are_accepted() {
        assert_eq!(run(Ok(7)).expect("abi 7").abi.get(), 7);
        assert_eq!(evaluate_abi(u32::MAX).expect("max").abi.get(), u32::MAX);
    }

    #[test]
    fn core5_min_abi_is_6() {
        assert_eq!(MIN_LANDLOCK_ABI, 6);
    }

    #[test]
    fn core5_abi5_and_abi1_fail_closed() {
        for n in [1u32, 5] {
            let e = err(Ok(n));
            assert_eq!(e.code, ErrorCode::FailedPrecondition);
            assert_eq!(
                e.reason,
                LandlockUnavailable::AbiTooOld {
                    detected: n,
                    required: 6
                }
            );
        }
    }

    #[test]
    fn core5_abi0_is_invalid_response() {
        let e = err(Ok(0));
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(
            e.reason,
            LandlockUnavailable::InvalidKernelResponse { raw: 0 }
        );
    }

    #[test]
    fn core5_enosys_and_eopnotsupp_fail_closed() {
        let e = err(Err(SysError::Os(sys::ENOSYS)));
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.reason, LandlockUnavailable::KernelLacksLandlock);
        let e = err(Err(SysError::Os(sys::EOPNOTSUPP)));
        assert_eq!(e.code, ErrorCode::FailedPrecondition);
        assert_eq!(e.reason, LandlockUnavailable::DisabledAtBoot);
    }

    #[test]
    fn core5_other_errno_and_unsupported_arch() {
        let e = err(Err(SysError::Os(sys::EPERM)));
        assert_eq!(e.code, ErrorCode::Internal);
        assert_eq!(
            e.reason,
            LandlockUnavailable::ProbeFailed { errno: sys::EPERM }
        );
        let e = err(Err(SysError::Unsupported));
        assert_eq!(e.code, ErrorCode::Unimplemented);
        assert_eq!(e.reason, LandlockUnavailable::UnsupportedArchitecture);
    }

    #[test]
    fn core5_display_and_reason_codes() {
        let e = err(Ok(5));
        let text = e.to_string();
        assert!(text.starts_with("FAILED_PRECONDITION: "), "{text}");
        assert!(text.ends_with("(landlock_abi_too_old)"), "{text}");
        assert_eq!(
            LandlockUnavailable::KernelLacksLandlock.as_str(),
            "kernel_lacks_landlock"
        );
        assert_eq!(
            LandlockUnavailable::DisabledAtBoot.as_str(),
            "landlock_disabled_at_boot"
        );
    }

    /// 実機の生結果から期待値を導いて `detect_landlock_abi` と照合する（カーネル版数に依存しない）。
    #[test]
    fn core5_detect_matches_raw_probe() {
        let actual = detect_landlock_abi();
        match sys::landlock_abi_version() {
            Ok(n) if n >= 6 => assert_eq!(actual.expect("ok").abi.get(), n),
            Ok(n @ 1..=5) => assert_eq!(
                actual.expect_err("too old").reason,
                LandlockUnavailable::AbiTooOld {
                    detected: n,
                    required: 6
                }
            ),
            Err(SysError::Os(e)) if e == sys::ENOSYS => assert_eq!(
                actual.expect_err("enosys").reason,
                LandlockUnavailable::KernelLacksLandlock
            ),
            Err(SysError::Os(e)) if e == sys::EOPNOTSUPP => assert_eq!(
                actual.expect_err("disabled").reason,
                LandlockUnavailable::DisabledAtBoot
            ),
            // seccomp 等で syscall が制限された環境・対応外アーキテクチャでも実装は拒否理由を返す。
            Err(SysError::Os(e)) => assert_eq!(
                actual.expect_err("probe failed").reason,
                LandlockUnavailable::ProbeFailed { errno: e }
            ),
            Err(SysError::Unsupported) => assert_eq!(
                actual.expect_err("unsupported arch").reason,
                LandlockUnavailable::UnsupportedArchitecture
            ),
            other => {
                // 0 応答・MultiThreaded は実 syscall では発生しない。必ず拒否側へ倒れることだけ確認する。
                assert!(actual.is_err(), "unexpected raw probe result: {other:?}");
            }
        }
    }

    #[test]
    #[ignore = "requires Landlock ABI >= 6 (Linux 6.12+). CORE-5"]
    fn core5_detect_requires_abi6_on_real_host() {
        let s = detect_landlock_abi().expect("Landlock ABI >= 6 required");
        assert!(s.abi.get() >= 6);
    }
}
