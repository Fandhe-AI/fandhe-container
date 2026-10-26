//! `doctor` の Landlock ABI の診断: rootless の `start` が前提にする下限と、`--audit-policy strict` が前提にする
//! 監査の下限に対して、実行中カーネルの Landlock ABI を示す（CORE-5・SEC-4・#2761）。
//!
//! `start`（core の本番 launcher）は Landlock ABI 6 以上が無いと起動を拒否し（`core::landlock::MIN_LANDLOCK_ABI`）、
//! ABI 7 未満では拒否の監査ログ制御フラグを渡せず監査が縮退する（`MIN_LANDLOCK_AUDIT_ABI`。`start --audit-policy strict`
//! はその縮退を理由に起動を拒否する）。利用者が `start` の失敗まで知れないため、本モジュールが同じ検出を読み取り専用で示す。
//!
//! # `start` との一致
//! 検出は core の `landlock::detect_landlock_abi`（読み取り専用の問い合わせ 1 回）をそのまま使い、CLI 側に規則を書き直さない。
//! 下限の値も core の定数を参照する。
//!
//! # 構成と出力
//! - 事実の収集（[`collect`]。検出は Linux のみ）と評価（[`evaluate`]。純粋関数で全 OS で単体テストできる）を分ける。
//! - 出力は他の check と同じ JSON Lines の項目（`severity`・`code`・`message`・`remediation`・`check`・`state`）に、
//!   数値の `abi`（分からないときは `null`）・`required`・`audit_required` を足した 1 行。errno・パスなどホスト固有の値は載せない（REPAIR-4）。
//! - 終了ステータス: ABI が下限未満・無効・未対応なら Warning（3）、判定できなければ判定不能（4）、それ以外は 0。
//!   ABI 6 のみ（監査の下限未満）は `start` が通るため通知で、0 に寄与する。
//! - 非 Linux は対象外（出力なし）。`doctor` の `run` が最後に評価して書き出す。

use super::DoctorExitStatus;
use crate::json::json_escape;

/// 実行中カーネルの Landlock の検出結果（ホスト固有の値は持たない）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockProbeState {
    /// ABI が `start` の下限以上。値は検出した ABI。
    Supported {
        /// 検出した ABI。
        abi: u32,
    },
    /// ABI が `start` の下限未満（1 以上）。
    AbiTooOld {
        /// 検出した ABI。
        detected: u32,
    },
    /// カーネルに Landlock の syscall が無い。
    KernelLacksLandlock,
    /// ビルド済みだが起動時に無効化されている（`lsm=` に `landlock` が無い等）。
    DisabledAtBoot,
    /// 対応外アーキテクチャ。
    UnsupportedArchitecture,
    /// カーネルが仕様上ありえない応答（ABI 0）を返した。
    InvalidKernelResponse,
    /// 上記以外の失敗（未知の理由を含む。fail-closed で判定不能に倒す）。
    ProbeFailed,
    /// Linux 以外では対象外。
    Unsupported,
}

/// 評価の元になる事実。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockFindings {
    /// 検出結果。
    pub state: LandlockProbeState,
    /// `start` に要る ABI の下限（core の `MIN_LANDLOCK_ABI`）。
    pub required: u32,
    /// 拒否の監査ログ制御に要る ABI の下限（core の `MIN_LANDLOCK_AUDIT_ABI`）。
    pub audit_required: u32,
}

/// 評価結果の結論。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockOutcome {
    /// 問題なし（通知を含む）。
    Ok,
    /// `start` が通らない前提の不成立。
    Warning,
    /// 判定できなかった。
    Inconclusive,
    /// 対象外（非 Linux）。
    NotApplicable,
}

/// 診断 1 件（出力 1 行）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockDiagnostic {
    /// `warning` か `notice`。
    pub severity: &'static str,
    /// 機械可読なコード。
    pub code: &'static str,
    /// 人間向けの説明（英語。固定文言）。
    pub message: &'static str,
    /// 対処の案内（doctor 自身は設定を変更しない）。
    pub remediation: Vec<&'static str>,
    /// 状態の語彙。
    pub state: &'static str,
    /// 検出した ABI（分からないときは `None`）。
    pub abi: Option<u32>,
}

/// 評価結果。表示（[`LandlockReport::write_json_lines`]）と終了ステータス（[`LandlockReport::exit_status`]）の元になる。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockReport {
    /// 結論。
    pub outcome: LandlockOutcome,
    /// 診断（対象外では空）。
    pub diagnostics: Vec<LandlockDiagnostic>,
    /// `start` に要る ABI の下限。
    pub required: u32,
    /// 監査の下限。
    pub audit_required: u32,
}

const KERNEL_REMEDIATION: &str = "Use a kernel built with CONFIG_SECURITY_LANDLOCK (Linux 6.12 or later provides Landlock ABI 6 and 7 where available)";
const LSM_REMEDIATION: &str = "Include landlock in the kernel boot parameter lsm= (or CONFIG_LSM) so that Landlock is enabled at boot";

fn diag(
    severity: &'static str,
    code: &'static str,
    message: &'static str,
    remediation: Vec<&'static str>,
    state: &'static str,
    abi: Option<u32>,
) -> LandlockDiagnostic {
    LandlockDiagnostic {
        severity,
        code,
        message,
        remediation,
        state,
        abi,
    }
}

/// 事実から診断と結論を決める（純粋関数）。
pub fn evaluate(f: &LandlockFindings) -> LandlockReport {
    use LandlockProbeState as S;
    let (outcome, d) = match f.state {
        S::Supported { abi } if abi >= f.audit_required => (
            LandlockOutcome::Ok,
            Some(diag(
                "notice",
                "LANDLOCK_ABI_SUPPORTED",
                "the kernel Landlock ABI satisfies the requirements of start and of the strict audit policy",
                vec![],
                "supported",
                Some(abi),
            )),
        ),
        S::Supported { abi } => (
            LandlockOutcome::Ok,
            Some(diag(
                "notice",
                "LANDLOCK_AUDIT_ABI_TOO_OLD",
                "the kernel Landlock ABI satisfies start but is below the ABI needed to control Landlock denial logging",
                vec![
                    "start --audit-policy strict refuses to start on this kernel because the audit coverage is degraded (landlock_audit_abi_too_old); the default best-effort policy starts with a warning",
                    KERNEL_REMEDIATION,
                ],
                "audit_abi_too_old",
                Some(abi),
            )),
        ),
        S::AbiTooOld { detected } => (
            LandlockOutcome::Warning,
            Some(diag(
                "warning",
                "LANDLOCK_ABI_TOO_OLD",
                "the kernel Landlock ABI is below the minimum that start requires",
                vec![KERNEL_REMEDIATION],
                "abi_too_old",
                Some(detected),
            )),
        ),
        S::KernelLacksLandlock => (
            LandlockOutcome::Warning,
            Some(diag(
                "warning",
                "LANDLOCK_UNSUPPORTED",
                "the kernel does not provide Landlock; start refuses to run without it",
                vec![KERNEL_REMEDIATION],
                "kernel_lacks_landlock",
                None,
            )),
        ),
        S::DisabledAtBoot => (
            LandlockOutcome::Warning,
            Some(diag(
                "warning",
                "LANDLOCK_DISABLED",
                "Landlock is built into the kernel but disabled at boot; start refuses to run without it",
                vec![LSM_REMEDIATION],
                "disabled_at_boot",
                None,
            )),
        ),
        S::UnsupportedArchitecture => (
            LandlockOutcome::Warning,
            Some(diag(
                "warning",
                "LANDLOCK_UNSUPPORTED_ARCHITECTURE",
                "Landlock is not supported on this CPU architecture; start refuses to run without it",
                vec![],
                "unsupported_architecture",
                None,
            )),
        ),
        S::InvalidKernelResponse => (
            LandlockOutcome::Inconclusive,
            Some(diag(
                "notice",
                "LANDLOCK_CHECK_INCONCLUSIVE",
                "the kernel returned an invalid Landlock ABI response; the check is inconclusive",
                vec![],
                "invalid_kernel_response",
                None,
            )),
        ),
        S::ProbeFailed => (
            LandlockOutcome::Inconclusive,
            Some(diag(
                "notice",
                "LANDLOCK_CHECK_INCONCLUSIVE",
                "the Landlock ABI query failed; the check is inconclusive",
                vec![],
                "probe_failed",
                None,
            )),
        ),
        S::Unsupported => (LandlockOutcome::NotApplicable, None),
    };
    LandlockReport {
        outcome,
        diagnostics: d.into_iter().collect(),
        required: f.required,
        audit_required: f.audit_required,
    }
}

impl LandlockReport {
    /// 結論に対応する終了ステータス。
    pub fn exit_status(&self) -> DoctorExitStatus {
        match self.outcome {
            LandlockOutcome::Ok | LandlockOutcome::NotApplicable => DoctorExitStatus::Ok,
            LandlockOutcome::Warning => DoctorExitStatus::Warning,
            LandlockOutcome::Inconclusive => DoctorExitStatus::Inconclusive,
        }
    }

    /// 診断を 1 件 1 行の JSON Lines で書き出す（他の check の行に `abi`・`required`・`audit_required` を足した形）。
    pub fn write_json_lines(&self, w: &mut impl std::io::Write) -> std::io::Result<()> {
        for d in &self.diagnostics {
            let rem: Vec<String> = d
                .remediation
                .iter()
                .map(|r| format!("\"{}\"", json_escape(r)))
                .collect();
            let abi = match d.abi {
                Some(v) => v.to_string(),
                None => "null".to_string(),
            };
            writeln!(
                w,
                "{{\"severity\":\"{}\",\"code\":\"{}\",\"message\":\"{}\",\"remediation\":[{}],\"check\":\"landlock\",\"state\":\"{}\",\"abi\":{},\"required\":{},\"audit_required\":{}}}",
                d.severity,
                json_escape(d.code),
                json_escape(d.message),
                rem.join(","),
                json_escape(d.state),
                abi,
                self.required,
                self.audit_required,
            )?;
        }
        Ok(())
    }
}

/// `start` に要る ABI の下限（Linux は core の定数。非 Linux は core が Landlock を持たないため同値の固定値）。
#[cfg(target_os = "linux")]
const REQUIRED_ABI: u32 = fandhe_container_core::landlock::MIN_LANDLOCK_ABI;
#[cfg(not(target_os = "linux"))]
const REQUIRED_ABI: u32 = 6;

/// 事実を集める（読み取り専用の問い合わせ 1 回）。
#[cfg(target_os = "linux")]
pub fn collect() -> LandlockFindings {
    use fandhe_container_core::landlock::{LandlockUnavailable as U, detect_landlock_abi};
    let state = match detect_landlock_abi() {
        Ok(s) => LandlockProbeState::Supported { abi: s.abi.get() },
        Err(e) => match e.reason {
            U::AbiTooOld { detected, .. } => LandlockProbeState::AbiTooOld { detected },
            U::KernelLacksLandlock => LandlockProbeState::KernelLacksLandlock,
            U::DisabledAtBoot => LandlockProbeState::DisabledAtBoot,
            U::UnsupportedArchitecture => LandlockProbeState::UnsupportedArchitecture,
            U::InvalidKernelResponse { .. } => LandlockProbeState::InvalidKernelResponse,
            U::ProbeFailed { .. } => LandlockProbeState::ProbeFailed,
            // 未知の理由は Ok と断定せず判定不能に倒す（fail-closed）。
            _ => LandlockProbeState::ProbeFailed,
        },
    };
    LandlockFindings {
        state,
        required: REQUIRED_ABI,
        audit_required: fandhe_container_core::launch_isolation::MIN_LANDLOCK_AUDIT_ABI,
    }
}

/// 非 Linux は対象外。
#[cfg(not(target_os = "linux"))]
pub fn collect() -> LandlockFindings {
    LandlockFindings {
        state: LandlockProbeState::Unsupported,
        required: REQUIRED_ABI,
        audit_required: fandhe_container_core::launch_isolation::MIN_LANDLOCK_AUDIT_ABI,
    }
}

#[cfg(test)]
mod tests {
    use super::LandlockProbeState as S;
    use super::*;

    fn findings(state: S) -> LandlockFindings {
        LandlockFindings {
            state,
            required: 6,
            audit_required: 7,
        }
    }

    fn line(state: S) -> String {
        let mut buf = Vec::new();
        evaluate(&findings(state))
            .write_json_lines(&mut buf)
            .expect("write");
        String::from_utf8(buf).expect("utf8")
    }

    /// CORE-5・SEC-4: 各状態の JSON 1 行を完全一致で照合する（数値は `abi`・`required`・`audit_required`）。
    #[test]
    fn core5_doctor_landlock_json_lines() {
        assert_eq!(
            line(S::Supported { abi: 7 }),
            "{\"severity\":\"notice\",\"code\":\"LANDLOCK_ABI_SUPPORTED\",\"message\":\"the kernel Landlock ABI satisfies the requirements of start and of the strict audit policy\",\"remediation\":[],\"check\":\"landlock\",\"state\":\"supported\",\"abi\":7,\"required\":6,\"audit_required\":7}\n"
        );
        let l6 = line(S::Supported { abi: 6 });
        assert!(
            l6.contains("\"code\":\"LANDLOCK_AUDIT_ABI_TOO_OLD\""),
            "{l6}"
        );
        assert!(
            l6.contains(
                "\"state\":\"audit_abi_too_old\",\"abi\":6,\"required\":6,\"audit_required\":7}\n"
            ),
            "{l6}"
        );
        assert!(
            l6.contains("--audit-policy strict refuses to start"),
            "{l6}"
        );
        let l5 = line(S::AbiTooOld { detected: 5 });
        assert!(
            l5.starts_with("{\"severity\":\"warning\",\"code\":\"LANDLOCK_ABI_TOO_OLD\""),
            "{l5}"
        );
        assert!(
            l5.ends_with(
                "\"state\":\"abi_too_old\",\"abi\":5,\"required\":6,\"audit_required\":7}\n"
            ),
            "{l5}"
        );
        for (st, code, token) in [
            (
                S::KernelLacksLandlock,
                "LANDLOCK_UNSUPPORTED",
                "kernel_lacks_landlock",
            ),
            (S::DisabledAtBoot, "LANDLOCK_DISABLED", "disabled_at_boot"),
            (
                S::UnsupportedArchitecture,
                "LANDLOCK_UNSUPPORTED_ARCHITECTURE",
                "unsupported_architecture",
            ),
            (
                S::InvalidKernelResponse,
                "LANDLOCK_CHECK_INCONCLUSIVE",
                "invalid_kernel_response",
            ),
            (
                S::ProbeFailed,
                "LANDLOCK_CHECK_INCONCLUSIVE",
                "probe_failed",
            ),
        ] {
            let l = line(st);
            assert_eq!(l.matches('\n').count(), 1, "{l}");
            assert!(l.contains(&format!("\"code\":\"{code}\"")), "{l}");
            assert!(
                l.ends_with(&format!(
                    "\"state\":\"{token}\",\"abi\":null,\"required\":6,\"audit_required\":7}}\n"
                )),
                "{l}"
            );
        }
        assert_eq!(line(S::Unsupported), "");
    }

    /// CORE-5: 終了ステータスは Warning=3・判定不能=4・それ以外=0（ABI 6 のみの通知と対象外は 0）。
    #[test]
    fn core5_doctor_landlock_exit_status() {
        let code = |s: S| evaluate(&findings(s)).exit_status().code();
        assert_eq!(code(S::Supported { abi: 7 }), 0);
        assert_eq!(code(S::Supported { abi: 6 }), 0);
        assert_eq!(code(S::AbiTooOld { detected: 5 }), 3);
        assert_eq!(code(S::KernelLacksLandlock), 3);
        assert_eq!(code(S::DisabledAtBoot), 3);
        assert_eq!(code(S::UnsupportedArchitecture), 3);
        assert_eq!(code(S::InvalidKernelResponse), 4);
        assert_eq!(code(S::ProbeFailed), 4);
        assert_eq!(code(S::Unsupported), 0);
        assert_eq!(
            evaluate(&findings(S::Unsupported)).outcome,
            LandlockOutcome::NotApplicable
        );
    }

    /// CORE-5: 収集した下限は core の定数と一致し、検出結果は core の `detect_landlock_abi` の写しである。
    #[cfg(target_os = "linux")]
    #[test]
    fn core5_doctor_landlock_collect_matches_core() {
        use fandhe_container_core::landlock::{
            LandlockUnavailable as U, MIN_LANDLOCK_ABI, detect_landlock_abi,
        };
        let f = collect();
        assert_eq!(f.required, MIN_LANDLOCK_ABI);
        assert_eq!(f.audit_required, 7);
        match detect_landlock_abi() {
            Ok(s) => assert_eq!(f.state, S::Supported { abi: s.abi.get() }),
            Err(e) => {
                let want = match e.reason {
                    U::AbiTooOld { detected, .. } => S::AbiTooOld { detected },
                    U::KernelLacksLandlock => S::KernelLacksLandlock,
                    U::DisabledAtBoot => S::DisabledAtBoot,
                    U::UnsupportedArchitecture => S::UnsupportedArchitecture,
                    U::InvalidKernelResponse { .. } => S::InvalidKernelResponse,
                    _ => S::ProbeFailed,
                };
                assert_eq!(f.state, want);
            }
        }
    }
}
