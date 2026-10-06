//! コンテナ終了の分類と restart ポリシー評価（TASK-159.1・#487／TASK-159.2・#488・SUP-3・MS-9。関連: SUP-1・REPAIR-3）。
//!
//! [`crate::run::monitor`] が回収した [`ProcessExit`] を、正常終了・異常終了（非 0 終了コード）・
//! シグナル終了に分類する。分類結果は [`evaluate_restart`]（restart ポリシー `no` / `on-failure[:N]` /
//! `always` / `unless-stopped` の純粋な再起動要否判定）の入力になる。状態ファイルへ書く終了コードの写像
//! （`exit_code_of`）と `restart_count` を進める既定判定（`is_abnormal_exit`）もここに置く。
//!
//! # 未実装の将来仕様（REPAIR-3）
//! - 再 launch・バックオフ・`restart_count` の加算管理・state.json 反映・`run.rs` へのポリシー配線は
//!   未実装（#489・TASK-159.3。SUP-3）。[`evaluate_restart`] は現状どこからも呼ばれない。
//! - 明示的な stop の検知は SUP-9 の担当で、本モジュールは [`StopIntent`] を入力として受けるだけ。
//!   再 launch 時の `unless-stopped` と `always` の差（stop 済みを復帰させるか）も未実装（SUP-3・SUP-9）。
//!
//! # 外部入力の扱い
//! ポリシー文字列（将来 TOML・CLI から届く）は長さを上限検証し、完全一致と ASCII 数字のみの `N` だけを受理する
//! （`unwrap` / 添字アクセスなし。エラー文言に入力を埋め込まない）。
//! 終了状態はカーネル応答に由来するため、シグナル番号は範囲検証し、`128 + s` は `checked_add` で計算する
//! （panic しない）。回収済みの値だけを入力とし、記録済み pid への `kill` / `waitpid` は行わない（SEC-1）。

use std::num::NonZeroU32;
use std::str::FromStr;

use fandhe_container_core::oci_runtime::ProcessExit;
use fandhe_container_core::traits::{ErrorCode, Signal, TraitError};

/// 終了の分類結果（SUP-3・TASK-159.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitClass {
    /// 終了コード 0 の正常終了。
    Success,
    /// 非 0 の終了コードでの終了。
    Failure {
        /// 終了コード（負値を含み得る）。
        code: i32,
    },
    /// 有効範囲（1..=64）のシグナルによる終了。
    Signaled {
        /// 終了させたシグナル。
        signal: Signal,
    },
    /// 分類できない終了（範囲外のシグナル番号、または未知の終了種別）。
    Unknown,
}

impl ExitClass {
    /// 異常終了（`Failure` / `Signaled`）か。`Unknown` は根拠なく異常扱いしない。
    ///
    /// 範囲外シグナルは `Unknown` のため `false` だが、`restart_count` の既定判定
    /// `is_abnormal_exit` は従来どおり `true` とする（加算条件を変えないため）。
    pub fn is_abnormal(self) -> bool {
        matches!(self, ExitClass::Failure { .. } | ExitClass::Signaled { .. })
    }
}

/// 回収済みの終了状態を分類する。
pub fn classify_exit(exit: ProcessExit) -> ExitClass {
    match exit {
        ProcessExit::Exited(0) => ExitClass::Success,
        ProcessExit::Exited(code) => ExitClass::Failure { code },
        ProcessExit::Signaled(s) => u8::try_from(s)
            .ok()
            .and_then(|n| Signal::new(n).ok())
            .map_or(ExitClass::Unknown, |signal| ExitClass::Signaled { signal }),
        _ => ExitClass::Unknown,
    }
}

/// 終了状態を状態ファイルへ記録する終了コードへ写す（`Signaled(s)` は `128 + s`。あふれたら `None`）。
pub(crate) fn exit_code_of(exit: ProcessExit) -> Option<i32> {
    match exit {
        ProcessExit::Exited(c) => Some(c),
        ProcessExit::Signaled(s) => 128i32.checked_add(s),
        _ => None,
    }
}

/// 異常終了（非 0 終了・シグナル終了）か。`restart_count` を進める既定判定（TASK-157.5・SUP-3）。
///
/// シグナル終了は番号の範囲にかかわらず `true`（従来挙動）。未知の終了種別は加算しない。
/// ポリシー評価（[`evaluate_restart`]）への置き換え（#489・TASK-159.3）までの暫定判定。
pub(crate) fn is_abnormal_exit(exit: ProcessExit) -> bool {
    match exit {
        ProcessExit::Exited(c) => c != 0,
        ProcessExit::Signaled(_) => true,
        _ => false,
    }
}

/// ポリシー文字列の最大長（バイト）。外部入力の長さを先に検証する（DoS 防止）。
const MAX_POLICY_LEN: usize = 32;

/// restart ポリシー（SUP-3・TASK-159.2）。既定は `No`（設定が無ければ再起動しない。fail-closed）。
///
/// 4 ポリシーの名前のみ spec が定め、細部は Docker の慣行に合わせた解釈。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RestartPolicy {
    /// 再起動しない（`no`）。
    #[default]
    No,
    /// 異常終了（`Failure` / `Signaled`）のときのみ再起動する（`on-failure[:N]`）。
    OnFailure {
        /// 再起動回数の上限。`None` は無制限。`on-failure:0` は曖昧なためパーサが拒否する。
        max_retries: Option<NonZeroU32>,
    },
    /// 終了種別に関わらず再起動する（`always`）。
    Always,
    /// 明示的 stop を除き再起動する（`unless-stopped`）。
    UnlessStopped,
}

impl FromStr for RestartPolicy {
    type Err = TraitError;

    /// `no` / `always` / `unless-stopped` / `on-failure` / `on-failure:N`（N は 1 以上の `u32`）の完全一致のみ受理する。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || TraitError::new(ErrorCode::InvalidArgument, "invalid restart policy");
        if s.len() > MAX_POLICY_LEN {
            return Err(invalid());
        }
        match s.split_once(':') {
            None => match s {
                "no" => Ok(RestartPolicy::No),
                "always" => Ok(RestartPolicy::Always),
                "unless-stopped" => Ok(RestartPolicy::UnlessStopped),
                "on-failure" => Ok(RestartPolicy::OnFailure { max_retries: None }),
                _ => Err(invalid()),
            },
            Some(("on-failure", n)) => {
                if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(invalid());
                }
                let n = n.parse::<u32>().map_err(|_| invalid())?;
                let n = NonZeroU32::new(n).ok_or_else(invalid)?;
                Ok(RestartPolicy::OnFailure {
                    max_retries: Some(n),
                })
            }
            Some(_) => Err(invalid()),
        }
    }
}

/// 明示的 stop の有無（[`evaluate_restart`] の入力）。検知は SUP-9 の担当で、本モジュールは行わない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StopIntent {
    /// stop 要求なし。
    NotRequested,
    /// stop 要求あり。
    Requested,
}

/// 再起動要否の判定結果（SUP-3・TASK-159.2）。#489 がバックオフ等を足せるよう真偽値にしない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RestartDecision {
    /// 再起動する。
    Restart,
    /// 再起動しない。
    DoNotRestart {
        /// 再起動しない理由。
        reason: NoRestartReason,
    },
}

/// 再起動しない理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoRestartReason {
    /// ポリシーが `no`。
    PolicyNo,
    /// 正常終了（`on-failure`）。
    ExitedSuccessfully,
    /// `on-failure:N` の上限に達した。
    RetriesExhausted,
    /// 明示的 stop が要求された。
    ExplicitStop,
    /// 終了を分類できず異常と判断しない（`on-failure`）。
    UnclassifiedExit,
}

impl NoRestartReason {
    /// 構造化ログ向けの機械可読な識別子（REPAIR-4）。
    pub fn as_str(self) -> &'static str {
        match self {
            NoRestartReason::PolicyNo => "policy_no",
            NoRestartReason::ExitedSuccessfully => "exited_successfully",
            NoRestartReason::RetriesExhausted => "retries_exhausted",
            NoRestartReason::ExplicitStop => "explicit_stop",
            NoRestartReason::UnclassifiedExit => "unclassified_exit",
        }
    }
}

/// 終了検知後の再起動要否を判定する純粋関数（状態・I/O なし。SUP-3・TASK-159.2）。
///
/// 評価順: 明示的 stop（全ポリシーで再起動しない。Docker 互換）→ `no` → `always` / `unless-stopped`
/// （常に再起動）→ `on-failure`。このため終了検知時点では `always` と `unless-stopped` は同じ結果になり、
/// 差は再 launch 時の挙動（未実装。SUP-3・SUP-9）にある。
///
/// `restart_count` は「これまでに行った再起動の回数」として受ける。現状の `run.rs` は異常終了の検知回数として
/// 加算しており、意味の統一は #489（TASK-159.3）が行う。呼び出し元は未配線（同 #489）。
pub fn evaluate_restart(
    policy: RestartPolicy,
    exit: ExitClass,
    restart_count: u32,
    stop: StopIntent,
) -> RestartDecision {
    let no = |reason| RestartDecision::DoNotRestart { reason };
    if stop == StopIntent::Requested {
        return no(NoRestartReason::ExplicitStop);
    }
    match policy {
        RestartPolicy::No => no(NoRestartReason::PolicyNo),
        RestartPolicy::Always | RestartPolicy::UnlessStopped => RestartDecision::Restart,
        RestartPolicy::OnFailure { max_retries } => match exit {
            ExitClass::Success => no(NoRestartReason::ExitedSuccessfully),
            ExitClass::Unknown => no(NoRestartReason::UnclassifiedExit),
            ExitClass::Failure { .. } | ExitClass::Signaled { .. } => match max_retries {
                Some(n) if restart_count >= n.get() => no(NoRestartReason::RetriesExhausted),
                _ => RestartDecision::Restart,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(n: u8) -> ExitClass {
        ExitClass::Signaled {
            signal: Signal::new(n).expect("valid signal"),
        }
    }

    /// SUP-3・TASK-159.1: 終了コードの分類。
    #[test]
    fn sup3_task159_1_classify_exited() {
        assert_eq!(classify_exit(ProcessExit::Exited(0)), ExitClass::Success);
        assert_eq!(
            classify_exit(ProcessExit::Exited(1)),
            ExitClass::Failure { code: 1 }
        );
        assert_eq!(
            classify_exit(ProcessExit::Exited(255)),
            ExitClass::Failure { code: 255 }
        );
        assert_eq!(
            classify_exit(ProcessExit::Exited(-1)),
            ExitClass::Failure { code: -1 }
        );
    }

    /// SUP-3・TASK-159.1: シグナル種別の判別。
    #[test]
    fn sup3_task159_1_classify_signaled() {
        assert_eq!(
            classify_exit(ProcessExit::Signaled(9)),
            ExitClass::Signaled {
                signal: Signal::SIGKILL
            }
        );
        assert_eq!(
            classify_exit(ProcessExit::Signaled(15)),
            ExitClass::Signaled {
                signal: Signal::SIGTERM
            }
        );
        assert_eq!(classify_exit(ProcessExit::Signaled(64)), sig(64));
    }

    /// SUP-3・TASK-159.1: 範囲外シグナルは Unknown。
    #[test]
    fn sup3_task159_1_classify_out_of_range_signal() {
        for s in [0, 65, -1, i32::MAX] {
            assert_eq!(classify_exit(ProcessExit::Signaled(s)), ExitClass::Unknown);
        }
    }

    /// SUP-3・TASK-159.1: 状態ファイルへ書く終了コードの写像。
    #[test]
    fn sup3_task159_1_exit_code_of_table() {
        assert_eq!(exit_code_of(ProcessExit::Exited(0)), Some(0));
        assert_eq!(exit_code_of(ProcessExit::Exited(255)), Some(255));
        assert_eq!(exit_code_of(ProcessExit::Exited(-1)), Some(-1));
        assert_eq!(exit_code_of(ProcessExit::Signaled(9)), Some(137));
        assert_eq!(exit_code_of(ProcessExit::Signaled(15)), Some(143));
        assert_eq!(exit_code_of(ProcessExit::Signaled(64)), Some(192));
        assert_eq!(exit_code_of(ProcessExit::Signaled(0)), Some(128));
        assert_eq!(exit_code_of(ProcessExit::Signaled(65)), Some(193));
        assert_eq!(exit_code_of(ProcessExit::Signaled(-1)), Some(127));
        assert_eq!(exit_code_of(ProcessExit::Signaled(i32::MAX)), None);
    }

    /// SUP-3・TASK-159.1: 分類の異常判定と `is_abnormal_exit` の差（範囲外シグナルのみ）。
    #[test]
    fn sup3_task159_1_is_abnormal_vs_exit_default() {
        assert!(!classify_exit(ProcessExit::Exited(0)).is_abnormal());
        assert!(classify_exit(ProcessExit::Exited(1)).is_abnormal());
        assert!(classify_exit(ProcessExit::Signaled(15)).is_abnormal());
        assert!(!classify_exit(ProcessExit::Signaled(65)).is_abnormal());
        assert!(is_abnormal_exit(ProcessExit::Signaled(65)));
    }

    fn nz(n: u32) -> Option<NonZeroU32> {
        NonZeroU32::new(n)
    }

    fn dn(reason: NoRestartReason) -> RestartDecision {
        RestartDecision::DoNotRestart { reason }
    }

    fn ev(p: RestartPolicy, e: ExitClass, c: u32) -> RestartDecision {
        evaluate_restart(p, e, c, StopIntent::NotRequested)
    }

    fn all_exits() -> [ExitClass; 4] {
        [
            ExitClass::Success,
            ExitClass::Failure { code: 1 },
            sig(9),
            ExitClass::Unknown,
        ]
    }

    /// SUP-3・TASK-159.2: `no` は常に再起動しない。
    #[test]
    fn sup3_task159_2_policy_no() {
        for e in all_exits() {
            for c in [0, 5] {
                assert_eq!(ev(RestartPolicy::No, e, c), dn(NoRestartReason::PolicyNo));
            }
        }
    }

    /// SUP-3・TASK-159.2: `on-failure`（無制限）。
    #[test]
    fn sup3_task159_2_on_failure_unlimited() {
        let p = RestartPolicy::OnFailure { max_retries: None };
        assert_eq!(
            ev(p, ExitClass::Success, 0),
            dn(NoRestartReason::ExitedSuccessfully)
        );
        assert_eq!(
            ev(p, ExitClass::Unknown, 0),
            dn(NoRestartReason::UnclassifiedExit)
        );
        for e in [
            ExitClass::Failure { code: 1 },
            ExitClass::Failure { code: -1 },
            sig(15),
        ] {
            assert_eq!(ev(p, e, 0), RestartDecision::Restart);
            assert_eq!(ev(p, e, u32::MAX), RestartDecision::Restart);
        }
    }

    /// SUP-3・TASK-159.2: `on-failure:N` の上限。
    #[test]
    fn sup3_task159_2_on_failure_limited() {
        let p3 = RestartPolicy::OnFailure { max_retries: nz(3) };
        let f = ExitClass::Failure { code: 2 };
        for c in [0, 2] {
            assert_eq!(ev(p3, f, c), RestartDecision::Restart);
        }
        for c in [3, 4, u32::MAX] {
            assert_eq!(ev(p3, f, c), dn(NoRestartReason::RetriesExhausted));
        }
        assert_eq!(
            ev(p3, ExitClass::Success, 0),
            dn(NoRestartReason::ExitedSuccessfully)
        );
        let p1 = RestartPolicy::OnFailure { max_retries: nz(1) };
        assert_eq!(ev(p1, sig(9), 0), RestartDecision::Restart);
        assert_eq!(ev(p1, sig(9), 1), dn(NoRestartReason::RetriesExhausted));
    }

    /// SUP-3・TASK-159.2: `always` / `unless-stopped` は stop 要求なしなら常に再起動。
    #[test]
    fn sup3_task159_2_always_and_unless_stopped() {
        for p in [RestartPolicy::Always, RestartPolicy::UnlessStopped] {
            for e in all_exits() {
                for c in [0, u32::MAX] {
                    assert_eq!(ev(p, e, c), RestartDecision::Restart);
                }
            }
        }
    }

    /// SUP-3・TASK-159.2: stop 要求ありは全ポリシーで再起動しない。
    #[test]
    fn sup3_task159_2_explicit_stop() {
        let policies = [
            RestartPolicy::No,
            RestartPolicy::OnFailure { max_retries: None },
            RestartPolicy::OnFailure { max_retries: nz(3) },
            RestartPolicy::Always,
            RestartPolicy::UnlessStopped,
        ];
        for p in policies {
            for e in all_exits() {
                assert_eq!(
                    evaluate_restart(p, e, 0, StopIntent::Requested),
                    dn(NoRestartReason::ExplicitStop)
                );
            }
        }
    }

    /// SUP-3・TASK-159.2: `classify_exit` との連結（範囲外シグナルは Unknown）。
    #[test]
    fn sup3_task159_2_with_classify_exit() {
        let e = classify_exit(ProcessExit::Signaled(65));
        assert_eq!(
            ev(RestartPolicy::OnFailure { max_retries: None }, e, 0),
            dn(NoRestartReason::UnclassifiedExit)
        );
        assert_eq!(ev(RestartPolicy::Always, e, 0), RestartDecision::Restart);
    }

    /// SUP-3・TASK-159.2: ポリシー文字列の受理。
    #[test]
    fn sup3_task159_2_parse_accepts() {
        let cases = [
            ("no", RestartPolicy::No),
            ("always", RestartPolicy::Always),
            ("unless-stopped", RestartPolicy::UnlessStopped),
            ("on-failure", RestartPolicy::OnFailure { max_retries: None }),
            (
                "on-failure:1",
                RestartPolicy::OnFailure { max_retries: nz(1) },
            ),
            (
                "on-failure:4294967295",
                RestartPolicy::OnFailure {
                    max_retries: nz(u32::MAX),
                },
            ),
        ];
        for (s, want) in cases {
            assert_eq!(s.parse::<RestartPolicy>().expect(s), want);
        }
    }

    /// SUP-3・TASK-159.2: ポリシー文字列の拒否（`on-failure:0` は曖昧なため fail-closed）。
    #[test]
    fn sup3_task159_2_parse_rejects() {
        let long = "a".repeat(MAX_POLICY_LEN + 1);
        let cases = [
            "",
            "NO",
            " no",
            "no ",
            "always:1",
            "no:0",
            "on-failure:",
            "on-failure:0",
            "on-failure:-1",
            "on-failure:+1",
            "on-failure:1x",
            "on-failure:4294967296",
            "on-failure:1:2",
            "restart",
            long.as_str(),
        ];
        for s in cases {
            let err = s.parse::<RestartPolicy>().expect_err(s);
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{s}");
        }
    }

    /// SUP-3・TASK-159.2: 既定値と理由の識別子。
    #[test]
    fn sup3_task159_2_default_and_reason_strings() {
        assert_eq!(RestartPolicy::default(), RestartPolicy::No);
        assert_eq!(NoRestartReason::PolicyNo.as_str(), "policy_no");
        assert_eq!(
            NoRestartReason::ExitedSuccessfully.as_str(),
            "exited_successfully"
        );
        assert_eq!(
            NoRestartReason::RetriesExhausted.as_str(),
            "retries_exhausted"
        );
        assert_eq!(NoRestartReason::ExplicitStop.as_str(), "explicit_stop");
        assert_eq!(
            NoRestartReason::UnclassifiedExit.as_str(),
            "unclassified_exit"
        );
    }
}
