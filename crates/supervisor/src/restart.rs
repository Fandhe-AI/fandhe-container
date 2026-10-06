//! コンテナ終了の分類（restart 判定の入力。TASK-159.1・#487・SUP-3・MS-9。関連: SUP-1・REPAIR-3）。
//!
//! [`crate::run::monitor`] が回収した [`ProcessExit`] を、正常終了・異常終了（非 0 終了コード）・
//! シグナル終了に分類する。分類結果は restart ポリシー評価（#488・TASK-159.2）の入力になり、
//! 状態ファイルへ書く終了コードの写像（`exit_code_of`）と `restart_count` を進める既定判定
//! （`is_abnormal_exit`）もここに置く。
//!
//! # 未実装の将来仕様（REPAIR-3）
//! ポリシー `no` / `on-failure[:N]` / `always` / `unless-stopped` の評価・再 launch・バックオフは
//! 未実装（#488・#489。TASK-159.2・TASK-159.3）。明示的な stop との区別は SUP-9 の担当で、
//! 本モジュールは持ち込まない。
//!
//! # 外部入力の扱い
//! 終了状態はカーネル応答に由来するため、シグナル番号は範囲検証し、`128 + s` は `checked_add` で計算する
//! （panic しない）。回収済みの値だけを入力とし、記録済み pid への `kill` / `waitpid` は行わない（SEC-1）。

use fandhe_container_core::oci_runtime::ProcessExit;
use fandhe_container_core::traits::Signal;

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
/// ポリシー評価（#488）への置き換えまでの暫定判定。
pub(crate) fn is_abnormal_exit(exit: ProcessExit) -> bool {
    match exit {
        ProcessExit::Exited(c) => c != 0,
        ProcessExit::Signaled(_) => true,
        _ => false,
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
}
