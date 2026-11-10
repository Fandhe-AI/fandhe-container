//! stream-exec helper の起動失敗の段名・errno を fd 2 へ出す診断行の語彙と組み立て（SUP-6・REPAIR-4・SEC-1・CRI-6・#4284）。
//!
//! # 役割と呼び出し文脈
//!
//! [`super::helper`] は起動の途中で失敗すると `Result` frame の `Failed(code)` だけを返し、どの段で・どの errno で
//! 失敗したかは外へ出なかった。本モジュールは、その段を閉じた語彙 [`HelperStage`] で表し、失敗 1 件を 1 行の
//! 構造化行（[`HelperFailure::diagnostic_line`]）にする。helper の `run_stream_exec_main` が `Result` の送信より前に
//! fd 2 へ書き、plugin-cri の読み手（`exec_launcher::diagnostics`。#4171）が同じ語彙で引き直して構造化ログへ転送する。
//! 語彙の正は本モジュール（plugin-cri は [`HelperStage::from_token`] で引き直す）。
//!
//! # 行の形式（固定）
//!
//! `{"component":"supervisor.stream_exec","stage":"<HelperStage>","code":"<ErrorCode>","errno":<n>|"none"}`
//!
//! - 入力は `&'static str` と整数だけで、パス・コンテナ ID・argv・自由文字列は型の上で入らない（SEC-1。ログ注入不可）
//! - errno は OS の errno（1..=4095）があるときだけ数値で出す。無い段は固定語 `"none"`、範囲外は `"other"`
//!   （plugin-cri の `parse_errno` は 0 を受けないため 0 は使わない）
//! - 全トークンに `helper_` 接頭辞を付け、core の `ExecChildStep`・`IsolationStage` の語彙と衝突させない
//!
//! # 未実装・残余（REPAIR-3）
//!
//! core の `TraitError` は errno を持たないため、状態ストア・launch env・監査 sink・要求の検証が起こす失敗の errno は
//! `none` になる。errno を運べるのは helper 自身の syscall・制御クライアントの OS エラー・channel の入出力の失敗に限る。
//! Linux 限定（`stream_exec` と同じ cfg）。

use fandhe_container_core::traits::ErrorCode;

/// 1 行の上限（plugin-cri の `DIAG_MAX_LINE_BYTES` と同じ。改行を含まない長さで固定する）。
pub const DIAG_LINE_MAX_BYTES: usize = 512;

/// 診断行の `component` の値（plugin-cri の語彙表と一致させる）。
pub const DIAG_COMPONENT: &str = "supervisor.stream_exec";

/// helper の起動失敗の段（閉じた語彙。トークンは `helper_` 接頭辞つき）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperStage {
    /// fd 0 の channel の確保（dup・fstat・socket 判定）。
    Channel,
    /// `set_dumpable(false)`。
    Dumpable,
    /// 引数の解釈。
    Args,
    /// 状態ストアを開く。
    StateOpen,
    /// 状態記録の取得。
    StateGet,
    /// `Running` かつ記録 pid の一致の照合。
    StateMismatch,
    /// launch 時 env の読み込み。
    LaunchEnv,
    /// 監査 sink の構築。
    AuditSink,
    /// exec 要求の検証。
    Request,
    /// kind 6（起動時 pidfd の受け取り）。
    PidfdHandover,
    /// `StdioHandover` の受信。
    StdioHandover,
    /// 受け取った stdio の fd の種別検査。
    StdioKind,
    /// exec 前の残り時間が 0。
    Deadline,
    /// kind 7（exec 子 cgroup の通知と ack）。
    CgroupNotify,
    /// `Started` の送信。
    StartedSend,
    /// tty の exec で、検証済みの pty master を channel の `PtyMaster` で送れなかった（errno あり。#4416・#4446）。
    PtyMasterSend,
    /// tty の exec で pty の受け渡しが失敗した（受信の検証で拒否・期限切れ・master 未着。分類は `Result` と同じ。#4416・#4446）。
    PtyMaster,
    /// exec の通し（上記以外の失敗。tty の割り当て前に worker が自分の失敗で終わった場合を含む）。
    Exec,
    /// `Result` の送信。
    ResultSend,
}

impl HelperStage {
    /// 全語彙（出力・試験の網羅の基準）。
    pub const ALL: [Self; 19] = [
        Self::Channel,
        Self::Dumpable,
        Self::Args,
        Self::StateOpen,
        Self::StateGet,
        Self::StateMismatch,
        Self::LaunchEnv,
        Self::AuditSink,
        Self::Request,
        Self::PidfdHandover,
        Self::StdioHandover,
        Self::StdioKind,
        Self::Deadline,
        Self::CgroupNotify,
        Self::StartedSend,
        Self::PtyMasterSend,
        Self::PtyMaster,
        Self::Exec,
        Self::ResultSend,
    ];

    /// 診断行の `stage` の値（固定の静的文字列）。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Channel => "helper_channel",
            Self::Dumpable => "helper_dumpable",
            Self::Args => "helper_args",
            Self::StateOpen => "helper_state_open",
            Self::StateGet => "helper_state_get",
            Self::StateMismatch => "helper_state_mismatch",
            Self::LaunchEnv => "helper_launch_env",
            Self::AuditSink => "helper_audit_sink",
            Self::Request => "helper_request",
            Self::PidfdHandover => "helper_pidfd_handover",
            Self::StdioHandover => "helper_stdio_handover",
            Self::StdioKind => "helper_stdio_kind",
            Self::Deadline => "helper_deadline",
            Self::CgroupNotify => "helper_cgroup_notify",
            Self::StartedSend => "helper_started_send",
            Self::PtyMasterSend => "helper_pty_master_send",
            Self::PtyMaster => "helper_pty_master",
            Self::Exec => "helper_exec",
            Self::ResultSend => "helper_result_send",
        }
    }

    /// 受信した `stage` の値を閉じた語彙で引き直す。語彙外は `None`。
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == token)
    }
}

/// helper の起動失敗 1 件（段・分類・OS の errno）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelperFailure {
    /// 失敗した段。
    pub stage: HelperStage,
    /// `Result` frame の `Failed(code)` と同じ分類。
    pub code: ErrorCode,
    /// OS の errno（無いときは `None`）。
    pub errno: Option<i32>,
}

impl HelperFailure {
    /// 段・分類・errno から作る。
    pub fn new(stage: HelperStage, code: ErrorCode, errno: Option<i32>) -> Self {
        Self { stage, code, errno }
    }

    /// 診断行（改行なし）。固定語彙と整数だけで組む（モジュール doc の形式）。
    pub fn diagnostic_line(&self) -> String {
        let errno = match self.errno {
            Some(n) if (1..=4095).contains(&n) => n.to_string(),
            Some(_) => "\"other\"".to_string(),
            None => "\"none\"".to_string(),
        };
        format!(
            "{{\"component\":\"{DIAG_COMPONENT}\",\"stage\":\"{}\",\"code\":\"{}\",\"errno\":{errno}}}",
            self.stage.as_str(),
            self.code.as_str(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::exec::{ExecChildStep, IsolationStage};

    /// SUP-6・REPAIR-4（#4284）: 全段のトークンは `from_token` で往復し、重複しない。
    #[test]
    fn sup6_4284_stage_tokens_roundtrip_and_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for stage in HelperStage::ALL {
            assert_eq!(HelperStage::from_token(stage.as_str()), Some(stage));
            assert!(stage.as_str().starts_with("helper_"));
            assert!(seen.insert(stage.as_str()), "duplicate {}", stage.as_str());
        }
        assert_eq!(seen.len(), 19);
        assert_eq!(HelperStage::from_token("cgroup_join"), None);
    }

    /// SUP-6（#4284）: helper の段は core の語彙と衝突しない（plugin-cri が引き直しを取り違えない）。
    #[test]
    fn sup6_4284_stage_tokens_do_not_collide_with_core_vocabulary() {
        for stage in HelperStage::ALL {
            assert!(ExecChildStep::from_token(stage.as_str()).is_none());
            assert!(IsolationStage::from_token(stage.as_str()).is_none());
        }
    }

    /// REPAIR-4・SEC-1（#4284）: 行は固定の形式で、errno は数値・`none`・`other` のいずれか。
    #[test]
    fn sup6_4284_diagnostic_line_concrete_values() {
        let line = |stage, code, errno| HelperFailure::new(stage, code, errno).diagnostic_line();
        assert_eq!(
            line(HelperStage::PidfdHandover, ErrorCode::Unavailable, Some(2)),
            "{\"component\":\"supervisor.stream_exec\",\"stage\":\"helper_pidfd_handover\",\"code\":\"UNAVAILABLE\",\"errno\":2}"
        );
        assert_eq!(
            line(HelperStage::Channel, ErrorCode::InvalidArgument, None),
            "{\"component\":\"supervisor.stream_exec\",\"stage\":\"helper_channel\",\"code\":\"INVALID_ARGUMENT\",\"errno\":\"none\"}"
        );
        for bad in [0, -1, 4096] {
            assert!(
                line(HelperStage::Exec, ErrorCode::Internal, Some(bad))
                    .ends_with("\"errno\":\"other\"}"),
                "errno {bad}"
            );
        }
        assert!(
            line(HelperStage::Exec, ErrorCode::Internal, Some(4095)).ends_with("\"errno\":4095}")
        );
    }

    /// REPAIR-4（#4284）: どの段・分類でも行は上限未満で、改行・引用符を余分に含まない。
    #[test]
    fn sup6_4284_every_line_is_bounded_single_line_ascii() {
        for stage in HelperStage::ALL {
            for code in ErrorCode::ALL {
                let line = HelperFailure::new(stage, code, Some(111)).diagnostic_line();
                assert!(line.len() < DIAG_LINE_MAX_BYTES, "{line}");
                assert!(line.bytes().all(|b| b.is_ascii_graphic()), "{line}");
                assert_eq!(line.matches('"').count(), 14, "{line}");
            }
        }
    }
}
