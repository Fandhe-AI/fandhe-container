//! plugin 境界機構が返す共通の構造化エラー型（TASK-107.1・PLUG-2・ERR-1・MS-3）。
//!
//! 後続のフレーム・transport・UDS・タイムアウトの各モジュール（#245・#247〜#250）が
//! 返すエラーをここに集約する。core 側の `fandhe_container_core::traits::types::ErrorCode`
//! と機械可読文字列を揃えるが、依存方向は `core → plugin`（`docs/architecture.md`）で
//! plugin は core に依存できないため、本 crate 内で独立に定義する。`TraitError` への
//! 変換は core 側の proxy 実装（TASK-114）の責務である。
//! ワイヤー上の表現（serde）は TASK-107.3（#247）で扱い、ここでは持たない。

use std::error::Error;
use std::fmt;

/// `PluginError::message` の最大バイト数。plugin 由来の文字列は untrusted のため、
/// 無制限な保持・ログ肥大を防ぐ上限として切り詰める。
pub const PLUGIN_ERROR_MESSAGE_MAX_BYTES: usize = 4096;

/// `PluginError` の機械可読な分類（ERR-1）。
///
/// 文字列表現は core の `ErrorCode::as_str` と同一（変換を無損失にする契約）。
/// `#[non_exhaustive]` のため、呼び出し側の `match` は `_` 分岐を持つこと。
/// フレーム破損・資源上限系のコードは、使う sub（#245 等）で追加する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PluginErrorCode {
    /// 引数・入力が不正。
    InvalidArgument,
    /// 対象が存在しない。
    NotFound,
    /// 対象が既に存在する。
    AlreadyExists,
    /// 前提状態を満たしていない。
    FailedPrecondition,
    /// 未実装（スタブ）。
    Unimplemented,
    /// 内部エラー。
    Internal,
    /// 権限不足。
    PermissionDenied,
    /// 相手の応答待ちが上限を超えた（REPAIR-5）。
    Timeout,
    /// 接続断・相手不在。
    Unavailable,
}

impl PluginErrorCode {
    /// 機械可読な `code` 文字列を返す（ERR-1）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::Timeout => "TIMEOUT",
            Self::Unavailable => "UNAVAILABLE",
        }
    }
}

impl fmt::Display for PluginErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// plugin 境界機構の構造化エラー（`code` と `message`。ERR-1）。
///
/// `message` には資格情報・ペイロード内容を載せない。上限
/// [`PLUGIN_ERROR_MESSAGE_MAX_BYTES`] を超える分は UTF-8 文字境界で切り詰める。
/// 相手 plugin 由来の文字列は untrusted であり、出力へ載せる側（JSON 化等）が
/// エスケープする（TASK-107.3 以降の責務）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PluginError {
    code: PluginErrorCode,
    message: String,
}

impl PluginError {
    /// エラーを生成する。`message` が上限を超える場合は文字境界で切り詰める。
    ///
    /// 入力全体を複製せず、上限内の UTF-8 接頭部分だけを確保する（確保量が
    /// [`PLUGIN_ERROR_MESSAGE_MAX_BYTES`] で頭打ちになる。AGENTS.md「リソース上限」）。
    pub fn new(code: PluginErrorCode, message: impl AsRef<str>) -> Self {
        let src = message.as_ref();
        let mut end = src.len().min(PLUGIN_ERROR_MESSAGE_MAX_BYTES);
        while end > 0 && !src.is_char_boundary(end) {
            end -= 1;
        }
        // `end` は文字境界のため `get` は常に `Some` だが、panic を避けて空文字へ倒す。
        let message = String::from(src.get(..end).unwrap_or_default());
        Self { code, message }
    }

    /// 機械可読な分類を返す。
    pub fn code(&self) -> PluginErrorCode {
        self.code
    }

    /// 人間可読なメッセージを返す。
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl Error for PluginError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plug2_error_code_as_str_matches_all_variants() {
        let cases = [
            (PluginErrorCode::InvalidArgument, "INVALID_ARGUMENT"),
            (PluginErrorCode::NotFound, "NOT_FOUND"),
            (PluginErrorCode::AlreadyExists, "ALREADY_EXISTS"),
            (PluginErrorCode::FailedPrecondition, "FAILED_PRECONDITION"),
            (PluginErrorCode::Unimplemented, "UNIMPLEMENTED"),
            (PluginErrorCode::Internal, "INTERNAL"),
            (PluginErrorCode::PermissionDenied, "PERMISSION_DENIED"),
            (PluginErrorCode::Timeout, "TIMEOUT"),
            (PluginErrorCode::Unavailable, "UNAVAILABLE"),
        ];
        for (code, s) in cases {
            assert_eq!(code.as_str(), s);
        }
    }

    #[test]
    fn err1_plugin_error_exposes_code_and_message() {
        let e = PluginError::new(PluginErrorCode::NotFound, "no such plugin");
        assert_eq!(e.code(), PluginErrorCode::NotFound);
        assert_eq!(e.message(), "no such plugin");
    }

    #[test]
    fn err1_plugin_error_display_is_code_colon_message() {
        let e = PluginError::new(PluginErrorCode::Timeout, "plugin rpc timed out");
        assert_eq!(e.to_string(), "TIMEOUT: plugin rpc timed out");
    }

    #[test]
    fn err1_error_code_display_matches_as_str() {
        assert_eq!(PluginErrorCode::Internal.to_string(), "INTERNAL");
    }

    #[test]
    fn plug2_message_is_truncated_at_max_bytes() {
        let e = PluginError::new(
            PluginErrorCode::Internal,
            "a".repeat(PLUGIN_ERROR_MESSAGE_MAX_BYTES + 1),
        );
        assert_eq!(e.message().len(), 4096);
    }

    #[test]
    fn plug2_message_truncation_keeps_utf8_boundary() {
        let e = PluginError::new(PluginErrorCode::Internal, "あ".repeat(1400));
        assert_eq!(e.message().len(), 4095);
        assert!(e.message().chars().all(|c| c == 'あ'));
    }

    #[test]
    fn plug2_message_capacity_is_bounded_for_oversized_input() {
        let e = PluginError::new(
            PluginErrorCode::Internal,
            "a".repeat(PLUGIN_ERROR_MESSAGE_MAX_BYTES * 64),
        );
        assert_eq!(e.message().len(), PLUGIN_ERROR_MESSAGE_MAX_BYTES);
        assert!(e.message.capacity() <= PLUGIN_ERROR_MESSAGE_MAX_BYTES);
    }

    #[test]
    fn plug2_message_within_limit_is_kept_as_is() {
        let e = PluginError::new(PluginErrorCode::Internal, "b".repeat(4096));
        assert_eq!(e.message().len(), 4096);
    }

    #[test]
    fn err1_plugin_error_implements_std_error() {
        let e = PluginError::new(PluginErrorCode::Unavailable, "closed");
        let d: &dyn Error = &e;
        assert_eq!(d.to_string(), "UNAVAILABLE: closed");
    }
}
