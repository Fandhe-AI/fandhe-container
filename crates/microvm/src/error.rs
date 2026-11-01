//! `fandhe-container-microvm` 共通の構造化エラー型（TASK-74.1.1・MVM-1・ERR-1）。
//!
//! 機械可読な `code` と英語の `message` を持つ。core・plugin には依存せず、文字列表現のみ
//! `PluginErrorCode::as_str` と揃えて独立に定義する（`fandhe-container-platform-windows` の `WinError` と同じ方針）。
//! 境界を越える写像は将来の plugin-microvm（TASK-117）の責務。
//! `message` には英語の固定文言と数値（errno・API 版数）だけを載せ、パスは載せない。

use std::error::Error;
use std::fmt;

/// `MicrovmError` の機械可読な分類（ERR-1）。
///
/// `#[non_exhaustive]` のため、他 crate の `match` は網羅にできない。文字列から戻すときは
/// [`MicrovmErrorCode::from_name`] の `None` を fail-closed で扱う。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MicrovmErrorCode {
    /// 対象（`/dev/kvm`）が存在しない。
    NotFound,
    /// 権限不足（EACCES・EPERM）。
    PermissionDenied,
    /// 前提条件を満たさない（KVM デバイスでない・API 版数が 12 以外）。
    FailedPrecondition,
    /// 資源不足（ENOMEM・EMFILE・ENFILE）。
    ResourceExhausted,
    /// 対応外の OS / アーキテクチャ（fail-closed）。
    Unimplemented,
    /// 引数が不正（vCPU id が範囲外。EINVAL）。
    InvalidArgument,
    /// 既に存在する（vCPU id の重複。EEXIST）。
    AlreadyExists,
    /// 上記以外の内部エラー。
    Internal,
    /// 期限内に完了しなかった（`KVM_RUN` の期限超過。REPAIR-5）。
    DeadlineExceeded,
}

impl MicrovmErrorCode {
    /// 全 variant の一覧（宣言順）。`from_name` の唯一の出所。
    pub const ALL: [MicrovmErrorCode; 9] = [
        MicrovmErrorCode::NotFound,
        MicrovmErrorCode::PermissionDenied,
        MicrovmErrorCode::FailedPrecondition,
        MicrovmErrorCode::ResourceExhausted,
        MicrovmErrorCode::Unimplemented,
        MicrovmErrorCode::InvalidArgument,
        MicrovmErrorCode::AlreadyExists,
        MicrovmErrorCode::Internal,
        MicrovmErrorCode::DeadlineExceeded,
    ];

    /// ワイヤー・ログ用の文字列表現（`PluginErrorCode::as_str` と同じ表記）。
    pub const fn as_str(self) -> &'static str {
        match self {
            MicrovmErrorCode::NotFound => "NOT_FOUND",
            MicrovmErrorCode::PermissionDenied => "PERMISSION_DENIED",
            MicrovmErrorCode::FailedPrecondition => "FAILED_PRECONDITION",
            MicrovmErrorCode::ResourceExhausted => "RESOURCE_EXHAUSTED",
            MicrovmErrorCode::Unimplemented => "UNIMPLEMENTED",
            MicrovmErrorCode::InvalidArgument => "INVALID_ARGUMENT",
            MicrovmErrorCode::AlreadyExists => "ALREADY_EXISTS",
            MicrovmErrorCode::Internal => "INTERNAL",
            MicrovmErrorCode::DeadlineExceeded => "DEADLINE_EXCEEDED",
        }
    }

    /// 文字列表現から分類を戻す（完全一致のみ。未知は `None`）。
    pub fn from_name(name: &str) -> Option<MicrovmErrorCode> {
        Self::ALL.iter().copied().find(|c| c.as_str() == name)
    }
}

/// KVM 操作の失敗（機械可読な `code` と英語の `message`。ERR-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicrovmError {
    code: MicrovmErrorCode,
    message: String,
}

impl MicrovmError {
    /// 分類とメッセージから作る。
    pub fn new(code: MicrovmErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// 機械可読な分類。
    pub fn code(&self) -> MicrovmErrorCode {
        self.code
    }

    /// 英語の説明文。
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MicrovmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for MicrovmError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// variant を足したら網羅 match が壊れて ALL の更新漏れに気づける。
    fn ordinal(c: MicrovmErrorCode) -> usize {
        match c {
            MicrovmErrorCode::NotFound => 0,
            MicrovmErrorCode::PermissionDenied => 1,
            MicrovmErrorCode::FailedPrecondition => 2,
            MicrovmErrorCode::ResourceExhausted => 3,
            MicrovmErrorCode::Unimplemented => 4,
            MicrovmErrorCode::InvalidArgument => 5,
            MicrovmErrorCode::AlreadyExists => 6,
            MicrovmErrorCode::Internal => 7,
            MicrovmErrorCode::DeadlineExceeded => 8,
        }
    }

    #[test]
    fn all_covers_every_variant_in_order() {
        assert_eq!(MicrovmErrorCode::ALL.len(), 9);
        for (i, c) in MicrovmErrorCode::ALL.iter().enumerate() {
            assert_eq!(ordinal(*c), i);
        }
    }

    #[test]
    fn as_str_values_and_roundtrip() {
        assert_eq!(MicrovmErrorCode::NotFound.as_str(), "NOT_FOUND");
        assert_eq!(
            MicrovmErrorCode::PermissionDenied.as_str(),
            "PERMISSION_DENIED"
        );
        assert_eq!(
            MicrovmErrorCode::FailedPrecondition.as_str(),
            "FAILED_PRECONDITION"
        );
        assert_eq!(
            MicrovmErrorCode::ResourceExhausted.as_str(),
            "RESOURCE_EXHAUSTED"
        );
        assert_eq!(MicrovmErrorCode::Unimplemented.as_str(), "UNIMPLEMENTED");
        assert_eq!(
            MicrovmErrorCode::InvalidArgument.as_str(),
            "INVALID_ARGUMENT"
        );
        assert_eq!(MicrovmErrorCode::AlreadyExists.as_str(), "ALREADY_EXISTS");
        assert_eq!(MicrovmErrorCode::Internal.as_str(), "INTERNAL");
        assert_eq!(
            MicrovmErrorCode::DeadlineExceeded.as_str(),
            "DEADLINE_EXCEEDED"
        );
        for c in MicrovmErrorCode::ALL {
            assert_eq!(MicrovmErrorCode::from_name(c.as_str()), Some(c));
        }
        assert_eq!(MicrovmErrorCode::from_name("not_found"), None);
        assert_eq!(MicrovmErrorCode::from_name(""), None);
    }

    #[test]
    fn display_is_code_colon_message() {
        let e = MicrovmError::new(MicrovmErrorCode::NotFound, "KVM device not found");
        assert_eq!(e.to_string(), "NOT_FOUND: KVM device not found");
        assert_eq!(e.code(), MicrovmErrorCode::NotFound);
        assert_eq!(e.message(), "KVM device not found");
    }
}
