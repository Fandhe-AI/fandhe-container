//! `fandhe-container-net` が返す共通の構造化エラー型（TASK-136.1・NET-11・ERR-1・MS-8）。
//!
//! netlink コーデック（`netlink` モジュール）と、後続のソケット送受信・link / address / route
//! 操作（#843〜#846・#301）・nftables（#304）が返すエラーをここに集約する。
//! 機械可読な `code` と英語の `message` を持つ（ERR-1）。`fandhe-container-plugin` へは依存せず、
//! 文字列表現のみ `PluginErrorCode::as_str` と揃えて独立に定義する。
//! `message` には受信バイト列の内容を載せず、長さ・オフセット等の数値のみを載せる。

use std::error::Error;
use std::fmt;

/// `NetError` の機械可読な分類（ERR-1）。
///
/// `#[non_exhaustive]` のため、呼び出し側の `match` は `_` 分岐を持つこと。
/// ソケット層（#843）で `Timeout`・`PermissionDenied`・`Unimplemented`・`ResourceExhausted`・`Internal`、
/// request / ACK 層（#844）で `NotFound`・`AlreadyExists`・`FailedPrecondition` を追加した。文字列は `PluginErrorCode::as_str` と揃える。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetErrorCode {
    /// エンコード側の不正入力・上限超過、およびカーネルが拒否した要求（`EINVAL`。#844）。
    InvalidArgument,
    /// デコード側で検出した不正な長さ・切り詰め（受信データの破損）。
    DataLoss,
    /// 期限内に応答が得られなかった（REPAIR-5）。
    Timeout,
    /// 権限不足（`EPERM`・`EACCES`）。
    PermissionDenied,
    /// 対応外の OS・アーキテクチャ・プロトコル（fail-closed）。
    Unimplemented,
    /// fd・メモリ・カーネルバッファ等の資源枯渇。
    ResourceExhausted,
    /// 対象が存在しない（`ENOENT`・`ENODEV`。#844）。
    NotFound,
    /// 対象がすでに存在する（`EEXIST`。#844）。
    AlreadyExists,
    /// 現在の状態では実行できない（`EBUSY`。#844）。
    FailedPrecondition,
    /// 上記以外の内部エラー（分類できない errno 等）。
    Internal,
}

impl NetErrorCode {
    /// 機械可読な `code` 文字列を返す（ERR-1）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DataLoss => "DATA_LOSS",
            Self::Timeout => "TIMEOUT",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Internal => "INTERNAL",
        }
    }
}

/// `fandhe-container-net` 共通のエラー（`code` と `message`）。
///
/// フィールドは非公開で、`code()` / `message()` から読む。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetError {
    code: NetErrorCode,
    message: String,
}

impl NetError {
    /// 分類とメッセージ（英語。バイト列の内容を含めない）からエラーを作る。
    pub fn new(code: NetErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// 機械可読な分類を返す。
    pub fn code(&self) -> NetErrorCode {
        self.code
    }

    /// 人間可読なメッセージを返す。
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for NetError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-11・ERR-1: code 文字列と Display の具体値。
    #[test]
    fn code_strings_and_display() {
        assert_eq!(NetErrorCode::InvalidArgument.as_str(), "INVALID_ARGUMENT");
        assert_eq!(NetErrorCode::DataLoss.as_str(), "DATA_LOSS");
        assert_eq!(NetErrorCode::Timeout.as_str(), "TIMEOUT");
        assert_eq!(NetErrorCode::PermissionDenied.as_str(), "PERMISSION_DENIED");
        assert_eq!(NetErrorCode::Unimplemented.as_str(), "UNIMPLEMENTED");
        assert_eq!(
            NetErrorCode::ResourceExhausted.as_str(),
            "RESOURCE_EXHAUSTED"
        );
        assert_eq!(NetErrorCode::NotFound.as_str(), "NOT_FOUND");
        assert_eq!(NetErrorCode::AlreadyExists.as_str(), "ALREADY_EXISTS");
        assert_eq!(
            NetErrorCode::FailedPrecondition.as_str(),
            "FAILED_PRECONDITION"
        );
        assert_eq!(NetErrorCode::Internal.as_str(), "INTERNAL");
        let e = NetError::new(NetErrorCode::DataLoss, "truncated");
        assert_eq!(e.to_string(), "DATA_LOSS: truncated");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.message(), "truncated");
    }
}
