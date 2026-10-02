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
/// 他のコード（`Timeout`・`PermissionDenied` 等）は、使う Issue（#843・#844 等）で追加する。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetErrorCode {
    /// エンコード側の不正入力・上限超過。
    InvalidArgument,
    /// デコード側で検出した不正な長さ・切り詰め（受信データの破損）。
    DataLoss,
}

impl NetErrorCode {
    /// 機械可読な `code` 文字列を返す（ERR-1）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DataLoss => "DATA_LOSS",
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
        let e = NetError::new(NetErrorCode::DataLoss, "truncated");
        assert_eq!(e.to_string(), "DATA_LOSS: truncated");
        assert_eq!(e.code(), NetErrorCode::DataLoss);
        assert_eq!(e.message(), "truncated");
    }
}
