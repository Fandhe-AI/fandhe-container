//! `fandhe-container-platform-windows` 共通の構造化エラー型（TASK-67.2・WIN-2・ERR-1）。
//!
//! 機械可読な `code` と英語の `message` を持つ。`fandhe-container-plugin` へは依存せず、文字列表現のみ
//! `PluginErrorCode::as_str` と揃えて独立に定義する（`fandhe-container-net` の `NetError` と同じ方針）。
//! `message` には英語の固定文言と数値（行番号・バイト長）だけを載せ、`.wslconfig` の内容やパスは載せない
//! （kernelCommandLine やユーザー名入りパスを含みうるため）。
//!
//! `.wslconfig` 操作（`wslconfig` モジュール）と WSL2 操作（`wsl2` モジュール。`Wsl2Error` は本型の別名）が
//! 共通で使う。分類拡張は `#[non_exhaustive]` のため互換（TASK-67.5・#376 で
//! `FailedPrecondition`・`Timeout`・`DataLoss` を追加し、WSL2 側の暫定エラー型を統合した）。

use std::error::Error;
use std::fmt;

/// `WinError` の機械可読な分類（ERR-1）。
///
/// `#[non_exhaustive]` のため、呼び出し側の `match` は `_` 分岐を持つこと。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WinErrorCode {
    /// 不正な入力（構文エラー・非 UTF-8・NUL・通常ファイル以外・不正なパス・不正な引数）。
    InvalidArgument,
    /// 対象（ファイル・親ディレクトリ）が存在しない。
    NotFound,
    /// 権限不足、またはシンボリックリンクの拒否（fail-closed）。
    PermissionDenied,
    /// 大きさの上限超過。
    ResourceExhausted,
    /// 対応外の OS（fail-closed）。
    Unimplemented,
    /// 前提条件を満たさない（WSL2 無効・virtiofs 非成立の厳格拒否など。ERR-1）。
    FailedPrecondition,
    /// 期限内に終了しなかった（REPAIR-5）。
    Timeout,
    /// 外部出力が空・未対応形式・不正なエンコーディング。
    DataLoss,
    /// 上記以外の内部エラー（分類できない I/O 失敗）。
    Internal,
}

impl WinErrorCode {
    /// 機械可読な `code` 文字列を返す（ERR-1。`PluginErrorCode::as_str` と表記を揃える）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotFound => "NOT_FOUND",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Timeout => "TIMEOUT",
            Self::DataLoss => "DATA_LOSS",
            Self::Internal => "INTERNAL",
        }
    }
}

/// 本 crate 共通のエラー（`code` と `message`）。フィールドは非公開で `code()` / `message()` から読む。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinError {
    code: WinErrorCode,
    message: String,
}

impl WinError {
    /// 分類と英語のメッセージ（入力の内容・パスを含めない）からエラーを作る。
    pub fn new(code: WinErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// 機械可読な分類を返す。
    pub fn code(&self) -> WinErrorCode {
        self.code
    }

    /// 英語のメッセージを返す。
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for WinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for WinError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全 code 文字列と Display の具体値（ERR-1）。
    #[test]
    fn code_strings_and_display() {
        let cases = [
            (WinErrorCode::InvalidArgument, "INVALID_ARGUMENT"),
            (WinErrorCode::NotFound, "NOT_FOUND"),
            (WinErrorCode::PermissionDenied, "PERMISSION_DENIED"),
            (WinErrorCode::ResourceExhausted, "RESOURCE_EXHAUSTED"),
            (WinErrorCode::Unimplemented, "UNIMPLEMENTED"),
            (WinErrorCode::FailedPrecondition, "FAILED_PRECONDITION"),
            (WinErrorCode::Timeout, "TIMEOUT"),
            (WinErrorCode::DataLoss, "DATA_LOSS"),
            (WinErrorCode::Internal, "INTERNAL"),
        ];
        for (code, s) in cases {
            assert_eq!(code.as_str(), s);
        }
        let e = WinError::new(WinErrorCode::NotFound, "missing");
        assert_eq!(e.to_string(), "NOT_FOUND: missing");
        assert_eq!(e.code(), WinErrorCode::NotFound);
        assert_eq!(e.message(), "missing");
    }
}
