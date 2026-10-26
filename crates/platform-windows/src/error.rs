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
/// `#[non_exhaustive]` のため、他 crate の `match` は網羅にできない。`_` に吸収させず、[`WinErrorCode::ALL`] 由来の
/// `const` 表＋`find` と表外への明示の倒し先にし、試験で表の網羅を照合する（REPAIR-1・ERR-1）。
/// 文字列から戻すときは [`WinErrorCode::from_name`] の `None` を fail-closed で扱う。
///
/// core の `ErrorCode` への写像は持たせない: 本 crate は core にも plugin にも意図して依存しない。境界を越える
/// 唯一の経路は plugin-windows の `to_plugin_error`（`PluginErrorCode` へ）で、core との対応は
/// `PluginErrorCode` を経由して決まる。
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
    /// 全 variant の一覧（宣言順）。`from_name` の唯一の出所（REPAIR-1・ERR-1）。
    ///
    /// variant を足したら単体試験（`ordinal` の網羅 match と件数）が検出する。
    pub const ALL: [WinErrorCode; 9] = [
        WinErrorCode::InvalidArgument,
        WinErrorCode::NotFound,
        WinErrorCode::PermissionDenied,
        WinErrorCode::ResourceExhausted,
        WinErrorCode::Unimplemented,
        WinErrorCode::FailedPrecondition,
        WinErrorCode::Timeout,
        WinErrorCode::DataLoss,
        WinErrorCode::Internal,
    ];

    /// `as_str` の逆写像。完全一致だけを受ける（大文字小文字の畳み込み・空白の除去をしない）。
    ///
    /// 未知は `None` で、呼び出し側は固定文言で拒否する（fail-closed。既知の variant へ黙って
    /// 置き換えない）。現時点で製品経路の呼び出し元は無く、往復試験と将来の受信側のために置く。
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }

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

    /// wildcard の無い網羅 match。variant を足すとここでコンパイルが落ちる（`ALL` の件数と対）。
    fn ordinal(code: WinErrorCode) -> usize {
        match code {
            WinErrorCode::InvalidArgument => 0,
            WinErrorCode::NotFound => 1,
            WinErrorCode::PermissionDenied => 2,
            WinErrorCode::ResourceExhausted => 3,
            WinErrorCode::Unimplemented => 4,
            WinErrorCode::FailedPrecondition => 5,
            WinErrorCode::Timeout => 6,
            WinErrorCode::DataLoss => 7,
            WinErrorCode::Internal => 8,
        }
    }

    /// REPAIR-1・ERR-1: `ALL` が宣言順に全 variant を過不足なく並べている。
    #[test]
    fn err1_winerrorcode_all_covers_every_variant() {
        for (i, c) in WinErrorCode::ALL.into_iter().enumerate() {
            assert_eq!(ordinal(c), i);
        }
        assert_eq!(WinErrorCode::ALL.len(), 9);
        let set: std::collections::HashSet<_> = WinErrorCode::ALL.into_iter().collect();
        assert_eq!(set.len(), 9);
    }

    /// ERR-1: ワイヤーへ出す code 名は固定（変えると互換が壊れる）。`from_name` は完全一致の逆写像。
    #[test]
    fn err1_winerrorcode_wire_names_are_fixed_and_roundtrip() {
        let table = [
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
        assert_eq!(table.len(), WinErrorCode::ALL.len());
        for (i, (code, name)) in table.into_iter().enumerate() {
            assert_eq!(WinErrorCode::ALL[i], code);
            assert_eq!(code.as_str(), name);
            assert_eq!(WinErrorCode::from_name(name), Some(code));
        }
        for bad in [
            "",
            "internal",
            "INTERNAL ",
            " INTERNAL",
            "INTERNAL\n",
            "UNKNOWN",
        ] {
            assert_eq!(WinErrorCode::from_name(bad), None, "{bad:?}");
        }
    }

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
