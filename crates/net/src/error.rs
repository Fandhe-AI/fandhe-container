//! `fandhe-container-net` が返す共通の構造化エラー型（TASK-136.1・NET-11・ERR-1・MS-8）。
//!
//! netlink コーデック（`netlink` モジュール）と、後続のソケット送受信・link / address / route
//! 操作（#843〜#846・#301）・nftables（#304）が返すエラーをここに集約する。
//! 機械可読な `code` と英語の `message` を持つ（ERR-1）。`fandhe-container-plugin` へは依存せず、
//! 文字列表現のみ `PluginErrorCode::as_str` と揃えて独立に定義する。
//! `message` には受信バイト列の内容を載せず、長さ・オフセット等の数値のみを載せる。唯一の例外は拡張 ACK の
//! `NLMSGERR_ATTR_MSG`（NET-11）で、NUL で切り・128 バイト上限・ASCII 印字可能文字以外は `?` に置換した
//! 文字列に限って載せる。

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

    /// 全 variant の一覧（宣言順）。`from_name` の唯一の出所（REPAIR-1・ERR-1）。
    ///
    /// variant を足したら単体試験が検出する。
    pub const ALL: [NetErrorCode; 10] = [
        Self::InvalidArgument,
        Self::DataLoss,
        Self::Timeout,
        Self::PermissionDenied,
        Self::Unimplemented,
        Self::ResourceExhausted,
        Self::NotFound,
        Self::AlreadyExists,
        Self::FailedPrecondition,
        Self::Internal,
    ];

    /// [`Self::as_str`] の逆写像。完全一致だけを受け、未知の文字列は `None`（呼び出し側は fail-closed で扱う）。
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
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
    /// 分類とメッセージ（英語。バイト列の内容を含めない。拡張 ACK の文字列は上記のサニタイズ済みのものに限る）からエラーを作る。
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

    /// wildcard の無い網羅 match。variant を足すとここでコンパイルが落ちる（`ALL` の件数と対）。
    fn ordinal(code: NetErrorCode) -> usize {
        match code {
            NetErrorCode::InvalidArgument => 0,
            NetErrorCode::DataLoss => 1,
            NetErrorCode::Timeout => 2,
            NetErrorCode::PermissionDenied => 3,
            NetErrorCode::Unimplemented => 4,
            NetErrorCode::ResourceExhausted => 5,
            NetErrorCode::NotFound => 6,
            NetErrorCode::AlreadyExists => 7,
            NetErrorCode::FailedPrecondition => 8,
            NetErrorCode::Internal => 9,
        }
    }

    /// REPAIR-1・ERR-1: `ALL` が宣言順に全 variant を過不足なく並べている。
    #[test]
    fn err1_net_error_code_all_covers_every_variant() {
        for (i, c) in NetErrorCode::ALL.into_iter().enumerate() {
            assert_eq!(ordinal(c), i);
        }
        assert_eq!(NetErrorCode::ALL.len(), 10);
        let set: std::collections::HashSet<_> = NetErrorCode::ALL.into_iter().collect();
        assert_eq!(set.len(), 10);
    }

    /// ERR-1: ワイヤーへ出す code 名は固定（変えると互換が壊れる）。`from_name` は完全一致の逆写像。
    #[test]
    fn err1_net_error_code_wire_names_are_fixed_and_roundtrip() {
        let table = [
            (NetErrorCode::InvalidArgument, "INVALID_ARGUMENT"),
            (NetErrorCode::DataLoss, "DATA_LOSS"),
            (NetErrorCode::Timeout, "TIMEOUT"),
            (NetErrorCode::PermissionDenied, "PERMISSION_DENIED"),
            (NetErrorCode::Unimplemented, "UNIMPLEMENTED"),
            (NetErrorCode::ResourceExhausted, "RESOURCE_EXHAUSTED"),
            (NetErrorCode::NotFound, "NOT_FOUND"),
            (NetErrorCode::AlreadyExists, "ALREADY_EXISTS"),
            (NetErrorCode::FailedPrecondition, "FAILED_PRECONDITION"),
            (NetErrorCode::Internal, "INTERNAL"),
        ];
        assert_eq!(table.len(), NetErrorCode::ALL.len());
        for (i, (code, name)) in table.into_iter().enumerate() {
            assert_eq!(NetErrorCode::ALL[i], code);
            assert_eq!(code.as_str(), name);
            assert_eq!(NetErrorCode::from_name(name), Some(code));
        }
        for bad in [
            "",
            "internal",
            "INTERNAL ",
            " INTERNAL",
            "INTERNAL\n",
            "UNKNOWN",
        ] {
            assert_eq!(NetErrorCode::from_name(bad), None, "{bad:?}");
        }
    }

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
