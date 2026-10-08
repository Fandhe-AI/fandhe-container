//! venus wire パースの構造化エラー（GPU-6・TASK-172.2・ERR-1）。
//!
//! [`super::WireReader`]・[`super::parse_command_header`] が返す。ゲスト由来の untrusted バイト列に
//! 起因する失敗だけを表し、入力バイト列そのものはメッセージへ埋め込まない（数値・オフセットのみ。
//! ログ注入と肥大の防止）。`code()` は機械可読な `venus_wire.*` 形式、`message()` は英語。
//! plugin 境界の `PluginErrorCode` への写像は後続（コマンドストリーム実行 #765 側。REPAIR-3: 未実装）。

use std::fmt;

/// venus コマンドストリームのパース失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VenusWireError {
    /// 入力が途中で尽きた（`needed` バイト必要だが `remaining` バイトしかない）。
    Truncated { needed: usize, remaining: usize },
    /// 候補外・未知のコマンド種別。形式が長さを持たず読み飛ばせないため、ストリーム全体を拒否する。
    UnsupportedCommand { raw: u32 },
    /// 配列件数・長さが上限を超えた、または `usize` へ変換できない。
    LengthExceeded { requested: u64, max: u64 },
    /// 4 バイト境界の算術がオーバーフローした。
    Misaligned { len: usize },
    /// コマンドフラグに定義外のビットが立っている。
    InvalidFlags { raw: u32 },
}

impl VenusWireError {
    /// 機械可読なエラーコード（`venus_wire.*`）。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Truncated { .. } => "venus_wire.truncated",
            Self::UnsupportedCommand { .. } => "venus_wire.unsupported_command",
            Self::LengthExceeded { .. } => "venus_wire.length_exceeded",
            Self::Misaligned { .. } => "venus_wire.misaligned",
            Self::InvalidFlags { .. } => "venus_wire.invalid_flags",
        }
    }

    /// 人間可読の英語メッセージ（入力バイト列は含めない）。
    pub fn message(&self) -> String {
        match self {
            Self::Truncated { needed, remaining } => {
                format!("command stream truncated: need {needed} bytes, {remaining} remaining")
            }
            Self::UnsupportedCommand { raw } => {
                format!("unsupported venus command type {raw}")
            }
            Self::LengthExceeded { requested, max } => {
                format!("length {requested} exceeds limit {max}")
            }
            Self::Misaligned { len } => {
                format!("length {len} overflows 4-byte alignment")
            }
            Self::InvalidFlags { raw } => {
                format!("undefined command flag bits set: {raw:#x}")
            }
        }
    }
}

impl fmt::Display for VenusWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for VenusWireError {}

/// venus capset 応答の構造化エラー（GPU-6・TASK-172.3・ERR-1）。
///
/// [`super::respond_capset_query`]・[`super::capset_info`] が返す。ゲスト由来の `u32`
/// （capset index・id・version）が未対応のときの fail-closed な拒否を表す。メッセージには
/// 数値のみを含める。`code()` は機械可読な `venus_capset.*` 形式、`message()` は英語。
/// virtio-gpu の ctrl エラー応答への写像は TASK-175 のデバイスモデル側（REPAIR-3: 未実装）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VenusCapsetError {
    /// VENUS 以外の capset id が要求された。
    UnsupportedCapset { id: u32 },
    /// 対応する最大 version を超える version が要求された。
    UnsupportedVersion { requested: u32, max: u32 },
    /// capset info の index が範囲外（`count` 個のみ広告している）。
    IndexOutOfRange { index: u32, count: u32 },
}

impl VenusCapsetError {
    /// 機械可読なエラーコード（`venus_capset.*`）。
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedCapset { .. } => "venus_capset.unsupported_capset",
            Self::UnsupportedVersion { .. } => "venus_capset.unsupported_version",
            Self::IndexOutOfRange { .. } => "venus_capset.index_out_of_range",
        }
    }

    /// 人間可読の英語メッセージ（数値のみ。入力由来の文字列は含めない）。
    pub fn message(&self) -> String {
        match self {
            Self::UnsupportedCapset { id } => format!("unsupported capset id {id}"),
            Self::UnsupportedVersion { requested, max } => {
                format!("unsupported capset version {requested}, max {max}")
            }
            Self::IndexOutOfRange { index, count } => {
                format!("capset index {index} out of range, count {count}")
            }
        }
    }
}

impl fmt::Display for VenusCapsetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for VenusCapsetError {}
