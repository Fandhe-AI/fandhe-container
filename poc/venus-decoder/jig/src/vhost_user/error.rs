//! vhost-user メッセージ codec のエラー型（GPU-6・TASK-172 F1.1・#1516）。
//!
//! 呼び出し元は [`super`] の復号・符号化関数で、将来は F1.2（ソケット I/O）が code を構造化ログへ出す。
//! 入力は frontend 由来の untrusted バイト列なので、エラーには数値と固定語彙だけを載せ、
//! 受け取ったバイト列はエコーしない（ログ注入の防止。`crate::log` と同じ方針）。

use std::fmt;

/// 機械可読なエラー種別。`as_str` の大文字スネーク表記が外部に出す code。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecErrorCode {
    /// ヘッダ（12 バイト）に満たない。
    ShortHeader,
    /// flags の version が 1 ではない。
    UnsupportedVersion,
    /// flags の予約ビット、または方向に合わないビット（要求に REPLY・応答に NEED_REPLY）。
    InvalidFlags,
    /// ヘッダの size が `MAX_PAYLOAD_LEN` を超える。ペイロードを読む前に判定する。
    PayloadTooLarge,
    /// 治具が扱う最小集合に無い要求種別。
    UnknownRequest,
    /// バッファ長が `12 + size` と違う、または要求種別ごとの期待長と違う。
    LengthMismatch,
    /// フィールド値がワイヤー上の制約（予約ビット・個数・サイズ上限）に違反している。
    InvalidValue,
}

impl CodecErrorCode {
    /// 外部へ出す固定の code 文字列。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShortHeader => "SHORT_HEADER",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::InvalidFlags => "INVALID_FLAGS",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::UnknownRequest => "UNKNOWN_REQUEST",
            Self::LengthMismatch => "LENGTH_MISMATCH",
            Self::InvalidValue => "INVALID_VALUE",
        }
    }
}

/// 構造化エラー。`request` は判明している場合の要求種別の生の数値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecError {
    /// 機械可読な種別。
    pub code: CodecErrorCode,
    /// 判明している要求 ID（ヘッダが読めた場合のみ）。
    pub request: Option<u32>,
}

impl CodecError {
    pub(crate) fn new(code: CodecErrorCode, request: Option<u32>) -> Self {
        Self { code, request }
    }

    /// 英語の固定文（入力由来の文字列を含まない）。
    pub fn message(&self) -> &'static str {
        match self.code {
            CodecErrorCode::ShortHeader => "vhost-user header is shorter than 12 bytes",
            CodecErrorCode::UnsupportedVersion => "vhost-user header version is not 1",
            CodecErrorCode::InvalidFlags => "vhost-user header flags are invalid",
            CodecErrorCode::PayloadTooLarge => "vhost-user payload size exceeds the limit",
            CodecErrorCode::UnknownRequest => "vhost-user request is not supported",
            CodecErrorCode::LengthMismatch => "vhost-user message length does not match",
            CodecErrorCode::InvalidValue => "vhost-user payload field value is invalid",
        }
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.request {
            Some(r) => write!(
                f,
                "{} (request={r}): {}",
                self.code.as_str(),
                self.message()
            ),
            None => write!(f, "{}: {}", self.code.as_str(), self.message()),
        }
    }
}

impl std::error::Error for CodecError {}
