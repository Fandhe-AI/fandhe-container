//! `fandhe-container-oci` が返す共通の構造化エラー型（TASK-51.1・OCI-1・ERR-1）。
//!
//! レジストリクライアント基盤（`registry` モジュール）と、後続のトークン取得（#401）・manifest 取得（#402）・
//! blob 取得（#403）が返すエラーをここに集約する。機械可読な `code` と英語の `message` を持つ（ERR-1）。
//! `fandhe-container-plugin` へは依存せず、文字列表現のみ `PluginErrorCode::as_str` と揃えて独立に定義する。
//!
//! `message` の契約: 英語で書き、トークン・`Authorization` ヘッダ・資格情報・レジストリ応答の本文を載せない
//! （security.md）。HTTP ステータスは `message` に埋めず `http_status` に数値で持つ。長さは
//! [`OCI_ERROR_MESSAGE_MAX_BYTES`] で切り詰め、制御文字は空白へ置換する。例外として、未対応のレイヤーの
//! mediaType だけは、長さを制限し文字を置き換えた値を載せる（`manifest` モジュール。#2037）。

use std::error::Error;
use std::fmt;

/// `message` の最大バイト数。超過分は UTF-8 の文字境界で切り詰める。
pub const OCI_ERROR_MESSAGE_MAX_BYTES: usize = 1024;

/// `OciError` の機械可読な分類（ERR-1）。
///
/// `#[non_exhaustive]` のため、呼び出し側の `match` は `_` 分岐を持つこと。
/// HTTP ステータスとの対応は `code_for_http_status`（#401・TASK-51.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OciErrorCode {
    /// イメージ参照・URL 部品の構文違反。
    InvalidArgument,
    /// 対応外・未実装の入力、機能、実行環境を、推測で処理せずに拒否する（fail-closed）。再試行しても成功しない。
    ///
    /// 例: CPU 機能の不足・platform に対応が無いアーキテクチャ・OS、未対応の manifest の `schemaVersion` /
    /// `mediaType`、未対応のレイヤー `mediaType`（zstd 等）、sha256 以外の diff_id、`openat2` が無いカーネルや
    /// ディレクトリ fd 起点・symlink を辿らない open が使えない環境での展開と blob の open（`VerifiedLayerBlob` の
    /// 非 Unix を含む）、非 Linux での所有者適用・user namespace の検査、symlink エントリを作れないホスト、
    /// AUFS メタデータ（`.wh..wh.plnk` 等）への hardlink（#2312）、bearer 認証や資格情報を要する registry。
    /// ビヘイビア: OCI-1・OCI-2・OCI-3・REPAIR-3。
    Unimplemented,
    /// 接続失敗（#401 以降で使う）。
    Unavailable,
    /// 期限内に応答が得られなかった（REPAIR-5）。
    Timeout,
    /// 認可の拒否。
    PermissionDenied,
    /// 対象が存在しない。
    NotFound,
    /// 応答の破損。
    DataLoss,
    /// 上限超過。
    ResourceExhausted,
    /// ルート証明書が 0 件など、前提が満たされていない。
    FailedPrecondition,
    /// 同じ実体を指す名前がすでに在る（レイヤー展開での別表記の衝突。IO-5・TASK-52.3）。
    AlreadyExists,
    /// 上記以外の内部エラー。
    Internal,
}

impl OciErrorCode {
    /// 機械可読な `code` 文字列を返す（ERR-1）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Unavailable => "UNAVAILABLE",
            Self::Timeout => "TIMEOUT",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::NotFound => "NOT_FOUND",
            Self::DataLoss => "DATA_LOSS",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::Internal => "INTERNAL",
        }
    }

    /// 全 variant の一覧（宣言順）。`from_name` の唯一の出所（REPAIR-1・ERR-1）。
    ///
    /// variant を足したら単体試験が検出する。
    pub const ALL: [OciErrorCode; 11] = [
        Self::InvalidArgument,
        Self::Unimplemented,
        Self::Unavailable,
        Self::Timeout,
        Self::PermissionDenied,
        Self::NotFound,
        Self::DataLoss,
        Self::ResourceExhausted,
        Self::FailedPrecondition,
        Self::AlreadyExists,
        Self::Internal,
    ];

    /// [`Self::as_str`] の逆写像。完全一致だけを受け、未知の文字列は `None`（呼び出し側は fail-closed で扱う）。
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }
}

/// `fandhe-container-oci` 共通のエラー（`code` と `message`、任意の HTTP ステータス）。
///
/// フィールドは非公開で、各 getter から読む。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciError {
    code: OciErrorCode,
    message: String,
    http_status: Option<u16>,
}

impl OciError {
    /// 分類とメッセージ（英語。資格情報・応答本文を含めない）からエラーを作る。
    ///
    /// 制御文字は空白へ置換し、[`OCI_ERROR_MESSAGE_MAX_BYTES`] を超える分は文字境界で切り詰める。
    pub fn new(code: OciErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: sanitize_message(&message.into()),
            http_status: None,
        }
    }

    /// レジストリ応答の HTTP ステータスを付ける（#401〜#403 が使う）。
    pub fn with_http_status(mut self, status: u16) -> Self {
        self.http_status = Some(status);
        self
    }

    /// 機械可読な分類を返す。
    pub fn code(&self) -> OciErrorCode {
        self.code
    }

    /// 人間可読なメッセージを返す。
    pub fn message(&self) -> &str {
        &self.message
    }

    /// 起因した HTTP ステータス（あれば）を返す。
    pub fn http_status(&self) -> Option<u16> {
        self.http_status
    }
}

/// HTTP ステータスを `OciErrorCode` へ写像する（TASK-51.2・OCI-1。#401〜#403 が共通で使う）。
///
/// 401 / 403 は `PermissionDenied`、404 は `NotFound`、408 は `Timeout`、429 と 5xx は `Unavailable`、
/// その他の 4xx は `InvalidArgument`、上記以外（想定外の 1xx / 3xx 等）は `Internal`。
/// 呼び出し側は併せて `with_http_status` でステータスを別持ちする。
pub(crate) fn code_for_http_status(status: u16) -> OciErrorCode {
    match status {
        401 | 403 => OciErrorCode::PermissionDenied,
        404 => OciErrorCode::NotFound,
        408 => OciErrorCode::Timeout,
        429 | 500..=599 => OciErrorCode::Unavailable,
        400..=499 => OciErrorCode::InvalidArgument,
        _ => OciErrorCode::Internal,
    }
}

/// 制御文字を空白へ置換し、上限バイト数で文字境界に切り詰める。
fn sanitize_message(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(OCI_ERROR_MESSAGE_MAX_BYTES));
    for c in raw.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if out.len().saturating_add(c.len_utf8()) > OCI_ERROR_MESSAGE_MAX_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

impl fmt::Display for OciError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for OciError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// wildcard の無い網羅 match。variant を足すとここでコンパイルが落ちる（`ALL` の件数と対）。
    fn ordinal(code: OciErrorCode) -> usize {
        match code {
            OciErrorCode::InvalidArgument => 0,
            OciErrorCode::Unimplemented => 1,
            OciErrorCode::Unavailable => 2,
            OciErrorCode::Timeout => 3,
            OciErrorCode::PermissionDenied => 4,
            OciErrorCode::NotFound => 5,
            OciErrorCode::DataLoss => 6,
            OciErrorCode::ResourceExhausted => 7,
            OciErrorCode::FailedPrecondition => 8,
            OciErrorCode::AlreadyExists => 9,
            OciErrorCode::Internal => 10,
        }
    }

    /// REPAIR-1・ERR-1: `ALL` が宣言順に全 variant を過不足なく並べている。
    #[test]
    fn err1_oci_error_code_all_covers_every_variant() {
        for (i, c) in OciErrorCode::ALL.into_iter().enumerate() {
            assert_eq!(ordinal(c), i);
        }
        assert_eq!(OciErrorCode::ALL.len(), 11);
        let set: std::collections::HashSet<_> = OciErrorCode::ALL.into_iter().collect();
        assert_eq!(set.len(), 11);
    }

    /// ERR-1: ワイヤーへ出す code 名は固定（変えると互換が壊れる）。`from_name` は完全一致の逆写像。
    #[test]
    fn err1_oci_error_code_wire_names_are_fixed_and_roundtrip() {
        let table = [
            (OciErrorCode::InvalidArgument, "INVALID_ARGUMENT"),
            (OciErrorCode::Unimplemented, "UNIMPLEMENTED"),
            (OciErrorCode::Unavailable, "UNAVAILABLE"),
            (OciErrorCode::Timeout, "TIMEOUT"),
            (OciErrorCode::PermissionDenied, "PERMISSION_DENIED"),
            (OciErrorCode::NotFound, "NOT_FOUND"),
            (OciErrorCode::DataLoss, "DATA_LOSS"),
            (OciErrorCode::ResourceExhausted, "RESOURCE_EXHAUSTED"),
            (OciErrorCode::FailedPrecondition, "FAILED_PRECONDITION"),
            (OciErrorCode::AlreadyExists, "ALREADY_EXISTS"),
            (OciErrorCode::Internal, "INTERNAL"),
        ];
        assert_eq!(table.len(), OciErrorCode::ALL.len());
        for (i, (code, name)) in table.into_iter().enumerate() {
            assert_eq!(OciErrorCode::ALL[i], code);
            assert_eq!(code.as_str(), name);
            assert_eq!(OciErrorCode::from_name(name), Some(code));
        }
        for bad in [
            "",
            "internal",
            "INTERNAL ",
            " INTERNAL",
            "INTERNAL\n",
            "UNKNOWN",
        ] {
            assert_eq!(OciErrorCode::from_name(bad), None, "{bad:?}");
        }
    }

    /// OCI-1・ERR-1: code 文字列と Display の具体値。
    #[test]
    fn code_strings_and_display() {
        let table = [
            (OciErrorCode::InvalidArgument, "INVALID_ARGUMENT"),
            (OciErrorCode::Unimplemented, "UNIMPLEMENTED"),
            (OciErrorCode::Unavailable, "UNAVAILABLE"),
            (OciErrorCode::Timeout, "TIMEOUT"),
            (OciErrorCode::PermissionDenied, "PERMISSION_DENIED"),
            (OciErrorCode::NotFound, "NOT_FOUND"),
            (OciErrorCode::DataLoss, "DATA_LOSS"),
            (OciErrorCode::ResourceExhausted, "RESOURCE_EXHAUSTED"),
            (OciErrorCode::FailedPrecondition, "FAILED_PRECONDITION"),
            (OciErrorCode::AlreadyExists, "ALREADY_EXISTS"),
            (OciErrorCode::Internal, "INTERNAL"),
        ];
        for (code, s) in table {
            assert_eq!(code.as_str(), s);
        }
        let e = OciError::new(OciErrorCode::InvalidArgument, "bad reference");
        assert_eq!(e.to_string(), "INVALID_ARGUMENT: bad reference");
        assert_eq!(e.http_status(), None);
    }

    /// OCI-1: HTTP ステータス写像の具体値。
    #[test]
    fn http_status_mapping() {
        let table = [
            (401, OciErrorCode::PermissionDenied),
            (403, OciErrorCode::PermissionDenied),
            (404, OciErrorCode::NotFound),
            (408, OciErrorCode::Timeout),
            (429, OciErrorCode::Unavailable),
            (500, OciErrorCode::Unavailable),
            (503, OciErrorCode::Unavailable),
            (400, OciErrorCode::InvalidArgument),
            (416, OciErrorCode::InvalidArgument),
            (302, OciErrorCode::Internal),
        ];
        for (status, code) in table {
            assert_eq!(code_for_http_status(status), code, "status {status}");
        }
    }

    /// ERR-1: HTTP ステータスは message と別に数値で保持する。
    #[test]
    fn http_status_is_kept_separately() {
        let e = OciError::new(OciErrorCode::NotFound, "manifest unknown").with_http_status(404);
        assert_eq!(e.http_status(), Some(404));
        assert_eq!(e.message(), "manifest unknown");
    }

    /// ERR-1・ERR-2: 制御文字は空白へ置換される。
    #[test]
    fn control_chars_are_replaced() {
        let e = OciError::new(OciErrorCode::Internal, "a\nb\u{1b}[0mc");
        assert_eq!(e.message(), "a b [0mc");
    }

    /// ERR-2: 上限で UTF-8 の境界に切り詰める（3 バイト文字で境界を跨ぐ）。
    #[test]
    fn message_is_truncated_on_char_boundary() {
        let e = OciError::new(OciErrorCode::Internal, "あ".repeat(400));
        assert_eq!(e.message().len(), 1023);
        assert_eq!(e.message().chars().count(), 341);
    }
}
