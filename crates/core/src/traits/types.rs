//! 拡張点トレイト（`ContainerRuntime`・`StateStore`・`NetworkPlugin`・`VolumeProvider`）が
//! 共有する型（TASK-4・CRI-7）。
//!
//! `ContainerId` は OCI-5 の状態パス（`/run/fandhe-container/<id>/state.json` 等）の
//! 1 パス要素になるため、外部入力（CLI・CRI・MCP リクエスト）から作る際にここで検証し、
//! 検証済みでない値を型として表現できないようにする。`TraitError` は 4 トレイト共通の
//! 構造化エラー型（ERR-1: 機械可読な `code` / `message`）。

use std::error::Error;
use std::fmt;

/// コンテナ ID の許容文字数の上限（NAME_MAX 相当。多くの Linux ファイルシステムの
/// ファイル名長上限に合わせ、状態ファイルのパス要素として安全な範囲に収める）。
const CONTAINER_ID_MAX_LEN: usize = 255;

/// 検証済みのコンテナ識別子。
///
/// `ContainerRuntime`・`StateStore` 等がパス要素（状態ファイル名・ネットワーク namespace
/// 名等）として使うため、パストラバーサル（`.`・`..`・区切り文字）や NUL・非 ASCII 制御文字を
/// 型のレベルで排除する。生成は [`ContainerId::new`] のみで、検証を経ずに値を作れない。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContainerId(String);

impl ContainerId {
    /// 入力文字列を検証してコンテナ ID を作る。
    ///
    /// 拒否条件（いずれかに該当すると `ErrorCode::InvalidArgument`）:
    /// - 空文字列、`.`、`..`
    /// - 長さが `CONTAINER_ID_MAX_LEN`（255 バイト）を超える
    /// - `[A-Za-z0-9._-]` 以外の文字を含む（`/`・`\`・NUL・空白・非 ASCII を含む）
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        if value.is_empty() || value == "." || value == ".." {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "container id must not be empty, \".\", or \"..\"",
            ));
        }
        if value.len() > CONTAINER_ID_MAX_LEN {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("container id must be at most {CONTAINER_ID_MAX_LEN} bytes"),
            ));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "container id must match [A-Za-z0-9._-]",
            ));
        }
        Ok(Self(value))
    }

    /// 検証済み文字列への参照を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for ContainerId {
    type Error = TraitError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for ContainerId {
    type Error = TraitError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// 拡張点トレイトの応答が返す機械可読なエラー分類（ERR-1・ERR-3・ERR-5 の体系）。
///
/// `#[non_exhaustive]` により、呼び出し側の `match` は将来のバリアント追加に備えて
/// `_` 分岐を持つ必要がある。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// 引数が不正（形式・範囲・検証違反）。
    InvalidArgument,
    /// 対象が見つからない。
    NotFound,
    /// 対象がすでに存在する（例: 同一 ID での二重作成）。
    AlreadyExists,
    /// 現在の状態では実行できない前提条件違反（例: 未作成のコンテナへの start）。
    FailedPrecondition,
    /// 未実装。
    Unimplemented,
    /// 内部エラー。
    Internal,
    /// 権限不足。
    PermissionDenied,
    /// 相手の応答待ちが上限時間を超えた（REPAIR-5）。
    Timeout,
    /// plugin プロセスに到達できない、または通信が切断された。
    ///
    /// ERR-1/3/5 の既定表にはない追加コードである。`ContainerRuntime` 等の実装は
    /// 別プロセス plugin（PLUG-1）であり、境界機構（UDS）の接続断・プロセス未起動を
    /// 表す分類が必要なため設ける。spec（error-format.md）への反映要否は別途ユーザーへ
    /// 報告する（本 crate では拡張済みの分類として扱う）。
    Unavailable,
}

impl ErrorCode {
    /// エラーコードを ERR-1 の機械可読文字列表現に変換する。
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

/// 拡張点トレイト（`ContainerRuntime` 等）が返す構造化エラー。
///
/// `code` は機械可読な分類、`message` は人間可読な説明（ERR-1）。plugin からの応答は
/// untrusted な外部入力であるため、proxy 実装（G8・TASK-107/114）は `message` の長さを
/// 上限検証してから `TraitError` を組み立てる。レジストリ資格情報等の秘密情報を
/// `message` に含めない（security.md）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TraitError {
    code: ErrorCode,
    message: String,
}

impl TraitError {
    /// エラーコードとメッセージから構造化エラーを作る。
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// 機械可読なエラーコードを返す。
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// 人間可読なエラーメッセージを返す。
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TraitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for TraitError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRI-7: 受理される ContainerId の例（英数字・区切り記号・境界長）。
    #[test]
    fn cri7_container_id_accepts_valid_values() {
        assert_eq!(ContainerId::new("abc").unwrap().as_str(), "abc");
        assert_eq!(ContainerId::new("a-b_c.1").unwrap().as_str(), "a-b_c.1");
        let hex64 = "a".repeat(64);
        assert!(ContainerId::new(hex64).is_ok());
        let max_len = "a".repeat(255);
        assert!(ContainerId::new(max_len).is_ok());
    }

    /// CRI-7: 拒否される ContainerId の例（空・トラバーサル・区切り文字・NUL・非 ASCII・長さ超過）。
    #[test]
    fn cri7_container_id_rejects_invalid_values() {
        let cases: Vec<String> = vec![
            String::new(),
            ".".to_string(),
            "..".to_string(),
            "a/b".to_string(),
            "a\\b".to_string(),
            "a b".to_string(),
            "a\0b".to_string(),
            "é".to_string(),
            "a".repeat(256),
        ];
        for case in cases {
            let err = ContainerId::new(case.clone()).expect_err("must be rejected");
            assert_eq!(
                err.code().as_str(),
                "INVALID_ARGUMENT",
                "case {case:?} should be INVALID_ARGUMENT"
            );
        }
    }

    /// CRI-7: ErrorCode の全バリアントが ERR-1 の機械可読文字列と一致する。
    #[test]
    fn cri7_error_code_as_str_matches_err1_strings() {
        assert_eq!(ErrorCode::InvalidArgument.as_str(), "INVALID_ARGUMENT");
        assert_eq!(ErrorCode::NotFound.as_str(), "NOT_FOUND");
        assert_eq!(ErrorCode::AlreadyExists.as_str(), "ALREADY_EXISTS");
        assert_eq!(
            ErrorCode::FailedPrecondition.as_str(),
            "FAILED_PRECONDITION"
        );
        assert_eq!(ErrorCode::Unimplemented.as_str(), "UNIMPLEMENTED");
        assert_eq!(ErrorCode::Internal.as_str(), "INTERNAL");
        assert_eq!(ErrorCode::PermissionDenied.as_str(), "PERMISSION_DENIED");
        assert_eq!(ErrorCode::Timeout.as_str(), "TIMEOUT");
        assert_eq!(ErrorCode::Unavailable.as_str(), "UNAVAILABLE");
    }

    /// CRI-7: TraitError の Display が "<CODE>: <message>" 形式になる。
    #[test]
    fn cri7_trait_error_display_format() {
        let err = TraitError::new(ErrorCode::NotFound, "container not found");
        assert_eq!(err.to_string(), "NOT_FOUND: container not found");
    }
}
