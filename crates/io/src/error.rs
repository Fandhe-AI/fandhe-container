//! `fandhe-container-io` 共通の構造化エラー型（TASK-11.1・IO-1・ERR-1・MS-1）。
//!
//! `transport` モジュールの送受信トレイトが返すエラーをここに集約する。core 側の
//! `fandhe_container_core::traits::types::{ErrorCode, TraitError}`（CRI-7）と機械可読
//! 文字列表現を揃えるが、依存方向は `core → io`（`docs/architecture.md`）であり
//! io は core に依存しないため、本 crate 内で独立に定義する。

use std::error::Error;
use std::fmt;

/// `IoError` の機械可読な分類（ERR-1）。
///
/// `#[non_exhaustive]` により、呼び出し側の `match` は将来のバリアント追加に備えて
/// `_` 分岐を持つ必要がある。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IoErrorCode {
    /// 引数が不正（形式・範囲の違反。例: [`crate::transport::IoTimeout`] の範囲外）。
    InvalidArgument,
    /// 相手の応答待ちが上限時間を超えた（REPAIR-5）。
    Timeout,
    /// 接続断・相手不在（トランスポートがすでに閉じている）。
    Unavailable,
    /// 未実装。
    Unimplemented,
    /// 内部エラー。
    Internal,
    /// フレームのチェックサム不一致（TASK-11.3・IO-1・REPAIR-2・#70）。
    ///
    /// [`crate::protocol::Frame::decode_body`] がヘッダ＋ペイロードから計算した
    /// CRC-32C と、フレーム末尾のチェックサムが一致しない場合に返す。長さの
    /// 不一致（[`IoErrorCode::InvalidArgument`]）とは別のコードとして区別する
    /// （PoC-8 BREAK-2 のような偶発的破損の検出であり、真正性〔改ざん耐性〕は
    /// 保証しない。詳細は `docs/design/io-protocol.md`）。
    ///
    /// gRPC 正準コードの `DATA_LOSS` を借用した名称であり、ERR-1/3/5 の既定表には
    /// ない拡張コード。spec `error-format.md` への反映要否は spec 側への報告事項
    /// （spec-reference）。
    DataLoss,
    /// 呼び出し側が設定した上限に達しており、これ以上の資源確保を拒否する
    /// （TASK-12.1・IO-1・#73）。
    ///
    /// [`crate::client::SendQueue`] が未 ACK 件数の上限（[`crate::client::InFlightLimit`]）
    /// に達したときに、[`crate::client::PipelineClient::send`] がトランスポートへの
    /// 書き込み前に返す。無制限にリソースを確保し続けることを防ぐための境界であり
    /// （security.md「不安全な設計」観点）、`InvalidArgument`（引数そのものの形式・
    /// 範囲違反）とは区別する。
    ///
    /// gRPC 正準コードの `RESOURCE_EXHAUSTED` を借用した名称であり、`DataLoss` と
    /// 同じく ERR-1/3/5 の既定表にはない拡張コード。spec `error-format.md` への
    /// 反映要否は spec 側への報告事項（spec-reference）。
    ResourceExhausted,
}

impl IoErrorCode {
    /// エラーコードを ERR-1 の機械可読文字列表現に変換する。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::Timeout => "TIMEOUT",
            Self::Unavailable => "UNAVAILABLE",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::DataLoss => "DATA_LOSS",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
        }
    }
}

impl fmt::Display for IoErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `transport` の送受信トレイトが返す構造化エラー（ERR-1: 機械可読な `code` /
/// 人間可読な `message`）。
///
/// # 契約
/// - `message` にペイロード内容・レジストリ資格情報等の秘密情報を含めない
///   （security.md）。
/// - 相手側（untrusted なトランスポートの先）由来の文字列を `message` に載せる場合、
///   その長さの上限検証は受信実装（TASK-12・TASK-13）の責務であり、本型はそれを
///   前提とせず任意長の `String` をそのまま保持する。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IoError {
    code: IoErrorCode,
    message: String,
}

impl IoError {
    /// エラーコードとメッセージから構造化エラーを作る。
    pub fn new(code: IoErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// 機械可読なエラーコードを返す。
    pub fn code(&self) -> IoErrorCode {
        self.code
    }

    /// 人間可読なエラーメッセージを返す。
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for IoError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// IO-1: `IoErrorCode` の全バリアントが ERR-1 の機械可読文字列と一致する。
    #[test]
    fn io1_error_code_as_str_matches_all_variants() {
        assert_eq!(IoErrorCode::InvalidArgument.as_str(), "INVALID_ARGUMENT");
        assert_eq!(IoErrorCode::Timeout.as_str(), "TIMEOUT");
        assert_eq!(IoErrorCode::Unavailable.as_str(), "UNAVAILABLE");
        assert_eq!(IoErrorCode::Unimplemented.as_str(), "UNIMPLEMENTED");
        assert_eq!(IoErrorCode::Internal.as_str(), "INTERNAL");
        assert_eq!(IoErrorCode::DataLoss.as_str(), "DATA_LOSS");
        assert_eq!(
            IoErrorCode::ResourceExhausted.as_str(),
            "RESOURCE_EXHAUSTED"
        );
    }

    /// IO-1: `IoError` の `Display` が `"<CODE>: <message>"` 形式になる。
    #[test]
    fn io1_io_error_display_includes_code_and_message() {
        let err = IoError::new(IoErrorCode::Timeout, "ack not received within timeout");
        assert_eq!(err.to_string(), "TIMEOUT: ack not received within timeout");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert_eq!(err.message(), "ack not received within timeout");
    }
}
