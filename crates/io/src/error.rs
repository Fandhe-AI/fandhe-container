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
    ///
    /// spec `error-format.md` の ERR-3 対応表の `DEADLINE_EXCEEDED` に当たる。ERR-1・
    /// ERR-5 と I/O 共有プロトコルの `code` 文字列では `TIMEOUT` と表記する（同表の注記。
    /// ACK 待ち〔TASK-12〕・UDS の受付と送受信〔TASK-13.2.1〕の期限超過で返す。MS-1）。
    Timeout,
    /// 接続断・相手不在（トランスポートがすでに閉じている）。
    ///
    /// spec `error-format.md` の ERR-3 対応表の `UNAVAILABLE`。接続し直せば回復し得る
    /// 状態を表し、`InvalidArgument`（要求内容の誤り）とは区別する（相手が閉じた接続・
    /// エラー後に失効した接続の再使用で返す。TASK-12・TASK-13.2.1・MS-1）。
    Unavailable,
    /// 未実装。
    Unimplemented,
    /// 内部エラー。
    Internal,
    /// フレームのチェックサム不一致（TASK-11.3・IO-1・REPAIR-2・#70）。
    ///
    /// [`crate::protocol::Frame::decode_body`] がヘッダ＋ペイロードから計算した
    /// CRC-32C と、フレーム末尾のチェックサムが一致しない場合に返す。
    /// [`crate::protocol::FrameHeader::from_bytes`] がヘッダ単体の CRC-32C
    /// （`header_crc`。設計レビュー・2026-09-28 オーナー決定・#67・#115）の
    /// 不一致を検出した場合も同じコードを返す。長さの不一致
    /// （[`IoErrorCode::InvalidArgument`]）とは別のコードとして区別する
    /// （PoC-8 BREAK-2 のような偶発的破損の検出であり、真正性〔改ざん耐性〕は
    /// 保証しない。詳細は `docs/design/io-protocol.md`）。
    ///
    /// gRPC 正準コードの `DATA_LOSS` を借用した名称。spec
    /// `error-format.md` の ERR-3 対応表に `DATA_LOSS` として定義済み
    /// （2026-09-28 追加。受信データの破損検出全般を指し、I/O 共有プロトコルの
    /// フレーム破損もこのコードを返す旨が明記されている）。
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
    /// 受信経路でも同じ意味で使う: [`crate::recv_limits::ReceiveLimits::admit`]
    /// （TASK-13.4・#796）が、申告長または滞留件数が設定上限に達したフレームを
    /// 本体バッファ確保前に拒否する際に返す。
    ///
    /// gRPC 正準コードの `RESOURCE_EXHAUSTED` を借用した名称であり、`DataLoss` と
    /// 同じく ERR-1/3/5 の既定表にはない拡張コード。spec `error-format.md` への
    /// 反映要否は spec 側への報告事項（spec-reference）。
    ResourceExhausted,
    /// 既存の対象と衝突しており、これ以上の作成・登録を拒否する
    /// （TASK-19.1・IO-5・#99）。
    ///
    /// [`crate::fs_normalize::CaseCollisionSet::try_insert`] が、既に登録済みの
    /// パスと大文字小文字または Unicode 正規化（NFC/NFD）の違いだけで衝突する相対パスを
    /// 拒否する際に返す（TASK-21.1）
    /// （APFS / NTFS の大文字小文字非区別と ext4 の区別との差異により、ゲスト側で
    /// 別ファイルとして作成するとホスト側で黙って上書きされうるため、ゲスト側で
    /// 検出してエラーを返す）。
    ///
    /// spec `error-format.md` の ERR-3 対応表の `ALREADY_EXISTS` と同じ名称。ただし
    /// ERR-3 の定義は「同一 ID のコンテナ・Pod サンドボックスが既に存在する状態での
    /// `Create` 系呼び出し」であり、I/O 共有層（IO-5）のパス衝突での使用は同表に
    /// 明記されていない。spec 側への反映要否は spec 側への報告事項（spec-reference）。
    AlreadyExists,
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
            Self::AlreadyExists => "ALREADY_EXISTS",
        }
    }
}

impl fmt::Display for IoErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// [`IoError`] が保持する `message` の最大バイト数（UTF-8 バイト単位。#1116・
/// ERR-1・IO-1・REPAIR-4）。
///
/// 相手由来の値や OS のエラー文字列を含むメッセージが、ログ・エラー応答へ無制限に
/// 流れることを防ぐ（security.md「不安全な設計」観点）。値を 1024 とした根拠:
/// - 大文字小文字衝突のメッセージ（`fs_normalize`）が約 615 バイトになるため、
///   正当なメッセージを削らない余裕が要る
/// - 観測ログ側の [`crate::MAX_SEND_LOG_MESSAGE_BYTES`]（512）より大きく保つことで、
///   本上限で切られたメッセージは観測ログでも必ず `message_truncated: true` になる
///   （`observe.rs` の `const` アサートで固定する）
pub const MAX_IO_ERROR_MESSAGE_BYTES: usize = 1024;

/// `message` を `max_bytes` バイト以内へ UTF-8 の文字境界で切り詰める。
///
/// 戻り値は `(切り詰め後の文字列, 切り詰めが発生したか)`。外部入力起点の文字列を
/// 添字アクセスせず `get` で切り出す。[`IoError::new`] と
/// `observe::truncate_message_bytes` から呼ばれる。
pub(crate) fn truncate_str_to_bytes(message: &str, max_bytes: usize) -> (&str, bool) {
    let end = truncation_end(message, max_bytes);
    if end == message.len() {
        return (message, false);
    }
    (message.get(..end).unwrap_or(""), true)
}

/// `max_bytes` 以下で最大の文字境界のバイト位置を返す（`message.len()` 以下）。
fn truncation_end(message: &str, max_bytes: usize) -> usize {
    if message.len() <= max_bytes {
        return message.len();
    }
    let mut end = max_bytes;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// `transport` の送受信トレイトが返す構造化エラー（ERR-1: 機械可読な `code` /
/// 人間可読な `message`）。
///
/// # 契約
/// - `message` にペイロード内容・レジストリ資格情報等の秘密情報を含めない
///   （security.md）。
/// - `message` は常に [`MAX_IO_ERROR_MESSAGE_BYTES`] バイト以下で、[`IoError::new`] が
///   超過分を UTF-8 の文字境界で切り捨てる（#1116）。保持・[`fmt::Display`]・
///   [`fmt::Debug`]・上位 crate への伝播のすべてがこの上限で有界になる。切り捨ての
///   有無は [`IoError::message_truncated`] で分かる。切り捨てには `...` 等の印を足さない。
/// - 上限は保持量の境界であり、呼び出し元が `new` へ渡す前に巨大な `String` を作る
///   こと自体は防げない（相手由来の長さの検証は受信実装の責務）。
/// - 制御文字のエスケープは本型では行わない（出力側の責務）。
/// - `PartialEq` は切り捨てフラグも比較する（切り捨てた結果と、同じ内容を最初から
///   渡したものは不一致になる）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct IoError {
    code: IoErrorCode,
    message: String,
    message_truncated: bool,
}

impl IoError {
    /// エラーコードとメッセージから構造化エラーを作る。
    ///
    /// `message` が [`MAX_IO_ERROR_MESSAGE_BYTES`] を超える場合は文字境界で切り捨てる。
    /// 切り捨ての有無にかかわらず、capacity が上限を超えている場合は余剰容量を解放する
    /// （`message_truncated` は内容の切り捨てだけを表す）。
    pub fn new(code: IoErrorCode, message: impl Into<String>) -> Self {
        let mut message: String = message.into();
        let end = truncation_end(&message, MAX_IO_ERROR_MESSAGE_BYTES);
        let message_truncated = end < message.len();
        if message_truncated {
            message.truncate(end);
        }
        // 切り捨ての有無とは独立に、必要長に対して過大な capacity は解放する
        // （受信バッファを短縮して渡された場合などに巨大な確保を保持し続けない）。
        // 通常の `format!` 由来の小さな余剰（上限以下）では再確保しない。
        if message.capacity() > MAX_IO_ERROR_MESSAGE_BYTES {
            message.shrink_to_fit();
        }
        Self {
            code,
            message,
            message_truncated,
        }
    }

    /// `new` に渡されたメッセージが [`MAX_IO_ERROR_MESSAGE_BYTES`] を超え、切り捨てられた
    /// かを返す。
    pub fn message_truncated(&self) -> bool {
        self.message_truncated
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
        assert_eq!(IoErrorCode::AlreadyExists.as_str(), "ALREADY_EXISTS");
    }

    /// IO-1: `IoError` の `Display` が `"<CODE>: <message>"` 形式になる。
    #[test]
    fn io1_io_error_display_includes_code_and_message() {
        let err = IoError::new(IoErrorCode::Timeout, "ack not received within timeout");
        assert_eq!(err.to_string(), "TIMEOUT: ack not received within timeout");
        assert_eq!(err.code(), IoErrorCode::Timeout);
        assert_eq!(err.message(), "ack not received within timeout");
    }

    /// ERR-1・IO-1（#1116）: 上限ちょうどは切り捨てず、1 バイト超は上限まで切る。
    #[test]
    fn err1_message_limit_boundaries() {
        let exact = IoError::new(IoErrorCode::Timeout, "a".repeat(1024));
        assert_eq!(exact.message().len(), 1024);
        assert!(!exact.message_truncated());

        let over = IoError::new(IoErrorCode::Timeout, "a".repeat(1025));
        assert_eq!(over.message(), "a".repeat(1024));
        assert!(over.message_truncated());
    }

    /// ERR-1・REPAIR-4（#1116）: 巨大入力でも Display / Debug が有界になる。
    #[test]
    fn err1_huge_message_is_bounded_in_display_and_debug() {
        let err = IoError::new(IoErrorCode::Timeout, "a".repeat(1024 * 1024));
        assert_eq!(err.message().len(), 1024);
        assert!(err.message_truncated());
        assert_eq!(err.to_string().len(), "TIMEOUT: ".len() + 1024);
        let debug = format!("{err:?}");
        assert!(!debug.contains(&"a".repeat(1025)));
        assert!(debug.contains("message_truncated: true"));
    }

    /// ERR-1（#1116）: マルチバイト文字の途中では文字の手前で切る。
    #[test]
    fn err1_message_limit_respects_char_boundaries() {
        let three = IoError::new(IoErrorCode::Internal, format!("{}あ", "a".repeat(1023)));
        assert_eq!(three.message().len(), 1023);
        assert!(three.message_truncated());

        let four = IoError::new(
            IoErrorCode::Internal,
            format!("{}\u{1F600}", "a".repeat(1022)),
        );
        assert_eq!(four.message().len(), 1022);
        assert!(four.message_truncated());

        let fits = IoError::new(IoErrorCode::Internal, format!("{}あ", "a".repeat(1021)));
        assert_eq!(fits.message().len(), 1024);
        assert!(!fits.message_truncated());

        let only = IoError::new(IoErrorCode::Internal, "あ".repeat(400));
        assert_eq!(only.message().len(), 1023);
        assert_eq!(only.message().chars().count(), 341);
        assert!(only.message_truncated());
    }

    /// ERR-1（#1116）: 空文字列と短文は不変。
    #[test]
    fn err1_short_and_empty_messages_are_unchanged() {
        let empty = IoError::new(IoErrorCode::Internal, "");
        assert_eq!(empty.message(), "");
        assert!(!empty.message_truncated());
        let short = IoError::new(IoErrorCode::Internal, "short");
        assert_eq!(short.message(), "short");
        assert!(!short.message_truncated());
    }

    /// ERR-1（#1116）: 短文でも過大な capacity は解放される。
    #[test]
    fn err1_short_message_releases_excess_capacity() {
        let mut big = String::with_capacity(1024 * 1024);
        big.push_str("short");
        let err = IoError::new(IoErrorCode::Internal, big);
        assert_eq!(err.message(), "short");
        assert!(!err.message_truncated());
        assert!(err.message.capacity() <= MAX_IO_ERROR_MESSAGE_BYTES);
    }

    /// ERR-1（#1116）: ヘルパー単体の具体値。
    #[test]
    fn err1_truncate_str_to_bytes_concrete_values() {
        assert_eq!(truncate_str_to_bytes("abc", 0), ("", true));
        assert_eq!(truncate_str_to_bytes("abc", 1), ("a", true));
        assert_eq!(truncate_str_to_bytes("abc", 3), ("abc", false));
        assert_eq!(truncate_str_to_bytes("あい", 4), ("あ", true));
        assert_eq!(truncate_str_to_bytes("あ", 2), ("", true));
    }
}
