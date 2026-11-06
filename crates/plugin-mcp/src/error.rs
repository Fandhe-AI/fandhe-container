//! MCP サーバーのエラー型（JSON-RPC 2.0 エラーオブジェクトと ERR-5 の対応表。MCP-4・ERR-5・TASK-120.1）。
//!
//! `crate::server` の応答組み立てから呼ばれ、次の 2 経路を型で分ける。
//! - [`ProtocolError`]: プロトコルレベルの失敗。JSON-RPC `error`（`code` / `message` / `data.code`）になる。
//!   `data.code` は ERR-1 体系（core の `ErrorCode`）。
//! - [`ToolError`]: ツール実行時の業務エラー。JSON-RPC error にせず `tools/call` の result
//!   （`isError: true`、`content[0].text` に `{"code","message"}` の JSON）へ変換する。
//!
//! 引数の誤りは版で分かれる（ERR-5・SEP-1303・D8）。2025-06-18 の経路は [`ProtocolError::InvalidArguments`]
//! （`-32602`）、2026-07-28 の経路は [`ToolError::invalid_argument`]（`isError`）。要求の形の不正は両経路とも `-32602`。
//!
//! 契約: `message` は分類ごとの固定英文のみ。メソッド名・ツール名・id・入力値、および
//! `TraitError::message`（パス等を含み得る）を応答へ反射させない。
//! `data.code` の割り当て（`-32700` / `-32600` / `-32602` -> `INVALID_ARGUMENT`、
//! `-32601` -> `UNIMPLEMENTED`、`-32603` -> `INTERNAL`）は ERR-5 の表が定める（#2217）。
//! `server.rs` が全てのエラー応答をこの型経由で組み立てる（TASK-120.2・#470）。
//!
//! MCP 2026-07-28 の `-32022`（未対応の版）は入力値（`data.requested`）を持つため
//! [`UnsupportedVersionError`] が担う（MCP-3・TASK-119.2）。`-32020`〜`-32099` は MCP の予約範囲で、
//! 本サーバーが返すのは `-32022` のみ。`data.code` は `-32022` -> `UNIMPLEMENTED`。

use fandhe_container_core::traits::{ErrorCode, TraitError};
use serde_json::{Value, json};

/// JSON-RPC 2.0 の標準エラーコード（ERR-5 の表で使うもの）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonRpcCode {
    /// `-32700`
    ParseError,
    /// `-32600`
    InvalidRequest,
    /// `-32601`
    MethodNotFound,
    /// `-32602`
    InvalidParams,
    /// `-32603`
    InternalError,
    /// `-32022`（MCP 2026-07-28 の `UnsupportedProtocolVersionError`。`-32020`〜`-32099` の予約範囲。MCP-3・TASK-119.2）
    UnsupportedProtocolVersion,
}

impl JsonRpcCode {
    /// JSON-RPC の数値コード。
    pub const fn code(self) -> i64 {
        match self {
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::InternalError => -32603,
            Self::UnsupportedProtocolVersion => -32022,
        }
    }

    /// 標準の固定メッセージ（入力値を含まない）。
    pub const fn message(self) -> &'static str {
        match self {
            Self::ParseError => "Parse error",
            Self::InvalidRequest => "Invalid Request",
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
            Self::InternalError => "Internal error",
            Self::UnsupportedProtocolVersion => "Unsupported protocol version",
        }
    }
}

/// `data.requested` の最大バイト数（切り詰めの上限。入力の反射を有界にする。MCP-3・D2）。
pub const MAX_REQUESTED_VERSION_BYTES: usize = 64;

/// 未対応の MCP プロトコル版（`-32022`。`data` に `supported`・`requested`、`data.code = UNIMPLEMENTED`。
/// MCP-3・TASK-119.2・D9）。
///
/// `ProtocolError` は入力値を持たない `Copy` 型のため別の型にした。`requested` は外部入力なので、
/// コンストラクタで [`MAX_REQUESTED_VERSION_BYTES`] 以下（UTF-8 の文字境界）に切り詰め、型で上限を保証する。
/// `message` とログには入力値を入れない（REPAIR-4）。`-32021`（必要な機能の欠如）は返さない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedVersionError {
    requested: String,
    supported: &'static [&'static str],
}

impl UnsupportedVersionError {
    /// 要求された版（切り詰め前の任意文字列）と対応版の一覧から作る。
    pub fn new(requested: &str, supported: &'static [&'static str]) -> Self {
        let mut end = requested.len().min(MAX_REQUESTED_VERSION_BYTES);
        while !requested.is_char_boundary(end) {
            end -= 1;
        }
        Self {
            requested: requested.get(..end).unwrap_or_default().to_owned(),
            supported,
        }
    }

    /// 対応する JSON-RPC コード（`-32022`）。
    pub const fn rpc_code(&self) -> JsonRpcCode {
        JsonRpcCode::UnsupportedProtocolVersion
    }

    /// JSON-RPC の `error` オブジェクト（`data` は `supported`・`requested`・`code`）。
    pub fn to_error_object(&self) -> Value {
        let rpc = self.rpc_code();
        json!({
            "code": rpc.code(),
            "message": rpc.message(),
            "data": {
                "supported": self.supported,
                "requested": self.requested,
                "code": ErrorCode::Unimplemented.as_str(),
            },
        })
    }

    /// エラー応答全体。
    pub fn to_response(&self, id: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "error": self.to_error_object()})
    }
}

/// プロトコルレベルの失敗（ERR-5 の JSON-RPC error 行。MCP-4・TASK-120.1）。
///
/// バリアントが `code` / `message` / `data.code` の組を一意に決めるため、誤った組み合わせを表現できない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// JSON として解釈できない（`-32700`）。
    Parse,
    /// JSON-RPC リクエストとして不正（`-32600`）。
    InvalidRequest,
    /// 存在しないメソッド（`-32601`）。
    MethodNotFound,
    /// 未知のツール名（ERR-5 では `-32602`）。
    UnknownTool,
    /// `tools/call` の要求の形の不正、`_meta` の必須フィールドの欠落、2025-06-18 の経路の引数のスキーマ違反（`-32602`）。
    /// 2026-07-28 の経路の引数の誤りは [`ToolError::invalid_argument`]（`isError`。ERR-5・D8）。
    InvalidArguments,
    /// サーバー内部の失敗（`-32603`）。
    Internal,
}

impl ProtocolError {
    /// 対応する JSON-RPC 標準コード。
    pub const fn rpc_code(self) -> JsonRpcCode {
        match self {
            Self::Parse => JsonRpcCode::ParseError,
            Self::InvalidRequest => JsonRpcCode::InvalidRequest,
            Self::MethodNotFound => JsonRpcCode::MethodNotFound,
            Self::UnknownTool | Self::InvalidArguments => JsonRpcCode::InvalidParams,
            Self::Internal => JsonRpcCode::InternalError,
        }
    }

    /// `error.data.code` に載せる ERR-1 体系の分類。
    pub const fn data_code(self) -> ErrorCode {
        match self {
            Self::Parse | Self::InvalidRequest | Self::UnknownTool | Self::InvalidArguments => {
                ErrorCode::InvalidArgument
            }
            Self::MethodNotFound => ErrorCode::Unimplemented,
            Self::Internal => ErrorCode::Internal,
        }
    }

    /// JSON-RPC の `error` オブジェクト（`code` / `message` / `data.code`）。
    pub fn to_error_object(self) -> Value {
        let rpc = self.rpc_code();
        json!({
            "code": rpc.code(),
            "message": rpc.message(),
            "data": {"code": self.data_code().as_str()},
        })
    }

    /// エラー応答全体。`id` は呼び出し側で検証済みの値をそのまま `id` フィールドへ置く。
    pub fn to_response(self, id: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "error": self.to_error_object()})
    }
}

/// ツール実行時の業務エラー（ERR-5 の `isError` 行。MCP-4・TASK-120.1）。2026-07-28 の経路では
/// 入力検証の誤り（[`ToolError::invalid_argument`]。SEP-1303・D8・#4001）も担う。
///
/// 保持するのは分類のみ。`TraitError::message` はパス等を含み得るため一切出力へ流さない。
/// `UNAVAILABLE` は ERR-5 の表に無い core の拡張分類だが、現行どおり業務結果として扱う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolError {
    code: ErrorCode,
}

impl ToolError {
    /// バックエンドの失敗から分類だけを取り出す。
    pub fn from_trait_error(err: &TraitError) -> Self {
        Self { code: err.code() }
    }

    /// 2026-07-28 の経路の入力検証の誤り（`INVALID_ARGUMENT`。ERR-5・SEP-1303・D8）。
    /// `message` は固定英文で、入力値・フィールド名を含めない（REPAIR-4）。
    pub const fn invalid_argument() -> Self {
        Self {
            code: ErrorCode::InvalidArgument,
        }
    }

    /// ERR-1 体系の分類。
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// 分類名（`NOT_FOUND` 等）。
    pub fn code_str(&self) -> &'static str {
        self.code.as_str()
    }

    /// 分類ごとの固定英文。`ErrorCode::ALL` と同数の表から引く（`Internal` も明示。表の外の
    /// 将来の code は `"Internal error"`。REPAIR-1・ERR-1）。
    pub fn message(&self) -> &'static str {
        TOOL_ERROR_MESSAGES
            .iter()
            .find(|(c, _)| *c == self.code)
            .map_or("Internal error", |(_, m)| m)
    }

    /// `tools/call` の result（`isError: true`。`content[0].text` は `{"code","message"}` の JSON 文字列）。
    pub fn to_call_result(&self) -> Value {
        let body = json!({"code": self.code_str(), "message": self.message()});
        json!({
            "content": [{"type": "text", "text": body.to_string()}],
            "isError": true,
        })
    }
}

/// `ToolError::message` の表（`ErrorCode::ALL` と同数。試験が網羅と重複なしを照合する）。
const TOOL_ERROR_MESSAGES: [(ErrorCode, &str); 10] = [
    (ErrorCode::InvalidArgument, "Invalid argument"),
    (ErrorCode::NotFound, "Container not found"),
    (ErrorCode::AlreadyExists, "Already exists"),
    (
        ErrorCode::FailedPrecondition,
        "Operation not allowed in the current state",
    ),
    (ErrorCode::Unimplemented, "Not implemented"),
    (ErrorCode::Internal, "Internal error"),
    (ErrorCode::PermissionDenied, "Permission denied"),
    (ErrorCode::Timeout, "Operation timed out"),
    (ErrorCode::Unavailable, "Backend unavailable"),
    (ErrorCode::ResourceExhausted, "Resource exhausted"),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// MCP-3: `-32022` のコード・固定文言・`data` の完全一致。
    #[test]
    fn mcp3_unsupported_version_error_object() {
        let e = UnsupportedVersionError::new("1900-01-01", &["2026-07-28"]);
        assert_eq!(
            e.to_response(json!(7)),
            json!({"jsonrpc":"2.0","id":7,"error":{
                "code":-32022,"message":"Unsupported protocol version",
                "data":{"supported":["2026-07-28"],"requested":"1900-01-01","code":"UNIMPLEMENTED"}}})
        );
        assert_eq!(JsonRpcCode::UnsupportedProtocolVersion.code(), -32022);
    }

    /// MCP-3・D2: `requested` は 64 バイトで切り詰め、文字境界を割らない。
    #[test]
    fn mcp3_unsupported_version_requested_is_truncated_on_char_boundary() {
        let exact = "a".repeat(64);
        let e = UnsupportedVersionError::new(&exact, &["2026-07-28"]);
        assert_eq!(e.to_error_object()["data"]["requested"], exact.as_str());
        let long = "a".repeat(65);
        let e = UnsupportedVersionError::new(&long, &["2026-07-28"]);
        assert_eq!(e.to_error_object()["data"]["requested"], exact.as_str());
        // 'あ' は 3 バイト。63 バイト + 'あ' は 66 バイトで、64 バイトの境界は途中になる。
        let multi = format!("{}あ", "a".repeat(63));
        let e = UnsupportedVersionError::new(&multi, &["2026-07-28"]);
        assert_eq!(
            e.to_error_object()["data"]["requested"],
            "a".repeat(63).as_str()
        );
        let e = UnsupportedVersionError::new("", &["2026-07-28"]);
        assert_eq!(e.to_error_object()["data"]["requested"], "");
    }

    /// REPAIR-1・ERR-1: 文言の表が `ErrorCode::ALL` を過不足なく覆い、全件で文言が空でない。
    #[test]
    fn mcp4_err5_tool_error_message_table_covers_all() {
        assert_eq!(TOOL_ERROR_MESSAGES.len(), ErrorCode::ALL.len());
        for (i, code) in ErrorCode::ALL.into_iter().enumerate() {
            let hits = TOOL_ERROR_MESSAGES
                .iter()
                .filter(|(c, _)| *c == code)
                .count();
            assert_eq!(hits, 1, "{code:?}");
            assert_eq!(TOOL_ERROR_MESSAGES[i].0, code);
            let m = ToolError { code }.message();
            assert!(!m.is_empty(), "{code:?}");
        }
    }

    #[test]
    fn mcp4_err5_protocol_error_table() {
        let cases = [
            (
                ProtocolError::Parse,
                -32700,
                "Parse error",
                "INVALID_ARGUMENT",
            ),
            (
                ProtocolError::InvalidRequest,
                -32600,
                "Invalid Request",
                "INVALID_ARGUMENT",
            ),
            (
                ProtocolError::MethodNotFound,
                -32601,
                "Method not found",
                "UNIMPLEMENTED",
            ),
            (
                ProtocolError::UnknownTool,
                -32602,
                "Invalid params",
                "INVALID_ARGUMENT",
            ),
            (
                ProtocolError::InvalidArguments,
                -32602,
                "Invalid params",
                "INVALID_ARGUMENT",
            ),
            (
                ProtocolError::Internal,
                -32603,
                "Internal error",
                "INTERNAL",
            ),
        ];
        for (err, code, message, data) in cases {
            assert_eq!(
                err.to_response(json!(7)),
                json!({"jsonrpc": "2.0", "id": 7,
                    "error": {"code": code, "message": message, "data": {"code": data}}}),
                "{err:?}"
            );
        }
    }

    #[test]
    fn mcp4_err5_unknown_tool_is_32602_invalid_argument() {
        let e = ProtocolError::UnknownTool.to_error_object();
        assert_eq!(e["code"], json!(-32602));
        assert_eq!(e["message"], json!("Invalid params"));
        assert_eq!(e["data"]["code"], json!("INVALID_ARGUMENT"));
    }

    #[test]
    fn mcp4_err5_invalid_arguments_is_32602_invalid_argument() {
        let e = ProtocolError::InvalidArguments.to_error_object();
        assert_eq!(e["code"], json!(-32602));
        assert_eq!(e["message"], json!("Invalid params"));
        assert_eq!(e["data"]["code"], json!("INVALID_ARGUMENT"));
    }

    #[test]
    fn mcp4_err5_method_not_found_is_32601() {
        let e = ProtocolError::MethodNotFound.to_error_object();
        assert_eq!(e["code"], json!(-32601));
        assert_eq!(e["message"], json!("Method not found"));
        assert_eq!(e["data"]["code"], json!("UNIMPLEMENTED"));
    }

    #[test]
    fn mcp4_err5_internal_error_carries_internal_code() {
        let e = ProtocolError::Internal.to_error_object();
        assert_eq!(e["code"], json!(-32603));
        assert_eq!(e["data"]["code"], json!("INTERNAL"));
    }

    #[test]
    fn mcp4_err5_json_rpc_code_values() {
        let cases = [
            (JsonRpcCode::ParseError, -32700, "Parse error"),
            (JsonRpcCode::InvalidRequest, -32600, "Invalid Request"),
            (JsonRpcCode::MethodNotFound, -32601, "Method not found"),
            (JsonRpcCode::InvalidParams, -32602, "Invalid params"),
            (JsonRpcCode::InternalError, -32603, "Internal error"),
        ];
        for (c, n, m) in cases {
            assert_eq!(c.code(), n);
            assert_eq!(c.message(), m);
        }
    }

    #[test]
    fn mcp4_err5_business_error_becomes_is_error_result() {
        let cases = [
            (ErrorCode::NotFound, "NOT_FOUND", "Container not found"),
            (
                ErrorCode::FailedPrecondition,
                "FAILED_PRECONDITION",
                "Operation not allowed in the current state",
            ),
            (ErrorCode::AlreadyExists, "ALREADY_EXISTS", "Already exists"),
            (
                ErrorCode::PermissionDenied,
                "PERMISSION_DENIED",
                "Permission denied",
            ),
            (ErrorCode::Timeout, "TIMEOUT", "Operation timed out"),
            (ErrorCode::Unimplemented, "UNIMPLEMENTED", "Not implemented"),
            (ErrorCode::Unavailable, "UNAVAILABLE", "Backend unavailable"),
            (
                ErrorCode::ResourceExhausted,
                "RESOURCE_EXHAUSTED",
                "Resource exhausted",
            ),
            (ErrorCode::Internal, "INTERNAL", "Internal error"),
            (
                ErrorCode::InvalidArgument,
                "INVALID_ARGUMENT",
                "Invalid argument",
            ),
        ];
        for (code, name, message) in cases {
            let err = ToolError::from_trait_error(&TraitError::new(code, "detail"));
            assert_eq!(err.code_str(), name);
            let result = err.to_call_result();
            assert_eq!(result["isError"], json!(true));
            assert!(result.get("error").is_none());
            let content = result["content"].as_array().expect("content array");
            assert_eq!(content.len(), 1);
            assert_eq!(content[0]["type"], json!("text"));
            let text = content[0]["text"].as_str().expect("text");
            let parsed: Value = serde_json::from_str(text).expect("json text");
            assert_eq!(parsed, json!({"code": name, "message": message}));
        }
    }

    #[test]
    fn mcp4_err5_business_error_does_not_leak_trait_message() {
        let e = TraitError::new(ErrorCode::NotFound, "/secret/zzSECRETzz");
        let out = ToolError::from_trait_error(&e).to_call_result().to_string();
        assert!(!out.contains("zzSECRETzz"));
    }

    #[test]
    fn mcp4_err5_protocol_error_ignores_id_contents() {
        let resp = ProtocolError::UnknownTool.to_response(json!("zzIDzz"));
        assert_eq!(resp["id"], json!("zzIDzz"));
        let err = resp["error"].to_string();
        assert!(!err.contains("zzIDzz"));
    }

    /// MCP-4・ERR-5: 2026-07-28 の経路の入力検証の誤りは固定文言の `isError` result になる。
    #[test]
    fn err5_tool_error_invalid_argument_call_result() {
        let te = ToolError::invalid_argument();
        assert_eq!(te.code_str(), "INVALID_ARGUMENT");
        assert_eq!(
            te.to_call_result(),
            json!({
                "content": [{"type": "text", "text": "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"Invalid argument\"}"}],
                "isError": true,
            })
        );
    }
}
