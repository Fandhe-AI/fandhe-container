//! MCP サーバーのエラー型（JSON-RPC 2.0 エラーオブジェクトと ERR-5 の対応表。MCP-4・ERR-5・TASK-120.1）。
//!
//! `crate::server` の応答組み立てから呼ばれ、次の 2 経路を型で分ける。
//! - [`ProtocolError`]: プロトコルレベルの失敗。JSON-RPC `error`（`code` / `message` / `data.code`）になる。
//!   `data.code` は ERR-1 体系（core の `ErrorCode`）。
//! - [`ToolError`]: ツール実行時の業務エラー。JSON-RPC error にせず `tools/call` の result
//!   （`isError: true`、`content[0].text` に `{"code","message"}` の JSON）へ変換する。
//!
//! 契約: `message` は分類ごとの固定英文のみ。メソッド名・ツール名・id・入力値、および
//! `TraitError::message`（パス等を含み得る）を応答へ反射させない。
//! `data.code` について ERR-5 が定めるのは、全プロトコルエラーに ERR-1 体系の `code` を付けることだけで、
//! 5 行とも値は書かれていない。割り当て（`-32700` / `-32600` / `-32602` -> `INVALID_ARGUMENT`、
//! `-32601` -> `UNIMPLEMENTED`、`-32603` -> `INTERNAL`）は ERR-3 の分類に沿った本実装の判断で、
//! spec へ明記するかはオーナー確認事項（#2217 で追跡）。
//! `server.rs` が全てのエラー応答をこの型経由で組み立てる（TASK-120.2・#470）。

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
        }
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
    /// 引数のスキーマ違反・params の型不正（`-32602`）。
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

/// ツール実行時の業務エラー（ERR-5 の `isError` 行。MCP-4・TASK-120.1）。
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

    /// ERR-1 体系の分類。
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// 分類名（`NOT_FOUND` 等）。
    pub fn code_str(&self) -> &'static str {
        self.code.as_str()
    }

    /// 分類ごとの固定英文。
    pub fn message(&self) -> &'static str {
        match self.code {
            ErrorCode::InvalidArgument => "Invalid argument",
            ErrorCode::NotFound => "Container not found",
            ErrorCode::AlreadyExists => "Already exists",
            ErrorCode::FailedPrecondition => "Operation not allowed in the current state",
            ErrorCode::Unimplemented => "Not implemented",
            ErrorCode::PermissionDenied => "Permission denied",
            ErrorCode::Timeout => "Operation timed out",
            ErrorCode::Unavailable => "Backend unavailable",
            ErrorCode::ResourceExhausted => "Resource exhausted",
            _ => "Internal error",
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
