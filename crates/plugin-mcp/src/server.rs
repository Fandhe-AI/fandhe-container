//! stdio JSON-RPC 2.0 による MCP サーバーの処理（MCP-1・MCP-2。TASK-118.2・#465）。
//!
//! bin（`src/main.rs`）から stdin / stdout を渡されて呼ばれる。準拠する MCP のリビジョンは 2025-06-18
//! （2026-07-28 版への追随は MCP-3・TASK-119）。フレーミングは改行区切りの 1 行 1 メッセージで、
//! 応答ごとに flush する。プロトコル処理は純関数 [`handle_message`] に切り出し、プロセスを起動せず
//! 具体値で検証できるようにしている。
//!
//! 実装済み: `initialize`・`tools/list`・`ping`、通知の黙殺（`notifications/initialized` 等）。
//!
//! 未実装（REPAIR-3）: `tools/call` は `UNIMPLEMENTED` を返すだけで、TASK-118.3（#466）で
//! コンテナ実行層の操作へ接続する。エラー型は `provisional_error` の仮実装で、ERR-5 の対応表に
//! 沿った `error.rs` と `isError: true` への変換は TASK-120（#469・#470）で置き換える。
//! UDS 経由の疎通と peer 認証（PLUG-12）は TASK-118.4（#467）。

use std::io::{self, BufRead, Write};

use serde::Serialize;
use serde_json::{Map, Value, json};

/// 本サーバーが応答する MCP のプロトコル版（MCP-1）。
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// 1 行あたりの受信上限（バイト）。超過分は確保せず読み捨てる（無制限確保による DoS 対策）。
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INTERNAL_ERROR: i64 = -32603;

/// [`serve`] の失敗。入出力の内容は `Display` に含めない。
#[derive(Debug)]
pub enum ServeError {
    /// 入力側の読み込み失敗。
    Read(io::Error),
    /// 出力側の書き込み・flush 失敗。
    Write(io::Error),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeError::Read(_) => f.write_str("failed to read request"),
            ServeError::Write(_) => f.write_str("failed to write response"),
        }
    }
}

impl std::error::Error for ServeError {}

/// `initialize` の result（MCP 2025-06-18）。
#[derive(Serialize)]
struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    protocol_version: &'static str,
    capabilities: Capabilities,
    #[serde(rename = "serverInfo")]
    server_info: ServerInfo,
}

#[derive(Serialize)]
struct Capabilities {
    tools: ToolsCapability,
}

#[derive(Serialize)]
struct ToolsCapability {
    #[serde(rename = "listChanged")]
    list_changed: bool,
}

#[derive(Serialize)]
struct ServerInfo {
    name: &'static str,
    version: &'static str,
}

/// `tools/list` の result。ページングはしないため `nextCursor` を持たない。
#[derive(Serialize)]
struct ToolsListResult {
    tools: Vec<Tool>,
}

/// ツール定義（MCP-2）。`inputSchema` は 2025-06-18 で必須。
#[derive(Serialize)]
struct Tool {
    name: &'static str,
    description: &'static str,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
}

/// MCP-2 の 2 ツールの定義（PoC-13 の参照実装と同じスキーマ形）。
fn tool_definitions() -> Vec<Tool> {
    vec![
        Tool {
            name: "list_containers",
            description: "List containers managed by fandhe-container.",
            input_schema: json!({"type": "object", "properties": {}}),
        },
        Tool {
            name: "start_container",
            description: "Start the container identified by container_id.",
            input_schema: json!({
                "type": "object",
                "properties": {"container_id": {"type": "string"}},
                "required": ["container_id"]
            }),
        },
    ]
}

/// 成功応答を 1 行 JSON に符号化する。
fn success(id: Value, result: impl Serialize) -> Option<String> {
    let result = serde_json::to_value(result).ok()?;
    serde_json::to_string(&json!({"jsonrpc": "2.0", "id": id, "result": result})).ok()
}

/// 仮のエラー応答生成（REPAIR-3）。TASK-120（#469）で ERR-5 の対応表に沿った `error.rs` へ置き換える。
/// `message` は固定の英文のみを渡し、入力値を反射させない。
fn provisional_error(
    id: Value,
    code: i64,
    message: &str,
    data_code: Option<&str>,
) -> Option<String> {
    let mut error = Map::new();
    error.insert("code".into(), json!(code));
    error.insert("message".into(), json!(message));
    if let Some(c) = data_code {
        error.insert("data".into(), json!({"code": c}));
    }
    serde_json::to_string(&json!({"jsonrpc": "2.0", "id": id, "error": error})).ok()
}

/// 1 メッセージ（改行除去済みの 1 行）を処理する。応答不要（通知・クライアントからの応答）は `None`。
/// 返す文字列は 1 行 JSON で改行を含まない。外部入力は `get()` / `as_*()` で取り出し panic しない。
pub fn handle_message(line: &[u8]) -> Option<String> {
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return provisional_error(Value::Null, PARSE_ERROR, "Parse error", None);
    };
    // 2025-06-18 は JSON-RPC のバッチを廃止している。配列もここで拒否する。
    let Some(obj) = value.as_object() else {
        return provisional_error(Value::Null, INVALID_REQUEST, "Invalid Request", None);
    };

    let raw_id = obj.get("id");
    // 文字列・整数の id のみ有効（MCP は null を許さない）。
    let valid_id = raw_id
        .filter(|v| v.is_string() || v.is_i64() || v.is_u64())
        .cloned();
    let invalid = || {
        provisional_error(
            valid_id.clone().unwrap_or(Value::Null),
            INVALID_REQUEST,
            "Invalid Request",
            None,
        )
    };

    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return invalid();
    }
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        // クライアントからの応答（本サーバーはリクエストを送らない）は無視する。
        if obj.contains_key("result") || obj.contains_key("error") {
            return None;
        }
        return invalid();
    };
    // id の無いメッセージは通知。未知のメソッドでも応答しない。
    raw_id?;
    let Some(id) = valid_id.clone() else {
        return invalid();
    };

    match method {
        "initialize" => success(
            id,
            InitializeResult {
                protocol_version: PROTOCOL_VERSION,
                capabilities: Capabilities {
                    tools: ToolsCapability {
                        list_changed: false,
                    },
                },
                server_info: ServerInfo {
                    name: "fandhe-container-plugin-mcp",
                    version: env!("CARGO_PKG_VERSION"),
                },
            },
        ),
        "tools/list" => success(
            id,
            ToolsListResult {
                tools: tool_definitions(),
            },
        ),
        "ping" => success(id, json!({})),
        // スタブ（REPAIR-3）: TASK-118.3（#466）で実装する。
        "tools/call" => {
            provisional_error(id, INTERNAL_ERROR, "Not implemented", Some("UNIMPLEMENTED"))
        }
        _ => provisional_error(id, METHOD_NOT_FOUND, "Method not found", None),
    }
}

/// 標準の上限 [`MAX_LINE_BYTES`] で EOF まで処理する。EOF で `Ok(())`。
pub fn serve<R: BufRead, W: Write>(reader: R, writer: W) -> Result<(), ServeError> {
    serve_with_limit(reader, writer, MAX_LINE_BYTES)
}

/// 1 行の読み取り結果。
enum Line {
    Data(Vec<u8>),
    Overflow,
}

/// 1 行を読む。上限超過分は積まずに改行まで読み捨て `Overflow` を返す。EOF のみなら `None`。
fn read_line<R: BufRead>(reader: &mut R, limit: usize) -> io::Result<Option<Line>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut overflow = false;
    let mut seen = false;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        seen = true;
        let (take, found) = match chunk.iter().position(|&b| b == b'\n') {
            Some(pos) => (pos, true),
            None => (chunk.len(), false),
        };
        if !overflow {
            if buf.len().saturating_add(take) > limit {
                overflow = true;
                buf = Vec::new();
            } else {
                buf.extend_from_slice(chunk.get(..take).unwrap_or_default());
            }
        }
        reader.consume(if found { take + 1 } else { take });
        if found {
            break;
        }
    }
    if !seen {
        return Ok(None);
    }
    if overflow {
        return Ok(Some(Line::Overflow));
    }
    Ok(Some(Line::Data(buf)))
}

fn serve_with_limit<R: BufRead, W: Write>(
    mut reader: R,
    mut writer: W,
    limit: usize,
) -> Result<(), ServeError> {
    loop {
        let line = match read_line(&mut reader, limit).map_err(ServeError::Read)? {
            None => return Ok(()),
            Some(l) => l,
        };
        let response = match line {
            Line::Overflow => {
                provisional_error(Value::Null, INVALID_REQUEST, "Invalid Request", None)
            }
            Line::Data(mut data) => {
                if data.last() == Some(&b'\r') {
                    data.pop();
                }
                if data.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                handle_message(&data)
            }
        };
        if let Some(r) = response {
            writer
                .write_all(r.as_bytes())
                .and_then(|()| writer.write_all(b"\n"))
                .and_then(|()| writer.flush())
                .map_err(ServeError::Write)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn call(line: &str) -> Option<Value> {
        handle_message(line.as_bytes()).map(|s| {
            assert!(!s.contains('\n'));
            serde_json::from_str(&s).expect("response is JSON")
        })
    }

    fn init_req(id: &str, ver: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"initialize","params":{{"protocolVersion":"{ver}","capabilities":{{}},"clientInfo":{{"name":"t","version":"0"}}}}}}"#
        )
    }

    #[test]
    fn mcp1_initialize_returns_protocol_version_2025_06_18() {
        let v = call(&init_req("1", "2025-06-18")).unwrap();
        assert_eq!(
            v,
            json!({"jsonrpc":"2.0","id":1,"result":{
                "protocolVersion":"2025-06-18",
                "capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{"name":"fandhe-container-plugin-mcp","version":env!("CARGO_PKG_VERSION")}
            }})
        );
    }

    #[test]
    fn mcp1_initialize_answers_supported_version_for_other_request() {
        let v = call(&init_req("1", "2024-11-05")).unwrap();
        assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    }

    #[test]
    fn mcp1_initialize_echoes_string_id() {
        let v = call(&init_req("\"abc\"", "2025-06-18")).unwrap();
        assert_eq!(v["id"], "abc");
    }

    #[test]
    fn mcp2_tools_list_returns_two_tool_definitions() {
        let v = call(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).unwrap();
        assert_eq!(
            v,
            json!({"jsonrpc":"2.0","id":2,"result":{"tools":[
                {"name":"list_containers","description":"List containers managed by fandhe-container.",
                 "inputSchema":{"type":"object","properties":{}}},
                {"name":"start_container","description":"Start the container identified by container_id.",
                 "inputSchema":{"type":"object","properties":{"container_id":{"type":"string"}},"required":["container_id"]}}
            ]}})
        );
    }

    #[test]
    fn mcp1_initialized_notification_gets_no_response() {
        assert_eq!(
            call(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            None
        );
    }

    #[test]
    fn unknown_notification_gets_no_response() {
        assert_eq!(call(r#"{"jsonrpc":"2.0","method":"foo/bar"}"#), None);
    }

    #[test]
    fn unknown_method_returns_32601() {
        let v = call(r#"{"jsonrpc":"2.0","id":3,"method":"foo/bar"}"#).unwrap();
        assert_eq!(
            v,
            json!({"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"Method not found"}})
        );
    }

    #[test]
    fn tools_call_is_unimplemented_32603() {
        let v = call(r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}}"#).unwrap();
        assert_eq!(v["error"]["code"], -32603);
        assert_eq!(v["error"]["data"]["code"], "UNIMPLEMENTED");
    }

    #[test]
    fn ping_returns_empty_result() {
        let v = call(r#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#).unwrap();
        assert_eq!(v, json!({"jsonrpc":"2.0","id":5,"result":{}}));
    }

    #[test]
    fn invalid_json_returns_32700_with_null_id() {
        let v = call("{not json").unwrap();
        assert_eq!(
            v,
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})
        );
    }

    #[test]
    fn invalid_utf8_returns_32700() {
        let s = handle_message(&[0xff, 0xfe, b'{']).unwrap();
        assert!(s.contains("-32700"));
    }

    #[test]
    fn batch_array_returns_32600() {
        let v = call(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#).unwrap();
        assert_eq!(v["error"]["code"], -32600);
        assert_eq!(v["id"], Value::Null);
    }

    #[test]
    fn wrong_jsonrpc_version_returns_32600() {
        let v = call(r#"{"jsonrpc":"1.0","id":7,"method":"ping"}"#).unwrap();
        assert_eq!(v["error"]["code"], -32600);
        assert_eq!(v["id"], 7);
    }

    #[test]
    fn null_id_returns_32600() {
        let v = call(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#).unwrap();
        assert_eq!(v["error"]["code"], -32600);
        assert_eq!(v["id"], Value::Null);
    }

    #[test]
    fn missing_method_returns_32600() {
        let v = call(r#"{"jsonrpc":"2.0","id":8}"#).unwrap();
        assert_eq!(v["error"]["code"], -32600);
        assert_eq!(v["id"], 8);
    }

    #[test]
    fn client_response_message_is_ignored() {
        assert_eq!(call(r#"{"jsonrpc":"2.0","id":9,"result":{}}"#), None);
    }

    #[test]
    fn error_message_does_not_echo_method_name() {
        let s = handle_message(br#"{"jsonrpc":"2.0","id":1,"method":"zzSECRETzz"}"#).unwrap();
        assert!(!s.contains("zzSECRETzz"));
    }

    #[test]
    fn serve_answers_lines_in_order_skipping_notifications() {
        let input = format!(
            "{}\n{}\n\n   \n{}\r\n",
            init_req("1", "2025-06-18"),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#
        );
        let mut out = Vec::new();
        serve(Cursor::new(input), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let a: Value = serde_json::from_str(lines[0]).unwrap();
        let b: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(a["id"], 1);
        assert_eq!(b["id"], 2);
        assert_eq!(b["result"]["tools"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn serve_rejects_oversized_line_and_continues() {
        let input = format!(
            "{}\n{}\n",
            "x".repeat(100),
            r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#
        );
        let mut out = Vec::new();
        serve_with_limit(Cursor::new(input), &mut out, 64).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("-32600"));
        assert!(lines[1].contains(r#""result":{}"#));
    }

    struct FailWriter;
    impl Write for FailWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("x"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn serve_reports_write_error() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let r = serve(Cursor::new(input), FailWriter);
        assert!(matches!(r, Err(ServeError::Write(_))));
    }
}
