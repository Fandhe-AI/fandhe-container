//! stdio JSON-RPC 2.0 による MCP サーバーの処理（MCP-1・MCP-2。TASK-118.2・MS-4・#465）。
//!
//! bin（`src/main.rs`）から stdin / stdout を渡されて呼ばれる。準拠する MCP のリビジョンは 2025-06-18
//! （2026-07-28 版への追随は MCP-3・TASK-119）。フレーミングは改行区切りの 1 行 1 メッセージで、
//! 応答ごとに flush する。プロトコル処理は純関数 [`handle_message`] に切り出し、プロセスを起動せず
//! 具体値で検証できるようにしている。JSON の符号化・入出力・期限管理はトランスポート側（[`serve`]）が持つ。
//!
//! 期限（REPAIR-5）: 接続のアイドル待ち（次のメッセージの先頭バイトが来るまで）は無期限だが、
//! メッセージの先頭バイトを受けてから 1 行を読み切るまでは [`Limits::message_timeout`]、
//! 応答の書き込み・flush は [`Limits::write_timeout`] で打ち切り、超過時は [`ServeError`] を返す。
//! stdin / stdout の読み書きは専用スレッドで行い、停止したスレッドはプロセス終了で回収される。
//!
//! 可観測性（REPAIR-4）: 要求ごとに 1 行 JSON（`event` / `op` / `result` / `code` / `latency_us`）を
//! ログ sink（既定は stderr）へ出す。`op` は既知メソッドの固定名か `other` で、入力値は反射させない。
//!
//! 実装済み: `initialize`・`tools/list`・`ping`、通知の黙殺（`notifications/initialized` 等）。
//!
//! 未実装（REPAIR-3）: `tools/call` は `UNIMPLEMENTED` を返すだけで、TASK-118.3（#466）で
//! コンテナ実行層の操作へ接続する。エラー型は `provisional_error` の仮実装で、ERR-5 の対応表に
//! 沿った `error.rs` と `isError: true` への変換は TASK-120（#469・#470）で置き換える。
//! UDS 経由の疎通と peer 認証（PLUG-12）は TASK-118.4（#467）。

use std::io::{self, BufRead, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Map, Value, json};

/// 本サーバーが応答する MCP のプロトコル版（MCP-1）。
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// 1 行あたりの受信上限（バイト）。超過分は確保せず読み捨てる（無制限確保による DoS 対策）。
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// メッセージ受信開始後に 1 行を読み切るまでの既定の期限（REPAIR-5）。
/// AGENTS.md の推奨（新規の応答待ちは 5〜10 秒）の上限に合わせる。1 行は最大 1 MiB で、
/// 先頭バイト受信後の読み切りに 10 秒を超える正当な理由はない。
pub const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);

/// 応答 1 件の書き込み・flush の既定の期限（REPAIR-5）。推奨範囲（5〜10 秒）の上限に合わせる。
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// 診断出力（stderr）を待つ上限。超過時は診断を捨てて処理を続ける（REPAIR-5）。
pub const DIAG_TIMEOUT: Duration = Duration::from_secs(2);

/// ログ用キューの深さ。満杯なら新しい行を捨てる（要求処理を止めない）。
const LOG_QUEUE_DEPTH: usize = 64;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

/// [`serve_with`] の上限・期限。
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// 1 行あたりの受信上限（バイト）。
    pub max_line_bytes: usize,
    /// メッセージの先頭バイト受信から 1 行を読み切るまでの期限。
    pub message_timeout: Duration,
    /// 応答 1 件の書き込み・flush の期限。
    pub write_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_line_bytes: MAX_LINE_BYTES,
            message_timeout: MESSAGE_TIMEOUT,
            write_timeout: WRITE_TIMEOUT,
        }
    }
}

/// [`serve`] の失敗。入出力の内容は `Display` に含めない。
#[derive(Debug)]
pub enum ServeError {
    /// 入力側の読み込み失敗。
    Read(io::Error),
    /// 出力側の書き込み・flush 失敗。
    Write(io::Error),
    /// メッセージ受信開始後、期限内に 1 行を読み切れなかった（REPAIR-5）。
    ReadTimeout,
    /// 応答の書き込み・flush が期限内に完了しなかった（REPAIR-5）。
    WriteTimeout,
    /// 応答の JSON 符号化に失敗した（通知の無応答とは区別する）。
    Encode,
    /// 読み書きスレッドを生成できなかった（OS のスレッド上限等）。
    Spawn(io::Error),
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeError::Read(_) => f.write_str("failed to read request"),
            ServeError::Write(_) => f.write_str("failed to write response"),
            ServeError::ReadTimeout => f.write_str("timed out reading request"),
            ServeError::WriteTimeout => f.write_str("timed out writing response"),
            ServeError::Encode => f.write_str("failed to encode response"),
            ServeError::Spawn(_) => f.write_str("failed to spawn worker thread"),
        }
    }
}

impl std::error::Error for ServeError {}

/// [`handle_message`] の結果。応答の有無・種別とログ用の分類を持つ。
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// 返す JSON-RPC 応答。通知・クライアントからの応答など応答不要なら `None`（処理エラーではない）。
    pub reply: Option<Value>,
    /// ログ用の操作名。既知メソッドの固定名か `other`（入力値は反射させない）。
    pub op: &'static str,
    /// 応答が JSON-RPC エラーのときのコード。
    pub error_code: Option<i64>,
}

impl Outcome {
    fn none(op: &'static str) -> Self {
        Self {
            reply: None,
            op,
            error_code: None,
        }
    }

    fn ok(op: &'static str, reply: Value) -> Self {
        Self {
            reply: Some(reply),
            op,
            error_code: None,
        }
    }

    fn err(op: &'static str, reply: Value, code: i64) -> Self {
        Self {
            reply: Some(reply),
            op,
            error_code: Some(code),
        }
    }
}

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

/// 仮のエラー応答生成（REPAIR-3）。TASK-120（#469）で ERR-5 の対応表に沿った `error.rs` へ置き換える。
/// `message` は固定の英文のみを渡し、入力値を反射させない。
fn error_outcome(
    op: &'static str,
    id: Value,
    code: i64,
    message: &str,
    data_code: Option<&str>,
) -> Outcome {
    let mut error = Map::new();
    error.insert("code".into(), json!(code));
    error.insert("message".into(), json!(message));
    if let Some(c) = data_code {
        error.insert("data".into(), json!({"code": c}));
    }
    Outcome::err(
        op,
        json!({"jsonrpc": "2.0", "id": id, "error": error}),
        code,
    )
}

/// 成功応答を組み立てる。result の変換に失敗したら内部エラー応答にする。
fn success(op: &'static str, id: Value, result: impl Serialize) -> Outcome {
    match serde_json::to_value(result) {
        Ok(result) => Outcome::ok(op, json!({"jsonrpc": "2.0", "id": id, "result": result})),
        Err(_) => error_outcome(op, id, INTERNAL_ERROR, "Internal error", None),
    }
}

/// `initialize` の params を検証する（MCP 2025-06-18: protocolVersion・capabilities・clientInfo 必須）。
fn initialize_params_valid(params: Option<&Value>) -> bool {
    let Some(p) = params.and_then(Value::as_object) else {
        return false;
    };
    let version_ok = p.get("protocolVersion").is_some_and(Value::is_string);
    let caps_ok = p.get("capabilities").is_some_and(Value::is_object);
    let info_ok = p
        .get("clientInfo")
        .and_then(Value::as_object)
        .is_some_and(|i| {
            i.get("name").is_some_and(Value::is_string)
                && i.get("version").is_some_and(Value::is_string)
        });
    version_ok && caps_ok && info_ok
}

/// 既知メソッドの固定名（ログ用）。未知は `other`。
fn op_name(method: &str) -> &'static str {
    match method {
        "initialize" => "initialize",
        "tools/list" => "tools/list",
        "tools/call" => "tools/call",
        "ping" => "ping",
        m if m.starts_with("notifications/") => "notification",
        _ => "other",
    }
}

/// 1 メッセージ（改行除去済みの 1 行）を処理する。応答不要（通知・クライアントからの応答）は
/// `reply: None`。入口で [`MAX_LINE_BYTES`] を超える入力を解析前に拒否する。JSON 符号化は呼び出し側
/// （[`serve`]）が行う。外部入力は `get()` / `as_*()` で取り出し panic しない。
pub fn handle_message(line: &[u8]) -> Outcome {
    if line.len() > MAX_LINE_BYTES {
        return error_outcome(
            "other",
            Value::Null,
            INVALID_REQUEST,
            "Invalid Request",
            None,
        );
    }
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return error_outcome("other", Value::Null, PARSE_ERROR, "Parse error", None);
    };
    // 2025-06-18 は JSON-RPC のバッチを廃止している。配列もここで拒否する。
    let Some(obj) = value.as_object() else {
        return error_outcome(
            "other",
            Value::Null,
            INVALID_REQUEST,
            "Invalid Request",
            None,
        );
    };

    let op = obj
        .get("method")
        .and_then(Value::as_str)
        .map_or("other", op_name);
    let raw_id = obj.get("id");
    // 文字列・整数の id のみ有効（MCP は null を許さない）。
    let valid_id = raw_id
        .filter(|v| v.is_string() || v.is_i64() || v.is_u64())
        .cloned();
    let invalid = || {
        error_outcome(
            op,
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
            return Outcome::none("response");
        }
        return invalid();
    };
    // id の無いメッセージは通知。未知のメソッドでも応答しない。
    if raw_id.is_none() {
        return Outcome::none(op);
    }
    let Some(id) = valid_id.clone() else {
        return invalid();
    };

    // params は省略・オブジェクト・配列のいずれか（JSON-RPC 2.0）。既知メソッド共通の入口で検証する。
    let params_type_ok = obj
        .get("params")
        .is_none_or(|p| p.is_object() || p.is_array());
    if !params_type_ok && matches!(method, "initialize" | "tools/list" | "tools/call" | "ping") {
        return error_outcome(op, id, INVALID_PARAMS, "Invalid params", None);
    }

    match method {
        "initialize" => {
            if !initialize_params_valid(obj.get("params")) {
                return error_outcome(op, id, INVALID_PARAMS, "Invalid params", None);
            }
            success(
                op,
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
            )
        }
        "tools/list" => success(
            op,
            id,
            ToolsListResult {
                tools: tool_definitions(),
            },
        ),
        "ping" => success(op, id, json!({})),
        // スタブ（REPAIR-3）: TASK-118.3（#466）で実装する。
        "tools/call" => error_outcome(
            op,
            id,
            INTERNAL_ERROR,
            "Not implemented",
            Some("UNIMPLEMENTED"),
        ),
        _ => error_outcome(op, id, METHOD_NOT_FOUND, "Method not found", None),
    }
}

/// 標準の上限・期限で EOF まで処理する。EOF で `Ok(())`。ログは stderr へ 1 行 JSON で出す。
pub fn serve<R, W>(reader: R, writer: W) -> Result<(), ServeError>
where
    R: BufRead + Send + 'static,
    W: Write + Send + 'static,
{
    // stderr が詰まっても要求処理を止めないよう、ログは専用スレッドへ非ブロッキングで渡す（REPAIR-5）。
    let (tx, rx) = mpsc::sync_channel::<String>(LOG_QUEUE_DEPTH);
    // 配送完了の合図。終了時に未配送ログを期限付きで待つために使う（REPAIR-4・REPAIR-5）。
    let (done_tx, done_rx) = mpsc::sync_channel::<()>(1);
    let spawned = thread::Builder::new()
        .name("mcp-log".into())
        .spawn(move || {
            for line in rx {
                // 壊れた stderr で panic しない。詰まった場合はこのスレッドだけが止まる。
                let _ = writeln!(io::stderr(), "{line}");
            }
            let _ = done_tx.send(());
        });
    let logger_alive = spawned.is_ok();
    let result = serve_with(reader, writer, Limits::default(), &mut |line| {
        if logger_alive {
            // 満杯・切断時は捨てる（try_send は待たない）。
            let _ = tx.try_send(line.to_owned());
        }
    });
    // Sender を drop してキューを閉じ、ログスレッドが drain し終えるのを DIAG_TIMEOUT まで待つ。
    // stderr が停止していれば期限で打ち切り、終了は止めない。
    drop(tx);
    if logger_alive {
        let _ = done_rx.recv_timeout(DIAG_TIMEOUT);
    }
    result
}

/// 診断 1 行を stderr へ書く。書き込みを専用スレッドで行い [`DIAG_TIMEOUT`] で打ち切る（REPAIR-5）。
/// 期限超過・スレッド生成失敗時は診断を捨てる。bin が終了時の診断に使う。
pub fn write_diagnostic(line: &str) {
    let owned = format!("{line}\n");
    let (tx, rx) = mpsc::sync_channel::<()>(1);
    let spawned = thread::Builder::new()
        .name("mcp-diag".into())
        .spawn(move || {
            let mut err = io::stderr();
            let _ = err.write_all(owned.as_bytes()).and_then(|()| err.flush());
            let _ = tx.send(());
        });
    if spawned.is_ok() {
        let _ = rx.recv_timeout(DIAG_TIMEOUT);
    }
}

/// 1 行の読み取り結果。
enum Line {
    Data(Vec<u8>),
    Overflow,
}

/// 読み取りスレッドからの通知。
enum Event {
    /// メッセージの先頭バイトを受けた（ここから [`Limits::message_timeout`] を数える）。
    Started,
    Line(Line),
    Eof,
    Failed(io::Error),
}

/// 1 行を読む。上限超過分は積まずに改行まで読み捨て `Overflow` を返す。EOF のみなら `None`。
/// 先頭バイトを受けた時点で `on_start` を 1 度呼ぶ。
fn read_line<R: BufRead>(
    reader: &mut R,
    limit: usize,
    on_start: &mut dyn FnMut(),
) -> io::Result<Option<Line>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut overflow = false;
    let mut seen = false;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            break;
        }
        if !seen {
            seen = true;
            on_start();
        }
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

/// 構造化ログ 1 行（REPAIR-4）。`op` は固定名のみで入力値を含まない。
fn log_request(log: &mut dyn FnMut(&str), outcome: &Outcome, started: Instant) {
    let result = match (&outcome.reply, outcome.error_code) {
        (None, _) => "no_reply",
        (Some(_), None) => "ok",
        (Some(_), Some(_)) => "error",
    };
    let line = json!({
        "event": "mcp.request",
        "op": outcome.op,
        "result": result,
        "code": outcome.error_code,
        "latency_us": u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
    });
    log(&line.to_string());
}

/// トランスポート障害のログ 1 行。
fn log_transport(log: &mut dyn FnMut(&str), code: &str) {
    log(&json!({"event": "mcp.transport", "result": "error", "code": code}).to_string());
}

/// 上限・期限・ログ sink を指定して EOF まで処理する。
///
/// 読み書きは専用スレッドで行い、本関数は期限付きで結果を待つ（REPAIR-5）。
pub fn serve_with<R, W>(
    mut reader: R,
    mut writer: W,
    limits: Limits,
    log: &mut dyn FnMut(&str),
) -> Result<(), ServeError>
where
    R: BufRead + Send + 'static,
    W: Write + Send + 'static,
{
    let (ev_tx, ev_rx) = mpsc::sync_channel::<Event>(4);
    let max_line = limits.max_line_bytes;
    let (out_tx, out_rx) = mpsc::sync_channel::<String>(1);
    let (done_tx, done_rx) = mpsc::sync_channel::<io::Result<()>>(1);
    // 書き込みスレッドを先に作る。読み取りスレッドの生成に失敗したら out_tx を drop して回収させる。
    if let Err(e) = thread::Builder::new()
        .name("mcp-write".into())
        .spawn(move || {
            for text in out_rx {
                let res = writer
                    .write_all(text.as_bytes())
                    .and_then(|()| writer.write_all(b"\n"))
                    .and_then(|()| writer.flush());
                let failed = res.is_err();
                if done_tx.send(res).is_err() || failed {
                    break;
                }
            }
        })
    {
        log_transport(log, "UNAVAILABLE");
        return Err(ServeError::Spawn(e));
    }
    let reader_spawn = thread::Builder::new()
        .name("mcp-read".into())
        .spawn(move || {
            loop {
                let started_tx = ev_tx.clone();
                let mut on_start = move || {
                    let _ = started_tx.send(Event::Started);
                };
                match read_line(&mut reader, max_line, &mut on_start) {
                    Ok(None) => {
                        let _ = ev_tx.send(Event::Eof);
                        break;
                    }
                    Ok(Some(line)) => {
                        if ev_tx.send(Event::Line(line)).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = ev_tx.send(Event::Failed(e));
                        break;
                    }
                }
            }
        });
    if let Err(e) = reader_spawn {
        // out_tx は return で drop され、書き込みスレッドは終了する。
        drop(out_tx);
        log_transport(log, "UNAVAILABLE");
        return Err(ServeError::Spawn(e));
    }

    loop {
        // アイドル待ちは無期限。メッセージの先頭バイトが来てからは期限付き。
        let Ok(first) = ev_rx.recv() else {
            return Ok(());
        };
        let line = match first {
            Event::Eof => return Ok(()),
            Event::Failed(e) => {
                log_transport(log, "UNAVAILABLE");
                return Err(ServeError::Read(e));
            }
            Event::Line(l) => l,
            Event::Started => match ev_rx.recv_timeout(limits.message_timeout) {
                Ok(Event::Line(l)) => l,
                Ok(Event::Failed(e)) => {
                    log_transport(log, "UNAVAILABLE");
                    return Err(ServeError::Read(e));
                }
                Ok(Event::Eof | Event::Started) | Err(RecvTimeoutError::Disconnected) => {
                    return Ok(());
                }
                Err(RecvTimeoutError::Timeout) => {
                    log_transport(log, "DEADLINE_EXCEEDED");
                    return Err(ServeError::ReadTimeout);
                }
            },
        };
        let began = Instant::now();
        let outcome = match line {
            Line::Overflow => error_outcome(
                "other",
                Value::Null,
                INVALID_REQUEST,
                "Invalid Request",
                None,
            ),
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
        if let Some(reply) = &outcome.reply {
            let Ok(text) = serde_json::to_string(reply) else {
                log_transport(log, "INTERNAL");
                return Err(ServeError::Encode);
            };
            if out_tx.send(text).is_err() {
                log_transport(log, "UNAVAILABLE");
                return Err(ServeError::Write(io::Error::from(
                    io::ErrorKind::BrokenPipe,
                )));
            }
            match done_rx.recv_timeout(limits.write_timeout) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    log_transport(log, "UNAVAILABLE");
                    return Err(ServeError::Write(e));
                }
                Err(RecvTimeoutError::Timeout) => {
                    log_transport(log, "DEADLINE_EXCEEDED");
                    return Err(ServeError::WriteTimeout);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    log_transport(log, "UNAVAILABLE");
                    return Err(ServeError::Write(io::Error::from(
                        io::ErrorKind::BrokenPipe,
                    )));
                }
            }
        }
        log_request(log, &outcome, began);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    fn call(line: &str) -> Option<Value> {
        handle_message(line.as_bytes()).reply.inspect(|v| {
            assert!(!v.to_string().contains('\n'));
        })
    }

    fn init_req(id: &str, ver: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"initialize","params":{{"protocolVersion":"{ver}","capabilities":{{}},"clientInfo":{{"name":"t","version":"0"}}}}}}"#
        )
    }

    /// テスト用の共有出力バッファ（serve は writer を 'static で受けるため）。
    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SharedBuf {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    fn run(input: String, limits: Limits) -> (Result<(), ServeError>, String, Vec<String>) {
        let out = SharedBuf::default();
        let mut logs = Vec::new();
        let r = serve_with(Cursor::new(input), out.clone(), limits, &mut |l| {
            logs.push(l.to_owned());
        });
        (r, out.text(), logs)
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
    fn mcp1_initialize_rejects_invalid_params_with_32602() {
        let cases = [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":[]}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"t","version":"0"}}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":[],"clientInfo":{"name":"t","version":"0"}}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t"}}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":1,"version":"0"}}}"#,
        ];
        for case in cases {
            let v = call(case).unwrap();
            assert_eq!(
                v,
                json!({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params"}}),
                "case: {case}"
            );
        }
    }

    /// MCP-1: initialize 以外でも params がオブジェクト・配列以外なら -32602。
    #[test]
    fn mcp1_non_initialize_rejects_scalar_params_with_32602() {
        for method in ["tools/list", "ping"] {
            for params in ["1", "\"invalid\"", "true", "null"] {
                let line =
                    format!(r#"{{"jsonrpc":"2.0","id":3,"method":"{method}","params":{params}}}"#);
                let v = call(&line).unwrap();
                assert_eq!(
                    v,
                    json!({"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Invalid params"}}),
                    "case: {line}"
                );
            }
            for params in ["{}", "[]"] {
                let line =
                    format!(r#"{{"jsonrpc":"2.0","id":3,"method":"{method}","params":{params}}}"#);
                assert!(call(&line).unwrap().get("result").is_some(), "case: {line}");
            }
        }
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
        let o = handle_message(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert_eq!(
            o,
            Outcome {
                reply: None,
                op: "notification",
                error_code: None
            }
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
        let o = handle_message(&[0xff, 0xfe, b'{']);
        assert_eq!(o.error_code, Some(-32700));
    }

    #[test]
    fn oversized_input_is_rejected_before_parsing() {
        // 有効な JSON でも上限超過なら解析せず -32600（REPAIR-5 の入口検査）。
        let pad = " ".repeat(MAX_LINE_BYTES);
        let line = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"ping"{pad}}}"#);
        let o = handle_message(line.as_bytes());
        assert_eq!(o.error_code, Some(-32600));
        assert_eq!(o.reply.unwrap()["id"], Value::Null);
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
        let o = handle_message(br#"{"jsonrpc":"2.0","id":1,"method":"zzSECRETzz"}"#);
        assert!(!o.reply.unwrap().to_string().contains("zzSECRETzz"));
        assert_eq!(o.op, "other");
    }

    #[test]
    fn serve_answers_lines_in_order_skipping_notifications() {
        let input = format!(
            "{}\n{}\n\n   \n{}\r\n",
            init_req("1", "2025-06-18"),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#
        );
        let (r, text, _) = run(input, Limits::default());
        r.unwrap();
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
        let limits = Limits {
            max_line_bytes: 64,
            ..Limits::default()
        };
        let (r, text, _) = run(input, limits);
        r.unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("-32600"));
        assert!(lines[1].contains(r#""result":{}"#));
    }

    #[test]
    fn serve_logs_structured_record_per_request_without_input_content() {
        let input = format!(
            "{}\n{}\n{}\n",
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"zzSECRETzz"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        );
        let (r, _, logs) = run(input, Limits::default());
        r.unwrap();
        assert_eq!(logs.len(), 3);
        let recs: Vec<Value> = logs
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(recs[0]["event"], "mcp.request");
        assert_eq!(recs[0]["op"], "ping");
        assert_eq!(recs[0]["result"], "ok");
        assert_eq!(recs[0]["code"], Value::Null);
        assert!(recs[0]["latency_us"].is_u64());
        assert_eq!(recs[1]["op"], "other");
        assert_eq!(recs[1]["result"], "error");
        assert_eq!(recs[1]["code"], -32601);
        assert_eq!(recs[2]["op"], "notification");
        assert_eq!(recs[2]["result"], "no_reply");
        assert!(logs.iter().all(|l| !l.contains("zzSECRETzz")));
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

    /// 先頭の断片を返したあと一定時間ブロックする reader（REPAIR-5 の受信停止の模擬）。
    struct StallReader {
        sent: bool,
    }
    impl io::Read for StallReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }
    impl BufRead for StallReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.sent {
                thread::sleep(Duration::from_secs(3));
                Ok(&[])
            } else {
                self.sent = true;
                Ok(b"{\"jsonrpc\"")
            }
        }
        fn consume(&mut self, _: usize) {}
    }

    #[test]
    fn serve_times_out_when_message_stalls_after_first_byte() {
        let limits = Limits {
            message_timeout: Duration::from_millis(100),
            ..Limits::default()
        };
        let mut logs = Vec::new();
        let r = serve_with(
            StallReader { sent: false },
            SharedBuf::default(),
            limits,
            &mut |l| logs.push(l.to_owned()),
        );
        assert!(matches!(r, Err(ServeError::ReadTimeout)));
        assert!(logs[0].contains("DEADLINE_EXCEEDED"));
    }

    struct StallWriter;
    impl Write for StallWriter {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            thread::sleep(Duration::from_secs(3));
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn serve_times_out_when_response_write_stalls() {
        let limits = Limits {
            write_timeout: Duration::from_millis(100),
            ..Limits::default()
        };
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let r = serve_with(Cursor::new(input), StallWriter, limits, &mut |_| {});
        assert!(matches!(r, Err(ServeError::WriteTimeout)));
    }
}
