//! stdio JSON-RPC 2.0 による MCP サーバーの処理（MCP-1・MCP-2。TASK-118.2・MS-4・#465）。
//!
//! bin（`src/main.rs`）から stdin / stdout を渡されて呼ばれる。準拠する MCP のリビジョンは 2025-06-18
//! （legacy。`initialize` で始まる経路）と 2026-07-28（modern。ステートレスコア）の dual-era
//! （MCP-3・TASK-119.2・D1）。フレーミングは改行区切りの 1 行 1 メッセージで、
//! 応答ごとに flush する。プロトコル処理は純関数 [`handle_message_on`] に切り出し、プロセスを起動せず
//! 具体値で検証できるようにしている。JSON の符号化・入出力・期限管理はトランスポート側（[`serve`]）が持つ。
//!
//! 経路の判定（MCP-3）: `params._meta` に `io.modelcontextprotocol/protocolVersion` があれば modern。
//! 版が [`SUPPORTED_VERSIONS`] に無ければ `-32022`、`clientCapabilities` が無ければ `-32602`（版の検査が先）。
//! キーが無ければ、`initialize` か、`initialize` を成功させた接続（[`ConnectionState`]）の要求は legacy、
//! それ以外は `basic/index` の「必須フィールド欠落は拒否」に従い `-32602`。modern の要求は接続状態を
//! 読まず書かない（要求ごとに自己完結）。
//!
//! 期限（REPAIR-5）: 接続のアイドル待ち（次のメッセージの先頭バイトが来るまで）は無期限だが、
//! メッセージの先頭バイトを受けてから 1 行を読み切るまでは [`Limits::message_timeout`]、
//! 応答の書き込み・flush は [`Limits::write_timeout`] で打ち切り、超過時は [`ServeError`] を返す。
//! stdin / stdout の読み書きは専用スレッドで行い、停止したスレッドはプロセス終了で回収される。
//!
//! 可観測性（REPAIR-4）: 要求ごとに 1 行 JSON（`event` / `op` / `result` / `code` / `latency_us`）を
//! ログ sink（既定は stderr）へ出す。`op` は既知メソッドの固定名か `other` で、入力値は反射させない。
//!
//! 実装済み: `initialize`・`tools/list`・`ping`・`tools/call`（`list_containers`・`start_container`。
//! TASK-118.3・#466）、通知の黙殺（`notifications/initialized` 等）。`tools/call` の実行は
//! [`crate::backend::ToolBackend`] へ委ねる。引数の不正は `-32602`（`data.code = INVALID_ARGUMENT`）、
//! バックエンドの業務エラーは result の `isError: true` に固定文言の `{code, message}` を載せる。
//!
//! エラー応答は `crate::error` の `ProtocolError` / `ToolError` で組み立てる（MCP-4・ERR-5・TASK-120.2）。
//!
//! modern の実装済み: `server/discover`・`tools/list`（`ttlMs`・`cacheScope` つき）・`tools/call`。
//! `ping`・`initialize` は modern では `-32601`。result には `_meta` の `serverInfo` と
//! `resultType: "complete"` を足す（`finish_modern` に集約。#717・MCP-3。legacy には付けない）。
//!
//! 未実装・簡易実装（REPAIR-3）: 2026-07-28 の経路の引数不正を `isError` で返す扱いも未実装（#4001。現状は `-32602`）。
//! `start_container` の本番起動は未実装（`crate::backend` の doc を参照。#1718）。
//! UDS 経由の疎通と peer 認証（PLUG-12）は `crate::uds`（TASK-118.4・#467）が持つ。

use std::io::{self, BufRead, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};

use crate::backend::{CoreBackend, ToolBackend, UnavailableBackend};
use crate::error::{ProtocolError, ToolError, UnsupportedVersionError};
use fandhe_container_core::traits::{ContainerId, TraitError};

/// legacy 経路（`initialize`）で応答する MCP のプロトコル版（MCP-1）。
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// modern 経路（ステートレスコア）のプロトコル版（MCP-3・TASK-119.2）。
pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

/// `_meta` で受理する版の一覧（`-32022` の `data.supported`・`server/discover` の `supportedVersions`）。
/// legacy の 2025-06-18 は `initialize` からのみ到達できるため載せない（`docs/design/mcp-2026-07-28-migration.md`）。
pub const SUPPORTED_VERSIONS: [&str; 1] = [MODERN_PROTOCOL_VERSION];

/// `tools/list`・`server/discover` の `ttlMs`。一覧は実行ファイルの差し替えでしか変わらないため 1 時間（MCP-3・D6）。
pub const CACHE_TTL_MS: u64 = 3_600_000;

/// `tools/list`・`server/discover` の `cacheScope`。一覧は全利用者で同一のため `public`（MCP-3・D6）。
pub const CACHE_SCOPE: &str = "public";

/// 要求の `_meta` で版を運ぶキー。
const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// 要求の `_meta` で機能を運ぶキー（欠落は `-32602`）。
const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
/// 応答の `_meta` に載せる `serverInfo` のキー。
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// modern の result に載せる `resultType` のキー（SEP-2322・MCP-3）。
const RESULT_TYPE_KEY: &str = "resultType";
/// `resultType` の値。本サーバーはクライアントへ追加入力を求めない（D4）ので、result は常に完了を表す。
const RESULT_TYPE_COMPLETE: &str = "complete";

const SERVER_NAME: &str = "fandhe-container-plugin-mcp";

/// 接続（stdio プロセスまたは UDS の 1 接続）ごとの状態。保持するのは 1 ビットのみで増大しない。
///
/// legacy の経路で `initialize` が成功したときだけ `legacy` が立つ。modern の要求は読まず書かない
/// （`basic/index` の「前の要求に依存しない」）。`serve_with`・`serve_uds_with` が接続ごとに 1 つ作る。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionState {
    legacy: bool,
}

impl ConnectionState {
    /// `initialize` 済み（legacy）の接続か。
    pub fn is_legacy(&self) -> bool {
        self.legacy
    }
}

/// 要求の経路。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Legacy,
    Modern,
}

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
    /// `tools/call` で実行したツールの固定名（`list_containers` / `start_container`）。それ以外は `None`。
    pub tool: Option<&'static str>,
    /// ツールの業務エラー（`isError: true`）の ERR-1 コード。JSON-RPC としては成功応答のため `error_code` と区別する。
    pub tool_error: Option<&'static str>,
}

impl Outcome {
    fn none(op: &'static str) -> Self {
        Self {
            reply: None,
            op,
            error_code: None,
            tool: None,
            tool_error: None,
        }
    }

    fn ok(op: &'static str, reply: Value) -> Self {
        Self {
            reply: Some(reply),
            op,
            error_code: None,
            tool: None,
            tool_error: None,
        }
    }

    /// プロトコルエラー応答。応答本文とログ用コードを同じ `ProtocolError` から導く（ERR-5）。
    fn err(op: &'static str, id: Value, e: ProtocolError) -> Self {
        Self {
            reply: Some(e.to_response(id)),
            op,
            error_code: Some(e.rpc_code().code()),
            tool: None,
            tool_error: None,
        }
    }

    /// `-32022`（未対応の版）の応答。ログには入力値を載せない（コードのみ。REPAIR-4）。
    fn err_unsupported_version(op: &'static str, id: Value, e: &UnsupportedVersionError) -> Self {
        Self {
            reply: Some(e.to_response(id)),
            op,
            error_code: Some(e.rpc_code().code()),
            tool: None,
            tool_error: None,
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
/// `ttl_ms`・`cache_scope` は modern のときだけ載せる（legacy は 2025-06-18 のまま。MCP-3・D6）。
#[derive(Serialize)]
struct ToolsListResult {
    tools: Vec<Tool>,
    #[serde(rename = "ttlMs", skip_serializing_if = "Option::is_none")]
    ttl_ms: Option<u64>,
    #[serde(rename = "cacheScope", skip_serializing_if = "Option::is_none")]
    cache_scope: Option<&'static str>,
}

/// `server/discover` の result（MCP 2026-07-28。MCP-3）。
#[derive(Serialize)]
struct DiscoverResult {
    #[serde(rename = "supportedVersions")]
    supported_versions: [&'static str; 1],
    capabilities: Capabilities,
    #[serde(rename = "ttlMs")]
    ttl_ms: u64,
    #[serde(rename = "cacheScope")]
    cache_scope: &'static str,
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

/// 成功応答を組み立てる。result の変換に失敗したら内部エラー応答にする。
fn success(op: &'static str, id: Value, result: impl Serialize) -> Outcome {
    match serde_json::to_value(result) {
        Ok(result) => Outcome::ok(op, json!({"jsonrpc": "2.0", "id": id, "result": result})),
        Err(_) => Outcome::err(op, id, ProtocolError::Internal),
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
        "server/discover" => "server/discover",
        m if m.starts_with("notifications/") => "notification",
        _ => "other",
    }
}

/// 1 メッセージを「`initialize` 済みの接続の 1 要求」として処理する薄い入口（[`handle_message_on`] 経由）。
/// 単体試験と、接続状態を持たない呼び出し元向け。`_meta` の無い要求は legacy として扱う。
pub fn handle_message(line: &[u8]) -> Outcome {
    handle_message_with(line, &UnavailableBackend)
}

/// [`handle_message`] のバックエンド指定版。`tools/call` の実行を `backend` へ委ねる（MCP-2）。
pub fn handle_message_with(line: &[u8], backend: &dyn ToolBackend) -> Outcome {
    let mut conn = ConnectionState { legacy: true };
    handle_message_on(line, backend, &mut conn)
}

/// `params._meta` から経路を決める（MCP-3）。`Err` はそのまま返す応答。
///
/// 版の検査を `clientCapabilities` の検査より先に行う。未知の版の必須フィールドは判断できず、
/// `-32022` なら stdio の互換プローブが modern と認識できるため。`clientInfo` 等の任意キーは読まない。
fn detect_route(
    op: &'static str,
    id: &Value,
    method: &str,
    params: Option<&Value>,
    conn: &ConnectionState,
) -> Result<Route, Outcome> {
    let meta = params
        .and_then(Value::as_object)
        .and_then(|p| p.get("_meta"))
        .and_then(Value::as_object);
    let Some(version) = meta.and_then(|m| m.get(META_PROTOCOL_VERSION)) else {
        return if method == "initialize" || conn.legacy {
            Ok(Route::Legacy)
        } else {
            Err(Outcome::err(
                op,
                id.clone(),
                ProtocolError::InvalidArguments,
            ))
        };
    };
    let Some(version) = version.as_str() else {
        return Err(Outcome::err(
            op,
            id.clone(),
            ProtocolError::InvalidArguments,
        ));
    };
    if !SUPPORTED_VERSIONS.contains(&version) {
        let e = UnsupportedVersionError::new(version, &SUPPORTED_VERSIONS);
        return Err(Outcome::err_unsupported_version(op, id.clone(), &e));
    }
    let caps_ok = meta
        .and_then(|m| m.get(META_CLIENT_CAPABILITIES))
        .is_some_and(Value::is_object);
    if !caps_ok {
        return Err(Outcome::err(
            op,
            id.clone(),
            ProtocolError::InvalidArguments,
        ));
    }
    Ok(Route::Modern)
}

/// 接続状態つきで 1 メッセージ（改行除去済みの 1 行）を処理する本体（MCP-3）。応答不要（通知・クライアント
/// からの応答）は `reply: None`。入口で [`MAX_LINE_BYTES`] を超える入力を解析前に拒否する。JSON 符号化は
/// 呼び出し側（[`serve`]）が行う。外部入力は `get()` / `as_*()` で取り出し panic しない。
pub fn handle_message_on(
    line: &[u8],
    backend: &dyn ToolBackend,
    conn: &mut ConnectionState,
) -> Outcome {
    if line.len() > MAX_LINE_BYTES {
        return Outcome::err("other", Value::Null, ProtocolError::InvalidRequest);
    }
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return Outcome::err("other", Value::Null, ProtocolError::Parse);
    };
    // 2025-06-18 は JSON-RPC のバッチを廃止している。配列もここで拒否する。
    let Some(obj) = value.as_object() else {
        return Outcome::err("other", Value::Null, ProtocolError::InvalidRequest);
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
        Outcome::err(
            op,
            valid_id.clone().unwrap_or(Value::Null),
            ProtocolError::InvalidRequest,
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
    // id の無いメッセージは通知。未知のメソッドでも応答しない（経路の判定も掛けない）。
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
    if !params_type_ok
        && matches!(
            method,
            "initialize" | "tools/list" | "tools/call" | "ping" | "server/discover"
        )
    {
        return Outcome::err(op, id, ProtocolError::InvalidArguments);
    }

    match detect_route(op, &id, method, obj.get("params"), conn) {
        Err(outcome) => outcome,
        Ok(Route::Legacy) => dispatch_legacy(op, method, id, obj.get("params"), backend, conn),
        Ok(Route::Modern) => {
            finish_modern(dispatch_modern(op, method, id, obj.get("params"), backend))
        }
    }
}

/// legacy（2025-06-18）のメソッド表。`initialize` の成功だけが接続状態を `legacy` にする。
fn dispatch_legacy(
    op: &'static str,
    method: &str,
    id: Value,
    params: Option<&Value>,
    backend: &dyn ToolBackend,
    conn: &mut ConnectionState,
) -> Outcome {
    match method {
        "initialize" => {
            if !initialize_params_valid(params) {
                return Outcome::err(op, id, ProtocolError::InvalidArguments);
            }
            conn.legacy = true;
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
                        name: SERVER_NAME,
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
                ttl_ms: None,
                cache_scope: None,
            },
        ),
        "ping" => success(op, id, json!({})),
        "tools/call" => tools_call(id, params, backend),
        _ => Outcome::err(op, id, ProtocolError::MethodNotFound),
    }
}

/// modern（2026-07-28）のメソッド表。`initialize`・`ping`・未知のメソッドは `-32601`。
/// 接続状態は受け取らない（要求ごとに自己完結。MCP-3）。
fn dispatch_modern(
    op: &'static str,
    method: &str,
    id: Value,
    params: Option<&Value>,
    backend: &dyn ToolBackend,
) -> Outcome {
    match method {
        "server/discover" => success(
            op,
            id,
            DiscoverResult {
                supported_versions: SUPPORTED_VERSIONS,
                capabilities: Capabilities {
                    tools: ToolsCapability {
                        list_changed: false,
                    },
                },
                ttl_ms: CACHE_TTL_MS,
                cache_scope: CACHE_SCOPE,
            },
        ),
        "tools/list" => success(
            op,
            id,
            ToolsListResult {
                tools: tool_definitions(),
                ttl_ms: Some(CACHE_TTL_MS),
                cache_scope: Some(CACHE_SCOPE),
            },
        ),
        "tools/call" => tools_call(id, params, backend),
        _ => Outcome::err(op, id, ProtocolError::MethodNotFound),
    }
}

/// modern の応答の仕上げ。`result` を持つ応答（`isError: true` を含む）の `_meta` へ `serverInfo` を、
/// 直下へ `resultType: "complete"` を足す（#717・MCP-3）。エラー応答は素通しする。
/// legacy は本関数を通らないので `resultType` が付かない（D3）。
fn finish_modern(mut outcome: Outcome) -> Outcome {
    if let Some(result) = outcome
        .reply
        .as_mut()
        .and_then(|r| r.get_mut("result"))
        .and_then(Value::as_object_mut)
    {
        result.insert(RESULT_TYPE_KEY.to_owned(), json!(RESULT_TYPE_COMPLETE));
        let info = json!({"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")});
        let meta = result
            .entry("_meta")
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(m) = meta.as_object_mut() {
            m.insert(META_SERVER_INFO.to_owned(), info);
        }
    }
    outcome
}

/// 引数不正（`-32602`・`data.code = INVALID_ARGUMENT`）の応答。固定文言のみで、ツール名・ID を反射させない。
fn invalid_arguments(id: Value) -> Outcome {
    Outcome::err("tools/call", id, ProtocolError::InvalidArguments)
}

/// 業務エラーの `tools/call` result（`isError: true`）。`crate::error::ToolError` で組み立て（MCP-4・ERR-5）、
/// `TraitError::message`（パス等を含み得る）は出力へ流さない。
fn tool_error_result(tool: &'static str, id: Value, err: &TraitError) -> Outcome {
    let te = ToolError::from_trait_error(err);
    let result = te.to_call_result();
    let mut out = Outcome::ok(
        "tools/call",
        json!({"jsonrpc": "2.0", "id": id, "result": result}),
    );
    out.tool = Some(tool);
    out.tool_error = Some(te.code_str());
    out
}

/// ツール成功の `tools/call` result。`structuredContent` と同内容の JSON 文字列を `content` にも載せる（2025-06-18）。
fn tool_success_result(tool: &'static str, id: Value, structured: impl Serialize) -> Outcome {
    let Ok(structured) = serde_json::to_value(structured) else {
        return Outcome::err("tools/call", id, ProtocolError::Internal);
    };
    let result = json!({
        "content": [{"type": "text", "text": structured.to_string()}],
        "structuredContent": structured,
        "isError": false,
    });
    let mut out = Outcome::ok(
        "tools/call",
        json!({"jsonrpc": "2.0", "id": id, "result": result}),
    );
    out.tool = Some(tool);
    out
}

/// `tools/call` の params を検証してツールを実行する（MCP-2）。外部入力は `get()` / `as_*()` で扱う。
fn tools_call(id: Value, params: Option<&Value>, backend: &dyn ToolBackend) -> Outcome {
    let Some(params) = params.and_then(Value::as_object) else {
        return invalid_arguments(id);
    };
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return invalid_arguments(id);
    };
    let args = match params.get("arguments") {
        None => None,
        Some(v) => match v.as_object() {
            Some(o) => Some(o),
            None => return invalid_arguments(id),
        },
    };
    match name {
        "list_containers" => match backend.list_containers() {
            Ok(list) => tool_success_result("list_containers", id, list),
            Err(e) => tool_error_result("list_containers", id, &e),
        },
        "start_container" => {
            let Some(cid) = args
                .and_then(|a| a.get("container_id"))
                .and_then(Value::as_str)
                .and_then(|s| ContainerId::new(s).ok())
            else {
                return invalid_arguments(id);
            };
            match backend.start_container(&cid) {
                Ok(started) => tool_success_result("start_container", id, started),
                Err(e) => tool_error_result("start_container", id, &e),
            }
        }
        _ => Outcome::err("tools/call", id, ProtocolError::UnknownTool),
    }
}

/// 標準の上限・期限で EOF まで処理する。EOF で `Ok(())`。ログは stderr へ 1 行 JSON で出す。
pub fn serve<R, W>(reader: R, writer: W) -> Result<(), ServeError>
where
    R: BufRead + Send + 'static,
    W: Write + Send + 'static,
{
    let backend = CoreBackend::production();
    with_stderr_log(|log| serve_with(reader, writer, Limits::default(), &backend, log))
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
pub(crate) enum Line {
    Data(Vec<u8>),
    Overflow,
}

/// 読み取りスレッドからの通知。
enum Event {
    /// メッセージの先頭バイトを受けた合図。期限の起点は共有スロットが持つ。
    /// キューが満杯なら捨てる（`try_send`）。メイン側はイベントを処理するたびに
    /// スロットを読み直すため、取りこぼしても期限監視は失われない（REPAIR-5）。
    Started,
    /// 値は (先頭バイトの受信時刻, 1 行を読み切った時刻)。
    /// キューに滞留しただけの行と実際の期限超過を区別する。
    Line(Line, Instant, Instant),
    Eof,
    Failed(io::Error),
}

/// 1 行を読む。上限超過分は積まずに改行まで読み捨て `Overflow` を返す。EOF のみなら `None`。
/// 先頭バイトを受けた時点で `on_start` を 1 度呼ぶ。
pub(crate) fn read_line<R: BufRead>(
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
pub(crate) fn log_request(log: &mut dyn FnMut(&str), outcome: &Outcome, started: Instant) {
    let result = match (&outcome.reply, outcome.error_code) {
        (None, _) => "no_reply",
        (Some(_), None) => "ok",
        (Some(_), Some(_)) => "error",
    };
    let result = if outcome.tool_error.is_some() {
        "tool_error"
    } else {
        result
    };
    let line = json!({
        "event": "mcp.request",
        "op": outcome.op,
        "tool": outcome.tool,
        "result": result,
        "code": outcome.tool_error.map_or_else(|| json!(outcome.error_code), |c| json!(c)),
        "latency_us": u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
    });
    log(&line.to_string());
}

/// トランスポート障害のログ 1 行。
pub(crate) fn log_transport(log: &mut dyn FnMut(&str), code: &str) {
    log(&json!({"event": "mcp.transport", "result": "error", "code": code}).to_string());
}

/// 読み切った 1 行を JSON-RPC として処理する。空白のみの行は読み飛ばして `None`。
///
/// stdio の [`serve_with`] と UDS の `crate::uds::serve_uds_with` が共有する。末尾の `\r` は除去し、
/// 上限超過は `-32600` にする（MCP-1。入力内容は応答へ反射させない）。
pub(crate) fn process_line(
    line: Line,
    backend: &dyn ToolBackend,
    conn: &mut ConnectionState,
) -> Option<Outcome> {
    match line {
        Line::Overflow => Some(Outcome::err(
            "other",
            Value::Null,
            ProtocolError::InvalidRequest,
        )),
        Line::Data(mut data) => {
            if data.last() == Some(&b'\r') {
                data.pop();
            }
            if data.iter().all(u8::is_ascii_whitespace) {
                return None;
            }
            Some(handle_message_on(&data, backend, conn))
        }
    }
}

/// ログを専用スレッド経由で stderr へ非ブロッキングに出しながら `f` を実行する。
///
/// stderr が詰まっても要求処理を止めず、終了時は未配送ログを [`DIAG_TIMEOUT`] まで待つ
/// （REPAIR-4・REPAIR-5）。[`serve`] と `crate::uds::serve_uds` が使う。
pub(crate) fn with_stderr_log<T>(f: impl FnOnce(&mut dyn FnMut(&str)) -> T) -> T {
    let (tx, rx) = mpsc::sync_channel::<String>(LOG_QUEUE_DEPTH);
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
    let result = f(&mut |line| {
        if logger_alive {
            // 満杯・切断時は捨てる（try_send は待たない）。
            let _ = tx.try_send(line.to_owned());
        }
    });
    drop(tx);
    if logger_alive {
        let _ = done_rx.recv_timeout(DIAG_TIMEOUT);
    }
    result
}

/// 上限・期限・ログ sink を指定して EOF まで処理する。
///
/// 読み書きは専用スレッドで行い、本関数は期限付きで結果を待つ（REPAIR-5）。
pub fn serve_with<R, W>(
    mut reader: R,
    mut writer: W,
    limits: Limits,
    backend: &dyn ToolBackend,
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
    // 受信中メッセージの先頭バイト受信時刻。読み取りスレッドが書き、メインが期限計算に読む。
    // 受信完了の観測を Started の配送待ち（キュー満杯時のブロック）に依存させない（REPAIR-5）。
    let slot: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let reader_slot = Arc::clone(&slot);
    let reader_spawn = thread::Builder::new()
        .name("mcp-read".into())
        .spawn(move || {
            loop {
                let started_tx = ev_tx.clone();
                let start_slot = Arc::clone(&reader_slot);
                let mut on_start = move || {
                    if let Ok(mut g) = start_slot.lock() {
                        *g = Some(Instant::now());
                    }
                    // 満杯なら捨てる。読み取りを止めない。
                    let _ = started_tx.try_send(Event::Started);
                };
                let res = read_line(&mut reader, max_line, &mut on_start);
                let done = Instant::now();
                let start = reader_slot
                    .lock()
                    .ok()
                    .and_then(|mut g| g.take())
                    .unwrap_or(done);
                match res {
                    Ok(None) => {
                        let _ = ev_tx.send(Event::Eof);
                        break;
                    }
                    Ok(Some(line)) => {
                        if ev_tx.send(Event::Line(line, start, done)).is_err() {
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

    // 接続ごとの状態（1 ビット）。modern の要求は読まず書かない（MCP-3）。
    let mut conn = ConnectionState::default();
    loop {
        // アイドル待ちは無期限。メッセージの先頭バイトが来てからは、その受信時刻からの
        // 絶対期限で待つ。直前の応答書き込み中に始まった受信でも数え直さない（REPAIR-5）。
        let overdue_at = slot
            .lock()
            .ok()
            .and_then(|g| *g)
            .map(|t0| t0 + limits.message_timeout);
        let ev = match overdue_at {
            None => match ev_rx.recv() {
                Ok(ev) => ev,
                Err(_) => return Ok(()),
            },
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match ev_rx.recv_timeout(remaining) {
                    Ok(ev) => ev,
                    Err(RecvTimeoutError::Disconnected) => return Ok(()),
                    Err(RecvTimeoutError::Timeout) => match ev_rx.try_recv() {
                        Ok(ev) => ev,
                        Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
                        Err(mpsc::TryRecvError::Empty) => {
                            // 同じ受信が未完のまま期限を過ぎていれば超過。完了済みなら再評価する。
                            let still = slot.lock().ok().and_then(|g| *g);
                            if still.is_some_and(|t| t + limits.message_timeout <= Instant::now()) {
                                log_transport(log, "DEADLINE_EXCEEDED");
                                return Err(ServeError::ReadTimeout);
                            }
                            continue;
                        }
                    },
                }
            }
        };
        let line = match ev {
            Event::Started => continue,
            Event::Eof => return Ok(()),
            Event::Failed(e) => {
                log_transport(log, "UNAVAILABLE");
                return Err(ServeError::Read(e));
            }
            Event::Line(l, start, done) => {
                // 期限内に読み切った行は、キューで待たされていても受理する。
                if done > start + limits.message_timeout {
                    log_transport(log, "DEADLINE_EXCEEDED");
                    return Err(ServeError::ReadTimeout);
                }
                l
            }
        };
        let began = Instant::now();
        let Some(outcome) = process_line(line, backend, &mut conn) else {
            continue;
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
    use crate::backend::{ContainerList, ContainerSummary, StartedSummary};
    use fandhe_container_core::traits::ErrorCode;
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
        let r = serve_with(
            Cursor::new(input),
            out.clone(),
            limits,
            &UnavailableBackend,
            &mut |l| {
                logs.push(l.to_owned());
            },
        );
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
                json!({"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params","data":{"code":"INVALID_ARGUMENT"}}}),
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
                    json!({"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"Invalid params","data":{"code":"INVALID_ARGUMENT"}}}),
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
                error_code: None,
                tool: None,
                tool_error: None,
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
            json!({"jsonrpc":"2.0","id":3,"error":{"code":-32601,"message":"Method not found","data":{"code":"UNIMPLEMENTED"}}})
        );
    }

    /// 固定の結果を返すフェイクバックエンド。
    struct Fake {
        list: Result<ContainerList, TraitError>,
        start: Result<StartedSummary, TraitError>,
    }

    impl ToolBackend for Fake {
        fn list_containers(&self) -> Result<ContainerList, TraitError> {
            self.list.clone()
        }
        fn start_container(&self, _id: &ContainerId) -> Result<StartedSummary, TraitError> {
            self.start.clone()
        }
    }

    fn summary(id: &str, status: &str, pid: Option<u32>) -> ContainerSummary {
        ContainerSummary {
            id: id.to_owned(),
            status: status.to_owned(),
            pid,
        }
    }

    fn fake_ok() -> Fake {
        Fake {
            list: Ok(ContainerList {
                containers: vec![
                    summary("c1", "running", Some(42)),
                    summary("c2", "created", None),
                ],
                truncated: false,
            }),
            start: Ok(summary("c1", "running", Some(42))),
        }
    }

    fn fake_err(code: ErrorCode, msg: &str) -> Fake {
        Fake {
            list: Err(TraitError::new(code, msg)),
            start: Err(TraitError::new(code, msg)),
        }
    }

    fn call_with(line: &str, backend: &dyn ToolBackend) -> Value {
        handle_message_with(line.as_bytes(), backend).reply.unwrap()
    }

    fn tools_call_req(params: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{params}}}"#)
    }

    #[test]
    fn mcp2_tools_call_list_containers_returns_records() {
        let v = call_with(&tools_call_req(r#"{"name":"list_containers"}"#), &fake_ok());
        let expected = json!({"containers":[
            {"id":"c1","status":"running","pid":42},
            {"id":"c2","status":"created","pid":null}
        ],"truncated":false});
        assert_eq!(v["result"]["isError"], false);
        assert_eq!(v["result"]["structuredContent"], expected);
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(serde_json::from_str::<Value>(text).unwrap(), expected);
        assert_eq!(v["result"]["content"][0]["type"], "text");
    }

    #[test]
    fn mcp2_tools_call_start_container_returns_started() {
        let v = call_with(
            &tools_call_req(r#"{"name":"start_container","arguments":{"container_id":"c1"}}"#),
            &fake_ok(),
        );
        assert_eq!(v["result"]["isError"], false);
        assert_eq!(
            v["result"]["structuredContent"],
            json!({"id":"c1","status":"running","pid":42})
        );
    }

    #[test]
    fn mcp2_tools_call_unknown_tool_is_32602_without_echo() {
        let v = call_with(&tools_call_req(r#"{"name":"zzSECRETzz"}"#), &fake_ok());
        assert_eq!(v["error"]["code"], -32602);
        assert_eq!(v["error"]["data"]["code"], "INVALID_ARGUMENT");
        assert!(!v.to_string().contains("zzSECRETzz"));
    }

    #[test]
    fn mcp2_tools_call_rejects_bad_params_with_32602() {
        let long_id = "a".repeat(256);
        let cases = [
            "[]".to_owned(),
            "{}".to_owned(),
            r#"{"name":1}"#.to_owned(),
            r#"{"name":"list_containers","arguments":[]}"#.to_owned(),
            r#"{"name":"start_container"}"#.to_owned(),
            r#"{"name":"start_container","arguments":{}}"#.to_owned(),
            r#"{"name":"start_container","arguments":{"container_id":1}}"#.to_owned(),
            r#"{"name":"start_container","arguments":{"container_id":"a/b"}}"#.to_owned(),
            r#"{"name":"start_container","arguments":{"container_id":".."}}"#.to_owned(),
            r#"{"name":"start_container","arguments":{"container_id":""}}"#.to_owned(),
            format!(r#"{{"name":"start_container","arguments":{{"container_id":"{long_id}"}}}}"#),
        ];
        for params in cases {
            let v = call_with(&tools_call_req(&params), &fake_ok());
            assert_eq!(v["error"]["code"], -32602, "params: {params}");
            assert_eq!(v["error"]["data"]["code"], "INVALID_ARGUMENT");
        }
        // params 省略。
        let v = call_with(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call"}"#,
            &fake_ok(),
        );
        assert_eq!(v["error"]["code"], -32602);
    }

    #[test]
    fn mcp4_backend_business_error_sets_is_error_with_fixed_message() {
        let cases = [
            (ErrorCode::NotFound, "NOT_FOUND", "Container not found"),
            (
                ErrorCode::FailedPrecondition,
                "FAILED_PRECONDITION",
                "Operation not allowed in the current state",
            ),
            (ErrorCode::Unimplemented, "UNIMPLEMENTED", "Not implemented"),
            (ErrorCode::Timeout, "TIMEOUT", "Operation timed out"),
        ];
        for (code, name, message) in cases {
            let backend = fake_err(code, "/secret/path/zzSECRETzz");
            for params in [
                r#"{"name":"list_containers"}"#,
                r#"{"name":"start_container","arguments":{"container_id":"c1"}}"#,
            ] {
                let v = call_with(&tools_call_req(params), &backend);
                assert_eq!(v["result"]["isError"], true);
                let text = v["result"]["content"][0]["text"].as_str().unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(text).unwrap(),
                    json!({"code": name, "message": message})
                );
                assert!(!v.to_string().contains("zzSECRETzz"));
                assert!(v.get("error").is_none());
            }
        }
    }

    #[test]
    fn mcp2_unavailable_backend_reports_unimplemented_via_handle_message() {
        let o = handle_message(tools_call_req(r#"{"name":"list_containers"}"#).as_bytes());
        let v = o.reply.unwrap();
        assert_eq!(v["result"]["isError"], true);
        assert_eq!(o.tool_error, Some("UNIMPLEMENTED"));
        assert_eq!(o.tool, Some("list_containers"));
    }

    #[test]
    fn serve_logs_tool_name_without_input_values() {
        let input = format!(
            "{}\n{}\n{}\n",
            init_req("0", "2025-06-18"),
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"start_container","arguments":{"container_id":"zzSECRETzz"}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_containers"}}"#,
        );
        let out = SharedBuf::default();
        let mut logs = Vec::new();
        serve_with(
            Cursor::new(input),
            out.clone(),
            Limits::default(),
            &fake_ok(),
            &mut |l| logs.push(l.to_owned()),
        )
        .unwrap();
        let recs: Vec<Value> = logs
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(recs[0]["op"], "initialize");
        assert_eq!(recs[1]["tool"], "start_container");
        assert_eq!(recs[1]["result"], "ok");
        assert_eq!(recs[2]["tool"], "list_containers");
        assert!(logs.iter().all(|l| !l.contains("zzSECRETzz")));
        // 業務エラーはログ上で区別する。
        let o = handle_message_with(
            tools_call_req(r#"{"name":"list_containers"}"#).as_bytes(),
            &fake_err(ErrorCode::NotFound, "x"),
        );
        let mut logs = Vec::new();
        log_request(&mut |l| logs.push(l.to_owned()), &o, Instant::now());
        let rec: Value = serde_json::from_str(&logs[0]).unwrap();
        assert_eq!(rec["result"], "tool_error");
        assert_eq!(rec["code"], "NOT_FOUND");
    }

    #[test]
    fn ping_returns_empty_result() {
        let v = call(r#"{"jsonrpc":"2.0","id":5,"method":"ping"}"#).unwrap();
        assert_eq!(v, json!({"jsonrpc":"2.0","id":5,"result":{}}));
    }

    const ERR5_INVALID_PARAMS: &str = r#"{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"Invalid params","data":{"code":"INVALID_ARGUMENT"}}}"#;

    /// MCP-4・ERR-5: 未定義ツール名の `tools/call` は -32602 + `data.code = INVALID_ARGUMENT`（完全一致）。
    #[test]
    fn mcp4_err5_tools_call_unknown_tool_returns_error_object() {
        let o = handle_message_with(
            tools_call_req(r#"{"name":"zzSECRETzz"}"#).as_bytes(),
            &fake_ok(),
        );
        let expected: Value = serde_json::from_str(ERR5_INVALID_PARAMS).unwrap();
        assert_eq!(o.reply.as_ref().unwrap(), &expected);
        assert_eq!(o.error_code, Some(-32602));
        assert_eq!(o.tool, None);
        assert_eq!(o.tool_error, None);
        assert!(!o.reply.unwrap().to_string().contains("zzSECRETzz"));
    }

    /// MCP-4・ERR-5: 引数不正の `tools/call` は未知ツールと同じ ERR-5 のエラーオブジェクトを返す。
    #[test]
    fn mcp4_err5_tools_call_invalid_arguments_return_error_object() {
        let expected: Value = serde_json::from_str(ERR5_INVALID_PARAMS).unwrap();
        let long_id = "a".repeat(256);
        let cases = [
            "[]".to_owned(),
            "{}".to_owned(),
            r#"{"name":1}"#.to_owned(),
            r#"{"name":"list_containers","arguments":[]}"#.to_owned(),
            r#"{"name":"start_container"}"#.to_owned(),
            r#"{"name":"start_container","arguments":{}}"#.to_owned(),
            r#"{"name":"start_container","arguments":{"container_id":1}}"#.to_owned(),
            r#"{"name":"start_container","arguments":{"container_id":"a/b"}}"#.to_owned(),
            format!(r#"{{"name":"start_container","arguments":{{"container_id":"{long_id}"}}}}"#),
        ];
        for params in cases {
            let o = handle_message_with(tools_call_req(&params).as_bytes(), &fake_ok());
            assert_eq!(o.reply.as_ref().unwrap(), &expected, "params: {params}");
            assert_eq!(o.error_code, Some(-32602), "params: {params}");
        }
        let o = handle_message_with(
            br#"{"jsonrpc":"2.0","id":4,"method":"tools/call"}"#,
            &fake_ok(),
        );
        assert_eq!(o.reply.as_ref().unwrap(), &expected);
    }

    /// MCP-4・ERR-5: 全てのプロトコルエラーが `ProtocolError` の対応表どおりの `error` を返す。
    #[test]
    fn mcp4_err5_protocol_errors_carry_data_code() {
        let big = vec![b'x'; MAX_LINE_BYTES + 1];
        let cases: Vec<(Outcome, ProtocolError)> = vec![
            (handle_message(&big), ProtocolError::InvalidRequest),
            (
                process_line(
                    Line::Overflow,
                    &UnavailableBackend,
                    &mut ConnectionState::default(),
                )
                .unwrap(),
                ProtocolError::InvalidRequest,
            ),
            (handle_message(b"{not json"), ProtocolError::Parse),
            (handle_message(b"[]"), ProtocolError::InvalidRequest),
            (
                handle_message(br#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#),
                ProtocolError::InvalidRequest,
            ),
            (
                handle_message(br#"{"jsonrpc":"2.0","id":1,"method":"foo"}"#),
                ProtocolError::MethodNotFound,
            ),
        ];
        for (o, e) in cases {
            let reply = o.reply.unwrap();
            assert_eq!(reply["error"], e.to_error_object());
            assert_eq!(o.error_code, Some(e.rpc_code().code()));
        }
    }

    /// MCP-4・ERR-5: 業務エラーは `ToolError` と同一の result（`isError: true`）で、error キーを持たない。
    #[test]
    fn mcp4_err5_business_error_matches_tool_error_result() {
        for (code, name) in [
            (ErrorCode::AlreadyExists, "ALREADY_EXISTS"),
            (ErrorCode::PermissionDenied, "PERMISSION_DENIED"),
            (ErrorCode::Unavailable, "UNAVAILABLE"),
            (ErrorCode::Internal, "INTERNAL"),
            (ErrorCode::InvalidArgument, "INVALID_ARGUMENT"),
        ] {
            let o = handle_message_with(
                tools_call_req(r#"{"name":"list_containers"}"#).as_bytes(),
                &fake_err(code, "/secret/path"),
            );
            let reply = o.reply.as_ref().unwrap();
            let te = ToolError::from_trait_error(&TraitError::new(code, "/secret/path"));
            assert_eq!(reply["result"], te.to_call_result());
            assert!(reply.get("error").is_none());
            assert_eq!(o.tool_error, Some(name));
            assert!(!reply.to_string().contains("/secret/path"));
        }
    }

    #[test]
    fn invalid_json_returns_32700_with_null_id() {
        let v = call("{not json").unwrap();
        assert_eq!(
            v,
            json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error","data":{"code":"INVALID_ARGUMENT"}}})
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
            "{}\n{}\n{}\n",
            init_req("0", "2025-06-18"),
            "x".repeat(400),
            r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#
        );
        let limits = Limits {
            max_line_bytes: 300,
            ..Limits::default()
        };
        let (r, text, _) = run(input, limits);
        r.unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("2025-06-18"));
        assert!(lines[1].contains("-32600"));
        assert!(lines[2].contains(r#""result":{}"#));
    }

    #[test]
    fn serve_logs_structured_record_per_request_without_input_content() {
        let input = format!(
            "{}\n{}\n{}\n{}\n",
            init_req("0", "2025-06-18"),
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"zzSECRETzz"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        );
        let (r, _, logs) = run(input, Limits::default());
        r.unwrap();
        assert_eq!(logs.len(), 4);
        let recs: Vec<Value> = logs
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(recs[0]["op"], "initialize");
        assert_eq!(recs[1]["event"], "mcp.request");
        assert_eq!(recs[1]["op"], "ping");
        assert_eq!(recs[1]["result"], "ok");
        assert_eq!(recs[1]["code"], Value::Null);
        assert!(recs[1]["latency_us"].is_u64());
        assert_eq!(recs[2]["op"], "other");
        assert_eq!(recs[2]["result"], "error");
        assert_eq!(recs[2]["code"], -32601);
        assert_eq!(recs[3]["op"], "notification");
        assert_eq!(recs[3]["result"], "no_reply");
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
            &UnavailableBackend,
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
        let r = serve_with(
            Cursor::new(input),
            StallWriter,
            limits,
            &UnavailableBackend,
            &mut |_| {},
        );
        assert!(matches!(r, Err(ServeError::WriteTimeout)));
    }

    /// 1 通目の完結行 → 2 通目の先頭断片 → 遅延 → 残りと改行、の順に返す reader。
    struct SplitReader {
        stage: usize,
        chunks: Vec<(Duration, Vec<u8>)>,
    }
    impl io::Read for SplitReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }
    impl BufRead for SplitReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            match self.chunks.get(self.stage) {
                Some((delay, data)) => {
                    if self.stage > 0 && !delay.is_zero() && !data.is_empty() {
                        thread::sleep(*delay);
                    }
                    Ok(data.as_slice())
                }
                None => Ok(&[]),
            }
        }
        fn consume(&mut self, n: usize) {
            if n > 0 {
                self.stage += 1;
            }
        }
    }

    /// 応答書き込みに 300ms かかる writer。
    struct SlowWriter;
    impl Write for SlowWriter {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            thread::sleep(Duration::from_millis(300));
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// 先読みされた次リクエストの期限は、メインスレッドがキューから取り出した時刻ではなく
    /// 先頭バイトの受信時刻から数える（REPAIR-5。前応答の書き込み中に受信が始まる 9s + 9s の縮小版）。
    #[test]
    fn serve_counts_message_deadline_from_first_byte_not_dequeue() {
        let limits = Limits {
            message_timeout: Duration::from_millis(500),
            ..Limits::default()
        };
        let ping = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n".to_vec();
        let reader = SplitReader {
            stage: 0,
            chunks: vec![
                (Duration::ZERO, ping),
                (Duration::ZERO, b"{\"jsonrpc\":\"2.0\",".to_vec()),
                (
                    Duration::from_millis(600),
                    b"\"id\":2,\"method\":\"ping\"}\n".to_vec(),
                ),
            ],
        };
        let mut logs = Vec::new();
        let r = serve_with(reader, SlowWriter, limits, &UnavailableBackend, &mut |l| {
            logs.push(l.to_owned())
        });
        assert!(matches!(r, Err(ServeError::ReadTimeout)), "{r:?}");
        assert!(logs.iter().any(|l| l.contains("DEADLINE_EXCEEDED")));
    }

    /// 応答書き込みが遅くキューが満杯でも、受信済みの正常な要求は ReadTimeout にならない
    /// （REPAIR-5。受信期限と送信期限は独立。Started の配送待ちで受信完了の観測を止めない）。
    #[test]
    fn serve_does_not_time_out_buffered_requests_while_queue_is_full() {
        let limits = Limits {
            message_timeout: Duration::from_millis(100),
            write_timeout: Duration::from_secs(1),
            ..Limits::default()
        };
        let mut input = String::new();
        for i in 1..=10 {
            input.push_str(&format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"ping\"}}\n"
            ));
        }
        let r = serve_with(
            Cursor::new(input.into_bytes()),
            SlowWriter,
            limits,
            &UnavailableBackend,
            &mut |_| {},
        );
        assert!(r.is_ok(), "{r:?}");
    }

    // ---- MCP-3（TASK-119.2）: dual-era のステートレスコア ----

    fn invalid_params_error(id: i64) -> Value {
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"Invalid params","data":{"code":"INVALID_ARGUMENT"}}})
    }

    /// modern の要求を組む。`params_rest` は `_meta` 以外の params のフィールド（`,` 始まり）。
    fn modern_req(id: i64, method: &str, version: &str, params_rest: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{"_meta":{{"io.modelcontextprotocol/protocolVersion":"{version}","io.modelcontextprotocol/clientCapabilities":{{}}}}{params_rest}}}}}"#
        )
    }

    fn on(line: &str, conn: &mut ConnectionState) -> Value {
        handle_message_on(line.as_bytes(), &fake_ok(), conn)
            .reply
            .unwrap()
    }

    fn server_info() -> Value {
        json!({"name":"fandhe-container-plugin-mcp","version":env!("CARGO_PKG_VERSION")})
    }

    fn tool_defs_json() -> Value {
        json!([
            {"name":"list_containers","description":"List containers managed by fandhe-container.",
             "inputSchema":{"type":"object","properties":{}}},
            {"name":"start_container","description":"Start the container identified by container_id.",
             "inputSchema":{"type":"object","properties":{"container_id":{"type":"string"}},"required":["container_id"]}}
        ])
    }

    #[test]
    fn mcp3_uninitialized_connection_rejects_requests_without_meta() {
        let reqs = [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_containers"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"foo/bar"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"server/discover"}"#,
        ];
        for r in reqs {
            let mut conn = ConnectionState::default();
            assert_eq!(on(r, &mut conn), invalid_params_error(1), "case: {r}");
            assert!(!conn.is_legacy());
        }
    }

    #[test]
    fn mcp3_initialized_connection_keeps_legacy_behavior() {
        let mut conn = ConnectionState::default();
        let init = on(&init_req("1", "2025-06-18"), &mut conn);
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert!(conn.is_legacy());
        let list = on(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            &mut conn,
        );
        assert_eq!(
            list,
            json!({"jsonrpc":"2.0","id":2,"result":{"tools":tool_defs_json()}})
        );
        assert_eq!(
            on(r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#, &mut conn),
            json!({"jsonrpc":"2.0","id":3,"result":{}})
        );
        let disc = on(
            r#"{"jsonrpc":"2.0","id":4,"method":"server/discover"}"#,
            &mut conn,
        );
        assert_eq!(disc["error"]["code"], -32601);
        assert_eq!(disc["error"]["data"]["code"], "UNIMPLEMENTED");
    }

    /// legacy（2025-06-18）の result には `resultType` を付けない（MCP-3・D3）。
    #[test]
    fn mcp3_legacy_results_have_no_result_type() {
        let mut conn = ConnectionState::default();
        let init = on(&init_req("1", "2025-06-18"), &mut conn);
        let list = on(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            &mut conn,
        );
        let ping = on(r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#, &mut conn);
        let call = on(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_containers"}}"#,
            &mut conn,
        );
        let err_backend = fake_err(ErrorCode::NotFound, "x");
        let call_err = handle_message_on(
            br#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list_containers"}}"#,
            &err_backend,
            &mut conn,
        )
        .reply
        .unwrap();
        assert_eq!(call_err["result"]["isError"], true);
        for v in [&init, &list, &ping, &call, &call_err] {
            let result = v["result"].as_object().expect("result object");
            assert!(!result.contains_key("resultType"), "{v}");
        }
    }

    /// 経路は要求ごとに決まり、同じ接続でも modern にだけ `resultType` が付く（MCP-3・D3）。
    #[test]
    fn mcp3_result_type_follows_route_per_request() {
        let mut conn = ConnectionState::default();
        on(&init_req("1", "2025-06-18"), &mut conn);
        let modern = on(&modern_req(2, "tools/list", "2026-07-28", ""), &mut conn);
        assert_eq!(modern["result"]["resultType"], "complete");
        let legacy = on(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
            &mut conn,
        );
        assert!(
            !legacy["result"]
                .as_object()
                .unwrap()
                .contains_key("resultType")
        );
    }

    #[test]
    fn mcp3_failed_initialize_does_not_make_connection_legacy() {
        let mut conn = ConnectionState::default();
        let bad = on(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            &mut conn,
        );
        assert_eq!(bad, invalid_params_error(1));
        assert!(!conn.is_legacy());
        let list = on(
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            &mut conn,
        );
        assert_eq!(list, invalid_params_error(2));
    }

    #[test]
    fn mcp3_progress_token_only_meta_is_legacy_after_initialize_only() {
        let req =
            r#"{"jsonrpc":"2.0","id":5,"method":"ping","params":{"_meta":{"progressToken":"p"}}}"#;
        let mut fresh = ConnectionState::default();
        assert_eq!(on(req, &mut fresh), invalid_params_error(5));
        let mut conn = ConnectionState { legacy: true };
        assert_eq!(
            on(req, &mut conn),
            json!({"jsonrpc":"2.0","id":5,"result":{}})
        );
    }

    #[test]
    fn mcp3_modern_request_is_independent_of_connection_state() {
        let req = modern_req(1, "tools/list", "2026-07-28", "");
        let mut fresh = ConnectionState::default();
        let mut legacy = ConnectionState { legacy: true };
        let a = on(&req, &mut fresh);
        let b = on(&req, &mut legacy);
        assert_eq!(a, b);
        assert_eq!(fresh, ConnectionState::default());
        assert_eq!(legacy, ConnectionState { legacy: true });
    }

    #[test]
    fn mcp3_server_discover_result() {
        let mut conn = ConnectionState::default();
        let v = on(
            &modern_req(1, "server/discover", "2026-07-28", ""),
            &mut conn,
        );
        assert_eq!(
            v,
            json!({"jsonrpc":"2.0","id":1,"result":{
                "supportedVersions":["2026-07-28"],
                "capabilities":{"tools":{"listChanged":false}},
                "ttlMs":3600000,
                "cacheScope":"public",
                "resultType":"complete",
                "_meta":{"io.modelcontextprotocol/serverInfo":server_info()}
            }})
        );
    }

    #[test]
    fn mcp3_modern_tools_list_result() {
        let mut conn = ConnectionState::default();
        let v = on(&modern_req(2, "tools/list", "2026-07-28", ""), &mut conn);
        assert_eq!(
            v,
            json!({"jsonrpc":"2.0","id":2,"result":{
                "tools":tool_defs_json(),
                "ttlMs":3600000,
                "cacheScope":"public",
                "resultType":"complete",
                "_meta":{"io.modelcontextprotocol/serverInfo":server_info()}
            }})
        );
    }

    #[test]
    fn mcp3_modern_tools_call_results() {
        let mut conn = ConnectionState::default();
        let v = on(
            &modern_req(
                3,
                "tools/call",
                "2026-07-28",
                r#","name":"list_containers""#,
            ),
            &mut conn,
        );
        let expected = json!({"containers":[
            {"id":"c1","status":"running","pid":42},
            {"id":"c2","status":"created","pid":null}
        ],"truncated":false});
        assert_eq!(v["result"]["isError"], false);
        assert_eq!(v["result"]["resultType"], "complete");
        assert_eq!(v["result"]["structuredContent"], expected);
        assert_eq!(
            v["result"]["_meta"],
            json!({"io.modelcontextprotocol/serverInfo":server_info()})
        );
        let v = on(
            &modern_req(
                4,
                "tools/call",
                "2026-07-28",
                r#","name":"start_container","arguments":{"container_id":"c1"}"#,
            ),
            &mut conn,
        );
        assert_eq!(v["result"]["resultType"], "complete");
        assert_eq!(
            v["result"]["structuredContent"],
            json!({"id":"c1","status":"running","pid":42})
        );
        assert_eq!(
            v["result"]["_meta"],
            json!({"io.modelcontextprotocol/serverInfo":server_info()})
        );
        // 業務エラーにも serverInfo が付く。
        let err_backend = fake_err(ErrorCode::NotFound, "x");
        let o = handle_message_on(
            modern_req(
                5,
                "tools/call",
                "2026-07-28",
                r#","name":"list_containers""#,
            )
            .as_bytes(),
            &err_backend,
            &mut conn,
        );
        let v = o.reply.unwrap();
        assert_eq!(v["result"]["isError"], true);
        assert_eq!(v["result"]["resultType"], "complete");
        assert_eq!(
            v["result"]["_meta"],
            json!({"io.modelcontextprotocol/serverInfo":server_info()})
        );
        // 未知のツールは -32602（エラー応答に _meta は足さない）。
        let v = on(
            &modern_req(6, "tools/call", "2026-07-28", r#","name":"nope""#),
            &mut conn,
        );
        assert_eq!(v, invalid_params_error(6));
    }

    #[test]
    fn mcp3_modern_ping_initialize_and_unknown_methods_are_32601() {
        let mut conn = ConnectionState::default();
        for m in ["ping", "initialize", "foo/bar"] {
            let v = on(&modern_req(1, m, "2026-07-28", ""), &mut conn);
            assert_eq!(
                v,
                json!({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found","data":{"code":"UNIMPLEMENTED"}}}),
                "method: {m}"
            );
        }
        assert!(!conn.is_legacy());
    }

    #[test]
    fn mcp3_unsupported_version_is_32022() {
        for ver in ["1900-01-01", "2025-06-18", ""] {
            for method in ["tools/list", "foo/bar"] {
                let mut conn = ConnectionState::default();
                let v = on(&modern_req(1, method, ver, ""), &mut conn);
                assert_eq!(
                    v,
                    json!({"jsonrpc":"2.0","id":1,"error":{
                        "code":-32022,"message":"Unsupported protocol version",
                        "data":{"supported":["2026-07-28"],"requested":ver,"code":"UNIMPLEMENTED"}}}),
                    "ver: {ver:?} method: {method}"
                );
            }
        }
    }

    #[test]
    fn mcp3_missing_required_meta_fields_are_32602() {
        let mut conn = ConnectionState::default();
        let cases = [
            // clientCapabilities 欠落
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#,
            // clientCapabilities がオブジェクト以外
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[]}}}"#,
            // 版が文字列以外
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":20260728,"io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        ];
        for c in cases {
            assert_eq!(on(c, &mut conn), invalid_params_error(1), "case: {c}");
        }
    }

    #[test]
    fn mcp3_version_check_precedes_required_fields() {
        let mut conn = ConnectionState::default();
        let v = on(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01"}}}"#,
            &mut conn,
        );
        assert_eq!(v["error"]["code"], -32022);
    }

    #[test]
    fn mcp3_requested_version_is_truncated_to_64_bytes() {
        let long = "v".repeat(500);
        let mut conn = ConnectionState::default();
        let v = on(&modern_req(1, "tools/list", &long, ""), &mut conn);
        assert_eq!(v["error"]["data"]["requested"], "v".repeat(64).as_str());
    }

    #[test]
    fn mcp3_notification_with_unsupported_version_gets_no_reply() {
        let mut conn = ConnectionState::default();
        let line = r#"{"jsonrpc":"2.0","method":"notifications/x","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01"}}}"#;
        let o = handle_message_on(line.as_bytes(), &fake_ok(), &mut conn);
        assert_eq!(o.reply, None);
    }

    #[test]
    fn mcp3_serve_tracks_connection_state_and_logs_without_version_text() {
        let input = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            init_req("2", "2025-06-18"),
            r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#,
            modern_req(4, "server/discover", "2026-07-28", ""),
            modern_req(5, "tools/list", "zzSECRETzz", ""),
        );
        let (r, text, logs) = run(input, Limits::default());
        r.unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0]["error"]["code"], -32602);
        assert_eq!(lines[1]["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(lines[2], json!({"jsonrpc":"2.0","id":3,"result":{}}));
        assert_eq!(lines[3]["result"]["cacheScope"], "public");
        assert_eq!(lines[4]["error"]["code"], -32022);
        assert_eq!(lines[4]["error"]["data"]["requested"], "zzSECRETzz");
        let recs: Vec<Value> = logs
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(recs[3]["op"], "server/discover");
        assert_eq!(recs[4]["code"], -32022);
        assert!(logs.iter().all(|l| !l.contains("zzSECRETzz")));
    }
}
