//! MCP 2026-07-28 への追随後も MCP-1・MCP-2 の疎通が維持されることを固定する結合試験
//! （TASK-119.5・#719。MCP-3・MCP-1・MCP-2・REPAIR-4・REPAIR-5・REPAIR-12）。
//!
//! 役割分担: `tests/startup.rs` は起動・引数・個別の経路の断面、`tests/integration.rs` は UDS の疎通、
//! `src/server.rs` の単体試験は経路判定と ERR-5 を担う。本ファイルは次を足す。
//! - 実バイナリ（stdio）での `initialize` → `tools/list` → `tools/call` の一連（legacy・modern の両経路。
//!   `list_containers` は状態ルートを本ファイルの一時領域へ向けて実際に呼ぶ）
//! - 同一接続での dual-era の混在と `tools/list` の順序の不変
//! - stdout に応答以外（サーバー発の要求・通知）を書かないこと、stderr が入力値を反射しないこと
//! - ツール名の指針と `inputSchema` の固定（`docs/design/mcp-2026-07-28-migration.md` 3 章）
//! - 公開 API とフェイクのバックエンドでの 2 ツールの正常応答の形
//!
//! 待ちはすべて期限つきで、超過時は kill して失敗にする（REPAIR-5）。製品コードは変更しない。

use std::io::{Read, Write};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use fandhe_container_core::traits::{ContainerId, TraitError};
use fandhe_container_plugin_mcp::backend::{
    ContainerList, ContainerSummary, StartedSummary, ToolBackend,
};
use fandhe_container_plugin_mcp::server::{ConnectionState, handle_message_on};
use serde_json::{Value, json};

#[path = "../../core/tests/support/scratch_root.rs"]
mod scratch_root;

/// 子プロセスの終了を待つ上限（REPAIR-5）。
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);
/// kill 後の回収と出力収集を待つ上限（REPAIR-5）。
const REAP_TIMEOUT: Duration = Duration::from_secs(10);
/// 2026-07-28 の経路の `_meta`（版とクライアント機能）。
const META: &str = r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}"#;
const INIT: &str = r#"{"jsonrpc":"2.0","id":ID,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#;
const INITIALIZED: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

fn spawn_reader<R: Read + Send + 'static>(mut pipe: R) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    rx
}

/// 実バイナリを環境変数なし（`XDG_RUNTIME_DIR` だけ指定）で起動し、期限内に終了と出力収集を完了させる。
fn run(runtime_dir: &std::path::Path, lines: &[String]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fandhe-container-plugin-mcp"));
    cmd.env_clear().env("XDG_RUNTIME_DIR", runtime_dir);
    // Windows ではプロセス起動に SystemRoot が要る。
    if let Some(root) = std::env::var_os("SystemRoot") {
        cmd.env("SystemRoot", root);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn fandhe-container-plugin-mcp");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let input = format!("{}\n", lines.join("\n")).into_bytes();
    thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let out_rx = spawn_reader(child.stdout.take().expect("stdout is piped"));
    let err_rx = spawn_reader(child.stderr.take().expect("stderr is piped"));

    let deadline = Instant::now() + CHILD_TIMEOUT;
    let status = loop {
        match child.try_wait().expect("failed to poll child") {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let reap_deadline = Instant::now() + REAP_TIMEOUT;
                while Instant::now() < reap_deadline {
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                panic!("fandhe-container-plugin-mcp did not exit within {CHILD_TIMEOUT:?}");
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    };
    let collect_deadline = Instant::now() + REAP_TIMEOUT;
    let remaining = || collect_deadline.saturating_duration_since(Instant::now());
    let stdout = out_rx
        .recv_timeout(remaining())
        .expect("stdout was not collected within the deadline");
    let stderr = err_rx
        .recv_timeout(remaining())
        .expect("stderr was not collected within the deadline");
    Output {
        status,
        stdout,
        stderr,
    }
}

/// 一時領域と、その子の `run`（0700）。`run` を `XDG_RUNTIME_DIR` に使い、実環境の状態ルートへ触れない。
struct Runtime {
    scratch: scratch_root::ScratchDir,
}

impl Runtime {
    fn new() -> Self {
        // root だと状態ルートが `/run/fandhe-container` に解決され実環境へ触れるため、skip せず失敗させる。
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt as _;
            let uid = std::fs::metadata("/proc/self")
                .map(|m| m.uid())
                .expect("stat /proc/self");
            assert_ne!(uid, 0, "this test must run as a non-root user");
        }
        let scratch = scratch_root::ScratchDir::new("fc-mcp-proto", Duration::from_secs(10));
        let run = scratch.path().join("run");
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&run)
                .expect("create runtime dir");
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&run).expect("create runtime dir");
        Self { scratch }
    }

    fn dir(&self) -> std::path::PathBuf {
        self.scratch.path().join("run")
    }
}

fn modern(id: u64, method: &str, extra: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{{{META}{extra}}}}}"#)
}

fn legacy(id: u64, method: &str, params: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}"{params}}}"#)
}

fn init(id: u64) -> String {
    INIT.replace("ID", &id.to_string())
}

fn call_params(name: &str, args: &str) -> String {
    format!(r#","name":"{name}","arguments":{args}"#)
}

/// stdout の全行が JSON-RPC 2.0 の応答（`result` か `error` の一方）で、`id` が要求順に一致することを照合する。
/// サーバー発の要求・通知（`method` を持つ行）が無いこと（MUST NOT）を固定する。
fn responses(out: &Output, expected_ids: &[u64]) -> Vec<Value> {
    let text = String::from_utf8(out.stdout.clone()).expect("stdout is UTF-8");
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("stdout line is JSON"))
        .collect();
    assert_eq!(lines.len(), expected_ids.len(), "stdout: {text}");
    for (line, id) in lines.iter().zip(expected_ids) {
        let obj = line.as_object().expect("response is an object");
        assert_eq!(obj.get("jsonrpc"), Some(&json!("2.0")), "{line}");
        assert_eq!(obj.get("id"), Some(&json!(id)), "{line}");
        assert!(obj.get("method").is_none(), "server sent a request: {line}");
        assert!(
            obj.contains_key("result") ^ obj.contains_key("error"),
            "exactly one of result/error: {line}"
        );
    }
    lines
}

/// stderr の `mcp.request` の `op` 列。
fn ops(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).expect("stderr line is JSON"))
        .filter(|v| v["event"] == "mcp.request")
        .map(|v| v["op"].as_str().unwrap_or("").to_owned())
        .collect()
}

fn text_json(result: &Value) -> Value {
    let text = result["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("content[0].text is a string: {result}"));
    serde_json::from_str(text).expect("content[0].text is JSON")
}

/// 実バイナリの `list_containers` の結果（OS 差を 1 箇所に閉じる）。状態ルートが空の一時領域なので 0 件。
fn assert_list_containers_result(result: &Value) {
    #[cfg(target_os = "linux")]
    {
        assert_eq!(result["isError"], json!(false), "{result}");
        let expected = json!({"containers": [], "truncated": false});
        assert_eq!(result["structuredContent"], expected, "{result}");
        assert_eq!(text_json(result), expected, "{result}");
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Linux 以外は core の状態ストアが状態ルートを検査できず UNIMPLEMENTED（fail-closed）。
        assert_eq!(result["isError"], json!(true), "{result}");
        assert_eq!(
            text_json(result),
            json!({"code": "UNIMPLEMENTED", "message": "Not implemented"}),
            "{result}"
        );
    }
}

/// `start_container` は本番起動が未実装（REPAIR-3。#1718）のため、全 OS で `isError` の UNIMPLEMENTED。
fn assert_start_container_unimplemented(result: &Value) {
    assert_eq!(result["isError"], json!(true), "{result}");
    assert_eq!(
        text_json(result)["code"],
        json!("UNIMPLEMENTED"),
        "{result}"
    );
}

/// MCP-1・MCP-2・MCP-3: 追随後も legacy（2025-06-18）の `initialize` → `tools/list` → `tools/call` が通る。
#[test]
fn mcp1_mcp2_legacy_full_sequence_survives_over_stdio() {
    let rt = Runtime::new();
    let reqs = [
        init(1),
        INITIALIZED.to_owned(),
        legacy(2, "tools/list", ""),
        legacy(
            3,
            "tools/call",
            r#","params":{"name":"list_containers","arguments":{}}"#,
        ),
        legacy(
            4,
            "tools/call",
            r#","params":{"name":"start_container","arguments":{"container_id":"c1"}}"#,
        ),
    ];
    let out = run(&rt.dir(), &reqs);
    assert_eq!(out.status.code(), Some(0));
    let lines = responses(&out, &[1, 2, 3, 4]);
    assert_eq!(lines[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        lines[0]["result"]["serverInfo"]["name"],
        "fandhe-container-plugin-mcp"
    );
    assert_eq!(
        lines[0]["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
    let names: Vec<&str> = lines[1]["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(names, ["list_containers", "start_container"]);
    assert_list_containers_result(&lines[2]["result"]);
    assert_start_container_unimplemented(&lines[3]["result"]);
    // D3・D6: legacy の result には 2026-07-28 の項目が無い。
    for line in &lines {
        for key in ["resultType", "ttlMs", "cacheScope", "_meta"] {
            assert!(line["result"].get(key).is_none(), "{key} in {line}");
        }
    }
    assert_eq!(
        ops(&out),
        [
            "initialize",
            "notification",
            "tools/list",
            "tools/call",
            "tools/call"
        ]
    );
}

/// MCP-3・MCP-2: `initialize` なしの modern（2026-07-28）の `server/discover` → `tools/list` → `tools/call`。
#[test]
fn mcp3_mcp2_modern_full_sequence_over_stdio() {
    let rt = Runtime::new();
    let reqs = [
        modern(1, "server/discover", ""),
        modern(2, "tools/list", ""),
        modern(3, "tools/call", &call_params("list_containers", "{}")),
        modern(
            4,
            "tools/call",
            &call_params("start_container", r#"{"container_id":"c1"}"#),
        ),
    ];
    let out = run(&rt.dir(), &reqs);
    assert_eq!(out.status.code(), Some(0));
    let lines = responses(&out, &[1, 2, 3, 4]);
    for line in &lines {
        assert_eq!(line["result"]["resultType"], "complete", "{line}");
        assert_eq!(
            line["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "fandhe-container-plugin-mcp",
            "{line}"
        );
    }
    assert_eq!(
        lines[0]["result"]["supportedVersions"],
        json!(["2026-07-28"])
    );
    for line in &lines[..2] {
        assert_eq!(line["result"]["ttlMs"], 3_600_000, "{line}");
        assert_eq!(line["result"]["cacheScope"], "public", "{line}");
    }
    let names: Vec<&str> = lines[1]["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(names, ["list_containers", "start_container"]);
    assert_list_containers_result(&lines[2]["result"]);
    assert_start_container_unimplemented(&lines[3]["result"]);
    assert_eq!(
        ops(&out),
        ["server/discover", "tools/list", "tools/call", "tools/call"]
    );
}

fn tools_array(line: &Value) -> Value {
    line["result"]["tools"].clone()
}

/// MCP-3・MCP-2: 同一接続で経路が変わっても `tools/list` の `tools` 配列は同一で順序が決定的（SHOULD）。
#[test]
fn mcp3_tools_list_is_stable_across_routes_on_one_connection() {
    let rt = Runtime::new();
    let reqs = [
        modern(1, "tools/list", ""),
        init(2),
        legacy(3, "tools/list", ""),
        modern(4, "tools/list", ""),
    ];
    let out = run(&rt.dir(), &reqs);
    assert_eq!(out.status.code(), Some(0));
    let lines = responses(&out, &[1, 2, 3, 4]);
    assert_eq!(tools_array(&lines[0]), tools_array(&lines[2]));
    assert_eq!(tools_array(&lines[0]), tools_array(&lines[3]));
    let names: Vec<&str> = lines[0]["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert_eq!(names, ["list_containers", "start_container"]);
}

/// MCP-3: modern の要求は接続を legacy にせず、`initialize` の成功後だけ `_meta` なしの要求が通る。
#[test]
fn mcp3_dual_era_probe_then_initialize_over_stdio() {
    let rt = Runtime::new();
    let reqs = [
        modern(1, "server/discover", ""),
        legacy(2, "tools/list", ""),
        modern(3, "ping", ""),
        init(4),
        legacy(5, "tools/list", ""),
        modern(6, "tools/list", ""),
    ];
    let out = run(&rt.dir(), &reqs);
    assert_eq!(out.status.code(), Some(0));
    let lines = responses(&out, &[1, 2, 3, 4, 5, 6]);
    assert_eq!(lines[0]["result"]["resultType"], "complete");
    assert_eq!(lines[1]["error"]["code"], -32602, "{}", lines[1]);
    assert_eq!(lines[1]["error"]["data"]["code"], "INVALID_ARGUMENT");
    assert_eq!(lines[2]["error"]["code"], -32601, "{}", lines[2]);
    assert_eq!(lines[3]["result"]["protocolVersion"], "2025-06-18");
    assert!(lines[4]["result"].get("resultType").is_none());
    assert_eq!(
        lines[4]["result"]["tools"].as_array().map(Vec::len),
        Some(2)
    );
    assert_eq!(lines[5]["result"]["resultType"], "complete");
}

/// MCP-1・REPAIR-4: stdout は応答だけで、stderr は 1 行 JSON のログのみ。要求の版や状態ルートのパスを反射しない。
#[test]
fn mcp3_stdout_has_only_responses_and_logs_do_not_reflect_input() {
    let rt = Runtime::new();
    let unsupported = r#"{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01"}}}"#;
    let reqs = [
        modern(1, "server/discover", ""),
        init(2),
        INITIALIZED.to_owned(),
        legacy(3, "tools/list", ""),
        modern(4, "tools/list", ""),
        unsupported.to_owned(),
    ];
    let out = run(&rt.dir(), &reqs);
    assert_eq!(out.status.code(), Some(0));
    let lines = responses(&out, &[1, 2, 3, 4, 7]);
    assert_eq!(lines[4]["error"]["code"], -32022, "{}", lines[4]);
    let stderr = String::from_utf8(out.stderr.clone()).expect("stderr is UTF-8");
    for l in stderr.lines() {
        serde_json::from_str::<Value>(l).expect("stderr line is JSON");
    }
    assert!(!stderr.contains("1900-01-01"), "{stderr}");
    let run_dir = rt.dir();
    assert!(
        !stderr.contains(run_dir.to_str().expect("utf8 path")),
        "{stderr}"
    );
}

/// 公開 API 用のフェイク。本番の `start_container` は未実装のため、実バイナリでは確かめられない成功の形を
/// ここで固定する（MCP-2）。
struct Fake {
    started: std::sync::Mutex<Vec<String>>,
}

impl Fake {
    fn new() -> Self {
        Self {
            started: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl ToolBackend for Fake {
    fn list_containers(&self) -> Result<ContainerList, TraitError> {
        Ok(ContainerList {
            containers: vec![ContainerSummary {
                id: "c1".to_owned(),
                status: "running".to_owned(),
                pid: Some(42),
            }],
            truncated: false,
        })
    }

    fn start_container(&self, id: &ContainerId) -> Result<StartedSummary, TraitError> {
        self.started
            .lock()
            .expect("lock")
            .push(id.as_str().to_owned());
        Ok(ContainerSummary {
            id: id.as_str().to_owned(),
            status: "running".to_owned(),
            pid: Some(43),
        })
    }
}

fn send(backend: &Fake, conn: &mut ConnectionState, line: &str) -> Value {
    handle_message_on(line.as_bytes(), backend, conn)
        .reply
        .expect("a reply")
}

/// MCP-2・MCP-3: 2 ツールが両経路で正常応答の形（`isError: false`・`structuredContent`・`content`）を返す。
#[test]
fn mcp2_both_tools_succeed_on_both_routes_with_fake_backend() {
    let backend = Fake::new();
    let mut conn = ConnectionState::default();
    let list_args = r#","params":{"name":"list_containers","arguments":{}}"#;
    let start_args = r#","params":{"name":"start_container","arguments":{"container_id":"c1"}}"#;

    let init_reply = send(&backend, &mut conn, &init(1));
    assert_eq!(init_reply["result"]["protocolVersion"], "2025-06-18");
    let l = send(&backend, &mut conn, &legacy(2, "tools/call", list_args));
    let s = send(&backend, &mut conn, &legacy(3, "tools/call", start_args));
    // 同じ接続でも `_meta` つきの要求は modern として処理される。
    let ml = send(
        &backend,
        &mut conn,
        &modern(4, "tools/call", &call_params("list_containers", "{}")),
    );
    let ms = send(
        &backend,
        &mut conn,
        &modern(
            5,
            "tools/call",
            &call_params("start_container", r#"{"container_id":"c1"}"#),
        ),
    );

    let list_expected =
        json!({"containers":[{"id":"c1","status":"running","pid":42}],"truncated":false});
    let start_expected = json!({"id":"c1","status":"running","pid":43});
    for (reply, expected, is_modern) in [
        (&l, &list_expected, false),
        (&s, &start_expected, false),
        (&ml, &list_expected, true),
        (&ms, &start_expected, true),
    ] {
        let r = &reply["result"];
        assert_eq!(r["isError"], json!(false), "{reply}");
        assert_eq!(&r["structuredContent"], expected, "{reply}");
        assert_eq!(&text_json(r), expected, "{reply}");
        if is_modern {
            assert_eq!(r["resultType"], "complete", "{reply}");
        } else {
            assert!(r.get("resultType").is_none(), "{reply}");
        }
    }
    assert_eq!(*backend.started.lock().expect("lock"), ["c1", "c1"]);
}

fn tools_via_api() -> Vec<Value> {
    let backend = Fake::new();
    let mut conn = ConnectionState::default();
    let reply = send(&backend, &mut conn, &modern(1, "tools/list", ""));
    reply["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .clone()
}

/// MCP-3: ツール名は SEP-986 の指針（1〜128 文字・`[A-Za-z0-9_.-]`・一意）に適合する。
#[test]
fn mcp3_tool_names_follow_the_naming_guidance() {
    let tools = tools_via_api();
    let mut seen = Vec::new();
    for t in &tools {
        let name = t["name"].as_str().expect("name is a string");
        assert!((1..=128).contains(&name.len()), "{name}");
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')),
            "{name}"
        );
        assert!(!seen.contains(&name), "duplicate tool name {name}");
        seen.push(name);
    }
    assert_eq!(seen, ["list_containers", "start_container"]);
}

/// MCP-3: `inputSchema` を完全一致で固定する。`$schema` は付けない（無ければ 2020-12 が既定。SEP-1613）。
#[test]
fn mcp3_input_schemas_are_fixed_and_2020_12_compatible() {
    let tools = tools_via_api();
    assert_eq!(
        tools[0]["inputSchema"],
        json!({"type":"object","properties":{}})
    );
    assert_eq!(
        tools[1]["inputSchema"],
        json!({"type":"object","properties":{"container_id":{"type":"string"}},"required":["container_id"]})
    );
    for t in &tools {
        assert!(t["inputSchema"].get("$schema").is_none(), "{t}");
    }
}
