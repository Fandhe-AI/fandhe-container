//! fandhe-container-plugin-mcp: MCP サーバー plugin（参照実装。MCP-1・MCP-2。TASK-118・MS-4）。
//!
//! 本 crate は lib と bin（`src/main.rs`、バイナリ名 `fandhe-container-plugin-mcp`。PLUG-4・PLUG-11）
//! で構成する。lib の [`server`] が stdio JSON-RPC 2.0 の処理（`initialize` / `tools/list`。TASK-118.2）
//! を持ち、bin が stdin / stdout を配線する。`tools/call` と core との UDS 通信は未実装
//! （REPAIR-3。後続 sub で `fandhe-container-plugin` の UDS フレーム経由の core 通信を実装する）。
//! PLUG-1 区分は plugin（crate-naming.md）。

pub mod server;
