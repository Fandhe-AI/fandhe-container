//! fandhe-container-plugin-mcp: MCP サーバー plugin（参照実装。MCP-1・MCP-2。TASK-118・MS-4）。
//!
//! 本 crate は lib と bin（`src/main.rs`、バイナリ名 `fandhe-container-plugin-mcp`。PLUG-4・PLUG-11）
//! で構成する。lib の [`server`] が stdio JSON-RPC 2.0 の処理（`initialize` / `tools/list` / `tools/call`。TASK-118.2・118.3）
//! を持ち、bin が stdin / stdout を配線する。[`backend`] が `tools/call` の実行層で、`list_containers` は
//! core の状態ストアを読む。`start_container` の本番起動と core との UDS 通信は未実装
//! （REPAIR-3。起動は #1718、UDS は #467 で実装する）。
//! PLUG-1 区分は plugin（crate-naming.md）。

pub mod backend;
pub mod server;
