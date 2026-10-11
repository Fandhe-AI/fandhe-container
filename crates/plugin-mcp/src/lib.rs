//! fandhe-container-plugin-mcp: MCP サーバー plugin（参照実装。MCP-1・MCP-2。TASK-118・MS-4）。
//!
//! 本 crate は lib と bin（`src/main.rs`、バイナリ名 `fandhe-container-plugin-mcp`。PLUG-4・PLUG-11）
//! で構成する。lib の [`server`] が stdio JSON-RPC 2.0 の処理（`initialize` / `tools/list` / `tools/call`。TASK-118.2・118.3）
//! を持ち、bin が stdin / stdout を配線する。[`backend`] が `tools/call` の実行層で、`list_containers` は
//! core の状態ストアを読む。[`uds`] は core が bind した UDS へ peer 認証つき
//! （PLUG-12）で接続した上で同じ JSON-RPC 処理を行う（TASK-118.4・#467）。`start_container` の本番起動は
//! 未実装（REPAIR-3。#1718）。core 側 proxy との結線・フレーミングの確定は TASK-114。
//! PLUG-1 区分は plugin（crate-naming.md）。

pub mod backend;
pub mod server;
pub mod uds;
