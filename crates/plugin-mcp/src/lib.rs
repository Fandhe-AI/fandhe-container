//! fandhe-container-plugin-mcp: MCP サーバー plugin（参照実装。MCP-1・MCP-2。TASK-118）。
//!
//! 本 crate は lib と bin（`src/main.rs`、バイナリ名 `fandhe-container-plugin-mcp`。PLUG-4・PLUG-11）
//! で構成する。bin は TASK-118.1（#464）で追加した雛形で、MCP の処理は未実装
//! （REPAIR-3。後続 sub で `fandhe-container-plugin` の UDS フレーム経由の core 通信を実装する）。
//! lib に公開 API はない。PLUG-1 区分は plugin（crate-naming.md）。
