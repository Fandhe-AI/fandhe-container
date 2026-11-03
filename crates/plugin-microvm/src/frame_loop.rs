//! UDS フレーム受信ループの入口（本体は共有 crate `fandhe-container-plugin::frame_loop`。#3774。PLUG-1・REPAIR-1）。
//!
//! 受信ループ本体（2 段階受信・ヘッダ検証・エラー応答・`serve` / `serve_until`）は #3773 の判断（案 a）で
//! `crates/plugin` へ移した。本モジュールは `main.rs`・`adapter.rs`・結合試験の import を保つための再 export だけを持つ。
//! 本 crate に固有なのはハンドラ（`adapter::MicrovmRuntimeAdapter`）と SIGTERM の停止フラグ（`crate::sys`・`main.rs`）。
//! 単体試験は共有側へ移した。

pub use fandhe_container_plugin::frame_loop::{
    FRAME_DEADLINE, IDLE_POLL, LoopExit, REQUEST_BODY_MAX_ITEMS, RequestHandler,
    UnimplementedHandler, handle_frame, serve, serve_until,
};
