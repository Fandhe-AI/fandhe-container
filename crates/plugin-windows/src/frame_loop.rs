//! UDS フレーム受信ループの入口（本体は共有 crate `fandhe-container-plugin::frame_loop`。#3776。PLUG-1・REPAIR-1・WIN-2）。
//!
//! 受信ループ本体（2 段階受信・ヘッダ検証・エラー応答・送信ループ・`handle_with_stop`・代替受信）は #3773 の判断
//! （案 a）で `crates/plugin` へ移した。本モジュールは `main.rs`・`adapter.rs`・結合試験の import を保つための
//! 再 export と、本 crate の停止の粒度を固定する薄い `serve` / `serve_until` だけを持つ。
//! 本 crate に固有なのは方針 [`ShutdownPolicy::DiscardInProgress`]（受信・送信の途中でも停止フラグを見て
//! 未完了フレームを破棄する。TASK-116.5・#396・WIN-2）・ハンドラ（`adapter::WindowsRuntimeAdapter`）・
//! SIGTERM の停止フラグ（`crate::sys`・`main.rs`）。単体試験は共有側へ移した（実バイナリの終了コード・
//! stderr・SIGTERM の契約は `tests/frame_loop.rs`）。
//!
//! 再 export の `serve` / `serve_until` を共有側の名前のまま使うと [`ShutdownPolicy::CompleteFrame`] の
//! 挙動になり WIN-2 の 5 秒の猶予を守れないため、本モジュールで `DiscardInProgress` 固定の関数を定義する。

use std::sync::atomic::AtomicBool;

use fandhe_container_plugin::frame_loop::serve_until_with;
pub use fandhe_container_plugin::frame_loop::{
    FRAME_DEADLINE, IDLE_POLL, LoopExit, REQUEST_BODY_MAX_ITEMS, RequestHandler, ShutdownPolicy,
    UnimplementedHandler, handle_frame,
};
use fandhe_container_plugin::{PluginError, UdsStream};

/// 接続済み `stream` 上で要求を順次処理する（停止フラグなし）。立たない停止フラグで [`serve_until`] を呼ぶ。
pub fn serve<H: RequestHandler>(
    stream: &mut UdsStream,
    handler: &mut H,
) -> Result<LoopExit, PluginError> {
    serve_until(stream, handler, &AtomicBool::new(false))
}

/// [`serve`] に停止フラグ（SIGTERM）を加えたもの。[`ShutdownPolicy::DiscardInProgress`] 固定で共有側の
/// `serve_until_with` へ委譲する。検知遅れは最大 [`IDLE_POLL`]（TASK-116.5・#396・WIN-1・WIN-2）。
pub fn serve_until<H: RequestHandler>(
    stream: &mut UdsStream,
    handler: &mut H,
    stop: &AtomicBool,
) -> Result<LoopExit, PluginError> {
    serve_until_with(stream, handler, stop, ShutdownPolicy::DiscardInProgress)
}
