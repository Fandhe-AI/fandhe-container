//! 試験治具 VMM と自前 venus デコーダをつなぐ capset アダプタ（GPU-6・TASK-172.4・#888）。
//!
//! 役割: 治具 VMM が受けた virtio-gpu ctrl 要求のうち ctrl 要求（capset クエリ・`GET_DISPLAY_INFO`・`CTX_CREATE` / `CTX_DESTROY`。#1520）を
//! 復号して `fandhe_container_plugin_macos::gpu::venus` へ渡し、応答を ctrl 形式に符号化して構造化ログを 1 行出す。
//! 呼び出し元は将来のトランスポート層（vhost-user。後続 F1.2〜F1.4）で、現時点でどこからも呼ばれない。
//! TASK-175 の製品版 ctrl 枠とは別物の PoC 実装で、製品 crate はこのパッケージに依存しない。
//!
//! vhost-user のメッセージ codec は実装済み（`vhost_user`。F1.1・#1516）。fd の受け渡し（`SCM_RIGHTS`）と
//! ゲストメモリの mmap の安全なラッパーも実装済み（Linux 限定。F1.2・#1517）。`unsafe` は `sys` モジュール（承認範囲 U1〜U8）にだけ置く。
//!
//! 未実装（実装済みを装わない。REPAIR-3）: トランスポートのヘッダ単位のソケット I/O の枠組み（F1.4）、
//! virtqueue（F1.3・#1518）、セッション状態と応答ループ（F1.4・#1519）、上記以外の ctrl 応答（F2 の残り。未対応は `ERR_UNSPEC`）、
//! 実機での疎通（F3・#725）。

#![deny(unsafe_code)]

pub mod adapter;
pub mod ctrl;
pub mod device;
pub mod log;
pub mod vhost_user;

/// syscall の薄いラッパー。`unsafe` はここにだけ置く（#1517 の個別承認の範囲）。Linux 限定。
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;

#[cfg(test)]
mod tests;
