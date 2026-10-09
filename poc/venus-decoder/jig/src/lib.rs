//! 試験治具 VMM と自前 venus デコーダをつなぐ capset アダプタ（GPU-6・TASK-172.4・#888）。
//!
//! 役割: 治具 VMM が受けた virtio-gpu ctrl 要求のうち ctrl 要求（capset クエリ・`GET_DISPLAY_INFO`・`CTX_CREATE` / `CTX_DESTROY`。#1520）を
//! 復号して `fandhe_container_plugin_macos::gpu::venus` へ渡し、応答を ctrl 形式に符号化して構造化ログを 1 行出す。
//! 呼び出し元は `session`（vhost-user のセッションと ctrl キューの応答ループ。F1.4・#1519。Linux 限定）。
//! TASK-175 の製品版 ctrl 枠とは別物の PoC 実装で、製品 crate はこのパッケージに依存しない。
//!
//! vhost-user のメッセージ codec は実装済み（`vhost_user`。F1.1・#1516）。fd の受け渡し（`SCM_RIGHTS`）と
//! ゲストメモリの mmap の安全なラッパーも実装済み（Linux 限定。F1.2・#1517）。`unsafe` は `sys` モジュール（#1517 の個別承認 U1〜U10 と、PLUG-12 の peer credential 用 U11）にだけ置く。
//!
//! split virtqueue（記述子チェーンの走査と used への書き戻し。F1.3・#1518）は `virtqueue` に実装済み（トランスポートに依存しない）。
//!
//! セッションと ctrl キューの応答ループ（kick / call・used への書き戻し）は `session` に実装済み（F1.4・#1519。Linux 限定）。
//!
//! 起動入口（UDS の bind・期限つき accept・ログのファイル出力。F4・#1598）は `launch` と bin `venus-jig` に実装済み（Linux 限定）。
//!
//! 未実装（実装済みを装わない。REPAIR-3）: cursorq の処理、
//! `observe::snapshot_lines` の定期出力（終了時の集計出力は実装済み）と virtqueue 個別の観測カウンタ、上記以外の ctrl 応答（F2 の残り。未対応は `ERR_UNSPEC`）、
//! 実機での疎通（F3・#725）。

// unsafe の配置制約（#1517 の個別承認の条件）: crate 全体で unsafe を禁止し、syscall の薄いラッパーを置く `sys`
// だけで許可する。モジュールごとの deny にしないのは、新しく足したモジュールが既定で unsafe を許してしまうため。
#![deny(unsafe_code)]

pub mod adapter;
pub mod ctrl;
pub mod device;
#[cfg(target_os = "linux")]
pub mod launch;
pub mod log;
#[cfg(target_os = "linux")]
pub mod session;
pub mod vhost_user;
pub mod virtqueue;

/// syscall の薄いラッパー。`unsafe` はここにだけ置く（Linux 限定）。
// 理由: `sys` は #1517 の個別承認 U1〜U10 の unsafe（syscall・fd 所有・mmap・境界検査後のコピー）を持つ唯一の
// モジュールで、この allow はオーナーが承認条件として指定した配置（U1〜U8:
// https://github.com/Fandhe-AI/fandhe-container/issues/1517#issuecomment-6074351741 、U9・U10 と lint 構成:
// https://github.com/Fandhe-AI/fandhe-container/issues/1517#issuecomment-6075711404 ）。各 unsafe ブロックには
// `// SAFETY:` を付け、`unsafe fn` を外へ公開しない。外部入力の検証は `sys` の外の safe コードと `sys` の境界検査で行う。
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod sys;

#[cfg(test)]
mod tests;
