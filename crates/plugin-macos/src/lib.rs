//! fandhe-container-plugin-macos: macOS バックエンド plugin バイナリ（`fandhe-container-platform-macos` の実装を別プロセス化）。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G8（TASK-115）で実装する。macOS Venus（GPU-6、TASK-172〜181）の virtio-gpu デバイスモデル・
//! コンテキスト分配層・venus デコーダも `src/gpu/` 配下に置く定義になっている（crate-naming.md）。
//! `fandhe-container-plugin`（境界機構）の UDS フレームを介して core と通信する。PLUG-1 区分は plugin。
