//! fandhe-container-plugin-macos: macOS バックエンド plugin バイナリ（`fandhe-container-platform-macos` の実装を別プロセス化）。
//!
//! 実装済み: 起動引数の解析と socket パスの解決（[`startup`]。TASK-115.1・#385・MAC-1・PLUG-1）。
//! 未実装（実装済みを装わない。REPAIR-3）: フレーム送受信ループ（TASK-115.2）・`ContainerRuntime`
//! アダプタ（TASK-115.3）・peer 認証済み接続（TASK-115.4）・macOS Venus（GPU-6、TASK-172〜181。
//! virtio-gpu デバイスモデル等は `src/gpu/` 配下に置く定義。crate-naming.md）。
//!
//! 接続方向の現行契約: socket は core 側が bind し、plugin が接続する（`fandhe-container-plugin` の
//! `lifecycle` 冒頭「契約」）。本 crate は現時点で socket を開かない。bind / connect の方向は
//! TASK-115.2・115.4 の着手前に確定が必要な設計事項である。
//! `fandhe-container-plugin`（境界機構）の UDS フレームを介して core と通信する。PLUG-1 区分は plugin。

pub mod startup;
