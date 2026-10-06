//! fandhe-container-plugin-macos: macOS バックエンド plugin バイナリ（`fandhe-container-platform-macos` の実装を別プロセス化）。
//!
//! 実装済み: 起動引数の解析と socket パスの解決（[`startup`]。TASK-115.1・#385・MAC-1・PLUG-1）、
//! UDS 上の長さ接頭辞フレーム送受信ループ（[`frame_loop`]。TASK-115.2・#386）、
//! create / start / stop を platform-macos へ委譲するアダプタ（[`adapter`]。TASK-115.3・#387）。
//! 未実装（実装済みを装わない。REPAIR-3）: 型つき本体と core の `ContainerRuntime` への接続（TASK-114）・peer 認証済み接続（TASK-115.4）・macOS Venus（GPU-6、TASK-172〜181。
//! virtio-gpu デバイスモデル等は `src/gpu/` 配下に置く定義。crate-naming.md）。
//!
//! 接続方向の現行契約: socket は core 側が bind し、plugin が接続する（`fandhe-container-plugin` の
//! `lifecycle` 冒頭「契約」）。TASK-115.2 はこの connect 側を実装した。plugin 側 bind へ変える
//! 可否は TASK-115.4 の着手前に確定が必要な設計事項である。
//! `fandhe-container-plugin`（境界機構）の UDS フレームを介して core と通信する。PLUG-1 区分は plugin。

pub mod adapter;
pub mod frame_loop;
pub mod startup;
