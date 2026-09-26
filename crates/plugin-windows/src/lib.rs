//! fandhe-container-plugin-windows: Windows バックエンド plugin バイナリ（`fandhe-container-platform-windows` の実装を別プロセス化）。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G8（TASK-116）で実装する。`fandhe-container-plugin`（境界機構）の UDS フレームを介して
//! core と通信し、`fandhe-container-platform-windows` の WSL2 実装を実行する。PLUG-1 区分は plugin（crate-naming.md）。
