//! fandhe-container-plugin-cri: CRI サーバー plugin バイナリ（`fandhe-container-cri` の実装を別プロセス化）。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G8（TASK-114）で実装する。`fandhe-container-plugin`（境界機構）の UDS フレームを介して
//! core と通信し、`fandhe-container-cri` の Runtime/ImageService を実行する。PLUG-1 区分は plugin（crate-naming.md）。
