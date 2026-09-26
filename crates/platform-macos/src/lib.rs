//! fandhe-container-platform-macos: macOS Virtualization.framework 経由の VM 起動・VirtioFS。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G5（TASK-64〜66）で実装する。実行時は `fandhe-container-plugin-macos`（TASK-115）が
//! 本 crate を別プロセスとして動かす。PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。
