//! fandhe-container-cri: CRI 実装ライブラリ（Runtime/ImageService・shim v2・streaming）。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G4（TASK-56〜63）で実装する。実行時は `fandhe-container-plugin-cri`（TASK-114）が
//! 本 crate を別プロセスとして動かす。PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。
