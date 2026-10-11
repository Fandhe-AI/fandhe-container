//! fandhe-container-cri: CRI 実装ライブラリ（Runtime/ImageService・shim v2・streaming）。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G4（TASK-56〜63）で実装する。実行時は `fandhe-container-plugin-cri`（TASK-114）が
//! 本 crate を別プロセスとして動かす。PLUG-1 区分は plugin 境界の外側（バックエンド実装ライブラリ。crate-naming.md）。
//!
//! TASK-56.1（#423・CRI-3）で雛形を確認済み。proto は TASK-56.2（#424）で `proto/api.proto` に配置済み。`build.rs`（TASK-56.3・#426）が `OUT_DIR/runtime.v1.rs` へ
//! 生成するが、まだ `include!` していない。生成コードの取り込みとビルド確認は TASK-56.4（#427）、RPC 本体は TASK-57 以降で実装する。現状は実装のないスタブである。
