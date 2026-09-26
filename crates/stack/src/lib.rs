//! fandhe-container-stack: TOML スキーマ・`depends_on` 起動順・`profiles` 絞り込み。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G11（TASK-149 が crate 雛形、TASK-150・187〜188）で実装する。
//! `fandhe-container-compose-convert` から一方向に依存される（決定 5）。PLUG-1 区分は
//! core（CLI＋ライブラリ API。crate-naming.md）。
