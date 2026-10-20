//! fandhe-container-stack: TOML スキーマ・`depends_on` 起動順・`profiles` 絞り込み。
//!
//! 現状は雛形のみ。依存（serde・toml）は TASK-149.1（#583）で入ったが、型・parse /
//! serialize はまだ無い（TASK-149.2 以降。STACK-1・CLI-4。スタブの明示は REPAIR-3）。
//! 本体は G11（TASK-149、TASK-150・187〜188）で実装する。crate 名は crate-naming.md で確定済み。
//! `fandhe-container-compose-convert` から一方向に依存される（決定 5）。PLUG-1 区分は
//! core（CLI＋ライブラリ API。crate-naming.md）。
