//! fandhe-container-stack: TOML スキーマ・`depends_on` 起動順・`profiles` 絞り込み。
//!
//! 現状はトップレベルの型（`schema::ComposeToml` 等。TASK-149.2・#584）と `Service` の
//! 基本フィールド（TASK-149.3・#585）と拡張フィールド（restart・ulimits・devices・profiles 等。
//! TASK-149.4.1・#862）まで。healthcheck・deploy.resources は TASK-149.4.2（#863）、
//! parse / serialize の入口はまだ無い（STACK-1・CLI-4。未実装の明示は REPAIR-3）。
//! 本体は G11（TASK-149、TASK-150・187〜188）で実装する。crate 名は crate-naming.md で確定済み。
//! `fandhe-container-compose-convert` から一方向に依存される（決定 5）。PLUG-1 区分は
//! core（CLI＋ライブラリ API。crate-naming.md）。

pub mod schema;
