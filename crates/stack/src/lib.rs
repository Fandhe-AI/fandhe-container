//! fandhe-container-stack: TOML スキーマ・`depends_on` 起動順・`profiles` 絞り込み。
//!
//! 現状はトップレベルの型（`schema::ComposeToml` 等。TASK-149.2・#584）と `Service` の
//! 基本フィールド（TASK-149.3・#585）、拡張フィールド（restart・ulimits・devices・profiles 等。
//! TASK-149.4.1・#862）と healthcheck・deploy.resources（TASK-149.4.2・#863）まで。
//! `depends_on` の起動順計画・循環検出は `depends_on` モジュール（STACK-2・TASK-150.1・#589。`started` の待機は `depends_on::wait`・#590、`healthy` の待機は TASK-150.3・#591。healthy 未達のタイムアウトのエラー化は #592）。
//! `up` のトポロジカル順起動は `cli::up`（STACK-8・TASK-155.1・#618。本番アダプタと CLI 結線は未実装）。
//! `logs` は `cli::logs`（STACK-8・TASK-155.5・#622。本番アダプタと CLI 結線は未実装）。
//! `down` の依存逆順停止は `cli::down`（STACK-8・TASK-155.3・#620。本番アダプタと CLI 結線は未実装）。
//! `ps` の状態一覧は `cli::ps`（STACK-8・TASK-155.4・#621。本番アダプタと CLI 結線は未実装）。
//! parse / serialize の入口はまだ無い（STACK-1・CLI-4。未実装の明示は REPAIR-3）。
//! 本体は G11（TASK-149、TASK-150・187〜188）で実装する。crate 名は crate-naming.md で確定済み。
//! `fandhe-container-compose-convert` から一方向に依存される（決定 5）。PLUG-1 区分は
//! core（CLI＋ライブラリ API。crate-naming.md）。

pub mod cli;
pub mod depends_on;
pub mod schema;
