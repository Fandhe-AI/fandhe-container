//! fandhe-container-benches: crate をまたぐベンチ（TASK-113）と基準値（TASK-88・REPAIR-8）を置く crate。
//!
//! `publish = false`（crate-naming.md 決定 7）。ベンチ本体は `benches/benches/*.rs`（自動発見位置）に置き、
//! 計測ロジックは本 crate のモジュールに置く（`cargo test` でユニットテストするため）。
//! 現在のモジュールは [`plugin_boundary`]（TASK-113.2・PLUG-5。代表操作 B の計測部品）のみ。
//!
//! `benches/regression_placeholder.rs` に TASK-86.3（REPAIR-7 第 4 段階）で導入した
//! プレースホルダベンチが 1 本ある。決定的な固定値を出力するだけの stub で、CI の
//! ベンチ回帰ゲート（REPAIR-8）を暫定的に稼働させるためのもの。実測を伴う本物の
//! ベンチ（`plugin_boundary` 等）と実測基準値（`benches/baseline.json`）への置き換えは
//! それぞれ TASK-113・TASK-88 で行う。

pub mod plugin_boundary;
