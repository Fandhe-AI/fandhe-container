//! fandhe-container-benches: crate をまたぐベンチ（TASK-113）と基準値（TASK-88・REPAIR-8）を置く crate。
//!
//! ライブラリ本体は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! `publish = false`（crate-naming.md 決定 7）。ベンチ本体は該当 TASK で追加し、
//! `[[bench]]` の配置方針（`benches/benches/*.rs` か `path` 明示か）は TASK-113 で決める。
//!
//! `benches/regression_placeholder.rs` に TASK-86.3（REPAIR-7 第 4 段階）で導入した
//! プレースホルダベンチが 1 本ある。決定的な固定値を出力するだけの stub で、CI の
//! ベンチ回帰ゲート（REPAIR-8）を暫定的に稼働させるためのもの。実測を伴う本物の
//! ベンチ（`plugin_boundary` 等）と実測基準値（`benches/baseline.json`）への置き換えは
//! それぞれ TASK-113・TASK-88 で行う。
