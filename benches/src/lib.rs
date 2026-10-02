//! fandhe-container-benches: crate をまたぐベンチ（TASK-113）と基準値（TASK-88・REPAIR-8）を置く crate。
//!
//! `publish = false`（crate-naming.md 決定 7）。ベンチ本体は該当 TASK で追加する。
//! `[[bench]]` は `benches/benches/*.rs` の自動発見に任せる配置とする（TASK-113.1 で決定）。
//! `plugin_boundary` モジュールは代表操作 A の計測ロジック（TASK-113.1・PLUG-5）。
//! `plugin_boundary_list_images` モジュールは代表操作 B（イメージ一覧）の計測ロジック（TASK-113.2・PLUG-5）。
//!
//! `benches/regression_placeholder.rs` に TASK-86.3（REPAIR-7 第 4 段階）で導入した
//! プレースホルダベンチが 1 本ある。決定的な固定値を出力するだけの stub で、CI の
//! ベンチ回帰ゲート（REPAIR-8）を暫定的に稼働させるためのもの。`plugin_boundary` ベンチ
//! （代表操作 A。TASK-113.1）はゲート未接続で、実測基準値（`benches/baseline.json`）への
//! 置き換えは TASK-88、ゲート接続は TASK-113.3 で行う。

pub mod plugin_boundary;
pub mod plugin_boundary_list_images;
