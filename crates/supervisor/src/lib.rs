//! fandhe-container-supervisor: コンテナごとの軽量監視プロセス（restart・healthcheck・exec・logs・stats）。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G12（TASK-157〜171。TASK-157 が crate 雛形・監視プロセス基本ループ、SUP-1）で実装する。
//! `fandhe-container-core` の `StateStore` 既定実装を使い、2 つ目の実装は持たない（決定 6）。
//! PLUG-1 区分は core（D-19。plugin 境界〔PLUG-2〕を経由せず実行層コアの一部。crate-naming.md）。
