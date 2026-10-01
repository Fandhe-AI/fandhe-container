//! fandhe-container-supervisor: コンテナごとの軽量監視プロセス（restart・healthcheck・exec・logs・stats）。
//!
//! 常駐デーモンを持たない設計（CORE-1・D-19）の実装主体で、コンテナ 1 つにつき 1 プロセスで監視する（SUP-1）。
//! PLUG-1 区分は core（plugin 境界〔PLUG-2〕を経由せず実行層コアの一部。crate-naming.md）。
//!
//! 現状は状態配線（[`state`]。TASK-157.3）と監視ループ基本（[`run`]。TASK-157.4）、restart の土台（異常終了時の `restart_count` 更新。TASK-157.5）が実装済みで、restart ポリシー本体（SUP-3）・healthcheck・logs 等は未実装（TASK-1.3・TASK-157.1〔#235〕・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G12（TASK-157〜171）で、次の分割に沿って実装する。
//!
//! | issue | TASK | 内容 |
//! | ----- | ---- | ---- |
//! | #236 | TASK-157.2 | core への状態型追加 |
//! | #237 | TASK-157.3 | core の `StateStore` 配線（supervisor から使う） |
//! | #238 | TASK-157.4 | 監視ループ基本（実装済み） |
//! | #239 | TASK-157.5 | restart の土台（実装済み。ポリシー本体は SUP-3 で未実装） |
//! | #240〜#241 | TASK-157.6〜157.7 | healthcheck・logs（未実装） |
//! | #242 | TASK-157.8 | 結合テスト |
//! | #1069 | TASK-157.9 | state.json 書き込み排他 |
//!
//! supervisor から `fandhe-container-core` への一方向依存は導入済み（TASK-157.3・#237）。
//! `StateStore` は core の既定実装を使い、2 つ目の実装は持たない（決定 6）。

pub mod run;
pub mod state;
