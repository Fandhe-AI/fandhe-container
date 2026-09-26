//! fandhe-container-core: 実行層（namespace・cgroups v2・seccomp/Landlock・rootless・ログ・状態管理）。
//!
//! 現状は雛形のみで、実装はない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G3（TASK-27〜50）で実装する。`StateStore` トレイトとファイルベースの既定実装も
//! 本 crate に置く（TASK-31・決定 6）。PLUG-1 区分は core（crate-naming.md）。
//!
//! `traits` モジュールに `ContainerRuntime`・`StateStore`・`NetworkPlugin`・
//! `VolumeProvider` の 4 拡張点トレイトを定義する（TASK-4・CRI-7）。

pub mod traits;
