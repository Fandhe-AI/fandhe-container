//! fandhe-container-core: 実行層（namespace・cgroups v2・seccomp/Landlock・rootless・ログ・状態管理）。
//!
//! 現状は拡張点トレイト（[`traits`]。TASK-4・CRI-7）の定義のみを持ち、実行層本体
//! （namespace・cgroups v2・seccomp/Landlock・rootless 等）は G3（TASK-27〜50）で実装する
//! 未実装のままである（REPAIR-3: 実装済みを装わず、未実装であることも隠さない）。
//! `StateStore` トレイトとファイルベースの既定実装も本 crate に置く（TASK-31・決定 6）。
//! PLUG-1 区分は core（crate-naming.md）。

pub mod traits;
