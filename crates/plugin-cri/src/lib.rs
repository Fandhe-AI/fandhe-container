//! fandhe-container-plugin-cri: CRI サーバー plugin バイナリ（`fandhe-container-cri` の実装を別プロセス化）。
//!
//! 現状はバイナリの入口（起動引数の解析と終了コードの規則。[`startup`]）だけがある（TASK-114.1・#457・PLUG-1）。
//! CRI サーバー本体（adapter）は未実装で、TASK-114.2（#458）で移設する。core との境界越しの接続
//! （socket の解決・接続の向き・フレームの形）は TASK-114.3（#459）と `docs/design/plugin-backend-wiring.md`
//! （#1869。承認待ち）で決めるため、本雛形はそれを先取りしない（REPAIR-3）。
//! 将来は `fandhe-container-plugin`（境界機構）の UDS フレームを介して core と通信する。
//! PLUG-1 区分は plugin（crate-naming.md）。

pub mod startup;
