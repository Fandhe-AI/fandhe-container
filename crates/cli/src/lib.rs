//! fandhe-container-cli: 統一 CLI・基本コマンド（create/start/stop/delete/list/logs/ps）、観測性。
//!
//! 実装済みは [`doctor`] の判定材料取得（br_netfilter・Docker FORWARD policy。TASK-148.1・NET-10）のみで、
//! それ以外は雛形のまま実装がない（TASK-1.3・REPAIR-1。スタブの明示は REPAIR-3）。
//! 本体は G6（TASK-79〜98 の一部。crate の中核成果物は TASK-79〔基本コマンド〕・TASK-95〔エラー形式〕）で
//! 実装する。バイナリ名 `fandhe-container` は TASK-79 で付ける。PLUG-1 区分は core（crate-naming.md）。

pub mod doctor;
