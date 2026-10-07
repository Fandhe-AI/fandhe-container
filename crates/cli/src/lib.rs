//! fandhe-container-cli: 統一 CLI・基本コマンド（create/start/stop/delete/list/logs/ps）、観測性。
//!
//! 実装済みは [`doctor`] の判定材料取得（TASK-148.1）と評価層（警告・DOCKER-USER 案内・終了コード。TASK-148.2・NET-10）のみで、
//! バイナリ `fandhe-container` の入口と [`commands`] の骨格は TASK-79.1（#638・CLI-1・MS-6）で追加した。
//! `create` / `start` は core を直接呼ぶ（TASK-79.2.1・#866。ただし本番 launcher 未提供のため `start` は `UNIMPLEMENTED`）。
//! 他のコマンド本体は未実装で、呼ぶと `UNIMPLEMENTED` を返す（TASK-79.2.2〜79.4 で実装。REPAIR-3）。
//! それ以外は雛形のまま実装がない（TASK-1.3・REPAIR-1）。
//! 本体は G6（TASK-79〜98 の一部。crate の中核成果物は TASK-79〔基本コマンド〕・TASK-95〔エラー形式〕）で
//! 実装する。PLUG-1 区分は core（crate-naming.md）。

pub mod commands;
pub mod doctor;
