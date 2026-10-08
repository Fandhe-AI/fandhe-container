//! fandhe-container-cli: 統一 CLI・基本コマンド（create/start/stop/delete/list/logs/ps）、観測性。
//!
//! 実装済みは [`doctor`] の判定材料取得（TASK-148.1）と評価層（警告・DOCKER-USER 案内・終了コード。TASK-148.2・NET-10）のみで、
//! バイナリ `fandhe-container` の入口と [`commands`] の骨格は TASK-79.1（#638・CLI-1・MS-6）で追加した。
//! `create` / `start` は core を直接呼ぶ（TASK-79.2.1・#866。ただし本番 launcher 未提供のため `start` は `UNIMPLEMENTED`）。
//! `stop` / `delete` は TASK-79.2.2、`list` は状態ストアから一覧を出し、`logs` は存在確認までで内容は `UNIMPLEMENTED`（TASK-79.3・#640。REPAIR-3）。
//! [`error`] は ERR-1 の構造化エラー型と stderr 出力（TASK-95.1・#649）。各コマンドの終了経路（`commands::CliExit`）へ配線済み（TASK-95.2・#650）。
//! `setup` は OS 固有設定の要求ステップを提示する（TASK-80.1・CLI-2。検出・適用は未実装。日常操作コマンドからは到達しない。TASK-80.2）。
//! `signals` は親が受けた SIGINT・SIGTERM・SIGHUP を起動中の plugin へ転送してから終了する（#1513・PLUG-7。unix のみ）。
//! それ以外は雛形のまま実装がない（TASK-1.3・REPAIR-1）。
//! 本体は G6（TASK-79〜98 の一部。crate の中核成果物は TASK-79〔基本コマンド〕・TASK-95〔エラー形式〕）で
//! 実装する。PLUG-1 区分は core（crate-naming.md）。

pub mod commands;
pub mod doctor;
pub mod error;
pub mod setup;
#[cfg(unix)]
pub mod signals;
#[cfg(unix)]
pub(crate) mod sys;
