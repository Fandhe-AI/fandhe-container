//! WSL2 の検出・virtiofs マウント・9P フォールバック（スタブ。Windows のみ。WIN-1・WIN-2）。
//!
//! 将来の担当: WSL2 ディストリとバージョンの検出（TASK-67.3・#374）、virtiofs 共有マウントと
//! コンテナ実行の起動（TASK-67.4・#375）、9P へのフォールバックとエラー処理（TASK-67.5・#376）。
//! `wsl.exe` はシェルを介さず引数配列で起動し、タイムアウトを必ず付ける（REPAIR-5）。
//! `fandhe-container-plugin-windows`（TASK-116）から別プロセスとして呼ばれる。現状は未実装（REPAIR-3）。
