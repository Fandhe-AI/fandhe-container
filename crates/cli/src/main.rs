//! バイナリ `fandhe-container` の入口（薄いラッパー。ロジックは lib 側の `fandhe_container_cli::commands`。TASK-79.1・CLI-1）。
//!
//! 終了コード: 0 は未使用（全コマンド未実装）、2 は使い方エラー、3 は未実装。
//! 失敗時は stderr へ英語 1 行 JSON（`code` / `message`）を出す。各コマンド本体は TASK-79.2.1〜79.4 で実装する。

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let exit = fandhe_container_cli::commands::run(std::env::args_os().skip(1));
    // stderr 書き込み失敗では panic しない。
    let _ = writeln!(std::io::stderr(), "{}", exit.to_json_line());
    ExitCode::from(exit.exit_code)
}
