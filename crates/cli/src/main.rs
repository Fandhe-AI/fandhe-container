//! バイナリ `fandhe-container` の入口（薄いラッパー。ロジックは lib 側の `fandhe_container_cli::commands`。TASK-79.1・TASK-79.2.1・CLI-1・MS-6）。
//!
//! 終了コードは core の ERR-2 表に従う: 0 は成功（出力なし。`list` のみ stdout へ一覧を出す）、2 は使い方エラー・不正引数、
//! 3 は対象なし、8 は未実装など。本番の launcher が未提供のため `start` は成功せず 8 を返す。
//! 失敗時は stderr へ英語 1 行 JSON（`code` / `message`。core 由来は `op` も）を出す。

use std::process::ExitCode;

fn main() -> ExitCode {
    let exit = fandhe_container_cli::commands::run(std::env::args_os().skip(1));
    // stderr 書き込み失敗では panic せず、終了コードは書き込みの成否に依存させない。
    let _ = exit.write_stderr(&mut std::io::stderr());
    ExitCode::from(exit.exit_code())
}
