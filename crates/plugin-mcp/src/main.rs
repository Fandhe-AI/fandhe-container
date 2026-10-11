//! バイナリ `fandhe-container-plugin-mcp` の入口（MCP サーバー plugin の参照実装。MCP-1・MCP-2）。
//!
//! TASK-118.1（#464）で独立バイナリとしてビルドできるようにした雛形。MCP クライアントが stdio で
//! 起動するか、core が PLUG-4 の発見機構で起動するかは未確定のため、stdout は JSON-RPC の応答経路
//! として予約し何も書かない。診断は stderr に 1 行 JSON（`code` / `message`、英語）で出す。
//!
//! 終了コード（暫定契約）: 引数なしは 1（`UNIMPLEMENTED`）、引数ありは 2（`INVALID_ARGUMENT`）。
//! 引数の値は出力へ埋め込まない。stdin・環境変数は読まない。
//!
//! 未実装（REPAIR-3。TASK-118 の後続 sub で扱う）: stdin の JSON-RPC 2.0 処理、
//! `initialize` / `tools/list` / `tools/call`、`list_containers` / `start_container`、
//! core との UDS 接続と peer 認証（PLUG-12）、MCP-4 のエラー応答（ERR-5）、引数・環境変数の契約。

use std::io::Write;
use std::process::ExitCode;

const UNIMPLEMENTED_JSON: &str =
    "{\"code\":\"UNIMPLEMENTED\",\"message\":\"mcp server is not implemented yet\"}";
const INVALID_ARGUMENT_JSON: &str =
    "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"unexpected argument\"}";

/// stderr へ 1 行書く。壊れた stderr で panic しないよう書き込み結果は無視する。
fn stderr_line(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some() {
        stderr_line(INVALID_ARGUMENT_JSON);
        return ExitCode::from(2);
    }
    stderr_line(UNIMPLEMENTED_JSON);
    ExitCode::from(1)
}
