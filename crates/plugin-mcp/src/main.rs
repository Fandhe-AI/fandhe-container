//! バイナリ `fandhe-container-plugin-mcp` の入口（MCP サーバー plugin の参照実装。MCP-1・MCP-2）。
//!
//! TASK-118.1（#464）で独立バイナリとしてビルドできるようにした雛形。MCP クライアントが stdio で
//! 起動するか、core が PLUG-4 の発見機構で起動するかは未確定のため、stdout は JSON-RPC の応答経路
//! として予約し何も書かない。診断は stderr に 1 行 JSON（`code` / `message`、英語）で出す。
//!
//! 引数なしで起動すると stdin の JSON-RPC 2.0（改行区切り）を EOF まで処理し、応答を stdout へ書く
//! （`initialize` / `tools/list`。TASK-118.2・#465。処理本体は lib の `server`）。診断は stderr のみ。
//!
//! 終了コード: stdin の EOF まで正常処理は 0、stdin 読み込み失敗・stdout 書き込み失敗は 1
//! （`UNAVAILABLE`）、引数ありは 2（`INVALID_ARGUMENT`）。引数の値は出力へ埋め込まない。
//! 環境変数は読まない。
//!
//! 未実装（REPAIR-3。TASK-118 の後続 sub で扱う）: `tools/call`（#466）、
//! core との UDS 接続と peer 認証（PLUG-12。#467）、MCP-4 のエラー応答（ERR-5。#469・#470）。

use std::io::Write;
use std::process::ExitCode;

const READ_FAILED_JSON: &str =
    "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to read request from stdin\"}";
const WRITE_FAILED_JSON: &str =
    "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to write response to stdout\"}";
const INVALID_ARGUMENT_JSON: &str =
    "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"unexpected argument\"}";

/// stderr へ 1 行書く。壊れた stderr で panic しないよう書き込み結果は無視する。
fn stderr_line(line: &str) {
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// 引数ありの拒否（終了コード 2）。引数の値は診断へ埋め込まない（MCP-1・REPAIR-12）。
fn reject_args() -> ExitCode {
    stderr_line(INVALID_ARGUMENT_JSON);
    ExitCode::from(2)
}

fn main() -> ExitCode {
    use fandhe_container_plugin_mcp::server::{ServeError, serve};
    if std::env::args_os().nth(1).is_some() {
        return reject_args();
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match serve(stdin.lock(), stdout.lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(ServeError::Read(_)) => {
            stderr_line(READ_FAILED_JSON);
            ExitCode::from(1)
        }
        Err(ServeError::Write(_)) => {
            stderr_line(WRITE_FAILED_JSON);
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MCP-1・REPAIR-12: 診断 JSON は固定の具体値。
    #[test]
    fn diagnostics_are_fixed_json() {
        assert_eq!(
            INVALID_ARGUMENT_JSON,
            "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"unexpected argument\"}"
        );
        assert_eq!(
            READ_FAILED_JSON,
            "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to read request from stdin\"}"
        );
        assert_eq!(
            WRITE_FAILED_JSON,
            "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to write response to stdout\"}"
        );
    }
}
