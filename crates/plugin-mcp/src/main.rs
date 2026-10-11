//! バイナリ `fandhe-container-plugin-mcp` の入口（MCP サーバー plugin の参照実装。MCP-1・MCP-2。TASK-118・MS-4）。
//!
//! TASK-118.1（#464）で独立バイナリとしてビルドできるようにした雛形。MCP クライアントが stdio で
//! 起動するか、core が PLUG-4 の発見機構で起動するかは未確定のため、stdout は JSON-RPC の応答経路
//! として予約し何も書かない。診断は stderr に 1 行 JSON（`code` / `message`、英語）で出す。
//!
//! 引数なしで起動すると stdin の JSON-RPC 2.0（改行区切り）を EOF まで処理し、応答を stdout へ書く
//! （`initialize` / `tools/list` / `tools/call`。TASK-118.2・118.3。処理本体は lib の `server`）。診断は stderr のみ。
//!
//! 終了コード: stdin の EOF まで正常処理は 0、stdin 読み込み失敗・stdout 書き込み失敗・受信/送信の期限超過は 1
//! （`UNAVAILABLE`）、引数ありは 2（`INVALID_ARGUMENT`）。引数の値は出力へ埋め込まない。
//! 環境変数は本体では読まない（`list_containers` の状態ルート解決で core が `XDG_RUNTIME_DIR` を読む）。
//!
//! 未実装（REPAIR-3。TASK-118 の後続 sub で扱う）: `start_container` の本番起動（supervisor 起動の
//! adapter。#1718 待ちで、現状は `UNIMPLEMENTED` を `isError` で返す）、core との UDS 接続と peer 認証（PLUG-12。#467）、MCP-4 のエラー応答（ERR-5。#469・#470）。

use std::process::ExitCode;

const READ_FAILED_JSON: &str =
    "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to read request from stdin\"}";
const WRITE_FAILED_JSON: &str =
    "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to write response to stdout\"}";
const READ_TIMEOUT_JSON: &str =
    "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out reading request from stdin\"}";
const WRITE_TIMEOUT_JSON: &str =
    "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out writing response to stdout\"}";
const ENCODE_FAILED_JSON: &str =
    "{\"code\":\"INTERNAL\",\"message\":\"failed to encode response\"}";
const SPAWN_FAILED_JSON: &str =
    "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to spawn worker thread\"}";
const INVALID_ARGUMENT_JSON: &str =
    "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"unexpected argument\"}";

/// stderr へ 1 行書く。読まれない stderr で止まらないよう期限付きで書き、結果は無視する（REPAIR-5）。
fn stderr_line(line: &str) {
    fandhe_container_plugin_mcp::server::write_diagnostic(line);
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
    // 読み書きは serve 内の専用スレッドで行うため、'static な Stdin / Stdout を渡す（REPAIR-5）。
    match serve(std::io::BufReader::new(std::io::stdin()), std::io::stdout()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(ServeError::Read(_)) => {
            stderr_line(READ_FAILED_JSON);
            ExitCode::from(1)
        }
        Err(ServeError::Write(_)) => {
            stderr_line(WRITE_FAILED_JSON);
            ExitCode::from(1)
        }
        Err(ServeError::ReadTimeout) => {
            stderr_line(READ_TIMEOUT_JSON);
            ExitCode::from(1)
        }
        Err(ServeError::WriteTimeout) => {
            stderr_line(WRITE_TIMEOUT_JSON);
            ExitCode::from(1)
        }
        Err(ServeError::Spawn(_)) => {
            stderr_line(SPAWN_FAILED_JSON);
            ExitCode::from(1)
        }
        Err(ServeError::Encode) => {
            stderr_line(ENCODE_FAILED_JSON);
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
            READ_TIMEOUT_JSON,
            "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out reading request from stdin\"}"
        );
        assert_eq!(
            WRITE_TIMEOUT_JSON,
            "{\"code\":\"DEADLINE_EXCEEDED\",\"message\":\"timed out writing response to stdout\"}"
        );
        assert_eq!(
            ENCODE_FAILED_JSON,
            "{\"code\":\"INTERNAL\",\"message\":\"failed to encode response\"}"
        );
        assert_eq!(
            WRITE_FAILED_JSON,
            "{\"code\":\"UNAVAILABLE\",\"message\":\"failed to write response to stdout\"}"
        );
    }
}
