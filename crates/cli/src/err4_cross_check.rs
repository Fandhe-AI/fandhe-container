//! cli の stderr のエラー行（`cli_error`）を「1 行 1 JSON」の共有検査器で横断照合する（ERR-4・#3122）。
//!
//! TASK-98 の受け入れ条件 2（#653）の照合先のうち cli 分。core・io・plugin の分は各 crate の
//! `err4_cross_check` が同じ検査器（`crates/plugin/tests/support/json_lines_contract.rs`）で行う。
//! 警告行は `commands::stop_delete`・`create_pasta`・`plugin_backend` の各試験が、非公開の書き出し口に
//! 同じ検査器を当てる。実バイナリの stderr は `tests/binary_entry.rs` が照合する。
//! 対象外: stdout のデータ出力（`list`・`inspect` 等。ログ行ではない）。

use crate::error::CliError;
use crate::json_lines_contract::{HOSTILE_TEXT, SHARED_MAX_LOG_LINE_BYTES, check_stream};
use fandhe_container_core::traits::ErrorCode;

const HOSTILE_SANITIZED: &str = "a b c d e [31mf g h i j k l m\"n\\oあ";

/// ERR-4・#3122: 敵対的な message は空白へ置換され、`truncated` は出ない。
#[test]
fn err4_3122_cli_error_hostile_message() {
    let e = CliError::new(ErrorCode::InvalidArgument, HOSTILE_TEXT);
    let mut buf = Vec::new();
    e.write_stderr(&mut buf).unwrap();
    assert_eq!(buf, e.to_json_line().into_bytes());
    let f = &check_stream(&buf, SHARED_MAX_LOG_LINE_BYTES).unwrap()[0];
    assert_eq!(f.level.as_deref(), Some("error"));
    assert_eq!(f.event, "cli_error");
    assert_eq!(f.keys_vec(), ["level", "event", "code", "message"]);
    assert_eq!(f.str_of("code"), Some("INVALID_ARGUMENT"));
    assert_eq!(f.str_of("message"), Some(HOSTILE_SANITIZED));
    assert_eq!(f.bool_of("truncated"), None);
}

/// ERR-4・#3122: 最大長（4096 バイト）と上限超過（切り詰め）。
#[test]
fn err4_3122_cli_error_max_and_truncated() {
    let e = CliError::new(ErrorCode::Internal, "\"".repeat(4096));
    let line = e.to_json_line();
    let f = &check_stream(line.as_bytes(), SHARED_MAX_LOG_LINE_BYTES).unwrap()[0];
    assert_eq!(f.str_of("message").map(str::len), Some(4096));
    assert_eq!(f.bool_of("truncated"), None);

    let e = CliError::new(ErrorCode::Internal, "\n".repeat(9000));
    let line = e.to_json_line();
    let f = &check_stream(line.as_bytes(), SHARED_MAX_LOG_LINE_BYTES).unwrap()[0];
    assert_eq!(f.bool_of("truncated"), Some(true));
    assert!(f.str_of("message").unwrap().chars().all(|c| c == ' '));
}
