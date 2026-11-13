//! CLI の構造化エラー型と stderr 出力（ERR-1・TASK-95.1・MS-6）。
//!
//! CLI がエラー終了する際に、機械可読な `code` と人が読める `message` を持つ 1 行 JSON を
//! core の共通ログ型 `LogLine`（ERR-4・#3120）で組んで stderr へ出し、`code` に対応する非ゼロ終了コードで終了するための型を提供する。
//! `main.rs` → `commands::run` → `CliExit` の終了経路の下位に置く型で、コード体系と終了コードは
//! core（`ErrorCode`・`exit_code_for`）を SSOT として再利用し、cli 独自の分類は持たない。
//!
//! `OciRuntimeError`（ERR-2。`op` 付きで OCI Runtime 操作の失敗を表す）とは役割が異なり、
//! 本型は操作種別を持たない CLI 全般向けの形式である。行の形は OCI エラー行（`oci_runtime_error`）と
//! 揃え、`{"level":"error","event":"cli_error","code":..,"message":..[,"truncated":true]}` とする
//! （`truncated` は `message` を上限で切り詰めたときだけ付く）。
//!
//! # 現状（REPAIR-3）
//!
//! 各コマンドのエラーパス（`CliExit::Error`）へ配線済み（TASK-95.2・#650）。ライフサイクル操作の失敗
//! （`CliExit::Runtime`）は ERR-2 の `op` 付き形式を保つ。
//! ERR-4（JSON Lines 統一。TASK-98.2・#3120）の出力形式へ接続済み。stderr のログ行を新しく足すときは
//! `{"code"` を手で組まず、本型（または core の `LogLine` + `LogFields`）を通す。
//!
//! # 契約
//!
//! - `message` に資格情報・トークンを含めない（security.md）。
//! - `message` は untrusted な値（plugin 応答・OS エラー等）が混ざり得るため、構築時に core の
//!   `OciRuntimeError` と同じ規則でサニタイズする: Unicode 一般カテゴリ Cc（制御）・Cf（書式。
//!   双方向制御 U+202A〜U+202E・ゼロ幅文字等）・Zl / Zp（行区切り U+2028 / U+2029）を空白へ
//!   置換し、[`CLI_ERROR_MESSAGE_MAX_BYTES`] で打ち切る（行注入・端末制御・表示順の偽装を防ぐ）。
//!   判定表は core が SSOT で、cli に写しを持たず、core の公開 API `sanitize_display_bounded` を直接呼ぶ。
//! - 依存を増やさないため（cli は `serde` を直接依存に持たない）、本体は core の `LogFields`
//!   （順序つきのキーと値）で渡し、エスケープと 1 行の保証は core の `encode_json_line` に任せる。
//!   cli 共通の `json` モジュールは stdout のデータ出力（doctor・setup）専用である。

use std::fmt;
use std::io::Write;
use std::num::NonZeroU8;

use fandhe_container_core::logging::{
    LogEvent, LogFields, LogLevel, LogLine, LogValue, encode_json_line,
};
use fandhe_container_core::oci_runtime::{
    OCI_ERROR_MESSAGE_MAX_BYTES, OciRuntimeError, exit_code_for,
};
use fandhe_container_core::sanitize::sanitize_display_bounded;
use fandhe_container_core::traits::{ErrorCode, TraitError};

/// エラー行の event 名（コンパイル時に検証する）。
const CLI_ERROR_EVENT: LogEvent = match LogEvent::from_static("cli_error") {
    Some(e) => e,
    None => panic!("invalid log event name"),
};

/// [`CliError`] が保持する `message` の最大バイト数。core の OCI エラーの上限と同値。
pub const CLI_ERROR_MESSAGE_MAX_BYTES: usize = OCI_ERROR_MESSAGE_MAX_BYTES;

/// 構造化された CLI エラー（ERR-1）。`code` は機械可読、`message` は人間可読。
///
/// フィールドは private で、構築は [`CliError::new`] / `From` のみ。終了コードは
/// `NonZeroU8` 由来のため 0 になり得ない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    code: ErrorCode,
    message: String,
    /// `message` を上限（または `TraitError` / `OciRuntimeError` の上限）で切り詰めたか。
    message_truncated: bool,
}

impl CliError {
    /// コードとメッセージから作る。`message` はサニタイズと上限切り詰めを施して保持する。
    pub fn new(code: ErrorCode, message: impl AsRef<str>) -> Self {
        let sanitized = sanitize_display_bounded(message.as_ref(), CLI_ERROR_MESSAGE_MAX_BYTES);
        let message_truncated = sanitized.is_truncated();
        Self {
            code,
            message: sanitized.into_string(),
            message_truncated,
        }
    }

    /// `message` が上限で切り詰められたか。出力行の `truncated` キーの有無を決める。
    pub fn message_truncated(&self) -> bool {
        self.message_truncated
    }

    /// 機械可読なエラーコード。
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    /// ERR-1 の文字列表現（例: `NOT_FOUND`）。
    pub fn code_str(&self) -> &'static str {
        self.code.as_str()
    }

    /// 人間可読なメッセージ（サニタイズ済み）。
    pub fn message(&self) -> &str {
        &self.message
    }

    /// `code` に対応する非ゼロの終了コード（ERR-2 の対応表。core の `exit_code_for`）。
    pub fn exit_code(&self) -> NonZeroU8 {
        exit_code_for(self.code)
    }

    /// LF 終端のログ行のバイト列を作る（`level` → `event` → `code` → `message` → [`truncated`]）。
    ///
    /// 符号化に失敗した場合は何も書かせないため `None`。`message` は 4096 バイト以下で
    /// サニタイズ済みなので実際には到達しない。
    fn encode_line(&self) -> Option<Vec<u8>> {
        let mut entries: Vec<(&'static str, LogValue<'_>)> = vec![
            ("code", LogValue::Str(self.code_str())),
            ("message", LogValue::Str(&self.message)),
        ];
        if self.message_truncated {
            entries.push(("truncated", LogValue::Bool(true)));
        }
        let fields = LogFields::new(&entries);
        encode_json_line(&LogLine::new(CLI_ERROR_EVENT, &fields).with_level(LogLevel::Error)).ok()
    }

    /// LF で終わる 1 行の JSON 文字列を返す（例: `{"level":"error","event":"cli_error","code":"NOT_FOUND","message":"x"}`）。
    ///
    /// 符号化に失敗したときは、同じ `code` と固定の文言 `error line could not be encoded` で組み直し、
    /// それも失敗したら空文字列を返す（実際には `message` の上限により到達しない）。
    pub fn to_json_line(&self) -> String {
        if let Some(b) = self.encode_line().and_then(|b| String::from_utf8(b).ok()) {
            return b;
        }
        let entries = [
            ("code", LogValue::Str(self.code_str())),
            ("message", LogValue::Str("error line could not be encoded")),
        ];
        let fields = LogFields::new(&entries);
        encode_json_line(&LogLine::new(CLI_ERROR_EVENT, &fields).with_level(LogLevel::Error))
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_default()
    }

    /// 1 行 JSON を `out`（通常は stderr）へ書く。
    ///
    /// 行全体のバイト列を `write_all` 1 回で全量書き込もうとするだけで、他プロセスの出力が行の途中に
    /// 混ざらない（不可分な書き込みである）ことは保証しない。符号化に失敗したら何も書かず
    /// `InvalidData` を返す。書き込みに失敗しても呼び出し側は [`CliError::exit_code`] で終了する
    /// （終了コードは書き込み成否に依存しない）。
    pub fn write_stderr(&self, out: &mut dyn Write) -> std::io::Result<()> {
        match self.encode_line() {
            Some(b) => out.write_all(&b),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "error line could not be encoded",
            )),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code_str(), self.message)
    }
}

impl std::error::Error for CliError {}

impl From<TraitError> for CliError {
    fn from(e: TraitError) -> Self {
        let mut c = Self::new(e.code(), e.message());
        c.message_truncated |= e.message_truncated();
        c
    }
}

impl From<&OciRuntimeError> for CliError {
    /// `op` は落として `code` / `message` を引き継ぐ。
    fn from(e: &OciRuntimeError) -> Self {
        let mut c = Self::new(e.code(), e.message());
        c.message_truncated |= e.message_truncated();
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::oci_runtime::LifecycleOp;

    #[test]
    fn err1_fields_are_kept() {
        let e = CliError::new(ErrorCode::NotFound, "missing");
        assert_eq!(e.code(), ErrorCode::NotFound);
        assert_eq!(e.code_str(), "NOT_FOUND");
        assert_eq!(e.message(), "missing");
    }

    #[test]
    fn err1_exit_codes_are_nonzero_and_match_table() {
        let table = [
            (ErrorCode::InvalidArgument, 2),
            (ErrorCode::NotFound, 3),
            (ErrorCode::AlreadyExists, 4),
            (ErrorCode::FailedPrecondition, 5),
            (ErrorCode::Unimplemented, 8),
            (ErrorCode::Internal, 1),
            (ErrorCode::PermissionDenied, 6),
            (ErrorCode::Timeout, 7),
            (ErrorCode::Unavailable, 9),
        ];
        for (code, want) in table {
            assert_eq!(CliError::new(code, "x").exit_code().get(), want);
        }
    }

    #[test]
    fn err1_json_line_exact() {
        let e = CliError::new(ErrorCode::NotFound, "missing");
        assert_eq!(
            e.to_json_line(),
            "{\"level\":\"error\",\"event\":\"cli_error\",\"code\":\"NOT_FOUND\",\"message\":\"missing\"}\n"
        );
    }

    #[test]
    fn err1_json_escapes_quote_and_backslash() {
        let e = CliError::new(ErrorCode::InvalidArgument, "a\"b\\c");
        assert_eq!(
            e.to_json_line(),
            "{\"level\":\"error\",\"event\":\"cli_error\",\"code\":\"INVALID_ARGUMENT\",\"message\":\"a\\\"b\\\\c\"}\n"
        );
    }

    #[test]
    fn err1_control_and_separators_become_spaces() {
        let e = CliError::new(ErrorCode::Internal, "a\nb\rc\td\u{1b}e\u{2028}f\u{2029}g");
        assert_eq!(e.message(), "a b c d e f g");
        let line = e.to_json_line();
        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.ends_with("\"}\n"));
    }

    /// ERR-1: 双方向制御・ゼロ幅等の書式文字（Cf）も空白へ置換される（表示順の偽装を防ぐ）。
    #[test]
    fn err1_format_chars_become_spaces() {
        let e = CliError::new(
            ErrorCode::Internal,
            "a\u{202E}b\u{2066}c\u{2069}d\u{200F}e\u{061C}f\u{FEFF}g\u{200B}h",
        );
        assert_eq!(e.message(), "a b c d e f g h");
        assert_eq!(
            e.to_json_line(),
            "{\"level\":\"error\",\"event\":\"cli_error\",\"code\":\"INTERNAL\",\"message\":\"a b c d e f g h\"}\n"
        );
        // 変換経路（untrusted な TraitError の message）でも同じ規則になる。
        let t = CliError::from(TraitError::new(ErrorCode::NotFound, "x\u{202E}gpj.exe"));
        assert_eq!(t.message(), "x gpj.exe");
    }

    #[test]
    fn err1_message_is_truncated_at_char_boundary() {
        let e = CliError::new(ErrorCode::Internal, "a".repeat(10_000));
        assert_eq!(e.message().len(), CLI_ERROR_MESSAGE_MAX_BYTES);
        // 3 バイト文字が境界をまたぐ長さ（4096 は 3 の倍数でない）。
        let e = CliError::new(ErrorCode::Internal, "あ".repeat(5_000));
        assert_eq!(e.message().len(), 4095);
        assert_eq!(e.message().chars().count(), 1365);
    }

    #[test]
    fn err1_write_stderr_writes_all_bytes_even_when_partial() {
        // 1 回の write で 3 バイトしか受け付けない出力先でも全バイトが書かれる。
        struct Partial {
            buf: Vec<u8>,
        }
        impl Write for Partial {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                let n = b.len().min(3);
                self.buf.extend_from_slice(&b[..n]);
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let e = CliError::new(ErrorCode::NotFound, "missing");
        let mut w = Partial { buf: Vec::new() };
        e.write_stderr(&mut w).unwrap();
        assert_eq!(w.buf, e.to_json_line().into_bytes());
    }

    #[test]
    fn err1_write_failure_keeps_exit_code() {
        struct Failing;
        impl Write for Failing {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("closed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let e = CliError::new(ErrorCode::Timeout, "slow");
        assert!(e.write_stderr(&mut Failing).is_err());
        assert_eq!(e.exit_code().get(), 7);
    }

    #[test]
    fn err1_conversions_keep_code_and_message() {
        let t = CliError::from(TraitError::new(ErrorCode::Unavailable, "gone"));
        assert_eq!(t.code(), ErrorCode::Unavailable);
        assert_eq!(t.message(), "gone");

        let o = OciRuntimeError::new(LifecycleOp::Start, ErrorCode::NotFound, "no such");
        let c = CliError::from(&o);
        assert_eq!(
            c.to_json_line(),
            "{\"level\":\"error\",\"event\":\"cli_error\",\"code\":\"NOT_FOUND\",\"message\":\"no such\"}\n"
        );
    }

    /// ERR-4: 切り詰めたときだけ `truncated:true` が付き、ちょうど上限では付かない。
    #[test]
    fn err4_truncated_marker_only_when_cut() {
        let over = CliError::new(
            ErrorCode::Internal,
            "a".repeat(CLI_ERROR_MESSAGE_MAX_BYTES + 1),
        );
        assert!(over.message_truncated());
        assert!(over.to_json_line().ends_with("\",\"truncated\":true}\n"));
        let exact = CliError::new(ErrorCode::Internal, "a".repeat(CLI_ERROR_MESSAGE_MAX_BYTES));
        assert!(!exact.message_truncated());
        assert!(!exact.to_json_line().contains("truncated"));
    }

    /// ERR-4: 変換経路が切り詰めの印を引き継ぐ。
    #[test]
    fn err4_conversions_carry_truncation() {
        let o = OciRuntimeError::new(
            LifecycleOp::Start,
            ErrorCode::Internal,
            "a".repeat(CLI_ERROR_MESSAGE_MAX_BYTES + 5),
        );
        assert!(CliError::from(&o).message_truncated());
        let t = TraitError::new(ErrorCode::Internal, "a".repeat(100_000));
        assert!(CliError::from(t).message_truncated());
    }

    /// ERR-4: 全バイトがエスケープされる最悪の message でも 1 行で上限内に収まる。
    #[test]
    fn err4_worst_case_escape_fits_one_line() {
        let e = CliError::new(
            ErrorCode::Internal,
            "\"".repeat(CLI_ERROR_MESSAGE_MAX_BYTES),
        );
        let line = e.to_json_line();
        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.len() <= fandhe_container_core::logging::MAX_LOG_LINE_BYTES + 1);
        assert!(line.len() > 2 * CLI_ERROR_MESSAGE_MAX_BYTES);
    }

    /// ERR-4: OCI エラー行と同じ形（level → event → code → message → truncated）。
    #[test]
    fn err4_shape_matches_oci_error_line() {
        for msg in ["boom", "q\"x"] {
            let o = OciRuntimeError::new(LifecycleOp::Start, ErrorCode::NotFound, msg);
            let mut buf = Vec::new();
            o.write_json_line(&mut buf).unwrap();
            let oci = String::from_utf8(buf).unwrap();
            let cli = CliError::from(&o).to_json_line();
            let tail = |l: &str| l.split_once("\"code\"").unwrap().1.to_string();
            assert!(oci.starts_with("{\"level\":\"error\",\"event\":\"oci_runtime_error\""));
            assert!(cli.starts_with("{\"level\":\"error\",\"event\":\"cli_error\""));
            assert_eq!(tail(&oci), tail(&cli));
        }
    }

    #[test]
    fn err1_display_format() {
        let e = CliError::new(ErrorCode::NotFound, "missing");
        assert_eq!(e.to_string(), "NOT_FOUND: missing");
    }
}
