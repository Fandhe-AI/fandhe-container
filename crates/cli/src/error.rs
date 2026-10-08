//! CLI の構造化エラー型と stderr 出力（ERR-1・TASK-95.1・MS-6）。
//!
//! CLI がエラー終了する際に、機械可読な `code` と人が読める `message` を持つ 1 行 JSON を
//! stderr へ出し、`code` に対応する非ゼロ終了コードで終了するための型を提供する。
//! `main.rs` → `commands::run` → `CliExit` の終了経路の下位に置く型で、コード体系と終了コードは
//! core（`ErrorCode`・`exit_code_for`）を SSOT として再利用し、cli 独自の分類は持たない。
//!
//! `OciRuntimeError`（ERR-2。`op` 付きで OCI Runtime 操作の失敗を表す）とは役割が異なり、
//! 本型は操作種別を持たない CLI 全般向けの 2 フィールド（`code` / `message`）形式である。
//!
//! # 現状（REPAIR-3）
//!
//! 型と出力処理のみで、各コマンドのエラーパス（`CliExit`）への配線は TASK-95.2（#650）で行う。
//! 将来は ERR-4（JSON Lines 統一。TASK-98）の出力形式へ接続する。
//!
//! # 契約
//!
//! - `message` に資格情報・トークンを含めない（security.md）。
//! - `message` は untrusted な値（plugin 応答・OS エラー等）が混ざり得るため、構築時に core の
//!   `OciRuntimeError` と同じ規則でサニタイズする: Unicode 一般カテゴリ Cc（制御）・Cf（書式。
//!   双方向制御 U+202A〜U+202E・ゼロ幅文字等）・Zl / Zp（行区切り U+2028 / U+2029）を空白へ
//!   置換し、[`CLI_ERROR_MESSAGE_MAX_BYTES`] で打ち切る（行注入・端末制御・表示順の偽装を防ぐ）。
//!   判定表は core が SSOT で、cli に写しを持たない（`sanitize_bounded`）。
//! - 依存を増やさないため JSON は手で組む。キーは `code` → `message` の固定順・固定 2 個で、
//!   エスケープ関数は本モジュールの 1 か所に限る（`doctor.rs` の同種関数との共通化は後続課題）。

use std::fmt;
use std::io::Write;
use std::num::NonZeroU8;

use fandhe_container_core::oci_runtime::{
    LifecycleOp, OCI_ERROR_MESSAGE_MAX_BYTES, OciRuntimeError, exit_code_for,
};
use fandhe_container_core::traits::{ErrorCode, TraitError};

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
}

impl CliError {
    /// コードとメッセージから作る。`message` はサニタイズと上限切り詰めを施して保持する。
    pub fn new(code: ErrorCode, message: impl AsRef<str>) -> Self {
        Self {
            code,
            message: sanitize_bounded(message.as_ref()),
        }
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

    /// `{"code":"..","message":".."}` と LF からなる 1 行を返す。
    pub fn to_json_line(&self) -> String {
        let mut line = String::with_capacity(self.message.len() + 48);
        line.push_str("{\"code\":\"");
        line.push_str(self.code_str());
        line.push_str("\",\"message\":\"");
        json_escape_into(&mut line, &self.message);
        line.push_str("\"}\n");
        line
    }

    /// 1 行 JSON を `out`（通常は stderr）へ書く。
    ///
    /// 行全体のバイト列を `write_all` で全量書き込もうとするだけで、他プロセスの出力が行の途中に
    /// 混ざらない（不可分な書き込みである）ことは保証しない。部分書き込み時は複数回の write に
    /// 分かれ、エスケープ後の行は `PIPE_BUF`（4096）を超え得る。書き込みに失敗しても
    /// 呼び出し側は [`CliError::exit_code`] で終了する（終了コードは書き込み成否に依存しない）。
    pub fn write_stderr(&self, out: &mut dyn Write) -> std::io::Result<()> {
        out.write_all(self.to_json_line().as_bytes())
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
        Self::new(e.code(), e.message())
    }
}

impl From<&OciRuntimeError> for CliError {
    /// `op` は落として `code` / `message` を引き継ぐ。
    fn from(e: &OciRuntimeError) -> Self {
        Self::new(e.code(), e.message())
    }
}

/// 表示・行構造を乱す文字（Cc・Cf・Zl・Zp）を空白へ置換しつつ、UTF-8 文字境界で上限バイトに打ち切る。
///
/// 判定（Cf の範囲表を含む）は core の private 実装で、cli から直接は呼べない。写しを持つと
/// Unicode 版の更新で乖離するため、同じ規則を適用する公開入口 `OciRuntimeError::new` を通して
/// サニタイズ結果だけを取り出す。`op` は出力に使わないダミーで、`code` も結果に影響しない。
/// core 側は入力を借用のまま走査して上限で読み取りを止めるため、巨大な入力でも確保・走査は
/// [`CLI_ERROR_MESSAGE_MAX_BYTES`]（core の上限と同値）で頭打ちになる。
/// core がサニタイズ関数を公開したら直接呼び出しへ置き換える（runtime-builder 担当の後続課題）。
fn sanitize_bounded(input: &str) -> String {
    OciRuntimeError::new(LifecycleOp::Create, ErrorCode::Internal, input)
        .message()
        .to_owned()
}

/// JSON 文字列の中身として `s` を `out` へ追記する（`"`・`\`・0x20 未満をエスケープ）。
fn json_escape_into(out: &mut String, s: &str) {
    use std::fmt::Write as _;
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "{\"code\":\"NOT_FOUND\",\"message\":\"missing\"}\n"
        );
    }

    #[test]
    fn err1_json_escapes_quote_and_backslash() {
        let e = CliError::new(ErrorCode::InvalidArgument, "a\"b\\c");
        assert_eq!(
            e.to_json_line(),
            "{\"code\":\"INVALID_ARGUMENT\",\"message\":\"a\\\"b\\\\c\"}\n"
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
            "{\"code\":\"INTERNAL\",\"message\":\"a b c d e f g h\"}\n"
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
            "{\"code\":\"NOT_FOUND\",\"message\":\"no such\"}\n"
        );
    }

    #[test]
    fn err1_display_format() {
        let e = CliError::new(ErrorCode::NotFound, "missing");
        assert_eq!(e.to_string(), "NOT_FOUND: missing");
    }

    #[test]
    fn err1_json_escape_handles_low_control() {
        let mut s = String::new();
        json_escape_into(&mut s, "\u{1}\"\\\n");
        assert_eq!(s, "\\u0001\\\"\\\\\\n");
    }
}
