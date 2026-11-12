//! 外部入力の TOML を [`ComposeToml`] へ読む公開の入口（STACK-1・CLI-4・SEC-1）。
//!
//! 呼び出し元は CLI の `up` 等（結線は #3639 で未実装。`cli -> stack` の依存辺はユーザー承認待ち）。
//! 入力サイズの上限を確保の前に検査し（無制限確保による DoS を防ぐ）、UTF-8 を検証してから
//! `toml` へ渡す。`toml` のエラー本文は入力の断片（`env` の値など）を含みうるため、保持も表示もしない。
//! ファイルを開く処理（パス・期限）は結線側の責務で、本モジュールは `Read` を受ける。

use std::fmt;
use std::io::Read;

use crate::schema::ComposeToml;

/// 受け付ける入力の最大バイト数（compose-convert の入力上限と揃え、変換結果を受けられる大きさ）。
pub const MAX_STACK_TOML_BYTES: usize = 4 * 1024 * 1024;

/// TOML 入力の失敗。固定の分類だけを持ち、入力の内容は運ばない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TomlInputError {
    /// 入力が [`MAX_STACK_TOML_BYTES`] を超えた。
    TooLarge,
    /// UTF-8 ではない。
    NotUtf8,
    /// 読み取りに失敗した。
    Io,
    /// TOML の文法またはスキーマ（未知のキー・型の不一致）の誤り。
    Syntax,
}

impl TomlInputError {
    /// 機械可読なエラーコード。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io => "INTERNAL",
            _ => "INVALID_ARGUMENT",
        }
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        match self {
            Self::TooLarge => "stack file exceeds the size limit",
            Self::NotUtf8 => "stack file is not valid UTF-8",
            Self::Io => "failed to read the stack file",
            Self::Syntax => "stack file is not a valid stack definition",
        }
    }

    /// 終了コード（ERR-2 の表: INVALID_ARGUMENT は 2、INTERNAL は 1）。
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Io => 1,
            _ => 2,
        }
    }
}

impl fmt::Display for TomlInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for TomlInputError {}

/// 文字列の TOML を読む。長さを先に検査する。
pub fn parse_compose_toml(text: &str) -> Result<ComposeToml, TomlInputError> {
    if text.len() > MAX_STACK_TOML_BYTES {
        return Err(TomlInputError::TooLarge);
    }
    toml::from_str(text).map_err(|_| TomlInputError::Syntax)
}

/// `reader` から上限 + 1 バイトまでだけ読み、TOML として解析する。
pub fn read_compose_toml<R: Read>(reader: R) -> Result<ComposeToml, TomlInputError> {
    let mut buf = Vec::new();
    let limit = (MAX_STACK_TOML_BYTES as u64) + 1;
    reader
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|_| TomlInputError::Io)?;
    if buf.len() > MAX_STACK_TOML_BYTES {
        return Err(TomlInputError::TooLarge);
    }
    let text = String::from_utf8(buf).map_err(|_| TomlInputError::NotUtf8)?;
    parse_compose_toml(&text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const FULL: &str = include_str!("../testdata/schema_roundtrip_full.toml");

    /// 常に失敗する reader。
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("boom"))
        }
    }

    /// 指定長の有効な TOML（末尾をコメントで埋める）。
    fn padded(len: usize) -> String {
        let mut s = String::from("[services.a]\nimage = \"x\"\n#");
        while s.len() < len {
            s.push('x');
        }
        s
    }

    #[test]
    fn stack1_reads_full_fixture() {
        let parsed = parse_compose_toml(FULL).expect("fixture parses");
        assert!(!parsed.services.is_empty());
        assert!(read_compose_toml(Cursor::new(FULL.as_bytes())).is_ok());
    }

    #[test]
    fn sec1_limit_boundary() {
        let at = padded(MAX_STACK_TOML_BYTES);
        assert_eq!(at.len(), MAX_STACK_TOML_BYTES);
        assert!(parse_compose_toml(&at).is_ok());
        assert!(read_compose_toml(Cursor::new(at.as_bytes())).is_ok());
        let over = padded(MAX_STACK_TOML_BYTES + 1);
        assert_eq!(parse_compose_toml(&over), Err(TomlInputError::TooLarge));
        assert_eq!(
            read_compose_toml(Cursor::new(over.as_bytes())),
            Err(TomlInputError::TooLarge)
        );
    }

    #[test]
    fn sec1_invalid_utf8_and_io() {
        assert_eq!(
            read_compose_toml(Cursor::new(vec![0xff, 0xfe])),
            Err(TomlInputError::NotUtf8)
        );
        assert_eq!(read_compose_toml(Failing), Err(TomlInputError::Io));
    }

    #[test]
    fn sec1_syntax_error_hides_input() {
        let secret = "s3cr3t-value";
        for text in [
            format!("[services.a]\nenv = {{ K = \"{secret}\" \n"),
            format!("[services.a]\nunknown_key = \"{secret}\"\n"),
        ] {
            let err = parse_compose_toml(&text).expect_err("rejects");
            assert_eq!(err, TomlInputError::Syntax);
            assert!(!format!("{err} {err:?}").contains(secret));
        }
        assert_eq!(TomlInputError::Syntax.exit_code(), 2);
        assert_eq!(TomlInputError::Io.exit_code(), 1);
        assert_eq!(TomlInputError::Io.code(), "INTERNAL");
    }

    #[test]
    fn sec1_deep_nesting_is_rejected_without_panic() {
        let depth = 50_000;
        let text = format!(
            "[services.a]\nimage = {}{}\n",
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert_eq!(parse_compose_toml(&text), Err(TomlInputError::Syntax));
    }
}
