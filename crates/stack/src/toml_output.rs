//! `ComposeToml` を TOML 文字列へ直列化し、往復検証を通ったものだけを返す入口（STACK-3・STACK-5・SEC-1。#3613）。
//!
//! 役割: `fandhe-container-compose-convert` の `entry`（変換結果を stdout へ書く段）から呼ばれる。
//! `toml` への依存を stack 側に閉じ込め、compose-convert の依存を増やさないための置き場である。
//! 直列化した文字列を同じスキーマで読み戻し、変換直後の値と等しいときだけ `Ok` を返す（fail-closed）。
//!
//! 契約:
//! - 読み戻すのは自分で直列化した文字列だけで、外部入力の parse 入口ではない。外部入力を読む公開入口
//!   （入力サイズの上限つき）は #3639 の担当で、本モジュールは兼ねない。
//! - エラーは値を持たない固定の分類だけを返す。`toml` のエラー本文は env の値などを含みうるため
//!   保持も表示もしない（SEC-1）。

use crate::schema::ComposeToml;
use crate::toml_input::{TomlInputError, parse_compose_toml};

/// 直列化または往復検証の失敗。値（env・秘密など）は持たない（SEC-1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TomlOutputError {
    /// TOML への直列化に失敗した。
    Serialize,
    /// 直列化した文字列がスキーマで読み戻せなかった。
    Reparse,
    /// 読み戻した値が元の値と一致しなかった。
    RoundtripMismatch,
    /// 直列化した文字列が入力側の上限（`MAX_STACK_TOML_BYTES`）を超えた。
    /// stack の公開入力関数が拒否する成果物を成功として返さないための分類。
    TooLarge,
}

impl TomlOutputError {
    /// 機械可読な固定の分類名。
    pub fn code(self) -> &'static str {
        match self {
            Self::Serialize => "serialize-failed",
            Self::Reparse => "reparse-failed",
            Self::RoundtripMismatch => "roundtrip-mismatch",
            Self::TooLarge => "too-large",
        }
    }
}

/// `doc` を TOML に直列化し、読み戻して `doc` と等しいことを確かめてから返す（STACK-5）。
pub fn to_verified_toml_string(doc: &ComposeToml) -> Result<String, TomlOutputError> {
    let text = toml::to_string(doc).map_err(|_| TomlOutputError::Serialize)?;
    check_roundtrip(doc, &text)?;
    Ok(text)
}

/// `text` をスキーマで読み戻して `doc` と比べる。
fn check_roundtrip(doc: &ComposeToml, text: &str) -> Result<(), TomlOutputError> {
    // 公開入力関数と同じ経路で読み戻し、サイズ上限も読み込み側の契約と一致させる。
    let rt = parse_compose_toml(text).map_err(|e| match e {
        TomlInputError::TooLarge => TomlOutputError::TooLarge,
        _ => TomlOutputError::Reparse,
    })?;
    if rt == *doc {
        Ok(())
    } else {
        Err(TomlOutputError::RoundtripMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = include_str!("../testdata/schema_roundtrip_full.toml");

    /// STACK-5: 全フィールドの文書が往復検証を通り、`toml::to_string` と同じ文字列になる。
    #[test]
    fn full_document_roundtrips() {
        let doc: ComposeToml = toml::from_str(FULL).expect("fixture parses");
        let text = to_verified_toml_string(&doc).expect("verified");
        assert_eq!(text, toml::to_string(&doc).expect("to_string"));
        assert_eq!(toml::from_str::<ComposeToml>(&text).expect("reparse"), doc);
    }

    /// STACK-5: 空の文書は空文字列。
    #[test]
    fn default_document_is_empty() {
        assert_eq!(
            to_verified_toml_string(&ComposeToml::default()),
            Ok(String::new())
        );
    }

    /// STACK-5: 別の文書の TOML は不一致として拒否する。
    #[test]
    fn mismatch_is_rejected() {
        let doc: ComposeToml = toml::from_str(FULL).expect("fixture parses");
        assert_eq!(
            check_roundtrip(
                &ComposeToml::default(),
                &toml::to_string(&doc).expect("ser")
            ),
            Err(TomlOutputError::RoundtripMismatch)
        );
    }

    /// STACK-5: スキーマで読めない文字列は Reparse。
    #[test]
    fn unparsable_text_is_rejected() {
        assert_eq!(
            check_roundtrip(&ComposeToml::default(), "unknown_key = 1\n"),
            Err(TomlOutputError::Reparse)
        );
    }

    /// STACK-5: 入力側の上限を超える出力は TooLarge で拒否する（往復検証と読み込み側の契約の一致）。
    #[test]
    fn oversized_output_is_rejected_as_too_large() {
        let big = "a".repeat(crate::toml_input::MAX_STACK_TOML_BYTES);
        let text = format!("# {big}\n");
        assert!(text.len() > crate::toml_input::MAX_STACK_TOML_BYTES);
        assert_eq!(
            check_roundtrip(&ComposeToml::default(), &text),
            Err(TomlOutputError::TooLarge)
        );
        assert_eq!(TomlOutputError::TooLarge.code(), "too-large");
    }

    /// SEC-1: コードは固定文字列で、Debug に値が出ない。
    #[test]
    fn codes_are_fixed_and_debug_has_no_values() {
        assert_eq!(TomlOutputError::Serialize.code(), "serialize-failed");
        assert_eq!(TomlOutputError::Reparse.code(), "reparse-failed");
        assert_eq!(
            TomlOutputError::RoundtripMismatch.code(),
            "roundtrip-mismatch"
        );
        assert_eq!(format!("{:?}", TomlOutputError::Reparse), "Reparse");
    }
}
