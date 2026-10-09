//! cli 内で手組みする JSON 文字列のエスケープの唯一の実装（ERR-1・NET-10・REPAIR-1）。
//!
//! `error` モジュール（`CliError::to_json_line`）と `doctor` モジュール（JSON Lines 出力）が共用する。
//! 依存を増やさないため cli は JSON を手で組む方針で、エスケープ規則を 1 か所に置いて
//! 修正の波及先を減らす。crate 外へは公開しない。

use std::fmt::Write as _;

/// JSON 文字列の中身として `s` を `out` へ追記する（`"`・`\`・0x20 未満をエスケープ）。
pub(crate) fn json_escape_into(out: &mut String, s: &str) {
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

/// [`json_escape_into`] の新規 `String` を返す版（doctor の `format!` 組み立て用）。
pub(crate) fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    json_escape_into(&mut out, s);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net10_json_escape() {
        assert_eq!(json_escape("a\"b\\c\nd\u{1}"), "a\\\"b\\\\c\\nd\\u0001");
    }

    #[test]
    fn err1_json_escape_handles_low_control() {
        let mut s = String::new();
        json_escape_into(&mut s, "\u{1}\"\\\n");
        assert_eq!(s, "\\u0001\\\"\\\\\\n");
    }

    #[test]
    fn err1_json_escape_cr_tab_and_non_ascii() {
        assert_eq!(json_escape("\r\t\u{1f}é"), "\\r\\t\\u001fé");
        let mut s = String::from("x");
        json_escape_into(&mut s, "\r");
        assert_eq!(s, "x\\r");
    }
}
