//! 観測ログの `message` から除く「表示を乱す文字」の判定（ERR-1・ERR-2・REPAIR-1）。
//!
//! core の `sanitize` の判定表の写し。io は core に依存できない（crate 境界）ため複製する。
//! Unicode の版を上げるときは core と同時に再生成する。`observe` の JSON エスケープが、
//! DEL・C1・Cf・Zl・Zp・U+2065 を空白へ置換するために使う。

/// Unicode 一般カテゴリ Cf の範囲表（Unicode 16.0.0。昇順・重複なし・計 170 個。core と同一）。
pub(crate) const FORMAT_CHAR_RANGES: [(char, char); 21] = [
    ('\u{00AD}', '\u{00AD}'),
    ('\u{0600}', '\u{0605}'),
    ('\u{061C}', '\u{061C}'),
    ('\u{06DD}', '\u{06DD}'),
    ('\u{070F}', '\u{070F}'),
    ('\u{0890}', '\u{0891}'),
    ('\u{08E2}', '\u{08E2}'),
    ('\u{180E}', '\u{180E}'),
    ('\u{200B}', '\u{200F}'),
    ('\u{202A}', '\u{202E}'),
    ('\u{2060}', '\u{2064}'),
    ('\u{2066}', '\u{206F}'),
    ('\u{FEFF}', '\u{FEFF}'),
    ('\u{FFF9}', '\u{FFFB}'),
    ('\u{110BD}', '\u{110BD}'),
    ('\u{110CD}', '\u{110CD}'),
    ('\u{13430}', '\u{1343F}'),
    ('\u{1BCA0}', '\u{1BCA3}'),
    ('\u{1D173}', '\u{1D17A}'),
    ('\u{E0001}', '\u{E0001}'),
    ('\u{E0020}', '\u{E007F}'),
];

/// 表示・行構造を乱しうる文字か判定する（Cc・Cf・Zl・Zp と、将来の書式文字の予約 U+2065）。
/// 置換の形は呼び出し側（`observe::escape_json_string`）が決める。
pub(crate) fn is_display_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{2028}' | '\u{2029}' | '\u{2065}')
        || FORMAT_CHAR_RANGES
            .iter()
            .any(|&(lo, hi)| (lo..=hi).contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ERR-2: 範囲表は昇順・重複なしで合計 170 符号位置（core と同じ検査）。
    #[test]
    fn err2_format_char_table_is_sorted_disjoint_and_complete() {
        let mut total = 0u32;
        let mut prev_hi: Option<char> = None;
        for (lo, hi) in FORMAT_CHAR_RANGES {
            assert!(lo <= hi, "{lo:?}..={hi:?}");
            if let Some(p) = prev_hi {
                assert!(p < lo, "{p:?} overlaps {lo:?}");
            }
            prev_hi = Some(hi);
            total += u32::from(hi) - u32::from(lo) + 1;
        }
        assert_eq!(total, 170);
    }

    /// ERR-1: 代表文字の判定（core の判定表との一致を具体値で固定する）。
    #[test]
    fn err1_representative_chars_are_classified() {
        for c in [
            '\u{0}',
            '\u{1f}',
            '\u{7f}',
            '\u{85}',
            '\u{9f}',
            '\u{ad}',
            '\u{200b}',
            '\u{202e}',
            '\u{2028}',
            '\u{2029}',
            '\u{2065}',
            '\u{feff}',
            '\u{e0001}',
            '\u{e007f}',
        ] {
            assert!(is_display_unsafe_char(c), "{c:?}");
        }
        for c in ['a', 'é', '\u{301}', '\u{3164}', '\u{e000}', '\u{2070}'] {
            assert!(!is_display_unsafe_char(c), "{c:?}");
        }
    }
}
