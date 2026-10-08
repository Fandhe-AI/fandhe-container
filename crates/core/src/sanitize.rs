//! 表示を乱す文字の判定と有界追記（crate 内でただ 1 つの実装）。
//!
//! 外部由来（plugin 応答・ヘルパーの stderr・パス）の文字列をログ・エラーメッセージ・監査記録へ
//! 入れる前に、Unicode 一般カテゴリ Cc・Cf・Zl・Zp の文字を判定する。利用者は
//! `oci_runtime::error`（空白へ置換）・`rootless`（除去）・`exec::violation`（`escape_default`
//! 形式でエスケープ）。置換の形は呼び出し側が決め、本モジュールは判定と有界追記だけを持つ
//! （ERR-2・SEC-4・REPAIR-4・TASK-96.1）。

/// Unicode 一般カテゴリ Cf（Format）に属する符号位置の範囲（Unicode 16.0.0。昇順・重複なし・計 170 個）。
///
/// std は一般カテゴリを公開せず、依存も追加しないため、UnicodeData.txt の Cf を範囲表として持つ。
/// 個々の文字を選んで列挙したものではなく、カテゴリ全体の写しである（双方向制御 U+202A〜U+202E・
/// U+2066〜U+2069、ゼロ幅文字 U+200B〜U+200F、WORD JOINER U+2060、BOM U+FEFF、タグ文字 U+E0020〜
/// U+E007F 等を含む）。Unicode の版を上げる際は表ごと再生成する。
///
/// 本表は Unicode 16.0.0 に基づく。Unicode 17.0.0 の Cf 表とは照合していない（未照合）。
/// 版を上げるときは UnicodeData.txt から表ごと再生成して照合する。
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

/// `message` に残すと表示・行構造を乱しうる文字か判定する。
///
/// 規則は Unicode 一般カテゴリで定める: Cc（制御。`char::is_control()`）・Cf（書式。
/// [`FORMAT_CHAR_RANGES`]）・Zl（行区切り U+2028）・Zp（段落区切り U+2029）。改行・ESC による
/// 行注入・端末制御、双方向制御による表示順の偽装、ゼロ幅文字による不可視の挿入を防ぐ。
///
/// 加えて U+2065 も置換する。現行では未割り当て（Cn）だが、書式文字ブロック U+2060〜U+206F の
/// 内側に予約された符号位置で、将来 Cf として割り当てられうるため、ブロック全体を閉じておく
/// （fail-closed）。
///
/// 対象外（意図的）: Mn 等の結合文字（多くの文字体系の正当な表記に必須）、U+3164 等の不可視の
/// Lo、Co（私用領域）、上記以外の Cn（未割り当て。将来割り当ての追従は表の再生成で行う）。
/// これらは行構造・表示順を変えないため置換しない。
///
/// Cc の判定は std の Unicode 版に従うが、Cc は U+0000〜U+001F・U+007F〜U+009F で版によらず不変。
pub(crate) fn is_display_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{2028}' | '\u{2029}' | '\u{2065}')
        || FORMAT_CHAR_RANGES
            .iter()
            .any(|&(lo, hi)| (lo..=hi).contains(&c))
}

/// `chars` を先頭から読み、表示を乱す文字（[`is_display_unsafe_char`]）を空白へ置換しながら
/// `out` へ追記する。`out` の長さが `max_bytes` を超える直前で読み取りを止める（UTF-8 文字境界で
/// 切り詰める）。
///
/// 入力を借用のまま 1 文字ずつ走査し、上限以降は読まないため、入力が巨大（あるいは無限）でも
/// 追加の確保・走査は上限で頭打ちになる（untrusted 入力による DoS 防止。security.md）。
pub(crate) fn push_sanitized_bounded(
    out: &mut String,
    chars: impl Iterator<Item = char>,
    max_bytes: usize,
) {
    for c in chars {
        let c = if is_display_unsafe_char(c) { ' ' } else { c };
        // checked_add: `max_bytes` 近傍でも桁あふれせず上限判定する。
        let fits = out
            .len()
            .checked_add(c.len_utf8())
            .is_some_and(|next| next <= max_bytes);
        if !fits {
            break;
        }
        out.push(c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ERR-2: Cf の範囲表は昇順・重複なしで、Unicode 16.0.0 の Cf 全 170 符号位置と一致する。
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

    /// ERR-2: 走査は上限で止まる。無限の入力でも終了し、読み取るのは上限 + 1 文字まで。
    #[test]
    fn err2_sanitize_scan_stops_at_limit() {
        let mut consumed = 0usize;
        let chars = std::iter::repeat('a').inspect(|_| consumed += 1);
        let mut out = String::new();
        push_sanitized_bounded(&mut out, chars, 4096);
        assert_eq!(out.len(), 4096);
        assert_eq!(consumed, 4097);
    }
}
