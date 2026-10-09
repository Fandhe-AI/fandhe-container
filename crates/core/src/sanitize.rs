//! 表示を乱す文字の判定と有界追記（判定表は本モジュール内でただ 1 つの実装）。
//!
//! 外部由来（plugin 応答・ヘルパーの stderr・パス）の文字列をログ・エラーメッセージ・監査記録へ
//! 入れる前に、Unicode 一般カテゴリ Cc・Cf・Zl・Zp の文字を判定する。利用者は
//! `oci_runtime::error`（空白へ置換）・`rootless`（除去）・`exec::violation`（`escape_default`
//! 形式でエスケープ）。外部 crate 向けには空白置換の `sanitize_display_bounded` だけを公開し、
//! cli の `CliError` が使う（判定表は公開しない）。置換の形は呼び出し側が決め、本モジュールは判定と有界追記だけを持つ
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

/// [`sanitize_display_bounded`] の結果。サニタイズ済み文字列と、上限で打ち切ったかどうかを保持する。
///
/// 戻り値を生の `String` にせず構造化型にすることで、将来の付加情報（打ち切りバイト数等）を
/// 戻り値型を変えずに足せる（AGENTS.md の構造化戻り値規約・REPAIR-3・ERR-2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedDisplay {
    text: String,
    truncated: bool,
}

impl SanitizedDisplay {
    /// サニタイズ済みの文字列を借用で返す。
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// サニタイズ済みの文字列を所有権ごと取り出す。
    pub fn into_string(self) -> String {
        self.text
    }

    /// 入力が `max_bytes` の上限で打ち切られたとき true。
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

/// 表示を乱す文字（Cc・Cf・Zl・Zp と U+2065）を空白へ置換し、UTF-8 文字境界で `max_bytes` に
/// 打ち切った結果（[`SanitizedDisplay`]）を返す公開入口。
///
/// `OciRuntimeError::new`（core）と cli の `CliError::new` が同じ規則を共有するための単一の入口で、
/// 判定表は公開しない。`input` は借用のまま走査し上限で読み取りを止めるため、巨大な入力でも
/// 確保・走査は `max_bytes` で頭打ちになる（untrusted 入力の DoS 防止）。置換後の空白は元の文字
/// 以下のバイト長なので、確保は `min(入力長, max_bytes)` の 1 回で済む（ERR-1・ERR-2・SEC-4・TASK-96.1）。
pub fn sanitize_display_bounded(input: &str, max_bytes: usize) -> SanitizedDisplay {
    let mut text = String::with_capacity(input.len().min(max_bytes));
    push_sanitized_bounded(&mut text, input.chars(), max_bytes);
    // 置換は 1 文字対 1 文字なので、出力の文字数番目に入力文字が残っていれば打ち切られている。
    // 走査は出力の文字数までで頭打ち（入力全体は読まない）。
    let truncated = input.chars().nth(text.chars().count()).is_some();
    SanitizedDisplay { text, truncated }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ERR-2: 公開入口は制御・書式・行区切り文字を空白へ置換する。
    #[test]
    fn err2_sanitize_display_bounded_replaces_unsafe_chars() {
        assert_eq!(
            sanitize_display_bounded("a\u{202E}b\nc\u{2028}d", 4096).as_str(),
            "a b c d"
        );
    }

    /// ERR-2: 公開入口は UTF-8 文字境界で打ち切り、上限 0 は空文字列。
    #[test]
    fn err2_sanitize_display_bounded_truncates_at_char_boundary() {
        let s = sanitize_display_bounded(&"あ".repeat(5000), 4096);
        assert_eq!(
            (
                s.as_str().len(),
                s.as_str().chars().count(),
                s.is_truncated()
            ),
            (4095, 1365, true)
        );
        let a = sanitize_display_bounded(&"a".repeat(10_000), 4096);
        assert_eq!((a.as_str().len(), a.is_truncated()), (4096, true));
        let z = sanitize_display_bounded("abc", 0);
        assert_eq!((z.as_str(), z.is_truncated()), ("", true));
        let ok = sanitize_display_bounded("abc", 3);
        assert_eq!((ok.as_str(), ok.is_truncated()), ("abc", false));
    }

    /// ERR-2: 確保量は上限で頭打ちになる。
    #[test]
    fn err2_sanitize_display_bounded_capacity_is_capped() {
        let big = "a".repeat(1 << 20);
        assert_eq!(
            sanitize_display_bounded(&big, 4096)
                .into_string()
                .capacity(),
            4096
        );
        assert_eq!(
            sanitize_display_bounded("abc", 4096)
                .into_string()
                .capacity(),
            3
        );
    }

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
