//! 変換レポートの 1 行 JSON 出力（TASK-151.7・#602・STACK-3・MS-12）。
//!
//! 役割: [`crate::entry`]（bin の本体）が組み立てた [`FileConversionReport`] と `error_free` の判定を、
//! stderr へ出す 1 行 JSON へ直す。`serde_json` は許容依存の配置に compose-convert が無く、依存を増やさない
//! 方針（`dependency-policy`）のため、手書きの小さな出力器にした。出力は常に ASCII の 1 行。
//!
//! # 契約
//!
//! - 載せるのは正規形のキーパス・件数・固定の語彙・`file_id`・パスだけ。値・環境変数名・サービス名は載せない
//!   （`environment` に資格情報が入りうる。キーパスはユーザー定義名を `*` にした正規形で渡される）。
//! - 文字列はすべて [`json_escape`] を通す。`"`・`\`・制御文字・非 ASCII を `\uXXXX` にするため、
//!   端末のエスケープシーケンスの注入と JSON の破損を防ぐ。
//! - error-class-key の blocker は、外部手順の案内があるときだけ末尾に `guidance`（`code`・`message`）を持つ
//!   （TASK-154.1・STACK-7）。案内は固定語彙と固定文言で入力由来の文字列を含まず、`key_occurrences` には載せない
//!   （理由と次の手順は blocker に一本化して二重管理を避ける）。
//! - フィールドの順序は固定（機械照合と AI の読み取りのため。REPAIR-12）。

use std::fmt::Write as _;

use crate::classify::KeyClass;
use crate::conversion_rate::{ConversionRate, STACK4_THRESHOLD_PERCENT, format_basis_points};
use crate::report::{ErrorFreeBlocker, ErrorFreeVerdict, FileConversionReport};

/// レポートに出す分類の順序（STACK-3 の 4 分類と unrecognized）。
const CLASS_ORDER: [KeyClass; 5] = [
    KeyClass::Convert,
    KeyClass::Warning,
    KeyClass::ErrorIncompatible,
    KeyClass::ErrorUnsupportedYet,
    KeyClass::Unrecognized,
];

/// JSON 文字列の中身を作る（前後の引用符は付けない）。出力は ASCII のみ。
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out
}

fn quoted(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

/// 末尾に改行を付けた 1 行のエラー JSON。`extra` は `(キー, 文字列値)` で、値は escape される。
pub fn error_line(code: &str, message: &str, extra: &[(&str, &str)]) -> String {
    let mut s = format!(
        "{{\"code\":{},\"message\":{}",
        quoted(code),
        quoted(message)
    );
    for (k, v) in extra {
        let _ = write!(s, ",{}:{}", quoted(k), quoted(v));
    }
    s.push_str("}\n");
    s
}

/// ファイル 1 件のレポート行（末尾改行つき）。
///
/// `downgrade` は `--downgrade` 指定時の `(格下げしたキーと件数, 格下げ後の判定)`（TASK-182.1・#627）。
/// `None`（フラグなし）なら `downgraded` は空のオブジェクト、`error_free_with_downgrade` は `null`。
pub fn file_line(
    file_id: &str,
    report: &FileConversionReport,
    verdict: &ErrorFreeVerdict,
    downgrade: Option<(&[(String, u64)], &ErrorFreeVerdict)>,
) -> String {
    let mut s = String::new();
    let _ = write!(s, "{{\"kind\":\"file\",\"file_id\":{}", quoted(file_id));
    match report.parse_error {
        Some(code) => {
            let _ = write!(s, ",\"parse_error\":{}", quoted(code.as_str()));
        }
        None => s.push_str(",\"parse_error\":null"),
    }
    s.push_str(",\"counts\":{");
    for (i, class) in CLASS_ORDER.iter().enumerate() {
        let (mut keys, mut occurrences) = (0u64, 0u64);
        for (_, e) in report.key_occurrences.iter() {
            if e.class == *class {
                keys = keys.saturating_add(1);
                occurrences = occurrences.saturating_add(e.occurrences);
            }
        }
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            "{}:{{\"keys\":{keys},\"occurrences\":{occurrences}}}",
            quoted(class.as_str())
        );
    }
    s.push_str("},\"key_occurrences\":[");
    for (i, (path, e)) in report.key_occurrences.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            "{{\"key_path\":{},\"class\":{},\"occurrences\":{}}}",
            quoted(path),
            quoted(e.class.as_str()),
            e.occurrences
        );
    }
    let _ = write!(
        s,
        "],\"key_occurrences_overflowed\":{},\"value_drops\":{{",
        report.key_occurrences.overflowed()
    );
    for (i, (path, n)) in report.value_drops.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "{}:{n}", quoted(path));
    }
    let _ = write!(
        s,
        "}},\"value_drops_total\":{},\"downgraded\":{{",
        report.value_drops.total()
    );
    for (i, (path, n)) in downgrade.map(|(d, _)| d).unwrap_or(&[]).iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "{}:{n}", quoted(path));
    }
    let _ = write!(
        s,
        "}},\"error_free\":{},\"error_free_blockers\":[",
        verdict.is_error_free()
    );
    write_blockers(&mut s, verdict);
    s.push(']');
    match downgrade {
        Some((_, v)) => {
            let _ = write!(
                s,
                ",\"error_free_with_downgrade\":{},\"error_free_with_downgrade_blockers\":[",
                v.is_error_free()
            );
            write_blockers(&mut s, v);
            s.push(']');
        }
        None => s.push_str(
            ",\"error_free_with_downgrade\":null,\"error_free_with_downgrade_blockers\":[]",
        ),
    }
    s.push_str("}\n");
    s
}

/// blocker の配列の中身（前後の括弧なし）を書く。
fn write_blockers(s: &mut String, verdict: &ErrorFreeVerdict) {
    for (i, b) in verdict.blockers().iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        match b {
            ErrorFreeBlocker::ParseFailed(code) => {
                let _ = write!(
                    s,
                    "{{\"kind\":\"parse-failed\",\"code\":{}}}",
                    quoted(code.as_str())
                );
            }
            ErrorFreeBlocker::ErrorClassKey {
                key_path,
                class,
                occurrences,
                guidance,
            } => {
                let _ = write!(
                    s,
                    "{{\"kind\":\"error-class-key\",\"key_path\":{},\"class\":{},\"occurrences\":{occurrences}",
                    quoted(key_path),
                    quoted(class.as_str())
                );
                if let Some(g) = guidance {
                    let _ = write!(
                        s,
                        ",\"guidance\":{{\"code\":{},\"message\":{}}}",
                        quoted(g.code()),
                        quoted(g.message())
                    );
                }
                s.push('}');
            }
            ErrorFreeBlocker::ValueDrops { total } => {
                let _ = write!(s, "{{\"kind\":\"value-drops\",\"total\":{total}}}");
            }
            ErrorFreeBlocker::KeyOccurrencesOverflow => {
                s.push_str("{\"kind\":\"key-occurrences-overflow\"}");
            }
        }
    }
}

/// 最後の集計行（末尾改行つき）。`toml_output` は TOML の書き出しが未実装であることの明示（REPAIR-3）。
/// `error_free_with_downgrade_files` は `--downgrade` 指定時のみ `Some`（別集計。なければ `null`）。
/// `rate` は STACK-4 の出現数ベース変換可率（TASK-152.2・#606）で、`conversion_rate` に固定順で載る。
pub fn summary_line(
    files: u64,
    error_free_files: u64,
    error_free_with_downgrade_files: Option<u64>,
    parse_failed_files: u64,
    rate: &ConversionRate,
) -> String {
    let dg = error_free_with_downgrade_files.map_or("null".to_string(), |n| n.to_string());
    format!(
        "{{\"kind\":\"summary\",\"files\":{files},\"error_free_files\":{error_free_files},\"error_free_with_downgrade_files\":{dg},\"parse_failed_files\":{parse_failed_files},\"toml_output\":\"unimplemented\",\"conversion_rate\":{}}}\n",
        conversion_rate_json(rate)
    )
}

fn percent_or_null(bp: Option<u64>) -> String {
    bp.map_or("null".to_string(), |b| quoted(&format_basis_points(b)))
}

/// `conversion_rate` オブジェクト。固定語彙と件数だけで、入力由来の文字列は含まない。
fn conversion_rate_json(r: &ConversionRate) -> String {
    let mut s = format!(
        "{{\"basis\":\"occurrences-excluding-warning\",\"convert_occurrences\":{},\"warning_occurrences\":{},\"error_incompatible_occurrences\":{},\"error_unsupported_yet_occurrences\":{},\"unrecognized_occurrences\":{},\"total_occurrences\":{},\"rate_percent\":{},\"threshold_percent\":{},\"verdict\":{},\"lower_bound_convert_occurrences\":{},\"lower_bound_rate_percent\":{},\"lower_bound_verdict\":{},\"indeterminate_reasons\":[",
        r.convert,
        r.warning,
        r.error_incompatible,
        r.error_unsupported_yet,
        r.unrecognized,
        r.total,
        percent_or_null(r.rate_basis_points),
        STACK4_THRESHOLD_PERCENT,
        quoted(r.verdict.as_str()),
        r.lower_bound_convert,
        percent_or_null(r.lower_bound_basis_points),
        quoted(r.lower_bound_verdict.as_str()),
    );
    for (i, reason) in r.indeterminate_reasons.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&quoted(reason.as_str()));
    }
    s.push_str("]}");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose_convert::ComposeParseErrorCode;
    use crate::convert::ValueDrops;
    use crate::report::KeyOccurrences;

    /// STACK-3・REPAIR-12: 引用符・バックスラッシュ・制御文字・非 ASCII の変換。
    #[test]
    fn escape_specific_values() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("\u{1b}[31m"), "\\u001b[31m");
        assert_eq!(json_escape("\u{7f}"), "\\u007f");
        assert_eq!(json_escape("\u{e9}"), "\\u00e9");
        assert_eq!(json_escape("\u{1F600}"), "\\ud83d\\ude00");
    }

    /// STACK-3: 出力は ASCII の 1 行になる。
    #[test]
    fn error_line_is_single_ascii_line() {
        let l = error_line("NOT_FOUND", "m", &[("path", "/x/\u{1b}[2J\n\u{e9}")]);
        assert!(l.is_ascii());
        assert_eq!(l.matches('\n').count(), 1);
        assert_eq!(
            l,
            "{\"code\":\"NOT_FOUND\",\"message\":\"m\",\"path\":\"/x/\\u001b[2J\\n\\u00e9\"}\n"
        );
    }

    /// STACK-3・REPAIR-12: パース失敗の行は counts がすべて 0 で、blocker に parse-failed が載る。
    #[test]
    fn parse_failed_line_exact() {
        let r = FileConversionReport::parse_failed(ComposeParseErrorCode::InvalidArgument);
        let v = r.error_free();
        let l = file_line("b", &r, &v, None);
        assert_eq!(
            l,
            "{\"kind\":\"file\",\"file_id\":\"b\",\"parse_error\":\"INVALID_ARGUMENT\",\"counts\":{\"convert\":{\"keys\":0,\"occurrences\":0},\"warning\":{\"keys\":0,\"occurrences\":0},\"error-incompatible\":{\"keys\":0,\"occurrences\":0},\"error-unsupported-yet\":{\"keys\":0,\"occurrences\":0},\"unrecognized\":{\"keys\":0,\"occurrences\":0}},\"key_occurrences\":[],\"key_occurrences_overflowed\":false,\"value_drops\":{},\"value_drops_total\":0,\"downgraded\":{},\"error_free\":false,\"error_free_blockers\":[{\"kind\":\"parse-failed\",\"code\":\"INVALID_ARGUMENT\"}],\"error_free_with_downgrade\":null,\"error_free_with_downgrade_blockers\":[]}\n"
        );
    }

    /// STACK-3・REPAIR-12: 件数・value_drops・blocker を具体値で照合する。
    #[test]
    fn parsed_line_exact() {
        let mut occ = KeyOccurrences::new();
        occ.record("services.*.image", KeyClass::Convert);
        occ.record("services.*.image", KeyClass::Convert);
        occ.record("services.*.privileged", KeyClass::ErrorIncompatible);
        let mut drops = ValueDrops::new();
        drops.note("services.*.ports");
        let r = FileConversionReport::from_parsed(occ, drops);
        let v = r.error_free();
        let l = file_line("a\"", &r, &v, None);
        assert_eq!(
            l,
            "{\"kind\":\"file\",\"file_id\":\"a\\\"\",\"parse_error\":null,\"counts\":{\"convert\":{\"keys\":1,\"occurrences\":2},\"warning\":{\"keys\":0,\"occurrences\":0},\"error-incompatible\":{\"keys\":1,\"occurrences\":1},\"error-unsupported-yet\":{\"keys\":0,\"occurrences\":0},\"unrecognized\":{\"keys\":0,\"occurrences\":0}},\"key_occurrences\":[{\"key_path\":\"services.*.image\",\"class\":\"convert\",\"occurrences\":2},{\"key_path\":\"services.*.privileged\",\"class\":\"error-incompatible\",\"occurrences\":1}],\"key_occurrences_overflowed\":false,\"value_drops\":{\"services.*.ports\":1},\"value_drops_total\":1,\"downgraded\":{},\"error_free\":false,\"error_free_blockers\":[{\"kind\":\"error-class-key\",\"key_path\":\"services.*.privileged\",\"class\":\"error-incompatible\",\"occurrences\":1},{\"kind\":\"value-drops\",\"total\":1}],\"error_free_with_downgrade\":null,\"error_free_with_downgrade_blockers\":[]}\n"
        );
    }

    /// STACK-7: build の blocker は固定の案内を `guidance` に持つ（厳密一致）。
    #[test]
    fn stack7_build_guidance_line_exact() {
        let mut occ = KeyOccurrences::new();
        occ.record("services.*.build", KeyClass::ErrorIncompatible);
        let r = FileConversionReport::from_parsed(occ, ValueDrops::new());
        let l = file_line("a", &r, &r.error_free(), None);
        let want = format!(
            "\"error_free_blockers\":[{{\"kind\":\"error-class-key\",\"key_path\":\"services.*.build\",\"class\":\"error-incompatible\",\"occurrences\":1,\"guidance\":{{\"code\":\"external-build\",\"message\":\"{}\"}}}}]",
            crate::classify::IncompatibleGuidance::ExternalBuild.message()
        );
        assert!(l.contains(&want), "{l}");
        assert!(l.is_ascii() && l.matches('\n').count() == 1);
        assert_eq!(l.matches("guidance").count(), 1);
    }

    fn rate_of(entries: &[(&str, KeyClass, u64)], failed: bool) -> ConversionRate {
        let mut occ = KeyOccurrences::new();
        for (p, c, n) in entries {
            for _ in 0..*n {
                occ.record(p, *c);
            }
        }
        let mut t = crate::conversion_rate::ConversionRateTally::new();
        t.add(&FileConversionReport::from_parsed(occ, ValueDrops::new()));
        if failed {
            t.add(&FileConversionReport::parse_failed(
                ComposeParseErrorCode::InvalidArgument,
            ));
        }
        t.finish()
    }

    /// STACK-3・STACK-4: 集計行の形（変換可率つき）。
    #[test]
    fn summary_line_exact() {
        let r = rate_of(
            &[("a", KeyClass::Convert, 4), ("b", KeyClass::Warning, 1)],
            false,
        );
        assert_eq!(
            summary_line(3, 1, None, 1, &r),
            "{\"kind\":\"summary\",\"files\":3,\"error_free_files\":1,\"error_free_with_downgrade_files\":null,\"parse_failed_files\":1,\"toml_output\":\"unimplemented\",\"conversion_rate\":{\"basis\":\"occurrences-excluding-warning\",\"convert_occurrences\":4,\"warning_occurrences\":1,\"error_incompatible_occurrences\":0,\"error_unsupported_yet_occurrences\":0,\"unrecognized_occurrences\":0,\"total_occurrences\":5,\"rate_percent\":\"80.00\",\"threshold_percent\":80,\"verdict\":\"meets\",\"lower_bound_convert_occurrences\":4,\"lower_bound_rate_percent\":\"80.00\",\"lower_bound_verdict\":\"meets\",\"indeterminate_reasons\":[]}}\n"
        );
        assert!(
            summary_line(3, 1, Some(2), 1, &r).contains("\"error_free_with_downgrade_files\":2,")
        );
    }

    /// STACK-4: 判定不能と率 null の形。
    #[test]
    fn summary_line_indeterminate_exact() {
        let r = rate_of(&[], true);
        assert_eq!(
            summary_line(1, 0, None, 1, &r),
            "{\"kind\":\"summary\",\"files\":1,\"error_free_files\":0,\"error_free_with_downgrade_files\":null,\"parse_failed_files\":1,\"toml_output\":\"unimplemented\",\"conversion_rate\":{\"basis\":\"occurrences-excluding-warning\",\"convert_occurrences\":0,\"warning_occurrences\":0,\"error_incompatible_occurrences\":0,\"error_unsupported_yet_occurrences\":0,\"unrecognized_occurrences\":0,\"total_occurrences\":0,\"rate_percent\":null,\"threshold_percent\":80,\"verdict\":\"indeterminate\",\"lower_bound_convert_occurrences\":0,\"lower_bound_rate_percent\":null,\"lower_bound_verdict\":\"indeterminate\",\"indeterminate_reasons\":[\"parse-failed-files\",\"no-key-occurrences\"]}}\n"
        );
    }
}
