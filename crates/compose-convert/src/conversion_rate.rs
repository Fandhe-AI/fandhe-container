//! 出現数ベースの変換可率の集計（TASK-152.2・#606・STACK-4・MS-12）。
//!
//! 役割: [`crate::entry`] の `run_dir` が組み立てた [`FileConversionReport`] をファイルごとに [`ConversionRateTally`]
//! へ足し、最後の `summary` 行（[`crate::report_json::summary_line`]）に載せる [`ConversionRate`] を作る。
//! 実コーパスでの実測と 80% の妥当性判断は人間担当（#607・TASK-152.h1）で、本モジュールは計測だけを担う。
//!
//! # 計算式（STACK-4。PoC-16 の `aggregate.py` の `convert_occ / total_occ` と同じ）
//!
//! - 分子: 分類が `convert` のキーパスの出現数の合計。
//! - 分母: 全 5 分類（convert・warning・error-incompatible・error-unsupported-yet・unrecognized）の出現数の合計。
//!   「警告を除く」は warning を分子（変換可）に数えないという意味で、分母からは除かない。
//! - 分類はファイル内でキーパスごとに重い方へ寄せた記録をそのまま使う。
//! - `--downgrade` は分類を変えないため、変換可率は格下げの有無で変わらない。
//! - 下限（`lower_bound_*`）: ファイルごとに `value_drops` のキーパスのうち同じファイルで `convert` と記録された
//!   ものの出現数を分子から差し引く（単位はキーの出現数）。一致する convert の記録が無ければ差し引かない。
//!
//! # 判定（fail-closed）
//!
//! 比較は整数演算（`convert * 100 >= total * 80`、ちょうど 80% は満たす）。表示の率は切り捨てた 2 桁小数で、
//! 79.999% が "80.00" と表示されて判定と食い違うのを防ぐ。次のときは [`ThresholdVerdict::Indeterminate`]:
//! キー記録の溢れ・パース失敗ファイルの存在・分母 0。
//!
//! 出力は件数と固定語彙だけで、入力由来の文字列（値・名前・パス）は含めない。

use crate::classify::KeyClass;
use crate::report::FileConversionReport;

/// STACK-4 の変換可率の基準（パーセント）。
pub const STACK4_THRESHOLD_PERCENT: u64 = 80;

/// 80% 基準との比較結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ThresholdVerdict {
    /// 基準以上。
    Meets,
    /// 基準未満。
    Below,
    /// 件数が不完全または分母 0 で判定できない。
    Indeterminate,
}

impl ThresholdVerdict {
    /// JSON に出す固定語彙。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Meets => "meets",
            Self::Below => "below",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// 判定不能の理由（固定語彙）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndeterminateReason {
    /// どれかのファイルでキー記録を捨てた。
    KeyOccurrencesOverflowed,
    /// パースに失敗したファイルがあり、分母が不完全。
    ParseFailedFiles,
    /// 分母が 0。
    NoKeyOccurrences,
}

impl IndeterminateReason {
    /// JSON に出す固定語彙。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyOccurrencesOverflowed => "key-occurrences-overflowed",
            Self::ParseFailedFiles => "parse-failed-files",
            Self::NoKeyOccurrences => "no-key-occurrences",
        }
    }
}

/// 集計結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConversionRate {
    /// convert の出現数。
    pub convert: u64,
    /// warning の出現数。
    pub warning: u64,
    /// error-incompatible の出現数。
    pub error_incompatible: u64,
    /// error-unsupported-yet の出現数。
    pub error_unsupported_yet: u64,
    /// unrecognized の出現数。
    pub unrecognized: u64,
    /// 全分類の出現数の合計（分母）。
    pub total: u64,
    /// 率の basis points（切り捨て）。分母 0 なら `None`。
    pub rate_basis_points: Option<u64>,
    /// 基準との比較。
    pub verdict: ThresholdVerdict,
    /// 下限の分子（`value_drops` 分を差し引いた convert）。
    pub lower_bound_convert: u64,
    /// 下限の率の basis points。
    pub lower_bound_basis_points: Option<u64>,
    /// 下限の基準との比較。
    pub lower_bound_verdict: ThresholdVerdict,
    /// 判定不能の理由（固定順）。
    pub indeterminate_reasons: Vec<IndeterminateReason>,
}

/// `convert / total` の basis points（切り捨て）。分母 0 は `None`。
fn basis_points(convert: u64, total: u64) -> Option<u64> {
    if total == 0 {
        return None;
    }
    let bp = u128::from(convert) * 10_000 / u128::from(total);
    Some(u64::try_from(bp).unwrap_or(u64::MAX))
}

fn meets(convert: u64, total: u64) -> bool {
    u128::from(convert) * 100 >= u128::from(total) * u128::from(STACK4_THRESHOLD_PERCENT)
}

fn verdict_of(convert: u64, total: u64, incomplete: bool) -> ThresholdVerdict {
    if incomplete || total == 0 {
        ThresholdVerdict::Indeterminate
    } else if meets(convert, total) {
        ThresholdVerdict::Meets
    } else {
        ThresholdVerdict::Below
    }
}

/// basis points を `"85.08"` の形の文字列にする（浮動小数を使わない）。
pub fn format_basis_points(bp: u64) -> String {
    format!("{}.{:02}", bp / 100, bp % 100)
}

/// ファイルごとのレポートを足していく集計器。
#[derive(Debug, Clone, Default)]
pub struct ConversionRateTally {
    counts: [u64; 5],
    value_drop_convert: u64,
    overflowed: bool,
    parse_failed: bool,
}

fn class_index(c: KeyClass) -> usize {
    match c {
        KeyClass::Convert => 0,
        KeyClass::Warning => 1,
        KeyClass::ErrorIncompatible => 2,
        KeyClass::ErrorUnsupportedYet => 3,
        _ => 4,
    }
}

impl ConversionRateTally {
    /// 空の集計器。
    pub fn new() -> Self {
        Self::default()
    }

    /// ファイル 1 件のレポートを足す（加算は飽和）。
    pub fn add(&mut self, report: &FileConversionReport) {
        if report.parse_error.is_some() {
            self.parse_failed = true;
        }
        if report.key_occurrences.overflowed() {
            self.overflowed = true;
        }
        for (_, e) in report.key_occurrences.iter() {
            let i = class_index(e.class);
            self.counts[i] = self.counts[i].saturating_add(e.occurrences);
        }
        for (path, _) in report.value_drops.iter() {
            if let Some(e) = report.key_occurrences.get(path)
                && e.class == KeyClass::Convert
            {
                self.value_drop_convert = self.value_drop_convert.saturating_add(e.occurrences);
            }
        }
    }

    /// 集計を確定する。
    pub fn finish(&self) -> ConversionRate {
        let total = self.counts.iter().fold(0u64, |a, n| a.saturating_add(*n));
        let convert = self.counts[0];
        let lower = convert.saturating_sub(self.value_drop_convert);
        let mut reasons = Vec::new();
        if self.overflowed {
            reasons.push(IndeterminateReason::KeyOccurrencesOverflowed);
        }
        if self.parse_failed {
            reasons.push(IndeterminateReason::ParseFailedFiles);
        }
        if total == 0 {
            reasons.push(IndeterminateReason::NoKeyOccurrences);
        }
        let incomplete = self.overflowed || self.parse_failed;
        ConversionRate {
            convert,
            warning: self.counts[1],
            error_incompatible: self.counts[2],
            error_unsupported_yet: self.counts[3],
            unrecognized: self.counts[4],
            total,
            rate_basis_points: basis_points(convert, total),
            verdict: verdict_of(convert, total, incomplete),
            lower_bound_convert: lower,
            lower_bound_basis_points: basis_points(lower, total),
            lower_bound_verdict: verdict_of(lower, total, incomplete),
            indeterminate_reasons: reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose_convert::ComposeParseErrorCode;
    use crate::convert::ValueDrops;
    use crate::report::KeyOccurrences;

    fn report(entries: &[(&str, KeyClass, u64)], drops: &[&'static str]) -> FileConversionReport {
        let mut occ = KeyOccurrences::new();
        for (p, c, n) in entries {
            for _ in 0..*n {
                occ.record(p, *c);
            }
        }
        let mut d = ValueDrops::new();
        for p in drops {
            d.note(p);
        }
        FileConversionReport::from_parsed(occ, d)
    }

    fn rate(convert: u64, rest: u64) -> ConversionRate {
        let r = report(
            &[
                ("a", KeyClass::Convert, convert),
                ("b", KeyClass::ErrorUnsupportedYet, rest),
            ],
            &[],
        );
        let mut t = ConversionRateTally::new();
        t.add(&r);
        t.finish()
    }

    /// STACK-4: spec の 97/114（PoC-16 の local-server）。分母は warning を含む全分類。
    #[test]
    fn stack4_spec_value_97_of_114() {
        let r = report(
            &[
                ("c", KeyClass::Convert, 97),
                ("w", KeyClass::Warning, 2),
                ("e", KeyClass::ErrorIncompatible, 10),
                ("u", KeyClass::ErrorUnsupportedYet, 5),
            ],
            &[],
        );
        let mut t = ConversionRateTally::new();
        t.add(&r);
        let out = t.finish();
        assert_eq!(out.total, 114);
        assert_eq!(out.rate_basis_points, Some(8508));
        assert_eq!(out.verdict, ThresholdVerdict::Meets);
        assert_eq!(format_basis_points(8508), "85.08");
    }

    /// STACK-4: 下限は value_drops の convert 分を差し引く（97 - 4 = 93、81.57%）。
    #[test]
    fn stack4_lower_bound_93_of_114() {
        let r = report(
            &[
                ("services.*.volumes", KeyClass::Convert, 4),
                ("c", KeyClass::Convert, 93),
                ("w", KeyClass::Warning, 2),
                ("e", KeyClass::ErrorIncompatible, 15),
            ],
            &["services.*.volumes"],
        );
        let mut t = ConversionRateTally::new();
        t.add(&r);
        let out = t.finish();
        assert_eq!((out.convert, out.total), (97, 114));
        assert_eq!(out.lower_bound_convert, 93);
        assert_eq!(out.lower_bound_basis_points, Some(8157));
        assert_eq!(out.lower_bound_verdict, ThresholdVerdict::Meets);
    }

    /// STACK-4: 記録が無いパス・convert 以外の分類では差し引かない。
    #[test]
    fn lower_bound_ignores_unmatched_drops() {
        let r = report(
            &[("w", KeyClass::Warning, 3), ("c", KeyClass::Convert, 7)],
            &["w", "absent"],
        );
        let mut t = ConversionRateTally::new();
        t.add(&r);
        assert_eq!(t.finish().lower_bound_convert, 7);
    }

    /// STACK-4: 235/302 は 77.81% で基準未満。
    #[test]
    fn stack4_below_235_of_302() {
        let out = rate(235, 67);
        assert_eq!(out.rate_basis_points, Some(7781));
        assert_eq!(out.verdict, ThresholdVerdict::Below);
    }

    /// STACK-4: 境界。80/100 は満たし、79/100 と 7999/10000 は満たさない（表示も切り捨て）。
    #[test]
    fn stack4_boundary() {
        assert_eq!(rate(80, 20).verdict, ThresholdVerdict::Meets);
        assert_eq!(rate(79, 21).verdict, ThresholdVerdict::Below);
        let r = rate(7999, 2001);
        assert_eq!(r.verdict, ThresholdVerdict::Below);
        assert_eq!(r.rate_basis_points, Some(7999));
        assert_eq!(format_basis_points(7999), "79.99");
    }

    /// STACK-4: 分母 0 は率なし・判定不能。
    #[test]
    fn stack4_empty_is_indeterminate() {
        let out = ConversionRateTally::new().finish();
        assert_eq!(out.rate_basis_points, None);
        assert_eq!(out.verdict, ThresholdVerdict::Indeterminate);
        assert_eq!(
            out.indeterminate_reasons,
            vec![IndeterminateReason::NoKeyOccurrences]
        );
    }

    /// STACK-4: パース失敗ファイルを含むと判定不能（数えられた分の率は出す）。
    #[test]
    fn stack4_parse_failed_is_indeterminate() {
        let mut t = ConversionRateTally::new();
        t.add(&report(&[("c", KeyClass::Convert, 9)], &[]));
        t.add(&FileConversionReport::parse_failed(
            ComposeParseErrorCode::InvalidArgument,
        ));
        let out = t.finish();
        assert_eq!(out.rate_basis_points, Some(10_000));
        assert_eq!(out.verdict, ThresholdVerdict::Indeterminate);
        assert_eq!(out.lower_bound_verdict, ThresholdVerdict::Indeterminate);
        assert_eq!(
            out.indeterminate_reasons,
            vec![IndeterminateReason::ParseFailedFiles]
        );
    }

    /// STACK-4: 記録の溢れがあると判定不能。
    #[test]
    fn stack4_overflow_is_indeterminate() {
        let mut occ = KeyOccurrences::new();
        for i in 0..=crate::report::MAX_KEY_PATHS {
            occ.record(&format!("k{i}"), KeyClass::Convert);
        }
        assert!(occ.overflowed());
        let mut t = ConversionRateTally::new();
        t.add(&FileConversionReport::from_parsed(occ, ValueDrops::new()));
        let out = t.finish();
        assert_eq!(out.convert, crate::report::MAX_KEY_PATHS as u64);
        assert_eq!(out.verdict, ThresholdVerdict::Indeterminate);
        assert_eq!(
            out.indeterminate_reasons,
            vec![IndeterminateReason::KeyOccurrencesOverflowed]
        );
    }

    /// STACK-4: warning だけのファイルは分母に入り分子 0 になる。
    #[test]
    fn stack4_warning_only_is_below() {
        let mut t = ConversionRateTally::new();
        t.add(&report(&[("version", KeyClass::Warning, 1)], &[]));
        let out = t.finish();
        assert_eq!((out.convert, out.total), (0, 1));
        assert_eq!(out.verdict, ThresholdVerdict::Below);
    }

    /// 巨大な件数でもパニックしない。
    #[test]
    fn huge_counts_do_not_panic() {
        assert!(meets(u64::MAX, u64::MAX));
        assert_eq!(basis_points(u64::MAX, u64::MAX), Some(10_000));
        let mut t = ConversionRateTally::new();
        t.counts = [u64::MAX; 5];
        let out = t.finish();
        assert_eq!(out.total, u64::MAX);
    }
}
