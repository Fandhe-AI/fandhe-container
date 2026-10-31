//! ファイル単位の変換レポートと `error_free` 判定（TASK-151.4・#599・STACK-3・MS-12）。
//!
//! 役割: 1 つの compose ファイルについて、キーパス別の分類と出現数（[`KeyOccurrences`]）、
//! 変換できずに捨てた値の件数（[`ValueDrops`]）、パース失敗の有無を 1 か所に集め、
//! 「エラー 0 件」かを [`FileConversionReport::error_free`] で判定する。判定は PoC-16 と同じ 3 条件の論理積
//! （パース成功・エラー分類キー 0 件・`value_drops` 空）で、`value_drops` が 1 件でもあれば `error_free` にしない。
//! 呼び出し元は #601（unrecognized 0 件の確認）と #602（bin のレポート出力）を想定する。
//!
//! 未実装の範囲（REPAIR-3）: 文書を走査して [`KeyOccurrences`] を埋める走査器は `crate::key_scan`（#601）で、
//! 本モジュールは集計の型と判定だけを持つ。`deploy` の変換と GPU 予約の実加算
//! の結線も未実装。`--downgrade` と `error_free_with_downgrade` は TASK-182 で別集計として足し、
//! 本型の `error_free` の定義は変えない。
//!
//! 判定結果・blocker には値・環境変数名・サービス名を載せない（`environment` に資格情報が入りうるため）。
//! キーパスはユーザー定義名を `*` にした正規形で渡す契約である。

use std::collections::BTreeMap;

use crate::classify::KeyClass;
use crate::compose_convert::ComposeParseErrorCode;
use crate::convert::ValueDrops;

/// 異なるキーパスの記録数の上限。超えた記録は捨てずに溢れの印を立て、判定を不可にする（DoS 対策・fail-closed）。
pub const MAX_KEY_PATHS: usize = 4096;

/// キーパス 1 件の分類と出現数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyOccurrence {
    /// 分類。同じパスで混ざったときは重い方。
    pub class: KeyClass,
    /// 出現数。
    pub occurrences: u64,
}

/// キーパス別の分類と出現数。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyOccurrences {
    map: BTreeMap<String, KeyOccurrence>,
    overflowed: bool,
}

impl KeyOccurrences {
    /// 空の集計。
    pub fn new() -> Self {
        Self::default()
    }

    /// `key_path`（正規形）の出現を 1 件記録する。同じパスで分類が混ざったら重い方へ寄せる。
    /// 異なるパスが [`MAX_KEY_PATHS`] を超えたら記録せず溢れの印を立てる。
    pub fn record(&mut self, key_path: &str, class: KeyClass) {
        if let Some(e) = self.map.get_mut(key_path) {
            e.class = e.class.heavier(class);
            e.occurrences = e.occurrences.saturating_add(1);
            return;
        }
        if self.map.len() >= MAX_KEY_PATHS {
            self.overflowed = true;
            return;
        }
        self.map.insert(
            key_path.to_string(),
            KeyOccurrence {
                class,
                occurrences: 1,
            },
        );
    }

    /// `key_path` の記録。
    pub fn get(&self, key_path: &str) -> Option<KeyOccurrence> {
        self.map.get(key_path).copied()
    }

    /// パス順の `(キーパス, 記録)`。
    pub fn iter(&self) -> impl Iterator<Item = (&str, KeyOccurrence)> + '_ {
        self.map.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// 上限超過で記録を捨てたか。
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// `Unrecognized` の出現数の合計（#601 の確認用）。
    pub fn unrecognized_count(&self) -> u64 {
        self.map
            .values()
            .filter(|e| e.class == KeyClass::Unrecognized)
            .fold(0u64, |a, e| a.saturating_add(e.occurrences))
    }
}

/// ファイル単位の変換レポート。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileConversionReport {
    /// キーパス別の分類と出現数。
    pub key_occurrences: KeyOccurrences,
    /// 変換できずに捨てた値の件数。
    pub value_drops: ValueDrops,
    /// パース失敗のコード。失敗なら他の集計は空。
    pub parse_error: Option<ComposeParseErrorCode>,
}

impl FileConversionReport {
    /// パースに成功したファイルのレポート。
    pub fn from_parsed(key_occurrences: KeyOccurrences, value_drops: ValueDrops) -> Self {
        Self {
            key_occurrences,
            value_drops,
            parse_error: None,
        }
    }

    /// パースに失敗したファイルのレポート。
    pub fn parse_failed(code: ComposeParseErrorCode) -> Self {
        Self {
            key_occurrences: KeyOccurrences::new(),
            value_drops: ValueDrops::new(),
            parse_error: Some(code),
        }
    }

    /// `error_free` を判定する（STACK-3）。妨げた理由を blocker の一覧で返す。
    pub fn error_free(&self) -> ErrorFreeVerdict {
        let mut blockers = Vec::new();
        if let Some(code) = self.parse_error {
            blockers.push(ErrorFreeBlocker::ParseFailed(code));
        }
        for (path, e) in self.key_occurrences.iter() {
            if e.class.is_error() {
                blockers.push(ErrorFreeBlocker::ErrorClassKey {
                    key_path: path.to_string(),
                    class: e.class,
                    occurrences: e.occurrences,
                });
            }
        }
        if !self.value_drops.is_empty() {
            blockers.push(ErrorFreeBlocker::ValueDrops {
                total: self.value_drops.total(),
            });
        }
        if self.key_occurrences.overflowed() {
            blockers.push(ErrorFreeBlocker::KeyOccurrencesOverflow);
        }
        ErrorFreeVerdict { blockers }
    }
}

/// `error_free` を妨げる理由。値・名前は持たない。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorFreeBlocker {
    /// パースに失敗した。
    ParseFailed(ComposeParseErrorCode),
    /// エラー分類（Unrecognized を含む）のキーがある。
    ErrorClassKey {
        /// 正規形のキーパス。
        key_path: String,
        /// 分類。
        class: KeyClass,
        /// 出現数。
        occurrences: u64,
    },
    /// 捨てた値がある（`value_drops` が空でない）。
    ValueDrops {
        /// 合計件数。
        total: u64,
    },
    /// キーパスの記録が上限を超えた。
    KeyOccurrencesOverflow,
}

/// `error_free` の判定結果。真偽値だけでなく理由の一覧を持つ。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ErrorFreeVerdict {
    blockers: Vec<ErrorFreeBlocker>,
}

impl ErrorFreeVerdict {
    /// blocker が 0 件か。
    pub fn is_error_free(&self) -> bool {
        self.blockers.is_empty()
    }

    /// 妨げた理由の一覧。
    pub fn blockers(&self) -> &[ErrorFreeBlocker] {
        &self.blockers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compose_convert::parse_compose_yaml;
    use crate::convert::convert_top_level;

    const P_PORTS: &str = "services.*.ports";

    fn clean_occurrences() -> KeyOccurrences {
        let mut k = KeyOccurrences::new();
        k.record("services.*", KeyClass::Convert);
        k.record("services.*.image", KeyClass::Convert);
        k.record("services.*.stdin_open", KeyClass::Warning);
        k
    }

    /// STACK-3・REPAIR-12: value_drops が 0 件のときだけ error_free になる。
    #[test]
    fn stack3_error_free_only_when_value_drops_empty() {
        let r = FileConversionReport::from_parsed(clean_occurrences(), ValueDrops::new());
        let v = r.error_free();
        assert!(v.is_error_free());
        assert!(v.blockers().is_empty());

        let mut drops = ValueDrops::new();
        drops.note(P_PORTS);
        let r = FileConversionReport::from_parsed(clean_occurrences(), drops);
        let v = r.error_free();
        assert!(!v.is_error_free());
        assert_eq!(v.blockers(), &[ErrorFreeBlocker::ValueDrops { total: 1 }]);
    }

    /// STACK-3: drop が無くてもエラー分類のキーがあれば error_free にならない。
    #[test]
    fn stack3_error_class_key_blocks_error_free() {
        for class in [
            KeyClass::ErrorUnsupportedYet,
            KeyClass::ErrorIncompatible,
            KeyClass::Unrecognized,
        ] {
            let mut k = clean_occurrences();
            k.record("services.*.x", class);
            k.record("services.*.x", class);
            let v = FileConversionReport::from_parsed(k, ValueDrops::new()).error_free();
            assert!(!v.is_error_free());
            assert_eq!(
                v.blockers(),
                &[ErrorFreeBlocker::ErrorClassKey {
                    key_path: "services.*.x".to_string(),
                    class,
                    occurrences: 2
                }]
            );
        }
    }

    /// STACK-3: パース失敗は error_free にならない。
    #[test]
    fn stack3_parse_failure_is_not_error_free() {
        let v =
            FileConversionReport::parse_failed(ComposeParseErrorCode::InvalidArgument).error_free();
        assert!(!v.is_error_free());
        assert_eq!(
            v.blockers(),
            &[ErrorFreeBlocker::ParseFailed(
                ComposeParseErrorCode::InvalidArgument
            )]
        );
    }

    /// STACK-3: 同じパスで分類が混ざったら重い方、出現数は合算。
    #[test]
    fn stack3_key_occurrences_heavier_wins() {
        let mut k = KeyOccurrences::new();
        k.record("a", KeyClass::Convert);
        k.record("a", KeyClass::ErrorIncompatible);
        k.record("a", KeyClass::Warning);
        let e = k.get("a").unwrap();
        assert_eq!(e.class, KeyClass::ErrorIncompatible);
        assert_eq!(e.occurrences, 3);
    }

    /// STACK-3・REPAIR-12: 異なるパスが上限を超えたら判定不可（fail-closed）。
    #[test]
    fn stack3_key_occurrences_overflow_blocks() {
        let mut k = KeyOccurrences::new();
        for i in 0..=MAX_KEY_PATHS {
            k.record(&format!("p{i}"), KeyClass::Convert);
        }
        assert!(k.overflowed());
        assert_eq!(k.iter().count(), MAX_KEY_PATHS);
        let v = FileConversionReport::from_parsed(k, ValueDrops::new()).error_free();
        assert_eq!(v.blockers(), &[ErrorFreeBlocker::KeyOccurrencesOverflow]);
    }

    fn report_of(yaml: &str) -> FileConversionReport {
        let doc = parse_compose_yaml(yaml).unwrap();
        let mut drops = ValueDrops::new();
        let _ = convert_top_level(&doc, &mut drops);
        FileConversionReport::from_parsed(clean_occurrences(), drops)
    }

    /// STACK-3: 実 YAML の通し。long syntax の drop が 1 件あれば false、無ければ true。
    #[test]
    fn stack3_long_syntax_drop_makes_file_not_error_free() {
        let ok = report_of(
            "services:\n  s:\n    image: x\n    ports:\n      - {target: 80, published: 8080}\n",
        );
        assert!(ok.value_drops.is_empty());
        assert!(ok.error_free().is_error_free());

        let ng = report_of(
            "services:\n  s:\n    image: x\n    ports:\n      - {target: 80, mode: host}\n",
        );
        assert_eq!(ng.value_drops.get(P_PORTS), 1);
        assert_eq!(
            ng.error_free().blockers(),
            &[ErrorFreeBlocker::ValueDrops { total: 1 }]
        );
    }

    /// STACK-3: 判定結果の Debug に値・サービス名・環境変数名が出ない。
    #[test]
    fn stack3_verdict_does_not_contain_values() {
        let r = report_of(
            "services:\n  secretsvc:\n    environment:\n      TOKEN_NAME: 1.5\n    ports:\n      - {target: 80, mode: host}\n",
        );
        let dbg = format!("{:?}", r.error_free());
        assert!(!dbg.contains("secretsvc") && !dbg.contains("TOKEN_NAME"));
        assert!(!r.error_free().is_error_free());
    }
}
