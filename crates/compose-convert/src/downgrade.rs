//! `--downgrade=<key>[,...]` の値の解析と、格下げ許可の判定（TASK-182.1・#627・STACK-3・MS-12）。
//!
//! 役割: [`crate::entry`] が引数を解析する段で [`parse_downgrade_value`] を呼び、検証済みの
//! [`DowngradeSet`] を作る。[`crate::report::FileConversionReport`] はファイルごとの判定
//! （[`DowngradeSet::permits`]）に使い、`downgraded` と `error_free_with_downgrade` を求める。
//!
//! # 2 段の判定
//!
//! 1. 起動時の静的判定: 指定キーの静的な分類（[`classify_key_path`]）が `error-unsupported-yet` でなければ
//!    変換せず拒否する（`error-incompatible`・`unrecognized`・convert・warning は不可。STACK-3）。
//! 2. ファイルごとの判定: 実際にそのファイルで `error-unsupported-yet` と記録されたキーだけを格下げする。
//!    `services.*.network_mode` は静的には unsupported-yet だが、値が `host` / `container:` のファイルでは
//!    `error-incompatible` へ上がるため、格下げされずに blocker として残る。
//!
//! # TOML へ漏れない不変条件
//!
//! 格下げ対象は convert 分類ではなく [`crate::convert::convert_top_level`] の行き先を持たない。
//! 格下げは警告扱いにするだけで、TOML の出力内容を変えない。この検査は #629 が担う（TOML の書き出しは未実装）。
//!
//! # 入力の上限と PoC-16 との違い
//!
//! 値の長さ・要素数・1 要素の長さに上限を設け、割り当てより前または数えながら検査する。PoC-16 と違い、
//! 空の要素は拒否し（黙って捨てない）、同じフラグの繰り返しは [`crate::entry`] が拒否する。
//! エラーのメッセージは固定の英語で、入力の文字列を含めない。

use std::collections::BTreeSet;

use crate::classify::{KEY_CLASS_TABLE, KeyClass, classify_key_path};

/// 値全体の最大バイト数。
pub const MAX_DOWNGRADE_VALUE_BYTES: usize = 16 * 1024;
/// キー数の上限。
pub const MAX_DOWNGRADE_KEYS: usize = 256;
/// 1 要素の最大バイト数。
pub const MAX_DOWNGRADE_KEY_BYTES: usize = 256;

/// 検証済みの格下げ指定。[`parse_downgrade_value`] 経由でしか作れない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DowngradeSet {
    keys: BTreeSet<String>,
}

impl DowngradeSet {
    /// 指定に含まれるか。
    pub fn contains(&self, key_path: &str) -> bool {
        self.keys.contains(key_path)
    }

    /// キーパス順の指定。
    pub fn iter(&self) -> impl Iterator<Item = &str> + '_ {
        self.keys.iter().map(String::as_str)
    }

    /// 重複を除いたキー数。
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// 空か（解析を通った値は空にならない）。
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// ファイルごとの判定。指定にあり、かつそのファイルで記録された分類が `error-unsupported-yet` のときだけ true。
    pub fn permits(&self, key_path: &str, actual: KeyClass) -> bool {
        actual == KeyClass::ErrorUnsupportedYet && self.contains(key_path)
    }
}

/// 引数の値の誤り。入力の文字列は持たない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DowngradeArgError {
    /// 値が空。
    Empty,
    /// 値全体が [`MAX_DOWNGRADE_VALUE_BYTES`] を超えた。
    TooLong,
    /// 空の要素（`a,,b`・末尾の `,`）。
    EmptyItem {
        /// 0 起算の要素番号。
        index: usize,
    },
    /// 要素数が [`MAX_DOWNGRADE_KEYS`] を超えた。
    TooManyKeys,
    /// 1 要素が [`MAX_DOWNGRADE_KEY_BYTES`] を超えた。
    KeyTooLong {
        /// 0 起算の要素番号。
        index: usize,
    },
    /// 静的な分類が `error-unsupported-yet` ではない。
    NotDowngradable {
        /// 0 起算の要素番号。
        index: usize,
        /// 静的な分類。
        class: KeyClass,
        /// 分類表の行と一致したときだけ表側の文字列。利用者の入力は運ばない。
        key_path: Option<&'static str>,
    },
}

impl DowngradeArgError {
    /// 機械可読なコード。
    pub fn code(&self) -> &'static str {
        "INVALID_ARGUMENT"
    }

    /// 固定の英語メッセージ。
    pub fn message(&self) -> &'static str {
        match self {
            Self::Empty => "--downgrade value is empty",
            Self::TooLong => "--downgrade value is too long",
            Self::EmptyItem { .. } => "--downgrade contains an empty key",
            Self::TooManyKeys => "--downgrade has too many keys",
            Self::KeyTooLong { .. } => "--downgrade key is too long",
            Self::NotDowngradable { .. } => "--downgrade key is not error-unsupported-yet",
        }
    }
}

/// `--downgrade=` の値を解析する（STACK-3・TASK-182.1）。
pub fn parse_downgrade_value(value: &str) -> Result<DowngradeSet, DowngradeArgError> {
    if value.len() > MAX_DOWNGRADE_VALUE_BYTES {
        return Err(DowngradeArgError::TooLong);
    }
    if value.is_empty() {
        return Err(DowngradeArgError::Empty);
    }
    let mut keys = BTreeSet::new();
    for (index, raw) in value.split(',').enumerate() {
        if index >= MAX_DOWNGRADE_KEYS {
            return Err(DowngradeArgError::TooManyKeys);
        }
        let key = raw.trim_matches(|c: char| c.is_ascii_whitespace());
        if key.is_empty() {
            return Err(DowngradeArgError::EmptyItem { index });
        }
        if key.len() > MAX_DOWNGRADE_KEY_BYTES {
            return Err(DowngradeArgError::KeyTooLong { index });
        }
        let class = classify_key_path(key);
        if class != KeyClass::ErrorUnsupportedYet {
            let key_path = KEY_CLASS_TABLE
                .iter()
                .find(|(p, _)| *p == key)
                .map(|(p, _)| *p);
            return Err(DowngradeArgError::NotDowngradable {
                index,
                class,
                key_path,
            });
        }
        keys.insert(key.to_string());
    }
    Ok(DowngradeSet { keys })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsupported_rows() -> Vec<&'static str> {
        KEY_CLASS_TABLE
            .iter()
            .filter(|(_, c)| *c == KeyClass::ErrorUnsupportedYet)
            .map(|(p, _)| *p)
            .collect()
    }

    /// STACK-3・REPAIR-12: 表の全行で、unsupported-yet だけ受理し他は分類と表の文字列つきで拒否する。
    #[test]
    fn every_table_row_is_judged_by_class() {
        for (p, c) in KEY_CLASS_TABLE {
            let r = parse_downgrade_value(p);
            if *c == KeyClass::ErrorUnsupportedYet {
                assert_eq!(r.expect(p).iter().collect::<Vec<_>>(), vec![*p]);
            } else {
                assert_eq!(
                    r,
                    Err(DowngradeArgError::NotDowngradable {
                        index: 0,
                        class: *c,
                        key_path: Some(p),
                    }),
                    "{p}"
                );
            }
        }
    }

    /// STACK-3: 全 unsupported-yet 行を空白つきの区切りでまとめて受理する。
    #[test]
    fn accepts_all_unsupported_rows_with_spaces() {
        let rows = unsupported_rows();
        assert!(rows.len() >= 13);
        let set = parse_downgrade_value(&rows.join(", ")).expect("accepted");
        assert_eq!(set.len(), rows.len());
        assert!(set.contains("services.*.container_name"));
    }

    /// STACK-3: warning（x-*）と unrecognized は拒否し、unrecognized の入力は運ばない。
    #[test]
    fn rejects_warning_and_unrecognized() {
        assert_eq!(
            parse_downgrade_value("x-common"),
            Err(DowngradeArgError::NotDowngradable {
                index: 0,
                class: KeyClass::Warning,
                key_path: None,
            })
        );
        assert_eq!(
            parse_downgrade_value("services.*.container_name,services.*.totally_unknown"),
            Err(DowngradeArgError::NotDowngradable {
                index: 1,
                class: KeyClass::Unrecognized,
                key_path: None,
            })
        );
    }

    /// STACK-3: 空・空の要素の拒否と番号。
    #[test]
    fn rejects_empty_values_and_items() {
        assert_eq!(parse_downgrade_value(""), Err(DowngradeArgError::Empty));
        assert_eq!(
            parse_downgrade_value("services.*.tty,,services.*.user"),
            Err(DowngradeArgError::EmptyItem { index: 1 })
        );
        assert_eq!(
            parse_downgrade_value("services.*.tty,"),
            Err(DowngradeArgError::EmptyItem { index: 1 })
        );
        assert_eq!(
            parse_downgrade_value(" "),
            Err(DowngradeArgError::EmptyItem { index: 0 })
        );
    }

    /// REPAIR-12: 上限の境界。ちょうどは通り、超過は拒否する。
    #[test]
    fn limit_boundaries() {
        let long = "a".repeat(MAX_DOWNGRADE_KEY_BYTES);
        assert!(matches!(
            parse_downgrade_value(&long),
            Err(DowngradeArgError::NotDowngradable { .. })
        ));
        let over = "a".repeat(MAX_DOWNGRADE_KEY_BYTES + 1);
        assert_eq!(
            parse_downgrade_value(&over),
            Err(DowngradeArgError::KeyTooLong { index: 0 })
        );
        let exact = vec!["services.*.tty"; MAX_DOWNGRADE_KEYS].join(",");
        assert_eq!(parse_downgrade_value(&exact).expect("ok").len(), 1);
        let one_over = vec!["services.*.tty"; MAX_DOWNGRADE_KEYS + 1].join(",");
        assert_eq!(
            parse_downgrade_value(&one_over),
            Err(DowngradeArgError::TooManyKeys)
        );
        let big = "a".repeat(MAX_DOWNGRADE_VALUE_BYTES + 1);
        assert_eq!(parse_downgrade_value(&big), Err(DowngradeArgError::TooLong));
    }

    /// STACK-3: 重複は 1 つにまとめる。
    #[test]
    fn duplicates_collapse() {
        let s = parse_downgrade_value("services.*.tty,services.*.tty").expect("ok");
        assert_eq!(s.len(), 1);
        assert!(!s.is_empty());
    }

    /// STACK-3: ファイルごとの判定。network_mode が host 等で上がった場合は許可しない。
    #[test]
    fn permits_uses_recorded_class() {
        let s = parse_downgrade_value("services.*.network_mode,services.*.tty").expect("ok");
        assert!(s.permits("services.*.tty", KeyClass::ErrorUnsupportedYet));
        assert!(!s.permits("services.*.network_mode", KeyClass::ErrorIncompatible));
        assert!(!s.permits("services.*.user", KeyClass::ErrorUnsupportedYet));
        assert!(!s.permits("services.*.tty", KeyClass::Convert));
    }

    /// STACK-3: エラーに入力の目印が出ない。
    #[test]
    fn errors_do_not_echo_input() {
        let e = parse_downgrade_value("secret-marker").expect_err("rejected");
        assert!(!format!("{e:?}").contains("secret-marker"));
        assert!(!e.message().contains("secret-marker"));
        assert_eq!(e.code(), "INVALID_ARGUMENT");
    }
}
