//! compose.yaml の YAML 読み込みと、アンカー / エイリアス / マージキー（`<<`）の展開（TASK-151.1・#595・STACK-3・MS-12）。
//!
//! 変換器の最初の段。後続の段（キー分類 #596・TOML 変換 #598・value_drops #599・走査 #600〔`input_scan`〕・bin #602）は、
//! ここが返すパーサー非依存の単一モデル [`ComposeValue`] だけを読む。`serde-saphyr` の型は公開しない。
//!
//! # 契約
//!
//! - 入口は [`parse_compose_yaml`]。トップレベルは必ずマッピングで、展開後の木に `<<` キーは残らない。
//! - マージの優先順位は YAML の規則どおり: 明示キーがマージ由来のキーに勝ち、`<<: [*a, *b]` では先のマッピングが勝つ。
//! - マッピングのキーは文字列のみ（整数・真偽値・null のキーは拒否する。fail-closed）。出現順を保つ。
//! - 入力長・深さ・ノード数・アンカー / エイリアス数・エイリアス再生量に上限がある（無制限確保の防止）。
//! - エラーの `message` には入力の断片・キー名・値を載せない（`environment` に秘密が入りうるため）。
//!
//! # 制約（実装済みを装わない。REPAIR-3）
//!
//! - u64 / i64 を超える整数はパーサーの推論で `f64` になる。型の検証は TASK-151.3（#598）・value_drops（#599）が行う。
//! - `${VAR}` の補間はせず、文字列を生のまま保持する。
//! - タグ付きの値（`!custom`・compose の `!reset` / `!override` を含む）は拒否する。
//! - 1 ファイル内の複数ドキュメントは未対応（`Unimplemented`）。compose-go の override 合成は別 issue。

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_saphyr::options::{DuplicateKeyPolicy, MergeKeyPolicy};

/// 入力 YAML の最大バイト数。実在の compose.yaml は数十 KiB のため、4 MiB で十分に余裕がある。
pub const COMPOSE_MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
/// ネストの最大深さ。`deploy.resources.reservations.devices[].capabilities[]` で 8 前後、`x-*` に余裕を見る。
const COMPOSE_MAX_DEPTH: usize = 32;
const COMPOSE_MAX_NODES: usize = 200_000;
const COMPOSE_MAX_EVENTS: usize = 800_000;
/// compose は `x-*` でアンカーを多用するため gpu の CDI spec より大きくする。
const COMPOSE_MAX_ANCHORS: usize = 1_024;
const COMPOSE_MAX_ALIASES: usize = 4_096;
const COMPOSE_MAX_MERGE_KEYS: usize = 1_024;
/// 2 件以上は構造化エラーにするが、走査自体の上限としても締める。
const COMPOSE_MAX_DOCUMENTS: usize = 8;
/// エイリアスの再生分を見込んだスカラーの総バイト数。
const COMPOSE_MAX_SCALAR_BYTES: usize = 16 * 1024 * 1024;
/// 1 アンカーあたりのエイリアス展開回数（既定は無制限のため締める）。
const COMPOSE_MAX_EXPANSIONS_PER_ANCHOR: usize = 1_024;
/// エイリアス爆弾への備えとしての再生イベントの総数。
const COMPOSE_MAX_REPLAYED_EVENTS: usize = 200_000;

/// 数値。YAML の推論結果を正規化したもの（非負整数は常に `PosInt`）。
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum ComposeNumber {
    /// 非負整数。
    PosInt(u64),
    /// 負の整数。
    NegInt(i64),
    /// 浮動小数点数。
    Float(f64),
}

/// 展開済みの YAML 値。後続の段が読む単一モデル。
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ComposeValue {
    /// null（`~`・空値）。
    Null,
    /// 真偽値。`strict_booleans` により `true` / `false` のみ（`yes` / `on` は文字列）。
    Bool(bool),
    /// 数値。
    Number(ComposeNumber),
    /// 文字列（補間前の生の値）。
    String(String),
    /// シーケンス。
    Sequence(Vec<ComposeValue>),
    /// マッピング。
    Mapping(ComposeMapping),
}

/// 出現順を保つ文字列キーのマッピング。キーは一意。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ComposeMapping {
    entries: Vec<(String, ComposeValue)>,
}

impl ComposeMapping {
    /// キーで値を引く。
    pub fn get(&self, key: &str) -> Option<&ComposeValue> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// 出現順の `(キー, 値)` を返す。マージで足されたキーは明示キーの後ろに並ぶ。
    pub fn iter(&self) -> impl Iterator<Item = (&str, &ComposeValue)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// エントリ数。
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// エントリが無いか。
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl ComposeValue {
    /// 文字列なら中身を返す。
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// 非負整数なら返す。
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(ComposeNumber::PosInt(n)) => Some(*n),
            _ => None,
        }
    }

    /// 真偽値なら返す。
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// シーケンスなら要素のスライスを返す。
    pub fn as_sequence(&self) -> Option<&[ComposeValue]> {
        match self {
            Self::Sequence(v) => Some(v),
            _ => None,
        }
    }

    /// マッピングなら返す。
    pub fn as_mapping(&self) -> Option<&ComposeMapping> {
        match self {
            Self::Mapping(m) => Some(m),
            _ => None,
        }
    }

    /// マッピングか。
    pub fn is_mapping(&self) -> bool {
        matches!(self, Self::Mapping(_))
    }

    /// マッピングならキーで値を引く。マッピング以外は `None`。
    pub fn get(&self, key: &str) -> Option<&ComposeValue> {
        self.as_mapping().and_then(|m| m.get(key))
    }
}

/// 展開済みの compose ドキュメント。トップレベルは必ずマッピング。
#[derive(Debug, Clone, PartialEq)]
pub struct ComposeDocument {
    root: ComposeMapping,
}

impl ComposeDocument {
    /// トップレベルのマッピング。
    pub fn root(&self) -> &ComposeMapping {
        &self.root
    }

    /// トップレベルのキーで値を引く。
    pub fn get(&self, key: &str) -> Option<&ComposeValue> {
        self.root.get(key)
    }
}

/// エラーの分類。ERR-1 の流儀（機械可読な大文字コード）に合わせる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ComposeParseErrorCode {
    /// 入力が不正（YAML 構文・重複キー・不正なマージ・未対応のタグ・文字列でないキー等）。
    InvalidArgument,
    /// 入力長またはパーサーの資源上限を超えた。
    ResourceExhausted,
    /// 未対応の構造（複数ドキュメント）。
    Unimplemented,
}

impl ComposeParseErrorCode {
    /// 機械可読なコード文字列。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::Unimplemented => "UNIMPLEMENTED",
        }
    }
}

/// 読み込みエラー。`message` は固定の英語文言で、入力の内容を含まない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeParseError {
    /// 分類。
    pub code: ComposeParseErrorCode,
    /// 固定文言。
    pub message: &'static str,
    /// 1 始まりの行（取れた場合）。
    pub line: Option<u64>,
    /// 1 始まりの列（取れた場合）。
    pub column: Option<u64>,
}

impl ComposeParseError {
    fn new(code: ComposeParseErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            line: None,
            column: None,
        }
    }
}

impl fmt::Display for ComposeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)?;
        if let (Some(l), Some(c)) = (self.line, self.column) {
            write!(f, " (line {l}, column {c})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ComposeParseError {}

/// `serde-saphyr` のエラーを、入力内容を含まない固定文言へ写す（Display にキー名が出るため保持しない）。
fn classify(err: &serde_saphyr::Error) -> ComposeParseError {
    use ComposeParseErrorCode as C;
    use serde_saphyr::Error as E;
    let (code, msg) = match err {
        E::Budget { .. }
        | E::AliasReplayLimitExceeded { .. }
        | E::AliasExpansionLimitExceeded { .. }
        | E::AliasReplayStackDepthExceeded { .. } => (
            C::ResourceExhausted,
            "compose file exceeds a parser resource limit",
        ),
        E::DuplicateMappingKey { .. } => (
            C::InvalidArgument,
            "compose file has a duplicate mapping key",
        ),
        E::UnsupportedTag { .. } => (
            C::InvalidArgument,
            "compose file uses an unsupported YAML tag",
        ),
        E::MergeValueNotMapOrSeqOfMaps { .. } | E::MergeKeyNotAllowed { .. } => {
            (C::InvalidArgument, "compose file has an invalid merge key")
        }
        E::RecursiveReferencesRequireWeakTypes { .. } => {
            (C::InvalidArgument, "compose file has a recursive alias")
        }
        _ => (C::InvalidArgument, "compose file is not valid YAML"),
    };
    let e = ComposeParseError::new(code, msg);
    match err.location() {
        Some(loc) => ComposeParseError {
            line: Some(loc.line()),
            column: Some(loc.column()),
            ..e
        },
        None => e,
    }
}

/// マッピングのキー専用の読み手。文字列以外は拒否する。
struct ComposeKey(String);

impl<'de> Deserialize<'de> for ComposeKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct KeyVisitor;
        impl Visitor<'_> for KeyVisitor {
            type Value = ComposeKey;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string mapping key")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<ComposeKey, E> {
                Ok(ComposeKey(v.to_owned()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<ComposeKey, E> {
                Ok(ComposeKey(v))
            }
        }
        d.deserialize_any(KeyVisitor)
    }
}

impl<'de> Deserialize<'de> for ComposeValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ValueVisitor;
        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = ComposeValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a YAML value")
            }
            fn visit_unit<E: de::Error>(self) -> Result<ComposeValue, E> {
                Ok(ComposeValue::Null)
            }
            fn visit_none<E: de::Error>(self) -> Result<ComposeValue, E> {
                Ok(ComposeValue::Null)
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<ComposeValue, E> {
                Ok(ComposeValue::Bool(v))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<ComposeValue, E> {
                Ok(ComposeValue::Number(match u64::try_from(v) {
                    Ok(n) => ComposeNumber::PosInt(n),
                    Err(_) => ComposeNumber::NegInt(v),
                }))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<ComposeValue, E> {
                Ok(ComposeValue::Number(ComposeNumber::PosInt(v)))
            }
            fn visit_i128<E: de::Error>(self, v: i128) -> Result<ComposeValue, E> {
                match i64::try_from(v) {
                    Ok(n) => self.visit_i64(n),
                    Err(_) => match u64::try_from(v) {
                        Ok(n) => self.visit_u64(n),
                        Err(_) => Err(E::custom("integer out of range")),
                    },
                }
            }
            fn visit_u128<E: de::Error>(self, v: u128) -> Result<ComposeValue, E> {
                match u64::try_from(v) {
                    Ok(n) => self.visit_u64(n),
                    Err(_) => Err(E::custom("integer out of range")),
                }
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<ComposeValue, E> {
                Ok(ComposeValue::Number(ComposeNumber::Float(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<ComposeValue, E> {
                Ok(ComposeValue::String(v.to_owned()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<ComposeValue, E> {
                Ok(ComposeValue::String(v))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ComposeValue, A::Error> {
                // size_hint は確保量に使わない（件数の上限はパーサーの Budget が持つ）。
                let mut items = Vec::new();
                while let Some(v) = seq.next_element::<ComposeValue>()? {
                    items.push(v);
                }
                Ok(ComposeValue::Sequence(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ComposeValue, A::Error> {
                let mut entries = Vec::new();
                let mut seen = BTreeSet::new();
                while let Some(ComposeKey(k)) = map.next_key::<ComposeKey>()? {
                    // 重複はパーサーも弾くが、防御として重ねて検査する。
                    if !seen.insert(k.clone()) {
                        return Err(de::Error::custom("duplicate mapping key"));
                    }
                    let v = map.next_value::<ComposeValue>()?;
                    entries.push((k, v));
                }
                Ok(ComposeValue::Mapping(ComposeMapping { entries }))
            }
        }
        d.deserialize_any(ValueVisitor)
    }
}

/// compose.yaml の文字列を読み、アンカー / エイリアス / マージキーを展開した [`ComposeDocument`] を返す。
///
/// 後続の段（#596 以降）から呼ばれる入口。パニックしない。上限・拒否条件はモジュール doc を参照。
pub fn parse_compose_yaml(input: &str) -> Result<ComposeDocument, ComposeParseError> {
    use ComposeParseErrorCode as C;
    if input.len() > COMPOSE_MAX_INPUT_BYTES {
        return Err(ComposeParseError::new(
            C::ResourceExhausted,
            "compose file input is too large",
        ));
    }
    let mut budget = serde_saphyr::Budget::default();
    budget.max_depth = COMPOSE_MAX_DEPTH;
    budget.max_nodes = COMPOSE_MAX_NODES;
    budget.max_events = COMPOSE_MAX_EVENTS;
    budget.max_anchors = COMPOSE_MAX_ANCHORS;
    budget.max_aliases = COMPOSE_MAX_ALIASES;
    budget.max_merge_keys = COMPOSE_MAX_MERGE_KEYS;
    budget.max_documents = COMPOSE_MAX_DOCUMENTS;
    budget.max_total_scalar_bytes = COMPOSE_MAX_SCALAR_BYTES;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    options.alias_limits.max_alias_expansions_per_anchor = COMPOSE_MAX_EXPANSIONS_PER_ANCHOR;
    options.alias_limits.max_total_replayed_events = COMPOSE_MAX_REPLAYED_EVENTS;
    options.duplicate_keys = DuplicateKeyPolicy::Error;
    options.merge_keys = MergeKeyPolicy::Merge;
    options.strict_booleans = true;
    // 未知のタグ（!custom・!reset・!override）を黙って捨てず拒否する（fail-closed）。
    options.reject_unsupported_tags = true;
    // エラーにソース断片（environment の値を含みうる）を付けさせない。
    options.with_snippet = false;
    options.emit_comments = false;

    let mut docs = serde_saphyr::from_multiple_with_options::<ComposeValue>(input, options)
        .map_err(|e| classify(&e))?;
    if docs.len() > 1 {
        return Err(ComposeParseError::new(
            C::Unimplemented,
            "multiple YAML documents in one compose file are not supported yet",
        ));
    }
    match docs.pop() {
        None => Err(ComposeParseError::new(
            C::InvalidArgument,
            "compose file has no YAML document",
        )),
        Some(ComposeValue::Mapping(root)) => Ok(ComposeDocument { root }),
        Some(_) => Err(ComposeParseError::new(
            C::InvalidArgument,
            "compose file top level must be a mapping",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ComposeParseErrorCode as C;

    fn err(input: &str) -> ComposeParseError {
        parse_compose_yaml(input).expect_err("must fail")
    }

    fn keys(m: &ComposeMapping) -> Vec<&str> {
        m.iter().map(|(k, _)| k).collect()
    }

    /// STACK-3: 明示キーはマージ由来に勝ち、`<<` は残らず、マージ分は後ろに並ぶ。
    #[test]
    fn merge_explicit_key_wins_in_either_order() {
        let doc = parse_compose_yaml(
            "b: &b {x: 1, y: 2}\nfirst:\n  <<: *b\n  x: 9\nsecond:\n  x: 9\n  <<: *b\n",
        )
        .unwrap();
        let first = doc.get("first").unwrap();
        assert_eq!(first.get("x").unwrap().as_u64(), Some(9));
        assert_eq!(first.get("y").unwrap().as_u64(), Some(2));
        assert!(first.get("<<").is_none());
        let second = doc.get("second").unwrap().as_mapping().unwrap();
        assert_eq!(second.get("x").unwrap().as_u64(), Some(9));
        assert_eq!(keys(second), vec!["x", "y"]);
    }

    /// STACK-3: `<<: [*a, *b]` の衝突では先のマッピングが勝つ。
    #[test]
    fn merge_sequence_first_mapping_wins() {
        let doc =
            parse_compose_yaml("a: &a {k: A}\nb: &b {k: B, z: 1}\nm:\n  <<: [*a, *b]\n").unwrap();
        let m = doc.get("m").unwrap();
        assert_eq!(m.get("k").unwrap().as_str(), Some("A"));
        assert_eq!(m.get("z").unwrap().as_u64(), Some(1));
    }

    /// STACK-3: 引用した `'<<'` は通常のキー。
    #[test]
    fn quoted_merge_key_is_plain_key() {
        let doc = parse_compose_yaml("m:\n  '<<': 1\n").unwrap();
        assert_eq!(doc.get("m").unwrap().get("<<").unwrap().as_u64(), Some(1));
    }

    /// STACK-3: strict_booleans により `yes` / `no` / `on` は文字列、`true` は bool。
    #[test]
    fn strict_booleans() {
        let doc = parse_compose_yaml("a: yes\nb: no\nc: on\nd: true\n").unwrap();
        assert_eq!(doc.get("a").unwrap().as_str(), Some("yes"));
        assert_eq!(doc.get("b").unwrap().as_str(), Some("no"));
        assert_eq!(doc.get("c").unwrap().as_str(), Some("on"));
        assert_eq!(doc.get("d").unwrap().as_bool(), Some(true));
    }

    /// STACK-3: 数値は正規化される。
    #[test]
    fn numbers() {
        let doc = parse_compose_yaml("p: 7\nn: -3\nf: 1.5\nz: ~\n").unwrap();
        assert_eq!(
            doc.get("p"),
            Some(&ComposeValue::Number(ComposeNumber::PosInt(7)))
        );
        assert_eq!(
            doc.get("n"),
            Some(&ComposeValue::Number(ComposeNumber::NegInt(-3)))
        );
        assert_eq!(
            doc.get("f"),
            Some(&ComposeValue::Number(ComposeNumber::Float(1.5)))
        );
        assert_eq!(doc.get("z"), Some(&ComposeValue::Null));
    }

    /// STACK-3・REPAIR-12: 明示の重複キーは拒否。
    #[test]
    fn duplicate_key_rejected() {
        let e = err("a: 1\na: 2\n");
        assert_eq!(e.code, C::InvalidArgument);
        assert_eq!(e.message, "compose file has a duplicate mapping key");
    }

    /// STACK-3・REPAIR-12: 再帰エイリアスは拒否（パニックしない）。
    #[test]
    fn recursive_alias_rejected() {
        let e = err("a: &a [*a]\n");
        assert_eq!(e.code, C::InvalidArgument);
    }

    /// STACK-3・REPAIR-12: スカラーへのマージは拒否。
    #[test]
    fn merge_of_scalar_rejected() {
        let e = err("s: &s 1\nm:\n  <<: *s\n");
        assert_eq!(e.code, C::InvalidArgument);
        assert_eq!(e.message, "compose file has an invalid merge key");
    }

    /// STACK-3・REPAIR-3: 複数ドキュメントは黙って先頭を採らず未実装とする。
    #[test]
    fn multiple_documents_unimplemented() {
        let e = err("a: 1\n---\nb: 2\n");
        assert_eq!(e.code, C::Unimplemented);
    }

    /// STACK-3: 空・トップレベルが非マッピングは InvalidArgument。
    #[test]
    fn empty_and_non_mapping_top_level() {
        // null だけのドキュメントもパーサーは 0 件として返す。
        for input in ["", "---\n---\n", "~\n"] {
            let e = err(input);
            assert_eq!(e.code, C::InvalidArgument, "{input:?}");
            assert_eq!(e.message, "compose file has no YAML document");
        }
        for input in ["- a\n", "scalar\n"] {
            let e = err(input);
            assert_eq!(e.code, C::InvalidArgument, "{input:?}");
            assert_eq!(e.message, "compose file top level must be a mapping");
        }
    }

    /// REPAIR-12: 入力長の上限超過はパーサーに渡さず ResourceExhausted。
    #[test]
    fn oversized_input_rejected() {
        let e = err(&"a".repeat(COMPOSE_MAX_INPUT_BYTES + 1));
        assert_eq!(e.code, C::ResourceExhausted);
        assert_eq!(e.message, "compose file input is too large");
    }

    /// REPAIR-12: 深いネストは ResourceExhausted。
    #[test]
    fn deep_nesting_rejected() {
        let n = COMPOSE_MAX_DEPTH + 1;
        let e = err(&format!("a: {}1{}\n", "[".repeat(n), "]".repeat(n)));
        assert_eq!(e.code, C::ResourceExhausted);
    }

    /// REPAIR-12: 1 アンカーの過剰な展開は ResourceExhausted。
    #[test]
    fn alias_expansion_limit() {
        let mut s = String::from("a: &a x\nl:\n");
        for _ in 0..=COMPOSE_MAX_EXPANSIONS_PER_ANCHOR {
            s.push_str("  - *a\n");
        }
        let e = err(&s);
        assert_eq!(e.code, C::ResourceExhausted);
    }

    /// STACK-3: タグ付きの値は黙って捨てず拒否する。
    #[test]
    fn tags_rejected() {
        for input in ["a: !custom foo\n", "a: !reset []\n"] {
            let e = err(input);
            assert_eq!(e.code, C::InvalidArgument, "{input:?}");
            assert_eq!(e.message, "compose file uses an unsupported YAML tag");
        }
    }

    /// STACK-3: 文字列でないキーは拒否する。
    #[test]
    fn non_string_keys_rejected() {
        for input in ["1: a\n", "true: a\n", "~: a\n"] {
            assert_eq!(err(input).code, C::InvalidArgument, "{input:?}");
        }
    }

    /// SEC-1: エラーに入力のキー名・値を載せない。
    #[test]
    fn errors_do_not_leak_input() {
        let e = err("environment:\n  TOKEN: SECRET-SENTINEL-1234\n  TOKEN: other\n");
        for text in [e.to_string(), format!("{e:?}"), e.message.to_string()] {
            assert!(!text.contains("SECRET-SENTINEL-1234"), "{text}");
            assert!(!text.contains("TOKEN"), "{text}");
        }
    }
}
