//! コンテナの label（`--label key=value`）の指定モデル（SUP-12・TASK-169.5.1・#855・MS-9）。
//!
//! # 役割と呼び出し文脈
//!
//! [`super::ContainerOptions`] が保持する label の入口。`--label` 文字列を検証済みの [`Label`] へ解釈し、
//! [`Labels`] で 1 つの集合へ統合する。結果は [`Labels::annotations`] で core の
//! [`Annotations`] として取り出せ、`CreateStateRequest::with_annotations` へ渡すと
//! core の `FileStateStore` が `state.json` の `annotations`（OCI state の任意項目）へ永続化する
//! （supervisor は状態型・シリアライズを持たない。crate-naming.md 決定 6）。
//!
//! label はランタイムの挙動を変えない純粋なメタデータで、分離・権限・cgroup の判断には使わない。
//! 件数・長さ・キー形式の上限は core の [`Annotations`] が単一の真実源で、ここでは二重管理しない。
//! OS 非依存で 3 OS でビルド・テストする。
//!
//! # 解釈規則
//!
//! - `key=value` は最初の `=` で分割する（値に `=` を含められる）。
//! - `=` の無い `key` は値が空文字（Docker 準拠）。env の値なし拒否（ホスト環境の漏洩防止）とは異なり、
//!   label はホスト環境を参照しないため許可する。
//! - 同一キーは後勝ち（Docker 準拠）。
//!
//! # 対応しないもの（REPAIR-3）
//!
//! - CLI・本番 launcher から `CreateStateRequest` への結線は未実装（TASK-79・後続作業）。
//! - `inspect` 出力への反映・label によるフィルタは未実装（固定キー順契約は TASK-168.2 の関心事）。
//!
//! # 外部入力の扱い
//!
//! 入力長を確保前に上限検証してから分解する。エラーメッセージは core の固定英語文言で、入力値は含めない。
//! label は秘密情報の置き場ではないため `Debug` は伏せない（env と異なる）。

use fandhe_container_core::traits::types::{ErrorCode, TraitError};
use fandhe_container_core::traits::{ANNOTATIONS_MAX_TOTAL_BYTES, Annotations};

/// `--label` 1 件の最大バイト数（`key` + `=` + `value`。core の合計上限に `=` 分を足した値）。
const LABEL_MAX_INPUT_BYTES: usize = ANNOTATIONS_MAX_TOTAL_BYTES + 1;

/// `key=value` 1 件（検証済み）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    key: String,
    value: String,
}

impl Label {
    /// `--label key=value`（または値なしの `key`）を解釈する。
    ///
    /// キーが空・NUL / `=` / 制御文字を含む、値が NUL を含む、長さが上限超過のときは `InvalidArgument`。
    pub fn parse(input: &str) -> Result<Self, TraitError> {
        if input.len() > LABEL_MAX_INPUT_BYTES {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "label is too long",
            ));
        }
        let (key, value) = input.split_once('=').unwrap_or((input, ""));
        // 形式検証は core の Annotations に委ねる（上限・キー規則の二重管理を避ける）。
        Annotations::new([(key.to_owned(), value.to_owned())])?;
        Ok(Self {
            key: key.to_owned(),
            value: value.to_owned(),
        })
    }

    /// キー。
    pub fn key(&self) -> &str {
        &self.key
    }

    /// 値（値なしの指定では空文字）。
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// 統合済みの label 集合（同一キーは後勝ち・キー昇順）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Labels {
    annotations: Annotations,
}

impl Labels {
    /// 指定順の label を 1 つの集合へ統合する。
    ///
    /// 件数（`ANNOTATIONS_MAX_ENTRIES`）・合計長の超過は `InvalidArgument`。同一キーは後勝ち。
    pub fn resolve(labels: Vec<Label>) -> Result<Self, TraitError> {
        let annotations = Annotations::new(labels.into_iter().map(|l| (l.key, l.value)))?;
        Ok(Self { annotations })
    }

    /// `CreateStateRequest::with_annotations` へ渡す core の型。
    pub fn annotations(&self) -> &Annotations {
        &self.annotations
    }

    /// キー昇順の (key, value) 列。
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.annotations.iter()
    }

    /// 件数。
    pub fn len(&self) -> usize {
        self.annotations.len()
    }

    /// 空かどうか。
    pub fn is_empty(&self) -> bool {
        self.annotations.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::{ANNOTATION_MAX_KEY_BYTES, ANNOTATIONS_MAX_ENTRIES};

    fn kv(s: &str) -> (String, String) {
        let l = Label::parse(s).unwrap();
        (l.key().to_owned(), l.value().to_owned())
    }

    /// SUP-12・TASK-169.5.1: `a=b`・値空・値なし・値に `=`・非 ASCII を具体値で照合する。
    #[test]
    fn sup12_label_parse_valid_forms() {
        assert_eq!(kv("a=b"), ("a".into(), "b".into()));
        assert_eq!(kv("a="), ("a".into(), "".into()));
        assert_eq!(kv("a"), ("a".into(), "".into()));
        assert_eq!(kv("a=b=c"), ("a".into(), "b=c".into()));
        assert_eq!(
            kv("com.example.app=日本語"),
            ("com.example.app".into(), "日本語".into())
        );
        assert_eq!(kv("k= v "), ("k".into(), " v ".into()));
    }

    /// SUP-12・TASK-169.5.1: 不正な指定は InvalidArgument で拒否する。
    #[test]
    fn sup12_label_parse_rejects_invalid() {
        let long_key = format!("{}=v", "k".repeat(ANNOTATION_MAX_KEY_BYTES + 1));
        let long_all = format!("a={}", "v".repeat(LABEL_MAX_INPUT_BYTES));
        for bad in [
            "",
            "=v",
            "a\0=v",
            "a=v\0",
            "a\n=v",
            "a\x07=v",
            long_key.as_str(),
            long_all.as_str(),
        ] {
            let e = Label::parse(bad).unwrap_err();
            assert_eq!(e.code(), ErrorCode::InvalidArgument, "{bad:?}");
        }
    }

    /// SUP-12・TASK-169.5.1: 同一キーは後勝ち、件数・合計の超過は拒否する。
    #[test]
    fn sup12_labels_resolve_last_wins_and_limits() {
        let l = Labels::resolve(vec![
            Label::parse("b=1").unwrap(),
            Label::parse("a=x").unwrap(),
            Label::parse("b=2").unwrap(),
        ])
        .unwrap();
        assert_eq!(l.iter().collect::<Vec<_>>(), [("a", "x"), ("b", "2")]);
        assert_eq!(l.len(), 2);
        assert!(Labels::default().is_empty());

        let many: Vec<Label> = (0..=ANNOTATIONS_MAX_ENTRIES)
            .map(|i| Label::parse(&format!("k{i}=v")).unwrap())
            .collect();
        assert_eq!(
            Labels::resolve(many).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
        let big: Vec<Label> = (0..3)
            .map(|i| Label::parse(&format!("k{i}={}", "v".repeat(3000))).unwrap())
            .collect();
        assert_eq!(
            Labels::resolve(big).unwrap_err().code(),
            ErrorCode::InvalidArgument
        );
    }
}
