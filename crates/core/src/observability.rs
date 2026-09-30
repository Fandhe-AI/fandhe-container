//! 観測性（メトリクス）の集計型（REPAIR-4・TASK-84.1）。
//!
//! read / write / create / start 等の各操作について、成功・失敗カウントとレイテンシ分布
//! （min・mean・p95・max。PoC-8 の `op_stats` 相当）を表す固定スキーマの値型だけを定義する。
//! 後続の記録・出力・計装はこの型の上に積まれる。「壊れた値を表現できない型」（REPAIR-2）とし、
//! 生成は検証つきコンストラクタのみ、フィールドは private にして構築後の矛盾を防ぐ。
//! エラーは拡張点トレイトと共通の [`TraitError`]（`ErrorCode::InvalidArgument`。ERR-1）。
//!
//! # 未実装範囲（REPAIR-3）
//!
//! 本モジュールは型定義のみで、以下は未実装である。
//!
//! - レイテンシの記録・p95 の算出方式（nearest-rank かヒストグラム近似か）・スレッドセーフな集計: TASK-84.2
//! - 構造化ログ / JSON Lines での出力: TASK-84.3
//! - create / start / kill / delete への計装: TASK-84.4
//! - io の read / write 向け連携点と io 側の計装: TASK-84.5・TASK-84.7
//! - 結合テスト: TASK-84.6

use std::fmt;
use std::time::Duration;

use crate::traits::{ErrorCode, TraitError};

/// 操作名の許容バイト数の上限。ログのフィールドとして出すため短く抑える。
pub const OP_NAME_MAX_LEN: usize = 64;

/// 検証済みの操作名（`read`・`write`・`create`・`start` 等）。
///
/// TASK-84.3 で JSON Lines のキー / 値として出力するため、`[A-Za-z0-9._-]` かつ
/// [`OP_NAME_MAX_LEN`] バイト以下に限り、改行・引用符・制御文字によるログ行の偽装や分割を
/// 型の段階で防ぐ。閉じた enum にしないのは、TASK-84.5 で io 側の操作名を core に依存せず
/// 渡す方式が未決定のため。資格情報やホスト側の実パスをログのフィールドになる操作名に入れない。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpName(String);

impl OpName {
    /// 入力文字列を検証して操作名を作る。
    ///
    /// 空文字列・上限長超過・`[A-Za-z0-9._-]` 以外の文字を含む場合は
    /// `ErrorCode::InvalidArgument` を返す。
    pub fn new(value: impl Into<String>) -> Result<Self, TraitError> {
        let value = value.into();
        if value.is_empty() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "operation name must not be empty",
            ));
        }
        if value.len() > OP_NAME_MAX_LEN {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                format!("operation name must be at most {OP_NAME_MAX_LEN} bytes"),
            ));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "operation name must match [A-Za-z0-9._-]",
            ));
        }
        Ok(Self(value))
    }

    /// 検証済み文字列への参照を返す。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OpName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for OpName {
    type Error = TraitError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for OpName {
    type Error = TraitError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// レイテンシ分布の要約（min・mean・p95・max。REPAIR-4）。
///
/// `Duration` のため負値は表現できず、`min <= mean <= max` かつ `min <= p95 <= max` を
/// 構築時に保証する。p95 は 95 パーセンタイルの推定値という契約のみを持ち、算出方式は
/// TASK-84.2 で決める（REPAIR-3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencySummary {
    min: Duration,
    mean: Duration,
    p95: Duration,
    max: Duration,
}

impl LatencySummary {
    /// 4 値の順序関係を検証して要約を作る。
    ///
    /// `min > max`、または `mean`・`p95` が `[min, max]` の外にある場合は
    /// `ErrorCode::InvalidArgument` を返す。
    pub fn new(
        min: Duration,
        mean: Duration,
        p95: Duration,
        max: Duration,
    ) -> Result<Self, TraitError> {
        if min > max {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "latency min must not exceed max",
            ));
        }
        if mean < min || mean > max {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "latency mean must be within [min, max]",
            ));
        }
        if p95 < min || p95 > max {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "latency p95 must be within [min, max]",
            ));
        }
        Ok(Self {
            min,
            mean,
            p95,
            max,
        })
    }

    /// 最小レイテンシ。
    pub fn min(&self) -> Duration {
        self.min
    }

    /// 平均レイテンシ。
    pub fn mean(&self) -> Duration {
        self.mean
    }

    /// 95 パーセンタイルの推定値。
    pub fn p95(&self) -> Duration {
        self.p95
    }

    /// 最大レイテンシ。
    pub fn max(&self) -> Duration {
        self.max
    }
}

/// 操作 1 種類分の集計スナップショット（REPAIR-4・PoC-8 の `op_stats` 相当）。
///
/// 成功数・失敗数の合計が `u64` に収まること、および 0 件なのにレイテンシがある矛盾が
/// ないことを構築時に保証する。件数 1 以上でレイテンシを必須にはしない
/// （失敗やサンプリングをレイテンシに含めるかは TASK-84.2 で決める）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpStats {
    name: OpName,
    success: u64,
    failure: u64,
    latency: Option<LatencySummary>,
}

impl OpStats {
    /// 集計スナップショットを作る。
    ///
    /// `success + failure` が `u64` を超える場合、または 0 件なのに `latency` が
    /// `Some` の場合は `ErrorCode::InvalidArgument` を返す。
    pub fn new(
        name: OpName,
        success: u64,
        failure: u64,
        latency: Option<LatencySummary>,
    ) -> Result<Self, TraitError> {
        let Some(total) = success.checked_add(failure) else {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "total operation count must fit in u64",
            ));
        };
        if total == 0 && latency.is_some() {
            return Err(TraitError::new(
                ErrorCode::InvalidArgument,
                "latency must be absent when no operations were recorded",
            ));
        }
        Ok(Self {
            name,
            success,
            failure,
            latency,
        })
    }

    /// 操作名。
    pub fn name(&self) -> &OpName {
        &self.name
    }

    /// 成功件数。
    pub fn success(&self) -> u64 {
        self.success
    }

    /// 失敗件数。
    pub fn failure(&self) -> u64 {
        self.failure
    }

    /// レイテンシ分布の要約（未計測なら `None`）。
    pub fn latency(&self) -> Option<&LatencySummary> {
        self.latency.as_ref()
    }

    /// 成功と失敗の合計件数（構築時に桁あふれしないことを保証済み）。
    pub fn total(&self) -> u64 {
        self.success.saturating_add(self.failure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    fn code<T: fmt::Debug>(r: Result<T, TraitError>) -> ErrorCode {
        r.expect_err("must be rejected").code()
    }

    #[test]
    fn repair4_op_name_accepts_valid() {
        assert_eq!(OpName::new("create").unwrap().as_str(), "create");
        assert_eq!(OpName::new("a.b_c-1").unwrap().to_string(), "a.b_c-1");
        assert!(OpName::new("a".repeat(OP_NAME_MAX_LEN)).is_ok());
    }

    #[test]
    fn repair4_op_name_rejects_invalid() {
        let cases = [
            String::new(),
            "a".repeat(OP_NAME_MAX_LEN + 1),
            "a/b".to_string(),
            "a b".to_string(),
            "作成".to_string(),
            "\n".to_string(),
        ];
        for c in cases {
            assert_eq!(code(OpName::new(c)), ErrorCode::InvalidArgument);
        }
    }

    #[test]
    fn repair4_latency_accepts_ordered_values() {
        let l = LatencySummary::new(ms(1), ms(3), ms(5), ms(6)).unwrap();
        assert_eq!(
            (l.min(), l.mean(), l.p95(), l.max()),
            (ms(1), ms(3), ms(5), ms(6))
        );
        assert!(LatencySummary::new(ms(2), ms(2), ms(2), ms(2)).is_ok());
    }

    #[test]
    fn repair4_latency_rejects_min_above_max() {
        assert_eq!(
            code(LatencySummary::new(ms(7), ms(7), ms(7), ms(6))),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_latency_rejects_mean_below_min() {
        assert_eq!(
            code(LatencySummary::new(ms(2), ms(1), ms(3), ms(6))),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_latency_rejects_mean_above_max() {
        assert_eq!(
            code(LatencySummary::new(ms(1), ms(7), ms(3), ms(6))),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_latency_rejects_p95_below_min() {
        assert_eq!(
            code(LatencySummary::new(ms(2), ms(3), ms(1), ms(6))),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_latency_rejects_p95_above_max() {
        assert_eq!(
            code(LatencySummary::new(ms(1), ms(3), ms(7), ms(6))),
            ErrorCode::InvalidArgument
        );
    }

    fn name() -> OpName {
        OpName::new("read").unwrap()
    }

    #[test]
    fn repair4_op_stats_total_and_accessors() {
        let l = LatencySummary::new(ms(1), ms(3), ms(5), ms(6)).unwrap();
        let s = OpStats::new(name(), 3, 2, Some(l)).unwrap();
        assert_eq!(s.name().as_str(), "read");
        assert_eq!((s.success(), s.failure(), s.total()), (3, 2, 5));
        assert_eq!(s.latency(), Some(&l));
    }

    #[test]
    fn repair4_op_stats_rejects_count_overflow() {
        assert_eq!(
            code(OpStats::new(name(), u64::MAX, 1, None)),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_op_stats_rejects_latency_without_operations() {
        let l = LatencySummary::new(ms(1), ms(1), ms(1), ms(1)).unwrap();
        assert_eq!(
            code(OpStats::new(name(), 0, 0, Some(l))),
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn repair4_op_stats_accepts_boundaries() {
        assert_eq!(OpStats::new(name(), 0, 0, None).unwrap().total(), 0);
        assert_eq!(OpStats::new(name(), 5, 0, None).unwrap().total(), 5);
        assert_eq!(
            OpStats::new(name(), u64::MAX, 0, None).unwrap().total(),
            u64::MAX
        );
    }
}
