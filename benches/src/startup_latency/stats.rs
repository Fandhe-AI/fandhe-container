//! p95 などの順位統計（nearest-rank 法。TASK-190・REPAIR-8）。

use std::time::Duration;

/// nearest-rank 法のパーセンタイル。昇順に並べ、順位 `r = ceil(pct * n / 100)` の要素（添字 `r - 1`）を返す。
/// 空の入力・`pct` が 1〜100 の外は `None`。入力は並べ替えずコピーを使う。
pub fn percentile_nearest_rank(samples: &[Duration], pct: u32) -> Option<Duration> {
    if samples.is_empty() || pct == 0 || pct > 100 {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort();
    let n = u64::try_from(sorted.len()).ok()?;
    let rank = n.checked_mul(u64::from(pct))?.div_ceil(100);
    let index = usize::try_from(rank.checked_sub(1)?).ok()?;
    sorted.get(index).copied()
}

/// 標本の要約（診断用の p50・max を含む）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub samples: usize,
    pub p50: Duration,
    pub p95: Duration,
    pub max: Duration,
}

/// 要約を作る。空なら `None`。
pub fn summarize(samples: &[Duration]) -> Option<Summary> {
    Some(Summary {
        samples: samples.len(),
        p50: percentile_nearest_rank(samples, 50)?,
        p95: percentile_nearest_rank(samples, 95)?,
        max: samples.iter().copied().max()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    fn range(n: u64) -> Vec<Duration> {
        (1..=n).map(ms).collect()
    }

    /// REPAIR-8: n=1 は唯一の標本。
    #[test]
    fn single_sample_is_its_own_p95() {
        assert_eq!(percentile_nearest_rank(&[ms(7)], 95), Some(ms(7)));
    }

    #[test]
    fn n20_p95_is_19_and_p50_is_10() {
        let s = range(20);
        assert_eq!(percentile_nearest_rank(&s, 95), Some(ms(19)));
        assert_eq!(percentile_nearest_rank(&s, 50), Some(ms(10)));
    }

    #[test]
    fn n100_p95_is_95() {
        assert_eq!(percentile_nearest_rank(&range(100), 95), Some(ms(95)));
    }

    #[test]
    fn n101_p95_is_96() {
        assert_eq!(percentile_nearest_rank(&range(101), 95), Some(ms(96)));
    }

    #[test]
    fn input_order_does_not_matter() {
        let mut s = range(20);
        s.reverse();
        assert_eq!(percentile_nearest_rank(&s, 95), Some(ms(19)));
    }

    #[test]
    fn empty_and_out_of_range_are_none() {
        assert_eq!(percentile_nearest_rank(&[], 95), None);
        assert_eq!(percentile_nearest_rank(&[ms(1)], 0), None);
        assert_eq!(percentile_nearest_rank(&[ms(1)], 101), None);
        assert_eq!(summarize(&[]), None);
    }

    #[test]
    fn summary_has_p50_p95_max() {
        let s = summarize(&range(20)).expect("summary");
        assert_eq!(
            s,
            Summary {
                samples: 20,
                p50: ms(10),
                p95: ms(19),
                max: ms(20)
            }
        );
    }
}
