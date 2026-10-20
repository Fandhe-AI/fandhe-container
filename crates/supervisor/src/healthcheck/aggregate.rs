//! healthcheck の判定結果の集約（retries・start_period。TASK-161.3・#496・SUP-4・MS-9。関連: SUP-1・REPAIR-3・REPAIR-5）。
//!
//! 役割: 周期実行 [`super::run_periodic`] が tick ごとに得る probe の結果を、`state.json` の `health` へ書く値
//! （`Starting` / `Healthy` / `Unhealthy`）へ畳み込む。stack の `depends_on`（healthy 条件。STACK-2・TASK-150）が
//! 読むのはこの値なので、1 回の失敗で `Unhealthy` を公開せず、retries 回続けて失敗したときだけ `Unhealthy` にする。
//! 呼び出し元は `periodic` の `run_periodic`（`crate::health::probe_aggregate_and_record` へ閉包で渡す）。
//!
//! # 遷移の規則（spec の SUP-4 は遷移を定めていないため、本実装の判断であり spec 確定値ではない）
//! - 成功は `Ok(Healthy)` だけ。`Ok(Unhealthy)`・`Ok(Starting)`・`Err`（`Timeout`・`Internal`・`Unimplemented`・
//!   `Unavailable` を含む）はすべて失敗に数える（fail-closed。判定が終わらない状態を健全とみなさない）。
//! - 成功で連続失敗数を 0 に戻し `Healthy`。まだ一度も成功しておらず、開始から start_period 未満の間の失敗は数えない。
//! - それ以外の失敗は数え、`retries` 回に達したら `Unhealthy`。届かない間は現在値を保つ（未設定なら `Starting`）。

use std::num::NonZeroU32;
use std::time::Duration;

use fandhe_container_core::traits::{HealthStatus, TraitError};

use super::periodic::HealthcheckSchedule;

/// 連続失敗数と start_period から、書くべき `health` を決める集約器（1 つの周期実行につき 1 つ）。
#[derive(Debug, Clone)]
pub struct HealthAggregator {
    retries: NonZeroU32,
    start_period: Duration,
    consecutive_failures: u32,
    succeeded: bool,
}

impl HealthAggregator {
    /// retries 回の連続失敗で `Unhealthy` とする集約器を作る。
    pub fn new(retries: NonZeroU32, start_period: Duration) -> Self {
        Self {
            retries,
            start_period,
            consecutive_failures: 0,
            succeeded: false,
        }
    }

    /// スケジュールの retries・start_period から作る。
    pub fn from_schedule(schedule: &HealthcheckSchedule) -> Self {
        Self::new(schedule.retries(), schedule.start_period())
    }

    /// 現在の連続失敗数（start_period 中の失敗は含まない）。
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// probe の結果 1 件を取り込み、書くべき `health` を返す。
    ///
    /// `elapsed` は周期実行の開始から probe を呼ぶ直前までの経過、`current` は最新レコードの `health`。
    pub fn observe(
        &mut self,
        result: &Result<HealthStatus, TraitError>,
        elapsed: Duration,
        current: Option<HealthStatus>,
    ) -> HealthStatus {
        if matches!(result, Ok(HealthStatus::Healthy)) {
            self.consecutive_failures = 0;
            self.succeeded = true;
            return HealthStatus::Healthy;
        }
        let hold = current.unwrap_or(HealthStatus::Starting);
        if !self.succeeded && elapsed < self.start_period {
            return hold;
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= self.retries.get() {
            HealthStatus::Unhealthy
        } else {
            hold
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::traits::ErrorCode;

    const S: Duration = Duration::from_secs(1);

    fn agg(retries: u32, start: Duration) -> HealthAggregator {
        HealthAggregator::new(NonZeroU32::new(retries).unwrap(), start)
    }

    fn bad() -> Result<HealthStatus, TraitError> {
        Ok(HealthStatus::Unhealthy)
    }
    fn good() -> Result<HealthStatus, TraitError> {
        Ok(HealthStatus::Healthy)
    }

    /// 現在値を追従しながら列を流し、(書く値, 失敗数) を返す。
    fn feed(
        a: &mut HealthAggregator,
        seq: &[Result<HealthStatus, TraitError>],
    ) -> Vec<(HealthStatus, u32)> {
        let mut cur = Some(HealthStatus::Starting);
        let mut out = Vec::new();
        for r in seq {
            let h = a.observe(r, Duration::from_secs(100), cur);
            cur = Some(h);
            out.push((h, a.consecutive_failures()));
        }
        out
    }

    /// SUP-4・TASK-161.3: retries=3 で失敗 3 回続くと Unhealthy。
    #[test]
    fn sup4_aggregate_unhealthy_after_retries() {
        let mut a = agg(3, Duration::ZERO);
        assert_eq!(
            feed(&mut a, &[bad(), bad(), bad()]),
            vec![
                (HealthStatus::Starting, 1),
                (HealthStatus::Starting, 2),
                (HealthStatus::Unhealthy, 3)
            ]
        );
    }

    /// SUP-4・TASK-161.3: Healthy は retries 回目の失敗まで保たれる。
    #[test]
    fn sup4_aggregate_healthy_holds_until_retries() {
        let mut a = agg(3, Duration::ZERO);
        let r = feed(&mut a, &[good(), bad(), bad(), bad()]);
        let h: Vec<_> = r.iter().map(|x| x.0).collect();
        assert_eq!(
            h,
            vec![
                HealthStatus::Healthy,
                HealthStatus::Healthy,
                HealthStatus::Healthy,
                HealthStatus::Unhealthy
            ]
        );
    }

    /// SUP-4・TASK-161.3: 成功で連続失敗数が戻る。
    #[test]
    fn sup4_aggregate_success_resets() {
        let mut a = agg(3, Duration::ZERO);
        let r = feed(&mut a, &[bad(), bad(), good(), bad(), bad(), bad()]);
        assert_eq!(r[2], (HealthStatus::Healthy, 0));
        assert_eq!(r[4], (HealthStatus::Healthy, 2));
        assert_eq!(r[5], (HealthStatus::Unhealthy, 3));
    }

    /// SUP-4・TASK-161.3: start_period 中の失敗は数えず、過ぎれば数える。成功すると start_period は終わる。
    #[test]
    fn sup4_aggregate_start_period() {
        let mut a = agg(2, 12 * S);
        assert_eq!(a.observe(&bad(), 5 * S, None), HealthStatus::Starting);
        assert_eq!(a.consecutive_failures(), 0);
        assert_eq!(
            a.observe(&bad(), 12 * S, Some(HealthStatus::Starting)),
            HealthStatus::Starting
        );
        assert_eq!(a.consecutive_failures(), 1);
        assert_eq!(
            a.observe(&bad(), 15 * S, Some(HealthStatus::Starting)),
            HealthStatus::Unhealthy
        );

        let mut b = agg(2, 12 * S);
        assert_eq!(b.observe(&good(), 5 * S, None), HealthStatus::Healthy);
        b.observe(&bad(), 6 * S, Some(HealthStatus::Healthy));
        assert_eq!(b.consecutive_failures(), 1);
    }

    /// SUP-4・TASK-161.3: エラーと Starting も失敗に数える（fail-closed）。
    #[test]
    fn sup4_aggregate_errors_count_as_failure() {
        for code in [
            ErrorCode::Timeout,
            ErrorCode::Internal,
            ErrorCode::Unavailable,
            ErrorCode::Unimplemented,
        ] {
            let mut a = agg(1, Duration::ZERO);
            let e: Result<HealthStatus, TraitError> = Err(TraitError::new(code, "x"));
            assert_eq!(a.observe(&e, S, None), HealthStatus::Unhealthy);
        }
        let mut a = agg(1, Duration::ZERO);
        assert_eq!(
            a.observe(&Ok(HealthStatus::Starting), S, None),
            HealthStatus::Unhealthy
        );
    }

    /// SUP-4・TASK-161.3: retries=1 は 1 回目の失敗で Unhealthy。
    #[test]
    fn sup4_aggregate_retries_one() {
        let mut a = agg(1, Duration::ZERO);
        assert_eq!(feed(&mut a, &[bad()]), vec![(HealthStatus::Unhealthy, 1)]);
    }
}
