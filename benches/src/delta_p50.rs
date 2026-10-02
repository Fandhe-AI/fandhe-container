//! 境界越し p50 と同一プロセス p50 の差分 Δp50 と、CORE-10 の Linux 実機値に対する割合の
//! 算出（TASK-113.3・PLUG-5・PLUG-6・CORE-10・REPAIR-8）。
//!
//! 役割: 純粋な算術とログ行の整形だけを持つ。`plugin_boundary`（代表操作 A）と
//! `plugin_boundary_list_images`（代表操作 B）の両ベンチ（`benches/benches/*.rs`）から呼ばれ、
//! 結果 JSON の Δp50 metric と stderr の構造化ログ行の元になる。両ベンチの `BenchError` は別型のため、
//! 本モジュールは独自の [`DeltaError`] を返し、呼び出し側が自分のエラー型へ変換する。
//!
//! 回帰判定そのもの（15% 超の悪化で非ゼロ終了）は `scripts/check-bench-regression.sh` が担う。
//! 本モジュールは判定しない。CORE-10 比は固定定数に対する割合で、回帰 metric ではなくログ専用。
//!
//! fail-closed: Δ が 0 以下・非有限の場合は 0 へ丸めず [`DeltaError`] を返す。

use std::fmt;

/// CORE-10 の Linux 実機値の下限（秒）。
pub const CORE10_LINUX_LOW_S: f64 = 0.290;
/// CORE-10 の Linux 実機値の上限（秒）。
pub const CORE10_LINUX_HIGH_S: f64 = 0.298;

/// Δp50 の算出失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaError {
    /// 境界越し p50 が同一プロセス p50 以下（計測異常）。
    NonPositiveDelta,
    /// 入力が有限でない、または負。
    NonFinite,
    /// 往復回数が 0。
    InvalidRoundTrips,
}

impl DeltaError {
    /// 機械可読なエラーコード。
    pub fn code(self) -> &'static str {
        match self {
            DeltaError::NonPositiveDelta => "non-positive-delta",
            DeltaError::NonFinite => "non-finite",
            DeltaError::InvalidRoundTrips => "invalid-round-trips",
        }
    }
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = match self {
            DeltaError::NonPositiveDelta => "framed p50 must exceed in-process p50",
            DeltaError::NonFinite => "p50 values must be finite and non-negative",
            DeltaError::InvalidRoundTrips => "round trips must be at least 1",
        };
        f.write_str(m)
    }
}

impl std::error::Error for DeltaError {}

/// Δp50 と CORE-10 比。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Delta {
    /// 計測区間全体の Δp50（ns。PLUG-5 の N×Δp50）。
    pub total_ns: f64,
    /// 1 往復あたりの Δp50（ns）。
    pub per_round_trip_ns: f64,
    /// 計測区間の往復回数 N。
    pub round_trips: u32,
    /// `total_ns` の CORE-10 下限値（0.290 秒）に対する割合（%）。
    pub core10_ratio_low_percent: f64,
    /// `total_ns` の CORE-10 上限値（0.298 秒）に対する割合（%）。
    pub core10_ratio_high_percent: f64,
}

/// Δp50 と CORE-10 比を算出する。値は ns。
pub fn compute(inproc_ns: f64, framed_ns: f64, round_trips: u32) -> Result<Delta, DeltaError> {
    if round_trips == 0 {
        return Err(DeltaError::InvalidRoundTrips);
    }
    let valid = |v: f64| v.is_finite() && v >= 0.0;
    if !valid(inproc_ns) || !valid(framed_ns) {
        return Err(DeltaError::NonFinite);
    }
    let total = framed_ns - inproc_ns;
    if total <= 0.0 {
        return Err(DeltaError::NonPositiveDelta);
    }
    let ratio = |core10_s: f64| total / (core10_s * 1e9) * 100.0;
    Ok(Delta {
        total_ns: total,
        per_round_trip_ns: total / f64::from(round_trips),
        round_trips,
        core10_ratio_low_percent: ratio(CORE10_LINUX_LOW_S),
        core10_ratio_high_percent: ratio(CORE10_LINUX_HIGH_S),
    })
}

/// 英語の機械可読な 1 行ログ（stderr 用）を返す。
pub fn log_line(op: &str, d: &Delta) -> String {
    format!(
        "plugin_boundary: op={op} round_trips={} delta_p50_total_ns={} delta_p50_per_round_trip_ns={} core10_ratio_percent_at_0.290s={:.6} core10_ratio_percent_at_0.298s={:.6}",
        d.round_trips,
        d.total_ns,
        d.per_round_trip_ns,
        d.core10_ratio_low_percent,
        d.core10_ratio_high_percent
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    /// PLUG-5: 3 往復の Δp50 と CORE-10 比。
    #[test]
    fn plug5_compute_three_round_trips() {
        let d = compute(1_000.0, 28_000.0, 3).unwrap();
        assert_eq!(d.total_ns, 27_000.0);
        assert_eq!(d.per_round_trip_ns, 9_000.0);
        assert!(close(
            d.core10_ratio_low_percent,
            27_000.0 / 290_000_000.0 * 100.0
        ));
        assert!(close(
            d.core10_ratio_high_percent,
            27_000.0 / 298_000_000.0 * 100.0
        ));
    }

    /// PLUG-5: 1 往復では total と per_round_trip が一致する。
    #[test]
    fn plug5_compute_single_round_trip() {
        let d = compute(500.0, 9_915.0, 1).unwrap();
        assert_eq!(d.total_ns, 9_415.0);
        assert_eq!(d.per_round_trip_ns, 9_415.0);
    }

    /// REPAIR-8: Δ が 0 以下・非有限・往復 0 は fail-closed。
    #[test]
    fn plug5_compute_rejects_bad_input() {
        assert_eq!(compute(5.0, 5.0, 1), Err(DeltaError::NonPositiveDelta));
        assert_eq!(compute(9.0, 5.0, 1), Err(DeltaError::NonPositiveDelta));
        assert_eq!(compute(f64::NAN, 5.0, 1), Err(DeltaError::NonFinite));
        assert_eq!(compute(1.0, f64::INFINITY, 1), Err(DeltaError::NonFinite));
        assert_eq!(compute(1.0, 5.0, 0), Err(DeltaError::InvalidRoundTrips));
    }

    /// PLUG-5: ログ行の書式。
    #[test]
    fn plug5_log_line_exact() {
        let d = compute(1_000.0, 28_000.0, 3).unwrap();
        assert_eq!(
            log_line("a", &d),
            "plugin_boundary: op=a round_trips=3 delta_p50_total_ns=27000 delta_p50_per_round_trip_ns=9000 core10_ratio_percent_at_0.290s=0.009310 core10_ratio_percent_at_0.298s=0.009060"
        );
    }
}
