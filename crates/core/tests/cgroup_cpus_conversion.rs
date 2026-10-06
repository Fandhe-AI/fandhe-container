//! `--cpus` 相当値から `cpu.max` への変換の結合試験（SUP-13・TASK-170.1・#532）。
//!
//! 公開 API（`fandhe_container_core::cgroups`）のみを経由し、変換結果の具体値と拒否ケースを
//! 照合する。cgroup 実機は不要で既定のテスト集合で動く。変換値を実 cgroup の `set_cpu_max` へ
//! 渡す実機確認は `cgroup_cpu_max.rs`（`#[ignore]`・委譲 cgroup 前提）が担う。

use fandhe_container_core::cgroups::{CpuMax, CpuQuota, NANO_CPUS_PER_CPU};
use fandhe_container_core::traits::ErrorCode;

fn parts(max: &CpuMax) -> (CpuQuota, u64) {
    (max.quota(), max.period_us())
}

/// SUP-13・TASK-170.1: 10 進文字列から quota/period へ具体値で変換される。
#[test]
fn sup13_task170_1_parse_cpus_concrete_values() {
    let d = CpuMax::DEFAULT_PERIOD_US;
    for (input, quota) in [
        ("1", 100_000),
        ("1.5", 150_000),
        ("2", 200_000),
        ("0.5", 50_000),
        ("0.25", 25_000),
        ("0.01", 1_000),
    ] {
        let got = CpuMax::parse_cpus(input, d).unwrap_or_else(|e| panic!("{input}: {e:?}"));
        assert_eq!(parts(&got), (CpuQuota::Micros(quota), 100_000), "{input}");
    }
    let half = CpuMax::parse_cpus("1.5", 50_000).unwrap();
    assert_eq!(parts(&half), (CpuQuota::Micros(75_000), 50_000));
}

/// SUP-13・TASK-170.1: nano CPU 数からの変換は切り捨てで、文字列経路と一致する。
#[test]
fn sup13_task170_1_from_nano_cpus_matches_parse() {
    let d = CpuMax::DEFAULT_PERIOD_US;
    let nano = CpuMax::from_nano_cpus(NANO_CPUS_PER_CPU * 3 / 2, d).unwrap();
    assert_eq!(parts(&nano), (CpuQuota::Micros(150_000), 100_000));
    assert_eq!(nano, CpuMax::parse_cpus("1.5", d).unwrap());
    let truncated = CpuMax::from_nano_cpus(333_333_333, d).unwrap();
    assert_eq!(parts(&truncated), (CpuQuota::Micros(33_333), 100_000));
}

/// SUP-13・TASK-170.1: 0・下限未満・不正書式・範囲外は `InvalidArgument` で拒否される。
#[test]
fn sup13_task170_1_rejects_invalid_inputs() {
    let d = CpuMax::DEFAULT_PERIOD_US;
    for bad in [
        "",
        "0",
        "0.0",
        "0.001",
        "-1",
        "+1",
        " 1",
        "1 ",
        ".5",
        "1.",
        "1e2",
        "inf",
        "nan",
        "1.0000000001",
        "99999999999999999999",
    ] {
        let err = CpuMax::parse_cpus(bad, d).expect_err(bad);
        assert_eq!(err.code, ErrorCode::InvalidArgument, "{bad:?}");
    }
    for period in [999, 1_000_001] {
        let err = CpuMax::parse_cpus("1", period).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument, "period {period}");
    }
    let zero = CpuMax::from_nano_cpus(0, d).unwrap_err();
    assert_eq!(zero.code, ErrorCode::InvalidArgument);
    let huge = CpuMax::from_nano_cpus(u64::MAX, 1_000_000).unwrap_err();
    assert_eq!(huge.code, ErrorCode::InvalidArgument);
}
