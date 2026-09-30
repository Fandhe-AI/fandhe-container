//! メトリクス集計（`OpRecorder`）の分布・件数に関する結合試験（REPAIR-4・TASK-84.6）。
//!
//! 公開 API のみを外部から呼び、既知のレイテンシ列に対する min / mean / p95 / max と
//! 成功・失敗件数が期待どおりに集計されることを手計算した具体値で固定する。
//! p95 は nearest-rank（直近 `LATENCY_WINDOW_CAP` 件が対象）、min / mean / max は全件の
//! 厳密値という確定仕様を機械照合する（REPAIR-12）。
//!
//! 役割分担: JSON Lines の行形式・書き込み失敗は `observability_export.rs`、
//! 操作名検証・ガードの Drop 等の内部挙動は `src/observability.rs` のユニットテストが担う。
//! 実機権限・OS 固有 API を使わず、3 OS の既定テスト集合で動く。

use std::time::Duration;

use fandhe_container_core::observability::{LATENCY_WINDOW_CAP, OpName, OpOutcome, OpRecorder};

fn name(s: &str) -> OpName {
    OpName::new(s).expect("valid op name")
}

fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}

fn us(v: u64) -> Duration {
    Duration::from_micros(v)
}

/// REPAIR-4: nearest-rank（添字 ceil(0.95n)-1）の境界を具体値で確認する。
#[test]
fn repair4_p95_nearest_rank_boundaries() {
    // (件数, 期待 p95 ms)
    let cases: [(u64, u64); 7] = [
        (1, 1),
        (2, 2),
        (19, 19),
        (20, 19),
        (21, 20),
        (40, 38),
        (100, 95),
    ];
    for (n, expected_p95) in cases {
        let r = OpRecorder::new();
        let op = name("read");
        for i in 1..=n {
            r.record(&op, OpOutcome::Success, ms(i)).unwrap();
        }
        let stats = r.snapshot_op(&op).expect("op recorded");
        let lat = stats.latency().expect("latency present");
        assert_eq!(stats.total(), n, "n={n}");
        assert_eq!(lat.min(), ms(1), "n={n}");
        assert_eq!(lat.p95(), ms(expected_p95), "n={n}");
        assert_eq!(lat.max(), ms(n), "n={n}");
        if n == 100 {
            assert_eq!(lat.mean(), us(50_500));
        }
    }
}

/// REPAIR-4: 外れ値が上位 5% を超えたときだけ p95 に現れ、max / mean は常に反映される。
#[test]
fn repair4_p95_with_outliers() {
    let op = name("write");

    let r = OpRecorder::new();
    for _ in 0..19 {
        r.record(&op, OpOutcome::Success, ms(1)).unwrap();
    }
    r.record(&op, OpOutcome::Success, ms(1000)).unwrap();
    let s = r.snapshot_op(&op).unwrap();
    let lat = s.latency().unwrap();
    assert_eq!(lat.min(), ms(1));
    assert_eq!(lat.p95(), ms(1));
    assert_eq!(lat.max(), ms(1000));
    assert_eq!(lat.mean(), us(50_950));

    let r = OpRecorder::new();
    for _ in 0..18 {
        r.record(&op, OpOutcome::Success, ms(1)).unwrap();
    }
    for _ in 0..2 {
        r.record(&op, OpOutcome::Success, ms(1000)).unwrap();
    }
    let s = r.snapshot_op(&op).unwrap();
    let lat = s.latency().unwrap();
    assert_eq!(lat.p95(), ms(1000));
    assert_eq!(lat.max(), ms(1000));
    assert_eq!(lat.mean(), us(100_900));
}

/// REPAIR-4: 失敗も件数に数えられ、レイテンシ分布にも含まれる。
#[test]
fn repair4_failures_counted_and_included_in_latency() {
    let r = OpRecorder::new();
    let op = name("create");
    for _ in 0..3 {
        r.record(&op, OpOutcome::Success, ms(10)).unwrap();
    }
    for _ in 0..2 {
        r.record(&op, OpOutcome::Failure, ms(50)).unwrap();
    }
    let s = r.snapshot_op(&op).unwrap();
    assert_eq!((s.success(), s.failure(), s.total()), (3, 2, 5));
    let lat = s.latency().unwrap();
    assert_eq!(lat.min(), ms(10));
    assert_eq!(lat.mean(), ms(26));
    assert_eq!(lat.p95(), ms(50));
    assert_eq!(lat.max(), ms(50));
}

/// REPAIR-4: p95 は直近ウィンドウ、min / mean / max は全サンプルを対象にする。
#[test]
fn repair4_p95_uses_window_while_mean_uses_all_samples() {
    let r = OpRecorder::new();
    let op = name("read");
    for _ in 0..LATENCY_WINDOW_CAP {
        r.record(&op, OpOutcome::Success, ms(1)).unwrap();
    }
    for _ in 0..LATENCY_WINDOW_CAP {
        r.record(&op, OpOutcome::Success, ms(100)).unwrap();
    }
    let s = r.snapshot_op(&op).unwrap();
    assert_eq!(s.total(), 2048);
    let lat = s.latency().unwrap();
    assert_eq!(lat.min(), ms(1));
    assert_eq!(lat.mean(), us(50_500));
    assert_eq!(lat.p95(), ms(100));
    assert_eq!(lat.max(), ms(100));
}

/// REPAIR-4: 集計結果は記録順序に依存しない。
#[test]
fn repair4_latency_summary_is_order_independent() {
    let op = name("read");
    let ascending: Vec<u64> = (1..=20).collect();
    let descending: Vec<u64> = (1..=20).rev().collect();
    // 固定の置換（7 と 20 は互いに素なので全要素を 1 回ずつ通る）
    let permuted: Vec<u64> = (0..20).map(|i| (i * 7) % 20 + 1).collect();

    let mut summaries = Vec::new();
    for order in [&ascending, &descending, &permuted] {
        let r = OpRecorder::new();
        for &v in order {
            r.record(&op, OpOutcome::Success, ms(v)).unwrap();
        }
        let s = r.snapshot_op(&op).unwrap();
        summaries.push(*s.latency().unwrap());
    }
    assert_eq!(summaries[0], summaries[1]);
    assert_eq!(summaries[0], summaries[2]);
    assert_eq!(summaries[0].p95(), ms(19));
    assert_eq!(summaries[0].mean(), us(10_500));
}

/// REPAIR-4: 複数操作を交互に記録しても操作ごとに独立して集計され、一覧は名前昇順になる。
#[test]
fn repair4_multiple_ops_are_aggregated_independently() {
    let r = OpRecorder::new();
    let read = name("read");
    let write = name("write");
    r.record(&write, OpOutcome::Failure, ms(7)).unwrap();
    r.record(&read, OpOutcome::Success, ms(1)).unwrap();
    r.record(&write, OpOutcome::Success, ms(9)).unwrap();
    r.record(&read, OpOutcome::Success, ms(3)).unwrap();

    let rs = r.snapshot_op(&read).unwrap();
    assert_eq!((rs.success(), rs.failure()), (2, 0));
    let rl = rs.latency().unwrap();
    assert_eq!(
        (rl.min(), rl.mean(), rl.p95(), rl.max()),
        (ms(1), ms(2), ms(3), ms(3))
    );

    let ws = r.snapshot_op(&write).unwrap();
    assert_eq!((ws.success(), ws.failure()), (1, 1));
    let wl = ws.latency().unwrap();
    assert_eq!(
        (wl.min(), wl.mean(), wl.p95(), wl.max()),
        (ms(7), ms(8), ms(9), ms(9))
    );

    let all = r.snapshot();
    let names: Vec<&str> = all.iter().map(|s| s.name().as_str()).collect();
    assert_eq!(names, vec!["read", "write"]);
}

/// `?` 早期 return を模して、確定されないままガードが Drop される経路を作る。
fn early_return_without_finish(r: &OpRecorder, op: &OpName) -> Result<(), ()> {
    let _guard = r.start(op.clone());
    Err(())
}

/// REPAIR-4: `record_op`・ガード確定・ガード未確定 Drop のいずれも件数に反映される。
#[test]
fn repair4_guard_and_record_op_reflect_counts() {
    let r = OpRecorder::new();
    let op = name("start");

    let _: Result<(), ()> = r.record_op(&op, || Ok(()));
    let _: Result<(), ()> = r.record_op(&op, || Ok(()));
    let _: Result<(), ()> = r.record_op(&op, || Err(()));
    r.start(op.clone()).success();
    assert!(early_return_without_finish(&r, &op).is_err());

    let s = r.snapshot_op(&op).unwrap();
    assert_eq!((s.success(), s.failure()), (3, 2));
    // 経過時間は実測値のため具体値は検証せず、順序関係のみ確認する。
    let lat = s.latency().expect("latency present");
    assert!(lat.min() <= lat.p95());
    assert!(lat.p95() <= lat.max());
}

/// REPAIR-4: 既知の分布が JSON Lines 出力まで欠落・変形なく到達する。
#[test]
fn repair4_export_reports_known_distribution() {
    let r = OpRecorder::new();
    let op = name("read");
    for i in (1..=20u64).rev() {
        let outcome = if i <= 5 {
            OpOutcome::Failure
        } else {
            OpOutcome::Success
        };
        r.record(&op, outcome, ms(i)).unwrap();
    }

    let mut out: Vec<u8> = Vec::new();
    r.export_json_lines(Some(&mut out)).unwrap();
    let text = String::from_utf8(out).unwrap();

    let expected = concat!(
        "{\"event\":\"op_stats\",\"op\":\"read\",\"success\":15,\"failure\":5,\"count\":20,",
        "\"min_us\":1000,\"mean_us\":10500,\"p95_us\":19000,\"max_us\":20000}\n",
        "{\"event\":\"op_stats_meta\",\"ops\":1,\"dropped_records\":0}\n",
    );
    assert_eq!(text, expected);
}
