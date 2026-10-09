//! セッション・virtqueue 操作の成功 / 失敗件数と所要時間の集計（GPU-6・REPAIR-4・TASK-172 F1.4・#1519）。
//!
//! [`super::run`] がセッション 1 本ごとに保持し、終了時（正常・エラーの両方）に `venus_jig event=session_op ...` の
//! 構造化ログ行として出す。操作は vhost-user メッセージ 1 件の処理（受信・状態遷移・応答送信）、ctrl キューの kick 処理
//! （ring の走査・アダプタ呼び出し・used 書き込み）、call 通知の 3 種。セッションはエラーで打ち切られるため、失敗は
//! 最後の 1 件になる。固定語彙と数値だけを出し、frontend 由来の値はエコーしない（ログ注入の防止）。
//! `vhost_user::observe`（fd 受け渡し・ゲストメモリ I/O の集計）は別粒度で、同じ終了時に [`super::run`] が続けて出す。

use std::time::Duration;

/// 集計対象の操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionOp {
    /// vhost-user メッセージ 1 件の処理。
    Message,
    /// ctrl キューの kick 1 回分の処理（積まれた要求の応答まで）。
    CtrlKick,
    /// call の eventfd への通知。
    Notify,
}

impl SessionOp {
    const ALL: [SessionOp; 3] = [SessionOp::Message, SessionOp::CtrlKick, SessionOp::Notify];

    fn word(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::CtrlKick => "ctrl_kick",
            Self::Notify => "notify",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Message => 0,
            Self::CtrlKick => 1,
            Self::Notify => 2,
        }
    }
}

/// レイテンシ分布の階級数（[`BUCKET_UPPER_NS`] と同数。最後は上限なし）。
const BUCKETS: usize = 8;

/// 各階級の上限（ns。この値以下）と、ログに出す固定語彙のラベル。最後の階級は 1 秒超（上限なし）。
/// 階級の定義は固定でセッション間・操作間で比較できる（REPAIR-4）。メモリは操作ごとに `u64` 8 個で一定。
const BUCKET_UPPER_NS: [(u64, &str); BUCKETS] = [
    (1_000, "le_1us"),
    (10_000, "le_10us"),
    (100_000, "le_100us"),
    (1_000_000, "le_1ms"),
    (10_000_000, "le_10ms"),
    (100_000_000, "le_100ms"),
    (1_000_000_000, "le_1s"),
    (u64::MAX, "gt_1s"),
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Stat {
    ok: u64,
    err: u64,
    total_ns: u64,
    max_ns: u64,
    /// 所要時間の分布（非累積。階級は [`BUCKET_UPPER_NS`]）。
    hist: [u64; BUCKETS],
}

/// セッション 1 本分の集計。
#[derive(Debug, Default)]
pub(crate) struct SessionMetrics {
    stats: [Stat; SessionOp::ALL.len()],
}

impl SessionMetrics {
    /// 1 回の結果と所要時間を記録する。
    pub(crate) fn record(&mut self, op: SessionOp, ok: bool, elapsed: Duration) {
        let ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        if let Some(s) = self.stats.get_mut(op.index()) {
            if ok {
                s.ok = s.ok.saturating_add(1);
            } else {
                s.err = s.err.saturating_add(1);
            }
            s.total_ns = s.total_ns.saturating_add(ns);
            s.max_ns = s.max_ns.max(ns);
            let bucket = BUCKET_UPPER_NS
                .iter()
                .position(|(upper, _)| ns <= *upper)
                .unwrap_or(BUCKETS - 1);
            if let Some(h) = s.hist.get_mut(bucket) {
                *h = h.saturating_add(1);
            }
        }
    }

    /// 件数・合計時間・最大時間・分布を構造化ログ行にする（記録のない操作は出さない）。
    pub(crate) fn lines(&self) -> Vec<String> {
        SessionOp::ALL
            .iter()
            .filter_map(|op| {
                let s = self.stats.get(op.index())?;
                (s.ok + s.err > 0).then(|| {
                    let mut line = format!(
                        "venus_jig event=session_op op={} ok={} err={} total_ns={} max_ns={}",
                        op.word(),
                        s.ok,
                        s.err,
                        s.total_ns,
                        s.max_ns
                    );
                    for ((_, label), count) in BUCKET_UPPER_NS.iter().zip(s.hist.iter()) {
                        line.push_str(&format!(" {label}={count}"));
                    }
                    line
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GPU-6・REPAIR-4: 成功・失敗・合計・最大が具体値で集計され、記録のない操作は出ない。
    #[test]
    fn gpu6_session_metrics_count_and_format() {
        let mut m = SessionMetrics::default();
        m.record(SessionOp::Message, true, Duration::from_nanos(100));
        m.record(SessionOp::Message, true, Duration::from_nanos(50));
        m.record(SessionOp::Message, false, Duration::from_nanos(25));
        m.record(SessionOp::Notify, true, Duration::from_nanos(7));
        assert_eq!(
            m.lines(),
            vec![
                "venus_jig event=session_op op=message ok=2 err=1 total_ns=175 max_ns=100 \
                 le_1us=3 le_10us=0 le_100us=0 le_1ms=0 le_10ms=0 le_100ms=0 le_1s=0 gt_1s=0",
                "venus_jig event=session_op op=notify ok=1 err=0 total_ns=7 max_ns=7 \
                 le_1us=1 le_10us=0 le_100us=0 le_1ms=0 le_10ms=0 le_100ms=0 le_1s=0 gt_1s=0",
            ]
        );
    }

    /// GPU-6・REPAIR-4: 階級の境界（上限ちょうどは下の階級、超えると次）と 1 秒超が具体値で分かれる。
    #[test]
    fn repair4_session_metrics_histogram_bucket_boundaries() {
        let mut m = SessionMetrics::default();
        for ns in [
            1_000,
            1_001,
            10_000,
            999_999_999,
            1_000_000_000,
            1_000_000_001,
        ] {
            m.record(SessionOp::CtrlKick, true, Duration::from_nanos(ns));
        }
        assert_eq!(
            m.lines(),
            vec![
                "venus_jig event=session_op op=ctrl_kick ok=6 err=0 total_ns=3000012001 max_ns=1000000001 \
                 le_1us=1 le_10us=2 le_100us=0 le_1ms=0 le_10ms=0 le_100ms=0 le_1s=2 gt_1s=1",
            ]
        );
    }
}
