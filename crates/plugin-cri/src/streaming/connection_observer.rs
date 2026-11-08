//! ストリーミングサーバーの接続イベント（`ConnectionObserver`）を plugin-cri の telemetry へ流す本番実装（#4163・CRI-6・REPAIR-4）。
//!
//! 呼び出し元: cri の `StreamingServer` の accept タスクと接続タスクが [`ConnectionObserver::observe`] を同期で呼ぶ。
//! 注入は `streaming::bind_production_streaming` が `bind_with_observer` へ渡し、`main.rs` が共有 `OpRecorder` と
//! `telemetry::stderr_sink()` で組み立てる。これが無いと接続の受理・上限超過の拒否・期限切れが telemetry に出ない。
//!
//! # 出力
//! - 件数・レイテンシ: 共有 `OpRecorder` の 4 つの操作名（下表）。既存の 60 秒周期の `op_stats` 行に出る（正の件数はこちら）。
//! - 異常の構造化行: 理由ごとの累計が 2 のべき乗（1, 2, 4, …）に達した時だけ
//!   `{"event":"cri_streaming_connection","op":…,"outcome":"error","reason":<固定語彙>,"count":<累計>}` を 1 行出す。
//!   共有の stderr sink は peer 認証の監査行とも共用のため、接続の洪水で監査行を押し出さないための間引き
//!   （理由ごとにプロセス寿命で高々 64 行。REPAIR-5・SEC-4）。
//!
//! | イベント | 操作名 | 結果 | 異常行の reason |
//! | --- | --- | --- | --- |
//! | `Finished{Completed}` | `cri.streaming.connection` | 成功 | なし |
//! | `Finished{HttpError}` | `cri.streaming.connection` | 失敗 | なし（クライアント起因の雑音。件数のみ） |
//! | `Finished{DeadlineExceeded}` | `cri.streaming.connection_deadline` | 失敗 | `deadline_exceeded` |
//! | `Rejected` | `cri.streaming.connection_rejected` | 失敗 | `max_connections` |
//! | `AcceptFailed` | `cri.streaming.accept_failed` | 失敗 | `accept_failed` |
//!
//! # 契約
//! - ブロックしない: `observe` は `OpRecorder::record`（短い mutex と算術のみ）、`AtomicU64::fetch_add`、
//!   `LineSink::submit`（`try_send` のみ。満杯は件数へ集約）だけで I/O をしない。書き込みは `LineSink` の専用 thread が担う（REPAIR-5）。
//! - 出さない情報: トークン・コンテナ ID・入出力の内容・URL のパス・相手アドレス。`ConnectionEvent` が文字列を持たず、
//!   本実装もそれ以外の情報源を参照しない。行に埋めるのは `&'static str` と `u64` だけ（ログインジェクション不可。REPAIR-4）。
//! - 未実装（REPAIR-3）: Upgrade 後のセッションの停止時のドレイン方針は別 issue（#4111。REPAIR-5）。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::traits::TraitError;
use fandhe_container_cri::streaming::{ConnectionEvent, ConnectionObserver, ConnectionOutcome};

use crate::telemetry::LineSink;

/// 受け付けた接続の処理結果（正常終了と HTTP 失敗）の操作名。
pub const OP_CONNECTION: &str = "cri.streaming.connection";
/// 接続全体の期限切れの操作名。
pub const OP_CONNECTION_DEADLINE: &str = "cri.streaming.connection_deadline";
/// 同時接続数の上限超過による拒否の操作名。
pub const OP_CONNECTION_REJECTED: &str = "cri.streaming.connection_rejected";
/// `accept` 失敗の操作名。
pub const OP_ACCEPT_FAILED: &str = "cri.streaming.accept_failed";

/// 異常行の `event` 名。
pub const EVENT_NAME: &str = "cri_streaming_connection";
/// 上限超過の理由（固定語彙）。
pub const REASON_MAX_CONNECTIONS: &str = "max_connections";
/// 期限切れの理由。
pub const REASON_DEADLINE_EXCEEDED: &str = "deadline_exceeded";
/// accept 失敗の理由。
pub const REASON_ACCEPT_FAILED: &str = "accept_failed";

/// [`ConnectionObserver`] の本番実装。共有記録器へ件数を、sink へ間引いた異常行を渡す。
pub struct TelemetryConnectionObserver {
    recorder: Arc<OpRecorder>,
    sink: LineSink,
    connection: OpName,
    deadline: OpName,
    rejected: OpName,
    accept_failed: OpName,
    rejected_total: AtomicU64,
    accept_failed_total: AtomicU64,
    deadline_total: AtomicU64,
}

impl TelemetryConnectionObserver {
    /// 操作名を検証して作る。失敗は呼び出し側（`main.rs`）が起動中止にする（観測なしで動き続けない）。
    pub fn new(recorder: Arc<OpRecorder>, sink: LineSink) -> Result<Self, TraitError> {
        Ok(Self {
            recorder,
            sink,
            connection: OpName::new(OP_CONNECTION)?,
            deadline: OpName::new(OP_CONNECTION_DEADLINE)?,
            rejected: OpName::new(OP_CONNECTION_REJECTED)?,
            accept_failed: OpName::new(OP_ACCEPT_FAILED)?,
            rejected_total: AtomicU64::new(0),
            accept_failed_total: AtomicU64::new(0),
            deadline_total: AtomicU64::new(0),
        })
    }

    /// 累計 `n`（1 始まり）が 2 のべき乗なら異常行を積む。
    fn maybe_line(&self, op: &'static str, reason: &'static str, n: u64) {
        if n.is_power_of_two() {
            self.sink.submit(format!(
                "{{\"event\":\"{EVENT_NAME}\",\"op\":\"{op}\",\"outcome\":\"error\",\"reason\":\"{reason}\",\"count\":{n}}}"
            ));
        }
    }

    fn bump(counter: &AtomicU64) -> u64 {
        counter.fetch_add(1, Ordering::Relaxed).saturating_add(1)
    }
}

impl ConnectionObserver for TelemetryConnectionObserver {
    fn observe(&self, event: ConnectionEvent) {
        // record の失敗（名前数の上限など）は記録器側の dropped_records に計上されるため無視する。
        match event {
            ConnectionEvent::Finished { outcome, elapsed } => match outcome {
                ConnectionOutcome::Completed => {
                    let _ = self
                        .recorder
                        .record(&self.connection, OpOutcome::Success, elapsed);
                }
                ConnectionOutcome::HttpError => {
                    let _ = self
                        .recorder
                        .record(&self.connection, OpOutcome::Failure, elapsed);
                }
                ConnectionOutcome::DeadlineExceeded => {
                    let _ = self
                        .recorder
                        .record(&self.deadline, OpOutcome::Failure, elapsed);
                    let n = Self::bump(&self.deadline_total);
                    self.maybe_line(OP_CONNECTION_DEADLINE, REASON_DEADLINE_EXCEEDED, n);
                }
            },
            ConnectionEvent::Rejected => {
                let _ = self
                    .recorder
                    .record(&self.rejected, OpOutcome::Failure, Duration::ZERO);
                let n = Self::bump(&self.rejected_total);
                self.maybe_line(OP_CONNECTION_REJECTED, REASON_MAX_CONNECTIONS, n);
            }
            ConnectionEvent::AcceptFailed => {
                let _ =
                    self.recorder
                        .record(&self.accept_failed, OpOutcome::Failure, Duration::ZERO);
                let n = Self::bump(&self.accept_failed_total);
                self.maybe_line(OP_ACCEPT_FAILED, REASON_ACCEPT_FAILED, n);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;
    use std::sync::Mutex;

    use super::*;

    /// 書かれた行を集める出力先（試験用）。
    #[derive(Clone, Default)]
    pub(crate) struct Collect(pub(crate) Arc<Mutex<Vec<u8>>>);
    impl Write for Collect {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Collect {
        pub(crate) fn lines(&self) -> Vec<String> {
            String::from_utf8_lossy(&self.0.lock().unwrap())
                .lines()
                .map(str::to_string)
                .collect()
        }

        /// 行が `n` 本以上になるまで最大 2 秒待つ（書き込み thread は非同期）。
        pub(crate) fn wait_lines(&self, n: usize) {
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while self.lines().len() < n && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    fn name(s: &str) -> OpName {
        OpName::new(s).expect("name")
    }

    fn fin(outcome: ConnectionOutcome, ms: u64) -> ConnectionEvent {
        ConnectionEvent::Finished {
            outcome,
            elapsed: Duration::from_millis(ms),
        }
    }

    fn line(op: &str, reason: &str, count: u64) -> String {
        format!(
            "{{\"event\":\"cri_streaming_connection\",\"op\":\"{op}\",\"outcome\":\"error\",\"reason\":\"{reason}\",\"count\":{count}}}"
        )
    }

    /// 受理 2・拒否 1・期限切れ 1 で、件数と行が種別・回数とも具体値どおり（CRI-6・REPAIR-4・#4163）。
    #[test]
    fn cri6_repair4_4163_counts_and_lines_per_kind() {
        let rec = Arc::new(OpRecorder::new());
        let out = Collect::default();
        let sink = LineSink::spawn(Box::new(out.clone()), 16);
        let obs = TelemetryConnectionObserver::new(Arc::clone(&rec), sink.clone()).expect("new");
        obs.observe(fin(ConnectionOutcome::Completed, 5));
        obs.observe(fin(ConnectionOutcome::Completed, 7));
        obs.observe(ConnectionEvent::Rejected);
        obs.observe(fin(ConnectionOutcome::DeadlineExceeded, 900));
        out.wait_lines(2);
        let c = rec.snapshot_op(&name(OP_CONNECTION)).expect("conn");
        assert_eq!((c.success(), c.failure()), (2, 0));
        let r = rec.snapshot_op(&name(OP_CONNECTION_REJECTED)).expect("rej");
        assert_eq!((r.success(), r.failure()), (0, 1));
        let d = rec.snapshot_op(&name(OP_CONNECTION_DEADLINE)).expect("dl");
        assert_eq!((d.success(), d.failure()), (0, 1));
        assert!(rec.snapshot_op(&name(OP_ACCEPT_FAILED)).is_none());
        assert_eq!(rec.snapshot().len(), 3);
        assert_eq!(
            out.lines(),
            vec![
                line(OP_CONNECTION_REJECTED, REASON_MAX_CONNECTIONS, 1),
                line(OP_CONNECTION_DEADLINE, REASON_DEADLINE_EXCEEDED, 1),
            ]
        );
        // HttpError は件数のみ、AcceptFailed は件数と行。
        obs.observe(fin(ConnectionOutcome::HttpError, 3));
        obs.observe(ConnectionEvent::AcceptFailed);
        out.wait_lines(3);
        let c = rec.snapshot_op(&name(OP_CONNECTION)).expect("conn");
        assert_eq!((c.success(), c.failure()), (2, 1));
        let a = rec.snapshot_op(&name(OP_ACCEPT_FAILED)).expect("acc");
        assert_eq!((a.success(), a.failure()), (0, 1));
        let lines = out.lines();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[2], line(OP_ACCEPT_FAILED, REASON_ACCEPT_FAILED, 1));
    }

    /// 異常行は累計が 2 のべき乗の時だけ出る（洪水で共有 sink を埋めない。REPAIR-5・SEC-4）。
    #[test]
    fn repair5_4163_anomaly_lines_are_log_scaled() {
        let rec = Arc::new(OpRecorder::new());
        let out = Collect::default();
        let sink = LineSink::spawn(Box::new(out.clone()), 64);
        let obs = TelemetryConnectionObserver::new(Arc::clone(&rec), sink).expect("new");
        for _ in 0..1000 {
            obs.observe(ConnectionEvent::Rejected);
        }
        out.wait_lines(10);
        let expected: Vec<String> = (0..10)
            .map(|i| line(OP_CONNECTION_REJECTED, REASON_MAX_CONNECTIONS, 1u64 << i))
            .collect();
        assert_eq!(out.lines(), expected);
        let r = rec.snapshot_op(&name(OP_CONNECTION_REJECTED)).expect("rej");
        assert_eq!(r.failure(), 1000);
    }

    /// 書き込みが止まった sink でも `observe` は待たない（REPAIR-5・#4163）。
    #[test]
    fn repair5_4163_observe_does_not_block_on_stalled_sink() {
        struct Stall(std::sync::mpsc::Receiver<()>);
        impl Write for Stall {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                let _ = self.0.recv();
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let (gate, rx) = std::sync::mpsc::channel();
        let sink = LineSink::spawn(Box::new(Stall(rx)), 2);
        let rec = Arc::new(OpRecorder::new());
        let obs = TelemetryConnectionObserver::new(Arc::clone(&rec), sink.clone()).expect("new");
        let started = std::time::Instant::now();
        for _ in 0..10_000 {
            obs.observe(ConnectionEvent::AcceptFailed);
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        let a = rec.snapshot_op(&name(OP_ACCEPT_FAILED)).expect("acc");
        assert_eq!(a.failure(), 10_000);
        // 行は 2 のべき乗の 14 本（1..8192）。writer が 1 本を保持しキュー 2 本に積めた残りは件数へ集約される。
        assert!(sink.dropped() >= 14 - 4, "dropped={}", sink.dropped());
        assert!(sink.dropped() <= 13, "dropped={}", sink.dropped());
        drop(gate);
    }

    /// 操作名は `OpName` の規則に収まる。
    #[test]
    fn repair4_4163_op_names_are_valid() {
        for n in [
            OP_CONNECTION,
            OP_CONNECTION_DEADLINE,
            OP_CONNECTION_REJECTED,
            OP_ACCEPT_FAILED,
        ] {
            assert!(OpName::new(n).is_ok(), "{n}");
        }
        let sink = LineSink::spawn(Box::new(std::io::sink()), 2);
        assert!(TelemetryConnectionObserver::new(Arc::new(OpRecorder::new()), sink).is_ok());
    }
}
