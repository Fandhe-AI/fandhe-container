//! 稼働中の可観測性出力（peer 認証の拒否の監査行と CRI 操作の件数・レイテンシ。SEC-4・REPAIR-4・REPAIR-5）。
//!
//! 呼び出し元は `server::serve`（監査の配送）と `main.rs`（操作統計の定期出力）。
//! `fandhe-container-plugin` の `JsonLinesPeerAuthObserver` はメモリへ積むだけで出力しないため、
//! 受付の外（別 task）で回収し、有限キュー経由で専用 thread が stderr へ JSON Lines で書く。受付処理（`on_rejection`）は
//! 短い mutex の取得とメモリへの追記だけで、I/O をしない。
//!
//! # 未実装（REPAIR-3）
//! 出力先は stderr のみ。`crates/core` の永続的な監査ログ・メトリクス公開口への接続は #1869 の core 側 proxy の責務。

use std::io::Write;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use fandhe_container_core::observability::OpRecorder;
use fandhe_container_plugin::{JsonLinesPeerAuthObserver, PeerAuthObserver, PeerAuthRejection};

/// 監査行を回収して書き出す間隔。
pub const AUDIT_DRAIN_INTERVAL: Duration = Duration::from_secs(1);
/// 操作統計を書き出す間隔。
pub const OP_STATS_EXPORT_INTERVAL: Duration = Duration::from_secs(60);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // 毒化しても記録は続ける（監査を落とさない）。
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 共有バッファへ積む `PeerAuthObserver`。`UdsIncoming` に所有を渡した後も、共有側から回収できる。
pub struct SharedPeerAuthObserver {
    inner: Arc<Mutex<JsonLinesPeerAuthObserver>>,
}

impl SharedPeerAuthObserver {
    /// 観測フックと、回収用の共有バッファを作る。
    pub fn new() -> (Self, Arc<Mutex<JsonLinesPeerAuthObserver>>) {
        let inner = Arc::new(Mutex::new(JsonLinesPeerAuthObserver::new()));
        (
            Self {
                inner: Arc::clone(&inner),
            },
            inner,
        )
    }
}

impl PeerAuthObserver for SharedPeerAuthObserver {
    fn on_rejection(&mut self, event: &PeerAuthRejection<'_>) {
        lock(&self.inner).on_rejection(event);
    }
}

/// 書き出し待ちの行の上限（満杯なら捨てて件数へ集約する。REPAIR-5）。
pub const SINK_CAPACITY: usize = 256;

/// 出力先が止まってもランタイムを止めない有限容量の書き出し口。
///
/// `main.rs` は current_thread ランタイムのため、stderr への同期書き込みを task 内で行うと、
/// 受け手が読まなくなった時に accept・全 RPC・タイムアウト監視が止まる（REPAIR-5）。
/// 行は有限キューへ `try_send` するだけにし、実際の書き込みは専用 OS thread が行う。
/// 満杯・切断時は捨てず件数に集約し、次に書ける時に `telemetry_dropped` 行として残す（SEC-4）。
#[derive(Clone)]
pub struct LineSink {
    tx: std::sync::mpsc::SyncSender<String>,
    dropped: Arc<AtomicU64>,
    pending: Arc<AtomicUsize>,
}

impl LineSink {
    /// 専用 thread で `w` へ書く口を作る。thread を作れない場合は全行を件数へ集約する口になる。
    pub fn spawn(mut w: Box<dyn Write + Send>, capacity: usize) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<String>(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let pending = Arc::new(AtomicUsize::new(0));
        let (d, p) = (Arc::clone(&dropped), Arc::clone(&pending));
        // join しない（書き込みが止まっていてもシャットダウンを止めないため）。失敗時は rx が落ちて Disconnected になる。
        let _ = std::thread::Builder::new()
            .name("cri-telemetry-writer".into())
            .spawn(move || {
                while let Ok(line) = rx.recv() {
                    let n = d.swap(0, Ordering::Relaxed);
                    if n > 0 {
                        let notice = format!(
                            "{{\"event\":\"telemetry_dropped\",\"outcome\":\"error\",\"count\":{n}}}\n"
                        );
                        let _ = w.write_all(notice.as_bytes());
                    }
                    let _ = w.write_all(line.as_bytes());
                    let _ = w.write_all(b"\n");
                    let _ = w.flush();
                    p.fetch_sub(1, Ordering::Relaxed);
                }
            });
        Self {
            tx,
            dropped,
            pending,
        }
    }

    /// 1 行を積む。ブロックしない。積めなければ件数へ集約して false。
    pub fn submit(&self, line: String) -> bool {
        self.pending.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(line) {
            Ok(()) => true,
            Err(_) => {
                self.pending.fetch_sub(1, Ordering::Relaxed);
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// 捨てた行の累計（まだ通知行にしていない分）。
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// 書き出し待ちが空になるまで最大 `timeout` 待つ（終了時の最後の書き出し用。書き込みが止まっていても返る）。
    pub fn wait_idle(&self, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        while self.pending.load(Ordering::Relaxed) > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// プロセス共通の stderr 書き出し口（初回利用時に専用 thread を起こす）。
pub fn stderr_sink() -> &'static LineSink {
    static SINK: OnceLock<LineSink> = OnceLock::new();
    SINK.get_or_init(|| LineSink::spawn(Box::new(std::io::stderr()), SINK_CAPACITY))
}

/// 積まれた監査行を `sink` へ渡す。積めた行数を返す（積めない行は件数へ集約され、受付に影響しない）。
pub fn drain_audit_to(buf: &Mutex<JsonLinesPeerAuthObserver>, sink: &LineSink) -> usize {
    let lines = lock(buf).drain_lines();
    lines.into_iter().filter(|l| sink.submit(l.clone())).count()
}

/// `period` ごとに監査行を stderr 書き出し口へ渡し続ける（呼び出し側が abort して止める）。
pub async fn audit_drain_loop(buf: Arc<Mutex<JsonLinesPeerAuthObserver>>, period: Duration) {
    loop {
        tokio::time::sleep(period).await;
        drain_audit_to(&buf, stderr_sink());
    }
}

/// 操作統計を JSON Lines で `sink` へ渡す。積めた行数（符号化失敗時は 0）を返す。
pub fn export_op_stats_to(recorder: &OpRecorder, sink: &LineSink) -> usize {
    let mut out: Vec<u8> = Vec::new();
    match recorder.export_json_lines(Some(&mut out)) {
        Ok(_) => String::from_utf8_lossy(&out)
            .lines()
            .filter(|l| sink.submit((*l).to_string()))
            .count(),
        Err(_) => 0,
    }
}

/// `period` ごとに操作統計を stderr 書き出し口へ渡し続ける（呼び出し側が abort して止める）。
pub async fn op_stats_export_loop(recorder: Arc<OpRecorder>, period: Duration) {
    loop {
        tokio::time::sleep(period).await;
        export_op_stats_to(&recorder, stderr_sink());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::observability::{OpName, OpOutcome};

    /// 拒否が無ければ何も書かない。拒否の構築は `#[non_exhaustive]` のため plugin 側の試験が担う。
    #[test]
    fn empty_audit_buffer_writes_nothing() {
        let (obs, buf) = SharedPeerAuthObserver::new();
        fn assert_send<T: Send>(_: &T) {}
        assert_send(&obs);
        let sink = LineSink::spawn(Box::new(std::io::sink()), 4);
        assert_eq!(drain_audit_to(&buf, &sink), 0);
        assert_eq!(sink.dropped(), 0);
    }

    /// 書き込み先が止まっても submit はブロックせず、あふれた分は件数へ集約される（REPAIR-5・SEC-4）。
    #[test]
    fn stalled_writer_does_not_block_and_counts_drops() {
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
        let accepted = (0..20).filter(|i| sink.submit(format!("l{i}"))).count();
        assert!(accepted <= 4, "accepted={accepted}");
        assert_eq!(sink.dropped(), (20 - accepted) as u64);
        sink.wait_idle(Duration::from_millis(20));
        drop(gate);
    }

    #[test]
    fn op_stats_are_exported_with_meta_line() {
        let r = OpRecorder::new();
        r.record(
            &OpName::new("cri.run_pod_sandbox").unwrap(),
            OpOutcome::Success,
            Duration::from_millis(3),
        )
        .unwrap();
        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                lock(&self.0).extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf(Arc::new(Mutex::new(Vec::new())));
        let sink = LineSink::spawn(Box::new(buf.clone()), 16);
        assert_eq!(export_op_stats_to(&r, &sink), 2);
        sink.wait_idle(Duration::from_secs(5));
        let text = String::from_utf8(lock(&buf.0).clone()).unwrap();
        assert!(text.contains("cri.run_pod_sandbox"), "{text}");
    }
}
