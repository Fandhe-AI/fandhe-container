//! 稼働中の可観測性出力（peer 認証の拒否の監査行と CRI 操作の件数・レイテンシ。SEC-4・REPAIR-4・REPAIR-5）。
//!
//! 呼び出し元は `server::serve`（監査の配送）と `main.rs`（操作統計の定期出力）。
//! `fandhe-container-plugin` の `JsonLinesPeerAuthObserver` はメモリへ積むだけで出力しないため、
//! 受付の外（別 task）で回収し、有限キュー経由で専用 thread が stderr へ JSON Lines で書く。受付処理（`on_rejection`）は
//! 短い mutex の取得とメモリへの追記だけで、I/O をしない。
//!
//! # 監査の永続化（SEC-4・PLUG-12・#2484）
//! peer 認証の拒否は stderr の JSON Lines（可観測性）に加えて、[`PeerAuditForwarder`] が型つきの
//! `AuditRecord`（層 `plugin_peer`）を core の `AuditSink`（本番は `ControlAuditRelay` → `FileAuditSink`。
//! `<状態ルート>/@audit.log`）へ 1 件ずつ渡す。フック（`on_rejection`）では有界キューへ `try_send` するだけで
//! I/O をせず、書き込みは専用 OS thread が行う（`plugin-backend-wiring.md` 4.7 の「フックでは I/O をしない・
//! 有界バッファ・書き込み失敗を黙って捨てない」と同じ趣旨。ただし 4.7 の文字列回収ではなく型つきの記録を直接渡し、
//! JSON 行の読み直しを避ける。REPAIR-2）。
//!
//! 操作統計は記録器ごとのブロックで出す。本番は共有記録器と oci 専用記録器の 2 つで、1 周期に `op_stats_meta` 行が 2 行出る（共有・oci の順。#2900）。
//!
//! # 未実装（REPAIR-3）
//! - 操作統計の出力先は stderr のみ。メトリクス公開口への接続は #1869 の core 側 proxy の責務
//! - 監査の永続化経路は Linux 限定（`ControlAuditRelay` が Linux 限定、非 Linux の `FileAuditSink` は #2430 の
//!   判断待ち）。非 Linux では `PeerAuditForwarder` を渡さず、拒否は stderr にだけ残る

use std::io::Write;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use fandhe_container_core::audit_log::{
    AuditRecord, AuditSink, AuditTimestamp, PluginPeerRejection, current_pid,
};
use fandhe_container_core::observability::OpRecorder;
use fandhe_container_plugin::transport::UDS_ACCEPT_PEER_REJECTION_LIMIT;
use fandhe_container_plugin::{
    JsonLinesPeerAuthObserver, PeerAuthObserver, PeerAuthRejectReason, PeerAuthRejection,
};

/// 監査行を回収して書き出す間隔。
pub const AUDIT_DRAIN_INTERVAL: Duration = Duration::from_secs(1);
/// 操作統計を書き出す間隔。
pub const OP_STATS_EXPORT_INTERVAL: Duration = Duration::from_secs(60);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // 毒化しても記録は続ける（監査を落とさない）。
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// 監査キューの容量。1 回の受付で出得る拒否の最大件数（`UDS_ACCEPT_PEER_REJECTION_LIMIT` + 1）以上にして、
/// 1 回の受付の拒否を取りこぼさない（#2232 の申し送り）。
pub const PEER_AUDIT_QUEUE_CAPACITY: usize = 256;
const _: () = assert!(PEER_AUDIT_QUEUE_CAPACITY > UDS_ACCEPT_PEER_REJECTION_LIMIT as usize);

/// 監査キューが空でも欠落通知を出すために待つ間隔。
const FORWARDER_IDLE_TICK: Duration = Duration::from_secs(1);

/// plugin 側の拒否理由を core の閉じた語彙へ写す。将来 plugin 側に足される値は `Unknown` に落とす（落とさず記録する）。
pub fn plugin_peer_rejection(reason: PeerAuthRejectReason) -> PluginPeerRejection {
    match reason {
        PeerAuthRejectReason::UidMismatch => PluginPeerRejection::PeerUidMismatch,
        PeerAuthRejectReason::PeerUidUnavailable => PluginPeerRejection::PeerUidUnavailable,
        PeerAuthRejectReason::PidMismatch => PluginPeerRejection::PeerPidMismatch,
        PeerAuthRejectReason::PeerPidUnavailable => PluginPeerRejection::PeerPidUnavailable,
        _ => PluginPeerRejection::Unknown,
    }
}

/// peer 認証の拒否を core の `AuditSink` へ運ぶ有界キューと専用 thread（SEC-4・PLUG-12・#2484）。
///
/// 呼び出し元は [`SharedPeerAuthObserver::on_rejection`]（accept の最中。`current_thread` ランタイム上）。そこでは
/// ブロックできない（REPAIR-5）ので `try_send` だけを行い、`AuditSink::record`（`ControlAuditRelay` なら最大
/// `RECORD_WAIT_LIMIT` 待つ）は専用 OS thread が行う。キューがあふれた記録と、sink が失敗した記録は黙って捨てず、
/// 構造化行（固定語彙のみ）で `notices` へ残す。判定（接続の切断）は記録の成否に影響されない（fail-closed）。
pub struct PeerAuditForwarder {
    tx: std::sync::mpsc::SyncSender<AuditRecord>,
    dropped: Arc<AtomicU64>,
    pending: Arc<AtomicUsize>,
}

impl PeerAuditForwarder {
    /// `sink` へ書く thread を起こす。thread を作れなければ `Err` を返す（呼び出し側は受付を始めない。
    /// 記録経路なしで受け付けると以後の拒否が全て欠落するため。SEC-4・PLUG-12）。
    pub fn spawn(
        sink: Arc<dyn AuditSink>,
        capacity: usize,
        notices: LineSink,
    ) -> std::io::Result<Self> {
        Self::spawn_with(
            |job| {
                std::thread::Builder::new()
                    .name("cri-peer-audit".into())
                    .spawn(job)
                    .map(drop)
            },
            sink,
            capacity,
            notices,
        )
    }

    /// [`Self::spawn`] の本体。thread の生成器を差し替えられる（起動失敗の試験用）。
    fn spawn_with(
        start: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
        sink: Arc<dyn AuditSink>,
        capacity: usize,
        notices: LineSink,
    ) -> std::io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::sync_channel::<AuditRecord>(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let pending = Arc::new(AtomicUsize::new(0));
        let (d, p) = (Arc::clone(&dropped), Arc::clone(&pending));
        // join しない（sink が詰まってもシャットダウンを止めない）。tx が全て落ちると rx が閉じて終わる。
        start(Box::new(move || {
            loop {
                let received = rx.recv_timeout(FORWARDER_IDLE_TICK);
                let n = d.load(Ordering::Relaxed);
                if n > 0 {
                    let line = format!(
                        "{{\"event\":\"plugin_peer_audit_dropped\",\"outcome\":\"error\",\"count\":{n}}}"
                    );
                    // 通知を積めたときだけ引く（積めなければ保持して次回に回す。SEC-4）。
                    if notices.submit(line) {
                        d.fetch_sub(n, Ordering::Relaxed);
                    }
                }
                match received {
                    Ok(record) => {
                        if sink.record(&record).is_err() {
                            let token = record.reason().map_or("unknown", |r| r.as_str());
                            notices.submit(format!(
                                    "{{\"event\":\"plugin_peer_audit_unavailable\",\"outcome\":\"error\",\"reason\":\"{token}\"}}"
                                ));
                        }
                        p.fetch_sub(1, Ordering::Relaxed);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }
        }))?;
        Ok(Self {
            tx,
            dropped,
            pending,
        })
    }

    /// 拒否 1 件を型つきの記録にしてキューへ積む。ブロックしない。組み立てられない・積めない場合は欠落として数える。
    pub fn submit_rejection(&self, rejection: PluginPeerRejection, socket_path: &std::path::Path) {
        let (Ok(ts), Ok(pid)) = (AuditTimestamp::now(), current_pid()) else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let record = AuditRecord::new(ts, pid, rejection.audit_event(socket_path));
        self.pending.fetch_add(1, Ordering::Relaxed);
        if self.tx.try_send(record).is_err() {
            self.pending.fetch_sub(1, Ordering::Relaxed);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 通知にまだ出していない欠落件数。
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// 書き込み待ちが空になるまで最大 `timeout` 待つ（終了時の最後の書き出し・試験用。sink が止まっていても返る）。
    pub fn wait_idle(&self, timeout: Duration) {
        let deadline = std::time::Instant::now() + timeout;
        while self.pending.load(Ordering::Relaxed) > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// 共有バッファへ積む `PeerAuthObserver`。`UdsIncoming` に所有を渡した後も、共有側から回収できる。
/// 監査の永続化先（[`PeerAuditForwarder`]）を持たせると、拒否 1 件ごとに `AuditRecord` も 1 件渡す。
pub struct SharedPeerAuthObserver {
    inner: Arc<Mutex<JsonLinesPeerAuthObserver>>,
    audit: Option<Arc<PeerAuditForwarder>>,
}

impl SharedPeerAuthObserver {
    /// 観測フックと、回収用の共有バッファを作る。
    pub fn new() -> (Self, Arc<Mutex<JsonLinesPeerAuthObserver>>) {
        let inner = Arc::new(Mutex::new(JsonLinesPeerAuthObserver::new()));
        (
            Self {
                inner: Arc::clone(&inner),
                audit: None,
            },
            inner,
        )
    }

    /// 拒否を core の監査ログへも渡す口を付ける（SEC-4・#2484）。
    #[must_use]
    pub fn with_audit(mut self, audit: Arc<PeerAuditForwarder>) -> Self {
        self.audit = Some(audit);
        self
    }
}

impl PeerAuthObserver for SharedPeerAuthObserver {
    fn on_rejection(&mut self, event: &PeerAuthRejection<'_>) {
        lock(&self.inner).on_rejection(event);
        if let Some(audit) = &self.audit {
            audit.submit_rejection(plugin_peer_rejection(event.reason), event.socket_path);
        }
    }
}

/// 書き出し待ちの行の上限（満杯なら捨てて件数へ集約する。REPAIR-5）。
pub const SINK_CAPACITY: usize = 256;

/// `bytes` を書いて flush する。どちらかの失敗を呼び出し側へ返す。
fn write_flushed(w: &mut dyn Write, bytes: &[u8]) -> std::io::Result<()> {
    w.write_all(bytes)?;
    w.flush()
}

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
                    // 通知は書けた後にだけ件数を引く（書けなければ保持して次回に回す。SEC-4）。
                    let n = d.load(Ordering::Relaxed);
                    if n > 0 {
                        let notice = format!(
                            "{{\"event\":\"telemetry_dropped\",\"outcome\":\"error\",\"count\":{n}}}\n"
                        );
                        if write_flushed(&mut w, notice.as_bytes()).is_ok() {
                            d.fetch_sub(n, Ordering::Relaxed);
                        }
                    }
                    let mut bytes = line.into_bytes();
                    bytes.push(b'\n');
                    // 書き出しに失敗した行も欠落として件数へ加える（SEC-4）。
                    if write_flushed(&mut w, &bytes).is_err() {
                        d.fetch_add(1, Ordering::Relaxed);
                    }
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

/// 複数の記録器の操作統計を、記録器ごとのブロック（各ブロックは自分の `op_stats_meta` 行で終わる）として順に `sink` へ渡す。
/// 積めた行数の合計を返す（共有記録器と oci 専用記録器を分けて持つため。REPAIR-4・#2900）。
pub fn export_many_to(recorders: &[Arc<OpRecorder>], sink: &LineSink) -> usize {
    recorders.iter().map(|r| export_op_stats_to(r, sink)).sum()
}

/// `period` ごとに操作統計を stderr 書き出し口へ渡し続ける（呼び出し側が abort して止める）。
pub async fn op_stats_export_loop(recorder: Arc<OpRecorder>, period: Duration) {
    op_stats_export_loop_many(vec![recorder], period).await;
}

/// [`op_stats_export_loop`] の複数記録器版。1 周期に記録器の数だけブロック（`op_stats_meta` 行も同数）が出る
/// （本番は共有・oci 専用の順。#2900）。
pub async fn op_stats_export_loop_many(recorders: Vec<Arc<OpRecorder>>, period: Duration) {
    loop {
        tokio::time::sleep(period).await;
        export_many_to(&recorders, stderr_sink());
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

    /// 書き込み失敗は欠落件数へ加算され、復旧後の通知行で報告されて件数が 0 に戻る（SEC-4）。
    #[test]
    fn write_failure_is_counted_and_reported_after_recovery() {
        #[derive(Clone)]
        struct Flaky(Arc<Mutex<Vec<u8>>>, Arc<std::sync::atomic::AtomicBool>);
        impl Write for Flaky {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if self.1.load(Ordering::Relaxed) {
                    return Err(std::io::Error::other("broken pipe"));
                }
                lock(&self.0).extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let out = Arc::new(Mutex::new(Vec::new()));
        let failing = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let sink = LineSink::spawn(Box::new(Flaky(out.clone(), failing.clone())), 8);
        assert!(sink.submit("a".into()));
        assert!(sink.submit("b".into()));
        sink.wait_idle(Duration::from_secs(5));
        assert_eq!(sink.dropped(), 2);
        failing.store(false, Ordering::Relaxed);
        assert!(sink.submit("c".into()));
        sink.wait_idle(Duration::from_secs(5));
        let text = String::from_utf8(lock(&out).clone()).unwrap();
        assert!(text.contains("\"count\":2"), "{text}");
        assert!(text.ends_with("c\n"), "{text}");
        assert_eq!(sink.dropped(), 0);
    }

    /// 通知行の書き出しに失敗したら件数は保持される（SEC-4）。
    #[test]
    fn notice_failure_keeps_dropped_count() {
        struct FailNotice;
        impl Write for FailNotice {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if String::from_utf8_lossy(b).contains("telemetry_dropped") {
                    return Err(std::io::Error::other("full"));
                }
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = LineSink::spawn(Box::new(FailNotice), 1);
        sink.dropped.store(3, Ordering::Relaxed);
        assert!(sink.submit("x".into()));
        sink.wait_idle(Duration::from_secs(5));
        assert_eq!(sink.dropped(), 3);
    }

    /// テスト用の sink: 記録を溜める。`gate` が `Some` なら受信するまで `record` を止める。
    struct VecSink {
        records: Mutex<Vec<AuditRecord>>,
        gate: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        /// `record` が gate に入った（ワーカーが sink で止まった）ことを試験へ知らせる。
        entered: std::sync::atomic::AtomicBool,
        fail: bool,
    }

    impl VecSink {
        fn new(fail: bool) -> Arc<Self> {
            Arc::new(Self {
                records: Mutex::new(Vec::new()),
                gate: Mutex::new(None),
                entered: std::sync::atomic::AtomicBool::new(false),
                fail,
            })
        }
    }

    impl AuditSink for VecSink {
        fn record(
            &self,
            record: &AuditRecord,
        ) -> Result<(), fandhe_container_core::traits::TraitError> {
            let gate = lock(&self.gate).take();
            if let Some(rx) = gate {
                self.entered.store(true, Ordering::SeqCst);
                let _ = rx.recv();
            }
            if self.fail {
                return Err(fandhe_container_core::traits::TraitError::new(
                    fandhe_container_core::traits::ErrorCode::Internal,
                    "stub failure",
                ));
            }
            lock(&self.records).push(record.clone());
            Ok(())
        }
    }

    #[derive(Clone)]
    struct Collect(Arc<Mutex<Vec<u8>>>);
    impl Write for Collect {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            lock(&self.0).extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// SEC-4・PLUG-12・#2484: plugin 側の 4 理由が core の語彙へ写る。
    #[test]
    fn sec4_2484_reason_mapping_is_exact() {
        let cases = [
            (
                PeerAuthRejectReason::UidMismatch,
                "plugin_peer_uid_mismatch",
            ),
            (
                PeerAuthRejectReason::PeerUidUnavailable,
                "plugin_peer_uid_unavailable",
            ),
            (
                PeerAuthRejectReason::PidMismatch,
                "plugin_peer_pid_mismatch",
            ),
            (
                PeerAuthRejectReason::PeerPidUnavailable,
                "plugin_peer_pid_unavailable",
            ),
        ];
        for (reason, token) in cases {
            assert_eq!(plugin_peer_rejection(reason).as_str(), token);
        }
    }

    /// SEC-4・#2232 申し送り: 1 回の受付の最大件数（LIMIT + 1 = 17）を連続で積んでも全件 sink に届く。
    #[test]
    fn sec4_2484_max_burst_is_not_dropped() {
        let sink = VecSink::new(false);
        let notices = LineSink::spawn(Box::new(std::io::sink()), 4);
        let fwd =
            PeerAuditForwarder::spawn(sink.clone(), PEER_AUDIT_QUEUE_CAPACITY, notices).unwrap();
        let burst = UDS_ACCEPT_PEER_REJECTION_LIMIT as usize + 1;
        assert_eq!(burst, 17);
        for _ in 0..burst {
            fwd.submit_rejection(
                PluginPeerRejection::PeerUidMismatch,
                std::path::Path::new("/run/p/cri.sock"),
            );
        }
        fwd.wait_idle(Duration::from_secs(5));
        let records = lock(&sink.records);
        assert_eq!(records.len(), 17);
        assert_eq!(fwd.dropped(), 0);
        let first = records.first().unwrap();
        assert_eq!(
            first.reason().map(|r| r.as_str()),
            Some("plugin_peer_uid_mismatch")
        );
        assert_eq!(first.path(), Some(std::path::Path::new("/run/p/cri.sock")));
    }

    /// REPAIR-5・SEC-4: sink が止まっても submit はブロックせず、あふれた分は件数に集約され通知される。
    #[test]
    fn repair5_2484_stalled_sink_does_not_block_and_reports_drops() {
        let sink = VecSink::new(false);
        let (gate, rx) = std::sync::mpsc::channel();
        *lock(&sink.gate) = Some(rx);
        let out = Arc::new(Mutex::new(Vec::new()));
        let notices = LineSink::spawn(Box::new(Collect(out.clone())), 8);
        let fwd = PeerAuditForwarder::spawn(sink.clone(), 2, notices.clone()).unwrap();
        let reject = || {
            fwd.submit_rejection(
                PluginPeerRejection::PeerUidMismatch,
                std::path::Path::new("/s.sock"),
            )
        };
        // ワーカーが sink の gate で止まるまで待つ。ワーカーは記録を取り出す前に欠落件数を通知して引くため、
        // 止まる前に溢れさせると件数が引かれて下限が不定になる（間欠失敗の原因）。
        reject();
        let wait = std::time::Instant::now() + Duration::from_secs(5);
        while !sink.entered.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < wait,
                "worker never entered sink"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let started = std::time::Instant::now();
        for _ in 0..20 {
            reject();
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        // ワーカーは止まっているので引かれない。キュー容量 2 が埋まり、残り 18 件がちょうど欠落になる。
        let dropped = fwd.dropped();
        assert_eq!(dropped, 18);
        drop(gate);
        fwd.wait_idle(Duration::from_secs(5));
        // 次の記録（または 1 秒の周期）で欠落が通知される。
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while fwd.dropped() > 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(fwd.dropped(), 0);
        notices.wait_idle(Duration::from_secs(5));
        let text = String::from_utf8(lock(&out).clone()).unwrap();
        assert!(
            text.contains(&format!(
                "{{\"event\":\"plugin_peer_audit_dropped\",\"outcome\":\"error\",\"count\":{dropped}}}"
            )),
            "{text}"
        );
    }

    /// SEC-4・PLUG-12・#2484: thread を作れないときは `Err` を返し、黙って欠落口を返さない。
    #[test]
    fn sec4_2484_spawn_failure_is_returned() {
        let sink = VecSink::new(false);
        let notices = LineSink::spawn(Box::new(std::io::sink()), 4);
        let r = PeerAuditForwarder::spawn_with(
            |_job| Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
            sink,
            8,
            notices,
        );
        assert_eq!(
            r.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::WouldBlock)
        );
    }

    /// SEC-4・#2484: sink が失敗したら黙らず固定語彙の通知行を出す。
    #[test]
    fn sec4_2484_sink_failure_is_reported() {
        let sink = VecSink::new(true);
        let out = Arc::new(Mutex::new(Vec::new()));
        let notices = LineSink::spawn(Box::new(Collect(out.clone())), 8);
        let fwd = PeerAuditForwarder::spawn(sink, 8, notices.clone()).unwrap();
        fwd.submit_rejection(
            PluginPeerRejection::PeerPidMismatch,
            std::path::Path::new("/s.sock"),
        );
        fwd.wait_idle(Duration::from_secs(5));
        notices.wait_idle(Duration::from_secs(5));
        let text = String::from_utf8(lock(&out).clone()).unwrap();
        assert_eq!(
            text,
            "{\"event\":\"plugin_peer_audit_unavailable\",\"outcome\":\"error\",\"reason\":\"plugin_peer_pid_mismatch\"}\n"
        );
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

    /// REPAIR-4・#2900: 2 つの記録器は記録器ごとのブロック（データ行 + `op_stats_meta` 行）で、共有・oci の順に出る。
    #[test]
    fn op_stats_many_exports_one_block_per_recorder() {
        let mk = |n: &str| {
            let r = Arc::new(OpRecorder::new());
            r.record(
                &OpName::new(n).unwrap(),
                OpOutcome::Success,
                Duration::from_millis(1),
            )
            .unwrap();
            r
        };
        let recorders = vec![mk("cri.run_pod_sandbox"), mk("oci.layer.extract")];
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
        assert_eq!(export_many_to(&recorders, &sink), 4);
        sink.wait_idle(Duration::from_secs(5));
        let text = String::from_utf8(lock(&buf.0).clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        assert!(lines[0].contains("cri.run_pod_sandbox"), "{text}");
        assert!(lines[1].contains("op_stats_meta"), "{text}");
        assert!(lines[2].contains("oci.layer.extract"), "{text}");
        assert!(lines[3].contains("op_stats_meta"), "{text}");
    }
}
