//! 稼働中の可観測性出力（peer 認証の拒否の監査行と CRI 操作の件数・レイテンシ。SEC-4・REPAIR-4・REPAIR-5）。
//!
//! 呼び出し元は `server::serve`（監査の配送）と `main.rs`（操作統計の定期出力）。
//! `fandhe-container-plugin` の `JsonLinesPeerAuthObserver` はメモリへ積むだけで出力しないため、
//! 受付の外（別 task）で回収して stderr へ JSON Lines で書く。受付処理（`on_rejection`）は
//! 短い mutex の取得とメモリへの追記だけで、I/O をしない。
//!
//! # 未実装（REPAIR-3）
//! 出力先は stderr のみ。`crates/core` の永続的な監査ログ・メトリクス公開口への接続は #1869 の core 側 proxy の責務。

use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};
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

/// 積まれた監査行を `w` へ書く。書いた行数を返す（書き込み失敗は受付に影響させない）。
pub fn drain_audit_to(buf: &Mutex<JsonLinesPeerAuthObserver>, w: &mut dyn Write) -> usize {
    let lines = lock(buf).drain_lines();
    let mut n = 0;
    for l in &lines {
        if w.write_all(l.as_bytes()).is_err() || w.write_all(b"\n").is_err() {
            break;
        }
        n += 1;
    }
    let _ = w.flush();
    n
}

/// `period` ごとに監査行を stderr へ書き続ける（呼び出し側が abort して止める）。
pub async fn audit_drain_loop(buf: Arc<Mutex<JsonLinesPeerAuthObserver>>, period: Duration) {
    loop {
        tokio::time::sleep(period).await;
        drain_audit_to(&buf, &mut std::io::stderr());
    }
}

/// 操作統計を JSON Lines で `w` へ書く。書いた行数（失敗時は 0）を返す。
pub fn export_op_stats_to(recorder: &OpRecorder, w: &mut dyn Write) -> usize {
    let mut out: Vec<u8> = Vec::new();
    match recorder.export_json_lines(Some(&mut out)) {
        Ok(r) if w.write_all(&out).is_ok() => {
            let _ = w.flush();
            r.lines_written()
        }
        _ => 0,
    }
}

/// `period` ごとに操作統計を stderr へ書き続ける（呼び出し側が abort して止める）。
pub async fn op_stats_export_loop(recorder: Arc<OpRecorder>, period: Duration) {
    loop {
        tokio::time::sleep(period).await;
        export_op_stats_to(&recorder, &mut std::io::stderr());
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
        let mut out = Vec::new();
        assert_eq!(drain_audit_to(&buf, &mut out), 0);
        assert!(out.is_empty());
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
        let mut out = Vec::new();
        assert_eq!(export_op_stats_to(&r, &mut out), 2);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("cri.run_pod_sandbox"), "{text}");
    }
}
