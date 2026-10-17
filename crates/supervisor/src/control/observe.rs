//! 制御チャネルの監査と計測（Linux。SEC-4・REPAIR-4・SUP-1・SEC-1・#2058）。
//!
//! サーバ（[`super::server`]）が認証境界の拒否と各要求の結果を渡す先。
//!
//! - **監査**（SEC-4）: 別 uid・資格情報を確かめられない接続の拒否を、core の `AuditSink`
//!   （本番は `FileAuditSink`。ファイル追記が主経路でカーネル監査が代替）へ `ControlPeer` レコードとして 1 件記録する。
//!   記録の成否は拒否の判定を覆さない（fail-closed）。記録できなかったときだけ構造化ログへ出す。
//! - **計測**（REPAIR-4）: 要求ごとの成功・失敗とレイテンシを `OpRecorder` へ集計し、1 要求 1 行の構造化ログ
//!   （固定語彙と数値のみ。入力値・uid・パスは載せない）で出す。ログは待たない出力経路へ渡すだけで、
//!   キュー満杯なら捨てる（REPAIR-5）。

use std::sync::Arc;
use std::time::Duration;

use fandhe_container_core::audit_log::{
    AuditRecord, AuditSink, AuditTimestamp, ControlPeerRejection, current_pid,
};
use fandhe_container_core::observability::{OpName, OpOutcome, OpRecorder};
use fandhe_container_core::traits::ContainerId;

use super::log_control_event;

/// 要求の計測に使う操作名（`OpRecorder`）。
const OP_NAME: &str = "control_signal";

/// 監査の記録先と計測の集計器を束ねた観測の口。サーバが共有で持つ。
pub struct ControlObserver {
    audit: Option<Arc<dyn AuditSink>>,
    container: Option<ContainerId>,
    recorder: OpRecorder,
}

impl ControlObserver {
    /// `audit` は本番で `FileAuditSink`。開けなかったときは `None`（記録先が無いことを構造化ログに残す）。
    pub fn new(audit: Option<Arc<dyn AuditSink>>, container: Option<ContainerId>) -> Self {
        Self {
            audit,
            container,
            recorder: OpRecorder::new(),
        }
    }

    /// 集計器（試験と将来のメトリクス出力用）。
    pub fn recorder(&self) -> &OpRecorder {
        &self.recorder
    }

    /// 認証境界の拒否を監査の記録先へ 1 件記録する。記録できなければ構造化ログに出す。
    pub fn record_peer_rejection(&self, rejection: ControlPeerRejection) {
        log_control_event("control_peer_rejected", Some(rejection.as_str()));
        let delivered = self.audit.as_ref().is_some_and(|sink| {
            let (Ok(ts), Ok(pid)) = (AuditTimestamp::now(), current_pid()) else {
                return false;
            };
            let mut record = AuditRecord::new(ts, pid, rejection.audit_event());
            if let Some(id) = &self.container {
                record = record.with_container_id(id.clone());
            }
            sink.record(&record).is_ok()
        });
        if !delivered {
            log_control_event("control_audit_unavailable", Some(rejection.as_str()));
        }
    }

    /// 1 要求の結果とレイテンシを集計し、構造化ログを 1 行出す。
    pub fn record_request(&self, success: bool, elapsed: Duration) {
        let Ok(name) = OpName::new(OP_NAME) else {
            return;
        };
        let outcome = if success {
            OpOutcome::Success
        } else {
            OpOutcome::Failure
        };
        let _ = self.recorder.record(&name, outcome, elapsed);
        let (ok, ng) = self
            .recorder
            .snapshot_op(&name)
            .map_or((0, 0), |s| (s.success(), s.failure()));
        let line = format!(
            "{{\"component\":\"supervisor\",\"event\":\"control_request\",\"op\":\"{OP_NAME}\",\"outcome\":\"{}\",\"latency_us\":{},\"success_total\":{ok},\"failure_total\":{ng}}}\n",
            if success { "ok" } else { "error" },
            elapsed.as_micros()
        );
        let _ = crate::stderr_sink::stderr().emit(line.into_bytes());
    }
}
