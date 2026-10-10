//! マウント検証/API レイヤーの拒否を監査レコードにして記録先へ渡す共通処理（SEC-4・TASK-41.4・#195）。
//!
//! # 役割と呼び出し元
//!
//! - `exec::audit_mount_violation`（Linux のマウント検証層。`IsolationViolation` の写像）と
//!   `oci_runtime` の `audit_mount_config_error` / `MountDestination::resolve_in_audited`
//!   （API 層）が、拒否を返す直前に `deliver` / [`record_mount_rejection`] を呼ぶ
//! - 時刻と PID は拒否を返した直後に同じプロセスで取得する（「拒否と同時」の意味）
//! - OS 非依存（3 OS でコンパイルされる）
//!
//! # 契約
//!
//! - **記録の成否で拒否を覆さない**（fail-closed）。拒否エラーは [`AuditedRejection::error`] に
//!   そのまま返り、記録の結果は [`AuditDelivery`] に載る（黙って捨てない）
//! - 1 回の拒否につき sink へ渡すのは 1 件
//! - マウント層の拒否ではないエラーは記録せず [`AuditDelivery::NotApplicable`] を返す
//!
//! # 未実装（REPAIR-3）
//!
//! 本番 sink `FileAuditSink`（#1594）は実装済み。本番 launcher・fork 後の子プロセスへの `AuditSink` の引き回しは
//! 後続（TASK-29 / TASK-157 系）。現時点で本番経路からは呼ばれない。

use std::path::Path;

use crate::traits::{ContainerId, TraitError};

use super::{
    AuditEvent, AuditPath, AuditPid, AuditRecord, AuditRecordError, AuditSink, AuditTimestamp,
};

/// 記録の結果。真偽値にせず将来拡張できる形にする。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditDelivery {
    /// sink が 1 件受理した。
    Recorded,
    /// sink が記録に失敗した。
    SinkFailed(TraitError),
    /// 時計異常または PID 変換不能でレコードを組み立てられなかった。
    RecordUnavailable(AuditRecordError),
    /// マウント層の拒否ではないため記録しなかった。
    NotApplicable,
}

/// 拒否エラーと記録結果の組。`error` は記録の成否に関わらず元のまま。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditedRejection<E> {
    /// 元の拒否エラー（変更しない）。
    pub error: E,
    /// 記録の結果。
    pub delivery: AuditDelivery,
}

impl<E> AuditedRejection<E> {
    /// 記録しなかった（対象外の）拒否として包む。
    pub fn not_applicable(error: E) -> Self {
        Self {
            error,
            delivery: AuditDelivery::NotApplicable,
        }
    }
}

/// 自プロセス（記録を行うプロセス）の PID。`i32` に収まらない値は `PidNotPositive`（panic しない）。
///
/// 違反したプロセスや pid1 の PID ではない。コンテナとの対応はレコードの `container_id` で取る（#1618）。
pub fn current_pid() -> Result<AuditPid, AuditRecordError> {
    let raw = i32::try_from(std::process::id()).unwrap_or(0);
    AuditPid::new(raw)
}

/// 現在時刻・自 PID でレコードを組み立てて sink へ 1 回だけ渡す。
///
/// 記録の `pid` は**記録を行うプロセス**（supervisor・exec の親・launch の側）のもので、違反した
/// プロセスや pid1 ではない。対象のコンテナは検証済みの `container`（不明なら `None`）で示す（#1618）。
pub(crate) fn deliver(
    event: AuditEvent,
    container: Option<&ContainerId>,
    sink: &dyn AuditSink,
) -> AuditDelivery {
    let timestamp = match AuditTimestamp::now() {
        Ok(t) => t,
        Err(e) => return AuditDelivery::RecordUnavailable(e),
    };
    let pid = match current_pid() {
        Ok(p) => p,
        Err(e) => return AuditDelivery::RecordUnavailable(e),
    };
    let mut record = AuditRecord::new(timestamp, pid, event);
    if let Some(id) = container {
        record = record.with_container_id(id.clone());
    }
    match sink.record(&record) {
        Ok(()) => AuditDelivery::Recorded,
        Err(e) => AuditDelivery::SinkFailed(e),
    }
}

/// マウント拒否 `error` を `Mount` レコードとして記録し、`error` をそのまま返す。
///
/// `path` は分かる場合のみ（計画段階の拒否は `None`）。
///
/// 移行（#1618）: 引数 `container` を `sink` の直前に追加した。対象のコンテナ ID が無い呼び出し側は
/// `None` を渡す（記録の `container_id` は null になる）。
pub fn record_mount_rejection<E>(
    error: E,
    path: Option<&Path>,
    container: Option<&ContainerId>,
    sink: &dyn AuditSink,
) -> AuditedRejection<E> {
    let event = AuditEvent::Mount {
        path: path.map(AuditPath::new),
    };
    let delivery = deliver(event, container, sink);
    AuditedRejection { error, delivery }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::audit_log::{AuditLayer, AuditRecordErrorKind};
    use crate::traits::ErrorCode;
    use std::sync::Mutex;

    /// テスト用 sink（件数上限付き）。
    pub(crate) struct VecSink {
        pub(crate) records: Mutex<Vec<AuditRecord>>,
        pub(crate) fail: bool,
    }

    impl VecSink {
        pub(crate) fn new(fail: bool) -> Self {
            Self {
                records: Mutex::new(Vec::new()),
                fail,
            }
        }
        pub(crate) fn snapshot(&self) -> Vec<AuditRecord> {
            self.records.lock().map(|r| r.clone()).unwrap_or_default()
        }
    }

    impl AuditSink for VecSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            if self.fail {
                return Err(TraitError::new(ErrorCode::Internal, "sink failed"));
            }
            let mut g = self
                .records
                .lock()
                .map_err(|_| TraitError::new(ErrorCode::Internal, "poisoned"))?;
            if g.len() >= 16 {
                return Err(TraitError::new(ErrorCode::Internal, "sink full"));
            }
            g.push(record.clone());
            Ok(())
        }
    }

    /// SEC-4: パス付き拒否が Mount レコード 1 件になる。
    #[test]
    fn sec4_task41_4_records_one_mount_record_with_path() {
        let sink = VecSink::new(false);
        let r = record_mount_rejection("denied", Some(Path::new("/proc/sys")), None, &sink);
        assert_eq!(r.error, "denied");
        assert_eq!(r.delivery, AuditDelivery::Recorded);
        let recs = sink.snapshot();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::Mount);
        assert_eq!(recs[0].syscall(), None);
        assert_eq!(recs[0].path(), Some(Path::new("/proc/sys")));
        assert_eq!(recs[0].pid().get(), std::process::id());
        assert_eq!(recs[0].container_id(), None);
    }

    /// SEC-4・#1618: 検証済みのコンテナ ID が記録に載る。pid は記録したプロセス自身のまま。
    #[test]
    fn sec4_1618_records_container_id() {
        let sink = VecSink::new(false);
        let id = ContainerId::new("c1").unwrap();
        let r = record_mount_rejection("denied", None, Some(&id), &sink);
        assert_eq!(r.delivery, AuditDelivery::Recorded);
        let recs = sink.snapshot();
        assert_eq!(recs[0].container_id().map(ContainerId::as_str), Some("c1"));
        assert_eq!(recs[0].pid().get(), std::process::id());
    }

    /// SEC-4: パス無しの拒否は path なしで記録される。
    #[test]
    fn sec4_task41_4_records_without_path() {
        let sink = VecSink::new(false);
        let r = record_mount_rejection(7u8, None, None, &sink);
        assert_eq!(r.delivery, AuditDelivery::Recorded);
        assert_eq!(sink.snapshot()[0].path(), None);
    }

    /// SEC-4・fail-closed: sink が失敗しても拒否エラーは変わらない。
    #[test]
    fn sec4_task41_4_sink_failure_keeps_rejection() {
        let sink = VecSink::new(true);
        let r = record_mount_rejection("denied", None, None, &sink);
        assert_eq!(r.error, "denied");
        assert_eq!(
            r.delivery,
            AuditDelivery::SinkFailed(TraitError::new(ErrorCode::Internal, "sink failed"))
        );
        assert_eq!(sink.snapshot().len(), 0);
    }

    #[test]
    fn sec4_task41_4_current_pid_matches_process() {
        assert_eq!(current_pid().map(|p| p.get()), Ok(std::process::id()));
        assert_eq!(
            AuditPid::new(0).map_err(|e| e.kind()),
            Err(AuditRecordErrorKind::PidNotPositive)
        );
    }
}
