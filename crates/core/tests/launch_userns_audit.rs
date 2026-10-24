//! launch の状態 pipe 経由で、bind mount の段の user namespace 由来の拒否理由が親の監査に届く結合試験
//! （SEC-4・SEC-5・REPAIR-10・REPAIR-12。TASK-29 追補・#2072）。
//!
//! 子の符号化 → 状態 pipe → 親の厳格な復号 → 層 `mount` の記録までを、本番と同じ関数
//! （`exec-test-support` の入口 `relay_mount_binds_failure_for_test`）で往復させる。root・実コンテナは不要で、
//! Linux の既定のテスト集合で動く。非 Linux では `exec` モジュール自体が無い（OS 非該当）。

#![cfg(target_os = "linux")]

use std::sync::Mutex;

use fandhe_container_core::audit_log::{AuditDelivery, AuditLayer, AuditRecord, AuditSink};
use fandhe_container_core::exec::{ViolationReason, relay_mount_binds_failure_for_test};
use fandhe_container_core::traits::{ErrorCode, TraitError};

struct VecSink(Mutex<Vec<AuditRecord>>);

impl AuditSink for VecSink {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        let mut g = self
            .0
            .lock()
            .map_err(|_| TraitError::new(ErrorCode::Internal, "poisoned"))?;
        g.push(record.clone());
        Ok(())
    }
}

/// SEC-4・SEC-5・#2072: 追加した 2 理由は launch の報告経路を通り、親側の層 `mount` に理由コードだけ
/// （パスなし）で 1 件ずつ記録され、エラーのコードは理由に対応する値になる。
#[test]
fn sec4_sec5_2072_bind_userns_reasons_reach_parent_audit() {
    for (reason, token, code) in [
        (
            ViolationReason::UserNamespaceRequired,
            "user_namespace_required",
            ErrorCode::InvalidArgument,
        ),
        (
            ViolationReason::HostRootIdentityMapping,
            "host_root_identity_mapping",
            ErrorCode::FailedPrecondition,
        ),
    ] {
        let sink = VecSink(Mutex::new(Vec::new()));
        let r = relay_mount_binds_failure_for_test(reason, &sink, None).unwrap_err();
        assert_eq!(r.delivery, AuditDelivery::Recorded, "{token}");
        assert_eq!(r.error.code, code, "{token}");
        assert_eq!(
            r.error.violation.as_ref().map(|v| v.reason.as_str()),
            Some(token)
        );
        let recs = sink.0.lock().unwrap();
        assert_eq!(recs.len(), 1, "{token}");
        assert_eq!(recs[0].layer(), AuditLayer::Mount);
        assert_eq!(recs[0].path(), None);
        assert_eq!(recs[0].reason().map(|x| x.as_str()), Some(token));
    }
}

/// 段 `mount_binds` でも許可リスト外の理由（`NoNamespaces`）は子で落ち、記録されず理由なしで届く。
#[test]
fn sec4_2072_other_reason_is_not_recorded() {
    let sink = VecSink(Mutex::new(Vec::new()));
    let r =
        relay_mount_binds_failure_for_test(ViolationReason::NoNamespaces, &sink, None).unwrap_err();
    assert_eq!(r.delivery, AuditDelivery::NotApplicable);
    assert!(r.error.violation.is_none());
    assert!(sink.0.lock().unwrap().is_empty());
}

/// SEC-4・#2624: launch の PID 1 が exec 前に返す entrypoint 系の違反 8 理由は、状態 pipe の 2 行目を通り、
/// 親側の層 `entrypoint` に理由コードだけ（パスなし）で 1 拒否 1 件ずつ記録される。
#[test]
fn sec4_2624_every_entrypoint_reason_reaches_parent_audit() {
    use fandhe_container_core::exec::relay_entrypoint_violation_for_test;
    use fandhe_container_core::traits::ContainerId;

    let id = ContainerId::new("c2624").unwrap();
    assert_eq!(ViolationReason::ENTRYPOINT_REASONS.len(), 8);
    for reason in ViolationReason::ENTRYPOINT_REASONS {
        let token = reason.as_str();
        let sink = VecSink(Mutex::new(Vec::new()));
        let r = relay_entrypoint_violation_for_test(reason, &sink, Some(&id)).unwrap_err();
        assert_eq!(r.delivery, AuditDelivery::Recorded, "{token}");
        assert_eq!(
            r.error.violation.as_ref().map(|v| v.reason.as_str()),
            Some(token)
        );
        let recs = sink.0.lock().unwrap();
        assert_eq!(recs.len(), 1, "{token}");
        assert_eq!(recs[0].layer(), AuditLayer::Entrypoint);
        assert_eq!(recs[0].path(), None);
        assert_eq!(recs[0].reason().map(|x| x.as_str()), Some(token));
    }
}

/// SEC-4・#2624: entrypoint 系ではない理由（マウント層の `NoNamespaces`）は子の符号化で落ち、記録されない。
#[test]
fn sec4_2624_non_entrypoint_reason_is_not_recorded() {
    use fandhe_container_core::exec::relay_entrypoint_violation_for_test;

    let sink = VecSink(Mutex::new(Vec::new()));
    let r = relay_entrypoint_violation_for_test(ViolationReason::NoNamespaces, &sink, None)
        .unwrap_err();
    assert_eq!(r.delivery, AuditDelivery::NotApplicable);
    assert!(r.error.violation.is_none());
    assert!(sink.0.lock().unwrap().is_empty());
}
