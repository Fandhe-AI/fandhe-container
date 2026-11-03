//! launch の状態 pipe 経由で、Landlock 段の Mount 由来のルールの照合の違反が親の監査に届く結合試験
//! （SEC-1・SEC-4・CORE-5・REPAIR-12。#2130）。
//!
//! 子の符号化（`E landlock ...`）→ 状態 pipe → 親の厳格な復号 → 層 `mount` の記録までを、本番と同じ関数
//! （`exec-test-support` の入口 `relay_landlock_failure_for_test`）で往復させる。root・実コンテナは不要で、
//! Linux の既定のテスト集合で動く。非 Linux では `exec` モジュール自体が無い（OS 非該当）。

#![cfg(target_os = "linux")]

use std::sync::Mutex;

use fandhe_container_core::audit_log::{AuditDelivery, AuditLayer, AuditRecord, AuditSink};
use fandhe_container_core::exec::{ViolationReason, relay_landlock_failure_for_test};
use fandhe_container_core::traits::{ContainerId, ErrorCode, TraitError};

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

/// SEC-4・SEC-1・CORE-5・#2130: Landlock 段の 3 理由は、親側の層 `mount` に理由コードだけ（パスなし）で
/// 1 拒否 1 件ずつ記録される。
#[test]
fn sec4_2130_every_landlock_reason_reaches_parent_audit() {
    let id = ContainerId::new("c2130").unwrap();
    let cases = [
        (
            ViolationReason::LandlockMountIdentityMismatch,
            "landlock_mount_identity_mismatch",
        ),
        (
            ViolationReason::LandlockMountNotRoot,
            "landlock_mount_not_root",
        ),
        (
            ViolationReason::LandlockMountNotReadOnly,
            "landlock_mount_not_read_only",
        ),
    ];
    for (reason, token) in cases {
        let sink = VecSink(Mutex::new(Vec::new()));
        let r = relay_landlock_failure_for_test(reason, &sink, Some(&id)).unwrap_err();
        assert_eq!(r.delivery, AuditDelivery::Recorded, "{token}");
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

/// SEC-4・#2130: 段 `landlock` で許可しない理由（entrypoint 系）は子の符号化で落ち、記録されず理由なしで届く。
#[test]
fn sec4_2130_non_landlock_reason_is_not_recorded() {
    let sink = VecSink(Mutex::new(Vec::new()));
    let r =
        relay_landlock_failure_for_test(ViolationReason::EntrypointIsRuntimeBinary, &sink, None)
            .unwrap_err();
    assert_eq!(r.delivery, AuditDelivery::NotApplicable);
    assert!(r.error.violation.is_none());
    assert!(sink.0.lock().unwrap().is_empty());
}
