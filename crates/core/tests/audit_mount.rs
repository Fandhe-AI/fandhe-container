//! マウント検証/API レイヤーの監査記録の結合試験（SEC-4・OCI-4・CORE-2・TASK-41.4・#195）。
//!
//! 公開 API だけを crate の外から呼ぶ。実機権限は不要で 3 OS の既定のテスト集合で動く。

use std::path::Path;
use std::sync::Mutex;

use fandhe_container_core::audit_log::{
    AuditDelivery, AuditLayer, AuditRecord, AuditSink, record_mount_rejection,
};
use fandhe_container_core::oci_runtime::{audit_mount_config_error, parse_config_bytes};
use fandhe_container_core::traits::{ErrorCode, TraitError};

/// 件数上限付きのテスト用 sink。
struct VecSink(Mutex<Vec<AuditRecord>>);

impl AuditSink for VecSink {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        let mut g = self
            .0
            .lock()
            .map_err(|_| TraitError::new(ErrorCode::Internal, "poisoned"))?;
        if g.len() >= 16 {
            return Err(TraitError::new(ErrorCode::Internal, "full"));
        }
        g.push(record.clone());
        Ok(())
    }
}

fn config(mounts: &str, args: &str) -> String {
    format!(
        r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs"}},
"process":{{"user":{{"uid":0,"gid":0}},"args":{args},"cwd":"/"}},
"mounts":{mounts}}}"#
    )
}

/// SEC-4: 不正な mounts destination の拒否が path なしの Mount レコード 1 件になる。
#[test]
fn sec4_task41_4_rejected_destination_is_recorded() {
    let sink = VecSink(Mutex::new(Vec::new()));
    let json = config(r#"[{"destination":"/../etc"}]"#, r#"["/bin/sh"]"#);
    let err = parse_config_bytes(json.as_bytes()).expect_err("rejected");
    let r = audit_mount_config_error(err, &sink);
    assert_eq!(r.delivery, AuditDelivery::Recorded);
    assert_eq!(r.error.code(), ErrorCode::InvalidArgument);
    let g = sink.0.lock().expect("lock");
    assert_eq!(g.len(), 1);
    assert_eq!(g[0].layer(), AuditLayer::Mount);
    assert_eq!(g[0].syscall(), None);
    assert_eq!(g[0].path(), None);
    assert_eq!(g[0].pid().get(), std::process::id());
}

/// SEC-4: マウント以外の拒否は記録しない。
#[test]
fn sec4_task41_4_non_mount_rejection_not_recorded() {
    let sink = VecSink(Mutex::new(Vec::new()));
    let json = config(r#"[{"destination":"/proc"}]"#, "[]");
    let err = parse_config_bytes(json.as_bytes()).expect_err("rejected");
    let r = audit_mount_config_error(err, &sink);
    assert_eq!(r.delivery, AuditDelivery::NotApplicable);
    assert_eq!(sink.0.lock().expect("lock").len(), 0);
}

/// SEC-4: パス付きの記録（公開 API）。
#[test]
fn sec4_task41_4_record_mount_rejection_with_path() {
    let sink = VecSink(Mutex::new(Vec::new()));
    let r = record_mount_rejection((), Some(Path::new("/etc")), &sink);
    assert_eq!(r.delivery, AuditDelivery::Recorded);
    assert_eq!(
        sink.0.lock().expect("lock")[0].path(),
        Some(Path::new("/etc"))
    );
}
