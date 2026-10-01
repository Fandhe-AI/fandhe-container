//! 監査レコード型の公開 API 結合テスト（SEC-4・TASK-41.1・#192。REPAIR-12 の機械照合）。
//!
//! 外部 crate の立場から `fandhe_container_core::audit_log` の型で 3 レイヤーのレコードを組み立て、
//! 受入基準（各フィールドの表現・不正値の構築拒否）を具体値で照合する。cfg を付けないため
//! 3 OS の CI で実行され、型が OS 非依存であることの保証にもなる。

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use fandhe_container_core::audit_log::{
    AuditEvent, AuditLayer, AuditPath, AuditPid, AuditRecord, AuditRecordErrorKind, AuditSink,
    AuditSyscallArch, AuditSyscallNr, AuditTimestamp, SeccompDenialReport, record_seccomp_denial,
};
use fandhe_container_core::traits::TraitError;

fn ts() -> AuditTimestamp {
    AuditTimestamp::from_unix_duration(Duration::from_secs(1_700_000_000))
}

#[test]
fn sec4_task41_1_three_layers_are_representable() {
    let pid = AuditPid::new(1234).unwrap();
    let seccomp = AuditRecord::new(
        ts(),
        pid,
        AuditEvent::Seccomp {
            syscall: AuditSyscallNr::new(272).unwrap(),
            arch: AuditSyscallArch::from_raw(0xC000_003E),
        },
    );
    assert_eq!(seccomp.layer().as_str(), "seccomp");
    assert_eq!(seccomp.syscall().map(AuditSyscallNr::get), Some(272));
    assert_eq!(seccomp.path(), None);

    let landlock = AuditRecord::new(
        ts(),
        pid,
        AuditEvent::Landlock {
            path: AuditPath::new("/etc/passwd"),
            syscall: None,
        },
    );
    assert_eq!(landlock.layer(), AuditLayer::Landlock);
    assert_eq!(landlock.path(), Some(Path::new("/etc/passwd")));

    let mount = AuditRecord::new(ts(), pid, AuditEvent::Mount { path: None });
    assert_eq!(mount.layer().as_str(), "mount");
    assert_eq!(mount.pid().get(), 1234);
    assert_eq!(
        mount.timestamp().as_unix_duration().as_secs(),
        1_700_000_000
    );
}

#[test]
fn sec4_task41_1_invalid_values_cannot_be_constructed() {
    assert_eq!(
        AuditPid::new(0).unwrap_err().kind(),
        AuditRecordErrorKind::PidNotPositive
    );
    assert_eq!(
        AuditSyscallNr::new(-5).unwrap_err().kind(),
        AuditRecordErrorKind::SyscallNegative
    );
    // 拒否される不正パスも記録可能（SEC-4）。
    let empty = AuditPath::new("");
    assert_eq!(empty.as_path(), Path::new(""));
    assert!(!empty.is_truncated());
}

#[derive(Default)]
struct VecSink(Mutex<Vec<AuditRecord>>);

impl AuditSink for VecSink {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        self.0.lock().unwrap().push(record.clone());
        Ok(())
    }
}

/// SEC-4・TASK-41.2: 拒否報告 1 件につきレコードが 1 件、番号・arch・pid が報告と一致する。
#[test]
fn sec4_task41_2_denial_report_yields_exactly_one_matching_record() {
    let sink = VecSink::default();
    let sigsys = SeccompDenialReport::from_sigsys(1, 272, 0xC000_003E, 42).unwrap();
    record_seccomp_denial(&sigsys, ts(), &sink).unwrap();
    assert_eq!(sink.0.lock().unwrap().len(), 1);
    let notif = SeccompDenialReport::from_user_notif(7, 97, 0xC000_00B7).unwrap();
    record_seccomp_denial(&notif, ts(), &sink).unwrap();
    assert_eq!(sink.0.lock().unwrap().len(), 2);
    let records = sink.0.lock().unwrap();
    let got: Vec<(u32, u32, u32)> = records
        .iter()
        .map(|r| {
            (
                r.syscall().unwrap().get(),
                r.seccomp_arch().unwrap().get(),
                r.pid().get(),
            )
        })
        .collect();
    assert_eq!(got, vec![(272, 0xC000_003E, 42), (97, 0xC000_00B7, 7)]);
    assert!(records.iter().all(|r| r.layer().as_str() == "seccomp"));
}

#[test]
fn sec4_task41_2_non_seccomp_signal_is_rejected() {
    assert_eq!(
        SeccompDenialReport::from_sigsys(2, 272, 0xC000_003E, 42)
            .unwrap_err()
            .kind(),
        AuditRecordErrorKind::NotSeccompSignal
    );
}
