//! 監査ログのローカルファイル書き込み経路の結合テスト（SEC-4・TASK-41.5.1・#839）。

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use fandhe_container_core::audit_log::{
    AuditEvent, AuditFileWriter, AuditPath, AuditPid, AuditRecord, AuditSyscallNr, AuditTimestamp,
    AuditWriteErrorKind,
};
use fandhe_container_core::traits::ErrorCode;

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("afw-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn rec(n: i32) -> AuditRecord {
    AuditRecord::new(
        AuditTimestamp::from_unix_duration(Duration::new(1, 2)),
        AuditPid::new(n).unwrap(),
        AuditEvent::Seccomp {
            syscall: AuditSyscallNr::new(272).unwrap(),
        },
    )
}

/// SEC-4・TASK-41.5.1: 0600 で作成し追記する。既存内容は保持される。
#[test]
fn sec4_task41_5_1_creates_0600_and_appends() {
    let d = tmp("append");
    let p = d.join("audit.log");
    fs::write(&p, "old\n").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    let mut w = AuditFileWriter::open(&p).unwrap();
    w.write_record(&rec(1)).unwrap();
    w.write_record(&rec(2)).unwrap();
    let s = fs::read_to_string(&p).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "old");
    assert!(lines[1].contains("\"pid\":1,"));
    assert!(lines[2].contains("\"pid\":2,"));

    let q = d.join("new.log");
    AuditFileWriter::open(&q).unwrap();
    assert_eq!(
        fs::metadata(&q).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_dir_all(&d).unwrap();
}

/// SEC-4・TASK-41.5.1: 相対パス・symlink・ディレクトリ・緩い権限を拒否する。
#[test]
fn sec4_task41_5_1_rejects_unsafe_targets() {
    let d = tmp("reject");
    let e = AuditFileWriter::open(std::path::Path::new("rel.log")).unwrap_err();
    assert_eq!(e.kind(), AuditWriteErrorKind::RelativePath);
    assert_eq!(e.error_code(), ErrorCode::InvalidArgument);

    let target = d.join("t");
    fs::write(&target, "").unwrap();
    let link = d.join("l");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(
        AuditFileWriter::open(&link).unwrap_err().kind(),
        AuditWriteErrorKind::Open
    );

    assert_eq!(
        AuditFileWriter::open(&d).unwrap_err().kind(),
        AuditWriteErrorKind::Open
    );

    let loose = d.join("loose");
    fs::write(&loose, "").unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
    let e = AuditFileWriter::open(&loose).unwrap_err();
    assert_eq!(e.kind(), AuditWriteErrorKind::InsecureFile);
    assert_eq!(e.error_code(), ErrorCode::PermissionDenied);
    fs::remove_dir_all(&d).unwrap();
}

/// SEC-4・TASK-41.5.1: 改行入りパスでも 1 レコード 1 行。
#[test]
fn sec4_task41_5_1_one_line_per_record() {
    let d = tmp("inject");
    let p = d.join("a.log");
    let mut w = AuditFileWriter::open(&p).unwrap();
    let r = AuditRecord::new(
        AuditTimestamp::from_unix_duration(Duration::new(1, 2)),
        AuditPid::new(3).unwrap(),
        AuditEvent::Mount {
            path: Some(AuditPath::new("/x\n{\"forged\":1}")),
        },
    );
    w.write_record(&r).unwrap();
    assert_eq!(fs::read_to_string(&p).unwrap().lines().count(), 1);
    fs::remove_dir_all(&d).unwrap();
}
