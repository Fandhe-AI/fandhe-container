//! 監査ログ書き込みのロック取得待ちの期限切れの結合テスト（REPAIR-5・#1703）。
//!
//! 期限切れまでプロセス内の待ち行列の先頭を占有するため、他の書き込み試験と同じプロセスで
//! 並行に走らせない（別の結合テストバイナリとして分離する）。

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use fandhe_container_core::audit_log::{
    AuditEvent, AuditFileWriter, AuditPid, AuditRecord, AuditSyscallNr, AuditTimestamp,
    AuditWriteErrorKind,
};

#[path = "support/scratch_root.rs"]
mod scratch_root;

fn rec(n: i32) -> AuditRecord {
    AuditRecord::new(
        AuditTimestamp::from_unix_duration(Duration::new(1, 2)),
        AuditPid::new(n).unwrap(),
        AuditEvent::Seccomp {
            syscall: AuditSyscallNr::new(272).unwrap(),
            arch: fandhe_container_core::audit_log::AuditSyscallArch::from_raw(3221225534),
        },
    )
}

/// REPAIR-5・#1703: 他の open file description が flock を握り続けると、書き込みは期限（5 秒）で `Lock` に
/// なり行を残さない。解放後の後続書き込みは成功し、期限切れの待ち手が後続を塞がない。
#[test]
fn repair5_1703_lock_timeout_then_later_write_succeeds() {
    // pid だけの名前を先に消さず、排他作成の `ScratchDir` の子を使う（#3434・REPAIR-12）。
    let scratch = scratch_root::ScratchDir::new("afw-timeout", Duration::from_secs(10));
    let d = scratch.path().join("d");
    fs::create_dir(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
    let p = d.join("audit.log");
    let mut w = AuditFileWriter::open(&p).unwrap();
    w.write_record(&rec(1)).unwrap();

    let holder = fs::File::open(&p).unwrap();
    holder.lock().unwrap();
    let started = std::time::Instant::now();
    let err = w.write_record(&rec(2)).unwrap_err();
    assert_eq!(err.kind(), AuditWriteErrorKind::Lock);
    assert!(started.elapsed() >= Duration::from_secs(4));
    assert!(started.elapsed() < Duration::from_secs(9));
    holder.unlock().unwrap();
    drop(holder);

    w.write_record(&rec(3)).unwrap();
    let s = fs::read_to_string(&p).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("\"pid\":1,"));
    assert!(lines[1].contains("\"pid\":3,"));
}
