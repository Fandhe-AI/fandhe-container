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

#[path = "support/scratch_root.rs"]
mod scratch_root;

/// 排他作成した `ScratchDir` の子（0700）を返す。pid だけの名前を先に消す旧方式の置き換え（#3434・REPAIR-12）。
/// guard は呼び出し側が試験の終わりまで束縛する（drop で後始末する）。
fn tmp(name: &str) -> (scratch_root::ScratchDir, std::path::PathBuf) {
    let scratch = scratch_root::ScratchDir::new(&format!("afw-{name}"), Duration::from_secs(10));
    let d = scratch.path().join("d");
    fs::create_dir(&d).unwrap();
    // 親ディレクトリは group/other 書き込み不可でなければ拒否される（SEC-4）ため 0700 にする。
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
    (scratch, d)
}

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

/// REPAIR-12・#3434: 旧方式の pid だけの名前（`afw-<name>-<pid>`）の残骸（FIFO の `audit.log`）があっても、
/// `tmp` は別名の空のディレクトリを返して書き込みに成功し、残骸に触れない。drop は自分のパスだけを消す。
/// 残骸は排他作成できた場合だけ自分で消す（既に存在すれば本物の残骸として使い、消さない）。
#[test]
fn repair12_3434_tmp_ignores_legacy_pid_residue() {
    use std::os::unix::fs::FileTypeExt as _;
    struct Cleanup(std::path::PathBuf, bool);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if self.1 {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }
    let legacy = std::env::temp_dir().join(format!("afw-legacy3434-{}", std::process::id()));
    let created = fs::create_dir(&legacy).is_ok();
    let _cleanup = Cleanup(legacy.clone(), created);
    if created {
        let status = std::process::Command::new("mkfifo")
            .arg(legacy.join("audit.log"))
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo failed: {status:?}");
        fs::write(legacy.join("file"), b"x").expect("write residue");
    }
    let (scratch, d) = tmp("legacy3434");
    assert_ne!(d, legacy);
    assert_eq!(fs::read_dir(&d).unwrap().count(), 0);
    let p = d.join("audit.log");
    let mut w = AuditFileWriter::open(&p).unwrap();
    w.write_record(&rec(1)).unwrap();
    assert_eq!(fs::read_to_string(&p).unwrap().lines().count(), 1);
    let fifo = fs::symlink_metadata(legacy.join("audit.log")).expect("residue fifo");
    assert!(fifo.file_type().is_fifo(), "{:?}", fifo.file_type());
    drop(w);
    drop(scratch);
    assert_eq!(
        fs::symlink_metadata(&d).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert!(fs::symlink_metadata(legacy.join("audit.log")).is_ok());
}

/// SEC-4・TASK-41.5.1: 0600 で作成し追記する。既存内容は保持される。
#[test]
fn sec4_task41_5_1_creates_0600_and_appends() {
    let (_scratch, d) = tmp("append");
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
}

/// SEC-4・TASK-41.5.1: 相対パス・symlink・ディレクトリ・緩い権限を拒否する。
#[test]
fn sec4_task41_5_1_rejects_unsafe_targets() {
    let (_scratch, d) = tmp("reject");
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

    let sub = d.join("sub");
    fs::create_dir(&sub).unwrap();
    assert_eq!(
        AuditFileWriter::open(&sub).unwrap_err().kind(),
        AuditWriteErrorKind::Open
    );
    // 直接の親が group/other 書き込み可（sticky の /tmp 等）なら拒否する。
    assert_eq!(
        AuditFileWriter::open(&std::env::temp_dir().join("afw-direct-child.log"))
            .unwrap_err()
            .kind(),
        AuditWriteErrorKind::InsecureFile
    );

    let loose = d.join("loose");
    fs::write(&loose, "").unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
    let e = AuditFileWriter::open(&loose).unwrap_err();
    assert_eq!(e.kind(), AuditWriteErrorKind::InsecureFile);
    assert_eq!(e.error_code(), ErrorCode::PermissionDenied);
}

/// SEC-4・TASK-41.5.1: 改行入りパスでも 1 レコード 1 行。
#[test]
fn sec4_task41_5_1_one_line_per_record() {
    let (_scratch, d) = tmp("inject");
    let p = d.join("a.log");
    let mut w = AuditFileWriter::open(&p).unwrap();
    let r = AuditRecord::new(
        AuditTimestamp::from_unix_duration(Duration::new(1, 2)),
        AuditPid::new(3).unwrap(),
        AuditEvent::Mount {
            path: Some(AuditPath::new("/x\n{\"forged\":1}")),
            reason: None,
        },
    );
    w.write_record(&r).unwrap();
    assert_eq!(fs::read_to_string(&p).unwrap().lines().count(), 1);
}

/// REPAIR-5・#1703: 複数の `AuditFileWriter` が公開 API 経由で並行に書いても、プロセス内の順番待ちで
/// 全スレッドが期限切れ（`Lock`）にならず、全レコードが 1 行ずつ欠落・混在なく追記される。
#[test]
fn repair5_1703_concurrent_writers_all_succeed_without_interleaving() {
    const THREADS: i32 = 8;
    const PER_THREAD: i32 = 25;
    let (_scratch, d) = tmp("concurrent");
    let p = d.join("audit.log");
    drop(AuditFileWriter::open(&p).unwrap());

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let p = p.clone();
            std::thread::spawn(move || {
                let mut w = AuditFileWriter::open(&p).unwrap();
                for i in 0..PER_THREAD {
                    // pid = スレッド番号 * 1000 + 連番（スレッドごとの書き込み順を後で照合する）。
                    w.write_record(&rec((t + 1) * 1000 + i + 1)).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    let s = fs::read_to_string(&p).unwrap();
    let pids_all: Vec<i32> = s
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("each line is JSON");
            i32::try_from(v["pid"].as_i64().expect("pid is integer")).unwrap()
        })
        .collect();
    assert_eq!(pids_all.len(), (THREADS * PER_THREAD) as usize);
    for t in 0..THREADS {
        let expected: Vec<i32> = (0..PER_THREAD).map(|i| (t + 1) * 1000 + i + 1).collect();
        let found: Vec<i32> = pids_all
            .iter()
            .copied()
            .filter(|pid| pid / 1000 == t + 1)
            .collect();
        assert_eq!(found, expected, "thread {t} records keep their order");
    }
}
