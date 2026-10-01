//! 監査レコード型の公開 API 結合テスト（SEC-4・TASK-41.1・#192。REPAIR-12 の機械照合）。
//!
//! 外部 crate の立場から `fandhe_container_core::audit_log` の型で 3 レイヤーのレコードを組み立て、
//! 受入基準（各フィールドの表現・不正値の構築拒否）を具体値で照合する。cfg を付けないため
//! 3 OS の CI で実行され、型が OS 非依存であることの保証にもなる。
//!
//! # TASK-41.6・#197: 3 レイヤー横断の結合テスト
//!
//! seccomp・Landlock・マウント検証の違反試行を同じ 1 つの sink へ流し、件数・順序・レイヤー・各フィールドと
//! `encode_json_line` のワイヤー表現を具体値で照合する（SEC-4・CORE-5・OCI-4。テスト名は `sec4_task41_6_*`）。
//! 実機前提の部分は次のとおりで、既定のテスト集合で動くものを実機前提へ移していない。
//!
//! - Landlock: 実カーネルの EACCES 後の監査は `tests/landlock.rs`（`harness = false`・ABI 6+ は `-- --ignored`）
//!   が照合済み。ここでは純関数経路（`landlock_denial_record(_now)`）で照合する
//! - seccomp: 現行フィルタは禁止 syscall に `ERRNO(EPERM)` を返し SIGSYS・USER_NOTIF が起きないため、
//!   実カーネルからフックへの配送は未実装（REPAIR-3）。拒否報告を入力にした経路で照合する
//! - マウント（exec 層）: 肯定側の違反は `MountIsolation` の証跡（新しい PID/mount namespace の PID 1）が要る
//!   実機前提で未整備。ここでは OCI API 層の肯定側と exec 層の負の対照のみ。実機テストは後続課題

use std::path::Path;
use std::sync::Mutex;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fandhe_container_core::audit_log::{
    AUDIT_PATH_MAX_BYTES, AuditDelivery, AuditEvent, AuditLayer, AuditPath, AuditPid, AuditRecord,
    AuditRecordErrorKind, AuditSink, AuditSyscallArch, AuditSyscallNr, AuditTimestamp,
    LANDLOCK_DENIED_ERRNO, SeccompDenialReport, encode_json_line, landlock_denial_record,
    landlock_denial_record_now, record_mount_rejection, record_seccomp_denial,
};
use fandhe_container_core::oci_runtime::{audit_mount_config_error, parse_config_bytes};
use fandhe_container_core::traits::{ErrorCode, TraitError};

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

// ---- TASK-41.6・#197: 3 レイヤー横断 ----

/// 件数上限（16 件）付きの sink。無制限確保を避ける。
struct BoundedSink(Mutex<Vec<AuditRecord>>);

impl BoundedSink {
    fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }
    fn snapshot(&self) -> Vec<AuditRecord> {
        self.0.lock().expect("lock").clone()
    }
}

impl AuditSink for BoundedSink {
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

/// 常に失敗する sink。
struct FailingSink;

impl AuditSink for FailingSink {
    fn record(&self, _record: &AuditRecord) -> Result<(), TraitError> {
        Err(TraitError::new(ErrorCode::Internal, "sink failed"))
    }
}

fn fixed_ts() -> AuditTimestamp {
    AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5))
}

/// ワイヤー表現を検証して JSON に戻す（末尾 LF は 1 個だけ。ログ注入対策）。
fn wire(rec: &AuditRecord) -> serde_json::Value {
    let line = encode_json_line(rec).expect("encode");
    assert_eq!(line.last(), Some(&b'\n'));
    assert_eq!(line.iter().filter(|b| **b == b'\n').count(), 1);
    serde_json::from_slice(&line).expect("json")
}

/// SEC-4・TASK-41.6: 3 レイヤーの違反試行が 1 つの sink に順序どおり・具体値で記録される。
#[test]
fn sec4_task41_6_three_layers_into_one_sink() {
    let sink = BoundedSink::new();

    let report = SeccompDenialReport::from_sigsys(1, 272, 0xC000_003E, 42).unwrap();
    record_seccomp_denial(&report, fixed_ts(), &sink).unwrap();

    let ll = landlock_denial_record(
        Path::new("/denied/new"),
        Some(LANDLOCK_DENIED_ERRNO),
        None,
        AuditPid::new(4242).unwrap(),
        fixed_ts(),
    )
    .expect("landlock record");
    sink.record(&ll).unwrap();

    let m = record_mount_rejection("denied", Some(Path::new("/proc/sys")), &sink);
    assert_eq!(m.delivery, AuditDelivery::Recorded);
    assert_eq!(m.error, "denied");

    let recs = sink.snapshot();
    assert_eq!(recs.len(), 3);
    let layers: Vec<AuditLayer> = recs.iter().map(AuditRecord::layer).collect();
    assert_eq!(
        layers,
        vec![AuditLayer::Seccomp, AuditLayer::Landlock, AuditLayer::Mount]
    );
    assert_eq!(recs[0].syscall().map(AuditSyscallNr::get), Some(272));
    assert_eq!(
        recs[0].seccomp_arch().map(AuditSyscallArch::get),
        Some(0xC000_003E)
    );
    assert_eq!(recs[0].pid().get(), 42);
    assert_eq!(recs[0].path(), None);
    assert_eq!(recs[1].path(), Some(Path::new("/denied/new")));
    assert_eq!(recs[1].pid().get(), 4242);
    assert_eq!(recs[2].path(), Some(Path::new("/proc/sys")));
    assert_eq!(recs[2].pid().get(), std::process::id());

    let j0 = wire(&recs[0]);
    assert_eq!(j0["event"], "audit");
    assert_eq!(j0["layer"], "seccomp");
    assert_eq!(j0["pid"], 42);
    assert_eq!(j0["syscall"], 272);
    assert_eq!(j0["arch"], 3_221_225_534u64);
    assert!(j0["path"].is_null());
    assert!(j0["path_truncated"].is_null());
    assert_eq!(j0["ts_sec"], 1_700_000_000u64);
    assert_eq!(j0["ts_nsec"], 5);

    let j1 = wire(&recs[1]);
    assert_eq!(j1["layer"], "landlock");
    assert_eq!(j1["pid"], 4242);
    assert!(j1["syscall"].is_null());
    assert!(j1["arch"].is_null());
    assert_eq!(j1["path"], "/denied/new");
    assert_eq!(j1["path_truncated"], false);
    assert_eq!(j1["path_original_len"], 11);
    assert_eq!(j1["ts_sec"], 1_700_000_000u64);

    let j2 = wire(&recs[2]);
    assert_eq!(j2["layer"], "mount");
    assert_eq!(j2["pid"], std::process::id());
    assert!(j2["syscall"].is_null());
    assert!(j2["arch"].is_null());
    assert_eq!(j2["path"], "/proc/sys");
    assert_eq!(j2["path_truncated"], false);
    assert!(j2["ts_sec"].as_u64().unwrap() > 1_600_000_000);
}

fn oci_config(mounts: &str, args: &str) -> String {
    format!(
        r#"{{"ociVersion":"1.2.0","root":{{"path":"rootfs"}},
"process":{{"user":{{"uid":0,"gid":0}},"args":{args},"cwd":"/"}},
"mounts":{mounts}}}"#
    )
}

/// SEC-4・OCI-4・TASK-41.6: OCI config の不正 destination 拒否が path なしの Mount 1 件になり、
/// destination 以外の拒否は記録されない。
#[test]
fn sec4_task41_6_mount_api_violation_via_oci_config() {
    let sink = BoundedSink::new();
    let json = oci_config(r#"[{"destination":"/../etc"}]"#, r#"["/bin/sh"]"#);
    let err = parse_config_bytes(json.as_bytes()).expect_err("rejected");
    let r = audit_mount_config_error(err, &sink);
    assert_eq!(r.delivery, AuditDelivery::Recorded);
    assert_eq!(r.error.code(), ErrorCode::InvalidArgument);
    let recs = sink.snapshot();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].layer(), AuditLayer::Mount);
    assert_eq!(recs[0].path(), None);
    let j = wire(&recs[0]);
    assert_eq!(j["layer"], "mount");
    assert!(j["path"].is_null());

    let json = oci_config(r#"[{"destination":"/proc"}]"#, "[]");
    let err = parse_config_bytes(json.as_bytes()).expect_err("rejected");
    let r = audit_mount_config_error(err, &sink);
    assert_eq!(r.delivery, AuditDelivery::NotApplicable);
    assert_eq!(sink.snapshot().len(), 1);
}

/// SEC-4・CORE-5・TASK-41.6: Landlock は EACCES のみ記録し、巨大パスも落ちずに切り詰めて記録する。
#[test]
fn sec4_task41_6_landlock_only_eacces_is_recorded() {
    let sink = BoundedSink::new();
    let rec = landlock_denial_record_now(Path::new("/denied/x"), Some(LANDLOCK_DENIED_ERRNO))
        .unwrap()
        .expect("record");
    sink.record(&rec).unwrap();
    assert_eq!(rec.pid().get(), std::process::id());
    assert_eq!(rec.path(), Some(Path::new("/denied/x")));

    for errno in [None, Some(2), Some(1)] {
        assert!(
            landlock_denial_record_now(Path::new("/denied/x"), errno)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(sink.snapshot().len(), 1);

    let long = format!("/{}", "a".repeat(AUDIT_PATH_MAX_BYTES + 100));
    let rec = landlock_denial_record_now(Path::new(&long), Some(LANDLOCK_DENIED_ERRNO))
        .unwrap()
        .expect("record");
    let j = wire(&rec);
    assert_eq!(j["path_truncated"], true);
    assert_eq!(j["path_original_len"], long.len());
}

/// SEC-4・TASK-41.6: exec 層の違反でない拒否（namespace 空）は記録せず、元のエラーを変えない。
/// 肯定側（MountTarget 等）は PID 1 の実機前提で後続課題（モジュール文書参照）。
#[cfg(target_os = "linux")]
#[test]
fn sec4_task41_6_exec_non_mount_violation_is_not_recorded() {
    use fandhe_container_core::exec::{IsolationConfig, NamespaceSet, audit_mount_violation, plan};
    let err = plan(&IsolationConfig {
        namespaces: NamespaceSet::empty(),
        hostname: None,
    })
    .expect_err("rejected");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(err.violation.is_some());
    let sink = BoundedSink::new();
    let r = audit_mount_violation(err.clone(), &sink);
    assert_eq!(r.delivery, AuditDelivery::NotApplicable);
    assert_eq!(r.error.code, err.code);
    assert_eq!(r.error.message, err.message);
    assert_eq!(sink.snapshot().len(), 0);
}

/// 件数・arch・layer・syscall 番号だけを数える sink（レコードを保持しない）。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
struct CountingSink {
    count: AtomicUsize,
    expected_arch: u32,
    nrs: Mutex<Vec<u32>>,
    mismatches: AtomicUsize,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl AuditSink for CountingSink {
    fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
        self.count.fetch_add(1, Ordering::SeqCst);
        if record.layer() != AuditLayer::Seccomp
            || record.seccomp_arch().map(AuditSyscallArch::get) != Some(self.expected_arch)
        {
            self.mismatches.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(nr) = record.syscall() {
            self.nrs
                .lock()
                .map_err(|_| TraitError::new(ErrorCode::Internal, "poisoned"))?
                .push(nr.get());
        }
        Ok(())
    }
}

/// SEC-4・CORE-5・TASK-41.6: 禁止 syscall 一覧の全件が seccomp レコード 1 件ずつになる。
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn sec4_task41_6_every_denied_syscall_yields_one_record() {
    use fandhe_container_core::seccomp::{DeniedSyscall, SyscallLookup, table_for_target_arch};
    let table = table_for_target_arch().expect("table");
    let arch = table.audit_arch().get();
    let sink = CountingSink {
        count: AtomicUsize::new(0),
        expected_arch: arch,
        nrs: Mutex::new(Vec::new()),
        mismatches: AtomicUsize::new(0),
    };
    let mut expected = Vec::new();
    for d in DeniedSyscall::ALL {
        if let SyscallLookup::Present(nr) = table.number_of(d) {
            expected.push(nr.get());
            let report = SeccompDenialReport::from_sigsys(
                1,
                i32::try_from(nr.get()).expect("nr fits i32"),
                arch,
                5,
            )
            .unwrap();
            record_seccomp_denial(&report, fixed_ts(), &sink).unwrap();
        }
    }
    assert!(!expected.is_empty());
    assert_eq!(sink.count.load(Ordering::SeqCst), expected.len());
    assert_eq!(sink.mismatches.load(Ordering::SeqCst), 0);
    assert_eq!(*sink.nrs.lock().unwrap(), expected);
}

/// SEC-4・TASK-41.6: sink の失敗は拒否エラーを覆さない（fail-closed）。seccomp 経路はエラーを伝播する。
#[test]
fn sec4_task41_6_sink_failure_does_not_override_rejection() {
    let r = record_mount_rejection("denied", Some(Path::new("/proc/sys")), &FailingSink);
    assert_eq!(r.error, "denied");
    match r.delivery {
        AuditDelivery::SinkFailed(e) => assert_eq!(e.code(), ErrorCode::Internal),
        other => panic!("unexpected delivery: {other:?}"),
    }
    let report = SeccompDenialReport::from_sigsys(1, 272, 0xC000_003E, 42).unwrap();
    let err = record_seccomp_denial(&report, fixed_ts(), &FailingSink).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Internal);
}
