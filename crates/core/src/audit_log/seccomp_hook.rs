//! seccomp 拒否報告から監査レコードを作るフック（SEC-4・CORE-5・TASK-41.2・#193）。
//!
//! # 役割
//!
//! カーネルの seccomp 拒否報告（SIGSYS の siginfo、または user notification の `seccomp_notif`）を
//! 検証済みの [`SeccompDenialReport`] に変換し、[`AuditRecord`] をちょうど 1 件組み立てて
//! [`AuditSink`] へ渡す。OS 非依存の純粋な関数で、syscall・I/O・`unsafe` を持たない。
//!
//! # 呼び出し元・契約
//!
//! - 呼び出し元は supervisor の USER_NOTIF listener ループ（`fandhe-container-supervisor` の `seccomp_notify`。#2025）。
//!   SIGSYS ハンドラ経由（`from_sigsys`）は未実装（REPAIR-3）。supervisor の start 経路は `ProductionLauncherBuilder::
//!   seccomp_errno_delivery(UserNotif)` で ERRNO 側の 40 件を通知にし、ループが PID を変換して本フックで記録してから
//!   `-EPERM` で応答する。それ以外の launcher（既定の `Errno`）は従来どおり `ERRNO(EPERM)` で報告が発生しない。exec 経路（#2385）は filter を `USER_NOTIF` で載せ、応答者は exec の親（supervisor の `exec`。
//!   期限つきの本フック `record_seccomp_denial_for_until` で記録。#2544）。`unshare`・`ptrace`・`kexec_load` は `KILL_PROCESS`（ESC-06）。`KILL_PROCESS` では終了するプロセス自身が記録を書けず、
//!   プロセス内の SIGSYS ハンドラ経由の `SeccompDenialReport::from_sigsys` も使えない。そのため KILL 側では
//!   本フックを使わない（正の記録はカーネルの `AUDIT_SECCOMP`、補助は親の回収点が出す
//!   `AuditEvent::ExitSignal`。#2004）
//! - カーネル報告値は untrusted。構築子で検証し、panic しない。syscall 番号・arch は拒否された試行を
//!   落とさないよう値を保存する（SEC-4 の 100% 記録）
//! - シンクの失敗は握りつぶさず `Err` で伝播する。リトライ・フォールバックは呼び出し側（`write_with_fallback`・#840 の `KernelAuditFallback`）の担当

use crate::traits::{ContainerId, TraitError};

use super::{
    AuditEvent, AuditPid, AuditRecord, AuditRecordError, AuditRecordErrorKind, AuditSink,
    AuditSyscallArch, AuditSyscallNr, AuditTimestamp,
};

/// `SYS_SECCOMP`（`si_code`。`include/uapi/asm-generic/siginfo.h`。アーキ共通の汎用値）。
const SYS_SECCOMP: i32 = 1;

/// 拒否報告の経路。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeccompReportSource {
    /// `SECCOMP_RET_TRAP` による SIGSYS の siginfo。
    Sigsys,
    /// `SECCOMP_RET_USER_NOTIF` の `seccomp_notif`。
    UserNotif,
}

/// 検証済みの seccomp 拒否報告（SEC-4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SeccompDenialReport {
    pid: AuditPid,
    syscall: AuditSyscallNr,
    arch: AuditSyscallArch,
    source: SeccompReportSource,
}

impl SeccompDenialReport {
    /// SIGSYS の siginfo の値から構築する。
    ///
    /// `si_code` が `SYS_SECCOMP` でなければ `NotSeccompSignal`。SIGSYS の siginfo は PID を持たないため、
    /// `pid` には呼び出し側（ハンドラ）が自プロセスの PID を渡す。
    pub fn from_sigsys(
        si_code: i32,
        si_syscall: i32,
        si_arch: u32,
        pid: i32,
    ) -> Result<Self, AuditRecordError> {
        if si_code != SYS_SECCOMP {
            return Err(AuditRecordError::new(
                AuditRecordErrorKind::NotSeccompSignal,
            ));
        }
        Ok(Self {
            pid: AuditPid::new(pid)?,
            syscall: AuditSyscallNr::from_seccomp_data_nr(si_syscall),
            arch: AuditSyscallArch::from_raw(si_arch),
            source: SeccompReportSource::Sigsys,
        })
    }

    /// `seccomp_notif`（`data.nr`・`data.arch`）と、違反プロセスの PID から構築する。
    ///
    /// `seccomp_notif.pid` は **listener（受信側）の PID namespace** での PID であり、そのままでは
    /// [`AuditPid`] の契約（記録対象プロセス自身の PID namespace から見た PID）を満たさない。
    /// 呼び出し側（supervisor の USER_NOTIF listener）は、`/proc/<notif.pid>/status` の `NSpid` 等で
    /// 違反プロセス自身の PID namespace での PID へ変換した値を `pid_in_process_ns` に渡すこと
    /// （SIGSYS 経路の `from_sigsys` が渡す自 PID と同じ名前空間に揃う。変換の実装は listener 側
    /// で後続作業。REPAIR-3）。`seccomp_notif.pid` を無変換で渡してはならない。
    ///
    /// `pid_in_process_ns` が 0 または `i32::MAX` 超なら `PidNotPositive`。
    pub fn from_user_notif(
        pid_in_process_ns: u32,
        nr: i32,
        arch: u32,
    ) -> Result<Self, AuditRecordError> {
        let pid = i32::try_from(pid_in_process_ns)
            .map_err(|_| AuditRecordError::new(AuditRecordErrorKind::PidNotPositive))
            .and_then(AuditPid::new)?;
        Ok(Self {
            pid,
            syscall: AuditSyscallNr::from_seccomp_data_nr(nr),
            arch: AuditSyscallArch::from_raw(arch),
            source: SeccompReportSource::UserNotif,
        })
    }

    /// 違反したプロセスの PID。
    pub fn pid(&self) -> AuditPid {
        self.pid
    }

    /// 拒否された syscall。
    pub fn syscall(&self) -> AuditSyscallNr {
        self.syscall
    }

    /// 報告されたアーキ識別子。
    pub fn arch(&self) -> AuditSyscallArch {
        self.arch
    }

    /// 報告の経路。
    pub fn source(&self) -> SeccompReportSource {
        self.source
    }
}

/// 拒否報告 1 件につき [`AuditRecord`] をちょうど 1 件作り、`sink.record` を 1 回だけ呼ぶ（コンテナ ID なし）。
///
/// タイムスタンプは呼び出し側が `AuditTimestamp::now()` で渡す（テストで固定値を注入するため）。
/// シンクのエラーはそのまま返す。コンテナ ID を載せるなら [`record_seccomp_denial_for`]。
pub fn record_seccomp_denial<S: AuditSink + ?Sized>(
    report: &SeccompDenialReport,
    timestamp: AuditTimestamp,
    sink: &S,
) -> Result<(), TraitError> {
    record_seccomp_denial_for(report, timestamp, None, sink)
}

/// [`record_seccomp_denial`] にコンテナ ID を載せる版（SEC-4・#2025）。呼び出し元は supervisor の seccomp 通知ループで、
/// 自分が監視するコンテナの ID を渡す（記録をコンテナに結び付ける。ID は検証済みの [`ContainerId`]）。
pub fn record_seccomp_denial_for<S: AuditSink + ?Sized>(
    report: &SeccompDenialReport,
    timestamp: AuditTimestamp,
    container_id: Option<&ContainerId>,
    sink: &S,
) -> Result<(), TraitError> {
    let record = AuditRecord::new(
        timestamp,
        report.pid,
        AuditEvent::Seccomp {
            syscall: report.syscall,
            arch: report.arch,
        },
    );
    sink.record(&match container_id {
        Some(id) => record.with_container_id(id.clone()),
        None => record,
    })
}

/// [`record_seccomp_denial_for`] の期限つき版（SEC-4・SUP-6・REPAIR-5・#2544）。`sink.record_until` を 1 回だけ呼ぶ。
/// 呼び出し元は exec の親の同期の応答者（supervisor の `seccomp_notify`）で、通知の応答期限を `deadline` に渡し、
/// 記録先が詰まっても応答が期限を越えて遅れないようにする。期限を守るかは `sink` の `record_until` の実装次第。
pub fn record_seccomp_denial_for_until<S: AuditSink + ?Sized>(
    report: &SeccompDenialReport,
    timestamp: AuditTimestamp,
    container_id: Option<&ContainerId>,
    sink: &S,
    deadline: std::time::Instant,
) -> Result<(), TraitError> {
    let record = AuditRecord::new(
        timestamp,
        report.pid,
        AuditEvent::Seccomp {
            syscall: report.syscall,
            arch: report.arch,
        },
    );
    sink.record_until(
        &match container_id {
            Some(id) => record.with_container_id(id.clone()),
            None => record,
        },
        deadline,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;
    use crate::audit_log::AuditLayer;
    use crate::traits::ErrorCode;

    #[derive(Default)]
    struct VecSink {
        records: Mutex<Vec<AuditRecord>>,
        fail: bool,
        until_calls: Mutex<Vec<std::time::Instant>>,
    }

    impl AuditSink for VecSink {
        fn record_until(
            &self,
            record: &AuditRecord,
            deadline: std::time::Instant,
        ) -> Result<(), TraitError> {
            self.until_calls.lock().unwrap().push(deadline);
            self.records.lock().unwrap().push(record.clone());
            Ok(())
        }

        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            self.records.lock().unwrap().push(record.clone());
            if self.fail {
                Err(TraitError::new(ErrorCode::Internal, "sink failed"))
            } else {
                Ok(())
            }
        }
    }

    fn ts() -> AuditTimestamp {
        AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5))
    }

    fn record_one(report: &SeccompDenialReport) -> AuditRecord {
        let sink = VecSink::default();
        record_seccomp_denial(report, ts(), &sink).unwrap();
        let mut records = sink.records.lock().unwrap();
        assert_eq!(records.len(), 1);
        records.remove(0)
    }

    #[test]
    fn sec4_task41_2_sigsys_report_is_recorded_once() {
        let report = SeccompDenialReport::from_sigsys(1, 272, 0xC000_003E, 42).unwrap();
        assert_eq!(report.source(), SeccompReportSource::Sigsys);
        let r = record_one(&report);
        assert_eq!(r.layer(), AuditLayer::Seccomp);
        assert_eq!(r.syscall().map(AuditSyscallNr::get), Some(272));
        assert_eq!(
            r.seccomp_arch().map(AuditSyscallArch::get),
            Some(0xC000_003E)
        );
        assert_eq!(r.pid().get(), 42);
        assert_eq!(r.path(), None);
        assert_eq!(r.timestamp(), ts());
    }

    #[test]
    fn sec4_task41_2_user_notif_report_is_recorded_once() {
        let report = SeccompDenialReport::from_user_notif(7, 97, 0xC000_00B7).unwrap();
        assert_eq!(report.source(), SeccompReportSource::UserNotif);
        let r = record_one(&report);
        assert_eq!(r.syscall().map(AuditSyscallNr::get), Some(97));
        assert_eq!(
            r.seccomp_arch().map(AuditSyscallArch::get),
            Some(0xC000_00B7)
        );
        assert_eq!(r.pid().get(), 7);
    }

    #[test]
    fn sec4_task41_2_unusual_numbers_and_arch_are_preserved() {
        let x32 = SeccompDenialReport::from_user_notif(1, 0x4000_0000 | 272, 0xC000_003E).unwrap();
        assert_eq!(
            record_one(&x32).syscall().map(AuditSyscallNr::get),
            Some(0x4000_0110)
        );
        let neg = SeccompDenialReport::from_sigsys(1, -1, 0xC000_003E, 1).unwrap();
        assert_eq!(
            record_one(&neg).syscall().map(AuditSyscallNr::get),
            Some(0xFFFF_FFFF)
        );
        let i386 = SeccompDenialReport::from_sigsys(1, 1, 0x4000_0003, 1).unwrap();
        assert_eq!(
            record_one(&i386).seccomp_arch().map(AuditSyscallArch::get),
            Some(0x4000_0003)
        );
    }

    #[test]
    fn sec4_task41_2_invalid_reports_are_rejected() {
        assert_eq!(
            SeccompDenialReport::from_sigsys(0, 1, 0, 1)
                .unwrap_err()
                .kind(),
            AuditRecordErrorKind::NotSeccompSignal
        );
        for pid in [0, -1] {
            assert_eq!(
                SeccompDenialReport::from_sigsys(1, 1, 0, pid)
                    .unwrap_err()
                    .kind(),
                AuditRecordErrorKind::PidNotPositive
            );
        }
        for pid in [0u32, i32::MAX as u32 + 1, u32::MAX] {
            assert_eq!(
                SeccompDenialReport::from_user_notif(pid, 1, 0)
                    .unwrap_err()
                    .kind(),
                AuditRecordErrorKind::PidNotPositive
            );
        }
        assert_eq!(
            SeccompDenialReport::from_user_notif(i32::MAX as u32, 1, 0)
                .unwrap()
                .pid()
                .get(),
            2_147_483_647
        );
    }

    #[test]
    fn sec4_task41_2_sink_error_is_propagated_after_single_call() {
        let report = SeccompDenialReport::from_sigsys(1, 272, 0xC000_003E, 42).unwrap();
        let sink = VecSink {
            fail: true,
            ..VecSink::default()
        };
        let err = record_seccomp_denial(&report, ts(), &sink).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Internal);
        assert_eq!(err.message(), "sink failed");
        assert_eq!(sink.records.lock().unwrap().len(), 1);
    }

    #[test]
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn sec4_task41_2_table_numbers_match_recorded_numbers() {
        use crate::seccomp::{DeniedSyscall, SyscallLookup, table_for_target_arch};
        let table = table_for_target_arch().unwrap();
        let arch = table.audit_arch().get();
        let expected: [(DeniedSyscall, u32); 3] =
            if cfg!(all(target_arch = "x86_64", target_pointer_width = "64")) {
                [
                    (DeniedSyscall::Unshare, 272),
                    (DeniedSyscall::Ptrace, 101),
                    (DeniedSyscall::KexecLoad, 246),
                ]
            } else {
                [
                    (DeniedSyscall::Unshare, 97),
                    (DeniedSyscall::Ptrace, 117),
                    (DeniedSyscall::KexecLoad, 104),
                ]
            };
        for (d, want) in expected {
            let SyscallLookup::Present(nr) = table.number_of(d) else {
                panic!("syscall must be present in the host table");
            };
            let report = SeccompDenialReport::from_sigsys(1, nr.get() as i32, arch, 5).unwrap();
            let r = record_one(&report);
            assert_eq!(r.syscall().map(AuditSyscallNr::get), Some(want));
            assert_eq!(r.seccomp_arch().map(AuditSyscallArch::get), Some(arch));
        }
    }

    /// SEC-4・#2025: コンテナ ID を載せる版は記録に ID・番号・arch・PID をそのまま載せる。
    #[test]
    fn sec4_2025_record_for_carries_the_container_id() {
        let sink = VecSink::default();
        let report = SeccompDenialReport::from_user_notif(4242, 312, 0xC000_003E).unwrap();
        let id = ContainerId::new("web-1").unwrap();
        record_seccomp_denial_for(&report, ts(), Some(&id), &sink).unwrap();
        let recs = sink.records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].container_id().map(ContainerId::as_str),
            Some("web-1")
        );
        assert_eq!(recs[0].pid().get(), 4242);
        assert_eq!(recs[0].syscall().map(AuditSyscallNr::get), Some(312));
    }

    /// SEC-4・SUP-6・#2544: 期限つき版は `record_until` をちょうど 1 回呼び、期限・ID・番号・arch・PID をそのまま渡す。
    #[test]
    fn sec4_2544_record_for_until_calls_record_until_once() {
        let sink = VecSink::default();
        let report = SeccompDenialReport::from_user_notif(77, 312, 0xC000_003E).unwrap();
        let id = ContainerId::new("web-2").unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        record_seccomp_denial_for_until(&report, ts(), Some(&id), &sink, deadline).unwrap();
        assert_eq!(*sink.until_calls.lock().unwrap(), vec![deadline]);
        let recs = sink.records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(
            recs[0].container_id().map(ContainerId::as_str),
            Some("web-2")
        );
        assert_eq!(recs[0].pid().get(), 77);
        assert_eq!(recs[0].syscall().map(AuditSyscallNr::get), Some(312));
    }
}
