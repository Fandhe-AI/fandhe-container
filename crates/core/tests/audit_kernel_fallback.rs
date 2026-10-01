//! カーネル監査フォールバックの結合試験（SEC-4・TASK-41.5.2・#840）。Linux 専用。
//!
//! 実カーネルの NETLINK_AUDIT へ公開 API（`KernelAuditFallback`）だけで送る。
//!
//! - 既定のテスト集合（否定側）: 期待値を環境から決定的に導く。初期 user namespace の外では ACK が
//!   `ECONNREFUSED` なので `KernelAuditUnavailable`、初期 namespace で `CAP_AUDIT_WRITE` が無ければ
//!   `EPERM` なので `KernelAuditPermissionDenied`。いずれも何も書き込まない。`CAP_AUDIT_WRITE` を持つ
//!   環境では送信するとホストの監査ログへ書き込んでしまうため、否定側テストは送信せず失敗させる
//!   （その環境は肯定側テストの対象）
//! - 実機前提（肯定側）: `#[ignore]`。`CAP_AUDIT_WRITE` を持つ初期 user namespace でのみ実行する
//!   （AGENTS.md「実機前提テスト」）

#![cfg(target_os = "linux")]

use std::time::Duration;

use fandhe_container_core::audit_log::{
    AuditEvent, AuditFallback, AuditPid, AuditRecord, AuditSyscallArch, AuditSyscallNr,
    AuditTimestamp, AuditWriteError, AuditWriteErrorKind, KernelAuditFallback,
};
use fandhe_container_core::traits::ErrorCode;

/// `CAP_AUDIT_WRITE`（include/uapi/linux/capability.h）。
const CAP_AUDIT_WRITE_BIT: u32 = 29;

fn record() -> AuditRecord {
    AuditRecord::new(
        AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
        AuditPid::new(1).unwrap(),
        AuditEvent::Seccomp {
            syscall: AuditSyscallNr::new(272).unwrap(),
            arch: AuditSyscallArch::from_raw(0xC000_003E),
        },
    )
}

/// `/proc/self/status` の `CapEff` に `CAP_AUDIT_WRITE` があるか。
fn has_cap_audit_write() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .unwrap()
        .trim();
    let bits = u64::from_str_radix(hex, 16).unwrap();
    bits & (1u64 << CAP_AUDIT_WRITE_BIT) != 0
}

/// 初期 user namespace か（`/proc/self/uid_map` が全範囲の恒等写像）。
fn in_initial_user_namespace() -> bool {
    let map = std::fs::read_to_string("/proc/self/uid_map").unwrap();
    map.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"]
}

fn send() -> Result<(), AuditWriteError> {
    let primary = AuditWriteError::fallback_unavailable();
    KernelAuditFallback::new().record_fallback(&record(), &primary)
}

/// SEC-4・TASK-41.5.2: 書き込み権限が無い環境ではカーネルが拒否し、分類済みエラーで返る（何も書かない）。
#[test]
fn sec4_task41_5_2_real_kernel_rejects_without_privilege() {
    let initial_ns = in_initial_user_namespace();
    let cap = has_cap_audit_write();
    assert!(
        !(initial_ns && cap),
        "CAP_AUDIT_WRITE in the initial user namespace would write to the host audit log; \
         run the ignored positive test instead"
    );
    let err = send().unwrap_err();
    if initial_ns {
        assert_eq!(err.kind(), AuditWriteErrorKind::KernelAuditPermissionDenied);
        assert_eq!(err.error_code(), ErrorCode::PermissionDenied);
    } else {
        assert_eq!(err.kind(), AuditWriteErrorKind::KernelAuditUnavailable);
        assert_eq!(err.error_code(), ErrorCode::Unavailable);
    }
}

/// SEC-4・TASK-41.5.2: 実カーネルへの肯定側送信（ACK が 0）。ホストの監査ログへ 1 件書き込む。
#[test]
#[ignore = "requires CAP_AUDIT_WRITE in the initial user namespace; writes to the host audit log (SEC-4)"]
fn sec4_task41_5_2_real_kernel_accepts_with_cap_audit_write() {
    assert_eq!(send(), Ok(()));
}
