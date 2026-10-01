//! Landlock レイヤーの監査フック（SEC-4・TASK-41.3・#194）。
//!
//! # 役割
//!
//! Landlock ルール（TASK-39・CORE-5）により `EACCES` で拒否されたアクセス試行を観測した呼び出し側が、
//! 本モジュールの関数へ errno を渡し、[`AuditRecord`]（`AuditEvent::Landlock`）を 1 件組み立てる。
//! 純粋な errno 分類とレコード構築のみで、syscall も I/O も永続化も持たない（OS 非依存。3 OS でコンパイルされる）。
//!
//! # 呼び出し元・契約
//!
//! - `exec::observe_landlock_path_access`（TASK-39.5）が、Landlock 適用後（`restrict_self` 成功後）の同一スレッドで
//!   試したプローブの結果ごとに [`landlock_denial_record_now`] を呼ぶ。1 回の拒否観測につきレコードはちょうど 1 件
//! - 呼び出してよいのは「Landlock ruleset の適用に成功したスレッドでの観測」に限る。未適用の拒否は Landlock 由来ではない
//! - 渡すパスは呼び出し側のもの（本番ではコンテナ内パス）。改行・制御文字を含みうるため、出力側（#839）でエスケープする
//! - [`AuditPath`] は上限で切り詰めるので、長いパスでも拒否試行の記録は失われない
//!
//! # 帰属の限界
//!
//! `EACCES` は DAC（通常のパーミッション）でも返る。レコードの意味は「Landlock 適用下で観測された `EACCES`」であり、
//! Landlock 由来と証明したものではない。厳密な帰属はカーネル側の Landlock 監査（未実装）の担当。
//!
//! # 将来仕様（REPAIR-3: 実装済みを装わない）
//!
//! Landlock にはユーザー空間への違反通知経路がなく、`EACCES` は呼び出したプロセス自身にしか返らない。
//! したがってコンテナのワークロードプロセスが受けた拒否の捕捉（Linux 6.15+ の Landlock 監査ログ・auditd 連携）は
//! 未実装（#840 は主経路失敗時のフォールバックのみ）、エントリポイントの `execveat` が `EACCES` を返した場合の配線は後続作業で、本モジュールは未対応。
//! 本モジュールだけで SEC-4 の「100% 記録」を達成したとは扱わない。
//! `std::fs` 操作が使う syscall はアーキ・libc 依存のため、syscall 番号は推測せず `None` を渡す運用とする。

use std::path::Path;

use super::{
    AuditEvent, AuditPath, AuditPid, AuditRecord, AuditRecordError, AuditRecordErrorKind,
    AuditSyscallNr, AuditTimestamp,
};

/// Landlock の FS 拒否が返す errno（`EACCES`。x86_64・aarch64 共通で 13）。
///
/// OS 非依存モジュールのため `crate::sys` を使わずローカル定数とし、Linux ビルドのテストで
/// `sys::EACCES` との一致を照合して乖離を防ぐ。
pub const LANDLOCK_DENIED_ERRNO: i32 = 13;

/// 拒否観測から監査レコードを 1 件組み立てる（純粋関数）。
///
/// `errno` が [`LANDLOCK_DENIED_ERRNO`] のときのみ `Some`。成功（`None`）・他の errno は `None`。
/// 呼び出し元は `exec::observe_landlock_path_access`。帰属の限界はモジュール文書を参照（SEC-4・TASK-41.3）。
pub fn landlock_denial_record(
    path: &Path,
    errno: Option<i32>,
    syscall: Option<AuditSyscallNr>,
    pid: AuditPid,
    timestamp: AuditTimestamp,
) -> Option<AuditRecord> {
    if errno != Some(LANDLOCK_DENIED_ERRNO) {
        return None;
    }
    Some(AuditRecord::new(
        timestamp,
        pid,
        AuditEvent::Landlock {
            path: AuditPath::new(path),
            syscall,
        },
    ))
}

/// 現在のプロセス ID・時刻で [`landlock_denial_record`] を呼ぶ便宜関数（syscall は `None`）。
///
/// `errno` が `EACCES` でなければ PID・時刻を取得せず `Ok(None)`。PID / 時刻の取得失敗は黙殺せず
/// `Err` で返す（panic しない）。
pub fn landlock_denial_record_now(
    path: &Path,
    errno: Option<i32>,
) -> Result<Option<AuditRecord>, AuditRecordError> {
    if errno != Some(LANDLOCK_DENIED_ERRNO) {
        return Ok(None);
    }
    let pid = i32::try_from(std::process::id())
        .map_err(|_| AuditRecordError::new(AuditRecordErrorKind::PidNotPositive))
        .and_then(AuditPid::new)?;
    let timestamp = AuditTimestamp::now()?;
    Ok(landlock_denial_record(path, errno, None, pid, timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::{AUDIT_PATH_MAX_BYTES, AuditLayer};
    use std::time::Duration;

    fn pid() -> AuditPid {
        AuditPid::new(4242).expect("pid")
    }

    fn ts() -> AuditTimestamp {
        AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5))
    }

    /// SEC-4・TASK-41.3: EACCES 1 回で対象パス付きレコードがちょうど 1 件。
    #[test]
    fn sec4_task41_3_eacces_yields_one_record_with_path() {
        let r =
            landlock_denial_record(Path::new("/x/y"), Some(13), None, pid(), ts()).expect("record");
        assert_eq!(r.layer(), AuditLayer::Landlock);
        assert_eq!(r.path(), Some(Path::new("/x/y")));
        assert_eq!(r.syscall(), None);
        assert_eq!(r.pid().get(), 4242);
        assert_eq!(r.timestamp(), ts());
    }

    /// SEC-4・TASK-41.3: 観測できた syscall はそのまま保持する。
    #[test]
    fn sec4_task41_3_syscall_is_kept() {
        let nr = AuditSyscallNr::new(257).expect("nr");
        let r = landlock_denial_record(Path::new("/a"), Some(13), Some(nr), pid(), ts())
            .expect("record");
        assert_eq!(r.syscall().map(AuditSyscallNr::get), Some(257));
    }

    /// SEC-4・TASK-41.3: EACCES 以外（成功・ENOENT・EPERM・負値・内容不一致 -2）は記録しない。
    #[test]
    fn sec4_task41_3_non_eacces_yields_none() {
        for e in [None, Some(2), Some(1), Some(-1), Some(-2), Some(0)] {
            assert!(
                landlock_denial_record(Path::new("/a"), e, None, pid(), ts()).is_none(),
                "{e:?}"
            );
        }
    }

    /// SEC-4・TASK-41.3: 上限超過のパスでも記録は失われず、切り詰められる。
    #[test]
    fn sec4_task41_3_long_path_is_truncated_not_dropped() {
        let long = format!("/{}", "a".repeat(AUDIT_PATH_MAX_BYTES + 100));
        let r =
            landlock_denial_record(Path::new(&long), Some(13), None, pid(), ts()).expect("record");
        let p = r.path().expect("path");
        assert!(p.as_os_str().len() <= AUDIT_PATH_MAX_BYTES);
    }

    /// SEC-4・TASK-41.3: 便宜関数は現在 PID で 1 件、EACCES 以外は `Ok(None)`。
    #[test]
    fn sec4_task41_3_now_uses_current_pid() {
        let r = landlock_denial_record_now(Path::new("/p"), Some(13))
            .expect("ok")
            .expect("record");
        assert_eq!(r.pid().get(), std::process::id());
        assert_eq!(r.path(), Some(Path::new("/p")));
        assert_eq!(
            landlock_denial_record_now(Path::new("/p"), Some(2)).expect("ok"),
            None
        );
    }

    /// ローカル定数が sys の EACCES と乖離しないことを照合する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_task41_3_errno_matches_sys_eacces() {
        assert_eq!(LANDLOCK_DENIED_ERRNO, crate::sys::EACCES);
    }
}
