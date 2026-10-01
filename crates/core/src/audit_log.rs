//! 分離違反の監査レコード型（SEC-4・TASK-41.1・#192）。
//!
//! # 役割
//!
//! seccomp・Landlock・マウント検証/API の 3 レイヤーで起きた分離違反の試行を、原因特定に必要な情報
//! （syscall 番号・対象パス・プロセス ID・タイムスタンプ）付きで表す固定スキーマの型を定義する。
//! 本モジュールは型のみで、syscall も I/O も持たない（OS 非依存。3 OS でコンパイルされる）。
//!
//! # 呼び出し元・契約
//!
//! - TASK-41.3（#194）の Landlock フックは [`landlock_denial_record`] で実装済み（プロセス内で観測した
//!   `EACCES` の写像まで。ワークロードの拒否の捕捉は #840）
//! - TASK-41.2（#193 seccomp フック）・41.4（#195 マウント検証/API。
//!   `exec::IsolationViolation` からの写像もここで扱う）が、違反検知時に [`AuditRecord`] を組み立てる
//! - ローカルファイルへの JSON Lines 書き込み（主経路）は `file_writer` で実装済み（TASK-41.5.1・#839）。
//!   型自体に `serde` の derive は付けず、非公開 DTO でワイヤースキーマへ写す（#652 で共通ログ型へ統一予定）。
//!   カーネル監査連携・クラッシュ時の記録保持は #840 の担当で**未実装**（REPAIR-3: 実装済みを装わない）
//! - レイヤーごとのペイロードを [`AuditEvent`] の enum で持ち、「syscall の無い seccomp 違反」のような
//!   不正な組み合わせを構築できない（REPAIR-2）。値は各 newtype の構築子が検証する
//! - 秘密情報（資格情報・環境変数・namespace 識別子）は含めない。ホスト側の実パスを載せるかは各フックで判断する
//!
//! # 将来仕様
//!
//! syscall 番号はアーキテクチャ相対（x86_64 / aarch64 で異なる）。アーキ識別子（`AUDIT_ARCH_*`）や
//! コンテナ ID を持たせるかは #193 以降で決める。フィールドは非公開かつ `#[non_exhaustive]` なので、
//! 後から追加しても破壊的変更にならない。

mod file_writer;
mod landlock;

pub use file_writer::{
    AUDIT_LINE_MAX_BYTES, AuditFallback, AuditFileWriter, AuditWriteError, AuditWriteErrorKind,
    AuditWriteFailure, AuditWriteOutcome, NoAuditFallback, encode_json_line, write_with_fallback,
};

pub use landlock::{LANDLOCK_DENIED_ERRNO, landlock_denial_record, landlock_denial_record_now};

use std::fmt;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::seccomp::SyscallNr;
use crate::traits::ErrorCode;

/// [`AuditPath`] が保持するバイト長の上限（Linux の `PATH_MAX` に合わせる。超過分は切り詰める）。
pub const AUDIT_PATH_MAX_BYTES: usize = 4096;

/// 監査レコード構築エラーの分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditRecordErrorKind {
    /// PID が 0 以下。
    PidNotPositive,
    /// syscall 番号が負。
    SyscallNegative,
    /// 時計が UNIX エポックより前を指している。
    ClockBeforeEpoch,
}

/// 監査レコード構築エラー（ERR 系の構造化形式）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditRecordError {
    kind: AuditRecordErrorKind,
}

impl AuditRecordError {
    fn new(kind: AuditRecordErrorKind) -> Self {
        Self { kind }
    }

    /// 分類を返す。
    pub fn kind(&self) -> AuditRecordErrorKind {
        self.kind
    }

    /// 構造化エラーコード。入力検証は `InvalidArgument`、時計の異常は `Internal`。
    pub fn error_code(&self) -> ErrorCode {
        match self.kind {
            AuditRecordErrorKind::ClockBeforeEpoch => ErrorCode::Internal,
            _ => ErrorCode::InvalidArgument,
        }
    }

    /// 人間向け説明（英語。入力値は含めない）。
    pub fn message(&self) -> &'static str {
        match self.kind {
            AuditRecordErrorKind::PidNotPositive => "audit pid must be positive",
            AuditRecordErrorKind::SyscallNegative => "audit syscall number must not be negative",
            AuditRecordErrorKind::ClockBeforeEpoch => "system clock is before the UNIX epoch",
        }
    }
}

impl fmt::Display for AuditRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_code().as_str(), self.message())
    }
}

impl std::error::Error for AuditRecordError {}

/// 監査対象の syscall 番号。
///
/// `seccomp::SyscallNr` は禁止テーブル専用で構築できないため、カーネルが報告した任意の番号
/// （`siginfo.si_syscall` 等。C の `int`）を記録できる独自型を置く。番号はアーキテクチャ相対。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditSyscallNr(u32);

impl AuditSyscallNr {
    /// カーネル報告値（`int`）から構築する。負値は拒否する。
    pub fn new(nr: i32) -> Result<Self, AuditRecordError> {
        u32::try_from(nr)
            .map(Self)
            .map_err(|_| AuditRecordError::new(AuditRecordErrorKind::SyscallNegative))
    }

    /// 番号を返す。
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<SyscallNr> for AuditSyscallNr {
    /// 禁止テーブル由来の番号を取り込む。
    fn from(nr: SyscallNr) -> Self {
        Self(nr.get())
    }
}

/// 監査対象のプロセス ID（`pid_t` の有効範囲 `1..=i32::MAX`）。
///
/// 記録したプロセスの PID namespace から見た PID。ホスト側 PID との突き合わせは
/// カーネル監査経路（#840）の担当。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditPid(NonZeroU32);

impl AuditPid {
    /// `pid_t` から構築する。0 以下は拒否する。
    pub fn new(pid: i32) -> Result<Self, AuditRecordError> {
        u32::try_from(pid)
            .ok()
            .and_then(NonZeroU32::new)
            .map(Self)
            .ok_or_else(|| AuditRecordError::new(AuditRecordErrorKind::PidNotPositive))
    }

    /// PID を返す（常に 1 以上 `i32::MAX` 以下）。
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// UNIX エポックからの経過時間（壁時計）で表すタイムスタンプ。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuditTimestamp(Duration);

impl AuditTimestamp {
    /// エポックからの経過時間から構築する。
    pub const fn from_unix_duration(d: Duration) -> Self {
        Self(d)
    }

    /// 現在時刻から構築する。時計がエポック前なら `ClockBeforeEpoch`（panic させない）。
    pub fn now() -> Result<Self, AuditRecordError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(Self)
            .map_err(|_| AuditRecordError::new(AuditRecordErrorKind::ClockBeforeEpoch))
    }

    /// エポックからの経過時間を返す。
    pub const fn as_unix_duration(self) -> Duration {
        self.0
    }

    /// エポックからのナノ秒を返す。
    pub const fn as_unix_nanos(self) -> u128 {
        self.0.as_nanos()
    }
}

/// 違反対象のパス。拒否された入力そのものを記録するため、不正なパスも受け入れる（SEC-4）。
///
/// 空・NUL 含有・[`AUDIT_PATH_MAX_BYTES`] 超のパスはまさにマウント検証等で拒否される入力であり、
/// 構築を拒否すると拒否試行の記録（100%）が失われる。そのため構築は失敗せず、上限超過分は
/// UTF-8 文字境界で切り詰めて保持し（`ViolationSubject::from_path` と同じ方針）、
/// 元のバイト長を [`AuditPath::original_len`] で残す。
///
/// 改行・制御文字・NUL を含みうるため、出力時は書き込み側（#839）が必ずエスケープすること
/// （ログ注入対策）。相対パスも要求しない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPath {
    path: PathBuf,
    original_len: usize,
}

impl AuditPath {
    /// 任意のパスから構築する（失敗しない）。
    ///
    /// 上限以下ならそのまま保持する。超過時のみ先頭上限バイトを lossy UTF-8 に変換した上で文字境界まで切り詰める
    /// （非 UTF-8 バイトは U+FFFD に置換される）。保持バイト長は常に [`AUDIT_PATH_MAX_BYTES`] 以下。
    pub fn new<P: AsRef<Path> + ?Sized>(path: &P) -> Self {
        let path = path.as_ref();
        let original_len = path.as_os_str().as_encoded_bytes().len();
        if original_len <= AUDIT_PATH_MAX_BYTES {
            return Self {
                path: path.to_path_buf(),
                original_len,
            };
        }
        // 先頭 AUDIT_PATH_MAX_BYTES バイトだけを lossy 変換する（入力全体に比例する確保を避ける。
        // 非 UTF-8 バイトは 1 バイト→3 バイトに膨らむが、確保は上限の定数倍に収まる）。
        let head = path
            .as_os_str()
            .as_encoded_bytes()
            .get(..AUDIT_PATH_MAX_BYTES)
            .unwrap_or_default();
        let lossy = String::from_utf8_lossy(head);
        let mut end = AUDIT_PATH_MAX_BYTES.min(lossy.len());
        while end > 0 && !lossy.is_char_boundary(end) {
            end -= 1;
        }
        let kept = lossy.get(..end).unwrap_or("");
        Self {
            path: PathBuf::from(kept),
            original_len,
        }
    }

    /// 保持しているパス（切り詰め後の場合あり）を返す。
    pub fn as_path(&self) -> &Path {
        &self.path
    }

    /// 元のパスのバイト長を返す。
    pub fn original_len(&self) -> usize {
        self.original_len
    }

    /// 上限超過で切り詰められたか。
    pub fn is_truncated(&self) -> bool {
        self.original_len > AUDIT_PATH_MAX_BYTES
    }
}

/// 違反を検知したレイヤー。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditLayer {
    /// seccomp フィルタ（CORE-5）。
    Seccomp,
    /// Landlock ruleset（CORE-5）。
    Landlock,
    /// マウント検証 / API（SEC-4）。
    Mount,
}

impl AuditLayer {
    /// 後続エンコーダが使う安定トークン。
    pub const fn as_str(self) -> &'static str {
        match self {
            AuditLayer::Seccomp => "seccomp",
            AuditLayer::Landlock => "landlock",
            AuditLayer::Mount => "mount",
        }
    }
}

/// レイヤー別のペイロード。不正な組み合わせ（syscall の無い seccomp 違反等）を構築できない。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditEvent {
    /// seccomp 違反。syscall は必須。パスは持たない（ユーザー空間ポインタは TOCTOU になるため）。
    Seccomp {
        /// 拒否された syscall。
        syscall: AuditSyscallNr,
    },
    /// Landlock 違反。パスは必須、syscall は観測できた場合のみ。
    Landlock {
        /// 拒否されたアクセスの対象パス。
        path: AuditPath,
        /// 観測できた場合の syscall。
        syscall: Option<AuditSyscallNr>,
    },
    /// マウント検証 / API の拒否。パス検証による拒否ならパスあり、計画段階の拒否ならなし。
    Mount {
        /// 拒否されたマウント先パス。
        path: Option<AuditPath>,
    },
}

impl AuditEvent {
    /// 対応するレイヤーを返す。
    pub fn layer(&self) -> AuditLayer {
        match self {
            AuditEvent::Seccomp { .. } => AuditLayer::Seccomp,
            AuditEvent::Landlock { .. } => AuditLayer::Landlock,
            AuditEvent::Mount { .. } => AuditLayer::Mount,
        }
    }
}

/// 固定スキーマの監査レコード（SEC-4）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditRecord {
    timestamp: AuditTimestamp,
    pid: AuditPid,
    event: AuditEvent,
}

impl AuditRecord {
    /// 検証済みの要素から組み立てる（失敗しない）。
    pub fn new(timestamp: AuditTimestamp, pid: AuditPid, event: AuditEvent) -> Self {
        Self {
            timestamp,
            pid,
            event,
        }
    }

    /// 発生時刻。
    pub fn timestamp(&self) -> AuditTimestamp {
        self.timestamp
    }

    /// 違反したプロセスの PID。
    pub fn pid(&self) -> AuditPid {
        self.pid
    }

    /// レイヤー別ペイロード。
    pub fn event(&self) -> &AuditEvent {
        &self.event
    }

    /// 検知レイヤー。
    pub fn layer(&self) -> AuditLayer {
        self.event.layer()
    }

    /// syscall があれば返す。
    pub fn syscall(&self) -> Option<AuditSyscallNr> {
        match &self.event {
            AuditEvent::Seccomp { syscall } => Some(*syscall),
            AuditEvent::Landlock { syscall, .. } => *syscall,
            AuditEvent::Mount { .. } => None,
        }
    }

    /// 対象パスがあれば返す。
    pub fn path(&self) -> Option<&Path> {
        match &self.event {
            AuditEvent::Seccomp { .. } => None,
            AuditEvent::Landlock { path, .. } => Some(path.as_path()),
            AuditEvent::Mount { path } => path.as_ref().map(AuditPath::as_path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> AuditTimestamp {
        AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5))
    }

    fn pid(n: i32) -> AuditPid {
        AuditPid::new(n).unwrap()
    }

    #[test]
    fn sec4_task41_1_seccomp_record_accessors() {
        let r = AuditRecord::new(
            ts(),
            pid(42),
            AuditEvent::Seccomp {
                syscall: AuditSyscallNr::new(272).unwrap(),
            },
        );
        assert_eq!(r.layer(), AuditLayer::Seccomp);
        assert_eq!(r.syscall().map(AuditSyscallNr::get), Some(272));
        assert_eq!(r.path(), None);
        assert_eq!(r.pid().get(), 42);
        assert_eq!(
            r.timestamp().as_unix_duration(),
            Duration::new(1_700_000_000, 5)
        );
        assert_eq!(r.timestamp().as_unix_nanos(), 1_700_000_000_000_000_005);
    }

    #[test]
    fn sec4_task41_1_landlock_record_with_and_without_syscall() {
        let p = AuditPath::new("/etc/shadow");
        let with = AuditRecord::new(
            ts(),
            pid(7),
            AuditEvent::Landlock {
                path: p.clone(),
                syscall: Some(AuditSyscallNr::new(2).unwrap()),
            },
        );
        assert_eq!(with.layer(), AuditLayer::Landlock);
        assert_eq!(with.syscall().map(AuditSyscallNr::get), Some(2));
        assert_eq!(with.path(), Some(Path::new("/etc/shadow")));
        let without = AuditRecord::new(
            ts(),
            pid(7),
            AuditEvent::Landlock {
                path: p,
                syscall: None,
            },
        );
        assert_eq!(without.syscall(), None);
        assert_eq!(without.path(), Some(Path::new("/etc/shadow")));
    }

    #[test]
    fn sec4_task41_1_mount_record_with_and_without_path() {
        let with = AuditRecord::new(
            ts(),
            pid(9),
            AuditEvent::Mount {
                path: Some(AuditPath::new("/proc/sys")),
            },
        );
        assert_eq!(with.layer(), AuditLayer::Mount);
        assert_eq!(with.path(), Some(Path::new("/proc/sys")));
        assert_eq!(with.syscall(), None);
        let without = AuditRecord::new(ts(), pid(9), AuditEvent::Mount { path: None });
        assert_eq!(without.path(), None);
    }

    #[test]
    fn sec4_task41_1_layer_tokens() {
        assert_eq!(AuditLayer::Seccomp.as_str(), "seccomp");
        assert_eq!(AuditLayer::Landlock.as_str(), "landlock");
        assert_eq!(AuditLayer::Mount.as_str(), "mount");
    }

    #[test]
    fn sec4_task41_1_pid_bounds() {
        for bad in [0, -1, i32::MIN] {
            assert_eq!(
                AuditPid::new(bad).unwrap_err().kind(),
                AuditRecordErrorKind::PidNotPositive
            );
        }
        assert_eq!(AuditPid::new(1).unwrap().get(), 1);
        assert_eq!(AuditPid::new(i32::MAX).unwrap().get(), 2_147_483_647);
    }

    #[test]
    fn sec4_task41_1_syscall_bounds() {
        assert_eq!(
            AuditSyscallNr::new(-1).unwrap_err().kind(),
            AuditRecordErrorKind::SyscallNegative
        );
        assert_eq!(AuditSyscallNr::new(0).unwrap().get(), 0);
        assert_eq!(AuditSyscallNr::new(272).unwrap().get(), 272);
    }

    #[test]
    fn sec4_task41_1_path_accepts_rejected_inputs() {
        // 拒否される入力そのものも記録できる（SEC-4 の 100% 記録）。
        let empty = AuditPath::new("");
        assert_eq!(empty.as_path(), Path::new(""));
        assert!(!empty.is_truncated());
        let nul = AuditPath::new("/a\0b");
        assert_eq!(nul.as_path(), Path::new("/a\0b"));
        assert_eq!(nul.original_len(), 4);
        assert_eq!(AuditPath::new("rel/path").as_path(), Path::new("rel/path"));
        let exact = AuditPath::new(&"a".repeat(AUDIT_PATH_MAX_BYTES));
        assert!(!exact.is_truncated());
        assert_eq!(exact.as_path().as_os_str().len(), AUDIT_PATH_MAX_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn sec4_task41_1_path_truncates_non_utf8_within_limit() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let bytes = vec![0xffu8; AUDIT_PATH_MAX_BYTES * 4];
        let p = AuditPath::new(OsStr::from_bytes(&bytes));
        assert!(p.is_truncated());
        assert_eq!(p.original_len(), AUDIT_PATH_MAX_BYTES * 4);
        // U+FFFD（3 バイト）単位で境界まで切り詰められる。
        assert_eq!(p.as_path().as_os_str().len(), 4095);
    }

    #[test]
    fn sec4_task41_1_path_truncates_over_limit() {
        let long = AuditPath::new(&"a".repeat(AUDIT_PATH_MAX_BYTES + 10));
        assert!(long.is_truncated());
        assert_eq!(long.original_len(), AUDIT_PATH_MAX_BYTES + 10);
        assert_eq!(long.as_path().as_os_str().len(), AUDIT_PATH_MAX_BYTES);
        // マルチバイト文字の境界で切り詰める（3 バイト文字が上限をまたぐ）。
        let multi = AuditPath::new(&"あ".repeat(AUDIT_PATH_MAX_BYTES / 3 + 1));
        assert!(multi.is_truncated());
        assert_eq!(multi.as_path().as_os_str().len(), 4095);
        let mount = AuditRecord::new(
            ts(),
            pid(3),
            AuditEvent::Mount {
                path: Some(AuditPath::new(&"b".repeat(5000))),
            },
        );
        assert_eq!(mount.path().map(|p| p.as_os_str().len()), Some(4096));
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn sec4_task41_1_from_table_syscall_nr() {
        use crate::seccomp::{DeniedSyscall, SyscallLookup};
        let table = crate::seccomp::table_for_target_arch().unwrap();
        let SyscallLookup::Present(nr) = table.number_of(DeniedSyscall::Unshare) else {
            panic!("unshare must be present in the host table");
        };
        let expected = if cfg!(target_arch = "x86_64") {
            272
        } else {
            97
        };
        assert_eq!(AuditSyscallNr::from(nr).get(), expected);
    }

    #[test]
    fn sec4_task41_1_timestamp_now_is_after_epoch() {
        let t = AuditTimestamp::now().unwrap();
        assert!(t.as_unix_duration() > Duration::from_secs(1_600_000_000));
    }

    #[test]
    fn sec4_task41_1_error_codes_and_messages() {
        let e = AuditPid::new(0).unwrap_err();
        assert_eq!(e.error_code(), ErrorCode::InvalidArgument);
        assert_eq!(e.message(), "audit pid must be positive");
        assert_eq!(
            e.to_string(),
            "INVALID_ARGUMENT: audit pid must be positive"
        );
        let c = AuditRecordError::new(AuditRecordErrorKind::ClockBeforeEpoch);
        assert_eq!(c.error_code(), ErrorCode::Internal);
        assert_eq!(c.message(), "system clock is before the UNIX epoch");
    }
}
