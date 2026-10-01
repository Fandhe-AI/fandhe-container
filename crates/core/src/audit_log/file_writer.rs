//! 監査レコードのローカルファイル書き込み経路（SEC-4・TASK-41.5.1・#839）。
//!
//! # 役割
//!
//! [`AuditRecord`] を JSON Lines（1 行 1 オブジェクト・LF 終端）にエンコードし、追記専用ファイルへ
//! 書き込む「主経路」を提供する。書き込み失敗は panic させず [`AuditWriteError`] で返し、
//! [`AuditFallback`] を介して代替経路（#840・TASK-41.5.2 のカーネル監査連携）へ引き渡せる。
//!
//! # 呼び出し元・契約
//!
//! - 各レイヤーのフック（seccomp / Landlock / マウント。TASK-41.2〜41.4）が組み立てた [`AuditRecord`] を
//!   supervisor / CLI の配線が [`write_with_fallback`] へ渡す想定（配線と `AuditSink` への適合は後続）
//! - [`encode_json_line`] はワイヤースキーマの単一の定義点。#840・#652（TASK-98.1・ERR-4 の共通ログ型）が再利用する
//! - 全キー常在の固定スキーマ。値が無いものは `null`。`path` は lossy UTF-8 で、制御文字・改行・NUL は
//!   JSON エスケープされる（ログ注入対策: 生の LF は行末の 1 個だけ）
//! - [`AuditFileWriter::open`] は symlink・FIFO・他者所有・group/other 権限付きのファイルを拒否する。
//!   **親ディレクトリの信頼性（所有者・権限）の検証は呼び出し側の責務**
//! - 部分書き込みで壊れた行は、次回書き込みの行頭に LF を付けて独立した行に隔離する（読み手は破損行を
//!   読み飛ばす）。失敗時の重複（主経路に部分書き込み＋フォールバックにも記録）は許容し、欠落は許容しない
//! - 非 Linux では symlink・所有者の信頼境界を検査できないため `open` は `Unimplemented` 相当の
//!   `Unsupported`（fail-closed）
//!
//! # 将来仕様
//!
//! seccomp の `arch` フィールドは未出力（TASK-41.2 のマージ後にスキーマへ追加）。フォールバックの実体は
//! #840 で実装し、本モジュールの [`NoAuditFallback`] はそれまでのスタブ（REPAIR-3）。

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use super::{AuditEvent, AuditRecord};
use crate::traits::ErrorCode;

/// 1 行（LF 含む）のバイト長上限。パス 4096 バイトの JSON エスケープ最大 6 倍＋固定部に収まる値。
pub const AUDIT_LINE_MAX_BYTES: usize = 32 * 1024;

/// 監査書き込みエラーの分類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditWriteErrorKind {
    /// 相対パスが渡された。
    RelativePath,
    /// この OS / アーキテクチャでは安全に開けない。
    Unsupported,
    /// 通常ファイルではない（FIFO・ディレクトリ・デバイス）。
    NotRegularFile,
    /// 所有者が実効 uid でない、または group/other 権限を持つ。
    InsecureFile,
    /// ファイルを開けない（symlink 含む）。
    Open,
    /// レコードをエンコードできない。
    Encode,
    /// エンコード結果が [`AUDIT_LINE_MAX_BYTES`] を超えた。
    LineTooLong,
    /// 書き込みに失敗した。
    Write,
    /// 永続化（fsync）に失敗した。
    Sync,
    /// フォールバック経路が未実装・利用不可。
    FallbackUnavailable,
}

/// 監査書き込みエラー（ERR 系の構造化形式。errno・パスは含めない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditWriteError {
    kind: AuditWriteErrorKind,
}

impl AuditWriteError {
    fn new(kind: AuditWriteErrorKind) -> Self {
        Self { kind }
    }

    /// フォールバック実装（#840）が自身の利用不可を表すための構築子。
    pub fn fallback_unavailable() -> Self {
        Self::new(AuditWriteErrorKind::FallbackUnavailable)
    }

    /// 分類を返す。
    pub fn kind(&self) -> AuditWriteErrorKind {
        self.kind
    }

    /// 構造化エラーコード。
    pub fn error_code(&self) -> ErrorCode {
        match self.kind {
            AuditWriteErrorKind::RelativePath => ErrorCode::InvalidArgument,
            AuditWriteErrorKind::Unsupported | AuditWriteErrorKind::FallbackUnavailable => {
                ErrorCode::Unimplemented
            }
            AuditWriteErrorKind::NotRegularFile | AuditWriteErrorKind::InsecureFile => {
                ErrorCode::PermissionDenied
            }
            _ => ErrorCode::Internal,
        }
    }

    /// 人間向け説明（英語。パス・errno・レコード内容は含めない）。
    pub fn message(&self) -> &'static str {
        match self.kind {
            AuditWriteErrorKind::RelativePath => "audit log path must be absolute",
            AuditWriteErrorKind::Unsupported => "audit log file is not supported on this platform",
            AuditWriteErrorKind::NotRegularFile => "audit log path is not a regular file",
            AuditWriteErrorKind::InsecureFile => {
                "audit log file must be owned by the current user and not accessible by others"
            }
            AuditWriteErrorKind::Open => "failed to open audit log file",
            AuditWriteErrorKind::Encode => "failed to encode audit record",
            AuditWriteErrorKind::LineTooLong => "encoded audit record exceeds the line limit",
            AuditWriteErrorKind::Write => "failed to write audit record",
            AuditWriteErrorKind::Sync => "failed to sync audit log file",
            AuditWriteErrorKind::FallbackUnavailable => "audit fallback path is not available",
        }
    }
}

impl fmt::Display for AuditWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_code().as_str(), self.message())
    }
}

impl std::error::Error for AuditWriteError {}

/// ワイヤー表現（非公開 DTO）。キー順はフィールド宣言順。
#[derive(Serialize)]
struct AuditLineDto {
    event: &'static str,
    layer: &'static str,
    ts_sec: u64,
    ts_nsec: u32,
    pid: u32,
    syscall: Option<u32>,
    path: Option<String>,
    path_truncated: Option<bool>,
    path_original_len: Option<usize>,
}

/// レコードを JSON 1 行（LF 終端）へエンコードする。
///
/// 非 UTF-8 のパスは lossy 変換する（`Serialize for Path` は非 UTF-8 でエラーになるため使わない）。
pub fn encode_json_line(record: &AuditRecord) -> Result<Vec<u8>, AuditWriteError> {
    let (syscall, path) = match record.event() {
        AuditEvent::Seccomp { syscall, .. } => (Some(syscall.get()), None),
        AuditEvent::Landlock { path, syscall, .. } => (syscall.map(|s| s.get()), Some(path)),
        AuditEvent::Mount { path, .. } => (None, path.as_ref()),
    };
    let ts = record.timestamp().as_unix_duration();
    let dto = AuditLineDto {
        event: "audit",
        layer: record.event().layer().as_str(),
        ts_sec: ts.as_secs(),
        ts_nsec: ts.subsec_nanos(),
        pid: record.pid().get(),
        syscall,
        path: path.map(|p| p.as_path().to_string_lossy().into_owned()),
        path_truncated: path.map(|p| p.is_truncated()),
        path_original_len: path.map(|p| p.original_len()),
    };
    let mut line =
        serde_json::to_vec(&dto).map_err(|_| AuditWriteError::new(AuditWriteErrorKind::Encode))?;
    line.push(b'\n');
    if line.len() > AUDIT_LINE_MAX_BYTES {
        return Err(AuditWriteError::new(AuditWriteErrorKind::LineTooLong));
    }
    Ok(line)
}

/// 追記専用の監査ログファイル（主経路）。
#[derive(Debug)]
pub struct AuditFileWriter {
    file: File,
    /// 直前の書き込みが失敗し、末尾に部分行が残っている可能性がある。
    needs_line_break: bool,
}

impl AuditFileWriter {
    /// 絶対パスの監査ログを追記モード・0600 で開く（無ければ作成）。
    ///
    /// 最終要素の symlink は辿らず（`O_NOFOLLOW`）、FIFO でも open が止まらない（`O_NONBLOCK`。REPAIR-5）。
    /// 開いたハンドルの fstat で通常ファイル・所有者・権限を検証する。
    pub fn open(path: &Path) -> Result<Self, AuditWriteError> {
        if !path.is_absolute() {
            return Err(AuditWriteError::new(AuditWriteErrorKind::RelativePath));
        }
        open_checked(path)
    }

    /// テスト用: 検査なしで `File` を包む（読み取り専用ファイルで書き込み失敗を再現する）。
    #[cfg(test)]
    pub(crate) fn from_file_unchecked(file: File) -> Self {
        Self {
            file,
            needs_line_break: false,
        }
    }

    /// 1 レコードを 1 回の `write_all` で書き、`sync_data` まで行う。
    ///
    /// 失敗時は panic せず `Err` を返す。呼び出し側は [`write_with_fallback`] で代替経路へ回す。
    pub fn write_record(&mut self, record: &AuditRecord) -> Result<(), AuditWriteError> {
        let line = encode_json_line(record)?;
        let mut buf = Vec::with_capacity(line.len() + 1);
        if self.needs_line_break {
            buf.push(b'\n');
        }
        buf.extend_from_slice(&line);
        if self.file.write_all(&buf).is_err() {
            self.needs_line_break = true;
            return Err(AuditWriteError::new(AuditWriteErrorKind::Write));
        }
        if self.file.sync_data().is_err() {
            self.needs_line_break = true;
            return Err(AuditWriteError::new(AuditWriteErrorKind::Sync));
        }
        self.needs_line_break = false;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn open_checked(path: &Path) -> Result<AuditFileWriter, AuditWriteError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};

    let flags = crate::sys::nofollow_nonblock_open_flags()
        .ok_or_else(|| AuditWriteError::new(AuditWriteErrorKind::Unsupported))?;
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(flags)
        .open(path)
        .map_err(|_| AuditWriteError::new(AuditWriteErrorKind::Open))?;
    let meta = file
        .metadata()
        .map_err(|_| AuditWriteError::new(AuditWriteErrorKind::Open))?;
    if !meta.file_type().is_file() {
        return Err(AuditWriteError::new(AuditWriteErrorKind::NotRegularFile));
    }
    if meta.uid() != crate::sys::effective_uid() || meta.mode() & 0o077 != 0 {
        return Err(AuditWriteError::new(AuditWriteErrorKind::InsecureFile));
    }
    // 再オープン時に末尾が LF でない（前回プロセスの torn line）場合、最初の追記前に LF を挿入して
    // 新レコードを既存の部分行から隔離する。pread なので O_APPEND の書き込み位置に影響しない。
    let needs_line_break = match meta.len().checked_sub(1) {
        None => false,
        Some(last) => {
            let mut b = [0u8; 1];
            file.read_exact_at(&mut b, last)
                .map_err(|_| AuditWriteError::new(AuditWriteErrorKind::Open))?;
            b[0] != b'\n'
        }
    };
    Ok(AuditFileWriter {
        file,
        needs_line_break,
    })
}

#[cfg(not(target_os = "linux"))]
fn open_checked(_path: &Path) -> Result<AuditFileWriter, AuditWriteError> {
    Err(AuditWriteError::new(AuditWriteErrorKind::Unsupported))
}

/// 主経路が失敗したときの代替経路のフック点（#840・TASK-41.5.2 がカーネル監査連携で実装する）。
pub trait AuditFallback {
    /// 主経路の失敗 `primary` を受けて `record` を代替経路へ記録する。
    fn record_fallback(
        &mut self,
        record: &AuditRecord,
        primary: &AuditWriteError,
    ) -> Result<(), AuditWriteError>;
}

/// 既定のスタブ。常に `FallbackUnavailable`（`Unimplemented`）を返す。
///
/// #840 でカーネル監査連携が実装されるまでの暫定（REPAIR-3: 実装済みを装わない）。
#[derive(Debug, Default, Clone, Copy)]
pub struct NoAuditFallback;

impl AuditFallback for NoAuditFallback {
    fn record_fallback(
        &mut self,
        _record: &AuditRecord,
        _primary: &AuditWriteError,
    ) -> Result<(), AuditWriteError> {
        Err(AuditWriteError::fallback_unavailable())
    }
}

/// [`write_with_fallback`] の成功結果。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditWriteOutcome {
    /// 主経路（ローカルファイル）に記録できた。
    Primary,
    /// 主経路は失敗したが代替経路に記録できた。
    Fallback {
        /// 主経路の失敗。
        primary_error: AuditWriteError,
    },
}

/// 主経路・代替経路の両方が失敗した（記録が欠落した）ことを表す。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditWriteFailure {
    primary: AuditWriteError,
    fallback: AuditWriteError,
}

impl AuditWriteFailure {
    /// 主経路のエラー。
    pub fn primary(&self) -> &AuditWriteError {
        &self.primary
    }

    /// 代替経路のエラー。
    pub fn fallback(&self) -> &AuditWriteError {
        &self.fallback
    }

    /// 構造化エラーコード（常に `Internal`）。
    pub fn error_code(&self) -> ErrorCode {
        ErrorCode::Internal
    }

    /// 人間向け説明（英語）。
    pub fn message(&self) -> &'static str {
        "audit record could not be persisted by primary or fallback path"
    }
}

impl fmt::Display for AuditWriteFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error_code().as_str(), self.message())
    }
}

impl std::error::Error for AuditWriteFailure {}

/// 主経路へ書き、失敗したときだけ `fallback` を 1 回呼ぶ。
pub fn write_with_fallback(
    primary: &mut AuditFileWriter,
    fallback: &mut dyn AuditFallback,
    record: &AuditRecord,
) -> Result<AuditWriteOutcome, AuditWriteFailure> {
    match primary.write_record(record) {
        Ok(()) => Ok(AuditWriteOutcome::Primary),
        Err(primary_error) => match fallback.record_fallback(record, &primary_error) {
            Ok(()) => Ok(AuditWriteOutcome::Fallback { primary_error }),
            Err(fallback_error) => Err(AuditWriteFailure {
                primary: primary_error,
                fallback: fallback_error,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::{AuditPath, AuditPid, AuditSyscallNr, AuditTimestamp};
    use std::time::Duration;

    fn ts() -> AuditTimestamp {
        AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5))
    }

    fn rec(pid: i32, event: AuditEvent) -> AuditRecord {
        AuditRecord::new(ts(), AuditPid::new(pid).unwrap(), event)
    }

    fn text(r: &AuditRecord) -> String {
        String::from_utf8(encode_json_line(r).unwrap()).unwrap()
    }

    /// SEC-4・TASK-41.5.1: seccomp レコードのワイヤー表現。
    #[test]
    fn sec4_task41_5_1_encode_seccomp() {
        let r = rec(
            42,
            AuditEvent::Seccomp {
                syscall: AuditSyscallNr::new(272).unwrap(),
            },
        );
        assert_eq!(
            text(&r),
            "{\"event\":\"audit\",\"layer\":\"seccomp\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":42,\"syscall\":272,\"path\":null,\"path_truncated\":null,\"path_original_len\":null}\n"
        );
    }

    /// SEC-4・TASK-41.5.1: Landlock（パスあり・syscall なし）と Mount（パスなし）。
    #[test]
    fn sec4_task41_5_1_encode_landlock_and_mount() {
        let l = rec(
            7,
            AuditEvent::Landlock {
                path: AuditPath::new("/etc/shadow"),
                syscall: None,
            },
        );
        assert_eq!(
            text(&l),
            "{\"event\":\"audit\",\"layer\":\"landlock\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":7,\"syscall\":null,\"path\":\"/etc/shadow\",\"path_truncated\":false,\"path_original_len\":11}\n"
        );
        let m = rec(8, AuditEvent::Mount { path: None });
        assert_eq!(
            text(&m),
            "{\"event\":\"audit\",\"layer\":\"mount\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":8,\"syscall\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null}\n"
        );
    }

    /// SEC-4・TASK-41.5.1: 改行・NUL はエスケープされ 1 行に収まる（ログ注入対策）。
    #[test]
    fn sec4_task41_5_1_escapes_control_chars() {
        let r = rec(
            1,
            AuditEvent::Mount {
                path: Some(AuditPath::new("/a\nb\0c")),
            },
        );
        let s = text(&r);
        assert!(s.contains("\"path\":\"/a\\nb\\u0000c\""), "{s}");
        assert_eq!(s.matches('\n').count(), 1);
        assert!(s.ends_with('\n'));
    }

    /// SEC-4・TASK-41.5.1: 切り詰めの記録。
    #[test]
    fn sec4_task41_5_1_truncated_path() {
        let long = format!("/{}", "a".repeat(4999));
        let r = rec(
            1,
            AuditEvent::Mount {
                path: Some(AuditPath::new(&long)),
            },
        );
        let s = text(&r);
        assert!(
            s.contains("\"path_truncated\":true,\"path_original_len\":5000"),
            "{s}"
        );
    }

    /// SEC-4・TASK-41.5.1: 非 UTF-8 パスは U+FFFD に置換されエンコードは失敗しない。
    #[cfg(unix)]
    #[test]
    fn sec4_task41_5_1_non_utf8_path_is_lossy() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let p = Path::new(OsStr::from_bytes(b"/x\xffy"));
        let r = rec(
            1,
            AuditEvent::Mount {
                path: Some(AuditPath::new(p)),
            },
        );
        assert!(text(&r).contains("\"path\":\"/x\u{fffd}y\""));
    }

    fn failing_writer() -> AuditFileWriter {
        // 読み取り専用で開いた File への write は必ず失敗する。
        AuditFileWriter::from_file_unchecked(File::open(std::env::current_exe().unwrap()).unwrap())
    }

    fn sample() -> AuditRecord {
        rec(1, AuditEvent::Mount { path: None })
    }

    struct Recorder {
        calls: Vec<AuditWriteErrorKind>,
        result: Result<(), AuditWriteErrorKind>,
    }

    impl AuditFallback for Recorder {
        fn record_fallback(
            &mut self,
            _record: &AuditRecord,
            primary: &AuditWriteError,
        ) -> Result<(), AuditWriteError> {
            self.calls.push(primary.kind());
            self.result.map_err(AuditWriteError::new)
        }
    }

    /// SEC-4・TASK-41.5.1: 書き込み失敗は panic せず Err。
    #[test]
    fn sec4_task41_5_1_write_failure_is_error() {
        let e = failing_writer().write_record(&sample()).unwrap_err();
        assert_eq!(e.kind(), AuditWriteErrorKind::Write);
        assert_eq!(e.error_code(), ErrorCode::Internal);
    }

    /// SEC-4・TASK-41.5.1: 主経路失敗時にフォールバックが 1 回だけ呼ばれる。
    #[test]
    fn sec4_task41_5_1_fallback_called_once_on_failure() {
        let mut fb = Recorder {
            calls: vec![],
            result: Ok(()),
        };
        let out = write_with_fallback(&mut failing_writer(), &mut fb, &sample()).unwrap();
        assert_eq!(fb.calls, vec![AuditWriteErrorKind::Write]);
        assert!(
            matches!(out, AuditWriteOutcome::Fallback { ref primary_error }
            if primary_error.kind() == AuditWriteErrorKind::Write)
        );
    }

    /// SEC-4・TASK-41.5.1: 両系統失敗は AuditWriteFailure（Internal）。
    #[test]
    fn sec4_task41_5_1_both_fail() {
        let mut fb = Recorder {
            calls: vec![],
            result: Err(AuditWriteErrorKind::FallbackUnavailable),
        };
        let f = write_with_fallback(&mut failing_writer(), &mut fb, &sample()).unwrap_err();
        assert_eq!(f.primary().kind(), AuditWriteErrorKind::Write);
        assert_eq!(
            f.fallback().kind(),
            AuditWriteErrorKind::FallbackUnavailable
        );
        assert_eq!(f.error_code(), ErrorCode::Internal);
        let e = NoAuditFallback
            .record_fallback(&sample(), f.primary())
            .unwrap_err();
        assert_eq!(e.error_code(), ErrorCode::Unimplemented);
    }

    /// SEC-4・TASK-41.5.1: 失敗後は次回書き込みで行頭 LF を付ける状態になる。
    #[test]
    fn sec4_task41_5_1_line_break_after_failure() {
        let mut w = failing_writer();
        assert!(w.write_record(&sample()).is_err());
        assert!(w.needs_line_break);
    }

    /// SEC-4・TASK-41.5.1: 末尾が LF でない既存ファイルを再オープンしても、新レコードは独立した行になる。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_task41_5_1_reopen_isolates_torn_tail() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fandhe-auditw-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.log");
        std::fs::write(&path, b"{\"torn\":").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut w = AuditFileWriter::open(&path).unwrap();
        w.write_record(&sample()).unwrap();
        drop(w);
        // LF で終わる既存ファイルの再オープンでは余分な空行を入れない。
        let mut w = AuditFileWriter::open(&path).unwrap();
        w.write_record(&sample()).unwrap();
        drop(w);

        let got = std::fs::read_to_string(&path).unwrap();
        let line = text(&sample());
        assert_eq!(got, format!("{{\"torn\":\n{line}{line}"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
