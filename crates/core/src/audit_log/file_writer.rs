//! 監査レコードのローカルファイル書き込み経路（SEC-4・TASK-41.5.1・#839）。
//!
//! # 役割
//!
//! [`AuditRecord`] を JSON Lines（1 行 1 オブジェクト・LF 終端）にエンコードし、追記専用ファイルへ
//! 書き込む「主経路」を提供する。書き込み失敗は panic させず [`AuditWriteError`] で返し、
//! [`AuditFallback`] を介して代替経路（TASK-41.5.2・#840 のカーネル監査フォールバック）へ引き渡せる。
//!
//! # 呼び出し元・契約
//!
//! - 各レイヤーのフック（seccomp / Landlock / マウント。TASK-41.2〜41.4）が組み立てた [`AuditRecord`] を
//!   supervisor / CLI の配線が [`write_with_fallback`] へ渡す想定（`AuditSink` への適合は `FileAuditSink`〔#1594〕で実装済み）
//! - [`encode_json_line`] はワイヤースキーマの単一の定義点。#840・#652（TASK-98.1・ERR-4 の共通ログ型）が再利用する
//! - 全キー常在の固定スキーマ。値が無いものは `null`。`path` は lossy UTF-8 で、制御文字・改行・NUL は
//!   JSON エスケープされる（ログ注入対策: 生の LF は行末の 1 個だけ）
//! - [`AuditFileWriter::open`] は symlink・FIFO・他者所有・group/other 権限付きのファイルを拒否する。
//!   親ディレクトリも `/` から 1 要素ずつ `O_NOFOLLOW|O_DIRECTORY` で辿って fd で固定し、いずれかが
//!   symlink・非ディレクトリ・root でも実効 uid 所有でもない・group/other 書き込み可（sticky 付きの祖先は
//!   許容。直接の親は不可）なら拒否する。ファイルは固定した親 fd の `/proc/self/fd/N/<name>` 経由で開き、
//!   検証後の親の差し替え（TOCTOU）を防ぐ
//! - 書き込みは `flock`（排他）を `AUDIT_LOCK_TIMEOUT` を上限に取得してから 1 レコードずつ行う。複数の
//!   writer（同一プロセス内・別プロセス）が同じファイルを開いても、`write_all` の複数 write の間に他者の
//!   追記が割り込まず、行が混ざらない。ロック下で末尾が LF でなければ行頭 LF で破損行を隔離する
//! - 部分書き込みで壊れた行は、次回書き込みの行頭に LF を付けて独立した行に隔離する（読み手は破損行を
//!   読み飛ばす）。失敗時の重複（主経路に部分書き込み＋フォールバックにも記録）は許容し、欠落は許容しない
//! - 非 Linux では symlink・所有者の信頼境界を検査できないため `open` は `Unimplemented` 相当の
//!   `Unsupported`（fail-closed）
//!
//! # 将来仕様
//!
//! 代替経路の実体は `kernel_audit` の `KernelAuditFallback`（主経路の失敗時にだけカーネル監査へ送る）。
//! 常時の二重記録（tee）によるクラッシュ・改ざん時の記録保持は未実装（REPAIR-3）。

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;

use super::{AuditEvent, AuditRecord};
use crate::traits::ErrorCode;

/// 書き込みロック取得の待ち時間上限（REPAIR-5: 無期限に待たない）。
const AUDIT_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// ロック取得のリトライ間隔。
const AUDIT_LOCK_RETRY: Duration = Duration::from_millis(5);

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
    /// 所有者が実効 uid でない、group/other 権限を持つ、またはハードリンク数が 1 でない。
    InsecureFile,
    /// ファイルを開けない（symlink 含む）。
    Open,
    /// レコードをエンコードできない。
    Encode,
    /// エンコード結果が [`AUDIT_LINE_MAX_BYTES`] を超えた。
    LineTooLong,
    /// 書き込みに失敗した。
    Write,
    /// 書き込みロックを期限内に取得できなかった。
    Lock,
    /// ロック操作自体が I/O エラーで失敗した（タイムアウトではない）。
    LockFailed,
    /// 永続化（fsync）に失敗した。
    Sync,
    /// フォールバック経路が未実装・利用不可。
    FallbackUnavailable,
    /// カーネル監査へ到達できない（audit 非搭載・初期 user namespace 外・socket 作成不可。TASK-41.5.2）。
    KernelAuditUnavailable,
    /// カーネル監査が `CAP_AUDIT_WRITE` 不足で書き込みを拒否した（ACK が `EPERM`）。
    KernelAuditPermissionDenied,
    /// カーネル監査の ACK が上限時間内に届かなかった（REPAIR-5）。
    KernelAuditTimeout,
    /// カーネル監査が `EPERM` / `ECONNREFUSED` 以外の errno で書き込みを拒否した。
    KernelAuditRejected,
    /// カーネル監査との送受信が I/O エラーで失敗した、または ACK の形式が不正だった。
    KernelAuditIo,
    /// 主経路のファイル書き込みを隔離した子プロセスが期限内に終わらなかった（ストレージ停止等。
    /// 子は SIGKILL で止め、代替経路へ進む。REPAIR-5・`FileAuditSink`）。
    IsolationTimeout,
    /// 主経路を隔離するプロセスを作れなかった（呼び出しプロセスが複数スレッドで fork できない等）。
    /// 期限を保証できないため主経路は試行せず、代替経路へ進む（fail-closed。`FileAuditSink`）。
    IsolationUnavailable,
}

impl AuditWriteErrorKind {
    /// ログ・構造化行用の固定トークン（snake_case。レコード内容・errno を含まない）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RelativePath => "relative_path",
            Self::Unsupported => "unsupported",
            Self::NotRegularFile => "not_regular_file",
            Self::InsecureFile => "insecure_file",
            Self::Open => "open",
            Self::Encode => "encode",
            Self::LineTooLong => "line_too_long",
            Self::Write => "write",
            Self::Lock => "lock",
            Self::LockFailed => "lock_failed",
            Self::Sync => "sync",
            Self::FallbackUnavailable => "fallback_unavailable",
            Self::KernelAuditUnavailable => "kernel_audit_unavailable",
            Self::KernelAuditPermissionDenied => "kernel_audit_permission_denied",
            Self::KernelAuditTimeout => "kernel_audit_timeout",
            Self::KernelAuditRejected => "kernel_audit_rejected",
            Self::KernelAuditIo => "kernel_audit_io",
            Self::IsolationTimeout => "isolation_timeout",
            Self::IsolationUnavailable => "isolation_unavailable",
        }
    }
}

/// 監査書き込みエラー（ERR 系の構造化形式。errno・パスは含めない）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditWriteError {
    kind: AuditWriteErrorKind,
}

impl AuditWriteError {
    pub(super) fn new(kind: AuditWriteErrorKind) -> Self {
        Self { kind }
    }

    /// フォールバック実装が自身の利用不可を表すための構築子。
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
            AuditWriteErrorKind::Lock
            | AuditWriteErrorKind::KernelAuditTimeout
            | AuditWriteErrorKind::IsolationTimeout => ErrorCode::Timeout,
            AuditWriteErrorKind::IsolationUnavailable => ErrorCode::Unavailable,
            // 環境上カーネル監査へ到達できない状態（未実装ではない）。`Unimplemented` と区別する。
            AuditWriteErrorKind::KernelAuditUnavailable => ErrorCode::Unavailable,
            AuditWriteErrorKind::KernelAuditPermissionDenied => ErrorCode::PermissionDenied,
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
            AuditWriteErrorKind::Lock => "timed out waiting for the audit log lock",
            AuditWriteErrorKind::LockFailed => "failed to acquire the audit log lock",
            AuditWriteErrorKind::Sync => "failed to sync audit log file",
            AuditWriteErrorKind::FallbackUnavailable => "audit fallback path is not available",
            AuditWriteErrorKind::KernelAuditUnavailable => {
                "kernel audit subsystem is not reachable from this environment"
            }
            AuditWriteErrorKind::KernelAuditPermissionDenied => {
                "kernel audit rejected the message: CAP_AUDIT_WRITE is required"
            }
            AuditWriteErrorKind::KernelAuditTimeout => {
                "timed out waiting for the kernel audit acknowledgement"
            }
            AuditWriteErrorKind::KernelAuditRejected => "kernel audit rejected the message",
            AuditWriteErrorKind::KernelAuditIo => "kernel audit exchange failed",
            AuditWriteErrorKind::IsolationTimeout => {
                "isolated audit log write did not finish within the time limit"
            }
            AuditWriteErrorKind::IsolationUnavailable => {
                "audit log write could not be isolated in a bounded child process"
            }
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
    /// seccomp のみ: syscall 番号を解釈するための `AUDIT_ARCH_*`（番号はアーキ相対のため併記）。
    arch: Option<u32>,
    path: Option<String>,
    path_truncated: Option<bool>,
    path_original_len: Option<usize>,
    /// plugin 信頼検証と exec 対象のみ: 拒否理由トークン（他レイヤーでは出力しない＝既存行は不変）。
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

/// レコードを JSON 1 行（LF 終端）へエンコードする。
///
/// 非 UTF-8 のパスは lossy 変換する（`Serialize for Path` は非 UTF-8 でエラーになるため使わない）。
pub fn encode_json_line(record: &AuditRecord) -> Result<Vec<u8>, AuditWriteError> {
    let (syscall, path) = match record.event() {
        AuditEvent::Seccomp { syscall, .. } => (Some(syscall.get()), None),
        AuditEvent::Landlock { path, syscall, .. } => (syscall.map(|s| s.get()), Some(path)),
        AuditEvent::Mount { path, .. } => (None, path.as_ref()),
        AuditEvent::PluginTrust { path, .. } => (None, Some(path)),
        AuditEvent::ExecTarget { .. } | AuditEvent::Entrypoint { .. } => (None, None),
    };
    let ts = record.timestamp().as_unix_duration();
    let dto = AuditLineDto {
        event: "audit",
        layer: record.event().layer().as_str(),
        ts_sec: ts.as_secs(),
        ts_nsec: ts.subsec_nanos(),
        pid: record.pid().get(),
        syscall,
        arch: record.seccomp_arch().map(|a| a.get()),
        path: path.map(|p| p.as_path().to_string_lossy().into_owned()),
        path_truncated: path.map(|p| p.is_truncated()),
        path_original_len: path.map(|p| p.original_len()),
        reason: record.reason().map(|r| r.as_str()),
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
        Self { file }
    }

    /// 1 レコードを排他ロック下で `write_all` し、`sync_data` まで行う。
    ///
    /// 失敗時は panic せず `Err` を返す。呼び出し側は [`write_with_fallback`] で代替経路へ回す。
    pub fn write_record(&mut self, record: &AuditRecord) -> Result<(), AuditWriteError> {
        let line = encode_json_line(record)?;
        self.lock_exclusive()?;
        let result = self.write_locked(&line);
        // 解放失敗は致命的ではない（fd を閉じれば解放される）。結果は書き込みの成否で決める。
        let _ = self.file.unlock();
        result
    }

    fn lock_exclusive(&self) -> Result<(), AuditWriteError> {
        let deadline = Instant::now() + AUDIT_LOCK_TIMEOUT;
        loop {
            match self.file.try_lock() {
                Ok(()) => return Ok(()),
                Err(std::fs::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(AuditWriteError::new(AuditWriteErrorKind::Lock));
                    }
                    std::thread::sleep(AUDIT_LOCK_RETRY);
                }
                Err(std::fs::TryLockError::Error(_)) => {
                    return Err(AuditWriteError::new(AuditWriteErrorKind::LockFailed));
                }
            }
        }
    }

    fn write_locked(&mut self, line: &[u8]) -> Result<(), AuditWriteError> {
        let mut buf = Vec::with_capacity(line.len() + 1);
        // 行頭 LF の要否は、ロック下で確認した実際の末尾バイトだけで決める（自身の直前の失敗・他 writer・
        // 前回プロセスの部分行を区別せず扱う。sync 失敗後など末尾が既に LF なら空行を作らない）。
        if tail_is_unterminated(&self.file) {
            buf.push(b'\n');
        }
        buf.extend_from_slice(line);
        if self.file.write_all(&buf).is_err() {
            return Err(AuditWriteError::new(AuditWriteErrorKind::Write));
        }
        if self.file.sync_data().is_err() {
            return Err(AuditWriteError::new(AuditWriteErrorKind::Sync));
        }
        Ok(())
    }
}

/// ファイル末尾が LF で終わっていない（空ファイルは終端済み扱い）か。読めない場合は安全側で `true`。
#[cfg(unix)]
fn tail_is_unterminated(file: &File) -> bool {
    use std::os::unix::fs::FileExt;
    let Ok(meta) = file.metadata() else {
        return true;
    };
    let Some(last) = meta.len().checked_sub(1) else {
        return false;
    };
    let mut b = [0u8; 1];
    match file.read_exact_at(&mut b, last) {
        Ok(()) => b[0] != b'\n',
        Err(_) => true,
    }
}

#[cfg(not(unix))]
fn tail_is_unterminated(_file: &File) -> bool {
    false
}

/// `/` から `dir` まで 1 要素ずつ `O_NOFOLLOW|O_DIRECTORY` で辿り、各要素の所有者・権限を検証して
/// 最後の要素の fd（O_PATH）を返す。`..`・相対要素は拒否する。
#[cfg(target_os = "linux")]
fn open_trusted_parent(dir: &Path) -> Result<std::os::fd::OwnedFd, AuditWriteError> {
    use std::ffi::CString;
    use std::os::fd::AsFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let open_err = || AuditWriteError::new(AuditWriteErrorKind::Open);
    let insecure = || AuditWriteError::new(AuditWriteErrorKind::InsecureFile);
    let euid = crate::sys::effective_uid();

    let mut names = Vec::new();
    for c in dir.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => names.push(CString::new(n.as_bytes()).map_err(|_| open_err())?),
            _ => return Err(open_err()),
        }
    }
    let mut cur = crate::sys::open_dir_path_nofollow(None, c"/").map_err(|_| open_err())?;
    let total = names.len();
    // 検証は root 自身（index なし）から: 祖先すべてを同じ基準で検査する。
    let check = |fd: &std::os::fd::OwnedFd, is_parent: bool| -> Result<(), AuditWriteError> {
        let meta = File::from(fd.as_fd().try_clone_to_owned().map_err(|_| open_err())?)
            .metadata()
            .map_err(|_| open_err())?;
        if !meta.file_type().is_dir() {
            return Err(AuditWriteError::new(AuditWriteErrorKind::NotRegularFile));
        }
        let owner_ok = meta.uid() == 0 || meta.uid() == euid;
        let mode = meta.mode();
        // group/other 書き込み可は、sticky 付きの祖先（/tmp 等）のみ許容する。直接の親は不可。
        let writable_ok = mode & 0o022 == 0 || (!is_parent && mode & 0o1000 != 0);
        if owner_ok && writable_ok {
            Ok(())
        } else {
            Err(insecure())
        }
    };
    check(&cur, total == 0)?;
    for (i, name) in names.iter().enumerate() {
        let next =
            crate::sys::open_dir_path_nofollow(Some(cur.as_fd()), name).map_err(|_| open_err())?;
        check(&next, i + 1 == total)?;
        cur = next;
    }
    Ok(cur)
}

#[cfg(target_os = "linux")]
fn open_checked(path: &Path) -> Result<AuditFileWriter, AuditWriteError> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let open_err = || AuditWriteError::new(AuditWriteErrorKind::Open);
    let flags = crate::sys::nofollow_nonblock_open_flags()
        .ok_or_else(|| AuditWriteError::new(AuditWriteErrorKind::Unsupported))?;
    // 最終要素は親要素と同じくバイト列として扱う（Linux の正当な非 UTF-8 ファイル名を拒否しない）。
    // 検証は空・NUL のみ（NUL は open(2) に渡せない値のため明示的に弾く）。
    let name = path
        .file_name()
        .filter(|n| !n.is_empty() && !n.as_bytes().contains(&0))
        .ok_or_else(open_err)?;
    let parent = path.parent().ok_or_else(open_err)?;
    // 親を fd で固定してから、その fd の magic link 経由で最終要素を開く（検証後の差し替えを防ぐ）。
    let parent_fd = open_trusted_parent(parent)?;
    let via_fd =
        std::path::PathBuf::from(format!("/proc/self/fd/{}", parent_fd.as_raw_fd())).join(name);
    // 書き込み可能 fd を開く前に、副作用のない lstat（open しない）で既存エントリの種別を確認する。
    // デバイス・FIFO 等は open(2) 自体が副作用を持ち得るため、通常ファイル以外は開かずに拒否する。
    // 不在（NotFound）は新規作成のため許可。lstat と open の間の差し替えは、親が信頼済み
    // （所有者・権限検証済みで fd 固定）であること、O_NOFOLLOW|O_NONBLOCK、および open 後の
    // fstat 再検証で防ぐ。
    match std::fs::symlink_metadata(&via_fd) {
        // symlink・ディレクトリは従来どおり Open 失敗として扱う（open(2) の ELOOP / EISDIR 相当）。
        Ok(m) if m.file_type().is_symlink() || m.file_type().is_dir() => return Err(open_err()),
        Ok(m) if !m.file_type().is_file() => {
            return Err(AuditWriteError::new(AuditWriteErrorKind::NotRegularFile));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(open_err()),
    }
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(flags)
        .open(&via_fd)
        .map_err(|_| open_err())?;
    drop(parent_fd);
    let meta = file.metadata().map_err(|_| open_err())?;
    if !meta.file_type().is_file() {
        return Err(AuditWriteError::new(AuditWriteErrorKind::NotRegularFile));
    }
    // ハードリンク数が 1 でなければ、別パスの機密ファイル（同一所有者・0600）への link を
    // 監査ログパスに仕込まれた可能性がある。追記による改変を防ぐため拒否する（SEC-4）。
    if meta.nlink() != 1 || meta.uid() != crate::sys::effective_uid() || meta.mode() & 0o077 != 0 {
        return Err(AuditWriteError::new(AuditWriteErrorKind::InsecureFile));
    }
    // 末尾が LF でない（torn line）場合の隔離は、書き込みごとにロック下で判定する。
    Ok(AuditFileWriter { file })
}

#[cfg(not(target_os = "linux"))]
fn open_checked(_path: &Path) -> Result<AuditFileWriter, AuditWriteError> {
    Err(AuditWriteError::new(AuditWriteErrorKind::Unsupported))
}

/// 主経路が失敗したときの代替経路のフック点（TASK-41.5.2・#840。実装は `KernelAuditFallback`）。
pub trait AuditFallback {
    /// 主経路の失敗 `primary` を受けて `record` を代替経路へ記録する。
    fn record_fallback(
        &mut self,
        record: &AuditRecord,
        primary: &AuditWriteError,
    ) -> Result<(), AuditWriteError>;
}

/// カーネル監査を使わない構成・テスト用の代替経路。常に `FallbackUnavailable`（`Unimplemented`）を返す。
///
/// 本番のカーネル監査フォールバックは `KernelAuditFallback`（TASK-41.5.2・#840）。本型は「代替経路なし」を
/// 明示する構成のために残す（記録は欠落するため、両経路失敗として [`AuditWriteFailure`] が返る）。
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

/// 主経路・代替経路の両方が失敗した（記録が欠落した）ことを表す（SEC-4・TASK-41.5.2）。
///
/// # 両経路失敗時の扱い
///
/// - 構造化エラーコードは常に `INTERNAL`。両経路のエラー（kind とコード）は [`Self::primary`]・
///   [`Self::fallback`] で保持する
/// - 記録の成否で分離違反の拒否判定を覆さない（fail-closed。`AuditSink` の契約と同じ）。拒否は維持したまま、
///   記録が欠落した事実だけを呼び出し側へ返す
/// - 黙って捨てない。通知の責務は `FileAuditSink`（#1594）が持ち、[`Self::write_json_line`] の固定スキーマ
///   1 行を stderr へ 1 回出力する（レコード内容・パス・errno は含まない）
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditWriteFailure {
    primary: AuditWriteError,
    fallback: AuditWriteError,
}

impl AuditWriteFailure {
    /// 主経路の open 自体が失敗し、代替経路も失敗した場合など、crate 内で両エラーから組み立てる
    /// （`FileAuditSink`。#1594）。
    pub(crate) fn new(primary: AuditWriteError, fallback: AuditWriteError) -> Self {
        Self { primary, fallback }
    }

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

    /// 両経路失敗を固定スキーマの 1 行（LF 終端）で `out` へ書く（stderr 出力用。REPAIR-4）。
    ///
    /// キーは `event`・`code`・`primary`・`primary_code`・`fallback`・`fallback_code` の固定順。
    /// 値はすべて固定トークンで、レコード内容・パス・errno を含めない（ログ注入・秘密情報の回避）。
    pub fn write_json_line(&self, out: &mut dyn Write) -> std::io::Result<()> {
        writeln!(
            out,
            "{{\"event\":\"audit_write_failure\",\"code\":\"{}\",\"primary\":\"{}\",\"primary_code\":\"{}\",\"fallback\":\"{}\",\"fallback_code\":\"{}\"}}",
            self.error_code().as_str(),
            self.primary.kind().as_str(),
            self.primary.error_code().as_str(),
            self.fallback.kind().as_str(),
            self.fallback.error_code().as_str(),
        )
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
    use crate::audit_log::{AuditPath, AuditPid, AuditSyscallArch, AuditSyscallNr, AuditTimestamp};
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
                arch: AuditSyscallArch::from_raw(3221225534),
            },
        );
        assert_eq!(
            text(&r),
            "{\"event\":\"audit\",\"layer\":\"seccomp\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":42,\"syscall\":272,\"arch\":3221225534,\"path\":null,\"path_truncated\":null,\"path_original_len\":null}\n"
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
            "{\"event\":\"audit\",\"layer\":\"landlock\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":7,\"syscall\":null,\"arch\":null,\"path\":\"/etc/shadow\",\"path_truncated\":false,\"path_original_len\":11}\n"
        );
        let m = rec(8, AuditEvent::Mount { path: None });
        assert_eq!(
            text(&m),
            "{\"event\":\"audit\",\"layer\":\"mount\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":8,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null}\n"
        );
    }

    /// PLUG-11・TASK-122.5: plugin 信頼検証レコードは reason を末尾に持つ（既存レイヤーの行は不変）。
    #[test]
    fn plug11_task122_5_encode_plugin_trust_has_reason() {
        let r = rec(
            9,
            AuditEvent::PluginTrust {
                path: AuditPath::new("/p/plugin"),
                reason: crate::audit_log::AuditReason::new("hash_mismatch"),
            },
        );
        assert_eq!(
            text(&r),
            "{\"event\":\"audit\",\"layer\":\"plugin_trust\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":9,\"syscall\":null,\"arch\":null,\"path\":\"/p/plugin\",\"path_truncated\":false,\"path_original_len\":9,\"reason\":\"hash_mismatch\"}\n"
        );
    }

    /// SEC-4・SUP-6・TASK-163 追補: exec 対象レコードはパスが null で reason を持つ。
    #[test]
    fn sec4_sup6_task163_encode_exec_target_has_reason_without_path() {
        let r = rec(
            11,
            AuditEvent::ExecTarget {
                reason: crate::audit_log::AuditReason::new("exec_target_cgroup_mismatch"),
            },
        );
        assert_eq!(
            text(&r),
            "{\"event\":\"audit\",\"layer\":\"exec_target\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":11,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"reason\":\"exec_target_cgroup_mismatch\"}\n"
        );
    }

    /// SEC-4・SUP-6・TASK-163 追補・#1595: entrypoint レコードはパスが null で reason を持つ。
    #[test]
    fn sec4_sup6_task163_encode_entrypoint_has_reason_without_path() {
        let r = rec(
            12,
            AuditEvent::Entrypoint {
                reason: crate::audit_log::AuditReason::new("entrypoint_is_runtime_binary"),
            },
        );
        assert_eq!(
            text(&r),
            "{\"event\":\"audit\",\"layer\":\"entrypoint\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":12,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"reason\":\"entrypoint_is_runtime_binary\"}\n"
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

    /// SEC-4・TASK-41.5.1: 失敗後も行頭 LF の要否は実際の末尾で決まる（末尾が LF なら空行を作らない）。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_task41_5_1_no_blank_line_when_tail_is_lf() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_dir("nolf");
        let path = dir.join("audit.log");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut w = AuditFileWriter::open(&path).unwrap();
        // 書き込み失敗（読み取り専用 fd）を経ても、別 fd 側の追記結果に空行が混ざらない。
        assert!(failing_writer().write_record(&sample()).is_err());
        w.write_record(&sample()).unwrap();
        w.write_record(&sample()).unwrap();
        let line = text(&sample());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{line}{line}")
        );
    }

    /// SEC-4・TASK-41.5.1: 末尾が LF でない既存ファイルを再オープンしても、新レコードは独立した行になる。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_task41_5_1_reopen_isolates_torn_tail() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_dir("torn");
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

    #[cfg(target_os = "linux")]
    fn fresh_dir(tag: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fandhe-auditw-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    /// SEC-4・TASK-41.5.1: 親ディレクトリが symlink なら拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_task41_5_1_rejects_symlinked_parent() {
        let dir = fresh_dir("symparent");
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = AuditFileWriter::open(&link.join("audit.log")).unwrap_err();
        assert_eq!(e.kind(), AuditWriteErrorKind::Open);
        assert!(!real.join("audit.log").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-4・TASK-41.5.1: group/other が書き込める親ディレクトリは拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_task41_5_1_rejects_world_writable_parent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_dir("wwparent");
        let parent = dir.join("p");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = AuditFileWriter::open(&parent.join("audit.log")).unwrap_err();
        assert_eq!(e.kind(), AuditWriteErrorKind::InsecureFile);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-4・TASK-41.5.1: 他パスへのハードリンクになっている既存ファイルは拒否し、内容を改変しない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_task41_5_1_rejects_hardlinked_file() {
        let dir = fresh_dir("hardlink");
        let secret = dir.join("secret");
        std::fs::write(&secret, b"top-secret\n").unwrap();
        std::fs::set_permissions(&secret, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .unwrap();
        let audit = dir.join("audit.log");
        std::fs::hard_link(&secret, &audit).unwrap();
        let e = AuditFileWriter::open(&audit).unwrap_err();
        assert_eq!(e.kind(), AuditWriteErrorKind::InsecureFile);
        assert_eq!(std::fs::read(&secret).unwrap(), b"top-secret\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-4・TASK-41.5.1: 既存の非通常ファイル（FIFO）は open せず NotRegularFile で拒否する。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_task41_5_1_rejects_fifo_without_opening() {
        let dir = fresh_dir("fifo");
        let fifo = dir.join("audit.fifo");
        // unsafe を避けるため mkfifo(1) で作る（coreutils。無ければテスト環境不備として失敗させる）。
        let st = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(st.success());
        let e = AuditFileWriter::open(&fifo).unwrap_err();
        assert_eq!(e.kind(), AuditWriteErrorKind::NotRegularFile);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TASK-41.5.1: 正当な非 UTF-8 ファイル名（Linux）でも開ける。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_task41_5_1_accepts_non_utf8_file_name() {
        use std::os::unix::ffi::OsStrExt;
        let dir = fresh_dir("nonutf8");
        let path = dir.join(std::ffi::OsStr::from_bytes(b"audit-\xff.log"));
        let mut w = AuditFileWriter::open(&path).unwrap();
        w.write_record(&sample()).unwrap();
        drop(w);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text(&sample()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ERR-4: ロック I/O 失敗はタイムアウトと区別され、Timeout コードにならない。
    #[test]
    fn err4_lock_failed_is_not_timeout() {
        let e = AuditWriteError::new(AuditWriteErrorKind::LockFailed);
        assert_eq!(e.error_code(), ErrorCode::Internal);
        assert_eq!(e.message(), "failed to acquire the audit log lock");
        let t = AuditWriteError::new(AuditWriteErrorKind::Lock);
        assert_eq!(t.error_code(), ErrorCode::Timeout);
    }

    /// SEC-4・TASK-41.5.1: 複数 writer の並行書き込みでも全行が完全な JSON 行になる。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_task41_5_1_concurrent_writers_do_not_interleave() {
        let dir = fresh_dir("concurrent");
        let path = dir.join("audit.log");
        let long = format!("/{}", "a".repeat(3000));
        let handles: Vec<_> = (0..4)
            .map(|t| {
                let path = path.clone();
                let long = long.clone();
                std::thread::spawn(move || {
                    let mut w = AuditFileWriter::open(&path).unwrap();
                    for _ in 0..25 {
                        let r = rec(
                            t + 1,
                            AuditEvent::Mount {
                                path: Some(AuditPath::new(&long)),
                            },
                        );
                        w.write_record(&r).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let got = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = got.lines().collect();
        assert_eq!(lines.len(), 100);
        for l in lines {
            assert!(
                l.starts_with("{\"event\":\"audit\"") && l.ends_with('}'),
                "{l}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
