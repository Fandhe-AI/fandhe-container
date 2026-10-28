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
//! - [`encode_json_line`] はワイヤースキーマの単一の定義点。#840。本体は非公開 DTO で、封筒（`event`）は共通ログ型 `logging::LogLine` が付ける（#3115・ERR-4）
//! - 全キー常在の固定スキーマ。値が無いものは `null`（`reason` だけは対象外の層で省略。`container_id` は常在で、段を持つ記録だけその後ろに `stage`。#3121）。`path` は lossy UTF-8 で、制御文字・改行・NUL は
//!   JSON エスケープされる（ログ注入対策: 生の LF は行末の 1 個だけ）
//! - [`AuditFileWriter::open`] は symlink・FIFO・他者所有・group/other 権限付きのファイルを拒否する。
//!   親ディレクトリも `/` から 1 要素ずつ `O_NOFOLLOW|O_DIRECTORY` で辿って fd で固定し、いずれかが
//!   symlink・非ディレクトリ・root でも実効 uid 所有でもない・group/other 書き込み可（sticky 付きの祖先は
//!   許容。直接の親は不可）なら拒否する。ファイルは固定した親 fd の `/proc/self/fd/N/<name>` 経由で開き、
//!   検証後の親の差し替え（TOCTOU）を防ぐ
//! - 書き込みは `flock`（排他）を `AUDIT_LOCK_TIMEOUT` を上限に取得してから 1 レコードずつ行う。複数の
//!   writer（同一プロセス内・別プロセス）が同じファイルを開いても、`write_all` の複数 write の間に他者の
//!   追記が割り込まず、行が混ざらない。ロック下で末尾が LF でなければ行頭 LF で破損行を隔離する
//! - 同一プロセス内の書き手は、`flock` を取る前にプロセス全体で 1 本の FIFO（`TurnQueue`）に並び、
//!   先頭の 1 者だけが `flock` をポーリングする。解放側は `flock` を手放してから次の待ち手へ順番を渡すため、
//!   解放直後に取り直す書き手が他のスレッドを飢えさせない（#1703）。プロセス間は従来どおり `flock` の
//!   ポーリングのみで、プロセス間の FIFO は保証しない（本番の `FileAuditSink` は 1 レコードごとに子プロセスで
//!   書くため、プロセス内の待ち行列は事実上空である）
//! - 部分書き込みで壊れた行は、次回書き込みの行頭に LF を付けて独立した行に隔離する（読み手は破損行を
//!   読み飛ばす）。失敗時の重複（主経路に部分書き込み＋フォールバックにも記録）は許容し、欠落は許容しない
//! - 非 Linux では symlink・所有者の信頼境界を検査できないため `open` は `Unimplemented` 相当の
//!   `Unsupported`（fail-closed）
//!
//! # 将来仕様
//!
//! 代替経路の実体は `kernel_audit` の `KernelAuditFallback`（主経路の失敗時にだけカーネル監査へ送る）。
//! 常時の二重記録（tee）によるクラッシュ・改ざん時の記録保持は未実装（REPAIR-3）。

use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::{AuditEvent, AuditRecord};
use crate::logging::{self, LogEvent, LogLine, LogLineErrorKind};
use crate::traits::ErrorCode;

/// 書き込みロック取得の待ち時間上限（REPAIR-5: 無期限に待たない）。
///
/// プロセス内の順番待ち（`TurnQueue`）と `flock` のポーリングを合わせた 1 本の期限として掛かる
/// （2 段それぞれに 5 秒ずつ許して最大 10 秒待つことはしない）。
const AUDIT_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// ロック取得のリトライ間隔。
const AUDIT_LOCK_RETRY: Duration = Duration::from_millis(5);

/// プロセス内の書き手を到着順に並べる待ち行列（#1703・REPAIR-5）。
///
/// `flock` のポーリング（5ms 間隔）だけでは、`unlock` 直後に次のレコードの `try_lock` を呼ぶ書き手が、
/// 眠っている他の書き手より常に先に取り直して飢えさせる。その結果、最後尾のスレッドの待ちが
/// 「残りレコード数 ×（`write_all` + `sync_data`）」まで伸び、`sync_data` が遅い環境で期限（5 秒）を超えて
/// `Lock` になっていた。先頭の 1 者だけが `flock` を取りに行き、解放後に次へ渡すことで取得を FIFO にする。
///
/// - 期限は呼び出し側が決めた 1 本の `deadline` を共有する。期限を過ぎた待ち手は自分のチケットを取り除いて
///   `Err` を返し、後続を塞がない（呼び出し側は `Lock` として代替経路へ回す）
/// - `Mutex` が poison されても `into_inner` で続行する。臨界区間は `VecDeque` の push・retain・先頭参照だけで、
///   途中で panic しても不変条件が崩れないため。`LockFailed` に倒すと以後の書き込みがすべて代替経路へ回る
/// - fork 安全性: `FileAuditSink` は単一スレッドの親から子を fork し、親はその時点で `write_record` の中に
///   いない。子は空の待ち行列を引き継ぎ、他スレッドに握られた `Mutex` を引き継がない
/// - 既知の限界（REPAIR-3）: 待ち行列はプロセスに 1 本で、別ファイルへの書き手も直列化する。あるファイルの
///   `sync_data` が止まると、同じプロセスの別ファイルの書き手も期限まで待つ。本番は 1 本の `@audit.log` にだけ
///   書く。`(dev, ino)` ごとの分離は将来課題
struct TurnQueue {
    waiting: Mutex<VecDeque<u64>>,
    changed: Condvar,
    next_ticket: AtomicU64,
}

/// 本番の書き込み経路が共有するプロセス全体の待ち行列。
static AUDIT_WRITE_QUEUE: TurnQueue = TurnQueue::new();

/// `TurnQueue` のチケットを保持している間だけ生きるガード。drop で自分のチケットを取り除き次へ通知する。
struct TurnGuard<'q> {
    queue: &'q TurnQueue,
    ticket: u64,
}

impl TurnQueue {
    const fn new() -> Self {
        Self {
            waiting: Mutex::new(VecDeque::new()),
            changed: Condvar::new(),
            next_ticket: AtomicU64::new(0),
        }
    }

    fn lock_waiting(&self) -> MutexGuard<'_, VecDeque<u64>> {
        self.waiting.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// 末尾に並び、先頭になるまで `deadline` を上限に待つ。期限切れは `Err(())`（チケットは取り除き済み）。
    fn enter(&self, deadline: Instant) -> Result<TurnGuard<'_>, ()> {
        let ticket = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        self.lock_waiting().push_back(ticket);
        // push 後に生成する。以降の return / panic でも drop が必ずチケットを取り除く。
        let guard = TurnGuard {
            queue: self,
            ticket,
        };
        let mut waiting = self.lock_waiting();
        loop {
            // 先頭であっても期限切れなら通さない（期限超過後に起床して保持者の解放を見た場合も拒否。REPAIR-5）。
            let now = Instant::now();
            if now >= deadline {
                // guard の drop が同じ Mutex を取るため、先に手放す。
                drop(waiting);
                return Err(());
            }
            if waiting.front() == Some(&ticket) {
                drop(waiting);
                return Ok(guard);
            }
            waiting = self
                .changed
                .wait_timeout(waiting, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// テスト用: 待ち行列の長さ（保持者を含む）。
    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock_waiting().len()
    }
}

impl Drop for TurnGuard<'_> {
    fn drop(&mut self) {
        self.queue.lock_waiting().retain(|t| *t != self.ticket);
        self.queue.changed.notify_all();
    }
}

/// 1 行（LF 含む）のバイト長上限。パス 4096 バイトの JSON エスケープ最大 6 倍＋固定部に収まる値。
///
/// 値の定義元は [`logging::MAX_LOG_LINE_BYTES`] に一本化した（#3115・ERR-4）。共通ログ型は LF を除く
/// 本体をこの値で縛り、監査は加えて LF 込みの長さを同じ値で縛る。そのため監査の実効上限は共通の上限より
/// 1 バイト厳しい（既存の監査の上限を緩めないため）。
pub const AUDIT_LINE_MAX_BYTES: usize = logging::MAX_LOG_LINE_BYTES;

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
    /// レコードをエンコードできない（共通ログ型の `Encode`: オブジェクトでない本体、LF / CR の防御検査）。
    Encode,
    /// エンコード結果が [`AUDIT_LINE_MAX_BYTES`] を超えた（共通ログ型の `TooLong` と、LF 込みの後段検査の両方）。
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
    /// 主経路を隔離した子プロセスが、継承した fd（3 以上）を閉じられなかった（`close_range(2)` が無い Linux 5.11
    /// 未満のカーネル等）。子は I/O せずに終わり、代替経路へ進む（fail-closed。`FileAuditSink`。fork 不能の
    /// `IsolationUnavailable` と運用で見分けるための別種別）。
    IsolationFdsNotClosed,
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
            Self::IsolationFdsNotClosed => "isolation_fds_not_closed",
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
            AuditWriteErrorKind::IsolationUnavailable
            | AuditWriteErrorKind::IsolationFdsNotClosed => ErrorCode::Unavailable,
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
            AuditWriteErrorKind::IsolationFdsNotClosed => {
                "isolated audit log writer could not close inherited file descriptors"
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

/// ワイヤー表現（非公開 DTO。`LogLine` の本体）。キー順はフィールド宣言順で、先頭の `event` は封筒が付ける。
/// 予約キー `level` / `event` を持たない（持つと重複キーになる。試験で検出する）。
#[derive(Serialize)]
struct AuditLineDto<'a> {
    layer: &'static str,
    ts_sec: u64,
    ts_nsec: u32,
    /// 記録を組み立てたプロセスの PID（違反したプロセスや pid1 とは限らない。層ごとの意味は
    /// `AuditRecord` の doc）。コンテナとの対応は `container_id` で取る。
    pid: u32,
    syscall: Option<u32>,
    /// seccomp のみ: syscall 番号を解釈するための `AUDIT_ARCH_*`（番号はアーキ相対のため併記）。
    arch: Option<u32>,
    path: Option<String>,
    path_truncated: Option<bool>,
    path_original_len: Option<usize>,
    /// 理由を持つレイヤー（plugin 信頼検証・exec 対象・entrypoint、理由つきの mount）のみ: 拒否理由トークン（他レイヤーでは出力しない＝既存行は不変）。
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    /// `exit_signal` 層のみ: 終了シグナル番号（他レイヤーでは出力しない＝既存行は不変。#2004）。
    #[serde(skip_serializing_if = "Option::is_none")]
    signal: Option<u8>,
    /// `exit_signal` 層のみ: 終了したプロセスの PID（回収した側の PID namespace の値。他レイヤーでは出力しない）。
    #[serde(skip_serializing_if = "Option::is_none")]
    target_pid: Option<u32>,
    /// `audit_coverage` 層のみ: 縮退した seccomp KILL 側の理由トークン（他レイヤーでは出力しない。#2027）。
    #[serde(skip_serializing_if = "Option::is_none")]
    seccomp_kill_reason: Option<&'static str>,
    /// `audit_coverage` 層のみ: 縮退した Landlock 側の理由トークン（他レイヤーでは出力しない。#2027）。
    #[serde(skip_serializing_if = "Option::is_none")]
    landlock_reason: Option<&'static str>,
    /// 検証済みの `ContainerId`（`[A-Za-z0-9._-]`・255 バイト以下）の生の値。不明なら `null`（省略しない）。
    /// 常在で、段を持たない記録では末尾（既存キーの値と順序は変えない。#1618）。
    container_id: Option<&'a str>,
    /// 拒否した段（`IsolationStage` と同じ固定語彙）。段を持つ記録のみ、`container_id` の後ろに出す
    /// （他は省略＝既存行は不変。#3121）。
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<&'static str>,
}

/// 監査行の `event` 値。コンパイル時に検証する（実行時に panic する経路を作らない）。
const AUDIT_EVENT: LogEvent = match LogEvent::from_static("audit") {
    Some(e) => e,
    None => panic!("invalid audit log event name"),
};

/// 本体を共通ログ型（level なし）で 1 行（LF 終端）にする。
///
/// 共通ログ型の `TooLong` / `Encode` を [`AuditWriteErrorKind`] へ写し、さらに LF 込みの長さを
/// [`AUDIT_LINE_MAX_BYTES`] で縛る（共通ログ型は LF を除く本体だけを縛るため、1 バイト厳しい）。
fn encode_audit_body<F: Serialize>(body: &F) -> Result<Vec<u8>, AuditWriteError> {
    let line = logging::encode_json_line(&LogLine::new(AUDIT_EVENT, body)).map_err(|e| {
        AuditWriteError::new(match e.kind() {
            LogLineErrorKind::TooLong => AuditWriteErrorKind::LineTooLong,
            _ => AuditWriteErrorKind::Encode,
        })
    })?;
    if line.len() > AUDIT_LINE_MAX_BYTES {
        return Err(AuditWriteError::new(AuditWriteErrorKind::LineTooLong));
    }
    Ok(line)
}

/// レコードを JSON 1 行（LF 終端）へエンコードする。
///
/// 非 UTF-8 のパスは lossy 変換する（`Serialize for Path` は非 UTF-8 でエラーになるため使わない）。
/// 出力は共通ログ型 `LogLine` 経由で、移行前とバイト列が同じ（#3115・ERR-4）。
pub fn encode_json_line(record: &AuditRecord) -> Result<Vec<u8>, AuditWriteError> {
    encode_audit_body(&audit_line_dto(record))
}

/// レコードをワイヤー表現（`LogLine` の本体）へ写す。
fn audit_line_dto(record: &AuditRecord) -> AuditLineDto<'_> {
    let (syscall, path) = match record.event() {
        AuditEvent::Seccomp { syscall, .. } => (Some(syscall.get()), None),
        AuditEvent::Landlock { path, syscall, .. } => (syscall.map(|s| s.get()), Some(path)),
        AuditEvent::Mount { path, .. } => (None, path.as_ref()),
        AuditEvent::PluginTrust { path, .. } | AuditEvent::PluginPeer { path, .. } => {
            (None, Some(path))
        }
        AuditEvent::ExecTarget { .. }
        | AuditEvent::Entrypoint { .. }
        | AuditEvent::PastaVerify { .. }
        | AuditEvent::ControlPeer { .. }
        | AuditEvent::ExitSignal { .. }
        | AuditEvent::AuditCoverageDegraded { .. } => (None, None),
    };
    let ts = record.timestamp().as_unix_duration();
    AuditLineDto {
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
        signal: record.exit_signal().map(|s| s.get()),
        target_pid: record.target_pid().map(|p| p.get()),
        seccomp_kill_reason: record
            .coverage_reasons()
            .and_then(|(s, _)| s)
            .map(|r| r.as_str()),
        landlock_reason: record
            .coverage_reasons()
            .and_then(|(_, l)| l)
            .map(|r| r.as_str()),
        container_id: record.container_id().map(|c| c.as_str()),
        stage: record.stage().map(|s| s.as_str()),
    }
}

/// 追記専用の監査ログファイル（主経路）。
#[derive(Debug)]
pub struct AuditFileWriter {
    file: File,
    /// 開いたときの親ディレクトリ(書き込み可能性の確認用の一時ファイルを同じ FS に作るため)。
    /// 検査なしで包んだ試験用の writer では `None`(確認は fail-closed で `Write`)。
    dir: Option<std::path::PathBuf>,
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
        Self { file, dir: None }
    }

    /// テスト用: 検査なしで `File` と確認用の親ディレクトリを包む。
    #[cfg(all(test, unix))]
    pub(crate) fn from_file_unchecked_in(file: File, dir: std::path::PathBuf) -> Self {
        Self {
            file,
            dir: Some(dir),
        }
    }

    /// 1 レコードを排他ロック下で `write_all` し、`sync_data` まで行う。
    ///
    /// 失敗時は panic せず `Err` を返す。呼び出し側は [`write_with_fallback`] で代替経路へ回す。
    pub fn write_record(&mut self, record: &AuditRecord) -> Result<(), AuditWriteError> {
        let line = encode_json_line(record)?;
        // `_turn` は `flock` の解放より後に drop される（宣言順の逆）。先に flock を手放してから次の待ち手へ
        // 順番を渡すことで、受け渡しの隙間に他者の書き込みが割り込んでも行は混ざらない。
        let _turn = self.lock_exclusive(&AUDIT_WRITE_QUEUE, Instant::now() + AUDIT_LOCK_TIMEOUT)?;
        let result = self.write_locked(&line);
        // 解放失敗は致命的ではない（fd を閉じれば解放される）。結果は書き込みの成否で決める。
        let _ = self.file.unlock();
        result
    }

    /// 本番の記録経路と同じ手順（排他 `flock` の取得 → 実バイトの書き込み → `sync_data`）が通るかを確かめる
    /// （起動前の記録経路の確認。SEC-4・REPAIR-5・#2027）。
    ///
    /// 別プロセスが `flock` を保持していれば `AUDIT_LOCK_TIMEOUT` で `Lock` になる。追記・永続化できない保存先
    /// （読み取り専用・満杯〔ENOSPC / EDQUOT〕など）は、**共有ログには一切書かず**、同じディレクトリ(同じ FS)に
    /// 作った一時ファイルへ 1 バイト書いて `sync_data` することで検出し、`Write` / `Sync` にする。一時ファイルは
    /// 作成直後・書き込み前に unlink するため、確認の途中で子が SIGKILL されても残骸は残らない。共有ログを巻き戻す
    /// 必要が無く、`flock` を取らない追尾型の読み手にも確認用のバイトは見えない（SEC-4・REPAIR-5）。
    pub fn probe_append(&mut self) -> Result<(), AuditWriteError> {
        self.probe_append_with(&AUDIT_WRITE_QUEUE, AUDIT_LOCK_TIMEOUT)
    }

    /// [`Self::probe_append`] の本体(順番待ちの列と `flock` の待ち上限を差し替えられる。単体試験が共有の列を塞がないため)。
    fn probe_append_with(
        &mut self,
        queue: &TurnQueue,
        timeout: Duration,
    ) -> Result<(), AuditWriteError> {
        let _turn = self.lock_exclusive(queue, Instant::now() + timeout)?;
        let result = self.check_fsize_room().and_then(|()| match &self.dir {
            Some(dir) => probe_scratch_write(dir),
            None => Err(AuditWriteError::new(AuditWriteErrorKind::Write)),
        });
        let _ = self.file.unlock();
        result
    }

    /// 既存ログに 1 レコード分の追記余地があるか、継承した `RLIMIT_FSIZE` の soft と照合する
    /// (一時ファイルの書き込みでは、ログ固有の上限到達を検出できないため。SEC-4・#2027)。読めなければ `Write`。
    #[cfg(target_os = "linux")]
    fn check_fsize_room(&self) -> Result<(), AuditWriteError> {
        let write_err = || AuditWriteError::new(AuditWriteErrorKind::Write);
        let (soft, _hard) = crate::sys::get_rlimit_self(crate::rlimits::RlimitKind::Fsize)
            .map_err(|_| write_err())?;
        let len = self.file.metadata().map_err(|_| write_err())?.len();
        if fits_fsize_limit(len, soft) {
            Ok(())
        } else {
            Err(write_err())
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn check_fsize_room(&self) -> Result<(), AuditWriteError> {
        Ok(())
    }

    /// プロセス内の順番待ち → `flock` のポーリングの順に、共通の `deadline` までに排他を取る。
    fn lock_exclusive<'q>(
        &self,
        queue: &'q TurnQueue,
        deadline: Instant,
    ) -> Result<TurnGuard<'q>, AuditWriteError> {
        let turn = queue
            .enter(deadline)
            .map_err(|()| AuditWriteError::new(AuditWriteErrorKind::Lock))?;
        loop {
            // flock を試す前に期限を確認する（期限切れでファイル書き込みへ進ませない。REPAIR-5）。
            if Instant::now() >= deadline {
                return Err(AuditWriteError::new(AuditWriteErrorKind::Lock));
            }
            match self.file.try_lock() {
                Ok(()) => {
                    // 取得直後にも確認し、期限切れなら解放して拒否する。
                    if Instant::now() >= deadline {
                        let _ = self.file.unlock();
                        return Err(AuditWriteError::new(AuditWriteErrorKind::Lock));
                    }
                    return Ok(turn);
                }
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

/// `dir` の信頼検査済み fd 配下に **名前を持たない** 一時ファイル(`O_TMPFILE`)を作り、1 バイトを書いて
/// `sync_data` する(共有ログに触れない書き込み可能性の確認。[`AuditFileWriter::probe_append`])。
///
/// 名前が一度も付かないため、確認の途中で子が SIGKILL されても残骸は残らない(作成と unlink の間の窓が無い)。
/// `O_TMPFILE` に対応しない FS・カーネル(`EOPNOTSUPP`・`EISDIR`・`EINVAL`)では確認できないとして
/// `Unsupported` で失敗する(名前付きファイルへ落とすと残骸の窓が戻るため。fail-closed)。
#[cfg(target_os = "linux")]
fn probe_scratch_write(dir: &Path) -> Result<(), AuditWriteError> {
    let mut scratch = open_unnamed_scratch(dir)?;
    scratch
        .write_all(b"\n")
        .map_err(|_| AuditWriteError::new(AuditWriteErrorKind::Write))?;
    scratch
        .sync_data()
        .map_err(|_| AuditWriteError::new(AuditWriteErrorKind::Sync))
}

/// `dir`(信頼検査つきで辿る)の FS に無名の一時ファイルを作って返す。
#[cfg(target_os = "linux")]
fn open_unnamed_scratch(dir: &Path) -> Result<File, AuditWriteError> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let flag = crate::sys::tmpfile_open_flag()
        .ok_or_else(|| AuditWriteError::new(AuditWriteErrorKind::Unsupported))?;
    let parent_fd = open_trusted_parent(dir)?;
    // 最終要素は検査済みの親ディレクトリ自身(`/proc/self/fd/N` は magic link で、O_NOFOLLOW は付けない。
    // `O_TMPFILE` は無名ファイルを作るだけで、既存ファイルを開かない)。
    let via_fd = std::path::PathBuf::from(format!("/proc/self/fd/{}", parent_fd.as_raw_fd()));
    OpenOptions::new()
        .write(true)
        .mode(0o600)
        .custom_flags(flag)
        .open(&via_fd)
        .map_err(|e| {
            // EOPNOTSUPP(95)・EISDIR(21: O_TMPFILE を知らない古いカーネル)・EINVAL(22)。
            let unsupported = matches!(e.raw_os_error(), Some(95 | 21 | 22));
            AuditWriteError::new(if unsupported {
                AuditWriteErrorKind::Unsupported
            } else {
                AuditWriteErrorKind::Write
            })
        })
}

/// 既存ログの長さ `len` に最大 1 レコード(先頭の LF を含む [`AUDIT_LINE_MAX_BYTES`] + 1)を足しても、継承した
/// ファイルサイズ制限 `soft`(`RLIMIT_FSIZE` の soft。`u64::MAX` は無制限)に収まるか。
/// 収まらなければ実際の追記は `EFBIG`(または `SIGXFSZ`)になる(SEC-4・#2027)。
#[cfg(target_os = "linux")]
fn fits_fsize_limit(len: u64, soft: u64) -> bool {
    if soft == u64::MAX {
        return true;
    }
    let record = u64::try_from(AUDIT_LINE_MAX_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    len.saturating_add(record) <= soft
}

#[cfg(not(target_os = "linux"))]
fn probe_scratch_write(_dir: &Path) -> Result<(), AuditWriteError> {
    Err(AuditWriteError::new(AuditWriteErrorKind::Unsupported))
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
    Ok(AuditFileWriter {
        file,
        dir: Some(parent.to_path_buf()),
    })
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

    /// [`Self::record_fallback`] の絶対期限つき版(REPAIR-5・SEC-4。`AuditSink::record_until` から呼ぶ)。
    ///
    /// 既定は `deadline` を見ずに委譲する。応答を待つ実装は、待ちを `deadline` までに絞るよう上書きすること。
    fn record_fallback_until(
        &mut self,
        record: &AuditRecord,
        primary: &AuditWriteError,
        _deadline: std::time::Instant,
    ) -> Result<(), AuditWriteError> {
        self.record_fallback(record, primary)
    }
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
    /// 出力は共通ログ型 `LogLine` 経由で、移行前の `writeln!` とバイト列が同じ（#3209・ERR-4）。
    /// 書き込みは `write_all` 1 回で、`writeln!` のように断片に分かれない。
    pub fn write_json_line(&self, out: &mut dyn Write) -> std::io::Result<()> {
        let body = AuditWriteFailureDto {
            code: self.error_code().as_str(),
            primary: self.primary.kind().as_str(),
            primary_code: self.primary.error_code().as_str(),
            fallback: self.fallback.kind().as_str(),
            fallback_code: self.fallback.error_code().as_str(),
        };
        logging::write_json_line(out, &LogLine::new(AUDIT_WRITE_FAILURE_EVENT, &body))
            .map_err(|e| std::io::Error::other(e.message()))
    }
}

/// `audit_write_failure` 行の本体（非公開 DTO。`LogLine` の本体）。キー順はフィールド宣言順で、
/// 値はすべて固定トークン。予約キー `level` / `event` を持たない（試験で検出する）。
#[derive(Serialize)]
struct AuditWriteFailureDto {
    code: &'static str,
    primary: &'static str,
    primary_code: &'static str,
    fallback: &'static str,
    fallback_code: &'static str,
}

/// 両経路失敗行の `event` 値。コンパイル時に検証する（実行時に panic する経路を作らない）。
const AUDIT_WRITE_FAILURE_EVENT: LogEvent = match LogEvent::from_static("audit_write_failure") {
    Some(e) => e,
    None => panic!("invalid audit_write_failure log event name"),
};

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
    /// SEC-4・#2027: 別の open file description が排他 `flock` を保持していれば `probe_append` は `Lock` で失敗し、
    /// 解放後は監査ログへ 1 バイトも書かずに成功する(open できるだけでは記録経路の確認にならない)。
    #[cfg(unix)]
    #[test]
    fn sec4_2027_probe_append_fails_while_locked_elsewhere() {
        let dir = std::env::temp_dir().join(format!("fc-probe-append-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 確認用の一時ファイルは信頼検査済みの親に作る(umask に依らず 0700 にする)。
        std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        let path = dir.join("audit.log");
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .unwrap();
        let queue = TurnQueue::new();
        let holder = file.try_clone().unwrap();
        // 別の open file description(`open` し直す)で保持する。
        let other = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        other.lock().unwrap();
        let mut writer = AuditFileWriter::from_file_unchecked_in(holder, dir.clone());
        let e = writer
            .probe_append_with(&queue, Duration::from_millis(200))
            .unwrap_err();
        assert_eq!(e.kind(), AuditWriteErrorKind::Lock);
        drop(other);
        // 並行する他の試験の fork が fd の複製を持つ間は解放されないため、解放後は長めに待つ。
        let released = writer.probe_append_with(&queue, Duration::from_secs(5));
        #[cfg(target_os = "linux")]
        {
            released.unwrap();
        }
        // Linux 以外では確認用の一時ファイル書き込みを実装しておらず、fail-closed で `Unsupported` を返す。
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(
                released.unwrap_err().kind(),
                AuditWriteErrorKind::Unsupported
            );
        }
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        drop(file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-4・#2027: 継承したファイルサイズ制限に 1 レコード分の余地が無ければ失敗し、あれば(無制限を含め)通る。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_2027_fsize_limit_is_checked_against_existing_log_length() {
        let record = AUDIT_LINE_MAX_BYTES as u64 + 1;
        assert!(fits_fsize_limit(0, u64::MAX));
        assert!(fits_fsize_limit(u64::MAX - 1, u64::MAX));
        assert!(fits_fsize_limit(100, 100 + record));
        assert!(!fits_fsize_limit(101, 100 + record));
        assert!(!fits_fsize_limit(0, record - 1));
        assert!(!fits_fsize_limit(u64::MAX, 1 << 40));
    }

    /// SEC-4・#2027: `probe_append` は実際の `RLIMIT_FSIZE` の soft を読んで照合する(現在値の下で空のログは通る)。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_2027_probe_reads_inherited_fsize_limit() {
        let (soft, _) = crate::sys::get_rlimit_self(crate::rlimits::RlimitKind::Fsize).unwrap();
        let dir = std::env::temp_dir().join(format!("fc-probe-fsize-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut w = AuditFileWriter::open(&dir.join("audit.log")).unwrap();
        // 現在の制限で、空のログには余地がある(無制限または十分大きい)ことだけを確かめる。
        assert_eq!(w.check_fsize_room().is_ok(), fits_fsize_limit(0, soft));
        w.probe_append().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-4・REPAIR-5・#2027: 書き込み確認の一時ファイルは名前を持たない(`O_TMPFILE`)。開いている間もディレクトリには
    /// 何も現れず、確認の途中で SIGKILL されても残骸の窓が無い。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_repair5_probe_scratch_is_unnamed_while_open() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fc-probe-tmpfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        match open_unnamed_scratch(&dir) {
            Ok(mut scratch) => {
                scratch.write_all(b"\n").unwrap();
                assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
            }
            // この FS が O_TMPFILE に対応しない環境では fail-closed の `Unsupported` になる。
            Err(e) => assert_eq!(e.kind(), AuditWriteErrorKind::Unsupported),
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SEC-4・REPAIR-5・#2027: 確認(`probe_append`)は共有ログを巻き戻さない。確認の前後で長さは変わらず(減らず)、
    /// 続けて書いた記録は確認の前の末尾にそのまま連なる。同じディレクトリに一時ファイルの残骸も残らない。
    #[cfg(target_os = "linux")]
    #[test]
    fn sec4_repair5_probe_never_rewinds_shared_log() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("fc-probe-mono-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("audit.log");
        let mut w = AuditFileWriter::open(&path).unwrap();
        let r = rec(
            9,
            AuditEvent::Mount {
                path: None,
                reason: None,
            },
        );
        let line_len = encode_json_line(&r).unwrap().len() as u64;
        w.write_record(&r).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), line_len);
        w.probe_append().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), line_len);
        w.write_record(&r).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), line_len * 2);
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec!["audit.log".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
            "{\"event\":\"audit\",\"layer\":\"seccomp\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":42,\"syscall\":272,\"arch\":3221225534,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"container_id\":null}\n"
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
            "{\"event\":\"audit\",\"layer\":\"landlock\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":7,\"syscall\":null,\"arch\":null,\"path\":\"/etc/shadow\",\"path_truncated\":false,\"path_original_len\":11,\"container_id\":null}\n"
        );
        let m = rec(
            8,
            AuditEvent::Mount {
                path: None,
                reason: None,
            },
        );
        assert_eq!(
            text(&m),
            "{\"event\":\"audit\",\"layer\":\"mount\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":8,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"container_id\":null}\n"
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
            "{\"event\":\"audit\",\"layer\":\"plugin_trust\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":9,\"syscall\":null,\"arch\":null,\"path\":\"/p/plugin\",\"path_truncated\":false,\"path_original_len\":9,\"reason\":\"hash_mismatch\",\"container_id\":null}\n"
        );
    }

    /// SEC-4・ESC-06・#2004: exit_signal レコードは signal と target_pid を持ち、syscall・arch は null。
    #[test]
    fn sec4_2004_encode_exit_signal_has_signal_and_target_pid_without_syscall() {
        let r = rec(
            9,
            AuditEvent::ExitSignal {
                signal: crate::audit_log::AuditSignal::new(31).unwrap(),
                target_pid: crate::audit_log::AuditPid::new(1234).unwrap(),
            },
        )
        .with_container_id(crate::traits::ContainerId::new("c1").unwrap());
        assert_eq!(
            text(&r),
            "{\"event\":\"audit\",\"layer\":\"exit_signal\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":9,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"signal\":31,\"target_pid\":1234,\"container_id\":\"c1\"}\n"
        );
    }

    /// SEC-4・#2027: audit_coverage レコードは縮退した層の理由だけを持ち、縮退していない層のキーは出さない。
    #[test]
    fn sec4_2027_encode_audit_coverage_has_layer_reasons() {
        let r = rec(
            12,
            AuditEvent::AuditCoverageDegraded {
                seccomp_kill: None,
                landlock: Some(crate::audit_log::AuditReason::new(
                    "landlock_audit_abi_too_old",
                )),
            },
        );
        assert_eq!(
            text(&r),
            "{\"event\":\"audit\",\"layer\":\"audit_coverage\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":12,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"landlock_reason\":\"landlock_audit_abi_too_old\",\"container_id\":null}\n"
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
            "{\"event\":\"audit\",\"layer\":\"exec_target\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":11,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"reason\":\"exec_target_cgroup_mismatch\",\"container_id\":null}\n"
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
            "{\"event\":\"audit\",\"layer\":\"entrypoint\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":12,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"reason\":\"entrypoint_is_runtime_binary\",\"container_id\":null}\n"
        );
    }

    fn cid(v: &str) -> crate::traits::ContainerId {
        crate::traits::ContainerId::new(v).unwrap()
    }

    /// SEC-4・SUP-6・REPAIR-2・#1618: exec_target の行は末尾に検証済みのコンテナ ID を持つ（行まるごと一致）。
    #[test]
    fn sec4_sup6_1618_encode_exec_target_with_container_id() {
        let r = rec(
            11,
            AuditEvent::ExecTarget {
                reason: crate::audit_log::AuditReason::new("exec_target_cgroup_mismatch"),
            },
        )
        .with_container_id(cid("c1"));
        assert_eq!(
            text(&r),
            "{\"event\":\"audit\",\"layer\":\"exec_target\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":11,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"reason\":\"exec_target_cgroup_mismatch\",\"container_id\":\"c1\"}\n"
        );
    }

    /// SEC-4・#1618: mount の行はパスあり・なしの両方で末尾が container_id になる。
    #[test]
    fn sec4_1618_encode_mount_with_container_id() {
        let with_path = rec(
            8,
            AuditEvent::Mount {
                path: Some(AuditPath::new("/proc/sys")),
                reason: None,
            },
        )
        .with_container_id(cid("c1"));
        assert!(
            text(&with_path).ends_with("\"path_original_len\":9,\"container_id\":\"c1\"}\n"),
            "{}",
            text(&with_path)
        );
        let no_path = rec(
            8,
            AuditEvent::Mount {
                path: None,
                reason: None,
            },
        )
        .with_container_id(cid("c1"));
        assert!(
            text(&no_path).ends_with("\"path_original_len\":null,\"container_id\":\"c1\"}\n"),
            "{}",
            text(&no_path)
        );
    }

    /// SEC-4・ERR-4・#3121: 段なしの記録は全層で `"stage"` キーを持たず、末尾は従来どおり `container_id`。
    #[test]
    fn sec4_3121_records_without_stage_keep_bytes() {
        let events = [
            AuditEvent::Seccomp {
                syscall: AuditSyscallNr::new(272).unwrap(),
                arch: AuditSyscallArch::from_raw(3221225534),
            },
            AuditEvent::Landlock {
                path: AuditPath::new("/etc/shadow"),
                syscall: None,
            },
            AuditEvent::Mount {
                path: None,
                reason: Some(crate::audit_log::AuditReason::new(
                    "readonly_path_apply_failed",
                )),
            },
            AuditEvent::PluginTrust {
                path: AuditPath::new("/p/plugin"),
                reason: crate::audit_log::AuditReason::new("hash_mismatch"),
            },
            AuditEvent::ExecTarget {
                reason: crate::audit_log::AuditReason::new("exec_target_cgroup_mismatch"),
            },
            AuditEvent::Entrypoint {
                reason: crate::audit_log::AuditReason::new("entrypoint_is_runtime_binary"),
            },
        ];
        for e in events {
            let s = text(&rec(3, e.clone()));
            assert!(!s.contains("\"stage\""), "{s}");
            assert!(s.ends_with(",\"container_id\":null}\n"), "{s}");
            let s = text(&rec(3, e).with_container_id(cid("c1")));
            assert!(!s.contains("\"stage\""), "{s}");
            assert!(s.ends_with(",\"container_id\":\"c1\"}\n"), "{s}");
        }
    }

    /// SEC-4・ERR-4・#3121: 段つきの 1 行全体の厳密バイト列。`stage` は `container_id` の後ろ（ID が null でも）。
    #[test]
    fn sec4_3121_encode_mount_with_stage_is_exact() {
        let ev = || AuditEvent::Mount {
            path: None,
            reason: Some(crate::audit_log::AuditReason::new(
                "readonly_path_apply_failed",
            )),
        };
        let stage = crate::audit_log::AuditStage::new("mount_readonly_paths");
        let with_id = rec(8, ev()).with_container_id(cid("c1")).with_stage(stage);
        assert_eq!(
            text(&with_id),
            "{\"event\":\"audit\",\"layer\":\"mount\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":8,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"reason\":\"readonly_path_apply_failed\",\"container_id\":\"c1\",\"stage\":\"mount_readonly_paths\"}\n"
        );
        let no_id = rec(8, ev()).with_stage(stage);
        assert!(
            text(&no_id).ends_with(",\"container_id\":null,\"stage\":\"mount_readonly_paths\"}\n"),
            "{}",
            text(&no_id)
        );
    }

    /// SEC-4・ERR-4・#3121: 最悪ケース（制御文字だけの 4096 バイトのパス・最長の理由・255 バイトの ID・段）でも 1 行の上限に収まる。
    #[test]
    fn sec4_3121_stage_worst_case_line_fits() {
        let id = "a".repeat(255);
        let r = rec(
            2_000_000_000,
            AuditEvent::Mount {
                path: Some(AuditPath::new(&"\u{1}".repeat(4096))),
                reason: Some(crate::audit_log::AuditReason::new(
                    "rootfs_symlink_or_not_directory",
                )),
            },
        )
        .with_container_id(cid(&id))
        .with_stage(crate::audit_log::AuditStage::new("mount_readonly_paths"));
        let line = encode_json_line(&r).expect("worst case encodes");
        assert!(line.len() <= AUDIT_LINE_MAX_BYTES, "{}", line.len());
        assert!(String::from_utf8(line).unwrap().ends_with(&format!(
            ",\"container_id\":\"{id}\",\"stage\":\"mount_readonly_paths\"}}\n"
        )));
    }

    /// SEC-4・#1618: ID が無い記録は全層で `"container_id":null` を末尾に持つ。
    #[test]
    fn sec4_1618_encode_without_container_id_is_null() {
        let events = [
            AuditEvent::Seccomp {
                syscall: AuditSyscallNr::new(272).unwrap(),
                arch: AuditSyscallArch::from_raw(3221225534),
            },
            AuditEvent::Landlock {
                path: AuditPath::new("/etc/shadow"),
                syscall: None,
            },
            AuditEvent::Mount {
                path: None,
                reason: None,
            },
            AuditEvent::PluginTrust {
                path: AuditPath::new("/p/plugin"),
                reason: crate::audit_log::AuditReason::new("hash_mismatch"),
            },
            AuditEvent::ExecTarget {
                reason: crate::audit_log::AuditReason::new("exec_target_cgroup_mismatch"),
            },
            AuditEvent::Entrypoint {
                reason: crate::audit_log::AuditReason::new("entrypoint_is_runtime_binary"),
            },
        ];
        for e in events {
            let s = text(&rec(3, e));
            assert!(s.ends_with(",\"container_id\":null}\n"), "{s}");
        }
    }

    /// SEC-4・PLUG-12・#2484: plugin_peer の 1 行は層・path・理由トークンを持ち、コンテナ ID は null。
    #[test]
    fn sec4_2484_encode_plugin_peer_is_exact() {
        let r = rec(
            9,
            crate::audit_log::PluginPeerRejection::PeerUidMismatch
                .audit_event(std::path::Path::new("/run/p/cri.sock")),
        );
        assert_eq!(
            text(&r),
            "{\"event\":\"audit\",\"layer\":\"plugin_peer\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":9,\"syscall\":null,\"arch\":null,\"path\":\"/run/p/cri.sock\",\"path_truncated\":false,\"path_original_len\":15,\"reason\":\"plugin_peer_uid_mismatch\",\"container_id\":null}\n"
        );
    }

    /// SEC-4・#1701: 理由つきの mount の 1 行（パスなし／パスあり）の具体値。`reason` は `container_id` の直前。
    #[test]
    fn sec4_1701_encode_mount_with_reason_is_exact() {
        let no_path = rec(
            8,
            AuditEvent::Mount {
                path: None,
                reason: Some(crate::audit_log::AuditReason::new("rootfs_is_host_root")),
            },
        )
        .with_container_id(cid("c1"));
        assert_eq!(
            text(&no_path),
            "{\"event\":\"audit\",\"layer\":\"mount\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":8,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"reason\":\"rootfs_is_host_root\",\"container_id\":\"c1\"}\n"
        );
        let with_path = rec(
            8,
            AuditEvent::Mount {
                path: Some(AuditPath::new("/proc/sys")),
                reason: Some(crate::audit_log::AuditReason::new("target_on_shared_mount")),
            },
        )
        .with_container_id(cid("c1"));
        let t = text(&with_path);
        assert!(t.contains("\"path\":\"/proc/sys\""), "{t}");
        assert!(
            t.ends_with("\"reason\":\"target_on_shared_mount\",\"container_id\":\"c1\"}\n"),
            "{t}"
        );
    }

    /// SEC-4・#1701: 理由つきの mount の最悪ケースでも 1 行の上限に収まる。
    #[test]
    fn sec4_1701_mount_reason_worst_case_line_fits() {
        let id = "a".repeat(255);
        let r = rec(
            2_000_000_000,
            AuditEvent::Mount {
                path: Some(AuditPath::new(&"\u{1}".repeat(4096))),
                reason: Some(crate::audit_log::AuditReason::new(
                    "rootfs_symlink_or_not_directory",
                )),
            },
        )
        .with_container_id(cid(&id));
        let line = encode_json_line(&r).expect("worst case encodes");
        assert!(line.len() <= AUDIT_LINE_MAX_BYTES, "{}", line.len());
    }

    /// SEC-4・#1618: 最悪ケース（制御文字だけの 4096 バイトのパス＋255 バイトの ID）でも 1 行の上限に収まる。
    #[test]
    fn sec4_1618_worst_case_line_fits() {
        let path = "\u{1}".repeat(4096);
        let id = "a".repeat(255);
        let r = rec(
            2_000_000_000,
            AuditEvent::Mount {
                path: Some(AuditPath::new(&path)),
                reason: None,
            },
        )
        .with_container_id(cid(&id));
        let line = encode_json_line(&r).expect("worst case encodes");
        assert!(line.len() <= AUDIT_LINE_MAX_BYTES, "{}", line.len());
        assert!(
            String::from_utf8(line)
                .unwrap()
                .ends_with(&format!(",\"container_id\":\"{id}\"}}\n"))
        );
    }

    /// SEC-4・TASK-41.5.1: 改行・NUL はエスケープされ 1 行に収まる（ログ注入対策）。
    #[test]
    fn sec4_task41_5_1_escapes_control_chars() {
        let r = rec(
            1,
            AuditEvent::Mount {
                path: Some(AuditPath::new("/a\nb\0c")),
                reason: None,
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
                reason: None,
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
                reason: None,
            },
        );
        assert!(text(&r).contains("\"path\":\"/x\u{fffd}y\""));
    }

    fn failing_writer() -> AuditFileWriter {
        // 読み取り専用で開いた File への write は必ず失敗する。
        AuditFileWriter::from_file_unchecked(File::open(std::env::current_exe().unwrap()).unwrap())
    }

    fn sample() -> AuditRecord {
        rec(
            1,
            AuditEvent::Mount {
                path: None,
                reason: None,
            },
        )
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
                                reason: None,
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

    /// REPAIR-5・#1703: 解放直後に取り直す書き手より、先に並んだ待ち手が先に順番を得る。
    #[test]
    fn repair5_1703_queue_hands_off_to_waiter_before_reacquire() {
        use std::sync::Arc;
        let queue = Arc::new(TurnQueue::new());
        let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let far = || Instant::now() + Duration::from_secs(30);

        let first = queue.enter(far()).unwrap();
        let waiter = {
            let (queue, order) = (Arc::clone(&queue), Arc::clone(&order));
            std::thread::spawn(move || {
                let _turn = queue.enter(far()).unwrap();
                order.lock().unwrap().push("waiter");
            })
        };
        // 待ち手が並ぶまで待つ（上限付き）。
        let limit = Instant::now() + Duration::from_secs(10);
        while queue.len() < 2 {
            assert!(Instant::now() < limit, "waiter did not enqueue");
            std::thread::yield_now();
        }
        drop(first);
        // 解放の直後に取り直しても、待ち手の後ろに並ぶ。
        let second = queue.enter(far()).unwrap();
        order.lock().unwrap().push("main");
        drop(second);
        waiter.join().unwrap();
        assert_eq!(*order.lock().unwrap(), vec!["waiter", "main"]);
        assert_eq!(queue.len(), 0);
    }

    /// REPAIR-5・#1703: 順番待ちの期限切れは `Lock` になり、自分のチケットを取り除く。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_1703_queue_deadline_returns_lock_and_removes_ticket() {
        let dir = fresh_dir("queue-deadline");
        let path = dir.join("audit.log");
        let queue = TurnQueue::new();
        let holder = queue
            .enter(Instant::now() + Duration::from_secs(30))
            .unwrap();
        let w = AuditFileWriter::open(&path).unwrap();
        let err = w
            .lock_exclusive(&queue, Instant::now() + Duration::from_millis(50))
            .err()
            .unwrap();
        assert_eq!(err.kind, AuditWriteErrorKind::Lock);
        assert_eq!(queue.len(), 1);
        drop(holder);
        assert_eq!(queue.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REPAIR-5・#1703: 保持者が解放済みで期限切れの待ち手が先頭になった場合は拒否し、チケットを残さない。
    #[cfg(target_os = "linux")]
    #[test]
    fn repair5_1703_expired_waiter_at_front_is_rejected() {
        let dir = fresh_dir("queue-expired-front");
        let path = dir.join("audit.log");
        let queue = TurnQueue::new();
        let w = AuditFileWriter::open(&path).unwrap();
        // 先頭（保持者なし）でも、期限が過ぎていれば enter / lock_exclusive は Lock で拒否する。
        let past = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        assert!(queue.enter(past).is_err());
        assert_eq!(queue.len(), 0);
        let err = w.lock_exclusive(&queue, past).err().unwrap();
        assert_eq!(err.kind, AuditWriteErrorKind::Lock);
        assert_eq!(queue.len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 全種別の代表レコード。ワイルドカード無しの match で、`AuditEvent` に種別を足すとここが落ちる。
    fn every_kind() -> Vec<(&'static str, AuditEvent)> {
        use crate::audit_log::{AuditReason, AuditSignal, ControlPeerRejection};
        let events = vec![
            AuditEvent::Seccomp {
                syscall: AuditSyscallNr::new(272).unwrap(),
                arch: AuditSyscallArch::from_raw(3221225534),
            },
            AuditEvent::Landlock {
                path: AuditPath::new("/etc/shadow"),
                syscall: AuditSyscallNr::new(2).ok(),
            },
            AuditEvent::Mount {
                path: Some(AuditPath::new("/m")),
                reason: Some(AuditReason::new("rootfs_is_host_root")),
            },
            AuditEvent::PluginTrust {
                path: AuditPath::new("/p"),
                reason: AuditReason::new("hash_mismatch"),
            },
            AuditEvent::PluginPeer {
                path: AuditPath::new("/s"),
                reason: AuditReason::new("plugin_peer_uid_mismatch"),
            },
            AuditEvent::ExecTarget {
                reason: AuditReason::new("exec_target_cgroup_mismatch"),
            },
            AuditEvent::Entrypoint {
                reason: AuditReason::new("entrypoint_is_runtime_binary"),
            },
            crate::audit_log::PastaVerifyRejection::RecordChanged.audit_event(),
            ControlPeerRejection::PeerUidMismatch.audit_event(),
            AuditEvent::ExitSignal {
                signal: AuditSignal::new(31).unwrap(),
                target_pid: AuditPid::new(1234).unwrap(),
            },
            AuditEvent::AuditCoverageDegraded {
                seccomp_kill: Some(AuditReason::new("seccomp_kill_audit_unavailable")),
                landlock: Some(AuditReason::new("landlock_audit_abi_too_old")),
            },
        ];
        events
            .into_iter()
            .map(|e| {
                let name = match &e {
                    AuditEvent::Seccomp { .. } => "seccomp",
                    AuditEvent::Landlock { .. } => "landlock",
                    AuditEvent::Mount { .. } => "mount",
                    AuditEvent::PluginTrust { .. } => "plugin_trust",
                    AuditEvent::PluginPeer { .. } => "plugin_peer",
                    AuditEvent::ExecTarget { .. } => "exec_target",
                    AuditEvent::Entrypoint { .. } => "entrypoint",
                    AuditEvent::PastaVerify { .. } => "pasta_verify",
                    AuditEvent::ControlPeer { .. } => "control_peer",
                    AuditEvent::ExitSignal { .. } => "exit_signal",
                    AuditEvent::AuditCoverageDegraded { .. } => "audit_coverage",
                };
                (name, e)
            })
            .collect()
    }

    /// ERR-4・SEC-4・#3115: 全種別を網羅し、本体が予約キー `event` / `level` を持たない（重複キーを出さない）。
    #[test]
    fn err4_sec4_3115_body_has_no_reserved_keys() {
        let kinds = every_kind();
        let names: std::collections::BTreeSet<_> = kinds.iter().map(|(n, _)| *n).collect();
        assert_eq!(names.len(), 11);
        for (name, e) in kinds {
            for cid_opt in [None, Some(cid("c1"))] {
                let mut r = rec(5, e.clone());
                if let Some(c) = cid_opt {
                    r = r.with_container_id(c);
                }
                let v = serde_json::to_value(audit_line_dto(&r)).unwrap();
                let obj = v
                    .as_object()
                    .unwrap_or_else(|| panic!("{name}: not an object"));
                assert!(!obj.contains_key("event"), "{name}");
                assert!(!obj.contains_key("level"), "{name}");
                let line = text(&r);
                assert!(
                    line.starts_with("{\"event\":\"audit\",\"layer\":"),
                    "{name}: {line}"
                );
                assert!(line.contains("\"container_id\":"), "{name}");
            }
        }
    }

    /// ERR-4・SEC-4・#3209: `audit_write_failure` の行が移行前の `writeln!` とバイト単位で一致する
    /// （全種別の組、完全一致のリテラル、予約キーを持たないこと）。
    #[test]
    fn err4_sec4_3209_write_failure_line_bytes_unchanged() {
        use AuditWriteErrorKind as K;
        let kinds = [
            K::RelativePath,
            K::Unsupported,
            K::NotRegularFile,
            K::InsecureFile,
            K::Open,
            K::Encode,
            K::LineTooLong,
            K::Write,
            K::Lock,
            K::LockFailed,
            K::Sync,
            K::FallbackUnavailable,
            K::KernelAuditUnavailable,
            K::KernelAuditPermissionDenied,
            K::KernelAuditTimeout,
            K::KernelAuditRejected,
            K::KernelAuditIo,
            K::IsolationTimeout,
            K::IsolationUnavailable,
            K::IsolationFdsNotClosed,
        ];
        for p in kinds {
            for f in kinds {
                let failure =
                    AuditWriteFailure::new(AuditWriteError::new(p), AuditWriteError::new(f));
                let mut out = Vec::new();
                failure.write_json_line(&mut out).unwrap();
                // 移行前の書式（writeln! の手組み）を試験内に写して照合する。
                let old = format!(
                    "{{\"event\":\"audit_write_failure\",\"code\":\"{}\",\"primary\":\"{}\",\"primary_code\":\"{}\",\"fallback\":\"{}\",\"fallback_code\":\"{}\"}}\n",
                    failure.error_code().as_str(),
                    failure.primary().kind().as_str(),
                    failure.primary().error_code().as_str(),
                    failure.fallback().kind().as_str(),
                    failure.fallback().error_code().as_str(),
                );
                assert_eq!(String::from_utf8(out).unwrap(), old, "{p:?}/{f:?}");
            }
        }
        let failure = AuditWriteFailure::new(
            AuditWriteError::new(K::Write),
            AuditWriteError::new(K::FallbackUnavailable),
        );
        let mut out = Vec::new();
        failure.write_json_line(&mut out).unwrap();
        let line = String::from_utf8(out).unwrap();
        assert!(
            line.starts_with(
                "{\"event\":\"audit_write_failure\",\"code\":\"INTERNAL\",\"primary\":\"write\","
            ),
            "{line}"
        );
        assert!(
            line.ends_with(
                "\"fallback\":\"fallback_unavailable\",\"fallback_code\":\"UNIMPLEMENTED\"}\n"
            ),
            "{line}"
        );
        let dto = AuditWriteFailureDto {
            code: "INTERNAL",
            primary: "write",
            primary_code: "INTERNAL",
            fallback: "open",
            fallback_code: "INTERNAL",
        };
        let v = serde_json::to_value(&dto).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("event"));
        assert!(!obj.contains_key("level"));
    }

    /// ERR-4・SEC-4・#3115: ControlPeer の行全体（移行前の出力の写し）。
    #[test]
    fn err4_sec4_3115_control_peer_exact_bytes() {
        use crate::audit_log::ControlPeerRejection;
        let r = rec(8, ControlPeerRejection::PeerUidMismatch.audit_event());
        assert_eq!(
            text(&r),
            "{\"event\":\"audit\",\"layer\":\"control_channel\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":8,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"reason\":\"control_peer_uid_mismatch\",\"container_id\":null}\n"
        );
        let r = rec(
            8,
            ControlPeerRejection::PeerCredentialsUnavailable.audit_event(),
        )
        .with_container_id(cid("c1"));
        assert_eq!(
            text(&r),
            "{\"event\":\"audit\",\"layer\":\"control_channel\",\"ts_sec\":1700000000,\"ts_nsec\":5,\"pid\":8,\"syscall\":null,\"arch\":null,\"path\":null,\"path_truncated\":null,\"path_original_len\":null,\"reason\":\"control_peer_credentials_unavailable\",\"container_id\":\"c1\"}\n"
        );
    }

    #[derive(Serialize)]
    struct Pad<'a> {
        s: &'a str,
    }

    /// ERR-4・SEC-4・#3115: 行長の境界。LF 込みの上限は緩めない（本体 = MAX は拒否）。
    #[test]
    fn err4_sec4_3115_line_limit_boundary() {
        assert_eq!(AUDIT_LINE_MAX_BYTES, crate::logging::MAX_LOG_LINE_BYTES);
        let fixed = "{\"event\":\"audit\",\"s\":\"\"}".len();
        let pad = |body_len: usize| "a".repeat(body_len - fixed);
        let ok = encode_audit_body(&Pad {
            s: &pad(AUDIT_LINE_MAX_BYTES - 1),
        })
        .unwrap();
        assert_eq!(ok.len(), AUDIT_LINE_MAX_BYTES);
        for n in [AUDIT_LINE_MAX_BYTES, AUDIT_LINE_MAX_BYTES + 1] {
            let e = encode_audit_body(&Pad { s: &pad(n) }).unwrap_err();
            assert_eq!(e.kind, AuditWriteErrorKind::LineTooLong, "{n}");
        }
        let e = encode_audit_body(&42u32).unwrap_err();
        assert_eq!(e.kind, AuditWriteErrorKind::Encode);
    }
}
