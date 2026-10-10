//! 分離違反の監査レコード型（SEC-4・TASK-41.1・#192）。
//!
//! # 役割
//!
//! seccomp・Landlock・マウント検証/API・plugin 信頼検証（TASK-122.5）・exec 対象（#1465）・エントリポイント検証（#1595）の 6 レイヤーで起きた分離違反の試行を、原因特定に必要な情報
//! （syscall 番号・対象パス・プロセス ID・タイムスタンプ）付きで表す固定スキーマの型を定義する。
//! 本モジュールは型のみで、syscall も I/O も持たない（OS 非依存。3 OS でコンパイルされる）。
//!
//! # 呼び出し元・契約
//!
//! - マウント検証/API レイヤーの記録ヘルパと記録先トレイトは [`mount`]・[`AuditSink`]（TASK-41.4・#195。
//!   `exec::audit_mount_violation` と `oci_runtime::audit_mount_config_error` がここを使う。
//!   本番 sink `FileAuditSink`〔#1594〕は実装済み。launcher・CLI・healthcheck 等への配線は未実装）
//! - exec の対象の拒否（層 `exec_target`）は `exec::audit_exec_violation` / `exec::record_exec_target_rejection`
//!   が [`AuditEvent::ExecTarget`] として記録する。supervisor の通しの入口 `run_command` が親プロセス側で
//!   1 拒否 1 件を記録する（#1465）。パスは持たない（型で保証）
//! - エントリポイント検証の拒否（層 `entrypoint`。#1595）は `exec::audit_entrypoint_violation` /
//!   `exec::record_entrypoint_rejection` が [`AuditEvent::Entrypoint`] として記録する。launch と exec の
//!   子が共有する検証（`exec_checked_entrypoint` 等）の拒否理由 8 種を載せる層で、exec の
//!   `SetupFailed` は supervisor の `run_command*` が親側で 1 拒否 1 件を記録する。パスは持たない
//!   （型で保証）。記録の PID と時刻は記録を行った親プロセスのもので、時刻は拒否から最大で exec の
//!   上限時間ぶん遅れ得る。ワイヤー形式には安定値 `entrypoint` が `layer` に増える（既存の層の行は不変。
//!   `reason` を持つ層は plugin_trust・exec_target・entrypoint の 3 つ）。launch 経路の本番配線は #1314
//! - TASK-41.3（#194）の Landlock フックは [`landlock_denial_record`] で実装済み（プロセス内で観測した
//!   `EACCES` の写像まで。ワークロードの拒否のカーネル側監査〔Linux 6.15+ の `AUDIT_LANDLOCK_*`〕による
//!   捕捉は未実装）
//! - TASK-41.2（#193。seccomp フックは `seccomp_hook` に実装済み。拒否報告 [`SeccompDenialReport`] から
//!   レコードを 1 件組み立てて [`AuditSink`] へ渡す。ただし現行フィルタは禁止 syscall に `ERRNO(EPERM)` を返し
//!   SIGSYS も通知も発生しないため、本番の配送経路〔TRAP + SIGSYS ハンドラ / USER_NOTIF + supervisor listener〕は
//!   **未実装**で、フックはまだ本番経路から呼ばれない。REPAIR-3）・41.4（#195 マウント検証/API。
//!   `exec::IsolationViolation` からの写像もここで扱う）が、違反検知時に [`AuditRecord`] を組み立てる
//! - ローカルファイルへの JSON Lines 書き込み（主経路）は `file_writer` で実装済み（TASK-41.5.1・#839）。
//!   型自体に `serde` の derive は付けず、非公開 DTO でワイヤースキーマへ写す（#652 で共通ログ型へ統一予定）。
//!   主経路の失敗時のカーネル監査（NETLINK_AUDIT）フォールバックは `kernel_audit` で実装済み（TASK-41.5.2・#840）。
//!   両者を束ねる本番 sink `FileAuditSink`（`AuditSink` 実装。#1594）も実装済みで、supervisor の exec は
//!   `exec::default_audit_sink` で構築する。一方、常時の二重記録（tee）によるクラッシュ・改ざん時の記録保持、
//!   CLI・healthcheck・mount・plugin 信頼検証への配線は **未実装**（REPAIR-3: 実装済みを装わない）
//! - レイヤーごとのペイロードを [`AuditEvent`] の enum で持ち、「syscall の無い seccomp 違反」のような
//!   不正な組み合わせを構築できない（REPAIR-2）。値は各 newtype の構築子が検証する
//! - 秘密情報（資格情報・環境変数・namespace 識別子）は含めない。ホスト側の実パスを載せるかは各フックで判断する
//!
//! # 将来仕様
//!
//! syscall 番号はアーキテクチャ相対（x86_64 / aarch64 で異なる）ため、seccomp レコードは
//! アーキ識別子（`AUDIT_ARCH_*`。[`AuditSyscallArch`]）を併せて持つ（#193 で決定）。
//! コンテナ ID を持たせるかは #194 以降で決める。フィールドは非公開かつ `#[non_exhaustive]` なので、
//! 後から追加しても破壊的変更にならない。

mod file_sink;
mod file_writer;
mod kernel_audit;
mod landlock;

pub use file_sink::{AUDIT_LOG_FILE_NAME, FileAuditSink, RECORD_WAIT_LIMIT};
pub use file_writer::{
    AUDIT_LINE_MAX_BYTES, AuditFallback, AuditFileWriter, AuditWriteError, AuditWriteErrorKind,
    AuditWriteFailure, AuditWriteOutcome, NoAuditFallback, encode_json_line, write_with_fallback,
};

pub use kernel_audit::{KERNEL_AUDIT_ACK_TIMEOUT, KernelAuditFallback};
pub use landlock::{LANDLOCK_DENIED_ERRNO, landlock_denial_record, landlock_denial_record_now};

use std::fmt;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::seccomp::{AuditArch, SyscallNr};
use crate::traits::ErrorCode;

pub mod mount;
mod seccomp_hook;
mod sink;

pub use mount::{AuditDelivery, AuditedRejection, current_pid, record_mount_rejection};
pub use seccomp_hook::{SeccompDenialReport, SeccompReportSource, record_seccomp_denial};
pub use sink::AuditSink;

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
    /// SIGSYS の `si_code` が `SYS_SECCOMP` ではない（seccomp 由来でないシグナル）。
    NotSeccompSignal,
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
            AuditRecordErrorKind::NotSeccompSignal => "signal is not a seccomp report",
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

    /// `seccomp_data.nr`（カーネルの `int`）のビットパターンを u32 として保持する（失敗しない）。
    ///
    /// BPF は `nr` を u32 として比較するため、`syscall(-1)`（0xFFFF_FFFF）や x32 ビット付き番号も
    /// フィルタで拒否されうる。[`AuditSyscallNr::new`] は負値を拒否するので、拒否された試行の記録が
    /// 落ちないよう seccomp 報告経路ではこちらを使う（SEC-4 の 100% 記録）。
    pub const fn from_seccomp_data_nr(nr: i32) -> Self {
        Self(nr.cast_unsigned())
    }

    /// 番号を返す。
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// syscall 番号を解釈するためのアーキ識別子（`AUDIT_ARCH_*` の生の値）。
///
/// `KILL_PROCESS` は対象アーキと異なる arch で発火するため、外部アーキの値こそ記録対象になる。
/// そのためどんな値でも受け付ける。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditSyscallArch(u32);

impl AuditSyscallArch {
    /// カーネル報告値から構築する（失敗しない）。
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// `AUDIT_ARCH_*` の値を返す。
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<AuditArch> for AuditSyscallArch {
    /// 禁止テーブル由来の値を取り込む。
    fn from(a: AuditArch) -> Self {
        Self(a.get())
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
/// 記録したプロセス自身の PID namespace から見た PID。他の namespace（例: seccomp USER_NOTIF の
/// listener 側 PID）の値は、呼び出し側が変換してから渡す契約（SEC-4。`seccomp_hook` 参照）。
/// ホスト側 PID との突き合わせはカーネル監査経路の担当（#840 の `KernelAuditFallback` は本 PID を本文に載せるだけで、変換はしない）。
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
/// 改行・制御文字・NUL を含みうるため、出力時は書き込み側（`file_writer`・実装済み）が必ずエスケープすること
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

/// 監査レコードに載せる拒否理由トークン（PLUG-11・TASK-122.5）。
///
/// crate 内の静的 ASCII トークンからのみ構築できる（`pub(crate)` 構築子）。外部入力由来の文字列を
/// 載せられない型にしてログ注入を防ぐ（REPAIR-2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditReason(&'static str);

impl AuditReason {
    /// 静的トークンから構築する（crate 内専用）。
    pub(crate) const fn new(token: &'static str) -> Self {
        Self(token)
    }

    /// トークンを返す。
    pub const fn as_str(self) -> &'static str {
        self.0
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
    /// plugin 信頼検証（所有者・モード・ハッシュ。PLUG-11・SEC-4・TASK-122.5）。
    PluginTrust,
    /// 稼働中コンテナへの exec の対象の拒否（SEC-4・SUP-6・TASK-163 追補・#1465）。
    ExecTarget,
    /// エントリポイント検証の拒否（launch と exec の子で共有。SEC-4・SUP-6・TASK-163 追補・#1595）。
    Entrypoint,
}

impl AuditLayer {
    /// 後続エンコーダが使う安定トークン。
    pub const fn as_str(self) -> &'static str {
        match self {
            AuditLayer::Seccomp => "seccomp",
            AuditLayer::Landlock => "landlock",
            AuditLayer::Mount => "mount",
            AuditLayer::PluginTrust => "plugin_trust",
            AuditLayer::ExecTarget => "exec_target",
            AuditLayer::Entrypoint => "entrypoint",
        }
    }
}

/// レイヤー別のペイロード。不正な組み合わせ（syscall の無い seccomp 違反等）を構築できない。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditEvent {
    /// seccomp 違反。syscall・arch は必須。パスは持たない（ユーザー空間ポインタは TOCTOU になるため）。
    ///
    /// 破壊的変更（TASK-41.2・SEC-4）: TASK-41.1 の `Seccomp { syscall }` に必須の `arch` を追加した。
    /// syscall 番号はアーキ相対で arch 無しでは解釈できず、後から任意項目にすると誤解釈した記録を
    /// 構築できてしまうため、互換形（任意項目・別 variant）にしない。本 crate は `publish = false` で
    /// 外部利用者がおらず、リポ内の構築・match は同 PR で追随済み。
    /// 移行手順: 構築は `Seccomp { syscall, arch: AuditSyscallArch::from_raw(<AUDIT_ARCH_*>) }` とし、
    /// パターンは `Seccomp { syscall, .. }` と書く（`arch` を読むなら `AuditRecord::seccomp_arch()`）。
    Seccomp {
        /// 拒否された syscall。
        syscall: AuditSyscallNr,
        /// syscall 番号の解釈に必要なアーキ識別子。
        arch: AuditSyscallArch,
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
    /// plugin 信頼検証の拒否（PLUG-11・TASK-122.5）。パスと拒否理由は必須。
    PluginTrust {
        /// 拒否された plugin ファイルまたは探索先ディレクトリのパス。
        path: AuditPath,
        /// 拒否理由トークン（静的トークン。[`AuditReason`] 参照）。
        reason: AuditReason,
    },
    /// 稼働中コンテナへの exec の対象の拒否（SEC-4・SUP-6・TASK-163 追補・#1465）。
    ///
    /// 理由トークンだけを持ち、**パスは持たない**（型で保証する。REPAIR-2）。期待 cgroup パス・
    /// ホスト側パス・namespace 識別子はコンテナ ID と cgroup 配置の記録から再導出でき原因特定に不要で、
    /// システム共通の監査ログ（カーネル監査フォールバック）へホスト構成を露出させないため。
    ExecTarget {
        /// 拒否理由トークン（`exec_target_*` 等の静的トークン。[`AuditReason`] 参照）。
        reason: AuditReason,
    },
    /// エントリポイント検証の拒否（SEC-4・SUP-6・SEC-1・TASK-163 追補・#1595）。
    ///
    /// 理由トークンだけを持ち、**パスは持たない**（型で保証する。REPAIR-2）。対象は常にそのコンテナの
    /// エントリポイントか新 root の `/dev`・`/proc`・`/dev/null` で理由コードだけで原因を特定でき、
    /// システム共通の監査ログへコンテナ内パスやホスト構成を出さないため。
    Entrypoint {
        /// 拒否理由トークン（`entrypoint_*` 等の静的トークン。[`AuditReason`] 参照）。
        reason: AuditReason,
    },
}

impl AuditEvent {
    /// 対応するレイヤーを返す。
    pub fn layer(&self) -> AuditLayer {
        match self {
            AuditEvent::Seccomp { .. } => AuditLayer::Seccomp,
            AuditEvent::Landlock { .. } => AuditLayer::Landlock,
            AuditEvent::Mount { .. } => AuditLayer::Mount,
            AuditEvent::PluginTrust { .. } => AuditLayer::PluginTrust,
            AuditEvent::ExecTarget { .. } => AuditLayer::ExecTarget,
            AuditEvent::Entrypoint { .. } => AuditLayer::Entrypoint,
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
            AuditEvent::Seccomp { syscall, .. } => Some(*syscall),
            AuditEvent::Landlock { syscall, .. } => *syscall,
            AuditEvent::Mount { .. }
            | AuditEvent::PluginTrust { .. }
            | AuditEvent::ExecTarget { .. }
            | AuditEvent::Entrypoint { .. } => None,
        }
    }

    /// seccomp レコードのアーキ識別子（他レイヤーでは `None`）。
    pub fn seccomp_arch(&self) -> Option<AuditSyscallArch> {
        match &self.event {
            AuditEvent::Seccomp { arch, .. } => Some(*arch),
            _ => None,
        }
    }

    /// 対象パスがあれば返す。
    pub fn path(&self) -> Option<&Path> {
        match &self.event {
            AuditEvent::Seccomp { .. }
            | AuditEvent::ExecTarget { .. }
            | AuditEvent::Entrypoint { .. } => None,
            AuditEvent::Landlock { path, .. } => Some(path.as_path()),
            AuditEvent::Mount { path } => path.as_ref().map(AuditPath::as_path),
            AuditEvent::PluginTrust { path, .. } => Some(path.as_path()),
        }
    }

    /// 拒否理由トークン（plugin 信頼検証・exec 対象・エントリポイントのレコードのみ。他レイヤーは `None`）。
    pub fn reason(&self) -> Option<AuditReason> {
        match &self.event {
            AuditEvent::PluginTrust { reason, .. }
            | AuditEvent::ExecTarget { reason }
            | AuditEvent::Entrypoint { reason } => Some(*reason),
            _ => None,
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
                arch: AuditSyscallArch::from_raw(0xC000_003E),
            },
        );
        assert_eq!(
            r.seccomp_arch().map(AuditSyscallArch::get),
            Some(0xC000_003E)
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
        assert_eq!(AuditLayer::ExecTarget.as_str(), "exec_target");
        assert_eq!(AuditLayer::Entrypoint.as_str(), "entrypoint");
    }

    /// SEC-4・SUP-6・TASK-163 追補・#1595: entrypoint レコードは理由だけを持ち、パス・syscall は持たない。
    #[test]
    fn sec4_sup6_task163_entrypoint_record_accessors() {
        let r = AuditRecord::new(
            ts(),
            pid(12),
            AuditEvent::Entrypoint {
                reason: AuditReason::new("entrypoint_is_runtime_binary"),
            },
        );
        assert_eq!(r.layer(), AuditLayer::Entrypoint);
        assert_eq!(
            r.reason().map(AuditReason::as_str),
            Some("entrypoint_is_runtime_binary")
        );
        assert_eq!(r.path(), None);
        assert_eq!(r.syscall(), None);
        assert_eq!(r.seccomp_arch(), None);
        assert_eq!(r.pid().get(), 12);
    }

    /// SEC-4・SUP-6・TASK-163 追補: exec 対象レコードは理由だけを持ち、パス・syscall は持たない。
    #[test]
    fn sec4_sup6_task163_exec_target_record_accessors() {
        let r = AuditRecord::new(
            ts(),
            pid(11),
            AuditEvent::ExecTarget {
                reason: AuditReason::new("exec_target_cgroup_mismatch"),
            },
        );
        assert_eq!(r.layer(), AuditLayer::ExecTarget);
        assert_eq!(
            r.reason().map(AuditReason::as_str),
            Some("exec_target_cgroup_mismatch")
        );
        assert_eq!(r.path(), None);
        assert_eq!(r.syscall(), None);
        assert_eq!(r.seccomp_arch(), None);
        assert_eq!(r.pid().get(), 11);
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
