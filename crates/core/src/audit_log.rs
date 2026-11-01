//! 分離違反の監査レコード型（SEC-4・TASK-41.1・#192）。
//!
//! # 役割
//!
//! `AuditLayer` の 11 種（seccomp・landlock・mount・plugin_trust・plugin_peer・exec_target・entrypoint・
//! control_channel・exit_signal・audit_coverage・pasta_verify）で起きた分離違反の試行と、それに付随する補助の記録を、
//! 原因特定に必要な情報（syscall 番号・対象パス・プロセス ID・タイムスタンプ）付きで表す固定スキーマの型を定義する。
//! `exit_signal` は違反そのものではなく回収点が見た終了シグナルの補助記録、`audit_coverage` は監査を 100% 満たせない
//! 環境で起動を続けた縮退の記録である。
//! 本モジュール本体（`audit_log.rs`）の型定義は syscall も I/O も持たない（OS 非依存。3 OS でコンパイルされる）。
//! I/O を持つのは下位モジュール（`file_writer`・`kernel_audit`・`control_relay`・`file_sink` など）である。
//!
//! # 呼び出し元・契約
//!
//! - マウント検証/API レイヤーの記録ヘルパと記録先トレイトは [`mount`]・[`AuditSink`]（TASK-41.4・#195。
//!   `exec::audit_mount_violation` と `oci_runtime::audit_mount_config_error` がここを使う。
//!   本番 sink `FileAuditSink`〔#1594〕は実装済み。CLI の create は destination 拒否を配線済み〔#2480〕。plugin-cri の peer 認証の拒否は層 `plugin_peer` として配線済み〔#2484〕。healthcheck 等への配線は未実装）
//! - exec の対象の拒否（層 `exec_target`）は `exec::audit_exec_violation` / `exec::record_exec_target_rejection`
//!   が [`AuditEvent::ExecTarget`] として記録する。supervisor の通しの入口 `run_command` が親プロセス側で
//!   1 拒否 1 件を記録する（#1465。worker の経路の拒否は `exec::record_exec_worker_rejection_at` で、種別 `rootfs_pivot`
//!   の `rootfs_is_host_root` は層 `mount` のパスなし・理由コードつきの 1 件になる）。パスは持たない（型で保証）
//! - エントリポイント検証の拒否（層 `entrypoint`。#1595）は `exec::audit_entrypoint_violation` /
//!   `exec::record_entrypoint_rejection` が [`AuditEvent::Entrypoint`] として記録する。launch と exec の
//!   子が共有する検証（`exec_checked_entrypoint` 等）の拒否理由 8 種を載せる層で、exec の
//!   `SetupFailed` は supervisor の `run_command*` が親側で 1 拒否 1 件を記録する。パスは持たない
//!   （型で保証）。記録の PID と時刻は記録を行った親プロセスのもので、時刻は拒否から最大で exec の
//!   上限時間ぶん遅れ得る。ワイヤー形式には安定値 `entrypoint` が `layer` に増える（既存の層の行は不変。
//!   `reason` を持つ層は plugin_trust・plugin_peer・exec_target・entrypoint・pasta_verify・control_channel と、理由つきの mount のレコード）。launch 経路（本番 launcher の子）の entrypoint 違反は、子が状態 pipe の exec 前の 2 行目で返し、親〔launcher の呼び出し元〕が `exec::audit_entrypoint_violation` で記録して配線済み（#2624）。`R` の後の `execveat` の errno 由来の失敗は `X` 行で届き起動失敗になるが、違反ではないため記録しない（#2716）。状態 pipe を持たない `spawn_container` 系の子は、製品コードからの呼び出し元が無いため配線しないと決定（#2716。製品の入口を足すときは状態 pipe 付きの `spawn_container_via_intermediate` を通すこと。REPAIR-3）
//! - pasta バイナリの起動時の再検証の拒否（層 `pasta_verify`。SEC-4・PLUG-11・NET-9・#3330）は、supervisor の start の入口が
//!   [`AuditEvent::PastaVerify`] として中継 sink（`ControlAuditRelay`）経由で 1 拒否 1 件を配送する（実装済み）。理由は
//!   [`PastaVerifyRejection`] の 2 種（`pasta_record_changed`・`pasta_permission_denied`）で、パスは持たない（型で保証）。
//!   作成時（CLI の create）の `PermissionDenied` は D2 と両立しないため記録しない
//! - supervisor の制御チャネルの接続元の拒否（層 `control_channel`。SEC-4・SEC-1・SUP-1・#2058）は、制御チャネルのサーバー
//!   （`fandhe-container-supervisor` の `control/server.rs`）が `ControlObserver::record_peer_rejection`
//!   （`control/observe.rs`）経由で [`AuditEvent::ControlPeer`] として記録する。理由は [`ControlPeerRejection`] の 2 種
//!   （`control_peer_uid_mismatch`・`control_peer_credentials_unavailable`）で、パス・接続元の uid と pid は持たない。
//!   コンテナ ID は observer が持っていれば付く。supervisor は複数スレッドのため配送は中継 `ControlAuditRelay` を通し、
//!   記録先へ書けなければ構造化ログ（`control_peer_rejected`）に出す
//! - 終了シグナルの補助記録（層 `exit_signal`。SEC-4・ESC-06・#2004）は、本番 launcher の回収点
//!   （`oci_runtime::launch` の `with_exit_audit`・`record_exit_signal_once`）が、SIGSYS で終わったのを初めて見たときに
//!   回収の後で 1 回だけ [`AuditEvent::ExitSignal`] として記録する。[`record_exit_signal_until`] を [`RECORD_WAIT_LIMIT`]
//!   の期限つきで使い、記録先は supervisor が単一スレッドの間に作った `ControlAuditRelay`（`exit_audit_sink`。#2236）。
//!   コンテナ ID・signal・target_pid（回収した側の PID namespace の値）を載せ、syscall・arch は持たない。
//!   seccomp 由来とは断定できない補助の記録で、正の記録はカーネルの `AUDIT_SECCOMP`。pid 1 以外の子孫は観測できない
//! - 監査の縮退の記録（層 `audit_coverage`。SEC-4・#2027）の判定は `coverage` モジュール（[`assess`]・[`AuditCoverage`]・
//!   [`AuditCoveragePolicy`] の `best-effort`・`strict`）で行う。本番 launcher の `assess_audit_coverage` が fork の前に評価し、
//!   厳格モードなら起動を拒否する。縮退していれば [`AuditEvent::AuditCoverageDegraded`] を `mount::deliver_until` で
//!   コンテナ ID つき・launch の期限つきの 1 件として配送する。書けなければ [`AUDIT_COVERAGE_RECORD_FAILED_LINE`] を出し、
//!   分離の記録（`state.json` の `launchIsolation`・inspect）にも失敗を載せる（#2468）。理由は `reason` ではなく
//!   `seccomp_kill`・`landlock` の 2 欄（ワイヤーでは `seccomp_kill_reason`・`landlock_reason`。`coverage_reasons()`）で持つ
//! - TASK-41.3（#194）の Landlock フックは [`landlock_denial_record`] で実装済み（プロセス内で観測した
//!   `EACCES` の写像まで。ワークロードの拒否のカーネル側監査〔Linux 6.15+ の `AUDIT_LANDLOCK_*`〕による
//!   捕捉は未実装）
//! - TASK-41.2（#193。seccomp フックは `seccomp_hook` に実装済み。拒否報告 [`SeccompDenialReport`] から
//!   レコードを 1 件組み立てて [`AuditSink`] へ渡す。ただし現行フィルタは禁止 syscall に `ERRNO(EPERM)` を返し
//!   〔`unshare`・`ptrace`・`kexec_load` は `KILL_PROCESS` で終了するが、終了するプロセス自身は記録を書けない〕
//!   通知は発生しない既定の launcher では、フックは呼ばれない。supervisor の start 経路は
//!   `ProductionLauncherBuilder::seccomp_errno_delivery(UserNotif)` で ERRNO 側を USER_NOTIF にし、listener ループ
//!   〔`fandhe-container-supervisor::seccomp_notify`。#2025〕が `record_seccomp_denial_for` で記録してから `-EPERM` で応答する。
//!   exec 経路〔SUP-6〕も #2544 で USER_NOTIF になり、exec の親が listener に応答して記録する（`docs/design/audit-delivery.md` 9.4）。KILL 側の正の記録はカーネルの
//!   `AUDIT_SECCOMP`、親の回収点が出す `exit_signal` 層の補助記録は [`AuditEvent::ExitSignal`]〔#2004〕）・41.4（#195 マウント検証/API。
//!   `exec::IsolationViolation` からの写像もここで扱う）が、違反検知時に [`AuditRecord`] を組み立てる
//! - ローカルファイルへの JSON Lines 書き込み（主経路）は `file_writer` で実装済み（TASK-41.5.1・#839）。
//!   型自体に `serde` の derive は付けず、非公開 DTO でワイヤースキーマへ写す（共通ログ型 `LogLine` 経由で書く。#3115・ERR-4）。
//!   主経路の失敗時のカーネル監査（NETLINK_AUDIT）フォールバックは `kernel_audit` で実装済み（TASK-41.5.2・#840）。
//!   両者を束ねる本番 sink `FileAuditSink`（`AuditSink` 実装。#1594）も実装済みで、supervisor の exec は
//!   `exec::default_audit_sink` で構築する。一方、常時の二重記録（tee）によるクラッシュ・改ざん時の記録保持は **未実装**（REPAIR-3: 実装済みを装わない。追跡先は #3417 のコメントで諮る）。
//!   launch 経路（launcher）への配線は supervisor の start 経路から結線済み（#1819。`default_audit_sink` の sink を本番 launcher へ渡す）で、
//!   healthcheck は単一スレッドの exec 専用 helper（supervisor の `healthcheck-exec`）が `FileAuditSink` を直接使う（#2441。結線は #2953）。CLI の exec への配線は #2626 が追う（未実装）。plugin 信頼検証は
//!   CLI の plugin バックエンド（`fandhe-container-cli` の `plugin_backend`。macOS・Windows の本番経路）に配線済み
//!   （#2013）。記録先は `FileAuditSink::open_in_state_root` で作り、macOS では主経路（`file_writer` の fd 相対 open と
//!   拡張 ACL の拒否、`file_sink` の `run_isolated` の macOS 版。#2429）が成功すれば `Recorded` になる（代替経路は
//!   未実装で、主経路が失敗すれば `SinkFailed`。#2430）。Windows では `FileStateStore` が未実装のため記録先を作れず
//!   `SinkFailed` になる。レジストリ・spawn への配線は #1869 の設計〔docs/design/plugin-backend-wiring.md。承認と実装 issue の起票は #2232〕
//! - レイヤーごとのペイロードを [`AuditEvent`] の enum で持ち、「syscall の無い seccomp 違反」のような
//!   不正な組み合わせを構築できない（REPAIR-2）。値は各 newtype の構築子が検証する
//! - 秘密情報（資格情報・環境変数・namespace 識別子）は含めない。ホスト側の実パスを載せるかは各フックで判断する
//!
//! # 将来仕様
//!
//! syscall 番号はアーキテクチャ相対（x86_64 / aarch64 で異なる）ため、seccomp レコードは
//! アーキ識別子（`AUDIT_ARCH_*`。[`AuditSyscallArch`]）を併せて持つ（#193 で決定）。
//! コンテナ ID は #1618 で [`AuditRecord::container_id`] として追加済み（検証済みの `ContainerId` のみ。
//! mount・exec_target・entrypoint の配送ヘルパが載せる。seccomp は supervisor の listener ループが `record_seccomp_denial_for` で載せる〔#2025〕。
//! pasta_verify〔start の入口。#3330〕・control_channel〔observer が分かる場合〕・exit_signal〔#2004〕・audit_coverage〔#2027〕も載せる。landlock への配線は未実装。
//! plugin_trust は検証がコンテナを特定する前に走り特定のコンテナに属さないため、載せない〔#2013〕。plugin_peer も特定のコンテナに属さないため載せない）。
//! 拒否した段は #3121 で [`AuditRecord::stage`] として追加済み（`IsolationStage` と同じ固定語彙の [`AuditStage`]）。
//! `ExecError::stage` が手元にある記録点（`exec` のマウント・exec 対象・entrypoint の違反と launch の pre-pivot 失敗）と、
//! supervisor の exec の親の記録が載せる。他の層は載せない（キー自体を出さない）。親の記録点の段の対応づけ（#3209・#3294）:
//!
//! - **entrypoint**（worker の `ok` 行。`exec::record_entrypoint_rejection_at`）: 結果行で届いた `ExecChildStep` を
//!   `ExecChildStep::stage` で写す。届かなければ載せない
//! - **worker の失敗**（worker の `err` 行。`exec::record_exec_worker_rejection_at`）: `err` 行の段の欄は
//!   `IsolationStage::as_str` のトークンで、親は `IsolationStage::from_token` で引き直してそのまま記録の `stage` に載せる
//!   （恒等の写像で、第 2 の対応表は持たない）。worker は違反を伴うときだけ `ExecError::stage` を運ぶ。bundle の rootfs の
//!   固定の拒否〔`RootfsPinError`〕は段を持たないため、利用者向けメッセージ（`exec stage Validate:`）と同じ出所の
//!   `Validate` を呼び出した段として運ぶ。欄の無い旧形式の行・未知のトークン・違反なしで段ありは
//!   壊れた行として拒否し、記録しない（fail-closed）。違反ありで段なしは受理し、段を捏造せず段なしで記録する
//!
//! pid1 の PID は未検証の候補しか得られないため載せない。フィールドは非公開かつ `#[non_exhaustive]` なので、
//! 後から追加しても破壊的変更にならない。
//!
//! # 段を載せない記録点と理由（未実装。#3209・REPAIR-3）
//!
//! - **制御チャネルの中継**（`ControlAuditRelay`）: 枠が段を運ばず、段つきの記録を通すと段は落ちる（拒否せず記録は
//!   残す。試験で固定）。現行の配線では段つきの記録（単一スレッドの launch と pre-pivot）は `FileAuditSink` へ直接
//!   書かれ中継を通らず、exec の親も中継ではなく `FileAuditSink` を使うため、段を運ぶ必要が生じていない。拡張が
//!   要るのは、複数スレッドの文脈から中継経由で段つきの層を記録する経路を足すとき（healthcheck は
//!   単一スレッドの helper が `FileAuditSink` を直接使うため該当しない。#2441）。そのときは段だけでなく Entrypoint・ExecTarget などの層ごと運べるようにする

#[cfg(target_os = "linux")]
mod control_relay;
mod coverage;
mod file_sink;
mod file_writer;
mod kernel_audit;
mod landlock;

#[cfg(target_os = "linux")]
pub use control_relay::ControlAuditRelay;
pub use coverage::{
    AUDIT_COVERAGE_RECORD_FAILED_LINE, AUDIT_COVERAGE_STRICT_REFUSAL, AuditCoverage,
    AuditCoveragePolicy, CoverageLayer, DegradeReason, KernelAuditLayerStatus, KernelAuditProbe,
    assess,
};
pub use file_sink::{AUDIT_LOG_FILE_NAME, FileAuditSink, RECORD_WAIT_LIMIT, reap_pending_children};
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
use crate::traits::{ContainerId, ErrorCode};

pub mod mount;
mod seccomp_hook;
mod sink;

pub use mount::{
    AuditDelivery, AuditedRejection, current_pid, record_exit_signal, record_exit_signal_until,
    record_mount_rejection,
};
pub use seccomp_hook::{
    SeccompDenialReport, SeccompReportSource, record_seccomp_denial, record_seccomp_denial_for,
    record_seccomp_denial_for_until,
};
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
    /// シグナル番号が `1..=64` の範囲外（[`AuditSignal`]）。
    SignalOutOfRange,
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
            AuditRecordErrorKind::SignalOutOfRange => "audit signal number must be in 1..=64",
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
/// 記録したプロセス自身の PID namespace から見た PID。違反したプロセスの PID とは限らない
/// （層ごとの意味は [`AuditRecord`] の doc。コンテナとの対応は `container_id` で取る）。他の namespace（例: seccomp USER_NOTIF の
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

/// 終了シグナルの番号（Linux のシグナル番号の有効範囲 `1..=64`）。
///
/// [`AuditEvent::ExitSignal`] が持つ。親の `waitpid` が得た終了シグナルの値で、syscall の情報は一切含まない
/// （SEC-4・ESC-06・#2004）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditSignal(u8);

impl AuditSignal {
    /// シグナル番号から構築する。`1..=64` の範囲外は `SignalOutOfRange`。
    pub fn new(signal: i32) -> Result<Self, AuditRecordError> {
        u8::try_from(signal)
            .ok()
            .filter(|s| (1..=64).contains(s))
            .map(Self)
            .ok_or_else(|| AuditRecordError::new(AuditRecordErrorKind::SignalOutOfRange))
    }

    /// シグナル番号を返す（常に 1 以上 64 以下）。
    pub const fn get(self) -> u8 {
        self.0
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

/// 監査レコードに載せる、拒否した段（stage）のトークン（SEC-4・ERR-4・REPAIR-4・#3121）。
///
/// 語彙は実行層の `IsolationStage`（`ExecError::stage`）の固定語彙（snake_case）と同じで、Linux 限定の
/// `From<IsolationStage>`（`exec.rs`）が唯一の生成経路。構築子は crate 内専用なので、外部入力由来の
/// 文字列を載せられない（ログ注入の防止。REPAIR-2）。`audit_log` は 3 OS でコンパイルされ
/// `IsolationStage` は Linux 限定のため、型自体は文字列の newtype にしてある。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditStage(&'static str);

impl AuditStage {
    /// 静的トークンから構築する（crate 内専用）。
    #[cfg(any(target_os = "linux", test))]
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
    /// plugin の gRPC サーバー（plugin-cri）が受付時の peer credential 照合で接続を拒否した記録
    /// （別 uid・資格情報を確かめられない接続。SEC-4・PLUG-12・#2484）。
    PluginPeer,
    /// 稼働中コンテナへの exec の対象の拒否（SEC-4・SUP-6・TASK-163 追補・#1465）。
    ExecTarget,
    /// エントリポイント検証の拒否（launch と exec の子で共有。SEC-4・SUP-6・TASK-163 追補・#1595）。
    Entrypoint,
    /// supervisor の制御チャネルの接続元の拒否（別 uid・資格情報を確かめられない接続。SEC-4・SEC-1・SUP-1・#2058）。
    ControlChannel,
    /// 親（回収した側）が `waitpid` で得た終了シグナルの補助記録（SEC-4・ESC-06・#2004）。
    ///
    /// seccomp 由来とは断定しない（コンテナ内の `kill(SIGSYS)` と区別できない）ため、層は `Seccomp` と別にする。
    ExitSignal,
    /// 監査の記録を 100% 満たせない環境で起動を続けた縮退の記録（SEC-4・#2027）。
    AuditCoverage,
    /// start の起動時に行う pasta バイナリの再検証が改ざんの疑いで拒否した記録（SEC-4・PLUG-11・NET-9・#3330）。
    PastaVerify,
}

impl AuditLayer {
    /// 後続エンコーダが使う安定トークン。
    pub const fn as_str(self) -> &'static str {
        match self {
            AuditLayer::Seccomp => "seccomp",
            AuditLayer::Landlock => "landlock",
            AuditLayer::Mount => "mount",
            AuditLayer::PluginTrust => "plugin_trust",
            AuditLayer::PluginPeer => "plugin_peer",
            AuditLayer::ExecTarget => "exec_target",
            AuditLayer::Entrypoint => "entrypoint",
            AuditLayer::ControlChannel => "control_channel",
            AuditLayer::ExitSignal => "exit_signal",
            AuditLayer::AuditCoverage => "audit_coverage",
            AuditLayer::PastaVerify => "pasta_verify",
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
    ///
    /// 違反の理由コード（`ViolationReason` の静的トークン。例: `rootfs_is_host_root`）を `reason` に載せる
    /// （SEC-4・TASK-41.4 追補・#1701）。理由の語彙を持たない API 層（OCI config の拒否。
    /// `record_mount_rejection`）は `None` で、その行の出力は従来と変わらない。OCI 側に理由トークンを
    /// 持たせるかは #652（TASK-98.1）の共通ログ型と合わせて決める（REPAIR-3）。
    ///
    /// 破壊的変更: `Seccomp` の `arch`（TASK-41.2）と同じく、フィールド追加で構築とパターンが壊れる。
    /// 移行手順: 構築は `Mount { path, reason: None }`（理由を持つ経路は `Some(..)`）、
    /// パターンは `Mount { path, .. }` と書く（理由を読むなら `AuditRecord::reason()`）。
    Mount {
        /// 拒否されたマウント先パス。
        path: Option<AuditPath>,
        /// 違反の理由コード（静的トークン。[`AuditReason`] 参照）。API 層の拒否では `None`。
        reason: Option<AuditReason>,
    },
    /// plugin 信頼検証の拒否（PLUG-11・TASK-122.5）。パスと拒否理由は必須。
    PluginTrust {
        /// 拒否された plugin ファイルまたは探索先ディレクトリのパス。
        path: AuditPath,
        /// 拒否理由トークン（静的トークン。[`AuditReason`] 参照）。
        reason: AuditReason,
    },
    /// plugin-cri の gRPC サーバーが接続元を拒否した記録（SEC-4・PLUG-12・#2484）。
    ///
    /// socket のパス（`plugin-backend-wiring.md` 4.7）と閉じた語彙の理由トークンを持ち、接続元の
    /// uid・pid の値とコンテナ ID は持たない（拒否は特定のコンテナに属さない。REPAIR-2）。
    /// 構築は [`PluginPeerRejection::audit_event`] で行う。
    PluginPeer {
        /// 受付に使った socket のパス。
        path: AuditPath,
        /// 拒否理由トークン（[`PluginPeerRejection::as_str`]）。
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
    /// start の起動時の pasta バイナリの再検証が改ざんの疑いで拒否した記録（SEC-4・PLUG-11・NET-9・#3330）。
    ///
    /// 理由トークンだけを持ち、**パスは持たない**（型で保証する。REPAIR-2）。構築は
    /// [`PastaVerifyRejection::audit_event`] で行う。
    PastaVerify {
        /// 拒否理由トークン（[`PastaVerifyRejection::as_str`]）。
        reason: AuditReason,
    },
    /// supervisor の制御チャネルが接続元を拒否した記録（SEC-4・SEC-1・SUP-1・#2058）。
    ///
    /// 理由トークンだけを持ち、パス・接続元の uid・pid は持たない（型で保証する。REPAIR-2）。
    /// 構築は [`ControlPeerRejection::audit_event`] で行う。
    ControlPeer {
        /// 拒否理由トークン（[`ControlPeerRejection::as_str`]）。
        reason: AuditReason,
    },
    /// 親が回収したコンテナプロセスの終了シグナル（SEC-4・ESC-06・TASK-41 追補・#2004。補助の記録）。
    ///
    /// `SECCOMP_RET_KILL_PROCESS` で終了したプロセスは自分では記録を書けない。正の記録（syscall・arch・pid）は
    /// カーネルの `AUDIT_SECCOMP` が担い、本種別はそれと突き合わせるための補助に限る。コンテナ内の
    /// `kill(SIGSYS)` と区別できないため seccomp 由来とは断定せず、**syscall・arch を型として持たない**
    /// （終了シグナルから syscall を推測した記録を作れない。REPAIR-2）。
    ExitSignal {
        /// 終了シグナル。
        signal: AuditSignal,
        /// 終了したプロセスの PID。**回収した側の PID namespace** から見た値で、`AuditPid` の doc にある
        /// 「対象プロセス自身の名前空間」とは異なる。ホストの PID namespace の回収者なら、カーネル記録の
        /// `pid=` と一致する。記録した側の PID は [`AuditRecord::pid`]。
        target_pid: AuditPid,
    },
    /// カーネル監査頼みの層が縮退したまま起動を続けた記録（SEC-4・TASK-41 追補・#2027。監査配送 6/6）。
    ///
    /// 固定語彙の理由トークンだけを持ち、パス・ホスト由来の文字列は持たない（型で保証する。REPAIR-2）。
    /// 縮退していない層は `None`。構築は [`AuditCoverage::degraded_event`]（両方 `None` の値を作らない）。
    /// #2018 の承認事項 3（方式の実装に必要な範囲の `AuditEvent` の変更）による追加。
    AuditCoverageDegraded {
        /// `KILL_PROCESS` の `AUDIT_SECCOMP` が縮退している場合の理由。
        seccomp_kill: Option<AuditReason>,
        /// Landlock の `AUDIT_LANDLOCK_*` が縮退している場合の理由。
        landlock: Option<AuditReason>,
    },
}

/// pasta バイナリの起動時の再検証が改ざんの疑いで拒否した理由（SEC-4・PLUG-11・NET-9・#3330）。固定語彙で、入力値を載せない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PastaVerifyRejection {
    /// 記録した識別（所有者・inode・サイズ・ハッシュ等）と今のバイナリが一致しない。
    RecordChanged,
    /// バイナリまたは祖先ディレクトリの権限・所有者の検査に通らない。
    PermissionDenied,
}

impl PastaVerifyRejection {
    /// 監査レコードに入る静的トークン。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordChanged => "pasta_record_changed",
            Self::PermissionDenied => "pasta_permission_denied",
        }
    }

    /// 対応する監査イベントを返す。
    pub fn audit_event(self) -> AuditEvent {
        AuditEvent::PastaVerify {
            reason: AuditReason::new(self.as_str()),
        }
    }
}

/// 制御チャネルが接続元を拒否した理由（SEC-4・SEC-1・SUP-1・#2058）。固定語彙で、入力値を載せない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlPeerRejection {
    /// 接続元の uid が supervisor の実効 uid と違う。
    PeerUidMismatch,
    /// `SO_PEERCRED` で接続元の資格情報を取れなかった。
    PeerCredentialsUnavailable,
}

impl ControlPeerRejection {
    /// 監査レコードに入る静的トークン。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerUidMismatch => "control_peer_uid_mismatch",
            Self::PeerCredentialsUnavailable => "control_peer_credentials_unavailable",
        }
    }

    /// 対応する監査イベントを返す。
    pub fn audit_event(self) -> AuditEvent {
        AuditEvent::ControlPeer {
            reason: AuditReason::new(self.as_str()),
        }
    }
}

/// plugin の gRPC サーバーが接続元を拒否した理由（SEC-4・PLUG-12・#2484）。固定語彙で、入力値を載せない。
///
/// plugin crate の `PeerAuthRejectReason` に対応する。core は plugin crate に依存しないため、
/// 写像は plugin-cri 側で行い、将来 plugin 側に足される値は `Unknown` に落とす。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PluginPeerRejection {
    /// 接続元の uid が期待値と違う。
    PeerUidMismatch,
    /// 接続元の uid を取得できなかった。
    PeerUidUnavailable,
    /// 接続元の pid が期待値と違う。
    PeerPidMismatch,
    /// 接続元の pid を取得できなかった。
    PeerPidUnavailable,
    /// 上記以外（呼び出し側が知らない理由。落とさず記録するための受け皿）。
    Unknown,
}

impl PluginPeerRejection {
    /// 監査レコードに入る静的トークン。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerUidMismatch => "plugin_peer_uid_mismatch",
            Self::PeerUidUnavailable => "plugin_peer_uid_unavailable",
            Self::PeerPidMismatch => "plugin_peer_pid_mismatch",
            Self::PeerPidUnavailable => "plugin_peer_pid_unavailable",
            Self::Unknown => "plugin_peer_unknown",
        }
    }

    /// 受け付けた socket のパスから監査イベントを返す。
    pub fn audit_event(self, path: &Path) -> AuditEvent {
        AuditEvent::PluginPeer {
            path: AuditPath::new(path),
            reason: AuditReason::new(self.as_str()),
        }
    }
}

impl AuditEvent {
    /// 対応するレイヤーを返す。
    pub fn layer(&self) -> AuditLayer {
        match self {
            AuditEvent::Seccomp { .. } => AuditLayer::Seccomp,
            AuditEvent::Landlock { .. } => AuditLayer::Landlock,
            AuditEvent::Mount { .. } => AuditLayer::Mount,
            AuditEvent::PluginTrust { .. } => AuditLayer::PluginTrust,
            AuditEvent::PluginPeer { .. } => AuditLayer::PluginPeer,
            AuditEvent::ExecTarget { .. } => AuditLayer::ExecTarget,
            AuditEvent::Entrypoint { .. } => AuditLayer::Entrypoint,
            AuditEvent::PastaVerify { .. } => AuditLayer::PastaVerify,
            AuditEvent::ControlPeer { .. } => AuditLayer::ControlChannel,
            AuditEvent::ExitSignal { .. } => AuditLayer::ExitSignal,
            AuditEvent::AuditCoverageDegraded { .. } => AuditLayer::AuditCoverage,
        }
    }
}

/// 固定スキーマの監査レコード（SEC-4）。
///
/// # `pid` と `container_id` の意味（#1618）
///
/// - [`AuditRecord::pid`] は**記録を組み立てたプロセス**の PID であり、違反した側とは限らない。
///   mount・exec_target・entrypoint の層（`mount::deliver` 経由）では supervisor・exec の親・launch の側の
///   PID で、違反したプロセスでも pid1 でもない。seccomp は報告元（ハンドラ / listener）が伝えた
///   違反プロセスの PID（[`SeccompDenialReport`] の契約）、landlock は `landlock_denial_record_now` を
///   呼んだプロセスの PID
/// - 「どのコンテナに対する試行か」は [`AuditRecord::container_id`] で取る。検証済みの
///   [`ContainerId`]（文字種 `[A-Za-z0-9._-]`・255 バイト以下）だけを載せるので、ログ注入の
///   経路にならず、パスなどホスト構成も出ない（REPAIR-2）。ID が不明な呼び出し側は載せない（`None`）
///
/// # 将来仕様（REPAIR-3）
///
/// 対象 pid1 の PID は載せない。`StateRecord` の pid は `identify_pid1` を通るまで未検証の候補で、
/// exec_target の拒否はその検証が失敗した場合なので、載せると未検証の値を「対象」と誤記する
/// 恐れがある（PID の再利用もあり得る）。検証済み pid1 の記録は別設計（TASK-41 追補・TASK-163）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditRecord {
    timestamp: AuditTimestamp,
    pid: AuditPid,
    event: AuditEvent,
    container_id: Option<ContainerId>,
    stage: Option<AuditStage>,
}

impl AuditRecord {
    /// 検証済みの要素から組み立てる（失敗しない）。
    pub fn new(timestamp: AuditTimestamp, pid: AuditPid, event: AuditEvent) -> Self {
        Self {
            timestamp,
            pid,
            event,
            container_id: None,
            stage: None,
        }
    }

    /// 拒否した段を載せる（SEC-4・ERR-4・#3121）。
    ///
    /// 経路検査の拒否は汎用の理由トークンで記録されるため、どの段（readonly_paths か masked_paths か等）
    /// の拒否かは `ExecError::stage` にしか無かった。段を知る呼び出し側（`exec` の記録点）だけがこれで足す。
    /// 段を持たない記録ではワイヤーにキー自体を出さず、既存の行は変わらない。
    /// 制御チャネルの中継（`ControlAuditRelay`）は枠が段を運ばないので、通すと段は落ちる（REPAIR-3。試験で固定、
    /// 理由はモジュール doc の「段を載せない記録点と理由」。#3209）。
    #[must_use]
    pub(crate) fn with_stage(mut self, stage: AuditStage) -> Self {
        self.stage = Some(stage);
        self
    }

    /// 記録に載せた段。載せない記録は `None`（ワイヤーではキー自体が無い）。
    pub fn stage(&self) -> Option<AuditStage> {
        self.stage
    }

    /// 検証済みのコンテナ ID を載せる（#1618）。
    ///
    /// [`ContainerId`] は構築時に文字種・長さが検証済みなので、ファイル（JSON Lines）にも
    /// カーネル監査の key=value にも生の値で出せる。`new` のシグネチャは変えず、ID を知る
    /// 呼び出し側（`mount::deliver` 等）だけがこれで足す。
    #[must_use]
    pub fn with_container_id(mut self, id: ContainerId) -> Self {
        self.container_id = Some(id);
        self
    }

    /// 記録に載せたコンテナ ID。不明な呼び出し側の記録は `None`（ワイヤーでは null / `?`）。
    pub fn container_id(&self) -> Option<&ContainerId> {
        self.container_id.as_ref()
    }

    /// 発生時刻。
    pub fn timestamp(&self) -> AuditTimestamp {
        self.timestamp
    }

    /// 記録を組み立てたプロセスの PID（層ごとの意味は [`AuditRecord`] の doc）。
    ///
    /// 「違反したプロセス」とは限らない。コンテナとの対応は [`AuditRecord::container_id`] で取る。
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
            | AuditEvent::PluginPeer { .. }
            | AuditEvent::ExecTarget { .. }
            | AuditEvent::Entrypoint { .. }
            | AuditEvent::PastaVerify { .. }
            | AuditEvent::ControlPeer { .. }
            | AuditEvent::ExitSignal { .. }
            | AuditEvent::AuditCoverageDegraded { .. } => None,
        }
    }

    /// 終了シグナル（[`AuditEvent::ExitSignal`] のみ。他は `None`）。
    pub fn exit_signal(&self) -> Option<AuditSignal> {
        match &self.event {
            AuditEvent::ExitSignal { signal, .. } => Some(*signal),
            _ => None,
        }
    }

    /// 終了したプロセスの PID（[`AuditEvent::ExitSignal`] のみ。回収した側の PID namespace の値）。
    pub fn target_pid(&self) -> Option<AuditPid> {
        match &self.event {
            AuditEvent::ExitSignal { target_pid, .. } => Some(*target_pid),
            _ => None,
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
            | AuditEvent::Entrypoint { .. }
            | AuditEvent::PastaVerify { .. }
            | AuditEvent::ControlPeer { .. }
            | AuditEvent::ExitSignal { .. }
            | AuditEvent::AuditCoverageDegraded { .. } => None,
            AuditEvent::Landlock { path, .. } => Some(path.as_path()),
            AuditEvent::Mount { path, .. } => path.as_ref().map(AuditPath::as_path),
            AuditEvent::PluginTrust { path, .. } | AuditEvent::PluginPeer { path, .. } => {
                Some(path.as_path())
            }
        }
    }

    /// 縮退の理由トークン（[`AuditEvent::AuditCoverageDegraded`] のみ。`(seccomp_kill, landlock)`）。
    pub fn coverage_reasons(&self) -> Option<(Option<AuditReason>, Option<AuditReason>)> {
        match &self.event {
            AuditEvent::AuditCoverageDegraded {
                seccomp_kill,
                landlock,
            } => Some((*seccomp_kill, *landlock)),
            _ => None,
        }
    }

    /// 拒否理由トークン（plugin_trust・plugin_peer・exec_target・entrypoint・pasta_verify・control_channel、
    /// および理由を持つ mount のレコード。seccomp・landlock・exit_signal・理由なしの mount は `None`。
    /// audit_coverage の理由は 2 欄に分かれるため `coverage_reasons()` で得る）。
    pub fn reason(&self) -> Option<AuditReason> {
        match &self.event {
            AuditEvent::Mount { reason, .. } => *reason,
            AuditEvent::PluginTrust { reason, .. }
            | AuditEvent::PluginPeer { reason, .. }
            | AuditEvent::ExecTarget { reason }
            | AuditEvent::Entrypoint { reason }
            | AuditEvent::PastaVerify { reason }
            | AuditEvent::ControlPeer { reason } => Some(*reason),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-4・#1701: 理由つきの `Mount` は `reason()` が静的トークンを返し、理由なしは `None`。
    #[test]
    fn sec4_1701_mount_reason_accessor() {
        let with = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
            AuditPid::new(9).unwrap(),
            AuditEvent::Mount {
                path: None,
                reason: Some(AuditReason::new("rootfs_is_host_root")),
            },
        );
        assert_eq!(
            with.reason().map(|r| r.as_str()),
            Some("rootfs_is_host_root")
        );
        assert_eq!(with.path(), None);
        let without = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
            AuditPid::new(9).unwrap(),
            AuditEvent::Mount {
                path: None,
                reason: None,
            },
        );
        assert_eq!(without.reason(), None);
    }

    /// SEC-4・ESC-06・#2004: `ExitSignal` は syscall・arch・パスを持たず、シグナルと対象 PID を返す。
    /// `AuditSignal` は `1..=64` だけ受け付ける。
    #[test]
    fn sec4_2004_exit_signal_record_has_no_syscall() {
        let r = AuditRecord::new(
            ts(),
            pid(9),
            AuditEvent::ExitSignal {
                signal: AuditSignal::new(31).unwrap(),
                target_pid: pid(1234),
            },
        );
        assert_eq!(r.layer(), AuditLayer::ExitSignal);
        assert_eq!(r.layer().as_str(), "exit_signal");
        assert_eq!(r.syscall(), None);
        assert_eq!(r.seccomp_arch(), None);
        assert_eq!(r.path(), None);
        assert_eq!(r.reason(), None);
        assert_eq!(r.exit_signal().map(AuditSignal::get), Some(31));
        assert_eq!(r.target_pid().map(AuditPid::get), Some(1234));
        for bad in [0, 65, -1] {
            assert_eq!(
                AuditSignal::new(bad).unwrap_err().kind(),
                AuditRecordErrorKind::SignalOutOfRange
            );
        }
        for ok in [1u8, 31, 64] {
            assert_eq!(AuditSignal::new(i32::from(ok)).unwrap().get(), ok);
        }
    }

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
                reason: None,
            },
        );
        assert_eq!(with.layer(), AuditLayer::Mount);
        assert_eq!(with.path(), Some(Path::new("/proc/sys")));
        assert_eq!(with.syscall(), None);
        let without = AuditRecord::new(
            ts(),
            pid(9),
            AuditEvent::Mount {
                path: None,
                reason: None,
            },
        );
        assert_eq!(without.path(), None);
    }

    #[test]
    fn sec4_task41_1_layer_tokens() {
        assert_eq!(AuditLayer::Seccomp.as_str(), "seccomp");
        assert_eq!(AuditLayer::Landlock.as_str(), "landlock");
        assert_eq!(AuditLayer::Mount.as_str(), "mount");
        assert_eq!(AuditLayer::ExecTarget.as_str(), "exec_target");
        assert_eq!(AuditLayer::Entrypoint.as_str(), "entrypoint");
        assert_eq!(AuditLayer::ControlChannel.as_str(), "control_channel");
        assert_eq!(
            ControlPeerRejection::PeerUidMismatch.as_str(),
            "control_peer_uid_mismatch"
        );
        assert_eq!(
            ControlPeerRejection::PeerCredentialsUnavailable
                .audit_event()
                .layer(),
            AuditLayer::ControlChannel
        );
    }

    /// SEC-4・NET-9・#3330: pasta_verify の層トークン・理由トークン・レコードのアクセサ（パスを持たない）。
    #[test]
    fn sec4_3330_pasta_verify_tokens_and_accessors() {
        assert_eq!(AuditLayer::PastaVerify.as_str(), "pasta_verify");
        assert_eq!(
            PastaVerifyRejection::RecordChanged.as_str(),
            "pasta_record_changed"
        );
        assert_eq!(
            PastaVerifyRejection::PermissionDenied.as_str(),
            "pasta_permission_denied"
        );
        let r = AuditRecord::new(
            AuditTimestamp::from_unix_duration(Duration::new(1_700_000_000, 5)),
            AuditPid::new(9).unwrap(),
            PastaVerifyRejection::PermissionDenied.audit_event(),
        );
        assert_eq!(r.layer(), AuditLayer::PastaVerify);
        assert_eq!(
            r.reason().map(AuditReason::as_str),
            Some("pasta_permission_denied")
        );
        assert!(r.path().is_none());
        assert!(r.syscall().is_none());
    }

    /// SEC-4・PLUG-12・#2484: plugin_peer の理由トークン 5 種・層トークン・パスと理由のアクセサ。
    #[test]
    fn sec4_2484_plugin_peer_tokens_and_accessors() {
        assert_eq!(AuditLayer::PluginPeer.as_str(), "plugin_peer");
        let tokens = [
            (
                PluginPeerRejection::PeerUidMismatch,
                "plugin_peer_uid_mismatch",
            ),
            (
                PluginPeerRejection::PeerUidUnavailable,
                "plugin_peer_uid_unavailable",
            ),
            (
                PluginPeerRejection::PeerPidMismatch,
                "plugin_peer_pid_mismatch",
            ),
            (
                PluginPeerRejection::PeerPidUnavailable,
                "plugin_peer_pid_unavailable",
            ),
            (PluginPeerRejection::Unknown, "plugin_peer_unknown"),
        ];
        for (rejection, token) in tokens {
            assert_eq!(rejection.as_str(), token);
            let rec = AuditRecord::new(
                AuditTimestamp::from_unix_duration(Duration::new(1, 0)),
                AuditPid::new(1).unwrap(),
                rejection.audit_event(Path::new("/s.sock")),
            );
            assert_eq!(rec.layer(), AuditLayer::PluginPeer);
            assert_eq!(rec.path(), Some(Path::new("/s.sock")));
            assert_eq!(rec.reason().map(AuditReason::as_str), Some(token));
            assert_eq!(rec.syscall(), None);
            assert_eq!(rec.container_id(), None);
        }
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
    fn sec4_task41_1618_record_container_id_accessor() {
        let rec = AuditRecord::new(
            ts(),
            pid(7),
            AuditEvent::Mount {
                path: None,
                reason: None,
            },
        );
        assert_eq!(rec.container_id(), None);
        let with = rec.with_container_id(ContainerId::new("c1").unwrap());
        assert_eq!(with.container_id().map(ContainerId::as_str), Some("c1"));
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
                reason: None,
            },
        );
        assert_eq!(mount.path().map(|p| p.as_os_str().len()), Some(4096));
    }

    #[test]
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn sec4_task41_1_from_table_syscall_nr() {
        use crate::seccomp::{DeniedSyscall, SyscallLookup};
        let table = crate::seccomp::table_for_target_arch().unwrap();
        let SyscallLookup::Present(nr) = table.number_of(DeniedSyscall::Unshare) else {
            panic!("unshare must be present in the host table");
        };
        let expected = if cfg!(all(target_arch = "x86_64", target_pointer_width = "64")) {
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
