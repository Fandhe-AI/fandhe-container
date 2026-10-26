//! launch 経路の pivot 前段の結果を、子から親へ返す状態 pipe のワイヤー形式と判定（TASK-29 追補・#1815。
//! SEC-4・CORE-2・REPAIR-2・REPAIR-5）。
//!
//! # 役割と呼び出し文脈
//!
//! `process::run_pre_pivot`（fork 後の子。`config.json` 由来の値を処理した後の untrusted なプロセス）の各段が
//! 失敗しても、親は終了コードしか見えず、どの段がどの理由で失敗したか分からない。そこで子は pivot 前段の結果を
//! bounded な pipe に 1 行書き（[`report_ready`]・[`report_failure`]）、親は期限つきで読んで
//! （[`read_pre_pivot_status`]）判定し（[`resolve_pre_pivot_status`]）、拒否を呼び出し側から受け取った
//! `AuditSink` へ書く。**子は sink に触らない**。呼び出し元は `launch_intermediate::spawn_container_via_intermediate`
//! だけで、本番 launcher（`oci_runtime::ProductionLauncher`。#1816）が呼ぶ。
//!
//! # ワイヤー形式（ASCII 1 行・LF 終端・最大 [`PRE_PIVOT_STATUS_MAX_BYTES`] バイト）
//!
//! ```text
//! P\n                                  pivot 前段がすべて成功
//! F <step> <CODE> <reason|->\n         段 <step> が失敗（<CODE> は ErrorCode、<reason> は違反理由コードか -）
//! ```
//!
//! # exec 前の 2 行目（entrypoint 系の違反。SEC-4・#2624）
//!
//! 上の 1 行目（`P`）の後、PID 1 は seccomp の listener を送って C の ACK を待ち、エントリポイントの検証
//! （`process::prepare_exec_child`）を経て `execveat` する。この検証の違反（`ViolationReason::ENTRYPOINT_REASONS`
//! の 8 理由）を C が監査に記録できるよう、同じ状態 pipe に 2 行目を書く。
//!
//! ```text
//! R\n                                  検証の全手順が通り、`execveat` を呼ぶ直前
//! E <CODE> <reason|->\n                `execveat` の前の手順が失敗（<reason> は entrypoint 系の理由コードか -）
//! X <CODE>\n                           `R` の後の `execveat` が戻った（errno 由来の失敗。#2716）
//! ```
//!
//! 1 行目と 2 行目は先頭のトークン（`P`/`F` と `R`/`E`）で字句上も分かれ、取り違えは `Malformed` になる。
//! 2 行目は C が `P` を読み終え、listener を受け取って ACK を返した**後**にしか書かれない（PID 1 は ACK を待ってから
//! 検証へ進み、C は `P` の判定より前に listener を受け取らない）ため、2 行が 1 回の `read` に混ざらない。
//! 復号は 1 行目と同じく厳格で、理由は `ViolationReason::from_entrypoint_token`（固定語彙の走査）で静的な値へ
//! 引き直す。
//!
//! # `R` の後の `execveat` の失敗（`X`。SEC-4・CORE-5・ERR-1・#2716）
//!
//! `R` の後に `execveat` が errno で失敗したら、子は `R` に続けて `X <CODE>` を書く。`<CODE>` は
//! `process::exec_errno_to_code` による errno の分類（`ErrorCode` の名前のみ。errno の生値・文字列は運ばない）。
//! 親は `R` の後も書き込み側が全て閉じる（EOF）まで読む（[`read_exec_phase_until_close`]）。EOF だけなら
//! `execveat` の成功（状態 pipe は close-on-exec）、`X` が届けば起動失敗で、PID 1 は回収する。
//! 完成した失敗報告（`E` 行、`R` に続く `X` 行）は EOF を待たずに判定する（子が stderr で詰まっても `Timeout` に置き換えない。REPAIR-5）。
//! 受理する形は `R\n`・`R\nX <CODE>\n`・`E ...\n` の 3 つだけで、それ以外は `Malformed`（fail-closed）。
//! **`X` は監査に記録しない**: ENOENT・ENOEXEC 等は設定の誤りで違反ではなく、EACCES・EPERM は DAC・noexec・
//! Landlock・LSM のどれによるかをユーザー空間から区別できず、Landlock / LSM の拒否はカーネル側の監査が担うため
//! （誤記録と二重記録を避ける。この判断はオーナーが見直し得るもので、承認済みではない）。既知の限界:
//! `R` から `execveat` の完了までの間にシグナルで死ぬと EOF になり成功と判定される（EOF の後の生存確認は、
//! すぐ終わる正当なプログラムを誤って失敗にするため入れない）。
//!
//! 運ぶのは段の名前・`ErrorCode`・任意の違反理由コードだけで、英語メッセージ・パス・errno 文字列は運ばない。
//! 復号は厳格（単一スペース区切り・フィールド数固定・全トークンが許可リスト内・末尾に余分なバイト無し）で、
//! 親は固定語彙の許可リストで引き直した静的トークンだけを監査レコードに入れる。`CODE` と `reason` の整合
//! （`reason.error_code()` との一致）は検査しない: `CODE` は情報用で、記録の有無は `reason` だけで決まるため
//! （段 `mount_binds` と組で受ける user namespace 由来の 2 理由〔#2072〕も同じ規則）。段と理由の整合は
//! 段つきの許可リスト（[`launch_violation`]）で検査する。ただし保護の適用失敗の 2 理由（段 `readonly_paths` /
//! `masked_paths` と組。SEC-4・SEC-2・#2013）に限り、親は `CODE` を復号した `ExecError::code` に使う（errno 由来の
//! 分類を保つため。`CODE` は許可リストの `ErrorCode` 語彙に限られ、記録の有無・理由は変わらない）。

use std::io::{Read as _, Write as _};
use std::os::fd::AsFd as _;
use std::time::{Duration, Instant};

use crate::audit_log::{AuditSink, AuditedRejection};
use crate::sys::{self, SysError};
use crate::traits::ContainerId;
use crate::traits::types::ErrorCode;

use super::{
    ExecError, IsolationStage, ViolationKind, ViolationReason, audit_entrypoint_violation,
    record_launch_mount_rejection,
};

/// 状態行の最大バイト数（LF を含む）。最長の行は約 85 バイトで、それより十分大きい固定上限。
pub(super) const PRE_PIVOT_STATUS_MAX_BYTES: usize = 160;

/// 読み取りの期限に許す最大値（`Instant` の加算オーバーフローを避ける丸め）。
const READ_TIMEOUT_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// pivot 前段の段（`process::run_pre_pivot` の呼び出し順）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum PrePivotStep {
    /// mount namespace の分離の確立。
    Establish,
    /// rootfs の準備。
    PrepareRootfs,
    /// 固定した rootfs との実体の照合。
    VerifyPinned,
    /// `/sys` への sysfs の供給（`mounts[]` の sysfs の指定時のみ。#2020・SEC-2）。`readonly_paths` より前に載せる。
    MountSysfs,
    /// 専用 `/dev` の作成。
    CreateDefaultDevices,
    /// tmpfs のマウント。
    MountTmpfs,
    /// ファイルの注入。
    InjectFiles,
    /// 検証済み bind mount の適用（指定時のみ。#1914）。user namespace 由来の 2 理由（SEC-5。
    /// `ViolationReason::MOUNT_BINDS_USER_NAMESPACE_REASONS`）は、この段に限って許可リストに入り、
    /// 親へ届いて層 `mount` に記録される（#2072）。他の段では `Malformed`。
    MountBinds,
    /// 読み取り専用にするパスの固定集合の適用（`setup` の有無によらず常に走る。#1850）。
    ReadonlyPaths,
    /// 覆うパスの固定集合の適用（`setup` 指定時のみ。検証済みの `/dev/null` が要るため。#1851）。
    MaskedPaths,
    /// `pivot_root`。
    PivotRoot,
    /// pivot 後の作業ディレクトリへの `chdir`（`process.cwd`。OCI-1・TASK-29。違反記録は運ばない）。
    WorkingDir,
}

impl PrePivotStep {
    const ALL: [Self; 12] = [
        Self::Establish,
        Self::PrepareRootfs,
        Self::VerifyPinned,
        Self::MountSysfs,
        Self::CreateDefaultDevices,
        Self::MountTmpfs,
        Self::InjectFiles,
        Self::MountBinds,
        Self::ReadonlyPaths,
        Self::MaskedPaths,
        Self::PivotRoot,
        Self::WorkingDir,
    ];

    /// 段名（ワイヤー上のトークン。単体テストの `RecordingOps` の段名と一致させる）。
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Establish => "establish",
            Self::PrepareRootfs => "prepare_rootfs",
            Self::VerifyPinned => "verify_pinned",
            Self::MountSysfs => "mount_sysfs",
            Self::CreateDefaultDevices => "create_default_devices",
            Self::MountTmpfs => "mount_tmpfs",
            Self::InjectFiles => "inject_files",
            Self::MountBinds => "mount_binds",
            Self::ReadonlyPaths => "readonly_paths",
            Self::MaskedPaths => "masked_paths",
            Self::PivotRoot => "pivot_root",
            Self::WorkingDir => "working_dir",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == token)
    }

    /// 段に対応する `ExecError::stage`（親が段名から写像する。ステージ自体は運ばない）。
    pub(super) fn stage(self) -> IsolationStage {
        match self {
            Self::Establish => IsolationStage::MountPrivate,
            Self::PrepareRootfs | Self::VerifyPinned => IsolationStage::PrepareRootfs,
            Self::MountSysfs => IsolationStage::MountSysfs,
            Self::CreateDefaultDevices => IsolationStage::CreateDevices,
            Self::MountTmpfs => IsolationStage::MountTmpfs,
            Self::InjectFiles => IsolationStage::InjectFiles,
            Self::MountBinds => IsolationStage::MountBinds,
            Self::ReadonlyPaths => IsolationStage::MountReadonlyPaths,
            Self::MaskedPaths => IsolationStage::MountMaskedPaths,
            Self::PivotRoot => IsolationStage::PivotRoot,
            Self::WorkingDir => IsolationStage::WorkingDir,
        }
    }
}

/// 段つきの許可リスト照合（子の符号化と親の復号で共有する唯一の規則。#2072）。
///
/// `ViolationReason::from_launch_token` が通す理由に加え、段 `MountBinds` に限って user namespace 由来の 2 理由
/// （SEC-5）を `Some` にする。子は untrusted なので、文字列は固定語彙の走査で静的な値へ引き直す。
fn launch_violation(step: PrePivotStep, token: &str) -> Option<ViolationReason> {
    if let Some(r) = ViolationReason::from_launch_token(token) {
        return Some(r);
    }
    match step {
        PrePivotStep::MountBinds => ViolationReason::MOUNT_BINDS_USER_NAMESPACE_REASONS
            .into_iter()
            .find(|r| r.as_str() == token),
        // 保護の適用失敗は、自分の段の理由だけを通す（段と理由の食い違いは `Malformed`。#2013）。
        PrePivotStep::ReadonlyPaths | PrePivotStep::MaskedPaths | PrePivotStep::MountSysfs => {
            ViolationReason::PROTECTED_PATH_APPLY_REASONS
                .into_iter()
                .find(|r| r.as_str() == token && r.stage() == step.stage())
        }
        _ => None,
    }
}

/// 子が報告する pivot 前段の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PrePivotFailure {
    pub(super) step: PrePivotStep,
    pub(super) code: ErrorCode,
    /// 違反理由（許可リストの種別のものだけ。それ以外は `None`）。
    pub(super) violation: Option<ViolationReason>,
}

impl PrePivotFailure {
    /// 子側の唯一の作成入口。許可リスト外の違反理由は落とす（失敗として報告する点は変わらない）。
    pub(super) fn from_exec_error(step: PrePivotStep, error: &ExecError) -> Self {
        let violation = error
            .violation
            .as_ref()
            .and_then(|v| launch_violation(step, v.reason.as_str()));
        Self {
            step,
            code: error.code,
            violation,
        }
    }
}

/// pivot 前段の結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PrePivotStatus {
    /// すべての段が成功した。
    Ready,
    /// いずれかの段が失敗した。
    Failed(PrePivotFailure),
}

/// 符号化済みの状態行（固定長配列＋長さ。`Vec` を手で組まない。REPAIR-2）。
#[derive(Debug, Clone, Copy)]
pub(super) struct EncodedStatus {
    buf: [u8; PRE_PIVOT_STATUS_MAX_BYTES],
    len: usize,
}

impl EncodedStatus {
    pub(super) fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    fn push(&mut self, part: &str) -> bool {
        let end = self.len.saturating_add(part.len());
        match self.buf.get_mut(self.len..end) {
            Some(dst) => {
                dst.copy_from_slice(part.as_bytes());
                self.len = end;
                true
            }
            None => false,
        }
    }
}

/// 符号化が上限に収まらないときの失敗行（到達しない想定。成功行に落とさず失敗側へ倒す）。
const FALLBACK_FAILURE: &[u8] = b"F pivot_root INTERNAL -\n";

impl PrePivotStatus {
    /// 状態行へ符号化する。
    pub(super) fn encode(&self) -> EncodedStatus {
        let mut out = EncodedStatus {
            buf: [0; PRE_PIVOT_STATUS_MAX_BYTES],
            len: 0,
        };
        let ok = match self {
            Self::Ready => out.push("P\n"),
            Self::Failed(f) => {
                out.push("F ")
                    && out.push(f.step.as_str())
                    && out.push(" ")
                    && out.push(f.code.as_str())
                    && out.push(" ")
                    && out.push(f.violation.map_or("-", ViolationReason::as_str))
                    && out.push("\n")
            }
        };
        if !ok {
            out.len = 0;
            if let Some(dst) = out.buf.get_mut(..FALLBACK_FAILURE.len()) {
                dst.copy_from_slice(FALLBACK_FAILURE);
                out.len = FALLBACK_FAILURE.len();
            }
        }
        out
    }

    /// 末尾の LF を含む 1 行を厳格に復号する（純関数。許可リスト外・形式違反は `Malformed`）。
    pub(super) fn decode(line: &[u8]) -> Result<Self, PrePivotStatusError> {
        let body = line
            .strip_suffix(b"\n")
            .ok_or(PrePivotStatusError::Malformed)?;
        let text = std::str::from_utf8(body).map_err(|_| PrePivotStatusError::Malformed)?;
        let parts: Vec<&str> = text.split(' ').collect();
        match parts.as_slice() {
            ["P"] => Ok(Self::Ready),
            ["F", step, code, reason] => {
                let step = PrePivotStep::from_token(step).ok_or(PrePivotStatusError::Malformed)?;
                let code = ErrorCode::from_name(code).ok_or(PrePivotStatusError::Malformed)?;
                let violation = if *reason == "-" {
                    None
                } else {
                    Some(launch_violation(step, reason).ok_or(PrePivotStatusError::Malformed)?)
                };
                Ok(Self::Failed(PrePivotFailure {
                    step,
                    code,
                    violation,
                }))
            }
            _ => Err(PrePivotStatusError::Malformed),
        }
    }
}

/// 親が状態を読めなかった理由（すべて起動失敗として扱う。fail-closed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum PrePivotStatusError {
    /// 期限内に行が完成しなかった（REPAIR-5）。
    Timeout,
    /// 何も書かれないまま書き込み側が閉じた（子が報告前に終了した）。
    ClosedBeforeReport,
    /// 改行の前に書き込み側が閉じた。
    Truncated,
    /// 上限を超える長さの行。
    TooLong,
    /// 形式違反・許可リスト外・末尾の余分なバイト。
    Malformed,
    /// poll / read の失敗。
    Io,
}

impl PrePivotStatusError {
    /// 起動失敗の `ExecError` へ写す（固定の英語メッセージ。`Timeout` だけ `ErrorCode::Timeout`）。
    pub(super) fn to_exec_error(self) -> ExecError {
        let (code, what) = match self {
            Self::Timeout => (
                ErrorCode::Timeout,
                "timed out waiting for the pre-pivot status",
            ),
            Self::ClosedBeforeReport => (
                ErrorCode::Internal,
                "the container child exited before reporting the pre-pivot status",
            ),
            Self::Truncated => (ErrorCode::Internal, "the pre-pivot status was truncated"),
            Self::TooLong => (ErrorCode::Internal, "the pre-pivot status is too long"),
            Self::Malformed => (ErrorCode::Internal, "the pre-pivot status is malformed"),
            Self::Io => (ErrorCode::Internal, "cannot read the pre-pivot status pipe"),
        };
        ExecError::new(code, IsolationStage::Spawn, what)
    }
}

/// 子側: 成功行 `P` を 1 回の `write_all` で書く。
pub(super) fn report_ready(status: &std::fs::File) -> Result<(), ExecError> {
    write_status(status, &PrePivotStatus::Ready.encode())
}

/// 子側: 失敗行 `F ...` を 1 回の `write_all` で書く。
pub(super) fn report_failure(
    status: &std::fs::File,
    failure: &PrePivotFailure,
) -> Result<(), ExecError> {
    write_status(status, &PrePivotStatus::Failed(*failure).encode())
}

fn write_status(mut status: &std::fs::File, line: &EncodedStatus) -> Result<(), ExecError> {
    // fd を複製せずに直接書く（失敗要因を `write` だけにする。`exec` の状態 pipe と同じ流儀）。
    status
        .write_all(line.as_bytes())
        .map_err(|e| ExecError::from_io(&e, IsolationStage::Spawn, "report the pre-pivot status"))
}

/// 親側: 状態 pipe（読み取り側）から 1 行を期限つきで読んで復号する（REPAIR-5）。
///
/// 期限は全体で `timeout`（1 バイトずつ滴下されても延びない）。バッファは `PRE_PIVOT_STATUS_MAX_BYTES` を
/// 超えて読まない。親は fork 直後に書き込み側を閉じていること（EOF を観測できる条件）。
pub(super) fn read_pre_pivot_status(
    status: &std::fs::File,
    timeout: Duration,
) -> Result<PrePivotStatus, PrePivotStatusError> {
    let (buf, end) = read_line_bounded::<PRE_PIVOT_STATUS_MAX_BYTES>(status, timeout)?;
    PrePivotStatus::decode(buf.get(..end).unwrap_or(&[]))
}

/// pipe から LF 終端の 1 行を、全体で `timeout`・最大 `N` バイトの範囲で読む（REPAIR-5）。
///
/// 戻り値は `(バッファ, LF を含む行の長さ)`。行の後ろに余分なバイトがあれば `Malformed`、`N` バイト以内に LF が
/// 無ければ `TooLong`、行の完成前に EOF なら `ClosedBeforeReport`（0 バイト）または `Truncated`。pivot 前段の状態行
/// と、中間プロセスの報告行（`launch_intermediate`）が共用する。
pub(super) fn read_line_bounded<const N: usize>(
    pipe: &std::fs::File,
    timeout: Duration,
) -> Result<([u8; N], usize), PrePivotStatusError> {
    let deadline = Instant::now() + timeout.min(READ_TIMEOUT_MAX);
    let mut buf = [0u8; N];
    let mut filled = 0usize;
    loop {
        if let Some(pos) = buf
            .get(..filled)
            .and_then(|b| b.iter().position(|c| *c == b'\n'))
        {
            let end = pos + 1;
            if end < filled {
                return Err(PrePivotStatusError::Malformed);
            }
            return Ok((buf, end));
        }
        let Some(rest) = buf.get_mut(filled..).filter(|r| !r.is_empty()) else {
            return Err(PrePivotStatusError::TooLong);
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        // ミリ秒へ切り上げ、`i32` に飽和させる。
        let millis = remaining.as_millis().saturating_add(u128::from(
            !remaining.subsec_nanos().is_multiple_of(1_000_000),
        ));
        let millis = i32::try_from(millis).unwrap_or(i32::MAX);
        match sys::poll_readable(pipe.as_fd(), millis) {
            Ok(true) => {}
            Ok(false) => {
                if Instant::now() >= deadline {
                    return Err(PrePivotStatusError::Timeout);
                }
                continue;
            }
            Err(SysError::Os(errno)) if errno == sys::EINTR => continue,
            Err(_) => return Err(PrePivotStatusError::Io),
        }
        match (&*pipe).read(rest) {
            Ok(0) => {
                return Err(if filled == 0 {
                    PrePivotStatusError::ClosedBeforeReport
                } else {
                    PrePivotStatusError::Truncated
                });
            }
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(PrePivotStatusError::Io),
        }
    }
}

/// exec 前の 2 行目（モジュール doc の「exec 前の 2 行目」）の復号結果。
///
/// 1 行目（[`PrePivotStatus`]）と別の型にして、`P`/`F` と `R`/`E` の取り違えを型で防ぐ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecPhaseStatus {
    /// エントリポイントの検証の全手順が通り、`execveat` を呼ぶ直前。
    Ready,
    /// `execveat` の前の手順が失敗した。
    Failed {
        code: ErrorCode,
        /// entrypoint 系の違反理由（`ENTRYPOINT_REASONS` のものだけ。それ以外は `None`）。
        violation: Option<ViolationReason>,
    },
    /// `R` を書いた後の `execveat` 自体が戻った（errno 由来の失敗。#2716）。`code` は errno の分類
    /// （`process::exec_errno_to_code`）。errno の生値・文字列は運ばない。
    Returned { code: ErrorCode },
}

impl ExecPhaseStatus {
    /// 子側の唯一の作成入口。entrypoint 系以外の理由は落とす（失敗として報告する点は変わらない）。
    pub(super) fn failed_from(error: &ExecError) -> Self {
        Self::Failed {
            code: error.code,
            violation: error
                .violation
                .as_ref()
                .and_then(|v| ViolationReason::from_entrypoint_token(v.reason.as_str())),
        }
    }

    /// 状態行へ符号化する。
    pub(super) fn encode(&self) -> EncodedStatus {
        let mut out = EncodedStatus {
            buf: [0; PRE_PIVOT_STATUS_MAX_BYTES],
            len: 0,
        };
        let ok = match self {
            Self::Ready => out.push("R\n"),
            Self::Failed { code, violation } => {
                out.push("E ")
                    && out.push(code.as_str())
                    && out.push(" ")
                    && out.push(violation.map_or("-", ViolationReason::as_str))
                    && out.push("\n")
            }
            Self::Returned { code } => out.push("X ") && out.push(code.as_str()) && out.push("\n"),
        };
        if !ok {
            // 到達しない想定。成功行に落とさず、理由なしの失敗へ倒す。
            out.len = 0;
            let _ = out.push("E INTERNAL -\n");
        }
        out
    }

    /// 末尾の LF を含む 1 行を厳格に復号する（純関数。許可リスト外・形式違反は `Malformed`）。
    pub(super) fn decode(line: &[u8]) -> Result<Self, PrePivotStatusError> {
        let body = line
            .strip_suffix(b"\n")
            .ok_or(PrePivotStatusError::Malformed)?;
        let text = std::str::from_utf8(body).map_err(|_| PrePivotStatusError::Malformed)?;
        let parts: Vec<&str> = text.split(' ').collect();
        match parts.as_slice() {
            ["R"] => Ok(Self::Ready),
            ["X", code] => Ok(Self::Returned {
                code: ErrorCode::from_name(code).ok_or(PrePivotStatusError::Malformed)?,
            }),
            ["E", code, reason] => {
                let code = ErrorCode::from_name(code).ok_or(PrePivotStatusError::Malformed)?;
                let violation = if *reason == "-" {
                    None
                } else {
                    Some(
                        ViolationReason::from_entrypoint_token(reason)
                            .ok_or(PrePivotStatusError::Malformed)?,
                    )
                };
                Ok(Self::Failed { code, violation })
            }
            _ => Err(PrePivotStatusError::Malformed),
        }
    }
}

/// 子側: `execveat` の直前に `R` を 1 回の `write_all` で書く。書けなければ `execveat` へ進まない（fail-closed）。
pub(super) fn report_exec_ready(status: &std::fs::File) -> Result<(), ExecError> {
    write_status(status, &ExecPhaseStatus::Ready.encode())
}

/// 子側: `execveat` の前の手順の失敗 `error` を `E ...` として書く。
pub(super) fn report_exec_failure(
    status: &std::fs::File,
    error: &ExecError,
) -> Result<(), ExecError> {
    write_status(status, &ExecPhaseStatus::failed_from(error).encode())
}

/// 子側: `R` の後の `execveat` が戻ったことを `X <CODE>` として書く（best-effort。#2716）。
///
/// 書けなくても元のエラーを返すのは呼び出し側の責務で、親は `R` だけを読んで EOF になり成功と判定する
/// （書けない状況は pipe の破損のみで、その場合 PID 1 はすぐ終了する）。
pub(super) fn report_exec_returned(
    status: &std::fs::File,
    code: ErrorCode,
) -> Result<(), ExecError> {
    write_status(status, &ExecPhaseStatus::Returned { code }.encode())
}

/// 親側が EOF まで読む 2 行目以降の最大バイト数（`R\n` と `X <CODE>\n` の 2 行ぶん）。
const EXEC_PHASE_TAIL_MAX_BYTES: usize = 2 * PRE_PIVOT_STATUS_MAX_BYTES;

/// exec 前後の状態（2 行目以降を EOF まで読んだ結果。#2716）。
///
/// [`ExecPhaseStatus`]（1 行の型）と別にして、「`R` を読んだ」ことと「`execveat` が成功した」ことを取り違えない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecPhaseOutcome {
    /// `R` の後に何も届かず EOF になった。状態 pipe は close-on-exec のため、`execveat` の成功を意味する。
    Executed,
    /// `R` の後に `X <CODE>` が届いた。`execveat` が errno で失敗した。
    ExecReturned { code: ErrorCode },
    /// `execveat` の前の手順が失敗した（`E`）。
    Failed {
        code: ErrorCode,
        violation: Option<ViolationReason>,
    },
}

impl ExecPhaseOutcome {
    /// EOF まで読んだバイト列を厳格に復号する（純関数）。
    ///
    /// 受理するのは `R\n`・`R\nX <CODE>\n`・`E ...\n` の 3 形だけ。空は `ClosedBeforeReport`、LF なしは
    /// `Truncated`、それ以外（`R` の後の `E`、`X` の単独、余分なバイト、許可リスト外の CODE）は `Malformed`。
    pub(super) fn decode_tail(bytes: &[u8]) -> Result<Self, PrePivotStatusError> {
        if bytes.is_empty() {
            return Err(PrePivotStatusError::ClosedBeforeReport);
        }
        let pos = bytes
            .iter()
            .position(|c| *c == b'\n')
            .ok_or(PrePivotStatusError::Truncated)?;
        let (first, rest) = bytes.split_at(pos + 1);
        match ExecPhaseStatus::decode(first)? {
            ExecPhaseStatus::Ready if rest.is_empty() => Ok(Self::Executed),
            ExecPhaseStatus::Ready => match ExecPhaseStatus::decode(rest)? {
                ExecPhaseStatus::Returned { code } => Ok(Self::ExecReturned { code }),
                _ => Err(PrePivotStatusError::Malformed),
            },
            ExecPhaseStatus::Failed { code, violation } if rest.is_empty() => {
                Ok(Self::Failed { code, violation })
            }
            _ => Err(PrePivotStatusError::Malformed),
        }
    }
}

/// 親側: 状態 pipe の 2 行目以降を、書き込み側が全て閉じる（EOF）まで期限つきで読んで復号する（REPAIR-5・#2716）。
///
/// 1 行目を読み終えた後にだけ呼ぶこと。期限は全体で `timeout`（1 バイトずつ滴下されても延びない）、バッファは
/// 固定長で、超えたら `TooLong`。`R` の後は `execveat` の成功（close-on-exec による EOF）か `X` を待つ。
///
/// 既知の限界: `R` を書いてから `execveat` が完了するまでの間（syscall 1 回ぶん）にシグナルで PID 1 が死ぬと、
/// EOF になり `Executed` と判定される。EOF の後の生存確認は、すぐ終わる正当なプログラムを誤って失敗にするため
/// 入れない（`exec_command` が受け入れている限界と同じ）。
pub(super) fn read_exec_phase_until_close(
    status: &std::fs::File,
    timeout: Duration,
) -> Result<ExecPhaseOutcome, PrePivotStatusError> {
    let deadline = Instant::now() + timeout.min(READ_TIMEOUT_MAX);
    // 1 バイト余分に持ち、上限ちょうどで EOF になる正常系と、上限超過を区別する。
    let mut buf = [0u8; EXEC_PHASE_TAIL_MAX_BYTES + 1];
    let mut filled = 0usize;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = remaining.as_millis().saturating_add(u128::from(
            !remaining.subsec_nanos().is_multiple_of(1_000_000),
        ));
        let millis = i32::try_from(millis).unwrap_or(i32::MAX);
        match sys::poll_readable(status.as_fd(), millis) {
            Ok(true) => {}
            Ok(false) => {
                if Instant::now() >= deadline {
                    return Err(PrePivotStatusError::Timeout);
                }
                continue;
            }
            Err(SysError::Os(errno)) if errno == sys::EINTR => continue,
            Err(_) => return Err(PrePivotStatusError::Io),
        }
        let Some(rest) = buf.get_mut(filled..).filter(|r| !r.is_empty()) else {
            return Err(PrePivotStatusError::TooLong);
        };
        match (&*status).read(rest) {
            Ok(0) => break,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(PrePivotStatusError::Io),
        }
        if filled > EXEC_PHASE_TAIL_MAX_BYTES {
            return Err(PrePivotStatusError::TooLong);
        }
        // 完成した失敗報告（`E` 行、または `R` に続く `X` 行）は EOF を待たずに判定する。子は失敗報告の後に
        // stderr へ同期書き込みしてから終了するため、stderr が詰まると状態 pipe が閉じず、届いた失敗コードが
        // `Timeout` に置き換わる（REPAIR-5・CORE-5。EOF 待ちは成功候補の `R` だけの場合に限る）。
        let got = buf.get(..filled).unwrap_or(&[]);
        let lines = got.iter().filter(|c| **c == b'\n').count();
        let complete_failure = match got.first() {
            Some(b'E') => lines >= 1,
            Some(b'R') => lines >= 2,
            _ => false,
        };
        if complete_failure {
            return ExecPhaseOutcome::decode_tail(got);
        }
    }
    ExecPhaseOutcome::decode_tail(buf.get(..filled).unwrap_or(&[]))
}

/// 2 行目以降の読み取り結果を起動の成否へ判定し、entrypoint 系の違反を親で記録する（SEC-4・#2624・#2716）。
///
/// `Executed` だけが `Ok`。違反ありの失敗は [`audit_entrypoint_violation`] が層 `entrypoint` のレコードを 1 件書く
/// （パスなし。時刻と PID は記録を行った親のもの）。理由なしの失敗・`ExecReturned`（`R` の後の `execveat` の
/// errno 由来の失敗。設定の誤りか DAC / LSM の拒否で、ユーザー空間からは違反と区別できないため記録しない。
/// カーネル側の監査が担う）・読み取り失敗は記録せず `NotApplicable`（fail-closed。記録の失敗で拒否は覆らない）。
pub(super) fn resolve_exec_phase_status(
    result: Result<ExecPhaseOutcome, PrePivotStatusError>,
    audit: LaunchAudit<'_>,
) -> Result<(), Box<AuditedRejection<ExecError>>> {
    match result {
        Ok(ExecPhaseOutcome::Executed) => Ok(()),
        Ok(ExecPhaseOutcome::Failed {
            violation: Some(reason),
            ..
        }) => Err(Box::new(audit_entrypoint_violation(
            ExecError::from_violation_at(reason, None, IsolationStage::Exec),
            audit.container,
            audit.sink,
        ))),
        Ok(ExecPhaseOutcome::Failed {
            code,
            violation: None,
        }) => Err(Box::new(AuditedRejection::not_applicable(ExecError::new(
            code,
            IsolationStage::Exec,
            "the entrypoint could not be prepared in the container child",
        )))),
        Ok(ExecPhaseOutcome::ExecReturned { code }) => {
            Err(Box::new(AuditedRejection::not_applicable(ExecError::new(
                code,
                IsolationStage::Exec,
                "the entrypoint execveat failed in the container child",
            ))))
        }
        Err(e) => Err(Box::new(AuditedRejection::not_applicable(
            e.to_exec_error(),
        ))),
    }
}

/// 結合試験専用: `R` の後の `execveat` の失敗 `code` を、子の符号化（`R` と `X`）・状態 pipe・親の復号まで本番と
/// 同じ関数で往復させる（SEC-4・#2716）。記録は発生しない（`NotApplicable`）ことの照合に使う。
#[doc(hidden)]
#[cfg(feature = "exec-test-support")]
pub fn relay_exec_returned_for_test(
    code: ErrorCode,
    sink: &dyn AuditSink,
    container: Option<&ContainerId>,
) -> Result<(), Box<AuditedRejection<ExecError>>> {
    let (r, w) = std::io::pipe().map_err(|e| {
        Box::new(AuditedRejection::not_applicable(ExecError::from_io(
            &e,
            IsolationStage::Spawn,
            "create the test pipe",
        )))
    })?;
    let w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
    let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
    report_exec_ready(&w).map_err(|e| Box::new(AuditedRejection::not_applicable(e)))?;
    report_exec_returned(&w, code).map_err(|e| Box::new(AuditedRejection::not_applicable(e)))?;
    drop(w);
    let status = read_exec_phase_until_close(&r, Duration::from_secs(5));
    resolve_exec_phase_status(status, LaunchAudit { sink, container })
}
/// 結合試験専用: entrypoint 系の違反 `reason` を、子の符号化・状態 pipe・親の復号と記録まで本番と同じ関数で
/// 往復させる（SEC-4・#2624）。通常の利用者は呼ばない。
#[doc(hidden)]
#[cfg(feature = "exec-test-support")]
pub fn relay_entrypoint_violation_for_test(
    reason: ViolationReason,
    sink: &dyn AuditSink,
    container: Option<&ContainerId>,
) -> Result<(), Box<AuditedRejection<ExecError>>> {
    let (r, w) = std::io::pipe().map_err(|e| {
        Box::new(AuditedRejection::not_applicable(ExecError::from_io(
            &e,
            IsolationStage::Spawn,
            "create the test pipe",
        )))
    })?;
    let w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
    let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
    let error = ExecError::from_violation_at(reason, None, IsolationStage::Exec);
    report_exec_failure(&w, &error).map_err(|e| Box::new(AuditedRejection::not_applicable(e)))?;
    drop(w);
    let status = read_exec_phase_until_close(&r, Duration::from_secs(5));
    resolve_exec_phase_status(status, LaunchAudit { sink, container })
}

/// 結合試験専用: 段 `mount_binds` の違反 `reason` を、子の符号化・状態 pipe・親の復号と記録まで本番と同じ関数で
/// 往復させる（SEC-4・SEC-5・REPAIR-10・#2072）。通常の利用者は呼ばない。
///
/// 子の失敗（`ExecError::from_violation_at(reason, None, MountBinds)`）を `report_failure` で pipe へ書き、
/// `read_pre_pivot_status` で読んで `resolve_pre_pivot_status` に渡す。許可リスト外の理由は子で落ちて理由なしで届く。
#[doc(hidden)]
#[cfg(feature = "exec-test-support")]
pub fn relay_mount_binds_failure_for_test(
    reason: ViolationReason,
    sink: &dyn AuditSink,
    container: Option<&ContainerId>,
) -> Result<(), Box<AuditedRejection<ExecError>>> {
    let (r, w) = std::io::pipe().map_err(|e| {
        Box::new(AuditedRejection::not_applicable(ExecError::from_io(
            &e,
            IsolationStage::Spawn,
            "create the test pipe",
        )))
    })?;
    let w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
    let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
    let error = ExecError::from_violation_at(reason, None, IsolationStage::MountBinds);
    let failure = PrePivotFailure::from_exec_error(PrePivotStep::MountBinds, &error);
    report_failure(&w, &failure).map_err(|e| Box::new(AuditedRejection::not_applicable(e)))?;
    drop(w);
    let status = read_pre_pivot_status(&r, Duration::from_secs(5));
    resolve_pre_pivot_status(status, LaunchAudit { sink, container })
}

/// 単体テスト専用: 子の失敗 `error`（段 `step`）を、子の符号化・状態 pipe・親の復号と記録まで本番と同じ関数で
/// 往復させる（SEC-4・#2013）。`path_masks` / `masked_paths` の適用失敗が、実際の `ExecError` から親の監査記録まで
/// 届くことを具体値で照合するために使う。
#[cfg(test)]
pub(super) fn relay_failure_for_test(
    step: PrePivotStep,
    error: &ExecError,
    audit: LaunchAudit<'_>,
) -> Result<(), Box<AuditedRejection<ExecError>>> {
    let (r, w) = std::io::pipe().expect("pipe");
    let w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
    let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
    let failure = PrePivotFailure::from_exec_error(step, error);
    report_failure(&w, &failure).expect("report");
    drop(w);
    resolve_pre_pivot_status(read_pre_pivot_status(&r, Duration::from_secs(5)), audit)
}

/// 起動時の監査の渡し先（借用。`LaunchSpec` に載せない理由: `Debug + Clone + PartialEq + Eq` の値型に
/// `&dyn AuditSink` を載せると derive が壊れるため。本番 launcher が起動ごとに作って渡す）。
#[derive(Clone, Copy)]
pub(crate) struct LaunchAudit<'a> {
    /// 記録の書き込み先（親だけが触る）。
    pub(crate) sink: &'a dyn AuditSink,
    /// 記録の `container_id`（検証済み ID。無ければ `None`）。
    pub(crate) container: Option<&'a ContainerId>,
}

/// 読み取り結果を起動の成否へ判定し、違反を親で記録する（SEC-4・CORE-2）。
///
/// `Ready` だけが `Ok`。失敗行は段・`ErrorCode`・違反理由から `ExecError` を作る（メッセージは固定語彙のみ）。
/// 違反ありなら `record_launch_mount_rejection` が層 `mount` のレコードを 1 件書く（`establish_precondition`・
/// `evidence_mismatch` は `NotApplicable`）。読み取り失敗は `NotApplicable`。
pub(super) fn resolve_pre_pivot_status(
    result: Result<PrePivotStatus, PrePivotStatusError>,
    audit: LaunchAudit<'_>,
) -> Result<(), Box<AuditedRejection<ExecError>>> {
    match result {
        Ok(PrePivotStatus::Ready) => Ok(()),
        Ok(PrePivotStatus::Failed(f)) => Err(Box::new(match f.violation {
            Some(reason) => {
                let mut error = ExecError::from_violation_at(reason, None, f.step.stage());
                // 保護の適用失敗は errno 由来の分類（古いカーネルの `Unimplemented` 等）をワイヤーの `CODE` で保つ。
                // 他の理由の `code` は理由から決まる静的な値のまま（#2013）。
                if reason.kind() == ViolationKind::ProtectedPathApply {
                    error.code = f.code;
                }
                record_launch_mount_rejection(error, reason, audit.container, audit.sink)
            }
            None => AuditedRejection::not_applicable(ExecError::new(
                f.code,
                f.step.stage(),
                format!(
                    "pre-pivot step '{}' failed in the container child",
                    f.step.as_str()
                ),
            )),
        })),
        Err(e) => Err(Box::new(AuditedRejection::not_applicable(
            e.to_exec_error(),
        ))),
    }
}

#[cfg(test)]
fn step_ordinal(step: PrePivotStep) -> usize {
    match step {
        PrePivotStep::Establish => 0,
        PrePivotStep::PrepareRootfs => 1,
        PrePivotStep::VerifyPinned => 2,
        PrePivotStep::MountSysfs => 3,
        PrePivotStep::CreateDefaultDevices => 4,
        PrePivotStep::MountTmpfs => 5,
        PrePivotStep::InjectFiles => 6,
        PrePivotStep::MountBinds => 7,
        PrePivotStep::ReadonlyPaths => 8,
        PrePivotStep::MaskedPaths => 9,
        PrePivotStep::PivotRoot => 10,
        PrePivotStep::WorkingDir => 11,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_log::{AuditDelivery, AuditLayer, AuditRecord};
    use crate::traits::TraitError;
    use std::sync::Mutex;

    struct VecSink {
        records: Mutex<Vec<AuditRecord>>,
        fail: bool,
    }

    impl VecSink {
        fn new(fail: bool) -> Self {
            Self {
                records: Mutex::new(Vec::new()),
                fail,
            }
        }
        fn snapshot(&self) -> Vec<AuditRecord> {
            self.records.lock().map(|r| r.clone()).unwrap_or_default()
        }
    }

    impl AuditSink for VecSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            if self.fail {
                return Err(TraitError::new(ErrorCode::Internal, "sink failed"));
            }
            if let Ok(mut g) = self.records.lock() {
                g.push(record.clone());
            }
            Ok(())
        }
    }

    fn fail(step: PrePivotStep, code: ErrorCode, v: Option<ViolationReason>) -> PrePivotStatus {
        PrePivotStatus::Failed(PrePivotFailure {
            step,
            code,
            violation: v,
        })
    }

    fn pipe_with(bytes: &[u8]) -> std::fs::File {
        let (r, w) = std::io::pipe().unwrap();
        let mut w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
        w.write_all(bytes).unwrap();
        drop(w);
        std::fs::File::from(std::os::fd::OwnedFd::from(r))
    }

    /// 段の一覧は全 variant を網羅する（`ErrorCode` は types.rs の試験）（足し忘れの検出。REPAIR-2）。
    #[test]
    fn sec4_1815_tables_cover_every_variant() {
        for (i, s) in PrePivotStep::ALL.into_iter().enumerate() {
            assert_eq!(step_ordinal(s), i);
        }
        assert_eq!(PrePivotStep::ALL.len(), 12);
    }

    /// 具体値の符号化（ワイヤー形式の固定。SEC-4・REPAIR-2）。
    #[test]
    fn sec4_1815_encode_concrete_lines() {
        assert_eq!(PrePivotStatus::Ready.encode().as_bytes(), b"P\n");
        let s = fail(
            PrePivotStep::CreateDefaultDevices,
            ErrorCode::FailedPrecondition,
            Some(ViolationReason::TargetOnSharedMount),
        );
        assert_eq!(
            s.encode().as_bytes(),
            b"F create_default_devices FAILED_PRECONDITION target_on_shared_mount\n"
        );
        let s = fail(PrePivotStep::PivotRoot, ErrorCode::Internal, None);
        assert_eq!(s.encode().as_bytes(), b"F pivot_root INTERNAL -\n");
        let s = fail(
            PrePivotStep::MountBinds,
            ErrorCode::PermissionDenied,
            Some(ViolationReason::BindSourceNotAccessible),
        );
        assert_eq!(
            s.encode().as_bytes(),
            b"F mount_binds PERMISSION_DENIED bind_source_not_accessible\n"
        );
    }

    /// 全段 x 全 ErrorCode x 全許可理由の往復と、最長の行が上限に収まること。
    #[test]
    fn sec4_1815_roundtrip_every_step_code_and_reason() {
        let mut longest = 0;
        for step in PrePivotStep::ALL {
            for code in ErrorCode::ALL {
                let mut reasons: Vec<Option<ViolationReason>> = vec![None];
                reasons.extend(
                    ViolationReason::ALL
                        .into_iter()
                        .filter(|r| launch_violation(step, r.as_str()) == Some(*r))
                        .map(Some),
                );
                for v in reasons {
                    let s = fail(step, code, v);
                    let enc = s.encode();
                    longest = longest.max(enc.as_bytes().len());
                    assert_eq!(PrePivotStatus::decode(enc.as_bytes()), Ok(s));
                }
            }
        }
        assert!(longest <= PRE_PIVOT_STATUS_MAX_BYTES, "{longest}");
    }

    /// 厳格な復号: 許可リスト外・形式違反は `Malformed`（SEC-4）。
    #[test]
    fn sec4_1815_decode_rejects_malformed_lines() {
        let cases: [&[u8]; 23] = [
            b"",
            b"P",
            b"P\n\n",
            b"p\n",
            b"P \n",
            b"F establish INTERNAL\n",
            b"F establish INTERNAL - x\n",
            b"F  establish INTERNAL -\n",
            b"F bogus INTERNAL -\n",
            b"F establish internal -\n",
            b"F establish BOGUS -\n",
            b"F establish INTERNAL exec_target_cgroup_mismatch\n",
            b"F establish INTERNAL plan_rejected\n",
            b"F establish INTERNAL no_namespaces\n",
            // #2072: user namespace 由来の 2 理由は段 mount_binds と組のときだけ受ける。
            b"F establish INTERNAL user_namespace_required\n",
            b"F prepare_rootfs FAILED_PRECONDITION host_root_identity_mapping\n",
            b"F mount_binds INVALID_ARGUMENT no_namespaces\n",
            b"F mount_binds INVALID_ARGUMENT user_namespace_required \n",
            // #2013: 保護の適用失敗の 2 理由は自分の段と組のときだけ受ける。
            b"F establish INTERNAL readonly_path_apply_failed\n",
            b"F masked_paths FAILED_PRECONDITION readonly_path_apply_failed\n",
            b"F readonly_paths UNIMPLEMENTED masked_path_apply_failed\n",
            b"F mount_binds INTERNAL masked_path_apply_failed\n",
            b"F readonly_paths INTERNAL readonly_path_apply_failed \n",
        ];
        for c in cases {
            assert_eq!(
                PrePivotStatus::decode(c),
                Err(PrePivotStatusError::Malformed),
                "{:?}",
                String::from_utf8_lossy(c)
            );
        }
    }

    /// 親の読み取り: 正常行・EOF のみ・途中 EOF・上限超・余分なバイト（REPAIR-5・SEC-4）。
    #[test]
    fn repair5_1815_read_status_variants() {
        let t = Duration::from_secs(5);
        assert_eq!(
            read_pre_pivot_status(&pipe_with(b"P\n"), t),
            Ok(PrePivotStatus::Ready)
        );
        assert_eq!(
            read_pre_pivot_status(&pipe_with(b""), t),
            Err(PrePivotStatusError::ClosedBeforeReport)
        );
        assert_eq!(
            read_pre_pivot_status(&pipe_with(b"F establish"), t),
            Err(PrePivotStatusError::Truncated)
        );
        assert_eq!(
            read_pre_pivot_status(&pipe_with(b"P\nP\n"), t),
            Err(PrePivotStatusError::Malformed)
        );
        assert_eq!(
            read_pre_pivot_status(&pipe_with(&[b'F'; PRE_PIVOT_STATUS_MAX_BYTES + 1]), t),
            Err(PrePivotStatusError::TooLong)
        );
        let mut long = vec![b'F'; PRE_PIVOT_STATUS_MAX_BYTES];
        long.push(b'\n');
        assert_eq!(
            read_pre_pivot_status(&pipe_with(&long), t),
            Err(PrePivotStatusError::TooLong)
        );
    }

    /// 書き込み側が開いたまま無出力・滴下でも全体の期限で打ち切る（REPAIR-5）。
    #[test]
    fn repair5_1815_read_status_times_out_on_silence_and_drip() {
        let (r, w) = std::io::pipe().unwrap();
        let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
        let started = Instant::now();
        assert_eq!(
            read_pre_pivot_status(&r, Duration::from_millis(50)),
            Err(PrePivotStatusError::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(5));

        let mut w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
        let dripper = std::thread::spawn(move || {
            for _ in 0..40 {
                if w.write_all(b"F").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        assert_eq!(
            read_pre_pivot_status(&r, Duration::from_millis(150)),
            Err(PrePivotStatusError::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(r);
        dripper.join().unwrap();
    }

    /// 子側の報告が親で復元される（段ごとの失敗が名前と ErrorCode の具体値で戻る）。
    #[test]
    fn sec4_1815_report_failure_roundtrips_through_pipe() {
        for step in PrePivotStep::ALL {
            let (r, w) = std::io::pipe().unwrap();
            let w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
            let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
            let f = PrePivotFailure {
                step,
                code: ErrorCode::PermissionDenied,
                violation: None,
            };
            report_failure(&w, &f).unwrap();
            drop(w);
            assert_eq!(
                read_pre_pivot_status(&r, Duration::from_secs(5)),
                Ok(PrePivotStatus::Failed(f))
            );
        }
        let (r, w) = std::io::pipe().unwrap();
        let w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
        report_ready(&w).unwrap();
        drop(w);
        let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
        assert_eq!(
            read_pre_pivot_status(&r, Duration::from_secs(5)),
            Ok(PrePivotStatus::Ready)
        );
    }

    /// 子側の作成入口は許可リスト外の違反理由を落とす（失敗自体は報告する）。
    #[test]
    fn sec4_1815_from_exec_error_drops_out_of_allowlist_reason() {
        let e = ExecError::from_violation(ViolationReason::EntrypointIsRuntimeBinary, None);
        let f = PrePivotFailure::from_exec_error(PrePivotStep::PivotRoot, &e);
        assert_eq!(f.violation, None);
        assert_eq!(f.code, ErrorCode::PermissionDenied);
        let e = ExecError::from_violation(ViolationReason::PathMissing, None);
        let f = PrePivotFailure::from_exec_error(PrePivotStep::PrepareRootfs, &e);
        assert_eq!(f.violation, Some(ViolationReason::PathMissing));
    }

    /// #2072: 段 mount_binds の user namespace 由来の 2 理由は子で残り、符号化・復号で往復する。
    /// 他の段・他の PlanRejected 理由は子で落ちる。
    #[test]
    fn sec4_2072_mount_binds_user_namespace_reasons_roundtrip() {
        for (reason, code, line) in [
            (
                ViolationReason::UserNamespaceRequired,
                ErrorCode::InvalidArgument,
                &b"F mount_binds INVALID_ARGUMENT user_namespace_required\n"[..],
            ),
            (
                ViolationReason::HostRootIdentityMapping,
                ErrorCode::FailedPrecondition,
                &b"F mount_binds FAILED_PRECONDITION host_root_identity_mapping\n"[..],
            ),
        ] {
            let e = ExecError::from_violation_at(reason, None, IsolationStage::MountBinds);
            let f = PrePivotFailure::from_exec_error(PrePivotStep::MountBinds, &e);
            assert_eq!(f.code, code);
            assert_eq!(f.violation, Some(reason));
            assert_eq!(PrePivotStatus::Failed(f).encode().as_bytes(), line);
            assert_eq!(PrePivotStatus::decode(line), Ok(PrePivotStatus::Failed(f)));
            let other = PrePivotFailure::from_exec_error(PrePivotStep::PrepareRootfs, &e);
            assert_eq!(other.violation, None);
        }
        let e = ExecError::from_violation_at(
            ViolationReason::NoNamespaces,
            None,
            IsolationStage::MountBinds,
        );
        let f = PrePivotFailure::from_exec_error(PrePivotStep::MountBinds, &e);
        assert_eq!(f.violation, None);
    }

    /// #2072: 親は 2 理由を層 mount のパスなし・理由コードつきで 1 件記録する。
    #[test]
    fn sec4_2072_resolve_records_mount_binds_user_namespace_reasons() {
        for (reason, token) in [
            (
                ViolationReason::UserNamespaceRequired,
                "user_namespace_required",
            ),
            (
                ViolationReason::HostRootIdentityMapping,
                "host_root_identity_mapping",
            ),
        ] {
            let sink = VecSink::new(false);
            let status = fail(PrePivotStep::MountBinds, reason.error_code(), Some(reason));
            let r = resolve_pre_pivot_status(Ok(status), audit(&sink, None)).unwrap_err();
            assert_eq!(r.delivery, AuditDelivery::Recorded);
            assert_eq!(r.error.stage, IsolationStage::MountBinds);
            assert_eq!(r.error.code, reason.error_code());
            assert_eq!(
                r.error.violation.as_ref().map(|v| v.reason.as_str()),
                Some(token)
            );
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1);
            assert_eq!(recs[0].layer(), AuditLayer::Mount);
            assert_eq!(recs[0].path(), None);
            assert!(format!("{:?}", recs[0]).contains(token), "{token}");
        }
    }

    fn audit<'a>(sink: &'a VecSink, id: Option<&'a ContainerId>) -> LaunchAudit<'a> {
        LaunchAudit {
            sink,
            container: id,
        }
    }

    /// 監査: マウント層 3 種別が 1 件ずつ、パスなし・理由コードつき・自プロセス pid で記録される。
    #[test]
    fn sec4_1815_resolve_records_mount_layer_reasons() {
        let id = ContainerId::new("c1").unwrap();
        for (step, reason, token) in [
            (
                PrePivotStep::PrepareRootfs,
                ViolationReason::PathMissing,
                "path_missing",
            ),
            (
                PrePivotStep::CreateDefaultDevices,
                ViolationReason::TargetOnSharedMount,
                "target_on_shared_mount",
            ),
            (
                PrePivotStep::PrepareRootfs,
                ViolationReason::RootfsIsHostRoot,
                "rootfs_is_host_root",
            ),
        ] {
            let sink = VecSink::new(false);
            let status = PrePivotStatus::Failed(PrePivotFailure {
                step,
                code: reason.error_code(),
                violation: Some(reason),
            });
            let r = resolve_pre_pivot_status(Ok(status), audit(&sink, Some(&id))).unwrap_err();
            assert_eq!(r.delivery, AuditDelivery::Recorded);
            assert_eq!(r.error.stage, step.stage());
            assert_eq!(r.error.code, reason.error_code());
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1);
            assert_eq!(recs[0].layer(), AuditLayer::Mount);
            assert_eq!(recs[0].path(), None);
            assert_eq!(recs[0].pid().get(), std::process::id());
            assert_eq!(recs[0].container_id().map(ContainerId::as_str), Some("c1"));
            assert!(format!("{:?}", recs[0]).contains(token), "{token}");
        }
        // container_id なし。
        let sink = VecSink::new(false);
        let status = fail(
            PrePivotStep::PrepareRootfs,
            ErrorCode::InvalidArgument,
            Some(ViolationReason::PathMissing),
        );
        resolve_pre_pivot_status(Ok(status), audit(&sink, None)).unwrap_err();
        assert_eq!(sink.snapshot()[0].container_id(), None);
    }

    /// 監査: establish / evidence の違反・違反なしの失敗・読み取り失敗は記録 0 件（`NotApplicable`）。
    #[test]
    fn sec4_1815_resolve_does_not_record_other_failures() {
        let cases = [
            Ok(fail(
                PrePivotStep::Establish,
                ErrorCode::FailedPrecondition,
                Some(ViolationReason::EstablishNotPid1),
            )),
            Ok(fail(
                PrePivotStep::PrepareRootfs,
                ErrorCode::FailedPrecondition,
                Some(ViolationReason::EvidenceCallerNotPid1),
            )),
            Ok(fail(PrePivotStep::MountTmpfs, ErrorCode::Internal, None)),
            Err(PrePivotStatusError::Timeout),
            Err(PrePivotStatusError::Malformed),
        ];
        for c in cases {
            let sink = VecSink::new(false);
            let r = resolve_pre_pivot_status(c, audit(&sink, None)).unwrap_err();
            assert_eq!(r.delivery, AuditDelivery::NotApplicable);
            assert!(sink.snapshot().is_empty());
        }
        let sink = VecSink::new(false);
        let r = resolve_pre_pivot_status(
            Ok(fail(PrePivotStep::MountTmpfs, ErrorCode::Internal, None)),
            audit(&sink, None),
        )
        .unwrap_err();
        assert_eq!(r.error.code, ErrorCode::Internal);
        assert_eq!(r.error.stage, IsolationStage::MountTmpfs);
        assert_eq!(
            r.error.message,
            "pre-pivot step 'mount_tmpfs' failed in the container child"
        );
        let r = resolve_pre_pivot_status(Err(PrePivotStatusError::Timeout), audit(&sink, None))
            .unwrap_err();
        assert_eq!(r.error.code, ErrorCode::Timeout);
        assert!(resolve_pre_pivot_status(Ok(PrePivotStatus::Ready), audit(&sink, None)).is_ok());
    }

    /// fail-closed: sink が失敗しても拒否は覆らず、結果は `SinkFailed`。
    #[test]
    fn sec4_1815_sink_failure_keeps_rejection() {
        let sink = VecSink::new(true);
        let status = fail(
            PrePivotStep::PrepareRootfs,
            ErrorCode::InvalidArgument,
            Some(ViolationReason::PathMissing),
        );
        let r = resolve_pre_pivot_status(Ok(status), audit(&sink, None)).unwrap_err();
        assert!(matches!(r.delivery, AuditDelivery::SinkFailed(_)));
        assert_eq!(r.error.code, ErrorCode::InvalidArgument);
        assert_eq!(r.error.stage, IsolationStage::PrepareRootfs);
    }

    /// 監査（#2013）: 保護の適用失敗は、段ごとの理由で層 `mount` に 1 件記録され、`ErrorCode` はワイヤーの値のまま
    /// （`Unimplemented` を保つ）、`stage` は段に対応し、`message` は理由の静的な英語になる。パスは載らない。
    #[test]
    fn sec4_2013_resolve_records_protected_path_apply_and_keeps_code() {
        let id = ContainerId::new("c1").unwrap();
        for (step, reason, code, token, stage, message) in [
            (
                PrePivotStep::ReadonlyPaths,
                ViolationReason::ReadonlyPathApplyFailed,
                ErrorCode::Unimplemented,
                "readonly_path_apply_failed",
                IsolationStage::MountReadonlyPaths,
                "failed to apply a read-only path protection",
            ),
            (
                PrePivotStep::MaskedPaths,
                ViolationReason::MaskedPathApplyFailed,
                ErrorCode::FailedPrecondition,
                "masked_path_apply_failed",
                IsolationStage::MountMaskedPaths,
                "failed to apply a masked path protection",
            ),
            (
                PrePivotStep::MountSysfs,
                ViolationReason::SysfsApplyFailed,
                ErrorCode::FailedPrecondition,
                "sysfs_apply_failed",
                IsolationStage::MountSysfs,
                "failed to apply the read-only sysfs mount",
            ),
        ] {
            let sink = VecSink::new(false);
            let r = resolve_pre_pivot_status(
                Ok(fail(step, code, Some(reason))),
                audit(&sink, Some(&id)),
            )
            .unwrap_err();
            assert_eq!(r.delivery, AuditDelivery::Recorded);
            assert_eq!(r.error.code, code);
            assert_eq!(r.error.stage, stage);
            assert_eq!(r.error.message, message);
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1);
            assert_eq!(recs[0].layer(), AuditLayer::Mount);
            assert_eq!(recs[0].path(), None);
            assert_eq!(recs[0].reason().map(|x| x.as_str()), Some(token));
            assert_eq!(recs[0].container_id().map(ContainerId::as_str), Some("c1"));

            // sink が失敗しても拒否は覆らない（fail-closed）。
            let failing = VecSink::new(true);
            let r = resolve_pre_pivot_status(
                Ok(fail(step, code, Some(reason))),
                audit(&failing, Some(&id)),
            )
            .unwrap_err();
            assert!(matches!(r.delivery, AuditDelivery::SinkFailed(_)));
            assert_eq!(r.error.code, code);
            assert_eq!(r.error.stage, stage);
        }
    }

    /// 監査（SEC-4・SEC-2・#2020）: sysfs の適用失敗の理由は段 `mount_sysfs` でだけ許可リストを通り、
    /// 他の段・他の保護の理由は段の食い違いとして落ちる（`launch_violation` は子と親で共有）。
    #[test]
    fn sec4_2020_sysfs_apply_reason_passes_only_at_its_own_step() {
        let t = "sysfs_apply_failed";
        assert_eq!(
            launch_violation(PrePivotStep::MountSysfs, t),
            Some(ViolationReason::SysfsApplyFailed)
        );
        for step in [
            PrePivotStep::ReadonlyPaths,
            PrePivotStep::MaskedPaths,
            PrePivotStep::MountBinds,
            PrePivotStep::PivotRoot,
        ] {
            assert_eq!(launch_violation(step, t), None, "{}", step.as_str());
        }
        for t in ["readonly_path_apply_failed", "masked_path_apply_failed"] {
            assert_eq!(launch_violation(PrePivotStep::MountSysfs, t), None);
        }
    }

    /// 監査（#2013）: 他の理由の `code` は従来どおり理由から決まる静的な値のまま（ワイヤーの `CODE` で上書きしない）。
    #[test]
    fn sec4_2013_other_reasons_keep_static_code() {
        let sink = VecSink::new(false);
        let r = resolve_pre_pivot_status(
            Ok(fail(
                PrePivotStep::PrepareRootfs,
                ErrorCode::Internal,
                Some(ViolationReason::PathMissing),
            )),
            audit(&sink, None),
        )
        .unwrap_err();
        assert_eq!(r.error.code, ErrorCode::InvalidArgument);
    }

    /// 2 行目の具体値の符号化（ワイヤー形式の固定。SEC-4・#2624）。
    #[test]
    fn sec4_2624_encode_concrete_exec_phase_lines() {
        assert_eq!(ExecPhaseStatus::Ready.encode().as_bytes(), b"R\n");
        let e = ExecPhaseStatus::Failed {
            code: ErrorCode::PermissionDenied,
            violation: Some(ViolationReason::EntrypointIsRuntimeBinary),
        };
        assert_eq!(
            e.encode().as_bytes(),
            b"E PERMISSION_DENIED entrypoint_is_runtime_binary\n"
        );
        let n = ExecPhaseStatus::Failed {
            code: ErrorCode::NotFound,
            violation: None,
        };
        assert_eq!(n.encode().as_bytes(), b"E NOT_FOUND -\n");
    }

    /// 8 理由すべてが符号化・復号で往復し、親の記録は層 `entrypoint` に理由コードだけ・パスなしで 1 件（SEC-4・#2624）。
    #[test]
    fn sec4_2624_every_entrypoint_reason_roundtrips_and_records_once() {
        assert_eq!(ViolationReason::ENTRYPOINT_REASONS.len(), 8);
        let id = ContainerId::new("c2624").unwrap();
        for reason in ViolationReason::ENTRYPOINT_REASONS {
            let error = ExecError::from_violation_at(reason, None, IsolationStage::Exec);
            let status = ExecPhaseStatus::failed_from(&error);
            let decoded = ExecPhaseStatus::decode(status.encode().as_bytes()).unwrap();
            assert_eq!(decoded, status);
            let outcome = ExecPhaseOutcome::decode_tail(status.encode().as_bytes()).unwrap();
            let sink = VecSink::new(false);
            let r = resolve_exec_phase_status(Ok(outcome), audit(&sink, Some(&id))).unwrap_err();
            let token = reason.as_str();
            assert_eq!(r.delivery, AuditDelivery::Recorded, "{token}");
            assert_eq!(r.error.stage, IsolationStage::Exec);
            assert_eq!(r.error.code, reason.error_code(), "{token}");
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1, "{token}");
            assert_eq!(recs[0].layer(), AuditLayer::Entrypoint);
            assert_eq!(recs[0].path(), None);
            assert_eq!(recs[0].reason().map(|x| x.as_str()), Some(token));
        }
    }

    /// 理由なしの失敗は記録せず `NotApplicable`、`R` は `Ok`、読み取り失敗は起動失敗（SEC-4・REPAIR-5・#2624）。
    #[test]
    fn sec4_2624_resolve_exec_phase_other_outcomes() {
        let sink = VecSink::new(false);
        assert!(
            resolve_exec_phase_status(Ok(ExecPhaseOutcome::Executed), audit(&sink, None)).is_ok()
        );
        let r = resolve_exec_phase_status(
            Ok(ExecPhaseOutcome::Failed {
                code: ErrorCode::NotFound,
                violation: None,
            }),
            audit(&sink, None),
        )
        .unwrap_err();
        assert_eq!(r.delivery, AuditDelivery::NotApplicable);
        assert_eq!(r.error.code, ErrorCode::NotFound);
        assert_eq!(r.error.stage, IsolationStage::Exec);
        let r = resolve_exec_phase_status(Err(PrePivotStatusError::Timeout), audit(&sink, None))
            .unwrap_err();
        assert_eq!(r.delivery, AuditDelivery::NotApplicable);
        assert_eq!(r.error.code, ErrorCode::Timeout);
        assert!(sink.snapshot().is_empty());
    }

    /// 厳格な復号: 許可リスト外の理由・余分なスペース・フィールド不足・1 行目の行・LF なしは `Malformed`（SEC-4・#2624）。
    #[test]
    fn sec4_2624_decode_rejects_malformed_exec_phase_lines() {
        for line in [
            &b"E PERMISSION_DENIED target_moved\n"[..],
            b"E PERMISSION_DENIED  entrypoint_is_runtime_binary\n",
            b"E PERMISSION_DENIED\n",
            b"E BOGUS -\n",
            b"R extra\n",
            b"P\n",
            b"F pivot_root INTERNAL -\n",
            b"R",
            b"\n",
        ] {
            assert_eq!(
                ExecPhaseStatus::decode(line),
                Err(PrePivotStatusError::Malformed),
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
        // 1 行目の復号は 2 行目の行を受けない。
        assert_eq!(
            PrePivotStatus::decode(b"R\n"),
            Err(PrePivotStatusError::Malformed)
        );
    }

    /// 子の失敗が entrypoint 系以外の違反なら理由は落ちるが、失敗としては届く（SEC-4・#2624）。
    #[test]
    fn sec4_2624_non_entrypoint_violation_is_dropped_but_reported() {
        let error = ExecError::from_violation_at(
            ViolationReason::TargetOnSharedMount,
            None,
            IsolationStage::Exec,
        );
        let status = ExecPhaseStatus::failed_from(&error);
        assert!(matches!(
            status,
            ExecPhaseStatus::Failed {
                violation: None,
                ..
            }
        ));
        // 実際の pipe 越しの往復（読み取りは期限つき）。
        let file = pipe_with(status.encode().as_bytes());
        assert_eq!(
            read_exec_phase_until_close(&file, Duration::from_secs(5)),
            Ok(ExecPhaseOutcome::Failed {
                code: ErrorCode::FailedPrecondition,
                violation: None
            })
        );
    }

    /// 完成した失敗報告は、状態 pipe が閉じなくても `Timeout` にならず失敗コードで返る
    /// （子が stderr で詰まる状況の模擬。REPAIR-5・CORE-5・#2716）。
    #[test]
    fn repair5_2716_complete_failure_report_is_decided_without_eof() {
        for (bytes, expected) in [
            (
                &b"R\nX PERMISSION_DENIED\n"[..],
                ExecPhaseOutcome::ExecReturned {
                    code: ErrorCode::PermissionDenied,
                },
            ),
            (
                b"E NOT_FOUND -\n",
                ExecPhaseOutcome::Failed {
                    code: ErrorCode::NotFound,
                    violation: None,
                },
            ),
        ] {
            let (r, w) = std::io::pipe().unwrap();
            let mut w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
            w.write_all(bytes).unwrap();
            // 書き込み側は閉じない（EOF にならない）。
            let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
            assert_eq!(
                read_exec_phase_until_close(&r, Duration::from_secs(5)),
                Ok(expected),
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
            drop(w);
        }
        // 成功候補の `R` だけなら EOF を待つ（閉じなければ期限で `Timeout`）。
        let (r, w) = std::io::pipe().unwrap();
        let mut w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
        w.write_all(b"R\n").unwrap();
        let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
        assert_eq!(
            read_exec_phase_until_close(&r, Duration::from_millis(200)),
            Err(PrePivotStatusError::Timeout)
        );
        drop(w);
    }

    /// `X` 行の具体値の符号化（ワイヤー形式の固定。SEC-4・#2716）。
    #[test]
    fn sec4_2716_encode_concrete_exec_returned_lines() {
        for (code, line) in [
            (ErrorCode::NotFound, &b"X NOT_FOUND\n"[..]),
            (ErrorCode::PermissionDenied, b"X PERMISSION_DENIED\n"),
            (ErrorCode::InvalidArgument, b"X INVALID_ARGUMENT\n"),
        ] {
            assert_eq!(ExecPhaseStatus::Returned { code }.encode().as_bytes(), line);
            assert_eq!(
                ExecPhaseStatus::decode(line),
                Ok(ExecPhaseStatus::Returned { code })
            );
        }
    }

    /// 末尾の復号: 受理する 3 形と、拒否する形（SEC-4・#2716）。
    #[test]
    fn sec4_2716_decode_tail_accepts_three_shapes_and_rejects_the_rest() {
        assert_eq!(
            ExecPhaseOutcome::decode_tail(b"R\n"),
            Ok(ExecPhaseOutcome::Executed)
        );
        assert_eq!(
            ExecPhaseOutcome::decode_tail(b"R\nX NOT_FOUND\n"),
            Ok(ExecPhaseOutcome::ExecReturned {
                code: ErrorCode::NotFound
            })
        );
        assert_eq!(
            ExecPhaseOutcome::decode_tail(b"E NOT_FOUND -\n"),
            Ok(ExecPhaseOutcome::Failed {
                code: ErrorCode::NotFound,
                violation: None
            })
        );
        assert_eq!(
            ExecPhaseOutcome::decode_tail(b""),
            Err(PrePivotStatusError::ClosedBeforeReport)
        );
        assert_eq!(
            ExecPhaseOutcome::decode_tail(b"R"),
            Err(PrePivotStatusError::Truncated)
        );
        for bytes in [
            &b"X NOT_FOUND\n"[..],
            b"R\nE NOT_FOUND -\n",
            b"R\nX FOO\n",
            b"R\nX NOT_FOUND\nZ",
            b"R\nX NOT_FOUND\nX NOT_FOUND\n",
            b"R\nR\n",
            b"E NOT_FOUND -\nX NOT_FOUND\n",
            b"E NOT_FOUND -\nR\n",
        ] {
            assert!(
                ExecPhaseOutcome::decode_tail(bytes).is_err(),
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
        }
    }

    /// `ErrorCode` の全値が `X` 行として上限内に収まり、往復する（SEC-4・#2716）。
    #[test]
    fn sec4_2716_every_error_code_fits_and_roundtrips_as_exec_returned() {
        for code in [
            ErrorCode::NotFound,
            ErrorCode::PermissionDenied,
            ErrorCode::InvalidArgument,
            ErrorCode::Internal,
            ErrorCode::Timeout,
            ErrorCode::FailedPrecondition,
        ] {
            let mut bytes = b"R\n".to_vec();
            bytes.extend_from_slice(ExecPhaseStatus::Returned { code }.encode().as_bytes());
            assert!(bytes.len() <= EXEC_PHASE_TAIL_MAX_BYTES);
            assert_eq!(
                ExecPhaseOutcome::decode_tail(&bytes),
                Ok(ExecPhaseOutcome::ExecReturned { code })
            );
        }
    }

    /// `R` と `X` が 1 回の `read` に入っても正しく復号される。EOF が無ければ期限切れ（SEC-4・REPAIR-5・#2716）。
    #[test]
    fn sec4_2716_read_until_close_handles_coalesced_lines_and_timeout() {
        let file = pipe_with(b"R\nX PERMISSION_DENIED\n");
        assert_eq!(
            read_exec_phase_until_close(&file, Duration::from_secs(5)),
            Ok(ExecPhaseOutcome::ExecReturned {
                code: ErrorCode::PermissionDenied
            })
        );
        let file = pipe_with(b"R\n");
        assert_eq!(
            read_exec_phase_until_close(&file, Duration::from_secs(5)),
            Ok(ExecPhaseOutcome::Executed)
        );
        // 書き込み側を保持したまま `R` だけ書く: EOF が来ないので期限切れ。
        let (r, w) = std::io::pipe().unwrap();
        let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
        let w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
        report_exec_ready(&w).unwrap();
        let started = Instant::now();
        assert_eq!(
            read_exec_phase_until_close(&r, Duration::from_millis(200)),
            Err(PrePivotStatusError::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(w);
    }

    /// 上限を超える入力は `TooLong`（無制限に読まない。SEC-4・#2716）。
    #[test]
    fn sec4_2716_read_until_close_rejects_oversized_input() {
        let big = vec![b'X'; EXEC_PHASE_TAIL_MAX_BYTES + 1];
        let file = pipe_with(&big);
        assert_eq!(
            read_exec_phase_until_close(&file, Duration::from_secs(5)),
            Err(PrePivotStatusError::TooLong)
        );
    }

    /// `ExecReturned` は起動失敗で、記録は 0 件・分類は errno 由来のコードのまま（SEC-4・#2716）。
    #[test]
    fn sec4_2716_exec_returned_is_a_launch_failure_without_audit_record() {
        let sink = VecSink::new(false);
        for code in [
            ErrorCode::NotFound,
            ErrorCode::PermissionDenied,
            ErrorCode::InvalidArgument,
        ] {
            let r = resolve_exec_phase_status(
                Ok(ExecPhaseOutcome::ExecReturned { code }),
                audit(&sink, None),
            )
            .unwrap_err();
            assert_eq!(r.delivery, AuditDelivery::NotApplicable);
            assert_eq!(r.error.code, code);
            assert_eq!(r.error.stage, IsolationStage::Exec);
        }
        assert!(sink.snapshot().is_empty());
    }
}
