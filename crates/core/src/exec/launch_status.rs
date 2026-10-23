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
    ExecError, IsolationStage, ViolationKind, ViolationReason, record_launch_mount_rejection,
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

/// `ErrorCode` の全 variant（`as_str` の逆引き用。`ErrorCode` に `from_str` が無いため）。
/// 足し忘れは `error_code_ordinal` を使う単体テストが検出する。
pub(super) const ALL_ERROR_CODES: [ErrorCode; 10] = [
    ErrorCode::InvalidArgument,
    ErrorCode::NotFound,
    ErrorCode::AlreadyExists,
    ErrorCode::FailedPrecondition,
    ErrorCode::Unimplemented,
    ErrorCode::Internal,
    ErrorCode::PermissionDenied,
    ErrorCode::Timeout,
    ErrorCode::Unavailable,
    ErrorCode::ResourceExhausted,
];

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
                let code = ALL_ERROR_CODES
                    .into_iter()
                    .find(|c| c.as_str() == *code)
                    .ok_or(PrePivotStatusError::Malformed)?;
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
fn error_code_ordinal(code: ErrorCode) -> usize {
    match code {
        ErrorCode::InvalidArgument => 0,
        ErrorCode::NotFound => 1,
        ErrorCode::AlreadyExists => 2,
        ErrorCode::FailedPrecondition => 3,
        ErrorCode::Unimplemented => 4,
        ErrorCode::Internal => 5,
        ErrorCode::PermissionDenied => 6,
        ErrorCode::Timeout => 7,
        ErrorCode::Unavailable => 8,
        ErrorCode::ResourceExhausted => 9,
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

    /// `ErrorCode`・段の一覧は全 variant を網羅する（足し忘れの検出。REPAIR-2）。
    #[test]
    fn sec4_1815_tables_cover_every_variant() {
        for (i, c) in ALL_ERROR_CODES.into_iter().enumerate() {
            assert_eq!(error_code_ordinal(c), i);
        }
        assert_eq!(ALL_ERROR_CODES.len(), 10);
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
            for code in ALL_ERROR_CODES {
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
}
