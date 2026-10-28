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
//! E <step> <CODE> <reason|->\n        `execveat` の前の手順が失敗（<step> は [`ExecPhaseStep`] の段、<reason> は entrypoint 系の理由コードか -。#2895）
//! X <CODE>\n                           `R` の後の `execveat` が戻った（errno 由来の失敗。#2716）
//! ```
//!
//! 1 行目と 2 行目は先頭のトークン（`P`/`F` と `R`/`E`）で字句上も分かれ、取り違えは `Malformed` になる。
//! 2 行目は C が `P` を読み終え、listener を受け取って ACK を返した**後**にしか書かれない（PID 1 は ACK を待ってから
//! 検証へ進み、C は `P` の判定より前に listener を受け取らない）ため、2 行が 1 回の `read` に混ざらない。
//! 復号は 1 行目と同じく厳格で、理由は `ViolationReason::from_entrypoint_token`（固定語彙の走査）で静的な値へ
//! 引き直す。`E` 行の `<step>` も同じく固定語彙 [`ExecPhaseStep`] の許可リストで引き直し、未知の語・上限
//! （1 語 48 バイト）を超える語・旧 3 語形式は `Malformed` にする（状態 pipe の両端は同じランタイムのバイナリなので
//! 旧形式との互換は持たない。fail-closed）。
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
//! # 稼働中コンテナへの exec の失敗の行との対応（SUP-6・REPAIR-3・#2822）
//!
//! exec の子は同じ考え方（段・`ErrorCode`・理由コードだけを運ぶ）で、`<終了コード> <step> <CODE> <reason|->` の 4 語の
//! 行を別の状態 pipe に書く。語彙 `process::ExecChildStep` は `F <step>` の `PrePivotStep` とは別で、対応は
//! `ExecChildStep` の doc の表を正とする（要点: exec の `execveat` は本モジュールの `X`、`report_ready` は `R` を書けない
//! 場合、`close_fds` から `stdio_null` の 11 段は本モジュールの `E` 行と同じトークンで運ぶ共有の段
//! （[`LAUNCH_SHARED_EXEC_CHILD_STEPS`]。#2895）。`parent_lifetime`・`cgroup_join`・`report_ready`・`execveat` は
//! `E` 行では受けない。launch だけの段は `verify_caller`・`restriction_evidence`・`verify_root`・`landlock` の 4 つ（`landlock` は Landlock 段の照合の違反 3 理由を運ぶ。#2130）。
//! `F <step>` の 14 段に対応する exec の段は無い）。
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
use crate::launch_isolation::RecordedMountIdentity;
use crate::sys::{self, SysError};
use crate::traits::ContainerId;
use crate::traits::types::ErrorCode;

use super::{
    ExecChildStep, ExecError, IsolationStage, ViolationKind, ViolationReason,
    audit_entrypoint_violation, record_launch_mount_rejection_at,
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
    /// namespaced な sysctl の適用（`linux.sysctl` の指定時のみ。`readonly_paths` が `/proc/sys` を読み取り専用にする前。
    /// 違反の理由は運ばない。CRI-2・CORE-3・#2670）。
    ApplySysctls,
    /// `/sys` への sysfs の供給（`mounts[]` の sysfs の指定時のみ。#2020・SEC-2）。`readonly_paths` より前に載せる。
    MountSysfs,
    /// 専用 `/dev` の作成。
    CreateDefaultDevices,
    /// tmpfs のマウント。
    MountTmpfs,
    /// ファイルの注入。
    InjectFiles,
    /// 管理ルートの `/etc/hosts`・`/etc/resolv.conf` の bind mount（`LaunchOptions::etc_files` の指定時のみ。NET-12・#1872）。
    EtcFiles,
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
    /// pivot 直後の rootfs の読み取り専用化（`root.readonly=true` のときだけ。違反記録は運ばない。CORE-5・SEC-1・#2767）。
    RootReadOnly,
    /// pivot 後の作業ディレクトリへの `chdir`（`process.cwd`。OCI-1・TASK-29。違反記録は運ばない）。
    WorkingDir,
}

impl PrePivotStep {
    const ALL: [Self; 15] = [
        Self::Establish,
        Self::PrepareRootfs,
        Self::VerifyPinned,
        Self::ApplySysctls,
        Self::MountSysfs,
        Self::CreateDefaultDevices,
        Self::MountTmpfs,
        Self::InjectFiles,
        Self::EtcFiles,
        Self::MountBinds,
        Self::ReadonlyPaths,
        Self::MaskedPaths,
        Self::PivotRoot,
        Self::RootReadOnly,
        Self::WorkingDir,
    ];

    /// 段名（ワイヤー上のトークン。単体テストの `RecordingOps` の段名と一致させる）。
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Establish => "establish",
            Self::PrepareRootfs => "prepare_rootfs",
            Self::VerifyPinned => "verify_pinned",
            Self::ApplySysctls => "apply_sysctls",
            Self::MountSysfs => "mount_sysfs",
            Self::CreateDefaultDevices => "create_default_devices",
            Self::MountTmpfs => "mount_tmpfs",
            Self::InjectFiles => "inject_files",
            Self::EtcFiles => "etc_files",
            Self::MountBinds => "mount_binds",
            Self::ReadonlyPaths => "readonly_paths",
            Self::MaskedPaths => "masked_paths",
            Self::PivotRoot => "pivot_root",
            Self::RootReadOnly => "root_readonly",
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
            Self::ApplySysctls => IsolationStage::ApplySysctls,
            Self::MountSysfs => IsolationStage::MountSysfs,
            Self::CreateDefaultDevices => IsolationStage::CreateDevices,
            Self::MountTmpfs => IsolationStage::MountTmpfs,
            Self::InjectFiles => IsolationStage::InjectFiles,
            Self::EtcFiles => IsolationStage::MountEtcFiles,
            Self::MountBinds => IsolationStage::MountBinds,
            Self::ReadonlyPaths => IsolationStage::MountReadonlyPaths,
            Self::MaskedPaths => IsolationStage::MountMaskedPaths,
            Self::PivotRoot => IsolationStage::PivotRoot,
            Self::RootReadOnly => IsolationStage::RootReadOnly,
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

/// [`read_pre_pivot_status`] の、1 行目の後ろのバイトを取り込まない版（listener を受け取る launch 経路用。SEC-4・#2130）。
///
/// Landlock 段の失敗の `E landlock ...` は ACK の手順を経ずに `P` の直後に書かれ得るため、1 回の `read` で 2 行が
/// 混ざって `Malformed` になるのを避け、1 バイトずつ LF まで読む。後続のバイトは続く
/// `read_exec_phase_until_close` が厳格に復号する（余分な行は `Malformed`）。それ以外は [`read_pre_pivot_status`] と同じ。
pub(super) fn read_pre_pivot_status_leaving_tail(
    status: &std::fs::File,
    timeout: Duration,
) -> Result<PrePivotStatus, PrePivotStatusError> {
    let (buf, end) = read_line_inner::<PRE_PIVOT_STATUS_MAX_BYTES>(status, timeout, true)?;
    PrePivotStatus::decode(buf.get(..end).unwrap_or(&[]))
}

/// 子側: Mount 由来のルールの launch 時の識別子のブロック（`L <n>` と `M ...` × n 行）を 1 回の `write_all` で書く。
///
/// `P` の直後・Landlock 段より前に書く（親は `P` の判定の後・listener を受け取る前にこれを読み切る）。パス・
/// メッセージは運ばない（SEC-1・SEC-4・#3201）。書けなければ先へ進まない（親が識別子を得られないまま起動しない。fail-closed）。
pub(super) fn report_mount_identities(
    status: &std::fs::File,
    entries: &[(usize, RecordedMountIdentity)],
) -> Result<(), ExecError> {
    let mut block = format!("L {}\n", entries.len());
    for (rule, id) in entries {
        block.push_str(&format!(
            "M {} {} {} {} {}\n",
            rule,
            id.mnt_id(),
            id.dev(),
            id.ino(),
            u8::from(id.read_only())
        ));
    }
    (&*status)
        .write_all(block.as_bytes())
        .map_err(|e| ExecError::from_io(&e, IsolationStage::Spawn, "report the mount identities"))
}

/// 先頭 0 の無い 10 進の `u64`（`"0"` は可）。符号・空白・空文字・桁あふれは `None`。
fn parse_canonical_u64(token: &str) -> Option<u64> {
    let bytes = token.as_bytes();
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return None;
    }
    token.parse().ok()
}

/// 親側: 状態 pipe から [`report_mount_identities`] のブロックを期限つきで読み切って厳格に復号する
/// （SEC-1・SEC-4・REPAIR-2・REPAIR-5・#3201）。
///
/// `expected` は親が fork の前に ruleset から計算した Mount 由来のルールの位置の列（昇順）。本数と各行のルール位置が
/// これと完全一致することを要求する（確保の前に本数を検証する）。子は pivot 前段の後の untrusted なプロセスなので、
/// 単一スペース区切り・フィールド数固定・先頭 0 なし・`u64` の範囲内・`mnt_id` 0 なし・`ro` は `0`/`1` だけを受け、
/// 違反はすべて `Malformed`。1 バイトずつ LF まで読むため、後続の `E`/`R` 行を取り込まない。
pub(super) fn read_mount_identity_block(
    status: &std::fs::File,
    expected: &[usize],
    timeout: Duration,
) -> Result<Vec<(usize, RecordedMountIdentity)>, PrePivotStatusError> {
    let deadline = Instant::now() + timeout.min(READ_TIMEOUT_MAX);
    let line = || -> Result<String, PrePivotStatusError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let (buf, end) = read_line_inner::<PRE_PIVOT_STATUS_MAX_BYTES>(status, remaining, true)?;
        let bytes = buf.get(..end).unwrap_or(&[]);
        let text = std::str::from_utf8(bytes).map_err(|_| PrePivotStatusError::Malformed)?;
        text.strip_suffix('\n')
            .map(str::to_owned)
            .ok_or(PrePivotStatusError::Malformed)
    };
    let header = line()?;
    let count = header
        .strip_prefix("L ")
        .and_then(parse_canonical_u64)
        .ok_or(PrePivotStatusError::Malformed)?;
    if usize::try_from(count).ok() != Some(expected.len()) {
        return Err(PrePivotStatusError::Malformed);
    }
    let mut out = Vec::with_capacity(expected.len());
    for want in expected {
        let text = line()?;
        let fields: Vec<&str> = text.split(' ').collect();
        let [tag, rule, mnt_id, dev, ino, ro] = fields.as_slice() else {
            return Err(PrePivotStatusError::Malformed);
        };
        let bad = PrePivotStatusError::Malformed;
        if *tag != "M" {
            return Err(bad);
        }
        let rule = parse_canonical_u64(rule)
            .and_then(|r| usize::try_from(r).ok())
            .ok_or(bad)?;
        if rule != *want {
            return Err(bad);
        }
        let read_only = match *ro {
            "0" => false,
            "1" => true,
            _ => return Err(bad),
        };
        let id = RecordedMountIdentity::new(
            parse_canonical_u64(mnt_id).ok_or(bad)?,
            parse_canonical_u64(dev).ok_or(bad)?,
            parse_canonical_u64(ino).ok_or(bad)?,
            read_only,
        )
        .map_err(|_| bad)?;
        out.push((rule, id));
    }
    Ok(out)
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
    read_line_inner::<N>(pipe, timeout, false)
}

/// [`read_line_bounded`] の本体。`single_byte` が真なら 1 回の `read` で 1 バイトだけ読み、LF の後ろのバイトを
/// 取り込まない（行の後ろの余分なバイトは呼び出し側が続けて読む）。偽なら従来どおり、後ろに余分なバイトがあれば
/// `Malformed`。
fn read_line_inner<const N: usize>(
    pipe: &std::fs::File,
    timeout: Duration,
    single_byte: bool,
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
        let rest = if single_byte {
            rest.get_mut(..1).unwrap_or(&mut [])
        } else {
            rest
        };
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

/// `E` 行の語（段・CODE・理由）1 つの最大バイト数（語彙を引く前の長さの上限。exec の失敗の行
/// `process::EXEC_FAILURE_TOKEN_MAX` と同じ値。#2895）。
const EXEC_PHASE_TOKEN_MAX: usize = 48;

/// launch の `E` 行が受ける、exec と共有する `ExecChildStep`（`prepare_exec_child` の 11 段。#2895）。
///
/// `parent_lifetime`・`cgroup_join`（launch の PID 1 には無い）・`report_ready`（`R` を書けなければ行を書かない）・
/// `execveat`（`X` が担う）は `E` 行では受けない。`ExecChildStep::from_token` が通るだけでは受理しない
/// （取り違えた行を fail-closed に落とすため）。launch は `deferred_fsize = None` なので `deferred_rlimit` は
/// 実際には届かないが、`prepare_exec_child` の段なので語彙には含める。
pub(super) const LAUNCH_SHARED_EXEC_CHILD_STEPS: [ExecChildStep; 11] = [
    ExecChildStep::CloseFds,
    ExecChildStep::Setsid,
    ExecChildStep::OpenRoot,
    ExecChildStep::OpenEntrypoint,
    ExecChildStep::RuntimeIdentity,
    ExecChildStep::SelectExecutable,
    ExecChildStep::DeferredRlimit,
    ExecChildStep::Interpreter,
    ExecChildStep::ScriptFd,
    ExecChildStep::PrepareFds,
    ExecChildStep::StdioNull,
];

/// launch の `E` 行が運ぶ、`execveat` 前の手順の段（固定語彙。SUP-6・REPAIR-3・REPAIR-4・#2895）。
///
/// 子（PID 1）は untrusted 扱いなので、運ぶのはこのトークンだけで、親は [`ExecPhaseStep::from_token`] で
/// 静的な値へ引き直す（未知の語は `Malformed`）。段は情報用で、`reason` との整合は検査しない
/// （監査の記録の有無は従来どおり `reason` だけで決まる）。
/// - launch だけの段: `landlock`（制限ステージ列の Landlock 段。照合の違反 3 理由を運ぶ。#2130）、
///   `verify_caller`・`restriction_evidence`（`run_child` の検証）、`verify_root`（pivot 後の
///   `/` の mount ID 照合。`PrePivotStep` の `pivot_root` と重ならない名前）
/// - exec と共有する段: [`LAUNCH_SHARED_EXEC_CHILD_STEPS`] の 11 段（`prepare_exec_child` の手順）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum ExecPhaseStep {
    /// `isolation.verify_caller(Exec)` の失敗（launch だけ）。
    VerifyCaller,
    /// 制限適用の証跡の要求 `require_restriction_evidence` の失敗（launch だけ）。
    RestrictionEvidence,
    /// pivot 後の `/` の mount ID 照合 `verify_pivot_root` の失敗（launch だけ）。
    VerifyRoot,
    /// 制限ステージ列の Landlock 段の失敗（launch だけ。SEC-1・SEC-4・CORE-5・#2130）。Landlock 段は `P` の後、
    /// seccomp の listener を送る前に走るため、失敗すると親は listener を受け取れず、この段の `E` 行だけが
    /// 照合の違反（`ViolationReason::LANDLOCK_APPLY_REASONS`）を親へ運ぶ。
    Landlock,
    /// exec と共有する `prepare_exec_child` の段。
    Child(ExecChildStep),
}

impl ExecPhaseStep {
    /// launch だけの段（4 段）。
    pub(super) const LAUNCH_ONLY: [Self; 4] = [
        Self::VerifyCaller,
        Self::RestrictionEvidence,
        Self::VerifyRoot,
        Self::Landlock,
    ];

    /// ワイヤー上のトークン。
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::VerifyCaller => "verify_caller",
            Self::RestrictionEvidence => "restriction_evidence",
            Self::VerifyRoot => "verify_root",
            Self::Landlock => "landlock",
            Self::Child(step) => step.as_str(),
        }
    }

    /// トークンから静的な値へ引き直す（launch だけの段と [`LAUNCH_SHARED_EXEC_CHILD_STEPS`] の走査。共有外の
    /// exec の段・未知のトークンは `None`）。
    pub(super) fn from_token(token: &str) -> Option<Self> {
        Self::LAUNCH_ONLY
            .into_iter()
            .find(|s| s.as_str() == token)
            .or_else(|| {
                LAUNCH_SHARED_EXEC_CHILD_STEPS
                    .into_iter()
                    .find(|s| s.as_str() == token)
                    .map(Self::Child)
            })
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
        /// 失敗した手順（#2895）。
        step: ExecPhaseStep,
        code: ErrorCode,
        /// entrypoint 系の違反理由（`ENTRYPOINT_REASONS` のものだけ。それ以外は `None`）。
        violation: Option<ViolationReason>,
    },
    /// `R` を書いた後の `execveat` 自体が戻った（errno 由来の失敗。#2716）。`code` は errno の分類
    /// （`process::exec_errno_to_code`）。errno の生値・文字列は運ばない。
    Returned { code: ErrorCode },
}

/// `E` 行の段 `step` と理由コード `token` の組から理由を引き直す唯一の許可リスト照合（子の符号化と親の復号で共有。#2130）。
///
/// 段 `landlock` は Landlock 段の 3 理由（`LANDLOCK_APPLY_REASONS`）だけ、それ以外の段は entrypoint 系の 8 理由だけを
/// 通す。段と理由の食い違いは `None`（復号側は `Malformed`、符号化側は理由を落とす）。子は untrusted なので、
/// 文字列は固定語彙の走査で静的な値へ引き直す。
fn exec_phase_violation(step: ExecPhaseStep, token: &str) -> Option<ViolationReason> {
    match step {
        ExecPhaseStep::Landlock => ViolationReason::from_landlock_apply_token(token),
        _ => ViolationReason::from_entrypoint_token(token),
    }
}

impl ExecPhaseStatus {
    /// 子側の唯一の作成入口。段と整合しない理由は落とす（失敗として報告する点は変わらない）。
    pub(super) fn failed_from(step: ExecPhaseStep, error: &ExecError) -> Self {
        Self::Failed {
            step,
            code: error.code,
            violation: error
                .violation
                .as_ref()
                .and_then(|v| exec_phase_violation(step, v.reason.as_str())),
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
            Self::Failed {
                step,
                code,
                violation,
            } => {
                out.push("E ")
                    && out.push(step.as_str())
                    && out.push(" ")
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
            // 段は固定の `verify_caller` を使う（到達しない想定の代替行で、段は情報用のため）。
            let _ = out.push("E verify_caller INTERNAL -\n");
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
        // 語彙を引く前に各語の長さを抑える（untrusted な子の入力。#2895）。
        if parts.iter().any(|w| w.len() > EXEC_PHASE_TOKEN_MAX) {
            return Err(PrePivotStatusError::Malformed);
        }
        match parts.as_slice() {
            ["R"] => Ok(Self::Ready),
            ["X", code] => Ok(Self::Returned {
                code: ErrorCode::from_name(code).ok_or(PrePivotStatusError::Malformed)?,
            }),
            ["E", step, code, reason] => {
                let step = ExecPhaseStep::from_token(step).ok_or(PrePivotStatusError::Malformed)?;
                let code = ErrorCode::from_name(code).ok_or(PrePivotStatusError::Malformed)?;
                let violation = if *reason == "-" {
                    None
                } else {
                    Some(exec_phase_violation(step, reason).ok_or(PrePivotStatusError::Malformed)?)
                };
                Ok(Self::Failed {
                    step,
                    code,
                    violation,
                })
            }
            _ => Err(PrePivotStatusError::Malformed),
        }
    }
}

/// 子側: `execveat` の直前に `R` を 1 回の `write_all` で書く。書けなければ `execveat` へ進まない（fail-closed）。
pub(super) fn report_exec_ready(status: &std::fs::File) -> Result<(), ExecError> {
    write_status(status, &ExecPhaseStatus::Ready.encode())
}

/// 子側: `execveat` の前の手順 `step` の失敗 `error` を `E <step> ...` として書く。
pub(super) fn report_exec_failure(
    status: &std::fs::File,
    step: ExecPhaseStep,
    error: &ExecError,
) -> Result<(), ExecError> {
    write_status(status, &ExecPhaseStatus::failed_from(step, error).encode())
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
        step: ExecPhaseStep,
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
            ExecPhaseStatus::Failed {
                step,
                code,
                violation,
            } if rest.is_empty() => Ok(Self::Failed {
                step,
                code,
                violation,
            }),
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
        // 段 `landlock` の照合の違反は層 `mount` に記録する（#2130）。親が組み立てた `ExecError::stage` を記録にも載せる。
        Ok(ExecPhaseOutcome::Failed {
            step: ExecPhaseStep::Landlock,
            code,
            violation: Some(reason),
        }) => {
            let mut error = ExecError::from_violation_at(reason, None, IsolationStage::Landlock);
            // errno 由来の分類（`Unimplemented` 等）をワイヤーの `CODE` で保つ。記録の有無・理由は変わらない。
            error.code = code;
            Err(Box::new(record_launch_mount_rejection_at(
                error,
                reason,
                Some(IsolationStage::Landlock),
                audit.container,
                audit.sink,
            )))
        }
        Ok(ExecPhaseOutcome::Failed {
            violation: Some(reason),
            ..
        }) => Err(Box::new(audit_entrypoint_violation(
            ExecError::from_violation_at(reason, None, IsolationStage::Exec),
            audit.container,
            audit.sink,
        ))),
        Ok(ExecPhaseOutcome::Failed {
            step,
            code,
            violation: None,
        }) => Err(Box::new(AuditedRejection::not_applicable(ExecError::new(
            code,
            // Landlock 段の失敗は段 `Landlock` のまま運ぶ（理由なしは記録しない。#2130）。
            if step == ExecPhaseStep::Landlock {
                IsolationStage::Landlock
            } else {
                IsolationStage::Exec
            },
            // 静的な段のトークンだけを入れる（子の自由文は運ばない。`PrePivotStep` の文言と同じ形）。
            format!(
                "exec phase step '{}' failed in the container child",
                step.as_str()
            ),
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
    // 段は違反の出どころとして自然な共有の段に固定する（段は情報用で記録の有無には影響しない）。
    report_exec_failure(
        &w,
        ExecPhaseStep::Child(ExecChildStep::OpenEntrypoint),
        &error,
    )
    .map_err(|e| Box::new(AuditedRejection::not_applicable(e)))?;
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

/// 結合試験専用: 段 `landlock` の違反 `reason` を、子の符号化・状態 pipe・親の復号と記録まで本番と同じ関数で
/// 往復させる（SEC-1・SEC-4・CORE-5・#2130）。通常の利用者は呼ばない。
///
/// 許可リスト外の理由（entrypoint 系等）は子の符号化で落ち、理由なしの失敗として届く（記録されない）。
#[doc(hidden)]
#[cfg(feature = "exec-test-support")]
pub fn relay_landlock_failure_for_test(
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
    let error = ExecError::from_violation_at(reason, None, IsolationStage::Landlock);
    report_exec_failure(&w, ExecPhaseStep::Landlock, &error)
        .map_err(|e| Box::new(AuditedRejection::not_applicable(e)))?;
    drop(w);
    let status = read_exec_phase_until_close(&r, Duration::from_secs(5));
    resolve_exec_phase_status(status, LaunchAudit { sink, container })
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
                // 段は親が組み立てた `ExecError::stage` を記録にも載せる（#3121）。
                let stage = error.stage;
                record_launch_mount_rejection_at(
                    error,
                    reason,
                    Some(stage),
                    audit.container,
                    audit.sink,
                )
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
        PrePivotStep::ApplySysctls => 3,
        PrePivotStep::MountSysfs => 4,
        PrePivotStep::CreateDefaultDevices => 5,
        PrePivotStep::MountTmpfs => 6,
        PrePivotStep::InjectFiles => 7,
        PrePivotStep::EtcFiles => 8,
        PrePivotStep::MountBinds => 9,
        PrePivotStep::ReadonlyPaths => 10,
        PrePivotStep::MaskedPaths => 11,
        PrePivotStep::PivotRoot => 12,
        PrePivotStep::RootReadOnly => 13,
        PrePivotStep::WorkingDir => 14,
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

    /// SEC-1・SEC-4・REPAIR-2・#3201: 識別子のブロックの符号化は具体値で固定され、復号で往復する。
    #[test]
    fn sec1_3201_mount_identity_block_roundtrips_with_exact_wire_form() {
        let entries = vec![
            (1, RecordedMountIdentity::new(11, 2, 3, false).unwrap()),
            (3, RecordedMountIdentity::new(13, 4, 5, true).unwrap()),
        ];
        let (r, w) = std::io::pipe().unwrap();
        let w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
        report_mount_identities(&w, &entries).unwrap();
        drop(w);
        let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
        let got = read_mount_identity_block(&r, &[1, 3], Duration::from_secs(5)).unwrap();
        assert_eq!(got, entries);

        let r = pipe_with(b"L 1\nM 7 11 2 3 1\n");
        let got = read_mount_identity_block(&r, &[7], Duration::from_secs(5)).unwrap();
        assert_eq!(
            got,
            vec![(7, RecordedMountIdentity::new(11, 2, 3, true).unwrap())]
        );
        let r = pipe_with(b"L 0\n");
        assert_eq!(
            read_mount_identity_block(&r, &[], Duration::from_secs(5)).unwrap(),
            Vec::new()
        );
    }

    /// SEC-1・SEC-4・REPAIR-2・#3201: 本数・ルール位置・書式・ro の値の違反は `Malformed`、行の途中の EOF は
    /// `Malformed` 以外の失敗になり、いずれも識別子を返さない(fail-closed)。
    #[test]
    fn sec1_3201_mount_identity_block_rejects_malformed_input() {
        let cases: &[(&[u8], &[usize])] = &[
            (b"L 2\nM 1 11 2 3 0\nM 3 13 4 5 1\n", &[1]),
            (b"L 1\nM 2 11 2 3 0\n", &[1]),
            (b"L 1\nM 1 11 2 3 2\n", &[1]),
            (b"L 1\nM 1 011 2 3 0\n", &[1]),
            (b"L 1\nM 1 0 2 3 0\n", &[1]),
            (b"L 1\nM 1  11 2 3 0\n", &[1]),
            (b"L 1\nM 1 11 2 3\n", &[1]),
            (b"L 1\nX 1 11 2 3 0\n", &[1]),
            (b"L 01\nM 1 11 2 3 0\n", &[1]),
            (b"L 1\nM 1 99999999999999999999 2 3 0\n", &[1]),
            (b"P\n", &[]),
        ];
        for (bytes, expected) in cases {
            let r = pipe_with(bytes);
            assert_eq!(
                read_mount_identity_block(&r, expected, Duration::from_secs(5)),
                Err(PrePivotStatusError::Malformed),
                "{:?}",
                String::from_utf8_lossy(bytes)
            );
        }
        let r = pipe_with(b"L 1\nM 1 11 2");
        assert!(read_mount_identity_block(&r, &[1], Duration::from_secs(5)).is_err());
        let r = pipe_with(b"");
        assert!(read_mount_identity_block(&r, &[], Duration::from_secs(5)).is_err());
    }

    /// 段の一覧は全 variant を網羅する（`ErrorCode` は types.rs の試験）（足し忘れの検出。REPAIR-2）。
    #[test]
    fn sec4_1815_tables_cover_every_variant() {
        for (i, s) in PrePivotStep::ALL.into_iter().enumerate() {
            assert_eq!(step_ordinal(s), i);
        }
        assert_eq!(PrePivotStep::ALL.len(), 15);
    }

    /// exec の子の段（`ExecChildStep`）と launch の段のトークンは重ならない（取り違えの検出。SUP-6・#2822）。
    #[test]
    fn sup6_2822_exec_child_tokens_do_not_overlap_pre_pivot_tokens() {
        for exec_step in super::super::ExecChildStep::ALL {
            for step in PrePivotStep::ALL {
                assert_ne!(exec_step.as_str(), step.as_str());
            }
        }
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

    /// SEC-4・#2130: listener 経路の 1 行目の読みは `P` の後ろのバイトを取り込まず、続く 2 行目の読みが `E landlock` を
    /// 受け取る。余分な行は 2 行目の復号で `Malformed`。
    #[test]
    fn sec4_2130_leaving_tail_keeps_the_next_line_for_the_phase_reader() {
        let t = Duration::from_secs(5);
        let f = pipe_with(b"P\nE landlock FAILED_PRECONDITION landlock_mount_not_root\n");
        assert_eq!(
            read_pre_pivot_status_leaving_tail(&f, t),
            Ok(PrePivotStatus::Ready)
        );
        assert_eq!(
            read_exec_phase_until_close(&f, t),
            Ok(ExecPhaseOutcome::Failed {
                step: ExecPhaseStep::Landlock,
                code: ErrorCode::FailedPrecondition,
                violation: Some(ViolationReason::LandlockMountNotRoot),
            })
        );
        let f = pipe_with(b"P\nP\n");
        assert_eq!(
            read_pre_pivot_status_leaving_tail(&f, t),
            Ok(PrePivotStatus::Ready)
        );
        assert_eq!(
            read_exec_phase_until_close(&f, t),
            Err(PrePivotStatusError::Malformed)
        );
        assert_eq!(
            read_pre_pivot_status_leaving_tail(&pipe_with(b"F establish"), t),
            Err(PrePivotStatusError::Truncated)
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
            step: ExecPhaseStep::Child(ExecChildStep::OpenEntrypoint),
            code: ErrorCode::PermissionDenied,
            violation: Some(ViolationReason::EntrypointIsRuntimeBinary),
        };
        assert_eq!(
            e.encode().as_bytes(),
            b"E open_entrypoint PERMISSION_DENIED entrypoint_is_runtime_binary\n"
        );
        let n = ExecPhaseStatus::Failed {
            step: ExecPhaseStep::VerifyRoot,
            code: ErrorCode::NotFound,
            violation: None,
        };
        assert_eq!(n.encode().as_bytes(), b"E verify_root NOT_FOUND -\n");
    }

    /// 8 理由すべてが符号化・復号で往復し、親の記録は層 `entrypoint` に理由コードだけ・パスなしで 1 件（SEC-4・#2624）。
    #[test]
    fn sec4_2624_every_entrypoint_reason_roundtrips_and_records_once() {
        assert_eq!(ViolationReason::ENTRYPOINT_REASONS.len(), 8);
        let id = ContainerId::new("c2624").unwrap();
        for reason in ViolationReason::ENTRYPOINT_REASONS {
            let error = ExecError::from_violation_at(reason, None, IsolationStage::Exec);
            let status = ExecPhaseStatus::failed_from(
                ExecPhaseStep::Child(ExecChildStep::OpenEntrypoint),
                &error,
            );
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
                step: ExecPhaseStep::VerifyRoot,
                code: ErrorCode::NotFound,
                violation: None,
            }),
            audit(&sink, None),
        )
        .unwrap_err();
        assert_eq!(r.delivery, AuditDelivery::NotApplicable);
        assert_eq!(r.error.code, ErrorCode::NotFound);
        assert_eq!(r.error.stage, IsolationStage::Exec);
        assert_eq!(
            r.error.message,
            "exec phase step 'verify_root' failed in the container child"
        );
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
            &b"E open_entrypoint PERMISSION_DENIED target_moved\n"[..],
            b"E open_entrypoint PERMISSION_DENIED  entrypoint_is_runtime_binary\n",
            b"E open_entrypoint PERMISSION_DENIED\n",
            b"E open_entrypoint BOGUS -\n",
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
        let status = ExecPhaseStatus::failed_from(ExecPhaseStep::VerifyCaller, &error);
        assert!(matches!(
            status,
            ExecPhaseStatus::Failed {
                step: ExecPhaseStep::VerifyCaller,
                violation: None,
                ..
            }
        ));
        // 実際の pipe 越しの往復（読み取りは期限つき）。
        let file = pipe_with(status.encode().as_bytes());
        assert_eq!(
            read_exec_phase_until_close(&file, Duration::from_secs(5)),
            Ok(ExecPhaseOutcome::Failed {
                step: ExecPhaseStep::VerifyCaller,
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
                b"E setsid NOT_FOUND -\n",
                ExecPhaseOutcome::Failed {
                    step: ExecPhaseStep::Child(ExecChildStep::Setsid),
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
            ExecPhaseOutcome::decode_tail(b"E restriction_evidence NOT_FOUND -\n"),
            Ok(ExecPhaseOutcome::Failed {
                step: ExecPhaseStep::RestrictionEvidence,
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
            b"R\nE setsid NOT_FOUND -\n",
            b"R\nX FOO\n",
            b"R\nX NOT_FOUND\nZ",
            b"R\nX NOT_FOUND\nX NOT_FOUND\n",
            b"R\nR\n",
            b"E setsid NOT_FOUND -\nX NOT_FOUND\n",
            b"E setsid NOT_FOUND -\nR\n",
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

    /// 全 `ExecPhaseStep`（launch だけの 3 段と共有の 11 段）。
    fn all_phase_steps() -> Vec<ExecPhaseStep> {
        let mut v = ExecPhaseStep::LAUNCH_ONLY.to_vec();
        v.extend(LAUNCH_SHARED_EXEC_CHILD_STEPS.map(ExecPhaseStep::Child));
        v
    }

    /// SUP-6・REPAIR-3・#2895: `E` 行は段つきの具体値へ符号化される。
    #[test]
    fn sup6_2895_encode_concrete_exec_phase_lines() {
        let line = |step, code, violation| {
            ExecPhaseStatus::Failed {
                step,
                code,
                violation,
            }
            .encode()
        };
        assert_eq!(
            line(
                ExecPhaseStep::VerifyCaller,
                ErrorCode::PermissionDenied,
                None
            )
            .as_bytes(),
            b"E verify_caller PERMISSION_DENIED -\n"
        );
        assert_eq!(
            line(
                ExecPhaseStep::RestrictionEvidence,
                ErrorCode::FailedPrecondition,
                None
            )
            .as_bytes(),
            b"E restriction_evidence FAILED_PRECONDITION -\n"
        );
        assert_eq!(
            line(
                ExecPhaseStep::VerifyRoot,
                ErrorCode::FailedPrecondition,
                None
            )
            .as_bytes(),
            b"E verify_root FAILED_PRECONDITION -\n"
        );
        assert_eq!(
            line(
                ExecPhaseStep::Child(ExecChildStep::StdioNull),
                ErrorCode::Internal,
                Some(ViolationReason::EntrypointIsRuntimeBinary)
            )
            .as_bytes(),
            b"E stdio_null INTERNAL entrypoint_is_runtime_binary\n"
        );
    }

    /// SUP-6・#2895: 全段 x 全 `ErrorCode` x 全 entrypoint 理由が往復し、最長の行も上限内に収まる。
    #[test]
    fn sup6_2895_roundtrip_every_step_code_and_reason() {
        let steps = all_phase_steps();
        assert_eq!(steps.len(), 15);
        let mut longest = 0;
        for step in steps {
            for code in ErrorCode::ALL {
                // 段 `landlock` は Landlock 段の 3 理由だけ、他の段は entrypoint 系の 8 理由だけが往復する（#2130）。
                let allowed: &[ViolationReason] = if step == ExecPhaseStep::Landlock {
                    &ViolationReason::LANDLOCK_APPLY_REASONS
                } else {
                    &ViolationReason::ENTRYPOINT_REASONS
                };
                let reasons = std::iter::once(None).chain(allowed.iter().copied().map(Some));
                for violation in reasons {
                    let status = ExecPhaseStatus::Failed {
                        step,
                        code,
                        violation,
                    };
                    let enc = status.encode();
                    longest = longest.max(enc.as_bytes().len());
                    assert_eq!(ExecPhaseStatus::decode(enc.as_bytes()), Ok(status));
                    assert_eq!(
                        ExecPhaseOutcome::decode_tail(enc.as_bytes()),
                        Ok(ExecPhaseOutcome::Failed {
                            step,
                            code,
                            violation
                        })
                    );
                }
            }
        }
        assert!(longest <= PRE_PIVOT_STATUS_MAX_BYTES, "{longest}");
    }

    /// SUP-6・#2895: 旧 3 語形式・共有外の exec の段・語彙外・長すぎる語・空の段は `Malformed`。
    #[test]
    fn sup6_2895_decode_rejects_bad_steps() {
        let long = format!("E {} NOT_FOUND -\n", "s".repeat(EXEC_PHASE_TOKEN_MAX + 1));
        let lines: Vec<&[u8]> = vec![
            b"E NOT_FOUND -\n",
            b"E parent_lifetime NOT_FOUND -\n",
            b"E cgroup_join NOT_FOUND -\n",
            b"E report_ready NOT_FOUND -\n",
            b"E execveat NOT_FOUND -\n",
            b"E bogus NOT_FOUND -\n",
            b"E pivot_root NOT_FOUND -\n",
            b"E  NOT_FOUND -\n",
            b"E setsid  NOT_FOUND -\n",
            long.as_bytes(),
        ];
        for line in lines {
            assert_eq!(
                ExecPhaseStatus::decode(line),
                Err(PrePivotStatusError::Malformed),
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
    }

    /// SUP-6・REPAIR-3・#2895: 共有の許可リストは `prepare_exec_child` の 11 段と一致し、launch だけの 3 語は
    /// exec の全段・pivot 前段のどちらとも重ならない。
    #[test]
    fn sup6_2895_step_tokens_do_not_overlap() {
        let shared: Vec<&str> = LAUNCH_SHARED_EXEC_CHILD_STEPS
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(
            shared,
            [
                "close_fds",
                "setsid",
                "open_root",
                "open_entrypoint",
                "runtime_identity",
                "select_executable",
                "deferred_rlimit",
                "interpreter",
                "script_fd",
                "prepare_fds",
                "stdio_null"
            ]
        );
        let only: Vec<&str> = ExecPhaseStep::LAUNCH_ONLY
            .iter()
            .map(|s| s.as_str())
            .collect();
        assert_eq!(
            only,
            [
                "verify_caller",
                "restriction_evidence",
                "verify_root",
                "landlock"
            ]
        );
        for token in &only {
            assert!(ExecChildStep::from_token(token).is_none(), "{token}");
            assert!(PrePivotStep::from_token(token).is_none(), "{token}");
        }
        // exec の全段のうち、共有でないものは `E` 行で受けない。
        for step in ExecChildStep::ALL {
            let accepted = ExecPhaseStep::from_token(step.as_str()).is_some();
            assert_eq!(
                accepted,
                LAUNCH_SHARED_EXEC_CHILD_STEPS.contains(&step),
                "{}",
                step.as_str()
            );
        }
        // 全トークンが一意。
        let mut all: Vec<&str> = all_phase_steps().into_iter().map(|s| s.as_str()).collect();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 15);
    }

    /// 子の符号化 → 状態 pipe → 親の復号 → 記録までを段 `landlock` で往復させる（本番と同じ関数）。
    fn relay_landlock(
        reason: ViolationReason,
        sink: &VecSink,
    ) -> Result<(), Box<AuditedRejection<ExecError>>> {
        let (r, w) = std::io::pipe().unwrap();
        let w = std::fs::File::from(std::os::fd::OwnedFd::from(w));
        let r = std::fs::File::from(std::os::fd::OwnedFd::from(r));
        let error = ExecError::from_violation_at(reason, None, IsolationStage::Landlock);
        report_exec_failure(&w, ExecPhaseStep::Landlock, &error).unwrap();
        drop(w);
        resolve_exec_phase_status(
            read_exec_phase_until_close(&r, Duration::from_secs(5)),
            LaunchAudit {
                sink,
                container: None,
            },
        )
    }

    /// SEC-4・SEC-1・CORE-5・#2130: 段 `landlock` の 3 理由は 1 拒否 1 件、層 `mount`・パスなし・段 `landlock` で記録される。
    #[test]
    fn sec4_2130_landlock_reasons_are_recorded_once_with_stage() {
        assert_eq!(ViolationReason::LANDLOCK_APPLY_REASONS.len(), 3);
        for reason in ViolationReason::LANDLOCK_APPLY_REASONS {
            let token = reason.as_str();
            let sink = VecSink::new(false);
            let r = relay_landlock(reason, &sink).unwrap_err();
            assert_eq!(r.delivery, AuditDelivery::Recorded, "{token}");
            assert_eq!(r.error.stage, IsolationStage::Landlock, "{token}");
            assert_eq!(
                r.error.violation.as_ref().map(|v| v.reason.as_str()),
                Some(token)
            );
            let recs = sink.snapshot();
            assert_eq!(recs.len(), 1, "{token}");
            assert_eq!(recs[0].layer(), AuditLayer::Mount);
            assert_eq!(recs[0].path(), None);
            assert_eq!(recs[0].reason().map(|x| x.as_str()), Some(token));
        }
    }

    /// SEC-4・#2130: 記録先が失敗しても拒否は覆らず、失敗は `SinkFailed` として残る。
    #[test]
    fn sec4_2130_sink_failure_keeps_the_landlock_rejection() {
        let sink = VecSink::new(true);
        let r = relay_landlock(ViolationReason::LandlockMountNotRoot, &sink).unwrap_err();
        assert!(
            matches!(r.delivery, AuditDelivery::SinkFailed { .. }),
            "{:?}",
            r.delivery
        );
        assert_eq!(r.error.stage, IsolationStage::Landlock);
        assert!(sink.snapshot().is_empty());
    }

    /// SEC-4・#2130: 段と理由の食い違い（段 `landlock` に entrypoint 系、entrypoint 系の段に landlock の理由）は復号で
    /// `Malformed`（fail-closed）。理由 `-` は記録なしの失敗のまま、段は `Landlock`。
    #[test]
    fn sec4_2130_landlock_step_reason_mismatch_is_malformed() {
        let lines: [&[u8]; 3] = [
            b"E landlock INTERNAL entrypoint_is_runtime_binary\n",
            b"E open_root FAILED_PRECONDITION landlock_mount_not_root\n",
            b"E landlock FAILED_PRECONDITION bogus\n",
        ];
        for line in lines {
            assert_eq!(
                ExecPhaseStatus::decode(line),
                Err(PrePivotStatusError::Malformed),
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
        let sink = VecSink::new(false);
        let r = resolve_exec_phase_status(
            ExecPhaseOutcome::decode_tail(b"E landlock UNIMPLEMENTED -\n"),
            LaunchAudit {
                sink: &sink,
                container: None,
            },
        )
        .unwrap_err();
        assert_eq!(r.delivery, AuditDelivery::NotApplicable);
        assert_eq!(r.error.code, ErrorCode::Unimplemented);
        assert_eq!(r.error.stage, IsolationStage::Landlock);
        assert!(sink.snapshot().is_empty());
    }

    /// 子の符号化は段と整合しない理由を落とす（段 `landlock` に entrypoint 系の理由は載らない）。
    #[test]
    fn sec4_2130_failed_from_drops_reason_of_the_other_family() {
        let e = ExecError::from_violation_at(
            ViolationReason::EntrypointIsRuntimeBinary,
            None,
            IsolationStage::Landlock,
        );
        assert_eq!(
            ExecPhaseStatus::failed_from(ExecPhaseStep::Landlock, &e)
                .encode()
                .as_bytes(),
            format!("E landlock {} -\n", e.code.as_str()).as_bytes()
        );
    }
}
