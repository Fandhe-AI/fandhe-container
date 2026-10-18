//! 本番 launcher が使う、中間プロセス経由のコンテナ起動（TASK-29 追補・#1816。CORE-1・CORE-2・CORE-5・
//! SEC-1・SEC-4・SEC-5・REPAIR-2・REPAIR-3・REPAIR-5）。
//!
//! # 役割と呼び出し文脈
//!
//! `oci_runtime` の本番 `ProcessLauncher`（`ProductionLauncher`）が、fork 前の準備（分離計画・Landlock の
//! ruleset・ステージ列・状態 pipe）を済ませたうえで呼ぶ唯一の起動入口 [`spawn_container_via_intermediate`]。
//! 呼び出しプロセス C（`Threads: 1` の supervisor。child subreaper の証跡を持つ）は次の順で動く。
//!
//! ```text
//! C --fork--> I(中間プロセス) : isolate(plan。範囲写像では mapper を fork し、応答まで待つ) -> fork -> PID 1(child_main) / 報告 pipe へ "K <pid>" -> _exit
//! C : 報告 pipe を期限つきで読む -> adopt_reparented(pid) で PID 1 の pidfd を開く -> I を回収する
//!   -> 状態 pipe(pivot 前段の結果)を読み、監査(C だけが sink に触る)・判定 -> 失敗なら PID 1 を kill_and_reap
//! ```
//!
//! - **二重 fork の理由**: `unshare(CLONE_NEWPID)` の効果は次の子にだけ及ぶ。呼び出しプロセスを分離すると
//!   supervisor 自身が namespace に入ってしまうため、使い捨ての I が分離して PID 1 を作る
//! - **I は監査 sink に触れない**: PID 1 が死んだ後の I は新しい PID namespace の中にあり、`fork` が失敗する。
//!   `FileAuditSink::record` は内部で fork するため、I で記録すると主経路が使えない。C は元の PID namespace で
//!   `Threads: 1` なので sink が主経路で書ける
//! - **PID の再利用**: C は child subreaper（[`ChildSubreaper`] の証跡を引数に取る）。I の終了で PID 1 は C へ
//!   再親付けされ、C が回収するまで pid は解放されない。pidfd は報告の受領直後に開けばよく、確認応答は要らない
//! - **fork は `Threads: 1` が前提**: C が複数スレッドなら I を作らず `FailedPrecondition` で拒否する(副作用は
//!   pipe の作成のみ)。I は C の単一スレッドの fork 子で、`fork_single_threaded_no_flush` を使うため C の stdio
//!   バッファを二重に出力しない
//!
//! # 報告 pipe のワイヤー形式(REPAIR-2。ASCII 1 行・LF 終端・最大 [`REPORT_MAX_BYTES`] バイト)
//!
//! ```text
//! K <pid>\n              PID 1 のホスト側 pid(1 以上の 10 進。先頭 0 なし)
//! R <CODE> <phase>\n     失敗(<CODE> は ErrorCode、<phase> は isolate | spawn)
//! ```
//!
//! 運ぶのは pid・`ErrorCode`・固定語彙の段名だけで、英語メッセージ・パス・errno は運ばない。復号は厳格(単一
//! スペース区切り・フィールド数固定・全トークンが許可リスト内・末尾に余分なバイト無し)。
//!
//! # 時間上限(REPAIR-5)
//!
//! `timeout` を入口で 1 つの期限に変換し、報告の読み取りと状態の読み取りは同じ期限から残り時間を導く。失敗後の
//! 後始末が足す上限は固定値(中間プロセスの回収 [`INTERMEDIATE_REAP_TIMEOUT`]、`kill_and_reap` の
//! `KILL_REAP_TIMEOUT`)で、戻りは `timeout` ＋後始末の上限以内。
//!
//! # 未実装・残余(REPAIR-3)
//!
//! - **報告前の PID 1(CORE-2)**: I が PID 1 を作った後、`K` の報告前に停止・終了すると C は pid を知れない。
//!   I は fork の直前に起動ごとの識別子(`LaunchTag`)を `comm` へ設定し、PID 1 はそれを継承する。C は報告の
//!   無い失敗で I を SIGKILL して回収した後(PID 1 は C へ再親付け済み)、`/proc` から「親が C で `comm` が
//!   識別子と一致する」子を探して `kill_and_reap` する(`recover_unreported_init`)。I を回収できない場合は
//!   再親付けが起きないため探索せず、I を `unreaped` で返し、探索できなかった識別子を `rescans` で返す(呼び出し側が
//!   起動予約を保持し、`confirm_no_process` が I の回収後に `rescan_unreported_init` で再探索する。#1817)。報告が `R`(失敗)の経路は PID 1 を作っていないため探索しない
//! - **開始ゲート(CORE-2)**: PID 1 は C が `K` の pid を受領して pidfd を開き、1 行の許可を書くまで exec に進まない
//!   (exec で `comm` の識別子が失われると、報告前の PID 1 を特定できなくなるため)。C が許可せず閉じる・期限
//!   ([`START_GATE_TIMEOUT`])切れの PID 1 は exec せずに終了する
//! - **探索の fail-closed**: `/proc` の列挙・stat / comm の読み取りや解析の失敗は `reap_error` に残し、消滅を
//!   確認できた場合(対象が `ENOENT`/`ESRCH` で消えた)と区別する
//! - 回収できなかった子は [`PreparedLaunchFailure::unreaped`] で呼び出し側(launcher)へ返す。握りつぶさない
//! - `dev.tty.legacy_tiocsti` の警告出力(#1739)は本入口に足していない

use std::io::Write as _;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd as _, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use crate::audit_log::AuditedRejection;
use crate::sys;
use crate::traits::types::ErrorCode;

use super::launch_status::{
    ALL_ERROR_CODES, LaunchAudit, PrePivotStatusError, read_line_bounded, read_pre_pivot_status,
    resolve_pre_pivot_status,
};
use super::process::{
    ChildStdio, ContainerChild, EXIT_SETUP_FAILED, Entrypoint, KILL_REAP_TIMEOUT, PrePivotSetup,
    PreparedLaunchFailure, child_main, exec_status_pipe,
};
use super::{
    ChildSubreaper, ExecError, IsolationPlan, IsolationStage, StagePipeline,
    SubordinateIsolationPlan, isolate, isolate_rootless_subordinate_no_flush,
};

/// 報告行の最大バイト数(LF を含む)。最長の行(`R FAILED_PRECONDITION isolate\n` 約 30 バイト)より大きい固定上限。
pub(super) const REPORT_MAX_BYTES: usize = 48;

/// 報告後に中間プロセスが終了して回収できるまでの待ち上限(REPAIR-5)。超えたら SIGKILL して回収する。
pub(super) const INTERMEDIATE_REAP_TIMEOUT: Duration = Duration::from_secs(5);

/// PID 1 が C の開始許可を待つ上限(C は pid 受領直後に許可するため通常は即時。CORE-2・REPAIR-5)。
const START_GATE_TIMEOUT: Duration = Duration::from_secs(60);
/// 期限に許す最大値(`Instant` の加算オーバーフローを避ける丸め)。
const TIMEOUT_MAX: Duration = Duration::from_secs(24 * 60 * 60);

/// 中間プロセスが失敗した段(ワイヤー上のトークン)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum IntermediatePhase {
    /// `isolate`(namespace 分離・ID 写像)。
    Isolate,
    /// PID 1 の `fork`。
    Spawn,
}

impl IntermediatePhase {
    const ALL: [Self; 2] = [Self::Isolate, Self::Spawn];

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Isolate => "isolate",
            Self::Spawn => "spawn",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == token)
    }

    /// 親が段名から写す `ExecError` の段と固定メッセージ(パス・errno を含めない)。
    fn describe(self) -> (IsolationStage, &'static str) {
        match self {
            Self::Isolate => (
                IsolationStage::Unshare,
                "namespace isolation failed in the intermediate process",
            ),
            Self::Spawn => (
                IsolationStage::Spawn,
                "the container init could not be created in the intermediate process",
            ),
        }
    }
}

/// 中間プロセスから C への報告。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(super) enum IntermediateReport {
    /// PID 1 を作った(ホスト側の pid)。
    Pid1(NonZeroU32),
    /// 失敗した(原因の `ErrorCode` と段)。
    Failed {
        code: ErrorCode,
        phase: IntermediatePhase,
    },
}

/// 符号化済みの報告行(固定長配列＋長さ。`Vec` を手で組まない。REPAIR-2)。
#[derive(Debug, Clone, Copy)]
pub(super) struct EncodedReport {
    buf: [u8; REPORT_MAX_BYTES],
    len: usize,
}

impl EncodedReport {
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

/// 符号化が上限に収まらないときの失敗行(到達しない想定。成功行に落とさず失敗側へ倒す)。
const FALLBACK_REPORT: &[u8] = b"R INTERNAL spawn\n";

impl IntermediateReport {
    /// 報告行へ符号化する。
    pub(super) fn encode(&self) -> EncodedReport {
        let mut out = EncodedReport {
            buf: [0; REPORT_MAX_BYTES],
            len: 0,
        };
        let ok = match self {
            Self::Pid1(pid) => {
                // u32 の 10 進は最大 10 桁。固定長の一時バッファへ書く。
                let mut digits = [0u8; 10];
                let text = format_u32(pid.get(), &mut digits);
                out.push("K ") && out.push(text) && out.push("\n")
            }
            Self::Failed { code, phase } => {
                out.push("R ")
                    && out.push(code.as_str())
                    && out.push(" ")
                    && out.push(phase.as_str())
                    && out.push("\n")
            }
        };
        if !ok {
            out.len = 0;
            if let Some(dst) = out.buf.get_mut(..FALLBACK_REPORT.len()) {
                dst.copy_from_slice(FALLBACK_REPORT);
                out.len = FALLBACK_REPORT.len();
            }
        }
        out
    }

    /// 末尾の LF を含む 1 行を厳格に復号する(純関数。許可リスト外・形式違反は `Malformed`)。
    pub(super) fn decode(line: &[u8]) -> Result<Self, PrePivotStatusError> {
        let body = line
            .strip_suffix(b"\n")
            .ok_or(PrePivotStatusError::Malformed)?;
        let text = std::str::from_utf8(body).map_err(|_| PrePivotStatusError::Malformed)?;
        let parts: Vec<&str> = text.split(' ').collect();
        match parts.as_slice() {
            ["K", pid] => Ok(Self::Pid1(parse_pid(pid)?)),
            ["R", code, phase] => {
                let code = ALL_ERROR_CODES
                    .into_iter()
                    .find(|c| c.as_str() == *code)
                    .ok_or(PrePivotStatusError::Malformed)?;
                let phase =
                    IntermediatePhase::from_token(phase).ok_or(PrePivotStatusError::Malformed)?;
                Ok(Self::Failed { code, phase })
            }
            _ => Err(PrePivotStatusError::Malformed),
        }
    }
}

/// 10 進の pid を厳格に復号する(数字のみ・先頭 0 なし・10 桁以内・0 を拒否)。
fn parse_pid(token: &str) -> Result<NonZeroU32, PrePivotStatusError> {
    let canonical = !token.is_empty()
        && token.len() <= 10
        && token.bytes().all(|b| b.is_ascii_digit())
        && !token.starts_with('0');
    if !canonical {
        return Err(PrePivotStatusError::Malformed);
    }
    token
        .parse::<u32>()
        .ok()
        .and_then(NonZeroU32::new)
        .ok_or(PrePivotStatusError::Malformed)
}

/// `value` を 10 進で `buf` に書き、書いた部分を `&str` で返す(アロケーションなし)。
fn format_u32(value: u32, buf: &mut [u8; 10]) -> &str {
    let mut rest = value;
    let mut start = buf.len();
    loop {
        start = start.saturating_sub(1);
        if let Some(slot) = buf.get_mut(start) {
            // `rest % 10` は 0..=9 のため `u8` に収まる。
            *slot = b'0' + u8::try_from(rest % 10).unwrap_or(0);
        }
        rest /= 10;
        if rest == 0 || start == 0 {
            break;
        }
    }
    std::str::from_utf8(buf.get(start..).unwrap_or(&[])).unwrap_or("")
}

/// 報告の読み取り失敗を起動失敗の `ExecError` へ写す(固定の英語メッセージ。`Timeout` だけ `ErrorCode::Timeout`)。
fn report_read_error(e: PrePivotStatusError) -> ExecError {
    let (code, what) = match e {
        PrePivotStatusError::Timeout => (
            ErrorCode::Timeout,
            "timed out waiting for the intermediate process report",
        ),
        PrePivotStatusError::ClosedBeforeReport => (
            ErrorCode::Internal,
            "the intermediate process exited before reporting",
        ),
        PrePivotStatusError::Truncated => (
            ErrorCode::Internal,
            "the intermediate process report was truncated",
        ),
        PrePivotStatusError::TooLong => (
            ErrorCode::Internal,
            "the intermediate process report is too long",
        ),
        PrePivotStatusError::Malformed => (
            ErrorCode::Internal,
            "the intermediate process report is malformed",
        ),
        PrePivotStatusError::Io => (
            ErrorCode::Internal,
            "cannot read the intermediate process report pipe",
        ),
    };
    ExecError::new(code, IsolationStage::Spawn, what)
}

/// 起動ごとの識別子(`comm` に設定する 15 バイト以下の ASCII 名。CORE-2)。
///
/// 報告前に失われた PID 1 を C が特定するための印で、同じプロセス内の起動ごとに異なる(カウンタ)。
/// `execve` で `comm` は実行ファイル名に置き換わるため、起動に成功したコンテナとは衝突しない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LaunchTag {
    comm: [u8; 16],
    len: usize,
}

static LAUNCH_TAG_COUNTER: AtomicU32 = AtomicU32::new(0);

impl LaunchTag {
    /// 新しい識別子(`fdh-l` + 8 桁の 16 進カウンタ = 13 バイト)。
    pub(crate) fn fresh() -> Self {
        let n = LAUNCH_TAG_COUNTER.fetch_add(1, Ordering::Relaxed);
        let text = format!("fdh-l{n:08x}");
        let mut comm = [0u8; 16];
        let len = text.len().min(15);
        if let (Some(dst), Some(src)) = (comm.get_mut(..len), text.as_bytes().get(..len)) {
            dst.copy_from_slice(src);
        }
        Self { comm, len }
    }

    /// `PR_SET_NAME` へ渡す NUL 終端つきの 16 バイト。
    fn comm_bytes(&self) -> &[u8; 16] {
        &self.comm
    }

    /// `/proc/<pid>/comm` の内容(LF 抜き)との照合に使う名前。
    fn name(&self) -> &str {
        self.comm
            .get(..self.len)
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("")
    }
}

/// 中間プロセスの各動作(単体テストが呼び出し順を記録できるよう差し替え可能にした継ぎ目。本番の実装は
/// [`RealIntermediateOps`] で、既存の公開関数を呼ぶだけ)。
pub(super) trait IntermediateOps {
    /// namespace 分離(`isolate`)。
    fn isolate(&mut self) -> Result<(), ExecError>;
    /// PID 1 を fork する(戻り値はホスト側の pid)。
    fn spawn_pid1(&mut self) -> Result<u32, ExecError>;
    /// C へ報告する。
    fn report(&mut self, report: &IntermediateReport) -> Result<(), ExecError>;
    /// 報告できなかった PID 1 を殺して回収する(C が pid を知らないまま残さない)。
    fn abort_pid1(&mut self, pid: u32);
}

/// 中間プロセスの本体: `isolate` → PID 1 の fork → 報告。戻り値は `_exit` に渡す終了コード。
///
/// `isolate` に失敗したら PID 1 は作らない。PID 1 を作った後に報告できなかった場合は PID 1 を殺す(C が
/// pid を知らない PID 1 を残さない。fail-closed)。
pub(super) fn intermediate_body<O: IntermediateOps>(ops: &mut O) -> i32 {
    if let Err(e) = ops.isolate() {
        let _ = ops.report(&IntermediateReport::Failed {
            code: e.code,
            phase: IntermediatePhase::Isolate,
        });
        return EXIT_SETUP_FAILED;
    }
    let pid = match ops.spawn_pid1() {
        Ok(pid) => pid,
        Err(e) => {
            let _ = ops.report(&IntermediateReport::Failed {
                code: e.code,
                phase: IntermediatePhase::Spawn,
            });
            return EXIT_SETUP_FAILED;
        }
    };
    let Some(nonzero) = NonZeroU32::new(pid) else {
        let _ = ops.report(&IntermediateReport::Failed {
            code: ErrorCode::Internal,
            phase: IntermediatePhase::Spawn,
        });
        return EXIT_SETUP_FAILED;
    };
    if ops.report(&IntermediateReport::Pid1(nonzero)).is_err() {
        ops.abort_pid1(pid);
        return EXIT_SETUP_FAILED;
    }
    0
}

/// fork 後の子で、継承した不要な fd を閉じる。子は `_exit` で終わり `File` を drop しないため二重 close にならない。
fn close_inherited(fd: RawFd) -> Result<(), sys::SysError> {
    match u32::try_from(fd) {
        Ok(n) => sys::close_fd_number(n),
        Err(_) => Ok(()),
    }
}

/// PID 1 側の開始ゲート: C の許可(1 行)を期限つきで待つ。C が許可せずに閉じた(EOF)・期限切れ・読み取り失敗は
/// 失敗で、PID 1 は exec せずに終了する。C は許可の直前まで失敗経路で PID 1 を kill・回収するため、期限は
/// 最後の砦(孤児が無期限に残らない)。CORE-2。
fn await_start_gate(gate_r: &std::fs::File, timeout: Duration) -> Result<(), PrePivotStatusError> {
    read_line_bounded::<1>(gate_r, timeout).map(|_| ())
}

/// 本番の動作(既存の `isolate`・`child_main` への薄い委譲)。
struct RealIntermediateOps<'a> {
    plan: IntermediatePlan<'a>,
    rootfs: &'a Path,
    entry: &'a Entrypoint,
    stages: Option<StagePipeline>,
    stdio: Option<ChildStdio>,
    setup: PrePivotSetup<'a>,
    report: &'a std::fs::File,
    tag: LaunchTag,
    gate_r: &'a std::fs::File,
}

impl IntermediateOps for RealIntermediateOps<'_> {
    fn isolate(&mut self) -> Result<(), ExecError> {
        match self.plan {
            IntermediatePlan::SingleId(plan) => isolate(plan).map(|_| ()),
            // mapper の fork は flush しない版(I は C の stdio バッファを複製した子。#2009)。
            IntermediatePlan::Subordinate(plan) => {
                isolate_rootless_subordinate_no_flush(plan).map(|_| ())
            }
        }
    }

    fn spawn_pid1(&mut self) -> Result<u32, ExecError> {
        let (Some(stages), Some(stdio)) = (self.stages.take(), self.stdio.take()) else {
            return Err(ExecError::new(
                ErrorCode::Internal,
                IsolationStage::Spawn,
                "the container init was already spawned",
            ));
        };
        let (rootfs, entry, setup) = (self.rootfs, self.entry, self.setup);
        let gate_r = self.gate_r;
        let report_fd = self.report.as_raw_fd();
        // 識別子は fork で PID 1 へ継承される。設定できなければ、報告前に失われた PID 1 を C が特定できなく
        // なるため、PID 1 を作らずに失敗させる(fail-closed。CORE-2)。
        sys::set_process_comm(self.tag.comm_bytes())
            .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "set the launch tag"))?;
        // 親(I)の stdio バッファを子が二重に出力しないよう flush しない経路を使う。子は `_exit` するだけ。
        sys::fork_single_threaded_no_flush(
            move || {
                // PID 1 は報告 pipe の書き込み側を継承している。持ち続けると、K の報告前に I が終了しても
                // C が EOF を観測できず期限まで待つ。開始ゲート待ちの前に閉じる(CORE-2・REPAIR-5)。
                if close_inherited(report_fd).is_err() {
                    return EXIT_SETUP_FAILED;
                }
                match await_start_gate(gate_r, START_GATE_TIMEOUT) {
                    Ok(()) => child_main(rootfs, entry, stages, Some(setup), stdio),
                    Err(_) => EXIT_SETUP_FAILED,
                }
            },
            EXIT_SETUP_FAILED,
        )
        .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "fork"))
    }

    fn report(&mut self, report: &IntermediateReport) -> Result<(), ExecError> {
        let line = report.encode();
        let mut pipe = self.report;
        pipe.write_all(line.as_bytes())
            .map_err(|e| ExecError::from_io(&e, IsolationStage::Spawn, "report to the launcher"))
    }

    fn abort_pid1(&mut self, pid: u32) {
        let _ = ContainerChild::new(pid).kill_and_reap(KILL_REAP_TIMEOUT);
    }
}

/// 中間プロセス I が `isolate` する分離計画(権限モデルごとの検証済み計画。借用)。
#[derive(Clone, Copy)]
pub(crate) enum IntermediatePlan<'a> {
    /// 単一 ID 写像(`exec::plan`。`RootlessSingleId`)。
    SingleId(&'a IsolationPlan),
    /// subuid / subgid の範囲写像(`exec::plan_rootless_subordinate`。`RootlessSubordinateIds`。CORE-6・#2009)。
    Subordinate(&'a SubordinateIsolationPlan),
}

/// [`spawn_container_via_intermediate`] へ渡す、fork 前に C が準備した値(借用)。
pub(crate) struct IntermediateSpec<'a> {
    /// 検証済みの分離計画(euid 0 の写像は計画の段階で拒否済み。SEC-5)。
    pub(crate) plan: IntermediatePlan<'a>,
    /// rootfs のパス(使用は `setup.pinned_rootfs` の固定 fd との照合を通る)。
    pub(crate) rootfs: &'a Path,
    /// exec するエントリポイント。
    pub(crate) entry: &'a Entrypoint,
    /// pivot 前段の指定。`status` は本入口が上書きする。
    pub(crate) setup: PrePivotSetup<'a>,
}

/// 中間プロセス経由でコンテナの PID 1 を起動する(本番 launcher の唯一の起動入口。#1816)。
///
/// `timeout` を上限に、中間プロセスの報告と pivot 前段の結果を読む。成功なら PID 1 の [`ContainerChild`](pidfd
/// つき。呼び出し側が回収の所有者)を返す。失敗・期限切れ・形式違反のいずれでも起動失敗とし、生成済みの PID 1 と
/// 中間プロセスを回収する(回収できなければ [`PreparedLaunchFailure::unreaped`] に返す)。違反は `audit` の
/// sink へ C が 1 件記録する(層 `mount`・パスなし)。
///
/// 前提: 呼び出しプロセスが `Threads: 1`(満たさなければ `FailedPrecondition`。副作用は pipe の作成のみ)。成功
/// (`P`)の後の失敗(ステージ列・exec)は本入口では返らず、PID 1 の終了として観測される。
pub(crate) fn spawn_container_via_intermediate(
    spec: IntermediateSpec<'_>,
    stages: StagePipeline,
    stdio: ChildStdio,
    subreaper: &ChildSubreaper,
    audit: LaunchAudit<'_>,
    timeout: Duration,
) -> Result<ContainerChild, Box<PreparedLaunchFailure>> {
    let IntermediateSpec {
        plan,
        rootfs,
        entry,
        setup,
    } = spec;
    let tag = LaunchTag::fresh();
    launch_via_intermediate(
        sys::self_is_single_threaded,
        |status, report, gate_r| {
            let mut ops = RealIntermediateOps {
                plan,
                rootfs,
                entry,
                stages: Some(stages),
                stdio: Some(stdio),
                setup: PrePivotSetup {
                    status: Some(status),
                    ..setup
                },
                report,
                tag,
                gate_r,
            };
            intermediate_body(&mut ops)
        },
        subreaper,
        audit,
        timeout,
        &tag,
    )
}

/// [`spawn_container_via_intermediate`] の本体。中間プロセスの動作(`intermediate`)と fork 前のスレッド数判定を
/// 注入できるようにして、成功・各失敗・無報告の期限切れを結合試験で照合する(REPAIR-10・REPAIR-12)。
///
/// `intermediate` は fork した中間プロセスの中で `(状態 pipe の書き込み側, 報告 pipe の書き込み側)` を受けて
/// 呼ばれ、戻り値が `_exit` の終了コードになる。
fn launch_via_intermediate(
    is_single_threaded: impl FnOnce() -> bool,
    intermediate: impl FnOnce(&std::fs::File, &std::fs::File, &std::fs::File) -> i32,
    subreaper: &ChildSubreaper,
    audit: LaunchAudit<'_>,
    timeout: Duration,
    tag: &LaunchTag,
) -> Result<ContainerChild, Box<PreparedLaunchFailure>> {
    let not_started = |e: ExecError| {
        Box::new(PreparedLaunchFailure::clean(
            AuditedRejection::not_applicable(e),
        ))
    };
    let deadline = Instant::now() + timeout.min(TIMEOUT_MAX);
    let remaining = || deadline.saturating_duration_since(Instant::now());
    let (status_r, status_w) = exec_status_pipe().map_err(not_started)?;
    let (report_r, report_w) = exec_status_pipe().map_err(not_started)?;
    // 開始ゲート: C が PID 1 の pid を受領して pidfd を開くまで、PID 1 を exec に進ませない(`comm` の識別子は
    // exec で失われ、報告前の PID 1 を特定できなくなるため。CORE-2)。
    let (gate_r, gate_w) = exec_status_pipe().map_err(not_started)?;
    let (status_ref, report_ref) = (&status_w, &report_w);
    let gate_r_ref = &gate_r;
    let (gate_w_fd, report_r_fd, status_r_fd) = (
        gate_w.as_raw_fd(),
        report_r.as_raw_fd(),
        status_r.as_raw_fd(),
    );
    // fork 前の stdout / stderr の同期 flush は無期限に止まり得て、下の期限が効かなくなる(REPAIR-5)ため、
    // flush しない経路を使う。中間プロセスは `_exit` するので二重出力は起きない。
    let intermediate_pid = sys::fork_single_threaded_with_no_flush(
        is_single_threaded,
        move || {
            // I が持つべきでない C 専用の端点を閉じる。I から fork される PID 1 へ継承されると、C が許可前に
            // 終了しても gate_r が EOF を観測できず、PID 1 が期限まで残る(CORE-2・REPAIR-5)。
            if close_inherited(gate_w_fd).is_err()
                || close_inherited(report_r_fd).is_err()
                || close_inherited(status_r_fd).is_err()
            {
                return EXIT_SETUP_FAILED;
            }
            intermediate(status_ref, report_ref, gate_r_ref)
        },
        EXIT_SETUP_FAILED,
    )
    .map_err(|e| not_started(ExecError::from_sys(e, IsolationStage::Spawn, "fork")))?;
    // 親が書き込み側を持ち続けると、子が報告せずに終了しても EOF を観測できない。
    drop(status_w);
    drop(report_w);
    drop(gate_r);
    let intermediate_child = ContainerChild::spawned(intermediate_pid);

    let report = read_line_bounded::<REPORT_MAX_BYTES>(&report_r, remaining())
        .and_then(|(buf, end)| IntermediateReport::decode(buf.get(..end).unwrap_or(&[])));
    let pid1 = match report {
        Ok(IntermediateReport::Pid1(pid)) => pid,
        Ok(IntermediateReport::Failed { code, phase }) => {
            let (stage, what) = phase.describe();
            return Err(reap_intermediate_failure(
                intermediate_child,
                ExecError::new(code, stage, what),
            ));
        }
        Err(e) => {
            // 報告が無い中間プロセスは眠っている可能性があるため、待たずに殺して回収する。
            let mut failure = kill_intermediate_failure(intermediate_child, report_read_error(e));
            // 中間プロセスが死んだ後なら、報告前に作られた PID 1 は C へ再親付け済みで、識別子で特定できる。
            // 中間プロセスを回収できていなければ再親付けされておらず、探索しても見つからない(返す `unreaped` に
            // 中間プロセスが残るため、呼び出し側は起動予約を保持する)。
            if failure.unreaped.is_empty() {
                recover_unreported_init(&mut failure, tag, subreaper);
            } else {
                // 探索しなかった(できなかった)ので、呼び出し側が中間プロセスの回収後に再探索できるよう識別子を返す
                // (`confirm_no_process`。#1817)。
                failure.rescans.push(*tag);
            }
            return Err(failure);
        }
    };

    // 中間プロセスの終了前に PID 1 の pidfd を開く(C が subreaper のため、回収まで pid は解放されない)。
    let child = ContainerChild::adopt_reparented(pid1, subreaper);
    // pid を握った後で開始を許可する。許可できなければ PID 1 を殺して失敗にする(fail-closed)。
    let mut gate = &gate_w;
    if let Err(e) = gate.write_all(b"\n") {
        let mut failure = reap_intermediate_failure(
            intermediate_child,
            ExecError::from_io(&e, IsolationStage::Spawn, "release the init start gate"),
        );
        if let Err(kill_error) = child.kill_and_reap(KILL_REAP_TIMEOUT) {
            if failure.reap_error.is_none() {
                failure.reap_error = Some(kill_error);
            }
            failure.unreaped.push(child);
        }
        return Err(failure);
    }
    drop(gate_w);
    if let Err(reap_error) = reap_intermediate(&intermediate_child) {
        // 中間プロセスを回収できない: PID 1 を殺し、回収できなかった中間プロセスを返す(孤児化の防止)。
        // PID 1 の回収に失敗した場合も握りつぶさず、中間プロセスとあわせて両方のハンドルを返す(CORE-2)。
        let mut unreaped = vec![intermediate_child];
        if child.kill_and_reap(KILL_REAP_TIMEOUT).is_err() {
            unreaped.push(child);
        }
        return Err(Box::new(PreparedLaunchFailure {
            rejection: AuditedRejection::not_applicable(ExecError::new(
                ErrorCode::Internal,
                IsolationStage::Wait,
                "the intermediate process could not be reaped",
            )),
            unreaped,
            reap_error: Some(reap_error),
            rescans: Vec::new(),
        }));
    }

    let status = read_pre_pivot_status(&status_r, remaining());
    match resolve_pre_pivot_status(status, audit) {
        Ok(()) => Ok(child),
        Err(rejection) => match child.kill_and_reap(KILL_REAP_TIMEOUT) {
            Ok(_) => Err(Box::new(PreparedLaunchFailure::clean(*rejection))),
            // 回収失敗は握りつぶさず、子のハンドルごと呼び出し側へ返す(孤児化の防止。CORE-2)。
            Err(reap_error) => Err(Box::new(PreparedLaunchFailure::with_unreaped(
                *rejection, child, reap_error,
            ))),
        },
    }
}

/// `/proc/<pid>/stat` から親 pid を読む(`comm` に空白や `)` が含まれても、最後の `)` の後ろから読む)。
fn parent_pid_of(stat: &str) -> Option<u32> {
    let after = stat.rsplit_once(')')?.1;
    // 続くフィールド: state ppid ...
    after.split_whitespace().nth(1)?.parse().ok()
}

/// 報告前の PID 1 の探索結果(`rescan_unreported_init`)。
///
/// `unreaped` は見つけたが回収できなかった子(`kill_and_reap` の失敗)、`error` は探索自体の失敗または最初の回収失敗。
/// 両方とも空(`None`)のときだけ「報告前の PID 1 は残っていない」と言える(fail-closed。CORE-2)。
#[derive(Debug, Default)]
pub(crate) struct Rescan {
    /// 回収できなかった子(ハンドルごと返す。孤児化させない)。
    pub(crate) unreaped: Vec<ContainerChild>,
    /// 最初の失敗の理由(探索の失敗を含む)。
    pub(crate) error: Option<ExecError>,
    /// 探索が途中で失敗し、見逃した候補があり得るか(`error` のうち、回収失敗でなく探索の失敗)。
    pub(crate) scan_incomplete: bool,
}

impl Rescan {
    /// 報告前の PID 1 が残っていないと確かめられたか(試験用)。
    #[cfg(test)]
    pub(crate) fn is_clean(&self) -> bool {
        self.unreaped.is_empty() && self.error.is_none()
    }
}

/// 報告前に失われた PID 1 を特定して kill・回収し、回収できなかったものを `failure.unreaped` へ足す(CORE-2)。
///
/// 探索の実体は [`rescan_unreported_init`]。探索自体が失敗した場合は、呼び出し側(launcher)が後で再探索できるよう
/// `failure.rescans` に識別子を残す(`confirm_no_process`。#1817)。起動失敗の理由は変えない。
fn recover_unreported_init(
    failure: &mut PreparedLaunchFailure,
    tag: &LaunchTag,
    subreaper: &ChildSubreaper,
) {
    let found = rescan_unreported_init(tag, subreaper, KILL_REAP_TIMEOUT);
    if found.scan_incomplete {
        failure.rescans.push(*tag);
    }
    if failure.reap_error.is_none() {
        failure.reap_error = found.error;
    }
    failure.unreaped.extend(found.unreaped);
}

/// 起動識別子 `tag` を `comm` に持つ、C の子(報告前に失われた PID 1)を `/proc` から探して kill・回収する(CORE-2)。
///
/// 対象は「親が C 自身で、`comm` が `tag` と完全一致する」子だけ。`/proc` の読み取りに失敗しても panic せず、
/// 列挙・読み取り・解析のどれかが失敗して候補を検査できなかった事実は `error` に `Internal` で残す(消滅を確認できた
/// 場合と区別する。fail-closed)。回収の待ちは見つけた子ごとに `reap_timeout` を上限とする(REPAIR-5)。探索は失敗
/// 経路と `confirm_no_process` でのみ走り、成功経路の負荷にならない。
///
/// 前提: 中間プロセスを回収済みであること(未回収だと PID 1 は C へ再親付けされず見つからない)。
pub(crate) fn rescan_unreported_init(
    tag: &LaunchTag,
    subreaper: &ChildSubreaper,
    reap_timeout: Duration,
) -> Rescan {
    let mut out = Rescan::default();
    let me = std::process::id();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        note_scan_failure(&mut out, "cannot scan /proc for the init");
        return out;
    };
    for entry in entries {
        // 列挙の途中の失敗は、見逃した候補があり得るため残存なしとは言えない(fail-closed)。
        let Ok(entry) = entry else {
            note_scan_failure(&mut out, "cannot enumerate /proc for the init");
            continue;
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
            .and_then(NonZeroU32::new)
        else {
            continue;
        };
        let base = Path::new("/proc").join(pid.get().to_string());
        let stat = match read_proc_text(&base.join("stat")) {
            Ok(Some(stat)) => stat,
            // 探索中に消えた(= 回収済み)ので対象外。
            Ok(None) => continue,
            Err(_) => {
                note_scan_failure(
                    &mut out,
                    "cannot read a /proc stat while scanning for the init",
                );
                continue;
            }
        };
        let Some(parent) = parent_pid_of(&stat) else {
            note_scan_failure(
                &mut out,
                "cannot parse a /proc stat while scanning for the init",
            );
            continue;
        };
        if parent != me {
            continue;
        }
        let comm = match read_proc_text(&base.join("comm")) {
            Ok(Some(comm)) => comm,
            Ok(None) => continue,
            Err(_) => {
                note_scan_failure(
                    &mut out,
                    "cannot read a /proc comm while scanning for the init",
                );
                continue;
            }
        };
        if comm.trim_end_matches('\n') != tag.name() {
            continue;
        }
        // 親が C の未回収の子(subreaper が再親付けした)なので、回収まで pid は解放されず、pidfd が開けなくても
        // `kill(2)` が別プロセスへ届くことはない。
        let child = ContainerChild::adopt_reparented(pid, subreaper);
        if let Err(e) = child.kill_and_reap(reap_timeout) {
            if out.error.is_none() {
                out.error = Some(e);
            }
            out.unreaped.push(child);
        }
    }
    out
}

/// `/proc` のテキストを読む。対象が消えていれば `Ok(None)`(列挙から読むまでの間に終了した)、それ以外の失敗は
/// `Err`(呼び出し側が fail-closed で扱う)。
fn read_proc_text(path: &Path) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(3) => {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// 探索自体ができなかったことを残す(未回収の子が無くても、呼び出し側が残存を疑えるようにする)。
fn note_scan_failure(out: &mut Rescan, what: &'static str) {
    out.scan_incomplete = true;
    if out.error.is_none() {
        out.error = Some(ExecError::new(
            ErrorCode::Internal,
            IsolationStage::Wait,
            what,
        ));
    }
}

/// 報告後の中間プロセスを回収する。`INTERMEDIATE_REAP_TIMEOUT` 内に終わらなければ SIGKILL して回収する。
fn reap_intermediate(child: &ContainerChild) -> Result<(), ExecError> {
    match child.wait_for_exit(INTERMEDIATE_REAP_TIMEOUT) {
        Ok(Some(_)) => Ok(()),
        Ok(None) | Err(_) => child.kill_and_reap(KILL_REAP_TIMEOUT).map(|_| ()),
    }
}

/// 失敗を報告した中間プロセスを回収して、起動失敗を返す。回収できなければハンドルごと返す(孤児化の防止)。
fn reap_intermediate_failure(
    child: ContainerChild,
    error: ExecError,
) -> Box<PreparedLaunchFailure> {
    match reap_intermediate(&child) {
        Ok(()) => Box::new(PreparedLaunchFailure::clean(
            AuditedRejection::not_applicable(error),
        )),
        Err(reap_error) => Box::new(PreparedLaunchFailure::with_unreaped(
            AuditedRejection::not_applicable(error),
            child,
            reap_error,
        )),
    }
}

/// 報告の無い(または不正な)中間プロセスを SIGKILL して回収し、起動失敗を返す。
fn kill_intermediate_failure(
    child: ContainerChild,
    error: ExecError,
) -> Box<PreparedLaunchFailure> {
    match child.kill_and_reap(KILL_REAP_TIMEOUT) {
        Ok(_) => Box::new(PreparedLaunchFailure::clean(
            AuditedRejection::not_applicable(error),
        )),
        // 回収失敗は握りつぶさず、ハンドルごと返す(孤児化の防止。CORE-2)。
        Err(reap_error) => Box::new(PreparedLaunchFailure::with_unreaped(
            AuditedRejection::not_applicable(error),
            child,
            reap_error,
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;
    use std::sync::Mutex;

    use super::*;
    use crate::audit_log::{AuditLayer, AuditRecord, AuditSink};
    use crate::exec::ViolationReason;
    use crate::exec::launch_status::{PrePivotFailure, PrePivotStep, report_failure, report_ready};
    use crate::exec::process::ChildExit;
    use crate::traits::{ContainerId, TraitError};

    // ---- ワイヤー(REPAIR-2) ----

    fn pid(n: u32) -> NonZeroU32 {
        NonZeroU32::new(n).unwrap()
    }

    /// REPAIR-2: 報告行の往復と、符号化の具体値。
    #[test]
    fn repair2_report_roundtrip_and_exact_bytes() {
        let cases = [
            (IntermediateReport::Pid1(pid(1)), &b"K 1\n"[..]),
            (IntermediateReport::Pid1(pid(4242)), &b"K 4242\n"[..]),
            (
                IntermediateReport::Pid1(pid(u32::MAX)),
                &b"K 4294967295\n"[..],
            ),
            (
                IntermediateReport::Failed {
                    code: ErrorCode::FailedPrecondition,
                    phase: IntermediatePhase::Isolate,
                },
                &b"R FAILED_PRECONDITION isolate\n"[..],
            ),
            (
                IntermediateReport::Failed {
                    code: ErrorCode::PermissionDenied,
                    phase: IntermediatePhase::Spawn,
                },
                &b"R PERMISSION_DENIED spawn\n"[..],
            ),
        ];
        for (report, bytes) in cases {
            let encoded = report.encode();
            assert_eq!(encoded.as_bytes(), bytes);
            assert_eq!(IntermediateReport::decode(bytes), Ok(report));
        }
    }

    /// REPAIR-2: 全 `ErrorCode` と全段が往復でき、最長の行が上限に収まる。
    #[test]
    fn repair2_every_code_and_phase_fits_and_roundtrips() {
        for code in ALL_ERROR_CODES {
            for phase in IntermediatePhase::ALL {
                let report = IntermediateReport::Failed { code, phase };
                let encoded = report.encode();
                assert!(encoded.as_bytes().len() < REPORT_MAX_BYTES);
                assert_eq!(IntermediateReport::decode(encoded.as_bytes()), Ok(report));
            }
        }
    }

    /// REPAIR-2: 不正な行(pid 0・桁あふれ・先頭 0・符号・余分なトークン・許可リスト外・LF なし)を拒否する。
    #[test]
    fn repair2_decode_rejects_malformed_lines() {
        let bad: [&[u8]; 19] = [
            b"K 0\n",
            b"K 4294967296\n",
            b"K 99999999999\n",
            b"K 01\n",
            b"K +5\n",
            b"K -5\n",
            b"K 5 \n",
            b"K\n",
            b"K  5\n",
            b"K 5 6\n",
            b"P\n",
            b"R INTERNAL\n",
            b"R INTERNAL isolate extra\n",
            b"R BOGUS isolate\n",
            b"R INTERNAL pivot_root\n",
            b"R internal spawn\n",
            b"K 5",
            b"",
            b"\n",
        ];
        for line in bad {
            assert_eq!(
                IntermediateReport::decode(line),
                Err(PrePivotStatusError::Malformed),
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
    }

    // ---- intermediate_body の順序(フォーク無し) ----

    #[derive(Default)]
    struct RecordingOps {
        calls: Vec<String>,
        isolate_error: Option<ErrorCode>,
        spawn_result: Option<Result<u32, ErrorCode>>,
        report_fails: bool,
    }

    impl IntermediateOps for RecordingOps {
        fn isolate(&mut self) -> Result<(), ExecError> {
            self.calls.push("isolate".to_owned());
            match self.isolate_error {
                Some(code) => Err(ExecError::new(code, IsolationStage::Unshare, "x")),
                None => Ok(()),
            }
        }

        fn spawn_pid1(&mut self) -> Result<u32, ExecError> {
            self.calls.push("spawn_pid1".to_owned());
            match self.spawn_result.unwrap_or(Ok(77)) {
                Ok(pid) => Ok(pid),
                Err(code) => Err(ExecError::new(code, IsolationStage::Spawn, "x")),
            }
        }

        fn report(&mut self, report: &IntermediateReport) -> Result<(), ExecError> {
            let line = report.encode();
            self.calls.push(format!(
                "report {}",
                String::from_utf8_lossy(line.as_bytes()).trim_end()
            ));
            if self.report_fails {
                return Err(ExecError::new(
                    ErrorCode::Internal,
                    IsolationStage::Spawn,
                    "x",
                ));
            }
            Ok(())
        }

        fn abort_pid1(&mut self, pid: u32) {
            self.calls.push(format!("abort_pid1 {pid}"));
        }
    }

    /// CORE-1: 成功は isolate → spawn_pid1 → report の順で、終了コード 0。
    #[test]
    fn core1_body_runs_isolate_spawn_report_in_order() {
        let mut ops = RecordingOps::default();
        assert_eq!(intermediate_body(&mut ops), 0);
        assert_eq!(ops.calls, ["isolate", "spawn_pid1", "report K 77"]);
    }

    /// SEC-5: isolate が失敗したら PID 1 を作らず、失敗(段 isolate)だけを報告する。
    #[test]
    fn sec5_body_isolate_failure_never_spawns_pid1() {
        let mut ops = RecordingOps {
            isolate_error: Some(ErrorCode::PermissionDenied),
            ..RecordingOps::default()
        };
        assert_eq!(intermediate_body(&mut ops), EXIT_SETUP_FAILED);
        assert_eq!(ops.calls, ["isolate", "report R PERMISSION_DENIED isolate"]);
    }

    /// CORE-2: PID 1 の fork が失敗したら段 spawn で報告する。
    #[test]
    fn core2_body_spawn_failure_reports_spawn_phase() {
        let mut ops = RecordingOps {
            spawn_result: Some(Err(ErrorCode::Internal)),
            ..RecordingOps::default()
        };
        assert_eq!(intermediate_body(&mut ops), EXIT_SETUP_FAILED);
        assert_eq!(
            ops.calls,
            ["isolate", "spawn_pid1", "report R INTERNAL spawn"]
        );
    }

    /// CORE-2: 報告に失敗したら、C が pid を知らない PID 1 を殺す(残さない)。
    #[test]
    fn core2_body_report_failure_aborts_pid1() {
        let mut ops = RecordingOps {
            report_fails: true,
            ..RecordingOps::default()
        };
        assert_eq!(intermediate_body(&mut ops), EXIT_SETUP_FAILED);
        assert_eq!(
            ops.calls,
            ["isolate", "spawn_pid1", "report K 77", "abort_pid1 77"]
        );
    }

    /// fork が pid 0 を返す異常でも成功を報告しない。
    #[test]
    fn core2_body_zero_pid_is_a_failure() {
        let mut ops = RecordingOps {
            spawn_result: Some(Ok(0)),
            ..RecordingOps::default()
        };
        assert_eq!(intermediate_body(&mut ops), EXIT_SETUP_FAILED);
        assert_eq!(
            ops.calls,
            ["isolate", "spawn_pid1", "report R INTERNAL spawn"]
        );
    }

    // ---- 起動入口(フォークあり。中間プロセスの動作を注入) ----

    struct VecSink(Mutex<Vec<AuditRecord>>);

    impl AuditSink for VecSink {
        fn record(&self, record: &AuditRecord) -> Result<(), TraitError> {
            self.0.lock().unwrap().push(record.clone());
            Ok(())
        }
    }

    /// PID 1 の代役と中間プロセスの動作。
    #[derive(Clone, Copy)]
    enum Behavior {
        /// PID 1 が `P` を報告して終了し、中間プロセスが `K` を報告して終了する。
        Ready,
        /// PID 1 が失敗(違反あり)を報告して眠り、中間プロセスが `K` を報告する。
        FailWithViolation,
        /// PID 1 が何も報告せず眠る(状態の期限切れ)。
        PidOneSilent,
        /// 中間プロセスが何も報告せず眠る(報告の期限切れ)。
        IntermediateSilent,
        /// 中間プロセスが識別子を設定して PID 1 を作り、`K` を報告する前に眠る(報告前の PID 1。CORE-2)。
        PidOneBeforeReport,
        /// 中間プロセスが isolate の失敗を報告して終了する。
        IsolateFails,
        /// 中間プロセスが不正な行を書いて終了する。
        MalformedReport,
        /// 中間プロセスが PID 1 の fork の失敗(`R <CODE> spawn`)を報告して終了する。
        SpawnFails,
    }

    /// 代役の PID 1 を fork し、その pid をテストへ渡す(`pid_write`)。
    fn fork_stand_in(
        status: &std::fs::File,
        pid_write: &std::fs::File,
        body: impl FnOnce(&std::fs::File) -> i32,
    ) -> u32 {
        let pid = sys::fork_single_threaded_with(|| true, || body(status), EXIT_SETUP_FAILED)
            .expect("fork the stand-in");
        let mut w = pid_write;
        let _ = w.write_all(&pid.to_le_bytes());
        pid
    }

    fn send_report(report: &std::fs::File, r: &IntermediateReport) {
        let mut w = report;
        w.write_all(r.encode().as_bytes()).expect("report");
    }

    fn run(
        behavior: Behavior,
        timeout: Duration,
    ) -> (
        Result<ContainerChild, Box<PreparedLaunchFailure>>,
        VecSink,
        Option<u32>,
    ) {
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let (mut pid_read, pid_write) = std::io::pipe().unwrap();
        let pid_write = std::fs::File::from(std::os::fd::OwnedFd::from(pid_write));
        let sink = VecSink(Mutex::new(Vec::new()));
        let id = ContainerId::new("c1816").unwrap();
        let audit = LaunchAudit {
            sink: &sink,
            container: Some(&id),
        };
        let tag = LaunchTag::fresh();
        let result = launch_via_intermediate(
            || true,
            |status, report, gate_r| {
                match behavior {
                    Behavior::Ready => {
                        let pid1 = fork_stand_in(status, &pid_write, |s| {
                            // C の許可(pid 受領後)より前には進まない。許可が無ければ失敗で終了する。
                            if await_start_gate(gate_r, Duration::from_secs(10)).is_err() {
                                return EXIT_SETUP_FAILED;
                            }
                            let _ = report_ready(s);
                            0
                        });
                        send_report(report, &IntermediateReport::Pid1(pid(pid1)));
                    }
                    Behavior::FailWithViolation => {
                        let pid1 = fork_stand_in(status, &pid_write, |s| {
                            let _ = report_failure(
                                s,
                                &PrePivotFailure {
                                    step: PrePivotStep::PivotRoot,
                                    code: ErrorCode::PermissionDenied,
                                    violation: Some(ViolationReason::TargetOnSharedMount),
                                },
                            );
                            std::thread::sleep(Duration::from_secs(120));
                            0
                        });
                        send_report(report, &IntermediateReport::Pid1(pid(pid1)));
                    }
                    Behavior::PidOneSilent => {
                        let pid1 = fork_stand_in(status, &pid_write, |_| {
                            std::thread::sleep(Duration::from_secs(120));
                            0
                        });
                        send_report(report, &IntermediateReport::Pid1(pid(pid1)));
                    }
                    Behavior::IntermediateSilent => {
                        let mut w = &pid_write;
                        let _ = w.write_all(&std::process::id().to_le_bytes());
                        std::thread::sleep(Duration::from_secs(120));
                    }
                    Behavior::PidOneBeforeReport => {
                        sys::set_process_comm(tag.comm_bytes()).expect("set the tag");
                        let _pid1 = fork_stand_in(status, &pid_write, |_| {
                            std::thread::sleep(Duration::from_secs(120));
                            0
                        });
                        // 報告せずに眠る(C は期限切れで中間プロセスを殺す)。
                        std::thread::sleep(Duration::from_secs(120));
                    }
                    Behavior::IsolateFails => {
                        send_report(
                            report,
                            &IntermediateReport::Failed {
                                code: ErrorCode::PermissionDenied,
                                phase: IntermediatePhase::Isolate,
                            },
                        );
                        return EXIT_SETUP_FAILED;
                    }
                    Behavior::MalformedReport => {
                        let mut w = report;
                        let _ = w.write_all(b"K 0\n");
                        return EXIT_SETUP_FAILED;
                    }
                    Behavior::SpawnFails => {
                        send_report(
                            report,
                            &IntermediateReport::Failed {
                                code: ErrorCode::Unavailable,
                                phase: IntermediatePhase::Spawn,
                            },
                        );
                        return EXIT_SETUP_FAILED;
                    }
                }
                0
            },
            &subreaper,
            audit,
            timeout,
            &tag,
        );
        drop(pid_write);
        let mut buf = [0u8; 4];
        let seen = pid_read
            .read_exact(&mut buf)
            .ok()
            .map(|()| u32::from_le_bytes(buf));
        (result, sink, seen)
    }

    /// 回収済みなら `/proc/<pid>` は残らない(ゾンビも残さない)。
    fn gone(pid: u32) -> bool {
        !Path::new(&format!("/proc/{pid}")).exists()
    }

    /// CORE-1・CORE-2(#1816): 成功は PID 1 の `ContainerChild`(pidfd つき)を返し、回収されずに終了を待てる。
    /// 中間プロセスは回収済みで、監査は 0 件。
    #[test]
    fn core1_via_intermediate_success_returns_adopted_pid1() {
        let (result, sink, pid1) = run(Behavior::Ready, Duration::from_secs(10));
        let child = result.unwrap();
        assert_eq!(Some(child.pid()), pid1);
        assert!(child.pidfd().is_some());
        assert_eq!(
            child.wait_timeout(Duration::from_secs(10)).unwrap(),
            ChildExit::Exited(0)
        );
        assert!(sink.0.lock().unwrap().is_empty());
    }

    /// SEC-4(#1816): pivot 前段の違反は C が 1 件記録し、起動失敗を返して PID 1 を回収する。
    #[test]
    fn sec4_via_intermediate_failure_audits_and_reaps_pid1() {
        let (result, sink, pid1) = run(Behavior::FailWithViolation, Duration::from_secs(10));
        let failure = result.expect_err("launch must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::FailedPrecondition);
        assert_eq!(
            failure.rejection.error.violation.as_ref().map(|v| v.reason),
            Some(ViolationReason::TargetOnSharedMount)
        );
        assert!(failure.unreaped.is_empty());
        assert!(failure.reap_error.is_none());
        let recs = sink.0.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer(), AuditLayer::Mount);
        assert_eq!(
            recs[0].container_id().map(ContainerId::as_str),
            Some("c1816")
        );
        assert!(gone(pid1.unwrap()), "the init {pid1:?} must be reaped");
    }

    /// REPAIR-5(#1816): PID 1 が状態を報告しないと `Timeout` で失敗し、記録は 0 件、PID 1 を回収する。
    #[test]
    fn repair5_via_intermediate_silent_pid1_times_out_and_is_reaped() {
        let started = Instant::now();
        let (result, sink, pid1) = run(Behavior::PidOneSilent, Duration::from_millis(500));
        let failure = result.expect_err("launch must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Timeout);
        assert_eq!(failure.rejection.error.violation, None);
        assert!(failure.unreaped.is_empty());
        assert!(sink.0.lock().unwrap().is_empty());
        assert!(gone(pid1.unwrap()), "the init {pid1:?} must be reaped");
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    /// REPAIR-5(#1816): 中間プロセスが報告しないと `Timeout` で失敗し、中間プロセスを SIGKILL して回収する。
    #[test]
    fn repair5_via_intermediate_silent_intermediate_times_out_and_is_killed() {
        let started = Instant::now();
        let (result, sink, intermediate) =
            run(Behavior::IntermediateSilent, Duration::from_millis(300));
        let failure = result.expect_err("launch must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Timeout);
        assert_eq!(
            failure.rejection.error.message,
            "timed out waiting for the intermediate process report"
        );
        assert!(failure.unreaped.is_empty());
        assert!(sink.0.lock().unwrap().is_empty());
        assert!(
            gone(intermediate.unwrap()),
            "the intermediate must be reaped"
        );
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    /// CORE-2(#1816): 中間プロセスが PID 1 を作った後、`K` の報告前に止まっても、C は識別子で再親付けされた
    /// PID 1 を特定して回収する(残さない)。報告されない PID 1 の pid は fork_stand_in がテストへ渡す。
    #[test]
    fn core2_via_intermediate_unreported_init_is_recovered_by_tag() {
        let (result, _sink, pid1) = run(Behavior::PidOneBeforeReport, Duration::from_millis(500));
        let failure = result.expect_err("launch must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Timeout);
        assert!(failure.unreaped.is_empty());
        assert!(failure.reap_error.is_none());
        let pid1 = pid1.expect("the stand-in pid");
        // 回収済みならゾンビも含めて `/proc/<pid>` が無い。
        assert!(
            gone(pid1),
            "the unreported init {pid1} must be killed and reaped"
        );
    }

    /// CORE-2(#1817): I が PID 1 の fork 失敗(`R ... spawn`)を報告して終了する経路では、子は残らず、探索の
    /// 再実行も要らない(`rescans` は空)。I は回収済みで `/proc` に残らない。
    #[test]
    fn core2_via_intermediate_spawn_failure_report_leaves_nothing() {
        let (result, sink, _) = run(Behavior::SpawnFails, Duration::from_secs(10));
        let failure = result.expect_err("launch must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Unavailable);
        assert_eq!(failure.rejection.error.stage, IsolationStage::Spawn);
        assert!(failure.unreaped.is_empty());
        assert!(failure.reap_error.is_none());
        assert!(failure.rescans.is_empty());
        assert!(sink.0.lock().unwrap().is_empty());
    }

    /// CORE-2・REPAIR-5(#1817): 識別子を `comm` に持つ C の子を、再探索が kill・回収する(`confirm_no_process` の
    /// 再探索の実体)。見つけた子は回収済みで `/proc` に残らず、結果は「残っていない」(`is_clean`)。
    #[test]
    fn core2_rescan_finds_tagged_child_and_reaps_it() {
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let tag = LaunchTag::fresh();
        let (mut ready_read, ready_write) = std::io::pipe().unwrap();
        let ready_write = std::fs::File::from(std::os::fd::OwnedFd::from(ready_write));
        let pid1 = sys::fork_single_threaded_with(
            || true,
            || {
                if sys::set_process_comm(tag.comm_bytes()).is_err() {
                    return EXIT_SETUP_FAILED;
                }
                let mut w = &ready_write;
                let _ = w.write_all(b"R");
                std::thread::sleep(Duration::from_secs(120));
                0
            },
            EXIT_SETUP_FAILED,
        )
        .expect("fork the tagged child");
        drop(ready_write);
        let mut mark = [0u8; 1];
        ready_read.read_exact(&mut mark).unwrap();
        let found = rescan_unreported_init(&tag, &subreaper, Duration::from_secs(5));
        assert!(found.is_clean(), "{found:?}");
        assert!(!found.scan_incomplete);
        assert!(gone(pid1), "the tagged child {pid1} must be reaped");
        // 2 回目は何も見つからない(別の識別子の子や回収済みの子は対象外)。
        assert!(rescan_unreported_init(&tag, &subreaper, Duration::from_secs(1)).is_clean());
    }

    /// CORE-2・REPAIR-5(#1816): I が許可前に報告なしで終了しても、PID 1 は gate_w を継承していないため、C の
    /// 失敗(gate_w の drop)で開始ゲートが EOF となり、期限(10 秒)を待たずに終了する。
    #[test]
    fn core2_start_gate_sees_eof_when_launcher_aborts_before_release() {
        let _subreaper = ChildSubreaper::enable().expect("subreaper");
        let (mut mark_read, mark_write) = std::io::pipe().unwrap();
        let mark_write = std::fs::File::from(std::os::fd::OwnedFd::from(mark_write));
        let sink = VecSink(Mutex::new(Vec::new()));
        let audit = LaunchAudit {
            sink: &sink,
            container: None,
        };
        let tag = LaunchTag::fresh();
        let started = Instant::now();
        let result = launch_via_intermediate(
            || true,
            |status, _report, gate_r| {
                let _ = sys::fork_single_threaded_with(
                    || true,
                    || {
                        let waited = Instant::now();
                        let eof = await_start_gate(gate_r, Duration::from_secs(10)).is_err()
                            && waited.elapsed() < Duration::from_secs(8);
                        let _ = status;
                        let mut w = &mark_write;
                        let _ = w.write_all(if eof { b"E" } else { b"T" });
                        0
                    },
                    EXIT_SETUP_FAILED,
                );
                // 報告せずに終了する。
                EXIT_SETUP_FAILED
            },
            &_subreaper,
            audit,
            Duration::from_secs(5),
            &tag,
        );
        assert!(result.is_err());
        drop(result);
        let mut mark = [0u8; 1];
        mark_read.read_exact(&mut mark).unwrap();
        assert_eq!(&mark, b"E", "the init must see EOF on the start gate");
        assert!(started.elapsed() < Duration::from_secs(9));
    }

    /// CORE-2: 開始ゲートは許可の 1 行で通り、許可なしの close(EOF)では失敗する。
    #[test]
    fn core2_start_gate_requires_release_and_fails_on_eof() {
        let (r, w) = exec_status_pipe().unwrap();
        (&w).write_all(b"\n").unwrap();
        assert_eq!(await_start_gate(&r, Duration::from_secs(5)), Ok(()));
        let (r, w) = exec_status_pipe().unwrap();
        drop(w);
        assert!(await_start_gate(&r, Duration::from_secs(5)).is_err());
        let (r, _w) = exec_status_pipe().unwrap();
        assert_eq!(
            await_start_gate(&r, Duration::from_millis(50)),
            Err(PrePivotStatusError::Timeout)
        );
    }

    /// CORE-2: 消えた /proc エントリは `None`、存在するが読めない/解析できないものは失敗として区別される。
    #[test]
    fn core2_read_proc_text_distinguishes_vanished_from_failure() {
        assert!(matches!(
            read_proc_text(Path::new("/proc/4294967295/stat")),
            Ok(None)
        ));
        assert!(
            read_proc_text(Path::new("/proc/self/stat"))
                .unwrap()
                .is_some()
        );
        // ディレクトリは読めず、消滅とは区別して失敗にする。
        assert!(read_proc_text(Path::new("/proc/self")).is_err());
    }

    /// CORE-2: 識別子は起動ごとに異なり、15 バイト以下の ASCII。
    #[test]
    fn core2_launch_tag_is_unique_and_fits_comm() {
        let (a, b) = (LaunchTag::fresh(), LaunchTag::fresh());
        assert_ne!(a.name(), b.name());
        assert_eq!(a.name().len(), 13);
        assert!(a.name().starts_with("fdh-l"));
        assert_eq!(a.comm_bytes().get(13), Some(&0));
    }

    /// CORE-2: `/proc/<pid>/stat` の親 pid は、comm に空白と `)` を含んでも読める。
    #[test]
    fn core2_parent_pid_parses_tricky_comm() {
        assert_eq!(parent_pid_of("123 (a b) c) S 456 1 1 0"), Some(456));
        assert_eq!(parent_pid_of("123 (x) S 7 1 1 0"), Some(7));
        assert_eq!(parent_pid_of("garbage"), None);
    }

    /// SEC-5(#1816): isolate の失敗報告は元の `ErrorCode` と固定文言で返り、監査は 0 件。
    #[test]
    fn sec5_via_intermediate_isolate_failure_is_propagated() {
        let (result, sink, _) = run(Behavior::IsolateFails, Duration::from_secs(10));
        let failure = result.expect_err("launch must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::PermissionDenied);
        assert_eq!(failure.rejection.error.stage, IsolationStage::Unshare);
        assert_eq!(
            failure.rejection.error.message,
            "namespace isolation failed in the intermediate process"
        );
        assert!(failure.unreaped.is_empty());
        assert!(sink.0.lock().unwrap().is_empty());
    }

    /// REPAIR-2(#1816): 不正な報告(pid 0)は起動失敗(`Internal`)として扱う。
    #[test]
    fn repair2_via_intermediate_malformed_report_fails_closed() {
        let (result, _sink, _) = run(Behavior::MalformedReport, Duration::from_secs(10));
        let failure = result.expect_err("launch must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Internal);
        assert_eq!(
            failure.rejection.error.message,
            "the intermediate process report is malformed"
        );
    }

    /// CORE-1(#1816): 複数スレッドの呼び出しは中間プロセスを作らず `FailedPrecondition`。
    #[test]
    fn core1_via_intermediate_refuses_multithreaded_caller() {
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let sink = VecSink(Mutex::new(Vec::new()));
        let audit = LaunchAudit {
            sink: &sink,
            container: None,
        };
        let result = launch_via_intermediate(
            || false,
            |_, _, _| panic!("the intermediate must not run"),
            &subreaper,
            audit,
            Duration::from_secs(1),
            &LaunchTag::fresh(),
        );
        let failure = result.expect_err("must refuse");
        assert_eq!(failure.rejection.error.code, ErrorCode::FailedPrecondition);
        assert!(failure.unreaped.is_empty());
    }

    /// 子プロセス側の本体(`REPAIR5_1816_MARKER` が無ければ何もしない)。親が stdout の pipe を満杯にした
    /// 合図(`<marker>.go`)を待ってから、stdout に未送信のバッファを持った状態で起動処理を行い、期限内に
    /// 失敗が返ったら `<marker>` を書く。
    #[test]
    fn repair5_1816_child_stdout_full_helper() {
        let Some(marker) = std::env::var_os("REPAIR5_1816_MARKER") else {
            return;
        };
        let marker = std::path::PathBuf::from(marker);
        let go = marker.with_extension("go");
        let _ = std::fs::write(marker.with_extension("ready"), b"1");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !go.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        // 改行なしの 1 バイトは LineWriter に残り、flush すると満杯の pipe で止まる。
        let _ = std::io::stdout().write_all(b"x");
        let (result, _sink, _pid) = run(Behavior::IntermediateSilent, Duration::from_millis(500));
        if result.is_err() {
            let _ = std::fs::write(&marker, b"done");
        }
    }

    /// REPAIR-5(#1816): 親の stdout が満杯の pipe でバッファが未送信でも、期限つき起動は fork 前の flush で
    /// 止まらず、指定した timeout の範囲で失敗を返す。
    #[test]
    fn repair5_1816_launch_does_not_block_on_full_stdout_pipe() {
        if std::env::var_os("REPAIR5_1816_MARKER").is_some() {
            return;
        }
        let (reader, writer) = std::io::pipe().unwrap();
        let filler_writer = writer.try_clone().unwrap();
        let marker = std::env::temp_dir().join(format!("repair5-1816-{}", std::process::id()));
        let (ready, go) = (marker.with_extension("ready"), marker.with_extension("go"));
        for f in [&marker, &ready, &go] {
            let _ = std::fs::remove_file(f);
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "--nocapture",
                "--test-threads=1",
                "exec::launch_intermediate::tests::repair5_1816_child_stdout_full_helper",
            ])
            .env("REPAIR5_1816_MARKER", &marker)
            .stdout(writer)
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let wait_for = |path: &Path, secs: u64| {
            let deadline = Instant::now() + Duration::from_secs(secs);
            while !path.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            path.exists()
        };
        let child_ready = wait_for(&ready, 20);
        // 読まれない pipe を満杯にする(満杯になると書き込みスレッドが止まる)。
        let filler = std::thread::spawn(move || {
            let mut w = filler_writer;
            let chunk = [0u8; 4096];
            while w.write_all(&chunk).is_ok() {}
        });
        std::thread::sleep(Duration::from_millis(500));
        let _ = std::fs::write(&go, b"1");
        let finished = child_ready && wait_for(&marker, 20);
        let _ = child.kill();
        let _ = child.wait();
        drop(reader);
        let _ = filler.join();
        for f in [&marker, &ready, &go] {
            let _ = std::fs::remove_file(f);
        }
        assert!(finished, "launch blocked on a full stdout pipe");
    }
}
