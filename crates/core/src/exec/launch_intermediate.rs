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
//!   -> (listener の受け渡しの後)状態 pipe の 2 行目(exec 前の `R`/`E`。entrypoint 系の違反)を読み、同様に記録・判定(#2624)
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
//! # seccomp の listener の受け渡し(SEC-4・TASK-41 追補・#2024。監査配送 2/6)
//!
//! C は fork の前に socketpair(`SOCK_SEQPACKET`。C の端は `SO_PASSCRED`)を作り、子の端を PID 1 へ渡す。I は C の端を
//! 閉じてから動く。PID 1 は最終段 `Seccomp` で `NEW_LISTENER` 付きの適用をして listener を送り、C の ACK を待ってから
//! exec する。C は状態(`P`)の判定が成功した後に期限つきで受け取り、検証([`super::seccomp_listener`])に通ったものを
//! [`LaunchedChild`] に載せる。**EOF・期限切れ・検証の不一致は PID 1 を回収して起動失敗**(listener 無しで走らせない)。
//! 副作用として、`Seccomp` 段より前の段(Landlock 等)で PID 1 が失敗した場合も、C は listener を受け取れず
//! 起動失敗として観測する(従来は PID 1 の終了として観測していた。具体的な原因は PID 1 の stderr に残る)。
//! 応答ループは #2025。本番の filter は当面 ERRNO 版のため通知は生じない。
//!
//! # netns の素性の同期点(NET-6・SEC-1・SEC-4・#3206。`docs/design/network-wiring.md` D8)
//!
//! `IntermediateSpec::netns_sync` が `Some`(`network_mode=host` / `loopback` の起動)なら、C は fork の前に基準(自分の netns の
//! (dev, ino))を取り、listener 用とは別の socketpair を作る。PID 1 は開始ゲートの通過後・`child_main` の前に自分の netns を
//! 送って ACK を待ち、C は中間プロセスの回収後・状態 `P` の判定の前に受信して期待と照合する([`super::netns_sync`])。不一致・
//! 形式違反は層 `mount` に 1 件記録し、EOF・期限切れを含むどの失敗でも PID 1 を回収して起動失敗(fail-closed)。
//! C の端は I で閉じるので、C が死ぬと PID 1 は EOF で exec せずに終わる。
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
//!   I は `isolate`(範囲写像の mapper の fork)の前に起動ごとの識別子(`LaunchTag`)を `comm` へ設定し、mapper と PID 1 はそれを継承する(期限切れで I だけが殺されても、再親付けされた mapper を同じ探索で回収する。mapper の子の helper〔`newuidmap` / `newgidmap`〕は exec で識別子を失うため、mapper は自分のセッションを作り、探索は識別子を持つプロセスを錨に「親が錨」か「セッション ID が錨」の子孫を列挙して先に kill・回収する。錨は子孫が居ないと確かめるまで回収しない)。C は報告の
//!   無い失敗で I を SIGKILL して回収した後(PID 1 は C へ再親付け済み)、`/proc` から「親が C で `comm` が
//!   識別子と一致する」子を探して `kill_and_reap` する(`recover_unreported_init`)。I を回収できない場合は
//!   再親付けが起きないため探索せず、I を `unreaped` で返し、探索できなかった識別子を `rescans` で返す(呼び出し側が
//!   起動予約を保持し、`confirm_no_process` が I の回収後に `rescan_unreported_init` で再探索する。#1817)。報告が `R`(失敗)の経路も、I が範囲写像の失敗で mapper を kill せずに残す(helper ごと C に回収させる)ため、I の回収後に同じ探索を行う(#2009)
//! - **開始ゲート(CORE-2)**: PID 1 は C が `K` の pid を受領して pidfd を開き、1 行の許可を書くまで exec に進まない
//!   (exec で `comm` の識別子が失われると、報告前の PID 1 を特定できなくなるため)。C が許可せず閉じる・期限
//!   ([`START_GATE_TIMEOUT`])切れの PID 1 は exec せずに終了する
//! - **探索の fail-closed**: `/proc` の列挙・stat / comm の読み取りや解析の失敗は `reap_error` に残し、消滅を
//!   確認できた場合(対象が `ENOENT`/`ESRCH` で消えた)と区別する
//! - 回収できなかった子は [`PreparedLaunchFailure::unreaped`] で呼び出し側(launcher)へ返す。握りつぶさない

use std::io::Write as _;
use std::num::NonZeroU32;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use crate::audit_log::AuditedRejection;
use crate::sys;
use crate::traits::types::ErrorCode;

use super::launch_status::{
    ExecPhaseOutcome, ExecPhaseStep, LaunchAudit, PrePivotStatus, PrePivotStatusError,
    read_exec_phase_until_close, read_line_bounded, read_mount_identity_block,
    read_pre_pivot_status, read_pre_pivot_status_leaving_tail, resolve_exec_phase_status,
    resolve_pre_pivot_status,
};
use super::netns_sync::{
    AttachCheck, NETNS_SYNC_ACK_TIMEOUT, NetnsCheck, NetnsHandover, NetnsSyncRequest,
    NetnsSyncSender, capture_baseline, capture_user_baseline, netns_socketpair, receive_and_verify,
};
use super::process::{
    ChildStdio, ContainerChild, EXIT_SETUP_FAILED, Entrypoint, KILL_REAP_TIMEOUT, PrePivotSetup,
    PreparedLaunchFailure, child_main, exec_status_pipe, report_legacy_tiocsti_to,
};
use super::seccomp_listener::{
    ListenerReceiveFailure, ListenerSender, SeccompListener, listener_socketpair,
    receive_listener_or_closed,
};
use super::{
    ChildSubreaper, ExecError, IsolationPlan, IsolationStage, StagePipeline,
    SubordinateIsolationPlan, isolate, isolate_rootless_subordinate_no_flush,
};
use crate::launch_isolation::RecordedMountIdentity;
use crate::oci_runtime::NetnsAttachHook;

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
                let code = ErrorCode::from_name(code).ok_or(PrePivotStatusError::Malformed)?;
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
    /// pod の user・ipc namespace への join(あれば `isolate` は作成ではなく参加する。#2674)。
    join: Option<&'a crate::oci_runtime::NamespaceJoin>,
    rootfs: &'a Path,
    entry: &'a Entrypoint,
    stages: Option<StagePipeline>,
    stdio: Option<ChildStdio>,
    setup: PrePivotSetup<'a>,
    report: &'a std::fs::File,
    tag: LaunchTag,
    gate_r: &'a std::fs::File,
    /// seccomp の listener を C へ渡す socketpair の子の端(借用。PID 1 は複製を `Seccomp` 段へ渡す。SEC-4・#2024)。
    listener_end: &'a OwnedFd,
    /// netns の素性の同期点の socketpair の子の端(同期点を通す起動だけ `Some`。PID 1 は複製を使う。NET-6・#3206)。
    netns_end: Option<&'a OwnedFd>,
    /// 同期点で子が渡す fd の組(Attachable は netns と user namespace の 2 本。NET-9・#1939)。
    netns_handover: NetnsHandover,
}

impl IntermediateOps for RealIntermediateOps<'_> {
    fn isolate(&mut self) -> Result<(), ExecError> {
        // 範囲写像では holder(user namespace を作って保持する使い捨てプロセス。I は終始 non-dumpable のまま
        // holder の namespace へ参加する。#2374)と mapper を I の子として fork する。どちらも識別子を継承させ、起動の期限切れで C が I だけを
        // 殺した場合や、範囲写像の失敗で I が mapper を残して `R` を報告した場合に、再親付けされた mapper を
        // `rescan_unreported_init` が見つけて helper ごと回収できるようにする(CORE-2)。設定できなければ mapper を
        // 作らずに失敗させる(fail-closed)。
        sys::set_process_comm(self.tag.comm_bytes())
            .map_err(|e| ExecError::from_sys(e, IsolationStage::Spawn, "set the launch tag"))?;
        // pod の namespace へ join する起動は mapper・holder を使わず、参加先の写像を計画と照合する(#2674)。
        if let Some(join) = self.join {
            return super::isolate_join(self.plan, join);
        }
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
        // PID 1 の `Seccomp` 段が listener を送る口。複製は close-on-exec で、段が送信後に閉じる。複製できなければ
        // PID 1 を作らずに失敗させる(listener 無しで実行させない。fail-closed。SEC-4・#2024)。
        let delivery = stages.seccomp_delivery();
        let sender = ListenerSender::new(self.listener_end.try_clone().map_err(|e| {
            ExecError::from_io(&e, IsolationStage::Spawn, "duplicate the listener socket")
        })?)
        .with_delivery(delivery);
        let stages = stages.with_listener_sender(sender);
        // netns の同期点の口。複製できなければ PID 1 を作らずに失敗させる(同期点を飛ばして走らせない。fail-closed。#3206)。
        let netns_handover = self.netns_handover;
        let netns_sender = self
            .netns_end
            .map(|end| {
                end.try_clone().map(NetnsSyncSender::new).map_err(|e| {
                    ExecError::from_io(&e, IsolationStage::Spawn, "duplicate the netns socket")
                })
            })
            .transpose()?;
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
                if await_start_gate(gate_r, START_GATE_TIMEOUT).is_err() {
                    return EXIT_SETUP_FAILED;
                }
                // exec 直前の同期点(NET-6・SEC-1・#3206): pivot と資格情報の切り替え(`CapabilityDrop` 段)より前に、
                // 自分の netns(Attachable は続けて user namespace)を C へ渡して検証済みの ACK を待つ。ACK が無ければ
                // (EOF・期限切れ・拒否・呼び出し側のフックの失敗)exec しない。
                if let Some(sender) = netns_sender
                    && sender
                        .hand_over(netns_handover, NETNS_SYNC_ACK_TIMEOUT)
                        .is_err()
                {
                    return EXIT_SETUP_FAILED;
                }
                child_main(rootfs, entry, stages, Some(setup), stdio)
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
    /// pod の user・ipc namespace への join(`None` なら新しく作る。CRI-2・CORE-3。#2674)。
    pub(crate) join: Option<&'a crate::oci_runtime::NamespaceJoin>,
    /// rootfs のパス(使用は `setup.pinned_rootfs` の固定 fd との照合を通る)。
    pub(crate) rootfs: &'a Path,
    /// exec するエントリポイント。
    pub(crate) entry: &'a Entrypoint,
    /// pivot 前段の指定。`status` は本入口が上書きする。
    pub(crate) setup: PrePivotSetup<'a>,
    /// exec 直前の netns の素性の同期点(`Host` と `Loopback` の起動だけ `Some`。`FromConfig` は通さない。
    /// NET-6・SEC-1・#3206。`docs/design/network-wiring.md` D8)。
    pub(crate) netns_sync: Option<NetnsSyncRequest>,
    /// 同期点の中で呼ぶ呼び出し側の準備処理(`Attachable` の起動だけ `Some`。他は `None`。欠落は launch の入口が fork の前に
    /// 拒否する。NET-9・CORE-6・#1939)。
    pub(crate) netns_attach: Option<&'a dyn NetnsAttachHook>,
}

/// 中間プロセス経由でコンテナの PID 1 を起動する(本番 launcher の唯一の起動入口。#1816)。
///
/// `timeout` を上限に、中間プロセスの報告と pivot 前段の結果を読む。成功なら PID 1 の [`ContainerChild`](pidfd
/// つき。呼び出し側が回収の所有者)を返す。失敗・期限切れ・形式違反のいずれでも起動失敗とし、生成済みの PID 1 と
/// 中間プロセスを回収する(回収できなければ [`PreparedLaunchFailure::unreaped`] に返す)。違反は `audit` の
/// sink へ C が 1 件記録する(層 `mount`・パスなし)。
///
/// 前提: 呼び出しプロセスが `Threads: 1`(満たさなければ `FailedPrecondition`。副作用は pipe の作成のみ)。成功
/// (`P`)の後は seccomp の listener を受け取り、さらに PID 1 が `execveat` の直前に書く 2 行目(`R`)まで読んで成功とする。
/// エントリポイントの検証の失敗(`E`。entrypoint 系の違反 8 理由。`launch_status` の「exec 前の 2 行目」)は起動失敗として
/// 返り、違反ありなら C が `audit_entrypoint_violation` で層 `entrypoint` に 1 件記録する(SEC-4・#2624)。
/// `R` の後の `execveat` 自体の errno 由来の失敗は、PID 1 が `X <CODE>` を書き、C が `R` の後も EOF まで読んで
/// 起動失敗にする(違反ではないため記録の対象外。#2716)。EOF が来なければ期限切れで失敗にして PID 1 を回収する。
///
/// `dev.tty.legacy_tiocsti` の警告(CORE-5・SEC-1・REPAIR-4・REPAIR-5・#1739・#2008): 中間プロセスの fork に成功した
/// 後、C の側で 1 回だけ、host の値が `1` のときに固定の 1 行を C の stderr へ出す(従来経路
/// `spawn_container_with_stages` と同じ契約。観測のみで起動の可否は変えない)。fork 前の拒否(複数スレッド・pipe・
/// fork の失敗)では出さない。出力は待たず(AF_UNIX の socket 以外へは書かない)、報告を読む期限を食わない。
/// restart の再 launch(#2043)が本入口を通れば launch のたびに 1 行出る(host のグローバルな値の観測のため)。
/// stderr が AF_UNIX の socket でない構成(CLI の `start` は null)では捨てられるため、supervisor が start の成功後に
/// 同じ観測を自分のログ(`@supervisor-logs`)へも残す。
pub(crate) fn spawn_container_via_intermediate(
    spec: IntermediateSpec<'_>,
    stages: StagePipeline,
    stdio: ChildStdio,
    subreaper: &ChildSubreaper,
    audit: LaunchAudit<'_>,
    timeout: Duration,
) -> Result<LaunchedChild, Box<PreparedLaunchFailure>> {
    let IntermediateSpec {
        plan,
        join,
        rootfs,
        entry,
        setup,
        netns_sync,
        netns_attach,
    } = spec;
    let tag = LaunchTag::fresh();
    let netns_handover = netns_sync.map_or(NetnsHandover::NetOnly, |r| r.handover);
    // 基準(supervisor 自身の netns)は fork の前に取る。取れなければ子を作らずに拒否する(fail-closed。#3206)。
    let netns = match netns_sync {
        None => None,
        Some(request) => {
            let baseline = match request.baseline {
                Some(baseline) => baseline,
                None => capture_baseline().map_err(|e| {
                    Box::new(PreparedLaunchFailure::clean(
                        AuditedRejection::not_applicable(e),
                    ))
                })?,
            };
            // 2 本版(Attachable)はフックと C 自身の user namespace の基準が要る。欠ければ子を作らずに拒否する
            // (フック無しで合図を送らない。fail-closed。NET-9・#1939)。
            let attach = match (request.handover, netns_attach) {
                (NetnsHandover::NetOnly, _) => None,
                (NetnsHandover::NetAndUser, None) => {
                    return Err(Box::new(PreparedLaunchFailure::clean(
                        AuditedRejection::not_applicable(ExecError::new(
                            ErrorCode::Internal,
                            IsolationStage::NetnsAttach,
                            "the attachable network mode has no attach hook",
                        )),
                    )));
                }
                (NetnsHandover::NetAndUser, Some(hook)) => Some(AttachCheck {
                    user_baseline: capture_user_baseline().map_err(|e| {
                        Box::new(PreparedLaunchFailure::clean(
                            AuditedRejection::not_applicable(e),
                        ))
                    })?,
                    hook,
                }),
            };
            Some(NetnsCheck {
                expectation: request.expectation,
                baseline,
                attach,
            })
        }
    };
    // 子が状態 pipe で返す識別子のブロックの期待列（Mount 由来のルールの位置）。fork の前に ruleset から計算する（#3201）。
    let expected_mounts = stages.mount_rule_positions();
    launch_via_intermediate(
        sys::self_is_single_threaded,
        |status, report, gate_r, listener_end, netns_end| {
            let mut ops = RealIntermediateOps {
                plan,
                join,
                rootfs,
                entry,
                stages: Some(stages),
                stdio: Some(stdio),
                setup: with_status(setup, status),
                report,
                tag,
                gate_r,
                listener_end,
                netns_end,
                netns_handover,
            };
            intermediate_body(&mut ops)
        },
        Some(&expected_mounts),
        netns,
        subreaper,
        audit,
        timeout,
        &tag,
        (
            crate::legacy_tiocsti::read_host(),
            std::io::stderr().as_fd(),
        ),
    )
}

/// 呼び出し側の `setup` に状態 pipe の書き込み側だけを足す。`sysctls` を含むほかの段は必ず引き継ぐ
/// (捨てると config の `linux.sysctl` が受理されたのに適用されない。CRI-2・CORE-3・SEC-1・#2670)。
fn with_status<'a>(setup: PrePivotSetup<'a>, status: &'a std::fs::File) -> PrePivotSetup<'a> {
    PrePivotSetup {
        status: Some(status),
        ..setup
    }
}

/// 起動に成功した PID 1 のハンドルと、PID 1 から受け取った seccomp の listener(SEC-4・#2024)。
#[derive(Debug)]
pub(crate) struct LaunchedChild {
    /// PID 1 のハンドル(pidfd つき。呼び出し側が回収の所有者)。
    pub(crate) child: ContainerChild,
    /// 検証済みの listener。本番の入口(`spawn_container_via_intermediate`)は必ず `Some`(受け取れなければ
    /// 起動失敗)。受け渡し無しの試験用経路だけが `None`。
    pub(crate) listener: Option<SeccompListener>,
    /// 子が pivot 前段の直後に返した Mount 由来のルールの launch 時の識別子（`(ルール位置, 識別子)`。昇順。親が fork の前に
    /// 計算した期待列と完全一致を確認済み）。launcher が分離の記録へ添える（SEC-1・SEC-4・#3201）。受け渡し無しの
    /// 試験用経路は空。
    pub(crate) mount_identities: Vec<(usize, RecordedMountIdentity)>,
}

/// [`spawn_container_via_intermediate`] の本体。中間プロセスの動作(`intermediate`)と fork 前のスレッド数判定を
/// 注入できるようにして、成功・各失敗・無報告の期限切れを結合試験で照合する(REPAIR-10・REPAIR-12)。
///
/// `intermediate` は fork した中間プロセスの中で `(状態 pipe の書き込み側, 報告 pipe の書き込み側, 開始ゲートの
/// 読み取り側, listener socketpair の子の端, netns 同期点の socketpair の子の端〔`netns` が `Some` のときだけ〕)` を
/// 受けて呼ばれ、戻り値が `_exit` の終了コードになる。
///
/// `netns` が `Some` なら、PID 1 が exec 直前に渡す自分の netns を状態の判定より前に受け取って検証し(基準と期待の
/// 照合。不一致・形式違反は層 `mount` に 1 件記録する)、合格したときだけ ACK を返す。EOF・期限切れ・不合格は PID 1 を
/// 回収して起動失敗(fail-closed)。NET-6・SEC-1・SEC-4・#3206。
///
/// `listener_handoff` が `Some(expected_mounts)` なら、状態の判定（`P`）が成功した後に、子が返す識別子のブロック
/// （`launch_status` の `L`/`M`。ルール位置が `expected_mounts` と完全一致すること。#3201）を読み切り、そのあと PID 1 から
/// seccomp の listener を期限つきで受け取って検証し(EOF・期限切れ・検証の不一致は PID 1 を回収して起動失敗。
/// fail-closed)、ACK を返す。`None` は受け渡しの無い試験用の立て替え PID 1 のためだけに使い、本番の入口は常に `Some`。
// 理由: 注入点(スレッド判定・中間プロセス・listener の有無)と、期限・監査・識別子・警告の出力先は独立に差し替える値で、
// 束ねる型を作ると試験側の組み立てが増えるだけのため引数のまま渡す。
#[allow(clippy::too_many_arguments)]
fn launch_via_intermediate(
    is_single_threaded: impl FnOnce() -> bool,
    intermediate: impl FnOnce(
        &std::fs::File,
        &std::fs::File,
        &std::fs::File,
        &OwnedFd,
        Option<&OwnedFd>,
    ) -> i32,
    listener_handoff: Option<&[usize]>,
    netns: Option<NetnsCheck<'_>>,
    subreaper: &ChildSubreaper,
    audit: LaunchAudit<'_>,
    timeout: Duration,
    tag: &LaunchTag,
    legacy: (crate::legacy_tiocsti::LegacyTiocsti, BorrowedFd<'_>),
) -> Result<LaunchedChild, Box<PreparedLaunchFailure>> {
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
    // seccomp の listener の受け渡し(SEC-4・#2024)。C の端は `SO_PASSCRED` 設定済み(送信元の pid を受け取る)。
    let (parent_end, child_end) = listener_socketpair().map_err(not_started)?;
    // netns の素性の同期点(NET-6・#3206)。同期点を通す起動だけ作る。C の端も `SO_PASSCRED` 設定済み。
    let netns_pair = netns
        .as_ref()
        .map(|_| netns_socketpair().map_err(not_started))
        .transpose()?;
    let (netns_parent, netns_child) = match netns_pair {
        Some((parent, child)) => (Some(parent), Some(child)),
        None => (None, None),
    };
    let (status_ref, report_ref) = (&status_w, &report_w);
    let (gate_r_ref, child_end_ref, netns_child_ref) = (&gate_r, &child_end, netns_child.as_ref());
    let netns_parent_fd = netns_parent.as_ref().map(|f| f.as_raw_fd());
    let (gate_w_fd, report_r_fd, status_r_fd, parent_end_fd) = (
        gate_w.as_raw_fd(),
        report_r.as_raw_fd(),
        status_r.as_raw_fd(),
        parent_end.as_raw_fd(),
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
                || close_inherited(parent_end_fd).is_err()
            {
                return EXIT_SETUP_FAILED;
            }
            // netns 同期点の C の端も閉じる(PID 1 へ継承されると、C の死を PID 1 が EOF で検出できない。REPAIR-5)。
            if let Some(fd) = netns_parent_fd
                && close_inherited(fd).is_err()
            {
                return EXIT_SETUP_FAILED;
            }
            intermediate(
                status_ref,
                report_ref,
                gate_r_ref,
                child_end_ref,
                netns_child_ref,
            )
        },
        EXIT_SETUP_FAILED,
    )
    .map_err(|e| not_started(ExecError::from_sys(e, IsolationStage::Spawn, "fork")))?;
    // fork に成功したので、`dev.tty.legacy_tiocsti` の警告を 1 回だけ出す(観測のみ。結果は起動の可否に使わない)。
    let _ = report_legacy_tiocsti_to(legacy.0, legacy.1);
    // 親が書き込み側を持ち続けると、子が報告せずに終了しても EOF を観測できない。
    drop(status_w);
    drop(report_w);
    drop(gate_r);
    // 子の端を C が持ち続けると、PID 1 が送る前に死んでも EOF を観測できない。
    drop(child_end);
    drop(netns_child);
    let intermediate_child = ContainerChild::spawned(intermediate_pid);

    let report = read_line_bounded::<REPORT_MAX_BYTES>(&report_r, remaining())
        .and_then(|(buf, end)| IntermediateReport::decode(buf.get(..end).unwrap_or(&[])));
    let pid1 = match report {
        Ok(IntermediateReport::Pid1(pid)) => pid,
        Ok(IntermediateReport::Failed { code, phase }) => {
            let (stage, what) = phase.describe();
            let mut failure =
                reap_intermediate_failure(intermediate_child, ExecError::new(code, stage, what));
            // `R` の経路でも、I が識別子を継承させた子(範囲写像の mapper とその helper)が残り得る。I は失敗時に
            // mapper を kill しない(`isolate_rootless_subordinate_no_flush`)ため、I の回収後に C へ再親付けされた
            // mapper を識別子で探して helper ごと回収する(CORE-2)。I を回収できていなければ再親付けが起きないので、
            // 識別子を返して `confirm_no_process` の再探索に回す(#1817)。
            if failure.unreaped.is_empty() {
                recover_unreported_init(&mut failure, tag, subreaper);
            } else {
                failure.rescans.push(*tag);
            }
            return Err(failure);
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

    // exec 直前の同期点: PID 1 の netns の素性を状態の判定より前に検証する(PID 1 は pivot の前でこれを待つ。NET-6・SEC-1・
    // #3206)。不一致・形式違反は層 `mount` に 1 件記録し、EOF・期限切れ・errno は記録しない(系のエラー)。
    if let (Some(check), Some(sock)) = (netns.as_ref(), netns_parent.as_ref())
        && let Err(failure) = receive_and_verify(sock.as_fd(), pid1.get(), check, deadline)
    {
        let rejection = match failure.reason {
            Some(reason) => super::record_launch_mount_rejection_at(
                failure.error,
                reason,
                Some(IsolationStage::NetnsVerify),
                audit.container,
                audit.sink,
            ),
            None => AuditedRejection::not_applicable(failure.error),
        };
        return Err(kill_pid1_failure(child, rejection));
    }
    // listener を受け取る経路(本番)は、後ろのバイト(Landlock 段の `E`)を取り込まない版で 1 行目を読む(#2130)。
    let status = if listener_handoff.is_some() {
        read_pre_pivot_status_leaving_tail(&status_r, remaining())
    } else {
        read_pre_pivot_status(&status_r, remaining())
    };
    // `P` の直後の識別子のブロックは、listener を受け取る前に読み切る(PID 1 は `P` の後に先にこれを書く。#3201)。
    // 欠落・形式違反・期限切れは listener を受け取らず PID 1 を回収する(記録できない識別子で走らせない。fail-closed)。
    let mut mount_identities = Vec::new();
    let status = match (status, listener_handoff) {
        (Ok(PrePivotStatus::Ready), Some(expected)) => {
            match read_mount_identity_block(&status_r, expected, remaining()) {
                Ok(ids) => {
                    mount_identities = ids;
                    Ok(PrePivotStatus::Ready)
                }
                Err(e) => {
                    return Err(kill_pid1_failure(
                        child,
                        AuditedRejection::not_applicable(e.to_exec_error()),
                    ));
                }
            }
        }
        (other, _) => other,
    };
    match resolve_pre_pivot_status(status, audit) {
        Ok(()) if listener_handoff.is_none() => Ok(LaunchedChild {
            child,
            listener: None,
            mount_identities: Vec::new(),
        }),
        Ok(()) => match receive_listener_or_closed(parent_end.as_fd(), pid1.get(), deadline) {
            // listener を受け取って ACK を返した後に、PID 1 が書く exec 前の 2 行目(`R`/`E`)を読む(SEC-4・#2624)。
            // 順序の根拠: PID 1 は ACK を待ってからエントリポイントの検証へ進み、C は上の `P` の判定より前に listener を
            // 受け取らない。したがって 2 行目は `P` を読み終えた後にしか書かれず、2 行が 1 回の `read` に混ざらない。
            Ok(listener) => {
                let exec_phase = read_exec_phase_until_close(&status_r, remaining());
                match resolve_exec_phase_status(exec_phase, audit) {
                    Ok(()) => Ok(LaunchedChild {
                        child,
                        listener: Some(listener),
                        mount_identities,
                    }),
                    Err(rejection) => Err(kill_pid1_failure(child, *rejection)),
                }
            }
            // 受け渡せなければ listener 無しで走らせない。PID 1 は ACK 待ちか既に終了しているため回収する。
            // 送り手が閉じただけ(seccomp より前で子が終わった)なら、Landlock 段の失敗が状態 pipe の `E landlock ...`
            // で照合の違反を運んでいないか読む(SEC-4・#2130)。何も無い・他の形・読み取り失敗のときは従来どおり
            // 元の `ExecError` を記録なしで返す(拒否は覆さない。期限は入口の単一期限の残り)。
            Err(f) => Err(kill_pid1_failure(
                child,
                landlock_rejection_after_sender_closed(&f, &status_r, remaining(), audit),
            )),
        },
        Err(rejection) => Err(kill_pid1_failure(child, *rejection)),
    }
}

/// listener の送り手が閉じた失敗 `f` について、状態 pipe の Landlock 段の `E` 行を読み、照合の違反があれば層 `mount` に
/// 1 件記録した拒否を返す(SEC-1・SEC-4・CORE-5・#2130)。`E landlock` 以外(何も無い・`R`・他の段・形式違反・期限切れ)は
/// `f.error` を `not_applicable` で返す(従来の挙動。記録の失敗や読み取りの失敗で拒否は覆らない)。
fn landlock_rejection_after_sender_closed(
    f: &ListenerReceiveFailure,
    status_r: &std::fs::File,
    timeout: Duration,
    audit: LaunchAudit<'_>,
) -> AuditedRejection<ExecError> {
    let fallback = || AuditedRejection::not_applicable(f.error.clone());
    if !f.sender_closed {
        return fallback();
    }
    match read_exec_phase_until_close(status_r, timeout) {
        Ok(
            outcome @ ExecPhaseOutcome::Failed {
                step: ExecPhaseStep::Landlock,
                ..
            },
        ) => resolve_exec_phase_status(Ok(outcome), audit)
            .err()
            .map_or_else(fallback, |r| *r),
        _ => fallback(),
    }
}

/// 起動失敗にする PID 1 を kill して回収し、`rejection` を添えた失敗を返す。回収に失敗した場合は握りつぶさず、
/// 子のハンドルごと呼び出し側へ返す(孤児化の防止。CORE-2)。
fn kill_pid1_failure(
    child: ContainerChild,
    rejection: AuditedRejection<ExecError>,
) -> Box<PreparedLaunchFailure> {
    match child.kill_and_reap(KILL_REAP_TIMEOUT) {
        Ok(_) => Box::new(PreparedLaunchFailure::clean(rejection)),
        Err(reap_error) => Box::new(PreparedLaunchFailure::with_unreaped(
            rejection, child, reap_error,
        )),
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
    let mut candidates: Vec<NonZeroU32> = Vec::new();
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
        candidates.push(pid);
    }
    // 2 段階で回収する(CORE-6・SEC-5・#2376)。範囲写像の helper(`newuidmap` / `newgidmap`)は holder を pid の数値で
    // 受け取るため、識別子つきの子(holder・mapper・PID 1)のどれかを回収する前に、全員の子孫(helper)を止めて
    // ゾンビ化を確かめる。1 つでも保持(列挙不完全・停止未確認)になれば、その子孫の helper が生きている可能性が
    // あるため、どの錨も回収しない(停止したまま残し、`scan_incomplete` により呼び出し側が識別子で再探索する)。
    // 候補の列挙自体が不完全(`/proc` の列挙・stat・comm の読み取りの失敗)なら、見逃した候補(mapper 等)の helper が
    // 生きている可能性があるため、見つけた候補も止めるだけで回収しない。
    let listing_incomplete = out.scan_incomplete;
    let mut halted = Vec::with_capacity(candidates.len());
    let mut retained = false;
    for pid in candidates {
        match halt_tagged(pid, reap_timeout, me, &mut out) {
            Some(members) => halted.push((pid, members)),
            None => retained = true,
        }
    }
    if !may_reap_halted(listing_incomplete, retained) {
        out.scan_incomplete = true;
        return out;
    }
    for (pid, members) in halted {
        reap_halted(pid, members, subreaper, reap_timeout, &mut out);
    }
    out
}

/// 識別子を持つ C の子 `pid`(報告前の PID 1、または範囲写像の mapper)を、子孫(helper)ごと kill・回収する(CORE-2)。
///
/// mapper が起動する `newuidmap` / `newgidmap`(helper)は exec で `comm` が識別子でなくなるため、識別子では
/// 見つからない。mapper は fork 直後に自分のセッション(ID = mapper の pid)を作る(`exec` の
/// `isolate_rootless_subordinate_with`)ので、helper は「親が mapper」か「セッション ID が mapper の pid」で特定する。
/// 後者は mapper が helper を残して終了し、helper が C へ再親付けされた後でも成り立つ。そのため mapper は、子孫が
/// 居ないことを確かめるまで回収しない(未回収のゾンビが pid を保持し、セッション ID が別プロセスへ再利用されない。
/// 帰属の錨)。手順は次のとおり。
///
/// 1. `SIGSTOP` を送り、`/proc` の state が停止(`T`)かゾンビ(`Z`)になるまで期限つきで待つ(以後 fork しない)。
///    `SignalDelivery` を返す `send_signal` はゾンビをその場で回収してしまい錨を失うため使わない(未回収の子なので
///    `kill(2)` が別プロセスへ届くことはない)
/// 2. 子孫を列挙する。親が `pid` か C で、かつ(親が `pid` またはセッション ID が `pid`)のプロセスだけを対象とし、
///    それ以外の親を持つ子孫(helper の子等。pid の安定を保証できない)が居れば列挙不完全とする
/// 3. 停止を確かめられない・列挙不完全なら、`pid` も子孫も kill・回収せずに保持する(走査不完全。呼び出し側が
///    識別子を `rescans` に残し、次の再探索が同じ錨から再び辿る。fail-closed)
/// 4. 子孫を `SIGKILL` し、全員のゾンビ化を確かめる(ここまでが本関数。保持なら `None`)
/// 5. `pid` を kill・回収 → C へ再親付けされた子孫を回収する([`reap_halted`]。呼び出し側は、全候補の 1〜4 が
///    済んでから 5 に進む。helper が holder を pid で受け取るため、helper を止める前に holder を回収しない。#2376)
fn halt_tagged(
    pid: NonZeroU32,
    reap_timeout: Duration,
    me: u32,
    out: &mut Rescan,
) -> Option<Vec<NonZeroU32>> {
    let halted = halt_and_confirm(pid.get(), reap_timeout);
    // 子孫の列挙が不完全かを、この候補の分だけ判定する(他の候補で立った不完全フラグと区別する)。
    let earlier_incomplete = std::mem::replace(&mut out.scan_incomplete, false);
    let members = if halted {
        descendants_of(pid.get(), me, out)
    } else {
        note_scan_failure(
            out,
            "cannot confirm a tagged process stopped or exited before listing its descendants",
        );
        Vec::new()
    };
    let enumeration_incomplete = out.scan_incomplete;
    out.scan_incomplete |= earlier_incomplete;
    if must_retain_tagged(halted, enumeration_incomplete) {
        // 列挙を完了できていない間は kill・回収しない。殺すと未列挙の helper が C へ再親付けされ、回収すると錨の
        // pid(セッション ID)が解放されて helper の帰属を失い、次の `confirm_no_process` が Clean に進む(CORE-2)。
        // ハンドルは `unreaped`(後で無条件に kill・回収される通常の未回収ハンドル)へ入れない。捨てても対象は
        // 停止中(またはゾンビ)のまま残り、`scan_incomplete` により呼び出し側が識別子を `rescans` に残すので、次の
        // 再探索が識別子で再び見つけ、列挙を完了してから回収する。
        if out.error.is_none() {
            out.error = Some(ExecError::new(
                ErrorCode::Internal,
                IsolationStage::Wait,
                "kept a tagged process because its descendants could not be fully listed",
            ));
        }
        return None;
    }
    for member in &members {
        // 子孫は停止(またはゾンビ)の錨か C の未回収の子なので、回収されるまで pid は再利用されない。
        let _ = sys::kill_pid(member.get(), sys::Signal::Kill);
    }
    // SIGKILL は送達と終了が同時でないため、列挙の後・終了の前に fork された子孫を取りこぼし得る。全員がゾンビに
    // なった(以後 fork できない)ことを確かめてから列挙し直し、増えていれば保持する(上と同じ理由。fail-closed)。
    if !settled_after_kill(pid.get(), &members, me, reap_timeout) {
        out.scan_incomplete = true;
        if out.error.is_none() {
            out.error = Some(ExecError::new(
                ErrorCode::Internal,
                IsolationStage::Wait,
                "kept a tagged process because its descendants did not settle after SIGKILL",
            ));
        }
        return None;
    }
    Some(members)
}

/// [`halt_tagged`] で子孫を止めた識別子つきの子 `pid` を kill・回収し、C へ再親付けされた子孫 `members` を回収する
/// (CORE-2)。呼び出し側は、同じ再探索の全候補の [`halt_tagged`] が保持なしで済んだ後にだけ呼ぶ(#2376)。
fn reap_halted(
    pid: NonZeroU32,
    mut members: Vec<NonZeroU32>,
    subreaper: &ChildSubreaper,
    reap_timeout: Duration,
    out: &mut Rescan,
) {
    let child = ContainerChild::adopt_reparented(pid, subreaper);
    if let Err(e) = child.kill_and_reap(reap_timeout) {
        if out.error.is_none() {
            out.error = Some(e);
        }
        out.unreaped.push(child);
    }
    // 錨の死(または回収)で C(subreaper)へ再親付けされた子孫を回収する。
    for member in members.drain(..) {
        let reparented = ContainerChild::adopt_reparented(member, subreaper);
        if let Err(e) = reparented.kill_and_reap(reap_timeout) {
            if out.error.is_none() {
                out.error = Some(e);
            }
            out.unreaped.push(reparented);
        }
    }
}

/// `SIGKILL` を送った子孫 `members` が期限内に全員ゾンビになり、列挙し直しても子孫が増えていないか(CORE-2・REPAIR-5)。
///
/// `members` は錨か C の未回収の子なので、回収されるまで `/proc` から消えない(消えた・読めないは `false`)。
fn settled_after_kill(anchor: u32, members: &[NonZeroU32], me: u32, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout.min(Duration::from_secs(2));
    for member in members {
        let path = Path::new("/proc")
            .join(member.get().to_string())
            .join("stat");
        loop {
            match read_proc_text(&path) {
                Ok(Some(stat)) if proc_state_of(&stat) == Some('Z') => break,
                Ok(Some(stat)) if proc_state_of(&stat).is_some() => {}
                _ => return false,
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let mut again = Rescan::default();
    let relisted = descendants_of(anchor, me, &mut again);
    !again.scan_incomplete && relisted.iter().all(|p| members.contains(p))
}

/// 止めた候補(錨)を回収へ進めてよいか。候補の列挙が不完全か、どれか 1 つでも保持になったら、どの錨も回収しない
/// (helper が holder を pid の数値で受け取るため、helper を止めたと言えない間に holder の pid を解放しない。
/// CORE-6・SEC-5・#2376)。
fn may_reap_halted(listing_incomplete: bool, retained: bool) -> bool {
    !listing_incomplete && !retained
}

/// 識別子つきの子を kill・回収せず保持すべきか。停止(またはゾンビ化)を確認できない、または子孫の列挙が不完全な
/// ときは、未列挙の helper の帰属を失わないよう保持する(CORE-2)。
fn must_retain_tagged(halted: bool, enumeration_incomplete: bool) -> bool {
    !halted || enumeration_incomplete
}

/// 未回収の子 `pid` へ `SIGSTOP` を送り、`/proc/<pid>/stat` の state が停止(`T` / `t`)かゾンビ(`Z`)になるまで
/// 期限つきで待つ(REPAIR-5)。どちらかを確認できたときだけ `true`(SIGSTOP は送達が停止完了を意味しない。CORE-2)。
///
/// ゾンビは回収しない(呼び出し側が子孫の帰属の錨として使う)。`ESRCH`(契約外の回収者が回収済み)・読み取り失敗・
/// 期限切れは `false`。
fn halt_and_confirm(pid: u32, timeout: Duration) -> bool {
    let Some(stop) = std::num::NonZeroU8::new(SIGSTOP_NUMBER) else {
        return false;
    };
    // `pid` は親が C の未回収の子(呼び出し側で確認済み)なので、回収まで pid は再利用されない。ゾンビへの
    // `kill(2)` は成功するが効かない(下の state で判定する)。
    if sys::kill_pid(pid, sys::Signal::Number(stop)).is_err() {
        return false;
    }
    let path = Path::new("/proc").join(pid.to_string()).join("stat");
    let deadline = std::time::Instant::now() + timeout.min(Duration::from_secs(2));
    loop {
        match read_proc_text(&path) {
            Ok(Some(stat)) => match proc_state_of(&stat) {
                Some('T' | 't' | 'Z') => return true,
                Some(_) => {}
                None => return false,
            },
            _ => return false,
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// `/proc/<pid>/stat` の state 文字(`comm` の括弧の後の最初のフィールド)。
fn proc_state_of(stat: &str) -> Option<char> {
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    rest.trim_start().chars().next()
}

/// `SIGSTOP` の番号(x86_64 / aarch64 共通の asm-generic。`sys::Signal::Number` と同じ前提)。
const SIGSTOP_NUMBER: u8 = 19;

/// `/proc/<pid>/stat` の親 pid とセッション ID(`comm` の括弧の後の state ppid pgrp session の 2 番目と 4 番目)。
fn parent_and_session_of(stat: &str) -> Option<(u32, u32)> {
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let parent = fields.nth(1)?.parse().ok()?;
    let session = fields.nth(1)?.parse().ok()?;
    Some((parent, session))
}

/// 錨 `anchor`(識別子つきの C の子)の子孫を `/proc` から列挙する(CORE-2)。
///
/// 対象は `anchor` 以外で「親が `anchor`」または「セッション ID が `anchor`」のプロセス。親が `anchor` でも C(`me`)
/// でもない子孫は、pid の安定(未回収であること)を保証できず kill できないため、列挙不完全として残す。列挙・読み取り・
/// 解析の失敗も `note_scan_failure` で残す(fail-closed)。
fn descendants_of(anchor: u32, me: u32, out: &mut Rescan) -> Vec<NonZeroU32> {
    descendants_in(Path::new("/proc"), anchor, me, out)
}

/// `descendants_of` の本体。`/proc` の場所を差し替えられる(試験が stat の fixture を渡して探索処理そのものを検証する。
/// REPAIR-12・#2394)。
fn descendants_in(proc_root: &Path, anchor: u32, me: u32, out: &mut Rescan) -> Vec<NonZeroU32> {
    const WHAT: &str = "cannot scan /proc for the descendants of a tagged process";
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        note_scan_failure(out, WHAT);
        return found;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            note_scan_failure(out, WHAT);
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
        if pid.get() == anchor {
            continue;
        }
        let path = proc_root.join(pid.get().to_string()).join("stat");
        let stat = match read_proc_text(&path) {
            Ok(Some(stat)) => stat,
            Ok(None) => continue,
            Err(_) => {
                note_scan_failure(out, WHAT);
                continue;
            }
        };
        // 終了処理中(state `X`/`x`)の task は ppid 0・pgrp/session -1 を返し、数値として解析できない。終了済みで
        // kill も回収も要らないため、消えたものと同じく列挙から外す(#2394。これを解析失敗として残すと、他の
        // プロセスの終了と重なっただけで列挙不完全になる)。
        if matches!(proc_state_of(&stat), Some('X' | 'x')) {
            continue;
        }
        // 終了処理中(`X` / `x`)のタスクはセッション ID を -1 と表示し解析できない。もう fork もユーザー空間への
        // 復帰もしないため、無関係なものとして除く(列挙不完全にしない)。
        if matches!(proc_state_of(&stat), Some('X' | 'x')) {
            continue;
        }
        match parent_and_session_of(&stat) {
            Some((parent, _)) if parent == anchor => found.push(pid),
            Some((parent, session)) if session == anchor => {
                if parent == me {
                    found.push(pid);
                } else {
                    note_scan_failure(
                        out,
                        "a descendant of a tagged process has an unexpected parent",
                    );
                }
            }
            Some(_) => {}
            None => note_scan_failure(out, WHAT),
        }
    }
    found
}

/// セッション `session` に属するプロセスが、期限内に全員終了した(ゾンビか、回収されて `/proc` から消えた)か
/// (CORE-6・SEC-5・#2376。REPAIR-5)。
///
/// rootless の範囲写像の失敗の後始末(`exec::stop_mapper_and_helpers`)が、mapper のグループへ `SIGKILL` を送った後、
/// holder を回収する前に helper(mapper のセッションを継承する)の終了を確かめるために使う。`SIGKILL` は送達と終了が
/// 同時でなく、実行中の syscall は `kill(2)` が戻った後も完了し得るため。呼び出し側は `session` が未回収の自分の子の
/// pid であること(セッション ID が再利用されない)を保証する。`/proc` の列挙・読み取り・解析に失敗したら `false`
/// (fail-closed)。
pub(super) fn session_members_exited(session: u32, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout.min(Duration::from_secs(2));
    loop {
        match session_has_live_member(session) {
            Some(false) => return true,
            Some(true) => {}
            None => return false,
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// セッション `session` に、ゾンビでないプロセスが居るか(`/proc` を 1 回走査する)。走査できなければ `None`。
fn session_has_live_member(session: u32) -> Option<bool> {
    for entry in std::fs::read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = match read_proc_text(&Path::new("/proc").join(pid.to_string()).join("stat")) {
            Ok(Some(stat)) => stat,
            // 走査中に消えた(回収された)。
            Ok(None) => continue,
            Err(_) => return None,
        };
        // 終了処理中(`X` / `x`)のタスクはセッション ID を -1 と表示し解析できないため、先に state で除く
        // (もうユーザー空間へ戻らない)。
        match proc_state_of(&stat)? {
            'X' | 'x' => continue,
            'Z' => continue,
            _ => {}
        }
        let (_, member_session) = parent_and_session_of(&stat)?;
        if member_session == session {
            return Some(true);
        }
    }
    Some(false)
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
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;

    // 規約(#2249): 複数スレッドの試験プロセスの fork 子から更に fork するときは flush しない版
    // (`fork_single_threaded_with_no_flush`)を使う。fork 子は他スレッドが握っていた stdout / stderr の
    // ロックを引き継ぐため、flush する版だと子の中で永久に止まり得る(本番の spawn_pid1・mapper も flush しない)。
    use super::*;

    /// 中間プロセス経路の setup 組み直しが sysctls を落とさない(CRI-2・CORE-3・SEC-1・#2670)。
    #[test]
    fn with_status_keeps_sysctl_plan() {
        let mut set = crate::sysctl::SysctlSet::new();
        set.insert(
            crate::sysctl::SysctlKey::parse("kernel.shmmax").unwrap(),
            crate::sysctl::SysctlValue::parse("16384").unwrap(),
        )
        .unwrap();
        let plan = crate::exec::sysctls::SysctlPlan::new(&set, crate::exec::NamespaceSet::all())
            .unwrap()
            .unwrap();
        let file = std::fs::File::open("/").unwrap();
        let setup = PrePivotSetup {
            config_paths: crate::exec::ConfigPaths::NONE,
            devices: crate::exec::DevptsGidSource::Rootful,
            tmpfs: None,
            inject: None,
            etc_files: None,
            binds: None,
            sysfs: None,
            sysctls: Some(&plan),
            pinned_rootfs: None,
            status: None,
            working_dir: None,
            root_readonly: true,
        };
        let out = with_status(setup, &file);
        assert!(out.sysctls.is_some());
        assert!(out.root_readonly);
        assert!(out.status.is_some());
    }

    use crate::audit_log::{AuditLayer, AuditRecord, AuditSink};
    use crate::exec::ViolationReason;
    use crate::exec::launch_status::{
        ExecPhaseStep, PrePivotFailure, PrePivotStep, report_exec_failure, report_exec_ready,
        report_exec_returned, report_failure, report_mount_identities, report_ready,
    };
    use crate::exec::process::ChildExit;
    use crate::traits::{ContainerId, TraitError};

    /// fork する試験を 1 本ずつ実行するための試験プロセス内の直列化ロック(#2394・CORE-6・REPAIR-12)。
    ///
    /// 試験は同じプロセスの複数スレッドで並列に走り、fork 子は fork 時点でプロセスが持つ全 fd の複製を引き継ぐ
    /// (CLOEXEC は exec でしか効かない)。別の試験の fork 子(120 秒眠る代役・mapper 等)が、いま EOF を待っている
    /// 試験の pipe の書き込み端(開始ゲート・報告 pipe)を複製して握り続けると、書き手を全部閉じても EOF が届かず、
    /// 期限切れや無期限の待ちになる(間欠失敗の原因。1/300 程度)。fd の寿命ごと排他にするため、fork を行う試験は
    /// 冒頭でこのロックを取り、終了まで保持する。本番の起動経路は単一スレッドで fd の寿命が重ならないため対象外。
    fn serialize_forks() -> std::sync::MutexGuard<'static, ()> {
        static FORK_SERIAL: Mutex<()> = Mutex::new(());
        // 別の試験が panic してもロックは有効にしておく(失敗が連鎖して原因を隠さない)。
        FORK_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

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
        for code in ErrorCode::ALL {
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
        /// 中間プロセスが識別子を継承した mapper 相当(自分のセッションを作り、識別子を持たない helper 相当を起動して
        /// 眠る)を残したまま、isolate の失敗(`R`)を報告して終了する(範囲写像の handshake 失敗。CORE-2・#2009)。
        /// テストへは helper と mapper の pid をこの順で渡す。
        IsolateFailsLeavingMapper,
    }

    /// 代役の PID 1 を fork し、その pid をテストへ渡す(`pid_write`)。
    fn fork_stand_in(
        status: &std::fs::File,
        pid_write: &std::fs::File,
        body: impl FnOnce(&std::fs::File) -> i32,
    ) -> u32 {
        let pid =
            sys::fork_single_threaded_with_no_flush(|| true, || body(status), EXIT_SETUP_FAILED)
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
        // 警告の出力先は試験プロセスの stderr にせず(libtest の出力を汚さない)、読まれない socketpair にする。
        let (out_tx, _out_rx) = UnixStream::pair().unwrap();
        run_with(
            behavior,
            timeout,
            crate::legacy_tiocsti::LegacyTiocsti::Absent,
            out_tx.as_fd(),
        )
    }

    /// [`run`] に `dev.tty.legacy_tiocsti` の観測値と警告の出力先を足した本体(#2008)。
    fn run_with(
        behavior: Behavior,
        timeout: Duration,
        legacy: crate::legacy_tiocsti::LegacyTiocsti,
        legacy_out: BorrowedFd<'_>,
    ) -> (
        Result<ContainerChild, Box<PreparedLaunchFailure>>,
        VecSink,
        Option<u32>,
    ) {
        let (result, sink, pids) = run_with_pids(behavior, timeout, legacy, legacy_out, 1);
        (result, sink, pids.first().copied())
    }

    /// [`run`] の、代役が渡す pid を `count` 個まで読む版(複数の代役の消滅を照合する試験用)。
    fn run_pids(
        behavior: Behavior,
        timeout: Duration,
        count: usize,
    ) -> (
        Result<ContainerChild, Box<PreparedLaunchFailure>>,
        VecSink,
        Vec<u32>,
    ) {
        let (out_tx, _out_rx) = UnixStream::pair().unwrap();
        run_with_pids(
            behavior,
            timeout,
            crate::legacy_tiocsti::LegacyTiocsti::Absent,
            out_tx.as_fd(),
            count,
        )
    }

    /// 識別子を継承した mapper 相当を fork する。mapper 相当は自分のセッションを作り(`isolate_rootless_subordinate_with`
    /// と同じ)、識別子を持たない helper 相当を起動して眠る。helper 相当は自分と mapper の pid を `pid_write` へ書き、
    /// `ready_w` へ 1 バイト書いて眠る。
    fn fork_mapper_with_helper(
        pid_write: &std::fs::File,
        ready_w: &std::io::PipeWriter,
    ) -> Result<u32, sys::SysError> {
        sys::fork_single_threaded_with_no_flush(
            || true,
            || {
                if sys::new_session().is_err() {
                    return EXIT_SETUP_FAILED;
                }
                let helper = sys::fork_single_threaded_with_no_flush(
                    || true,
                    || {
                        if sys::set_process_comm(b"notatag-helper\0\0").is_err() {
                            return EXIT_SETUP_FAILED;
                        }
                        let mut buf = [0u8; 8];
                        buf[..4].copy_from_slice(&std::process::id().to_le_bytes());
                        buf[4..]
                            .copy_from_slice(&std::os::unix::process::parent_id().to_le_bytes());
                        let mut w = pid_write;
                        let _ = w.write_all(&buf);
                        let mut r = ready_w;
                        let _ = r.write_all(b"R");
                        std::thread::sleep(Duration::from_secs(120));
                        0
                    },
                    EXIT_SETUP_FAILED,
                );
                if helper.is_err() {
                    return EXIT_SETUP_FAILED;
                }
                std::thread::sleep(Duration::from_secs(120));
                0
            },
            EXIT_SETUP_FAILED,
        )
    }

    /// [`run_with`] の本体。代役が `pid_write` へ書く pid を `count` 個まで読む。
    fn run_with_pids(
        behavior: Behavior,
        timeout: Duration,
        legacy: crate::legacy_tiocsti::LegacyTiocsti,
        legacy_out: BorrowedFd<'_>,
        count: usize,
    ) -> (
        Result<ContainerChild, Box<PreparedLaunchFailure>>,
        VecSink,
        Vec<u32>,
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
            |status, report, gate_r, _listener_end, _netns_end| {
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
                    Behavior::IsolateFailsLeavingMapper => {
                        sys::set_process_comm(tag.comm_bytes()).expect("set the tag");
                        let (mut ready_r, ready_w) = std::io::pipe().expect("ready pipe");
                        let mapper = fork_mapper_with_helper(&pid_write, &ready_w);
                        drop(ready_w);
                        if mapper.is_err() {
                            return EXIT_SETUP_FAILED;
                        }
                        // helper が起動してから失敗を報告する(helper が居る状態の回収を照合する)。
                        let mut mark = [0u8; 1];
                        let _ = ready_r.read_exact(&mut mark);
                        send_report(
                            report,
                            &IntermediateReport::Failed {
                                code: ErrorCode::PermissionDenied,
                                phase: IntermediatePhase::Isolate,
                            },
                        );
                        return EXIT_SETUP_FAILED;
                    }
                }
                0
            },
            None,
            None,
            &subreaper,
            audit,
            timeout,
            &tag,
            (legacy, legacy_out),
        )
        .map(|launched| launched.child);
        drop(pid_write);
        let mut seen = Vec::new();
        let mut buf = [0u8; 4];
        while seen.len() < count && pid_read.read_exact(&mut buf).is_ok() {
            seen.push(u32::from_le_bytes(buf));
        }
        (result, sink, seen)
    }

    /// listener の受け渡しの試験で、代役の PID 1(または中間プロセス)が取る動作。
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Handoff {
        /// 実 listener を載せて送り、ACK を待って exec 前の `R` を書き、0 で終了する(正常)。
        Good,
        /// ACK の後に entrypoint 系の違反 `E ... entrypoint_is_runtime_binary` を書いて終了する(SEC-4・#2624)。
        ExecViolation,
        /// ACK の後に理由なしの失敗 `E verify_root NOT_FOUND -` を書いて終了する(記録されない)。
        ExecFailureWithoutReason,
        /// ACK の後に許可リスト外の理由(`E open_entrypoint PERMISSION_DENIED target_moved`)を書いて終了する(`Malformed`)。
        ExecForeignReason,
        /// ACK の後に共有外の exec の段(`E parent_lifetime INTERNAL -`)を書いて終了する(`Malformed`。#2895)。
        ExecForeignStep,
        /// ACK の後に 2 行目を書かずに終了する(EOF)。
        ExecSilentExit,
        /// ACK の後に 2 行目を書かずに眠る(期限切れ)。
        ExecSilentSleep,
        /// ACK の後に `R` と `X NOT_FOUND` を書いて終了する(`execveat` が errno で失敗。起動失敗・記録なし。#2716)。
        ExecReturned,
        /// ACK の後に `R` を書き、書き込み側を持ったまま眠る(EOF が来ない。期限切れで失敗・回収。#2716)。
        ExecReadyThenSleep,
        /// `P` を報告して何も送らずに終了する(EOF で即時に失敗するはず)。
        NoSend,
        /// `P` を報告し、listener を送らずに Landlock 段の照合の違反 `E landlock ... landlock_mount_not_root` を書いて
        /// 終了する(seccomp より前の Landlock 段の失敗。SEC-4・#2130)。
        LandlockViolation,
        /// 上と同じだが、違反の理由なしの `E landlock UNIMPLEMENTED -` を書く(記録されない)。
        LandlockWithoutReason,
        /// listener ではない fd(pipe)を送る(種別の不一致)。
        WrongFd,
        /// PID 1 ではなく中間プロセスが listener を送る(送信元 pid の不一致)。
        WrongSender,
        /// listener を得る前の適用失敗(`EBUSY` 相当の `FailedPrecondition`)を構造化して送り、0 で終了する。
        ReportBusy,
        /// `P` の直後に Mount 由来のルール 2 本(位置 1・3)の識別子のブロックを書き、`Good` と同じに進む(#3201)。
        MountIdentitiesGood,
        /// 上と同じだが、2 本目のルール位置が期待(3)と食い違う 4 を書く(`Malformed`。listener は受け取らない)。
        MountIdentitiesWrongRule,
    }

    /// `MountIdentitiesGood` が書く識別子(位置 1・3)。
    fn fake_mount_identities() -> Vec<(usize, RecordedMountIdentity)> {
        vec![
            (1, RecordedMountIdentity::new(11, 2, 3, false).unwrap()),
            (3, RecordedMountIdentity::new(13, 4, 5, true).unwrap()),
        ]
    }

    /// 実 listener を載せた状態の fd を作る(forked 単一スレッドの子の中でだけ呼ぶ。filter は子に残る)。
    fn child_listener() -> std::os::fd::OwnedFd {
        assert_eq!(sys::set_no_new_privs(), Ok(()));
        let p = crate::seccomp::build_filter_for_target_arch().expect("filter");
        sys::seccomp_notify::seccomp_set_filter_new_listener(&p).expect("listener")
    }

    /// `with_listener = true` で起動し、結果と所要時間を返す。
    fn run_handoff(
        mode: Handoff,
        timeout: Duration,
    ) -> (
        Result<LaunchedChild, Box<PreparedLaunchFailure>>,
        Duration,
        u32,
    ) {
        let (result, elapsed, pid1, _records) = run_handoff_audited(mode, timeout);
        (result, elapsed, pid1)
    }

    /// [`run_handoff`] に、C が sink へ記録したレコードを足した版(SEC-4・#2624)。
    fn run_handoff_audited(
        mode: Handoff,
        timeout: Duration,
    ) -> (
        Result<LaunchedChild, Box<PreparedLaunchFailure>>,
        Duration,
        u32,
        Vec<AuditRecord>,
    ) {
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let (mut pid_read, pid_write) = std::io::pipe().unwrap();
        let pid_write = std::fs::File::from(std::os::fd::OwnedFd::from(pid_write));
        let sink = VecSink(Mutex::new(Vec::new()));
        let id = ContainerId::new("c2024").unwrap();
        let audit = LaunchAudit {
            sink: &sink,
            container: Some(&id),
        };
        let (out_tx, _out_rx) = UnixStream::pair().unwrap();
        let tag = LaunchTag::fresh();
        let started = Instant::now();
        let result = launch_via_intermediate(
            || true,
            |status, report, gate_r, listener_end, _netns_end| {
                let end = listener_end.try_clone().expect("dup");
                let pid1 = fork_stand_in(status, &pid_write, move |s| {
                    if await_start_gate(gate_r, Duration::from_secs(10)).is_err() {
                        return EXIT_SETUP_FAILED;
                    }
                    let _ = report_ready(s);
                    // `P` の直後に識別子のブロックを書く(`NoSend` は書かずに終了する。#3201)。
                    let block = match mode {
                        Handoff::NoSend => None,
                        Handoff::MountIdentitiesGood => Some(fake_mount_identities()),
                        Handoff::MountIdentitiesWrongRule => {
                            let mut ids = fake_mount_identities();
                            ids[1].0 = 4;
                            Some(ids)
                        }
                        _ => Some(Vec::new()),
                    };
                    if let Some(entries) = block {
                        let _ = report_mount_identities(s, &entries);
                    }
                    let sender = ListenerSender::new(end);
                    match mode {
                        Handoff::Good
                        | Handoff::MountIdentitiesGood
                        | Handoff::MountIdentitiesWrongRule => {
                            match sender.hand_over(child_listener(), Duration::from_secs(10)) {
                                Ok(()) => {
                                    let _ = report_exec_ready(s);
                                    0
                                }
                                Err(_) => 3,
                            }
                        }
                        Handoff::ExecViolation
                        | Handoff::ExecFailureWithoutReason
                        | Handoff::ExecForeignReason
                        | Handoff::ExecForeignStep
                        | Handoff::ExecSilentExit
                        | Handoff::ExecSilentSleep
                        | Handoff::ExecReturned
                        | Handoff::ExecReadyThenSleep => {
                            if sender
                                .hand_over(child_listener(), Duration::from_secs(10))
                                .is_err()
                            {
                                return 3;
                            }
                            let mut w = s;
                            match mode {
                                Handoff::ExecViolation => {
                                    let _ = report_exec_failure(
                                        s,
                                        ExecPhaseStep::Child(
                                            crate::exec::ExecChildStep::OpenEntrypoint,
                                        ),
                                        &ExecError::from_violation_at(
                                            ViolationReason::EntrypointIsRuntimeBinary,
                                            None,
                                            IsolationStage::Exec,
                                        ),
                                    );
                                }
                                Handoff::ExecFailureWithoutReason => {
                                    let _ = report_exec_failure(
                                        s,
                                        ExecPhaseStep::VerifyRoot,
                                        &ExecError::new(
                                            ErrorCode::NotFound,
                                            IsolationStage::Exec,
                                            "not found",
                                        ),
                                    );
                                }
                                Handoff::ExecReturned => {
                                    let _ = report_exec_ready(s);
                                    let _ = report_exec_returned(s, ErrorCode::NotFound);
                                }
                                Handoff::ExecReadyThenSleep => {
                                    let _ = report_exec_ready(s);
                                }
                                Handoff::ExecForeignStep => {
                                    let _ = w.write_all(b"E parent_lifetime INTERNAL -\n");
                                }
                                Handoff::ExecForeignReason => {
                                    let _ = w.write_all(
                                        b"E open_entrypoint PERMISSION_DENIED target_moved\n",
                                    );
                                }
                                _ => {}
                            }
                            // 実際の子は `E` を書いた後に終了する(親は EOF まで読む。#2716)。眠るのは無報告の試験だけ。
                            if matches!(
                                mode,
                                Handoff::ExecSilentSleep | Handoff::ExecReadyThenSleep
                            ) {
                                std::thread::sleep(Duration::from_secs(120));
                            }
                            0
                        }
                        Handoff::NoSend | Handoff::WrongSender => 0,
                        Handoff::LandlockViolation => {
                            let _ = report_exec_failure(
                                s,
                                ExecPhaseStep::Landlock,
                                &ExecError::from_violation_at(
                                    ViolationReason::LandlockMountNotRoot,
                                    None,
                                    IsolationStage::Landlock,
                                ),
                            );
                            0
                        }
                        Handoff::LandlockWithoutReason => {
                            let _ = report_exec_failure(
                                s,
                                ExecPhaseStep::Landlock,
                                &ExecError::new(
                                    ErrorCode::Unimplemented,
                                    IsolationStage::Landlock,
                                    "unavailable",
                                ),
                            );
                            0
                        }
                        Handoff::ReportBusy => {
                            sender.report_failure(&ExecError::new(
                                ErrorCode::FailedPrecondition,
                                IsolationStage::Seccomp,
                                "busy",
                            ));
                            0
                        }
                        Handoff::WrongFd => {
                            let (r, _w) = std::io::pipe().expect("pipe");
                            match sender
                                .hand_over(std::os::fd::OwnedFd::from(r), Duration::from_secs(5))
                            {
                                Ok(()) => 0,
                                Err(_) => 3,
                            }
                        }
                    }
                });
                send_report(report, &IntermediateReport::Pid1(pid(pid1)));
                if mode == Handoff::WrongSender {
                    // 中間プロセス(PID 1 とは別の pid)が送る。送信後に終了するので、C は回収した後でも読める。
                    let (r, _w) = std::io::pipe().expect("pipe");
                    let _ = sys::seccomp_notify::send_fd_with_token(
                        listener_end.as_fd(),
                        b'L',
                        std::os::fd::OwnedFd::from(r).as_fd(),
                    );
                }
                0
            },
            Some(match mode {
                Handoff::MountIdentitiesGood | Handoff::MountIdentitiesWrongRule => &[1, 3],
                _ => &[],
            }),
            None,
            &subreaper,
            audit,
            timeout,
            &tag,
            (crate::legacy_tiocsti::LegacyTiocsti::Absent, out_tx.as_fd()),
        );
        let elapsed = started.elapsed();
        drop(pid_write);
        let mut buf = [0u8; 4];
        let _ = pid_read.read_exact(&mut buf);
        let records = sink.0.lock().unwrap().clone();
        (result, elapsed, u32::from_le_bytes(buf), records)
    }

    /// SEC-4・#2624: PID 1 が exec 前に返す entrypoint 系の違反(`E`)は、C が層 `entrypoint` に 1 件だけ記録し、
    /// 起動失敗にして PID 1 を回収する。
    #[test]
    fn sec4_2624_launch_records_entrypoint_violation_and_reaps_pid1() {
        let _serial = serialize_forks();
        let (result, _, pid1, records) =
            run_handoff_audited(Handoff::ExecViolation, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::PermissionDenied);
        assert_eq!(failure.rejection.error.stage, IsolationStage::Exec);
        assert_eq!(
            failure
                .rejection
                .error
                .violation
                .as_ref()
                .map(|v| v.reason.as_str()),
            Some("entrypoint_is_runtime_binary")
        );
        assert_eq!(
            failure.rejection.delivery,
            crate::audit_log::AuditDelivery::Recorded
        );
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].layer(), AuditLayer::Entrypoint);
        assert_eq!(
            records[0].reason().map(|r| r.as_str()),
            Some("entrypoint_is_runtime_binary")
        );
        assert_eq!(records[0].path(), None);
    }

    /// SEC-4・#2624: 理由なしの失敗(`E verify_root NOT_FOUND -`)は起動失敗にするが記録しない。
    #[test]
    fn sec4_2624_launch_fails_without_record_for_reasonless_exec_failure() {
        let _serial = serialize_forks();
        let (result, _, pid1, records) =
            run_handoff_audited(Handoff::ExecFailureWithoutReason, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::NotFound);
        assert_eq!(failure.rejection.error.stage, IsolationStage::Exec);
        assert_eq!(
            failure.rejection.error.message,
            "exec phase step 'verify_root' failed in the container child"
        );
        assert_eq!(
            failure.rejection.delivery,
            crate::audit_log::AuditDelivery::NotApplicable
        );
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
        assert!(records.is_empty());
    }

    /// SEC-4・#2624: 許可リスト外の理由・2 行目の欠落(EOF)・期限切れは、記録せずに起動失敗にして PID 1 を回収する
    /// (fail-closed。REPAIR-5)。
    #[test]
    fn sec4_2624_launch_fails_closed_on_malformed_missing_or_late_exec_phase() {
        let _serial = serialize_forks();
        for (mode, timeout, message) in [
            (
                Handoff::ExecForeignReason,
                Duration::from_secs(20),
                "the pre-pivot status is malformed",
            ),
            (
                // exec と共有しない段(#2895)は語彙外として拒否する。
                Handoff::ExecForeignStep,
                Duration::from_secs(20),
                "the pre-pivot status is malformed",
            ),
            (
                Handoff::ExecSilentExit,
                Duration::from_secs(20),
                "the container child exited before reporting the pre-pivot status",
            ),
            (
                Handoff::ExecSilentSleep,
                Duration::from_secs(4),
                "timed out waiting for the pre-pivot status",
            ),
        ] {
            let (result, elapsed, pid1, records) = run_handoff_audited(mode, timeout);
            let failure = result.expect_err("must fail");
            assert_eq!(failure.rejection.error.message, message);
            assert_eq!(
                failure.rejection.delivery,
                crate::audit_log::AuditDelivery::NotApplicable
            );
            assert!(failure.unreaped.is_empty());
            assert!(gone(pid1));
            assert!(records.is_empty());
            assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
        }
    }

    /// SEC-4・#2716: `R` の後の `execveat` の失敗(`X`)は、記録なしの起動失敗で PID 1 を回収する。`R` の後に EOF が
    /// 来なければ(書き込み側を保持したまま停止)期限切れで失敗にして回収する(REPAIR-5)。
    #[test]
    fn sec4_2716_launch_fails_on_execveat_failure_after_ready_and_on_silence_after_ready() {
        let _serial = serialize_forks();
        let (result, elapsed, pid1, records) =
            run_handoff_audited(Handoff::ExecReturned, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::NotFound);
        assert_eq!(failure.rejection.error.stage, IsolationStage::Exec);
        assert_eq!(
            failure.rejection.error.message,
            "the entrypoint execveat failed in the container child"
        );
        assert_eq!(
            failure.rejection.delivery,
            crate::audit_log::AuditDelivery::NotApplicable
        );
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
        assert!(records.is_empty());
        assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");

        let (result, elapsed, pid1, records) =
            run_handoff_audited(Handoff::ExecReadyThenSleep, Duration::from_secs(4));
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Timeout);
        assert_eq!(
            failure.rejection.error.message,
            "timed out waiting for the pre-pivot status"
        );
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
        assert!(records.is_empty());
        assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
    }

    /// SEC-1・SEC-4・#3201: `P` の直後に子が返した Mount 由来のルールの識別子が、期待列(位置 1・3)と一致すれば
    /// `LaunchedChild::mount_identities` に載る。位置が期待と食い違えば listener を受け取らず PID 1 を回収して
    /// 起動失敗にする(fail-closed)。
    #[test]
    fn sec1_3201_launch_carries_mount_identities_and_rejects_a_mismatch() {
        let _serial = serialize_forks();
        let (result, _, _) = run_handoff(Handoff::MountIdentitiesGood, Duration::from_secs(20));
        let launched = result.expect("launch must succeed");
        assert_eq!(launched.mount_identities, fake_mount_identities());
        assert!(launched.listener.is_some());

        let (result, _, pid1, records) =
            run_handoff_audited(Handoff::MountIdentitiesWrongRule, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(
            failure.rejection.error.message,
            "the pre-pivot status is malformed"
        );
        assert_eq!(
            failure.rejection.delivery,
            crate::audit_log::AuditDelivery::NotApplicable
        );
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
        assert!(records.is_empty());
    }

    /// SEC-4・#2024: PID 1 が載せた実 listener を C が受け取り、種別・close-on-exec を満たす。PID 1 は ACK を
    /// 受けて 0 で終了する。
    #[test]
    fn sec4_2024_launch_receives_a_verified_listener_and_acks() {
        let _serial = serialize_forks();
        let (result, _, _) = run_handoff(Handoff::Good, Duration::from_secs(20));
        let launched = result.expect("launch must succeed");
        let listener = launched.listener.expect("listener");
        let kind =
            std::fs::read_link(format!("/proc/self/fd/{}", listener.as_fd().as_raw_fd())).unwrap();
        assert_eq!(kind.to_str(), Some("anon_inode:seccomp notify"));
        // PID 1 は hand_over の ACK を受けた場合だけ 0 で終了する(失敗は 3)。
        assert_eq!(
            launched
                .child
                .wait_for_exit(Duration::from_secs(10))
                .unwrap(),
            Some(ChildExit::Exited(0))
        );
    }

    /// SEC-4・REPAIR-5・#2024: PID 1 が送らずに終了すると、C は期限(20 秒)を待たず EOF で起動を失敗させる。
    #[test]
    fn sec4_2024_launch_fails_fast_when_the_listener_never_arrives() {
        let _serial = serialize_forks();
        let (result, elapsed, _) = run_handoff(Handoff::NoSend, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Internal);
        assert_eq!(failure.rejection.error.stage, IsolationStage::Spawn);
        assert!(failure.unreaped.is_empty());
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    }

    /// SEC-4・SEC-1・CORE-5・#2130: seccomp より前の Landlock 段の照合の違反は、listener の EOF に潰れず、層 `mount`・
    /// 段 `landlock` の記録が 1 件残る。PID 1 は回収される。
    #[test]
    fn sec4_2130_launch_records_landlock_violation_after_sender_closed() {
        let _serial = serialize_forks();
        let (result, _, pid1, records) =
            run_handoff_audited(Handoff::LandlockViolation, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(
            failure.rejection.delivery,
            crate::audit_log::AuditDelivery::Recorded
        );
        assert_eq!(failure.rejection.error.stage, IsolationStage::Landlock);
        assert_eq!(
            failure
                .rejection
                .error
                .violation
                .as_ref()
                .map(|v| v.reason.as_str()),
            Some("landlock_mount_not_root")
        );
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].layer(), crate::audit_log::AuditLayer::Mount);
        assert_eq!(records[0].path(), None);
        assert_eq!(
            records[0].reason().map(|r| r.as_str()),
            Some("landlock_mount_not_root")
        );
    }

    /// SEC-4・#2130: 理由なしの Landlock 段の失敗は記録せず、段 `Landlock` の失敗のまま(`NotApplicable`)。
    /// 何も書かずに終わった場合(`NoSend`)は従来の EOF 由来の `Internal`・段 `Seccomp` のまま記録なし。
    #[test]
    fn sec4_2130_landlock_failure_without_reason_and_silent_exit_are_not_recorded() {
        let _serial = serialize_forks();
        let (result, _, pid1, records) =
            run_handoff_audited(Handoff::LandlockWithoutReason, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(
            failure.rejection.delivery,
            crate::audit_log::AuditDelivery::NotApplicable
        );
        assert_eq!(failure.rejection.error.code, ErrorCode::Unimplemented);
        assert_eq!(failure.rejection.error.stage, IsolationStage::Landlock);
        assert!(gone(pid1));
        assert!(records.is_empty());

        let (result, _, _, records) = run_handoff_audited(Handoff::NoSend, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(
            failure.rejection.delivery,
            crate::audit_log::AuditDelivery::NotApplicable
        );
        assert_eq!(failure.rejection.error.code, ErrorCode::Internal);
        assert_eq!(failure.rejection.error.stage, IsolationStage::Spawn);
        assert!(records.is_empty());
    }

    /// SEC-4・#2024: listener 取得前の適用失敗(祖先に listener がある `EBUSY`)は EOF 由来の `Internal` に潰れず、
    /// 段 `Seccomp` の `FailedPrecondition` として C に復元され、PID 1 は回収される。
    #[test]
    fn sec4_2024_launch_restores_failed_precondition_from_pre_listener_failure() {
        let _serial = serialize_forks();
        let (result, elapsed, pid1) = run_handoff(Handoff::ReportBusy, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::FailedPrecondition);
        assert_eq!(failure.rejection.error.stage, IsolationStage::Seccomp);
        assert_eq!(
            failure.rejection.error.message,
            "seccomp listener unavailable: an ancestor filter already has a listener, or the process state forbids it"
        );
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
        assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    }

    /// SEC-4・#2024: listener ではない fd を送ると拒否され、PID 1 は回収される(ACK は返らない)。
    #[test]
    fn sec4_2024_launch_rejects_a_non_listener_fd_and_reaps_pid1() {
        let _serial = serialize_forks();
        let (result, _, pid1) = run_handoff(Handoff::WrongFd, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(
            failure.rejection.error.message,
            "the received fd is not a seccomp notification fd"
        );
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
    }

    /// SEC-4・#2024: PID 1 以外の送信元(pid の不一致)からの fd は拒否される。
    #[test]
    fn sec4_2024_launch_rejects_a_sender_other_than_pid1() {
        let _serial = serialize_forks();
        let (result, _, pid1) = run_handoff(Handoff::WrongSender, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(
            failure.rejection.error.message,
            "the listener message came from an unexpected process"
        );
        assert!(gone(pid1));
    }

    /// 回収済みなら `/proc/<pid>` は残らない(ゾンビも残さない)。
    /// 期限つきで `buf` を読み切る(期限なしのブロッキング読みでハングさせない。REPAIR-5)。
    fn read_within(r: &mut std::io::PipeReader, buf: &mut [u8], timeout: Duration) {
        use std::io::Read;
        use std::os::fd::AsFd;
        let deadline = std::time::Instant::now() + timeout;
        let mut got = 0;
        while got < buf.len() {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!left.is_zero(), "the child was not ready in time");
            let ms = i32::try_from(left.as_millis()).unwrap_or(i32::MAX);
            if !sys::poll_readable(r.as_fd(), ms).expect("poll") {
                continue;
            }
            let n = r.read(&mut buf[got..]).expect("read");
            assert!(n > 0, "the child closed the pipe before reporting");
            got += n;
        }
    }

    /// 識別子を設定し、自分のセッションを作って子孫を起動する代役(mapper 相当)を fork する。`body` は代役の中で
    /// 子孫を作り、pid をテストへ渡す。
    fn fork_tagged_session_leader(tag: LaunchTag, body: impl FnOnce() -> i32) -> u32 {
        sys::fork_single_threaded_with_no_flush(
            || true,
            || {
                if sys::set_process_comm(tag.comm_bytes()).is_err() || sys::new_session().is_err() {
                    return EXIT_SETUP_FAILED;
                }
                body()
            },
            EXIT_SETUP_FAILED,
        )
        .expect("fork the tagged process")
    }

    fn wait_state(pid: u32, state: char) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .is_ok_and(|s| proc_state_of(&s) == Some(state))
        {
            assert!(
                Instant::now() < deadline,
                "{pid} did not reach state {state}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn parent_of(pid: u32) -> Option<u32> {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| parent_pid_of(&s))
    }

    /// CORE-2(#2009・Codex P1): 識別子つきの mapper が helper を残して終了した(ゾンビ化し、helper は C へ再親付け
    /// された)場合でも、再探索は mapper のゾンビを錨として回収せずに保ち、セッション ID で helper を特定して kill・
    /// 回収してから mapper を回収する(識別子の消失で Clean に進まない)。
    #[test]
    fn core2_exited_mapper_still_anchors_its_orphaned_helper() {
        let _serial = serialize_forks();
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let tag = LaunchTag::fresh();
        let (mut ready_read, ready_write) = std::io::pipe().unwrap();
        let ready_write = std::fs::File::from(std::os::fd::OwnedFd::from(ready_write));
        let mapper = fork_tagged_session_leader(tag, || {
            let helper = sys::fork_single_threaded_with_no_flush(
                || true,
                || {
                    if sys::set_process_comm(b"notatag-helper\0\0").is_err() {
                        return EXIT_SETUP_FAILED;
                    }
                    let mut w = &ready_write;
                    let _ = w.write_all(&std::process::id().to_le_bytes());
                    std::thread::sleep(Duration::from_secs(120));
                    0
                },
                EXIT_SETUP_FAILED,
            );
            if helper.is_err() {
                return EXIT_SETUP_FAILED;
            }
            // helper を残して終了する(helper は C へ再親付けされる)。
            0
        });
        drop(ready_write);
        let mut buf = [0u8; 4];
        read_within(&mut ready_read, &mut buf, Duration::from_secs(10));
        let helper = u32::from_le_bytes(buf);
        wait_state(mapper, 'Z');
        // helper は mapper の終了で C(この試験プロセス)へ再親付けされ、識別子も親子関係も持たない。
        let me = std::process::id();
        let deadline = Instant::now() + Duration::from_secs(10);
        while parent_of(helper) != Some(me) {
            assert!(
                Instant::now() < deadline,
                "the helper {helper} was not reparented"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let found = rescan_unreported_init(&tag, &subreaper, Duration::from_secs(5));
        assert!(found.is_clean(), "{found:?}");
        assert!(!found.scan_incomplete, "{found:?}");
        assert!(gone(helper), "the orphaned helper {helper} must be reaped");
        assert!(gone(mapper), "the exited mapper {mapper} must be reaped");
    }

    /// CORE-2(#2009): pid の安定を保証できない子孫(helper の子)が居る間は、識別子つきの子も子孫も kill・回収
    /// せずに保持し(`unreaped` に入れない)、`scan_incomplete` と `error` で再探索を要求する。次の再探索も同じ錨を
    /// 見つける(識別子の不在で解除されない)。
    #[test]
    fn core2_tagged_process_with_unlisted_descendant_is_kept_across_rescans() {
        let _serial = serialize_forks();
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let tag = LaunchTag::fresh();
        let (mut ready_read, ready_write) = std::io::pipe().unwrap();
        let ready_write = std::fs::File::from(std::os::fd::OwnedFd::from(ready_write));
        let mapper = fork_tagged_session_leader(tag, || {
            let helper = sys::fork_single_threaded_with_no_flush(
                || true,
                || {
                    if sys::set_process_comm(b"notatag-helper\0\0").is_err() {
                        return EXIT_SETUP_FAILED;
                    }
                    let grandchild = sys::fork_single_threaded_with_no_flush(
                        || true,
                        || {
                            let _ = sys::set_process_comm(b"notatag-grand\0\0\0");
                            let mut buf = [0u8; 8];
                            buf[..4].copy_from_slice(
                                &std::os::unix::process::parent_id().to_le_bytes(),
                            );
                            buf[4..].copy_from_slice(&std::process::id().to_le_bytes());
                            let mut w = &ready_write;
                            let _ = w.write_all(&buf);
                            std::thread::sleep(Duration::from_secs(120));
                            0
                        },
                        EXIT_SETUP_FAILED,
                    );
                    if grandchild.is_err() {
                        return EXIT_SETUP_FAILED;
                    }
                    std::thread::sleep(Duration::from_secs(120));
                    0
                },
                EXIT_SETUP_FAILED,
            );
            if helper.is_err() {
                return EXIT_SETUP_FAILED;
            }
            std::thread::sleep(Duration::from_secs(120));
            0
        });
        drop(ready_write);
        let mut buf = [0u8; 8];
        read_within(&mut ready_read, &mut buf, Duration::from_secs(10));
        let helper = u32::from_le_bytes(buf[..4].try_into().unwrap());
        let grandchild = u32::from_le_bytes(buf[4..].try_into().unwrap());
        for _ in 0..2 {
            let found = rescan_unreported_init(&tag, &subreaper, Duration::from_secs(1));
            assert!(found.unreaped.is_empty(), "{found:?}");
            assert!(found.scan_incomplete, "{found:?}");
            assert_eq!(
                found.error.as_ref().map(|e| e.message.as_str()),
                Some("a descendant of a tagged process has an unexpected parent"),
                "{found:?}"
            );
            assert!(!gone(mapper) && !gone(helper) && !gone(grandchild));
        }
        // 後始末: 孫 → helper の順に止め、mapper を回収してから再親付けされた子孫を回収する。
        let _ = sys::kill_pid(grandchild, sys::Signal::Kill);
        let _ = sys::kill_pid(helper, sys::Signal::Kill);
        wait_state(helper, 'Z');
        let anchor = ContainerChild::adopt_reparented(NonZeroU32::new(mapper).unwrap(), &subreaper);
        anchor
            .kill_and_reap(Duration::from_secs(5))
            .expect("reap the mapper");
        for pid in [helper, grandchild] {
            let child = ContainerChild::adopt_reparented(NonZeroU32::new(pid).unwrap(), &subreaper);
            child
                .kill_and_reap(Duration::from_secs(5))
                .expect("reap a descendant");
        }
    }

    /// CORE-6・SEC-5・CORE-2(#2376): 同じ識別子の候補のうち 1 つでも保持(子孫の列挙不完全)になれば、子孫を持たない
    /// 候補(holder 相当)も回収しない。helper は holder を pid の数値で受け取るため、helper を止めたと言えない間に
    /// holder を回収して pid を解放しない。保持した候補は停止したまま残り、`scan_incomplete` で再探索を要求する。
    #[test]
    fn core6_rescan_keeps_holder_while_another_candidate_is_retained() {
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let tag = LaunchTag::fresh();
        let (mut ready_read, ready_write) = std::io::pipe().unwrap();
        let ready_write = std::fs::File::from(std::os::fd::OwnedFd::from(ready_write));
        // holder 相当: 識別子を持ち、子孫を持たない。
        let holder = fork_tagged_session_leader(tag, || {
            std::thread::sleep(Duration::from_secs(120));
            0
        });
        // mapper 相当: helper の下に pid の安定を保証できない孫が居る(列挙不完全で保持される)。
        let mapper = fork_tagged_session_leader(tag, || {
            let helper = sys::fork_single_threaded_with_no_flush(
                || true,
                || {
                    if sys::set_process_comm(b"notatag-helper\0\0").is_err() {
                        return EXIT_SETUP_FAILED;
                    }
                    let grandchild = sys::fork_single_threaded_with_no_flush(
                        || true,
                        || {
                            let _ = sys::set_process_comm(b"notatag-grand\0\0\0");
                            let mut buf = [0u8; 8];
                            buf[..4].copy_from_slice(
                                &std::os::unix::process::parent_id().to_le_bytes(),
                            );
                            buf[4..].copy_from_slice(&std::process::id().to_le_bytes());
                            let mut w = &ready_write;
                            let _ = w.write_all(&buf);
                            std::thread::sleep(Duration::from_secs(120));
                            0
                        },
                        EXIT_SETUP_FAILED,
                    );
                    if grandchild.is_err() {
                        return EXIT_SETUP_FAILED;
                    }
                    std::thread::sleep(Duration::from_secs(120));
                    0
                },
                EXIT_SETUP_FAILED,
            );
            if helper.is_err() {
                return EXIT_SETUP_FAILED;
            }
            std::thread::sleep(Duration::from_secs(120));
            0
        });
        drop(ready_write);
        let mut buf = [0u8; 8];
        read_within(&mut ready_read, &mut buf, Duration::from_secs(10));
        let helper = u32::from_le_bytes(buf[..4].try_into().unwrap());
        let grandchild = u32::from_le_bytes(buf[4..].try_into().unwrap());
        let found = rescan_unreported_init(&tag, &subreaper, Duration::from_secs(1));
        assert!(found.unreaped.is_empty(), "{found:?}");
        assert!(found.scan_incomplete, "{found:?}");
        assert_eq!(
            found.error.as_ref().map(|e| e.message.as_str()),
            Some("a descendant of a tagged process has an unexpected parent"),
            "{found:?}"
        );
        let me = std::process::id();
        assert_eq!(parent_of(holder), Some(me), "the holder must not be reaped");
        assert!(!gone(mapper) && !gone(helper) && !gone(grandchild));
        // 後始末: 孫 → helper の順に止め、錨(mapper・holder)を回収してから再親付けされた子孫を回収する。
        let _ = sys::kill_pid(grandchild, sys::Signal::Kill);
        let _ = sys::kill_pid(helper, sys::Signal::Kill);
        wait_state(helper, 'Z');
        for pid in [mapper, holder, helper, grandchild] {
            let child = ContainerChild::adopt_reparented(NonZeroU32::new(pid).unwrap(), &subreaper);
            child
                .kill_and_reap(Duration::from_secs(5))
                .expect("reap a test process");
        }
    }

    /// CORE-6・SEC-5(#2376): 候補の列挙が不完全か、どれかの候補が保持になったら、どの錨も回収へ進めない。
    #[test]
    fn core6_halted_anchors_are_reaped_only_after_a_complete_listing() {
        assert!(may_reap_halted(false, false));
        assert!(!may_reap_halted(true, false));
        assert!(!may_reap_halted(false, true));
        assert!(!may_reap_halted(true, true));
    }

    /// CORE-6・SEC-5(#2376): セッションの全員の終了確認は、生きているメンバーが居る間は期限で `false`、全員が
    /// ゾンビになれば `true` を返す(holder の回収前に helper の終了を確かめる経路の実体)。
    #[test]
    fn core6_session_members_exited_waits_for_all_members() {
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let tag = LaunchTag::fresh();
        let (mut ready_read, ready_write) = std::io::pipe().unwrap();
        let ready_write = std::fs::File::from(std::os::fd::OwnedFd::from(ready_write));
        let leader = fork_tagged_session_leader(tag, || {
            let member = sys::fork_single_threaded_with_no_flush(
                || true,
                || {
                    let mut w = &ready_write;
                    let _ = w.write_all(&std::process::id().to_le_bytes());
                    std::thread::sleep(Duration::from_secs(120));
                    0
                },
                EXIT_SETUP_FAILED,
            );
            if member.is_err() {
                return EXIT_SETUP_FAILED;
            }
            std::thread::sleep(Duration::from_secs(120));
            0
        });
        drop(ready_write);
        let mut buf = [0u8; 4];
        read_within(&mut ready_read, &mut buf, Duration::from_secs(10));
        let member = u32::from_le_bytes(buf);
        assert!(!session_members_exited(leader, Duration::from_millis(100)));
        sys::kill_process_group(leader, sys::Signal::Kill).expect("kill the session group");
        assert!(session_members_exited(leader, Duration::from_secs(2)));
        assert_eq!(parent_of(member), Some(std::process::id()));
        for pid in [leader, member] {
            let child = ContainerChild::adopt_reparented(NonZeroU32::new(pid).unwrap(), &subreaper);
            child
                .kill_and_reap(Duration::from_secs(5))
                .expect("reap a test process");
        }
    }

    /// CORE-2: 停止(ゾンビ化)未確認・列挙不完全のどちらでも保持し、両方を満たしたときだけ回収へ進む。
    #[test]
    fn core2_tagged_process_is_retained_unless_halted_and_fully_listed() {
        assert!(must_retain_tagged(false, false));
        assert!(must_retain_tagged(true, true));
        assert!(must_retain_tagged(false, true));
        assert!(!must_retain_tagged(true, false));
    }

    /// CORE-2: `/proc/<pid>/stat` の親 pid とセッション ID を、`comm` に空白や `)` があっても読む。
    #[test]
    fn core2_parent_and_session_parse_tricky_comm() {
        assert_eq!(
            parent_and_session_of("12 (a) b) S 34 56 78 0 -1"),
            Some((34, 78))
        );
        assert_eq!(parent_and_session_of("12 (x) S 34"), None);
        assert_eq!(parent_and_session_of("garbage"), None);
    }

    #[test]
    fn core2_proc_state_parses_tricky_comm() {
        assert_eq!(proc_state_of("12 (a) b) T 1 2"), Some('T'));
        assert_eq!(proc_state_of("garbage"), None);
    }

    /// CORE-2・REPAIR-12(#2394): 終了処理中(state `X`)の task の stat は ppid 0・pgrp / session -1 で、
    /// 親とセッションとしては解析できない。`descendants_of` は state を先に見て、これを列挙不完全にしない。
    #[test]
    fn core2_dying_task_stat_has_dead_state_and_unparsable_session() {
        let dying =
            "831151 (fdh-l00000002) X 0 -1 -1 0 -1 4227148 63 0 0 0 0 0 0 0 20 0 0 0 221010080\n";
        assert_eq!(proc_state_of(dying), Some('X'));
        assert_eq!(parent_and_session_of(dying), None);
    }

    /// 疑似 `/proc`(一時ディレクトリ)に `<pid>/stat` を置く。
    fn fake_proc(label: &str, stats: &[(u32, &str)]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("core2-2394-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (pid, stat) in stats {
            let dir = root.join(pid.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("stat"), stat).unwrap();
        }
        root
    }

    /// CORE-2・REPAIR-12(#2394): 探索処理そのものに fixture を渡す。終了処理中(`X` / `x`)の task は除外され
    /// `scan_incomplete` が立たず、通常の子は列挙される。
    #[test]
    fn core2_descendants_skip_dying_tasks_without_marking_incomplete() {
        let dying_x = "300 (a) X 0 -1 -1 0 -1 4227148\n";
        let dying_lx = "301 (b) x 0 -1 -1 0 -1 4227148\n";
        let child = "302 (c) S 100 100 100 0 -1 0\n";
        let root = fake_proc(
            "skip",
            &[
                (300, dying_x),
                (301, dying_lx),
                (302, child),
                (100, "100 (anchor) S 1 100 100 0 -1 0\n"),
            ],
        );
        let mut out = Rescan::default();
        let found = descendants_in(&root, 100, 1, &mut out);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(found, vec![pid(302)]);
        assert!(!out.scan_incomplete, "{out:?}");
        assert!(out.error.is_none(), "{out:?}");
    }

    /// 対照: state が生きていて解析できない stat(壊れた stat)は従来どおり `scan_incomplete` になる。
    #[test]
    fn core2_descendants_unparsable_live_stat_marks_incomplete() {
        let broken = "303 (d) S 0 -1 -1 0 -1 4227148\n";
        let root = fake_proc("broken", &[(303, broken)]);
        let mut out = Rescan::default();
        let found = descendants_in(&root, 100, 1, &mut out);
        let _ = std::fs::remove_dir_all(&root);
        assert!(found.is_empty(), "{found:?}");
        assert!(out.scan_incomplete, "{out:?}");
        assert!(out.error.is_some(), "{out:?}");
    }

    fn gone(pid: u32) -> bool {
        !Path::new(&format!("/proc/{pid}")).exists()
    }

    /// CORE-1・CORE-2(#1816): 成功は PID 1 の `ContainerChild`(pidfd つき)を返し、回収されずに終了を待てる。
    /// 中間プロセスは回収済みで、監査は 0 件。
    #[test]
    fn core1_via_intermediate_success_returns_adopted_pid1() {
        let _serial = serialize_forks();
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

    /// netns 同期点の代役の PID 1 の振る舞い。
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum NetnsStandIn {
        /// 本物の送り手で自分の netns(`NetAndUser` は続けて user namespace)を送り、ACK を受けたら `P` を書いて 0 で終了する。
        Honest(NetnsHandover),
        /// 何も送らず眠る(C は期限で失敗にする)。
        Silent,
        /// 何も送らずに終了する(C は EOF を観測する)。
        ExitsEarly,
    }

    /// 同期点を通す起動を代役の PID 1 で行う(`with_listener = false`)。結果・代役の pid・記録を返す。
    fn run_netns(
        mode: NetnsStandIn,
        check: NetnsCheck<'_>,
        timeout: Duration,
    ) -> (
        Result<LaunchedChild, Box<PreparedLaunchFailure>>,
        u32,
        Vec<AuditRecord>,
    ) {
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let (mut pid_read, pid_write) = std::io::pipe().unwrap();
        let pid_write = std::fs::File::from(std::os::fd::OwnedFd::from(pid_write));
        let sink = VecSink(Mutex::new(Vec::new()));
        let id = ContainerId::new("c3206").unwrap();
        let audit = LaunchAudit {
            sink: &sink,
            container: Some(&id),
        };
        let (out_tx, _out_rx) = UnixStream::pair().unwrap();
        let tag = LaunchTag::fresh();
        let result = launch_via_intermediate(
            || true,
            |status, report, gate_r, _listener_end, netns_end| {
                let end = netns_end.expect("netns end").try_clone().expect("dup");
                let pid1 = fork_stand_in(status, &pid_write, move |s| {
                    if await_start_gate(gate_r, Duration::from_secs(10)).is_err() {
                        return EXIT_SETUP_FAILED;
                    }
                    match mode {
                        NetnsStandIn::Honest(handover) => {
                            match NetnsSyncSender::new(end)
                                .hand_over(handover, Duration::from_secs(10))
                            {
                                Ok(()) => {
                                    let _ = report_ready(s);
                                    0
                                }
                                Err(_) => 3,
                            }
                        }
                        NetnsStandIn::Silent => {
                            std::thread::sleep(Duration::from_secs(120));
                            0
                        }
                        NetnsStandIn::ExitsEarly => 3,
                    }
                });
                send_report(report, &IntermediateReport::Pid1(pid(pid1)));
                0
            },
            None,
            Some(check),
            &subreaper,
            audit,
            timeout,
            &tag,
            (crate::legacy_tiocsti::LegacyTiocsti::Absent, out_tx.as_fd()),
        );
        let mut buf = [0u8; 4];
        std::io::Read::read_exact(&mut pid_read, &mut buf).expect("pid1");
        let records = sink.0.lock().unwrap().clone();
        (result, u32::from_le_bytes(buf), records)
    }

    fn own_netns() -> super::super::netns_sync::NetnsIdentity {
        capture_baseline().expect("own netns")
    }

    /// NET-6・SEC-1(#3206): Host 相当(基準と同じ)の代役は同期点を通り、起動に成功する。記録は 0 件。
    #[test]
    fn net6_sec1_3206_launch_passes_the_netns_sync_point_when_identity_matches() {
        let _serial = serialize_forks();
        let check = NetnsCheck {
            expectation: super::super::netns_sync::NetnsExpectation::SameAsBaseline,
            baseline: own_netns(),
            attach: None,
        };
        let (result, pid1, records) = run_netns(
            NetnsStandIn::Honest(NetnsHandover::NetOnly),
            check,
            Duration::from_secs(20),
        );
        let launched = result.expect("must launch");
        assert_eq!(launched.child.pid(), pid1);
        assert_eq!(
            launched
                .child
                .wait_timeout(Duration::from_secs(10))
                .unwrap(),
            ChildExit::Exited(0)
        );
        assert!(records.is_empty());
    }

    /// NET-6・SEC-1・SEC-4(#3206): Loopback 相当(基準と異なる)なのに基準と同じ netns なら、`netns_identity_mismatch` で
    /// 拒否して 1 件記録し、PID 1 は exec せずに回収される。段は `netns_verify`、code は FailedPrecondition。
    #[test]
    fn net6_sec1_sec4_3206_launch_rejects_and_audits_a_netns_mismatch() {
        let _serial = serialize_forks();
        let check = NetnsCheck {
            expectation: super::super::netns_sync::NetnsExpectation::DiffersFromBaseline,
            baseline: own_netns(),
            attach: None,
        };
        let (result, pid1, records) = run_netns(
            NetnsStandIn::Honest(NetnsHandover::NetOnly),
            check,
            Duration::from_secs(20),
        );
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::FailedPrecondition);
        assert_eq!(failure.rejection.error.stage, IsolationStage::NetnsVerify);
        assert_eq!(
            failure
                .rejection
                .error
                .violation
                .as_ref()
                .map(|v| v.reason.as_str()),
            Some("netns_identity_mismatch")
        );
        assert_eq!(
            failure.rejection.delivery,
            crate::audit_log::AuditDelivery::Recorded
        );
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].layer(), crate::audit_log::AuditLayer::Mount);
        assert_eq!(records[0].path(), None);
        assert_eq!(
            records[0].reason().map(|r| r.as_str()),
            Some("netns_identity_mismatch")
        );
        assert_eq!(records[0].stage().map(|s| s.as_str()), Some("netns_verify"));
    }

    /// REPAIR-5(#3206): 代役が何も送らず終了(EOF)・眠る(期限切れ)のどちらも、記録なしの起動失敗になり PID 1 は回収される。
    #[test]
    fn repair5_3206_launch_fails_closed_when_the_netns_never_arrives() {
        let _serial = serialize_forks();
        let check = NetnsCheck {
            expectation: super::super::netns_sync::NetnsExpectation::SameAsBaseline,
            baseline: own_netns(),
            attach: None,
        };
        let (result, pid1, records) =
            run_netns(NetnsStandIn::ExitsEarly, check, Duration::from_secs(20));
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::FailedPrecondition);
        assert_eq!(failure.rejection.error.stage, IsolationStage::NetnsVerify);
        assert!(gone(pid1));
        assert!(records.is_empty());

        let check = NetnsCheck {
            expectation: super::super::netns_sync::NetnsExpectation::SameAsBaseline,
            baseline: own_netns(),
            attach: None,
        };
        let started = Instant::now();
        let (result, pid1, records) =
            run_netns(NetnsStandIn::Silent, check, Duration::from_secs(2));
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Timeout);
        assert_eq!(failure.rejection.error.stage, IsolationStage::NetnsVerify);
        assert!(started.elapsed() < Duration::from_secs(15));
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
        assert!(records.is_empty());
    }

    /// 呼び出しを記録するフック(C 側で呼ばれる)。`delay` の間眠ってから `result` を返す。
    struct AttachHookProbe {
        calls: Mutex<Vec<(super::super::netns_sync::NetnsIdentity, bool)>>,
        result: Result<(), ErrorCode>,
        delay: Duration,
    }

    impl NetnsAttachHook for AttachHookProbe {
        fn attach(
            &self,
            namespaces: crate::oci_runtime::AttachableNamespaces,
            _deadline: Instant,
        ) -> Result<(), crate::traits::types::TraitError> {
            use std::os::unix::fs::MetadataExt as _;
            let net = std::fs::File::from(namespaces.net().try_clone_to_owned().unwrap())
                .metadata()
                .unwrap();
            let user = std::fs::File::from(namespaces.user().try_clone_to_owned().unwrap())
                .metadata()
                .unwrap();
            let own_user = std::fs::metadata("/proc/thread-self/ns/user").unwrap();
            let id =
                super::super::netns_sync::NetnsIdentity::from_parts_for_test(net.dev(), net.ino());
            self.calls
                .lock()
                .unwrap()
                .push((id, user.ino() == own_user.ino()));
            std::thread::sleep(self.delay);
            self.result
                .map_err(|c| crate::traits::types::TraitError::new(c, "private detail"))
        }
    }

    fn probe(result: Result<(), ErrorCode>, delay: Duration) -> AttachHookProbe {
        AttachHookProbe {
            calls: Mutex::new(Vec::new()),
            result,
            delay,
        }
    }

    fn attach_check(hook: &AttachHookProbe) -> NetnsCheck<'_> {
        NetnsCheck {
            expectation: super::super::netns_sync::NetnsExpectation::SameAsBaseline,
            baseline: own_netns(),
            attach: Some(AttachCheck {
                // 代役は試験プロセスと同じ user namespace にいるため、基準は別の値にして「異なる」判定を通す。
                user_baseline: super::super::netns_sync::NetnsIdentity::from_parts_for_test(0, 0),
                hook,
            }),
        }
    }

    /// NET-9・CORE-6・SEC-1(#1939): 2 本版は net → user の順に届き、フックが 1 回だけ呼ばれ(受け取った netns の素性が
    /// 送り手のものと一致)、合図(ACK)の後に `P` が届いて起動が成功する。記録は 0 件。
    #[test]
    fn net9_core6_1939_attachable_calls_hook_once_then_launches() {
        let _serial = serialize_forks();
        let hook = probe(Ok(()), Duration::ZERO);
        let (result, pid1, records) = run_netns(
            NetnsStandIn::Honest(NetnsHandover::NetAndUser),
            attach_check(&hook),
            Duration::from_secs(20),
        );
        let launched = result.expect("must launch");
        assert_eq!(launched.child.pid(), pid1);
        assert_eq!(
            launched
                .child
                .wait_timeout(Duration::from_secs(10))
                .unwrap(),
            ChildExit::Exited(0)
        );
        assert!(records.is_empty());
        let calls = hook.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], (own_netns(), true));
    }

    /// NET-9・REPAIR-5(#1939): フックが Err なら ACK を送らず PID 1 を回収する。code を保ち、段は `NetnsAttach`、記録は 0 件。
    #[test]
    fn net9_repair5_1939_hook_failure_reaps_pid1_without_ack_or_audit() {
        let _serial = serialize_forks();
        let hook = probe(Err(ErrorCode::Unavailable), Duration::ZERO);
        let (result, pid1, records) = run_netns(
            NetnsStandIn::Honest(NetnsHandover::NetAndUser),
            attach_check(&hook),
            Duration::from_secs(20),
        );
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Unavailable);
        assert_eq!(failure.rejection.error.stage, IsolationStage::NetnsAttach);
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
        assert!(records.is_empty());
        assert_eq!(hook.calls.lock().unwrap().len(), 1);
    }

    /// NET-9・REPAIR-5(#1939): フックが Ok でも launch の期限を越えていれば `Timeout`(段 `NetnsAttach`)で失敗し、回収する。
    #[test]
    fn net9_repair5_1939_hook_returning_after_the_deadline_is_a_timeout() {
        let _serial = serialize_forks();
        let hook = probe(Ok(()), Duration::from_millis(2500));
        let (result, pid1, records) = run_netns(
            NetnsStandIn::Honest(NetnsHandover::NetAndUser),
            attach_check(&hook),
            Duration::from_secs(2),
        );
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Timeout);
        assert_eq!(failure.rejection.error.stage, IsolationStage::NetnsAttach);
        assert!(failure.unreaped.is_empty());
        assert!(gone(pid1));
        assert!(records.is_empty());
    }

    /// NET-9・SEC-1・SEC-4(#1939): 2 本を期待したのに 1 本しか送らない子は `netns_handoff_invalid` を 1 件記録して回収され、
    /// フックは呼ばれない。
    #[test]
    fn net9_sec1_sec4_1939_single_fd_sender_is_rejected_before_the_hook() {
        let _serial = serialize_forks();
        let hook = probe(Ok(()), Duration::ZERO);
        let (result, pid1, records) = run_netns(
            NetnsStandIn::Honest(NetnsHandover::NetOnly),
            attach_check(&hook),
            Duration::from_secs(20),
        );
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::FailedPrecondition);
        assert_eq!(failure.rejection.error.stage, IsolationStage::NetnsVerify);
        assert!(gone(pid1));
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].reason().map(|r| r.as_str()),
            Some("netns_handoff_invalid")
        );
        assert!(hook.calls.lock().unwrap().is_empty());
    }

    /// NET-9・REPAIR-5(#1939): 2 本版でも代役が何も送らず終了・眠るなら、記録なしの起動失敗になり PID 1 は回収される。
    #[test]
    fn net9_repair5_1939_attachable_fails_closed_when_nothing_arrives() {
        let _serial = serialize_forks();
        let hook = probe(Ok(()), Duration::ZERO);
        let (result, pid1, records) = run_netns(
            NetnsStandIn::ExitsEarly,
            attach_check(&hook),
            Duration::from_secs(20),
        );
        let failure = result.expect_err("must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::FailedPrecondition);
        assert!(gone(pid1));
        assert!(records.is_empty());
        let (result, pid1, _records) = run_netns(
            NetnsStandIn::Silent,
            attach_check(&hook),
            Duration::from_secs(2),
        );
        assert_eq!(
            result.expect_err("must fail").rejection.error.code,
            ErrorCode::Timeout
        );
        assert!(gone(pid1));
        assert!(hook.calls.lock().unwrap().is_empty());
    }

    /// 子プロセス側の本体(`REPAIR12_2249_CHILD` が無ければ何もしない)。別スレッドが stdout / stderr の
    /// ロックを握っている間に fork しても、入れ子の代役の fork が flush で止まらず成功することを確かめる。
    /// ロックは共有 libtest プロセスを巻き込まないよう、親が再 exec した専用プロセスの中でだけ握る。
    #[test]
    fn repair12_2249_stand_in_fork_ignores_stdio_locks_helper() {
        if std::env::var_os("REPAIR12_2249_CHILD").is_none() {
            return;
        }
        use std::sync::mpsc;
        let (held_tx, held_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _out = std::io::stdout().lock();
            let _err = std::io::stderr().lock();
            let _ = held_tx.send(());
            // 解放の合図か送信側の drop、最長 30 秒で必ず抜ける。
            let _ = release_rx.recv_timeout(Duration::from_secs(30));
        });
        held_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("lock holder ready");
        let (result, sink, pid1) = run(Behavior::Ready, Duration::from_secs(10));
        drop(release_tx);
        holder.join().unwrap();
        let child = result.unwrap();
        assert_eq!(Some(child.pid()), pid1);
        assert!(child.pidfd().is_some());
        assert_eq!(
            child.wait_timeout(Duration::from_secs(10)).unwrap(),
            ChildExit::Exited(0)
        );
        assert!(sink.0.lock().unwrap().is_empty());
    }

    /// CORE-1・REPAIR-5・REPAIR-12(#2249): 他スレッドが stdout / stderr のロックを握っている間に fork しても、
    /// 入れ子の代役の fork が flush で止まらず成功する(修正前は中間プロセスが報告せず Timeout になった)。
    /// process-global のロックで並列テストを巻き込まないよう、`--test-threads=1` の子プロセスへ隔離して確かめる。
    #[test]
    fn repair12_2249_stand_in_fork_ignores_stdio_locks_held_by_other_threads() {
        let _serial = serialize_forks();
        if std::env::var_os("REPAIR12_2249_CHILD").is_some() {
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "--no-capture",
                "--test-threads=1",
                "exec::launch_intermediate::tests::repair12_2249_stand_in_fork_ignores_stdio_locks_helper",
            ])
            .env("REPAIR12_2249_CHILD", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        if status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let status = status.expect("isolated child timed out");
        assert!(status.success(), "isolated child failed: {status:?}");
    }

    /// SEC-4(#1816): pivot 前段の違反は C が 1 件記録し、起動失敗を返して PID 1 を回収する。
    #[test]
    fn sec4_via_intermediate_failure_audits_and_reaps_pid1() {
        let _serial = serialize_forks();
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
        let _serial = serialize_forks();
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
        let _serial = serialize_forks();
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
        let _serial = serialize_forks();
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
        let _serial = serialize_forks();
        let (result, sink, _) = run(Behavior::SpawnFails, Duration::from_secs(10));
        let failure = result.expect_err("launch must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Unavailable);
        assert_eq!(failure.rejection.error.stage, IsolationStage::Spawn);
        assert!(failure.unreaped.is_empty());
        assert!(failure.reap_error.is_none());
        assert!(failure.rescans.is_empty());
        assert!(sink.0.lock().unwrap().is_empty());
    }

    /// CORE-2(#2009・Codex P1): I が識別子つきの mapper(helper つき)を残したまま `R`(isolate 失敗)を報告して
    /// 終了しても、C は I の回収後に識別子で再探索し、helper と mapper を kill・回収する。結果は残存なし(`unreaped`・
    /// `reap_error`・`rescans` が空)で、両者とも `/proc` に残らない。
    #[test]
    fn core2_via_intermediate_isolate_failure_reaps_left_mapper_and_helper() {
        let _serial = serialize_forks();
        let (result, sink, pids) = run_pids(
            Behavior::IsolateFailsLeavingMapper,
            Duration::from_secs(10),
            2,
        );
        let failure = result.expect_err("launch must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::PermissionDenied);
        assert_eq!(failure.rejection.error.stage, IsolationStage::Unshare);
        assert!(failure.unreaped.is_empty(), "{failure:?}");
        assert!(failure.reap_error.is_none(), "{failure:?}");
        assert!(failure.rescans.is_empty(), "{failure:?}");
        assert!(sink.0.lock().unwrap().is_empty());
        let [helper, mapper] = pids[..] else {
            panic!("the stand-ins did not report their pids: {pids:?}");
        };
        assert!(gone(helper), "the helper {helper} must be reaped");
        assert!(gone(mapper), "the mapper {mapper} must be reaped");
    }

    /// CORE-2・REPAIR-5(#1817): 識別子を `comm` に持つ C の子を、再探索が kill・回収する(`confirm_no_process` の
    /// 再探索の実体)。見つけた子は回収済みで `/proc` に残らず、結果は「残っていない」(`is_clean`)。
    #[test]
    fn core2_rescan_finds_tagged_child_and_reaps_it() {
        let _serial = serialize_forks();
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let tag = LaunchTag::fresh();
        let (mut ready_read, ready_write) = std::io::pipe().unwrap();
        let ready_write = std::fs::File::from(std::os::fd::OwnedFd::from(ready_write));
        let pid1 = sys::fork_single_threaded_with_no_flush(
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
        read_within(&mut ready_read, &mut mark, Duration::from_secs(10));
        let found = rescan_unreported_init(&tag, &subreaper, Duration::from_secs(5));
        assert!(found.is_clean(), "{found:?}");
        assert!(!found.scan_incomplete);
        assert!(gone(pid1), "the tagged child {pid1} must be reaped");
        // 2 回目は何も見つからない(別の識別子の子や回収済みの子は対象外)。
        assert!(rescan_unreported_init(&tag, &subreaper, Duration::from_secs(1)).is_clean());
    }

    /// CORE-2(#2009): 識別子を持つ子(mapper)が exec 済みの子(`comm` が識別子でない helper)を持つとき、再探索は
    /// 子も kill・回収し、`/proc` に残さない。
    #[test]
    fn core2_rescan_also_reaps_untagged_children_of_tagged_process() {
        let _serial = serialize_forks();
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let tag = LaunchTag::fresh();
        let (mut ready_read, ready_write) = std::io::pipe().unwrap();
        let ready_write = std::fs::File::from(std::os::fd::OwnedFd::from(ready_write));
        let mapper = sys::fork_single_threaded_with_no_flush(
            || true,
            || {
                if sys::set_process_comm(tag.comm_bytes()).is_err() {
                    return EXIT_SETUP_FAILED;
                }
                // 識別子を持たない子(exec 後の helper 相当)。comm を別名にし、設定後に自分の pid を報告する
                // (comm を継承したままでは、回収漏れがタグ探索で拾われて検出できない。REPAIR-12)。
                let helper = sys::fork_single_threaded_with_no_flush(
                    || true,
                    || {
                        if sys::set_process_comm(b"notatag-helper\0\0").is_err() {
                            return EXIT_SETUP_FAILED;
                        }
                        let mut w = &ready_write;
                        let _ = w.write_all(&std::process::id().to_le_bytes());
                        std::thread::sleep(Duration::from_secs(120));
                        0
                    },
                    EXIT_SETUP_FAILED,
                );
                if helper.is_err() {
                    return EXIT_SETUP_FAILED;
                }
                std::thread::sleep(Duration::from_secs(120));
                0
            },
            EXIT_SETUP_FAILED,
        )
        .expect("fork the tagged mapper");
        drop(ready_write);
        let mut buf = [0u8; 4];
        read_within(&mut ready_read, &mut buf, Duration::from_secs(10));
        let helper = u32::from_le_bytes(buf);
        let found = rescan_unreported_init(&tag, &subreaper, Duration::from_secs(5));
        assert!(found.is_clean(), "{found:?}");
        assert!(gone(mapper), "the tagged mapper {mapper} must be reaped");
        assert!(gone(helper), "the helper {helper} must be reaped");
    }

    /// CORE-2・REPAIR-5(#1816): I が許可前に報告なしで終了しても、PID 1 は gate_w を継承していないため、C の
    /// 失敗(gate_w の drop)で開始ゲートが EOF となり、期限(10 秒)を待たずに終了する。
    #[test]
    fn core2_start_gate_sees_eof_when_launcher_aborts_before_release() {
        let _serial = serialize_forks();
        let _subreaper = ChildSubreaper::enable().expect("subreaper");
        let (mut mark_read, mark_write) = std::io::pipe().unwrap();
        let mark_write = std::fs::File::from(std::os::fd::OwnedFd::from(mark_write));
        let sink = VecSink(Mutex::new(Vec::new()));
        let audit = LaunchAudit {
            sink: &sink,
            container: None,
        };
        let tag = LaunchTag::fresh();
        let (gate_out_tx, _gate_out_rx) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let result = launch_via_intermediate(
            || true,
            |status, _report, gate_r, _listener_end, _netns_end| {
                let _ = sys::fork_single_threaded_with_no_flush(
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
            None,
            None,
            &_subreaper,
            audit,
            Duration::from_secs(5),
            &tag,
            (
                crate::legacy_tiocsti::LegacyTiocsti::Absent,
                gate_out_tx.as_fd(),
            ),
        );
        assert!(result.is_err());
        drop(result);
        let mut mark = [0u8; 1];
        read_within(&mut mark_read, &mut mark, Duration::from_secs(10));
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
        let _serial = serialize_forks();
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
        let _serial = serialize_forks();
        let (result, _sink, _) = run(Behavior::MalformedReport, Duration::from_secs(10));
        let failure = result.expect_err("launch must fail");
        assert_eq!(failure.rejection.error.code, ErrorCode::Internal);
        assert_eq!(
            failure.rejection.error.message,
            "the intermediate process report is malformed"
        );
    }

    // ---- dev.tty.legacy_tiocsti の警告(CORE-5・SEC-1・REPAIR-4・REPAIR-5・#1739・#2008) ----

    use crate::legacy_tiocsti::LegacyTiocsti;

    const LEGACY_LINE: &str = r#"{"level":"warn","event":"legacy_tiocsti_enabled","sysctl":"dev.tty.legacy_tiocsti","value":1}"#;

    fn read_available(rx: &mut UnixStream) -> Vec<u8> {
        rx.set_nonblocking(true).expect("nonblocking");
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match rx.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("read: {e}"),
            }
        }
        out
    }

    /// 有効のとき、固定 1 行がちょうど 1 回、改行付きで届き、起動は成功する。
    #[test]
    fn core5_sec1_2008_enabled_emits_exact_line_once() {
        let _serial = serialize_forks();
        assert_eq!(
            crate::legacy_tiocsti::warning_line(LegacyTiocsti::Enabled),
            Some(LEGACY_LINE)
        );
        let (tx, mut rx) = UnixStream::pair().unwrap();
        let (result, _sink, _) = run_with(
            Behavior::Ready,
            Duration::from_secs(10),
            LegacyTiocsti::Enabled,
            tx.as_fd(),
        );
        let child = result.unwrap();
        assert_eq!(
            child.wait_timeout(Duration::from_secs(10)).unwrap(),
            ChildExit::Exited(0)
        );
        assert_eq!(
            read_available(&mut rx),
            format!("{LEGACY_LINE}\n").into_bytes()
        );
        assert_eq!(read_available(&mut rx), Vec::<u8>::new());
    }

    /// 対象外の状態では何も出力されない。
    #[test]
    fn core5_sec1_2008_non_applicable_states_emit_nothing() {
        let _serial = serialize_forks();
        for state in [
            LegacyTiocsti::Absent,
            LegacyTiocsti::Disabled,
            LegacyTiocsti::Unexpected,
            LegacyTiocsti::ReadFailed {
                kind: std::io::ErrorKind::PermissionDenied,
            },
        ] {
            let (tx, mut rx) = UnixStream::pair().unwrap();
            let (result, _sink, _) =
                run_with(Behavior::Ready, Duration::from_secs(10), state, tx.as_fd());
            let child = result.unwrap();
            assert_eq!(
                child.wait_timeout(Duration::from_secs(10)).unwrap(),
                ChildExit::Exited(0)
            );
            assert_eq!(read_available(&mut rx), Vec::<u8>::new(), "{state:?}");
        }
    }

    /// fork の後なら、起動が失敗しても警告は 1 行出る。
    #[test]
    fn core5_sec1_2008_emitted_even_when_launch_fails() {
        let _serial = serialize_forks();
        let (tx, mut rx) = UnixStream::pair().unwrap();
        let (result, _sink, _) = run_with(
            Behavior::IsolateFails,
            Duration::from_secs(10),
            LegacyTiocsti::Enabled,
            tx.as_fd(),
        );
        assert!(result.is_err());
        assert_eq!(
            read_available(&mut rx),
            format!("{LEGACY_LINE}\n").into_bytes()
        );
    }

    /// 出力先が満杯でも起動は待たされず成功する(REPAIR-5)。
    #[test]
    fn repair5_2008_full_output_does_not_block_launch() {
        let _serial = serialize_forks();
        let (mut tx, rx) = UnixStream::pair().unwrap();
        tx.set_nonblocking(true).unwrap();
        let chunk = [b'x'; 4096];
        loop {
            match std::io::Write::write(&mut tx, &chunk) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("fill: {e}"),
            }
        }
        tx.set_nonblocking(false).unwrap();
        let started = Instant::now();
        let (result, _sink, _) = run_with(
            Behavior::Ready,
            Duration::from_secs(10),
            LegacyTiocsti::Enabled,
            tx.as_fd(),
        );
        let child = result.unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(
            child.wait_timeout(Duration::from_secs(10)).unwrap(),
            ChildExit::Exited(0)
        );
        drop(rx);
    }

    /// 読み手が閉じていても起動は失敗せず、SIGPIPE で落ちない(`MSG_NOSIGNAL`)。
    #[test]
    fn repair5_2008_closed_peer_does_not_fail_launch() {
        let _serial = serialize_forks();
        let (tx, rx) = UnixStream::pair().unwrap();
        drop(rx);
        let (result, _sink, _) = run_with(
            Behavior::Ready,
            Duration::from_secs(10),
            LegacyTiocsti::Enabled,
            tx.as_fd(),
        );
        let child = result.unwrap();
        assert_eq!(
            child.wait_timeout(Duration::from_secs(10)).unwrap(),
            ChildExit::Exited(0)
        );
    }

    /// CORE-1(#1816): 複数スレッドの呼び出しは中間プロセスを作らず `FailedPrecondition`。
    #[test]
    fn core1_via_intermediate_refuses_multithreaded_caller() {
        let _serial = serialize_forks();
        let subreaper = ChildSubreaper::enable().expect("subreaper");
        let sink = VecSink(Mutex::new(Vec::new()));
        let audit = LaunchAudit {
            sink: &sink,
            container: None,
        };
        let (out_tx, _out_rx) = UnixStream::pair().unwrap();
        let result = launch_via_intermediate(
            || false,
            |_, _, _, _, _| panic!("the intermediate must not run"),
            None,
            None,
            &subreaper,
            audit,
            Duration::from_secs(1),
            &LaunchTag::fresh(),
            (crate::legacy_tiocsti::LegacyTiocsti::Absent, out_tx.as_fd()),
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
        let _serial = serialize_forks();
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
                "--no-capture",
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
