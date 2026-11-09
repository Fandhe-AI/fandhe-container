//! stream-exec helper の本体（CRI の Exec の本番 backend のサーバー側。SUP-6・SEC-1・REPAIR-5・#3760）。
//!
//! # 役割と呼び出し文脈
//!
//! plugin-cri（#3761）が CRI の Exec 要求ごとに supervisor の実行ファイルを第 1 引数 `stream-exec` で起動し、
//! その単一スレッドのプロセスの中で `exec::run_command_with_pidfd_output_notify` を通して結果を返す。
//! 方式の選定は `docs/design/cri-streaming-server.md`「本番 backend の設計」（#3752。案 α）で、制御チャネル（`control`）
//! には新しい種別を足さない。helper が既存の kind 6（起動時 pidfd の複製の受け取り）と kind 7（exec 子 cgroup の通知）
//! を [`crate::control::ControlExecHandover`] 経由で使い、plugin-cri との間は fd 0 の socketpair
//! （[`super::channel`]・[`super::wire`]）で結ぶ。bin の `main` が [`is_stream_exec_invocation`] で `run_main` より前に
//! 振り分ける（結果を channel で返すため `run_main` の fd 検証・結果チャネルを通さない）。
//!
//! # 契約（fd の割り当て）
//!
//! - fd 0: plugin-cri との channel（socket であることを確かめる。socket でなければ診断行を fd 2 に出して終了コード 1）
//! - fd 1: `/dev/null`（helper 自身は書かない。コマンドの stdout は channel で受け取った fd）
//! - fd 2: 診断行。起動の失敗は段名・分類・errno の 1 行（[`HelperFailure::diagnostic_line`]。語彙は [`super::diag`]。#4284）を
//!   `Result` の送信より前に書く（plugin-cri の読み手が停止後の短い drain で確実に拾えるように）。`Result` の送信が失敗した
//!   ときは `helper_result_send` の行を足す。子の段の失敗（`NotStarted`）は `Result` frame が段を運ぶので行を足さない。
//!   要求元の消滅で取り消したときの行（`code` と `message`）は従来の形のまま（実機前提の試験が照合する。#4166）。core の診断 JSON 行もここへ出る
//! - 環境変数は空・cwd は `/`（[`stream_exec_command`]）。引数は [`StreamExecArgs`] の形式
//!
//! # 処理順
//!
//! `close_fds_from(3)` → fd 0 を channel として確保 → `set_dumpable(false)` → 引数の解釈 → 状態記録の照合（`Running` かつ
//! pid が `--expect-pid` と一致。不一致は exec も監査もしない）→ launch 時 env の読み込み → 監査 sink の構築（作れなければ
//! exec も pidfd の要求もしない。SEC-4）→ kind 6 で pidfd の複製を受ける（孤児は `Unavailable`。記録 pid からの
//! `pidfd_open` へは縮退しない。SEC-1）→ `StdioHandover` の受信（mask は `--stdio` と一致が必要）→ exec の通し
//! （`on_created` で kind 7 の通知と ack の後に、exec 子 cgroup の名前を載せた `Started` を送る。#4221）→ exec の待ちの刻みごとに fd 0 の `Signal` を受けて `SignalAck` を返す（wire v4・#4282。`signal_tick`）。コマンドの pid が worker から届けば `Spawned` を送る（刻みで届かなかった短命なコマンドは後始末で `Result` の前に送る。#4316）
//! → `Result` の送信。以降の失敗はすべて `Result` frame で返す。
//!
//! # コマンドへのシグナル（#4282・SUP-6・CRI-5・SEC-1）
//!
//! plugin-cri の `Signal`（許可リスト [`super::wire::ExecSignal`]。SIGKILL は含まない）を、worker から渡されたコマンドの pidfd へ
//! `pidfd_send_signal` する（`exec::CommandSignaler`。子孫へは送らない）。保留は 1 件まで、pidfd が未着の間は 2 秒まで再試行して
//! `not_started`。受信に失敗した後は以後受けず ack も返さない（診断行 1 行。exec は止めない）。helper は seccomp・Landlock を受けて
//! いないので、rootless でもコンテナの user namespace の所有者として CAP_KILL を持つ。詳細は `docs/design/shim-v2-production-binary.md`
//! 「exec のシグナル」。
//!
//! # 接続断・期限（REPAIR-5）
//!
//! すべての待ち（kind 6・stdio・kind 7・exec 全体・結果の送信）に期限がある。plugin-cri が helper を kill すれば、
//! helper が持つ制御チャネルの接続が閉じ、supervisor の `exec_guard` が通知済みの exec 子 cgroup を回収する。
//! PDEATHSIG は使わない（plugin-cri は多スレッドで、子を作ったスレッドの終了で誤発火するため。`unsafe` も足さない）。
//!
//! # 未実装・残余（REPAIR-3）
//!
//! - tty（pty の割り当てと `PtyMaster` の送信）は後続 issue（#3761 では本番で fail-closed）で、本 helper は `--tty` を受けない。
//! - 受け取る stdio の fd は socket か FIFO に限る（`require_stdio_kinds`。#3761・SEC-1）。plugin-cri 側の結線は #3761 で実装済み。
//! - 要求元（plugin-cri）の異常終了の検知（#4166・SUP-6・SEC-1・REPAIR-5）: exec の間、supervisor の serve ループの刻みごとに
//!   fd 0 を `poll(timeout = 0)` で見て（[`channel::requester_gone`]。読まない・消費しない）、`POLLHUP`・`POLLERR`・
//!   `POLLRDHUP`・`POLLNVAL` なら exec を取り消す（コマンドの停止と exec 子 cgroup の回収の後に `Unavailable` で終わる。
//!   fd 2 に診断行を 1 行出す）。通常は要求元の消滅から 2 秒以内に終わる。取り消しは短絡に限り、判定の失敗・検知できない場合は
//!   従来どおり exec の期限（`--timeout-ms`）で終わる（上限は期限 + `hold_grace`）。残る窓: listener の受け渡し前（既存の短い
//!   期限に任せる）・seccomp の通知の処理中（記録の期限つきで最大 5 秒遅れる）・要求元が自分の channel の端を他プロセスへ
//!   漏らした場合（端が閉じず検知できない）。
//! - launch 時 env の読み込み（`launch_env_for`）は I/O が止まり得るが、単一スレッドを保つため期限つきの作業スレッドで
//!   包まない（healthcheck helper・CLI exec と同じ残余）。
//! - 起動失敗の errno は OS の errno があるときだけ運べる。状態ストア・launch env・監査 sink・要求の検証の失敗は core の
//!   `TraitError` が errno を持たないため `none` になる（#4284。`TraitError` へ errno を持たせる案は別 issue）。
//! - env は受け付けない（CRI は env を渡さず、基底は `config.json` の `process.env` と launch 時 env だけ。SEC-1）。
//! - `argv` の先頭（コマンド本体）は絶対パスのみ（PATH 探索は #2439 の判断待ち）。

use std::ffi::{OsStr, OsString};
use std::io::Write as _;
use std::num::NonZeroU32;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fandhe_container_core::audit_log::{AuditSink, AuditedRejection};
use fandhe_container_core::exec::{
    ChildExit, ENTRYPOINT_MAX_ARGS, ExecCgroupName, ExecExit, emit_diagnostic_line_to,
};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, GetStateRequest, StateRecord, StateStore, TraitError,
};

use super::channel::{self, ChannelError};
use super::diag::{HelperFailure, HelperStage};
use super::wire::{
    ChildStatus, ExecSignal, ExitSignal, SignalAckCode, StdioMask, StreamExecOutcome,
    error_code_to_u8, step_to_u8,
};
use crate::control::protocol::MAX_EXEC_HOLD_SECS;
use crate::control::{ControlExecHandover, ExecControlFailure, ExecPidfdSource};
use crate::exec::{
    CommandSignaler, ExecLaunchIo, ExecRequest, ExecSignalDelivery, ExecStdio, default_audit_sink,
};

/// helper を起動するサブコマンド名（bin の第 1 引数）。
pub const STREAM_EXEC_SUBCOMMAND: &str = "stream-exec";

/// helper の `argv[0]`（固定。実行ファイルのパス文字列を使わない）。
pub const STREAM_EXEC_ARG0: &str = "fandhe-container-supervisor";

/// kind 6（pidfd の受け取り）に割り当てる上限（全体の期限の内側で打ち切る。REPAIR-5）。
const HANDOVER_BUDGET: Duration = Duration::from_secs(5);
/// `StdioHandover` の受信に割り当てる上限。
const STDIO_BUDGET: Duration = Duration::from_secs(5);
/// `Started`・`Result` の送信に割り当てる上限。
const SEND_BUDGET: Duration = Duration::from_secs(5);

/// bin の main が helper へ振り分ける呼び出しか（第 1 引数が `stream-exec`）。`run_main` より前に判定する。
pub fn is_stream_exec_invocation(first: Option<&OsStr>) -> bool {
    first == Some(OsStr::new(STREAM_EXEC_SUBCOMMAND))
}

/// helper の引数（検証済み）。
///
/// 形式: `--root <絶対パス> --id <ContainerId> --expect-pid <n> --timeout-ms <n> --stdio <0..7> -- <argv0> [<arg>...]`。
/// 各オプションはちょうど 1 回。未知（`--env` を含む）・重複・欠落・`--` の欠落・空のコマンドは拒否する。コマンドは
/// シェルを通さない argv の配列で、先頭は絶対パスのみ。件数は `ENTRYPOINT_MAX_ARGS`（CLI の exec と同じ上限。CRI の
/// Exec の cmd も利用者の任意コマンドのため）を超えた時点で集めるのをやめて拒否し、1 要素と合計のサイズ・NUL は
/// [`ExecRequest::new`] が検証する。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamExecArgs {
    root: PathBuf,
    id: ContainerId,
    expect_pid: NonZeroU32,
    timeout: Duration,
    stdio: StdioMask,
    command: Vec<String>,
}

fn invalid() -> TraitError {
    TraitError::new(
        ErrorCode::InvalidArgument,
        "invalid stream-exec helper arguments",
    )
}

impl StreamExecArgs {
    /// plugin-cri 側が組み立てる。検証は [`Self::parse`] と同じ規則。
    pub fn new(
        root: PathBuf,
        id: ContainerId,
        expect_pid: NonZeroU32,
        timeout: Duration,
        stdio: StdioMask,
        command: Vec<String>,
    ) -> Result<Self, TraitError> {
        let max = Duration::from_secs(MAX_EXEC_HOLD_SECS);
        // 起動引数はミリ秒単位。端数は切り上げて正規化し、0 になる正の期限
        // （例: 500 マイクロ秒）を `--timeout-ms 0` として生成しない。
        let timeout = match u64::try_from(timeout.as_nanos().div_ceil(1_000_000)) {
            Ok(ms) => Duration::from_millis(ms),
            Err(_) => return Err(invalid()),
        };
        if !root.is_absolute() || timeout.is_zero() || timeout > max {
            return Err(invalid());
        }
        if command.len() > ENTRYPOINT_MAX_ARGS {
            return Err(invalid());
        }
        let first = command.first().ok_or_else(invalid)?;
        if !Path::new(first).is_absolute() {
            return Err(invalid());
        }
        // 1 要素・合計のサイズと NUL は exec 共通関数の要求と同じ規則で確かめる。
        ExecRequest::new(first.as_str(), command.iter().cloned())?;
        Ok(Self {
            root,
            id,
            expect_pid,
            timeout,
            stdio,
            command,
        })
    }

    /// サブコマンド名を除いた引数列に直す（`Command::args` へ渡す）。
    pub fn to_args(&self) -> Vec<OsString> {
        let mut out: Vec<OsString> = vec![
            "--root".into(),
            self.root.clone().into_os_string(),
            "--id".into(),
            self.id.as_str().into(),
            "--expect-pid".into(),
            self.expect_pid.get().to_string().into(),
            "--timeout-ms".into(),
            self.timeout.as_millis().to_string().into(),
            "--stdio".into(),
            self.stdio.bits().to_string().into(),
            "--".into(),
        ];
        out.extend(self.command.iter().map(OsString::from));
        out
    }

    /// サブコマンド名を除いた引数列を解釈する。
    pub fn parse<I>(args: I) -> Result<Self, TraitError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut iter = args.into_iter();
        let mut root: Option<OsString> = None;
        let mut id: Option<String> = None;
        let mut pid: Option<String> = None;
        let mut timeout_ms: Option<String> = None;
        let mut stdio: Option<String> = None;
        let mut command: Vec<String> = Vec::new();
        let mut separated = false;
        while let Some(arg) = iter.next() {
            if arg == OsStr::new("--") {
                separated = true;
                for rest in iter.by_ref() {
                    // 件数は上限を超えた時点で打ち切る（それ以上は確保しない）。
                    if command.len() >= ENTRYPOINT_MAX_ARGS {
                        return Err(invalid());
                    }
                    command.push(rest.into_string().map_err(|_| invalid())?);
                }
                break;
            }
            let value = iter.next().ok_or_else(invalid)?;
            let text = |v: OsString| v.into_string().map_err(|_| invalid());
            let taken = match arg.to_str() {
                Some("--root") => root.replace(value).is_some(),
                Some("--id") => id.replace(text(value)?).is_some(),
                Some("--expect-pid") => pid.replace(text(value)?).is_some(),
                Some("--timeout-ms") => timeout_ms.replace(text(value)?).is_some(),
                Some("--stdio") => stdio.replace(text(value)?).is_some(),
                _ => return Err(invalid()),
            };
            if taken {
                return Err(invalid());
            }
        }
        if !separated {
            return Err(invalid());
        }
        let expect_pid = pid
            .as_deref()
            .and_then(|t| t.parse::<u32>().ok())
            .and_then(NonZeroU32::new)
            .ok_or_else(invalid)?;
        let timeout_ms = timeout_ms
            .as_deref()
            .and_then(|t| t.parse::<u64>().ok())
            .ok_or_else(invalid)?;
        let stdio = stdio
            .as_deref()
            .and_then(|t| t.parse::<u8>().ok())
            .and_then(StdioMask::new)
            .ok_or_else(invalid)?;
        let id = ContainerId::new(id.as_deref().ok_or_else(invalid)?)?;
        Self::new(
            PathBuf::from(root.ok_or_else(invalid)?),
            id,
            expect_pid,
            Duration::from_millis(timeout_ms),
            stdio,
            command,
        )
    }

    /// 状態ルート。
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 対象コンテナの ID。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 呼び出し元が期待する pid1 の記録 pid。
    pub fn expect_pid(&self) -> NonZeroU32 {
        self.expect_pid
    }

    /// exec 全体の期限。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// plugin-cri が渡す stdio の mask。
    pub fn stdio(&self) -> StdioMask {
        self.stdio
    }

    /// 実行する argv（先頭は絶対パス）。
    pub fn command(&self) -> &[String] {
        &self.command
    }
}

/// helper を起動する `Command`（`argv[0]` は固定・環境は空・cwd は `/`）。stdio は呼び出し側が設定する
/// （fd 0 に channel の socketpair、fd 1 は `/dev/null`、fd 2 は診断の受け口）。
///
/// `supervisor_exe` は呼び出し側（plugin-cri）が解決した信頼できる絶対パスで、`PATH` からは探さない
/// （`/proc/self/exe` は plugin-cri 自身を指すため使えない。SEC-1・PLUG-11）。
pub fn stream_exec_command(supervisor_exe: &Path, args: &StreamExecArgs) -> std::process::Command {
    use std::os::unix::process::CommandExt as _;
    let mut command = std::process::Command::new(supervisor_exe);
    command
        .arg0(STREAM_EXEC_ARG0)
        .arg(STREAM_EXEC_SUBCOMMAND)
        .args(args.to_args())
        .env_clear()
        .current_dir("/");
    command
}

/// exec の通しの結果を `Result` frame の値へ写す（純関数）。範囲外の値と番号表に無い値は捏造せず `Failed(Internal)` にし、
/// 段だけが番号表に無いときは「不明」（`None`）にする。
pub fn outcome_from_result(
    result: Result<ExecExit, AuditedRejection<TraitError>>,
) -> StreamExecOutcome {
    let internal = StreamExecOutcome::Failed(ErrorCode::Internal);
    let status = |exit: ChildExit| -> Option<ChildStatus> {
        match exit {
            ChildExit::Exited(n) => u8::try_from(n).ok().map(ChildStatus::Exited),
            ChildExit::Signaled(s) => u8::try_from(s)
                .ok()
                .and_then(ExitSignal::new)
                .map(ChildStatus::Signaled),
            _ => None,
        }
    };
    let known = |code: ErrorCode| error_code_to_u8(code).is_some();
    match result {
        Ok(ExecExit::Command(exit)) => match status(exit) {
            Some(ChildStatus::Exited(n)) => StreamExecOutcome::Exited(n),
            Some(ChildStatus::Signaled(s)) => StreamExecOutcome::Signaled(s),
            None => internal,
        },
        Ok(ExecExit::SetupFailed {
            exit, step, code, ..
        }) => match status(exit) {
            Some(exit) if known(code) => StreamExecOutcome::NotStarted {
                exit,
                step: step.filter(|s| step_to_u8(*s).is_some()),
                code,
            },
            _ => internal,
        },
        Ok(_) => internal,
        Err(AuditedRejection { error, .. }) => {
            let code = error.code();
            if known(code) {
                StreamExecOutcome::Failed(code)
            } else {
                internal
            }
        }
    }
}

/// 実行役の成功側（終了状態と、起動したコマンドのホスト側 pid。#4316）。
///
/// `command_pid` は `Command`（コマンドが起動して終了した）ときだけ `Some`。短命なコマンドが刻みの中継より先に終わっても、
/// 後始末で `Spawned` を `Result` より前に送るための控え（[`serve_reporting`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerExit {
    /// コマンドの終了状態。
    pub exit: ExecExit,
    /// コマンドの pid（起動していなければ `None`）。
    pub command_pid: Option<NonZeroU32>,
}

/// 実行役の型（本番は `production_runner`。試験は偽を渡す）。成功側は終了状態と pid だけに絞る。
pub type Runner<'a> = dyn Fn(
        &StateRecord,
        BorrowedFd<'_>,
        &ExecRequest,
        Duration,
        &dyn AuditSink,
        ExecLaunchIo<'_>,
    ) -> Result<RunnerExit, AuditedRejection<TraitError>>
    + 'a;

/// 監査 sink の生成口の型。
pub type SinkFactory<'a> = dyn Fn(&Path) -> Result<Box<dyn AuditSink>, TraitError> + 'a;

/// launch 時 env の読み込み口の型。
pub type LaunchEnvLoader<'a> = dyn Fn(&Path, &StateRecord) -> Result<Vec<String>, TraitError> + 'a;

/// [`serve`] の注入点（本番は [`run_stream_exec_main`] が組む。試験は偽に差し替える）。
pub struct Deps<'a> {
    /// 状態ストア。
    pub store: &'a dyn StateStore,
    /// 起動時 pidfd の取得元（本番は [`ControlExecHandover`]）。
    pub source: &'a dyn ExecPidfdSource,
    /// 監査 sink の生成口。
    pub make_sink: &'a SinkFactory<'a>,
    /// launch 時 env の読み込み口。
    pub launch_env: &'a LaunchEnvLoader<'a>,
    /// exec の実行役。
    pub run: &'a Runner<'a>,
}

fn production_sink(root: &Path) -> Result<Box<dyn AuditSink>, TraitError> {
    default_audit_sink(Some(root.to_path_buf())).map(|s| Box::new(s) as Box<dyn AuditSink>)
}

fn production_runner(
    record: &StateRecord,
    pidfd: BorrowedFd<'_>,
    request: &ExecRequest,
    timeout: Duration,
    audit: &dyn AuditSink,
    io: ExecLaunchIo<'_>,
) -> Result<RunnerExit, AuditedRejection<TraitError>> {
    crate::exec::run_command_with_pidfd_output_notify(record, pidfd, request, timeout, audit, io)
        .map(|audited| RunnerExit {
            exit: audited.outcome.exit,
            command_pid: audited.outcome.command_pid,
        })
}

/// `Started` の送信期限。`SEND_BUDGET` を `total_deadline` で頭打ちにする（期限後に `Started` を出さない。REPAIR-5・SUP-6）。
/// 期限切れ（`now >= total_deadline`）なら期限は `now` となり、`send_started` は送らず `Timeout` で失敗する。
fn started_send_deadline(now: Instant, total_deadline: Instant) -> Instant {
    total_deadline.min(now + SEND_BUDGET)
}

/// [`serve_reporting`] の結果: `Result` frame の値と、起動の失敗の段・errno（#4284）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeReport {
    /// `Result` frame として送る値。
    pub outcome: StreamExecOutcome,
    /// 起動の失敗の段・分類・errno（`Exited`・`Signaled`・`NotStarted` と、要求元の消滅による取り消しは `None`）。
    pub failure: Option<HelperFailure>,
}

fn early(stage: HelperStage, code: ErrorCode, errno: Option<i32>) -> ServeReport {
    ServeReport {
        outcome: StreamExecOutcome::Failed(code),
        failure: Some(HelperFailure::new(stage, code, errno)),
    }
}

fn early_trait(stage: HelperStage, e: &TraitError) -> ServeReport {
    early(stage, e.code(), None)
}

fn early_control(stage: HelperStage, e: &ExecControlFailure) -> ServeReport {
    early(stage, e.error().code(), e.errno())
}

fn early_channel(stage: HelperStage, e: &ChannelError) -> ServeReport {
    early(stage, e.code(), e.errno())
}

/// 前提検査から exec の通しまで（処理順はモジュール doc）。`channel` へは `Started`・`Spawned`・`SignalAck` を送り、`Result` は返り値で
/// 呼び出し側（[`run_stream_exec_main`]）が送る。失敗の段・errno が要るときは [`serve_reporting`]。
pub fn serve(channel: &UnixStream, args: &StreamExecArgs, deps: &Deps<'_>) -> StreamExecOutcome {
    serve_reporting(channel, args, deps).outcome
}

/// [`serve`] と同じ処理で、`Result` の値に加えて起動の失敗の段・errno を返す（fd 2 の診断行用。SUP-6・REPAIR-4・#4284）。
pub fn serve_reporting(
    channel: &UnixStream,
    args: &StreamExecArgs,
    deps: &Deps<'_>,
) -> ServeReport {
    let started = Instant::now();
    let total_deadline = started.checked_add(args.timeout()).unwrap_or(started);

    let record = match deps.store.get(&GetStateRequest::new(args.id().clone())) {
        Ok(record) => record,
        Err(e) => return early_trait(HelperStage::StateGet, &e),
    };
    let status = record.status();
    if status.state() != ContainerState::Running || status.pid() != Some(args.expect_pid()) {
        return early(
            HelperStage::StateMismatch,
            ErrorCode::FailedPrecondition,
            None,
        );
    }
    let launch_env = match (deps.launch_env)(args.root(), &record) {
        Ok(env) => env,
        Err(e) => return early_trait(HelperStage::LaunchEnv, &e),
    };
    // 監査の記録先を先に作る（作れなければ supervisor へ接続も exec もしない。fail-closed。SEC-4）。
    let sink = match (deps.make_sink)(args.root()) {
        Ok(sink) => sink,
        Err(e) => return early_trait(HelperStage::AuditSink, &e),
    };
    let request = match args
        .command()
        .first()
        .map(|first| ExecRequest::new(first.as_str(), args.command().iter().cloned()))
    {
        Some(Ok(request)) => request,
        Some(Err(e)) => return early_trait(HelperStage::Request, &e),
        None => return early(HelperStage::Request, ErrorCode::InvalidArgument, None),
    };

    // 接続（`handover`）は exec の後始末が終わるまで保持する。drop が切断で、supervisor は通知済みの exec 子 cgroup を回収する。
    let pid = args.expect_pid();
    let handover_deadline = total_deadline.min(Instant::now() + HANDOVER_BUDGET);
    let handover = match deps
        .source
        .obtain_with_errno(args.id(), pid, handover_deadline)
    {
        Ok(handover) => handover,
        Err(e) => return early_control(HelperStage::PidfdHandover, &e),
    };

    let stdio_deadline = total_deadline.min(Instant::now() + STDIO_BUDGET);
    let fds = match channel::recv_stdio_handover(channel, args.stdio(), stdio_deadline) {
        Ok(fds) => fds,
        Err(e) => return early_channel(HelperStage::StdioHandover, &e),
    };
    // 受け取った fd の種別を exec より前に検査する。不一致は fork も kind 7 の通知もせず終える（SEC-1・#3761）。
    if let Err(failure) = require_stdio_kinds(&fds) {
        return ServeReport {
            outcome: StreamExecOutcome::Failed(failure.code),
            failure: Some(failure),
        };
    }

    let remaining = total_deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return early(HelperStage::Deadline, ErrorCode::Timeout, None);
    }
    // 通知（kind 7 と ack）に成功してから `Started` を送る。どちらかが失敗したら worker を fork せず exec を中止する。
    // 失敗の段と errno は実行役の `Err` へ写る前にここで覚える（core の `TraitError` は errno を持たない。#4284）。
    let created_failure: std::cell::Cell<Option<HelperFailure>> = std::cell::Cell::new(None);
    let on_created = |name: &ExecCgroupName| -> Result<(), TraitError> {
        if let Err(e) = handover.notify_created_with_errno(name, total_deadline) {
            created_failure.set(Some(HelperFailure::new(
                HelperStage::CgroupNotify,
                e.error().code(),
                e.errno(),
            )));
            return Err(e.into_error());
        }
        channel::send_started(
            channel,
            name,
            started_send_deadline(Instant::now(), total_deadline),
        )
        .map_err(|e| {
            created_failure.set(Some(HelperFailure::new(
                HelperStage::StartedSend,
                e.code(),
                e.errno(),
            )));
            TraitError::new(e.code(), "failed to report the exec start to the caller")
        })
    };
    // 要求元（plugin-cri）の消滅の検知（#4166）。fd 0 の channel を読まずに `poll(timeout = 0)` で見て、消滅なら exec を
    // 取り消す（短絡に限り、期限と `hold_grace` は弱めない）。取り消したかは診断行のために覚える。
    let cancelled = std::cell::Cell::new(false);
    let cancel = || {
        let gone = channel::requester_gone(channel);
        if gone {
            cancelled.set(true);
        }
        gone
    };
    // コマンドへのシグナル（#4282）。exec の刻みごとに fd 0 の `Signal` を受け、コマンドの pidfd へ送って `SignalAck` を返す。
    let signal_state = SignalState::default();
    let signal_hook =
        |signaler: &dyn CommandSignaler| signal_tick(channel, &signal_state, signaler);
    let io = ExecLaunchIo {
        launch_env: &launch_env,
        stdio: ExecStdio {
            stdin: fds.stdin.as_ref().map(AsFd::as_fd),
            stdout: fds.stdout.as_ref().map(AsFd::as_fd),
            stderr: fds.stderr.as_ref().map(AsFd::as_fd),
        },
        on_created: Some(&on_created),
        cancel: Some(&cancel),
        signal: Some(&signal_hook),
    };
    let result = (deps.run)(
        &record,
        handover.pidfd(),
        &request,
        remaining,
        sink.as_ref(),
        io,
    );
    if cancelled.get() {
        // 期限切れ（`timeout`）との区別のための固定語彙の診断行（fd 2。結果は相手不在で送れない）。
        diagnose(
            "unavailable",
            "stream-exec requester went away; exec cancelled",
        );
    }
    // 短命なコマンドが刻みの中継より先に終わったときのため、起動したコマンドの pid を結果から控える（#4316）。
    let runner_pid = result.as_ref().ok().and_then(|r| r.command_pid);
    let outcome = outcome_from_result(result.map(|r| r.exit));
    // 刻みで送れていなければ、保留の ack と `Result` より前に `Spawned` を送る（`Spawned` は常に `Result` の前。#4316）。
    if let Some(pid) = runner_pid {
        send_spawned_once(channel, &signal_state, pid);
    }
    // exec が終わった時点で保留のシグナルがあれば、`Result` の前に ack を返す（#4282）。コマンドが終わっていれば
    // `exited`、そうでなければ pidfd が届かないままだったので `not_started`。要求元が消えていれば送れず、結果は捨てる。
    if let Some((signal, _)) = signal_state.pending.take() {
        let code = match outcome {
            StreamExecOutcome::Exited(_) | StreamExecOutcome::Signaled(_) => SignalAckCode::Exited,
            _ => SignalAckCode::NotStarted,
        };
        let _ = channel::send_signal_ack(channel, signal, code, Instant::now() + SIGNAL_ACK_BUDGET);
    }
    // 失敗の段: 通知・`Started` の送信で覚えたものを優先し、無ければ実行役の失敗（`Failed`）を `helper_exec` とする。
    // 取り消し（要求元の消滅）は従来の行があるので足さない。
    let failure = match created_failure.take() {
        Some(f) => Some(f),
        None if cancelled.get() => None,
        None => match outcome {
            StreamExecOutcome::Failed(code) => {
                Some(HelperFailure::new(HelperStage::Exec, code, None))
            }
            _ => None,
        },
    };
    ServeReport { outcome, failure }
}

/// 保留のシグナルを持つ猶予の上限: コマンドの pidfd が届かないまま過ぎたら `not_started` を返す（REPAIR-5）。
const SIGNAL_START_GRACE: Duration = Duration::from_secs(2);
/// `SignalAck` の送信に割り当てる上限（exec の待ちの刻みの中で呼ばれるため短くする。REPAIR-5）。
const SIGNAL_ACK_BUDGET: Duration = Duration::from_millis(500);

/// helper が持つシグナルの状態（単一スレッド。#4282）。
#[derive(Default)]
struct SignalState {
    /// 受け取って結果を返していないシグナルと、受け取った時刻（保留は 1 件まで）。
    pending: std::cell::Cell<Option<(ExecSignal, Instant)>>,
    /// 受信に失敗した（frame の境界を信頼できないため、以後は受信も ack の送信もしない）。
    dead: std::cell::Cell<bool>,
    /// `Spawned` を送る試行を済ませた（成功・失敗を問わず再送しない。#4316）。
    spawned_sent: std::cell::Cell<bool>,
}

/// `Spawned` を高々 1 回だけ best-effort で送る（#4316・SUP-6）。送信の失敗は握りつぶす（pid は表示用で、`Result` と exec は
/// 止めない）。部分書き込みで後続の frame の境界が崩れる窓は `SignalAck` と同じ残余（期限は [`SIGNAL_ACK_BUDGET`]）。
fn send_spawned_once(channel: &UnixStream, state: &SignalState, pid: NonZeroU32) {
    if state.spawned_sent.replace(true) {
        return;
    }
    let _ = channel::send_spawned(channel, pid, Instant::now() + SIGNAL_ACK_BUDGET);
}

/// exec の待ちの刻みごとのシグナル処理（[`ExecLaunchIo::signal`] の実体。#4282・SUP-6・SEC-1・REPAIR-5）。
///
/// 保留が無ければ fd 0 の `Signal` を 1 件だけ（待たずに）受ける。保留があれば [`CommandSignaler::deliver`] を試し、結果を
/// `SignalAck` で返す（`NotStarted` は [`SIGNAL_START_GRACE`] まで保留して再試行）。受信に失敗した（壊れた frame・許可外の番号・
/// 旧い版・fd 付き）ときは以後シグナルを受けず（ack も返さない）、固定語彙の診断行を 1 行出す。exec は止めず従来の期限で終わる。
fn signal_tick(channel: &UnixStream, state: &SignalState, signaler: &dyn CommandSignaler) {
    // コマンドの pid が worker から届いていれば、同じ刻みの `SignalAck` より前に `Spawned` を送る（#4316）。
    if !state.spawned_sent.get()
        && let Some(pid) = signaler.command_pid()
    {
        send_spawned_once(channel, state, pid);
    }
    if state.pending.get().is_none() && !state.dead.get() {
        match channel::try_recv_signal(channel) {
            Ok(Some(signal)) => state.pending.set(Some((signal, Instant::now()))),
            Ok(None) => {}
            Err(_) => {
                state.dead.set(true);
                diagnose(
                    "invalid-argument",
                    "stream-exec received a malformed signal frame; further signals are ignored",
                );
            }
        }
    }
    let Some((signal, since)) = state.pending.get() else {
        return;
    };
    let code = match signaler.deliver(signal.number()) {
        ExecSignalDelivery::Delivered => SignalAckCode::Delivered,
        ExecSignalDelivery::Exited => SignalAckCode::Exited,
        ExecSignalDelivery::NotStarted => {
            if since.elapsed() < SIGNAL_START_GRACE {
                return;
            }
            SignalAckCode::NotStarted
        }
        // `Unavailable` と将来の未知の結果は、送れなかったものとして返す（fail-closed）。
        _ => SignalAckCode::Unavailable,
    };
    state.pending.set(None);
    let _ = channel::send_signal_ack(channel, signal, code, Instant::now() + SIGNAL_ACK_BUDGET);
}

/// 受け取った stdin・stdout・stderr の fd が AF_UNIX の socket か FIFO（pipe）であることを確かめる（SUP-6・SEC-1・#3761）。
///
/// 通常ファイル・ディレクトリ・文字デバイス（tty・pty・`/dev/null` を含む）・ブロックデバイスは `InvalidArgument`。
/// ホストの端末 fd をコンテナのコマンドへ渡すと `TIOCSTI` 等で境界を越えうるため、plugin-cri が作る socketpair か
/// pipe 以外を受けない。fd は複製して `fstat` し、複製は直ちに閉じる（`unsafe` なし）。
fn require_stdio_kinds(fds: &channel::StdioFds) -> Result<(), HelperFailure> {
    let internal = |e: std::io::Error| {
        HelperFailure::new(
            HelperStage::StdioKind,
            ErrorCode::Internal,
            e.raw_os_error(),
        )
    };
    for fd in [&fds.stdin, &fds.stdout, &fds.stderr].into_iter().flatten() {
        let dup = fd.as_fd().try_clone_to_owned().map_err(internal)?;
        let file = std::fs::File::from(dup);
        let ty = file.metadata().map_err(internal)?.file_type();
        if !(ty.is_socket() || ty.is_fifo()) {
            return Err(HelperFailure::new(
                HelperStage::StdioKind,
                ErrorCode::InvalidArgument,
                None,
            ));
        }
    }
    Ok(())
}

/// fd 0 の複製を channel として確保する。socket でなければ `None`（fail-closed）。`unsafe` を使わず、複製した fd が
/// socket であることを `fstat` で確かめてから `UnixStream` にする。
fn channel_from_stdin() -> Result<UnixStream, HelperFailure> {
    let fail = |errno: Option<i32>| {
        HelperFailure::new(HelperStage::Channel, ErrorCode::InvalidArgument, errno)
    };
    let dup = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|e| fail(e.raw_os_error()))?;
    let file = std::fs::File::from(dup);
    let meta = file.metadata().map_err(|e| fail(e.raw_os_error()))?;
    if !meta.file_type().is_socket() {
        return Err(fail(None));
    }
    Ok(UnixStream::from(OwnedFd::from(file)))
}

/// fd 2 へ構造化された診断行を 1 本書く（要求元の消滅の取り消しの行。固定語彙のみ）。
fn diagnose(code: &str, message: &str) {
    let mut err = std::io::stderr();
    let _ = writeln!(err, "{{\"code\":\"{code}\",\"message\":\"{message}\"}}");
    let _ = err.flush();
}

/// helper の入口。`args` はサブコマンド名を除いた引数列。結果を channel へ送れたら 0、送れなければ 1 を返す。
pub fn run_stream_exec_main<I>(args: I) -> ExitCode
where
    I: IntoIterator<Item = OsString>,
{
    // 継承 fd の整理が最初。fd 0〜2 は呼び出し側の `Command` が置いたものだけを使う。
    let _ = crate::sys::close_fds_from(3);
    let channel = match channel_from_stdin() {
        Ok(channel) => channel,
        Err(failure) => {
            write_failure_line(&failure);
            return ExitCode::FAILURE;
        }
    };
    let ServeReport { outcome, failure } = run_with_channel(&channel, args);
    // 診断行は `Result` の送信より前に書く（読み手は `Result` を受けてから停止し、短い drain で残りを読むため）。
    if let Some(failure) = failure {
        write_failure_line(&failure);
    }
    match channel::send_result(&channel, &outcome, Instant::now() + SEND_BUDGET) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            write_failure_line(&HelperFailure::new(
                HelperStage::ResultSend,
                e.code(),
                e.errno(),
            ));
            ExitCode::FAILURE
        }
    }
}

/// 起動の失敗 1 件を fd 2 へ 1 行で書く（[`HelperFailure::diagnostic_line`]。固定語彙と整数だけ）。
///
/// fd 2 は読み手が読まない・端だけ保持することがあるため、待たない最善努力の送信
/// （`emit_diagnostic_line_to`。`MSG_DONTWAIT`）にする。満杯なら捨て、後続の `Result` の送信を止めない（REPAIR-5）。
fn write_failure_line(failure: &HelperFailure) {
    write_failure_line_to(std::io::stderr().as_fd(), failure);
}

fn write_failure_line_to(out: BorrowedFd<'_>, failure: &HelperFailure) {
    let _ = emit_diagnostic_line_to(out, &failure.diagnostic_line());
}

fn run_with_channel<I>(channel: &UnixStream, args: I) -> ServeReport
where
    I: IntoIterator<Item = OsString>,
{
    // dumpable を落とせないまま特権操作へ進まない（fail-closed。SEC-1）。
    if let Err(e) = crate::sys::set_dumpable(false) {
        return early(HelperStage::Dumpable, ErrorCode::Internal, e.raw_os_error());
    }
    let args = match StreamExecArgs::parse(args) {
        Ok(args) => args,
        Err(e) => return early_trait(HelperStage::Args, &e),
    };
    let store = match crate::state::open_default_store(Some(args.root().to_path_buf())) {
        Ok(store) => store,
        Err(e) => return early_trait(HelperStage::StateOpen, &e),
    };
    let source = ControlExecHandover::new(args.root().to_path_buf());
    let deps = Deps {
        store: store.as_ref(),
        source: &source,
        make_sink: &production_sink,
        launch_env: &crate::container_options::store::launch_env_for,
        run: &production_runner,
    };
    serve_reporting(channel, &args, &deps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::exec::ExecChildStep;

    fn os(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    fn good() -> Vec<OsString> {
        os(&[
            "--root",
            "/run/fandhe",
            "--id",
            "web1",
            "--expect-pid",
            "4242",
            "--timeout-ms",
            "28000",
            "--stdio",
            "7",
            "--",
            "/bin/echo",
            "hello world",
        ])
    }

    /// SUP-6・REPAIR-5（#4284）: 満杯の診断 socket へも `write_failure_line_to` は停止せず戻り、空きがあれば行が届く。
    #[test]
    fn sup6_4284_write_failure_line_does_not_block_on_full_socket() {
        let (a, mut b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        let chunk = [b'x'; 4096];
        let mut filled = 0usize;
        while let Ok(n) = std::io::Write::write(&mut &a, &chunk) {
            filled += n;
            assert!(filled < 64 << 20, "socket never filled");
        }
        assert!(filled > 0);
        let failure = HelperFailure::new(HelperStage::ResultSend, ErrorCode::Internal, Some(32));
        let t = Instant::now();
        write_failure_line_to(a.as_fd(), &failure);
        assert!(t.elapsed() < Duration::from_secs(2));
        // 満杯の間に書いた分は捨てられ、drain 後の送信は 1 行そのまま届く。
        b.set_nonblocking(true).unwrap();
        let mut buf = vec![0u8; 1 << 16];
        let mut drained = 0usize;
        while let Ok(n) = std::io::Read::read(&mut b, &mut buf) {
            if n == 0 {
                break;
            }
            drained += n;
        }
        assert_eq!(drained, filled, "full-socket write must be dropped");
        write_failure_line_to(a.as_fd(), &failure);
        let n = std::io::Read::read(&mut b, &mut buf).unwrap();
        let expected = format!("{}\n", failure.diagnostic_line());
        assert_eq!(&buf[..n], expected.as_bytes());
    }

    /// SUP-6・REPAIR-5（#3760）: `Started` の送信期限は `total_deadline` で頭打ちになり、期限後は送られず `Timeout` になる。
    #[test]
    fn sup6_3760_started_send_deadline_is_capped_by_total_deadline() {
        let now = Instant::now();
        let far = now + Duration::from_secs(60);
        assert_eq!(started_send_deadline(now, far), now + SEND_BUDGET);
        let near = now + Duration::from_millis(100);
        assert_eq!(started_send_deadline(now, near), near);
        // 残りがほぼ 0（期限切れ）: 送信は Started を出さず Timeout で失敗する。
        let (a, mut b) = UnixStream::pair().unwrap();
        let expired = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        let deadline = started_send_deadline(Instant::now(), expired);
        let err = channel::send_started(&a, &ExecCgroupName::new("exec-4242-0").unwrap(), deadline)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::Timeout);
        b.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut buf = [0u8; 1];
        assert!(
            std::io::Read::read(&mut b, &mut buf).is_err(),
            "no Started bytes may be sent"
        );
    }

    fn reject(args: Vec<OsString>, why: &str) {
        let err = StreamExecArgs::parse(args).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument, "{why}");
    }

    /// SUP-6・REPAIR-2（#3760）: 正常な引数は検証済みの値になり、`to_args` で元の並びへ戻る。
    #[test]
    fn sup6_3760_parse_roundtrips_the_documented_form() {
        let parsed = StreamExecArgs::parse(good()).unwrap();
        assert_eq!(parsed.root(), Path::new("/run/fandhe"));
        assert_eq!(parsed.id().as_str(), "web1");
        assert_eq!(parsed.expect_pid().get(), 4242);
        assert_eq!(parsed.timeout(), Duration::from_millis(28_000));
        assert_eq!(parsed.stdio().bits(), 7);
        assert_eq!(
            parsed.command(),
            ["/bin/echo".to_string(), "hello world".into()]
        );
        assert_eq!(parsed.to_args(), good());
    }

    /// SEC-1・REPAIR-5（#3760）: ミリ秒未満の端数は切り上げて正規化し、`to_args` は常に parse が受ける形になる。
    #[test]
    fn sec1_3760_new_rounds_sub_millisecond_timeout_up() {
        let build = |t: Duration| {
            StreamExecArgs::new(
                PathBuf::from("/run/fandhe"),
                ContainerId::new("web1").unwrap(),
                NonZeroU32::new(4242).unwrap(),
                t,
                StdioMask::new(7).unwrap(),
                vec!["/bin/echo".to_string()],
            )
        };
        for (input, ms) in [
            (Duration::from_micros(500), 1),
            (Duration::from_nanos(1), 1),
            (Duration::from_micros(1_500), 2),
            (Duration::from_millis(3), 3),
        ] {
            let args = build(input).unwrap();
            assert_eq!(args.timeout(), Duration::from_millis(ms));
            let reparsed = StreamExecArgs::parse(args.to_args()).unwrap();
            assert_eq!(reparsed.timeout(), Duration::from_millis(ms));
        }
        assert!(build(Duration::ZERO).is_err());
    }

    /// SEC-1・REPAIR-5（#3760）: 不正な形はすべて `InvalidArgument` で拒否する。
    #[test]
    fn sec1_3760_parse_rejects_every_malformed_form() {
        let set = |idx: usize, value: &str| {
            let mut v = good();
            v[idx] = OsString::from(value);
            v
        };
        reject(set(1, "relative/root"), "relative root");
        reject(set(3, "bad id/with slash"), "bad id");
        reject(set(5, "0"), "pid 0");
        reject(set(7, "0"), "timeout 0");
        reject(set(7, "3600001"), "timeout over the limit");
        reject(set(7, "abc"), "timeout not a number");
        reject(set(9, "8"), "reserved stdio bit");
        reject(set(9, "256"), "stdio out of u8");
        reject(set(11, "bin/relative"), "relative argv0");
        let mut unknown = good();
        unknown.splice(0..0, os(&["--env", "A=B"]));
        reject(unknown, "env is not accepted");
        let mut dup = good();
        dup.splice(0..0, os(&["--id", "other"]));
        reject(dup, "duplicate option");
        reject(
            good().into_iter().filter(|a| a != "--").collect(),
            "missing separator",
        );
        reject(good().into_iter().take(11).collect(), "empty command");
        reject(good().into_iter().skip(2).collect(), "missing root");
        reject(os(&[]), "no arguments");
    }

    /// SEC-1・REPAIR-5（#3760）: argv は件数の上限を超えた時点で拒否し、1 要素の上限と NUL も拒否する。
    #[test]
    fn sec1_3760_parse_enforces_argv_limits() {
        let mut at_limit = good();
        at_limit.truncate(11);
        at_limit.extend((0..ENTRYPOINT_MAX_ARGS).map(|_| OsString::from("/b")));
        // 先頭が絶対パスの 4096 件はちょうど上限内。
        assert!(StreamExecArgs::parse(at_limit.clone()).is_ok());
        at_limit.push(OsString::from("x"));
        reject(at_limit, "4097 elements");

        let mut huge = good();
        huge.truncate(11);
        huge.push(OsString::from("/b"));
        huge.push(OsString::from(
            "x".repeat(fandhe_container_core::exec::ENTRYPOINT_MAX_STRING_BYTES),
        ));
        reject(huge, "one element over the size limit");

        let mut nul = good();
        nul.truncate(11);
        nul.push(OsString::from("/b"));
        nul.push(OsString::from("a\0b"));
        reject(nul, "NUL byte");
    }

    /// SUP-6（#3760）: 起動の判定は第 1 引数が `stream-exec` のときだけ。
    #[test]
    fn sup6_3760_invocation_detection() {
        assert!(is_stream_exec_invocation(Some(OsStr::new("stream-exec"))));
        assert!(!is_stream_exec_invocation(Some(OsStr::new(
            "healthcheck-exec"
        ))));
        assert!(!is_stream_exec_invocation(None));
    }

    /// SUP-6（#3760）: 結果の写像（終了コード・シグナル・起動前の失敗・拒否・範囲外）を具体値で固定する。
    #[test]
    fn sup6_3760_outcome_mapping() {
        use fandhe_container_core::exec::ExecExit as E;
        let ok = |e: ExecExit| outcome_from_result(Ok(e));
        assert_eq!(
            ok(E::Command(ChildExit::Exited(0))),
            StreamExecOutcome::Exited(0)
        );
        assert_eq!(
            ok(E::Command(ChildExit::Exited(3))),
            StreamExecOutcome::Exited(3)
        );
        assert_eq!(
            ok(E::Command(ChildExit::Signaled(9))),
            StreamExecOutcome::Signaled(ExitSignal::new(9).unwrap())
        );
        assert_eq!(
            ok(E::SetupFailed {
                exit: ChildExit::Exited(127),
                violation: None,
                code: ErrorCode::NotFound,
                step: Some(ExecChildStep::Execveat),
            }),
            StreamExecOutcome::NotStarted {
                exit: ChildStatus::Exited(127),
                step: Some(ExecChildStep::Execveat),
                code: ErrorCode::NotFound,
            }
        );
        assert_eq!(
            ok(E::Command(ChildExit::Exited(300))),
            StreamExecOutcome::Failed(ErrorCode::Internal)
        );
        assert_eq!(
            ok(E::Command(ChildExit::Signaled(0))),
            StreamExecOutcome::Failed(ErrorCode::Internal)
        );
        assert_eq!(
            outcome_from_result(Err(AuditedRejection::not_applicable(TraitError::new(
                ErrorCode::Timeout,
                "exec timed out before starting the command"
            )))),
            StreamExecOutcome::Failed(ErrorCode::Timeout)
        );
    }
}
