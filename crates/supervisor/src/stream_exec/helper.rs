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
//! - fd 2: 診断行（channel を確保できない場合と、core の診断 JSON 行）
//! - 環境変数は空・cwd は `/`（[`stream_exec_command`]）。引数は [`StreamExecArgs`] の形式
//!
//! # 処理順
//!
//! `close_fds_from(3)` → fd 0 を channel として確保 → `set_dumpable(false)` → 引数の解釈 → 状態記録の照合（`Running` かつ
//! pid が `--expect-pid` と一致。不一致は exec も監査もしない）→ launch 時 env の読み込み → 監査 sink の構築（作れなければ
//! exec も pidfd の要求もしない。SEC-4）→ kind 6 で pidfd の複製を受ける（孤児は `Unavailable`。記録 pid からの
//! `pidfd_open` へは縮退しない。SEC-1）→ `StdioHandover` の受信（mask は `--stdio` と一致が必要）→ exec の通し
//! （`on_created` で kind 7 の通知と ack の後に `Started` を送る）→ `Result` の送信。以降の失敗はすべて `Result` frame で返す。
//!
//! # 接続断・期限（REPAIR-5）
//!
//! すべての待ち（kind 6・stdio・kind 7・exec 全体・結果の送信）に期限がある。plugin-cri が helper を kill すれば、
//! helper が持つ制御チャネルの接続が閉じ、supervisor の `exec_guard` が通知済みの exec 子 cgroup を回収する。
//! PDEATHSIG は使わない（plugin-cri は多スレッドで、子を作ったスレッドの終了で誤発火するため。`unsafe` も足さない）。
//!
//! # 未実装・残余（REPAIR-3）
//!
//! - tty（pty の割り当てと `PtyMaster` の送信）は #3758・#3761 の範囲で、本 helper は `--tty` を受けない。
//! - helper は単一スレッドのため fd 0 を見張れない。plugin-cri が helper を kill せずに異常終了した場合や channel だけを
//!   閉じた場合は、exec の期限（`--timeout-ms`）が来て worker が止まり helper が終わるまで動く（上限は期限 + `hold_grace`）。
//! - launch 時 env の読み込み（`launch_env_for`）は I/O が止まり得るが、単一スレッドを保つため期限つきの作業スレッドで
//!   包まない（healthcheck helper・CLI exec と同じ残余）。
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
use fandhe_container_core::exec::{ChildExit, ENTRYPOINT_MAX_ARGS, ExecCgroupName, ExecExit};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, GetStateRequest, StateRecord, StateStore, TraitError,
};

use super::channel::{self, ChannelError};
use super::wire::{
    ChildStatus, ExitSignal, StdioMask, StreamExecOutcome, error_code_to_u8, step_to_u8,
};
use crate::control::protocol::MAX_EXEC_HOLD_SECS;
use crate::control::{ControlExecHandover, ExecPidfdSource};
use crate::exec::{ExecLaunchIo, ExecRequest, ExecStdio, default_audit_sink};

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

/// 実行役の型（本番は `production_runner`。試験は偽を渡す）。成功側は終了状態だけに絞る。
pub type Runner<'a> = dyn Fn(
        &StateRecord,
        BorrowedFd<'_>,
        &ExecRequest,
        Duration,
        &dyn AuditSink,
        ExecLaunchIo<'_>,
    ) -> Result<ExecExit, AuditedRejection<TraitError>>
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
) -> Result<ExecExit, AuditedRejection<TraitError>> {
    crate::exec::run_command_with_pidfd_output_notify(record, pidfd, request, timeout, audit, io)
        .map(|audited| audited.outcome.exit)
}

fn failed(e: &TraitError) -> StreamExecOutcome {
    StreamExecOutcome::Failed(e.code())
}

fn channel_failed(e: &ChannelError) -> StreamExecOutcome {
    StreamExecOutcome::Failed(e.code())
}

/// `Started` の送信期限。`SEND_BUDGET` を `total_deadline` で頭打ちにする（期限後に `Started` を出さない。REPAIR-5・SUP-6）。
/// 期限切れ（`now >= total_deadline`）なら期限は `now` となり、`send_started` は送らず `Timeout` で失敗する。
fn started_send_deadline(now: Instant, total_deadline: Instant) -> Instant {
    total_deadline.min(now + SEND_BUDGET)
}

/// 前提検査から exec の通しまで（処理順はモジュール doc）。`channel` へは `Started` だけを送り、`Result` は返り値で
/// 呼び出し側（[`run_stream_exec_main`]）が送る。
pub fn serve(channel: &UnixStream, args: &StreamExecArgs, deps: &Deps<'_>) -> StreamExecOutcome {
    let started = Instant::now();
    let total_deadline = started.checked_add(args.timeout()).unwrap_or(started);

    let record = match deps.store.get(&GetStateRequest::new(args.id().clone())) {
        Ok(record) => record,
        Err(e) => return failed(&e),
    };
    let status = record.status();
    if status.state() != ContainerState::Running || status.pid() != Some(args.expect_pid()) {
        return StreamExecOutcome::Failed(ErrorCode::FailedPrecondition);
    }
    let launch_env = match (deps.launch_env)(args.root(), &record) {
        Ok(env) => env,
        Err(e) => return failed(&e),
    };
    // 監査の記録先を先に作る（作れなければ supervisor へ接続も exec もしない。fail-closed。SEC-4）。
    let sink = match (deps.make_sink)(args.root()) {
        Ok(sink) => sink,
        Err(e) => return failed(&e),
    };
    let request = match args
        .command()
        .first()
        .map(|first| ExecRequest::new(first.as_str(), args.command().iter().cloned()))
    {
        Some(Ok(request)) => request,
        Some(Err(e)) => return failed(&e),
        None => return StreamExecOutcome::Failed(ErrorCode::InvalidArgument),
    };

    // 接続（`handover`）は exec の後始末が終わるまで保持する。drop が切断で、supervisor は通知済みの exec 子 cgroup を回収する。
    let pid = args.expect_pid();
    let handover_deadline = total_deadline.min(Instant::now() + HANDOVER_BUDGET);
    let handover = match deps.source.obtain(args.id(), pid, handover_deadline) {
        Ok(handover) => handover,
        Err(e) => return failed(&e),
    };

    let stdio_deadline = total_deadline.min(Instant::now() + STDIO_BUDGET);
    let fds = match channel::recv_stdio_handover(channel, args.stdio(), stdio_deadline) {
        Ok(fds) => fds,
        Err(e) => return channel_failed(&e),
    };

    let remaining = total_deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return StreamExecOutcome::Failed(ErrorCode::Timeout);
    }
    // 通知（kind 7 と ack）に成功してから `Started` を送る。どちらかが失敗したら worker を fork せず exec を中止する。
    let on_created = |name: &ExecCgroupName| -> Result<(), TraitError> {
        handover.notify_created(name, total_deadline)?;
        channel::send_started(
            channel,
            started_send_deadline(Instant::now(), total_deadline),
        )
        .map_err(|e| TraitError::new(e.code(), "failed to report the exec start to the caller"))
    };
    let io = ExecLaunchIo {
        launch_env: &launch_env,
        stdio: ExecStdio {
            stdin: fds.stdin.as_ref().map(AsFd::as_fd),
            stdout: fds.stdout.as_ref().map(AsFd::as_fd),
            stderr: fds.stderr.as_ref().map(AsFd::as_fd),
        },
        on_created: Some(&on_created),
    };
    let result = (deps.run)(
        &record,
        handover.pidfd(),
        &request,
        remaining,
        sink.as_ref(),
        io,
    );
    outcome_from_result(result)
}

/// fd 0 の複製を channel として確保する。socket でなければ `None`（fail-closed）。`unsafe` を使わず、複製した fd が
/// socket であることを `fstat` で確かめてから `UnixStream` にする。
fn channel_from_stdin() -> Option<UnixStream> {
    let dup = std::io::stdin().as_fd().try_clone_to_owned().ok()?;
    let file = std::fs::File::from(dup);
    if !file.metadata().ok()?.file_type().is_socket() {
        return None;
    }
    Some(UnixStream::from(OwnedFd::from(file)))
}

/// fd 2 へ構造化された診断行を 1 本書く（channel を確保できない場合の唯一の報告口。固定語彙のみ）。
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
    let Some(channel) = channel_from_stdin() else {
        diagnose("invalid-argument", "stream-exec requires a socket on fd 0");
        return ExitCode::FAILURE;
    };
    let outcome = run_with_channel(&channel, args);
    match channel::send_result(&channel, &outcome, Instant::now() + SEND_BUDGET) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

fn run_with_channel<I>(channel: &UnixStream, args: I) -> StreamExecOutcome
where
    I: IntoIterator<Item = OsString>,
{
    // dumpable を落とせないまま特権操作へ進まない（fail-closed。SEC-1）。
    if crate::sys::set_dumpable(false).is_err() {
        return StreamExecOutcome::Failed(ErrorCode::Internal);
    }
    let args = match StreamExecArgs::parse(args) {
        Ok(args) => args,
        Err(e) => return failed(&e),
    };
    let store = match crate::state::open_default_store(Some(args.root().to_path_buf())) {
        Ok(store) => store,
        Err(e) => return failed(&e),
    };
    let source = ControlExecHandover::new(args.root().to_path_buf());
    let deps = Deps {
        store: store.as_ref(),
        source: &source,
        make_sink: &production_sink,
        launch_env: &crate::container_options::store::launch_env_for,
        run: &production_runner,
    };
    serve(channel, &args, &deps)
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
        let err = channel::send_started(&a, deadline).unwrap_err();
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
