//! `exec` コマンド本体（稼働中コンテナの中でコマンドを実行する。SUP-6・SEC-4・CLI-1・#2626）。
//!
//! `commands::run` が argv を解析した後に [`run_exec`] を呼ぶ。実処理は supervisor crate の
//! `exec::run_command_with_pidfd`（pidfd 固定・namespace / cgroup 参加・制限の再適用・1 拒否 1 件の監査記録）へ委ね、
//! 本 module はその呼び出しに必要な 3 つを揃える配線だけを持つ。
//!
//! # 配線（なぜこの順か）
//!
//! 1. 要求の構築（`ExecRequest`: 絶対パス・argv・`--env` の上限検証。状態ルートを触る前に不正入力を断る）
//! 2. 状態ストアを開き、記録が `Running` で pid を持つことを確かめる
//! 3. 監査の記録先を作る（[`default_audit_sink`]。`<状態ルート>/@audit.log`）。**作れなければ exec しない**（fail-closed。
//!    監査なしで実行する経路は無い。SEC-4）。supervisor へ接続する前に作るのは、監査できない exec のために pidfd を
//!    複製させないため
//! 4. supervisor の制御チャネルから起動時 pidfd の複製を受け取る（`ExecPidfdSource`。`state.json` の pid から
//!    `pidfd_open` する縮退はしない。SEC-1）
//! 5. `run_command_with_pidfd` を呼ぶ（監査 sink を必須引数として渡す）
//!
//! 委譲スコープ（#2626 の review 対応）: core の cgroup 参加は移動元と移動先の共通祖先への書き込み権を要するため、
//! ログインセッションの cgroup からでは `PermissionDenied` になる。`run_exec` は 1 の検査と「稼働中か」の確認の後、
//! 自分自身を `systemd-run --user --scope -p Delegate=yes --` で再実行し（目印の環境変数で再帰を止める）、
//! スコープ内の実行が 2〜5 を行う。親は子の終了コードを引き継ぐ。計測（`OpRecorder`、操作名 `exec`）は
//! 実行した側が 1 回だけ行う（REPAIR-4）。
//!
//! 5 の呼び出しプロセスは **単一スレッド** でなければならない（`setns` は多スレッドを拒否する。core の
//! `fork_single_threaded` が実行時にも強制する）。本 module は 1〜4 でスレッドを起こさない（`plugin_backend` を通る
//! 非 Linux の経路は別）。pidfd（`OwnedFd`）は関数を抜けると閉じ、コマンドへは渡らない（core が `execveat` の前に
//! `close_range` で閉じる）。
//!
//! # 終了コード（ERR-2 との重なり）
//!
//! - コマンドが起動した（`ExecExit::Command`）: `Exited(n)` は `n` をそのまま、`Signaled(s)` は `128 + s`。
//! - コマンドが起動していない（`ExecExit::SetupFailed`。`execve` 前の失敗）: 子の終了状態をそのまま返す
//!   （通常 125 / 126 / 127）。分離違反の拒否は supervisor 側で層 `entrypoint` の監査に 1 件記録済み。
//! - 拒否・期限超過・到達不能（`run_command_with_pidfd` の `Err`、pidfd の受け渡しの失敗等）: エラーコードを ERR-2 の
//!   `OCI_EXIT_*`（1〜10）に写し、stderr に `{"code","message"}` の 1 行を出す。
//!
//! コマンド自身の終了コード 1〜10 は `OCI_EXIT_*` と重なる。見分けは **stderr の構造化エラー行の有無**
//! （行があれば基盤側の失敗、無ければコマンドの終了コード。docker exec と同じ考え方）。`AuditDelivery::SinkFailed` のときの
//! 固定スキーマ 1 行の通知は sink が 1 回だけ出す契約なので、本 module は出し直さない。
//!
//! # 未実装・簡易実装（REPAIR-3）
//!
//! - コマンドの標準入出力は `/dev/null` に固定（`exec.rs` のモジュール doc「未実装」）。cwd・ユーザーの指定も無い。
//! - supervisor 不在（孤児化・supervisor の再起動後）の exec は拒否される（起動時 pidfd を失うため。担当は #2688）。
//! - rootful の起動（`start` が `UNIMPLEMENTED`）は対象外。healthcheck の配線は #2441。
//! - 非 Linux は plugin 経由（#1869 の設計・TASK-125）。現状は他のコマンドと同じく fail-closed で失敗する。

#[cfg(target_os = "linux")]
pub(super) use linux::run_exec;

#[cfg(not(target_os = "linux"))]
pub(super) fn run_exec(
    global: &super::args::GlobalArgs,
    _args: &super::args::ExecArgs,
) -> super::CliExit {
    use fandhe_container_core::traits::ErrorCode;

    use super::CliExit;

    // 他のコマンドと同じ plugin 発見機構の拒否に到達させる（OS 別のバックエンド振り分け。CLI-2 の対象外）。
    match super::create_start::open_store(global) {
        Err(e) => super::list_logs::store_open_failure(&e),
        Ok(_) => CliExit::failed(ErrorCode::Unimplemented),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{OsStr, OsString};
    use std::os::fd::{AsFd as _, BorrowedFd};
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::Path;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditSink, AuditedRejection};
    use fandhe_container_core::exec::{ChildExit, ExecExit};
    use fandhe_container_core::observability::OpRecorder;
    use fandhe_container_core::oci_runtime::OCI_EXIT_INTERNAL;
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, ErrorCode, GetStateRequest, StateRecord, StateStore,
        TraitError,
    };
    use fandhe_container_supervisor::control::listener::effective_uid;
    use fandhe_container_supervisor::control::{ExecPidfdSource, production_exec_pidfd_source};
    use fandhe_container_supervisor::exec::{
        AuditedOutcome, ExecRequest, default_audit_sink, run_command_with_pidfd,
    };
    use fandhe_container_supervisor::start_client::locate_systemd_run;
    use fandhe_container_supervisor::start_contract::USER_SCOPE_WRAPPER_ARGS;
    use fandhe_container_supervisor::user_scope::user_manager_env;

    use super::super::CliExit;
    use super::super::args::{ExecArgs, GlobalArgs};
    use super::super::create_start::open_store;
    use super::super::list_logs::{record_op, store_open_failure};
    use crate::error::CliError;

    /// pidfd の受け渡しに割り当てる上限（全体の期限の内側で打ち切る。REPAIR-5）。
    const HANDOVER_BUDGET: Duration = Duration::from_secs(5);

    /// 監査の記録先を作る注入点（本番は [`production_sink`]）。引数は検査済みの状態ルート。
    type SinkFactory<'a> = dyn Fn(&Path) -> Result<Box<dyn AuditSink>, TraitError> + 'a;

    /// `run_command_with_pidfd` の注入点（本番は [`production_runner`]。試験は偽の実行役を渡す）。
    /// 成功側は終了状態（`ExecExit`）だけを返す。`AuditedOutcome` の他の欄（適用件数・監査配送の結果）は CLI の
    /// 終了コードに影響せず、`ExecOutcome` は外から構築できないため、注入点は `ExecExit` に絞る。
    type Runner<'a> = dyn Fn(
            &StateRecord,
            BorrowedFd<'_>,
            &ExecRequest,
            Duration,
            &dyn AuditSink,
        ) -> Result<ExecExit, AuditedRejection<TraitError>>
        + 'a;

    /// 本番の記録先: `<状態ルート>/@audit.log` を主経路にする `FileAuditSink`（#1594）。
    fn production_sink(root: &Path) -> Result<Box<dyn AuditSink>, TraitError> {
        default_audit_sink(Some(root.to_path_buf())).map(|s| Box::new(s) as Box<dyn AuditSink>)
    }

    /// 本番の実行役: supervisor の通しの入口。
    fn production_runner(
        record: &StateRecord,
        pidfd: BorrowedFd<'_>,
        request: &ExecRequest,
        timeout: Duration,
        audit: &dyn AuditSink,
    ) -> Result<ExecExit, AuditedRejection<TraitError>> {
        run_command_with_pidfd(record, pidfd, request, timeout, audit)
            .map(|AuditedOutcome { outcome, .. }| outcome.exit)
    }

    /// 要求を構築する（`ExecRequest::new` が絶対パス・argv・件数・長さ・NUL を検証する。`--env` は上限を検証して足す）。
    fn build_request(args: &ExecArgs) -> Result<ExecRequest, TraitError> {
        let argv = std::iter::once(args.path.clone()).chain(args.args.iter().cloned());
        ExecRequest::new(args.path.as_str(), argv)?.with_env(&args.env)
    }

    /// 子の終了状態をプロセスの終了コードへ写す（`Exited(n)` は `n`、`Signaled(s)` は `128 + s`）。
    /// 範囲外の値は `OCI_EXIT_INTERNAL`（1）に倒す（値を捏造しない）。
    fn child_exit_code(exit: ChildExit) -> u8 {
        let code = match exit {
            ChildExit::Exited(n) => u8::try_from(n).ok(),
            ChildExit::Signaled(s) => s.checked_add(128).and_then(|c| u8::try_from(c).ok()),
            _ => None,
        };
        code.unwrap_or(OCI_EXIT_INTERNAL.get())
    }

    /// 配線の本体。成功は「コマンドの終了コード」（コマンドが起動していない場合の子の終了状態を含む）、
    /// 失敗は基盤側の構造化エラー。順序と契約はモジュール doc。
    pub(super) fn exec_in_container(
        store: &dyn StateStore,
        source: &dyn ExecPidfdSource,
        make_sink: &SinkFactory<'_>,
        run: &Runner<'_>,
        id: &ContainerId,
        request: &ExecRequest,
        timeout: Duration,
    ) -> Result<u8, TraitError> {
        let started = Instant::now();
        let total_deadline = started.checked_add(timeout).unwrap_or(started);

        let record = store.get(&GetStateRequest::new(id.clone()))?;
        let status = record.status();
        let pid = match status.pid() {
            Some(pid) if status.state() == ContainerState::Running => pid,
            _ => {
                return Err(TraitError::new(
                    ErrorCode::FailedPrecondition,
                    "container is not running",
                ));
            }
        };

        // 監査の記録先を先に作る（作れなければ supervisor へ接続も exec もしない。fail-closed）。
        let root = store.host_state_root().ok_or_else(|| {
            TraitError::new(
                ErrorCode::Unimplemented,
                "the state store does not expose a host state root",
            )
        })?;
        let sink = make_sink(root)?;

        // pidfd の受け渡しは全体の期限の内側で、さらに上限を設ける。
        let handover_deadline = total_deadline.min(started + HANDOVER_BUDGET);
        let pidfd = source.obtain(id, pid, handover_deadline)?;

        // 残りの時間が `run_command_with_pidfd` の全体の上限になる（準備から終了待ちまで）。
        let remaining = total_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TraitError::new(
                ErrorCode::Timeout,
                "exec timed out before the command started",
            ));
        }
        match run(&record, pidfd.as_fd(), request, remaining, sink.as_ref()) {
            Ok(exit) => Ok(child_exit_code(exit.child_exit())),
            // 拒否は記録の成否に関わらず覆らない。記録の失敗の通知は sink が 1 回だけ出す（ここでは出し直さない）。
            Err(AuditedRejection { error, .. }) => Err(error),
        }
    }

    /// 委譲スコープの内側で動いていることを子へ伝える環境変数（再実行の無限再帰を止める目印）。
    /// 偽装されても exec 側の cgroup 参加が `PermissionDenied` で fail-closed になるだけで、権限は増えない。
    const IN_SCOPE_ENV: &str = "FANDHE_CONTAINER_EXEC_IN_USER_SCOPE";

    /// 委譲スコープで再実行するコマンドを組む（`systemd-run --user --scope ... -- <自分> <元の argv>`。シェルも文字列連結も使わない）。
    fn scoped_command(
        systemd_run: &Path,
        exe: &Path,
        argv: impl IntoIterator<Item = OsString>,
        xdg: &OsStr,
    ) -> Command {
        let mut cmd = Command::new(systemd_run);
        cmd.args(USER_SCOPE_WRAPPER_ARGS);
        cmd.arg(exe);
        cmd.args(argv);
        cmd.env("XDG_RUNTIME_DIR", xdg);
        cmd.env(IN_SCOPE_ENV, "1");
        cmd
    }

    /// 子プロセスの終了状態を exec の終了コードへ写す（シグナル終了は `128 + s`。範囲外は `OCI_EXIT_INTERNAL`）。
    fn status_to_code(status: std::process::ExitStatus) -> u8 {
        let code = match (status.code(), status.signal()) {
            (Some(c), _) => u8::try_from(c).ok(),
            (None, Some(s)) => s.checked_add(128).and_then(|c| u8::try_from(c).ok()),
            (None, None) => None,
        };
        code.unwrap_or(OCI_EXIT_INTERNAL.get())
    }

    /// 再実行した子が「CLI として最後まで走った」ことを親へ伝える目印ファイルの絶対パス（環境変数）。
    /// systemd-run 自身の失敗（スコープ登録の失敗・user マネージャの stale ソケット等）は、子の CLI が走らないため
    /// 目印が作られず、親が「コマンドの失敗」と取り違えない（終了コード 1〜10 は ERR-2 と重なるため。ERR-2・SUP-6）。
    const RESULT_FILE_ENV: &str = "FANDHE_CONTAINER_EXEC_RESULT_FILE";
    /// 再実行した子へ渡す残り時間（ミリ秒）。子はこれと `--timeout` の小さい方を全体の期限にする（REPAIR-5）。
    const REMAINING_MS_ENV: &str = "FANDHE_CONTAINER_EXEC_REMAINING_MS";
    /// 再実行した子が「CLI として走り始めた」ことを親へ伝える目印ファイルのパス（環境変数）。
    /// 親はこれが作られるまでの systemd-run 自身の stderr（D-Bus 接続失敗等の非 JSON の診断）を捨てる（ERR-1・ERR-2）。
    const START_FILE_ENV: &str = "FANDHE_CONTAINER_EXEC_START_FILE";
    /// 親が子の自前の Timeout 報告を待つ猶予。内側の worker 回収（supervisor の `WORKER_GRACE` 7 秒）と
    /// 子 cgroup の後始末（同 `CHILD_CGROUP_CLEANUP_TIMEOUT` 5 秒）の合計以上にし、通常の期限切れでは
    /// 子が自前の構造化 Timeout を出して cgroup を回収し終えてから親が待ち終えるようにする（REPAIR-5・SUP-6）。
    const PARENT_GRACE: Duration = Duration::from_secs(14);
    /// 親が子を `SIGKILL` した後の回収待ちの上限（無期限に待たない。REPAIR-5）。
    const REAP_BOUND: Duration = Duration::from_secs(2);
    /// systemd-run の stderr を一度に読む量と、捕捉を終えるのを待つ上限。
    const STDERR_CHUNK: usize = 4096;
    const STDERR_DRAIN_WAIT: Duration = Duration::from_secs(1);
    /// 子の終了待ちの確認間隔。
    const WAIT_POLL: Duration = Duration::from_millis(20);

    /// 委譲スコープ内の子が使う期限。環境変数が無い・壊れていれば `--timeout` のまま、あれば小さい方（延長はしない）。
    fn scoped_timeout(requested: Duration) -> Duration {
        std::env::var(REMAINING_MS_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|ms| requested.min(Duration::from_millis(ms).max(Duration::from_millis(1))))
            .unwrap_or(requested)
    }

    /// 子が最後まで走ったことを示す目印を作る（`create_new` で既存・symlink を辿らない。失敗は親が wrapper 失敗と判断する）。
    fn write_result_marker() {
        write_marker(RESULT_FILE_ENV);
    }

    /// 環境変数 `env` が指すパスへ目印ファイルを作る（無ければ何もしない）。
    fn write_marker(env: &str) {
        let Some(path) = std::env::var_os(env) else {
            return;
        };
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path);
    }

    /// 呼び出しプロセスを user マネージャの委譲スコープへ移すため、自分自身を `systemd-run --user --scope` で再実行する。
    ///
    /// core の cgroup 参加（`exec/cgroup_join.rs`）は移動元と移動先の共通祖先の `cgroup.procs` への書き込み権を要する。
    /// ログインセッションの cgroup からでは祖先が root 所有で `PermissionDenied` になるため、user マネージャ配下
    /// （委譲済み）の scope で実行する。systemd-run は scope 登録後に同じプロセスでコマンドを exec する。
    /// 再実行した子が終了コードと stderr の構造化エラー行を決め、親は終了コードだけを引き継ぐ（stdout は継承。stderr は走り始めの目印までの wrapper の診断を捨て、以降を流す）。
    /// 親は全体の期限（`timeout` + 猶予）の間だけ待ち、超えたら子を止めて回収し `Timeout` を返す（REPAIR-5）。
    /// 子が目印を作らずに終わったとき（systemd-run 自身の失敗）は固定文言の構造化エラーにする。
    /// 前提（systemd-run・user マネージャ）が満たせないときは exec せず失敗する（fail-closed）。
    /// 子を `SIGKILL` して有限時間だけ回収を待つ。回収できたかを返す（待ち続けない。REPAIR-5）。
    fn kill_and_reap(child: &mut std::process::Child) -> bool {
        let _ = child.kill();
        let deadline = Instant::now() + REAP_BOUND;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(WAIT_POLL),
                _ => return false,
            }
        }
    }

    /// systemd-run の stderr を捨てるか流すかを決めながら読み切る（容量は 1 回 `STDERR_CHUNK`、保持しない）。
    /// 子の「走り始めた」目印が出るまでの出力（wrapper の非 JSON 診断）は捨て、出た後（子 CLI 自身の構造化エラー等）は
    /// そのまま親の stderr へ流す。目印は子が最初の出力より前に作る。終了で `done` を立てる。
    fn forward_after_start(
        mut stderr: std::process::ChildStderr,
        start: std::path::PathBuf,
        done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        use std::io::{Read, Write};
        let mut buf = [0u8; STDERR_CHUNK];
        while let Ok(n) = stderr.read(&mut buf) {
            let Some(chunk) = buf.get(..n).filter(|c| !c.is_empty()) else {
                break;
            };
            if start.exists() {
                let mut out = std::io::stderr().lock();
                let _ = out.write_all(chunk);
                let _ = out.flush();
            }
        }
        done.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// 戻り値の後ろは「計測を子が行った」かどうか（起動前の失敗・wrapper の失敗・親の期限切れは親が計測する。REPAIR-4）。
    fn rerun_in_user_scope(timeout: Duration) -> (CliExit, bool) {
        let started = Instant::now();
        let fail = |code: ErrorCode, msg: &str| (CliExit::Error(CliError::new(code, msg)), false);
        let euid = match effective_uid() {
            Ok(u) => u,
            Err(e) => return (failure(&e), false),
        };
        let systemd_run = match locate_systemd_run(euid) {
            Ok(p) => p,
            Err(e) => return fail(e.code(), e.message()),
        };
        let xdg = match user_manager_env(std::env::var_os("XDG_RUNTIME_DIR").as_deref(), euid) {
            Ok(x) => x,
            Err(e) => return fail(ErrorCode::FailedPrecondition, e.message()),
        };
        let Ok(exe) = std::env::current_exe() else {
            return fail(
                ErrorCode::FailedPrecondition,
                "cannot resolve the cli executable path",
            );
        };
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let marker =
            Path::new(&xdg).join(format!("fandhe-exec-{}-{nanos}.done", std::process::id()));
        let mut cmd = scoped_command(&systemd_run, &exe, std::env::args_os().skip(1), &xdg);
        cmd.env(RESULT_FILE_ENV, &marker);
        let start_marker = marker.with_extension("start");
        cmd.env(START_FILE_ENV, &start_marker);
        // 起動前に使った時間を引き、子が内側の期限をそろえて数えられるようにする。
        let remaining = timeout.saturating_sub(started.elapsed());
        cmd.env(REMAINING_MS_ENV, remaining.as_millis().to_string());
        cmd.stderr(std::process::Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(_) => {
                return fail(
                    ErrorCode::Unavailable,
                    "failed to run the command in a user scope",
                );
            }
        };
        let drained = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        match child.stderr.take() {
            Some(stderr) => {
                let (path, flag) = (start_marker.clone(), std::sync::Arc::clone(&drained));
                std::thread::spawn(move || forward_after_start(stderr, path, flag));
            }
            None => drained.store(true, std::sync::atomic::Ordering::SeqCst),
        }
        let deadline = started
            .checked_add(timeout)
            .and_then(|d| d.checked_add(PARENT_GRACE))
            .unwrap_or(started);
        let waited = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(Ok(status)),
                Ok(None) if Instant::now() >= deadline => break None,
                Ok(None) => std::thread::sleep(WAIT_POLL),
                Err(e) => break Some(Err(e)),
            }
        };
        // 子が終わった直後の出力を取りこぼさないよう、捕捉の終了を有限時間だけ待つ。
        let drain_deadline = Instant::now() + STDERR_DRAIN_WAIT;
        while !drained.load(std::sync::atomic::Ordering::SeqCst) && Instant::now() < drain_deadline
        {
            std::thread::sleep(WAIT_POLL);
        }
        let ran = marker.exists();
        let _ = std::fs::remove_file(&marker);
        let _ = std::fs::remove_file(&start_marker);
        match waited {
            None => {
                let _ = kill_and_reap(&mut child);
                fail(
                    ErrorCode::Timeout,
                    "exec timed out waiting for the user scope command",
                )
            }
            Some(Err(_)) => {
                let _ = kill_and_reap(&mut child);
                fail(
                    ErrorCode::Unavailable,
                    "failed to wait for the user scope command",
                )
            }
            Some(Ok(status)) if ran => (CliExit::Executed(status_to_code(status)), true),
            Some(Ok(_)) => fail(
                ErrorCode::Unavailable,
                "the user scope wrapper failed before running the command",
            ),
        }
    }

    /// 本番入口の `exec`。コマンドの終了コードで終了し（stderr は空）、基盤側の失敗は構造化エラー 1 行で終了する。
    ///
    /// 不正入力・コンテナ不在・非稼働は委譲スコープへ移る前に断る。通ったら（まだ委譲スコープの外なら）自分自身を
    /// 委譲スコープで再実行し、スコープ内の実行が本体を行う。全体の成否とレイテンシは 1 回だけ計測する（REPAIR-4）。
    pub(in super::super) fn run_exec(global: &GlobalArgs, args: &ExecArgs) -> CliExit {
        let started = Instant::now();
        let recorder = OpRecorder::new();
        // 委譲スコープ内の子は、最初の出力より前に「走り始めた」目印を作る（wrapper の診断と見分ける）。
        write_marker(START_FILE_ENV);
        let (exit, delegated) = run_exec_inner(global, args);
        // 委譲スコープ内の子は、最後まで走ったことを親へ伝える（systemd-run 自身の失敗と見分ける）。
        write_result_marker();
        // 委譲スコープでの再実行の親は、子が自分の分を記録するため記録しない（二重計上を避ける）。
        if !delegated {
            record_op(&recorder, "exec", is_ok(&exit), started);
        }
        exit
    }

    fn is_ok(exit: &CliExit) -> bool {
        matches!(exit, CliExit::Success | CliExit::Executed(0))
    }

    /// 戻り値の後ろは「計測を委譲スコープの子が行った」かどうか。
    fn run_exec_inner(global: &GlobalArgs, args: &ExecArgs) -> (CliExit, bool) {
        let prepared = ContainerId::new(args.id.as_str())
            .and_then(|id| build_request(args).map(|request| (id, request)));
        let (id, request) = match prepared {
            Ok(v) => v,
            Err(e) => return (failure(&e), false),
        };
        let store = match open_store(global) {
            Ok(s) => s,
            Err(e) => return (store_open_failure(&e), false),
        };
        if std::env::var_os(IN_SCOPE_ENV).is_none() {
            // 早期の拒否（不在・非稼働）は再実行の前に返す。
            match store.get(&GetStateRequest::new(id.clone())) {
                Err(e) => return (failure(&e), false),
                Ok(r) if r.status().state() != ContainerState::Running => {
                    return (
                        failure(&TraitError::new(
                            ErrorCode::FailedPrecondition,
                            "container is not running",
                        )),
                        false,
                    );
                }
                Ok(_) => {}
            }
            return rerun_in_user_scope(args.timeout);
        }
        let source = production_exec_pidfd_source(&store);
        let result = exec_in_container(
            &store,
            source.as_ref(),
            &production_sink,
            &production_runner,
            &id,
            &request,
            scoped_timeout(args.timeout),
        );
        match result {
            Ok(code) => (CliExit::Executed(code), false),
            Err(e) => (failure(&e), false),
        }
    }

    /// 基盤側の失敗: `code` / `message` の構造化エラー（終了コードは ERR-2 の表）。message は core / supervisor が組んだ
    /// 固定文言で、`CliError::new` がサニタイズと上限切り詰めを施す。
    fn failure(e: &TraitError) -> CliExit {
        CliExit::Error(CliError::new(e.code(), e.message()))
    }

    #[cfg(test)]
    mod tests;
}
