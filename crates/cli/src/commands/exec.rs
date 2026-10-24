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
    use std::os::fd::{AsFd as _, BorrowedFd};
    use std::path::Path;
    use std::time::{Duration, Instant};

    use fandhe_container_core::audit_log::{AuditSink, AuditedRejection};
    use fandhe_container_core::exec::{ChildExit, ExecExit};
    use fandhe_container_core::oci_runtime::OCI_EXIT_INTERNAL;
    use fandhe_container_core::traits::{
        ContainerId, ContainerState, ErrorCode, GetStateRequest, StateRecord, StateStore,
        TraitError,
    };
    use fandhe_container_supervisor::control::{ExecPidfdSource, production_exec_pidfd_source};
    use fandhe_container_supervisor::exec::{
        AuditedOutcome, ExecRequest, default_audit_sink, run_command_with_pidfd,
    };

    use super::super::CliExit;
    use super::super::args::{ExecArgs, GlobalArgs};
    use super::super::create_start::open_store;
    use super::super::list_logs::store_open_failure;
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

    /// 本番入口の `exec`。コマンドの終了コードで終了し（stderr は空）、基盤側の失敗は構造化エラー 1 行で終了する。
    pub(in super::super) fn run_exec(global: &GlobalArgs, args: &ExecArgs) -> CliExit {
        let prepared = ContainerId::new(args.id.as_str())
            .and_then(|id| build_request(args).map(|request| (id, request)));
        let (id, request) = match prepared {
            Ok(v) => v,
            Err(e) => return failure(&e),
        };
        let store = match open_store(global) {
            Ok(s) => s,
            Err(e) => return store_open_failure(&e),
        };
        let source = production_exec_pidfd_source(&store);
        let result = exec_in_container(
            &store,
            source.as_ref(),
            &production_sink,
            &production_runner,
            &id,
            &request,
            args.timeout,
        );
        match result {
            Ok(code) => CliExit::Executed(code),
            Err(e) => failure(&e),
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
