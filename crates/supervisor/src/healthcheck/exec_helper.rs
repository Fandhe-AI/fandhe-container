//! healthcheck の exec 専用 helper プロセスの本体（SUP-4・SUP-6・SEC-1・SEC-4・REPAIR-5・#2441）。
//!
//! # 役割と呼び出し文脈
//! supervisor 本体は logs 捕捉スレッド等を持つ多スレッドのため、`setns` を伴う exec 共通関数
//! （`exec::run_command_with_pidfd_output`）を直接呼べない（core が `Threads: 1` を強制する）。そこで本番アダプタ
//! `ExecHealthProbe`（`healthcheck::exec_probe`）は probe のたびに `/proc/self/exe healthcheck-exec ...` を新しい
//! プロセスとして起動し、その単一スレッドのプロセスの中で exec の通しを実行する（`netns-holder` と同じ「自分自身を
//! 別サブコマンドで再実行する」方式。判断記録は `docs/design/healthcheck-exec-helper.md`）。bin の `main` が
//! [`is_health_exec_invocation`] で `run_main` より前に振り分ける。
//!
//! # 契約（fd の割り当てと結果の返し方）
//! - fd 0: 起動時の pidfd の複製（対象 pid1 の固定。SEC-1。core が pidfd と記録 pid の一致を照合する）
//! - fd 1: コマンドの stdout / stderr の出力先（結合した 1 本）。helper 自身は書かない
//! - fd 2: 結果行 1 本（[`HealthExecLine`]。`FCHX1 ...`）。core の診断 JSON 行も同じ fd へ出る
//! - 環境変数は空・cwd は `/`。引数は [`HealthExecArgs`] の形式
//!
//! # 処理順
//! `close_fds_from(3)` → `set_dumpable(false)` → 引数の解釈 → 状態の読み込みと前提検査（`Running`・pid・所有者。
//! 不一致は `stale` で、exec も監査もしない）→ launch 時の env 上書きの読み込み → 監査の記録先の構築
//! （`FileAuditSink` を直接使う。単一スレッドのため中継を通さず、段が落ちない。SEC-4）→ exec の通し → 結果行。
//!
//! # ambient capability（SEC-1）
//! helper 自身は ambient capability を継承したまま動く（rootful の `setns`・cgroup join に必要）。コマンドの
//! `execveat` の前に、core の再適用（`reapply_restrictions`）が bounding・ambient・permitted を落として読み戻す。
//!
//! # 未実装・残余（REPAIR-3）
//! - launch 時 env の読み込み（`container_options::store::launch_env_for`）は、本来 I/O が止まり得るため期限つきの
//!   作業スレッドで包むべきだが、helper は単一スレッドを保つ必要があるため包まない。helper 全体の期限は
//!   exec の期限（アダプタの `T` より短い）と、supervisor 側の exec 子 cgroup の `cgroup.kill` で縛る（helper へ
//!   シグナルは送らない。固まった helper は supervisor が `Child` を保持して次の probe を `Unavailable` にする）。

use std::ffi::{OsStr, OsString};
use std::io::Write as _;
use std::num::NonZeroU32;
use std::os::fd::AsFd as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use fandhe_container_core::audit_log::AuditedRejection;
use fandhe_container_core::exec::ExecExit;
use fandhe_container_core::traits::{
    ContainerId, ContainerState, ErrorCode, GetStateRequest, TraitError,
};

use super::exec_wire::{AuditToken, HealthExecLine};
use crate::exec::{AuditedOutcome, ExecRequest};
use crate::run::MAX_POLL_INTERVAL;

/// helper を起動するサブコマンド名（bin の第 1 引数）。
pub const HEALTH_EXEC_SUBCOMMAND: &str = "healthcheck-exec";

/// helper の `argv[0]`（固定。`/proc/self/exe` のパス文字列を使わない）。
pub const HEALTH_EXEC_ARG0: &str = "fandhe-container-supervisor";

/// 自分自身（`/proc/self/exe`）を `subcommand` で起動する `Command`（`argv[0]` は固定・環境は空・cwd は `/`）。
/// stdio は呼び出し側が設定する。reaper が helper を、supervisor が reaper を起動するときに同じ決め方を使う。
pub fn self_exe_command(subcommand: &str, args: &[OsString]) -> std::process::Command {
    use std::os::unix::process::CommandExt as _;
    let mut command = std::process::Command::new("/proc/self/exe");
    command
        .arg0(HEALTH_EXEC_ARG0)
        .arg(subcommand)
        .args(args)
        .env_clear()
        .current_dir("/");
    command
}

/// `/proc/<pid>/stat` の ppid（4 番目）。`comm` は括弧内に空白や `)` を含み得るため、最後の `)` の後ろから数える。
pub fn parse_stat_ppid(stat: &str) -> Option<u32> {
    let after = stat.get(stat.rfind(')')? + 1..)?;
    // `)` の直後の語が 3 番目（state）、次が ppid。
    after.split_whitespace().nth(1)?.parse().ok()
}

/// この helper を起動した supervisor の pid。helper の親は reaper で、その親が supervisor（3 段。`exec_reaper`）。
/// 親の stat を読めない・親が終わって再親付けされた場合は `None`（fail-closed。呼び出し側は `Stale` にする）。
pub fn calling_supervisor_pid() -> Option<NonZeroU32> {
    let reaper = std::os::unix::process::parent_id();
    let stat = std::fs::read_to_string(format!("/proc/{reaper}/stat")).ok()?;
    NonZeroU32::new(parse_stat_ppid(&stat)?)
}

/// bin の main が helper へ振り分ける呼び出しか（第 1 引数が `healthcheck-exec`）。`run_main` より前に判定する。
pub fn is_health_exec_invocation(first: Option<&OsStr>) -> bool {
    first == Some(OsStr::new(HEALTH_EXEC_SUBCOMMAND))
}

/// helper の引数（検証済み）。
///
/// 形式: `--root <絶対パス> --id <ContainerId> --expect-pid <n> --timeout-ms <n> -- <argv0> [<arg>...]`。
/// 各オプションはちょうど 1 回。未知・重複・欠落・`--` の欠落・空のコマンドは拒否する。コマンドはシェルを通さない
/// argv の配列で、先頭は絶対パスのみ（PATH 探索はしない。#2439 の判断待ち）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthExecArgs {
    root: PathBuf,
    id: ContainerId,
    expect_pid: NonZeroU32,
    timeout: Duration,
    command: Vec<String>,
}

impl HealthExecArgs {
    /// アダプタ側が組み立てる。検証は [`Self::parse`] と同じ規則。
    pub fn new(
        root: PathBuf,
        id: ContainerId,
        expect_pid: NonZeroU32,
        timeout: Duration,
        command: Vec<String>,
    ) -> Result<Self, TraitError> {
        let invalid = || {
            TraitError::new(
                fandhe_container_core::traits::ErrorCode::InvalidArgument,
                "invalid healthcheck exec helper arguments",
            )
        };
        if !root.is_absolute() || timeout.is_zero() || timeout > MAX_POLL_INTERVAL {
            return Err(invalid());
        }
        // コマンドの書式（絶対パス・件数・サイズ・NUL）は exec 共通関数の要求と同じ規則で確かめる。
        let first = command.first().ok_or_else(invalid)?;
        if !std::path::Path::new(first).is_absolute() {
            return Err(invalid());
        }
        ExecRequest::new(first.as_str(), command.iter().cloned())?;
        Ok(Self {
            root,
            id,
            expect_pid,
            timeout,
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
        let invalid = || {
            TraitError::new(
                fandhe_container_core::traits::ErrorCode::InvalidArgument,
                "invalid healthcheck exec helper arguments",
            )
        };
        let mut iter = args.into_iter();
        let (mut root, mut id, mut pid, mut timeout_ms): (
            Option<OsString>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = (None, None, None, None);
        let mut command: Vec<String> = Vec::new();
        let mut separated = false;
        while let Some(arg) = iter.next() {
            if arg == OsStr::new("--") {
                separated = true;
                for rest in iter.by_ref() {
                    if command.len() >= crate::healthcheck::MAX_COMMAND_ARGS {
                        return Err(invalid());
                    }
                    command.push(rest.into_string().map_err(|_| invalid())?);
                }
                break;
            }
            let value = iter.next().ok_or_else(invalid)?;
            let slot_taken = match arg.to_str() {
                Some("--root") => root.replace(value).is_some(),
                Some("--id") => id
                    .replace(value.into_string().map_err(|_| invalid())?)
                    .is_some(),
                Some("--expect-pid") => pid
                    .replace(value.into_string().map_err(|_| invalid())?)
                    .is_some(),
                Some("--timeout-ms") => timeout_ms
                    .replace(value.into_string().map_err(|_| invalid())?)
                    .is_some(),
                _ => return Err(invalid()),
            };
            if slot_taken {
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
        let id = ContainerId::new(id.as_deref().ok_or_else(invalid)?)?;
        Self::new(
            PathBuf::from(root.ok_or_else(invalid)?),
            id,
            expect_pid,
            Duration::from_millis(timeout_ms),
            command,
        )
    }

    /// 状態ルート。
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// 対象コンテナの ID。
    pub fn id(&self) -> &ContainerId {
        &self.id
    }

    /// 呼び出し元が期待する pid1 の記録 pid（restart 後の古い呼び出しを `stale` で弾く）。
    pub fn expect_pid(&self) -> NonZeroU32 {
        self.expect_pid
    }

    /// exec の通しの期限。
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// 実行する argv（先頭は絶対パス）。
    pub fn command(&self) -> &[String] {
        &self.command
    }
}

/// exec の通しの結果を結果行へ写す（純関数）。判定は `health_from_exec_exit` を通す（SUP-4）。
pub fn line_from_result(
    result: Result<AuditedOutcome, AuditedRejection<TraitError>>,
) -> HealthExecLine {
    use fandhe_container_core::exec::ChildExit;
    use fandhe_container_core::traits::{ErrorCode, HealthStatus};
    match result {
        Ok(audited) => {
            let audit = AuditToken::from_delivery(&audited.audit);
            let exit_audit = AuditToken::from_delivery(&audited.exit_audit);
            let internal = || HealthExecLine::Failed {
                code: ErrorCode::Internal,
                audit,
            };
            match audited.outcome.exit {
                ExecExit::SetupFailed {
                    violation,
                    code,
                    step,
                    ..
                } => HealthExecLine::NotStarted {
                    step,
                    code,
                    violation: violation.is_some(),
                    audit,
                },
                exit @ ExecExit::Command(ChildExit::Exited(n)) => {
                    match (u8::try_from(n), super::health_from_exec_exit(exit)) {
                        (Ok(code), Ok(health)) => HealthExecLine::Exited {
                            code,
                            healthy: health == HealthStatus::Healthy,
                            audit,
                            exit_audit,
                        },
                        _ => internal(),
                    }
                }
                ExecExit::Command(ChildExit::Signaled(n)) => match u8::try_from(n) {
                    Ok(signal) if (1..=64).contains(&signal) => HealthExecLine::Signaled {
                        signal,
                        audit,
                        exit_audit,
                    },
                    _ => internal(),
                },
                _ => internal(),
            }
        }
        Err(rejected) => HealthExecLine::Failed {
            code: rejected.error.code(),
            audit: AuditToken::from_delivery(&rejected.delivery),
        },
    }
}

/// helper の入口。`args` はサブコマンド名を除いた引数列。結果行を fd 2 へ書き、書けたら 0、書けなければ 1 を返す。
pub fn run_health_exec_main<I>(args: I) -> ExitCode
where
    I: IntoIterator<Item = OsString>,
{
    // 継承 fd の整理が最初。fd 0〜2 は supervisor の `Command` が置いたものだけを使う。
    let _ = crate::sys::close_fds_from(3);
    // dumpable を落とせないまま特権操作へ進まない（fail-closed。`start_entry::run_main_inner` と同じ。SEC-1）。
    let line = if crate::sys::set_dumpable(false).is_err() {
        HealthExecLine::Failed {
            code: ErrorCode::Internal,
            audit: AuditToken::Na,
        }
    } else {
        match HealthExecArgs::parse(args) {
            Ok(args) => execute(&args),
            Err(_) => HealthExecLine::Invalid,
        }
    };
    let mut err = std::io::stderr();
    match err.write_all(&line.encode()).and_then(|()| err.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

/// 前提検査から exec の通しまで。結果行を返す。
fn execute(args: &HealthExecArgs) -> HealthExecLine {
    let failed = |e: TraitError| HealthExecLine::Failed {
        code: e.code(),
        audit: AuditToken::Na,
    };
    let store = match crate::state::open_default_store(Some(args.root().to_path_buf())) {
        Ok(store) => store,
        Err(e) => return failed(e),
    };
    let record = match store.get(&GetStateRequest::new(args.id().clone())) {
        Ok(record) => record,
        Err(e) => return failed(e),
    };
    // 起動した supervisor 自身（reaper の親。helper の親は reaper）が、記録上の所有者であること。restart 後の古い
    // アダプタからの呼び出しは、exec へ進むと pidfd の不一致が違反として毎回監査されてしまうため、ここで弾く（SUP-1）。
    let parent = calling_supervisor_pid();
    let status = record.status();
    if status.state() != ContainerState::Running
        || status.pid() != Some(args.expect_pid())
        || parent.is_none()
        || record.supervisor_pid() != parent
    {
        return HealthExecLine::Stale;
    }
    let launch_env = match crate::container_options::store::launch_env_for(args.root(), &record) {
        Ok(env) => env,
        Err(e) => return failed(e),
    };
    let sink = match crate::exec::default_audit_sink(Some(args.root().to_path_buf())) {
        Ok(sink) => sink,
        Err(e) => return failed(e),
    };
    let Some(first) = args.command().first() else {
        return HealthExecLine::Invalid;
    };
    let request = match ExecRequest::new(first.as_str(), args.command().iter().cloned()) {
        Ok(request) => request,
        Err(_) => return HealthExecLine::Invalid,
    };
    let (stdin, stdout) = (std::io::stdin(), std::io::stdout());
    // 排他作成に成功した exec 子 cgroup の名前を、結果行より先に fd 2 へ通知する（supervisor はこれを受けた
    // cgroup だけを停止する。pid からの推定はしない）。
    let notify = |name: &fandhe_container_core::exec::ExecCgroupName| {
        let mut err = std::io::stderr();
        let _ = err
            .write_all(&super::exec_wire::encode_cgroup_created(name))
            .and_then(|()| err.flush());
    };
    let result = crate::exec::run_command_with_pidfd_output_notify(
        &record,
        stdin.as_fd(),
        &request,
        args.timeout(),
        &sink,
        crate::exec::ExecLaunchIo {
            launch_env: &launch_env,
            output: Some(stdout.as_fd()),
            on_created: Some(&notify),
        },
    );
    line_from_result(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fandhe_container_core::audit_log::AuditDelivery;
    use fandhe_container_core::exec::{ChildExit, ExecChildStep, ViolationReason};
    use fandhe_container_core::traits::ErrorCode;

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
            "--",
            "/bin/check",
            "--flag",
            "x y",
        ])
    }

    /// SUP-4・SUP-6（#2441）: 正常な引数は検証済みの値になり、`to_args` で元の並びへ戻る。
    #[test]
    fn sup4_2441_parse_accepts_the_documented_form_and_roundtrips() {
        let parsed = HealthExecArgs::parse(good()).unwrap();
        assert_eq!(parsed.root(), std::path::Path::new("/run/fandhe"));
        assert_eq!(parsed.id().as_str(), "web1");
        assert_eq!(parsed.expect_pid().get(), 4242);
        assert_eq!(parsed.timeout(), Duration::from_millis(28_000));
        assert_eq!(
            parsed.command(),
            ["/bin/check".to_string(), "--flag".into(), "x y".into()]
        );
        assert_eq!(parsed.to_args(), good());
    }

    /// SEC-1・REPAIR-2（#2441）: 相対の root・不正な id・pid 0・timeout 0 と上限超過・未知と重複のオプション・
    /// `--` なし・空のコマンド・相対の argv[0] はすべて拒否する。
    #[test]
    fn sup4_2441_parse_rejects_every_malformed_form() {
        let with = |from: usize, to: usize, value: &str| {
            let mut v = good();
            for (i, item) in v.iter_mut().enumerate() {
                if (from..to).contains(&i) {
                    *item = OsString::from(value);
                }
            }
            v
        };
        let reject = |args: Vec<OsString>, why: &str| {
            let err = HealthExecArgs::parse(args).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidArgument, "{why}");
        };
        reject(with(1, 2, "relative/root"), "relative root");
        reject(with(3, 4, "bad id/with slash"), "bad id");
        reject(with(5, 6, "0"), "pid 0");
        reject(with(5, 6, "-1"), "negative pid");
        reject(with(7, 8, "0"), "timeout 0");
        reject(with(7, 8, "60001"), "timeout over the limit");
        reject(with(7, 8, "abc"), "timeout not a number");
        reject(with(9, 10, "bin/relative"), "relative argv0");
        let mut unknown = good();
        unknown.insert(0, "--bogus".into());
        unknown.insert(1, "1".into());
        reject(unknown, "unknown option");
        let mut dup = good();
        dup.splice(0..0, os(&["--id", "other"]));
        reject(dup, "duplicate option");
        reject(
            good().into_iter().filter(|a| a != "--").collect(),
            "missing separator",
        );
        reject(good().into_iter().take(9).collect(), "empty command");
        reject(good().into_iter().skip(2).collect(), "missing root");
        reject(os(&[]), "no arguments");
    }

    /// SUP-4（#2441）: 起動の判定は第 1 引数が `healthcheck-exec` のときだけ。
    #[test]
    fn sup4_2441_stat_ppid_parses_tricky_comm() {
        assert_eq!(parse_stat_ppid("12 (a b) c) S 345 6 7"), Some(345));
        assert_eq!(parse_stat_ppid("12 (x) S"), None);
        assert_eq!(parse_stat_ppid("garbage"), None);
    }

    #[test]
    fn sup4_2441_invocation_detection() {
        assert!(is_health_exec_invocation(Some(OsStr::new(
            "healthcheck-exec"
        ))));
        assert!(!is_health_exec_invocation(Some(OsStr::new("netns-holder"))));
        assert!(!is_health_exec_invocation(None));
    }

    fn outcome(exit: ExecExit) -> AuditedOutcome {
        // 公開の入口でしか作れない型のため、実機でなくても作れる最小の `ExecOutcome` を使う。
        crate::exec::audited_outcome_for_test(exit, AuditDelivery::NotApplicable)
    }

    /// SUP-4（#2441）: 終了コード 0 は healthy、非 0 とシグナルは unhealthy、`SetupFailed` は起動していない
    /// 結果として段と分類を保つ。拒否は `failed` で分類を保つ。
    #[test]
    fn sup4_2441_line_from_result_mapping() {
        assert_eq!(
            line_from_result(Ok(outcome(ExecExit::Command(ChildExit::Exited(0))))),
            HealthExecLine::Exited {
                code: 0,
                healthy: true,
                audit: AuditToken::Na,
                exit_audit: AuditToken::Na
            }
        );
        assert_eq!(
            line_from_result(Ok(outcome(ExecExit::Command(ChildExit::Exited(3))))),
            HealthExecLine::Exited {
                code: 3,
                healthy: false,
                audit: AuditToken::Na,
                exit_audit: AuditToken::Na
            }
        );
        assert_eq!(
            line_from_result(Ok(outcome(ExecExit::Command(ChildExit::Signaled(9))))),
            HealthExecLine::Signaled {
                signal: 9,
                audit: AuditToken::Na,
                exit_audit: AuditToken::Na
            }
        );
        // 終了コード 127 でもコマンド自身が返したものは不健全として扱う（`SetupFailed` と区別する）。
        assert_eq!(
            line_from_result(Ok(outcome(ExecExit::Command(ChildExit::Exited(127))))),
            HealthExecLine::Exited {
                code: 127,
                healthy: false,
                audit: AuditToken::Na,
                exit_audit: AuditToken::Na
            }
        );
        assert_eq!(
            line_from_result(Ok(outcome(ExecExit::SetupFailed {
                exit: ChildExit::Exited(127),
                violation: Some(ViolationReason::EntrypointIsRuntimeBinary),
                code: ErrorCode::PermissionDenied,
                step: Some(ExecChildStep::RuntimeIdentity),
            }))),
            HealthExecLine::NotStarted {
                step: Some(ExecChildStep::RuntimeIdentity),
                code: ErrorCode::PermissionDenied,
                violation: true,
                audit: AuditToken::Na
            }
        );
        assert_eq!(
            line_from_result(Err(AuditedRejection::not_applicable(TraitError::new(
                ErrorCode::Timeout,
                "exec timed out before starting the command"
            )))),
            HealthExecLine::Failed {
                code: ErrorCode::Timeout,
                audit: AuditToken::Na
            }
        );
        assert_eq!(
            line_from_result(Ok(outcome(ExecExit::Command(ChildExit::Exited(300))))),
            HealthExecLine::Failed {
                code: ErrorCode::Internal,
                audit: AuditToken::Na
            }
        );
    }
}
