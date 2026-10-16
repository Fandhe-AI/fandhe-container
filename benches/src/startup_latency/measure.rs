//! 起動レイテンシの計測本体（Linux・x86_64 / aarch64 限定。TASK-190・REPAIR-8・REPAIR-5・CORE-10）。
//!
//! 1 試行は「core の `oci_runtime::create` → `systemd-run --user --scope` で supervisor の bin を起動 → 結果チャネルの
//! `FCSUP1 OK` を読み終える」までで、CLI は経由しない。supervisor は本番 launcher（#1819）まで到達するため、分離
//! （user namespace・cgroup・Landlock）込みの起動を測る。分離を弱める経路は持たず、失敗は失敗として数える（REPAIR-3）。
//!
//! # 後始末（core の `delete` を使わない理由）
//! ベンチのプロセスは試行ごとの systemd スコープの外にいるため、`delete` は委譲スコープの照合で
//! `FailedPrecondition` になる（#2049 の観察と同じ）。記録済みのスコープを外から開く core の API の変更は
//! #1314 の決定の変更にあたるため範囲外とし、状態・cgroup・プローブの消滅を検証してから状態ルートごと消す。
//! 検証できなければ ID を `leftover_ids` に積み、以後の試行を止めて非ゼロで終わる（fail-closed）。

use super::StartupLatencyError;
use super::args::Plan;
use super::bin_check::verify_executable;
use super::bundle::build_bundle;
use super::output::{Failures, Params, RunResult, Sample, render_json};
use super::probe_env::effective_uid;
use super::report::{ReportOutcome, classify, spawn_report_reader};
use fandhe_container_core::cgroups::CgroupName;
use fandhe_container_core::observability::OpRecorder;
use fandhe_container_core::oci_runtime::{StartTimeouts, create};
use fandhe_container_core::traits::{
    ContainerId, ContainerState, CreateRequest, GetStateRequest, StateStore,
};
use fandhe_container_supervisor::start_contract::cli_receive_deadline;
use fandhe_container_supervisor::state::open_default_store;
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// supervisor の終了を待つ上限（成功時はコンテナの終了を待って 0 で終わる）。
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);
/// kill 後の回収を待つ上限。
const REAP_TIMEOUT: Duration = Duration::from_secs(10);
/// cgroup の消滅・プローブの消滅を待つ上限。
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
/// systemd のスコープ GC を待つ短い猶予（その後は空の cgroup を自分で消す）。
const CGROUP_GC_GRACE: Duration = Duration::from_millis(500);
const POLL: Duration = Duration::from_millis(20);

fn io_err(what: &'static str, e: &std::io::Error) -> StartupLatencyError {
    StartupLatencyError::new("io-error", format!("{what} failed ({:?})", e.kind()))
}

/// 1 試行で起きた失敗の種別。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fail {
    Create,
    Spawn,
    ReportErr(&'static str),
    ReportTimeout,
    ReportEof,
    ReportInvalid,
    SupervisorExit,
}

/// 試行後の状態の期待値。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// OK を受けた: `Stopped`。
    Stopped,
    /// ERR を受けた: `Created` かつ pid なし。
    Created,
    /// 期限切れ・EOF・不正: 何でもよい（残っていれば強制的に掃除する）。
    Any,
}

struct Trial {
    sample: Option<Sample>,
    fails: Vec<Fail>,
    leftover: bool,
}

struct Ctx<'a> {
    plan: &'a Plan,
    work: &'a Path,
    bundle: &'a Path,
    nonce: &'a str,
    deadline: Instant,
}

impl Ctx<'_> {
    /// 待ちの期限を全体の残り時間で切り詰める（最低 1 秒は残して後始末の判定を可能にする）。
    fn cap(&self, d: Duration) -> Duration {
        d.min(
            self.deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_secs(1)),
        )
    }
}

enum ExitWait {
    Exited(Option<i32>),
    TimedOut { reaped: bool },
}

/// 子の終了を期限つきで待つ。超過したら kill して回収を `REAP_TIMEOUT` まで待つ（REPAIR-5）。
fn wait_for_exit(child: &mut Child, timeout: Duration) -> ExitWait {
    let until = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return ExitWait::Exited(status.code()),
            Ok(None) => {}
            Err(_) => return ExitWait::TimedOut { reaped: false },
        }
        if Instant::now() >= until {
            break;
        }
        std::thread::sleep(POLL);
    }
    let _ = child.kill();
    let reap_until = Instant::now() + REAP_TIMEOUT;
    while Instant::now() < reap_until {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return ExitWait::TimedOut { reaped: true };
        }
        std::thread::sleep(POLL);
    }
    ExitWait::TimedOut { reaped: false }
}

/// `/proc` を走査し、この実行の nonce を引数に持つプローブの数を数える。
fn probe_count(nonce: &str) -> usize {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return 0;
    };
    let needle = nonce.as_bytes();
    dir.flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                && std::fs::read(e.path().join("cmdline")).is_ok_and(|c| {
                    !needle.is_empty() && c.windows(needle.len()).any(|w| w == needle)
                })
        })
        .count()
}

fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= until {
            return cond();
        }
        std::thread::sleep(POLL);
    }
}

/// コンテナの cgroup（ベンチが作った `fc-<id>@<instance>` だけ）を消す。消えた（または元から無い）なら `true`。
fn remove_container_cgroup(dir: &Path) -> bool {
    if wait_until(CGROUP_GC_GRACE, || !dir.exists()) {
        return true;
    }
    let procs = dir.join("cgroup.procs");
    let populated = std::fs::read_to_string(&procs).is_ok_and(|s| !s.trim().is_empty());
    if populated {
        let _ = std::fs::write(dir.join("cgroup.kill"), "1");
        let drained = wait_until(CLEANUP_TIMEOUT, || {
            std::fs::read_to_string(&procs).is_ok_and(|s| s.trim().is_empty())
        });
        if !drained {
            return false;
        }
    }
    let _ = std::fs::remove_dir(dir);
    !dir.exists()
}

/// 試行後の状態・cgroup・プローブを検証し、全部満たしたときだけ状態ルートを消す。
fn settle(
    ctx: &Ctx<'_>,
    store: &Arc<dyn StateStore>,
    id: &ContainerId,
    root: &Path,
    expect: Expect,
) -> bool {
    let Ok(record) = store.get(&GetStateRequest::new(id.clone())) else {
        return false;
    };
    let state_ok = match expect {
        Expect::Stopped => record.status().state() == ContainerState::Stopped,
        Expect::Created => {
            record.status().state() == ContainerState::Created && record.status().pid().is_none()
        }
        Expect::Any => true,
    };
    let mut ok = state_ok;
    if let Some(placement) = record.cgroup() {
        match CgroupName::for_instance(id, placement.instance()) {
            Ok(name) => {
                let scope = placement.scope().as_str().trim_start_matches('/');
                let dir = Path::new("/sys/fs/cgroup").join(scope).join(name.as_str());
                ok &= remove_container_cgroup(&dir);
            }
            Err(_) => ok = false,
        }
    }
    let probes_gone = wait_until(ctx.cap(CLEANUP_TIMEOUT), || probe_count(ctx.nonce) == 0);
    ok &= probes_gone;
    if ok {
        ok = std::fs::remove_dir_all(root).is_ok();
    }
    ok
}

fn run_trial(ctx: &Ctx<'_>, n: u32) -> Result<(Trial, String), StartupLatencyError> {
    let id_str = format!("fcsl{}t{n}", std::process::id());
    let root = ctx.work.join(format!("state-{n}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .map_err(|e| io_err("create state root", &e))?;
    let store = open_default_store(Some(root.clone()))
        .map_err(|_| StartupLatencyError::new("io-error", "open the state store failed"))?;
    let id = ContainerId::new(id_str.clone())
        .map_err(|_| StartupLatencyError::new("invalid-args", "container id is invalid"))?;
    let req = CreateRequest::new(id.clone(), ctx.bundle.to_path_buf())
        .map_err(|_| StartupLatencyError::new("invalid-args", "create request is invalid"))?;

    let mut fails = Vec::new();
    // 計測区間の始点: create を呼ぶ直前。
    let t0 = Instant::now();
    let created = create(store.as_ref(), &OpRecorder::new(), &req);
    let create_elapsed = t0.elapsed();
    if created.is_err() {
        fails.push(Fail::Create);
        let leftover = std::fs::remove_dir_all(&root).is_err();
        return Ok((
            Trial {
                sample: None,
                fails,
                leftover,
            },
            id_str,
        ));
    }

    let mut child = match Command::new(&ctx.plan.systemd_run)
        .args(["--user", "--scope", "--quiet", "-p", "Delegate=yes", "--"])
        .arg(&ctx.plan.supervisor_bin)
        .arg("start")
        .arg("--root")
        .arg(&root)
        .arg(&id_str)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .process_group(0)
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            fails.push(Fail::Spawn);
            // 起動できていないので、残るのは Created の状態だけ。
            let leftover = !settle(ctx, &store, &id, &root, Expect::Created);
            return Ok((
                Trial {
                    sample: None,
                    fails,
                    leftover,
                },
                id_str,
            ));
        }
    };
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = wait_for_exit(&mut child, Duration::from_millis(1));
        fails.push(Fail::Spawn);
        return Ok((
            Trial {
                sample: None,
                fails,
                leftover: true,
            },
            id_str,
        ));
    };
    let rx = spawn_report_reader(stdout);
    let report_wait = ctx.cap(cli_receive_deadline(&StartTimeouts::default()));
    let outcome = classify(rx.recv_timeout(report_wait));

    let mut sample = None;
    let (expect_exit, expect_state) = match outcome {
        ReportOutcome::Started { at, .. } => {
            sample = Some(Sample {
                total: at.duration_since(t0),
                create: create_elapsed,
            });
            (Some(0), Expect::Stopped)
        }
        ReportOutcome::Failed { code, exit_code } => {
            fails.push(Fail::ReportErr(code));
            (Some(i32::from(exit_code)), Expect::Created)
        }
        ReportOutcome::Timeout => {
            fails.push(Fail::ReportTimeout);
            (None, Expect::Any)
        }
        ReportOutcome::Eof => {
            fails.push(Fail::ReportEof);
            (None, Expect::Any)
        }
        ReportOutcome::Invalid => {
            fails.push(Fail::ReportInvalid);
            (None, Expect::Any)
        }
    };
    let mut reaped = true;
    match wait_for_exit(&mut child, ctx.cap(EXIT_TIMEOUT)) {
        ExitWait::Exited(code) => {
            if let Some(expected) = expect_exit
                && code != Some(expected)
            {
                fails.push(Fail::SupervisorExit);
            }
        }
        ExitWait::TimedOut { reaped: r } => {
            fails.push(Fail::SupervisorExit);
            reaped = r;
        }
    }
    let settled = reaped && settle(ctx, &store, &id, &root, expect_state);
    Ok((
        Trial {
            sample,
            fails,
            leftover: !settled,
        },
        id_str,
    ))
}

fn tally(failures: &mut Failures, fails: &[Fail], leftover: bool) {
    for f in fails {
        match f {
            Fail::Create => failures.create += 1,
            Fail::Spawn => failures.spawn += 1,
            Fail::ReportErr(code) => {
                failures.report_err += 1;
                *failures.report_err_codes.entry(code).or_insert(0) += 1;
            }
            Fail::ReportTimeout => failures.report_timeout += 1,
            Fail::ReportEof => failures.report_eof += 1,
            Fail::ReportInvalid => failures.report_invalid += 1,
            Fail::SupervisorExit => failures.supervisor_exit += 1,
        }
    }
    if leftover {
        failures.cleanup += 1;
    }
}

/// 試行を直列に回して結果を集める。残りが出たら以後の試行は行わない。
fn run_trials(ctx: &Ctx<'_>) -> Result<RunResult, StartupLatencyError> {
    let mut samples = Vec::new();
    let mut failures = Failures::default();
    let mut leftover_ids = Vec::new();
    let total = ctx.plan.warmup.saturating_add(ctx.plan.trials);
    for n in 0..total {
        if Instant::now() >= ctx.deadline {
            return Err(StartupLatencyError::new(
                "deadline-exceeded",
                "the overall deadline passed before all trials finished",
            ));
        }
        let (trial, id) = run_trial(ctx, n)?;
        tally(&mut failures, &trial.fails, trial.leftover);
        if n >= ctx.plan.warmup
            && let Some(s) = trial.sample
        {
            samples.push(s);
        }
        if trial.leftover {
            leftover_ids.push(id);
            break;
        }
    }
    let timeouts = StartTimeouts::default();
    Ok(RunResult {
        params: Params {
            trials: ctx.plan.trials,
            warmup: ctx.plan.warmup,
            timeout_secs: ctx.plan.timeout_secs,
            report_timeout_ms: u64::try_from(cli_receive_deadline(&timeouts).as_millis())
                .unwrap_or(u64::MAX),
            exit_timeout_ms: u64::try_from(EXIT_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
            cleanup_timeout_ms: u64::try_from(CLEANUP_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
        },
        samples,
        failures,
        leftover_ids,
        arch: std::env::consts::ARCH,
    })
}

/// 計測を実行する。入口（`startup_latency::execute`）から呼ばれる。
pub fn run(plan: Plan) -> Result<super::Execution, StartupLatencyError> {
    let euid = effective_uid().ok_or_else(|| {
        StartupLatencyError::new(
            "unsupported-environment",
            "cannot determine the effective uid",
        )
    })?;
    if euid == 0 {
        // rootful の起動は supervisor が拒否する（SEC-5）。
        return Err(StartupLatencyError::new(
            "unsupported-environment",
            "must run as a non-root user",
        ));
    }
    verify_executable(&plan.supervisor_bin, euid)?;
    verify_executable(&plan.systemd_run, euid)?;

    let base: PathBuf = match &plan.work_dir {
        Some(d) => d.clone(),
        None => std::fs::canonicalize(std::env::temp_dir())
            .map_err(|e| io_err("canonicalize temp dir", &e))?,
    };
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let dir_name = format!("fandhe-startup-latency-{pid}-{nanos}");
    let work = base.join(&dir_name);
    // 排他作成（既存なら失敗）。0700 で他ユーザーから隔離する。
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&work)
        .map_err(|e| io_err("create work dir", &e))?;

    let nonce = format!("{pid:x}{nanos:x}");
    let result = build_bundle(&work, &nonce).and_then(|bundle| {
        let ctx = Ctx {
            plan: &plan,
            work: &work,
            bundle: &bundle,
            nonce: &nonce,
            deadline: Instant::now() + Duration::from_secs(plan.timeout_secs),
        };
        run_trials(&ctx)
    });
    let keep = matches!(&result, Ok(r) if !r.leftover_ids.is_empty());
    if keep {
        // 調査用に残す。相対名だけを出す（絶対パスを出さない）。
        eprintln!("startup_latency: leftover resources; work dir kept as {dir_name}");
    } else {
        let _ = std::fs::remove_dir_all(&work);
    }
    let result = result?;
    let json = render_json(&result)?;
    Ok(super::Execution::Done {
        clean: result.is_clean(),
        json,
        output: plan.output,
    })
}
